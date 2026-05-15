use std::sync::Arc;

use crate::{
    account::NewAccount,
    config::AuthConfig,
    error::{Error, Result},
    mailer::{LogMailer, Mailer, SharedMailer},
    password::{Argon2Hasher, Hasher},
    plugin::SharedPlugin,
    session::{IssuedSession, NewSession, Session},
    storage::Storage,
    time_provider::{Clock, SharedClock, SystemClock},
    token::{hash_token, random_token},
    user::{NewUser, User},
    verification::NewVerification,
};

/// High-level orchestrator. Cheap to clone — internally just `Arc`s.
#[derive(Clone)]
pub struct Auth {
    inner: Arc<AuthInner>,
}

struct AuthInner {
    storage: Arc<dyn Storage>,
    hasher: Arc<dyn Hasher>,
    clock: SharedClock,
    mailer: SharedMailer,
    config: AuthConfig,
    plugins: Vec<SharedPlugin>,
}

impl Auth {
    pub fn builder() -> AuthBuilder {
        AuthBuilder::default()
    }

    pub fn config(&self) -> &AuthConfig {
        &self.inner.config
    }

    pub fn storage(&self) -> &Arc<dyn Storage> {
        &self.inner.storage
    }

    pub fn clock(&self) -> &SharedClock {
        &self.inner.clock
    }

    pub fn plugins(&self) -> &[SharedPlugin] {
        &self.inner.plugins
    }

    pub fn mailer(&self) -> &SharedMailer {
        &self.inner.mailer
    }

    // --------- Sign-up (email + password) ---------

    pub async fn sign_up_email(
        &self,
        email: &str,
        password: &str,
        name: Option<String>,
    ) -> Result<User> {
        let email = normalize_email(email);
        if password.len() < self.inner.config.min_password_length {
            return Err(Error::bad_request("password too short"));
        }
        if self
            .inner
            .storage
            .find_user_by_email(&email)
            .await?
            .is_some()
        {
            return Err(Error::UserAlreadyExists);
        }

        let user = self
            .inner
            .storage
            .create_user(NewUser {
                email: email.clone(),
                name,
                image: None,
                email_verified: false,
            })
            .await?;

        let password_hash = self.inner.hasher.hash(password)?;
        self.inner
            .storage
            .create_account(NewAccount {
                user_id: user.id,
                provider: "credentials".into(),
                provider_account_id: email,
                password_hash: Some(password_hash),
                access_token: None,
                refresh_token: None,
                expires_at: None,
                scope: None,
                id_token: None,
            })
            .await?;

        for p in &self.inner.plugins {
            p.on_user_created(&user).await?;
        }

        if self.inner.config.send_verification_email_on_signup {
            let _ = self.request_email_verification(&user.email).await;
        }

        Ok(user)
    }

    // --------- Sign-in (email + password) ---------

    pub async fn sign_in_email(
        &self,
        email: &str,
        password: &str,
        ip: Option<String>,
        ua: Option<String>,
    ) -> Result<(User, IssuedSession)> {
        let email = normalize_email(email);
        for p in &self.inner.plugins {
            p.before_sign_in(&email).await?;
        }

        let user = self
            .inner
            .storage
            .find_user_by_email(&email)
            .await?
            .ok_or(Error::InvalidCredentials)?;

        if self.inner.config.require_email_verification && !user.email_verified {
            return Err(Error::Unauthorized);
        }

        let account = self
            .inner
            .storage
            .find_account_by_user(&user.id, "credentials")
            .await?
            .ok_or(Error::InvalidCredentials)?;
        let hash = account.password_hash.as_deref().ok_or(Error::InvalidCredentials)?;

        if !self.inner.hasher.verify(password, hash)? {
            return Err(Error::InvalidCredentials);
        }

        let issued = self.create_session(&user, ip, ua).await?;
        Ok((user, issued))
    }

    // --------- Session lifecycle ---------

    pub async fn create_session(
        &self,
        user: &User,
        ip: Option<String>,
        ua: Option<String>,
    ) -> Result<IssuedSession> {
        let token = random_token(32);
        let token_hash = hash_token(&token);
        let now = self.inner.clock.now();
        let expires_at = now + self.inner.config.session_ttl;

        let session = self
            .inner
            .storage
            .create_session(NewSession {
                token_hash,
                user_id: user.id,
                expires_at,
                ip_address: ip,
                user_agent: ua,
            })
            .await?;

        for p in &self.inner.plugins {
            p.after_sign_in(user, &session).await?;
        }

        Ok(IssuedSession {
            token,
            expires_at: session.expires_at,
        })
    }

    pub async fn validate_session(&self, token: &str) -> Result<(User, Session)> {
        let token_hash = hash_token(token);
        let session = self
            .inner
            .storage
            .find_session(&token_hash)
            .await?
            .ok_or(Error::InvalidSession)?;

        if session.expires_at <= self.inner.clock.now() {
            let _ = self.inner.storage.delete_session(&token_hash).await;
            return Err(Error::InvalidSession);
        }

        let user = self
            .inner
            .storage
            .find_user_by_id(&session.user_id)
            .await?
            .ok_or(Error::InvalidSession)?;
        Ok((user, session))
    }

    pub async fn sign_out(&self, token: &str) -> Result<()> {
        let token_hash = hash_token(token);
        if let Some(session) = self.inner.storage.find_session(&token_hash).await? {
            for p in &self.inner.plugins {
                p.before_sign_out(&session).await?;
            }
        }
        self.inner.storage.delete_session(&token_hash).await
    }

    // --------- Email verification ---------

    /// Generate a verification token and send it via the configured mailer.
    /// Always succeeds even if the email is unknown (avoid user enumeration).
    pub async fn request_email_verification(&self, email: &str) -> Result<()> {
        let email = normalize_email(email);
        let Some(user) = self.inner.storage.find_user_by_email(&email).await? else {
            return Ok(());
        };
        if user.email_verified {
            return Ok(());
        }
        let link = self
            .issue_verification_link(&user.email, EMAIL_VERIFY_PURPOSE, &self.inner.config.email_verification_path)
            .await?;
        self.inner
            .mailer
            .send_verification_email(&user.email, &link)
            .await
    }

    pub async fn verify_email(&self, token: &str) -> Result<User> {
        let value_hash = hash_token(token);
        let mut user = self.consume_verification_for_user(EMAIL_VERIFY_PURPOSE, &value_hash).await?;
        if !user.email_verified {
            user.email_verified = true;
            user.updated_at = self.inner.clock.now();
            self.inner.storage.update_user(&user).await?;
        }
        Ok(user)
    }

    // --------- Password reset ---------

    /// Always returns Ok to prevent user enumeration.
    pub async fn request_password_reset(&self, email: &str) -> Result<()> {
        let email = normalize_email(email);
        let Some(user) = self.inner.storage.find_user_by_email(&email).await? else {
            return Ok(());
        };
        let link = self
            .issue_verification_link(&user.email, PASSWORD_RESET_PURPOSE, &self.inner.config.password_reset_path)
            .await?;
        self.inner
            .mailer
            .send_password_reset_email(&user.email, &link)
            .await
    }

    pub async fn reset_password(&self, token: &str, new_password: &str) -> Result<User> {
        if new_password.len() < self.inner.config.min_password_length {
            return Err(Error::bad_request("password too short"));
        }
        let value_hash = hash_token(token);
        let user = self.consume_verification_for_user(PASSWORD_RESET_PURPOSE, &value_hash).await?;

        let mut account = self
            .inner
            .storage
            .find_account_by_user(&user.id, "credentials")
            .await?
            .ok_or(Error::UserNotFound)?;
        account.password_hash = Some(self.inner.hasher.hash(new_password)?);
        self.inner.storage.update_account(&account).await?;

        // Invalidate all existing sessions on password change.
        self.inner.storage.delete_sessions_for_user(&user.id).await?;
        Ok(user)
    }

    // --------- Internal helpers ---------

    async fn issue_verification_link(
        &self,
        identifier: &str,
        purpose: &str,
        path: &str,
    ) -> Result<String> {
        let token = random_token(32);
        let value_hash = hash_token(&token);
        let expires_at = self.inner.clock.now() + self.inner.config.verification_ttl;
        self.inner
            .storage
            .create_verification(NewVerification {
                identifier: identifier.to_string(),
                purpose: purpose.to_string(),
                value_hash,
                expires_at,
            })
            .await?;
        Ok(format!(
            "{}{}?token={}",
            self.inner.config.base_url.trim_end_matches('/'),
            path,
            token
        ))
    }

    async fn consume_verification_for_user(
        &self,
        purpose: &str,
        value_hash: &str,
    ) -> Result<User> {
        // The identifier was the email at issue-time; we don't know it from
        // the token alone, so we let storage match on (purpose, value_hash).
        let v = self
            .inner
            .storage
            .consume_verification_by_value(purpose, value_hash)
            .await?
            .ok_or(Error::InvalidVerification)?;
        self.inner
            .storage
            .find_user_by_email(&v.identifier)
            .await?
            .ok_or(Error::InvalidVerification)
    }
}

pub const EMAIL_VERIFY_PURPOSE: &str = "email_verify";
pub const PASSWORD_RESET_PURPOSE: &str = "password_reset";

fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

#[derive(Default)]
pub struct AuthBuilder {
    storage: Option<Arc<dyn Storage>>,
    hasher: Option<Arc<dyn Hasher>>,
    clock: Option<SharedClock>,
    mailer: Option<SharedMailer>,
    config: Option<AuthConfig>,
    plugins: Vec<SharedPlugin>,
}

impl AuthBuilder {
    pub fn storage<S: Storage>(mut self, storage: S) -> Self {
        self.storage = Some(Arc::new(storage));
        self
    }

    pub fn storage_arc(mut self, storage: Arc<dyn Storage>) -> Self {
        self.storage = Some(storage);
        self
    }

    pub fn hasher<H: Hasher>(mut self, hasher: H) -> Self {
        self.hasher = Some(Arc::new(hasher));
        self
    }

    pub fn clock<C: Clock>(mut self, clock: C) -> Self {
        self.clock = Some(Arc::new(clock));
        self
    }

    pub fn mailer<M: Mailer>(mut self, mailer: M) -> Self {
        self.mailer = Some(Arc::new(mailer));
        self
    }

    pub fn config(mut self, config: AuthConfig) -> Self {
        self.config = Some(config);
        self
    }

    pub fn plugin(mut self, plugin: SharedPlugin) -> Self {
        self.plugins.push(plugin);
        self
    }

    pub fn build(self) -> Result<Auth> {
        let storage = self
            .storage
            .ok_or_else(|| Error::bad_request("storage is required"))?;
        Ok(Auth {
            inner: Arc::new(AuthInner {
                storage,
                hasher: self.hasher.unwrap_or_else(|| Arc::new(Argon2Hasher)),
                clock: self.clock.unwrap_or_else(|| Arc::new(SystemClock)),
                mailer: self.mailer.unwrap_or_else(|| Arc::new(LogMailer)),
                config: self.config.unwrap_or_default(),
                plugins: self.plugins,
            }),
        })
    }
}
