//! OAuth2 / OIDC plugin for rauth.
//!
//! Provides ready-made provider configs (Google, GitHub) plus a generic
//! [`OAuthProvider`] for any OAuth2 server. The flow uses PKCE and a
//! one-shot CSRF `state` stored in the verifications table.

use base64::Engine;
use rand::RngCore;
use rauth_core::{
    account::NewAccount,
    error::{Error, Result},
    session::IssuedSession,
    user::{NewUser, User},
    verification::NewVerification,
    Auth,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, sync::Arc};
use time::Duration;

#[cfg(feature = "axum")]
pub mod axum_router;

const STATE_TTL_SECS: i64 = 600;

/// Mapping function from a provider's userinfo JSON payload to a
/// canonical [`OAuthUserInfo`].
pub type UserInfoMapper = fn(&serde_json::Value) -> Result<OAuthUserInfo>;

/// Canonical fields extracted from a provider's userinfo response.
#[derive(Debug, Clone)]
pub struct OAuthUserInfo {
    pub provider_account_id: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub name: Option<String>,
    pub image: Option<String>,
}

#[derive(Clone)]
pub struct OAuthProvider {
    pub id: String,
    pub client_id: String,
    pub client_secret: String,
    pub authorize_url: String,
    pub token_url: String,
    pub userinfo_url: String,
    pub scopes: Vec<String>,
    pub redirect_uri: String,
    pub user_agent: String,
    pub map_userinfo: UserInfoMapper,
}

impl OAuthProvider {
    /// Google provider (OIDC). Uses `openid email profile` scopes.
    pub fn google(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        Self {
            id: "google".into(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            authorize_url: "https://accounts.google.com/o/oauth2/v2/auth".into(),
            token_url: "https://oauth2.googleapis.com/token".into(),
            userinfo_url: "https://openidconnect.googleapis.com/v1/userinfo".into(),
            scopes: vec!["openid".into(), "email".into(), "profile".into()],
            redirect_uri: redirect_uri.into(),
            user_agent: "rauth-oauth/0.1".into(),
            map_userinfo: map_google,
        }
    }

    /// GitHub provider. Default scopes `read:user user:email`.
    pub fn github(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        Self {
            id: "github".into(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            authorize_url: "https://github.com/login/oauth/authorize".into(),
            token_url: "https://github.com/login/oauth/access_token".into(),
            userinfo_url: "https://api.github.com/user".into(),
            scopes: vec!["read:user".into(), "user:email".into()],
            redirect_uri: redirect_uri.into(),
            user_agent: "rauth-oauth/0.1".into(),
            map_userinfo: map_github,
        }
    }
}

fn map_google(v: &serde_json::Value) -> Result<OAuthUserInfo> {
    Ok(OAuthUserInfo {
        provider_account_id: v
            .get("sub")
            .and_then(|s| s.as_str())
            .ok_or_else(|| Error::Plugin("google: missing sub".into()))?
            .to_string(),
        email: v.get("email").and_then(|s| s.as_str()).map(str::to_string),
        email_verified: v
            .get("email_verified")
            .and_then(|b| b.as_bool())
            .unwrap_or(false),
        name: v.get("name").and_then(|s| s.as_str()).map(str::to_string),
        image: v.get("picture").and_then(|s| s.as_str()).map(str::to_string),
    })
}

fn map_github(v: &serde_json::Value) -> Result<OAuthUserInfo> {
    Ok(OAuthUserInfo {
        provider_account_id: v
            .get("id")
            .map(|n| n.to_string())
            .ok_or_else(|| Error::Plugin("github: missing id".into()))?,
        email: v.get("email").and_then(|s| s.as_str()).map(str::to_string),
        email_verified: v.get("email").and_then(|s| s.as_str()).is_some(),
        name: v.get("name").and_then(|s| s.as_str()).map(str::to_string),
        image: v.get("avatar_url").and_then(|s| s.as_str()).map(str::to_string),
    })
}

/// Engine that owns the configured providers and an HTTP client.
#[derive(Clone)]
pub struct OAuth {
    inner: Arc<OAuthInner>,
}

struct OAuthInner {
    auth: Auth,
    providers: HashMap<String, OAuthProvider>,
    http: reqwest::Client,
}

impl OAuth {
    pub fn new(auth: Auth) -> Self {
        Self {
            inner: Arc::new(OAuthInner {
                auth,
                providers: HashMap::new(),
                http: reqwest::Client::builder().build().expect("reqwest client"),
            }),
        }
    }

    pub fn with_provider(self, p: OAuthProvider) -> Self {
        let mut providers = self.inner.providers.clone();
        providers.insert(p.id.clone(), p);
        Self {
            inner: Arc::new(OAuthInner {
                auth: self.inner.auth.clone(),
                providers,
                http: self.inner.http.clone(),
            }),
        }
    }

    pub fn auth(&self) -> &Auth {
        &self.inner.auth
    }

    pub fn provider(&self, id: &str) -> Option<&OAuthProvider> {
        self.inner.providers.get(id)
    }

    /// Build the authorization URL the user should be redirected to.
    pub async fn start(&self, provider_id: &str) -> Result<String> {
        let p = self
            .provider(provider_id)
            .ok_or_else(|| Error::bad_request(format!("unknown oauth provider: {provider_id}")))?;

        let state = random_url_token(16);
        let verifier = random_url_token(32);
        let challenge = pkce_challenge(&verifier);

        self.inner
            .auth
            .storage()
            .create_verification(NewVerification {
                identifier: state.clone(),
                purpose: oauth_state_purpose(provider_id),
                value_hash: verifier,
                expires_at: self.inner.auth.clock().now() + Duration::seconds(STATE_TTL_SECS),
            })
            .await?;

        let mut url =
            url::Url::parse(&p.authorize_url).map_err(|e| Error::Plugin(e.to_string()))?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &p.client_id)
            .append_pair("redirect_uri", &p.redirect_uri)
            .append_pair("scope", &p.scopes.join(" "))
            .append_pair("state", &state)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256");
        Ok(url.into())
    }

    /// Exchange the authorization code, fetch userinfo, find/create the user
    /// + account, and return an issued session.
    pub async fn callback(
        &self,
        provider_id: &str,
        code: &str,
        state: &str,
        ip: Option<String>,
        ua: Option<String>,
    ) -> Result<(User, IssuedSession)> {
        let p = self
            .provider(provider_id)
            .ok_or_else(|| Error::bad_request(format!("unknown oauth provider: {provider_id}")))?;

        let v = self
            .inner
            .auth
            .storage()
            .consume_verification_by_identifier(state, &oauth_state_purpose(provider_id))
            .await?
            .ok_or(Error::InvalidVerification)?;
        let code_verifier = v.value_hash;

        let token: TokenResponse = self
            .inner
            .http
            .post(&p.token_url)
            .header(reqwest::header::ACCEPT, "application/json")
            .header(reqwest::header::USER_AGENT, &p.user_agent)
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", p.redirect_uri.as_str()),
                ("client_id", p.client_id.as_str()),
                ("client_secret", p.client_secret.as_str()),
                ("code_verifier", code_verifier.as_str()),
            ])
            .send()
            .await
            .map_err(|e| Error::Plugin(format!("token exchange: {e}")))?
            .error_for_status()
            .map_err(|e| Error::Plugin(format!("token exchange: {e}")))?
            .json()
            .await
            .map_err(|e| Error::Plugin(format!("token exchange decode: {e}")))?;

        let userinfo: serde_json::Value = self
            .inner
            .http
            .get(&p.userinfo_url)
            .header(reqwest::header::ACCEPT, "application/json")
            .header(reqwest::header::USER_AGENT, &p.user_agent)
            .bearer_auth(&token.access_token)
            .send()
            .await
            .map_err(|e| Error::Plugin(format!("userinfo: {e}")))?
            .error_for_status()
            .map_err(|e| Error::Plugin(format!("userinfo: {e}")))?
            .json()
            .await
            .map_err(|e| Error::Plugin(format!("userinfo decode: {e}")))?;

        let mut info = (p.map_userinfo)(&userinfo)?;

        // GitHub-specific: if the primary email is private, fetch /user/emails.
        if info.email.is_none() && provider_id == "github" {
            let emails: Vec<GithubEmail> = self
                .inner
                .http
                .get("https://api.github.com/user/emails")
                .header(reqwest::header::ACCEPT, "application/vnd.github+json")
                .header(reqwest::header::USER_AGENT, &p.user_agent)
                .bearer_auth(&token.access_token)
                .send()
                .await
                .map_err(|e| Error::Plugin(format!("github emails: {e}")))?
                .error_for_status()
                .map_err(|e| Error::Plugin(format!("github emails: {e}")))?
                .json()
                .await
                .map_err(|e| Error::Plugin(format!("github emails decode: {e}")))?;
            if let Some(primary) = emails.into_iter().find(|e| e.primary && e.verified) {
                info.email = Some(primary.email);
                info.email_verified = true;
            }
        }

        let storage = self.inner.auth.storage().clone();
        let user = if let Some(account) = storage
            .find_account(provider_id, &info.provider_account_id)
            .await?
        {
            storage
                .find_user_by_id(&account.user_id)
                .await?
                .ok_or(Error::UserNotFound)?
        } else if let Some(email) = info.email.clone() {
            let existing = storage.find_user_by_email(&email).await?;
            let user = match existing {
                Some(u) => u,
                None => {
                    storage
                        .create_user(NewUser {
                            email: email.clone(),
                            name: info.name.clone(),
                            image: info.image.clone(),
                            email_verified: info.email_verified,
                        })
                        .await?
                }
            };
            storage
                .create_account(NewAccount {
                    user_id: user.id,
                    provider: provider_id.to_string(),
                    provider_account_id: info.provider_account_id.clone(),
                    password_hash: None,
                    access_token: Some(token.access_token.clone()),
                    refresh_token: token.refresh_token.clone(),
                    expires_at: None,
                    scope: token.scope.clone(),
                    id_token: token.id_token.clone(),
                })
                .await?;
            user
        } else {
            return Err(Error::Plugin(
                "provider returned no email; cannot create account".into(),
            ));
        };

        let issued = self.inner.auth.create_session(&user, ip, ua).await?;
        Ok((user, issued))
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}

#[derive(Deserialize)]
struct GithubEmail {
    email: String,
    primary: bool,
    verified: bool,
}

fn oauth_state_purpose(provider_id: &str) -> String {
    format!("oauth_state:{provider_id}")
}

fn random_url_token(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

fn pkce_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}
