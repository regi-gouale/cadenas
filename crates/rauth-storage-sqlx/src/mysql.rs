use async_trait::async_trait;
use rauth_core::{
    account::{Account, NewAccount},
    error::{Error, Result},
    organization::{Membership, Organization, OrganizationId, Role},
    session::{NewSession, Session},
    storage::Storage,
    totp::TotpFactor,
    user::{NewUser, User, UserId},
    verification::{NewVerification, Verification},
};
use sqlx::mysql::MySqlPool;
use time::OffsetDateTime;
use uuid::Uuid;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS users (
    id              VARCHAR(36) PRIMARY KEY,
    email           VARCHAR(320) NOT NULL UNIQUE,
    email_verified  INTEGER NOT NULL DEFAULT 0,
    name            VARCHAR(255),
    image           TEXT,
    created_at      VARCHAR(64) NOT NULL,
    updated_at      VARCHAR(64) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS accounts (
    user_id              VARCHAR(36) NOT NULL,
    provider             VARCHAR(64) NOT NULL,
    provider_account_id  VARCHAR(255) NOT NULL,
    password_hash        TEXT,
    access_token         TEXT,
    refresh_token        TEXT,
    expires_at           VARCHAR(64),
    scope                TEXT,
    id_token             TEXT,
    created_at           VARCHAR(64) NOT NULL,
    updated_at           VARCHAR(64) NOT NULL,
    INDEX idx_accounts_user (user_id),
    PRIMARY KEY (provider, provider_account_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS sessions (
    token_hash   VARCHAR(128) PRIMARY KEY,
    user_id      VARCHAR(36) NOT NULL,
    expires_at   VARCHAR(64) NOT NULL,
    created_at   VARCHAR(64) NOT NULL,
    ip_address   VARCHAR(128),
    user_agent   TEXT,
    INDEX idx_sessions_user (user_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS verifications (
    identifier  VARCHAR(255) NOT NULL,
    purpose     VARCHAR(128) NOT NULL,
    value_hash  VARCHAR(128) NOT NULL,
    expires_at  VARCHAR(64) NOT NULL,
    created_at  VARCHAR(64) NOT NULL,
    PRIMARY KEY (identifier, purpose, value_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS totp_factors (
    user_id     VARCHAR(36) PRIMARY KEY,
    secret_b32  VARCHAR(128) NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 0,
    created_at  VARCHAR(64) NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS organizations (
    id          VARCHAR(36) PRIMARY KEY,
    slug        VARCHAR(128) NOT NULL UNIQUE,
    name        VARCHAR(255) NOT NULL,
    created_at  VARCHAR(64) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS memberships (
    organization_id  VARCHAR(36) NOT NULL,
    user_id          VARCHAR(36) NOT NULL,
    role             VARCHAR(32) NOT NULL,
    created_at       VARCHAR(64) NOT NULL,
    INDEX idx_memberships_user (user_id),
    PRIMARY KEY (organization_id, user_id),
    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
"#;

#[derive(Clone)]
pub struct MySqlStorage {
    pool: MySqlPool,
}

impl MySqlStorage {
    pub fn new(pool: MySqlPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &MySqlPool {
        &self.pool
    }

    /// Apply the embedded schema (idempotent).
    pub async fn migrate(&self) -> Result<()> {
        for stmt in SCHEMA.split(';') {
            let s = stmt.trim();
            if s.is_empty() {
                continue;
            }
            sqlx::query(s).execute(&self.pool).await.map_err(Error::storage)?;
        }
        Ok(())
    }
}

fn parse_dt(s: &str) -> Result<OffsetDateTime> {
    OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
        .map_err(|e| Error::storage(e))
}

fn fmt_dt(dt: OffsetDateTime) -> String {
    dt.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| dt.to_string())
}

#[async_trait]
impl Storage for MySqlStorage {
    async fn create_user(&self, input: NewUser) -> Result<User> {
        let id = UserId::new();
        let now = OffsetDateTime::now_utc();
        sqlx::query(
            r#"INSERT INTO users (id, email, email_verified, name, image, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)"#,
        )
        .bind(id.0.to_string())
        .bind(&input.email)
        .bind(input.email_verified as i64)
        .bind(&input.name)
        .bind(&input.image)
        .bind(fmt_dt(now))
        .execute(&self.pool)
        .await
        .map_err(Error::storage)?;

        Ok(User {
            id,
            email: input.email,
            email_verified: input.email_verified,
            name: input.name,
            image: input.image,
            created_at: now,
            updated_at: now,
        })
    }

    async fn find_user_by_id(&self, id: &UserId) -> Result<Option<User>> {
        let row: Option<(String, String, i64, Option<String>, Option<String>, String, String)> =
            sqlx::query_as(
                r#"SELECT id, email, email_verified, name, image, created_at, updated_at
                   FROM users WHERE id = ?"#,
            )
            .bind(id.0.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(Error::storage)?;

        row.map(row_to_user).transpose()
    }

    async fn find_user_by_email(&self, email: &str) -> Result<Option<User>> {
        let row: Option<(String, String, i64, Option<String>, Option<String>, String, String)> =
            sqlx::query_as(
                r#"SELECT id, email, email_verified, name, image, created_at, updated_at
                   FROM users WHERE LOWER(email) = LOWER(?)"#,
            )
            .bind(email)
            .fetch_optional(&self.pool)
            .await
            .map_err(Error::storage)?;

        row.map(row_to_user).transpose()
    }

    async fn update_user(&self, user: &User) -> Result<()> {
        let now = OffsetDateTime::now_utc();
        sqlx::query(
            r#"UPDATE users SET email = ?, email_verified = ?, name = ?, image = ?, updated_at = ?
               WHERE id = ?"#,
        )
        .bind(user.id.0.to_string())
        .bind(&user.email)
        .bind(user.email_verified as i64)
        .bind(&user.name)
        .bind(&user.image)
        .bind(fmt_dt(now))
        .execute(&self.pool)
        .await
        .map_err(Error::storage)?;
        Ok(())
    }

    async fn create_account(&self, input: NewAccount) -> Result<Account> {
        let now = OffsetDateTime::now_utc();
        sqlx::query(
            r#"INSERT INTO accounts
                (user_id, provider, provider_account_id, password_hash,
                 access_token, refresh_token, expires_at, scope, id_token,
                 created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#,
        )
        .bind(input.user_id.0.to_string())
        .bind(&input.provider)
        .bind(&input.provider_account_id)
        .bind(&input.password_hash)
        .bind(&input.access_token)
        .bind(&input.refresh_token)
        .bind(input.expires_at.map(fmt_dt))
        .bind(&input.scope)
        .bind(&input.id_token)
        .bind(fmt_dt(now))
        .execute(&self.pool)
        .await
        .map_err(Error::storage)?;

        Ok(Account {
            user_id: input.user_id,
            provider: input.provider,
            provider_account_id: input.provider_account_id,
            password_hash: input.password_hash,
            access_token: input.access_token,
            refresh_token: input.refresh_token,
            expires_at: input.expires_at,
            scope: input.scope,
            id_token: input.id_token,
            created_at: now,
            updated_at: now,
        })
    }

    async fn find_account(
        &self,
        provider: &str,
        provider_account_id: &str,
    ) -> Result<Option<Account>> {
        let row: Option<AccountRow> = sqlx::query_as(
            r#"SELECT user_id, provider, provider_account_id, password_hash,
                      access_token, refresh_token, expires_at, scope, id_token,
                      created_at, updated_at
               FROM accounts WHERE provider = ? AND provider_account_id = ?"#,
        )
        .bind(provider)
        .bind(provider_account_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(Error::storage)?;
        row.map(row_to_account).transpose()
    }

    async fn find_account_by_user(
        &self,
        user_id: &UserId,
        provider: &str,
    ) -> Result<Option<Account>> {
        let row: Option<AccountRow> = sqlx::query_as(
            r#"SELECT user_id, provider, provider_account_id, password_hash,
                      access_token, refresh_token, expires_at, scope, id_token,
                      created_at, updated_at
               FROM accounts WHERE user_id = ? AND provider = ?"#,
        )
        .bind(user_id.0.to_string())
        .bind(provider)
        .fetch_optional(&self.pool)
        .await
        .map_err(Error::storage)?;
        row.map(row_to_account).transpose()
    }

    async fn update_account(&self, account: &Account) -> Result<()> {
        let now = OffsetDateTime::now_utc();
        sqlx::query(
            r#"UPDATE accounts SET
                  password_hash = ?, access_token = ?, refresh_token = ?,
                  expires_at = ?, scope = ?, id_token = ?, updated_at = ?
               WHERE provider = ? AND provider_account_id = ?"#,
        )
        .bind(&account.provider)
        .bind(&account.provider_account_id)
        .bind(&account.password_hash)
        .bind(&account.access_token)
        .bind(&account.refresh_token)
        .bind(account.expires_at.map(fmt_dt))
        .bind(&account.scope)
        .bind(&account.id_token)
        .bind(fmt_dt(now))
        .execute(&self.pool)
        .await
        .map_err(Error::storage)?;
        Ok(())
    }

    async fn create_session(&self, input: NewSession) -> Result<Session> {
        let now = OffsetDateTime::now_utc();
        sqlx::query(
            r#"INSERT INTO sessions (token_hash, user_id, expires_at, created_at, ip_address, user_agent)
               VALUES (?, ?, ?, ?, ?, ?)"#,
        )
        .bind(&input.token_hash)
        .bind(input.user_id.0.to_string())
        .bind(fmt_dt(input.expires_at))
        .bind(fmt_dt(now))
        .bind(&input.ip_address)
        .bind(&input.user_agent)
        .execute(&self.pool)
        .await
        .map_err(Error::storage)?;

        Ok(Session {
            token_hash: input.token_hash,
            user_id: input.user_id,
            expires_at: input.expires_at,
            created_at: now,
            ip_address: input.ip_address,
            user_agent: input.user_agent,
        })
    }

    async fn find_session(&self, token_hash: &str) -> Result<Option<Session>> {
        let row: Option<(String, String, String, String, Option<String>, Option<String>)> =
            sqlx::query_as(
                r#"SELECT token_hash, user_id, expires_at, created_at, ip_address, user_agent
                   FROM sessions WHERE token_hash = ?"#,
            )
            .bind(token_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(Error::storage)?;

        match row {
            None => Ok(None),
            Some((th, uid, exp, created, ip, ua)) => Ok(Some(Session {
                token_hash: th,
                user_id: UserId(Uuid::parse_str(&uid).map_err(Error::storage)?),
                expires_at: parse_dt(&exp)?,
                created_at: parse_dt(&created)?,
                ip_address: ip,
                user_agent: ua,
            })),
        }
    }

    async fn delete_session(&self, token_hash: &str) -> Result<()> {
        sqlx::query("DELETE FROM sessions WHERE token_hash = ?")
            .bind(token_hash)
            .execute(&self.pool)
            .await
            .map_err(Error::storage)?;
        Ok(())
    }

    async fn delete_sessions_for_user(&self, user_id: &UserId) -> Result<()> {
        sqlx::query("DELETE FROM sessions WHERE user_id = ?")
            .bind(user_id.0.to_string())
            .execute(&self.pool)
            .await
            .map_err(Error::storage)?;
        Ok(())
    }

    async fn create_verification(&self, input: NewVerification) -> Result<Verification> {
        let now = OffsetDateTime::now_utc();
        sqlx::query(
            r#"INSERT INTO verifications (identifier, purpose, value_hash, expires_at, created_at)
               VALUES (?, ?, ?, ?, ?)"#,
        )
        .bind(&input.identifier)
        .bind(&input.purpose)
        .bind(&input.value_hash)
        .bind(fmt_dt(input.expires_at))
        .bind(fmt_dt(now))
        .execute(&self.pool)
        .await
        .map_err(Error::storage)?;

        Ok(Verification {
            identifier: input.identifier,
            purpose: input.purpose,
            value_hash: input.value_hash,
            expires_at: input.expires_at,
            created_at: now,
        })
    }

    async fn consume_verification(
        &self,
        identifier: &str,
        purpose: &str,
        value_hash: &str,
    ) -> Result<Option<Verification>> {
        let mut tx = self.pool.begin().await.map_err(Error::storage)?;
        let row: Option<(String, String, String, String, String)> = sqlx::query_as(
            r#"SELECT identifier, purpose, value_hash, expires_at, created_at
               FROM verifications
               WHERE identifier = ? AND purpose = ? AND value_hash = ?"#,
        )
        .bind(identifier)
        .bind(purpose)
        .bind(value_hash)
        .fetch_optional(&mut *tx)
        .await
        .map_err(Error::storage)?;

        let Some((id, pu, vh, exp, created)) = row else {
            tx.commit().await.map_err(Error::storage)?;
            return Ok(None);
        };

        sqlx::query(
            r#"DELETE FROM verifications
               WHERE identifier = ? AND purpose = ? AND value_hash = ?"#,
        )
        .bind(&id)
        .bind(&pu)
        .bind(&vh)
        .execute(&mut *tx)
        .await
        .map_err(Error::storage)?;
        tx.commit().await.map_err(Error::storage)?;

        let expires_at = parse_dt(&exp)?;
        if expires_at <= OffsetDateTime::now_utc() {
            return Ok(None);
        }
        Ok(Some(Verification {
            identifier: id,
            purpose: pu,
            value_hash: vh,
            expires_at,
            created_at: parse_dt(&created)?,
        }))
    }

    async fn consume_verification_by_value(
        &self,
        purpose: &str,
        value_hash: &str,
    ) -> Result<Option<Verification>> {
        let mut tx = self.pool.begin().await.map_err(Error::storage)?;
        let row: Option<(String, String, String, String, String)> = sqlx::query_as(
            r#"SELECT identifier, purpose, value_hash, expires_at, created_at
               FROM verifications
               WHERE purpose = ? AND value_hash = ?"#,
        )
        .bind(purpose)
        .bind(value_hash)
        .fetch_optional(&mut *tx)
        .await
        .map_err(Error::storage)?;

        let Some((id, pu, vh, exp, created)) = row else {
            tx.commit().await.map_err(Error::storage)?;
            return Ok(None);
        };

        sqlx::query(r#"DELETE FROM verifications WHERE purpose = ? AND value_hash = ?"#)
            .bind(&pu)
            .bind(&vh)
            .execute(&mut *tx)
            .await
            .map_err(Error::storage)?;
        tx.commit().await.map_err(Error::storage)?;

        let expires_at = parse_dt(&exp)?;
        if expires_at <= OffsetDateTime::now_utc() {
            return Ok(None);
        }
        Ok(Some(Verification {
            identifier: id,
            purpose: pu,
            value_hash: vh,
            expires_at,
            created_at: parse_dt(&created)?,
        }))
    }

    async fn consume_verification_by_identifier(
        &self,
        identifier: &str,
        purpose: &str,
    ) -> Result<Option<Verification>> {
        let mut tx = self.pool.begin().await.map_err(Error::storage)?;
        let row: Option<(String, String, String, String, String)> = sqlx::query_as(
            r#"SELECT identifier, purpose, value_hash, expires_at, created_at
               FROM verifications
               WHERE identifier = ? AND purpose = ?"#,
        )
        .bind(identifier)
        .bind(purpose)
        .fetch_optional(&mut *tx)
        .await
        .map_err(Error::storage)?;

        let Some((id, pu, vh, exp, created)) = row else {
            tx.commit().await.map_err(Error::storage)?;
            return Ok(None);
        };

        sqlx::query(
            r#"DELETE FROM verifications WHERE identifier = ? AND purpose = ?"#,
        )
        .bind(&id)
        .bind(&pu)
        .execute(&mut *tx)
        .await
        .map_err(Error::storage)?;
        tx.commit().await.map_err(Error::storage)?;

        let expires_at = parse_dt(&exp)?;
        if expires_at <= OffsetDateTime::now_utc() {
            return Ok(None);
        }
        Ok(Some(Verification {
            identifier: id,
            purpose: pu,
            value_hash: vh,
            expires_at,
            created_at: parse_dt(&created)?,
        }))
    }

    // ---------- TOTP ----------

    async fn get_totp(&self, user_id: &UserId) -> Result<Option<TotpFactor>> {
        let row: Option<(String, String, i64, String)> = sqlx::query_as(
            r#"SELECT user_id, secret_b32, enabled, created_at
               FROM totp_factors WHERE user_id = ?"#,
        )
        .bind(user_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(Error::storage)?;
        let Some((uid, secret, enabled, created)) = row else {
            return Ok(None);
        };
        Ok(Some(TotpFactor {
            user_id: UserId(Uuid::parse_str(&uid).map_err(|e| Error::Plugin(e.to_string()))?),
            secret_b32: secret,
            enabled: enabled != 0,
            created_at: parse_dt(&created)?,
        }))
    }

    async fn upsert_totp(
        &self,
        user_id: &UserId,
        secret_b32: &str,
        enabled: bool,
    ) -> Result<()> {
        let now = fmt_dt(OffsetDateTime::now_utc());
        sqlx::query(
            r#"INSERT INTO totp_factors (user_id, secret_b32, enabled, created_at)
               VALUES (?, ?, ?, ?)
                             ON DUPLICATE KEY UPDATE
                                 secret_b32 = VALUES(secret_b32),
                                 enabled    = VALUES(enabled)"#,
        )
        .bind(user_id.to_string())
        .bind(secret_b32)
        .bind(if enabled { 1i64 } else { 0 })
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(Error::storage)?;
        Ok(())
    }

    async fn delete_totp(&self, user_id: &UserId) -> Result<()> {
        sqlx::query(r#"DELETE FROM totp_factors WHERE user_id = ?"#)
            .bind(user_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(Error::storage)?;
        Ok(())
    }

    // ---------- Organizations ----------

    async fn create_organization(&self, slug: &str, name: &str) -> Result<Organization> {
        let id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();
        sqlx::query(
            r#"INSERT INTO organizations (id, slug, name, created_at) VALUES (?, ?, ?, ?)"#,
        )
        .bind(id.to_string())
        .bind(slug)
        .bind(name)
        .bind(fmt_dt(now))
        .execute(&self.pool)
        .await
        .map_err(Error::storage)?;
        Ok(Organization {
            id: OrganizationId(id),
            slug: slug.to_string(),
            name: name.to_string(),
            created_at: now,
        })
    }

    async fn find_organization_by_id(
        &self,
        id: &OrganizationId,
    ) -> Result<Option<Organization>> {
        let row: Option<(String, String, String, String)> = sqlx::query_as(
            r#"SELECT id, slug, name, created_at FROM organizations WHERE id = ?"#,
        )
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(Error::storage)?;
        let Some((id, slug, name, created)) = row else {
            return Ok(None);
        };
        Ok(Some(Organization {
            id: OrganizationId(
                Uuid::parse_str(&id).map_err(|e| Error::Plugin(e.to_string()))?,
            ),
            slug,
            name,
            created_at: parse_dt(&created)?,
        }))
    }

    async fn find_organization_by_slug(&self, slug: &str) -> Result<Option<Organization>> {
        let row: Option<(String, String, String, String)> = sqlx::query_as(
            r#"SELECT id, slug, name, created_at FROM organizations WHERE LOWER(slug) = LOWER(?)"#,
        )
        .bind(slug)
        .fetch_optional(&self.pool)
        .await
        .map_err(Error::storage)?;
        let Some((id, slug, name, created)) = row else {
            return Ok(None);
        };
        Ok(Some(Organization {
            id: OrganizationId(
                Uuid::parse_str(&id).map_err(|e| Error::Plugin(e.to_string()))?,
            ),
            slug,
            name,
            created_at: parse_dt(&created)?,
        }))
    }

    async fn delete_organization(&self, id: &OrganizationId) -> Result<()> {
        sqlx::query(r#"DELETE FROM organizations WHERE id = ?"#)
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(Error::storage)?;
        Ok(())
    }

    async fn list_organizations_for_user(
        &self,
        user_id: &UserId,
    ) -> Result<Vec<(Organization, Role)>> {
        let rows: Vec<(String, String, String, String, String)> = sqlx::query_as(
            r#"SELECT o.id, o.slug, o.name, o.created_at, m.role
               FROM organizations o
               JOIN memberships m ON m.organization_id = o.id
               WHERE m.user_id = ?
               ORDER BY o.created_at DESC"#,
        )
        .bind(user_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(Error::storage)?;
        let mut out = Vec::with_capacity(rows.len());
        for (id, slug, name, created, role) in rows {
            out.push((
                Organization {
                    id: OrganizationId(
                        Uuid::parse_str(&id).map_err(|e| Error::Plugin(e.to_string()))?,
                    ),
                    slug,
                    name,
                    created_at: parse_dt(&created)?,
                },
                Role::from_str(&role)
                    .ok_or_else(|| Error::Plugin(format!("invalid role: {role}")))?,
            ));
        }
        Ok(out)
    }

    async fn add_member(
        &self,
        org_id: &OrganizationId,
        user_id: &UserId,
        role: Role,
    ) -> Result<Membership> {
        let now = OffsetDateTime::now_utc();
        sqlx::query(
            r#"INSERT INTO memberships (organization_id, user_id, role, created_at)
               VALUES (?, ?, ?, ?)
               ON DUPLICATE KEY UPDATE role = VALUES(role)"#,
        )
        .bind(org_id.to_string())
        .bind(user_id.to_string())
        .bind(role.as_str())
        .bind(fmt_dt(now))
        .execute(&self.pool)
        .await
        .map_err(Error::storage)?;
        Ok(Membership {
            organization_id: *org_id,
            user_id: *user_id,
            role,
            created_at: now,
        })
    }

    async fn update_member_role(
        &self,
        org_id: &OrganizationId,
        user_id: &UserId,
        role: Role,
    ) -> Result<()> {
        sqlx::query(
            r#"UPDATE memberships SET role = ? WHERE organization_id = ? AND user_id = ?"#,
        )
        .bind(org_id.to_string())
        .bind(user_id.to_string())
        .bind(role.as_str())
        .execute(&self.pool)
        .await
        .map_err(Error::storage)?;
        Ok(())
    }

    async fn remove_member(&self, org_id: &OrganizationId, user_id: &UserId) -> Result<()> {
        sqlx::query(
            r#"DELETE FROM memberships WHERE organization_id = ? AND user_id = ?"#,
        )
        .bind(org_id.to_string())
        .bind(user_id.to_string())
        .execute(&self.pool)
        .await
        .map_err(Error::storage)?;
        Ok(())
    }

    async fn find_membership(
        &self,
        org_id: &OrganizationId,
        user_id: &UserId,
    ) -> Result<Option<Membership>> {
        let row: Option<(String, String, String, String)> = sqlx::query_as(
            r#"SELECT organization_id, user_id, role, created_at
               FROM memberships WHERE organization_id = ? AND user_id = ?"#,
        )
        .bind(org_id.to_string())
        .bind(user_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(Error::storage)?;
        let Some((oid, uid, role, created)) = row else {
            return Ok(None);
        };
        Ok(Some(Membership {
            organization_id: OrganizationId(
                Uuid::parse_str(&oid).map_err(|e| Error::Plugin(e.to_string()))?,
            ),
            user_id: UserId(
                Uuid::parse_str(&uid).map_err(|e| Error::Plugin(e.to_string()))?,
            ),
            role: Role::from_str(&role)
                .ok_or_else(|| Error::Plugin(format!("invalid role: {role}")))?,
            created_at: parse_dt(&created)?,
        }))
    }

    async fn list_members(&self, org_id: &OrganizationId) -> Result<Vec<Membership>> {
        let rows: Vec<(String, String, String, String)> = sqlx::query_as(
            r#"SELECT organization_id, user_id, role, created_at
               FROM memberships WHERE organization_id = ?
               ORDER BY created_at ASC"#,
        )
        .bind(org_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(Error::storage)?;
        let mut out = Vec::with_capacity(rows.len());
        for (oid, uid, role, created) in rows {
            out.push(Membership {
                organization_id: OrganizationId(
                    Uuid::parse_str(&oid).map_err(|e| Error::Plugin(e.to_string()))?,
                ),
                user_id: UserId(
                    Uuid::parse_str(&uid).map_err(|e| Error::Plugin(e.to_string()))?,
                ),
                role: Role::from_str(&role)
                    .ok_or_else(|| Error::Plugin(format!("invalid role: {role}")))?,
                created_at: parse_dt(&created)?,
            });
        }
        Ok(out)
    }
}

type AccountRow = (
    String,         // user_id
    String,         // provider
    String,         // provider_account_id
    Option<String>, // password_hash
    Option<String>, // access_token
    Option<String>, // refresh_token
    Option<String>, // expires_at
    Option<String>, // scope
    Option<String>, // id_token
    String,         // created_at
    String,         // updated_at
);

fn row_to_user(
    row: (String, String, i64, Option<String>, Option<String>, String, String),
) -> Result<User> {
    let (id, email, verified, name, image, created, updated) = row;
    Ok(User {
        id: UserId(Uuid::parse_str(&id).map_err(Error::storage)?),
        email,
        email_verified: verified != 0,
        name,
        image,
        created_at: parse_dt(&created)?,
        updated_at: parse_dt(&updated)?,
    })
}

fn row_to_account(row: AccountRow) -> Result<Account> {
    let (
        user_id,
        provider,
        provider_account_id,
        password_hash,
        access_token,
        refresh_token,
        expires_at,
        scope,
        id_token,
        created_at,
        updated_at,
    ) = row;
    Ok(Account {
        user_id: UserId(Uuid::parse_str(&user_id).map_err(Error::storage)?),
        provider,
        provider_account_id,
        password_hash,
        access_token,
        refresh_token,
        expires_at: expires_at.as_deref().map(parse_dt).transpose()?,
        scope,
        id_token,
        created_at: parse_dt(&created_at)?,
        updated_at: parse_dt(&updated_at)?,
    })
}
