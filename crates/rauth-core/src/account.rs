use crate::user::UserId;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// An authentication account: either a credentials record (provider="credentials")
/// or a federated identity (provider="google", "github", ...).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub user_id: UserId,
    pub provider: String,
    pub provider_account_id: String,
    pub password_hash: Option<String>,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub expires_at: Option<OffsetDateTime>,
    pub scope: Option<String>,
    pub id_token: Option<String>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Clone)]
pub struct NewAccount {
    pub user_id: UserId,
    pub provider: String,
    pub provider_account_id: String,
    pub password_hash: Option<String>,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub expires_at: Option<OffsetDateTime>,
    pub scope: Option<String>,
    pub id_token: Option<String>,
}
