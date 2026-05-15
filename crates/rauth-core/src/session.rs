use crate::user::UserId;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Hashed token (sha256 hex). Never the raw token.
    pub token_hash: String,
    pub user_id: UserId,
    pub expires_at: OffsetDateTime,
    pub created_at: OffsetDateTime,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NewSession {
    pub token_hash: String,
    pub user_id: UserId,
    pub expires_at: OffsetDateTime,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

/// What the client receives — raw token + metadata.
#[derive(Debug, Clone, Serialize)]
pub struct IssuedSession {
    pub token: String,
    pub expires_at: OffsetDateTime,
}
