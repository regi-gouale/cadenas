use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Generic verification token (email verification, password reset, magic link, ...).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verification {
    /// Logical identifier (e.g. email address or user id).
    pub identifier: String,
    /// Purpose tag, e.g. "email_verify", "password_reset".
    pub purpose: String,
    /// SHA-256 hex digest of the secret token.
    pub value_hash: String,
    pub expires_at: OffsetDateTime,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone)]
pub struct NewVerification {
    pub identifier: String,
    pub purpose: String,
    pub value_hash: String,
    pub expires_at: OffsetDateTime,
}
