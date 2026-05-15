use crate::user::UserId;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpFactor {
    pub user_id: UserId,
    pub secret_b32: String,
    pub enabled: bool,
    pub created_at: OffsetDateTime,
}
