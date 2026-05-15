//! Organizations, teams and roles plugin (scaffold).
//!
//! Domain types are defined here; the storage trait extension and HTTP
//! endpoints will be added in a follow-up.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(transparent)]
pub struct OrganizationId(pub Uuid);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Organization {
    pub id: OrganizationId,
    pub slug: String,
    pub name: String,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Owner,
    Admin,
    Member,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Membership {
    pub organization_id: OrganizationId,
    pub user_id: rauth_core::user::UserId,
    pub role: Role,
    pub created_at: OffsetDateTime,
}
