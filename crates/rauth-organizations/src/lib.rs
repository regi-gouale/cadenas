//! Organizations / teams / roles plugin.
//!
//! Domain types live in `rauth_core::organization` and are re-exported here.
//! This crate adds an Axum router and small business-logic helpers.

pub use rauth_core::organization::{Membership, Organization, OrganizationId, Role};

#[cfg(feature = "axum")]
pub mod axum_router;
