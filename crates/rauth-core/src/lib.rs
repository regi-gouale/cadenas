//! `rauth-core` — building blocks for [`rauth`], a Rust port of better-auth.
//!
//! This crate is HTTP- and database-agnostic. It defines:
//! * Domain types (`User`, `Session`, `Account`, `Verification`).
//! * The [`storage::Storage`] trait every backend implements.
//! * Password hashing, token generation, time abstraction.
//! * The high-level [`auth::Auth`] orchestrator and its plugin system.

pub mod error;
pub mod time_provider;
pub mod token;
pub mod password;
pub mod mailer;
pub mod totp_codes;
pub mod user;
pub mod session;
pub mod account;
pub mod verification;
pub mod totp;
pub mod organization;
pub mod storage;
pub mod plugin;
pub mod auth;
pub mod config;

pub use error::{Error, Result};
pub use auth::Auth;
pub use config::AuthConfig;
pub use storage::Storage;
