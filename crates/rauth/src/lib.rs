//! `rauth` — better-auth, in Rust.
//!
//! This crate is an umbrella that re-exports the building blocks. Pick the
//! Cargo features you need (`axum`, `sqlite`, `oauth`, `totp`, ...).
//!
//! ```ignore
//! use rauth::{Auth, AuthConfig};
//! use rauth::storage::SqliteStorage;
//! use sqlx::sqlite::SqlitePoolOptions;
//!
//! # async fn run() -> rauth::Result<()> {
//! let pool = SqlitePoolOptions::new().connect("sqlite::memory:").await.unwrap();
//! let storage = SqliteStorage::new(pool);
//! storage.migrate().await?;
//!
//! let auth = Auth::builder()
//!     .storage(storage)
//!     .config(AuthConfig::default())
//!     .build()?;
//!
//! let app = axum::Router::new()
//!     .nest("/api/auth", rauth::axum::router(auth));
//! # let _ = app;
//! # Ok(())
//! # }
//! ```

pub use rauth_core::*;

#[cfg(feature = "axum")]
pub mod axum {
    pub use rauth_axum::*;
}

#[cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]
pub mod storage {
    pub use rauth_storage_sqlx::*;
}

#[cfg(feature = "oauth")]
pub mod oauth {
    pub use rauth_oauth::*;
}

#[cfg(feature = "totp")]
pub mod totp {
    pub use rauth_totp::*;
}

#[cfg(feature = "organizations")]
pub mod organizations {
    pub use rauth_organizations::*;
}

#[cfg(feature = "rate-limit")]
pub mod rate_limit {
    pub use rauth_rate_limit::*;
}
