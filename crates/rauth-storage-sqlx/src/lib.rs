//! SQLx-backed [`Storage`](rauth_core::Storage) implementations.
//!
//! Enable a backend with a Cargo feature: `sqlite` (default), `postgres`, `mysql`.

#[cfg(feature = "sqlite")]
pub mod sqlite;

#[cfg(feature = "sqlite")]
pub use sqlite::SqliteStorage;
