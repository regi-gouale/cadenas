//! SQLx-backed [`Storage`](rauth_core::Storage) implementations.
//!
//! Enable a backend with a Cargo feature: `sqlite` (default), `postgres`, `mysql`.

#[cfg(feature = "sqlite")]
pub mod sqlite;

#[cfg(feature = "sqlite")]
pub use sqlite::SqliteStorage;

#[cfg(feature = "postgres")]
pub mod postgres;

#[cfg(feature = "postgres")]
pub use postgres::PostgresStorage;

#[cfg(feature = "mysql")]
pub mod mysql;

#[cfg(feature = "mysql")]
pub use mysql::MySqlStorage;
