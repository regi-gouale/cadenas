# Copilot Instructions

## Build & Test

```sh
# Build the whole workspace
cargo build

# Run all tests
cargo test

# Run tests for a single crate
cargo test -p rauth-core

# Run a specific test
cargo test -p rauth-core <test_name>

# Check compilation without building
cargo check

# Lint
cargo clippy
```

Minimum supported Rust version: **1.75**. Default features are `axum` + `sqlite`; use them unless a task explicitly requires disabling defaults or enabling a different storage backend.

## Architecture

`rauth` is a Rust port of [better-auth](https://www.better-auth.com/): a batteries-included auth toolkit that mounts as a single Axum router.

The workspace is layered:

```
rauth-core            # HTTP- and DB-agnostic: domain types, Storage trait, Auth orchestrator, plugin system
rauth-storage-sqlx    # SQLx adapter implementing Storage (SQLite default; Postgres/MySQL behind features)
rauth-axum            # Mounts rauth-core's Auth as an Axum Router; exposes AuthSession extractor
rauth-oauth           # OAuth2/OIDC engine (PKCE) + Axum router; built-in Google & GitHub providers
rauth-totp            # TOTP 2FA enrolment/challenge + Axum router
rauth-organizations   # Org/team/role management + Axum router
rauth-rate-limit      # Token-bucket middleware; in-memory default, trait-pluggable
rauth                 # Umbrella crate: re-exports everything, gates each module behind a Cargo feature
```

`Auth` (in `rauth-core`) is the central orchestrator. It holds `Arc<dyn Storage>`, `Arc<dyn Hasher>`, `Arc<dyn Clock>`, `Arc<dyn Mailer>`, and a `Vec<SharedPlugin>`. It is cheap to clone (everything inside is `Arc`).

Session tokens are never stored raw — only a SHA-256 hash (`hash_token`) is persisted. The same pattern applies to verification tokens (email verify, password reset, TOTP challenge, OAuth state).

`Verification` is a general-purpose one-time-token table used for: email verification, password reset, TOTP challenges, and OAuth PKCE `state`. Every token is consumed atomically on first use.

## Key Conventions

### Error handling

All public functions return `rauth_core::Result<T>` (alias for `std::result::Result<T, rauth_core::Error>`). Use the constructors:

- `Error::bad_request("msg")` for validation failures
- `Error::storage(err)` for DB errors (wraps any `std::error::Error + Send + Sync + 'static`)
- `Error::Plugin("msg".into())` for errors originating in OAuth/plugin code

`ApiError` in `rauth-axum` is a newtype over `Error` that implements `IntoResponse` — map the domain error to the right HTTP status there, not in `rauth-core`.

### Storage trait

Every new persistence operation must be added to the `Storage` trait in `rauth-core/src/storage.rs` and implemented in all three backends (`sqlite.rs`, `postgres.rs`, `mysql.rs`). The schema is embedded as a const string in each backend file and applied via `.migrate()`.

### Feature flags (`rauth` umbrella crate)

Use these feature flags on `rauth`:

- `axum`: enables the Axum integration crate (`rauth-axum`)
- `sqlite`: enables SQLx SQLite storage (`rauth-storage-sqlx/sqlite`)
- `postgres`: enables SQLx PostgreSQL storage (`rauth-storage-sqlx/postgres`)
- `mysql`: enables SQLx MySQL storage (`rauth-storage-sqlx/mysql`)
- `oauth`: enables OAuth/OIDC support (`rauth-oauth`)
- `totp`: enables TOTP 2FA support (`rauth-totp`)
- `organizations`: enables organizations support (`rauth-organizations`)
- `rate-limit`: enables rate-limiting middleware (`rauth-rate-limit`)
- `full`: enables all optional modules above

Default feature set: `["axum", "sqlite"]`.

### Plugin system

Plugins implement the `Plugin` trait (`rauth-core/src/plugin.rs`) with optional hooks: `on_user_created`, `before_sign_in`, `after_sign_in`, `before_sign_out`. All hooks default to no-op.

### Token & cookie flow

- Session tokens: `random_token(32)` → raw token returned to client, `hash_token` stored in DB
- `AuthSession` extractor accepts both `Bearer <token>` (Authorization header) and the session cookie (`rauth.session` by default, configurable via `AuthConfig::session_cookie_name`)
- `trust_proxy: true` is required to read `X-Forwarded-For`

### TOTP sign-in interruption

`Auth::sign_in_email` returns `SignInResult::TotpRequired { challenge_token, user_id }` (HTTP 202) instead of issuing a session when the user has TOTP enabled. The client must then call `/totp/challenge` with `{ challenge_token, code }`.

### Domain ID types

User IDs and org IDs are newtype wrappers around `uuid::Uuid` (e.g. `UserId(Uuid)`). Always use `.to_string()` when serializing to JSON responses.

### Time

Use `time::OffsetDateTime` (the `time` crate, not `std::time` or `chrono`). The `Clock` trait (`time_provider.rs`) abstracts wall time to enable deterministic tests.
