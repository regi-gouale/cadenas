# rauth — better-auth, in Rust

`rauth` is a port of [better-auth](https://www.better-auth.com/) to Rust. The
goal is to give Rust applications the same batteries-included authentication
toolkit: email + password, OAuth, 2FA, organizations, sessions, plugins.

> Status: **early scaffold**. The MVP (email/password + sessions + Axum +
> SQLite) is implemented end-to-end. OAuth, TOTP, organizations and rate
> limiting are scaffolded as separate crates and will be fleshed out next.

## Workspace layout

```
crates/
  rauth-core/           Core types, traits, sessions, password hashing
  rauth-storage-sqlx/   SQLx adapter (SQLite today; Postgres / MySQL behind features)
  rauth-axum/           Axum HTTP adapter — `auth.handler` equivalent
  rauth-oauth/          OAuth2 / OIDC plugin (scaffold)
  rauth-totp/           TOTP 2FA plugin
  rauth-organizations/  Organizations / teams / roles (scaffold)
  rauth-rate-limit/     Token-bucket rate limiter
  rauth/                Umbrella crate re-exporting the above
examples/
  axum-sqlite/          Minimal end-to-end example
```

## Quick start

```rust
use rauth::{storage::SqliteStorage, Auth, AuthConfig};
use sqlx::sqlite::SqlitePoolOptions;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pool = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await?;
    let storage = SqliteStorage::new(pool);
    storage.migrate().await?;

    let auth = Auth::builder()
        .storage(storage)
        .config(AuthConfig::default())
        .build()?;

    let app = axum::Router::new()
        .nest("/api/auth", rauth::axum::router(auth));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
```

### HTTP endpoints exposed today

| Method | Path                    | Body                              | Description                         |
| ------ | ----------------------- | --------------------------------- | ----------------------------------- |
| POST   | `/sign-up/email`        | `{ email, password, name? }`      | Create a user with credentials      |
| POST   | `/sign-in/email`        | `{ email, password }`             | Sign in, sets `rauth.session` cookie |
| POST   | `/sign-out`             | —                                 | Revoke current session              |
| GET    | `/session`              | —                                 | Returns the current user (or 401)   |

In your own Axum handlers, extract the session with `rauth::axum::AuthSession`.

## Roadmap

- [x] Email + password, sessions, cookies + bearer
- [x] SQLite storage (SQLx)
- [x] Axum mountable router + extractor
- [ ] OAuth2 providers (Google, GitHub, …) — start/callback, PKCE, account linking
- [ ] TOTP 2FA enrolment + challenge endpoints
- [ ] Magic link / OTP email
- [ ] Email verification + password reset endpoints
- [ ] Organizations, teams, roles
- [ ] Rate limit middleware wired into the router
- [ ] Postgres + MySQL adapters
- [ ] Passkeys / WebAuthn

## License

Dual-licensed under MIT or Apache-2.0.
