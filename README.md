# rauth — better-auth, in Rust

`rauth` is a port of [better-auth](https://www.better-auth.com/) to Rust. The
goal is to give Rust applications the same batteries-included authentication
toolkit: email + password, OAuth, 2FA, organizations, sessions, plugins.

> Status: **early but usable**. Email/password, sessions, email verification,
> password reset, OAuth (Google + GitHub with PKCE), TOTP 2FA, organizations
> and a token-bucket rate limiter are all implemented behind a single Axum
> router. SQLite is the default adapter; Postgres / MySQL are available behind
> Cargo features.

## Workspace layout

```
crates/
  rauth-core/           Core types, traits, sessions, password hashing, TOTP algo
  rauth-storage-sqlx/   SQLx adapter (SQLite, Postgres, MySQL)
  rauth-axum/           Axum HTTP adapter — `auth.handler` equivalent
  rauth-oauth/          OAuth2 / OIDC plugin (Google, GitHub, generic) + Axum router
  rauth-totp/           TOTP 2FA enrolment / challenge endpoints
  rauth-organizations/  Organizations / teams / roles + Axum router
  rauth-rate-limit/     Token-bucket rate limiter + Axum middleware
  rauth/                Umbrella crate re-exporting the above
examples/
  axum-sqlite/          End-to-end example wiring everything together
```

## Quick start

```rust
use rauth::{storage::SqliteStorage, Auth, AuthConfig};
use sqlx::sqlite::SqlitePoolOptions;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pool = SqlitePoolOptions::new().connect("sqlite::memory:").await?;
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

### HTTP endpoints

Mounted under whatever prefix you choose (the example uses `/api/auth`).

#### Email + password (always on)

| Method | Path                      | Body                                                          |
| ------ | ------------------------- | ------------------------------------------------------------- |
| POST   | `/sign-up/email`          | `{ email, password, name? }`                                  |
| POST   | `/sign-in/email`          | `{ email, password }` — returns session **or** TOTP challenge |
| POST   | `/sign-out`               | —                                                             |
| GET    | `/session`                | —                                                             |
| POST   | `/verify-email/request`   | `{ email }`                                                   |
| POST   | `/verify-email`           | `{ token }`                                                   |
| POST   | `/password-reset/request` | `{ email }`                                                   |
| POST   | `/password-reset`         | `{ token, new_password }`                                     |

When the user has TOTP enabled, `/sign-in/email` responds `202 Accepted` with
`{ totp_required: true, challenge_token, user_id }` instead of issuing a session.

#### TOTP (`rauth_totp::axum_router::router`)

| Method | Path         | Auth | Body                        |
| ------ | ------------ | ---- | --------------------------- |
| POST   | `/setup`     | yes  | —                           |
| POST   | `/confirm`   | yes  | `{ code }`                  |
| POST   | `/disable`   | yes  | `{ code }`                  |
| POST   | `/challenge` | no   | `{ challenge_token, code }` |

#### OAuth (`rauth_oauth::axum_router::router`)

| Method | Path                   | Description                                    |
| ------ | ---------------------- | ---------------------------------------------- |
| GET    | `/{provider}/start`    | Redirects to the provider authorize URL (PKCE) |
| GET    | `/{provider}/callback` | Exchanges code, links account, sets session    |

Built-in providers: `OAuthProvider::google(...)`, `OAuthProvider::github(...)`.
Generic providers can be constructed by filling `OAuthProvider` directly.

#### Organizations (`rauth_organizations::axum_router::router`)

| Method | Path                      | Auth | Notes                              |
| ------ | ------------------------- | ---- | ---------------------------------- |
| POST   | `/`                       | yes  | Caller becomes Owner               |
| GET    | `/`                       | yes  | Lists caller's orgs + role         |
| GET    | `/{id}`                   | yes  | Member only                        |
| DELETE | `/{id}`                   | yes  | Owner only                         |
| GET    | `/{id}/members`           | yes  | Member only                        |
| POST   | `/{id}/members`           | yes  | Admin/Owner; cannot grant >self    |
| PATCH  | `/{id}/members/{user_id}` | yes  | Admin/Owner; cannot grant >self    |
| DELETE | `/{id}/members/{user_id}` | yes  | Admin/Owner; member can leave self |

#### Rate limiting (`rauth_rate_limit::axum_layer::limit`)

```rust
use std::{sync::Arc, time::Duration};
use axum::middleware;
use rauth::rate_limit::{InMemoryRateLimiter, RateLimiter, axum_layer::limit};

let limiter: Arc<dyn RateLimiter> =
    Arc::new(InMemoryRateLimiter::new(10, Duration::from_secs(60)));

let app = router.layer(middleware::from_fn_with_state(limiter, limit));
```

Plug your own `RateLimiter` impl (e.g. Redis-backed) without touching the router.

In your own Axum handlers, extract the session with `rauth::axum::AuthSession`.

## Roadmap

- [x] Email + password, sessions, cookies + bearer
- [x] SQLite storage (SQLx)
- [x] Axum mountable router + extractor
- [x] Email verification + password reset endpoints
- [x] OAuth2 providers (Google, GitHub) with PKCE + account linking
- [x] TOTP 2FA enrolment + challenge
- [x] Organizations, teams, roles
- [x] Rate-limit middleware
- [ ] Magic link / OTP email
- [x] Postgres + MySQL adapters
- [ ] Passkeys / WebAuthn

## License

Dual-licensed under MIT or Apache-2.0.
