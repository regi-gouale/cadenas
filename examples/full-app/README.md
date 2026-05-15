# rauth — full-app example

A small but complete Axum app on top of `rauth`:

- **email + password** sign-up / sign-in
- **email verification** + **password reset** (links printed to the console via the default `LogMailer`)
- **TOTP 2FA** enrolment (`/api/auth/totp/setup` → `confirm`) and second-factor challenge during sign-in
- optional **OAuth** (Google, GitHub) — auto-mounted when env vars are set
- **Organizations** REST API
- **Rate limit** middleware (30 req/min/(IP,path))
- A tiny **notes API** (`/api/notes`) demonstrating how to consume `AuthSession` in your own handlers
- A single-page HTML UI served at `/`

## Run

```bash
cargo run -p rauth-example-full-app
```

then open <http://localhost:3000>.

The SQLite database persists to `./rauth-demo.sqlite`. Delete the file to start fresh.

## Environment

| Variable                       | Default                                            |
| ------------------------------ | -------------------------------------------------- |
| `DATABASE_URL`                 | `sqlite://./rauth-demo.sqlite?mode=rwc`            |
| `RAUTH_BASE_URL`               | `http://localhost:3000`                            |
| `GOOGLE_OAUTH_CLIENT_ID`       | _unset → Google OAuth disabled_                    |
| `GOOGLE_OAUTH_CLIENT_SECRET`   |                                                    |
| `GITHUB_OAUTH_CLIENT_ID`       | _unset → GitHub OAuth disabled_                    |
| `GITHUB_OAUTH_CLIENT_SECRET`   |                                                    |
| `RUST_LOG`                     | `info,rauth=debug,sqlx=warn`                       |

When OAuth providers are configured, the redirect URIs registered with the
provider should be:

```
{RAUTH_BASE_URL}/api/auth/oauth/google/callback
{RAUTH_BASE_URL}/api/auth/oauth/github/callback
```

## Routes

| Path                                | Description                                    |
| ----------------------------------- | ---------------------------------------------- |
| `GET  /`                            | Demo SPA (sign-in / sign-up / notes / TOTP)    |
| `*    /api/auth/...`                | All `rauth` auth endpoints (see top-level README) |
| `*    /api/auth/totp/...`           | TOTP enrol / confirm / disable / challenge     |
| `*    /api/auth/organizations/...`  | Organizations CRUD + memberships               |
| `*    /api/auth/oauth/...`          | OAuth start + callback (when configured)       |
| `GET  /api/notes`                   | List the signed-in user's notes                |
| `POST /api/notes`                   | `{ content }` — create a note                  |
| `DELETE /api/notes/{id}`            | Delete a note                                  |

## Demo TOTP flow

1. Sign up + sign in.
2. Click **Enroll TOTP** in the dashboard. A `otpauth://` URI is shown.
3. Add the URI to Google Authenticator / 1Password / Bitwarden, then submit
   the 6-digit code in the **Confirm** form.
4. Sign out, sign in again — the form will switch to the TOTP challenge step.

## Demo email-verification / password-reset

`LogMailer` prints the magic link to the terminal. Look for a line starting
with `verification email link:` or `password reset email link:` and open it
in your browser.
