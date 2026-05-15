//! Axum router for TOTP enrolment + sign-in second factor.
//!
//! Mount as `Router::nest("/api/auth/totp", rauth_totp::axum_router::router(auth))`.
//!
//! * `POST /setup`     — auth required. Generates secret, returns `{secret, otpauth_uri}`.
//! * `POST /confirm`   — auth required. Body `{code}`. Marks factor enabled.
//! * `POST /disable`   — auth required. Body `{code}`. Removes the factor.
//! * `POST /challenge` — public. Body `{challenge_token, code}`. Returns session cookie.

use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use rauth_axum::{build_cookie, client_ip, ApiError, AuthSession};
use rauth_core::Auth;
use serde::Deserialize;

pub fn router(auth: Auth) -> Router {
    Router::new()
        .route("/setup", post(setup))
        .route("/confirm", post(confirm))
        .route("/disable", post(disable))
        .route("/challenge", post(challenge))
        .with_state(auth)
}

#[derive(Deserialize)]
struct CodeBody {
    code: String,
}

#[derive(Deserialize)]
struct ChallengeBody {
    challenge_token: String,
    code: String,
}

async fn setup(
    State(auth): State<Auth>,
    session: AuthSession,
) -> Result<Response, ApiError> {
    let issuer = derive_issuer(&auth);
    let (secret, uri) = auth.enroll_totp(&session.user, &issuer).await?;
    Ok(Json(serde_json::json!({ "secret": secret, "otpauth_uri": uri })).into_response())
}

async fn confirm(
    State(auth): State<Auth>,
    session: AuthSession,
    Json(body): Json<CodeBody>,
) -> Result<Response, ApiError> {
    auth.confirm_totp(&session.user, &body.code).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn disable(
    State(auth): State<Auth>,
    session: AuthSession,
    Json(body): Json<CodeBody>,
) -> Result<Response, ApiError> {
    auth.disable_totp(&session.user, &body.code).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn challenge(
    State(auth): State<Auth>,
    headers: axum::http::HeaderMap,
    Json(body): Json<ChallengeBody>,
) -> Result<Response, ApiError> {
    let ip = client_ip(&headers, auth.config().trust_proxy);
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    let (user, issued) = auth
        .complete_totp_challenge(&body.challenge_token, &body.code, ip, ua)
        .await?;
    let cookie = build_cookie(&auth, &issued);
    Ok((
        [(header::SET_COOKIE, cookie)],
        Json(serde_json::json!({
            "user": { "id": user.id.to_string(), "email": user.email },
            "session": { "expires_at": issued.expires_at.to_string() },
        })),
    )
        .into_response())
}

fn derive_issuer(auth: &Auth) -> String {
    let url = auth.config().base_url.as_str();
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_else(|| "rauth".into())
}
