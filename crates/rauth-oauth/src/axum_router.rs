//! Axum router for OAuth start + callback.
//!
//! Mount as `Router::nest("/api/auth/oauth", rauth_oauth::axum_router::router(oauth))`.
//!
//! * `GET /{provider}/start` → 302 to provider authorize URL.
//! * `GET /{provider}/callback?code=...&state=...` → exchanges, sets the
//!   session cookie, then redirects to `?redirect=...` if provided, else `/`.

use axum::{
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Redirect, Response},
    routing::get,
    Router,
};
use rauth_axum::ApiError;
use serde::Deserialize;

use crate::OAuth;

pub fn router(oauth: OAuth) -> Router {
    Router::new()
        .route("/:provider/start", get(start))
        .route("/:provider/callback", get(callback))
        .with_state(oauth)
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct StartQuery {
    redirect: Option<String>,
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    redirect: Option<String>,
}

async fn start(
    State(oauth): State<OAuth>,
    Path(provider): Path<String>,
    Query(_q): Query<StartQuery>,
) -> Result<Response, ApiError> {
    let url = oauth.start(&provider).await?;
    Ok(Redirect::to(&url).into_response())
}

async fn callback(
    State(oauth): State<OAuth>,
    Path(provider): Path<String>,
    Query(q): Query<CallbackQuery>,
    headers: axum::http::HeaderMap,
) -> Result<Response, ApiError> {
    if let Some(err) = q.error {
        return Ok((StatusCode::BAD_REQUEST, format!("oauth error: {err}")).into_response());
    }
    let code = q.code.ok_or_else(|| ApiError(rauth_core::Error::bad_request("missing code")))?;
    let state = q.state.ok_or_else(|| ApiError(rauth_core::Error::bad_request("missing state")))?;

    let ua = headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok()).map(str::to_string);

    let (_user, issued) = oauth.callback(&provider, &code, &state, None, ua).await?;
    let cookie = build_session_cookie(oauth.auth(), &issued);
    let redirect_to = q.redirect.unwrap_or_else(|| "/".to_string());

    Ok(([(header::SET_COOKIE, cookie)], Redirect::to(&redirect_to)).into_response())
}

fn build_session_cookie(
    auth: &rauth_core::Auth,
    issued: &rauth_core::session::IssuedSession,
) -> String {
    let max_age = (issued.expires_at - auth.clock().now()).whole_seconds().max(0);
    format!(
        "{}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}",
        auth.config().session_cookie_name,
        issued.token,
        max_age
    )
}
