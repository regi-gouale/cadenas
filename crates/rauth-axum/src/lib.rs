//! Axum integration for [`rauth_core::Auth`].
//!
//! Mount the router under any base path:
//!
//! ```ignore
//! let app = axum::Router::new()
//!     .nest("/api/auth", rauth_axum::router(auth.clone()));
//! ```
//!
//! Extract the current session in your own handlers via [`AuthSession`].

use axum::{
    async_trait,
    extract::{FromRef, FromRequestParts, State},
    http::{header, request::Parts, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use rauth_core::{
    auth::SignInResult,
    error::Error,
    session::{IssuedSession, Session},
    user::User,
    Auth,
};
use serde::{Deserialize, Serialize};

/// Build the mountable auth router.
pub fn router(auth: Auth) -> Router {
    Router::new()
        .route("/sign-up/email", post(sign_up_email))
        .route("/sign-in/email", post(sign_in_email))
        .route("/sign-out", post(sign_out))
        .route("/session", get(get_session))
        .route("/verify-email/request", post(request_email_verification))
        .route("/verify-email", post(verify_email))
        .route("/password-reset/request", post(request_password_reset))
        .route("/password-reset", post(reset_password))
        .with_state(auth)
}

#[derive(Deserialize)]
struct SignUpEmailBody {
    email: String,
    password: String,
    name: Option<String>,
}

#[derive(Deserialize)]
struct SignInEmailBody {
    email: String,
    password: String,
}

#[derive(Serialize)]
struct UserDto<'a> {
    id: String,
    email: &'a str,
    email_verified: bool,
    name: Option<&'a str>,
    image: Option<&'a str>,
}

impl<'a> From<&'a User> for UserDto<'a> {
    fn from(u: &'a User) -> Self {
        Self {
            id: u.id.to_string(),
            email: &u.email,
            email_verified: u.email_verified,
            name: u.name.as_deref(),
            image: u.image.as_deref(),
        }
    }
}

#[derive(Serialize)]
struct SignInResponse<'a> {
    user: UserDto<'a>,
    session: &'a IssuedSession,
}

async fn sign_up_email(
    State(auth): State<Auth>,
    Json(body): Json<SignUpEmailBody>,
) -> Result<Response, ApiError> {
    let user = auth
        .sign_up_email(&body.email, &body.password, body.name)
        .await?;
    Ok((StatusCode::CREATED, Json(UserDto::from(&user))).into_response())
}

async fn sign_in_email(
    State(auth): State<Auth>,
    headers: axum::http::HeaderMap,
    Json(body): Json<SignInEmailBody>,
) -> Result<Response, ApiError> {
    let ip = client_ip(&headers, auth.config().trust_proxy);
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let result = auth
        .sign_in_email(&body.email, &body.password, ip, ua)
        .await?;

    match result {
        SignInResult::Authenticated { user, session: issued } => {
            let cookie = build_cookie(&auth, &issued);
            let body = Json(SignInResponse {
                user: UserDto::from(&user),
                session: &issued,
            });
            Ok(([(header::SET_COOKIE, cookie)], body).into_response())
        }
        SignInResult::TotpRequired {
            challenge_token,
            user_id,
        } => Ok((
            StatusCode::ACCEPTED,
            Json(serde_json::json!({
                "totp_required": true,
                "challenge_token": challenge_token,
                "user_id": user_id.to_string(),
            })),
        )
            .into_response()),
    }
}

async fn sign_out(
    State(auth): State<Auth>,
    headers: axum::http::HeaderMap,
) -> Result<Response, ApiError> {
    if let Some(token) = extract_token(&auth, &headers) {
        auth.sign_out(&token).await?;
    }
    let clear = clear_cookie(&auth);
    Ok(([(header::SET_COOKIE, clear)], StatusCode::NO_CONTENT).into_response())
}

async fn get_session(
    State(auth): State<Auth>,
    headers: axum::http::HeaderMap,
) -> Result<Response, ApiError> {
    let Some(token) = extract_token(&auth, &headers) else {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };
    let (user, _session) = auth.validate_session(&token).await?;
    Ok(Json(UserDto::from(&user)).into_response())
}

#[derive(Deserialize)]
struct EmailBody {
    email: String,
}

#[derive(Deserialize)]
struct TokenBody {
    token: String,
}

#[derive(Deserialize)]
struct ResetPasswordBody {
    token: String,
    password: String,
}

async fn request_email_verification(
    State(auth): State<Auth>,
    Json(body): Json<EmailBody>,
) -> Result<Response, ApiError> {
    auth.request_email_verification(&body.email).await?;
    Ok(StatusCode::ACCEPTED.into_response())
}

async fn verify_email(
    State(auth): State<Auth>,
    Json(body): Json<TokenBody>,
) -> Result<Response, ApiError> {
    let user = auth.verify_email(&body.token).await?;
    Ok(Json(UserDto::from(&user)).into_response())
}

async fn request_password_reset(
    State(auth): State<Auth>,
    Json(body): Json<EmailBody>,
) -> Result<Response, ApiError> {
    auth.request_password_reset(&body.email).await?;
    Ok(StatusCode::ACCEPTED.into_response())
}

async fn reset_password(
    State(auth): State<Auth>,
    Json(body): Json<ResetPasswordBody>,
) -> Result<Response, ApiError> {
    let user = auth.reset_password(&body.token, &body.password).await?;
    Ok(Json(UserDto::from(&user)).into_response())
}

/// Axum extractor that resolves the current authenticated session.
pub struct AuthSession {
    pub user: User,
    pub session: Session,
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthSession
where
    S: Send + Sync,
    Auth: FromRef<S>,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth = Auth::from_ref(state);
        let token = extract_token(&auth, &parts.headers).ok_or(ApiError(Error::Unauthorized))?;
        let (user, session) = auth.validate_session(&token).await?;
        Ok(Self { user, session })
    }
}

// ----------- helpers -----------

pub fn extract_token(auth: &Auth, headers: &axum::http::HeaderMap) -> Option<String> {
    if let Some(h) = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        if let Some(rest) = h.strip_prefix("Bearer ") {
            return Some(rest.trim().to_string());
        }
    }
    let cookie_name = &auth.config().session_cookie_name;
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(';'))
        .map(str::trim)
        .find_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            (k == cookie_name).then(|| v.to_string())
        })
}

pub fn client_ip(headers: &axum::http::HeaderMap, trust_proxy: bool) -> Option<String> {
    if trust_proxy {
        if let Some(v) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            if let Some(first) = v.split(',').next() {
                return Some(first.trim().to_string());
            }
        }
    }
    None
}

pub fn build_cookie(auth: &Auth, issued: &IssuedSession) -> String {
    let max_age = (issued.expires_at - auth.clock().now()).whole_seconds().max(0);
    format!(
        "{}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}",
        auth.config().session_cookie_name,
        issued.token,
        max_age
    )
}

pub fn clear_cookie(auth: &Auth) -> String {
    format!(
        "{}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0",
        auth.config().session_cookie_name
    )
}

/// Newtype to convert [`rauth_core::Error`] into HTTP responses.
pub struct ApiError(pub Error);

impl From<Error> for ApiError {
    fn from(e: Error) -> Self {
        Self(e)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = match &self.0 {
            Error::InvalidCredentials => (StatusCode::UNAUTHORIZED, "invalid_credentials"),
            Error::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Error::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
            Error::UserAlreadyExists => (StatusCode::CONFLICT, "user_exists"),
            Error::UserNotFound => (StatusCode::NOT_FOUND, "user_not_found"),
            Error::InvalidSession => (StatusCode::UNAUTHORIZED, "invalid_session"),
            Error::InvalidVerification => (StatusCode::BAD_REQUEST, "invalid_verification"),
            Error::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
            Error::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request"),
            Error::Password(_) => (StatusCode::INTERNAL_SERVER_ERROR, "password_error"),
            Error::Storage(_) => (StatusCode::INTERNAL_SERVER_ERROR, "storage_error"),
            Error::Plugin(_) => (StatusCode::INTERNAL_SERVER_ERROR, "plugin_error"),
            Error::Other(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        };
        let body = serde_json::json!({
            "error": code,
            "message": self.0.to_string(),
        });
        (status, Json(body)).into_response()
    }
}
