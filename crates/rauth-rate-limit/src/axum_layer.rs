//! Axum middleware that enforces a [`RateLimiter`] on incoming requests.
//!
//! Use [`limit`] to wrap any handler with a per-IP+route bucket:
//!
//! ```ignore
//! use std::sync::Arc;
//! use std::time::Duration;
//! use axum::{Router, routing::post, middleware};
//! use rauth_rate_limit::{InMemoryRateLimiter, axum_layer::limit};
//!
//! let limiter = Arc::new(InMemoryRateLimiter::new(10, Duration::from_secs(60)));
//! let app: Router = Router::new()
//!     .route("/sign-in", post(handler))
//!     .layer(middleware::from_fn_with_state(limiter, limit));
//! ```

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};

use crate::RateLimiter;

/// Middleware function suitable for `axum::middleware::from_fn_with_state`.
///
/// Key = `"{client_ip}:{path}"`. Falls back to `"unknown"` when no IP can be
/// extracted (request did not include `x-forwarded-for` and the connect_info
/// extension is unavailable).
pub async fn limit(
    State(limiter): State<Arc<dyn RateLimiter>>,
    req: Request,
    next: Next,
) -> Response {
    let ip = client_ip(&req).unwrap_or_else(|| "unknown".into());
    let path = req.uri().path().to_string();
    let key = format!("{ip}:{path}");

    if !limiter.check(&key).await {
        let body = Json(serde_json::json!({
            "error": "rate_limited",
            "message": "too many requests",
        }));
        return (StatusCode::TOO_MANY_REQUESTS, body).into_response();
    }

    next.run(req).await
}

fn client_ip(req: &Request) -> Option<String> {
    if let Some(v) = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
    {
        if let Some(first) = v.split(',').next() {
            return Some(first.trim().to_string());
        }
    }
    if let Some(v) = req.headers().get("x-real-ip").and_then(|v| v.to_str().ok()) {
        return Some(v.trim().to_string());
    }
    None
}
