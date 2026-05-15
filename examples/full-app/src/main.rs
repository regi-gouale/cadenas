//! End-to-end demo wiring `rauth` into a small "personal notes" app.
//!
//! Run:
//!     cargo run -p rauth-example-full-app
//!
//! Open: http://localhost:3000
//!
//! Optional environment variables:
//!     DATABASE_URL                  default: sqlite://./rauth-demo.sqlite?mode=rwc
//!     RAUTH_BASE_URL                default: http://localhost:3000
//!     GOOGLE_OAUTH_CLIENT_ID        enables Google OAuth
//!     GOOGLE_OAUTH_CLIENT_SECRET
//!     GITHUB_OAUTH_CLIENT_ID        enables GitHub OAuth
//!     GITHUB_OAUTH_CLIENT_SECRET

mod notes;

use std::{sync::Arc, time::Duration};

use axum::{
    http::header,
    middleware,
    response::{Html, IntoResponse},
    routing::get,
    Router,
};
use rauth::{
    organizations::axum_router as orgs_router,
    rate_limit::{axum_layer::limit, InMemoryRateLimiter, RateLimiter},
    storage::SqliteStorage,
    totp::axum_router as totp_router,
    Auth, AuthConfig,
};
use sqlx::sqlite::SqlitePoolOptions;
use tower_http::trace::TraceLayer;

const INDEX_HTML: &str = include_str!("../static/index.html");

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,rauth=debug,sqlx=warn".into()),
        )
        .init();

    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "sqlite://./rauth-demo.sqlite?mode=rwc".into());
    let base_url = std::env::var("RAUTH_BASE_URL")
        .unwrap_or_else(|_| "http://localhost:3000".into());

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&db_url)
        .await?;
    sqlx::query("PRAGMA foreign_keys = ON;")
        .execute(&pool)
        .await?;

    let storage = SqliteStorage::new(pool.clone());
    storage.migrate().await?;
    notes::migrate(&pool).await?;

    let auth = Auth::builder()
        .storage(storage)
        .config(AuthConfig {
            base_url: base_url.clone(),
            send_verification_email_on_signup: true,
            ..AuthConfig::default()
        })
        .build()?;

    // Auth-protected sub-router (rate-limited).
    let limiter: Arc<dyn RateLimiter> =
        Arc::new(InMemoryRateLimiter::new(30, Duration::from_secs(60)));

    let mut auth_routes = Router::new()
        .merge(rauth::axum::router(auth.clone()))
        .nest("/totp", totp_router::router(auth.clone()))
        .nest("/organizations", orgs_router::router(auth.clone()));

    // OAuth (only mounted if at least one provider is configured).
    {
        use rauth::oauth::{axum_router as oauth_router, OAuth, OAuthProvider};
        let mut oauth = OAuth::new(auth.clone());
        let mut any = false;
        if let (Ok(id), Ok(secret)) = (
            std::env::var("GOOGLE_OAUTH_CLIENT_ID"),
            std::env::var("GOOGLE_OAUTH_CLIENT_SECRET"),
        ) {
            any = true;
            oauth = oauth.with_provider(OAuthProvider::google(
                id,
                secret,
                format!("{base_url}/api/auth/oauth/google/callback"),
            ));
            tracing::info!("Google OAuth enabled");
        }
        if let (Ok(id), Ok(secret)) = (
            std::env::var("GITHUB_OAUTH_CLIENT_ID"),
            std::env::var("GITHUB_OAUTH_CLIENT_SECRET"),
        ) {
            any = true;
            oauth = oauth.with_provider(OAuthProvider::github(
                id,
                secret,
                format!("{base_url}/api/auth/oauth/github/callback"),
            ));
            tracing::info!("GitHub OAuth enabled");
        }
        if any {
            auth_routes = auth_routes.nest("/oauth", oauth_router::router(oauth));
        }
    }

    let auth_routes =
        auth_routes.layer(middleware::from_fn_with_state(limiter.clone(), limit));

    // Notes API (also rate-limited).
    let notes_state = notes::NotesState {
        auth: auth.clone(),
        pool,
    };
    let notes_routes = notes::router(notes_state)
        .layer(middleware::from_fn_with_state(limiter, limit));

    let app = Router::new()
        .route("/", get(index))
        .nest("/api/auth", auth_routes)
        .nest("/api/notes", notes_routes)
        .layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    tracing::info!("listening on http://{}", listener.local_addr()?);
    axum::serve(listener, app).await?;
    Ok(())
}

async fn index() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        Html(INDEX_HTML),
    )
}
