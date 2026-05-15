use std::{sync::Arc, time::Duration};

use axum::middleware;
use rauth::{
    organizations::axum_router as orgs_router,
    rate_limit::{axum_layer::limit, InMemoryRateLimiter, RateLimiter},
    storage::SqliteStorage,
    totp::axum_router as totp_router,
    Auth, AuthConfig,
};
use sqlx::sqlite::SqlitePoolOptions;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect("sqlite::memory:")
        .await?;

    let storage = SqliteStorage::new(pool);
    storage.migrate().await?;

    let auth = Auth::builder()
        .storage(storage)
        .config(AuthConfig {
            base_url: "http://localhost:3000".into(),
            ..AuthConfig::default()
        })
        .build()?;

    // 10 requests / minute / (ip, path) on every /api/auth route.
    let limiter: Arc<dyn RateLimiter> =
        Arc::new(InMemoryRateLimiter::new(10, Duration::from_secs(60)));

    let mut auth_routes = axum::Router::new()
        .merge(rauth::axum::router(auth.clone()))
        .nest("/totp", totp_router::router(auth.clone()))
        .nest("/organizations", orgs_router::router(auth.clone()));

    // Optional OAuth — enabled when GOOGLE_OAUTH_CLIENT_ID / GITHUB_OAUTH_CLIENT_ID are set.
    {
        use rauth::oauth::{axum_router as oauth_router, OAuth, OAuthProvider};
        let mut oauth = OAuth::new(auth.clone());
        if let (Ok(id), Ok(secret)) = (
            std::env::var("GOOGLE_OAUTH_CLIENT_ID"),
            std::env::var("GOOGLE_OAUTH_CLIENT_SECRET"),
        ) {
            oauth = oauth.with_provider(OAuthProvider::google(
                id,
                secret,
                "http://localhost:3000/api/auth/oauth/google/callback",
            ));
        }
        if let (Ok(id), Ok(secret)) = (
            std::env::var("GITHUB_OAUTH_CLIENT_ID"),
            std::env::var("GITHUB_OAUTH_CLIENT_SECRET"),
        ) {
            oauth = oauth.with_provider(OAuthProvider::github(
                id,
                secret,
                "http://localhost:3000/api/auth/oauth/github/callback",
            ));
        }
        auth_routes = auth_routes.nest("/oauth", oauth_router::router(oauth));
    }

    let auth_routes = auth_routes.layer(middleware::from_fn_with_state(limiter, limit));

    let app = axum::Router::new().nest("/api/auth", auth_routes);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    tracing::info!("listening on http://{}", listener.local_addr()?);
    axum::serve(listener, app).await?;
    Ok(())
}
