use rauth::{storage::SqliteStorage, Auth, AuthConfig};
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

    let app = axum::Router::new().nest("/api/auth", rauth::axum::router(auth));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    tracing::info!("listening on http://{}", listener.local_addr()?);
    axum::serve(listener, app).await?;
    Ok(())
}
