use std::sync::Arc;

use prism_sync_relay::{cleanup, config::Config, db::Database, routes, state::AppState};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let config = Config::from_env();
    let port = config.port;

    let db = Database::open(&config.db_path, config.reader_pool_size)
        .expect("failed to open database");
    tracing::info!(db_path = %config.db_path, "Database opened");

    let state = AppState::new(db, config);
    cleanup::spawn_cleanup_task(Arc::new(state.clone()));
    let app = routes::router(state);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .expect("failed to bind");
    tracing::info!("prism-sync-relay listening on port {port}");
    axum::serve(listener, app).await.expect("server error");
}
