use std::sync::Arc;

use prism_sync_relay::{cleanup, config::Config, db::Database, routes, state::AppState};

#[cfg(all(feature = "test-helpers", not(debug_assertions)))]
compile_error!("test-helpers feature must not be enabled in release builds");

#[tokio::main]
async fn main() {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    let json_mode = std::env::var("LOG_FORMAT")
        .map(|v| v == "json")
        .unwrap_or(false);

    if json_mode {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(env_filter)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .init();
    }

    let mut config = Config::from_env();
    let port = config.port;

    let db =
        Database::open(&config.db_path, config.reader_pool_size).expect("failed to open database");

    // Resolve registration token (env var → file → auto-generate).
    // Must run after Database::open so the data directory exists.
    config.resolve_registration_token();
    tracing::info!(db_path = %config.db_path, "Database opened");

    let state = AppState::new(db, config);
    cleanup::spawn_cleanup_task(Arc::new(state.clone()));
    let app = routes::router(state);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .expect("failed to bind");
    tracing::info!("prism-sync-relay listening on port {port}");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await
    .expect("server error");
}
