use std::sync::Arc;

use anyhow::Context;
use prism_sync_relay::{cleanup, config::Config, db::Database, routes, state::AppState};

#[cfg(all(feature = "test-helpers", not(debug_assertions)))]
compile_error!("test-helpers feature must not be enabled in release builds");

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    let json_mode = std::env::var("LOG_FORMAT").map(|v| v == "json").unwrap_or(false);

    if json_mode {
        tracing_subscriber::fmt().json().with_env_filter(env_filter).init();
    } else {
        tracing_subscriber::fmt().with_env_filter(env_filter).init();
    }

    // Log panics via tracing instead of the default stderr handler.
    std::panic::set_hook(Box::new(|info| {
        let payload = if let Some(s) = info.payload().downcast_ref::<&str>() {
            (*s).to_string()
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "unknown panic payload".to_string()
        };
        let location = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "unknown location".to_string());
        tracing::error!(panic.payload = %payload, panic.location = %location, "thread panicked");
    }));

    let mut config = Config::try_from_env().context("invalid relay configuration")?;
    let port = config.port;

    let db = Database::open(&config.db_path, config.reader_pool_size)
        .context("failed to open database")?;

    // Resolve registration token (env var → file → auto-generate).
    // Must run after Database::open so the data directory exists.
    config.resolve_registration_token();
    tracing::info!(db_path = %config.db_path, "Database opened");

    let state = AppState::new(db, config);
    let cleanup_handle = cleanup::spawn_cleanup_task(Arc::new(state.clone()));
    let app = routes::router(state);

    let listener =
        tokio::net::TcpListener::bind(format!("0.0.0.0:{port}")).await.context("failed to bind")?;
    tracing::info!("prism-sync-relay listening on port {port}");
    axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>())
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server error")?;

    tracing::info!("shutting down — aborting cleanup task");
    cleanup_handle.abort();

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        match tokio::signal::ctrl_c().await {
            Ok(()) => {}
            Err(e) => {
                tracing::error!("failed to install Ctrl+C handler: {e}");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(e) => {
                tracing::error!("failed to install SIGTERM handler: {e}");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => tracing::info!("received SIGINT, starting graceful shutdown"),
        _ = terminate => tracing::info!("received SIGTERM, starting graceful shutdown"),
    }
}
