use std::sync::Arc;

use anyhow::Context;
use prism_sync_relay::{cleanup, config::Config, db, db::Database, routes, state::AppState};

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

    // File writes require explicit opt-in and a valid durable root. Otherwise
    // new snapshots stay inline while existing blob files remain readable.
    let explicit_file_backing =
        prism_sync_relay::config::snapshot_file_backing_explicitly_requested(|key| {
            std::env::var(key).ok()
        });
    let snapshot_storage = config
        .resolve_snapshot_storage(explicit_file_backing)
        .context("invalid snapshot storage configuration")?;
    match &snapshot_storage {
        prism_sync_relay::SnapshotStorage::FileBacked(root) => {
            tracing::info!(
                snapshot_root = %root.display(),
                "snapshot file backing enabled"
            );
        }
        prism_sync_relay::SnapshotStorage::InlineWithExistingFiles(root) => {
            tracing::info!(
                snapshot_root = %root.display(),
                "snapshot file writes disabled; existing blobs remain readable"
            );
        }
        prism_sync_relay::SnapshotStorage::Inline => {
            tracing::info!("snapshot file writes disabled; new snapshots remain inline in SQLite");
        }
    }

    let db = Database::open(&config.db_path, config.reader_pool_size)
        .context("failed to open database")?;

    // Resolve registration token (env var → file → auto-generate).
    // Must run after Database::open so the data directory exists.
    config.resolve_registration_token();
    tracing::info!(db_path = %config.db_path, "Database opened");

    // Pairing lease enablement gate. Hosted deployments fronted by a proxy must
    // have a TRUSTED_PROXY_CIDRS allowlist, or every user's renewal would key on
    // the tunnel peer and collapse into one rate-limit bucket. Self-host with
    // direct peers needs no allowlist, so a missing one is only a warning there.
    //
    // "Hosted" is inferred from a configured public origin hint rather than a
    // build flag: the binary behaves identically for self-host and hosted, and
    // what matters here is only whether something fronts the relay.
    let hosted_deployment =
        config.gif_public_base_url.as_deref().is_some_and(|url| !url.trim().is_empty());
    config.validate_pairing_lease_proxy_trust(hosted_deployment).map_err(anyhow::Error::msg)?;
    if let Some(warning) = config.pairing_lease_trusted_proxy_warning() {
        tracing::warn!("{warning}");
    }
    if config.pairing_lease_supported() {
        tracing::info!(
            max_concurrent_leased = config.pairing_lease_max_concurrent_sessions(),
            "Pairing lease enabled"
        );
    }

    // Resumable snapshot upload gate. Two independent conditions, both reported
    // rather than silently degrading, because "advertised but not actually
    // usable" is the failure mode that hurts: a client that commits to the
    // resumable path and then cannot complete has no safe fallback mid-ceremony.
    //
    // 1. The operator must have asked for it (`SNAPSHOT_UPLOAD_ENABLED=true`).
    // 2. Snapshot storage must be file-backed. A resumable session stages bytes
    //    on disk and publishes a `blob_ref`; publishing that reference into an
    //    inline-only deployment would leave a snapshot row whose bytes do not
    //    exist, so capability is withheld instead — never written anyway.
    if config.snapshot_upload.enabled && !snapshot_storage.is_file_backed() {
        tracing::warn!(
            "SNAPSHOT_UPLOAD_ENABLED=true but snapshot file backing is not active (snapshot \
             storage resolved to inline writes); resumable snapshot uploads stay dark. Set \
             SNAPSHOT_FILE_BACKING_ENABLED=true with MEDIA_STORAGE_PATH on an absolute \
             writable persistent path to enable them."
        );
    }
    if let Some(capability) = config.snapshot_upload_capability(&snapshot_storage) {
        tracing::info!(
            chunk_bytes = capability.chunk_bytes,
            max_wire_bytes = capability.max_wire_bytes,
            global_reserved_bytes = config.snapshot_upload.global_reserved_bytes,
            group_reserved_bytes = config.snapshot_upload.group_reserved_bytes,
            free_space_reserve_bytes = config.snapshot_upload.free_space_reserve_bytes,
            "Resumable snapshot uploads enabled and advertised"
        );
    } else if config.snapshot_upload.enabled {
        // Enabled but withheld: the ceilings are present-but-invalid (the only
        // remaining gate). Make that explicit so the operator fixes config
        // rather than hunting a phantom storage problem.
        tracing::warn!(
            global_reserved_bytes = config.snapshot_upload.global_reserved_bytes,
            group_reserved_bytes = config.snapshot_upload.group_reserved_bytes,
            free_space_reserve_bytes = config.snapshot_upload.free_space_reserve_bytes,
            "resumable snapshot upload capability withheld: resource ceilings must all be \
             positive and the per-group ceiling must not exceed the global ceiling"
        );
    }

    let state = AppState::with_snapshot_storage(db, config, snapshot_storage);
    let cleanup_handle = cleanup::spawn_cleanup_task(Arc::new(state.clone()));
    // Keep a handle to the DB so the shutdown path can persist the lineage
    // companion after `state` is moved into the router.
    let shutdown_db = state.db.clone();
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

    // Persist the lineage companion at the clean shutdown point so the on-disk
    // high-water mark reflects every batch issued this run.
    if let Err(e) =
        shutdown_db.with_conn(|conn| db::write_lineage_companion(shutdown_db.db_path(), conn))
    {
        tracing::warn!("failed to write lineage companion on shutdown: {e}");
    }

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
