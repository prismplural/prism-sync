use axum::{extract::State, http::HeaderMap, response::IntoResponse, routing::get, Router};
use std::sync::atomic::Ordering;

use crate::{auth, errors::AppError, state::AppState};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/metrics", get(prometheus_metrics))
        .route("/metrics/node", get(node_metrics))
}

/// Expose Prometheus-format metrics.
///
/// If `METRICS_TOKEN` is configured, the request must include a matching
/// `Authorization: Bearer <token>` header. If no token is configured the
/// endpoint is open (suitable for internal / firewalled deployments).
async fn prometheus_metrics(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    // Optional bearer-token gate.
    if let Some(expected_token) = state.config.metrics_token.as_deref() {
        let provided = headers
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or("");
        if !auth::timing_safe_eq(provided, expected_token) {
            return Err(AppError::Unauthorized);
        }
    }

    let m = &state.metrics;
    let connected = state.connected_device_count().await;

    let db = state.db.clone();
    let (registered_syncs, stored_batches, db_size_bytes, freelist_pages) =
        tokio::task::spawn_blocking(move || {
            db.with_read_conn(|conn| {
                let registered_syncs: u64 = conn
                    .query_row("SELECT COUNT(*) FROM sync_groups", [], |r| r.get(0))
                    .unwrap_or(0);

                let stored_batches: u64 = conn
                    .query_row("SELECT COUNT(*) FROM batches", [], |r| r.get(0))
                    .unwrap_or(0);

                let db_size_bytes: u64 = conn
                    .query_row(
                        "SELECT page_count * page_size \
                         FROM pragma_page_count(), pragma_page_size()",
                        [],
                        |r| r.get(0),
                    )
                    .unwrap_or(0);

                let freelist_pages: u64 = conn
                    .query_row("PRAGMA freelist_count;", [], |r| r.get(0))
                    .unwrap_or(0);

                Ok::<(u64, u64, u64, u64), rusqlite::Error>((
                    registered_syncs,
                    stored_batches,
                    db_size_bytes,
                    freelist_pages,
                ))
            })
        })
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?
        .unwrap_or((0, 0, 0, 0));

    let output = format!(
        "# HELP prism_connected_devices Current WebSocket connections\n\
         # TYPE prism_connected_devices gauge\n\
         prism_connected_devices {connected}\n\
         # HELP prism_registered_syncs Total registered sync groups\n\
         # TYPE prism_registered_syncs gauge\n\
         prism_registered_syncs {registered_syncs}\n\
         # HELP prism_stored_batches Current batch count\n\
         # TYPE prism_stored_batches gauge\n\
         prism_stored_batches {stored_batches}\n\
         # HELP prism_db_size_bytes SQLite database size in bytes\n\
         # TYPE prism_db_size_bytes gauge\n\
         prism_db_size_bytes {db_size_bytes}\n\
         # HELP prism_changesets_pushed_total Lifetime changeset push operations\n\
         # TYPE prism_changesets_pushed_total counter\n\
         prism_changesets_pushed_total {}\n\
         # HELP prism_changesets_pulled_total Lifetime changeset pull operations\n\
         # TYPE prism_changesets_pulled_total counter\n\
         prism_changesets_pulled_total {}\n\
         # HELP prism_changesets_pruned_total Changesets pruned by cleanup\n\
         # TYPE prism_changesets_pruned_total counter\n\
         prism_changesets_pruned_total {}\n\
         # HELP prism_ws_notifications_total WebSocket notifications sent\n\
         # TYPE prism_ws_notifications_total counter\n\
         prism_ws_notifications_total {}\n\
         # HELP prism_auth_failures_total Failed authentication attempts\n\
         # TYPE prism_auth_failures_total counter\n\
         prism_auth_failures_total {}\n\
         # HELP prism_snapshots_exchanged_total Snapshot uploads and downloads\n\
         # TYPE prism_snapshots_exchanged_total counter\n\
         prism_snapshots_exchanged_total {}\n\
         # HELP prism_registrations_total Device registrations completed\n\
         # TYPE prism_registrations_total counter\n\
         prism_registrations_total {}\n\
         # HELP prism_freelist_pages SQLite freelist pages awaiting vacuum\n\
         # TYPE prism_freelist_pages gauge\n\
         prism_freelist_pages {freelist_pages}\n\
         # HELP prism_vacuum_pages_freed_total Pages reclaimed by incremental vacuum\n\
         # TYPE prism_vacuum_pages_freed_total counter\n\
         prism_vacuum_pages_freed_total {}\n\
         # HELP prism_last_cleanup_timestamp_seconds Unix timestamp of last successful cleanup cycle\n\
         # TYPE prism_last_cleanup_timestamp_seconds gauge\n\
         prism_last_cleanup_timestamp_seconds {}\n",
        m.changesets_pushed.load(Ordering::Relaxed),
        m.changesets_pulled.load(Ordering::Relaxed),
        m.changesets_pruned.load(Ordering::Relaxed),
        m.ws_notifications.load(Ordering::Relaxed),
        m.auth_failures.load(Ordering::Relaxed),
        m.snapshots_exchanged.load(Ordering::Relaxed),
        m.registrations.load(Ordering::Relaxed),
        m.vacuum_pages_freed.load(Ordering::Relaxed),
        m.last_cleanup_epoch_secs.load(Ordering::Relaxed),
    );

    Ok((
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        output,
    ))
}

/// Reverse-proxy to node-exporter, gated by the same METRICS_TOKEN.
/// Returns 404 if NODE_EXPORTER_URL is not configured.
async fn node_metrics(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    // Same bearer-token gate as /metrics.
    if let Some(expected_token) = state.config.metrics_token.as_deref() {
        let provided = headers
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or("");
        if !auth::timing_safe_eq(provided, expected_token) {
            return Err(AppError::Unauthorized);
        }
    }

    let base_url = state
        .config
        .node_exporter_url
        .as_deref()
        .ok_or(AppError::NotFound)?;

    let url = format!("{base_url}/metrics");
    let body = reqwest::get(&url)
        .await
        .map_err(|e| AppError::Internal(format!("node-exporter fetch failed: {e}")))?
        .text()
        .await
        .map_err(|e| AppError::Internal(format!("node-exporter read failed: {e}")))?;

    Ok((
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        body,
    ))
}
