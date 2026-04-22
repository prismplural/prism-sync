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

    let stored_batches = m.cached_stored_batches.load(Ordering::Relaxed);
    let db_size_bytes = m.cached_db_size_bytes.load(Ordering::Relaxed);
    let freelist_pages = m.cached_freelist_pages.load(Ordering::Relaxed);

    let output = format!(
        "# HELP prism_connected_devices Current WebSocket connections\n\
         # TYPE prism_connected_devices gauge\n\
         prism_connected_devices {connected}\n\
         # HELP prism_stored_batches Current batch count\n\
         # TYPE prism_stored_batches gauge\n\
         prism_stored_batches {stored_batches}\n\
         # HELP prism_db_size_bytes SQLite database size in bytes\n\
         # TYPE prism_db_size_bytes gauge\n\
         prism_db_size_bytes {db_size_bytes}\n\
         # HELP prism_freelist_pages SQLite freelist pages awaiting vacuum\n\
         # TYPE prism_freelist_pages gauge\n\
         prism_freelist_pages {freelist_pages}\n\
         # HELP prism_last_cleanup_timestamp_seconds Unix timestamp of last successful cleanup cycle\n\
         # TYPE prism_last_cleanup_timestamp_seconds gauge\n\
         prism_last_cleanup_timestamp_seconds {}\n",
        m.last_cleanup_epoch_secs.load(Ordering::Relaxed),
    );

    Ok(([("content-type", "text/plain; version=0.0.4; charset=utf-8")], output))
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

    let base_url = state.config.node_exporter_url.as_deref().ok_or(AppError::NotFound)?;

    let url = format!("{base_url}/metrics");
    let body = reqwest::get(&url)
        .await
        .map_err(|e| AppError::Internal(format!("node-exporter fetch failed: {e}")))?
        .text()
        .await
        .map_err(|e| AppError::Internal(format!("node-exporter read failed: {e}")))?;

    Ok(([("content-type", "text/plain; version=0.0.4; charset=utf-8")], body))
}
