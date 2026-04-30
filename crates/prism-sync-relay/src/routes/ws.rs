use axum::{
    extract::{
        ws::{Message, WebSocket},
        Extension, Path, State, WebSocketUpgrade,
    },
    response::IntoResponse,
};
use futures::{SinkExt, StreamExt};

use crate::{db, errors::AppError, state::AppState};

use super::AuthIdentity;

/// Close code for slow consumer.
#[allow(dead_code)]
const CLOSE_SLOW_CONSUMER: u16 = 4002;
/// Ping interval in seconds.
const PING_INTERVAL_SECS: u64 = 30;

// ---------------------------------------------------------------------------
// ws_upgrade — GET /v1/sync/{sync_id}/ws
// ---------------------------------------------------------------------------

pub async fn ws_upgrade(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthIdentity>,
    Path(path_sync_id): Path<String>,
    ws: WebSocketUpgrade,
) -> Result<impl IntoResponse, AppError> {
    if path_sync_id != auth.sync_id {
        return Err(AppError::Forbidden("sync_id mismatch"));
    }

    tracing::debug!(
        sync_id = %trunc(&auth.sync_id),
        device_id = %trunc(&auth.device_id),
        "WebSocket upgrade requested"
    );

    Ok(ws.on_upgrade(move |socket| handle_ws(state, auth.sync_id, auth.device_id, socket)))
}

// ---------------------------------------------------------------------------
// WebSocket handler
// ---------------------------------------------------------------------------

async fn handle_ws(state: AppState, sync_id: String, device_id: String, socket: WebSocket) {
    let (mut ws_sink, mut ws_stream) = socket.split();

    let ok_msg = serde_json::json!({"type": "auth_ok"}).to_string();
    if ws_sink.send(Message::Text(ok_msg.into())).await.is_err() {
        return;
    }

    tracing::debug!(
        sync_id = %trunc(&sync_id),
        device_id = %trunc(&device_id),
        "WebSocket authenticated"
    );

    // Step 1: Register — last-connection-wins (old connection's channel is dropped)
    let mut rx = state.register_ws(&sync_id, &device_id).await;

    // Ensure device receipt exists
    {
        let db = state.db.clone();
        let sid = sync_id.clone();
        let did = device_id.clone();
        let _ = tokio::task::spawn_blocking(move || {
            db.with_conn(|conn| db::upsert_device_receipt(conn, &sid, &did, 0))
        })
        .await;
    }

    // Step 2: Forward notifications + keepalive pings to WS
    let sid_send = sync_id.clone();
    let did_send = device_id.clone();
    let send_task = tokio::spawn(async move {
        let mut ping_interval =
            tokio::time::interval(std::time::Duration::from_secs(PING_INTERVAL_SECS));
        ping_interval.tick().await; // skip first immediate tick
        loop {
            tokio::select! {
                msg = rx.recv() => {
                    match msg {
                        Some(text) => {
                            if ws_sink.send(Message::Text(text.into())).await.is_err() {
                                break;
                            }
                        }
                        None => break, // channel closed (replaced by new connection)
                    }
                }
                _ = ping_interval.tick() => {
                    if ws_sink.send(Message::Ping(Vec::new().into())).await.is_err() {
                        break;
                    }
                }
            }
        }
        tracing::debug!(
            sync_id = %trunc(&sid_send),
            device_id = %trunc(&did_send),
            "WS send task ended"
        );
    });

    // Step 3: Process incoming messages (ping/pong only — ack is HTTP-only)
    while let Some(Ok(msg)) = ws_stream.next().await {
        match msg {
            Message::Ping(_) | Message::Pong(_) => {}
            Message::Close(_) => break,
            _ => {}
        }
    }

    // Step 4: Cleanup
    state.unregister_ws(&sync_id, &device_id).await;
    send_task.abort();

    tracing::debug!(
        sync_id = %trunc(&sync_id),
        device_id = %trunc(&device_id),
        "WebSocket disconnected"
    );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn trunc(s: &str) -> &str {
    let end = s.len().min(16);
    &s[..end]
}
