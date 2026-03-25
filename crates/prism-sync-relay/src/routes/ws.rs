use axum::{
    extract::{
        ws::{CloseFrame, Message, WebSocket},
        Path, State, WebSocketUpgrade,
    },
    response::IntoResponse,
};
use futures::{SinkExt, StreamExt};

use crate::{db, errors::AppError, state::AppState};

/// Close code for failed auth.
const CLOSE_AUTH_FAILED: u16 = 4001;
/// Close code for slow consumer.
#[allow(dead_code)]
const CLOSE_SLOW_CONSUMER: u16 = 4002;
/// Auth timeout in seconds.
const AUTH_TIMEOUT_SECS: u64 = 10;
/// Ping interval in seconds.
const PING_INTERVAL_SECS: u64 = 30;

// ---------------------------------------------------------------------------
// ws_upgrade — GET /v1/sync/{sync_id}/ws
// ---------------------------------------------------------------------------

pub async fn ws_upgrade(
    State(state): State<AppState>,
    Path(sync_id): Path<String>,
    ws: WebSocketUpgrade,
) -> Result<impl IntoResponse, AppError> {
    tracing::debug!(
        sync_id = %trunc(&sync_id),
        "WebSocket upgrade requested"
    );

    Ok(ws.on_upgrade(move |socket| handle_ws(state, sync_id, socket)))
}

// ---------------------------------------------------------------------------
// WebSocket handler
// ---------------------------------------------------------------------------

async fn handle_ws(state: AppState, sync_id: String, socket: WebSocket) {
    let (mut ws_sink, mut ws_stream) = socket.split();

    // Step 1: Wait for auth message with timeout
    let auth_result =
        tokio::time::timeout(std::time::Duration::from_secs(AUTH_TIMEOUT_SECS), async {
            while let Some(Ok(msg)) = ws_stream.next().await {
                match msg {
                    Message::Text(text) => {
                        return parse_and_validate_auth(&state, &sync_id, text.as_str()).await;
                    }
                    Message::Close(_) => return None,
                    _ => continue,
                }
            }
            None
        })
        .await;

    let device_id = match auth_result {
        Ok(Some(device_id)) => {
            let ok_msg = serde_json::json!({"type": "auth_ok"}).to_string();
            if ws_sink.send(Message::Text(ok_msg.into())).await.is_err() {
                return;
            }
            device_id
        }
        _ => {
            let _ = ws_sink
                .send(Message::Close(Some(CloseFrame {
                    code: CLOSE_AUTH_FAILED,
                    reason: "Authentication failed".into(),
                })))
                .await;
            return;
        }
    };

    tracing::debug!(
        sync_id = %trunc(&sync_id),
        device_id = %trunc(&device_id),
        "WebSocket authenticated"
    );

    // Step 2: Register — last-connection-wins (old connection's channel is dropped)
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

    // Step 3: Forward notifications + keepalive pings to WS
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

    // Step 4: Process incoming messages (ack + ping/pong)
    let state_recv = state.clone();
    let sid_recv = sync_id.clone();
    let did_recv = device_id.clone();
    let stale_threshold = state.config.stale_device_secs as i64;

    while let Some(Ok(msg)) = ws_stream.next().await {
        match msg {
            Message::Text(text) => {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(text.as_str()) {
                    if json["type"] == "ack" {
                        if let Some(server_seq) = json["server_seq"].as_i64() {
                            handle_ws_ack(
                                &state_recv,
                                &sid_recv,
                                &did_recv,
                                server_seq,
                                stale_threshold,
                            )
                            .await;
                        }
                    }
                }
            }
            Message::Ping(_) | Message::Pong(_) => {}
            Message::Close(_) => break,
            _ => {}
        }
    }

    // Step 5: Cleanup
    state.unregister_ws(&sync_id, &device_id).await;
    send_task.abort();

    tracing::debug!(
        sync_id = %trunc(&sync_id),
        device_id = %trunc(&device_id),
        "WebSocket disconnected"
    );
}

// ---------------------------------------------------------------------------
// Auth message parsing & validation
// ---------------------------------------------------------------------------

async fn parse_and_validate_auth(state: &AppState, sync_id: &str, text: &str) -> Option<String> {
    let json: serde_json::Value = serde_json::from_str(text).ok()?;

    if json["type"].as_str()? != "auth" {
        return None;
    }

    let device_id = json["device_id"].as_str()?.to_string();
    let token = json["token"].as_str()?.to_string();

    let expected_sync_id = sync_id.to_string();
    let session_expiry = state.config.session_expiry_secs as i64;

    // Phase 1 — Read (blocking): validate session + check device is active
    let db_read = state.db.clone();
    let expected_sid = expected_sync_id.clone();
    let expected_did = device_id.clone();
    let result = tokio::task::spawn_blocking(move || {
        db_read.with_read_conn(|conn| {
            let session = db::validate_session(conn, &token)?;
            match session {
                Some((sid, did)) if sid == expected_sid && did == expected_did => {
                    // Also verify the device is still active (not revoked)
                    let device = db::get_device(conn, &sid, &did)?;
                    match device {
                        Some(d) if d.status == "active" => Ok(Some(did)),
                        _ => Ok(None),
                    }
                }
                _ => Ok(None),
            }
        })
    })
    .await
    .ok()?
    .ok()?;

    // Phase 2 — Write (fire-and-forget): touch session + device
    if let Some(ref did) = result {
        let db_write = state.db.clone();
        let sid = expected_sync_id;
        let did = did.clone();
        tokio::spawn(async move {
            let _ = tokio::task::spawn_blocking(move || {
                db_write.with_conn(|conn| {
                    db::touch_session(conn, &sid, &did, session_expiry)?;
                    db::touch_device(conn, &sid, &did)
                })
            })
            .await;
        });
    }

    result
}

// ---------------------------------------------------------------------------
// WebSocket ACK handler
// ---------------------------------------------------------------------------

async fn handle_ws_ack(
    state: &AppState,
    sync_id: &str,
    device_id: &str,
    server_seq: i64,
    stale_threshold: i64,
) {
    let db = state.db.clone();
    let sid = sync_id.to_string();
    let did = device_id.to_string();

    let result = tokio::task::spawn_blocking(move || {
        db.with_conn(|conn| {
            db::upsert_device_receipt(conn, &sid, &did, server_seq)?;
            match db::get_safe_prune_seq(conn, &sid, stale_threshold)? {
                Some(safe_seq) => db::prune_batches_before(conn, &sid, safe_seq),
                None => Ok(0),
            }
        })
    })
    .await;

    if let Ok(Ok(pruned)) = result {
        if pruned > 0 {
            tracing::debug!(
                sync_id = %trunc(sync_id),
                device_id = %trunc(device_id),
                pruned,
                "Pruned acked batches via WS ack"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn trunc(s: &str) -> &str {
    let end = s.len().min(16);
    &s[..end]
}
