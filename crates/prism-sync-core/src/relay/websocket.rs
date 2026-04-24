use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures_util::{FutureExt, SinkExt, StreamExt};
use rand::Rng;
use tokio::sync::broadcast;
use tokio::time;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, error, info, warn};

use super::redact_url;
use super::traits::SyncNotification;
use crate::runtime::background_runtime;

/// Maximum reconnect delay in seconds.
const MAX_RECONNECT_DELAY_SECS: u64 = 30;

/// Ping interval in seconds.
const PING_INTERVAL_SECS: u64 = 30;

/// WebSocket client for real-time sync notifications.
///
/// Features:
/// - Message-based auth (credentials sent as first message, not in URL)
/// - Auto-reconnect with exponential backoff (1s, 2s, 4s, 8s, 16s, cap 30s)
/// - Ping/pong keepalive every 30 seconds
/// - Parse notification messages: new_data, device_revoked, epoch_rotated
/// - Notifications broadcast via tokio::sync::broadcast
///
/// Ported from Dart `lib/core/sync/server_relay.dart` (WebSocket section).
pub struct WebSocketClient {
    ws_url: String,
    device_id: String,
    auth_token: String,
    notification_tx: broadcast::Sender<SyncNotification>,
    /// Handle to the background task. Uses std::sync::Mutex so the handle
    /// can be stored/aborted without requiring a Tokio runtime context
    /// (important on mobile where FRB's executor is not a Tokio runtime).
    task_handle: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    intentional_close: Arc<AtomicBool>,
    /// Whether the WebSocket is currently authenticated and receiving messages.
    connected: Arc<AtomicBool>,
}

impl Drop for WebSocketClient {
    fn drop(&mut self) {
        // Signal the reconnect loop to stop and abort the background task.
        // Without this, dropping a JoinHandle merely detaches the task — the
        // reconnect loop would run forever on background_runtime() with stale
        // credentials.
        //
        // `get_mut()` is safe here: Drop gives &mut self, guaranteeing
        // exclusive access without needing to lock the mutex.
        self.intentional_close.store(true, Ordering::SeqCst);
        if let Some(h) = self.task_handle.get_mut().unwrap().take() {
            h.abort();
        }
    }
}

impl WebSocketClient {
    /// Create a new WebSocket client without connecting.
    pub fn new(
        ws_url: String,
        device_id: String,
        auth_token: String,
        notification_tx: broadcast::Sender<SyncNotification>,
    ) -> Self {
        Self {
            ws_url,
            device_id,
            auth_token,
            notification_tx,
            task_handle: std::sync::Mutex::new(None),
            intentional_close: Arc::new(AtomicBool::new(false)),
            connected: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Whether the WebSocket is currently authenticated and receiving messages.
    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::SeqCst)
    }

    /// Connect and start the background read/reconnect loop.
    ///
    /// Spawns on `background_runtime()` so the reconnect loop survives beyond
    /// the calling async context. This is necessary on mobile (iOS/Android)
    /// where FRB's async executor is not a Tokio runtime and `tokio::spawn`
    /// would panic.
    pub async fn connect(&self) {
        // Abort any existing task first (sync lock — no await needed).
        if let Some(h) = self.task_handle.lock().unwrap().take() {
            h.abort();
        }

        self.intentional_close.store(false, Ordering::SeqCst);
        self.connected.store(false, Ordering::SeqCst);

        let ws_url = self.ws_url.clone();
        let device_id = self.device_id.clone();
        let auth_token = self.auth_token.clone();
        let notification_tx = self.notification_tx.clone();
        let intentional_close = Arc::clone(&self.intentional_close);
        let connected = Arc::clone(&self.connected);

        info!("[prism_ws] Starting reconnect loop for {}", redact_url(&ws_url));

        let handle = background_runtime().spawn(async move {
            let safe_url = redact_url(&ws_url);
            let mut attempt: u32 = 0;

            loop {
                if intentional_close.load(Ordering::SeqCst) {
                    debug!("WebSocket intentional close, stopping reconnect loop");
                    debug!("[prism_ws] Intentional close, stopping");
                    break;
                }

                info!("[prism_ws] Connecting to {safe_url} (attempt {attempt})");
                connected.store(false, Ordering::SeqCst);

                // Wrap in catch_unwind to surface panics (e.g. rustls
                // CryptoProvider not installed) as visible errors instead of
                // silently killing the reconnect loop.
                let run_result = std::panic::AssertUnwindSafe(Self::run_connection(
                    &ws_url,
                    &device_id,
                    &auth_token,
                    &notification_tx,
                    &intentional_close,
                    &connected,
                ))
                .catch_unwind()
                .await;

                // Only emit disconnected if we were previously connected.
                if connected.swap(false, Ordering::SeqCst) {
                    let _ = notification_tx
                        .send(SyncNotification::ConnectionStateChanged { connected: false });
                }

                match run_result {
                    Err(panic_val) => {
                        let msg = panic_val
                            .downcast_ref::<&str>()
                            .copied()
                            .or_else(|| panic_val.downcast_ref::<String>().map(String::as_str))
                            .unwrap_or("unknown panic");
                        error!("[prism_ws] PANIC in run_connection (attempt {attempt}): {msg}");
                    }
                    Ok(Ok(())) => {
                        // Clean disconnect or intentional close.
                        if intentional_close.load(Ordering::SeqCst) {
                            debug!("[prism_ws] Intentional close after run_connection");
                            break;
                        }
                        // Unexpected clean close — reconnect.
                        warn!("[prism_ws] Connection closed cleanly (unexpected), reconnecting");
                        attempt = 0;
                    }
                    Ok(Err(e)) => {
                        warn!("[prism_ws] Connection error (attempt {attempt}): {e}");
                    }
                }

                if intentional_close.load(Ordering::SeqCst) {
                    debug!("[prism_ws] Intentional close after error, stopping");
                    break;
                }

                // Exponential backoff with jitter: min(2^attempt, MAX_RECONNECT_DELAY_SECS) + rand(0..500ms).
                // Jitter prevents thundering herd when many clients reconnect simultaneously.
                let base_secs = (1u64 << attempt.min(5)).min(MAX_RECONNECT_DELAY_SECS);
                let jitter_ms = rand::thread_rng().gen_range(0u64..500);
                let delay = Duration::from_secs(base_secs) + Duration::from_millis(jitter_ms);
                info!("WebSocket reconnecting in {base_secs}s +{jitter_ms}ms jitter (attempt {attempt})");
                time::sleep(delay).await;
                attempt = attempt.saturating_add(1);
            }
        });

        *self.task_handle.lock().unwrap() = Some(handle);
    }

    /// Disconnect and stop the background task.
    pub async fn disconnect(&self) {
        self.intentional_close.store(true, Ordering::SeqCst);
        if let Some(handle) = self.task_handle.lock().unwrap().take() {
            handle.abort();
        }
    }

    /// Run a single WebSocket connection until it closes or errors.
    async fn run_connection(
        ws_url: &str,
        device_id: &str,
        auth_token: &str,
        notification_tx: &broadcast::Sender<SyncNotification>,
        intentional_close: &AtomicBool,
        connected: &AtomicBool,
    ) -> Result<(), String> {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;

        // Do NOT set Sec-WebSocket-Protocol. If the client sends this header,
        // tungstenite requires the server to echo it in the 101 response. The
        // relay's Axum WebSocketUpgrade handler does not call .protocols(), so
        // it omits the header, causing tungstenite to reject the handshake with
        // SubProtocolError::NoSubProtocol. Omitting the header entirely avoids
        // this and matches the relay's behavior.
        let request = ws_url.into_client_request().map_err(|e| format!("invalid WS URL: {e}"))?;

        let safe_url = redact_url(ws_url);
        info!("[prism_ws] TCP/TLS connecting to {safe_url}");
        let connect_result = tokio_tungstenite::connect_async(request).await;
        let (ws_stream, _response) = connect_result.map_err(|e| {
            warn!("[prism_ws] connect_async FAILED: {e}");
            format!("WS connect failed: {e}")
        })?;

        info!("[prism_ws] Connected successfully to {safe_url}");
        info!("WebSocket connected to {ws_url}");

        let (mut write, mut read) = ws_stream.split();

        // Send auth frame.
        let auth_msg = serde_json::json!({
            "type": "auth",
            "device_id": device_id,
            "token": auth_token,
        });
        write.send(Message::Text(auth_msg.to_string())).await.map_err(|e| {
            warn!("[prism_ws] Auth send FAILED: {e}");
            format!("WS auth send failed: {e}")
        })?;

        debug!("[prism_ws] Auth frame sent, waiting for messages");
        debug!("WebSocket auth frame sent");

        // Ping timer.
        let mut ping_interval = time::interval(Duration::from_secs(PING_INTERVAL_SECS));
        // Skip the immediate first tick.
        ping_interval.tick().await;

        loop {
            tokio::select! {
                _ = ping_interval.tick() => {
                    if intentional_close.load(Ordering::SeqCst) {
                        let _ = write.send(Message::Close(None)).await;
                        break;
                    }
                    if let Err(e) = write.send(Message::Ping(vec![])).await {
                        return Err(format!("WS ping send failed: {e}"));
                    }
                }
                msg = read.next() => {
                    match msg {
                        Some(Ok(Message::Text(text))) => {
                            Self::handle_message(&text, notification_tx, connected);
                        }
                        Some(Ok(Message::Close(_))) => {
                            debug!("WebSocket received close frame");
                            break;
                        }
                        Some(Ok(_)) => {
                            // Binary, Ping, Pong — ignore.
                        }
                        Some(Err(e)) => {
                            return Err(format!("WS read error: {e}"));
                        }
                        None => {
                            // Stream ended.
                            break;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Parse a JSON text message and broadcast the appropriate notification.
    fn handle_message(
        text: &str,
        notification_tx: &broadcast::Sender<SyncNotification>,
        connected: &AtomicBool,
    ) {
        let parsed: serde_json::Value = match serde_json::from_str(text) {
            Ok(v) => v,
            Err(e) => {
                warn!("WebSocket received non-JSON message: {e}");
                return;
            }
        };

        let msg_type = parsed["type"].as_str().unwrap_or("");

        let notification = match msg_type {
            "new_data" => {
                let server_seq = parsed["server_seq"].as_i64().unwrap_or(0);
                Some(SyncNotification::NewData { server_seq })
            }
            "device_revoked" => {
                let device_id = parsed["device_id"].as_str().unwrap_or("").to_string();
                let new_epoch = parsed["new_epoch"].as_i64().unwrap_or(0) as i32;
                let remote_wipe = parsed["remote_wipe"].as_bool().unwrap_or(false);
                Some(SyncNotification::DeviceRevoked { device_id, new_epoch, remote_wipe })
            }
            "epoch_rotated" => {
                let new_epoch = parsed["new_epoch"].as_i64().unwrap_or(0) as i32;
                Some(SyncNotification::EpochRotated { new_epoch })
            }
            "token_rotated" => {
                let new_token = parsed["new_token"].as_str().unwrap_or("").to_string();
                Some(SyncNotification::TokenRotated { new_token })
            }
            "pong" => {
                // Keepalive response — ignore.
                None
            }
            "auth_ok" => {
                connected.store(true, Ordering::SeqCst);
                let _ = notification_tx
                    .send(SyncNotification::ConnectionStateChanged { connected: true });
                debug!("[prism_ws] auth_ok received — authenticated successfully");
                debug!("WebSocket auth_ok received");
                None
            }
            _ => {
                debug!("WebSocket unknown message type: {msg_type}");
                None
            }
        };

        if let Some(n) = notification {
            // Ignore send error (no active receivers).
            let _ = notification_tx.send(n);
        }
    }
}
