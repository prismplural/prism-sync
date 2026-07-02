use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures_util::future::BoxFuture;
use futures_util::{FutureExt, SinkExt, StreamExt};
use rand::Rng;
use tokio::sync::broadcast;
use tokio::time;
use tokio_tungstenite::tungstenite::Error as TungsteniteError;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, error, info, warn};

use super::redact_url;
use super::traits::{RelayError, SyncNotification};
use crate::runtime::background_runtime;

/// Maximum reconnect delay in seconds.
const MAX_RECONNECT_DELAY_SECS: u64 = 30;

/// Ping interval in seconds.
const PING_INTERVAL_SECS: u64 = 30;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefreshSessionPolicy {
    AllowRefresh,
    ExistingTokenOnly,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RefreshSessionResult {
    Refreshed(String),
    CurrentToken(String),
}

pub type RefreshSessionCallback = Arc<
    dyn Fn(
            String,
            RefreshSessionPolicy,
        ) -> BoxFuture<'static, Result<Option<RefreshSessionResult>, RelayError>>
        + Send
        + Sync,
>;

#[derive(Debug)]
enum WebSocketRunError {
    AuthStatus(u16),
    Other(String),
}

impl std::fmt::Display for WebSocketRunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WebSocketRunError::AuthStatus(status) => {
                write!(f, "websocket auth failed with HTTP {status}")
            }
            WebSocketRunError::Other(message) => f.write_str(message),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum AuthFailureAction {
    RetryWithToken { token: String, refresh_attempted: bool },
    RetryWithBackoff,
    RetryWithBackoffAfterRefreshFailure,
    Stop,
}

/// WebSocket client for real-time sync notifications.
///
/// Features:
/// - Bearer auth during the HTTP upgrade (credentials are not placed in the URL)
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
    refresh_session: Option<RefreshSessionCallback>,
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
        refresh_session: Option<RefreshSessionCallback>,
        notification_tx: broadcast::Sender<SyncNotification>,
    ) -> Self {
        Self {
            ws_url,
            device_id,
            auth_token,
            refresh_session,
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
        let mut auth_token = self.auth_token.clone();
        let refresh_session = self.refresh_session.clone();
        let notification_tx = self.notification_tx.clone();
        let intentional_close = Arc::clone(&self.intentional_close);
        let connected = Arc::clone(&self.connected);

        info!("[prism_ws] Starting reconnect loop for {}", redact_url(&ws_url));

        let handle = background_runtime().spawn(async move {
            let safe_url = redact_url(&ws_url);
            let mut attempt: u32 = 0;
            let mut refresh_attempted_for_current_token = false;
            let mut post_refresh_retry_consumed_for_current_token = false;

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
                let was_connected = connected.swap(false, Ordering::SeqCst);
                if was_connected {
                    let _ = notification_tx
                        .send(SyncNotification::ConnectionStateChanged { connected: false });
                    refresh_attempted_for_current_token = false;
                    post_refresh_retry_consumed_for_current_token = false;
                }

                match run_result {
                    Err(panic_val) => {
                        refresh_attempted_for_current_token = false;
                        post_refresh_retry_consumed_for_current_token = false;
                        let msg = panic_val
                            .downcast_ref::<&str>()
                            .copied()
                            .or_else(|| panic_val.downcast_ref::<String>().map(String::as_str))
                            .unwrap_or("unknown panic");
                        error!("[prism_ws] PANIC in run_connection (attempt {attempt}): {msg}");
                    }
                    Ok(Ok(())) => {
                        refresh_attempted_for_current_token = false;
                        post_refresh_retry_consumed_for_current_token = false;
                        // Clean disconnect or intentional close.
                        if intentional_close.load(Ordering::SeqCst) {
                            debug!("[prism_ws] Intentional close after run_connection");
                            break;
                        }
                        // Unexpected clean close — reconnect.
                        warn!("[prism_ws] Connection closed cleanly (unexpected), reconnecting");
                        attempt = 0;
                    }
                    Ok(Err(WebSocketRunError::AuthStatus(status))) => {
                        warn!(
                            "[prism_ws] Auth failed during WebSocket upgrade \
                             (HTTP {status}, attempt {attempt})"
                        );
                        match Self::resolve_auth_failure(
                            status,
                            &auth_token,
                            refresh_attempted_for_current_token,
                            post_refresh_retry_consumed_for_current_token,
                            refresh_session.as_ref(),
                            &notification_tx,
                            &device_id,
                        )
                        .await
                        {
                            AuthFailureAction::RetryWithToken {
                                token,
                                refresh_attempted,
                            } => {
                                auth_token = token;
                                refresh_attempted_for_current_token = refresh_attempted;
                                post_refresh_retry_consumed_for_current_token = false;
                                continue;
                            }
                            AuthFailureAction::RetryWithBackoff => {}
                            AuthFailureAction::RetryWithBackoffAfterRefreshFailure => {
                                refresh_attempted_for_current_token = true;
                                post_refresh_retry_consumed_for_current_token = true;
                            }
                            AuthFailureAction::Stop => break,
                        }
                    }
                    Ok(Err(e)) => {
                        refresh_attempted_for_current_token = false;
                        post_refresh_retry_consumed_for_current_token = false;
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
        _device_id: &str,
        auth_token: &str,
        notification_tx: &broadcast::Sender<SyncNotification>,
        intentional_close: &AtomicBool,
        connected: &AtomicBool,
    ) -> Result<(), WebSocketRunError> {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        use tokio_tungstenite::tungstenite::http::{header::AUTHORIZATION, HeaderValue};

        // Do NOT set Sec-WebSocket-Protocol. If the client sends this header,
        // tungstenite requires the server to echo it in the 101 response. The
        // relay's Axum WebSocketUpgrade handler does not call .protocols(), so
        // it omits the header, causing tungstenite to reject the handshake with
        // SubProtocolError::NoSubProtocol. Omitting the header entirely avoids
        // this and matches the relay's behavior.
        let mut request = ws_url
            .into_client_request()
            .map_err(|e| WebSocketRunError::Other(format!("invalid WS URL: {e}")))?;
        let auth_header = HeaderValue::from_str(&format!("Bearer {auth_token}"))
            .map_err(|e| WebSocketRunError::Other(format!("invalid WS auth header: {e}")))?;
        request.headers_mut().insert(AUTHORIZATION, auth_header);

        let safe_url = redact_url(ws_url);
        info!("[prism_ws] TCP/TLS connecting to {safe_url}");
        let connect_result = tokio_tungstenite::connect_async(request).await;
        let (ws_stream, _response) = match connect_result {
            Ok(result) => result,
            Err(e) => {
                if let Some(status) = Self::auth_status_from_error(&e) {
                    warn!("[prism_ws] connect_async auth rejected with HTTP {status}");
                    return Err(WebSocketRunError::AuthStatus(status));
                }
                warn!("[prism_ws] connect_async FAILED: {e}");
                return Err(WebSocketRunError::Other(format!("WS connect failed: {e}")));
            }
        };

        info!("[prism_ws] Connected successfully to {safe_url}");
        info!("WebSocket connected to {ws_url}");

        let (mut write, mut read) = ws_stream.split();

        debug!("[prism_ws] WebSocket upgraded, waiting for messages");

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
                        return Err(WebSocketRunError::Other(format!("WS ping send failed: {e}")));
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
                            return Err(WebSocketRunError::Other(format!("WS read error: {e}")));
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

    fn auth_status_from_error(error: &TungsteniteError) -> Option<u16> {
        match error {
            TungsteniteError::Http(response) => {
                let status = response.status().as_u16();
                // The relay's websocket bearer-session middleware returns 401
                // for missing, expired, invalid, or revoked sessions. 403 is
                // reserved for forbidden request shapes after auth, such as a
                // path sync_id mismatch, so spending a signed refresh on 403
                // would hide a real authorization failure.
                (status == 401).then_some(status)
            }
            _ => None,
        }
    }

    async fn resolve_auth_failure(
        status: u16,
        failed_token: &str,
        refresh_already_attempted: bool,
        post_refresh_retry_consumed: bool,
        refresh_session: Option<&RefreshSessionCallback>,
        notification_tx: &broadcast::Sender<SyncNotification>,
        device_id: &str,
    ) -> AuthFailureAction {
        let Some(refresh_session) = refresh_session else {
            warn!("[prism_ws] Session refresh unavailable after WebSocket auth failure; retrying");
            return AuthFailureAction::RetryWithBackoff;
        };
        let terminal_message: Option<String>;
        {
            let policy = if refresh_already_attempted {
                RefreshSessionPolicy::ExistingTokenOnly
            } else {
                RefreshSessionPolicy::AllowRefresh
            };
            match refresh_session(failed_token.to_string(), policy).await {
                Ok(Some(result)) => match result {
                    RefreshSessionResult::Refreshed(new_token) => {
                        info!("[prism_ws] Session refresh succeeded after WebSocket auth failure");
                        return AuthFailureAction::RetryWithToken {
                            token: new_token,
                            refresh_attempted: true,
                        };
                    }
                    RefreshSessionResult::CurrentToken(new_token) => {
                        info!(
                            "[prism_ws] Reusing newer session token after WebSocket auth failure"
                        );
                        return AuthFailureAction::RetryWithToken {
                            token: new_token,
                            refresh_attempted: false,
                        };
                    }
                },
                Ok(None) => {
                    if refresh_already_attempted {
                        if post_refresh_retry_consumed {
                            warn!(
                                "[prism_ws] No newer session token after refreshed WebSocket token failed"
                            );
                            terminal_message = Some(
                                "Sync could not authenticate with the relay after the refreshed WebSocket token was rejected."
                                    .to_string(),
                            );
                        } else {
                            warn!(
                                "[prism_ws] Refreshed WebSocket token failed; retrying once with backoff"
                            );
                            return AuthFailureAction::RetryWithBackoffAfterRefreshFailure;
                        }
                    } else {
                        warn!(
                            "[prism_ws] Session refresh unavailable after WebSocket auth failure; retrying"
                        );
                        return AuthFailureAction::RetryWithBackoff;
                    }
                }
                Err(RelayError::DeviceRevoked { remote_wipe }) => {
                    let _ = notification_tx.send(SyncNotification::DeviceRevoked {
                        device_id: device_id.to_string(),
                        new_epoch: 0,
                        remote_wipe,
                    });
                    return AuthFailureAction::Stop;
                }
                Err(e) if Self::is_retryable_refresh_error(&e) => {
                    warn!(
                        error = %e,
                        "[prism_ws] Session refresh failed transiently after WebSocket auth failure"
                    );
                    return AuthFailureAction::RetryWithBackoff;
                }
                Err(
                    e @ (RelayError::Auth { .. }
                    | RelayError::DeviceIdentityMismatch { .. }
                    | RelayError::UpgradeRequired { .. }),
                ) => {
                    warn!(
                        error = %e,
                        "[prism_ws] Session refresh failed with terminal auth error after WebSocket auth failure"
                    );
                    terminal_message = Some(format!(
                        "Sync could not authenticate with the relay after session refresh: {e}"
                    ));
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        "[prism_ws] Session refresh failed unexpectedly after WebSocket auth failure"
                    );
                    return AuthFailureAction::RetryWithBackoff;
                }
            }
        }

        let message = terminal_message.unwrap_or_else(|| {
            "Sync could not authenticate with the relay after session refresh.".to_string()
        });
        let _ = notification_tx.send(SyncNotification::WebSocketAuthFailed { status, message });
        AuthFailureAction::Stop
    }

    fn is_retryable_refresh_error(error: &RelayError) -> bool {
        matches!(
            error,
            RelayError::Network { .. } | RelayError::Timeout { .. } | RelayError::Server { .. }
        )
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
                // SECURITY (H3): this frame is an UNTRUSTED HINT — it carries no
                // signature. Consumers MUST NOT take any destructive action on
                // it alone; they gate wipes/credential-clears on
                // `PrismSync::confirm_self_revocation` (a signature-verified
                // signed-registry check). Do NOT add trust to this parser.
                let device_id = parsed["device_id"].as_str().unwrap_or("").to_string();
                let new_epoch = parsed["new_epoch"].as_i64().unwrap_or(0) as i32;
                // TODO(security): bind remote_wipe intent into the signed
                // revocation artifact (Layer B). This bool is relay-controlled
                // here; after Layer A only a verifiably-revoked device can wipe,
                // but the wipe *intent* is still unauthenticated. Binding it into
                // the signed revocation would close the residual.
                let remote_wipe = parsed["remote_wipe"].as_bool().unwrap_or(false);
                Some(SyncNotification::DeviceRevoked { device_id, new_epoch, remote_wipe })
            }
            "epoch_rotated" => {
                let new_epoch = parsed["new_epoch"].as_i64().unwrap_or(0) as i32;
                Some(SyncNotification::EpochRotated { new_epoch })
            }
            "rekey_needed" => {
                // A cleanup-time hint that the 90d auto-revoke left the group
                // owing a forced rotation. Carries no key material — the reacting
                // device drives the rekey from a freshly imported VERIFIED
                // registry, so the relay cannot steer who receives the new epoch
                // key. Safe to act on as a trigger (it cannot cause a destructive
                // action): the worst case is a no-op rekey already resolved by a
                // peer, which the epoch CAS turns into a benign reconcile.
                Some(SyncNotification::RekeyNeeded)
            }
            // NOTE: no `token_rotated` WS arm. The relay never legitimately
            // sends this frame (the only producer is the in-process signed
            // `/session/refresh` flow, which broadcasts `TokenRotated` directly
            // on `notification_tx`). Decoding it here would let an untrusted
            // relay clobber the persisted session token — the notification
            // handler now writes `TokenRotated` to the secure store — so the
            // credential-store write path stays restricted to refresh-originated
            // rotations. A token rotation pushed over WS is dropped as unknown.
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    #[derive(Clone, Copy)]
    enum StubAction {
        Reject(u16),
        CloseWithoutResponse,
    }

    fn spawn_ws_auth_reject_stub(requests_to_accept: usize) -> (String, Arc<Mutex<Vec<String>>>) {
        spawn_ws_stub(vec![StubAction::Reject(401); requests_to_accept])
    }

    fn spawn_ws_stub(actions: Vec<StubAction>) -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let auth_headers = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&auth_headers);

        std::thread::spawn(move || {
            for action in actions {
                let Ok((mut stream, _)) = listener.accept() else {
                    break;
                };
                let auth = read_auth_header(&mut stream);
                captured.lock().unwrap().push(auth);
                match action {
                    StubAction::Reject(status) => {
                        let reason = match status {
                            401 => "Unauthorized",
                            403 => "Forbidden",
                            _ => "Error",
                        };
                        let response = format!(
                            "HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        );
                        let _ = stream.write_all(response.as_bytes());
                        let _ = stream.flush();
                    }
                    StubAction::CloseWithoutResponse => {}
                }
            }
        });

        (format!("ws://127.0.0.1:{}/v1/sync/test/ws", addr.port()), auth_headers)
    }

    fn read_auth_header(stream: &mut TcpStream) -> String {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        while !buf.windows(4).any(|window| window == b"\r\n\r\n") && buf.len() < 16 * 1024 {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        let req = String::from_utf8_lossy(&buf);
        req.lines()
            .find(|line| line.to_ascii_lowercase().starts_with("authorization:"))
            .unwrap_or("")
            .to_string()
    }

    async fn wait_for_auth_count(auth_headers: &Arc<Mutex<Vec<String>>>, count: usize) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while auth_headers.lock().unwrap().len() < count {
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for {count} websocket requests"
            );
            time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test]
    async fn websocket_auth_401_refreshes_once_and_retries_with_fresh_token() {
        let (ws_url, auth_headers) = spawn_ws_auth_reject_stub(3);
        let (notification_tx, mut notification_rx) = broadcast::channel(8);
        let refresh_calls = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&refresh_calls);
        let refresh_session: RefreshSessionCallback = Arc::new(move |_failed_token, policy| {
            let calls = Arc::clone(&calls);
            Box::pin(async move {
                if policy == RefreshSessionPolicy::ExistingTokenOnly {
                    return Ok(None);
                }
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(Some(RefreshSessionResult::Refreshed("fresh-token".to_string())))
            })
        });
        let client = WebSocketClient::new(
            ws_url,
            "device-1".to_string(),
            "expired-token".to_string(),
            Some(refresh_session),
            notification_tx,
        );

        client.connect().await;

        let notification = time::timeout(Duration::from_secs(10), notification_rx.recv())
            .await
            .expect("terminal auth notification")
            .expect("notification channel open");
        assert!(matches!(notification, SyncNotification::WebSocketAuthFailed { status: 401, .. }));
        wait_for_auth_count(&auth_headers, 3).await;

        let headers = auth_headers.lock().unwrap().clone();
        assert!(headers[0].contains("Bearer expired-token"), "{headers:?}");
        assert!(headers[1].contains("Bearer fresh-token"), "{headers:?}");
        assert!(headers[2].contains("Bearer fresh-token"), "{headers:?}");
        assert_eq!(
            refresh_calls.load(Ordering::SeqCst),
            1,
            "401s after refresh must not start a refresh loop"
        );

        client.disconnect().await;
    }

    #[tokio::test]
    async fn websocket_auth_terminal_refresh_error_reports_cause() {
        let (ws_url, auth_headers) = spawn_ws_auth_reject_stub(1);
        let (notification_tx, mut notification_rx) = broadcast::channel(8);
        let refresh_session: RefreshSessionCallback = Arc::new(move |_failed_token, _policy| {
            Box::pin(async move {
                Err(RelayError::UpgradeRequired {
                    min_signature_version: 4,
                    message: "update required".to_string(),
                })
            })
        });
        let client = WebSocketClient::new(
            ws_url,
            "device-1".to_string(),
            "expired-token".to_string(),
            Some(refresh_session),
            notification_tx,
        );

        client.connect().await;

        let notification = time::timeout(Duration::from_secs(2), notification_rx.recv())
            .await
            .expect("terminal auth notification")
            .expect("notification channel open");
        assert!(matches!(
            notification,
            SyncNotification::WebSocketAuthFailed {
                status: 401,
                ref message
            } if message.contains("upgrade required")
                && message.contains("min_signature_version=4")
        ));
        wait_for_auth_count(&auth_headers, 1).await;

        client.disconnect().await;
    }

    #[tokio::test]
    async fn websocket_auth_refresh_device_revoked_stops_without_reconnect() {
        let (ws_url, auth_headers) = spawn_ws_auth_reject_stub(1);
        let (notification_tx, mut notification_rx) = broadcast::channel(8);
        let refresh_calls = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&refresh_calls);
        let refresh_session: RefreshSessionCallback = Arc::new(move |_failed_token, _policy| {
            let calls = Arc::clone(&calls);
            Box::pin(async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Err(RelayError::DeviceRevoked { remote_wipe: true })
            })
        });
        let client = WebSocketClient::new(
            ws_url,
            "device-1".to_string(),
            "expired-token".to_string(),
            Some(refresh_session),
            notification_tx,
        );

        client.connect().await;

        let notification = time::timeout(Duration::from_secs(2), notification_rx.recv())
            .await
            .expect("revoked notification")
            .expect("notification channel open");
        assert!(matches!(
            notification,
            SyncNotification::DeviceRevoked {
                ref device_id,
                remote_wipe: true,
                ..
            } if device_id == "device-1"
        ));
        wait_for_auth_count(&auth_headers, 1).await;
        time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            auth_headers.lock().unwrap().len(),
            1,
            "revoked refresh must not reconnect the websocket"
        );
        assert_eq!(refresh_calls.load(Ordering::SeqCst), 1);

        client.disconnect().await;
    }

    #[tokio::test]
    async fn websocket_auth_transient_refresh_failure_retries_with_backoff() {
        let (ws_url, auth_headers) = spawn_ws_auth_reject_stub(4);
        let (notification_tx, mut notification_rx) = broadcast::channel(8);
        let refresh_calls = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&refresh_calls);
        let refresh_session: RefreshSessionCallback = Arc::new(move |_failed_token, policy| {
            let calls = Arc::clone(&calls);
            Box::pin(async move {
                if policy == RefreshSessionPolicy::ExistingTokenOnly {
                    return Ok(None);
                }
                let call = calls.fetch_add(1, Ordering::SeqCst);
                if call == 0 {
                    Err(RelayError::Network { message: "offline".to_string() })
                } else {
                    Ok(Some(RefreshSessionResult::Refreshed("fresh-token".to_string())))
                }
            })
        });
        let client = WebSocketClient::new(
            ws_url,
            "device-1".to_string(),
            "expired-token".to_string(),
            Some(refresh_session),
            notification_tx,
        );

        client.connect().await;

        let notification = time::timeout(Duration::from_secs(15), notification_rx.recv())
            .await
            .expect("terminal auth notification after retrying refresh")
            .expect("notification channel open");
        assert!(matches!(notification, SyncNotification::WebSocketAuthFailed { status: 401, .. }));
        wait_for_auth_count(&auth_headers, 4).await;

        let headers = auth_headers.lock().unwrap().clone();
        assert!(headers[0].contains("Bearer expired-token"), "{headers:?}");
        assert!(headers[1].contains("Bearer expired-token"), "{headers:?}");
        assert!(headers[2].contains("Bearer fresh-token"), "{headers:?}");
        assert!(headers[3].contains("Bearer fresh-token"), "{headers:?}");
        assert_eq!(
            refresh_calls.load(Ordering::SeqCst),
            2,
            "transient refresh failure must not become terminal auth"
        );

        client.disconnect().await;
    }

    #[tokio::test]
    async fn websocket_auth_unexpected_refresh_failure_retries_with_backoff() {
        let (ws_url, auth_headers) = spawn_ws_auth_reject_stub(4);
        let (notification_tx, mut notification_rx) = broadcast::channel(8);
        let refresh_calls = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&refresh_calls);
        let refresh_session: RefreshSessionCallback = Arc::new(move |_failed_token, policy| {
            let calls = Arc::clone(&calls);
            Box::pin(async move {
                if policy == RefreshSessionPolicy::ExistingTokenOnly {
                    return Ok(None);
                }
                let call = calls.fetch_add(1, Ordering::SeqCst);
                if call == 0 {
                    Err(RelayError::Protocol { message: "unexpected refresh response".to_string() })
                } else {
                    Ok(Some(RefreshSessionResult::Refreshed("fresh-token".to_string())))
                }
            })
        });
        let client = WebSocketClient::new(
            ws_url,
            "device-1".to_string(),
            "expired-token".to_string(),
            Some(refresh_session),
            notification_tx,
        );

        client.connect().await;

        let notification = time::timeout(Duration::from_secs(15), notification_rx.recv())
            .await
            .expect("terminal auth notification after retrying refresh")
            .expect("notification channel open");
        assert!(matches!(notification, SyncNotification::WebSocketAuthFailed { status: 401, .. }));
        wait_for_auth_count(&auth_headers, 4).await;

        let headers = auth_headers.lock().unwrap().clone();
        assert!(headers[0].contains("Bearer expired-token"), "{headers:?}");
        assert!(headers[1].contains("Bearer expired-token"), "{headers:?}");
        assert!(headers[2].contains("Bearer fresh-token"), "{headers:?}");
        assert!(headers[3].contains("Bearer fresh-token"), "{headers:?}");
        assert_eq!(
            refresh_calls.load(Ordering::SeqCst),
            2,
            "unexpected refresh failure must not become terminal auth"
        );

        client.disconnect().await;
    }

    #[tokio::test]
    async fn websocket_auth_uses_newer_current_token_after_refresh_race() {
        let (ws_url, auth_headers) = spawn_ws_auth_reject_stub(3);
        let (notification_tx, mut notification_rx) = broadcast::channel(8);
        let refresh_calls = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&refresh_calls);
        let refresh_session: RefreshSessionCallback = Arc::new(move |failed_token, policy| {
            let calls = Arc::clone(&calls);
            Box::pin(async move {
                let call = calls.fetch_add(1, Ordering::SeqCst);
                match (call, policy, failed_token.as_str()) {
                    (0, RefreshSessionPolicy::AllowRefresh, "expired-token") => {
                        Ok(Some(RefreshSessionResult::Refreshed("ws-token".to_string())))
                    }
                    (1, RefreshSessionPolicy::ExistingTokenOnly, "ws-token") => {
                        Ok(Some(RefreshSessionResult::CurrentToken("http-token".to_string())))
                    }
                    (2, RefreshSessionPolicy::AllowRefresh, "http-token") => {
                        Err(RelayError::Auth { message: "current token rejected".to_string() })
                    }
                    _ => Ok(None),
                }
            })
        });
        let client = WebSocketClient::new(
            ws_url,
            "device-1".to_string(),
            "expired-token".to_string(),
            Some(refresh_session),
            notification_tx,
        );

        client.connect().await;

        let notification = time::timeout(Duration::from_secs(2), notification_rx.recv())
            .await
            .expect("terminal auth notification after retrying newer current token")
            .expect("notification channel open");
        assert!(matches!(notification, SyncNotification::WebSocketAuthFailed { status: 401, .. }));
        wait_for_auth_count(&auth_headers, 3).await;

        let headers = auth_headers.lock().unwrap().clone();
        assert!(headers[0].contains("Bearer expired-token"), "{headers:?}");
        assert!(headers[1].contains("Bearer ws-token"), "{headers:?}");
        assert!(headers[2].contains("Bearer http-token"), "{headers:?}");
        assert_eq!(
            refresh_calls.load(Ordering::SeqCst),
            3,
            "newer current token should be tried before terminal auth"
        );

        client.disconnect().await;
    }

    #[tokio::test]
    async fn websocket_auth_without_refresh_callback_retries_with_backoff() {
        let (ws_url, auth_headers) = spawn_ws_auth_reject_stub(2);
        let (notification_tx, mut notification_rx) = broadcast::channel(8);
        let client = WebSocketClient::new(
            ws_url,
            "device-1".to_string(),
            "expired-token".to_string(),
            None,
            notification_tx,
        );

        client.connect().await;

        wait_for_auth_count(&auth_headers, 2).await;
        let maybe_notification =
            time::timeout(Duration::from_millis(150), notification_rx.recv()).await;
        assert!(
            maybe_notification.is_err(),
            "callback-less 401 should retry instead of emitting terminal auth"
        );

        client.disconnect().await;
    }

    #[tokio::test]
    async fn websocket_auth_unavailable_refresh_retries_with_backoff() {
        let (ws_url, auth_headers) = spawn_ws_auth_reject_stub(2);
        let (notification_tx, mut notification_rx) = broadcast::channel(8);
        let refresh_calls = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&refresh_calls);
        let refresh_session: RefreshSessionCallback = Arc::new(move |_failed_token, _policy| {
            let calls = Arc::clone(&calls);
            Box::pin(async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(None)
            })
        });
        let client = WebSocketClient::new(
            ws_url,
            "device-1".to_string(),
            "expired-token".to_string(),
            Some(refresh_session),
            notification_tx,
        );

        client.connect().await;

        wait_for_auth_count(&auth_headers, 2).await;
        let maybe_notification =
            time::timeout(Duration::from_millis(150), notification_rx.recv()).await;
        assert!(
            maybe_notification.is_err(),
            "unavailable refresh route should retry instead of emitting terminal auth"
        );
        assert_eq!(
            refresh_calls.load(Ordering::SeqCst),
            2,
            "unavailable refresh route should keep checking on later 401s"
        );

        client.disconnect().await;
    }

    #[tokio::test]
    async fn websocket_403_retries_without_session_refresh() {
        let (ws_url, auth_headers) =
            spawn_ws_stub(vec![StubAction::Reject(403), StubAction::Reject(403)]);
        let (notification_tx, mut notification_rx) = broadcast::channel(8);
        let refresh_calls = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&refresh_calls);
        let refresh_session: RefreshSessionCallback = Arc::new(move |_failed_token, _policy| {
            let calls = Arc::clone(&calls);
            Box::pin(async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(Some(RefreshSessionResult::Refreshed("fresh-token".to_string())))
            })
        });
        let client = WebSocketClient::new(
            ws_url,
            "device-1".to_string(),
            "expired-token".to_string(),
            Some(refresh_session),
            notification_tx,
        );

        client.connect().await;

        wait_for_auth_count(&auth_headers, 2).await;
        let maybe_notification =
            time::timeout(Duration::from_millis(150), notification_rx.recv()).await;
        assert!(
            maybe_notification.is_err(),
            "403 should use generic reconnect backoff instead of terminal auth"
        );
        assert_eq!(
            refresh_calls.load(Ordering::SeqCst),
            0,
            "403 should not spend a signed session refresh"
        );

        client.disconnect().await;
    }

    #[tokio::test]
    async fn websocket_auth_refresh_guard_resets_after_non_auth_failure() {
        let (ws_url, auth_headers) = spawn_ws_stub(vec![
            StubAction::Reject(401),
            StubAction::CloseWithoutResponse,
            StubAction::Reject(401),
            StubAction::Reject(401),
            StubAction::Reject(401),
        ]);
        let (notification_tx, mut notification_rx) = broadcast::channel(8);
        let refresh_calls = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&refresh_calls);
        let refresh_session: RefreshSessionCallback = Arc::new(move |_failed_token, policy| {
            let calls = Arc::clone(&calls);
            Box::pin(async move {
                if policy == RefreshSessionPolicy::ExistingTokenOnly {
                    return Ok(None);
                }
                let call = calls.fetch_add(1, Ordering::SeqCst);
                Ok(Some(RefreshSessionResult::Refreshed(format!("fresh-token-{call}"))))
            })
        });
        let client = WebSocketClient::new(
            ws_url,
            "device-1".to_string(),
            "expired-token".to_string(),
            Some(refresh_session),
            notification_tx,
        );

        client.connect().await;

        let notification = time::timeout(Duration::from_secs(15), notification_rx.recv())
            .await
            .expect("terminal auth notification after second refreshed token fails")
            .expect("notification channel open");
        assert!(matches!(notification, SyncNotification::WebSocketAuthFailed { status: 401, .. }));
        wait_for_auth_count(&auth_headers, 5).await;

        let headers = auth_headers.lock().unwrap().clone();
        assert!(headers[0].contains("Bearer expired-token"), "{headers:?}");
        assert!(headers[1].contains("Bearer fresh-token-0"), "{headers:?}");
        assert!(headers[2].contains("Bearer fresh-token-0"), "{headers:?}");
        assert!(headers[3].contains("Bearer fresh-token-1"), "{headers:?}");
        assert!(headers[4].contains("Bearer fresh-token-1"), "{headers:?}");
        assert_eq!(
            refresh_calls.load(Ordering::SeqCst),
            2,
            "non-auth reconnect failures must not make later 401s use ExistingTokenOnly"
        );

        client.disconnect().await;
    }
}
