use std::collections::HashMap;
use std::pin::Pin;
use std::time::Duration;

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{DateTime, Utc};
use futures_util::Stream;
use reqwest::Client;
use tokio::sync::broadcast;
use tracing::debug;

use super::redact_url;
use super::traits::*;
use super::websocket::WebSocketClient;

/// HTTP relay client for the V2 sync API.
///
/// Ported from Dart `lib/core/sync/server_relay.dart`.
pub struct ServerRelay {
    base_url: String,
    sync_id: String,
    device_id: String,
    device_session_token: String,
    client: Client,
    request_timeout: Duration,
    snapshot_timeout: Duration,
    notification_tx: broadcast::Sender<SyncNotification>,
    ws_client: tokio::sync::Mutex<Option<WebSocketClient>>,
}

impl ServerRelay {
    /// Create a new `ServerRelay`.
    ///
    /// Returns an error if `base_url` does not start with `https://`
    /// (unless it starts with `http://localhost`, which is allowed for
    /// local development).
    pub fn new(
        base_url: String,
        sync_id: String,
        device_id: String,
        device_session_token: String,
    ) -> Result<Self, String> {
        if !base_url.starts_with("https://") && !base_url.starts_with("http://localhost") {
            return Err(format!(
                "ServerRelay requires an HTTPS URL (got: {base_url:?}). \
                 Use http://localhost only for local development."
            ));
        }

        let (notification_tx, _) = broadcast::channel(64);
        // NOTE: Do NOT set a global timeout on the Client — use per-request
        // timeouts instead, because snapshots need a longer deadline than
        // normal change pulls.
        let client = Client::builder()
            .build()
            .map_err(|e| format!("Failed to build HTTP client: {e}"))?;

        Ok(Self {
            base_url,
            sync_id,
            device_id,
            device_session_token,
            client,
            request_timeout: Duration::from_secs(15),
            snapshot_timeout: Duration::from_secs(120),
            notification_tx,
            ws_client: tokio::sync::Mutex::new(None),
        })
    }

    fn base_path(&self) -> String {
        format!("{}/v1/sync/{}", self.base_url, self.sync_id)
    }

    fn apply_auth(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        builder
            .header(
                "Authorization",
                format!("Bearer {}", self.device_session_token),
            )
            .header("X-Device-Id", &self.device_id)
    }

    /// Classify an HTTP status code into a RelayError.
    fn classify_error(status: u16, body: &str) -> RelayError {
        match status {
            401 | 403 => RelayError::Auth {
                message: format!("HTTP {status}: {body}"),
            },
            408 | 504 => RelayError::Timeout {
                message: format!("HTTP {status}: {body}"),
            },
            409 => RelayError::EpochRotation {
                new_epoch: 0, // caller should parse from body
            },
            500..=599 => RelayError::Server {
                status_code: status,
                message: body.to_string(),
            },
            _ => RelayError::Protocol {
                message: format!("Unexpected HTTP {status}: {body}"),
            },
        }
    }

    /// Classify a reqwest error into a RelayError.
    fn classify_reqwest_error(err: reqwest::Error) -> RelayError {
        if err.is_timeout() {
            RelayError::Timeout {
                message: err.to_string(),
            }
        } else if err.is_connect() || err.is_request() {
            RelayError::Network {
                message: err.to_string(),
            }
        } else if let Some(status) = err.status() {
            Self::classify_error(status.as_u16(), &err.to_string())
        } else {
            RelayError::Network {
                message: err.to_string(),
            }
        }
    }

    /// Whether the WebSocket is currently authenticated and receiving messages.
    pub fn is_websocket_connected(&self) -> bool {
        // Use try_lock to avoid blocking — if the lock is held, assume disconnected.
        self.ws_client
            .try_lock()
            .map(|guard| guard.as_ref().map_or(false, |ws| ws.is_connected()))
            .unwrap_or(false)
    }

    /// Build the WebSocket URL from the base HTTP URL.
    fn ws_url(&self) -> String {
        let scheme = if self.base_url.starts_with("https") {
            "wss"
        } else {
            "ws"
        };
        // Strip the scheme from base_url to get host:port/path.
        let rest = self
            .base_url
            .strip_prefix("https://")
            .or_else(|| self.base_url.strip_prefix("http://"))
            .unwrap_or(&self.base_url);
        format!("{scheme}://{rest}/v1/sync/{}/ws", self.sync_id)
    }
}

#[async_trait]
impl SyncRelay for ServerRelay {
    async fn get_registration_nonce(&self) -> Result<String, RelayError> {
        let url = format!("{}/register-nonce", self.base_path());
        debug!("get_registration_nonce");

        let resp = self
            .client
            .get(&url)
            .timeout(self.request_timeout)
            .send()
            .await
            .map_err(Self::classify_reqwest_error)?;

        let status = resp.status().as_u16();
        if status >= 400 {
            let body_text = resp.text().await.unwrap_or_default();
            return Err(Self::classify_error(status, &body_text));
        }

        let json: serde_json::Value = resp.json().await.map_err(|e| RelayError::Protocol {
            message: format!("Failed to parse nonce response: {e}"),
        })?;

        json["nonce"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| RelayError::Protocol {
                message: "nonce field missing from response".to_string(),
            })
    }

    async fn register_device(&self, req: RegisterRequest) -> Result<RegisterResponse, RelayError> {
        let url = format!("{}/register", self.base_path());

        let body = serde_json::json!({
            "device_id": req.device_id,
            "signing_public_key": hex::encode(&req.signing_public_key),
            "x25519_public_key": hex::encode(&req.x25519_public_key),
            "registration_challenge": hex::encode(&req.registration_challenge),
            "nonce": req.nonce,
            "signed_invitation": req.signed_invitation.as_ref().map(|inv| {
                serde_json::json!({
                    "sync_id": inv.sync_id,
                    "relay_url": inv.relay_url,
                    "wrapped_dek": inv.wrapped_dek,
                    "salt": inv.salt,
                    "inviter_device_id": inv.inviter_device_id,
                    "inviter_ed25519_pk": inv.inviter_ed25519_pk,
                    "signature": inv.signature,
                    "joiner_device_id": inv.joiner_device_id,
                    "current_epoch": inv.current_epoch,
                    "epoch_key_hex": inv.epoch_key_hex,
                })
            }),
        });

        let resp = self
            .apply_auth(self.client.post(&url))
            .json(&body)
            .timeout(self.request_timeout)
            .send()
            .await
            .map_err(Self::classify_reqwest_error)?;

        let status = resp.status().as_u16();
        if status >= 400 {
            let body_text = resp.text().await.unwrap_or_default();
            return Err(Self::classify_error(status, &body_text));
        }

        resp.json::<RegisterResponse>()
            .await
            .map_err(|e| RelayError::Protocol {
                message: format!("Failed to parse register response: {e}"),
            })
    }

    async fn pull_changes(&self, since: i64) -> Result<PullResponse, RelayError> {
        let url = format!("{}/changes?since={since}", self.base_path());
        debug!("pull_changes since={since}");

        let resp = self
            .apply_auth(self.client.get(&url))
            .timeout(self.request_timeout)
            .send()
            .await
            .map_err(Self::classify_reqwest_error)?;

        let status = resp.status().as_u16();
        if status >= 400 {
            let body_text = resp.text().await.unwrap_or_default();
            return Err(Self::classify_error(status, &body_text));
        }

        let json: serde_json::Value = resp.json().await.map_err(|e| RelayError::Protocol {
            message: format!("Failed to parse pull response: {e}"),
        })?;

        let max_server_seq = json["max_server_seq"].as_i64().unwrap_or(0);
        let min_acked_seq = json["min_acked_seq"].as_i64();

        let batches_json = json["batches"].as_array().cloned().unwrap_or_default();

        let mut batches = Vec::with_capacity(batches_json.len());
        for b in batches_json {
            let server_seq = b["server_seq"].as_i64().unwrap_or(0);
            let received_at: DateTime<Utc> = b["received_at"]
                .as_i64()
                .and_then(|ts| DateTime::from_timestamp(ts, 0))
                .unwrap_or_else(Utc::now);
            let envelope: SignedBatchEnvelope = serde_json::from_value(b["envelope"].clone())
                .map_err(|e| RelayError::Protocol {
                    message: format!("Failed to parse envelope: {e}"),
                })?;
            batches.push(ReceivedBatch {
                server_seq,
                received_at,
                envelope,
            });
        }

        Ok(PullResponse {
            batches,
            max_server_seq,
            min_acked_seq,
        })
    }

    async fn push_changes(&self, batch: OutgoingBatch) -> Result<i64, RelayError> {
        let url = format!("{}/changes", self.base_path());
        debug!("push_changes batch_id={}", batch.batch_id);

        let resp = self
            .apply_auth(self.client.put(&url))
            .header("X-Batch-Id", &batch.batch_id)
            .header("X-Epoch", batch.envelope.epoch.to_string())
            .header("Content-Type", "application/json")
            .json(&batch.envelope)
            .timeout(self.request_timeout)
            .send()
            .await
            .map_err(Self::classify_reqwest_error)?;

        let status = resp.status().as_u16();
        if status >= 400 {
            let body_text = resp.text().await.unwrap_or_default();
            return Err(Self::classify_error(status, &body_text));
        }

        let json: serde_json::Value = resp.json().await.map_err(|e| RelayError::Protocol {
            message: format!("Failed to parse push response: {e}"),
        })?;

        Ok(json["server_seq"].as_i64().unwrap_or(0))
    }

    async fn get_snapshot(&self) -> Result<Option<SnapshotResponse>, RelayError> {
        let url = format!("{}/snapshot", self.base_path());
        debug!("get_snapshot");

        let resp = self
            .apply_auth(self.client.get(&url))
            .timeout(self.snapshot_timeout)
            .send()
            .await
            .map_err(Self::classify_reqwest_error)?;

        let status = resp.status().as_u16();
        if status == 404 {
            return Ok(None);
        }
        if status >= 400 {
            let body_text = resp.text().await.unwrap_or_default();
            return Err(Self::classify_error(status, &body_text));
        }

        let epoch: i32 = resp
            .headers()
            .get("X-Epoch")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);

        let server_seq_at: i64 = resp
            .headers()
            .get("X-Server-Seq-At")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);

        let data = resp.bytes().await.map_err(|e| RelayError::Network {
            message: format!("Failed to read snapshot body: {e}"),
        })?;

        Ok(Some(SnapshotResponse {
            epoch,
            server_seq_at,
            data: data.to_vec(),
        }))
    }

    async fn put_snapshot(
        &self,
        epoch: i32,
        server_seq_at: i64,
        data: Vec<u8>,
        ttl_secs: Option<u64>,
        for_device_id: Option<String>,
    ) -> Result<(), RelayError> {
        let url = format!("{}/snapshot", self.base_path());
        debug!("put_snapshot epoch={epoch} server_seq_at={server_seq_at}");

        let mut req = self
            .apply_auth(self.client.put(&url))
            .header("X-Epoch", epoch.to_string())
            .header("X-Server-Seq-At", server_seq_at.to_string());

        if let Some(ttl) = ttl_secs {
            req = req.header("X-Snapshot-TTL", ttl.to_string());
        }
        if let Some(ref device_id) = for_device_id {
            req = req.header("X-For-Device-Id", device_id);
        }

        let resp = req
            .body(data)
            .timeout(self.snapshot_timeout)
            .send()
            .await
            .map_err(Self::classify_reqwest_error)?;

        let status = resp.status().as_u16();
        if status >= 400 {
            let body_text = resp.text().await.unwrap_or_default();
            return Err(Self::classify_error(status, &body_text));
        }

        Ok(())
    }

    async fn list_devices(&self) -> Result<Vec<DeviceInfo>, RelayError> {
        let url = format!("{}/devices", self.base_path());
        debug!("list_devices");

        let resp = self
            .apply_auth(self.client.get(&url))
            .timeout(self.request_timeout)
            .send()
            .await
            .map_err(Self::classify_reqwest_error)?;

        let status = resp.status().as_u16();
        if status >= 400 {
            let body_text = resp.text().await.unwrap_or_default();
            return Err(Self::classify_error(status, &body_text));
        }

        resp.json::<Vec<DeviceInfo>>()
            .await
            .map_err(|e| RelayError::Protocol {
                message: format!("Failed to parse devices response: {e}"),
            })
    }

    async fn revoke_device(&self, device_id: &str, remote_wipe: bool) -> Result<(), RelayError> {
        let mut url = format!("{}/devices/{device_id}", self.base_path());
        if remote_wipe {
            url.push_str("?remote_wipe=true");
        }
        debug!("revoke_device {device_id} remote_wipe={remote_wipe}");

        let resp = self
            .apply_auth(self.client.delete(&url))
            .timeout(self.request_timeout)
            .send()
            .await
            .map_err(Self::classify_reqwest_error)?;

        let status = resp.status().as_u16();
        if status >= 400 {
            let body_text = resp.text().await.unwrap_or_default();
            return Err(Self::classify_error(status, &body_text));
        }

        Ok(())
    }

    async fn check_wipe_status(&self, device_id: &str) -> Result<Option<bool>, RelayError> {
        let url = format!("{}/devices/{}/wipe-status", self.base_path(), device_id);
        // NOTE: This is unauthenticated — do NOT use apply_auth
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(Self::classify_reqwest_error)?;
        match resp.status().as_u16() {
            200 => {
                let json: serde_json::Value =
                    resp.json().await.map_err(|e| RelayError::Protocol {
                        message: format!("Failed to parse wipe-status response: {e}"),
                    })?;
                Ok(json["remote_wipe"].as_bool())
            }
            404 => Ok(None),
            status => Err(RelayError::Protocol {
                message: format!("Unexpected HTTP {status}"),
            }),
        }
    }

    async fn post_rekey_artifacts(
        &self,
        epoch: i32,
        revoked_device_id: &str,
        wrapped_keys: HashMap<String, Vec<u8>>,
    ) -> Result<i32, RelayError> {
        let url = format!("{}/rekey", self.base_path());
        debug!("post_rekey_artifacts epoch={epoch} revoked={revoked_device_id}");

        // Encode wrapped keys as base64.
        let encoded_keys: HashMap<String, String> = wrapped_keys
            .into_iter()
            .map(|(k, v)| (k, BASE64.encode(v)))
            .collect();

        let body = serde_json::json!({
            "epoch": epoch,
            "revoked_device_id": revoked_device_id,
            "wrapped_keys": encoded_keys,
        });

        let resp = self
            .apply_auth(self.client.post(&url))
            .json(&body)
            .timeout(self.request_timeout)
            .send()
            .await
            .map_err(Self::classify_reqwest_error)?;

        let status = resp.status().as_u16();
        if status >= 400 {
            let body_text = resp.text().await.unwrap_or_default();
            return Err(Self::classify_error(status, &body_text));
        }

        let json: serde_json::Value = resp.json().await.map_err(|e| RelayError::Protocol {
            message: format!("Failed to parse rekey response: {e}"),
        })?;

        Ok(json["new_epoch"].as_i64().unwrap_or(epoch as i64) as i32)
    }

    async fn get_rekey_artifact(
        &self,
        epoch: i32,
        device_id: &str,
    ) -> Result<Option<Vec<u8>>, RelayError> {
        let url = format!("{}/rekey/{epoch}/{device_id}", self.base_path());
        debug!("get_rekey_artifact epoch={epoch} device={device_id}");

        let resp = self
            .apply_auth(self.client.get(&url))
            .timeout(self.request_timeout)
            .send()
            .await
            .map_err(Self::classify_reqwest_error)?;

        let status = resp.status().as_u16();
        if status == 404 {
            return Ok(None);
        }
        if status >= 400 {
            let body_text = resp.text().await.unwrap_or_default();
            return Err(Self::classify_error(status, &body_text));
        }

        let json: serde_json::Value = resp.json().await.map_err(|e| RelayError::Protocol {
            message: format!("Failed to parse rekey artifact: {e}"),
        })?;

        let wrapped_key = json["wrapped_key"]
            .as_str()
            .and_then(|s| BASE64.decode(s).ok());

        Ok(wrapped_key)
    }

    async fn deregister(&self) -> Result<(), RelayError> {
        let url = format!("{}/devices/{}", self.base_path(), self.device_id);
        debug!("deregister device_id={}", self.device_id);

        let resp = self
            .apply_auth(self.client.delete(&url))
            .timeout(self.request_timeout)
            .send()
            .await
            .map_err(Self::classify_reqwest_error)?;

        let status = resp.status().as_u16();
        if status >= 400 {
            let body_text = resp.text().await.unwrap_or_default();
            return Err(Self::classify_error(status, &body_text));
        }

        Ok(())
    }

    async fn delete_sync_group(&self) -> Result<(), RelayError> {
        let url = self.base_path();
        debug!("delete_sync_group");

        let resp = self
            .apply_auth(self.client.delete(&url))
            .timeout(self.request_timeout)
            .send()
            .await
            .map_err(Self::classify_reqwest_error)?;

        let status = resp.status().as_u16();
        if status >= 400 {
            let body_text = resp.text().await.unwrap_or_default();
            return Err(Self::classify_error(status, &body_text));
        }

        Ok(())
    }

    async fn ack(&self, server_seq: i64) -> Result<(), RelayError> {
        let url = format!("{}/ack", self.base_path());
        debug!("ack server_seq={server_seq}");

        let body = serde_json::json!({ "server_seq": server_seq });

        let resp = self
            .apply_auth(self.client.post(&url))
            .json(&body)
            .timeout(self.request_timeout)
            .send()
            .await
            .map_err(Self::classify_reqwest_error)?;

        let status = resp.status().as_u16();
        if status >= 400 {
            let body_text = resp.text().await.unwrap_or_default();
            return Err(Self::classify_error(status, &body_text));
        }

        Ok(())
    }

    async fn connect_websocket(&self) -> Result<(), RelayError> {
        let ws_url = self.ws_url();
        eprintln!(
            "[prism_relay] connect_websocket url={}",
            redact_url(&ws_url)
        );
        debug!("connect_websocket url={ws_url}");

        let ws = WebSocketClient::new(
            ws_url,
            self.device_id.clone(),
            self.device_session_token.clone(),
            self.notification_tx.clone(),
        );
        ws.connect().await;

        *self.ws_client.lock().await = Some(ws);
        Ok(())
    }

    async fn disconnect_websocket(&self) -> Result<(), RelayError> {
        debug!("disconnect_websocket");
        if let Some(ws) = self.ws_client.lock().await.as_ref() {
            ws.disconnect().await;
        }
        *self.ws_client.lock().await = None;
        Ok(())
    }

    fn notifications(&self) -> Pin<Box<dyn Stream<Item = SyncNotification> + Send>> {
        let rx = self.notification_tx.subscribe();
        use futures_util::StreamExt;
        Box::pin(
            tokio_stream::wrappers::BroadcastStream::new(rx)
                .filter_map(|r: Result<SyncNotification, _>| async move { r.ok() }),
        )
    }

    async fn dispose(&self) -> Result<(), RelayError> {
        self.disconnect_websocket().await?;
        Ok(())
    }
}
