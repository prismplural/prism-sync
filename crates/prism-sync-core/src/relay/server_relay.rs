use std::collections::HashMap;
use std::pin::Pin;
use std::time::Duration;

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer, SigningKey};
use futures_util::Stream;
use rand::RngCore;
use reqwest::Client;
use sha2::{Digest, Sha256};
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
    request_signing_key: SigningKey,
    request_ml_dsa_signing_key: prism_sync_crypto::DevicePqSigningKey,
    registration_token: Option<String>,
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
        request_signing_key: SigningKey,
        request_ml_dsa_signing_key: prism_sync_crypto::DevicePqSigningKey,
        registration_token: Option<String>,
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
            request_signing_key,
            request_ml_dsa_signing_key,
            registration_token,
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

    fn canonical_path(&self, suffix: &str) -> String {
        format!("/v1/sync/{}{}", self.sync_id, suffix)
    }

    fn apply_auth(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        builder
            .header(
                "Authorization",
                format!("Bearer {}", self.device_session_token),
            )
            .header("X-Device-Id", &self.device_id)
    }

    fn apply_signed_auth(
        &self,
        builder: reqwest::RequestBuilder,
        method: &str,
        canonical_path: &str,
        body: &[u8],
    ) -> reqwest::RequestBuilder {
        let timestamp = Utc::now().timestamp().to_string();
        let mut nonce_bytes = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = hex::encode(nonce_bytes);
        let signing_data =
            self.build_request_signing_data(method, canonical_path, body, &timestamp, &nonce);

        // V3 hybrid signature: Ed25519 + ML-DSA-65 with labeled WNS
        let m_prime = prism_sync_crypto::pq::build_hybrid_message_representative(
            b"http_request",
            &signing_data,
        )
        .expect("hardcoded http request context should be <= 255 bytes");
        let hybrid_sig = prism_sync_crypto::pq::HybridSignature {
            ed25519_sig: self.request_signing_key.sign(&m_prime).to_bytes().to_vec(),
            ml_dsa_65_sig: self.request_ml_dsa_signing_key.sign(&m_prime),
        };
        let mut wire = Vec::with_capacity(1 + hybrid_sig.to_bytes().len());
        wire.push(0x03);
        wire.extend_from_slice(&hybrid_sig.to_bytes());
        let signature_b64 = BASE64.encode(&wire);

        self.apply_auth(builder)
            .header("X-Prism-Timestamp", timestamp)
            .header("X-Prism-Nonce", nonce)
            .header("X-Prism-Signature", signature_b64)
    }

    fn build_request_signing_data(
        &self,
        method: &str,
        canonical_path: &str,
        body: &[u8],
        timestamp: &str,
        nonce: &str,
    ) -> Vec<u8> {
        let body_hash = Sha256::digest(body);
        let mut data = Vec::new();
        data.extend_from_slice(b"PRISM_SYNC_HTTP_V2\x00");
        write_len_prefixed(&mut data, method.as_bytes());
        write_len_prefixed(&mut data, canonical_path.as_bytes());
        write_len_prefixed(&mut data, self.sync_id.as_bytes());
        write_len_prefixed(&mut data, self.device_id.as_bytes());
        data.extend_from_slice(&body_hash);
        write_len_prefixed(&mut data, timestamp.as_bytes());
        write_len_prefixed(&mut data, nonce.as_bytes());
        data
    }

    /// Classify an HTTP status code into a RelayError.
    fn classify_error(status: u16, body: &str) -> RelayError {
        match status {
            401 => {
                // Check if this is a structured auth response from the relay.
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
                    match json.get("error").and_then(|v| v.as_str()) {
                        Some("device_revoked") => {
                            let remote_wipe = json
                                .get("remote_wipe")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false);
                            return RelayError::DeviceRevoked { remote_wipe };
                        }
                        Some("device_identity_mismatch") => {
                            let message = json
                                .get("message")
                                .and_then(|v| v.as_str())
                                .map(str::to_owned)
                                .unwrap_or_else(|| format!("HTTP {status}: {body}"));
                            return RelayError::DeviceIdentityMismatch { message };
                        }
                        _ => {}
                    }
                }
                RelayError::Auth {
                    message: format!("HTTP {status}: {body}"),
                }
            }
            403 => {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
                    if json.get("error").and_then(|v| v.as_str()) == Some("upgrade_required") {
                        let min_signature_version = json
                            .get("min_signature_version")
                            .and_then(|v| v.as_u64())
                            .and_then(|v| u8::try_from(v).ok())
                            .unwrap_or(3);
                        let message = json
                            .get("message")
                            .and_then(|v| v.as_str())
                            .map(str::to_owned)
                            .unwrap_or_else(|| format!("HTTP {status}: {body}"));
                        return RelayError::UpgradeRequired {
                            min_signature_version,
                            message,
                        };
                    }
                }
                RelayError::Auth {
                    message: format!("HTTP {status}: {body}"),
                }
            }
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
            .map(|guard| guard.as_ref().is_some_and(|ws| ws.is_connected()))
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

fn write_len_prefixed(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

#[async_trait]
impl SyncRelay for ServerRelay {
    async fn get_registration_nonce(&self) -> Result<RegistrationNonceResponse, RelayError> {
        let url = format!("{}/register-nonce", self.base_path());
        debug!("get_registration_nonce");

        let mut req = self.client.get(&url).timeout(self.request_timeout);
        if let Some(token) = &self.registration_token {
            req = req.header("X-Registration-Token", token);
        }
        let resp = req.send().await.map_err(Self::classify_reqwest_error)?;

        let status = resp.status().as_u16();
        if status >= 400 {
            let body_text = resp.text().await.unwrap_or_default();
            return Err(Self::classify_error(status, &body_text));
        }

        resp.json::<RegistrationNonceResponse>()
            .await
            .map_err(|e| RelayError::Protocol {
                message: format!("Failed to parse nonce response: {e}"),
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
            "pow_solution": req.pow_solution.as_ref().map(|solution| {
                serde_json::json!({
                    "counter": solution.counter,
                })
            }),
            "first_device_admission_proof": req.first_device_admission_proof.as_ref().map(|proof| {
                serde_json::to_value(proof).expect("first-device admission proof serializes")
            }),
            "registry_approval": req.registry_approval.as_ref().map(|approval| {
                serde_json::json!({
                    "approver_device_id": approval.approver_device_id,
                    "approver_ed25519_pk": approval.approver_ed25519_pk,
                    "approval_signature": approval.approval_signature,
                    "signed_registry_snapshot": approval.signed_registry_snapshot,
                })
            }),
        });

        let mut req = self
            .apply_auth(self.client.post(&url))
            .json(&body)
            .timeout(self.request_timeout);
        if let Some(token) = &self.registration_token {
            req = req.header("X-Registration-Token", token);
        }
        let resp = req.send().await.map_err(Self::classify_reqwest_error)?;

        let status = resp.status().as_u16();
        if status >= 400 {
            let body_text = resp.text().await.unwrap_or_default();
            if status == 409 {
                return Err(RelayError::Protocol {
                    message: format!("HTTP 409: {body_text}"),
                });
            }
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

        let password_version = json
            .get("password_version")
            .and_then(|v| v.as_i64())
            .map(|v| v as i32);

        Ok(PullResponse {
            batches,
            max_server_seq,
            min_acked_seq,
            password_version,
        })
    }

    async fn push_changes(&self, batch: OutgoingBatch) -> Result<i64, RelayError> {
        let url = format!("{}/changes", self.base_path());
        let path = self.canonical_path("/changes");
        debug!("push_changes batch_id={}", batch.batch_id);

        let body_bytes = serde_json::to_vec(&batch.envelope).map_err(|e| RelayError::Protocol {
            message: format!("Failed to serialize batch: {e}"),
        })?;

        let resp = self
            .apply_signed_auth(self.client.put(&url), "PUT", &path, &body_bytes)
            .header("X-Batch-Id", &batch.batch_id)
            .header("Content-Type", "application/json")
            .body(body_bytes)
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

        let json: serde_json::Value = resp.json().await.map_err(|e| RelayError::Protocol {
            message: format!("Failed to parse snapshot response: {e}"),
        })?;

        let epoch = json["epoch"].as_i64().unwrap_or(0) as i32;
        let server_seq_at = json["server_seq_at"].as_i64().unwrap_or(0);
        let data = json["data"]
            .as_str()
            .and_then(|s| BASE64.decode(s).ok())
            .unwrap_or_default();

        let sender_device_id = json["sender_device_id"].as_str().unwrap_or("").to_string();

        Ok(Some(SnapshotResponse {
            epoch,
            server_seq_at,
            data,
            sender_device_id,
        }))
    }

    async fn put_snapshot(
        &self,
        _epoch: i32,
        server_seq_at: i64,
        data: Vec<u8>,
        ttl_secs: Option<u64>,
        for_device_id: Option<String>,
        sender_device_id: String,
    ) -> Result<(), RelayError> {
        let url = format!("{}/snapshot", self.base_path());
        let path = self.canonical_path("/snapshot");
        debug!("put_snapshot server_seq_at={server_seq_at}");

        let mut req = self
            .apply_signed_auth(self.client.put(&url), "PUT", &path, &data)
            .header("X-Server-Seq-At", server_seq_at.to_string());

        if let Some(ttl) = ttl_secs {
            req = req.header("X-Snapshot-TTL", ttl.to_string());
        }
        if let Some(ref device_id) = for_device_id {
            req = req.header("X-For-Device-Id", device_id);
        }
        req = req.header("X-Sender-Device-Id", &sender_device_id);

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

    async fn revoke_device(
        &self,
        device_id: &str,
        remote_wipe: bool,
        new_epoch: i32,
        wrapped_keys: HashMap<String, Vec<u8>>,
    ) -> Result<i32, RelayError> {
        let path = self.canonical_path(&format!("/devices/{device_id}/revoke"));
        let url = format!("{}{}", self.base_url, path);
        debug!("revoke_device_atomic {device_id} remote_wipe={remote_wipe} epoch={new_epoch}");

        let encoded_keys: HashMap<String, String> = wrapped_keys
            .into_iter()
            .map(|(k, v)| (k, BASE64.encode(v)))
            .collect();
        let body = serde_json::json!({
            "new_epoch": new_epoch,
            "remote_wipe": remote_wipe,
            "wrapped_keys": encoded_keys,
        });
        let body_bytes = serde_json::to_vec(&body).map_err(|e| RelayError::Protocol {
            message: format!("Failed to encode revoke request: {e}"),
        })?;

        let resp = self
            .apply_signed_auth(self.client.post(&url), "POST", &path, &body_bytes)
            .header("Content-Type", "application/json")
            .body(body_bytes)
            .timeout(self.request_timeout)
            .send()
            .await
            .map_err(Self::classify_reqwest_error)?;

        let status = resp.status().as_u16();
        if status >= 400 {
            let body_text = resp.text().await.unwrap_or_default();
            return Err(Self::classify_error(status, &body_text));
        }
        if status == 204 {
            return Ok(new_epoch);
        }

        let json: serde_json::Value = resp.json().await.map_err(|e| RelayError::Protocol {
            message: format!("Failed to parse atomic revoke response: {e}"),
        })?;
        Ok(json["new_epoch"].as_i64().unwrap_or(new_epoch as i64) as i32)
    }

    async fn post_rekey_artifacts(
        &self,
        epoch: i32,
        wrapped_keys: HashMap<String, Vec<u8>>,
    ) -> Result<i32, RelayError> {
        let path = self.canonical_path("/rekey");
        let url = format!("{}{}", self.base_url, path);
        debug!("post_rekey_artifacts epoch={epoch}");

        // Encode wrapped keys as base64.
        let encoded_keys: HashMap<String, String> = wrapped_keys
            .into_iter()
            .map(|(k, v)| (k, BASE64.encode(v)))
            .collect();

        let body = serde_json::json!({
            "epoch": epoch,
            "wrapped_keys": encoded_keys,
        });
        let body_bytes = serde_json::to_vec(&body).map_err(|e| RelayError::Protocol {
            message: format!("Failed to encode rekey request: {e}"),
        })?;

        let resp = self
            .apply_signed_auth(self.client.post(&url), "POST", &path, &body_bytes)
            .header("Content-Type", "application/json")
            .body(body_bytes)
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
        let url = format!("{}/rekey/{device_id}?epoch={epoch}", self.base_path());
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
        let path = self.canonical_path(&format!("/devices/{}", self.device_id));
        let url = format!("{}{}", self.base_url, path);
        debug!("deregister device_id={}", self.device_id);

        let resp = self
            .apply_signed_auth(self.client.delete(&url), "DELETE", &path, &[])
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
        let path = self.canonical_path("");
        let url = format!("{}{}", self.base_url, path);
        debug!("delete_sync_group");

        let resp = self
            .apply_signed_auth(self.client.delete(&url), "DELETE", &path, &[])
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
        let path = self.canonical_path("/ack");
        debug!("ack server_seq={server_seq}");

        let body_bytes = serde_json::to_vec(&serde_json::json!({ "server_seq": server_seq }))
            .map_err(|e| RelayError::Protocol {
                message: format!("Failed to serialize ack body: {e}"),
            })?;

        let resp = self
            .apply_signed_auth(self.client.post(&url), "POST", &path, &body_bytes)
            .header("Content-Type", "application/json")
            .body(body_bytes)
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

#[cfg(test)]
mod tests {
    use super::ServerRelay;
    use crate::relay::traits::RelayError;

    #[test]
    fn classify_error_keeps_device_revoked_response_structured() {
        let err =
            ServerRelay::classify_error(401, r#"{"error":"device_revoked","remote_wipe":true}"#);

        assert!(matches!(
            err,
            RelayError::DeviceRevoked { remote_wipe: true }
        ));
    }

    #[test]
    fn classify_error_parses_device_identity_mismatch() {
        let err = ServerRelay::classify_error(
            401,
            r#"{"error":"device_identity_mismatch","message":"keys do not match"}"#,
        );

        assert!(matches!(
            err,
            RelayError::DeviceIdentityMismatch { ref message }
                if message == "keys do not match"
        ));
    }

    #[test]
    fn classify_error_falls_back_to_auth_for_unknown_401_json() {
        let err = ServerRelay::classify_error(401, r#"{"error":"something_else"}"#);

        assert!(matches!(err, RelayError::Auth { .. }));
    }

    #[test]
    fn classify_error_parses_upgrade_required_response() {
        let err = ServerRelay::classify_error(
            403,
            r#"{"error":"upgrade_required","min_signature_version":3,"message":"update"}"#,
        );

        assert!(matches!(
            err,
            RelayError::UpgradeRequired {
                min_signature_version: 3,
                ref message,
            } if message == "update"
        ));
    }
}
