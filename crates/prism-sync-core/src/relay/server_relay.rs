use std::collections::HashMap;
use std::pin::Pin;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer, SigningKey};
use futures_util::Stream;
use prism_sync_crypto::pq::hybrid_signature_contexts;
use rand::RngCore;
use reqwest::Client;
use sha2::{Digest, Sha256};
use tokio::sync::broadcast;
use tracing::debug;

use super::redact_url;
use super::traits::*;
use super::websocket::WebSocketClient;

const SNAPSHOT_REQUEST_TIMEOUT_SECS: u64 = 300;

/// Client-side ceiling on a `/changes` pull body, sized to comfortably EXCEED
/// the legitimate worst-case page so it only ever catches a truly anomalous
/// (relay-malicious, beyond-protocol) response — never a legal large pull.
///
/// The relay's `pull_changes` (`relay/src/routes/sync.rs`) does NOT bound the
/// response by any byte budget — only by batch count. This client pulls with
/// `DEFAULT_PULL_PAGE_LIMIT` (= 500, `engine::state`) batches per page, each up
/// to the relay's `MAX_CHANGESET_SIZE` (= 1 MiB). So a single legitimate page
/// can carry ~500 MiB of raw changeset bytes. On the wire those bytes are
/// base64-encoded (~1.34×) and wrapped in a JSON envelope, so the legitimate
/// body can reach ~670 MiB. We set the cap above that (768 MiB) so a normal
/// large backlog page — e.g. a bulk inline-base64 avatar resupply (~750 KB
/// each) — is never rejected. A smaller cap (e.g. the 150 MiB snapshot budget)
/// would hard-`Protocol`-error a legal page, and the retry uses identical
/// params (no page-halving) → a permanent sync stall.
///
/// Derivation: DEFAULT_PULL_PAGE_LIMIT (500) * MAX_CHANGESET_SIZE (1 MiB)
///   = 512 MiB raw; * ~1.34 base64 + JSON overhead ≈ 686 MiB; round up to a
///   clean 768 MiB.
///
/// TODO(perf/security): the proper fix is a relay-side per-page byte budget (so
/// pages are bounded by bytes, not just batch count) and/or client page-halving
/// on over-cap; this generous cap is an interim that prevents unbounded
/// allocation without stalling legit large pulls.
const MAX_PULL_RESPONSE_BYTES: usize = 768 * 1024 * 1024;

/// Client-side ceiling on a `GET /snapshot` body, matching the relay's own
/// `MAX_SNAPSHOT_WIRE_BYTES` upload limit (the largest legitimate body).
const MAX_SNAPSHOT_RESPONSE_BYTES: usize = crate::snapshot_limits::MAX_SNAPSHOT_WIRE_BYTES;

/// Client-side ceiling on a `GET /media/<id>` body. The relay's default
/// `MEDIA_MAX_FILE_BYTES` is 10 MiB; cap generously at 64 MiB so a tightened
/// or relaxed relay config still leaves a hard client-side bound against a
/// malicious relay streaming an unbounded media body.
const MAX_MEDIA_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

/// HTTP relay client for the V2 sync API.
///
/// Ported from Dart `lib/core/sync/server_relay.dart`.
pub struct ServerRelay {
    base_url: String,
    sync_id: String,
    device_id: String,
    device_session_token: RwLock<String>,
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
        //
        // The connect/pool/keepalive settings below are separate from the
        // per-request deadline: they bound how long we'll wait for a TCP
        // connect to start and how long idle sockets stay pooled. Without
        // them, a slow or half-open TLS handshake can consume the full
        // per-request budget before any data flows, and an iOS-backgrounded
        // connection can return stale sockets after resume.
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .pool_idle_timeout(Some(Duration::from_secs(90)))
            .tcp_keepalive(Some(Duration::from_secs(60)))
            .build()
            .map_err(|e| format!("Failed to build HTTP client: {e}"))?;

        Ok(Self {
            base_url,
            sync_id,
            device_id,
            device_session_token: RwLock::new(device_session_token),
            request_signing_key,
            request_ml_dsa_signing_key,
            registration_token,
            client,
            request_timeout: Duration::from_secs(15),
            // Align snapshot uploads with the relay default. This also bounds
            // media transfers; relay media routes may time out sooner.
            snapshot_timeout: Duration::from_secs(SNAPSHOT_REQUEST_TIMEOUT_SECS),
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
            .header("Authorization", format!("Bearer {}", self.current_session_token()))
            .header("X-Device-Id", &self.device_id)
    }

    fn current_session_token(&self) -> String {
        self.device_session_token.read().unwrap_or_else(|poisoned| poisoned.into_inner()).clone()
    }

    fn update_session_token(&self, token: String) {
        *self.device_session_token.write().unwrap_or_else(|poisoned| poisoned.into_inner()) = token;
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
            hybrid_signature_contexts::HTTP_REQUEST,
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

    /// Map a non-error (`< 400`) media-upload status to an outcome. `202` is the
    /// relay's "another writer holds the PENDING reserve" response (in-progress,
    /// NOT a success the caller may act on); everything else non-error — `200`
    /// (insert / idempotent / repair / resurrect) and any `204`/`2xx` from an old
    /// relay — is committed/servable.
    fn upload_outcome_for_status(status: u16) -> MediaUploadOutcome {
        if status == 202 {
            MediaUploadOutcome::IN_PROGRESS
        } else {
            MediaUploadOutcome::COMMITTED
        }
    }

    /// Classify an HTTP status code into a RelayError.
    fn classify_error(status: u16, body: &str) -> RelayError {
        match status {
            401 => {
                // Check if this is a structured auth response from the relay.
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
                    match json.get("error").and_then(|v| v.as_str()) {
                        Some("device_revoked") => {
                            let remote_wipe =
                                json.get("remote_wipe").and_then(|v| v.as_bool()).unwrap_or(false);
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
                RelayError::Auth { message: format!("HTTP {status}: {body}") }
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
                        return RelayError::UpgradeRequired { min_signature_version, message };
                    }
                }
                RelayError::Auth { message: format!("HTTP {status}: {body}") }
            }
            408 | 504 => RelayError::Timeout { message: format!("HTTP {status}: {body}") },
            409 => {
                // A not-yet-upgraded relay 409s a standalone /rekey while
                // `needs_rekey` is set (the older "must use the atomic endpoint"
                // guard). It arrives either as plaintext or, on a slightly newer
                // relay, as a structured `use_atomic_revoke` body. The client's
                // standalone/pairing rekey never sends `revoked_device_id`, so
                // this 409 can only mean the relay predates the atomic-revoke
                // endpoint — surface it as a retryable upgrade-pending condition
                // instead of a hard failure.
                if body.contains("Rekey after revocation must use the atomic endpoint") {
                    return RelayError::RelayUpgradePending {
                        message: format!("HTTP {status}: {body}"),
                    };
                }
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
                    if json.get("error").and_then(|v| v.as_str()) == Some("use_atomic_revoke") {
                        return RelayError::RelayUpgradePending {
                            message: format!("HTTP {status}: {body}"),
                        };
                    }
                    match json.get("error").and_then(|v| v.as_str()) {
                        Some("must_bootstrap_from_snapshot") => {
                            let since_seq =
                                json.get("since_seq").and_then(|v| v.as_i64()).unwrap_or(0);
                            let first_retained_seq = json
                                .get("first_retained_seq")
                                .and_then(|v| v.as_i64())
                                .unwrap_or(0);
                            let message = json
                                .get("message")
                                .and_then(|v| v.as_str())
                                .map(str::to_owned)
                                .unwrap_or_else(|| format!("HTTP {status}: {body}"));
                            return RelayError::MustBootstrapFromSnapshot {
                                since_seq,
                                first_retained_seq,
                                message,
                            };
                        }
                        Some("stale_snapshot_seq") => {
                            // Distinct from the `EpochRotation` fallback so
                            // the engine can route the 409 through the
                            // suppression matrix instead of epoch recovery.
                            //
                            // `current_server_seq_at` and
                            // `current_target_device_id` are both required.
                            // Missing-vs-`null` is a meaningful distinction
                            // for the target field — JSON `null` means the
                            // existing snapshot is untargeted (a real
                            // semantic value), but an absent field means
                            // the body is malformed and substituting `None`
                            // would collapse a (None, Some) race into the
                            // (None, None) suppress branch.
                            let seq = json.get("current_server_seq_at").and_then(|v| v.as_i64());
                            let target_parsed = match json.get("current_target_device_id") {
                                None => None,
                                Some(v) if v.is_null() => Some(None),
                                Some(v) => v.as_str().map(|s| Some(s.to_owned())),
                            };
                            if let (Some(seq), Some(target)) = (seq, target_parsed) {
                                return RelayError::SnapshotStale {
                                    current_server_seq_at: seq,
                                    current_target_device_id: target,
                                };
                            }
                        }
                        _ => {}
                    }
                }
                RelayError::EpochRotation {
                    new_epoch: 0, // caller should parse from body
                }
            }
            413 => RelayError::Server {
                status_code: status,
                message: format!("Payload too large: {body}"),
            },
            500..=599 => RelayError::Server { status_code: status, message: body.to_string() },
            _ => RelayError::Protocol { message: format!("Unexpected HTTP {status}: {body}") },
        }
    }

    fn classify_media_upload_error(status: u16, body: &str) -> RelayError {
        if status == 409 {
            return RelayError::Protocol { message: format!("HTTP 409: {body}") };
        }
        Self::classify_error(status, body)
    }

    /// Classify a reqwest error into a RelayError.
    fn classify_reqwest_error(err: reqwest::Error) -> RelayError {
        if err.is_timeout() {
            RelayError::Timeout { message: err.to_string() }
        } else if err.is_connect() || err.is_request() {
            RelayError::Network { message: err.to_string() }
        } else if let Some(status) = err.status() {
            Self::classify_error(status.as_u16(), &err.to_string())
        } else {
            RelayError::Network { message: err.to_string() }
        }
    }

    /// Read a response body with a hard byte ceiling.
    ///
    /// `reqwest` imposes **no** default body-size limit, so a malicious or
    /// buggy relay could stream an unbounded body and exhaust client memory.
    /// This mirrors the `get_signed_registry` 512 KiB guard but applies it to
    /// the large-body endpoints (`/changes`, `/snapshot`, `/media/*`):
    ///
    /// 1. If the relay advertises a `Content-Length` over `max_bytes`, reject
    ///    before reading a single byte.
    /// 2. Stream the body chunk-by-chunk with a running counter and abort the
    ///    instant the accumulated size exceeds `max_bytes` — so a relay that
    ///    lies about (or omits) `Content-Length` still cannot blow past the cap.
    async fn read_body_capped(
        resp: reqwest::Response,
        max_bytes: usize,
        endpoint: &str,
    ) -> Result<Vec<u8>, RelayError> {
        use futures_util::StreamExt;

        if let Some(len) = resp.content_length() {
            if len > max_bytes as u64 {
                return Err(RelayError::Protocol {
                    message: format!(
                        "{endpoint} response too large: Content-Length {len} bytes (max {max_bytes})"
                    ),
                });
            }
        }

        let mut body = Vec::new();
        let mut stream = resp.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(Self::classify_reqwest_error)?;
            if body.len() + chunk.len() > max_bytes {
                return Err(RelayError::Protocol {
                    message: format!(
                        "{endpoint} response too large: exceeded {max_bytes} bytes mid-stream"
                    ),
                });
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
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
        let scheme = if self.base_url.starts_with("https") { "wss" } else { "ws" };
        // Strip the scheme from base_url to get host:port/path.
        let rest = self
            .base_url
            .strip_prefix("https://")
            .or_else(|| self.base_url.strip_prefix("http://"))
            .unwrap_or(&self.base_url);
        format!("{scheme}://{rest}/v1/sync/{}/ws", self.sync_id)
    }

    pub async fn fetch_gif_service_config(&self) -> Result<GifServiceConfig, RelayError> {
        let url = format!("{}/capabilities", self.base_path());
        let response = self
            .apply_auth(self.client.get(&url))
            .timeout(self.request_timeout)
            .send()
            .await
            .map_err(Self::classify_reqwest_error)?;

        let status = response.status().as_u16();
        if status >= 400 {
            let body_text = response.text().await.unwrap_or_default();
            return Err(Self::classify_error(status, &body_text));
        }

        let json: serde_json::Value = response.json().await.map_err(|e| RelayError::Protocol {
            message: format!("Failed to parse capability response: {e}"),
        })?;
        serde_json::from_value(json["gifs"].clone()).map_err(|e| RelayError::Protocol {
            message: format!("Failed to parse GIF capability payload: {e}"),
        })
    }
}

fn write_len_prefixed(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

impl ServerRelay {
    /// Shared pull implementation for both [`pull_changes`] and
    /// [`pull_changes_paged`]. When `limit` is `Some`, it is sent as a query
    /// param; the relay clamps it to 1..=1000 server-side.
    ///
    /// [`pull_changes`]: SyncTransport::pull_changes
    /// [`pull_changes_paged`]: SyncTransport::pull_changes_paged
    async fn do_pull(&self, since: i64, limit: Option<i64>) -> Result<PullResponse, RelayError> {
        match self.do_pull_once(since, limit).await {
            Err(RelayError::Auth { .. }) if self.try_refresh_session().await => {
                // The session was expired; we minted a fresh one. Retry exactly
                // once with the new token (the request rebuilds with the live
                // token). A second 401 is surfaced — no retry loop.
                self.do_pull_once(since, limit).await
            }
            other => other,
        }
    }

    async fn do_pull_once(
        &self,
        since: i64,
        limit: Option<i64>,
    ) -> Result<PullResponse, RelayError> {
        let url = match limit {
            Some(n) => format!("{}/changes?since={since}&limit={n}", self.base_path()),
            None => format!("{}/changes?since={since}", self.base_path()),
        };
        debug!("pull_changes since={since} limit={limit:?}");

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

        // Read the body under a hard cap before parsing — reqwest has no default
        // body limit, so a malicious relay could otherwise stream an unbounded
        // body into a `serde_json::Value` and exhaust client memory.
        let body = Self::read_body_capped(resp, MAX_PULL_RESPONSE_BYTES, "/changes").await?;

        // A decode failure here is almost always a truncated body from a mid-flight
        // network drop — not a malformed payload from the relay. Route it through
        // the same classifier as the original send error so it lands as Network
        // (transient, retryable) instead of Protocol (hard error). The next sync
        // cycle re-pulls cleanly and the user never sees a spurious failure.
        let json: serde_json::Value =
            serde_json::from_slice(&body).map_err(|e| RelayError::Network { message: e.to_string() })?;

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
            batches.push(ReceivedBatch { server_seq, received_at, envelope });
        }

        let password_version =
            json.get("password_version").and_then(|v| v.as_i64()).map(|v| v as i32);

        Ok(PullResponse { batches, max_server_seq, min_acked_seq, password_version })
    }
}

#[async_trait]
impl SyncTransport for ServerRelay {
    async fn pull_changes(&self, since: i64) -> Result<PullResponse, RelayError> {
        self.do_pull(since, None).await
    }

    async fn pull_changes_paged(
        &self,
        since: i64,
        limit: i64,
    ) -> Result<PullResponse, RelayError> {
        self.do_pull(since, Some(limit)).await
    }

    async fn push_changes(&self, batch: OutgoingBatch) -> Result<i64, RelayError> {
        match self.push_changes_once(&batch).await {
            Err(RelayError::Auth { .. }) if self.try_refresh_session().await => {
                self.push_changes_once(&batch).await
            }
            other => other,
        }
    }

    async fn ack(&self, server_seq: i64) -> Result<(), RelayError> {
        match self.ack_once(server_seq).await {
            Err(RelayError::Auth { .. }) if self.try_refresh_session().await => {
                self.ack_once(server_seq).await
            }
            other => other,
        }
    }

    async fn refresh_session(&self) -> Result<Option<String>, RelayError> {
        self.do_refresh_session().await
    }
}

impl ServerRelay {
    async fn push_changes_once(&self, batch: &OutgoingBatch) -> Result<i64, RelayError> {
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

    async fn ack_once(&self, server_seq: i64) -> Result<(), RelayError> {
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

    /// Best-effort session refresh for the retry-once-on-401 path. Returns
    /// `true` only when a fresh token was minted and installed (so a retry is
    /// worthwhile). A revoked answer, an old relay (404/405), or any other
    /// failure returns `false` so the original 401 propagates unchanged — a
    /// `DeviceRevoked` answer is surfaced by the explicit `do_refresh_session`
    /// path the engine drives, not swallowed here.
    async fn try_refresh_session(&self) -> bool {
        matches!(self.do_refresh_session().await, Ok(Some(_)))
    }

    /// Signed `POST /session/refresh`. On success rotates the in-memory session
    /// token, broadcasts `SyncNotification::TokenRotated` (so the engine can
    /// surface a `SessionTokenRotated` event for app re-persistence), and
    /// returns the new token. A structured `device_revoked` 401 surfaces as
    /// `RelayError::DeviceRevoked`. An old relay that does not know the route
    /// (404/405) returns `Ok(None)` so callers stay in reconnecting.
    async fn do_refresh_session(&self) -> Result<Option<String>, RelayError> {
        let path = self.canonical_path("/session/refresh");
        let url = format!("{}{}", self.base_url, path);
        debug!("refresh_session device_id={}", self.device_id);

        let body = serde_json::json!({ "device_id": self.device_id });
        let body_bytes = serde_json::to_vec(&body).map_err(|e| RelayError::Protocol {
            message: format!("Failed to encode refresh request: {e}"),
        })?;

        // Signed against the device's stored keys — there is no valid session to
        // present (the whole point of this route is recovering an expired one).
        let resp = self
            .apply_signed_auth(self.client.post(&url), "POST", &path, &body_bytes)
            .header("Content-Type", "application/json")
            .body(body_bytes)
            .timeout(self.request_timeout)
            .send()
            .await
            .map_err(Self::classify_reqwest_error)?;

        let status = resp.status().as_u16();
        if status == 404 || status == 405 {
            // Relay predates this endpoint — degrade gracefully, no worse than
            // before the recovery path existed.
            debug!("refresh_session unsupported by relay (HTTP {status})");
            return Ok(None);
        }
        if status >= 400 {
            let body_text = resp.text().await.unwrap_or_default();
            return Err(Self::classify_error(status, &body_text));
        }

        let json: serde_json::Value = resp.json().await.map_err(|e| RelayError::Protocol {
            message: format!("Failed to parse refresh response: {e}"),
        })?;
        let token = json
            .get("device_session_token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RelayError::Protocol {
                message: "refresh response missing device_session_token".to_string(),
            })?
            .to_string();

        self.update_session_token(token.clone());
        // Surface the rotation so the engine re-persists the credential. A
        // lagging receiver is fine — refresh-on-401 at next launch is the
        // fallback if the broadcast is missed.
        let _ = self.notification_tx.send(SyncNotification::TokenRotated { new_token: token.clone() });

        Ok(Some(token))
    }
}

#[async_trait]
impl DeviceRegistry for ServerRelay {
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

        resp.json::<RegistrationNonceResponse>().await.map_err(|e| RelayError::Protocol {
            message: format!("Failed to parse nonce response: {e}"),
        })
    }

    async fn register_device(&self, req: RegisterRequest) -> Result<RegisterResponse, RelayError> {
        let url = format!("{}/register", self.base_path());

        let body = build_register_device_body(&req);

        let mut req =
            self.apply_auth(self.client.post(&url)).json(&body).timeout(self.request_timeout);
        if let Some(token) = &self.registration_token {
            req = req.header("X-Registration-Token", token);
        }
        let resp = req.send().await.map_err(Self::classify_reqwest_error)?;

        let status = resp.status().as_u16();
        if status >= 400 {
            let body_text = resp.text().await.unwrap_or_default();
            if status == 409 {
                return Err(RelayError::Protocol { message: format!("HTTP 409: {body_text}") });
            }
            return Err(Self::classify_error(status, &body_text));
        }

        let register_response = resp.json::<RegisterResponse>().await.map_err(|e| {
            RelayError::Protocol { message: format!("Failed to parse register response: {e}") }
        })?;

        // Pairing creates this relay before a session token exists, then
        // reuses it for authenticated registry/snapshot calls after
        // registration succeeds.
        self.update_session_token(register_response.device_session_token.clone());

        Ok(register_response)
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

        resp.json::<Vec<DeviceInfo>>().await.map_err(|e| RelayError::Protocol {
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

        let encoded_keys: HashMap<String, String> =
            wrapped_keys.into_iter().map(|(k, v)| (k, BASE64.encode(v))).collect();
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

    async fn rotate_ml_dsa(
        &self,
        device_id: &str,
        new_ml_dsa_pk: &[u8],
        new_generation: u32,
        proof: &prism_sync_crypto::pq::continuity_proof::MlDsaContinuityProof,
        signed_registry_snapshot: Option<&[u8]>,
    ) -> Result<RotateMlDsaResponse, RelayError> {
        let path = self.canonical_path(&format!("/devices/{device_id}/rotate-ml-dsa"));
        let url = format!("{}{}", self.base_url, path);
        debug!("rotate_ml_dsa device_id={device_id} generation={new_generation}");

        let body = serde_json::json!({
            "new_ml_dsa_pk": BASE64.encode(new_ml_dsa_pk),
            "ml_dsa_key_generation": new_generation,
            "timestamp": proof.timestamp,
            "old_signs_new": BASE64.encode(&proof.old_signs_new),
            "new_signs_old": BASE64.encode(&proof.new_signs_old),
            "signed_registry_snapshot": signed_registry_snapshot.map(|s| BASE64.encode(s)),
        });
        let body_bytes = serde_json::to_vec(&body).map_err(|e| RelayError::Protocol {
            message: format!("Failed to encode rotate-ml-dsa request: {e}"),
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

        resp.json::<RotateMlDsaResponse>().await.map_err(|e| RelayError::Protocol {
            message: format!("Failed to parse rotate-ml-dsa response: {e}"),
        })
    }

    async fn get_signed_registry(&self) -> Result<Option<SignedRegistryResponse>, RelayError> {
        let path = self.canonical_path("/registry");
        let url = format!("{}{}", self.base_url, path);
        debug!("get_signed_registry");

        let resp = self
            .apply_signed_auth(self.client.get(&url), "GET", &path, &[])
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

        let response: SignedRegistryResponse = resp.json().await.map_err(|e| {
            RelayError::Protocol { message: format!("Failed to parse registry response: {e}") }
        })?;

        // Client-side size cap to protect against malicious relay
        if response.artifact_blob.len() > 512 * 1024 {
            return Err(RelayError::Protocol {
                message: format!(
                    "Registry artifact too large: {} bytes (max 524288)",
                    response.artifact_blob.len()
                ),
            });
        }

        Ok(Some(response))
    }

    async fn put_signed_registry(
        &self,
        signed_registry_snapshot: &[u8],
    ) -> Result<i64, RelayError> {
        let path = self.canonical_path("/registry");
        let url = format!("{}{}", self.base_url, path);
        debug!("put_signed_registry bytes={}", signed_registry_snapshot.len());

        let body = serde_json::json!({
            "signed_registry_snapshot": BASE64.encode(signed_registry_snapshot),
        });
        let body_bytes = serde_json::to_vec(&body).map_err(|e| RelayError::Protocol {
            message: format!("Failed to encode registry request: {e}"),
        })?;

        let resp = self
            .apply_signed_auth(self.client.put(&url), "PUT", &path, &body_bytes)
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
            message: format!("Failed to parse registry response: {e}"),
        })?;

        Ok(json["registry_version"].as_i64().unwrap_or(0))
    }
}

#[async_trait]
impl EpochManagement for ServerRelay {
    async fn post_rekey_artifacts(
        &self,
        epoch: i32,
        wrapped_keys: HashMap<String, Vec<u8>>,
        signed_registry_snapshot: Option<&[u8]>,
    ) -> Result<i32, RelayError> {
        let path = self.canonical_path("/rekey");
        let url = format!("{}{}", self.base_url, path);
        debug!("post_rekey_artifacts epoch={epoch}");

        // Encode wrapped keys as base64.
        let encoded_keys: HashMap<String, String> =
            wrapped_keys.into_iter().map(|(k, v)| (k, BASE64.encode(v))).collect();

        let body = serde_json::json!({
            "epoch": epoch,
            "wrapped_keys": encoded_keys,
            "signed_registry_snapshot": signed_registry_snapshot.map(|s| BASE64.encode(s)),
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

        let wrapped_key = json["wrapped_key"].as_str().and_then(|s| BASE64.decode(s).ok());

        Ok(wrapped_key)
    }
}

#[async_trait]
impl SnapshotExchange for ServerRelay {
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

        // Cap the snapshot body before buffering it — reqwest has no default
        // body limit. Mirrors the relay's own MAX_SNAPSHOT_WIRE_BYTES bound.
        let body = Self::read_body_capped(resp, MAX_SNAPSHOT_RESPONSE_BYTES, "/snapshot").await?;
        let json: serde_json::Value =
            serde_json::from_slice(&body).map_err(|e| RelayError::Protocol {
                message: format!("Failed to parse snapshot response: {e}"),
            })?;

        let epoch = json["epoch"].as_i64().unwrap_or(0) as i32;
        let server_seq_at = json["server_seq_at"].as_i64().unwrap_or(0);
        let data = json["data"].as_str().and_then(|s| BASE64.decode(s).ok()).unwrap_or_default();

        let sender_device_id = json["sender_device_id"].as_str().unwrap_or("").to_string();

        Ok(Some(SnapshotResponse { epoch, server_seq_at, data, sender_device_id }))
    }

    async fn put_snapshot(
        &self,
        _epoch: i32,
        server_seq_at: i64,
        envelope_bytes: Vec<u8>,
        ttl_secs: Option<u64>,
        for_device_id: Option<String>,
        uploader_device_id: String,
        progress: Option<SnapshotUploadProgress>,
    ) -> Result<(), RelayError> {
        let url = format!("{}/snapshot", self.base_path());
        let path = self.canonical_path("/snapshot");
        debug!("put_snapshot server_seq_at={server_seq_at} bytes={}", envelope_bytes.len());

        let total: u64 = envelope_bytes.len() as u64;

        // Sign before we move the bytes into the streamed body — the
        // signature binds to the full payload hash, so the server can still
        // verify regardless of chunking.
        let mut req = self
            .apply_signed_auth(self.client.put(&url), "PUT", &path, &envelope_bytes)
            .header("X-Server-Seq-At", server_seq_at.to_string())
            .header("Content-Length", total.to_string());

        if let Some(ttl) = ttl_secs {
            req = req.header("X-Snapshot-TTL", ttl.to_string());
        }
        if let Some(ref device_id) = for_device_id {
            req = req.header("X-For-Device-Id", device_id);
        }
        req = req.header("X-Sender-Device-Id", &uploader_device_id);

        // Build a chunked stream so the body is sent in 64 KiB pieces.
        // Each yielded chunk notifies the progress callback, throttled to at
        // most one invocation per max(64 KiB, 200 ms).
        const CHUNK_SIZE: usize = 64 * 1024;
        const PROGRESS_INTERVAL: Duration = Duration::from_millis(200);

        let progress_cb = progress.clone();
        let last_emit: Arc<Mutex<Option<Instant>>> = Arc::new(Mutex::new(None));

        let envelope = Arc::new(envelope_bytes);
        let len = envelope.len();

        // State: (current offset). `unfold` yields `Vec<u8>` chunks until we
        // hit the end.
        let stream = futures_util::stream::unfold(0usize, move |offset| {
            let envelope = envelope.clone();
            let progress_cb = progress_cb.clone();
            let last_emit = last_emit.clone();
            async move {
                if offset >= len {
                    return None;
                }
                let end = (offset + CHUNK_SIZE).min(len);
                let chunk: Vec<u8> = envelope[offset..end].to_vec();
                let new_offset = end;

                if let Some(cb) = progress_cb.as_ref() {
                    let now = Instant::now();
                    let mut guard = last_emit.lock().unwrap();
                    let is_final = new_offset >= len;
                    let should_emit = match *guard {
                        None => true,
                        Some(last) => is_final || now.duration_since(last) >= PROGRESS_INTERVAL,
                    };
                    if should_emit {
                        *guard = Some(now);
                        drop(guard);
                        cb(new_offset as u64, total);
                    }
                }

                Some((Ok::<Vec<u8>, std::io::Error>(chunk), new_offset))
            }
        });

        let body = reqwest::Body::wrap_stream(stream);

        let resp = req
            .body(body)
            .timeout(self.snapshot_timeout)
            .send()
            .await
            .map_err(Self::classify_reqwest_error)?;

        let status = resp.status().as_u16();
        if status >= 400 {
            let body_text = resp.text().await.unwrap_or_default();
            return Err(Self::classify_error(status, &body_text));
        }

        // Ensure a final progress tick lands with `(total, total)` so callers
        // see 100% even if the server relay buffered the last chunk.
        if let Some(cb) = progress.as_ref() {
            cb(total, total);
        }

        Ok(())
    }

    async fn delete_snapshot(&self) -> Result<(), RelayError> {
        let path = self.canonical_path("/snapshot");
        let url = format!("{}{}", self.base_url, path);
        debug!("delete_snapshot");

        let resp = self
            .apply_signed_auth(self.client.delete(&url), "DELETE", &path, &[])
            .timeout(self.request_timeout)
            .send()
            .await
            .map_err(Self::classify_reqwest_error)?;

        let status = resp.status().as_u16();
        match status {
            204 | 200 => Ok(()),
            404 => Err(RelayError::NotFound),
            403 => {
                let body_text = resp.text().await.unwrap_or_default();
                Err(RelayError::Forbidden { message: body_text })
            }
            _ => {
                let body_text = resp.text().await.unwrap_or_default();
                Err(RelayError::Http { status, body: body_text })
            }
        }
    }
}

#[async_trait]
impl MediaRelay for ServerRelay {
    async fn upload_media(
        &self,
        media_id: &str,
        content_hash: &str,
        data: Vec<u8>,
        ttl_secs: Option<u64>,
    ) -> Result<MediaUploadOutcome, RelayError> {
        self.upload_media_classified(media_id, content_hash, data, ttl_secs, false)
            .await
    }

    async fn upload_media_classified(
        &self,
        media_id: &str,
        content_hash: &str,
        data: Vec<u8>,
        ttl_secs: Option<u64>,
        pairing_push: bool,
    ) -> Result<MediaUploadOutcome, RelayError> {
        let url = format!("{}/media", self.base_path());
        let path = self.canonical_path("/media");
        debug!("upload_media media_id={media_id} ttl_secs={ttl_secs:?} pairing_push={pairing_push}");

        // X-Media-TTL / X-Media-Upload-Class are NOT part of the signed request
        // bytes (signing covers body/path/device/timestamp/nonce), so an old
        // relay simply ignores them and applies its default retention + lane —
        // back-compat both ways.
        let mut req = self
            .apply_signed_auth(self.client.post(&url), "POST", &path, &data)
            .header("X-Media-Id", media_id)
            .header("X-Content-Hash", content_hash)
            .header("Content-Type", "application/octet-stream");
        if let Some(ttl) = ttl_secs {
            req = req.header("X-Media-TTL", ttl.to_string());
        }
        // Only meaningful on an ephemeral (TTL-bearing) upload; the relay treats
        // the pairing class as a no-op without a TTL.
        if pairing_push {
            req = req.header("X-Media-Upload-Class", "pairing");
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
            return Err(Self::classify_media_upload_error(status, &body_text));
        }
        Ok(Self::upload_outcome_for_status(status))
    }

    async fn download_media(&self, media_id: &str) -> Result<Vec<u8>, RelayError> {
        let url = format!("{}/media/{}", self.base_path(), media_id);
        debug!("download_media media_id={media_id}");

        let resp = self
            .apply_auth(self.client.get(&url))
            .timeout(self.snapshot_timeout)
            .send()
            .await
            .map_err(Self::classify_reqwest_error)?;

        let status = resp.status().as_u16();
        if status >= 400 {
            // Map a media 404 to NotFound LOCALLY (not in the shared
            // `classify_error`): a missing blob is the media heal's trigger, not a
            // protocol error. The shared classifier serves many sync routes
            // where a 404 is terminal, and `NotFound` maps to the retryable
            // `Server` category (error.rs / sync_service.rs) — making it generic
            // would turn terminal sync-route 404s into retried-forever errors.
            if status == 404 {
                return Err(RelayError::NotFound);
            }
            let body_text = resp.text().await.unwrap_or_default();
            return Err(Self::classify_error(status, &body_text));
        }

        // Cap the media body before buffering — reqwest has no default body
        // limit, so an oversized/unbounded body from a malicious relay would
        // otherwise be read fully into memory.
        Self::read_body_capped(resp, MAX_MEDIA_RESPONSE_BYTES, "/media").await
    }

    async fn batch_exists(&self, media_ids: &[String]) -> Result<Vec<String>, RelayError> {
        let url = format!("{}/media/exists", self.base_path());
        debug!("batch_exists count={}", media_ids.len());

        let resp = self
            .apply_auth(self.client.post(&url))
            .json(&serde_json::json!({ "media_ids": media_ids }))
            .timeout(self.request_timeout)
            .send()
            .await
            .map_err(Self::classify_reqwest_error)?;

        let status = resp.status().as_u16();
        if status >= 400 {
            // 404/405 from an old relay surfaces here; heal callers treat that as
            // "feature absent", distinct from a successful empty result.
            let body_text = resp.text().await.unwrap_or_default();
            return Err(Self::classify_error(status, &body_text));
        }

        let body: serde_json::Value = resp.json().await.map_err(Self::classify_reqwest_error)?;
        // A 200 without `present` is malformed; "all absent" would request
        // every missing blob.
        match body.get("present").and_then(|p| p.as_array()) {
            Some(arr) => {
                Ok(arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            }
            None => Err(RelayError::Protocol {
                message: "batch-exists response missing 'present' array".into(),
            }),
        }
    }

    async fn send_ephemeral(
        &self,
        envelope: &crate::ephemeral::EphemeralEnvelope,
    ) -> Result<(), RelayError> {
        let path = self.canonical_path("/device-messages");
        let url = format!("{}/device-messages", self.base_path());
        debug!("send_ephemeral message_id={} epoch_id={}", envelope.message_id, envelope.epoch_id);

        let body = serde_json::json!({
            "message_id": envelope.message_id,
            "epoch_id": envelope.epoch_id,
            "recipient_device_id": envelope.recipient_device_id,
            "payload": BASE64.encode(&envelope.payload),
        });
        let body_bytes = serde_json::to_vec(&body).map_err(|e| RelayError::Protocol {
            message: format!("Failed to serialize send_ephemeral body: {e}"),
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
            // 404/405 from an old relay surfaces here; the caller treats that as
            // "feature absent ⇒ no-op".
            let body_text = resp.text().await.unwrap_or_default();
            return Err(Self::classify_error(status, &body_text));
        }
        Ok(())
    }

    async fn fetch_pending_ephemeral(
        &self,
    ) -> Result<Vec<crate::ephemeral::EphemeralEnvelope>, RelayError> {
        let path = self.canonical_path("/device-messages/pending");
        let url = format!("{}/device-messages/pending", self.base_path());
        debug!("fetch_pending_ephemeral");

        let resp = self
            .apply_signed_auth(self.client.get(&url), "GET", &path, &[])
            .timeout(self.request_timeout)
            .send()
            .await
            .map_err(Self::classify_reqwest_error)?;

        let status = resp.status().as_u16();
        if status >= 400 {
            let body_text = resp.text().await.unwrap_or_default();
            return Err(Self::classify_error(status, &body_text));
        }

        let body: serde_json::Value = resp.json().await.map_err(Self::classify_reqwest_error)?;
        let arr = body.get("messages").and_then(|m| m.as_array()).ok_or_else(|| {
            RelayError::Protocol {
                message: "pending-messages response missing 'messages' array".into(),
            }
        })?;

        let mut out = Vec::with_capacity(arr.len());
        for m in arr {
            // Skip a malformed entry rather than failing the whole drain — one
            // bad row from a misbehaving proxy shouldn't strand the others.
            let (Some(message_id), Some(epoch_id), Some(payload_b64), Some(sender)) = (
                m.get("message_id").and_then(|v| v.as_str()),
                m.get("epoch_id").and_then(|v| v.as_u64()),
                m.get("payload").and_then(|v| v.as_str()),
                m.get("sender_device_id").and_then(|v| v.as_str()),
            ) else {
                continue;
            };
            let Ok(epoch_id) = u32::try_from(epoch_id) else { continue };
            let Ok(payload) = BASE64.decode(payload_b64) else { continue };
            let recipient_device_id = m
                .get("recipient_device_id")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            out.push(crate::ephemeral::EphemeralEnvelope {
                message_id: message_id.to_string(),
                epoch_id,
                sender_device_id: sender.to_string(),
                recipient_device_id,
                payload,
            });
        }
        Ok(out)
    }

    async fn ack_ephemeral(&self, message_ids: &[String]) -> Result<(), RelayError> {
        if message_ids.is_empty() {
            return Ok(());
        }
        let path = self.canonical_path("/device-messages/ack");
        let url = format!("{}/device-messages/ack", self.base_path());
        debug!("ack_ephemeral count={}", message_ids.len());

        let body = serde_json::json!({ "message_ids": message_ids });
        let body_bytes = serde_json::to_vec(&body).map_err(|e| RelayError::Protocol {
            message: format!("Failed to serialize ack_ephemeral body: {e}"),
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
}

#[async_trait]
impl SyncRelay for ServerRelay {
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

    async fn connect_websocket(&self) -> Result<(), RelayError> {
        let ws_url = self.ws_url();
        debug!("[prism_relay] connect_websocket url={}", redact_url(&ws_url));

        let ws = WebSocketClient::new(
            ws_url,
            self.device_id.clone(),
            self.current_session_token(),
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

fn build_register_device_body(req: &RegisterRequest) -> serde_json::Value {
    serde_json::json!({
        "device_id": &req.device_id,
        "signing_public_key": hex::encode(&req.signing_public_key),
        "x25519_public_key": hex::encode(&req.x25519_public_key),
        "ml_dsa_65_public_key": hex::encode(&req.ml_dsa_65_public_key),
        "ml_kem_768_public_key": hex::encode(&req.ml_kem_768_public_key),
        "x_wing_public_key": hex::encode(&req.x_wing_public_key),
        "registration_challenge": hex::encode(&req.registration_challenge),
        "nonce": &req.nonce,
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
                "approver_device_id": &approval.approver_device_id,
                "approver_ed25519_pk": &approval.approver_ed25519_pk,
                "approver_ml_dsa_65_pk": &approval.approver_ml_dsa_65_pk,
                "approval_signature": &approval.approval_signature,
                "signed_registry_snapshot": &approval.signed_registry_snapshot,
            })
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::ServerRelay;
    use crate::relay::traits::{
        MediaUploadOutcome, RegisterRequest, RegistryApproval, RelayError,
    };

    #[test]
    fn media_upload_status_maps_to_outcome() {
        // 200 (insert / idempotent / repair / resurrect) ⇒ committed.
        assert_eq!(ServerRelay::upload_outcome_for_status(200), MediaUploadOutcome::COMMITTED);
        // 202 (a concurrent writer holds the reserve) ⇒ in-progress, NOT success.
        let in_progress = ServerRelay::upload_outcome_for_status(202);
        assert_eq!(in_progress, MediaUploadOutcome::IN_PROGRESS);
        assert!(!in_progress.committed, "202 must not look like a committed success");
        assert!(in_progress.in_progress);
        // An old relay's 204/other 2xx ⇒ committed (back-compat).
        assert_eq!(ServerRelay::upload_outcome_for_status(204), MediaUploadOutcome::COMMITTED);
    }

    #[test]
    fn shared_classify_error_keeps_404_as_protocol() {
        // 404 → NotFound is mapped LOCALLY in `download_media` only. The
        // shared classifier must keep 404 → Protocol so terminal sync-route 404s
        // don't become the retryable Server category that NotFound maps to —
        // which would retry them forever.
        assert!(matches!(
            ServerRelay::classify_error(404, "not found"),
            RelayError::Protocol { .. }
        ));
        // 405 (old relay, feature absent) likewise stays Protocol.
        assert!(matches!(
            ServerRelay::classify_error(405, "method not allowed"),
            RelayError::Protocol { .. }
        ));
    }

    fn test_relay(initial_session_token: &str) -> ServerRelay {
        let device_id = "test-device";
        let device_secret = prism_sync_crypto::DeviceSecret::generate();
        let signing_key =
            device_secret.ed25519_keypair(device_id).expect("test ed25519 key").into_signing_key();
        let ml_dsa_key = device_secret.ml_dsa_65_keypair(device_id).expect("test ml-dsa key");

        ServerRelay::new(
            "http://localhost".to_string(),
            "00".repeat(32),
            device_id.to_string(),
            initial_session_token.to_string(),
            signing_key,
            ml_dsa_key,
            None,
        )
        .expect("test relay")
    }

    #[test]
    fn snapshot_timeout_matches_relay_default() {
        let relay = test_relay("token");

        assert_eq!(
            relay.snapshot_timeout,
            std::time::Duration::from_secs(super::SNAPSHOT_REQUEST_TIMEOUT_SECS)
        );
    }

    #[test]
    fn classify_error_keeps_device_revoked_response_structured() {
        let err =
            ServerRelay::classify_error(401, r#"{"error":"device_revoked","remote_wipe":true}"#);

        assert!(matches!(err, RelayError::DeviceRevoked { remote_wipe: true }));
    }

    #[test]
    fn updated_session_token_is_used_for_auth_headers() {
        let relay = test_relay("");

        let before = relay
            .apply_auth(relay.client.get("http://localhost/test"))
            .build()
            .expect("request before update");
        assert_eq!(
            before.headers().get("authorization").and_then(|v| v.to_str().ok()),
            Some("Bearer ")
        );

        relay.update_session_token("registered-session-token".to_string());

        let after = relay
            .apply_auth(relay.client.get("http://localhost/test"))
            .build()
            .expect("request after update");
        assert_eq!(
            after.headers().get("authorization").and_then(|v| v.to_str().ok()),
            Some("Bearer registered-session-token")
        );
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
    fn classify_error_parses_must_bootstrap_from_snapshot_response() {
        let err = ServerRelay::classify_error(
            409,
            r#"{"error":"must_bootstrap_from_snapshot","message":"bootstrap","since_seq":2,"first_retained_seq":5}"#,
        );

        assert!(matches!(
            err,
            RelayError::MustBootstrapFromSnapshot {
                since_seq: 2,
                first_retained_seq: 5,
                ref message,
            } if message == "bootstrap"
        ));
    }

    #[test]
    fn classify_error_recognizes_snapshot_stale() {
        let err = ServerRelay::classify_error(
            409,
            r#"{"error":"stale_snapshot_seq","current_server_seq_at":42,"current_target_device_id":"joiner-A"}"#,
        );

        assert!(matches!(
            err,
            RelayError::SnapshotStale {
                current_server_seq_at: 42,
                ref current_target_device_id,
            } if current_target_device_id.as_deref() == Some("joiner-A")
        ));
    }

    #[test]
    fn classify_error_snapshot_stale_handles_null_target() {
        // JSON `null` means the existing snapshot is untargeted (a real
        // semantic value, distinct from an absent field).
        let err = ServerRelay::classify_error(
            409,
            r#"{"error":"stale_snapshot_seq","current_server_seq_at":7,"current_target_device_id":null}"#,
        );

        assert!(matches!(
            err,
            RelayError::SnapshotStale { current_server_seq_at: 7, current_target_device_id: None }
        ));
    }

    #[test]
    fn classify_error_snapshot_stale_falls_back_when_target_field_absent() {
        // Absence is treated as malformed body rather than untargeted —
        // mapping it to `None` would collapse a (None, Some) race into
        // the (None, None) suppress branch in the engine matrix and
        // silently lose an untargeted upload's universal availability
        // when a partially-upgraded relay returns this shape.
        // existing snapshot collapses to `(None, None)` in the matrix
        // and gets silently suppressed — losing universal availability.
        // Falling through to `EpochRotation` surfaces the malformed body
        // as a real error so callers don't silently drop the upload.
        let err = ServerRelay::classify_error(
            409,
            r#"{"error":"stale_snapshot_seq","current_server_seq_at":42}"#,
        );
        match err {
            RelayError::EpochRotation { new_epoch: 0 } => {}
            other => panic!("expected EpochRotation fallback, got {other:?}"),
        }
    }

    #[test]
    fn classify_error_snapshot_stale_falls_back_when_seq_missing() {
        // A body claiming `stale_snapshot_seq` without `current_server_seq_at`
        // must NOT coerce to seq=0 — that would let the engine absorb a
        // malformed 409 as Ok(()) through the suppression path.
        let body = r#"{"error":"stale_snapshot_seq","current_target_device_id":"foo"}"#;
        let err = ServerRelay::classify_error(409, body);
        match err {
            RelayError::EpochRotation { new_epoch: 0 } => {}
            other => panic!("expected EpochRotation fallback, got {other:?}"),
        }
    }

    #[test]
    fn classify_error_snapshot_stale_falls_back_when_seq_wrong_type() {
        let body = r#"{"error":"stale_snapshot_seq","current_server_seq_at":"not-a-number"}"#;
        let err = ServerRelay::classify_error(409, body);
        match err {
            RelayError::EpochRotation { new_epoch: 0 } => {}
            other => panic!("expected EpochRotation fallback, got {other:?}"),
        }
    }

    #[test]
    fn classify_error_falls_back_for_unknown_409_body() {
        // The unknown-409 fallback must survive the addition of the
        // `stale_snapshot_seq` branch, or 409s that genuinely need
        // epoch-rotation handling will misroute.
        let err = ServerRelay::classify_error(409, r#"{"error":"something_else"}"#);
        assert!(matches!(err, RelayError::EpochRotation { new_epoch: 0 }));
    }

    #[test]
    fn media_upload_409_does_not_report_epoch_rotation() {
        let err = ServerRelay::classify_media_upload_error(
            409,
            r#"{"error":"conflict","message":"Media with this ID already exists"}"#,
        );
        assert!(matches!(err, RelayError::Protocol { ref message } if message.contains("409")));
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

    #[test]
    fn register_device_body_includes_approver_ml_dsa_key() {
        let expected_pk = "bb".repeat(1952);
        let body = super::build_register_device_body(&RegisterRequest {
            device_id: "device-1".to_string(),
            signing_public_key: vec![0x11; 32],
            x25519_public_key: vec![0x22; 32],
            ml_dsa_65_public_key: vec![0x33; 1952],
            ml_kem_768_public_key: vec![0x44; 1184],
            x_wing_public_key: vec![],
            registration_challenge: vec![0x55; 64],
            nonce: "nonce".to_string(),
            pow_solution: None,
            first_device_admission_proof: None,
            registry_approval: Some(RegistryApproval {
                approver_device_id: "approver-1".to_string(),
                approver_ed25519_pk: "aa".repeat(32),
                approver_ml_dsa_65_pk: "bb".repeat(1952),
                approval_signature: "cc".repeat(64),
                signed_registry_snapshot: vec![0xdd; 4],
            }),
        });

        let approval = body
            .get("registry_approval")
            .and_then(|value| value.as_object())
            .expect("registry approval object");

        assert_eq!(
            approval.get("approver_ml_dsa_65_pk").and_then(|value| value.as_str()).map(|s| s.len()),
            Some(expected_pk.len())
        );
        assert_eq!(
            approval.get("approver_ml_dsa_65_pk").and_then(|value| value.as_str()),
            Some(expected_pk.as_str())
        );
    }

    // ── session-refresh retry-once semantics ──

    use crate::relay::traits::SyncTransport;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// Minimal blocking HTTP/1.1 stub. Accepts connections in a loop (reqwest
    /// opens a fresh `Connection: close` socket per request) and dispatches by
    /// the request line: `/session/refresh` requests bump `refresh_count` and
    /// return `refresh_body` with `refresh_status`; everything else returns 401
    /// before any refresh, then 200 `ok_body` after — so the retry path is
    /// observable purely through the refresh counter and the final result.
    fn spawn_retry_stub(
        refresh_status: u16,
        refresh_body: &'static str,
        ok_body: &'static str,
    ) -> (String, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let refresh_count = Arc::new(AtomicUsize::new(0));
        let counter = refresh_count.clone();

        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(mut stream) = conn else { break };
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let first_line = req.lines().next().unwrap_or("");
                let (status, body) = if first_line.contains("/session/refresh") {
                    counter.fetch_add(1, Ordering::SeqCst);
                    (refresh_status, refresh_body)
                } else if counter.load(Ordering::SeqCst) == 0 {
                    // No refresh yet -> the (expired) session is rejected.
                    (401, "Unauthorized")
                } else {
                    (200, ok_body)
                };
                let response = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });

        (format!("http://localhost:{}", addr.port()), refresh_count)
    }

    fn test_relay_at(base_url: &str) -> ServerRelay {
        let device_id = "test-device";
        let device_secret = prism_sync_crypto::DeviceSecret::generate();
        let signing_key =
            device_secret.ed25519_keypair(device_id).expect("test ed25519 key").into_signing_key();
        let ml_dsa_key = device_secret.ml_dsa_65_keypair(device_id).expect("test ml-dsa key");
        ServerRelay::new(
            base_url.to_string(),
            "00".repeat(32),
            device_id.to_string(),
            "expired-token".to_string(),
            signing_key,
            ml_dsa_key,
            None,
        )
        .expect("test relay")
    }

    #[tokio::test]
    async fn pull_401_triggers_exactly_one_refresh_and_retries() {
        let (url, refresh_count) = spawn_retry_stub(
            200,
            r#"{"device_session_token":"fresh-token"}"#,
            r#"{"max_server_seq":0,"batches":[]}"#,
        );
        let relay = test_relay_at(&url);

        // The first pull gets 401; refresh mints a fresh token; retry succeeds.
        let result = relay.pull_changes(0).await;
        assert!(result.is_ok(), "pull should recover via refresh: {result:?}");
        assert_eq!(refresh_count.load(Ordering::SeqCst), 1, "exactly one refresh");
        // The transport rotated to the refreshed token.
        assert_eq!(relay.current_session_token(), "fresh-token");
    }

    #[tokio::test]
    async fn refresh_returning_device_revoked_surfaces_without_retry_loop() {
        let (url, refresh_count) = spawn_retry_stub(
            401,
            r#"{"error":"device_revoked","remote_wipe":true,"signed_registry":null}"#,
            r#"{"max_server_seq":0,"batches":[]}"#,
        );
        let relay = test_relay_at(&url);

        let result = relay.pull_changes(0).await;
        // The refresh told us we are revoked: the original 401 (Auth) propagates
        // because `try_refresh_session` returns false for a non-rotating answer,
        // and no second refresh is attempted.
        assert!(matches!(result, Err(RelayError::Auth { .. })), "got {result:?}");
        assert_eq!(refresh_count.load(Ordering::SeqCst), 1, "no refresh retry loop");
        // Token unchanged — nothing was rotated.
        assert_eq!(relay.current_session_token(), "expired-token");
    }

    #[tokio::test]
    async fn refresh_session_returns_token_on_success() {
        let (url, refresh_count) = spawn_retry_stub(
            200,
            r#"{"device_session_token":"rotated"}"#,
            r#"{"max_server_seq":0,"batches":[]}"#,
        );
        let relay = test_relay_at(&url);

        let rotated = relay.refresh_session().await.expect("refresh ok");
        assert_eq!(rotated.as_deref(), Some("rotated"));
        assert_eq!(refresh_count.load(Ordering::SeqCst), 1);
        assert_eq!(relay.current_session_token(), "rotated");
    }

    #[tokio::test]
    async fn refresh_session_against_old_relay_returns_none() {
        // An old relay that does not know the route 404s — degrade gracefully.
        let (url, _refresh_count) = spawn_retry_stub(404, "Not Found", "{}");
        let relay = test_relay_at(&url);

        let result = relay.refresh_session().await.expect("refresh should not hard-error on 404");
        assert!(result.is_none(), "unsupported route -> Ok(None), stay reconnecting");
    }
}
