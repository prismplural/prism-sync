use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use reqwest::Client;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::time::Duration;
use tracing::debug;

use super::traits::RelayError;

/// A pending sharing-init payload retrieved from the relay.
#[derive(Debug, Clone)]
pub struct PendingSharingInit {
    pub init_id: String,
    pub sender_id: String,
    pub payload: Vec<u8>,
    pub created_at: i64,
}

#[derive(Deserialize)]
struct PrekeyBundleResponse {
    identity_bundle: String,
    signed_prekey: String,
}

#[derive(Deserialize)]
struct FetchPendingInitsResponse {
    payloads: Vec<PendingSharingInitResponse>,
}

#[derive(Deserialize)]
struct PendingSharingInitResponse {
    init_id: String,
    sender_id: String,
    payload: String,
    created_at: i64,
}

/// Relay operations for the sharing bootstrap.
///
/// Authenticated operations use the device's session token and signed request headers.
/// Prekey bundle fetches are unauthenticated.
#[async_trait]
pub trait SharingRelay: Send + Sync {
    /// Publish the user's sharing identity bundle.
    async fn publish_identity(
        &self,
        sharing_id: &str,
        identity_bundle: &[u8],
    ) -> Result<(), RelayError>;

    /// Publish a signed prekey for this device.
    async fn publish_prekey(
        &self,
        sharing_id: &str,
        device_id: &str,
        prekey_id: &str,
        prekey_bundle: &[u8],
    ) -> Result<(), RelayError>;

    /// Fetch a recipient's prekey bundle by sharing_id.
    /// Returns `(identity_bundle_bytes, prekey_bundle_bytes)` on success, or `None` if not found.
    /// Unauthenticated.
    async fn fetch_prekey_bundle(
        &self,
        sharing_id: &str,
    ) -> Result<Option<(Vec<u8>, Vec<u8>)>, RelayError>;

    /// Upload an encrypted sharing-init payload.
    async fn upload_sharing_init(
        &self,
        init_id: &str,
        recipient_id: &str,
        sender_id: &str,
        payload: &[u8],
    ) -> Result<(), RelayError>;

    /// Fetch all pending sharing-init payloads for the authenticated user.
    /// The relay atomically marks returned payloads as consumed.
    async fn fetch_pending_inits(&self) -> Result<Vec<PendingSharingInit>, RelayError>;

    /// Remove identity bundle and all prekeys (sharing disable).
    async fn remove_identity(&self) -> Result<(), RelayError>;
}

/// HTTP relay client for the sharing bootstrap API.
///
/// Debug omits the signing key for security.
pub struct ServerSharingRelay {
    base_url: String,
    client: Client,
    session_token: String,
    sync_id: String,
    device_id: String,
    signing_key: SigningKey,
    ml_dsa_signing_key: prism_sync_crypto::DevicePqSigningKey,
    request_timeout: Duration,
}

impl std::fmt::Debug for ServerSharingRelay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerSharingRelay")
            .field("base_url", &self.base_url)
            .field("sync_id", &self.sync_id)
            .field("device_id", &self.device_id)
            .finish_non_exhaustive()
    }
}

impl ServerSharingRelay {
    /// Create a new `ServerSharingRelay`.
    ///
    /// Returns an error if `base_url` does not start with `https://`
    /// (unless it starts with `http://localhost`, which is allowed for
    /// local development).
    pub fn new(
        base_url: String,
        session_token: String,
        sync_id: String,
        device_id: String,
        signing_key: SigningKey,
        ml_dsa_signing_key: prism_sync_crypto::DevicePqSigningKey,
    ) -> Result<Self, String> {
        if !base_url.starts_with("https://") && !base_url.starts_with("http://localhost") {
            return Err(format!(
                "ServerSharingRelay requires an HTTPS URL (got: {base_url:?}). \
                 Use http://localhost only for local development."
            ));
        }

        let client =
            Client::builder().build().map_err(|e| format!("Failed to build HTTP client: {e}"))?;

        Ok(Self {
            base_url,
            client,
            session_token,
            sync_id,
            device_id,
            signing_key,
            ml_dsa_signing_key,
            request_timeout: Duration::from_secs(15),
        })
    }

    fn apply_auth(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        builder
            .header("Authorization", format!("Bearer {}", self.session_token))
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
            ed25519_sig: self.signing_key.sign(&m_prime).to_bytes().to_vec(),
            ml_dsa_65_sig: self.ml_dsa_signing_key.sign(&m_prime),
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
            401 => RelayError::Auth { message: format!("HTTP {status}: {body}") },
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
            409 => RelayError::Protocol { message: format!("HTTP 409 Conflict: {body}") },
            500..=599 => RelayError::Server { status_code: status, message: body.to_string() },
            _ => RelayError::Protocol { message: format!("Unexpected HTTP {status}: {body}") },
        }
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
}

fn write_len_prefixed(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

fn decode_base64_field(field_name: &str, value: &str) -> Result<Vec<u8>, RelayError> {
    BASE64.decode(value).map_err(|e| RelayError::Protocol {
        message: format!("Invalid base64 in {field_name}: {e}"),
    })
}

fn validate_hex_id(field_name: &str, value: &str) -> Result<(), RelayError> {
    if value.len() == 32 && value.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(RelayError::Protocol { message: format!("Invalid {field_name} in relay response") })
    }
}

#[async_trait]
impl SharingRelay for ServerSharingRelay {
    async fn publish_identity(
        &self,
        sharing_id: &str,
        identity_bundle: &[u8],
    ) -> Result<(), RelayError> {
        let path = "/v1/sharing/identity";
        let url = format!("{}{}", self.base_url, path);
        debug!("publish_identity sharing_id={sharing_id}");

        let body = serde_json::json!({
            "sharing_id": sharing_id,
            "identity_bundle": BASE64.encode(identity_bundle),
        });
        let body_bytes = serde_json::to_vec(&body).map_err(|e| RelayError::Protocol {
            message: format!("Failed to serialize publish_identity body: {e}"),
        })?;

        let resp = self
            .apply_signed_auth(self.client.put(&url), "PUT", path, &body_bytes)
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

    async fn publish_prekey(
        &self,
        sharing_id: &str,
        device_id: &str,
        prekey_id: &str,
        prekey_bundle: &[u8],
    ) -> Result<(), RelayError> {
        let path = "/v1/sharing/prekey";
        let url = format!("{}{}", self.base_url, path);
        debug!("publish_prekey sharing_id={sharing_id} device_id={device_id}");

        let body = serde_json::json!({
            "sharing_id": sharing_id,
            "device_id": device_id,
            "prekey_id": prekey_id,
            "prekey_bundle": BASE64.encode(prekey_bundle),
        });
        let body_bytes = serde_json::to_vec(&body).map_err(|e| RelayError::Protocol {
            message: format!("Failed to serialize publish_prekey body: {e}"),
        })?;

        let resp = self
            .apply_signed_auth(self.client.put(&url), "PUT", path, &body_bytes)
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

    async fn fetch_prekey_bundle(
        &self,
        sharing_id: &str,
    ) -> Result<Option<(Vec<u8>, Vec<u8>)>, RelayError> {
        let url = format!("{}/v1/sharing/{}/bundle", self.base_url, sharing_id);
        debug!("fetch_prekey_bundle sharing_id={sharing_id}");

        // Unauthenticated — no auth headers.
        let resp = self
            .client
            .get(&url)
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

        let json: PrekeyBundleResponse = resp.json().await.map_err(|e| RelayError::Protocol {
            message: format!("Failed to parse prekey bundle response: {e}"),
        })?;

        let identity_bundle = decode_base64_field("identity_bundle", &json.identity_bundle)?;
        let prekey_bundle = decode_base64_field("signed_prekey", &json.signed_prekey)?;

        Ok(Some((identity_bundle, prekey_bundle)))
    }

    async fn upload_sharing_init(
        &self,
        init_id: &str,
        recipient_id: &str,
        sender_id: &str,
        payload: &[u8],
    ) -> Result<(), RelayError> {
        let path = "/v1/sharing/init";
        let url = format!("{}{}", self.base_url, path);
        debug!("upload_sharing_init init_id={init_id}");

        let body = serde_json::json!({
            "init_id": init_id,
            "recipient_id": recipient_id,
            "sender_id": sender_id,
            "payload": BASE64.encode(payload),
        });
        let body_bytes = serde_json::to_vec(&body).map_err(|e| RelayError::Protocol {
            message: format!("Failed to serialize upload_sharing_init body: {e}"),
        })?;

        let resp = self
            .apply_signed_auth(self.client.post(&url), "POST", path, &body_bytes)
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

    async fn fetch_pending_inits(&self) -> Result<Vec<PendingSharingInit>, RelayError> {
        let path = "/v1/sharing/init/pending";
        let url = format!("{}{}", self.base_url, path);
        debug!("fetch_pending_inits");

        let resp = self
            .apply_signed_auth(self.client.get(&url), "GET", path, &[])
            .timeout(self.request_timeout)
            .send()
            .await
            .map_err(Self::classify_reqwest_error)?;

        let status = resp.status().as_u16();
        if status >= 400 {
            let body_text = resp.text().await.unwrap_or_default();
            return Err(Self::classify_error(status, &body_text));
        }

        let json: FetchPendingInitsResponse =
            resp.json().await.map_err(|e| RelayError::Protocol {
                message: format!("Failed to parse fetch_pending_inits response: {e}"),
            })?;

        let mut result = Vec::with_capacity(json.payloads.len());
        for pending in json.payloads {
            validate_hex_id("init_id", &pending.init_id)?;
            validate_hex_id("sender_id", &pending.sender_id)?;
            result.push(PendingSharingInit {
                init_id: pending.init_id,
                sender_id: pending.sender_id,
                payload: decode_base64_field("payload", &pending.payload)?,
                created_at: pending.created_at,
            });
        }

        Ok(result)
    }

    async fn remove_identity(&self) -> Result<(), RelayError> {
        let path = "/v1/sharing/identity";
        let url = format!("{}{}", self.base_url, path);
        debug!("remove_identity");

        let resp = self
            .apply_signed_auth(self.client.delete(&url), "DELETE", path, &[])
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    fn serve_once(status: u16, body: &str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let body = body.to_string();

        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request_buf = [0u8; 2048];
            let _ = stream.read(&mut request_buf);
            let response = format!(
                "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.flush().unwrap();
        });

        format!("http://localhost:{}", addr.port())
    }

    fn test_ml_dsa_key() -> prism_sync_crypto::DevicePqSigningKey {
        let ds = prism_sync_crypto::DeviceSecret::generate();
        ds.ml_dsa_65_keypair("test-device").unwrap()
    }

    #[test]
    fn rejects_non_https_url() {
        let key = SigningKey::from_bytes(&[1u8; 32]);
        let result = ServerSharingRelay::new(
            "http://example.com".to_string(),
            "token".to_string(),
            "sync-id".to_string(),
            "device-id".to_string(),
            key,
            test_ml_dsa_key(),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("HTTPS"));
    }

    #[test]
    fn allows_localhost_http() {
        let key = SigningKey::from_bytes(&[1u8; 32]);
        let result = ServerSharingRelay::new(
            "http://localhost:8080".to_string(),
            "token".to_string(),
            "sync-id".to_string(),
            "device-id".to_string(),
            key,
            test_ml_dsa_key(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn allows_https_url() {
        let key = SigningKey::from_bytes(&[1u8; 32]);
        let result = ServerSharingRelay::new(
            "https://relay.example.com".to_string(),
            "token".to_string(),
            "sync-id".to_string(),
            "device-id".to_string(),
            key,
            test_ml_dsa_key(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn classify_error_409_is_protocol() {
        let err = ServerSharingRelay::classify_error(409, "duplicate init_id");
        assert!(matches!(err, RelayError::Protocol { .. }));
    }

    #[test]
    fn classify_error_401_is_auth() {
        let err = ServerSharingRelay::classify_error(401, "unauthorized");
        assert!(matches!(err, RelayError::Auth { .. }));
    }

    #[test]
    fn classify_error_403_upgrade_required_is_structured() {
        let err = ServerSharingRelay::classify_error(
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
    fn classify_error_500_is_server() {
        let err = ServerSharingRelay::classify_error(500, "internal error");
        assert!(matches!(err, RelayError::Server { status_code: 500, .. }));
    }

    #[tokio::test]
    async fn fetch_pending_inits_rejects_missing_fields() {
        let base_url = serve_once(
            200,
            r#"{"payloads":[{"init_id":"00112233445566778899aabbccddeeff","sender_id":"ffeeddccbbaa99887766554433221100","created_at":123}]}"#,
        );
        let relay = ServerSharingRelay::new(
            base_url,
            "token".to_string(),
            "sync-id".to_string(),
            "device-id".to_string(),
            SigningKey::from_bytes(&[1u8; 32]),
            test_ml_dsa_key(),
        )
        .unwrap();

        let err = relay.fetch_pending_inits().await.unwrap_err();
        assert!(matches!(err, RelayError::Protocol { .. }));
    }

    #[tokio::test]
    async fn fetch_pending_inits_rejects_invalid_base64_payload() {
        let base_url = serve_once(
            200,
            r#"{"payloads":[{"init_id":"00112233445566778899aabbccddeeff","sender_id":"ffeeddccbbaa99887766554433221100","payload":"***","created_at":123}]}"#,
        );
        let relay = ServerSharingRelay::new(
            base_url,
            "token".to_string(),
            "sync-id".to_string(),
            "device-id".to_string(),
            SigningKey::from_bytes(&[1u8; 32]),
            test_ml_dsa_key(),
        )
        .unwrap();

        let err = relay.fetch_pending_inits().await.unwrap_err();
        assert!(matches!(err, RelayError::Protocol { .. }));
    }
}
