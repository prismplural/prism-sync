//! Relay communication trait and HTTP client for PQ hybrid device pairing.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use reqwest::Client;
use serde::Deserialize;

use super::traits::RelayError;

// ── Pairing slot enum ──

/// Named slots in a pairing session for exchanging blobs between devices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingSlot {
    Init,
    Confirmation,
    Credentials,
    Joiner,
}

impl PairingSlot {
    pub fn as_path_segment(&self) -> &'static str {
        match self {
            Self::Init => "init",
            Self::Confirmation => "confirmation",
            Self::Credentials => "credentials",
            Self::Joiner => "joiner",
        }
    }
}

// ── Pairing relay trait ──

/// Transport layer for the pairing ceremony's relay communication.
///
/// Ships with `ServerPairingRelay` (HTTP) and `MockPairingRelay` (in-memory).
#[async_trait]
pub trait PairingRelay: Send + Sync {
    /// Create a new pairing session. Returns the rendezvous_id (16 bytes).
    async fn create_session(&self, joiner_bootstrap: &[u8]) -> Result<[u8; 16], RelayError>;

    /// Fetch the joiner's bootstrap record.
    async fn get_bootstrap(&self, rendezvous_id: &str) -> Result<Vec<u8>, RelayError>;

    /// Post a blob to a named slot.
    async fn put_slot(
        &self,
        rendezvous_id: &str,
        slot: PairingSlot,
        data: &[u8],
    ) -> Result<(), RelayError>;

    /// Poll a named slot. Returns None if not yet posted.
    async fn get_slot(
        &self,
        rendezvous_id: &str,
        slot: PairingSlot,
    ) -> Result<Option<Vec<u8>>, RelayError>;

    /// Delete the pairing session.
    ///
    /// This operation is idempotent. The HTTP relay returns `204 No Content`
    /// even if the session was already absent.
    async fn delete_session(&self, rendezvous_id: &str) -> Result<(), RelayError>;
}

// ── HTTP implementation ──

#[derive(Deserialize)]
struct CreateSessionResponse {
    rendezvous_id: String,
}

/// HTTP client for the pairing relay endpoints.
#[derive(Debug)]
pub struct ServerPairingRelay {
    base_url: String,
    client: Client,
    request_timeout: Duration,
}

impl ServerPairingRelay {
    /// Create a new `ServerPairingRelay`.
    ///
    /// Returns an error if the URL does not use HTTPS (except `http://localhost`
    /// for local development).
    pub fn new(relay_url: String) -> Result<Self, String> {
        if !relay_url.starts_with("https://") && !relay_url.starts_with("http://localhost") {
            return Err(format!(
                "PairingRelay requires HTTPS (got: {relay_url:?}). \
                 http://localhost allowed for local development only."
            ));
        }
        let client =
            Client::builder().build().map_err(|e| format!("Failed to build HTTP client: {e}"))?;
        Ok(Self { base_url: relay_url, client, request_timeout: Duration::from_secs(15) })
    }

    /// Classify an HTTP status code into a `RelayError`.
    fn classify_error(status: u16, body: &str) -> RelayError {
        match status {
            401 | 403 => RelayError::Auth { message: format!("HTTP {status}: {body}") },
            408 | 504 => RelayError::Timeout { message: format!("HTTP {status}: {body}") },
            500..=599 => RelayError::Server { status_code: status, message: body.to_string() },
            _ => RelayError::Protocol { message: format!("Unexpected HTTP {status}: {body}") },
        }
    }

    /// Classify a reqwest error into a `RelayError`.
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

#[async_trait]
impl PairingRelay for ServerPairingRelay {
    async fn create_session(&self, joiner_bootstrap: &[u8]) -> Result<[u8; 16], RelayError> {
        let url = format!("{}/v1/pairing", self.base_url);
        let body = serde_json::json!({
            "joiner_bootstrap": BASE64.encode(joiner_bootstrap),
        });

        let resp = self
            .client
            .post(&url)
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

        let parsed: CreateSessionResponse =
            resp.json().await.map_err(|e| RelayError::Protocol {
                message: format!("Failed to parse create_session response: {e}"),
            })?;

        let bytes = hex::decode(&parsed.rendezvous_id).map_err(|e| RelayError::Protocol {
            message: format!("Invalid rendezvous_id hex: {e}"),
        })?;

        let id: [u8; 16] = bytes.try_into().map_err(|v: Vec<u8>| RelayError::Protocol {
            message: format!("rendezvous_id has wrong length: expected 16, got {}", v.len()),
        })?;

        Ok(id)
    }

    async fn get_bootstrap(&self, rendezvous_id: &str) -> Result<Vec<u8>, RelayError> {
        let url = format!("{}/v1/pairing/{}/bootstrap", self.base_url, rendezvous_id);

        let resp = self
            .client
            .get(&url)
            .timeout(self.request_timeout)
            .send()
            .await
            .map_err(Self::classify_reqwest_error)?;

        let status = resp.status().as_u16();
        match status {
            200 => {
                let body_text = resp.text().await.map_err(|e| RelayError::Protocol {
                    message: format!("Failed to read bootstrap body: {e}"),
                })?;
                BASE64.decode(&body_text).map_err(|e| RelayError::Protocol {
                    message: format!("Invalid base64 in bootstrap response: {e}"),
                })
            }
            204 => Err(RelayError::Protocol { message: "bootstrap not available".to_string() }),
            404 => Err(RelayError::Protocol { message: "session not found".to_string() }),
            _ => {
                let body_text = resp.text().await.unwrap_or_default();
                Err(Self::classify_error(status, &body_text))
            }
        }
    }

    async fn put_slot(
        &self,
        rendezvous_id: &str,
        slot: PairingSlot,
        data: &[u8],
    ) -> Result<(), RelayError> {
        let url =
            format!("{}/v1/pairing/{}/{}", self.base_url, rendezvous_id, slot.as_path_segment());

        let resp = self
            .client
            .put(&url)
            .header("Content-Type", "application/octet-stream")
            .body(data.to_vec())
            .timeout(self.request_timeout)
            .send()
            .await
            .map_err(Self::classify_reqwest_error)?;

        let status = resp.status().as_u16();
        match status {
            200 | 204 => Ok(()),
            409 => Err(RelayError::Protocol { message: "slot already written".to_string() }),
            404 => Err(RelayError::Protocol { message: "session not found".to_string() }),
            _ => {
                let body_text = resp.text().await.unwrap_or_default();
                Err(Self::classify_error(status, &body_text))
            }
        }
    }

    async fn get_slot(
        &self,
        rendezvous_id: &str,
        slot: PairingSlot,
    ) -> Result<Option<Vec<u8>>, RelayError> {
        let url =
            format!("{}/v1/pairing/{}/{}", self.base_url, rendezvous_id, slot.as_path_segment());

        let resp = self
            .client
            .get(&url)
            .timeout(self.request_timeout)
            .send()
            .await
            .map_err(Self::classify_reqwest_error)?;

        let status = resp.status().as_u16();
        match status {
            200 => {
                let body = resp.bytes().await.map_err(|e| RelayError::Protocol {
                    message: format!("Failed to read slot body: {e}"),
                })?;
                Ok(Some(body.to_vec()))
            }
            204 => Ok(None),
            404 => Err(RelayError::Protocol { message: "session not found".to_string() }),
            _ => {
                let body_text = resp.text().await.unwrap_or_default();
                Err(Self::classify_error(status, &body_text))
            }
        }
    }

    async fn delete_session(&self, rendezvous_id: &str) -> Result<(), RelayError> {
        let url = format!("{}/v1/pairing/{}", self.base_url, rendezvous_id);

        let resp = self
            .client
            .delete(&url)
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

// ── Mock implementation (for tests) ──

struct MockSession {
    joiner_bootstrap: Vec<u8>,
    slots: HashMap<String, Vec<u8>>,
}

/// In-memory mock for unit testing pairing flows without HTTP.
pub struct MockPairingRelay {
    sessions: Mutex<HashMap<String, MockSession>>,
    next_id_counter: Mutex<u32>,
}

impl MockPairingRelay {
    pub fn new() -> Self {
        Self { sessions: Mutex::new(HashMap::new()), next_id_counter: Mutex::new(0) }
    }
}

impl Default for MockPairingRelay {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PairingRelay for MockPairingRelay {
    async fn create_session(&self, joiner_bootstrap: &[u8]) -> Result<[u8; 16], RelayError> {
        let mut counter = self.next_id_counter.lock().unwrap();
        let id_num = *counter;
        *counter += 1;

        let mut id = [0u8; 16];
        id[12..16].copy_from_slice(&id_num.to_be_bytes());

        let rendezvous_hex = hex::encode(id);

        self.sessions.lock().unwrap().insert(
            rendezvous_hex,
            MockSession { joiner_bootstrap: joiner_bootstrap.to_vec(), slots: HashMap::new() },
        );

        Ok(id)
    }

    async fn get_bootstrap(&self, rendezvous_id: &str) -> Result<Vec<u8>, RelayError> {
        let sessions = self.sessions.lock().unwrap();
        let session = sessions
            .get(rendezvous_id)
            .ok_or_else(|| RelayError::Protocol { message: "session not found".to_string() })?;
        Ok(session.joiner_bootstrap.clone())
    }

    async fn put_slot(
        &self,
        rendezvous_id: &str,
        slot: PairingSlot,
        data: &[u8],
    ) -> Result<(), RelayError> {
        let mut sessions = self.sessions.lock().unwrap();
        let session = sessions
            .get_mut(rendezvous_id)
            .ok_or_else(|| RelayError::Protocol { message: "session not found".to_string() })?;

        let slot_name = slot.as_path_segment().to_string();
        if session.slots.contains_key(&slot_name) {
            return Err(RelayError::Protocol { message: "slot already written".to_string() });
        }

        session.slots.insert(slot_name, data.to_vec());
        Ok(())
    }

    async fn get_slot(
        &self,
        rendezvous_id: &str,
        slot: PairingSlot,
    ) -> Result<Option<Vec<u8>>, RelayError> {
        let sessions = self.sessions.lock().unwrap();
        let session = sessions
            .get(rendezvous_id)
            .ok_or_else(|| RelayError::Protocol { message: "session not found".to_string() })?;
        Ok(session.slots.get(slot.as_path_segment()).cloned())
    }

    async fn delete_session(&self, rendezvous_id: &str) -> Result<(), RelayError> {
        let mut sessions = self.sessions.lock().unwrap();
        sessions
            .remove(rendezvous_id)
            .ok_or_else(|| RelayError::Protocol { message: "session not found".to_string() })?;
        Ok(())
    }
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    fn rendezvous_hex(id: &[u8; 16]) -> String {
        hex::encode(id)
    }

    #[tokio::test]
    async fn mock_relay_create_session() {
        let relay = MockPairingRelay::new();
        let id = relay.create_session(b"bootstrap-data").await.unwrap();
        assert_eq!(id.len(), 16);
    }

    #[tokio::test]
    async fn mock_relay_get_bootstrap() {
        let relay = MockPairingRelay::new();
        let bootstrap = b"test-bootstrap-payload";
        let id = relay.create_session(bootstrap).await.unwrap();
        let rid = rendezvous_hex(&id);

        let result = relay.get_bootstrap(&rid).await.unwrap();
        assert_eq!(result, bootstrap);
    }

    #[tokio::test]
    async fn mock_relay_put_get_slot() {
        let relay = MockPairingRelay::new();
        let id = relay.create_session(b"boot").await.unwrap();
        let rid = rendezvous_hex(&id);

        let data = b"slot-payload-bytes";
        relay.put_slot(&rid, PairingSlot::Init, data).await.unwrap();

        let result = relay.get_slot(&rid, PairingSlot::Init).await.unwrap();
        assert_eq!(result, Some(data.to_vec()));
    }

    #[tokio::test]
    async fn mock_relay_slot_write_once() {
        let relay = MockPairingRelay::new();
        let id = relay.create_session(b"boot").await.unwrap();
        let rid = rendezvous_hex(&id);

        relay.put_slot(&rid, PairingSlot::Confirmation, b"first").await.unwrap();

        let err = relay.put_slot(&rid, PairingSlot::Confirmation, b"second").await.unwrap_err();

        assert!(
            err.to_string().contains("slot already written"),
            "expected 'slot already written', got: {err}"
        );
    }

    #[tokio::test]
    async fn mock_relay_get_slot_not_set() {
        let relay = MockPairingRelay::new();
        let id = relay.create_session(b"boot").await.unwrap();
        let rid = rendezvous_hex(&id);

        let result = relay.get_slot(&rid, PairingSlot::Credentials).await.unwrap();
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn mock_relay_session_not_found() {
        let relay = MockPairingRelay::new();

        let err = relay.get_bootstrap("nonexistent").await.unwrap_err();
        assert!(
            err.to_string().contains("session not found"),
            "expected 'session not found', got: {err}"
        );

        let err = relay.put_slot("nonexistent", PairingSlot::Init, b"data").await.unwrap_err();
        assert!(err.to_string().contains("session not found"));

        let err = relay.get_slot("nonexistent", PairingSlot::Init).await.unwrap_err();
        assert!(err.to_string().contains("session not found"));
    }

    #[tokio::test]
    async fn mock_relay_delete_session() {
        let relay = MockPairingRelay::new();
        let id = relay.create_session(b"boot").await.unwrap();
        let rid = rendezvous_hex(&id);

        relay.delete_session(&rid).await.unwrap();

        let err = relay.get_bootstrap(&rid).await.unwrap_err();
        assert!(err.to_string().contains("session not found"));
    }

    #[test]
    fn server_pairing_relay_rejects_http() {
        let result = ServerPairingRelay::new("http://example.com".to_string());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("HTTPS"));
    }

    #[test]
    fn server_pairing_relay_allows_https() {
        let result = ServerPairingRelay::new("https://example.com".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn server_pairing_relay_allows_localhost() {
        let result = ServerPairingRelay::new("http://localhost:8080".to_string());
        assert!(result.is_ok());
    }
}
