//! Relay communication trait and HTTP client for PQ hybrid device pairing.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use reqwest::Client;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::traits::RelayError;

// ── Pairing slot enum ──

/// Named slots in a pairing session for exchanging blobs between devices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingSlot {
    Init,
    Confirmation,
    Credentials,
    Joiner,
    /// Optional initiator lease capability, posted **before** [`Self::Init`].
    ///
    /// Legacy relays 404 this slot, which means no lease and never a ceremony
    /// failure. Old joiners never fetch it; new joiners fetch it only after
    /// parsing and authenticating the unchanged `pairing_init`, so posting it
    /// first removes the empty-slot race.
    LeaseCapability,
}

impl PairingSlot {
    pub fn as_path_segment(&self) -> &'static str {
        match self {
            Self::Init => "init",
            Self::Confirmation => "confirmation",
            Self::Credentials => "credentials",
            Self::Joiner => "joiner",
            Self::LeaseCapability => "lease_capability",
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

    /// Create a new pairing session, optionally committing a lease verifier.
    ///
    /// `lease` carries the joiner's optional create metadata
    /// (`lease_key_hash = SHA-256(capability inner frame)`, `lease_version`).
    /// The returned [`CreatePairingSessionOutcome::lease_version`] is the
    /// relay's echo, which is authoritative: old relays ignore unknown request
    /// fields and simply omit the echo, which means fixed-TTL pairing.
    ///
    /// The default implementation preserves source compatibility for external,
    /// mock, and self-hosted implementors: it delegates to
    /// [`Self::create_session`], which never offers a lease and therefore
    /// always reports no relay echo (safe downgrade).
    async fn create_session_with_lease(
        &self,
        joiner_bootstrap: &[u8],
        lease: Option<PairingLeaseOffer<'_>>,
    ) -> Result<CreatePairingSessionOutcome, RelayError> {
        let _ = lease;
        let rendezvous_id = self.create_session(joiner_bootstrap).await?;
        Ok(CreatePairingSessionOutcome { rendezvous_id, lease_version: None })
    }

    /// Renew the opaque pairing lease.
    ///
    /// `POST /v1/pairing/{rendezvous_id}/lease/renew` with the exact 32-byte
    /// `pairing_lease_secret` as the body; `204` means renewed.
    ///
    /// Every failure is nonfatal to the ceremony. The relay returns the same
    /// not-found response for unknown, expired, unsupported, wrong-secret,
    /// pre-confirmation, consumed, and saturated sessions, which the caller
    /// classifies as [`crate::relay::traits::RelayError::NotFound`] (terminal for
    /// the lease) so the endpoint is not a state oracle.
    ///
    /// The default implementation reports `NotFound`, which is the correct
    /// downgrade for any implementor that does not speak the lease protocol:
    /// lease renewal is simply unavailable and the ceremony continues under its
    /// previous expiry.
    async fn renew_lease(
        &self,
        rendezvous_id: &str,
        lease_secret: &[u8; 32],
    ) -> Result<(), RelayError> {
        let _ = (rendezvous_id, lease_secret);
        Err(RelayError::NotFound)
    }
}

// ── Lease negotiation types ──────────────────────────────────────────────────

/// The joiner's optional lease metadata sent with session creation.
#[derive(Debug, Clone, Copy)]
pub struct PairingLeaseOffer<'a> {
    /// `SHA-256` of the capability inner frame the initiator will post.
    pub lease_key_hash: &'a [u8; 32],
    /// Requested lease version (v1 = 1).
    pub lease_version: u16,
}

/// Result of creating a pairing session, including the relay's lease echo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreatePairingSessionOutcome {
    /// The new rendezvous ID.
    pub rendezvous_id: [u8; 16],
    /// The relay's echoed lease version, when it supports the lease.
    ///
    /// `None` means absent: either the relay ignored the request's optional
    /// create fields (old relay), or the joiner did not offer a lease.
    pub lease_version: Option<u16>,
}

impl CreatePairingSessionOutcome {
    /// Whether the relay echoed a supported lease version.
    pub fn relay_supports_lease(&self, requested: u16) -> bool {
        self.lease_version == Some(requested)
    }
}

// ── HTTP implementation ──

#[derive(Deserialize)]
struct CreateSessionResponse {
    rendezvous_id: String,
    /// The relay's lease echo. Absent on old relays (unknown response field is
    /// tolerated, and an ignored request field is detected from its absence).
    #[serde(default)]
    lease_version: Option<u16>,
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
        Ok(self.create_session_with_lease(joiner_bootstrap, None).await?.rendezvous_id)
    }

    async fn create_session_with_lease(
        &self,
        joiner_bootstrap: &[u8],
        lease: Option<PairingLeaseOffer<'_>>,
    ) -> Result<CreatePairingSessionOutcome, RelayError> {
        let url = format!("{}/v1/pairing", self.base_url);
        let mut body = serde_json::json!({
            "joiner_bootstrap": BASE64.encode(joiner_bootstrap),
        });
        // Optional lease metadata. Old relays ignore unknown request fields, so
        // the absence of the response echo—not successful creation—is
        // authoritative and means fixed-TTL pairing.
        if let Some(offer) = lease {
            let object = body.as_object_mut().ok_or_else(|| RelayError::Protocol {
                message: "create_session body must be a JSON object".to_string(),
            })?;
            object.insert(
                "lease_key_hash".to_string(),
                serde_json::Value::String(BASE64.encode(offer.lease_key_hash)),
            );
            object.insert(
                "lease_version".to_string(),
                serde_json::Value::Number(serde_json::Number::from(offer.lease_version as u64)),
            );
        }

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

        let rendezvous_id: [u8; 16] =
            bytes.try_into().map_err(|v: Vec<u8>| RelayError::Protocol {
                message: format!("rendezvous_id has wrong length: expected 16, got {}", v.len()),
            })?;

        Ok(CreatePairingSessionOutcome { rendezvous_id, lease_version: parsed.lease_version })
    }

    async fn renew_lease(
        &self,
        rendezvous_id: &str,
        lease_secret: &[u8; 32],
    ) -> Result<(), RelayError> {
        let url = format!("{}/v1/pairing/{}/lease/renew", self.base_url, rendezvous_id);

        let resp = self
            .client
            .post(&url)
            .header("Content-Type", "application/octet-stream")
            .body(lease_secret.to_vec())
            .timeout(self.request_timeout)
            .send()
            .await
            .map_err(Self::classify_reqwest_error)?;

        let status = resp.status().as_u16();
        match status {
            200 | 204 => Ok(()),
            // Unknown, expired, unsupported, wrong-secret, pre-confirmation,
            // consumed, and saturated sessions are all the same uniform
            // not-found so the endpoint is not a state oracle. Terminal for the
            // lease, but never fatal to the ceremony.
            404 => Err(RelayError::NotFound),
            _ => {
                let body_text = resp.text().await.unwrap_or_default();
                Err(Self::classify_error(status, &body_text))
            }
        }
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
    /// Set-once create-time lease verifier (immutable, nullable).
    lease_key_hash: Option<[u8; 32]>,
    /// Lease version committed at create time.
    lease_version: Option<u16>,
}

/// In-memory mock for unit testing pairing flows without HTTP.
pub struct MockPairingRelay {
    sessions: Mutex<HashMap<String, MockSession>>,
    next_id_counter: Mutex<u32>,
    /// Whether this mock behaves like a lease-capable relay. Clearing it models
    /// an old relay that ignores the optional create fields and 404s the
    /// capability slot, i.e. the nonfatal fixed-TTL downgrade.
    lease_supported: std::sync::atomic::AtomicBool,
    /// Number of successful renewals observed, for assertions.
    renew_successes: std::sync::atomic::AtomicU64,
}

impl MockPairingRelay {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            next_id_counter: Mutex::new(0),
            lease_supported: std::sync::atomic::AtomicBool::new(true),
            renew_successes: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Test hook: model an old relay that neither echoes the lease version nor
    /// serves the lease endpoints.
    pub fn set_lease_supported(&self, supported: bool) {
        self.lease_supported.store(supported, std::sync::atomic::Ordering::Release);
    }

    /// Test hook: how many renewals this mock accepted.
    pub fn renew_successes(&self) -> u64 {
        self.renew_successes.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Test hook: overwrite the stored joiner bootstrap record for a session,
    /// simulating a malicious relay that serves tampered bootstrap bytes on a
    /// post-ceremony fetch. Used to prove the initiator never re-trusts the
    /// relay's bootstrap record for the joiner's identity keys.
    pub fn tamper_bootstrap(&self, rendezvous_id: &str, joiner_bootstrap: Vec<u8>) {
        if let Some(session) = self.sessions.lock().unwrap().get_mut(rendezvous_id) {
            session.joiner_bootstrap = joiner_bootstrap;
        }
    }

    /// Test hook for terminal slot consumption.
    #[cfg(test)]
    pub fn remove_slot_for_test(&self, rendezvous_id: &str, slot: PairingSlot) {
        if let Some(session) = self.sessions.lock().unwrap().get_mut(rendezvous_id) {
            session.slots.remove(slot.as_path_segment());
        }
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
        Ok(self.create_session_with_lease(joiner_bootstrap, None).await?.rendezvous_id)
    }

    async fn create_session_with_lease(
        &self,
        joiner_bootstrap: &[u8],
        lease: Option<PairingLeaseOffer<'_>>,
    ) -> Result<CreatePairingSessionOutcome, RelayError> {
        let mut counter = self.next_id_counter.lock().unwrap();
        let id_num = *counter;
        *counter += 1;

        let mut id = [0u8; 16];
        id[12..16].copy_from_slice(&id_num.to_be_bytes());

        let rendezvous_hex = hex::encode(id);

        // A relay only commits and echoes the lease when it actually supports
        // it. Otherwise the create response carries no echo, which is what a
        // legacy relay looks like: safe downgrade, not an error.
        let supported = self.lease_supported.load(std::sync::atomic::Ordering::Acquire);
        let (lease_key_hash, lease_version): (Option<[u8; 32]>, Option<u16>) = match lease {
            Some(offer) if supported => (Some(*offer.lease_key_hash), Some(offer.lease_version)),
            _ => (None, None),
        };

        self.sessions.lock().unwrap().insert(
            rendezvous_hex,
            MockSession {
                joiner_bootstrap: joiner_bootstrap.to_vec(),
                slots: HashMap::new(),
                lease_key_hash,
                lease_version,
            },
        );

        Ok(CreatePairingSessionOutcome { rendezvous_id: id, lease_version })
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

        // An old relay does not know this slot at all.
        if slot == PairingSlot::LeaseCapability
            && !self.lease_supported.load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(RelayError::NotFound);
        }

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

        if slot == PairingSlot::LeaseCapability
            && !self.lease_supported.load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(RelayError::NotFound);
        }

        Ok(session.slots.get(slot.as_path_segment()).cloned())
    }

    async fn delete_session(&self, rendezvous_id: &str) -> Result<(), RelayError> {
        let mut sessions = self.sessions.lock().unwrap();
        sessions
            .remove(rendezvous_id)
            .ok_or_else(|| RelayError::Protocol { message: "session not found".to_string() })?;
        Ok(())
    }

    async fn renew_lease(
        &self,
        rendezvous_id: &str,
        lease_secret: &[u8; 32],
    ) -> Result<(), RelayError> {
        if !self.lease_supported.load(std::sync::atomic::Ordering::Acquire) {
            return Err(RelayError::NotFound);
        }
        let sessions = self.sessions.lock().unwrap();
        let session = sessions.get(rendezvous_id).ok_or(RelayError::NotFound)?;

        // Uniform not-found for unsupported sessions, matching the relay's
        // no-state-oracle behavior. A committed v1 verifier is required: a
        // legacy row carries none, and a session created without an echo never
        // had one.
        if session.lease_version != Some(crate::pairing::lease::LEASE_VERSION_V1) {
            return Err(RelayError::NotFound);
        }
        let Some(committed) = session.lease_key_hash else {
            return Err(RelayError::NotFound);
        };

        // Constant-time verifier comparison.
        let presented: [u8; 32] = Sha256::digest(lease_secret).into();
        let mut diff = 0u8;
        for (a, b) in committed.iter().zip(presented.iter()) {
            diff |= a ^ b;
        }
        if diff != 0 {
            return Err(RelayError::NotFound);
        }

        self.renew_successes.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
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
