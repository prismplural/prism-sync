use std::collections::HashMap;
use std::pin::Pin;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures_util::Stream;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Error type for relay operations.
#[derive(Debug, Error)]
pub enum RelayError {
    #[error("network error: {message}")]
    Network { message: String },

    #[error("server error ({status_code}): {message}")]
    Server { status_code: u16, message: String },

    #[error("request timeout: {message}")]
    Timeout { message: String },

    #[error("auth error: {message}")]
    Auth { message: String },

    #[error("device identity mismatch: {message}")]
    DeviceIdentityMismatch { message: String },

    #[error("protocol error: {message}")]
    Protocol { message: String },

    #[error("epoch rotation required: new_epoch={new_epoch}")]
    EpochRotation { new_epoch: i32 },

    #[error("clock skew detected: drift={drift_ms}ms from device {device_id}")]
    ClockSkew { drift_ms: i64, device_id: String },

    #[error("key changed: {message}")]
    KeyChanged { message: String },

    #[error("device revoked (remote_wipe={remote_wipe})")]
    DeviceRevoked { remote_wipe: bool },
}

impl RelayError {
    /// Returns the error kind for categorization.
    pub fn kind(&self) -> RelayErrorKind {
        match self {
            RelayError::Network { .. } => RelayErrorKind::Network,
            RelayError::Server { .. } => RelayErrorKind::Server,
            RelayError::Timeout { .. } => RelayErrorKind::Timeout,
            RelayError::Auth { .. } => RelayErrorKind::Auth,
            RelayError::DeviceIdentityMismatch { .. } => RelayErrorKind::DeviceIdentityMismatch,
            RelayError::Protocol { .. } => RelayErrorKind::Protocol,
            RelayError::EpochRotation { .. } => RelayErrorKind::EpochRotation,
            RelayError::ClockSkew { .. } => RelayErrorKind::ClockSkew,
            RelayError::KeyChanged { .. } => RelayErrorKind::KeyChanged,
            RelayError::DeviceRevoked { .. } => RelayErrorKind::DeviceRevoked,
        }
    }

    /// Returns whether this error is retryable.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self.kind(),
            RelayErrorKind::Network | RelayErrorKind::Timeout | RelayErrorKind::Server
        )
    }
}

/// Classification of relay error kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayErrorKind {
    Network,
    Server,
    Timeout,
    Auth,
    DeviceIdentityMismatch,
    Protocol,
    EpochRotation,
    ClockSkew,
    KeyChanged,
    DeviceRevoked,
}

// ── Request/Response types ──

/// Proof that an existing trusted device approved this registration.
/// Sent by joiners whose PairingRequest was approved by a group member.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryApproval {
    /// Device ID of the approving (existing) device.
    pub approver_device_id: String,
    /// Ed25519 public key of the approver (32 bytes, hex-encoded).
    pub approver_ed25519_pk: String,
    /// Ed25519 signature over the canonical approval data (hex-encoded).
    pub approval_signature: String,
    /// The signed registry snapshot (wire format: [sig || json]).
    /// Allows the relay to verify group membership without seeing plaintext.
    pub signed_registry_snapshot: Vec<u8>,
}

/// Optional first-device admission proof used by public relays to gate new
/// sync-group creation without relying on bearer invites.
///
/// The relay treats these proofs as anti-abuse signals only. They do not
/// become part of the long-term sync trust model after registration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FirstDeviceAdmissionProof {
    /// Android hardware-backed key attestation certificate chain. Each element
    /// is a base64-encoded DER certificate, leaf-first.
    AndroidKeyAttestation { certificate_chain: Vec<String> },

    /// Apple App Attest attestation object, bound to the relay-issued nonce.
    AppleAppAttest {
        key_id: String,
        attestation_object: String,
    },
}

/// Registration request for a new device.
///
/// There are two admission paths:
///
/// - **First device (new group):** `first_device_admission_proof` may be
///   supplied as a platform signal, and `pow_solution` remains the universal
///   fallback. `registry_approval` is `None` because there is no existing group.
///
/// - **Existing group (joiner):** `registry_approval` carries the approver's
///   attestation that this device was admitted via the pairing flow.
#[derive(Debug, Clone)]
pub struct RegisterRequest {
    pub device_id: String,
    pub signing_public_key: Vec<u8>,
    pub x25519_public_key: Vec<u8>,
    pub registration_challenge: Vec<u8>,
    pub nonce: String,
    pub pow_solution: Option<ProofOfWorkSolution>,
    pub first_device_admission_proof: Option<FirstDeviceAdmissionProof>,
    pub registry_approval: Option<RegistryApproval>,
}

/// Optional anti-abuse challenge returned with a registration nonce.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofOfWorkChallenge {
    pub algorithm: String,
    pub difficulty_bits: u8,
}

/// PoW response sent back during registration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofOfWorkSolution {
    pub counter: u64,
}

/// Registration nonce plus any optional first-device admission challenge.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct RegistrationNonceResponse {
    pub nonce: String,
    #[serde(default)]
    pub pow_challenge: Option<ProofOfWorkChallenge>,
}

/// Registration response with device session token.
#[derive(Debug, Clone, Deserialize)]
pub struct RegisterResponse {
    pub device_session_token: String,
}

/// Response from pulling changes.
#[derive(Debug, Clone)]
pub struct PullResponse {
    pub batches: Vec<ReceivedBatch>,
    pub max_server_seq: i64,
    pub min_acked_seq: Option<i64>,
    /// The current password version for this sync group.
    /// `None` if the relay is older and doesn't include this field.
    pub password_version: Option<i32>,
}

/// A batch received from the relay, including the full signed envelope.
///
/// IMPORTANT: The relay passes through the complete SignedBatchEnvelope
/// so that clients can verify the sender's Ed25519 signature before
/// decrypting. The relay does NOT verify signatures (zero-knowledge).
#[derive(Debug, Clone)]
pub struct ReceivedBatch {
    pub server_seq: i64,
    pub received_at: DateTime<Utc>,
    pub envelope: SignedBatchEnvelope,
}

/// An outgoing batch to push to the relay.
#[derive(Debug, Clone)]
pub struct OutgoingBatch {
    pub batch_id: String,
    pub envelope: SignedBatchEnvelope,
}

/// Signed and encrypted batch envelope.
///
/// Contains all fields needed for verification and decryption.
/// See spec section "Batch Sender Authentication (Ed25519 Signatures)".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedBatchEnvelope {
    pub protocol_version: u16,
    pub sync_id: String,
    pub epoch: i32,
    pub batch_id: String,
    pub batch_kind: String,
    pub sender_device_id: String,
    #[serde(with = "base64_hash")]
    pub payload_hash: [u8; 32],
    #[serde(with = "base64_bytes")]
    pub signature: Vec<u8>,
    #[serde(with = "base64_nonce")]
    pub nonce: [u8; 24],
    #[serde(with = "base64_bytes")]
    pub ciphertext: Vec<u8>,
}

/// Response from fetching a snapshot.
///
/// The `data` field contains the full serialized `SignedBatchEnvelope`
/// (with `batch_kind = "snapshot"`) so that the receiver can verify the
/// sender's Ed25519 signature before decrypting the snapshot content.
#[derive(Debug, Clone)]
pub struct SnapshotResponse {
    pub epoch: i32,
    pub server_seq_at: i64,
    pub data: Vec<u8>,
    pub sender_device_id: String,
}

/// Information about a device in the sync group (from relay).
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceInfo {
    pub device_id: String,
    pub epoch: i32,
    pub status: String,
    #[serde(
        default,
        alias = "signing_public_key",
        deserialize_with = "deserialize_base64_or_bytes"
    )]
    pub ed25519_public_key: Vec<u8>,
    #[serde(default, deserialize_with = "deserialize_base64_or_bytes")]
    pub x25519_public_key: Vec<u8>,
    pub permission: Option<String>,
}

/// Serde module for `Vec<u8>` that serializes as base64 and deserializes
/// from either base64 strings or integer arrays (backward-compatible).
///
/// Use with `#[serde(with = "base64_bytes")]` on `Vec<u8>` fields.
pub(crate) mod base64_bytes {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{de, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        deserializer.deserialize_any(Base64OrBytesVisitor)
    }

    struct Base64OrBytesVisitor;

    impl<'de> de::Visitor<'de> for Base64OrBytesVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a base64 string or byte array")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Vec<u8>, E> {
            STANDARD.decode(v).map_err(de::Error::custom)
        }

        fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<u8>, A::Error> {
            let mut bytes = Vec::new();
            while let Some(b) = seq.next_element::<u8>()? {
                bytes.push(b);
            }
            Ok(bytes)
        }

        fn visit_none<E: de::Error>(self) -> Result<Vec<u8>, E> {
            Ok(Vec::new())
        }

        fn visit_unit<E: de::Error>(self) -> Result<Vec<u8>, E> {
            Ok(Vec::new())
        }
    }
}

/// Serde module for `[u8; 32]` that serializes as base64 and deserializes
/// from either base64 strings or integer arrays.
pub(crate) mod base64_hash {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{de, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
        let bytes: Vec<u8> = super::base64_bytes::deserialize(deserializer)?;
        bytes
            .try_into()
            .map_err(|_| de::Error::custom("expected 32 bytes for hash"))
    }
}

/// Serde module for `[u8; 24]` (nonce) that serializes as base64 and deserializes
/// from either base64 strings or integer arrays.
pub(crate) mod base64_nonce {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{de, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 24], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 24], D::Error> {
        let bytes: Vec<u8> = super::base64_bytes::deserialize(deserializer)?;
        bytes
            .try_into()
            .map_err(|_| de::Error::custom("expected 24 bytes for nonce"))
    }
}

/// Deserialize a `Vec<u8>` from either a base64-encoded JSON string or a raw byte array.
///
/// The relay server sends public keys as base64 strings, but in-memory / mock
/// usage may provide raw byte arrays. This handles both cases.
fn deserialize_base64_or_bytes<'de, D>(deserializer: D) -> std::result::Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    base64_bytes::deserialize(deserializer)
}

/// Real-time notification from the relay WebSocket.
#[derive(Debug, Clone)]
pub enum SyncNotification {
    /// New data is available; trigger a pull cycle.
    NewData { server_seq: i64 },
    /// A device was revoked from the sync group.
    DeviceRevoked {
        device_id: String,
        new_epoch: i32,
        remote_wipe: bool,
    },
    /// The epoch was rotated; recover the new epoch key.
    EpochRotated { new_epoch: i32 },
    /// Session token was rotated (handled internally).
    TokenRotated { new_token: String },
    /// WebSocket connection state changed (for UI display).
    ConnectionStateChanged { connected: bool },
}

/// Transport layer for communicating with the relay server.
///
/// Ships with `ServerRelay` (HTTP + WebSocket). Consumers can mock
/// or replace for testing or alternative transports.
///
/// Ported from Dart `lib/core/sync/sync_relay.dart`.
#[async_trait]
pub trait SyncRelay: Send + Sync {
    /// Fetch a single-use registration nonce from the relay.
    ///
    /// The nonce is cryptographically random, short-lived (60s), and consumed
    /// after a single use. The client signs `sync_id || device_id || nonce`
    /// with its Ed25519 key as a challenge-response for registration.
    async fn get_registration_nonce(
        &self,
    ) -> std::result::Result<RegistrationNonceResponse, RelayError>;

    /// Register device with relay via challenge-response.
    /// Returns device-scoped session token.
    async fn register_device(
        &self,
        req: RegisterRequest,
    ) -> std::result::Result<RegisterResponse, RelayError>;

    /// Pull encrypted batches since a given server sequence number.
    async fn pull_changes(&self, since: i64) -> std::result::Result<PullResponse, RelayError>;

    /// Push an encrypted batch. Returns the server-assigned sequence number.
    async fn push_changes(&self, batch: OutgoingBatch) -> std::result::Result<i64, RelayError>;

    /// Download full snapshot for first-sync bootstrap.
    async fn get_snapshot(&self) -> std::result::Result<Option<SnapshotResponse>, RelayError>;

    /// Upload snapshot.
    ///
    /// Optional `ttl_secs` makes the snapshot ephemeral (auto-deleted after TTL).
    /// Optional `for_device_id` targets the snapshot at a specific device
    /// (relay deletes it after that device downloads it).
    async fn put_snapshot(
        &self,
        epoch: i32,
        server_seq_at: i64,
        data: Vec<u8>,
        ttl_secs: Option<u64>,
        for_device_id: Option<String>,
        sender_device_id: String,
    ) -> std::result::Result<(), RelayError>;

    /// List all devices in this sync group.
    async fn list_devices(&self) -> std::result::Result<Vec<DeviceInfo>, RelayError>;

    /// Atomically revoke a device and rotate to `new_epoch`.
    ///
    /// `wrapped_keys` must contain wrapped epoch-key artifacts for all
    /// surviving devices.
    async fn revoke_device(
        &self,
        device_id: &str,
        remote_wipe: bool,
        new_epoch: i32,
        wrapped_keys: HashMap<String, Vec<u8>>,
    ) -> std::result::Result<i32, RelayError>;

    /// Standalone non-revoking epoch rotation.
    ///
    /// Posts per-device wrapped epoch-key artifacts for `epoch`.
    async fn post_rekey_artifacts(
        &self,
        epoch: i32,
        wrapped_keys: HashMap<String, Vec<u8>>,
    ) -> std::result::Result<i32, RelayError>;

    /// Fetch this device's wrapped epoch key for a given epoch.
    async fn get_rekey_artifact(
        &self,
        epoch: i32,
        device_id: &str,
    ) -> std::result::Result<Option<Vec<u8>>, RelayError>;

    /// Self-deregister this device from the sync group.
    async fn deregister(&self) -> std::result::Result<(), RelayError>;

    /// Delete the entire sync group and all data on the relay.
    async fn delete_sync_group(&self) -> std::result::Result<(), RelayError>;

    /// Acknowledge receipt of server_seq (allows relay to prune).
    async fn ack(&self, server_seq: i64) -> std::result::Result<(), RelayError>;

    /// Connect WebSocket for real-time notifications.
    async fn connect_websocket(&self) -> std::result::Result<(), RelayError>;

    /// Disconnect WebSocket.
    async fn disconnect_websocket(&self) -> std::result::Result<(), RelayError>;

    /// Stream of real-time notifications from the relay.
    fn notifications(&self) -> Pin<Box<dyn Stream<Item = SyncNotification> + Send>>;

    /// Dispose of all resources.
    async fn dispose(&self) -> std::result::Result<(), RelayError>;
}
