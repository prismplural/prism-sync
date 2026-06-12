use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures_util::Stream;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Callback invoked by `put_snapshot` to report upload progress.
///
/// Arguments are `(bytes_sent_cumulative, bytes_total)`. The callback is
/// invoked on each yielded upload chunk; server-side streaming throttles the
/// frequency so consumers do not need to rate-limit further.
pub type SnapshotUploadProgress = Arc<dyn Fn(u64, u64) + Send + Sync>;

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

    #[error("upgrade required: min_signature_version={min_signature_version}, {message}")]
    UpgradeRequired { min_signature_version: u8, message: String },

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

    #[error("must bootstrap from snapshot: since_seq={since_seq}, first_retained_seq={first_retained_seq}")]
    MustBootstrapFromSnapshot { since_seq: i64, first_retained_seq: i64, message: String },

    /// A `PUT /snapshot` upload lost the seq-ordering race against an
    /// existing snapshot. Distinct from [`Self::EpochRotation`] so the
    /// engine can route it through the suppression matrix in
    /// `SyncEngine::upload_pairing_snapshot` (see
    /// `should_suppress_stale_snapshot` for the audience rules).
    ///
    /// `current_target_device_id` carries the existing snapshot's
    /// pairing target so the matrix can distinguish the cases that
    /// suppress (same audience or wider) from the cases that propagate
    /// (any narrower audience would silently lose availability).
    #[error(
        "snapshot stale: current_server_seq_at={current_server_seq_at}, \
         current_target_device_id={current_target_device_id:?}"
    )]
    SnapshotStale { current_server_seq_at: i64, current_target_device_id: Option<String> },

    #[error("not found")]
    NotFound,

    #[error("forbidden: {message}")]
    Forbidden { message: String },

    /// A not-yet-upgraded relay still 409s a standalone `/rekey` while
    /// `needs_rekey` is set (the older "must use the atomic endpoint" guard).
    /// Surfaced as a retryable condition so a pairing rekey backs off and retries
    /// rather than failing hard — the new relay un-deadlocks it on deploy.
    #[error("relay upgrade pending: {message}")]
    RelayUpgradePending { message: String },

    #[error("http error ({status}): {body}")]
    Http { status: u16, body: String },
}

impl RelayError {
    /// Returns the error kind for categorization.
    pub fn kind(&self) -> RelayErrorKind {
        match self {
            RelayError::Network { .. } => RelayErrorKind::Network,
            RelayError::Server { .. } => RelayErrorKind::Server,
            RelayError::Timeout { .. } => RelayErrorKind::Timeout,
            RelayError::Auth { .. } => RelayErrorKind::Auth,
            RelayError::UpgradeRequired { .. } => RelayErrorKind::UpgradeRequired,
            RelayError::DeviceIdentityMismatch { .. } => RelayErrorKind::DeviceIdentityMismatch,
            RelayError::Protocol { .. } => RelayErrorKind::Protocol,
            RelayError::EpochRotation { .. } => RelayErrorKind::EpochRotation,
            RelayError::ClockSkew { .. } => RelayErrorKind::ClockSkew,
            RelayError::KeyChanged { .. } => RelayErrorKind::KeyChanged,
            RelayError::DeviceRevoked { .. } => RelayErrorKind::DeviceRevoked,
            RelayError::MustBootstrapFromSnapshot { .. } => {
                RelayErrorKind::MustBootstrapFromSnapshot
            }
            RelayError::SnapshotStale { .. } => RelayErrorKind::SnapshotStale,
            RelayError::NotFound => RelayErrorKind::NotFound,
            RelayError::Forbidden { .. } => RelayErrorKind::Forbidden,
            RelayError::RelayUpgradePending { .. } => RelayErrorKind::RelayUpgradePending,
            RelayError::Http { .. } => RelayErrorKind::Http,
        }
    }

    /// Returns whether this error is retryable.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self.kind(),
            RelayErrorKind::Network
                | RelayErrorKind::Timeout
                | RelayErrorKind::Server
                // An old relay still 409ing a needs_rekey'd standalone
                // rekey is transient — it clears the moment the relay upgrades.
                | RelayErrorKind::RelayUpgradePending
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
    UpgradeRequired,
    DeviceIdentityMismatch,
    Protocol,
    EpochRotation,
    ClockSkew,
    KeyChanged,
    DeviceRevoked,
    MustBootstrapFromSnapshot,
    /// Stale snapshot upload — the relay already has a snapshot with a
    /// `server_seq_at` strictly greater than (or equal to) ours. The
    /// caller should treat this as success-equivalent and drop the
    /// upload rather than triggering any recovery codepath.
    SnapshotStale,
    NotFound,
    Forbidden,
    /// A not-yet-upgraded relay 409s a standalone rekey while `needs_rekey`
    /// is set. Retryable — clears on relay deploy.
    RelayUpgradePending,
    Http,
}

// ── Request/Response types ──

/// Proof that an existing trusted device approved this registration.
/// Sent by joiners whose PairingRequest was approved by a group member.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryApproval {
    /// Device ID of the approving (existing) device.
    pub approver_device_id: String,
    /// Ed25519 public key of the approver (classical component of hybrid identity) (32 bytes, hex-encoded).
    pub approver_ed25519_pk: String,
    /// ML-DSA-65 public key of the approver (1952 bytes, hex-encoded).
    #[serde(default)]
    pub approver_ml_dsa_65_pk: String,
    /// Hybrid signature (Ed25519 + ML-DSA-65) over the canonical approval data (hex-encoded).
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
    AppleAppAttest { key_id: String, attestation_object: String },
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
    pub ml_dsa_65_public_key: Vec<u8>,
    pub ml_kem_768_public_key: Vec<u8>,
    pub x_wing_public_key: Vec<u8>,
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
    #[serde(default)]
    pub min_signature_version: Option<u8>,
}

/// Registration response with device session token.
#[derive(Debug, Clone, Deserialize)]
pub struct RegisterResponse {
    pub device_session_token: String,
    #[serde(default)]
    pub min_signature_version: Option<u8>,
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
/// so that clients can verify the sender's hybrid signature (Ed25519 + ML-DSA-65) before
/// decrypting. The relay does NOT verify signatures — content authenticity is checked client-side.
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
/// Protocol version 3 uses hybrid Ed25519 + ML-DSA-65 signatures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedBatchEnvelope {
    pub protocol_version: u16,
    pub sync_id: String,
    pub epoch: i32,
    pub batch_id: String,
    pub batch_kind: String,
    pub sender_device_id: String,
    /// ML-DSA key generation of the sender (bound into canonical signed data).
    #[serde(default)]
    pub sender_ml_dsa_key_generation: u32,
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
/// sender's hybrid signature (Ed25519 + ML-DSA-65) before decrypting the snapshot content.
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
    #[serde(default, deserialize_with = "deserialize_base64_or_bytes")]
    pub ml_dsa_65_public_key: Vec<u8>,
    #[serde(default, deserialize_with = "deserialize_base64_or_bytes")]
    pub ml_kem_768_public_key: Vec<u8>,
    #[serde(default, deserialize_with = "deserialize_base64_or_bytes")]
    pub x_wing_public_key: Vec<u8>,
    pub permission: Option<String>,
    #[serde(default)]
    pub ml_dsa_key_generation: u32,
    /// Group-level rekey-needed flag, mirrored onto every device entry by
    /// the relay's `list_devices`. `true` means the 90d auto-revoke left the
    /// group owing a forced epoch rotation; a polling client (no live WS) reads
    /// it to drive the standalone rekey that clears it. Defaults to `false` so an
    /// older relay that omits the key still deserializes.
    #[serde(default)]
    pub needs_rekey: bool,
}

/// Relay-advertised GIF service configuration for the current sync server.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GifServiceConfig {
    pub enabled: bool,
    pub api_base_url: Option<String>,
    pub media_proxy_enabled: bool,
}

/// Serde module for `Vec<u8>` that serializes as base64 and deserializes
/// from either base64 strings or integer arrays (backward-compatible).
///
/// Use with `#[serde(with = "base64_bytes")]` on `Vec<u8>` fields.
pub(crate) mod base64_bytes {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{de, Deserializer, Serializer};

    pub(crate) fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
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

    pub(crate) fn serialize<S: Serializer>(
        bytes: &[u8; 32],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<[u8; 32], D::Error> {
        let bytes: Vec<u8> = super::base64_bytes::deserialize(deserializer)?;
        bytes.try_into().map_err(|_| de::Error::custom("expected 32 bytes for hash"))
    }
}

/// Serde module for `[u8; 24]` (nonce) that serializes as base64 and deserializes
/// from either base64 strings or integer arrays.
pub(crate) mod base64_nonce {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{de, Deserializer, Serializer};

    pub(crate) fn serialize<S: Serializer>(
        bytes: &[u8; 24],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<[u8; 24], D::Error> {
        let bytes: Vec<u8> = super::base64_bytes::deserialize(deserializer)?;
        bytes.try_into().map_err(|_| de::Error::custom("expected 24 bytes for nonce"))
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
    DeviceRevoked { device_id: String, new_epoch: i32, remote_wipe: bool },
    /// The epoch was rotated; recover the new epoch key.
    EpochRotated { new_epoch: i32 },
    /// The relay's cleanup auto-revoked an abandoned device and the group now
    /// owes a forced rekey. One active device should run a standalone rekey
    /// to advance the epoch and clear the relay's `needs_rekey` flag.
    RekeyNeeded,
    /// Session token was rotated (handled internally).
    TokenRotated { new_token: String },
    /// WebSocket connection state changed (for UI display).
    ConnectionStateChanged { connected: bool },
}

/// Response from ML-DSA key rotation.
#[derive(Debug, Clone, Deserialize)]
pub struct RotateMlDsaResponse {
    pub ml_dsa_key_generation: u32,
}

/// Response from fetching the latest signed registry artifact.
#[derive(Debug, Clone, Deserialize)]
pub struct SignedRegistryResponse {
    pub registry_version: i64,
    #[serde(with = "base64_bytes")]
    pub artifact_blob: Vec<u8>,
    pub artifact_kind: String,
}

// ── Sub-traits ──
//
// The `SyncRelay` supertrait composes these focused sub-traits so that
// consumers can depend on only the slice of relay functionality they need.

/// Core sync data transport: pull, push, and acknowledge batches.
#[async_trait]
pub trait SyncTransport: Send + Sync {
    /// Pull encrypted batches since a given server sequence number.
    async fn pull_changes(&self, since: i64) -> std::result::Result<PullResponse, RelayError>;

    /// Pull at most `limit` batches since `since`.
    ///
    /// The default implementation ignores `limit` and delegates to
    /// [`pull_changes`], so existing test doubles and minimal transports keep
    /// working unchanged (they return whatever page size the relay defaults to).
    /// Real transports (the HTTP `ServerRelay`) override this to request a
    /// specific page size, letting the client drain a large backlog in far
    /// fewer round-trips by paging to head within one sync cycle.
    ///
    /// [`pull_changes`]: SyncTransport::pull_changes
    async fn pull_changes_paged(
        &self,
        since: i64,
        _limit: i64,
    ) -> std::result::Result<PullResponse, RelayError> {
        self.pull_changes(since).await
    }

    /// Push an encrypted batch. Returns the server-assigned sequence number.
    async fn push_changes(&self, batch: OutgoingBatch) -> std::result::Result<i64, RelayError>;

    /// Acknowledge receipt of server_seq (allows relay to prune).
    async fn ack(&self, server_seq: i64) -> std::result::Result<(), RelayError>;

    /// Recover an expired device session via the signed `/session/refresh`
    /// endpoint. On success the transport rotates its in-memory token and
    /// returns `Ok(Some(token))` so the engine can surface a
    /// `SyncEvent::SessionTokenRotated` for the app to re-persist. Returns
    /// `Ok(None)` when refresh is not available (e.g. an old relay that 404/405s
    /// the route — the caller stays in reconnecting, no worse than today).
    ///
    /// The default impl is a no-op so mock transports and test doubles keep
    /// compiling unchanged; only the HTTP `ServerRelay` performs a real refresh.
    async fn refresh_session(&self) -> std::result::Result<Option<String>, RelayError> {
        Ok(None)
    }
}

/// Device lifecycle: registration, listing, revocation, deregistration, and key rotation.
#[async_trait]
pub trait DeviceRegistry: Send + Sync {
    /// Fetch a single-use registration nonce from the relay.
    ///
    /// The nonce is cryptographically random, short-lived (60s), and consumed
    /// after a single use. The client signs `sync_id || device_id || nonce`
    /// with its hybrid Ed25519 + ML-DSA-65 key as a challenge-response for registration.
    async fn get_registration_nonce(
        &self,
    ) -> std::result::Result<RegistrationNonceResponse, RelayError>;

    /// Register device with relay via challenge-response.
    /// Returns device-scoped session token.
    async fn register_device(
        &self,
        req: RegisterRequest,
    ) -> std::result::Result<RegisterResponse, RelayError>;

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

    /// Self-deregister this device from the sync group.
    async fn deregister(&self) -> std::result::Result<(), RelayError>;

    /// Rotate this device's ML-DSA key on the relay.
    ///
    /// Sends the new public key, the target generation number, and a
    /// continuity proof (cross-signatures between old and new keys) so the
    /// relay can verify ownership continuity before accepting the rotation.
    async fn rotate_ml_dsa(
        &self,
        device_id: &str,
        new_ml_dsa_pk: &[u8],
        new_generation: u32,
        proof: &prism_sync_crypto::pq::continuity_proof::MlDsaContinuityProof,
        signed_registry_snapshot: Option<&[u8]>,
    ) -> std::result::Result<RotateMlDsaResponse, RelayError>;

    /// Fetch the latest signed registry artifact for this sync group.
    ///
    /// Returns the signed snapshot blob that clients can verify independently
    /// of the relay. Returns `Ok(None)` if no artifact exists (e.g., single-
    /// device groups).
    async fn get_signed_registry(
        &self,
    ) -> std::result::Result<Option<SignedRegistryResponse>, RelayError>;

    /// Publish a signed registry snapshot for this sync group.
    ///
    /// The relay stores the opaque artifact; peers verify its signature and
    /// epoch bindings locally before trusting it.
    async fn put_signed_registry(
        &self,
        signed_registry_snapshot: &[u8],
    ) -> std::result::Result<i64, RelayError>;
}

/// Epoch key rotation: posting and retrieving per-device wrapped epoch keys.
#[async_trait]
pub trait EpochManagement: Send + Sync {
    /// Standalone non-revoking epoch rotation.
    ///
    /// Posts per-device wrapped epoch-key artifacts for `epoch`.
    async fn post_rekey_artifacts(
        &self,
        epoch: i32,
        wrapped_keys: HashMap<String, Vec<u8>>,
        signed_registry_snapshot: Option<&[u8]>,
    ) -> std::result::Result<i32, RelayError>;

    /// Fetch this device's wrapped epoch key for a given epoch.
    async fn get_rekey_artifact(
        &self,
        epoch: i32,
        device_id: &str,
    ) -> std::result::Result<Option<Vec<u8>>, RelayError>;
}

/// Snapshot exchange: uploading and downloading full-state snapshots for bootstrap.
#[async_trait]
pub trait SnapshotExchange: Send + Sync {
    /// Download full snapshot for first-sync bootstrap.
    async fn get_snapshot(&self) -> std::result::Result<Option<SnapshotResponse>, RelayError>;

    /// Upload snapshot.
    ///
    /// Optional `ttl_secs` makes the snapshot ephemeral (auto-deleted after TTL).
    /// Optional `for_device_id` targets the snapshot at a specific device
    /// (relay deletes it after that device downloads it). Optional `progress`
    /// callback is invoked as the body streams — `(bytes_sent, bytes_total)`.
    async fn put_snapshot(
        &self,
        epoch: i32,
        server_seq_at: i64,
        envelope_bytes: Vec<u8>,
        ttl_secs: Option<u64>,
        for_device_id: Option<String>,
        uploader_device_id: String,
        progress: Option<SnapshotUploadProgress>,
    ) -> std::result::Result<(), RelayError>;

    /// Explicitly delete the snapshot stored for this sync group.
    ///
    /// Used by the pair-time ACK handshake: the joiner calls this after it
    /// successfully imports the snapshot so the relay stops holding the blob.
    /// `Ok(())` means the snapshot was deleted or never existed;
    /// `Err(RelayError::NotFound)` means the relay confirmed no snapshot row
    /// was present at the moment of the call (the caller may treat this as
    /// idempotent success).
    async fn delete_snapshot(&self) -> std::result::Result<(), RelayError>;
}

/// Outcome of a media upload, distinguishing a committed (servable) blob from a
/// 202 "another writer is mid-upload" response.
///
/// The relay's idempotent upsert returns HTTP 200 when the blob is committed
/// (insert / idempotent / repair / resurrect) and HTTP 202 when a concurrent
/// writer already holds the PENDING reserve. **Only a `committed` outcome is a
/// success the caller may act on** — e.g. the heal responder may broadcast
/// `media_uploaded` only on `committed`; on `in_progress` it must back off and
/// re-check batch-exists (the in-flight writer may still fail, in which case the
/// blob heals on the next demand after the stale-pending reap).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MediaUploadOutcome {
    /// The blob is committed and servable (HTTP 200).
    pub committed: bool,
    /// Another writer holds the reserve; this upload had no effect (HTTP 202).
    pub in_progress: bool,
}

impl MediaUploadOutcome {
    /// The blob is committed and servable.
    pub const COMMITTED: Self = Self { committed: true, in_progress: false };
    /// Another writer holds the reserve; back off, do not treat as success.
    pub const IN_PROGRESS: Self = Self { committed: false, in_progress: true };
}

/// Media upload and download.
#[async_trait]
pub trait MediaRelay: Send + Sync {
    /// Upload an encrypted media blob to the relay.
    ///
    /// `ttl_secs` optionally requests a short per-blob TTL (re-supply / pairing
    /// push); the relay clamps it to `[MEDIA_RESUPPLY_TTL_MIN, retention]`.
    /// `None` ⇒ the relay's default retention. The header is ignored by an old
    /// relay (graceful downgrade to default retention).
    async fn upload_media(
        &self,
        media_id: &str,
        content_hash: &str,
        data: Vec<u8>,
        ttl_secs: Option<u64>,
    ) -> std::result::Result<MediaUploadOutcome, RelayError>;

    /// Upload an encrypted blob, optionally tagged as a **pairing push** so
    /// the relay meters it on the dedicated pairing-push lane (a joiner burst)
    /// instead of the re-supply lane. Only meaningful with a `ttl_secs`.
    ///
    /// The default delegates to [`upload_media`] (ignoring the tag), so mocks
    /// need no change — only the server relay overrides this to set the header.
    /// Override exactly one of the two methods with the real upload; pointing
    /// `upload_media` here without also overriding this recurses forever.
    async fn upload_media_classified(
        &self,
        media_id: &str,
        content_hash: &str,
        data: Vec<u8>,
        ttl_secs: Option<u64>,
        pairing_push: bool,
    ) -> std::result::Result<MediaUploadOutcome, RelayError> {
        let _ = pairing_push;
        self.upload_media(media_id, content_hash, data, ttl_secs).await
    }

    /// Download an encrypted media blob from the relay.
    async fn download_media(&self, media_id: &str) -> std::result::Result<Vec<u8>, RelayError>;

    /// Return the subset of `media_ids` the relay currently holds and can serve
    /// (committed, not deleted, not past TTL) — the batch-exists query. Lets
    /// the heal requester skip blobs the relay already has and the pairing push
    /// skip present ones.
    ///
    /// An old relay without this endpoint returns a transport error (404/405)
    /// rather than an empty list; callers must treat that as "feature
    /// absent ⇒ no-op", never as "all blobs absent".
    async fn batch_exists(
        &self,
        media_ids: &[String],
    ) -> std::result::Result<Vec<String>, RelayError>;

    /// Post one sealed ephemeral message to the relay's device-message mailbox
    /// The relay stamps the authenticated sender; the
    /// envelope's `sender_device_id` is ignored on send. An old relay without
    /// the endpoint returns a transport error (404/405) the caller treats as
    /// "feature absent ⇒ no-op".
    async fn send_ephemeral(
        &self,
        envelope: &crate::ephemeral::EphemeralEnvelope,
    ) -> std::result::Result<(), RelayError>;

    /// Drain this device's pending mailbox: messages addressed to it or
    /// broadcast, not sent by it, not expired, not yet acked by it. Read-only —
    /// the caller decrypts each and then ACKs (a separate call) so a broadcast
    /// stays visible to the other recipients. An old relay returns a transport
    /// error (404/405) ⇒ no-op.
    async fn fetch_pending_ephemeral(
        &self,
    ) -> std::result::Result<Vec<crate::ephemeral::EphemeralEnvelope>, RelayError>;

    /// Acknowledge processed (or skipped/undecryptable) mailbox messages so the
    /// relay stops redelivering them to this device. Per-device — never hides a
    /// broadcast from the other recipients.
    async fn ack_ephemeral(
        &self,
        message_ids: &[String],
    ) -> std::result::Result<(), RelayError>;
}

/// Transport layer for communicating with the relay server.
///
/// Composes all sub-traits ([`SyncTransport`], [`DeviceRegistry`],
/// [`EpochManagement`], [`SnapshotExchange`], [`MediaRelay`]) plus
/// WebSocket lifecycle and group management methods that don't fit
/// a single sub-trait.
///
/// Ships with `ServerRelay` (HTTP + WebSocket). Consumers can mock
/// or replace for testing or alternative transports.
///
/// Ported from Dart `lib/core/sync/sync_relay.dart`.
#[async_trait]
pub trait SyncRelay:
    SyncTransport + DeviceRegistry + EpochManagement + SnapshotExchange + MediaRelay
{
    /// Delete the entire sync group and all data on the relay.
    async fn delete_sync_group(&self) -> std::result::Result<(), RelayError>;

    /// Connect WebSocket for real-time notifications.
    async fn connect_websocket(&self) -> std::result::Result<(), RelayError>;

    /// Disconnect WebSocket.
    async fn disconnect_websocket(&self) -> std::result::Result<(), RelayError>;

    /// Stream of real-time notifications from the relay.
    fn notifications(&self) -> Pin<Box<dyn Stream<Item = SyncNotification> + Send>>;

    /// Dispose of all resources.
    async fn dispose(&self) -> std::result::Result<(), RelayError>;
}
