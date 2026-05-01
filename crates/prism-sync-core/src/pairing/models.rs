use std::collections::BTreeMap;

use prism_sync_crypto::pq::{hybrid_signature_contexts, HybridSignature};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Ed25519 signature length in bytes.
const ED25519_SIG_LEN: usize = 64;

/// Hybrid signature version byte for Phase 5 wire formats.
const HYBRID_SIGNATURE_VERSION_V2: u8 = 0x02;

/// Hybrid signature version byte for Phase 6 V3 labeled WNS wire formats.
const HYBRID_SIGNATURE_VERSION_V3: u8 = 0x03;

/// Sent by the joining device (Device B → Device A) to initiate pairing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingRequest {
    /// Stable, unique identifier for the joining device.
    pub device_id: String,
    /// Ed25519 public key (32 bytes) used for signing.
    pub ed25519_public_key: Vec<u8>,
    /// X25519 public key (32 bytes) used for key exchange.
    pub x25519_public_key: Vec<u8>,
}

impl PairingRequest {}

/// Sent by the inviting device (Device A → Device B) in response to a
/// [`PairingRequest`].
///
/// This struct carries **all** data a joining device needs to enter a sync
/// group: relay coordinates, key material, and a signed device registry.
///
/// # Contract (frozen)
///
/// The fields below form a stable wire contract. Adding new fields is
/// permitted (with `#[serde(default)]`); removing or renaming existing
/// fields is a breaking change.
///
/// # Admission contexts
///
/// A `PairingResponse` is produced in exactly two situations:
///
/// 1. **First-device bootstrap** -- the very first device creates the sync
///    group, self-signs, and builds a registry snapshot containing only
///    itself. [`admission_context`](Self::admission_context) returns
///    `"first_device"`.
///
/// 2. **Existing-group join** -- an already-enrolled device approves a new
///    joiner, signs with its existing device keys, and includes the full
///    set of known devices in the registry snapshot.
///    [`admission_context`](Self::admission_context) returns
///    `"existing_group"`.
#[derive(Clone, Serialize, Deserialize)]
pub struct PairingResponse {
    /// WebSocket URL of the relay server this sync group uses (e.g.
    /// `"wss://relay.example.com"`).
    pub relay_url: String,

    /// Unique identifier for the sync group (UUID-style string).
    pub sync_id: String,

    /// BIP39 12-word mnemonic. Combined with the user's password via
    /// Argon2id to derive the MEK, which in turn unwraps `wrapped_dek`.
    pub mnemonic: String,

    /// DEK wrapped (encrypted) under the MEK using XSalsa20-Poly1305.
    /// Layout: `[24-byte nonce || ciphertext || 16-byte MAC]`.
    pub wrapped_dek: Vec<u8>,

    /// Argon2id salt (typically 32 bytes) used when deriving the MEK from
    /// the password + mnemonic.
    pub salt: Vec<u8>,

    /// Hex-encoded Ed25519 signature over the canonical invitation signing
    /// data produced by [`build_invitation_signing_data`]. 128 hex chars
    /// representing a 64-byte signature. V1 format (legacy). Current V3 uses
    /// hybrid Ed25519 + ML-DSA-65 signatures.
    pub signed_invitation: String,

    /// [`SignedRegistrySnapshot`] in its wire format. V1 legacy format was
    /// `[64-byte Ed25519 signature || canonical JSON]`. Current V3 format is
    /// `[0x03 || HybridSignature || canonical JSON V3]` with domain
    /// `PRISM_SYNC_REGISTRY_V3\x00` and hybrid Ed25519 + ML-DSA-65 signatures.
    /// Use [`SignedRegistrySnapshot::verify_and_decode_hybrid`] to validate and
    /// deserialize.
    pub signed_keyring: Vec<u8>,

    /// Device ID of the inviter, needed to look up its public key for
    /// signature verification of `signed_invitation`.
    pub inviter_device_id: String,

    /// Ed25519 public key of the inviter (32 bytes). Used to verify both
    /// `signed_invitation` and the signature inside `signed_keyring`.
    pub inviter_ed25519_pk: Vec<u8>,

    /// ML-DSA-65 public key of the inviter (1952 bytes). Used together with
    /// `inviter_ed25519_pk` for Phase 5 hybrid verification of
    /// `signed_invitation` and `signed_keyring`.
    #[serde(default)]
    pub inviter_ml_dsa_65_pk: Vec<u8>,

    /// Device ID of the joining device, if the invitation targets a
    /// specific device. `None` for open invitations.
    #[serde(default)]
    pub joiner_device_id: Option<String>,

    /// Current epoch number. `0` means no key rotation has occurred and the
    /// sync key is derived directly from the DEK via HKDF.
    #[serde(default)]
    pub current_epoch: u32,

    /// Current epoch key (32 bytes when `current_epoch > 0`, empty
    /// otherwise). Used as the symmetric key for encrypting sync ops in
    /// the current epoch.
    #[serde(default)]
    pub epoch_key: Vec<u8>,

    /// Optional approver signature over the canonical registry-approval
    /// payload used during existing-group relay admission.
    ///
    /// Present for joiner-initiated approvals produced by an existing group
    /// member. Absent for first-device bootstrap and legacy invitation-only
    /// flows.
    #[serde(default)]
    pub registry_approval_signature: Option<String>,

    /// Optional registration token for self-hosted relays with registration
    /// gating enabled. Carried in the pairing response so that paired
    /// devices automatically receive it.
    #[serde(default)]
    pub registration_token: Option<String>,
}

impl std::fmt::Debug for PairingResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairingResponse")
            .field("relay_url", &self.relay_url)
            .field("sync_id", &self.sync_id)
            .field("mnemonic", &"[REDACTED]")
            .field("wrapped_dek", &format!("[{} bytes]", self.wrapped_dek.len()))
            .field("salt", &format!("[{} bytes]", self.salt.len()))
            .field("inviter_device_id", &self.inviter_device_id)
            .field("joiner_device_id", &self.joiner_device_id)
            .field("current_epoch", &self.current_epoch)
            .field("epoch_key", &format!("[{} bytes]", self.epoch_key.len()))
            .field("registration_token", &self.registration_token.as_ref().map(|_| "[REDACTED]"))
            .finish_non_exhaustive()
    }
}

impl PairingResponse {
    /// Returns the admission context implied by this response.
    ///
    /// Parses the JSON portion of [`signed_keyring`](Self::signed_keyring)
    /// (without verifying the signature) to count registry entries.
    ///
    /// * `"first_device"` -- the snapshot contains exactly one entry whose
    ///   `device_id` matches [`inviter_device_id`](Self::inviter_device_id).
    /// * `"existing_group"` -- all other cases (multiple devices, or a
    ///   single device that does not match the inviter).
    pub fn admission_context(&self) -> &'static str {
        let first_byte = self.signed_keyring.first().copied();
        let json_bytes = if first_byte == Some(HYBRID_SIGNATURE_VERSION_V2)
            || first_byte == Some(HYBRID_SIGNATURE_VERSION_V3)
        {
            // V2/V3 hybrid format: [version][HybridSignature][JSON]
            let remaining = &self.signed_keyring[1..];
            let Ok(signature_len) = HybridSignature::encoded_len(remaining) else {
                return "existing_group";
            };
            if remaining.len() <= signature_len {
                return "existing_group";
            }
            &remaining[signature_len..]
        } else {
            // V1 Ed25519-only format: [64B signature][JSON]
            if self.signed_keyring.len() <= ED25519_SIG_LEN {
                return "existing_group";
            }
            &self.signed_keyring[ED25519_SIG_LEN..]
        };

        // Try V3 wrapper format first, then fall back to bare array (V1/V2 legacy).
        #[derive(serde::Deserialize)]
        struct V3Wrapper {
            entries: Vec<RegistrySnapshotEntry>,
        }
        let entries: Vec<RegistrySnapshotEntry> =
            if let Ok(w) = serde_json::from_slice::<V3Wrapper>(json_bytes) {
                w.entries
            } else if let Ok(e) = serde_json::from_slice::<Vec<RegistrySnapshotEntry>>(json_bytes) {
                e
            } else {
                return "existing_group";
            };
        if entries.len() == 1 && entries[0].device_id == self.inviter_device_id {
            "first_device"
        } else {
            "existing_group"
        }
    }

    /// Validate the epoch/key invariants carried in the pairing response.
    pub fn validate_epoch_fields(&self) -> std::result::Result<(), &'static str> {
        if self.current_epoch > 0 && self.epoch_key.len() != 32 {
            return Err("current_epoch > 0 requires a 32-byte epoch_key");
        }
        if self.current_epoch == 0 && !self.epoch_key.is_empty() {
            return Err("current_epoch == 0 requires an empty epoch_key");
        }
        Ok(())
    }
}

/// Build the canonical bytes that get signed for an invitation.
///
/// Uses a deterministic binary format with domain separation prefix
/// `PRISM_SYNC_INVITE_V1\x00` to prevent signature reuse across protocols.
#[allow(clippy::too_many_arguments)]
pub fn build_invitation_signing_data(
    sync_id: &str,
    relay_url: &str,
    wrapped_dek: &[u8],
    salt: &[u8],
    inviter_device_id: &str,
    inviter_ed25519_pk: &[u8; 32],
    joiner_device_id: Option<&str>,
    current_epoch: u32,
    epoch_key: &[u8],
) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(b"PRISM_SYNC_INVITE_V1\x00");
    write_len_prefixed(&mut data, sync_id.as_bytes());
    write_len_prefixed(&mut data, relay_url.as_bytes());
    data.extend_from_slice(&(wrapped_dek.len() as u32).to_be_bytes());
    data.extend_from_slice(wrapped_dek);
    data.extend_from_slice(&(salt.len() as u32).to_be_bytes());
    data.extend_from_slice(salt);
    write_len_prefixed(&mut data, inviter_device_id.as_bytes());
    data.extend_from_slice(inviter_ed25519_pk);
    if let Some(jid) = joiner_device_id {
        write_len_prefixed(&mut data, jid.as_bytes());
    }
    data.extend_from_slice(&current_epoch.to_be_bytes());
    write_len_prefixed(&mut data, epoch_key);
    data
}

/// Build the canonical bytes that get signed for a hybrid invitation.
///
/// V2 extends the signed payload with the inviter's ML-DSA-65 public key so
/// that the invitation binds the full hybrid device identity.
#[allow(clippy::too_many_arguments)]
pub fn build_invitation_signing_data_v2(
    sync_id: &str,
    relay_url: &str,
    wrapped_dek: &[u8],
    salt: &[u8],
    inviter_device_id: &str,
    inviter_ed25519_pk: &[u8; 32],
    inviter_ml_dsa_65_pk: &[u8],
    joiner_device_id: Option<&str>,
    current_epoch: u32,
    epoch_key: &[u8],
) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(b"PRISM_SYNC_INVITATION_V2\x00");
    write_len_prefixed(&mut data, sync_id.as_bytes());
    write_len_prefixed(&mut data, relay_url.as_bytes());
    data.extend_from_slice(&(wrapped_dek.len() as u32).to_be_bytes());
    data.extend_from_slice(wrapped_dek);
    data.extend_from_slice(&(salt.len() as u32).to_be_bytes());
    data.extend_from_slice(salt);
    write_len_prefixed(&mut data, inviter_device_id.as_bytes());
    data.extend_from_slice(inviter_ed25519_pk);
    write_len_prefixed(&mut data, inviter_ml_dsa_65_pk);
    if let Some(jid) = joiner_device_id {
        write_len_prefixed(&mut data, jid.as_bytes());
    }
    data.extend_from_slice(&current_epoch.to_be_bytes());
    write_len_prefixed(&mut data, epoch_key);
    data
}

/// Build the canonical bytes that get signed for an existing-group
/// registry approval.
pub fn build_registry_approval_signing_data(
    sync_id: &str,
    approver_device_id: &str,
    signed_registry_snapshot: &[u8],
) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(b"PRISM_SYNC_REGISTRY_APPROVAL_V1\x00");
    write_len_prefixed(&mut data, sync_id.as_bytes());
    write_len_prefixed(&mut data, approver_device_id.as_bytes());
    write_len_prefixed(&mut data, signed_registry_snapshot);
    data
}

/// Build the canonical bytes that get signed for a hybrid existing-group
/// registry approval.
pub fn build_registry_approval_signing_data_v2(
    sync_id: &str,
    approver_device_id: &str,
    signed_registry_snapshot: &[u8],
) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(b"PRISM_SYNC_REGISTRY_APPROVAL_V2\x00");
    write_len_prefixed(&mut data, sync_id.as_bytes());
    write_len_prefixed(&mut data, approver_device_id.as_bytes());
    write_len_prefixed(&mut data, signed_registry_snapshot);
    data
}

fn write_len_prefixed(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

/// Locally-held credentials for a sync group after creation.
pub struct SyncGroupCredentials {
    pub sync_id: String,
    pub mnemonic: String,
    pub wrapped_dek: Vec<u8>,
    pub salt: Vec<u8>,
}

// ── Typed Signed Registry Snapshot ──────────────────────────────────────────

/// Domain separation prefix for registry snapshot signatures.
const REGISTRY_SNAPSHOT_DOMAIN: &[u8] = b"PRISM_SYNC_REGISTRY_V1\x00";
#[allow(dead_code)]
const REGISTRY_SNAPSHOT_DOMAIN_V2: &[u8] = b"PRISM_SYNC_REGISTRY_V2\x00";
const REGISTRY_SNAPSHOT_DOMAIN_V3: &[u8] = b"PRISM_SYNC_REGISTRY_V3\x00";

/// Well-known AAD used by [`compute_epoch_key_hash`] to bind the per-epoch
/// commitment under a domain that is distinct from any sync-ciphertext AAD.
///
/// Changing this byte string invalidates all previously-computed hashes and
/// therefore breaks signed-registry verification — only bump it together with
/// a registry version bump.
const REGISTRY_EPOCH_HASH_AAD: &[u8] = b"prism_registry_epoch_hash_v1";

/// First `registry_version` value for which `current_epoch` and
/// `epoch_key_hashes` are required to be populated.
///
/// Snapshots with `registry_version >= SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING`
/// MUST carry a non-empty `epoch_key_hashes` map (covering at least the
/// signed `current_epoch`). Older snapshots are accepted under a tolerance
/// window with a logged deprecation warning and will become a hard error in
/// a future release once all peers have rolled forward.
///
/// Choice of value: pre-existing in-tree producers under
/// `crates/prism-sync-core/src/` always passed `registry_version: 0`, so the
/// first version that requires the new fields is `1`.
pub const SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING: i64 = 1;

/// Compute the domain-separated epoch-key commitment used inside
/// [`SignedRegistrySnapshot::epoch_key_hashes`].
///
/// Defined as `SHA-256(wrap(epoch_key, REGISTRY_EPOCH_HASH_AAD))` where
/// `wrap` is XChaCha20-Poly1305 with the epoch key as the AEAD key, the
/// well-known AAD as the AAD, an all-zero nonce, and empty plaintext.
///
/// The all-zero nonce is safe here because the output is never decrypted —
/// it is hashed into a commitment. The AAD makes the commitment unforgeable
/// without the epoch key, which is the property we need for the signed
/// registry to anchor per-epoch state.
pub fn compute_epoch_key_hash(epoch_key: &[u8; 32]) -> [u8; 32] {
    let mac = prism_sync_crypto::aead::xchacha_aead_mac_zero_nonce(
        epoch_key.as_slice(),
        REGISTRY_EPOCH_HASH_AAD,
    )
    .expect("xchacha_aead_mac_zero_nonce with 32-byte key cannot fail");
    let digest = Sha256::digest(&mac);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// A single device entry inside a [`SignedRegistrySnapshot`].
///
/// Mirrors the fields of [`crate::storage::DeviceRecord`] that are relevant
/// for trust establishment during pairing. Timestamps are intentionally
/// excluded — they are local metadata, not part of the verified registry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistrySnapshotEntry {
    pub sync_id: String,
    pub device_id: String,
    pub ed25519_public_key: Vec<u8>,
    pub x25519_public_key: Vec<u8>,
    #[serde(default)]
    pub ml_dsa_65_public_key: Vec<u8>,
    #[serde(default)]
    pub ml_kem_768_public_key: Vec<u8>,
    #[serde(default)]
    pub x_wing_public_key: Vec<u8>,
    pub status: String,
    #[serde(default)]
    pub ml_dsa_key_generation: u32,
}

/// A signed, typed snapshot of the device registry.
///
/// Produced by the inviting device and included (serialized) in
/// [`PairingResponse::signed_keyring`]. The joining device verifies the
/// signature before importing the entries into its local registry.
///
/// Wire format (V1/V2, legacy): `[64-byte Ed25519 signature || canonical JSON]`
/// covering `PRISM_SYNC_REGISTRY_V1\x00 || canonical JSON`. V3 uses a hybrid
/// Ed25519 + ML-DSA-65 signature bound into the V3 signed payload format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedRegistrySnapshot {
    pub entries: Vec<RegistrySnapshotEntry>,
    /// Registry version bound into the V3 signed payload.
    ///
    /// For snapshots decoded from V1/V2 wire format, this defaults to `0`.
    #[serde(default)]
    pub registry_version: i64,
    /// The current epoch the producing device believed it was in when the
    /// snapshot was signed.
    ///
    /// Cryptographically anchors registry state to the epoch ratchet so that
    /// a malicious relay cannot fabricate epoch state during pairing
    /// reconciliation. See [`SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING`].
    #[serde(default)]
    pub current_epoch: u32,
    /// Per-epoch commitments produced via [`compute_epoch_key_hash`].
    ///
    /// Keys are epoch numbers. Values are 32-byte commitments unforgeable
    /// without knowledge of the underlying epoch key. A receiver that holds
    /// the same epoch key locally can recompute the commitment and verify
    /// that the signed registry agrees with its local epoch ratchet.
    ///
    /// Required for `registry_version >= SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING`.
    #[serde(default)]
    pub epoch_key_hashes: BTreeMap<u32, [u8; 32]>,
}

impl SignedRegistrySnapshot {
    /// Build a snapshot from a list of device entries with a registry version.
    ///
    /// The new `current_epoch` and `epoch_key_hashes` fields default to `0`
    /// and empty respectively. Use [`Self::new_with_epoch_binding`] when
    /// producing a snapshot at or above
    /// [`SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING`].
    pub fn new(entries: Vec<RegistrySnapshotEntry>, registry_version: i64) -> Self {
        Self { entries, registry_version, current_epoch: 0, epoch_key_hashes: BTreeMap::new() }
    }

    /// Build a snapshot that cryptographically binds the current epoch and
    /// per-epoch key commitments into the signed payload.
    ///
    /// `epoch_key_hashes` must contain at least an entry for `current_epoch`.
    /// Callers typically populate it with every epoch the local key
    /// hierarchy holds keys for (via [`compute_epoch_key_hash`]).
    pub fn new_with_epoch_binding(
        entries: Vec<RegistrySnapshotEntry>,
        registry_version: i64,
        current_epoch: u32,
        epoch_key_hashes: BTreeMap<u32, [u8; 32]>,
    ) -> Self {
        Self { entries, registry_version, current_epoch, epoch_key_hashes }
    }

    /// Canonical JSON encoding used for both signing and wire transport.
    ///
    /// Entries are sorted by `device_id` to ensure deterministic output
    /// regardless of insertion order.
    pub fn canonical_json(&self) -> Vec<u8> {
        let mut sorted = self.entries.clone();
        sorted.sort_by(|a, b| a.device_id.cmp(&b.device_id));
        serde_json::to_vec(&sorted).unwrap_or_default()
    }

    /// Build the data that gets signed: domain prefix + canonical JSON.
    fn signing_data(&self) -> Vec<u8> {
        let json = self.canonical_json();
        let mut data = Vec::with_capacity(REGISTRY_SNAPSHOT_DOMAIN.len() + json.len());
        data.extend_from_slice(REGISTRY_SNAPSHOT_DOMAIN);
        data.extend_from_slice(&json);
        data
    }

    /// Build the Phase 5 hybrid signing payload: versioned domain + canonical JSON.
    #[allow(dead_code)]
    fn signing_data_v2(&self) -> Vec<u8> {
        let json = self.canonical_json();
        let mut data = Vec::with_capacity(REGISTRY_SNAPSHOT_DOMAIN_V2.len() + json.len());
        data.extend_from_slice(REGISTRY_SNAPSHOT_DOMAIN_V2);
        data.extend_from_slice(&json);
        data
    }

    /// Canonical JSON encoding for V3 wire format.
    ///
    /// Produces a wrapper object
    /// `{ "registry_version": i64, "current_epoch": u32, "epoch_key_hashes": {epoch: hex32}, "entries": [...] }`
    /// with entries sorted by `device_id` and epoch_key_hashes sorted by
    /// epoch (`BTreeMap`) for deterministic output. The new
    /// `current_epoch`/`epoch_key_hashes` fields are skipped when at default
    /// values to preserve byte-for-byte compatibility with legacy snapshots
    /// (registry_version < SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING).
    pub fn canonical_json_v3(&self) -> Vec<u8> {
        let mut sorted = self.entries.clone();
        sorted.sort_by(|a, b| a.device_id.cmp(&b.device_id));

        // Skip current_epoch+epoch_key_hashes from JSON output entirely when
        // they're at defaults AND registry_version is below the binding
        // threshold. Above the threshold, always include both fields even if
        // empty so verification can detect tampered "zeroing" attacks.
        let omit_epoch_binding = self.registry_version
            < SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING
            && self.current_epoch == 0
            && self.epoch_key_hashes.is_empty();

        if omit_epoch_binding {
            #[derive(serde::Serialize)]
            struct LegacyWrapper<'a> {
                registry_version: i64,
                entries: &'a [RegistrySnapshotEntry],
            }
            serde_json::to_vec(&LegacyWrapper {
                registry_version: self.registry_version,
                entries: &sorted,
            })
            .unwrap_or_default()
        } else {
            #[derive(serde::Serialize)]
            struct Wrapper<'a> {
                registry_version: i64,
                current_epoch: u32,
                epoch_key_hashes: &'a BTreeMap<u32, [u8; 32]>,
                entries: &'a [RegistrySnapshotEntry],
            }
            serde_json::to_vec(&Wrapper {
                registry_version: self.registry_version,
                current_epoch: self.current_epoch,
                epoch_key_hashes: &self.epoch_key_hashes,
                entries: &sorted,
            })
            .unwrap_or_default()
        }
    }

    /// Build the V3 signing payload: `PRISM_SYNC_REGISTRY_V3\x00 || canonical_json_v3()`.
    fn signing_data_v3(&self) -> Vec<u8> {
        let json = self.canonical_json_v3();
        let mut data = Vec::with_capacity(REGISTRY_SNAPSHOT_DOMAIN_V3.len() + json.len());
        data.extend_from_slice(REGISTRY_SNAPSHOT_DOMAIN_V3);
        data.extend_from_slice(&json);
        data
    }

    /// Sign the snapshot with the given Ed25519 signing key.
    ///
    /// Returns the wire format: `[64-byte signature || canonical JSON]`.
    pub fn sign(&self, signing_key: &prism_sync_crypto::DeviceSigningKey) -> Vec<u8> {
        let data = self.signing_data();
        let signature = signing_key.sign(&data);
        let json = self.canonical_json();
        [signature, json].concat()
    }

    /// Sign the snapshot with both Ed25519 and ML-DSA-65 using V3 labeled WNS.
    ///
    /// Returns the wire format:
    /// `[0x03][HybridSignature::to_bytes()][canonical JSON V3]`.
    ///
    /// The signed payload uses the `PRISM_SYNC_REGISTRY_V3` domain and
    /// a wrapper object `{ "registry_version": i64, "entries": [...] }` so
    /// that the registry version is cryptographically bound to the snapshot.
    pub fn sign_hybrid(
        &self,
        signing_key: &prism_sync_crypto::DeviceSigningKey,
        pq_signing_key: &prism_sync_crypto::DevicePqSigningKey,
    ) -> Vec<u8> {
        let data = self.signing_data_v3();
        let m_prime = prism_sync_crypto::pq::build_hybrid_message_representative(
            hybrid_signature_contexts::REGISTRY_SNAPSHOT,
            &data,
        )
        .expect("hardcoded registry snapshot context should be <= 255 bytes");
        let hybrid_sig = HybridSignature {
            ed25519_sig: signing_key.sign(&m_prime),
            ml_dsa_65_sig: pq_signing_key.sign(&m_prime),
        };
        let json = self.canonical_json_v3();
        let mut out = Vec::with_capacity(1 + hybrid_sig.to_bytes().len() + json.len());
        out.push(HYBRID_SIGNATURE_VERSION_V3);
        out.extend_from_slice(&hybrid_sig.to_bytes());
        out.extend_from_slice(&json);
        out
    }

    /// Verify and decode a signed snapshot from its wire format.
    ///
    /// Returns the decoded snapshot if the signature is valid, or an error
    /// describing the failure.
    pub fn verify_and_decode(
        signed_bytes: &[u8],
        expected_signer_pk: &[u8; 32],
    ) -> std::result::Result<Self, String> {
        if signed_bytes.len() < ED25519_SIG_LEN {
            return Err("signed snapshot too short".into());
        }

        let (sig_bytes, json_bytes) = signed_bytes.split_at(ED25519_SIG_LEN);

        // Reconstruct signing data with domain prefix
        let mut signing_data =
            Vec::with_capacity(REGISTRY_SNAPSHOT_DOMAIN.len() + json_bytes.len());
        signing_data.extend_from_slice(REGISTRY_SNAPSHOT_DOMAIN);
        signing_data.extend_from_slice(json_bytes);

        prism_sync_crypto::DeviceSigningKey::verify(expected_signer_pk, &signing_data, sig_bytes)
            .map_err(|e| format!("registry snapshot signature invalid: {e}"))?;

        let entries: Vec<RegistrySnapshotEntry> = serde_json::from_slice(json_bytes)
            .map_err(|e| format!("registry snapshot JSON invalid: {e}"))?;

        Ok(Self {
            entries,
            registry_version: 0,
            current_epoch: 0,
            epoch_key_hashes: BTreeMap::new(),
        })
    }

    /// Verify and decode a hybrid-signed snapshot from its wire format.
    ///
    /// Production decoding accepts only the Phase 6 V3 labeled-WNS wire format
    /// with the `PRISM_SYNC_REGISTRY_V3` signing domain and a wrapper JSON
    /// object `{ "registry_version": i64, "entries": [...] }`.
    pub fn verify_and_decode_hybrid(
        signed_bytes: &[u8],
        expected_ed25519_pk: &[u8; 32],
        expected_ml_dsa_pk: &[u8],
    ) -> std::result::Result<Self, String> {
        let Some((&version, remaining)) = signed_bytes.split_first() else {
            return Err("signed snapshot too short".into());
        };
        if version != HYBRID_SIGNATURE_VERSION_V3 {
            return Err("signed snapshot missing V3 hybrid signature version".into());
        }

        let signature_len = HybridSignature::encoded_len(remaining)
            .map_err(|e| format!("registry snapshot signature invalid: {e}"))?;
        if remaining.len() <= signature_len {
            return Err("signed snapshot missing JSON payload".into());
        }
        let signature = HybridSignature::from_bytes(&remaining[..signature_len])
            .map_err(|e| format!("registry snapshot signature invalid: {e}"))?;
        let json_bytes = &remaining[signature_len..];

        let mut signing_data =
            Vec::with_capacity(REGISTRY_SNAPSHOT_DOMAIN_V3.len() + json_bytes.len());
        signing_data.extend_from_slice(REGISTRY_SNAPSHOT_DOMAIN_V3);
        signing_data.extend_from_slice(json_bytes);

        signature
            .verify_v3(
                &signing_data,
                hybrid_signature_contexts::REGISTRY_SNAPSHOT,
                expected_ed25519_pk,
                expected_ml_dsa_pk,
            )
            .map_err(|e| format!("registry snapshot signature invalid: {e}"))?;

        #[derive(serde::Deserialize)]
        struct Wrapper {
            registry_version: i64,
            #[serde(default)]
            current_epoch: u32,
            #[serde(default)]
            epoch_key_hashes: BTreeMap<u32, [u8; 32]>,
            entries: Vec<RegistrySnapshotEntry>,
        }

        let wrapper: Wrapper = serde_json::from_slice(json_bytes)
            .map_err(|e| format!("registry snapshot JSON invalid: {e}"))?;

        // Enforce that snapshots claiming the new registry-version floor
        // actually carry the binding fields, and that the binding map covers
        // the signed current_epoch. Older snapshots are accepted with a
        // logged deprecation warning so we can ship the wire change before
        // every producer in the network has rolled forward; this tolerance
        // window is intended to close in a follow-up release.
        if wrapper.registry_version >= SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING {
            if wrapper.epoch_key_hashes.is_empty() {
                return Err(format!(
                    "registry_version {} requires non-empty epoch_key_hashes",
                    wrapper.registry_version
                ));
            }
            if !wrapper.epoch_key_hashes.contains_key(&wrapper.current_epoch) {
                return Err(format!(
                    "registry epoch_key_hashes missing entry for current_epoch {}",
                    wrapper.current_epoch
                ));
            }
        } else {
            tracing::warn!(
                registry_version = wrapper.registry_version,
                "deprecated: signed registry snapshot lacks current_epoch / epoch_key_hashes binding (registry_version < {}); legacy tolerance is temporary and will be removed in a future release",
                SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING
            );
        }

        Ok(Self {
            entries: wrapper.entries,
            registry_version: wrapper.registry_version,
            current_epoch: wrapper.current_epoch,
            epoch_key_hashes: wrapper.epoch_key_hashes,
        })
    }

    /// Convert snapshot entries to [`crate::storage::DeviceRecord`]s for import.
    pub fn to_device_records(&self) -> Vec<crate::storage::DeviceRecord> {
        self.entries
            .iter()
            .map(|e| crate::storage::DeviceRecord {
                sync_id: e.sync_id.clone(),
                device_id: e.device_id.clone(),
                ed25519_public_key: e.ed25519_public_key.clone(),
                x25519_public_key: e.x25519_public_key.clone(),
                ml_dsa_65_public_key: e.ml_dsa_65_public_key.clone(),
                ml_kem_768_public_key: e.ml_kem_768_public_key.clone(),
                x_wing_public_key: e.x_wing_public_key.clone(),
                status: e.status.clone(),
                registered_at: chrono::Utc::now(),
                revoked_at: None,
                ml_dsa_key_generation: e.ml_dsa_key_generation,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sample response with a valid BIP39 mnemonic and realistic crypto sizes.
    fn sample_response() -> PairingResponse {
        let mnemonic = prism_sync_crypto::mnemonic::generate();
        PairingResponse {
            relay_url: "wss://relay.example.com".into(),
            sync_id: "test-sync-id-123".into(),
            mnemonic,
            wrapped_dek: vec![0x42; 72], // 24B nonce + 32B ct + 16B MAC
            salt: vec![0x13; 32],        // Argon2id salt
            signed_invitation: hex::encode([0xBB; 64]), // 64-byte Ed25519 sig as hex
            signed_keyring: vec![0xCC; 200], // sig + keyring JSON
            inviter_device_id: "device-001".into(),
            inviter_ed25519_pk: vec![0xAA; 32],
            inviter_ml_dsa_65_pk: Vec::new(),
            joiner_device_id: Some("abcdef123456".to_string()),
            current_epoch: 2,
            epoch_key: vec![0xBB; 32],
            registry_approval_signature: Some(hex::encode([0xDD; 64])),
            registration_token: None,
        }
    }

    #[test]
    fn pairing_request_serialization_roundtrip() {
        let req = PairingRequest {
            device_id: "device-abc".into(),
            ed25519_public_key: vec![1u8; 32],
            x25519_public_key: vec![2u8; 32],
        };
        let json = serde_json::to_vec(&req).unwrap();
        let decoded: PairingRequest = serde_json::from_slice(&json).unwrap();
        assert_eq!(decoded.device_id, req.device_id);
        assert_eq!(decoded.ed25519_public_key, req.ed25519_public_key);
        assert_eq!(decoded.x25519_public_key, req.x25519_public_key);
    }

    #[test]
    fn pairing_response_serialization_roundtrip() {
        let resp = sample_response();
        let json = serde_json::to_vec(&resp).unwrap();
        let decoded: PairingResponse = serde_json::from_slice(&json).unwrap();
        assert_eq!(decoded.sync_id, resp.sync_id);
        assert_eq!(decoded.relay_url, resp.relay_url);
        assert_eq!(decoded.mnemonic, resp.mnemonic);
        assert_eq!(decoded.wrapped_dek, resp.wrapped_dek);
        assert_eq!(decoded.salt, resp.salt);
        assert_eq!(decoded.signed_invitation, resp.signed_invitation);
        assert_eq!(decoded.signed_keyring, resp.signed_keyring);
        assert_eq!(decoded.registry_approval_signature, resp.registry_approval_signature);
    }

    #[test]
    fn epoch_field_validation_rejects_mismatches() {
        let mut resp = sample_response();
        resp.current_epoch = 1;
        resp.epoch_key.clear();
        assert!(resp.validate_epoch_fields().is_err());

        let mut resp = sample_response();
        resp.current_epoch = 0;
        assert!(resp.validate_epoch_fields().is_err());
    }

    // ── admission_context tests ──

    #[test]
    fn admission_context_first_device() {
        let (key, _pk) = make_signing_key();
        let snapshot = SignedRegistrySnapshot::new(
            vec![RegistrySnapshotEntry {
                sync_id: "sync-1".into(),
                device_id: "device-001".into(),
                ed25519_public_key: vec![0xAA; 32],
                x25519_public_key: vec![0xBB; 32],
                ml_dsa_65_public_key: Vec::new(),
                ml_kem_768_public_key: Vec::new(),
                x_wing_public_key: Vec::new(),
                status: "active".into(),
                ml_dsa_key_generation: 0,
            }],
            0,
        );
        let mut resp = sample_response();
        resp.inviter_device_id = "device-001".into();
        resp.signed_keyring = snapshot.sign(&key);
        assert_eq!(resp.admission_context(), "first_device");
    }

    #[test]
    fn admission_context_existing_group() {
        let (key, _pk) = make_signing_key();
        let snapshot = SignedRegistrySnapshot::new(
            vec![
                RegistrySnapshotEntry {
                    sync_id: "sync-1".into(),
                    device_id: "device-001".into(),
                    ed25519_public_key: vec![0xAA; 32],
                    x25519_public_key: vec![0xBB; 32],
                    ml_dsa_65_public_key: Vec::new(),
                    ml_kem_768_public_key: Vec::new(),
                    x_wing_public_key: Vec::new(),
                    status: "active".into(),
                    ml_dsa_key_generation: 0,
                },
                RegistrySnapshotEntry {
                    sync_id: "sync-1".into(),
                    device_id: "device-002".into(),
                    ed25519_public_key: vec![0xCC; 32],
                    x25519_public_key: vec![0xDD; 32],
                    ml_dsa_65_public_key: Vec::new(),
                    ml_kem_768_public_key: Vec::new(),
                    x_wing_public_key: Vec::new(),
                    status: "active".into(),
                    ml_dsa_key_generation: 0,
                },
            ],
            0,
        );
        let mut resp = sample_response();
        resp.inviter_device_id = "device-001".into();
        resp.signed_keyring = snapshot.sign(&key);
        assert_eq!(resp.admission_context(), "existing_group");
    }

    #[test]
    fn admission_context_single_entry_different_inviter() {
        let (key, _pk) = make_signing_key();
        let snapshot = SignedRegistrySnapshot::new(
            vec![RegistrySnapshotEntry {
                sync_id: "sync-1".into(),
                device_id: "device-999".into(),
                ed25519_public_key: vec![0xAA; 32],
                x25519_public_key: vec![0xBB; 32],
                ml_dsa_65_public_key: Vec::new(),
                ml_kem_768_public_key: Vec::new(),
                x_wing_public_key: Vec::new(),
                status: "active".into(),
                ml_dsa_key_generation: 0,
            }],
            0,
        );
        let mut resp = sample_response();
        resp.inviter_device_id = "device-001".into();
        resp.signed_keyring = snapshot.sign(&key);
        assert_eq!(resp.admission_context(), "existing_group");
    }

    #[test]
    fn admission_context_unparseable_keyring() {
        let mut resp = sample_response();
        resp.signed_keyring = vec![0xFF; 100]; // garbage
        assert_eq!(resp.admission_context(), "existing_group");
    }

    #[test]
    fn admission_context_oversized_hybrid_signature_len_returns_existing_group() {
        let mut resp = sample_response();
        resp.signed_keyring = vec![HYBRID_SIGNATURE_VERSION_V3];
        resp.signed_keyring.extend_from_slice(&u32::MAX.to_le_bytes());

        let result = std::panic::catch_unwind(|| resp.admission_context());
        assert!(result.is_ok(), "oversized hybrid signature length should not panic");
        assert_eq!(result.unwrap(), "existing_group");
    }

    // ── SignedRegistrySnapshot tests ──

    fn make_signing_key() -> (prism_sync_crypto::DeviceSigningKey, [u8; 32]) {
        let secret = prism_sync_crypto::DeviceSecret::generate();
        let key = secret.ed25519_keypair("test-device").unwrap();
        let pk = key.public_key_bytes();
        (key, pk)
    }

    fn make_pq_signing_key() -> (prism_sync_crypto::DevicePqSigningKey, Vec<u8>) {
        let secret = prism_sync_crypto::DeviceSecret::generate();
        let key = secret.ml_dsa_65_keypair("test-device").unwrap();
        let pk = key.public_key_bytes();
        (key, pk)
    }

    fn sample_snapshot() -> SignedRegistrySnapshot {
        SignedRegistrySnapshot::new(
            vec![
                RegistrySnapshotEntry {
                    sync_id: "sync-1".into(),
                    device_id: "dev-a".into(),
                    ed25519_public_key: vec![1u8; 32],
                    x25519_public_key: vec![2u8; 32],
                    ml_dsa_65_public_key: Vec::new(),
                    ml_kem_768_public_key: Vec::new(),
                    x_wing_public_key: Vec::new(),
                    status: "active".into(),
                    ml_dsa_key_generation: 0,
                },
                RegistrySnapshotEntry {
                    sync_id: "sync-1".into(),
                    device_id: "dev-b".into(),
                    ed25519_public_key: vec![3u8; 32],
                    x25519_public_key: vec![4u8; 32],
                    ml_dsa_65_public_key: Vec::new(),
                    ml_kem_768_public_key: Vec::new(),
                    x_wing_public_key: Vec::new(),
                    status: "active".into(),
                    ml_dsa_key_generation: 0,
                },
            ],
            0,
        )
    }

    #[test]
    fn snapshot_sign_and_verify_roundtrip() {
        let (key, pk) = make_signing_key();
        let snapshot = sample_snapshot();
        let signed = snapshot.sign(&key);
        let decoded = SignedRegistrySnapshot::verify_and_decode(&signed, &pk).unwrap();
        assert_eq!(decoded.entries.len(), 2);
        // Entries are sorted by device_id in canonical form
        assert_eq!(decoded.entries[0].device_id, "dev-a");
        assert_eq!(decoded.entries[1].device_id, "dev-b");
    }

    #[test]
    fn snapshot_hybrid_sign_and_verify_roundtrip() {
        let secret = prism_sync_crypto::DeviceSecret::generate();
        let signing_key = secret.ed25519_keypair("test-device").unwrap();
        let ed_pk = signing_key.public_key_bytes();
        let pq_signing_key = secret.ml_dsa_65_keypair("test-device").unwrap();
        let pq_pk = pq_signing_key.public_key_bytes();
        let snapshot = sample_snapshot();

        let signed = snapshot.sign_hybrid(&signing_key, &pq_signing_key);
        let decoded =
            SignedRegistrySnapshot::verify_and_decode_hybrid(&signed, &ed_pk, &pq_pk).unwrap();

        assert_eq!(decoded.entries.len(), 2);
        assert_eq!(decoded.entries[0].device_id, "dev-a");
        assert_eq!(decoded.entries[1].device_id, "dev-b");
    }

    #[test]
    fn snapshot_hybrid_rejects_version_floor_without_epoch_hashes() {
        let secret = prism_sync_crypto::DeviceSecret::generate();
        let signing_key = secret.ed25519_keypair("test-device").unwrap();
        let ed_pk = signing_key.public_key_bytes();
        let pq_signing_key = secret.ml_dsa_65_keypair("test-device").unwrap();
        let pq_pk = pq_signing_key.public_key_bytes();
        let entries = sample_snapshot().entries;
        let snapshot =
            SignedRegistrySnapshot::new(entries, SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING);

        let signed = snapshot.sign_hybrid(&signing_key, &pq_signing_key);
        let err =
            SignedRegistrySnapshot::verify_and_decode_hybrid(&signed, &ed_pk, &pq_pk).unwrap_err();

        assert!(err.contains("requires non-empty epoch_key_hashes"), "unexpected error: {err}");
    }

    #[test]
    fn snapshot_hybrid_rejects_missing_current_epoch_hash() {
        let secret = prism_sync_crypto::DeviceSecret::generate();
        let signing_key = secret.ed25519_keypair("test-device").unwrap();
        let ed_pk = signing_key.public_key_bytes();
        let pq_signing_key = secret.ml_dsa_65_keypair("test-device").unwrap();
        let pq_pk = pq_signing_key.public_key_bytes();
        let mut epoch_key_hashes = BTreeMap::new();
        epoch_key_hashes.insert(0, compute_epoch_key_hash(&[0x42; 32]));
        let entries = sample_snapshot().entries;
        let snapshot = SignedRegistrySnapshot::new_with_epoch_binding(
            entries,
            SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING,
            1,
            epoch_key_hashes,
        );

        let signed = snapshot.sign_hybrid(&signing_key, &pq_signing_key);
        let err =
            SignedRegistrySnapshot::verify_and_decode_hybrid(&signed, &ed_pk, &pq_pk).unwrap_err();

        assert!(err.contains("missing entry for current_epoch 1"), "unexpected error: {err}");
    }

    #[test]
    fn snapshot_hybrid_accepts_epoch_binding() {
        let secret = prism_sync_crypto::DeviceSecret::generate();
        let signing_key = secret.ed25519_keypair("test-device").unwrap();
        let ed_pk = signing_key.public_key_bytes();
        let pq_signing_key = secret.ml_dsa_65_keypair("test-device").unwrap();
        let pq_pk = pq_signing_key.public_key_bytes();
        let mut epoch_key_hashes = BTreeMap::new();
        let hash = compute_epoch_key_hash(&[0x42; 32]);
        epoch_key_hashes.insert(0, hash);
        let entries = sample_snapshot().entries;
        let snapshot = SignedRegistrySnapshot::new_with_epoch_binding(
            entries,
            SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING,
            0,
            epoch_key_hashes,
        );

        let signed = snapshot.sign_hybrid(&signing_key, &pq_signing_key);
        let decoded =
            SignedRegistrySnapshot::verify_and_decode_hybrid(&signed, &ed_pk, &pq_pk).unwrap();

        assert_eq!(decoded.current_epoch, 0);
        assert_eq!(decoded.epoch_key_hashes.get(&0), Some(&hash));
    }

    #[test]
    fn snapshot_canonical_json_is_deterministic() {
        // Order of entries should not matter — canonical form sorts by device_id
        let snapshot_ab = SignedRegistrySnapshot::new(
            vec![
                RegistrySnapshotEntry {
                    sync_id: "s".into(),
                    device_id: "b".into(),
                    ed25519_public_key: vec![2u8; 32],
                    x25519_public_key: vec![2u8; 32],
                    ml_dsa_65_public_key: Vec::new(),
                    ml_kem_768_public_key: Vec::new(),
                    x_wing_public_key: Vec::new(),
                    status: "active".into(),
                    ml_dsa_key_generation: 0,
                },
                RegistrySnapshotEntry {
                    sync_id: "s".into(),
                    device_id: "a".into(),
                    ed25519_public_key: vec![1u8; 32],
                    x25519_public_key: vec![1u8; 32],
                    ml_dsa_65_public_key: Vec::new(),
                    ml_kem_768_public_key: Vec::new(),
                    x_wing_public_key: Vec::new(),
                    status: "active".into(),
                    ml_dsa_key_generation: 0,
                },
            ],
            0,
        );
        let snapshot_ba = SignedRegistrySnapshot::new(
            vec![
                RegistrySnapshotEntry {
                    sync_id: "s".into(),
                    device_id: "a".into(),
                    ed25519_public_key: vec![1u8; 32],
                    x25519_public_key: vec![1u8; 32],
                    ml_dsa_65_public_key: Vec::new(),
                    ml_kem_768_public_key: Vec::new(),
                    x_wing_public_key: Vec::new(),
                    status: "active".into(),
                    ml_dsa_key_generation: 0,
                },
                RegistrySnapshotEntry {
                    sync_id: "s".into(),
                    device_id: "b".into(),
                    ed25519_public_key: vec![2u8; 32],
                    x25519_public_key: vec![2u8; 32],
                    ml_dsa_65_public_key: Vec::new(),
                    ml_kem_768_public_key: Vec::new(),
                    x_wing_public_key: Vec::new(),
                    status: "active".into(),
                    ml_dsa_key_generation: 0,
                },
            ],
            0,
        );
        assert_eq!(snapshot_ab.canonical_json(), snapshot_ba.canonical_json());
    }

    #[test]
    fn snapshot_rejects_wrong_signer() {
        let (key, _pk) = make_signing_key();
        let (_other_key, other_pk) = make_signing_key();
        let snapshot = sample_snapshot();
        let signed = snapshot.sign(&key);

        let err = SignedRegistrySnapshot::verify_and_decode(&signed, &other_pk).unwrap_err();
        assert!(err.contains("signature invalid"), "expected signature error, got: {err}");
    }

    #[test]
    fn snapshot_rejects_tampered_json() {
        let (key, pk) = make_signing_key();
        let snapshot = sample_snapshot();
        let mut signed = snapshot.sign(&key);
        // Tamper with the JSON portion (after 64-byte signature)
        if signed.len() > 65 {
            signed[65] ^= 0xFF;
        }

        let err = SignedRegistrySnapshot::verify_and_decode(&signed, &pk).unwrap_err();
        // Could fail as signature or JSON error depending on where the tamper lands
        assert!(err.contains("invalid"), "expected error on tampered snapshot, got: {err}");
    }

    #[test]
    fn snapshot_rejects_truncated_payload() {
        let err = SignedRegistrySnapshot::verify_and_decode(&[0u8; 10], &[0u8; 32]).unwrap_err();
        assert!(err.contains("too short"));
    }

    #[test]
    fn snapshot_hybrid_rejects_wrong_signer() {
        let secret = prism_sync_crypto::DeviceSecret::generate();
        let signing_key = secret.ed25519_keypair("test-device").unwrap();
        let pq_signing_key = secret.ml_dsa_65_keypair("test-device").unwrap();
        let snapshot = sample_snapshot();
        let signed = snapshot.sign_hybrid(&signing_key, &pq_signing_key);

        let (_other_pq_key, other_pq_pk) = make_pq_signing_key();
        let err = SignedRegistrySnapshot::verify_and_decode_hybrid(
            &signed,
            &signing_key.public_key_bytes(),
            &other_pq_pk,
        )
        .unwrap_err();
        assert!(err.contains("signature invalid"));
    }

    #[test]
    fn snapshot_hybrid_rejects_oversized_signature_len_without_panic() {
        let mut signed = vec![HYBRID_SIGNATURE_VERSION_V3];
        signed.extend_from_slice(&u32::MAX.to_le_bytes());

        let result = std::panic::catch_unwind(|| {
            SignedRegistrySnapshot::verify_and_decode_hybrid(&signed, &[0u8; 32], &[0u8; 1952])
        });

        assert!(result.is_ok(), "oversized hybrid signature length should not panic");
        let err = result.unwrap().unwrap_err();
        assert!(err.contains("registry snapshot signature invalid"), "unexpected error: {err}");
    }

    #[test]
    fn snapshot_to_device_records_preserves_fields() {
        let snapshot = sample_snapshot();
        let records = snapshot.to_device_records();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].sync_id, "sync-1");
        assert_eq!(records[0].device_id, "dev-a");
        assert_eq!(records[0].ed25519_public_key, vec![1u8; 32]);
        assert_eq!(records[0].x25519_public_key, vec![2u8; 32]);
        assert_eq!(records[0].status, "active");
    }

    #[test]
    fn snapshot_entry_serialization_roundtrip() {
        let entry = RegistrySnapshotEntry {
            sync_id: "sync-1".into(),
            device_id: "dev-a".into(),
            ed25519_public_key: vec![1u8; 32],
            x25519_public_key: vec![2u8; 32],
            ml_dsa_65_public_key: Vec::new(),
            ml_kem_768_public_key: Vec::new(),
            x_wing_public_key: Vec::new(),
            status: "active".into(),
            ml_dsa_key_generation: 0,
        };
        let json = serde_json::to_vec(&entry).unwrap();
        let decoded: RegistrySnapshotEntry = serde_json::from_slice(&json).unwrap();
        assert_eq!(decoded, entry);
    }

    #[test]
    fn invitation_signing_data_v2_binds_ml_dsa_key() {
        let base = build_invitation_signing_data_v2(
            "sync",
            "https://relay.example",
            &[1, 2, 3],
            &[4, 5, 6],
            "device-a",
            &[7u8; 32],
            &[8u8; 1952],
            Some("device-b"),
            1,
            &[9u8; 32],
        );
        let changed = build_invitation_signing_data_v2(
            "sync",
            "https://relay.example",
            &[1, 2, 3],
            &[4, 5, 6],
            "device-a",
            &[7u8; 32],
            &[10u8; 1952],
            Some("device-b"),
            1,
            &[9u8; 32],
        );

        assert_ne!(base, changed);
    }

    #[test]
    fn registry_approval_signing_data_v2_uses_distinct_domain() {
        let v1 = build_registry_approval_signing_data("sync", "device-a", b"snapshot");
        let v2 = build_registry_approval_signing_data_v2("sync", "device-a", b"snapshot");
        assert_ne!(v1, v2);
    }
}
