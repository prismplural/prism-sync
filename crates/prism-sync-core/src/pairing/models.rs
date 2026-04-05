use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use serde::{Deserialize, Serialize};

/// Version byte for the compact binary PairingRequest encoding format.
const PAIRING_REQUEST_VERSION: u8 = 0x01;

/// Version byte for the compact binary QR/URL encoding format.
const COMPACT_VERSION: u8 = 0x06;

/// BIP39 12-word mnemonic entropy length in bytes.
const MNEMONIC_ENTROPY_LEN: usize = 16;

/// Ed25519 signature length in bytes.
const ED25519_SIG_LEN: usize = 64;

/// Ed25519 public key length in bytes.
const ED25519_PK_LEN: usize = 32;

/// X25519 public key length in bytes.
const X25519_PK_LEN: usize = 32;

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

impl PairingRequest {
    /// Encode into a compact binary format for QR code transport.
    ///
    /// Format (big-endian lengths):
    /// ```text
    /// [1B version=0x01]
    /// [2B device_id len][device_id]
    /// [32B ed25519_public_key]
    /// [32B x25519_public_key]
    /// ```
    pub fn to_compact_bytes(&self) -> Option<Vec<u8>> {
        if self.ed25519_public_key.len() != ED25519_PK_LEN {
            return None;
        }
        if self.x25519_public_key.len() != X25519_PK_LEN {
            return None;
        }

        let mut buf =
            Vec::with_capacity(1 + 2 + self.device_id.len() + ED25519_PK_LEN + X25519_PK_LEN);
        buf.push(PAIRING_REQUEST_VERSION);
        write_len16(&mut buf, self.device_id.as_bytes())?;
        buf.extend_from_slice(&self.ed25519_public_key);
        buf.extend_from_slice(&self.x25519_public_key);
        Some(buf)
    }

    /// Decode from the compact binary format produced by [`to_compact_bytes`].
    pub fn from_compact_bytes(data: &[u8]) -> Option<Self> {
        let mut pos = 0;

        let version = data.get(pos).copied()?;
        if version != PAIRING_REQUEST_VERSION {
            return None;
        }
        pos += 1;

        let device_id = read_len16_str(data, &mut pos)?;

        if pos + ED25519_PK_LEN > data.len() {
            return None;
        }
        let ed25519_public_key = data[pos..pos + ED25519_PK_LEN].to_vec();
        pos += ED25519_PK_LEN;

        if pos + X25519_PK_LEN > data.len() {
            return None;
        }
        let x25519_public_key = data[pos..pos + X25519_PK_LEN].to_vec();
        pos += X25519_PK_LEN;

        // Reject trailing garbage — all bytes must be consumed
        if pos != data.len() {
            return None;
        }

        Some(PairingRequest {
            device_id,
            ed25519_public_key,
            x25519_public_key,
        })
    }
}

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
    /// representing a 64-byte signature.
    pub signed_invitation: String,

    /// [`SignedRegistrySnapshot`] in its wire format:
    /// `[64-byte Ed25519 signature || canonical JSON of RegistrySnapshotEntry[]]`.
    ///
    /// The signature covers `PRISM_SYNC_REGISTRY_V1\x00 || canonical JSON`.
    /// Use [`SignedRegistrySnapshot::verify_and_decode`] to validate and
    /// deserialize.
    pub signed_keyring: Vec<u8>,

    /// Device ID of the inviter, needed to look up its public key for
    /// signature verification of `signed_invitation`.
    pub inviter_device_id: String,

    /// Ed25519 public key of the inviter (32 bytes). Used to verify both
    /// `signed_invitation` and the signature inside `signed_keyring`.
    pub inviter_ed25519_pk: Vec<u8>,

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
        if self.signed_keyring.len() <= ED25519_SIG_LEN {
            return "existing_group";
        }
        let json_bytes = &self.signed_keyring[ED25519_SIG_LEN..];
        let entries: Vec<RegistrySnapshotEntry> = match serde_json::from_slice(json_bytes) {
            Ok(e) => e,
            Err(_) => return "existing_group",
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

    /// Encode into a compact binary format for QR codes and URLs.
    ///
    /// Format (big-endian lengths):
    /// ```text
    /// [1B version=0x05]
    /// [2B relay_url len][relay_url]
    /// [2B sync_id len][sync_id]
    /// [16B mnemonic entropy]       — BIP39 12-word → 16 bytes
    /// [2B wrapped_dek len][wrapped_dek]
    /// [2B salt len][salt]
    /// [64B signed_invitation]      — raw Ed25519 sig (not hex)
    /// [2B signed_keyring len][signed_keyring]
    /// [2B inviter_device_id len][inviter_device_id]
    /// [32B inviter_ed25519_pk]
    /// [2B joiner_device_id len][joiner_device_id]  — v0x03+; len=0 if None
    /// [4B current_epoch]                           — v0x04+; u32 big-endian
    /// [2B epoch_key len][epoch_key]                — v0x04+; 0 or 32 bytes
    /// [2B registry_approval_sig len][raw sig]      — v0x05+; 0 or 64 bytes
    /// ```
    pub fn to_compact_bytes(&self) -> Option<Vec<u8>> {
        let mnemonic_entropy = prism_sync_crypto::mnemonic::to_bytes(&self.mnemonic).ok()?;
        if mnemonic_entropy.len() != MNEMONIC_ENTROPY_LEN {
            return None;
        }

        let sig_bytes = hex::decode(&self.signed_invitation).ok()?;
        if sig_bytes.len() != ED25519_SIG_LEN {
            return None;
        }

        if self.inviter_ed25519_pk.len() != ED25519_PK_LEN {
            return None;
        }

        let approval_sig_bytes = match self.registry_approval_signature.as_ref() {
            Some(signature) => {
                let bytes = hex::decode(signature).ok()?;
                if bytes.len() != ED25519_SIG_LEN {
                    return None;
                }
                bytes
            }
            None => Vec::new(),
        };

        let mut buf = Vec::with_capacity(512);
        buf.push(COMPACT_VERSION);
        write_len16(&mut buf, self.relay_url.as_bytes())?;
        write_len16(&mut buf, self.sync_id.as_bytes())?;
        buf.extend_from_slice(&mnemonic_entropy);
        write_len16(&mut buf, &self.wrapped_dek)?;
        write_len16(&mut buf, &self.salt)?;
        buf.extend_from_slice(&sig_bytes);
        write_len16(&mut buf, &self.signed_keyring)?;
        write_len16(&mut buf, self.inviter_device_id.as_bytes())?;
        buf.extend_from_slice(&self.inviter_ed25519_pk);
        write_len16(
            &mut buf,
            self.joiner_device_id.as_deref().unwrap_or("").as_bytes(),
        )?;
        buf.extend_from_slice(&self.current_epoch.to_be_bytes());
        write_len16(&mut buf, &self.epoch_key)?;
        write_len16(&mut buf, &approval_sig_bytes)?;
        write_len16(
            &mut buf,
            self.registration_token.as_deref().unwrap_or("").as_bytes(),
        )?;
        Some(buf)
    }

    /// Decode from the compact binary format produced by [`to_compact_bytes`].
    pub fn from_compact_bytes(data: &[u8]) -> Option<Self> {
        let mut pos = 0;

        // Version check (accept current and previous versions for backward compat)
        let version = data.get(pos).copied()?;
        if version != COMPACT_VERSION
            && version != 0x05
            && version != 0x04
            && version != 0x03
            && version != 0x02
        {
            return None;
        }
        pos += 1;

        let relay_url = read_len16_str(data, &mut pos)?;
        let sync_id = read_len16_str(data, &mut pos)?;

        // Mnemonic entropy (16 bytes) → BIP39 words
        if pos + MNEMONIC_ENTROPY_LEN > data.len() {
            return None;
        }
        let mnemonic =
            prism_sync_crypto::mnemonic::from_bytes(&data[pos..pos + MNEMONIC_ENTROPY_LEN]).ok()?;
        pos += MNEMONIC_ENTROPY_LEN;

        let wrapped_dek = read_len16_bytes(data, &mut pos)?;
        let salt = read_len16_bytes(data, &mut pos)?;

        // Signed invitation (64 bytes) → hex string
        if pos + ED25519_SIG_LEN > data.len() {
            return None;
        }
        let signed_invitation = hex::encode(&data[pos..pos + ED25519_SIG_LEN]);
        pos += ED25519_SIG_LEN;

        let signed_keyring = read_len16_bytes(data, &mut pos)?;
        let inviter_device_id = read_len16_str(data, &mut pos)?;

        // Ed25519 public key (32 bytes)
        if pos + ED25519_PK_LEN > data.len() {
            return None;
        }
        let inviter_ed25519_pk = data[pos..pos + ED25519_PK_LEN].to_vec();
        pos += ED25519_PK_LEN;

        // v0x03+: read joiner_device_id; v0x02: default to None
        let joiner_device_id = if version >= 0x03 {
            let jid = read_len16_str(data, &mut pos)?;
            if jid.is_empty() {
                None
            } else {
                Some(jid)
            }
        } else {
            None
        };

        // v0x04+: read epoch fields; older versions default to epoch 0
        let (current_epoch, epoch_key) = if version >= 0x04 {
            if pos + 4 > data.len() {
                return None;
            }
            let epoch =
                u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
            pos += 4;
            let key = read_len16_bytes(data, &mut pos)?;
            (epoch, key)
        } else {
            (0, vec![])
        };

        let registry_approval_signature = if version >= 0x05 {
            let sig = read_len16_bytes(data, &mut pos)?;
            if sig.is_empty() {
                None
            } else if sig.len() == ED25519_SIG_LEN {
                Some(hex::encode(sig))
            } else {
                return None;
            }
        } else {
            None
        };

        let registration_token = if version >= 0x06 {
            let token_str = read_len16_str(data, &mut pos)?;
            if token_str.is_empty() {
                None
            } else {
                Some(token_str)
            }
        } else {
            None
        };

        // Reject trailing garbage — all bytes must be consumed
        if pos != data.len() {
            return None;
        }

        let response = PairingResponse {
            relay_url,
            sync_id,
            mnemonic,
            wrapped_dek,
            salt,
            signed_invitation,
            signed_keyring,
            inviter_device_id,
            inviter_ed25519_pk,
            joiner_device_id,
            current_epoch,
            epoch_key,
            registry_approval_signature,
            registration_token,
        };
        response.validate_epoch_fields().ok()?;
        Some(response)
    }
}

fn write_len16(buf: &mut Vec<u8>, data: &[u8]) -> Option<()> {
    let len: u16 = data.len().try_into().ok()?;
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(data);
    Some(())
}

fn read_len16_bytes(data: &[u8], pos: &mut usize) -> Option<Vec<u8>> {
    if *pos + 2 > data.len() {
        return None;
    }
    let len = u16::from_be_bytes([data[*pos], data[*pos + 1]]) as usize;
    *pos += 2;
    if *pos + len > data.len() {
        return None;
    }
    let result = data[*pos..*pos + len].to_vec();
    *pos += len;
    Some(result)
}

fn read_len16_str(data: &[u8], pos: &mut usize) -> Option<String> {
    let bytes = read_len16_bytes(data, pos)?;
    String::from_utf8(bytes).ok()
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
    pub status: String,
}

/// A signed, typed snapshot of the device registry.
///
/// Produced by the inviting device and included (serialized) in
/// [`PairingResponse::signed_keyring`]. The joining device verifies the
/// signature before importing the entries into its local registry.
///
/// Wire format: `[64-byte Ed25519 signature || canonical JSON]`
/// The signature covers `PRISM_SYNC_REGISTRY_V1\x00 || canonical JSON`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedRegistrySnapshot {
    pub entries: Vec<RegistrySnapshotEntry>,
}

impl SignedRegistrySnapshot {
    /// Build a snapshot from a list of device entries.
    pub fn new(entries: Vec<RegistrySnapshotEntry>) -> Self {
        Self { entries }
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

    /// Sign the snapshot with the given Ed25519 signing key.
    ///
    /// Returns the wire format: `[64-byte signature || canonical JSON]`.
    pub fn sign(&self, signing_key: &prism_sync_crypto::DeviceSigningKey) -> Vec<u8> {
        let data = self.signing_data();
        let signature = signing_key.sign(&data);
        let json = self.canonical_json();
        [signature, json].concat()
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

        Ok(Self { entries })
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
                status: e.status.clone(),
                registered_at: chrono::Utc::now(),
                revoked_at: None,
            })
            .collect()
    }
}

/// An invitation that can be rendered as a QR code, a word list, or a URL.
pub struct Invite {
    response: PairingResponse,
}

impl Invite {
    pub fn new(response: PairingResponse) -> Self {
        Self { response }
    }

    /// Compact binary payload suitable for embedding in a QR code.
    pub fn qr_payload(&self) -> Vec<u8> {
        self.response.to_compact_bytes().expect(
            "PairingResponse must have valid BIP39 mnemonic, Ed25519 signature, and public key",
        )
    }

    /// The BIP39 mnemonic words extracted from the response.
    pub fn words(&self) -> Vec<String> {
        self.response
            .mnemonic
            .split_whitespace()
            .map(String::from)
            .collect()
    }

    /// A deep-link URL (`prismsync://join?d=<base64url>`) that encodes the
    /// full [`PairingResponse`] in compact binary format.
    pub fn url(&self) -> String {
        let compact = self.response.to_compact_bytes().expect(
            "PairingResponse must have valid BIP39 mnemonic, Ed25519 signature, and public key",
        );
        let encoded = URL_SAFE_NO_PAD.encode(&compact);
        format!("prismsync://join?d={encoded}")
    }

    /// Parse an [`Invite`] back from a URL produced by [`Invite::url`].
    pub fn from_url(url: &str) -> Option<Self> {
        let data = url.strip_prefix("prismsync://join?d=")?;
        let bytes = URL_SAFE_NO_PAD.decode(data).ok()?;
        let response = PairingResponse::from_compact_bytes(&bytes)?;
        Some(Self { response })
    }

    /// Parse an [`Invite`] from raw QR bytes produced by [`Invite::qr_payload`].
    pub fn from_qr_payload(bytes: &[u8]) -> Option<Self> {
        let response = PairingResponse::from_compact_bytes(bytes)?;
        Some(Self { response })
    }

    /// Access the underlying [`PairingResponse`].
    pub fn response(&self) -> &PairingResponse {
        &self.response
    }

    /// Consume the invite and return the inner [`PairingResponse`].
    pub fn into_response(self) -> PairingResponse {
        self.response
    }
}

// Derive a base64-encoded representation of PairingResponse for debug purposes.
impl std::fmt::Debug for Invite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let encoded = STANDARD.encode(serde_json::to_vec(&self.response).unwrap_or_default());
        f.debug_struct("Invite")
            .field("sync_id", &self.response.sync_id)
            .field("relay_url", &self.response.relay_url)
            .field("payload_b64", &encoded)
            .finish()
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
    fn pairing_request_compact_bytes_roundtrip() {
        let req = PairingRequest {
            device_id: "device-abc".into(),
            ed25519_public_key: vec![0xAA; 32],
            x25519_public_key: vec![0xBB; 32],
        };
        let bytes = req
            .to_compact_bytes()
            .expect("compact encode should succeed");
        assert_eq!(bytes[0], PAIRING_REQUEST_VERSION);
        let decoded =
            PairingRequest::from_compact_bytes(&bytes).expect("compact decode should succeed");
        assert_eq!(decoded.device_id, req.device_id);
        assert_eq!(decoded.ed25519_public_key, req.ed25519_public_key);
        assert_eq!(decoded.x25519_public_key, req.x25519_public_key);
    }

    #[test]
    fn pairing_request_compact_bytes_rejects_wrong_version() {
        let req = PairingRequest {
            device_id: "device-abc".into(),
            ed25519_public_key: vec![0xAA; 32],
            x25519_public_key: vec![0xBB; 32],
        };
        let mut bytes = req.to_compact_bytes().unwrap();
        bytes[0] = 0xFF;
        assert!(PairingRequest::from_compact_bytes(&bytes).is_none());
    }

    #[test]
    fn pairing_request_compact_bytes_rejects_truncated_data() {
        let req = PairingRequest {
            device_id: "device-abc".into(),
            ed25519_public_key: vec![0xAA; 32],
            x25519_public_key: vec![0xBB; 32],
        };
        let bytes = req.to_compact_bytes().unwrap();
        // Truncate at various points
        assert!(PairingRequest::from_compact_bytes(&bytes[..1]).is_none());
        assert!(PairingRequest::from_compact_bytes(&bytes[..10]).is_none());
        assert!(PairingRequest::from_compact_bytes(&bytes[..bytes.len() - 1]).is_none());
    }

    #[test]
    fn pairing_request_compact_bytes_rejects_trailing_garbage() {
        let req = PairingRequest {
            device_id: "device-abc".into(),
            ed25519_public_key: vec![0xAA; 32],
            x25519_public_key: vec![0xBB; 32],
        };
        let mut bytes = req.to_compact_bytes().unwrap();
        bytes.push(0xFF);
        assert!(
            PairingRequest::from_compact_bytes(&bytes).is_none(),
            "should reject payload with trailing bytes",
        );
    }

    #[test]
    fn pairing_request_compact_rejects_wrong_key_lengths() {
        let req = PairingRequest {
            device_id: "device-abc".into(),
            ed25519_public_key: vec![0xAA; 16], // wrong length
            x25519_public_key: vec![0xBB; 32],
        };
        assert!(req.to_compact_bytes().is_none());

        let req = PairingRequest {
            device_id: "device-abc".into(),
            ed25519_public_key: vec![0xAA; 32],
            x25519_public_key: vec![0xBB; 16], // wrong length
        };
        assert!(req.to_compact_bytes().is_none());
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
        assert_eq!(
            decoded.registry_approval_signature,
            resp.registry_approval_signature
        );
    }

    #[test]
    fn compact_bytes_roundtrip() {
        let resp = sample_response();
        let bytes = resp
            .to_compact_bytes()
            .expect("compact encode should succeed");
        let decoded =
            PairingResponse::from_compact_bytes(&bytes).expect("compact decode should succeed");
        assert_eq!(decoded.relay_url, resp.relay_url);
        assert_eq!(decoded.sync_id, resp.sync_id);
        assert_eq!(decoded.mnemonic, resp.mnemonic);
        assert_eq!(decoded.wrapped_dek, resp.wrapped_dek);
        assert_eq!(decoded.salt, resp.salt);
        assert_eq!(decoded.signed_invitation, resp.signed_invitation);
        assert_eq!(decoded.signed_keyring, resp.signed_keyring);
        assert_eq!(decoded.inviter_device_id, resp.inviter_device_id);
        assert_eq!(decoded.inviter_ed25519_pk, resp.inviter_ed25519_pk);
        assert_eq!(decoded.current_epoch, resp.current_epoch);
        assert_eq!(decoded.epoch_key, resp.epoch_key);
        assert_eq!(
            decoded.registry_approval_signature,
            resp.registry_approval_signature
        );
        assert_eq!(decoded.registration_token, None);
    }

    #[test]
    fn compact_bytes_roundtrip_with_registration_token() {
        let mut resp = sample_response();
        resp.registration_token = Some("my-secret-token".into());
        let bytes = resp.to_compact_bytes().unwrap();
        let decoded = PairingResponse::from_compact_bytes(&bytes).unwrap();
        assert_eq!(
            decoded.registration_token,
            Some("my-secret-token".into()),
            "registration_token should survive compact roundtrip"
        );
    }

    #[test]
    fn compact_bytes_size_is_small() {
        let resp = sample_response();
        let compact = resp.to_compact_bytes().unwrap();
        let json = serde_json::to_vec(&resp).unwrap();
        // Compact should be significantly smaller than JSON
        assert!(
            compact.len() < json.len() / 2,
            "compact {} bytes should be less than half of JSON {} bytes",
            compact.len(),
            json.len(),
        );
        // Should fit in QR version 40-L (2956 bytes) with room to spare
        assert!(
            compact.len() < 1500,
            "compact {} bytes should be under 1500",
            compact.len(),
        );
    }

    #[test]
    fn compact_bytes_fails_for_invalid_mnemonic() {
        let mut resp = sample_response();
        resp.mnemonic = "not valid bip39 words".into();
        assert!(resp.to_compact_bytes().is_none());
    }

    #[test]
    fn compact_bytes_fails_for_wrong_version() {
        let resp = sample_response();
        let mut bytes = resp.to_compact_bytes().unwrap();
        bytes[0] = 0xFF; // wrong version
        assert!(PairingResponse::from_compact_bytes(&bytes).is_none());
    }

    #[test]
    fn compact_bytes_fails_for_truncated_data() {
        let resp = sample_response();
        let bytes = resp.to_compact_bytes().unwrap();
        // Truncate at various points
        assert!(PairingResponse::from_compact_bytes(&bytes[..10]).is_none());
        assert!(PairingResponse::from_compact_bytes(&bytes[..bytes.len() - 1]).is_none());
    }

    #[test]
    fn qr_payload_roundtrip() {
        let invite = Invite::new(sample_response());
        let payload = invite.qr_payload();
        // Should use compact format (starts with version byte)
        assert_eq!(payload[0], COMPACT_VERSION, "should use compact format");
        let restored = Invite::from_qr_payload(&payload).expect("should decode");
        assert_eq!(restored.response().sync_id, invite.response().sync_id);
        assert_eq!(restored.response().mnemonic, invite.response().mnemonic);
    }

    #[test]
    fn url_roundtrip() {
        let invite = Invite::new(sample_response());
        let url = invite.url();
        assert!(
            url.starts_with("prismsync://join?d="),
            "should use compact URL prefix"
        );
        let restored = Invite::from_url(&url).expect("should decode from URL");
        assert_eq!(restored.response().sync_id, invite.response().sync_id);
        assert_eq!(restored.response().relay_url, invite.response().relay_url);
        assert_eq!(restored.response().mnemonic, invite.response().mnemonic);
        assert_eq!(
            restored.response().wrapped_dek,
            invite.response().wrapped_dek
        );
    }

    #[test]
    fn url_compact_is_small() {
        let invite = Invite::new(sample_response());
        let url = invite.url();
        // Compact URL should be well under QR byte-mode capacity (2956 bytes)
        assert!(
            url.len() < 1500,
            "URL length {} should be under 1500",
            url.len(),
        );
    }

    #[test]
    fn words_returns_mnemonic_split() {
        let invite = Invite::new(sample_response());
        let words = invite.words();
        assert_eq!(words.len(), 12);
    }

    #[test]
    fn url_uses_url_safe_base64() {
        let invite = Invite::new(sample_response());
        let url = invite.url();
        let data_part = url.split('=').nth(1).unwrap_or(&url);
        assert!(!data_part.contains('+'), "must not contain '+'");
        assert!(!data_part.contains('/'), "must not contain '/'");
    }

    #[test]
    fn compact_bytes_rejects_oversized_field() {
        let mut resp = sample_response();
        // signed_keyring exceeding u16::MAX (65535) should cause to_compact_bytes to fail
        resp.signed_keyring = vec![0xCC; 65536];
        assert!(
            resp.to_compact_bytes().is_none(),
            "should reject field > u16::MAX"
        );
    }

    #[test]
    fn compact_bytes_rejects_trailing_garbage() {
        let resp = sample_response();
        let mut bytes = resp.to_compact_bytes().unwrap();
        bytes.push(0xFF); // append trailing garbage
        assert!(
            PairingResponse::from_compact_bytes(&bytes).is_none(),
            "should reject payload with trailing bytes",
        );
    }

    #[test]
    fn compact_bytes_rejects_invalid_utf8() {
        let resp = sample_response();
        let mut bytes = resp.to_compact_bytes().unwrap();
        // Corrupt the relay_url content (starts at offset 3, after version + 2-byte len)
        // The length prefix is at bytes[1..3], content starts at bytes[3]
        bytes[3] = 0xFF; // invalid UTF-8 start byte
        bytes[4] = 0xFE; // invalid UTF-8 continuation
        assert!(
            PairingResponse::from_compact_bytes(&bytes).is_none(),
            "should reject invalid UTF-8 in string fields",
        );
    }

    #[test]
    fn compact_bytes_rejects_wrong_registry_approval_signature_length() {
        let mut resp = sample_response();
        resp.registry_approval_signature = Some(hex::encode([0xAA; 32]));
        assert!(resp.to_compact_bytes().is_none());
    }

    #[test]
    fn compact_bytes_decodes_v04_without_registry_approval_signature() {
        let mut resp = sample_response();
        resp.registry_approval_signature = None;
        let mut bytes = resp.to_compact_bytes().unwrap();
        bytes[0] = 0x04;
        // v0x04 lacks both the approval signature (2B len16) and registration token (2B len16)
        let trimmed = &bytes[..bytes.len() - 4];
        let decoded = PairingResponse::from_compact_bytes(trimmed).expect("v0x04 decode");
        assert!(decoded.registry_approval_signature.is_none());
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
        let snapshot = SignedRegistrySnapshot::new(vec![RegistrySnapshotEntry {
            sync_id: "sync-1".into(),
            device_id: "device-001".into(),
            ed25519_public_key: vec![0xAA; 32],
            x25519_public_key: vec![0xBB; 32],
            status: "active".into(),
        }]);
        let mut resp = sample_response();
        resp.inviter_device_id = "device-001".into();
        resp.signed_keyring = snapshot.sign(&key);
        assert_eq!(resp.admission_context(), "first_device");
    }

    #[test]
    fn admission_context_existing_group() {
        let (key, _pk) = make_signing_key();
        let snapshot = SignedRegistrySnapshot::new(vec![
            RegistrySnapshotEntry {
                sync_id: "sync-1".into(),
                device_id: "device-001".into(),
                ed25519_public_key: vec![0xAA; 32],
                x25519_public_key: vec![0xBB; 32],
                status: "active".into(),
            },
            RegistrySnapshotEntry {
                sync_id: "sync-1".into(),
                device_id: "device-002".into(),
                ed25519_public_key: vec![0xCC; 32],
                x25519_public_key: vec![0xDD; 32],
                status: "active".into(),
            },
        ]);
        let mut resp = sample_response();
        resp.inviter_device_id = "device-001".into();
        resp.signed_keyring = snapshot.sign(&key);
        assert_eq!(resp.admission_context(), "existing_group");
    }

    #[test]
    fn admission_context_single_entry_different_inviter() {
        let (key, _pk) = make_signing_key();
        let snapshot = SignedRegistrySnapshot::new(vec![RegistrySnapshotEntry {
            sync_id: "sync-1".into(),
            device_id: "device-999".into(),
            ed25519_public_key: vec![0xAA; 32],
            x25519_public_key: vec![0xBB; 32],
            status: "active".into(),
        }]);
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

    // ── SignedRegistrySnapshot tests ──

    fn make_signing_key() -> (prism_sync_crypto::DeviceSigningKey, [u8; 32]) {
        let secret = prism_sync_crypto::DeviceSecret::generate();
        let key = secret.ed25519_keypair("test-device").unwrap();
        let pk = key.public_key_bytes();
        (key, pk)
    }

    fn sample_snapshot() -> SignedRegistrySnapshot {
        SignedRegistrySnapshot::new(vec![
            RegistrySnapshotEntry {
                sync_id: "sync-1".into(),
                device_id: "dev-a".into(),
                ed25519_public_key: vec![1u8; 32],
                x25519_public_key: vec![2u8; 32],
                status: "active".into(),
            },
            RegistrySnapshotEntry {
                sync_id: "sync-1".into(),
                device_id: "dev-b".into(),
                ed25519_public_key: vec![3u8; 32],
                x25519_public_key: vec![4u8; 32],
                status: "active".into(),
            },
        ])
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
    fn snapshot_canonical_json_is_deterministic() {
        // Order of entries should not matter — canonical form sorts by device_id
        let snapshot_ab = SignedRegistrySnapshot::new(vec![
            RegistrySnapshotEntry {
                sync_id: "s".into(),
                device_id: "b".into(),
                ed25519_public_key: vec![2u8; 32],
                x25519_public_key: vec![2u8; 32],
                status: "active".into(),
            },
            RegistrySnapshotEntry {
                sync_id: "s".into(),
                device_id: "a".into(),
                ed25519_public_key: vec![1u8; 32],
                x25519_public_key: vec![1u8; 32],
                status: "active".into(),
            },
        ]);
        let snapshot_ba = SignedRegistrySnapshot::new(vec![
            RegistrySnapshotEntry {
                sync_id: "s".into(),
                device_id: "a".into(),
                ed25519_public_key: vec![1u8; 32],
                x25519_public_key: vec![1u8; 32],
                status: "active".into(),
            },
            RegistrySnapshotEntry {
                sync_id: "s".into(),
                device_id: "b".into(),
                ed25519_public_key: vec![2u8; 32],
                x25519_public_key: vec![2u8; 32],
                status: "active".into(),
            },
        ]);
        assert_eq!(snapshot_ab.canonical_json(), snapshot_ba.canonical_json());
    }

    #[test]
    fn snapshot_rejects_wrong_signer() {
        let (key, _pk) = make_signing_key();
        let (_other_key, other_pk) = make_signing_key();
        let snapshot = sample_snapshot();
        let signed = snapshot.sign(&key);

        let err = SignedRegistrySnapshot::verify_and_decode(&signed, &other_pk).unwrap_err();
        assert!(
            err.contains("signature invalid"),
            "expected signature error, got: {err}"
        );
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
        assert!(
            err.contains("invalid"),
            "expected error on tampered snapshot, got: {err}"
        );
    }

    #[test]
    fn snapshot_rejects_truncated_payload() {
        let err = SignedRegistrySnapshot::verify_and_decode(&[0u8; 10], &[0u8; 32]).unwrap_err();
        assert!(err.contains("too short"));
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
            status: "active".into(),
        };
        let json = serde_json::to_vec(&entry).unwrap();
        let decoded: RegistrySnapshotEntry = serde_json::from_slice(&json).unwrap();
        assert_eq!(decoded, entry);
    }
}
