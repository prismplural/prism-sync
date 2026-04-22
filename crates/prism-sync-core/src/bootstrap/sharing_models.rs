//! Data models for the PQ hybrid remote sharing bootstrap (Phase 4).
//!
//! Provides binary-serializable structs for the sharing identity, prekeys,
//! init messages, and relationships. All binary formats use big-endian
//! length prefixes consistent with the pairing models in Phase 3.

use prism_sync_crypto::pq::HybridSignature;
use serde::{Deserialize, Serialize};

use super::BootstrapVersion;

const ED25519_PK_LEN: usize = 32;
const ML_DSA_65_PK_LEN: usize = 1952;
const XWING_EK_LEN: usize = 1216;
const KEM_CIPHERTEXT_LEN: usize = 1120;
const CONFIRMATION_MAC_LEN: usize = 32;
const SHARING_IDENTITY_SIGNATURE_CONTEXT: &[u8] = b"sharing_identity_bundle";
const SIGNED_PREKEY_SIGNATURE_CONTEXT: &[u8] = b"signed_prekey_bundle";

/// 30 days in seconds.
const PREKEY_MAX_AGE_SECS: i64 = 30 * 24 * 60 * 60;
/// 5 minutes in seconds.
const PREKEY_MAX_FUTURE_SECS: i64 = 5 * 60;

// ── SharingIdentityBundle ──────────────────────────────────────────────────

/// A user's sharing identity public keys with hybrid self-signature.
///
/// The identity is long-lived and used across all remote sharing sessions.
/// Both Ed25519 and ML-DSA-65 public keys are included for PQ hybrid auth.
#[derive(Debug, Clone)]
pub struct SharingIdentityBundle {
    pub version: BootstrapVersion,
    pub sharing_id: String,
    pub identity_generation: u32,
    pub ed25519_public_key: [u8; ED25519_PK_LEN],
    pub ml_dsa_65_public_key: Vec<u8>,
    /// HybridSignature (Ed25519 + ML-DSA-65) over the signed content.
    pub signature: Vec<u8>,
}

/// Public metadata extracted from a `SharingIdentityBundle` wire encoding.
///
/// This is useful when a caller needs to inspect the claimed `sharing_id` and
/// `identity_generation` before deciding whether to pin or reject an identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharingIdentityMetadata {
    pub version: BootstrapVersion,
    pub sharing_id: String,
    pub identity_generation: u32,
}

impl SharingIdentityBundle {
    /// Canonical binary encoding of the signed fields (everything except signature).
    ///
    /// ```text
    /// [1B  version]
    /// [2B  sharing_id_len BE][sharing_id UTF-8]
    /// [4B  identity_generation BE]
    /// [32B ed25519_public_key]
    /// [2B  ml_dsa_65_pk_len BE][ml_dsa_65_public_key]
    /// ```
    pub fn signed_content_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            1 + 2
                + self.sharing_id.len()
                + 4
                + ED25519_PK_LEN
                + 2
                + self.ml_dsa_65_public_key.len(),
        );
        buf.push(self.version.as_byte());
        write_len16(&mut buf, self.sharing_id.as_bytes());
        buf.extend_from_slice(&self.identity_generation.to_be_bytes());
        buf.extend_from_slice(&self.ed25519_public_key);
        write_len16(&mut buf, &self.ml_dsa_65_public_key);
        buf
    }

    /// Full wire format: signed content + `[4B signature_len BE][signature]`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let signed = self.signed_content_bytes();
        let mut buf = Vec::with_capacity(signed.len() + 4 + self.signature.len());
        buf.extend_from_slice(&signed);
        buf.extend_from_slice(&(self.signature.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.signature);
        buf
    }

    /// Parse only the public metadata from wire-format bytes.
    ///
    /// This validates the full bundle framing, including the trailing signature
    /// length and the absence of trailing data.
    pub fn parse_metadata(data: &[u8]) -> Option<SharingIdentityMetadata> {
        let parsed = parse_sharing_identity_wire(data)?;
        Some(SharingIdentityMetadata {
            version: parsed.version,
            sharing_id: parsed.sharing_id.to_string(),
            identity_generation: parsed.identity_generation,
        })
    }

    /// Return the signed-content prefix from wire-format bytes.
    ///
    /// This validates the full bundle framing before returning the portion that
    /// is covered by the hybrid self-signature.
    pub fn signed_content_from_bytes(data: &[u8]) -> Option<&[u8]> {
        let parsed = parse_sharing_identity_wire(data)?;
        Some(&data[..parsed.signed_content_end])
    }

    /// Parse from wire format with strict validation.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        let parsed = parse_sharing_identity_wire(data)?;
        Some(Self {
            version: parsed.version,
            sharing_id: parsed.sharing_id.to_string(),
            identity_generation: parsed.identity_generation,
            ed25519_public_key: parsed.ed25519_public_key,
            ml_dsa_65_public_key: parsed.ml_dsa_65_public_key.to_vec(),
            signature: parsed.signature.to_vec(),
        })
    }

    /// Create and self-sign a sharing identity bundle.
    pub fn sign(
        sharing_id: String,
        identity_generation: u32,
        ed25519_pk: [u8; ED25519_PK_LEN],
        ml_dsa_65_pk: Vec<u8>,
        ed25519_sk: &ed25519_dalek::SigningKey,
        ml_dsa_sk: &impl ml_dsa::signature::Signer<ml_dsa::Signature<ml_dsa::MlDsa65>>,
    ) -> Self {
        let mut bundle = Self {
            version: BootstrapVersion::V1,
            sharing_id,
            identity_generation,
            ed25519_public_key: ed25519_pk,
            ml_dsa_65_public_key: ml_dsa_65_pk,
            signature: Vec::new(),
        };

        let message = bundle.signed_content_bytes();
        let hybrid_sig = HybridSignature::sign_v3(
            &message,
            SHARING_IDENTITY_SIGNATURE_CONTEXT,
            ed25519_sk,
            ml_dsa_sk,
        )
        .expect("hardcoded sharing identity context should be <= 255 bytes");
        bundle.signature = hybrid_sig.to_bytes();
        bundle
    }

    /// Verify both Ed25519 AND ML-DSA-65 signatures.
    pub fn verify(&self) -> Result<(), prism_sync_crypto::CryptoError> {
        let message = self.signed_content_bytes();
        let hybrid_sig = HybridSignature::from_bytes(&self.signature)?;
        hybrid_sig.verify_v3(
            &message,
            SHARING_IDENTITY_SIGNATURE_CONTEXT,
            &self.ed25519_public_key,
            &self.ml_dsa_65_public_key,
        )
    }
}

// ── SignedPrekey ────────────────────────────────────────────────────────────

/// A device-level signed prekey for asynchronous key exchange.
///
/// The prekey contains an X-Wing encapsulation key (1216 bytes) and is signed
/// by the user's sharing identity keys.
#[derive(Debug, Clone)]
pub struct SignedPrekey {
    pub prekey_id: String,
    pub device_id: String,
    /// X-Wing encapsulation key (1216 bytes).
    pub xwing_ek: Vec<u8>,
    pub created_at: i64,
    /// HybridSignature (Ed25519 + ML-DSA-65).
    pub signature: Vec<u8>,
}

impl SignedPrekey {
    /// Canonical binary encoding of the signed fields.
    ///
    /// ```text
    /// [2B  prekey_id_len BE][prekey_id UTF-8]
    /// [2B  device_id_len BE][device_id UTF-8]
    /// [2B  xwing_ek_len BE][xwing_ek]
    /// [8B  created_at BE (i64)]
    /// ```
    pub fn signed_content_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            2 + self.prekey_id.len() + 2 + self.device_id.len() + 2 + self.xwing_ek.len() + 8,
        );
        write_len16(&mut buf, self.prekey_id.as_bytes());
        write_len16(&mut buf, self.device_id.as_bytes());
        write_len16(&mut buf, &self.xwing_ek);
        buf.extend_from_slice(&self.created_at.to_be_bytes());
        buf
    }

    /// Full wire format: signed content + `[4B signature_len BE][signature]`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let signed = self.signed_content_bytes();
        let mut buf = Vec::with_capacity(signed.len() + 4 + self.signature.len());
        buf.extend_from_slice(&signed);
        buf.extend_from_slice(&(self.signature.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.signature);
        buf
    }

    /// Parse from wire format with validation.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        let mut pos = 0;

        let prekey_id = read_len16_str(data, &mut pos)?;
        let device_id = read_len16_str(data, &mut pos)?;

        let xwing_ek = read_len16_bytes(data, &mut pos)?;
        if xwing_ek.len() != XWING_EK_LEN {
            return None;
        }

        let created_at = read_i64_be(data, &mut pos)?;
        let signature = read_len32_bytes(data, &mut pos)?;

        // Reject trailing data
        if pos != data.len() {
            return None;
        }

        Some(Self { prekey_id, device_id, xwing_ek, created_at, signature })
    }

    /// Create and sign a prekey bundle using the identity's signing keys.
    pub fn sign(
        prekey_id: String,
        device_id: String,
        xwing_ek: Vec<u8>,
        created_at: i64,
        ed25519_sk: &ed25519_dalek::SigningKey,
        ml_dsa_sk: &impl ml_dsa::signature::Signer<ml_dsa::Signature<ml_dsa::MlDsa65>>,
    ) -> Self {
        let mut prekey = Self { prekey_id, device_id, xwing_ek, created_at, signature: Vec::new() };

        let message = prekey.signed_content_bytes();
        let hybrid_sig = HybridSignature::sign_v3(
            &message,
            SIGNED_PREKEY_SIGNATURE_CONTEXT,
            ed25519_sk,
            ml_dsa_sk,
        )
        .expect("hardcoded signed prekey context should be <= 255 bytes");
        prekey.signature = hybrid_sig.to_bytes();
        prekey
    }

    /// Verify the prekey signature against the given identity bundle's public keys.
    pub fn verify(
        &self,
        identity: &SharingIdentityBundle,
    ) -> Result<(), prism_sync_crypto::CryptoError> {
        let message = self.signed_content_bytes();
        let hybrid_sig = HybridSignature::from_bytes(&self.signature)?;
        hybrid_sig.verify_v3(
            &message,
            SIGNED_PREKEY_SIGNATURE_CONTEXT,
            &identity.ed25519_public_key,
            &identity.ml_dsa_65_public_key,
        )
    }

    /// Check whether the prekey is fresh relative to `now` (Unix timestamp seconds).
    ///
    /// A prekey is fresh if:
    /// - `created_at` is within 30 days of `now` (not too old), AND
    /// - `created_at` is not more than 5 minutes in the future
    pub fn is_fresh(&self, now: i64) -> bool {
        let age = now - self.created_at;
        // Not too old (within 30 days)
        let not_expired = age <= PREKEY_MAX_AGE_SECS;
        // Not too far in the future (within 5 minutes)
        let not_future = self.created_at <= now + PREKEY_MAX_FUTURE_SECS;
        not_expired && not_future
    }
}

// ── SharingPrekeyBundle ────────────────────────────────────────────────────

/// Container for a sharing identity and its associated signed prekey.
///
/// The components are serialized independently for relay transport.
#[derive(Debug, Clone)]
pub struct SharingPrekeyBundle {
    pub identity: SharingIdentityBundle,
    pub signed_prekey: SignedPrekey,
}

// ── SharingInit ────────────────────────────────────────────────────────────

/// The initiator's first message in a remote sharing bootstrap session.
#[derive(Debug, Clone)]
pub struct SharingInit {
    pub version: BootstrapVersion,
    pub init_id: String,
    pub sender_identity: SharingIdentityBundle,
    /// Sender's ephemeral X-Wing encapsulation key (exactly 1216 bytes).
    pub sender_ephemeral_ek: Vec<u8>,
    /// KEM ciphertext (exactly 1120 bytes).
    pub kem_ciphertext: Vec<u8>,
    pub target_prekey_id: String,
    pub confirmation_mac: [u8; CONFIRMATION_MAC_LEN],
    pub encrypted_payload: Vec<u8>,
}

impl SharingInit {
    /// Wire format encoding.
    ///
    /// ```text
    /// [1B  version]
    /// [2B  init_id_len BE][init_id UTF-8]
    /// [4B  sender_identity_len BE][sender_identity.to_bytes()]
    /// [2B  sender_ephemeral_ek_len BE][sender_ephemeral_ek]
    /// [2B  kem_ciphertext_len BE][kem_ciphertext]
    /// [2B  target_prekey_id_len BE][target_prekey_id UTF-8]
    /// [32B confirmation_mac]
    /// [4B  encrypted_payload_len BE][encrypted_payload]
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        let identity_bytes = self.sender_identity.to_bytes();
        let mut buf = Vec::with_capacity(
            1 + 2
                + self.init_id.len()
                + 4
                + identity_bytes.len()
                + 2
                + self.sender_ephemeral_ek.len()
                + 2
                + self.kem_ciphertext.len()
                + 2
                + self.target_prekey_id.len()
                + CONFIRMATION_MAC_LEN
                + 4
                + self.encrypted_payload.len(),
        );
        buf.push(self.version.as_byte());
        write_len16(&mut buf, self.init_id.as_bytes());
        write_len32(&mut buf, &identity_bytes);
        write_len16(&mut buf, &self.sender_ephemeral_ek);
        write_len16(&mut buf, &self.kem_ciphertext);
        write_len16(&mut buf, self.target_prekey_id.as_bytes());
        buf.extend_from_slice(&self.confirmation_mac);
        write_len32(&mut buf, &self.encrypted_payload);
        buf
    }

    /// Parse from wire format with strict validation.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        let mut pos = 0;

        let version = BootstrapVersion::from_byte(*data.get(pos)?)?;
        pos += 1;

        let init_id = read_len16_str(data, &mut pos)?;

        // Parse sender identity from its embedded wire format
        let identity_bytes = read_len32_bytes(data, &mut pos)?;
        let sender_identity = SharingIdentityBundle::from_bytes(&identity_bytes)?;

        let sender_ephemeral_ek = read_len16_bytes(data, &mut pos)?;
        if sender_ephemeral_ek.len() != XWING_EK_LEN {
            return None;
        }

        let kem_ciphertext = read_len16_bytes(data, &mut pos)?;
        if kem_ciphertext.len() != KEM_CIPHERTEXT_LEN {
            return None;
        }

        let target_prekey_id = read_len16_str(data, &mut pos)?;
        let confirmation_mac = read_fixed::<CONFIRMATION_MAC_LEN>(data, &mut pos)?;
        let encrypted_payload = read_len32_bytes(data, &mut pos)?;

        // Reject trailing data
        if pos != data.len() {
            return None;
        }

        Some(Self {
            version,
            init_id,
            sender_identity,
            sender_ephemeral_ek,
            kem_ciphertext,
            target_prekey_id,
            confirmation_mac,
            encrypted_payload,
        })
    }
}

// ── SharingInitPayload ─────────────────────────────────────────────────────

/// The payload inside a SharingInit message, encrypted via EncryptedEnvelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharingInitPayload {
    pub display_name: String,
    pub offered_scopes: Vec<String>,
    pub sender_sharing_id: String,
}

// ── SharingRelationship ────────────────────────────────────────────────────

/// Persisted state of an established sharing relationship.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharingRelationship {
    pub peer_sharing_id: String,
    pub peer_display_name: String,
    pub pairwise_secret: Vec<u8>,
    /// SharingIdentityBundle canonical bytes (for pinning).
    pub pinned_identity: Vec<u8>,
    pub offered_scopes: Vec<String>,
    pub granted_scopes: Vec<String>,
    pub is_verified: bool,
    pub init_id: String,
    pub established_at: i64,
}

// ── Binary helpers ─────────────────────────────────────────────────────────

fn write_len16(buf: &mut Vec<u8>, data: &[u8]) {
    let len = data.len() as u16;
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(data);
}

fn write_len32(buf: &mut Vec<u8>, data: &[u8]) {
    let len = data.len() as u32;
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(data);
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

fn read_len32_bytes(data: &[u8], pos: &mut usize) -> Option<Vec<u8>> {
    if *pos + 4 > data.len() {
        return None;
    }
    let len =
        u32::from_be_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]]) as usize;
    *pos += 4;
    if *pos + len > data.len() {
        return None;
    }
    let result = data[*pos..*pos + len].to_vec();
    *pos += len;
    Some(result)
}

fn read_fixed<const N: usize>(data: &[u8], pos: &mut usize) -> Option<[u8; N]> {
    if *pos + N > data.len() {
        return None;
    }
    let arr: [u8; N] = data[*pos..*pos + N].try_into().ok()?;
    *pos += N;
    Some(arr)
}

fn read_i64_be(data: &[u8], pos: &mut usize) -> Option<i64> {
    if *pos + 8 > data.len() {
        return None;
    }
    let val = i64::from_be_bytes([
        data[*pos],
        data[*pos + 1],
        data[*pos + 2],
        data[*pos + 3],
        data[*pos + 4],
        data[*pos + 5],
        data[*pos + 6],
        data[*pos + 7],
    ]);
    *pos += 8;
    Some(val)
}

struct ParsedSharingIdentityWire<'a> {
    version: BootstrapVersion,
    sharing_id: &'a str,
    identity_generation: u32,
    ed25519_public_key: [u8; ED25519_PK_LEN],
    ml_dsa_65_public_key: &'a [u8],
    signature: &'a [u8],
    signed_content_end: usize,
}

fn parse_sharing_identity_wire(data: &[u8]) -> Option<ParsedSharingIdentityWire<'_>> {
    let mut pos = 0;

    let version = BootstrapVersion::from_byte(*data.get(pos)?)?;
    pos += 1;

    if pos + 2 > data.len() {
        return None;
    }
    let sharing_id_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    if pos + sharing_id_len > data.len() {
        return None;
    }
    let sharing_id = std::str::from_utf8(&data[pos..pos + sharing_id_len]).ok()?;
    pos += sharing_id_len;

    if pos + 4 > data.len() {
        return None;
    }
    let identity_generation =
        u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
    pos += 4;

    if pos + ED25519_PK_LEN > data.len() {
        return None;
    }
    let ed25519_public_key: [u8; ED25519_PK_LEN] =
        data[pos..pos + ED25519_PK_LEN].try_into().ok()?;
    pos += ED25519_PK_LEN;

    if pos + 2 > data.len() {
        return None;
    }
    let ml_dsa_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    if ml_dsa_len != ML_DSA_65_PK_LEN || pos + ml_dsa_len > data.len() {
        return None;
    }
    let ml_dsa_65_public_key = &data[pos..pos + ml_dsa_len];
    pos += ml_dsa_len;

    let signed_content_end = pos;

    if pos + 4 > data.len() {
        return None;
    }
    let signature_len =
        u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
    pos += 4;
    if pos + signature_len != data.len() {
        return None;
    }
    let signature = &data[pos..pos + signature_len];

    Some(ParsedSharingIdentityWire {
        version,
        sharing_id,
        identity_generation,
        ed25519_public_key,
        ml_dsa_65_public_key,
        signature,
        signed_content_end,
    })
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use ml_dsa::signature::Keypair;
    use ml_dsa::{KeyGen, MlDsa65};

    fn test_identity_keys() -> (SigningKey, ml_dsa::SigningKey<MlDsa65>) {
        use getrandom::rand_core::UnwrapErr;
        use getrandom::SysRng;

        let ed_sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let mut rng = UnwrapErr(SysRng);
        let ml_sk = MlDsa65::key_gen(&mut rng);
        (ed_sk, ml_sk)
    }

    fn sample_identity_bundle() -> (SharingIdentityBundle, SigningKey, ml_dsa::SigningKey<MlDsa65>)
    {
        let (ed_sk, ml_sk) = test_identity_keys();
        let ed_pk = ed_sk.verifying_key().to_bytes();
        let ml_vk = ml_sk.verifying_key();
        let ml_pk = AsRef::<[u8]>::as_ref(&ml_vk.encode()).to_vec();

        let bundle = SharingIdentityBundle::sign(
            "sharing-id-abc".to_string(),
            0,
            ed_pk,
            ml_pk,
            &ed_sk,
            &ml_sk,
        );
        (bundle, ed_sk, ml_sk)
    }

    // ── SharingIdentityBundle tests ────────────────────────────────────

    #[test]
    fn identity_bundle_round_trip() {
        let (bundle, _, _) = sample_identity_bundle();
        let bytes = bundle.to_bytes();
        let parsed = SharingIdentityBundle::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.version, bundle.version);
        assert_eq!(parsed.sharing_id, bundle.sharing_id);
        assert_eq!(parsed.identity_generation, bundle.identity_generation);
        assert_eq!(parsed.ed25519_public_key, bundle.ed25519_public_key);
        assert_eq!(parsed.ml_dsa_65_public_key, bundle.ml_dsa_65_public_key);
        assert_eq!(parsed.signature, bundle.signature);
    }

    #[test]
    fn identity_bundle_parse_metadata_round_trip() {
        let (bundle, _, _) = sample_identity_bundle();
        let bytes = bundle.to_bytes();
        let metadata = SharingIdentityBundle::parse_metadata(&bytes).unwrap();

        assert_eq!(metadata.version, bundle.version);
        assert_eq!(metadata.sharing_id, bundle.sharing_id);
        assert_eq!(metadata.identity_generation, bundle.identity_generation);
    }

    #[test]
    fn identity_bundle_signed_content_from_bytes_matches_struct_encoding() {
        let (bundle, _, _) = sample_identity_bundle();
        let bytes = bundle.to_bytes();
        let signed_content = SharingIdentityBundle::signed_content_from_bytes(&bytes).unwrap();

        assert_eq!(signed_content, bundle.signed_content_bytes());
    }

    #[test]
    fn identity_bundle_sign_verify_happy() {
        let (bundle, _, _) = sample_identity_bundle();
        bundle.verify().unwrap();
    }

    #[test]
    fn identity_bundle_verify_fails_with_tampered_key() {
        let (mut bundle, _, _) = sample_identity_bundle();
        bundle.ed25519_public_key[0] ^= 0xFF;
        assert!(bundle.verify().is_err());
    }

    #[test]
    fn identity_bundle_verify_fails_with_tampered_signature() {
        let (mut bundle, _, _) = sample_identity_bundle();
        // Tamper with the hybrid signature bytes
        if let Some(byte) = bundle.signature.get_mut(10) {
            *byte ^= 0xFF;
        }
        assert!(bundle.verify().is_err());
    }

    #[test]
    fn identity_bundle_rejects_v2_signature_format() {
        let (mut bundle, ed_sk, ml_sk) = sample_identity_bundle();
        let message = bundle.signed_content_bytes();
        let legacy_sig = HybridSignature::sign(&message, &ed_sk, &ml_sk);
        bundle.signature = legacy_sig.to_bytes();
        assert!(bundle.verify().is_err());
    }

    #[test]
    fn identity_bundle_rejects_trailing_data() {
        let (bundle, _, _) = sample_identity_bundle();
        let mut bytes = bundle.to_bytes();
        bytes.push(0xFF);
        assert!(SharingIdentityBundle::from_bytes(&bytes).is_none());
        assert!(SharingIdentityBundle::parse_metadata(&bytes).is_none());
        assert!(SharingIdentityBundle::signed_content_from_bytes(&bytes).is_none());
    }

    #[test]
    fn identity_bundle_rejects_wrong_ml_dsa_pk_len() {
        // Build a buffer with a wrong ML-DSA pk length.
        let mut bad = Vec::new();
        bad.push(BootstrapVersion::V1.as_byte());
        write_len16(&mut bad, b"test-id");
        bad.extend_from_slice(&0u32.to_be_bytes());
        bad.extend_from_slice(&[0xAA; ED25519_PK_LEN]);
        write_len16(&mut bad, &vec![0xBB; ML_DSA_65_PK_LEN - 1]); // wrong len
        write_len32(&mut bad, &[0xEE; 100]); // dummy sig
        assert!(SharingIdentityBundle::from_bytes(&bad).is_none());
    }

    // ── SignedPrekey tests ─────────────────────────────────────────────

    fn sample_signed_prekey() -> (SignedPrekey, SharingIdentityBundle) {
        let (bundle, ed_sk, ml_sk) = sample_identity_bundle();

        let prekey = SignedPrekey::sign(
            "prekey-001".to_string(),
            "device-xyz".to_string(),
            vec![0xDD; XWING_EK_LEN],
            1_700_000_000,
            &ed_sk,
            &ml_sk,
        );
        (prekey, bundle)
    }

    #[test]
    fn signed_prekey_round_trip() {
        let (prekey, _) = sample_signed_prekey();
        let bytes = prekey.to_bytes();
        let parsed = SignedPrekey::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.prekey_id, prekey.prekey_id);
        assert_eq!(parsed.device_id, prekey.device_id);
        assert_eq!(parsed.xwing_ek, prekey.xwing_ek);
        assert_eq!(parsed.created_at, prekey.created_at);
        assert_eq!(parsed.signature, prekey.signature);
    }

    #[test]
    fn signed_prekey_verify_against_identity() {
        let (prekey, bundle) = sample_signed_prekey();
        prekey.verify(&bundle).unwrap();
    }

    #[test]
    fn signed_prekey_verify_fails_with_wrong_identity() {
        let (prekey, _) = sample_signed_prekey();
        // Create a different identity
        let (other_bundle, _, _) = sample_identity_bundle();
        assert!(prekey.verify(&other_bundle).is_err());
    }

    #[test]
    fn signed_prekey_rejects_v2_signature_format() {
        let (bundle, ed_sk, ml_sk) = sample_identity_bundle();
        let mut prekey = SignedPrekey {
            prekey_id: "prekey-legacy".to_string(),
            device_id: "device-xyz".to_string(),
            xwing_ek: vec![0xDD; XWING_EK_LEN],
            created_at: 1_700_000_000,
            signature: Vec::new(),
        };
        let message = prekey.signed_content_bytes();
        let legacy_sig = HybridSignature::sign(&message, &ed_sk, &ml_sk);
        prekey.signature = legacy_sig.to_bytes();
        assert!(prekey.verify(&bundle).is_err());
    }

    #[test]
    fn signed_prekey_rejects_wrong_xwing_size() {
        let mut buf = Vec::new();
        write_len16(&mut buf, b"prekey-001");
        write_len16(&mut buf, b"device-xyz");
        write_len16(&mut buf, &vec![0xDD; 1215]); // wrong size
        buf.extend_from_slice(&1_700_000_000i64.to_be_bytes());
        write_len32(&mut buf, &[0xEE; 100]); // dummy sig

        assert!(SignedPrekey::from_bytes(&buf).is_none());
    }

    #[test]
    fn signed_prekey_rejects_trailing_data() {
        let (prekey, _) = sample_signed_prekey();
        let mut bytes = prekey.to_bytes();
        bytes.push(0xFF);
        assert!(SignedPrekey::from_bytes(&bytes).is_none());
    }

    #[test]
    fn signed_prekey_freshness_valid() {
        let now = 1_700_000_000i64;
        let prekey = SignedPrekey {
            prekey_id: "pk".to_string(),
            device_id: "dev".to_string(),
            xwing_ek: vec![0; XWING_EK_LEN],
            created_at: now - 86400, // 1 day ago
            signature: Vec::new(),
        };
        assert!(prekey.is_fresh(now));
    }

    #[test]
    fn signed_prekey_freshness_expired_31_days() {
        let now = 1_700_000_000i64;
        let prekey = SignedPrekey {
            prekey_id: "pk".to_string(),
            device_id: "dev".to_string(),
            xwing_ek: vec![0; XWING_EK_LEN],
            created_at: now - (31 * 24 * 60 * 60), // 31 days ago
            signature: Vec::new(),
        };
        assert!(!prekey.is_fresh(now));
    }

    #[test]
    fn signed_prekey_freshness_future_10_min() {
        let now = 1_700_000_000i64;
        let prekey = SignedPrekey {
            prekey_id: "pk".to_string(),
            device_id: "dev".to_string(),
            xwing_ek: vec![0; XWING_EK_LEN],
            created_at: now + 600, // 10 min in future
            signature: Vec::new(),
        };
        assert!(!prekey.is_fresh(now));
    }

    #[test]
    fn signed_prekey_freshness_borderline_ok() {
        let now = 1_700_000_000i64;
        // Exactly 30 days old
        let prekey = SignedPrekey {
            prekey_id: "pk".to_string(),
            device_id: "dev".to_string(),
            xwing_ek: vec![0; XWING_EK_LEN],
            created_at: now - (30 * 24 * 60 * 60),
            signature: Vec::new(),
        };
        assert!(prekey.is_fresh(now));
    }

    #[test]
    fn signed_prekey_freshness_borderline_future_ok() {
        let now = 1_700_000_000i64;
        // Exactly 5 min in future
        let prekey = SignedPrekey {
            prekey_id: "pk".to_string(),
            device_id: "dev".to_string(),
            xwing_ek: vec![0; XWING_EK_LEN],
            created_at: now + 300,
            signature: Vec::new(),
        };
        assert!(prekey.is_fresh(now));
    }

    // ── SharingInit tests ──────────────────────────────────────────────

    fn sample_sharing_init() -> SharingInit {
        let (bundle, _, _) = sample_identity_bundle();
        SharingInit {
            version: BootstrapVersion::V1,
            init_id: "init-001".to_string(),
            sender_identity: bundle,
            sender_ephemeral_ek: vec![0x44; XWING_EK_LEN],
            kem_ciphertext: vec![0x55; KEM_CIPHERTEXT_LEN],
            target_prekey_id: "prekey-001".to_string(),
            confirmation_mac: [0x66; CONFIRMATION_MAC_LEN],
            encrypted_payload: vec![0x77; 256],
        }
    }

    #[test]
    fn sharing_init_round_trip() {
        let init = sample_sharing_init();
        let bytes = init.to_bytes();
        let parsed = SharingInit::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.version, init.version);
        assert_eq!(parsed.init_id, init.init_id);
        assert_eq!(parsed.sender_identity.sharing_id, init.sender_identity.sharing_id);
        assert_eq!(parsed.sender_ephemeral_ek, init.sender_ephemeral_ek);
        assert_eq!(parsed.kem_ciphertext, init.kem_ciphertext);
        assert_eq!(parsed.target_prekey_id, init.target_prekey_id);
        assert_eq!(parsed.confirmation_mac, init.confirmation_mac);
        assert_eq!(parsed.encrypted_payload, init.encrypted_payload);
    }

    #[test]
    fn sharing_init_rejects_wrong_xwing_ek_size() {
        let (bundle, _, _) = sample_identity_bundle();
        let bad_init = SharingInit {
            version: BootstrapVersion::V1,
            init_id: "init-001".to_string(),
            sender_identity: bundle,
            sender_ephemeral_ek: vec![0x44; 1215], // wrong
            kem_ciphertext: vec![0x55; KEM_CIPHERTEXT_LEN],
            target_prekey_id: "prekey-001".to_string(),
            confirmation_mac: [0x66; CONFIRMATION_MAC_LEN],
            encrypted_payload: vec![0x77; 256],
        };
        let bad_bytes = bad_init.to_bytes();
        assert!(SharingInit::from_bytes(&bad_bytes).is_none());
    }

    #[test]
    fn sharing_init_rejects_wrong_ciphertext_size() {
        let (bundle, _, _) = sample_identity_bundle();
        let bad_init = SharingInit {
            version: BootstrapVersion::V1,
            init_id: "init-001".to_string(),
            sender_identity: bundle,
            sender_ephemeral_ek: vec![0x44; XWING_EK_LEN],
            kem_ciphertext: vec![0x55; 1119], // wrong
            target_prekey_id: "prekey-001".to_string(),
            confirmation_mac: [0x66; CONFIRMATION_MAC_LEN],
            encrypted_payload: vec![0x77; 256],
        };
        let bad_bytes = bad_init.to_bytes();
        assert!(SharingInit::from_bytes(&bad_bytes).is_none());
    }

    #[test]
    fn sharing_init_rejects_trailing_data() {
        let init = sample_sharing_init();
        let mut bytes = init.to_bytes();
        bytes.push(0xFF);
        assert!(SharingInit::from_bytes(&bytes).is_none());
    }

    // ── SharingInitPayload tests ───────────────────────────────────────

    #[test]
    fn sharing_init_payload_json_round_trip() {
        let payload = SharingInitPayload {
            display_name: "Alice".to_string(),
            offered_scopes: vec!["read:members".to_string(), "read:fronting".to_string()],
            sender_sharing_id: "sharing-id-abc".to_string(),
        };
        let json = serde_json::to_string(&payload).unwrap();
        let parsed: SharingInitPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.display_name, payload.display_name);
        assert_eq!(parsed.offered_scopes, payload.offered_scopes);
        assert_eq!(parsed.sender_sharing_id, payload.sender_sharing_id);
    }

    // ── SharingRelationship tests ──────────────────────────────────────

    #[test]
    fn sharing_relationship_json_round_trip() {
        let rel = SharingRelationship {
            peer_sharing_id: "peer-123".to_string(),
            peer_display_name: "Bob".to_string(),
            pairwise_secret: vec![0xAA; 32],
            pinned_identity: vec![0xBB; 100],
            offered_scopes: vec!["read:members".to_string()],
            granted_scopes: vec!["read:members".to_string()],
            is_verified: true,
            init_id: "init-001".to_string(),
            established_at: 1_700_000_000,
        };
        let json = serde_json::to_string(&rel).unwrap();
        let parsed: SharingRelationship = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.peer_sharing_id, rel.peer_sharing_id);
        assert_eq!(parsed.pairwise_secret, rel.pairwise_secret);
        assert_eq!(parsed.is_verified, rel.is_verified);
    }
}
