//! Data models for the PQ hybrid device pairing ceremony.
//!
//! Provides binary-serializable structs for the bootstrap handshake messages
//! exchanged during sync pairing (Phase 3). All binary formats use big-endian
//! length prefixes consistent with [`super::transcript`] and the legacy
//! pairing models in [`crate::pairing::models`].

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::BootstrapVersion;

const ED25519_PK_LEN: usize = 32;
const X25519_PK_LEN: usize = 32;
const ML_DSA_65_PK_LEN: usize = 1952;
const XWING_EK_LEN: usize = 1216;
/// ML-KEM-768 encapsulation key sits at the start of the X-Wing ek.
const ML_KEM_768_EK_LEN: usize = 1184;
const KEM_CIPHERTEXT_LEN: usize = 1120;
const CONFIRMATION_MAC_LEN: usize = 32;

// ── JoinerBootstrapRecord ───────────────────────────────────────────────────

/// The joiner's public key bundle, broadcast during the bootstrap ceremony.
#[derive(Debug, Clone)]
pub struct JoinerBootstrapRecord {
    pub version: BootstrapVersion,
    pub device_id: String,
    pub ed25519_public_key: [u8; 32],
    pub x25519_public_key: [u8; 32],
    pub ml_dsa_65_public_key: Vec<u8>,
    /// Atomic X-Wing encapsulation key (1216 bytes).
    pub xwing_ek: Vec<u8>,
}

impl JoinerBootstrapRecord {
    /// Deterministic binary encoding:
    /// ```text
    /// [1B version][2B device_id_len BE][device_id][32B ed25519_pk][32B x25519_pk]
    /// [2B ml_dsa_65_pk_len BE][ml_dsa_65_pk][2B xwing_ek_len BE][xwing_ek]
    /// ```
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            1 + 2
                + self.device_id.len()
                + ED25519_PK_LEN
                + X25519_PK_LEN
                + 2
                + self.ml_dsa_65_public_key.len()
                + 2
                + self.xwing_ek.len(),
        );
        buf.push(self.version.as_byte());
        write_len16(&mut buf, self.device_id.as_bytes());
        buf.extend_from_slice(&self.ed25519_public_key);
        buf.extend_from_slice(&self.x25519_public_key);
        write_len16(&mut buf, &self.ml_dsa_65_public_key);
        write_len16(&mut buf, &self.xwing_ek);
        buf
    }

    /// Parse from canonical bytes with strict size validation.
    pub fn from_canonical_bytes(data: &[u8]) -> Option<Self> {
        let mut pos = 0;

        let version = BootstrapVersion::from_byte(*data.get(pos)?)?;
        pos += 1;

        let device_id = read_len16_str(data, &mut pos)?;

        let ed25519_public_key = read_fixed::<ED25519_PK_LEN>(data, &mut pos)?;
        let x25519_public_key = read_fixed::<X25519_PK_LEN>(data, &mut pos)?;

        let ml_dsa_65_public_key = read_len16_bytes(data, &mut pos)?;
        if ml_dsa_65_public_key.len() != ML_DSA_65_PK_LEN {
            return None;
        }

        let xwing_ek = read_len16_bytes(data, &mut pos)?;
        if xwing_ek.len() != XWING_EK_LEN {
            return None;
        }

        // Reject trailing bytes
        if pos != data.len() {
            return None;
        }

        Some(Self {
            version,
            device_id,
            ed25519_public_key,
            x25519_public_key,
            ml_dsa_65_public_key,
            xwing_ek,
        })
    }

    /// The ML-KEM-768 encapsulation key (first 1184 bytes of the X-Wing ek).
    pub fn ml_kem_768_ek(&self) -> &[u8] {
        self.xwing_ek.get(..ML_KEM_768_EK_LEN).unwrap_or(&[])
    }

    /// SHA-256 commitment over the canonical byte encoding.
    pub fn commitment(&self) -> [u8; 32] {
        let bytes = self.to_canonical_bytes();
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        hasher.finalize().into()
    }
}

// ── RendezvousToken ─────────────────────────────────────────────────────────

/// Token exchanged out-of-band (QR code or deep link) to bootstrap a pairing.
#[derive(Debug, Clone)]
pub struct RendezvousToken {
    pub version: u8,
    pub rendezvous_id: [u8; 16],
    pub commitment: [u8; 32],
    pub relay_url_hint: String,
}

const RENDEZVOUS_TOKEN_VERSION: u8 = 0x01;

impl RendezvousToken {
    /// Create a new token, computing the commitment from the record.
    pub fn new(rendezvous_id: [u8; 16], record: &JoinerBootstrapRecord, relay_url: String) -> Self {
        Self {
            version: RENDEZVOUS_TOKEN_VERSION,
            rendezvous_id,
            commitment: record.commitment(),
            relay_url_hint: relay_url,
        }
    }

    /// Verify that the commitment matches the given record.
    pub fn verify_commitment(&self, record: &JoinerBootstrapRecord) -> bool {
        self.commitment == record.commitment()
    }

    /// Binary encoding:
    /// ```text
    /// [1B version][16B rendezvous_id][32B commitment][2B url_len BE][url]
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + 16 + 32 + 2 + self.relay_url_hint.len());
        buf.push(self.version);
        buf.extend_from_slice(&self.rendezvous_id);
        buf.extend_from_slice(&self.commitment);
        write_len16(&mut buf, self.relay_url_hint.as_bytes());
        buf
    }

    /// Parse from binary, rejecting unknown versions and trailing bytes.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        let mut pos = 0;

        let version = *data.get(pos)?;
        if version != RENDEZVOUS_TOKEN_VERSION {
            return None;
        }
        pos += 1;

        let rendezvous_id = read_fixed::<16>(data, &mut pos)?;
        let commitment = read_fixed::<32>(data, &mut pos)?;
        let relay_url_hint = read_len16_str(data, &mut pos)?;

        if pos != data.len() {
            return None;
        }

        Some(Self {
            version,
            rendezvous_id,
            commitment,
            relay_url_hint,
        })
    }

    /// Encode as a deep link URL: `prismsync://pair?d={base64url}`
    pub fn to_url(&self) -> String {
        let encoded = URL_SAFE_NO_PAD.encode(self.to_bytes());
        format!("prismsync://pair?d={encoded}")
    }

    /// Parse from a `prismsync://pair?d=...` URL.
    pub fn from_url(url: &str) -> Option<Self> {
        // Strip the scheme and path to find the query string
        let query = url.split('?').nth(1)?;
        let d_value = query
            .split('&')
            .find_map(|param| param.strip_prefix("d="))?;
        let bytes = URL_SAFE_NO_PAD.decode(d_value).ok()?;
        Self::from_bytes(&bytes)
    }

    /// Hex-encoded rendezvous ID.
    pub fn rendezvous_id_hex(&self) -> String {
        hex::encode(self.rendezvous_id)
    }
}

// ── PairingInit ─────────────────────────────────────────────────────────────

/// The initiator's first message to the joiner, carrying public keys,
/// KEM ciphertext, and confirmation MAC.
#[derive(Debug, Clone)]
pub struct PairingInit {
    pub version: BootstrapVersion,
    pub device_id: String,
    pub ed25519_public_key: [u8; 32],
    pub x25519_public_key: [u8; 32],
    pub ml_dsa_65_public_key: Vec<u8>,
    /// Atomic X-Wing encapsulation key (1216 bytes).
    pub xwing_ek: Vec<u8>,
    /// KEM ciphertext (1120 bytes).
    pub kem_ciphertext: Vec<u8>,
    /// Confirmation MAC (32 bytes).
    pub confirmation_mac: Vec<u8>,
    pub relay_origin: String,
}

impl PairingInit {
    /// Binary encoding with 2B BE length prefixes for variable fields.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            1 + 2
                + self.device_id.len()
                + ED25519_PK_LEN
                + X25519_PK_LEN
                + 2
                + self.ml_dsa_65_public_key.len()
                + 2
                + self.xwing_ek.len()
                + 2
                + self.kem_ciphertext.len()
                + CONFIRMATION_MAC_LEN
                + 2
                + self.relay_origin.len(),
        );
        buf.push(self.version.as_byte());
        write_len16(&mut buf, self.device_id.as_bytes());
        buf.extend_from_slice(&self.ed25519_public_key);
        buf.extend_from_slice(&self.x25519_public_key);
        write_len16(&mut buf, &self.ml_dsa_65_public_key);
        write_len16(&mut buf, &self.xwing_ek);
        write_len16(&mut buf, &self.kem_ciphertext);
        buf.extend_from_slice(&self.confirmation_mac);
        write_len16(&mut buf, self.relay_origin.as_bytes());
        buf
    }

    /// Parse from binary with validation.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        let mut pos = 0;

        let version = BootstrapVersion::from_byte(*data.get(pos)?)?;
        pos += 1;

        let device_id = read_len16_str(data, &mut pos)?;
        let ed25519_public_key = read_fixed::<ED25519_PK_LEN>(data, &mut pos)?;
        let x25519_public_key = read_fixed::<X25519_PK_LEN>(data, &mut pos)?;
        let ml_dsa_65_public_key = read_len16_bytes(data, &mut pos)?;
        if ml_dsa_65_public_key.len() != ML_DSA_65_PK_LEN {
            return None;
        }
        let xwing_ek = read_len16_bytes(data, &mut pos)?;
        if xwing_ek.len() != XWING_EK_LEN {
            return None;
        }
        let kem_ciphertext = read_len16_bytes(data, &mut pos)?;
        if kem_ciphertext.len() != KEM_CIPHERTEXT_LEN {
            return None;
        }
        let confirmation_mac = read_fixed::<CONFIRMATION_MAC_LEN>(data, &mut pos)?;
        let relay_origin = read_len16_str(data, &mut pos)?;

        if pos != data.len() {
            return None;
        }

        Some(Self {
            version,
            device_id,
            ed25519_public_key,
            x25519_public_key,
            ml_dsa_65_public_key,
            xwing_ek,
            kem_ciphertext,
            confirmation_mac: confirmation_mac.to_vec(),
            relay_origin,
        })
    }

    /// The ML-KEM-768 encapsulation key (first 1184 bytes of the X-Wing ek).
    pub fn ml_kem_768_ek(&self) -> &[u8] {
        self.xwing_ek.get(..ML_KEM_768_EK_LEN).unwrap_or(&[])
    }
}

// ── PairingPublicKeys ───────────────────────────────────────────────────────

/// Unified view of a device's public keys for transcript building.
#[derive(Debug, Clone)]
pub struct PairingPublicKeys {
    pub device_id: String,
    pub ed25519_pk: [u8; 32],
    pub x25519_pk: [u8; 32],
    pub ml_dsa_65_pk: Vec<u8>,
    pub xwing_ek: Vec<u8>,
}

impl PairingPublicKeys {
    /// The ML-KEM-768 encapsulation key (first 1184 bytes of the X-Wing ek).
    pub fn ml_kem_768_ek(&self) -> &[u8] {
        self.xwing_ek.get(..ML_KEM_768_EK_LEN).unwrap_or(&[])
    }
}

// ── CredentialBundle ────────────────────────────────────────────────────────

/// All credentials a joiner needs to enter a sync group, sent encrypted
/// inside an [`EncryptedEnvelope`](super::EncryptedEnvelope).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialBundle {
    pub sync_id: String,
    pub relay_url: String,
    pub mnemonic: String,
    pub wrapped_dek: Vec<u8>,
    pub salt: Vec<u8>,
    pub current_epoch: u32,
    pub epoch_key: Vec<u8>,
    pub signed_keyring: Vec<u8>,
    pub inviter_device_id: String,
    pub inviter_ed25519_pk: Vec<u8>,
    /// ML-DSA-65 public key of the inviter (Phase 5 hybrid verification).
    #[serde(default)]
    pub inviter_ml_dsa_65_pk: Vec<u8>,
    pub registry_approval_signature: Option<String>,
    pub registration_token: Option<String>,
}

// ── JoinerBundle ────────────────────────────────────────────────────────────

/// The joiner's public key material, sent back to the initiator after
/// credential exchange.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinerBundle {
    pub device_id: String,
    pub ed25519_public_key: Vec<u8>,
    pub x25519_public_key: Vec<u8>,
    pub ml_dsa_65_public_key: Vec<u8>,
    pub ml_kem_768_ek: Vec<u8>,
}

// ── SasDisplay ──────────────────────────────────────────────────────────────

/// Human-readable SAS display codes for the pairing ceremony.
#[derive(Debug)]
pub struct SasDisplay {
    pub words: String,
    pub decimal: String,
}

// ── Binary helpers ──────────────────────────────────────────────────────────

fn write_len16(buf: &mut Vec<u8>, data: &[u8]) {
    let len = data.len() as u16;
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

fn read_fixed<const N: usize>(data: &[u8], pos: &mut usize) -> Option<[u8; N]> {
    if *pos + N > data.len() {
        return None;
    }
    let arr: [u8; N] = data[*pos..*pos + N].try_into().ok()?;
    *pos += N;
    Some(arr)
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_joiner_record() -> JoinerBootstrapRecord {
        JoinerBootstrapRecord {
            version: BootstrapVersion::V1,
            device_id: "device-abc-123".to_string(),
            ed25519_public_key: [0xAA; 32],
            x25519_public_key: [0xBB; 32],
            ml_dsa_65_public_key: vec![0xCC; ML_DSA_65_PK_LEN],
            xwing_ek: vec![0xDD; XWING_EK_LEN],
        }
    }

    fn sample_pairing_init() -> PairingInit {
        PairingInit {
            version: BootstrapVersion::V1,
            device_id: "init-device-42".to_string(),
            ed25519_public_key: [0x11; 32],
            x25519_public_key: [0x22; 32],
            ml_dsa_65_public_key: vec![0x33; ML_DSA_65_PK_LEN],
            xwing_ek: vec![0x44; XWING_EK_LEN],
            kem_ciphertext: vec![0x55; 1120],
            confirmation_mac: vec![0x66; 32],
            relay_origin: "https://relay.example.com".to_string(),
        }
    }

    // ── JoinerBootstrapRecord tests ─────────────────────────────────────

    #[test]
    fn joiner_bootstrap_record_round_trip() {
        let record = sample_joiner_record();
        let bytes = record.to_canonical_bytes();
        let parsed = JoinerBootstrapRecord::from_canonical_bytes(&bytes).unwrap();

        assert_eq!(parsed.version, record.version);
        assert_eq!(parsed.device_id, record.device_id);
        assert_eq!(parsed.ed25519_public_key, record.ed25519_public_key);
        assert_eq!(parsed.x25519_public_key, record.x25519_public_key);
        assert_eq!(parsed.ml_dsa_65_public_key, record.ml_dsa_65_public_key);
        assert_eq!(parsed.xwing_ek, record.xwing_ek);
    }

    #[test]
    fn joiner_bootstrap_record_rejects_wrong_ed25519_size() {
        let record = sample_joiner_record();
        let good = record.to_canonical_bytes();
        // Build a malformed buffer with a 31-byte ed25519 key region:
        // take everything before ed25519 (version + len16 device_id),
        // insert 31 bytes, then append the rest (which won't align).
        let prefix_len = 1 + 2 + record.device_id.len(); // version + len16 + device_id
        let mut bad = Vec::new();
        bad.extend_from_slice(&good[..prefix_len]);
        bad.extend_from_slice(&[0xAA; 31]); // 31 bytes instead of 32
        bad.extend_from_slice(&good[prefix_len + 32..]); // skip 32-byte ed25519

        assert!(JoinerBootstrapRecord::from_canonical_bytes(&bad).is_none());
    }

    #[test]
    fn joiner_bootstrap_record_rejects_wrong_xwing_size() {
        // Build with xwing_ek of 1215 bytes
        let mut buf = Vec::new();
        buf.push(BootstrapVersion::V1.as_byte());
        write_len16(&mut buf, b"device-abc-123");
        buf.extend_from_slice(&[0xAA; 32]); // ed25519
        buf.extend_from_slice(&[0xBB; 32]); // x25519
        write_len16(&mut buf, &vec![0xCC; ML_DSA_65_PK_LEN]); // ml_dsa_65
        write_len16(&mut buf, &vec![0xDD; 1215]); // wrong size

        assert!(JoinerBootstrapRecord::from_canonical_bytes(&buf).is_none());
    }

    #[test]
    fn joiner_bootstrap_record_rejects_trailing_bytes() {
        let record = sample_joiner_record();
        let mut bytes = record.to_canonical_bytes();
        bytes.push(0xFF); // trailing byte

        assert!(JoinerBootstrapRecord::from_canonical_bytes(&bytes).is_none());
    }

    #[test]
    fn joiner_bootstrap_record_commitment_deterministic() {
        let r1 = sample_joiner_record();
        let r2 = sample_joiner_record();
        assert_eq!(r1.commitment(), r2.commitment());
    }

    #[test]
    fn joiner_bootstrap_record_commitment_changes() {
        let r1 = sample_joiner_record();
        let mut r2 = sample_joiner_record();
        r2.device_id = "different-device".to_string();
        assert_ne!(r1.commitment(), r2.commitment());
    }

    // ── RendezvousToken tests ───────────────────────────────────────────

    #[test]
    fn rendezvous_token_round_trip() {
        let record = sample_joiner_record();
        let token =
            RendezvousToken::new([0x42; 16], &record, "https://relay.example.com".to_string());
        let bytes = token.to_bytes();
        let parsed = RendezvousToken::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.version, token.version);
        assert_eq!(parsed.rendezvous_id, token.rendezvous_id);
        assert_eq!(parsed.commitment, token.commitment);
        assert_eq!(parsed.relay_url_hint, token.relay_url_hint);
    }

    #[test]
    fn rendezvous_token_verify_commitment_pass() {
        let record = sample_joiner_record();
        let token =
            RendezvousToken::new([0x42; 16], &record, "https://relay.example.com".to_string());
        assert!(token.verify_commitment(&record));
    }

    #[test]
    fn rendezvous_token_verify_commitment_fail() {
        let record = sample_joiner_record();
        let token =
            RendezvousToken::new([0x42; 16], &record, "https://relay.example.com".to_string());
        let mut modified = sample_joiner_record();
        modified.device_id = "tampered-device".to_string();
        assert!(!token.verify_commitment(&modified));
    }

    #[test]
    fn rendezvous_token_url_round_trip() {
        let record = sample_joiner_record();
        let token =
            RendezvousToken::new([0x42; 16], &record, "https://relay.example.com".to_string());
        let url = token.to_url();
        assert!(url.starts_with("prismsync://pair?d="));

        let parsed = RendezvousToken::from_url(&url).unwrap();
        assert_eq!(parsed.version, token.version);
        assert_eq!(parsed.rendezvous_id, token.rendezvous_id);
        assert_eq!(parsed.commitment, token.commitment);
        assert_eq!(parsed.relay_url_hint, token.relay_url_hint);
    }

    #[test]
    fn rendezvous_token_rejects_unknown_version() {
        let record = sample_joiner_record();
        let token =
            RendezvousToken::new([0x42; 16], &record, "https://relay.example.com".to_string());
        let mut bytes = token.to_bytes();
        bytes[0] = 0x02; // unknown version

        assert!(RendezvousToken::from_bytes(&bytes).is_none());
    }

    // ── PairingInit tests ───────────────────────────────────────────────

    #[test]
    fn pairing_init_round_trip() {
        let init = sample_pairing_init();
        let bytes = init.to_bytes();
        let parsed = PairingInit::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.version, init.version);
        assert_eq!(parsed.device_id, init.device_id);
        assert_eq!(parsed.ed25519_public_key, init.ed25519_public_key);
        assert_eq!(parsed.x25519_public_key, init.x25519_public_key);
        assert_eq!(parsed.ml_dsa_65_public_key, init.ml_dsa_65_public_key);
        assert_eq!(parsed.xwing_ek, init.xwing_ek);
        assert_eq!(parsed.kem_ciphertext, init.kem_ciphertext);
        assert_eq!(parsed.confirmation_mac, init.confirmation_mac);
        assert_eq!(parsed.relay_origin, init.relay_origin);
    }

    #[test]
    fn pairing_init_rejects_wrong_confirmation_mac_length() {
        let mut init = sample_pairing_init();
        init.confirmation_mac = vec![0x66; 31];
        let bytes = init.to_bytes();
        assert!(PairingInit::from_bytes(&bytes).is_none());
    }

    #[test]
    fn pairing_init_rejects_wrong_xwing_length() {
        let mut init = sample_pairing_init();
        init.xwing_ek = vec![0x44; 1215];
        let bytes = init.to_bytes();
        assert!(PairingInit::from_bytes(&bytes).is_none());
    }

    #[test]
    fn pairing_init_rejects_wrong_ciphertext_length() {
        let mut init = sample_pairing_init();
        init.kem_ciphertext = vec![0x55; 1119];
        let bytes = init.to_bytes();
        assert!(PairingInit::from_bytes(&bytes).is_none());
    }

    #[test]
    fn pairing_init_rejects_wrong_ml_dsa_length() {
        let mut init = sample_pairing_init();
        init.ml_dsa_65_public_key = vec![0x33; 1951];
        let bytes = init.to_bytes();
        assert!(PairingInit::from_bytes(&bytes).is_none());
    }

    #[test]
    fn short_xwing_ek_helpers_do_not_panic() {
        let short_record = JoinerBootstrapRecord {
            version: BootstrapVersion::V1,
            device_id: "short".to_string(),
            ed25519_public_key: [0x55; 32],
            x25519_public_key: [0x66; 32],
            ml_dsa_65_public_key: vec![0x77; ML_DSA_65_PK_LEN],
            xwing_ek: vec![0x88; 16],
        };
        assert!(short_record.ml_kem_768_ek().is_empty());

        let short_keys = PairingPublicKeys {
            device_id: "short".to_string(),
            ed25519_pk: [0x11; 32],
            x25519_pk: [0x22; 32],
            ml_dsa_65_pk: vec![0x33; ML_DSA_65_PK_LEN],
            xwing_ek: vec![0x44; 16],
        };
        assert!(short_keys.ml_kem_768_ek().is_empty());
    }

    // ── CredentialBundle tests ──────────────────────────────────────────

    #[test]
    fn credential_bundle_json_round_trip() {
        let bundle = CredentialBundle {
            sync_id: "sync-001".to_string(),
            relay_url: "https://relay.example.com".to_string(),
            mnemonic: "word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12"
                .to_string(),
            wrapped_dek: vec![0xAA; 56],
            salt: vec![0xBB; 32],
            current_epoch: 3,
            epoch_key: vec![0xCC; 32],
            signed_keyring: vec![0xDD; 128],
            inviter_device_id: "inviter-device".to_string(),
            inviter_ed25519_pk: vec![0xEE; 32],
            inviter_ml_dsa_65_pk: vec![0xFF; 1952],
            registry_approval_signature: Some("sig-hex".to_string()),
            registration_token: None,
        };

        let json = serde_json::to_string(&bundle).unwrap();
        let parsed: CredentialBundle = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.sync_id, bundle.sync_id);
        assert_eq!(parsed.relay_url, bundle.relay_url);
        assert_eq!(parsed.mnemonic, bundle.mnemonic);
        assert_eq!(parsed.wrapped_dek, bundle.wrapped_dek);
        assert_eq!(parsed.salt, bundle.salt);
        assert_eq!(parsed.current_epoch, bundle.current_epoch);
        assert_eq!(parsed.epoch_key, bundle.epoch_key);
        assert_eq!(parsed.signed_keyring, bundle.signed_keyring);
        assert_eq!(parsed.inviter_device_id, bundle.inviter_device_id);
        assert_eq!(parsed.inviter_ed25519_pk, bundle.inviter_ed25519_pk);
        assert_eq!(parsed.inviter_ml_dsa_65_pk, bundle.inviter_ml_dsa_65_pk);
        assert_eq!(
            parsed.registry_approval_signature,
            bundle.registry_approval_signature
        );
        assert_eq!(parsed.registration_token, bundle.registration_token);
    }
}
