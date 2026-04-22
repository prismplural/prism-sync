use super::HybridSignature;
use crate::error::{CryptoError, Result};
use serde::{Deserialize, Serialize};

/// Fixed size of an X25519 public key.
const X25519_PUBLIC_KEY_LEN: usize = 32;

/// Fixed size of an ML-KEM-768 encapsulation key.
const ML_KEM_768_EK_LEN: usize = 1184;

/// Domain separator for canonical signed prekey encoding.
const SIGNED_PREKEY_CONTEXT: &[u8] = b"PRISM_SIGNED_PREKEY_V1\0";

/// Protocol version for key bundles and bootstrap messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ProtocolVersion {
    /// Initial PQ-hybrid protocol
    V1 = 1,
}

/// Capability flags indicating what a device supports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityFlags {
    /// Supports ML-KEM-768 key encapsulation
    pub ml_kem_768: bool,
    /// Supports ML-DSA-65 signatures
    pub ml_dsa_65: bool,
    /// Supports hybrid Ed25519 + ML-DSA-65 signatures
    pub hybrid_signatures: bool,
}

impl Default for CapabilityFlags {
    fn default() -> Self {
        Self { ml_kem_768: true, ml_dsa_65: true, hybrid_signatures: true }
    }
}

/// A device's full public key bundle for the PQ bootstrap protocol.
/// Contains both classical and post-quantum public keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceKeyBundle {
    /// Unique device identifier
    pub device_id: String,
    /// Ed25519 verifying key (32 bytes, hex-encoded)
    pub ed25519_pk: String,
    /// X25519 public key (32 bytes, hex-encoded)
    pub x25519_pk: String,
    /// ML-DSA-65 verifying key (1952 bytes, hex-encoded)
    pub ml_dsa_65_pk: String,
    /// ML-KEM-768 encapsulation key (1184 bytes, hex-encoded)
    pub ml_kem_768_ek: String,
    /// Protocol version
    pub version: ProtocolVersion,
    /// What this device supports
    pub capabilities: CapabilityFlags,
}

impl DeviceKeyBundle {
    /// Create a DeviceKeyBundle from a DeviceSecret and device_id.
    /// Derives all keypairs deterministically.
    pub fn from_device_secret(
        secret: &crate::DeviceSecret,
        device_id: &str,
    ) -> crate::error::Result<Self> {
        let ed_kp = secret.ed25519_keypair(device_id)?;
        let x_kp = secret.x25519_keypair(device_id)?;
        let ml_dsa_kp = secret.ml_dsa_65_keypair(device_id)?;
        let ml_kem_kp = secret.ml_kem_768_keypair(device_id)?;

        Ok(Self {
            device_id: device_id.to_string(),
            ed25519_pk: crate::hex::encode(&ed_kp.public_key_bytes()),
            x25519_pk: crate::hex::encode(&x_kp.public_key_bytes()),
            ml_dsa_65_pk: crate::hex::encode(&ml_dsa_kp.public_key_bytes()),
            ml_kem_768_ek: crate::hex::encode(&ml_kem_kp.public_key_bytes()),
            version: ProtocolVersion::V1,
            capabilities: CapabilityFlags::default(),
        })
    }
}

/// A signed prekey combining classical and PQ key exchange keys.
/// Signed by the user's identity key to bind it to the user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPrekey {
    /// Unique key identifier (UUID v4)
    pub key_id: String,
    /// X25519 public key (32 bytes, hex-encoded)
    pub x25519_pk: String,
    /// ML-KEM-768 encapsulation key (1184 bytes, hex-encoded)
    pub ml_kem_768_ek: String,
    /// When this prekey was created (Unix timestamp seconds)
    pub created_at: u64,
    /// Hybrid signature over the canonical prekey data
    /// (serialized as the HybridSignature wire format, hex-encoded)
    pub signature: String,
}

impl SignedPrekey {
    /// Create and sign a canonical signed prekey bundle.
    pub fn sign(
        key_id: impl Into<String>,
        x25519_pk: &[u8; X25519_PUBLIC_KEY_LEN],
        ml_kem_768_ek: &[u8],
        created_at: u64,
        ed25519_sk: &ed25519_dalek::SigningKey,
        ml_dsa_sk: &impl ml_dsa::signature::Signer<ml_dsa::Signature<ml_dsa::MlDsa65>>,
    ) -> Result<Self> {
        if ml_kem_768_ek.len() != ML_KEM_768_EK_LEN {
            return Err(CryptoError::InvalidKeyMaterial(format!(
                "ml-kem-768 encapsulation key: expected {ML_KEM_768_EK_LEN} bytes, got {}",
                ml_kem_768_ek.len()
            )));
        }

        let mut prekey = Self {
            key_id: key_id.into(),
            x25519_pk: crate::hex::encode(x25519_pk),
            ml_kem_768_ek: crate::hex::encode(ml_kem_768_ek),
            created_at,
            signature: String::new(),
        };

        let message = prekey.canonical_bytes()?;
        let signature = HybridSignature::sign(&message, ed25519_sk, ml_dsa_sk);
        prekey.signature = crate::hex::encode(&signature.to_bytes());
        Ok(prekey)
    }

    /// Canonical byte representation used for signing and verification.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let key_id = self.key_id.as_bytes();
        if key_id.len() > u32::MAX as usize {
            return Err(CryptoError::InvalidInput(
                "signed prekey key_id exceeds u32::MAX bytes".into(),
            ));
        }

        let x25519_pk =
            decode_fixed_hex("x25519 public key", &self.x25519_pk, X25519_PUBLIC_KEY_LEN)?;
        let ml_kem_768_ek = decode_fixed_hex(
            "ml-kem-768 encapsulation key",
            &self.ml_kem_768_ek,
            ML_KEM_768_EK_LEN,
        )?;

        let total_len = SIGNED_PREKEY_CONTEXT.len()
            + 4
            + key_id.len()
            + 8
            + x25519_pk.len()
            + ml_kem_768_ek.len();
        let mut buf = Vec::with_capacity(total_len);
        buf.extend_from_slice(SIGNED_PREKEY_CONTEXT);
        buf.extend_from_slice(&(key_id.len() as u32).to_le_bytes());
        buf.extend_from_slice(key_id);
        buf.extend_from_slice(&self.created_at.to_le_bytes());
        buf.extend_from_slice(&x25519_pk);
        buf.extend_from_slice(&ml_kem_768_ek);
        Ok(buf)
    }

    /// Verify the signed prekey against the user-level identity keys.
    pub fn verify(&self, ed25519_pk: &[u8; 32], ml_dsa_pk: &[u8]) -> Result<()> {
        let signature_bytes = crate::hex::decode(&self.signature)?;
        let signature = HybridSignature::from_bytes(&signature_bytes)?;
        let message = self.canonical_bytes()?;
        signature.verify(&message, ed25519_pk, ml_dsa_pk)
    }
}

/// User-level sharing identity.
/// This is the long-lived identity used for async sharing (not sync pairing).
/// The exact root-secret derivation path remains open for Phase 4.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSharingIdentity {
    /// Random opaque identifier, NOT derived from keys.
    /// Stable across key rotations.
    pub sharing_id: String,
    /// Ed25519 identity verifying key (32 bytes, hex-encoded)
    pub ed25519_identity_pk: String,
    /// ML-DSA-65 identity verifying key (1952 bytes, hex-encoded)
    pub ml_dsa_65_identity_pk: String,
    /// Protocol version
    pub version: ProtocolVersion,
}

fn decode_fixed_hex(field_name: &str, hex_str: &str, expected_len: usize) -> Result<Vec<u8>> {
    let bytes = crate::hex::decode(hex_str)?;
    if bytes.len() != expected_len {
        return Err(CryptoError::InvalidKeyMaterial(format!(
            "{field_name}: expected {expected_len} bytes, got {}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DeviceSecret;
    use ed25519_dalek::SigningKey;
    use ml_dsa::signature::Keypair;
    use ml_dsa::{KeyGen, MlDsa65};

    #[test]
    fn device_key_bundle_from_secret() {
        let secret = DeviceSecret::generate();
        let bundle = DeviceKeyBundle::from_device_secret(&secret, "test_device").unwrap();
        assert_eq!(bundle.device_id, "test_device");
        assert_eq!(bundle.version, ProtocolVersion::V1);
        assert!(bundle.capabilities.ml_kem_768);
        // Ed25519 pk is 32 bytes = 64 hex chars
        assert_eq!(bundle.ed25519_pk.len(), 64);
        // X25519 pk is 32 bytes = 64 hex chars
        assert_eq!(bundle.x25519_pk.len(), 64);
        // ML-DSA-65 pk is 1952 bytes = 3904 hex chars
        assert_eq!(bundle.ml_dsa_65_pk.len(), 3904);
        // ML-KEM-768 ek is 1184 bytes = 2368 hex chars
        assert_eq!(bundle.ml_kem_768_ek.len(), 2368);
    }

    #[test]
    fn device_key_bundle_deterministic() {
        let secret = DeviceSecret::from_bytes(vec![42u8; 32]).unwrap();
        let b1 = DeviceKeyBundle::from_device_secret(&secret, "dev").unwrap();
        let secret2 = DeviceSecret::from_bytes(vec![42u8; 32]).unwrap();
        let b2 = DeviceKeyBundle::from_device_secret(&secret2, "dev").unwrap();
        assert_eq!(b1.ed25519_pk, b2.ed25519_pk);
        assert_eq!(b1.ml_dsa_65_pk, b2.ml_dsa_65_pk);
        assert_eq!(b1.ml_kem_768_ek, b2.ml_kem_768_ek);
    }

    #[test]
    fn device_key_bundle_json_roundtrip() {
        let secret = DeviceSecret::generate();
        let bundle = DeviceKeyBundle::from_device_secret(&secret, "test").unwrap();
        let json = serde_json::to_string(&bundle).unwrap();
        let restored: DeviceKeyBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(bundle.device_id, restored.device_id);
        assert_eq!(bundle.ed25519_pk, restored.ed25519_pk);
        assert_eq!(bundle.ml_dsa_65_pk, restored.ml_dsa_65_pk);
    }

    #[test]
    fn protocol_version_serialization() {
        let v = ProtocolVersion::V1;
        let json = serde_json::to_string(&v).unwrap();
        let restored: ProtocolVersion = serde_json::from_str(&json).unwrap();
        assert_eq!(v, restored);
    }

    #[test]
    fn capability_flags_default() {
        let flags = CapabilityFlags::default();
        assert!(flags.ml_kem_768);
        assert!(flags.ml_dsa_65);
        assert!(flags.hybrid_signatures);
    }

    #[test]
    fn signed_prekey_sign_verify_roundtrip() {
        let (prekey, ed_pk, ml_pk) = signed_prekey_fixture();
        prekey.verify(&ed_pk, &ml_pk).unwrap();
    }

    #[test]
    fn signed_prekey_verify_detects_tamper() {
        let (mut prekey, ed_pk, ml_pk) = signed_prekey_fixture();

        prekey.created_at += 1;
        assert!(prekey.verify(&ed_pk, &ml_pk).is_err());
    }

    #[test]
    fn signed_prekey_canonical_bytes_reject_invalid_lengths() {
        let prekey = SignedPrekey {
            key_id: "test-key-id".to_string(),
            x25519_pk: "aa".repeat(31),
            ml_kem_768_ek: "bb".repeat(1184),
            created_at: 1234567890,
            signature: String::new(),
        };
        assert!(prekey.canonical_bytes().is_err());
    }

    #[test]
    fn signed_prekey_json_roundtrip() {
        let (prekey, _ed_pk, _ml_pk) = signed_prekey_fixture();
        let json = serde_json::to_string(&prekey).unwrap();
        let restored: SignedPrekey = serde_json::from_str(&json).unwrap();
        assert_eq!(prekey.key_id, restored.key_id);
        assert_eq!(prekey.created_at, restored.created_at);
        assert_eq!(prekey.signature, restored.signature);
    }

    #[test]
    fn user_sharing_identity_json_roundtrip() {
        let identity = UserSharingIdentity {
            sharing_id: "random-opaque-id".to_string(),
            ed25519_identity_pk: "aa".repeat(32),
            ml_dsa_65_identity_pk: "bb".repeat(1952),
            version: ProtocolVersion::V1,
        };
        let json = serde_json::to_string(&identity).unwrap();
        let restored: UserSharingIdentity = serde_json::from_str(&json).unwrap();
        assert_eq!(identity.sharing_id, restored.sharing_id);
        assert_eq!(identity.version, restored.version);
    }

    fn sharing_identity_keys() -> (SigningKey, ml_dsa::SigningKey<MlDsa65>) {
        use getrandom::rand_core::UnwrapErr;
        use getrandom::SysRng;

        let ed_sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let mut rng = UnwrapErr(SysRng);
        let ml_sk = MlDsa65::key_gen(&mut rng);
        (ed_sk, ml_sk)
    }

    fn signed_prekey_fixture() -> (SignedPrekey, [u8; 32], Vec<u8>) {
        let (ed_sk, ml_sk) = sharing_identity_keys();
        let ed_pk = ed_sk.verifying_key().to_bytes();
        let ml_vk = ml_sk.verifying_key();
        let ml_pk_encoded = ml_vk.encode();
        let ml_pk = AsRef::<[u8]>::as_ref(&ml_pk_encoded).to_vec();

        let secret = DeviceSecret::from_bytes(vec![7u8; 32]).unwrap();
        let x25519 = secret.x25519_keypair("sharing-device").unwrap();
        let ml_kem = secret.ml_kem_768_keypair("sharing-device").unwrap();

        let prekey = SignedPrekey::sign(
            "prekey-1",
            &x25519.public_key_bytes(),
            &ml_kem.public_key_bytes(),
            1_725_000_000,
            &ed_sk,
            &ml_sk,
        )
        .unwrap();

        (prekey, ed_pk, ml_pk)
    }
}
