//! Cross-signed continuity proof for ML-DSA key rotation.
//!
//! When a device rotates its ML-DSA-65 signing key, it must produce a proof
//! that both the old key signs the new key and the new key signs the old key,
//! bound to the device ID and generation numbers. This prevents unauthorized
//! key replacement.

use serde::{Deserialize, Serialize};

use super::HybridSignature;
use crate::device_identity::{DevicePqSigningKey, DeviceSecret};
use crate::error::{CryptoError, Result};

/// Maximum age of a continuity proof for verification (48 hours).
const PROOF_MAX_AGE_SECS: i64 = 48 * 3600;

/// Domain separator for rotation proof messages, following the project's
/// established convention from `auth.rs` (`PRISM_SYNC_CHALLENGE_V2\x00`, etc.).
const ROTATION_PROOF_DOMAIN: &[u8] = b"PRISM_KEY_ROTATION_PROOF_V1\x00";

/// Cross-signed proof that an ML-DSA key rotation is legitimate.
///
/// Both the old and new keys sign each other, bound to the device ID,
/// generation numbers, and a timestamp. This prevents unauthorized key
/// replacement and limits replay windows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlDsaContinuityProof {
    pub device_id: String,
    pub old_generation: u32,
    pub new_generation: u32,
    /// Unix timestamp (seconds) when the proof was created.
    #[serde(default)]
    pub timestamp: i64,
    /// The new ML-DSA-65 public key (raw bytes).
    pub new_ml_dsa_pk: Vec<u8>,
    /// HybridSignature::sign_v3(proof_message, "ml_dsa_rotation", ed25519_sk, old_ml_dsa_sk)
    pub old_signs_new: Vec<u8>,
    /// ML-DSA.sign(proof_message_reverse, new_ml_dsa_sk)
    pub new_signs_old: Vec<u8>,
}

impl MlDsaContinuityProof {
    /// Build the proof message for one direction of the cross-signature.
    ///
    /// Format: `DOMAIN_SEP || len(device_id) (LE u32) || device_id_bytes
    ///          || from_gen (LE u32) || to_gen (LE u32) || timestamp (LE i64)
    ///          || target_pk`
    ///
    /// Domain separator follows the project's auth.rs convention. Timestamp
    /// bounds replay window. Device_id is length-prefixed for unambiguous parsing.
    fn proof_message(
        device_id: &str,
        from_gen: u32,
        to_gen: u32,
        timestamp: i64,
        target_pk: &[u8],
    ) -> Vec<u8> {
        let id_bytes = device_id.as_bytes();
        let mut msg = Vec::with_capacity(
            ROTATION_PROOF_DOMAIN.len() + 4 + id_bytes.len() + 4 + 4 + 8 + target_pk.len(),
        );
        msg.extend_from_slice(ROTATION_PROOF_DOMAIN);
        msg.extend_from_slice(&(id_bytes.len() as u32).to_le_bytes());
        msg.extend_from_slice(id_bytes);
        msg.extend_from_slice(&from_gen.to_le_bytes());
        msg.extend_from_slice(&to_gen.to_le_bytes());
        msg.extend_from_slice(&timestamp.to_le_bytes());
        msg.extend_from_slice(target_pk);
        msg
    }

    /// Create a continuity proof for rotating from `old_generation` to `new_generation`.
    ///
    /// The old ML-DSA key and the device's Ed25519 key produce a hybrid V3 signature
    /// over the new public key. The new ML-DSA key produces a standalone ML-DSA
    /// signature over the old public key. Both signatures are bound to the device ID
    /// and generation numbers.
    pub fn create(
        device_secret: &DeviceSecret,
        device_id: &str,
        old_generation: u32,
        new_generation: u32,
    ) -> Result<Self> {
        if new_generation <= old_generation {
            return Err(CryptoError::InvalidKeyMaterial(
                "new generation must be greater than old generation".into(),
            ));
        }

        // Derive old and new ML-DSA keypairs
        let old_ml_dsa = device_secret.ml_dsa_65_keypair_v(device_id, old_generation)?;
        let new_ml_dsa = device_secret.ml_dsa_65_keypair_v(device_id, new_generation)?;
        let ed25519 = device_secret.ed25519_keypair(device_id)?;

        let new_pk = new_ml_dsa.public_key_bytes();
        let old_pk = old_ml_dsa.public_key_bytes();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        // Old signs new: hybrid V3 signature with context "ml_dsa_rotation"
        let msg_old_signs_new =
            Self::proof_message(device_id, old_generation, new_generation, timestamp, &new_pk);
        let hybrid_sig = HybridSignature::sign_v3(
            &msg_old_signs_new,
            b"ml_dsa_rotation",
            &ed25519.into_signing_key(),
            old_ml_dsa.as_signing_key(),
        )?;
        let old_signs_new = hybrid_sig.to_bytes();

        // New signs old: ML-DSA only (proves possession of new key)
        let msg_new_signs_old =
            Self::proof_message(device_id, new_generation, old_generation, timestamp, &old_pk);
        let new_signs_old = new_ml_dsa.sign(&msg_new_signs_old);

        Ok(Self {
            device_id: device_id.to_string(),
            old_generation,
            new_generation,
            timestamp,
            new_ml_dsa_pk: new_pk,
            old_signs_new,
            new_signs_old,
        })
    }

    /// Verify the continuity proof given the device's Ed25519 public key and old
    /// ML-DSA public key.
    ///
    /// Checks both directions of the cross-signature:
    /// 1. The old key (hybrid V3) signed the new key.
    /// 2. The new key (ML-DSA only) signed the old key.
    pub fn verify(&self, ed25519_pk: &[u8; 32], old_ml_dsa_pk: &[u8]) -> Result<()> {
        if self.new_generation <= self.old_generation {
            return Err(CryptoError::InvalidKeyMaterial(
                "new generation must be greater than old generation".into(),
            ));
        }

        // Check timestamp freshness (reject proofs older than 48 hours)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        if self.timestamp > 0 && (now - self.timestamp) > PROOF_MAX_AGE_SECS {
            return Err(CryptoError::InvalidKeyMaterial(
                format!(
                    "continuity proof expired: created {}s ago, max {}s",
                    now - self.timestamp,
                    PROOF_MAX_AGE_SECS
                ),
            ));
        }

        // Verify old-signs-new (hybrid V3 with context "ml_dsa_rotation")
        let msg_old_signs_new = Self::proof_message(
            &self.device_id,
            self.old_generation,
            self.new_generation,
            self.timestamp,
            &self.new_ml_dsa_pk,
        );
        let hybrid_sig = HybridSignature::from_bytes(&self.old_signs_new)?;
        hybrid_sig.verify_v3(
            &msg_old_signs_new,
            b"ml_dsa_rotation",
            ed25519_pk,
            old_ml_dsa_pk,
        )?;

        // Verify new-signs-old (ML-DSA only)
        let msg_new_signs_old = Self::proof_message(
            &self.device_id,
            self.new_generation,
            self.old_generation,
            self.timestamp,
            old_ml_dsa_pk,
        );
        DevicePqSigningKey::verify(&self.new_ml_dsa_pk, &msg_new_signs_old, &self.new_signs_old)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEVICE_ID: &str = "test-device-001";

    fn test_secret() -> DeviceSecret {
        DeviceSecret::from_bytes(vec![42u8; 32]).unwrap()
    }

    #[test]
    fn valid_proof_verifies() {
        let secret = test_secret();
        let proof = MlDsaContinuityProof::create(&secret, DEVICE_ID, 0, 1).unwrap();

        let ed25519 = secret.ed25519_keypair(DEVICE_ID).unwrap();
        let old_ml_dsa = secret.ml_dsa_65_keypair_v(DEVICE_ID, 0).unwrap();

        proof
            .verify(&ed25519.public_key_bytes(), &old_ml_dsa.public_key_bytes())
            .expect("valid proof should verify");
    }

    #[test]
    fn tampered_old_signs_new_fails() {
        let secret = test_secret();
        let mut proof = MlDsaContinuityProof::create(&secret, DEVICE_ID, 0, 1).unwrap();

        // Flip a byte in old_signs_new
        proof.old_signs_new[10] ^= 0xFF;

        let ed25519 = secret.ed25519_keypair(DEVICE_ID).unwrap();
        let old_ml_dsa = secret.ml_dsa_65_keypair_v(DEVICE_ID, 0).unwrap();

        assert!(
            proof
                .verify(&ed25519.public_key_bytes(), &old_ml_dsa.public_key_bytes())
                .is_err(),
            "tampered old_signs_new should fail verification"
        );
    }

    #[test]
    fn tampered_new_signs_old_fails() {
        let secret = test_secret();
        let mut proof = MlDsaContinuityProof::create(&secret, DEVICE_ID, 0, 1).unwrap();

        // Flip a byte in new_signs_old
        proof.new_signs_old[10] ^= 0xFF;

        let ed25519 = secret.ed25519_keypair(DEVICE_ID).unwrap();
        let old_ml_dsa = secret.ml_dsa_65_keypair_v(DEVICE_ID, 0).unwrap();

        assert!(
            proof
                .verify(&ed25519.public_key_bytes(), &old_ml_dsa.public_key_bytes())
                .is_err(),
            "tampered new_signs_old should fail verification"
        );
    }

    #[test]
    fn wrong_ed25519_pk_fails() {
        let secret = test_secret();
        let proof = MlDsaContinuityProof::create(&secret, DEVICE_ID, 0, 1).unwrap();

        // Use a different device's Ed25519 key
        let wrong_ed25519 = secret.ed25519_keypair("wrong-device").unwrap();
        let old_ml_dsa = secret.ml_dsa_65_keypair_v(DEVICE_ID, 0).unwrap();

        assert!(
            proof
                .verify(
                    &wrong_ed25519.public_key_bytes(),
                    &old_ml_dsa.public_key_bytes()
                )
                .is_err(),
            "wrong ed25519 pk should fail verification"
        );
    }

    #[test]
    fn wrong_old_ml_dsa_pk_fails() {
        let secret = test_secret();
        let proof = MlDsaContinuityProof::create(&secret, DEVICE_ID, 0, 1).unwrap();

        let ed25519 = secret.ed25519_keypair(DEVICE_ID).unwrap();
        // Use a different device's ML-DSA key as the "old" key
        let wrong_ml_dsa = secret.ml_dsa_65_keypair("wrong-device").unwrap();

        assert!(
            proof
                .verify(
                    &ed25519.public_key_bytes(),
                    &wrong_ml_dsa.public_key_bytes()
                )
                .is_err(),
            "wrong old ML-DSA pk should fail verification"
        );
    }

    #[test]
    fn generation_rollback_rejected() {
        let secret = test_secret();

        // new_gen == old_gen
        let result = MlDsaContinuityProof::create(&secret, DEVICE_ID, 1, 1);
        assert!(result.is_err(), "equal generations should be rejected");

        // new_gen < old_gen
        let result = MlDsaContinuityProof::create(&secret, DEVICE_ID, 2, 1);
        assert!(
            result.is_err(),
            "new_gen < old_gen should be rejected"
        );
    }

    #[test]
    fn generation_gap_works() {
        let secret = test_secret();

        // Skip from gen 0 to gen 3
        let proof = MlDsaContinuityProof::create(&secret, DEVICE_ID, 0, 3).unwrap();

        let ed25519 = secret.ed25519_keypair(DEVICE_ID).unwrap();
        let old_ml_dsa = secret.ml_dsa_65_keypair_v(DEVICE_ID, 0).unwrap();

        proof
            .verify(&ed25519.public_key_bytes(), &old_ml_dsa.public_key_bytes())
            .expect("generation gap proof should verify");
    }

    #[test]
    fn mismatched_device_id_fails() {
        let secret = test_secret();
        let mut proof = MlDsaContinuityProof::create(&secret, DEVICE_ID, 0, 1).unwrap();

        // Change the device_id in the proof — signature should no longer verify
        // because device_id is bound into the signed message.
        proof.device_id = "wrong-device-id".to_string();

        let ed25519 = secret.ed25519_keypair(DEVICE_ID).unwrap();
        let old_ml_dsa = secret.ml_dsa_65_keypair_v(DEVICE_ID, 0).unwrap();

        assert!(
            proof
                .verify(&ed25519.public_key_bytes(), &old_ml_dsa.public_key_bytes())
                .is_err(),
            "mismatched device_id should fail verification"
        );
    }
}
