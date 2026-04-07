//! Post-quantum cryptographic primitives for prism-sync.
//!
//! Provides hybrid signatures (Ed25519 + ML-DSA-65) and typed model types
//! for the PQ bootstrap protocol.

pub mod hybrid_kem;
pub mod models;
pub use models::*;

use crate::error::{CryptoError, Result};
use ed25519_dalek::Signer as Ed25519Signer;
use ed25519_dalek::Verifier as Ed25519Verifier;
use ml_dsa::signature::Signer as MlDsaSigner;
use ml_dsa::signature::Verifier as MlDsaVerifier;
use ml_dsa::MlDsa65;

/// Expected size of an Ed25519 signature in bytes.
const ED25519_SIG_LEN: usize = 64;

/// Expected size of an ML-DSA-65 signature in bytes.
const ML_DSA_65_SIG_LEN: usize = 3309;

/// A hybrid signature combining Ed25519 (classical) and ML-DSA-65 (post-quantum).
/// Both signatures must verify for the hybrid to be valid.
///
/// Wire format: `[4B ed25519_len LE][ed25519_sig][4B ml_dsa_len LE][ml_dsa_sig]`
#[derive(Clone, Debug)]
pub struct HybridSignature {
    /// The Ed25519 signature (64 bytes).
    pub ed25519_sig: Vec<u8>,
    /// The ML-DSA-65 signature (3309 bytes).
    pub ml_dsa_65_sig: Vec<u8>,
}

impl HybridSignature {
    /// Sign `message` with both an Ed25519 key and an ML-DSA-65 key.
    /// Accepts any ML-DSA-65 signer (both `SigningKey` and `ExpandedSigningKey`).
    pub fn sign(
        message: &[u8],
        ed25519_sk: &ed25519_dalek::SigningKey,
        ml_dsa_sk: &impl MlDsaSigner<ml_dsa::Signature<MlDsa65>>,
    ) -> Self {
        let ed_sig = ed25519_sk.sign(message);
        let ml_sig: ml_dsa::Signature<MlDsa65> = ml_dsa_sk.sign(message);
        let ml_sig_encoded = ml_sig.encode();

        HybridSignature {
            ed25519_sig: ed_sig.to_bytes().to_vec(),
            ml_dsa_65_sig: AsRef::<[u8]>::as_ref(&ml_sig_encoded).to_vec(),
        }
    }

    /// Verify both signatures over `message`.
    ///
    /// Both the Ed25519 and ML-DSA-65 signatures are checked. To avoid
    /// leaking which signature failed via timing, both are always evaluated
    /// before returning an error.
    pub fn verify(&self, message: &[u8], ed25519_pk: &[u8; 32], ml_dsa_pk: &[u8]) -> Result<()> {
        // Verify Ed25519
        let ed_result = (|| -> Result<()> {
            let vk = ed25519_dalek::VerifyingKey::from_bytes(ed25519_pk)
                .map_err(|e| CryptoError::InvalidKeyMaterial(format!("ed25519 public key: {e}")))?;
            let sig = ed25519_dalek::Signature::from_slice(&self.ed25519_sig)
                .map_err(|e| CryptoError::InvalidKeyMaterial(format!("ed25519 signature: {e}")))?;
            vk.verify(message, &sig)
                .map_err(|e| CryptoError::SignatureVerificationFailed(format!("ed25519: {e}")))?;
            Ok(())
        })();

        // Verify ML-DSA-65
        let ml_result = (|| -> Result<()> {
            let enc_arr =
                ml_dsa::EncodedVerifyingKey::<MlDsa65>::try_from(ml_dsa_pk).map_err(|_| {
                    CryptoError::InvalidKeyMaterial(format!(
                        "ml-dsa-65 public key: expected {} bytes, got {}",
                        std::mem::size_of::<ml_dsa::EncodedVerifyingKey<MlDsa65>>(),
                        ml_dsa_pk.len()
                    ))
                })?;
            let vk = ml_dsa::VerifyingKey::<MlDsa65>::decode(&enc_arr);

            let sig = ml_dsa::Signature::<MlDsa65>::try_from(self.ml_dsa_65_sig.as_slice())
                .map_err(|e| {
                    CryptoError::InvalidKeyMaterial(format!("ml-dsa-65 signature: {e}"))
                })?;
            vk.verify(message, &sig)
                .map_err(|e| CryptoError::SignatureVerificationFailed(format!("ml-dsa-65: {e}")))?;
            Ok(())
        })();

        // Both must succeed — check both before returning
        match (ed_result, ml_result) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(e), _) => Err(e),
            (_, Err(e)) => Err(e),
        }
    }

    /// Serialize to wire format.
    ///
    /// Format: `[4B ed25519_len LE][ed25519_sig][4B ml_dsa_len LE][ml_dsa_sig]`
    pub fn to_bytes(&self) -> Vec<u8> {
        let ed_len = self.ed25519_sig.len() as u32;
        let ml_len = self.ml_dsa_65_sig.len() as u32;
        let total = 4 + self.ed25519_sig.len() + 4 + self.ml_dsa_65_sig.len();
        let mut buf = Vec::with_capacity(total);
        buf.extend_from_slice(&ed_len.to_le_bytes());
        buf.extend_from_slice(&self.ed25519_sig);
        buf.extend_from_slice(&ml_len.to_le_bytes());
        buf.extend_from_slice(&self.ml_dsa_65_sig);
        buf
    }

    /// Deserialize from wire format, validating expected signature sizes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 8 {
            return Err(CryptoError::InvalidKeyMaterial(
                "hybrid signature too short: need at least 8 bytes for length headers".into(),
            ));
        }

        let ed_len = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;

        if data.len() < 4 + ed_len + 4 {
            return Err(CryptoError::InvalidKeyMaterial(format!(
                "hybrid signature truncated: ed25519_len={ed_len} but only {} bytes remain",
                data.len() - 4
            )));
        }

        let ed_sig = data[4..4 + ed_len].to_vec();

        let ml_offset = 4 + ed_len;
        let ml_len =
            u32::from_le_bytes(data[ml_offset..ml_offset + 4].try_into().unwrap()) as usize;

        if data.len() < ml_offset + 4 + ml_len {
            return Err(CryptoError::InvalidKeyMaterial(format!(
                "hybrid signature truncated: ml_dsa_len={ml_len} but only {} bytes remain",
                data.len() - ml_offset - 4
            )));
        }

        let expected_total = ml_offset + 4 + ml_len;
        if data.len() != expected_total {
            return Err(CryptoError::InvalidKeyMaterial(format!(
                "hybrid signature has trailing data: expected {expected_total} bytes, got {}",
                data.len()
            )));
        }

        let ml_sig = data[ml_offset + 4..ml_offset + 4 + ml_len].to_vec();

        if ed_sig.len() != ED25519_SIG_LEN {
            return Err(CryptoError::InvalidKeyMaterial(format!(
                "ed25519 signature: expected {ED25519_SIG_LEN} bytes, got {}",
                ed_sig.len()
            )));
        }

        if ml_sig.len() != ML_DSA_65_SIG_LEN {
            return Err(CryptoError::InvalidKeyMaterial(format!(
                "ml-dsa-65 signature: expected {ML_DSA_65_SIG_LEN} bytes, got {}",
                ml_sig.len()
            )));
        }

        Ok(HybridSignature {
            ed25519_sig: ed_sig,
            ml_dsa_65_sig: ml_sig,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use ml_dsa::signature::Keypair;
    use ml_dsa::{KeyGen, MlDsa65};

    /// Generate an Ed25519 keypair for testing.
    fn ed25519_keypair() -> SigningKey {
        SigningKey::generate(&mut rand::rngs::OsRng)
    }

    /// Generate an ML-DSA-65 keypair for testing using a random seed.
    fn ml_dsa_keypair() -> ml_dsa::SigningKey<MlDsa65> {
        use getrandom::rand_core::UnwrapErr;
        use getrandom::SysRng;
        let mut rng = UnwrapErr(SysRng);
        MlDsa65::key_gen(&mut rng)
    }

    #[test]
    fn hybrid_signature_round_trip() {
        let ed_sk = ed25519_keypair();
        let ml_sk = ml_dsa_keypair();
        let msg = b"Hello, hybrid world!";

        let sig = HybridSignature::sign(msg, &ed_sk, &ml_sk);

        let ed_pk = ed_sk.verifying_key().to_bytes();
        let ml_vk = ml_sk.verifying_key();
        let ml_pk_encoded = ml_vk.encode();
        let ml_pk_bytes = AsRef::<[u8]>::as_ref(&ml_pk_encoded);

        sig.verify(msg, &ed_pk, ml_pk_bytes)
            .expect("verification should succeed");
    }

    #[test]
    fn hybrid_signature_serialize_deserialize() {
        let ed_sk = ed25519_keypair();
        let ml_sk = ml_dsa_keypair();
        let msg = b"Serialize me";

        let sig = HybridSignature::sign(msg, &ed_sk, &ml_sk);
        let bytes = sig.to_bytes();
        let sig2 = HybridSignature::from_bytes(&bytes).expect("deserialization should succeed");

        let ed_pk = ed_sk.verifying_key().to_bytes();
        let ml_vk = ml_sk.verifying_key();
        let ml_pk_encoded = ml_vk.encode();
        let ml_pk_bytes = AsRef::<[u8]>::as_ref(&ml_pk_encoded);

        sig2.verify(msg, &ed_pk, ml_pk_bytes)
            .expect("verification after round-trip should succeed");
    }

    #[test]
    fn hybrid_signature_tamper_ed25519_fails() {
        let ed_sk = ed25519_keypair();
        let ml_sk = ml_dsa_keypair();
        let msg = b"Don't tamper with me";

        let mut sig = HybridSignature::sign(msg, &ed_sk, &ml_sk);
        // Flip a bit in the ed25519 signature
        sig.ed25519_sig[0] ^= 0xFF;

        let ed_pk = ed_sk.verifying_key().to_bytes();
        let ml_vk = ml_sk.verifying_key();
        let ml_pk_encoded = ml_vk.encode();
        let ml_pk_bytes = AsRef::<[u8]>::as_ref(&ml_pk_encoded);

        assert!(sig.verify(msg, &ed_pk, ml_pk_bytes).is_err());
    }

    #[test]
    fn hybrid_signature_tamper_ml_dsa_fails() {
        let ed_sk = ed25519_keypair();
        let ml_sk = ml_dsa_keypair();
        let msg = b"Don't tamper with me either";

        let mut sig = HybridSignature::sign(msg, &ed_sk, &ml_sk);
        // Flip a bit in the ML-DSA signature
        sig.ml_dsa_65_sig[0] ^= 0xFF;

        let ed_pk = ed_sk.verifying_key().to_bytes();
        let ml_vk = ml_sk.verifying_key();
        let ml_pk_encoded = ml_vk.encode();
        let ml_pk_bytes = AsRef::<[u8]>::as_ref(&ml_pk_encoded);

        assert!(sig.verify(msg, &ed_pk, ml_pk_bytes).is_err());
    }

    #[test]
    fn hybrid_signature_tamper_message_fails() {
        let ed_sk = ed25519_keypair();
        let ml_sk = ml_dsa_keypair();
        let msg_a = b"Message A";
        let msg_b = b"Message B";

        let sig = HybridSignature::sign(msg_a, &ed_sk, &ml_sk);

        let ed_pk = ed_sk.verifying_key().to_bytes();
        let ml_vk = ml_sk.verifying_key();
        let ml_pk_encoded = ml_vk.encode();
        let ml_pk_bytes = AsRef::<[u8]>::as_ref(&ml_pk_encoded);

        assert!(sig.verify(msg_b, &ed_pk, ml_pk_bytes).is_err());
    }

    #[test]
    fn hybrid_signature_expected_sizes() {
        let ed_sk = ed25519_keypair();
        let ml_sk = ml_dsa_keypair();
        let msg = b"Size check";

        let sig = HybridSignature::sign(msg, &ed_sk, &ml_sk);

        assert_eq!(sig.ed25519_sig.len(), ED25519_SIG_LEN);
        assert_eq!(sig.ml_dsa_65_sig.len(), ML_DSA_65_SIG_LEN);

        let bytes = sig.to_bytes();
        assert_eq!(bytes.len(), 4 + ED25519_SIG_LEN + 4 + ML_DSA_65_SIG_LEN);
        assert_eq!(bytes.len(), 3381);
    }

    #[test]
    fn hybrid_signature_from_bytes_too_short() {
        // Empty
        assert!(HybridSignature::from_bytes(&[]).is_err());
        // Just 4 bytes (one length header, no data)
        assert!(HybridSignature::from_bytes(&[64, 0, 0, 0]).is_err());
        // Valid ed25519 length but truncated
        let mut short = vec![0u8; 4 + ED25519_SIG_LEN + 4];
        short[0..4].copy_from_slice(&(ED25519_SIG_LEN as u32).to_le_bytes());
        // ml_dsa length says 3309 but no data follows
        let ml_offset = 4 + ED25519_SIG_LEN;
        short[ml_offset..ml_offset + 4].copy_from_slice(&(ML_DSA_65_SIG_LEN as u32).to_le_bytes());
        assert!(HybridSignature::from_bytes(&short).is_err());
    }

    #[test]
    fn hybrid_signature_from_bytes_trailing_data_rejected() {
        let ed_sk = ed25519_keypair();
        let ml_sk = ml_dsa_keypair();
        let sig = HybridSignature::sign(b"test", &ed_sk, &ml_sk);
        let mut bytes = sig.to_bytes();
        bytes.push(0xFF); // append trailing byte
        assert!(HybridSignature::from_bytes(&bytes).is_err());
    }
}
