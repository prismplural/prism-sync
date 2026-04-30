//! Post-quantum cryptographic primitives for prism-sync.
//!
//! Provides hybrid signatures (Ed25519 + ML-DSA-65) and typed model types
//! for the PQ bootstrap protocol.

pub mod continuity_proof;
pub mod hybrid_kem;
pub mod models;
pub use models::*;

use crate::error::{CryptoError, Result};
use ed25519_dalek::Signer as Ed25519Signer;
use ml_dsa::signature::Signer as MlDsaSigner;
use ml_dsa::signature::Verifier as MlDsaVerifier;
use ml_dsa::MlDsa65;

/// IETF composite-signatures draft prefix.
const COMPOSITE_PREFIX: &[u8] = b"CompositeAlgorithmSignatures2025";

/// Prism-specific label (not an X.509 OID, but follows the draft pattern).
const PRISM_LABEL: &[u8] = b"PrismHybridSig-v3";

/// Build the labeled message representative per IETF composite-sigs-15 pattern.
///
/// M' = Prefix || Label || u8(context.len()) || context || SHA-512(message)
///
/// The context must be <= 255 bytes.
pub fn build_hybrid_message_representative(context: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    use sha2::{Digest, Sha512};
    if context.len() > 255 {
        return Err(CryptoError::InvalidKeyMaterial(format!(
            "context must be <= 255 bytes, got {}",
            context.len()
        )));
    }
    let hash = Sha512::digest(message);
    let mut m_prime =
        Vec::with_capacity(COMPOSITE_PREFIX.len() + PRISM_LABEL.len() + 1 + context.len() + 64);
    m_prime.extend_from_slice(COMPOSITE_PREFIX);
    m_prime.extend_from_slice(PRISM_LABEL);
    m_prime.push(context.len() as u8);
    m_prime.extend_from_slice(context);
    m_prime.extend_from_slice(&hash);
    Ok(m_prime)
}

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
    /// leaking which signature failed via timing or outward errors, both are
    /// always evaluated before returning a generic verification error.
    pub fn verify(&self, message: &[u8], ed25519_pk: &[u8; 32], ml_dsa_pk: &[u8]) -> Result<()> {
        // Verify Ed25519
        let ed_result = (|| -> std::result::Result<(), ()> {
            let vk = ed25519_dalek::VerifyingKey::from_bytes(ed25519_pk).map_err(|_| ())?;
            let sig = ed25519_dalek::Signature::from_slice(&self.ed25519_sig).map_err(|_| ())?;
            vk.verify_strict(message, &sig).map_err(|_| ())?;
            Ok(())
        })();

        // Verify ML-DSA-65
        let ml_result = (|| -> std::result::Result<(), ()> {
            let enc_arr =
                ml_dsa::EncodedVerifyingKey::<MlDsa65>::try_from(ml_dsa_pk).map_err(|_| ())?;
            let vk = ml_dsa::VerifyingKey::<MlDsa65>::decode(&enc_arr);

            let sig = ml_dsa::Signature::<MlDsa65>::try_from(self.ml_dsa_65_sig.as_slice())
                .map_err(|_| ())?;
            vk.verify(message, &sig).map_err(|_| ())?;
            Ok(())
        })();

        // Both must succeed — check both before returning
        match (ed_result, ml_result) {
            (Ok(()), Ok(())) => Ok(()),
            _ => Err(CryptoError::SignatureVerificationFailed(
                "hybrid signature verification failed".into(),
            )),
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

    /// Sign with V3 labeled WNS construction.
    ///
    /// Both algorithms sign the same message representative M', built from the
    /// IETF composite-signatures draft pattern with a Prism-specific label and
    /// caller-supplied context string.
    pub fn sign_v3(
        message: &[u8],
        context: &[u8],
        ed25519_sk: &ed25519_dalek::SigningKey,
        ml_dsa_sk: &impl MlDsaSigner<ml_dsa::Signature<MlDsa65>>,
    ) -> Result<Self> {
        let m_prime = build_hybrid_message_representative(context, message)?;
        let ed_sig = ed25519_sk.sign(&m_prime);
        let ml_sig: ml_dsa::Signature<MlDsa65> = ml_dsa_sk.sign(&m_prime);
        let ml_sig_encoded = ml_sig.encode();

        Ok(HybridSignature {
            ed25519_sig: ed_sig.to_bytes().to_vec(),
            ml_dsa_65_sig: AsRef::<[u8]>::as_ref(&ml_sig_encoded).to_vec(),
        })
    }

    /// Verify V3 labeled WNS signature.
    ///
    /// Reconstructs the message representative M' from the supplied context and
    /// message, then delegates to [`verify`].
    pub fn verify_v3(
        &self,
        message: &[u8],
        context: &[u8],
        ed25519_pk: &[u8; 32],
        ml_dsa_pk: &[u8],
    ) -> Result<()> {
        let m_prime = build_hybrid_message_representative(context, message)?;
        self.verify(&m_prime, ed25519_pk, ml_dsa_pk)
    }

    /// Return the byte length of the hybrid signature encoded at the start of
    /// `data`, accepting trailing bytes owned by an outer envelope.
    ///
    /// # Errors
    ///
    /// Returns an error if `data` is truncated, has invalid component lengths,
    /// or if offset arithmetic overflows on the target platform.
    pub fn encoded_len(data: &[u8]) -> Result<usize> {
        let ed_len = read_len_le(data, 0, "ed25519")?;
        if ed_len != ED25519_SIG_LEN {
            return Err(CryptoError::InvalidKeyMaterial(format!(
                "ed25519 signature: expected {ED25519_SIG_LEN} bytes, got {ed_len}"
            )));
        }

        let ml_len_offset = checked_add(4, ed_len, "ml-dsa length offset")?;
        let ml_len = read_len_le(data, ml_len_offset, "ml-dsa-65")?;
        if ml_len != ML_DSA_65_SIG_LEN {
            return Err(CryptoError::InvalidKeyMaterial(format!(
                "ml-dsa-65 signature: expected {ML_DSA_65_SIG_LEN} bytes, got {ml_len}"
            )));
        }

        let ml_sig_offset = checked_add(ml_len_offset, 4, "ml-dsa signature offset")?;
        let expected_total = checked_add(ml_sig_offset, ml_len, "hybrid signature length")?;
        if data.len() < expected_total {
            return Err(CryptoError::InvalidKeyMaterial(format!(
                "hybrid signature truncated: expected {expected_total} bytes, got {}",
                data.len()
            )));
        }

        Ok(expected_total)
    }

    /// Deserialize from wire format, validating expected signature sizes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let expected_total = Self::encoded_len(data)?;
        if data.len() != expected_total {
            return Err(CryptoError::InvalidKeyMaterial(format!(
                "hybrid signature has trailing data: expected {expected_total} bytes, got {}",
                data.len()
            )));
        }

        let ed_start = 4;
        let ed_end = ed_start + ED25519_SIG_LEN;
        let ml_start = ed_end + 4;
        let ml_end = ml_start + ML_DSA_65_SIG_LEN;

        let ed_sig = data[ed_start..ed_end].to_vec();
        let ml_sig = data[ml_start..ml_end].to_vec();

        Ok(HybridSignature { ed25519_sig: ed_sig, ml_dsa_65_sig: ml_sig })
    }
}

fn read_len_le(data: &[u8], offset: usize, label: &str) -> Result<usize> {
    let end = checked_add(offset, 4, "length field end")?;
    let bytes = data.get(offset..end).ok_or_else(|| {
        CryptoError::InvalidKeyMaterial(format!(
            "hybrid signature truncated: missing {label} length"
        ))
    })?;
    let arr: [u8; 4] = bytes.try_into().map_err(|_| {
        CryptoError::InvalidKeyMaterial(format!(
            "hybrid signature malformed: invalid {label} length"
        ))
    })?;
    Ok(u32::from_le_bytes(arr) as usize)
}

fn checked_add(lhs: usize, rhs: usize, what: &str) -> Result<usize> {
    lhs.checked_add(rhs).ok_or_else(|| {
        CryptoError::InvalidKeyMaterial(format!("hybrid signature length overflow: {what}"))
    })
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

        sig.verify(msg, &ed_pk, ml_pk_bytes).expect("verification should succeed");
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

    #[test]
    fn hybrid_signature_encoded_len_accepts_trailing_payload() {
        let ed_sk = ed25519_keypair();
        let ml_sk = ml_dsa_keypair();
        let sig = HybridSignature::sign(b"test", &ed_sk, &ml_sk);
        let mut bytes = sig.to_bytes();
        let sig_len = bytes.len();
        bytes.extend_from_slice(br#"{"entries":[]}"#);

        assert_eq!(HybridSignature::encoded_len(&bytes).unwrap(), sig_len);
        assert!(HybridSignature::from_bytes(&bytes).is_err());
    }

    #[test]
    fn hybrid_signature_from_bytes_rejects_oversized_ed25519_len_without_panic() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());

        let result = std::panic::catch_unwind(|| HybridSignature::from_bytes(&bytes));
        assert!(result.is_ok(), "oversized ed25519 length should not panic");
        assert!(result.unwrap().is_err());
    }

    #[test]
    fn hybrid_signature_from_bytes_rejects_oversized_ml_dsa_len_without_panic() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(ED25519_SIG_LEN as u32).to_le_bytes());
        bytes.extend_from_slice(&[0u8; ED25519_SIG_LEN]);
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());

        let result = std::panic::catch_unwind(|| HybridSignature::from_bytes(&bytes));
        assert!(result.is_ok(), "oversized ML-DSA length should not panic");
        assert!(result.unwrap().is_err());
    }

    #[test]
    fn hybrid_signature_verify_error_does_not_name_failed_component() {
        let ed_sk = ed25519_keypair();
        let ml_sk = ml_dsa_keypair();
        let sig = HybridSignature::sign(b"test", &ed_sk, &ml_sk);
        let wrong_ed_sk = ed25519_keypair();

        let ml_vk = ml_sk.verifying_key();
        let ml_pk_encoded = ml_vk.encode();
        let ml_pk_bytes = AsRef::<[u8]>::as_ref(&ml_pk_encoded);
        let err =
            sig.verify(b"test", &wrong_ed_sk.verifying_key().to_bytes(), ml_pk_bytes).unwrap_err();
        let err = err.to_string();

        assert!(err.contains("hybrid signature verification failed"), "got: {err}");
        assert!(!err.contains("ed25519"), "component detail leaked: {err}");
        assert!(!err.contains("ml-dsa"), "component detail leaked: {err}");
    }

    #[test]
    fn v3_sign_verify_round_trip() {
        let ed_sk = ed25519_keypair();
        let ml_sk = ml_dsa_keypair();
        let msg = b"V3 round trip test";
        let ctx = b"test_context";

        let sig =
            HybridSignature::sign_v3(msg, ctx, &ed_sk, &ml_sk).expect("sign_v3 should succeed");

        let ed_pk = ed_sk.verifying_key().to_bytes();
        let ml_vk = ml_sk.verifying_key();
        let ml_pk_encoded = ml_vk.encode();
        let ml_pk_bytes = AsRef::<[u8]>::as_ref(&ml_pk_encoded);

        sig.verify_v3(msg, ctx, &ed_pk, ml_pk_bytes).expect("V3 verification should succeed");
    }

    #[test]
    fn v3_rejects_tampered_message() {
        let ed_sk = ed25519_keypair();
        let ml_sk = ml_dsa_keypair();
        let ctx = b"test_context";

        let sig = HybridSignature::sign_v3(b"original", ctx, &ed_sk, &ml_sk)
            .expect("sign_v3 should succeed");

        let ed_pk = ed_sk.verifying_key().to_bytes();
        let ml_vk = ml_sk.verifying_key();
        let ml_pk_encoded = ml_vk.encode();
        let ml_pk_bytes = AsRef::<[u8]>::as_ref(&ml_pk_encoded);

        assert!(sig.verify_v3(b"tampered", ctx, &ed_pk, ml_pk_bytes).is_err());
    }

    #[test]
    fn v3_rejects_wrong_context() {
        let ed_sk = ed25519_keypair();
        let ml_sk = ml_dsa_keypair();
        let msg = b"context test";

        let sig = HybridSignature::sign_v3(msg, b"context_a", &ed_sk, &ml_sk)
            .expect("sign_v3 should succeed");

        let ed_pk = ed_sk.verifying_key().to_bytes();
        let ml_vk = ml_sk.verifying_key();
        let ml_pk_encoded = ml_vk.encode();
        let ml_pk_bytes = AsRef::<[u8]>::as_ref(&ml_pk_encoded);

        assert!(sig.verify_v3(msg, b"context_b", &ed_pk, ml_pk_bytes).is_err());
    }

    #[test]
    fn v2_signature_does_not_verify_under_v3() {
        let ed_sk = ed25519_keypair();
        let ml_sk = ml_dsa_keypair();
        let msg = b"cross-version test";
        let ctx = b"test_context";

        // Sign with V2 (bare WNS — signs message directly)
        let v2_sig = HybridSignature::sign(msg, &ed_sk, &ml_sk);

        let ed_pk = ed_sk.verifying_key().to_bytes();
        let ml_vk = ml_sk.verifying_key();
        let ml_pk_encoded = ml_vk.encode();
        let ml_pk_bytes = AsRef::<[u8]>::as_ref(&ml_pk_encoded);

        // V2 sig should fail V3 verification (different message construction)
        assert!(v2_sig.verify_v3(msg, ctx, &ed_pk, ml_pk_bytes).is_err());
    }

    #[test]
    fn build_hybrid_message_representative_pinned_vector() {
        use sha2::{Digest, Sha512};

        let context = b"test";
        let message = b"hello";

        let m_prime = build_hybrid_message_representative(context, message)
            .expect("should succeed with small context");

        // Verify structure: prefix || label || len(context) || context || SHA-512(message)
        let hash = Sha512::digest(message);

        let mut expected = Vec::new();
        expected.extend_from_slice(b"CompositeAlgorithmSignatures2025");
        expected.extend_from_slice(b"PrismHybridSig-v3");
        expected.push(4); // context.len()
        expected.extend_from_slice(b"test");
        expected.extend_from_slice(&hash);

        assert_eq!(m_prime, expected);
        // Total length: 32 + 17 + 1 + 4 + 64 = 118
        assert_eq!(m_prime.len(), 118);
    }

    #[test]
    fn oversize_context_returns_error_not_panic() {
        let big_context = vec![0x42u8; 256]; // 1 byte over the limit
        let message = b"test message";
        let result = build_hybrid_message_representative(&big_context, message);
        assert!(result.is_err(), "context > 255 bytes should return Err, not panic");

        // Exactly 255 should still work
        let max_context = vec![0x42u8; 255];
        let result = build_hybrid_message_representative(&max_context, message);
        assert!(result.is_ok(), "context of exactly 255 bytes should succeed");
    }

    #[test]
    fn sign_v3_oversize_context_returns_error() {
        let ed_sk = ed25519_keypair();
        let ml_sk = ml_dsa_keypair();
        let big_context = vec![0x42u8; 256];
        let result = HybridSignature::sign_v3(b"msg", &big_context, &ed_sk, &ml_sk);
        assert!(result.is_err(), "sign_v3 with oversize context should return Err");
    }
}
