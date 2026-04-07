//! Sharing identity derivation from DEK.
//!
//! Derives user-level sharing identity keys (Ed25519 + ML-DSA-65) from the
//! DEK, sharing_id, and identity_generation. These long-lived identity keys
//! are used for the asynchronous remote sharing bootstrap (Phase 4).

use ed25519_dalek::SigningKey as Ed25519SigningKey;
use ml_dsa::MlDsa65;
use zeroize::{Zeroize, Zeroizing};

use prism_sync_crypto::kdf;

use crate::error::{CoreError, Result};

/// Derive the 32-byte sharing identity seed from the DEK.
///
/// salt = sharing_id_bytes (16 raw bytes) || identity_generation (4 bytes BE)
/// info = "prism_sharing_identity_v1"
pub fn derive_sharing_identity_seed(
    dek: &[u8],
    sharing_id_bytes: &[u8; 16],
    identity_generation: u32,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut salt = Vec::with_capacity(20);
    salt.extend_from_slice(sharing_id_bytes);
    salt.extend_from_slice(&identity_generation.to_be_bytes());

    kdf::derive_subkey(dek, &salt, b"prism_sharing_identity_v1").map_err(CoreError::from)
}

/// Derive the Ed25519 keypair from a 32-byte sharing identity seed.
///
/// Uses HKDF with info "prism_sharing_ed25519_v1" to derive the Ed25519
/// secret key bytes.
pub fn derive_sharing_ed25519_keypair(seed: &[u8; 32]) -> Result<(Ed25519SigningKey, [u8; 32])> {
    let sub_seed = kdf::derive_subkey(seed, &[], b"prism_sharing_ed25519_v1")?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&sub_seed);
    let signing_key = Ed25519SigningKey::from_bytes(&arr);
    let public_key = signing_key.verifying_key().to_bytes();
    arr.zeroize();
    Ok((signing_key, public_key))
}

/// Derive the ML-DSA-65 expanded signing key from a 32-byte sharing identity seed.
///
/// Uses HKDF with info "prism_sharing_ml_dsa_65_v1" to derive a sub-seed,
/// then uses `ExpandedSigningKey::from_seed` for deterministic keygen.
///
/// Returns the expanded signing key and the encoded public key bytes.
pub fn derive_sharing_ml_dsa_keypair(
    seed: &[u8; 32],
) -> Result<(ml_dsa::ExpandedSigningKey<MlDsa65>, Vec<u8>)> {
    let sub_seed = kdf::derive_subkey(seed, &[], b"prism_sharing_ml_dsa_65_v1")?;
    let mut seed_arr = ml_dsa::B32::try_from(sub_seed.as_slice()).map_err(|_| {
        CoreError::Crypto(prism_sync_crypto::CryptoError::KdfFailed(
            "ML-DSA seed length mismatch".into(),
        ))
    })?;
    let signing_key = ml_dsa::ExpandedSigningKey::<MlDsa65>::from_seed(&seed_arr);
    seed_arr.zeroize();

    let vk = signing_key.verifying_key();
    let encoded = vk.encode();
    let pk_bytes = AsRef::<[u8]>::as_ref(&encoded).to_vec();

    Ok((signing_key, pk_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_dek() -> Vec<u8> {
        vec![42u8; 32]
    }

    fn test_sharing_id() -> [u8; 16] {
        [0xAA; 16]
    }

    #[test]
    fn identity_seed_deterministic() {
        let dek = test_dek();
        let sid = test_sharing_id();
        let s1 = derive_sharing_identity_seed(&dek, &sid, 0).unwrap();
        let s2 = derive_sharing_identity_seed(&dek, &sid, 0).unwrap();
        assert_eq!(*s1, *s2);
        assert_eq!(s1.len(), 32);
    }

    #[test]
    fn different_sharing_ids_different_seeds() {
        let dek = test_dek();
        let s1 = derive_sharing_identity_seed(&dek, &[0xAA; 16], 0).unwrap();
        let s2 = derive_sharing_identity_seed(&dek, &[0xBB; 16], 0).unwrap();
        assert_ne!(*s1, *s2);
    }

    #[test]
    fn different_generations_different_seeds() {
        let dek = test_dek();
        let sid = test_sharing_id();
        let s1 = derive_sharing_identity_seed(&dek, &sid, 0).unwrap();
        let s2 = derive_sharing_identity_seed(&dek, &sid, 1).unwrap();
        assert_ne!(*s1, *s2);
    }

    #[test]
    fn ed25519_keypair_deterministic() {
        let dek = test_dek();
        let sid = test_sharing_id();
        let seed = derive_sharing_identity_seed(&dek, &sid, 0).unwrap();
        let mut seed_arr = [0u8; 32];
        seed_arr.copy_from_slice(&seed);

        let (_, pk1) = derive_sharing_ed25519_keypair(&seed_arr).unwrap();
        let (_, pk2) = derive_sharing_ed25519_keypair(&seed_arr).unwrap();
        assert_eq!(pk1, pk2);
    }

    #[test]
    fn ed25519_different_seeds_different_keys() {
        let (_, pk1) = derive_sharing_ed25519_keypair(&[1u8; 32]).unwrap();
        let (_, pk2) = derive_sharing_ed25519_keypair(&[2u8; 32]).unwrap();
        assert_ne!(pk1, pk2);
    }

    #[test]
    fn ml_dsa_keypair_deterministic() {
        let (_, pk1) = derive_sharing_ml_dsa_keypair(&[42u8; 32]).unwrap();
        let (_, pk2) = derive_sharing_ml_dsa_keypair(&[42u8; 32]).unwrap();
        assert_eq!(pk1, pk2);
        assert_eq!(pk1.len(), 1952);
    }

    #[test]
    fn ml_dsa_different_seeds_different_keys() {
        let (_, pk1) = derive_sharing_ml_dsa_keypair(&[1u8; 32]).unwrap();
        let (_, pk2) = derive_sharing_ml_dsa_keypair(&[2u8; 32]).unwrap();
        assert_ne!(pk1, pk2);
    }

    #[test]
    fn full_derivation_pipeline() {
        let dek = test_dek();
        let sid = test_sharing_id();
        let seed = derive_sharing_identity_seed(&dek, &sid, 0).unwrap();
        let mut seed_arr = [0u8; 32];
        seed_arr.copy_from_slice(&seed);

        let (ed_sk, ed_pk) = derive_sharing_ed25519_keypair(&seed_arr).unwrap();
        let (ml_sk, ml_pk) = derive_sharing_ml_dsa_keypair(&seed_arr).unwrap();

        // Verify the keys work for signing
        use ed25519_dalek::Signer;
        let msg = b"test message";
        let sig = ed_sk.sign(msg);
        ed25519_dalek::VerifyingKey::from_bytes(&ed_pk)
            .unwrap()
            .verify_strict(msg, &sig)
            .unwrap();

        use ml_dsa::signature::Signer as MlSigner;
        let ml_sig = ml_sk.sign(msg);
        let ml_sig_bytes = ml_sig.encode();
        prism_sync_crypto::DevicePqSigningKey::verify(
            &ml_pk,
            msg,
            AsRef::<[u8]>::as_ref(&ml_sig_bytes),
        )
        .unwrap();
    }
}
