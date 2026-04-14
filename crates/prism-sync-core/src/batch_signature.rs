use sha2::{Digest, Sha256};

use prism_sync_crypto::pq::HybridSignature;
use prism_sync_crypto::DevicePqSigningKey;

use crate::error::{CoreError, Result};
use crate::relay::SignedBatchEnvelope;
use crate::storage::StorageError;

/// Magic bytes prefixing all canonical signed data.
const MAGIC: &[u8] = b"PRISM_SYNC_BATCH_V3";

/// Current protocol version.
const PROTOCOL_VERSION: u16 = 3;

/// Compute SHA-256 hash of plaintext payload bytes.
///
/// This hash is computed over the exact decrypted bytes (not a reserialized
/// object) to avoid cross-language serialization drift.
pub fn compute_payload_hash(plaintext: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(plaintext);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Build the V2 canonical signed data (legacy format, kept for migration tests).
#[cfg(test)]
fn build_canonical_signed_data_v2(
    protocol_version: u16,
    sync_id: &str,
    epoch: i32,
    batch_id: &str,
    batch_kind: &str,
    sender_device_id: &str,
    payload_hash: &[u8; 32],
) -> Vec<u8> {
    let mut data = Vec::with_capacity(256);

    data.extend_from_slice(b"PRISM_SYNC_BATCH_V2");
    data.push(0x00);
    data.extend_from_slice(&protocol_version.to_be_bytes());
    write_len_prefixed_utf8(&mut data, sync_id);
    data.extend_from_slice(&epoch.to_be_bytes());
    write_len_prefixed_utf8(&mut data, batch_id);
    write_len_prefixed_utf8(&mut data, batch_kind);
    write_len_prefixed_utf8(&mut data, sender_device_id);
    data.extend_from_slice(payload_hash);

    data
}

/// Build the canonical signed data for a V3 envelope.
///
/// Binary format (deterministic, NOT JSON — avoids cross-language serialization drift):
/// ```text
/// "PRISM_SYNC_BATCH_V3" || 0x00
/// || be_u16(protocol_version)
/// || len_prefixed_utf8(sync_id)
/// || be_i32(epoch)
/// || len_prefixed_utf8(batch_id)
/// || len_prefixed_utf8(batch_kind)
/// || len_prefixed_utf8(sender_device_id)
/// || be_u32(sender_ml_dsa_key_generation)
/// || payload_hash (32 bytes, raw)
/// ```
///
/// Where `len_prefixed_utf8` = `be_u32(len) || utf8_bytes`.
///
/// V3 adds `sender_ml_dsa_key_generation` (vs V2) so the verifier checks the
/// signature against the correct version of the sender's ML-DSA key, preventing
/// a downgrade attack where a revoked key generation is replayed.
#[allow(clippy::too_many_arguments)]
pub fn build_canonical_signed_data(
    protocol_version: u16,
    sync_id: &str,
    epoch: i32,
    batch_id: &str,
    batch_kind: &str,
    sender_device_id: &str,
    sender_ml_dsa_key_generation: u32,
    payload_hash: &[u8; 32],
) -> Vec<u8> {
    let mut data = Vec::with_capacity(256);

    // Magic + null separator
    data.extend_from_slice(MAGIC);
    data.push(0x00);

    // Protocol version (big-endian u16)
    data.extend_from_slice(&protocol_version.to_be_bytes());

    // Length-prefixed UTF-8 fields
    write_len_prefixed_utf8(&mut data, sync_id);

    // Epoch (big-endian i32)
    data.extend_from_slice(&epoch.to_be_bytes());

    write_len_prefixed_utf8(&mut data, batch_id);
    write_len_prefixed_utf8(&mut data, batch_kind);
    write_len_prefixed_utf8(&mut data, sender_device_id);

    // ML-DSA key generation (big-endian u32)
    data.extend_from_slice(&sender_ml_dsa_key_generation.to_be_bytes());

    // Payload hash (raw 32 bytes)
    data.extend_from_slice(payload_hash);

    data
}

/// Write a length-prefixed UTF-8 string: be_u32(len) || utf8_bytes.
fn write_len_prefixed_utf8(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

/// Sign a batch with the sender's Ed25519 + ML-DSA-65 hybrid signing keys.
///
/// Returns a `SignedBatchEnvelope` with the hybrid signature populated.
#[allow(clippy::too_many_arguments)]
pub fn sign_batch(
    signing_key: &ed25519_dalek::SigningKey,
    ml_dsa_signing_key: &DevicePqSigningKey,
    sync_id: &str,
    epoch: i32,
    batch_id: &str,
    batch_kind: &str,
    sender_device_id: &str,
    sender_ml_dsa_key_generation: u32,
    payload_hash: &[u8; 32],
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
) -> Result<SignedBatchEnvelope> {
    let canonical = build_canonical_signed_data(
        PROTOCOL_VERSION,
        sync_id,
        epoch,
        batch_id,
        batch_kind,
        sender_device_id,
        sender_ml_dsa_key_generation,
        payload_hash,
    );

    let hybrid_sig = HybridSignature::sign_v3(
        &canonical,
        b"sync_batch",
        signing_key,
        ml_dsa_signing_key.as_signing_key(),
    )
    .map_err(|e| CoreError::Serialization(format!("hybrid signature: {e}")))?;

    Ok(SignedBatchEnvelope {
        protocol_version: PROTOCOL_VERSION,
        sync_id: sync_id.to_string(),
        epoch,
        batch_id: batch_id.to_string(),
        batch_kind: batch_kind.to_string(),
        sender_device_id: sender_device_id.to_string(),
        payload_hash: *payload_hash,
        signature: hybrid_sig.to_bytes(),
        nonce,
        ciphertext,
        sender_ml_dsa_key_generation,
    })
}

/// Verify a batch envelope's hybrid Ed25519 + ML-DSA-65 signature.
///
/// Both Ed25519 and ML-DSA-65 signatures must verify.
/// Does NOT verify payload_hash (that requires decryption first).
pub fn verify_batch_signature(
    envelope: &SignedBatchEnvelope,
    sender_ed25519_pk: &[u8; 32],
    sender_ml_dsa_pk: &[u8],
) -> Result<()> {
    let canonical = build_canonical_signed_data(
        envelope.protocol_version,
        &envelope.sync_id,
        envelope.epoch,
        &envelope.batch_id,
        &envelope.batch_kind,
        &envelope.sender_device_id,
        envelope.sender_ml_dsa_key_generation,
        &envelope.payload_hash,
    );

    let hybrid_sig = HybridSignature::from_bytes(&envelope.signature)
        .map_err(|e| CoreError::Serialization(format!("hybrid signature: {e}")))?;

    hybrid_sig
        .verify_v3(&canonical, b"sync_batch", sender_ed25519_pk, sender_ml_dsa_pk)
        .map_err(|e| CoreError::Storage(StorageError::Logic(format!("Batch signature verification failed: {e}"))))?;

    Ok(())
}

/// Verify that the decrypted payload matches the envelope's payload_hash.
///
/// Call this after decryption to ensure data integrity.
pub fn verify_payload_hash(envelope: &SignedBatchEnvelope, decrypted_bytes: &[u8]) -> Result<()> {
    let computed = compute_payload_hash(decrypted_bytes);
    if computed != envelope.payload_hash {
        return Err(CoreError::Storage(StorageError::Logic(
            "Payload hash mismatch: decrypted data does not match signed hash".to_string(),
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use prism_sync_crypto::DeviceSecret;
    use rand::rngs::OsRng;

    fn make_signing_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn make_ml_dsa_keypair() -> DevicePqSigningKey {
        let ds = DeviceSecret::generate();
        ds.ml_dsa_65_keypair("test-device").unwrap()
    }

    fn sample_envelope(
        signing_key: &SigningKey,
        ml_dsa_signing_key: &DevicePqSigningKey,
    ) -> SignedBatchEnvelope {
        let plaintext = b"test payload data";
        let payload_hash = compute_payload_hash(plaintext);
        let nonce = [0u8; 24];
        let ciphertext = vec![1, 2, 3, 4, 5];

        sign_batch(
            signing_key,
            ml_dsa_signing_key,
            "sync-group-1",
            0,
            "batch-uuid-123",
            "ops",
            "device-abc",
            0,
            &payload_hash,
            nonce,
            ciphertext,
        )
        .expect("sign_batch should succeed")
    }

    #[test]
    fn sign_then_verify_succeeds() {
        let signing_key = make_signing_key();
        let ml_dsa_key = make_ml_dsa_keypair();
        let ed25519_pk = signing_key.verifying_key().to_bytes();
        let ml_dsa_pk = ml_dsa_key.public_key_bytes();
        let envelope = sample_envelope(&signing_key, &ml_dsa_key);

        assert!(verify_batch_signature(&envelope, &ed25519_pk, &ml_dsa_pk).is_ok());
    }

    #[test]
    fn verify_with_wrong_key_fails() {
        let signing_key = make_signing_key();
        let ml_dsa_key = make_ml_dsa_keypair();
        let envelope = sample_envelope(&signing_key, &ml_dsa_key);

        let wrong_key = make_signing_key();
        let wrong_ed25519_pk = wrong_key.verifying_key().to_bytes();
        let wrong_ml_dsa_key = make_ml_dsa_keypair();
        let wrong_ml_dsa_pk = wrong_ml_dsa_key.public_key_bytes();

        assert!(verify_batch_signature(&envelope, &wrong_ed25519_pk, &ml_dsa_key.public_key_bytes()).is_err());
        assert!(verify_batch_signature(&envelope, &signing_key.verifying_key().to_bytes(), &wrong_ml_dsa_pk).is_err());
    }

    #[test]
    fn tampered_envelope_fails() {
        let signing_key = make_signing_key();
        let ml_dsa_key = make_ml_dsa_keypair();
        let ed25519_pk = signing_key.verifying_key().to_bytes();
        let ml_dsa_pk = ml_dsa_key.public_key_bytes();
        let mut envelope = sample_envelope(&signing_key, &ml_dsa_key);

        envelope.batch_id = "tampered-batch-id".to_string();

        assert!(verify_batch_signature(&envelope, &ed25519_pk, &ml_dsa_pk).is_err());
    }

    #[test]
    fn tampered_epoch_fails() {
        let signing_key = make_signing_key();
        let ml_dsa_key = make_ml_dsa_keypair();
        let ed25519_pk = signing_key.verifying_key().to_bytes();
        let ml_dsa_pk = ml_dsa_key.public_key_bytes();
        let mut envelope = sample_envelope(&signing_key, &ml_dsa_key);

        envelope.epoch = 99;

        assert!(verify_batch_signature(&envelope, &ed25519_pk, &ml_dsa_pk).is_err());
    }

    #[test]
    fn tampered_payload_hash_fails() {
        let signing_key = make_signing_key();
        let ml_dsa_key = make_ml_dsa_keypair();
        let ed25519_pk = signing_key.verifying_key().to_bytes();
        let ml_dsa_pk = ml_dsa_key.public_key_bytes();
        let mut envelope = sample_envelope(&signing_key, &ml_dsa_key);

        envelope.payload_hash[0] ^= 0xFF;

        assert!(verify_batch_signature(&envelope, &ed25519_pk, &ml_dsa_pk).is_err());
    }

    #[test]
    fn payload_hash_correct() {
        let data = b"hello world";
        let hash = compute_payload_hash(data);

        let expected =
            hex::decode("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")
                .unwrap_or_default();

        assert_eq!(hash.len(), 32);
        assert_eq!(hash, compute_payload_hash(data));
        assert_ne!(hash, [0u8; 32]);
        if expected.len() == 32 {
            let mut exp_arr = [0u8; 32];
            exp_arr.copy_from_slice(&expected);
            assert_eq!(hash, exp_arr);
        }
    }

    #[test]
    fn payload_hash_mismatch() {
        let signing_key = make_signing_key();
        let ml_dsa_key = make_ml_dsa_keypair();
        let envelope = sample_envelope(&signing_key, &ml_dsa_key);

        let wrong_data = b"different payload data";
        assert!(verify_payload_hash(&envelope, wrong_data).is_err());
    }

    #[test]
    fn payload_hash_match() {
        let signing_key = make_signing_key();
        let ml_dsa_key = make_ml_dsa_keypair();
        let plaintext = b"test payload data";
        let payload_hash = compute_payload_hash(plaintext);
        let envelope = sign_batch(
            &signing_key,
            &ml_dsa_key,
            "sync-group-1",
            0,
            "batch-uuid-123",
            "ops",
            "device-abc",
            0,
            &payload_hash,
            [0u8; 24],
            vec![1, 2, 3],
        )
        .unwrap();

        assert!(verify_payload_hash(&envelope, plaintext).is_ok());
    }

    #[test]
    fn canonical_format_deterministic() {
        let payload_hash = [42u8; 32];
        let data1 = build_canonical_signed_data(3, "sync-1", 0, "batch-1", "ops", "device-1", 0, &payload_hash);
        let data2 = build_canonical_signed_data(3, "sync-1", 0, "batch-1", "ops", "device-1", 0, &payload_hash);
        assert_eq!(data1, data2);
    }

    #[test]
    fn canonical_format_fields_order() {
        let payload_hash = [0u8; 32];
        let data = build_canonical_signed_data(3, "abc", 1, "bid", "ops", "did", 42, &payload_hash);

        assert!(data.starts_with(MAGIC));
        assert_eq!(data[MAGIC.len()], 0x00);

        let ver_offset = MAGIC.len() + 1;
        assert_eq!(&data[ver_offset..ver_offset + 2], &[0x00, 0x03]);

        let gen_offset = data.len() - 32 - 4;
        assert_eq!(&data[gen_offset..gen_offset + 4], &42u32.to_be_bytes());

        assert_eq!(&data[data.len() - 32..], &payload_hash);
    }

    #[test]
    fn different_sync_ids_produce_different_canonical_data() {
        let payload_hash = [0u8; 32];
        let data1 = build_canonical_signed_data(3, "sync-a", 0, "b", "ops", "d", 0, &payload_hash);
        let data2 = build_canonical_signed_data(3, "sync-b", 0, "b", "ops", "d", 0, &payload_hash);
        assert_ne!(data1, data2);
    }

    #[test]
    fn tampered_generation_fails() {
        let signing_key = make_signing_key();
        let ml_dsa_key = make_ml_dsa_keypair();
        let ed25519_pk = signing_key.verifying_key().to_bytes();
        let ml_dsa_pk = ml_dsa_key.public_key_bytes();
        let mut envelope = sample_envelope(&signing_key, &ml_dsa_key);

        // Envelope was signed with generation 0; change it to 1 after signing.
        // Verification should fail because generation is bound in the canonical data.
        envelope.sender_ml_dsa_key_generation = 1;

        assert!(verify_batch_signature(&envelope, &ed25519_pk, &ml_dsa_pk).is_err());
    }

    #[test]
    fn hybrid_batch_tampered_ed25519_half_fails() {
        let signing_key = make_signing_key();
        let ml_dsa_key = make_ml_dsa_keypair();
        let ed25519_pk = signing_key.verifying_key().to_bytes();
        let ml_dsa_pk = ml_dsa_key.public_key_bytes();
        let mut envelope = sample_envelope(&signing_key, &ml_dsa_key);

        // Parse the hybrid signature, corrupt only the Ed25519 portion, re-serialize
        let mut hybrid_sig = HybridSignature::from_bytes(&envelope.signature)
            .expect("should parse hybrid signature");
        hybrid_sig.ed25519_sig[0] ^= 0xFF;
        envelope.signature = hybrid_sig.to_bytes();

        assert!(verify_batch_signature(&envelope, &ed25519_pk, &ml_dsa_pk).is_err());
    }

    #[test]
    fn hybrid_batch_tampered_ml_dsa_half_fails() {
        let signing_key = make_signing_key();
        let ml_dsa_key = make_ml_dsa_keypair();
        let ed25519_pk = signing_key.verifying_key().to_bytes();
        let ml_dsa_pk = ml_dsa_key.public_key_bytes();
        let mut envelope = sample_envelope(&signing_key, &ml_dsa_key);

        // Parse the hybrid signature, corrupt only the ML-DSA portion, re-serialize
        let mut hybrid_sig = HybridSignature::from_bytes(&envelope.signature)
            .expect("should parse hybrid signature");
        hybrid_sig.ml_dsa_65_sig[0] ^= 0xFF;
        envelope.signature = hybrid_sig.to_bytes();

        assert!(verify_batch_signature(&envelope, &ed25519_pk, &ml_dsa_pk).is_err());
    }

    #[test]
    fn truncated_hybrid_signature_rejected() {
        let signing_key = make_signing_key();
        let ml_dsa_key = make_ml_dsa_keypair();
        let ed25519_pk = signing_key.verifying_key().to_bytes();
        let ml_dsa_pk = ml_dsa_key.public_key_bytes();
        let mut envelope = sample_envelope(&signing_key, &ml_dsa_key);

        // Truncate the hybrid signature to 8 bytes — far too short to be valid
        envelope.signature = envelope.signature[..8].to_vec();

        assert!(
            verify_batch_signature(&envelope, &ed25519_pk, &ml_dsa_pk).is_err(),
            "truncated signature should be rejected"
        );
    }

    #[test]
    fn garbage_hybrid_signature_rejected() {
        let signing_key = make_signing_key();
        let ml_dsa_key = make_ml_dsa_keypair();
        let ed25519_pk = signing_key.verifying_key().to_bytes();
        let ml_dsa_pk = ml_dsa_key.public_key_bytes();
        let mut envelope = sample_envelope(&signing_key, &ml_dsa_key);

        // Replace signature with random bytes of the same length
        let sig_len = envelope.signature.len();
        envelope.signature = (0..sig_len).map(|i| (i as u8).wrapping_mul(37).wrapping_add(13)).collect();

        assert!(
            verify_batch_signature(&envelope, &ed25519_pk, &ml_dsa_pk).is_err(),
            "garbage signature of correct length should be rejected"
        );
    }

    #[test]
    fn wrong_ml_dsa_pk_length_rejected() {
        let signing_key = make_signing_key();
        let ml_dsa_key = make_ml_dsa_keypair();
        let ed25519_pk = signing_key.verifying_key().to_bytes();
        let envelope = sample_envelope(&signing_key, &ml_dsa_key);

        // Pass a 100-byte array instead of the correct 1952-byte ML-DSA public key
        let wrong_ml_dsa_pk = vec![0u8; 100];

        assert!(
            verify_batch_signature(&envelope, &ed25519_pk, &wrong_ml_dsa_pk).is_err(),
            "wrong ML-DSA public key length should be rejected"
        );
    }

    #[test]
    fn future_v4_batch_envelope_rejected() {
        let signing_key = make_signing_key();
        let ml_dsa_key = make_ml_dsa_keypair();
        let ed25519_pk = signing_key.verifying_key().to_bytes();
        let ml_dsa_pk = ml_dsa_key.public_key_bytes();
        let mut envelope = sample_envelope(&signing_key, &ml_dsa_key);

        // Change the protocol_version to 4 after signing.
        // The verifier reconstructs canonical data using envelope.protocol_version,
        // which now differs from the version (3) used when signing — so the
        // canonical data will not match and signature verification must fail.
        envelope.protocol_version = 4;

        assert!(
            verify_batch_signature(&envelope, &ed25519_pk, &ml_dsa_pk).is_err(),
            "envelope with future protocol version should be rejected"
        );
    }

    #[test]
    fn v2_signature_rejected_by_v3_verifier() {
        use ed25519_dalek::Signer;

        let signing_key = make_signing_key();
        let ml_dsa_key = make_ml_dsa_keypair();
        let ed25519_pk = signing_key.verifying_key().to_bytes();
        let ml_dsa_pk = ml_dsa_key.public_key_bytes();

        let plaintext = b"test payload data";
        let payload_hash = compute_payload_hash(plaintext);

        let v2_canonical = build_canonical_signed_data_v2(
            2, "sync-group-1", 0, "batch-uuid-123", "ops", "device-abc", &payload_hash,
        );

        let ed25519_sig = signing_key.sign(&v2_canonical);

        let envelope = SignedBatchEnvelope {
            protocol_version: 2,
            sync_id: "sync-group-1".to_string(),
            epoch: 0,
            batch_id: "batch-uuid-123".to_string(),
            batch_kind: "ops".to_string(),
            sender_device_id: "device-abc".to_string(),
            payload_hash,
            signature: ed25519_sig.to_bytes().to_vec(),
            nonce: [0u8; 24],
            ciphertext: vec![1, 2, 3, 4, 5],
            sender_ml_dsa_key_generation: 0,
        };

        assert!(verify_batch_signature(&envelope, &ed25519_pk, &ml_dsa_pk).is_err());
    }
}
