use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::error::{CoreError, Result};
use crate::relay::SignedBatchEnvelope;

/// Magic bytes prefixing all canonical signed data.
const MAGIC: &[u8] = b"PRISM_SYNC_BATCH_V2";

/// Current protocol version.
const PROTOCOL_VERSION: u16 = 2;

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

/// Build the canonical signed data for an envelope.
///
/// Binary format (deterministic, NOT JSON):
/// ```text
/// "PRISM_SYNC_BATCH_V2" || 0x00
/// || be_u16(protocol_version)
/// || len_prefixed_utf8(sync_id)
/// || be_i32(epoch)
/// || len_prefixed_utf8(batch_id)
/// || len_prefixed_utf8(batch_kind)
/// || len_prefixed_utf8(sender_device_id)
/// || payload_hash (32 bytes, raw)
/// ```
///
/// Where `len_prefixed_utf8` = `be_u32(len) || utf8_bytes`.
pub fn build_canonical_signed_data(
    protocol_version: u16,
    sync_id: &str,
    epoch: i32,
    batch_id: &str,
    batch_kind: &str,
    sender_device_id: &str,
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

/// Sign a batch with the sender's Ed25519 signing key.
///
/// Returns a `SignedBatchEnvelope` with the signature populated.
///
/// Parameters:
/// - `signing_key`: The sender device's Ed25519 private key
/// - `sync_id`: The sync group ID
/// - `epoch`: Current epoch number
/// - `batch_id`: UUID of this batch
/// - `batch_kind`: "ops" or "snapshot"
/// - `sender_device_id`: The sending device's ID
/// - `payload_hash`: SHA-256 of the plaintext ops JSON before encryption
/// - `nonce`: XChaCha20-Poly1305 nonce used for encryption (24 bytes)
/// - `ciphertext`: Encrypted batch data (ciphertext + MAC)
#[allow(clippy::too_many_arguments)]
pub fn sign_batch(
    signing_key: &SigningKey,
    sync_id: &str,
    epoch: i32,
    batch_id: &str,
    batch_kind: &str,
    sender_device_id: &str,
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
        payload_hash,
    );

    let signature = signing_key.sign(&canonical);

    Ok(SignedBatchEnvelope {
        protocol_version: PROTOCOL_VERSION,
        sync_id: sync_id.to_string(),
        epoch,
        batch_id: batch_id.to_string(),
        batch_kind: batch_kind.to_string(),
        sender_device_id: sender_device_id.to_string(),
        payload_hash: *payload_hash,
        signature: signature.to_bytes().to_vec(),
        nonce,
        ciphertext,
    })
}

/// Verify a batch envelope's Ed25519 signature.
///
/// Steps:
/// 1. Reconstruct canonical signed data from envelope fields
/// 2. Verify Ed25519 signature against sender's public key
///
/// Does NOT verify payload_hash (that requires decryption first).
pub fn verify_batch_signature(
    envelope: &SignedBatchEnvelope,
    sender_public_key: &VerifyingKey,
) -> Result<()> {
    let canonical = build_canonical_signed_data(
        envelope.protocol_version,
        &envelope.sync_id,
        envelope.epoch,
        &envelope.batch_id,
        &envelope.batch_kind,
        &envelope.sender_device_id,
        &envelope.payload_hash,
    );

    let signature = Signature::from_slice(&envelope.signature)
        .map_err(|e| CoreError::Serialization(format!("Invalid signature bytes: {e}")))?;

    sender_public_key
        .verify(&canonical, &signature)
        .map_err(|_| CoreError::Storage("Batch signature verification failed".to_string()))
}

/// Verify that the decrypted payload matches the envelope's payload_hash.
///
/// Call this after decryption to ensure data integrity.
pub fn verify_payload_hash(envelope: &SignedBatchEnvelope, decrypted_bytes: &[u8]) -> Result<()> {
    let computed = compute_payload_hash(decrypted_bytes);
    if computed != envelope.payload_hash {
        return Err(CoreError::Storage(
            "Payload hash mismatch: decrypted data does not match signed hash".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn make_signing_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn sample_envelope(signing_key: &SigningKey) -> SignedBatchEnvelope {
        let plaintext = b"test payload data";
        let payload_hash = compute_payload_hash(plaintext);
        let nonce = [0u8; 24];
        let ciphertext = vec![1, 2, 3, 4, 5];

        sign_batch(
            signing_key,
            "sync-group-1",
            0,
            "batch-uuid-123",
            "ops",
            "device-abc",
            &payload_hash,
            nonce,
            ciphertext,
        )
        .expect("sign_batch should succeed")
    }

    #[test]
    fn sign_then_verify_succeeds() {
        let signing_key = make_signing_key();
        let verifying_key = signing_key.verifying_key();
        let envelope = sample_envelope(&signing_key);

        assert!(verify_batch_signature(&envelope, &verifying_key).is_ok());
    }

    #[test]
    fn verify_with_wrong_key_fails() {
        let signing_key = make_signing_key();
        let envelope = sample_envelope(&signing_key);

        let wrong_key = make_signing_key();
        let wrong_verifying_key = wrong_key.verifying_key();

        assert!(verify_batch_signature(&envelope, &wrong_verifying_key).is_err());
    }

    #[test]
    fn tampered_envelope_fails() {
        let signing_key = make_signing_key();
        let verifying_key = signing_key.verifying_key();
        let mut envelope = sample_envelope(&signing_key);

        // Tamper with the batch_id after signing
        envelope.batch_id = "tampered-batch-id".to_string();

        assert!(verify_batch_signature(&envelope, &verifying_key).is_err());
    }

    #[test]
    fn tampered_epoch_fails() {
        let signing_key = make_signing_key();
        let verifying_key = signing_key.verifying_key();
        let mut envelope = sample_envelope(&signing_key);

        // Tamper with the epoch after signing
        envelope.epoch = 99;

        assert!(verify_batch_signature(&envelope, &verifying_key).is_err());
    }

    #[test]
    fn tampered_payload_hash_fails() {
        let signing_key = make_signing_key();
        let verifying_key = signing_key.verifying_key();
        let mut envelope = sample_envelope(&signing_key);

        // Tamper with payload_hash after signing
        envelope.payload_hash[0] ^= 0xFF;

        assert!(verify_batch_signature(&envelope, &verifying_key).is_err());
    }

    #[test]
    fn payload_hash_correct() {
        let data = b"hello world";
        let hash = compute_payload_hash(data);

        // SHA-256("hello world") known value
        let expected =
            hex::decode("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")
                .unwrap_or_default();

        // Verify the hash is 32 bytes and consistent
        assert_eq!(hash.len(), 32);
        // Verify same input produces same hash (deterministic)
        assert_eq!(hash, compute_payload_hash(data));
        // Verify it's non-zero
        assert_ne!(hash, [0u8; 32]);
        // Cross-check against known SHA-256 if hex decoding succeeded (64 hex chars = 32 bytes)
        if expected.len() == 32 {
            let mut exp_arr = [0u8; 32];
            exp_arr.copy_from_slice(&expected);
            assert_eq!(hash, exp_arr);
        }
    }

    #[test]
    fn payload_hash_mismatch() {
        let signing_key = make_signing_key();
        let envelope = sample_envelope(&signing_key);

        let wrong_data = b"different payload data";
        assert!(verify_payload_hash(&envelope, wrong_data).is_err());
    }

    #[test]
    fn payload_hash_match() {
        let signing_key = make_signing_key();
        let plaintext = b"test payload data";
        let payload_hash = compute_payload_hash(plaintext);
        let envelope = sign_batch(
            &signing_key,
            "sync-group-1",
            0,
            "batch-uuid-123",
            "ops",
            "device-abc",
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
        let data1 = build_canonical_signed_data(
            2,
            "sync-1",
            0,
            "batch-1",
            "ops",
            "device-1",
            &payload_hash,
        );
        let data2 = build_canonical_signed_data(
            2,
            "sync-1",
            0,
            "batch-1",
            "ops",
            "device-1",
            &payload_hash,
        );
        assert_eq!(data1, data2);
    }

    #[test]
    fn canonical_format_fields_order() {
        let payload_hash = [0u8; 32];
        let data = build_canonical_signed_data(2, "abc", 1, "bid", "ops", "did", &payload_hash);

        // Verify magic bytes at start
        assert!(data.starts_with(MAGIC));

        // Null separator after magic
        assert_eq!(data[MAGIC.len()], 0x00);

        // Protocol version (big-endian u16 = 0x0002) follows null separator
        let ver_offset = MAGIC.len() + 1;
        assert_eq!(&data[ver_offset..ver_offset + 2], &[0x00, 0x02]);

        // Payload hash (32 bytes) at the end
        assert_eq!(&data[data.len() - 32..], &payload_hash);
    }

    #[test]
    fn different_sync_ids_produce_different_canonical_data() {
        let payload_hash = [0u8; 32];
        let data1 = build_canonical_signed_data(2, "sync-a", 0, "b", "ops", "d", &payload_hash);
        let data2 = build_canonical_signed_data(2, "sync-b", 0, "b", "ops", "d", &payload_hash);
        assert_ne!(data1, data2);
    }
}
