#[cfg(test)]
use ed25519_dalek::{Signature, VerifyingKey};
use prism_sync_crypto::pq::{hybrid_signature_contexts, HybridSignature};
use rand::RngCore;
use sha2::{Digest, Sha256};

const SUPPORTED_SIGNATURE_VERSION: u8 = 0x03;

/// Generate a secure session token (32 random bytes, hex encoded = 64 chars).
pub(crate) fn generate_session_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// SHA-256 hash of a token string, returned as lowercase hex.
pub(crate) fn hash_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    hex::encode(digest)
}

/// Constant-time comparison for fixed-length values (SHA-256 hex digests).
///
/// XOR fold runs in constant time over the full length. The early length check
/// does not leak information because both inputs are always 64-char hex-encoded
/// SHA-256 hashes in practice.
pub(crate) fn timing_safe_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).fold(0u8, |acc, (&x, &y)| acc | (x ^ y)) == 0
}

/// Verify an Ed25519 challenge signature.
///
/// The challenge uses a canonical binary format with domain separator:
/// ```text
/// "PRISM_SYNC_CHALLENGE_V1" || 0x00
/// || len_prefixed_utf8(sync_id)
/// || len_prefixed_utf8(device_id)
/// || len_prefixed_utf8(nonce)
/// ```
#[cfg(test)]
pub fn verify_ed25519_challenge(
    public_key: &[u8],
    sync_id: &str,
    device_id: &str,
    nonce: &str,
    signature: &[u8],
) -> bool {
    let Ok(pk_bytes): Result<[u8; 32], _> = public_key.try_into() else {
        return false;
    };
    let Ok(verifying_key) = VerifyingKey::from_bytes(&pk_bytes) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(signature) else {
        return false;
    };

    let mut data = Vec::new();
    data.extend_from_slice(b"PRISM_SYNC_CHALLENGE_V1\x00");
    write_len_prefixed(&mut data, sync_id.as_bytes());
    write_len_prefixed(&mut data, device_id.as_bytes());
    write_len_prefixed(&mut data, nonce.as_bytes());

    verifying_key.verify_strict(&data, &sig).is_ok()
}

/// Verify a hybrid registration challenge signature.
///
/// Wire format for `versioned_signature`:
/// `[0x03][HybridSignature::to_bytes()]`
pub(crate) fn verify_hybrid_challenge(
    ed25519_public_key: &[u8],
    ml_dsa_public_key: &[u8],
    sync_id: &str,
    device_id: &str,
    nonce: &str,
    versioned_signature: &[u8],
) -> bool {
    let Ok(pk_bytes): Result<[u8; 32], _> = ed25519_public_key.try_into() else {
        return false;
    };
    let Some((&version, signature_bytes)) = versioned_signature.split_first() else {
        return false;
    };

    if version != SUPPORTED_SIGNATURE_VERSION {
        return false;
    }

    let Ok(signature) = HybridSignature::from_bytes(signature_bytes) else {
        return false;
    };

    let mut data = Vec::new();
    data.extend_from_slice(b"PRISM_SYNC_CHALLENGE_V2\x00");
    write_len_prefixed(&mut data, sync_id.as_bytes());
    write_len_prefixed(&mut data, device_id.as_bytes());
    write_len_prefixed(&mut data, nonce.as_bytes());

    signature
        .verify_v3(&data, hybrid_signature_contexts::DEVICE_CHALLENGE, &pk_bytes, ml_dsa_public_key)
        .is_ok()
}

/// Validate that a sync ID is a 64-char hex string (32 bytes).
pub(crate) fn is_valid_sync_id(sync_id: &str) -> bool {
    sync_id.len() == 64 && sync_id.chars().all(|c| c.is_ascii_hexdigit())
}

/// Validate a device ID.
///
/// Requirements:
/// - non-empty
/// - <= 128 bytes
/// - printable ASCII only (no control chars, no DEL)
/// - no pipe `|` characters (used as AAD field separator)
pub(crate) fn is_valid_device_id(device_id: &str) -> bool {
    !device_id.is_empty()
        && device_id.len() <= 128
        && device_id.bytes().all(|b| (0x20..=0x7e).contains(&b) && b != b'|')
}

/// Build canonical bytes that get signed for destructive HTTP requests.
///
/// Domain-separated binary format:
/// ```text
/// "PRISM_SYNC_HTTP_V1" || 0x00
/// || len_prefixed_utf8(method)
/// || len_prefixed_utf8(path)
/// || len_prefixed_utf8(sync_id)
/// || len_prefixed_utf8(device_id)
/// || sha256(body) (32 bytes)
/// || len_prefixed_utf8(timestamp)
/// || len_prefixed_utf8(nonce)
/// ```
#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub fn build_request_signing_data(
    method: &str,
    path: &str,
    sync_id: &str,
    device_id: &str,
    body: &[u8],
    timestamp: &str,
    nonce: &str,
) -> Vec<u8> {
    let body_hash = Sha256::digest(body);
    let mut data = Vec::new();
    data.extend_from_slice(b"PRISM_SYNC_HTTP_V1\x00");
    write_len_prefixed(&mut data, method.as_bytes());
    write_len_prefixed(&mut data, path.as_bytes());
    write_len_prefixed(&mut data, sync_id.as_bytes());
    write_len_prefixed(&mut data, device_id.as_bytes());
    data.extend_from_slice(&body_hash);
    write_len_prefixed(&mut data, timestamp.as_bytes());
    write_len_prefixed(&mut data, nonce.as_bytes());
    data
}

/// Build canonical bytes that get signed for destructive HTTP requests in the
/// Phase 5 hybrid format.
#[allow(clippy::too_many_arguments)]
pub fn build_request_signing_data_v2(
    method: &str,
    path: &str,
    sync_id: &str,
    device_id: &str,
    body: &[u8],
    timestamp: &str,
    nonce: &str,
) -> Vec<u8> {
    let body_hash = Sha256::digest(body);
    let mut data = Vec::new();
    data.extend_from_slice(b"PRISM_SYNC_HTTP_V2\x00");
    write_len_prefixed(&mut data, method.as_bytes());
    write_len_prefixed(&mut data, path.as_bytes());
    write_len_prefixed(&mut data, sync_id.as_bytes());
    write_len_prefixed(&mut data, device_id.as_bytes());
    data.extend_from_slice(&body_hash);
    write_len_prefixed(&mut data, timestamp.as_bytes());
    write_len_prefixed(&mut data, nonce.as_bytes());
    data
}

/// Verify an Ed25519 signature over canonical request signing data.
#[cfg(test)]
pub fn verify_request_signature(
    signing_public_key: &[u8],
    signing_data: &[u8],
    signature: &[u8],
) -> bool {
    let Ok(pk_bytes): Result<[u8; 32], _> = signing_public_key.try_into() else {
        return false;
    };
    let Ok(verifying_key) = VerifyingKey::from_bytes(&pk_bytes) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(signature) else {
        return false;
    };
    verifying_key.verify_strict(signing_data, &sig).is_ok()
}

/// Verify a hybrid signature over canonical request signing data.
///
/// Wire format for `versioned_signature`:
/// `[0x03][HybridSignature::to_bytes()]`
pub(crate) fn verify_hybrid_request_signature(
    ed25519_public_key: &[u8],
    ml_dsa_public_key: &[u8],
    signing_data: &[u8],
    versioned_signature: &[u8],
) -> bool {
    let Ok(pk_bytes): Result<[u8; 32], _> = ed25519_public_key.try_into() else {
        return false;
    };
    let Some((&version, signature_bytes)) = versioned_signature.split_first() else {
        return false;
    };

    if version != SUPPORTED_SIGNATURE_VERSION {
        return false;
    }

    let Ok(signature) = HybridSignature::from_bytes(signature_bytes) else {
        return false;
    };

    signature
        .verify_v3(
            signing_data,
            hybrid_signature_contexts::HTTP_REQUEST,
            &pk_bytes,
            ml_dsa_public_key,
        )
        .is_ok()
}

/// Write a length-prefixed field: `(data.len() as u32).to_be_bytes() || data`.
fn write_len_prefixed(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use prism_sync_crypto::DeviceSecret;

    fn make_versioned_hybrid_signature(
        message: &[u8],
        device_id: &str,
    ) -> (Vec<u8>, [u8; 32], Vec<u8>) {
        use ed25519_dalek::Signer;

        let secret = DeviceSecret::generate();
        let ed_signing_key = secret.ed25519_keypair(device_id).unwrap();
        let ed_public_key = ed_signing_key.public_key_bytes();
        let pq_signing_key = secret.ml_dsa_65_keypair(device_id).unwrap();
        let pq_public_key = pq_signing_key.public_key_bytes();

        let hybrid_sig = HybridSignature {
            ed25519_sig: ed_signing_key.into_signing_key().sign(message).to_bytes().to_vec(),
            ml_dsa_65_sig: pq_signing_key.sign(message),
        };

        let mut versioned = vec![0x02]; // V2 (now rejected)
        versioned.extend_from_slice(&hybrid_sig.to_bytes());
        (versioned, ed_public_key, pq_public_key)
    }

    #[test]
    fn test_generate_session_token() {
        let token = generate_session_token();
        assert_eq!(token.len(), 64);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));

        // Two tokens should differ
        let token2 = generate_session_token();
        assert_ne!(token, token2);
    }

    #[test]
    fn test_hash_token() {
        let hash = hash_token("hello");
        assert_eq!(hash.len(), 64);
        // SHA-256 of "hello" is deterministic
        let hash2 = hash_token("hello");
        assert_eq!(hash, hash2);
        // Different input => different hash
        assert_ne!(hash_token("hello"), hash_token("world"));
    }

    #[test]
    fn test_timing_safe_eq() {
        assert!(timing_safe_eq("abc", "abc"));
        assert!(!timing_safe_eq("abc", "abd"));
        assert!(!timing_safe_eq("abc", "ab"));
        assert!(!timing_safe_eq("", "a"));
        assert!(timing_safe_eq("", ""));
    }

    #[test]
    fn test_is_valid_sync_id() {
        let valid = "a".repeat(64);
        assert!(is_valid_sync_id(&valid));
        assert!(!is_valid_sync_id("short"));
        assert!(!is_valid_sync_id(&"g".repeat(64))); // non-hex
    }

    #[test]
    fn test_verify_ed25519_challenge() {
        use ed25519_dalek::Signer;

        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let public_key = signing_key.verifying_key();

        let sync_id = "a".repeat(64);
        let device_id = "test-device";
        let nonce = "test-nonce-123";

        // Build canonical challenge
        let mut data = Vec::new();
        data.extend_from_slice(b"PRISM_SYNC_CHALLENGE_V1\x00");
        write_len_prefixed(&mut data, sync_id.as_bytes());
        write_len_prefixed(&mut data, device_id.as_bytes());
        write_len_prefixed(&mut data, nonce.as_bytes());

        let signature = signing_key.sign(&data);

        assert!(verify_ed25519_challenge(
            public_key.as_bytes(),
            &sync_id,
            device_id,
            nonce,
            &signature.to_bytes(),
        ));

        // Wrong nonce should fail
        assert!(!verify_ed25519_challenge(
            public_key.as_bytes(),
            &sync_id,
            device_id,
            "wrong-nonce",
            &signature.to_bytes(),
        ));
    }

    #[test]
    fn test_is_valid_device_id() {
        assert!(is_valid_device_id("device-1"));
        assert!(is_valid_device_id("abc_123"));
        assert!(!is_valid_device_id(""));
        assert!(!is_valid_device_id(&"a".repeat(129)));
        assert!(!is_valid_device_id("line\nbreak"));
        assert!(!is_valid_device_id("tab\tchar"));
    }

    #[test]
    fn test_verify_request_signature() {
        use ed25519_dalek::Signer;

        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let method = "POST";
        let path = "/v1/sync/sync123/devices/dev2/revoke";
        let sync_id = "a".repeat(64);
        let device_id = "device-1";
        let body = br#"{"k":"v"}"#;
        let timestamp = "1700000000";
        let nonce = "nonce-1";
        let data =
            build_request_signing_data(method, path, &sync_id, device_id, body, timestamp, nonce);
        let sig = signing_key.sign(&data);
        assert!(verify_request_signature(
            signing_key.verifying_key().as_bytes(),
            &data,
            &sig.to_bytes(),
        ));

        let wrong_data = build_request_signing_data(
            method,
            path,
            &sync_id,
            device_id,
            br#"{"k":"tampered"}"#,
            timestamp,
            nonce,
        );
        assert!(!verify_request_signature(
            signing_key.verifying_key().as_bytes(),
            &wrong_data,
            &sig.to_bytes(),
        ));
    }

    #[test]
    fn test_verify_hybrid_challenge_rejects_v2() {
        let sync_id = "a".repeat(64);
        let device_id = "test-device";
        let nonce = "test-nonce-123";

        let mut data = Vec::new();
        data.extend_from_slice(b"PRISM_SYNC_CHALLENGE_V2\x00");
        write_len_prefixed(&mut data, sync_id.as_bytes());
        write_len_prefixed(&mut data, device_id.as_bytes());
        write_len_prefixed(&mut data, nonce.as_bytes());

        let (versioned_sig, ed_pk, ml_pk) = make_versioned_hybrid_signature(&data, device_id);

        // V2 signatures are now rejected after sunset
        assert!(!verify_hybrid_challenge(
            &ed_pk,
            &ml_pk,
            &sync_id,
            device_id,
            nonce,
            &versioned_sig,
        ));
    }

    #[test]
    fn test_verify_hybrid_request_signature_rejects_v2() {
        let device_id = "device-1";
        let data = build_request_signing_data_v2(
            "POST",
            "/v1/sync/sync123/rekey",
            &"a".repeat(64),
            device_id,
            br#"{"k":"v"}"#,
            "1700000000",
            "nonce-1",
        );

        let (versioned_sig, ed_pk, ml_pk) = make_versioned_hybrid_signature(&data, device_id);
        // V2 signatures are now rejected after sunset
        assert!(!verify_hybrid_request_signature(&ed_pk, &ml_pk, &data, &versioned_sig,));
    }

    fn make_versioned_hybrid_signature_v3(
        message: &[u8],
        context: &[u8],
        device_id: &str,
    ) -> (Vec<u8>, [u8; 32], Vec<u8>) {
        use ed25519_dalek::Signer;
        use prism_sync_crypto::pq::build_hybrid_message_representative;

        let secret = DeviceSecret::generate();
        let ed_signing_key = secret.ed25519_keypair(device_id).unwrap();
        let ed_public_key = ed_signing_key.public_key_bytes();
        let pq_signing_key = secret.ml_dsa_65_keypair(device_id).unwrap();
        let pq_public_key = pq_signing_key.public_key_bytes();

        let m_prime = build_hybrid_message_representative(context, message)
            .expect("hardcoded test context should be <= 255 bytes");
        let hybrid_sig = HybridSignature {
            ed25519_sig: ed_signing_key.into_signing_key().sign(&m_prime).to_bytes().to_vec(),
            ml_dsa_65_sig: pq_signing_key.sign(&m_prime),
        };

        let mut versioned = vec![0x03];
        versioned.extend_from_slice(&hybrid_sig.to_bytes());
        (versioned, ed_public_key, pq_public_key)
    }

    #[test]
    fn test_verify_hybrid_challenge_v3() {
        let sync_id = "a".repeat(64);
        let device_id = "test-device";
        let nonce = "test-nonce-123";

        let mut data = Vec::new();
        data.extend_from_slice(b"PRISM_SYNC_CHALLENGE_V2\x00");
        write_len_prefixed(&mut data, sync_id.as_bytes());
        write_len_prefixed(&mut data, device_id.as_bytes());
        write_len_prefixed(&mut data, nonce.as_bytes());

        let (versioned_sig, ed_pk, ml_pk) = make_versioned_hybrid_signature_v3(
            &data,
            hybrid_signature_contexts::DEVICE_CHALLENGE,
            device_id,
        );

        assert!(verify_hybrid_challenge(
            &ed_pk,
            &ml_pk,
            &sync_id,
            device_id,
            nonce,
            &versioned_sig,
        ));
        assert!(!verify_hybrid_challenge(
            &ed_pk,
            &ml_pk,
            &sync_id,
            device_id,
            "wrong-nonce",
            &versioned_sig,
        ));
    }

    #[test]
    fn test_verify_hybrid_request_signature_v3() {
        let device_id = "device-1";
        let data = build_request_signing_data_v2(
            "POST",
            "/v1/sync/sync123/rekey",
            &"a".repeat(64),
            device_id,
            br#"{"k":"v"}"#,
            "1700000000",
            "nonce-1",
        );

        let (versioned_sig, ed_pk, ml_pk) = make_versioned_hybrid_signature_v3(
            &data,
            hybrid_signature_contexts::HTTP_REQUEST,
            device_id,
        );
        assert!(verify_hybrid_request_signature(&ed_pk, &ml_pk, &data, &versioned_sig,));
    }

    #[test]
    fn test_verify_hybrid_request_signature_rejects_legacy_raw_ed25519() {
        use ed25519_dalek::Signer;

        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let data = build_request_signing_data_v2(
            "DELETE",
            "/v1/sync/sync123",
            &"a".repeat(64),
            "device-1",
            &[],
            "1700000000",
            "nonce-1",
        );
        let raw_sig = signing_key.sign(&data).to_bytes();

        assert!(!verify_hybrid_request_signature(
            signing_key.verifying_key().as_bytes(),
            &[0u8; 1952],
            &data,
            &raw_sig,
        ));
    }
}
