use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand::RngCore;
use sha2::{Digest, Sha256};

/// Generate a secure session token (32 random bytes, hex encoded = 64 chars).
pub fn generate_session_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// SHA-256 hash of a token string, returned as lowercase hex.
pub fn hash_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    hex::encode(digest)
}

/// Constant-time comparison for fixed-length values (SHA-256 hex digests).
///
/// XOR fold runs in constant time over the full length. The early length check
/// does not leak information because both inputs are always 64-char hex-encoded
/// SHA-256 hashes in practice.
pub fn timing_safe_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (&x, &y)| acc | (x ^ y))
        == 0
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

    verifying_key.verify(&data, &sig).is_ok()
}

/// Validate that a sync ID is a 64-char hex string (32 bytes).
pub fn is_valid_sync_id(sync_id: &str) -> bool {
    sync_id.len() == 64 && sync_id.chars().all(|c| c.is_ascii_hexdigit())
}

/// Write a length-prefixed field: `(data.len() as u32).to_be_bytes() || data`.
fn write_len_prefixed(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

/// Build the canonical bytes that get signed for an invitation.
///
/// Uses a deterministic binary format with domain separation prefix
/// `PRISM_SYNC_INVITE_V1\x00` to prevent signature reuse across protocols.
/// Mirrors `prism-sync-core::pairing::models::build_invitation_signing_data`.
pub fn build_invitation_signing_data(
    sync_id: &str,
    relay_url: &str,
    wrapped_dek: &[u8],
    salt: &[u8],
    inviter_device_id: &str,
    inviter_ed25519_pk: &[u8; 32],
    joiner_device_id: Option<&str>,
    current_epoch: u32,
    epoch_key: &[u8],
) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(b"PRISM_SYNC_INVITE_V1\x00");
    write_len_prefixed(&mut data, sync_id.as_bytes());
    write_len_prefixed(&mut data, relay_url.as_bytes());
    data.extend_from_slice(&(wrapped_dek.len() as u32).to_be_bytes());
    data.extend_from_slice(wrapped_dek);
    data.extend_from_slice(&(salt.len() as u32).to_be_bytes());
    data.extend_from_slice(salt);
    write_len_prefixed(&mut data, inviter_device_id.as_bytes());
    data.extend_from_slice(inviter_ed25519_pk);
    if let Some(jid) = joiner_device_id {
        write_len_prefixed(&mut data, jid.as_bytes());
    }
    data.extend_from_slice(&current_epoch.to_be_bytes());
    write_len_prefixed(&mut data, epoch_key);
    data
}

/// Verify an Ed25519 signature over invitation signing data.
pub fn verify_invitation_signature(
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
    verifying_key.verify(signing_data, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

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
}
