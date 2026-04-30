use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use crypto_secretbox::XSalsa20Poly1305;

use crate::error::{CryptoError, Result};

const XCHACHA_NONCE_LEN: usize = 24;
const XSALSA_NONCE_LEN: usize = 24;

// ── XChaCha20-Poly1305 (sync data encryption) ──

/// Encrypt plaintext with XChaCha20-Poly1305. Returns `nonce || ciphertext+MAC`.
pub fn xchacha_encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| CryptoError::InvalidKeyMaterial(format!("invalid key: {e}")))?;
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| CryptoError::EncryptionFailed(format!("encryption failed: {e}")))?;
    let mut out = Vec::with_capacity(XCHACHA_NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt `nonce || ciphertext+MAC` with XChaCha20-Poly1305.
pub fn xchacha_decrypt(key: &[u8], blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < XCHACHA_NONCE_LEN + 16 {
        return Err(CryptoError::DecryptionFailed("ciphertext too short".into()));
    }
    let (nonce_bytes, ciphertext) = blob.split_at(XCHACHA_NONCE_LEN);
    let nonce = XNonce::from_slice(nonce_bytes);
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| CryptoError::InvalidKeyMaterial(format!("invalid key: {e}")))?;
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::DecryptionFailed("decryption failed".into()))
}

/// Encrypt with XChaCha20-Poly1305 and AAD. Returns `nonce || ciphertext+MAC`.
pub fn xchacha_encrypt_aead(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| CryptoError::InvalidKeyMaterial(format!("invalid key: {e}")))?;
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let payload = chacha20poly1305::aead::Payload { msg: plaintext, aad };
    let ciphertext = cipher
        .encrypt(&nonce, payload)
        .map_err(|e| CryptoError::EncryptionFailed(format!("encryption failed: {e}")))?;
    let mut out = Vec::with_capacity(XCHACHA_NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt `nonce || ciphertext+MAC` with XChaCha20-Poly1305 and AAD.
pub fn xchacha_decrypt_aead(key: &[u8], blob: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < XCHACHA_NONCE_LEN + 16 {
        return Err(CryptoError::DecryptionFailed("ciphertext too short".into()));
    }
    let (nonce_bytes, ciphertext) = blob.split_at(XCHACHA_NONCE_LEN);
    let nonce = XNonce::from_slice(nonce_bytes);
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| CryptoError::InvalidKeyMaterial(format!("invalid key: {e}")))?;
    let payload = chacha20poly1305::aead::Payload { msg: ciphertext, aad };
    cipher
        .decrypt(nonce, payload)
        .map_err(|_| CryptoError::DecryptionFailed("decryption failed or AAD mismatch".into()))
}

/// Encrypt for sync: returns (ciphertext+MAC, nonce) separately.
pub fn xchacha_encrypt_for_sync(
    key: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, [u8; XCHACHA_NONCE_LEN])> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| CryptoError::InvalidKeyMaterial(format!("invalid key: {e}")))?;
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let payload = chacha20poly1305::aead::Payload { msg: plaintext, aad };
    let ciphertext = cipher
        .encrypt(&nonce, payload)
        .map_err(|e| CryptoError::EncryptionFailed(format!("encryption failed: {e}")))?;
    let mut nonce_arr = [0u8; XCHACHA_NONCE_LEN];
    nonce_arr.copy_from_slice(&nonce);
    Ok((ciphertext, nonce_arr))
}

/// Decrypt from sync: takes ciphertext+MAC and nonce separately.
pub fn xchacha_decrypt_from_sync(
    key: &[u8],
    ciphertext: &[u8],
    nonce: &[u8; XCHACHA_NONCE_LEN],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let nonce = XNonce::from_slice(nonce);
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| CryptoError::InvalidKeyMaterial(format!("invalid key: {e}")))?;
    let payload = chacha20poly1305::aead::Payload { msg: ciphertext, aad };
    cipher
        .decrypt(nonce, payload)
        .map_err(|_| CryptoError::DecryptionFailed("decryption failed or AAD mismatch".into()))
}

/// Compute a deterministic AEAD-based MAC over the given AAD with the given
/// key, using XChaCha20-Poly1305 with an all-zero nonce and empty plaintext.
///
/// Returns `nonce (24 bytes) || ciphertext+MAC` — for empty plaintext this
/// is `24 bytes nonce || 16 bytes Poly1305 tag` = 40 bytes.
///
/// Only safe for hash-material / commitment use cases where the AAD is a
/// well-known domain-separating string and the input is never used as
/// confidentiality material. The all-zero nonce is acceptable here because
/// the output is never decrypted — it is hashed (e.g., via SHA-256) to form
/// a commitment. The AAD makes the output unforgeable without the key.
///
/// Do NOT use this for encrypting any sensitive plaintext: the all-zero
/// nonce would leak plaintext on key reuse.
pub fn xchacha_aead_mac_zero_nonce(key: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| CryptoError::InvalidKeyMaterial(format!("invalid key: {e}")))?;
    let zero_nonce = [0u8; XCHACHA_NONCE_LEN];
    let xnonce = XNonce::from_slice(&zero_nonce);
    let payload = chacha20poly1305::aead::Payload { msg: &[], aad };
    let ciphertext = cipher
        .encrypt(xnonce, payload)
        .map_err(|e| CryptoError::EncryptionFailed(format!("encryption failed: {e}")))?;
    let mut out = Vec::with_capacity(XCHACHA_NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&zero_nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

// ── Cross-language test helpers (test-only, deterministic nonce) ──

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn xchacha_encrypt_with_nonce(
    key: &[u8],
    plaintext: &[u8],
    nonce: &[u8; 24],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| CryptoError::InvalidKeyMaterial(format!("invalid key: {e}")))?;
    let xnonce = XNonce::from_slice(nonce);
    let ciphertext = cipher
        .encrypt(xnonce, plaintext)
        .map_err(|e| CryptoError::EncryptionFailed(format!("encryption failed: {e}")))?;
    let mut out = Vec::with_capacity(XCHACHA_NONCE_LEN + ciphertext.len());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Wrap with a specific nonce (for cross-language test vectors).
/// In production, always use `secretbox_wrap` which generates a random nonce.
#[cfg(test)]
fn secretbox_wrap_with_nonce(mek: &[u8], plaintext: &[u8], nonce: &[u8; 24]) -> Result<Vec<u8>> {
    let cipher = XSalsa20Poly1305::new_from_slice(mek)
        .map_err(|e| CryptoError::InvalidKeyMaterial(format!("invalid MEK: {e}")))?;
    let xnonce = crypto_secretbox::Nonce::from_slice(nonce);
    let ciphertext = cipher
        .encrypt(xnonce, plaintext)
        .map_err(|e| CryptoError::EncryptionFailed(format!("secretbox seal failed: {e}")))?;
    let mut out = Vec::with_capacity(XSALSA_NONCE_LEN + ciphertext.len());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

// ── XSalsa20-Poly1305 (DEK wrapping) ──

/// Wrap DEK under MEK using XSalsa20-Poly1305 (secretbox).
/// Returns `nonce (24 bytes) || ciphertext+MAC`.
pub fn secretbox_wrap(mek: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XSalsa20Poly1305::new_from_slice(mek)
        .map_err(|e| CryptoError::InvalidKeyMaterial(format!("invalid MEK: {e}")))?;
    let nonce = XSalsa20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| CryptoError::EncryptionFailed(format!("secretbox seal failed: {e}")))?;
    let mut out = Vec::with_capacity(XSALSA_NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Unwrap DEK from `nonce || ciphertext+MAC` using XSalsa20-Poly1305.
pub fn secretbox_unwrap(mek: &[u8], wrapped: &[u8]) -> Result<Vec<u8>> {
    if wrapped.len() < XSALSA_NONCE_LEN + 16 {
        return Err(CryptoError::DecryptionFailed("wrapped DEK too short".into()));
    }
    let (nonce_bytes, ciphertext) = wrapped.split_at(XSALSA_NONCE_LEN);
    let nonce = crypto_secretbox::Nonce::from_slice(nonce_bytes);
    let cipher = XSalsa20Poly1305::new_from_slice(mek)
        .map_err(|e| CryptoError::InvalidKeyMaterial(format!("invalid MEK: {e}")))?;
    cipher.decrypt(nonce, ciphertext).map_err(|_| {
        CryptoError::DecryptionFailed(
            "secretbox open failed — wrong password or corrupted data".into(),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> Vec<u8> {
        vec![42u8; 32]
    }

    #[test]
    fn xchacha_roundtrip() {
        let key = test_key();
        let blob = xchacha_encrypt(&key, b"hello world").unwrap();
        let decrypted = xchacha_decrypt(&key, &blob).unwrap();
        assert_eq!(decrypted, b"hello world");
    }

    #[test]
    fn xchacha_different_ciphertexts() {
        let key = test_key();
        let blob1 = xchacha_encrypt(&key, b"same input").unwrap();
        let blob2 = xchacha_encrypt(&key, b"same input").unwrap();
        assert_ne!(blob1, blob2);
    }

    #[test]
    fn xchacha_wire_format_size() {
        let key = test_key();
        let blob = xchacha_encrypt(&key, b"abc").unwrap();
        assert_eq!(blob.len(), 43); // 24 + 3 + 16
    }

    #[test]
    fn xchacha_corrupted_fails() {
        let key = test_key();
        let mut blob = xchacha_encrypt(&key, b"test").unwrap();
        blob[30] ^= 0xff;
        assert!(xchacha_decrypt(&key, &blob).is_err());
    }

    #[test]
    fn xchacha_too_short_fails() {
        assert!(xchacha_decrypt(&test_key(), &[0u8; 10]).is_err());
    }

    #[test]
    fn xchacha_wrong_key_fails() {
        let blob = xchacha_encrypt(&[1u8; 32], b"test").unwrap();
        assert!(xchacha_decrypt(&[2u8; 32], &blob).is_err());
    }

    #[test]
    fn xchacha_aead_roundtrip() {
        let key = test_key();
        let blob = xchacha_encrypt_aead(&key, b"secret", b"aad").unwrap();
        let decrypted = xchacha_decrypt_aead(&key, &blob, b"aad").unwrap();
        assert_eq!(decrypted, b"secret");
    }

    #[test]
    fn xchacha_aead_wrong_aad_fails() {
        let key = test_key();
        let blob = xchacha_encrypt_aead(&key, b"secret", b"correct").unwrap();
        assert!(xchacha_decrypt_aead(&key, &blob, b"wrong").is_err());
    }

    #[test]
    fn sync_encrypt_decrypt_roundtrip() {
        let key = test_key();
        let aad = b"prism_sync|sync_id|device_id|0|batch_id|ops";
        let (ct, nonce) = xchacha_encrypt_for_sync(&key, b"ops data", aad).unwrap();
        let decrypted = xchacha_decrypt_from_sync(&key, &ct, &nonce, aad).unwrap();
        assert_eq!(decrypted, b"ops data");
    }

    #[test]
    fn sync_wrong_aad_fails() {
        let key = test_key();
        let (ct, nonce) = xchacha_encrypt_for_sync(&key, b"ops", b"aad1").unwrap();
        assert!(xchacha_decrypt_from_sync(&key, &ct, &nonce, b"aad2").is_err());
    }

    #[test]
    fn secretbox_roundtrip() {
        let mek = test_key();
        let dek = vec![99u8; 32];
        let wrapped = secretbox_wrap(&mek, &dek).unwrap();
        let unwrapped = secretbox_unwrap(&mek, &wrapped).unwrap();
        assert_eq!(unwrapped, dek);
    }

    #[test]
    fn secretbox_known_nonce_matches_dart_vector() {
        let key =
            crate::hex::decode("db84a725d43098af93af9ed0caab6816d78e717dcd0081b1f124017fa942ba1c")
                .unwrap();
        let nonce = [0x03u8; 24];
        let plaintext = [0x42u8; 32];
        let expected_ciphertext = crate::hex::decode(
            "53364972b9eff1856cb2aa5459cc9666e8cc05a9bae7f2801434e9db9d9c76a7e00e8bc926bd1d02fba122016349627e"
        ).unwrap();

        let blob = secretbox_wrap_with_nonce(&key, &plaintext, &nonce).unwrap();

        assert_eq!(&blob[..24], &nonce);
        assert_eq!(&blob[24..], expected_ciphertext.as_slice());
    }

    #[test]
    fn secretbox_wrong_key_fails() {
        let wrapped = secretbox_wrap(&[1u8; 32], &[99u8; 32]).unwrap();
        assert!(secretbox_unwrap(&[2u8; 32], &wrapped).is_err());
    }

    #[test]
    fn secretbox_too_short_fails() {
        assert!(secretbox_unwrap(&test_key(), &[0u8; 10]).is_err());
    }

    #[test]
    fn secretbox_wire_format_size() {
        let wrapped = secretbox_wrap(&test_key(), &[0u8; 32]).unwrap();
        assert_eq!(wrapped.len(), 72); // 24 + 32 + 16
    }
}
