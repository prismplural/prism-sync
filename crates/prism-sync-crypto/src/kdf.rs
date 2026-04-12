use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};

/// Argon2id parameters matching the Dart implementation.
const ARGON2_OPS_LIMIT: u32 = 3;
const ARGON2_MEM_LIMIT_KIB: u32 = 65536; // 64 MiB = 65536 KiB = 67108864 bytes
const ARGON2_OUTPUT_LEN: usize = 32;

/// Derive MEK (Master Encryption Key) from password + secret key using Argon2id.
///
/// Returns `Zeroizing<Vec<u8>>` — MEK is auto-zeroized when dropped.
pub fn derive_mek(password: &[u8], secret_key: &[u8], salt: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut combined = Zeroizing::new(Vec::with_capacity(password.len() + secret_key.len()));
    combined.extend_from_slice(password);
    combined.extend_from_slice(secret_key);

    let params = Params::new(
        ARGON2_MEM_LIMIT_KIB,
        ARGON2_OPS_LIMIT,
        1, // parallelism = 1 (libsodium default)
        Some(ARGON2_OUTPUT_LEN),
    )
    .map_err(|e| CryptoError::KdfFailed(format!("invalid Argon2 params: {e}")))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = Zeroizing::new(vec![0u8; ARGON2_OUTPUT_LEN]);
    argon2
        .hash_password_into(&combined, salt, &mut output)
        .map_err(|e| CryptoError::KdfFailed(format!("Argon2id failed: {e}")))?;

    Ok(output)
}

/// Derive a 32-byte subkey using HKDF-SHA256.
///
/// Returns `Zeroizing<Vec<u8>>` — subkey is auto-zeroized when dropped.
pub fn derive_subkey(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    // IMPORTANT: Empty salt must be treated as None (HashLen zeros) to match
    // PointyCastle's behavior where empty/null salt → SHA-256 HashLen zeros.
    let salt_opt = if salt.is_empty() { None } else { Some(salt) };
    let hk = Hkdf::<Sha256>::new(salt_opt, ikm);
    let mut output = Zeroizing::new(vec![0u8; 32]);
    hk.expand(info, &mut output)
        .map_err(|e| CryptoError::KdfFailed(format!("HKDF expand failed: {e}")))?;
    Ok(output)
}

/// Derive epoch 0 sync key from DEK.
pub fn derive_epoch_zero_key(dek: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let salt = 0u32.to_be_bytes();
    derive_subkey(dek, &salt, b"epoch_sync\0")
}

/// Derive group invitation secret from DEK.
pub fn derive_group_invite_secret(dek: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    derive_subkey(dek, &[], b"prism_group_invite")
}

/// Derive database encryption key from DEK.
pub fn derive_database_key(dek: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    derive_subkey(dek, &[], b"prism_database_key")
}

/// Derive the local storage key from DEK and device secret.
///
/// Used to tie the device's local database encryption key to both the
/// sync group identity (via DEK) and the device identity (via DeviceSecret).
/// IKM = DEK, salt = DeviceSecret bytes, info = "prism_local_storage_key".
pub fn derive_local_storage_key(dek: &[u8], device_secret: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    derive_subkey(dek, device_secret, b"prism_local_storage_key")
}

/// Derive an arbitrary-length subkey using HKDF-SHA256.
pub fn derive_subkey_long(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    len: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let salt_opt = if salt.is_empty() { None } else { Some(salt) };
    let hk = Hkdf::<Sha256>::new(salt_opt, ikm);
    let mut output = Zeroizing::new(vec![0u8; len]);
    hk.expand(info, &mut output)
        .map_err(|e| CryptoError::KdfFailed(format!("HKDF expand failed: {e}")))?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_mek_deterministic() {
        let password = b"test_password";
        let secret = vec![1u8; 16];
        let salt = vec![2u8; 16];
        let mek1 = derive_mek(password, &secret, &salt).unwrap();
        let mek2 = derive_mek(password, &secret, &salt).unwrap();
        assert_eq!(mek1.len(), 32);
        assert_eq!(*mek1, *mek2);
    }

    #[test]
    fn derive_mek_different_passwords() {
        let secret = vec![1u8; 16];
        let salt = vec![2u8; 16];
        let mek1 = derive_mek(b"password_a", &secret, &salt).unwrap();
        let mek2 = derive_mek(b"password_b", &secret, &salt).unwrap();
        assert_ne!(*mek1, *mek2);
    }

    #[test]
    fn derive_mek_different_secrets() {
        let password = b"test_password";
        let salt = vec![2u8; 16];
        let mek1 = derive_mek(password, &[1u8; 16], &salt).unwrap();
        let mek2 = derive_mek(password, &[3u8; 16], &salt).unwrap();
        assert_ne!(*mek1, *mek2);
    }

    #[test]
    fn derive_subkey_deterministic() {
        let ikm = vec![42u8; 32];
        let key1 = derive_subkey(&ikm, &[], b"test_info").unwrap();
        let key2 = derive_subkey(&ikm, &[], b"test_info").unwrap();
        assert_eq!(key1.len(), 32);
        assert_eq!(*key1, *key2);
    }

    #[test]
    fn derive_subkey_different_info() {
        let ikm = vec![42u8; 32];
        let key1 = derive_subkey(&ikm, &[], b"info_a").unwrap();
        let key2 = derive_subkey(&ikm, &[], b"info_b").unwrap();
        assert_ne!(*key1, *key2);
    }

    #[test]
    fn derive_epoch_zero_key_is_32_bytes() {
        let dek = vec![42u8; 32];
        let key = derive_epoch_zero_key(&dek).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn derive_group_invite_secret_is_32_bytes() {
        let dek = vec![42u8; 32];
        let key = derive_group_invite_secret(&dek).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn derive_database_key_is_32_bytes() {
        let dek = vec![42u8; 32];
        let key = derive_database_key(&dek).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn derive_subkey_long_64_bytes_deterministic() {
        let ikm = vec![42u8; 32];
        let key1 = derive_subkey_long(&ikm, b"salt", b"info", 64).unwrap();
        let key2 = derive_subkey_long(&ikm, b"salt", b"info", 64).unwrap();
        assert_eq!(key1.len(), 64);
        assert_eq!(*key1, *key2);
    }
}
