use std::collections::HashMap;

use rand::RngCore;
use zeroize::Zeroizing;

use crate::aead;
use crate::error::{CryptoError, Result};
use crate::kdf;

const SALT_LEN: usize = 16;
const DEK_LEN: usize = 32;
const WRAPPED_DEK_V2_PREFIX: &[u8] = b"PRISM_DEK_WRAP\x02";
const WRAPPED_DEK_AAD_DOMAIN: &[u8] = b"PRISM_SYNC_WRAPPED_DEK";
const WRAPPED_DEK_AAD_PURPOSE: &[u8] = b"mek-to-dek";
const WRAPPED_DEK_AAD_ALGORITHM: &[u8] = b"xchacha20poly1305";
const WRAPPED_DEK_AAD_KDF: &[u8] = b"argon2id-mek-v1";

fn push_len_prefixed_field(out: &mut Vec<u8>, field: &[u8]) -> Result<()> {
    let len: u16 = field.len().try_into().map_err(|_| {
        CryptoError::InvalidInput(format!("AAD field is too long: {} bytes", field.len()))
    })?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(field);
    Ok(())
}

fn build_wrapped_dek_v2_aad(salt: &[u8]) -> Result<Vec<u8>> {
    let mut aad = Vec::new();
    push_len_prefixed_field(&mut aad, WRAPPED_DEK_AAD_DOMAIN)?;
    aad.push(2);
    push_len_prefixed_field(&mut aad, WRAPPED_DEK_AAD_PURPOSE)?;
    push_len_prefixed_field(&mut aad, WRAPPED_DEK_AAD_ALGORITHM)?;
    push_len_prefixed_field(&mut aad, WRAPPED_DEK_AAD_KDF)?;
    aad.extend_from_slice(&(DEK_LEN as u16).to_be_bytes());
    push_len_prefixed_field(&mut aad, salt)?;
    Ok(aad)
}

fn wrap_dek_v2(mek: &[u8], dek: &[u8], salt: &[u8]) -> Result<Vec<u8>> {
    let aad = build_wrapped_dek_v2_aad(salt)?;
    let ciphertext = aead::xchacha_encrypt_aead(mek, dek, &aad)?;
    let mut wrapped = Vec::with_capacity(WRAPPED_DEK_V2_PREFIX.len() + ciphertext.len());
    wrapped.extend_from_slice(WRAPPED_DEK_V2_PREFIX);
    wrapped.extend_from_slice(&ciphertext);
    Ok(wrapped)
}

fn unwrap_dek_v2(mek: &[u8], wrapped: &[u8], salt: &[u8]) -> Result<Vec<u8>> {
    let ciphertext = wrapped.strip_prefix(WRAPPED_DEK_V2_PREFIX).ok_or_else(|| {
        CryptoError::InvalidKeyMaterial(
            "unsupported wrapped DEK format; beta reset requires v2 wrapped DEK".into(),
        )
    })?;
    let aad = build_wrapped_dek_v2_aad(salt)?;
    aead::xchacha_decrypt_aead(mek, ciphertext, &aad)
}

/// Manages the password-based key hierarchy for prism-sync.
///
/// Lifecycle:
/// 1. `initialize(password, secret_key)` — first-time setup, creates DEK
/// 2. `unlock(password, secret_key, wrapped_dek, salt)` — subsequent unlocks
/// 3. Use `epoch_key()`, `database_key()`, etc. while unlocked
/// 4. `lock()` — zeros all key material
///
/// All sensitive key material uses `Zeroizing<Vec<u8>>` for automatic cleanup.
/// The DEK and all epoch keys are zeroized on drop.
pub struct KeyHierarchy {
    unlocked: bool,
    dek: Zeroizing<Vec<u8>>,
    epoch_keys: HashMap<u32, Zeroizing<Vec<u8>>>,
}

impl Drop for KeyHierarchy {
    fn drop(&mut self) {
        self.unlocked = false;
        // dek: Zeroizing<Vec<u8>> handles DEK automatically
        // epoch_keys: each Zeroizing<Vec<u8>> zeroizes on drop when HashMap drops
    }
}

impl KeyHierarchy {
    pub fn new() -> Self {
        Self { unlocked: false, dek: Zeroizing::new(Vec::new()), epoch_keys: HashMap::new() }
    }

    pub fn is_unlocked(&self) -> bool {
        self.unlocked
    }

    /// First-time setup: generate random DEK, wrap under password+secret_key.
    /// Returns (wrapped_dek, salt) to persist in secure storage.
    pub fn initialize(&mut self, password: &str, secret_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut salt = vec![0u8; SALT_LEN];
        rand::rngs::OsRng.fill_bytes(&mut salt);

        let mut dek_bytes = Zeroizing::new(vec![0u8; DEK_LEN]);
        rand::rngs::OsRng.fill_bytes(&mut dek_bytes);

        // Derive MEK (Zeroizing — auto-cleaned on drop)
        let mek = kdf::derive_mek(password.as_bytes(), secret_key, &salt)?;

        // Wrap DEK under MEK with a versioned AEAD envelope.
        let wrapped_dek = wrap_dek_v2(&mek, &dek_bytes, &salt)?;

        // Store DEK
        self.dek = dek_bytes;
        self.unlocked = true;

        // Pre-derive epoch 0 key
        let epoch0 = kdf::derive_epoch_zero_key(&self.dek)?;
        self.epoch_keys.insert(0, epoch0);

        Ok((wrapped_dek, salt))
    }

    /// Unlock with existing credentials.
    pub fn unlock(
        &mut self,
        password: &str,
        secret_key: &[u8],
        wrapped_dek: &[u8],
        salt: &[u8],
    ) -> Result<()> {
        if !wrapped_dek.starts_with(WRAPPED_DEK_V2_PREFIX) {
            return Err(CryptoError::InvalidKeyMaterial(
                "unsupported wrapped DEK format; beta reset requires v2 wrapped DEK".into(),
            ));
        }

        let mek = kdf::derive_mek(password.as_bytes(), secret_key, salt)?;
        let dek = unwrap_dek_v2(&mek, wrapped_dek, salt)?;

        if dek.len() != DEK_LEN {
            return Err(CryptoError::InvalidKeyMaterial(format!(
                "DEK is {} bytes, expected {DEK_LEN}",
                dek.len()
            )));
        }

        self.dek = Zeroizing::new(dek);
        self.unlocked = true;

        let epoch0 = kdf::derive_epoch_zero_key(&self.dek)?;
        self.epoch_keys.insert(0, epoch0);

        Ok(())
    }

    /// Restore unlocked state directly from raw DEK bytes.
    ///
    /// Bypasses password-based key derivation (Argon2id). Use this when the
    /// host has recovered the DEK from a platform-protected runtime cache and
    /// needs to restore subsequent app launches without the user's password.
    pub fn restore_from_dek(&mut self, dek_bytes: &[u8]) -> Result<()> {
        if dek_bytes.len() != DEK_LEN {
            return Err(CryptoError::InvalidKeyMaterial(format!(
                "DEK is {} bytes, expected {DEK_LEN}",
                dek_bytes.len()
            )));
        }
        self.dek = Zeroizing::new(dek_bytes.to_vec());
        self.unlocked = true;

        let epoch0 = kdf::derive_epoch_zero_key(&self.dek)?;
        self.epoch_keys.insert(0, epoch0);

        Ok(())
    }

    /// Change password: re-wraps existing DEK under new password.
    /// Returns (new_wrapped_dek, new_salt). DEK itself does not change.
    pub fn change_password(
        &self,
        new_password: &str,
        secret_key: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        self.require_unlocked()?;

        let mut salt = vec![0u8; SALT_LEN];
        rand::rngs::OsRng.fill_bytes(&mut salt);

        let mek = kdf::derive_mek(new_password.as_bytes(), secret_key, &salt)?;
        let wrapped_dek = wrap_dek_v2(&mek, &self.dek, &salt)?;

        Ok((wrapped_dek, salt))
    }

    /// Get epoch key by epoch number.
    /// Epoch 0 is derived from DEK. Others must be stored via `store_epoch_key`.
    pub fn epoch_key(&self, epoch: u32) -> Result<&[u8]> {
        self.require_unlocked()?;
        self.epoch_keys.get(&epoch).map(|k| k.as_slice()).ok_or_else(|| {
            CryptoError::InvalidKeyMaterial(format!(
                "epoch {epoch} key not available — must be stored via store_epoch_key()"
            ))
        })
    }

    /// Store an epoch key received during rekey.
    pub fn store_epoch_key(&mut self, epoch: u32, key: Zeroizing<Vec<u8>>) {
        // Old value auto-zeroized when Zeroizing<Vec<u8>> drops
        self.epoch_keys.insert(epoch, key);
    }

    /// Remove a cached epoch key. Removed key material is zeroized on drop.
    pub fn remove_epoch_key(&mut self, epoch: u32) {
        self.epoch_keys.remove(&epoch);
    }

    pub fn has_epoch_key(&self, epoch: u32) -> bool {
        self.epoch_keys.contains_key(&epoch)
    }

    /// Return the sorted list of epochs for which keys are cached in memory.
    /// Diagnostic-only — does not expose any key material.
    pub fn known_epochs(&self) -> Vec<u32> {
        let mut epochs: Vec<u32> = self.epoch_keys.keys().copied().collect();
        epochs.sort_unstable();
        epochs
    }

    /// Iterate over (epoch, key) pairs in ascending epoch order.
    ///
    /// Yields a 32-byte array reference for each cached epoch key. Returns
    /// `Err` if any epoch key is not exactly 32 bytes (which would indicate
    /// corrupt state). The returned references borrow the `KeyHierarchy`
    /// — the caller must not keep them past the next mutation.
    pub fn epoch_keys_iter(&self) -> Result<Vec<(u32, &[u8; 32])>> {
        self.require_unlocked()?;
        let mut entries: Vec<(u32, &[u8; 32])> = Vec::with_capacity(self.epoch_keys.len());
        let mut epochs: Vec<u32> = self.epoch_keys.keys().copied().collect();
        epochs.sort_unstable();
        for epoch in epochs {
            let key_vec =
                self.epoch_keys.get(&epoch).expect("epoch key just enumerated should exist");
            let key_arr: &[u8; 32] = key_vec.as_slice().try_into().map_err(|_| {
                CryptoError::InvalidKeyMaterial(format!(
                    "epoch {epoch} key has unexpected length {}",
                    key_vec.len()
                ))
            })?;
            entries.push((epoch, key_arr));
        }
        Ok(entries)
    }

    /// Export all cached epoch keys (for SyncRuntimeKeys persistence).
    pub fn export_epoch_keys(&self) -> Result<HashMap<u32, Zeroizing<Vec<u8>>>> {
        self.require_unlocked()?;
        Ok(self.epoch_keys.iter().map(|(k, v)| (*k, Zeroizing::new(v.to_vec()))).collect())
    }

    /// Import epoch keys (for SyncRuntimeKeys restore).
    pub fn import_epoch_keys(&mut self, keys: HashMap<u32, Zeroizing<Vec<u8>>>) {
        for (epoch, key) in keys {
            self.epoch_keys.insert(epoch, key);
        }
    }

    /// Clear all cached epoch keys. Each is zeroized on drop.
    pub fn clear_epoch_keys(&mut self) {
        self.epoch_keys.clear();
    }

    /// Derive group invitation secret from DEK.
    pub fn group_invite_secret(&self) -> Result<Zeroizing<Vec<u8>>> {
        self.require_unlocked()?;
        kdf::derive_group_invite_secret(&self.dek)
    }

    /// Derive database encryption key from DEK.
    pub fn database_key(&self) -> Result<Zeroizing<Vec<u8>>> {
        self.require_unlocked()?;
        kdf::derive_database_key(&self.dek)
    }

    /// Derive the local storage key from DEK and device secret.
    ///
    /// Ties the device's local database encryption key to both the sync group
    /// identity (via DEK) and the device identity (via DeviceSecret). Returns
    /// an error if the hierarchy is locked or if no DeviceSecret is set.
    pub fn local_storage_key(&self, device_secret_bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        self.require_unlocked()?;
        kdf::derive_local_storage_key(&self.dek, device_secret_bytes)
    }

    /// Lock: zero all key material.
    pub fn lock(&mut self) {
        self.dek = Zeroizing::new(Vec::new());
        self.epoch_keys.clear();
        self.unlocked = false;
    }

    /// Get raw DEK bytes.
    pub fn dek(&self) -> Result<&[u8]> {
        self.require_unlocked()?;
        Ok(&self.dek)
    }

    fn require_unlocked(&self) -> Result<()> {
        if !self.unlocked {
            return Err(CryptoError::Locked);
        }
        Ok(())
    }
}

impl Default for KeyHierarchy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_secret_key() -> Vec<u8> {
        vec![1u8; 16]
    }

    #[test]
    fn starts_locked() {
        let kh = KeyHierarchy::new();
        assert!(!kh.is_unlocked());
    }

    #[test]
    fn initialize_unlocks() {
        let mut kh = KeyHierarchy::new();
        let (wrapped, salt) = kh.initialize("password", &test_secret_key()).unwrap();
        assert!(kh.is_unlocked());
        assert!(wrapped.starts_with(WRAPPED_DEK_V2_PREFIX));
        assert_eq!(salt.len(), 16);
    }

    #[test]
    fn lock_clears_state() {
        let mut kh = KeyHierarchy::new();
        kh.initialize("password", &test_secret_key()).unwrap();
        kh.lock();
        assert!(!kh.is_unlocked());
        assert!(kh.epoch_key(0).is_err());
    }

    #[test]
    fn unlock_with_correct_password() {
        let mut kh = KeyHierarchy::new();
        let secret = test_secret_key();
        let (wrapped, salt) = kh.initialize("password", &secret).unwrap();
        let epoch0_before = kh.epoch_key(0).unwrap().to_vec();
        kh.lock();

        kh.unlock("password", &secret, &wrapped, &salt).unwrap();
        assert!(kh.is_unlocked());
        assert_eq!(kh.epoch_key(0).unwrap(), epoch0_before);
    }

    #[test]
    fn unlock_with_wrong_password_fails() {
        let mut kh = KeyHierarchy::new();
        let secret = test_secret_key();
        let (wrapped, salt) = kh.initialize("password", &secret).unwrap();
        kh.lock();
        assert!(kh.unlock("wrong_password", &secret, &wrapped, &salt).is_err());
    }

    #[test]
    fn wrapped_dek_v2_roundtrip_preserves_dek() {
        let mut kh = KeyHierarchy::new();
        let secret = test_secret_key();
        let (wrapped, salt) = kh.initialize("password", &secret).unwrap();
        let dek = kh.dek().unwrap().to_vec();
        assert!(wrapped.starts_with(WRAPPED_DEK_V2_PREFIX));

        kh.lock();
        kh.unlock("password", &secret, &wrapped, &salt).unwrap();
        assert_eq!(kh.dek().unwrap(), dek);
    }

    #[test]
    fn wrapped_dek_v2_ciphertext_tampering_fails() {
        let mut kh = KeyHierarchy::new();
        let secret = test_secret_key();
        let (mut wrapped, salt) = kh.initialize("password", &secret).unwrap();
        let last = wrapped.len() - 1;
        wrapped[last] ^= 0xff;

        kh.lock();
        assert!(kh.unlock("password", &secret, &wrapped, &salt).is_err());
    }

    #[test]
    fn wrapped_dek_v2_salt_aad_tampering_fails() {
        let mut kh = KeyHierarchy::new();
        let secret = test_secret_key();
        let (wrapped, mut salt) = kh.initialize("password", &secret).unwrap();
        salt[0] ^= 0xff;

        kh.lock();
        assert!(kh.unlock("password", &secret, &wrapped, &salt).is_err());
    }

    #[test]
    fn wrapped_dek_v2_aad_binds_salt_independent_of_mek() {
        let secret = test_secret_key();
        let mut salt = vec![0u8; SALT_LEN];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let mek = kdf::derive_mek(b"password", &secret, &salt).unwrap();
        let dek = vec![7u8; DEK_LEN];
        let wrapped = wrap_dek_v2(&mek, &dek, &salt).unwrap();

        let mut aad_salt = salt.clone();
        aad_salt[0] ^= 0xff;
        assert!(unwrap_dek_v2(&mek, &wrapped, &aad_salt).is_err());
    }

    #[test]
    fn legacy_wrapped_dek_format_is_rejected() {
        let mut kh = KeyHierarchy::new();
        let secret = test_secret_key();
        let (_, salt) = kh.initialize("password", &secret).unwrap();
        kh.lock();

        let legacy_wrapped_dek = vec![0u8; 24 + DEK_LEN + 16];
        let err = kh
            .unlock("password", &secret, &legacy_wrapped_dek, &salt)
            .expect_err("legacy wrapped DEK must not unlock");
        assert!(err.to_string().contains("unsupported wrapped DEK format"));
    }

    #[test]
    fn unlock_with_wrong_secret_fails() {
        let mut kh = KeyHierarchy::new();
        let secret = test_secret_key();
        let (wrapped, salt) = kh.initialize("password", &secret).unwrap();
        kh.lock();
        assert!(kh.unlock("password", &[99u8; 16], &wrapped, &salt).is_err());
    }

    #[test]
    fn epoch_zero_key_is_32_bytes() {
        let mut kh = KeyHierarchy::new();
        kh.initialize("password", &test_secret_key()).unwrap();
        assert_eq!(kh.epoch_key(0).unwrap().len(), 32);
    }

    #[test]
    fn epoch_zero_key_consistent() {
        let mut kh = KeyHierarchy::new();
        let secret = test_secret_key();
        let (wrapped, salt) = kh.initialize("password", &secret).unwrap();
        let key1 = kh.epoch_key(0).unwrap().to_vec();
        kh.lock();
        kh.unlock("password", &secret, &wrapped, &salt).unwrap();
        assert_eq!(kh.epoch_key(0).unwrap(), key1);
    }

    #[test]
    fn database_key_is_32_bytes() {
        let mut kh = KeyHierarchy::new();
        kh.initialize("password", &test_secret_key()).unwrap();
        assert_eq!(kh.database_key().unwrap().len(), 32);
    }

    #[test]
    fn change_password_preserves_keys() {
        let mut kh = KeyHierarchy::new();
        let secret = test_secret_key();
        kh.initialize("old_password", &secret).unwrap();
        let epoch0 = kh.epoch_key(0).unwrap().to_vec();
        let db_key = kh.database_key().unwrap().to_vec();

        let (new_wrapped, new_salt) = kh.change_password("new_password", &secret).unwrap();
        assert!(new_wrapped.starts_with(WRAPPED_DEK_V2_PREFIX));
        kh.lock();
        kh.unlock("new_password", &secret, &new_wrapped, &new_salt).unwrap();
        assert_eq!(kh.epoch_key(0).unwrap(), epoch0);
        assert_eq!(*kh.database_key().unwrap(), db_key);
    }

    #[test]
    fn store_and_retrieve_epoch_key() {
        let mut kh = KeyHierarchy::new();
        kh.initialize("password", &test_secret_key()).unwrap();
        let epoch3_key = Zeroizing::new(vec![77u8; 32]);
        kh.store_epoch_key(3, epoch3_key.clone());
        assert!(kh.has_epoch_key(3));
        assert_eq!(kh.epoch_key(3).unwrap(), &*epoch3_key);
    }

    #[test]
    fn remove_epoch_key_removes_only_target_epoch() {
        let mut kh = KeyHierarchy::new();
        kh.initialize("password", &test_secret_key()).unwrap();
        let epoch3_key = Zeroizing::new(vec![77u8; 32]);
        let epoch4_key = Zeroizing::new(vec![88u8; 32]);
        kh.store_epoch_key(3, epoch3_key);
        kh.store_epoch_key(4, epoch4_key.clone());

        kh.remove_epoch_key(3);

        assert!(!kh.has_epoch_key(3));
        assert!(kh.epoch_key(3).is_err());
        assert_eq!(kh.epoch_key(4).unwrap(), &*epoch4_key);
        assert!(kh.has_epoch_key(0));
    }

    #[test]
    fn missing_epoch_key_returns_error() {
        let mut kh = KeyHierarchy::new();
        kh.initialize("password", &test_secret_key()).unwrap();
        assert!(kh.epoch_key(5).is_err());
    }

    #[test]
    fn locked_operations_fail() {
        let kh = KeyHierarchy::new();
        assert!(kh.epoch_key(0).is_err());
        assert!(kh.database_key().is_err());
        assert!(kh.group_invite_secret().is_err());
    }

    #[test]
    fn all_derived_keys_differ() {
        let mut kh = KeyHierarchy::new();
        kh.initialize("password", &test_secret_key()).unwrap();
        let epoch0 = kh.epoch_key(0).unwrap().to_vec();
        let db_key = kh.database_key().unwrap();
        let invite = kh.group_invite_secret().unwrap();
        assert_ne!(epoch0, *db_key);
        assert_ne!(epoch0, *invite);
        assert_ne!(*db_key, *invite);
    }

    #[test]
    fn device_identity_independent_of_dek() {
        use crate::{mnemonic, DeviceSecret, DeviceSigningKey};

        let device_secret = DeviceSecret::generate();
        let signing_key = device_secret.ed25519_keypair("device_123").unwrap();
        let _exchange_key = device_secret.x25519_keypair("device_123").unwrap();

        // Sign and verify
        let message = b"registration challenge data";
        let signature = signing_key.sign(message);
        DeviceSigningKey::verify(&signing_key.public_key_bytes(), message, &signature).unwrap();

        // Device keys differ from DEK-derived keys
        let mut kh = KeyHierarchy::new();
        let secret_key = mnemonic::to_bytes(&mnemonic::generate()).unwrap();
        kh.initialize("password", &secret_key).unwrap();
        assert_ne!(signing_key.public_key_bytes().to_vec(), kh.epoch_key(0).unwrap());
    }
}
