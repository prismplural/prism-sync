use std::collections::HashMap;

use rand::RngCore;
use zeroize::Zeroizing;

use crate::aead;
use crate::error::{CryptoError, Result};
use crate::kdf;

const SALT_LEN: usize = 16;
const DEK_LEN: usize = 32;

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
        Self {
            unlocked: false,
            dek: Zeroizing::new(Vec::new()),
            epoch_keys: HashMap::new(),
        }
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

        // Wrap DEK under MEK
        let wrapped_dek = aead::secretbox_wrap(&mek, &dek_bytes)?;

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
        let mek = kdf::derive_mek(password.as_bytes(), secret_key, salt)?;
        let dek = aead::secretbox_unwrap(&mek, wrapped_dek)?;

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
    /// raw DEK has been persisted in a platform keychain and needs to be
    /// restored on subsequent app launches without the user's password.
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
        let wrapped_dek = aead::secretbox_wrap(&mek, &self.dek)?;

        Ok((wrapped_dek, salt))
    }

    /// Get epoch key by epoch number.
    /// Epoch 0 is derived from DEK. Others must be stored via `store_epoch_key`.
    pub fn epoch_key(&self, epoch: u32) -> Result<&[u8]> {
        self.require_unlocked()?;
        self.epoch_keys
            .get(&epoch)
            .map(|k| k.as_slice())
            .ok_or_else(|| {
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

    pub fn has_epoch_key(&self, epoch: u32) -> bool {
        self.epoch_keys.contains_key(&epoch)
    }

    /// Export all cached epoch keys (for SyncRuntimeKeys persistence).
    pub fn export_epoch_keys(&self) -> Result<HashMap<u32, Zeroizing<Vec<u8>>>> {
        self.require_unlocked()?;
        Ok(self
            .epoch_keys
            .iter()
            .map(|(k, v)| (*k, Zeroizing::new(v.to_vec())))
            .collect())
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
    pub fn local_storage_key(
        &self,
        device_secret_bytes: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
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
        assert!(!wrapped.is_empty());
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
        assert!(kh
            .unlock("wrong_password", &secret, &wrapped, &salt)
            .is_err());
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
        kh.lock();
        kh.unlock("new_password", &secret, &new_wrapped, &new_salt)
            .unwrap();
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
        assert_ne!(
            signing_key.public_key_bytes().to_vec(),
            kh.epoch_key(0).unwrap()
        );
    }
}
