//! Prekey store for managing per-device signed hybrid prekeys.
//!
//! Maintains a current prekey and a set of previous (grace-period) prekeys
//! so that in-flight sharing-init messages targeting recently-rotated prekeys
//! can still be decapsulated.

use prism_sync_crypto::pq::hybrid_kem::XWingKem;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::sharing_models::SignedPrekey;
use crate::error::{CoreError, Result};
use crate::secure_store::SecureStore;
use crate::storage::StorageError;

/// 7 days in seconds.
const PREKEY_ROTATION_INTERVAL_SECS: i64 = 7 * 24 * 3600;
/// 72 hours in seconds.
const PREKEY_GRACE_PERIOD_SECS: i64 = 72 * 3600;
const XWING_DK_SEED_LEN: usize = 32;
const XWING_EK_LEN: usize = 1216;

pub const SHARING_PREKEY_STORE_KEY: &str = "sharing_prekey_store";

// ---------------------------------------------------------------------------
// PrekeyEntry
// ---------------------------------------------------------------------------

/// A single prekey entry with its decapsulation key material.
struct PrekeyEntry {
    prekey_id: String,
    /// 32-byte seed from which the X-Wing dk can be reconstructed.
    xwing_dk_seed: Zeroizing<[u8; 32]>,
    /// X-Wing encapsulation key (1216 bytes) — stored so the recipient can
    /// reconstruct the transcript without re-deriving from dk.
    xwing_ek: Vec<u8>,
    created_at: i64,
    /// When the grace period ends (only meaningful for previous entries).
    expires_at: i64,
}

// ---------------------------------------------------------------------------
// PrekeyStore
// ---------------------------------------------------------------------------

/// Manages current and previous prekeys for a single device.
///
/// The current prekey is the one published to the relay. Previous prekeys
/// are kept during a grace period so that in-flight sharing-init messages
/// can still be decapsulated.
pub struct PrekeyStore {
    current: Option<PrekeyEntry>,
    previous: Vec<PrekeyEntry>,
}

impl PrekeyStore {
    /// Create an empty prekey store.
    pub fn new() -> Self {
        Self {
            current: None,
            previous: Vec::new(),
        }
    }

    /// Get the decapsulation key seed for a prekey_id.
    ///
    /// Searches current and previous entries. Returns the 32-byte dk seed.
    pub fn get_dk_seed(&self, prekey_id: &str) -> Option<&[u8; 32]> {
        if let Some(ref entry) = self.current {
            if entry.prekey_id == prekey_id {
                return Some(&entry.xwing_dk_seed);
            }
        }
        for entry in &self.previous {
            if entry.prekey_id == prekey_id {
                return Some(&entry.xwing_dk_seed);
            }
        }
        None
    }

    /// Get the X-Wing encapsulation key for a prekey_id.
    ///
    /// Needed by the recipient to reconstruct the transcript.
    pub fn get_ek(&self, prekey_id: &str) -> Option<&[u8]> {
        if let Some(ref entry) = self.current {
            if entry.prekey_id == prekey_id {
                return Some(&entry.xwing_ek);
            }
        }
        for entry in &self.previous {
            if entry.prekey_id == prekey_id {
                return Some(&entry.xwing_ek);
            }
        }
        None
    }

    /// Check if the current prekey needs rotation (older than 7 days or missing).
    pub fn needs_rotation(&self, now: i64) -> bool {
        match &self.current {
            None => true,
            Some(entry) => (now - entry.created_at) >= PREKEY_ROTATION_INTERVAL_SECS,
        }
    }

    /// Generate a new prekey. Signs it with the user identity keys.
    ///
    /// Pushes the current prekey to previous (with grace period expiry).
    /// Prunes expired previous entries.
    /// Returns the new [`SignedPrekey`] for upload to the relay.
    pub fn rotate(
        &mut self,
        ed25519_sk: &ed25519_dalek::SigningKey,
        ml_dsa_sk: &impl ml_dsa::signature::Signer<ml_dsa::Signature<ml_dsa::MlDsa65>>,
        device_id: &str,
        now: i64,
    ) -> Result<SignedPrekey> {
        // 1. Generate fresh X-Wing keypair from CSPRNG seed
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(seed.as_mut())
            .map_err(|e| CoreError::Engine(format!("CSPRNG failed: {e}")))?;
        let dk = XWingKem::decapsulation_key_from_bytes(&seed);
        let ek = XWingKem::encapsulation_key_bytes(&dk);

        // 2. Generate prekey_id: 16 random bytes, hex-encoded
        let mut id_bytes = [0u8; 16];
        getrandom::fill(&mut id_bytes)
            .map_err(|e| CoreError::Engine(format!("CSPRNG failed: {e}")))?;
        let prekey_id = hex::encode(id_bytes);

        // 3. Sign the prekey
        let signed_prekey = SignedPrekey::sign(
            prekey_id.clone(),
            device_id.to_string(),
            ek.clone(),
            now,
            ed25519_sk,
            ml_dsa_sk,
        );

        // 4. Push current to previous with grace period
        if let Some(old) = self.current.take() {
            self.previous.push(PrekeyEntry {
                prekey_id: old.prekey_id,
                xwing_dk_seed: old.xwing_dk_seed,
                xwing_ek: old.xwing_ek,
                created_at: old.created_at,
                expires_at: now + PREKEY_GRACE_PERIOD_SECS,
            });
        }

        // 5. Set new current
        self.current = Some(PrekeyEntry {
            prekey_id,
            xwing_dk_seed: seed,
            xwing_ek: ek,
            created_at: now,
            expires_at: i64::MAX, // current never expires
        });

        // 6. Prune expired previous entries
        self.prune_expired(now);

        Ok(signed_prekey)
    }

    /// Prune expired previous entries.
    pub fn prune_expired(&mut self, now: i64) {
        self.previous.retain(|entry| entry.expires_at > now);
    }

    /// Get the current prekey_id (for relay upload tracking).
    pub fn current_prekey_id(&self) -> Option<&str> {
        self.current.as_ref().map(|e| e.prekey_id.as_str())
    }

    /// Serialize for secure storage.
    pub fn to_json(&self) -> Result<String> {
        let serializable = SerializablePrekeyStore {
            current: self.current.as_ref().map(entry_to_serializable),
            previous: self.previous.iter().map(entry_to_serializable).collect(),
        };
        serde_json::to_string(&serializable).map_err(CoreError::from)
    }

    /// Deserialize from secure storage.
    pub fn from_json(json: &str) -> Result<Self> {
        let serializable: SerializablePrekeyStore =
            serde_json::from_str(json).map_err(CoreError::from)?;
        let current = match serializable.current {
            Some(entry) => Some(serializable_to_entry(entry)?),
            None => None,
        };
        let previous = serializable
            .previous
            .into_iter()
            .map(serializable_to_entry)
            .collect::<Result<Vec<_>>>()?;

        Ok(Self { current, previous })
    }

    pub fn load(secure_store: &dyn SecureStore) -> Result<Self> {
        match secure_store.get(SHARING_PREKEY_STORE_KEY)? {
            Some(bytes) => {
                let json = String::from_utf8(bytes).map_err(|e| {
                    CoreError::Storage(StorageError::Logic(format!("invalid UTF-8 in {SHARING_PREKEY_STORE_KEY}: {e}")))
                })?;
                Self::from_json(&json)
            }
            None => Ok(Self::new()),
        }
    }

    pub fn save(&self, secure_store: &dyn SecureStore) -> Result<()> {
        let json = self.to_json()?;
        secure_store.set(SHARING_PREKEY_STORE_KEY, json.as_bytes())
    }

    pub fn clear_persisted(secure_store: &dyn SecureStore) -> Result<()> {
        secure_store.delete(SHARING_PREKEY_STORE_KEY)
    }
}

impl Default for PrekeyStore {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// JSON serialization helpers
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct SerializablePrekeyEntry {
    prekey_id: String,
    xwing_dk_seed_hex: String,
    xwing_ek_hex: String,
    created_at: i64,
    expires_at: i64,
}

#[derive(Serialize, Deserialize)]
struct SerializablePrekeyStore {
    current: Option<SerializablePrekeyEntry>,
    previous: Vec<SerializablePrekeyEntry>,
}

fn entry_to_serializable(entry: &PrekeyEntry) -> SerializablePrekeyEntry {
    SerializablePrekeyEntry {
        prekey_id: entry.prekey_id.clone(),
        xwing_dk_seed_hex: hex::encode(entry.xwing_dk_seed.as_ref()),
        xwing_ek_hex: hex::encode(&entry.xwing_ek),
        created_at: entry.created_at,
        expires_at: entry.expires_at,
    }
}

fn serializable_to_entry(s: SerializablePrekeyEntry) -> Result<PrekeyEntry> {
    let prekey_id = s.prekey_id.clone();
    let seed_bytes = hex::decode(&s.xwing_dk_seed_hex).map_err(|e| {
        CoreError::Storage(StorageError::Logic(format!(
            "invalid xwing_dk_seed_hex for prekey {prekey_id}: {e}"
        )))
    })?;
    if seed_bytes.len() != XWING_DK_SEED_LEN {
        return Err(CoreError::Storage(StorageError::Logic(format!(
            "invalid xwing_dk_seed length for prekey {prekey_id}: expected {XWING_DK_SEED_LEN} bytes, got {}",
            seed_bytes.len()
        ))));
    }

    let xwing_ek = hex::decode(&s.xwing_ek_hex).map_err(|e| {
        CoreError::Storage(StorageError::Logic(format!("invalid xwing_ek_hex for prekey {prekey_id}: {e}")))
    })?;
    if xwing_ek.len() != XWING_EK_LEN {
        return Err(CoreError::Storage(StorageError::Logic(format!(
            "invalid xwing_ek length for prekey {prekey_id}: expected {XWING_EK_LEN} bytes, got {}",
            xwing_ek.len()
        ))));
    }

    let mut seed = Zeroizing::new([0u8; XWING_DK_SEED_LEN]);
    seed.copy_from_slice(&seed_bytes);

    Ok(PrekeyEntry {
        prekey_id: s.prekey_id,
        xwing_dk_seed: seed,
        xwing_ek,
        created_at: s.created_at,
        expires_at: s.expires_at,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use ml_dsa::{KeyGen, MlDsa65};
    use std::collections::HashMap;
    use std::sync::Mutex;

    fn test_identity_keys() -> (SigningKey, ml_dsa::SigningKey<MlDsa65>) {
        let ed_sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let mut rng = getrandom::rand_core::UnwrapErr(getrandom::SysRng);
        let ml_sk = MlDsa65::key_gen(&mut rng);
        (ed_sk, ml_sk)
    }

    #[derive(Default)]
    struct MemStore {
        data: Mutex<HashMap<String, Vec<u8>>>,
    }

    impl SecureStore for MemStore {
        fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
            Ok(self.data.lock().unwrap().get(key).cloned())
        }

        fn set(&self, key: &str, value: &[u8]) -> Result<()> {
            self.data
                .lock()
                .unwrap()
                .insert(key.to_string(), value.to_vec());
            Ok(())
        }

        fn delete(&self, key: &str) -> Result<()> {
            self.data.lock().unwrap().remove(key);
            Ok(())
        }

        fn clear(&self) -> Result<()> {
            self.data.lock().unwrap().clear();
            Ok(())
        }
    }

    #[test]
    fn new_store_has_no_current() {
        let store = PrekeyStore::new();
        assert!(store.current_prekey_id().is_none());
        assert!(store.get_dk_seed("anything").is_none());
    }

    #[test]
    fn after_rotate_current_exists() {
        let mut store = PrekeyStore::new();
        let (ed_sk, ml_sk) = test_identity_keys();
        let now = 1_700_000_000i64;

        let prekey = store.rotate(&ed_sk, &ml_sk, "device-1", now).unwrap();
        assert!(store.current_prekey_id().is_some());
        assert_eq!(store.current_prekey_id().unwrap(), prekey.prekey_id);
        assert!(store.get_dk_seed(&prekey.prekey_id).is_some());
        assert!(store.get_ek(&prekey.prekey_id).is_some());
    }

    #[test]
    fn second_rotate_keeps_previous_accessible() {
        let mut store = PrekeyStore::new();
        let (ed_sk, ml_sk) = test_identity_keys();
        let now = 1_700_000_000i64;

        let prekey1 = store.rotate(&ed_sk, &ml_sk, "device-1", now).unwrap();
        let prekey2 = store.rotate(&ed_sk, &ml_sk, "device-1", now + 1).unwrap();

        // Both accessible
        assert!(store.get_dk_seed(&prekey1.prekey_id).is_some());
        assert!(store.get_dk_seed(&prekey2.prekey_id).is_some());
        // Current is prekey2
        assert_eq!(store.current_prekey_id().unwrap(), prekey2.prekey_id);
    }

    #[test]
    fn grace_period_expiry_prunes_previous() {
        let mut store = PrekeyStore::new();
        let (ed_sk, ml_sk) = test_identity_keys();
        let now = 1_700_000_000i64;

        let prekey1 = store.rotate(&ed_sk, &ml_sk, "device-1", now).unwrap();
        let _prekey2 = store.rotate(&ed_sk, &ml_sk, "device-1", now + 1).unwrap();

        // prekey1 should still be accessible (grace period hasn't expired)
        assert!(store.get_dk_seed(&prekey1.prekey_id).is_some());

        // After grace period expires
        store.prune_expired(now + PREKEY_GRACE_PERIOD_SECS + 2);
        assert!(store.get_dk_seed(&prekey1.prekey_id).is_none());
    }

    #[test]
    fn needs_rotation_true_when_no_current() {
        let store = PrekeyStore::new();
        assert!(store.needs_rotation(1_700_000_000));
    }

    #[test]
    fn needs_rotation_true_when_old() {
        let mut store = PrekeyStore::new();
        let (ed_sk, ml_sk) = test_identity_keys();
        let now = 1_700_000_000i64;

        store.rotate(&ed_sk, &ml_sk, "device-1", now).unwrap();
        // 7 days later
        assert!(store.needs_rotation(now + PREKEY_ROTATION_INTERVAL_SECS));
    }

    #[test]
    fn needs_rotation_false_when_fresh() {
        let mut store = PrekeyStore::new();
        let (ed_sk, ml_sk) = test_identity_keys();
        let now = 1_700_000_000i64;

        store.rotate(&ed_sk, &ml_sk, "device-1", now).unwrap();
        // 1 day later
        assert!(!store.needs_rotation(now + 86400));
    }

    #[test]
    fn json_round_trip() {
        let mut store = PrekeyStore::new();
        let (ed_sk, ml_sk) = test_identity_keys();
        let now = 1_700_000_000i64;

        let prekey1 = store.rotate(&ed_sk, &ml_sk, "device-1", now).unwrap();
        let prekey2 = store.rotate(&ed_sk, &ml_sk, "device-1", now + 100).unwrap();

        let json = store.to_json().unwrap();
        let restored = PrekeyStore::from_json(&json).unwrap();

        assert_eq!(restored.current_prekey_id().unwrap(), prekey2.prekey_id);
        assert!(restored.get_dk_seed(&prekey1.prekey_id).is_some());
        assert!(restored.get_dk_seed(&prekey2.prekey_id).is_some());
        assert!(restored.get_ek(&prekey1.prekey_id).is_some());
        assert!(restored.get_ek(&prekey2.prekey_id).is_some());

        // dk seeds should match
        assert_eq!(
            store.get_dk_seed(&prekey1.prekey_id).unwrap(),
            restored.get_dk_seed(&prekey1.prekey_id).unwrap()
        );
    }

    #[test]
    fn from_json_rejects_invalid_seed_hex() {
        let json = serde_json::json!({
            "current": {
                "prekey_id": "pk-1",
                "xwing_dk_seed_hex": "not-hex",
                "xwing_ek_hex": hex::encode(vec![0xAB; XWING_EK_LEN]),
                "created_at": 1_700_000_000i64,
                "expires_at": i64::MAX,
            },
            "previous": [],
        })
        .to_string();

        let err = match PrekeyStore::from_json(&json) {
            Ok(_) => panic!("expected invalid seed hex to fail"),
            Err(err) => err.to_string(),
        };
        assert!(
            err.contains("invalid xwing_dk_seed_hex"),
            "expected invalid seed error, got: {err}"
        );
    }

    #[test]
    fn from_json_rejects_invalid_xwing_ek_length() {
        let json = serde_json::json!({
            "current": {
                "prekey_id": "pk-1",
                "xwing_dk_seed_hex": hex::encode([0x11; XWING_DK_SEED_LEN]),
                "xwing_ek_hex": hex::encode(vec![0xAB; XWING_EK_LEN - 1]),
                "created_at": 1_700_000_000i64,
                "expires_at": i64::MAX,
            },
            "previous": [],
        })
        .to_string();

        let err = match PrekeyStore::from_json(&json) {
            Ok(_) => panic!("expected invalid xwing_ek length to fail"),
            Err(err) => err.to_string(),
        };
        assert!(
            err.contains("invalid xwing_ek length"),
            "expected invalid xwing_ek length error, got: {err}"
        );
    }

    #[test]
    fn save_and_load_secure_store_round_trip() {
        let mut store = PrekeyStore::new();
        let (ed_sk, ml_sk) = test_identity_keys();
        let now = 1_700_000_000i64;
        let prekey = store.rotate(&ed_sk, &ml_sk, "device-1", now).unwrap();
        let secure_store = MemStore::default();

        store.save(&secure_store).unwrap();

        let restored = PrekeyStore::load(&secure_store).unwrap();
        assert_eq!(restored.current_prekey_id().unwrap(), prekey.prekey_id);
        assert!(restored.get_dk_seed(&prekey.prekey_id).is_some());
        assert!(restored.get_ek(&prekey.prekey_id).is_some());
    }

    #[test]
    fn load_missing_secure_store_returns_empty_store() {
        let secure_store = MemStore::default();
        let restored = PrekeyStore::load(&secure_store).unwrap();
        assert!(restored.current_prekey_id().is_none());
    }

    #[test]
    fn signed_prekey_verifies_against_identity() {
        let mut store = PrekeyStore::new();
        let (ed_sk, ml_sk) = test_identity_keys();
        let now = 1_700_000_000i64;

        let ed_pk = ed_sk.verifying_key().to_bytes();
        let ml_vk = ml_dsa::signature::Keypair::verifying_key(&ml_sk);
        let ml_pk = AsRef::<[u8]>::as_ref(&ml_vk.encode()).to_vec();

        let identity = super::super::sharing_models::SharingIdentityBundle::sign(
            "test-sharing-id".to_string(),
            0,
            ed_pk,
            ml_pk,
            &ed_sk,
            &ml_sk,
        );

        let prekey = store.rotate(&ed_sk, &ml_sk, "device-1", now).unwrap();
        prekey.verify(&identity).unwrap();
    }
}
