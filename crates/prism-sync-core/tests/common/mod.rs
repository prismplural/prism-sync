//! Shared test fixtures for prism-sync-core integration tests.
//!
//! Not every test file uses every item, so we allow dead_code globally.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Mutex;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

use prism_sync_core::relay::{DeviceInfo, MockRelay};
use prism_sync_core::schema::{SyncFieldDef, SyncSchema, SyncType, SyncValue};
use prism_sync_core::secure_store::SecureStore;
use prism_sync_core::storage::RusqliteSyncStorage;
use prism_sync_core::syncable_entity::SyncableEntity;
use prism_sync_core::{CrdtChange, SyncMetadata};

// ═══════════════════════════════════════════════════════════════════════════
// MemorySecureStore — simple in-memory SecureStore for testing
// ═══════════════════════════════════════════════════════════════════════════

pub struct MemorySecureStore {
    data: Mutex<HashMap<String, Vec<u8>>>,
}

impl MemorySecureStore {
    pub fn new() -> Self {
        Self {
            data: Mutex::new(HashMap::new()),
        }
    }
}

impl SecureStore for MemorySecureStore {
    fn get(&self, key: &str) -> prism_sync_core::Result<Option<Vec<u8>>> {
        Ok(self.data.lock().unwrap().get(key).cloned())
    }

    fn set(&self, key: &str, value: &[u8]) -> prism_sync_core::Result<()> {
        self.data
            .lock()
            .unwrap()
            .insert(key.to_string(), value.to_vec());
        Ok(())
    }

    fn delete(&self, key: &str) -> prism_sync_core::Result<()> {
        self.data.lock().unwrap().remove(key);
        Ok(())
    }

    fn clear(&self) -> prism_sync_core::Result<()> {
        self.data.lock().unwrap().clear();
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// MockTaskEntity — in-memory SyncableEntity for testing
// ═══════════════════════════════════════════════════════════════════════════

/// A test entity that stores rows in a `HashMap<entity_id, HashMap<field, SyncValue>>`.
pub struct MockTaskEntity {
    rows: Mutex<HashMap<String, HashMap<String, SyncValue>>>,
    deleted: Mutex<HashMap<String, bool>>,
}

impl MockTaskEntity {
    pub fn new() -> Self {
        Self {
            rows: Mutex::new(HashMap::new()),
            deleted: Mutex::new(HashMap::new()),
        }
    }

    pub fn get_field(&self, entity_id: &str, field: &str) -> Option<SyncValue> {
        self.rows
            .lock()
            .unwrap()
            .get(entity_id)
            .and_then(|row| row.get(field).cloned())
    }
}

#[async_trait::async_trait]
impl SyncableEntity for MockTaskEntity {
    fn table_name(&self) -> &str {
        "tasks"
    }

    fn field_definitions(&self) -> &[SyncFieldDef] {
        // Leak a static slice for the test lifetime — fine in tests.
        static FIELDS: std::sync::LazyLock<Vec<SyncFieldDef>> = std::sync::LazyLock::new(|| {
            vec![
                SyncFieldDef {
                    name: "title".to_string(),
                    sync_type: SyncType::String,
                },
                SyncFieldDef {
                    name: "done".to_string(),
                    sync_type: SyncType::Bool,
                },
            ]
        });
        &FIELDS
    }

    async fn read_row(
        &self,
        entity_id: &str,
    ) -> prism_sync_core::Result<Option<HashMap<String, SyncValue>>> {
        Ok(self.rows.lock().unwrap().get(entity_id).cloned())
    }

    async fn write_fields(
        &self,
        entity_id: &str,
        fields: &HashMap<String, SyncValue>,
        _hlc: &str,
        _is_new: bool,
    ) -> prism_sync_core::Result<()> {
        let mut rows = self.rows.lock().unwrap();
        let row = rows.entry(entity_id.to_string()).or_default();
        for (k, v) in fields {
            row.insert(k.clone(), v.clone());
        }
        Ok(())
    }

    async fn soft_delete(&self, entity_id: &str, _hlc: &str) -> prism_sync_core::Result<()> {
        self.deleted
            .lock()
            .unwrap()
            .insert(entity_id.to_string(), true);
        Ok(())
    }

    async fn is_deleted(&self, entity_id: &str) -> prism_sync_core::Result<bool> {
        Ok(self
            .deleted
            .lock()
            .unwrap()
            .get(entity_id)
            .copied()
            .unwrap_or(false))
    }

    async fn hard_delete(&self, entity_id: &str) -> prism_sync_core::Result<()> {
        self.rows.lock().unwrap().remove(entity_id);
        self.deleted.lock().unwrap().remove(entity_id);
        Ok(())
    }

    async fn begin_batch(&self) -> prism_sync_core::Result<()> {
        Ok(())
    }
    async fn commit_batch(&self) -> prism_sync_core::Result<()> {
        Ok(())
    }
    async fn rollback_batch(&self) -> prism_sync_core::Result<()> {
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Test helpers
// ═══════════════════════════════════════════════════════════════════════════

pub const SYNC_ID: &str = "test-sync-group";

pub fn test_schema() -> SyncSchema {
    SyncSchema::builder()
        .entity("tasks", |e| {
            e.field("title", SyncType::String)
                .field("done", SyncType::Bool)
        })
        .build()
}

pub fn make_signing_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

pub fn init_key_hierarchy() -> prism_sync_crypto::KeyHierarchy {
    let mut kh = prism_sync_crypto::KeyHierarchy::new();
    kh.initialize("test-password", &[1u8; 16]).unwrap();
    kh
}

/// Register sync metadata so the engine can find it.
pub fn setup_sync_metadata(storage: &RusqliteSyncStorage, device_id: &str) {
    use prism_sync_core::storage::SyncStorage;
    let mut tx = storage.begin_tx().unwrap();
    tx.upsert_sync_metadata(&SyncMetadata {
        sync_id: SYNC_ID.to_string(),
        local_device_id: device_id.to_string(),
        current_epoch: 0,
        last_pulled_server_seq: 0,
        last_pushed_at: None,
        last_successful_sync_at: None,
        registered_at: Some(chrono::Utc::now()),
        needs_rekey: false,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    })
    .unwrap();
    tx.commit().unwrap();
}

/// Register a device in both the relay and storage so signature verification works.
pub fn register_device(
    relay: &MockRelay,
    storage: &RusqliteSyncStorage,
    device_id: &str,
    verifying_key: &ed25519_dalek::VerifyingKey,
) {
    use prism_sync_core::storage::{DeviceRecord, SyncStorage};

    let pk_bytes = verifying_key.to_bytes().to_vec();

    relay.add_device(DeviceInfo {
        device_id: device_id.to_string(),
        epoch: 0,
        status: "active".to_string(),
        ed25519_public_key: pk_bytes.clone(),
        x25519_public_key: vec![0u8; 32],
        permission: None,
    });

    let mut tx = storage.begin_tx().unwrap();
    tx.upsert_device_record(&DeviceRecord {
        sync_id: SYNC_ID.to_string(),
        device_id: device_id.to_string(),
        ed25519_public_key: pk_bytes,
        x25519_public_key: vec![0u8; 32],
        ml_dsa_65_public_key: Vec::new(),
        ml_kem_768_public_key: Vec::new(),
        status: "active".to_string(),
        registered_at: chrono::Utc::now(),
        revoked_at: None,
    })
    .unwrap();
    tx.commit().unwrap();
}

/// Insert pending ops into storage so the engine can push them.
pub fn insert_pending_ops(storage: &RusqliteSyncStorage, ops: &[CrdtChange], batch_id: &str) {
    use prism_sync_core::storage::{PendingOp, SyncStorage};
    let mut tx = storage.begin_tx().unwrap();
    for op in ops {
        tx.insert_pending_op(&PendingOp {
            op_id: op.op_id.clone(),
            sync_id: SYNC_ID.to_string(),
            epoch: op.epoch,
            device_id: op.device_id.clone(),
            local_batch_id: batch_id.to_string(),
            entity_table: op.entity_table.clone(),
            entity_id: op.entity_id.clone(),
            field_name: op.field_name.clone(),
            encoded_value: op.encoded_value.clone(),
            is_delete: op.is_delete,
            client_hlc: op.client_hlc.clone(),
            created_at: chrono::Utc::now(),
            pushed_at: None,
        })
        .unwrap();
    }
    tx.commit().unwrap();
}
