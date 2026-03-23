//! Integration tests for ephemeral snapshot feature.
//!
//! These tests verify the snapshot upload, bootstrap, and incremental sync
//! interactions using in-memory storage and MockRelay.
//!
//! **Key insight:** `field_versions` are only populated during the *merge*
//! phase (when pulling remote ops). A device that only pushes its own ops
//! will not have field_versions in its storage. Therefore, for snapshot tests
//! that need populated snapshots, we use a two-device pattern:
//!   1. Device A pushes ops to the relay.
//!   2. Device B pulls and merges them (populating field_versions on B).
//!   3. Device B exports/uploads the snapshot.
//!   4. Device C bootstraps from the snapshot.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

use prism_sync_core::engine::{SyncConfig, SyncEngine};
use prism_sync_core::relay::{DeviceInfo, MockRelay};
use prism_sync_core::schema::{SyncFieldDef, SyncSchema, SyncType, SyncValue};
use prism_sync_core::storage::RusqliteSyncStorage;
use prism_sync_core::syncable_entity::SyncableEntity;
use prism_sync_core::{CrdtChange, Hlc, SyncMetadata};

// ═══════════════════════════════════════════════════════════════════════════
// MockTaskEntity — in-memory SyncableEntity for testing
// ═══════════════════════════════════════════════════════════════════════════

struct MockTaskEntity {
    rows: Mutex<HashMap<String, HashMap<String, SyncValue>>>,
    deleted: Mutex<HashMap<String, bool>>,
}

impl MockTaskEntity {
    fn new() -> Self {
        Self {
            rows: Mutex::new(HashMap::new()),
            deleted: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait::async_trait]
impl SyncableEntity for MockTaskEntity {
    fn table_name(&self) -> &str {
        "tasks"
    }

    fn field_definitions(&self) -> &[SyncFieldDef] {
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

const SYNC_ID: &str = "test-sync-group";

fn test_schema() -> SyncSchema {
    SyncSchema::builder()
        .entity("tasks", |e| {
            e.field("title", SyncType::String)
                .field("done", SyncType::Bool)
        })
        .build()
}

fn make_signing_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

fn init_key_hierarchy() -> prism_sync_crypto::KeyHierarchy {
    let mut kh = prism_sync_crypto::KeyHierarchy::new();
    kh.initialize("test-password", &[1u8; 16]).unwrap();
    kh
}

/// Create a key hierarchy that shares the same epoch 0 key as the given one.
fn shared_key_hierarchy(
    source: &prism_sync_crypto::KeyHierarchy,
) -> prism_sync_crypto::KeyHierarchy {
    let mut kh = prism_sync_crypto::KeyHierarchy::new();
    kh.initialize("other-password", &[2u8; 16]).unwrap();
    let epoch0 = source.epoch_key(0).unwrap();
    kh.store_epoch_key(0, zeroize::Zeroizing::new(epoch0.to_vec()));
    kh
}

fn setup_sync_metadata(storage: &RusqliteSyncStorage, device_id: &str) {
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

fn register_device(
    relay: &MockRelay,
    storage: &RusqliteSyncStorage,
    device_id: &str,
    verifying_key: &ed25519_dalek::VerifyingKey,
) {
    use prism_sync_core::storage::SyncStorage;

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
    tx.upsert_device_record(&prism_sync_core::storage::DeviceRecord {
        sync_id: SYNC_ID.to_string(),
        device_id: device_id.to_string(),
        ed25519_public_key: pk_bytes,
        x25519_public_key: vec![0u8; 32],
        status: "active".to_string(),
        registered_at: chrono::Utc::now(),
        revoked_at: None,
    })
    .unwrap();
    tx.commit().unwrap();
}

fn insert_pending_ops(storage: &RusqliteSyncStorage, ops: &[CrdtChange], batch_id: &str) {
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

/// Create ops for a single task with title and done fields.
fn make_task_ops(
    device_id: &str,
    task_id: &str,
    title: &str,
    done: bool,
    batch_id: &str,
) -> Vec<CrdtChange> {
    let hlc = Hlc::now(device_id, None);
    vec![
        CrdtChange {
            op_id: format!("tasks:{task_id}:title:{hlc}:{device_id}"),
            batch_id: Some(batch_id.to_string()),
            entity_id: task_id.to_string(),
            entity_table: "tasks".to_string(),
            field_name: "title".to_string(),
            encoded_value: format!("\"{title}\""),
            client_hlc: hlc.to_string(),
            is_delete: false,
            device_id: device_id.to_string(),
            epoch: 0,
            server_seq: None,
        },
        CrdtChange {
            op_id: format!("tasks:{task_id}:done:{hlc}:{device_id}"),
            batch_id: Some(batch_id.to_string()),
            entity_id: task_id.to_string(),
            entity_table: "tasks".to_string(),
            field_name: "done".to_string(),
            encoded_value: done.to_string(),
            client_hlc: hlc.to_string(),
            is_delete: false,
            device_id: device_id.to_string(),
            epoch: 0,
            server_seq: None,
        },
    ]
}

/// Set up a device pair where:
///  - Device A pushes the given task ops to the relay.
///  - Device B pulls and merges them (populating field_versions).
///  - Device B uploads a snapshot.
///
/// Returns (relay, key_hierarchy, device_b_signing_key, device_b_storage).
/// The relay now has a snapshot and the pushed batches.
async fn push_and_create_snapshot(
    task_ops: Vec<(&str, &str, bool, &str)>, // (task_id, title, done, batch_id)
) -> (
    Arc<MockRelay>,
    prism_sync_crypto::KeyHierarchy,
    SigningKey,
    SigningKey,
    Arc<RusqliteSyncStorage>,
) {
    let key_hierarchy = init_key_hierarchy();
    let signing_key_a = make_signing_key();
    let signing_key_b = make_signing_key();
    let device_a_id = "device-aaa";
    let device_b_id = "device-bbb";

    let relay = Arc::new(MockRelay::new());

    // --- Device A setup ---
    let storage_a = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_a: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage_a, device_a_id);
    register_device(
        &relay,
        &storage_a,
        device_a_id,
        &signing_key_a.verifying_key(),
    );

    // Insert all task ops for device A
    for (task_id, title, done, batch_id) in &task_ops {
        let ops = make_task_ops(device_a_id, task_id, title, *done, batch_id);
        insert_pending_ops(&storage_a, &ops, batch_id);
    }

    let engine_a = SyncEngine::new(
        storage_a.clone(),
        relay.clone(),
        vec![entity_a],
        test_schema(),
        SyncConfig::default(),
    );

    // Push all from device A
    let result = engine_a
        .sync(SYNC_ID, &key_hierarchy, &signing_key_a, device_a_id)
        .await
        .unwrap();
    assert!(
        result.error.is_none(),
        "Device A push failed: {:?}",
        result.error
    );

    // --- Device B setup: pull and merge to populate field_versions ---
    let storage_b = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_b: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage_b, device_b_id);
    register_device(
        &relay,
        &storage_b,
        device_a_id,
        &signing_key_a.verifying_key(),
    );
    register_device(
        &relay,
        &storage_b,
        device_b_id,
        &signing_key_b.verifying_key(),
    );

    let engine_b = SyncEngine::new(
        storage_b.clone(),
        relay.clone(),
        vec![entity_b],
        test_schema(),
        SyncConfig::default(),
    );

    // Pull and merge (populates field_versions on device B)
    let result_b = engine_b
        .sync(SYNC_ID, &key_hierarchy, &signing_key_b, device_b_id)
        .await
        .unwrap();
    assert!(
        result_b.error.is_none(),
        "Device B pull failed: {:?}",
        result_b.error
    );
    assert!(result_b.merged > 0, "Device B should have merged ops");

    // Device B uploads the snapshot
    engine_b
        .upload_pairing_snapshot(SYNC_ID, &key_hierarchy, 0, device_b_id, Some(300), None)
        .await
        .unwrap();

    (
        relay,
        key_hierarchy,
        signing_key_a,
        signing_key_b,
        storage_b,
    )
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 4: Snapshot bootstrap then incremental
// ═══════════════════════════════════════════════════════════════════════════

/// Device A pushes task-1, Device B merges and uploads snapshot at seq N.
/// Device A then pushes task-2 (N+1). Device C bootstraps from snapshot
/// (state at N), syncs incrementally (gets N+1), verify complete state.
#[tokio::test]
async fn test_snapshot_bootstrap_then_incremental() {
    let key_hierarchy = init_key_hierarchy();
    let signing_key_a = make_signing_key();
    let device_a_id = "device-aaa";

    let relay = Arc::new(MockRelay::new());

    // --- Device A: create task-1 and push ---
    let storage_a = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_a: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage_a, device_a_id);
    register_device(
        &relay,
        &storage_a,
        device_a_id,
        &signing_key_a.verifying_key(),
    );

    let ops_1 = make_task_ops(device_a_id, "task-1", "Buy groceries", false, "batch-1");
    insert_pending_ops(&storage_a, &ops_1, "batch-1");

    let engine_a = SyncEngine::new(
        storage_a.clone(),
        relay.clone(),
        vec![entity_a.clone()],
        test_schema(),
        SyncConfig::default(),
    );

    let result = engine_a
        .sync(SYNC_ID, &key_hierarchy, &signing_key_a, device_a_id)
        .await
        .unwrap();
    assert!(result.error.is_none(), "push failed: {:?}", result.error);
    assert_eq!(result.pushed, 1);

    // --- Device B: pull/merge to populate field_versions, then upload snapshot ---
    let signing_key_b = make_signing_key();
    let device_b_id = "device-bbb";
    let storage_b = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_b: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage_b, device_b_id);
    register_device(
        &relay,
        &storage_b,
        device_a_id,
        &signing_key_a.verifying_key(),
    );
    register_device(
        &relay,
        &storage_b,
        device_b_id,
        &signing_key_b.verifying_key(),
    );

    let engine_b = SyncEngine::new(
        storage_b.clone(),
        relay.clone(),
        vec![entity_b],
        test_schema(),
        SyncConfig::default(),
    );

    let result_b = engine_b
        .sync(SYNC_ID, &key_hierarchy, &signing_key_b, device_b_id)
        .await
        .unwrap();
    assert!(result_b.error.is_none());
    assert_eq!(result_b.merged, 2, "should merge title + done ops");

    // Device B uploads snapshot (has field_versions from merge)
    engine_b
        .upload_pairing_snapshot(SYNC_ID, &key_hierarchy, 0, device_b_id, Some(300), None)
        .await
        .unwrap();

    // --- Device A: push task-2 AFTER snapshot was taken ---
    // Need a small delay so HLC is different
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let ops_2 = make_task_ops(device_a_id, "task-2", "Walk the dog", true, "batch-2");
    insert_pending_ops(&storage_a, &ops_2, "batch-2");

    let result_a2 = engine_a
        .sync(SYNC_ID, &key_hierarchy, &signing_key_a, device_a_id)
        .await
        .unwrap();
    assert!(result_a2.error.is_none());
    assert_eq!(result_a2.pushed, 1);

    // --- Device C: bootstrap from snapshot, then incremental ---
    let key_hierarchy_c = shared_key_hierarchy(&key_hierarchy);
    let signing_key_c = make_signing_key();
    let device_c_id = "device-ccc";

    let storage_c = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_c: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage_c, device_c_id);
    register_device(
        &relay,
        &storage_c,
        device_a_id,
        &signing_key_a.verifying_key(),
    );
    register_device(
        &relay,
        &storage_c,
        device_b_id,
        &signing_key_b.verifying_key(),
    );
    register_device(
        &relay,
        &storage_c,
        device_c_id,
        &signing_key_c.verifying_key(),
    );

    let engine_c = SyncEngine::new(
        storage_c.clone(),
        relay.clone(),
        vec![entity_c],
        test_schema(),
        SyncConfig::default(),
    );

    // Bootstrap from snapshot — restores task-1 field_versions
    let (count, entity_changes) = engine_c
        .bootstrap_from_snapshot(SYNC_ID, &key_hierarchy_c)
        .await
        .unwrap();

    assert!(count > 0, "snapshot should contain at least 1 entity");
    assert!(
        !entity_changes.is_empty(),
        "entity_changes should be non-empty"
    );

    // Verify task-1 is in the bootstrap entity_changes
    let task_1_change = entity_changes.iter().find(|c| c.entity_id == "task-1");
    assert!(
        task_1_change.is_some(),
        "task-1 should be in snapshot entity_changes"
    );
    let task_1 = task_1_change.unwrap();
    assert_eq!(task_1.table, "tasks");
    assert_eq!(
        task_1.fields.get("title"),
        Some(&"\"Buy groceries\"".to_string())
    );

    // Incremental sync to get task-2 (pushed after snapshot)
    let result_c = engine_c
        .sync(SYNC_ID, &key_hierarchy_c, &signing_key_c, device_c_id)
        .await
        .unwrap();
    assert!(
        result_c.error.is_none(),
        "incremental sync failed: {:?}",
        result_c.error
    );
    assert!(result_c.pulled > 0, "should pull post-snapshot batches");
    assert!(result_c.merged > 0, "should merge post-snapshot ops");

    // Verify task-2 arrived via incremental sync
    let task_2_change = result_c
        .entity_changes
        .iter()
        .find(|c| c.entity_id == "task-2");
    assert!(
        task_2_change.is_some(),
        "task-2 should be in incremental changes"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 5: Bootstrap without snapshot falls back
// ═══════════════════════════════════════════════════════════════════════════

/// Device B calls bootstrap with no snapshot on relay, returns Ok(0),
/// then syncs incrementally to get all data.
#[tokio::test]
async fn test_bootstrap_without_snapshot_falls_back() {
    let key_hierarchy = init_key_hierarchy();
    let signing_key_a = make_signing_key();
    let device_a_id = "device-aaa";

    let relay = Arc::new(MockRelay::new());
    let storage_a = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_a: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage_a, device_a_id);
    register_device(
        &relay,
        &storage_a,
        device_a_id,
        &signing_key_a.verifying_key(),
    );

    // Device A pushes data (no snapshot uploaded)
    let ops = make_task_ops(device_a_id, "task-1", "Test task", false, "batch-1");
    insert_pending_ops(&storage_a, &ops, "batch-1");

    let engine_a = SyncEngine::new(
        storage_a.clone(),
        relay.clone(),
        vec![entity_a],
        test_schema(),
        SyncConfig::default(),
    );

    engine_a
        .sync(SYNC_ID, &key_hierarchy, &signing_key_a, device_a_id)
        .await
        .unwrap();

    // --- Device B: try bootstrap (no snapshot available) ---
    let key_hierarchy_b = shared_key_hierarchy(&key_hierarchy);
    let signing_key_b = make_signing_key();
    let device_b_id = "device-bbb";

    let storage_b = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_b: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage_b, device_b_id);
    register_device(
        &relay,
        &storage_b,
        device_a_id,
        &signing_key_a.verifying_key(),
    );
    register_device(
        &relay,
        &storage_b,
        device_b_id,
        &signing_key_b.verifying_key(),
    );

    let engine_b = SyncEngine::new(
        storage_b.clone(),
        relay.clone(),
        vec![entity_b],
        test_schema(),
        SyncConfig::default(),
    );

    // Bootstrap returns (0, []) when no snapshot exists
    let (count, entity_changes) = engine_b
        .bootstrap_from_snapshot(SYNC_ID, &key_hierarchy_b)
        .await
        .unwrap();

    assert_eq!(
        count, 0,
        "bootstrap with no snapshot should return 0 entities"
    );
    assert!(entity_changes.is_empty(), "entity_changes should be empty");

    // Incremental sync picks up all data
    let result = engine_b
        .sync(SYNC_ID, &key_hierarchy_b, &signing_key_b, device_b_id)
        .await
        .unwrap();
    assert!(
        result.error.is_none(),
        "incremental sync failed: {:?}",
        result.error
    );
    assert_eq!(result.pulled, 1, "should pull 1 batch incrementally");
    assert_eq!(result.merged, 2, "should merge 2 ops (title + done)");

    let task = result
        .entity_changes
        .iter()
        .find(|c| c.entity_id == "task-1");
    assert!(task.is_some(), "task-1 should be in entity_changes");
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 6: Bootstrap wrong epoch key
// ═══════════════════════════════════════════════════════════════════════════

/// Upload snapshot with epoch 0 key, try bootstrap with different key —
/// decrypt should fail.
#[tokio::test]
async fn test_bootstrap_wrong_epoch_key() {
    // Use the helper to create a snapshot with real data
    let (relay, _key_hierarchy, _sk_a, _sk_b, _storage_b) =
        push_and_create_snapshot(vec![("task-1", "Secret task", false, "batch-1")]).await;

    // --- Device C: try bootstrap with a COMPLETELY DIFFERENT key hierarchy ---
    let mut wrong_kh = prism_sync_crypto::KeyHierarchy::new();
    wrong_kh
        .initialize("completely-wrong-password", &[99u8; 16])
        .unwrap();
    // Do NOT copy epoch 0 key — the default epoch key will be different

    let storage_c = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_c: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());
    setup_sync_metadata(&storage_c, "device-ccc");

    let engine_c = SyncEngine::new(
        storage_c.clone(),
        relay.clone(),
        vec![entity_c],
        test_schema(),
        SyncConfig::default(),
    );

    // Bootstrap should fail because the epoch key doesn't match
    let result = engine_c.bootstrap_from_snapshot(SYNC_ID, &wrong_kh).await;

    assert!(
        result.is_err(),
        "bootstrap with wrong epoch key should fail"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("decrypt")
            || err_msg.contains("Decrypt")
            || err_msg.contains("crypto")
            || err_msg.contains("snapshot"),
        "error should mention decryption failure, got: {err_msg}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 11: Pairing works without snapshot
// ═══════════════════════════════════════════════════════════════════════════

/// Full pairing flow where snapshot is not available — verify the new device
/// can still sync via incremental pull.
#[tokio::test]
async fn test_pairing_works_without_snapshot() {
    let key_hierarchy = init_key_hierarchy();
    let signing_key_a = make_signing_key();
    let signing_key_b = make_signing_key();
    let device_a_id = "device-aaa";
    let device_b_id = "device-bbb";

    let relay = Arc::new(MockRelay::new());

    // --- Device A: push data (no snapshot) ---
    let storage_a = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_a: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage_a, device_a_id);
    register_device(
        &relay,
        &storage_a,
        device_a_id,
        &signing_key_a.verifying_key(),
    );

    let ops_1 = make_task_ops(device_a_id, "task-1", "First task", false, "batch-1");
    let ops_2 = make_task_ops(device_a_id, "task-2", "Second task", true, "batch-2");
    insert_pending_ops(&storage_a, &ops_1, "batch-1");
    insert_pending_ops(&storage_a, &ops_2, "batch-2");

    let engine_a = SyncEngine::new(
        storage_a.clone(),
        relay.clone(),
        vec![entity_a],
        test_schema(),
        SyncConfig::default(),
    );

    let result_a = engine_a
        .sync(SYNC_ID, &key_hierarchy, &signing_key_a, device_a_id)
        .await
        .unwrap();
    assert!(result_a.error.is_none());
    assert_eq!(result_a.pushed, 2);

    // Device A does NOT upload a snapshot (simulating snapshot upload failure)

    // --- Device B: join without snapshot ---
    let key_hierarchy_b = shared_key_hierarchy(&key_hierarchy);
    let storage_b = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_b: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage_b, device_b_id);
    register_device(
        &relay,
        &storage_b,
        device_a_id,
        &signing_key_a.verifying_key(),
    );
    register_device(
        &relay,
        &storage_b,
        device_b_id,
        &signing_key_b.verifying_key(),
    );

    let engine_b = SyncEngine::new(
        storage_b.clone(),
        relay.clone(),
        vec![entity_b],
        test_schema(),
        SyncConfig::default(),
    );

    // Bootstrap returns nothing
    let (count, _) = engine_b
        .bootstrap_from_snapshot(SYNC_ID, &key_hierarchy_b)
        .await
        .unwrap();
    assert_eq!(count, 0);

    // Incremental sync picks up all data
    let result_b = engine_b
        .sync(SYNC_ID, &key_hierarchy_b, &signing_key_b, device_b_id)
        .await
        .unwrap();
    assert!(
        result_b.error.is_none(),
        "sync failed: {:?}",
        result_b.error
    );
    assert_eq!(result_b.pulled, 2, "should pull both batches");
    assert_eq!(
        result_b.merged, 4,
        "should merge 4 ops (2 tasks x 2 fields)"
    );

    let has_task_1 = result_b
        .entity_changes
        .iter()
        .any(|c| c.entity_id == "task-1");
    let has_task_2 = result_b
        .entity_changes
        .iter()
        .any(|c| c.entity_id == "task-2");
    assert!(has_task_1, "task-1 should be in entity_changes");
    assert!(has_task_2, "task-2 should be in entity_changes");
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 12: Bootstrap emits remote changes
// ═══════════════════════════════════════════════════════════════════════════

/// Bootstrap from snapshot, verify entity_changes are returned with correct
/// entities and field values.
#[tokio::test]
async fn test_bootstrap_emits_remote_changes() {
    // Create a snapshot containing 3 tasks
    let (relay, key_hierarchy, _sk_a, _sk_b, _storage_b) = push_and_create_snapshot(vec![
        ("task-1", "Alpha", false, "batch-1"),
        ("task-2", "Beta", true, "batch-2"),
        ("task-3", "Gamma", false, "batch-3"),
    ])
    .await;

    // --- Device C: bootstrap ---
    let key_hierarchy_c = shared_key_hierarchy(&key_hierarchy);
    let storage_c = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_c: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());
    setup_sync_metadata(&storage_c, "device-ccc");

    let engine_c = SyncEngine::new(
        storage_c.clone(),
        relay.clone(),
        vec![entity_c],
        test_schema(),
        SyncConfig::default(),
    );

    let (count, entity_changes) = engine_c
        .bootstrap_from_snapshot(SYNC_ID, &key_hierarchy_c)
        .await
        .unwrap();

    assert_eq!(count, 3, "snapshot should contain 3 entities");
    assert_eq!(
        entity_changes.len(),
        3,
        "should emit 3 EntityChange entries"
    );

    // Verify each entity has the correct fields
    for change in &entity_changes {
        assert_eq!(change.table, "tasks");
        assert!(!change.is_delete);
        assert!(
            change.fields.contains_key("title"),
            "should have title field"
        );
        assert!(change.fields.contains_key("done"), "should have done field");
    }

    // Verify specific values
    let alpha = entity_changes
        .iter()
        .find(|c| c.entity_id == "task-1")
        .unwrap();
    assert_eq!(alpha.fields.get("title"), Some(&"\"Alpha\"".to_string()));

    let beta = entity_changes
        .iter()
        .find(|c| c.entity_id == "task-2")
        .unwrap();
    assert_eq!(beta.fields.get("title"), Some(&"\"Beta\"".to_string()));

    let gamma = entity_changes
        .iter()
        .find(|c| c.entity_id == "task-3")
        .unwrap();
    assert_eq!(gamma.fields.get("title"), Some(&"\"Gamma\"".to_string()));
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 13: Push limit without snapshot
// ═══════════════════════════════════════════════════════════════════════════

/// No snapshot, push many batches, verify push still works and no blocking.
#[tokio::test]
async fn test_push_limit_without_snapshot() {
    let key_hierarchy = init_key_hierarchy();
    let signing_key = make_signing_key();
    let device_id = "device-aaa";

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage, device_id);
    register_device(&relay, &storage, device_id, &signing_key.verifying_key());

    // Push 10 batches
    for i in 0..10 {
        let ops = make_task_ops(
            device_id,
            &format!("task-{i}"),
            &format!("Task number {i}"),
            false,
            &format!("batch-{i}"),
        );
        insert_pending_ops(&storage, &ops, &format!("batch-{i}"));
    }

    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity],
        test_schema(),
        SyncConfig::default(),
    );

    let result = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key, device_id)
        .await
        .unwrap();
    assert!(result.error.is_none(), "push failed: {:?}", result.error);
    assert_eq!(result.pushed, 10);
    assert_eq!(relay.batch_count(), 10);

    // Push more after initial batches — verify no blocking
    let more_ops = make_task_ops(device_id, "task-extra", "Extra task", true, "batch-extra");
    insert_pending_ops(&storage, &more_ops, "batch-extra");

    let result2 = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key, device_id)
        .await
        .unwrap();
    assert!(result2.error.is_none());
    assert_eq!(result2.pushed, 1);
    assert_eq!(relay.batch_count(), 11);
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 14: Snapshot roundtrip preserves data
// ═══════════════════════════════════════════════════════════════════════════

/// Create data, export snapshot via engine, import on fresh storage,
/// verify all field_versions match.
#[tokio::test]
async fn test_snapshot_roundtrip_preserves_data() {
    // Use the helper to create a populated snapshot
    let (relay, key_hierarchy, _sk_a, _sk_b, storage_b) = push_and_create_snapshot(vec![
        ("task-1", "First", false, "batch-1"),
        ("task-2", "Second", true, "batch-2"),
    ])
    .await;

    // --- Device C: bootstrap from the snapshot ---
    let key_hierarchy_c = shared_key_hierarchy(&key_hierarchy);
    let storage_c = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_c: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());
    setup_sync_metadata(&storage_c, "device-ccc");

    let engine_c = SyncEngine::new(
        storage_c.clone(),
        relay.clone(),
        vec![entity_c],
        test_schema(),
        SyncConfig::default(),
    );

    let (count, entity_changes) = engine_c
        .bootstrap_from_snapshot(SYNC_ID, &key_hierarchy_c)
        .await
        .unwrap();

    assert_eq!(count, 2, "should restore 2 entities");

    // Verify field_versions in storage_c match those in storage_b (the snapshot source)
    use prism_sync_core::storage::SyncStorage;
    // Check task-1 title
    let fv_b_1_title = storage_b
        .get_field_version(SYNC_ID, "tasks", "task-1", "title")
        .unwrap()
        .expect("source field_version for task-1 title should exist");
    let fv_c_1_title = storage_c
        .get_field_version(SYNC_ID, "tasks", "task-1", "title")
        .unwrap()
        .expect("imported field_version for task-1 title should exist");

    assert_eq!(fv_b_1_title.winning_op_id, fv_c_1_title.winning_op_id);
    assert_eq!(fv_b_1_title.winning_hlc, fv_c_1_title.winning_hlc);
    assert_eq!(
        fv_b_1_title.winning_encoded_value,
        fv_c_1_title.winning_encoded_value
    );
    assert_eq!(
        fv_b_1_title.winning_device_id,
        fv_c_1_title.winning_device_id
    );

    // Check task-2 done
    let fv_b_2_done = storage_b
        .get_field_version(SYNC_ID, "tasks", "task-2", "done")
        .unwrap()
        .expect("source field_version for task-2 done should exist");
    let fv_c_2_done = storage_c
        .get_field_version(SYNC_ID, "tasks", "task-2", "done")
        .unwrap()
        .expect("imported field_version for task-2 done should exist");

    assert_eq!(fv_b_2_done.winning_op_id, fv_c_2_done.winning_op_id);
    assert_eq!(
        fv_b_2_done.winning_encoded_value,
        fv_c_2_done.winning_encoded_value
    );

    // Bootstrap must preserve the joining device's local identity, not the
    // source device identity embedded in the snapshot.
    let imported_meta = storage_c
        .get_sync_metadata(SYNC_ID)
        .unwrap()
        .expect("imported sync metadata should exist");
    assert_eq!(imported_meta.local_device_id, "device-ccc");

    // Verify entity_changes have correct data
    let task_1 = entity_changes
        .iter()
        .find(|c| c.entity_id == "task-1")
        .unwrap();
    assert_eq!(task_1.fields.get("title"), Some(&"\"First\"".to_string()));

    let task_2 = entity_changes
        .iter()
        .find(|c| c.entity_id == "task-2")
        .unwrap();
    assert_eq!(task_2.fields.get("done"), Some(&"true".to_string()));
}

// ═══════════════════════════════════════════════════════════════════════════
// Regression: snapshot must not be device-targeted
// ═══════════════════════════════════════════════════════════════════════════

/// Regression test for: engine was passing uploader's device_id as for_device_id,
/// causing the relay to target the snapshot at the uploader. The joining device
/// (different device_id) would then receive 403 Forbidden when bootstrapping.
///
/// This test asserts two things:
///   1. The engine uploads the snapshot with for_device_id = None (no targeting).
///   2. A device with a completely different ID can still bootstrap from it.
///
/// If someone regresses this by passing Some(device_id) to put_snapshot again,
/// assertion 1 will fail immediately. Assertion 2 also guards against server-side
/// regressions where targeting enforcement would break bootstrap for new devices.
#[tokio::test]
async fn test_snapshot_not_targeted_at_uploader() {
    let (relay, key_hierarchy, _sk_a, _sk_b, _storage_b) =
        push_and_create_snapshot(vec![("task-1", "Buy groceries", false, "batch-1")]).await;

    // 1. The snapshot must have been uploaded with no device targeting.
    //    If this fails, the engine is passing the uploader's device_id as
    //    for_device_id — which would block any joining device from downloading.
    assert_eq!(
        relay.snapshot_target_device_id(),
        None,
        "snapshot must not be targeted at a specific device: the joining \
         device's ID is unknown at upload time, so for_device_id must be None"
    );

    // 2. A device that was not involved in uploading can still bootstrap.
    //    "device-zzz" is a completely fresh device with no prior relationship
    //    to the snapshot uploader.
    let key_hierarchy_z = shared_key_hierarchy(&key_hierarchy);
    let signing_key_z = make_signing_key();
    let device_z_id = "device-zzz";

    let storage_z = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_z: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());
    setup_sync_metadata(&storage_z, device_z_id);

    let engine_z = SyncEngine::new(
        storage_z.clone(),
        relay.clone(),
        vec![entity_z],
        test_schema(),
        SyncConfig::default(),
    );

    let (count, entity_changes) = engine_z
        .bootstrap_from_snapshot(SYNC_ID, &key_hierarchy_z)
        .await
        .expect("bootstrap must succeed for a device that was not the snapshot uploader");

    assert!(
        count > 0,
        "joining device should receive entities from snapshot"
    );
    assert!(
        entity_changes.iter().any(|c| c.entity_id == "task-1"),
        "joining device should see task-1 from snapshot"
    );

    // Also verify via get_snapshot_for_device that the relay would serve
    // the snapshot to any device when no targeting is set.
    let snap_for_z = relay.get_snapshot_for_device(device_z_id);
    assert!(
        snap_for_z.is_some(),
        "relay should serve untargeted snapshot to any device"
    );
    let _ = signing_key_z; // suppress unused warning
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Snapshot upload with device targeting
// ═══════════════════════════════════════════════════════════════════════════

/// Verify that `upload_pairing_snapshot` succeeds when called with a
/// `for_device_id` (targeted snapshot). The relay-side enforcement of
/// targeting is outside our scope — this test only checks that the
/// parameter flows through the engine without error.
#[tokio::test]
async fn test_snapshot_upload_with_device_targeting() {
    let key_hierarchy = init_key_hierarchy();
    let signing_key_a = make_signing_key();
    let signing_key_b = make_signing_key();
    let device_a_id = "device-aaa";
    let device_b_id = "device-bbb";

    let relay = Arc::new(MockRelay::new());

    // --- Device A: push data ---
    let storage_a = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_a: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage_a, device_a_id);
    register_device(
        &relay,
        &storage_a,
        device_a_id,
        &signing_key_a.verifying_key(),
    );

    let ops = make_task_ops(device_a_id, "task-1", "Targeted task", false, "batch-1");
    insert_pending_ops(&storage_a, &ops, "batch-1");

    let engine_a = SyncEngine::new(
        storage_a.clone(),
        relay.clone(),
        vec![entity_a],
        test_schema(),
        SyncConfig::default(),
    );

    let result = engine_a
        .sync(SYNC_ID, &key_hierarchy, &signing_key_a, device_a_id)
        .await
        .unwrap();
    assert!(result.error.is_none(), "push failed: {:?}", result.error);

    // --- Device B: pull/merge to populate field_versions ---
    let storage_b = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_b: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage_b, device_b_id);
    register_device(
        &relay,
        &storage_b,
        device_a_id,
        &signing_key_a.verifying_key(),
    );
    register_device(
        &relay,
        &storage_b,
        device_b_id,
        &signing_key_b.verifying_key(),
    );

    let engine_b = SyncEngine::new(
        storage_b.clone(),
        relay.clone(),
        vec![entity_b],
        test_schema(),
        SyncConfig::default(),
    );

    let result_b = engine_b
        .sync(SYNC_ID, &key_hierarchy, &signing_key_b, device_b_id)
        .await
        .unwrap();
    assert!(result_b.error.is_none());
    assert!(result_b.merged > 0, "Device B should have merged ops");

    // Upload snapshot with a specific target device
    engine_b
        .upload_pairing_snapshot(
            SYNC_ID,
            &key_hierarchy,
            0,
            device_b_id,
            Some(300),
            Some("target-device-123".to_string()),
        )
        .await
        .unwrap();

    // Verify the relay recorded the target device ID
    assert_eq!(
        relay.snapshot_target_device_id(),
        Some("target-device-123".to_string()),
        "snapshot should be targeted at the specified device"
    );
}
