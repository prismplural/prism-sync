//! Integration tests for `PrismSync::bootstrap_existing_state` — the
//! first-device bootstrap path described in
//! `docs/plans/first-device-bootstrap-snapshot.md` (Phase A.1).

mod common;

use std::collections::HashMap;
use std::sync::Arc;

use common::{MemorySecureStore, MockTaskEntity, SYNC_ID};

use prism_sync_core::engine::SeedRecord;
use prism_sync_core::hlc::Hlc;
use prism_sync_core::relay::MockRelay;
use prism_sync_core::schema::{SyncSchema, SyncType, SyncValue};
use prism_sync_core::storage::{
    DeviceRecord, RusqliteSyncStorage, SyncMetadata, SyncStorage,
};
use prism_sync_core::syncable_entity::SyncableEntity;
use prism_sync_core::{CoreError, PrismSync};

fn bootstrap_schema() -> SyncSchema {
    SyncSchema::builder()
        .entity("tasks", |e| e.field("title", SyncType::String).field("done", SyncType::Bool))
        .build()
}

/// Build a `PrismSync` handle that has been "registered" as the sole device
/// (one row in `device_registry`, no applied_ops, `last_pulled_server_seq = 0`).
fn setup_sole_device(
    extra_devices: usize,
    last_pulled: i64,
    insert_applied_op: bool,
    insert_pending_ops: usize,
) -> (PrismSync, Arc<RusqliteSyncStorage>) {
    let schema = bootstrap_schema();
    let storage: Arc<RusqliteSyncStorage> = Arc::new(RusqliteSyncStorage::in_memory().unwrap());

    {
        let mut tx = storage.begin_tx().unwrap();
        tx.upsert_sync_metadata(&SyncMetadata {
            sync_id: SYNC_ID.to_string(),
            local_device_id: "device-a".to_string(),
            current_epoch: 0,
            last_pulled_server_seq: last_pulled,
            last_pushed_at: None,
            last_successful_sync_at: None,
            registered_at: Some(chrono::Utc::now()),
            needs_rekey: false,
            last_imported_registry_version: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        })
        .unwrap();

        // Sole device by default
        tx.upsert_device_record(&DeviceRecord {
            sync_id: SYNC_ID.to_string(),
            device_id: "device-a".to_string(),
            ed25519_public_key: vec![1u8; 32],
            x25519_public_key: vec![2u8; 32],
            ml_dsa_65_public_key: vec![],
            ml_kem_768_public_key: vec![],
            x_wing_public_key: vec![],
            status: "active".to_string(),
            registered_at: chrono::Utc::now(),
            revoked_at: None,
            ml_dsa_key_generation: 0,
        })
        .unwrap();

        for i in 0..extra_devices {
            tx.upsert_device_record(&DeviceRecord {
                sync_id: SYNC_ID.to_string(),
                device_id: format!("device-extra-{i}"),
                ed25519_public_key: vec![3u8; 32],
                x25519_public_key: vec![4u8; 32],
                ml_dsa_65_public_key: vec![],
                ml_kem_768_public_key: vec![],
                x_wing_public_key: vec![],
                status: "active".to_string(),
                registered_at: chrono::Utc::now(),
                revoked_at: None,
                ml_dsa_key_generation: 0,
            })
            .unwrap();
        }

        if insert_applied_op {
            tx.insert_applied_op(&prism_sync_core::storage::AppliedOp {
                op_id: "op-applied-1".to_string(),
                sync_id: SYNC_ID.to_string(),
                epoch: 0,
                device_id: "remote-device".to_string(),
                client_hlc: "100:0:remotedev0001".to_string(),
                server_seq: 1,
                applied_at: chrono::Utc::now(),
            })
            .unwrap();
        }

        for i in 0..insert_pending_ops {
            tx.insert_pending_op(&prism_sync_core::storage::PendingOp {
                op_id: format!("orphan-{i}"),
                sync_id: SYNC_ID.to_string(),
                epoch: 0,
                device_id: "device-a".to_string(),
                local_batch_id: format!("orphan-batch-{i}"),
                entity_table: "tasks".to_string(),
                entity_id: format!("orphan-task-{i}"),
                field_name: "title".to_string(),
                encoded_value: format!("\"orphan {i}\""),
                is_delete: false,
                client_hlc: format!("1:{i}:devicea000000"),
                created_at: chrono::Utc::now(),
                pushed_at: None,
            })
            .unwrap();
        }

        tx.commit().unwrap();
    }

    let entity: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    let mut sync = PrismSync::builder()
        .schema(schema)
        .storage(storage.clone())
        .secure_store(Arc::new(MemorySecureStore::new()))
        .entity(entity)
        .build()
        .unwrap();

    sync.initialize("pw", &[7u8; 16]).unwrap();

    let relay = Arc::new(MockRelay::new());
    sync.configure_engine(
        relay,
        SYNC_ID.to_string(),
        "device-a".to_string(),
        0,
        0,
    );

    (sync, storage)
}

fn task_record(id: &str, title: &str, done: bool) -> SeedRecord {
    let mut fields: HashMap<String, SyncValue> = HashMap::new();
    fields.insert("title".to_string(), SyncValue::String(title.to_string()));
    fields.insert("done".to_string(), SyncValue::Bool(done));
    SeedRecord { table: "tasks".to_string(), entity_id: id.to_string(), fields }
}

#[tokio::test]
async fn bootstrap_seeds_field_versions_without_pending_ops() {
    let (mut sync, storage) = setup_sole_device(0, 0, false, 0);

    let records =
        vec![task_record("t-1", "first", false), task_record("t-2", "second", true)];
    let report = sync.bootstrap_existing_state(records).await.unwrap();
    assert_eq!(report.entity_count, 2);
    assert!(report.snapshot_bytes > 0);

    // field_versions populated
    for (id, field, _) in [
        ("t-1", "title", "first"),
        ("t-1", "done", "false"),
        ("t-2", "title", "second"),
        ("t-2", "done", "true"),
    ] {
        let fv = storage.get_field_version(SYNC_ID, "tasks", id, field).unwrap();
        assert!(fv.is_some(), "missing field_version for {id}.{field}");
    }

    // No pending_ops and no applied_ops
    let batch_ids = storage.get_unpushed_batch_ids(SYNC_ID).unwrap();
    assert!(batch_ids.is_empty(), "seed must not produce pending_ops: {batch_ids:?}");
    assert!(!storage.has_any_applied_ops(SYNC_ID).unwrap());
}

#[tokio::test]
async fn bootstrap_rejects_when_peer_device_exists() {
    let (mut sync, _storage) = setup_sole_device(1, 0, false, 0);
    let err = sync
        .bootstrap_existing_state(vec![task_record("t-1", "x", false)])
        .await
        .unwrap_err();
    assert!(
        matches!(err, CoreError::BootstrapNotAllowed(ref msg) if msg.contains("device")),
        "expected BootstrapNotAllowed mentioning device, got: {err:?}"
    );
}

#[tokio::test]
async fn bootstrap_rejects_when_last_pulled_nonzero() {
    let (mut sync, _storage) = setup_sole_device(0, 5, false, 0);
    let err = sync
        .bootstrap_existing_state(vec![task_record("t-1", "x", false)])
        .await
        .unwrap_err();
    assert!(
        matches!(err, CoreError::BootstrapNotAllowed(ref msg) if msg.contains("last_pulled_server_seq")),
        "expected BootstrapNotAllowed mentioning last_pulled_server_seq, got: {err:?}"
    );
}

#[tokio::test]
async fn bootstrap_rejects_when_applied_ops_exist() {
    let (mut sync, _storage) = setup_sole_device(0, 0, true, 0);
    let err = sync
        .bootstrap_existing_state(vec![task_record("t-1", "x", false)])
        .await
        .unwrap_err();
    assert!(
        matches!(err, CoreError::BootstrapNotAllowed(ref msg) if msg.contains("applied_ops")),
        "expected BootstrapNotAllowed mentioning applied_ops, got: {err:?}"
    );
}

#[tokio::test]
async fn bootstrap_clears_orphan_pending_ops() {
    let (mut sync, storage) = setup_sole_device(0, 0, false, 10);

    // sanity: 10 orphan batches exist
    assert_eq!(storage.get_unpushed_batch_ids(SYNC_ID).unwrap().len(), 10);

    sync.bootstrap_existing_state(vec![task_record("t-1", "x", false)]).await.unwrap();

    // orphan pending_ops gone; seed_fields did NOT create new ones
    assert!(
        storage.get_unpushed_batch_ids(SYNC_ID).unwrap().is_empty(),
        "bootstrap must clear orphan pending_ops"
    );
}

#[tokio::test]
async fn bootstrap_advances_hlc_watermark() {
    let (mut sync, storage) = setup_sole_device(0, 0, false, 0);

    // Seed with an intentionally large number of records so the emitter
    // ticks the HLC counter above 9 — the regression case for `:9` vs `:10`
    // lexicographic HLC string ordering.
    let mut records = Vec::new();
    for i in 0..12 {
        records.push(task_record(&format!("t-{i}"), &format!("title {i}"), false));
    }
    sync.bootstrap_existing_state(records).await.unwrap();

    // Find the max seeded HLC across all field_versions.
    let hlcs = storage.list_all_field_version_hlcs(SYNC_ID).unwrap();
    let max_seeded =
        Hlc::parse_many_and_max(&hlcs).unwrap().expect("seeded HLCs should exist");

    // Now record_create on a new entity post-bootstrap; the new op's HLC
    // must be strictly greater than every seeded HLC (including the :10
    // counter row that naive string-MAX would have missed).
    let mut new_fields: HashMap<String, SyncValue> = HashMap::new();
    new_fields.insert("title".to_string(), SyncValue::String("post-bootstrap".into()));
    sync.record_create("tasks", "post-boot-1", &new_fields).unwrap();

    let fv = storage
        .get_field_version(SYNC_ID, "tasks", "post-boot-1", "title")
        .unwrap()
        .expect("field_version should exist after record_create");
    let new_hlc = Hlc::from_string(&fv.winning_hlc).unwrap();
    assert!(
        new_hlc > max_seeded,
        "post-bootstrap HLC {new_hlc:?} must exceed max seeded HLC {max_seeded:?}"
    );
}

/// Round-trip: seed → export_snapshot → import into a fresh storage →
/// field_versions match.
#[tokio::test]
async fn bootstrap_round_trips_through_snapshot() {
    let (mut sync, storage) = setup_sole_device(0, 0, false, 0);

    let records = vec![
        task_record("t-1", "alpha", false),
        task_record("t-2", "beta", true),
        task_record("t-3", "gamma", false),
    ];
    sync.bootstrap_existing_state(records).await.unwrap();

    let blob = storage.export_snapshot(SYNC_ID).unwrap();

    // Fresh storage; import the blob.
    let fresh = RusqliteSyncStorage::in_memory().unwrap();
    let count = {
        let mut tx = fresh.begin_tx().unwrap();
        let count = tx.import_snapshot(SYNC_ID, &blob).unwrap();
        tx.commit().unwrap();
        count
    };
    assert_eq!(count, 3, "three entities should round-trip");

    // field_versions parity
    for (id, field, expected) in [
        ("t-1", "title", "\"alpha\""),
        ("t-1", "done", "false"),
        ("t-2", "title", "\"beta\""),
        ("t-2", "done", "true"),
        ("t-3", "title", "\"gamma\""),
        ("t-3", "done", "false"),
    ] {
        let fv = fresh
            .get_field_version(SYNC_ID, "tasks", id, field)
            .unwrap()
            .unwrap_or_else(|| panic!("missing fv after import: {id}.{field}"));
        assert_eq!(
            fv.winning_encoded_value.as_deref(),
            Some(expected),
            "value mismatch for {id}.{field}"
        );
    }
}

#[tokio::test]
async fn bootstrap_tombstone_roundtrip() {
    let (mut sync, storage) = setup_sole_device(0, 0, false, 0);

    let mut fields = HashMap::new();
    fields.insert("title".to_string(), SyncValue::String("doomed".into()));
    fields.insert("is_deleted".to_string(), SyncValue::Bool(true));
    let records = vec![SeedRecord {
        table: "tasks".to_string(),
        entity_id: "t-dead".to_string(),
        fields,
    }];
    sync.bootstrap_existing_state(records).await.unwrap();

    let blob = storage.export_snapshot(SYNC_ID).unwrap();
    let fresh = RusqliteSyncStorage::in_memory().unwrap();
    {
        let mut tx = fresh.begin_tx().unwrap();
        tx.import_snapshot(SYNC_ID, &blob).unwrap();
        tx.commit().unwrap();
    }

    let tomb = fresh
        .get_field_version(SYNC_ID, "tasks", "t-dead", "is_deleted")
        .unwrap()
        .expect("tombstone field_version should exist after import");
    assert_eq!(
        tomb.winning_encoded_value.as_deref(),
        Some("true"),
        "tombstone must survive the round-trip"
    );
}

#[tokio::test]
async fn bootstrap_returns_snapshot_too_large_for_oversized_blob() {
    // We can't realistically fabricate a >100 MB compressed blob from
    // `seed_fields` in CI time. Instead, drive the size-gate directly by
    // bypassing the seeding path: construct a large "payload" inserted into
    // field_versions via ordinary DB writes, then call
    // `bootstrap_existing_state` with no records to trigger only the size
    // probe. The export snapshot will reflect the large state.
    let (mut sync, storage) = setup_sole_device(0, 0, false, 0);

    // Pack ~130 MiB of cryptographically random bytes across multiple
    // field_versions so the compressed snapshot exceeds 100 MB. Random
    // input is the worst case for zstd — the compressed blob stays close
    // to the plaintext size.
    use rand::RngCore;
    {
        let mut tx = storage.begin_tx().unwrap();
        use base64::Engine as _;
        use prism_sync_core::storage::FieldVersion;
        for i in 0..260u32 {
            let mut blob = vec![0u8; 512 * 1024];
            rand::thread_rng().fill_bytes(&mut blob);
            let encoded = format!(
                "\"{}\"",
                base64::engine::general_purpose::STANDARD.encode(&blob)
            );
            tx.upsert_field_version(&FieldVersion {
                sync_id: SYNC_ID.to_string(),
                entity_table: "tasks".to_string(),
                entity_id: format!("t-{i}"),
                field_name: "title".to_string(),
                winning_op_id: format!("op-{i}"),
                winning_device_id: "device-a".to_string(),
                winning_hlc: format!("1:{i}:devicea000000"),
                winning_encoded_value: Some(encoded),
                updated_at: chrono::Utc::now(),
            })
            .unwrap();
        }
        tx.commit().unwrap();
    }

    let err = sync.bootstrap_existing_state(Vec::new()).await.unwrap_err();
    match err {
        CoreError::SnapshotTooLarge { bytes } => {
            assert!(
                bytes > 100 * 1024 * 1024,
                "expected bytes > 100 MiB, got {bytes}"
            );
        }
        other => panic!("expected SnapshotTooLarge, got: {other:?}"),
    }
}
