//! Storage error-path and edge-case tests for `RusqliteSyncStorage`.
//!
//! These tests exercise the real SQLite-backed storage with boundary inputs
//! to verify graceful handling of duplicates, missing data, rollbacks, etc.

mod common;

use chrono::Utc;
use prism_sync_core::storage::{
    AppliedOp, DeviceRecord, FieldVersion, PendingOp, RusqliteSyncStorage, SyncMetadata,
    SyncStorage,
};

// ── Helpers ──

fn make_storage() -> RusqliteSyncStorage {
    RusqliteSyncStorage::in_memory().expect("in-memory storage")
}

fn sample_metadata(sync_id: &str) -> SyncMetadata {
    SyncMetadata {
        sync_id: sync_id.to_string(),
        local_device_id: "dev-1".to_string(),
        current_epoch: 0,
        last_pulled_server_seq: 0,
        last_pushed_at: None,
        last_successful_sync_at: None,
        registered_at: Some(Utc::now()),
        needs_rekey: false,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn sample_pending_op(op_id: &str, batch_id: &str) -> PendingOp {
    PendingOp {
        op_id: op_id.to_string(),
        sync_id: "sync-1".to_string(),
        epoch: 0,
        device_id: "dev-1".to_string(),
        local_batch_id: batch_id.to_string(),
        entity_table: "tasks".to_string(),
        entity_id: "entity-1".to_string(),
        field_name: "title".to_string(),
        encoded_value: "\"hello\"".to_string(),
        is_delete: false,
        client_hlc: "2026-01-01T00:00:00Z-0000-dev1".to_string(),
        created_at: Utc::now(),
        pushed_at: None,
    }
}

fn sample_applied_op(op_id: &str, server_seq: i64) -> AppliedOp {
    AppliedOp {
        op_id: op_id.to_string(),
        sync_id: "sync-1".to_string(),
        epoch: 0,
        device_id: "dev-1".to_string(),
        client_hlc: "2026-01-01T00:00:00Z-0000-dev1".to_string(),
        server_seq,
        applied_at: Utc::now(),
    }
}

fn sample_field_version(entity_id: &str, field: &str, hlc: &str) -> FieldVersion {
    FieldVersion {
        sync_id: "sync-1".to_string(),
        entity_table: "tasks".to_string(),
        entity_id: entity_id.to_string(),
        field_name: field.to_string(),
        winning_op_id: format!("op-{entity_id}-{field}"),
        winning_device_id: "dev-1".to_string(),
        winning_hlc: hlc.to_string(),
        winning_encoded_value: Some("\"value\"".to_string()),
        updated_at: Utc::now(),
    }
}

fn sample_device_record(device_id: &str) -> DeviceRecord {
    DeviceRecord {
        sync_id: "sync-1".to_string(),
        device_id: device_id.to_string(),
        ed25519_public_key: vec![0u8; 32],
        x25519_public_key: vec![0u8; 32],
        ml_dsa_65_public_key: vec![0u8; 1952],
        ml_kem_768_public_key: vec![0u8; 1184],
        status: "active".to_string(),
        registered_at: Utc::now(),
        revoked_at: None,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Transaction safety
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn transaction_rollback_prevents_partial_state() {
    let storage = make_storage();

    // Begin a transaction, insert metadata, then rollback
    let mut tx = storage.begin_tx().unwrap();
    tx.upsert_sync_metadata(&sample_metadata("sync-rollback"))
        .unwrap();
    tx.rollback().unwrap();

    // The metadata should not exist
    let meta = storage.get_sync_metadata("sync-rollback").unwrap();
    assert!(meta.is_none(), "rolled-back metadata should not be visible");
}

#[test]
fn transaction_drop_without_commit_acts_as_rollback() {
    let storage = make_storage();

    {
        let mut tx = storage.begin_tx().unwrap();
        tx.upsert_sync_metadata(&sample_metadata("sync-drop"))
            .unwrap();
        // tx is dropped without commit or rollback
    }

    let meta = storage.get_sync_metadata("sync-drop").unwrap();
    assert!(meta.is_none(), "dropped tx should auto-rollback");
}

#[test]
fn transaction_rollback_undoes_multiple_writes() {
    let storage = make_storage();

    // First commit some baseline data
    let mut tx = storage.begin_tx().unwrap();
    tx.upsert_sync_metadata(&sample_metadata("sync-1")).unwrap();
    tx.commit().unwrap();

    // Now start a new tx, do several writes, then rollback
    let mut tx = storage.begin_tx().unwrap();
    tx.insert_pending_op(&sample_pending_op("op-1", "batch-1"))
        .unwrap();
    tx.insert_applied_op(&sample_applied_op("applied-1", 1))
        .unwrap();
    tx.upsert_field_version(&sample_field_version("e1", "title", "hlc-1"))
        .unwrap();
    tx.upsert_device_record(&sample_device_record("dev-new"))
        .unwrap();
    tx.rollback().unwrap();

    // None of those writes should be visible
    assert!(!storage.is_op_applied("applied-1").unwrap());
    assert!(storage
        .get_field_version("sync-1", "tasks", "e1", "title")
        .unwrap()
        .is_none());
    assert!(storage
        .get_device_record("sync-1", "dev-new")
        .unwrap()
        .is_none());
    assert!(storage.get_unpushed_batch_ids("sync-1").unwrap().is_empty());
}

#[test]
fn committed_transaction_persists_data() {
    let storage = make_storage();

    let mut tx = storage.begin_tx().unwrap();
    tx.upsert_sync_metadata(&sample_metadata("sync-1")).unwrap();
    tx.insert_pending_op(&sample_pending_op("op-1", "batch-1"))
        .unwrap();
    tx.commit().unwrap();

    // Data should be visible
    assert!(storage.get_sync_metadata("sync-1").unwrap().is_some());
    assert_eq!(storage.get_unpushed_batch_ids("sync-1").unwrap().len(), 1);
}

// ═══════════════════════════════════════════════════════════════════════════
// Storage edge cases — reads on missing data
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn read_nonexistent_sync_metadata_returns_none() {
    let storage = make_storage();
    let meta = storage.get_sync_metadata("no-such-sync").unwrap();
    assert!(meta.is_none());
}

#[test]
fn read_nonexistent_field_version_returns_none() {
    let storage = make_storage();
    let fv = storage
        .get_field_version("sync-1", "tasks", "no-entity", "no-field")
        .unwrap();
    assert!(fv.is_none());
}

#[test]
fn read_nonexistent_device_record_returns_none() {
    let storage = make_storage();
    let dr = storage.get_device_record("sync-1", "no-device").unwrap();
    assert!(dr.is_none());
}

#[test]
fn is_op_applied_returns_false_for_unknown_op() {
    let storage = make_storage();
    assert!(!storage.is_op_applied("nonexistent-op").unwrap());
}

#[test]
fn list_device_records_empty_when_none_exist() {
    let storage = make_storage();
    let devices = storage.list_device_records("sync-1").unwrap();
    assert!(devices.is_empty());
}

#[test]
fn get_unpushed_batch_ids_empty_when_no_ops() {
    let storage = make_storage();
    let batches = storage.get_unpushed_batch_ids("sync-1").unwrap();
    assert!(batches.is_empty());
}

#[test]
fn load_batch_ops_empty_for_nonexistent_batch() {
    let storage = make_storage();
    let ops = storage.load_batch_ops("no-such-batch").unwrap();
    assert!(ops.is_empty());
}

// ═══════════════════════════════════════════════════════════════════════════
// Upsert / duplicate behavior
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn upsert_sync_metadata_overwrites_existing() {
    let storage = make_storage();

    let mut tx = storage.begin_tx().unwrap();
    tx.upsert_sync_metadata(&sample_metadata("sync-1")).unwrap();
    tx.commit().unwrap();

    // Upsert again with different device_id
    let mut meta2 = sample_metadata("sync-1");
    meta2.local_device_id = "dev-2".to_string();
    meta2.current_epoch = 5;

    let mut tx = storage.begin_tx().unwrap();
    tx.upsert_sync_metadata(&meta2).unwrap();
    tx.commit().unwrap();

    let retrieved = storage.get_sync_metadata("sync-1").unwrap().unwrap();
    assert_eq!(retrieved.local_device_id, "dev-2");
    assert_eq!(retrieved.current_epoch, 5);
}

#[test]
fn upsert_field_version_overwrites_previous_winner() {
    let storage = make_storage();

    let mut tx = storage.begin_tx().unwrap();
    tx.upsert_field_version(&sample_field_version("e1", "title", "hlc-1"))
        .unwrap();
    tx.commit().unwrap();

    // Upsert with a new HLC
    let mut fv2 = sample_field_version("e1", "title", "hlc-2");
    fv2.winning_op_id = "op-newer".to_string();
    fv2.winning_encoded_value = Some("\"updated\"".to_string());

    let mut tx = storage.begin_tx().unwrap();
    tx.upsert_field_version(&fv2).unwrap();
    tx.commit().unwrap();

    let fv = storage
        .get_field_version("sync-1", "tasks", "e1", "title")
        .unwrap()
        .unwrap();
    assert_eq!(fv.winning_op_id, "op-newer");
    assert_eq!(fv.winning_hlc, "hlc-2");
}

#[test]
fn upsert_device_record_overwrites_existing() {
    let storage = make_storage();

    let mut tx = storage.begin_tx().unwrap();
    tx.upsert_device_record(&sample_device_record("dev-1"))
        .unwrap();
    tx.commit().unwrap();

    // Upsert with revoked status
    let mut dr2 = sample_device_record("dev-1");
    dr2.status = "revoked".to_string();
    dr2.revoked_at = Some(Utc::now());

    let mut tx = storage.begin_tx().unwrap();
    tx.upsert_device_record(&dr2).unwrap();
    tx.commit().unwrap();

    let dr = storage
        .get_device_record("sync-1", "dev-1")
        .unwrap()
        .unwrap();
    assert_eq!(dr.status, "revoked");
    assert!(dr.revoked_at.is_some());
}

#[test]
fn insert_duplicate_pending_op_id_errors() {
    let storage = make_storage();

    let mut tx = storage.begin_tx().unwrap();
    tx.insert_pending_op(&sample_pending_op("dup-op", "batch-1"))
        .unwrap();
    // Same op_id again should fail (PRIMARY KEY constraint)
    let result = tx.insert_pending_op(&sample_pending_op("dup-op", "batch-1"));
    assert!(result.is_err(), "duplicate pending op_id should error");
    // Transaction is still usable after the error — rollback to clean up
    tx.rollback().unwrap();
}

#[test]
fn insert_duplicate_applied_op_is_ignored() {
    let storage = make_storage();

    let mut tx = storage.begin_tx().unwrap();
    tx.insert_applied_op(&sample_applied_op("aop-1", 1))
        .unwrap();
    // INSERT OR IGNORE means duplicate should silently succeed
    tx.insert_applied_op(&sample_applied_op("aop-1", 1))
        .unwrap();
    tx.commit().unwrap();

    assert!(storage.is_op_applied("aop-1").unwrap());
}

// ═══════════════════════════════════════════════════════════════════════════
// Sync metadata edge cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn update_last_pulled_seq_creates_metadata_if_missing() {
    let storage = make_storage();

    // update_last_pulled_seq uses INSERT ... ON CONFLICT, so it can create a row
    let mut tx = storage.begin_tx().unwrap();
    tx.update_last_pulled_seq("new-sync", 42).unwrap();
    tx.commit().unwrap();

    let meta = storage.get_sync_metadata("new-sync").unwrap().unwrap();
    assert_eq!(meta.last_pulled_server_seq, 42);
}

#[test]
fn update_last_successful_sync_creates_metadata_if_missing() {
    let storage = make_storage();

    let mut tx = storage.begin_tx().unwrap();
    tx.update_last_successful_sync("new-sync").unwrap();
    tx.commit().unwrap();

    let meta = storage.get_sync_metadata("new-sync").unwrap().unwrap();
    assert!(meta.last_successful_sync_at.is_some());
}

#[test]
fn update_current_epoch_on_nonexistent_metadata_is_noop() {
    let storage = make_storage();

    // UPDATE ... WHERE sync_id = ? on a missing row affects 0 rows — no error
    let mut tx = storage.begin_tx().unwrap();
    tx.update_current_epoch("no-such-sync", 5).unwrap();
    tx.commit().unwrap();

    // Still no metadata
    assert!(storage.get_sync_metadata("no-such-sync").unwrap().is_none());
}

#[test]
fn update_last_pulled_seq_updates_existing_metadata() {
    let storage = make_storage();

    let mut tx = storage.begin_tx().unwrap();
    tx.upsert_sync_metadata(&sample_metadata("sync-1")).unwrap();
    tx.commit().unwrap();

    let mut tx = storage.begin_tx().unwrap();
    tx.update_last_pulled_seq("sync-1", 100).unwrap();
    tx.commit().unwrap();

    let meta = storage.get_sync_metadata("sync-1").unwrap().unwrap();
    assert_eq!(meta.last_pulled_server_seq, 100);
    // Original device_id should be preserved
    assert_eq!(meta.local_device_id, "dev-1");
}

// ═══════════════════════════════════════════════════════════════════════════
// Pending ops edge cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn mark_batch_pushed_on_nonexistent_batch_is_noop() {
    let storage = make_storage();

    let mut tx = storage.begin_tx().unwrap();
    // Should not error — UPDATE on 0 rows is fine
    tx.mark_batch_pushed("no-such-batch").unwrap();
    tx.commit().unwrap();
}

#[test]
fn delete_pushed_ops_when_none_exist_is_noop() {
    let storage = make_storage();

    let mut tx = storage.begin_tx().unwrap();
    tx.delete_pushed_ops("sync-1").unwrap();
    tx.commit().unwrap();
}

#[test]
fn delete_pushed_ops_only_removes_pushed() {
    let storage = make_storage();

    let mut tx = storage.begin_tx().unwrap();
    tx.insert_pending_op(&sample_pending_op("op-1", "batch-1"))
        .unwrap();
    tx.insert_pending_op(&{
        let mut op = sample_pending_op("op-2", "batch-2");
        op.pushed_at = Some(Utc::now());
        op
    })
    .unwrap();
    tx.commit().unwrap();

    let mut tx = storage.begin_tx().unwrap();
    tx.delete_pushed_ops("sync-1").unwrap();
    tx.commit().unwrap();

    // op-1 (unpushed) should remain, op-2 (pushed) should be gone
    let batches = storage.get_unpushed_batch_ids("sync-1").unwrap();
    assert_eq!(batches.len(), 1);
    assert_eq!(batches[0], "batch-1");
}

// ═══════════════════════════════════════════════════════════════════════════
// Pruning edge cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn prune_applied_ops_when_none_exist_returns_zero() {
    let storage = make_storage();

    let mut tx = storage.begin_tx().unwrap();
    let deleted = tx
        .delete_applied_ops_below_seq("sync-1", 100, 1000)
        .unwrap();
    tx.commit().unwrap();
    assert_eq!(deleted, 0);
}

#[test]
fn prune_applied_ops_respects_seq_threshold() {
    let storage = make_storage();

    let mut tx = storage.begin_tx().unwrap();
    tx.insert_applied_op(&sample_applied_op("aop-1", 5))
        .unwrap();
    tx.insert_applied_op(&sample_applied_op("aop-2", 10))
        .unwrap();
    tx.insert_applied_op(&sample_applied_op("aop-3", 15))
        .unwrap();
    tx.commit().unwrap();

    // Prune ops with server_seq < 12
    let mut tx = storage.begin_tx().unwrap();
    let deleted = tx.delete_applied_ops_below_seq("sync-1", 12, 100).unwrap();
    tx.commit().unwrap();

    assert_eq!(deleted, 2); // aop-1 (seq=5) and aop-2 (seq=10)
    assert!(storage.is_op_applied("aop-3").unwrap()); // seq=15 should remain
}

#[test]
fn prune_applied_ops_respects_limit() {
    let storage = make_storage();

    let mut tx = storage.begin_tx().unwrap();
    tx.insert_applied_op(&sample_applied_op("aop-1", 1))
        .unwrap();
    tx.insert_applied_op(&sample_applied_op("aop-2", 2))
        .unwrap();
    tx.insert_applied_op(&sample_applied_op("aop-3", 3))
        .unwrap();
    tx.commit().unwrap();

    // Prune all below seq 100, but limit to 2
    let mut tx = storage.begin_tx().unwrap();
    let deleted = tx.delete_applied_ops_below_seq("sync-1", 100, 2).unwrap();
    tx.commit().unwrap();

    assert_eq!(deleted, 2);
}

#[test]
fn count_prunable_applied_ops_when_empty() {
    let storage = make_storage();
    let count = storage.count_prunable_applied_ops("sync-1", 100).unwrap();
    assert_eq!(count, 0);
}

#[test]
fn delete_field_versions_for_nonexistent_entity_is_noop() {
    let storage = make_storage();

    let mut tx = storage.begin_tx().unwrap();
    // Should not error
    tx.delete_field_versions_for_entity("sync-1", "tasks", "no-such-entity")
        .unwrap();
    tx.commit().unwrap();
}

#[test]
fn delete_field_versions_removes_all_fields_for_entity() {
    let storage = make_storage();

    let mut tx = storage.begin_tx().unwrap();
    tx.upsert_field_version(&sample_field_version("e1", "title", "hlc-1"))
        .unwrap();
    tx.upsert_field_version(&sample_field_version("e1", "done", "hlc-2"))
        .unwrap();
    tx.upsert_field_version(&sample_field_version("e2", "title", "hlc-3"))
        .unwrap();
    tx.commit().unwrap();

    let mut tx = storage.begin_tx().unwrap();
    tx.delete_field_versions_for_entity("sync-1", "tasks", "e1")
        .unwrap();
    tx.commit().unwrap();

    // e1 fields should be gone
    assert!(storage
        .get_field_version("sync-1", "tasks", "e1", "title")
        .unwrap()
        .is_none());
    assert!(storage
        .get_field_version("sync-1", "tasks", "e1", "done")
        .unwrap()
        .is_none());
    // e2 should remain
    assert!(storage
        .get_field_version("sync-1", "tasks", "e2", "title")
        .unwrap()
        .is_some());
}

// ═══════════════════════════════════════════════════════════════════════════
// Device registry edge cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn remove_nonexistent_device_record_is_noop() {
    let storage = make_storage();

    let mut tx = storage.begin_tx().unwrap();
    tx.remove_device_record("sync-1", "no-such-device").unwrap();
    tx.commit().unwrap();
}

#[test]
fn remove_device_record_works() {
    let storage = make_storage();

    let mut tx = storage.begin_tx().unwrap();
    tx.upsert_device_record(&sample_device_record("dev-1"))
        .unwrap();
    tx.upsert_device_record(&sample_device_record("dev-2"))
        .unwrap();
    tx.commit().unwrap();

    assert_eq!(storage.list_device_records("sync-1").unwrap().len(), 2);

    let mut tx = storage.begin_tx().unwrap();
    tx.remove_device_record("sync-1", "dev-1").unwrap();
    tx.commit().unwrap();

    assert!(storage
        .get_device_record("sync-1", "dev-1")
        .unwrap()
        .is_none());
    assert!(storage
        .get_device_record("sync-1", "dev-2")
        .unwrap()
        .is_some());
    assert_eq!(storage.list_device_records("sync-1").unwrap().len(), 1);
}

// ═══════════════════════════════════════════════════════════════════════════
// Large value handling
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn large_encoded_value_round_trips() {
    let storage = make_storage();
    let large_value = "x".repeat(1_000_000); // 1MB string

    let mut op = sample_pending_op("large-op", "batch-large");
    op.encoded_value = large_value.clone();

    let mut tx = storage.begin_tx().unwrap();
    tx.insert_pending_op(&op).unwrap();
    tx.commit().unwrap();

    let ops = storage.load_batch_ops("batch-large").unwrap();
    assert_eq!(ops.len(), 1);
    assert_eq!(ops[0].encoded_value.len(), 1_000_000);
    assert_eq!(ops[0].encoded_value, large_value);
}

#[test]
fn large_entity_id_round_trips() {
    let storage = make_storage();
    let large_id = "id-".to_string() + &"a".repeat(10_000);

    let mut fv = sample_field_version(&large_id, "title", "hlc-1");
    fv.entity_id = large_id.clone();

    let mut tx = storage.begin_tx().unwrap();
    tx.upsert_field_version(&fv).unwrap();
    tx.commit().unwrap();

    let result = storage
        .get_field_version("sync-1", "tasks", &large_id, "title")
        .unwrap();
    assert!(result.is_some());
    assert_eq!(result.unwrap().entity_id, large_id);
}

// ═══════════════════════════════════════════════════════════════════════════
// clear_sync_state
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn clear_sync_state_removes_all_data_for_sync_id() {
    let storage = make_storage();

    let mut tx = storage.begin_tx().unwrap();
    tx.upsert_sync_metadata(&sample_metadata("sync-1")).unwrap();
    tx.insert_pending_op(&sample_pending_op("op-1", "batch-1"))
        .unwrap();
    tx.insert_applied_op(&sample_applied_op("aop-1", 1))
        .unwrap();
    tx.upsert_field_version(&sample_field_version("e1", "title", "hlc-1"))
        .unwrap();
    tx.upsert_device_record(&sample_device_record("dev-1"))
        .unwrap();
    tx.commit().unwrap();

    let mut tx = storage.begin_tx().unwrap();
    tx.clear_sync_state("sync-1").unwrap();
    tx.commit().unwrap();

    assert!(storage.get_sync_metadata("sync-1").unwrap().is_none());
    assert!(storage.get_unpushed_batch_ids("sync-1").unwrap().is_empty());
    assert!(!storage.is_op_applied("aop-1").unwrap());
    assert!(storage
        .get_field_version("sync-1", "tasks", "e1", "title")
        .unwrap()
        .is_none());
    assert!(storage.list_device_records("sync-1").unwrap().is_empty());
}

#[test]
fn clear_sync_state_does_not_affect_other_sync_ids() {
    let storage = make_storage();

    let mut tx = storage.begin_tx().unwrap();
    tx.upsert_sync_metadata(&sample_metadata("sync-1")).unwrap();
    tx.upsert_sync_metadata(&sample_metadata("sync-2")).unwrap();
    tx.upsert_device_record(&sample_device_record("dev-1"))
        .unwrap();
    // Add device for sync-2
    tx.upsert_device_record(&DeviceRecord {
        sync_id: "sync-2".to_string(),
        device_id: "dev-1".to_string(),
        ed25519_public_key: vec![1u8; 32],
        x25519_public_key: vec![1u8; 32],
        ml_dsa_65_public_key: vec![2u8; 1952],
        ml_kem_768_public_key: vec![3u8; 1184],
        status: "active".to_string(),
        registered_at: Utc::now(),
        revoked_at: None,
    })
    .unwrap();
    tx.commit().unwrap();

    let mut tx = storage.begin_tx().unwrap();
    tx.clear_sync_state("sync-1").unwrap();
    tx.commit().unwrap();

    // sync-2 should be unaffected
    assert!(storage.get_sync_metadata("sync-2").unwrap().is_some());
    assert_eq!(storage.list_device_records("sync-2").unwrap().len(), 1);
}

// ═══════════════════════════════════════════════════════════════════════════
// Sequential transaction reuse (concurrent access prevented by Mutex)
// ═══════════════════════════════════════════════════════════════════════════

/// `RusqliteSyncStorage` wraps `Mutex<Connection>`. Calling `begin_tx()` locks
/// the mutex and holds the `MutexGuard` inside the returned `RusqliteTx`.
/// This means a second `begin_tx()` on the same thread would deadlock, and on
/// another thread it blocks until the first tx is dropped/committed/rolled back.
///
/// This test verifies that sequential transactions (tx1 → commit → tx2 → commit)
/// work correctly, which is the intended usage pattern.
#[test]
fn sequential_transactions_work_after_commit() {
    let storage = make_storage();

    // First transaction: insert metadata
    let mut tx = storage.begin_tx().unwrap();
    tx.upsert_sync_metadata(&sample_metadata("sync-seq"))
        .unwrap();
    tx.commit().unwrap();

    // Second transaction: insert more data (mutex is released after commit)
    let mut tx = storage.begin_tx().unwrap();
    tx.insert_pending_op(&sample_pending_op("op-seq-1", "batch-seq"))
        .unwrap();
    tx.commit().unwrap();

    // Both writes should be visible
    assert!(storage.get_sync_metadata("sync-seq").unwrap().is_some());
    // pending op helper uses sync_id "sync-1"
    assert_eq!(storage.get_unpushed_batch_ids("sync-1").unwrap().len(), 1);
}

#[test]
fn sequential_transactions_work_after_rollback() {
    let storage = make_storage();

    // First transaction: insert then rollback
    let mut tx = storage.begin_tx().unwrap();
    tx.upsert_sync_metadata(&sample_metadata("sync-rb"))
        .unwrap();
    tx.rollback().unwrap();

    // Second transaction should succeed (mutex released after rollback)
    let mut tx = storage.begin_tx().unwrap();
    tx.upsert_sync_metadata(&sample_metadata("sync-rb"))
        .unwrap();
    tx.commit().unwrap();

    assert!(storage.get_sync_metadata("sync-rb").unwrap().is_some());
}

#[test]
fn sequential_transactions_work_after_drop() {
    let storage = make_storage();

    // First transaction: dropped without commit or rollback
    {
        let mut tx = storage.begin_tx().unwrap();
        tx.upsert_sync_metadata(&sample_metadata("sync-drop2"))
            .unwrap();
        // tx dropped here — auto-rollback
    }

    // Second transaction should succeed (mutex released on drop)
    let mut tx = storage.begin_tx().unwrap();
    tx.upsert_sync_metadata(&sample_metadata("sync-drop2"))
        .unwrap();
    tx.commit().unwrap();

    assert!(storage.get_sync_metadata("sync-drop2").unwrap().is_some());
}

// ═══════════════════════════════════════════════════════════════════════════
// Malformed snapshot import
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn import_snapshot_empty_bytes_returns_error() {
    let storage = make_storage();
    let mut tx = storage.begin_tx().unwrap();
    let result = tx.import_snapshot("sync-1", &[]);
    assert!(result.is_err(), "empty bytes should return Err, not panic");
}

#[test]
fn import_snapshot_garbage_bytes_returns_error() {
    let storage = make_storage();
    let mut tx = storage.begin_tx().unwrap();
    let result = tx.import_snapshot("sync-1", &[0xFF, 0xFE, 0x00, 0x01]);
    assert!(
        result.is_err(),
        "garbage bytes should return Err, not panic"
    );
}

#[test]
fn import_snapshot_truncated_zstd_returns_error() {
    let storage = make_storage();
    let mut tx = storage.begin_tx().unwrap();
    // Valid zstd magic number (0xFD2FB528 little-endian) but truncated payload
    let result = tx.import_snapshot("sync-1", &[0x28, 0xB5, 0x2F, 0xFD, 0x00]);
    assert!(
        result.is_err(),
        "truncated zstd frame should return Err, not panic"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Prunable tombstones
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn list_prunable_tombstones_empty_when_no_tombstones() {
    let storage = make_storage();
    let tombstones = storage.list_prunable_tombstones("sync-1", 100, 10).unwrap();
    assert!(tombstones.is_empty());
}

#[test]
fn list_prunable_tombstones_finds_deleted_entities() {
    let storage = make_storage();

    let mut tx = storage.begin_tx().unwrap();
    // Create a field_version for is_deleted = "true"
    tx.upsert_field_version(&FieldVersion {
        sync_id: "sync-1".to_string(),
        entity_table: "tasks".to_string(),
        entity_id: "deleted-entity".to_string(),
        field_name: "is_deleted".to_string(),
        winning_op_id: "delete-op-1".to_string(),
        winning_device_id: "dev-1".to_string(),
        winning_hlc: "hlc-1".to_string(),
        winning_encoded_value: Some("true".to_string()),
        updated_at: Utc::now(),
    })
    .unwrap();
    // Create a matching applied_op with server_seq below the threshold
    tx.insert_applied_op(&AppliedOp {
        op_id: "delete-op-1".to_string(),
        sync_id: "sync-1".to_string(),
        epoch: 0,
        device_id: "dev-1".to_string(),
        client_hlc: "hlc-1".to_string(),
        server_seq: 5,
        applied_at: Utc::now(),
    })
    .unwrap();
    tx.commit().unwrap();

    let tombstones = storage.list_prunable_tombstones("sync-1", 10, 100).unwrap();
    assert_eq!(tombstones.len(), 1);
    assert_eq!(
        tombstones[0],
        ("tasks".to_string(), "deleted-entity".to_string())
    );

    // With threshold below the seq, should find nothing
    let tombstones = storage.list_prunable_tombstones("sync-1", 3, 100).unwrap();
    assert!(tombstones.is_empty());
}
