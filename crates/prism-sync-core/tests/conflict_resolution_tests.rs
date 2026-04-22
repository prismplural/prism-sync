//! Parametric conflict resolution tests for the CRDT merge engine.
//!
//! These tests exercise the field-level Last-Write-Wins merge with its
//! 3-level tiebreaker: HLC (timestamp → counter → node_id) → device_id → op_id
//! across a variety of scenarios:
//!
//! - HLC tiebreaker: timestamp, counter, node_id, then device_id, op_id
//! - Concurrent writes: same field / different fields / three devices
//! - Edge cases: tombstone protection, resurrection prevention,
//!   empty-vs-null values, rapid successive writes

mod common;

use std::collections::HashMap;
use std::sync::Arc;

use ed25519_dalek::SigningKey;

use prism_sync_core::engine::{MergeEngine, SyncConfig, SyncEngine};
use prism_sync_core::relay::MockRelay;
use prism_sync_core::schema::SyncValue;
use prism_sync_core::storage::{FieldVersion, RusqliteSyncStorage, SyncStorage};
use prism_sync_core::syncable_entity::SyncableEntity;
use prism_sync_core::{batch_signature, sync_aad, CrdtChange, Hlc};

use common::*;

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

/// Build a CrdtChange for the "tasks" table with the given parameters.
fn make_op(
    entity_id: &str,
    field_name: &str,
    encoded_value: &str,
    hlc: &Hlc,
    device_id: &str,
    op_id: Option<&str>,
) -> CrdtChange {
    let op_id = op_id
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("tasks:{}:{}:{}:{}", entity_id, field_name, hlc, device_id));
    CrdtChange {
        op_id,
        batch_id: Some("batch-1".to_string()),
        entity_id: entity_id.to_string(),
        entity_table: "tasks".to_string(),
        field_name: field_name.to_string(),
        encoded_value: encoded_value.to_string(),
        client_hlc: hlc.to_string(),
        is_delete: false,
        device_id: device_id.to_string(),
        epoch: 0,
        server_seq: None,
    }
}

/// Build a soft-delete CrdtChange (is_deleted field).
fn make_delete_op(entity_id: &str, hlc: &Hlc, device_id: &str) -> CrdtChange {
    let op_id = format!("tasks:{}:is_deleted:{}:{}", entity_id, hlc, device_id);
    CrdtChange {
        op_id,
        batch_id: Some("batch-1".to_string()),
        entity_id: entity_id.to_string(),
        entity_table: "tasks".to_string(),
        field_name: "is_deleted".to_string(),
        encoded_value: "true".to_string(),
        client_hlc: hlc.to_string(),
        is_delete: true,
        device_id: device_id.to_string(),
        epoch: 0,
        server_seq: None,
    }
}

/// No field versions exist — everything is new.
fn no_field_versions(
    _sync_id: &str,
    _table: &str,
    _eid: &str,
    _field: &str,
) -> prism_sync_core::Result<Option<FieldVersion>> {
    Ok(None)
}

/// No ops applied yet.
fn no_ops_applied(_op_id: &str) -> prism_sync_core::Result<bool> {
    Ok(false)
}

/// Create a signed + encrypted batch envelope from CrdtChange ops.
fn make_encrypted_batch(
    ops: &[CrdtChange],
    key_hierarchy: &prism_sync_crypto::KeyHierarchy,
    signing_key: &SigningKey,
    ml_dsa_signing_key: &prism_sync_crypto::DevicePqSigningKey,
    batch_id: &str,
    sender_device_id: &str,
) -> prism_sync_core::relay::SignedBatchEnvelope {
    let plaintext = CrdtChange::encode_batch(ops).unwrap();
    let payload_hash = batch_signature::compute_payload_hash(&plaintext);
    let epoch_key = key_hierarchy.epoch_key(0).unwrap();
    let aad = sync_aad::build_sync_aad(SYNC_ID, sender_device_id, 0, batch_id, "ops");
    let (ciphertext, nonce) =
        prism_sync_crypto::aead::xchacha_encrypt_for_sync(epoch_key, &plaintext, &aad).unwrap();

    batch_signature::sign_batch(
        signing_key,
        ml_dsa_signing_key,
        SYNC_ID,
        0,
        batch_id,
        "ops",
        sender_device_id,
        0,
        &payload_hash,
        nonce,
        ciphertext,
    )
    .unwrap()
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. HLC tiebreaker — later timestamp wins
// ═══════════════════════════════════════════════════════════════════════════

/// When two devices write the same field at different timestamps,
/// the op with the later (higher) HLC timestamp wins.
#[test]
fn test_later_hlc_timestamp_wins_field_conflict() {
    let schema = test_schema();
    let merge = MergeEngine::new(schema);

    let hlc_early = Hlc::new(1000, 0, "dev-a");
    let hlc_late = Hlc::new(2000, 0, "dev-b");

    // Incoming batch: early write followed by late write
    let ops = vec![
        make_op("t1", "title", "\"Early\"", &hlc_early, "dev-a", None),
        make_op("t1", "title", "\"Late\"", &hlc_late, "dev-b", None),
    ];

    let winners =
        merge.determine_winners(&ops, &no_field_versions, &no_ops_applied, SYNC_ID).unwrap();

    assert_eq!(winners.len(), 1, "only one op should win for the same field");
    let winner = winners.values().next().unwrap();
    assert_eq!(winner.op.encoded_value, "\"Late\"");
    assert_eq!(winner.op.device_id, "dev-b");
}

/// When the later timestamp op comes first in the batch, it should still win.
#[test]
fn test_later_hlc_wins_regardless_of_batch_order() {
    let schema = test_schema();
    let merge = MergeEngine::new(schema);

    let hlc_early = Hlc::new(1000, 0, "dev-a");
    let hlc_late = Hlc::new(2000, 0, "dev-b");

    // Late op first in the batch
    let ops = vec![
        make_op("t1", "title", "\"Late\"", &hlc_late, "dev-b", None),
        make_op("t1", "title", "\"Early\"", &hlc_early, "dev-a", None),
    ];

    let winners =
        merge.determine_winners(&ops, &no_field_versions, &no_ops_applied, SYNC_ID).unwrap();

    assert_eq!(winners.len(), 1);
    let winner = winners.values().next().unwrap();
    assert_eq!(winner.op.encoded_value, "\"Late\"");
}

/// Lower HLC op should lose against a persisted field version with a higher HLC.
#[test]
fn test_lower_hlc_loses_against_persisted_field_version() {
    let schema = test_schema();
    let merge = MergeEngine::new(schema);

    let hlc_old = Hlc::new(500, 0, "dev-old");

    let ops = vec![make_op("t1", "title", "\"OldValue\"", &hlc_old, "dev-old", None)];

    // Persisted field version has a higher HLC
    let get_fv = |_sync_id: &str,
                  _table: &str,
                  _eid: &str,
                  field: &str|
     -> prism_sync_core::Result<Option<FieldVersion>> {
        if field == "title" {
            Ok(Some(FieldVersion {
                sync_id: SYNC_ID.to_string(),
                entity_table: "tasks".to_string(),
                entity_id: "t1".to_string(),
                field_name: "title".to_string(),
                winning_op_id: "existing-op".to_string(),
                winning_device_id: "dev-existing".to_string(),
                winning_hlc: Hlc::new(9000, 0, "dev-existing").to_string(),
                winning_encoded_value: None,
                updated_at: chrono::Utc::now(),
            }))
        } else {
            Ok(None)
        }
    };

    let winners = merge.determine_winners(&ops, &get_fv, &no_ops_applied, SYNC_ID).unwrap();

    assert!(winners.is_empty(), "old HLC should not beat existing field version");
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. HLC counter tiebreaker
// ═══════════════════════════════════════════════════════════════════════════

/// Same timestamp, different counter — higher counter wins.
#[test]
fn test_higher_hlc_counter_wins() {
    let schema = test_schema();
    let merge = MergeEngine::new(schema);

    let hlc_low_counter = Hlc::new(5000, 1, "dev-a");
    let hlc_high_counter = Hlc::new(5000, 5, "dev-b");

    let ops = vec![
        make_op("t1", "title", "\"LowCounter\"", &hlc_low_counter, "dev-a", None),
        make_op("t1", "title", "\"HighCounter\"", &hlc_high_counter, "dev-b", None),
    ];

    let winners =
        merge.determine_winners(&ops, &no_field_versions, &no_ops_applied, SYNC_ID).unwrap();

    assert_eq!(winners.len(), 1);
    let winner = winners.values().next().unwrap();
    assert_eq!(winner.op.encoded_value, "\"HighCounter\"");
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. Device ID tiebreaker (same HLC)
// ═══════════════════════════════════════════════════════════════════════════

/// Same HLC timestamp and counter — lexicographically greater device_id wins.
#[test]
fn test_device_id_tiebreaker_same_hlc() {
    let schema = test_schema();
    let merge = MergeEngine::new(schema);

    // Same timestamp and counter, different node_id in HLC + different device_id
    let hlc_a = Hlc::new(5000, 0, "node-a");
    let hlc_b = Hlc::new(5000, 0, "node-a"); // same HLC

    let ops = vec![
        make_op("t1", "title", "\"FromAlpha\"", &hlc_a, "device-alpha", None),
        make_op("t1", "title", "\"FromZulu\"", &hlc_b, "device-zulu", None),
    ];

    let winners =
        merge.determine_winners(&ops, &no_field_versions, &no_ops_applied, SYNC_ID).unwrap();

    assert_eq!(winners.len(), 1);
    let winner = winners.values().next().unwrap();
    // "device-zulu" > "device-alpha" lexicographically
    assert_eq!(winner.op.encoded_value, "\"FromZulu\"");
    assert_eq!(winner.op.device_id, "device-zulu");
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. Op ID tiebreaker (same HLC, same device_id)
// ═══════════════════════════════════════════════════════════════════════════

/// Same HLC and device_id — lexicographically greater op_id wins.
#[test]
fn test_op_id_tiebreaker_same_hlc_same_device() {
    let schema = test_schema();
    let merge = MergeEngine::new(schema);

    let hlc = Hlc::new(5000, 0, "node-x");

    let ops = vec![
        make_op("t1", "title", "\"OpA\"", &hlc, "dev-same", Some("op-aaa")),
        make_op("t1", "title", "\"OpZ\"", &hlc, "dev-same", Some("op-zzz")),
    ];

    let winners =
        merge.determine_winners(&ops, &no_field_versions, &no_ops_applied, SYNC_ID).unwrap();

    assert_eq!(winners.len(), 1);
    let winner = winners.values().next().unwrap();
    // "op-zzz" > "op-aaa"
    assert_eq!(winner.op.encoded_value, "\"OpZ\"");
    assert_eq!(winner.op.op_id, "op-zzz");
}

// ═══════════════════════════════════════════════════════════════════════════
// 5. Different fields on same entity — both preserved (no conflict)
// ═══════════════════════════════════════════════════════════════════════════

/// Device A writes "title", Device B writes "done" — both should win
/// because they target different fields.
#[test]
fn test_different_fields_both_preserved() {
    let schema = test_schema();
    let merge = MergeEngine::new(schema);

    let hlc_a = Hlc::new(1000, 0, "dev-a");
    let hlc_b = Hlc::new(2000, 0, "dev-b");

    let ops = vec![
        make_op("t1", "title", "\"MyTitle\"", &hlc_a, "dev-a", None),
        make_op("t1", "done", "true", &hlc_b, "dev-b", None),
    ];

    let winners =
        merge.determine_winners(&ops, &no_field_versions, &no_ops_applied, SYNC_ID).unwrap();

    assert_eq!(winners.len(), 2, "both ops on different fields should win");

    let values: Vec<&str> = winners.values().map(|w| w.op.field_name.as_str()).collect();
    assert!(values.contains(&"title"));
    assert!(values.contains(&"done"));
}

// ═══════════════════════════════════════════════════════════════════════════
// 6. Three devices write same field concurrently — deterministic winner
// ═══════════════════════════════════════════════════════════════════════════

/// Three devices write the same field with different timestamps.
/// The one with the highest HLC should deterministically win.
#[test]
fn test_three_devices_same_field_deterministic_winner() {
    let schema = test_schema();
    let merge = MergeEngine::new(schema);

    let hlc_a = Hlc::new(1000, 0, "dev-a");
    let hlc_b = Hlc::new(3000, 0, "dev-b");
    let hlc_c = Hlc::new(2000, 0, "dev-c");

    let ops = vec![
        make_op("t1", "title", "\"FromA\"", &hlc_a, "dev-a", None),
        make_op("t1", "title", "\"FromB\"", &hlc_b, "dev-b", None),
        make_op("t1", "title", "\"FromC\"", &hlc_c, "dev-c", None),
    ];

    let winners =
        merge.determine_winners(&ops, &no_field_versions, &no_ops_applied, SYNC_ID).unwrap();

    assert_eq!(winners.len(), 1);
    let winner = winners.values().next().unwrap();
    assert_eq!(winner.op.encoded_value, "\"FromB\"", "device B with HLC 3000 should win");
}

/// Three devices, same HLC timestamp — device_id tiebreaker should give
/// deterministic result regardless of batch ordering.
#[test]
fn test_three_devices_same_hlc_device_tiebreaker() {
    let schema = test_schema();
    let merge = MergeEngine::new(schema);

    let hlc = Hlc::new(5000, 0, "shared-node");

    // Try multiple orderings to confirm determinism
    for ordering in
        [["dev-a", "dev-b", "dev-c"], ["dev-c", "dev-a", "dev-b"], ["dev-b", "dev-c", "dev-a"]]
    {
        let ops: Vec<CrdtChange> = ordering
            .iter()
            .map(|dev| make_op("t1", "title", &format!("\"From-{}\"", dev), &hlc, dev, None))
            .collect();

        let winners =
            merge.determine_winners(&ops, &no_field_versions, &no_ops_applied, SYNC_ID).unwrap();

        assert_eq!(winners.len(), 1);
        let winner = winners.values().next().unwrap();
        // "dev-c" is lexicographically greatest
        assert_eq!(
            winner.op.device_id, "dev-c",
            "dev-c should always win (greatest device_id), ordering: {:?}",
            ordering
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 7. Soft delete vs field update — later HLC delete wins
// ═══════════════════════════════════════════════════════════════════════════

/// When a soft delete (is_deleted=true) has a later HLC than a field update,
/// the delete should win and subsequent field updates on the same entity
/// should be blocked by tombstone protection.
#[tokio::test]
async fn test_soft_delete_wins_with_later_hlc() {
    let key_hierarchy = init_key_hierarchy();
    let signing_key_local = make_signing_key();
    let signing_key_remote = make_signing_key();
    let ml_dsa_key_remote = make_ml_dsa_keypair();
    let local_device = "device-local";
    let remote_device = "device-remote";

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity = Arc::new(MockTaskEntity::new());
    let entity_ref: Arc<dyn SyncableEntity> = entity.clone();

    setup_sync_metadata(&storage, local_device);
    register_device(&relay, &storage, local_device, &signing_key_local.verifying_key());
    register_device_with_pq(
        &relay,
        &storage,
        remote_device,
        &signing_key_remote.verifying_key(),
        &ml_dsa_key_remote.public_key_bytes(),
    );

    // Local has a field version for title at HLC 1000
    let hlc_local = Hlc::new(1000, 0, local_device);
    {
        let mut tx = storage.begin_tx().unwrap();
        tx.upsert_field_version(&FieldVersion {
            sync_id: SYNC_ID.to_string(),
            entity_table: "tasks".to_string(),
            entity_id: "t-del".to_string(),
            field_name: "title".to_string(),
            winning_op_id: "local-title-op".to_string(),
            winning_device_id: local_device.to_string(),
            winning_hlc: hlc_local.to_string(),
            winning_encoded_value: None,
            updated_at: chrono::Utc::now(),
        })
        .unwrap();
        tx.commit().unwrap();
    }

    // Remote sends a delete at HLC 2000 (later — should win)
    let hlc_delete = Hlc::new(2000, 0, remote_device);
    let delete_op = make_delete_op("t-del", &hlc_delete, remote_device);

    let envelope = make_encrypted_batch(
        &[delete_op],
        &key_hierarchy,
        &signing_key_remote,
        &ml_dsa_key_remote,
        "batch-del",
        remote_device,
    );
    relay.inject_batch(envelope);

    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity_ref],
        test_schema(),
        SyncConfig::default(),
    );

    let result = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key_local, None, local_device, 0)
        .await
        .unwrap();

    assert!(result.error.is_none(), "sync error: {:?}", result.error);
    assert_eq!(result.merged, 1, "delete op should be merged");

    // Verify the entity was soft deleted
    assert!(entity.is_deleted("t-del").await.unwrap(), "entity should be soft deleted");
}

/// After a soft delete is tombstoned (is_deleted field_version exists),
/// a subsequent field update should NOT resurrect the entity.
#[test]
fn test_tombstone_prevents_resurrection() {
    let schema = test_schema();
    let merge = MergeEngine::new(schema);

    // is_deleted=true is already the winning field version
    let hlc_delete = Hlc::new(5000, 0, "dev-deleter");
    let get_fv = |_sync_id: &str,
                  _table: &str,
                  _eid: &str,
                  field: &str|
     -> prism_sync_core::Result<Option<FieldVersion>> {
        if field == "is_deleted" {
            Ok(Some(FieldVersion {
                sync_id: SYNC_ID.to_string(),
                entity_table: "tasks".to_string(),
                entity_id: "t-dead".to_string(),
                field_name: "is_deleted".to_string(),
                winning_op_id: "delete-op".to_string(),
                winning_device_id: "dev-deleter".to_string(),
                winning_hlc: hlc_delete.to_string(),
                winning_encoded_value: Some("true".to_string()),
                updated_at: chrono::Utc::now(),
            }))
        } else {
            Ok(None)
        }
    };

    // Even with a very high HLC, a title update should be rejected
    let hlc_update = Hlc::new(9999, 0, "dev-updater");
    let ops =
        vec![make_op("t-dead", "title", "\"Resurrected!\"", &hlc_update, "dev-updater", None)];

    let winners = merge.determine_winners(&ops, &get_fv, &no_ops_applied, SYNC_ID).unwrap();

    assert!(winners.is_empty(), "title update on tombstoned entity should be rejected");
}

/// A delete op on a tombstoned entity IS allowed (e.g. re-confirming deletion
/// with a higher HLC).
#[test]
fn test_delete_op_allowed_on_tombstoned_entity() {
    let schema = test_schema();
    let merge = MergeEngine::new(schema);

    let hlc_old_delete = Hlc::new(5000, 0, "dev-deleter");
    let get_fv = |_sync_id: &str,
                  _table: &str,
                  _eid: &str,
                  field: &str|
     -> prism_sync_core::Result<Option<FieldVersion>> {
        if field == "is_deleted" {
            Ok(Some(FieldVersion {
                sync_id: SYNC_ID.to_string(),
                entity_table: "tasks".to_string(),
                entity_id: "t-dead".to_string(),
                field_name: "is_deleted".to_string(),
                winning_op_id: "old-delete-op".to_string(),
                winning_device_id: "dev-deleter".to_string(),
                winning_hlc: hlc_old_delete.to_string(),
                winning_encoded_value: Some("true".to_string()),
                updated_at: chrono::Utc::now(),
            }))
        } else {
            Ok(None)
        }
    };

    // New delete with higher HLC should still be accepted
    let hlc_new_delete = Hlc::new(8000, 0, "dev-other");
    let ops = vec![make_delete_op("t-dead", &hlc_new_delete, "dev-other")];

    let winners = merge.determine_winners(&ops, &get_fv, &no_ops_applied, SYNC_ID).unwrap();

    assert_eq!(winners.len(), 1, "newer delete op should win over old delete");
}

// ═══════════════════════════════════════════════════════════════════════════
// 8. Empty string vs null value conflict
// ═══════════════════════════════════════════════════════════════════════════

/// Empty string and null are distinct values; the later HLC should win
/// regardless of the value.
#[test]
fn test_empty_string_vs_null_later_hlc_wins() {
    let schema = test_schema();
    let merge = MergeEngine::new(schema);

    let hlc_null = Hlc::new(1000, 0, "dev-a");
    let hlc_empty = Hlc::new(2000, 0, "dev-b");

    let ops = vec![
        make_op("t1", "title", "null", &hlc_null, "dev-a", None),
        make_op("t1", "title", "\"\"", &hlc_empty, "dev-b", None),
    ];

    let winners =
        merge.determine_winners(&ops, &no_field_versions, &no_ops_applied, SYNC_ID).unwrap();

    assert_eq!(winners.len(), 1);
    let winner = winners.values().next().unwrap();
    assert_eq!(winner.op.encoded_value, "\"\"", "later HLC (empty string) should win over null");
}

/// Null value with higher HLC wins over empty string with lower HLC.
#[test]
fn test_null_wins_over_empty_string_with_later_hlc() {
    let schema = test_schema();
    let merge = MergeEngine::new(schema);

    let hlc_empty = Hlc::new(1000, 0, "dev-a");
    let hlc_null = Hlc::new(2000, 0, "dev-b");

    let ops = vec![
        make_op("t1", "title", "\"\"", &hlc_empty, "dev-a", None),
        make_op("t1", "title", "null", &hlc_null, "dev-b", None),
    ];

    let winners =
        merge.determine_winners(&ops, &no_field_versions, &no_ops_applied, SYNC_ID).unwrap();

    assert_eq!(winners.len(), 1);
    let winner = winners.values().next().unwrap();
    assert_eq!(winner.op.encoded_value, "null", "later HLC (null) should win over empty string");
}

// ═══════════════════════════════════════════════════════════════════════════
// 9. Rapid successive writes from same device (counter increment)
// ═══════════════════════════════════════════════════════════════════════════

/// Multiple rapid writes from the same device should use HLC counter
/// to order them, with the highest counter winning.
#[test]
fn test_rapid_successive_writes_counter_ordering() {
    let schema = test_schema();
    let merge = MergeEngine::new(schema);

    let same_ts = 5000i64;
    // Simulates rapid writes where wall clock doesn't advance
    let hlc_0 = Hlc::new(same_ts, 0, "dev-fast");
    let hlc_1 = Hlc::new(same_ts, 1, "dev-fast");
    let hlc_2 = Hlc::new(same_ts, 2, "dev-fast");
    let hlc_3 = Hlc::new(same_ts, 3, "dev-fast");

    let ops = vec![
        make_op("t1", "title", "\"First\"", &hlc_0, "dev-fast", Some("op-0")),
        make_op("t1", "title", "\"Second\"", &hlc_1, "dev-fast", Some("op-1")),
        make_op("t1", "title", "\"Third\"", &hlc_2, "dev-fast", Some("op-2")),
        make_op("t1", "title", "\"Fourth\"", &hlc_3, "dev-fast", Some("op-3")),
    ];

    let winners =
        merge.determine_winners(&ops, &no_field_versions, &no_ops_applied, SYNC_ID).unwrap();

    assert_eq!(winners.len(), 1);
    let winner = winners.values().next().unwrap();
    assert_eq!(winner.op.encoded_value, "\"Fourth\"", "highest counter should win");
    assert_eq!(winner.op.client_hlc, hlc_3.to_string());
}

// ═══════════════════════════════════════════════════════════════════════════
// 10. Idempotency — already-applied ops are skipped
// ═══════════════════════════════════════════════════════════════════════════

/// Ops that have already been applied should be skipped entirely.
#[test]
fn test_already_applied_ops_skipped() {
    let schema = test_schema();
    let merge = MergeEngine::new(schema);

    let hlc = Hlc::new(5000, 0, "dev-a");
    let ops = vec![make_op("t1", "title", "\"Hello\"", &hlc, "dev-a", Some("already-done"))];

    let is_applied = |op_id: &str| -> prism_sync_core::Result<bool> { Ok(op_id == "already-done") };

    let winners = merge.determine_winners(&ops, &no_field_versions, &is_applied, SYNC_ID).unwrap();

    assert!(winners.is_empty(), "already-applied op should be skipped");
}

// ═══════════════════════════════════════════════════════════════════════════
// 11. Unknown table/field ops are skipped
// ═══════════════════════════════════════════════════════════════════════════

/// Ops targeting unknown tables should be silently skipped.
#[test]
fn test_unknown_table_ops_skipped() {
    let schema = test_schema();
    let merge = MergeEngine::new(schema);

    let hlc = Hlc::new(5000, 0, "dev-a");
    let mut op = make_op("t1", "title", "\"Hello\"", &hlc, "dev-a", None);
    op.entity_table = "nonexistent_table".to_string();

    let winners =
        merge.determine_winners(&[op], &no_field_versions, &no_ops_applied, SYNC_ID).unwrap();

    assert!(winners.is_empty(), "op for unknown table should be skipped");
}

/// Ops targeting unknown fields should be silently skipped.
#[test]
fn test_unknown_field_ops_skipped() {
    let schema = test_schema();
    let merge = MergeEngine::new(schema);

    let hlc = Hlc::new(5000, 0, "dev-a");
    let op = make_op("t1", "nonexistent_field", "\"Hello\"", &hlc, "dev-a", None);

    let winners =
        merge.determine_winners(&[op], &no_field_versions, &no_ops_applied, SYNC_ID).unwrap();

    assert!(winners.is_empty(), "op for unknown field should be skipped");
}

// ═══════════════════════════════════════════════════════════════════════════
// 12. Multiple entities in same batch — independent resolution
// ═══════════════════════════════════════════════════════════════════════════

/// Conflicts on different entities should be resolved independently.
#[test]
fn test_multiple_entities_resolved_independently() {
    let schema = test_schema();
    let merge = MergeEngine::new(schema);

    let hlc_a_early = Hlc::new(1000, 0, "dev-a");
    let hlc_b_late = Hlc::new(2000, 0, "dev-b");
    let hlc_a_late = Hlc::new(3000, 0, "dev-a");
    let hlc_b_early = Hlc::new(500, 0, "dev-b");

    let ops = vec![
        // Entity t1: dev-b's write at HLC 2000 should win
        make_op("t1", "title", "\"T1-DevA\"", &hlc_a_early, "dev-a", None),
        make_op("t1", "title", "\"T1-DevB\"", &hlc_b_late, "dev-b", None),
        // Entity t2: dev-a's write at HLC 3000 should win
        make_op("t2", "title", "\"T2-DevA\"", &hlc_a_late, "dev-a", None),
        make_op("t2", "title", "\"T2-DevB\"", &hlc_b_early, "dev-b", None),
    ];

    let winners =
        merge.determine_winners(&ops, &no_field_versions, &no_ops_applied, SYNC_ID).unwrap();

    assert_eq!(winners.len(), 2, "one winner per entity");

    let winner_values: HashMap<String, String> =
        winners.values().map(|w| (w.op.entity_id.clone(), w.op.encoded_value.clone())).collect();

    assert_eq!(winner_values["t1"], "\"T1-DevB\"", "t1: dev-b with HLC 2000 wins");
    assert_eq!(winner_values["t2"], "\"T2-DevA\"", "t2: dev-a with HLC 3000 wins");
}

// ═══════════════════════════════════════════════════════════════════════════
// 13. Full integration: concurrent writes from two devices through sync
// ═══════════════════════════════════════════════════════════════════════════

/// Full engine integration test: Device A has a local write, Device B sends
/// a conflicting write through the relay. The higher HLC should win and
/// be reflected in the entity store.
#[tokio::test]
async fn test_full_sync_concurrent_write_conflict() {
    let key_hierarchy = init_key_hierarchy();
    let signing_key_local = make_signing_key();
    let signing_key_remote = make_signing_key();
    let ml_dsa_key_remote = make_ml_dsa_keypair();
    let local_device = "device-local";
    let remote_device = "device-remote";

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity = Arc::new(MockTaskEntity::new());
    let entity_ref: Arc<dyn SyncableEntity> = entity.clone();

    setup_sync_metadata(&storage, local_device);
    register_device(&relay, &storage, local_device, &signing_key_local.verifying_key());
    register_device_with_pq(
        &relay,
        &storage,
        remote_device,
        &signing_key_remote.verifying_key(),
        &ml_dsa_key_remote.public_key_bytes(),
    );

    // Local device has title="Local" at HLC 1000
    let hlc_local = Hlc::new(1000, 0, local_device);
    {
        let mut tx = storage.begin_tx().unwrap();
        tx.upsert_field_version(&FieldVersion {
            sync_id: SYNC_ID.to_string(),
            entity_table: "tasks".to_string(),
            entity_id: "t-concurrent".to_string(),
            field_name: "title".to_string(),
            winning_op_id: "local-op".to_string(),
            winning_device_id: local_device.to_string(),
            winning_hlc: hlc_local.to_string(),
            winning_encoded_value: None,
            updated_at: chrono::Utc::now(),
        })
        .unwrap();
        tx.commit().unwrap();
    }

    // Remote sends title="Remote" at HLC 5000 (higher — should win)
    let hlc_remote = Hlc::new(5000, 0, remote_device);
    let remote_ops =
        vec![make_op("t-concurrent", "title", "\"Remote Wins\"", &hlc_remote, remote_device, None)];

    let envelope = make_encrypted_batch(
        &remote_ops,
        &key_hierarchy,
        &signing_key_remote,
        &ml_dsa_key_remote,
        "batch-remote",
        remote_device,
    );
    relay.inject_batch(envelope);

    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity_ref],
        test_schema(),
        SyncConfig::default(),
    );

    let result = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key_local, None, local_device, 0)
        .await
        .unwrap();

    assert!(result.error.is_none(), "sync error: {:?}", result.error);
    assert_eq!(result.merged, 1);

    // Verify remote won
    let title = entity.get_field("t-concurrent", "title");
    assert_eq!(
        title,
        Some(SyncValue::String("Remote Wins".to_string())),
        "remote with higher HLC should win"
    );

    // Verify field_version updated
    let fv = storage
        .get_field_version(SYNC_ID, "tasks", "t-concurrent", "title")
        .unwrap()
        .expect("field_version should exist");
    assert_eq!(fv.winning_device_id, remote_device);
    assert_eq!(fv.winning_hlc, hlc_remote.to_string());
}

/// Full engine integration: remote writes a different field than the local
/// one — both should coexist without conflict.
#[tokio::test]
async fn test_full_sync_different_fields_no_conflict() {
    let key_hierarchy = init_key_hierarchy();
    let signing_key_local = make_signing_key();
    let signing_key_remote = make_signing_key();
    let ml_dsa_key_remote = make_ml_dsa_keypair();
    let local_device = "device-local";
    let remote_device = "device-remote";

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity = Arc::new(MockTaskEntity::new());
    let entity_ref: Arc<dyn SyncableEntity> = entity.clone();

    setup_sync_metadata(&storage, local_device);
    register_device(&relay, &storage, local_device, &signing_key_local.verifying_key());
    register_device_with_pq(
        &relay,
        &storage,
        remote_device,
        &signing_key_remote.verifying_key(),
        &ml_dsa_key_remote.public_key_bytes(),
    );

    // Local has title field
    let hlc_local = Hlc::new(1000, 0, local_device);
    {
        let mut tx = storage.begin_tx().unwrap();
        tx.upsert_field_version(&FieldVersion {
            sync_id: SYNC_ID.to_string(),
            entity_table: "tasks".to_string(),
            entity_id: "t-dual".to_string(),
            field_name: "title".to_string(),
            winning_op_id: "local-title-op".to_string(),
            winning_device_id: local_device.to_string(),
            winning_hlc: hlc_local.to_string(),
            winning_encoded_value: None,
            updated_at: chrono::Utc::now(),
        })
        .unwrap();
        tx.commit().unwrap();
    }

    // Remote writes "done" field (different field — no conflict)
    let hlc_remote = Hlc::new(2000, 0, remote_device);
    let remote_ops = vec![make_op("t-dual", "done", "true", &hlc_remote, remote_device, None)];

    let envelope = make_encrypted_batch(
        &remote_ops,
        &key_hierarchy,
        &signing_key_remote,
        &ml_dsa_key_remote,
        "batch-done",
        remote_device,
    );
    relay.inject_batch(envelope);

    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity_ref],
        test_schema(),
        SyncConfig::default(),
    );

    let result = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key_local, None, local_device, 0)
        .await
        .unwrap();

    assert!(result.error.is_none(), "sync error: {:?}", result.error);
    assert_eq!(result.merged, 1);

    // Verify "done" was written without disturbing "title"
    let done = entity.get_field("t-dual", "done");
    assert_eq!(done, Some(SyncValue::Bool(true)));

    // Title field_version should still reflect local device
    let fv_title = storage
        .get_field_version(SYNC_ID, "tasks", "t-dual", "title")
        .unwrap()
        .expect("title field_version should still exist");
    assert_eq!(fv_title.winning_device_id, local_device);
}

// ═══════════════════════════════════════════════════════════════════════════
// 14. Incoming op equal to current winner — no change (not "wins")
// ═══════════════════════════════════════════════════════════════════════════

/// When an incoming op has the exact same HLC, device_id, and op_id as the
/// current winner, `wins_over` returns false (equal is NOT greater), so
/// it should be skipped.
#[test]
fn test_equal_op_does_not_win() {
    let schema = test_schema();
    let merge = MergeEngine::new(schema);

    let hlc = Hlc::new(5000, 0, "dev-a");
    let ops = vec![make_op("t1", "title", "\"Hello\"", &hlc, "dev-a", Some("same-op"))];

    // Persisted field version has exactly the same HLC and device
    let get_fv = |_sync_id: &str,
                  _table: &str,
                  _eid: &str,
                  field: &str|
     -> prism_sync_core::Result<Option<FieldVersion>> {
        if field == "title" {
            Ok(Some(FieldVersion {
                sync_id: SYNC_ID.to_string(),
                entity_table: "tasks".to_string(),
                entity_id: "t1".to_string(),
                field_name: "title".to_string(),
                winning_op_id: "same-op".to_string(),
                winning_device_id: "dev-a".to_string(),
                winning_hlc: hlc.to_string(),
                winning_encoded_value: None,
                updated_at: chrono::Utc::now(),
            }))
        } else {
            Ok(None)
        }
    };

    let winners = merge.determine_winners(&ops, &get_fv, &no_ops_applied, SYNC_ID).unwrap();

    // The op doesn't strictly win (equal is not greater), but it won't be
    // skipped by idempotency check since we're using no_ops_applied.
    // The merge engine's wins_over returns false for equal, so the op is skipped.
    assert!(winners.is_empty(), "equal op should not win over existing field version");
}

// ═══════════════════════════════════════════════════════════════════════════
// 15. HLC node_id tiebreaker (same timestamp and counter, different node_id)
// ═══════════════════════════════════════════════════════════════════════════

/// Same timestamp and counter but different HLC node_ids — the lexicographically
/// greater node_id wins via HLC comparison (before device_id is even checked).
#[test]
fn test_hlc_node_id_tiebreaker() {
    let schema = test_schema();
    let merge = MergeEngine::new(schema);

    // Same timestamp and counter, different node_ids in HLC.
    // Both ops share the same device_id so the device_id tiebreaker is irrelevant.
    let hlc_a = Hlc::new(5000, 0, "node-a");
    let hlc_b = Hlc::new(5000, 0, "node-b");

    let ops = vec![
        make_op("t1", "title", "\"NodeA\"", &hlc_a, "same-device", None),
        make_op("t1", "title", "\"NodeB\"", &hlc_b, "same-device", None),
    ];

    let winners =
        merge.determine_winners(&ops, &no_field_versions, &no_ops_applied, SYNC_ID).unwrap();

    assert_eq!(winners.len(), 1);
    let winner = winners.values().next().unwrap();
    // "node-b" > "node-a" lexicographically, so HLC with node-b wins
    assert_eq!(winner.op.encoded_value, "\"NodeB\"");
}

// ═══════════════════════════════════════════════════════════════════════════
// 16. Lower-HLC delete loses against existing tombstone
// ═══════════════════════════════════════════════════════════════════════════

/// When an entity is already tombstoned at HLC 5000 and a delete op arrives
/// with a LOWER HLC (3000), the incoming delete should lose (empty winners).
#[test]
fn test_lower_hlc_delete_loses_against_existing_tombstone() {
    let schema = test_schema();
    let merge = MergeEngine::new(schema);

    let hlc_existing_delete = Hlc::new(5000, 0, "dev-deleter");
    let get_fv = |_sync_id: &str,
                  _table: &str,
                  _eid: &str,
                  field: &str|
     -> prism_sync_core::Result<Option<FieldVersion>> {
        if field == "is_deleted" {
            Ok(Some(FieldVersion {
                sync_id: SYNC_ID.to_string(),
                entity_table: "tasks".to_string(),
                entity_id: "t-dead".to_string(),
                field_name: "is_deleted".to_string(),
                winning_op_id: "existing-delete-op".to_string(),
                winning_device_id: "dev-deleter".to_string(),
                winning_hlc: hlc_existing_delete.to_string(),
                winning_encoded_value: Some("true".to_string()),
                updated_at: chrono::Utc::now(),
            }))
        } else {
            Ok(None)
        }
    };

    // Incoming delete with LOWER HLC — should lose
    let hlc_late_delete = Hlc::new(3000, 0, "dev-other");
    let ops = vec![make_delete_op("t-dead", &hlc_late_delete, "dev-other")];

    let winners = merge.determine_winners(&ops, &get_fv, &no_ops_applied, SYNC_ID).unwrap();

    assert!(winners.is_empty(), "lower-HLC delete should lose against existing tombstone");
}

// ═══════════════════════════════════════════════════════════════════════════
// 17. Un-deleted entity allows subsequent field updates
// ═══════════════════════════════════════════════════════════════════════════

/// When an entity was un-deleted (is_deleted field_version has winning_encoded_value
/// "false"), subsequent field updates should NOT be blocked by tombstone protection.
#[test]
fn test_undeleted_entity_allows_field_updates() {
    let schema = test_schema();
    let merge = MergeEngine::new(schema);

    let hlc_undelete = Hlc::new(5000, 0, "dev-undeleter");
    let get_fv = |_sync_id: &str,
                  _table: &str,
                  _eid: &str,
                  field: &str|
     -> prism_sync_core::Result<Option<FieldVersion>> {
        if field == "is_deleted" {
            // Entity was un-deleted: is_deleted field version exists with value "false"
            Ok(Some(FieldVersion {
                sync_id: SYNC_ID.to_string(),
                entity_table: "tasks".to_string(),
                entity_id: "t-revived".to_string(),
                field_name: "is_deleted".to_string(),
                winning_op_id: "undelete-op".to_string(),
                winning_device_id: "dev-undeleter".to_string(),
                winning_hlc: hlc_undelete.to_string(),
                winning_encoded_value: Some("false".to_string()),
                updated_at: chrono::Utc::now(),
            }))
        } else {
            Ok(None)
        }
    };

    // Field update on the un-deleted entity should be accepted
    let hlc_update = Hlc::new(6000, 0, "dev-updater");
    let ops =
        vec![make_op("t-revived", "title", "\"Alive Again\"", &hlc_update, "dev-updater", None)];

    let winners = merge.determine_winners(&ops, &get_fv, &no_ops_applied, SYNC_ID).unwrap();

    assert_eq!(winners.len(), 1, "field update on un-deleted entity should be accepted");
    let winner = winners.values().next().unwrap();
    assert_eq!(winner.op.encoded_value, "\"Alive Again\"");
}
