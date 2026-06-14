//! Integration tests for the SyncEngine pull -> merge -> push cycle.
//!
//! These tests exercise the full sync pipeline using:
//! - `RusqliteSyncStorage::in_memory()` for local sync state
//! - `MockRelay` for the relay transport
//! - A `MockTaskEntity` implementing `SyncableEntity` backed by a `HashMap`
//! - Real `KeyHierarchy` and `Ed25519` signing keys for crypto

mod common;

use std::sync::Arc;

use ed25519_dalek::SigningKey;

use prism_sync_core::engine::{SyncConfig, SyncEngine, SyncResult};
use prism_sync_core::events::SyncEvent;
use prism_sync_core::relay::{
    InjectedPullError, MockRelay, SignedBatchEnvelope, SnapshotExchange, SyncTransport,
};
use prism_sync_core::schema::{SyncSchema, SyncType, SyncValue};
use prism_sync_core::storage::{
    AppliedOpEntry, DeviceRegistryEntry, FieldVersionEntry, RusqliteSyncStorage, SnapshotData,
    SyncMetadataEntry, SyncStorage, SNAPSHOT_VERSION,
};
use prism_sync_core::syncable_entity::SyncableEntity;
use prism_sync_core::{batch_signature, sync_aad, CoreError, CrdtChange, Hlc};

use common::*;

// ═══════════════════════════════════════════════════════════════════════════
// Test-file-specific helpers
// ═══════════════════════════════════════════════════════════════════════════

/// Create a signed + encrypted batch envelope from CrdtChange ops.
fn make_encrypted_batch(
    ops: &[CrdtChange],
    key_hierarchy: &prism_sync_crypto::KeyHierarchy,
    signing_key: &SigningKey,
    ml_dsa_signing_key: &prism_sync_crypto::DevicePqSigningKey,
    batch_id: &str,
    sender_device_id: &str,
) -> SignedBatchEnvelope {
    make_encrypted_batch_with_generation(
        ops,
        key_hierarchy,
        signing_key,
        ml_dsa_signing_key,
        batch_id,
        sender_device_id,
        0,
    )
}

fn make_encrypted_batch_with_generation(
    ops: &[CrdtChange],
    key_hierarchy: &prism_sync_crypto::KeyHierarchy,
    signing_key: &SigningKey,
    ml_dsa_signing_key: &prism_sync_crypto::DevicePqSigningKey,
    batch_id: &str,
    sender_device_id: &str,
    sender_ml_dsa_key_generation: u32,
) -> SignedBatchEnvelope {
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
        sender_ml_dsa_key_generation,
        &payload_hash,
        nonce,
        ciphertext,
    )
    .unwrap()
}

/// Build a signed + encrypted batch at an explicit epoch, using `epoch_key` for
/// the AEAD. Mirrors `make_encrypted_batch_with_generation` but lets a test
/// produce a batch at an epoch the *receiver* does not yet hold.
fn make_encrypted_batch_at_epoch(
    ops: &[CrdtChange],
    epoch_key: &[u8; 32],
    epoch: i32,
    signing_key: &SigningKey,
    ml_dsa_signing_key: &prism_sync_crypto::DevicePqSigningKey,
    batch_id: &str,
    sender_device_id: &str,
) -> SignedBatchEnvelope {
    let plaintext = CrdtChange::encode_batch(ops).unwrap();
    let payload_hash = batch_signature::compute_payload_hash(&plaintext);
    let aad = sync_aad::build_sync_aad(SYNC_ID, sender_device_id, epoch, batch_id, "ops");
    let (ciphertext, nonce) =
        prism_sync_crypto::aead::xchacha_encrypt_for_sync(epoch_key, &plaintext, &aad).unwrap();

    batch_signature::sign_batch(
        signing_key,
        ml_dsa_signing_key,
        SYNC_ID,
        epoch,
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

fn make_snapshot_envelope_bytes(
    snapshot: &SnapshotData,
    key_hierarchy: &prism_sync_crypto::KeyHierarchy,
    signing_key: &SigningKey,
    ml_dsa_signing_key: &prism_sync_crypto::DevicePqSigningKey,
    batch_id: &str,
    sender_device_id: &str,
    server_seq_at: i64,
) -> Vec<u8> {
    let json = serde_json::to_vec(snapshot).unwrap();
    let compressed = zstd::encode_all(json.as_slice(), 3).unwrap();
    let payload_hash = batch_signature::compute_payload_hash(&compressed);
    let epoch_key = key_hierarchy.epoch_key(0).unwrap();
    let aad = sync_aad::build_snapshot_aad(
        SYNC_ID,
        sender_device_id,
        0,
        server_seq_at,
        batch_id,
        "snapshot",
    );
    let (ciphertext, nonce) =
        prism_sync_crypto::aead::xchacha_encrypt_for_sync(epoch_key, &compressed, &aad).unwrap();

    let envelope = batch_signature::sign_batch(
        signing_key,
        ml_dsa_signing_key,
        SYNC_ID,
        0,
        batch_id,
        "snapshot",
        sender_device_id,
        0,
        &payload_hash,
        nonce,
        ciphertext,
    )
    .unwrap();

    serde_json::to_vec(&envelope).unwrap()
}

fn task_title_op(op_id: &str, device_id: &str, hlc_node_id: &str) -> CrdtChange {
    let hlc = Hlc::new(1_710_500_000_000, 0, hlc_node_id);
    CrdtChange {
        op_id: op_id.to_string(),
        batch_id: Some("batch-attribution".to_string()),
        entity_id: "task-attribution".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "title".to_string(),
        encoded_value: "\"Forged title\"".to_string(),
        client_hlc: hlc.to_string(),
        is_delete: false,
        device_id: device_id.to_string(),
        epoch: 0,
        server_seq: None,
    }
}

fn schema_with_future_field() -> SyncSchema {
    SyncSchema::builder()
        .entity("tasks", |e| {
            e.field("title", SyncType::String)
                .field("done", SyncType::Bool)
                .field("future_note", SyncType::String)
        })
        .build()
}

async fn pull_injected_sender_batch(
    ops: Vec<CrdtChange>,
) -> (SyncResult, Arc<RusqliteSyncStorage>, Arc<MockTaskEntity>) {
    pull_injected_sender_batch_with_config(ops, SyncConfig::default()).await
}

/// Like [`pull_injected_sender_batch`], but wires an event sink and drains every
/// emitted [`SyncEvent`] so quarantine/stall assertions can inspect them.
async fn pull_injected_sender_batch_capturing_events(
    ops: Vec<CrdtChange>,
) -> (SyncResult, Arc<RusqliteSyncStorage>, Arc<MockTaskEntity>, Vec<SyncEvent>) {
    let key_hierarchy = init_key_hierarchy();
    let signing_key_sender = make_signing_key();
    let ml_dsa_key_sender = make_ml_dsa_keypair();
    let signing_key_receiver = make_signing_key();
    let sender_id = "device-sender";
    let receiver_id = "device-receiver";

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity = Arc::new(MockTaskEntity::new());
    let entity_ref: Arc<dyn SyncableEntity> = entity.clone();

    setup_sync_metadata(&storage, receiver_id);
    register_device_with_pq(
        &relay,
        &storage,
        sender_id,
        &signing_key_sender.verifying_key(),
        &ml_dsa_key_sender.public_key_bytes(),
    );
    register_device(&relay, &storage, receiver_id, &signing_key_receiver.verifying_key());

    let envelope = make_encrypted_batch(
        &ops,
        &key_hierarchy,
        &signing_key_sender,
        &ml_dsa_key_sender,
        "batch-attribution",
        sender_id,
    );
    relay.inject_batch(envelope);

    let (event_tx, mut event_rx) = tokio::sync::broadcast::channel::<SyncEvent>(64);
    let engine =
        SyncEngine::new(storage.clone(), relay, vec![entity_ref], test_schema(), SyncConfig::default())
            .with_event_sink(event_tx.clone());
    let result = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key_receiver, None, receiver_id, 0)
        .await
        .unwrap();

    let mut events = Vec::new();
    while let Ok(event) = event_rx.try_recv() {
        events.push(event);
    }

    (result, storage, entity, events)
}

async fn pull_injected_sender_batch_with_config(
    ops: Vec<CrdtChange>,
    config: SyncConfig,
) -> (SyncResult, Arc<RusqliteSyncStorage>, Arc<MockTaskEntity>) {
    let key_hierarchy = init_key_hierarchy();
    let signing_key_sender = make_signing_key();
    let ml_dsa_key_sender = make_ml_dsa_keypair();
    let signing_key_receiver = make_signing_key();
    let sender_id = "device-sender";
    let receiver_id = "device-receiver";

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity = Arc::new(MockTaskEntity::new());
    let entity_ref: Arc<dyn SyncableEntity> = entity.clone();

    setup_sync_metadata(&storage, receiver_id);
    register_device_with_pq(
        &relay,
        &storage,
        sender_id,
        &signing_key_sender.verifying_key(),
        &ml_dsa_key_sender.public_key_bytes(),
    );
    register_device(&relay, &storage, receiver_id, &signing_key_receiver.verifying_key());

    let envelope = make_encrypted_batch(
        &ops,
        &key_hierarchy,
        &signing_key_sender,
        &ml_dsa_key_sender,
        "batch-attribution",
        sender_id,
    );
    relay.inject_batch(envelope);

    let engine = SyncEngine::new(storage.clone(), relay, vec![entity_ref], test_schema(), config);
    let result = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key_receiver, None, receiver_id, 0)
        .await
        .unwrap();

    (result, storage, entity)
}

fn current_time_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64
}

fn snapshot_device_entry(
    device_id: &str,
    verifying_key: &ed25519_dalek::VerifyingKey,
    ml_dsa_pk: &[u8],
) -> DeviceRegistryEntry {
    DeviceRegistryEntry {
        device_id: device_id.to_string(),
        ed25519_public_key: hex::encode(verifying_key.to_bytes()),
        x25519_public_key: hex::encode([0u8; 32]),
        ml_dsa_65_public_key: hex::encode(ml_dsa_pk),
        ml_kem_768_public_key: String::new(),
        x_wing_public_key: String::new(),
        status: "active".to_string(),
        registered_at: "2024-03-15T00:00:00Z".to_string(),
        revoked_at: None,
        ml_dsa_key_generation: 0,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Pull-to-head paging
// ═══════════════════════════════════════════════════════════════════════════

/// A backlog larger than one page must drain to head within a single sync
/// cycle. With `pull_page_limit = 2` and 5 batches, the loop pages 2 + 2 + 1
/// (a short final page signals "caught up"). The pre-fix single-pull behaviour
/// — or the buggy `last_pulled < max_server_seq` loop condition, where
/// `max_server_seq` is only the page max — would stop after the first 2.
#[tokio::test]
async fn pull_to_head_drains_backlog_larger_than_one_page() {
    let key_hierarchy = init_key_hierarchy();
    let signing_key_sender = make_signing_key();
    let ml_dsa_key_sender = make_ml_dsa_keypair();
    let signing_key_receiver = make_signing_key();
    let sender_id = "device-sender";
    let receiver_id = "device-receiver";

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity = Arc::new(MockTaskEntity::new());
    let entity_ref: Arc<dyn SyncableEntity> = entity.clone();

    setup_sync_metadata(&storage, receiver_id);
    register_device_with_pq(
        &relay,
        &storage,
        sender_id,
        &signing_key_sender.verifying_key(),
        &ml_dsa_key_sender.public_key_bytes(),
    );
    register_device(&relay, &storage, receiver_id, &signing_key_receiver.verifying_key());

    const N: usize = 5;
    for i in 0..N {
        // Distinct op_id / batch_id / entity_id per batch so all five apply.
        let hlc = Hlc::new(1_710_500_000_000 + i as i64, 0, sender_id);
        let op = CrdtChange {
            op_id: format!("op-{i}"),
            batch_id: Some(format!("batch-{i}")),
            entity_id: format!("task-{i}"),
            entity_table: "tasks".to_string(),
            field_name: "title".to_string(),
            encoded_value: "\"hi\"".to_string(),
            client_hlc: hlc.to_string(),
            is_delete: false,
            device_id: sender_id.to_string(),
            epoch: 0,
            server_seq: None,
        };
        let envelope = make_encrypted_batch(
            std::slice::from_ref(&op),
            &key_hierarchy,
            &signing_key_sender,
            &ml_dsa_key_sender,
            &format!("batch-{i}"),
            sender_id,
        );
        relay.inject_batch(envelope);
    }

    let config = SyncConfig { pull_page_limit: 2, ..Default::default() };
    let engine =
        SyncEngine::new(storage.clone(), relay.clone(), vec![entity_ref], test_schema(), config);
    let result = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key_receiver, None, receiver_id, 0)
        .await
        .unwrap();

    assert_eq!(result.pulled, N as u64, "every batch should drain to head in one cycle");
    assert_eq!(relay.pull_call_count(), 3, "5 batches @ page size 2 => 3 pull calls (2+2+1)");
    for i in 0..N {
        assert!(storage.is_op_applied(&format!("op-{i}")).unwrap(), "op-{i} should be applied");
    }
}

/// The pull-to-head loop stops at its per-cycle page budget rather than
/// monopolising one cycle; the cursor advances so the next cycle resumes. With
/// `pull_page_limit = 1` and `max_pull_pages_per_cycle = 3`, 5 batches drain as
/// 3 (budget) then 2 — not 5 in one cycle.
#[tokio::test]
async fn pull_to_head_stops_at_per_cycle_page_budget() {
    let key_hierarchy = init_key_hierarchy();
    let signing_key_sender = make_signing_key();
    let ml_dsa_key_sender = make_ml_dsa_keypair();
    let signing_key_receiver = make_signing_key();
    let sender_id = "device-sender";
    let receiver_id = "device-receiver";

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity = Arc::new(MockTaskEntity::new());
    let entity_ref: Arc<dyn SyncableEntity> = entity.clone();

    setup_sync_metadata(&storage, receiver_id);
    register_device_with_pq(
        &relay,
        &storage,
        sender_id,
        &signing_key_sender.verifying_key(),
        &ml_dsa_key_sender.public_key_bytes(),
    );
    register_device(&relay, &storage, receiver_id, &signing_key_receiver.verifying_key());

    const N: usize = 5;
    for i in 0..N {
        let hlc = Hlc::new(1_710_500_000_000 + i as i64, 0, sender_id);
        let op = CrdtChange {
            op_id: format!("budget-op-{i}"),
            batch_id: Some(format!("budget-batch-{i}")),
            entity_id: format!("budget-task-{i}"),
            entity_table: "tasks".to_string(),
            field_name: "title".to_string(),
            encoded_value: "\"hi\"".to_string(),
            client_hlc: hlc.to_string(),
            is_delete: false,
            device_id: sender_id.to_string(),
            epoch: 0,
            server_seq: None,
        };
        let envelope = make_encrypted_batch(
            std::slice::from_ref(&op),
            &key_hierarchy,
            &signing_key_sender,
            &ml_dsa_key_sender,
            &format!("budget-batch-{i}"),
            sender_id,
        );
        relay.inject_batch(envelope);
    }

    // One batch per page, budget of 3 pages per cycle.
    let config =
        SyncConfig { pull_page_limit: 1, max_pull_pages_per_cycle: 3, ..Default::default() };
    let engine =
        SyncEngine::new(storage.clone(), relay.clone(), vec![entity_ref], test_schema(), config);

    // Cycle 1: stops at the 3-page budget with batches still on the relay.
    let r1 = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key_receiver, None, receiver_id, 0)
        .await
        .unwrap();
    assert_eq!(r1.pulled, 3, "first cycle stops at the page budget (3), not the full 5");

    // Cycle 2: cursor advanced, so it resumes and drains the remaining 2.
    let r2 = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key_receiver, None, receiver_id, 0)
        .await
        .unwrap();
    assert_eq!(r2.pulled, 2, "second cycle drains the remainder");
    for i in 0..N {
        assert!(storage.is_op_applied(&format!("budget-op-{i}")).unwrap(), "budget-op-{i} applied");
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Attribution binding regressions
// ═══════════════════════════════════════════════════════════════════════════

/// A batch whose op device_id mismatches the envelope sender is a poison
/// batch — fail-closed on apply, but it must NOT wedge pull (whole-batch
/// quarantine + cursor advance + event), unlike the older hard-Err that froze
/// the cursor and the push phase on the same seq forever.
#[tokio::test]
async fn quarantines_entire_batch_when_op_device_id_differs_from_envelope_sender() {
    let sender_id = "device-sender";
    let good = task_title_op("op-good", sender_id, sender_id);
    let bad = CrdtChange {
        op_id: "op-bad-device".to_string(),
        field_name: "done".to_string(),
        encoded_value: "true".to_string(),
        ..task_title_op("op-bad-device", "device-forged", "device-forged")
    };

    let (result, storage, entity, events) =
        pull_injected_sender_batch_capturing_events(vec![good, bad]).await;

    assert!(result.error.is_none(), "poison batch must not surface a terminal error: {:?}", result.error);
    assert_eq!(result.merged, 0, "no op from the tainted batch may be applied");
    assert_eq!(entity.get_field("task-attribution", "title"), None);
    assert_eq!(entity.get_field("task-attribution", "done"), None);
    assert_eq!(
        storage.get_sync_metadata(SYNC_ID).unwrap().unwrap().last_pulled_server_seq,
        1,
        "quarantined batch must advance the pull cursor so the group is not wedged"
    );

    let quarantined = storage.list_quarantined_pull_batches(SYNC_ID).unwrap();
    assert_eq!(quarantined.len(), 1);
    assert_eq!(quarantined[0].reason, "attribution_mismatch");
    assert_eq!(quarantined[0].server_seq, 1);
    assert_eq!(quarantined[0].sender_device_id, sender_id);

    assert!(
        events.iter().any(|e| matches!(
            e,
            SyncEvent::PullBatchQuarantined { reason, .. } if reason == "attribution_mismatch"
        )),
        "expected a PullBatchQuarantined event for the attribution mismatch"
    );
}

/// Same fail-open-on-availability discipline for an HLC-node mismatch.
#[tokio::test]
async fn quarantines_batch_when_op_hlc_node_differs_from_envelope_sender() {
    let sender_id = "device-sender";
    let op = task_title_op("op-bad-hlc", sender_id, "device-forged");

    let (result, storage, entity, events) =
        pull_injected_sender_batch_capturing_events(vec![op]).await;

    assert!(result.error.is_none(), "{:?}", result.error);
    assert_eq!(result.merged, 0);
    assert_eq!(entity.get_field("task-attribution", "title"), None);
    assert_eq!(
        storage.get_sync_metadata(SYNC_ID).unwrap().unwrap().last_pulled_server_seq,
        1,
        "quarantined batch must advance the pull cursor"
    );

    let quarantined = storage.list_quarantined_pull_batches(SYNC_ID).unwrap();
    assert_eq!(quarantined.len(), 1);
    assert_eq!(quarantined[0].reason, "attribution_mismatch");

    assert!(events.iter().any(|e| matches!(
        e,
        SyncEvent::PullBatchQuarantined { reason, .. } if reason == "attribution_mismatch"
    )));
}

// ═══════════════════════════════════════════════════════════════════════════
// Poison pull batches quarantine-and-advance (never wedge pull or push)
// ═══════════════════════════════════════════════════════════════════════════

/// Helper: build a validly-signed envelope whose declared payload_hash does not
/// match the encrypted plaintext (a poison/tampered batch).
fn make_hash_mismatched_batch(
    ops: &[CrdtChange],
    key_hierarchy: &prism_sync_crypto::KeyHierarchy,
    signing_key: &SigningKey,
    ml_dsa_signing_key: &prism_sync_crypto::DevicePqSigningKey,
    batch_id: &str,
    sender_device_id: &str,
) -> SignedBatchEnvelope {
    let plaintext = CrdtChange::encode_batch(ops).unwrap();
    let mut wrong_hash = batch_signature::compute_payload_hash(&plaintext);
    wrong_hash[0] ^= 0xff; // corrupt the declared hash
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
        &wrong_hash,
        nonce,
        ciphertext,
    )
    .unwrap()
}

/// Helper: build a validly-signed envelope whose decrypted plaintext is correct
/// against the declared payload_hash but is NOT a decodable CRDT batch (garbage
/// bytes). Models cross-version wire skew: signature + hash verify, but this
/// build's `decode_batch` cannot parse the plaintext.
fn make_undecodable_batch(
    plaintext: &[u8],
    key_hierarchy: &prism_sync_crypto::KeyHierarchy,
    signing_key: &SigningKey,
    ml_dsa_signing_key: &prism_sync_crypto::DevicePqSigningKey,
    batch_id: &str,
    sender_device_id: &str,
) -> SignedBatchEnvelope {
    // Hash is computed over the actual (garbage) plaintext, so verify_payload_hash
    // passes and the failure lands specifically on decode_batch.
    let payload_hash = batch_signature::compute_payload_hash(plaintext);
    let epoch_key = key_hierarchy.epoch_key(0).unwrap();
    let aad = sync_aad::build_sync_aad(SYNC_ID, sender_device_id, 0, batch_id, "ops");
    let (ciphertext, nonce) =
        prism_sync_crypto::aead::xchacha_encrypt_for_sync(epoch_key, plaintext, &aad).unwrap();
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

/// An undecodable batch (valid signature, valid payload_hash over garbage that
/// `decode_batch` rejects — the cross-version-skew case) is quarantined with
/// reason `decode_failed`, the cursor advances, the event fires, and a queued
/// local op still pushes (push not starved). Repeated immediate cycles do NOT
/// churn the cursor and bump retry_count exactly once per eligible replay.
///
/// NOTE: the plan's "replay applies after decoder upgrade" half is not covered
/// here — `CrdtChange::decode_batch` is a free static fn with no decoder seam, so
/// swapping in a decoder that accepts the garbage is impractical in a Rust unit
/// test. Tracked as a declared deviation; the quarantine half (the safety net
/// the commit message leans on) is what is exercised.
#[tokio::test]
async fn undecodable_batch_quarantined_with_decode_failed_reason() {
    let key_hierarchy = init_key_hierarchy();
    let signing_key_sender = make_signing_key();
    let ml_dsa_key_sender = make_ml_dsa_keypair();
    let signing_key_receiver = make_signing_key();
    let ml_dsa_key_receiver = make_ml_dsa_keypair();
    let sender_id = "device-sender";
    let receiver_id = "device-receiver";

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity = Arc::new(MockTaskEntity::new());
    let entity_ref: Arc<dyn SyncableEntity> = entity.clone();

    setup_sync_metadata(&storage, receiver_id);
    register_device_with_pq(
        &relay,
        &storage,
        sender_id,
        &signing_key_sender.verifying_key(),
        &ml_dsa_key_sender.public_key_bytes(),
    );
    register_device_with_pq(
        &relay,
        &storage,
        receiver_id,
        &signing_key_receiver.verifying_key(),
        &ml_dsa_key_receiver.public_key_bytes(),
    );

    // Seq 1: undecodable batch (binary garbage, not JSON).
    let garbage = b"\xff\xfe\x00\x01 this is not a CRDT batch \x80\x81";
    let poison = make_undecodable_batch(
        garbage,
        &key_hierarchy,
        &signing_key_sender,
        &ml_dsa_key_sender,
        "batch-undecodable",
        sender_id,
    );
    let poison_seq = relay.inject_batch(poison);

    // Seq 2: good batch — must apply past the poison one.
    let good_op = make_op(sender_id, "batch-good-remote", 0, "good-remote");
    let good = make_encrypted_batch(
        std::slice::from_ref(&good_op),
        &key_hierarchy,
        &signing_key_sender,
        &ml_dsa_key_sender,
        "batch-good-remote",
        sender_id,
    );
    let good_seq = relay.inject_batch(good);

    // A local op queued to push this same cycle (push-not-starved assertion).
    let local_op = make_op(receiver_id, "batch-local", 0, "local");
    insert_pending_ops(&storage, std::slice::from_ref(&local_op), "batch-local");

    let (event_tx, mut event_rx) =
        tokio::sync::broadcast::channel::<prism_sync_core::events::SyncEvent>(32);
    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity_ref],
        test_schema(),
        SyncConfig::default(),
    )
    .with_event_sink(event_tx.clone());

    let result = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key_receiver, Some(&ml_dsa_key_receiver), receiver_id, 0)
        .await
        .unwrap();

    assert!(result.error.is_none(), "no terminal error: {:?}", result.error);
    assert_eq!(result.merged, 1, "only the good batch applies");
    assert_eq!(
        entity.get_field("task-good-remote", "title"),
        Some(SyncValue::String("hello".into()))
    );

    assert_eq!(
        storage.get_sync_metadata(SYNC_ID).unwrap().unwrap().last_pulled_server_seq,
        good_seq,
        "cursor must advance past the undecodable batch to the good one"
    );

    let quarantined = storage.list_quarantined_pull_batches(SYNC_ID).unwrap();
    assert_eq!(quarantined.len(), 1);
    assert_eq!(quarantined[0].reason, "decode_failed");
    assert_eq!(quarantined[0].server_seq, poison_seq);
    assert_eq!(quarantined[0].retry_count, 0, "no replay has run yet");

    // Push not starved.
    assert_eq!(result.pushed, 1, "queued local op must still push despite the poison batch");
    assert!(relay.push_call_batch_ids().contains(&"batch-local".to_string()));

    let mut saw_event = false;
    while let Ok(event) = event_rx.try_recv() {
        if let prism_sync_core::events::SyncEvent::PullBatchQuarantined { reason, server_seq, .. } =
            event
        {
            if reason == "decode_failed" && server_seq == poison_seq {
                saw_event = true;
            }
        }
    }
    assert!(saw_event, "expected PullBatchQuarantined(decode_failed) event");

    // Cursor after cycle 1: at least the good batch's seq. (It may sit higher
    // because the receiver echoes back its own just-pushed local batch on a later
    // pull — that is not the poison batch being re-consumed.)
    let cursor_after_c1 =
        storage.get_sync_metadata(SYNC_ID).unwrap().unwrap().last_pulled_server_seq;
    assert!(cursor_after_c1 >= good_seq);

    // Second cycle (immediate, default backoff). The first Phase 0b replay is
    // always eligible, attempts decode, fails identically, and bumps retry_count
    // to 1 — without re-applying anything and without rewinding past the poison
    // batch (its quarantine row keeps its original server_seq).
    let r2 = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key_receiver, Some(&ml_dsa_key_receiver), receiver_id, 0)
        .await
        .unwrap();
    assert!(r2.error.is_none(), "{:?}", r2.error);
    let q2 = storage.list_quarantined_pull_batches(SYNC_ID).unwrap();
    assert_eq!(q2.len(), 1, "still undecodable -> stays quarantined");
    assert_eq!(q2[0].retry_count, 1, "first replay bumps retry_count once");
    assert_eq!(q2[0].server_seq, poison_seq, "poison row's seq is unchanged");
    assert_eq!(entity.get_field("task-undecodable", "title"), None, "poison op never applies");
    let cursor_after_c2 =
        storage.get_sync_metadata(SYNC_ID).unwrap().unwrap().last_pulled_server_seq;
    assert!(cursor_after_c2 >= cursor_after_c1, "cursor must be monotonic, never rewound");

    // Third cycle (still immediate): now within the backoff window (retry_count=1
    // -> 60s @ 30s base), so the row is SKIPPED — retry_count stays at 1, proving
    // the gate prevents per-cycle decode churn (and, structurally, any per-row
    // sender-resolution network fetch the replay would otherwise issue).
    let r3 = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key_receiver, Some(&ml_dsa_key_receiver), receiver_id, 0)
        .await
        .unwrap();
    assert!(r3.error.is_none(), "{:?}", r3.error);
    let q3 = storage.list_quarantined_pull_batches(SYNC_ID).unwrap();
    assert_eq!(q3.len(), 1);
    assert_eq!(
        q3[0].retry_count, 1,
        "backoff gate must skip the replay within the window (no retry_count bump)"
    );
}

/// A batch encrypted at an epoch the receiver does not yet hold no
/// longer hard-wedges the pull cursor. It quarantines-and-advances (reason
/// `missing_epoch_key`), the cursor AND the relay ack advance past it (so the
/// relay's min-acked prune floor is never pinned for the group), and once the
/// epoch key arrives Phase 0b replay applies it to the identical merge result a
/// live pull would have produced.
#[tokio::test]
async fn missing_epoch_key_batch_quarantines_advances_then_replays_on_key_arrival() {
    let mut key_hierarchy = init_key_hierarchy(); // receiver: holds only epoch 0
    let signing_key_sender = make_signing_key();
    let ml_dsa_key_sender = make_ml_dsa_keypair();
    let signing_key_receiver = make_signing_key();
    let ml_dsa_key_receiver = make_ml_dsa_keypair();
    let sender_id = "device-sender";
    let receiver_id = "device-receiver";

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity = Arc::new(MockTaskEntity::new());
    let entity_ref: Arc<dyn SyncableEntity> = entity.clone();

    setup_sync_metadata(&storage, receiver_id);
    register_device_with_pq(
        &relay,
        &storage,
        sender_id,
        &signing_key_sender.verifying_key(),
        &ml_dsa_key_sender.public_key_bytes(),
    );
    register_device_with_pq(
        &relay,
        &storage,
        receiver_id,
        &signing_key_receiver.verifying_key(),
        &ml_dsa_key_receiver.public_key_bytes(),
    );

    // The sender encrypts a batch at epoch 2 with a key the receiver lacks.
    let epoch2_key = [0xABu8; 32];
    let op = make_op(sender_id, "batch-epoch2", 2, "epoch2");
    let envelope = make_encrypted_batch_at_epoch(
        std::slice::from_ref(&op),
        &epoch2_key,
        2,
        &signing_key_sender,
        &ml_dsa_key_sender,
        "batch-epoch2",
        sender_id,
    );
    let q_seq = relay.inject_batch(envelope);

    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity_ref],
        test_schema(),
        SyncConfig::default(),
    );

    // Cycle 1: the receiver cannot decrypt the epoch-2 batch. Previously this hard-
    // errored (CoreError::MissingEpochKey), froze the cursor, and the device
    // never acked. Now sync returns Ok and the cursor/ack advance past it.
    let r1 = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key_receiver, Some(&ml_dsa_key_receiver), receiver_id, 0)
        .await
        .unwrap();
    assert!(r1.error.is_none(), "missing epoch key must not be a terminal sync error: {:?}", r1.error);
    assert_eq!(r1.merged, 0, "nothing applies while the key is absent");

    assert_eq!(
        storage.get_sync_metadata(SYNC_ID).unwrap().unwrap().last_pulled_server_seq,
        q_seq,
        "cursor must advance past the undecryptable batch"
    );
    assert!(
        relay.ack_calls().iter().any(|&s| s >= q_seq),
        "the relay ack must advance past the quarantined seq so pruning is unpinned"
    );

    let q = storage.list_quarantined_pull_batches(SYNC_ID).unwrap();
    assert_eq!(q.len(), 1, "exactly one quarantined pull batch");
    assert_eq!(q[0].reason, "missing_epoch_key");
    assert_eq!(q[0].server_seq, q_seq);
    assert_eq!(q[0].epoch, Some(2), "the row records the batch epoch for the replay gate");
    assert_eq!(storage.quarantined_pull_batch_count(SYNC_ID).unwrap(), 1);

    // Cycle 2 with the key STILL absent: the reason-aware gate skips the row with
    // no crypto/network and no retry_count churn (it cannot succeed yet).
    let r2 = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key_receiver, Some(&ml_dsa_key_receiver), receiver_id, 0)
        .await
        .unwrap();
    assert!(r2.error.is_none());
    let q2 = storage.list_quarantined_pull_batches(SYNC_ID).unwrap();
    assert_eq!(q2.len(), 1, "row stays quarantined while the key is missing");
    assert_eq!(q2[0].retry_count, 0, "no replay attempt is made while the key is absent");
    assert_eq!(entity.get_field("task-epoch2", "title"), None, "op not applied yet");

    // The epoch-2 key arrives (catch-up / recovery / bundle history). Phase 0b
    // replay re-runs the full pipeline and applies the batch.
    key_hierarchy.store_epoch_key(2, zeroize::Zeroizing::new(epoch2_key.to_vec()));
    let r3 = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key_receiver, Some(&ml_dsa_key_receiver), receiver_id, 0)
        .await
        .unwrap();
    assert!(r3.error.is_none(), "{:?}", r3.error);
    assert_eq!(
        entity.get_field("task-epoch2", "title"),
        Some(SyncValue::String("hello".into())),
        "the batch must apply identically once its epoch key is installed"
    );
    assert!(
        storage.list_quarantined_pull_batches(SYNC_ID).unwrap().is_empty(),
        "the row is deleted after a successful replay"
    );
    assert_eq!(storage.quarantined_pull_batch_count(SYNC_ID).unwrap(), 0);
}

/// Fail-closed boundary: a genuine `DecryptFailed` — the receiver HOLDS the
/// epoch key but the ciphertext authenticates wrong (tamper/corruption) — must
/// stay a hard error, never quarantine-and-advance. Only key-ABSENT is
/// quarantined; an authentication failure under a held key is not.
#[tokio::test]
async fn decrypt_failed_with_held_key_still_hard_fails() {
    let key_hierarchy = init_key_hierarchy(); // receiver holds epoch 0
    let signing_key_sender = make_signing_key();
    let ml_dsa_key_sender = make_ml_dsa_keypair();
    let signing_key_receiver = make_signing_key();
    let ml_dsa_key_receiver = make_ml_dsa_keypair();
    let sender_id = "device-sender";
    let receiver_id = "device-receiver";

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage, receiver_id);
    register_device_with_pq(
        &relay,
        &storage,
        sender_id,
        &signing_key_sender.verifying_key(),
        &ml_dsa_key_sender.public_key_bytes(),
    );
    register_device_with_pq(
        &relay,
        &storage,
        receiver_id,
        &signing_key_receiver.verifying_key(),
        &ml_dsa_key_receiver.public_key_bytes(),
    );

    // Build a valid epoch-0 batch, then corrupt the ciphertext so AEAD auth fails
    // under the key the receiver holds. The signature is recomputed over the
    // tampered ciphertext so we reach STEP 2 (decrypt) rather than failing
    // signature verification first.
    let op = make_op(sender_id, "batch-tamper", 0, "tamper");
    let plaintext = CrdtChange::encode_batch(std::slice::from_ref(&op)).unwrap();
    let payload_hash = batch_signature::compute_payload_hash(&plaintext);
    let epoch_key = key_hierarchy.epoch_key(0).unwrap();
    let aad = sync_aad::build_sync_aad(SYNC_ID, sender_id, 0, "batch-tamper", "ops");
    let (mut ciphertext, nonce) =
        prism_sync_crypto::aead::xchacha_encrypt_for_sync(epoch_key, &plaintext, &aad).unwrap();
    ciphertext[0] ^= 0xFF; // corrupt one byte -> AEAD authentication fails
    let envelope = batch_signature::sign_batch(
        &signing_key_sender,
        &ml_dsa_key_sender,
        SYNC_ID,
        0,
        "batch-tamper",
        "ops",
        sender_id,
        0,
        &payload_hash,
        nonce,
        ciphertext,
    )
    .unwrap();
    relay.inject_batch(envelope);

    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity],
        test_schema(),
        SyncConfig::default(),
    );

    // A held-key decrypt failure bubbles as a terminal error (it is in the
    // recoverable-key-error set the engine re-raises), not Ok-with-error and
    // never quarantine-and-advance.
    let err = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key_receiver, Some(&ml_dsa_key_receiver), receiver_id, 0)
        .await
        .expect_err("a DecryptFailed under a held key must remain a terminal error");
    assert!(
        matches!(err, CoreError::DecryptFailed { epoch: 0, .. }),
        "unexpected error: {err}"
    );
    assert!(
        storage.list_quarantined_pull_batches(SYNC_ID).unwrap().is_empty(),
        "a held-key decrypt failure must NOT be quarantined (fail-closed)"
    );
}

/// A poison batch (hash mismatch) at seq N followed by a good batch at N+1: the
/// good batch applies, the cursor reaches N+1, the poison envelope is
/// quarantined with reason payload_hash_mismatch, the event fires, AND a queued
/// local op is still pushed in the same cycle (push is not starved by the poison
/// batch — the older hard-wedge would have returned before the push phase).
#[tokio::test]
async fn poison_batch_quarantined_good_batch_applies_and_push_not_starved() {
    let key_hierarchy = init_key_hierarchy();
    let signing_key_sender = make_signing_key();
    let ml_dsa_key_sender = make_ml_dsa_keypair();
    let signing_key_receiver = make_signing_key();
    let ml_dsa_key_receiver = make_ml_dsa_keypair();
    let sender_id = "device-sender";
    let receiver_id = "device-receiver";

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity = Arc::new(MockTaskEntity::new());
    let entity_ref: Arc<dyn SyncableEntity> = entity.clone();

    setup_sync_metadata(&storage, receiver_id);
    register_device_with_pq(
        &relay,
        &storage,
        sender_id,
        &signing_key_sender.verifying_key(),
        &ml_dsa_key_sender.public_key_bytes(),
    );
    register_device_with_pq(
        &relay,
        &storage,
        receiver_id,
        &signing_key_receiver.verifying_key(),
        &ml_dsa_key_receiver.public_key_bytes(),
    );

    // Seq 1: poison batch.
    let poison_op = make_op(sender_id, "batch-poison", 0, "poison");
    let poison = make_hash_mismatched_batch(
        std::slice::from_ref(&poison_op),
        &key_hierarchy,
        &signing_key_sender,
        &ml_dsa_key_sender,
        "batch-poison",
        sender_id,
    );
    let poison_seq = relay.inject_batch(poison);

    // Seq 2: good batch.
    let good_op = make_op(sender_id, "batch-good-remote", 0, "good-remote");
    let good = make_encrypted_batch(
        std::slice::from_ref(&good_op),
        &key_hierarchy,
        &signing_key_sender,
        &ml_dsa_key_sender,
        "batch-good-remote",
        sender_id,
    );
    let good_seq = relay.inject_batch(good);

    // A local op queued to push this same cycle.
    let local_op = make_op(receiver_id, "batch-local", 0, "local");
    insert_pending_ops(&storage, std::slice::from_ref(&local_op), "batch-local");

    let (event_tx, mut event_rx) =
        tokio::sync::broadcast::channel::<prism_sync_core::events::SyncEvent>(32);
    let engine =
        SyncEngine::new(storage.clone(), relay.clone(), vec![entity_ref], test_schema(), SyncConfig::default())
            .with_event_sink(event_tx.clone());

    let result = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key_receiver, Some(&ml_dsa_key_receiver), receiver_id, 0)
        .await
        .unwrap();

    assert!(result.error.is_none(), "no terminal error: {:?}", result.error);
    assert_eq!(result.merged, 1, "only the good batch applies");
    assert_eq!(entity.get_field("task-good-remote", "title"), Some(SyncValue::String("hello".into())));
    assert_eq!(entity.get_field("task-poison", "title"), None, "poison op must not apply");

    assert_eq!(
        storage.get_sync_metadata(SYNC_ID).unwrap().unwrap().last_pulled_server_seq,
        good_seq,
        "cursor must reach the good batch past the poison one"
    );

    let quarantined = storage.list_quarantined_pull_batches(SYNC_ID).unwrap();
    assert_eq!(quarantined.len(), 1);
    assert_eq!(quarantined[0].reason, "payload_hash_mismatch");
    assert_eq!(quarantined[0].server_seq, poison_seq);

    // Push not starved: the local op was pushed in the same cycle.
    assert_eq!(result.pushed, 1, "the queued local op must still push despite the poison batch");
    assert!(relay.push_call_batch_ids().contains(&"batch-local".to_string()));

    let mut saw_event = false;
    while let Ok(event) = event_rx.try_recv() {
        if let prism_sync_core::events::SyncEvent::PullBatchQuarantined { reason, server_seq, .. } =
            event
        {
            if reason == "payload_hash_mismatch" && server_seq == poison_seq {
                saw_event = true;
            }
        }
    }
    assert!(saw_event, "expected PullBatchQuarantined(payload_hash_mismatch) event");
}

/// Mid-page stall ack discipline. A page of three batches where batch 2 is
/// from an unresolvable (unknown, no-registry) sender: batch 1 (known sender)
/// applies and advances the cursor to seq1; batch 2's transient verdict STALLS,
/// breaking the page loop so batches 2 and 3 are left unconsumed; and crucially
/// the device acks seq1 — NOT the page-max seq3 — so the relay can never prune
/// batches 2 or 3. The push phase still runs.
#[tokio::test]
async fn mid_page_stall_acks_cursor_not_page_max() {
    let key_hierarchy = init_key_hierarchy();
    let known_signing = make_signing_key();
    let known_ml_dsa = make_ml_dsa_keypair();
    let unknown_signing = make_signing_key();
    let unknown_ml_dsa = make_ml_dsa_keypair();
    let receiver_signing = make_signing_key();
    let receiver_ml_dsa = make_ml_dsa_keypair();

    let known_id = "device-known";
    let unknown_id = "device-unknown";
    let receiver_id = "device-receiver";

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity = Arc::new(MockTaskEntity::new());
    let entity_ref: Arc<dyn SyncableEntity> = entity.clone();

    setup_sync_metadata(&storage, receiver_id);
    register_device_with_pq(
        &relay,
        &storage,
        receiver_id,
        &receiver_signing.verifying_key(),
        &receiver_ml_dsa.public_key_bytes(),
    );
    // The known sender IS in the local registry; the unknown sender is NOT, and
    // there is no signed registry artifact -> resolving it returns Ok(None), a
    // transient verdict.
    register_device_with_pq(
        &relay,
        &storage,
        known_id,
        &known_signing.verifying_key(),
        &known_ml_dsa.public_key_bytes(),
    );

    // Seq 1: good batch from the known sender (applies).
    let op1 = make_op(known_id, "batch-1", 0, "one");
    let b1 = make_encrypted_batch(
        std::slice::from_ref(&op1),
        &key_hierarchy,
        &known_signing,
        &known_ml_dsa,
        "batch-1",
        known_id,
    );
    let seq1 = relay.inject_batch(b1);

    // Seq 2: batch from the unknown sender (stalls the page).
    let op2 = make_op(unknown_id, "batch-2", 0, "two");
    let b2 = make_encrypted_batch(
        std::slice::from_ref(&op2),
        &key_hierarchy,
        &unknown_signing,
        &unknown_ml_dsa,
        "batch-2",
        unknown_id,
    );
    let seq2 = relay.inject_batch(b2);

    // Seq 3: another good batch from the known sender — must remain unconsumed
    // because the page loop breaks at the seq-2 stall.
    let op3 = make_op(known_id, "batch-3", 0, "three");
    let b3 = make_encrypted_batch(
        std::slice::from_ref(&op3),
        &key_hierarchy,
        &known_signing,
        &known_ml_dsa,
        "batch-3",
        known_id,
    );
    // Injected so the page is genuinely longer than the applied prefix; its seq
    // is not asserted directly (the `acks == vec![seq1]` check below already
    // proves nothing past seq1 is acked).
    let _seq3 = relay.inject_batch(b3);

    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity_ref],
        test_schema(),
        SyncConfig::default(),
    );

    let result = engine
        .sync(SYNC_ID, &key_hierarchy, &receiver_signing, Some(&receiver_ml_dsa), receiver_id, 0)
        .await
        .unwrap();
    assert!(result.error.is_none(), "stall is non-fatal: {:?}", result.error);

    // Only batch 1 applied; batch 3 is past the stall and never reached.
    assert_eq!(entity.get_field("task-one", "title"), Some(SyncValue::String("hello".into())));
    assert_eq!(entity.get_field("task-two", "title"), None, "stalled batch not applied");
    assert_eq!(entity.get_field("task-three", "title"), None, "post-stall batch unconsumed");

    // Cursor sits at seq1: advanced past the applied batch, frozen behind the
    // stall.
    assert_eq!(
        storage.get_sync_metadata(SYNC_ID).unwrap().unwrap().last_pulled_server_seq,
        seq1,
        "cursor must stop at the applied batch, behind the stalled one"
    );

    // Yield so the fire-and-forget ack task runs before we read ack_calls();
    // otherwise the negative assertion below could pass simply because the ack
    // task never got polled on the current-thread test runtime.
    tokio::task::yield_now().await;

    // Ack discipline: ack EXACTLY seq1 (the local cursor), never the page max
    // (seq3) and never the stalled seq2. This is what stops the relay from
    // pruning the unconsumed batches 2 and 3. A positive equality check (not just
    // "not greater than seq1") so a regression back to page-max acking fails
    // deterministically rather than depending on ack-task timing.
    let acks = relay.ack_calls();
    assert_eq!(
        acks,
        vec![seq1],
        "must ack exactly the local cursor seq1, not the stalled seq2 or page max seq3"
    );

    // The unknown sender's batch is the stall row; batch 3 is not (loop broke).
    let stalls = storage.list_pull_stalls(SYNC_ID).unwrap();
    assert_eq!(stalls.len(), 1, "one stall row");
    assert_eq!(stalls[0].server_seq, seq2);
    assert_eq!(stalls[0].reason, "sender_unresolved");
    assert!(
        storage.list_quarantined_pull_batches(SYNC_ID).unwrap().is_empty(),
        "within budget -> stall, not quarantine"
    );
}

/// A batch quarantined because its signature did not verify under the sender's
/// (then-wrong) registered key. The cursor advances; repeated sync cycles bump
/// retry_count with backoff and do NOT churn the cursor. Once the correct key is
/// imported, Phase 0b replay verifies, applies the ops, and deletes the row.
#[tokio::test]
async fn invalid_signature_batch_quarantines_then_replays_after_key_import() {
    use prism_sync_core::storage::DeviceRecord;

    let key_hierarchy = init_key_hierarchy();
    let real_sender_signing = make_signing_key();
    let real_sender_ml_dsa = make_ml_dsa_keypair();
    let wrong_ml_dsa = make_ml_dsa_keypair();
    let signing_key_receiver = make_signing_key();
    let sender_id = "device-sender";
    let receiver_id = "device-receiver";

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity = Arc::new(MockTaskEntity::new());
    let entity_ref: Arc<dyn SyncableEntity> = entity.clone();

    setup_sync_metadata(&storage, receiver_id);
    // Register the sender with the WRONG ML-DSA key so verification fails first.
    register_device_with_pq(
        &relay,
        &storage,
        sender_id,
        &real_sender_signing.verifying_key(),
        &wrong_ml_dsa.public_key_bytes(),
    );
    register_device(&relay, &storage, receiver_id, &signing_key_receiver.verifying_key());

    // The batch is signed with the sender's REAL ML-DSA key.
    let op = make_op(sender_id, "batch-rotate", 0, "rotate");
    let envelope = make_encrypted_batch(
        std::slice::from_ref(&op),
        &key_hierarchy,
        &real_sender_signing,
        &real_sender_ml_dsa,
        "batch-rotate",
        sender_id,
    );
    let seq = relay.inject_batch(envelope);

    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity_ref],
        test_schema(),
        // Disable replay backoff so the three back-to-back cycles each attempt a
        // replay; the backoff gate itself is pinned by
        // `quarantine_replay_backoff_skips_within_window`.
        SyncConfig { quarantine_replay_backoff_base_ms: 0, ..SyncConfig::default() },
    );

    // Cycle 1: signature fails under the wrong key -> quarantine + advance.
    let r1 = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key_receiver, None, receiver_id, 0)
        .await
        .unwrap();
    assert!(r1.error.is_none(), "{:?}", r1.error);
    assert_eq!(entity.get_field("task-rotate", "title"), None);
    assert_eq!(storage.get_sync_metadata(SYNC_ID).unwrap().unwrap().last_pulled_server_seq, seq);
    let q1 = storage.list_quarantined_pull_batches(SYNC_ID).unwrap();
    assert_eq!(q1.len(), 1);
    assert_eq!(q1[0].reason, "invalid_signature");
    assert_eq!(q1[0].retry_count, 0);

    // Cycle 2: still wrong key -> replay fails, retry_count bumps, no churn.
    let r2 = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key_receiver, None, receiver_id, 0)
        .await
        .unwrap();
    assert!(r2.error.is_none(), "{:?}", r2.error);
    let q2 = storage.list_quarantined_pull_batches(SYNC_ID).unwrap();
    assert_eq!(q2.len(), 1, "still quarantined while the key is wrong");
    assert_eq!(q2[0].retry_count, 1, "retry_count must bump on identical failure");
    assert!(q2[0].last_retry_at.is_some());
    assert_eq!(storage.get_sync_metadata(SYNC_ID).unwrap().unwrap().last_pulled_server_seq, seq);

    // Import the correct ML-DSA key (simulating registry propagation).
    {
        let mut tx = storage.begin_tx().unwrap();
        tx.upsert_device_record(&DeviceRecord {
            sync_id: SYNC_ID.to_string(),
            device_id: sender_id.to_string(),
            ed25519_public_key: real_sender_signing.verifying_key().to_bytes().to_vec(),
            x25519_public_key: vec![0u8; 32],
            ml_dsa_65_public_key: real_sender_ml_dsa.public_key_bytes(),
            ml_kem_768_public_key: Vec::new(),
            x_wing_public_key: Vec::new(),
            status: "active".to_string(),
            registered_at: chrono::Utc::now(),
            revoked_at: None,
            ml_dsa_key_generation: 0,
        })
        .unwrap();
        tx.commit().unwrap();
    }

    // Cycle 3: Phase 0b replay verifies under the correct key and applies.
    let r3 = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key_receiver, None, receiver_id, 0)
        .await
        .unwrap();
    assert!(r3.error.is_none(), "{:?}", r3.error);
    assert_eq!(entity.get_field("task-rotate", "title"), Some(SyncValue::String("hello".into())));
    assert!(
        storage.list_quarantined_pull_batches(SYNC_ID).unwrap().is_empty(),
        "replayed batch's quarantine row must be deleted"
    );
    // Cursor never rewound below the live-pull seq.
    assert_eq!(storage.get_sync_metadata(SYNC_ID).unwrap().unwrap().last_pulled_server_seq, seq);
}

/// Revoking the poison sender after quarantine: the next Phase 0b replay
/// terminally discards the row (fail-closed) and applies nothing.
#[tokio::test]
async fn quarantined_batch_from_revoked_sender_is_discarded() {
    use prism_sync_core::storage::DeviceRecord;

    let key_hierarchy = init_key_hierarchy();
    let real_sender_signing = make_signing_key();
    let real_sender_ml_dsa = make_ml_dsa_keypair();
    let wrong_ml_dsa = make_ml_dsa_keypair();
    let signing_key_receiver = make_signing_key();
    let sender_id = "device-sender";
    let receiver_id = "device-receiver";

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity = Arc::new(MockTaskEntity::new());
    let entity_ref: Arc<dyn SyncableEntity> = entity.clone();

    setup_sync_metadata(&storage, receiver_id);
    register_device_with_pq(
        &relay,
        &storage,
        sender_id,
        &real_sender_signing.verifying_key(),
        &wrong_ml_dsa.public_key_bytes(),
    );
    register_device(&relay, &storage, receiver_id, &signing_key_receiver.verifying_key());

    let op = make_op(sender_id, "batch-revoke", 0, "revoke");
    let envelope = make_encrypted_batch(
        std::slice::from_ref(&op),
        &key_hierarchy,
        &real_sender_signing,
        &real_sender_ml_dsa,
        "batch-revoke",
        sender_id,
    );
    relay.inject_batch(envelope);

    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity_ref],
        test_schema(),
        SyncConfig::default(),
    );

    // Cycle 1: invalid signature -> quarantine.
    engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key_receiver, None, receiver_id, 0)
        .await
        .unwrap();
    assert_eq!(storage.list_quarantined_pull_batches(SYNC_ID).unwrap().len(), 1);

    // Revoke the sender locally.
    {
        let mut tx = storage.begin_tx().unwrap();
        tx.upsert_device_record(&DeviceRecord {
            sync_id: SYNC_ID.to_string(),
            device_id: sender_id.to_string(),
            ed25519_public_key: real_sender_signing.verifying_key().to_bytes().to_vec(),
            x25519_public_key: vec![0u8; 32],
            ml_dsa_65_public_key: real_sender_ml_dsa.public_key_bytes(),
            ml_kem_768_public_key: Vec::new(),
            x_wing_public_key: Vec::new(),
            status: "revoked".to_string(),
            registered_at: chrono::Utc::now(),
            revoked_at: Some(chrono::Utc::now()),
            ml_dsa_key_generation: 0,
        })
        .unwrap();
        tx.commit().unwrap();
    }

    // Cycle 2: replay sees the revoked sender -> terminal discard, nothing applies.
    let r2 = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key_receiver, None, receiver_id, 0)
        .await
        .unwrap();
    assert!(r2.error.is_none(), "{:?}", r2.error);
    assert_eq!(entity.get_field("task-revoke", "title"), None, "revoked sender's op must not apply");
    assert!(
        storage.list_quarantined_pull_batches(SYNC_ID).unwrap().is_empty(),
        "quarantine row from a revoked sender must be terminally discarded"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Schema quarantine regressions
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn unknown_field_op_is_quarantined_without_advancing_applied_ops() {
    let sender_id = "device-sender";
    let op = CrdtChange {
        op_id: "op-future-field".to_string(),
        batch_id: Some("batch-attribution".to_string()),
        entity_id: "task-quarantine".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "future_note".to_string(),
        encoded_value: "\"Backfill me\"".to_string(),
        client_hlc: Hlc::new(1_710_500_000_000, 0, sender_id).to_string(),
        is_delete: false,
        device_id: sender_id.to_string(),
        epoch: 0,
        server_seq: None,
    };

    let (result, storage, entity) = pull_injected_sender_batch(vec![op]).await;

    assert!(result.error.is_none(), "{:?}", result.error);
    assert_eq!(result.merged, 0);
    assert_eq!(entity.get_field("task-quarantine", "future_note"), None);
    assert!(!storage.is_op_applied("op-future-field").unwrap());
    assert_eq!(
        storage.get_sync_metadata(SYNC_ID).unwrap().unwrap().last_pulled_server_seq,
        1,
        "quarantined batches still advance the pull cursor"
    );

    let quarantined = storage.list_quarantined_ops(SYNC_ID).unwrap();
    assert_eq!(quarantined.len(), 1);
    assert_eq!(quarantined[0].op_id, "op-future-field");
    assert_eq!(quarantined[0].reason, "unknown_field");
    assert_eq!(quarantined[0].server_seq, 1);
}

#[tokio::test]
async fn quarantined_op_replays_when_schema_adds_field() {
    let sender_id = "device-sender";
    let receiver_id = "device-receiver";
    let op = CrdtChange {
        op_id: "op-future-field".to_string(),
        batch_id: Some("batch-attribution".to_string()),
        entity_id: "task-quarantine".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "future_note".to_string(),
        encoded_value: "\"Backfill me\"".to_string(),
        client_hlc: Hlc::new(1_710_500_000_000, 0, sender_id).to_string(),
        is_delete: false,
        device_id: sender_id.to_string(),
        epoch: 0,
        server_seq: None,
    };

    let (_result, storage, entity) = pull_injected_sender_batch(vec![op]).await;
    assert_eq!(storage.list_quarantined_ops(SYNC_ID).unwrap().len(), 1);

    let relay = Arc::new(MockRelay::new());
    let entity_ref: Arc<dyn SyncableEntity> = entity.clone();
    let engine = SyncEngine::new(
        storage.clone(),
        relay,
        vec![entity_ref],
        schema_with_future_field(),
        SyncConfig::default(),
    );
    let result = engine
        .sync(SYNC_ID, &init_key_hierarchy(), &make_signing_key(), None, receiver_id, 0)
        .await
        .unwrap();

    assert!(result.error.is_none(), "{:?}", result.error);
    assert_eq!(result.merged, 1);
    assert_eq!(
        entity.get_field("task-quarantine", "future_note"),
        Some(SyncValue::String("Backfill me".to_string()))
    );
    assert!(storage.list_quarantined_ops(SYNC_ID).unwrap().is_empty());
    assert!(storage.is_op_applied("op-future-field").unwrap());
}

/// A `future_hlc` quarantined op whose field is ALSO schema-unknown must NOT be
/// replayed-and-deleted once drift decays: the replay loop skips schema-unknown
/// ops (so it cannot apply this one), and Phase C must therefore leave its
/// quarantine row intact rather than delete it. Deleting it would be permanent
/// data loss — the pull cursor is already past the batch, so the relay can no
/// longer redeliver it. Regression guard for the `is_replay_eligible` future_hlc
/// arm's `schema_known` requirement (and the Phase C applied-only deletion).
#[tokio::test]
async fn future_hlc_op_with_unknown_field_is_not_replayed_or_deleted() {
    use prism_sync_core::storage::QuarantinedOp;

    let receiver_id = "device-receiver";
    let sender_id = "device-sender";

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity = Arc::new(MockTaskEntity::new());
    let entity_ref: Arc<dyn SyncableEntity> = entity.clone();
    let signing_key_receiver = make_signing_key();

    setup_sync_metadata(&storage, receiver_id);
    register_device(&relay, &storage, receiver_id, &signing_key_receiver.verifying_key());

    // HLC at "now" so the future-drift check is well within tolerance — the only
    // thing that should keep this op quarantined is its schema-unknown field.
    let now_ms = chrono::Utc::now().timestamp_millis();
    let in_tolerance_hlc = Hlc::new(now_ms, 0, sender_id);
    let quarantined_op = CrdtChange {
        op_id: "op-future-unknown".to_string(),
        batch_id: Some("batch-future-unknown".to_string()),
        entity_id: "task-future".to_string(),
        // `future_note` is absent from `test_schema()` — schema-unknown.
        entity_table: "tasks".to_string(),
        field_name: "future_note".to_string(),
        encoded_value: "\"Deferred edit\"".to_string(),
        client_hlc: in_tolerance_hlc.to_string(),
        is_delete: false,
        device_id: sender_id.to_string(),
        epoch: 0,
        server_seq: None,
    };

    {
        let mut tx = storage.begin_tx().unwrap();
        tx.insert_quarantined_op(&QuarantinedOp {
            sync_id: SYNC_ID.to_string(),
            op_id: quarantined_op.op_id.clone(),
            op: quarantined_op.clone(),
            reason: "future_hlc".to_string(),
            server_seq: 1,
            quarantined_at: chrono::Utc::now(),
        })
        .unwrap();
        tx.commit().unwrap();
    }
    assert_eq!(storage.list_quarantined_ops(SYNC_ID).unwrap().len(), 1);

    // Engine schema does NOT know `future_note`.
    let engine =
        SyncEngine::new(storage.clone(), relay, vec![entity_ref], test_schema(), SyncConfig::default());
    let result = engine
        .sync(SYNC_ID, &init_key_hierarchy(), &signing_key_receiver, None, receiver_id, 0)
        .await
        .unwrap();

    assert!(result.error.is_none(), "{:?}", result.error);
    assert_eq!(result.merged, 0, "schema-unknown op must not be applied");
    assert!(
        !storage.is_op_applied("op-future-unknown").unwrap(),
        "op was never applied, so applied_ops must not record it",
    );
    let remaining = storage.list_quarantined_ops(SYNC_ID).unwrap();
    assert_eq!(remaining.len(), 1, "quarantine row must survive replay (no silent drop)");
    assert_eq!(remaining[0].op_id, "op-future-unknown");
    assert_eq!(remaining[0].reason, "future_hlc");
    assert_eq!(
        entity.get_field("task-future", "future_note"),
        None,
        "no consumer-side effect from a non-replayed op",
    );
}

/// A pulled batch carrying a `_bulk_reset` sentinel (for which this build has
/// no handler) plus replacement rows: the replacement rows apply, the sentinel
/// is quarantined per-op with reason `unsupported_bulk_reset` and is NOT marked
/// applied, the cursor advances, and repeated sync cycles never apply, delete,
/// or re-insert the quarantine row (no replay churn). Marking it applied
/// as a no-op (the pre-fix behaviour) would silently and unrecoverably diverge
/// the moment any peer emits a bulk reset.
#[tokio::test]
async fn bulk_reset_op_quarantined_replacement_rows_apply_no_replay_churn() {
    use prism_sync_core::BULK_RESET_FIELD;

    let sender_id = "device-sender";
    let receiver_id = "device-receiver";

    let reset_op = CrdtChange {
        op_id: "op-bulk-reset".to_string(),
        batch_id: Some("batch-attribution".to_string()),
        entity_id: "task-bulk".to_string(),
        entity_table: "tasks".to_string(),
        field_name: BULK_RESET_FIELD.to_string(),
        encoded_value: "null".to_string(),
        client_hlc: Hlc::new(1_710_500_000_000, 0, sender_id).to_string(),
        is_delete: false,
        device_id: sender_id.to_string(),
        epoch: 0,
        server_seq: None,
    };
    let replacement_op = CrdtChange {
        op_id: "op-replacement".to_string(),
        batch_id: Some("batch-attribution".to_string()),
        entity_id: "task-bulk".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "title".to_string(),
        encoded_value: "\"Fresh\"".to_string(),
        client_hlc: Hlc::new(1_710_500_000_001, 0, sender_id).to_string(),
        is_delete: false,
        device_id: sender_id.to_string(),
        epoch: 0,
        server_seq: None,
    };

    let (result, storage, entity) =
        pull_injected_sender_batch(vec![reset_op, replacement_op]).await;

    assert!(result.error.is_none(), "{:?}", result.error);
    assert_eq!(result.merged, 1, "only the replacement row wins; the reset is quarantined");
    assert_eq!(
        entity.get_field("task-bulk", "title"),
        Some(SyncValue::String("Fresh".to_string())),
        "replacement row applies"
    );
    assert!(
        storage.is_op_applied("op-replacement").unwrap(),
        "replacement row is recorded applied"
    );
    assert!(
        !storage.is_op_applied("op-bulk-reset").unwrap(),
        "bulk reset must NOT be marked applied (the no-op-apply trap)"
    );
    assert_eq!(
        storage.get_sync_metadata(SYNC_ID).unwrap().unwrap().last_pulled_server_seq,
        1,
        "cursor advances past the consumed batch"
    );

    let quarantined = storage.list_quarantined_ops(SYNC_ID).unwrap();
    assert_eq!(quarantined.len(), 1);
    assert_eq!(quarantined[0].op_id, "op-bulk-reset");
    assert_eq!(quarantined[0].reason, "unsupported_bulk_reset");
    assert_eq!(quarantined[0].server_seq, 1);

    // Ten more sync cycles must not churn: no apply, no delete, no re-insert,
    // no error. `unsupported_bulk_reset` is never replay-eligible in this build.
    let relay = Arc::new(MockRelay::new());
    let entity_ref: Arc<dyn SyncableEntity> = entity.clone();
    let engine = SyncEngine::new(
        storage.clone(),
        relay,
        vec![entity_ref],
        test_schema(),
        SyncConfig::default(),
    );
    for cycle in 0..10 {
        let r = engine
            .sync(SYNC_ID, &init_key_hierarchy(), &make_signing_key(), None, receiver_id, 0)
            .await
            .unwrap();
        assert!(r.error.is_none(), "cycle {cycle}: {:?}", r.error);
        assert_eq!(r.merged, 0, "cycle {cycle}: nothing new applies");
        let q = storage.list_quarantined_ops(SYNC_ID).unwrap();
        assert_eq!(q.len(), 1, "cycle {cycle}: quarantine row neither deleted nor duplicated");
        assert_eq!(q[0].op_id, "op-bulk-reset");
        assert!(
            !storage.is_op_applied("op-bulk-reset").unwrap(),
            "cycle {cycle}: reset still not applied"
        );
    }
}

#[tokio::test]
async fn snapshot_import_accepts_rows_from_trusted_non_uploader_device() {
    let key_hierarchy = init_key_hierarchy();
    let signing_key_source = make_signing_key();
    let ml_dsa_key_source = make_ml_dsa_keypair();
    let signing_key_sender = make_signing_key();
    let ml_dsa_key_sender = make_ml_dsa_keypair();
    let signing_key_receiver = make_signing_key();
    let source_id = "device-source";
    let sender_id = "device-sender";
    let receiver_id = "device-receiver";
    let server_seq_at = 7;

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage, receiver_id);
    register_device_with_pq(
        &relay,
        &storage,
        source_id,
        &signing_key_source.verifying_key(),
        &ml_dsa_key_source.public_key_bytes(),
    );
    register_device_with_pq(
        &relay,
        &storage,
        sender_id,
        &signing_key_sender.verifying_key(),
        &ml_dsa_key_sender.public_key_bytes(),
    );
    register_device(&relay, &storage, receiver_id, &signing_key_receiver.verifying_key());

    let source_hlc = Hlc::new(1_710_500_000_000, 0, source_id).to_string();
    let snapshot = SnapshotData {
        version: SNAPSHOT_VERSION,
        field_versions: vec![FieldVersionEntry {
            entity_table: "tasks".to_string(),
            entity_id: "task-snapshot".to_string(),
            field_name: "title".to_string(),
            winning_hlc: source_hlc.clone(),
            winning_device_id: source_id.to_string(),
            winning_op_id: "op-source-snapshot".to_string(),
            winning_encoded_value: Some("\"Source snapshot row\"".to_string()),
            updated_at: "2024-03-15T00:00:00Z".to_string(),
        }],
        device_registry: vec![
            snapshot_device_entry(
                source_id,
                &signing_key_source.verifying_key(),
                &ml_dsa_key_source.public_key_bytes(),
            ),
            snapshot_device_entry(
                sender_id,
                &signing_key_sender.verifying_key(),
                &ml_dsa_key_sender.public_key_bytes(),
            ),
        ],
        applied_ops: vec![AppliedOpEntry {
            op_id: "op-source-snapshot".to_string(),
            sync_id: SYNC_ID.to_string(),
            epoch: 0,
            device_id: source_id.to_string(),
            client_hlc: source_hlc,
            server_seq: server_seq_at,
            applied_at: "2024-03-15T00:00:00Z".to_string(),
        }],
        sync_metadata: SyncMetadataEntry {
            sync_id: SYNC_ID.to_string(),
            local_device_id: sender_id.to_string(),
            current_epoch: 0,
            last_pulled_server_seq: server_seq_at,
        },
    };
    let envelope_bytes = make_snapshot_envelope_bytes(
        &snapshot,
        &key_hierarchy,
        &signing_key_sender,
        &ml_dsa_key_sender,
        "snapshot-trusted-source",
        sender_id,
        server_seq_at,
    );
    relay
        .put_snapshot(0, server_seq_at, envelope_bytes, None, None, sender_id.to_string(), None)
        .await
        .unwrap();

    let engine =
        SyncEngine::new(storage.clone(), relay, vec![entity], test_schema(), SyncConfig::default());
    let (count, entity_changes) =
        engine.bootstrap_from_snapshot(SYNC_ID, &key_hierarchy).await.unwrap();

    assert_eq!(count, 1);
    assert_eq!(
        storage
            .get_field_version(SYNC_ID, "tasks", "task-snapshot", "title")
            .unwrap()
            .unwrap()
            .winning_device_id,
        source_id
    );
    assert!(storage.is_op_applied("op-source-snapshot").unwrap());
    assert_eq!(entity_changes.len(), 1);
    assert_eq!(entity_changes[0].fields.get("title"), Some(&"\"Source snapshot row\"".to_string()));
}

/// A snapshot auto-bootstrap (the relay-history-pruned path that runs
/// `bootstrap_from_snapshot`): a snapshot field whose winning HLC is far in the
/// future (the same condition the pull path defers) must NOT be imported as a
/// live field, must NOT surface in the returned EntityChanges, and must instead
/// land in the per-op quarantine lane with the shared `future_hlc` reason — so
/// the snapshot channel can never diverge from the op channel, and the replay
/// path picks it up once the local clock catches up.
#[tokio::test]
async fn bootstrap_from_snapshot_quarantines_future_drift_field() {
    let key_hierarchy = init_key_hierarchy();
    let signing_key_source = make_signing_key();
    let ml_dsa_key_source = make_ml_dsa_keypair();
    let signing_key_sender = make_signing_key();
    let ml_dsa_key_sender = make_ml_dsa_keypair();
    let signing_key_receiver = make_signing_key();
    let source_id = "device-source";
    let sender_id = "device-sender";
    let receiver_id = "device-receiver";
    let server_seq_at = 7;

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage, receiver_id);
    register_device_with_pq(
        &relay,
        &storage,
        source_id,
        &signing_key_source.verifying_key(),
        &ml_dsa_key_source.public_key_bytes(),
    );
    register_device_with_pq(
        &relay,
        &storage,
        sender_id,
        &signing_key_sender.verifying_key(),
        &ml_dsa_key_sender.public_key_bytes(),
    );
    register_device(&relay, &storage, receiver_id, &signing_key_receiver.verifying_key());

    // A live field whose winner sits an hour in the future — well past the 60s
    // drift bound the op channel enforces.
    let future_ms = chrono::Utc::now().timestamp_millis() + 3_600_000;
    let drift_hlc = Hlc::new(future_ms, 0, source_id).to_string();
    let snapshot = SnapshotData {
        version: SNAPSHOT_VERSION,
        field_versions: vec![FieldVersionEntry {
            entity_table: "tasks".to_string(),
            entity_id: "task-drift".to_string(),
            field_name: "title".to_string(),
            winning_hlc: drift_hlc.clone(),
            winning_device_id: source_id.to_string(),
            winning_op_id: "op-drift".to_string(),
            winning_encoded_value: Some("\"Drifted title\"".to_string()),
            updated_at: "2024-03-15T00:00:00Z".to_string(),
        }],
        device_registry: vec![
            snapshot_device_entry(
                source_id,
                &signing_key_source.verifying_key(),
                &ml_dsa_key_source.public_key_bytes(),
            ),
            snapshot_device_entry(
                sender_id,
                &signing_key_sender.verifying_key(),
                &ml_dsa_key_sender.public_key_bytes(),
            ),
        ],
        // The drift op is deliberately NOT pre-marked applied, so the quarantine
        // stays replayable once the clock catches up.
        applied_ops: vec![],
        sync_metadata: SyncMetadataEntry {
            sync_id: SYNC_ID.to_string(),
            local_device_id: sender_id.to_string(),
            current_epoch: 0,
            last_pulled_server_seq: server_seq_at,
        },
    };
    let envelope_bytes = make_snapshot_envelope_bytes(
        &snapshot,
        &key_hierarchy,
        &signing_key_sender,
        &ml_dsa_key_sender,
        "snapshot-drift",
        sender_id,
        server_seq_at,
    );
    relay
        .put_snapshot(0, server_seq_at, envelope_bytes, None, None, sender_id.to_string(), None)
        .await
        .unwrap();

    let engine =
        SyncEngine::new(storage.clone(), relay, vec![entity], test_schema(), SyncConfig::default());
    let (count, entity_changes) =
        engine.bootstrap_from_snapshot(SYNC_ID, &key_hierarchy).await.unwrap();

    // No live import, no EntityChange for the drifted field.
    assert_eq!(count, 0);
    assert!(
        entity_changes.is_empty(),
        "a future-drift snapshot field must not surface as a live EntityChange"
    );
    assert!(
        storage.get_field_version(SYNC_ID, "tasks", "task-drift", "title").unwrap().is_none(),
        "a future-drift snapshot field must not import into field_versions"
    );
    assert!(!storage.is_op_applied("op-drift").unwrap());

    // It is held in the per-op quarantine lane with the shared reason string.
    let quarantined = storage.list_quarantined_ops(SYNC_ID).unwrap();
    assert_eq!(quarantined.len(), 1);
    assert_eq!(quarantined[0].op_id, "op-drift");
    assert_eq!(quarantined[0].reason, "future_hlc");
    assert_eq!(quarantined[0].op.device_id, source_id);
    assert_eq!(quarantined[0].op.client_hlc, drift_hlc);
}

/// Regression: a snapshot field within the drift bound (now+30s) bootstraps
/// normally — imported live, surfaced as an EntityChange, never quarantined.
#[tokio::test]
async fn bootstrap_from_snapshot_imports_within_bound_field() {
    let key_hierarchy = init_key_hierarchy();
    let signing_key_source = make_signing_key();
    let ml_dsa_key_source = make_ml_dsa_keypair();
    let signing_key_sender = make_signing_key();
    let ml_dsa_key_sender = make_ml_dsa_keypair();
    let signing_key_receiver = make_signing_key();
    let source_id = "device-source";
    let sender_id = "device-sender";
    let receiver_id = "device-receiver";
    let server_seq_at = 9;

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage, receiver_id);
    register_device_with_pq(
        &relay,
        &storage,
        source_id,
        &signing_key_source.verifying_key(),
        &ml_dsa_key_source.public_key_bytes(),
    );
    register_device_with_pq(
        &relay,
        &storage,
        sender_id,
        &signing_key_sender.verifying_key(),
        &ml_dsa_key_sender.public_key_bytes(),
    );
    register_device(&relay, &storage, receiver_id, &signing_key_receiver.verifying_key());

    let near_ms = chrono::Utc::now().timestamp_millis() + 30_000; // within the 60s bound
    let near_hlc = Hlc::new(near_ms, 0, source_id).to_string();
    let snapshot = SnapshotData {
        version: SNAPSHOT_VERSION,
        field_versions: vec![FieldVersionEntry {
            entity_table: "tasks".to_string(),
            entity_id: "task-near".to_string(),
            field_name: "title".to_string(),
            winning_hlc: near_hlc.clone(),
            winning_device_id: source_id.to_string(),
            winning_op_id: "op-near".to_string(),
            winning_encoded_value: Some("\"Within bound\"".to_string()),
            updated_at: "2024-03-15T00:00:00Z".to_string(),
        }],
        device_registry: vec![
            snapshot_device_entry(
                source_id,
                &signing_key_source.verifying_key(),
                &ml_dsa_key_source.public_key_bytes(),
            ),
            snapshot_device_entry(
                sender_id,
                &signing_key_sender.verifying_key(),
                &ml_dsa_key_sender.public_key_bytes(),
            ),
        ],
        applied_ops: vec![],
        sync_metadata: SyncMetadataEntry {
            sync_id: SYNC_ID.to_string(),
            local_device_id: sender_id.to_string(),
            current_epoch: 0,
            last_pulled_server_seq: server_seq_at,
        },
    };
    let envelope_bytes = make_snapshot_envelope_bytes(
        &snapshot,
        &key_hierarchy,
        &signing_key_sender,
        &ml_dsa_key_sender,
        "snapshot-near",
        sender_id,
        server_seq_at,
    );
    relay
        .put_snapshot(0, server_seq_at, envelope_bytes, None, None, sender_id.to_string(), None)
        .await
        .unwrap();

    let engine =
        SyncEngine::new(storage.clone(), relay, vec![entity], test_schema(), SyncConfig::default());
    let (count, entity_changes) =
        engine.bootstrap_from_snapshot(SYNC_ID, &key_hierarchy).await.unwrap();

    assert_eq!(count, 1);
    assert_eq!(entity_changes.len(), 1);
    assert_eq!(
        entity_changes[0].fields.get("title"),
        Some(&"\"Within bound\"".to_string())
    );
    assert_eq!(
        storage
            .get_field_version(SYNC_ID, "tasks", "task-near", "title")
            .unwrap()
            .unwrap()
            .winning_encoded_value,
        Some("\"Within bound\"".to_string())
    );
    assert!(storage.list_quarantined_ops(SYNC_ID).unwrap().is_empty());
}

/// Supersede: once a later same-device op has won the same field, the
/// future-drift quarantine row from the snapshot import is dead on arrival (it
/// can never win LWW), so the reused replay path evicts it on the next sync
/// cycle rather than holding it forever or resurrecting stale state.
#[tokio::test]
async fn bootstrap_from_snapshot_drift_quarantine_evicted_by_later_same_device_op() {
    use prism_sync_core::storage::FieldVersion;

    let key_hierarchy = init_key_hierarchy();
    let signing_key_source = make_signing_key();
    let ml_dsa_key_source = make_ml_dsa_keypair();
    let signing_key_sender = make_signing_key();
    let ml_dsa_key_sender = make_ml_dsa_keypair();
    let signing_key_receiver = make_signing_key();
    let source_id = "device-source";
    let sender_id = "device-sender";
    let receiver_id = "device-receiver";
    let server_seq_at = 11;

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage, receiver_id);
    register_device_with_pq(
        &relay,
        &storage,
        source_id,
        &signing_key_source.verifying_key(),
        &ml_dsa_key_source.public_key_bytes(),
    );
    register_device_with_pq(
        &relay,
        &storage,
        sender_id,
        &signing_key_sender.verifying_key(),
        &ml_dsa_key_sender.public_key_bytes(),
    );
    register_device(&relay, &storage, receiver_id, &signing_key_receiver.verifying_key());

    let future_ms = chrono::Utc::now().timestamp_millis() + 3_600_000;
    let drift_hlc = Hlc::new(future_ms, 0, source_id).to_string();
    let snapshot = SnapshotData {
        version: SNAPSHOT_VERSION,
        field_versions: vec![FieldVersionEntry {
            entity_table: "tasks".to_string(),
            entity_id: "task-drift".to_string(),
            field_name: "title".to_string(),
            winning_hlc: drift_hlc.clone(),
            winning_device_id: source_id.to_string(),
            winning_op_id: "op-drift".to_string(),
            winning_encoded_value: Some("\"Drifted title\"".to_string()),
            updated_at: "2024-03-15T00:00:00Z".to_string(),
        }],
        device_registry: vec![
            snapshot_device_entry(
                source_id,
                &signing_key_source.verifying_key(),
                &ml_dsa_key_source.public_key_bytes(),
            ),
            snapshot_device_entry(
                sender_id,
                &signing_key_sender.verifying_key(),
                &ml_dsa_key_sender.public_key_bytes(),
            ),
        ],
        applied_ops: vec![],
        sync_metadata: SyncMetadataEntry {
            sync_id: SYNC_ID.to_string(),
            local_device_id: sender_id.to_string(),
            current_epoch: 0,
            last_pulled_server_seq: server_seq_at,
        },
    };
    let envelope_bytes = make_snapshot_envelope_bytes(
        &snapshot,
        &key_hierarchy,
        &signing_key_sender,
        &ml_dsa_key_sender,
        "snapshot-drift",
        sender_id,
        server_seq_at,
    );
    relay
        .put_snapshot(0, server_seq_at, envelope_bytes, None, None, sender_id.to_string(), None)
        .await
        .unwrap();

    let engine =
        SyncEngine::new(storage.clone(), relay, vec![entity], test_schema(), SyncConfig::default());
    engine.bootstrap_from_snapshot(SYNC_ID, &key_hierarchy).await.unwrap();
    assert_eq!(storage.list_quarantined_ops(SYNC_ID).unwrap().len(), 1);

    // The source device's clock recovered, so its NEXT edit to the same field
    // carries a monotonically higher HLC than the excursion op and wins the
    // field. (HLC is per-device monotonic, so the recovered edit's HLC strictly
    // exceeds the excursion's even though it was emitted "now".) Simulate that
    // applied winner directly in storage.
    {
        let mut tx = storage.begin_tx().unwrap();
        tx.upsert_field_version(&FieldVersion {
            sync_id: SYNC_ID.to_string(),
            entity_table: "tasks".to_string(),
            entity_id: "task-drift".to_string(),
            field_name: "title".to_string(),
            winning_op_id: "op-recovered".to_string(),
            winning_device_id: source_id.to_string(),
            winning_hlc: Hlc::new(future_ms, 1, source_id).to_string(),
            winning_encoded_value: Some("\"Recovered title\"".to_string()),
            updated_at: chrono::Utc::now(),
        })
        .unwrap();
        tx.commit().unwrap();
    }

    // A sync cycle's Phase 0 replay evaluates the supersede rule and evicts the
    // dead drift quarantine row.
    engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key_receiver, None, receiver_id, 0)
        .await
        .unwrap();

    assert!(
        storage.list_quarantined_ops(SYNC_ID).unwrap().is_empty(),
        "the superseded future-drift quarantine row must be evicted"
    );
    // The recovered winner stands; the stale excursion value never resurrects.
    assert_eq!(
        storage
            .get_field_version(SYNC_ID, "tasks", "task-drift", "title")
            .unwrap()
            .unwrap()
            .winning_encoded_value,
        Some("\"Recovered title\"".to_string())
    );
}

/// Data-loss guard: a snapshot whose `applied_ops` ALREADY lists the
/// over-bound field's winning op (legacy pre-replay data, or an exporter that
/// replayed it while it was within-bound to its faster clock) must still recover.
/// The gate must NOT mark that op applied on import — otherwise the replay
/// would skip it (merge skips already-applied ops) and then delete its quarantine
/// row as "replayed", losing the field forever. Once the clock catches up the
/// quarantined op replays and the field lands in field_versions.
#[tokio::test]
async fn bootstrap_from_snapshot_quarantined_op_in_applied_ops_still_recovers() {
    let key_hierarchy = init_key_hierarchy();
    let signing_key_source = make_signing_key();
    let ml_dsa_key_source = make_ml_dsa_keypair();
    let signing_key_sender = make_signing_key();
    let ml_dsa_key_sender = make_ml_dsa_keypair();
    let signing_key_receiver = make_signing_key();
    let source_id = "device-source";
    let sender_id = "device-sender";
    let receiver_id = "device-receiver";
    let server_seq_at = 9;

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage, receiver_id);
    register_device_with_pq(
        &relay,
        &storage,
        source_id,
        &signing_key_source.verifying_key(),
        &ml_dsa_key_source.public_key_bytes(),
    );
    register_device_with_pq(
        &relay,
        &storage,
        sender_id,
        &signing_key_sender.verifying_key(),
        &ml_dsa_key_sender.public_key_bytes(),
    );
    register_device(&relay, &storage, receiver_id, &signing_key_receiver.verifying_key());

    // 90s ahead — over the default 60s bound at bootstrap, but inside the wider
    // bound used for the replay pass (simulating the local clock catching up).
    let future_ms = current_time_ms() + 90_000;
    let drift_hlc = Hlc::new(future_ms, 0, source_id).to_string();
    let snapshot = SnapshotData {
        version: SNAPSHOT_VERSION,
        field_versions: vec![FieldVersionEntry {
            entity_table: "tasks".to_string(),
            entity_id: "task-drift".to_string(),
            field_name: "title".to_string(),
            winning_hlc: drift_hlc.clone(),
            winning_device_id: source_id.to_string(),
            winning_op_id: "op-drift".to_string(),
            winning_encoded_value: Some("\"Drifted title\"".to_string()),
            updated_at: "2024-03-15T00:00:00Z".to_string(),
        }],
        device_registry: vec![
            snapshot_device_entry(
                source_id,
                &signing_key_source.verifying_key(),
                &ml_dsa_key_source.public_key_bytes(),
            ),
            snapshot_device_entry(
                sender_id,
                &signing_key_sender.verifying_key(),
                &ml_dsa_key_sender.public_key_bytes(),
            ),
        ],
        // The exporter ran the op as applied (its faster clock made it in-bound),
        // so the snapshot carries op-drift in applied_ops. The importer must NOT
        // honor that for the field it is quarantining.
        applied_ops: vec![AppliedOpEntry {
            op_id: "op-drift".to_string(),
            sync_id: SYNC_ID.to_string(),
            epoch: 0,
            device_id: source_id.to_string(),
            client_hlc: drift_hlc.clone(),
            server_seq: server_seq_at,
            applied_at: "2024-03-15T00:00:00Z".to_string(),
        }],
        sync_metadata: SyncMetadataEntry {
            sync_id: SYNC_ID.to_string(),
            local_device_id: sender_id.to_string(),
            current_epoch: 0,
            last_pulled_server_seq: server_seq_at,
        },
    };
    let envelope_bytes = make_snapshot_envelope_bytes(
        &snapshot,
        &key_hierarchy,
        &signing_key_sender,
        &ml_dsa_key_sender,
        "snapshot-drift",
        sender_id,
        server_seq_at,
    );
    relay
        .put_snapshot(0, server_seq_at, envelope_bytes, None, None, sender_id.to_string(), None)
        .await
        .unwrap();

    // Bootstrap at the default 60s bound: op-drift is over-bound, so its field is
    // quarantined and — critically — op-drift must NOT be marked applied.
    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity.clone()],
        test_schema(),
        SyncConfig::default(),
    );
    engine.bootstrap_from_snapshot(SYNC_ID, &key_hierarchy).await.unwrap();
    assert!(
        !storage.is_op_applied("op-drift").unwrap(),
        "a quarantined snapshot op must not be marked applied, or replay loses the field"
    );
    assert!(storage.get_field_version(SYNC_ID, "tasks", "task-drift", "title").unwrap().is_none());
    assert_eq!(storage.list_quarantined_ops(SYNC_ID).unwrap().len(), 1);

    // The local clock catches up (modeled by a wider drift bound): a Phase 0
    // replay cycle applies the quarantined op and the field lands. On the buggy
    // code op-drift was already applied, so replay skipped it and deleted the
    // quarantine row — the field never appeared and this assert failed.
    let replay_engine = SyncEngine::new(
        storage.clone(),
        relay,
        vec![entity],
        test_schema(),
        SyncConfig { max_clock_drift_ms: 200_000, ..Default::default() },
    );
    replay_engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key_receiver, None, receiver_id, 0)
        .await
        .unwrap();

    assert_eq!(
        storage
            .get_field_version(SYNC_ID, "tasks", "task-drift", "title")
            .unwrap()
            .expect("the quarantined field must be applied to field_versions on replay")
            .winning_encoded_value,
        Some("\"Drifted title\"".to_string())
    );
    assert!(
        storage.list_quarantined_ops(SYNC_ID).unwrap().is_empty(),
        "the replayed quarantine row is removed once applied"
    );
    assert!(storage.is_op_applied("op-drift").unwrap(), "the op is applied after replay");
}

/// A snapshot auto-bootstrap (the relay-history-pruned path that runs
/// `bootstrap_from_snapshot`) must preserve the device's existing
/// `last_imported_registry_version` freshness baseline. The snapshot blob carries
/// no baseline, so without the importer's preserve-on-REPLACE fix the bootstrap
/// would NULL it and re-arm the stale-registry false-wipe on exactly the devices
/// that just bootstrapped.
#[tokio::test]
async fn bootstrap_from_snapshot_preserves_last_imported_registry_version() {
    use prism_sync_core::storage::SyncStorage as _;

    let key_hierarchy = init_key_hierarchy();
    let signing_key_source = make_signing_key();
    let ml_dsa_key_source = make_ml_dsa_keypair();
    let signing_key_sender = make_signing_key();
    let ml_dsa_key_sender = make_ml_dsa_keypair();
    let signing_key_receiver = make_signing_key();
    let source_id = "device-source";
    let sender_id = "device-sender";
    let receiver_id = "device-receiver";
    let server_seq_at = 42;

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage, receiver_id);
    // The device has already imported registry version 17 (its freshness
    // baseline). This is the value the snapshot import must not clobber.
    {
        let mut tx = storage.begin_tx().unwrap();
        tx.update_last_imported_registry_version(SYNC_ID, 17).unwrap();
        tx.commit().unwrap();
    }
    register_device_with_pq(
        &relay,
        &storage,
        source_id,
        &signing_key_source.verifying_key(),
        &ml_dsa_key_source.public_key_bytes(),
    );
    register_device_with_pq(
        &relay,
        &storage,
        sender_id,
        &signing_key_sender.verifying_key(),
        &ml_dsa_key_sender.public_key_bytes(),
    );
    register_device(&relay, &storage, receiver_id, &signing_key_receiver.verifying_key());

    let alive_hlc = Hlc::new(1_710_500_000_000, 0, source_id).to_string();
    let snapshot = SnapshotData {
        version: SNAPSHOT_VERSION,
        field_versions: vec![FieldVersionEntry {
            entity_table: "tasks".to_string(),
            entity_id: "task-alive".to_string(),
            field_name: "title".to_string(),
            winning_hlc: alive_hlc.clone(),
            winning_device_id: source_id.to_string(),
            winning_op_id: "op-alive".to_string(),
            winning_encoded_value: Some("\"Still here\"".to_string()),
            updated_at: "2024-03-15T00:00:00Z".to_string(),
        }],
        device_registry: vec![
            snapshot_device_entry(
                source_id,
                &signing_key_source.verifying_key(),
                &ml_dsa_key_source.public_key_bytes(),
            ),
            snapshot_device_entry(
                sender_id,
                &signing_key_sender.verifying_key(),
                &ml_dsa_key_sender.public_key_bytes(),
            ),
        ],
        applied_ops: vec![AppliedOpEntry {
            op_id: "op-alive".to_string(),
            sync_id: SYNC_ID.to_string(),
            epoch: 0,
            device_id: source_id.to_string(),
            client_hlc: alive_hlc,
            server_seq: server_seq_at,
            applied_at: "2024-03-15T00:00:00Z".to_string(),
        }],
        // The snapshot's metadata names the SENDER as local_device_id — the
        // importer must keep the RECEIVER's local id AND its baseline.
        sync_metadata: SyncMetadataEntry {
            sync_id: SYNC_ID.to_string(),
            local_device_id: sender_id.to_string(),
            current_epoch: 0,
            last_pulled_server_seq: server_seq_at,
        },
    };
    let envelope_bytes = make_snapshot_envelope_bytes(
        &snapshot,
        &key_hierarchy,
        &signing_key_sender,
        &ml_dsa_key_sender,
        "snapshot-baseline",
        sender_id,
        server_seq_at,
    );
    relay
        .put_snapshot(0, server_seq_at, envelope_bytes, None, None, sender_id.to_string(), None)
        .await
        .unwrap();

    let engine =
        SyncEngine::new(storage.clone(), relay, vec![entity], test_schema(), SyncConfig::default());
    engine.bootstrap_from_snapshot(SYNC_ID, &key_hierarchy).await.unwrap();

    let meta = storage.get_sync_metadata(SYNC_ID).unwrap().unwrap();
    assert_eq!(
        meta.last_imported_registry_version,
        Some(17),
        "snapshot bootstrap must preserve the freshness baseline"
    );
    assert_eq!(
        meta.local_device_id, receiver_id,
        "snapshot bootstrap must keep the local device id, not adopt the snapshot's"
    );
    assert_eq!(meta.last_pulled_server_seq, server_seq_at, "transport cursor still advances");
}

/// Snapshot import writes the consumer-delivery journal in the SAME tx as
/// the import + cursor advance, so a kill between import-commit and Dart apply
/// still finds the full accepted set listed for the startup drain. A normal
/// field journals a value delivery; an `is_deleted=true` field journals a
/// delete delivery.
#[tokio::test]
async fn bootstrap_from_snapshot_journals_accepted_field_versions() {
    let key_hierarchy = init_key_hierarchy();
    let signing_key_source = make_signing_key();
    let ml_dsa_key_source = make_ml_dsa_keypair();
    let signing_key_sender = make_signing_key();
    let ml_dsa_key_sender = make_ml_dsa_keypair();
    let signing_key_receiver = make_signing_key();
    let source_id = "device-source";
    let sender_id = "device-sender";
    let receiver_id = "device-receiver";
    let server_seq_at = 42;

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage, receiver_id);
    register_device_with_pq(
        &relay,
        &storage,
        source_id,
        &signing_key_source.verifying_key(),
        &ml_dsa_key_source.public_key_bytes(),
    );
    register_device_with_pq(
        &relay,
        &storage,
        sender_id,
        &signing_key_sender.verifying_key(),
        &ml_dsa_key_sender.public_key_bytes(),
    );
    register_device(&relay, &storage, receiver_id, &signing_key_receiver.verifying_key());

    let alive_hlc = Hlc::new(1_710_500_000_000, 0, source_id).to_string();
    let dead_hlc = Hlc::new(1_710_500_000_001, 0, source_id).to_string();
    let snapshot = SnapshotData {
        version: SNAPSHOT_VERSION,
        field_versions: vec![
            FieldVersionEntry {
                entity_table: "tasks".to_string(),
                entity_id: "task-alive".to_string(),
                field_name: "title".to_string(),
                winning_hlc: alive_hlc.clone(),
                winning_device_id: source_id.to_string(),
                winning_op_id: "op-alive".to_string(),
                winning_encoded_value: Some("\"Still here\"".to_string()),
                updated_at: "2024-03-15T00:00:00Z".to_string(),
            },
            FieldVersionEntry {
                entity_table: "tasks".to_string(),
                entity_id: "task-dead".to_string(),
                field_name: "is_deleted".to_string(),
                winning_hlc: dead_hlc.clone(),
                winning_device_id: source_id.to_string(),
                winning_op_id: "op-dead".to_string(),
                winning_encoded_value: Some("true".to_string()),
                updated_at: "2024-03-15T00:00:00Z".to_string(),
            },
        ],
        device_registry: vec![
            snapshot_device_entry(
                source_id,
                &signing_key_source.verifying_key(),
                &ml_dsa_key_source.public_key_bytes(),
            ),
            snapshot_device_entry(
                sender_id,
                &signing_key_sender.verifying_key(),
                &ml_dsa_key_sender.public_key_bytes(),
            ),
        ],
        applied_ops: vec![
            AppliedOpEntry {
                op_id: "op-alive".to_string(),
                sync_id: SYNC_ID.to_string(),
                epoch: 0,
                device_id: source_id.to_string(),
                client_hlc: alive_hlc,
                server_seq: server_seq_at,
                applied_at: "2024-03-15T00:00:00Z".to_string(),
            },
            AppliedOpEntry {
                op_id: "op-dead".to_string(),
                sync_id: SYNC_ID.to_string(),
                epoch: 0,
                device_id: source_id.to_string(),
                client_hlc: dead_hlc,
                server_seq: server_seq_at,
                applied_at: "2024-03-15T00:00:00Z".to_string(),
            },
        ],
        sync_metadata: SyncMetadataEntry {
            sync_id: SYNC_ID.to_string(),
            local_device_id: sender_id.to_string(),
            current_epoch: 0,
            last_pulled_server_seq: server_seq_at,
        },
    };
    let envelope_bytes = make_snapshot_envelope_bytes(
        &snapshot,
        &key_hierarchy,
        &signing_key_sender,
        &ml_dsa_key_sender,
        "snapshot-journal",
        sender_id,
        server_seq_at,
    );
    relay
        .put_snapshot(0, server_seq_at, envelope_bytes, None, None, sender_id.to_string(), None)
        .await
        .unwrap();

    let engine =
        SyncEngine::new(storage.clone(), relay, vec![entity], test_schema(), SyncConfig::default());
    let (count, _changes) = engine.bootstrap_from_snapshot(SYNC_ID, &key_hierarchy).await.unwrap();
    assert_eq!(count, 2);

    // Cursor advanced to the snapshot's server_seq, and the journal lists both
    // accepted field versions — committed in the same tx as the import.
    assert_eq!(
        storage.get_sync_metadata(SYNC_ID).unwrap().unwrap().last_pulled_server_seq,
        server_seq_at
    );

    let journal = storage.list_consumer_deliveries(SYNC_ID, 0, 100).unwrap();
    assert_eq!(journal.len(), 2, "two accepted field versions -> two journal rows");

    let alive = journal.iter().find(|r| r.entity_id == "task-alive").expect("alive row");
    assert_eq!(alive.field_name.as_deref(), Some("title"));
    assert_eq!(alive.encoded_value.as_deref(), Some("\"Still here\""));
    assert!(!alive.is_delete);
    assert_eq!(alive.server_seq, server_seq_at);

    let dead = journal.iter().find(|r| r.entity_id == "task-dead").expect("dead row");
    assert!(dead.is_delete, "is_deleted=true field -> delete delivery");
    assert_eq!(dead.field_name, None);
    assert_eq!(dead.encoded_value, None);
}

/// Regression for the bootstrap half of the delete-absorbing journal blocker: a
/// tombstoned entity whose accepted `is_deleted=true` field is ordered BEFORE its
/// other accepted fields in the snapshot vec must still journal a SINGLE delete
/// delivery — never the surviving sparse fields. Import retains the non-is_deleted
/// fields in field_versions (it is per-field), so without the absorbing drop a
/// freshly paired device would deliver the entity live-with-fields and resurrect
/// it (the old event path handled this via the absorbing snapshot builder).
#[tokio::test]
async fn bootstrap_from_snapshot_journal_is_delete_absorbing_when_is_deleted_ordered_first() {
    let key_hierarchy = init_key_hierarchy();
    let signing_key_source = make_signing_key();
    let ml_dsa_key_source = make_ml_dsa_keypair();
    let signing_key_sender = make_signing_key();
    let ml_dsa_key_sender = make_ml_dsa_keypair();
    let signing_key_receiver = make_signing_key();
    let source_id = "device-source";
    let sender_id = "device-sender";
    let receiver_id = "device-receiver";
    let server_seq_at = 7;

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage, receiver_id);
    register_device_with_pq(
        &relay,
        &storage,
        source_id,
        &signing_key_source.verifying_key(),
        &ml_dsa_key_source.public_key_bytes(),
    );
    register_device_with_pq(
        &relay,
        &storage,
        sender_id,
        &signing_key_sender.verifying_key(),
        &ml_dsa_key_sender.public_key_bytes(),
    );
    register_device(&relay, &storage, receiver_id, &signing_key_receiver.verifying_key());

    let del_hlc = Hlc::new(1_710_500_000_000, 0, source_id).to_string();
    let title_hlc = Hlc::new(1_710_500_000_001, 0, source_id).to_string();
    let snapshot = SnapshotData {
        version: SNAPSHOT_VERSION,
        // `is_deleted` ordered FIRST, then `title` for the SAME entity.
        field_versions: vec![
            FieldVersionEntry {
                entity_table: "tasks".to_string(),
                entity_id: "task-zombie".to_string(),
                field_name: "is_deleted".to_string(),
                winning_hlc: del_hlc.clone(),
                winning_device_id: source_id.to_string(),
                winning_op_id: "op-del".to_string(),
                winning_encoded_value: Some("true".to_string()),
                updated_at: "2024-03-15T00:00:00Z".to_string(),
            },
            FieldVersionEntry {
                entity_table: "tasks".to_string(),
                entity_id: "task-zombie".to_string(),
                field_name: "title".to_string(),
                winning_hlc: title_hlc.clone(),
                winning_device_id: source_id.to_string(),
                winning_op_id: "op-title".to_string(),
                winning_encoded_value: Some("\"Ghost\"".to_string()),
                updated_at: "2024-03-15T00:00:00Z".to_string(),
            },
        ],
        device_registry: vec![
            snapshot_device_entry(
                source_id,
                &signing_key_source.verifying_key(),
                &ml_dsa_key_source.public_key_bytes(),
            ),
            snapshot_device_entry(
                sender_id,
                &signing_key_sender.verifying_key(),
                &ml_dsa_key_sender.public_key_bytes(),
            ),
        ],
        applied_ops: vec![
            AppliedOpEntry {
                op_id: "op-del".to_string(),
                sync_id: SYNC_ID.to_string(),
                epoch: 0,
                device_id: source_id.to_string(),
                client_hlc: del_hlc,
                server_seq: server_seq_at,
                applied_at: "2024-03-15T00:00:00Z".to_string(),
            },
            AppliedOpEntry {
                op_id: "op-title".to_string(),
                sync_id: SYNC_ID.to_string(),
                epoch: 0,
                device_id: source_id.to_string(),
                client_hlc: title_hlc,
                server_seq: server_seq_at,
                applied_at: "2024-03-15T00:00:00Z".to_string(),
            },
        ],
        sync_metadata: SyncMetadataEntry {
            sync_id: SYNC_ID.to_string(),
            local_device_id: sender_id.to_string(),
            current_epoch: 0,
            last_pulled_server_seq: server_seq_at,
        },
    };
    let envelope_bytes = make_snapshot_envelope_bytes(
        &snapshot,
        &key_hierarchy,
        &signing_key_sender,
        &ml_dsa_key_sender,
        "snapshot-zombie",
        sender_id,
        server_seq_at,
    );
    relay
        .put_snapshot(0, server_seq_at, envelope_bytes, None, None, sender_id.to_string(), None)
        .await
        .unwrap();

    let engine =
        SyncEngine::new(storage.clone(), relay, vec![entity], test_schema(), SyncConfig::default());
    engine.bootstrap_from_snapshot(SYNC_ID, &key_hierarchy).await.unwrap();

    // Both fields are retained in field_versions by import (per-field), but the
    // journal carries ONLY the delete delivery — the surviving `title` is dropped.
    let journal = storage.list_consumer_deliveries(SYNC_ID, 0, 100).unwrap();
    let rows: Vec<_> = journal.iter().filter(|r| r.entity_id == "task-zombie").collect();
    assert_eq!(rows.len(), 1, "tombstoned entity journals one delete row, not its fields");
    assert!(rows[0].is_delete);
    assert_eq!(rows[0].field_name, None);
    assert_eq!(rows[0].encoded_value, None);
}

/// Conflict C8 auto-exclusion property: a snapshot field that import decides
/// SkipStale (the receiver already holds a newer local winner) must produce NO
/// consumer_deliveries row — the in-tx post-import equality re-read excludes it
/// automatically, so later import gates (tombstone/snapshot) get the same exclusion for
/// free. Pins the property the plan requires (the all-accepted test alone does
/// not exercise it).
#[tokio::test]
async fn bootstrap_from_snapshot_journal_excludes_skipstale_fields() {
    use prism_sync_core::storage::FieldVersion;

    let key_hierarchy = init_key_hierarchy();
    let signing_key_source = make_signing_key();
    let ml_dsa_key_source = make_ml_dsa_keypair();
    let signing_key_sender = make_signing_key();
    let ml_dsa_key_sender = make_ml_dsa_keypair();
    let signing_key_receiver = make_signing_key();
    let source_id = "device-source";
    let sender_id = "device-sender";
    let receiver_id = "device-receiver";
    let server_seq_at = 9;

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage, receiver_id);
    register_device_with_pq(
        &relay,
        &storage,
        source_id,
        &signing_key_source.verifying_key(),
        &ml_dsa_key_source.public_key_bytes(),
    );
    register_device_with_pq(
        &relay,
        &storage,
        sender_id,
        &signing_key_sender.verifying_key(),
        &ml_dsa_key_sender.public_key_bytes(),
    );
    register_device(&relay, &storage, receiver_id, &signing_key_receiver.verifying_key());

    // The receiver already holds a NEWER local winner for task-stale/title, so
    // the snapshot's older row imports as SkipStale.
    let local_newer_hlc = Hlc::new(1_710_500_999_999, 0, receiver_id).to_string();
    {
        let mut tx = storage.begin_tx().unwrap();
        tx.upsert_field_version(&FieldVersion {
            sync_id: SYNC_ID.to_string(),
            entity_table: "tasks".to_string(),
            entity_id: "task-stale".to_string(),
            field_name: "title".to_string(),
            winning_op_id: "op-local".to_string(),
            winning_device_id: receiver_id.to_string(),
            winning_hlc: local_newer_hlc,
            winning_encoded_value: Some("\"Local wins\"".to_string()),
            updated_at: chrono::Utc::now(),
        })
        .unwrap();
        tx.commit().unwrap();
    }

    let stale_hlc = Hlc::new(1_710_500_000_000, 0, source_id).to_string();
    let fresh_hlc = Hlc::new(1_710_500_000_001, 0, source_id).to_string();
    let snapshot = SnapshotData {
        version: SNAPSHOT_VERSION,
        field_versions: vec![
            // SkipStale: older than the receiver's local winner -> NOT journaled.
            FieldVersionEntry {
                entity_table: "tasks".to_string(),
                entity_id: "task-stale".to_string(),
                field_name: "title".to_string(),
                winning_hlc: stale_hlc.clone(),
                winning_device_id: source_id.to_string(),
                winning_op_id: "op-stale".to_string(),
                winning_encoded_value: Some("\"Snapshot loses\"".to_string()),
                updated_at: "2024-03-15T00:00:00Z".to_string(),
            },
            // Accepted (no local winner) -> journaled.
            FieldVersionEntry {
                entity_table: "tasks".to_string(),
                entity_id: "task-fresh".to_string(),
                field_name: "title".to_string(),
                winning_hlc: fresh_hlc.clone(),
                winning_device_id: source_id.to_string(),
                winning_op_id: "op-fresh".to_string(),
                winning_encoded_value: Some("\"Snapshot wins\"".to_string()),
                updated_at: "2024-03-15T00:00:00Z".to_string(),
            },
        ],
        device_registry: vec![
            snapshot_device_entry(
                source_id,
                &signing_key_source.verifying_key(),
                &ml_dsa_key_source.public_key_bytes(),
            ),
            snapshot_device_entry(
                sender_id,
                &signing_key_sender.verifying_key(),
                &ml_dsa_key_sender.public_key_bytes(),
            ),
        ],
        applied_ops: vec![
            AppliedOpEntry {
                op_id: "op-stale".to_string(),
                sync_id: SYNC_ID.to_string(),
                epoch: 0,
                device_id: source_id.to_string(),
                client_hlc: stale_hlc,
                server_seq: server_seq_at,
                applied_at: "2024-03-15T00:00:00Z".to_string(),
            },
            AppliedOpEntry {
                op_id: "op-fresh".to_string(),
                sync_id: SYNC_ID.to_string(),
                epoch: 0,
                device_id: source_id.to_string(),
                client_hlc: fresh_hlc,
                server_seq: server_seq_at,
                applied_at: "2024-03-15T00:00:00Z".to_string(),
            },
        ],
        sync_metadata: SyncMetadataEntry {
            sync_id: SYNC_ID.to_string(),
            local_device_id: sender_id.to_string(),
            current_epoch: 0,
            last_pulled_server_seq: server_seq_at,
        },
    };
    let envelope_bytes = make_snapshot_envelope_bytes(
        &snapshot,
        &key_hierarchy,
        &signing_key_sender,
        &ml_dsa_key_sender,
        "snapshot-skipstale",
        sender_id,
        server_seq_at,
    );
    relay
        .put_snapshot(0, server_seq_at, envelope_bytes, None, None, sender_id.to_string(), None)
        .await
        .unwrap();

    let engine =
        SyncEngine::new(storage.clone(), relay, vec![entity], test_schema(), SyncConfig::default());
    engine.bootstrap_from_snapshot(SYNC_ID, &key_hierarchy).await.unwrap();

    let journal = storage.list_consumer_deliveries(SYNC_ID, 0, 100).unwrap();
    assert!(
        journal.iter().all(|r| r.entity_id != "task-stale"),
        "SkipStale snapshot field must not be journaled"
    );
    assert_eq!(
        journal.iter().filter(|r| r.entity_id == "task-fresh").count(),
        1,
        "accepted snapshot field is journaled"
    );
}

#[tokio::test]
async fn sync_bootstraps_from_snapshot_when_relay_history_was_pruned() {
    let key_hierarchy = init_key_hierarchy();
    let signing_key_sender = make_signing_key();
    let ml_dsa_key_sender = make_ml_dsa_keypair();
    let signing_key_receiver = make_signing_key();
    let sender_id = "device-sender";
    let receiver_id = "device-receiver";
    let server_seq_at = 77;

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage, receiver_id);
    register_device_with_pq(
        &relay,
        &storage,
        sender_id,
        &signing_key_sender.verifying_key(),
        &ml_dsa_key_sender.public_key_bytes(),
    );
    register_device(&relay, &storage, receiver_id, &signing_key_receiver.verifying_key());

    let snapshot_hlc = Hlc::new(1_710_500_000_000, 0, sender_id).to_string();
    let snapshot = SnapshotData {
        version: SNAPSHOT_VERSION,
        field_versions: vec![FieldVersionEntry {
            entity_table: "tasks".to_string(),
            entity_id: "task-bootstrap".to_string(),
            field_name: "title".to_string(),
            winning_hlc: snapshot_hlc.clone(),
            winning_device_id: sender_id.to_string(),
            winning_op_id: "op-bootstrap-snapshot".to_string(),
            winning_encoded_value: Some("\"Snapshot row\"".to_string()),
            updated_at: "2024-03-15T00:00:00Z".to_string(),
        }],
        device_registry: vec![snapshot_device_entry(
            sender_id,
            &signing_key_sender.verifying_key(),
            &ml_dsa_key_sender.public_key_bytes(),
        )],
        applied_ops: vec![AppliedOpEntry {
            op_id: "op-bootstrap-snapshot".to_string(),
            sync_id: SYNC_ID.to_string(),
            epoch: 0,
            device_id: sender_id.to_string(),
            client_hlc: snapshot_hlc,
            server_seq: server_seq_at,
            applied_at: "2024-03-15T00:00:00Z".to_string(),
        }],
        sync_metadata: SyncMetadataEntry {
            sync_id: SYNC_ID.to_string(),
            local_device_id: sender_id.to_string(),
            current_epoch: 0,
            last_pulled_server_seq: server_seq_at,
        },
    };
    let envelope_bytes = make_snapshot_envelope_bytes(
        &snapshot,
        &key_hierarchy,
        &signing_key_sender,
        &ml_dsa_key_sender,
        "snapshot-pruned-history",
        sender_id,
        server_seq_at,
    );
    relay
        .put_snapshot(0, server_seq_at, envelope_bytes, None, None, sender_id.to_string(), None)
        .await
        .unwrap();
    relay.fail_next_pulls_with(
        1,
        InjectedPullError::MustBootstrapFromSnapshot { first_retained_seq: server_seq_at },
    );

    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity],
        test_schema(),
        SyncConfig::default(),
    );

    let result = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key_receiver, None, receiver_id, 0)
        .await
        .unwrap();

    assert!(result.error.is_none(), "sync should recover via snapshot: {:?}", result.error);
    assert_eq!(relay.pull_call_count(), 2, "sync should retry pull once after snapshot import");
    assert_eq!(
        storage.get_sync_metadata(SYNC_ID).unwrap().unwrap().last_pulled_server_seq,
        server_seq_at
    );
    assert_eq!(result.entity_changes.len(), 1);
    assert_eq!(result.entity_changes[0].fields.get("title"), Some(&"\"Snapshot row\"".to_string()));
}

#[tokio::test]
async fn snapshot_import_rejects_rows_from_untrusted_foreign_device() {
    let key_hierarchy = init_key_hierarchy();
    let signing_key_sender = make_signing_key();
    let ml_dsa_key_sender = make_ml_dsa_keypair();
    let signing_key_receiver = make_signing_key();
    let sender_id = "device-sender";
    let receiver_id = "device-receiver";
    let foreign_id = "device-forged";
    let server_seq_at = 7;

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage, receiver_id);
    register_device_with_pq(
        &relay,
        &storage,
        sender_id,
        &signing_key_sender.verifying_key(),
        &ml_dsa_key_sender.public_key_bytes(),
    );
    register_device(&relay, &storage, receiver_id, &signing_key_receiver.verifying_key());

    let foreign_hlc = Hlc::new(1_710_500_000_000, 0, foreign_id).to_string();
    let snapshot = SnapshotData {
        version: SNAPSHOT_VERSION,
        field_versions: vec![FieldVersionEntry {
            entity_table: "tasks".to_string(),
            entity_id: "task-snapshot".to_string(),
            field_name: "title".to_string(),
            winning_hlc: foreign_hlc.clone(),
            winning_device_id: foreign_id.to_string(),
            winning_op_id: "op-foreign-snapshot".to_string(),
            winning_encoded_value: Some("\"Foreign snapshot row\"".to_string()),
            updated_at: "2024-03-15T00:00:00Z".to_string(),
        }],
        device_registry: Vec::new(),
        applied_ops: Vec::new(),
        sync_metadata: SyncMetadataEntry {
            sync_id: SYNC_ID.to_string(),
            local_device_id: sender_id.to_string(),
            current_epoch: 0,
            last_pulled_server_seq: server_seq_at,
        },
    };
    let envelope_bytes = make_snapshot_envelope_bytes(
        &snapshot,
        &key_hierarchy,
        &signing_key_sender,
        &ml_dsa_key_sender,
        "snapshot-attribution",
        sender_id,
        server_seq_at,
    );
    relay
        .put_snapshot(0, server_seq_at, envelope_bytes, None, None, sender_id.to_string(), None)
        .await
        .unwrap();

    let engine =
        SyncEngine::new(storage.clone(), relay, vec![entity], test_schema(), SyncConfig::default());
    let result = engine.bootstrap_from_snapshot(SYNC_ID, &key_hierarchy).await;

    let err = result.unwrap_err().to_string();
    assert!(err.contains("snapshot field_versions references untrusted device"), "{err}");
    assert!(
        storage.get_field_version(SYNC_ID, "tasks", "task-snapshot", "title").unwrap().is_none(),
        "foreign-attribution snapshot row must not be imported"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// HLC hardening regressions
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn drops_malformed_hlc_op_without_blocking_good_ops_in_same_batch() {
    let sender_id = "device-sender";
    let good_hlc = Hlc::new(current_time_ms() - 1_000, 0, sender_id);

    let good = CrdtChange {
        op_id: "op-good-hlc".to_string(),
        batch_id: Some("batch-attribution".to_string()),
        entity_id: "task-malformed-hlc".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "title".to_string(),
        encoded_value: "\"Accepted title\"".to_string(),
        client_hlc: good_hlc.to_string(),
        is_delete: false,
        device_id: sender_id.to_string(),
        epoch: 0,
        server_seq: None,
    };
    let malformed = CrdtChange {
        op_id: "op-malformed-hlc".to_string(),
        batch_id: Some("batch-attribution".to_string()),
        entity_id: "task-malformed-hlc".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "done".to_string(),
        encoded_value: "true".to_string(),
        client_hlc: "-1:0:device-sender".to_string(),
        is_delete: false,
        device_id: sender_id.to_string(),
        epoch: 0,
        server_seq: None,
    };

    let (result, storage, entity) = pull_injected_sender_batch(vec![good, malformed]).await;

    assert!(result.error.is_none(), "malformed HLC op should be dropped: {:?}", result.error);
    assert_eq!(result.pulled, 1);
    assert_eq!(result.merged, 1);
    assert_eq!(
        entity.get_field("task-malformed-hlc", "title"),
        Some(SyncValue::String("Accepted title".to_string()))
    );
    assert_eq!(entity.get_field("task-malformed-hlc", "done"), None);
    assert!(storage.is_op_applied("op-good-hlc").unwrap());
    assert!(!storage.is_op_applied("op-malformed-hlc").unwrap());
    assert_eq!(
        storage.get_sync_metadata(SYNC_ID).unwrap().unwrap().last_pulled_server_seq,
        1,
        "batch cursor should advance after dropping only the malformed op"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Future-HLC ops are quarantined (not silently dropped) and replayed with
// their ORIGINAL HLC once the receiver's clock is within tolerance.
// ═══════════════════════════════════════════════════════════════════════════

/// Wire up a receiver engine over an explicit storage/relay so a test can run
/// multiple sync passes (e.g. quarantine at a tight drift bound, then replay at
/// a looser one) against the same persisted state. `inject_seq1_batch=false`
/// runs a Phase-0-only cycle (no relay redelivery) to exercise quarantine
/// replay.
async fn f07_sync_once(
    storage: &Arc<RusqliteSyncStorage>,
    relay: &Arc<MockRelay>,
    receiver_id: &str,
    signing_key_receiver: &SigningKey,
    key_hierarchy: &prism_sync_crypto::KeyHierarchy,
    config: SyncConfig,
    entity: Arc<dyn SyncableEntity>,
) -> SyncResult {
    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity],
        test_schema(),
        config,
    );
    engine
        .sync(SYNC_ID, key_hierarchy, signing_key_receiver, None, receiver_id, 0)
        .await
        .unwrap()
}

#[tokio::test]
async fn future_drifted_op_is_quarantined_then_replayed_with_original_hlc() {
    let key_hierarchy = init_key_hierarchy();
    let signing_key_sender = make_signing_key();
    let ml_dsa_key_sender = make_ml_dsa_keypair();
    let signing_key_receiver = make_signing_key();
    let sender_id = "device-sender";
    let receiver_id = "device-receiver";

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage, receiver_id);
    register_device_with_pq(
        &relay,
        &storage,
        sender_id,
        &signing_key_sender.verifying_key(),
        &ml_dsa_key_sender.public_key_bytes(),
    );
    register_device(&relay, &storage, receiver_id, &signing_key_receiver.verifying_key());

    let now_ms = current_time_ms();
    let good_hlc = Hlc::new(now_ms - 1_000, 0, sender_id);
    // 90s into the future — beyond the 1s tolerance for the first pass, but well
    // within the 200s tolerance used for the replay pass.
    let future_hlc = Hlc::new(now_ms + 90_000, 0, sender_id);

    let good = CrdtChange {
        op_id: "op-good-hlc".to_string(),
        batch_id: Some("batch-attribution".to_string()),
        entity_id: "task-hlc-drift".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "title".to_string(),
        encoded_value: "\"Accepted title\"".to_string(),
        client_hlc: good_hlc.to_string(),
        is_delete: false,
        device_id: sender_id.to_string(),
        epoch: 0,
        server_seq: None,
    };
    let future_drifted = CrdtChange {
        op_id: "op-future-hlc".to_string(),
        batch_id: Some("batch-attribution".to_string()),
        entity_id: "task-hlc-drift".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "done".to_string(),
        encoded_value: "true".to_string(),
        client_hlc: future_hlc.to_string(),
        is_delete: false,
        device_id: sender_id.to_string(),
        epoch: 0,
        server_seq: None,
    };

    let envelope = make_encrypted_batch(
        &[good, future_drifted],
        &key_hierarchy,
        &signing_key_sender,
        &ml_dsa_key_sender,
        "batch-attribution",
        sender_id,
    );
    relay.inject_batch(envelope);

    // Pass 1: tight tolerance — the future op is quarantined, not dropped.
    let result = f07_sync_once(
        &storage,
        &relay,
        receiver_id,
        &signing_key_receiver,
        &key_hierarchy,
        SyncConfig { max_clock_drift_ms: 1_000, ..Default::default() },
        entity.clone(),
    )
    .await;

    assert!(result.error.is_none(), "live pull should succeed: {:?}", result.error);
    assert_eq!(result.pulled, 1);
    assert_eq!(result.merged, 1, "only the in-tolerance op applies on pass 1");
    assert_eq!(
        entity.get_field("task-hlc-drift", "title"),
        Some(SyncValue::String("Accepted title".to_string()))
    );
    assert_eq!(entity.get_field("task-hlc-drift", "done"), None);
    assert!(storage.is_op_applied("op-good-hlc").unwrap());
    assert!(
        !storage.is_op_applied("op-future-hlc").unwrap(),
        "future-HLC op must NOT be marked applied",
    );
    assert_eq!(
        storage.get_sync_metadata(SYNC_ID).unwrap().unwrap().last_pulled_server_seq,
        1,
        "cursor advances after applying the in-tolerance ops",
    );
    let quarantined = storage.list_quarantined_ops(SYNC_ID).unwrap();
    assert_eq!(quarantined.len(), 1, "future-HLC op is durably quarantined, not dropped");
    assert_eq!(quarantined[0].op_id, "op-future-hlc");
    assert_eq!(quarantined[0].reason, "future_hlc");
    let original_hlc = quarantined[0].op.client_hlc.clone();
    assert_eq!(original_hlc, future_hlc.to_string(), "the ORIGINAL HLC is preserved for replay");

    // Pass 2: loosen tolerance so the 90s drift is in-bounds; Phase 0 replays it.
    let result = f07_sync_once(
        &storage,
        &relay,
        receiver_id,
        &signing_key_receiver,
        &key_hierarchy,
        SyncConfig { max_clock_drift_ms: 200_000, ..Default::default() },
        entity.clone(),
    )
    .await;
    assert!(result.error.is_none(), "replay pass should succeed: {:?}", result.error);

    assert_eq!(
        entity.get_field("task-hlc-drift", "done"),
        Some(SyncValue::Bool(true)),
        "the quarantined op is applied on replay once drift is within tolerance",
    );
    assert!(storage.is_op_applied("op-future-hlc").unwrap());
    let fv = storage
        .get_field_version(SYNC_ID, "tasks", "task-hlc-drift", "done")
        .unwrap()
        .expect("done has a field_version after replay");
    assert_eq!(
        fv.winning_hlc, original_hlc,
        "replay applies with the op's ORIGINAL HLC so LWW converges across peers",
    );
    assert!(
        storage.list_quarantined_ops(SYNC_ID).unwrap().is_empty(),
        "the quarantine row is deleted after a successful replay",
    );
}

/// A future-HLC op that is still beyond tolerance must NOT be replayed: no
/// applied_ops insert, no quarantine churn, the row is left untouched.
#[tokio::test]
async fn future_drifted_op_still_beyond_tolerance_is_not_replayed() {
    let key_hierarchy = init_key_hierarchy();
    let signing_key_sender = make_signing_key();
    let ml_dsa_key_sender = make_ml_dsa_keypair();
    let signing_key_receiver = make_signing_key();
    let sender_id = "device-sender";
    let receiver_id = "device-receiver";

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage, receiver_id);
    register_device_with_pq(
        &relay,
        &storage,
        sender_id,
        &signing_key_sender.verifying_key(),
        &ml_dsa_key_sender.public_key_bytes(),
    );
    register_device(&relay, &storage, receiver_id, &signing_key_receiver.verifying_key());

    let now_ms = current_time_ms();
    let future_hlc = Hlc::new(now_ms + 300_000, 0, sender_id); // 5 min ahead
    let future_drifted = CrdtChange {
        op_id: "op-far-future".to_string(),
        batch_id: Some("batch-attribution".to_string()),
        entity_id: "task-far".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "done".to_string(),
        encoded_value: "true".to_string(),
        client_hlc: future_hlc.to_string(),
        is_delete: false,
        device_id: sender_id.to_string(),
        epoch: 0,
        server_seq: None,
    };
    let envelope = make_encrypted_batch(
        &[future_drifted],
        &key_hierarchy,
        &signing_key_sender,
        &ml_dsa_key_sender,
        "batch-attribution",
        sender_id,
    );
    relay.inject_batch(envelope);

    // Quarantine, then run several more cycles at the default 60s tolerance —
    // the op stays 5 min ahead the whole time, so nothing should change.
    for _ in 0..3 {
        let result = f07_sync_once(
            &storage,
            &relay,
            receiver_id,
            &signing_key_receiver,
            &key_hierarchy,
            SyncConfig::default(),
            entity.clone(),
        )
        .await;
        assert!(result.error.is_none(), "{:?}", result.error);
    }

    let quarantined = storage.list_quarantined_ops(SYNC_ID).unwrap();
    assert_eq!(quarantined.len(), 1, "row must persist (no churn, no drop) while still far-future");
    assert_eq!(quarantined[0].reason, "future_hlc");
    assert!(!storage.is_op_applied("op-far-future").unwrap());
    assert_eq!(entity.get_field("task-far", "done"), None);
}

/// Convergence: a peer that quarantines a future op then replays it must reach
/// the SAME field_version as a peer that accepted it immediately — even when the
/// quarantining peer makes an interleaved local edit at a LOWER HLC. The future
/// op wins LWW on both, and the C2 supersede rule must NOT fire (the interleaved
/// winner is from a DIFFERENT device).
#[tokio::test]
async fn future_drifted_op_wins_lww_over_lower_interleaved_local_edit_on_replay() {
    use prism_sync_core::storage::{FieldVersion, QuarantinedOp};

    let receiver_id = "device-receiver";
    let sender_id = "device-sender";

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity = Arc::new(MockTaskEntity::new());
    let entity_ref: Arc<dyn SyncableEntity> = entity.clone();
    let signing_key_receiver = make_signing_key();

    setup_sync_metadata(&storage, receiver_id);
    register_device(&relay, &storage, receiver_id, &signing_key_receiver.verifying_key());

    let now_ms = current_time_ms();
    let future_hlc = Hlc::new(now_ms, 5, sender_id); // in-tolerance "now" for replay
    let quarantined_op = CrdtChange {
        op_id: "op-future-conv".to_string(),
        batch_id: Some("batch-conv".to_string()),
        entity_id: "task-conv".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "title".to_string(),
        encoded_value: "\"Sender wins\"".to_string(),
        client_hlc: future_hlc.to_string(),
        is_delete: false,
        device_id: sender_id.to_string(),
        epoch: 0,
        server_seq: None,
    };

    // The receiver already has a LOWER-HLC local edit to the same field from its
    // OWN device — the future op must beat it on replay (and the supersede rule
    // must not evict the quarantined op, since the winner is a different device).
    let local_hlc = Hlc::new(now_ms - 10_000, 0, receiver_id);
    {
        let mut tx = storage.begin_tx().unwrap();
        tx.upsert_field_version(&FieldVersion {
            sync_id: SYNC_ID.to_string(),
            entity_table: "tasks".to_string(),
            entity_id: "task-conv".to_string(),
            field_name: "title".to_string(),
            winning_op_id: "op-local".to_string(),
            winning_device_id: receiver_id.to_string(),
            winning_hlc: local_hlc.to_string(),
            winning_encoded_value: Some("\"Local edit\"".to_string()),
            updated_at: chrono::Utc::now(),
        })
        .unwrap();
        tx.insert_quarantined_op(&QuarantinedOp {
            sync_id: SYNC_ID.to_string(),
            op_id: quarantined_op.op_id.clone(),
            op: quarantined_op.clone(),
            reason: "future_hlc".to_string(),
            server_seq: 1,
            quarantined_at: chrono::Utc::now(),
        })
        .unwrap();
        tx.commit().unwrap();
    }

    let result = f07_sync_once(
        &storage,
        &relay,
        receiver_id,
        &signing_key_receiver,
        &init_key_hierarchy(),
        SyncConfig::default(),
        entity_ref,
    )
    .await;
    assert!(result.error.is_none(), "{:?}", result.error);

    let fv = storage
        .get_field_version(SYNC_ID, "tasks", "task-conv", "title")
        .unwrap()
        .expect("title field_version exists");
    assert_eq!(
        fv.winning_op_id, "op-future-conv",
        "the higher-HLC future op wins LWW over the lower-HLC interleaved local edit",
    );
    assert_eq!(fv.winning_hlc, future_hlc.to_string(), "replay keeps the op's ORIGINAL HLC");
    assert!(storage.is_op_applied("op-future-conv").unwrap());
    assert!(
        storage.list_quarantined_ops(SYNC_ID).unwrap().is_empty(),
        "quarantine row deleted after the replay applied it",
    );
}

/// C2 supersede eviction: once a LATER op from the SAME device wins the same
/// field, the quarantined future-HLC op can never win LWW, so it is EVICTED
/// (deleted) — never replayed — bounding the quarantine backlog.
#[tokio::test]
async fn superseded_future_drifted_op_is_evicted_not_replayed() {
    use prism_sync_core::storage::{FieldVersion, QuarantinedOp};

    let receiver_id = "device-receiver";
    let sender_id = "device-sender";

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity = Arc::new(MockTaskEntity::new());
    let entity_ref: Arc<dyn SyncableEntity> = entity.clone();
    let signing_key_receiver = make_signing_key();

    setup_sync_metadata(&storage, receiver_id);
    register_device(&relay, &storage, receiver_id, &signing_key_receiver.verifying_key());

    let now_ms = current_time_ms();
    // The quarantined future op is in tolerance ("now"), so absent the supersede
    // rule it WOULD replay — proving eviction is what suppresses it.
    let future_hlc = Hlc::new(now_ms, 1, sender_id);
    let quarantined_op = CrdtChange {
        op_id: "op-superseded".to_string(),
        batch_id: Some("batch-sup".to_string()),
        entity_id: "task-sup".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "title".to_string(),
        encoded_value: "\"Stale future value\"".to_string(),
        client_hlc: future_hlc.to_string(),
        is_delete: false,
        device_id: sender_id.to_string(),
        epoch: 0,
        server_seq: None,
    };

    // A LATER op from the SAME sender already won this field (higher HLC).
    let later_hlc = Hlc::new(now_ms + 5_000, 0, sender_id);
    {
        let mut tx = storage.begin_tx().unwrap();
        tx.upsert_field_version(&FieldVersion {
            sync_id: SYNC_ID.to_string(),
            entity_table: "tasks".to_string(),
            entity_id: "task-sup".to_string(),
            field_name: "title".to_string(),
            winning_op_id: "op-later".to_string(),
            winning_device_id: sender_id.to_string(),
            winning_hlc: later_hlc.to_string(),
            winning_encoded_value: Some("\"Newer value\"".to_string()),
            updated_at: chrono::Utc::now(),
        })
        .unwrap();
        tx.insert_quarantined_op(&QuarantinedOp {
            sync_id: SYNC_ID.to_string(),
            op_id: quarantined_op.op_id.clone(),
            op: quarantined_op.clone(),
            reason: "future_hlc".to_string(),
            server_seq: 1,
            quarantined_at: chrono::Utc::now(),
        })
        .unwrap();
        tx.commit().unwrap();
    }
    assert_eq!(storage.list_quarantined_ops(SYNC_ID).unwrap().len(), 1);

    let result = f07_sync_once(
        &storage,
        &relay,
        receiver_id,
        &signing_key_receiver,
        &init_key_hierarchy(),
        SyncConfig::default(),
        entity_ref,
    )
    .await;
    assert!(result.error.is_none(), "{:?}", result.error);

    assert!(
        storage.list_quarantined_ops(SYNC_ID).unwrap().is_empty(),
        "the superseded future-HLC row must be EVICTED (deleted), not held forever",
    );
    assert!(
        !storage.is_op_applied("op-superseded").unwrap(),
        "the superseded op must never be applied (it can't win LWW)",
    );
    let fv = storage
        .get_field_version(SYNC_ID, "tasks", "task-sup", "title")
        .unwrap()
        .unwrap();
    assert_eq!(fv.winning_op_id, "op-later", "the later winner is untouched");
}


/// An envelope declaring a newer ML-DSA generation than the receiver knows
/// (a not-yet-propagated rotation) must STALL — cursor frozen, nothing applied,
/// no advance, push still runs — instead of the old skip-and-advance that
/// permanently lost the batch. Once the receiver imports the gen-1 key, the
/// stalled batch verifies under it and applies.
#[tokio::test]
async fn stale_generation_stalls_then_applies_after_key_import() {
    use prism_sync_core::storage::DeviceRecord;

    let key_hierarchy = init_key_hierarchy();
    let signing_key_local = make_signing_key();
    let signing_key_remote = make_signing_key();
    // The remote rotated to a gen-1 ML-DSA key; the receiver only knows gen 0.
    let ml_dsa_key_remote_gen1 = make_ml_dsa_keypair();
    let local_device = "device-local";
    let remote_device = "device-remote";

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity = Arc::new(MockTaskEntity::new());
    let entity_ref: Arc<dyn SyncableEntity> = entity.clone();

    setup_sync_metadata(&storage, local_device);
    register_device(&relay, &storage, local_device, &signing_key_local.verifying_key());
    // Receiver's local record for the remote is gen 0 with a different key — it
    // has not yet learned the rotation.
    register_device_with_pq(
        &relay,
        &storage,
        remote_device,
        &signing_key_remote.verifying_key(),
        &make_ml_dsa_keypair().public_key_bytes(),
    );

    let hlc = Hlc::new(current_time_ms() - 1_000, 0, remote_device);
    let ops = vec![CrdtChange {
        op_id: "op-generation-mismatch".to_string(),
        batch_id: Some("batch-generation-mismatch".to_string()),
        entity_id: "task-generation-mismatch".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "title".to_string(),
        encoded_value: "\"Rotated edit\"".to_string(),
        client_hlc: hlc.to_string(),
        is_delete: false,
        device_id: remote_device.to_string(),
        epoch: 0,
        server_seq: None,
    }];

    // Batch is signed at generation 1 with the rotated key.
    let envelope = make_encrypted_batch_with_generation(
        &ops,
        &key_hierarchy,
        &signing_key_remote,
        &ml_dsa_key_remote_gen1,
        "batch-generation-mismatch",
        remote_device,
        1,
    );
    let seq = relay.inject_batch(envelope);

    let engine = SyncEngine::new(
        storage.clone(),
        relay,
        vec![entity_ref],
        test_schema(),
        SyncConfig::default(),
    );

    // Cycle 1: gen 1 > local gen 0, no registry to refresh from -> STALL.
    let r1 = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key_local, None, local_device, 0)
        .await
        .unwrap();
    assert!(r1.error.is_none(), "stall is non-fatal: {:?}", r1.error);
    assert_eq!(r1.merged, 0, "nothing applied while stalled");
    assert_eq!(entity.get_field("task-generation-mismatch", "title"), None);
    assert_eq!(
        storage.get_sync_metadata(SYNC_ID).unwrap().unwrap().last_pulled_server_seq,
        0,
        "cursor must stay behind the stale-generation batch (no skip-and-advance)"
    );
    let stalls = storage.list_pull_stalls(SYNC_ID).unwrap();
    assert_eq!(stalls.len(), 1, "the batch must be recorded as stalled");
    assert_eq!(stalls[0].server_seq, seq);
    assert_eq!(stalls[0].reason, "stale_key_generation");
    assert!(
        storage.list_quarantined_pull_batches(SYNC_ID).unwrap().is_empty(),
        "a stall within budget must not quarantine yet"
    );

    // Import the gen-1 key (simulating registry propagation).
    {
        let mut tx = storage.begin_tx().unwrap();
        tx.upsert_device_record(&DeviceRecord {
            sync_id: SYNC_ID.to_string(),
            device_id: remote_device.to_string(),
            ed25519_public_key: signing_key_remote.verifying_key().to_bytes().to_vec(),
            x25519_public_key: vec![0u8; 32],
            ml_dsa_65_public_key: ml_dsa_key_remote_gen1.public_key_bytes(),
            ml_kem_768_public_key: Vec::new(),
            x_wing_public_key: Vec::new(),
            status: "active".to_string(),
            registered_at: chrono::Utc::now(),
            revoked_at: None,
            ml_dsa_key_generation: 1,
        })
        .unwrap();
        tx.commit().unwrap();
    }

    // Cycle 2: the gen-1 key resolves -> the stalled batch verifies and applies.
    let r2 = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key_local, None, local_device, 0)
        .await
        .unwrap();
    assert!(r2.error.is_none(), "{:?}", r2.error);
    assert_eq!(
        entity.get_field("task-generation-mismatch", "title"),
        Some(SyncValue::String("Rotated edit".to_string())),
        "the rotated sender's batch must converge once the gen-1 key propagates"
    );
    assert_eq!(
        storage.get_sync_metadata(SYNC_ID).unwrap().unwrap().last_pulled_server_seq,
        seq,
        "cursor advances after the batch applies"
    );
    assert!(
        storage.list_pull_stalls(SYNC_ID).unwrap().is_empty(),
        "the stall row must clear once the batch resolves"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 1: Push and pull roundtrip
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_push_and_pull_roundtrip() {
    // --- Device A: create ops and push ---
    let key_hierarchy_a = init_key_hierarchy();
    let signing_key_a = make_signing_key();
    let ml_dsa_key_a = make_ml_dsa_keypair();
    let device_a_id = "device-aaa";

    let relay = Arc::new(MockRelay::new());
    let storage_a = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_a: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage_a, device_a_id);
    register_device_with_pq(
        &relay,
        &storage_a,
        device_a_id,
        &signing_key_a.verifying_key(),
        &ml_dsa_key_a.public_key_bytes(),
    );

    // Create ops for device A
    let hlc_a = Hlc::now(device_a_id, None);
    let ops_a = vec![
        CrdtChange {
            op_id: format!("tasks:task-1:title:{}:{}", hlc_a, device_a_id),
            batch_id: Some("batch-a1".to_string()),
            entity_id: "task-1".to_string(),
            entity_table: "tasks".to_string(),
            field_name: "title".to_string(),
            encoded_value: "\"Buy groceries\"".to_string(),
            client_hlc: hlc_a.to_string(),
            is_delete: false,
            device_id: device_a_id.to_string(),
            epoch: 0,
            server_seq: None,
        },
        CrdtChange {
            op_id: format!("tasks:task-1:done:{}:{}", hlc_a, device_a_id),
            batch_id: Some("batch-a1".to_string()),
            entity_id: "task-1".to_string(),
            entity_table: "tasks".to_string(),
            field_name: "done".to_string(),
            encoded_value: "false".to_string(),
            client_hlc: hlc_a.to_string(),
            is_delete: false,
            device_id: device_a_id.to_string(),
            epoch: 0,
            server_seq: None,
        },
    ];

    insert_pending_ops(&storage_a, &ops_a, "batch-a1");

    let engine_a = SyncEngine::new(
        storage_a.clone(),
        relay.clone(),
        vec![entity_a],
        test_schema(),
        SyncConfig::default(),
    );

    // Push from device A
    let result_a = engine_a
        .sync(SYNC_ID, &key_hierarchy_a, &signing_key_a, Some(&ml_dsa_key_a), device_a_id, 0)
        .await
        .unwrap();
    assert!(result_a.error.is_none(), "push failed: {:?}", result_a.error);
    assert_eq!(result_a.pushed, 1, "expected 1 batch pushed");
    assert_eq!(relay.batch_count(), 1, "relay should have 1 batch");

    // --- Device B: pull and verify ---
    let key_hierarchy_b = {
        // Device B needs the same epoch key as A (same sync group).
        // In production this comes from rekey exchange; here we just reuse.
        let mut kh = prism_sync_crypto::KeyHierarchy::new();
        kh.initialize("test-password-b", &[2u8; 16]).unwrap();
        // Copy epoch 0 key from A
        let epoch0 = key_hierarchy_a.epoch_key(0).unwrap();
        kh.store_epoch_key(0, zeroize::Zeroizing::new(epoch0.to_vec()));
        kh
    };
    let signing_key_b = make_signing_key();
    let device_b_id = "device-bbb";

    let storage_b = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity_b = Arc::new(MockTaskEntity::new());
    let entity_b_ref: Arc<dyn SyncableEntity> = entity_b.clone();

    setup_sync_metadata(&storage_b, device_b_id);
    // Device B must know device A's public key for signature verification
    register_device_with_pq(
        &relay,
        &storage_b,
        device_a_id,
        &signing_key_a.verifying_key(),
        &ml_dsa_key_a.public_key_bytes(),
    );
    register_device(&relay, &storage_b, device_b_id, &signing_key_b.verifying_key());

    let engine_b = SyncEngine::new(
        storage_b.clone(),
        relay.clone(),
        vec![entity_b_ref],
        test_schema(),
        SyncConfig::default(),
    );

    let result_b = engine_b
        .sync(SYNC_ID, &key_hierarchy_b, &signing_key_b, None, device_b_id, 0)
        .await
        .unwrap();
    assert!(result_b.error.is_none(), "pull failed: {:?}", result_b.error);
    assert_eq!(result_b.pulled, 1, "expected 1 batch pulled");
    assert_eq!(result_b.merged, 2, "expected 2 ops merged (title + done)");

    // Verify entity data arrived
    let title = entity_b.get_field("task-1", "title");
    assert_eq!(title, Some(SyncValue::String("Buy groceries".to_string())));

    let done = entity_b.get_field("task-1", "done");
    assert_eq!(done, Some(SyncValue::Bool(false)));
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 2: Conflict resolution — higher HLC wins
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_conflict_resolution() {
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

    // Local device wrote title="Local Title" at a recent HLC
    let now_ms =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis()
            as i64;
    let hlc_local = Hlc::new(now_ms - 5000, 0, local_device);

    // Seed a field_version for the local write so merge sees it as the incumbent
    {
        use prism_sync_core::storage::{FieldVersion, SyncStorage};
        let mut tx = storage.begin_tx().unwrap();
        tx.upsert_field_version(&FieldVersion {
            sync_id: SYNC_ID.to_string(),
            entity_table: "tasks".to_string(),
            entity_id: "task-conflict".to_string(),
            field_name: "title".to_string(),
            winning_op_id: "local-op-1".to_string(),
            winning_device_id: local_device.to_string(),
            winning_hlc: hlc_local.to_string(),
            winning_encoded_value: None,
            updated_at: chrono::Utc::now(),
        })
        .unwrap();
        tx.commit().unwrap();
    }

    // Remote device wrote title="Remote Title" at a later HLC (HIGHER — should win)
    let hlc_remote = Hlc::new(now_ms - 2000, 0, remote_device);
    let remote_ops = vec![CrdtChange {
        op_id: format!("tasks:task-conflict:title:{}:{}", hlc_remote, remote_device),
        batch_id: Some("batch-remote".to_string()),
        entity_id: "task-conflict".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "title".to_string(),
        encoded_value: "\"Remote Title\"".to_string(),
        client_hlc: hlc_remote.to_string(),
        is_delete: false,
        device_id: remote_device.to_string(),
        epoch: 0,
        server_seq: None,
    }];

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
    assert_eq!(result.merged, 1, "remote op should win and be applied");

    // Remote's higher HLC should have won
    let title = entity.get_field("task-conflict", "title");
    assert_eq!(
        title,
        Some(SyncValue::String("Remote Title".to_string())),
        "Higher HLC (remote) should win the conflict"
    );

    // Verify field_version was updated to reflect remote winner
    {
        use prism_sync_core::storage::SyncStorage;
        let fv = storage
            .get_field_version(SYNC_ID, "tasks", "task-conflict", "title")
            .unwrap()
            .expect("field_version should exist");
        assert_eq!(fv.winning_device_id, remote_device);
        assert_eq!(fv.winning_hlc, hlc_remote.to_string());
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 3: Signature verification — wrong signature is rejected
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_signature_verification() {
    let key_hierarchy = init_key_hierarchy();
    let signing_key_local = make_signing_key();
    let signing_key_remote = make_signing_key();
    let ml_dsa_key_remote = make_ml_dsa_keypair();
    let signing_key_attacker = make_signing_key(); // different key!
    let ml_dsa_key_attacker = make_ml_dsa_keypair(); // different key!
    let local_device = "device-local";
    let remote_device = "device-remote";

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage, local_device);
    register_device(&relay, &storage, local_device, &signing_key_local.verifying_key());
    // Register remote device with its REAL public key
    register_device_with_pq(
        &relay,
        &storage,
        remote_device,
        &signing_key_remote.verifying_key(),
        &ml_dsa_key_remote.public_key_bytes(),
    );

    // Create a batch signed with the ATTACKER's key (not the remote device's)
    let hlc = Hlc::now(remote_device, None);
    let ops = vec![CrdtChange {
        op_id: "attacker-op-1".to_string(),
        batch_id: Some("batch-evil".to_string()),
        entity_id: "task-evil".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "title".to_string(),
        encoded_value: "\"Evil Title\"".to_string(),
        client_hlc: hlc.to_string(),
        is_delete: false,
        device_id: remote_device.to_string(), // claims to be remote
        epoch: 0,
        server_seq: None,
    }];

    // Sign with attacker's key (not the registered remote key)
    let envelope = make_encrypted_batch(
        &ops,
        &key_hierarchy,
        &signing_key_attacker,
        &ml_dsa_key_attacker,
        "batch-evil",
        remote_device,
    );
    relay.inject_batch(envelope);

    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity],
        test_schema(),
        SyncConfig::default(),
    );

    let result = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key_local, None, local_device, 0)
        .await
        .unwrap();

    // Bad-signature batches are skipped (not merged), not fatal errors.
    // The batch is counted as pulled (server_seq advanced) but not merged.
    assert!(
        result.error.is_none(),
        "Signature failure should skip the batch, not abort sync: {:?}",
        result.error
    );
    assert_eq!(result.pulled, 1, "Bad batch should still be counted as pulled");
    assert_eq!(result.merged, 0, "Bad batch should NOT be merged");
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 4: Payload hash verification — tampered ciphertext content rejected
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_payload_hash_verification() {
    let key_hierarchy = init_key_hierarchy();
    let signing_key_local = make_signing_key();
    let signing_key_remote = make_signing_key();
    let ml_dsa_key_remote = make_ml_dsa_keypair();
    let local_device = "device-local";
    let remote_device = "device-remote";

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage, local_device);
    register_device(&relay, &storage, local_device, &signing_key_local.verifying_key());
    register_device_with_pq(
        &relay,
        &storage,
        remote_device,
        &signing_key_remote.verifying_key(),
        &ml_dsa_key_remote.public_key_bytes(),
    );

    // Build a valid batch first
    let hlc = Hlc::now(remote_device, None);
    let ops_original = vec![CrdtChange {
        op_id: "legit-op-1".to_string(),
        batch_id: Some("batch-tampered".to_string()),
        entity_id: "task-legit".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "title".to_string(),
        encoded_value: "\"Original Title\"".to_string(),
        client_hlc: hlc.to_string(),
        is_delete: false,
        device_id: remote_device.to_string(),
        epoch: 0,
        server_seq: None,
    }];

    // Compute payload_hash from the ORIGINAL ops
    let plaintext_original = CrdtChange::encode_batch(&ops_original).unwrap();
    let payload_hash_original = batch_signature::compute_payload_hash(&plaintext_original);

    // Now encrypt DIFFERENT content (tampered ops) but sign with the original hash
    let ops_tampered = vec![CrdtChange {
        op_id: "legit-op-1".to_string(),
        batch_id: Some("batch-tampered".to_string()),
        entity_id: "task-legit".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "title".to_string(),
        encoded_value: "\"TAMPERED Title\"".to_string(), // different!
        client_hlc: hlc.to_string(),
        is_delete: false,
        device_id: remote_device.to_string(),
        epoch: 0,
        server_seq: None,
    }];

    let plaintext_tampered = CrdtChange::encode_batch(&ops_tampered).unwrap();

    let epoch_key = key_hierarchy.epoch_key(0).unwrap();
    let aad = sync_aad::build_sync_aad(SYNC_ID, remote_device, 0, "batch-tampered", "ops");
    let (ciphertext, nonce) =
        prism_sync_crypto::aead::xchacha_encrypt_for_sync(epoch_key, &plaintext_tampered, &aad)
            .unwrap();

    // Sign with the ORIGINAL payload_hash (mismatches the encrypted content)
    let envelope = batch_signature::sign_batch(
        &signing_key_remote,
        &ml_dsa_key_remote,
        SYNC_ID,
        0,
        "batch-tampered",
        "ops",
        remote_device,
        0,
        &payload_hash_original, // hash of original, but ciphertext is tampered
        nonce,
        ciphertext,
    )
    .unwrap();

    let seq = relay.inject_batch(envelope);

    let (event_tx, mut event_rx) =
        tokio::sync::broadcast::channel::<prism_sync_core::events::SyncEvent>(32);
    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity],
        test_schema(),
        SyncConfig::default(),
    )
    .with_event_sink(event_tx.clone());

    let result = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key_local, None, local_device, 0)
        .await
        .unwrap();

    // A payload-hash mismatch quarantines the whole envelope and advances
    // the cursor rather than hard-wedging pull (and the push phase) forever.
    assert!(result.error.is_none(), "poison batch must not surface a terminal error: {:?}", result.error);
    assert_eq!(result.merged, 0, "no op from the tampered batch may be applied");
    assert_eq!(
        storage.get_sync_metadata(SYNC_ID).unwrap().unwrap().last_pulled_server_seq,
        seq,
        "quarantined batch must advance the pull cursor"
    );

    let quarantined = storage.list_quarantined_pull_batches(SYNC_ID).unwrap();
    assert_eq!(quarantined.len(), 1);
    assert_eq!(quarantined[0].reason, "payload_hash_mismatch");
    assert_eq!(quarantined[0].server_seq, seq);

    let mut saw_event = false;
    while let Ok(event) = event_rx.try_recv() {
        if let prism_sync_core::events::SyncEvent::PullBatchQuarantined { reason, .. } = event {
            if reason == "payload_hash_mismatch" {
                saw_event = true;
            }
        }
    }
    assert!(saw_event, "expected a PullBatchQuarantined event with reason payload_hash_mismatch");
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 5: Ack is sent after pull with correct max_server_seq
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_sync_sends_ack_after_pull() {
    let key_hierarchy = init_key_hierarchy();
    let signing_key_local = make_signing_key();
    let signing_key_remote = make_signing_key();
    let ml_dsa_key_remote = make_ml_dsa_keypair();
    let local_device = "device-local";
    let remote_device = "device-remote";

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage, local_device);
    register_device(&relay, &storage, local_device, &signing_key_local.verifying_key());
    register_device_with_pq(
        &relay,
        &storage,
        remote_device,
        &signing_key_remote.verifying_key(),
        &ml_dsa_key_remote.public_key_bytes(),
    );

    // Inject a batch from the remote device
    let hlc = Hlc::now(remote_device, None);
    let ops = vec![CrdtChange {
        op_id: format!("tasks:t1:title:{}:{}", hlc, remote_device),
        batch_id: Some("batch-1".to_string()),
        entity_id: "t1".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "title".to_string(),
        encoded_value: "\"Hello\"".to_string(),
        client_hlc: hlc.to_string(),
        is_delete: false,
        device_id: remote_device.to_string(),
        epoch: 0,
        server_seq: None,
    }];
    let envelope = make_encrypted_batch(
        &ops,
        &key_hierarchy,
        &signing_key_remote,
        &ml_dsa_key_remote,
        "batch-1",
        remote_device,
    );
    let injected_seq = relay.inject_batch(envelope);

    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity],
        test_schema(),
        SyncConfig::default(),
    );

    let result = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key_local, None, local_device, 0)
        .await
        .unwrap();
    assert!(result.error.is_none(), "sync failed: {:?}", result.error);

    // Yield to let the fire-and-forget ack task complete
    tokio::task::yield_now().await;

    // Ack reports the local pull cursor (ack-equals-cursor). With the single
    // batch fully applied the cursor equals the injected seq, so the ack matches.
    let acks = relay.ack_calls();
    assert_eq!(acks.len(), 1, "expected exactly 1 ack call");
    assert_eq!(acks[0], injected_seq, "ack should report the local pull cursor after applying the batch");
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 6: Ack failure does not abort sync
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_ack_failure_does_not_abort_sync() {
    let key_hierarchy = init_key_hierarchy();
    let signing_key_local = make_signing_key();
    let signing_key_remote = make_signing_key();
    let ml_dsa_key_remote = make_ml_dsa_keypair();
    let local_device = "device-local";
    let remote_device = "device-remote";

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage, local_device);
    register_device(&relay, &storage, local_device, &signing_key_local.verifying_key());
    register_device_with_pq(
        &relay,
        &storage,
        remote_device,
        &signing_key_remote.verifying_key(),
        &ml_dsa_key_remote.public_key_bytes(),
    );

    let hlc = Hlc::now(remote_device, None);
    let ops = vec![CrdtChange {
        op_id: format!("tasks:t1:title:{}:{}", hlc, remote_device),
        batch_id: Some("batch-1".to_string()),
        entity_id: "t1".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "title".to_string(),
        encoded_value: "\"Hello\"".to_string(),
        client_hlc: hlc.to_string(),
        is_delete: false,
        device_id: remote_device.to_string(),
        epoch: 0,
        server_seq: None,
    }];
    let envelope = make_encrypted_batch(
        &ops,
        &key_hierarchy,
        &signing_key_remote,
        &ml_dsa_key_remote,
        "batch-1",
        remote_device,
    );
    relay.inject_batch(envelope);

    // Make ack fail
    relay.set_ack_error("simulated network failure");

    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity],
        test_schema(),
        SyncConfig::default(),
    );

    let result = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key_local, None, local_device, 0)
        .await
        .unwrap();

    // Sync should succeed despite ack failure
    assert!(result.error.is_none(), "ack failure should not cause sync error: {:?}", result.error);
    assert_eq!(result.pulled, 1, "batch should still be pulled");
    assert_eq!(result.merged, 1, "ops should still be merged");
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 7: Pruning runs when min_acked_seq is available
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_sync_prunes_with_min_acked_seq() {
    let key_hierarchy = init_key_hierarchy();
    let signing_key_local = make_signing_key();
    let signing_key_remote = make_signing_key();
    let ml_dsa_key_remote = make_ml_dsa_keypair();
    let local_device = "device-local";
    let remote_device = "device-remote";

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage, local_device);
    register_device(&relay, &storage, local_device, &signing_key_local.verifying_key());
    register_device_with_pq(
        &relay,
        &storage,
        remote_device,
        &signing_key_remote.verifying_key(),
        &ml_dsa_key_remote.public_key_bytes(),
    );

    // Inject and pull a batch first so applied_ops get populated
    let hlc = Hlc::now(remote_device, None);
    let ops = vec![CrdtChange {
        op_id: format!("tasks:t1:title:{}:{}", hlc, remote_device),
        batch_id: Some("batch-1".to_string()),
        entity_id: "t1".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "title".to_string(),
        encoded_value: "\"Hello\"".to_string(),
        client_hlc: hlc.to_string(),
        is_delete: false,
        device_id: remote_device.to_string(),
        epoch: 0,
        server_seq: None,
    }];
    let envelope = make_encrypted_batch(
        &ops,
        &key_hierarchy,
        &signing_key_remote,
        &ml_dsa_key_remote,
        "batch-1",
        remote_device,
    );
    relay.inject_batch(envelope);

    // Set min_acked_seq high enough to prune the batch we just pulled
    relay.set_min_acked_seq(100);

    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity],
        test_schema(),
        SyncConfig::default(),
    );

    let result = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key_local, None, local_device, 0)
        .await
        .unwrap();
    assert!(result.error.is_none(), "sync failed: {:?}", result.error);

    // Should have pruned the applied_ops for the batch we pulled
    assert!(
        result.pruned > 0,
        "expected pruning to have cleaned up ops, got pruned={}",
        result.pruned
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 8: Pruning runs on empty pull when min_acked_seq is set
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_prune_runs_on_empty_pull() {
    use prism_sync_core::storage::{AppliedOp, SyncStorage};

    let key_hierarchy = init_key_hierarchy();
    let signing_key = make_signing_key();
    let device_id = "device-local";

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage, device_id);
    register_device(&relay, &storage, device_id, &signing_key.verifying_key());

    // Manually insert an applied_op with a low server_seq
    {
        let mut tx = storage.begin_tx().unwrap();
        tx.insert_applied_op(&AppliedOp {
            op_id: "old-op-1".to_string(),
            sync_id: SYNC_ID.to_string(),
            epoch: 0,
            device_id: "device-remote".to_string(),
            client_hlc: "0:0:device-remote".to_string(),
            server_seq: 5,
            applied_at: chrono::Utc::now(),
        })
        .unwrap();
        tx.commit().unwrap();
    }

    // No batches to pull, but min_acked_seq is above our applied_op
    relay.set_min_acked_seq(10);

    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity],
        test_schema(),
        SyncConfig::default(),
    );

    let result =
        engine.sync(SYNC_ID, &key_hierarchy, &signing_key, None, device_id, 0).await.unwrap();
    assert!(result.error.is_none(), "sync failed: {:?}", result.error);

    // Verify the old applied_op was pruned
    assert!(result.pruned > 0, "expected pruning on empty pull with min_acked_seq=10");

    // Verify the op is actually gone from storage
    assert!(
        !storage.is_op_applied("old-op-1").unwrap(),
        "old-op-1 should have been pruned from applied_ops"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 9: No pruning when min_acked_seq is None
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_no_pruning_without_min_acked_seq() {
    use prism_sync_core::storage::{AppliedOp, SyncStorage};

    let key_hierarchy = init_key_hierarchy();
    let signing_key = make_signing_key();
    let device_id = "device-local";

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage, device_id);
    register_device(&relay, &storage, device_id, &signing_key.verifying_key());

    // Insert an applied_op
    {
        let mut tx = storage.begin_tx().unwrap();
        tx.insert_applied_op(&AppliedOp {
            op_id: "keep-me".to_string(),
            sync_id: SYNC_ID.to_string(),
            epoch: 0,
            device_id: "device-remote".to_string(),
            client_hlc: "0:0:device-remote".to_string(),
            server_seq: 5,
            applied_at: chrono::Utc::now(),
        })
        .unwrap();
        tx.commit().unwrap();
    }

    // min_acked_seq is None (default) — no pruning should happen

    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity],
        test_schema(),
        SyncConfig::default(),
    );

    let result =
        engine.sync(SYNC_ID, &key_hierarchy, &signing_key, None, device_id, 0).await.unwrap();
    assert!(result.error.is_none(), "sync failed: {:?}", result.error);
    assert_eq!(result.pruned, 0, "should not prune without min_acked_seq");

    // Op should still exist
    assert!(storage.is_op_applied("keep-me").unwrap(), "op should not have been pruned");
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 10: Push without ML-DSA key errors
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn push_without_ml_dsa_key_errors() {
    let key_hierarchy = init_key_hierarchy();
    let signing_key = make_signing_key();
    let ml_dsa_key = make_ml_dsa_keypair();
    let device_id = "device-local";

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage, device_id);
    register_device_with_pq(
        &relay,
        &storage,
        device_id,
        &signing_key.verifying_key(),
        &ml_dsa_key.public_key_bytes(),
    );

    // Insert pending ops so there is something to push
    let hlc = Hlc::now(device_id, None);
    let ops = vec![CrdtChange {
        op_id: format!("tasks:t1:title:{}:{}", hlc, device_id),
        batch_id: Some("batch-nopq".to_string()),
        entity_id: "t1".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "title".to_string(),
        encoded_value: "\"Hello\"".to_string(),
        client_hlc: hlc.to_string(),
        is_delete: false,
        device_id: device_id.to_string(),
        epoch: 0,
        server_seq: None,
    }];
    insert_pending_ops(&storage, &ops, "batch-nopq");

    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity],
        test_schema(),
        SyncConfig::default(),
    );

    // Call sync with None for ml_dsa_signing_key — push should fail
    let result =
        engine.sync(SYNC_ID, &key_hierarchy, &signing_key, None, device_id, 0).await.unwrap();

    assert!(result.error.is_some(), "Expected an error when pushing without ML-DSA signing key");
    let err_msg = result.error.unwrap();
    assert!(
        err_msg.contains("ML-DSA signing key required"),
        "Error should mention ML-DSA signing key required, got: {err_msg}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Push at current-epoch semantics (Bucket 3 of sync-robustness plan)
// ═══════════════════════════════════════════════════════════════════════════

/// Helper: seed epoch 1 key into a KeyHierarchy derived from epoch 0.
fn seed_epoch_1_key(kh: &mut prism_sync_crypto::KeyHierarchy) {
    // 32 deterministic bytes — the actual key value doesn't matter for
    // these tests; only that the hierarchy has something at epoch 1.
    kh.store_epoch_key(1, zeroize::Zeroizing::new(vec![0xCDu8; 32]));
}

/// Helper: overwrite `current_epoch` in `sync_metadata`.
fn set_metadata_current_epoch(storage: &RusqliteSyncStorage, device_id: &str, epoch: i32) {
    use prism_sync_core::storage::SyncStorage;
    let mut tx = storage.begin_tx().unwrap();
    tx.upsert_sync_metadata(&prism_sync_core::SyncMetadata {
        sync_id: SYNC_ID.to_string(),
        local_device_id: device_id.to_string(),
        current_epoch: epoch,
        last_pulled_server_seq: 0,
        last_pushed_at: None,
        last_successful_sync_at: None,
        registered_at: Some(chrono::Utc::now()),
        needs_rekey: false,
        last_imported_registry_version: None,
        relay_log_token: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    })
    .unwrap();
    tx.commit().unwrap();
}

fn make_op(device_id: &str, batch_id: &str, epoch: i32, suffix: &str) -> CrdtChange {
    let hlc = Hlc::now(device_id, None);
    CrdtChange {
        op_id: format!("tasks:task-{suffix}:title:{hlc}:{device_id}"),
        batch_id: Some(batch_id.to_string()),
        entity_id: format!("task-{suffix}"),
        entity_table: "tasks".to_string(),
        field_name: "title".to_string(),
        encoded_value: "\"hello\"".to_string(),
        client_hlc: hlc.to_string(),
        is_delete: false,
        device_id: device_id.to_string(),
        epoch,
        server_seq: None,
    }
}

/// If the group rotates from epoch 0 -> 1 while ops are still pending at
/// epoch 0, the push must re-tag the envelope to the current epoch (1)
/// so the relay's `envelope.epoch == group.current_epoch` check succeeds.
#[tokio::test]
async fn push_uses_current_epoch_not_stored_op_epoch() {
    let mut key_hierarchy = init_key_hierarchy();
    seed_epoch_1_key(&mut key_hierarchy);

    let signing_key = make_signing_key();
    let ml_dsa_key = make_ml_dsa_keypair();
    let device_id = "device-push-curr";

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage, device_id);
    register_device_with_pq(
        &relay,
        &storage,
        device_id,
        &signing_key.verifying_key(),
        &ml_dsa_key.public_key_bytes(),
    );

    // Pending op was created at epoch 0.
    let ops = vec![make_op(device_id, "batch-push-curr", 0, "1")];
    insert_pending_ops(&storage, &ops, "batch-push-curr");

    // Group has since rotated to epoch 1.
    set_metadata_current_epoch(&storage, device_id, 1);

    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity],
        test_schema(),
        SyncConfig::default(),
    );

    let result = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key, Some(&ml_dsa_key), device_id, 0)
        .await
        .unwrap();
    assert!(result.error.is_none(), "push should succeed at re-tagged epoch: {:?}", result.error);
    assert_eq!(result.pushed, 1, "expected 1 batch pushed");
    assert_eq!(relay.batch_count(), 1, "relay should have 1 envelope");

    // The relay stores StoredBatch with envelope.epoch — we can't poke
    // into the private state, but pull_changes returns the envelopes.
    let pulled = relay.pull_changes(0).await.unwrap();
    assert_eq!(pulled.batches.len(), 1);
    assert_eq!(
        pulled.batches[0].envelope.epoch, 1,
        "envelope must be re-tagged to current_epoch (1)"
    );
}

/// The push phase stops at `push_batch_cap` batches per cycle and flags
/// `push_incomplete`; a second cycle drains the remainder and clears the flag.
#[tokio::test]
async fn push_caps_batches_per_cycle_and_flags_incomplete() {
    let key_hierarchy = init_key_hierarchy();
    let signing_key = make_signing_key();
    let ml_dsa_key = make_ml_dsa_keypair();
    let device_id = "device-push-cap";

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage, device_id);
    register_device_with_pq(
        &relay,
        &storage,
        device_id,
        &signing_key.verifying_key(),
        &ml_dsa_key.public_key_bytes(),
    );

    // Three local batches queued for push.
    for i in 0..3 {
        let ops = vec![make_op(device_id, &format!("batch-{i}"), 0, &i.to_string())];
        insert_pending_ops(&storage, &ops, &format!("batch-{i}"));
    }

    let config = SyncConfig { push_batch_cap: 2, ..Default::default() };
    let engine =
        SyncEngine::new(storage.clone(), relay.clone(), vec![entity], test_schema(), config);

    // Cycle 1: the cap stops the push at 2 and flags more remaining.
    let r1 = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key, Some(&ml_dsa_key), device_id, 0)
        .await
        .unwrap();
    assert_eq!(r1.pushed, 2, "first cycle pushes exactly the cap");
    assert!(r1.push_incomplete, "first cycle flags more to push");
    assert_eq!(relay.batch_count(), 2);

    // Cycle 2: drains the remaining batch and clears the flag.
    let r2 = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key, Some(&ml_dsa_key), device_id, 0)
        .await
        .unwrap();
    assert_eq!(r2.pushed, 1, "second cycle pushes the remainder");
    assert!(!r2.push_incomplete, "second cycle is complete");
    assert_eq!(relay.batch_count(), 3);
}

/// The push queue is ordered by typed logical HLC, not wall-clock
/// `created_at`. A create batch (earlier HLC) and a later update batch for the
/// same entity are queued; the update's `created_at` is doctored 90s earlier
/// than the create's, simulating a backward clock step while the backlog sat
/// queued. The old `ORDER BY MIN(created_at)` would have pushed the update
/// first — which makes the receiver's non-strict apply silently drop the
/// NOT-NULL create. The typed-HLC sort keeps emission order so the relay
/// receives the create strictly before the update.
#[tokio::test]
async fn push_orders_by_hlc_not_wallclock_after_backward_step() {
    let key_hierarchy = init_key_hierarchy();
    let signing_key = make_signing_key();
    let ml_dsa_key = make_ml_dsa_keypair();
    let device_id = "device-push-order";

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage, device_id);
    register_device_with_pq(
        &relay,
        &storage,
        device_id,
        &signing_key.verifying_key(),
        &ml_dsa_key.public_key_bytes(),
    );

    // Two batches for the same entity, emitted in HLC order: create first
    // (counter 0), update second (counter 1). The HLCs are explicit so the
    // ordering does not depend on wall-clock resolution.
    let base_ts = 1_778_947_200_000_i64;
    let create_hlc = Hlc::new(base_ts, 0, device_id);
    let update_hlc = Hlc::new(base_ts, 1, device_id);
    let create_op = CrdtChange {
        op_id: format!("tasks:task-1:title:{create_hlc}:{device_id}"),
        batch_id: Some("batch-create".to_string()),
        entity_id: "task-1".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "title".to_string(),
        encoded_value: "\"created\"".to_string(),
        client_hlc: create_hlc.to_string(),
        is_delete: false,
        device_id: device_id.to_string(),
        epoch: 0,
        server_seq: None,
    };
    let update_op = CrdtChange {
        op_id: format!("tasks:task-1:title:{update_hlc}:{device_id}"),
        batch_id: Some("batch-update".to_string()),
        entity_id: "task-1".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "title".to_string(),
        encoded_value: "\"updated\"".to_string(),
        client_hlc: update_hlc.to_string(),
        is_delete: false,
        device_id: device_id.to_string(),
        epoch: 0,
        server_seq: None,
    };

    // The create batch carries a normal emit time; the later update batch
    // carries one 90s earlier, simulating a backward wall-clock step.
    let create_at = chrono::Utc::now();
    let update_at = create_at - chrono::Duration::seconds(90);
    // Insert the update first so the result cannot depend on insertion order.
    insert_pending_ops_at(&storage, std::slice::from_ref(&update_op), "batch-update", update_at);
    insert_pending_ops_at(&storage, std::slice::from_ref(&create_op), "batch-create", create_at);

    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity],
        test_schema(),
        SyncConfig::default(),
    );

    let result = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key, Some(&ml_dsa_key), device_id, 0)
        .await
        .unwrap();
    assert!(result.error.is_none(), "push should succeed: {:?}", result.error);
    assert_eq!(result.pushed, 2, "both batches must push");

    let order = relay.push_call_batch_ids();
    assert_eq!(
        order,
        vec!["batch-create".to_string(), "batch-update".to_string()],
        "the create batch (earlier HLC) must reach the relay before the later \
         update even though the update's created_at is 90s earlier (F39)"
    );
}

/// Degenerate case: metadata claims current_epoch = N but the KeyHierarchy
/// has no key at N. Push must fail with a clear error, NOT silently fall
/// back to an older epoch key. It must bubble as `MissingEpochKey` so the
/// higher-level sync service can recover the key and retry the push.
#[tokio::test]
async fn push_still_fails_when_current_epoch_key_missing() {
    let key_hierarchy = init_key_hierarchy(); // only epoch 0 available

    let signing_key = make_signing_key();
    let ml_dsa_key = make_ml_dsa_keypair();
    let device_id = "device-push-missing-key";

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage, device_id);
    register_device_with_pq(
        &relay,
        &storage,
        device_id,
        &signing_key.verifying_key(),
        &ml_dsa_key.public_key_bytes(),
    );

    let ops = vec![make_op(device_id, "batch-missing-key", 0, "1")];
    insert_pending_ops(&storage, &ops, "batch-missing-key");
    set_metadata_current_epoch(&storage, device_id, 2); // no key for epoch 2

    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity],
        test_schema(),
        SyncConfig::default(),
    );

    let err = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key, Some(&ml_dsa_key), device_id, 0)
        .await
        .expect_err("push must fail when current_epoch key is missing");
    assert!(matches!(err, CoreError::MissingEpochKey { epoch: 2 }), "unexpected error: {err}");
}

/// If the stored op epoch is somehow *higher* than sync_metadata
/// current_epoch (shouldn't happen in practice), the defensive `.max`
/// keeps the push at the higher value so it doesn't regress to a stale
/// epoch. Exercises the `current_epoch.max(ops[0].epoch)` branch.
#[tokio::test]
async fn push_honors_max_of_current_and_op_epoch() {
    let mut key_hierarchy = init_key_hierarchy();
    seed_epoch_1_key(&mut key_hierarchy);

    let signing_key = make_signing_key();
    let ml_dsa_key = make_ml_dsa_keypair();
    let device_id = "device-push-max";

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage, device_id);
    register_device_with_pq(
        &relay,
        &storage,
        device_id,
        &signing_key.verifying_key(),
        &ml_dsa_key.public_key_bytes(),
    );

    // Op claims epoch 1 (unexpected but possible after a recovered rekey);
    // sync_metadata still shows 0. Push must use epoch 1.
    let ops = vec![make_op(device_id, "batch-max", 1, "1")];
    insert_pending_ops(&storage, &ops, "batch-max");
    set_metadata_current_epoch(&storage, device_id, 0);

    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity],
        test_schema(),
        SyncConfig::default(),
    );

    let result = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key, Some(&ml_dsa_key), device_id, 0)
        .await
        .unwrap();
    assert!(result.error.is_none(), "push must succeed: {:?}", result.error);

    let pulled = relay.pull_changes(0).await.unwrap();
    assert_eq!(pulled.batches.len(), 1);
    assert_eq!(pulled.batches[0].envelope.epoch, 1, "envelope must be at max(current=0, op=1) = 1");
}

// ═══════════════════════════════════════════════════════════════════════════
// Phase 1B: push-quarantine for oversized batches
// ═══════════════════════════════════════════════════════════════════════════

/// A 413 from the relay must quarantine the offending batch, keep its
/// `pending_ops` rows intact, leave following batches eligible for push,
/// and emit `SyncEvent::QuarantinedBatch`. The cycle as a whole must
/// succeed — no terminal sync error toast.
#[tokio::test]
async fn push_quarantines_batch_on_relay_413_and_continues_other_batches() {
    let key_hierarchy = init_key_hierarchy();
    let signing_key = make_signing_key();
    let ml_dsa_key = make_ml_dsa_keypair();
    let device_id = "device-413-quarantine";

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage, device_id);
    register_device_with_pq(
        &relay,
        &storage,
        device_id,
        &signing_key.verifying_key(),
        &ml_dsa_key.public_key_bytes(),
    );

    // Two batches: the first will be rejected with 413, the second must still push.
    let bad_op = make_op(device_id, "batch-bad", 0, "bad");
    let good_op = make_op(device_id, "batch-good", 0, "good");
    insert_pending_ops(&storage, std::slice::from_ref(&bad_op), "batch-bad");
    insert_pending_ops(&storage, std::slice::from_ref(&good_op), "batch-good");

    relay.fail_push_with_413("batch-bad");

    let (event_tx, mut event_rx) =
        tokio::sync::broadcast::channel::<prism_sync_core::events::SyncEvent>(32);
    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity],
        test_schema(),
        SyncConfig::default(),
    )
    .with_event_sink(event_tx.clone());

    let result = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key, Some(&ml_dsa_key), device_id, 0)
        .await
        .unwrap();

    assert!(result.error.is_none(), "cycle must not surface a terminal error: {:?}", result.error);
    assert_eq!(result.pushed, 1, "only the non-quarantined batch should be marked pushed");

    // Verify the relay saw push attempts for both batches.
    let push_calls = relay.push_call_batch_ids();
    assert!(push_calls.contains(&"batch-bad".to_string()));
    assert!(push_calls.contains(&"batch-good".to_string()));

    // Storage: bad batch quarantined, good batch deleted from pending_ops.
    let quarantined = storage.list_quarantined_batches(SYNC_ID).unwrap();
    assert_eq!(quarantined.len(), 1, "exactly one batch must be quarantined");
    assert_eq!(quarantined[0].batch_id, "batch-bad");
    assert_eq!(quarantined[0].entity_table, "tasks");
    assert_eq!(quarantined[0].entity_id, bad_op.entity_id);
    assert_eq!(quarantined[0].error_code, "payload_too_large");
    assert!(
        quarantined[0].error_message.contains("413")
            || quarantined[0].error_message.to_lowercase().contains("payload"),
        "error_message should reflect 413 path: {}",
        quarantined[0].error_message
    );
    assert!(quarantined[0].body_bytes > 0, "body_bytes must be populated");

    // The good batch's ops must be gone (push success deletes them).
    let good_ops = storage.load_batch_ops("batch-good").unwrap();
    assert!(good_ops.is_empty(), "good batch ops must be deleted after successful push");

    // The bad batch's ops must remain so recovery can repartition them.
    let bad_ops = storage.load_batch_ops("batch-bad").unwrap();
    assert_eq!(bad_ops.len(), 1, "quarantined batch ops must be retained");

    // get_unpushed_batch_ids must skip the quarantined batch on subsequent cycles.
    let unpushed = storage.get_unpushed_batch_ids(SYNC_ID).unwrap();
    assert!(
        !unpushed.contains(&"batch-bad".to_string()),
        "quarantined batch must be excluded from unpushed list"
    );

    // Drain events and assert QuarantinedBatch fired.
    let mut saw_quarantine_event = false;
    while let Ok(event) = event_rx.try_recv() {
        if let prism_sync_core::events::SyncEvent::QuarantinedBatch {
            batch_id, error_code, ..
        } = event
        {
            if batch_id == "batch-bad" && error_code == "payload_too_large" {
                saw_quarantine_event = true;
                break;
            }
        }
    }
    assert!(saw_quarantine_event, "expected SyncEvent::QuarantinedBatch for batch-bad");
}

/// The client-side guard (body > 1_000_000 bytes) must quarantine the
/// batch BEFORE contacting the relay. Used for defense in depth when the
/// Phase 1A partitioner mis-estimates envelope size.
#[tokio::test]
async fn push_quarantines_batch_when_client_guard_trips() {
    let key_hierarchy = init_key_hierarchy();
    let signing_key = make_signing_key();
    let ml_dsa_key = make_ml_dsa_keypair();
    let device_id = "device-guard-quarantine";

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage, device_id);
    register_device_with_pq(
        &relay,
        &storage,
        device_id,
        &signing_key.verifying_key(),
        &ml_dsa_key.public_key_bytes(),
    );

    // Build a pending op whose JSON-encoded value alone exceeds the guard.
    // The envelope wrapping easily pushes the whole body past 1_000_000.
    // `encoded_value` is stored as a JSON-encoded string, so generate a
    // ~1.4 MB JSON-safe payload (only ASCII letters — no escaping).
    let huge_value = format!("\"{}\"", "X".repeat(1_400_000));
    let hlc = Hlc::now(device_id, None);
    let big_op = CrdtChange {
        op_id: format!("tasks:huge:title:{hlc}:{device_id}"),
        batch_id: Some("batch-huge".to_string()),
        entity_id: "task-huge".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "title".to_string(),
        encoded_value: huge_value,
        client_hlc: hlc.to_string(),
        is_delete: false,
        device_id: device_id.to_string(),
        epoch: 0,
        server_seq: None,
    };
    insert_pending_ops(&storage, std::slice::from_ref(&big_op), "batch-huge");

    let (event_tx, mut event_rx) =
        tokio::sync::broadcast::channel::<prism_sync_core::events::SyncEvent>(32);
    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity],
        test_schema(),
        SyncConfig::default(),
    )
    .with_event_sink(event_tx.clone());

    let result = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key, Some(&ml_dsa_key), device_id, 0)
        .await
        .unwrap();

    assert!(result.error.is_none(), "cycle must not surface a terminal error: {:?}", result.error);
    assert_eq!(result.pushed, 0, "guard-quarantined batch must not be marked pushed");

    // Relay must NOT have seen this batch at all — guard fires before push.
    let push_calls = relay.push_call_batch_ids();
    assert!(
        !push_calls.contains(&"batch-huge".to_string()),
        "client guard must short-circuit the relay call (saw: {push_calls:?})"
    );

    let quarantined = storage.list_quarantined_batches(SYNC_ID).unwrap();
    assert_eq!(quarantined.len(), 1);
    assert_eq!(quarantined[0].batch_id, "batch-huge");
    assert_eq!(quarantined[0].error_code, "payload_too_large_client_guard");
    assert!(
        quarantined[0].body_bytes > 1_000_000,
        "body_bytes must record the measured envelope size, got {}",
        quarantined[0].body_bytes
    );

    let mut saw_event = false;
    while let Ok(event) = event_rx.try_recv() {
        if let prism_sync_core::events::SyncEvent::QuarantinedBatch {
            batch_id, error_code, ..
        } = event
        {
            if batch_id == "batch-huge" && error_code == "payload_too_large_client_guard" {
                saw_event = true;
                break;
            }
        }
    }
    assert!(saw_event, "expected SyncEvent::QuarantinedBatch with client_guard code");
}

// ═══════════════════════════════════════════════════════════════════════════
// Consumer-delivery journal
// ═══════════════════════════════════════════════════════════════════════════

/// A pulled winning op is journaled into `consumer_deliveries` in the SAME tx as
/// the cursor advance — the at-least-once delivery guarantee. The journal row
/// carries the field winner; the cursor moved; both are durable after the cycle.
#[tokio::test]
async fn apply_remote_batch_journals_winning_op_with_cursor() {
    let sender_id = "device-sender";
    let op = CrdtChange {
        op_id: "op-journal-1".to_string(),
        batch_id: Some("batch-attribution".to_string()),
        entity_id: "task-journal".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "title".to_string(),
        encoded_value: "\"Hello\"".to_string(),
        client_hlc: Hlc::new(1_710_500_000_000, 0, sender_id).to_string(),
        is_delete: false,
        device_id: sender_id.to_string(),
        epoch: 0,
        server_seq: None,
    };

    let (result, storage, _entity) = pull_injected_sender_batch(vec![op]).await;
    assert!(result.error.is_none(), "{:?}", result.error);
    assert_eq!(result.merged, 1);

    // Cursor advanced.
    assert_eq!(
        storage.get_sync_metadata(SYNC_ID).unwrap().unwrap().last_pulled_server_seq,
        1
    );

    // Exactly one journal row, carrying the winner's payload, at the batch seq.
    let journal = storage.list_consumer_deliveries(SYNC_ID, 0, 100).unwrap();
    assert_eq!(journal.len(), 1, "one winning op -> one journal row");
    assert_eq!(journal[0].entity_table, "tasks");
    assert_eq!(journal[0].entity_id, "task-journal");
    assert_eq!(journal[0].field_name.as_deref(), Some("title"));
    assert_eq!(journal[0].encoded_value.as_deref(), Some("\"Hello\""));
    assert!(!journal[0].is_delete);
    assert_eq!(journal[0].server_seq, 1);
}

/// A pulled delete winner journals a delete delivery (`field_name = None`,
/// `is_delete = true`) so the Dart drain tombstones the entity.
#[tokio::test]
async fn apply_remote_batch_journals_delete_winner() {
    let sender_id = "device-sender";
    let op = CrdtChange {
        op_id: "op-journal-del".to_string(),
        batch_id: Some("batch-attribution".to_string()),
        entity_id: "task-gone".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "is_deleted".to_string(),
        encoded_value: "true".to_string(),
        client_hlc: Hlc::new(1_710_500_000_000, 0, sender_id).to_string(),
        is_delete: true,
        device_id: sender_id.to_string(),
        epoch: 0,
        server_seq: None,
    };

    let (result, storage, _entity) = pull_injected_sender_batch(vec![op]).await;
    assert!(result.error.is_none(), "{:?}", result.error);

    let journal = storage.list_consumer_deliveries(SYNC_ID, 0, 100).unwrap();
    assert_eq!(journal.len(), 1);
    assert!(journal[0].is_delete, "delete op -> delete delivery");
    assert_eq!(journal[0].field_name, None);
    assert_eq!(journal[0].encoded_value, None);
    assert_eq!(journal[0].entity_id, "task-gone");
}

/// Regression for the delete-absorbing journal blocker: a single batch carrying
/// an edit AND a delete for ONE entity yields BOTH ops as winners (merge keeps
/// the earlier edit when it is processed before the in-batch tombstone is
/// established — verified in merge.rs determine_winners). The journal must
/// deliver ONLY the delete row for that entity, never the subsumed field row,
/// so a `take_undelivered_changes` chunk boundary can never split [delete, field]
/// and resurrect the row at-least-once between acks (board-delete-resurrection
/// class). Independent of the HashMap winner iteration order.
#[tokio::test]
async fn apply_remote_batch_journal_drops_field_subsumed_by_same_batch_delete() {
    let sender_id = "device-sender";
    // Edit has the lower HLC and is listed first, so the merge processes it
    // before the tombstone and keeps it as a winner alongside the delete.
    let edit = CrdtChange {
        op_id: "op-edit".to_string(),
        batch_id: Some("batch-attribution".to_string()),
        entity_id: "task-edel".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "title".to_string(),
        encoded_value: "\"Edited\"".to_string(),
        client_hlc: Hlc::new(1_710_500_000_000, 0, sender_id).to_string(),
        is_delete: false,
        device_id: sender_id.to_string(),
        epoch: 0,
        server_seq: None,
    };
    let delete = CrdtChange {
        op_id: "op-del".to_string(),
        batch_id: Some("batch-attribution".to_string()),
        entity_id: "task-edel".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "is_deleted".to_string(),
        encoded_value: "true".to_string(),
        client_hlc: Hlc::new(1_710_500_000_001, 0, sender_id).to_string(),
        is_delete: true,
        device_id: sender_id.to_string(),
        epoch: 0,
        server_seq: None,
    };

    let (result, storage, _entity) = pull_injected_sender_batch(vec![edit, delete]).await;
    assert!(result.error.is_none(), "{:?}", result.error);
    // Both ops merged (the edit is a winner too — that is the whole point), but
    // only the delete is journaled.
    assert_eq!(result.merged, 2, "edit and delete both win the merge");

    let journal = storage.list_consumer_deliveries(SYNC_ID, 0, 100).unwrap();
    let for_entity: Vec<_> = journal.iter().filter(|r| r.entity_id == "task-edel").collect();
    assert_eq!(
        for_entity.len(),
        1,
        "only the delete row is journaled for a same-batch edit+delete entity"
    );
    assert!(for_entity[0].is_delete, "the single journaled row is the delete");
    assert_eq!(for_entity[0].field_name, None);
}

/// Re-pulling the same batch (idempotent replay) must not duplicate already
/// committed winners as fresh journal rows beyond the at-least-once contract:
/// a batch whose op is already applied produces no new winner, so no new row.
#[tokio::test]
async fn apply_remote_batch_journal_is_idempotent_on_replayed_batch() {
    let key_hierarchy = init_key_hierarchy();
    let signing_key_sender = make_signing_key();
    let ml_dsa_key_sender = make_ml_dsa_keypair();
    let signing_key_receiver = make_signing_key();
    let sender_id = "device-sender";
    let receiver_id = "device-receiver";

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity = Arc::new(MockTaskEntity::new());
    let entity_ref: Arc<dyn SyncableEntity> = entity.clone();

    setup_sync_metadata(&storage, receiver_id);
    register_device_with_pq(
        &relay,
        &storage,
        sender_id,
        &signing_key_sender.verifying_key(),
        &ml_dsa_key_sender.public_key_bytes(),
    );
    register_device(&relay, &storage, receiver_id, &signing_key_receiver.verifying_key());

    let op = task_title_op("op-journal-idem", sender_id, sender_id);
    let envelope = make_encrypted_batch(
        &[op],
        &key_hierarchy,
        &signing_key_sender,
        &ml_dsa_key_sender,
        "batch-attribution",
        sender_id,
    );
    relay.inject_batch(envelope);

    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity_ref],
        test_schema(),
        SyncConfig::default(),
    );

    engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key_receiver, None, receiver_id, 0)
        .await
        .unwrap();
    let after_first = storage.list_consumer_deliveries(SYNC_ID, 0, 100).unwrap();
    assert_eq!(after_first.len(), 1, "first pull journals the winner");

    // The MockRelay's pull cursor advanced past the batch; a second sync sees an
    // empty page, so no new journal rows. (Idempotency at the apply level is
    // covered by the storage `is_op_applied` gate even if redelivered.)
    engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key_receiver, None, receiver_id, 0)
        .await
        .unwrap();
    let after_second = storage.list_consumer_deliveries(SYNC_ID, 0, 100).unwrap();
    assert_eq!(
        after_second.len(),
        1,
        "replayed/empty cycle must not add journal rows"
    );
}
