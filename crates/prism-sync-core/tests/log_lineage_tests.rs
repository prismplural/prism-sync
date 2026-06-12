//! Integration tests: relay log-lineage token + cursor-reset recovery.
//!
//! A relay DB restored from backup re-issues lower server_seqs. An up-to-date
//! client (cursor above the regressed head) must NOT read the resulting empty
//! page as "in sync"; it resets its cursor and re-pulls surviving + new history
//! (idempotent LWW merge). The relay signals this two ways: a changed `log_token`
//! in a successful pull response, or a `cursor_ahead_of_log` 409. Both drive the
//! same recovery; `SyncResult.log_regressed` is set for telemetry.

mod common;

use std::sync::Arc;

use ed25519_dalek::SigningKey;

use prism_sync_core::engine::{SyncConfig, SyncEngine};
use prism_sync_core::relay::{InjectedPullError, MockRelay, SignedBatchEnvelope};
use prism_sync_core::storage::{RusqliteSyncStorage, SyncStorage};
use prism_sync_core::syncable_entity::SyncableEntity;
use prism_sync_core::{batch_signature, sync_aad, CrdtChange, Hlc};

use common::*;

/// Create a signed + encrypted batch envelope from CrdtChange ops (epoch 0).
fn make_encrypted_batch(
    ops: &[CrdtChange],
    key_hierarchy: &prism_sync_crypto::KeyHierarchy,
    signing_key: &SigningKey,
    ml_dsa_signing_key: &prism_sync_crypto::DevicePqSigningKey,
    batch_id: &str,
    sender_device_id: &str,
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
        0,
        &payload_hash,
        nonce,
        ciphertext,
    )
    .unwrap()
}

/// Pre-seed the stored relay-log token (as if a prior pull observed it).
fn seed_relay_log_token(storage: &RusqliteSyncStorage, token: &str) {
    let mut tx = storage.begin_tx().unwrap();
    tx.update_relay_log_token(SYNC_ID, token).unwrap();
    tx.commit().unwrap();
}

fn stored_relay_log_token(storage: &RusqliteSyncStorage) -> Option<String> {
    storage.get_sync_metadata(SYNC_ID).unwrap().unwrap().relay_log_token
}

fn stored_cursor(storage: &RusqliteSyncStorage) -> i64 {
    storage.get_sync_metadata(SYNC_ID).unwrap().unwrap().last_pulled_server_seq
}

/// Seed a stall row keyed by an old-lineage server_seq (as if a prior pull on the
/// pre-restore lineage stalled on it).
fn seed_pull_stall(storage: &RusqliteSyncStorage, server_seq: i64) {
    let mut tx = storage.begin_tx().unwrap();
    tx.record_pull_stall(SYNC_ID, server_seq, "sender_unresolved").unwrap();
    tx.commit().unwrap();
}

fn pull_stall_count(storage: &RusqliteSyncStorage) -> usize {
    storage.list_pull_stalls(SYNC_ID).unwrap().len()
}

fn one_sender_op(sender_id: &str, i: usize) -> CrdtChange {
    let hlc = Hlc::new(1_710_500_000_000 + i as i64, 0, sender_id);
    CrdtChange {
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
    }
}

/// A changed `log_token` in a successful pull response → cursor reset to 0, the
/// new token persisted, history re-pulled and applied, `log_regressed` set.
#[tokio::test]
async fn log_token_mismatch_resets_cursor_and_repulls_with_flag() {
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

    // The device already observed a DIFFERENT lineage on a prior sync.
    seed_relay_log_token(&storage, "old-lineage-token");
    let relay_token = relay.log_token().expect("mock relay mints a token");
    assert_ne!(relay_token, "old-lineage-token");

    let op = one_sender_op(sender_id, 0);
    let envelope = make_encrypted_batch(
        std::slice::from_ref(&op),
        &key_hierarchy,
        &signing_key_sender,
        &ml_dsa_key_sender,
        "batch-0",
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
    let result = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key_receiver, None, receiver_id, 0)
        .await
        .unwrap();

    assert!(result.log_regressed, "a lineage-token change sets log_regressed");
    assert!(!result.has_error(), "recovery re-pulls cleanly: {:?}", result.error);
    assert!(storage.is_op_applied("op-0").unwrap(), "re-pulled history is applied");
    assert_eq!(
        stored_relay_log_token(&storage).as_deref(),
        Some(relay_token.as_str()),
        "the new lineage token is persisted",
    );
    assert!(stored_cursor(&storage) > 0, "cursor advanced over the re-pulled batch");
}

/// A `cursor_ahead_of_log` 409 → identical recovery (reset + re-pull) with one
/// bounded retry; the retry succeeds and applies surviving history.
#[tokio::test]
async fn cursor_ahead_of_log_resets_and_repulls_within_cycle() {
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

    let op = one_sender_op(sender_id, 0);
    let envelope = make_encrypted_batch(
        std::slice::from_ref(&op),
        &key_hierarchy,
        &signing_key_sender,
        &ml_dsa_key_sender,
        "batch-0",
        sender_id,
    );
    relay.inject_batch(envelope);

    // First pull 409s cursor_ahead_of_log; the bounded retry then succeeds.
    relay.fail_next_pulls_with(1, InjectedPullError::CursorAheadOfLog { log_head_seq: 0 });

    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity_ref],
        test_schema(),
        SyncConfig::default(),
    );
    let result = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key_receiver, None, receiver_id, 0)
        .await
        .unwrap();

    assert!(result.log_regressed, "cursor_ahead_of_log recovery sets log_regressed");
    assert!(!result.has_error(), "the bounded retry succeeds: {:?}", result.error);
    assert!(storage.is_op_applied("op-0").unwrap(), "surviving history is re-pulled and applied");
}

/// The flagship restore shape: a DB-only restore rotates the relay token AND
/// leaves the client cursor above the restored head, so the client both 409s
/// (`cursor_ahead_of_log`) AND already holds a STALE stored token. The 409
/// recovery must clear that stored token so the follow-up pull's rotated token is
/// adopted, not re-detected as a second lineage trip — otherwise the bounded
/// retry double-counts and surfaces a bogus "flapping" error.
#[tokio::test]
async fn db_only_restore_recovers_in_one_cycle_without_double_counting() {
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

    // The device observed the PRE-restore lineage on a prior sync; the relay has
    // since rotated its token (startup detected the DB-only restore).
    seed_relay_log_token(&storage, "pre-restore-token");
    let rotated_token = relay.log_token().expect("mock relay mints a (rotated) token");
    assert_ne!(rotated_token, "pre-restore-token");

    let op = one_sender_op(sender_id, 0);
    let envelope = make_encrypted_batch(
        std::slice::from_ref(&op),
        &key_hierarchy,
        &signing_key_sender,
        &ml_dsa_key_sender,
        "batch-0",
        sender_id,
    );
    relay.inject_batch(envelope);

    // First pull 409s (cursor above restored head); the bounded retry then pulls
    // the re-issued history and observes the rotated token.
    relay.fail_next_pulls_with(1, InjectedPullError::CursorAheadOfLog { log_head_seq: 0 });

    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity_ref],
        test_schema(),
        SyncConfig::default(),
    );
    let result = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key_receiver, None, receiver_id, 0)
        .await
        .unwrap();

    assert!(
        !result.has_error(),
        "the stale token is cleared on the 409, so the rotated token adopts cleanly \
         in a single bounded retry: {:?}",
        result.error,
    );
    assert!(
        result.log_regressed,
        "the telemetry signal the client half exists to deliver must fire on the flagship path",
    );
    assert!(storage.is_op_applied("op-0").unwrap(), "re-issued history is re-pulled and applied");
    assert_eq!(
        stored_relay_log_token(&storage).as_deref(),
        Some(rotated_token.as_str()),
        "the rotated lineage token is adopted and persisted",
    );
}

/// A lineage reset must drop all stall rows keyed by the now-defunct old-lineage
/// seqs — otherwise a stale stall past the 24h
/// ceiling converts a re-issued seq to quarantine-and-advance on its first hiccup.
#[tokio::test]
async fn lineage_reset_clears_old_lineage_pull_stalls() {
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

    // The device carries stall rows from the pre-restore lineage and observed its
    // token. The relay has since rotated (a different token signals the restore).
    seed_relay_log_token(&storage, "pre-restore-token");
    seed_pull_stall(&storage, 7);
    seed_pull_stall(&storage, 11);
    assert_eq!(pull_stall_count(&storage), 2, "stalls seeded on the old lineage");

    let op = one_sender_op(sender_id, 0);
    let envelope = make_encrypted_batch(
        std::slice::from_ref(&op),
        &key_hierarchy,
        &signing_key_sender,
        &ml_dsa_key_sender,
        "batch-0",
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
    let result = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key_receiver, None, receiver_id, 0)
        .await
        .unwrap();

    assert!(result.log_regressed, "the token mismatch is a lineage reset");
    assert!(!result.has_error(), "recovery re-pulls cleanly: {:?}", result.error);
    assert_eq!(
        pull_stall_count(&storage),
        0,
        "old-lineage stall rows must not survive the lineage reset",
    );
}

/// Two consecutive `cursor_ahead_of_log` trips (the relay keeps 409ing right
/// after the reset) → surfaced error, no infinite loop, no silent skip.
#[tokio::test]
async fn two_consecutive_cursor_ahead_trips_surface_an_error() {
    let key_hierarchy = init_key_hierarchy();
    let signing_key_receiver = make_signing_key();
    let receiver_id = "device-receiver";

    let relay = Arc::new(MockRelay::new());
    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity = Arc::new(MockTaskEntity::new());
    let entity_ref: Arc<dyn SyncableEntity> = entity.clone();

    setup_sync_metadata(&storage, receiver_id);
    register_device(&relay, &storage, receiver_id, &signing_key_receiver.verifying_key());

    // Both the initial pull AND the post-reset retry 409 → second consecutive
    // trip surfaces rather than looping.
    relay.fail_next_pulls_with(2, InjectedPullError::CursorAheadOfLog { log_head_seq: 0 });

    let engine = SyncEngine::new(
        storage.clone(),
        relay.clone(),
        vec![entity_ref],
        test_schema(),
        SyncConfig::default(),
    );
    let result = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key_receiver, None, receiver_id, 0)
        .await
        .unwrap();

    assert!(result.has_error(), "a second consecutive trip must surface an error");
    assert_eq!(
        result.error_code.as_deref(),
        Some("cursor_ahead_of_log"),
        "the surfaced error is the lineage trip, not a generic failure",
    );
    // Exactly two pull attempts: the initial trip + one bounded retry.
    assert_eq!(relay.pull_call_count(), 2, "no further retries after the second trip");
}

/// An old relay (no `log_token` in the response) → lineage tracking stays inert:
/// no reset, no flag, history pulled normally.
#[tokio::test]
async fn old_relay_without_log_token_is_unchanged() {
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

    // Mimic a pre-lineage relay: no log_token in any pull response.
    relay.set_log_token(None);

    let op = one_sender_op(sender_id, 0);
    let envelope = make_encrypted_batch(
        std::slice::from_ref(&op),
        &key_hierarchy,
        &signing_key_sender,
        &ml_dsa_key_sender,
        "batch-0",
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
    let result = engine
        .sync(SYNC_ID, &key_hierarchy, &signing_key_receiver, None, receiver_id, 0)
        .await
        .unwrap();

    assert!(!result.log_regressed, "no log_token => no lineage tracking");
    assert!(!result.has_error(), "{:?}", result.error);
    assert!(storage.is_op_applied("op-0").unwrap(), "history pulled normally");
    assert_eq!(stored_relay_log_token(&storage), None, "no token is adopted from an old relay");
}
