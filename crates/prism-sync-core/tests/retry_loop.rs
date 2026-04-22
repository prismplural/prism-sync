//! Integration tests for `SyncService::sync_now` retry loop.
//!
//! The inner retry loop is the first tier of the two-tier retry architecture
//! (inner: 3x2s tight retries inside one sync cycle; outer: driver
//! exponential backoff across cycles). These tests exercise the inner loop
//! directly against a real `SyncEngine` + `MockRelay` pair where the relay
//! is configured to fail the first N `pull_changes` calls before returning
//! success.

mod common;

use std::sync::Arc;

use prism_sync_core::engine::{SyncConfig, SyncEngine};
use prism_sync_core::events::{SyncErrorKind, SyncEvent};
use prism_sync_core::relay::{InjectedPullError, MockRelay, SignedBatchEnvelope};
use prism_sync_core::storage::RusqliteSyncStorage;
use prism_sync_core::sync_service::SyncService;
use prism_sync_core::syncable_entity::SyncableEntity;
use prism_sync_core::{batch_signature, sync_aad, CrdtChange};
use tokio::sync::broadcast;
use zeroize::Zeroizing;

use common::*;

/// Bundle of fixtures a retry-loop test needs to drive assertions.
struct TestService {
    service: SyncService,
    event_rx: broadcast::Receiver<SyncEvent>,
    key_hierarchy: prism_sync_crypto::KeyHierarchy,
    signing_key: ed25519_dalek::SigningKey,
    ml_dsa_key: prism_sync_crypto::DevicePqSigningKey,
    device_id: String,
    storage: Arc<RusqliteSyncStorage>,
}

/// Build a `SyncService` pre-wired to a `SyncEngine` + `MockRelay` using
/// the shared test fixtures. Returns everything the test needs to drive
/// assertions, including a handle on the underlying storage so tests can
/// seed pending ops.
async fn make_service(relay: Arc<MockRelay>) -> TestService {
    let key_hierarchy = init_key_hierarchy();
    let signing_key = make_signing_key();
    let ml_dsa_key = make_ml_dsa_keypair();
    let device_id = "device-retry-test".to_string();

    let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    let entity: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());

    setup_sync_metadata(&storage, &device_id);
    register_device_with_pq(
        &relay,
        &storage,
        &device_id,
        &signing_key.verifying_key(),
        &ml_dsa_key.public_key_bytes(),
    );

    let engine =
        SyncEngine::new(storage.clone(), relay, vec![entity], test_schema(), SyncConfig::default());

    let (event_tx, event_rx) = broadcast::channel::<SyncEvent>(64);
    let mut service = SyncService::new(event_tx);
    service.set_engine(engine, SYNC_ID.to_string());

    TestService { service, event_rx, key_hierarchy, signing_key, ml_dsa_key, device_id, storage }
}

fn make_encrypted_batch_at_epoch(
    ops: &[CrdtChange],
    key_hierarchy: &prism_sync_crypto::KeyHierarchy,
    signing_key: &ed25519_dalek::SigningKey,
    ml_dsa_signing_key: &prism_sync_crypto::DevicePqSigningKey,
    batch_id: &str,
    sender_device_id: &str,
    epoch: i32,
) -> SignedBatchEnvelope {
    let plaintext = CrdtChange::encode_batch(ops).unwrap();
    let payload_hash = batch_signature::compute_payload_hash(&plaintext);
    let epoch_key = key_hierarchy.epoch_key(epoch as u32).unwrap();
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

/// Drain all currently-available events from a broadcast receiver,
/// returning them in the order they were sent.
fn drain_events(rx: &mut broadcast::Receiver<SyncEvent>) -> Vec<SyncEvent> {
    let mut out = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        out.push(ev);
    }
    out
}

/// Transient network errors must be retried inside a single `sync_now`
/// call. The mock is set to fail 2 pulls, so the 3rd attempt succeeds and
/// the final outcome is `Ok(result)` with no error.
#[tokio::test(start_paused = true)]
async fn sync_now_retries_on_transient_network_error_and_eventually_succeeds() {
    let relay = Arc::new(MockRelay::new());
    relay.fail_next_pulls(2);

    let TestService {
        mut service,
        mut event_rx,
        key_hierarchy: kh,
        signing_key: sk,
        ml_dsa_key: ml_dsa,
        device_id,
        ..
    } = make_service(relay.clone()).await;

    let fut = service.sync_now(&kh, &sk, Some(&ml_dsa), &device_id, 0);
    let result = fut.await.expect("sync_now should eventually succeed");

    assert!(result.error.is_none(), "final result should be clean: {:?}", result.error);
    assert_eq!(
        relay.pull_call_count(),
        3,
        "expected 3 total pull_changes calls (2 fails + 1 success)"
    );

    // Event sequence should be: SyncStarted -> SyncCompleted(no_error).
    // No Error event on this path.
    let events = drain_events(&mut event_rx);
    assert!(
        matches!(events.first(), Some(SyncEvent::SyncStarted)),
        "first event must be SyncStarted: {events:?}"
    );
    let completed = events
        .iter()
        .find(|e| matches!(e, SyncEvent::SyncCompleted(_)))
        .expect("must emit SyncCompleted");
    if let SyncEvent::SyncCompleted(r) = completed {
        assert!(r.error.is_none(), "SyncCompleted.error should be None");
    }
    assert!(
        !events.iter().any(|e| matches!(e, SyncEvent::Error(_))),
        "should not emit Error on retry-then-success path: {events:?}"
    );
}

/// When all 4 attempts (1 + 3 retries) fail with a retryable network
/// error, `sync_now` must emit `SyncCompleted` FIRST (with the populated
/// error field) and THEN `Error`, and finally return `Err`.
///
/// The SyncCompleted-before-Error ordering is load-bearing: the Dart UI
/// resets `isSyncing: false` only on the `SyncCompleted` branch. See
/// Appendix B.1 / B.9 of the robustness plan.
#[tokio::test(start_paused = true)]
async fn sync_now_emits_sync_completed_before_error_on_exhausted_retries() {
    let relay = Arc::new(MockRelay::new());
    relay.fail_next_pulls(10); // more than INNER_RETRY_MAX + 1

    let TestService {
        mut service,
        mut event_rx,
        key_hierarchy: kh,
        signing_key: sk,
        ml_dsa_key: ml_dsa,
        device_id,
        ..
    } = make_service(relay.clone()).await;

    let fut = service.sync_now(&kh, &sk, Some(&ml_dsa), &device_id, 0);
    let result = fut.await;
    assert!(result.is_err(), "exhausted retries must return Err, got Ok");

    // INNER_RETRY_MAX = 3 additional retries -> 4 total pull attempts.
    assert_eq!(relay.pull_call_count(), 4, "expected 1 initial + 3 retries = 4 total pulls");

    let events = drain_events(&mut event_rx);

    // Find the positions of SyncCompleted and Error.
    let completed_idx = events
        .iter()
        .position(|e| matches!(e, SyncEvent::SyncCompleted(_)))
        .expect("must emit SyncCompleted on exhausted retries");
    let error_idx = events
        .iter()
        .position(|e| matches!(e, SyncEvent::Error(_)))
        .expect("must emit Error on exhausted retries");

    assert!(
        completed_idx < error_idx,
        "SyncCompleted must be emitted BEFORE Error (isSyncing reset): \
         completed@{completed_idx}, error@{error_idx}, events={events:?}"
    );

    // SyncCompleted payload must carry the error text + structured kind.
    if let SyncEvent::SyncCompleted(r) = &events[completed_idx] {
        assert!(r.error.is_some(), "SyncCompleted.error must be populated");
        assert_eq!(
            r.error_kind.as_ref(),
            Some(&SyncErrorKind::Network),
            "error_kind must be Network, got {:?}",
            r.error_kind
        );
    } else {
        unreachable!()
    }

    // Error event should classify as Network.
    if let SyncEvent::Error(err) = &events[error_idx] {
        assert_eq!(err.kind, SyncErrorKind::Network);
        assert!(err.retryable, "Network error is retryable by category");
    } else {
        unreachable!()
    }
}

/// Auth errors are NOT retryable — they should surface immediately with
/// no retry attempts.
#[tokio::test(start_paused = true)]
async fn sync_now_does_not_retry_on_auth_error() {
    let relay = Arc::new(MockRelay::new());
    relay.fail_next_pulls_with(10, InjectedPullError::Auth);

    let TestService {
        mut service,
        mut event_rx,
        key_hierarchy: kh,
        signing_key: sk,
        ml_dsa_key: ml_dsa,
        device_id,
        ..
    } = make_service(relay.clone()).await;

    let result = service.sync_now(&kh, &sk, Some(&ml_dsa), &device_id, 0).await;
    assert!(result.is_err(), "auth error must return Err");

    assert_eq!(
        relay.pull_call_count(),
        1,
        "auth is non-retryable: expected exactly 1 pull attempt"
    );

    let events = drain_events(&mut event_rx);
    let err_event = events
        .iter()
        .find_map(|e| match e {
            SyncEvent::Error(err) => Some(err),
            _ => None,
        })
        .expect("must emit Error");
    assert_eq!(err_event.kind, SyncErrorKind::Auth);
}

/// Server (5xx) errors ARE retryable — they should hit the full retry
/// budget before surfacing.
#[tokio::test(start_paused = true)]
async fn sync_now_retries_on_server_error() {
    let relay = Arc::new(MockRelay::new());
    relay.fail_next_pulls_with(10, InjectedPullError::Server);

    let TestService {
        mut service,
        mut event_rx,
        key_hierarchy: kh,
        signing_key: sk,
        ml_dsa_key: ml_dsa,
        device_id,
        ..
    } = make_service(relay.clone()).await;

    let result = service.sync_now(&kh, &sk, Some(&ml_dsa), &device_id, 0).await;
    assert!(result.is_err(), "exhausted server errors must return Err");

    assert_eq!(relay.pull_call_count(), 4, "expected 1 + 3 retries = 4 total pull attempts on 5xx");

    let events = drain_events(&mut event_rx);
    let err_event = events
        .iter()
        .find_map(|e| match e {
            SyncEvent::Error(err) => Some(err),
            _ => None,
        })
        .expect("must emit Error");
    assert_eq!(err_event.kind, SyncErrorKind::Server);
}

/// `last_sync_time` must not advance on a failed sync (otherwise
/// catch-up-if-stale would treat a string of failures as "recently synced"
/// and skip work).
#[tokio::test(start_paused = true)]
async fn sync_now_does_not_update_last_sync_time_on_error() {
    let relay = Arc::new(MockRelay::new());
    relay.fail_next_pulls(10);

    let TestService {
        mut service,
        key_hierarchy: kh,
        signing_key: sk,
        ml_dsa_key: ml_dsa,
        device_id,
        ..
    } = make_service(relay.clone()).await;

    assert!(service.last_sync_time().is_none());

    let _ = service.sync_now(&kh, &sk, Some(&ml_dsa), &device_id, 0).await;
    assert!(
        service.last_sync_time().is_none(),
        "last_sync_time must stay None after a failed sync"
    );
}

/// When the relay responds with `device_revoked`, the engine catches the
/// error at the pull phase and wraps it into `Ok(SyncResult)`. The
/// retry-loop path must:
/// - NOT retry (auth is not retryable);
/// - Propagate `error_code = "device_revoked"` and `remote_wipe` verbatim
///   on the emitted `SyncCompleted` event;
/// - Emit a dedicated `SyncEvent::DeviceRevoked` so Dart can trigger
///   credential cleanup even if it only listens to that event;
/// - Emit `SyncEvent::Error` with `code: Some("device_revoked")` and
///   `remote_wipe: Some(true)`;
/// - Return `Err(CoreError::Relay { code: Some("device_revoked"), .. })`
///   so the FFI layer's error-encoding path surfaces the structured
///   metadata to Dart.
///
/// Regression guard for Fix 2 of the 2026-04-11 sync robustness plan.
#[tokio::test(start_paused = true)]
async fn sync_now_propagates_device_revoked_code_through_result_error() {
    let relay = Arc::new(MockRelay::new());
    relay.fail_next_pulls_with(10, InjectedPullError::DeviceRevoked { remote_wipe: true });

    let TestService {
        mut service,
        mut event_rx,
        key_hierarchy: kh,
        signing_key: sk,
        ml_dsa_key: ml_dsa,
        device_id,
        ..
    } = make_service(relay.clone()).await;

    let result = service.sync_now(&kh, &sk, Some(&ml_dsa), &device_id, 0).await;

    // Revocation surfaces as Err — not retryable.
    let err = result.expect_err("device_revoked must return Err");
    match err {
        prism_sync_core::CoreError::Relay { code, remote_wipe, .. } => {
            assert_eq!(
                code.as_deref(),
                Some("device_revoked"),
                "synthetic CoreError::Relay must carry device_revoked code"
            );
            assert_eq!(
                remote_wipe,
                Some(true),
                "synthetic CoreError::Relay must carry remote_wipe flag"
            );
        }
        other => panic!("expected CoreError::Relay, got {other:?}"),
    }

    // Exactly one pull attempt — auth-class errors are not retryable.
    assert_eq!(relay.pull_call_count(), 1, "device_revoked must not be retried");

    let events = drain_events(&mut event_rx);

    // SyncCompleted must carry the structured error metadata.
    let completed = events
        .iter()
        .find_map(|e| match e {
            SyncEvent::SyncCompleted(r) => Some(r),
            _ => None,
        })
        .expect("must emit SyncCompleted");
    assert_eq!(
        completed.error_code.as_deref(),
        Some("device_revoked"),
        "SyncCompleted.error_code must be device_revoked"
    );
    assert_eq!(completed.remote_wipe, Some(true));
    assert_eq!(completed.error_kind.as_ref(), Some(&SyncErrorKind::Auth));

    // A dedicated DeviceRevoked event must also fire so Dart handlers
    // that only listen to it still run cleanup.
    let device_revoked = events
        .iter()
        .find(|e| matches!(e, SyncEvent::DeviceRevoked { .. }))
        .expect("must emit SyncEvent::DeviceRevoked");
    if let SyncEvent::DeviceRevoked { device_id: did, remote_wipe } = device_revoked {
        assert_eq!(did, &device_id);
        assert!(*remote_wipe, "remote_wipe flag must propagate");
    }

    // The Error event must also carry the structured code + remote_wipe.
    let err_event = events
        .iter()
        .find_map(|e| match e {
            SyncEvent::Error(err) => Some(err),
            _ => None,
        })
        .expect("must emit Error");
    assert_eq!(err_event.kind, SyncErrorKind::Auth);
    assert_eq!(err_event.code.as_deref(), Some("device_revoked"));
    assert_eq!(err_event.remote_wipe, Some(true));
}

/// Local/permanent failures — missing epoch key, missing ML-DSA signing
/// key, storage errors, etc. — must classify as `Protocol` (not
/// `Network`). The retry loop must:
/// - Not retry (Protocol is not in `sync_error_kind_retryable`);
/// - Fire exactly one engine.sync attempt (one pull);
/// - Surface `SyncErrorKind::Protocol` through the Error event so Dart's
///   event-driven drain does NOT treat this as transient.
///
/// Regression guard for Fix 3 of the 2026-04-11 sync robustness plan.
/// We trigger the error by seeding a pending op into storage and then
/// calling `sync_now` without an ML-DSA signing key; the engine's push
/// phase catches `CoreError::Engine("ML-DSA signing key required ...")`.
#[tokio::test(start_paused = true)]
async fn sync_now_does_not_retry_on_missing_ml_dsa_key_error() {
    let relay = Arc::new(MockRelay::new());

    let TestService {
        mut service,
        mut event_rx,
        key_hierarchy: kh,
        signing_key: sk,
        ml_dsa_key: _ml_dsa,
        device_id,
        storage,
    } = make_service(relay.clone()).await;

    // Seed a pending op directly into storage so the push phase runs.
    let hlc = prism_sync_core::Hlc::now(&device_id, None);
    let op = prism_sync_core::CrdtChange {
        op_id: format!("tasks:task-1:title:{}:{}", hlc, &device_id),
        batch_id: Some("batch-proto".to_string()),
        entity_id: "task-1".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "title".to_string(),
        encoded_value: "\"hi\"".to_string(),
        client_hlc: hlc.to_string(),
        is_delete: false,
        device_id: device_id.clone(),
        epoch: 0,
        server_seq: None,
    };
    insert_pending_ops(&storage, std::slice::from_ref(&op), "batch-proto");

    // Pass None for ml_dsa_signing_key -> push_phase returns
    // `CoreError::Engine("ML-DSA signing key required ...")`, which
    // `classify_core_error` now maps to `SyncErrorKind::Protocol`.
    let result = service.sync_now(&kh, &sk, None, &device_id, 0).await;

    // With Protocol classification, Err must surface after 1 attempt.
    assert!(result.is_err(), "local engine error must surface as Err");
    assert_eq!(relay.pull_call_count(), 1, "local engine errors must not retry");

    let events = drain_events(&mut event_rx);
    let err_event = events
        .iter()
        .find_map(|e| match e {
            SyncEvent::Error(err) => Some(err),
            _ => None,
        })
        .expect("must emit Error");
    assert_eq!(
        err_event.kind,
        SyncErrorKind::Protocol,
        "local engine error must classify as Protocol (not Network)"
    );
    assert!(!err_event.retryable, "Protocol errors must not be retryable");

    // Completed event must also carry the Protocol kind so Dart's
    // event-driven drain knows to skip.
    let completed = events
        .iter()
        .find_map(|e| match e {
            SyncEvent::SyncCompleted(r) => Some(r),
            _ => None,
        })
        .expect("must emit SyncCompleted");
    assert_eq!(
        completed.error_kind.as_ref(),
        Some(&SyncErrorKind::Protocol),
        "SyncCompleted.error_kind must be Protocol"
    );
}

/// A pulled batch at a newer epoch must surface as a local/protocol failure
/// when the receiver is missing that epoch key. The retry loop must not
/// treat this like a transient network issue, and relay-only metadata must
/// stay unset.
#[tokio::test(start_paused = true)]
async fn sync_now_does_not_retry_on_missing_epoch_key_pull_error() {
    let relay = Arc::new(MockRelay::new());

    let TestService {
        mut service,
        mut event_rx,
        key_hierarchy: kh,
        signing_key: sk,
        ml_dsa_key: ml_dsa,
        device_id,
        storage,
    } = make_service(relay.clone()).await;

    let remote_device = "device-remote-epoch-miss";
    let remote_signing_key = make_signing_key();
    let remote_ml_dsa = make_ml_dsa_keypair();
    register_device_with_pq(
        &relay,
        &storage,
        remote_device,
        &remote_signing_key.verifying_key(),
        &remote_ml_dsa.public_key_bytes(),
    );

    let mut sender_kh = init_key_hierarchy();
    sender_kh.store_epoch_key(1, Zeroizing::new(vec![0x11; 32]));

    let hlc = prism_sync_core::Hlc::now(remote_device, None);
    let ops = vec![CrdtChange {
        op_id: format!("tasks:task-epoch:title:{}:{remote_device}", hlc),
        batch_id: Some("batch-missing-epoch".to_string()),
        entity_id: "task-epoch".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "title".to_string(),
        encoded_value: "\"needs recovery\"".to_string(),
        client_hlc: hlc.to_string(),
        is_delete: false,
        device_id: remote_device.to_string(),
        epoch: 1,
        server_seq: None,
    }];

    let envelope = make_encrypted_batch_at_epoch(
        &ops,
        &sender_kh,
        &remote_signing_key,
        &remote_ml_dsa,
        "batch-missing-epoch",
        remote_device,
        1,
    );
    relay.inject_batch(envelope);

    let result = service.sync_now(&kh, &sk, Some(&ml_dsa), &device_id, 0).await;
    assert!(result.is_err(), "missing epoch key must return Err");
    assert_eq!(
        relay.pull_call_count(),
        1,
        "missing epoch key is local/protocol, so it must not retry"
    );

    let events = drain_events(&mut event_rx);
    let err_event = events
        .iter()
        .find_map(|e| match e {
            SyncEvent::Error(err) => Some(err),
            _ => None,
        })
        .expect("must emit Error");
    assert_eq!(err_event.kind, SyncErrorKind::Protocol);
    assert!(!err_event.retryable);
    assert!(err_event.code.is_none());
    assert!(err_event.remote_wipe.is_none());

    let completed = events
        .iter()
        .find_map(|e| match e {
            SyncEvent::SyncCompleted(result) => Some(result),
            _ => None,
        })
        .expect("must emit SyncCompleted");
    assert_eq!(completed.error_kind.as_ref(), Some(&SyncErrorKind::Protocol));
    assert!(completed.error_code.is_none());
    assert!(completed.remote_wipe.is_none());
}

/// If a device has the wrong key material cached for a pulled epoch, the
/// decrypt failure must surface as a local/protocol failure without retries
/// or relay-scoped metadata.
#[tokio::test(start_paused = true)]
async fn sync_now_does_not_retry_on_epoch_decrypt_failure() {
    let relay = Arc::new(MockRelay::new());

    let TestService {
        mut service,
        mut event_rx,
        mut key_hierarchy,
        signing_key: sk,
        ml_dsa_key: ml_dsa,
        device_id,
        storage,
    } = make_service(relay.clone()).await;

    let remote_device = "device-remote-decrypt-fail";
    let remote_signing_key = make_signing_key();
    let remote_ml_dsa = make_ml_dsa_keypair();
    register_device_with_pq(
        &relay,
        &storage,
        remote_device,
        &remote_signing_key.verifying_key(),
        &remote_ml_dsa.public_key_bytes(),
    );

    key_hierarchy.store_epoch_key(1, Zeroizing::new(vec![0x22; 32]));
    let mut sender_kh = init_key_hierarchy();
    sender_kh.store_epoch_key(1, Zeroizing::new(vec![0x33; 32]));

    let hlc = prism_sync_core::Hlc::now(remote_device, None);
    let ops = vec![CrdtChange {
        op_id: format!("tasks:task-bad-key:title:{}:{remote_device}", hlc),
        batch_id: Some("batch-decrypt-fail".to_string()),
        entity_id: "task-bad-key".to_string(),
        entity_table: "tasks".to_string(),
        field_name: "title".to_string(),
        encoded_value: "\"bad key\"".to_string(),
        client_hlc: hlc.to_string(),
        is_delete: false,
        device_id: remote_device.to_string(),
        epoch: 1,
        server_seq: None,
    }];

    let envelope = make_encrypted_batch_at_epoch(
        &ops,
        &sender_kh,
        &remote_signing_key,
        &remote_ml_dsa,
        "batch-decrypt-fail",
        remote_device,
        1,
    );
    relay.inject_batch(envelope);

    let result = service.sync_now(&key_hierarchy, &sk, Some(&ml_dsa), &device_id, 0).await;
    assert!(result.is_err(), "decrypt failure must return Err");
    assert_eq!(
        relay.pull_call_count(),
        1,
        "decrypt failure is local/protocol, so it must not retry"
    );

    let events = drain_events(&mut event_rx);
    let err_event = events
        .iter()
        .find_map(|e| match e {
            SyncEvent::Error(err) => Some(err),
            _ => None,
        })
        .expect("must emit Error");
    assert_eq!(err_event.kind, SyncErrorKind::Protocol);
    assert!(!err_event.retryable);
    assert!(err_event.code.is_none());
    assert!(err_event.remote_wipe.is_none());

    let completed = events
        .iter()
        .find_map(|e| match e {
            SyncEvent::SyncCompleted(result) => Some(result),
            _ => None,
        })
        .expect("must emit SyncCompleted");
    assert_eq!(completed.error_kind.as_ref(), Some(&SyncErrorKind::Protocol));
    assert!(completed.error_code.is_none());
    assert!(completed.remote_wipe.is_none());
}
