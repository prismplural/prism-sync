//! Engine-level integration tests for the lean v1 resumable pair-time snapshot
//! uploader.
//!
//! Where `resumable_snapshot_upload_tests.rs` drives the uploader directly with
//! an in-memory relay model, these tests go through
//! [`SyncEngine::upload_pairing_snapshot`] and the real `MockRelay`, which now
//! carries additive resumable support plus per-operation fault injection. That
//! is what proves the *wiring*: transport selection, the single-PUT fallback,
//! and byte-exact publication of the actual signed envelope.
//!
//! The resumable capability is dark by default on `MockRelay` (matching the
//! relay's own default), so every fallback assertion here is meaningful: a test
//! must opt in before the resumable path exists at all.

mod common;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use common::{MockTaskEntity, SYNC_ID};

use prism_sync_core::engine::{SyncConfig, SyncEngine};
use prism_sync_core::relay::mock::MockResumableFault;
use prism_sync_core::relay::traits::{SnapshotExchange, SnapshotUploadProgress};
use prism_sync_core::relay::MockRelay;
use prism_sync_core::schema::{SyncSchema, SyncType};
use prism_sync_core::snapshot_upload::{
    SnapshotUploadCapability, UploadState, SNAPSHOT_UPLOAD_CHUNK_BYTES, SNAPSHOT_UPLOAD_VERSION_V1,
};
use prism_sync_core::storage::{RusqliteSyncStorage, SyncMetadata, SyncStorage};
use prism_sync_core::syncable_entity::SyncableEntity;

fn resumable_schema() -> SyncSchema {
    SyncSchema::builder()
        .entity("tasks", |e| e.field("title", SyncType::String).field("done", SyncType::Bool))
        .build()
}

/// An engine on a mock relay, ready for `upload_pairing_snapshot`.
fn engine_for_upload(relay: Arc<MockRelay>) -> (SyncEngine, prism_sync_crypto::KeyHierarchy) {
    let storage: Arc<RusqliteSyncStorage> = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
    {
        let mut tx = storage.begin_tx().unwrap();
        tx.upsert_sync_metadata(&SyncMetadata {
            sync_id: SYNC_ID.to_string(),
            local_device_id: "device-a".to_string(),
            current_epoch: 0,
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

    let entity: Arc<dyn SyncableEntity> = Arc::new(MockTaskEntity::new());
    let engine =
        SyncEngine::new(storage, relay, vec![entity], resumable_schema(), SyncConfig::default());

    let mut kh = prism_sync_crypto::KeyHierarchy::new();
    kh.initialize("pw", &[7u8; 16]).unwrap();
    kh.store_epoch_key(0, zeroize::Zeroizing::new(vec![0xAB; 32]));
    (engine, kh)
}

fn advertised_capability() -> SnapshotUploadCapability {
    SnapshotUploadCapability {
        version: SNAPSHOT_UPLOAD_VERSION_V1,
        chunk_bytes: SNAPSHOT_UPLOAD_CHUNK_BYTES,
        max_wire_bytes: 150 * 1024 * 1024,
        session_idle_ttl_secs: 3600,
    }
}

/// Run one pairing-snapshot upload through the engine.
async fn run_upload(
    engine: &SyncEngine,
    kh: &prism_sync_crypto::KeyHierarchy,
) -> Result<(), prism_sync_core::CoreError> {
    let ds = prism_sync_crypto::DeviceSecret::generate();
    let signing_key = ds.ed25519_keypair("device-a").unwrap().into_signing_key();
    let ml_dsa_key = ds.ml_dsa_65_keypair_v("device-a", 0).unwrap();
    engine
        .upload_pairing_snapshot(
            SYNC_ID,
            kh,
            0,
            "device-a",
            &signing_key,
            &ml_dsa_key,
            0,
            Some(300),
            Some("device-b".to_string()),
            None,
        )
        .await
}

/// The envelope bytes the engine actually produced, read back from the relay.
async fn published(relay: &MockRelay) -> Vec<u8> {
    relay.get_snapshot().await.unwrap().expect("a snapshot must be published").data
}

#[tokio::test]
async fn old_relay_falls_back_to_the_single_put() {
    // Capability is dark, which is the old-relay shape (and MockRelay's default).
    let relay = Arc::new(MockRelay::new());
    let (engine, kh) = engine_for_upload(Arc::clone(&relay));

    run_upload(&engine, &kh).await.unwrap();

    assert!(relay.get_snapshot().await.unwrap().is_some(), "single PUT must publish");
    assert_eq!(
        relay.resumable_session_count(),
        0,
        "an old relay must never see a resumable session"
    );
    assert_eq!(relay.resumable_complete_calls(), 0);
}

#[tokio::test]
async fn group_wide_request_falls_back_to_the_single_put() {
    // Resumable v1 uploads are targeted-only. A group-wide request (no target
    // device) is not a semantic rejection worth surfacing: it simply keeps using
    // the existing single PUT, which still supports a null audience. No
    // resumable session may be opened for it.
    let relay = Arc::new(MockRelay::new());
    relay.set_resumable_capability(Some(advertised_capability()));
    let (engine, kh) = engine_for_upload(Arc::clone(&relay));

    let ds = prism_sync_crypto::DeviceSecret::generate();
    let signing_key = ds.ed25519_keypair("device-a").unwrap().into_signing_key();
    let ml_dsa_key = ds.ml_dsa_65_keypair_v("device-a", 0).unwrap();
    engine
        .upload_pairing_snapshot(
            SYNC_ID,
            &kh,
            0,
            "device-a",
            &signing_key,
            &ml_dsa_key,
            0,
            Some(300),
            // Group-wide: no target device.
            None,
            None,
        )
        .await
        .unwrap();

    assert!(relay.get_snapshot().await.unwrap().is_some(), "the single PUT must publish");
    assert_eq!(
        relay.resumable_session_count(),
        0,
        "a group-wide request must never open a resumable session"
    );
    assert_eq!(relay.resumable_create_calls(), 0);
    assert_eq!(
        relay.snapshot_target_device_id(),
        None,
        "the published snapshot must stay group-wide"
    );
}

#[tokio::test]
async fn new_relay_uses_the_resumable_path_and_publishes_the_exact_envelope() {
    let relay = Arc::new(MockRelay::new());
    relay.set_resumable_capability(Some(advertised_capability()));
    let (engine, kh) = engine_for_upload(Arc::clone(&relay));

    run_upload(&engine, &kh).await.unwrap();

    assert_eq!(relay.resumable_create_calls(), 1);
    assert_eq!(relay.resumable_session_count(), 1);
    assert_eq!(relay.resumable_complete_calls(), 1);

    // The published bytes are the exact signed envelope, byte for byte: the
    // resumable transport must not reserialize, re-chunk, or re-encode it.
    let resumable = relay.resumable_published_bytes().expect("resumable publication");
    let via_get = published(&relay).await;
    assert_eq!(resumable, via_get, "the resumable path and GET must agree exactly");
    assert!(!resumable.is_empty());
    // And it really is a SignedBatchEnvelope, not some transport wrapper: the
    // exact existing envelope shape with `batch_kind = "snapshot"`.
    let parsed: serde_json::Value = serde_json::from_slice(&resumable).unwrap();
    assert_eq!(parsed["batch_kind"], "snapshot");
    assert_eq!(parsed["sync_id"], SYNC_ID);
    assert_eq!(parsed["sender_device_id"], "device-a");
    assert_eq!(parsed["protocol_version"], 3);
    // The envelope is opaque to the transport: it carries ciphertext and a
    // hybrid signature, never a re-serialized or re-encoded body.
    assert!(parsed["ciphertext"].is_string(), "the payload stays base64 ciphertext");
    assert!(parsed["signature"].is_string());
}

#[tokio::test]
async fn a_lost_create_response_does_not_create_a_second_reservation() {
    let relay = Arc::new(MockRelay::new());
    relay.set_resumable_capability(Some(advertised_capability()));
    relay.inject_resumable_fault("create", MockResumableFault::CommitThenTransportError);
    let (engine, kh) = engine_for_upload(Arc::clone(&relay));

    run_upload(&engine, &kh).await.unwrap();

    // Two attempts, one session: the upload key is what makes recovery possible.
    assert_eq!(relay.resumable_create_calls(), 2);
    assert_eq!(relay.resumable_session_count(), 1);
    assert_eq!(relay.resumable_complete_calls(), 1);
    assert_eq!(relay.resumable_published_bytes(), Some(published(&relay).await));
}

#[tokio::test]
async fn a_lost_complete_response_is_idempotent_at_the_engine_level() {
    let relay = Arc::new(MockRelay::new());
    relay.set_resumable_capability(Some(advertised_capability()));
    relay.inject_resumable_fault("complete", MockResumableFault::CommitThenTransportError);
    let (engine, kh) = engine_for_upload(Arc::clone(&relay));

    run_upload(&engine, &kh).await.unwrap();

    assert_eq!(relay.resumable_complete_calls(), 2, "the completion is retried once");
    // The second completion observed `completed` and republished nothing.
    assert_eq!(relay.resumable_published_bytes(), Some(published(&relay).await));
}

#[tokio::test]
async fn a_fatal_session_rejection_still_uses_the_single_put_fallback_decision() {
    // A relay that advertises the capability but rejects the create with an
    // unsupported-audience error is a *semantic* rejection, not a downgrade.
    // It must surface as an error, never be retried through the old PUT with
    // different semantics.
    let relay = Arc::new(MockRelay::new());
    relay.set_resumable_capability(Some(advertised_capability()));
    relay.inject_resumable_fault(
        "create",
        MockResumableFault::Structured(400, "unsupported_snapshot_audience".to_string()),
    );
    let (engine, kh) = engine_for_upload(Arc::clone(&relay));

    let error = run_upload(&engine, &kh).await.unwrap_err();
    let rendered = format!("{error:?}");
    assert!(
        rendered.contains("Forbidden") || rendered.contains("Relay"),
        "a semantic rejection must surface as a relay error, got {rendered}"
    );
    // Nothing was published through either path.
    assert!(relay.get_snapshot().await.unwrap().is_none());
    assert_eq!(relay.resumable_complete_calls(), 0);
}

#[tokio::test]
async fn retry_exhaustion_through_the_engine_publishes_nothing() {
    let relay = Arc::new(MockRelay::new());
    relay.set_resumable_capability(Some(advertised_capability()));
    // Every chunk attempt fails transiently. The injected fault is consumed
    // once, so re-inject it to cover the whole bounded retry budget.
    let (engine, kh) = engine_for_upload(Arc::clone(&relay));

    // Every create attempt is transiently shed, so the bounded retry budget
    // exhausts and the failure surfaces instead of looping.
    relay.inject_resumable_fault_repeating(
        "create",
        MockResumableFault::Structured(503, "upload_busy".to_string()),
    );
    let error = run_upload(&engine, &kh).await.unwrap_err();
    let rendered = format!("{error:?}");
    assert!(rendered.contains("503") || rendered.contains("Relay"), "got {rendered}");
    assert!(relay.get_snapshot().await.unwrap().is_none(), "nothing may be published");
    assert_eq!(relay.resumable_complete_calls(), 0);
    // The five-attempt bounded policy, not an unbounded loop.
    assert_eq!(relay.resumable_create_calls(), 5);
}

#[tokio::test]
async fn a_progress_callback_still_observes_monotonic_offsets_on_the_resumable_path() {
    let relay = Arc::new(MockRelay::new());
    relay.set_resumable_capability(Some(advertised_capability()));
    let (engine, kh) = engine_for_upload(Arc::clone(&relay));

    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    let progress: SnapshotUploadProgress = Arc::new(move |sent, total| {
        sink.lock().unwrap().push((sent, total));
    });

    let ds = prism_sync_crypto::DeviceSecret::generate();
    let signing_key = ds.ed25519_keypair("device-a").unwrap().into_signing_key();
    let ml_dsa_key = ds.ml_dsa_65_keypair_v("device-a", 0).unwrap();
    engine
        .upload_pairing_snapshot(
            SYNC_ID,
            &kh,
            0,
            "device-a",
            &signing_key,
            &ml_dsa_key,
            0,
            Some(300),
            Some("device-b".to_string()),
            Some(progress),
        )
        .await
        .unwrap();

    let observed = seen.lock().unwrap().clone();
    assert!(!observed.is_empty(), "the progress callback must fire");
    let total = observed[0].1;
    assert!(observed.windows(2).all(|pair| pair[0].0 <= pair[1].0), "progress must not regress");
    assert_eq!(observed.last().unwrap().0, total, "progress must reach 100%");
    assert_eq!(observed.last().unwrap().1, total);
}

#[tokio::test]
async fn resumable_upload_can_be_aborted_leaving_no_published_snapshot() {
    use prism_sync_core::snapshot_upload::abort_upload_best_effort;
    use prism_sync_core::snapshot_upload::ResumableSnapshotTransport;

    let relay = Arc::new(MockRelay::new());
    relay.set_resumable_capability(Some(advertised_capability()));

    // Create a session and abort it, as a cancelled ceremony would.
    let body = prism_sync_core::snapshot_upload::CreateUploadRequest {
        version: SNAPSHOT_UPLOAD_VERSION_V1,
        upload_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        epoch: 0,
        server_seq_at: 0,
        target_device_id: "device-b".to_string(),
        ttl_secs: 300,
        total_bytes: 128,
        body_sha256: "00".repeat(32),
    };
    let created =
        ResumableSnapshotTransport::create_snapshot_upload(relay.as_ref(), &body).await.unwrap();

    abort_upload_best_effort(relay.as_ref(), &created.upload_id).await;

    assert_eq!(
        relay.resumable_state(&created.upload_id),
        Some(UploadState::Failed),
        "a cancelled ceremony's session must be terminal"
    );
    assert_eq!(relay.resumable_abort_calls(), 1);
    assert!(relay.get_snapshot().await.unwrap().is_none());
}

#[tokio::test]
async fn progress_signal_is_never_a_renewal_hint_for_the_relay() {
    // The uploader's progress hook receives only an offset. This asserts the
    // privacy property structurally: the transport-facing hook surface has no
    // way to express an upload ID, target, byte total, or pairing linkage.
    let relay = Arc::new(MockRelay::new());
    relay.set_resumable_capability(Some(advertised_capability()));

    let observed_offsets = Arc::new(AtomicU64::new(0));
    let counter = Arc::clone(&observed_offsets);
    struct OffsetOnlyHook {
        calls: Arc<AtomicU64>,
    }
    #[async_trait::async_trait]
    impl prism_sync_core::snapshot_upload::SnapshotUploadProgressHook for OffsetOnlyHook {
        async fn on_committed_offset_advanced(&mut self, committed_offset: u64) {
            assert!(committed_offset > 0);
            self.calls.fetch_add(1, Ordering::AcqRel);
        }
    }

    // The hook is invoked only for strictly increasing offsets; a single small
    // envelope therefore yields exactly one signal.
    let envelope = vec![0u8; 4096];
    let uploader = prism_sync_core::snapshot_upload::SnapshotUploader::new(
        relay.as_ref(),
        &envelope,
        prism_sync_core::snapshot_upload::SnapshotUploadRequest {
            epoch: 0,
            server_seq_at: 0,
            target_device_id: "device-b".to_string(),
            ttl_secs: 300,
        },
    );
    let mut hook = OffsetOnlyHook { calls: counter };
    uploader.run(Some(&mut hook)).await.unwrap();
    assert_eq!(observed_offsets.load(Ordering::Acquire), 1);
}
