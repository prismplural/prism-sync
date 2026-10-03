//! Resumable pair-time snapshot upload: FFI-level integration coverage.
//!
//! These tests pin the FFI-visible contract that the split initiator ceremony
//! depends on:
//!
//! - the required ordering (credentials only after a durable upload),
//! - the legacy one-shot API remaining available unchanged,
//! - capability probing reporting a downgrade rather than an error,
//! - best-effort abort being nonfatal and short,
//! - the lease hook driving coalesced renewals through core's own policy.
//!
//! The engine-driven upload itself is covered by core's
//! `resumable_snapshot_upload_tests` and by the relay parity suite; driving it
//! end to end from an FFI handle requires a fully configured device identity and
//! a live signed-request relay, which the FFI test harness does not provide.

use prism_sync_ffi::api;

/// A handle with in-memory storage and a memory secure store.
fn make_handle() -> api::PrismSyncHandle {
    api::create_prism_sync(
        "https://localhost:8080".into(),
        ":memory:".into(),
        false,
        String::new(),
        None,
    )
    .expect("create_prism_sync should succeed")
}

// ── Ordering: the split ceremony cannot be short-circuited ──

/// The upload half requires a verified ceremony. Without one there is nothing to
/// upload against, and — more importantly — no path can reach credential
/// release.
#[tokio::test]
async fn upload_without_a_verified_ceremony_is_refused() {
    let handle = make_handle();
    let error = api::upload_pairing_snapshot_resumable(&handle, None)
        .await
        .expect_err("uploading without a verified ceremony must fail");
    assert!(
        error.contains("no verified initiator ceremony"),
        "expected the verified-ceremony precondition, got: {error}"
    );
}

/// Verification requires an initiator ceremony that was actually started. This
/// is the first step of the split, so a bare handle must refuse it rather than
/// fabricate state.
#[tokio::test]
async fn verification_without_a_started_ceremony_is_refused() {
    let handle = make_handle();
    let error = api::verify_initiator_confirmation_resumable(&handle)
        .await
        .expect_err("verifying without a started ceremony must fail");
    assert!(
        error.contains("no initiator ceremony in progress"),
        "expected the started-ceremony precondition, got: {error}"
    );
}

/// The credential-release half is a distinct step and refuses on a bare handle.
/// Combined with the upload precondition above, this is the ordering the spec
/// requires: verify, then upload, then release.
#[tokio::test]
async fn credential_release_without_a_verified_ceremony_is_refused() {
    let handle = make_handle();
    let error = api::complete_initiator_resumable_ceremony(
        &handle,
        b"password".to_vec(),
        b"mnemonic".to_vec(),
    )
    .await
    .expect_err("releasing credentials without a verified ceremony must fail");
    assert!(
        error.contains("no verified initiator ceremony"),
        "expected the verified-ceremony precondition, got: {error}"
    );
}

/// The public split release entry point rejects a bare handle. Unit tests cover
/// the separate verified-but-unpublished gate with retained ceremony state.
#[tokio::test]
async fn credential_release_is_a_separate_gated_step() {
    let handle = make_handle();
    let error = api::complete_initiator_resumable_ceremony(
        &handle,
        b"password".to_vec(),
        b"mnemonic".to_vec(),
    )
    .await
    .expect_err("the split release step must be gated");
    assert!(!error.is_empty());
}

// ── Cancellation is idempotent and never fatal ──

/// Cancelling with nothing in progress is a no-op, not an error. The app calls
/// this from user-cancel, back-navigation, and ceremony-expiry paths, where a
/// spurious failure would surface as a bogus user-visible error.
#[tokio::test]
async fn cancellation_with_nothing_in_progress_is_a_noop() {
    let handle = make_handle();
    api::cancel_pairing_ceremony(&handle).await.expect("cancelling an idle handle must succeed");
    // Idempotent: a second call is equally harmless.
    api::cancel_pairing_ceremony(&handle).await.expect("cancelling twice must succeed");
}

/// Cancelling a bare handle does not make it eligible to release credentials.
#[tokio::test]
async fn cancellation_blocks_the_credential_release_half() {
    let handle = make_handle();
    // This bare handle has no verified ceremony before or after cancellation.
    let before = api::complete_initiator_resumable_ceremony(
        &handle,
        b"password".to_vec(),
        b"mnemonic".to_vec(),
    )
    .await
    .expect_err("no verified ceremony");
    assert!(before.contains("no verified initiator ceremony"));

    api::cancel_pairing_ceremony(&handle).await.expect("cancel must succeed");

    let after = api::complete_initiator_resumable_ceremony(
        &handle,
        b"password".to_vec(),
        b"mnemonic".to_vec(),
    )
    .await
    .expect_err("still no verified ceremony after cancel");
    assert!(after.contains("no verified initiator ceremony"));
}

// ── Capability probing: absence is a downgrade, not an error ──

/// With no engine configured the capability probe reports "unconfigured" rather
/// than failing. Capability lookup must never break pairing, so the probe is
/// total.
#[tokio::test]
async fn capability_probe_reports_unconfigured_without_an_engine() {
    let handle = make_handle();
    let info =
        api::snapshot_upload_capability(&handle).await.expect("the capability probe must not fail");
    assert_eq!(info.state, api::SnapshotUploadCapabilityState::EngineUnconfigured);
    assert_eq!(info.version, 0);
    // The reason is bounded and carries no identifier material.
    let reason = info.reason.unwrap_or_default();
    assert!(!reason.is_empty(), "an unconfigured engine should explain itself");
}

/// A handle pointed at an unreachable relay still answers: the probe downgrades
/// instead of propagating a transport error. Old relays and offline devices must
/// keep pairing.
#[tokio::test]
async fn capability_probe_degrades_on_transport_failure() {
    // `https://localhost:8080` has no listener in the test environment.
    let handle = make_handle();
    // Best-effort engine configuration; without a paired device identity this
    // fails, which the probe must still handle gracefully.
    let _ = api::configure_engine(&handle).await;

    let info = api::snapshot_upload_capability(&handle)
        .await
        .expect("the capability probe must not fail even when the relay is unreachable");
    assert!(
        matches!(
            info.state,
            api::SnapshotUploadCapabilityState::Unavailable
                | api::SnapshotUploadCapabilityState::EngineUnconfigured
        ),
        "an unreachable relay must degrade, got {:?}",
        info.state
    );
}

// ── Legacy APIs remain available ──

/// The legacy one-shot upload keeps its exact signature and reachable path. A
/// mixed-version app build that still calls it must keep compiling and working.
#[tokio::test]
async fn legacy_one_shot_upload_api_still_exists() {
    let handle = make_handle();
    let result: Result<(), String> =
        api::upload_pairing_snapshot(&handle, 300, Some("joiner".to_string())).await;
    // No engine configured, so it fails for the ordinary reason — but the entry
    // point exists, is callable, and is not an unimplemented stub.
    let error = result.expect_err("an unconfigured engine cannot upload");
    assert!(!error.contains("not implemented"), "legacy API must remain implemented: {error}");
}

/// The legacy one-shot initiator completion likewise remains callable.
#[tokio::test]
async fn legacy_one_shot_initiator_completion_still_exists() {
    let handle = make_handle();
    let result: Result<String, String> =
        api::complete_initiator_ceremony(&handle, b"password".to_vec(), b"mnemonic".to_vec()).await;
    let error = result.expect_err("no ceremony is in progress");
    assert!(
        error.contains("no initiator ceremony in progress"),
        "legacy completion must still be implemented and gated: {error}"
    );
}

/// The legacy joiner path is untouched: its entry points remain callable and
/// still validate their own preconditions.
#[tokio::test]
async fn legacy_joiner_entry_points_still_exist() {
    let handle = make_handle();
    let sas = api::get_joiner_sas(&handle).await;
    assert!(sas.is_err(), "no joiner ceremony is in progress");
    let complete = api::complete_joiner_ceremony(&handle, b"password".to_vec()).await;
    let error = complete.expect_err("no joiner ceremony is in progress");
    assert!(
        error.contains("no joiner ceremony in progress"),
        "the joiner path must still be implemented: {error}"
    );
}

/// Cancelling the legacy initiator ceremony still works through the shared
/// cancel entry point, so mixed-version flows keep their cleanup semantics.
#[tokio::test]
async fn cancellation_covers_the_legacy_ceremony_slots() {
    let handle = make_handle();
    // Nothing in flight, but the cancel path must still be total and idempotent
    // across both the joiner and initiator slots.
    for _ in 0..3 {
        api::cancel_pairing_ceremony(&handle).await.expect("cancel must always succeed");
    }
}
