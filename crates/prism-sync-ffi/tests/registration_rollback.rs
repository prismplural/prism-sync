//! Tests for `rollback_first_device_registration`.
//!
//! The rollback FFI is the registry-free counterpart to
//! [`api::deregister_device`]: it cleans up an orphaned relay-side device
//! registration when initiator setup fails after `create_sync_group` returned
//! but before any local registry/keychain row was durable. These tests pin
//! the four contract bullets from the Block 4 plan:
//!
//! 1. NoOp when the in-memory secure store has nothing useful.
//! 2. Deregistered on a clean single-call success path.
//! 3. GroupDeleted fallback when the relay rejects deregister with a 403
//!    "last active device" body.
//! 4. Idempotence: a second back-to-back call after success is a NoOp.
//!
//! Plus negative cases:
//! - Failed (not panic) on relay 5xx / network error, with structured reason.
//! - The function does NOT touch the local registry (works WITHOUT registry
//!   seeding). Verified by leaving storage empty and observing that NO call
//!   to `load_device_ml_dsa_generation` happens — if it did, the function
//!   would emit a "device not in local registry" failure instead of the
//!   relay-error-driven outcomes asserted below.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get},
    Router,
};
use prism_sync_ffi::api;

/// In-process axum mock for the parts of the relay that
/// `rollback_first_device_registration` touches.
///
/// Tracks call counts so tests can assert exactly which endpoints were hit
/// and in what order, and lets each test program a per-endpoint response.
#[derive(Clone, Default)]
struct MockRelayState {
    deregister_calls: Arc<AtomicUsize>,
    delete_group_calls: Arc<AtomicUsize>,
    deregister_response: Arc<std::sync::Mutex<MockResponse>>,
    delete_group_response: Arc<std::sync::Mutex<MockResponse>>,
}

#[derive(Clone)]
struct MockResponse {
    status: u16,
    body: String,
}

impl Default for MockResponse {
    fn default() -> Self {
        Self { status: 204, body: String::new() }
    }
}

impl MockRelayState {
    fn set_deregister(&self, status: u16, body: &str) {
        *self.deregister_response.lock().unwrap() = MockResponse { status, body: body.to_string() };
    }

    fn set_delete_group(&self, status: u16, body: &str) {
        *self.delete_group_response.lock().unwrap() =
            MockResponse { status, body: body.to_string() };
    }

    fn deregister_count(&self) -> usize {
        self.deregister_calls.load(Ordering::SeqCst)
    }

    fn delete_group_count(&self) -> usize {
        self.delete_group_calls.load(Ordering::SeqCst)
    }
}

async fn handle_deregister(State(state): State<MockRelayState>) -> impl IntoResponse {
    state.deregister_calls.fetch_add(1, Ordering::SeqCst);
    let resp = state.deregister_response.lock().unwrap().clone();
    let status = StatusCode::from_u16(resp.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (status, resp.body)
}

async fn handle_delete_group(State(state): State<MockRelayState>) -> impl IntoResponse {
    state.delete_group_calls.fetch_add(1, Ordering::SeqCst);
    let resp = state.delete_group_response.lock().unwrap().clone();
    let status = StatusCode::from_u16(resp.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (status, resp.body)
}

/// Stand-in for the `min_signature_version_floor` GET probe that
/// `ensure_handle_supports_signature_version_floor` does NOT make — but
/// keeping a couple of harmless GETs around helps ensure routing works.
async fn handle_health() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

/// Spin up an axum mock server bound to `127.0.0.1:0`, then return a relay
/// URL anchored at `http://localhost:<port>` so it matches the
/// `ServerRelay::new` allow-list (which only accepts `https://` or
/// `http://localhost`).
async fn start_mock_relay() -> (String, MockRelayState, tokio::task::JoinHandle<()>) {
    let state = MockRelayState::default();
    let app = Router::new()
        .route("/v1/sync/{sync_id}/devices/{device_id}", delete(handle_deregister))
        .route("/v1/sync/{sync_id}", delete(handle_delete_group))
        .route("/health", get(handle_health))
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    // ServerRelay::new only accepts https:// or http://localhost (not raw
    // 127.0.0.1), so use the localhost alias for the test URL.
    let url = format!("http://localhost:{port}");
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (url, state, handle)
}

fn make_handle(relay_url: &str) -> api::PrismSyncHandle {
    api::create_prism_sync(
        relay_url.into(),
        ":memory:".into(),
        true, // allow_insecure: required for the http://localhost mock URL
        String::new(),
        None,
    )
    .expect("create_prism_sync should succeed")
}

/// Seed the four credentials the rollback path expects to read from the
/// in-memory secure store. Mirrors what `PairingService::create_sync_group`
/// would have written before any later FFI step had a chance to fail.
async fn seed_rollback_credentials(handle: &api::PrismSyncHandle) {
    // 32-byte device_secret matches `DeviceSecret::from_bytes` length.
    let mut entries: HashMap<String, Vec<u8>> = HashMap::new();
    entries.insert("sync_id".into(), b"sync-rollback-test".to_vec());
    entries.insert("device_id".into(), b"dev-rollback-test".to_vec());
    entries.insert("session_token".into(), b"token-rollback-test".to_vec());
    entries.insert("device_secret".into(), vec![0x42; 32]);
    api::seed_secure_store(handle, entries).await.expect("seed secure store");
}

fn parse_outcome(json: &str) -> serde_json::Value {
    serde_json::from_str(json).unwrap_or_else(|_| panic!("rollback returned non-JSON: {json}"))
}

// ── 1. NoOp ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn rollback_returns_no_op_when_secure_store_is_empty() {
    let (url, state, _server) = start_mock_relay().await;
    let handle = make_handle(&url);

    let result = api::rollback_first_device_registration(&handle).await;
    let json = result.expect("FFI must not error — failures are reported via outcome");
    let parsed = parse_outcome(&json);

    assert_eq!(parsed["outcome"], "no_op");
    // Reason should mention which credential was missing first.
    assert!(parsed["reason"].is_string(), "no_op outcome must include reason");
    assert_eq!(state.deregister_count(), 0, "must not contact relay when nothing to roll back");
    assert_eq!(state.delete_group_count(), 0);
}

#[tokio::test]
async fn rollback_returns_no_op_when_only_partial_credentials_present() {
    let (url, state, _server) = start_mock_relay().await;
    let handle = make_handle(&url);

    // Seed only sync_id — missing device_id, session_token, device_secret.
    let mut entries: HashMap<String, Vec<u8>> = HashMap::new();
    entries.insert("sync_id".into(), b"sync-rollback".to_vec());
    api::seed_secure_store(&handle, entries).await.unwrap();

    let json = api::rollback_first_device_registration(&handle).await.expect("FFI must not error");
    let parsed = parse_outcome(&json);

    assert_eq!(parsed["outcome"], "no_op");
    assert_eq!(state.deregister_count(), 0);
}

#[tokio::test]
async fn insecure_non_localhost_relay_is_rejected_without_echoing_url() {
    // SECURITY: with the `insecure-transport-dev` feature OFF (the default,
    // including release builds), a cleartext http:// non-localhost relay is
    // rejected at construction — the runtime `allow_insecure = true` cannot
    // open a cleartext transport off the loopback. The error must not echo the
    // secret-bearing URL back to Dart.
    let err = api::create_prism_sync(
        "http://relay.example.com/private/path?token=super-secret".into(),
        ":memory:".into(),
        true,
        String::new(),
        None,
    )
    .expect_err("cleartext non-localhost relay must be rejected when insecure-transport-dev is off");

    assert!(!err.contains("relay.example.com"), "error must not echo host, got: {err}");
    assert!(!err.contains("private/path"), "error must not echo path, got: {err}");
    assert!(!err.contains("super-secret"), "error must not echo token, got: {err}");
}

// ── 2. Deregistered on the happy path ───────────────────────────────────

#[tokio::test]
async fn rollback_returns_deregistered_on_relay_204() {
    let (url, state, _server) = start_mock_relay().await;
    let handle = make_handle(&url);
    seed_rollback_credentials(&handle).await;

    state.set_deregister(204, "");

    let json = api::rollback_first_device_registration(&handle).await.expect("FFI must not error");
    let parsed = parse_outcome(&json);

    assert_eq!(parsed["outcome"], "deregistered");
    assert_eq!(state.deregister_count(), 1);
    assert_eq!(state.delete_group_count(), 0, "must not call delete_sync_group on success");
}

// ── 3. GroupDeleted fallback ────────────────────────────────────────────

#[tokio::test]
async fn rollback_falls_back_to_delete_group_on_last_active_device_403() {
    let (url, state, _server) = start_mock_relay().await;
    let handle = make_handle(&url);
    seed_rollback_credentials(&handle).await;

    // Mirror the relay's literal: see `do_self_deregister` in
    // `prism-sync-relay/src/routes/devices.rs`.
    state.set_deregister(
        403,
        "Cannot deregister the last active device; delete the sync group instead",
    );
    state.set_delete_group(204, "");

    let json = api::rollback_first_device_registration(&handle).await.expect("FFI must not error");
    let parsed = parse_outcome(&json);

    assert_eq!(parsed["outcome"], "group_deleted");
    assert_eq!(parsed["fallback_from"], "last_active_device");
    assert_eq!(state.deregister_count(), 1);
    assert_eq!(state.delete_group_count(), 1, "must fall back to delete_sync_group on 403");
}

#[tokio::test]
async fn rollback_does_not_fall_back_for_unrelated_403() {
    let (url, state, _server) = start_mock_relay().await;
    let handle = make_handle(&url);
    seed_rollback_credentials(&handle).await;

    // 403 with a body that doesn't match the sole-device pattern must NOT
    // trigger the delete_sync_group fallback — that would be destructive in
    // any other "forbidden" scenario (auth misconfig, revocation, etc.).
    state.set_deregister(403, "auth token rejected");

    let json = api::rollback_first_device_registration(&handle).await.expect("FFI must not error");
    let parsed = parse_outcome(&json);

    assert_eq!(parsed["outcome"], "failed");
    assert_eq!(parsed["stage"], "deregister");
    assert_eq!(state.delete_group_count(), 0, "must not delete the group on a non-sole-device 403");
}

// ── 4. Idempotence ─────────────────────────────────────────────────────

#[tokio::test]
async fn rollback_is_idempotent_after_successful_deregister() {
    let (url, state, _server) = start_mock_relay().await;
    let handle = make_handle(&url);
    seed_rollback_credentials(&handle).await;

    state.set_deregister(204, "");

    // First call succeeds and clears the four credentials from the in-memory
    // secure store.
    let first_json = api::rollback_first_device_registration(&handle).await.unwrap();
    assert_eq!(parse_outcome(&first_json)["outcome"], "deregistered");
    assert_eq!(state.deregister_count(), 1);

    // Second call must NOT throw, must NOT contact the relay again, and must
    // resolve to a NoOp because the credentials are gone.
    let second_json = api::rollback_first_device_registration(&handle).await.unwrap();
    assert_eq!(parse_outcome(&second_json)["outcome"], "no_op");
    assert_eq!(state.deregister_count(), 1, "second call must not contact the relay");
    assert_eq!(state.delete_group_count(), 0);
}

#[tokio::test]
async fn rollback_is_idempotent_after_group_deleted_fallback() {
    let (url, state, _server) = start_mock_relay().await;
    let handle = make_handle(&url);
    seed_rollback_credentials(&handle).await;

    state.set_deregister(403, "Cannot deregister the last active device");
    state.set_delete_group(204, "");

    let first_json = api::rollback_first_device_registration(&handle).await.unwrap();
    assert_eq!(parse_outcome(&first_json)["outcome"], "group_deleted");

    let second_json = api::rollback_first_device_registration(&handle).await.unwrap();
    assert_eq!(parse_outcome(&second_json)["outcome"], "no_op");
    // Counts must not increase past the first run.
    assert_eq!(state.deregister_count(), 1);
    assert_eq!(state.delete_group_count(), 1);
}

// ── 5. Failed (not panic) on relay 5xx / network error ────────────────

#[tokio::test]
async fn rollback_returns_failed_on_relay_5xx() {
    let (url, state, _server) = start_mock_relay().await;
    let handle = make_handle(&url);
    seed_rollback_credentials(&handle).await;

    state.set_deregister(500, "internal server error");

    let json = api::rollback_first_device_registration(&handle).await.unwrap();
    let parsed = parse_outcome(&json);

    assert_eq!(parsed["outcome"], "failed");
    assert_eq!(parsed["stage"], "deregister");
    assert!(parsed["reason"].is_string());
}

#[tokio::test]
async fn rollback_returns_failed_when_relay_unreachable() {
    // Bind a listener, capture its port, then drop it so the connection is
    // refused. Removes the network dependency from the test.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let url = format!("http://localhost:{port}");
    let handle = make_handle(&url);
    seed_rollback_credentials(&handle).await;

    let json = api::rollback_first_device_registration(&handle).await.unwrap();
    let parsed = parse_outcome(&json);

    assert_eq!(parsed["outcome"], "failed");
    assert_eq!(parsed["stage"], "deregister");
    assert!(
        parsed["reason"].is_string() && !parsed["reason"].as_str().unwrap().is_empty(),
        "failed outcome must include a non-empty reason"
    );
}

// ── 5b. Concurrency safety: CAS on clear ───────────────────────────────

/// If a setup retry seeds NEW values for the four rollback credential keys
/// while the relay request is in flight, the post-relay clear must NOT
/// wipe those new values. Verified end-to-end by wiring the relay mock so
/// its `deregister` handler signals "request received, now mutating" then
/// awaits a "go" gate. The test mutates `sync_id` while the handler is
/// blocked, releases the gate, and asserts the mutated key survives the
/// post-relay clear while the unchanged keys are cleared.
///
/// Drives the production code path verbatim (no helper exposed for
/// tests), so a regression in either the snapshot capture or the CAS
/// guard breaks this test.
#[tokio::test]
async fn rollback_clear_preserves_sync_id_mutated_during_relay_request() {
    use std::sync::Arc;
    use tokio::sync::Notify;

    // Per-test mock that gates the deregister handler so the test can
    // reliably mutate the secure store while the rollback is awaiting
    // the relay response.
    #[derive(Clone)]
    struct GatedState {
        in_flight: Arc<Notify>,
        release: Arc<Notify>,
    }

    async fn handle_deregister_gated(
        axum::extract::State(state): axum::extract::State<GatedState>,
    ) -> impl IntoResponse {
        // Signal the test that the rollback is now awaiting the relay.
        state.in_flight.notify_one();
        // Wait for the test to mutate the secure store and release us.
        state.release.notified().await;
        (StatusCode::NO_CONTENT, "")
    }

    let in_flight = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let state = GatedState { in_flight: in_flight.clone(), release: release.clone() };

    let app = Router::new()
        .route("/v1/sync/{sync_id}/devices/{device_id}", delete(handle_deregister_gated))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let _server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let url = format!("http://localhost:{port}");

    let handle = Arc::new(make_handle(&url));
    seed_rollback_credentials(&handle).await;

    let rollback_handle = handle.clone();
    let rollback_task =
        tokio::spawn(
            async move { api::rollback_first_device_registration(&rollback_handle).await },
        );

    // Wait for the rollback to enter the relay request — at this point
    // it has already snapshotted the four credentials and released the
    // handle lock, so we can re-acquire it to mutate the store.
    in_flight.notified().await;

    // Simulate a setup retry that re-seeded all four rollback keys during
    // the relay round-trip. Only `sync_id` changes; the other three retain
    // their original values so we can verify CAS clears the unchanged keys.
    let new_sync_id = b"sync-RETRY-SEEDED".to_vec();
    let mut mutator: HashMap<String, Vec<u8>> = HashMap::new();
    mutator.insert("sync_id".into(), new_sync_id.clone());
    mutator.insert("device_id".into(), b"dev-rollback-test".to_vec());
    mutator.insert("session_token".into(), b"token-rollback-test".to_vec());
    mutator.insert("device_secret".into(), vec![0x42; 32]);
    api::seed_secure_store(&handle, mutator).await.unwrap();

    // Release the deregister handler; the rollback proceeds into
    // `clear_rollback_credentials` with the snapshot it captured at the
    // top — original `sync_id` value, not the new one.
    release.notify_one();

    let json = rollback_task.await.unwrap().unwrap();
    let parsed = parse_outcome(&json);
    assert_eq!(parsed["outcome"], "deregistered");

    // Drain the secure store to inspect the post-clear state.
    let drained = api::drain_secure_store(&handle).await.unwrap();

    // sync_id was mutated during the relay window — CAS must see it
    // changed and refuse to delete. The new value survives.
    assert_eq!(
        drained.get("sync_id").map(|v| v.as_slice()),
        Some(new_sync_id.as_slice()),
        "concurrently-seeded sync_id must NOT be wiped by CAS clear",
    );
    // Unchanged keys: CAS sees the value still matches the snapshot and
    // clears them as the original code did.
    assert!(!drained.contains_key("device_id"), "device_id was unchanged and should be cleared",);
    assert!(
        !drained.contains_key("session_token"),
        "session_token was unchanged and should be cleared",
    );
    assert!(
        !drained.contains_key("device_secret"),
        "device_secret was unchanged and should be cleared",
    );
}

// ── 6. Bypasses the local registry ─────────────────────────────────────

#[tokio::test]
async fn rollback_works_without_local_registry_seeding() {
    // The whole point of this FFI is that it does NOT call
    // `load_device_ml_dsa_generation` (which would fail with "device not in
    // local registry" because `import_keyring` hasn't run yet for the
    // initiator failure window). Confirm by leaving the in-memory storage
    // entirely empty (no `import_keyring` call) and asserting we still get
    // a relay-driven outcome — `Deregistered`, not `Failed{stage:
    // load_device_ml_dsa_generation}`.
    let (url, state, _server) = start_mock_relay().await;
    let handle = make_handle(&url);
    seed_rollback_credentials(&handle).await;

    state.set_deregister(204, "");

    let json = api::rollback_first_device_registration(&handle).await.unwrap();
    let parsed = parse_outcome(&json);

    assert_eq!(parsed["outcome"], "deregistered");
    let reason = parsed["reason"].as_str().unwrap_or("");
    assert!(
        !reason.contains("not in local registry"),
        "rollback path must not consult the local registry; got reason: {reason}"
    );
}
