//! Tests for `PrismSync::verify_credentials` — read-only credential check.
//!
//! Verifies that:
//! - Correct credentials return `Ok(true)` without modifying engine state.
//! - Wrong PIN returns `Ok(false)` without modifying engine state.
//! - Wrong mnemonic returns `Ok(false)` without modifying engine state.
//! - Missing `wrapped_dek` returns `Err`.
//! - Missing `dek_salt` returns `Err`.
//!
//! Log redaction: the implementation must not log plaintext MEK, DEK, or
//! wrapped key material. This is enforced by code review against the
//! `tracing` call sites — no `tracing::debug!` of secret bytes is permitted.
//! (No automated log-capture harness is wired in this crate; see AGENTS.md
//! "Crypto And Secret Handling".)

mod common;

use std::sync::Arc;

use prism_sync_core::schema::{SyncSchema, SyncType};
use prism_sync_core::secure_store::SecureStore;
use prism_sync_core::storage::RusqliteSyncStorage;
use prism_sync_core::PrismSync;

use common::MemorySecureStore;

// ── Helpers ────────────────────────────────────────────────────────────────

fn minimal_schema() -> SyncSchema {
    SyncSchema::builder().entity("items", |e| e.field("name", SyncType::String)).build()
}

fn make_initialized_engine() -> (PrismSync, Vec<u8>, Vec<u8>) {
    let storage = Arc::new(RusqliteSyncStorage::in_memory().expect("in-memory SQLite"));
    let store = Arc::new(MemorySecureStore::new());

    let mut sync = PrismSync::builder()
        .schema(minimal_schema())
        .storage(storage)
        .secure_store(store)
        .build()
        .expect("build should succeed");

    let mnemonic = PrismSync::generate_secret_key().expect("generate_secret_key");
    let secret_key = prism_sync_crypto::mnemonic::to_bytes(&mnemonic).expect("mnemonic to_bytes");

    sync.initialize("test-pin", &secret_key).expect("initialize");

    (sync, b"test-pin".to_vec(), secret_key)
}

fn make_initialized_engine_locked() -> (PrismSync, Vec<u8>, Vec<u8>) {
    let (mut sync, password, secret_key) = make_initialized_engine();
    sync.lock();
    (sync, password, secret_key)
}

// ── Tests ──────────────────────────────────────────────────────────────────

/// Correct credentials return Ok(true) and `is_unlocked()` is unchanged.
#[test]
fn correct_credentials_returns_true_no_state_change_unlocked() {
    let (sync, password, secret_key) = make_initialized_engine();

    // Engine is currently unlocked — verify_credentials must not change that.
    assert!(sync.is_unlocked(), "precondition: engine should be unlocked");

    let result = sync.verify_credentials(&password, &secret_key);
    assert!(matches!(result, Ok(true)), "correct creds should return Ok(true), got: {result:?}");

    // is_unlocked unchanged
    assert!(sync.is_unlocked(), "is_unlocked should remain true after verify_credentials");
}

/// Correct credentials on a locked engine: returns Ok(true), engine stays locked.
#[test]
fn correct_credentials_returns_true_no_state_change_locked() {
    let (sync, password, secret_key) = make_initialized_engine_locked();

    assert!(!sync.is_unlocked(), "precondition: engine should be locked");

    let result = sync.verify_credentials(&password, &secret_key);
    assert!(
        matches!(result, Ok(true)),
        "correct creds should return Ok(true) even on locked engine, got: {result:?}"
    );

    // Engine must still be locked — verify_credentials is read-only.
    assert!(!sync.is_unlocked(), "is_unlocked should remain false after verify_credentials");
}

/// Correct credentials: DEK export bytes are identical before and after.
#[test]
fn correct_credentials_dek_export_unchanged() {
    let (sync, password, secret_key) = make_initialized_engine();

    let dek_before = sync.export_dek().expect("export_dek before");

    let result = sync.verify_credentials(&password, &secret_key);
    assert!(matches!(result, Ok(true)), "expected Ok(true), got: {result:?}");

    let dek_after = sync.export_dek().expect("export_dek after");
    assert_eq!(dek_before, dek_after, "DEK bytes must be identical after verify_credentials");
}

/// Wrong PIN: returns Ok(false), engine state unchanged (locked stays locked).
#[test]
fn wrong_pin_returns_false() {
    let (sync, _password, secret_key) = make_initialized_engine_locked();

    let result = sync.verify_credentials(b"wrong-pin", &secret_key);
    assert!(matches!(result, Ok(false)), "wrong PIN should return Ok(false), got: {result:?}");

    assert!(!sync.is_unlocked(), "is_unlocked should remain false after wrong-pin verify");
}

/// Wrong PIN on unlocked engine: returns Ok(false), DEK export bytes unchanged.
#[test]
fn wrong_pin_dek_export_unchanged() {
    let (sync, _password, secret_key) = make_initialized_engine();

    let dek_before = sync.export_dek().expect("export_dek before");

    let result = sync.verify_credentials(b"wrong-pin", &secret_key);
    assert!(matches!(result, Ok(false)), "expected Ok(false), got: {result:?}");

    let dek_after = sync.export_dek().expect("export_dek after");
    assert_eq!(dek_before, dek_after, "DEK bytes must be unchanged after wrong-pin verify");
}

/// Wrong mnemonic: returns Ok(false), engine state unchanged.
#[test]
fn wrong_mnemonic_returns_false() {
    let (sync, password, _secret_key) = make_initialized_engine_locked();

    // A different valid mnemonic — produces different secret_key bytes.
    let different_mnemonic = PrismSync::generate_secret_key().expect("generate_secret_key");
    let different_secret_key =
        prism_sync_crypto::mnemonic::to_bytes(&different_mnemonic).expect("mnemonic to_bytes");

    let result = sync.verify_credentials(&password, &different_secret_key);
    assert!(matches!(result, Ok(false)), "wrong mnemonic should return Ok(false), got: {result:?}");

    assert!(!sync.is_unlocked(), "is_unlocked should remain false after wrong-mnemonic verify");
}

/// Wrong mnemonic on unlocked engine: DEK export bytes unchanged.
#[test]
fn wrong_mnemonic_dek_export_unchanged() {
    let (sync, password, _secret_key) = make_initialized_engine();

    let dek_before = sync.export_dek().expect("export_dek before");

    let different_mnemonic = PrismSync::generate_secret_key().expect("generate_secret_key");
    let different_secret_key =
        prism_sync_crypto::mnemonic::to_bytes(&different_mnemonic).expect("mnemonic to_bytes");

    let result = sync.verify_credentials(&password, &different_secret_key);
    assert!(matches!(result, Ok(false)), "expected Ok(false), got: {result:?}");

    let dek_after = sync.export_dek().expect("export_dek after");
    assert_eq!(dek_before, dek_after, "DEK bytes must be unchanged after wrong-mnemonic verify");
}

/// Missing `wrapped_dek` returns Err (not Ok(false)).
#[test]
fn missing_wrapped_dek_returns_err() {
    let storage = Arc::new(RusqliteSyncStorage::in_memory().expect("in-memory SQLite"));
    let store = Arc::new(MemorySecureStore::new());

    let mut sync = PrismSync::builder()
        .schema(minimal_schema())
        .storage(storage)
        .secure_store(store.clone())
        .build()
        .expect("build");

    let mnemonic = PrismSync::generate_secret_key().expect("generate_secret_key");
    let secret_key = prism_sync_crypto::mnemonic::to_bytes(&mnemonic).expect("to_bytes");

    sync.initialize("pin", &secret_key).expect("initialize");

    // Delete `wrapped_dek` to simulate missing entry.
    store.delete("wrapped_dek").expect("delete wrapped_dek");

    let result = sync.verify_credentials(b"pin", &secret_key);
    assert!(result.is_err(), "missing wrapped_dek should return Err, got: {result:?}");
}

/// Missing `dek_salt` returns Err (not Ok(false)).
#[test]
fn missing_dek_salt_returns_err() {
    let storage = Arc::new(RusqliteSyncStorage::in_memory().expect("in-memory SQLite"));
    let store = Arc::new(MemorySecureStore::new());

    let mut sync = PrismSync::builder()
        .schema(minimal_schema())
        .storage(storage)
        .secure_store(store.clone())
        .build()
        .expect("build");

    let mnemonic = PrismSync::generate_secret_key().expect("generate_secret_key");
    let secret_key = prism_sync_crypto::mnemonic::to_bytes(&mnemonic).expect("to_bytes");

    sync.initialize("pin", &secret_key).expect("initialize");

    // Delete `dek_salt` to simulate missing entry.
    store.delete("dek_salt").expect("delete dek_salt");

    let result = sync.verify_credentials(b"pin", &secret_key);
    assert!(result.is_err(), "missing dek_salt should return Err, got: {result:?}");
}

/// Best-effort timing-channel test: Err and Ok(false) paths must complete in
/// roughly the same time (no short-circuit on missing prefix vs. AEAD fail).
///
/// Marked `#[ignore]` — timing tests are inherently flaky on shared CI runners.
/// Run manually: `cargo test -p prism-sync-core verify_credentials -- --ignored`
///
/// Note: Argon2id dominates both paths (both perform the full KDF), so the
/// timing difference between them should be negligible. The AEAD decrypt
/// failure is constant-time within the chacha20poly1305 crate's guarantees.
///
/// Important: The Err path (missing wrapped_dek) short-circuits *before*
/// Argon2id, so it will be much faster than Ok(false). This test documents
/// the asymmetry rather than asserting timing equality. The security
/// implication is acceptable: the Err path indicates an infrastructure
/// problem (missing store entry), not a credential check, so it does not
/// leak whether the credential was correct.
#[test]
#[ignore]
fn timing_channel_ok_false_vs_err_documented() {
    use std::time::Instant;

    let (sync, _password, secret_key) = make_initialized_engine_locked();

    // Build a second engine with the wrapped_dek deleted (Err path).
    let storage2 = Arc::new(RusqliteSyncStorage::in_memory().expect("in-memory SQLite"));
    let store2 = Arc::new(MemorySecureStore::new());
    let mut sync2 = PrismSync::builder()
        .schema(minimal_schema())
        .storage(storage2)
        .secure_store(store2.clone())
        .build()
        .expect("build");
    let mnemonic2 = PrismSync::generate_secret_key().expect("generate_secret_key");
    let secret_key2 = prism_sync_crypto::mnemonic::to_bytes(&mnemonic2).expect("to_bytes");
    sync2.initialize("pin2", &secret_key2).expect("initialize");
    store2.delete("wrapped_dek").expect("delete wrapped_dek");

    const ROUNDS: usize = 10; // keep low — Argon2id is expensive

    let mut ok_false_total = 0u128;
    for _ in 0..ROUNDS {
        let t = Instant::now();
        let _ = sync.verify_credentials(b"wrong-pin", &secret_key);
        ok_false_total += t.elapsed().as_millis();
    }

    let mut err_total = 0u128;
    for _ in 0..ROUNDS {
        let t = Instant::now();
        let _ = sync2.verify_credentials(b"pin2", &secret_key2);
        err_total += t.elapsed().as_millis();
    }

    let ok_false_mean = ok_false_total / ROUNDS as u128;
    let err_mean = err_total / ROUNDS as u128;

    // Document the timing difference — Err path is much faster (no Argon2id).
    println!("ok_false mean: {ok_false_mean}ms, err (missing wrapped_dek) mean: {err_mean}ms");
    println!("Note: Err path short-circuits before Argon2id; this is expected and acceptable.");

    // The only assertion: Ok(false) must actually run Argon2id and take >100ms.
    assert!(
        ok_false_mean > 100,
        "Ok(false) path should run Argon2id (>100ms), got: {ok_false_mean}ms — \
         check that verify_credentials does not short-circuit on wrong creds"
    );
}
