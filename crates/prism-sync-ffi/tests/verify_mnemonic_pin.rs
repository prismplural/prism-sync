//! Tests for the `verify_mnemonic_pin` FFI function.
//!
//! Exercises:
//! - Happy path (correct creds) → Ok(true), handle state unchanged.
//! - Wrong creds → Ok(false), handle state unchanged.
//! - Missing wrapped_dek → Err.

use prism_sync_ffi::api;

/// Helper: initialize a handle with known credentials and return
/// (handle, password_bytes, secret_key_bytes).
async fn initialized_handle() -> (api::PrismSyncHandle, Vec<u8>, Vec<u8>) {
    let handle = api::create_prism_sync(
        "https://localhost:8080".into(),
        ":memory:".into(),
        false,
        String::new(),
        None,
    )
    .expect("create_prism_sync should succeed");

    let mnemonic = api::generate_secret_key().expect("generate_secret_key");
    let secret_key_bytes =
        api::mnemonic_to_bytes(mnemonic.into_bytes()).expect("mnemonic_to_bytes");

    api::initialize(&handle, b"test-pin".to_vec(), secret_key_bytes.clone())
        .await
        .expect("initialize should succeed");

    // Lock so verify_mnemonic_pin is tested against a locked engine.
    api::lock(&handle).await;

    (handle, b"test-pin".to_vec(), secret_key_bytes)
}

// ── Happy path ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn verify_mnemonic_pin_correct_returns_true() {
    let (handle, password, secret_key) = initialized_handle().await;

    let result = api::verify_mnemonic_pin(&handle, password, secret_key).await;
    assert!(matches!(result, Ok(true)), "correct creds should return Ok(true), got: {result:?}");

    // Handle remains locked — verify_mnemonic_pin has no side effects.
    assert!(!api::is_unlocked(&handle).await, "handle should remain locked");
}

// ── Wrong credentials ───────────────────────────────────────────────────────

#[tokio::test]
async fn verify_mnemonic_pin_wrong_pin_returns_false() {
    let (handle, _password, secret_key) = initialized_handle().await;

    let result = api::verify_mnemonic_pin(&handle, b"wrong-pin".to_vec(), secret_key).await;
    assert!(matches!(result, Ok(false)), "wrong PIN should return Ok(false), got: {result:?}");

    assert!(!api::is_unlocked(&handle).await, "handle should remain locked after wrong PIN");
}

#[tokio::test]
async fn verify_mnemonic_pin_wrong_mnemonic_returns_false() {
    let (handle, password, _secret_key) = initialized_handle().await;

    let different_mnemonic = api::generate_secret_key().expect("generate different secret key");
    let different_secret_key =
        api::mnemonic_to_bytes(different_mnemonic.into_bytes()).expect("mnemonic_to_bytes");

    let result = api::verify_mnemonic_pin(&handle, password, different_secret_key).await;
    assert!(matches!(result, Ok(false)), "wrong mnemonic should return Ok(false), got: {result:?}");
}

// ── Missing wrapped_dek → Err ───────────────────────────────────────────────

#[tokio::test]
async fn verify_mnemonic_pin_missing_wrapped_dek_returns_err() {
    // Drain entries from a initialized handle, remove wrapped_dek, then
    // seed a *fresh* handle with those stripped entries so the secure store
    // is clean (no pre-existing wrapped_dek).
    let (source_handle, password, secret_key) = initialized_handle().await;

    let mut store_entries =
        api::drain_secure_store(&source_handle).await.expect("drain_secure_store");
    store_entries.remove("wrapped_dek");

    // Fresh handle — starts with an empty MemorySecureStore.
    let target_handle = api::create_prism_sync(
        "https://localhost:8080".into(),
        ":memory:".into(),
        false,
        String::new(),
        None,
    )
    .expect("create_prism_sync for target_handle");

    // Seed without wrapped_dek so verify_credentials will see it is missing.
    api::seed_secure_store(&target_handle, store_entries).await.expect("seed_secure_store");

    let result = api::verify_mnemonic_pin(&target_handle, password, secret_key).await;
    assert!(result.is_err(), "missing wrapped_dek should return Err, got: {result:?}");
}
