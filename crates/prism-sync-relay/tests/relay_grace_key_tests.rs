//! Tests for ML-DSA grace-key fallback in auth middleware.
//!
//! After a device rotates its ML-DSA key, both the old and new keys should be
//! accepted for authentication during a 30-day grace period.

mod common;

use reqwest::Client;

use prism_sync_crypto::DeviceSecret;
use prism_sync_relay::db;

use common::*;

/// Register a first device via the HTTP API (creating the sync group), then
/// prepare a second device via direct DB insertion. Returns the second device's
/// token and keys.
async fn setup_device(
    url: &str,
    db: &std::sync::Arc<db::Database>,
    sync_id: &str,
    device_id: &str,
) -> (String, TestDeviceKeys) {
    let client = Client::new();
    let first_id = generate_device_id();
    let first_keys = TestDeviceKeys::generate(&first_id);
    let _ = register_device(&client, url, sync_id, &first_id, &first_keys).await;
    prepare_device(db, sync_id, device_id).await
}

/// Helper: push a test envelope using the given ML-DSA keypair for signing.
/// Returns the HTTP status code.
async fn push_with_ml_dsa_key(
    url: &str,
    token: &str,
    sync_id: &str,
    device_id: &str,
    ed25519_key: &ed25519_dalek::SigningKey,
    ml_dsa_key: &prism_sync_crypto::DevicePqSigningKey,
    batch_id: &str,
) -> u16 {
    let client = Client::new();
    let envelope = make_test_envelope(sync_id, device_id, batch_id, 0);
    let body_bytes = serde_json::to_vec(&envelope).unwrap();
    let path = format!("/v1/sync/{sync_id}/changes");

    let resp = apply_signed_headers_hybrid(
        client
            .put(format!("{url}{path}"))
            .header("Authorization", format!("Bearer {token}"))
            .header("X-Device-Id", device_id)
            .header("Content-Type", "application/json"),
        ed25519_key,
        ml_dsa_key,
        "PUT",
        &path,
        sync_id,
        device_id,
        &body_bytes,
    )
    .body(body_bytes)
    .send()
    .await
    .unwrap();

    resp.status().as_u16()
}

/// Request signed with the current ML-DSA key passes (baseline).
#[tokio::test]
async fn test_current_key_passes() {
    let (url, _server, db) = start_test_relay().await;
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let (token, keys) = setup_device(&url, &db, &sync_id, &device_id).await;

    let ml_dsa_kp = keys.device_secret.ml_dsa_65_keypair(&device_id).unwrap();
    let status = push_with_ml_dsa_key(
        &url,
        &token,
        &sync_id,
        &device_id,
        &keys.ed25519_signing_key,
        &ml_dsa_kp,
        "batch-current-key",
    )
    .await;

    assert!((200..300).contains(&status), "current key should pass: {status}");
}

/// Request signed with a grace-period key passes when prev key is set and not expired.
#[tokio::test]
async fn test_grace_key_passes_during_grace_period() {
    let (url, _server, db) = start_test_relay().await;
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let (token, keys) = setup_device(&url, &db, &sync_id, &device_id).await;

    // The device was registered with keys derived from keys.device_secret.
    // That's the "old" key. Generate a new secret for the "rotated" key.
    let old_ml_dsa_kp = keys.device_secret.ml_dsa_65_keypair(&device_id).unwrap();
    let old_ml_dsa_pk = old_ml_dsa_kp.public_key_bytes();

    let new_device_secret = DeviceSecret::generate();
    let new_ml_dsa_kp = new_device_secret.ml_dsa_65_keypair(&device_id).unwrap();
    let new_ml_dsa_pk = new_ml_dsa_kp.public_key_bytes();

    // Simulate key rotation: current key = new, prev key = old, grace period active
    let grace_expires = db::now_secs() + 30 * 86400;
    let sid = sync_id.clone();
    let did = device_id.clone();
    db.with_conn(move |conn| {
        conn.execute(
            "UPDATE devices SET ml_dsa_65_public_key = ?1, \
             prev_ml_dsa_65_public_key = ?2, prev_ml_dsa_65_expires_at = ?3 \
             WHERE sync_id = ?4 AND device_id = ?5",
            rusqlite::params![new_ml_dsa_pk, old_ml_dsa_pk, grace_expires, sid, did],
        )?;
        Ok::<_, rusqlite::Error>(())
    })
    .unwrap();

    // Sign with the OLD ML-DSA key (grace key) — should succeed
    let status = push_with_ml_dsa_key(
        &url,
        &token,
        &sync_id,
        &device_id,
        &keys.ed25519_signing_key,
        &old_ml_dsa_kp,
        "batch-grace-key",
    )
    .await;

    assert!((200..300).contains(&status), "grace key should pass during grace period: {status}");
}

/// Request signed with an expired grace key fails.
#[tokio::test]
async fn test_expired_grace_key_fails() {
    let (url, _server, db) = start_test_relay().await;
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let (token, keys) = setup_device(&url, &db, &sync_id, &device_id).await;

    let old_ml_dsa_kp = keys.device_secret.ml_dsa_65_keypair(&device_id).unwrap();
    let old_ml_dsa_pk = old_ml_dsa_kp.public_key_bytes();

    let new_device_secret = DeviceSecret::generate();
    let new_ml_dsa_kp = new_device_secret.ml_dsa_65_keypair(&device_id).unwrap();
    let new_ml_dsa_pk = new_ml_dsa_kp.public_key_bytes();

    // Grace period already expired
    let grace_expires = db::now_secs() - 1;
    let sid = sync_id.clone();
    let did = device_id.clone();
    db.with_conn(move |conn| {
        conn.execute(
            "UPDATE devices SET ml_dsa_65_public_key = ?1, \
             prev_ml_dsa_65_public_key = ?2, prev_ml_dsa_65_expires_at = ?3 \
             WHERE sync_id = ?4 AND device_id = ?5",
            rusqlite::params![new_ml_dsa_pk, old_ml_dsa_pk, grace_expires, sid, did],
        )?;
        Ok::<_, rusqlite::Error>(())
    })
    .unwrap();

    // Sign with the OLD ML-DSA key — should fail (grace period expired)
    let status = push_with_ml_dsa_key(
        &url,
        &token,
        &sync_id,
        &device_id,
        &keys.ed25519_signing_key,
        &old_ml_dsa_kp,
        "batch-expired-grace",
    )
    .await;

    assert_eq!(status, 401, "expired grace key should be rejected: {status}");
}

/// Request signed with a completely unknown key fails (neither current nor grace).
#[tokio::test]
async fn test_unknown_key_fails() {
    let (url, _server, db) = start_test_relay().await;
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let (token, keys) = setup_device(&url, &db, &sync_id, &device_id).await;

    // Generate a totally unrelated ML-DSA keypair
    let unknown_secret = DeviceSecret::generate();
    let unknown_ml_dsa_kp = unknown_secret.ml_dsa_65_keypair(&device_id).unwrap();

    // Sign with an unknown ML-DSA key — should fail
    let status = push_with_ml_dsa_key(
        &url,
        &token,
        &sync_id,
        &device_id,
        &keys.ed25519_signing_key,
        &unknown_ml_dsa_kp,
        "batch-unknown-key",
    )
    .await;

    assert_eq!(status, 401, "unknown key should be rejected: {status}");
}
