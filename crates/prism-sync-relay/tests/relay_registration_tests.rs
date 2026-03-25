//! End-to-end tests for device registration, listing, status, authentication,
//! revocation, rekey, and invitation flows against the actual prism-sync-relay
//! server running in-process with an in-memory SQLite database.
//!
//! These tests use raw `reqwest` calls to exercise the relay HTTP API because
//! `ServerRelay::new()` only accepts `http://localhost` or `https://` URLs and
//! uses base64 encoding for keys while the relay expects hex — so direct HTTP
//! calls give us more control and validate the actual wire protocol.

mod common;

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use reqwest::Client;
use serde_json::Value;

use prism_sync_relay::{
    config::Config,
    db::{self, Database},
    routes,
    state::AppState,
};

use common::*;

// ───────────────────────────── Test 1: Registration E2E ─────────────────

#[tokio::test]
async fn test_registration_flow() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let signing_key = SigningKey::generate(&mut rand::thread_rng());

    // 1. Fetch nonce
    let nonce_resp = client
        .get(format!("{url}/v1/sync/{sync_id}/register-nonce"))
        .send()
        .await
        .unwrap();
    assert_eq!(nonce_resp.status(), 200);
    let nonce_json: Value = nonce_resp.json().await.unwrap();
    let nonce = nonce_json["nonce"].as_str().expect("nonce field missing");
    assert!(!nonce.is_empty());

    // 2. Sign challenge
    let challenge_sig = sign_challenge(&signing_key, &sync_id, &device_id, nonce);

    // 3. Generate X25519 key
    let mut x25519_pk = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut x25519_pk);

    // 4. Register
    let register_resp = client
        .post(format!("{url}/v1/sync/{sync_id}/register"))
        .json(&serde_json::json!({
            "device_id": device_id,
            "signing_public_key": hex::encode(signing_key.verifying_key().as_bytes()),
            "x25519_public_key": hex::encode(x25519_pk),
            "registration_challenge": hex::encode(&challenge_sig),
            "nonce": nonce,
        }))
        .send()
        .await
        .unwrap();
    assert!(
        register_resp.status().is_success(),
        "register failed: {}",
        register_resp.status()
    );
    let token_json: Value = register_resp.json().await.unwrap();
    let token = token_json["device_session_token"].as_str().unwrap();
    assert!(token.len() >= 32, "session token too short");

    // 5. Verify we can use the token for an authenticated request (health-check via devices list)
    let devices_resp = client
        .get(format!("{url}/v1/sync/{sync_id}/devices"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id)
        .send()
        .await
        .unwrap();
    assert_eq!(devices_resp.status(), 200);
    let devices: Vec<Value> = devices_resp.json().await.unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0]["device_id"].as_str().unwrap(), device_id);
    assert_eq!(devices[0]["status"].as_str().unwrap(), "active");
}

#[tokio::test]
async fn test_registration_rejects_bad_challenge() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();

    // Fetch nonce
    let nonce_resp = client
        .get(format!("{url}/v1/sync/{sync_id}/register-nonce"))
        .send()
        .await
        .unwrap();
    let nonce_json: Value = nonce_resp.json().await.unwrap();
    let nonce = nonce_json["nonce"].as_str().unwrap();

    // Use a random key but sign with wrong data (wrong nonce)
    let signing_key = SigningKey::generate(&mut rand::thread_rng());
    let bad_sig = sign_challenge(&signing_key, &sync_id, &device_id, "wrong-nonce");

    let mut x25519_pk = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut x25519_pk);

    let register_resp = client
        .post(format!("{url}/v1/sync/{sync_id}/register"))
        .json(&serde_json::json!({
            "device_id": device_id,
            "signing_public_key": hex::encode(signing_key.verifying_key().as_bytes()),
            "x25519_public_key": hex::encode(x25519_pk),
            "registration_challenge": hex::encode(&bad_sig),
            "nonce": nonce,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        register_resp.status(),
        401,
        "bad challenge should be rejected"
    );
}

#[tokio::test]
async fn test_registration_rejects_expired_nonce() {
    // Start relay with very short nonce expiry
    let config = Config {
        port: 0,
        db_path: ":memory:".into(),
        nonce_expiry_secs: 0, // Expire immediately
        session_expiry_secs: 3600,
        invite_ttl_secs: 86400,
        sync_inactive_ttl_secs: 7_776_000,
        stale_device_secs: 2_592_000,
        cleanup_interval_secs: 3600,
        max_unpruned_batches: 10_000,
        metrics_token: None,
        nonce_rate_limit: 100,
        nonce_rate_window_secs: 60,
        snapshot_default_ttl_secs: 86400,
        reader_pool_size: 2,
        node_exporter_url: None,
    };

    let db = Database::in_memory().expect("in-memory db");
    let state = AppState::new(db, config);
    let app = routes::router(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://127.0.0.1:{}", addr.port());
    let _handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let signing_key = SigningKey::generate(&mut rand::thread_rng());

    // Fetch nonce
    let nonce_resp = client
        .get(format!("{url}/v1/sync/{sync_id}/register-nonce"))
        .send()
        .await
        .unwrap();
    let nonce_json: Value = nonce_resp.json().await.unwrap();
    let nonce = nonce_json["nonce"].as_str().unwrap();

    // No sleep needed: nonce_expiry_secs=0 means expires_at == created_at.
    // The consume check is `expires_at > now` (strict inequality), so a nonce
    // with zero TTL is expired the instant it is created — even within the same
    // second.

    let challenge_sig = sign_challenge(&signing_key, &sync_id, &device_id, nonce);
    let mut x25519_pk = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut x25519_pk);

    let register_resp = client
        .post(format!("{url}/v1/sync/{sync_id}/register"))
        .json(&serde_json::json!({
            "device_id": device_id,
            "signing_public_key": hex::encode(signing_key.verifying_key().as_bytes()),
            "x25519_public_key": hex::encode(x25519_pk),
            "registration_challenge": hex::encode(&challenge_sig),
            "nonce": nonce,
        }))
        .send()
        .await
        .unwrap();
    // Should fail with 400 (bad request — expired nonce)
    assert_eq!(
        register_resp.status(),
        400,
        "expired nonce should be rejected"
    );
}

// ───────────────────────────── Test: Nonce rate limiting ────────────────

#[tokio::test]
async fn test_nonce_rate_limiting() {
    // Start relay with a low nonce rate limit
    let config = Config {
        port: 0,
        db_path: ":memory:".into(),
        nonce_expiry_secs: 60,
        session_expiry_secs: 3600,
        invite_ttl_secs: 86400,
        sync_inactive_ttl_secs: 7_776_000,
        stale_device_secs: 2_592_000,
        cleanup_interval_secs: 3600,
        max_unpruned_batches: 10_000,
        metrics_token: None,
        nonce_rate_limit: 3, // Only 3 nonces per window
        nonce_rate_window_secs: 60,
        snapshot_default_ttl_secs: 86400,
        reader_pool_size: 2,
        node_exporter_url: None,
    };

    let db = Database::in_memory().expect("in-memory db");
    let state = AppState::new(db, config);
    let app = routes::router(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://127.0.0.1:{}", addr.port());
    let _handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let client = Client::new();
    let sync_id = generate_sync_id();

    // First 3 requests should succeed
    for i in 0..3 {
        let resp = client
            .get(format!("{url}/v1/sync/{sync_id}/register-nonce"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "request {i} should succeed");
    }

    // 4th request should be rate-limited
    let resp = client
        .get(format!("{url}/v1/sync/{sync_id}/register-nonce"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 429, "4th request should be rate-limited");

    // Different sync_id should still work
    let other_sync_id = generate_sync_id();
    let resp = client
        .get(format!("{url}/v1/sync/{other_sync_id}/register-nonce"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "different sync_id should not be rate-limited"
    );
}

// ───────────────────────────── Test 3: Device List ──────────────────────

#[tokio::test]
async fn test_list_devices_returns_public_keys() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    // Register device
    let device_id = generate_device_id();
    let signing_key = SigningKey::generate(&mut rand::thread_rng());
    let token = register_device(&client, &url, &sync_id, &device_id, &signing_key).await;

    // List devices
    let resp = client
        .get(format!("{url}/v1/sync/{sync_id}/devices"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let devices: Vec<Value> = resp.json().await.unwrap();
    assert_eq!(devices.len(), 1);

    let dev = &devices[0];
    assert_eq!(dev["device_id"].as_str().unwrap(), device_id);
    assert_eq!(dev["status"].as_str().unwrap(), "active");
    assert_eq!(dev["epoch"].as_i64().unwrap(), 0);
    assert_eq!(dev["permission"].as_str().unwrap(), "admin");

    // Verify public keys are present (base64-encoded by the relay)
    let b64 = base64::engine::general_purpose::STANDARD;
    let signing_pk_b64 = dev["signing_public_key"].as_str().unwrap();
    let signing_pk_bytes = b64.decode(signing_pk_b64).unwrap();
    assert_eq!(
        signing_pk_bytes,
        signing_key.verifying_key().as_bytes().as_slice(),
        "signing public key should match"
    );

    let x25519_pk_b64 = dev["x25519_public_key"].as_str().unwrap();
    let x25519_pk_bytes = b64.decode(x25519_pk_b64).unwrap();
    assert_eq!(x25519_pk_bytes.len(), 32, "x25519 key should be 32 bytes");
}

// ───────────────────────────── Test 6: Auth rejection ───────────────────

#[tokio::test]
async fn test_unauthenticated_requests_rejected() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    // No auth header
    let resp = client
        .get(format!("{url}/v1/sync/{sync_id}/devices"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // Invalid token
    let resp2 = client
        .get(format!("{url}/v1/sync/{sync_id}/devices"))
        .header("Authorization", "Bearer invalid-short")
        .send()
        .await
        .unwrap();
    assert_eq!(resp2.status(), 401);

    // Token with correct length but not registered
    let fake_token = "a".repeat(64);
    let resp3 = client
        .get(format!("{url}/v1/sync/{sync_id}/devices"))
        .header("Authorization", format!("Bearer {fake_token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp3.status(), 401);
}

// ──────────────────────── Test 8: Delete sync group ─────────────────────

#[tokio::test]
async fn test_delete_sync_group() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let device_id = generate_device_id();
    let signing_key = SigningKey::generate(&mut rand::thread_rng());
    let token = register_device(&client, &url, &sync_id, &device_id, &signing_key).await;

    // Push some data first
    let envelope = make_test_envelope(&sync_id, &device_id, "batch-delete-test", 0);
    let push_resp = client
        .put(format!("{url}/v1/sync/{sync_id}/changes"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id)
        .json(&envelope)
        .send()
        .await
        .unwrap();
    assert!(push_resp.status().is_success());

    // Delete the sync group (only sole admin can do this)
    let del_resp = client
        .delete(format!("{url}/v1/sync/{sync_id}"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id)
        .send()
        .await
        .unwrap();
    assert_eq!(del_resp.status(), 204);

    // Further requests should fail (session invalidated / group gone)
    let pull_resp = client
        .get(format!("{url}/v1/sync/{sync_id}/changes?since=0"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id)
        .send()
        .await
        .unwrap();
    // Should fail — either 401 (session deleted) or 404 (group gone)
    assert!(
        pull_resp.status() == 401 || pull_resp.status() == 404,
        "expected 401 or 404 after group deletion, got {}",
        pull_resp.status()
    );
}

// ──────────────────────── Test 9: Rekey artifacts ───────────────────────

#[tokio::test]
async fn test_rekey_artifacts_store_and_retrieve() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    // Register a single device (admin)
    let device_id = generate_device_id();
    let signing_key = SigningKey::generate(&mut rand::thread_rng());
    let token = register_device(&client, &url, &sync_id, &device_id, &signing_key).await;

    let b64 = base64::engine::general_purpose::STANDARD;

    // Post rekey artifacts: epoch 0 -> 1, no revoked device, just wrap for self
    let wrapped_key_data = b"fake-wrapped-epoch-key-for-device";
    let rekey_resp = client
        .post(format!("{url}/v1/sync/{sync_id}/rekey"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id)
        .json(&serde_json::json!({
            "epoch": 1,
            "wrapped_keys": {
                device_id.clone(): b64.encode(wrapped_key_data),
            },
        }))
        .send()
        .await
        .unwrap();
    assert!(
        rekey_resp.status().is_success(),
        "rekey failed: {} - {:?}",
        rekey_resp.status(),
        rekey_resp.text().await.ok()
    );

    // Re-register to get a new token (epoch has changed, old session should still work
    // but let's use the one we have)
    // Actually the token should still be valid since we just bumped epoch.

    // Retrieve the artifact
    let artifact_resp = client
        .get(format!("{url}/v1/sync/{sync_id}/rekey/1/{device_id}"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id)
        .send()
        .await
        .unwrap();
    assert_eq!(artifact_resp.status(), 200);
    let artifact_json: Value = artifact_resp.json().await.unwrap();
    let retrieved = b64
        .decode(artifact_json["wrapped_key"].as_str().unwrap())
        .unwrap();
    assert_eq!(retrieved, wrapped_key_data);

    // Non-existent artifact returns 404
    let missing_resp = client
        .get(format!("{url}/v1/sync/{sync_id}/rekey/99/{device_id}"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id)
        .send()
        .await
        .unwrap();
    assert_eq!(missing_resp.status(), 404);
}

// ──────────────────────── Test 10: Health check ─────────────────────────

#[tokio::test]
async fn test_health_endpoint() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();

    let resp = client.get(format!("{url}/health")).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let json: Value = resp.json().await.unwrap();
    assert_eq!(json["status"].as_str().unwrap(), "ok");
}

// ───────────────────── Test: Rate limiting with window expiry e2e ────────

#[tokio::test]
async fn test_nonce_rate_limiting_window_expiry() {
    // Start relay with a very low rate limit and short window
    let config = Config {
        port: 0,
        db_path: ":memory:".into(),
        nonce_expiry_secs: 60,
        session_expiry_secs: 3600,
        invite_ttl_secs: 86400,
        sync_inactive_ttl_secs: 7_776_000,
        stale_device_secs: 2_592_000,
        cleanup_interval_secs: 3600,
        max_unpruned_batches: 10_000,
        metrics_token: None,
        nonce_rate_limit: 2,       // Only 2 nonces per window
        nonce_rate_window_secs: 1, // 1-second window
        snapshot_default_ttl_secs: 86400,
        reader_pool_size: 2,
        node_exporter_url: None,
    };

    let db = Database::in_memory().expect("in-memory db");
    let state = AppState::new(db, config);
    let app = routes::router(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://127.0.0.1:{}", addr.port());
    let _handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let client = Client::new();
    let sync_id = generate_sync_id();

    // First 2 requests should succeed
    for i in 0..2 {
        let resp = client
            .get(format!("{url}/v1/sync/{sync_id}/register-nonce"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "request {i} should succeed");
    }

    // 3rd request should be rate-limited
    let resp = client
        .get(format!("{url}/v1/sync/{sync_id}/register-nonce"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 429, "3rd request should be rate-limited");

    // Poll until the 1-second rate-limit window expires.
    // Uses a retry loop instead of a fixed sleep to tolerate CI timing jitter.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        let resp = client
            .get(format!("{url}/v1/sync/{sync_id}/register-nonce"))
            .send()
            .await
            .unwrap();
        if resp.status() == 200 {
            break; // Window expired, request succeeded
        }
        assert!(
            std::time::Instant::now() < deadline,
            "rate-limit window did not expire within 5 seconds"
        );
    }
}

// ──────────────── Test: Registration rollback on missing invitation ──────

#[tokio::test]
async fn test_registration_rollback_no_invitation() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    // Register first device successfully (creates the sync group)
    let device_a_id = generate_device_id();
    let signing_key_a = SigningKey::generate(&mut rand::thread_rng());
    let token_a = register_device(&client, &url, &sync_id, &device_a_id, &signing_key_a).await;

    // Attempt to register a second device WITHOUT an invitation
    let device_b_id = generate_device_id();
    let signing_key_b = SigningKey::generate(&mut rand::thread_rng());

    // Fetch nonce for device B
    let nonce_resp = client
        .get(format!("{url}/v1/sync/{sync_id}/register-nonce"))
        .send()
        .await
        .unwrap();
    assert_eq!(nonce_resp.status(), 200);
    let nonce_json: Value = nonce_resp.json().await.unwrap();
    let nonce = nonce_json["nonce"].as_str().unwrap().to_string();

    // Sign challenge for device B
    let challenge_sig = sign_challenge(&signing_key_b, &sync_id, &device_b_id, &nonce);

    let mut x25519_pk = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut x25519_pk);

    // Register device B without signed_invitation — should fail
    let register_resp = client
        .post(format!("{url}/v1/sync/{sync_id}/register"))
        .json(&serde_json::json!({
            "device_id": device_b_id,
            "signing_public_key": hex::encode(signing_key_b.verifying_key().as_bytes()),
            "x25519_public_key": hex::encode(x25519_pk),
            "registration_challenge": hex::encode(&challenge_sig),
            "nonce": nonce,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        register_resp.status(),
        401,
        "second device without invitation should be rejected"
    );

    // Verify the first device's sync group is still intact
    let devices_resp = client
        .get(format!("{url}/v1/sync/{sync_id}/devices"))
        .header("Authorization", format!("Bearer {token_a}"))
        .header("X-Device-Id", &device_a_id)
        .send()
        .await
        .unwrap();
    assert_eq!(devices_resp.status(), 200);
    let devices: Vec<Value> = devices_resp.json().await.unwrap();
    assert_eq!(devices.len(), 1, "only the first device should exist");
    assert_eq!(devices[0]["device_id"].as_str().unwrap(), device_a_id);
    assert_eq!(devices[0]["status"].as_str().unwrap(), "active");

    // Verify push still works for device A (sync group not corrupted)
    let envelope = make_test_envelope(&sync_id, &device_a_id, "batch-after-rollback", 0);
    let push_resp = client
        .put(format!("{url}/v1/sync/{sync_id}/changes"))
        .header("Authorization", format!("Bearer {token_a}"))
        .header("X-Device-Id", &device_a_id)
        .json(&envelope)
        .send()
        .await
        .unwrap();
    assert!(
        push_resp.status().is_success(),
        "push should still work after failed registration: {}",
        push_resp.status()
    );
}

// ────────────── Test: Revoke does not bump epoch ──────────────

#[tokio::test]
async fn test_revoke_does_not_bump_epoch() {
    let (url, _server, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    // Register admin device via HTTP
    let admin_id = generate_device_id();
    let admin_key = SigningKey::generate(&mut rand::thread_rng());
    let admin_token = register_device(&client, &url, &sync_id, &admin_id, &admin_key).await;

    // Register target device directly via DB
    let target_id = generate_device_id();
    let _target_token = prepare_device(&db, &sync_id, &target_id).await;

    // Revoke the target device
    let revoke_resp = client
        .delete(format!("{url}/v1/sync/{sync_id}/devices/{target_id}"))
        .header("Authorization", format!("Bearer {admin_token}"))
        .header("X-Device-Id", &admin_id)
        .send()
        .await
        .unwrap();
    assert_eq!(revoke_resp.status(), 204, "revoke should return 204");

    // Verify epoch is still 0 by posting a rekey with epoch=1.
    // If current epoch were already 1, this would fail with "must be current_epoch + 1".
    let b64 = base64::engine::general_purpose::STANDARD;
    let rekey_resp = client
        .post(format!("{url}/v1/sync/{sync_id}/rekey"))
        .header("Authorization", format!("Bearer {admin_token}"))
        .header("X-Device-Id", &admin_id)
        .json(&serde_json::json!({
            "epoch": 1,
            "wrapped_keys": {
                admin_id.clone(): b64.encode(b"fake-wrapped-key"),
            },
        }))
        .send()
        .await
        .unwrap();
    assert!(
        rekey_resp.status().is_success(),
        "rekey with epoch=1 should succeed (proving epoch was 0 after revoke): {} - {:?}",
        rekey_resp.status(),
        rekey_resp.text().await.ok()
    );
}

// ────────────── Test: Revoke then rekey atomic flow ──────────────

#[tokio::test]
async fn test_revoke_then_rekey_atomic_flow() {
    let (url, _server, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    // Register admin device via HTTP
    let admin_id = generate_device_id();
    let admin_key = SigningKey::generate(&mut rand::thread_rng());
    let admin_token = register_device(&client, &url, &sync_id, &admin_id, &admin_key).await;

    // Register target device directly via DB
    let target_id = generate_device_id();
    let _target_token = prepare_device(&db, &sync_id, &target_id).await;

    // Revoke the target device
    let revoke_resp = client
        .delete(format!("{url}/v1/sync/{sync_id}/devices/{target_id}"))
        .header("Authorization", format!("Bearer {admin_token}"))
        .header("X-Device-Id", &admin_id)
        .send()
        .await
        .unwrap();
    assert_eq!(revoke_resp.status(), 204);

    // Post rekey with revoked_device_id, wrapping keys for admin only
    let b64 = base64::engine::general_purpose::STANDARD;
    let wrapped_key_data = b"fake-wrapped-epoch-key-for-admin";
    let rekey_resp = client
        .post(format!("{url}/v1/sync/{sync_id}/rekey"))
        .header("Authorization", format!("Bearer {admin_token}"))
        .header("X-Device-Id", &admin_id)
        .json(&serde_json::json!({
            "epoch": 1,
            "revoked_device_id": target_id,
            "wrapped_keys": {
                admin_id.clone(): b64.encode(wrapped_key_data),
            },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        rekey_resp.status(),
        200,
        "rekey after revoke should succeed: {:?}",
        rekey_resp.text().await.ok()
    );

    // Verify the rekey artifact exists for the admin device
    let artifact_resp = client
        .get(format!("{url}/v1/sync/{sync_id}/rekey/1/{admin_id}"))
        .header("Authorization", format!("Bearer {admin_token}"))
        .header("X-Device-Id", &admin_id)
        .send()
        .await
        .unwrap();
    assert_eq!(artifact_resp.status(), 200);
    let artifact_json: Value = artifact_resp.json().await.unwrap();
    let retrieved = b64
        .decode(artifact_json["wrapped_key"].as_str().unwrap())
        .unwrap();
    assert_eq!(retrieved, wrapped_key_data);
}

// ────────────── Test: Rekey idempotent revocation ──────────────

#[tokio::test]
async fn test_rekey_idempotent_revocation() {
    let (url, _server, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    // Register admin device via HTTP
    let admin_id = generate_device_id();
    let admin_key = SigningKey::generate(&mut rand::thread_rng());
    let admin_token = register_device(&client, &url, &sync_id, &admin_id, &admin_key).await;

    // Register target device directly via DB
    let target_id = generate_device_id();
    let _target_token = prepare_device(&db, &sync_id, &target_id).await;

    // Revoke the target device (first revocation)
    let revoke_resp = client
        .delete(format!("{url}/v1/sync/{sync_id}/devices/{target_id}"))
        .header("Authorization", format!("Bearer {admin_token}"))
        .header("X-Device-Id", &admin_id)
        .send()
        .await
        .unwrap();
    assert_eq!(revoke_resp.status(), 204);

    // Post rekey with revoked_device_id=target_id — device already revoked,
    // should succeed because rekey revocation is idempotent
    let b64 = base64::engine::general_purpose::STANDARD;
    let rekey_resp = client
        .post(format!("{url}/v1/sync/{sync_id}/rekey"))
        .header("Authorization", format!("Bearer {admin_token}"))
        .header("X-Device-Id", &admin_id)
        .json(&serde_json::json!({
            "epoch": 1,
            "revoked_device_id": target_id,
            "wrapped_keys": {
                admin_id.clone(): b64.encode(b"fake-wrapped-key-idempotent"),
            },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        rekey_resp.status(),
        200,
        "rekey with already-revoked device should succeed (idempotent): {:?}",
        rekey_resp.text().await.ok()
    );
}

// ────── Test: Invite after epoch rotation includes epoch fields ──────

#[tokio::test]
async fn test_invite_after_epoch_rotation_includes_epoch_fields() {
    let (url, _server, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    // 1. Register admin device via HTTP
    let admin_id = generate_device_id();
    let admin_key = SigningKey::generate(&mut rand::thread_rng());
    let admin_token = register_device(&client, &url, &sync_id, &admin_id, &admin_key).await;

    // 2. Register a second device (target to be revoked) directly via DB
    let target_id = generate_device_id();
    let _target_token = prepare_device(&db, &sync_id, &target_id).await;

    // 3. Revoke the target device
    let revoke_resp = client
        .delete(format!("{url}/v1/sync/{sync_id}/devices/{target_id}"))
        .header("Authorization", format!("Bearer {admin_token}"))
        .header("X-Device-Id", &admin_id)
        .send()
        .await
        .unwrap();
    assert_eq!(revoke_resp.status(), 204, "revoke should return 204");

    // 4. Post rekey with epoch=1 to complete the rotation
    let b64 = base64::engine::general_purpose::STANDARD;
    let rekey_resp = client
        .post(format!("{url}/v1/sync/{sync_id}/rekey"))
        .header("Authorization", format!("Bearer {admin_token}"))
        .header("X-Device-Id", &admin_id)
        .json(&serde_json::json!({
            "epoch": 1,
            "revoked_device_id": target_id,
            "wrapped_keys": {
                admin_id.clone(): b64.encode(b"fake-wrapped-key-epoch1"),
            },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        rekey_resp.status(),
        200,
        "rekey to epoch 1 should succeed: {:?}",
        rekey_resp.text().await.ok()
    );

    // 5. Verify the sync group is now at epoch 1
    let epoch = db
        .with_conn(|conn| db::get_sync_group_epoch(conn, &sync_id))
        .expect("get epoch");
    assert_eq!(
        epoch,
        Some(1),
        "sync group should be at epoch 1 after rekey"
    );

    // 6. Construct a signed invitation at epoch 1 with epoch fields and register
    //    a third device using it.
    let joiner_id = generate_device_id();
    let joiner_key = SigningKey::generate(&mut rand::thread_rng());

    let wrapped_dek = b"fake-wrapped-dek-for-joiner";
    let salt = b"fake-salt-value-16b!";
    let epoch_key = [0xEE; 32];
    let relay_url = &url;
    let admin_pk_bytes: [u8; 32] = *admin_key.verifying_key().as_bytes();

    // Build canonical signing data including epoch fields
    let signing_data = prism_sync_relay::auth::build_invitation_signing_data(
        &sync_id,
        relay_url,
        wrapped_dek,
        salt,
        &admin_id,
        &admin_pk_bytes,
        Some(&joiner_id),
        1, // current_epoch
        &epoch_key,
    );
    let invitation_sig = admin_key.sign(&signing_data);

    // Fetch nonce for joiner
    let nonce_resp = client
        .get(format!("{url}/v1/sync/{sync_id}/register-nonce"))
        .send()
        .await
        .unwrap();
    assert_eq!(nonce_resp.status(), 200);
    let nonce_json: Value = nonce_resp.json().await.unwrap();
    let nonce = nonce_json["nonce"].as_str().unwrap().to_string();

    // Sign registration challenge for joiner
    let challenge_sig = sign_challenge(&joiner_key, &sync_id, &joiner_id, &nonce);

    let mut x25519_pk = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut x25519_pk);

    // 7. Register the third device with the signed invitation including epoch fields
    let register_resp = client
        .post(format!("{url}/v1/sync/{sync_id}/register"))
        .json(&serde_json::json!({
            "device_id": joiner_id,
            "signing_public_key": hex::encode(joiner_key.verifying_key().as_bytes()),
            "x25519_public_key": hex::encode(x25519_pk),
            "registration_challenge": hex::encode(&challenge_sig),
            "nonce": nonce,
            "signed_invitation": {
                "sync_id": sync_id,
                "relay_url": relay_url,
                "wrapped_dek": hex::encode(wrapped_dek),
                "salt": hex::encode(salt),
                "inviter_device_id": admin_id,
                "inviter_ed25519_pk": hex::encode(admin_pk_bytes),
                "signature": hex::encode(invitation_sig.to_bytes()),
                "joiner_device_id": joiner_id,
                "current_epoch": 1,
                "epoch_key_hex": hex::encode(epoch_key),
            },
        }))
        .send()
        .await
        .unwrap();
    let status = register_resp.status();
    let body: Value = register_resp.json().await.unwrap_or_default();
    assert!(
        status.is_success(),
        "registration with epoch-1 invitation should succeed: {status} - {body}"
    );
    assert!(
        body["device_session_token"].as_str().is_some(),
        "response should contain a session token"
    );
}

#[tokio::test]
async fn test_stale_invitation_epoch_is_rejected() {
    let (url, _server, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let admin_id = generate_device_id();
    let admin_key = SigningKey::generate(&mut rand::thread_rng());
    let admin_token = register_device(&client, &url, &sync_id, &admin_id, &admin_key).await;

    let target_id = generate_device_id();
    let _target_token = prepare_device(&db, &sync_id, &target_id).await;

    let revoke_resp = client
        .delete(format!("{url}/v1/sync/{sync_id}/devices/{target_id}"))
        .header("Authorization", format!("Bearer {admin_token}"))
        .header("X-Device-Id", &admin_id)
        .send()
        .await
        .unwrap();
    assert_eq!(revoke_resp.status(), 204);

    let b64 = base64::engine::general_purpose::STANDARD;
    let rekey_resp = client
        .post(format!("{url}/v1/sync/{sync_id}/rekey"))
        .header("Authorization", format!("Bearer {admin_token}"))
        .header("X-Device-Id", &admin_id)
        .json(&serde_json::json!({
            "epoch": 1,
            "revoked_device_id": target_id,
            "wrapped_keys": {
                admin_id.clone(): b64.encode(b"fake-wrapped-key-epoch1"),
            },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(rekey_resp.status(), 200);

    let joiner_id = generate_device_id();
    let joiner_key = SigningKey::generate(&mut rand::thread_rng());
    let wrapped_dek = b"fake-wrapped-dek-for-joiner";
    let salt = b"fake-salt-value-16b!";
    let relay_url = &url;
    let admin_pk_bytes: [u8; 32] = *admin_key.verifying_key().as_bytes();

    let signing_data = prism_sync_relay::auth::build_invitation_signing_data(
        &sync_id,
        relay_url,
        wrapped_dek,
        salt,
        &admin_id,
        &admin_pk_bytes,
        Some(&joiner_id),
        0,
        &[],
    );
    let invitation_sig = admin_key.sign(&signing_data);

    let nonce_resp = client
        .get(format!("{url}/v1/sync/{sync_id}/register-nonce"))
        .send()
        .await
        .unwrap();
    assert_eq!(nonce_resp.status(), 200);
    let nonce_json: Value = nonce_resp.json().await.unwrap();
    let nonce = nonce_json["nonce"].as_str().unwrap().to_string();

    let challenge_sig = sign_challenge(&joiner_key, &sync_id, &joiner_id, &nonce);
    let mut x25519_pk = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut x25519_pk);

    let register_resp = client
        .post(format!("{url}/v1/sync/{sync_id}/register"))
        .json(&serde_json::json!({
            "device_id": joiner_id,
            "signing_public_key": hex::encode(joiner_key.verifying_key().as_bytes()),
            "x25519_public_key": hex::encode(x25519_pk),
            "registration_challenge": hex::encode(&challenge_sig),
            "nonce": nonce,
            "signed_invitation": {
                "sync_id": sync_id,
                "relay_url": relay_url,
                "wrapped_dek": hex::encode(wrapped_dek),
                "salt": hex::encode(salt),
                "inviter_device_id": admin_id,
                "inviter_ed25519_pk": hex::encode(admin_pk_bytes),
                "signature": hex::encode(invitation_sig.to_bytes()),
                "joiner_device_id": joiner_id,
                "current_epoch": 0,
                "epoch_key_hex": "",
            },
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        register_resp.status(),
        401,
        "stale epoch invitation should be rejected"
    );
}
