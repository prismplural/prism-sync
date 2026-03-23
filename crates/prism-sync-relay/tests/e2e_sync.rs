//! End-to-end tests: prism-sync-core's ServerRelay types against the actual
//! prism-sync-relay server running in-process with an in-memory SQLite database.
//!
//! These tests use raw `reqwest` calls to exercise the relay HTTP API because
//! `ServerRelay::new()` only accepts `http://localhost` or `https://` URLs and
//! uses base64 encoding for keys while the relay expects hex — so direct HTTP
//! calls give us more control and validate the actual wire protocol.

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

// ───────────────────────────── Test harness ─────────────────────────────

/// Start the relay server in-process on a random port with an in-memory DB.
/// Returns `(base_url, server_handle, db)`.
async fn start_test_relay() -> (
    String,
    tokio::task::JoinHandle<()>,
    std::sync::Arc<Database>,
) {
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
        nonce_rate_limit: 100,
        nonce_rate_window_secs: 60,
        snapshot_default_ttl_secs: 86400,
    };

    let db = Database::in_memory().expect("in-memory db");
    let state = AppState::new(db, config);
    let db = state.db.clone();
    let app = routes::router(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://127.0.0.1:{}", addr.port());

    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (url, handle, db)
}

/// Generate a valid 64-char hex sync ID (32 random bytes).
fn generate_sync_id() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Generate a short device ID.
fn generate_device_id() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Build the canonical challenge bytes that the relay expects, then sign them.
///
/// Format: `"PRISM_SYNC_CHALLENGE_V1" || 0x00 || len_prefixed(sync_id) || len_prefixed(device_id) || len_prefixed(nonce)`
fn sign_challenge(
    signing_key: &SigningKey,
    sync_id: &str,
    device_id: &str,
    nonce: &str,
) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(b"PRISM_SYNC_CHALLENGE_V1\x00");
    write_len_prefixed(&mut data, sync_id.as_bytes());
    write_len_prefixed(&mut data, device_id.as_bytes());
    write_len_prefixed(&mut data, nonce.as_bytes());

    let sig = signing_key.sign(&data);
    sig.to_bytes().to_vec()
}

fn write_len_prefixed(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

/// Full registration helper: fetches nonce, signs challenge, registers device.
/// Returns the session token.
async fn register_device(
    client: &Client,
    url: &str,
    sync_id: &str,
    device_id: &str,
    signing_key: &SigningKey,
) -> String {
    // 1. Fetch nonce
    let nonce_resp = client
        .get(format!("{url}/v1/sync/{sync_id}/register-nonce"))
        .send()
        .await
        .unwrap();
    assert_eq!(nonce_resp.status(), 200, "nonce request failed");
    let nonce_json: Value = nonce_resp.json().await.unwrap();
    let nonce = nonce_json["nonce"].as_str().unwrap().to_string();

    // 2. Sign challenge
    let challenge_sig = sign_challenge(signing_key, sync_id, device_id, &nonce);

    // 3. Generate X25519 key (just random 32 bytes for testing)
    let mut x25519_pk = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut x25519_pk);

    // 4. Register — relay expects hex-encoded keys
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
    let status = register_resp.status();
    let token_json: Value = register_resp.json().await.unwrap_or_else(|e| {
        panic!("registration failed (status {status}): {e}");
    });
    assert!(
        status.is_success(),
        "registration failed: {status} - {token_json}"
    );
    token_json["device_session_token"]
        .as_str()
        .expect("missing device_session_token in register response")
        .to_string()
}

/// Build a minimal valid `SignedBatchEnvelope` JSON for testing.
/// The relay stores it opaquely — it only extracts `batch_id` and `epoch`.
fn make_test_envelope(sync_id: &str, device_id: &str, batch_id: &str, epoch: i64) -> Value {
    let payload_hash = vec![0u8; 32];
    let signature = vec![0u8; 64];
    let nonce = vec![0u8; 24];
    serde_json::json!({
        "protocol_version": 1,
        "sync_id": sync_id,
        "epoch": epoch,
        "batch_id": batch_id,
        "batch_kind": "incremental",
        "sender_device_id": device_id,
        "payload_hash": payload_hash,
        "signature": signature,
        "nonce": nonce,
        "ciphertext": base64::engine::general_purpose::STANDARD.encode(b"test-encrypted-data"),
    })
}

async fn prepare_device(db: &std::sync::Arc<Database>, sync_id: &str, device_id: &str) -> String {
    let device_id = device_id.to_string();
    let sync_id = sync_id.to_string();
    db.with_conn(|conn| {
        db::register_device(
            conn, &sync_id, &device_id, &[7u8; 32], &[8u8; 32], 0, "admin",
        )?;
        let token = db::create_session(conn, &sync_id, &device_id, 3600)?;
        Ok(token)
    })
    .expect("prepare device")
}

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

    // Wait a moment so the nonce expires (expiry_secs = 0 means created_at + 0 < now)
    tokio::time::sleep(std::time::Duration::from_millis(2200)).await;

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

// ───────────────────────────── Test 2: Push + Pull Roundtrip ────────────

#[tokio::test]
async fn test_push_pull_roundtrip() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    // Register Device A
    let device_a_id = generate_device_id();
    let signing_key_a = SigningKey::generate(&mut rand::thread_rng());
    let token_a = register_device(&client, &url, &sync_id, &device_a_id, &signing_key_a).await;

    // Register Device B (needs invitation for existing group... actually, let's check)
    // The relay requires an invitation for non-first devices. For testing, we need
    // to register B with a signed invitation. This is complex, so let's use a
    // workaround: register both devices as "first" in separate sync groups and
    // test push/pull within a single device. OR we can test that device A can
    // push and pull its own data.

    // Device A pushes a batch
    let envelope = make_test_envelope(&sync_id, &device_a_id, "batch-001", 0);
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
        "push failed: {}",
        push_resp.status()
    );
    let push_json: Value = push_resp.json().await.unwrap();
    let server_seq = push_json["server_seq"].as_i64().unwrap();
    assert!(server_seq > 0, "server_seq should be positive");

    // Device A pushes a second batch
    let envelope2 = make_test_envelope(&sync_id, &device_a_id, "batch-002", 0);
    let push_resp2 = client
        .put(format!("{url}/v1/sync/{sync_id}/changes"))
        .header("Authorization", format!("Bearer {token_a}"))
        .header("X-Device-Id", &device_a_id)
        .json(&envelope2)
        .send()
        .await
        .unwrap();
    assert!(push_resp2.status().is_success());
    let push_json2: Value = push_resp2.json().await.unwrap();
    let server_seq2 = push_json2["server_seq"].as_i64().unwrap();
    assert!(server_seq2 > server_seq, "server_seq should increase");

    // Pull all changes since 0
    let pull_resp = client
        .get(format!("{url}/v1/sync/{sync_id}/changes?since=0"))
        .header("Authorization", format!("Bearer {token_a}"))
        .header("X-Device-Id", &device_a_id)
        .send()
        .await
        .unwrap();
    assert_eq!(pull_resp.status(), 200);
    let pull_json: Value = pull_resp.json().await.unwrap();
    let batches = pull_json["batches"].as_array().unwrap();
    assert_eq!(batches.len(), 2, "should have 2 batches");
    assert_eq!(
        batches[0]["envelope"]["batch_id"].as_str().unwrap(),
        "batch-001"
    );
    assert_eq!(
        batches[1]["envelope"]["batch_id"].as_str().unwrap(),
        "batch-002"
    );
    assert_eq!(pull_json["max_server_seq"].as_i64().unwrap(), server_seq2);

    // Pull since first batch — should only get second
    let pull_resp2 = client
        .get(format!(
            "{url}/v1/sync/{sync_id}/changes?since={server_seq}"
        ))
        .header("Authorization", format!("Bearer {token_a}"))
        .header("X-Device-Id", &device_a_id)
        .send()
        .await
        .unwrap();
    assert_eq!(pull_resp2.status(), 200);
    let pull_json2: Value = pull_resp2.json().await.unwrap();
    let batches2 = pull_json2["batches"].as_array().unwrap();
    assert_eq!(batches2.len(), 1, "should only have 1 batch after first");
    assert_eq!(
        batches2[0]["envelope"]["batch_id"].as_str().unwrap(),
        "batch-002"
    );

    // Duplicate push should return same server_seq (idempotent)
    let push_resp_dup = client
        .put(format!("{url}/v1/sync/{sync_id}/changes"))
        .header("Authorization", format!("Bearer {token_a}"))
        .header("X-Device-Id", &device_a_id)
        .json(&envelope)
        .send()
        .await
        .unwrap();
    assert!(push_resp_dup.status().is_success());
    let dup_json: Value = push_resp_dup.json().await.unwrap();
    assert_eq!(
        dup_json["server_seq"].as_i64().unwrap(),
        server_seq,
        "duplicate push should return original server_seq"
    );
}

#[tokio::test]
async fn test_targeted_snapshot_allows_only_intended_device() {
    let (url, _server, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let device_a_id = generate_device_id();
    let signing_key_a = SigningKey::generate(&mut rand::thread_rng());
    let token_a = register_device(&client, &url, &sync_id, &device_a_id, &signing_key_a).await;

    let device_b_id = generate_device_id();
    let token_b = prepare_device(&db, &sync_id, &device_b_id).await;

    let upload_resp = client
        .put(format!("{url}/v1/sync/{sync_id}/snapshot"))
        .header("Authorization", format!("Bearer {token_a}"))
        .header("X-Device-Id", &device_a_id)
        .header("X-Epoch", "0")
        .header("X-Server-Seq-At", "42")
        .header("X-Snapshot-TTL", "300")
        .header("X-For-Device-Id", &device_b_id)
        .body(b"targeted-snapshot".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(upload_resp.status(), 204);

    let denied_resp = client
        .get(format!("{url}/v1/sync/{sync_id}/snapshot"))
        .header("Authorization", format!("Bearer {token_a}"))
        .header("X-Device-Id", &device_a_id)
        .send()
        .await
        .unwrap();
    assert_eq!(denied_resp.status(), 403, "wrong device should be denied");

    let download_resp = client
        .get(format!("{url}/v1/sync/{sync_id}/snapshot"))
        .header("Authorization", format!("Bearer {token_b}"))
        .header("X-Device-Id", &device_b_id)
        .send()
        .await
        .unwrap();
    assert_eq!(
        download_resp.status(),
        200,
        "target device should be allowed"
    );
    assert_eq!(
        download_resp.bytes().await.unwrap().as_ref(),
        b"targeted-snapshot"
    );

    let post_delete_resp = client
        .get(format!("{url}/v1/sync/{sync_id}/snapshot"))
        .header("Authorization", format!("Bearer {token_b}"))
        .header("X-Device-Id", &device_b_id)
        .send()
        .await
        .unwrap();
    assert_eq!(
        post_delete_resp.status(),
        404,
        "snapshot should auto-delete"
    );
}

#[tokio::test]
async fn test_targeted_snapshot_expires() {
    let (url, _server, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let device_a_id = generate_device_id();
    let signing_key_a = SigningKey::generate(&mut rand::thread_rng());
    let token_a = register_device(&client, &url, &sync_id, &device_a_id, &signing_key_a).await;

    let device_b_id = generate_device_id();
    let token_b = prepare_device(&db, &sync_id, &device_b_id).await;

    let upload_resp = client
        .put(format!("{url}/v1/sync/{sync_id}/snapshot"))
        .header("Authorization", format!("Bearer {token_a}"))
        .header("X-Device-Id", &device_a_id)
        .header("X-Epoch", "0")
        .header("X-Server-Seq-At", "99")
        .header("X-Snapshot-TTL", "1")
        .header("X-For-Device-Id", &device_b_id)
        .body(b"expiring-snapshot".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(upload_resp.status(), 204);

    db.with_conn(|conn| {
        conn.execute(
            "UPDATE snapshots SET expires_at = ?1 WHERE sync_id = ?2",
            rusqlite::params![db::now_secs() - 1, sync_id],
        )?;
        Ok(())
    })
    .expect("force snapshot expiry");

    let expired_resp = client
        .get(format!("{url}/v1/sync/{sync_id}/snapshot"))
        .header("Authorization", format!("Bearer {token_b}"))
        .header("X-Device-Id", &device_b_id)
        .send()
        .await
        .unwrap();
    assert_eq!(
        expired_resp.status(),
        404,
        "expired snapshot should be hidden"
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

// ───────────────────────────── Test 4: Snapshot ─────────────────────────

#[tokio::test]
async fn test_snapshot_put_get_roundtrip() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let device_id = generate_device_id();
    let signing_key = SigningKey::generate(&mut rand::thread_rng());
    let token = register_device(&client, &url, &sync_id, &device_id, &signing_key).await;

    // Initially no snapshot
    let get_resp = client
        .get(format!("{url}/v1/sync/{sync_id}/snapshot"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id)
        .send()
        .await
        .unwrap();
    assert_eq!(get_resp.status(), 404, "no snapshot initially");

    // Upload snapshot
    let snapshot_data = b"encrypted-snapshot-payload-here";
    let put_resp = client
        .put(format!("{url}/v1/sync/{sync_id}/snapshot"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id)
        .header("X-Epoch", "0")
        .header("X-Server-Seq-At", "42")
        .body(snapshot_data.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(put_resp.status(), 204, "snapshot put should return 204");

    // Download snapshot
    let get_resp2 = client
        .get(format!("{url}/v1/sync/{sync_id}/snapshot"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id)
        .send()
        .await
        .unwrap();
    assert_eq!(get_resp2.status(), 200);
    assert_eq!(
        get_resp2
            .headers()
            .get("X-Epoch")
            .unwrap()
            .to_str()
            .unwrap(),
        "0"
    );
    assert_eq!(
        get_resp2
            .headers()
            .get("X-Server-Seq-At")
            .unwrap()
            .to_str()
            .unwrap(),
        "42"
    );
    let body = get_resp2.bytes().await.unwrap();
    assert_eq!(body.as_ref(), snapshot_data);
}

// ───────────────────────────── Test 5: ACK and Pruning ──────────────────

#[tokio::test]
async fn test_ack_triggers_pruning() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let device_id = generate_device_id();
    let signing_key = SigningKey::generate(&mut rand::thread_rng());
    let token = register_device(&client, &url, &sync_id, &device_id, &signing_key).await;

    // Push several batches
    let mut last_seq = 0i64;
    for i in 0..5 {
        let envelope = make_test_envelope(&sync_id, &device_id, &format!("batch-{i:03}"), 0);
        let resp = client
            .put(format!("{url}/v1/sync/{sync_id}/changes"))
            .header("Authorization", format!("Bearer {token}"))
            .header("X-Device-Id", &device_id)
            .json(&envelope)
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success());
        let json: Value = resp.json().await.unwrap();
        last_seq = json["server_seq"].as_i64().unwrap();
    }

    // Upload a snapshot covering all batches (required for pruning)
    let put_snap = client
        .put(format!("{url}/v1/sync/{sync_id}/snapshot"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id)
        .header("X-Epoch", "0")
        .header("X-Server-Seq-At", last_seq.to_string())
        .body(b"snapshot-data".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(put_snap.status(), 204);

    // ACK up to last_seq (this is the only device, so min_acked = last_seq)
    let ack_resp = client
        .post(format!("{url}/v1/sync/{sync_id}/ack"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id)
        .json(&serde_json::json!({ "server_seq": last_seq }))
        .send()
        .await
        .unwrap();
    assert_eq!(ack_resp.status(), 204);

    // Pull from 0 — batches before the safe prune point should be gone
    let pull_resp = client
        .get(format!("{url}/v1/sync/{sync_id}/changes?since=0"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id)
        .send()
        .await
        .unwrap();
    assert_eq!(pull_resp.status(), 200);
    let pull_json: Value = pull_resp.json().await.unwrap();
    let remaining = pull_json["batches"].as_array().unwrap().len();
    // Pruning deletes batches with id < safe_prune_seq.
    // safe_prune_seq = min(snapshot_seq_at, min_acked_seq) = min(last_seq, last_seq) = last_seq.
    // Batches with id < last_seq should be pruned; only the last batch (id == last_seq) remains.
    assert!(
        remaining <= 1,
        "expected at most 1 batch after ack+prune, got {remaining}"
    );
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

// ───────────────────────────── Test 7: Epoch mismatch on push ───────────

#[tokio::test]
async fn test_push_rejects_wrong_epoch() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let device_id = generate_device_id();
    let signing_key = SigningKey::generate(&mut rand::thread_rng());
    let token = register_device(&client, &url, &sync_id, &device_id, &signing_key).await;

    // Try to push with epoch 5 (current is 0)
    let envelope = make_test_envelope(&sync_id, &device_id, "batch-wrong-epoch", 5);
    let push_resp = client
        .put(format!("{url}/v1/sync/{sync_id}/changes"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id)
        .json(&envelope)
        .send()
        .await
        .unwrap();
    assert_eq!(
        push_resp.status(),
        403,
        "push with wrong epoch should be rejected"
    );
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

    // Sleep just over 1 second so the window expires
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    // After window expiry, the next request should succeed
    let resp = client
        .get(format!("{url}/v1/sync/{sync_id}/register-nonce"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "request after window expiry should succeed"
    );
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
