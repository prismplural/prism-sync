//! End-to-end tests for batch push/pull, sync operations, signature verification,
//! ACK/pruning, and epoch enforcement against the actual prism-sync-relay server
//! running in-process with an in-memory SQLite database.
//!
//! These tests use raw `reqwest` calls to exercise the relay HTTP API because
//! `ServerRelay::new()` only accepts `http://localhost` or `https://` URLs and
//! uses base64 encoding for keys while the relay expects hex — so direct HTTP
//! calls give us more control and validate the actual wire protocol.

mod common;

use base64::Engine;
use ed25519_dalek::Signer;
use prism_sync_relay::db;
use reqwest::Client;
use serde_json::Value;

use common::*;

/// Helper: push a batch with signed headers.
async fn push_signed(
    client: &Client,
    url: &str,
    sync_id: &str,
    device_id: &str,
    token: &str,
    keys: &TestDeviceKeys,
    envelope: &Value,
) -> reqwest::Response {
    let body_bytes = serde_json::to_vec(envelope).unwrap();
    let path = format!("/v1/sync/{sync_id}/changes");
    apply_signed_headers(
        client
            .put(format!("{url}/v1/sync/{sync_id}/changes"))
            .header("Authorization", format!("Bearer {token}"))
            .header("X-Device-Id", device_id)
            .header("Content-Type", "application/json"),
        keys,
        "PUT",
        &path,
        sync_id,
        device_id,
        &body_bytes,
    )
    .body(body_bytes)
    .send()
    .await
    .unwrap()
}

/// Helper: ACK a server sequence with signed headers.
async fn ack_signed(
    client: &Client,
    url: &str,
    sync_id: &str,
    device_id: &str,
    token: &str,
    keys: &TestDeviceKeys,
    server_seq: i64,
) -> reqwest::Response {
    let body_bytes = serde_json::to_vec(&serde_json::json!({ "server_seq": server_seq })).unwrap();
    let path = format!("/v1/sync/{sync_id}/ack");
    apply_signed_headers(
        client
            .post(format!("{url}/v1/sync/{sync_id}/ack"))
            .header("Authorization", format!("Bearer {token}"))
            .header("X-Device-Id", device_id)
            .header("Content-Type", "application/json"),
        keys,
        "POST",
        &path,
        sync_id,
        device_id,
        &body_bytes,
    )
    .body(body_bytes)
    .send()
    .await
    .unwrap()
}

#[allow(clippy::too_many_arguments)]
fn apply_signed_headers_with_nonce(
    builder: reqwest::RequestBuilder,
    keys: &TestDeviceKeys,
    method: &str,
    path: &str,
    sync_id: &str,
    device_id: &str,
    body: &[u8],
    timestamp: &str,
    nonce: &str,
) -> reqwest::RequestBuilder {
    let ml_dsa_key = keys.device_secret.ml_dsa_65_keypair(device_id).unwrap();
    let signing_data = prism_sync_relay::auth::build_request_signing_data_v2(
        method, path, sync_id, device_id, body, timestamp, nonce,
    );
    let m_prime =
        prism_sync_crypto::pq::build_hybrid_message_representative(b"http_request", &signing_data)
            .expect("hardcoded http request context should be <= 255 bytes");
    let hybrid_sig = prism_sync_crypto::pq::HybridSignature {
        ed25519_sig: keys.ed25519_signing_key.sign(&m_prime).to_bytes().to_vec(),
        ml_dsa_65_sig: ml_dsa_key.sign(&m_prime),
    };
    let mut wire = vec![0x03u8];
    wire.extend_from_slice(&hybrid_sig.to_bytes());

    builder
        .header("X-Prism-Timestamp", timestamp)
        .header("X-Prism-Nonce", nonce)
        .header("X-Prism-Signature", base64::engine::general_purpose::STANDARD.encode(&wire))
}

// ───────────────────────────── Test 2: Push + Pull Roundtrip ────────────

#[tokio::test]
async fn test_push_pull_roundtrip() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    // Register Device A
    let device_a_id = generate_device_id();
    let keys_a = TestDeviceKeys::generate(&device_a_id);
    let token_a = register_device(&client, &url, &sync_id, &device_a_id, &keys_a).await;

    // Device A pushes a batch
    let envelope = make_test_envelope(&sync_id, &device_a_id, "batch-001", 0);
    let push_resp =
        push_signed(&client, &url, &sync_id, &device_a_id, &token_a, &keys_a, &envelope).await;
    assert!(push_resp.status().is_success(), "push failed: {}", push_resp.status());
    let push_json: Value = push_resp.json().await.unwrap();
    let server_seq = push_json["server_seq"].as_i64().unwrap();
    assert!(server_seq > 0, "server_seq should be positive");

    // Device A pushes a second batch
    let envelope2 = make_test_envelope(&sync_id, &device_a_id, "batch-002", 0);
    let push_resp2 =
        push_signed(&client, &url, &sync_id, &device_a_id, &token_a, &keys_a, &envelope2).await;
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
    assert_eq!(batches[0]["envelope"]["batch_id"].as_str().unwrap(), "batch-001");
    assert_eq!(batches[1]["envelope"]["batch_id"].as_str().unwrap(), "batch-002");
    assert_eq!(pull_json["max_server_seq"].as_i64().unwrap(), server_seq2);

    // Pull since first batch — should only get second
    let pull_resp2 = client
        .get(format!("{url}/v1/sync/{sync_id}/changes?since={server_seq}"))
        .header("Authorization", format!("Bearer {token_a}"))
        .header("X-Device-Id", &device_a_id)
        .send()
        .await
        .unwrap();
    assert_eq!(pull_resp2.status(), 200);
    let pull_json2: Value = pull_resp2.json().await.unwrap();
    let batches2 = pull_json2["batches"].as_array().unwrap();
    assert_eq!(batches2.len(), 1, "should only have 1 batch after first");
    assert_eq!(batches2[0]["envelope"]["batch_id"].as_str().unwrap(), "batch-002");

    // Duplicate push should return same server_seq (idempotent)
    let push_resp_dup =
        push_signed(&client, &url, &sync_id, &device_a_id, &token_a, &keys_a, &envelope).await;
    assert!(push_resp_dup.status().is_success());
    let dup_json: Value = push_resp_dup.json().await.unwrap();
    assert_eq!(
        dup_json["server_seq"].as_i64().unwrap(),
        server_seq,
        "duplicate push should return original server_seq"
    );
}

#[tokio::test]
async fn test_signed_request_replay_rejected_after_relay_restart() {
    let temp_dir = tempfile::tempdir().unwrap();
    let mut config = test_config();
    config.db_path = temp_dir.path().join("relay.db").to_string_lossy().to_string();
    config.media_storage_path = temp_dir.path().join("media").to_string_lossy().to_string();

    let (url, server, db) = start_test_relay_with_config(config.clone()).await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;

    let envelope = make_test_envelope(&sync_id, &device_id, "batch-replay", 0);
    let body_bytes = serde_json::to_vec(&envelope).unwrap();
    let path = format!("/v1/sync/{sync_id}/changes");
    let timestamp = prism_sync_relay::db::now_secs().to_string();
    let nonce = uuid::Uuid::new_v4().to_string();

    let first_resp = apply_signed_headers_with_nonce(
        client
            .put(format!("{url}/v1/sync/{sync_id}/changes"))
            .header("Authorization", format!("Bearer {token}"))
            .header("X-Device-Id", &device_id)
            .header("Content-Type", "application/json"),
        &keys,
        "PUT",
        &path,
        &sync_id,
        &device_id,
        &body_bytes,
        &timestamp,
        &nonce,
    )
    .body(body_bytes.clone())
    .send()
    .await
    .unwrap();
    assert!(
        first_resp.status().is_success(),
        "initial signed push failed: {}",
        first_resp.status()
    );

    server.abort();
    let _ = server.await;
    drop(db);

    let (url_after_restart, restarted_server, _restarted_db) =
        start_test_relay_with_config(config).await;
    let replay_resp = apply_signed_headers_with_nonce(
        client
            .put(format!("{url_after_restart}/v1/sync/{sync_id}/changes"))
            .header("Authorization", format!("Bearer {token}"))
            .header("X-Device-Id", &device_id)
            .header("Content-Type", "application/json"),
        &keys,
        "PUT",
        &path,
        &sync_id,
        &device_id,
        &body_bytes,
        &timestamp,
        &nonce,
    )
    .body(body_bytes)
    .send()
    .await
    .unwrap();
    assert_eq!(
        replay_resp.status(),
        401,
        "replayed signed request should be rejected after restart"
    );

    restarted_server.abort();
    let _ = restarted_server.await;
}

// ───────────────────────────── Test 5: ACK and Pruning ──────────────────

#[tokio::test]
async fn test_ack_does_not_prune_synchronously() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;

    // Push several batches
    let mut last_seq = 0i64;
    for i in 0..5 {
        let envelope = make_test_envelope(&sync_id, &device_id, &format!("batch-{i:03}"), 0);
        let resp = push_signed(&client, &url, &sync_id, &device_id, &token, &keys, &envelope).await;
        assert!(resp.status().is_success());
        let json: Value = resp.json().await.unwrap();
        last_seq = json["server_seq"].as_i64().unwrap();
    }

    // Upload a snapshot covering all batches (required for pruning)
    let snapshot_body = b"snapshot-data".to_vec();
    let snapshot_path = format!("/v1/sync/{sync_id}/snapshot");
    let put_snap = apply_signed_headers(
        client
            .put(format!("{url}/v1/sync/{sync_id}/snapshot"))
            .header("Authorization", format!("Bearer {token}"))
            .header("X-Device-Id", &device_id)
            .header("X-Server-Seq-At", last_seq.to_string()),
        &keys,
        "PUT",
        &snapshot_path,
        &sync_id,
        &device_id,
        &snapshot_body,
    )
    .body(snapshot_body)
    .send()
    .await
    .unwrap();
    assert_eq!(put_snap.status(), 204);

    // ACK up to last_seq (this is the only device, so min_acked = last_seq)
    let ack_resp = ack_signed(&client, &url, &sync_id, &device_id, &token, &keys, last_seq).await;
    assert_eq!(ack_resp.status(), 204);

    // Pull from 0 immediately after ACK. Periodic cleanup owns pruning, so
    // /ack must not delete any retained batch history synchronously.
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
    assert_eq!(remaining, 5, "ack must not prune batches synchronously");
}

#[tokio::test]
async fn test_ack_above_latest_seq_returns_400() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;

    let envelope = make_test_envelope(&sync_id, &device_id, "batch-001", 0);
    let push_resp =
        push_signed(&client, &url, &sync_id, &device_id, &token, &keys, &envelope).await;
    assert!(push_resp.status().is_success());
    let push_json: Value = push_resp.json().await.unwrap();
    let server_seq = push_json["server_seq"].as_i64().unwrap();

    let ack_resp =
        ack_signed(&client, &url, &sync_id, &device_id, &token, &keys, server_seq + 1).await;
    assert_eq!(ack_resp.status(), 400, "ack above latest server seq should be rejected");
}

#[tokio::test]
async fn test_cleanup_pruning_requires_group_wide_snapshot() {
    let (url, _server, relay_db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let device_a_id = generate_device_id();
    let keys_a = TestDeviceKeys::generate(&device_a_id);
    let token_a = register_device(&client, &url, &sync_id, &device_a_id, &keys_a).await;

    let device_b_id = generate_device_id();
    let (token_b, keys_b) = prepare_device(&relay_db, &sync_id, &device_b_id).await;

    let mut last_seq = 0i64;
    for i in 0..5 {
        let envelope = make_test_envelope(&sync_id, &device_a_id, &format!("batch-{i:03}"), 0);
        let resp =
            push_signed(&client, &url, &sync_id, &device_a_id, &token_a, &keys_a, &envelope).await;
        assert!(resp.status().is_success(), "push failed: {}", resp.status());
        let json: Value = resp.json().await.unwrap();
        last_seq = json["server_seq"].as_i64().unwrap();
    }

    let ack_a =
        ack_signed(&client, &url, &sync_id, &device_a_id, &token_a, &keys_a, last_seq).await;
    assert_eq!(ack_a.status(), 204);
    let ack_b =
        ack_signed(&client, &url, &sync_id, &device_b_id, &token_b, &keys_b, last_seq).await;
    assert_eq!(ack_b.status(), 204);

    relay_db
        .with_conn(|conn| {
            let future = db::now_secs() + 3600;

            db::upsert_snapshot(
                conn,
                &sync_id,
                0,
                last_seq,
                b"targeted-snapshot",
                Some(future),
                Some(&device_b_id),
                Some(&device_a_id),
            )?;
            assert_eq!(
                db::get_safe_prune_seq(conn, &sync_id, 3600)?,
                None,
                "targeted snapshots must not authorize group-wide pruning"
            );
            let pruned = db::prune_batches_with_unexpired_snapshots(conn, 3600)?;
            assert_eq!(pruned, 0, "targeted snapshot must not prune retained batches");
            let batches = db::get_batches_since(conn, &sync_id, 0, 100)?;
            assert_eq!(batches.len(), 5);

            db::upsert_snapshot(
                conn,
                &sync_id,
                0,
                last_seq,
                b"group-wide-snapshot",
                Some(future),
                None,
                Some(&device_a_id),
            )?;
            assert_eq!(db::get_safe_prune_seq(conn, &sync_id, 3600)?, Some(last_seq));
            let pruned = db::prune_batches_with_unexpired_snapshots(conn, 3600)?;
            assert_eq!(pruned, 4, "group-wide snapshot should permit cleanup pruning");
            let batches = db::get_batches_since(conn, &sync_id, 0, 100)?;
            assert_eq!(batches.len(), 1);
            assert_eq!(batches[0].server_seq, last_seq);

            Ok(())
        })
        .unwrap();
}

#[tokio::test]
async fn test_pull_stale_cursor_returns_must_bootstrap_response() {
    let (url, _server, relay_db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;

    let mut last_seq = 0i64;
    for i in 0..5 {
        let envelope = make_test_envelope(&sync_id, &device_id, &format!("batch-{i:03}"), 0);
        let resp = push_signed(&client, &url, &sync_id, &device_id, &token, &keys, &envelope).await;
        assert!(resp.status().is_success(), "push failed: {}", resp.status());
        let json: Value = resp.json().await.unwrap();
        last_seq = json["server_seq"].as_i64().unwrap();
    }

    relay_db
        .with_conn(|conn| {
            let pruned = db::prune_batches_before(conn, &sync_id, last_seq)?;
            assert_eq!(pruned, 4);
            assert_eq!(db::get_first_retained_batch_seq(conn, &sync_id)?, Some(last_seq));
            Ok(())
        })
        .unwrap();

    let stale_pull = client
        .get(format!("{url}/v1/sync/{sync_id}/changes?since=0"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id)
        .send()
        .await
        .unwrap();
    assert_eq!(stale_pull.status(), 409);
    let stale_json: Value = stale_pull.json().await.unwrap();
    assert_eq!(stale_json["error"].as_str(), Some("must_bootstrap_from_snapshot"));
    assert_eq!(stale_json["since_seq"].as_i64(), Some(0));
    assert_eq!(stale_json["first_retained_seq"].as_i64(), Some(last_seq));

    let continuous_pull = client
        .get(format!("{url}/v1/sync/{sync_id}/changes?since={}", last_seq - 1))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id)
        .send()
        .await
        .unwrap();
    assert_eq!(continuous_pull.status(), 200);
    let continuous_json: Value = continuous_pull.json().await.unwrap();
    let batches = continuous_json["batches"].as_array().unwrap();
    assert_eq!(batches.len(), 1);
    assert_eq!(batches[0]["server_seq"].as_i64(), Some(last_seq));
}

// ───────────────────────────── Test 7: Epoch mismatch on push ───────────

#[tokio::test]
async fn test_push_rejects_wrong_epoch() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;

    // Try to push with epoch 5 (current is 0)
    let envelope = make_test_envelope(&sync_id, &device_id, "batch-wrong-epoch", 5);
    let push_resp =
        push_signed(&client, &url, &sync_id, &device_id, &token, &keys, &envelope).await;
    assert_eq!(push_resp.status(), 403, "push with wrong epoch should be rejected");
}

// ───────────────── Tests: unsigned mutation requests are rejected ──────────

#[tokio::test]
async fn test_push_rejects_unsigned_request() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;

    let envelope = make_test_envelope(&sync_id, &device_id, "batch-unsigned", 0);
    let resp = client
        .put(format!("{url}/v1/sync/{sync_id}/changes"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id)
        .header("Content-Type", "application/json")
        .json(&envelope)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "push without signature headers should be rejected");
}

#[tokio::test]
async fn test_put_snapshot_rejects_unsigned_request() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;

    let resp = client
        .put(format!("{url}/v1/sync/{sync_id}/snapshot"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id)
        .header("X-Server-Seq-At", "1")
        .body(b"snapshot-data".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "snapshot upload without signature headers should be rejected");
}

#[tokio::test]
async fn test_ack_rejects_unsigned_request() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;

    let resp = client
        .post(format!("{url}/v1/sync/{sync_id}/ack"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id)
        .header("Content-Type", "application/json")
        .body(serde_json::to_vec(&serde_json::json!({ "server_seq": 1 })).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "ack without signature headers should be rejected");
}
