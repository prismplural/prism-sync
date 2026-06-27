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
use prism_sync_crypto::pq::hybrid_signature_contexts;
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
    let m_prime = prism_sync_crypto::pq::build_hybrid_message_representative(
        hybrid_signature_contexts::HTTP_REQUEST,
        &signing_data,
    )
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

            // Bump the seq because `upsert_snapshot` rejects equal-seq
            // overwrites; incidental to this test's purpose (group-wide
            // snapshot enables pruning).
            db::upsert_snapshot(
                conn,
                &sync_id,
                0,
                last_seq + 1,
                b"group-wide-snapshot",
                Some(future),
                None,
                Some(&device_a_id),
            )?;
            // Safe prune watermark is `min(snap_seq, min_acked)`; both
            // devices acked at `last_seq` so it stays at `last_seq`
            // despite the snapshot sitting one ahead.
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

#[tokio::test]
async fn test_pull_cursor_above_log_head_returns_409_cursor_ahead_of_log() {
    // A cursor above the log head can only happen after the relay's seq
    // stream regressed (a restore re-issued lower seqs). The relay must reject it
    // loudly instead of answering the empty page an up-to-date client reads as
    // "in sync".
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;

    let mut last_seq = 0i64;
    for i in 0..3 {
        let envelope = make_test_envelope(&sync_id, &device_id, &format!("batch-{i:03}"), 0);
        let resp = push_signed(&client, &url, &sync_id, &device_id, &token, &keys, &envelope).await;
        assert!(resp.status().is_success(), "push failed: {}", resp.status());
        let json: Value = resp.json().await.unwrap();
        last_seq = json["server_seq"].as_i64().unwrap();
    }

    // since == head: a valid up-to-date cursor returns an empty page with the
    // additive lineage fields present.
    let at_head = client
        .get(format!("{url}/v1/sync/{sync_id}/changes?since={last_seq}"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id)
        .send()
        .await
        .unwrap();
    assert_eq!(at_head.status(), 200, "cursor at head is valid");
    let at_head_json: Value = at_head.json().await.unwrap();
    assert!(at_head_json["batches"].as_array().unwrap().is_empty());
    assert_eq!(at_head_json["log_head_seq"].as_i64(), Some(last_seq));
    assert!(at_head_json["log_token"].as_str().is_some(), "additive log_token present");

    // since > head: regressed lineage → structured 409 with both fields.
    let ahead = client
        .get(format!("{url}/v1/sync/{sync_id}/changes?since={}", last_seq + 5))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id)
        .send()
        .await
        .unwrap();
    assert_eq!(ahead.status(), 409);
    let ahead_json: Value = ahead.json().await.unwrap();
    assert_eq!(ahead_json["error"].as_str(), Some("cursor_ahead_of_log"));
    assert_eq!(ahead_json["since_seq"].as_i64(), Some(last_seq + 5));
    assert_eq!(ahead_json["log_head_seq"].as_i64(), Some(last_seq));
}

#[tokio::test]
async fn test_pull_cursor_above_head_for_fully_pruned_group_uses_floor() {
    // Head accounting: once every batch is pruned, MAX(id)=0 but the head is
    // the pruned floor. A cursor at the floor is in-sync (200 empty); only a
    // cursor strictly above the floor trips cursor_ahead_of_log.
    let (url, _server, relay_db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;

    let mut last_seq = 0i64;
    for i in 0..3 {
        let envelope = make_test_envelope(&sync_id, &device_id, &format!("batch-{i:03}"), 0);
        let resp = push_signed(&client, &url, &sync_id, &device_id, &token, &keys, &envelope).await;
        assert!(resp.status().is_success());
        let json: Value = resp.json().await.unwrap();
        last_seq = json["server_seq"].as_i64().unwrap();
    }

    // Prune everything: floor advances to last_seq, MAX(id) drops to 0.
    relay_db
        .with_conn(|conn| {
            db::prune_batches_before(conn, &sync_id, last_seq + 1)?;
            assert_eq!(db::get_latest_seq(conn, &sync_id)?, 0);
            assert_eq!(db::get_pruned_floor_seq(conn, &sync_id)?, last_seq);
            Ok(())
        })
        .unwrap();

    // Cursor at the floor: head == floor, so this is in-sync, not ahead.
    let at_floor = client
        .get(format!("{url}/v1/sync/{sync_id}/changes?since={last_seq}"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id)
        .send()
        .await
        .unwrap();
    assert_eq!(at_floor.status(), 200, "cursor at the pruned floor is the head, not ahead");
    let at_floor_json: Value = at_floor.json().await.unwrap();
    assert_eq!(at_floor_json["log_head_seq"].as_i64(), Some(last_seq));

    // Cursor above the floor: regressed lineage.
    let above = client
        .get(format!("{url}/v1/sync/{sync_id}/changes?since={}", last_seq + 1))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id)
        .send()
        .await
        .unwrap();
    assert_eq!(above.status(), 409);
    let above_json: Value = above.json().await.unwrap();
    assert_eq!(above_json["error"].as_str(), Some("cursor_ahead_of_log"));
    assert_eq!(above_json["log_head_seq"].as_i64(), Some(last_seq));
}

#[tokio::test]
async fn test_ack_accepts_cursor_at_pruned_floor() {
    let (url, _server, relay_db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;

    let mut last_seq = 0i64;
    for i in 0..3 {
        let envelope = make_test_envelope(&sync_id, &device_id, &format!("batch-{i:03}"), 0);
        let resp = push_signed(&client, &url, &sync_id, &device_id, &token, &keys, &envelope).await;
        assert!(resp.status().is_success(), "push failed: {}", resp.status());
        let json: Value = resp.json().await.unwrap();
        last_seq = json["server_seq"].as_i64().unwrap();
    }

    relay_db
        .with_conn(|conn| {
            let pruned = db::prune_batches_before(conn, &sync_id, last_seq + 1)?;
            assert_eq!(pruned, 3);
            assert_eq!(db::get_latest_seq(conn, &sync_id)?, 0);
            assert_eq!(db::get_pruned_floor_seq(conn, &sync_id)?, last_seq);
            Ok(())
        })
        .unwrap();

    let accepted = ack_signed(&client, &url, &sync_id, &device_id, &token, &keys, last_seq).await;
    assert_eq!(
        accepted.status(),
        204,
        "ack at a known pruned floor should not produce a 400 storm"
    );

    let too_far =
        ack_signed(&client, &url, &sync_id, &device_id, &token, &keys, last_seq + 1).await;
    assert_eq!(too_far.status(), 400, "ack beyond retained or pruned history is still invalid");
}

#[tokio::test]
async fn test_pull_since_zero_succeeds_when_no_pruning_has_happened() {
    // Regression: the bootstrap floor must be a per-sync-group "we have pruned
    // through here" marker, not the global SQLite auto-increment of `batches.id`.
    // If two sync groups share a relay and the second one's first push lands at
    // a high global id, a fresh client at since=0 must still be able to pull —
    // nothing has been pruned for that sync group yet.
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();

    // Fill global batches.id to a non-trivial value via an unrelated sync group.
    let other_sync_id = generate_sync_id();
    let other_device_id = generate_device_id();
    let other_keys = TestDeviceKeys::generate(&other_device_id);
    let other_token =
        register_device(&client, &url, &other_sync_id, &other_device_id, &other_keys).await;
    for i in 0..5 {
        let envelope =
            make_test_envelope(&other_sync_id, &other_device_id, &format!("filler-{i:03}"), 0);
        let resp = push_signed(
            &client,
            &url,
            &other_sync_id,
            &other_device_id,
            &other_token,
            &other_keys,
            &envelope,
        )
        .await;
        assert!(resp.status().is_success());
    }

    // Now create a fresh sync group whose first batch will be assigned a high
    // global id, and push a single batch into it.
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;

    let envelope = make_test_envelope(&sync_id, &device_id, "first-batch", 0);
    let push_resp =
        push_signed(&client, &url, &sync_id, &device_id, &token, &keys, &envelope).await;
    assert!(push_resp.status().is_success());

    // A fresh client on this group with since=0 must succeed — no pruning has
    // happened, so the bootstrap rule should not fire.
    let pull = client
        .get(format!("{url}/v1/sync/{sync_id}/changes?since=0"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id)
        .send()
        .await
        .unwrap();
    assert_eq!(
        pull.status(),
        200,
        "fresh client at since=0 must pull successfully when no pruning has occurred (got {})",
        pull.status()
    );
    let body: Value = pull.json().await.unwrap();
    let batches = body["batches"].as_array().unwrap();
    assert_eq!(batches.len(), 1, "expected the single pushed batch");
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
    let body: Value = push_resp.json().await.unwrap();
    assert_eq!(body["error"], "epoch_mismatch");
    assert_eq!(body["envelope_epoch"], 5);
    assert_eq!(body["relay_epoch"], 0);
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

/// PUT a targeted snapshot with signed headers, returning the response.
#[allow(clippy::too_many_arguments)]
async fn put_targeted_snapshot(
    client: &Client,
    url: &str,
    sync_id: &str,
    device_id: &str,
    token: &str,
    keys: &TestDeviceKeys,
    server_seq_at: i64,
    for_device_id: &str,
    data: Vec<u8>,
) -> reqwest::Response {
    let path = format!("/v1/sync/{sync_id}/snapshot");
    let builder = client
        .put(format!("{url}/v1/sync/{sync_id}/snapshot"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", device_id)
        .header("X-Server-Seq-At", server_seq_at.to_string())
        .header("X-For-Device-Id", for_device_id);
    apply_signed_headers(builder, keys, "PUT", &path, sync_id, device_id, &data)
        .body(data)
        .send()
        .await
        .unwrap()
}

/// Full pairing-window: the initiator uploads a TARGETED snapshot for a
/// joiner that has NOT registered yet (so it is invisible to the ack floor),
/// then a registered device pushes and acks a tail batch above the snapshot
/// seq, and the hourly cleanup fires inside that window. The snapshot-aware
/// tail guard must keep `(S, head]` retained so that when the joiner finally
/// registers and pulls `since=S`, it receives the tail batch instead of a
/// `must_bootstrap_from_snapshot` loop that would brick it.
#[tokio::test]
async fn targeted_snapshot_tail_survives_cleanup_before_joiner_registers() {
    let (url, _server, db, state) = start_test_relay_with_state(test_config()).await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    // Initiator registers and pushes the baseline batch that the snapshot is cut at.
    let init_id = generate_device_id();
    let init_keys = TestDeviceKeys::generate(&init_id);
    let init_token = register_device(&client, &url, &sync_id, &init_id, &init_keys).await;

    let base_env = make_test_envelope(&sync_id, &init_id, "base", 0);
    let base_resp =
        push_signed(&client, &url, &sync_id, &init_id, &init_token, &init_keys, &base_env).await;
    let snapshot_seq = base_resp.json::<Value>().await.unwrap()["server_seq"].as_i64().unwrap();

    // Upload a TARGETED snapshot at S for a joiner that hasn't registered yet.
    let joiner_id = generate_device_id();
    let snap_resp = put_targeted_snapshot(
        &client,
        &url,
        &sync_id,
        &init_id,
        &init_token,
        &init_keys,
        snapshot_seq,
        &joiner_id,
        b"pair-snapshot".to_vec(),
    )
    .await;
    assert!(snap_resp.status().is_success(), "targeted snapshot upload failed");

    // A tail batch lands above S; the initiator (the only registered device) acks it.
    let tail_env = make_test_envelope(&sync_id, &init_id, "tail", 0);
    let tail_resp =
        push_signed(&client, &url, &sync_id, &init_id, &init_token, &init_keys, &tail_env).await;
    let tail_seq = tail_resp.json::<Value>().await.unwrap()["server_seq"].as_i64().unwrap();
    assert!(tail_seq > snapshot_seq);
    let ack_resp =
        ack_signed(&client, &url, &sync_id, &init_id, &init_token, &init_keys, tail_seq).await;
    assert!(ack_resp.status().is_success());

    // Hourly cleanup fires inside the pairing window. Without the tail guard,
    // ack-only pruning would delete the tail (the joiner is invisible to the floor).
    prism_sync_relay::cleanup::run_cleanup(&state).await;

    // The tail batch is still retained and the floor never passed S.
    let floor = db.with_read_conn(|conn| db::get_pruned_floor_seq(conn, &sync_id)).unwrap();
    assert!(floor <= snapshot_seq, "floor must not advance past the targeted snapshot seq");

    // The joiner registers (its 0-pinned receipt appears only now) and bootstraps
    // at cursor=S: the pull must deliver the tail batch, NOT a
    // must_bootstrap_from_snapshot error.
    let (joiner_token, _joiner_keys) = prepare_device(&db, &sync_id, &joiner_id).await;
    let pull = client
        .get(format!("{url}/v1/sync/{sync_id}/changes?since={snapshot_seq}"))
        .header("Authorization", format!("Bearer {joiner_token}"))
        .header("X-Device-Id", &joiner_id)
        .send()
        .await
        .unwrap();
    assert_eq!(pull.status(), 200, "joiner pull since=S must not trip must_bootstrap");
    let pull_json: Value = pull.json().await.unwrap();
    let batches = pull_json["batches"].as_array().unwrap();
    assert_eq!(batches.len(), 1, "the tail batch above the snapshot must be delivered");
    assert_eq!(batches[0]["envelope"]["batch_id"].as_str().unwrap(), "tail");
}

/// Shape-A detection rests on the lineage companion being kept current. Pin
/// that a cleanup cycle actually refreshes the on-disk companion's
/// `max_issued_batch_rowid` after new batches are issued — a silent regression of
/// cleanup step 16 would otherwise let a DB-only restore go undetected.
#[tokio::test]
async fn cleanup_refreshes_lineage_companion_high_water_mark() {
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("relay.db").to_string_lossy().to_string();
    let mut config = test_config();
    config.db_path = db_path.clone();
    let (url, _server, db, state) = start_test_relay_with_state(config).await;

    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;

    let companion_path = format!("{db_path}.lineage");
    let read_companion = || {
        let contents = std::fs::read_to_string(&companion_path).unwrap();
        serde_json::from_str::<db::LineageCompanion>(&contents).unwrap()
    };

    // The companion was written at startup before any batch existed.
    let before = read_companion();
    assert_eq!(before.max_issued_batch_rowid, 0, "no batch issued yet");

    for i in 0..3 {
        let envelope = make_test_envelope(&sync_id, &device_id, &format!("batch-{i:03}"), 0);
        let resp = push_signed(&client, &url, &sync_id, &device_id, &token, &keys, &envelope).await;
        assert!(resp.status().is_success());
    }
    let db_max = db.with_read_conn(db::get_max_issued_batch_rowid).unwrap();
    assert!(db_max >= 3, "three batches advanced the issued-rowid high-water mark");

    prism_sync_relay::cleanup::run_cleanup(&state).await;

    let after = read_companion();
    assert_eq!(
        after.max_issued_batch_rowid, db_max,
        "cleanup step 16 must refresh the companion to the current max issued rowid",
    );
    // The token is stable across the refresh (no regression occurred).
    assert_eq!(after.log_token, before.log_token, "the log token is unchanged by a clean cleanup");
}
