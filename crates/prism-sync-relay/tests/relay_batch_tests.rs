//! End-to-end tests for batch push/pull, sync operations, signature verification,
//! ACK/pruning, and epoch enforcement against the actual prism-sync-relay server
//! running in-process with an in-memory SQLite database.
//!
//! These tests use raw `reqwest` calls to exercise the relay HTTP API because
//! `ServerRelay::new()` only accepts `http://localhost` or `https://` URLs and
//! uses base64 encoding for keys while the relay expects hex — so direct HTTP
//! calls give us more control and validate the actual wire protocol.

mod common;

use ed25519_dalek::SigningKey;
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
    signing_key: &SigningKey,
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
        signing_key,
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

    // Device A pushes a batch
    let envelope = make_test_envelope(&sync_id, &device_a_id, "batch-001", 0);
    let push_resp = push_signed(
        &client,
        &url,
        &sync_id,
        &device_a_id,
        &token_a,
        &signing_key_a,
        &envelope,
    )
    .await;
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
    let push_resp2 = push_signed(
        &client,
        &url,
        &sync_id,
        &device_a_id,
        &token_a,
        &signing_key_a,
        &envelope2,
    )
    .await;
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
    let push_resp_dup = push_signed(
        &client,
        &url,
        &sync_id,
        &device_a_id,
        &token_a,
        &signing_key_a,
        &envelope,
    )
    .await;
    assert!(push_resp_dup.status().is_success());
    let dup_json: Value = push_resp_dup.json().await.unwrap();
    assert_eq!(
        dup_json["server_seq"].as_i64().unwrap(),
        server_seq,
        "duplicate push should return original server_seq"
    );
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
        let resp = push_signed(
            &client,
            &url,
            &sync_id,
            &device_id,
            &token,
            &signing_key,
            &envelope,
        )
        .await;
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
        &signing_key,
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
    let ack_body = serde_json::to_vec(&serde_json::json!({ "server_seq": last_seq })).unwrap();
    let ack_path = format!("/v1/sync/{sync_id}/ack");
    let ack_resp = apply_signed_headers(
        client
            .post(format!("{url}/v1/sync/{sync_id}/ack"))
            .header("Authorization", format!("Bearer {token}"))
            .header("X-Device-Id", &device_id)
            .header("Content-Type", "application/json"),
        &signing_key,
        "POST",
        &ack_path,
        &sync_id,
        &device_id,
        &ack_body,
    )
    .body(ack_body)
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
    let push_resp = push_signed(
        &client,
        &url,
        &sync_id,
        &device_id,
        &token,
        &signing_key,
        &envelope,
    )
    .await;
    assert_eq!(
        push_resp.status(),
        403,
        "push with wrong epoch should be rejected"
    );
}

// ───────────────── Tests: unsigned mutation requests are rejected ──────────

#[tokio::test]
async fn test_push_rejects_unsigned_request() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let device_id = generate_device_id();
    let signing_key = SigningKey::generate(&mut rand::thread_rng());
    let token = register_device(&client, &url, &sync_id, &device_id, &signing_key).await;

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
    assert_eq!(
        resp.status(),
        400,
        "push without signature headers should be rejected"
    );
}

#[tokio::test]
async fn test_put_snapshot_rejects_unsigned_request() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let device_id = generate_device_id();
    let signing_key = SigningKey::generate(&mut rand::thread_rng());
    let token = register_device(&client, &url, &sync_id, &device_id, &signing_key).await;

    let resp = client
        .put(format!("{url}/v1/sync/{sync_id}/snapshot"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id)
        .header("X-Server-Seq-At", "1")
        .body(b"snapshot-data".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        400,
        "snapshot upload without signature headers should be rejected"
    );
}

#[tokio::test]
async fn test_ack_rejects_unsigned_request() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let device_id = generate_device_id();
    let signing_key = SigningKey::generate(&mut rand::thread_rng());
    let token = register_device(&client, &url, &sync_id, &device_id, &signing_key).await;

    let resp = client
        .post(format!("{url}/v1/sync/{sync_id}/ack"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id)
        .header("Content-Type", "application/json")
        .body(serde_json::to_vec(&serde_json::json!({ "server_seq": 1 })).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        400,
        "ack without signature headers should be rejected"
    );
}
