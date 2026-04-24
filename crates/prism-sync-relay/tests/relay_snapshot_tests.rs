//! End-to-end tests for snapshot put/get, targeting, and expiry against the
//! actual prism-sync-relay server running in-process with an in-memory SQLite
//! database.
//!
//! These tests use raw `reqwest` calls to exercise the relay HTTP API because
//! `ServerRelay::new()` only accepts `http://localhost` or `https://` URLs and
//! uses base64 encoding for keys while the relay expects hex — so direct HTTP
//! calls give us more control and validate the actual wire protocol.

mod common;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use reqwest::Client;

use prism_sync_relay::db;
use prism_sync_relay::snapshot_limits::MAX_SNAPSHOT_WIRE_BYTES;

use common::*;

/// Helper: PUT a snapshot with signed headers.
#[allow(clippy::too_many_arguments)]
async fn put_snapshot_signed(
    client: &Client,
    url: &str,
    sync_id: &str,
    device_id: &str,
    token: &str,
    keys: &TestDeviceKeys,
    server_seq_at: &str,
    snapshot_data: Vec<u8>,
    extra_headers: &[(&str, &str)],
) -> reqwest::Response {
    let path = format!("/v1/sync/{sync_id}/snapshot");
    let mut builder = client
        .put(format!("{url}/v1/sync/{sync_id}/snapshot"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", device_id)
        .header("X-Server-Seq-At", server_seq_at);
    for (k, v) in extra_headers {
        builder = builder.header(*k, *v);
    }
    apply_signed_headers(builder, keys, "PUT", &path, sync_id, device_id, &snapshot_data)
        .body(snapshot_data)
        .send()
        .await
        .unwrap()
}

// ───────────────────────────── Test 4: Snapshot ─────────────────────────

#[tokio::test]
async fn test_snapshot_put_get_roundtrip() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;

    // Initially no snapshot
    let get_resp = client
        .get(format!("{url}/v1/sync/{sync_id}/snapshot"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id)
        .send()
        .await
        .unwrap();
    assert_eq!(get_resp.status(), 404, "no snapshot initially");

    // Upload snapshot (epoch is looked up from device record, no X-Epoch header)
    let snapshot_data = b"encrypted-snapshot-payload-here";
    let put_resp = put_snapshot_signed(
        &client,
        &url,
        &sync_id,
        &device_id,
        &token,
        &keys,
        "42",
        snapshot_data.to_vec(),
        &[],
    )
    .await;
    assert_eq!(put_resp.status(), 204, "snapshot put should return 204");

    // Download snapshot (response is now JSON with base64-encoded data)
    let get_resp2 = client
        .get(format!("{url}/v1/sync/{sync_id}/snapshot"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id)
        .send()
        .await
        .unwrap();
    assert_eq!(get_resp2.status(), 200);
    let json: serde_json::Value = get_resp2.json().await.unwrap();
    assert_eq!(json["epoch"].as_i64().unwrap(), 0);
    assert_eq!(json["server_seq_at"].as_i64().unwrap(), 42);
    let decoded_data = BASE64.decode(json["data"].as_str().unwrap()).unwrap();
    assert_eq!(decoded_data.as_slice(), snapshot_data);
}

#[tokio::test]
async fn test_targeted_snapshot_allows_only_intended_device() {
    let (url, _server, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let device_a_id = generate_device_id();
    let keys_a = TestDeviceKeys::generate(&device_a_id);
    let token_a = register_device(&client, &url, &sync_id, &device_a_id, &keys_a).await;

    let device_b_id = generate_device_id();
    let (token_b, _keys_b) = prepare_device(&db, &sync_id, &device_b_id).await;

    let upload_resp = put_snapshot_signed(
        &client,
        &url,
        &sync_id,
        &device_a_id,
        &token_a,
        &keys_a,
        "42",
        b"targeted-snapshot".to_vec(),
        &[("X-Snapshot-TTL", "300"), ("X-For-Device-Id", &device_b_id)],
    )
    .await;
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
    assert_eq!(download_resp.status(), 200, "target device should be allowed");
    let json: serde_json::Value = download_resp.json().await.unwrap();
    let decoded_data = BASE64.decode(json["data"].as_str().unwrap()).unwrap();
    assert_eq!(decoded_data.as_slice(), b"targeted-snapshot");

    // Regression: GET must NOT auto-delete. Retention is now ACK-gated
    // via DELETE /v1/sync/{sync_id}/snapshot from the target device.
    let second_get = client
        .get(format!("{url}/v1/sync/{sync_id}/snapshot"))
        .header("Authorization", format!("Bearer {token_b}"))
        .header("X-Device-Id", &device_b_id)
        .send()
        .await
        .unwrap();
    assert_eq!(second_get.status(), 200, "snapshot must survive a GET (no auto-delete)");
    let json2: serde_json::Value = second_get.json().await.unwrap();
    let decoded2 = BASE64.decode(json2["data"].as_str().unwrap()).unwrap();
    assert_eq!(decoded2.as_slice(), b"targeted-snapshot");
}

#[tokio::test]
async fn test_targeted_snapshot_expires() {
    let (url, _server, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let device_a_id = generate_device_id();
    let keys_a = TestDeviceKeys::generate(&device_a_id);
    let token_a = register_device(&client, &url, &sync_id, &device_a_id, &keys_a).await;

    let device_b_id = generate_device_id();
    let (token_b, _keys_b) = prepare_device(&db, &sync_id, &device_b_id).await;

    let upload_resp = put_snapshot_signed(
        &client,
        &url,
        &sync_id,
        &device_a_id,
        &token_a,
        &keys_a,
        "99",
        b"expiring-snapshot".to_vec(),
        &[("X-Snapshot-TTL", "1"), ("X-For-Device-Id", &device_b_id)],
    )
    .await;
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
    assert_eq!(expired_resp.status(), 404, "expired snapshot should be hidden");
}

// ───────────────── Size-limit and DELETE-ACK tests (Phase B.3) ─────────────

/// Issue a signed DELETE against `/v1/sync/{sync_id}/snapshot`.
async fn delete_snapshot_signed(
    client: &Client,
    url: &str,
    sync_id: &str,
    device_id: &str,
    token: &str,
    keys: &TestDeviceKeys,
) -> reqwest::Response {
    let path = format!("/v1/sync/{sync_id}/snapshot");
    let builder = client
        .delete(format!("{url}/v1/sync/{sync_id}/snapshot"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", device_id);
    apply_signed_headers(builder, keys, "DELETE", &path, sync_id, device_id, &[])
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn test_snapshot_accepts_25mb_payload() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;

    // 25 MB baseline — the v-prior limit is comfortably within the new cap.
    let snapshot = vec![0u8; 25 * 1024 * 1024];
    let resp = put_snapshot_signed(
        &client, &url, &sync_id, &device_id, &token, &keys, "1", snapshot, &[],
    )
    .await;
    assert_eq!(resp.status(), 204, "25 MB snapshot should be accepted");
}

#[tokio::test]
async fn test_snapshot_accepts_140mb_payload() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;

    // 140 MB — above the v-prior 25 MB cap, below the new 150 MB wire cap.
    // Exercises both the raised router body limit and the raised handler
    // body.len() check.
    let snapshot = vec![0u8; 140 * 1024 * 1024];
    let resp = put_snapshot_signed(
        &client, &url, &sync_id, &device_id, &token, &keys, "1", snapshot, &[],
    )
    .await;
    assert_eq!(resp.status(), 204, "140 MB snapshot should be accepted under the new cap");
}

#[tokio::test]
async fn test_snapshot_rejects_over_wire_limit() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;

    // 151 MB — 1 MB over the MAX_SNAPSHOT_WIRE_BYTES cap. The router
    // body-limit layer should reject before the handler runs; in that
    // case axum returns 413 (Payload Too Large) directly.
    let snapshot = vec![0u8; 151 * 1024 * 1024];
    assert!(snapshot.len() > MAX_SNAPSHOT_WIRE_BYTES);
    let resp = put_snapshot_signed(
        &client, &url, &sync_id, &device_id, &token, &keys, "1", snapshot, &[],
    )
    .await;
    assert_eq!(resp.status(), 413, "oversize snapshot should be rejected with 413");
}

#[tokio::test]
async fn test_get_snapshot_does_not_auto_delete() {
    // Regression: GET used to auto-delete after cross-device download.
    // With ACK-gated retention the snapshot must survive any number of
    // GETs until the target device explicitly DELETEs it.
    let (url, _server, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let initiator_id = generate_device_id();
    let keys_init = TestDeviceKeys::generate(&initiator_id);
    let token_init = register_device(&client, &url, &sync_id, &initiator_id, &keys_init).await;

    let joiner_id = generate_device_id();
    let (token_joiner, _keys_joiner) = prepare_device(&db, &sync_id, &joiner_id).await;

    let put_resp = put_snapshot_signed(
        &client,
        &url,
        &sync_id,
        &initiator_id,
        &token_init,
        &keys_init,
        "7",
        b"persistent-snapshot".to_vec(),
        &[("X-For-Device-Id", &joiner_id)],
    )
    .await;
    assert_eq!(put_resp.status(), 204);

    for attempt in 0..3 {
        let resp = client
            .get(format!("{url}/v1/sync/{sync_id}/snapshot"))
            .header("Authorization", format!("Bearer {token_joiner}"))
            .header("X-Device-Id", &joiner_id)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "GET #{attempt} must still find the snapshot");
        let json: serde_json::Value = resp.json().await.unwrap();
        let decoded = BASE64.decode(json["data"].as_str().unwrap()).unwrap();
        assert_eq!(decoded.as_slice(), b"persistent-snapshot");
    }
}

#[tokio::test]
async fn test_delete_snapshot_by_target_device_removes_it() {
    let (url, _server, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let initiator_id = generate_device_id();
    let keys_init = TestDeviceKeys::generate(&initiator_id);
    let token_init = register_device(&client, &url, &sync_id, &initiator_id, &keys_init).await;

    let joiner_id = generate_device_id();
    let (token_joiner, keys_joiner) = prepare_device(&db, &sync_id, &joiner_id).await;

    let put_resp = put_snapshot_signed(
        &client,
        &url,
        &sync_id,
        &initiator_id,
        &token_init,
        &keys_init,
        "9",
        b"ack-me".to_vec(),
        &[("X-For-Device-Id", &joiner_id)],
    )
    .await;
    assert_eq!(put_resp.status(), 204);

    // Target device ACKs the snapshot — expect 204.
    let del_resp = delete_snapshot_signed(
        &client,
        &url,
        &sync_id,
        &joiner_id,
        &token_joiner,
        &keys_joiner,
    )
    .await;
    assert_eq!(del_resp.status(), 204, "target device should be able to ACK-delete");

    // Subsequent GET returns 404.
    let get_resp = client
        .get(format!("{url}/v1/sync/{sync_id}/snapshot"))
        .header("Authorization", format!("Bearer {token_joiner}"))
        .header("X-Device-Id", &joiner_id)
        .send()
        .await
        .unwrap();
    assert_eq!(get_resp.status(), 404, "snapshot should be gone after ACK-delete");
}

#[tokio::test]
async fn test_delete_snapshot_by_non_target_device_is_forbidden() {
    let (url, _server, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let initiator_id = generate_device_id();
    let keys_init = TestDeviceKeys::generate(&initiator_id);
    let token_init = register_device(&client, &url, &sync_id, &initiator_id, &keys_init).await;

    let joiner_id = generate_device_id();
    let (_token_joiner, _keys_joiner) = prepare_device(&db, &sync_id, &joiner_id).await;

    // Third device registered on the same sync group — not the snapshot target.
    let attacker_id = generate_device_id();
    let (token_attacker, keys_attacker) = prepare_device(&db, &sync_id, &attacker_id).await;

    let put_resp = put_snapshot_signed(
        &client,
        &url,
        &sync_id,
        &initiator_id,
        &token_init,
        &keys_init,
        "9",
        b"hands-off".to_vec(),
        &[("X-For-Device-Id", &joiner_id)],
    )
    .await;
    assert_eq!(put_resp.status(), 204);

    let resp = delete_snapshot_signed(
        &client,
        &url,
        &sync_id,
        &attacker_id,
        &token_attacker,
        &keys_attacker,
    )
    .await;
    assert_eq!(resp.status(), 403, "non-target device must not be able to ACK-delete");
}

#[tokio::test]
async fn test_delete_snapshot_when_missing_returns_404() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;

    let resp =
        delete_snapshot_signed(&client, &url, &sync_id, &device_id, &token, &keys).await;
    assert_eq!(resp.status(), 404, "DELETE with no snapshot present should be 404");
}
