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
use ed25519_dalek::SigningKey;
use reqwest::Client;

use prism_sync_relay::db;

use common::*;

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

    // Upload snapshot (epoch is looked up from device record, no X-Epoch header)
    let snapshot_data = b"encrypted-snapshot-payload-here";
    let put_resp = client
        .put(format!("{url}/v1/sync/{sync_id}/snapshot"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id)
        .header("X-Server-Seq-At", "42")
        .body(snapshot_data.to_vec())
        .send()
        .await
        .unwrap();
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
    let signing_key_a = SigningKey::generate(&mut rand::thread_rng());
    let token_a = register_device(&client, &url, &sync_id, &device_a_id, &signing_key_a).await;

    let device_b_id = generate_device_id();
    let token_b = prepare_device(&db, &sync_id, &device_b_id).await;

    let upload_resp = client
        .put(format!("{url}/v1/sync/{sync_id}/snapshot"))
        .header("Authorization", format!("Bearer {token_a}"))
        .header("X-Device-Id", &device_a_id)
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
    let json: serde_json::Value = download_resp.json().await.unwrap();
    let decoded_data = BASE64.decode(json["data"].as_str().unwrap()).unwrap();
    assert_eq!(decoded_data.as_slice(), b"targeted-snapshot");

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
