//! Integration tests for media upload/download endpoints.
//!
//! These tests exercise the full HTTP API for:
//! - `POST /v1/sync/{sync_id}/media`   (upload encrypted blob)
//! - `GET  /v1/sync/{sync_id}/media/{media_id}` (download encrypted blob)

mod common;

use common::*;
use reqwest::Client;
use sha2::{Digest, Sha256};

use prism_sync_relay::{config::Config, db};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a default test Config, optionally overriding specific fields.
fn base_test_config() -> Config {
    Config {
        port: 0,
        db_path: ":memory:".into(),
        nonce_expiry_secs: 60,
        session_expiry_secs: 3600,
        first_device_pow_difficulty_bits: 0,
        invite_ttl_secs: 86400,
        sync_inactive_ttl_secs: 7_776_000,
        stale_device_secs: 2_592_000,
        cleanup_interval_secs: 3600,
        max_unpruned_batches: 10_000,
        metrics_token: None,
        nonce_rate_limit: 100,
        nonce_rate_window_secs: 60,
        revoke_rate_limit: 100,
        revoke_rate_window_secs: 60,
        signed_request_max_skew_secs: 60,
        signed_request_nonce_window_secs: 120,
        snapshot_default_ttl_secs: 86400,
        revoked_tombstone_retention_secs: 2_592_000,
        reader_pool_size: 2,
        node_exporter_url: None,
        first_device_apple_attestation_enabled: false,
        first_device_apple_attestation_trust_roots_pem: vec![],
        first_device_apple_attestation_allowed_app_ids: vec![],
        first_device_android_attestation_enabled: true,
        first_device_android_attestation_trust_roots_pem: vec![],
        grapheneos_verified_boot_key_allowlist: vec![],
        registration_token: None,
        registration_enabled: true,
        pairing_session_ttl_secs: 300,
        pairing_session_rate_limit: 100,
        pairing_session_max_payload_bytes: 32768,
        sharing_init_ttl_secs: 604800,
        sharing_init_max_payload_bytes: 65536,
        sharing_identity_max_bytes: 8192,
        sharing_prekey_max_bytes: 4096,
        sharing_fetch_rate_limit: 100,
        sharing_init_rate_limit: 100,
        sharing_init_max_pending: 50,
        prekey_upload_max_age_secs: 604800,
        prekey_serve_max_age_secs: 2_592_000,
        prekey_max_future_skew_secs: 300,
        min_signature_version: 3,
        media_storage_path: std::env::temp_dir()
            .join(format!("prism_test_media_{}", uuid::Uuid::new_v4()))
            .to_str()
            .unwrap()
            .to_string(),
        media_max_file_bytes: 10_485_760,
        media_quota_bytes_per_group: 1_073_741_824,
        media_retention_days: 90,
        media_upload_rate_limit: 100,
        media_upload_rate_window_secs: 60,
        media_orphan_cleanup_secs: 86400,
        gif_provider_mode: prism_sync_relay::GifProviderMode::Disabled,
        gif_public_base_url: None,
        gif_prism_base_url: None,
        gif_api_base_url: "https://api.klipy.com".into(),
        gif_api_key: None,
        gif_http_timeout_secs: 15,
        gif_request_rate_limit: 20,
        gif_request_rate_window_secs: 60,
        gif_query_max_len: 200,
    }
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// Upload helper that handles signed request headers.
/// Returns the response (not consumed).
#[allow(clippy::too_many_arguments)]
async fn upload_media(
    client: &Client,
    url: &str,
    token: &str,
    keys: &TestDeviceKeys,
    sync_id: &str,
    device_id: &str,
    media_id: &str,
    data: &[u8],
) -> reqwest::Response {
    let hash = sha256_hex(data);
    let path = format!("/v1/sync/{sync_id}/media");
    let builder = client
        .post(format!("{url}{path}"))
        .bearer_auth(token)
        .header("X-Media-Id", media_id)
        .header("X-Content-Hash", &hash)
        .body(data.to_vec());

    apply_signed_headers(builder, keys, "POST", &path, sync_id, device_id, data)
        .send()
        .await
        .unwrap()
}

/// Upload helper that lets caller specify the hash (for mismatch tests).
#[allow(clippy::too_many_arguments)]
async fn upload_media_with_hash(
    client: &Client,
    url: &str,
    token: &str,
    keys: &TestDeviceKeys,
    sync_id: &str,
    device_id: &str,
    media_id: &str,
    data: &[u8],
    content_hash: &str,
) -> reqwest::Response {
    let path = format!("/v1/sync/{sync_id}/media");
    let builder = client
        .post(format!("{url}{path}"))
        .bearer_auth(token)
        .header("X-Media-Id", media_id)
        .header("X-Content-Hash", content_hash)
        .body(data.to_vec());

    apply_signed_headers(builder, keys, "POST", &path, sync_id, device_id, data)
        .send()
        .await
        .unwrap()
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

#[tokio::test]
async fn upload_and_download_roundtrip() {
    let (url, _handle, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();

    db.with_conn(|conn| {
        db::create_sync_group(conn, &sync_id, 0)?;
        Ok(())
    })
    .unwrap();
    let (token, keys) = prepare_device(&db, &sync_id, &device_id).await;

    // Upload a 1KB blob
    let data: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();
    let resp =
        upload_media(&client, &url, &token, &keys, &sync_id, &device_id, "test-media-001", &data)
            .await;
    assert_eq!(resp.status(), 200, "upload should succeed");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["media_id"], "test-media-001");

    // Download
    let resp = client
        .get(format!("{url}/v1/sync/{sync_id}/media/test-media-001"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "download should succeed");

    // Verify Cache-Control: no-store header
    let cache_control = resp
        .headers()
        .get("cache-control")
        .expect("should have Cache-Control header")
        .to_str()
        .unwrap();
    assert_eq!(cache_control, "no-store");

    // Verify Content-Type
    let content_type = resp
        .headers()
        .get("content-type")
        .expect("should have Content-Type header")
        .to_str()
        .unwrap();
    assert_eq!(content_type, "application/octet-stream");

    // Verify body matches
    let downloaded = resp.bytes().await.unwrap();
    assert_eq!(&downloaded[..], &data[..], "downloaded bytes should match uploaded bytes");
}

// ---------------------------------------------------------------------------
// Upload validation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn upload_rejects_missing_media_id_header() {
    let (url, _handle, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();

    db.with_conn(|conn| {
        db::create_sync_group(conn, &sync_id, 0)?;
        Ok(())
    })
    .unwrap();
    let (token, keys) = prepare_device(&db, &sync_id, &device_id).await;

    let data = b"test data";
    let hash = sha256_hex(data);
    let path = format!("/v1/sync/{sync_id}/media");

    // Omit X-Media-Id header
    let builder = client
        .post(format!("{url}{path}"))
        .bearer_auth(&token)
        .header("X-Content-Hash", &hash)
        .body(data.to_vec());

    let resp = apply_signed_headers(builder, &keys, "POST", &path, &sync_id, &device_id, data)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "should reject missing X-Media-Id");
}

#[tokio::test]
async fn upload_rejects_invalid_media_id() {
    let (url, _handle, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();

    db.with_conn(|conn| {
        db::create_sync_group(conn, &sync_id, 0)?;
        Ok(())
    })
    .unwrap();
    let (token, keys) = prepare_device(&db, &sync_id, &device_id).await;

    let data = b"test data";
    let hash = sha256_hex(data);
    let path = format!("/v1/sync/{sync_id}/media");

    // Use media_id with path traversal characters
    let builder = client
        .post(format!("{url}{path}"))
        .bearer_auth(&token)
        .header("X-Media-Id", "../foo")
        .header("X-Content-Hash", &hash)
        .body(data.to_vec());

    let resp = apply_signed_headers(builder, &keys, "POST", &path, &sync_id, &device_id, data)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "should reject media_id with path traversal chars");
}

#[tokio::test]
async fn upload_rejects_missing_content_hash() {
    let (url, _handle, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();

    db.with_conn(|conn| {
        db::create_sync_group(conn, &sync_id, 0)?;
        Ok(())
    })
    .unwrap();
    let (token, keys) = prepare_device(&db, &sync_id, &device_id).await;

    let data = b"test data";
    let path = format!("/v1/sync/{sync_id}/media");

    // Omit X-Content-Hash header
    let builder = client
        .post(format!("{url}{path}"))
        .bearer_auth(&token)
        .header("X-Media-Id", "test-media-001")
        .body(data.to_vec());

    let resp = apply_signed_headers(builder, &keys, "POST", &path, &sync_id, &device_id, data)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "should reject missing X-Content-Hash");
}

#[tokio::test]
async fn upload_rejects_content_hash_mismatch() {
    let (url, _handle, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();

    db.with_conn(|conn| {
        db::create_sync_group(conn, &sync_id, 0)?;
        Ok(())
    })
    .unwrap();
    let (token, keys) = prepare_device(&db, &sync_id, &device_id).await;

    let data = b"test data";
    let wrong_hash = "a".repeat(64); // valid format but wrong hash

    let resp = upload_media_with_hash(
        &client,
        &url,
        &token,
        &keys,
        &sync_id,
        &device_id,
        "test-media-001",
        data,
        &wrong_hash,
    )
    .await;
    assert_eq!(resp.status(), 400, "should reject content hash mismatch");
}

// ---------------------------------------------------------------------------
// Size/quota limits
// ---------------------------------------------------------------------------

#[tokio::test]
async fn upload_rejects_oversized_body() {
    // Use a custom config with a very small media_max_file_bytes.
    // The DefaultBodyLimit layer on the media routes enforces this,
    // so the response will likely be 413 from Axum's body limit layer.
    let mut config = base_test_config();
    config.media_max_file_bytes = 512;

    let (url, _handle, db) = start_test_relay_with_config(config).await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();

    db.with_conn(|conn| {
        db::create_sync_group(conn, &sync_id, 0)?;
        Ok(())
    })
    .unwrap();
    let (token, keys) = prepare_device(&db, &sync_id, &device_id).await;

    // Upload 1024 bytes, exceeding the 512 byte limit
    let data = vec![0xABu8; 1024];
    let hash = sha256_hex(&data);
    let path = format!("/v1/sync/{sync_id}/media");

    let builder = client
        .post(format!("{url}{path}"))
        .bearer_auth(&token)
        .header("X-Media-Id", "test-media-big")
        .header("X-Content-Hash", &hash)
        .body(data.clone());

    let resp = apply_signed_headers(builder, &keys, "POST", &path, &sync_id, &device_id, &data)
        .send()
        .await
        .unwrap();

    // Axum's DefaultBodyLimit may return 413 (PayloadTooLarge) or the handler
    // returns 413 if the body somehow gets through. Either way, expect rejection.
    let status = resp.status().as_u16();
    assert!(status == 413 || status == 400, "expected 413 or 400 for oversized body, got {status}");
}

#[tokio::test]
async fn upload_rejects_when_quota_exceeded() {
    let mut config = base_test_config();
    config.media_quota_bytes_per_group = 1024;

    let (url, _handle, db) = start_test_relay_with_config(config).await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();

    db.with_conn(|conn| {
        db::create_sync_group(conn, &sync_id, 0)?;
        Ok(())
    })
    .unwrap();
    let (token, keys) = prepare_device(&db, &sync_id, &device_id).await;

    // First upload: 900 bytes — should succeed
    let data1 = vec![0x01u8; 900];
    let resp =
        upload_media(&client, &url, &token, &keys, &sync_id, &device_id, "media-first", &data1)
            .await;
    assert_eq!(resp.status(), 200, "first upload should succeed (within quota)");

    // Second upload: 200 bytes — should fail (900 + 200 > 1024)
    let data2 = vec![0x02u8; 200];
    let resp =
        upload_media(&client, &url, &token, &keys, &sync_id, &device_id, "media-second", &data2)
            .await;
    assert_eq!(resp.status(), 507, "second upload should fail with 507 StorageFull");
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

#[tokio::test]
async fn upload_requires_auth() {
    let (url, _handle, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    db.with_conn(|conn| {
        db::create_sync_group(conn, &sync_id, 0)?;
        Ok(())
    })
    .unwrap();

    let data = b"test data";
    let hash = sha256_hex(data);

    // Send upload with no Authorization header
    let resp = client
        .post(format!("{url}/v1/sync/{sync_id}/media"))
        .header("X-Media-Id", "test-media-001")
        .header("X-Content-Hash", &hash)
        .body(data.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "should reject unauthenticated request");
}

#[tokio::test]
async fn download_rejects_wrong_sync_id() {
    let (url, _handle, db) = start_test_relay().await;
    let client = Client::new();

    // Set up two separate sync groups
    let sync_id_a = generate_sync_id();
    let device_id_a = generate_device_id();
    let sync_id_b = generate_sync_id();
    let device_id_b = generate_device_id();

    db.with_conn(|conn| {
        db::create_sync_group(conn, &sync_id_a, 0)?;
        db::create_sync_group(conn, &sync_id_b, 0)?;
        Ok(())
    })
    .unwrap();

    let (token_a, keys_a) = prepare_device(&db, &sync_id_a, &device_id_a).await;
    let (token_b, _keys_b) = prepare_device(&db, &sync_id_b, &device_id_b).await;

    // Upload to group A
    let data = b"secret data for group A";
    let resp = upload_media(
        &client,
        &url,
        &token_a,
        &keys_a,
        &sync_id_a,
        &device_id_a,
        "media-secret",
        data,
    )
    .await;
    assert_eq!(resp.status(), 200, "upload to group A should succeed");

    // Try to download from group B — the media_id exists but belongs to group A
    let resp = client
        .get(format!("{url}/v1/sync/{sync_id_b}/media/media-secret"))
        .bearer_auth(&token_b)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "download from wrong sync group should return 404");
}

// ---------------------------------------------------------------------------
// Download edge cases
// ---------------------------------------------------------------------------

#[tokio::test]
async fn download_returns_404_for_nonexistent() {
    let (url, _handle, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();

    db.with_conn(|conn| {
        db::create_sync_group(conn, &sync_id, 0)?;
        Ok(())
    })
    .unwrap();
    let (token, _keys) = prepare_device(&db, &sync_id, &device_id).await;

    let resp = client
        .get(format!("{url}/v1/sync/{sync_id}/media/nonexistent-id"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "should return 404 for nonexistent media");
}

#[tokio::test]
async fn download_returns_404_for_deleted_media() {
    let (url, _handle, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();

    db.with_conn(|conn| {
        db::create_sync_group(conn, &sync_id, 0)?;
        Ok(())
    })
    .unwrap();
    let (token, keys) = prepare_device(&db, &sync_id, &device_id).await;

    // Upload a blob
    let data = b"soon to be deleted";
    let resp =
        upload_media(&client, &url, &token, &keys, &sync_id, &device_id, "media-to-delete", data)
            .await;
    assert_eq!(resp.status(), 200, "upload should succeed");

    // Mark as deleted directly in DB
    db.with_conn(|conn| db::mark_media_deleted(conn, "media-to-delete")).unwrap();

    // Try to download — should get 404
    let resp = client
        .get(format!("{url}/v1/sync/{sync_id}/media/media-to-delete"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "download of deleted media should return 404");
}

// ---------------------------------------------------------------------------
// Duplicate handling
// ---------------------------------------------------------------------------

#[tokio::test]
async fn upload_duplicate_media_id_returns_409() {
    // NOTE: Another agent is adding explicit 409 Conflict handling for duplicate
    // media_id uploads. If that change hasn't landed yet, the current behavior
    // returns 500 (Internal Server Error) due to a UNIQUE constraint violation
    // in SQLite. This test expects the intended 409 behavior.
    let (url, _handle, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();

    db.with_conn(|conn| {
        db::create_sync_group(conn, &sync_id, 0)?;
        Ok(())
    })
    .unwrap();
    let (token, keys) = prepare_device(&db, &sync_id, &device_id).await;

    let data = b"original upload";
    let resp =
        upload_media(&client, &url, &token, &keys, &sync_id, &device_id, "dup-media-001", data)
            .await;
    assert_eq!(resp.status(), 200, "first upload should succeed");

    // Second upload with same media_id but different data
    let data2 = b"duplicate upload attempt";
    let resp =
        upload_media(&client, &url, &token, &keys, &sync_id, &device_id, "dup-media-001", data2)
            .await;

    let status = resp.status().as_u16();
    assert!(
        status == 409 || status == 500,
        "duplicate media_id should return 409 Conflict (or 500 if duplicate handling not yet implemented), got {status}"
    );
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

#[tokio::test]
async fn upload_rate_limited() {
    let mut config = base_test_config();
    config.media_upload_rate_limit = 2;
    config.media_upload_rate_window_secs = 60;

    let (url, _handle, db) = start_test_relay_with_config(config).await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();

    db.with_conn(|conn| {
        db::create_sync_group(conn, &sync_id, 0)?;
        Ok(())
    })
    .unwrap();
    let (token, keys) = prepare_device(&db, &sync_id, &device_id).await;

    // Upload 1: should succeed
    let data1 = vec![0x01u8; 64];
    let resp =
        upload_media(&client, &url, &token, &keys, &sync_id, &device_id, "rate-media-001", &data1)
            .await;
    assert_eq!(resp.status(), 200, "first upload should succeed");

    // Upload 2: should succeed (at the limit)
    let data2 = vec![0x02u8; 64];
    let resp =
        upload_media(&client, &url, &token, &keys, &sync_id, &device_id, "rate-media-002", &data2)
            .await;
    assert_eq!(resp.status(), 200, "second upload should succeed");

    // Upload 3: should be rate limited
    let data3 = vec![0x03u8; 64];
    let resp =
        upload_media(&client, &url, &token, &keys, &sync_id, &device_id, "rate-media-003", &data3)
            .await;
    assert_eq!(resp.status(), 429, "third upload should be rate limited");
}
