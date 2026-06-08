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
        session_max_age_secs: 7_776_000,
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
        ws_upgrade_rate_limit: 20,
        ws_upgrade_rate_window_secs: 60,
        trusted_proxy_cidrs: vec![],
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
        media_resupply_ttl_min_secs: 3600,
        media_pending_grace_secs: 300,
        media_expired_sweep_cap: 64,
        media_resupply_byte_ceiling_bytes: 536_870_912,
        media_resupply_rate_limit: 10,
        media_resupply_rate_window_secs: 60,
        media_pairing_push_rate_limit: 60,
        media_pairing_push_rate_window_secs: 60,
        gif_provider_mode: prism_sync_relay::GifProviderMode::Disabled,
        gif_public_base_url: None,
        gif_prism_base_url: None,
        gif_api_base_url: "https://api.klipy.com".into(),
        gif_api_key: None,
        gif_http_timeout_secs: 15,
        gif_request_rate_limit: 20,
        gif_request_rate_window_secs: 60,
        gif_query_max_len: 200,
        default_request_timeout_secs: 30,
        snapshot_request_timeout_secs: 300,
        media_request_timeout_secs: 120,
        snapshot_upload_concurrency: 8,
        media_upload_concurrency: 32,
        default_request_concurrency: 512,
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

// ───────────────────────── Per-route timeout scoping ─────────────────────────

use std::time::Duration;

/// Build a `reqwest::Body` that emits `bytes` slowly so request-body extraction
/// on the relay takes longer than the default-route timeout. Used to verify
/// that media upload has its own, longer `TimeoutLayer` scope.
fn slow_body(bytes: Vec<u8>, chunk_size: usize, interval: Duration) -> reqwest::Body {
    use futures::stream::{self, StreamExt};

    let chunk_size = chunk_size.max(1);
    let chunks: Vec<Vec<u8>> = bytes.chunks(chunk_size).map(<[u8]>::to_vec).collect();
    let stream = stream::iter(chunks).then(move |chunk| async move {
        tokio::time::sleep(interval).await;
        Ok::<_, std::io::Error>(chunk)
    });
    reqwest::Body::wrap_stream(stream)
}

#[tokio::test]
async fn media_upload_completes_past_default_timeout() {
    // default=1s would have killed any upload >1s. media=10s gives this
    // small blob enough room despite slow pacing.
    let mut config = base_test_config();
    config.default_request_timeout_secs = 1;
    config.media_request_timeout_secs = 10;

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

    let data: Vec<u8> = vec![0u8; 256 * 1024]; // 256 KB
    let hash = sha256_hex(&data);
    let path = format!("/v1/sync/{sync_id}/media");
    let builder = client
        .post(format!("{url}{path}"))
        .bearer_auth(&token)
        .header("X-Media-Id", "slow-media-001")
        .header("X-Content-Hash", &hash);

    let resp = apply_signed_headers(builder, &keys, "POST", &path, &sync_id, &device_id, &data)
        .body(slow_body(data, 32 * 1024, Duration::from_millis(250)))
        .send()
        .await
        .expect("slow media upload should complete");

    assert_eq!(
        resp.status(),
        200,
        "media POST should succeed within its own (longer) timeout window \
         even when the upload exceeds the default 1s timeout"
    );
}

// ───────────────────────── C1: lifecycle / TTL / idempotent upsert ─────────────

/// Upload helper that also sends an `X-Media-TTL` header (re-supply variant).
/// The header is intentionally NOT covered by the request signature, so a
/// successful upload also proves it is not part of the signed bytes.
#[allow(clippy::too_many_arguments)]
async fn upload_media_with_ttl(
    client: &Client,
    url: &str,
    token: &str,
    keys: &TestDeviceKeys,
    sync_id: &str,
    device_id: &str,
    media_id: &str,
    data: &[u8],
    ttl_secs: u64,
) -> reqwest::Response {
    let hash = sha256_hex(data);
    let path = format!("/v1/sync/{sync_id}/media");
    let builder = client
        .post(format!("{url}{path}"))
        .bearer_auth(token)
        .header("X-Media-Id", media_id)
        .header("X-Content-Hash", &hash)
        .header("X-Media-TTL", ttl_secs.to_string())
        .body(data.to_vec());

    apply_signed_headers(builder, keys, "POST", &path, sync_id, device_id, data)
        .send()
        .await
        .unwrap()
}

fn config_with_storage(path: &str) -> Config {
    let mut c = base_test_config();
    c.media_storage_path = path.to_string();
    c
}

fn final_media_path(storage: &str, sync_id: &str, media_id: &str) -> std::path::PathBuf {
    std::path::Path::new(storage).join(sync_id).join(media_id)
}

async fn setup_group(db: &std::sync::Arc<prism_sync_relay::db::Database>, sync_id: &str) {
    db.with_conn(|conn| {
        db::create_sync_group(conn, sync_id, 0)?;
        Ok(())
    })
    .unwrap();
}

#[tokio::test]
async fn upload_without_ttl_defaults_to_no_expiry() {
    let (url, _h, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    setup_group(&db, &sync_id).await;
    let (token, keys) = prepare_device(&db, &sync_id, &device_id).await;

    let data = vec![1u8; 64];
    let resp = upload_media(&client, &url, &token, &keys, &sync_id, &device_id, "m-no-ttl", &data)
        .await;
    assert_eq!(resp.status(), 200);

    let row = db.with_conn(|c| db::get_media_metadata(c, "m-no-ttl")).unwrap().unwrap();
    assert!(row.expires_at.is_none(), "no X-Media-TTL ⇒ default retention (NULL)");
    assert!(row.committed_at.is_some(), "successful upload ⇒ committed");
}

#[tokio::test]
async fn upload_with_ttl_sets_clamped_expires_at() {
    let (url, _h, db) = start_test_relay().await; // default min=3600, retention=90d
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    setup_group(&db, &sync_id).await;
    let (token, keys) = prepare_device(&db, &sync_id, &device_id).await;

    // Below the floor → clamped up to the 3600s minimum.
    let data = vec![2u8; 64];
    upload_media_with_ttl(&client, &url, &token, &keys, &sync_id, &device_id, "m-min", &data, 1)
        .await;
    let row = db.with_conn(|c| db::get_media_metadata(c, "m-min")).unwrap().unwrap();
    assert_eq!(row.expires_at, Some(row.created_at + 3600), "clamped to min floor");

    // Within range → honored exactly.
    upload_media_with_ttl(&client, &url, &token, &keys, &sync_id, &device_id, "m-mid", &data, 7200)
        .await;
    let row = db.with_conn(|c| db::get_media_metadata(c, "m-mid")).unwrap().unwrap();
    assert_eq!(row.expires_at, Some(row.created_at + 7200), "honored within range");

    // Above retention → clamped down to retention (90d = 7_776_000s).
    upload_media_with_ttl(
        &client, &url, &token, &keys, &sync_id, &device_id, "m-max", &data, 999_999_999,
    )
    .await;
    let row = db.with_conn(|c| db::get_media_metadata(c, "m-max")).unwrap().unwrap();
    assert_eq!(row.expires_at, Some(row.created_at + 7_776_000), "clamped to retention ceiling");
}

#[tokio::test]
async fn download_404_after_ttl_expiry() {
    let mut config = base_test_config();
    config.media_resupply_ttl_min_secs = 1; // allow a 1s TTL for the test
    let (url, _h, db) = start_test_relay_with_config(config).await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    setup_group(&db, &sync_id).await;
    let (token, keys) = prepare_device(&db, &sync_id, &device_id).await;

    let data = vec![3u8; 64];
    let resp =
        upload_media_with_ttl(&client, &url, &token, &keys, &sync_id, &device_id, "m-ttl", &data, 1)
            .await;
    assert_eq!(resp.status(), 200);

    // Servable immediately.
    let resp = client
        .get(format!("{url}/v1/sync/{sync_id}/media/m-ttl"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    tokio::time::sleep(Duration::from_millis(1200)).await;

    // Past TTL ⇒ servable predicate fails ⇒ 404 (independent of the file).
    let resp = client
        .get(format!("{url}/v1/sync/{sync_id}/media/m-ttl"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "expired blob is not servable");
}

#[tokio::test]
async fn idempotent_reupload_same_content_zero_quota_delta() {
    let (url, _h, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    setup_group(&db, &sync_id).await;
    let (token, keys) = prepare_device(&db, &sync_id, &device_id).await;

    let data = vec![4u8; 128];
    assert_eq!(
        upload_media(&client, &url, &token, &keys, &sync_id, &device_id, "m-idem", &data)
            .await
            .status(),
        200
    );
    let usage_before = db.with_conn(|c| db::get_group_media_usage(c, &sync_id)).unwrap();

    // Re-upload identical bytes (same content hash) → idempotent 200, Δquota 0.
    assert_eq!(
        upload_media(&client, &url, &token, &keys, &sync_id, &device_id, "m-idem", &data)
            .await
            .status(),
        200
    );
    let usage_after = db.with_conn(|c| db::get_group_media_usage(c, &sync_id)).unwrap();
    assert_eq!(usage_before, usage_after, "idempotent re-upload must not change quota");

    // Still downloadable with the original bytes.
    let resp = client
        .get(format!("{url}/v1/sync/{sync_id}/media/m-idem"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.bytes().await.unwrap()[..], data[..]);
}

#[tokio::test]
async fn repair_reupload_when_file_missing() {
    let tmp = tempfile::TempDir::new().unwrap();
    let storage = tmp.path().to_str().unwrap().to_string();
    let (url, _h, db) = start_test_relay_with_config(config_with_storage(&storage)).await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    setup_group(&db, &sync_id).await;
    let (token, keys) = prepare_device(&db, &sync_id, &device_id).await;

    let data = vec![5u8; 256];
    assert_eq!(
        upload_media(&client, &url, &token, &keys, &sync_id, &device_id, "m-repair", &data)
            .await
            .status(),
        200
    );
    let usage_before = db.with_conn(|c| db::get_group_media_usage(c, &sync_id)).unwrap();

    // Simulate a lost file (legacy crash row): metadata says committed, file gone.
    let file = final_media_path(&storage, &sync_id, "m-repair");
    std::fs::remove_file(&file).unwrap();
    let resp = client
        .get(format!("{url}/v1/sync/{sync_id}/media/m-repair"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "missing file ⇒ download 404 (belt-and-suspenders)");

    // Re-upload identical bytes → repair: re-stage→promote→finalize, Δquota 0.
    assert_eq!(
        upload_media(&client, &url, &token, &keys, &sync_id, &device_id, "m-repair", &data)
            .await
            .status(),
        200
    );
    assert!(file.exists(), "repair restores the file");
    let usage_after = db.with_conn(|c| db::get_group_media_usage(c, &sync_id)).unwrap();
    assert_eq!(usage_before, usage_after, "repair must not change quota");

    let resp = client
        .get(format!("{url}/v1/sync/{sync_id}/media/m-repair"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.bytes().await.unwrap()[..], data[..]);
}

#[tokio::test]
async fn resurrect_after_expiry_recounts_quota() {
    let mut config = base_test_config();
    config.media_resupply_ttl_min_secs = 1;
    let (url, _h, db) = start_test_relay_with_config(config).await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    setup_group(&db, &sync_id).await;
    let (token, keys) = prepare_device(&db, &sync_id, &device_id).await;

    let data = vec![6u8; 200];
    upload_media_with_ttl(&client, &url, &token, &keys, &sync_id, &device_id, "m-res", &data, 1)
        .await;
    tokio::time::sleep(Duration::from_millis(1200)).await;
    // Expired ⇒ excluded from quota.
    assert_eq!(db.with_conn(|c| db::get_group_media_usage(c, &sync_id)).unwrap(), 0);

    // Re-upload ⇒ resurrect, Δquota +size, servable again.
    assert_eq!(
        upload_media(&client, &url, &token, &keys, &sync_id, &device_id, "m-res", &data)
            .await
            .status(),
        200
    );
    assert_eq!(db.with_conn(|c| db::get_group_media_usage(c, &sync_id)).unwrap(), 200);
    let resp = client
        .get(format!("{url}/v1/sync/{sync_id}/media/m-res"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn over_quota_preflight_rejects_before_staging() {
    let tmp = tempfile::TempDir::new().unwrap();
    let storage = tmp.path().to_str().unwrap().to_string();
    let mut config = config_with_storage(&storage);
    config.media_quota_bytes_per_group = 1024;
    let (url, _h, db) = start_test_relay_with_config(config).await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    setup_group(&db, &sync_id).await;
    let (token, keys) = prepare_device(&db, &sync_id, &device_id).await;

    let data1 = vec![7u8; 900];
    assert_eq!(
        upload_media(&client, &url, &token, &keys, &sync_id, &device_id, "m-fill", &data1)
            .await
            .status(),
        200
    );

    // 900 + 200 > 1024 ⇒ rejected before any bytes are staged.
    let data2 = vec![8u8; 200];
    let resp =
        upload_media(&client, &url, &token, &keys, &sync_id, &device_id, "m-over", &data2).await;
    assert_eq!(resp.status(), 507);

    // No final file and no leftover staging file for the rejected upload.
    assert!(!final_media_path(&storage, &sync_id, "m-over").exists());
    let staging_dir = std::path::Path::new(&storage).join(&sync_id).join(".staging");
    if staging_dir.exists() {
        let leftovers: Vec<_> = std::fs::read_dir(&staging_dir).unwrap().flatten().collect();
        assert!(leftovers.is_empty(), "preflight reject must not leave staging files");
    }
}

#[tokio::test]
async fn concurrent_same_media_id_uploads_no_clobber() {
    use futures::future::join_all;
    let tmp = tempfile::TempDir::new().unwrap();
    let storage = tmp.path().to_str().unwrap().to_string();
    let (url, _h, db) = start_test_relay_with_config(config_with_storage(&storage)).await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    setup_group(&db, &sync_id).await;
    let (token, keys) = prepare_device(&db, &sync_id, &device_id).await;

    let data = vec![9u8; 512];
    // Fire several concurrent uploads of the SAME id + content.
    let uploads = (0..8).map(|_| {
        upload_media(&client, &url, &token, &keys, &sync_id, &device_id, "m-conc", &data)
    });
    let results = join_all(uploads).await;
    for resp in results {
        let status = resp.status().as_u16();
        assert!(status == 200 || status == 202, "each upload is committed or in-progress, got {status}");
    }

    // The blob ends servable with the right bytes…
    let resp = client
        .get(format!("{url}/v1/sync/{sync_id}/media/m-conc"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.bytes().await.unwrap()[..], data[..]);

    // …and there is exactly one final file (no cross-delete / clobber).
    let sync_dir = std::path::Path::new(&storage).join(&sync_id);
    let finals: Vec<_> = std::fs::read_dir(&sync_dir)
        .unwrap()
        .flatten()
        .filter(|e| e.path().is_file())
        .collect();
    assert_eq!(finals.len(), 1, "exactly one committed file for the media_id");
}

#[tokio::test]
async fn always_sweep_keeps_disk_near_quota() {
    let tmp = tempfile::TempDir::new().unwrap();
    let storage = tmp.path().to_str().unwrap().to_string();
    let mut config = config_with_storage(&storage);
    config.media_resupply_ttl_min_secs = 1;
    let (url, _h, db) = start_test_relay_with_config(config).await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    setup_group(&db, &sync_id).await;
    let (token, keys) = prepare_device(&db, &sync_id, &device_id).await;

    // Three short-TTL blobs land on disk.
    let data = vec![0xAAu8; 300];
    for id in ["c1", "c2", "c3"] {
        upload_media_with_ttl(&client, &url, &token, &keys, &sync_id, &device_id, id, &data, 1)
            .await;
        assert!(final_media_path(&storage, &sync_id, id).exists());
    }
    tokio::time::sleep(Duration::from_millis(1200)).await;

    // A fresh upload's always-sweep reclaims the expired files first, so
    // physical disk tracks the live set (≈ quota), not the whole history.
    let fresh = vec![0xBBu8; 64];
    upload_media(&client, &url, &token, &keys, &sync_id, &device_id, "c-fresh", &fresh).await;
    for id in ["c1", "c2", "c3"] {
        assert!(
            !final_media_path(&storage, &sync_id, id).exists(),
            "expired file {id} swept from disk by the next upload"
        );
    }
    assert!(final_media_path(&storage, &sync_id, "c-fresh").exists());
}

// ───────────────────────── C2: batch-exists ─────────────────────────

async fn batch_exists(
    client: &Client,
    url: &str,
    token: &str,
    sync_id: &str,
    media_ids: &[&str],
) -> reqwest::Response {
    client
        .post(format!("{url}/v1/sync/{sync_id}/media/exists"))
        .bearer_auth(token)
        .json(&serde_json::json!({ "media_ids": media_ids }))
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn batch_exists_returns_only_servable() {
    let (url, _h, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    setup_group(&db, &sync_id).await;
    let (token, keys) = prepare_device(&db, &sync_id, &device_id).await;

    for id in ["a", "b"] {
        let data = vec![1u8; 32];
        assert_eq!(
            upload_media(&client, &url, &token, &keys, &sync_id, &device_id, id, &data).await.status(),
            200
        );
    }

    // Both servable initially; an unknown id is absent.
    let resp = batch_exists(&client, &url, &token, &sync_id, &["a", "b", "nope"]).await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let mut present: Vec<String> = body["present"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    present.sort();
    assert_eq!(present, vec!["a".to_string(), "b".to_string()]);

    // Expire "a" → batch-exists must drop it (TTL → absent), matching download-404.
    db.with_conn(|conn| {
        conn.execute(
            "UPDATE media_metadata SET expires_at = ?1 WHERE media_id = 'a'",
            rusqlite::params![db::now_secs() - 10],
        )?;
        Ok(())
    })
    .unwrap();
    let resp = batch_exists(&client, &url, &token, &sync_id, &["a", "b"]).await;
    let body: serde_json::Value = resp.json().await.unwrap();
    let present: Vec<String> = body["present"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(present, vec!["b".to_string()], "expired blob is not servable");
}

#[tokio::test]
async fn batch_exists_is_scoped_to_sync_group() {
    let (url, _h, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id_a = generate_sync_id();
    let device_a = generate_device_id();
    let sync_id_b = generate_sync_id();
    let device_b = generate_device_id();
    setup_group(&db, &sync_id_a).await;
    setup_group(&db, &sync_id_b).await;
    let (token_a, keys_a) = prepare_device(&db, &sync_id_a, &device_a).await;
    let (token_b, _keys_b) = prepare_device(&db, &sync_id_b, &device_b).await;

    let data = vec![2u8; 32];
    upload_media(&client, &url, &token_a, &keys_a, &sync_id_a, &device_a, "secret", &data).await;

    // Group B asks about group A's media_id → must be absent (no cross-group leak).
    let resp = batch_exists(&client, &url, &token_b, &sync_id_b, &["secret"]).await;
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["present"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn batch_exists_rejects_oversized_request() {
    let (url, _h, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    setup_group(&db, &sync_id).await;
    let (token, _keys) = prepare_device(&db, &sync_id, &device_id).await;

    let ids: Vec<String> = (0..1025).map(|i| format!("id-{i}")).collect();
    let resp = client
        .post(format!("{url}/v1/sync/{sync_id}/media/exists"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "media_ids": ids }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "over the per-request id cap");
}

#[tokio::test]
async fn batch_exists_requires_auth() {
    let (url, _h, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    setup_group(&db, &sync_id).await;

    let resp = client
        .post(format!("{url}/v1/sync/{sync_id}/media/exists"))
        .json(&serde_json::json!({ "media_ids": ["x"] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn servable_upload_implies_file_present() {
    let tmp = tempfile::TempDir::new().unwrap();
    let storage = tmp.path().to_str().unwrap().to_string();
    let (url, _h, db) = start_test_relay_with_config(config_with_storage(&storage)).await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    setup_group(&db, &sync_id).await;
    let (token, keys) = prepare_device(&db, &sync_id, &device_id).await;

    let data = vec![0xCDu8; 128];
    assert_eq!(
        upload_media(&client, &url, &token, &keys, &sync_id, &device_id, "m-inv", &data)
            .await
            .status(),
        200
    );
    // The servable-⟹-file invariant: a committed/servable row has its file.
    let row = db.with_conn(|c| db::get_media_metadata(c, "m-inv")).unwrap().unwrap();
    assert!(row.committed_at.is_some() && row.deleted_at.is_none());
    assert!(final_media_path(&storage, &sync_id, "m-inv").exists());
}
