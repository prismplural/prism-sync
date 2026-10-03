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
use prism_sync_relay::snapshot_limits::{
    DEFAULT_TARGETED_SNAPSHOT_TTL_SECS, MAX_SNAPSHOT_WIRE_BYTES, MAX_TARGETED_SNAPSHOTS_PER_GROUP,
};

use common::*;

// ───────────────── File-backed snapshot blob tests ─────────────────
//
// The relay stores snapshot bytes on disk (like media) and keeps only a
// `blob_ref` in the row, so the writer-mutex hold during PUT is tiny. These
// tests pin a known storage root so they can assert on the on-disk files
// directly, then verify PUT/GET/DELETE/expiry/cap/cleanup all keep the file
// set and the wire semantics consistent.

/// A test config whose media (and therefore the derived snapshot) storage lives
/// under `tmp`, so both trees are cleaned up when the `TempDir` drops. Returns
/// the config and the resolved snapshot storage root.
///
/// The startup storage gate canonicalizes the configured root, so the returned
/// root is canonicalized too — otherwise an assertion on the on-disk tree would
/// compare against a different (symlinked) path on platforms where the temp
/// directory itself is a symlink.
fn storage_under_tmp(tmp: &std::path::Path) -> (prism_sync_relay::config::Config, String) {
    let mut config = test_config();
    let canonical_tmp = std::fs::canonicalize(tmp).unwrap();
    let media = canonical_tmp.join("media");
    std::fs::create_dir_all(&media).unwrap();
    config.media_storage_path = media.to_str().unwrap().to_string();
    let snapshot_root = canonical_tmp.join("media-snapshots").to_str().unwrap().to_string();
    (config, snapshot_root)
}

/// List the snapshot blob files currently on disk for one group.
fn snapshot_files(snapshot_root: &str, sync_id: &str) -> Vec<std::path::PathBuf> {
    let dir = std::path::Path::new(snapshot_root).join(sync_id);
    match std::fs::read_dir(&dir) {
        Ok(rd) => rd.flatten().map(|e| e.path()).filter(|p| p.is_file()).collect(),
        Err(_) => Vec::new(),
    }
}

#[tokio::test]
async fn file_backed_put_stores_blob_on_disk_and_get_roundtrips() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (config, snapshot_root) = storage_under_tmp(tmp.path());
    let (url, _server, db) = start_file_backed_test_relay_with_config(config).await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;

    let payload = vec![7u8; 1024 * 1024]; // 1 MB
    let resp = put_snapshot_signed(
        &client,
        &url,
        &sync_id,
        &device_id,
        &token,
        &keys,
        "42",
        payload.clone(),
        &[],
    )
    .await;
    assert_eq!(resp.status(), 204);

    // The row is file-backed: a blob_ref is set and the inline `data` is empty.
    let (blob_ref, inline_len): (Option<String>, i64) = db
        .with_read_conn(|conn| {
            conn.query_row(
                "SELECT blob_ref, LENGTH(data) FROM snapshots WHERE sync_id = ?1",
                rusqlite::params![sync_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
        })
        .unwrap();
    assert!(blob_ref.is_some(), "row should reference an on-disk blob");
    assert_eq!(inline_len, 0, "file-backed row stores no inline bytes");

    // Exactly one blob file on disk, holding the raw (verbatim) bytes.
    let files = snapshot_files(&snapshot_root, &sync_id);
    assert_eq!(files.len(), 1, "exactly one snapshot blob on disk");
    assert_eq!(std::fs::read(&files[0]).unwrap(), payload, "blob bytes stored verbatim");

    // GET reads the file back and round-trips the bytes through the wire shape.
    let get = client
        .get(format!("{url}/v1/sync/{sync_id}/snapshot"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id)
        .send()
        .await
        .unwrap();
    assert_eq!(get.status(), 200);
    let json: serde_json::Value = get.json().await.unwrap();
    assert_eq!(json["server_seq_at"].as_i64().unwrap(), 42);
    assert_eq!(BASE64.decode(json["data"].as_str().unwrap()).unwrap(), payload);
}

#[tokio::test]
async fn file_backed_replace_unlinks_old_blob() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (config, snapshot_root) = storage_under_tmp(tmp.path());
    let (url, _server, _db) = start_file_backed_test_relay_with_config(config).await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;

    let r1 = put_snapshot_signed(
        &client,
        &url,
        &sync_id,
        &device_id,
        &token,
        &keys,
        "1",
        b"v1-bytes".to_vec(),
        &[],
    )
    .await;
    assert_eq!(r1.status(), 204);
    let after_v1 = snapshot_files(&snapshot_root, &sync_id);
    assert_eq!(after_v1.len(), 1, "first upload writes one blob");
    let first_path = after_v1[0].clone();

    let r2 = put_snapshot_signed(
        &client,
        &url,
        &sync_id,
        &device_id,
        &token,
        &keys,
        "2",
        b"v2-bytes-longer".to_vec(),
        &[],
    )
    .await;
    assert_eq!(r2.status(), 204);

    // The replace wrote a NEW unique file and unlinked the old one: exactly one
    // blob remains, and it is not the v1 file.
    let after_v2 = snapshot_files(&snapshot_root, &sync_id);
    assert_eq!(after_v2.len(), 1, "replace leaves exactly one blob (old unlinked)");
    assert_ne!(after_v2[0], first_path, "the replacing upload uses a fresh filename");
    assert!(!first_path.exists(), "the superseded blob was unlinked");

    let get = client
        .get(format!("{url}/v1/sync/{sync_id}/snapshot"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id)
        .send()
        .await
        .unwrap();
    let json: serde_json::Value = get.json().await.unwrap();
    assert_eq!(BASE64.decode(json["data"].as_str().unwrap()).unwrap(), b"v2-bytes-longer");
}

#[tokio::test]
async fn stale_put_cleans_up_its_own_blob() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (config, snapshot_root) = storage_under_tmp(tmp.path());
    let (url, _server, _db) = start_file_backed_test_relay_with_config(config).await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;

    let r1 = put_snapshot_signed(
        &client,
        &url,
        &sync_id,
        &device_id,
        &token,
        &keys,
        "5",
        b"winner".to_vec(),
        &[],
    )
    .await;
    assert_eq!(r1.status(), 204);
    assert_eq!(snapshot_files(&snapshot_root, &sync_id).len(), 1);

    // A stale (lower seq) upload is rejected with 409 — and the file it wrote
    // before the row guard ran must be cleaned up, leaving no orphan.
    let r2 = put_snapshot_signed(
        &client,
        &url,
        &sync_id,
        &device_id,
        &token,
        &keys,
        "3",
        b"loser".to_vec(),
        &[],
    )
    .await;
    assert_eq!(r2.status(), 409, "lower-seq upload is stale");
    let files = snapshot_files(&snapshot_root, &sync_id);
    assert_eq!(files.len(), 1, "the rejected upload left no orphan blob");

    // The surviving snapshot is still the winner.
    let get = client
        .get(format!("{url}/v1/sync/{sync_id}/snapshot"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id)
        .send()
        .await
        .unwrap();
    let json: serde_json::Value = get.json().await.unwrap();
    assert_eq!(BASE64.decode(json["data"].as_str().unwrap()).unwrap(), b"winner");
}

#[tokio::test]
async fn delete_snapshot_unlinks_blob() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (config, snapshot_root) = storage_under_tmp(tmp.path());
    let (url, _server, db) = start_file_backed_test_relay_with_config(config).await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let initiator = generate_device_id();
    let keys_init = TestDeviceKeys::generate(&initiator);
    let token_init = register_device(&client, &url, &sync_id, &initiator, &keys_init).await;

    let joiner = generate_device_id();
    let (token_joiner, keys_joiner) = prepare_device(&db, &sync_id, &joiner).await;

    let put = put_snapshot_signed(
        &client,
        &url,
        &sync_id,
        &initiator,
        &token_init,
        &keys_init,
        "7",
        b"pair-bootstrap".to_vec(),
        &[("X-For-Device-Id", &joiner)],
    )
    .await;
    assert_eq!(put.status(), 204);
    assert_eq!(snapshot_files(&snapshot_root, &sync_id).len(), 1);

    // The target ACK-deletes; the row and its on-disk blob both go away.
    let del =
        delete_snapshot_signed(&client, &url, &sync_id, &joiner, &token_joiner, &keys_joiner).await;
    assert_eq!(del.status(), 204);
    assert_eq!(snapshot_files(&snapshot_root, &sync_id).len(), 0, "blob unlinked on ACK-delete");

    let get = client
        .get(format!("{url}/v1/sync/{sync_id}/snapshot"))
        .header("Authorization", format!("Bearer {token_joiner}"))
        .header("X-Device-Id", &joiner)
        .send()
        .await
        .unwrap();
    assert_eq!(get.status(), 404);
}

#[tokio::test]
async fn ttl_expiry_cleanup_unlinks_blob() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (config, snapshot_root) = storage_under_tmp(tmp.path());
    let (url, _server, db, state) = start_file_backed_test_relay_with_state(config).await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let initiator = generate_device_id();
    let keys_init = TestDeviceKeys::generate(&initiator);
    let token_init = register_device(&client, &url, &sync_id, &initiator, &keys_init).await;
    let joiner = generate_device_id();
    prepare_device(&db, &sync_id, &joiner).await;

    let put = put_snapshot_signed(
        &client,
        &url,
        &sync_id,
        &initiator,
        &token_init,
        &keys_init,
        "9",
        b"expiring-pair".to_vec(),
        &[("X-Snapshot-TTL", "60"), ("X-For-Device-Id", &joiner)],
    )
    .await;
    assert_eq!(put.status(), 204);
    assert_eq!(snapshot_files(&snapshot_root, &sync_id).len(), 1);

    // Force the row past its TTL, then run one cleanup pass: the expired row is
    // deleted AND its on-disk blob is unlinked (file expiry mirrors row expiry).
    db.with_conn(|conn| {
        conn.execute(
            "UPDATE snapshots SET expires_at = ?1 WHERE sync_id = ?2",
            rusqlite::params![db::now_secs() - 1, sync_id],
        )?;
        Ok(())
    })
    .unwrap();

    prism_sync_relay::cleanup::run_cleanup(&state).await;

    assert_eq!(
        snapshot_files(&snapshot_root, &sync_id).len(),
        0,
        "expired snapshot blob unlinked by cleanup"
    );
    let remaining = db
        .with_read_conn(|conn| {
            conn.query_row(
                "SELECT COUNT(*) FROM snapshots WHERE sync_id = ?1",
                rusqlite::params![sync_id],
                |row| row.get::<_, i64>(0),
            )
        })
        .unwrap();
    assert_eq!(remaining, 0, "expired snapshot row deleted by cleanup");
}

#[tokio::test]
async fn cap_reject_writes_no_blob() {
    // The preflight cap check rejects a fresh audience BEFORE persisting bytes,
    // so a 409 too_many_targeted_snapshots never leaves an orphan blob on disk.
    let tmp = tempfile::TempDir::new().unwrap();
    let (config, snapshot_root) = storage_under_tmp(tmp.path());
    let (url, _server, db) = start_file_backed_test_relay_with_config(config).await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let initiator = generate_device_id();
    let keys_init = TestDeviceKeys::generate(&initiator);
    let token_init = register_device(&client, &url, &sync_id, &initiator, &keys_init).await;

    for i in 0..MAX_TARGETED_SNAPSHOTS_PER_GROUP {
        let joiner = generate_device_id();
        prepare_device(&db, &sync_id, &joiner).await;
        let resp = put_snapshot_signed(
            &client,
            &url,
            &sync_id,
            &initiator,
            &token_init,
            &keys_init,
            &format!("{}", 100 + i),
            b"filler".to_vec(),
            &[("X-For-Device-Id", &joiner)],
        )
        .await;
        assert_eq!(resp.status(), 204);
    }
    // The cap is full: one blob per filler audience.
    assert_eq!(
        snapshot_files(&snapshot_root, &sync_id).len() as i64,
        MAX_TARGETED_SNAPSHOTS_PER_GROUP
    );

    let overflow = generate_device_id();
    prepare_device(&db, &sync_id, &overflow).await;
    let resp = put_snapshot_signed(
        &client,
        &url,
        &sync_id,
        &initiator,
        &token_init,
        &keys_init,
        "999",
        b"one-too-many".to_vec(),
        &[("X-For-Device-Id", &overflow)],
    )
    .await;
    assert_eq!(resp.status(), 409);
    // No extra blob was written for the rejected audience.
    assert_eq!(
        snapshot_files(&snapshot_root, &sync_id).len() as i64,
        MAX_TARGETED_SNAPSHOTS_PER_GROUP,
        "a cap-rejected upload writes no blob"
    );
}

#[tokio::test]
async fn legacy_inline_snapshot_still_served_and_replaceable() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (config, snapshot_root) = storage_under_tmp(tmp.path());
    let (url, _server, db) = start_file_backed_test_relay_with_config(config).await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;

    // Seed a legacy INLINE group-wide row (bytes in `data`, no blob_ref) — the
    // shape every row had before file-backing.
    let sid = sync_id.clone();
    db.with_conn(move |conn| {
        db::upsert_snapshot(conn, &sid, 0, 5, b"legacy-inline", None, None, Some("seed"))
    })
    .unwrap();
    assert_eq!(snapshot_files(&snapshot_root, &sync_id).len(), 0, "inline row has no file");

    // GET serves it straight from the column.
    let get = client
        .get(format!("{url}/v1/sync/{sync_id}/snapshot"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id)
        .send()
        .await
        .unwrap();
    assert_eq!(get.status(), 200);
    let json: serde_json::Value = get.json().await.unwrap();
    assert_eq!(BASE64.decode(json["data"].as_str().unwrap()).unwrap(), b"legacy-inline");

    // A higher-seq file-backed PUT replaces the inline row. The old row had no
    // blob, so nothing is unlinked; the new bytes come back from disk.
    let put = put_snapshot_signed(
        &client,
        &url,
        &sync_id,
        &device_id,
        &token,
        &keys,
        "6",
        b"now-file-backed".to_vec(),
        &[],
    )
    .await;
    assert_eq!(put.status(), 204);
    assert_eq!(snapshot_files(&snapshot_root, &sync_id).len(), 1, "replacement is file-backed");

    let get2 = client
        .get(format!("{url}/v1/sync/{sync_id}/snapshot"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id)
        .send()
        .await
        .unwrap();
    let json2: serde_json::Value = get2.json().await.unwrap();
    assert_eq!(BASE64.decode(json2["data"].as_str().unwrap()).unwrap(), b"now-file-backed");
}

#[tokio::test]
async fn delete_account_removes_snapshot_dir() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (config, snapshot_root) = storage_under_tmp(tmp.path());
    let (url, _server, _db) = start_file_backed_test_relay_with_config(config).await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;

    let put = put_snapshot_signed(
        &client,
        &url,
        &sync_id,
        &device_id,
        &token,
        &keys,
        "1",
        b"group-snap".to_vec(),
        &[],
    )
    .await;
    assert_eq!(put.status(), 204);
    assert_eq!(snapshot_files(&snapshot_root, &sync_id).len(), 1);

    // The sole active admin deletes the whole group; its snapshot tree is gone.
    let path = format!("/v1/sync/{sync_id}");
    let builder = client
        .delete(format!("{url}{path}"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id);
    let del = apply_signed_headers(builder, &keys, "DELETE", &path, &sync_id, &device_id, &[])
        .send()
        .await
        .unwrap();
    assert_eq!(del.status(), 204);

    let group_dir = std::path::Path::new(&snapshot_root).join(&sync_id);
    assert!(!group_dir.exists(), "group snapshot dir removed on account delete");
}

/// PUT a snapshot with signed headers, returning the raw result so callers can
/// tolerate a connection-level error (e.g. the server closing the connection on
/// an oversize body). Most callers want [`put_snapshot_signed`].
#[allow(clippy::too_many_arguments)]
async fn try_put_snapshot_signed(
    client: &Client,
    url: &str,
    sync_id: &str,
    device_id: &str,
    token: &str,
    keys: &TestDeviceKeys,
    server_seq_at: &str,
    snapshot_data: Vec<u8>,
    extra_headers: &[(&str, &str)],
) -> reqwest::Result<reqwest::Response> {
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
}

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
    try_put_snapshot_signed(
        client,
        url,
        sync_id,
        device_id,
        token,
        keys,
        server_seq_at,
        snapshot_data,
        extra_headers,
    )
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

    // A non-target device sees the row as simply absent (404 → client maps to
    // Ok(None)). The old cross-target 403 path is gone: with per-audience rows
    // the query never returns another device's targeted snapshot, so there is
    // no row to forbid.
    let denied_resp = client
        .get(format!("{url}/v1/sync/{sync_id}/snapshot"))
        .header("Authorization", format!("Bearer {token_a}"))
        .header("X-Device-Id", &device_a_id)
        .send()
        .await
        .unwrap();
    assert_eq!(denied_resp.status(), 404, "non-target device sees no snapshot");

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
    let resp =
        put_snapshot_signed(&client, &url, &sync_id, &device_id, &token, &keys, "1", snapshot, &[])
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
    let resp =
        put_snapshot_signed(&client, &url, &sync_id, &device_id, &token, &keys, "1", snapshot, &[])
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

    // 1 MB over the cap. The body-limit layer rejects mid-stream, so depending
    // on timing the server either responds 413 or closes the connection before
    // the client finishes writing (a reqwest error). Both mean "rejected"; only
    // an accepted upload is a bug.
    let snapshot = vec![0u8; 151 * 1024 * 1024];
    assert!(snapshot.len() > MAX_SNAPSHOT_WIRE_BYTES);
    let result = try_put_snapshot_signed(
        &client,
        &url,
        &sync_id,
        &device_id,
        &token,
        &keys,
        "1",
        snapshot,
        &[],
    )
    .await;
    if let Ok(resp) = result {
        assert!(
            resp.status() == 413 || resp.status() == 400,
            "oversize snapshot should be rejected (413/400), got {}",
            resp.status()
        );
    }
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
    let del_resp =
        delete_snapshot_signed(&client, &url, &sync_id, &joiner_id, &token_joiner, &keys_joiner)
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
async fn test_delete_snapshot_by_non_target_device_returns_404() {
    // The ACK-delete is a single conditional writer scoped to the caller's own
    // targeted row. A device that is not the target of any row matches nothing,
    // so it gets 404 even while another joiner's row exists — and crucially it
    // cannot delete that other row (the old read-then-delete TOCTOU is gone).
    let (url, _server, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let initiator_id = generate_device_id();
    let keys_init = TestDeviceKeys::generate(&initiator_id);
    let token_init = register_device(&client, &url, &sync_id, &initiator_id, &keys_init).await;

    let joiner_id = generate_device_id();
    let (token_joiner, _keys_joiner) = prepare_device(&db, &sync_id, &joiner_id).await;

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
    assert_eq!(resp.status(), 404, "non-target device's ACK-delete matches no row");

    // The targeted joiner's row is untouched — the attacker could not delete it.
    let get_resp = client
        .get(format!("{url}/v1/sync/{sync_id}/snapshot"))
        .header("Authorization", format!("Bearer {token_joiner}"))
        .header("X-Device-Id", &joiner_id)
        .send()
        .await
        .unwrap();
    assert_eq!(get_resp.status(), 200, "the real target's snapshot must survive");
}

#[tokio::test]
async fn test_delete_snapshot_when_missing_returns_404() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;

    let resp = delete_snapshot_signed(&client, &url, &sync_id, &device_id, &token, &keys).await;
    assert_eq!(resp.status(), 404, "DELETE with no snapshot present should be 404");
}

// Regression: after the router split (only PUT gets the 150 MB layer,
// GET + DELETE sit under the normal 10 MiB authenticated cap), the
// bodyless methods must still function correctly even if a client
// sends a payload. Body limits are about DoS — since GET/DELETE ignore
// the body, the limit is hygiene only, not a correctness concern.
#[tokio::test]
async fn test_snapshot_get_accepts_request_with_body() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;

    // Upload a snapshot so GET can find it.
    let put_resp = put_snapshot_signed(
        &client,
        &url,
        &sync_id,
        &device_id,
        &token,
        &keys,
        "1",
        b"present".to_vec(),
        &[],
    )
    .await;
    assert_eq!(put_resp.status(), 204);

    // GET with a small body should still succeed. reqwest sets
    // Content-Length for us; axum ignores the body on GET handlers so
    // this exercises the "GET is bodyless but a client might still ship
    // bytes" hygiene path.
    let get_resp = client
        .get(format!("{url}/v1/sync/{sync_id}/snapshot"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id)
        .body(vec![0u8; 1024])
        .send()
        .await
        .unwrap();
    assert_eq!(get_resp.status(), 200, "GET must succeed regardless of body (body is ignored)",);
}

#[tokio::test]
async fn test_snapshot_delete_accepts_request_with_body() {
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
        "1",
        b"delete-me".to_vec(),
        &[("X-For-Device-Id", &joiner_id)],
    )
    .await;
    assert_eq!(put_resp.status(), 204);

    // DELETE with a body should still succeed. The signed-header
    // canonicalisation hashes an empty body, so we send a body that
    // won't match the signature of the real payload (signature is
    // still valid because it signs the empty body). The server must
    // process the DELETE regardless of the request body.
    let path = format!("/v1/sync/{sync_id}/snapshot");
    let builder = client
        .delete(format!("{url}/v1/sync/{sync_id}/snapshot"))
        .header("Authorization", format!("Bearer {token_joiner}"))
        .header("X-Device-Id", &joiner_id)
        .body(vec![0u8; 1024]);
    let resp =
        apply_signed_headers(builder, &keys_joiner, "DELETE", &path, &sync_id, &joiner_id, &[])
            .send()
            .await
            .unwrap();
    assert_eq!(resp.status(), 204, "DELETE must succeed regardless of body (body is ignored)",);
}

// ───────────────────────── Per-route timeout scoping ─────────────────────────
//
// These tests confirm that `PUT /v1/sync/{sync_id}/snapshot` is wrapped by its
// own `TimeoutLayer` with the configured `snapshot_request_timeout_secs`, and
// that the default-route timeout does NOT apply to it. The 30s production
// global timeout used to clip large snapshot uploads on slow connections,
// surfacing to users as 502 (broken pipe at cloudflared) on the pair flow.

use std::time::Duration;

/// Build a `reqwest::Body` that emits `bytes` slowly, one chunk at a time.
///
/// Signs over the full `bytes` slice (already done by `apply_signed_headers`),
/// but the wire transfer is paced so the request body extraction on the relay
/// takes long enough to exercise the timeout.
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

/// Build a Config tuned for the timeout tests below.
fn timeout_test_config(default_secs: u64, snapshot_secs: u64) -> prism_sync_relay::config::Config {
    let mut config = test_config();
    config.default_request_timeout_secs = default_secs;
    config.snapshot_request_timeout_secs = snapshot_secs;
    config
}

/// Snapshot PUT that streams the body slowly. Signs over `snapshot_data` so
/// the request is otherwise indistinguishable from a normal upload.
#[allow(clippy::too_many_arguments)]
async fn put_snapshot_with_slow_body(
    client: &Client,
    url: &str,
    sync_id: &str,
    device_id: &str,
    token: &str,
    keys: &TestDeviceKeys,
    server_seq_at: &str,
    snapshot_data: Vec<u8>,
    chunk_size: usize,
    interval: Duration,
) -> Result<reqwest::Response, reqwest::Error> {
    let path = format!("/v1/sync/{sync_id}/snapshot");
    let builder = client
        .put(format!("{url}/v1/sync/{sync_id}/snapshot"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", device_id)
        .header("X-Server-Seq-At", server_seq_at);
    apply_signed_headers(builder, keys, "PUT", &path, sync_id, device_id, &snapshot_data)
        .body(slow_body(snapshot_data, chunk_size, interval))
        .send()
        .await
}

#[tokio::test]
async fn test_snapshot_put_completes_past_default_timeout() {
    // default=1s would have killed any upload >1s under the old global timeout.
    // snapshot=10s gives this 1 MB upload enough room to finish despite the
    // slow body pacing (~1.5s wall clock here).
    let config = timeout_test_config(1, 10);
    let (url, _server, _db) = start_test_relay_with_config(config).await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;

    let snapshot = vec![0u8; 1024 * 1024]; // 1 MB
    let resp = put_snapshot_with_slow_body(
        &client,
        &url,
        &sync_id,
        &device_id,
        &token,
        &keys,
        "1",
        snapshot,
        128 * 1024, // 128 KB chunks → 8 chunks total
        Duration::from_millis(200),
    )
    .await
    .expect("slow snapshot upload should complete");

    assert_eq!(
        resp.status(),
        204,
        "snapshot PUT should succeed within its own (longer) timeout window \
         even when the upload exceeds the default 1s timeout"
    );
}

#[tokio::test]
async fn test_snapshot_put_times_out_at_its_own_ceiling() {
    // snapshot=2s; body paced to take ~5s. Expect 408 (or the client-side
    // equivalent of "server closed mid-write"). We accept either a clean 408
    // or a client-side connection error, because once the server drops the
    // TCP socket, reqwest may surface it as a transport error rather than a
    // response.
    let config = timeout_test_config(1, 2);
    let (url, _server, _db) = start_test_relay_with_config(config).await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;

    let snapshot = vec![0u8; 512 * 1024]; // 512 KB
    let result = put_snapshot_with_slow_body(
        &client,
        &url,
        &sync_id,
        &device_id,
        &token,
        &keys,
        "1",
        snapshot,
        32 * 1024,                  // 32 KB chunks → 16 chunks
        Duration::from_millis(350), // ~5.6s total
    )
    .await;

    match result {
        Ok(resp) => assert_eq!(
            resp.status(),
            408,
            "slow snapshot exceeding its own timeout should be rejected with 408"
        ),
        Err(err) => assert!(
            err.is_request() || err.is_body() || err.is_timeout() || err.is_connect(),
            "expected a client-side transport error when server drops the socket; got: {err}"
        ),
    }
}

#[tokio::test]
async fn test_snapshot_uses_its_own_timeout_not_the_default() {
    // Sanity check that the two scopes are genuinely independent: pin
    // default to 1s and snapshot to 30s, then upload a 256 KB body paced to
    // take ~2.5s. Default would kill it, snapshot allows it.
    let config = timeout_test_config(1, 30);
    let (url, _server, _db) = start_test_relay_with_config(config).await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;

    let snapshot = vec![0u8; 256 * 1024];
    let resp = put_snapshot_with_slow_body(
        &client,
        &url,
        &sync_id,
        &device_id,
        &token,
        &keys,
        "1",
        snapshot,
        32 * 1024,
        Duration::from_millis(350),
    )
    .await
    .expect("upload should complete under the snapshot timeout");

    assert_eq!(resp.status(), 204);
}

#[tokio::test]
async fn test_non_snapshot_route_still_respects_default_timeout() {
    // Inverse of `test_snapshot_uses_its_own_timeout_not_the_default`. If a
    // future refactor accidentally moved /changes into the snapshot sub-router,
    // the snapshot timeout (5 min in production, 30s here) would shadow the
    // default and this test would catch it.
    //
    // default=2s, snapshot=30s. Slow-stream a /changes PUT that takes ~3.5s.
    // Expect 408 from the default scope OR a client-side transport error
    // (server drops mid-write).
    let config = timeout_test_config(2, 30);
    let (url, _server, _db) = start_test_relay_with_config(config).await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;

    // Body content doesn't matter — auth will accept the signature over the
    // bytes we sign, and the handler would reject malformed JSON normally,
    // but the timeout fires during body buffering before the handler runs.
    let body_bytes = vec![b'{'; 64 * 1024]; // 64 KB of garbage
    let path = format!("/v1/sync/{sync_id}/changes");
    let builder = client
        .put(format!("{url}{path}"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id)
        .header("Content-Type", "application/json");
    let signed =
        apply_signed_headers(builder, &keys, "PUT", &path, &sync_id, &device_id, &body_bytes);
    // Stream the body at 8 KB / 450 ms → ~3.6s total, well past the 2s default.
    let result =
        signed.body(slow_body(body_bytes, 8 * 1024, Duration::from_millis(450))).send().await;

    match result {
        Ok(resp) => assert_eq!(
            resp.status(),
            408,
            "slow /changes PUT should be rejected by the default timeout, \
             not allowed to run to completion under the snapshot's wider scope"
        ),
        Err(err) => assert!(
            err.is_request() || err.is_body() || err.is_timeout() || err.is_connect(),
            "expected client-side transport error when server drops mid-write; got: {err}"
        ),
    }
}

// ───────────────────── put_snapshot seq-ordering race ─────────────────────
//
// Repros for the `WHERE excluded.server_seq_at > snapshots.server_seq_at OR
// snapshots.expires_at < unixepoch()` guard added to `db::upsert_snapshot`,
// plus the `AppError::SnapshotStale` mapping in `do_put_snapshot`.
//
// Policy: equal-seq is treated as stale (`>` not `>=`) because we want
// "strictly newer wins". Concurrent uploaders racing on the same
// `server_seq_at` thus see exactly one winner — the row content is
// deterministic regardless of arrival order.

/// Helper that reads a snapshot back as the uploader and returns the parsed
/// JSON body. Used by the race tests to verify which payload "won".
async fn fetch_snapshot_json(
    client: &Client,
    url: &str,
    sync_id: &str,
    device_id: &str,
    token: &str,
) -> serde_json::Value {
    let resp = client
        .get(format!("{url}/v1/sync/{sync_id}/snapshot"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", device_id)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "snapshot fetch should succeed");
    resp.json().await.unwrap()
}

#[tokio::test]
async fn put_snapshot_stale_seq_returns_conflict() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;

    // First upload at server_seq_at=100 — fresh insert.
    let resp = put_snapshot_signed(
        &client,
        &url,
        &sync_id,
        &device_id,
        &token,
        &keys,
        "100",
        b"fresh-data".to_vec(),
        &[],
    )
    .await;
    assert_eq!(resp.status(), 204, "first upload should succeed");

    // Try to upload server_seq_at=42 (stale).
    let resp = put_snapshot_signed(
        &client,
        &url,
        &sync_id,
        &device_id,
        &token,
        &keys,
        "42",
        b"stale-data".to_vec(),
        &[],
    )
    .await;
    assert_eq!(resp.status(), 409, "stale upload should return Conflict");

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "stale_snapshot_seq", "structured error key");
    assert_eq!(
        body["current_server_seq_at"].as_i64().unwrap(),
        100,
        "must report the current (newer) seq so the client can advance"
    );
    // The field's presence (vs. omission) is the wire signal that
    // distinguishes "existing snapshot is untargeted" from "malformed
    // body" on the client side, so it must be in the 409 even when
    // the existing snapshot was untargeted.
    assert!(
        body.get("current_target_device_id").is_some(),
        "current_target_device_id field must be present"
    );
    assert!(
        body["current_target_device_id"].is_null(),
        "existing snapshot was untargeted, so the field must be JSON null: {body:?}"
    );

    // Verify GET returns the fresh snapshot, not the stale one.
    let snapshot = fetch_snapshot_json(&client, &url, &sync_id, &device_id, &token).await;
    assert_eq!(snapshot["server_seq_at"].as_i64().unwrap(), 100);
    let decoded = BASE64.decode(snapshot["data"].as_str().unwrap()).unwrap();
    assert_eq!(decoded.as_slice(), b"fresh-data");
}

#[tokio::test]
async fn put_snapshot_equal_seq_cross_uploader_returns_conflict() {
    // Equal-seq cross-uploader writes still lose to the existing row.
    let (url, _server, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let device_a = generate_device_id();
    let keys_a = TestDeviceKeys::generate(&device_a);
    let token_a = register_device(&client, &url, &sync_id, &device_a, &keys_a).await;

    let device_b = generate_device_id();
    let (token_b, keys_b) = prepare_device(&db, &sync_id, &device_b).await;

    let resp = put_snapshot_signed(
        &client,
        &url,
        &sync_id,
        &device_a,
        &token_a,
        &keys_a,
        "100",
        b"data-from-a".to_vec(),
        &[],
    )
    .await;
    assert_eq!(resp.status(), 204);

    // Same seq, different uploader.
    let resp = put_snapshot_signed(
        &client,
        &url,
        &sync_id,
        &device_b,
        &token_b,
        &keys_b,
        "100",
        b"data-from-b".to_vec(),
        &[],
    )
    .await;
    assert_eq!(resp.status(), 409, "equal seq cross-uploader is still stale");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "stale_snapshot_seq");
    assert_eq!(body["current_server_seq_at"].as_i64().unwrap(), 100);
    assert!(
        body.get("current_target_device_id").is_some(),
        "current_target_device_id field must be present"
    );
    assert!(
        body["current_target_device_id"].is_null(),
        "untargeted existing snapshot → JSON null target"
    );

    // Original payload preserved.
    let snapshot = fetch_snapshot_json(&client, &url, &sync_id, &device_a, &token_a).await;
    let decoded = BASE64.decode(snapshot["data"].as_str().unwrap()).unwrap();
    assert_eq!(decoded.as_slice(), b"data-from-a");
}

#[tokio::test]
async fn put_snapshot_equal_seq_same_uploader_replaces() {
    // Pair retries reuse the uploader and seq but target a fresh joiner.
    let (url, _server, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let initiator = generate_device_id();
    let keys_init = TestDeviceKeys::generate(&initiator);
    let token_init = register_device(&client, &url, &sync_id, &initiator, &keys_init).await;

    let joiner_old = generate_device_id();
    let (_token_old, _keys_old) = prepare_device(&db, &sync_id, &joiner_old).await;
    let joiner_new = generate_device_id();
    let (token_new, _keys_new) = prepare_device(&db, &sync_id, &joiner_new).await;

    // First pairing attempt targets joiner_old.
    let resp = put_snapshot_signed(
        &client,
        &url,
        &sync_id,
        &initiator,
        &token_init,
        &keys_init,
        "100",
        b"first-attempt-snapshot".to_vec(),
        &[("X-For-Device-Id", &joiner_old)],
    )
    .await;
    assert_eq!(resp.status(), 204);

    // Retry targets the fresh joiner at the same seq.
    let resp = put_snapshot_signed(
        &client,
        &url,
        &sync_id,
        &initiator,
        &token_init,
        &keys_init,
        "100",
        b"retry-snapshot".to_vec(),
        &[("X-For-Device-Id", &joiner_new)],
    )
    .await;
    assert_eq!(resp.status(), 204, "same uploader, same seq, fresh joiner target must replace");

    // The new joiner can fetch, so the stored target changed too.
    let snapshot = fetch_snapshot_json(&client, &url, &sync_id, &joiner_new, &token_new).await;
    let decoded = BASE64.decode(snapshot["data"].as_str().unwrap()).unwrap();
    assert_eq!(decoded.as_slice(), b"retry-snapshot");
}

#[tokio::test]
async fn put_snapshot_different_audiences_coexist() {
    // Two concurrent pairings target different joiners. With per-audience rows
    // each lands in its own row regardless of seq order — the lower-seq second
    // upload is NOT stale against the first (different audience), so it is a
    // fresh insert, not a 409. Both joiners can then read their own snapshot.
    // This is the cross-target 403/409 path disappearing.
    let (url, _server, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let initiator_id = generate_device_id();
    let keys_init = TestDeviceKeys::generate(&initiator_id);
    let token_init = register_device(&client, &url, &sync_id, &initiator_id, &keys_init).await;

    let joiner_a = generate_device_id();
    let (token_a, _keys_a) = prepare_device(&db, &sync_id, &joiner_a).await;
    let joiner_b = generate_device_id();
    let (token_b, _keys_b) = prepare_device(&db, &sync_id, &joiner_b).await;

    // 1. seq=100 targeting joiner-A.
    let resp = put_snapshot_signed(
        &client,
        &url,
        &sync_id,
        &initiator_id,
        &token_init,
        &keys_init,
        "100",
        b"snapshot-for-A".to_vec(),
        &[("X-For-Device-Id", &joiner_a)],
    )
    .await;
    assert_eq!(resp.status(), 204, "first targeted upload should succeed");

    // 2. seq=42 targeting joiner-B — a different audience, so it does NOT
    //    contend with A's row even though 42 < 100. Fresh insert, not 409.
    let resp = put_snapshot_signed(
        &client,
        &url,
        &sync_id,
        &initiator_id,
        &token_init,
        &keys_init,
        "42",
        b"snapshot-for-B".to_vec(),
        &[("X-For-Device-Id", &joiner_b)],
    )
    .await;
    assert_eq!(resp.status(), 204, "different-audience upload must coexist, not 409");

    // Each joiner reads its own targeted snapshot.
    let snap_a = fetch_snapshot_json(&client, &url, &sync_id, &joiner_a, &token_a).await;
    assert_eq!(snap_a["server_seq_at"].as_i64().unwrap(), 100);
    assert_eq!(BASE64.decode(snap_a["data"].as_str().unwrap()).unwrap(), b"snapshot-for-A");

    let snap_b = fetch_snapshot_json(&client, &url, &sync_id, &joiner_b, &token_b).await;
    assert_eq!(snap_b["server_seq_at"].as_i64().unwrap(), 42);
    assert_eq!(BASE64.decode(snap_b["data"].as_str().unwrap()).unwrap(), b"snapshot-for-B");
}

#[tokio::test]
async fn put_snapshot_stale_within_audience_includes_target_in_409_body() {
    // A stale upload for the SAME audience still loses, and the 409 body must
    // carry that audience's target so the engine routes it through its
    // suppression matrix.
    let (url, _server, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let initiator_id = generate_device_id();
    let keys_init = TestDeviceKeys::generate(&initiator_id);
    let token_init = register_device(&client, &url, &sync_id, &initiator_id, &keys_init).await;

    let joiner = generate_device_id();
    let (_token_j, _keys_j) = prepare_device(&db, &sync_id, &joiner).await;

    // seq=100 targeting the joiner.
    let resp = put_snapshot_signed(
        &client,
        &url,
        &sync_id,
        &initiator_id,
        &token_init,
        &keys_init,
        "100",
        b"snapshot-v1".to_vec(),
        &[("X-For-Device-Id", &joiner)],
    )
    .await;
    assert_eq!(resp.status(), 204);

    // seq=42 targeting the SAME joiner — stale within that audience.
    let resp = put_snapshot_signed(
        &client,
        &url,
        &sync_id,
        &initiator_id,
        &token_init,
        &keys_init,
        "42",
        b"snapshot-v0".to_vec(),
        &[("X-For-Device-Id", &joiner)],
    )
    .await;
    assert_eq!(resp.status(), 409, "stale same-audience upload must return Conflict");

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "stale_snapshot_seq");
    assert_eq!(body["current_server_seq_at"].as_i64().unwrap(), 100);
    assert_eq!(
        body["current_target_device_id"].as_str(),
        Some(joiner.as_str()),
        "must report this audience's existing target (body = {body})"
    );
}

#[tokio::test]
async fn put_snapshot_replaces_expired_high_seq() {
    // The WHERE leg `OR snapshots.expires_at < unixepoch()` is what keeps an
    // expired high-seq row from blocking a fresh lower-seq upload. Without it
    // the new snapshot would 409 until the cleanup job ran.
    let (url, _server, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;

    // Upload server_seq_at=100 with a TTL header (any TTL will do — we force
    // expiry directly afterwards to make the test deterministic instead of
    // sleeping).
    let resp = put_snapshot_signed(
        &client,
        &url,
        &sync_id,
        &device_id,
        &token,
        &keys,
        "100",
        b"old-high-seq".to_vec(),
        &[("X-Snapshot-TTL", "60")],
    )
    .await;
    assert_eq!(resp.status(), 204);

    // Force the row to look expired. Avoids a real `tokio::time::sleep`.
    db.with_conn(|conn| {
        conn.execute(
            "UPDATE snapshots SET expires_at = ?1 WHERE sync_id = ?2",
            rusqlite::params![db::now_secs() - 1, sync_id],
        )?;
        Ok(())
    })
    .expect("force snapshot expiry");

    // Lower seq (=42) must succeed because the high-seq snapshot is expired.
    let resp = put_snapshot_signed(
        &client,
        &url,
        &sync_id,
        &device_id,
        &token,
        &keys,
        "42",
        b"fresh-low-seq".to_vec(),
        &[],
    )
    .await;
    assert_eq!(resp.status(), 204, "fresh upload should succeed over expired high-seq");

    let snapshot = fetch_snapshot_json(&client, &url, &sync_id, &device_id, &token).await;
    assert_eq!(snapshot["server_seq_at"].as_i64().unwrap(), 42);
    let decoded = BASE64.decode(snapshot["data"].as_str().unwrap()).unwrap();
    assert_eq!(decoded.as_slice(), b"fresh-low-seq");
}

#[tokio::test]
async fn put_snapshot_concurrent_higher_seq_wins() {
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;

    // Clone everything per task. `TestDeviceKeys` is not `Clone`, so we sign
    // both requests sequentially before racing — the actual relay PUTs are
    // what get raced, not the signature build.
    let client_a = client.clone();
    let client_b = client.clone();
    let url_a = url.clone();
    let url_b = url.clone();
    let sync_id_a = sync_id.clone();
    let sync_id_b = sync_id.clone();
    let device_id_a = device_id.clone();
    let device_id_b = device_id.clone();
    let token_a = token.clone();
    let token_b = token.clone();
    let path = format!("/v1/sync/{sync_id}/snapshot");

    let body_100 = b"hundred".to_vec();
    let req_100 = client_a
        .put(format!("{url_a}{path}"))
        .header("Authorization", format!("Bearer {token_a}"))
        .header("X-Device-Id", &device_id_a)
        .header("X-Server-Seq-At", "100");
    let req_100 =
        apply_signed_headers(req_100, &keys, "PUT", &path, &sync_id_a, &device_id_a, &body_100)
            .body(body_100);

    let body_42 = b"forty-two".to_vec();
    let req_42 = client_b
        .put(format!("{url_b}{path}"))
        .header("Authorization", format!("Bearer {token_b}"))
        .header("X-Device-Id", &device_id_b)
        .header("X-Server-Seq-At", "42");
    let req_42 =
        apply_signed_headers(req_42, &keys, "PUT", &path, &sync_id_b, &device_id_b, &body_42)
            .body(body_42);

    // Issue both PUTs concurrently. Whichever order they hit SQLite, the WHERE
    // guard ensures the higher-seq payload is what's stored.
    //
    // We don't assert specific status codes here because there are two valid
    // outcomes depending on SQLite's serialisation:
    //
    //   - seq=100 lands first, seq=42 lands second → 204 then 409 (the 42
    //     upload is stale w.r.t. the already-stored 100).
    //   - seq=42 lands first, seq=100 lands second → 204 then 204 (strictly
    //     newer; the upsert overwrites the older row legitimately).
    //
    // What matters for the race-correctness invariant is the *final stored
    // state*: regardless of who got accepted, the highest seq must win and
    // its payload must be on disk. The "stale" 409 is exercised
    // deterministically by `put_snapshot_stale_seq_returns_conflict` above
    // — this test specifically guards the convergence property.
    let (r1, r2) = tokio::join!(req_100.send(), req_42.send());
    let r1 = r1.unwrap();
    let r2 = r2.unwrap();
    let statuses = [r1.status().as_u16(), r2.status().as_u16()];
    assert!(
        statuses.iter().all(|s| *s == 204 || *s == 409),
        "expected only 204 or 409 outcomes; got {statuses:?}"
    );
    assert!(statuses.contains(&204), "at least one upload should have succeeded; got {statuses:?}");

    let snapshot = fetch_snapshot_json(&client, &url, &sync_id, &device_id, &token).await;
    assert_eq!(
        snapshot["server_seq_at"].as_i64().unwrap(),
        100,
        "higher seq must win regardless of arrival order"
    );
    let decoded = BASE64.decode(snapshot["data"].as_str().unwrap()).unwrap();
    assert_eq!(decoded.as_slice(), b"hundred");
}

// ───────────────────── per-audience rows + resource bounds ─────────────────

#[tokio::test]
async fn concurrent_pairing_snapshots_are_independent() {
    // Full concurrent-pairing route walk: an initiator pairs two joiners at
    // once. PUT B@100 and PUT E@101 both succeed (separate audiences), B GETs
    // its own row, E ACK-deletes only E's row, and B's row still reads 200.
    // The displaced-joiner-bricking class is gone.
    let (url, _server, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let initiator_id = generate_device_id();
    let keys_init = TestDeviceKeys::generate(&initiator_id);
    let token_init = register_device(&client, &url, &sync_id, &initiator_id, &keys_init).await;

    let joiner_b = generate_device_id();
    let (token_b, _keys_b) = prepare_device(&db, &sync_id, &joiner_b).await;
    let joiner_e = generate_device_id();
    let (token_e, keys_e) = prepare_device(&db, &sync_id, &joiner_e).await;

    let put_b = put_snapshot_signed(
        &client,
        &url,
        &sync_id,
        &initiator_id,
        &token_init,
        &keys_init,
        "100",
        b"for-B".to_vec(),
        &[("X-For-Device-Id", &joiner_b)],
    )
    .await;
    assert_eq!(put_b.status(), 204, "PUT B@100 succeeds");

    let put_e = put_snapshot_signed(
        &client,
        &url,
        &sync_id,
        &initiator_id,
        &token_init,
        &keys_init,
        "101",
        b"for-E".to_vec(),
        &[("X-For-Device-Id", &joiner_e)],
    )
    .await;
    assert_eq!(put_e.status(), 204, "PUT E@101 succeeds — no clobber of B's row");

    // B reads its own snapshot.
    let snap_b = fetch_snapshot_json(&client, &url, &sync_id, &joiner_b, &token_b).await;
    assert_eq!(snap_b["server_seq_at"].as_i64().unwrap(), 100);
    assert_eq!(BASE64.decode(snap_b["data"].as_str().unwrap()).unwrap(), b"for-B");

    // E ACK-deletes — removes only E's row.
    let del_e = delete_snapshot_signed(&client, &url, &sync_id, &joiner_e, &token_e, &keys_e).await;
    assert_eq!(del_e.status(), 204, "E ACK-deletes its own row");

    // B's row survives E's ACK-delete.
    let get_b = client
        .get(format!("{url}/v1/sync/{sync_id}/snapshot"))
        .header("Authorization", format!("Bearer {token_b}"))
        .header("X-Device-Id", &joiner_b)
        .send()
        .await
        .unwrap();
    assert_eq!(get_b.status(), 200, "B's snapshot must survive E's ACK-delete");
    let json: serde_json::Value = get_b.json().await.unwrap();
    assert_eq!(BASE64.decode(json["data"].as_str().unwrap()).unwrap(), b"for-B");
}

#[tokio::test]
async fn group_wide_only_group_has_no_ack_shortcut() {
    // A group-wide (untargeted) snapshot is not ACK-deletable: DELETE from any
    // device matches no targeted row, so it returns 404 and the row survives to
    // expire on its TTL. This keeps a device from short-circuiting TTL cleanup.
    let (url, _server, _db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;

    // Group-wide upload (no X-For-Device-Id).
    let put = put_snapshot_signed(
        &client,
        &url,
        &sync_id,
        &device_id,
        &token,
        &keys,
        "5",
        b"group-wide".to_vec(),
        &[],
    )
    .await;
    assert_eq!(put.status(), 204);

    let del = delete_snapshot_signed(&client, &url, &sync_id, &device_id, &token, &keys).await;
    assert_eq!(del.status(), 404, "group-wide rows are not ACK-deletable");

    // Still present.
    let get = client
        .get(format!("{url}/v1/sync/{sync_id}/snapshot"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id)
        .send()
        .await
        .unwrap();
    assert_eq!(get.status(), 200, "group-wide snapshot must survive a DELETE attempt");
}

#[tokio::test]
async fn targeted_snapshot_cap_rejects_new_audience() {
    // The relay caps concurrent unexpired targeted rows per group. Filling the
    // cap then targeting a fresh joiner yields 409 too_many_targeted_snapshots;
    // re-uploading to an existing audience still succeeds (no growth).
    let (url, _server, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let initiator_id = generate_device_id();
    let keys_init = TestDeviceKeys::generate(&initiator_id);
    let token_init = register_device(&client, &url, &sync_id, &initiator_id, &keys_init).await;

    // Fill the cap with distinct targeted audiences.
    let mut joiners = Vec::new();
    for i in 0..MAX_TARGETED_SNAPSHOTS_PER_GROUP {
        let joiner = generate_device_id();
        prepare_device(&db, &sync_id, &joiner).await;
        let resp = put_snapshot_signed(
            &client,
            &url,
            &sync_id,
            &initiator_id,
            &token_init,
            &keys_init,
            &format!("{}", 100 + i),
            b"cap-filler".to_vec(),
            &[("X-For-Device-Id", &joiner)],
        )
        .await;
        assert_eq!(resp.status(), 204, "filler upload {i} should succeed");
        joiners.push(joiner);
    }

    // One more distinct audience is rejected.
    let overflow_joiner = generate_device_id();
    prepare_device(&db, &sync_id, &overflow_joiner).await;
    let resp = put_snapshot_signed(
        &client,
        &url,
        &sync_id,
        &initiator_id,
        &token_init,
        &keys_init,
        "999",
        b"one-too-many".to_vec(),
        &[("X-For-Device-Id", &overflow_joiner)],
    )
    .await;
    assert_eq!(resp.status(), 409, "a new audience beyond the cap must be rejected");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "too_many_targeted_snapshots");
    assert_eq!(body["max"].as_i64().unwrap(), MAX_TARGETED_SNAPSHOTS_PER_GROUP);

    // Re-uploading to an EXISTING audience (higher seq) still succeeds — it
    // updates a row in place rather than adding one.
    let resp = put_snapshot_signed(
        &client,
        &url,
        &sync_id,
        &initiator_id,
        &token_init,
        &keys_init,
        "200",
        b"in-place-update".to_vec(),
        &[("X-For-Device-Id", &joiners[0])],
    )
    .await;
    assert_eq!(resp.status(), 204, "updating an existing audience must not trip the cap");
}

#[tokio::test]
async fn targeted_cap_counts_only_other_unexpired_audiences() {
    // The cap counts unexpired audiences OTHER than the caller's, so the live
    // unexpired total can never exceed the cap. Fill the cap, expire one row,
    // let a fresh joiner take the freed slot, then re-upload to the expired
    // audience: that refresh is rejected because four other audiences are now
    // unexpired — the row can't come back to make five.
    let (url, _server, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let initiator_id = generate_device_id();
    let keys_init = TestDeviceKeys::generate(&initiator_id);
    let token_init = register_device(&client, &url, &sync_id, &initiator_id, &keys_init).await;

    // Fill the cap with distinct targeted audiences.
    let mut joiners = Vec::new();
    for i in 0..MAX_TARGETED_SNAPSHOTS_PER_GROUP {
        let joiner = generate_device_id();
        prepare_device(&db, &sync_id, &joiner).await;
        let resp = put_snapshot_signed(
            &client,
            &url,
            &sync_id,
            &initiator_id,
            &token_init,
            &keys_init,
            &format!("{}", 100 + i),
            b"cap-filler".to_vec(),
            &[("X-For-Device-Id", &joiner)],
        )
        .await;
        assert_eq!(resp.status(), 204, "filler upload {i} should succeed");
        joiners.push(joiner);
    }

    // Expire the first audience's row directly.
    let expired_joiner = joiners[0].clone();
    db.with_conn(|conn| {
        conn.execute(
            "UPDATE snapshots SET expires_at = ?1 WHERE sync_id = ?2 AND target_device_id = ?3",
            rusqlite::params![db::now_secs() - 10, sync_id, expired_joiner],
        )?;
        Ok(())
    })
    .unwrap();

    // A fresh joiner now fits in the slot freed by the expired row.
    let fresh_joiner = generate_device_id();
    prepare_device(&db, &sync_id, &fresh_joiner).await;
    let resp = put_snapshot_signed(
        &client,
        &url,
        &sync_id,
        &initiator_id,
        &token_init,
        &keys_init,
        "500",
        b"fills-freed-slot".to_vec(),
        &[("X-For-Device-Id", &fresh_joiner)],
    )
    .await;
    assert_eq!(resp.status(), 204, "a fresh audience may reclaim an expired slot");

    // Re-uploading to the now-expired audience is rejected: the four other
    // audiences are unexpired, so refreshing this one would make five.
    let resp = put_snapshot_signed(
        &client,
        &url,
        &sync_id,
        &initiator_id,
        &token_init,
        &keys_init,
        "501",
        b"would-be-fifth".to_vec(),
        &[("X-For-Device-Id", &expired_joiner)],
    )
    .await;
    assert_eq!(resp.status(), 409, "refreshing an expired audience can't exceed the cap");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "too_many_targeted_snapshots");
}

#[tokio::test]
async fn targeted_upload_without_ttl_gets_default_ttl() {
    // A targeted upload with no X-Snapshot-TTL is given the relay default TTL
    // so it cannot live forever; a group-wide upload keeps no default expiry.
    let (url, _server, db) = start_test_relay().await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let initiator_id = generate_device_id();
    let keys_init = TestDeviceKeys::generate(&initiator_id);
    let token_init = register_device(&client, &url, &sync_id, &initiator_id, &keys_init).await;

    let joiner = generate_device_id();
    prepare_device(&db, &sync_id, &joiner).await;

    // Targeted, no TTL header.
    let resp = put_snapshot_signed(
        &client,
        &url,
        &sync_id,
        &initiator_id,
        &token_init,
        &keys_init,
        "7",
        b"targeted".to_vec(),
        &[("X-For-Device-Id", &joiner)],
    )
    .await;
    assert_eq!(resp.status(), 204);

    // Group-wide, no TTL header.
    let resp = put_snapshot_signed(
        &client,
        &url,
        &sync_id,
        &initiator_id,
        &token_init,
        &keys_init,
        "8",
        b"group-wide".to_vec(),
        &[],
    )
    .await;
    assert_eq!(resp.status(), 204);

    db.with_conn(|conn| {
        let now = db::now_secs();
        let targeted_expiry: Option<i64> = conn.query_row(
            "SELECT expires_at FROM snapshots WHERE sync_id = ?1 AND target_device_id = ?2",
            rusqlite::params![sync_id, joiner],
            |row| row.get(0),
        )?;
        let targeted_expiry = targeted_expiry.expect("targeted row must have a default TTL");
        assert!(
            targeted_expiry >= now + DEFAULT_TARGETED_SNAPSHOT_TTL_SECS - 60
                && targeted_expiry <= now + DEFAULT_TARGETED_SNAPSHOT_TTL_SECS + 60,
            "targeted default TTL should be ~{DEFAULT_TARGETED_SNAPSHOT_TTL_SECS}s out, got {}",
            targeted_expiry - now
        );

        let group_wide_expiry: Option<i64> = conn.query_row(
            "SELECT expires_at FROM snapshots WHERE sync_id = ?1 AND target_device_id IS NULL",
            rusqlite::params![sync_id],
            |row| row.get(0),
        )?;
        assert!(group_wide_expiry.is_none(), "group-wide upload keeps no default TTL");
        Ok(())
    })
    .expect("inspect stored snapshot expiries");
}

// ───────────────── Phase 0: persistent-storage safety ─────────────────
//
// The startup storage gate decides, once, whether snapshot bytes go to a file
// or stay inline in SQLite. An unusable root must either refuse startup (when
// the operator explicitly demanded file backing) or retain inline writes — it
// must never attempt a file-backed write against a bad root, because the row
// would commit while its bytes were never durably stored.

/// A canonical absolute root enables file backing, and the resolved path is the
/// canonicalized root the routes will join against.
#[tokio::test]
async fn valid_absolute_root_enables_file_backing() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (config, snapshot_root) = storage_under_tmp(tmp.path());
    let (_url, _server, _db, state) = start_file_backed_test_relay_with_state(config).await;

    assert!(
        state.snapshot_storage.is_file_backed(),
        "an absolute, writable, canonical root must enable file backing"
    );
    assert_eq!(
        state.snapshot_storage.root().unwrap(),
        std::path::Path::new(&snapshot_root),
        "resolved root is the canonicalized snapshot directory"
    );
}

/// A relative storage root downgrades to inline writes: the PUT still succeeds
/// (old clients keep working) and the row carries its bytes, so no snapshot row
/// can reference a blob that was never written.
#[tokio::test]
async fn relative_storage_root_falls_back_to_inline_writes() {
    let mut config = test_config();
    // A relative path resolves under the process CWD — exactly the ephemeral
    // container case the gate exists to refuse.
    config.media_storage_path = "data/relative-media-must-not-be-used".to_string();

    let (url, _server, db) = start_test_relay_with_config(config).await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;

    let payload = b"inline-fallback-payload".to_vec();
    let put = put_snapshot_signed(
        &client,
        &url,
        &sync_id,
        &device_id,
        &token,
        &keys,
        "3",
        payload.clone(),
        &[],
    )
    .await;
    assert_eq!(put.status(), 204, "inline fallback keeps single PUT working");

    // The row is inline: no blob reference, bytes present in `data`.
    let (blob_ref, inline_len): (Option<String>, i64) = db
        .with_read_conn(|conn| {
            conn.query_row(
                "SELECT blob_ref, LENGTH(data) FROM snapshots WHERE sync_id = ?1",
                rusqlite::params![sync_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
        })
        .unwrap();
    assert!(blob_ref.is_none(), "no blob reference may be written on a bad root");
    assert_eq!(inline_len, payload.len() as i64, "bytes are stored inline");

    // And the snapshot round-trips for the downloading device.
    let get = client
        .get(format!("{url}/v1/sync/{sync_id}/snapshot"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id)
        .send()
        .await
        .unwrap();
    assert_eq!(get.status(), 200);
    let body: serde_json::Value = get.json().await.unwrap();
    let decoded = BASE64.decode(body["data"].as_str().unwrap()).unwrap();
    assert_eq!(decoded, payload, "inline fallback round-trips byte-identically");
}

/// A published file-backed row whose blob has vanished — a partial restore, a
/// lost volume, or a manual delete — reads as the SAME snapshot-absent response
/// as no row at all, counts one bounded metric, and never becomes a generic 500
/// that a client would retry in a loop.
#[tokio::test]
async fn missing_published_blob_reads_as_snapshot_absent_with_metric() {
    use std::sync::atomic::Ordering;

    let tmp = tempfile::TempDir::new().unwrap();
    let (config, snapshot_root) = storage_under_tmp(tmp.path());
    let (url, _server, db, state) = start_file_backed_test_relay_with_state(config).await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;

    let put = put_snapshot_signed(
        &client,
        &url,
        &sync_id,
        &device_id,
        &token,
        &keys,
        "11",
        b"will-vanish".to_vec(),
        &[],
    )
    .await;
    assert_eq!(put.status(), 204);
    let files = snapshot_files(&snapshot_root, &sync_id);
    assert_eq!(files.len(), 1);
    assert_eq!(state.metrics.snapshots_missing_blob.load(Ordering::Relaxed), 0);

    // Simulate the lost blob while the SQLite row survives (the exact
    // SQLite-only restore the backup docs must warn about).
    std::fs::remove_file(&files[0]).unwrap();
    let row_still_there: i64 = db
        .with_read_conn(|conn| {
            conn.query_row(
                "SELECT COUNT(*) FROM snapshots WHERE sync_id = ?1",
                rusqlite::params![sync_id],
                |row| row.get(0),
            )
        })
        .unwrap();
    assert_eq!(row_still_there, 1, "the row outlives its blob");

    let get = client
        .get(format!("{url}/v1/sync/{sync_id}/snapshot"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id)
        .send()
        .await
        .unwrap();
    assert_eq!(get.status(), 404, "missing blob degrades to snapshot-absent, not 500");
    assert_eq!(
        state.metrics.snapshots_missing_blob.load(Ordering::Relaxed),
        1,
        "exactly one bounded observability increment per failed read"
    );

    // Repeated reads stay bounded: still snapshot-absent, still no 500.
    let again = client
        .get(format!("{url}/v1/sync/{sync_id}/snapshot"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id)
        .send()
        .await
        .unwrap();
    assert_eq!(again.status(), 404);
}

/// A symlinked group directory is refused outright: the relay must never write
/// snapshot bytes through a link planted inside the snapshot root.
#[cfg(unix)]
#[tokio::test]
async fn symlinked_group_dir_is_refused_by_put() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (config, snapshot_root) = storage_under_tmp(tmp.path());
    let outside = tmp.path().join("outside-target");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::create_dir_all(&snapshot_root).unwrap();

    let (url, _server, db) = start_file_backed_test_relay_with_config(config).await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;

    std::os::unix::fs::symlink(&outside, std::path::Path::new(&snapshot_root).join(&sync_id))
        .unwrap();

    // No `X-For-Device-Id`, so the write path is reached before any cap check.
    let put = put_snapshot_signed(
        &client,
        &url,
        &sync_id,
        &device_id,
        &token,
        &keys,
        "13",
        b"must-not-escape".to_vec(),
        &[],
    )
    .await;
    assert_eq!(put.status(), 500, "symlinked group directory is refused");

    assert!(
        std::fs::read_dir(&outside).unwrap().next().is_none(),
        "no bytes may be written through the planted symlink"
    );
    let rows: i64 = db
        .with_read_conn(|conn| {
            conn.query_row(
                "SELECT COUNT(*) FROM snapshots WHERE sync_id = ?1",
                rusqlite::params![sync_id],
                |row| row.get(0),
            )
        })
        .unwrap();
    assert_eq!(rows, 0, "a rejected write publishes no row");
}

#[tokio::test]
async fn default_absolute_root_keeps_put_inline_and_upload_routes_dark() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (mut config, root) = storage_under_tmp(tmp.path());
    config.snapshot_upload.enabled = true;
    let (url, _server, db, state) = start_test_relay_with_state(config).await;
    assert!(!state.snapshot_storage.is_file_backed());
    assert!(!std::path::Path::new(&root).exists());
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;
    let payload = b"legacy-inline".to_vec();
    let put = put_snapshot_signed(
        &client,
        &url,
        &sync_id,
        &device_id,
        &token,
        &keys,
        "1",
        payload.clone(),
        &[],
    )
    .await;
    assert_eq!(put.status(), 204);
    let row =
        db.with_read_conn(|conn| db::get_snapshot(conn, &sync_id, &device_id)).unwrap().unwrap();
    assert!(row.blob_ref.is_none());
    assert_eq!(row.data, payload);
    let downloaded = fetch_snapshot_json(&client, &url, &sync_id, &device_id, &token).await;
    assert_eq!(BASE64.decode(downloaded["data"].as_str().unwrap()).unwrap(), payload);
    let caps: serde_json::Value = client
        .get(format!("{url}/v1/sync/{sync_id}/capabilities"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(caps.get("snapshot_upload").is_none());
    let resp = client
        .post(format!("{url}/v1/sync/{sync_id}/snapshot/uploads"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id)
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    assert!(!std::path::Path::new(&root).exists(), "legacy PUT must not create blob storage");
}

#[tokio::test]
async fn disabling_file_writes_preserves_reads_ack_replacement_and_expiry_cleanup() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (config, root) = storage_under_tmp(tmp.path());
    let (url, server, db, mut state) = start_file_backed_test_relay_with_state(config).await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let initiator = generate_device_id();
    let keys = TestDeviceKeys::generate(&initiator);
    let token = register_device(&client, &url, &sync_id, &initiator, &keys).await;
    let mut targets = Vec::new();
    for _ in 0..3 {
        let target = generate_device_id();
        let (target_token, target_keys) = prepare_device(&db, &sync_id, &target).await;
        let put = put_snapshot_signed(
            &client,
            &url,
            &sync_id,
            &initiator,
            &token,
            &keys,
            "7",
            b"existing-file".to_vec(),
            &[("X-For-Device-Id", &target)],
        )
        .await;
        assert_eq!(put.status(), 204);
        targets.push((target, target_token, target_keys));
    }
    assert_eq!(snapshot_files(&root, &sync_id).len(), 3);
    server.abort();
    state.snapshot_storage = state.config.resolve_snapshot_storage(false).unwrap();
    assert!(!state.snapshot_storage.is_file_backed());
    assert!(state.snapshot_storage.root().is_some());
    let (url, _server, _, state) = start_test_relay_with_app_state(state).await;

    for (target, target_token, _) in &targets {
        let data = fetch_snapshot_json(&client, &url, &sync_id, target, target_token).await;
        assert_eq!(BASE64.decode(data["data"].as_str().unwrap()).unwrap(), b"existing-file");
    }
    let (target, target_token, target_keys) = &targets[0];
    let ack =
        delete_snapshot_signed(&client, &url, &sync_id, target, target_token, target_keys).await;
    assert_eq!(ack.status(), 204);
    assert_eq!(snapshot_files(&root, &sync_id).len(), 2);

    let (target, target_token, _) = &targets[1];
    let replacement = put_snapshot_signed(
        &client,
        &url,
        &sync_id,
        &initiator,
        &token,
        &keys,
        "8",
        b"new-inline".to_vec(),
        &[("X-For-Device-Id", target)],
    )
    .await;
    assert_eq!(replacement.status(), 204);
    let row = db.with_read_conn(|conn| db::get_snapshot(conn, &sync_id, target)).unwrap().unwrap();
    assert!(row.blob_ref.is_none());
    assert_eq!(row.data, b"new-inline");
    assert_eq!(snapshot_files(&root, &sync_id).len(), 1, "replacement unlinks the old blob");
    let data = fetch_snapshot_json(&client, &url, &sync_id, target, target_token).await;
    assert_eq!(BASE64.decode(data["data"].as_str().unwrap()).unwrap(), b"new-inline");

    db.with_conn(|conn| {
        conn.execute(
            "UPDATE snapshots SET expires_at = ?1 WHERE sync_id = ?2 AND target_device_id = ?3",
            rusqlite::params![db::now_secs() - 1, sync_id, targets[2].0],
        )?;
        Ok(())
    })
    .unwrap();
    prism_sync_relay::cleanup::run_cleanup(&state).await;
    assert!(snapshot_files(&root, &sync_id).is_empty());
    assert!(db
        .with_read_conn(|conn| db::get_snapshot(conn, &sync_id, &targets[2].0))
        .unwrap()
        .is_none());
}
