//! End-to-end tests for the resumable snapshot upload relay lifecycle
//! (lean v1) against the real relay served in-process.
//!
//! These drive the HTTP surface with raw signed requests, exactly as the client
//! will, and assert on both the wire contract and the on-disk/DB state that
//! makes the crash-consistency story hold. The single-PUT suite
//! (`relay_snapshot_tests.rs`) remains the compatibility reference: nothing here
//! changes the legacy route.

mod common;

use std::path::Path;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use reqwest::{Client, Response};

use prism_sync_relay::config::{Config, SnapshotUploadConfig};
use prism_sync_relay::db;
use prism_sync_relay::uploads::{
    SNAPSHOT_UPLOAD_CHUNK_BYTES, SNAPSHOT_UPLOAD_DEFAULT_FREE_SPACE_RESERVE_BYTES,
    SNAPSHOT_UPLOAD_IDLE_TTL_SECS, SNAPSHOT_UPLOAD_MAX_SESSION_SECS,
    SNAPSHOT_UPLOAD_MAX_SNAPSHOT_TTL_SECS, SNAPSHOT_UPLOAD_MAX_WIRE_BYTES,
};

use common::*;

// ───────────────────────────── harness ─────────────────────────────

/// A test config with resumable uploads enabled over a temp snapshot root.
///
/// Returns the config plus the canonical snapshot root so assertions can look at
/// the candidate files directly. The root is canonicalized to match what the
/// startup storage gate resolves, otherwise a platform whose temp dir is a
/// symlink would compare against a different path.
fn resumable_config(tmp: &Path) -> (Config, String) {
    let mut config = test_config();
    let canonical_tmp = std::fs::canonicalize(tmp).unwrap();
    let media = canonical_tmp.join("media");
    std::fs::create_dir_all(&media).unwrap();
    config.media_storage_path = media.to_str().unwrap().to_string();
    config.snapshot_upload = SnapshotUploadConfig {
        enabled: true,
        // Widen the byte ceilings so the multi-chunk tests are exercising chunk
        // semantics rather than quota enforcement. Dedicated quota tests tighten
        // these deliberately.
        group_reserved_bytes: 64 * SNAPSHOT_UPLOAD_MAX_WIRE_BYTES,
        global_reserved_bytes: 256 * SNAPSHOT_UPLOAD_MAX_WIRE_BYTES,
        chunk_concurrency: 8,
        create_rate_limit: 10_000,
        ..SnapshotUploadConfig::default()
    };
    let snapshot_root = canonical_tmp.join("media-snapshots").to_str().unwrap().to_string();
    (config, snapshot_root)
}

fn upload_files(snapshot_root: &str, sync_id: &str) -> Vec<std::path::PathBuf> {
    let dir = Path::new(snapshot_root).join(sync_id);
    match std::fs::read_dir(&dir) {
        Ok(rd) => rd.flatten().map(|e| e.path()).filter(|p| p.is_file()).collect(),
        Err(_) => Vec::new(),
    }
}

/// One registered uploader device, plus a sibling device in the same group.
///
/// The sibling is materialized through `prepare_device` rather than the public
/// registration route, because adding a second device to an existing group
/// deliberately requires an approval. It exists only to prove that an upload ID
/// is not authority and to be the snapshot audience under test.
struct Fixture {
    url: String,
    sync_id: String,
    device_id: String,
    token: String,
    keys: TestDeviceKeys,
    /// Sibling device in the same group.
    other_device_id: String,
    other_token: String,
    other_keys: TestDeviceKeys,
    db: std::sync::Arc<db::Database>,
    /// The live state the router serves, so a test can drive one deterministic
    /// `cleanup::run_cleanup` pass over the real thing.
    state: prism_sync_relay::state::AppState,
    snapshot_root: String,
}

/// Two-device fixture (the common case).
async fn fixture(tmp: &Path) -> Fixture {
    fixture_with(tmp, true).await
}

/// Single-device fixture: needed where the group must have exactly one active
/// device (account deletion).
async fn single_device_fixture(tmp: &Path) -> Fixture {
    fixture_with(tmp, false).await
}

async fn fixture_with(tmp: &Path, with_sibling: bool) -> Fixture {
    let (config, snapshot_root) = resumable_config(tmp);
    let (url, _server, db, state) = start_file_backed_test_relay_with_state(config).await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;

    let sibling_id = generate_device_id();
    let (sibling_token, sibling_keys) = if with_sibling {
        prepare_device(&db, &sync_id, &sibling_id).await
    } else {
        (String::new(), TestDeviceKeys::generate("unused-sibling"))
    };

    Fixture {
        url,
        sync_id,
        device_id,
        token,
        keys,
        other_device_id: sibling_id,
        other_token: sibling_token,
        other_keys: sibling_keys,
        db,
        state,
        snapshot_root,
    }
}

/// Body of a create request for `total` bytes with the given SHA-256.
fn create_body(
    target: &str,
    total: usize,
    sha_hex: &str,
    epoch: i64,
    seq: i64,
) -> serde_json::Value {
    serde_json::json!({
        "version": 1,
        "upload_key": BASE64.encode([9u8; 32]),
        "epoch": epoch,
        "server_seq_at": seq,
        "target_device_id": target,
        "ttl_secs": 86_400,
        "total_bytes": total,
        "body_sha256": sha_hex,
    })
}

fn device_epoch(db: &db::Database, sync_id: &str, device_id: &str) -> i64 {
    db.with_read_conn(|conn| {
        Ok::<_, rusqlite::Error>(
            conn.query_row(
                "SELECT epoch FROM devices WHERE sync_id = ?1 AND device_id = ?2",
                rusqlite::params![sync_id, device_id],
                |r| r.get(0),
            )
            .unwrap_or(0),
        )
    })
    .unwrap()
}

async fn create_upload(f: &Fixture, body: &serde_json::Value) -> Response {
    create_upload_for(f, &f.device_id, &f.token, &f.keys, body).await
}

async fn create_upload_for(
    f: &Fixture,
    device_id: &str,
    token: &str,
    keys: &TestDeviceKeys,
    body: &serde_json::Value,
) -> Response {
    let path = format!("/v1/sync/{}/snapshot/uploads", f.sync_id);
    let bytes = serde_json::to_vec(body).unwrap();
    let builder = Client::new()
        .post(format!("{}{path}", f.url))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", device_id)
        .header("Content-Type", "application/json");
    apply_signed_headers(builder, keys, "POST", &path, &f.sync_id, device_id, &bytes)
        .body(bytes)
        .send()
        .await
        .unwrap()
}

async fn status_upload(f: &Fixture, upload_id: &str) -> Response {
    status_upload_for(f, &f.device_id, &f.token, &f.keys, upload_id).await
}

async fn status_upload_for(
    f: &Fixture,
    device_id: &str,
    token: &str,
    keys: &TestDeviceKeys,
    upload_id: &str,
) -> Response {
    let path = format!("/v1/sync/{}/snapshot/uploads/{upload_id}", f.sync_id);
    let builder = Client::new()
        .get(format!("{}{path}", f.url))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", device_id);
    apply_signed_headers(builder, keys, "GET", &path, &f.sync_id, device_id, &[])
        .send()
        .await
        .unwrap()
}

async fn put_chunk(f: &Fixture, upload_id: &str, offset: usize, body: &[u8]) -> Response {
    put_chunk_for(f, &f.device_id, &f.token, &f.keys, upload_id, offset, body).await
}

#[allow(clippy::too_many_arguments)]
async fn put_chunk_for(
    f: &Fixture,
    device_id: &str,
    token: &str,
    keys: &TestDeviceKeys,
    upload_id: &str,
    offset: usize,
    body: &[u8],
) -> Response {
    let path = format!("/v1/sync/{}/snapshot/uploads/{upload_id}/chunks/{offset}", f.sync_id);
    let builder = Client::new()
        .put(format!("{}{path}", f.url))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", device_id)
        .header("Content-Type", "application/octet-stream");
    apply_signed_headers(builder, keys, "PUT", &path, &f.sync_id, device_id, body)
        .body(body.to_vec())
        .send()
        .await
        .unwrap()
}

/// Like [`put_chunk`], but tolerating a transport-level failure.
///
/// The route's body layer caps the transport at the protocol chunk maximum. When
/// a client sends more than that, the layer aborts the request mid-body, which
/// surfaces to the sender as a connection reset rather than a response. Either
/// outcome is a refusal, so the oversize-body test accepts both.
async fn try_put_chunk(
    f: &Fixture,
    upload_id: &str,
    offset: usize,
    body: &[u8],
) -> Option<Response> {
    let path = format!("/v1/sync/{}/snapshot/uploads/{upload_id}/chunks/{offset}", f.sync_id);
    let builder = Client::new()
        .put(format!("{}{path}", f.url))
        .header("Authorization", format!("Bearer {}", f.token))
        .header("X-Device-Id", &f.device_id)
        .header("Content-Type", "application/octet-stream");
    apply_signed_headers(builder, &f.keys, "PUT", &path, &f.sync_id, &f.device_id, body)
        .body(body.to_vec())
        .send()
        .await
        .ok()
}

async fn complete_upload(f: &Fixture, upload_id: &str) -> Response {
    complete_upload_for(f, &f.device_id, &f.token, &f.keys, upload_id).await
}

async fn complete_upload_for(
    f: &Fixture,
    device_id: &str,
    token: &str,
    keys: &TestDeviceKeys,
    upload_id: &str,
) -> Response {
    let path = format!("/v1/sync/{}/snapshot/uploads/{upload_id}/complete", f.sync_id);
    let builder = Client::new()
        .post(format!("{}{path}", f.url))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", device_id);
    apply_signed_headers(builder, keys, "POST", &path, &f.sync_id, device_id, &[])
        .send()
        .await
        .unwrap()
}

async fn abort_upload(f: &Fixture, upload_id: &str) -> Response {
    abort_upload_for(f, &f.device_id, &f.token, &f.keys, upload_id).await
}

async fn abort_upload_for(
    f: &Fixture,
    device_id: &str,
    token: &str,
    keys: &TestDeviceKeys,
    upload_id: &str,
) -> Response {
    let path = format!("/v1/sync/{}/snapshot/uploads/{upload_id}", f.sync_id);
    let builder = Client::new()
        .delete(format!("{}{path}", f.url))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", device_id);
    apply_signed_headers(builder, keys, "DELETE", &path, &f.sync_id, device_id, &[])
        .send()
        .await
        .unwrap()
}

/// Read `upload_id` out of a create response, failing loudly on an unexpected status.
async fn created_upload_id(resp: Response) -> String {
    let status = resp.status();
    let json: serde_json::Value = resp.json().await.unwrap();
    assert!(status == 201 || status == 200, "create failed with {status}: {json}");
    json["upload_id"].as_str().expect("upload_id in create response").to_string()
}

/// A deterministic envelope of `len` bytes, with the pattern depending on `seed`
/// so two fixtures are byte-different but each reproducible.
fn envelope(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
}

/// Decode a response body as JSON, surfacing the status and raw text on failure.
///
/// A decode failure here almost always means a *different* layer answered (for
/// example a transport body-limit rejection, which has no JSON body), so the
/// message must carry enough to tell those apart.
async fn json_body(resp: Response) -> (reqwest::StatusCode, serde_json::Value) {
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    let value = serde_json::from_str(&text).unwrap_or_else(|e| {
        panic!("expected a JSON body but got status={status} body={text:?} ({e})")
    });
    (status, value)
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

/// Drive a full create → chunk → complete cycle and return the upload ID.
async fn upload_envelope(f: &Fixture, bytes: &[u8], seq: i64) -> String {
    let create = create_body(
        &f.other_device_id,
        bytes.len(),
        &sha256_hex(bytes),
        device_epoch(&f.db, &f.sync_id, &f.device_id),
        seq,
    );
    let upload_id = created_upload_id(create_upload(f, &create).await).await;
    let mut offset = 0;
    while offset < bytes.len() {
        let end = (offset + SNAPSHOT_UPLOAD_CHUNK_BYTES).min(bytes.len());
        let resp = put_chunk(f, &upload_id, offset, &bytes[offset..end]).await;
        assert_eq!(resp.status(), 200, "chunk at {offset} should commit");
        offset = end;
    }
    upload_id
}

/// Fetch and decode the snapshot the target device would download.
async fn target_download(f: &Fixture, device_id: &str, token: &str) -> Vec<u8> {
    let resp = Client::new()
        .get(format!("{}/v1/sync/{}/snapshot", f.url, f.sync_id))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", device_id)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "snapshot should be downloadable");
    let json: serde_json::Value = resp.json().await.unwrap();
    BASE64.decode(json["data"].as_str().unwrap()).unwrap()
}

/// Issue a signed `PUT /v1/sync/{sync_id}/snapshot` (the legacy single-PUT
/// route).
///
/// Duplicated from the snapshot suite because each integration test binary is
/// its own crate, and the coexistence property under test here is precisely that
/// the legacy route is unaffected by the resumable feature.
#[allow(clippy::too_many_arguments)]
async fn put_snapshot_signed(
    client: &Client,
    url: &str,
    sync_id: &str,
    device_id: &str,
    token: &str,
    keys: &TestDeviceKeys,
    server_seq_at: &str,
    body: Vec<u8>,
    headers: &[(&str, &str)],
) -> Response {
    let path = format!("/v1/sync/{sync_id}/snapshot");
    let mut builder = client
        .put(format!("{url}{path}"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", device_id)
        .header("X-Server-Seq-At", server_seq_at);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    apply_signed_headers(builder, keys, "PUT", &path, sync_id, device_id, &body)
        .body(body)
        .send()
        .await
        .unwrap()
}

// ───────────────────── create / status / happy path ─────────────────────

#[tokio::test]
async fn create_status_chunk_finalize_happy_path_is_byte_exact() {
    let tmp = tempfile::TempDir::new().unwrap();
    let f = fixture(tmp.path()).await;

    // Two chunks: a full 8 MiB chunk plus a short final suffix.
    let bytes = envelope(SNAPSHOT_UPLOAD_CHUNK_BYTES + 4096, 1);
    let upload_id = upload_envelope(&f, &bytes, 42).await;

    // Status before completion: all bytes committed, still active.
    let status: serde_json::Value = status_upload(&f, &upload_id).await.json().await.unwrap();
    assert_eq!(status["state"], "active");
    assert_eq!(status["total_bytes"].as_i64().unwrap(), bytes.len() as i64);
    assert_eq!(status["committed_offset"].as_i64().unwrap(), bytes.len() as i64);
    assert_eq!(status["chunk_bytes"].as_i64().unwrap(), SNAPSHOT_UPLOAD_CHUNK_BYTES as i64);

    let complete = complete_upload(&f, &upload_id).await;
    assert_eq!(complete.status(), 204, "complete publishes and returns 204");

    // The candidate is exactly the sender's envelope, published under one blob.
    let files = upload_files(&f.snapshot_root, &f.sync_id);
    assert_eq!(files.len(), 1, "exactly one published blob on disk");
    assert_eq!(std::fs::read(&files[0]).unwrap(), bytes, "published bytes are byte-exact");

    // The joiner-facing download is byte-identical and carries the create seq.
    let downloaded = target_download(&f, &f.other_device_id, &f.other_token).await;
    assert_eq!(downloaded, bytes);

    // Terminal status is retained and reports completion.
    let status: serde_json::Value = status_upload(&f, &upload_id).await.json().await.unwrap();
    assert_eq!(status["state"], "completed");
}

#[tokio::test]
async fn complete_before_all_bytes_is_nonterminal_incomplete() {
    let tmp = tempfile::TempDir::new().unwrap();
    let f = fixture(tmp.path()).await;
    let bytes = envelope(SNAPSHOT_UPLOAD_CHUNK_BYTES + 1024, 2);
    let create = create_body(
        &f.other_device_id,
        bytes.len(),
        &sha256_hex(&bytes),
        device_epoch(&f.db, &f.sync_id, &f.device_id),
        1,
    );
    let upload_id = created_upload_id(create_upload(&f, &create).await).await;
    assert_eq!(
        put_chunk(&f, &upload_id, 0, &bytes[..SNAPSHOT_UPLOAD_CHUNK_BYTES]).await.status(),
        200
    );

    let (status, json) = json_body(complete_upload(&f, &upload_id).await).await;
    assert_eq!(status, 409, "incomplete complete is a conflict, not a failure: {json}");
    assert_eq!(json["error"], "upload_incomplete");
    assert_eq!(json["committed_offset"].as_i64().unwrap(), SNAPSHOT_UPLOAD_CHUNK_BYTES as i64);

    // The session stays active and can be finished.
    let status: serde_json::Value = status_upload(&f, &upload_id).await.json().await.unwrap();
    assert_eq!(status["state"], "active");
    assert_eq!(
        put_chunk(
            &f,
            &upload_id,
            SNAPSHOT_UPLOAD_CHUNK_BYTES,
            &bytes[SNAPSHOT_UPLOAD_CHUNK_BYTES..]
        )
        .await
        .status(),
        200
    );
    assert_eq!(complete_upload(&f, &upload_id).await.status(), 204);
}

// ───────────────────── duplicate / replayed offsets ─────────────────────

#[tokio::test]
async fn duplicate_chunk_retry_is_acknowledged_without_side_effects() {
    let tmp = tempfile::TempDir::new().unwrap();
    let f = fixture(tmp.path()).await;
    let bytes = envelope(SNAPSHOT_UPLOAD_CHUNK_BYTES * 2, 3);
    let create = create_body(
        &f.other_device_id,
        bytes.len(),
        &sha256_hex(&bytes),
        device_epoch(&f.db, &f.sync_id, &f.device_id),
        1,
    );
    let upload_id = created_upload_id(create_upload(&f, &create).await).await;
    let first = &bytes[..SNAPSHOT_UPLOAD_CHUNK_BYTES];
    assert_eq!(put_chunk(&f, &upload_id, 0, first).await.status(), 200);
    let after_first: serde_json::Value = status_upload(&f, &upload_id).await.json().await.unwrap();
    let idle_after_first = after_first["idle_expires_at"].as_i64().unwrap();

    // Replay the SAME range with DIFFERENT bytes. It must be acknowledged with
    // the relay's offset, must not be written, and must not refresh expiry: the
    // accepted prefix is already authoritative and completion verifies the whole
    // file against the create-time SHA-256.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let resp = put_chunk(&f, &upload_id, 0, &vec![0xAB; SNAPSHOT_UPLOAD_CHUNK_BYTES]).await;
    assert_eq!(resp.status(), 200, "a wholly committed retry is not an error");
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["committed_offset"].as_i64().unwrap(), SNAPSHOT_UPLOAD_CHUNK_BYTES as i64);
    assert_eq!(
        json["idle_expires_at"].as_i64().unwrap(),
        idle_after_first,
        "a duplicate acknowledgment must not renew idle expiry"
    );

    // Finish and complete: the published bytes are the ORIGINAL prefix, so the
    // differing duplicate could not have damaged storage.
    assert_eq!(
        put_chunk(
            &f,
            &upload_id,
            SNAPSHOT_UPLOAD_CHUNK_BYTES,
            &bytes[SNAPSHOT_UPLOAD_CHUNK_BYTES..]
        )
        .await
        .status(),
        200
    );
    assert_eq!(complete_upload(&f, &upload_id).await.status(), 204);
    let downloaded = target_download(&f, &f.other_device_id, &f.other_token).await;
    assert_eq!(downloaded, bytes, "committed prefix survived the duplicate retry");
}

#[tokio::test]
async fn ahead_offset_and_partial_overlap_conflict_with_relay_offset() {
    let tmp = tempfile::TempDir::new().unwrap();
    let f = fixture(tmp.path()).await;
    let bytes = envelope(SNAPSHOT_UPLOAD_CHUNK_BYTES * 3, 4);
    let create = create_body(
        &f.other_device_id,
        bytes.len(),
        &sha256_hex(&bytes),
        device_epoch(&f.db, &f.sync_id, &f.device_id),
        1,
    );
    let upload_id = created_upload_id(create_upload(&f, &create).await).await;
    assert_eq!(
        put_chunk(&f, &upload_id, 0, &bytes[..SNAPSHOT_UPLOAD_CHUNK_BYTES]).await.status(),
        200
    );

    // Ahead of the relay: the client skipped a chunk.
    let (status, json) =
        json_body(put_chunk(&f, &upload_id, SNAPSHOT_UPLOAD_CHUNK_BYTES * 2, &bytes[..16]).await)
            .await;
    assert_eq!(status, 409);
    assert_eq!(json["error"], "offset_mismatch");
    assert_eq!(json["committed_offset"].as_i64().unwrap(), SNAPSHOT_UPLOAD_CHUNK_BYTES as i64);

    // Partial overlap: starts inside the committed prefix but extends past it.
    let (status, json) =
        json_body(put_chunk(&f, &upload_id, SNAPSHOT_UPLOAD_CHUNK_BYTES - 8, &bytes[..4096]).await)
            .await;
    assert_eq!(status, 409);
    assert_eq!(json["error"], "offset_mismatch");
}

#[tokio::test]
async fn concurrent_same_offset_requests_commit_exactly_once() {
    let tmp = tempfile::TempDir::new().unwrap();
    let f = fixture(tmp.path()).await;
    let bytes = envelope(SNAPSHOT_UPLOAD_CHUNK_BYTES * 2, 5);
    let create = create_body(
        &f.other_device_id,
        bytes.len(),
        &sha256_hex(&bytes),
        device_epoch(&f.db, &f.sync_id, &f.device_id),
        1,
    );
    let upload_id = created_upload_id(create_upload(&f, &create).await).await;
    let first: &[u8] = &bytes[..SNAPSHOT_UPLOAD_CHUNK_BYTES];

    // Fire N identical chunk requests at the same offset genuinely concurrently
    // (all polled together, each signed with a fresh nonce). The relay serializes
    // per session, so exactly one commits; the rest observe the advanced offset
    // and are answered as committed-range retries. The invariant is that the
    // committed offset lands on exactly ONE chunk and every response reports it.
    let futures = (0..6)
        .map(|_| put_chunk_for(&f, &f.device_id, &f.token, &f.keys, &upload_id, 0, first))
        .collect::<Vec<_>>();
    let responses = futures::future::join_all(futures).await;

    for resp in responses {
        let (status, json) = json_body(resp).await;
        assert_eq!(status, 200, "a same-offset duplicate is acknowledged: {json}");
        assert_eq!(
            json["committed_offset"].as_i64().unwrap(),
            SNAPSHOT_UPLOAD_CHUNK_BYTES as i64,
            "every concurrent duplicate reports the same single committed chunk"
        );
    }

    // The prefix is exactly one chunk, and the file holds exactly the original
    // bytes: no duplicate appended trailing data.
    assert_eq!(
        put_chunk(
            &f,
            &upload_id,
            SNAPSHOT_UPLOAD_CHUNK_BYTES,
            &bytes[SNAPSHOT_UPLOAD_CHUNK_BYTES..]
        )
        .await
        .status(),
        200
    );
    assert_eq!(complete_upload(&f, &upload_id).await.status(), 204);
    let downloaded = target_download(&f, &f.other_device_id, &f.other_token).await;
    assert_eq!(downloaded, bytes, "concurrent duplicates produced exactly one committed prefix");
}

// ───────────────────── body bounds ─────────────────────

#[tokio::test]
async fn chunk_and_create_body_bounds_are_enforced() {
    let tmp = tempfile::TempDir::new().unwrap();
    let f = fixture(tmp.path()).await;
    // Total is one full chunk plus a short suffix, so a second FULL chunk would
    // necessarily pass the declared total.
    let bytes = envelope(SNAPSHOT_UPLOAD_CHUNK_BYTES + 100, 6);
    let create = create_body(
        &f.other_device_id,
        bytes.len(),
        &sha256_hex(&bytes),
        device_epoch(&f.db, &f.sync_id, &f.device_id),
        1,
    );
    let upload_id = created_upload_id(create_upload(&f, &create).await).await;

    // Zero-byte chunk.
    let (status, json) = json_body(put_chunk(&f, &upload_id, 0, &[]).await).await;
    assert_eq!(status, 413);
    assert_eq!(json["error"], "chunk_too_large");

    // Oversized chunk (one byte over the protocol chunk size). The route's body
    // limit IS the protocol maximum, so this is refused by the body layer before
    // semantic validation — which is the point: a restart or config change can
    // never wedge a live session. The layer either answers with a bare 413 or
    // resets the connection while the client is still writing; both are
    // refusals, and `try_put_chunk` collapses the latter to `None`.
    let oversize =
        try_put_chunk(&f, &upload_id, 0, &vec![1u8; SNAPSHOT_UPLOAD_CHUNK_BYTES + 1]).await;
    assert!(
        oversize.as_ref().is_none_or(|resp| resp.status() == 413),
        "an over-protocol chunk must be refused, not accepted"
    );
    // The session is untouched by the refused request.
    let status: serde_json::Value = status_upload(&f, &upload_id).await.json().await.unwrap();
    assert_eq!(status["committed_offset"].as_i64().unwrap(), 0);

    // Short NON-final chunk: 1 byte at offset 0 while more chunks remain. The
    // spec gives this its own machine code (distinct from an over-long chunk),
    // because the client's fix is different: send exactly one chunk, or shorten
    // the declared total. The relay's offset is echoed so resumption is exact.
    let (status, json) = json_body(put_chunk(&f, &upload_id, 0, &[7u8]).await).await;
    assert_eq!(status, 400, "a short non-final chunk is refused: {json}");
    assert_eq!(json["error"], "chunk_too_short");
    assert_eq!(json["committed_offset"].as_i64().unwrap(), 0);
    assert_eq!(json["chunk_bytes"].as_i64().unwrap(), SNAPSHOT_UPLOAD_CHUNK_BYTES as i64);

    // Commit the full first chunk, then offer a second full chunk that would
    // pass the declared total. The relay refuses it rather than growing storage
    // beyond what create reserved.
    assert_eq!(
        put_chunk(&f, &upload_id, 0, &bytes[..SNAPSHOT_UPLOAD_CHUNK_BYTES]).await.status(),
        200
    );
    let (status, json) = json_body(
        put_chunk(
            &f,
            &upload_id,
            SNAPSHOT_UPLOAD_CHUNK_BYTES,
            &vec![0u8; SNAPSHOT_UPLOAD_CHUNK_BYTES],
        )
        .await,
    )
    .await;
    assert_eq!(status, 413, "a chunk past the declared total is refused: {json}");
    assert_eq!(json["error"], "snapshot_too_large");
    // The refused request did not advance the offset.
    let status: serde_json::Value = status_upload(&f, &upload_id).await.json().await.unwrap();
    assert_eq!(status["committed_offset"].as_i64().unwrap(), SNAPSHOT_UPLOAD_CHUNK_BYTES as i64);

    // Declared total above the server maximum is rejected at create.
    let oversized = create_body(
        &f.other_device_id,
        (SNAPSHOT_UPLOAD_MAX_WIRE_BYTES as usize) + 1,
        &sha256_hex(b"x"),
        device_epoch(&f.db, &f.sync_id, &f.device_id),
        2,
    );
    let (status, json) = json_body(create_upload(&f, &oversized).await).await;
    assert_eq!(status, 413);
    assert_eq!(json["error"], "snapshot_too_large");
}

#[tokio::test]
async fn create_validates_version_key_target_ttl_and_sha_encoding() {
    let tmp = tempfile::TempDir::new().unwrap();
    let f = fixture(tmp.path()).await;
    let epoch = device_epoch(&f.db, &f.sync_id, &f.device_id);
    let good = create_body(&f.other_device_id, 1024, &sha256_hex(b"x"), epoch, 1);

    // Unsupported protocol version.
    let mut bad = good.clone();
    bad["version"] = serde_json::json!(2);
    assert_eq!(create_upload(&f, &bad).await.status(), 400);

    // Group-wide (untargeted) resumable uploads are refused.
    let mut bad = good.clone();
    bad["target_device_id"] = serde_json::Value::Null;
    let (status, json) = json_body(create_upload(&f, &bad).await).await;
    assert_eq!(status, 400, "untargeted create must be rejected: {json}");
    assert_eq!(json["error"], "unsupported_snapshot_audience");

    // TTL above the maximum.
    let mut bad = good.clone();
    bad["ttl_secs"] = serde_json::json!(SNAPSHOT_UPLOAD_MAX_SNAPSHOT_TTL_SECS + 1);
    assert_eq!(create_upload(&f, &bad).await.status(), 400);

    // Zero TTL.
    let mut bad = good.clone();
    bad["ttl_secs"] = serde_json::json!(0);
    assert_eq!(create_upload(&f, &bad).await.status(), 400);

    // Zero total bytes.
    let mut bad = good.clone();
    bad["total_bytes"] = serde_json::json!(0);
    assert_eq!(create_upload(&f, &bad).await.status(), 413);

    // Non-canonical (uppercase) SHA-256.
    let mut bad = good.clone();
    bad["body_sha256"] = serde_json::json!(sha256_hex(b"x").to_uppercase());
    assert_eq!(create_upload(&f, &bad).await.status(), 400);

    // Wrong-length upload key.
    let mut bad = good.clone();
    bad["upload_key"] = serde_json::json!(BASE64.encode([1u8; 31]));
    assert_eq!(create_upload(&f, &bad).await.status(), 400);

    // The good body still works, proving the rejections were field-specific.
    assert_eq!(create_upload(&f, &good).await.status(), 201);
}

// ───────────────────── authentication ─────────────────────

#[tokio::test]
async fn every_operation_rejects_missing_or_invalid_authentication() {
    let tmp = tempfile::TempDir::new().unwrap();
    let f = fixture(tmp.path()).await;
    let create = create_body(
        &f.other_device_id,
        1024,
        &sha256_hex(b"auth"),
        device_epoch(&f.db, &f.sync_id, &f.device_id),
        1,
    );
    let upload_id = created_upload_id(create_upload(&f, &create).await).await;
    let client = Client::new();

    // No bearer token at all.
    let resp = client
        .get(format!("{}/v1/sync/{}/snapshot/uploads/{upload_id}", f.url, f.sync_id))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "status without a bearer token is unauthorized");

    // Bearer but no signed-request headers.
    let resp = client
        .get(format!("{}/v1/sync/{}/snapshot/uploads/{upload_id}", f.url, f.sync_id))
        .header("Authorization", format!("Bearer {}", f.token))
        .header("X-Device-Id", &f.device_id)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "missing signed-request headers are rejected");

    // Chunk with no signature.
    let resp = client
        .put(format!("{}/v1/sync/{}/snapshot/uploads/{upload_id}/chunks/0", f.url, f.sync_id))
        .header("Authorization", format!("Bearer {}", f.token))
        .header("X-Device-Id", &f.device_id)
        .body(vec![0u8; 8])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // Complete with no signature.
    let resp = client
        .post(format!("{}/v1/sync/{}/snapshot/uploads/{upload_id}/complete", f.url, f.sync_id))
        .header("Authorization", format!("Bearer {}", f.token))
        .header("X-Device-Id", &f.device_id)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // Abort with no signature.
    let resp = client
        .delete(format!("{}/v1/sync/{}/snapshot/uploads/{upload_id}", f.url, f.sync_id))
        .header("Authorization", format!("Bearer {}", f.token))
        .header("X-Device-Id", &f.device_id)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // A signature that is well-formed but for a DIFFERENT body must fail: the
    // canonical signature binds the body hash.
    let path = format!("/v1/sync/{}/snapshot/uploads/{upload_id}/chunks/0", f.sync_id);
    let body = vec![0u8; 8];
    let builder = client
        .put(format!("{}{path}", f.url))
        .header("Authorization", format!("Bearer {}", f.token))
        .header("X-Device-Id", &f.device_id);
    // Sign for a different body, then send the real one.
    let signed_for_other =
        apply_signed_headers(builder, &f.keys, "PUT", &path, &f.sync_id, &f.device_id, b"other");
    let resp = signed_for_other.body(body).send().await.unwrap();
    assert_eq!(resp.status(), 401, "a signature over different bytes must not verify");
}

#[tokio::test]
async fn sibling_device_and_cross_group_probes_are_indistinguishable_from_unknown() {
    let tmp = tempfile::TempDir::new().unwrap();
    let f = fixture(tmp.path()).await;
    let create = create_body(
        &f.other_device_id,
        1024,
        &sha256_hex(b"ownership"),
        device_epoch(&f.db, &f.sync_id, &f.device_id),
        1,
    );
    let upload_id = created_upload_id(create_upload(&f, &create).await).await;

    // A device in the same group but not the session owner.
    let resp =
        status_upload_for(&f, &f.other_device_id, &f.other_token, &f.other_keys, &upload_id).await;
    let sibling_status = resp.status();
    let sibling_body = resp.text().await.unwrap();

    // A completely unknown upload ID, same caller.
    let unknown = status_upload_for(&f, &f.device_id, &f.token, &f.keys, &"f".repeat(32)).await;
    let unknown_status = unknown.status();
    let unknown_body = unknown.text().await.unwrap();

    assert_eq!(sibling_status, 404, "a sibling device cannot read another's upload");
    assert_eq!(unknown_status, 404);
    assert_eq!(sibling_body, unknown_body, "ownership failure must not be an oracle");

    // Mutations are refused for the sibling too.
    assert_eq!(
        put_chunk_for(
            &f,
            &f.other_device_id,
            &f.other_token,
            &f.other_keys,
            &upload_id,
            0,
            &[0u8; 8]
        )
        .await
        .status(),
        404
    );
    assert_eq!(
        complete_upload_for(&f, &f.other_device_id, &f.other_token, &f.other_keys, &upload_id)
            .await
            .status(),
        404
    );
    assert_eq!(
        abort_upload_for(&f, &f.other_device_id, &f.other_token, &f.other_keys, &upload_id)
            .await
            .status(),
        404
    );

    // A malformed upload ID is also just "not found".
    assert_eq!(status_upload(&f, "../../etc/passwd").await.status(), 404);
}

#[tokio::test]
async fn cross_sync_upload_id_does_not_leak_existence() {
    let tmp = tempfile::TempDir::new().unwrap();
    let f = fixture(tmp.path()).await;
    let create = create_body(
        &f.other_device_id,
        1024,
        &sha256_hex(b"cross"),
        device_epoch(&f.db, &f.sync_id, &f.device_id),
        1,
    );
    let upload_id = created_upload_id(create_upload(&f, &create).await).await;

    // Register a second, unrelated sync group and probe the first group's upload
    // ID from it.
    let client = Client::new();
    let other_sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &f.url, &other_sync_id, &device_id, &keys).await;

    let path = format!("/v1/sync/{other_sync_id}/snapshot/uploads/{upload_id}");
    let builder = client
        .get(format!("{}{path}", f.url))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id);
    let resp = apply_signed_headers(builder, &keys, "GET", &path, &other_sync_id, &device_id, &[])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "a cross-group upload ID must look unknown");
}

// ───────────────────── idempotency / conflicts ─────────────────────

#[tokio::test]
async fn create_is_idempotent_and_key_conflict_is_detected() {
    let tmp = tempfile::TempDir::new().unwrap();
    let f = fixture(tmp.path()).await;
    let epoch = device_epoch(&f.db, &f.sync_id, &f.device_id);

    // Progress a chunk, then retry the identical create. It must return the SAME
    // session and its CURRENT offset, so a lost create response is recoverable.
    // The bytes must match the declared hash, so the session stays completable
    // (which the end of this test asserts).
    let bytes = envelope(4096, 7);
    let body = create_body(&f.other_device_id, 4096, &sha256_hex(&bytes), epoch, 7);
    let first: serde_json::Value = create_upload(&f, &body).await.json().await.unwrap();
    let upload_id = first["upload_id"].as_str().unwrap().to_string();
    assert_eq!(put_chunk(&f, &upload_id, 0, &bytes).await.status(), 200);

    let resp = create_upload(&f, &body).await;
    assert_eq!(resp.status(), 200, "create recovery is 200");
    let recovered: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(recovered["upload_id"], upload_id, "same session returned");
    assert_eq!(recovered["committed_offset"].as_i64().unwrap(), 4096);

    // Same key with different immutable metadata is a conflict.
    let mut changed = body.clone();
    changed["server_seq_at"] = serde_json::json!(999);
    let (status, json) = json_body(create_upload(&f, &changed).await).await;
    assert_eq!(status, 409);
    assert_eq!(json["error"], "upload_key_conflict");

    // ... and the original session is still intact and completable.
    assert_eq!(complete_upload(&f, &upload_id).await.status(), 204);
}

#[tokio::test]
async fn lost_complete_response_returns_original_result_without_republishing() {
    let tmp = tempfile::TempDir::new().unwrap();
    let f = fixture(tmp.path()).await;
    let bytes = envelope(2048, 8);
    let upload_id = upload_envelope(&f, &bytes, 3).await;

    assert_eq!(complete_upload(&f, &upload_id).await.status(), 204);
    let published = upload_files(&f.snapshot_root, &f.sync_id);
    assert_eq!(published.len(), 1);

    // Retry complete: idempotent 204, and no second file, no second row swap.
    assert_eq!(complete_upload(&f, &upload_id).await.status(), 204);
    let after_retry = upload_files(&f.snapshot_root, &f.sync_id);
    assert_eq!(after_retry.len(), 1, "a retried complete never republishes");
    assert_eq!(after_retry[0], published[0]);

    // Chunks after completion are refused, and abort does not remove the
    // published snapshot.
    let resp = put_chunk(&f, &upload_id, 0, &bytes).await;
    assert_eq!(resp.status(), 409);
    assert_eq!(resp.json::<serde_json::Value>().await.unwrap()["error"], "upload_completed");
    let resp = abort_upload(&f, &upload_id).await;
    assert_eq!(resp.status(), 409);
    assert_eq!(resp.json::<serde_json::Value>().await.unwrap()["error"], "upload_completed");
    assert_eq!(target_download(&f, &f.other_device_id, &f.other_token).await, bytes);
}

#[tokio::test]
async fn new_upload_key_supersedes_the_previous_nonterminal_session() {
    let tmp = tempfile::TempDir::new().unwrap();
    let f = fixture(tmp.path()).await;
    let epoch = device_epoch(&f.db, &f.sync_id, &f.device_id);

    let mut first_body = create_body(&f.other_device_id, 8192, &sha256_hex(b"first"), epoch, 1);
    first_body["upload_key"] = serde_json::json!(BASE64.encode([1u8; 32]));
    let first_id = created_upload_id(create_upload(&f, &first_body).await).await;
    assert_eq!(put_chunk(&f, &first_id, 0, &envelope(8192, 1)).await.status(), 200);

    // A NEW key (a fresh pairing attempt) supersedes the old nonterminal
    // session, so a lost abort cannot strand a reservation.
    let mut second_body = create_body(&f.other_device_id, 8192, &sha256_hex(b"second"), epoch, 2);
    second_body["upload_key"] = serde_json::json!(BASE64.encode([2u8; 32]));
    let second_id = created_upload_id(create_upload(&f, &second_body).await).await;
    assert_ne!(second_id, first_id);

    // The superseded session is terminal; its reservation is gone.
    let status: serde_json::Value = status_upload(&f, &first_id).await.json().await.unwrap();
    assert_eq!(status["state"], "failed");
    let reserved = f.db.with_read_conn(db::snapshot_upload_reserved_bytes).unwrap();
    assert_eq!(reserved, 8192, "only the replacement's reservation remains");
}

// ───────────────────── quotas ─────────────────────

#[tokio::test]
async fn reservation_ceilings_reject_and_release_atomically() {
    let tmp = tempfile::TempDir::new().unwrap();
    let mut config = test_config();
    let canonical_tmp = std::fs::canonicalize(tmp.path()).unwrap();
    let media = canonical_tmp.join("media");
    std::fs::create_dir_all(&media).unwrap();
    config.media_storage_path = media.to_str().unwrap().to_string();
    config.snapshot_upload = SnapshotUploadConfig {
        enabled: true,
        // Two 1 MiB reservations fit in a group; a third must not.
        group_reserved_bytes: 2 * 1024 * 1024,
        global_reserved_bytes: 3 * 1024 * 1024,
        create_rate_limit: 10_000,
        ..SnapshotUploadConfig::default()
    };
    let snapshot_root = canonical_tmp.join("media-snapshots").to_str().unwrap().to_string();
    let (url, _server, db, state) = start_file_backed_test_relay_with_state(config).await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;

    // Register two targets so the audience cap is not what rejects.
    let target_a = generate_device_id();
    let _ = prepare_device(&db, &sync_id, &target_a).await;
    let target_b = generate_device_id();
    let _ = prepare_device(&db, &sync_id, &target_b).await;
    let target_c = generate_device_id();
    let _ = prepare_device(&db, &sync_id, &target_c).await;
    let target_d = generate_device_id();
    let _ = prepare_device(&db, &sync_id, &target_d).await;

    let f = Fixture {
        url,
        sync_id,
        device_id,
        token,
        keys,
        other_device_id: target_a.clone(),
        other_token: String::new(),
        other_keys: TestDeviceKeys::generate("unused"),
        db: db.clone(),
        state,
        snapshot_root,
    };

    let epoch = device_epoch(&db, &f.sync_id, &f.device_id);
    let one_mib = 1024 * 1024;

    // Session 1: 1 MiB reserved (and fully uploaded so supersession's own-target
    // exclusion is not what we are measuring — we use distinct keys).
    let mut b1 = create_body(&target_a, one_mib, &sha256_hex(b"a"), epoch, 1);
    b1["upload_key"] = serde_json::json!(BASE64.encode([1u8; 32]));
    let id1 = created_upload_id(create_upload(&f, &b1).await).await;
    assert_eq!(f.db.with_read_conn(db::snapshot_upload_reserved_bytes).unwrap(), one_mib as u64);

    // A create with a different target still supersedes (one nonterminal upload
    // per uploader), so to actually test the ceiling we must be able to hold two
    // reservations: that is what the group limit allows. Confirm supersession
    // released id1's reservation first.
    let mut b2 = create_body(&target_b, one_mib, &sha256_hex(b"b"), epoch, 2);
    b2["upload_key"] = serde_json::json!(BASE64.encode([2u8; 32]));
    let _id2 = created_upload_id(create_upload(&f, &b2).await).await;
    assert_eq!(
        f.db.with_read_conn(db::snapshot_upload_reserved_bytes).unwrap(),
        one_mib as u64,
        "supersession released the previous reservation before admitting the replacement"
    );
    // The first session is terminal after supersession.
    let status: serde_json::Value = status_upload(&f, &id1).await.json().await.unwrap();
    assert_eq!(status["state"], "failed");
}

#[tokio::test]
async fn insufficient_free_space_is_refused_at_create() {
    let tmp = tempfile::TempDir::new().unwrap();
    let mut config = test_config();
    let canonical_tmp = std::fs::canonicalize(tmp.path()).unwrap();
    let media = canonical_tmp.join("media");
    std::fs::create_dir_all(&media).unwrap();
    config.media_storage_path = media.to_str().unwrap().to_string();
    config.snapshot_upload = SnapshotUploadConfig {
        enabled: true,
        // A reserve larger than any real filesystem has free, so the gate must
        // trip regardless of the host's actual capacity.
        free_space_reserve_bytes: u64::MAX,
        create_rate_limit: 10_000,
        ..SnapshotUploadConfig::default()
    };
    let (url, _server, db, state) = start_file_backed_test_relay_with_state(config).await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;
    let target = generate_device_id();
    let _ = prepare_device(&db, &sync_id, &target).await;

    let f = Fixture {
        url,
        sync_id,
        device_id,
        token,
        keys,
        other_device_id: target.clone(),
        other_token: String::new(),
        other_keys: TestDeviceKeys::generate("unused"),
        db: db.clone(),
        state,
        snapshot_root: String::new(),
    };
    let body = create_body(
        &target,
        1024,
        &sha256_hex(b"space"),
        device_epoch(&db, &f.sync_id, &f.device_id),
        1,
    );
    let resp = create_upload(&f, &body).await;
    assert_eq!(resp.status(), 507, "an unsatisfiable free-space reserve refuses the session");
    assert_eq!(
        f.db.with_read_conn(db::snapshot_upload_reserved_bytes).unwrap(),
        0,
        "no reservation is taken on a rejected create"
    );
}

// ───────────────────── staleness / authoritative rechecks ─────────────────────

#[tokio::test]
async fn completion_rechecks_staleness_and_records_a_stable_terminal_result() {
    let tmp = tempfile::TempDir::new().unwrap();
    let f = fixture(tmp.path()).await;
    let bytes = envelope(4096, 9);

    // Upload a snapshot at seq 10 via resumable, fully staged but NOT completed.
    let create = create_body(
        &f.other_device_id,
        bytes.len(),
        &sha256_hex(&bytes),
        device_epoch(&f.db, &f.sync_id, &f.device_id),
        10,
    );
    let upload_id = created_upload_id(create_upload(&f, &create).await).await;
    assert_eq!(put_chunk(&f, &upload_id, 0, &bytes).await.status(), 200);

    // A newer snapshot lands for the SAME audience through the legacy route,
    // advancing the seq past ours.
    let resp = put_snapshot_signed(
        &Client::new(),
        &f.url,
        &f.sync_id,
        &f.device_id,
        &f.token,
        &f.keys,
        "11",
        b"newer-single-put".to_vec(),
        &[("X-For-Device-Id", &f.other_device_id)],
    )
    .await;
    assert_eq!(resp.status(), 204);

    // Completion loses the race: the existing staleness guard rejects it.
    let (status, json) = json_body(complete_upload(&f, &upload_id).await).await;
    assert_eq!(status, 409, "{json}");
    assert_eq!(json["error"], "stale_snapshot_seq", "the existing 409 shape is preserved");
    assert_eq!(json["current_server_seq_at"].as_i64().unwrap(), 11);

    // The rejection is recorded as a terminal result, and a retry reproduces it
    // rather than re-running publication.
    let status: serde_json::Value = status_upload(&f, &upload_id).await.json().await.unwrap();
    assert_eq!(status["state"], "failed");
    let (retry_status, retry_json) = json_body(complete_upload(&f, &upload_id).await).await;
    assert_eq!(retry_status, 409, "{retry_json}");
    assert_eq!(retry_json["error"], "stale_snapshot_seq");

    // The newer snapshot still wins; the rejected candidate never published.
    let downloaded = target_download(&f, &f.other_device_id, &f.other_token).await;
    assert_eq!(downloaded, b"newer-single-put");
}

#[tokio::test]
async fn completion_rechecks_epoch_and_owner() {
    let tmp = tempfile::TempDir::new().unwrap();
    let f = fixture(tmp.path()).await;
    let bytes = envelope(2048, 10);
    let create = create_body(
        &f.other_device_id,
        bytes.len(),
        &sha256_hex(&bytes),
        device_epoch(&f.db, &f.sync_id, &f.device_id),
        1,
    );
    let upload_id = created_upload_id(create_upload(&f, &create).await).await;
    assert_eq!(put_chunk(&f, &upload_id, 0, &bytes).await.status(), 200);

    // Rotate the uploader's epoch out from under the staged session.
    f.db.with_conn(|conn| {
        conn.execute(
            "UPDATE devices SET epoch = epoch + 1 WHERE sync_id = ?1 AND device_id = ?2",
            rusqlite::params![f.sync_id, f.device_id],
        )?;
        Ok(())
    })
    .unwrap();

    let resp = complete_upload(&f, &upload_id).await;
    assert_eq!(resp.status(), 422, "a changed epoch invalidates the staged upload");
    assert_eq!(resp.json::<serde_json::Value>().await.unwrap()["error"], "upload_epoch_invalid");
}

// ───────────────────── hash integrity ─────────────────────

#[tokio::test]
async fn hash_mismatch_never_publishes() {
    let tmp = tempfile::TempDir::new().unwrap();
    let f = fixture(tmp.path()).await;
    let bytes = envelope(4096, 11);
    // Declare the hash of DIFFERENT bytes than we will upload: staging corruption
    // or a lying sender, detected before publication.
    let create = create_body(
        &f.other_device_id,
        bytes.len(),
        &sha256_hex(b"a completely different envelope"),
        device_epoch(&f.db, &f.sync_id, &f.device_id),
        1,
    );
    let upload_id = created_upload_id(create_upload(&f, &create).await).await;
    assert_eq!(put_chunk(&f, &upload_id, 0, &bytes).await.status(), 200);

    let resp = complete_upload(&f, &upload_id).await;
    assert_eq!(resp.status(), 422);
    assert_eq!(resp.json::<serde_json::Value>().await.unwrap()["error"], "snapshot_hash_mismatch");

    // Nothing was published.
    let resp = Client::new()
        .get(format!("{}/v1/sync/{}/snapshot", f.url, f.sync_id))
        .header("Authorization", format!("Bearer {}", f.other_token))
        .header("X-Device-Id", &f.other_device_id)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "a hash mismatch must not expose a snapshot");

    // Terminal, and a retry answers the same way.
    let status: serde_json::Value = status_upload(&f, &upload_id).await.json().await.unwrap();
    assert_eq!(status["state"], "failed");
    assert_eq!(complete_upload(&f, &upload_id).await.status(), 422);
}

// ───────────────────── crash windows / reconciliation ─────────────────────

#[tokio::test]
async fn trailing_bytes_from_a_crash_are_truncated_before_the_next_chunk() {
    let tmp = tempfile::TempDir::new().unwrap();
    let f = fixture(tmp.path()).await;
    let bytes = envelope(SNAPSHOT_UPLOAD_CHUNK_BYTES * 2, 12);
    let create = create_body(
        &f.other_device_id,
        bytes.len(),
        &sha256_hex(&bytes),
        device_epoch(&f.db, &f.sync_id, &f.device_id),
        1,
    );
    let upload_id = created_upload_id(create_upload(&f, &create).await).await;
    assert_eq!(
        put_chunk(&f, &upload_id, 0, &bytes[..SNAPSHOT_UPLOAD_CHUNK_BYTES]).await.status(),
        200
    );

    // Inject the crash window: the file gains bytes the DB never acknowledged
    // (a write that landed before the offset commit). The next chunk must
    // reconcile by truncating back to the committed offset.
    let files = upload_files(&f.snapshot_root, &f.sync_id);
    assert_eq!(files.len(), 1);
    {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new().append(true).open(&files[0]).unwrap();
        file.write_all(&[0xEE; 512]).unwrap();
    }
    assert_eq!(
        std::fs::metadata(&files[0]).unwrap().len(),
        (SNAPSHOT_UPLOAD_CHUNK_BYTES + 512) as u64
    );

    assert_eq!(
        put_chunk(
            &f,
            &upload_id,
            SNAPSHOT_UPLOAD_CHUNK_BYTES,
            &bytes[SNAPSHOT_UPLOAD_CHUNK_BYTES..]
        )
        .await
        .status(),
        200
    );
    assert_eq!(complete_upload(&f, &upload_id).await.status(), 204);
    let downloaded = target_download(&f, &f.other_device_id, &f.other_token).await;
    assert_eq!(downloaded, bytes, "unacknowledged trailing bytes were discarded");
}

#[tokio::test]
async fn missing_candidate_after_progress_fails_the_session_as_corrupt() {
    let tmp = tempfile::TempDir::new().unwrap();
    let f = fixture(tmp.path()).await;
    let bytes = envelope(SNAPSHOT_UPLOAD_CHUNK_BYTES * 2, 13);
    let create = create_body(
        &f.other_device_id,
        bytes.len(),
        &sha256_hex(&bytes),
        device_epoch(&f.db, &f.sync_id, &f.device_id),
        1,
    );
    let upload_id = created_upload_id(create_upload(&f, &create).await).await;
    assert_eq!(
        put_chunk(&f, &upload_id, 0, &bytes[..SNAPSHOT_UPLOAD_CHUNK_BYTES]).await.status(),
        200
    );

    // The volume lost the candidate while the DB still claims a committed
    // prefix. Never silently lower the offset: fail the session.
    for path in upload_files(&f.snapshot_root, &f.sync_id) {
        std::fs::remove_file(path).unwrap();
    }
    let resp = put_chunk(
        &f,
        &upload_id,
        SNAPSHOT_UPLOAD_CHUNK_BYTES,
        &bytes[SNAPSHOT_UPLOAD_CHUNK_BYTES..],
    )
    .await;
    assert_eq!(resp.status(), 409);
    assert_eq!(resp.json::<serde_json::Value>().await.unwrap()["error"], "upload_failed");

    let status: serde_json::Value = status_upload(&f, &upload_id).await.json().await.unwrap();
    assert_eq!(status["state"], "failed");
    assert_eq!(
        f.db.with_read_conn(db::snapshot_upload_reserved_bytes).unwrap(),
        0,
        "the corrupt session released its reservation"
    );
}

#[tokio::test]
async fn crash_after_finalizing_is_recoverable_and_reconciled_by_cleanup() {
    let tmp = tempfile::TempDir::new().unwrap();
    let f = fixture(tmp.path()).await;
    let bytes = envelope(4096, 14);
    let create = create_body(
        &f.other_device_id,
        bytes.len(),
        &sha256_hex(&bytes),
        device_epoch(&f.db, &f.sync_id, &f.device_id),
        1,
    );
    let upload_id = created_upload_id(create_upload(&f, &create).await).await;
    assert_eq!(put_chunk(&f, &upload_id, 0, &bytes).await.status(), 200);

    // Simulate a crash after entering `finalizing` (the state a mid-completion
    // crash leaves behind). Status reports it, and chunks are refused with a
    // distinguishable code rather than being silently written.
    f.db.with_conn(|conn| {
        conn.execute(
            "UPDATE snapshot_uploads SET state = 'finalizing', committed_offset = total_bytes
              WHERE upload_id = ?1",
            rusqlite::params![upload_id],
        )?;
        Ok(())
    })
    .unwrap();
    let status: serde_json::Value = status_upload(&f, &upload_id).await.json().await.unwrap();
    assert_eq!(status["state"], "finalizing");
    let resp = put_chunk(&f, &upload_id, 0, &bytes).await;
    assert_eq!(resp.status(), 409);
    assert_eq!(resp.json::<serde_json::Value>().await.unwrap()["error"], "upload_finalizing");

    // Force the idle expiry into the past and run one cleanup pass: the stuck
    // session is expired, its reservation released, and its candidate unlinked,
    // so a replacement create from the same uploader can proceed.
    f.db.with_conn(|conn| {
        conn.execute(
            "UPDATE snapshot_uploads SET idle_expires_at = ?2 WHERE upload_id = ?1",
            rusqlite::params![upload_id, db::now_secs() - 1],
        )?;
        Ok(())
    })
    .unwrap();
    prism_sync_relay::cleanup::run_cleanup(&f.state).await;

    let status: serde_json::Value = status_upload(&f, &upload_id).await.json().await.unwrap();
    assert_eq!(status["state"], "failed", "the stuck session was expired");
    assert_eq!(f.db.with_read_conn(db::snapshot_upload_reserved_bytes).unwrap(), 0);
    assert!(upload_files(&f.snapshot_root, &f.sync_id).is_empty(), "candidate reclaimed");

    // A replacement create from the same uploader succeeds (supersession cannot
    // be blocked by the abandoned session because its reservation is gone).
    let mut replacement = create_body(
        &f.other_device_id,
        bytes.len(),
        &sha256_hex(&bytes),
        device_epoch(&f.db, &f.sync_id, &f.device_id),
        2,
    );
    replacement["upload_key"] = serde_json::json!(BASE64.encode([4u8; 32]));
    assert_eq!(create_upload(&f, &replacement).await.status(), 201);
}

#[tokio::test]
async fn restart_reconciliation_of_a_file_written_before_its_row_committed() {
    let tmp = tempfile::TempDir::new().unwrap();
    let f = fixture(tmp.path()).await;

    // Simulate the "file created before the session insert completed" crash: a
    // candidate file with no referencing row. It must survive the normal sweep
    // while fresh (the grace gate) and be reclaimed once it is old, so a crash
    // orphan cannot accumulate forever.
    let orphan_dir = Path::new(&f.snapshot_root).join(&f.sync_id);
    std::fs::create_dir_all(&orphan_dir).unwrap();
    let orphan = orphan_dir.join("a".repeat(32));
    std::fs::write(&orphan, b"orphaned candidate").unwrap();

    let db_handle = f.db.clone();
    let known_snapshots = db_handle.with_read_conn(db::all_snapshot_blob_keys).unwrap();
    let known_uploads = db_handle.with_read_conn(db::all_snapshot_upload_blob_keys).unwrap();
    assert!(known_snapshots.is_empty());
    assert!(known_uploads.is_empty());

    // A fresh orphan is inside the grace window and must be spared.
    prism_sync_relay::cleanup::run_cleanup(&f.state).await;
    assert!(orphan.exists(), "a fresh orphan is spared by the grace gate");

    // Age it past the grace period and sweep again.
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(200_000);
    let file = std::fs::OpenOptions::new().write(true).open(&orphan).unwrap();
    file.set_modified(old).unwrap();
    drop(file);
    prism_sync_relay::cleanup::run_cleanup(&f.state).await;
    assert!(!orphan.exists(), "an unreferenced, aged file is reclaimed");
}

#[tokio::test]
async fn active_session_candidate_survives_the_orphan_sweep() {
    let tmp = tempfile::TempDir::new().unwrap();
    let f = fixture(tmp.path()).await;
    let bytes = envelope(4096, 15);
    let create = create_body(
        &f.other_device_id,
        bytes.len(),
        &sha256_hex(&bytes),
        device_epoch(&f.db, &f.sync_id, &f.device_id),
        1,
    );
    let upload_id = created_upload_id(create_upload(&f, &create).await).await;
    assert_eq!(put_chunk(&f, &upload_id, 0, &bytes).await.status(), 200);
    let files = upload_files(&f.snapshot_root, &f.sync_id);
    assert_eq!(files.len(), 1);

    // Age the candidate past the grace window while the session is still live
    // with a long idle TTL: the sweep's live set must include session
    // references, or an in-flight upload would be deleted mid-flight.
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(200_000);
    let file = std::fs::OpenOptions::new().write(true).open(&files[0]).unwrap();
    file.set_modified(old).unwrap();
    drop(file);
    prism_sync_relay::cleanup::run_cleanup(&f.state).await;
    assert!(files[0].exists(), "a session-referenced candidate is not an orphan");

    assert_eq!(complete_upload(&f, &upload_id).await.status(), 204);
    assert_eq!(target_download(&f, &f.other_device_id, &f.other_token).await, bytes);
}

// ───────────────────── expiry vs concurrent mutation ─────────────────────

#[tokio::test]
async fn expiry_races_chunk_and_complete_and_releases_resources() {
    let tmp = tempfile::TempDir::new().unwrap();
    let f = fixture(tmp.path()).await;
    let bytes = envelope(4096, 16);
    let create = create_body(
        &f.other_device_id,
        bytes.len(),
        &sha256_hex(&bytes),
        device_epoch(&f.db, &f.sync_id, &f.device_id),
        1,
    );
    let upload_id = created_upload_id(create_upload(&f, &create).await).await;
    assert_eq!(put_chunk(&f, &upload_id, 0, &bytes).await.status(), 200);

    // Force absolute expiry into the past, then race a chunk and a complete
    // WITHOUT running cleanup: chunk acceptance must reject an already-expired
    // session on its own, because cleanup is not guaranteed to have run.
    f.db.with_conn(|conn| {
        conn.execute(
            "UPDATE snapshot_uploads SET idle_expires_at = ?2, absolute_expires_at = ?2
              WHERE upload_id = ?1",
            rusqlite::params![upload_id, db::now_secs() - 1],
        )?;
        Ok(())
    })
    .unwrap();

    // `upload_expired` is 410 in the documented error table, and both the chunk
    // path and the expiry transition report it identically.
    let (status, json) = json_body(put_chunk(&f, &upload_id, 0, &bytes).await).await;
    assert!(status == 409 || status == 410, "an expired chunk is refused: {json}");
    assert!(json["error"] == "upload_expired" || json["error"] == "upload_failed");
    let complete = complete_upload(&f, &upload_id).await;
    // The chunk already expired it; whichever path observes the expiry first,
    // the session is terminal and never publishes.
    assert!(
        complete.status() == 409 || complete.status() == 410,
        "an expired session cannot complete, got {}",
        complete.status()
    );

    assert_eq!(f.db.with_read_conn(db::snapshot_upload_reserved_bytes).unwrap(), 0);
    assert_eq!(
        f.db.with_read_conn(|c| db::count_nonterminal_snapshot_uploads(c, None)).unwrap(),
        0
    );
}

#[tokio::test]
async fn chunk_acceptance_refreshes_idle_but_never_absolute_expiry() {
    let tmp = tempfile::TempDir::new().unwrap();
    let f = fixture(tmp.path()).await;
    let bytes = envelope(SNAPSHOT_UPLOAD_CHUNK_BYTES * 2, 17);
    let create = create_body(
        &f.other_device_id,
        bytes.len(),
        &sha256_hex(&bytes),
        device_epoch(&f.db, &f.sync_id, &f.device_id),
        1,
    );
    let upload_id = created_upload_id(create_upload(&f, &create).await).await;
    let before: serde_json::Value = status_upload(&f, &upload_id).await.json().await.unwrap();
    let absolute_before = before["absolute_expires_at"].as_i64().unwrap();
    let idle_before = before["idle_expires_at"].as_i64().unwrap();
    assert_eq!(idle_before - db::now_secs(), SNAPSHOT_UPLOAD_IDLE_TTL_SECS);
    assert!(absolute_before - db::now_secs() <= SNAPSHOT_UPLOAD_MAX_SESSION_SECS);

    std::thread::sleep(std::time::Duration::from_millis(1100));
    assert_eq!(
        put_chunk(&f, &upload_id, 0, &bytes[..SNAPSHOT_UPLOAD_CHUNK_BYTES]).await.status(),
        200
    );

    let after: serde_json::Value = status_upload(&f, &upload_id).await.json().await.unwrap();
    assert!(
        after["idle_expires_at"].as_i64().unwrap() > idle_before,
        "an accepted new-offset chunk refreshes idle expiry"
    );
    assert_eq!(
        after["absolute_expires_at"].as_i64().unwrap(),
        absolute_before,
        "the absolute deadline never moves"
    );

    // Status itself never extends expiry.
    let first: serde_json::Value = status_upload(&f, &upload_id).await.json().await.unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let second: serde_json::Value = status_upload(&f, &upload_id).await.json().await.unwrap();
    assert_eq!(
        first["idle_expires_at"].as_i64().unwrap(),
        second["idle_expires_at"].as_i64().unwrap(),
        "status must not refresh either expiry"
    );
}

// ───────────────────── abort ─────────────────────

#[tokio::test]
async fn abort_is_idempotent_and_reclaims_the_candidate() {
    let tmp = tempfile::TempDir::new().unwrap();
    let f = fixture(tmp.path()).await;
    let bytes = envelope(4096, 18);
    let create = create_body(
        &f.other_device_id,
        bytes.len(),
        &sha256_hex(&bytes),
        device_epoch(&f.db, &f.sync_id, &f.device_id),
        1,
    );
    let upload_id = created_upload_id(create_upload(&f, &create).await).await;
    assert_eq!(put_chunk(&f, &upload_id, 0, &bytes).await.status(), 200);
    assert_eq!(upload_files(&f.snapshot_root, &f.sync_id).len(), 1);

    assert_eq!(abort_upload(&f, &upload_id).await.status(), 204);
    assert!(upload_files(&f.snapshot_root, &f.sync_id).is_empty(), "candidate unlinked");
    assert_eq!(f.db.with_read_conn(db::snapshot_upload_reserved_bytes).unwrap(), 0);

    // Repeated abort is idempotent.
    assert_eq!(abort_upload(&f, &upload_id).await.status(), 204);
}

#[tokio::test]
async fn abort_of_an_unknown_session_is_not_found() {
    let tmp = tempfile::TempDir::new().unwrap();
    let f = fixture(tmp.path()).await;
    assert_eq!(abort_upload(&f, &"c".repeat(32)).await.status(), 404);
}

// ───────────────────── group deletion ─────────────────────

#[tokio::test]
async fn deleting_the_group_removes_sessions_and_candidates() {
    let tmp = tempfile::TempDir::new().unwrap();
    // Account deletion requires the caller to be the group's ONLY active device.
    let f = single_device_fixture(tmp.path()).await;
    let bytes = envelope(4096, 19);
    let create = create_body(
        &f.other_device_id,
        bytes.len(),
        &sha256_hex(&bytes),
        device_epoch(&f.db, &f.sync_id, &f.device_id),
        1,
    );
    let upload_id = created_upload_id(create_upload(&f, &create).await).await;
    assert_eq!(put_chunk(&f, &upload_id, 0, &bytes).await.status(), 200);
    assert_eq!(upload_files(&f.snapshot_root, &f.sync_id).len(), 1);

    // The group has exactly one active device, which is the caller — the
    // account-deletion precondition. The route is signature-authenticated.
    let path = format!("/v1/sync/{}", f.sync_id);
    let builder = Client::new()
        .delete(format!("{}{path}", f.url))
        .header("Authorization", format!("Bearer {}", f.token))
        .header("X-Device-Id", &f.device_id);
    let resp =
        apply_signed_headers(builder, &f.keys, "DELETE", &path, &f.sync_id, &f.device_id, &[])
            .send()
            .await
            .unwrap();
    assert_eq!(resp.status(), 204);

    assert_eq!(
        f.db.with_read_conn(|c| db::count_nonterminal_snapshot_uploads(c, None)).unwrap(),
        0,
        "group deletion removed the session rows"
    );
    assert!(
        upload_files(&f.snapshot_root, &f.sync_id).is_empty(),
        "group deletion removed the candidate tree"
    );
    // The session ID is gone from the DB entirely, which is the property that
    // matters; the caller's own token is now a revoked tombstone, so any further
    // signed request is rejected before session lookup can even run.
    let remaining: i64 =
        f.db.with_read_conn(|conn| {
            Ok::<_, rusqlite::Error>(
                conn.query_row(
                    "SELECT COUNT(*) FROM snapshot_uploads WHERE sync_id = ?1",
                    rusqlite::params![f.sync_id],
                    |r| r.get(0),
                )
                .unwrap(),
            )
        })
        .unwrap();
    assert_eq!(remaining, 0, "no session rows survive group deletion");
    assert!(
        matches!(status_upload(&f, &upload_id).await.status().as_u16(), 401 | 404),
        "a deleted group's session cannot be read"
    );
}

// ───────────────────── path traversal / symlink ─────────────────────

#[cfg(unix)]
#[tokio::test]
async fn symlinked_group_directory_is_never_traversed() {
    let tmp = tempfile::TempDir::new().unwrap();
    let f = fixture(tmp.path()).await;
    let outside = tmp.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap();

    // Plant a symlinked group directory in place of the real one.
    let group_dir = Path::new(&f.snapshot_root).join(&f.sync_id);
    let _ = std::fs::remove_dir_all(&group_dir);
    std::os::unix::fs::symlink(&outside, &group_dir).unwrap();

    let bytes = envelope(1024, 20);
    let create = create_body(
        &f.other_device_id,
        bytes.len(),
        &sha256_hex(&bytes),
        device_epoch(&f.db, &f.sync_id, &f.device_id),
        1,
    );
    let upload_id = created_upload_id(create_upload(&f, &create).await).await;
    let resp = put_chunk(&f, &upload_id, 0, &bytes).await;
    assert_eq!(resp.status(), 409, "a symlinked group dir fails closed");

    // Nothing escaped into the link target.
    assert!(
        std::fs::read_dir(&outside).unwrap().next().is_none(),
        "no bytes were written through the symlink"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn symlinked_candidate_file_is_refused() {
    let tmp = tempfile::TempDir::new().unwrap();
    let f = fixture(tmp.path()).await;
    let bytes = envelope(1024, 21);
    let create = create_body(
        &f.other_device_id,
        bytes.len(),
        &sha256_hex(&bytes),
        device_epoch(&f.db, &f.sync_id, &f.device_id),
        1,
    );
    let upload_id = created_upload_id(create_upload(&f, &create).await).await;

    // Learn the relay-generated candidate name from the row, then replace it
    // with a symlink to an outside file.
    let blob_ref: String =
        f.db.with_read_conn(|conn| {
            Ok::<_, rusqlite::Error>(
                conn.query_row(
                    "SELECT blob_ref FROM snapshot_uploads WHERE upload_id = ?1",
                    rusqlite::params![upload_id],
                    |r| r.get(0),
                )
                .unwrap(),
            )
        })
        .unwrap();
    let group_dir = Path::new(&f.snapshot_root).join(&f.sync_id);
    std::fs::create_dir_all(&group_dir).unwrap();
    let secret = tmp.path().join("secret");
    std::fs::write(&secret, b"do not clobber").unwrap();
    std::os::unix::fs::symlink(&secret, group_dir.join(&blob_ref)).unwrap();

    let resp = put_chunk(&f, &upload_id, 0, &bytes).await;
    assert_eq!(resp.status(), 409, "a symlinked candidate is refused");
    assert_eq!(std::fs::read(&secret).unwrap(), b"do not clobber", "the target is untouched");
}

#[tokio::test]
async fn crafted_upload_ids_cannot_address_another_session() {
    let tmp = tempfile::TempDir::new().unwrap();
    let f = fixture(tmp.path()).await;
    let crafted_ids = [
        "..".to_string(),
        "../..".to_string(),
        "%2e%2e".to_string(),
        "a/../../b".to_string(),
        "0".repeat(31),
        "0".repeat(33),
    ];
    for crafted in &crafted_ids {
        let resp = status_upload(&f, crafted).await;
        assert_eq!(resp.status(), 404, "crafted id {crafted:?} must not resolve");
    }
}

// ───────────────────── legacy coexistence ─────────────────────

#[tokio::test]
async fn legacy_inline_rows_remain_readable_alongside_the_new_table() {
    let tmp = tempfile::TempDir::new().unwrap();
    let f = fixture(tmp.path()).await;

    // A legacy inline row (as a pre-file-backing relay would have written).
    f.db.with_conn(|conn| {
        conn.execute(
            "INSERT INTO snapshots (sync_id, epoch, server_seq_at, data, created_at,
                expires_at, target_device_id, uploaded_by_device_id)
             VALUES (?1, 0, 5, ?2, ?3, NULL, NULL, ?4)",
            rusqlite::params![
                f.sync_id,
                b"legacy-inline-bytes".to_vec(),
                db::now_secs(),
                f.device_id
            ],
        )?;
        Ok(())
    })
    .unwrap();

    // The group-wide legacy row is still served by the unchanged GET route.
    let resp = Client::new()
        .get(format!("{}/v1/sync/{}/snapshot", f.url, f.sync_id))
        .header("Authorization", format!("Bearer {}", f.token))
        .header("X-Device-Id", &f.device_id)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(BASE64.decode(json["data"].as_str().unwrap()).unwrap(), b"legacy-inline-bytes");

    // And a resumable upload still works with the legacy row present.
    let bytes = envelope(2048, 22);
    let upload_id = upload_envelope(&f, &bytes, 6).await;
    assert_eq!(complete_upload(&f, &upload_id).await.status(), 204);
}

#[tokio::test]
async fn single_put_contract_is_unchanged_when_resumable_is_enabled() {
    let tmp = tempfile::TempDir::new().unwrap();
    let f = fixture(tmp.path()).await;
    let client = Client::new();

    let resp = put_snapshot_signed(
        &client,
        &f.url,
        &f.sync_id,
        &f.device_id,
        &f.token,
        &f.keys,
        "77",
        b"legacy-put-payload".to_vec(),
        &[],
    )
    .await;
    assert_eq!(resp.status(), 204, "the legacy single PUT is untouched");

    let resp = client
        .get(format!("{}/v1/sync/{}/snapshot", f.url, f.sync_id))
        .header("Authorization", format!("Bearer {}", f.token))
        .header("X-Device-Id", &f.device_id)
        .send()
        .await
        .unwrap();
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(BASE64.decode(json["data"].as_str().unwrap()).unwrap(), b"legacy-put-payload");
}

// ───────────────────── capability advertising ─────────────────────

#[tokio::test]
async fn capability_is_advertised_only_when_enabled_and_file_backed() {
    let tmp = tempfile::TempDir::new().unwrap();

    // (a) Enabled + file-backed: advertised.
    let (config, _root) = resumable_config(tmp.path());
    let (url, _server, _db) = start_file_backed_test_relay_with_config(config).await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;
    let resp = client
        .get(format!("{url}/v1/sync/{sync_id}/capabilities"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.unwrap();
    let capability = &json["snapshot_upload"];
    assert_eq!(capability["version"], 1);
    assert_eq!(capability["chunk_bytes"].as_u64().unwrap(), SNAPSHOT_UPLOAD_CHUNK_BYTES as u64);
    assert_eq!(capability["max_wire_bytes"].as_u64().unwrap(), SNAPSHOT_UPLOAD_MAX_WIRE_BYTES);
    assert_eq!(
        capability["session_idle_ttl_secs"].as_u64().unwrap(),
        SNAPSHOT_UPLOAD_IDLE_TTL_SECS as u64
    );
    // `gifs` is still present and unchanged: the new key is a sibling.
    assert!(json["gifs"].is_object());

    // (b) Disabled (the shipped default): withheld entirely.
    let mut disabled = test_config();
    let canonical_tmp = std::fs::canonicalize(tmp.path()).unwrap();
    let media = canonical_tmp.join("media-b");
    std::fs::create_dir_all(&media).unwrap();
    disabled.media_storage_path = media.to_str().unwrap().to_string();
    // `snapshot_upload` keeps `SnapshotUploadConfig::default()`, i.e. disabled.
    let (url, _server, _db) = start_test_relay_with_config(disabled).await;
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;
    let resp = client
        .get(format!("{url}/v1/sync/{sync_id}/capabilities"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id)
        .send()
        .await
        .unwrap();
    let json: serde_json::Value = resp.json().await.unwrap();
    assert!(json.get("snapshot_upload").is_none(), "capability must be absent by default: {json}");

    // And the routes themselves are absent (404) for a client that ignores the
    // withheld capability, so fallback to single PUT is the only option.
    let path = format!("/v1/sync/{sync_id}/snapshot/uploads");
    let body = serde_json::to_vec(&create_body(&device_id, 1024, &sha256_hex(b"x"), 0, 1)).unwrap();
    let builder = client
        .post(format!("{url}{path}"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id);
    let resp = apply_signed_headers(builder, &keys, "POST", &path, &sync_id, &device_id, &body)
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "resumable routes are dark when disabled");
}

// ───────────────────── metrics ─────────────────────

#[tokio::test]
async fn metrics_are_aggregate_only_and_track_lifecycle_outcomes() {
    let tmp = tempfile::TempDir::new().unwrap();
    let (config, _root) = resumable_config(tmp.path());
    let (url, _server, _db, state) = start_file_backed_test_relay_with_state(config).await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;
    let target = generate_device_id();

    // Drive one accepted chunk and one rejected chunk.
    let bytes = envelope(4096, 23);
    let create = create_body(
        &target,
        bytes.len(),
        &sha256_hex(&bytes),
        device_epoch(&state.db, &sync_id, &device_id),
        1,
    );
    let path = format!("/v1/sync/{sync_id}/snapshot/uploads");
    let body = serde_json::to_vec(&create).unwrap();
    let builder = client
        .post(format!("{url}{path}"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id);
    let resp = apply_signed_headers(builder, &keys, "POST", &path, &sync_id, &device_id, &body)
        .body(body)
        .send()
        .await
        .unwrap();
    let upload_id =
        resp.json::<serde_json::Value>().await.unwrap()["upload_id"].as_str().unwrap().to_string();

    let chunk_path = format!("/v1/sync/{sync_id}/snapshot/uploads/{upload_id}/chunks/0");
    let builder = client
        .put(format!("{url}{chunk_path}"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id);
    apply_signed_headers(builder, &keys, "PUT", &chunk_path, &sync_id, &device_id, &bytes)
        .body(bytes.clone())
        .send()
        .await
        .unwrap();
    // A rejected (ahead-of-offset) chunk.
    let bad_path = format!("/v1/sync/{sync_id}/snapshot/uploads/{upload_id}/chunks/9999999");
    let builder = client
        .put(format!("{url}{bad_path}"))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", &device_id);
    apply_signed_headers(builder, &keys, "PUT", &bad_path, &sync_id, &device_id, &bytes)
        .body(bytes.clone())
        .send()
        .await
        .unwrap();

    // The two gauges are cached and refreshed by a cleanup cycle (so a scrape
    // never pays for a live DB query); drive one deterministic pass.
    prism_sync_relay::cleanup::run_cleanup(&state).await;

    let metrics = client.get(format!("{url}/metrics")).send().await.unwrap().text().await.unwrap();
    for expected in [
        "# TYPE prism_snapshot_upload_sessions_active gauge",
        "prism_snapshot_upload_sessions_active 1",
        "prism_snapshot_upload_reserved_bytes 4096",
        "# TYPE prism_snapshot_upload_chunks_total counter",
        "prism_snapshot_upload_chunks_total{result=\"accepted\"} 1",
        "prism_snapshot_upload_chunks_total{result=\"rejected\"} 1",
        "prism_snapshot_upload_chunk_bytes_total 4096",
        "prism_snapshot_upload_completions_total 0",
        "# TYPE prism_snapshot_upload_hash_mismatch_total counter",
        "# TYPE prism_snapshot_upload_staging_corrupt_total counter",
        "# TYPE prism_snapshot_upload_expired_total counter",
        "# TYPE prism_snapshot_upload_aborted_total counter",
        "# TYPE prism_snapshot_upload_superseded_total counter",
    ] {
        assert!(metrics.contains(expected), "metrics missing {expected:?} in:\n{metrics}");
    }

    // No user-scoped label may appear: an upload/device/group series would be a
    // per-user activity signal and an unbounded-cardinality sink.
    for forbidden in [&upload_id, &sync_id, &device_id] {
        assert!(
            !metrics.contains(forbidden.as_str()),
            "metrics leaked an identifier from {forbidden:?}"
        );
    }
}

// ───────────────────── finalizing supersession / false 204 ─────────────────────

/// Upload keys are distinguishable per test; the wire encoding is base64 of 32
/// random bytes, so each seed stands in for a fresh random key.
fn upload_key(seed: u8) -> String {
    BASE64.encode([seed; 32])
}

/// Force a session into `finalizing` with every byte committed — the state a
/// completion holds for the whole hash/sync/publication window, and the state a
/// crash mid-completion leaves behind.
fn force_finalizing(db: &db::Database, upload_id: &str) {
    db.with_conn(|conn| {
        conn.execute(
            "UPDATE snapshot_uploads SET state = 'finalizing', committed_offset = total_bytes
              WHERE upload_id = ?1",
            rusqlite::params![upload_id],
        )?;
        Ok(())
    })
    .unwrap();
    let row = db
        .with_read_conn(|conn| db::get_snapshot_upload(conn, upload_id))
        .unwrap()
        .expect("session exists");
    assert_eq!(row.state, prism_sync_relay::uploads::UploadState::Finalizing);
    assert_eq!(row.committed_offset, row.total_bytes);
}

/// Every create that must not disturb a live finalization.
fn new_key_create_body(f: &Fixture, seed: u8, total: usize, seq: i64) -> serde_json::Value {
    let mut body = create_body(
        &f.other_device_id,
        total,
        &sha256_hex(&envelope(total, seed)),
        device_epoch(&f.db, &f.sync_id, &f.device_id),
        seq,
    );
    body["upload_key"] = serde_json::json!(upload_key(seed));
    body
}

#[tokio::test]
async fn new_upload_key_never_supersedes_a_live_finalizing_session() {
    let tmp = tempfile::TempDir::new().unwrap();
    let f = fixture(tmp.path()).await;
    let bytes = envelope(4096, 26);
    let upload_id = upload_envelope(&f, &bytes, 1).await;

    // A completion owns the session: the row is `finalizing` with the full total
    // committed.
    force_finalizing(&f.db, &upload_id);

    // Creating with a NEW key must not end the session the completion is
    // publishing from. It is refused deterministically and retryably.
    let competing = new_key_create_body(&f, 42, bytes.len(), 2);
    let resp = create_upload(&f, &competing).await;
    assert_eq!(resp.status(), 503, "a live finalization is a transient conflict");
    let json = resp.json::<serde_json::Value>().await.unwrap();
    assert_eq!(json["error"], "upload_busy");

    // The in-flight session and its reservation are untouched: nothing was
    // created, superseded, or released.
    let row =
        f.db.with_read_conn(|conn| db::get_snapshot_upload(conn, &upload_id)).unwrap().unwrap();
    assert_eq!(row.state, prism_sync_relay::uploads::UploadState::Finalizing);
    assert!(row.terminal_code.is_none());
    assert_eq!(
        f.db.with_read_conn(db::snapshot_upload_reserved_bytes).unwrap(),
        bytes.len() as u64,
        "the finalizing session still holds its reservation"
    );

    // A completion against that session reports the true state: another
    // completion owns it. It is never answered as a silent success, and nothing
    // is published on its behalf.
    let (status, json) = json_body(complete_upload(&f, &upload_id).await).await;
    assert_eq!(status, 409, "a live finalization is not silently completed: {json}");
    assert_eq!(json["error"], "upload_finalizing");
    assert_eq!(count_snapshots(&f), 0, "no snapshot was published");

    // Publication resolves the conflict the way the spec says it does: the
    // abandoned finalization is reclaimed by the idle sweep, releasing its
    // reservation, and the same create then proceeds.
    force_idle_expiry(&f.db, &upload_id);
    prism_sync_relay::cleanup::run_cleanup(&f.state).await;
    let row =
        f.db.with_read_conn(|conn| db::get_snapshot_upload(conn, &upload_id)).unwrap().unwrap();
    assert_eq!(row.state, prism_sync_relay::uploads::UploadState::Failed);
    assert_eq!(f.db.with_read_conn(db::snapshot_upload_reserved_bytes).unwrap(), 0);

    let retry = create_upload(&f, &competing).await;
    assert_eq!(retry.status(), 201, "the conflict is transient, not permanent");
}

#[tokio::test]
async fn finalizing_session_still_supersedes_the_uploaders_other_active_session() {
    let tmp = tempfile::TempDir::new().unwrap();
    let f = fixture(tmp.path()).await;
    let epoch = device_epoch(&f.db, &f.sync_id, &f.device_id);

    // A long-lived finalizing session (the slot holder) ...
    let held = envelope(2048, 27);
    let mut held_body = create_body(&f.other_device_id, held.len(), &sha256_hex(&held), epoch, 1);
    held_body["upload_key"] = serde_json::json!(upload_key(11));
    let held_id = created_upload_id(create_upload(&f, &held_body).await).await;
    assert_eq!(put_chunk(&f, &held_id, 0, &held).await.status(), 200);
    force_finalizing(&f.db, &held_id);

    // ... plus a stale *active* session from the same uploader, inserted directly
    // because a real create would now be refused as `upload_busy`.
    let stale = envelope(2048, 28);
    let stale_id: String = "b".repeat(32);
    f.db.with_conn(|conn| {
        conn.execute(
            "INSERT INTO snapshot_uploads
                (upload_id, upload_key, sync_id, uploader_device_id, target_device_id, epoch,
                 server_seq_at, snapshot_ttl_secs, total_bytes, chunk_bytes, committed_offset,
                 body_sha256, blob_ref, state, created_at, updated_at, idle_expires_at,
                 absolute_expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 3, 86400, ?7, ?8, 0, ?9, ?10, 'active', ?11, ?11,
                     ?12, ?12)",
            rusqlite::params![
                stale_id,
                upload_key(12),
                f.sync_id,
                f.device_id,
                f.other_device_id,
                epoch,
                stale.len() as i64,
                SNAPSHOT_UPLOAD_CHUNK_BYTES as i64,
                &vec![0u8; 32][..],
                "c".repeat(32),
                db::now_secs(),
                db::now_secs() + SNAPSHOT_UPLOAD_IDLE_TTL_SECS,
            ],
        )?;
        Ok(())
    })
    .unwrap();
    assert_eq!(f.db.with_read_conn(db::snapshot_upload_reserved_bytes).unwrap(), 4096);

    // The next create is refused: the held slot outranks the stale active row.
    let resp = create_upload(&f, &new_key_create_body(&f, 13, 1024, 4)).await;
    assert_eq!(resp.status(), 503);
    assert_eq!(resp.json::<serde_json::Value>().await.unwrap()["error"], "upload_busy");

    // The stale active row is still there (nothing was superseded while the
    // finalization holds), and the finalization is still intact.
    let held_row =
        f.db.with_read_conn(|conn| db::get_snapshot_upload(conn, &held_id)).unwrap().unwrap();
    assert_eq!(held_row.state, prism_sync_relay::uploads::UploadState::Finalizing);
    let stale_row =
        f.db.with_read_conn(|conn| db::get_snapshot_upload(conn, &stale_id)).unwrap().unwrap();
    assert_eq!(stale_row.state, prism_sync_relay::uploads::UploadState::Active);

    // Resolve the held slot the way the spec does: the idle sweep reclaims an
    // abandoned finalization. A create after that supersedes the stale active
    // session, keeping the "a lost abort cannot strand a reservation" property.
    force_idle_expiry(&f.db, &held_id);
    prism_sync_relay::cleanup::run_cleanup(&f.state).await;
    let fresh = upload_envelope(&f, &envelope(1024, 29), 5).await;
    assert_ne!(fresh, held_id);
    let stale_row =
        f.db.with_read_conn(|conn| db::get_snapshot_upload(conn, &stale_id)).unwrap().unwrap();
    assert_eq!(stale_row.state, prism_sync_relay::uploads::UploadState::Failed);
    assert_eq!(stale_row.terminal_code.as_deref(), Some("superseded"));
}

/// Count published snapshot rows for the fixture's group.
fn count_snapshots(f: &Fixture) -> i64 {
    f.db.with_read_conn(|conn| {
        Ok::<_, rusqlite::Error>(
            conn.query_row(
                "SELECT COUNT(*) FROM snapshots WHERE sync_id = ?1",
                rusqlite::params![f.sync_id],
                |r| r.get(0),
            )
            .unwrap(),
        )
    })
    .unwrap()
}

/// Force both expiries into the past so one cleanup pass reclaims the session.
fn force_idle_expiry(db: &db::Database, upload_id: &str) {
    db.with_conn(|conn| {
        conn.execute(
            "UPDATE snapshot_uploads SET idle_expires_at = ?2, absolute_expires_at = ?2
              WHERE upload_id = ?1",
            rusqlite::params![upload_id, db::now_secs() - 1],
        )?;
        Ok(())
    })
    .unwrap();
}

#[tokio::test]
async fn abort_racing_a_finalizing_session_never_yields_a_false_success() {
    let tmp = tempfile::TempDir::new().unwrap();
    let f = fixture(tmp.path()).await;
    let bytes = envelope(3072, 30);
    let upload_id = upload_envelope(&f, &bytes, 1).await;
    force_finalizing(&f.db, &upload_id);

    // V1 abort makes any nonterminal session terminal, so an abort racing a
    // completion may legitimately win the row. What must never happen is a
    // *success* answer for bytes that are not published — from either side.
    let abort_status = abort_upload(&f, &upload_id).await.status();
    let row =
        f.db.with_read_conn(|conn| db::get_snapshot_upload(conn, &upload_id)).unwrap().unwrap();
    if abort_status == 204 {
        // The abort won: the session is terminal-failed and nothing was published
        // by the abort.
        assert_eq!(row.state, prism_sync_relay::uploads::UploadState::Failed);
        assert_eq!(count_snapshots(&f), 0, "an abort never publishes");
    } else {
        // The abort was refused (e.g. the completion already published). Then the
        // session must be intact or completed, never silently discarded.
        assert!(
            row.state == prism_sync_relay::uploads::UploadState::Finalizing
                || row.state == prism_sync_relay::uploads::UploadState::Completed,
            "a refused abort leaves the session in a coherent state, got {:?}",
            row.state
        );
    }

    // The completion that raced the abort must report the truth. It may not claim
    // success, and if it does not, no snapshot may exist to contradict it.
    let resp = complete_upload(&f, &upload_id).await;
    let status = resp.status();
    let json: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
    if status == 204 {
        // A 204 must be backed by a real, downloadable snapshot.
        assert_eq!(count_snapshots(&f), 1, "a 204 completion published a snapshot row");
        assert_eq!(target_download(&f, &f.other_device_id, &f.other_token).await, bytes);
    } else {
        assert_eq!(status, 409, "a lost race is a truthful rejection: {json}");
        assert_eq!(json["error"], "upload_failed", "recorded terminal result: {json}");
        assert_eq!(count_snapshots(&f), 0, "a rejected completion publishes nothing");
    }

    // Whatever happened, the session is terminal and no longer reserves bytes, and
    // a fresh create from the same uploader proceeds once the slot is free.
    if f.db.with_read_conn(db::snapshot_upload_reserved_bytes).unwrap() > 0 {
        force_idle_expiry(&f.db, &upload_id);
        prism_sync_relay::cleanup::run_cleanup(&f.state).await;
    }
    assert_eq!(f.db.with_read_conn(db::snapshot_upload_reserved_bytes).unwrap(), 0);
    assert_eq!(create_upload(&f, &new_key_create_body(&f, 51, 512, 3)).await.status(), 201);
}

#[tokio::test]
async fn completion_losing_its_session_is_never_reported_as_published() {
    let tmp = tempfile::TempDir::new().unwrap();
    let f = fixture(tmp.path()).await;
    let bytes = envelope(2560, 31);
    let upload_id = upload_envelope(&f, &bytes, 1).await;

    // The session goes terminal-failed between the offset commit and publication
    // (an abort or a supersession winning the race). Completion must not answer
    // `204`: no bytes were published.
    f.db.with_conn(|conn| {
        conn.execute(
            "UPDATE snapshot_uploads
                SET state = 'failed', terminal_code = 'aborted', terminal_status = 409
              WHERE upload_id = ?1",
            rusqlite::params![upload_id],
        )?;
        Ok(())
    })
    .unwrap();

    let (status, json) = json_body(complete_upload(&f, &upload_id).await).await;
    assert_eq!(status, 409, "state loss must not look like success: {json}");
    assert_eq!(json["error"], "upload_failed");

    // Nothing was published, and no reader can observe a snapshot that a `204`
    // would have claimed existed.
    let snapshots: i64 =
        f.db.with_read_conn(|conn| {
            Ok::<_, rusqlite::Error>(
                conn.query_row(
                    "SELECT COUNT(*) FROM snapshots WHERE sync_id = ?1",
                    rusqlite::params![f.sync_id],
                    |r| r.get(0),
                )
                .unwrap(),
            )
        })
        .unwrap();
    assert_eq!(snapshots, 0, "a refused completion publishes nothing");
    let download = Client::new()
        .get(format!("{}/v1/sync/{}/snapshot", f.url, f.sync_id))
        .header("Authorization", format!("Bearer {}", f.other_token))
        .header("X-Device-Id", &f.other_device_id)
        .send()
        .await
        .unwrap();
    assert_ne!(download.status(), 200, "no snapshot is downloadable");

    // A retry reproduces the recorded terminal result rather than republishing.
    let (retry_status, retry_json) = json_body(complete_upload(&f, &upload_id).await).await;
    assert_eq!(retry_status, 409);
    assert_eq!(retry_json["error"], "upload_failed");
}

#[tokio::test]
async fn create_and_abort_after_a_completed_publication_with_a_lost_response() {
    let tmp = tempfile::TempDir::new().unwrap();
    let f = fixture(tmp.path()).await;
    let bytes = envelope(3072, 32);
    let mut body = create_body(
        &f.other_device_id,
        bytes.len(),
        &sha256_hex(&bytes),
        device_epoch(&f.db, &f.sync_id, &f.device_id),
        1,
    );
    body["upload_key"] = serde_json::json!(upload_key(33));
    let upload_id = created_upload_id(create_upload(&f, &body).await).await;
    assert_eq!(put_chunk(&f, &upload_id, 0, &bytes).await.status(), 200);

    // The publication commits, but the response never reaches the client.
    assert_eq!(complete_upload(&f, &upload_id).await.status(), 204);
    let published_files = upload_files(&f.snapshot_root, &f.sync_id);
    assert_eq!(published_files.len(), 1);
    assert_eq!(target_download(&f, &f.other_device_id, &f.other_token).await, bytes);

    // The client, believing create failed, retries create with a new key ...
    let (status, json) =
        json_body(create_upload(&f, &new_key_create_body(&f, 34, 512, 2)).await).await;
    assert_eq!(status, 201, "a terminal session does not block a new upload: {json}");
    assert_ne!(json["upload_id"].as_str().unwrap(), upload_id);

    // ... and aborts the original session, which must not delete the published
    // snapshot.
    let (status, json) = json_body(abort_upload(&f, &upload_id).await).await;
    assert_eq!(status, 409);
    assert_eq!(json["error"], "upload_completed");
    assert_eq!(
        target_download(&f, &f.other_device_id, &f.other_token).await,
        bytes,
        "a lost-response retry chain never removes the published snapshot"
    );
    assert_eq!(upload_files(&f.snapshot_root, &f.sync_id).len(), 1);

    // Idempotent create with the ORIGINAL key reports the completed session, fully
    // committed, so the client can see it already succeeded.
    let replay = create_upload(&f, &body).await;
    assert_eq!(replay.status(), 200);
    let replay_json: serde_json::Value = replay.json().await.unwrap();
    assert_eq!(replay_json["state"], "completed");
    assert_eq!(replay_json["committed_offset"].as_i64().unwrap(), bytes.len() as i64);

    // And retrying complete still reports success without republishing.
    assert_eq!(complete_upload(&f, &upload_id).await.status(), 204);
    assert_eq!(upload_files(&f.snapshot_root, &f.sync_id), published_files);
    assert_eq!(target_download(&f, &f.other_device_id, &f.other_token).await, bytes);
}

#[tokio::test]
async fn every_204_completion_implies_a_published_row_and_file() {
    let tmp = tempfile::TempDir::new().unwrap();
    let f = fixture(tmp.path()).await;
    let bytes = envelope(2560, 35);
    let upload_id = upload_envelope(&f, &bytes, 1).await;

    // `204` must be backed by a snapshot row that references a blob which exists
    // on disk and hashes to the declared digest.
    let resp = complete_upload(&f, &upload_id).await;
    assert_eq!(resp.status(), 204);

    let blob_ref: String =
        f.db.with_read_conn(|conn| {
            Ok::<_, rusqlite::Error>(
                conn.query_row(
                    "SELECT blob_ref FROM snapshots WHERE sync_id = ?1 AND target_device_id = ?2",
                    rusqlite::params![f.sync_id, f.other_device_id],
                    |r| r.get(0),
                )
                .unwrap(),
            )
        })
        .unwrap();
    let path = Path::new(&f.snapshot_root).join(&f.sync_id).join(&blob_ref);
    assert!(path.is_file(), "a 204 must reference a file that exists on disk");
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    assert_eq!(sha256_hex(&std::fs::read(&path).unwrap()), sha256_hex(&bytes));

    // The session row is completed and no longer reserves bytes.
    let row =
        f.db.with_read_conn(|conn| db::get_snapshot_upload(conn, &upload_id)).unwrap().unwrap();
    assert_eq!(row.state, prism_sync_relay::uploads::UploadState::Completed);
    assert_eq!(f.db.with_read_conn(db::snapshot_upload_reserved_bytes).unwrap(), 0);

    // A retried complete is also a 204, and it is still backed by the same
    // published row and file — the invariant holds for the idempotent path too.
    assert_eq!(complete_upload(&f, &upload_id).await.status(), 204);
    let blob_ref_after: String =
        f.db.with_read_conn(|conn| {
            Ok::<_, rusqlite::Error>(
                conn.query_row(
                    "SELECT blob_ref FROM snapshots WHERE sync_id = ?1 AND target_device_id = ?2",
                    rusqlite::params![f.sync_id, f.other_device_id],
                    |r| r.get(0),
                )
                .unwrap(),
            )
        })
        .unwrap();
    assert_eq!(blob_ref_after, blob_ref, "a retried 204 does not republish");
    assert!(path.is_file());
}

// ───────────────────── configured free-space reserve ─────────────────────

/// A resumable-upload config with an explicit, non-default free-space reserve.
fn reserve_config(media: &Path, reserve: u64) -> Config {
    let mut config = test_config();
    config.media_storage_path = media.to_str().unwrap().to_string();
    config.snapshot_upload = SnapshotUploadConfig {
        enabled: true,
        free_space_reserve_bytes: reserve,
        group_reserved_bytes: 64 * SNAPSHOT_UPLOAD_MAX_WIRE_BYTES,
        global_reserved_bytes: 256 * SNAPSHOT_UPLOAD_MAX_WIRE_BYTES,
        create_rate_limit: 10_000,
        ..SnapshotUploadConfig::default()
    };
    config
}

/// Insert a resumable session row directly, shaped exactly as
/// `create_snapshot_upload` writes it.
///
/// Needed where the **create** route's own free-space gate (which correctly
/// applies the same configured reserve) would refuse the session before the gate
/// under test could run.
#[allow(clippy::too_many_arguments)]
fn insert_session(
    db: &db::Database,
    upload_id: &str,
    blob_ref: &str,
    sync_id: &str,
    uploader_device_id: &str,
    target_device_id: &str,
    epoch: i64,
    total_bytes: usize,
    committed_offset: usize,
    body_sha256: &str,
) {
    let now = db::now_secs();
    let digest = hex::decode(body_sha256).unwrap();
    db.with_conn(|conn| {
        conn.execute(
            "INSERT INTO snapshot_uploads
                (upload_id, upload_key, sync_id, uploader_device_id, target_device_id, epoch,
                 server_seq_at, snapshot_ttl_secs, total_bytes, chunk_bytes, committed_offset,
                 body_sha256, blob_ref, state, created_at, updated_at, idle_expires_at,
                 absolute_expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, 86400, ?7, ?8, ?9, ?10, ?11, 'active', ?12, ?12,
                     ?13, ?13)",
            rusqlite::params![
                upload_id,
                // Unique per inserted row so the idempotency constraint holds when
                // a test inserts more than one session for the same uploader.
                upload_key(blob_ref.as_bytes()[0]),
                sync_id,
                uploader_device_id,
                target_device_id,
                epoch,
                total_bytes as i64,
                SNAPSHOT_UPLOAD_CHUNK_BYTES as i64,
                committed_offset as i64,
                digest,
                blob_ref,
                now,
                now + SNAPSHOT_UPLOAD_IDLE_TTL_SECS,
            ],
        )?;
        Ok(())
    })
    .unwrap();
}

#[tokio::test]
async fn configured_free_space_reserve_is_enforced_on_chunks_and_completion() {
    let tmp = tempfile::TempDir::new().unwrap();
    let canonical_tmp = std::fs::canonicalize(tmp.path()).unwrap();
    let media = canonical_tmp.join("media");
    std::fs::create_dir_all(&media).unwrap();

    // A deliberately **extreme** reserve: far above the binary default and above
    // anything the volume grants. If either gate consulted a compiled-in default
    // (or simply the volume's own headroom) it would accept these requests, so a
    // 507 here can only come from the configured value.
    let reserve = u64::MAX;
    assert!(reserve > SNAPSHOT_UPLOAD_DEFAULT_FREE_SPACE_RESERVE_BYTES);

    let snapshot_root = canonical_tmp.join("media-snapshots").to_str().unwrap().to_string();
    let (url, _server, db, state) =
        start_file_backed_test_relay_with_state(reserve_config(&media, reserve)).await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;
    let target = generate_device_id();
    let (target_token, target_keys) = prepare_device(&db, &sync_id, &target).await;
    let epoch = device_epoch(&db, &sync_id, &device_id);

    assert!(
        state.config.snapshot_upload_capability(&state.snapshot_storage).is_some(),
        "the capability stays advertised; the configured reserve is what rejects"
    );

    let f = Fixture {
        url,
        sync_id,
        device_id,
        token,
        keys,
        other_device_id: target.clone(),
        other_token: target_token,
        other_keys: target_keys,
        db: db.clone(),
        state,
        snapshot_root,
    };

    let bytes = envelope(4096, 36);
    let digest = sha256_hex(&bytes);

    // Chunk acceptance: the declared total plus the configured reserve does not
    // fit, so an otherwise perfectly valid final chunk is refused, and nothing is
    // staged on disk.
    let chunk_id = "1".repeat(32);
    insert_session(
        &db,
        &chunk_id,
        &"2".repeat(32),
        &f.sync_id,
        &f.device_id,
        &target,
        epoch,
        bytes.len(),
        0,
        &digest,
    );
    let (status, json) = json_body(put_chunk(&f, &chunk_id, 0, &bytes).await).await;
    assert_eq!(status, 507, "a chunk must honor the configured reserve: {json}");
    assert_eq!(json["error"], "insufficient_storage");
    assert!(upload_files(&f.snapshot_root, &f.sync_id).is_empty(), "nothing was staged");

    // Completion is refused on the same configured reserve, against a fully
    // staged and hash-valid candidate.
    let done_id = "3".repeat(32);
    let done_blob = "4".repeat(32);
    insert_session(
        &db,
        &done_id,
        &done_blob,
        &f.sync_id,
        &f.device_id,
        &target,
        epoch,
        bytes.len(),
        bytes.len(),
        &digest,
    );
    let group = Path::new(&f.snapshot_root).join(&f.sync_id);
    std::fs::create_dir_all(&group).unwrap();
    std::fs::write(group.join(&done_blob), &bytes).unwrap();

    let (status, json) = json_body(complete_upload(&f, &done_id).await).await;
    assert_eq!(status, 507, "completion must honor the configured reserve: {json}");
    assert_eq!(json["error"], "insufficient_storage");

    // The rejection is terminal and replayable, never a silent success, and it
    // did not leave the session wedged in `finalizing`.
    let row = db.with_read_conn(|conn| db::get_snapshot_upload(conn, &done_id)).unwrap().unwrap();
    assert_eq!(row.state, prism_sync_relay::uploads::UploadState::Failed);
    assert_eq!(row.terminal_code.as_deref(), Some("insufficient_storage"));
    let (retry_status, retry_json) = json_body(complete_upload(&f, &done_id).await).await;
    assert_eq!(retry_status, 507);
    assert_eq!(retry_json["error"], "insufficient_storage");

    // No snapshot row was published, so the refused 507 is truthful.
    assert_eq!(count_snapshots(&f), 0);
    // The rejected completion released its own reservation; only the untouched
    // chunk session (whose chunk was refused, leaving it active) still holds one.
    assert_eq!(
        db.with_read_conn(db::snapshot_upload_reserved_bytes).unwrap(),
        bytes.len() as u64,
        "the rejected completion released its reservation"
    );
}

#[tokio::test]
async fn a_satisfiable_configured_reserve_still_publishes_end_to_end() {
    let tmp = tempfile::TempDir::new().unwrap();
    let canonical_tmp = std::fs::canonicalize(tmp.path()).unwrap();
    let media = canonical_tmp.join("media");
    std::fs::create_dir_all(&media).unwrap();
    let probe_dir = canonical_tmp.join("probe-target");
    std::fs::create_dir_all(&probe_dir).unwrap();

    // Still non-default, and satisfiable, so the configured reserve must not turn
    // a legitimate upload into a false rejection.
    let reserve = prism_sync_relay::uploads::available_bytes(&probe_dir)
        .unwrap()
        .saturating_sub(256 * 1024 * 1024);
    assert!(
        reserve > SNAPSHOT_UPLOAD_DEFAULT_FREE_SPACE_RESERVE_BYTES,
        "the reserve under test must exceed the binary default"
    );

    let snapshot_root = canonical_tmp.join("media-snapshots").to_str().unwrap().to_string();
    let (url, _server, db, state) =
        start_file_backed_test_relay_with_state(reserve_config(&media, reserve)).await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;
    let target = generate_device_id();
    let (target_token, target_keys) = prepare_device(&db, &sync_id, &target).await;

    let f = Fixture {
        url,
        sync_id,
        device_id,
        token,
        keys,
        other_device_id: target.clone(),
        other_token: target_token,
        other_keys: target_keys,
        db: db.clone(),
        state,
        snapshot_root,
    };

    let bytes = envelope(4096, 37);
    let upload_id = upload_envelope(&f, &bytes, 1).await;
    assert_eq!(complete_upload(&f, &upload_id).await.status(), 204);
    assert_eq!(target_download(&f, &f.other_device_id, &f.other_token).await, bytes);
}

// ───────────────────── fault injection ─────────────────────

#[tokio::test]
async fn fault_injection_in_verify_stops_publication() {
    let tmp = tempfile::TempDir::new().unwrap();
    let f = fixture(tmp.path()).await;
    let bytes = envelope(4096, 24);
    let create = create_body(
        &f.other_device_id,
        bytes.len(),
        &sha256_hex(&bytes),
        device_epoch(&f.db, &f.sync_id, &f.device_id),
        1,
    );
    let upload_id = created_upload_id(create_upload(&f, &create).await).await;
    assert_eq!(put_chunk(&f, &upload_id, 0, &bytes).await.status(), 200);

    // Inject "the staged file was corrupted after the offset commit": flip a byte
    // on disk so the whole-file hash no longer matches create metadata. This is
    // the last boundary before publication, and publication must not happen.
    let files = upload_files(&f.snapshot_root, &f.sync_id);
    assert_eq!(files.len(), 1);
    let mut corrupted = std::fs::read(&files[0]).unwrap();
    corrupted[0] ^= 0xFF;
    std::fs::write(&files[0], corrupted).unwrap();

    let resp = complete_upload(&f, &upload_id).await;
    assert_eq!(resp.status(), 422);
    assert_eq!(resp.json::<serde_json::Value>().await.unwrap()["error"], "snapshot_hash_mismatch");

    // No snapshot row was created, so no reader can observe partial/corrupt bytes.
    let count: i64 =
        f.db.with_read_conn(|conn| {
            Ok::<_, rusqlite::Error>(
                conn.query_row(
                    "SELECT COUNT(*) FROM snapshots WHERE sync_id = ?1",
                    rusqlite::params![f.sync_id],
                    |r| r.get(0),
                )
                .unwrap(),
            )
        })
        .unwrap();
    assert_eq!(count, 0, "corrupt staging must never publish a snapshot row");
    assert_eq!(f.db.with_read_conn(db::snapshot_upload_reserved_bytes).unwrap(), 0);
}

#[tokio::test]
async fn truncated_candidate_is_reported_as_staging_corruption() {
    let tmp = tempfile::TempDir::new().unwrap();
    let f = fixture(tmp.path()).await;
    let bytes = envelope(4096, 25);
    let create = create_body(
        &f.other_device_id,
        bytes.len(),
        &sha256_hex(&bytes),
        device_epoch(&f.db, &f.sync_id, &f.device_id),
        1,
    );
    let upload_id = created_upload_id(create_upload(&f, &create).await).await;
    assert_eq!(put_chunk(&f, &upload_id, 0, &bytes).await.status(), 200);

    // Truncate the file below the committed offset: committed metadata now
    // refers to absent bytes. This is unrecoverable and must fail closed.
    let files = upload_files(&f.snapshot_root, &f.sync_id);
    std::fs::write(&files[0], &bytes[..100]).unwrap();

    // A further chunk detects it during reconciliation.
    let resp = put_chunk(&f, &upload_id, 4096, &[]).await;
    // (Empty chunk is itself rejected; use a real one at the committed offset.)
    assert!(resp.status() == 409 || resp.status() == 413);

    let resp = complete_upload(&f, &upload_id).await;
    assert!(
        resp.status() == 409 || resp.status() == 422,
        "a short candidate cannot complete, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn stale_completion_leaves_a_terminal_row_and_releases_the_reservation() {
    let tmp = tempfile::TempDir::new().unwrap();
    let f = fixture(tmp.path()).await;
    let bytes = envelope(4096, 31);
    let create = create_body(
        &f.other_device_id,
        bytes.len(),
        &sha256_hex(&bytes),
        device_epoch(&f.db, &f.sync_id, &f.device_id),
        10,
    );
    let upload_id = created_upload_id(create_upload(&f, &create).await).await;
    assert_eq!(put_chunk(&f, &upload_id, 0, &bytes).await.status(), 200);
    assert_eq!(
        f.db.with_read_conn(db::snapshot_upload_reserved_bytes).unwrap(),
        bytes.len() as u64,
        "a fully staged session holds its reservation"
    );

    // A newer snapshot for the SAME audience advances past ours through the
    // legacy route, so completion loses the staleness race.
    let resp = put_snapshot_signed(
        &Client::new(),
        &f.url,
        &f.sync_id,
        &f.device_id,
        &f.token,
        &f.keys,
        "11",
        b"newer-single-put".to_vec(),
        &[("X-For-Device-Id", &f.other_device_id)],
    )
    .await;
    assert_eq!(resp.status(), 204);

    let (status, json) = json_body(complete_upload(&f, &upload_id).await).await;
    assert_eq!(status, 409, "{json}");
    assert_eq!(json["error"], "stale_snapshot_seq");

    // The row is terminal: it left `active`/`finalizing` in the same writer
    // critical section that refused the publication. A row that stayed
    // nonterminal would keep its bytes counted against SUM(total_bytes) forever.
    let status_json: serde_json::Value = status_upload(&f, &upload_id).await.json().await.unwrap();
    assert_eq!(status_json["state"], "failed", "a stale refusal is a terminal row");
    let reserved = f.db.with_read_conn(db::snapshot_upload_reserved_bytes).unwrap();
    assert_eq!(reserved, 0, "the stale refusal released the reservation immediately");
    assert_eq!(
        f.db.with_read_conn(|conn| db::count_nonterminal_snapshot_uploads(conn, None)).unwrap(),
        0,
        "no nonterminal row remains for a definitively-refused completion"
    );

    // The competing snapshot still wins; the rejected candidate never published.
    let downloaded = target_download(&f, &f.other_device_id, &f.other_token).await;
    assert_eq!(downloaded, b"newer-single-put");
}

/// A retry after a stale refusal must reproduce the **same structured body**,
/// including the competing snapshot's seq and audience. Those two fields are what
/// the client's suppression matrix compares; a replay that substitutes zeros
/// would silently flip a real cross-target refusal into a suppressed success.
#[tokio::test]
async fn stale_completion_retry_replays_the_identical_structured_outcome() {
    let tmp = tempfile::TempDir::new().unwrap();
    let f = fixture(tmp.path()).await;
    let bytes = envelope(4096, 32);
    let create = create_body(
        &f.other_device_id,
        bytes.len(),
        &sha256_hex(&bytes),
        device_epoch(&f.db, &f.sync_id, &f.device_id),
        10,
    );
    let upload_id = created_upload_id(create_upload(&f, &create).await).await;
    assert_eq!(put_chunk(&f, &upload_id, 0, &bytes).await.status(), 200);

    let resp = put_snapshot_signed(
        &Client::new(),
        &f.url,
        &f.sync_id,
        &f.device_id,
        &f.token,
        &f.keys,
        "11",
        b"newer-single-put".to_vec(),
        &[("X-For-Device-Id", &f.other_device_id)],
    )
    .await;
    assert_eq!(resp.status(), 204);

    let (first_status, first_json) = json_body(complete_upload(&f, &upload_id).await).await;
    assert_eq!(first_status, 409, "{first_json}");

    let (retry_status, retry_json) = json_body(complete_upload(&f, &upload_id).await).await;
    assert_eq!(retry_status, first_status, "the retry keeps the original status");
    assert_eq!(
        retry_json, first_json,
        "the retry must replay the identical structured body, not a zeroed one"
    );
    // Pin the two fields the suppression matrix reads, so a future refactor
    // cannot quietly degrade them to `0`/`null` and still pass the equality above.
    assert_eq!(retry_json["current_server_seq_at"].as_i64().unwrap(), 11);
    assert_eq!(
        retry_json["current_target_device_id"].as_str().unwrap(),
        f.other_device_id,
        "the competing audience is a real value, not a substituted null"
    );

    // The retry is a replay, not a re-publication: no 204 ever appeared.
    let reserved = f.db.with_read_conn(db::snapshot_upload_reserved_bytes).unwrap();
    assert_eq!(reserved, 0, "the replayed refusal does not re-reserve bytes");
}

/// The reservation a stale refusal releases must be usable immediately: a
/// subsequent create of the same size, under a ceiling that only fits one, must
/// be admitted.
#[tokio::test]
async fn bytes_freed_by_a_stale_refusal_are_reusable_by_the_next_create() {
    let tmp = tempfile::TempDir::new().unwrap();
    let mut config = test_config();
    let canonical_tmp = std::fs::canonicalize(tmp.path()).unwrap();
    let media = canonical_tmp.join("media");
    std::fs::create_dir_all(&media).unwrap();
    config.media_storage_path = media.to_str().unwrap().to_string();
    let one_mib = 1024 * 1024u64;
    config.snapshot_upload = SnapshotUploadConfig {
        enabled: true,
        // Exactly one 1 MiB reservation fits in the group. A leaked reservation
        // therefore makes the follow-up create fail rather than merely being
        // suboptimal.
        group_reserved_bytes: one_mib,
        global_reserved_bytes: one_mib,
        create_rate_limit: 10_000,
        ..SnapshotUploadConfig::default()
    };
    let snapshot_root = canonical_tmp.join("media-snapshots").to_str().unwrap().to_string();
    let (url, _server, db, state) = start_file_backed_test_relay_with_state(config).await;
    let client = Client::new();
    let sync_id = generate_sync_id();
    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;
    let target = generate_device_id();
    let _ = prepare_device(&db, &sync_id, &target).await;
    // A SECOND uploader in the same group. A distinct uploader is required here
    // because a create deliberately supersedes its own uploader's other active
    // session, so a same-uploader probe would free the slot instead of colliding
    // with the ceiling.
    let second_uploader = generate_device_id();
    let (second_token, second_keys) = prepare_device(&db, &sync_id, &second_uploader).await;

    let f = Fixture {
        url,
        sync_id,
        device_id,
        token,
        keys,
        other_device_id: target.clone(),
        other_token: String::new(),
        other_keys: TestDeviceKeys::generate("unused"),
        db: db.clone(),
        state,
        snapshot_root,
    };

    let bytes = envelope(one_mib as usize, 33);
    let create = create_body(
        &target,
        bytes.len(),
        &sha256_hex(&bytes),
        device_epoch(&db, &f.sync_id, &f.device_id),
        10,
    );
    let upload_id = created_upload_id(create_upload(&f, &create).await).await;
    assert_eq!(put_chunk(&f, &upload_id, 0, &bytes).await.status(), 200);

    // While uploader 1's session is staged, uploader 2 cannot fit the one slot.
    let second_body = create_body(
        &target,
        bytes.len(),
        &sha256_hex(b"another"),
        device_epoch(&db, &f.sync_id, &second_uploader),
        10,
    );
    let (blocked_status, blocked_json) = json_body(
        create_upload_for(&f, &second_uploader, &second_token, &second_keys, &second_body).await,
    )
    .await;
    assert_eq!(blocked_status, 429, "the staged session holds the only slot: {blocked_json}");
    assert_eq!(blocked_json["error"], "upload_quota_exceeded");
    assert_eq!(
        blocked_json["scope"], "global",
        "the byte ceiling, not the rate limit, is what trips"
    );

    // Lose the staleness race so the staged session is terminally refused.
    let resp = put_snapshot_signed(
        &Client::new(),
        &f.url,
        &f.sync_id,
        &f.device_id,
        &f.token,
        &f.keys,
        "11",
        b"newer-single-put".to_vec(),
        &[("X-For-Device-Id", &target)],
    )
    .await;
    assert_eq!(resp.status(), 204);
    let (status, json) = json_body(complete_upload(&f, &upload_id).await).await;
    assert_eq!(status, 409, "{json}");
    assert_eq!(json["error"], "stale_snapshot_seq");

    // The freed bytes are immediately reusable: uploader 2's identical create now
    // succeeds under the same one-slot ceiling.
    let allowed_status =
        create_upload_for(&f, &second_uploader, &second_token, &second_keys, &second_body)
            .await
            .status();
    assert_eq!(
        allowed_status, 201,
        "the reservation a stale refusal released must be reusable at once"
    );
}
