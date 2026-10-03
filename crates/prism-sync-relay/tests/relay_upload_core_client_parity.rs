//! Real HTTP parity for resumable snapshot uploads: the **core** client driven
//! through the **real** relay routes.
//!
//! The existing suites each stop short of this seam:
//!
//! - `relay_upload_tests.rs` pins the relay's HTTP contract with hand-rolled
//!   `reqwest` calls and hand-applied signed headers;
//! - `prism-sync-core/tests/resumable_snapshot_upload_tests.rs` pins the
//!   uploader's state machine against an in-memory transport double.
//!
//! Neither crosses the boundary, so nothing today proves that the two
//! independently tested implementations agree on canonical paths, the signed
//! request framing, the capability shape, or the exact bytes that end up
//! published. This file does: a real `prism_sync_core::relay::ServerRelay` (the
//! production transport, which signs every request itself) talks to a real
//! `prism-sync-relay` router over a real socket, and a real
//! `SnapshotUploader` drives a multi-chunk upload through the real routes.
//!
//! Nothing here hand-rolls a signed header or calls an upload route directly.
//! The only raw HTTP is the closing `GET /v1/sync/{sync_id}/snapshot`, which is
//! deliberately the request a receiving device actually makes. The one test
//! that injects a fault wraps the real transport and discards an already-issued
//! response; it never re-signs or re-routes anything.
//!
//! Capability stays dark by default: this file configures its own relay with
//! `enabled: true` over a temp root, exactly as `relay_upload_tests.rs` does, so
//! no production code changes to make the feature reachable.

mod common;

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use reqwest::Client;

use base64::Engine as _;

use prism_sync_core::batch_signature;
use prism_sync_core::relay::ServerRelay;
use prism_sync_core::snapshot_upload::{
    CapabilityUnavailableReason, ChunkResponse, CreateUploadRequest, CreateUploadResponse,
    ResumableSnapshotTransport, ResumableUploadError, SnapshotUploadCapability,
    SnapshotUploadOutcome, SnapshotUploadRequest, SnapshotUploadRetryPolicy, SnapshotUploader,
    UploadStatusResponse,
};
use prism_sync_relay::config::{Config, SnapshotUploadConfig};
use prism_sync_relay::db;
use prism_sync_relay::uploads::{SNAPSHOT_UPLOAD_CHUNK_BYTES, SNAPSHOT_UPLOAD_MAX_WIRE_BYTES};

use common::*;

/// Epoch the registered device starts at, sent in the create body and compared
/// against the device row.
const EPOCH: i32 = 0;
/// Snapshot point recorded in the signed create body.
const SERVER_SEQ_AT: i64 = 1;

// ───────────────────────────── harness ─────────────────────────────

/// A relay configured the way a deployment that wants resumable uploads runs:
/// file-backed snapshot storage plus the feature switched on.
///
/// Mirrors `relay_upload_tests::resumable_config`, which is the already-proven
/// way to make the capability reachable. Returns the canonical snapshot root so
/// the test can assert on the published blob directly.
fn resumable_config(tmp: &Path) -> (Config, String) {
    let mut config = test_config();
    let canonical_tmp = std::fs::canonicalize(tmp).unwrap();
    let media = canonical_tmp.join("media");
    std::fs::create_dir_all(&media).unwrap();
    config.media_storage_path = media.to_str().unwrap().to_string();
    config.snapshot_upload = SnapshotUploadConfig {
        enabled: true,
        // Widen the byte ceilings so the multi-chunk upload exercises chunk
        // semantics rather than quota enforcement.
        group_reserved_bytes: 64 * SNAPSHOT_UPLOAD_MAX_WIRE_BYTES,
        global_reserved_bytes: 256 * SNAPSHOT_UPLOAD_MAX_WIRE_BYTES,
        chunk_concurrency: 8,
        create_rate_limit: 10_000,
        ..SnapshotUploadConfig::default()
    };
    let snapshot_root = canonical_tmp.join("media-snapshots").to_str().unwrap().to_string();
    (config, snapshot_root)
}

/// One registered uploader device plus a sibling in the same group.
///
/// The sibling is materialized through `prepare_device` (an approval is
/// deliberately required to join an existing group) and exists to be the
/// snapshot audience the upload targets.
struct Fixture {
    /// `127.0.0.1` base URL, as the harness serves it.
    url: String,
    sync_id: String,
    device_id: String,
    token: String,
    keys: TestDeviceKeys,
    other_device_id: String,
    other_token: String,
    db: std::sync::Arc<db::Database>,
    snapshot_root: String,
}

async fn fixture(tmp: &Path) -> Fixture {
    let (config, snapshot_root) = resumable_config(tmp);
    let (url, _server, db, _state) = start_test_relay_with_state(config).await;
    let client = Client::new();
    let sync_id = generate_sync_id();

    let device_id = generate_device_id();
    let keys = TestDeviceKeys::generate(&device_id);
    let token = register_device(&client, &url, &sync_id, &device_id, &keys).await;

    let other_device_id = generate_device_id();
    let (other_token, _other_keys) = prepare_device(&db, &sync_id, &other_device_id).await;

    Fixture {
        url,
        sync_id,
        device_id,
        token,
        keys,
        other_device_id,
        other_token,
        db,
        snapshot_root,
    }
}

impl Fixture {
    /// A production `ServerRelay` for the uploader device.
    ///
    /// This is the real transport: it builds the canonical path, the
    /// `PRISM_SYNC_HTTP_V2` signing data, the hybrid Ed25519+ML-DSA-65
    /// signature, and a fresh nonce for every request on its own.
    fn uploader_relay(&self) -> ServerRelay {
        let ml_dsa_kp = self.keys.device_secret.ml_dsa_65_keypair(&self.device_id).unwrap();
        // `ServerRelay::new` accepts `http://localhost` only, so the harness's
        // `127.0.0.1` URL is rewritten rather than relaxed.
        let port = self.url.rsplit(':').next().unwrap();
        ServerRelay::new(
            format!("http://localhost:{port}"),
            self.sync_id.clone(),
            self.device_id.clone(),
            self.token.clone(),
            self.keys.ed25519_signing_key.clone(),
            ml_dsa_kp,
            None,
        )
        .expect("ServerRelay::new should accept a localhost URL")
    }
}

/// Zero backoff so the retry path is exercised without sleeping.
fn fast_retry() -> SnapshotUploadRetryPolicy {
    SnapshotUploadRetryPolicy {
        max_attempts: 3,
        initial_backoff: Duration::ZERO,
        max_backoff: Duration::ZERO,
    }
}

fn upload_request(f: &Fixture) -> SnapshotUploadRequest {
    SnapshotUploadRequest {
        epoch: EPOCH,
        server_seq_at: SERVER_SEQ_AT,
        target_device_id: f.other_device_id.clone(),
        ttl_secs: 86_400,
    }
}

/// Sign a real snapshot `SignedBatchEnvelope` with the uploader's own hybrid
/// device keys, using the same producer the engine uses.
///
/// The relay stores these bytes opaquely; the signature is here because the
/// envelope must be exactly what the engine would publish, not a stand-in.
fn sign_snapshot_envelope(f: &Fixture, batch_id: &str, ciphertext: Vec<u8>) -> Vec<u8> {
    let ml_dsa_kp = f.keys.device_secret.ml_dsa_65_keypair(&f.device_id).unwrap();
    let payload_hash = batch_signature::compute_payload_hash(b"prism snapshot parity payload");
    let envelope = batch_signature::sign_batch(
        &f.keys.ed25519_signing_key,
        &ml_dsa_kp,
        &f.sync_id,
        EPOCH,
        batch_id,
        "snapshot",
        &f.device_id,
        0,
        &payload_hash,
        [7u8; 24],
        ciphertext,
    )
    .expect("signing the snapshot envelope should succeed");
    serde_json::to_vec(&envelope).expect("serializing the envelope should succeed")
}

/// A real signed envelope whose serialized length needs more than one 8 MiB
/// chunk.
///
/// `ciphertext` is base64 on the wire, so its serialized contribution is
/// `4 * ceil(len / 3)`. A probe with an empty ciphertext measures the fixed
/// overhead (including the fixed-size hybrid signature), and the ciphertext
/// length is then solved to land just under two chunks. The signature is
/// computed over the **final** envelope, so the probe is only a length
/// measurement and the uploaded bytes are internally consistent.
fn multi_chunk_envelope(f: &Fixture) -> Vec<u8> {
    let probe_len = sign_snapshot_envelope(f, "snapshot-parity", Vec::new()).len();
    let target = 2 * SNAPSHOT_UPLOAD_CHUNK_BYTES - 1024;
    let ciphertext_len = 3 * (target.saturating_sub(probe_len) / 4);
    assert!(ciphertext_len > 0, "probe overhead already exceeded the target size");

    let bytes = sign_snapshot_envelope(f, "snapshot-parity", vec![0xC3u8; ciphertext_len]);
    assert!(
        bytes.len() > SNAPSHOT_UPLOAD_CHUNK_BYTES,
        "the envelope must need more than one chunk, got {} bytes",
        bytes.len()
    );
    bytes
}

fn upload_row(f: &Fixture, upload_id: &str) -> db::SnapshotUploadRow {
    f.db.with_read_conn(|conn| db::get_snapshot_upload(conn, upload_id))
        .expect("reading the upload row should succeed")
        .expect("the upload row must exist")
}

/// The published snapshot row for the addressed audience device.
///
/// This is the row a receiving device's `GET /snapshot` resolves, read back from
/// the relay's own database rather than inferred from the response body.
fn published_snapshot(f: &Fixture, audience_device_id: &str) -> db::SnapshotRecord {
    f.db.with_read_conn(|conn| db::get_snapshot(conn, &f.sync_id, audience_device_id))
        .expect("reading the snapshot row should succeed")
        .expect("a published snapshot row must exist for the addressed device")
}

/// Nonces the relay accepted for this device.
///
/// `verify_signed_request` records a nonce only after the signature verifies, so
/// every row here is one accepted request. The primary key is
/// `(device_id, nonce)`, which is the relay's replay protection.
fn accepted_nonces(f: &Fixture, device_id: &str) -> Vec<String> {
    f.db.with_read_conn(|conn| {
        let mut stmt = conn.prepare(
            "SELECT nonce FROM signed_request_nonces WHERE device_id = ?1 ORDER BY nonce",
        )?;
        let rows = stmt
            .query_map(rusqlite::params![device_id], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    })
    .expect("reading accepted nonces should succeed")
}

/// Fetch the snapshot the way the addressed device does: a plain authenticated
/// `GET /v1/sync/{sync_id}/snapshot`.
async fn audience_download(f: &Fixture, device_id: &str, token: &str) -> Vec<u8> {
    let resp = Client::new()
        .get(format!("{}/v1/sync/{}/snapshot", f.url, f.sync_id))
        .header("Authorization", format!("Bearer {token}"))
        .header("X-Device-Id", device_id)
        .send()
        .await
        .expect("snapshot GET should complete");
    assert_eq!(resp.status(), 200, "the addressed device should see the snapshot");
    let json: serde_json::Value = resp.json().await.expect("snapshot body should be JSON");
    let encoded = json["data"].as_str().expect("snapshot body should carry data");
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .expect("snapshot data should be base64")
}

// ─────────────────── the byte-carrying seam, end to end ───────────────────

#[tokio::test]
async fn core_uploader_publishes_exact_bytes_through_real_relay_routes() {
    let tmp = tempfile::TempDir::new().unwrap();
    let f = fixture(tmp.path()).await;
    let envelope = multi_chunk_envelope(&f);
    let transport = f.uploader_relay();

    // (1) The capability is parsed from the relay's real authenticated
    //     `/capabilities` endpoint — not injected, not inferred from config.
    let capability = transport
        .resumable_snapshot_capability()
        .await
        .expect("a file-backed, enabled relay must advertise snapshot_upload");
    assert_eq!(capability.version, 1, "v1 capability must come back as version 1");
    assert_eq!(
        capability.chunk_bytes, SNAPSHOT_UPLOAD_CHUNK_BYTES as u64,
        "the relay's session chunk size must match the v1 protocol constant"
    );
    assert!(
        capability.accepts_total(envelope.len() as u64),
        "advertised maximum {} must accept a {} byte envelope",
        capability.max_wire_bytes,
        envelope.len()
    );

    // (2) A real uploader drives a real multi-chunk envelope. This is the whole
    //     point: create, chunk, and complete all leave the process as signed
    //     HTTP requests the core client built by itself.
    let uploader = SnapshotUploader::new(&transport, &envelope, upload_request(&f))
        .with_retry_policy(fast_retry());
    let upload_key = uploader.upload_key().to_string();
    let outcome = uploader.run(None).await.expect("resumable upload must succeed");
    let SnapshotUploadOutcome::Uploaded { upload_id, total_bytes } = outcome else {
        panic!("expected the resumable path, got a capability downgrade");
    };
    assert_eq!(total_bytes, envelope.len() as u64, "the uploader must report the exact size");

    // (3) Every accepted request minted its own nonce: one create, one per
    //     chunk, and one complete. The relay records a nonce only after the
    //     signature verifies, and a replay would be rejected, so an exact count
    //     of distinct nonces proves both freshness and that the canonical
    //     signatures on every path were accepted.
    let expected_chunks = envelope.len().div_ceil(SNAPSHOT_UPLOAD_CHUNK_BYTES);
    assert_eq!(expected_chunks, 2, "this test must exercise a genuinely multi-chunk envelope");
    let expected_requests = 1 + expected_chunks + 1;
    let nonces = accepted_nonces(&f, &f.device_id);
    assert_eq!(
        nonces.len(),
        expected_requests,
        "one accepted nonce per create/chunk/complete request"
    );
    let mut distinct = nonces.clone();
    distinct.sort();
    distinct.dedup();
    assert_eq!(distinct.len(), nonces.len(), "signed-request nonces must never repeat");

    // (4) The status route answers for the completed session through the core
    //     transport, covering the fourth canonical path and its signature. The
    //     complete route answered 204 (the only success status the relay emits;
    //     the core transport turns any 4xx/5xx into an error), and re-completing
    //     is idempotently successful because the session is already published.
    let status = transport
        .snapshot_upload_status(&upload_id)
        .await
        .expect("status must be readable for the completed session");
    assert_eq!(status.state.as_deref(), Some("completed"), "the session must be terminal");
    assert_eq!(
        status.committed_offset,
        envelope.len() as i64,
        "a completed session reports its full offset"
    );
    transport
        .complete_snapshot_upload(&upload_id)
        .await
        .expect("a repeated complete must answer 204 without republishing");

    // (5) The relay's own record agrees with what the client committed to.
    let row = upload_row(&f, &upload_id);
    assert_eq!(row.state.as_str(), "completed");
    assert_eq!(row.committed_offset, envelope.len() as i64);
    assert_eq!(row.total_bytes, envelope.len() as i64);
    assert_eq!(
        row.target_device_id, f.other_device_id,
        "the audience must be the addressed device"
    );
    assert_eq!(row.epoch, i64::from(EPOCH));
    assert_eq!(row.server_seq_at, SERVER_SEQ_AT);

    // (6) The published snapshot row is file-backed: it records a blob reference
    //     inside the group directory and keeps no inline bytes.
    let snapshot = published_snapshot(&f, &f.other_device_id);
    assert!(
        snapshot.data.is_empty(),
        "a resumable publication must reference a blob, not carry bytes inline"
    );
    let blob_ref = snapshot.blob_ref.as_deref().expect("a file-backed row must record a blob_ref");
    assert_eq!(blob_ref, row.blob_ref, "the published row must reference the session's blob");
    let blob_path = Path::new(&f.snapshot_root).join(&f.sync_id).join(blob_ref);
    let on_disk = std::fs::read(&blob_path).expect("the published blob must exist on disk");
    assert_eq!(on_disk.len(), envelope.len(), "the published blob must be the full envelope");

    // (7) The audience device downloads byte-identical bytes over real HTTP.
    let downloaded = audience_download(&f, &f.other_device_id, &f.other_token).await;
    assert_eq!(downloaded, envelope, "the downloaded snapshot must be byte-identical");
    assert_eq!(on_disk, envelope, "the on-disk blob must be byte-identical");

    // The uploader's create-time commitment is what the published bytes hash to.
    let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
    sha2::Digest::update(&mut hasher, &envelope);
    assert_eq!(hex::encode(sha2::Digest::finalize(hasher)), hex::encode(row.body_sha256));
    assert_eq!(hex::encode(row.body_sha256), *uploader.body_sha256());
    assert!(!upload_key.is_empty(), "the uploader must have presented an idempotency key");
}

// ─────────────── lost/ambiguous response across the same seam ───────────────

/// Wraps the real transport and discards the first *successful* chunk response.
///
/// The real `PUT .../chunks/0` is sent by `ServerRelay` and really committed by
/// the relay; only the observation of the acknowledgment is lost, which is what a
/// dropped connection after a commit looks like. Nothing is re-signed, re-routed,
/// or short-circuited: the retry is another genuine signed HTTP request.
struct AmbiguousOnce<'a> {
    inner: &'a ServerRelay,
    chunk_calls: AtomicU64,
    dropped: AtomicBool,
}

impl<'a> AmbiguousOnce<'a> {
    fn new(inner: &'a ServerRelay) -> Self {
        Self { inner, chunk_calls: AtomicU64::new(0), dropped: AtomicBool::new(false) }
    }
}

#[async_trait::async_trait]
impl ResumableSnapshotTransport for AmbiguousOnce<'_> {
    async fn resumable_snapshot_capability(
        &self,
    ) -> Result<SnapshotUploadCapability, CapabilityUnavailableReason> {
        self.inner.resumable_snapshot_capability().await
    }

    async fn create_snapshot_upload(
        &self,
        body: &CreateUploadRequest,
    ) -> Result<CreateUploadResponse, ResumableUploadError> {
        self.inner.create_snapshot_upload(body).await
    }

    async fn snapshot_upload_status(
        &self,
        upload_id: &str,
    ) -> Result<UploadStatusResponse, ResumableUploadError> {
        self.inner.snapshot_upload_status(upload_id).await
    }

    async fn put_snapshot_upload_chunk(
        &self,
        upload_id: &str,
        offset: u64,
        chunk: &[u8],
    ) -> Result<ChunkResponse, ResumableUploadError> {
        self.chunk_calls.fetch_add(1, Ordering::SeqCst);
        let result = self.inner.put_snapshot_upload_chunk(upload_id, offset, chunk).await;
        if result.is_ok() && !self.dropped.swap(true, Ordering::SeqCst) {
            // The bytes are durable on the relay; the client just never learned
            // the offset. This is a transport failure (status 0), which is
            // exactly what the uploader is required to retry.
            return Err(ResumableUploadError::transport("simulated lost chunk response"));
        }
        result
    }

    async fn complete_snapshot_upload(&self, upload_id: &str) -> Result<(), ResumableUploadError> {
        self.inner.complete_snapshot_upload(upload_id).await
    }

    async fn abort_snapshot_upload(&self, upload_id: &str) -> Result<(), ResumableUploadError> {
        self.inner.abort_snapshot_upload(upload_id).await
    }
}

#[tokio::test]
async fn ambiguous_chunk_response_retries_with_a_fresh_nonce_and_reconciles() {
    let tmp = tempfile::TempDir::new().unwrap();
    let f = fixture(tmp.path()).await;
    let envelope = multi_chunk_envelope(&f);
    let relay = f.uploader_relay();
    let transport = AmbiguousOnce::new(&relay);

    let uploader = SnapshotUploader::new(&transport, &envelope, upload_request(&f))
        .with_retry_policy(fast_retry());
    let outcome = uploader.run(None).await.expect("the upload must still succeed");
    let SnapshotUploadOutcome::Uploaded { upload_id, total_bytes } = outcome else {
        panic!("expected the resumable path, got a capability downgrade");
    };
    assert_eq!(total_bytes, envelope.len() as u64);

    // The retry re-issued the *same range* rather than assuming a position: two
    // requests at offset 0. The relay treats the wholly committed range as an
    // idempotent retry and answers with its authoritative offset.
    let expected_chunks = envelope.len().div_ceil(SNAPSHOT_UPLOAD_CHUNK_BYTES);
    assert_eq!(
        transport.chunk_calls.load(Ordering::SeqCst),
        (expected_chunks + 1) as u64,
        "exactly one extra chunk request, retried from the acknowledged offset"
    );

    // The retried request carried a fresh nonce, so replay protection did not
    // turn the legitimate retry into a 401.
    let nonces = accepted_nonces(&f, &f.device_id);
    let mut distinct = nonces.clone();
    distinct.sort();
    distinct.dedup();
    assert_eq!(distinct.len(), nonces.len(), "the retry must have used a fresh nonce");
    assert_eq!(
        nonces.len() as u64,
        expected_chunks as u64 + 3,
        "one create + (chunks + 1) attempt + one complete"
    );

    let row = upload_row(&f, &upload_id);
    assert_eq!(row.state.as_str(), "completed");
    assert_eq!(row.committed_offset, envelope.len() as i64);

    // The duplicate acknowledgment wrote nothing and the published bytes are the
    // original ones.
    let downloaded = audience_download(&f, &f.other_device_id, &f.other_token).await;
    assert_eq!(downloaded, envelope, "a retried range must not damage the published bytes");
}

/// Measure transport separately from storage export/import. Keep production caps
/// unchanged and run each size in a separate process when profiling memory.
#[tokio::test]
#[ignore = "large transfer measurement; set PRISM_SNAPSHOT_CIPHERTEXT_MIB"]
async fn profile_large_snapshot_transport() {
    let mib: usize = std::env::var("PRISM_SNAPSHOT_CIPHERTEXT_MIB")
        .expect("set PRISM_SNAPSHOT_CIPHERTEXT_MIB")
        .parse()
        .unwrap();
    assert!((1..=181).contains(&mib));
    let tmp = tempfile::TempDir::new().unwrap();
    let f = fixture(tmp.path()).await;
    let start = std::time::Instant::now();
    let envelope = sign_snapshot_envelope(&f, "snapshot-profile", vec![0xC3; mib * 1024 * 1024]);
    let serialize_ms = start.elapsed().as_millis();
    let transport = f.uploader_relay();
    let capability = transport.resumable_snapshot_capability().await.unwrap();
    let start = std::time::Instant::now();
    let result = SnapshotUploader::new(&transport, &envelope, upload_request(&f)).run(None).await;
    let upload_ms = start.elapsed().as_millis();
    let mut download_ms = None;
    if capability.accepts_total(envelope.len() as u64) {
        assert!(matches!(result.unwrap(), SnapshotUploadOutcome::Uploaded { .. }));
        let start = std::time::Instant::now();
        let downloaded = audience_download(&f, &f.other_device_id, &f.other_token).await;
        download_ms = Some(start.elapsed().as_millis());
        assert_eq!(downloaded, envelope);
    } else {
        assert!(result.is_err(), "oversized envelopes must fail before uploading");
        assert!(accepted_nonces(&f, &f.device_id).is_empty());
    }
    println!(
        "{}",
        serde_json::json!({"ciphertext_mib": mib, "wire_bytes": envelope.len(),
        "accepted": capability.accepts_total(envelope.len() as u64),
        "serialize_ms": serialize_ms, "upload_ms": upload_ms, "download_ms": download_ms})
    );
}
