//! Throwaway localhost relay for the end-to-end FFI test harness.
//!
//! Binds 127.0.0.1 with OPEN registration, prints `RELAY_URL=http://127.0.0.1:<port>`
//! to stdout (so a spawning test can read the URL), then serves until killed.
//! NOT for production.
//!
//! Env overrides (for the kill+restart chaos test — so the relay can come back
//! on the SAME url with the SAME state):
//!   TEST_RELAY_PORT=<n>   bind a fixed port instead of an ephemeral one
//!   TEST_RELAY_DB=<path>  open a persistent file DB instead of in-memory
//!
//! Env override (for the resumable snapshot-upload parity test — so an
//! end-to-end test can exercise the split pairing ceremony against a relay that
//! actually offers the pairing lease and the resumable upload capability):
//!   TEST_RELAY_RESUMABLE=1
//!
//! Both features are dark by default in `localhost_test_config`, exactly as they
//! are in production, and `enabled: true` alone is not enough for the upload
//! capability: `snapshot_upload_supported` additionally requires file-backed
//! snapshot storage. This example therefore also points `media_storage_path` at
//! a real writable directory (fresh temp dir by default, or
//! `TEST_RELAY_MEDIA_DIR=<path>` when a test wants to inspect the published
//! blob). This is a test-only binary; no library or production code changes.
//!
//! Build: `cargo build --release -p prism-sync-relay --example test_relay`

use std::io::Write;

use prism_sync_relay::config::SnapshotUploadConfig;
use prism_sync_relay::uploads::SNAPSHOT_UPLOAD_MAX_WIRE_BYTES;

#[tokio::main]
async fn main() {
    let mut config = prism_sync_relay::config::localhost_test_config();

    // Opt-in only: without TEST_RELAY_RESUMABLE the config stays byte-identical
    // to `localhost_test_config()`, so existing suites see the same relay.
    if std::env::var("TEST_RELAY_RESUMABLE").as_deref() == Ok("1") {
        // A resumable session stages bytes on disk, so the capability is
        // withheld unless snapshot storage resolves to a file-backed root.
        let media_dir = match std::env::var("TEST_RELAY_MEDIA_DIR") {
            Ok(path) if !path.is_empty() => std::path::PathBuf::from(path),
            _ => {
                std::env::temp_dir().join(format!("prism_test_relay_media_{}", std::process::id()))
            }
        };
        std::fs::create_dir_all(&media_dir).expect("create media dir");
        config.media_storage_path = media_dir.to_string_lossy().into_owned();

        config.pairing_lease.enabled = true;
        config.snapshot_upload = SnapshotUploadConfig {
            enabled: true,
            // Widen the byte ceilings so a multi-chunk upload exercises chunk
            // semantics rather than quota enforcement.
            group_reserved_bytes: 64 * SNAPSHOT_UPLOAD_MAX_WIRE_BYTES,
            global_reserved_bytes: 256 * SNAPSHOT_UPLOAD_MAX_WIRE_BYTES,
            chunk_concurrency: 8,
            create_rate_limit: 10_000,
            ..SnapshotUploadConfig::default()
        };
    }

    let db = match std::env::var("TEST_RELAY_DB") {
        Ok(path) if !path.is_empty() => {
            prism_sync_relay::db::Database::open(&path, 2).expect("open file db")
        }
        _ => prism_sync_relay::db::Database::in_memory().expect("in-memory db"),
    };
    let state = prism_sync_relay::state::AppState::new(db, config);
    let app = prism_sync_relay::routes::router(state);

    let port: u16 = std::env::var("TEST_RELAY_PORT").ok().and_then(|v| v.parse().ok()).unwrap_or(0);
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await.expect("bind port");
    let addr = listener.local_addr().expect("local addr");

    // The spawning test reads this line to discover the port.
    println!("RELAY_URL=http://127.0.0.1:{}", addr.port());
    std::io::stdout().flush().expect("flush stdout");

    axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>())
        .await
        .expect("serve");
}
