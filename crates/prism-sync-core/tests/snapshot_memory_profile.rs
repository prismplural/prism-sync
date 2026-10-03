//! Opt-in storage snapshot measurement with deterministic synthetic data.
//! Run a single case per process so an external RSS profiler can measure its peak.
use std::time::Instant;

use base64::Engine;
use chrono::Utc;
use prism_sync_core::storage::{FieldVersion, RusqliteSyncStorage, SyncMetadata, SyncStorage};
use rand::{RngCore, SeedableRng};

#[test]
#[ignore = "large synthetic snapshot measurement; set PRISM_SNAPSHOT_ENTROPY_MIB"]
fn profile_snapshot_storage_roundtrip() {
    let mib: usize = std::env::var("PRISM_SNAPSHOT_ENTROPY_MIB")
        .expect("set PRISM_SNAPSHOT_ENTROPY_MIB")
        .parse()
        .unwrap();
    assert!((1..=256).contains(&mib));
    let dir = tempfile::tempdir().unwrap();
    let src =
        RusqliteSyncStorage::new(rusqlite::Connection::open(dir.path().join("src.db")).unwrap())
            .unwrap();
    let now = Utc::now();
    let mut tx = src.begin_tx().unwrap();
    tx.upsert_sync_metadata(&SyncMetadata {
        sync_id: "profile".into(),
        local_device_id: "sender".into(),
        current_epoch: 0,
        last_pulled_server_seq: 0,
        last_pushed_at: None,
        last_successful_sync_at: None,
        registered_at: None,
        needs_rekey: false,
        last_imported_registry_version: None,
        relay_log_token: None,
        created_at: now,
        updated_at: now,
    })
    .unwrap();
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    let mut bytes = vec![0; 64 * 1024];
    let rows = mib * 16;
    let seed_start = Instant::now();
    for index in 0..rows {
        rng.fill_bytes(&mut bytes);
        let text = base64::engine::general_purpose::STANDARD.encode(&bytes);
        tx.upsert_field_version(&FieldVersion {
            sync_id: "profile".into(),
            entity_table: "members".into(),
            entity_id: format!("member-{index}"),
            field_name: "description".into(),
            winning_op_id: format!("op-{index}"),
            winning_device_id: "sender".into(),
            winning_hlc: "1767225600000:1:sender".into(),
            winning_encoded_value: Some(serde_json::to_string(&text).unwrap()),
            updated_at: now,
        })
        .unwrap();
    }
    tx.commit().unwrap();
    let seed_ms = seed_start.elapsed().as_millis();
    let start = Instant::now();
    let snapshot = src.export_snapshot("profile").unwrap();
    let export_ms = start.elapsed().as_millis();
    let compressed_bytes = snapshot.len();
    let over_cap =
        compressed_bytes > prism_sync_core::snapshot_limits::MAX_SNAPSHOT_COMPRESSED_BYTES;
    let dst =
        RusqliteSyncStorage::new(rusqlite::Connection::open(dir.path().join("dst.db")).unwrap())
            .unwrap();
    let start = Instant::now();
    let mut tx = dst.begin_tx().unwrap();
    let imported = tx
        .import_snapshot("profile", &snapshot, prism_sync_core::clock_drift::MAX_CLOCK_DRIFT_MS)
        .unwrap();
    tx.commit().unwrap();
    assert_eq!(imported, rows as u64);
    let import_ms = start.elapsed().as_millis();
    assert_eq!(dst.export_snapshot("profile").unwrap(), snapshot);
    println!(
        "{}",
        serde_json::json!({"entropy_mib": mib, "rows": rows,
        "compressed_bytes": compressed_bytes, "over_production_cap": over_cap,
        "seed_ms": seed_ms, "export_ms": export_ms, "import_ms": import_ms})
    );
}
