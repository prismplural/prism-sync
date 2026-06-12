//! Tests for the relay device-lifecycle state machine (active/stale/revoked)
//! and its cleanup transitions, run against the actual prism-sync-relay DB.
//!
//! This file currently hosts the smoke test for the shared device-lifecycle
//! fixture (`age_device` / `run_mark_stale_devices` / `run_auto_revoke_devices`
//! in `common`); the device-trust-lockout behavioral tests build on the same
//! helpers.

mod common;

use common::{
    age_device, device_status, group_needs_rekey, prepare_device, run_auto_revoke_devices,
    run_mark_stale_devices, start_test_relay, AUTO_REVOKE_SECS, STALE_DEVICE_SECS,
};
use prism_sync_relay::db;

/// The fixture can age a device past the stale floor and past the auto-revoke
/// floor, and the cleanup steps drive the documented state transitions:
/// 31d offline + `mark_stale_devices` -> `stale`; 91d offline +
/// `auto_revoke_devices` -> `revoked` with the group flagged `needs_rekey`.
#[tokio::test]
async fn fixture_ages_device_through_stale_and_revoked() {
    let (_url, _server, db) = start_test_relay().await;
    let sync_id = "f".repeat(64);
    let device_id = "device-lifecycle-smoke";

    // The DB-direct device helper does not create the sync_groups row, but
    // auto_revoke flags needs_rekey on it — create it so the flag is readable.
    let sid = sync_id.clone();
    db.with_conn(move |conn| db::create_sync_group(conn, &sid, 0)).expect("create sync group");
    let (_token, _keys) = prepare_device(&db, &sync_id, device_id).await;

    // Freshly registered device starts active, group not yet flagged.
    assert_eq!(device_status(&db, &sync_id, device_id).as_deref(), Some("active"));
    assert_eq!(group_needs_rekey(&db, &sync_id), Some(false));

    // 31 days offline, then mark-stale -> stale.
    age_device(&db, &sync_id, device_id, 31);
    let staled = run_mark_stale_devices(&db, STALE_DEVICE_SECS);
    assert_eq!(staled, 1, "exactly one device should flip to stale");
    assert_eq!(device_status(&db, &sync_id, device_id).as_deref(), Some("stale"));
    // Group is not flagged for rekey by mark-stale alone.
    assert_eq!(group_needs_rekey(&db, &sync_id), Some(false));

    // 91 days offline, then auto-revoke -> revoked + needs_rekey.
    age_device(&db, &sync_id, device_id, 91);
    let revoked = run_auto_revoke_devices(&db, AUTO_REVOKE_SECS);
    assert_eq!(revoked, vec![sync_id.clone()], "the group should be reported as affected");
    assert_eq!(device_status(&db, &sync_id, device_id).as_deref(), Some("revoked"));
    assert_eq!(group_needs_rekey(&db, &sync_id), Some(true));
}
