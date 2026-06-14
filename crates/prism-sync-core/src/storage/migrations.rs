use rusqlite::Connection;

/// SQL migrations for sync engine tables.
///
/// Table schema matches the spec exactly:
/// - sync_metadata
/// - pending_ops (with indexes)
/// - applied_ops
/// - field_versions
/// - device_registry
const MIGRATIONS: &[&str] = &[
    "-- V1: Initial sync engine tables

    CREATE TABLE IF NOT EXISTS sync_metadata (
        sync_id TEXT PRIMARY KEY,
        local_device_id TEXT NOT NULL,
        current_epoch INTEGER NOT NULL DEFAULT 0,
        last_pulled_server_seq INTEGER NOT NULL DEFAULT 0,
        last_pushed_at TEXT,
        last_successful_sync_at TEXT,
        registered_at TEXT,
        needs_rekey INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS pending_ops (
        op_id TEXT PRIMARY KEY,
        sync_id TEXT NOT NULL,
        epoch INTEGER NOT NULL,
        device_id TEXT NOT NULL,
        local_batch_id TEXT NOT NULL,
        entity_table TEXT NOT NULL,
        entity_id TEXT NOT NULL,
        field_name TEXT NOT NULL,
        encoded_value TEXT,
        is_delete INTEGER NOT NULL DEFAULT 0,
        client_hlc TEXT NOT NULL,
        created_at TEXT NOT NULL,
        pushed_at TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_pending_ops_sync_pushed
        ON pending_ops(sync_id, pushed_at, created_at);

    CREATE INDEX IF NOT EXISTS idx_pending_ops_batch
        ON pending_ops(local_batch_id, created_at);

    CREATE TABLE IF NOT EXISTS applied_ops (
        op_id TEXT PRIMARY KEY,
        sync_id TEXT NOT NULL,
        epoch INTEGER NOT NULL,
        device_id TEXT NOT NULL,
        client_hlc TEXT NOT NULL,
        server_seq INTEGER NOT NULL,
        applied_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS field_versions (
        sync_id TEXT NOT NULL,
        entity_table TEXT NOT NULL,
        entity_id TEXT NOT NULL,
        field_name TEXT NOT NULL,
        winning_op_id TEXT NOT NULL,
        winning_device_id TEXT NOT NULL,
        winning_hlc TEXT NOT NULL,
        winning_encoded_value TEXT,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (sync_id, entity_table, entity_id, field_name)
    );

    CREATE TABLE IF NOT EXISTS device_registry (
        sync_id TEXT NOT NULL,
        device_id TEXT NOT NULL,
        ed25519_public_key BLOB NOT NULL,
        x25519_public_key BLOB NOT NULL,
        ml_dsa_65_public_key BLOB NOT NULL,
        ml_kem_768_public_key BLOB NOT NULL,
        status TEXT NOT NULL DEFAULT 'active',
        registered_at TEXT NOT NULL,
        revoked_at TEXT,
        PRIMARY KEY (sync_id, device_id)
    );
    ",
    "-- V2: Add ml_dsa_key_generation to device_registry
    ALTER TABLE device_registry ADD COLUMN ml_dsa_key_generation INTEGER NOT NULL DEFAULT 0;
    ",
    "-- V3: Track last imported registry version
    ALTER TABLE sync_metadata ADD COLUMN last_imported_registry_version INTEGER;
    ",
    "-- V4: Add x_wing_public_key to device_registry
    ALTER TABLE device_registry ADD COLUMN x_wing_public_key BLOB NOT NULL DEFAULT X'';
    ",
    "-- V5: Persist remote ops that target schema unknown to this client
    CREATE TABLE IF NOT EXISTS quarantined_ops (
        sync_id TEXT NOT NULL,
        op_id TEXT NOT NULL,
        server_seq INTEGER NOT NULL,
        entity_table TEXT NOT NULL,
        field_name TEXT NOT NULL,
        reason TEXT NOT NULL,
        op_json TEXT NOT NULL,
        quarantined_at TEXT NOT NULL,
        PRIMARY KEY (sync_id, op_id)
    );

    CREATE INDEX IF NOT EXISTS idx_quarantined_ops_sync_seq
        ON quarantined_ops(sync_id, server_seq, quarantined_at);
    ",
    "-- V6: Push-side quarantine for batches whose envelope exceeds the relay cap.
    -- Distinct from `quarantined_ops` (pull-side schema-unknown path): this is
    -- local-only diagnostic state, never replayed and never included in
    -- snapshots. Stores batch IDs + diagnostics only; the original ops live
    -- in `pending_ops` and recovery (Phase 1C) repartitions them in place.
    CREATE TABLE IF NOT EXISTS push_quarantine (
        sync_id TEXT NOT NULL,
        batch_id TEXT NOT NULL PRIMARY KEY,
        entity_table TEXT NOT NULL,
        entity_id TEXT NOT NULL,
        body_bytes INTEGER NOT NULL,
        error_code TEXT NOT NULL,
        error_message TEXT NOT NULL,
        quarantined_at TEXT NOT NULL
    ) STRICT;

    CREATE INDEX IF NOT EXISTS idx_push_quarantine_sync
        ON push_quarantine(sync_id);
    ",
    "-- V7: Index applied_ops(sync_id, server_seq) for prune-window queries.
    -- Without it, prune-window queries scan the full table; with it, SEARCH.
    -- Tombstone-prune joins by op_id (the PK) and is unaffected.
    CREATE INDEX IF NOT EXISTS idx_applied_ops_sync_seq
        ON applied_ops(sync_id, server_seq);
    ",
    "-- V8: Pull-failure discipline (replayable batch-level quarantine + stall budget).
    --
    -- `quarantined_pull_batches` durably holds the FULL SignedBatchEnvelope of an
    -- inbound batch that failed a deterministic pull-side check (payload-hash,
    -- decode, attribution, invalid signature, missing epoch key, ...). The cursor
    -- advances past it (relay stays an expiring transport buffer), but the device
    -- keeps custody so Phase 0b replay can re-run the full verify->decrypt->decode
    -- ->filter->apply pipeline once the blocking condition clears (schema upgrade,
    -- registry import, epoch key arrival). `reason` drives reason-aware replay
    -- eligibility; `epoch` is captured for the missing-epoch-key arm so replay can
    -- check whether the key is now in the hierarchy. Device-local, never
    -- replicated, never included in snapshots.
    -- PK is (sync_id, sender_device_id, batch_id), matching the relay's push
    -- dedup key (prism-sync-relay db.rs ~1601): two DIFFERENT senders can legally
    -- occupy the same batch_id in the log, so keying only on batch_id would let a
    -- compromised device evict an honest device's quarantined envelope via an
    -- INSERT OR REPLACE collision — silently destroying the only durable copy of a
    -- batch the cursor has already advanced past. sender_device_id is part of the
    -- key (not server_seq) so the row stays seq-independent for the C6 lineage
    -- reset, while still being collision-proof across senders.
    CREATE TABLE IF NOT EXISTS quarantined_pull_batches (
        sync_id TEXT NOT NULL,
        batch_id TEXT NOT NULL,
        server_seq INTEGER NOT NULL,
        epoch INTEGER,
        sender_device_id TEXT NOT NULL,
        envelope_json TEXT NOT NULL,
        reason TEXT NOT NULL,
        retry_count INTEGER NOT NULL DEFAULT 0,
        quarantined_at TEXT NOT NULL,
        last_retry_at TEXT,
        PRIMARY KEY (sync_id, sender_device_id, batch_id)
    );

    CREATE INDEX IF NOT EXISTS idx_quarantined_pull_batches_sync_seq
        ON quarantined_pull_batches(sync_id, server_seq, quarantined_at);

    -- `pull_stall` is the transient-retry budget: a batch whose sender keys or
    -- registry generation cannot be resolved *yet* (network/5xx, stale registry,
    -- not-yet-propagated rotation) freezes the cursor without advancing while we
    -- retry. One row per stalled server_seq; `attempts` counts cycles so a flaky
    -- endpoint (or a device claiming a bogus future generation) is bounded before
    -- conversion to quarantine-and-advance. Device-local.
    CREATE TABLE IF NOT EXISTS pull_stall (
        sync_id TEXT NOT NULL,
        server_seq INTEGER NOT NULL,
        reason TEXT NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        first_seen_at TEXT NOT NULL,
        last_seen_at TEXT NOT NULL,
        PRIMARY KEY (sync_id, server_seq)
    );

    -- `device_key_history` archives superseded ML-DSA verification keys so an
    -- in-flight pre-rotation batch still verifies after the receiver has already
    -- imported the rotated registry. When verify_and_import_signed_registry
    -- replaces a device record with a higher generation, the prior
    -- (generation, ml_dsa_65_public_key) is archived here; pull looks the key up
    -- by envelope.sender_ml_dsa_key_generation, matching the current record or
    -- this history exactly. Device-local, never replicated, never snapshotted.
    CREATE TABLE IF NOT EXISTS device_key_history (
        sync_id TEXT NOT NULL,
        device_id TEXT NOT NULL,
        ml_dsa_key_generation INTEGER NOT NULL,
        ml_dsa_65_public_key BLOB NOT NULL,
        archived_at TEXT NOT NULL,
        PRIMARY KEY (sync_id, device_id, ml_dsa_key_generation)
    );

    -- `consumer_deliveries` is the durable at-least-once delivery journal: one
    -- row per winning op, written in the SAME transaction as Phase C bookkeeping
    -- (applied_ops/field_versions/cursor) and the snapshot import, so a pulled
    -- winner survives process death between Rust apply and Dart consumer-DB
    -- write. Dart drains in id order and acks (deletes up to id) only after its
    -- own transaction commits. Local AUTOINCREMENT id (not a server seq), so a
    -- relay-log lineage reset leaves it untouched. Device-local.
    CREATE TABLE IF NOT EXISTS consumer_deliveries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sync_id TEXT NOT NULL,
        entity_table TEXT NOT NULL,
        entity_id TEXT NOT NULL,
        field_name TEXT,
        encoded_value TEXT,
        is_delete INTEGER NOT NULL DEFAULT 0,
        server_seq INTEGER NOT NULL,
        created_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_consumer_deliveries_sync_id
        ON consumer_deliveries(sync_id, id);
    ",
    "-- V9: Relay log-lineage token (F41).
    --
    -- `relay_log_token` records the lineage token of the relay seq stream that
    -- issued this group's current `last_pulled_server_seq`. The engine compares it
    -- to each pull response's `log_token`: a mismatch means the relay's log was
    -- restored from backup (the seq stream regressed), so the cursor is reset and
    -- history re-pulled (idempotent LWW merge). NULL until first observed against a
    -- lineage-aware relay; an old relay omits the field, leaving this NULL and
    -- behavior unchanged. Device-local, never replicated, never snapshotted.
    -- Written idempotently: the ALTER is a no-op-equivalent guarded by the version
    -- gate, so re-running migrations never double-adds the column.
    ALTER TABLE sync_metadata ADD COLUMN relay_log_token TEXT;
    ",
    "-- V10: Write-ahead epoch-key rotation journal (F24).
    --
    -- `pending_epoch_rotation` is the durable write-ahead marker a device stages
    -- BEFORE committing a revoke/rekey to the relay. The new epoch key K_N is
    -- staged in the secure store (`epoch_key_N`) and this row records the rotation
    -- in flight (epoch N + the revoked target). After the relay commits the epoch
    -- bump and the local cache/sqlite catch up, the row is cleared. On restart,
    -- `resume_pending_epoch_rotation` drives the staged rotation to a terminal
    -- state: fully committed if the relay reached N and our staged K_N matches the
    -- relay artifact, or discarded if a different device won the rotation. One row
    -- per sync group. Device-local, never replicated, never snapshotted.
    CREATE TABLE IF NOT EXISTS pending_epoch_rotation (
        sync_id TEXT NOT NULL PRIMARY KEY,
        epoch INTEGER NOT NULL,
        target_device_id TEXT,
        created_at TEXT NOT NULL
    );
    ",
];

pub fn apply(conn: &mut Connection) -> Result<(), String> {
    let current: i64 = conn
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|e| format!("read user_version failed: {e}"))?;
    let current = usize::try_from(current)
        .map_err(|_| format!("invalid negative schema version: {current}"))?;

    if current > MIGRATIONS.len() {
        return Err(format!(
            "database schema version {current} is newer than supported version {}",
            MIGRATIONS.len()
        ));
    }

    for (idx, sql) in MIGRATIONS.iter().enumerate().skip(current) {
        let tx = conn.transaction().map_err(|e| format!("begin migration failed: {e}"))?;
        tx.execute_batch(sql).map_err(|e| format!("migration {} failed: {e}", idx + 1))?;
        let version = i64::try_from(idx + 1)
            .map_err(|_| format!("migration version overflow at {}", idx + 1))?;
        tx.pragma_update(None, "user_version", version)
            .map_err(|e| format!("set user_version failed: {e}"))?;
        tx.commit().map_err(|e| format!("commit migration failed: {e}"))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn applies_all_migrations_and_records_latest_user_version() {
        let mut conn = Connection::open_in_memory().unwrap();

        apply(&mut conn).unwrap();

        let version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0)).unwrap();
        assert_eq!(version, MIGRATIONS.len() as i64);

        let x_wing_column_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('device_registry') WHERE name = 'x_wing_public_key'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(x_wing_column_count, 1);

        let quarantine_table_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'quarantined_ops'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(quarantine_table_count, 1);

        let push_quarantine_table_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'push_quarantine'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(push_quarantine_table_count, 1);

        // The combined V8 migration carries all four
        // tables: the two pull-failure tables plus device_key_history and
        // consumer_deliveries. They must all land in this single
        // version because `apply()` never re-runs a migration on a DB already
        // stamped at its version — folding them avoids a broken upgrade path.
        for table in [
            "quarantined_pull_batches",
            "pull_stall",
            "device_key_history",
            "consumer_deliveries",
            // V10: the epoch-rotation write-ahead journal.
            "pending_epoch_rotation",
        ] {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 1, "{table} table should exist after migrations");
        }

        // `quarantined_pull_batches` carries the epoch column so
        // the missing-epoch-key replay arm can check the key hierarchy.
        let epoch_column_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('quarantined_pull_batches') WHERE name = 'epoch'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(epoch_column_count, 1);
    }

    #[test]
    fn v9_adds_relay_log_token_column_and_is_idempotent() {
        // Stamp a DB at V8 (before the relay_log_token column) and upgrade: V9's
        // ALTER must add `relay_log_token` exactly once, and re-applying must not
        // re-add it.
        let mut conn = Connection::open_in_memory().unwrap();
        for sql in MIGRATIONS.iter().take(8) {
            conn.execute_batch(sql).unwrap();
        }
        conn.pragma_update(None, "user_version", 8i64).unwrap();
        assert_eq!(
            relay_log_token_column_count(&conn),
            0,
            "V8 DB has no relay_log_token column yet"
        );

        apply(&mut conn).unwrap();
        assert_eq!(relay_log_token_column_count(&conn), 1, "V9 adds the column");
        let version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0)).unwrap();
        assert_eq!(version, MIGRATIONS.len() as i64);

        // Re-running is a no-op (the version gate stops the ALTER re-firing).
        apply(&mut conn).unwrap();
        assert_eq!(relay_log_token_column_count(&conn), 1, "column not double-added");
    }

    fn relay_log_token_column_count(conn: &Connection) -> i64 {
        conn.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('sync_metadata') WHERE name = 'relay_log_token'",
            [],
            |row| row.get(0),
        )
        .unwrap()
    }

    #[test]
    fn v10_adds_pending_epoch_rotation_table_and_is_idempotent() {
        // Stamp a DB at V9 (before the epoch-rotation journal) and upgrade: V10
        // must create `pending_epoch_rotation` exactly once, and re-applying is a
        // no-op.
        let mut conn = Connection::open_in_memory().unwrap();
        for sql in MIGRATIONS.iter().take(9) {
            conn.execute_batch(sql).unwrap();
        }
        conn.pragma_update(None, "user_version", 9i64).unwrap();
        assert_eq!(
            pending_epoch_rotation_table_count(&conn),
            0,
            "V9 DB has no pending_epoch_rotation table yet"
        );

        apply(&mut conn).unwrap();
        assert_eq!(pending_epoch_rotation_table_count(&conn), 1, "V10 adds the table");
        let version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0)).unwrap();
        assert_eq!(version, MIGRATIONS.len() as i64);

        // Re-running is a no-op (version gate plus the IF NOT EXISTS guard).
        apply(&mut conn).unwrap();
        assert_eq!(pending_epoch_rotation_table_count(&conn), 1, "table not double-created");
    }

    fn pending_epoch_rotation_table_count(conn: &Connection) -> i64 {
        conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'pending_epoch_rotation'",
            [],
            |row| row.get(0),
        )
        .unwrap()
    }

    #[test]
    fn apply_is_idempotent_at_latest_version() {
        let mut conn = Connection::open_in_memory().unwrap();
        apply(&mut conn).unwrap();

        apply(&mut conn).unwrap();

        let version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0)).unwrap();
        assert_eq!(version, MIGRATIONS.len() as i64);
    }

    #[test]
    fn rejects_database_newer_than_supported_schema() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "user_version", (MIGRATIONS.len() + 1) as i64).unwrap();

        let err = apply(&mut conn).unwrap_err();
        assert!(err.contains("newer than supported version"), "{err}");
    }
}
