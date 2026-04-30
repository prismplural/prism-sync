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
