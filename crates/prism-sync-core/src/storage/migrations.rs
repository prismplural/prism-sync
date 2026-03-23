use rusqlite_migration::{Migrations, M};

/// SQL migrations for sync engine tables.
///
/// Table schema matches the spec exactly:
/// - sync_metadata
/// - pending_ops (with indexes)
/// - applied_ops
/// - field_versions
/// - device_registry
pub fn migrations() -> Migrations<'static> {
    Migrations::new(vec![M::up(
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
                status TEXT NOT NULL DEFAULT 'active',
                registered_at TEXT NOT NULL,
                revoked_at TEXT,
                PRIMARY KEY (sync_id, device_id)
            );
            ",
    )])
}
