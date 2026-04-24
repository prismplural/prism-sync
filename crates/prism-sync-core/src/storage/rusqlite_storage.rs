use std::collections::HashSet;
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use tracing::warn;

use super::error::StorageError;
use super::migrations;
use super::snapshot_format::*;
use super::traits::*;
use super::types::*;
use crate::error::{CoreError, Result};

// ── Row-mapping helpers ──

fn row_to_sync_metadata(row: &rusqlite::Row<'_>) -> rusqlite::Result<SyncMetadata> {
    Ok(SyncMetadata {
        sync_id: row.get("sync_id")?,
        local_device_id: row.get("local_device_id")?,
        current_epoch: row.get("current_epoch")?,
        last_pulled_server_seq: row.get("last_pulled_server_seq")?,
        last_pushed_at: None,          // filled below
        last_successful_sync_at: None, // filled below
        registered_at: None,           // filled below
        needs_rekey: row.get::<_, i32>("needs_rekey")? != 0,
        last_imported_registry_version: row.get("last_imported_registry_version").ok(),
        created_at: Utc::now(), // filled below
        updated_at: Utc::now(), // filled below
    })
}

fn fixup_sync_metadata(
    mut m: SyncMetadata,
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<SyncMetadata> {
    // Parse optional DateTime fields from TEXT columns
    let last_pushed: Option<String> = row.get("last_pushed_at")?;
    let last_sync: Option<String> = row.get("last_successful_sync_at")?;
    let registered: Option<String> = row.get("registered_at")?;
    let created: String = row.get("created_at")?;
    let updated: String = row.get("updated_at")?;

    // We do fallible parsing inside rusqlite::Result by mapping errors
    m.last_pushed_at = last_pushed
        .and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|d| d.with_timezone(&Utc)));
    m.last_successful_sync_at = last_sync
        .and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|d| d.with_timezone(&Utc)));
    m.registered_at = registered
        .and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|d| d.with_timezone(&Utc)));
    m.created_at = DateTime::parse_from_rfc3339(&created)
        .map(|d| d.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());
    m.updated_at = DateTime::parse_from_rfc3339(&updated)
        .map(|d| d.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());
    Ok(m)
}

fn row_to_pending_op(row: &rusqlite::Row<'_>) -> rusqlite::Result<PendingOp> {
    let created_str: String = row.get("created_at")?;
    let pushed_str: Option<String> = row.get("pushed_at")?;
    Ok(PendingOp {
        op_id: row.get("op_id")?,
        sync_id: row.get("sync_id")?,
        epoch: row.get("epoch")?,
        device_id: row.get("device_id")?,
        local_batch_id: row.get("local_batch_id")?,
        entity_table: row.get("entity_table")?,
        entity_id: row.get("entity_id")?,
        field_name: row.get("field_name")?,
        encoded_value: row.get("encoded_value")?,
        is_delete: row.get::<_, i32>("is_delete")? != 0,
        client_hlc: row.get("client_hlc")?,
        created_at: DateTime::parse_from_rfc3339(&created_str)
            .map(|d| d.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now()),
        pushed_at: pushed_str
            .and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|d| d.with_timezone(&Utc))),
    })
}

fn row_to_field_version(row: &rusqlite::Row<'_>) -> rusqlite::Result<FieldVersion> {
    let updated_str: String = row.get("updated_at")?;
    Ok(FieldVersion {
        sync_id: row.get("sync_id")?,
        entity_table: row.get("entity_table")?,
        entity_id: row.get("entity_id")?,
        field_name: row.get("field_name")?,
        winning_op_id: row.get("winning_op_id")?,
        winning_device_id: row.get("winning_device_id")?,
        winning_hlc: row.get("winning_hlc")?,
        winning_encoded_value: row.get("winning_encoded_value")?,
        updated_at: DateTime::parse_from_rfc3339(&updated_str)
            .map(|d| d.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now()),
    })
}

fn row_to_device_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<DeviceRecord> {
    let registered_str: String = row.get("registered_at")?;
    let revoked_str: Option<String> = row.get("revoked_at")?;
    Ok(DeviceRecord {
        sync_id: row.get("sync_id")?,
        device_id: row.get("device_id")?,
        ed25519_public_key: row.get("ed25519_public_key")?,
        x25519_public_key: row.get("x25519_public_key")?,
        ml_dsa_65_public_key: row.get("ml_dsa_65_public_key")?,
        ml_kem_768_public_key: row.get("ml_kem_768_public_key")?,
        x_wing_public_key: row.get("x_wing_public_key")?,
        status: row.get("status")?,
        registered_at: DateTime::parse_from_rfc3339(&registered_str)
            .map(|d| d.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now()),
        revoked_at: revoked_str
            .and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|d| d.with_timezone(&Utc))),
        // SQLite stores as INTEGER (i64); safe for practical generation counts
        ml_dsa_key_generation: row.get::<_, i32>("ml_dsa_key_generation")? as u32,
    })
}

// ── Shared query implementations (used by both SyncStorage and SyncStorageTx) ──

fn query_sync_metadata(conn: &Connection, sync_id: &str) -> Result<Option<SyncMetadata>> {
    conn.query_row("SELECT * FROM sync_metadata WHERE sync_id = ?1", params![sync_id], |row| {
        let m = row_to_sync_metadata(row)?;
        fixup_sync_metadata(m, row)
    })
    .optional()
    .map_err(CoreError::from)
}

fn query_unpushed_batch_ids(conn: &Connection, sync_id: &str) -> Result<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT DISTINCT local_batch_id, MIN(created_at) AS first_created \
             FROM pending_ops WHERE sync_id = ?1 AND pushed_at IS NULL \
             GROUP BY local_batch_id ORDER BY first_created ASC",
    )?;
    let rows = stmt.query_map(params![sync_id], |row| row.get::<_, String>(0))?;
    let mut result = Vec::new();
    for r in rows {
        result.push(r?);
    }
    Ok(result)
}

fn query_batch_ops(conn: &Connection, batch_id: &str) -> Result<Vec<PendingOp>> {
    let mut stmt = conn.prepare(
        "SELECT * FROM pending_ops WHERE local_batch_id = ?1 \
             ORDER BY created_at ASC, client_hlc ASC",
    )?;
    let rows = stmt.query_map(params![batch_id], row_to_pending_op)?;
    let mut result = Vec::new();
    for r in rows {
        result.push(r?);
    }
    Ok(result)
}

fn query_is_op_applied(conn: &Connection, op_id: &str) -> Result<bool> {
    let exists: Option<i32> = conn
        .query_row("SELECT 1 FROM applied_ops WHERE op_id = ?1 LIMIT 1", params![op_id], |row| {
            row.get(0)
        })
        .optional()?;
    Ok(exists.is_some())
}

fn query_field_version(
    conn: &Connection,
    sync_id: &str,
    table: &str,
    entity_id: &str,
    field: &str,
) -> Result<Option<FieldVersion>> {
    conn.query_row(
        "SELECT * FROM field_versions \
         WHERE sync_id = ?1 AND entity_table = ?2 AND entity_id = ?3 AND field_name = ?4",
        params![sync_id, table, entity_id, field],
        row_to_field_version,
    )
    .optional()
    .map_err(CoreError::from)
}

fn query_device_record(
    conn: &Connection,
    sync_id: &str,
    device_id: &str,
) -> Result<Option<DeviceRecord>> {
    conn.query_row(
        "SELECT * FROM device_registry WHERE sync_id = ?1 AND device_id = ?2",
        params![sync_id, device_id],
        row_to_device_record,
    )
    .optional()
    .map_err(CoreError::from)
}

fn query_list_device_records(conn: &Connection, sync_id: &str) -> Result<Vec<DeviceRecord>> {
    let mut stmt = conn.prepare("SELECT * FROM device_registry WHERE sync_id = ?1")?;
    let rows = stmt.query_map(params![sync_id], row_to_device_record)?;
    let mut result = Vec::new();
    for r in rows {
        result.push(r?);
    }
    Ok(result)
}

fn query_count_prunable_applied_ops(
    conn: &Connection,
    sync_id: &str,
    below_seq: i64,
) -> Result<usize> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM applied_ops WHERE sync_id = ?1 AND server_seq < ?2",
        params![sync_id, below_seq],
        |row| row.get(0),
    )?;
    Ok(count as usize)
}

fn query_list_prunable_tombstones(
    conn: &Connection,
    sync_id: &str,
    below_seq: i64,
    limit: usize,
) -> Result<Vec<(String, String)>> {
    // Find entities whose is_deleted field_version has a winning_encoded_value of "true"
    // and whose winning op was acknowledged (exists in applied_ops with server_seq < below_seq).
    let mut stmt = conn.prepare(
        "SELECT fv.entity_table, fv.entity_id \
             FROM field_versions fv \
             JOIN applied_ops ao ON ao.op_id = fv.winning_op_id \
             WHERE fv.sync_id = ?1 \
               AND fv.field_name = 'is_deleted' \
               AND fv.winning_encoded_value = 'true' \
               AND ao.server_seq < ?2 \
             LIMIT ?3",
    )?;
    let rows = stmt.query_map(params![sync_id, below_seq, limit as i64], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut result = Vec::new();
    for r in rows {
        result.push(r?);
    }
    Ok(result)
}

// ── Write helpers (used by SyncStorageTx) ──

fn exec_upsert_sync_metadata(conn: &Connection, meta: &SyncMetadata) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO sync_metadata \
         (sync_id, local_device_id, current_epoch, last_pulled_server_seq, \
          last_pushed_at, last_successful_sync_at, registered_at, needs_rekey, \
          last_imported_registry_version, created_at, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            meta.sync_id,
            meta.local_device_id,
            meta.current_epoch,
            meta.last_pulled_server_seq,
            meta.last_pushed_at.map(|d| d.to_rfc3339()),
            meta.last_successful_sync_at.map(|d| d.to_rfc3339()),
            meta.registered_at.map(|d| d.to_rfc3339()),
            meta.needs_rekey as i32,
            meta.last_imported_registry_version,
            meta.created_at.to_rfc3339(),
            meta.updated_at.to_rfc3339(),
        ],
    )?;
    Ok(())
}

fn exec_update_last_pulled_seq(conn: &Connection, sync_id: &str, seq: i64) -> Result<()> {
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO sync_metadata \
         (sync_id, local_device_id, current_epoch, last_pulled_server_seq, created_at, updated_at) \
         VALUES (?1, '', 0, ?2, ?3, ?3) \
         ON CONFLICT(sync_id) DO UPDATE SET last_pulled_server_seq = ?2, updated_at = ?3",
        params![sync_id, seq, now],
    )?;
    Ok(())
}

fn exec_update_last_successful_sync(conn: &Connection, sync_id: &str) -> Result<()> {
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO sync_metadata \
         (sync_id, local_device_id, current_epoch, last_pulled_server_seq, \
          last_successful_sync_at, created_at, updated_at) \
         VALUES (?1, '', 0, 0, ?2, ?2, ?2) \
         ON CONFLICT(sync_id) DO UPDATE SET last_successful_sync_at = ?2, updated_at = ?2",
        params![sync_id, now],
    )?;
    Ok(())
}

fn exec_update_current_epoch(conn: &Connection, sync_id: &str, epoch: i32) -> Result<()> {
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO sync_metadata \
         (sync_id, local_device_id, current_epoch, last_pulled_server_seq, created_at, updated_at) \
         VALUES (?1, '', ?2, 0, ?3, ?3) \
         ON CONFLICT(sync_id) DO UPDATE SET \
         current_epoch = excluded.current_epoch, updated_at = excluded.updated_at",
        params![sync_id, epoch, now],
    )?;
    Ok(())
}

fn exec_update_last_imported_registry_version(
    conn: &Connection,
    sync_id: &str,
    version: i64,
) -> Result<()> {
    conn.execute(
        "UPDATE sync_metadata SET last_imported_registry_version = ?2, updated_at = ?3 WHERE sync_id = ?1",
        params![sync_id, version, Utc::now().to_rfc3339()],
    )
    ?;
    Ok(())
}

fn exec_insert_pending_op(conn: &Connection, op: &PendingOp) -> Result<()> {
    conn.execute(
        "INSERT INTO pending_ops \
         (op_id, sync_id, epoch, device_id, local_batch_id, entity_table, entity_id, \
          field_name, encoded_value, is_delete, client_hlc, created_at, pushed_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            op.op_id,
            op.sync_id,
            op.epoch,
            op.device_id,
            op.local_batch_id,
            op.entity_table,
            op.entity_id,
            op.field_name,
            op.encoded_value,
            op.is_delete as i32,
            op.client_hlc,
            op.created_at.to_rfc3339(),
            op.pushed_at.map(|d| d.to_rfc3339()),
        ],
    )?;
    Ok(())
}

fn exec_mark_batch_pushed(conn: &Connection, batch_id: &str) -> Result<()> {
    conn.execute(
        "UPDATE pending_ops SET pushed_at = ?1 WHERE local_batch_id = ?2",
        params![Utc::now().to_rfc3339(), batch_id],
    )?;
    Ok(())
}

fn exec_delete_pushed_ops(conn: &Connection, sync_id: &str) -> Result<()> {
    conn.execute(
        "DELETE FROM pending_ops WHERE sync_id = ?1 AND pushed_at IS NOT NULL",
        params![sync_id],
    )?;
    Ok(())
}

fn exec_insert_applied_op(conn: &Connection, op: &AppliedOp) -> Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO applied_ops \
         (op_id, sync_id, epoch, device_id, client_hlc, server_seq, applied_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            op.op_id,
            op.sync_id,
            op.epoch,
            op.device_id,
            op.client_hlc,
            op.server_seq,
            op.applied_at.to_rfc3339(),
        ],
    )?;
    Ok(())
}

fn exec_upsert_field_version(conn: &Connection, fv: &FieldVersion) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO field_versions \
         (sync_id, entity_table, entity_id, field_name, winning_op_id, \
          winning_device_id, winning_hlc, winning_encoded_value, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            fv.sync_id,
            fv.entity_table,
            fv.entity_id,
            fv.field_name,
            fv.winning_op_id,
            fv.winning_device_id,
            fv.winning_hlc,
            fv.winning_encoded_value,
            fv.updated_at.to_rfc3339(),
        ],
    )?;
    Ok(())
}

fn exec_upsert_device_record(conn: &Connection, device: &DeviceRecord) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO device_registry \
         (sync_id, device_id, ed25519_public_key, x25519_public_key, \
          ml_dsa_65_public_key, ml_kem_768_public_key, x_wing_public_key, status, \
          registered_at, revoked_at, ml_dsa_key_generation) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            device.sync_id,
            device.device_id,
            device.ed25519_public_key,
            device.x25519_public_key,
            device.ml_dsa_65_public_key,
            device.ml_kem_768_public_key,
            device.x_wing_public_key,
            device.status,
            device.registered_at.to_rfc3339(),
            device.revoked_at.map(|d| d.to_rfc3339()),
            device.ml_dsa_key_generation as i32,
        ],
    )?;
    Ok(())
}

fn exec_remove_device_record(conn: &Connection, sync_id: &str, device_id: &str) -> Result<()> {
    conn.execute(
        "DELETE FROM device_registry WHERE sync_id = ?1 AND device_id = ?2",
        params![sync_id, device_id],
    )?;
    Ok(())
}

fn exec_clear_sync_state(conn: &Connection, sync_id: &str) -> Result<()> {
    conn.execute("DELETE FROM pending_ops WHERE sync_id = ?1", params![sync_id])?;
    conn.execute("DELETE FROM applied_ops WHERE sync_id = ?1", params![sync_id])?;
    conn.execute("DELETE FROM field_versions WHERE sync_id = ?1", params![sync_id])?;
    conn.execute("DELETE FROM device_registry WHERE sync_id = ?1", params![sync_id])?;
    conn.execute("DELETE FROM sync_metadata WHERE sync_id = ?1", params![sync_id])?;
    Ok(())
}

fn exec_delete_applied_ops_below_seq(
    conn: &Connection,
    sync_id: &str,
    below_seq: i64,
    limit: usize,
) -> Result<usize> {
    // SQLite supports LIMIT on DELETE when compiled with SQLITE_ENABLE_UPDATE_DELETE_LIMIT,
    // but that is not always available. Use a subquery approach instead.
    let affected = conn.execute(
        "DELETE FROM applied_ops WHERE op_id IN ( \
               SELECT op_id FROM applied_ops \
               WHERE sync_id = ?1 AND server_seq < ?2 \
               LIMIT ?3 \
             )",
        params![sync_id, below_seq, limit as i64],
    )?;
    Ok(affected)
}

fn exec_delete_field_versions_for_entity(
    conn: &Connection,
    sync_id: &str,
    table: &str,
    entity_id: &str,
) -> Result<()> {
    conn.execute(
        "DELETE FROM field_versions WHERE sync_id = ?1 AND entity_table = ?2 AND entity_id = ?3",
        params![sync_id, table, entity_id],
    )?;
    Ok(())
}

// ── Snapshot helpers ──

fn query_export_snapshot(conn: &Connection, sync_id: &str) -> Result<Vec<u8>> {
    // 1. Query all field_versions for this sync_id
    let mut fv_stmt = conn.prepare("SELECT * FROM field_versions WHERE sync_id = ?1")?;
    let field_versions: Vec<FieldVersionEntry> = fv_stmt
        .query_map(params![sync_id], |row| {
            Ok(FieldVersionEntry {
                entity_table: row.get("entity_table")?,
                entity_id: row.get("entity_id")?,
                field_name: row.get("field_name")?,
                winning_hlc: row.get("winning_hlc")?,
                winning_device_id: row.get("winning_device_id")?,
                winning_op_id: row.get("winning_op_id")?,
                winning_encoded_value: row.get("winning_encoded_value")?,
                updated_at: row.get("updated_at")?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    // 2. Query all device_registry rows for this sync_id
    let mut dr_stmt = conn.prepare("SELECT * FROM device_registry WHERE sync_id = ?1")?;
    let device_registry: Vec<DeviceRegistryEntry> = dr_stmt
        .query_map(params![sync_id], |row| {
            let ed25519: Vec<u8> = row.get("ed25519_public_key")?;
            let x25519: Vec<u8> = row.get("x25519_public_key")?;
            let ml_dsa: Vec<u8> = row.get("ml_dsa_65_public_key")?;
            let ml_kem: Vec<u8> = row.get("ml_kem_768_public_key")?;
            let x_wing: Vec<u8> = row.get("x_wing_public_key")?;
            Ok(DeviceRegistryEntry {
                device_id: row.get("device_id")?,
                ed25519_public_key: hex::encode(ed25519),
                x25519_public_key: hex::encode(x25519),
                ml_dsa_65_public_key: hex::encode(ml_dsa),
                ml_kem_768_public_key: hex::encode(ml_kem),
                x_wing_public_key: hex::encode(x_wing),
                status: row.get("status")?,
                registered_at: row.get("registered_at")?,
                revoked_at: row.get("revoked_at")?,
                ml_dsa_key_generation: row.get::<_, i32>("ml_dsa_key_generation")? as u32,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    // 3. Query all applied_ops for this sync_id
    let mut ao_stmt = conn.prepare("SELECT * FROM applied_ops WHERE sync_id = ?1")?;
    let applied_ops: Vec<AppliedOpEntry> = ao_stmt
        .query_map(params![sync_id], |row| {
            Ok(AppliedOpEntry {
                op_id: row.get("op_id")?,
                sync_id: row.get("sync_id")?,
                epoch: row.get("epoch")?,
                device_id: row.get("device_id")?,
                client_hlc: row.get("client_hlc")?,
                server_seq: row.get("server_seq")?,
                applied_at: row.get("applied_at")?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    // 4. Query sync_metadata for this sync_id
    let meta = query_sync_metadata(conn, sync_id)?;
    let sync_metadata = match meta {
        Some(m) => SyncMetadataEntry {
            sync_id: m.sync_id,
            local_device_id: m.local_device_id,
            current_epoch: m.current_epoch,
            last_pulled_server_seq: m.last_pulled_server_seq,
        },
        None => {
            return Err(CoreError::Storage(StorageError::Logic(format!(
                "No sync_metadata found for sync_id={sync_id}"
            ))));
        }
    };

    // 5. Serialize to JSON
    let snapshot = SnapshotData {
        version: SNAPSHOT_VERSION,
        field_versions,
        device_registry,
        applied_ops,
        sync_metadata,
    };
    let json = serde_json::to_vec(&snapshot)?;

    // 6. Compress with zstd (level 3)
    let compressed = zstd::encode_all(json.as_slice(), 3).map_err(|e| {
        CoreError::Storage(StorageError::Logic(format!("zstd compression failed: {e}")))
    })?;

    Ok(compressed)
}

fn exec_import_snapshot(conn: &Connection, sync_id: &str, data: &[u8]) -> Result<u64> {
    // 1. Decompress zstd
    let json = zstd::decode_all(data).map_err(|e| {
        CoreError::Storage(StorageError::Logic(format!("zstd decompression failed: {e}")))
    })?;

    // 2. Parse JSON
    let snapshot: SnapshotData = serde_json::from_slice(&json)?;

    if snapshot.version != SNAPSHOT_VERSION {
        return Err(CoreError::Storage(StorageError::Logic(format!(
            "Unsupported snapshot version: {} (expected {})",
            snapshot.version, SNAPSHOT_VERSION
        ))));
    }

    // Track unique entities for the return count
    let mut entities: HashSet<(String, String)> = HashSet::new();
    let existing_local_device_id =
        query_sync_metadata(conn, sync_id)?.map(|meta| meta.local_device_id);

    // 3. Insert field_versions (INSERT OR REPLACE)
    for fv in &snapshot.field_versions {
        conn.execute(
            "INSERT OR REPLACE INTO field_versions \
             (sync_id, entity_table, entity_id, field_name, winning_op_id, \
              winning_device_id, winning_hlc, winning_encoded_value, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                sync_id,
                fv.entity_table,
                fv.entity_id,
                fv.field_name,
                fv.winning_op_id,
                fv.winning_device_id,
                fv.winning_hlc,
                fv.winning_encoded_value,
                fv.updated_at,
            ],
        )?;
        entities.insert((fv.entity_table.clone(), fv.entity_id.clone()));
    }

    // 4. Insert device_registry (INSERT OR REPLACE)
    for dr in &snapshot.device_registry {
        let ed25519 = hex::decode(&dr.ed25519_public_key).map_err(|e| {
            CoreError::Storage(StorageError::Logic(format!("bad hex in ed25519_public_key: {e}")))
        })?;
        let x25519 = hex::decode(&dr.x25519_public_key).map_err(|e| {
            CoreError::Storage(StorageError::Logic(format!("bad hex in x25519_public_key: {e}")))
        })?;
        let ml_dsa = hex::decode(&dr.ml_dsa_65_public_key).map_err(|e| {
            CoreError::Storage(StorageError::Logic(format!("bad hex in ml_dsa_65_public_key: {e}")))
        })?;
        let ml_kem = hex::decode(&dr.ml_kem_768_public_key).map_err(|e| {
            CoreError::Storage(StorageError::Logic(format!(
                "bad hex in ml_kem_768_public_key: {e}"
            )))
        })?;
        let x_wing = hex::decode(&dr.x_wing_public_key).map_err(|e| {
            CoreError::Storage(StorageError::Logic(format!("bad hex in x_wing_public_key: {e}")))
        })?;
        conn.execute(
            "INSERT OR REPLACE INTO device_registry \
             (sync_id, device_id, ed25519_public_key, x25519_public_key, \
              ml_dsa_65_public_key, ml_kem_768_public_key, x_wing_public_key, status, \
              registered_at, revoked_at, ml_dsa_key_generation) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                sync_id,
                dr.device_id,
                ed25519,
                x25519,
                ml_dsa,
                ml_kem,
                x_wing,
                dr.status,
                dr.registered_at,
                dr.revoked_at,
                dr.ml_dsa_key_generation as i32,
            ],
        )?;
    }

    // 5. Insert applied_ops (INSERT OR IGNORE — idempotent)
    for ao in &snapshot.applied_ops {
        conn.execute(
            "INSERT OR IGNORE INTO applied_ops \
             (op_id, sync_id, epoch, device_id, client_hlc, server_seq, applied_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                ao.op_id,
                sync_id,
                ao.epoch,
                ao.device_id,
                ao.client_hlc,
                ao.server_seq,
                ao.applied_at,
            ],
        )?;
    }

    // 6. Update sync_metadata (last_pulled_server_seq, current_epoch)
    let sm = &snapshot.sync_metadata;
    let local_device_id = existing_local_device_id.unwrap_or_else(|| sm.local_device_id.clone());
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "INSERT OR REPLACE INTO sync_metadata \
         (sync_id, local_device_id, current_epoch, last_pulled_server_seq, \
          needs_rekey, created_at, updated_at) \
         VALUES (?1, ?2, ?3, ?4, 0, ?5, ?5)",
        params![sync_id, local_device_id, sm.current_epoch, sm.last_pulled_server_seq, now,],
    )?;

    // 7. Return count of unique entities
    Ok(entities.len() as u64)
}

// ════════════════════════════════════════════════════════════════════════════
// RusqliteSyncStorage
// ════════════════════════════════════════════════════════════════════════════

/// Batteries-included SyncStorage + SyncStorageTx backed by rusqlite.
///
/// SQLite pragmas set on open:
/// - journal_mode = WAL (concurrent readers during sync writes)
/// - busy_timeout = 5000 (5s wait on lock contention)
/// - synchronous = NORMAL (safe with WAL, faster than FULL)
/// - foreign_keys = ON
///
/// **Durability note:** WAL + synchronous=NORMAL preserves database integrity
/// but may lose the most recent committed transaction after power loss.
/// Acceptable because lost ops will be re-pulled from the relay on next sync.
pub struct RusqliteSyncStorage {
    conn: Mutex<Connection>,
}

impl RusqliteSyncStorage {
    pub fn new(conn: Connection) -> Result<Self> {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA busy_timeout = 5000;
             PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;",
        )?;

        let mut conn = conn;
        migrations::migrations().to_latest(&mut conn).map_err(|e| {
            CoreError::Storage(StorageError::Logic(format!("Migration failed: {e}")))
        })?;

        Ok(Self { conn: Mutex::new(conn) })
    }

    /// Create a new encrypted storage backed by an existing connection.
    ///
    /// The encryption key must be applied as the very first PRAGMA before any
    /// other database operations. Uses SQLCipher's `PRAGMA key` for AES-256.
    pub fn new_encrypted(conn: Connection, key: &[u8]) -> Result<Self> {
        let hex_key = hex::encode(key);
        conn.execute_batch(&format!("PRAGMA key = \"x'{hex_key}'\";")).map_err(|e| {
            CoreError::Storage(StorageError::Logic(format!("PRAGMA key failed: {e}")))
        })?;

        // Now proceed with normal setup
        Self::new(conn)
    }

    /// Create an in-memory storage instance for testing.
    pub fn in_memory() -> Result<Self> {
        Self::new(Connection::open_in_memory()?)
    }
}

impl SyncStorage for RusqliteSyncStorage {
    fn begin_tx(&self) -> Result<Box<dyn SyncStorageTx + '_>> {
        let guard = self.conn.lock().expect("SyncStorage mutex poisoned");
        guard.execute_batch("BEGIN IMMEDIATE")?;
        Ok(Box::new(RusqliteTx { conn: guard, committed: false }))
    }

    fn get_sync_metadata(&self, sync_id: &str) -> Result<Option<SyncMetadata>> {
        let conn = self.conn.lock().expect("mutex poisoned");
        query_sync_metadata(&conn, sync_id)
    }

    fn get_unpushed_batch_ids(&self, sync_id: &str) -> Result<Vec<String>> {
        let conn = self.conn.lock().expect("mutex poisoned");
        query_unpushed_batch_ids(&conn, sync_id)
    }

    fn load_batch_ops(&self, batch_id: &str) -> Result<Vec<PendingOp>> {
        let conn = self.conn.lock().expect("mutex poisoned");
        query_batch_ops(&conn, batch_id)
    }

    fn is_op_applied(&self, op_id: &str) -> Result<bool> {
        let conn = self.conn.lock().expect("mutex poisoned");
        query_is_op_applied(&conn, op_id)
    }

    fn get_field_version(
        &self,
        sync_id: &str,
        table: &str,
        entity_id: &str,
        field: &str,
    ) -> Result<Option<FieldVersion>> {
        let conn = self.conn.lock().expect("mutex poisoned");
        query_field_version(&conn, sync_id, table, entity_id, field)
    }

    fn get_device_record(&self, sync_id: &str, device_id: &str) -> Result<Option<DeviceRecord>> {
        let conn = self.conn.lock().expect("mutex poisoned");
        query_device_record(&conn, sync_id, device_id)
    }

    fn list_device_records(&self, sync_id: &str) -> Result<Vec<DeviceRecord>> {
        let conn = self.conn.lock().expect("mutex poisoned");
        query_list_device_records(&conn, sync_id)
    }

    fn count_prunable_applied_ops(&self, sync_id: &str, below_seq: i64) -> Result<usize> {
        let conn = self.conn.lock().expect("mutex poisoned");
        query_count_prunable_applied_ops(&conn, sync_id, below_seq)
    }

    fn list_prunable_tombstones(
        &self,
        sync_id: &str,
        below_seq: i64,
        limit: usize,
    ) -> Result<Vec<(String, String)>> {
        let conn = self.conn.lock().expect("mutex poisoned");
        query_list_prunable_tombstones(&conn, sync_id, below_seq, limit)
    }

    fn export_snapshot(&self, sync_id: &str) -> Result<Vec<u8>> {
        let conn = self.conn.lock().expect("mutex poisoned");
        query_export_snapshot(&conn, sync_id)
    }

    fn rekey(&self, new_key: &[u8; 32]) -> Result<()> {
        let hex = new_key.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let conn = self
            .conn
            .lock()
            .map_err(|_| CoreError::Storage(StorageError::Logic("lock poisoned".into())))?;
        conn.execute_batch(&format!("PRAGMA rekey = \"x'{hex}'\";\n")).map_err(|e| {
            CoreError::Storage(StorageError::Logic(format!("PRAGMA rekey failed: {e}")))
        })?;
        Ok(())
    }
}

// ════════════════════════════════════════════════════════════════════════════
// RusqliteTx — transaction handle
// ════════════════════════════════════════════════════════════════════════════

/// Transaction handle that holds the MutexGuard and uses explicit SQL
/// transaction control (BEGIN IMMEDIATE / COMMIT / ROLLBACK).
///
/// No lifetime tricks or self-referential structs needed — the guard
/// keeps the connection locked for the duration of the transaction,
/// and all SQL runs directly on the guarded `&Connection`.
struct RusqliteTx<'a> {
    conn: std::sync::MutexGuard<'a, Connection>,
    committed: bool,
}

impl Drop for RusqliteTx<'_> {
    fn drop(&mut self) {
        if !self.committed {
            // Auto-rollback on drop (same as rusqlite::Transaction behavior)
            warn!("SyncStorageTx dropped without explicit commit or rollback; rolling back");
            let _ = self.conn.execute_batch("ROLLBACK");
        }
    }
}

impl SyncStorageTx for RusqliteTx<'_> {
    // ── Reads ──

    fn is_op_applied(&self, op_id: &str) -> Result<bool> {
        query_is_op_applied(&self.conn, op_id)
    }

    fn get_field_version(
        &self,
        sync_id: &str,
        table: &str,
        entity_id: &str,
        field: &str,
    ) -> Result<Option<FieldVersion>> {
        query_field_version(&self.conn, sync_id, table, entity_id, field)
    }

    fn get_device_record(&self, sync_id: &str, device_id: &str) -> Result<Option<DeviceRecord>> {
        query_device_record(&self.conn, sync_id, device_id)
    }

    // ── Sync metadata ──

    fn upsert_sync_metadata(&mut self, meta: &SyncMetadata) -> Result<()> {
        exec_upsert_sync_metadata(&self.conn, meta)
    }

    fn update_last_pulled_seq(&mut self, sync_id: &str, seq: i64) -> Result<()> {
        exec_update_last_pulled_seq(&self.conn, sync_id, seq)
    }

    fn update_last_successful_sync(&mut self, sync_id: &str) -> Result<()> {
        exec_update_last_successful_sync(&self.conn, sync_id)
    }

    fn update_current_epoch(&mut self, sync_id: &str, epoch: i32) -> Result<()> {
        exec_update_current_epoch(&self.conn, sync_id, epoch)
    }

    fn update_last_imported_registry_version(&mut self, sync_id: &str, version: i64) -> Result<()> {
        exec_update_last_imported_registry_version(&self.conn, sync_id, version)
    }

    // ── Pending ops ──

    fn insert_pending_op(&mut self, op: &PendingOp) -> Result<()> {
        exec_insert_pending_op(&self.conn, op)
    }

    fn mark_batch_pushed(&mut self, batch_id: &str) -> Result<()> {
        exec_mark_batch_pushed(&self.conn, batch_id)
    }

    fn delete_pushed_ops(&mut self, sync_id: &str) -> Result<()> {
        exec_delete_pushed_ops(&self.conn, sync_id)
    }

    // ── Applied ops ──

    fn insert_applied_op(&mut self, op: &AppliedOp) -> Result<()> {
        exec_insert_applied_op(&self.conn, op)
    }

    // ── Field versions ──

    fn upsert_field_version(&mut self, fv: &FieldVersion) -> Result<()> {
        exec_upsert_field_version(&self.conn, fv)
    }

    // ── Device registry ──

    fn upsert_device_record(&mut self, device: &DeviceRecord) -> Result<()> {
        exec_upsert_device_record(&self.conn, device)
    }

    fn remove_device_record(&mut self, sync_id: &str, device_id: &str) -> Result<()> {
        exec_remove_device_record(&self.conn, sync_id, device_id)
    }

    // ── Cleanup ──

    fn clear_sync_state(&mut self, sync_id: &str) -> Result<()> {
        exec_clear_sync_state(&self.conn, sync_id)
    }

    // ── Pruning writes ──

    fn delete_applied_ops_below_seq(
        &mut self,
        sync_id: &str,
        below_seq: i64,
        limit: usize,
    ) -> Result<usize> {
        exec_delete_applied_ops_below_seq(&self.conn, sync_id, below_seq, limit)
    }

    fn delete_field_versions_for_entity(
        &mut self,
        sync_id: &str,
        table: &str,
        entity_id: &str,
    ) -> Result<()> {
        exec_delete_field_versions_for_entity(&self.conn, sync_id, table, entity_id)
    }

    fn import_snapshot(&mut self, sync_id: &str, data: &[u8]) -> Result<u64> {
        exec_import_snapshot(&self.conn, sync_id, data)
    }

    // ── Transaction lifecycle ──

    fn commit(mut self: Box<Self>) -> Result<()> {
        self.conn.execute_batch("COMMIT")?;
        self.committed = true;
        Ok(())
    }

    fn rollback(mut self: Box<Self>) -> Result<()> {
        self.conn.execute_batch("ROLLBACK")?;
        self.committed = true; // prevent double-rollback in Drop
        Ok(())
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_storage() -> RusqliteSyncStorage {
        RusqliteSyncStorage::in_memory().expect("in_memory storage should succeed")
    }

    fn sample_metadata(sync_id: &str) -> SyncMetadata {
        let now = Utc::now();
        SyncMetadata {
            sync_id: sync_id.to_string(),
            local_device_id: "device-abc".to_string(),
            current_epoch: 1,
            last_pulled_server_seq: 42,
            last_pushed_at: Some(now),
            last_successful_sync_at: None,
            registered_at: Some(now),
            needs_rekey: false,
            last_imported_registry_version: None,
            created_at: now,
            updated_at: now,
        }
    }

    fn sample_pending_op(op_id: &str, sync_id: &str, batch_id: &str) -> PendingOp {
        PendingOp {
            op_id: op_id.to_string(),
            sync_id: sync_id.to_string(),
            epoch: 1,
            device_id: "dev1".to_string(),
            local_batch_id: batch_id.to_string(),
            entity_table: "members".to_string(),
            entity_id: "ent-1".to_string(),
            field_name: "name".to_string(),
            encoded_value: "\"Alice\"".to_string(),
            is_delete: false,
            client_hlc: "2026-01-01T00:00:00.000Z:0000:dev1".to_string(),
            created_at: Utc::now(),
            pushed_at: None,
        }
    }

    fn sample_applied_op(op_id: &str, sync_id: &str) -> AppliedOp {
        AppliedOp {
            op_id: op_id.to_string(),
            sync_id: sync_id.to_string(),
            epoch: 1,
            device_id: "dev1".to_string(),
            client_hlc: "2026-01-01T00:00:00.000Z:0000:dev1".to_string(),
            server_seq: 10,
            applied_at: Utc::now(),
        }
    }

    fn sample_field_version(sync_id: &str) -> FieldVersion {
        FieldVersion {
            sync_id: sync_id.to_string(),
            entity_table: "members".to_string(),
            entity_id: "ent-1".to_string(),
            field_name: "name".to_string(),
            winning_op_id: "op-1".to_string(),
            winning_device_id: "dev1".to_string(),
            winning_hlc: "2026-01-01T00:00:00.000Z:0000:dev1".to_string(),
            winning_encoded_value: None,
            updated_at: Utc::now(),
        }
    }

    fn sample_device_record(sync_id: &str, device_id: &str) -> DeviceRecord {
        DeviceRecord {
            sync_id: sync_id.to_string(),
            device_id: device_id.to_string(),
            ed25519_public_key: vec![1, 2, 3, 4],
            x25519_public_key: vec![5, 6, 7, 8],
            ml_dsa_65_public_key: vec![9u8; 1952],
            ml_kem_768_public_key: vec![10u8; 1184],
            x_wing_public_key: vec![],
            status: "active".to_string(),
            registered_at: Utc::now(),
            revoked_at: None,
            ml_dsa_key_generation: 0,
        }
    }

    #[test]
    fn in_memory_creates_successfully() {
        let _storage = make_storage();
    }

    #[test]
    fn insert_and_retrieve_sync_metadata() {
        let storage = make_storage();
        let meta = sample_metadata("sync-1");

        let mut tx = storage.begin_tx().unwrap();
        tx.upsert_sync_metadata(&meta).unwrap();
        tx.commit().unwrap();

        let retrieved = storage.get_sync_metadata("sync-1").unwrap();
        assert!(retrieved.is_some());
        let r = retrieved.unwrap();
        assert_eq!(r.sync_id, "sync-1");
        assert_eq!(r.local_device_id, "device-abc");
        assert_eq!(r.current_epoch, 1);
        assert_eq!(r.last_pulled_server_seq, 42);
        assert!(!r.needs_rekey);
    }

    #[test]
    fn insert_and_retrieve_pending_ops() {
        let storage = make_storage();
        let op = sample_pending_op("op-1", "sync-1", "batch-1");

        let mut tx = storage.begin_tx().unwrap();
        tx.insert_pending_op(&op).unwrap();
        tx.commit().unwrap();

        let batch_ids = storage.get_unpushed_batch_ids("sync-1").unwrap();
        assert_eq!(batch_ids, vec!["batch-1"]);

        let ops = storage.load_batch_ops("batch-1").unwrap();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].op_id, "op-1");
        assert_eq!(ops[0].entity_table, "members");
        assert_eq!(ops[0].encoded_value, "\"Alice\"");
        assert!(!ops[0].is_delete);
    }

    #[test]
    fn mark_batch_pushed_works() {
        let storage = make_storage();
        let op = sample_pending_op("op-1", "sync-1", "batch-1");

        // Insert op
        let mut tx = storage.begin_tx().unwrap();
        tx.insert_pending_op(&op).unwrap();
        tx.commit().unwrap();

        // Verify unpushed
        let batch_ids = storage.get_unpushed_batch_ids("sync-1").unwrap();
        assert_eq!(batch_ids.len(), 1);

        // Mark pushed
        let mut tx = storage.begin_tx().unwrap();
        tx.mark_batch_pushed("batch-1").unwrap();
        tx.commit().unwrap();

        // Verify no longer unpushed
        let batch_ids = storage.get_unpushed_batch_ids("sync-1").unwrap();
        assert!(batch_ids.is_empty());

        // Verify the op still exists (just has pushed_at set)
        let ops = storage.load_batch_ops("batch-1").unwrap();
        assert_eq!(ops.len(), 1);
        assert!(ops[0].pushed_at.is_some());
    }

    #[test]
    fn is_op_applied_idempotency() {
        let storage = make_storage();
        let applied = sample_applied_op("op-1", "sync-1");

        // Not applied yet
        assert!(!storage.is_op_applied("op-1").unwrap());

        // Insert
        let mut tx = storage.begin_tx().unwrap();
        tx.insert_applied_op(&applied).unwrap();
        tx.commit().unwrap();

        // Now applied
        assert!(storage.is_op_applied("op-1").unwrap());

        // Inserting again should be a no-op (INSERT OR IGNORE)
        let mut tx = storage.begin_tx().unwrap();
        tx.insert_applied_op(&applied).unwrap();
        tx.commit().unwrap();

        assert!(storage.is_op_applied("op-1").unwrap());
    }

    #[test]
    fn upsert_field_version_overwrites() {
        let storage = make_storage();
        let fv1 = sample_field_version("sync-1");

        // Insert initial
        let mut tx = storage.begin_tx().unwrap();
        tx.upsert_field_version(&fv1).unwrap();
        tx.commit().unwrap();

        let retrieved =
            storage.get_field_version("sync-1", "members", "ent-1", "name").unwrap().unwrap();
        assert_eq!(retrieved.winning_op_id, "op-1");

        // Upsert with new winning op
        let fv2 = FieldVersion {
            winning_op_id: "op-2".to_string(),
            winning_device_id: "dev2".to_string(),
            ..fv1
        };
        let mut tx = storage.begin_tx().unwrap();
        tx.upsert_field_version(&fv2).unwrap();
        tx.commit().unwrap();

        let retrieved =
            storage.get_field_version("sync-1", "members", "ent-1", "name").unwrap().unwrap();
        assert_eq!(retrieved.winning_op_id, "op-2");
        assert_eq!(retrieved.winning_device_id, "dev2");
    }

    #[test]
    fn device_record_crud() {
        let storage = make_storage();
        let device = sample_device_record("sync-1", "dev-1");

        // Insert
        let mut tx = storage.begin_tx().unwrap();
        tx.upsert_device_record(&device).unwrap();
        tx.commit().unwrap();

        // Get
        let retrieved = storage.get_device_record("sync-1", "dev-1").unwrap().unwrap();
        assert_eq!(retrieved.device_id, "dev-1");
        assert_eq!(retrieved.ed25519_public_key, vec![1, 2, 3, 4]);
        assert_eq!(retrieved.status, "active");

        // List
        let device2 = sample_device_record("sync-1", "dev-2");
        let mut tx = storage.begin_tx().unwrap();
        tx.upsert_device_record(&device2).unwrap();
        tx.commit().unwrap();

        let devices = storage.list_device_records("sync-1").unwrap();
        assert_eq!(devices.len(), 2);

        // Remove
        let mut tx = storage.begin_tx().unwrap();
        tx.remove_device_record("sync-1", "dev-1").unwrap();
        tx.commit().unwrap();

        assert!(storage.get_device_record("sync-1", "dev-1").unwrap().is_none());
        assert_eq!(storage.list_device_records("sync-1").unwrap().len(), 1);
    }

    #[test]
    fn transaction_commit_persists() {
        let storage = make_storage();
        let meta = sample_metadata("sync-1");

        let mut tx = storage.begin_tx().unwrap();
        tx.upsert_sync_metadata(&meta).unwrap();
        tx.commit().unwrap();

        // Data should be visible after commit
        assert!(storage.get_sync_metadata("sync-1").unwrap().is_some());
    }

    #[test]
    fn transaction_rollback_reverts() {
        let storage = make_storage();
        let meta = sample_metadata("sync-1");

        // Insert and commit first record
        let mut tx = storage.begin_tx().unwrap();
        tx.upsert_sync_metadata(&meta).unwrap();
        tx.commit().unwrap();

        // Start new tx, insert pending op, then drop without commit
        {
            let mut tx = storage.begin_tx().unwrap();
            let op = sample_pending_op("op-rollback", "sync-1", "batch-rollback");
            tx.insert_pending_op(&op).unwrap();
            // Drop without commit — auto-rollback
            drop(tx);
        }

        // Pending op should NOT be visible
        let ops = storage.load_batch_ops("batch-rollback").unwrap();
        assert!(ops.is_empty());

        // But the committed metadata should still be there
        assert!(storage.get_sync_metadata("sync-1").unwrap().is_some());
    }

    #[test]
    fn clear_sync_state_removes_all_data() {
        let storage = make_storage();

        // Insert data across all tables
        let mut tx = storage.begin_tx().unwrap();
        tx.upsert_sync_metadata(&sample_metadata("sync-1")).unwrap();
        tx.insert_pending_op(&sample_pending_op("op-1", "sync-1", "batch-1")).unwrap();
        tx.insert_applied_op(&sample_applied_op("applied-1", "sync-1")).unwrap();
        tx.upsert_field_version(&sample_field_version("sync-1")).unwrap();
        tx.upsert_device_record(&sample_device_record("sync-1", "dev-1")).unwrap();
        tx.commit().unwrap();

        // Verify data exists
        assert!(storage.get_sync_metadata("sync-1").unwrap().is_some());
        assert!(!storage.get_unpushed_batch_ids("sync-1").unwrap().is_empty());
        assert!(storage.is_op_applied("applied-1").unwrap());
        assert!(storage.get_field_version("sync-1", "members", "ent-1", "name").unwrap().is_some());
        assert!(!storage.list_device_records("sync-1").unwrap().is_empty());

        // Clear
        let mut tx = storage.begin_tx().unwrap();
        tx.clear_sync_state("sync-1").unwrap();
        tx.commit().unwrap();

        // Verify all data removed
        assert!(storage.get_sync_metadata("sync-1").unwrap().is_none());
        assert!(storage.get_unpushed_batch_ids("sync-1").unwrap().is_empty());
        assert!(!storage.is_op_applied("applied-1").unwrap());
        assert!(storage.get_field_version("sync-1", "members", "ent-1", "name").unwrap().is_none());
        assert!(storage.list_device_records("sync-1").unwrap().is_empty());
    }

    #[test]
    fn delete_pushed_ops_removes_only_pushed() {
        let storage = make_storage();

        // Insert two ops in different batches
        let mut tx = storage.begin_tx().unwrap();
        tx.insert_pending_op(&sample_pending_op("op-1", "sync-1", "batch-1")).unwrap();
        tx.insert_pending_op(&sample_pending_op("op-2", "sync-1", "batch-2")).unwrap();
        // Mark only batch-1 as pushed
        tx.mark_batch_pushed("batch-1").unwrap();
        tx.commit().unwrap();

        // Delete pushed ops
        let mut tx = storage.begin_tx().unwrap();
        tx.delete_pushed_ops("sync-1").unwrap();
        tx.commit().unwrap();

        // batch-1 op should be gone, batch-2 op should remain
        let ops1 = storage.load_batch_ops("batch-1").unwrap();
        assert!(ops1.is_empty());

        let ops2 = storage.load_batch_ops("batch-2").unwrap();
        assert_eq!(ops2.len(), 1);
    }

    #[test]
    fn update_last_pulled_seq_works() {
        let storage = make_storage();
        let meta = sample_metadata("sync-1");

        let mut tx = storage.begin_tx().unwrap();
        tx.upsert_sync_metadata(&meta).unwrap();
        tx.commit().unwrap();

        let mut tx = storage.begin_tx().unwrap();
        tx.update_last_pulled_seq("sync-1", 100).unwrap();
        tx.commit().unwrap();

        let retrieved = storage.get_sync_metadata("sync-1").unwrap().unwrap();
        assert_eq!(retrieved.last_pulled_server_seq, 100);
    }

    #[test]
    fn update_last_successful_sync_works() {
        let storage = make_storage();
        let meta = sample_metadata("sync-1");

        let mut tx = storage.begin_tx().unwrap();
        tx.upsert_sync_metadata(&meta).unwrap();
        tx.commit().unwrap();

        let mut tx = storage.begin_tx().unwrap();
        tx.update_last_successful_sync("sync-1").unwrap();
        tx.commit().unwrap();

        let retrieved = storage.get_sync_metadata("sync-1").unwrap().unwrap();
        assert!(retrieved.last_successful_sync_at.is_some());
    }

    #[test]
    fn update_current_epoch_works() {
        let storage = make_storage();
        let meta = sample_metadata("sync-1");

        let mut tx = storage.begin_tx().unwrap();
        tx.upsert_sync_metadata(&meta).unwrap();
        tx.commit().unwrap();

        let mut tx = storage.begin_tx().unwrap();
        tx.update_current_epoch("sync-1", 7).unwrap();
        tx.commit().unwrap();

        let retrieved = storage.get_sync_metadata("sync-1").unwrap().unwrap();
        assert_eq!(retrieved.current_epoch, 7);
        assert_eq!(retrieved.local_device_id, meta.local_device_id);
        assert_eq!(retrieved.last_pulled_server_seq, meta.last_pulled_server_seq);
        assert_eq!(retrieved.last_pushed_at, meta.last_pushed_at);
        assert_eq!(retrieved.registered_at, meta.registered_at);
    }

    #[test]
    fn update_current_epoch_creates_sync_metadata_when_missing() {
        let storage = make_storage();

        let mut tx = storage.begin_tx().unwrap();
        tx.update_current_epoch("sync-1", 7).unwrap();
        tx.commit().unwrap();

        let retrieved = storage.get_sync_metadata("sync-1").unwrap().unwrap();
        assert_eq!(retrieved.sync_id, "sync-1");
        assert_eq!(retrieved.local_device_id, "");
        assert_eq!(retrieved.current_epoch, 7);
        assert_eq!(retrieved.last_pulled_server_seq, 0);
        assert!(retrieved.last_pushed_at.is_none());
        assert!(retrieved.last_successful_sync_at.is_none());
        assert!(retrieved.registered_at.is_none());
        assert!(!retrieved.needs_rekey);
        assert!(retrieved.last_imported_registry_version.is_none());
        assert_eq!(retrieved.created_at, retrieved.updated_at);
    }

    #[test]
    fn tx_reads_within_transaction() {
        let storage = make_storage();

        // Insert data
        let mut tx = storage.begin_tx().unwrap();
        tx.upsert_field_version(&sample_field_version("sync-1")).unwrap();
        tx.insert_applied_op(&sample_applied_op("applied-1", "sync-1")).unwrap();
        tx.upsert_device_record(&sample_device_record("sync-1", "dev-1")).unwrap();

        // Read within same transaction (before commit)
        assert!(tx.is_op_applied("applied-1").unwrap());
        assert!(tx.get_field_version("sync-1", "members", "ent-1", "name").unwrap().is_some());
        assert!(tx.get_device_record("sync-1", "dev-1").unwrap().is_some());

        tx.commit().unwrap();
    }

    #[test]
    fn pruning_count_applied_ops() {
        let storage = make_storage();

        // Insert applied ops with different server_seqs
        let mut tx = storage.begin_tx().unwrap();
        for i in 1i64..=5 {
            tx.insert_applied_op(&AppliedOp {
                op_id: format!("op-{i}"),
                sync_id: "sync-1".to_string(),
                epoch: 1,
                device_id: "dev1".to_string(),
                client_hlc: format!("2026-01-01T00:00:00.000Z:{i:04}:dev1"),
                server_seq: i * 10,
                applied_at: Utc::now(),
            })
            .unwrap();
        }
        tx.commit().unwrap();

        // Count ops below seq 35 (ops 10, 20, 30 → 3 ops)
        let count = storage.count_prunable_applied_ops("sync-1", 35).unwrap();
        assert_eq!(count, 3);
    }

    #[test]
    fn pruning_delete_applied_ops_below_seq() {
        let storage = make_storage();

        let mut tx = storage.begin_tx().unwrap();
        for i in 1i64..=5 {
            tx.insert_applied_op(&AppliedOp {
                op_id: format!("op-{i}"),
                sync_id: "sync-1".to_string(),
                epoch: 1,
                device_id: "dev1".to_string(),
                client_hlc: format!("2026-01-01T00:00:00.000Z:{i:04}:dev1"),
                server_seq: i * 10,
                applied_at: Utc::now(),
            })
            .unwrap();
        }
        tx.commit().unwrap();

        // Delete ops below seq 35 (ops 10, 20, 30)
        let mut tx = storage.begin_tx().unwrap();
        let deleted = tx.delete_applied_ops_below_seq("sync-1", 35, 10).unwrap();
        tx.commit().unwrap();
        assert_eq!(deleted, 3);

        // ops 40 and 50 should remain
        assert!(storage.is_op_applied("op-4").unwrap());
        assert!(storage.is_op_applied("op-5").unwrap());
        assert!(!storage.is_op_applied("op-1").unwrap());
    }

    #[test]
    fn pruning_delete_field_versions_for_entity() {
        let storage = make_storage();

        let mut tx = storage.begin_tx().unwrap();
        // Insert two field versions for the same entity
        tx.upsert_field_version(&FieldVersion {
            sync_id: "sync-1".to_string(),
            entity_table: "members".to_string(),
            entity_id: "ent-1".to_string(),
            field_name: "name".to_string(),
            winning_op_id: "op-1".to_string(),
            winning_device_id: "dev1".to_string(),
            winning_hlc: "2026-01-01T00:00:00.000Z:0001:dev1".to_string(),
            winning_encoded_value: Some("\"Alice\"".to_string()),
            updated_at: Utc::now(),
        })
        .unwrap();
        tx.upsert_field_version(&FieldVersion {
            sync_id: "sync-1".to_string(),
            entity_table: "members".to_string(),
            entity_id: "ent-1".to_string(),
            field_name: "is_deleted".to_string(),
            winning_op_id: "op-2".to_string(),
            winning_device_id: "dev1".to_string(),
            winning_hlc: "2026-01-01T00:00:00.000Z:0002:dev1".to_string(),
            winning_encoded_value: Some("true".to_string()),
            updated_at: Utc::now(),
        })
        .unwrap();
        // Insert field version for a different entity (should not be deleted)
        tx.upsert_field_version(&FieldVersion {
            sync_id: "sync-1".to_string(),
            entity_table: "members".to_string(),
            entity_id: "ent-2".to_string(),
            field_name: "name".to_string(),
            winning_op_id: "op-3".to_string(),
            winning_device_id: "dev1".to_string(),
            winning_hlc: "2026-01-01T00:00:00.000Z:0003:dev1".to_string(),
            winning_encoded_value: None,
            updated_at: Utc::now(),
        })
        .unwrap();
        tx.commit().unwrap();

        // Delete field versions for ent-1
        let mut tx = storage.begin_tx().unwrap();
        tx.delete_field_versions_for_entity("sync-1", "members", "ent-1").unwrap();
        tx.commit().unwrap();

        // ent-1 versions should be gone
        assert!(storage.get_field_version("sync-1", "members", "ent-1", "name").unwrap().is_none());
        assert!(storage
            .get_field_version("sync-1", "members", "ent-1", "is_deleted")
            .unwrap()
            .is_none());

        // ent-2 version should remain
        assert!(storage.get_field_version("sync-1", "members", "ent-2", "name").unwrap().is_some());
    }

    #[test]
    fn pruning_list_prunable_tombstones() {
        let storage = make_storage();

        let mut tx = storage.begin_tx().unwrap();
        // Insert an applied op for the delete operation
        tx.insert_applied_op(&AppliedOp {
            op_id: "delete-op-1".to_string(),
            sync_id: "sync-1".to_string(),
            epoch: 1,
            device_id: "dev1".to_string(),
            client_hlc: "2026-01-01T00:00:00.000Z:0001:dev1".to_string(),
            server_seq: 5,
            applied_at: Utc::now(),
        })
        .unwrap();
        // Insert field version linking the delete op
        tx.upsert_field_version(&FieldVersion {
            sync_id: "sync-1".to_string(),
            entity_table: "members".to_string(),
            entity_id: "ent-deleted".to_string(),
            field_name: "is_deleted".to_string(),
            winning_op_id: "delete-op-1".to_string(),
            winning_device_id: "dev1".to_string(),
            winning_hlc: "2026-01-01T00:00:00.000Z:0001:dev1".to_string(),
            winning_encoded_value: Some("true".to_string()),
            updated_at: Utc::now(),
        })
        .unwrap();
        tx.commit().unwrap();

        // Should find the tombstone below seq 10
        let tombstones = storage.list_prunable_tombstones("sync-1", 10, 100).unwrap();
        assert_eq!(tombstones.len(), 1);
        assert_eq!(tombstones[0].0, "members");
        assert_eq!(tombstones[0].1, "ent-deleted");

        // Should NOT find it below seq 5 (exclusive)
        let tombstones = storage.list_prunable_tombstones("sync-1", 5, 100).unwrap();
        assert!(tombstones.is_empty());
    }

    // ── Snapshot tests ──

    /// Populate a storage instance with representative data for snapshot tests.
    fn populate_for_snapshot(storage: &RusqliteSyncStorage) {
        let mut tx = storage.begin_tx().unwrap();
        tx.upsert_sync_metadata(&sample_metadata("sync-1")).unwrap();
        tx.upsert_field_version(&FieldVersion {
            sync_id: "sync-1".to_string(),
            entity_table: "members".to_string(),
            entity_id: "ent-1".to_string(),
            field_name: "name".to_string(),
            winning_op_id: "op-1".to_string(),
            winning_device_id: "dev1".to_string(),
            winning_hlc: "2026-01-01T00:00:00.000Z:0001:dev1".to_string(),
            winning_encoded_value: Some("\"Alice\"".to_string()),
            updated_at: Utc::now(),
        })
        .unwrap();
        tx.upsert_field_version(&FieldVersion {
            sync_id: "sync-1".to_string(),
            entity_table: "members".to_string(),
            entity_id: "ent-1".to_string(),
            field_name: "pronouns".to_string(),
            winning_op_id: "op-2".to_string(),
            winning_device_id: "dev1".to_string(),
            winning_hlc: "2026-01-01T00:00:00.000Z:0002:dev1".to_string(),
            winning_encoded_value: Some("\"she/her\"".to_string()),
            updated_at: Utc::now(),
        })
        .unwrap();
        tx.upsert_field_version(&FieldVersion {
            sync_id: "sync-1".to_string(),
            entity_table: "sessions".to_string(),
            entity_id: "ent-2".to_string(),
            field_name: "started_at".to_string(),
            winning_op_id: "op-3".to_string(),
            winning_device_id: "dev1".to_string(),
            winning_hlc: "2026-01-01T00:00:00.000Z:0003:dev1".to_string(),
            winning_encoded_value: Some("\"2026-01-01T00:00:00Z\"".to_string()),
            updated_at: Utc::now(),
        })
        .unwrap();
        tx.upsert_device_record(&sample_device_record("sync-1", "dev-1")).unwrap();
        tx.upsert_device_record(&sample_device_record("sync-1", "dev-2")).unwrap();
        tx.insert_applied_op(&AppliedOp {
            op_id: "applied-1".to_string(),
            sync_id: "sync-1".to_string(),
            epoch: 1,
            device_id: "dev1".to_string(),
            client_hlc: "2026-01-01T00:00:00.000Z:0001:dev1".to_string(),
            server_seq: 10,
            applied_at: Utc::now(),
        })
        .unwrap();
        tx.insert_applied_op(&AppliedOp {
            op_id: "applied-2".to_string(),
            sync_id: "sync-1".to_string(),
            epoch: 1,
            device_id: "dev1".to_string(),
            client_hlc: "2026-01-01T00:00:00.000Z:0002:dev1".to_string(),
            server_seq: 20,
            applied_at: Utc::now(),
        })
        .unwrap();
        tx.commit().unwrap();
    }

    #[test]
    fn export_snapshot_produces_compressed_data() {
        let storage = make_storage();
        populate_for_snapshot(&storage);

        let blob = storage.export_snapshot("sync-1").unwrap();
        // Compressed data should be non-empty
        assert!(!blob.is_empty());
        // Verify it decompresses to valid JSON
        let json = zstd::decode_all(blob.as_slice()).unwrap();
        let snapshot: SnapshotData = serde_json::from_slice(&json).unwrap();
        assert_eq!(snapshot.version, SNAPSHOT_VERSION);
        assert_eq!(snapshot.field_versions.len(), 3);
        assert_eq!(snapshot.device_registry.len(), 2);
        assert_eq!(snapshot.applied_ops.len(), 2);
        assert_eq!(snapshot.sync_metadata.sync_id, "sync-1");
        assert_eq!(snapshot.sync_metadata.last_pulled_server_seq, 42);
        assert_eq!(snapshot.sync_metadata.current_epoch, 1);
    }

    #[test]
    fn export_snapshot_missing_metadata_returns_error() {
        let storage = make_storage();
        // No data inserted — should error
        let result = storage.export_snapshot("nonexistent");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("No sync_metadata"));
    }

    #[test]
    fn import_snapshot_roundtrip() {
        // Export from one storage, import into another
        let src = make_storage();
        populate_for_snapshot(&src);
        let blob = src.export_snapshot("sync-1").unwrap();

        let dst = make_storage();
        let mut tx = dst.begin_tx().unwrap();
        let entity_count = tx.import_snapshot("sync-1", &blob).unwrap();
        tx.commit().unwrap();

        // 2 unique entities: (members, ent-1) and (sessions, ent-2)
        assert_eq!(entity_count, 2);

        // Verify field_versions were imported
        let fv = dst.get_field_version("sync-1", "members", "ent-1", "name").unwrap().unwrap();
        assert_eq!(fv.winning_op_id, "op-1");
        assert_eq!(fv.winning_encoded_value, Some("\"Alice\"".to_string()));

        let fv2 =
            dst.get_field_version("sync-1", "sessions", "ent-2", "started_at").unwrap().unwrap();
        assert_eq!(fv2.winning_op_id, "op-3");

        // Verify device_registry was imported
        let devices = dst.list_device_records("sync-1").unwrap();
        assert_eq!(devices.len(), 2);
        // Check keys were hex round-tripped correctly
        let d1 = dst.get_device_record("sync-1", "dev-1").unwrap().unwrap();
        assert_eq!(d1.ed25519_public_key, vec![1, 2, 3, 4]);
        assert_eq!(d1.x25519_public_key, vec![5, 6, 7, 8]);
        assert_eq!(d1.ml_dsa_65_public_key, vec![9u8; 1952]);
        assert_eq!(d1.ml_kem_768_public_key, vec![10u8; 1184]);
        assert_eq!(d1.ml_dsa_key_generation, 0);

        // Verify applied_ops were imported
        assert!(dst.is_op_applied("applied-1").unwrap());
        assert!(dst.is_op_applied("applied-2").unwrap());

        // Verify sync_metadata was imported
        let meta = dst.get_sync_metadata("sync-1").unwrap().unwrap();
        assert_eq!(meta.current_epoch, 1);
        assert_eq!(meta.last_pulled_server_seq, 42);
    }

    #[test]
    fn import_snapshot_is_idempotent() {
        let src = make_storage();
        populate_for_snapshot(&src);
        let blob = src.export_snapshot("sync-1").unwrap();

        let dst = make_storage();

        // Import twice — should not error
        let mut tx = dst.begin_tx().unwrap();
        tx.import_snapshot("sync-1", &blob).unwrap();
        tx.commit().unwrap();

        let mut tx = dst.begin_tx().unwrap();
        let count = tx.import_snapshot("sync-1", &blob).unwrap();
        tx.commit().unwrap();

        assert_eq!(count, 2);

        // Data should still be correct
        let fv = dst.get_field_version("sync-1", "members", "ent-1", "name").unwrap().unwrap();
        assert_eq!(fv.winning_op_id, "op-1");
    }

    #[test]
    fn import_snapshot_invalid_data_returns_error() {
        let storage = make_storage();
        let mut tx = storage.begin_tx().unwrap();
        // Random bytes that aren't valid zstd
        let result = tx.import_snapshot("sync-1", &[0xFF, 0xFE, 0xFD]);
        assert!(result.is_err());
    }

    #[test]
    fn export_snapshot_device_keys_hex_encoded() {
        let storage = make_storage();
        populate_for_snapshot(&storage);
        let blob = storage.export_snapshot("sync-1").unwrap();
        let json = zstd::decode_all(blob.as_slice()).unwrap();
        let snapshot: SnapshotData = serde_json::from_slice(&json).unwrap();

        // Keys should be hex-encoded in the snapshot
        for dr in &snapshot.device_registry {
            assert_eq!(dr.ed25519_public_key, "01020304");
            assert_eq!(dr.x25519_public_key, "05060708");
            assert_eq!(dr.ml_dsa_65_public_key, hex::encode(vec![9u8; 1952]));
            assert_eq!(dr.ml_kem_768_public_key, hex::encode(vec![10u8; 1184]));
        }
    }

    #[test]
    fn snapshot_compression_reduces_size() {
        let storage = make_storage();
        populate_for_snapshot(&storage);
        let blob = storage.export_snapshot("sync-1").unwrap();

        // Decompress to get raw JSON size
        let json = zstd::decode_all(blob.as_slice()).unwrap();

        // Compressed should be smaller than raw JSON
        // (for very small data this may not always hold, but our test data
        // has enough repetition)
        assert!(blob.len() <= json.len(), "compressed {} >= raw json {}", blob.len(), json.len());
    }

    #[test]
    fn snapshot_roundtrip_preserves_nonzero_ml_dsa_generation() {
        let src = make_storage();
        populate_for_snapshot(&src);

        // Update dev-1 to generation 5
        let mut dev = src.get_device_record("sync-1", "dev-1").unwrap().unwrap();
        dev.ml_dsa_key_generation = 5;
        let mut tx = src.begin_tx().unwrap();
        tx.upsert_device_record(&dev).unwrap();
        tx.commit().unwrap();

        // Export and import
        let blob = src.export_snapshot("sync-1").unwrap();
        let dst = make_storage();
        let mut tx = dst.begin_tx().unwrap();
        tx.import_snapshot("sync-1", &blob).unwrap();
        tx.commit().unwrap();

        // Verify non-zero generation survived
        let imported = dst.get_device_record("sync-1", "dev-1").unwrap().unwrap();
        assert_eq!(
            imported.ml_dsa_key_generation, 5,
            "ml_dsa_key_generation should survive snapshot round-trip"
        );
    }

    #[test]
    fn rekey_changes_encryption_key() {
        // Use a unique temp file path
        let path = std::env::temp_dir().join(format!(
            "prism_rekey_test_{}.db",
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));

        // Create an encrypted database with key [1u8; 32]
        let conn1 = Connection::open(&path).unwrap();
        let storage = RusqliteSyncStorage::new_encrypted(conn1, &[1u8; 32]).unwrap();

        // Rekey to [2u8; 32]
        let new_key = [2u8; 32];
        storage.rekey(&new_key).unwrap();
        drop(storage);

        // Open with new key — should succeed
        let conn2 = Connection::open(&path).unwrap();
        let storage2 = RusqliteSyncStorage::new_encrypted(conn2, &[2u8; 32]);
        assert!(storage2.is_ok(), "opening with new key should succeed");

        // Cleanup
        let _ = std::fs::remove_file(&path);
    }
}
