use std::collections::HashSet;
use std::sync::Mutex;

use chrono::{DateTime, SecondsFormat, Utc};
use rusqlite::{params, types::Type, Connection, OptionalExtension};
use tracing::warn;

use super::error::StorageError;
use super::migrations;
use super::snapshot_format::*;
use super::traits::*;
use super::types::*;
use crate::device_registry::{registry_import_action, RegistryImportAction, RegistryImportSource};
use crate::error::{CoreError, Result};
use crate::hlc::Hlc;

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

fn row_to_quarantined_op(row: &rusqlite::Row<'_>) -> rusqlite::Result<QuarantinedOp> {
    let quarantined_at: String = row.get("quarantined_at")?;
    let op_json: String = row.get("op_json")?;
    let op = serde_json::from_str(&op_json)
        .map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, Type::Text, Box::new(e)))?;

    Ok(QuarantinedOp {
        sync_id: row.get("sync_id")?,
        op_id: row.get("op_id")?,
        op,
        reason: row.get("reason")?,
        server_seq: row.get("server_seq")?,
        quarantined_at: DateTime::parse_from_rfc3339(&quarantined_at)
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
    // Exclude batches that are currently quarantined (their envelope exceeded
    // the relay body cap on a previous push). The push loop in `engine/mod.rs`
    // also has a defensive `continue` for any batch whose envelope measures
    // over the client-side guard, but excluding them here keeps the cycle
    // from even loading their op rows.
    //
    // ORDER BY first_created with first_hlc as a secondary tiebreaker. The
    // primary sort is fixed-width microsecond timestamps (see
    // `exec_insert_pending_op`), so lexical order on TEXT matches chronological
    // order. The HLC tiebreaker is belt-and-suspenders: HLCs are monotonic per
    // device (`{ms:013}:{counter:010}:{node_id}`), so even if two batches share
    // an identical `created_at` they still resolve to a deterministic partition
    // ordering — and any pre-existing variable-width rows from before Fix A
    // still partition correctly behind it.
    let mut stmt = conn.prepare(
        "SELECT DISTINCT local_batch_id, \
                MIN(created_at) AS first_created, \
                MIN(client_hlc) AS first_hlc \
             FROM pending_ops WHERE sync_id = ?1 AND pushed_at IS NULL \
               AND local_batch_id NOT IN ( \
                   SELECT batch_id FROM push_quarantine WHERE sync_id = ?1 \
               ) \
             GROUP BY local_batch_id \
             ORDER BY first_created ASC, first_hlc ASC",
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

fn query_quarantined_ops(conn: &Connection, sync_id: &str) -> Result<Vec<QuarantinedOp>> {
    let mut stmt = conn.prepare(
        "SELECT * FROM quarantined_ops \
         WHERE sync_id = ?1 \
         ORDER BY server_seq ASC, quarantined_at ASC, op_id ASC",
    )?;
    let rows = stmt.query_map(params![sync_id], row_to_quarantined_op)?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

fn row_to_quarantined_pull_batch(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<QuarantinedPullBatch> {
    let envelope_json: String = row.get("envelope_json")?;
    let envelope = serde_json::from_str(&envelope_json)
        .map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, Type::Text, Box::new(e)))?;
    let quarantined_at: String = row.get("quarantined_at")?;
    let last_retry_at: Option<String> = row.get("last_retry_at")?;
    Ok(QuarantinedPullBatch {
        sync_id: row.get("sync_id")?,
        batch_id: row.get("batch_id")?,
        server_seq: row.get("server_seq")?,
        epoch: row.get::<_, Option<i32>>("epoch")?,
        sender_device_id: row.get("sender_device_id")?,
        envelope,
        reason: row.get("reason")?,
        retry_count: row.get("retry_count")?,
        quarantined_at: DateTime::parse_from_rfc3339(&quarantined_at)
            .map(|d| d.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now()),
        last_retry_at: last_retry_at
            .and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|d| d.with_timezone(&Utc))),
    })
}

fn query_quarantined_pull_batches(
    conn: &Connection,
    sync_id: &str,
) -> Result<Vec<QuarantinedPullBatch>> {
    let mut stmt = conn.prepare(
        "SELECT * FROM quarantined_pull_batches \
         WHERE sync_id = ?1 \
         ORDER BY server_seq ASC, quarantined_at ASC, batch_id ASC",
    )?;
    let rows = stmt.query_map(params![sync_id], row_to_quarantined_pull_batch)?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

fn row_to_pull_stall(row: &rusqlite::Row<'_>) -> rusqlite::Result<PullStall> {
    let first_seen_at: String = row.get("first_seen_at")?;
    let last_seen_at: String = row.get("last_seen_at")?;
    Ok(PullStall {
        sync_id: row.get("sync_id")?,
        server_seq: row.get("server_seq")?,
        reason: row.get("reason")?,
        attempts: row.get("attempts")?,
        first_seen_at: DateTime::parse_from_rfc3339(&first_seen_at)
            .map(|d| d.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now()),
        last_seen_at: DateTime::parse_from_rfc3339(&last_seen_at)
            .map(|d| d.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now()),
    })
}

fn query_pull_stalls(conn: &Connection, sync_id: &str) -> Result<Vec<PullStall>> {
    let mut stmt = conn.prepare(
        "SELECT * FROM pull_stall WHERE sync_id = ?1 ORDER BY server_seq ASC",
    )?;
    let rows = stmt.query_map(params![sync_id], row_to_pull_stall)?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

fn row_to_consumer_delivery(row: &rusqlite::Row<'_>) -> rusqlite::Result<ConsumerDelivery> {
    let created_at: String = row.get("created_at")?;
    Ok(ConsumerDelivery {
        id: row.get("id")?,
        sync_id: row.get("sync_id")?,
        entity_table: row.get("entity_table")?,
        entity_id: row.get("entity_id")?,
        field_name: row.get("field_name")?,
        encoded_value: row.get("encoded_value")?,
        is_delete: row.get::<_, i64>("is_delete")? != 0,
        server_seq: row.get("server_seq")?,
        created_at: DateTime::parse_from_rfc3339(&created_at)
            .map(|d| d.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now()),
    })
}

fn query_list_consumer_deliveries(
    conn: &Connection,
    sync_id: &str,
    after_id: i64,
    limit: i64,
) -> Result<Vec<ConsumerDelivery>> {
    let mut stmt = conn.prepare(
        "SELECT * FROM consumer_deliveries \
         WHERE sync_id = ?1 AND id > ?2 \
         ORDER BY id ASC \
         LIMIT ?3",
    )?;
    let rows = stmt.query_map(params![sync_id, after_id, limit], row_to_consumer_delivery)?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

fn query_count_consumer_deliveries(conn: &Connection, sync_id: &str) -> Result<i64> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM consumer_deliveries WHERE sync_id = ?1",
        params![sync_id],
        |row| row.get(0),
    )?;
    Ok(count)
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
    // MAX-monotonic: never rewind. Quarantine replay (Phase 0b) re-applies past
    // batches without their server_seq, so the cursor must not move backwards
    // here. Legitimate rewinds go through `exec_reset_last_pulled_seq`.
    conn.execute(
        "INSERT INTO sync_metadata \
         (sync_id, local_device_id, current_epoch, last_pulled_server_seq, created_at, updated_at) \
         VALUES (?1, '', 0, ?2, ?3, ?3) \
         ON CONFLICT(sync_id) DO UPDATE SET \
         last_pulled_server_seq = MAX(last_pulled_server_seq, ?2), updated_at = ?3",
        params![sync_id, seq, now],
    )?;
    Ok(())
}

fn exec_reset_last_pulled_seq(conn: &Connection, sync_id: &str, seq: i64) -> Result<()> {
    let now = Utc::now().to_rfc3339();
    // Unconditional set (may rewind). Escape hatch for bootstrap/reset and the
    // relay-log lineage change, where the server-seq space itself changed.
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
    // MAX-monotonic in SQL so the replay-freshness baseline can never rewind,
    // even when two ratchets race (pairing-initiator publish vs the sync-loop
    // repair publisher, or a catch-up import once the baseline ratchet is wired in — storage
    // is a shared Arc<dyn SyncStorage> and the FFI ceremonies run outside the
    // Mutex<PrismSync>). The helper's read-side early-out is only an
    // optimization; this clamp is the actual atomic guarantee, mirroring
    // exec_update_last_pulled_seq. A NULL baseline (COALESCE) is treated as
    // below everything, so the first write lands.
    conn.execute(
        "UPDATE sync_metadata \
         SET last_imported_registry_version = \
                 MAX(COALESCE(last_imported_registry_version, ?2), ?2), \
             updated_at = ?3 \
         WHERE sync_id = ?1",
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
            // Fixed-width microseconds so TEXT ordering matches chronological
            // ordering across partition boundaries. `to_rfc3339()` strips
            // trailing zeros, so timestamps with different microsecond widths
            // would sort lexically out of order in `query_unpushed_batch_ids`.
            op.created_at.to_rfc3339_opts(SecondsFormat::Micros, true),
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

fn exec_delete_pushed_ops(conn: &Connection, sync_id: &str, batch_id: &str) -> Result<()> {
    conn.execute(
        "DELETE FROM pending_ops \
         WHERE sync_id = ?1 AND local_batch_id = ?2 AND pushed_at IS NOT NULL",
        params![sync_id, batch_id],
    )?;
    Ok(())
}

/// Rewrite `local_batch_id` on a single pending_ops row identified by op_id.
/// Used by Phase 1C recovery to repartition a quarantined batch into smaller
/// sub-batches without altering any other field on the row. Returns an error
/// if the update affected zero rows (caller passed an op_id that no longer
/// exists, indicating a torn pre-load state we shouldn't silently accept).
fn exec_update_pending_op_batch_id(
    conn: &Connection,
    op_id: &str,
    new_batch_id: &str,
) -> Result<()> {
    let updated = conn.execute(
        "UPDATE pending_ops SET local_batch_id = ?1 WHERE op_id = ?2",
        params![new_batch_id, op_id],
    )?;
    if updated == 0 {
        return Err(CoreError::Storage(StorageError::Logic(format!(
            "update_pending_op_batch_id: no pending_ops row for op_id={op_id}"
        ))));
    }
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
            // Fixed-width microseconds — see `exec_insert_pending_op` for the
            // rationale. Keeps any push-ordering or TEXT-sort query that
            // touches `field_versions.updated_at` lexically consistent.
            fv.updated_at.to_rfc3339_opts(SecondsFormat::Micros, true),
        ],
    )?;
    Ok(())
}

fn exec_insert_quarantined_op(conn: &Connection, op: &QuarantinedOp) -> Result<()> {
    let op_json = serde_json::to_string(&op.op)
        .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))?;
    conn.execute(
        "INSERT OR REPLACE INTO quarantined_ops \
         (sync_id, op_id, server_seq, entity_table, field_name, reason, op_json, quarantined_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            op.sync_id,
            op.op_id,
            op.server_seq,
            op.op.entity_table,
            op.op.field_name,
            op.reason,
            op_json,
            op.quarantined_at.to_rfc3339(),
        ],
    )?;
    Ok(())
}

fn exec_delete_quarantined_op(conn: &Connection, sync_id: &str, op_id: &str) -> Result<()> {
    conn.execute(
        "DELETE FROM quarantined_ops WHERE sync_id = ?1 AND op_id = ?2",
        params![sync_id, op_id],
    )?;
    Ok(())
}

fn exec_insert_consumer_delivery(conn: &Connection, delivery: &ConsumerDelivery) -> Result<()> {
    // `id` is AUTOINCREMENT — never supplied on insert, so the journal preserves
    // strict append order even across re-applies of the same op.
    conn.execute(
        "INSERT INTO consumer_deliveries \
         (sync_id, entity_table, entity_id, field_name, encoded_value, is_delete, \
          server_seq, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            delivery.sync_id,
            delivery.entity_table,
            delivery.entity_id,
            delivery.field_name,
            delivery.encoded_value,
            delivery.is_delete as i64,
            delivery.server_seq,
            delivery.created_at.to_rfc3339(),
        ],
    )?;
    Ok(())
}

fn exec_delete_consumer_deliveries_up_to(
    conn: &Connection,
    sync_id: &str,
    up_to_id: i64,
) -> Result<()> {
    conn.execute(
        "DELETE FROM consumer_deliveries WHERE sync_id = ?1 AND id <= ?2",
        params![sync_id, up_to_id],
    )?;
    Ok(())
}

fn exec_insert_quarantined_pull_batch(
    conn: &Connection,
    batch: &QuarantinedPullBatch,
) -> Result<()> {
    let envelope_json = serde_json::to_string(&batch.envelope)
        .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))?;
    conn.execute(
        "INSERT OR REPLACE INTO quarantined_pull_batches \
         (sync_id, batch_id, server_seq, epoch, sender_device_id, envelope_json, \
          reason, retry_count, quarantined_at, last_retry_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            batch.sync_id,
            batch.batch_id,
            batch.server_seq,
            batch.epoch,
            batch.sender_device_id,
            envelope_json,
            batch.reason,
            batch.retry_count,
            batch.quarantined_at.to_rfc3339(),
            batch.last_retry_at.map(|d| d.to_rfc3339()),
        ],
    )?;
    Ok(())
}

fn exec_delete_quarantined_pull_batch(
    conn: &Connection,
    sync_id: &str,
    sender_device_id: &str,
    batch_id: &str,
) -> Result<()> {
    conn.execute(
        "DELETE FROM quarantined_pull_batches \
         WHERE sync_id = ?1 AND sender_device_id = ?2 AND batch_id = ?3",
        params![sync_id, sender_device_id, batch_id],
    )?;
    Ok(())
}

fn exec_bump_quarantined_pull_batch_retry(
    conn: &Connection,
    sync_id: &str,
    sender_device_id: &str,
    batch_id: &str,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "UPDATE quarantined_pull_batches \
         SET retry_count = retry_count + 1, last_retry_at = ?4 \
         WHERE sync_id = ?1 AND sender_device_id = ?2 AND batch_id = ?3",
        params![sync_id, sender_device_id, batch_id, now],
    )?;
    Ok(())
}

fn exec_record_pull_stall(
    conn: &Connection,
    sync_id: &str,
    server_seq: i64,
    reason: &str,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO pull_stall \
         (sync_id, server_seq, reason, attempts, first_seen_at, last_seen_at) \
         VALUES (?1, ?2, ?3, 1, ?4, ?4) \
         ON CONFLICT(sync_id, server_seq) DO UPDATE SET \
         attempts = attempts + 1, reason = excluded.reason, last_seen_at = excluded.last_seen_at",
        params![sync_id, server_seq, reason, now],
    )?;
    Ok(())
}

fn exec_clear_pull_stall(conn: &Connection, sync_id: &str, server_seq: i64) -> Result<()> {
    conn.execute(
        "DELETE FROM pull_stall WHERE sync_id = ?1 AND server_seq = ?2",
        params![sync_id, server_seq],
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn exec_quarantine_batch(
    conn: &Connection,
    sync_id: &str,
    batch_id: &str,
    entity_table: &str,
    entity_id: &str,
    body_bytes: i64,
    error_code: &str,
    error_message: &str,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "INSERT OR REPLACE INTO push_quarantine \
         (sync_id, batch_id, entity_table, entity_id, body_bytes, error_code, error_message, quarantined_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![sync_id, batch_id, entity_table, entity_id, body_bytes, error_code, error_message, now],
    )?;
    Ok(())
}

fn exec_unquarantine_batch(conn: &Connection, sync_id: &str, batch_id: &str) -> Result<()> {
    conn.execute(
        "DELETE FROM push_quarantine WHERE sync_id = ?1 AND batch_id = ?2",
        params![sync_id, batch_id],
    )?;
    Ok(())
}

fn query_list_quarantined_batches(
    conn: &Connection,
    sync_id: &str,
) -> Result<Vec<QuarantinedBatchInfo>> {
    let mut stmt = conn.prepare(
        "SELECT batch_id, entity_table, entity_id, body_bytes, error_code, error_message, quarantined_at \
         FROM push_quarantine WHERE sync_id = ?1 \
         ORDER BY quarantined_at ASC, batch_id ASC",
    )?;
    let rows = stmt.query_map(params![sync_id], |row| {
        Ok(QuarantinedBatchInfo {
            batch_id: row.get(0)?,
            entity_table: row.get(1)?,
            entity_id: row.get(2)?,
            body_bytes: row.get(3)?,
            error_code: row.get(4)?,
            error_message: row.get(5)?,
            quarantined_at: row.get(6)?,
        })
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

fn query_quarantined_batch_count(conn: &Connection, sync_id: &str) -> Result<i64> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM push_quarantine WHERE sync_id = ?1",
        params![sync_id],
        |row| row.get(0),
    )?;
    Ok(count)
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

fn query_archived_device_key(
    conn: &Connection,
    sync_id: &str,
    device_id: &str,
    generation: u32,
) -> Result<Option<Vec<u8>>> {
    conn.query_row(
        "SELECT ml_dsa_65_public_key FROM device_key_history \
         WHERE sync_id = ?1 AND device_id = ?2 AND ml_dsa_key_generation = ?3",
        params![sync_id, device_id, generation as i64],
        |row| row.get::<_, Vec<u8>>(0),
    )
    .optional()
    .map_err(CoreError::from)
}

fn exec_archive_device_key(
    conn: &Connection,
    sync_id: &str,
    device_id: &str,
    generation: u32,
    ml_dsa_65_public_key: &[u8],
) -> Result<()> {
    // INSERT OR IGNORE: re-archiving the same (device, generation) keeps the
    // first key seen. A device's key for a given generation is fixed, so a
    // collision is a re-import of the same artifact, not a key change.
    conn.execute(
        "INSERT OR IGNORE INTO device_key_history \
         (sync_id, device_id, ml_dsa_key_generation, ml_dsa_65_public_key, archived_at) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            sync_id,
            device_id,
            generation as i64,
            ml_dsa_65_public_key,
            Utc::now().to_rfc3339(),
        ],
    )?;
    Ok(())
}

fn exec_clear_sync_state(conn: &Connection, sync_id: &str) -> Result<()> {
    conn.execute("DELETE FROM pending_ops WHERE sync_id = ?1", params![sync_id])?;
    conn.execute("DELETE FROM applied_ops WHERE sync_id = ?1", params![sync_id])?;
    conn.execute("DELETE FROM field_versions WHERE sync_id = ?1", params![sync_id])?;
    conn.execute("DELETE FROM quarantined_ops WHERE sync_id = ?1", params![sync_id])?;
    conn.execute("DELETE FROM push_quarantine WHERE sync_id = ?1", params![sync_id])?;
    // Pull-failure discipline tables are server-seq-scoped to the group's log;
    // a reset/re-pair gives the group a fresh seq space, so leftover envelopes
    // and stalls must not survive (they would replay batches from a wiped group).
    conn.execute("DELETE FROM quarantined_pull_batches WHERE sync_id = ?1", params![sync_id])?;
    conn.execute("DELETE FROM pull_stall WHERE sync_id = ?1", params![sync_id])?;
    // The consumer-delivery journal is group-scoped: a reset/re-pair wipes
    // field_versions and gives the group a fresh state, so any undrained rows
    // would replay deletes/edits for entities that no longer exist. Clear them
    // here for the same lineage reason as quarantined_pull_batches above.
    conn.execute("DELETE FROM consumer_deliveries WHERE sync_id = ?1", params![sync_id])?;
    conn.execute("DELETE FROM device_registry WHERE sync_id = ?1", params![sync_id])?;
    // Archived verification keys are scoped to this group's device registry; a
    // reset/re-pair rebuilds the registry, so superseded-key history must go too.
    conn.execute("DELETE FROM device_key_history WHERE sync_id = ?1", params![sync_id])?;
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

fn exec_delete_non_tombstone_field_versions_for_entity(
    conn: &Connection,
    sync_id: &str,
    table: &str,
    entity_id: &str,
) -> Result<usize> {
    let affected = conn.execute(
        "DELETE FROM field_versions \
         WHERE sync_id = ?1 \
           AND entity_table = ?2 \
           AND entity_id = ?3 \
           AND field_name <> 'is_deleted'",
        params![sync_id, table, entity_id],
    )?;
    Ok(affected)
}

fn query_list_all_field_version_hlcs(conn: &Connection, sync_id: &str) -> Result<Vec<String>> {
    let mut stmt = conn.prepare("SELECT winning_hlc FROM field_versions WHERE sync_id = ?1")?;
    let rows = stmt.query_map(params![sync_id], |row| row.get::<_, String>(0))?;
    let mut result = Vec::new();
    for r in rows {
        result.push(r?);
    }
    Ok(result)
}

fn exec_delete_all_pending_ops(conn: &Connection, sync_id: &str) -> Result<usize> {
    let affected = conn.execute("DELETE FROM pending_ops WHERE sync_id = ?1", params![sync_id])?;
    Ok(affected)
}

fn query_has_any_applied_ops(conn: &Connection, sync_id: &str) -> Result<bool> {
    let exists: Option<i32> = conn
        .query_row(
            "SELECT 1 FROM applied_ops WHERE sync_id = ?1 LIMIT 1",
            params![sync_id],
            |row| row.get(0),
        )
        .optional()?;
    Ok(exists.is_some())
}

fn query_count_devices_in_group(conn: &Connection, sync_id: &str) -> Result<usize> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM device_registry WHERE sync_id = ?1",
        params![sync_id],
        |row| row.get(0),
    )?;
    Ok(count as usize)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SnapshotFieldImportDecision {
    InsertOrUpdate,
    KeepExistingEqual,
    SkipStale,
}

fn snapshot_field_import_decision(
    conn: &Connection,
    sync_id: &str,
    fv: &FieldVersionEntry,
    locally_tombstoned: &HashSet<(String, String)>,
) -> Result<SnapshotFieldImportDecision> {
    // Per-ENTITY absorbing rule, mirroring engine::merge: a delete
    // subsumes every other field, so no non-`is_deleted` snapshot field may
    // import into an entity that is locally tombstoned — even at a higher HLC,
    // and even when the entity's other field_versions were already pruned away
    // (the pruner keeps only `is_deleted=true`, so a plain HLC compare would
    // find no existing row and blind-recreate the live field). `is_deleted`
    // itself still flows through the field-level absorbing branch below.
    if fv.field_name != "is_deleted"
        && locally_tombstoned.contains(&(fv.entity_table.clone(), fv.entity_id.clone()))
    {
        return Ok(SnapshotFieldImportDecision::SkipStale);
    }

    let snapshot_hlc = Hlc::from_string(&fv.winning_hlc)?;
    let existing: Option<(String, Option<String>)> = conn
        .query_row(
            "SELECT winning_hlc, winning_encoded_value FROM field_versions \
             WHERE sync_id = ?1 AND entity_table = ?2 AND entity_id = ?3 AND field_name = ?4",
            params![sync_id, fv.entity_table, fv.entity_id, fv.field_name],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;

    let Some((existing_hlc, existing_value)) = existing else {
        return Ok(SnapshotFieldImportDecision::InsertOrUpdate);
    };

    // `is_deleted` is absorbing on the snapshot channel too (mirrors
    // engine::merge): a snapshot's `false` must never replace a local `true` (any
    // HLC), and a `true` always wins over a local `false`, else a stale un-delete
    // could resurrect a tombstone via bootstrap. NULL local value = tombstone.
    if fv.field_name == "is_deleted" {
        let incoming_true = fv.winning_encoded_value.as_deref() == Some("true");
        let existing_true = is_tombstone_value(existing_value.as_deref());
        match (incoming_true, existing_true) {
            (true, false) => return Ok(SnapshotFieldImportDecision::InsertOrUpdate),
            (false, true) => return Ok(SnapshotFieldImportDecision::SkipStale),
            _ => {}
        }
    }

    let existing_hlc = Hlc::from_string(&existing_hlc)?;
    if snapshot_hlc > existing_hlc {
        Ok(SnapshotFieldImportDecision::InsertOrUpdate)
    } else if snapshot_hlc == existing_hlc {
        Ok(SnapshotFieldImportDecision::KeepExistingEqual)
    } else {
        Ok(SnapshotFieldImportDecision::SkipStale)
    }
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
    // Preserve local-only row values across the INSERT OR REPLACE below: the
    // snapshot blob carries no replay-freshness baseline, so a naive REPLACE
    // would NULL `last_imported_registry_version` on every auto-bootstrap and
    // hand a stale-registry replay a fail-open `confirm_self_revocation`.
    let existing_metadata = query_sync_metadata(conn, sync_id)?;
    let existing_local_device_id =
        existing_metadata.as_ref().map(|meta| meta.local_device_id.clone());
    let existing_last_imported_registry_version =
        existing_metadata.as_ref().and_then(|meta| meta.last_imported_registry_version);

    // 3. Insert field_versions only when the snapshot row is newer than the
    //    existing local winner. HLC ordering must stay typed; SQL string
    //    comparisons are wrong for counters such as ":9" vs ":10".
    //
    //    First snapshot the LOCAL tombstone state for every entity the snapshot
    //    touches (single query over `is_deleted` field_versions), so the
    //    per-field decision can enforce the same per-ENTITY absorbing rule as
    //    engine::merge before any field write. Uses the shared
    //    `is_tombstone_value` rule (NULL/absent → tombstoned).
    //
    //    This set is captured ONCE, before the loop, and is deliberately NOT
    //    updated when a snapshot's own `is_deleted = true` imports mid-loop: a
    //    new tombstone arriving in the snapshot may legitimately import alongside
    //    that same entity's residual live fields (they match the uploader's
    //    pre-delete state), and the field-level `is_deleted` absorbing branch
    //    already converges them. The downstream journal/EntityChange derivation
    //    (engine::mod) absorbs those residual fields via its own
    //    accepted-`is_deleted` set, so they are never delivered live. Folding
    //    mid-loop tombstones in here would be a behavior change, not a fix.
    let snapshot_entities: HashSet<(String, String)> = snapshot
        .field_versions
        .iter()
        .map(|fv| (fv.entity_table.clone(), fv.entity_id.clone()))
        .collect();
    let mut locally_tombstoned: HashSet<(String, String)> = HashSet::new();
    {
        let mut stmt = conn.prepare(
            "SELECT entity_table, entity_id, winning_encoded_value FROM field_versions \
             WHERE sync_id = ?1 AND field_name = 'is_deleted'",
        )?;
        let rows = stmt.query_map(params![sync_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        })?;
        for row in rows {
            let (entity_table, entity_id, value) = row?;
            let key = (entity_table, entity_id);
            if snapshot_entities.contains(&key) && is_tombstone_value(value.as_deref()) {
                locally_tombstoned.insert(key);
            }
        }
    }

    for fv in &snapshot.field_versions {
        match snapshot_field_import_decision(conn, sync_id, fv, &locally_tombstoned)? {
            SnapshotFieldImportDecision::InsertOrUpdate => {
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
            SnapshotFieldImportDecision::KeepExistingEqual => {
                entities.insert((fv.entity_table.clone(), fv.entity_id.clone()));
            }
            SnapshotFieldImportDecision::SkipStale => {}
        }
    }

    // 4. Insert device_registry through the same fail-closed reconciliation as
    //    every other registry write (`registry_import_action`). A snapshot's
    //    entries are attacker-influenced and can name any device id, so a raw
    //    INSERT OR REPLACE would let one rebind another device's pinned keys or
    //    un-revoke a local tombstone.
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

        let existing = query_device_record(conn, sync_id, &dr.device_id)?;
        // Timestamps don't affect the decision, so dummy values are fine here.
        let candidate = DeviceRecord {
            sync_id: sync_id.to_string(),
            device_id: dr.device_id.clone(),
            ed25519_public_key: ed25519.clone(),
            x25519_public_key: x25519.clone(),
            ml_dsa_65_public_key: ml_dsa.clone(),
            ml_kem_768_public_key: ml_kem.clone(),
            x_wing_public_key: x_wing.clone(),
            status: dr.status.clone(),
            registered_at: Utc::now(),
            revoked_at: None,
            ml_dsa_key_generation: dr.ml_dsa_key_generation,
        };

        match registry_import_action(existing.as_ref(), &candidate, RegistryImportSource::Snapshot)
        {
            RegistryImportAction::RejectKeyChange => {
                // Err rolls back the whole import transaction, so a poisoned
                // snapshot cannot partially apply.
                return Err(CoreError::DeviceKeyChanged { device_id: dr.device_id.clone() });
            }
            RegistryImportAction::KeepExisting => {
                tracing::warn!(
                    device_id = %dr.device_id,
                    "snapshot import: keeping pinned device record over unauthenticated change"
                );
                continue;
            }
            RegistryImportAction::Write => {}
        }

        // Keep the local generation for an already-pinned device: a snapshot
        // can't carry an authenticated rotation, so letting it bump the
        // generation (with unchanged key bytes) would only block a later
        // legitimate signed gen+1 rotation.
        let ml_dsa_generation_to_persist =
            existing.as_ref().map(|e| e.ml_dsa_key_generation).unwrap_or(dr.ml_dsa_key_generation);

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
                ml_dsa_generation_to_persist as i32,
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

    // 6. Update sync_metadata (last_pulled_server_seq, current_epoch).
    //    Preserve `last_imported_registry_version` across the REPLACE (NULL only
    //    if it was already NULL) — same pattern as `local_device_id` above. The
    //    snapshot blob never carries this baseline, so dropping it would re-arm
    //    the stale-registry false-wipe on exactly the devices that just
    //    auto-bootstrapped.
    let sm = &snapshot.sync_metadata;
    let local_device_id = existing_local_device_id.unwrap_or_else(|| sm.local_device_id.clone());
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "INSERT OR REPLACE INTO sync_metadata \
         (sync_id, local_device_id, current_epoch, last_pulled_server_seq, \
          last_imported_registry_version, needs_rekey, created_at, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, ?6)",
        params![
            sync_id,
            local_device_id,
            sm.current_epoch,
            sm.last_pulled_server_seq,
            existing_last_imported_registry_version,
            now,
        ],
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
    rekey_mode: RekeyMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RekeyMode {
    Noop,
    SqlCipher,
}

impl RusqliteSyncStorage {
    pub fn new(conn: Connection) -> Result<Self> {
        Self::new_with_rekey_mode(conn, RekeyMode::SqlCipher)
    }

    fn new_with_rekey_mode(mut conn: Connection, rekey_mode: RekeyMode) -> Result<Self> {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA busy_timeout = 5000;
             PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;",
        )?;

        migrations::apply(&mut conn).map_err(|e| {
            CoreError::Storage(StorageError::Logic(format!("Migration failed: {e}")))
        })?;

        Ok(Self { conn: Mutex::new(conn), rekey_mode })
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
        Self::new_with_rekey_mode(conn, RekeyMode::SqlCipher)
    }

    /// Create an in-memory storage instance for testing.
    pub fn in_memory() -> Result<Self> {
        Self::new_with_rekey_mode(Connection::open_in_memory()?, RekeyMode::Noop)
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

    fn list_quarantined_ops(&self, sync_id: &str) -> Result<Vec<QuarantinedOp>> {
        let conn = self.conn.lock().expect("mutex poisoned");
        query_quarantined_ops(&conn, sync_id)
    }

    fn list_quarantined_pull_batches(
        &self,
        sync_id: &str,
    ) -> Result<Vec<QuarantinedPullBatch>> {
        let conn = self.conn.lock().expect("mutex poisoned");
        query_quarantined_pull_batches(&conn, sync_id)
    }

    fn list_pull_stalls(&self, sync_id: &str) -> Result<Vec<PullStall>> {
        let conn = self.conn.lock().expect("mutex poisoned");
        query_pull_stalls(&conn, sync_id)
    }

    fn list_consumer_deliveries(
        &self,
        sync_id: &str,
        after_id: i64,
        limit: i64,
    ) -> Result<Vec<ConsumerDelivery>> {
        let conn = self.conn.lock().expect("mutex poisoned");
        query_list_consumer_deliveries(&conn, sync_id, after_id, limit)
    }

    fn count_consumer_deliveries(&self, sync_id: &str) -> Result<i64> {
        let conn = self.conn.lock().expect("mutex poisoned");
        query_count_consumer_deliveries(&conn, sync_id)
    }

    fn list_quarantined_batches(&self, sync_id: &str) -> Result<Vec<QuarantinedBatchInfo>> {
        let conn = self.conn.lock().expect("mutex poisoned");
        query_list_quarantined_batches(&conn, sync_id)
    }

    fn quarantined_batch_count(&self, sync_id: &str) -> Result<i64> {
        let conn = self.conn.lock().expect("mutex poisoned");
        query_quarantined_batch_count(&conn, sync_id)
    }

    fn get_device_record(&self, sync_id: &str, device_id: &str) -> Result<Option<DeviceRecord>> {
        let conn = self.conn.lock().expect("mutex poisoned");
        query_device_record(&conn, sync_id, device_id)
    }

    fn list_device_records(&self, sync_id: &str) -> Result<Vec<DeviceRecord>> {
        let conn = self.conn.lock().expect("mutex poisoned");
        query_list_device_records(&conn, sync_id)
    }

    fn get_archived_device_key(
        &self,
        sync_id: &str,
        device_id: &str,
        ml_dsa_key_generation: u32,
    ) -> Result<Option<Vec<u8>>> {
        let conn = self.conn.lock().expect("mutex poisoned");
        query_archived_device_key(&conn, sync_id, device_id, ml_dsa_key_generation)
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
        if self.rekey_mode == RekeyMode::Noop {
            return Ok(());
        }

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

    fn list_all_field_version_hlcs(&self, sync_id: &str) -> Result<Vec<String>> {
        let conn = self.conn.lock().expect("mutex poisoned");
        query_list_all_field_version_hlcs(&conn, sync_id)
    }

    fn delete_all_pending_ops(&self, sync_id: &str) -> Result<usize> {
        let conn = self.conn.lock().expect("mutex poisoned");
        conn.execute_batch("BEGIN IMMEDIATE")?;
        match exec_delete_all_pending_ops(&conn, sync_id) {
            Ok(n) => {
                conn.execute_batch("COMMIT")?;
                Ok(n)
            }
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }

    fn has_any_applied_ops(&self, sync_id: &str) -> Result<bool> {
        let conn = self.conn.lock().expect("mutex poisoned");
        query_has_any_applied_ops(&conn, sync_id)
    }

    fn count_devices_in_group(&self, sync_id: &str) -> Result<usize> {
        let conn = self.conn.lock().expect("mutex poisoned");
        query_count_devices_in_group(&conn, sync_id)
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

    fn reset_last_pulled_seq(&mut self, sync_id: &str, seq: i64) -> Result<()> {
        exec_reset_last_pulled_seq(&self.conn, sync_id, seq)
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

    fn delete_pushed_ops(&mut self, sync_id: &str, batch_id: &str) -> Result<()> {
        exec_delete_pushed_ops(&self.conn, sync_id, batch_id)
    }

    fn load_batch_ops(&self, batch_id: &str) -> Result<Vec<PendingOp>> {
        query_batch_ops(&self.conn, batch_id)
    }

    fn update_pending_op_batch_id(&mut self, op_id: &str, new_batch_id: &str) -> Result<()> {
        exec_update_pending_op_batch_id(&self.conn, op_id, new_batch_id)
    }

    fn delete_pending_op(&mut self, op_id: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM pending_ops WHERE op_id = ?1", params![op_id])?;
        Ok(())
    }

    // ── Applied ops ──

    fn insert_applied_op(&mut self, op: &AppliedOp) -> Result<()> {
        exec_insert_applied_op(&self.conn, op)
    }

    // ── Field versions ──

    fn upsert_field_version(&mut self, fv: &FieldVersion) -> Result<()> {
        exec_upsert_field_version(&self.conn, fv)
    }

    // ── Quarantined remote ops ──

    fn insert_quarantined_op(&mut self, op: &QuarantinedOp) -> Result<()> {
        exec_insert_quarantined_op(&self.conn, op)
    }

    fn delete_quarantined_op(&mut self, sync_id: &str, op_id: &str) -> Result<()> {
        exec_delete_quarantined_op(&self.conn, sync_id, op_id)
    }

    // ── Consumer delivery journal ──

    fn insert_consumer_delivery(&mut self, delivery: &ConsumerDelivery) -> Result<()> {
        exec_insert_consumer_delivery(&self.conn, delivery)
    }

    fn delete_consumer_deliveries_up_to(&mut self, sync_id: &str, up_to_id: i64) -> Result<()> {
        exec_delete_consumer_deliveries_up_to(&self.conn, sync_id, up_to_id)
    }

    // ── Quarantined remote pull batches (replayable) ──

    fn insert_quarantined_pull_batch(&mut self, batch: &QuarantinedPullBatch) -> Result<()> {
        exec_insert_quarantined_pull_batch(&self.conn, batch)
    }

    fn delete_quarantined_pull_batch(
        &mut self,
        sync_id: &str,
        sender_device_id: &str,
        batch_id: &str,
    ) -> Result<()> {
        exec_delete_quarantined_pull_batch(&self.conn, sync_id, sender_device_id, batch_id)
    }

    fn bump_quarantined_pull_batch_retry(
        &mut self,
        sync_id: &str,
        sender_device_id: &str,
        batch_id: &str,
    ) -> Result<()> {
        exec_bump_quarantined_pull_batch_retry(&self.conn, sync_id, sender_device_id, batch_id)
    }

    // ── Pull stall budget ──

    fn record_pull_stall(&mut self, sync_id: &str, server_seq: i64, reason: &str) -> Result<()> {
        exec_record_pull_stall(&self.conn, sync_id, server_seq, reason)
    }

    fn clear_pull_stall(&mut self, sync_id: &str, server_seq: i64) -> Result<()> {
        exec_clear_pull_stall(&self.conn, sync_id, server_seq)
    }

    // ── Quarantined local push batches ──

    fn quarantine_batch(
        &mut self,
        sync_id: &str,
        batch_id: &str,
        entity_table: &str,
        entity_id: &str,
        body_bytes: i64,
        error_code: &str,
        error_message: &str,
    ) -> Result<()> {
        exec_quarantine_batch(
            &self.conn,
            sync_id,
            batch_id,
            entity_table,
            entity_id,
            body_bytes,
            error_code,
            error_message,
        )
    }

    fn unquarantine_batch(&mut self, sync_id: &str, batch_id: &str) -> Result<()> {
        exec_unquarantine_batch(&self.conn, sync_id, batch_id)
    }

    // ── Device registry ──

    fn upsert_device_record(&mut self, device: &DeviceRecord) -> Result<()> {
        exec_upsert_device_record(&self.conn, device)
    }

    fn remove_device_record(&mut self, sync_id: &str, device_id: &str) -> Result<()> {
        exec_remove_device_record(&self.conn, sync_id, device_id)
    }

    fn archive_device_key(
        &mut self,
        sync_id: &str,
        device_id: &str,
        ml_dsa_key_generation: u32,
        ml_dsa_65_public_key: &[u8],
    ) -> Result<()> {
        exec_archive_device_key(
            &self.conn,
            sync_id,
            device_id,
            ml_dsa_key_generation,
            ml_dsa_65_public_key,
        )
    }

    fn get_archived_device_key(
        &self,
        sync_id: &str,
        device_id: &str,
        ml_dsa_key_generation: u32,
    ) -> Result<Option<Vec<u8>>> {
        query_archived_device_key(&self.conn, sync_id, device_id, ml_dsa_key_generation)
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

    fn delete_non_tombstone_field_versions_for_entity(
        &mut self,
        sync_id: &str,
        table: &str,
        entity_id: &str,
    ) -> Result<usize> {
        exec_delete_non_tombstone_field_versions_for_entity(&self.conn, sync_id, table, entity_id)
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
    use crate::relay::traits::SignedBatchEnvelope;

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
            client_hlc: "1767225600000:0:dev1".to_string(),
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
            client_hlc: "1767225600000:0:dev1".to_string(),
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
            winning_hlc: "1767225600000:0:dev1".to_string(),
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
    fn delete_pushed_ops_removes_only_target_pushed_batch() {
        let storage = make_storage();

        // Insert two ops in different batches
        let mut tx = storage.begin_tx().unwrap();
        tx.insert_pending_op(&sample_pending_op("op-1", "sync-1", "batch-1")).unwrap();
        tx.insert_pending_op(&sample_pending_op("op-2", "sync-1", "batch-2")).unwrap();
        tx.mark_batch_pushed("batch-1").unwrap();
        tx.mark_batch_pushed("batch-2").unwrap();
        tx.commit().unwrap();

        // Delete only the just-pushed batch.
        let mut tx = storage.begin_tx().unwrap();
        tx.delete_pushed_ops("sync-1", "batch-1").unwrap();
        tx.commit().unwrap();

        // batch-1 op should be gone, batch-2 op should remain even though it is also pushed.
        let ops1 = storage.load_batch_ops("batch-1").unwrap();
        assert!(ops1.is_empty());

        let ops2 = storage.load_batch_ops("batch-2").unwrap();
        assert_eq!(ops2.len(), 1);
        assert!(ops2[0].pushed_at.is_some());
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
    fn update_last_imported_registry_version_is_max_monotonic_in_sql() {
        // Exercises the storage primitive directly (not the ratchet helper's
        // read-side early-out) so the SQL-level MAX clamp is what's under test:
        // an interleaved lower-version write must never rewind a higher stored
        // baseline. This is the atomic guarantee the false-wipe gate relies on
        // when two ratchets race outside the engine Mutex.
        let storage = make_storage();
        let mut meta = sample_metadata("sync-1");
        meta.last_imported_registry_version = None;
        let mut tx = storage.begin_tx().unwrap();
        tx.upsert_sync_metadata(&meta).unwrap();
        tx.commit().unwrap();

        // First write from NULL baseline lands (COALESCE treats NULL as below).
        let mut tx = storage.begin_tx().unwrap();
        tx.update_last_imported_registry_version("sync-1", 5).unwrap();
        tx.commit().unwrap();
        assert_eq!(
            storage.get_sync_metadata("sync-1").unwrap().unwrap().last_imported_registry_version,
            Some(5)
        );

        // A lower-version write (e.g. a slower racing ratchet for an older
        // registry) must be clamped to the existing higher baseline.
        let mut tx = storage.begin_tx().unwrap();
        tx.update_last_imported_registry_version("sync-1", 3).unwrap();
        tx.commit().unwrap();
        assert_eq!(
            storage.get_sync_metadata("sync-1").unwrap().unwrap().last_imported_registry_version,
            Some(5),
            "lower-version write must not rewind the baseline"
        );

        // Equal writes are no-ops; strictly-greater writes advance.
        let mut tx = storage.begin_tx().unwrap();
        tx.update_last_imported_registry_version("sync-1", 5).unwrap();
        tx.update_last_imported_registry_version("sync-1", 9).unwrap();
        tx.commit().unwrap();
        assert_eq!(
            storage.get_sync_metadata("sync-1").unwrap().unwrap().last_imported_registry_version,
            Some(9)
        );
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
                client_hlc: format!("1767225600000:{i}:dev1"),
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
                client_hlc: format!("1767225600000:{i}:dev1"),
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
            winning_hlc: "1767225600000:1:dev1".to_string(),
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
            winning_hlc: "1767225600000:2:dev1".to_string(),
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
            winning_hlc: "1767225600000:3:dev1".to_string(),
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
    fn pruning_delete_non_tombstone_field_versions_preserves_is_deleted() {
        let storage = make_storage();

        let mut tx = storage.begin_tx().unwrap();
        tx.upsert_field_version(&FieldVersion {
            sync_id: "sync-1".to_string(),
            entity_table: "members".to_string(),
            entity_id: "ent-1".to_string(),
            field_name: "name".to_string(),
            winning_op_id: "op-1".to_string(),
            winning_device_id: "dev1".to_string(),
            winning_hlc: "1767225600000:1:dev1".to_string(),
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
            winning_hlc: "1767225600000:2:dev1".to_string(),
            winning_encoded_value: Some("true".to_string()),
            updated_at: Utc::now(),
        })
        .unwrap();
        tx.upsert_field_version(&FieldVersion {
            sync_id: "sync-1".to_string(),
            entity_table: "members".to_string(),
            entity_id: "ent-2".to_string(),
            field_name: "name".to_string(),
            winning_op_id: "op-3".to_string(),
            winning_device_id: "dev1".to_string(),
            winning_hlc: "1767225600000:3:dev1".to_string(),
            winning_encoded_value: Some("\"Bob\"".to_string()),
            updated_at: Utc::now(),
        })
        .unwrap();
        tx.commit().unwrap();

        let mut tx = storage.begin_tx().unwrap();
        let deleted = tx
            .delete_non_tombstone_field_versions_for_entity("sync-1", "members", "ent-1")
            .unwrap();
        tx.commit().unwrap();

        assert_eq!(deleted, 1);
        assert!(storage.get_field_version("sync-1", "members", "ent-1", "name").unwrap().is_none());
        assert!(storage
            .get_field_version("sync-1", "members", "ent-1", "is_deleted")
            .unwrap()
            .is_some());
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
            client_hlc: "1767225600000:1:dev1".to_string(),
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
            winning_hlc: "1767225600000:1:dev1".to_string(),
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
            winning_hlc: "1767225600000:1:dev1".to_string(),
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
            winning_hlc: "1767225600000:2:dev1".to_string(),
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
            winning_hlc: "1767225600000:3:dev1".to_string(),
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
            client_hlc: "1767225600000:1:dev1".to_string(),
            server_seq: 10,
            applied_at: Utc::now(),
        })
        .unwrap();
        tx.insert_applied_op(&AppliedOp {
            op_id: "applied-2".to_string(),
            sync_id: "sync-1".to_string(),
            epoch: 1,
            device_id: "dev1".to_string(),
            client_hlc: "1767225600000:2:dev1".to_string(),
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
    fn import_snapshot_preserves_last_imported_registry_version() {
        // The snapshot blob carries no replay-freshness baseline, so the
        // importer's INSERT OR REPLACE must preserve the destination's existing
        // `last_imported_registry_version` (and `local_device_id`) rather than
        // NULL it. A NULLed baseline would hand a stale-registry replay a
        // fail-open `confirm_self_revocation` on every auto-bootstrap.
        let src = make_storage();
        populate_for_snapshot(&src);
        let blob = src.export_snapshot("sync-1").unwrap();

        // Destination already has a baseline and its own local_device_id.
        let dst = make_storage();
        {
            let mut tx = dst.begin_tx().unwrap();
            let mut meta = sample_metadata("sync-1");
            meta.local_device_id = "local-device-xyz".to_string();
            tx.upsert_sync_metadata(&meta).unwrap();
            tx.update_last_imported_registry_version("sync-1", 10).unwrap();
            tx.commit().unwrap();
        }

        let mut tx = dst.begin_tx().unwrap();
        tx.import_snapshot("sync-1", &blob).unwrap();
        tx.commit().unwrap();

        let meta = dst.get_sync_metadata("sync-1").unwrap().unwrap();
        assert_eq!(
            meta.last_imported_registry_version,
            Some(10),
            "baseline must survive snapshot import unchanged"
        );
        assert_eq!(
            meta.local_device_id, "local-device-xyz",
            "local_device_id must survive snapshot import (importer must not adopt the snapshot's)"
        );
        // The snapshot's transport fields still land.
        assert_eq!(meta.current_epoch, 1);
        assert_eq!(meta.last_pulled_server_seq, 42);
    }

    #[test]
    fn import_snapshot_leaves_null_baseline_null_when_destination_has_none() {
        // The complement of the preservation test: a fresh auto-bootstrap with
        // no prior baseline stays NULL (the fail-safe state) rather than picking
        // up some value from the snapshot, which carries none.
        let src = make_storage();
        populate_for_snapshot(&src);
        let blob = src.export_snapshot("sync-1").unwrap();

        let dst = make_storage();
        let mut tx = dst.begin_tx().unwrap();
        tx.import_snapshot("sync-1", &blob).unwrap();
        tx.commit().unwrap();

        let meta = dst.get_sync_metadata("sync-1").unwrap().unwrap();
        assert_eq!(meta.last_imported_registry_version, None);
    }

    #[test]
    fn import_snapshot_is_deleted_is_absorbing() {
        // The snapshot channel must honor the same absorbing tombstone rule as
        // engine::merge: a snapshot's is_deleted=false must NOT overwrite a local
        // tombstone (any HLC), and a snapshot's is_deleted=true must win over a
        // local live value even at a lower HLC. Guards the snapshot-resurrection
        // vector found in review.
        let is_deleted_fv = |entity_id: &str, value: &str, hlc: &str, dev: &str| FieldVersion {
            sync_id: "sync-1".to_string(),
            entity_table: "members".to_string(),
            entity_id: entity_id.to_string(),
            field_name: "is_deleted".to_string(),
            winning_op_id: format!("op-{value}-{hlc}"),
            winning_device_id: dev.to_string(),
            winning_hlc: hlc.to_string(),
            winning_encoded_value: Some(value.to_string()),
            updated_at: Utc::now(),
        };

        // Case 1: snapshot false@high must NOT beat a local tombstone true@low.
        let src = make_storage();
        {
            let mut tx = src.begin_tx().unwrap();
            tx.upsert_sync_metadata(&sample_metadata("sync-1")).unwrap();
            tx.upsert_field_version(&is_deleted_fv("e1", "false", "9000:0:src", "src")).unwrap();
            tx.commit().unwrap();
        }
        let blob = src.export_snapshot("sync-1").unwrap();

        let dst = make_storage();
        {
            let mut tx = dst.begin_tx().unwrap();
            tx.upsert_sync_metadata(&sample_metadata("sync-1")).unwrap();
            tx.upsert_field_version(&is_deleted_fv("e1", "true", "1000:0:dst", "dst")).unwrap();
            tx.commit().unwrap();
        }
        {
            let mut tx = dst.begin_tx().unwrap();
            tx.import_snapshot("sync-1", &blob).unwrap();
            tx.commit().unwrap();
        }
        let fv = dst.get_field_version("sync-1", "members", "e1", "is_deleted").unwrap().unwrap();
        assert_eq!(
            fv.winning_encoded_value,
            Some("true".to_string()),
            "tombstone must survive a snapshot's higher-HLC is_deleted=false"
        );

        // Case 2: snapshot true@low must beat a local live is_deleted=false@high.
        let src2 = make_storage();
        {
            let mut tx = src2.begin_tx().unwrap();
            tx.upsert_sync_metadata(&sample_metadata("sync-1")).unwrap();
            tx.upsert_field_version(&is_deleted_fv("e2", "true", "1000:0:src", "src")).unwrap();
            tx.commit().unwrap();
        }
        let blob2 = src2.export_snapshot("sync-1").unwrap();

        let dst2 = make_storage();
        {
            let mut tx = dst2.begin_tx().unwrap();
            tx.upsert_sync_metadata(&sample_metadata("sync-1")).unwrap();
            tx.upsert_field_version(&is_deleted_fv("e2", "false", "9000:0:dst", "dst")).unwrap();
            tx.commit().unwrap();
        }
        {
            let mut tx = dst2.begin_tx().unwrap();
            tx.import_snapshot("sync-1", &blob2).unwrap();
            tx.commit().unwrap();
        }
        let fv2 = dst2.get_field_version("sync-1", "members", "e2", "is_deleted").unwrap().unwrap();
        assert_eq!(
            fv2.winning_encoded_value,
            Some("true".to_string()),
            "a snapshot tombstone must win over a local higher-HLC is_deleted=false"
        );
    }

    #[test]
    fn import_snapshot_skips_live_field_on_pruned_local_tombstone() {
        // After the TombstonePruner removed an entity's non-tombstone
        // field_versions (keeping only is_deleted=true), a snapshot carrying a
        // live field for that entity must NOT recreate it. Mirrors the
        // per-ENTITY absorbing rule engine::merge applies on the live channel.
        let live_name_fv = |entity_id: &str| FieldVersion {
            sync_id: "sync-1".to_string(),
            entity_table: "members".to_string(),
            entity_id: entity_id.to_string(),
            field_name: "name".to_string(),
            winning_op_id: format!("op-name-{entity_id}"),
            winning_device_id: "src".to_string(),
            winning_hlc: "5000:0:src".to_string(),
            winning_encoded_value: Some("\"Alice\"".to_string()),
            updated_at: Utc::now(),
        };

        // Source snapshot: a live name field for e1 (no is_deleted row — the
        // uploader never deleted it).
        let src = make_storage();
        {
            let mut tx = src.begin_tx().unwrap();
            tx.upsert_sync_metadata(&sample_metadata("sync-1")).unwrap();
            tx.upsert_field_version(&live_name_fv("e1")).unwrap();
            tx.commit().unwrap();
        }
        let blob = src.export_snapshot("sync-1").unwrap();

        // Destination: a PRUNED tombstone — only is_deleted='true' survives.
        let dst = make_storage();
        {
            let mut tx = dst.begin_tx().unwrap();
            tx.upsert_sync_metadata(&sample_metadata("sync-1")).unwrap();
            tx.upsert_field_version(&FieldVersion {
                sync_id: "sync-1".to_string(),
                entity_table: "members".to_string(),
                entity_id: "e1".to_string(),
                field_name: "is_deleted".to_string(),
                winning_op_id: "del-op".to_string(),
                winning_device_id: "dst".to_string(),
                winning_hlc: "1000:0:dst".to_string(),
                winning_encoded_value: Some("true".to_string()),
                updated_at: Utc::now(),
            })
            .unwrap();
            tx.commit().unwrap();
        }

        let count = {
            let mut tx = dst.begin_tx().unwrap();
            let count = tx.import_snapshot("sync-1", &blob).unwrap();
            tx.commit().unwrap();
            count
        };

        // The live name field must not have been recreated under the tombstone.
        assert!(
            dst.get_field_version("sync-1", "members", "e1", "name").unwrap().is_none(),
            "a live snapshot field must not import into a locally-tombstoned entity"
        );
        // ...and the tombstone is untouched.
        let tomb = dst.get_field_version("sync-1", "members", "e1", "is_deleted").unwrap().unwrap();
        assert_eq!(tomb.winning_encoded_value, Some("true".to_string()));
        // The entity contributed nothing to the import count.
        assert_eq!(count, 0, "a fully-skipped tombstoned entity is not counted");
    }

    #[test]
    fn import_snapshot_newer_hlc_snapshot_field_loses_to_tombstone() {
        // Second-order tombstone hole: a NON-pruned tombstoned entity (still holding an
        // older local `name` fv) must reject a newer-HLC snapshot `name` field.
        // The per-ENTITY rule beats the plain HLC compare that would otherwise
        // let the newer snapshot field win.
        let src = make_storage();
        {
            let mut tx = src.begin_tx().unwrap();
            tx.upsert_sync_metadata(&sample_metadata("sync-1")).unwrap();
            tx.upsert_field_version(&FieldVersion {
                sync_id: "sync-1".to_string(),
                entity_table: "members".to_string(),
                entity_id: "e1".to_string(),
                field_name: "name".to_string(),
                winning_op_id: "op-name-new".to_string(),
                winning_device_id: "src".to_string(),
                winning_hlc: "9000:0:src".to_string(), // newer than dst's
                winning_encoded_value: Some("\"NewName\"".to_string()),
                updated_at: Utc::now(),
            })
            .unwrap();
            tx.commit().unwrap();
        }
        let blob = src.export_snapshot("sync-1").unwrap();

        let dst = make_storage();
        {
            let mut tx = dst.begin_tx().unwrap();
            tx.upsert_sync_metadata(&sample_metadata("sync-1")).unwrap();
            // Tombstone + an older local name fv (NOT pruned).
            tx.upsert_field_version(&FieldVersion {
                sync_id: "sync-1".to_string(),
                entity_table: "members".to_string(),
                entity_id: "e1".to_string(),
                field_name: "is_deleted".to_string(),
                winning_op_id: "del-op".to_string(),
                winning_device_id: "dst".to_string(),
                winning_hlc: "1000:0:dst".to_string(),
                winning_encoded_value: Some("true".to_string()),
                updated_at: Utc::now(),
            })
            .unwrap();
            tx.upsert_field_version(&FieldVersion {
                sync_id: "sync-1".to_string(),
                entity_table: "members".to_string(),
                entity_id: "e1".to_string(),
                field_name: "name".to_string(),
                winning_op_id: "op-name-old".to_string(),
                winning_device_id: "dst".to_string(),
                winning_hlc: "2000:0:dst".to_string(), // older than the snapshot's
                winning_encoded_value: Some("\"OldName\"".to_string()),
                updated_at: Utc::now(),
            })
            .unwrap();
            tx.commit().unwrap();
        }

        {
            let mut tx = dst.begin_tx().unwrap();
            tx.import_snapshot("sync-1", &blob).unwrap();
            tx.commit().unwrap();
        }

        let name = dst.get_field_version("sync-1", "members", "e1", "name").unwrap().unwrap();
        assert_eq!(
            name.winning_encoded_value,
            Some("\"OldName\"".to_string()),
            "the entity tombstone must beat a newer-HLC snapshot field (not plain HLC LWW)"
        );
    }

    #[test]
    fn import_snapshot_tombstone_for_live_local_entity_still_absorbs() {
        // Regression on the existing is_deleted absorbing branch: a snapshot
        // is_deleted=true for a LOCALLY-LIVE entity must still import (the
        // per-entity gate keys off LOCAL tombstone state, so a live local entity
        // is not skipped — the delete flows through and tombstones it).
        let src = make_storage();
        {
            let mut tx = src.begin_tx().unwrap();
            tx.upsert_sync_metadata(&sample_metadata("sync-1")).unwrap();
            tx.upsert_field_version(&FieldVersion {
                sync_id: "sync-1".to_string(),
                entity_table: "members".to_string(),
                entity_id: "e1".to_string(),
                field_name: "is_deleted".to_string(),
                winning_op_id: "del-op".to_string(),
                winning_device_id: "src".to_string(),
                winning_hlc: "9000:0:src".to_string(),
                winning_encoded_value: Some("true".to_string()),
                updated_at: Utc::now(),
            })
            .unwrap();
            tx.commit().unwrap();
        }
        let blob = src.export_snapshot("sync-1").unwrap();

        let dst = make_storage();
        {
            let mut tx = dst.begin_tx().unwrap();
            tx.upsert_sync_metadata(&sample_metadata("sync-1")).unwrap();
            tx.upsert_field_version(&FieldVersion {
                sync_id: "sync-1".to_string(),
                entity_table: "members".to_string(),
                entity_id: "e1".to_string(),
                field_name: "is_deleted".to_string(),
                winning_op_id: "live-op".to_string(),
                winning_device_id: "dst".to_string(),
                winning_hlc: "1000:0:dst".to_string(),
                winning_encoded_value: Some("false".to_string()),
                updated_at: Utc::now(),
            })
            .unwrap();
            tx.commit().unwrap();
        }

        let count = {
            let mut tx = dst.begin_tx().unwrap();
            let count = tx.import_snapshot("sync-1", &blob).unwrap();
            tx.commit().unwrap();
            count
        };

        let tomb = dst.get_field_version("sync-1", "members", "e1", "is_deleted").unwrap().unwrap();
        assert_eq!(
            tomb.winning_encoded_value,
            Some("true".to_string()),
            "a snapshot tombstone for a locally-live entity must still import"
        );
        assert_eq!(count, 1, "the absorbing delete still counts the entity");
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
    fn import_snapshot_rejects_device_key_rebind() {
        // A snapshot must never rebind an already-pinned device's permanent keys.
        let src = make_storage();
        populate_for_snapshot(&src);
        let blob = src.export_snapshot("sync-1").unwrap();

        // Destination already has dev-1 pinned with a DIFFERENT ed25519 key.
        let dst = make_storage();
        let mut pinned = sample_device_record("sync-1", "dev-1");
        pinned.ed25519_public_key = vec![42, 42, 42, 42];
        let mut tx = dst.begin_tx().unwrap();
        tx.upsert_device_record(&pinned).unwrap();
        tx.commit().unwrap();

        // Import fails closed, and (because it errors mid-transaction) nothing
        // partially applies.
        let mut tx = dst.begin_tx().unwrap();
        let result = tx.import_snapshot("sync-1", &blob);
        assert!(
            matches!(result, Err(CoreError::DeviceKeyChanged { ref device_id }) if device_id == "dev-1"),
            "expected DeviceKeyChanged, got: {result:?}"
        );
        drop(tx); // rollback

        let d1 = dst.get_device_record("sync-1", "dev-1").unwrap().unwrap();
        assert_eq!(d1.ed25519_public_key, vec![42, 42, 42, 42], "pinned key must be unchanged");
        assert!(
            dst.get_device_record("sync-1", "dev-2").unwrap().is_none(),
            "snapshot must not partially apply when it fails closed"
        );
    }

    #[test]
    fn import_snapshot_does_not_unrevoke_pinned_device() {
        // A snapshot listing a locally revoked device as active must not un-revoke it.
        let src = make_storage();
        populate_for_snapshot(&src); // lists dev-1 as active
        let blob = src.export_snapshot("sync-1").unwrap();

        let dst = make_storage();
        let mut tx = dst.begin_tx().unwrap();
        tx.upsert_device_record(&sample_device_record("sync-1", "dev-1")).unwrap();
        tx.commit().unwrap();
        crate::device_registry::DeviceRegistryManager::revoke_device(&dst, "sync-1", "dev-1")
            .unwrap();

        let mut tx = dst.begin_tx().unwrap();
        tx.import_snapshot("sync-1", &blob).unwrap();
        tx.commit().unwrap();

        let d1 = dst.get_device_record("sync-1", "dev-1").unwrap().unwrap();
        assert_eq!(d1.status, "revoked", "import must not un-revoke a local tombstone");
        // The new device from the snapshot is still imported normally.
        assert!(dst.get_device_record("sync-1", "dev-2").unwrap().is_some());
    }

    #[test]
    fn import_snapshot_does_not_apply_ml_dsa_rotation() {
        // A snapshot must not rebind an existing device's ML-DSA signing key,
        // even with a higher generation — rotations are trusted only from a
        // signed registry artifact, never from unauthenticated snapshot data.
        let src = make_storage();
        let mut tx = src.begin_tx().unwrap();
        tx.upsert_sync_metadata(&sample_metadata("sync-1")).unwrap();
        let mut rotated = sample_device_record("sync-1", "dev-1");
        rotated.ml_dsa_65_public_key = vec![77u8; 1952]; // attacker-chosen ML-DSA key
        rotated.ml_dsa_key_generation = 5; // inflated generation
        tx.upsert_device_record(&rotated).unwrap();
        tx.commit().unwrap();
        let blob = src.export_snapshot("sync-1").unwrap();

        // Destination has dev-1 pinned at the original ML-DSA key / generation 0.
        let dst = make_storage();
        let mut tx = dst.begin_tx().unwrap();
        tx.upsert_device_record(&sample_device_record("sync-1", "dev-1")).unwrap();
        tx.commit().unwrap();

        let mut tx = dst.begin_tx().unwrap();
        tx.import_snapshot("sync-1", &blob).unwrap();
        tx.commit().unwrap();

        let d1 = dst.get_device_record("sync-1", "dev-1").unwrap().unwrap();
        assert_eq!(
            d1.ml_dsa_65_public_key,
            vec![9u8; 1952],
            "snapshot must not rebind the pinned ML-DSA key"
        );
        assert_eq!(d1.ml_dsa_key_generation, 0, "snapshot must not bump the ML-DSA generation");
    }

    #[test]
    fn import_snapshot_does_not_inflate_ml_dsa_generation() {
        // A snapshot with the SAME ML-DSA key bytes but an inflated generation
        // must not bump the pinned generation — otherwise it could block a
        // later legitimate signed gen+1 rotation.
        let src = make_storage();
        let mut tx = src.begin_tx().unwrap();
        tx.upsert_sync_metadata(&sample_metadata("sync-1")).unwrap();
        let mut inflated = sample_device_record("sync-1", "dev-1"); // identical key bytes
        inflated.ml_dsa_key_generation = 9; // inflated generation, key bytes unchanged
        tx.upsert_device_record(&inflated).unwrap();
        tx.commit().unwrap();
        let blob = src.export_snapshot("sync-1").unwrap();

        let dst = make_storage();
        let mut tx = dst.begin_tx().unwrap();
        tx.upsert_device_record(&sample_device_record("sync-1", "dev-1")).unwrap(); // gen 0
        tx.commit().unwrap();

        let mut tx = dst.begin_tx().unwrap();
        tx.import_snapshot("sync-1", &blob).unwrap();
        tx.commit().unwrap();

        let d1 = dst.get_device_record("sync-1", "dev-1").unwrap().unwrap();
        assert_eq!(d1.ml_dsa_key_generation, 0, "snapshot must not inflate the ML-DSA generation");
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

    // ── Bootstrap-support method tests ──

    #[test]
    fn list_all_field_version_hlcs_returns_every_winning_hlc() {
        let storage = make_storage();
        let mut tx = storage.begin_tx().unwrap();
        tx.upsert_field_version(&FieldVersion {
            sync_id: "sync-1".to_string(),
            entity_table: "members".to_string(),
            entity_id: "ent-1".to_string(),
            field_name: "name".to_string(),
            winning_op_id: "op-1".to_string(),
            winning_device_id: "dev1".to_string(),
            winning_hlc: "1700000000:9:dev1".to_string(),
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
            winning_hlc: "1700000000:10:dev1".to_string(),
            winning_encoded_value: Some("\"she/her\"".to_string()),
            updated_at: Utc::now(),
        })
        .unwrap();
        // Different sync group — must be excluded
        tx.upsert_field_version(&FieldVersion {
            sync_id: "sync-2".to_string(),
            entity_table: "members".to_string(),
            entity_id: "ent-x".to_string(),
            field_name: "name".to_string(),
            winning_op_id: "op-x".to_string(),
            winning_device_id: "dev1".to_string(),
            winning_hlc: "1700000999:0:dev1".to_string(),
            winning_encoded_value: Some("\"Other\"".to_string()),
            updated_at: Utc::now(),
        })
        .unwrap();
        tx.commit().unwrap();

        let mut hlcs = storage.list_all_field_version_hlcs("sync-1").unwrap();
        hlcs.sort();
        assert_eq!(hlcs, vec!["1700000000:10:dev1".to_string(), "1700000000:9:dev1".to_string()]);

        // Counter-order regression: the true max is :10, not :9.
        let max = crate::hlc::Hlc::parse_many_and_max(&hlcs).unwrap().unwrap();
        assert_eq!(max.counter, 10);

        // Empty sync group returns empty vec, not an error.
        let empty = storage.list_all_field_version_hlcs("sync-empty").unwrap();
        assert!(empty.is_empty());
    }

    #[test]
    fn delete_all_pending_ops_removes_only_this_sync_group() {
        let storage = make_storage();

        let mut tx = storage.begin_tx().unwrap();
        tx.insert_pending_op(&sample_pending_op("op-1", "sync-1", "batch-1")).unwrap();
        tx.insert_pending_op(&sample_pending_op("op-2", "sync-1", "batch-2")).unwrap();
        tx.insert_pending_op(&sample_pending_op("op-3", "sync-other", "batch-other")).unwrap();
        tx.commit().unwrap();

        let removed = storage.delete_all_pending_ops("sync-1").unwrap();
        assert_eq!(removed, 2);

        // Target sync group: no ops left
        assert!(storage.get_unpushed_batch_ids("sync-1").unwrap().is_empty());

        // Other sync group: untouched
        let other = storage.get_unpushed_batch_ids("sync-other").unwrap();
        assert_eq!(other, vec!["batch-other".to_string()]);

        // Calling again on an empty sync group returns 0.
        let removed_again = storage.delete_all_pending_ops("sync-1").unwrap();
        assert_eq!(removed_again, 0);
    }

    #[test]
    fn has_any_applied_ops_reflects_state() {
        let storage = make_storage();

        // Empty: false
        assert!(!storage.has_any_applied_ops("sync-1").unwrap());

        // Insert an applied op for sync-1
        let mut tx = storage.begin_tx().unwrap();
        tx.insert_applied_op(&sample_applied_op("applied-1", "sync-1")).unwrap();
        tx.commit().unwrap();
        assert!(storage.has_any_applied_ops("sync-1").unwrap());

        // Different sync group: still false
        assert!(!storage.has_any_applied_ops("sync-other").unwrap());
    }

    #[test]
    fn quarantined_ops_round_trip_and_clear_with_sync_state() {
        let storage = make_storage();
        let op = crate::crdt_change::CrdtChange::new(
            Some("op-quarantined".to_string()),
            Some("batch-quarantined".to_string()),
            "task-1".to_string(),
            "tasks".to_string(),
            "future_field".to_string(),
            Some("\"value\"".to_string()),
            Some("1000:0:device-a".to_string()),
            false,
            Some("device-a".to_string()),
            Some(0),
            None,
        );
        let quarantined = QuarantinedOp {
            sync_id: "sync-1".to_string(),
            op_id: op.op_id.clone(),
            op,
            reason: "unknown_field".to_string(),
            server_seq: 7,
            quarantined_at: Utc::now(),
        };

        let mut tx = storage.begin_tx().unwrap();
        tx.insert_quarantined_op(&quarantined).unwrap();
        tx.commit().unwrap();

        let rows = storage.list_quarantined_ops("sync-1").unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].op_id, "op-quarantined");
        assert_eq!(rows[0].op.field_name, "future_field");
        assert_eq!(rows[0].reason, "unknown_field");
        assert_eq!(rows[0].server_seq, 7);

        let mut tx = storage.begin_tx().unwrap();
        tx.clear_sync_state("sync-1").unwrap();
        tx.commit().unwrap();

        assert!(storage.list_quarantined_ops("sync-1").unwrap().is_empty());
    }

    // ── Pull-failure discipline: monotonic cursor + reset escape hatch ──

    #[test]
    fn update_last_pulled_seq_is_max_monotonic() {
        let storage = make_storage();
        let mut tx = storage.begin_tx().unwrap();
        tx.upsert_sync_metadata(&sample_metadata("sync-1")).unwrap();
        tx.commit().unwrap();

        // Advance forward.
        let mut tx = storage.begin_tx().unwrap();
        tx.update_last_pulled_seq("sync-1", 100).unwrap();
        tx.commit().unwrap();
        assert_eq!(storage.get_sync_metadata("sync-1").unwrap().unwrap().last_pulled_server_seq, 100);

        // A lower value (e.g. a Phase 0b replay re-applying an old batch) must
        // NOT rewind the cursor.
        let mut tx = storage.begin_tx().unwrap();
        tx.update_last_pulled_seq("sync-1", 40).unwrap();
        tx.commit().unwrap();
        assert_eq!(storage.get_sync_metadata("sync-1").unwrap().unwrap().last_pulled_server_seq, 100);

        // A higher value still advances.
        let mut tx = storage.begin_tx().unwrap();
        tx.update_last_pulled_seq("sync-1", 150).unwrap();
        tx.commit().unwrap();
        assert_eq!(storage.get_sync_metadata("sync-1").unwrap().unwrap().last_pulled_server_seq, 150);
    }

    #[test]
    fn reset_last_pulled_seq_can_rewind() {
        let storage = make_storage();
        let mut tx = storage.begin_tx().unwrap();
        tx.upsert_sync_metadata(&sample_metadata("sync-1")).unwrap();
        tx.update_last_pulled_seq("sync-1", 500).unwrap();
        tx.commit().unwrap();
        assert_eq!(storage.get_sync_metadata("sync-1").unwrap().unwrap().last_pulled_server_seq, 500);

        // The explicit reset escape hatch (bootstrap / relay-log lineage change) is
        // allowed to move the cursor backwards.
        let mut tx = storage.begin_tx().unwrap();
        tx.reset_last_pulled_seq("sync-1", 0).unwrap();
        tx.commit().unwrap();
        assert_eq!(storage.get_sync_metadata("sync-1").unwrap().unwrap().last_pulled_server_seq, 0);
    }

    #[test]
    fn reset_last_pulled_seq_creates_metadata_when_missing() {
        let storage = make_storage();
        let mut tx = storage.begin_tx().unwrap();
        tx.reset_last_pulled_seq("sync-1", 7).unwrap();
        tx.commit().unwrap();
        let m = storage.get_sync_metadata("sync-1").unwrap().unwrap();
        assert_eq!(m.last_pulled_server_seq, 7);
    }

    // ── Pull-failure discipline: quarantined_pull_batches + pull_stall ──

    fn sample_pull_envelope(sync_id: &str, batch_id: &str, sender: &str) -> SignedBatchEnvelope {
        SignedBatchEnvelope {
            protocol_version: 3,
            sync_id: sync_id.to_string(),
            epoch: 2,
            batch_id: batch_id.to_string(),
            batch_kind: "ops".to_string(),
            sender_device_id: sender.to_string(),
            sender_ml_dsa_key_generation: 1,
            payload_hash: [7u8; 32],
            signature: vec![1, 2, 3, 4],
            nonce: [9u8; 24],
            ciphertext: vec![5, 6, 7, 8, 9],
        }
    }

    fn sample_quarantined_pull_batch(
        sync_id: &str,
        batch_id: &str,
        server_seq: i64,
        reason: &str,
    ) -> QuarantinedPullBatch {
        sample_quarantined_pull_batch_from(sync_id, batch_id, server_seq, reason, "dev-c")
    }

    fn sample_quarantined_pull_batch_from(
        sync_id: &str,
        batch_id: &str,
        server_seq: i64,
        reason: &str,
        sender: &str,
    ) -> QuarantinedPullBatch {
        QuarantinedPullBatch {
            sync_id: sync_id.to_string(),
            batch_id: batch_id.to_string(),
            server_seq,
            epoch: Some(2),
            sender_device_id: sender.to_string(),
            envelope: sample_pull_envelope(sync_id, batch_id, sender),
            reason: reason.to_string(),
            retry_count: 0,
            quarantined_at: Utc::now(),
            last_retry_at: None,
        }
    }

    #[test]
    fn quarantined_pull_batch_round_trip_preserves_envelope() {
        let storage = make_storage();
        assert!(storage.list_quarantined_pull_batches("sync-1").unwrap().is_empty());

        let batch = sample_quarantined_pull_batch("sync-1", "batch-poison", 12, "payload_hash_mismatch");
        let mut tx = storage.begin_tx().unwrap();
        tx.insert_quarantined_pull_batch(&batch).unwrap();
        tx.commit().unwrap();

        let rows = storage.list_quarantined_pull_batches("sync-1").unwrap();
        assert_eq!(rows.len(), 1);
        let r = &rows[0];
        assert_eq!(r.batch_id, "batch-poison");
        assert_eq!(r.server_seq, 12);
        assert_eq!(r.epoch, Some(2));
        assert_eq!(r.sender_device_id, "dev-c");
        assert_eq!(r.reason, "payload_hash_mismatch");
        assert_eq!(r.retry_count, 0);
        assert!(r.last_retry_at.is_none());
        // Envelope survives the JSON round-trip intact.
        assert_eq!(r.envelope.batch_id, "batch-poison");
        assert_eq!(r.envelope.sender_ml_dsa_key_generation, 1);
        assert_eq!(r.envelope.payload_hash, [7u8; 32]);
        assert_eq!(r.envelope.ciphertext, vec![5, 6, 7, 8, 9]);
    }

    #[test]
    fn quarantined_pull_batches_list_ordered_by_server_seq() {
        let storage = make_storage();
        let mut tx = storage.begin_tx().unwrap();
        tx.insert_quarantined_pull_batch(&sample_quarantined_pull_batch(
            "sync-1", "b-high", 30, "decode_failed",
        ))
        .unwrap();
        tx.insert_quarantined_pull_batch(&sample_quarantined_pull_batch(
            "sync-1", "b-low", 10, "decode_failed",
        ))
        .unwrap();
        tx.commit().unwrap();

        let rows = storage.list_quarantined_pull_batches("sync-1").unwrap();
        let seqs: Vec<i64> = rows.iter().map(|r| r.server_seq).collect();
        assert_eq!(seqs, vec![10, 30]);
    }

    #[test]
    fn bump_and_delete_quarantined_pull_batch() {
        let storage = make_storage();
        let mut tx = storage.begin_tx().unwrap();
        tx.insert_quarantined_pull_batch(&sample_quarantined_pull_batch(
            "sync-1", "b", 5, "sender_unresolved",
        ))
        .unwrap();
        tx.commit().unwrap();

        // Bump retry twice; retry_count increments and last_retry_at is stamped.
        // (sample_quarantined_pull_batch stamps sender_device_id = "dev-c".)
        let mut tx = storage.begin_tx().unwrap();
        tx.bump_quarantined_pull_batch_retry("sync-1", "dev-c", "b").unwrap();
        tx.bump_quarantined_pull_batch_retry("sync-1", "dev-c", "b").unwrap();
        tx.commit().unwrap();

        let rows = storage.list_quarantined_pull_batches("sync-1").unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].retry_count, 2);
        assert!(rows[0].last_retry_at.is_some());

        // Delete (replay succeeded or sender revoked) removes the row.
        let mut tx = storage.begin_tx().unwrap();
        tx.delete_quarantined_pull_batch("sync-1", "dev-c", "b").unwrap();
        tx.commit().unwrap();
        assert!(storage.list_quarantined_pull_batches("sync-1").unwrap().is_empty());
    }

    #[test]
    fn quarantined_pull_batches_scoped_by_sync_id() {
        let storage = make_storage();
        let mut tx = storage.begin_tx().unwrap();
        tx.insert_quarantined_pull_batch(&sample_quarantined_pull_batch(
            "sync-1", "b1", 1, "decode_failed",
        ))
        .unwrap();
        tx.insert_quarantined_pull_batch(&sample_quarantined_pull_batch(
            "sync-other", "b2", 1, "decode_failed",
        ))
        .unwrap();
        tx.commit().unwrap();

        assert_eq!(storage.list_quarantined_pull_batches("sync-1").unwrap().len(), 1);
        assert_eq!(storage.list_quarantined_pull_batches("sync-other").unwrap().len(), 1);
        assert_eq!(storage.list_quarantined_pull_batches("sync-1").unwrap()[0].batch_id, "b1");
    }

    /// Two different senders sharing the same `batch_id` (legal on the wire — the
    /// relay dedups on `(sync_id, sender_device_id, batch_id)`) must NOT evict
    /// each other: the second insert keeps the first sender's envelope intact and
    /// deleting one leaves the other. This pins the cross-sender custody invariant
    /// that the `(sync_id, sender_device_id, batch_id)` PK exists to protect.
    #[test]
    fn same_batch_id_from_different_senders_coexist() {
        let storage = make_storage();
        let mut tx = storage.begin_tx().unwrap();
        tx.insert_quarantined_pull_batch(&sample_quarantined_pull_batch_from(
            "sync-1", "shared-id", 10, "invalid_signature", "honest-h",
        ))
        .unwrap();
        // A compromised device pushes a deliberately-failing batch under the SAME
        // batch_id; with batch_id alone as the key this REPLACE would destroy H's
        // durably-stored envelope.
        tx.insert_quarantined_pull_batch(&sample_quarantined_pull_batch_from(
            "sync-1", "shared-id", 11, "attribution_mismatch", "compromised-m",
        ))
        .unwrap();
        tx.commit().unwrap();

        let rows = storage.list_quarantined_pull_batches("sync-1").unwrap();
        assert_eq!(rows.len(), 2, "both senders' envelopes must be retained");
        assert!(rows.iter().any(|r| r.sender_device_id == "honest-h"));
        assert!(rows.iter().any(|r| r.sender_device_id == "compromised-m"));

        // Deleting M's row leaves H's intact, and vice versa.
        let mut tx = storage.begin_tx().unwrap();
        tx.delete_quarantined_pull_batch("sync-1", "compromised-m", "shared-id").unwrap();
        tx.commit().unwrap();
        let rows = storage.list_quarantined_pull_batches("sync-1").unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].sender_device_id, "honest-h");
        assert_eq!(rows[0].reason, "invalid_signature");
    }

    #[test]
    fn record_pull_stall_increments_attempts_and_preserves_first_seen() {
        let storage = make_storage();

        let mut tx = storage.begin_tx().unwrap();
        tx.record_pull_stall("sync-1", 42, "sender_unresolved").unwrap();
        tx.commit().unwrap();

        let rows = storage.list_pull_stalls("sync-1").unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].server_seq, 42);
        assert_eq!(rows[0].attempts, 1);
        assert_eq!(rows[0].reason, "sender_unresolved");
        let first_seen = rows[0].first_seen_at;

        // Bumping the same seq increments attempts, refreshes the reason, and
        // preserves first_seen_at.
        let mut tx = storage.begin_tx().unwrap();
        tx.record_pull_stall("sync-1", 42, "stale_key_generation").unwrap();
        tx.commit().unwrap();

        let rows = storage.list_pull_stalls("sync-1").unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].attempts, 2);
        assert_eq!(rows[0].reason, "stale_key_generation");
        assert_eq!(rows[0].first_seen_at, first_seen);
    }

    #[test]
    fn clear_pull_stall_removes_only_the_target_seq() {
        let storage = make_storage();
        let mut tx = storage.begin_tx().unwrap();
        tx.record_pull_stall("sync-1", 10, "sender_unresolved").unwrap();
        tx.record_pull_stall("sync-1", 20, "sender_unresolved").unwrap();
        tx.commit().unwrap();

        let mut tx = storage.begin_tx().unwrap();
        tx.clear_pull_stall("sync-1", 10).unwrap();
        tx.commit().unwrap();

        let rows = storage.list_pull_stalls("sync-1").unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].server_seq, 20);
    }

    #[test]
    fn clear_sync_state_empties_pull_failure_tables() {
        let storage = make_storage();
        let mut tx = storage.begin_tx().unwrap();
        tx.insert_quarantined_pull_batch(&sample_quarantined_pull_batch(
            "sync-1", "b", 5, "decode_failed",
        ))
        .unwrap();
        tx.record_pull_stall("sync-1", 5, "sender_unresolved").unwrap();
        tx.commit().unwrap();

        let mut tx = storage.begin_tx().unwrap();
        tx.clear_sync_state("sync-1").unwrap();
        tx.commit().unwrap();

        assert!(storage.list_quarantined_pull_batches("sync-1").unwrap().is_empty());
        assert!(storage.list_pull_stalls("sync-1").unwrap().is_empty());
    }

    // ── Consumer-delivery journal tests ──

    fn sample_consumer_delivery(
        sync_id: &str,
        entity_id: &str,
        field: Option<&str>,
        server_seq: i64,
    ) -> ConsumerDelivery {
        let is_delete = field.is_none();
        ConsumerDelivery {
            id: 0,
            sync_id: sync_id.to_string(),
            entity_table: "members".to_string(),
            entity_id: entity_id.to_string(),
            field_name: field.map(|f| f.to_string()),
            encoded_value: field.map(|f| format!("\"{f}-val\"")),
            is_delete,
            server_seq,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn consumer_delivery_journal_lists_in_id_order_and_filters_after_id() {
        let storage = make_storage();

        let mut tx = storage.begin_tx().unwrap();
        tx.insert_consumer_delivery(&sample_consumer_delivery("sync-1", "ent-1", Some("name"), 1))
            .unwrap();
        tx.insert_consumer_delivery(&sample_consumer_delivery("sync-1", "ent-2", Some("name"), 2))
            .unwrap();
        // A different group's row must never leak into sync-1's drain.
        tx.insert_consumer_delivery(&sample_consumer_delivery("sync-2", "ent-x", Some("name"), 9))
            .unwrap();
        tx.commit().unwrap();

        assert_eq!(storage.count_consumer_deliveries("sync-1").unwrap(), 2);
        assert_eq!(storage.count_consumer_deliveries("sync-2").unwrap(), 1);

        let rows = storage.list_consumer_deliveries("sync-1", 0, 100).unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows[0].id < rows[1].id, "rows must come back in id order");
        assert_eq!(rows[0].entity_id, "ent-1");
        assert_eq!(rows[0].field_name.as_deref(), Some("name"));
        assert!(!rows[0].is_delete);

        // after_id excludes already-drained rows.
        let after_first = storage.list_consumer_deliveries("sync-1", rows[0].id, 100).unwrap();
        assert_eq!(after_first.len(), 1);
        assert_eq!(after_first[0].entity_id, "ent-2");

        // limit caps the chunk.
        let capped = storage.list_consumer_deliveries("sync-1", 0, 1).unwrap();
        assert_eq!(capped.len(), 1);
        assert_eq!(capped[0].entity_id, "ent-1");
    }

    #[test]
    fn consumer_delivery_delete_row_roundtrips_with_null_field() {
        let storage = make_storage();

        let mut tx = storage.begin_tx().unwrap();
        tx.insert_consumer_delivery(&sample_consumer_delivery("sync-1", "ent-1", None, 5))
            .unwrap();
        tx.commit().unwrap();

        let rows = storage.list_consumer_deliveries("sync-1", 0, 100).unwrap();
        assert_eq!(rows.len(), 1);
        assert!(rows[0].is_delete);
        assert_eq!(rows[0].field_name, None);
        assert_eq!(rows[0].encoded_value, None);
        assert_eq!(rows[0].server_seq, 5);
    }

    #[test]
    fn ack_consumer_deliveries_removes_rows_up_to_id_inclusive() {
        let storage = make_storage();

        let mut tx = storage.begin_tx().unwrap();
        for i in 0..5 {
            tx.insert_consumer_delivery(&sample_consumer_delivery(
                "sync-1",
                &format!("ent-{i}"),
                Some("name"),
                i,
            ))
            .unwrap();
        }
        tx.commit().unwrap();

        let rows = storage.list_consumer_deliveries("sync-1", 0, 100).unwrap();
        assert_eq!(rows.len(), 5);
        let third_id = rows[2].id;

        // Ack up to the third row's id.
        let mut tx = storage.begin_tx().unwrap();
        tx.delete_consumer_deliveries_up_to("sync-1", third_id).unwrap();
        tx.commit().unwrap();

        let remaining = storage.list_consumer_deliveries("sync-1", 0, 100).unwrap();
        assert_eq!(remaining.len(), 2, "only rows with id > up_to_id survive");
        assert!(remaining.iter().all(|r| r.id > third_id));
    }

    #[test]
    fn consumer_delivery_journal_aborted_tx_leaves_no_rows() {
        // Crash-sim: the journal write shares its transaction with the cursor /
        // bookkeeping write, so a rolled-back tx must leave neither.
        let storage = make_storage();

        let mut tx = storage.begin_tx().unwrap();
        tx.update_last_pulled_seq("sync-1", 7).unwrap();
        tx.insert_consumer_delivery(&sample_consumer_delivery("sync-1", "ent-1", Some("name"), 7))
            .unwrap();
        tx.rollback().unwrap();

        // Neither the cursor advance nor the journal row survived the abort.
        assert!(storage.list_consumer_deliveries("sync-1", 0, 100).unwrap().is_empty());
        assert!(storage.get_sync_metadata("sync-1").unwrap().is_none());
    }

    #[test]
    fn clear_sync_state_empties_consumer_delivery_journal() {
        let storage = make_storage();
        let mut tx = storage.begin_tx().unwrap();
        tx.insert_consumer_delivery(&sample_consumer_delivery("sync-1", "ent-1", Some("name"), 1))
            .unwrap();
        tx.insert_consumer_delivery(&sample_consumer_delivery("sync-2", "ent-2", Some("name"), 1))
            .unwrap();
        tx.commit().unwrap();

        let mut tx = storage.begin_tx().unwrap();
        tx.clear_sync_state("sync-1").unwrap();
        tx.commit().unwrap();

        assert!(storage.list_consumer_deliveries("sync-1", 0, 100).unwrap().is_empty());
        // The other group's journal is untouched.
        assert_eq!(storage.count_consumer_deliveries("sync-2").unwrap(), 1);
    }

    #[test]
    fn archive_device_key_roundtrips_and_is_generation_scoped() {
        let storage = make_storage();

        let mut tx = storage.begin_tx().unwrap();
        tx.archive_device_key("sync-1", "dev-a", 0, &[0xAAu8; 16]).unwrap();
        tx.archive_device_key("sync-1", "dev-a", 1, &[0xBBu8; 16]).unwrap();
        tx.commit().unwrap();

        // Exact-generation lookup returns the matching archived key.
        assert_eq!(
            storage.get_archived_device_key("sync-1", "dev-a", 0).unwrap(),
            Some(vec![0xAAu8; 16])
        );
        assert_eq!(
            storage.get_archived_device_key("sync-1", "dev-a", 1).unwrap(),
            Some(vec![0xBBu8; 16])
        );
        // A generation never archived (and a different device) returns None.
        assert_eq!(storage.get_archived_device_key("sync-1", "dev-a", 2).unwrap(), None);
        assert_eq!(storage.get_archived_device_key("sync-1", "dev-b", 0).unwrap(), None);
    }

    #[test]
    fn archive_device_key_keeps_first_archived_on_conflict() {
        let storage = make_storage();

        let mut tx = storage.begin_tx().unwrap();
        tx.archive_device_key("sync-1", "dev-a", 0, &[0x11u8; 8]).unwrap();
        // Re-archiving the same (device, generation) is a no-op (INSERT OR IGNORE):
        // a device's key for a given generation is fixed.
        tx.archive_device_key("sync-1", "dev-a", 0, &[0x22u8; 8]).unwrap();
        tx.commit().unwrap();

        assert_eq!(
            storage.get_archived_device_key("sync-1", "dev-a", 0).unwrap(),
            Some(vec![0x11u8; 8])
        );
    }

    #[test]
    fn clear_sync_state_empties_device_key_history() {
        let storage = make_storage();
        let mut tx = storage.begin_tx().unwrap();
        tx.archive_device_key("sync-1", "dev-a", 0, &[0xAAu8; 8]).unwrap();
        tx.commit().unwrap();
        assert!(storage.get_archived_device_key("sync-1", "dev-a", 0).unwrap().is_some());

        let mut tx = storage.begin_tx().unwrap();
        tx.clear_sync_state("sync-1").unwrap();
        tx.commit().unwrap();

        assert_eq!(storage.get_archived_device_key("sync-1", "dev-a", 0).unwrap(), None);
    }

    #[test]
    fn count_devices_in_group_counts_registered_devices() {
        let storage = make_storage();

        assert_eq!(storage.count_devices_in_group("sync-1").unwrap(), 0);

        let mut tx = storage.begin_tx().unwrap();
        tx.upsert_device_record(&sample_device_record("sync-1", "dev-1")).unwrap();
        tx.commit().unwrap();
        assert_eq!(storage.count_devices_in_group("sync-1").unwrap(), 1);

        let mut tx = storage.begin_tx().unwrap();
        tx.upsert_device_record(&sample_device_record("sync-1", "dev-2")).unwrap();
        tx.upsert_device_record(&sample_device_record("sync-other", "dev-x")).unwrap();
        tx.commit().unwrap();
        assert_eq!(storage.count_devices_in_group("sync-1").unwrap(), 2);
        assert_eq!(storage.count_devices_in_group("sync-other").unwrap(), 1);
    }

    // ── Push-quarantine tests (Phase 1B) ──

    #[test]
    fn quarantine_batch_round_trip_and_unquarantine() {
        let storage = make_storage();

        // List on empty storage returns empty + count 0.
        assert!(storage.list_quarantined_batches("sync-1").unwrap().is_empty());
        assert_eq!(storage.quarantined_batch_count("sync-1").unwrap(), 0);

        // Quarantine one batch.
        let mut tx = storage.begin_tx().unwrap();
        tx.quarantine_batch(
            "sync-1",
            "batch-too-big",
            "members",
            "member-1",
            1_400_000,
            "payload_too_large",
            "relay returned 413",
        )
        .unwrap();
        tx.commit().unwrap();

        let rows = storage.list_quarantined_batches("sync-1").unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].batch_id, "batch-too-big");
        assert_eq!(rows[0].entity_table, "members");
        assert_eq!(rows[0].entity_id, "member-1");
        assert_eq!(rows[0].body_bytes, 1_400_000);
        assert_eq!(rows[0].error_code, "payload_too_large");
        assert_eq!(rows[0].error_message, "relay returned 413");
        assert!(!rows[0].quarantined_at.is_empty(), "quarantined_at populated by impl");
        assert_eq!(storage.quarantined_batch_count("sync-1").unwrap(), 1);

        // Unquarantine deletes the row.
        let mut tx = storage.begin_tx().unwrap();
        tx.unquarantine_batch("sync-1", "batch-too-big").unwrap();
        tx.commit().unwrap();

        assert!(storage.list_quarantined_batches("sync-1").unwrap().is_empty());
        assert_eq!(storage.quarantined_batch_count("sync-1").unwrap(), 0);
    }

    #[test]
    fn quarantine_batch_is_scoped_by_sync_id() {
        let storage = make_storage();

        let mut tx = storage.begin_tx().unwrap();
        tx.quarantine_batch(
            "sync-1",
            "batch-a",
            "members",
            "member-1",
            1_200_000,
            "payload_too_large",
            "a",
        )
        .unwrap();
        tx.quarantine_batch(
            "sync-other",
            "batch-b",
            "members",
            "member-2",
            1_300_000,
            "payload_too_large_client_guard",
            "b",
        )
        .unwrap();
        tx.commit().unwrap();

        assert_eq!(storage.quarantined_batch_count("sync-1").unwrap(), 1);
        assert_eq!(storage.quarantined_batch_count("sync-other").unwrap(), 1);

        let rows = storage.list_quarantined_batches("sync-1").unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].batch_id, "batch-a");
    }

    #[test]
    fn get_unpushed_batch_ids_excludes_quarantined() {
        let storage = make_storage();

        // Insert two pending batches.
        let mut tx = storage.begin_tx().unwrap();
        tx.insert_pending_op(&sample_pending_op("op-good", "sync-1", "batch-good")).unwrap();
        tx.insert_pending_op(&sample_pending_op("op-bad", "sync-1", "batch-bad")).unwrap();
        tx.commit().unwrap();

        // Before quarantine: both batches show up.
        let ids = storage.get_unpushed_batch_ids("sync-1").unwrap();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&"batch-good".to_string()));
        assert!(ids.contains(&"batch-bad".to_string()));

        // Quarantine the bad one.
        let mut tx = storage.begin_tx().unwrap();
        tx.quarantine_batch(
            "sync-1",
            "batch-bad",
            "members",
            "member-1",
            1_400_000,
            "payload_too_large",
            "relay 413",
        )
        .unwrap();
        tx.commit().unwrap();

        // After quarantine: only the good one shows up.
        let ids = storage.get_unpushed_batch_ids("sync-1").unwrap();
        assert_eq!(ids, vec!["batch-good".to_string()]);
    }

    #[test]
    fn clear_sync_state_empties_push_quarantine() {
        let storage = make_storage();

        // Seed metadata + quarantine row.
        let mut tx = storage.begin_tx().unwrap();
        tx.upsert_sync_metadata(&sample_metadata("sync-1")).unwrap();
        tx.quarantine_batch(
            "sync-1",
            "batch-stuck",
            "members",
            "member-1",
            1_400_000,
            "payload_too_large",
            "relay 413",
        )
        .unwrap();
        tx.commit().unwrap();

        assert_eq!(storage.quarantined_batch_count("sync-1").unwrap(), 1);

        let mut tx = storage.begin_tx().unwrap();
        tx.clear_sync_state("sync-1").unwrap();
        tx.commit().unwrap();

        assert_eq!(storage.quarantined_batch_count("sync-1").unwrap(), 0);
        assert!(storage.list_quarantined_batches("sync-1").unwrap().is_empty());
    }

    #[test]
    fn export_snapshot_excludes_push_quarantine_rows() {
        let storage = make_storage();
        populate_for_snapshot(&storage);

        // Add a push_quarantine row that must NOT bleed into the snapshot.
        let mut tx = storage.begin_tx().unwrap();
        tx.quarantine_batch(
            "sync-1",
            "batch-secret",
            "members",
            "member-1",
            1_400_000,
            "payload_too_large",
            "relay 413",
        )
        .unwrap();
        tx.commit().unwrap();

        let blob = storage.export_snapshot("sync-1").unwrap();
        let json = zstd::decode_all(blob.as_slice()).unwrap();

        // Decoded JSON must not contain the quarantine batch_id or error_code.
        let as_str = String::from_utf8_lossy(&json);
        assert!(
            !as_str.contains("batch-secret"),
            "snapshot leaked push_quarantine batch_id: {as_str}"
        );
        assert!(
            !as_str.contains("payload_too_large"),
            "snapshot leaked push_quarantine error_code: {as_str}"
        );

        // SnapshotData must still deserialize and only contain the populate_for_snapshot fields.
        let snapshot: SnapshotData = serde_json::from_slice(&json).unwrap();
        assert_eq!(snapshot.field_versions.len(), 3);
        assert_eq!(snapshot.applied_ops.len(), 2);
    }

    /// Regression for push ordering across multi-batch partitions.
    ///
    /// **Background:** `to_rfc3339()` strips trailing zeros, so an exact-
    /// millisecond timestamp emits `12:34:56.123Z` while the very next +1µs
    /// partition emits `12:34:56.123001Z`. Lexical TEXT comparison places
    /// `.123001Z` *before* `.123Z` (because `.` 0x2E < `Z` 0x5A), so the
    /// chronologically-earlier partition sorts second, inverting push order.
    ///
    /// **Fix A** (verified here): `exec_insert_pending_op` now writes
    /// `to_rfc3339_opts(SecondsFormat::Micros, true)`, which always emits
    /// exactly six subsecond digits. Two partitions whose chronological order
    /// differs by 1µs land at fixed-width `.123000Z` and `.123001Z` strings
    /// that sort correctly lexically.
    ///
    /// **Fix B** (verified here): `query_unpushed_batch_ids` now uses
    /// `MIN(client_hlc) ASC` as a secondary sort key, so if two batches end
    /// up sharing an identical `first_created` (e.g., two ops emitted within
    /// the same microsecond on a coarse clock) the per-device monotonic HLC
    /// still partitions them deterministically.
    #[test]
    fn unpushed_batch_ids_partition_order_is_deterministic_in_boundary_case() {
        // Part 1 — Fix A: verify the storage trait writes fixed-width
        // microsecond timestamps so a +1µs partition boundary cannot invert.
        let storage = make_storage();
        let sync_id = "sync-1";

        // Synthesize the exact P1 boundary case: partition[0] at an exact
        // millisecond, partition[1] at +1µs. Before Fix A these would write
        // as ".123Z" and ".123001Z" and sort lexically out of order.
        let t_partition0 = DateTime::parse_from_rfc3339("2026-05-11T08:00:00.123000Z")
            .unwrap()
            .with_timezone(&Utc);
        let t_partition1 = DateTime::parse_from_rfc3339("2026-05-11T08:00:00.123001Z")
            .unwrap()
            .with_timezone(&Utc);

        let op_partition0 = PendingOp {
            op_id: "op-partition0".into(),
            sync_id: sync_id.into(),
            epoch: 1,
            device_id: "dev1".into(),
            local_batch_id: "batch-partition0".into(),
            entity_table: "members".into(),
            entity_id: "ent-1".into(),
            field_name: "name".into(),
            encoded_value: "\"A\"".into(),
            is_delete: false,
            client_hlc: "1778947200123:0000000000:dev1".into(),
            created_at: t_partition0,
            pushed_at: None,
        };
        let op_partition1 = PendingOp {
            op_id: "op-partition1".into(),
            sync_id: sync_id.into(),
            epoch: 1,
            device_id: "dev1".into(),
            local_batch_id: "batch-partition1".into(),
            entity_table: "members".into(),
            entity_id: "ent-2".into(),
            field_name: "name".into(),
            encoded_value: "\"B\"".into(),
            is_delete: false,
            client_hlc: "1778947200123:0000000001:dev1".into(),
            created_at: t_partition1,
            pushed_at: None,
        };

        let mut tx = storage.begin_tx().unwrap();
        tx.insert_pending_op(&op_partition0).unwrap();
        tx.insert_pending_op(&op_partition1).unwrap();
        tx.commit().unwrap();

        // Sanity-check that the written strings are fixed-width microseconds.
        // If this ever regresses (e.g., someone switches back to `to_rfc3339`)
        // it will be visible here before the ordering assertion below.
        let stored: Vec<(String, String)> = {
            let conn = storage.conn.lock().expect("mutex poisoned");
            let mut stmt = conn
                .prepare(
                    "SELECT local_batch_id, created_at FROM pending_ops \
                     WHERE sync_id = ?1 ORDER BY local_batch_id",
                )
                .unwrap();
            let mut out = Vec::new();
            let rows = stmt
                .query_map(params![sync_id], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .unwrap();
            for r in rows {
                out.push(r.unwrap());
            }
            out
        };
        assert_eq!(
            stored,
            vec![
                ("batch-partition0".to_string(), "2026-05-11T08:00:00.123000Z".to_string()),
                ("batch-partition1".to_string(), "2026-05-11T08:00:00.123001Z".to_string()),
            ],
            "pending_ops.created_at must be written as fixed-width microseconds \
             so lexical TEXT order matches chronological order (Fix A)"
        );

        let ids = storage.get_unpushed_batch_ids(sync_id).unwrap();
        assert_eq!(
            ids,
            vec!["batch-partition0".to_string(), "batch-partition1".to_string()],
            "chronologically-earlier partition (`.123000Z`) must sort before \
             the +1µs partition (`.123001Z`) — Fix A makes the boundary case \
             impossible to express through the storage trait"
        );

        // Part 2 — Fix B: when two batches share an identical `created_at`
        // (e.g., two ops emitted within the same microsecond), the HLC
        // tiebreaker must produce a deterministic order. Insert via raw SQL
        // because the storage trait cannot easily produce a same-microsecond
        // tie at runtime.
        let storage_ties = make_storage();
        let sync_id = "sync-2";
        let same_ts = "2026-05-11T08:00:01.000000Z";
        let earlier_hlc = "1778947201000:0000000000:dev1";
        let later_hlc = "1778947201000:0000000001:dev1";

        {
            let conn = storage_ties.conn.lock().expect("mutex poisoned");
            // Inserted in reverse chronological order so the test fails if the
            // SQL relies on insertion order rather than the HLC tiebreaker.
            conn.execute(
                "INSERT INTO pending_ops \
                 (op_id, sync_id, epoch, device_id, local_batch_id, entity_table, entity_id, \
                  field_name, encoded_value, is_delete, client_hlc, created_at, pushed_at) \
                 VALUES (?1, ?2, 1, 'dev1', ?3, 'members', 'ent-2', 'name', '\"B\"', 0, ?4, ?5, NULL)",
                params!["op-later", sync_id, "batch-later", later_hlc, same_ts],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO pending_ops \
                 (op_id, sync_id, epoch, device_id, local_batch_id, entity_table, entity_id, \
                  field_name, encoded_value, is_delete, client_hlc, created_at, pushed_at) \
                 VALUES (?1, ?2, 1, 'dev1', ?3, 'members', 'ent-1', 'name', '\"A\"', 0, ?4, ?5, NULL)",
                params!["op-earlier", sync_id, "batch-earlier", earlier_hlc, same_ts],
            )
            .unwrap();
        }

        let ids = storage_ties.get_unpushed_batch_ids(sync_id).unwrap();
        assert_eq!(
            ids,
            vec!["batch-earlier".to_string(), "batch-later".to_string()],
            "when first_created ties, MIN(client_hlc) must break the tie in \
             HLC order — Fix B's secondary ORDER BY"
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
