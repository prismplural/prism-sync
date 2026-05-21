use super::types::*;
use crate::error::Result;

/// Storage layer for sync engine state — **top-level, object-safe trait**.
///
/// All methods are synchronous. The sync engine wraps calls in
/// `tokio::task::spawn_blocking` to avoid stalling the tokio reactor.
///
/// NOTE: This trait is object-safe (`dyn SyncStorage` is valid). All
/// transactional operations go through `SyncStorageTx`, obtained via
/// `begin_tx()`. This avoids the generic-method-on-trait-object problem
/// (Rust traits with generic methods are not object-safe).
pub trait SyncStorage: Send + Sync {
    /// Begin a transaction. Returns a boxed transaction handle.
    /// All mutating operations during a sync cycle should go through the tx.
    fn begin_tx(&self) -> Result<Box<dyn SyncStorageTx + '_>>;

    // ── Non-transactional reads ──

    /// Fetch metadata for a sync group.
    fn get_sync_metadata(&self, sync_id: &str) -> Result<Option<SyncMetadata>>;

    /// Get batch IDs of unpushed ops, ordered by first created_at ascending.
    /// Lightweight — does not load encoded_value blobs.
    fn get_unpushed_batch_ids(&self, sync_id: &str) -> Result<Vec<String>>;

    /// Load all ops for a single batch, including encoded_value.
    fn load_batch_ops(&self, batch_id: &str) -> Result<Vec<PendingOp>>;

    /// Check if a remote op has already been applied (by op_id).
    fn is_op_applied(&self, op_id: &str) -> Result<bool>;

    /// Get the current winning version for a field.
    fn get_field_version(
        &self,
        sync_id: &str,
        table: &str,
        entity_id: &str,
        field: &str,
    ) -> Result<Option<FieldVersion>>;

    /// List remote ops quarantined because they targeted schema unknown to
    /// this client at pull time.
    fn list_quarantined_ops(&self, _sync_id: &str) -> Result<Vec<QuarantinedOp>> {
        Ok(vec![])
    }

    /// List local push batches that were quarantined because their envelope
    /// exceeded the relay's body cap. Returns rows in `quarantined_at`
    /// insertion order.
    ///
    /// Default: empty (no-op for in-memory impls).
    fn list_quarantined_batches(&self, _sync_id: &str) -> Result<Vec<QuarantinedBatchInfo>> {
        Ok(vec![])
    }

    /// Return the count of push-quarantined batches for this sync group.
    /// Cheap wrapper around `list_quarantined_batches` so callers can poll
    /// for a UI banner without paying the row-construction cost.
    ///
    /// Default: 0 (no-op for in-memory impls).
    fn quarantined_batch_count(&self, _sync_id: &str) -> Result<i64> {
        Ok(0)
    }

    /// Get a device record by sync_id and device_id.
    fn get_device_record(&self, sync_id: &str, device_id: &str) -> Result<Option<DeviceRecord>>;

    /// List all device records for a sync group.
    fn list_device_records(&self, sync_id: &str) -> Result<Vec<DeviceRecord>>;

    // ── Pruning reads (default no-op implementations) ──

    /// Count applied_ops below a given server_seq. Default: 0 (no-op).
    fn count_prunable_applied_ops(&self, _sync_id: &str, _below_seq: i64) -> Result<usize> {
        Ok(0)
    }

    /// List (table, entity_id) pairs for soft-deleted entities whose delete op
    /// was below the given server_seq. Default: empty (no-op).
    fn list_prunable_tombstones(
        &self,
        _sync_id: &str,
        _below_seq: i64,
        _limit: usize,
    ) -> Result<Vec<(String, String)>> {
        Ok(vec![])
    }

    /// Export all sync state as a snapshot blob (JSON, then zstd-compressed).
    /// Contains field_versions, device_registry, applied_ops, and sync_metadata.
    fn export_snapshot(&self, sync_id: &str) -> Result<Vec<u8>>;

    /// Re-encrypt the underlying storage with a new 32-byte key.
    /// No-op for in-memory impls.
    fn rekey(&self, new_key: &[u8; 32]) -> Result<()>;

    /// List every `winning_hlc` string currently stored in `field_versions`
    /// for this sync group.
    ///
    /// Used by the first-device bootstrap path to compute the max HLC
    /// across all seeded rows. A SQL `MAX(winning_hlc)` would compare
    /// strings lexicographically — wrong for HLCs, because `":9"` sorts
    /// after `":10"`. Callers parse with `Hlc::from_string` and compare
    /// via `Hlc::Ord` instead.
    ///
    /// Default: empty (no-op).
    fn list_all_field_version_hlcs(&self, _sync_id: &str) -> Result<Vec<String>> {
        Ok(vec![])
    }

    /// Delete every `pending_ops` row for this sync group, transactionally.
    /// Returns the number of rows deleted.
    ///
    /// Used only by the first-device bootstrap guard cleanup path. In that
    /// path, any rows in `pending_ops` are orphans from a previous failed
    /// bootstrap attempt — there is no legitimate code path that could
    /// have produced a to-be-pushed mutation before first-pair.
    ///
    /// Default: 0 (no-op).
    fn delete_all_pending_ops(&self, _sync_id: &str) -> Result<usize> {
        Ok(0)
    }

    /// Check whether this sync group has any `applied_ops` rows.
    ///
    /// Cheap `SELECT 1 ... LIMIT 1`. Used by the first-device bootstrap
    /// setup-only guard to prove we have never merged a remote op.
    ///
    /// Default: false (no-op).
    fn has_any_applied_ops(&self, _sync_id: &str) -> Result<bool> {
        Ok(false)
    }

    /// Count entries in `device_registry` for this sync group.
    ///
    /// Used by the first-device bootstrap setup-only guard: `== 1` proves
    /// this device is the sole registered device.
    ///
    /// Default: 0 (no-op).
    fn count_devices_in_group(&self, _sync_id: &str) -> Result<usize> {
        Ok(0)
    }
}

/// Transactional operations on sync storage — obtained from `SyncStorage::begin_tx()`.
///
/// This is a separate trait from `SyncStorage` so that:
/// 1. `SyncStorage` stays object-safe (no generic methods)
/// 2. Transaction handles have clear ownership (no mutex self-deadlock)
/// 3. Commit/rollback semantics are explicit
///
/// The rusqlite implementation wraps a real `rusqlite::Transaction`.
pub trait SyncStorageTx {
    // ── Reads (needed by merge engine within a transaction) ──
    fn is_op_applied(&self, op_id: &str) -> Result<bool>;
    fn get_field_version(
        &self,
        sync_id: &str,
        table: &str,
        entity_id: &str,
        field: &str,
    ) -> Result<Option<FieldVersion>>;
    fn get_device_record(&self, sync_id: &str, device_id: &str) -> Result<Option<DeviceRecord>>;

    // ── Sync metadata ──
    fn upsert_sync_metadata(&mut self, meta: &SyncMetadata) -> Result<()>;
    fn update_last_pulled_seq(&mut self, sync_id: &str, seq: i64) -> Result<()>;
    fn update_last_successful_sync(&mut self, sync_id: &str) -> Result<()>;
    fn update_current_epoch(&mut self, sync_id: &str, epoch: i32) -> Result<()>;
    fn update_last_imported_registry_version(&mut self, sync_id: &str, version: i64) -> Result<()>;

    // ── Pending ops ──
    fn insert_pending_op(&mut self, op: &PendingOp) -> Result<()>;
    fn mark_batch_pushed(&mut self, batch_id: &str) -> Result<()>;
    fn delete_pushed_ops(&mut self, sync_id: &str, batch_id: &str) -> Result<()>;

    /// Load all `pending_ops` rows whose `local_batch_id` matches `batch_id`,
    /// inside the current transaction. Used by Phase 1C recovery to enumerate
    /// the ops in a quarantined batch before repartitioning them.
    ///
    /// Returns an empty vector if no rows match.
    ///
    /// Default: empty (no-op for in-memory impls).
    fn load_batch_ops(&self, _batch_id: &str) -> Result<Vec<PendingOp>> {
        Ok(vec![])
    }

    /// Rewrite the `local_batch_id` of a single `pending_ops` row identified
    /// by `op_id`. Every other column on the row (`op_id`, `client_hlc`,
    /// `device_id`, `epoch`, `encoded_value`, `created_at`, `entity_table`,
    /// `entity_id`, `field_name`, `is_delete`, `pushed_at`) must be preserved
    /// exactly — Phase 1C repair MUST NOT alter CRDT-bearing fields.
    ///
    /// Returns an error if the row does not exist or the update affected
    /// zero rows.
    ///
    /// Default: no-op for in-memory impls.
    fn update_pending_op_batch_id(&mut self, _op_id: &str, _new_batch_id: &str) -> Result<()> {
        Ok(())
    }

    // ── Applied ops ──
    fn insert_applied_op(&mut self, op: &AppliedOp) -> Result<()>;

    // ── Field versions ──
    fn upsert_field_version(&mut self, fv: &FieldVersion) -> Result<()>;

    // ── Quarantined remote ops ──
    fn insert_quarantined_op(&mut self, _op: &QuarantinedOp) -> Result<()> {
        Ok(())
    }
    fn delete_quarantined_op(&mut self, _sync_id: &str, _op_id: &str) -> Result<()> {
        Ok(())
    }

    // ── Quarantined local push batches ──

    /// Insert (or replace) a row recording that a local batch was quarantined
    /// because its envelope exceeded the relay body cap. The impl sets
    /// `quarantined_at` to `Utc::now().to_rfc3339()`.
    ///
    /// Default: no-op for in-memory impls.
    #[allow(clippy::too_many_arguments)]
    fn quarantine_batch(
        &mut self,
        _sync_id: &str,
        _batch_id: &str,
        _entity_table: &str,
        _entity_id: &str,
        _body_bytes: i64,
        _error_code: &str,
        _error_message: &str,
    ) -> Result<()> {
        Ok(())
    }

    /// Remove the quarantine row for a batch. Used by Phase 1C recovery
    /// after the batch's ops are repartitioned into smaller sub-batches.
    /// Default: no-op for in-memory impls.
    fn unquarantine_batch(&mut self, _sync_id: &str, _batch_id: &str) -> Result<()> {
        Ok(())
    }

    // ── Device registry ──
    fn upsert_device_record(&mut self, device: &DeviceRecord) -> Result<()>;
    fn remove_device_record(&mut self, sync_id: &str, device_id: &str) -> Result<()>;

    // ── Cleanup ──
    fn clear_sync_state(&mut self, sync_id: &str) -> Result<()>;

    // ── Pruning writes (default no-op implementations) ──

    /// Delete up to `limit` applied_ops rows with server_seq < below_seq.
    /// Returns the number of rows deleted. Default: 0 (no-op).
    fn delete_applied_ops_below_seq(
        &mut self,
        _sync_id: &str,
        _below_seq: i64,
        _limit: usize,
    ) -> Result<usize> {
        Ok(0)
    }

    /// Delete all field_versions rows for a specific entity.
    /// Used when hard-deleting a tombstoned entity. Default: no-op.
    fn delete_field_versions_for_entity(
        &mut self,
        _sync_id: &str,
        _table: &str,
        _entity_id: &str,
    ) -> Result<()> {
        Ok(())
    }

    /// Delete non-tombstone field_versions rows for a specific entity.
    /// Used when hard-deleting a tombstoned entity while preserving the
    /// `is_deleted` row that prevents stale ops from resurrecting it.
    /// Returns the number of rows deleted. Default: 0 (no-op).
    fn delete_non_tombstone_field_versions_for_entity(
        &mut self,
        _sync_id: &str,
        _table: &str,
        _entity_id: &str,
    ) -> Result<usize> {
        Ok(0)
    }

    /// Import sync state from a snapshot blob (zstd-compressed JSON).
    /// Returns the number of unique entities restored.
    fn import_snapshot(&mut self, sync_id: &str, data: &[u8]) -> Result<u64>;

    // ── Transaction lifecycle ──
    fn commit(self: Box<Self>) -> Result<()>;
    fn rollback(self: Box<Self>) -> Result<()>;
}
