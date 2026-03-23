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

    // ── Pending ops ──
    fn insert_pending_op(&mut self, op: &PendingOp) -> Result<()>;
    fn mark_batch_pushed(&mut self, batch_id: &str) -> Result<()>;
    fn delete_pushed_ops(&mut self, sync_id: &str) -> Result<()>;

    // ── Applied ops ──
    fn insert_applied_op(&mut self, op: &AppliedOp) -> Result<()>;

    // ── Field versions ──
    fn upsert_field_version(&mut self, fv: &FieldVersion) -> Result<()>;

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

    /// Import sync state from a snapshot blob (zstd-compressed JSON).
    /// Returns the number of unique entities restored.
    fn import_snapshot(&mut self, sync_id: &str, data: &[u8]) -> Result<u64>;

    // ── Transaction lifecycle ──
    fn commit(self: Box<Self>) -> Result<()>;
    fn rollback(self: Box<Self>) -> Result<()>;
}
