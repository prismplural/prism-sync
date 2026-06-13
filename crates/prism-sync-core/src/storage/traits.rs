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

    /// List remote batches durably quarantined after a deterministic pull-side
    /// failure, ordered by `server_seq` ascending. Phase 0b replay walks this
    /// list and re-runs the full pipeline per envelope.
    ///
    /// Default: empty (no-op for in-memory impls).
    fn list_quarantined_pull_batches(
        &self,
        _sync_id: &str,
    ) -> Result<Vec<QuarantinedPullBatch>> {
        Ok(vec![])
    }

    /// List the current pull-stall budget rows for this sync group, ordered by
    /// `server_seq` ascending. Default: empty (no-op for in-memory impls).
    fn list_pull_stalls(&self, _sync_id: &str) -> Result<Vec<PullStall>> {
        Ok(vec![])
    }

    /// List up to `limit` undrained consumer-delivery journal rows for this sync
    /// group with `id > after_id`, ordered by `id` ascending. The drain walks
    /// the journal in `id` order; `after_id = 0` returns from the start. Returns
    /// at most `limit` rows (the chunk the Dart drain applies before acking).
    ///
    /// Default: empty (no-op for in-memory impls).
    fn list_consumer_deliveries(
        &self,
        _sync_id: &str,
        _after_id: i64,
        _limit: i64,
    ) -> Result<Vec<ConsumerDelivery>> {
        Ok(vec![])
    }

    /// Count the consumer-delivery journal rows for this sync group. Used by the
    /// retention cap to decide whether the oldest rows must spill into the Dart
    /// quarantine lane. Default: 0 (no-op for in-memory impls).
    fn count_consumer_deliveries(&self, _sync_id: &str) -> Result<i64> {
        Ok(0)
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

    /// Look up an archived ML-DSA verification key for a device at an exact
    /// generation. Returns the superseded public key bytes if a rotation past
    /// that generation has been imported, or `None` if no such history exists
    /// (the generation is current, never-seen, or unrotated). Used by the pull
    /// path so a straggling pre-rotation batch verifies against the key it
    /// was signed with rather than being dropped once the receiver learns the
    /// rotated key.
    ///
    /// Default: `None` (no-op for in-memory impls).
    fn get_archived_device_key(
        &self,
        _sync_id: &str,
        _device_id: &str,
        _ml_dsa_key_generation: u32,
    ) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }

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

    /// List the `field_versions` rows this device authored whose winning HLC
    /// is more than `bound_ms` ahead of wall-clock now.
    ///
    /// Used by the relay-anchored clock-excursion repair to find the
    /// self-authored winners a forward clock step poisoned. The HLC is parsed
    /// in Rust because the TEXT encoding is unpadded (`":9"` sorts after
    /// `":10"`), so a SQL comparison would be wrong; the drift filter applies
    /// `clock_drift::is_excessively_future` against a single captured `now`.
    ///
    /// Default: empty (no-op).
    fn list_self_authored_future_fv(
        &self,
        _sync_id: &str,
        _device_id: &str,
        _bound_ms: i64,
    ) -> Result<Vec<FieldVersion>> {
        Ok(vec![])
    }

    /// Delete this device's UNPUSHED `pending_ops` whose `client_hlc` is more
    /// than `bound_ms` ahead of wall-clock now, transactionally. Returns the
    /// number of rows deleted.
    ///
    /// Used by the clock-excursion repair: a poisoned future op is safe to drop
    /// because its `field_versions` winner is itself self-authored and
    /// over-bound, and the repair re-emits that winner at a sane HLC. Only
    /// unpushed rows are touched — an already-pushed op is on a peer's log and
    /// out of scope. The
    /// HLC is parsed in Rust for the same unpadded-encoding reason as
    /// [`list_self_authored_future_fv`].
    ///
    /// Default: 0 (no-op).
    fn delete_unpushed_future_pending_ops(
        &self,
        _sync_id: &str,
        _device_id: &str,
        _bound_ms: i64,
    ) -> Result<usize> {
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
    /// Advance the pull cursor **monotonically**: stores
    /// `MAX(last_pulled_server_seq, seq)`, never rewinds. Quarantine replay
    /// (Phase 0b) re-applies past batches without their `server_seq`, so it must
    /// never be able to pull the cursor backwards. Legitimate rewinds (bootstrap,
    /// relay-log lineage reset) go through [`reset_last_pulled_seq`] instead.
    ///
    /// [`reset_last_pulled_seq`]: Self::reset_last_pulled_seq
    fn update_last_pulled_seq(&mut self, sync_id: &str, seq: i64) -> Result<()>;
    /// Explicitly set the pull cursor to `seq`, allowing a rewind. The escape
    /// hatch for legitimate resets — first-device bootstrap and the
    /// relay-log lineage change — where the cursor must move backwards because
    /// the server-seq space itself changed. Distinct from
    /// [`update_last_pulled_seq`]'s MAX-monotonic semantics so a reset cannot be
    /// silently no-op'd by a higher stored value.
    ///
    /// [`update_last_pulled_seq`]: Self::update_last_pulled_seq
    fn reset_last_pulled_seq(&mut self, sync_id: &str, seq: i64) -> Result<()>;
    /// Record the relay log-lineage token observed for this group. Set when
    /// a lineage-aware relay first reports a `log_token`, and overwritten on a
    /// detected lineage change (alongside a cursor reset). Device-local.
    fn update_relay_log_token(&mut self, sync_id: &str, token: &str) -> Result<()>;
    /// Forget the stored lineage token (set NULL). Used by the
    /// `cursor_ahead_of_log` recovery — whose 409 carries no token — so the
    /// follow-up pull's token is adopted fresh rather than re-detected as a
    /// mismatch and double-counted as a second lineage trip. Default: no-op.
    fn clear_relay_log_token(&mut self, _sync_id: &str) -> Result<()> {
        Ok(())
    }
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

    /// Delete a single `pending_ops` row by `op_id`. Used by Phase 1C repair to
    /// drop an op the field has moved past (a newer write for the same field
    /// won LWW) — pushing it would only re-quarantine. Default: no-op for
    /// in-memory impls.
    fn delete_pending_op(&mut self, _op_id: &str) -> Result<()> {
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

    // ── Consumer delivery journal ──

    /// Append one winning op to the durable consumer-delivery journal. MUST be
    /// called in the SAME transaction as the Phase C bookkeeping / snapshot
    /// import that committed the op to engine state, so the Rust cursor and the
    /// journal advance atomically — a pulled winner is then delivered
    /// at-least-once across process death. The impl assigns the AUTOINCREMENT
    /// `id` (the passed `delivery.id` is ignored on insert).
    /// Default: no-op for in-memory impls.
    fn insert_consumer_delivery(&mut self, _delivery: &ConsumerDelivery) -> Result<()> {
        Ok(())
    }

    /// Delete every consumer-delivery row with `id <= up_to_id` for this sync
    /// group — the Dart drain's ack, fired only AFTER its own consumer-DB
    /// transaction (apply or durable quarantine) commits. Default: no-op.
    fn delete_consumer_deliveries_up_to(&mut self, _sync_id: &str, _up_to_id: i64) -> Result<()> {
        Ok(())
    }

    // ── Quarantined remote pull batches (replayable) ──

    /// Insert (upsert) a quarantined pull batch, keyed by
    /// `(sync_id, sender_device_id, batch_id)`. The impl serializes the envelope
    /// to JSON and stores `batch.quarantined_at` / `batch.retry_count` verbatim.
    /// Re-quarantining an existing batch (same sender + `batch_id`) must preserve
    /// its accumulated `retry_count` and original `quarantined_at` rather than
    /// reset them — the caller re-reads the row and re-inserts with the existing
    /// values, or uses [`bump_quarantined_pull_batch_retry`] for the retry path.
    /// The key includes `sender_device_id` so one sender's poison batch can never
    /// REPLACE another sender's durably-stored envelope at the same `batch_id`.
    /// Default: no-op for in-memory impls.
    ///
    /// [`bump_quarantined_pull_batch_retry`]: Self::bump_quarantined_pull_batch_retry
    fn insert_quarantined_pull_batch(&mut self, _batch: &QuarantinedPullBatch) -> Result<()> {
        Ok(())
    }

    /// Delete a quarantined pull batch (Phase 0b replay succeeded, or the sender
    /// was revoked and the batch is terminally discarded). Keyed by
    /// `(sync_id, sender_device_id, batch_id)`.
    /// Default: no-op for in-memory impls.
    fn delete_quarantined_pull_batch(
        &mut self,
        _sync_id: &str,
        _sender_device_id: &str,
        _batch_id: &str,
    ) -> Result<()> {
        Ok(())
    }

    /// Bump `retry_count` and stamp `last_retry_at = now` for a quarantined pull
    /// batch whose replay attempt failed identically. Used to back off so a
    /// permanently-unapplicable batch does not churn every cycle. Keyed by
    /// `(sync_id, sender_device_id, batch_id)`.
    /// Default: no-op for in-memory impls.
    fn bump_quarantined_pull_batch_retry(
        &mut self,
        _sync_id: &str,
        _sender_device_id: &str,
        _batch_id: &str,
    ) -> Result<()> {
        Ok(())
    }

    // ── Pull stall budget ──

    /// Record (or bump) a stall on `server_seq`. On first insert `attempts`
    /// starts at 1 and both timestamps are now; on conflict `attempts` is
    /// incremented, `reason` and `last_seen_at` refreshed, `first_seen_at`
    /// preserved. Default: no-op for in-memory impls.
    fn record_pull_stall(&mut self, _sync_id: &str, _server_seq: i64, _reason: &str) -> Result<()> {
        Ok(())
    }

    /// Clear the stall row for `server_seq` once it resolves (keys imported,
    /// batch applied or quarantined). Default: no-op for in-memory impls.
    fn clear_pull_stall(&mut self, _sync_id: &str, _server_seq: i64) -> Result<()> {
        Ok(())
    }

    /// Clear every stall row for the group. A relay-log
    /// lineage reset re-issues the server-seq space, so all stall rows (keyed by
    /// old-lineage seqs) are stale and must not survive the reset — a stale row
    /// past the wall-clock ceiling would quarantine-and-advance a re-issued seq on
    /// its first transient hiccup. Default: no-op for in-memory impls.
    fn clear_all_pull_stalls(&mut self, _sync_id: &str) -> Result<()> {
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

    /// Archive a superseded ML-DSA verification key so a pre-rotation batch can
    /// still be verified after the device record advanced to a higher generation.
    /// Idempotent (keyed on `(sync_id, device_id, generation)`); archiving
    /// the same generation twice keeps the first-archived key. Must be called in
    /// the SAME transaction as the rotating `upsert_device_record` so the new key
    /// and the archived old key commit atomically.
    ///
    /// Default: no-op for in-memory impls.
    fn archive_device_key(
        &mut self,
        _sync_id: &str,
        _device_id: &str,
        _ml_dsa_key_generation: u32,
        _ml_dsa_65_public_key: &[u8],
    ) -> Result<()> {
        Ok(())
    }

    /// Read an archived device key from within the transaction (the import path
    /// reads the existing record and archives in the same tx). Returns the
    /// superseded public-key bytes or `None`.
    ///
    /// Default: `None` for in-memory impls.
    fn get_archived_device_key(
        &self,
        _sync_id: &str,
        _device_id: &str,
        _ml_dsa_key_generation: u32,
    ) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }

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
