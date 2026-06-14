use std::collections::HashMap;

use chrono::Utc;
use uuid::Uuid;

use crate::clock_drift::{is_excessively_future, MAX_CLOCK_DRIFT_MS};
use crate::error::{CoreError, Result};
use crate::hlc::Hlc;
use crate::schema::{encode_value, SyncValue};
use crate::storage::{FieldVersion, PendingOp, SyncStorage};

/// Constant field name used for delete tombstone ops.
pub const DELETED_FIELD: &str = "is_deleted";

/// Floor HLC timestamp (ms) for write-if-absent backfill ops: 2020-01-01.
///
/// Reconcile/backfill emission stamps never-synced fields at this constant so
/// they establish an entity on peers that lack it but lose LWW to any genuine
/// edit (every real op carries a ~now wall-clock HLC, far above this floor).
/// It sits above `Hlc::zero` (timestamp 0) so a backfill op still beats truly
/// empty state, and below any genuine op so it never reverts a real edit.
pub const BACKFILL_HLC_TIMESTAMP_MS: i64 = 1_577_836_800_000;

/// How [`OpEmitter::emit_reconcile_multi`] handles a field whose local Drift
/// value diverges from this device's `field_versions` winner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DivergentMode {
    /// Emit the divergent value at a fresh `tick()` HLC — treat the divergence
    /// as a genuine deferred local edit that should win as if made now.
    FreshHlc,
    /// Leave the divergent field alone (emit nothing). Pure backfill: only
    /// fields absent from `field_versions` are emitted, at the floor HLC.
    Skip,
}

/// Emit future-drift telemetry for an inherited watermark candidate.
///
/// The watermark is always inherited (monotonic max). A candidate more than
/// the drift bound ahead of wall clock is still inherited, but warned on: it
/// either reflects a local clock that regressed since the candidate was gated
/// in (benign, and inheritance is required for LWW) or a forward excursion
/// the relay-anchored repair will catch on the next validated sync cycle.
fn warn_if_future_drift(device_id: &str, hlc: &Hlc) {
    if is_excessively_future(hlc, Hlc::now_ms(), MAX_CLOCK_DRIFT_MS) {
        tracing::warn!(
            device_id = %device_id,
            incoming_node_id = %hlc.node_id,
            incoming_timestamp = hlc.timestamp,
            future_drift_ms = hlc.future_drift_ms(),
            "Inheriting future-drift HLC watermark for local emitter"
        );
    }
}

/// Records field-level ops into pending_ops at mutation time.
///
/// The caller is responsible for:
/// - Creating a `local_batch_id` (UUID v4) shared by all ops in one transaction
/// - Invoking `emit_create`, `emit_update`, or `emit_delete`
///
/// The OpEmitter ticks the HLC once per op-emitting call and stamps every op
/// in that invocation with the same HLC value, ensuring causal consistency
/// within a batch.
///
/// Ported from Dart `lib/core/sync/op_emitter.dart`.
pub struct OpEmitter {
    device_id: String,
    sync_id: String,
    epoch: i32,
    last_hlc: Hlc,
}

impl OpEmitter {
    pub fn new(device_id: String, sync_id: String, epoch: i32, last_hlc: Option<Hlc>) -> Self {
        let last_hlc = last_hlc.unwrap_or_else(|| Hlc::zero(&device_id));
        warn_if_future_drift(&device_id, &last_hlc);
        Self { device_id, sync_id, epoch, last_hlc }
    }

    /// The most recent HLC assigned by this emitter.
    pub fn last_hlc(&self) -> &Hlc {
        &self.last_hlc
    }

    /// The epoch currently stamped on emitted ops.
    pub fn epoch(&self) -> i32 {
        self.epoch
    }

    /// The sync group this emitter writes ops for.
    pub fn sync_id(&self) -> &str {
        &self.sync_id
    }

    /// Update the epoch used for new ops.
    pub fn set_epoch(&mut self, new_epoch: i32) {
        self.epoch = new_epoch;
    }

    /// Advance the emitter's HLC watermark. The next `tick()` will produce
    /// an HLC strictly greater than either `new_hlc` or the current
    /// wall-clock time, whichever is larger.
    ///
    /// Used after bootstrap/snapshot imports so locally minted HLCs never
    /// fall behind state that was seeded from an external source. Inheritance
    /// is unconditional (monotonic max only): every channel that writes a
    /// winner into `field_versions` — pull, snapshot import, local emit — is
    /// gated at entry against the writer's then-current clock, so a stored HLC
    /// that looks future at restart can only mean the local clock regressed
    /// since entry, which is exactly when inheritance is REQUIRED for LWW
    /// (the candidate is within the drift bound of real time, so emitted ops
    /// still pass every receiver's filter). A genuine forward excursion is
    /// caught instead by the relay-anchored repair. See [`crate::clock_drift`].
    pub fn set_last_hlc(&mut self, new_hlc: Hlc) {
        warn_if_future_drift(&self.device_id, &new_hlc);
        if new_hlc > self.last_hlc {
            self.last_hlc = new_hlc;
        }
    }

    /// Reset the watermark to wall-clock now, dropping a poisoned future HLC.
    ///
    /// Used only by the relay-anchored excursion repair: once a sync
    /// cycle has proved the local clock is within the drift bound of relay
    /// time, a watermark far in the future can only be a leftover forward
    /// clock excursion. `Hlc::try_now(device_id, None)` ignores `last_hlc`, so
    /// this is the one place the watermark is allowed to move backward — the
    /// next `tick()` then mints sane, peer-deliverable HLCs again.
    pub fn clamp_watermark_to_now(&mut self) -> Result<()> {
        self.last_hlc =
            Hlc::try_now(&self.device_id, None).map_err(|e| CoreError::Engine(e.to_string()))?;
        Ok(())
    }

    /// Tick the HLC once and return the new value.
    fn tick(&mut self) -> Result<Hlc> {
        let next_hlc = Hlc::try_now(&self.device_id, Some(&self.last_hlc))
            .map_err(|e| CoreError::Engine(e.to_string()))?;
        self.last_hlc = next_hlc.clone();
        Ok(next_hlc)
    }

    /// Emit ops for a newly created entity.
    ///
    /// Every entry in `fields` becomes one pending op row. All ops share the
    /// same HLC and `local_batch_id`.
    pub fn emit_create(
        &mut self,
        storage: &dyn SyncStorage,
        entity_table: &str,
        entity_id: &str,
        fields: &HashMap<String, SyncValue>,
        local_batch_id: &str,
    ) -> Result<()> {
        if fields.is_empty() {
            return Ok(());
        }

        let hlc = self.tick()?;
        let hlc_string = hlc.to_string();
        let now = Utc::now();

        let mut tx = storage.begin_tx()?;

        for (field_name, value) in fields {
            let op_id = Uuid::new_v4().to_string();
            let encoded = encode_value(value);

            tx.insert_pending_op(&PendingOp {
                op_id: op_id.clone(),
                sync_id: self.sync_id.clone(),
                epoch: self.epoch,
                device_id: self.device_id.clone(),
                local_batch_id: local_batch_id.to_string(),
                entity_table: entity_table.to_string(),
                entity_id: entity_id.to_string(),
                field_name: field_name.clone(),
                encoded_value: encoded.clone(),
                is_delete: false,
                client_hlc: hlc_string.clone(),
                created_at: now,
                pushed_at: None,
            })?;

            tx.upsert_field_version(&FieldVersion {
                sync_id: self.sync_id.clone(),
                entity_table: entity_table.to_string(),
                entity_id: entity_id.to_string(),
                field_name: field_name.clone(),
                winning_op_id: op_id,
                winning_device_id: self.device_id.clone(),
                winning_hlc: hlc_string.clone(),
                winning_encoded_value: Some(encoded),
                updated_at: now,
            })?;
        }

        tx.commit()?;

        tracing::debug!(
            table = entity_table,
            entity_id = entity_id,
            field_count = fields.len(),
            batch_id = local_batch_id,
            "Queued create ops"
        );

        Ok(())
    }

    /// Emit ops for a newly created entity, split across several batches.
    ///
    /// Each `(fields, batch_id)` partition becomes one logical batch of
    /// pending ops. The partitioner in `client.rs` builds the partition list
    /// to keep each batch's serialized envelope under the relay's 1 MB body
    /// cap. All partitions share **one** `storage.begin_tx()` transaction so
    /// the entire emission is atomic — a failure midway rolls back every
    /// partition, leaving no half-created entity in `pending_ops` /
    /// `field_versions`.
    ///
    /// HLC monotonicity: one `tick()` per partition. Partitions are emitted
    /// in the supplied order so the HLC values are deterministic; receivers
    /// merge by per-field LWW so per-partition HLCs do not need to be the
    /// same.
    ///
    /// Empty `fields` maps are skipped. If every partition is empty the call
    /// is a no-op (no transaction is opened).
    pub fn emit_create_multi(
        &mut self,
        storage: &dyn SyncStorage,
        entity_table: &str,
        entity_id: &str,
        partitions: &[(HashMap<String, SyncValue>, String)],
    ) -> Result<()> {
        self.emit_multi(storage, entity_table, entity_id, partitions, "create")
    }

    /// Emit ops for changed fields on an existing entity, split across
    /// several batches.
    ///
    /// See [`emit_create_multi`](Self::emit_create_multi) for the atomicity
    /// and HLC semantics. The same contract applies: every supplied
    /// partition commits together or none of them do.
    pub fn emit_update_multi(
        &mut self,
        storage: &dyn SyncStorage,
        entity_table: &str,
        entity_id: &str,
        partitions: &[(HashMap<String, SyncValue>, String)],
    ) -> Result<()> {
        self.emit_multi(storage, entity_table, entity_id, partitions, "update")
    }

    /// Shared implementation for `emit_create_multi` and `emit_update_multi`.
    /// `kind` is used only for trace logging — the on-wire op shape is the
    /// same in both directions.
    fn emit_multi(
        &mut self,
        storage: &dyn SyncStorage,
        entity_table: &str,
        entity_id: &str,
        partitions: &[(HashMap<String, SyncValue>, String)],
        kind: &'static str,
    ) -> Result<()> {
        // Skip partitions with no fields up front so we never open a tx for
        // an entirely empty emission.
        let non_empty: Vec<(&HashMap<String, SyncValue>, &str)> = partitions
            .iter()
            .filter(|(fields, _)| !fields.is_empty())
            .map(|(fields, batch_id)| (fields, batch_id.as_str()))
            .collect();
        if non_empty.is_empty() {
            return Ok(());
        }

        // Tick once per partition up front so a tick failure (HLC counter
        // overflow) is observed before we touch storage. `tick()` mutates
        // `self.last_hlc`, which we restore on rollback below.
        let saved_last_hlc = self.last_hlc.clone();
        let mut partition_hlcs: Vec<Hlc> = Vec::with_capacity(non_empty.len());
        for _ in 0..non_empty.len() {
            match self.tick() {
                Ok(hlc) => partition_hlcs.push(hlc),
                Err(e) => {
                    // Pre-storage failure: nothing was written. Restore the
                    // HLC watermark so the next emit attempts a clean tick.
                    self.last_hlc = saved_last_hlc;
                    return Err(e);
                }
            }
        }

        // Offset each partition's `created_at` by its index in microseconds so
        // the push-side query (`get_unpushed_batch_ids`) — which orders only by
        // `MIN(created_at) ASC` — yields a deterministic partition order. SQL
        // `ORDER BY` is non-deterministic on ties, so without this offset two
        // partitions stamped with the same `Utc::now()` could push out of order
        // and break invariants like "small-fields partition pushes first so
        // receivers can insert the entity row before large-field updates".
        // Rows within a single partition still share an identical timestamp,
        // preserving the existing same-batch invariants used elsewhere.
        let base_now = Utc::now();
        let mut tx = match storage.begin_tx() {
            Ok(tx) => tx,
            Err(e) => {
                // begin_tx failed after we already advanced the HLC. Restore
                // the watermark so the next call doesn't observe a phantom
                // advance.
                self.last_hlc = saved_last_hlc;
                return Err(e);
            }
        };

        // Track the total field count across partitions for the trace log.
        let mut total_field_count = 0usize;

        for (partition_index, ((fields, batch_id), hlc)) in
            non_empty.iter().zip(partition_hlcs.iter()).enumerate()
        {
            let hlc_string = hlc.to_string();
            let partition_now = base_now + chrono::Duration::microseconds(partition_index as i64);

            for (field_name, value) in *fields {
                let op_id = Uuid::new_v4().to_string();
                let encoded = encode_value(value);

                if let Err(e) = tx.insert_pending_op(&PendingOp {
                    op_id: op_id.clone(),
                    sync_id: self.sync_id.clone(),
                    epoch: self.epoch,
                    device_id: self.device_id.clone(),
                    local_batch_id: (*batch_id).to_string(),
                    entity_table: entity_table.to_string(),
                    entity_id: entity_id.to_string(),
                    field_name: field_name.clone(),
                    encoded_value: encoded.clone(),
                    is_delete: false,
                    client_hlc: hlc_string.clone(),
                    created_at: partition_now,
                    pushed_at: None,
                }) {
                    let _ = tx.rollback();
                    self.last_hlc = saved_last_hlc;
                    return Err(e);
                }

                if let Err(e) = tx.upsert_field_version(&FieldVersion {
                    sync_id: self.sync_id.clone(),
                    entity_table: entity_table.to_string(),
                    entity_id: entity_id.to_string(),
                    field_name: field_name.clone(),
                    winning_op_id: op_id,
                    winning_device_id: self.device_id.clone(),
                    winning_hlc: hlc_string.clone(),
                    winning_encoded_value: Some(encoded),
                    updated_at: partition_now,
                }) {
                    let _ = tx.rollback();
                    self.last_hlc = saved_last_hlc;
                    return Err(e);
                }

                total_field_count += 1;
            }
        }

        if let Err(e) = tx.commit() {
            // commit() consumes `tx`, so we cannot call rollback() here;
            // SQLite will already have rolled back its open transaction on
            // commit failure. Restore the HLC watermark so the next caller
            // doesn't observe a phantom advance.
            self.last_hlc = saved_last_hlc;
            return Err(e);
        }

        tracing::debug!(
            table = entity_table,
            entity_id = entity_id,
            partition_count = non_empty.len(),
            field_count = total_field_count,
            kind = kind,
            "Queued multi-batch ops"
        );

        Ok(())
    }

    /// Emit ops for changed fields on an existing entity.
    ///
    /// Only the fields that actually changed should be passed in
    /// `changed_fields`. Each becomes one pending op row.
    pub fn emit_update(
        &mut self,
        storage: &dyn SyncStorage,
        entity_table: &str,
        entity_id: &str,
        changed_fields: &HashMap<String, SyncValue>,
        local_batch_id: &str,
    ) -> Result<()> {
        if changed_fields.is_empty() {
            return Ok(());
        }

        let hlc = self.tick()?;
        let hlc_string = hlc.to_string();
        let now = Utc::now();

        let mut tx = storage.begin_tx()?;

        for (field_name, value) in changed_fields {
            let op_id = Uuid::new_v4().to_string();
            let encoded = encode_value(value);

            tx.insert_pending_op(&PendingOp {
                op_id: op_id.clone(),
                sync_id: self.sync_id.clone(),
                epoch: self.epoch,
                device_id: self.device_id.clone(),
                local_batch_id: local_batch_id.to_string(),
                entity_table: entity_table.to_string(),
                entity_id: entity_id.to_string(),
                field_name: field_name.clone(),
                encoded_value: encoded.clone(),
                is_delete: false,
                client_hlc: hlc_string.clone(),
                created_at: now,
                pushed_at: None,
            })?;

            tx.upsert_field_version(&FieldVersion {
                sync_id: self.sync_id.clone(),
                entity_table: entity_table.to_string(),
                entity_id: entity_id.to_string(),
                field_name: field_name.clone(),
                winning_op_id: op_id,
                winning_device_id: self.device_id.clone(),
                winning_hlc: hlc_string.clone(),
                winning_encoded_value: Some(encoded),
                updated_at: now,
            })?;
        }

        tx.commit()?;

        tracing::debug!(
            table = entity_table,
            entity_id = entity_id,
            field_count = changed_fields.len(),
            batch_id = local_batch_id,
            "Queued update ops"
        );

        Ok(())
    }

    /// Populate `field_versions` for an entity without emitting a `pending_op`.
    ///
    /// Used exclusively by the first-device bootstrap path to reconstruct
    /// CRDT state from pre-existing local data. Callers MUST guarantee the
    /// resulting state should not be pushed to the relay — there is no
    /// legitimate code path that mixes seeded rows with normal mutations,
    /// because bootstrap runs before first sync on the first device.
    ///
    /// Semantics: identical to `emit_create` except that we skip
    /// `insert_pending_op`. We still tick the HLC once and stamp every
    /// field in this invocation with that HLC, and we still upsert one
    /// `field_versions` row per field. Writes happen inside a single
    /// `BEGIN IMMEDIATE` transaction.
    #[allow(dead_code)] // Wired into `client::bootstrap_existing_state` by a follow-up patch.
    pub(crate) fn seed_fields(
        &mut self,
        storage: &dyn SyncStorage,
        entity_table: &str,
        entity_id: &str,
        fields: &HashMap<String, SyncValue>,
    ) -> Result<()> {
        if fields.is_empty() {
            return Ok(());
        }

        let hlc = self.tick()?;
        let hlc_string = hlc.to_string();
        let now = Utc::now();

        let mut tx = storage.begin_tx()?;

        for (field_name, value) in fields {
            // Never seed a phantom `is_deleted = false`: write-once-true, or it
            // could ride this device's bootstrap snapshot and beat a peer's
            // tombstone. Absence already reads as live.
            if field_name == DELETED_FIELD && matches!(value, SyncValue::Bool(false)) {
                continue;
            }

            let op_id = Uuid::new_v4().to_string();
            let encoded = encode_value(value);

            tx.upsert_field_version(&FieldVersion {
                sync_id: self.sync_id.clone(),
                entity_table: entity_table.to_string(),
                entity_id: entity_id.to_string(),
                field_name: field_name.clone(),
                winning_op_id: op_id,
                winning_device_id: self.device_id.clone(),
                winning_hlc: hlc_string.clone(),
                winning_encoded_value: Some(encoded),
                updated_at: now,
            })?;
        }

        tx.commit()?;

        tracing::debug!(
            table = entity_table,
            entity_id = entity_id,
            field_count = fields.len(),
            "Seeded field_versions for bootstrap"
        );

        Ok(())
    }

    /// Emit a tombstone op for a soft-deleted entity.
    ///
    /// Creates a single op with `field_name = "is_deleted"` and
    /// `encoded_value = "true"`.
    pub fn emit_delete(
        &mut self,
        storage: &dyn SyncStorage,
        entity_table: &str,
        entity_id: &str,
        local_batch_id: &str,
    ) -> Result<()> {
        let hlc = self.tick()?;
        let hlc_string = hlc.to_string();
        let now = Utc::now();
        let op_id = Uuid::new_v4().to_string();

        let mut tx = storage.begin_tx()?;

        tx.insert_pending_op(&PendingOp {
            op_id: op_id.clone(),
            sync_id: self.sync_id.clone(),
            epoch: self.epoch,
            device_id: self.device_id.clone(),
            local_batch_id: local_batch_id.to_string(),
            entity_table: entity_table.to_string(),
            entity_id: entity_id.to_string(),
            field_name: DELETED_FIELD.to_string(),
            encoded_value: "true".to_string(),
            is_delete: true,
            client_hlc: hlc_string.clone(),
            created_at: now,
            pushed_at: None,
        })?;

        tx.upsert_field_version(&FieldVersion {
            sync_id: self.sync_id.clone(),
            entity_table: entity_table.to_string(),
            entity_id: entity_id.to_string(),
            field_name: DELETED_FIELD.to_string(),
            winning_op_id: op_id,
            winning_device_id: self.device_id.clone(),
            winning_hlc: hlc_string,
            winning_encoded_value: Some("true".to_string()),
            updated_at: now,
        })?;

        tx.commit()?;

        tracing::debug!(
            table = entity_table,
            entity_id = entity_id,
            batch_id = local_batch_id,
            "Queued delete op"
        );

        Ok(())
    }

    /// Emit delete tombstones for many entities at once, packed into the
    /// supplied batches. Each partition is `(entity_ids, batch_id)`; all ops in
    /// a partition share one HLC tick and the batch id, so the push phase sends
    /// them as a single batch with many tombstone ops instead of one batch per
    /// row. All partitions commit in one transaction — together or not at all.
    pub fn emit_delete_multi(
        &mut self,
        storage: &dyn SyncStorage,
        entity_table: &str,
        partitions: &[(Vec<String>, String)],
    ) -> Result<()> {
        let non_empty: Vec<(&[String], &str)> = partitions
            .iter()
            .filter(|(ids, _)| !ids.is_empty())
            .map(|(ids, batch_id)| (ids.as_slice(), batch_id.as_str()))
            .collect();
        if non_empty.is_empty() {
            return Ok(());
        }

        // Tick once per partition up front so an HLC overflow is observed
        // before we touch storage; restore the watermark on any failure.
        let saved_last_hlc = self.last_hlc.clone();
        let mut partition_hlcs: Vec<Hlc> = Vec::with_capacity(non_empty.len());
        for _ in 0..non_empty.len() {
            match self.tick() {
                Ok(hlc) => partition_hlcs.push(hlc),
                Err(e) => {
                    self.last_hlc = saved_last_hlc;
                    return Err(e);
                }
            }
        }

        // Offset each partition's `created_at` by its index (microseconds) so
        // `get_unpushed_batch_ids` (which orders by MIN(created_at)) yields a
        // deterministic batch order, matching `emit_multi`.
        let base_now = Utc::now();
        let mut tx = match storage.begin_tx() {
            Ok(tx) => tx,
            Err(e) => {
                self.last_hlc = saved_last_hlc;
                return Err(e);
            }
        };

        let mut total_delete_count = 0usize;
        for (partition_index, ((entity_ids, batch_id), hlc)) in
            non_empty.iter().zip(partition_hlcs.iter()).enumerate()
        {
            let hlc_string = hlc.to_string();
            let partition_now = base_now + chrono::Duration::microseconds(partition_index as i64);

            for entity_id in *entity_ids {
                let op_id = Uuid::new_v4().to_string();

                if let Err(e) = tx.insert_pending_op(&PendingOp {
                    op_id: op_id.clone(),
                    sync_id: self.sync_id.clone(),
                    epoch: self.epoch,
                    device_id: self.device_id.clone(),
                    local_batch_id: (*batch_id).to_string(),
                    entity_table: entity_table.to_string(),
                    entity_id: entity_id.clone(),
                    field_name: DELETED_FIELD.to_string(),
                    encoded_value: "true".to_string(),
                    is_delete: true,
                    client_hlc: hlc_string.clone(),
                    created_at: partition_now,
                    pushed_at: None,
                }) {
                    let _ = tx.rollback();
                    self.last_hlc = saved_last_hlc;
                    return Err(e);
                }

                if let Err(e) = tx.upsert_field_version(&FieldVersion {
                    sync_id: self.sync_id.clone(),
                    entity_table: entity_table.to_string(),
                    entity_id: entity_id.clone(),
                    field_name: DELETED_FIELD.to_string(),
                    winning_op_id: op_id,
                    winning_device_id: self.device_id.clone(),
                    winning_hlc: hlc_string.clone(),
                    winning_encoded_value: Some("true".to_string()),
                    updated_at: partition_now,
                }) {
                    let _ = tx.rollback();
                    self.last_hlc = saved_last_hlc;
                    return Err(e);
                }

                total_delete_count += 1;
            }
        }

        if let Err(e) = tx.commit() {
            self.last_hlc = saved_last_hlc;
            return Err(e);
        }

        tracing::debug!(
            table = entity_table,
            partition_count = non_empty.len(),
            delete_count = total_delete_count,
            "Queued multi-batch deletes"
        );

        Ok(())
    }

    /// Mint an HLC stamped at `origin_ms` (clamped to the legal range) WITHOUT
    /// advancing the emitter watermark.
    ///
    /// The HLC's timestamp is clamped to `BACKFILL_HLC_TIMESTAMP_MS + 1 ..=
    /// now_ms()` so a replayed op can never claim to be from the future (which a
    /// near-future receiver would accept and let win), nor sink to/below the
    /// backfill floor (reserved for write-if-absent). The counter is a fresh
    /// `tick()`-equivalent against the watermark so two ops minted at the same
    /// origin within one batch stay distinguishable, and `node_id` stays local
    /// so `validate_attribution` on the receiver passes.
    ///
    /// `last_hlc` is deliberately NOT advanced: emitting below the watermark is
    /// already legal (offline `pending_ops` carry old `client_hlc`), and a
    /// replay must not push the live clock forward to the replayed value.
    pub fn mint_hlc_at(&self, origin_ms: i64) -> Hlc {
        let ceiling = Hlc::now_ms();
        let floor = BACKFILL_HLC_TIMESTAMP_MS + 1;
        let timestamp = origin_ms.clamp(floor, ceiling.max(floor));
        // Share the watermark's counter space when the origin lands on the
        // same millisecond, so ops minted back-to-back at one origin don't
        // collide; otherwise reset to 0. We never mutate `self.last_hlc`.
        let counter = if self.last_hlc.timestamp == timestamp {
            self.last_hlc.counter.saturating_add(1)
        } else {
            0
        };
        Hlc::new(timestamp, counter, self.device_id.clone())
    }

    /// Reconcile `fields` against this device's `field_versions`, emitting only
    /// what genuinely diverges — never a value the device already agrees with.
    ///
    /// Inside ONE storage transaction, per field:
    /// - value-equal to the local winner → skip (no op, no FV write); this is
    ///   the load-bearing change that stops re-broadcast from clobbering a
    ///   peer's un-pulled newer edit on an unchanged field.
    /// - no `field_versions` row (never synced) → emit `pending_op` + FV at the
    ///   floor backfill HLC; establishes the entity on peers that lack it but
    ///   loses to any existing state.
    /// - row present but value differs → per `divergent_mode`: `FreshHlc` emits
    ///   at a fresh `tick()` (a genuine deferred edit), `Skip` emits nothing.
    ///
    /// Field-versions are upserted only for the fields that actually emit. The
    /// `is_deleted = false` phantom-undelete strip is the caller's job (done in
    /// `client.rs` against the conditional `without_phantom_undelete`).
    pub fn emit_reconcile_multi(
        &mut self,
        storage: &dyn SyncStorage,
        entity_table: &str,
        entity_id: &str,
        fields: &HashMap<String, SyncValue>,
        divergent_mode: DivergentMode,
        local_batch_id: &str,
    ) -> Result<()> {
        if fields.is_empty() {
            return Ok(());
        }

        // Classify every field against field_versions before opening the write
        // transaction. Each field carries the HLC it should emit at, so the
        // fresh-tick path can advance the watermark deterministically.
        enum Plan {
            Floor,
            Fresh,
        }
        let mut plans: Vec<(&String, &SyncValue, String, Plan)> = Vec::new();
        for (field_name, value) in fields {
            let encoded = encode_value(value);
            match storage.get_field_version(&self.sync_id, entity_table, entity_id, field_name)? {
                None => plans.push((field_name, value, encoded, Plan::Floor)),
                Some(fv) => {
                    if fv.winning_encoded_value.as_deref() == Some(encoded.as_str()) {
                        // Value-equal: this device already agrees with its
                        // winner — emitting would only risk clobbering a peer.
                        continue;
                    }
                    match divergent_mode {
                        DivergentMode::FreshHlc => {
                            plans.push((field_name, value, encoded, Plan::Fresh))
                        }
                        DivergentMode::Skip => continue,
                    }
                }
            }
        }

        if plans.is_empty() {
            return Ok(());
        }

        // Pre-mint HLCs so a fresh-tick overflow is observed before any write,
        // restoring the watermark on failure (mirrors `emit_multi`).
        let saved_last_hlc = self.last_hlc.clone();
        let floor_hlc = Hlc::new(
            BACKFILL_HLC_TIMESTAMP_MS,
            0,
            self.device_id.clone(),
        );
        let mut stamped: Vec<(&String, &SyncValue, String, Hlc)> = Vec::with_capacity(plans.len());
        for (field_name, value, encoded, plan) in plans {
            let hlc = match plan {
                Plan::Floor => floor_hlc.clone(),
                Plan::Fresh => match self.tick() {
                    Ok(h) => h,
                    Err(e) => {
                        self.last_hlc = saved_last_hlc;
                        return Err(e);
                    }
                },
            };
            stamped.push((field_name, value, encoded, hlc));
        }

        let now = Utc::now();
        let mut tx = match storage.begin_tx() {
            Ok(tx) => tx,
            Err(e) => {
                self.last_hlc = saved_last_hlc;
                return Err(e);
            }
        };

        for (field_name, _value, encoded, hlc) in &stamped {
            let op_id = Uuid::new_v4().to_string();
            let hlc_string = hlc.to_string();
            let is_delete = field_name.as_str() == DELETED_FIELD && encoded == "true";

            if let Err(e) = tx.insert_pending_op(&PendingOp {
                op_id: op_id.clone(),
                sync_id: self.sync_id.clone(),
                epoch: self.epoch,
                device_id: self.device_id.clone(),
                local_batch_id: local_batch_id.to_string(),
                entity_table: entity_table.to_string(),
                entity_id: entity_id.to_string(),
                field_name: (*field_name).clone(),
                encoded_value: encoded.clone(),
                is_delete,
                client_hlc: hlc_string.clone(),
                created_at: now,
                pushed_at: None,
            }) {
                let _ = tx.rollback();
                self.last_hlc = saved_last_hlc;
                return Err(e);
            }

            // Guard the field_versions write: a floor/diverging op must never
            // regress a newer local winner. The pending_op still pushed (above)
            // so peers merge it and reject it under the same rule.
            if let Err(e) = Self::upsert_field_version_if_wins(
                &mut *tx,
                &self.sync_id,
                entity_table,
                entity_id,
                field_name,
                &op_id,
                &self.device_id,
                hlc,
                encoded,
                now,
            ) {
                let _ = tx.rollback();
                self.last_hlc = saved_last_hlc;
                return Err(e);
            }
        }

        if let Err(e) = tx.commit() {
            self.last_hlc = saved_last_hlc;
            return Err(e);
        }

        tracing::debug!(
            table = entity_table,
            entity_id = entity_id,
            field_count = stamped.len(),
            mode = ?divergent_mode,
            "Queued reconcile ops"
        );

        Ok(())
    }

    /// Like [`emit_create_multi`](Self::emit_create_multi) but stamps every
    /// partition at `origin_ms` via [`mint_hlc_at`](Self::mint_hlc_at) and
    /// guards each `field_versions` upsert with `wins_over` — a replay of an
    /// old captured op never advances the watermark nor regresses a newer local
    /// winner. The `pending_op` is always inserted so peers merge and reject it.
    pub fn emit_create_multi_at(
        &mut self,
        storage: &dyn SyncStorage,
        entity_table: &str,
        entity_id: &str,
        partitions: &[(HashMap<String, SyncValue>, String)],
        origin_ms: i64,
    ) -> Result<()> {
        self.emit_multi_at(storage, entity_table, entity_id, partitions, origin_ms, "create")
    }

    /// Update variant of [`emit_create_multi_at`](Self::emit_create_multi_at).
    pub fn emit_update_multi_at(
        &mut self,
        storage: &dyn SyncStorage,
        entity_table: &str,
        entity_id: &str,
        partitions: &[(HashMap<String, SyncValue>, String)],
        origin_ms: i64,
    ) -> Result<()> {
        self.emit_multi_at(storage, entity_table, entity_id, partitions, origin_ms, "update")
    }

    /// Shared implementation for the origin-stamped create/update variants.
    fn emit_multi_at(
        &mut self,
        storage: &dyn SyncStorage,
        entity_table: &str,
        entity_id: &str,
        partitions: &[(HashMap<String, SyncValue>, String)],
        origin_ms: i64,
        kind: &'static str,
    ) -> Result<()> {
        let non_empty: Vec<(&HashMap<String, SyncValue>, &str)> = partitions
            .iter()
            .filter(|(fields, _)| !fields.is_empty())
            .map(|(fields, batch_id)| (fields, batch_id.as_str()))
            .collect();
        if non_empty.is_empty() {
            return Ok(());
        }

        // One HLC per partition stamped at the same clamped origin, counters
        // incrementing so partitions stay distinguishable. `mint_hlc_at` does
        // not touch the watermark, so there is nothing to restore on failure.
        let base = self.mint_hlc_at(origin_ms);
        let mut partition_hlcs: Vec<Hlc> = Vec::with_capacity(non_empty.len());
        for index in 0..non_empty.len() {
            let counter = base.counter.checked_add(index as u32).ok_or_else(|| {
                CoreError::Engine(format!(
                    "HLC counter overflow stamping origin batch for {entity_table}/{entity_id}"
                ))
            })?;
            partition_hlcs.push(Hlc::new(base.timestamp, counter, self.device_id.clone()));
        }

        let base_now = Utc::now();
        let mut tx = storage.begin_tx()?;
        let mut total_field_count = 0usize;

        for (partition_index, ((fields, batch_id), hlc)) in
            non_empty.iter().zip(partition_hlcs.iter()).enumerate()
        {
            let hlc_string = hlc.to_string();
            let partition_now = base_now + chrono::Duration::microseconds(partition_index as i64);

            for (field_name, value) in *fields {
                let op_id = Uuid::new_v4().to_string();
                let encoded = encode_value(value);

                if let Err(e) = tx.insert_pending_op(&PendingOp {
                    op_id: op_id.clone(),
                    sync_id: self.sync_id.clone(),
                    epoch: self.epoch,
                    device_id: self.device_id.clone(),
                    local_batch_id: (*batch_id).to_string(),
                    entity_table: entity_table.to_string(),
                    entity_id: entity_id.to_string(),
                    field_name: field_name.clone(),
                    encoded_value: encoded.clone(),
                    is_delete: false,
                    client_hlc: hlc_string.clone(),
                    created_at: partition_now,
                    pushed_at: None,
                }) {
                    let _ = tx.rollback();
                    return Err(e);
                }

                if let Err(e) = Self::upsert_field_version_if_wins(
                    &mut *tx,
                    &self.sync_id,
                    entity_table,
                    entity_id,
                    field_name,
                    &op_id,
                    &self.device_id,
                    hlc,
                    &encoded,
                    partition_now,
                ) {
                    let _ = tx.rollback();
                    return Err(e);
                }

                total_field_count += 1;
            }
        }

        // `mint_hlc_at` never advanced the watermark, so there is nothing to
        // restore on a commit failure — SQLite rolls back its own tx.
        tx.commit()?;

        tracing::debug!(
            table = entity_table,
            entity_id = entity_id,
            partition_count = non_empty.len(),
            field_count = total_field_count,
            kind = kind,
            origin_ms = origin_ms,
            "Queued origin-stamped multi-batch ops"
        );

        Ok(())
    }

    /// Tombstone variant stamped at `origin_ms`. Always pushes the delete op;
    /// the `field_versions` write is `wins_over`-guarded so a stale-origin
    /// delete never overwrites a newer local winner (the receiver's absorbing
    /// tombstone rule still applies to the pushed op).
    pub fn emit_delete_at(
        &mut self,
        storage: &dyn SyncStorage,
        entity_table: &str,
        entity_id: &str,
        local_batch_id: &str,
        origin_ms: i64,
    ) -> Result<()> {
        let hlc = self.mint_hlc_at(origin_ms);
        let hlc_string = hlc.to_string();
        let now = Utc::now();
        let op_id = Uuid::new_v4().to_string();

        let mut tx = storage.begin_tx()?;

        if let Err(e) = tx.insert_pending_op(&PendingOp {
            op_id: op_id.clone(),
            sync_id: self.sync_id.clone(),
            epoch: self.epoch,
            device_id: self.device_id.clone(),
            local_batch_id: local_batch_id.to_string(),
            entity_table: entity_table.to_string(),
            entity_id: entity_id.to_string(),
            field_name: DELETED_FIELD.to_string(),
            encoded_value: "true".to_string(),
            is_delete: true,
            client_hlc: hlc_string,
            created_at: now,
            pushed_at: None,
        }) {
            let _ = tx.rollback();
            return Err(e);
        }

        if let Err(e) = Self::upsert_field_version_if_wins(
            &mut *tx,
            &self.sync_id,
            entity_table,
            entity_id,
            DELETED_FIELD,
            &op_id,
            &self.device_id,
            &hlc,
            "true",
            now,
        ) {
            let _ = tx.rollback();
            return Err(e);
        }

        tx.commit()?;

        tracing::debug!(
            table = entity_table,
            entity_id = entity_id,
            batch_id = local_batch_id,
            origin_ms = origin_ms,
            "Queued origin-stamped delete op"
        );

        Ok(())
    }

    /// Upsert a `field_versions` row only if the candidate `(hlc, device_id,
    /// op_id)` wins LWW over the row currently stored — the same three-level
    /// tiebreak the merge engine uses (`crdt_change::wins_over`). A replay or
    /// floor-HLC backfill that loses leaves the existing winner untouched, so a
    /// newer local edit is never regressed. Absent rows always write.
    #[allow(clippy::too_many_arguments)]
    fn upsert_field_version_if_wins(
        tx: &mut dyn crate::storage::SyncStorageTx,
        sync_id: &str,
        entity_table: &str,
        entity_id: &str,
        field_name: &str,
        op_id: &str,
        device_id: &str,
        hlc: &Hlc,
        encoded: &str,
        now: chrono::DateTime<Utc>,
    ) -> Result<()> {
        if let Some(existing) =
            tx.get_field_version(sync_id, entity_table, entity_id, field_name)?
        {
            let existing_hlc = Hlc::from_string(&existing.winning_hlc)?;
            let wins = match hlc.cmp(&existing_hlc) {
                std::cmp::Ordering::Greater => true,
                std::cmp::Ordering::Less => false,
                std::cmp::Ordering::Equal => match device_id.cmp(&existing.winning_device_id) {
                    std::cmp::Ordering::Greater => true,
                    std::cmp::Ordering::Less => false,
                    std::cmp::Ordering::Equal => op_id > existing.winning_op_id.as_str(),
                },
            };
            if !wins {
                return Ok(());
            }
        }

        tx.upsert_field_version(&FieldVersion {
            sync_id: sync_id.to_string(),
            entity_table: entity_table.to_string(),
            entity_id: entity_id.to_string(),
            field_name: field_name.to_string(),
            winning_op_id: op_id.to_string(),
            winning_device_id: device_id.to_string(),
            winning_hlc: hlc.to_string(),
            winning_encoded_value: Some(encoded.to_string()),
            updated_at: now,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::RusqliteSyncStorage;

    fn make_storage() -> RusqliteSyncStorage {
        RusqliteSyncStorage::in_memory().expect("in_memory storage should succeed")
    }

    fn make_emitter() -> OpEmitter {
        OpEmitter::new("a1b2c3d4e5f6".to_string(), "sync-1".to_string(), 1, None)
    }

    fn now_ms() -> i64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis()
            as i64
    }

    fn make_fields() -> HashMap<String, SyncValue> {
        let mut fields = HashMap::new();
        fields.insert("name".to_string(), SyncValue::String("Alice".to_string()));
        fields.insert("age".to_string(), SyncValue::Int(25));
        fields.insert("active".to_string(), SyncValue::Bool(true));
        fields
    }

    #[test]
    fn emit_create_stores_correct_number_of_pending_ops() {
        let storage = make_storage();
        let mut emitter = make_emitter();
        let fields = make_fields();

        emitter.emit_create(&storage, "members", "ent-1", &fields, "batch-1").unwrap();

        let ops = storage.load_batch_ops("batch-1").unwrap();
        assert_eq!(ops.len(), 3);

        // All ops should share the same entity info
        for op in &ops {
            assert_eq!(op.sync_id, "sync-1");
            assert_eq!(op.entity_table, "members");
            assert_eq!(op.entity_id, "ent-1");
            assert_eq!(op.local_batch_id, "batch-1");
            assert_eq!(op.device_id, "a1b2c3d4e5f6");
            assert_eq!(op.epoch, 1);
            assert!(!op.is_delete);
            assert!(op.pushed_at.is_none());
        }

        // All field names should be present
        let field_names: Vec<&str> = ops.iter().map(|op| op.field_name.as_str()).collect();
        assert!(field_names.contains(&"name"));
        assert!(field_names.contains(&"age"));
        assert!(field_names.contains(&"active"));
    }

    #[test]
    fn emit_update_stores_only_changed_fields() {
        let storage = make_storage();
        let mut emitter = make_emitter();

        let mut changed = HashMap::new();
        changed.insert("name".to_string(), SyncValue::String("Bob".to_string()));

        emitter.emit_update(&storage, "members", "ent-1", &changed, "batch-2").unwrap();

        let ops = storage.load_batch_ops("batch-2").unwrap();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].field_name, "name");
        assert_eq!(ops[0].encoded_value, "\"Bob\"");
    }

    #[test]
    fn emit_update_skips_empty_fields() {
        let storage = make_storage();
        let mut emitter = make_emitter();
        let hlc_before = emitter.last_hlc().clone();

        let empty: HashMap<String, SyncValue> = HashMap::new();
        emitter.emit_update(&storage, "members", "ent-1", &empty, "batch-empty").unwrap();

        // No ops stored
        let ops = storage.load_batch_ops("batch-empty").unwrap();
        assert!(ops.is_empty());

        // HLC should NOT have advanced (no tick for empty update)
        assert_eq!(*emitter.last_hlc(), hlc_before);
    }

    #[test]
    fn emit_create_skips_empty_fields() {
        let storage = make_storage();
        let mut emitter = make_emitter();
        let hlc_before = emitter.last_hlc().clone();

        let empty: HashMap<String, SyncValue> = HashMap::new();
        emitter.emit_create(&storage, "members", "ent-1", &empty, "batch-empty-create").unwrap();

        let ops = storage.load_batch_ops("batch-empty-create").unwrap();
        assert!(ops.is_empty());
        assert_eq!(*emitter.last_hlc(), hlc_before);
    }

    #[test]
    fn emit_update_returns_error_without_writing_when_hlc_counter_overflows() {
        let storage = make_storage();
        let mut emitter = make_emitter();
        let saturated = Hlc::new(now_ms() + 100_000, u32::MAX, "a1b2c3d4e5f6");
        emitter.set_last_hlc(saturated.clone());

        let mut changed = HashMap::new();
        changed.insert("name".to_string(), SyncValue::String("Bob".to_string()));

        let err = emitter
            .emit_update(&storage, "members", "ent-1", &changed, "batch-overflow")
            .unwrap_err();
        assert!(err.to_string().contains("HLC counter overflow"));
        assert_eq!(*emitter.last_hlc(), saturated);

        let ops = storage.load_batch_ops("batch-overflow").unwrap();
        assert!(ops.is_empty());
    }

    #[test]
    fn new_accepts_near_future_remote_initial_hlc() {
        let local_device = "a1b2c3d4e5f6";
        let future_remote_hlc = Hlc::new(now_ms() + 5_000, 0, "remote-device");

        let emitter = OpEmitter::new(
            local_device.to_string(),
            "sync-1".to_string(),
            1,
            Some(future_remote_hlc.clone()),
        );

        assert_eq!(emitter.last_hlc(), &future_remote_hlc);
    }

    #[test]
    fn new_inherits_excessive_future_remote_initial_hlc() {
        // Inheritance is unconditional. An over-bound remote watermark is
        // inherited (not zeroed), because the only way it reached field_versions
        // is past an entry gate — so it sits within the drift bound of real time
        // and the next tick must stay above it for LWW.
        let local_device = "a1b2c3d4e5f6";
        let future_remote_hlc = Hlc::new(now_ms() + 120_000, 0, "remote-device");

        let mut emitter = OpEmitter::new(
            local_device.to_string(),
            "sync-1".to_string(),
            1,
            Some(future_remote_hlc.clone()),
        );

        assert_eq!(emitter.last_hlc(), &future_remote_hlc);
        let next = emitter.tick().unwrap();
        assert!(next > future_remote_hlc, "next tick must strictly exceed the inherited watermark");
    }

    #[test]
    fn set_last_hlc_accepts_near_future_remote_hlc() {
        let mut emitter = make_emitter();
        let future_remote_hlc = Hlc::new(now_ms() + 5_000, 0, "remote-device");

        emitter.set_last_hlc(future_remote_hlc.clone());

        assert_eq!(emitter.last_hlc(), &future_remote_hlc);
    }

    #[test]
    fn set_last_hlc_inherits_excessive_future_remote_hlc() {
        // set_last_hlc inherits an over-bound remote watermark too, keeping
        // only the monotonic-max guard. The next tick stays strictly above it.
        let mut emitter = make_emitter();
        let future_remote_hlc = Hlc::new(now_ms() + 120_000, 0, "remote-device");

        emitter.set_last_hlc(future_remote_hlc.clone());

        assert_eq!(*emitter.last_hlc(), future_remote_hlc);
        let next = emitter.tick().unwrap();
        assert!(next > future_remote_hlc, "next tick must strictly exceed the inherited watermark");
    }

    #[test]
    fn set_last_hlc_accepts_past_remote_hlc() {
        let mut emitter = make_emitter();
        let remote_hlc = Hlc::new(1_710_500_000_000, 0, "remote-device");

        emitter.set_last_hlc(remote_hlc.clone());

        assert_eq!(emitter.last_hlc(), &remote_hlc);
    }

    #[test]
    fn clamp_watermark_to_now_drops_far_future_watermark() {
        let mut emitter = make_emitter();
        // Poison the watermark a full year ahead, as a forward clock excursion
        // would have. A normal `set_last_hlc` cannot move it back; the repair
        // clamp is the one path that may.
        let poisoned = Hlc::new(now_ms() + 365 * 24 * 60 * 60 * 1000, 0, emitter.last_hlc().node_id.clone());
        emitter.set_last_hlc(poisoned);
        assert!(emitter.last_hlc().future_drift_ms() > MAX_CLOCK_DRIFT_MS);

        emitter.clamp_watermark_to_now().unwrap();

        // The watermark is back at wall clock, so the next tick mints a sane HLC.
        let next = emitter.tick().unwrap();
        let drift = crate::clock_drift::future_drift_ms(&next, now_ms());
        assert_eq!(drift, 0);
    }

    #[test]
    fn minted_hlcs_strictly_increase_across_arbitrary_watermark_ops() {
        // Property: over any sequence of set_last_hlc / tick / clamp, each
        // tick mints an HLC strictly greater than the watermark it held just
        // before the tick, and strictly greater than every prior tick since the
        // last clamp — clamp is the one operation that may lower the watermark
        // (the relay-anchored excursion repair), so the strictly-increasing
        // chain is per-device and resets only at a clamp.
        let mut emitter = make_emitter();
        // Deterministic LCG so the sequence is reproducible (no proptest needed).
        let mut rng: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next_rng = || {
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            rng
        };

        let mut floor: Option<Hlc> = None; // last minted HLC since the last clamp
        for _ in 0..500 {
            match next_rng() % 5 {
                // set_last_hlc with a candidate spread around now (past, near
                // future, and over-bound future all included).
                0 | 1 => {
                    let offset = (next_rng() % 240_000) as i64 - 60_000; // [-60s, +180s]
                    let node = if next_rng() % 2 == 0 { "a1b2c3d4e5f6" } else { "remote-device" };
                    let candidate = Hlc::new(now_ms() + offset, (next_rng() % 8) as u32, node);
                    emitter.set_last_hlc(candidate);
                }
                // tick: must strictly exceed the watermark just before, and the
                // running floor since the last clamp.
                2 | 3 => {
                    let before = emitter.last_hlc().clone();
                    let minted = emitter.tick().unwrap();
                    assert!(minted > before, "tick {minted:?} must exceed pre-tick watermark {before:?}");
                    if let Some(prev) = &floor {
                        assert!(minted > *prev, "tick {minted:?} must exceed prior minted {prev:?}");
                    }
                    floor = Some(minted);
                }
                // clamp: resets the watermark to now and the increasing chain.
                _ => {
                    emitter.clamp_watermark_to_now().unwrap();
                    floor = None;
                }
            }
        }
    }

    #[test]
    fn emit_delete_stores_is_deleted_op() {
        let storage = make_storage();
        let mut emitter = make_emitter();

        emitter.emit_delete(&storage, "members", "ent-1", "batch-3").unwrap();

        let ops = storage.load_batch_ops("batch-3").unwrap();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].field_name, DELETED_FIELD);
        assert_eq!(ops[0].encoded_value, "true");
        assert!(ops[0].is_delete);
    }

    #[test]
    fn hlc_advances_between_emissions() {
        let storage = make_storage();
        let mut emitter = make_emitter();

        let mut fields1 = HashMap::new();
        fields1.insert("name".to_string(), SyncValue::String("Alice".to_string()));

        emitter.emit_create(&storage, "members", "ent-1", &fields1, "batch-a").unwrap();
        let hlc_after_create = emitter.last_hlc().clone();

        let mut fields2 = HashMap::new();
        fields2.insert("name".to_string(), SyncValue::String("Bob".to_string()));

        emitter.emit_update(&storage, "members", "ent-1", &fields2, "batch-b").unwrap();
        let hlc_after_update = emitter.last_hlc().clone();

        // HLC must advance: either timestamp increases or counter increments
        assert!(hlc_after_update > hlc_after_create);

        emitter.emit_delete(&storage, "members", "ent-1", "batch-c").unwrap();
        let hlc_after_delete = emitter.last_hlc().clone();

        assert!(hlc_after_delete > hlc_after_update);
    }

    #[test]
    fn field_versions_are_updated() {
        let storage = make_storage();
        let mut emitter = make_emitter();

        let mut fields = HashMap::new();
        fields.insert("name".to_string(), SyncValue::String("Alice".to_string()));
        fields.insert("age".to_string(), SyncValue::Int(25));

        emitter.emit_create(&storage, "members", "ent-1", &fields, "batch-fv").unwrap();

        // Both fields should have field versions
        let fv_name = storage.get_field_version("sync-1", "members", "ent-1", "name").unwrap();
        assert!(fv_name.is_some());
        let fv_name = fv_name.unwrap();
        assert_eq!(fv_name.winning_device_id, "a1b2c3d4e5f6");

        let fv_age = storage.get_field_version("sync-1", "members", "ent-1", "age").unwrap();
        assert!(fv_age.is_some());
        let fv_age = fv_age.unwrap();
        assert_eq!(fv_age.winning_device_id, "a1b2c3d4e5f6");

        // Both should share the same HLC (same tick)
        assert_eq!(fv_name.winning_hlc, fv_age.winning_hlc);

        // Now update name — should get a newer HLC
        let mut changed = HashMap::new();
        changed.insert("name".to_string(), SyncValue::String("Bob".to_string()));

        emitter.emit_update(&storage, "members", "ent-1", &changed, "batch-fv2").unwrap();

        let fv_name_updated =
            storage.get_field_version("sync-1", "members", "ent-1", "name").unwrap().unwrap();

        // The winning HLC for name should be newer than the original
        assert_ne!(fv_name_updated.winning_hlc, fv_name.winning_hlc);
        assert_ne!(fv_name_updated.winning_op_id, fv_name.winning_op_id);
    }

    #[test]
    fn field_version_for_delete() {
        let storage = make_storage();
        let mut emitter = make_emitter();

        emitter.emit_delete(&storage, "members", "ent-1", "batch-del").unwrap();

        let fv = storage.get_field_version("sync-1", "members", "ent-1", DELETED_FIELD).unwrap();
        assert!(fv.is_some());
        let fv = fv.unwrap();
        assert_eq!(fv.field_name, DELETED_FIELD);
        assert_eq!(fv.winning_device_id, "a1b2c3d4e5f6");
    }

    #[test]
    fn batch_id_groups_ops_correctly() {
        let storage = make_storage();
        let mut emitter = make_emitter();

        // Batch A: create with 2 fields
        let mut fields_a = HashMap::new();
        fields_a.insert("name".to_string(), SyncValue::String("Alice".to_string()));
        fields_a.insert("age".to_string(), SyncValue::Int(25));

        emitter.emit_create(&storage, "members", "ent-1", &fields_a, "batch-A").unwrap();

        // Batch B: update 1 field
        let mut fields_b = HashMap::new();
        fields_b.insert("name".to_string(), SyncValue::String("Bob".to_string()));

        emitter.emit_update(&storage, "members", "ent-1", &fields_b, "batch-B").unwrap();

        // Batch C: delete
        emitter.emit_delete(&storage, "members", "ent-1", "batch-C").unwrap();

        // Verify each batch has correct number of ops
        let ops_a = storage.load_batch_ops("batch-A").unwrap();
        assert_eq!(ops_a.len(), 2);
        for op in &ops_a {
            assert_eq!(op.local_batch_id, "batch-A");
        }

        let ops_b = storage.load_batch_ops("batch-B").unwrap();
        assert_eq!(ops_b.len(), 1);
        assert_eq!(ops_b[0].local_batch_id, "batch-B");

        let ops_c = storage.load_batch_ops("batch-C").unwrap();
        assert_eq!(ops_c.len(), 1);
        assert_eq!(ops_c[0].local_batch_id, "batch-C");

        // All batches should show up as unpushed
        let batch_ids = storage.get_unpushed_batch_ids("sync-1").unwrap();
        assert_eq!(batch_ids.len(), 3);
    }

    #[test]
    fn all_ops_in_create_share_same_hlc() {
        let storage = make_storage();
        let mut emitter = make_emitter();
        let fields = make_fields();

        emitter.emit_create(&storage, "members", "ent-1", &fields, "batch-hlc").unwrap();

        let ops = storage.load_batch_ops("batch-hlc").unwrap();
        assert_eq!(ops.len(), 3);

        // All ops in the same emission should share the same HLC
        let hlc = &ops[0].client_hlc;
        for op in &ops {
            assert_eq!(&op.client_hlc, hlc);
        }
    }

    #[test]
    fn seed_fields_upserts_field_versions_but_not_pending_ops() {
        let storage = make_storage();
        let mut emitter = make_emitter();
        let fields = make_fields();

        emitter.seed_fields(&storage, "members", "ent-seed", &fields).unwrap();

        // field_versions rows exist for each field
        for field_name in ["name", "age", "active"] {
            let fv = storage
                .get_field_version("sync-1", "members", "ent-seed", field_name)
                .unwrap()
                .expect("field_version should exist after seed_fields");
            assert_eq!(fv.winning_device_id, "a1b2c3d4e5f6");
            assert!(fv.winning_encoded_value.is_some());
        }

        // No pending_ops produced — no unpushed batches for this sync group
        let batch_ids = storage.get_unpushed_batch_ids("sync-1").unwrap();
        assert!(
            batch_ids.is_empty(),
            "seed_fields must NOT produce pending_ops (got batches: {batch_ids:?})"
        );

        // HLC advances on next emit_create: must be greater than the seeded HLC
        let seeded_hlc = emitter.last_hlc().clone();
        let mut more = HashMap::new();
        more.insert("name".to_string(), SyncValue::String("Carol".to_string()));
        emitter.emit_create(&storage, "members", "ent-next", &more, "batch-after-seed").unwrap();
        assert!(emitter.last_hlc() > &seeded_hlc);
    }

    #[test]
    fn seed_fields_skips_empty_fields() {
        let storage = make_storage();
        let mut emitter = make_emitter();
        let hlc_before = emitter.last_hlc().clone();

        let empty: HashMap<String, SyncValue> = HashMap::new();
        emitter.seed_fields(&storage, "members", "ent-empty", &empty).unwrap();

        // HLC should NOT have advanced when nothing was seeded
        assert_eq!(*emitter.last_hlc(), hlc_before);
    }

    #[test]
    fn encoded_values_match_schema_encoding() {
        let storage = make_storage();
        let mut emitter = make_emitter();

        let mut fields = HashMap::new();
        fields.insert("name".to_string(), SyncValue::String("Alice".to_string()));
        fields.insert("count".to_string(), SyncValue::Int(42));
        fields.insert("score".to_string(), SyncValue::Real(3.5));
        fields.insert("active".to_string(), SyncValue::Bool(false));
        fields.insert("note".to_string(), SyncValue::Null);

        emitter.emit_create(&storage, "members", "ent-1", &fields, "batch-enc").unwrap();

        let ops = storage.load_batch_ops("batch-enc").unwrap();

        for op in &ops {
            match op.field_name.as_str() {
                "name" => assert_eq!(op.encoded_value, "\"Alice\""),
                "count" => assert_eq!(op.encoded_value, "42"),
                "score" => assert_eq!(op.encoded_value, "3.5"),
                "active" => assert_eq!(op.encoded_value, "false"),
                "note" => assert_eq!(op.encoded_value, "null"),
                other => panic!("Unexpected field: {other}"),
            }
        }
    }

    // ── Multi-batch atomic emission tests ──

    #[test]
    fn emit_create_multi_writes_all_partitions_in_one_transaction() {
        let storage = make_storage();
        let mut emitter = make_emitter();

        let mut p1 = HashMap::new();
        p1.insert("name".to_string(), SyncValue::String("Alice".to_string()));
        p1.insert("pronouns".to_string(), SyncValue::String("she/her".to_string()));
        let mut p2 = HashMap::new();
        p2.insert("avatar".to_string(), SyncValue::String("avatar-bytes".to_string()));
        let mut p3 = HashMap::new();
        p3.insert("banner".to_string(), SyncValue::String("banner-bytes".to_string()));

        let partitions = vec![
            (p1, "batch-1".to_string()),
            (p2, "batch-2".to_string()),
            (p3, "batch-3".to_string()),
        ];

        emitter
            .emit_create_multi(&storage, "members", "ent-multi", &partitions)
            .expect("emit_create_multi should succeed");

        // Each partition produced its own batch with the right field count.
        let b1 = storage.load_batch_ops("batch-1").unwrap();
        let b2 = storage.load_batch_ops("batch-2").unwrap();
        let b3 = storage.load_batch_ops("batch-3").unwrap();
        assert_eq!(b1.len(), 2);
        assert_eq!(b2.len(), 1);
        assert_eq!(b3.len(), 1);

        // All ops share the same entity/sync metadata.
        for op in b1.iter().chain(b2.iter()).chain(b3.iter()) {
            assert_eq!(op.entity_table, "members");
            assert_eq!(op.entity_id, "ent-multi");
            assert_eq!(op.sync_id, "sync-1");
            assert!(!op.is_delete);
        }

        // Within a single partition, the HLC is shared.
        let p1_hlc = &b1[0].client_hlc;
        for op in &b1 {
            assert_eq!(&op.client_hlc, p1_hlc);
        }
        // Across partitions, HLCs differ (one tick per partition).
        let p2_hlc = &b2[0].client_hlc;
        let p3_hlc = &b3[0].client_hlc;
        assert_ne!(p1_hlc, p2_hlc);
        assert_ne!(p2_hlc, p3_hlc);
        assert_ne!(p1_hlc, p3_hlc);

        // field_versions exist for every field across partitions.
        for field in ["name", "pronouns", "avatar", "banner"] {
            let fv = storage
                .get_field_version("sync-1", "members", "ent-multi", field)
                .unwrap()
                .unwrap_or_else(|| panic!("missing field_version for {field}"));
            assert_eq!(fv.winning_device_id, "a1b2c3d4e5f6");
            assert!(fv.winning_encoded_value.is_some());
        }

        // All three batches show up in the unpushed set.
        let mut batch_ids = storage.get_unpushed_batch_ids("sync-1").unwrap();
        batch_ids.sort();
        assert_eq!(batch_ids, vec!["batch-1", "batch-2", "batch-3"]);
    }

    #[test]
    fn emit_update_multi_writes_all_partitions_in_one_transaction() {
        let storage = make_storage();
        let mut emitter = make_emitter();

        // Seed an initial create so the update has something to override.
        let mut create = HashMap::new();
        create.insert("name".to_string(), SyncValue::String("Alice".to_string()));
        create.insert("avatar".to_string(), SyncValue::String("avatar-v1".to_string()));
        emitter
            .emit_create(&storage, "members", "ent-u", &create, "create-batch")
            .expect("seed create");

        let mut p1 = HashMap::new();
        p1.insert("name".to_string(), SyncValue::String("Alice v2".to_string()));
        let mut p2 = HashMap::new();
        p2.insert("avatar".to_string(), SyncValue::String("avatar-v2".to_string()));

        let partitions = vec![(p1, "update-1".to_string()), (p2, "update-2".to_string())];

        emitter
            .emit_update_multi(&storage, "members", "ent-u", &partitions)
            .expect("emit_update_multi should succeed");

        let u1 = storage.load_batch_ops("update-1").unwrap();
        let u2 = storage.load_batch_ops("update-2").unwrap();
        assert_eq!(u1.len(), 1);
        assert_eq!(u2.len(), 1);
        assert_eq!(u1[0].field_name, "name");
        assert_eq!(u1[0].encoded_value, "\"Alice v2\"");
        assert_eq!(u2[0].field_name, "avatar");

        // field_versions reflect the new winners
        let fv_name =
            storage.get_field_version("sync-1", "members", "ent-u", "name").unwrap().unwrap();
        assert_eq!(fv_name.winning_encoded_value, Some("\"Alice v2\"".to_string()));
        let fv_avatar =
            storage.get_field_version("sync-1", "members", "ent-u", "avatar").unwrap().unwrap();
        assert_eq!(fv_avatar.winning_encoded_value, Some("\"avatar-v2\"".to_string()));
    }

    #[test]
    fn emit_create_multi_empty_partition_list_is_noop() {
        let storage = make_storage();
        let mut emitter = make_emitter();
        let hlc_before = emitter.last_hlc().clone();

        emitter
            .emit_create_multi(&storage, "members", "ent-noop", &[])
            .expect("empty partitions ok");

        let batches = storage.get_unpushed_batch_ids("sync-1").unwrap();
        assert!(batches.is_empty());
        assert_eq!(*emitter.last_hlc(), hlc_before);
    }

    #[test]
    fn emit_create_multi_skips_empty_partitions_in_list() {
        let storage = make_storage();
        let mut emitter = make_emitter();

        let mut p1 = HashMap::new();
        p1.insert("name".to_string(), SyncValue::String("Alice".to_string()));
        let p_empty: HashMap<String, SyncValue> = HashMap::new();

        let partitions = vec![
            (p_empty.clone(), "empty-1".to_string()),
            (p1, "real".to_string()),
            (p_empty, "empty-2".to_string()),
        ];

        emitter
            .emit_create_multi(&storage, "members", "ent-mixed", &partitions)
            .expect("mixed partitions ok");

        // Only the non-empty partition produced rows.
        let real = storage.load_batch_ops("real").unwrap();
        let empty_1 = storage.load_batch_ops("empty-1").unwrap();
        let empty_2 = storage.load_batch_ops("empty-2").unwrap();
        assert_eq!(real.len(), 1);
        assert!(empty_1.is_empty());
        assert!(empty_2.is_empty());
    }

    #[test]
    fn emit_create_multi_all_ops_in_partition_share_hlc_and_batch_id() {
        let storage = make_storage();
        let mut emitter = make_emitter();

        let mut p1 = HashMap::new();
        for n in 0..4 {
            p1.insert(format!("f{n}"), SyncValue::String(format!("v{n}")));
        }
        let mut p2 = HashMap::new();
        for n in 0..3 {
            p2.insert(format!("g{n}"), SyncValue::String(format!("w{n}")));
        }

        let partitions = vec![(p1, "p-1".to_string()), (p2, "p-2".to_string())];

        emitter.emit_create_multi(&storage, "members", "ent-share", &partitions).expect("multi ok");

        let ops_p1 = storage.load_batch_ops("p-1").unwrap();
        let ops_p2 = storage.load_batch_ops("p-2").unwrap();
        assert_eq!(ops_p1.len(), 4);
        assert_eq!(ops_p2.len(), 3);

        let hlc_p1 = &ops_p1[0].client_hlc;
        for op in &ops_p1 {
            assert_eq!(op.local_batch_id, "p-1");
            assert_eq!(&op.client_hlc, hlc_p1);
        }
        let hlc_p2 = &ops_p2[0].client_hlc;
        for op in &ops_p2 {
            assert_eq!(op.local_batch_id, "p-2");
            assert_eq!(&op.client_hlc, hlc_p2);
        }
        assert_ne!(hlc_p1, hlc_p2);

        // Every op_id is unique across the whole emission.
        let mut ids: Vec<_> =
            ops_p1.iter().chain(ops_p2.iter()).map(|op| op.op_id.clone()).collect();
        ids.sort();
        let unique_count = ids.iter().collect::<std::collections::HashSet<_>>().len();
        assert_eq!(unique_count, ids.len(), "op_ids must be unique");
    }

    #[test]
    fn emit_create_multi_assigns_distinct_created_at_per_partition() {
        // Regression guard: the push-side query orders unpushed batches by
        // `MIN(created_at) ASC`. If every partition shares the same
        // `created_at`, SQL `ORDER BY` is non-deterministic on the tie and
        // the small-fields-first invariant collapses. `emit_multi` must
        // offset each partition by its index in microseconds.
        let storage = make_storage();
        let mut emitter = make_emitter();

        // Member-shaped multi: small fields in partition 0, large fields in
        // later partitions — mirrors how the schema actually splits.
        let mut p0 = HashMap::new();
        p0.insert("name".to_string(), SyncValue::String("Alice".to_string()));
        p0.insert("pronouns".to_string(), SyncValue::String("she/her".to_string()));
        let mut p1 = HashMap::new();
        p1.insert("avatar".to_string(), SyncValue::String("avatar-bytes".to_string()));
        let mut p2 = HashMap::new();
        p2.insert("banner".to_string(), SyncValue::String("banner-bytes".to_string()));

        let partitions = vec![
            (p0, "p-ordered-0".to_string()),
            (p1, "p-ordered-1".to_string()),
            (p2, "p-ordered-2".to_string()),
        ];

        emitter
            .emit_create_multi(&storage, "members", "ent-order", &partitions)
            .expect("emit_create_multi should succeed");

        // The push-side query must return partitions in the order we emitted
        // them (small fields first), not whatever SQL happened to pick on a
        // tied `created_at`.
        let unpushed = storage.get_unpushed_batch_ids("sync-1").unwrap();
        assert_eq!(
            unpushed,
            vec!["p-ordered-0".to_string(), "p-ordered-1".to_string(), "p-ordered-2".to_string()],
            "unpushed batches must be returned in emission order"
        );

        // Every row inside a single partition shares its `created_at`...
        let b0 = storage.load_batch_ops("p-ordered-0").unwrap();
        let b1 = storage.load_batch_ops("p-ordered-1").unwrap();
        let b2 = storage.load_batch_ops("p-ordered-2").unwrap();
        assert!(!b0.is_empty() && !b1.is_empty() && !b2.is_empty());
        let ts0 = b0[0].created_at;
        let ts1 = b1[0].created_at;
        let ts2 = b2[0].created_at;
        for op in &b0 {
            assert_eq!(op.created_at, ts0, "all rows in p-ordered-0 share created_at");
        }
        for op in &b1 {
            assert_eq!(op.created_at, ts1, "all rows in p-ordered-1 share created_at");
        }
        for op in &b2 {
            assert_eq!(op.created_at, ts2, "all rows in p-ordered-2 share created_at");
        }

        // ...but partitions differ from each other.
        assert_ne!(ts0, ts1, "partition 0 and 1 must differ in created_at");
        assert_ne!(ts1, ts2, "partition 1 and 2 must differ in created_at");
        assert_ne!(ts0, ts2, "partition 0 and 2 must differ in created_at");

        // Delta from partition N's created_at to partition 0's must be
        // exactly N microseconds.
        assert_eq!(
            (ts1 - ts0).num_microseconds(),
            Some(1),
            "partition 1 should be exactly 1us after partition 0"
        );
        assert_eq!(
            (ts2 - ts0).num_microseconds(),
            Some(2),
            "partition 2 should be exactly 2us after partition 0"
        );
    }

    #[test]
    fn emit_update_multi_assigns_distinct_created_at_per_partition() {
        // Same invariant as the create-multi regression: update-multi flows
        // through the same `emit_multi` helper and must produce a
        // deterministic push order across partitions.
        let storage = make_storage();
        let mut emitter = make_emitter();

        // Seed an initial create so the update has something to override.
        let mut create = HashMap::new();
        create.insert("name".to_string(), SyncValue::String("Alice".to_string()));
        create.insert("avatar".to_string(), SyncValue::String("avatar-v1".to_string()));
        create.insert("banner".to_string(), SyncValue::String("banner-v1".to_string()));
        emitter
            .emit_create(&storage, "members", "ent-uo", &create, "seed-batch")
            .expect("seed create");

        let mut u0 = HashMap::new();
        u0.insert("name".to_string(), SyncValue::String("Alice v2".to_string()));
        let mut u1 = HashMap::new();
        u1.insert("avatar".to_string(), SyncValue::String("avatar-v2".to_string()));
        let mut u2 = HashMap::new();
        u2.insert("banner".to_string(), SyncValue::String("banner-v2".to_string()));

        let partitions = vec![
            (u0, "u-ordered-0".to_string()),
            (u1, "u-ordered-1".to_string()),
            (u2, "u-ordered-2".to_string()),
        ];

        emitter
            .emit_update_multi(&storage, "members", "ent-uo", &partitions)
            .expect("emit_update_multi should succeed");

        // Push-side query returns the seed batch first (it was inserted
        // earlier), then the three update batches in emission order.
        let unpushed = storage.get_unpushed_batch_ids("sync-1").unwrap();
        assert_eq!(
            unpushed,
            vec![
                "seed-batch".to_string(),
                "u-ordered-0".to_string(),
                "u-ordered-1".to_string(),
                "u-ordered-2".to_string(),
            ],
            "unpushed batches must be returned in emission order"
        );

        let b0 = storage.load_batch_ops("u-ordered-0").unwrap();
        let b1 = storage.load_batch_ops("u-ordered-1").unwrap();
        let b2 = storage.load_batch_ops("u-ordered-2").unwrap();
        let ts0 = b0[0].created_at;
        let ts1 = b1[0].created_at;
        let ts2 = b2[0].created_at;
        assert_ne!(ts0, ts1);
        assert_ne!(ts1, ts2);
        assert_ne!(ts0, ts2);
        assert_eq!((ts1 - ts0).num_microseconds(), Some(1));
        assert_eq!((ts2 - ts0).num_microseconds(), Some(2));
    }

    #[test]
    fn emit_create_multi_rolls_back_entire_emission_on_storage_failure() {
        // Seed a real storage so we can verify state after the failed emit.
        let real_storage = make_storage();
        // Wrap it in a FailingStorage that errors on the Nth pending_op insert.
        let failing = FailingStorage::new(real_storage);
        // Fail mid-way through the second partition. Partition 1 has 2 ops,
        // partition 2 has 3 ops; failing on the 3rd op (1-indexed) means one
        // op of partition 2 has already been inserted before the failure.
        failing.fail_on_pending_op_insert_at(3);

        let mut emitter = make_emitter();

        let mut p1 = HashMap::new();
        p1.insert("a".to_string(), SyncValue::String("aa".to_string()));
        p1.insert("b".to_string(), SyncValue::String("bb".to_string()));
        let mut p2 = HashMap::new();
        p2.insert("c".to_string(), SyncValue::String("cc".to_string()));
        p2.insert("d".to_string(), SyncValue::String("dd".to_string()));
        p2.insert("e".to_string(), SyncValue::String("ee".to_string()));

        let partitions = vec![(p1, "roll-1".to_string()), (p2, "roll-2".to_string())];

        let hlc_before = emitter.last_hlc().clone();
        let err = emitter
            .emit_create_multi(&failing, "members", "ent-roll", &partitions)
            .expect_err("emit_create_multi must propagate the storage error");
        assert!(
            err.to_string().contains("FailingStorage induced error"),
            "unexpected error: {err}"
        );

        // No pending_ops persisted for either batch.
        let b1 = failing.inner().load_batch_ops("roll-1").unwrap();
        let b2 = failing.inner().load_batch_ops("roll-2").unwrap();
        assert!(b1.is_empty(), "partition 1 should have rolled back, found: {b1:?}");
        assert!(b2.is_empty(), "partition 2 should have rolled back, found: {b2:?}");

        // No field_versions persisted.
        for field in ["a", "b", "c", "d", "e"] {
            let fv =
                failing.inner().get_field_version("sync-1", "members", "ent-roll", field).unwrap();
            assert!(fv.is_none(), "field_version for {field} should have rolled back");
        }

        // No unpushed batch IDs for this sync group.
        let batches = failing.inner().get_unpushed_batch_ids("sync-1").unwrap();
        assert!(batches.is_empty(), "unpushed_batch_ids should be empty, found: {batches:?}");

        // HLC watermark restored — no phantom advance.
        assert_eq!(*emitter.last_hlc(), hlc_before, "HLC watermark must be restored on failure");
    }

    #[test]
    fn emit_delete_multi_all_ops_in_partition_share_hlc_and_batch_id() {
        let storage = make_storage();
        let mut emitter = make_emitter();

        let p1: Vec<String> = (0..4).map(|n| format!("ent-{n}")).collect();
        let p2: Vec<String> = (4..7).map(|n| format!("ent-{n}")).collect();
        let partitions = vec![(p1, "del-1".to_string()), (p2, "del-2".to_string())];

        emitter.emit_delete_multi(&storage, "members", &partitions).expect("multi delete ok");

        let ops_p1 = storage.load_batch_ops("del-1").unwrap();
        let ops_p2 = storage.load_batch_ops("del-2").unwrap();
        assert_eq!(ops_p1.len(), 4);
        assert_eq!(ops_p2.len(), 3);

        // Each partition: shared HLC + batch_id; every op is a tombstone.
        let hlc_p1 = &ops_p1[0].client_hlc;
        for op in &ops_p1 {
            assert_eq!(op.local_batch_id, "del-1");
            assert_eq!(&op.client_hlc, hlc_p1);
            assert!(op.is_delete);
            assert_eq!(op.field_name, DELETED_FIELD);
            assert_eq!(op.encoded_value, "true");
        }
        let hlc_p2 = &ops_p2[0].client_hlc;
        for op in &ops_p2 {
            assert_eq!(op.local_batch_id, "del-2");
            assert_eq!(&op.client_hlc, hlc_p2);
        }
        assert_ne!(hlc_p1, hlc_p2, "distinct partitions get distinct HLC ticks");

        // Every entity appears exactly once; op_ids are unique.
        let mut entities: Vec<_> =
            ops_p1.iter().chain(ops_p2.iter()).map(|o| o.entity_id.clone()).collect();
        entities.sort();
        assert_eq!(entities, vec!["ent-0", "ent-1", "ent-2", "ent-3", "ent-4", "ent-5", "ent-6"]);
        let ids: std::collections::HashSet<_> =
            ops_p1.iter().chain(ops_p2.iter()).map(|o| o.op_id.clone()).collect();
        assert_eq!(ids.len(), 7, "op_ids must be unique across the emission");
    }

    #[test]
    fn emit_delete_multi_rolls_back_entire_emission_on_storage_failure() {
        let real_storage = make_storage();
        let failing = FailingStorage::new(real_storage);
        // Partition 1 has 2 ops, partition 2 has 3; fail on the 3rd insert =>
        // mid partition 2, after partition 1 was fully inserted.
        failing.fail_on_pending_op_insert_at(3);

        let mut emitter = make_emitter();

        let p1: Vec<String> = vec!["d0".into(), "d1".into()];
        let p2: Vec<String> = vec!["d2".into(), "d3".into(), "d4".into()];
        let partitions = vec![(p1, "droll-1".to_string()), (p2, "droll-2".to_string())];

        let hlc_before = emitter.last_hlc().clone();
        let err = emitter
            .emit_delete_multi(&failing, "members", &partitions)
            .expect_err("emit_delete_multi must propagate the storage error");
        assert!(
            err.to_string().contains("FailingStorage induced error"),
            "unexpected error: {err}"
        );

        // Nothing persisted for either batch — all partitions roll back together.
        assert!(failing.inner().load_batch_ops("droll-1").unwrap().is_empty());
        assert!(failing.inner().load_batch_ops("droll-2").unwrap().is_empty());
        for ent in ["d0", "d1", "d2", "d3", "d4"] {
            let fv =
                failing.inner().get_field_version("sync-1", "members", ent, DELETED_FIELD).unwrap();
            assert!(fv.is_none(), "field_version for {ent} must roll back");
        }
        assert!(failing.inner().get_unpushed_batch_ids("sync-1").unwrap().is_empty());
        assert_eq!(*emitter.last_hlc(), hlc_before, "HLC watermark must be restored on failure");
    }

    // ── Test-only storage that injects a failure mid-emission ──

    /// A `SyncStorage` wrapper that delegates to an inner store, but causes
    /// the next `Box<dyn SyncStorageTx>` it hands out to return an error from
    /// `insert_pending_op` on the configured call ordinal (1-indexed). The
    /// inner SQLite tx will then be rolled back implicitly when the dropped
    /// `RusqliteTx` releases its connection without committing.
    struct FailingStorage {
        inner: std::sync::Arc<RusqliteSyncStorage>,
        fail_at: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        seen: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl FailingStorage {
        fn new(inner: RusqliteSyncStorage) -> Self {
            Self {
                inner: std::sync::Arc::new(inner),
                fail_at: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                seen: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            }
        }

        fn fail_on_pending_op_insert_at(&self, ordinal: usize) {
            self.fail_at.store(ordinal, std::sync::atomic::Ordering::SeqCst);
        }

        fn inner(&self) -> &RusqliteSyncStorage {
            &self.inner
        }
    }

    impl SyncStorage for FailingStorage {
        fn begin_tx(&self) -> Result<Box<dyn crate::storage::SyncStorageTx + '_>> {
            let inner_tx = self.inner.begin_tx()?;
            Ok(Box::new(FailingTx {
                inner: inner_tx,
                fail_at: self.fail_at.clone(),
                seen: self.seen.clone(),
            }))
        }

        fn get_sync_metadata(&self, sync_id: &str) -> Result<Option<crate::storage::SyncMetadata>> {
            self.inner.get_sync_metadata(sync_id)
        }

        fn get_unpushed_batch_ids(&self, sync_id: &str) -> Result<Vec<String>> {
            self.inner.get_unpushed_batch_ids(sync_id)
        }

        fn load_batch_ops(&self, batch_id: &str) -> Result<Vec<PendingOp>> {
            self.inner.load_batch_ops(batch_id)
        }

        fn is_op_applied(&self, op_id: &str) -> Result<bool> {
            self.inner.is_op_applied(op_id)
        }

        fn get_field_version(
            &self,
            sync_id: &str,
            table: &str,
            entity_id: &str,
            field: &str,
        ) -> Result<Option<FieldVersion>> {
            self.inner.get_field_version(sync_id, table, entity_id, field)
        }

        fn get_device_record(
            &self,
            sync_id: &str,
            device_id: &str,
        ) -> Result<Option<crate::storage::DeviceRecord>> {
            self.inner.get_device_record(sync_id, device_id)
        }

        fn list_device_records(&self, sync_id: &str) -> Result<Vec<crate::storage::DeviceRecord>> {
            self.inner.list_device_records(sync_id)
        }

        fn export_snapshot(&self, sync_id: &str) -> Result<Vec<u8>> {
            self.inner.export_snapshot(sync_id)
        }

        fn rekey(&self, new_key: &[u8; 32]) -> Result<()> {
            self.inner.rekey(new_key)
        }
    }

    /// Transactional wrapper that injects an error on a configured ordinal
    /// `insert_pending_op` call. All other ops delegate to the inner
    /// rusqlite transaction.
    struct FailingTx<'a> {
        inner: Box<dyn crate::storage::SyncStorageTx + 'a>,
        fail_at: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        seen: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl crate::storage::SyncStorageTx for FailingTx<'_> {
        fn is_op_applied(&self, op_id: &str) -> Result<bool> {
            self.inner.is_op_applied(op_id)
        }

        fn get_field_version(
            &self,
            sync_id: &str,
            table: &str,
            entity_id: &str,
            field: &str,
        ) -> Result<Option<FieldVersion>> {
            self.inner.get_field_version(sync_id, table, entity_id, field)
        }

        fn get_device_record(
            &self,
            sync_id: &str,
            device_id: &str,
        ) -> Result<Option<crate::storage::DeviceRecord>> {
            self.inner.get_device_record(sync_id, device_id)
        }

        fn upsert_sync_metadata(&mut self, meta: &crate::storage::SyncMetadata) -> Result<()> {
            self.inner.upsert_sync_metadata(meta)
        }

        fn update_last_pulled_seq(&mut self, sync_id: &str, seq: i64) -> Result<()> {
            self.inner.update_last_pulled_seq(sync_id, seq)
        }

        fn reset_last_pulled_seq(&mut self, sync_id: &str, seq: i64) -> Result<()> {
            self.inner.reset_last_pulled_seq(sync_id, seq)
        }

        fn update_relay_log_token(&mut self, sync_id: &str, token: &str) -> Result<()> {
            self.inner.update_relay_log_token(sync_id, token)
        }

        fn update_last_successful_sync(&mut self, sync_id: &str) -> Result<()> {
            self.inner.update_last_successful_sync(sync_id)
        }

        fn update_current_epoch(&mut self, sync_id: &str, epoch: i32) -> Result<()> {
            self.inner.update_current_epoch(sync_id, epoch)
        }

        fn update_last_imported_registry_version(
            &mut self,
            sync_id: &str,
            version: i64,
        ) -> Result<()> {
            self.inner.update_last_imported_registry_version(sync_id, version)
        }

        fn insert_pending_op(&mut self, op: &PendingOp) -> Result<()> {
            let next = self.seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            let trip = self.fail_at.load(std::sync::atomic::Ordering::SeqCst);
            if trip != 0 && next == trip {
                return Err(CoreError::Storage(crate::storage::StorageError::Logic(
                    "FailingStorage induced error".to_string(),
                )));
            }
            self.inner.insert_pending_op(op)
        }

        fn mark_batch_pushed(&mut self, batch_id: &str) -> Result<()> {
            self.inner.mark_batch_pushed(batch_id)
        }

        fn delete_pushed_ops(&mut self, sync_id: &str, batch_id: &str) -> Result<()> {
            self.inner.delete_pushed_ops(sync_id, batch_id)
        }

        fn insert_applied_op(&mut self, op: &crate::storage::AppliedOp) -> Result<()> {
            self.inner.insert_applied_op(op)
        }

        fn upsert_field_version(&mut self, fv: &FieldVersion) -> Result<()> {
            self.inner.upsert_field_version(fv)
        }

        fn upsert_device_record(&mut self, device: &crate::storage::DeviceRecord) -> Result<()> {
            self.inner.upsert_device_record(device)
        }

        fn remove_device_record(&mut self, sync_id: &str, device_id: &str) -> Result<()> {
            self.inner.remove_device_record(sync_id, device_id)
        }

        fn clear_sync_state(&mut self, sync_id: &str) -> Result<()> {
            self.inner.clear_sync_state(sync_id)
        }

        fn import_snapshot(&mut self, sync_id: &str, data: &[u8], bound_ms: i64) -> Result<u64> {
            self.inner.import_snapshot(sync_id, data, bound_ms)
        }

        fn commit(self: Box<Self>) -> Result<()> {
            self.inner.commit()
        }

        fn rollback(self: Box<Self>) -> Result<()> {
            self.inner.rollback()
        }
    }

    // ── Origin-stamped + reconcile/backfill emission ──

    fn single_field(name: &str, value: SyncValue) -> HashMap<String, SyncValue> {
        let mut m = HashMap::new();
        m.insert(name.to_string(), value);
        m
    }

    fn fv(
        storage: &RusqliteSyncStorage,
        table: &str,
        entity_id: &str,
        field: &str,
    ) -> Option<FieldVersion> {
        storage.get_field_version("sync-1", table, entity_id, field).unwrap()
    }

    #[test]
    fn mint_hlc_at_clamps_to_origin_and_leaves_watermark_untouched() {
        let emitter = make_emitter();
        let watermark_before = emitter.last_hlc().clone();

        let origin = now_ms() - 3_600_000; // an hour ago
        let hlc = emitter.mint_hlc_at(origin);
        assert_eq!(hlc.timestamp, origin, "in-range origin is preserved");
        assert_eq!(hlc.node_id, "a1b2c3d4e5f6", "node_id stays local for attribution");

        // Watermark must not move — minting below it is legal.
        assert_eq!(*emitter.last_hlc(), watermark_before);

        // Future origin clamps down to now; floor origin clamps up off the floor.
        let future = emitter.mint_hlc_at(now_ms() + 10_000_000);
        assert!(future.timestamp <= Hlc::now_ms() + 1);
        let below_floor = emitter.mint_hlc_at(0);
        assert_eq!(below_floor.timestamp, BACKFILL_HLC_TIMESTAMP_MS + 1);
    }

    #[test]
    fn emit_update_multi_at_inserts_op_but_does_not_overwrite_newer_field_version() {
        let storage = make_storage();
        let mut emitter = make_emitter();

        // A genuine "now" write establishes the current winner.
        emitter
            .emit_update(&storage, "members", "ent-fv", &single_field("name", SyncValue::String("Beta".into())), "live")
            .unwrap();
        let winner = fv(&storage, "members", "ent-fv", "name").unwrap();
        let winner_op = winner.winning_op_id.clone();

        // Replay an OLDER captured value at an origin from an hour ago.
        let origin = now_ms() - 3_600_000;
        let partitions =
            vec![(single_field("name", SyncValue::String("Alpha".into())), "replay".to_string())];
        emitter.emit_update_multi_at(&storage, "members", "ent-fv", &partitions, origin).unwrap();

        // pending_op was inserted (so peers merge + reject it)...
        let ops = storage.load_batch_ops("replay").unwrap();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].encoded_value, "\"Alpha\"");
        let replay_hlc = Hlc::from_string(&ops[0].client_hlc).unwrap();
        assert_eq!(replay_hlc.timestamp, origin);

        // ...but field_versions still holds the newer "Beta" winner.
        let after = fv(&storage, "members", "ent-fv", "name").unwrap();
        assert_eq!(after.winning_encoded_value, Some("\"Beta\"".to_string()));
        assert_eq!(after.winning_op_id, winner_op, "newer winner not regressed");
    }

    #[test]
    fn reconcile_skips_equal_fresh_for_divergent_floor_for_absent() {
        let storage = make_storage();
        let mut emitter = make_emitter();

        // Seed two synced fields; leave a third never-synced.
        let mut seed = HashMap::new();
        seed.insert("name".to_string(), SyncValue::String("Same".into()));
        seed.insert("color_hex".to_string(), SyncValue::String("#000".into()));
        emitter.emit_create(&storage, "member_groups", "g1", &seed, "seed").unwrap();
        let equal_winner = fv(&storage, "member_groups", "g1", "name").unwrap().winning_op_id;

        // Reconcile: name equal, color_hex divergent, emoji absent.
        let mut fields = HashMap::new();
        fields.insert("name".to_string(), SyncValue::String("Same".into()));
        fields.insert("color_hex".to_string(), SyncValue::String("#fff".into()));
        fields.insert("emoji".to_string(), SyncValue::String("⭐".into()));
        emitter
            .emit_reconcile_multi(
                &storage,
                "member_groups",
                "g1",
                &fields,
                DivergentMode::FreshHlc,
                "recon",
            )
            .unwrap();

        let ops = storage.load_batch_ops("recon").unwrap();
        let by_field: HashMap<&str, &PendingOp> =
            ops.iter().map(|op| (op.field_name.as_str(), op)).collect();

        // Equal field: nothing emitted, winner untouched.
        assert!(!by_field.contains_key("name"), "value-equal field must not emit");
        assert_eq!(fv(&storage, "member_groups", "g1", "name").unwrap().winning_op_id, equal_winner);

        // Divergent field: fresh HLC (above the floor, ~now).
        let color = by_field.get("color_hex").expect("divergent field emits");
        let color_hlc = Hlc::from_string(&color.client_hlc).unwrap();
        assert!(color_hlc.timestamp > BACKFILL_HLC_TIMESTAMP_MS + 1);
        assert_eq!(
            fv(&storage, "member_groups", "g1", "color_hex").unwrap().winning_encoded_value,
            Some("\"#fff\"".to_string())
        );

        // Absent field: floor backfill HLC, FV now present.
        let emoji = by_field.get("emoji").expect("absent field emits");
        let emoji_hlc = Hlc::from_string(&emoji.client_hlc).unwrap();
        assert_eq!(emoji_hlc.timestamp, BACKFILL_HLC_TIMESTAMP_MS);
        assert!(fv(&storage, "member_groups", "g1", "emoji").is_some());
    }

    #[test]
    fn backfill_emits_only_absent_fields_at_floor_with_local_node_id() {
        let storage = make_storage();
        let mut emitter = make_emitter();

        // One field already synced (divergent), one never synced.
        emitter
            .emit_create(&storage, "member_groups", "g2", &single_field("name", SyncValue::String("Existing".into())), "seed2")
            .unwrap();
        let existing_winner = fv(&storage, "member_groups", "g2", "name").unwrap().winning_op_id;

        let mut fields = HashMap::new();
        fields.insert("name".to_string(), SyncValue::String("Divergent".into()));
        fields.insert("emoji".to_string(), SyncValue::String("🌟".into()));
        emitter
            .emit_reconcile_multi(
                &storage,
                "member_groups",
                "g2",
                &fields,
                DivergentMode::Skip,
                "back",
            )
            .unwrap();

        let ops = storage.load_batch_ops("back").unwrap();
        // Skip mode: divergent "name" never emits; only absent "emoji" does.
        assert_eq!(ops.len(), 1, "only the absent field is backfilled");
        assert_eq!(ops[0].field_name, "emoji");
        let hlc = Hlc::from_string(&ops[0].client_hlc).unwrap();
        assert_eq!(hlc.timestamp, BACKFILL_HLC_TIMESTAMP_MS, "exactly the floor, never fresh");
        assert_eq!(hlc.node_id, "a1b2c3d4e5f6", "local node_id");

        // Divergent winner untouched (first-device-wins).
        assert_eq!(fv(&storage, "member_groups", "g2", "name").unwrap().winning_op_id, existing_winner);
    }

    #[test]
    fn backfill_floor_op_does_not_regress_an_existing_field_version() {
        // A backfill of a field that already has any field_version row inserts
        // no op (Skip leaves divergent alone; equal is also a no-op).
        let storage = make_storage();
        let mut emitter = make_emitter();
        emitter
            .emit_update(&storage, "members", "ent-b", &single_field("name", SyncValue::String("Live".into())), "live-b")
            .unwrap();
        let winner = fv(&storage, "members", "ent-b", "name").unwrap();

        emitter
            .emit_reconcile_multi(
                &storage,
                "members",
                "ent-b",
                &single_field("name", SyncValue::String("Stale".into())),
                DivergentMode::Skip,
                "back-present",
            )
            .unwrap();

        let ops = storage.load_batch_ops("back-present").unwrap();
        assert!(ops.is_empty(), "present field is never backfilled");
        let after = fv(&storage, "members", "ent-b", "name").unwrap();
        assert_eq!(after.winning_op_id, winner.winning_op_id, "winner untouched");
    }
}
