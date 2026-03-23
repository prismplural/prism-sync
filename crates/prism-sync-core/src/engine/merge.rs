use std::collections::HashMap;

use crate::crdt_change::CrdtChange;
use crate::error::Result;
use crate::schema::SyncSchema;
use crate::storage::FieldVersion;

/// A winning operation from the merge process.
#[derive(Debug, Clone)]
pub struct WinningOp {
    pub op: CrdtChange,
    pub is_bulk_reset: bool,
}

/// Handles per-field LWW merge for incoming remote operations.
///
/// Merge algorithm (faithful port of Dart `DatabaseSyncBridge.applyRemoteChanges`):
///
/// For a group of ops targeting the same entity:
///
/// 1. **Tombstone protection:** If the entity already has a winning
///    `is_deleted = true` tombstone in field_versions, reject ALL
///    non-delete ops to prevent resurrection.
///
/// 2. **Per-field LWW merge:** For each op in the group:
///    a. Check in-batch winners first (handles multiple ops on
///    the same field within one batch)
///    b. Fall back to persisted field_versions
///    c. Three-level tiebreaker: HLC -> device_id -> op_id
///    d. If current winner holds, skip this op
///    e. If this op wins, update the in-batch winner tracking
///
/// 3. **Field version updates:** Only winning ops update field_versions.
///    Previous in-batch winners are removed from the won set when
///    superseded by a later op in the same batch.
///
/// Reference: Dart `lib/core/sync/database_sync_bridge.dart` lines 200-305
#[derive(Debug, Clone)]
pub struct MergeEngine {
    schema: SyncSchema,
}

impl MergeEngine {
    pub fn new(schema: SyncSchema) -> Self {
        Self { schema }
    }

    /// Determine which ops in a batch win the per-field LWW merge.
    ///
    /// Returns a map of op_id -> WinningOp for ops that beat the current field_versions.
    ///
    /// This method only determines winners -- it does NOT write to storage.
    /// The caller (SyncEngine) is responsible for updating field_versions
    /// and applied_ops within a transaction.
    ///
    /// Arguments:
    /// - `ops`: The batch of CrdtChange ops to merge
    /// - `get_field_version`: Closure to look up the current winning field version
    /// - `is_op_applied`: Closure to check idempotency (has this op already been applied?)
    #[allow(clippy::type_complexity)]
    pub fn determine_winners(
        &self,
        ops: &[CrdtChange],
        get_field_version: &dyn Fn(&str, &str, &str, &str) -> Result<Option<FieldVersion>>,
        is_op_applied: &dyn Fn(&str) -> Result<bool>,
        sync_id: &str,
    ) -> Result<HashMap<String, WinningOp>> {
        let mut winners: HashMap<String, WinningOp> = HashMap::new();

        // Track in-batch winners per (entity_table, entity_id, field_name)
        // so that when multiple ops in the same batch target the same field,
        // later ops compare against the batch-local winner.
        let mut batch_winners: HashMap<String, CrdtChange> = HashMap::new();

        for op in ops {
            // Skip unknown tables
            if !self.schema.has_table(&op.entity_table) {
                tracing::warn!("Skipping op for unknown table: {}", op.entity_table);
                continue;
            }

            // Validate field exists in schema (skip unknown fields with warning),
            // except "is_deleted" and bulk_reset which are always allowed
            if op.field_name != "is_deleted" && !op.is_bulk_reset() {
                if let Some(entity_def) = self.schema.entity(&op.entity_table) {
                    if entity_def.field_by_name(&op.field_name).is_none() {
                        tracing::warn!(
                            "Skipping op for unknown field: {}.{}",
                            op.entity_table,
                            op.field_name
                        );
                        continue;
                    }
                }
            }

            // Idempotency check: skip already-applied ops
            if is_op_applied(&op.op_id)? {
                continue;
            }

            // Bulk reset is handled specially by the caller
            if op.is_bulk_reset() {
                winners.insert(
                    op.op_id.clone(),
                    WinningOp {
                        op: op.clone(),
                        is_bulk_reset: true,
                    },
                );
                continue;
            }

            // Tombstone protection: check if entity is already tombstoned.
            // If so, only allow is_deleted ops (prevents resurrection).
            //
            // We also check that the winning encoded_value is "true" to handle
            // un-delete operations (is_deleted = "false"). If the winning value
            // is "false", the entity has been un-deleted and non-delete ops should
            // be allowed through.
            //
            // NOTE: We currently only emit `is_deleted = "true"` in the op emitter,
            // so the value will always be "true" in practice. The check is included
            // for safety and correctness if un-delete ops are added in the future.
            let delete_fv =
                get_field_version(sync_id, &op.entity_table, &op.entity_id, "is_deleted")?;
            let is_tombstoned = delete_fv
                .as_ref()
                .map(|fv| {
                    // Only treat as tombstoned if the winning value is "true".
                    // An is_deleted = "false" field version means the entity was un-deleted.
                    fv.winning_encoded_value.as_deref().unwrap_or("true") == "true"
                })
                .unwrap_or(false);
            if is_tombstoned && op.field_name != "is_deleted" {
                continue;
            }

            // Per-field LWW merge
            let field_key = format!("{}:{}:{}", op.entity_table, op.entity_id, op.field_name);

            // Check in-batch winner first, then fall back to persisted field_versions
            let current_winner: Option<CrdtChange> = if let Some(bw) = batch_winners.get(&field_key)
            {
                Some(bw.clone())
            } else {
                // Fall back to persisted field_versions
                let fv =
                    get_field_version(sync_id, &op.entity_table, &op.entity_id, &op.field_name)?;
                fv.map(|fv| {
                    CrdtChange::new(
                        Some(fv.winning_op_id),
                        None,
                        op.entity_id.clone(),
                        op.entity_table.clone(),
                        op.field_name.clone(),
                        None,
                        Some(fv.winning_hlc),
                        false,
                        Some(fv.winning_device_id),
                        None,
                        None,
                    )
                })
            };

            let op_wins = match &current_winner {
                Some(cw) => op.wins_over(cw)?,
                None => true, // no current winner, this op wins by default
            };

            if !op_wins {
                continue;
            }

            // This op wins -- remove any previous in-batch winner from winners map
            if let Some(prev_bw) = batch_winners.get(&field_key) {
                winners.remove(&prev_bw.op_id);
            }

            // Record this op as the new winner
            winners.insert(
                op.op_id.clone(),
                WinningOp {
                    op: op.clone(),
                    is_bulk_reset: false,
                },
            );
            batch_winners.insert(field_key, op.clone());
        }

        Ok(winners)
    }
}
