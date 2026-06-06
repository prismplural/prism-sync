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

/// Reason an op could not be merged with the client's current schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaQuarantineReason {
    UnknownTable(String),
    UnknownField { table: String, field: String },
}

impl SchemaQuarantineReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UnknownTable(_) => "unknown_table",
            Self::UnknownField { .. } => "unknown_field",
        }
    }
}

/// An op that must be retried after the host upgrades its schema.
#[derive(Debug, Clone)]
pub struct QuarantinedChange {
    pub op: CrdtChange,
    pub reason: SchemaQuarantineReason,
}

/// Result of merge winner selection, including schema-unknown ops that should
/// be persisted for later replay.
#[derive(Debug, Clone)]
pub struct MergeOutcome {
    pub winners: HashMap<String, WinningOp>,
    pub quarantined: Vec<QuarantinedChange>,
}

/// Handles per-field LWW merge for incoming remote operations.
///
/// Merge algorithm (faithful port of Dart `DatabaseSyncBridge.applyRemoteChanges`):
///
/// For a group of ops targeting the same entity:
///
/// 1. **Tombstone is absorbing:** `is_deleted` merges as `true ∨ false = true`
///    (not HLC-LWW) — `true` always wins, `false` never overrides it — and any
///    other op on a tombstoned entity is dropped. Blocks edit-after-delete and
///    phantom-un-delete resurrection, order-independently.
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

/// Reconstruct a minimal [`CrdtChange`] from a persisted [`FieldVersion`] for
/// LWW comparison. Carries the winning value (a `None` becomes `"null"`) for the
/// absorbing `is_deleted` check; [`CrdtChange::wins_over`] ignores it.
fn field_version_to_change(
    fv: FieldVersion,
    entity_table: &str,
    entity_id: &str,
    field_name: &str,
) -> CrdtChange {
    CrdtChange::new(
        Some(fv.winning_op_id),
        None,
        entity_id.to_string(),
        entity_table.to_string(),
        field_name.to_string(),
        fv.winning_encoded_value,
        Some(fv.winning_hlc),
        false,
        Some(fv.winning_device_id),
        None,
        None,
    )
}

impl MergeEngine {
    pub fn new(schema: SyncSchema) -> Self {
        Self { schema }
    }

    pub fn schema_quarantine_reason(&self, op: &CrdtChange) -> Option<SchemaQuarantineReason> {
        let Some(entity_def) = self.schema.entity(&op.entity_table) else {
            return Some(SchemaQuarantineReason::UnknownTable(op.entity_table.clone()));
        };

        if op.field_name != "is_deleted"
            && !op.is_bulk_reset()
            && entity_def.field_by_name(&op.field_name).is_none()
        {
            return Some(SchemaQuarantineReason::UnknownField {
                table: op.entity_table.clone(),
                field: op.field_name.clone(),
            });
        }

        None
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
        Ok(self
            .determine_winners_with_quarantine(ops, get_field_version, is_op_applied, sync_id)?
            .winners)
    }

    #[allow(clippy::type_complexity)]
    pub fn determine_winners_with_quarantine(
        &self,
        ops: &[CrdtChange],
        get_field_version: &dyn Fn(&str, &str, &str, &str) -> Result<Option<FieldVersion>>,
        is_op_applied: &dyn Fn(&str) -> Result<bool>,
        sync_id: &str,
    ) -> Result<MergeOutcome> {
        let mut winners: HashMap<String, WinningOp> = HashMap::new();
        let mut quarantined = Vec::new();

        // Track in-batch winners per (entity_table, entity_id, field_name)
        // so that when multiple ops in the same batch target the same field,
        // later ops compare against the batch-local winner.
        let mut batch_winners: HashMap<String, CrdtChange> = HashMap::new();

        for op in ops {
            if let Some(reason) = self.schema_quarantine_reason(op) {
                match &reason {
                    SchemaQuarantineReason::UnknownTable(table) => {
                        tracing::warn!("Quarantining op for unknown table: {table}");
                    }
                    SchemaQuarantineReason::UnknownField { table, field } => {
                        tracing::warn!("Quarantining op for unknown field: {table}.{field}");
                    }
                }
                quarantined.push(QuarantinedChange { op: op.clone(), reason });
                continue;
            }

            // Idempotency check: skip already-applied ops
            if is_op_applied(&op.op_id)? {
                continue;
            }

            // Bulk reset is handled specially by the caller
            if op.is_bulk_reset() {
                winners.insert(op.op_id.clone(), WinningOp { op: op.clone(), is_bulk_reset: true });
                continue;
            }

            // `is_deleted` is ABSORBING, not HLC-LWW: an incoming `true` always
            // beats `false` and `false` never overrides `true`, so a delete is
            // terminal regardless of HLC, batch grouping, or arrival order
            // (`true ∨ false = true` is a convergent join). The sender strips
            // `is_deleted = false` so honest peers never emit it; this is the
            // receiver backstop. Effective state = the in-batch winner if any,
            // else the persisted version.
            let is_deleted_key = format!("{}:{}:is_deleted", op.entity_table, op.entity_id);
            let current_deleted: Option<CrdtChange> =
                if let Some(bw) = batch_winners.get(&is_deleted_key) {
                    Some(bw.clone())
                } else {
                    get_field_version(sync_id, &op.entity_table, &op.entity_id, "is_deleted")?
                        .map(|fv| {
                            field_version_to_change(fv, &op.entity_table, &op.entity_id, "is_deleted")
                        })
                };
            // NULL/absent counts as a tombstone (defensive default); only an
            // explicit "false" is live.
            let is_tombstoned =
                current_deleted.as_ref().map(|c| c.encoded_value != "false").unwrap_or(false);

            // A delete subsumes every other field: drop non-`is_deleted` ops on a
            // tombstoned entity.
            if op.field_name != "is_deleted" && is_tombstoned {
                continue;
            }

            let field_key = format!("{}:{}:{}", op.entity_table, op.entity_id, op.field_name);

            let op_wins = if op.field_name == "is_deleted" {
                match &current_deleted {
                    None => true,
                    Some(cur) => {
                        let incoming_true = op.encoded_value == "true";
                        let current_true = cur.encoded_value != "false";
                        match (incoming_true, current_true) {
                            (true, false) => true,  // true absorbs false, any HLC
                            (false, true) => false, // false never beats a tombstone
                            _ => op.wins_over(cur)?, // same value: HLC tiebreak
                        }
                    }
                }
            } else {
                // Plain per-field LWW: in-batch winner first, then persisted.
                let current_winner: Option<CrdtChange> =
                    if let Some(bw) = batch_winners.get(&field_key) {
                        Some(bw.clone())
                    } else {
                        get_field_version(sync_id, &op.entity_table, &op.entity_id, &op.field_name)?
                            .map(|fv| {
                                field_version_to_change(
                                    fv,
                                    &op.entity_table,
                                    &op.entity_id,
                                    &op.field_name,
                                )
                            })
                    };
                match &current_winner {
                    Some(cw) => op.wins_over(cw)?,
                    None => true, // no current winner, this op wins by default
                }
            };

            if !op_wins {
                continue;
            }

            // This op wins -- remove any previous in-batch winner from winners map
            if let Some(prev_bw) = batch_winners.get(&field_key) {
                winners.remove(&prev_bw.op_id);
            }

            // Record this op as the new winner
            winners.insert(op.op_id.clone(), WinningOp { op: op.clone(), is_bulk_reset: false });
            batch_winners.insert(field_key, op.clone());
        }

        Ok(MergeOutcome { winners, quarantined })
    }
}
