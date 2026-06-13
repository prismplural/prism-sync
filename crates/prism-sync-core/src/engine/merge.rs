use std::collections::HashMap;

use crate::crdt_change::CrdtChange;
use crate::error::Result;
use crate::schema::SyncSchema;
use crate::storage::{is_tombstone_value, FieldVersion};

/// A winning operation from the merge process.
#[derive(Debug, Clone)]
pub struct WinningOp {
    pub op: CrdtChange,
}

/// Reason an op was quarantined into `quarantined_ops` (the per-op, replayable
/// lane) rather than applied.
///
/// The first two are schema-driven (the client doesn't know the table/field
/// yet). `FutureHlc` and `UnsupportedBulkReset` are added by the
/// pull-failure discipline so the per-op quarantine lane carries every
/// deferrable op-level failure, not only schema-unknown ones; both have a
/// canonical `as_str()` reason string that round-trips through the
/// `quarantined_ops.reason` TEXT column and drives reason-aware replay
/// eligibility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaQuarantineReason {
    UnknownTable(String),
    UnknownField { table: String, field: String },
    /// The op's HLC is further in the future than the receiver's drift
    /// tolerance. Deferred (not dropped) and replayed with its ORIGINAL HLC
    /// once the local clock catches up — convergence must not depend on which
    /// peer pulled when. Canonical reason string: `future_hlc` (shared by the
    /// pull filter and the snapshot gate).
    FutureHlc,
    /// A `_bulk_reset` sentinel op that this build has no handler for. Held
    /// durably so a future build that implements the table-clear can replay it,
    /// instead of recording it applied as a no-op. Reason string:
    /// `unsupported_bulk_reset`.
    UnsupportedBulkReset,
}

impl SchemaQuarantineReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UnknownTable(_) => "unknown_table",
            Self::UnknownField { .. } => "unknown_field",
            Self::FutureHlc => "future_hlc",
            Self::UnsupportedBulkReset => "unsupported_bulk_reset",
        }
    }
}

/// An op that must be retried after the host upgrades its schema.
#[derive(Debug, Clone)]
pub struct QuarantinedChange {
    pub op: CrdtChange,
    pub reason: SchemaQuarantineReason,
}

/// The current `field_versions` winner for a quarantined op's target field,
/// needed to evaluate the future-HLC supersede rule. Carries only the two
/// columns the rule reads.
#[derive(Debug, Clone)]
pub struct ReplayWinnerContext {
    pub winning_device_id: String,
    pub winning_hlc: String,
}

/// Reason-aware replay eligibility for a per-op quarantine row, replacing the
/// blanket "schema now knows it" filter.
///
/// `reason` is the persisted `quarantined_ops.reason` string; `schema_known` is
/// the caller's precomputed `schema_quarantine_reason(op).is_none()`. The other
/// inputs are only consulted by the arms that need them, so callers that only
/// have schema info can pass conservative defaults for the rest.
///
/// - `unknown_table` / `unknown_field` (and any legacy/unrecognized reason):
///   eligible iff the schema now knows the op's table+field.
/// - `future_hlc`: eligible once the op's HLC is within `max_clock_drift_ms` of
///   local wall-clock time AND the schema knows the op's table+field — *unless*
///   it was superseded. A later-applied op from the SAME device
///   targeting the SAME field evicts the quarantined future-HLC op (it can never
///   win LWW, so replaying it would only resurrect stale state);
///   `superseding_winner` carries that current winner. Returns `false` while
///   still beyond tolerance (no replay churn). The `schema_known` requirement is
///   load-bearing: a future-HLC op whose field is also schema-unknown would
///   otherwise pass this gate once drift decays, then be skipped by
///   `replay_quarantined_ops`'s checked-apply loop (which filters on
///   `schema_quarantine_reason(op).is_some()`) yet still have its quarantine row
///   deleted in Phase C — permanently losing the op (the cursor is already past
///   its batch). Gating on `schema_known` keeps every gate-passing op applicable.
/// - `unsupported_bulk_reset`: never eligible in this build (no handler exists);
///   a future build that implements the table-clear flips this.
pub fn is_replay_eligible(
    reason: &str,
    op: &CrdtChange,
    schema_known: bool,
    max_clock_drift_ms: i64,
    superseding_winner: Option<&ReplayWinnerContext>,
) -> bool {
    match reason {
        "future_hlc" => {
            // A future-HLC op whose table/field is still schema-unknown cannot be
            // applied by the replay loop; admitting it would only delete its
            // quarantine row without applying it. Keep it quarantined until BOTH
            // conditions (schema-known + within drift) hold.
            if !schema_known {
                return false;
            }
            // Supersede: a later op from this same device already won this
            // field, so the quarantined op is dead on arrival — evict it.
            if let Some(winner) = superseding_winner {
                if winner.winning_device_id == op.device_id {
                    if let (Ok(winner_hlc), Ok(op_hlc)) = (
                        crate::hlc::Hlc::from_string(&winner.winning_hlc),
                        crate::hlc::Hlc::from_string(&op.client_hlc),
                    ) {
                        if winner_hlc > op_hlc {
                            return false;
                        }
                    }
                }
            }
            match crate::hlc::Hlc::from_string(&op.client_hlc) {
                Ok(hlc) => hlc.future_drift_ms() <= max_clock_drift_ms.max(0),
                // An unparseable HLC can never merge; leave it quarantined.
                Err(_) => false,
            }
        }
        "unsupported_bulk_reset" => false,
        // unknown_table / unknown_field / legacy reasons: replay once the
        // schema knows the op's table+field.
        _ => schema_known,
    }
}

/// Whether a quarantined `future_hlc` op has been permanently superseded and
/// should be evicted (deleted) from `quarantined_ops` rather than held.
///
/// A later-applied op from the SAME device targeting the SAME
/// field beats the quarantined future-HLC op under LWW (a higher HLC always
/// wins, and HLCs from one device advance monotonically), so the quarantined op
/// can never become the winner — replaying it once the clock catches up would
/// only churn the merge engine to lose. Evicting it bounds the quarantine
/// backlog (a clock-excursion device can otherwise pile up rows that are
/// re-evaluated, never applied, every cycle) and matches the 00db70a
/// drop-superseded precedent. Returns `false` for any non-future-HLC reason and
/// when there is no current winner or it came from a different device / has a
/// lower HLC.
pub fn future_hlc_superseded(
    reason: &str,
    op: &CrdtChange,
    superseding_winner: Option<&ReplayWinnerContext>,
) -> bool {
    if reason != "future_hlc" {
        return false;
    }
    let Some(winner) = superseding_winner else {
        return false;
    };
    if winner.winning_device_id != op.device_id {
        return false;
    }
    match (
        crate::hlc::Hlc::from_string(&winner.winning_hlc),
        crate::hlc::Hlc::from_string(&op.client_hlc),
    ) {
        (Ok(winner_hlc), Ok(op_hlc)) => winner_hlc > op_hlc,
        _ => false,
    }
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

        // `_bulk_reset` is documented always-allowed wire vocabulary, but this
        // build has no handler that performs the table-clear. Route it
        // through the per-op quarantine lane so it is held durably (replayable
        // by a future build) instead of recorded applied as a no-op. This check
        // is ahead of the unknown-field check so every existing
        // `schema_quarantine_reason(op).is_some()` gate (ops_checked builders,
        // replay filter) excludes it automatically.
        if op.is_bulk_reset() {
            return Some(SchemaQuarantineReason::UnsupportedBulkReset);
        }

        if op.field_name != "is_deleted" && entity_def.field_by_name(&op.field_name).is_none() {
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
                    // FutureHlc / UnsupportedBulkReset are not produced by
                    // `schema_quarantine_reason` in this (infra-only) build —
                    // the future-HLC / bulk-reset routing that returns them lands later. The
                    // arms exist so the enum match stays exhaustive.
                    SchemaQuarantineReason::FutureHlc => {
                        tracing::warn!("Quarantining future-HLC op: {}", op.op_id);
                    }
                    SchemaQuarantineReason::UnsupportedBulkReset => {
                        tracing::warn!("Quarantining unsupported _bulk_reset op: {}", op.op_id);
                    }
                }
                quarantined.push(QuarantinedChange { op: op.clone(), reason });
                continue;
            }

            // Idempotency check: skip already-applied ops
            if is_op_applied(&op.op_id)? {
                continue;
            }

            // `_bulk_reset` ops never reach here: `schema_quarantine_reason`
            // returns `UnsupportedBulkReset` for them above, so they were
            // quarantined and `continue`d. No build-side handler exists yet.

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
            let is_tombstoned = current_deleted
                .as_ref()
                .map(|c| is_tombstone_value(Some(c.encoded_value.as_str())))
                .unwrap_or(false);

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
                        let current_true = is_tombstone_value(Some(cur.encoded_value.as_str()));
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
            winners.insert(op.op_id.clone(), WinningOp { op: op.clone() });
            batch_winners.insert(field_key, op.clone());
        }

        Ok(MergeOutcome { winners, quarantined })
    }
}

#[cfg(test)]
mod replay_eligibility_tests {
    use super::*;
    use crate::hlc::Hlc;

    const DRIFT_MS: i64 = 60_000;

    /// Build an op whose HLC is `offset_ms` relative to local wall clock
    /// (positive = future), authored by `device`.
    fn op_with_drift(device: &str, offset_ms: i64) -> CrdtChange {
        let ts = Hlc::now_ms() + offset_ms;
        CrdtChange::new(
            Some("op-1".to_string()),
            None,
            "ent-1".to_string(),
            "members".to_string(),
            "name".to_string(),
            Some("\"v\"".to_string()),
            Some(format!("{ts}:0:{device}")),
            false,
            Some(device.to_string()),
            Some(0),
            None,
        )
    }

    fn winner(device: &str, hlc_ts_ms: i64) -> ReplayWinnerContext {
        ReplayWinnerContext {
            winning_device_id: device.to_string(),
            winning_hlc: format!("{hlc_ts_ms}:0:{device}"),
        }
    }

    #[test]
    fn future_hlc_eligible_once_within_tolerance() {
        // 10s in the past relative to local clock → drift is negative → eligible.
        // A real future_hlc op always targets a schema-known field (that is how
        // the sender emitted it), so pass schema_known=true for these arms.
        let op = op_with_drift("dev-a", -10_000);
        assert!(is_replay_eligible("future_hlc", &op, true, DRIFT_MS, None));
    }

    #[test]
    fn future_hlc_not_eligible_while_beyond_tolerance() {
        // 5 minutes in the future → still beyond the 60s bound → no replay churn.
        let op = op_with_drift("dev-a", 300_000);
        assert!(!is_replay_eligible("future_hlc", &op, true, DRIFT_MS, None));
    }

    #[test]
    fn future_hlc_with_unknown_field_stays_quarantined() {
        // Even within tolerance, a future_hlc op whose field is schema-unknown
        // must NOT be eligible: the replay loop would skip it (schema-unknown)
        // yet Phase C would delete its quarantine row → permanent loss. The
        // schema_known guard prevents that.
        let op = op_with_drift("dev-a", -10_000);
        assert!(!is_replay_eligible("future_hlc", &op, false, DRIFT_MS, None));
    }

    #[test]
    fn future_hlc_boundary_at_tolerance_is_eligible() {
        // Just inside the bound (drift <= max). Subtract a slop so the wall-clock
        // tick between op construction and the check can't push it over.
        let op = op_with_drift("dev-a", DRIFT_MS - 5_000);
        assert!(is_replay_eligible("future_hlc", &op, true, DRIFT_MS, None));
    }

    #[test]
    fn future_hlc_superseded_by_later_same_device_op_is_evicted() {
        // The op is within tolerance, but the same device already won this field
        // with a strictly-later HLC → the quarantined op can never win LWW, so it
        // is evicted (supersede rule).
        let op = op_with_drift("dev-a", -10_000);
        let op_ts: i64 = op.client_hlc.split(':').next().unwrap().parse().unwrap();
        let later = winner("dev-a", op_ts + 1_000);
        assert!(!is_replay_eligible("future_hlc", &op, true, DRIFT_MS, Some(&later)));
    }

    #[test]
    fn future_hlc_not_superseded_by_other_device_winner() {
        // A later winner from a DIFFERENT device does not evict: the quarantined
        // op may still legitimately win LWW once its clock-drift decays.
        let op = op_with_drift("dev-a", -10_000);
        let op_ts: i64 = op.client_hlc.split(':').next().unwrap().parse().unwrap();
        let other = winner("dev-b", op_ts + 1_000);
        assert!(is_replay_eligible("future_hlc", &op, true, DRIFT_MS, Some(&other)));
    }

    #[test]
    fn future_hlc_not_superseded_when_winner_hlc_is_lower() {
        // Same device, but the recorded winner predates the quarantined op → not
        // actually superseding → the op stays eligible.
        let op = op_with_drift("dev-a", -10_000);
        let op_ts: i64 = op.client_hlc.split(':').next().unwrap().parse().unwrap();
        let earlier = winner("dev-a", op_ts - 1_000);
        assert!(is_replay_eligible("future_hlc", &op, true, DRIFT_MS, Some(&earlier)));
    }

    #[test]
    fn future_hlc_unparseable_stays_quarantined() {
        let mut op = op_with_drift("dev-a", -10_000);
        op.client_hlc = "not-an-hlc".to_string();
        assert!(!is_replay_eligible("future_hlc", &op, true, DRIFT_MS, None));
    }

    #[test]
    fn unsupported_bulk_reset_never_eligible() {
        let op = op_with_drift("dev-a", -10_000);
        // Even with schema known, this build has no handler → never replays.
        assert!(!is_replay_eligible("unsupported_bulk_reset", &op, true, DRIFT_MS, None));
    }

    #[test]
    fn schema_reasons_gate_on_schema_known() {
        let op = op_with_drift("dev-a", -10_000);
        for reason in ["unknown_table", "unknown_field"] {
            assert!(
                is_replay_eligible(reason, &op, true, DRIFT_MS, None),
                "{reason} should replay once schema knows it"
            );
            assert!(
                !is_replay_eligible(reason, &op, false, DRIFT_MS, None),
                "{reason} should stay quarantined while schema unknown"
            );
        }
    }

    #[test]
    fn unrecognized_reason_falls_back_to_schema_known() {
        // A legacy/unknown reason string is treated like the schema arms so an
        // older quarantine row can never wedge replay.
        let op = op_with_drift("dev-a", -10_000);
        assert!(is_replay_eligible("some_future_reason", &op, true, DRIFT_MS, None));
        assert!(!is_replay_eligible("some_future_reason", &op, false, DRIFT_MS, None));
    }

    #[test]
    fn schema_quarantine_reason_strings_round_trip() {
        assert_eq!(SchemaQuarantineReason::FutureHlc.as_str(), "future_hlc");
        assert_eq!(
            SchemaQuarantineReason::UnsupportedBulkReset.as_str(),
            "unsupported_bulk_reset"
        );
    }

    #[test]
    fn future_hlc_superseded_only_for_later_same_device_winner() {
        let op = op_with_drift("dev-a", -10_000);
        let op_ts: i64 = op.client_hlc.split(':').next().unwrap().parse().unwrap();

        // Later op from the SAME device → superseded (evict).
        let later = winner("dev-a", op_ts + 1_000);
        assert!(future_hlc_superseded("future_hlc", &op, Some(&later)));

        // Later op from a DIFFERENT device → not superseded.
        let other = winner("dev-b", op_ts + 1_000);
        assert!(!future_hlc_superseded("future_hlc", &op, Some(&other)));

        // Same device but earlier HLC → not superseding.
        let earlier = winner("dev-a", op_ts - 1_000);
        assert!(!future_hlc_superseded("future_hlc", &op, Some(&earlier)));

        // No current winner → not superseded.
        assert!(!future_hlc_superseded("future_hlc", &op, None));

        // Non-future-HLC reasons never report superseded (eviction is a
        // future-HLC-only policy).
        assert!(!future_hlc_superseded("unknown_field", &op, Some(&later)));
    }
}

#[cfg(test)]
mod bulk_reset_tests {
    use super::*;
    use crate::crdt_change::BULK_RESET_FIELD;
    use crate::schema::SyncType;

    fn members_schema() -> SyncSchema {
        SyncSchema::builder()
            .entity("members", |e| e.field("name", SyncType::String))
            .build()
    }

    fn op(op_id: &str, field: &str, hlc_ts: i64) -> CrdtChange {
        CrdtChange::new(
            Some(op_id.to_string()),
            Some("batch-1".to_string()),
            "ent-1".to_string(),
            "members".to_string(),
            field.to_string(),
            Some("\"v\"".to_string()),
            Some(format!("{hlc_ts}:0:dev-a")),
            false,
            Some("dev-a".to_string()),
            Some(0),
            None,
        )
    }

    fn no_field_versions(_: &str, _: &str, _: &str, _: &str) -> Result<Option<FieldVersion>> {
        Ok(None)
    }
    fn no_ops_applied(_: &str) -> Result<bool> {
        Ok(false)
    }

    /// A `_bulk_reset` op for a known table is routed to per-op quarantine with
    /// reason `unsupported_bulk_reset` rather than marked applied as a no-op.
    /// The `schema_quarantine_reason` gate is what every applied/replay
    /// path keys off, so it must report the op as quarantine-worthy.
    #[test]
    fn schema_quarantine_reason_flags_bulk_reset() {
        let engine = MergeEngine::new(members_schema());
        let reset = op("op-reset", BULK_RESET_FIELD, 1_000);
        assert_eq!(
            engine.schema_quarantine_reason(&reset),
            Some(SchemaQuarantineReason::UnsupportedBulkReset)
        );
        // A normal field on the same known table is not quarantined.
        let normal = op("op-name", "name", 1_000);
        assert_eq!(engine.schema_quarantine_reason(&normal), None);
    }

    /// `determine_winners_with_quarantine` puts the `_bulk_reset` op in
    /// `outcome.quarantined` (never `winners`), while accompanying replacement
    /// rows still win normally.
    #[test]
    fn determine_winners_quarantines_bulk_reset_and_keeps_replacement_rows() {
        let engine = MergeEngine::new(members_schema());
        let reset = op("op-reset", BULK_RESET_FIELD, 1_000);
        let replacement = op("op-name", "name", 2_000);

        let outcome = engine
            .determine_winners_with_quarantine(
                &[reset, replacement],
                &no_field_versions,
                &no_ops_applied,
                "sync-1",
            )
            .unwrap();

        assert!(
            !outcome.winners.contains_key("op-reset"),
            "bulk reset must never enter the winners map"
        );
        assert!(
            outcome.winners.contains_key("op-name"),
            "replacement rows still win"
        );
        assert_eq!(outcome.quarantined.len(), 1);
        assert_eq!(outcome.quarantined[0].op.op_id, "op-reset");
        assert_eq!(
            outcome.quarantined[0].reason,
            SchemaQuarantineReason::UnsupportedBulkReset
        );
    }
}

#[cfg(test)]
mod backfill_merge_tests {
    use super::*;
    use crate::op_emitter::BACKFILL_HLC_TIMESTAMP_MS;
    use crate::schema::SyncType;

    fn schema() -> SyncSchema {
        SyncSchema::builder()
            .entity("members", |e| e.field("name", SyncType::String))
            .build()
    }

    fn change(op_id: &str, hlc_ts: i64, device: &str, value: &str) -> CrdtChange {
        CrdtChange::new(
            Some(op_id.to_string()),
            Some("batch-1".to_string()),
            "ent-1".to_string(),
            "members".to_string(),
            "name".to_string(),
            Some(format!("\"{value}\"")),
            Some(format!("{hlc_ts}:0:{device}")),
            false,
            Some(device.to_string()),
            Some(0),
            None,
        )
    }

    fn no_field_versions(_: &str, _: &str, _: &str, _: &str) -> Result<Option<FieldVersion>> {
        Ok(None)
    }
    fn no_ops_applied(_: &str) -> Result<bool> {
        Ok(false)
    }

    /// A floor-HLC backfill op loses to ANY genuine (fresh-HLC) op for the same
    /// field, no matter which arrives first in the batch — the protection is
    /// purely HLC-level, so order is irrelevant.
    #[test]
    fn floor_backfill_loses_to_fresh_op_regardless_of_arrival_order() {
        let engine = MergeEngine::new(schema());
        let backfill = change("op-backfill", BACKFILL_HLC_TIMESTAMP_MS, "dev-a", "Backfill");
        let fresh = change("op-fresh", crate::hlc::Hlc::now_ms(), "dev-b", "Real");

        for ops in [
            vec![backfill.clone(), fresh.clone()],
            vec![fresh.clone(), backfill.clone()],
        ] {
            let winners = engine
                .determine_winners(&ops, &no_field_versions, &no_ops_applied, "sync-1")
                .unwrap();
            assert!(winners.contains_key("op-fresh"), "fresh op must win");
            assert!(!winners.contains_key("op-backfill"), "floor backfill must lose");
        }
    }

    /// A floor-HLC backfill op loses to a pre-existing field_version winner
    /// (write-if-absent: it only establishes state where none exists).
    #[test]
    fn floor_backfill_loses_to_existing_field_version() {
        let engine = MergeEngine::new(schema());
        let existing = FieldVersion {
            sync_id: "sync-1".to_string(),
            entity_table: "members".to_string(),
            entity_id: "ent-1".to_string(),
            field_name: "name".to_string(),
            winning_op_id: "op-existing".to_string(),
            winning_device_id: "dev-c".to_string(),
            winning_hlc: format!("{}:0:dev-c", crate::hlc::Hlc::now_ms() - 1_000),
            winning_encoded_value: Some("\"Existing\"".to_string()),
            updated_at: chrono::Utc::now(),
        };
        let get_fv = |_: &str, _: &str, _: &str, _: &str| Ok(Some(existing.clone()));

        let backfill = change("op-backfill", BACKFILL_HLC_TIMESTAMP_MS, "dev-a", "Backfill");
        let winners = engine
            .determine_winners(&[backfill], &get_fv, &no_ops_applied, "sync-1")
            .unwrap();
        assert!(winners.is_empty(), "backfill must not beat an existing winner");
    }

    /// Two devices backfilling the same field at the floor converge on the same
    /// winner (deterministic node_id/op_id tiebreak), independent of order.
    #[test]
    fn concurrent_floor_backfills_converge_deterministically() {
        let engine = MergeEngine::new(schema());
        let a = change("op-a", BACKFILL_HLC_TIMESTAMP_MS, "dev-a", "FromA");
        let b = change("op-b", BACKFILL_HLC_TIMESTAMP_MS, "dev-b", "FromB");

        let forward = engine
            .determine_winners(&[a.clone(), b.clone()], &no_field_versions, &no_ops_applied, "sync-1")
            .unwrap();
        let reverse = engine
            .determine_winners(&[b, a], &no_field_versions, &no_ops_applied, "sync-1")
            .unwrap();

        let forward_winner: Vec<&String> = forward.keys().collect();
        let reverse_winner: Vec<&String> = reverse.keys().collect();
        assert_eq!(forward_winner, reverse_winner, "winner is order-independent");
        // dev-b > dev-a lexicographically at equal HLC, so op-b wins.
        assert!(forward.contains_key("op-b"));
    }
}
