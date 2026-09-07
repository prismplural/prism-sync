//! Property-based tests for CRDT merge engine (R20).
//!
//! Validates the three fundamental CRDT properties using `proptest`:
//! 1. **Commutativity**: merge(a, b) == merge(b, a)
//! 2. **Idempotency**: merge(a, a) == a
//! 3. **Associativity**: merge(merge(a, b), c) == merge(a, merge(b, c))
//!
//! The merge engine uses field-level Last-Write-Wins with a 3-level tiebreaker:
//! HLC (timestamp -> counter -> node_id) -> device_id -> op_id.

mod common;

use std::collections::{HashMap, HashSet};
use std::path::Path;

use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;
use rusqlite::Connection;

use prism_sync_core::engine::MergeEngine;
use prism_sync_core::schema::{SyncSchema, SyncType};
use prism_sync_core::storage::{AppliedOp, FieldVersion, RusqliteSyncStorage, SyncStorage};
use prism_sync_core::CrdtChange;

use common::*;

// ═══════════════════════════════════════════════════════════════════════════
// Arbitrary strategy for generating valid CRDT operations
// ═══════════════════════════════════════════════════════════════════════════

/// Generate a valid HLC string with bounded timestamps and counters.
fn arb_hlc() -> impl Strategy<Value = (i64, u32, String)> {
    (
        1000_i64..100_000, // timestamp range (bounded, avoids overflow)
        0_u32..100,        // counter range
        "[a-z]{4}",        // node_id (short, deterministic-length)
    )
}

/// Generate a device_id string.
fn arb_device_id() -> impl Strategy<Value = String> {
    prop_oneof![Just("dev-a".to_string()), Just("dev-b".to_string()), Just("dev-c".to_string()),]
}

/// Generate an encoded field value.
fn arb_encoded_value() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("\"hello\"".to_string()),
        Just("\"world\"".to_string()),
        Just("\"foo\"".to_string()),
        Just("\"bar\"".to_string()),
        Just("true".to_string()),
        Just("false".to_string()),
    ]
}

/// Generate a single CrdtChange targeting the "tasks" table.
fn arb_op() -> impl Strategy<Value = CrdtChange> {
    (
        arb_hlc(),
        arb_device_id(),
        arb_encoded_value(),
        prop_oneof![Just("title"), Just("done")],
        prop_oneof![Just("t1"), Just("t2")],
    )
        .prop_map(|((ts, counter, node_id), device_id, value, field, entity_id)| {
            let hlc_str = format!("{ts}:{counter}:{node_id}");
            let op_id = format!("tasks:{entity_id}:{field}:{hlc_str}:{device_id}");
            CrdtChange {
                op_id,
                batch_id: Some("batch-1".to_string()),
                entity_id: entity_id.to_string(),
                entity_table: "tasks".to_string(),
                field_name: field.to_string(),
                encoded_value: value,
                client_hlc: hlc_str,
                is_delete: false,
                device_id,
                epoch: 0,
                server_seq: None,
            }
        })
}

/// Generate a batch of 1..8 CrdtChange ops.
fn arb_op_batch() -> impl Strategy<Value = Vec<CrdtChange>> {
    prop::collection::vec(arb_op(), 1..8)
}

// ═══════════════════════════════════════════════════════════════════════════
// Helpers for running the merge engine
// ═══════════════════════════════════════════════════════════════════════════

fn test_merge_schema() -> SyncSchema {
    SyncSchema::builder()
        .entity("tasks", |e| e.field("title", SyncType::String).field("done", SyncType::Bool))
        .build()
}

/// No persisted field versions — all ops are fresh.
fn no_field_versions(
    _sync_id: &str,
    _table: &str,
    _eid: &str,
    _field: &str,
) -> prism_sync_core::Result<Option<FieldVersion>> {
    Ok(None)
}

/// No ops applied yet.
fn no_ops_applied(_op_id: &str) -> prism_sync_core::Result<bool> {
    Ok(false)
}

/// Run the merge engine on a batch and return the winning field values
/// as a normalized map: (entity_id, field_name) -> (encoded_value, hlc, device_id, op_id).
///
/// This is a deterministic representation of the merge outcome that we can
/// compare across different application orders.
fn merge_outcome(
    ops: &[CrdtChange],
) -> HashMap<(String, String), (String, String, String, String)> {
    let schema = test_merge_schema();
    let merge = MergeEngine::new(schema);

    let winners =
        merge.determine_winners(ops, &no_field_versions, &no_ops_applied, SYNC_ID).unwrap();

    let mut outcome: HashMap<(String, String), (String, String, String, String)> = HashMap::new();
    for winner in winners.values() {
        let op = &winner.op;
        let key = (op.entity_id.clone(), op.field_name.clone());
        outcome.insert(
            key,
            (
                op.encoded_value.clone(),
                op.client_hlc.clone(),
                op.device_id.clone(),
                op.op_id.clone(),
            ),
        );
    }
    outcome
}

/// Run merge in two stages: first merge ops_a to get field versions,
/// then merge ops_b against those field versions.
/// Returns the combined outcome.
fn merge_sequential(
    ops_a: &[CrdtChange],
    ops_b: &[CrdtChange],
) -> HashMap<(String, String), (String, String, String, String)> {
    let schema = test_merge_schema();
    let merge = MergeEngine::new(schema);

    // First pass: merge ops_a from scratch
    let winners_a =
        merge.determine_winners(ops_a, &no_field_versions, &no_ops_applied, SYNC_ID).unwrap();

    // Build field versions from winners_a
    let mut field_versions: HashMap<String, FieldVersion> = HashMap::new();
    for winner in winners_a.values() {
        let op = &winner.op;
        let key = format!("{}:{}:{}", op.entity_table, op.entity_id, op.field_name);
        field_versions.insert(
            key,
            FieldVersion {
                sync_id: SYNC_ID.to_string(),
                entity_table: op.entity_table.clone(),
                entity_id: op.entity_id.clone(),
                field_name: op.field_name.clone(),
                winning_op_id: op.op_id.clone(),
                winning_device_id: op.device_id.clone(),
                winning_hlc: op.client_hlc.clone(),
                winning_encoded_value: Some(op.encoded_value.clone()),
                updated_at: chrono::Utc::now(),
            },
        );
    }

    // Collect applied op_ids from winners_a
    let applied_ops: std::collections::HashSet<String> = winners_a.keys().cloned().collect();

    // Second pass: merge ops_b against winners_a as persisted state
    let get_fv = |_sync_id: &str,
                  table: &str,
                  eid: &str,
                  field: &str|
     -> prism_sync_core::Result<Option<FieldVersion>> {
        let key = format!("{table}:{eid}:{field}");
        Ok(field_versions.get(&key).cloned())
    };

    let is_applied =
        |op_id: &str| -> prism_sync_core::Result<bool> { Ok(applied_ops.contains(op_id)) };

    let winners_b = merge.determine_winners(ops_b, &get_fv, &is_applied, SYNC_ID).unwrap();

    // Build final outcome: start from winners_a, overwrite with winners_b
    let mut outcome: HashMap<(String, String), (String, String, String, String)> = HashMap::new();
    for winner in winners_a.values().chain(winners_b.values()) {
        let op = &winner.op;
        let key = (op.entity_id.clone(), op.field_name.clone());
        // For the combined result, the latest winner for each field is correct
        // because winners_b was computed against winners_a state
        let candidate = (
            op.encoded_value.clone(),
            op.client_hlc.clone(),
            op.device_id.clone(),
            op.op_id.clone(),
        );
        // Only insert if this op would actually win (higher HLC/device/op)
        if let Some(existing) = outcome.get(&key) {
            let existing_change = CrdtChange {
                op_id: existing.3.clone(),
                batch_id: None,
                entity_id: op.entity_id.clone(),
                entity_table: op.entity_table.clone(),
                field_name: op.field_name.clone(),
                encoded_value: existing.0.clone(),
                client_hlc: existing.1.clone(),
                is_delete: false,
                device_id: existing.2.clone(),
                epoch: 0,
                server_seq: None,
            };
            if op.wins_over(&existing_change).unwrap_or(false) {
                outcome.insert(key, candidate);
            }
        } else {
            outcome.insert(key, candidate);
        }
    }
    outcome
}

// ═══════════════════════════════════════════════════════════════════════════
// Property 1: Commutativity — merge(a, b) == merge(b, a)
// ═══════════════════════════════════════════════════════════════════════════

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 500,
        failure_persistence: Some(Box::new(FileFailurePersistence::WithSource("proptest-regressions"))),
        .. ProptestConfig::default()
    })]

    /// Merging ops in any order within a single batch produces the same winners.
    ///
    /// This verifies that determine_winners is order-independent: the per-field
    /// LWW tiebreaker always picks the same winner regardless of which op the
    /// engine encounters first.
    #[test]
    fn commutativity_single_batch(ops in arb_op_batch()) {
        let forward = merge_outcome(&ops);

        let mut reversed = ops.clone();
        reversed.reverse();
        let backward = merge_outcome(&reversed);

        prop_assert_eq!(forward, backward,
            "Merge must be commutative: reversing op order within a batch should not change the outcome");
    }

    /// Merging batch A then B produces the same result as batch B then A.
    ///
    /// This is the stronger form of commutativity: two independent batches
    /// from different devices should converge regardless of arrival order.
    #[test]
    fn commutativity_two_batches(
        batch_a in arb_op_batch(),
        batch_b in arb_op_batch(),
    ) {
        let ab = merge_sequential(&batch_a, &batch_b);
        let ba = merge_sequential(&batch_b, &batch_a);

        prop_assert_eq!(ab, ba,
            "Merge must be commutative across batches: merge(A, B) == merge(B, A)");
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Stateful durable delete/replay coverage
// ═══════════════════════════════════════════════════════════════════════════

/// Each transition reopens SQLite; replay resends an earlier operation.
#[derive(Clone, Debug)]
enum StateAction {
    Apply(OperationSpec),
    Replay(u8),
}

#[derive(Clone, Debug)]
struct OperationSpec {
    entity_id: String,
    field_name: String,
    timestamp: i64,
    counter: u32,
    device_id: String,
    epoch: i32,
    is_delete: bool,
}

fn arb_state_action() -> impl Strategy<Value = StateAction> {
    prop_oneof![
        (
            prop_oneof![Just("t1".to_string()), Just("t2".to_string())],
            prop_oneof![
                Just(("title".to_string(), false)),
                Just(("done".to_string(), false)),
                Just(("is_deleted".to_string(), true)),
            ],
            1_i64..100,
            0_u32..8,
            arb_device_id(),
            0_i32..3,
        )
            .prop_map(
                |(entity_id, (field_name, is_delete), timestamp, counter, device_id, epoch)| {
                    StateAction::Apply(OperationSpec {
                        entity_id,
                        field_name,
                        timestamp,
                        counter,
                        device_id,
                        epoch,
                        is_delete,
                    })
                },
            ),
        (0_u8..24).prop_map(StateAction::Replay),
    ]
}

fn state_encoded_value(field_name: &str, timestamp: i64) -> String {
    match field_name {
        "done" => (timestamp % 2 == 0).to_string(),
        _ => format!("\"value-{timestamp}\""),
    }
}

fn state_operation(spec: &OperationSpec) -> CrdtChange {
    let client_hlc = format!("{}:{}:{}", spec.timestamp, spec.counter, spec.device_id);
    let op_id = format!(
        "tasks:{}:{}:{}:{}:e{}",
        spec.entity_id, spec.field_name, client_hlc, spec.device_id, spec.epoch
    );
    CrdtChange {
        op_id,
        batch_id: Some("state-machine".to_string()),
        entity_id: spec.entity_id.clone(),
        entity_table: "tasks".to_string(),
        field_name: spec.field_name.clone(),
        encoded_value: if spec.is_delete {
            "true".to_string()
        } else {
            state_encoded_value(&spec.field_name, spec.timestamp)
        },
        client_hlc,
        is_delete: spec.is_delete,
        device_id: spec.device_id.clone(),
        epoch: spec.epoch,
        server_seq: None,
    }
}

/// Independent LWW oracle; must not call production `wins_over`.
fn independently_wins(candidate: &CrdtChange, current: &CrdtChange) -> bool {
    fn rank(op: &CrdtChange) -> (i64, u32, &str, &str, &str) {
        let mut parts = op.client_hlc.splitn(3, ':');
        let timestamp = parts.next().unwrap().parse().unwrap();
        let counter = parts.next().unwrap().parse().unwrap();
        let node_id = parts.next().unwrap();
        (timestamp, counter, node_id, &op.device_id, &op.op_id)
    }

    rank(candidate) > rank(current)
}

#[derive(Default)]
struct ObservableModel {
    applied: HashSet<String>,
    deleted: HashSet<String>,
    live_fields: HashMap<(String, String), CrdtChange>,
}

impl ObservableModel {
    fn apply(&mut self, op: &CrdtChange) {
        if !self.applied.insert(op.op_id.clone()) {
            return;
        }
        if op.is_delete {
            self.deleted.insert(op.entity_id.clone());
            self.live_fields.retain(|(entity_id, _), _| entity_id != &op.entity_id);
            return;
        }
        if self.deleted.contains(&op.entity_id) {
            return;
        }

        let key = (op.entity_id.clone(), op.field_name.clone());
        match self.live_fields.get(&key) {
            Some(current) if !independently_wins(op, current) => {}
            _ => {
                self.live_fields.insert(key, op.clone());
            }
        }
    }
}

fn open_state_storage(path: &Path) -> Result<RusqliteSyncStorage, String> {
    RusqliteSyncStorage::new(Connection::open(path).map_err(|error| error.to_string())?)
        .map_err(|error| error.to_string())
}

/// Models remote apply: persist all replay markers, but only winning versions.
fn apply_and_persist_state_op(path: &Path, op: &CrdtChange) -> Result<(), String> {
    let storage = open_state_storage(path)?;
    let merge = MergeEngine::new(test_merge_schema());
    let winners = merge
        .determine_winners(
            std::slice::from_ref(op),
            &|sync_id, table, entity_id, field| {
                storage.get_field_version(sync_id, table, entity_id, field)
            },
            &|op_id| storage.is_op_applied(op_id),
            SYNC_ID,
        )
        .map_err(|error| error.to_string())?;

    let already_applied = storage.is_op_applied(&op.op_id).map_err(|error| error.to_string())?;
    let mut tx = storage.begin_tx().map_err(|error| error.to_string())?;
    if !already_applied {
        tx.insert_applied_op(&AppliedOp {
            op_id: op.op_id.clone(),
            sync_id: SYNC_ID.to_string(),
            epoch: op.epoch,
            device_id: op.device_id.clone(),
            client_hlc: op.client_hlc.clone(),
            server_seq: 1,
            applied_at: chrono::Utc::now(),
        })
        .map_err(|error| error.to_string())?;
    }
    for winner in winners.into_values() {
        let winner = winner.op;
        tx.upsert_field_version(&FieldVersion {
            sync_id: SYNC_ID.to_string(),
            entity_table: winner.entity_table.clone(),
            entity_id: winner.entity_id.clone(),
            field_name: winner.field_name.clone(),
            winning_op_id: winner.op_id.clone(),
            winning_device_id: winner.device_id.clone(),
            winning_hlc: winner.client_hlc.clone(),
            winning_encoded_value: Some(winner.encoded_value.clone()),
            updated_at: chrono::Utc::now(),
        })
        .map_err(|error| error.to_string())?;
    }
    tx.commit().map_err(|error| error.to_string())
}

fn assert_observable_state(path: &Path, model: &ObservableModel) -> Result<(), String> {
    let storage = open_state_storage(path)?;
    for entity_id in ["t1", "t2"] {
        let tombstone = storage
            .get_field_version(SYNC_ID, "tasks", entity_id, "is_deleted")
            .map_err(|error| error.to_string())?;
        let actual_deleted = tombstone
            .as_ref()
            .map(|version| version.winning_encoded_value.as_deref() != Some("false"))
            .unwrap_or(false);
        let expected_deleted = model.deleted.contains(entity_id);
        if actual_deleted != expected_deleted {
            return Err(format!(
                "delete state for {entity_id} differed: expected {expected_deleted}, got {actual_deleted}"
            ));
        }

        // Tombstones may retain historical versions; compare only live state.
        if expected_deleted {
            continue;
        }
        for field_name in ["title", "done"] {
            let actual = storage
                .get_field_version(SYNC_ID, "tasks", entity_id, field_name)
                .map_err(|error| error.to_string())?;
            let expected = model.live_fields.get(&(entity_id.to_string(), field_name.to_string()));
            match (actual, expected) {
                (None, None) => {}
                (Some(actual), Some(expected))
                    if actual.winning_op_id == expected.op_id
                        && actual.winning_encoded_value.as_deref()
                            == Some(expected.encoded_value.as_str()) => {}
                (actual, expected) => {
                    return Err(format!(
                        "live field {entity_id}.{field_name} differed: actual={actual:?}, expected={expected:?}"
                    ));
                }
            }
        }
    }
    for op_id in &model.applied {
        if !storage.is_op_applied(op_id).map_err(|error| error.to_string())? {
            return Err(format!("replay marker for {op_id} was lost after reopen"));
        }
    }
    Ok(())
}

fn run_state_machine(actions: &[StateAction]) -> Result<(), String> {
    let temp_dir = tempfile::tempdir().map_err(|error| error.to_string())?;
    let db_path = temp_dir.path().join("state-machine.sqlite");
    {
        let storage = open_state_storage(&db_path)?;
        setup_sync_metadata(&storage, "device-local");
    }

    let mut history = Vec::new();
    let mut model = ObservableModel::default();
    for action in actions {
        let operation = match action {
            StateAction::Apply(spec) => {
                let operation = state_operation(spec);
                history.push(operation.clone());
                Some(operation)
            }
            StateAction::Replay(index) if !history.is_empty() => {
                Some(history[usize::from(*index) % history.len()].clone())
            }
            StateAction::Replay(_) => None,
        };
        if let Some(operation) = operation {
            apply_and_persist_state_op(&db_path, &operation)?;
            model.apply(&operation);
        }
        assert_observable_state(&db_path, &model)?;
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 96,
        failure_persistence: Some(Box::new(FileFailurePersistence::WithSource("proptest-regressions"))),
        .. ProptestConfig::default()
    })]

    /// Sequential replay/reopen contract, not arbitrary tombstone batch ordering.
    #[test]
    fn stateful_delete_replay_and_reopen(actions in prop::collection::vec(arb_state_action(), 1..20)) {
        let result = run_state_machine(&actions);
        prop_assert!(result.is_ok(), "state machine failed: {}", result.unwrap_err());
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Property 2: Idempotency — merge(a, a) == a
// ═══════════════════════════════════════════════════════════════════════════

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 500,
        failure_persistence: Some(Box::new(FileFailurePersistence::WithSource("proptest-regressions"))),
        .. ProptestConfig::default()
    })]

    /// Merging a batch with itself produces the same result as merging once.
    ///
    /// This validates two things:
    /// 1. The in-batch dedup (same op appearing twice) doesn't alter outcomes.
    /// 2. The idempotency check (is_op_applied) correctly skips re-applied ops
    ///    when simulated via merge_sequential.
    #[test]
    fn idempotency_same_batch(ops in arb_op_batch()) {
        let single = merge_outcome(&ops);

        // Duplicate all ops within the same batch
        let mut doubled = ops.clone();
        doubled.extend(ops.clone());
        let dup = merge_outcome(&doubled);

        prop_assert_eq!(single, dup,
            "Merge must be idempotent: merging same ops twice should produce the same outcome");
    }

    /// Merging a batch, then merging the same batch again (with the first
    /// batch's winners as persisted state) should not change the outcome.
    #[test]
    fn idempotency_sequential(ops in arb_op_batch()) {
        let once = merge_outcome(&ops);
        let twice = merge_sequential(&ops, &ops);

        prop_assert_eq!(once, twice,
            "Merge must be idempotent: merge(a) == merge(merge(a), a)");
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Property 3: Associativity — merge(merge(a, b), c) == merge(a, merge(b, c))
// ═══════════════════════════════════════════════════════════════════════════

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 300,
        failure_persistence: Some(Box::new(FileFailurePersistence::WithSource("proptest-regressions"))),
        .. ProptestConfig::default()
    })]

    /// Three batches merged in different groupings converge to the same state.
    ///
    /// Tests: merge(merge(A, B), C) == merge(A, merge(B, C))
    #[test]
    fn associativity_three_batches(
        batch_a in arb_op_batch(),
        batch_b in arb_op_batch(),
        batch_c in arb_op_batch(),
    ) {
        // Left-associated: (A, B), then C
        let ab = merge_sequential(&batch_a, &batch_b);
        // Reconstruct the winning ops as a new batch for the left side
        let ab_ops = reconstruct_ops_from_outcome(&ab);
        let ab_c = merge_sequential(&ab_ops, &batch_c);

        // Right-associated: A, then (B, C)
        let bc = merge_sequential(&batch_b, &batch_c);
        let bc_ops = reconstruct_ops_from_outcome(&bc);
        let a_bc = merge_sequential(&batch_a, &bc_ops);

        prop_assert_eq!(ab_c, a_bc,
            "Merge must be associative: merge(merge(A, B), C) == merge(A, merge(B, C))");
    }
}

/// Reconstruct CrdtChange ops from a merge outcome map.
fn reconstruct_ops_from_outcome(
    outcome: &HashMap<(String, String), (String, String, String, String)>,
) -> Vec<CrdtChange> {
    outcome
        .iter()
        .map(|((entity_id, field_name), (value, hlc, device_id, op_id))| CrdtChange {
            op_id: op_id.clone(),
            batch_id: Some("reconstructed".to_string()),
            entity_id: entity_id.clone(),
            entity_table: "tasks".to_string(),
            field_name: field_name.clone(),
            encoded_value: value.clone(),
            client_hlc: hlc.clone(),
            is_delete: false,
            device_id: device_id.clone(),
            epoch: 0,
            server_seq: None,
        })
        .collect()
}

// ═══════════════════════════════════════════════════════════════════════════
// Additional property: Convergence
// ═══════════════════════════════════════════════════════════════════════════

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 200,
        failure_persistence: Some(Box::new(FileFailurePersistence::WithSource("proptest-regressions"))),
        .. ProptestConfig::default()
    })]

    /// N random permutations of the same op set always converge to the same state.
    ///
    /// This is a stronger convergence test: we shuffle the same ops into
    /// multiple random orderings and verify all produce identical results.
    #[test]
    fn convergence_random_permutations(
        ops in prop::collection::vec(arb_op(), 2..10),
        seed in any::<u64>(),
    ) {
        let reference = merge_outcome(&ops);

        // Test multiple shuffled orderings using a simple deterministic shuffle
        for iteration in 0_u64..5 {
            let mut shuffled = ops.clone();
            // Deterministic Fisher-Yates shuffle using seed + iteration
            let mix = seed.wrapping_add(iteration).wrapping_mul(6364136223846793005);
            let n = shuffled.len();
            for j in (1..n).rev() {
                let k = ((mix.wrapping_mul(j as u64 + 1)) >> 32) as usize % (j + 1);
                shuffled.swap(j, k);
            }

            let result = merge_outcome(&shuffled);
            let iter_str = format!("permutation {}", iteration);
            prop_assert_eq!(&reference, &result,
                "All permutations of the same ops must converge to the same state ({})", iter_str);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Additional property: LWW consistency
// ═══════════════════════════════════════════════════════════════════════════

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 500,
        failure_persistence: Some(Box::new(FileFailurePersistence::WithSource("proptest-regressions"))),
        .. ProptestConfig::default()
    })]

    /// The merge winner for a single field is always the op with the highest
    /// (HLC, device_id, op_id) tuple, validating the LWW tiebreaker.
    #[test]
    fn lww_winner_is_max(ops in prop::collection::vec(arb_op(), 1..6)) {
        let schema = test_merge_schema();
        let merge = MergeEngine::new(schema);

        let winners = merge
            .determine_winners(&ops, &no_field_versions, &no_ops_applied, SYNC_ID)
            .unwrap();

        // For each winning (entity_id, field_name), verify it beats all
        // other ops targeting the same field.
        for winner in winners.values() {
            let w = &winner.op;
            for op in &ops {
                if op.entity_id == w.entity_id
                    && op.field_name == w.field_name
                    && op.op_id != w.op_id
                {
                    prop_assert!(
                        w.wins_over(op).unwrap(),
                        "Winner {:?} should beat {:?} for field {}:{}",
                        w.op_id,
                        op.op_id,
                        w.entity_id,
                        w.field_name,
                    );
                }
            }
        }
    }
}
