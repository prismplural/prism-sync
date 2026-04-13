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

use std::collections::HashMap;

use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;

use prism_sync_core::engine::MergeEngine;
use prism_sync_core::schema::{SyncSchema, SyncType};
use prism_sync_core::storage::FieldVersion;
use prism_sync_core::CrdtChange;

use common::*;

// ═══════════════════════════════════════════════════════════════════════════
// Arbitrary strategy for generating valid CRDT operations
// ═══════════════════════════════════════════════════════════════════════════

/// Generate a valid HLC string with bounded timestamps and counters.
fn arb_hlc() -> impl Strategy<Value = (i64, u32, String)> {
    (
        1000_i64..100_000,    // timestamp range (bounded, avoids overflow)
        0_u32..100,           // counter range
        "[a-z]{4}",           // node_id (short, deterministic-length)
    )
}

/// Generate a device_id string.
fn arb_device_id() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("dev-a".to_string()),
        Just("dev-b".to_string()),
        Just("dev-c".to_string()),
    ]
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
        .prop_map(
            |((ts, counter, node_id), device_id, value, field, entity_id)| {
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
            },
        )
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
        .entity("tasks", |e| {
            e.field("title", SyncType::String)
                .field("done", SyncType::Bool)
        })
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

    let winners = merge
        .determine_winners(ops, &no_field_versions, &no_ops_applied, SYNC_ID)
        .unwrap();

    let mut outcome: HashMap<(String, String), (String, String, String, String)> = HashMap::new();
    for winner in winners.values() {
        if winner.is_bulk_reset {
            continue;
        }
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
    let winners_a = merge
        .determine_winners(ops_a, &no_field_versions, &no_ops_applied, SYNC_ID)
        .unwrap();

    // Build field versions from winners_a
    let mut field_versions: HashMap<String, FieldVersion> = HashMap::new();
    for winner in winners_a.values() {
        if winner.is_bulk_reset {
            continue;
        }
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
    let applied_ops: std::collections::HashSet<String> =
        winners_a.keys().cloned().collect();

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

    let winners_b = merge
        .determine_winners(ops_b, &get_fv, &is_applied, SYNC_ID)
        .unwrap();

    // Build final outcome: start from winners_a, overwrite with winners_b
    let mut outcome: HashMap<(String, String), (String, String, String, String)> = HashMap::new();
    for winner in winners_a.values().chain(winners_b.values()) {
        if winner.is_bulk_reset {
            continue;
        }
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
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
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
// Property 2: Idempotency — merge(a, a) == a
// ═══════════════════════════════════════════════════════════════════════════

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 500,
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
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
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
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
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
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
        failure_persistence: Some(Box::new(FileFailurePersistence::Off)),
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
            if winner.is_bulk_reset {
                continue;
            }
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
