//! Single source of truth for the receiver-side clock-drift tolerance, plus the
//! shared HLC-vs-wall-clock policy the clock-robustness work builds on.
//!
//! An HLC further in the future than this bound is treated as out-of-tolerance:
//! the pull filter defers it to quarantine instead of applying it, and the local
//! emitter refuses to inherit it as a watermark. The same number gates both
//! decisions, so it must come from one place — previously the value was
//! duplicated as `SyncConfig::max_clock_drift_ms`'s default and
//! `op_emitter::MAX_INHERITABLE_FUTURE_HLC_DRIFT_MS`, which could silently
//! diverge.
//!
//! This module also carries the clock-robustness surface:
//! - typed entry-gate helpers ([`is_excessively_future`], [`max_inheritable`])
//!   that take an explicit `now_ms` so the gate decision is testable without a
//!   real wall clock,
//! - a [`ClockConfidence`] hook the sync service stamps on every successful
//!   signed relay exchange — the excursion repair only runs while
//!   [`ClockConfidence::clock_recently_validated`] holds, which proves the local
//!   clock is within the bound of relay time (a backward step would 401 on the
//!   relay's symmetric skew check and never refresh confidence), and
//! - [`sort_batch_ids_by_typed_hlc`], the typed min-HLC push-queue order used
//!   instead of wall-clock `created_at`.

use std::time::Instant;

use crate::hlc::Hlc;

/// Maximum future drift, in milliseconds, a received HLC may carry before the
/// receiver treats it as out-of-tolerance. 60 seconds.
pub const MAX_CLOCK_DRIFT_MS: i64 = 60_000;

/// How far `hlc` sits in the future of `now_ms`, clamped to 0 for past/current
/// timestamps (old data is always legal in a CRDT).
///
/// Unlike [`Hlc::future_drift_ms`], `now_ms` is explicit so callers gate on a
/// single captured "now" and tests can pin it.
pub fn future_drift_ms(hlc: &Hlc, now_ms: i64) -> i64 {
    hlc.timestamp.saturating_sub(now_ms).max(0)
}

/// Whether `hlc` is further in the future than the drift bound allows.
///
/// Boundary is inclusive of the bound (drift exactly `bound_ms` is accepted),
/// matching [`Hlc::is_drift_exceeded`]'s `> bound` semantics so the entry gates
/// and the emitter inheritance check agree on the edge case.
pub fn is_excessively_future(hlc: &Hlc, now_ms: i64, bound_ms: i64) -> bool {
    future_drift_ms(hlc, now_ms) > bound_ms.max(0)
}

/// Pick the greatest candidate that is not excessively future, by `Hlc::Ord`.
///
/// Used by watermark inheritance: a near-future candidate (≤ bound ahead) is a
/// legitimate causal predecessor the emitter must not fall behind, while an
/// over-bound one is dropped here rather than poisoning the watermark. Returns
/// `None` when every candidate is over-bound (or the slice is empty).
pub fn max_inheritable(candidates: &[Hlc], now_ms: i64, bound_ms: i64) -> Option<Hlc> {
    candidates
        .iter()
        .filter(|hlc| !is_excessively_future(hlc, now_ms, bound_ms))
        .max()
        .cloned()
}

/// Order push-queue batches by their typed minimum HLC, not wall-clock time.
///
/// `batches` is `(batch_id, min_client_hlc, min_created_at)` — the per-batch
/// minimums a `GROUP BY local_batch_id` produces. Per-device HLCs are monotonic
/// across ticks regardless of how the wall clock moves, so sorting on the parsed
/// HLC (with `created_at` then `batch_id` as deterministic tiebreakers) yields
/// true emission order even after a backward clock step — which a lexical
/// `MIN(created_at)` sort gets wrong (a blob update can sort before the
/// entity create and the receiver silently drops the row).
///
/// HLC strings are compared via [`Hlc::Ord`], so `:9` sorts before `:10` as
/// intended. A row whose HLC fails to parse (should never happen for locally
/// minted ops) sorts last so it cannot jump ahead of a well-formed create.
pub fn sort_batch_ids_by_typed_hlc(mut batches: Vec<(String, String, String)>) -> Vec<String> {
    batches.sort_by(|a, b| {
        let a_hlc = Hlc::from_string(&a.1).ok();
        let b_hlc = Hlc::from_string(&b.1).ok();
        // None (unparseable) sorts after Some so malformed rows go last.
        match (a_hlc, b_hlc) {
            (Some(x), Some(y)) => x.cmp(&y),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        }
        .then_with(|| a.2.cmp(&b.2))
        .then_with(|| a.0.cmp(&b.0))
    });
    batches.into_iter().map(|(batch_id, _, _)| batch_id).collect()
}

/// Records when the local clock was last corroborated against relay time.
///
/// Any 2xx on a signed relay route proves `|local − relay| ≤ bound`, because the
/// relay rejects signed requests whose timestamp is outside the same symmetric
/// skew window (`SIGNED_REQUEST_MAX_SKEW_SECS`, default 60s). The excursion
/// repair gates on [`clock_recently_validated`](Self::clock_recently_validated)
/// so it only fires for a genuine forward excursion (clock now within bound of
/// relay) and never for a backward step (relay would 401 and confidence stays
/// stale).
///
/// Confidence is held as a monotonic [`Instant`] (immune to wall-clock jumps)
/// alongside the wall-clock millis observed at validation, so callers can both
/// age the confidence out and reason about the clock state at validation time.
#[derive(Debug, Default, Clone)]
pub struct ClockConfidence {
    last_validated: Option<(Instant, i64)>,
}

impl ClockConfidence {
    /// A confidence tracker that has never seen a successful signed exchange.
    pub fn new() -> Self {
        Self::default()
    }

    /// Stamp a successful signed relay exchange as of `now`.
    ///
    /// `wall_ms` is the local wall-clock time observed at the exchange; the
    /// monotonic instant is captured here so freshness survives wall-clock jumps.
    pub fn record_validated(&mut self, wall_ms: i64) {
        self.last_validated = Some((Instant::now(), wall_ms));
    }

    /// Whether the local clock was corroborated against the relay within the
    /// drift bound's worth of monotonic time.
    ///
    /// `false` until the first `record_validated`, and again once the last
    /// validation ages past `bound_ms`. Uses the monotonic instant so a clock
    /// step cannot spoof freshness.
    pub fn clock_recently_validated(&self, bound_ms: i64) -> bool {
        match self.last_validated {
            Some((instant, _)) => instant.elapsed().as_millis() as i64 <= bound_ms.max(0),
            None => false,
        }
    }

    /// The wall-clock millis recorded at the most recent validation, if any.
    pub fn last_validated_wall_ms(&self) -> Option<i64> {
        self.last_validated.map(|(_, wall_ms)| wall_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hlc_at(ts: i64, counter: u32) -> Hlc {
        Hlc::new(ts, counter, "devA")
    }

    #[test]
    fn future_drift_clamps_past_to_zero() {
        assert_eq!(future_drift_ms(&hlc_at(900, 0), 1000), 0);
        assert_eq!(future_drift_ms(&hlc_at(1000, 0), 1000), 0);
        assert_eq!(future_drift_ms(&hlc_at(1500, 0), 1000), 500);
    }

    #[test]
    fn is_excessively_future_boundary_is_inclusive_of_bound() {
        let now = 1_000_000;
        // Exactly at the bound: accepted (not excessive).
        assert!(!is_excessively_future(&hlc_at(now + MAX_CLOCK_DRIFT_MS, 0), now, MAX_CLOCK_DRIFT_MS));
        // One ms past the bound: excessive.
        assert!(is_excessively_future(
            &hlc_at(now + MAX_CLOCK_DRIFT_MS + 1, 0),
            now,
            MAX_CLOCK_DRIFT_MS
        ));
        // Well in the past: never excessive.
        assert!(!is_excessively_future(&hlc_at(now - 10 * MAX_CLOCK_DRIFT_MS, 0), now, MAX_CLOCK_DRIFT_MS));
    }

    #[test]
    fn max_inheritable_picks_greatest_non_excessive() {
        let now = 1_000_000;
        let bound = MAX_CLOCK_DRIFT_MS;
        let candidates = vec![
            hlc_at(now - 5_000, 0),            // past, eligible
            hlc_at(now + 10_000, 0),           // near future, eligible (the winner)
            hlc_at(now + bound + 50_000, 0),   // over bound, excluded
        ];
        let picked = max_inheritable(&candidates, now, bound).expect("an eligible candidate");
        assert_eq!(picked.timestamp, now + 10_000);
    }

    #[test]
    fn max_inheritable_none_when_all_excessive_or_empty() {
        let now = 1_000_000;
        let bound = MAX_CLOCK_DRIFT_MS;
        assert!(max_inheritable(&[], now, bound).is_none());
        let all_future = vec![hlc_at(now + bound + 1, 0), hlc_at(now + bound + 1_000, 0)];
        assert!(max_inheritable(&all_future, now, bound).is_none());
    }

    #[test]
    fn max_inheritable_breaks_ties_on_counter_then_node() {
        let now = 1_000_000;
        let bound = MAX_CLOCK_DRIFT_MS;
        let candidates =
            vec![Hlc::new(now + 1_000, 9, "devA"), Hlc::new(now + 1_000, 10, "devA")];
        let picked = max_inheritable(&candidates, now, bound).unwrap();
        // :10 beats :9 via typed Ord, not lexical.
        assert_eq!(picked.counter, 10);
    }

    #[test]
    fn typed_sort_orders_counter_9_before_10_unlike_lexical() {
        // Lexical "..:9.." > "..:10..", so a created_at-keyed sort gets this
        // wrong; the typed sort must place the :9 batch first.
        let batches = vec![
            ("b10".to_string(), "1700000000:10:devA".to_string(), "c0".to_string()),
            ("b9".to_string(), "1700000000:9:devA".to_string(), "c1".to_string()),
        ];
        assert_eq!(sort_batch_ids_by_typed_hlc(batches), vec!["b9", "b10"]);
    }

    #[test]
    fn typed_sort_ignores_backward_created_at_step() {
        // Create batch emitted first (HLC ts 100) with a normal created_at;
        // a later update (HLC ts 101) carries an EARLIER created_at after a
        // backward clock step. Emission order (HLC) must still win.
        let batches = vec![
            ("update".to_string(), "101:0:devA".to_string(), "00000000".to_string()),
            ("create".to_string(), "100:0:devA".to_string(), "99999999".to_string()),
        ];
        assert_eq!(sort_batch_ids_by_typed_hlc(batches), vec!["create", "update"]);
    }

    #[test]
    fn typed_sort_pushes_malformed_hlc_last() {
        let batches = vec![
            ("bad".to_string(), "not-an-hlc".to_string(), "c0".to_string()),
            ("good".to_string(), "100:0:devA".to_string(), "c1".to_string()),
        ];
        assert_eq!(sort_batch_ids_by_typed_hlc(batches), vec!["good", "bad"]);
    }

    #[test]
    fn clock_confidence_fresh_until_aged_out() {
        let mut conf = ClockConfidence::new();
        // Never validated.
        assert!(!conf.clock_recently_validated(MAX_CLOCK_DRIFT_MS));
        assert!(conf.last_validated_wall_ms().is_none());

        conf.record_validated(1_700_000_000_000);
        // Just validated: fresh within any non-negative bound.
        assert!(conf.clock_recently_validated(MAX_CLOCK_DRIFT_MS));
        assert_eq!(conf.last_validated_wall_ms(), Some(1_700_000_000_000));
        // A zero-length window is already "aged out" for a non-instantaneous
        // elapsed, but the just-recorded instant has ~0 elapsed so it holds.
        assert!(conf.clock_recently_validated(0));
    }

    #[test]
    fn clock_confidence_stale_after_window_elapses() {
        let mut conf = ClockConfidence::new();
        conf.record_validated(1_700_000_000_000);
        // Force the monotonic instant to look old by validating, then sleeping
        // past a tiny bound. Use a 1ms bound and a 5ms sleep to keep the test
        // fast and deterministic.
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(!conf.clock_recently_validated(1));
    }
}
