//! Pull-failure classification for the pull-failure cursor discipline.
//!
//! Every per-batch failure in the pull pipeline (verify -> decrypt -> decode ->
//! filter -> apply) maps to exactly one of two dispositions, so each failure
//! site dispatches uniformly instead of picking an ad-hoc policy (today's
//! silent skip-and-advance, hard-wedge-no-advance, or mark-applied-no-op):
//!
//! - [`PullBatchFailure::Transient`] -> STALL: the cursor does NOT advance, the
//!   relay ack stays behind the batch, push still runs, and the batch is retried
//!   next cycle (bounded by the [`pull_stall`] budget). For conditions that are
//!   expected to clear on their own — a network/5xx registry fetch, a stale
//!   registry that hasn't yet imported the sender, an ML-DSA generation the
//!   receiver hasn't propagated yet.
//!
//! - [`PullBatchFailure::Permanent`] -> QUARANTINE-AND-ADVANCE: the full
//!   `SignedBatchEnvelope` is durably written to `quarantined_pull_batches`, the
//!   cursor advances past it (the relay stays an expiring transport buffer), and
//!   Phase 0b replay re-runs the full pipeline once the blocking condition
//!   clears. For deterministic failures — payload-hash mismatch, undecodable
//!   plaintext, attribution mismatch, an invalid signature under a
//!   generation-matched key — and for a transient condition whose retry budget
//!   has been exhausted.
//!
//! Nothing is ever silently dropped, and no single batch can wedge the group.
//!
//! This is the shared classification the discipline is built around: the
//! per-batch dispatch in `pull_one_page` keys off it, the sender-resolution and
//! stale-generation paths produce `Transient` verdicts that convert to
//! `Permanent` after the retry budget, and Phase 0b replay reads the persisted
//! reason string back.
//!
//! [`pull_stall`]: crate::storage::PullStall

/// The reason a pull batch failed a deterministic, permanent check. The string
/// form is what gets persisted into `quarantined_pull_batches.reason` and read
/// back by reason-aware replay eligibility, so the `as_str` values are stable
/// wire-adjacent identifiers (device-local, but they must round-trip across
/// process restarts and app upgrades).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermanentPullReason {
    /// The decrypted plaintext did not hash to the envelope's declared
    /// payload hash.
    PayloadHashMismatch,
    /// The plaintext decrypted but could not be decoded into a batch (e.g.
    /// cross-version CBOR/JSON skew). Replayable after an app upgrade.
    DecodeFailed,
    /// An op inside the batch was attributed to a device other than the
    /// envelope sender. Whole-batch fail-closed by design.
    AttributionMismatch,
    /// The batch signature failed verification under a generation-matched key —
    /// a genuine cryptographic failure, distinct from a stale-registry
    /// generation mismatch (which is [`TransientPullReason::StaleKeyGeneration`]).
    InvalidSignature,
    /// The sender's keys could not be resolved within the retry budget (a
    /// transient sender-unresolved condition that was converted to permanent).
    SenderUnresolved,
    /// The envelope's ML-DSA generation never matched a resolvable key within
    /// the retry budget (a stale-generation stall converted to permanent).
    StaleKeyGeneration,
    /// The epoch key needed to decrypt the batch is not in the hierarchy. This
    /// quarantines-and-advances rather than
    /// hard-wedging the relay prune floor for the whole group; replay applies it
    /// once the key arrives.
    MissingEpochKey,
}

impl PermanentPullReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PayloadHashMismatch => "payload_hash_mismatch",
            Self::DecodeFailed => "decode_failed",
            Self::AttributionMismatch => "attribution_mismatch",
            Self::InvalidSignature => "invalid_signature",
            Self::SenderUnresolved => "sender_unresolved",
            Self::StaleKeyGeneration => "stale_key_generation",
            Self::MissingEpochKey => "missing_epoch_key",
        }
    }
}

/// The reason a pull batch could not be processed *yet* but is expected to
/// succeed on retry. Drives the `pull_stall` budget; on budget exhaustion the
/// caller converts to the paired [`PermanentPullReason`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransientPullReason {
    /// Resolving the sender's keys failed transiently — network/5xx on the
    /// registry fetch, an ambiguous `Ok(None)`, or a stale artifact missing the
    /// device. Converts to [`PermanentPullReason::SenderUnresolved`].
    SenderUnresolved,
    /// The envelope's ML-DSA generation is ahead of the locally-known registry
    /// (a not-yet-propagated rotation). Converts to
    /// [`PermanentPullReason::StaleKeyGeneration`].
    StaleKeyGeneration,
}

impl TransientPullReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SenderUnresolved => "sender_unresolved",
            Self::StaleKeyGeneration => "stale_key_generation",
        }
    }

    /// The permanent reason this stall converts to once the retry budget is
    /// exhausted (8 sync cycles / 24h).
    pub fn on_budget_exhausted(&self) -> PermanentPullReason {
        match self {
            Self::SenderUnresolved => PermanentPullReason::SenderUnresolved,
            Self::StaleKeyGeneration => PermanentPullReason::StaleKeyGeneration,
        }
    }
}

/// The classification of a single inbound batch's failure: the shared taxonomy
/// that `pull_one_page` dispatches on.
///
/// `Transient` stalls the cursor and retries; `Permanent` durably quarantines
/// the envelope and advances. `pull_one_page` carries the dispatch wiring; this
/// enum is the contract the downstream sender-resolution, stale-generation,
/// future-HLC, and bulk-reset paths build against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PullBatchFailure {
    Transient { reason: TransientPullReason },
    Permanent { reason: PermanentPullReason },
}

impl PullBatchFailure {
    /// The persisted reason string for this failure: the `pull_stall.reason` for
    /// a transient stall, or the `quarantined_pull_batches.reason` for a
    /// permanent quarantine.
    pub fn reason_str(&self) -> &'static str {
        match self {
            Self::Transient { reason } => reason.as_str(),
            Self::Permanent { reason } => reason.as_str(),
        }
    }

    pub fn is_transient(&self) -> bool {
        matches!(self, Self::Transient { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permanent_reason_strings_are_stable() {
        // These strings persist across process restarts and app upgrades, so a
        // change here is a data-migration concern — pin them.
        assert_eq!(PermanentPullReason::PayloadHashMismatch.as_str(), "payload_hash_mismatch");
        assert_eq!(PermanentPullReason::DecodeFailed.as_str(), "decode_failed");
        assert_eq!(PermanentPullReason::AttributionMismatch.as_str(), "attribution_mismatch");
        assert_eq!(PermanentPullReason::InvalidSignature.as_str(), "invalid_signature");
        assert_eq!(PermanentPullReason::SenderUnresolved.as_str(), "sender_unresolved");
        assert_eq!(PermanentPullReason::StaleKeyGeneration.as_str(), "stale_key_generation");
        assert_eq!(PermanentPullReason::MissingEpochKey.as_str(), "missing_epoch_key");
    }

    #[test]
    fn transient_reasons_convert_to_their_permanent_pair() {
        assert_eq!(
            TransientPullReason::SenderUnresolved.on_budget_exhausted().as_str(),
            "sender_unresolved",
        );
        assert_eq!(
            TransientPullReason::StaleKeyGeneration.on_budget_exhausted().as_str(),
            "stale_key_generation",
        );
    }

    #[test]
    fn failure_reason_str_and_transience() {
        let t = PullBatchFailure::Transient { reason: TransientPullReason::SenderUnresolved };
        assert!(t.is_transient());
        assert_eq!(t.reason_str(), "sender_unresolved");

        let p = PullBatchFailure::Permanent { reason: PermanentPullReason::DecodeFailed };
        assert!(!p.is_transient());
        assert_eq!(p.reason_str(), "decode_failed");
    }
}
