//! Single source of truth for the receiver-side clock-drift tolerance.
//!
//! An HLC further in the future than this bound is treated as out-of-tolerance:
//! the pull filter defers it to quarantine instead of applying it, and the local
//! emitter refuses to inherit it as a watermark. The same number gates both
//! decisions, so it must come from one place — previously the value was
//! duplicated as `SyncConfig::max_clock_drift_ms`'s default and
//! `op_emitter::MAX_INHERITABLE_FUTURE_HLC_DRIFT_MS`, which could silently
//! diverge.
//!
//! The HLC clock-robustness work extends this module with a
//! clock-confidence hook and typed-`Hlc` min/sort helpers; keep additions here
//! rather than reintroducing a second home for the bound.

/// Maximum future drift, in milliseconds, a received HLC may carry before the
/// receiver treats it as out-of-tolerance. 60 seconds.
pub const MAX_CLOCK_DRIFT_MS: i64 = 60_000;
