use std::time::Duration;

use crate::clock_drift::MAX_CLOCK_DRIFT_MS;
use crate::events::{EntityChange, SyncErrorKind};

/// The current state of the sync engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncState {
    /// No sync operation in progress.
    Idle,
    /// Pulling changes from the relay.
    Pulling,
    /// Merging remote changes with local state.
    Merging,
    /// Pushing local changes to the relay.
    Pushing,
    /// Retrying after a transient error.
    Retrying { attempt: u32 },
    /// Sync halted due to an error.
    Error { message: String },
}

/// Result of a single sync cycle.
#[derive(Debug, Clone)]
pub struct SyncResult {
    /// Number of batches pulled from the relay.
    pub pulled: u64,
    /// Number of ops that won the merge (were applied).
    pub merged: u64,
    /// Number of batches pushed to the relay.
    pub pushed: u64,
    /// Number of local ops and tombstones pruned.
    pub pruned: u64,
    /// Duration of the sync cycle.
    pub duration: Duration,
    /// Error encountered, if any.
    pub error: Option<String>,
    /// Structured classification of `error`, if populated.
    ///
    /// Populated alongside `error` by the engine's pull/push phases so both
    /// the inner retry loop in `SyncService::sync_now` and the UI can
    /// classify failures without string matching. `None` when `error` is
    /// also `None`.
    pub error_kind: Option<SyncErrorKind>,
    /// Error code from a relay failure (e.g. "device_revoked",
    /// "device_identity_mismatch"). Populated alongside `error` when the
    /// failure originated from a `CoreError::Relay` with a `code`.
    ///
    /// Critical for credential-cleanup paths: `device_revoked` responses
    /// arrive during pull/push but get wrapped back into `SyncResult`.
    /// Without this field, the Dart side only sees the stringified error
    /// and can't reliably trigger `_clearSyncCredentials`.
    pub error_code: Option<String>,
    /// Whether the relay also requested a remote wipe, copied from
    /// `CoreError::Relay.remote_wipe`. Only meaningful when
    /// `error_code == Some("device_revoked")`.
    pub remote_wipe: Option<bool>,
    /// Entity changes with full field values from the pull phase.
    ///
    /// Populated when remote changes were merged. Each entry contains
    /// the winning field values grouped by entity. The consumer uses
    /// this to apply changes to its own database (e.g. Drift).
    pub entity_changes: Vec<EntityChange>,
    /// `true` when the push phase stopped at its per-cycle cap
    /// ([`SyncConfig::push_batch_cap`]) with local batches still unsent. The
    /// sync driver re-arms another cycle so the queue keeps draining without
    /// waiting for a new local mutation. Always `false` on error paths.
    pub push_incomplete: bool,
    /// Telemetry: `true` when the relay's log lineage regressed this cycle (a
    /// new `log_token`, or a `cursor_ahead_of_log` response) and the engine reset
    /// the cursor to re-pull surviving + new history. Telemetry-only for this
    /// release — there is no user-facing flow; it lets the host surface that a
    /// relay restore was detected and history was re-fetched.
    pub log_regressed: bool,
    /// `true` when this cycle completed at least one 2xx on a *signed* relay
    /// route (push `PUT /changes`, ack `POST /ack`) — the routes the relay
    /// gates with `verify_signed_request`'s symmetric `X-Prism-Timestamp` skew
    /// check (`SIGNED_REQUEST_MAX_SKEW_SECS`, default 60s, kept in lockstep with
    /// [`crate::clock_drift::MAX_CLOCK_DRIFT_MS`]). A 2xx there proves
    /// `|local − relay| ≤ bound`, so this — and only this — is the relay anchor
    /// the excursion repair gates on. A pull-only cycle (`GET /changes` is
    /// bearer-only, no timestamp/skew check) leaves it `false`, so a backward
    /// clock step never arms the repair. Always `false` on
    /// error paths.
    pub signed_exchange_validated: bool,
}

impl Default for SyncResult {
    fn default() -> Self {
        Self {
            pulled: 0,
            merged: 0,
            pushed: 0,
            pruned: 0,
            duration: Duration::ZERO,
            error: None,
            error_kind: None,
            error_code: None,
            remote_wipe: None,
            entity_changes: Vec::new(),
            push_incomplete: false,
            log_regressed: false,
            signed_exchange_validated: false,
        }
    }
}

impl SyncResult {
    pub fn has_error(&self) -> bool {
        self.error.is_some()
    }

    /// Returns true if no ops were pulled, merged, pushed, or pruned.
    pub fn is_empty(&self) -> bool {
        self.pulled == 0 && self.merged == 0 && self.pushed == 0 && self.pruned == 0
    }
}

/// Default page size for the pull-to-head loop. The relay clamps to 1..=1000;
/// 500 drains a backlog in ~5x fewer round-trips than the relay's own default
/// of 100 while keeping each response small enough to decode/apply per page.
pub const DEFAULT_PULL_PAGE_LIMIT: i64 = 500;

/// Default cap on batches pushed per sync cycle. Bounds how long one cycle
/// spends pushing so a large outbound backlog can't starve the pull phase (and
/// thus delay incoming changes); the driver re-arms to drain the rest.
pub const DEFAULT_PUSH_BATCH_CAP: usize = 256;

/// Default cap on pull pages per sync cycle. Bounds how long one cycle spends
/// draining incoming so a huge backlog can't monopolise it; the cursor advances
/// so the next trigger resumes. At the default page size this is ~20k batches.
pub const DEFAULT_PULL_PAGES_PER_CYCLE: usize = 40;

/// Default base interval (30s) for Phase 0b quarantined-pull-batch replay
/// backoff. With the exponent capped at
/// [`crate::engine::QUARANTINE_REPLAY_BACKOFF_MAX_EXP`] (6), the longest wait
/// between replay attempts is ~32 minutes — small enough that a transient
/// condition (registry import, app upgrade) still recovers promptly, large
/// enough that a permanently-poison row stops churning crypto/network work.
pub const DEFAULT_QUARANTINE_REPLAY_BACKOFF_BASE_MS: i64 = 30_000;

/// Maximum number of sync cycles a transient pull stall (unresolvable
/// sender, stale ML-DSA generation) may hold the cursor before the batch
/// converts to quarantine-and-advance. The chosen bound is
/// "8 sync cycles or 24h wall clock, whichever first": this is the cycle half.
/// It bounds how long a flaky registry endpoint — or a malicious enrolled
/// device claiming a bogus future generation — can freeze a peer's pull cursor.
pub const DEFAULT_PULL_STALL_MAX_ATTEMPTS: i64 = 8;

/// Wall-clock ceiling (24h) on a transient pull stall, the other half of the
/// stall budget. Even if a device syncs only rarely (fewer than
/// [`DEFAULT_PULL_STALL_MAX_ATTEMPTS`] cycles in a day), a stall older than this
/// converts to quarantine-and-advance so the relay is not held off its prune
/// floor indefinitely.
pub const DEFAULT_PULL_STALL_MAX_AGE_MS: i64 = 24 * 60 * 60 * 1000;

/// Shortened stall budget (in cycles) applied to a *known-broken* sender — one
/// that has already had at least one batch convert to a durable quarantine for
/// the same reason (tracked in `pull_sender_health`). The first affected
/// sequence still uses the full [`DEFAULT_PULL_STALL_MAX_ATTEMPTS`]; every later
/// batch from that sender/reason quarantine-and-advances after this many cycles
/// so a persistently-unresolvable peer cannot re-incur the full head-of-line
/// stall once per batch. Reset when a Phase 0b replay recovery clears the
/// sender's health. Fail-closed semantics are unchanged — this only quarantines
/// (custody preserved, replayable) sooner; nothing is applied unverified.
pub const DEFAULT_SENDER_FAST_QUARANTINE_MAX_ATTEMPTS: i64 = 2;

/// Configuration for the sync engine.
#[derive(Debug, Clone)]
pub struct SyncConfig {
    /// Maximum clock drift allowed before halting sync (milliseconds).
    /// Default: [`crate::clock_drift::MAX_CLOCK_DRIFT_MS`] (60 seconds).
    pub max_clock_drift_ms: i64,
    /// Number of batches the client requests per `pull_changes` call while
    /// draining to head. See [`DEFAULT_PULL_PAGE_LIMIT`]. The relay clamps the
    /// value to 1..=1000.
    pub pull_page_limit: i64,
    /// Maximum pull pages per cycle before the pull-to-head loop yields and lets
    /// the next trigger resume. See [`DEFAULT_PULL_PAGES_PER_CYCLE`].
    pub max_pull_pages_per_cycle: usize,
    /// Maximum batches pushed in a single cycle before yielding back to the
    /// pull phase. See [`DEFAULT_PUSH_BATCH_CAP`]. `0` disables the cap.
    pub push_batch_cap: usize,
    /// Base interval (milliseconds) for Phase 0b quarantined-pull-batch replay
    /// backoff. A quarantined batch is re-eligible for replay only once
    /// `now >= last_retry_at + base * 2^min(retry_count, cap)`, so a permanently
    /// poison row (e.g. attribution mismatch, or an unresolvable/deregistered
    /// sender whose resolution triggers a relay registry fetch) does not re-run
    /// the full verify/decrypt/decode pipeline — or hit the network — every
    /// cycle forever. The first replay (no `last_retry_at` yet) always runs.
    /// `0` disables backoff (replay every cycle); used by tests that need an
    /// immediate retry. See [`DEFAULT_QUARANTINE_REPLAY_BACKOFF_BASE_MS`].
    pub quarantine_replay_backoff_base_ms: i64,
    /// Maximum sync cycles a transient pull stall holds the cursor
    /// before converting to quarantine-and-advance. See
    /// [`DEFAULT_PULL_STALL_MAX_ATTEMPTS`]. Configurable so tests can drive the
    /// budget-exhaustion conversion without running 8 cycles.
    pub pull_stall_max_attempts: i64,
    /// Wall-clock ceiling (ms) on a transient pull stall, the other half of the
    /// stall budget — whichever bound trips first wins. See
    /// [`DEFAULT_PULL_STALL_MAX_AGE_MS`].
    pub pull_stall_max_age_ms: i64,
    /// Shortened per-cycle stall budget for a sender already known to be broken
    /// for a given reason (it has a prior budget-exhausted quarantine recorded in
    /// `pull_sender_health`). See [`DEFAULT_SENDER_FAST_QUARANTINE_MAX_ATTEMPTS`].
    /// Configurable so tests can exercise the shortcut; set `>=
    /// pull_stall_max_attempts` to disable it.
    pub sender_fast_quarantine_max_attempts: i64,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            max_clock_drift_ms: MAX_CLOCK_DRIFT_MS,
            pull_page_limit: DEFAULT_PULL_PAGE_LIMIT,
            max_pull_pages_per_cycle: DEFAULT_PULL_PAGES_PER_CYCLE,
            push_batch_cap: DEFAULT_PUSH_BATCH_CAP,
            quarantine_replay_backoff_base_ms: DEFAULT_QUARANTINE_REPLAY_BACKOFF_BASE_MS,
            pull_stall_max_attempts: DEFAULT_PULL_STALL_MAX_ATTEMPTS,
            pull_stall_max_age_ms: DEFAULT_PULL_STALL_MAX_AGE_MS,
            sender_fast_quarantine_max_attempts: DEFAULT_SENDER_FAST_QUARANTINE_MAX_ATTEMPTS,
        }
    }
}
