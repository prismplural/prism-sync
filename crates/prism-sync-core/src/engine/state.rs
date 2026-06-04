use std::time::Duration;

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

/// Configuration for the sync engine.
#[derive(Debug, Clone)]
pub struct SyncConfig {
    /// Maximum clock drift allowed before halting sync (milliseconds).
    /// Default: 60_000 (60 seconds).
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
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            max_clock_drift_ms: 60_000,
            pull_page_limit: DEFAULT_PULL_PAGE_LIMIT,
            max_pull_pages_per_cycle: DEFAULT_PULL_PAGES_PER_CYCLE,
            push_batch_cap: DEFAULT_PUSH_BATCH_CAP,
        }
    }
}
