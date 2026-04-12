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
        }
    }
}

impl SyncResult {
    /// Returns true if an error was encountered.
    pub fn has_error(&self) -> bool {
        self.error.is_some()
    }

    /// Returns true if no ops were pulled, merged, pushed, or pruned.
    pub fn is_empty(&self) -> bool {
        self.pulled == 0 && self.merged == 0 && self.pushed == 0 && self.pruned == 0
    }
}

/// Configuration for the sync engine.
#[derive(Debug, Clone)]
pub struct SyncConfig {
    /// Maximum clock drift allowed before halting sync (milliseconds).
    /// Default: 60_000 (60 seconds).
    pub max_clock_drift_ms: i64,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            max_clock_drift_ms: 60_000,
        }
    }
}
