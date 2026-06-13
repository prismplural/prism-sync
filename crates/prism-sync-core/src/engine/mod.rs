pub mod merge;
pub mod pull_failure;
pub mod state;

pub use merge::{MergeEngine, QuarantinedChange, SchemaQuarantineReason, WinningOp};
pub use pull_failure::{PermanentPullReason, PullBatchFailure, TransientPullReason};
pub use state::{SyncConfig, SyncResult, SyncState};

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use tokio::sync::{broadcast, watch};

use crate::batch_signature;
use crate::crdt_change::CrdtChange;
use crate::device_registry::DeviceRegistryManager;
use crate::error::{CoreError, Result};
use crate::events::{EntityChange, SyncEvent};
use crate::hlc::Hlc;
use crate::op_emitter::OpEmitter;
use crate::pruning::TombstonePruner;
use crate::relay::traits::{RelayError, SnapshotUploadProgress};
use crate::relay::{OutgoingBatch, SyncRelay};
use crate::schema::{SyncSchema, SyncType, SyncValue};
use crate::snapshot_limits;
use crate::storage::StorageError;
use crate::storage::{
    is_tombstone_value, AppliedOp, DeviceRecord, FieldVersion, FieldVersionEntry, QuarantinedOp,
    QuarantinedPullBatch, SyncMetadata, SyncStorage,
};
use crate::sync_aad;
use crate::syncable_entity::SyncableEntity;

/// A single entity bundle used by `bootstrap_existing_state` to seed
/// `field_versions` from pre-existing local data.
///
/// Each record contributes one HLC-stamped entity to the CRDT state without
/// emitting any `pending_ops` — these rows are purely local reconstruction,
/// not mutations to be pushed.
#[derive(Debug, Clone)]
pub struct SeedRecord {
    pub table: String,
    pub entity_id: String,
    pub fields: HashMap<String, SyncValue>,
}

/// Summary of a `bootstrap_existing_state` dry run.
#[derive(Debug, Clone)]
pub struct BootstrapReport {
    /// Number of entities seeded.
    pub entity_count: u64,
    /// Size of the zstd-compressed snapshot blob produced by
    /// `export_snapshot` after seeding. Reported so the UI can surface
    /// how large the initial state is.
    pub snapshot_bytes: u64,
}

/// Key material resolved for a batch sender device.
pub struct SenderKeyInfo {
    /// Ed25519 public key (32 bytes).
    pub ed25519_pk: [u8; 32],
    /// ML-DSA-65 public key (may be empty for legacy devices).
    pub ml_dsa_65_pk: Vec<u8>,
    /// ML-DSA key generation (0 = initial, increases on rotation).
    pub ml_dsa_key_generation: u32,
}

/// Copy structured error metadata from a `CoreError` into `SyncResult`.
///
/// Populates `error`, `error_kind`, and — ONLY for `CoreError::Relay` —
/// the `error_code` + `remote_wipe` fields so the propagation chain all
/// the way out to Dart preserves `device_revoked` /
/// `device_identity_mismatch` / `upgrade_required` markers.
///
/// **Invariant:** `error_code` / `remote_wipe` carry RELAY response
/// metadata only. Local / engine errors (`DeviceKeyChanged`, `Engine`,
/// `Storage`, etc.) must NOT populate these fields because Dart treats
/// a non-null `error_code` as a relay response code for cleanup routing.
/// `DeviceKeyChanged` is surfaced via `SyncErrorKind::KeyChanged`, not
/// via `error_code`, and the UI keys off the `kind` for that path.
fn populate_result_error(result: &mut SyncResult, e: &CoreError) {
    result.error_kind = Some(crate::events::classify_core_error(e));
    result.error = Some(e.to_string());
    if let CoreError::Relay { code, remote_wipe, .. } = e {
        result.error_code = code.clone();
        result.remote_wipe = *remote_wipe;
    }
}

fn should_bubble_recoverable_key_error(error: &CoreError) -> bool {
    matches!(error, CoreError::MissingEpochKey { .. } | CoreError::DecryptFailed { .. })
}

fn is_must_bootstrap_from_snapshot(error: &CoreError) -> bool {
    matches!(
        error,
        CoreError::Relay {
            code: Some(code),
            ..
        } if code == "must_bootstrap_from_snapshot"
    )
}

/// The relay rejected the pull cursor as above its log head (a restored relay
/// DB regressed the seq stream). The engine resets the cursor and re-pulls.
fn is_cursor_ahead_of_log(error: &CoreError) -> bool {
    matches!(
        error,
        CoreError::Relay {
            code: Some(code),
            ..
        } if code == "cursor_ahead_of_log"
    )
}

#[cfg(debug_assertions)]
fn debug_assert_remote_op_matches_sender(op: &CrdtChange, trusted_sender_device_id: &str) {
    debug_assert_eq!(
        op.device_id, trusted_sender_device_id,
        "remote op.device_id must match trusted envelope sender at persistence"
    );
    let hlc = Hlc::from_string(&op.client_hlc)
        .expect("validated remote op HLC should parse at persistence");
    debug_assert_eq!(
        hlc.node_id, trusted_sender_device_id,
        "remote op.client_hlc node id must match trusted envelope sender at persistence"
    );
}

#[cfg(not(debug_assertions))]
fn debug_assert_remote_op_matches_sender(_op: &CrdtChange, _trusted_sender_device_id: &str) {}

/// Defensive client-side body cap for push envelopes.
///
/// The relay rejects envelopes larger than `MAX_CHANGESET_SIZE = 1 MiB`. We
/// quarantine at `1_000_000` bytes — slightly under that — so the push path
/// surfaces a clean local quarantine instead of round-tripping a 413 for the
/// pathological cases that slip past Phase 1A's measured partitioner.
///
/// `pub(crate)` so Phase 1C repair can tell whether a single op is genuinely
/// un-splittable (its own envelope exceeds this) versus merely needing
/// repartitioning.
pub(crate) const RELAY_BODY_GUARD_BYTES: usize = 1_000_000;

/// Wall-clock half of the per-cycle pull budget. One sync cycle drains at most
/// `config.max_pull_pages_per_cycle * config.pull_page_limit` batches or runs
/// for at most this duration, whichever comes first. The cursor advances as we
/// go, so a backlog larger than the budget finishes draining on the next sync
/// trigger instead of monopolising one cycle (and starving the push phase).
/// Page size and page count are configurable via [`SyncConfig::pull_page_limit`]
/// and [`SyncConfig::max_pull_pages_per_cycle`].
///
/// [`SyncConfig::pull_page_limit`]: crate::engine::state::SyncConfig::pull_page_limit
/// [`SyncConfig::max_pull_pages_per_cycle`]: crate::engine::state::SyncConfig::max_pull_pages_per_cycle
const MAX_PULL_CYCLE_DURATION: Duration = Duration::from_secs(20);

/// Upper bound on the backoff exponent for Phase 0b quarantined-pull-batch
/// replay. The wait between attempts is `base * 2^min(retry_count, this)`, so
/// the exponent caps the interval (and prevents an `i64` overflow as
/// `retry_count` grows without bound on a permanently-poison row).
const QUARANTINE_REPLAY_BACKOFF_MAX_EXP: u32 = 6;

/// Whether a quarantined pull batch is eligible for a Phase 0b replay attempt
/// this cycle, given the current wall clock, its accumulated `retry_count`, and
/// when it was last retried.
///
/// The first attempt (`last_retry_at == None`) always runs so a freshly
/// quarantined batch is re-evaluated promptly. After that, the batch backs off
/// exponentially: it is eligible only once
/// `now >= last_retry_at + base_ms * 2^min(retry_count, MAX_EXP)`. A `base_ms`
/// of `0` disables backoff entirely (eligible every cycle).
///
/// This is what stops a permanently-poison row (attribution mismatch that can
/// never clear, or an unresolvable/deregistered sender whose resolution issues a
/// relay registry fetch) from re-running the full verify/decrypt/decode pipeline
/// — and hitting the network — on every single sync cycle forever.
fn quarantine_replay_eligible(
    now: DateTime<Utc>,
    retry_count: i64,
    last_retry_at: Option<DateTime<Utc>>,
    base_ms: i64,
) -> bool {
    if base_ms <= 0 {
        return true;
    }
    let Some(last) = last_retry_at else {
        return true;
    };
    let exp = retry_count.clamp(0, QUARANTINE_REPLAY_BACKOFF_MAX_EXP as i64) as u32;
    // base_ms and the multiplier are both bounded (exp <= 6 -> 2^6 = 64), so this
    // saturates rather than overflows even for an absurd base.
    let wait_ms = base_ms.saturating_mul(1i64 << exp);
    let next_eligible = last + chrono::Duration::milliseconds(wait_ms);
    now >= next_eligible
}

/// Whether a `RelayError` corresponds to the relay's 413 `PayloadTooLarge`
/// response. Used by `push_phase` to quarantine the offending batch and
/// continue pushing the rest of the cycle.
fn is_payload_too_large_error(err: &RelayError) -> bool {
    matches!(err, RelayError::Server { status_code: 413, .. })
}

/// Decide whether a `RelayError::SnapshotStale` 409 from `put_snapshot`
/// should be suppressed as success-equivalent in `upload_pairing_snapshot`.
///
/// Suppress only when the existing snapshot's audience is a superset of
/// (or equal to) our intended audience — anything narrower would
/// silently lose availability for some device, because `snapshots` has
/// PRIMARY KEY on `sync_id` alone and the relay's GET 403s every device
/// that doesn't match the stored `target_device_id`.
///
/// | our target | existing target | suppress? |
/// |------------|-----------------|-----------|
/// | `None`     | `None`          | yes       |
/// | `None`     | `Some(_)`       | no — universal intent lost |
/// | `Some(x)`  | `None`          | no — targeted snapshot lost |
/// | `Some(x)`  | `Some(x)`       | yes — same-target race |
/// | `Some(x)`  | `Some(y)` (≠ x) | no — cross-target overwrite |
///
/// Also propagates a "stale" 409 whose cited seq is strictly lower than
/// ours, since that's a logically-invalid response from the relay.
///
/// Free function so the matrix can be unit-tested without a `SyncEngine`.
fn should_suppress_stale_snapshot(
    our_target: Option<&str>,
    existing_target: Option<&str>,
    our_seq: i64,
    existing_seq: i64,
) -> bool {
    if existing_seq < our_seq {
        return false;
    }
    match (our_target, existing_target) {
        (None, None) => true,
        (None, Some(_)) => false,
        (Some(_), None) => false,
        (Some(ours), Some(theirs)) => ours == theirs,
    }
}

/// Result of the pull phase, bundling counts with relay-reported metadata.
struct PullPhaseResult {
    pulled: u64,
    merged: u64,
    entity_changes: Vec<EntityChange>,
    max_server_seq: i64,
    min_acked_seq: Option<i64>,
    /// `true` when a page broke early on a transient sender-resolution stall.
    /// The paging loop must stop draining for the rest of this cycle:
    /// the stalled seq (and everything after it) stays unconsumed, so re-paging
    /// would only re-hit the same batch and bump its stall `attempts` again —
    /// which would exhaust the per-batch budget within one `sync()` call instead
    /// of across the mandated 8 sync cycles / 24h. One stall = one
    /// attempt per cycle.
    stalled: bool,
    /// `true` when this page observed a relay log-lineage change (new token
    /// or a `cursor_ahead_of_log` recovery). The cursor has been reset to 0 and
    /// the cycle re-pulls from the start of the new lineage. Telemetry-only.
    log_regressed: bool,
}

/// Outcome of [`SyncEngine::filter_batch_ops`]: either the partition of the
/// batch into immediately-applicable (`accepted`) and future-HLC `deferred` ops,
/// or a whole-batch attribution-mismatch verdict that `pull_one_page`
/// quarantines.
///
/// `deferred` ops are >60s ahead of the receiver's wall clock; they are
/// quarantined per-op into `quarantined_ops` with reason `future_hlc` rather
/// than dropped, so they replay with their ORIGINAL HLC once the local clock
/// catches up and convergence does not depend on which peer pulled when.
enum BatchFilterOutcome {
    Accepted { accepted: Vec<CrdtChange>, deferred: Vec<CrdtChange> },
    AttributionMismatch(String),
}

/// Typed verdict for resolving a batch sender's verification keys on the pull
/// path. The old code flattened every failure into one opaque `CoreError`
/// and treated all of them as skip-and-advance, conflating a permanent
/// revocation with a transient registry-fetch hiccup — so a network blip or a
/// not-yet-published-registry race during the unknown-sender window silently and
/// permanently dropped the batch (the relay then pruned it past the advanced
/// ack). This separates the two so the caller can STALL (retry, cursor frozen)
/// on transient conditions and only skip-and-advance on a genuine revocation.
enum SenderResolution {
    /// Keys resolved — either the local active record or a freshly fetched and
    /// verified signed-registry import.
    Resolved(SenderKeyInfo),
    /// The sender has a local registry record with a non-active status, or was
    /// revoked during a registry refresh. A permanent verdict: skip and advance
    /// (today's policy — pre-revocation in-flight edits are not applied).
    Revoked,
    /// The sender's keys could not be resolved *yet*: a network/5xx fetch error,
    /// an `Ok(None)` (registry not uploaded yet), a stale registry that does not
    /// yet contain the device, or a verification/monotonicity failure on the
    /// fetched artifact. All of these are expected to clear on their own, so the
    /// caller stalls and retries under the budget rather than dropping the batch.
    TransientlyUnavailable(CoreError),
}

/// The sync engine orchestrates the full pull -> merge -> push cycle.
///
/// It owns references to:
/// - `SyncStorage` -- local sync state (pending_ops, field_versions, etc.)
/// - `SyncRelay` -- transport to the relay server
/// - `SyncableEntity` implementations -- consumer data tables for merge writes
/// - `SyncSchema` -- registered entity tables and field types
///
/// All SyncStorage calls are wrapped in `tokio::task::spawn_blocking`
/// to avoid stalling the tokio reactor.
///
/// Uses trait objects (`dyn`) instead of generics so that Plan 4's public API
/// can store `Option<SyncEngine>` without propagating generic type parameters.
pub struct SyncEngine {
    storage: Arc<dyn SyncStorage>,
    relay: Arc<dyn SyncRelay>,
    entities: Vec<Arc<dyn SyncableEntity>>,
    schema: SyncSchema,
    config: SyncConfig,
    state_tx: watch::Sender<SyncState>,
    state_rx: watch::Receiver<SyncState>,
    merge_engine: MergeEngine,
    /// Optional channel for surfacing engine-side events to consumers.
    ///
    /// `SyncService` calls `with_event_sink` after construction so that
    /// `SyncEvent::QuarantinedBatch` (and any future engine-emitted variant)
    /// can reach the same `event_tx` that the service uses for
    /// `SyncStarted` / `SyncCompleted` / `RemoteChanges`. Tests that construct
    /// a `SyncEngine` directly without wiring a sink still work — emissions
    /// are silently dropped.
    event_tx: Option<broadcast::Sender<SyncEvent>>,
}

impl SyncEngine {
    /// Create a new SyncEngine.
    pub fn new(
        storage: Arc<dyn SyncStorage>,
        relay: Arc<dyn SyncRelay>,
        entities: Vec<Arc<dyn SyncableEntity>>,
        schema: SyncSchema,
        config: SyncConfig,
    ) -> Self {
        let (state_tx, state_rx) = watch::channel(SyncState::Idle);
        let merge_engine = MergeEngine::new(schema.clone());
        Self {
            storage,
            relay,
            entities,
            schema,
            config,
            state_tx,
            state_rx,
            merge_engine,
            event_tx: None,
        }
    }

    /// Install an event sink so engine-side events (e.g.
    /// `SyncEvent::QuarantinedBatch`) reach consumers. Called by
    /// `SyncService::set_engine` so the service and the engine share one
    /// broadcast channel; direct test consumers may skip this call.
    pub fn with_event_sink(mut self, event_tx: broadcast::Sender<SyncEvent>) -> Self {
        self.event_tx = Some(event_tx);
        self
    }

    /// Replace the event sink in place. Mirror of `with_event_sink` for
    /// callers that already hold a `&mut SyncEngine`.
    pub fn set_event_sink(&mut self, event_tx: broadcast::Sender<SyncEvent>) {
        self.event_tx = Some(event_tx);
    }

    fn emit_event(&self, event: SyncEvent) {
        if let Some(tx) = &self.event_tx {
            // We intentionally ignore send errors: a closed channel means no
            // one is listening, and an emit failure must not abort sync.
            let _ = tx.send(event);
        }
    }

    /// Get the current sync state.
    pub fn state(&self) -> SyncState {
        self.state_rx.borrow().clone()
    }

    /// Subscribe to state changes.
    pub fn watch_state(&self) -> watch::Receiver<SyncState> {
        self.state_rx.clone()
    }

    /// Borrow the relay trait object used for sync operations.
    ///
    /// Exposed so higher layers (PrismSync) can perform out-of-band relay
    /// work such as epoch-key catch-up recovery before a sync cycle runs.
    pub fn relay(&self) -> &Arc<dyn SyncRelay> {
        &self.relay
    }

    /// Execute a full sync cycle: pull -> merge -> push.
    ///
    /// `key_hierarchy` provides epoch keys by epoch number (not just "current epoch").
    /// This is critical because pulled batches may span multiple epochs during
    /// epoch rotation -- each batch is decrypted with its own epoch's key.
    #[tracing::instrument(
        skip(self, key_hierarchy, signing_key, ml_dsa_signing_key),
        fields(sync_id, device_id),
        err
    )]
    pub async fn sync(
        &self,
        sync_id: &str,
        key_hierarchy: &prism_sync_crypto::KeyHierarchy,
        signing_key: &ed25519_dalek::SigningKey,
        ml_dsa_signing_key: Option<&prism_sync_crypto::DevicePqSigningKey>,
        device_id: &str,
        ml_dsa_key_generation: u32,
    ) -> Result<SyncResult> {
        let start = Instant::now();
        let mut result = SyncResult::default();

        // Phase 0: replay remote ops that were quarantined because this
        // client did not yet know their schema. A newly configured schema can
        // make those ops valid without needing the relay to resend old history.
        self.set_state(SyncState::Merging);
        match self.replay_quarantined_ops(sync_id).await {
            Ok((merged, changes)) => {
                result.merged += merged;
                result.entity_changes.extend(changes);
            }
            Err(e) => {
                populate_result_error(&mut result, &e);
                result.duration = start.elapsed();
                self.set_state(SyncState::Error { message: e.to_string() });
                return Ok(result);
            }
        }

        // Phase 0b: replay durably quarantined poison pull batches whose blocking
        // condition may now have cleared (registry propagated, decoder upgraded).
        // A replay failure is non-fatal — the batch keeps its quarantine row and
        // backs off — so it never wedges the rest of the cycle.
        match self.replay_quarantined_pull_batches(sync_id, key_hierarchy).await {
            Ok((merged, changes)) => {
                result.merged += merged;
                result.entity_changes.extend(changes);
            }
            Err(e) => {
                tracing::warn!("quarantined pull-batch replay failed (non-fatal): {e}");
            }
        }

        // Phase 1: Pull
        self.set_state(SyncState::Pulling);
        let pull_result = self.pull_phase(sync_id, key_hierarchy, device_id).await;
        let pull_result = match pull_result {
            Ok(pr) => Ok(pr),
            Err(e) if is_must_bootstrap_from_snapshot(&e) => {
                tracing::warn!(
                    "pull cursor predates retained relay history; attempting snapshot bootstrap"
                );
                match self.bootstrap_from_snapshot(sync_id, key_hierarchy).await {
                    // The relay rejected our cursor and no snapshot is
                    // available to recover from — retrying the pull would just
                    // hit the same `MustBootstrapFromSnapshot` again, so
                    // surface a real error instead of looping silently.
                    Ok((0, _)) => Err(CoreError::Engine(
                        "relay required snapshot bootstrap but no snapshot is available; \
                         another paired device must upload a fresh snapshot before this device \
                         can sync"
                            .to_string(),
                    )),
                    Ok((_snapshot_entities, snapshot_changes)) => {
                        result.entity_changes.extend(snapshot_changes);
                        let retry = self.pull_phase(sync_id, key_hierarchy, device_id).await;
                        // The retry pull re-tripped must_bootstrap even though we
                        // just imported the snapshot at its server_seq_at. With the
                        // relay's snapshot-aware prune tail guard this is
                        // unreachable for a live pairing snapshot, so a recurrence
                        // means the tail above the snapshot was lost some other way
                        // (e.g. an un-clamped older relay). Surface both seqs from
                        // the bootstrap cursor and the relay floor so the loop is
                        // diagnosable rather than an opaque second error.
                        match retry {
                            Err(e) if is_must_bootstrap_from_snapshot(&e) => {
                                Err(CoreError::Engine(format!(
                                    "snapshot bootstrap did not resolve must_bootstrap: the relay \
                                     still reports the post-bootstrap cursor predates retained \
                                     history ({e}) — the snapshot tail was pruned out from under \
                                     this device"
                                )))
                            }
                            other => other,
                        }
                    }
                    Err(bootstrap_err) => Err(bootstrap_err),
                }
            }
            Err(e) => Err(e),
        };
        let min_acked_seq;
        match pull_result {
            Ok(pr) => {
                result.pulled = pr.pulled;
                result.merged += pr.merged;
                result.entity_changes.extend(pr.entity_changes);
                result.log_regressed = pr.log_regressed;
                min_acked_seq = pr.min_acked_seq;

                // Acknowledge up to the LOCAL pull cursor, not the relay page max
                // (`pr.max_server_seq`). The cursor advances past a batch iff it
                // was fully applied or durably quarantined here, so acking it can
                // never authorise the relay to prune a batch this device has
                // neither applied nor stored — which is what the transient
                // stalls (cursor held behind a batch) rely on.
                //
                // Awaited (not spawned): the ack is the one *signed* request a
                // pull-only cycle issues, so its 2xx is the relay clock anchor
                // the excursion repair gates on (`signed_exchange_validated`). A
                // failure stays non-fatal — we just leave the anchor unset, so
                // the repair defers to a later validated cycle rather than
                // arming on an unproven clock.
                let acked_cursor = self.local_pull_cursor(sync_id).await.unwrap_or(0);
                if acked_cursor > 0 {
                    match self.relay.ack(acked_cursor).await {
                        Ok(()) => result.signed_exchange_validated = true,
                        Err(e) => tracing::warn!("ack failed (non-fatal): {e}"),
                    }
                }
            }
            Err(e) => {
                if should_bubble_recoverable_key_error(&e) {
                    self.set_state(SyncState::Error { message: e.to_string() });
                    return Err(e);
                }
                populate_result_error(&mut result, &e);
                result.duration = start.elapsed();
                self.set_state(SyncState::Error { message: e.to_string() });
                return Ok(result);
            }
        }

        // Phase 1b: Prune acknowledged ops and tombstones
        if let Some(min_acked) = min_acked_seq {
            if min_acked > 0 {
                match TombstonePruner::prune(
                    self.storage.clone(),
                    &self.entities,
                    sync_id,
                    min_acked,
                    1000,
                )
                .await
                {
                    Ok(pr) => {
                        result.pruned = (pr.applied_ops_pruned
                            + pr.entities_hard_deleted
                            + pr.field_versions_pruned)
                            as u64;
                        if result.pruned > 0 {
                            tracing::info!(
                                applied_ops = pr.applied_ops_pruned,
                                tombstones = pr.entities_hard_deleted,
                                field_versions = pr.field_versions_pruned,
                                "pruned local ops"
                            );
                        }
                    }
                    Err(e) => tracing::warn!("prune failed (non-fatal): {e}"),
                }
            }
        }

        // Phase 2: Push
        self.set_state(SyncState::Pushing);
        let push_result = self
            .push_phase(
                sync_id,
                key_hierarchy,
                signing_key,
                ml_dsa_signing_key,
                device_id,
                ml_dsa_key_generation,
            )
            .await;
        match push_result {
            Ok((pushed, push_incomplete)) => {
                result.pushed = pushed;
                result.push_incomplete = push_incomplete;
                // A pushed batch is a 2xx on the signed `PUT /changes` route, an
                // independent relay clock anchor alongside the ack.
                if pushed > 0 {
                    result.signed_exchange_validated = true;
                }
            }
            Err(e) => {
                if should_bubble_recoverable_key_error(&e) {
                    self.set_state(SyncState::Error { message: e.to_string() });
                    return Err(e);
                }
                populate_result_error(&mut result, &e);
                result.duration = start.elapsed();
                self.set_state(SyncState::Error { message: e.to_string() });
                return Ok(result);
            }
        }

        // Drain the ephemeral mailbox after a successful pull/push.
        self.drain_ephemeral_messages(sync_id, key_hierarchy).await;

        result.duration = start.elapsed();
        self.set_state(SyncState::Idle);

        // Update last successful sync timestamp
        let storage = self.storage.clone();
        let sid = sync_id.to_string();
        tokio::task::spawn_blocking(move || {
            let mut tx = storage.begin_tx()?;
            tx.update_last_successful_sync(&sid)?;
            tx.commit()
        })
        .await
        .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))??;

        Ok(result)
    }

    fn set_state(&self, state: SyncState) {
        let _ = self.state_tx.send(state);
    }

    /// Drain the relay's ephemeral device-message mailbox:
    /// decrypt each pending message, surface the readable ones as
    /// [`SyncEvent::EphemeralMessage`], and ACK every drained id (decryptable or
    /// not — see [`crate::ephemeral::process_ephemeral_drain`]).
    ///
    /// Best-effort: an old relay without the endpoint (404/405) or any transient
    /// error is a silent no-op — never treated as "no messages" in a way that
    /// loses data, because the requester re-issues on its next cycle. Errors
    /// here never fail the surrounding sync.
    async fn drain_ephemeral_messages(
        &self,
        sync_id: &str,
        key_hierarchy: &prism_sync_crypto::KeyHierarchy,
    ) {
        let envelopes = match self.relay.fetch_pending_ephemeral().await {
            Ok(envelopes) => envelopes,
            Err(e) => {
                tracing::debug!("ephemeral drain skipped (feature absent or transient): {e}");
                return;
            }
        };
        if envelopes.is_empty() {
            return;
        }
        let (decoded, ack_ids) =
            crate::ephemeral::process_ephemeral_drain(key_hierarchy, sync_id, &envelopes);
        for msg in decoded {
            self.emit_event(SyncEvent::EphemeralMessage {
                sender_device_id: msg.sender_device_id,
                kind: msg.kind,
                media_id: msg.media_id,
                epoch_id: msg.epoch_id,
            });
        }
        if let Err(e) = self.relay.ack_ephemeral(&ack_ids).await {
            tracing::debug!("ephemeral ack failed (non-fatal): {e}");
        }
    }

    /// The local `last_pulled_server_seq` cursor for this group, or 0 if unset.
    /// This is the seq the engine acks to the relay (everything at or below it
    /// has been applied or durably quarantined locally).
    async fn local_pull_cursor(&self, sync_id: &str) -> Result<i64> {
        let storage = self.storage.clone();
        let sid = sync_id.to_string();
        let meta = tokio::task::spawn_blocking(move || storage.get_sync_metadata(&sid))
            .await
            .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))??;
        Ok(meta.map(|m| m.last_pulled_server_seq).unwrap_or(0))
    }

    /// Reconcile the relay's log-lineage token against the one we last saw.
    ///
    /// Returns `true` when the lineage REGRESSED (a different token than stored)
    /// — in which case the cursor has been reset to 0 and the new token persisted,
    /// so the caller must re-pull surviving + new history (idempotent LWW merge).
    /// Adopting a token on a never-seen group, or matching the stored token,
    /// returns `false`. An old relay (no `log_token`) is always `false` — lineage
    /// tracking stays inert and behavior is unchanged.
    async fn reconcile_log_lineage(
        &self,
        sync_id: &str,
        response_token: Option<&str>,
    ) -> Result<bool> {
        let Some(token) = response_token else {
            return Ok(false);
        };
        let token = token.to_string();

        let storage = self.storage.clone();
        let sid = sync_id.to_string();
        let stored = tokio::task::spawn_blocking(move || storage.get_sync_metadata(&sid))
            .await
            .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))??
            .and_then(|m| m.relay_log_token);

        match stored {
            // First lineage-aware pull for this group: adopt the token.
            None => {
                let storage = self.storage.clone();
                let sid = sync_id.to_string();
                let tok = token.clone();
                tokio::task::spawn_blocking(move || {
                    let mut tx = storage.begin_tx()?;
                    tx.update_relay_log_token(&sid, &tok)?;
                    tx.commit()
                })
                .await
                .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))??;
                Ok(false)
            }
            // Same lineage: nothing to do.
            Some(prev) if prev == token => Ok(false),
            // Lineage changed (relay DB restored): reset the cursor to re-pull from
            // 0 and persist the new token. The reset MUST go through the explicit
            // escape hatch — the MAX-monotonic update would silently no-op a reset
            // to 0.
            Some(prev) => {
                tracing::warn!(
                    sync_id = %sync_id,
                    old_token = %prev,
                    new_token = %token,
                    "relay log lineage changed (likely a relay DB restore); \
                     resetting pull cursor and re-pulling history"
                );
                let storage = self.storage.clone();
                let sid = sync_id.to_string();
                let tok = token.clone();
                tokio::task::spawn_blocking(move || {
                    let mut tx = storage.begin_tx()?;
                    tx.reset_last_pulled_seq(&sid, 0)?;
                    tx.update_relay_log_token(&sid, &tok)?;
                    // The new lineage re-issues the seq space, so every stall row
                    // (keyed by old-lineage seqs) is stale — drop them in the same
                    // tx as the cursor reset.
                    tx.clear_all_pull_stalls(&sid)?;
                    tx.commit()
                })
                .await
                .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))??;
                Ok(true)
            }
        }
    }

    /// Pull phase: drain the relay to head (or the per-cycle budget) by paging.
    ///
    /// Repeatedly pulls fixed-size pages via [`pull_one_page`] and accumulates
    /// the results. Terminates when the relay returns a short page (caught up)
    /// or a budget guard trips. The cursor lives in storage and advances as each
    /// page is applied, so a backlog larger than one cycle's budget resumes
    /// cleanly on the next sync trigger.
    ///
    /// [`pull_one_page`]: SyncEngine::pull_one_page
    async fn pull_phase(
        &self,
        sync_id: &str,
        key_hierarchy: &prism_sync_crypto::KeyHierarchy,
        device_id: &str,
    ) -> Result<PullPhaseResult> {
        let mut total_pulled = 0u64;
        let mut total_merged = 0u64;
        let mut all_entity_changes: Vec<EntityChange> = Vec::new();
        let mut max_server_seq = 0i64;
        // Carries the last clean page's value. The lineage-recovery paths `continue`
        // before assigning these, but they never reach the final return without a
        // clean page first (the loop ends only on a clean page's break), so the
        // value read at return is always a clean page's.
        let mut min_acked_seq: Option<i64>;

        let page_limit = self.config.pull_page_limit;
        let max_pages = self.config.max_pull_pages_per_cycle;
        let pull_start = Instant::now();
        let mut pages = 0usize;
        let mut stalled: bool;

        // Lineage telemetry + recovery bound. `log_regressed` is sticky for the cycle
        // (set once a lineage change is observed). `consecutive_regressions` caps
        // recovery at one re-pull: a second consecutive lineage trip (token still
        // changing, or the relay still 409ing `cursor_ahead_of_log` right after a
        // reset) surfaces an error rather than looping or silently skipping.
        let mut log_regressed = false;
        let mut consecutive_regressions = 0u8;

        loop {
            let (page, page_len) = match self.pull_one_page(sync_id, key_hierarchy, device_id).await
            {
                Ok(p) => p,
                Err(e) if is_cursor_ahead_of_log(&e) => {
                    // The relay rejected the cursor as above its log head — its seq
                    // stream regressed. Reset to 0, forget the stale token, and clear
                    // old-lineage stalls, then re-pull. Clearing the token is what
                    // makes the follow-up pull's (rotated) token ADOPT rather than
                    // re-trip as a mismatch — so this stays a single bounded retry.
                    consecutive_regressions += 1;
                    if consecutive_regressions > 1 {
                        tracing::error!(
                            sync_id = %sync_id,
                            "relay reported cursor_ahead_of_log again right after a reset; \
                             surfacing instead of looping"
                        );
                        return Err(e);
                    }
                    log_regressed = true;
                    tracing::warn!(
                        sync_id = %sync_id,
                        "relay reported cursor_ahead_of_log; resetting pull cursor and re-pulling"
                    );
                    self.reset_pull_cursor(sync_id).await?;
                    continue;
                }
                Err(e) => return Err(e),
            };

            // A lineage-token change reset the cursor to 0 inside the page
            // fetch. Re-page from the start of the new lineage, bounded to one
            // recovery so a relay flapping its token can't spin the cycle.
            if page.log_regressed {
                log_regressed = true;
                consecutive_regressions += 1;
                if consecutive_regressions > 1 {
                    tracing::error!(
                        sync_id = %sync_id,
                        "relay log token changed again right after a reset; \
                         surfacing instead of looping"
                    );
                    return Err(CoreError::Engine(
                        "relay log lineage changed repeatedly within one sync cycle; \
                         the relay may be flapping between restored states"
                            .to_string(),
                    ));
                }
                continue;
            }
            // A clean page resets the consecutive-trip guard.
            consecutive_regressions = 0;

            total_pulled += page.pulled;
            total_merged += page.merged;
            all_entity_changes.extend(page.entity_changes);
            max_server_seq = max_server_seq.max(page.max_server_seq);
            min_acked_seq = page.min_acked_seq;
            stalled = page.stalled;

            // A stall held the cursor behind a batch this page (transient
            // sender-resolution failure). The stalled seq and everything after it
            // are unconsumed, so paging again this cycle would re-pull the same
            // batch and bump its stall `attempts` a second time — exhausting the
            // budget within one cycle. Stop draining for the cycle (treat it like
            // reaching head); the next trigger retries from the same cursor and
            // bumps `attempts` exactly once more.
            if stalled {
                break;
            }
            // Empty page: nothing new on the relay → done.
            if page_len == 0 {
                break;
            }
            pages += 1;
            // A short page means the relay had fewer than a full page left, i.e.
            // we've reached head. (`max_server_seq` is only the page max, so a
            // seq comparison can't detect this — the page length does.)
            if (page_len as i64) < page_limit {
                break;
            }
            // Per-cycle budget: bound one cycle so a huge backlog can't
            // monopolise it (which would starve the push phase). The cursor has
            // already advanced, so the next trigger resumes the drain.
            if pages >= max_pages || pull_start.elapsed() >= MAX_PULL_CYCLE_DURATION {
                tracing::debug!(
                    pages,
                    total_pulled,
                    "pull-to-head hit per-cycle budget; will resume next trigger"
                );
                break;
            }
        }

        Ok(PullPhaseResult {
            pulled: total_pulled,
            merged: total_merged,
            entity_changes: all_entity_changes,
            max_server_seq,
            min_acked_seq,
            stalled,
            log_regressed,
        })
    }

    /// Reset the pull cursor to 0 (escape-hatch rewind) so the cycle re-pulls
    /// from the start of the relay's regressed lineage. Used by the
    /// `cursor_ahead_of_log` recovery, where the relay rejected the cursor before
    /// returning a token to reconcile against.
    ///
    /// The same tx also (a) clears the stored lineage token so the follow-up
    /// pull's token is adopted fresh instead of mismatched and double-counted —
    /// the 409 body carries no token to persist; and (b) drops all stall rows
    /// keyed by the now-defunct old-lineage seqs.
    async fn reset_pull_cursor(&self, sync_id: &str) -> Result<()> {
        let storage = self.storage.clone();
        let sid = sync_id.to_string();
        tokio::task::spawn_blocking(move || {
            let mut tx = storage.begin_tx()?;
            tx.reset_last_pulled_seq(&sid, 0)?;
            tx.clear_relay_log_token(&sid)?;
            tx.clear_all_pull_stalls(&sid)?;
            tx.commit()
        })
        .await
        .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))??;
        Ok(())
    }

    /// Pull and process a single page (one `pull_changes` round-trip). Returns
    /// the page's accumulated result plus the number of batches in the page, so
    /// the caller can detect a short/empty page (= caught up to head).
    #[tracing::instrument(skip(self, key_hierarchy), fields(sync_id, device_id), err)]
    async fn pull_one_page(
        &self,
        sync_id: &str,
        key_hierarchy: &prism_sync_crypto::KeyHierarchy,
        device_id: &str,
    ) -> Result<(PullPhaseResult, usize)> {
        // Get last pulled seq from storage (spawn_blocking). The cursor advances
        // as batches are applied, so each call resumes from the prior page.
        let storage = self.storage.clone();
        let sid = sync_id.to_string();
        let meta = tokio::task::spawn_blocking(move || storage.get_sync_metadata(&sid))
            .await
            .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))??;

        let since_seq = meta.map(|m| m.last_pulled_server_seq).unwrap_or(0);

        // Pull from relay (configurable page size; relay clamps to 1..=1000).
        let pull_response = self
            .relay
            .pull_changes_paged(since_seq, self.config.pull_page_limit)
            .await
            .map_err(CoreError::from_relay)?;

        // Reconcile the relay's log lineage before processing this page. A
        // lineage change resets the cursor to 0 and re-pulls from the start of the
        // new lineage — so discard this page (its seqs belong to the new lineage;
        // re-pulling from 0 is the correct, idempotent recovery) and let the
        // paging loop re-run. `page_len = 0` here would break the loop, so the
        // dedicated `log_regressed` signal tells `pull_phase` to re-page instead.
        if self.reconcile_log_lineage(sync_id, pull_response.log_token.as_deref()).await? {
            return Ok((
                PullPhaseResult {
                    pulled: 0,
                    merged: 0,
                    entity_changes: Vec::new(),
                    max_server_seq: 0,
                    min_acked_seq: pull_response.min_acked_seq,
                    stalled: false,
                    log_regressed: true,
                },
                0,
            ));
        }

        let min_acked_seq = pull_response.min_acked_seq;
        let max_server_seq = pull_response.max_server_seq;
        let page_len = pull_response.batches.len();

        if pull_response.batches.is_empty() {
            return Ok((
                PullPhaseResult {
                    pulled: 0,
                    merged: 0,
                    entity_changes: Vec::new(),
                    max_server_seq,
                    min_acked_seq,
                    stalled: false,
                    log_regressed: false,
                },
                0,
            ));
        }

        let mut total_pulled = 0u64;
        let mut total_merged = 0u64;
        let mut all_entity_changes: Vec<EntityChange> = Vec::new();
        // Set when a transient sender-resolution failure breaks the batch loop
        // early; signals `pull_phase` to stop paging for the cycle so the stalled
        // batch is retried (and its `attempts` bumped) at most once per cycle.
        let mut stalled = false;

        // Process each batch
        for batch in &pull_response.batches {
            let envelope = &batch.envelope;

            // Skip our own batches (still advance server_seq)
            if envelope.sender_device_id == device_id {
                self.advance_cursor_past_seq(sync_id, batch.server_seq, None).await?;
                total_pulled += 1;
                continue;
            }

            // STEP 1: Resolve the sender's hybrid (Ed25519 + ML-DSA-65) keys,
            // folding in the envelope's claimed ML-DSA generation so a
            // not-yet-imported rotation triggers a registry refresh. The verdict
            // separates a permanent revocation from a transient resolution
            // failure: a network/5xx fetch error, an `Ok(None)` (registry
            // not uploaded yet), or a stale registry that has not yet imported
            // the sender used to skip-and-advance — silently and permanently
            // losing the batch once the relay pruned past the advanced ack. Those
            // now STALL: the cursor is held behind the batch, the batch is
            // retried next cycle, and only on budget exhaustion does it convert
            // to a durable (replayable) quarantine.
            let sender_key_info = match self
                .resolve_sender_for_pull(
                    sync_id,
                    &envelope.sender_device_id,
                    Some(envelope.sender_ml_dsa_key_generation),
                )
                .await
            {
                SenderResolution::Resolved(ki) => {
                    // Sender resolution succeeded — drop a prior *sender_unresolved*
                    // stall on this seq. Do NOT clear a `stale_key_generation`
                    // stall here: STEP 1b below still has to confirm the
                    // envelope's exact generation resolved, and clearing it now
                    // would reset that budget every cycle (the generation race
                    // could then stall forever without ever converting to a
                    // quarantine). STEP 1b clears it itself once the gen key
                    // verifies.
                    self.clear_pull_stall_for_seq_if_reason(
                        sync_id,
                        batch.server_seq,
                        TransientPullReason::SenderUnresolved,
                    )
                    .await?;
                    ki
                }
                // Permanent verdict: the sender is revoked. Keep today's
                // skip-and-advance policy (pre-revocation in-flight edits are
                // not applied from a revoked device). Pinned explicitly so it
                // can't silently regress into a stall.
                SenderResolution::Revoked => {
                    tracing::warn!(
                        "Skipping batch from revoked sender {} (skip-and-advance)",
                        envelope.sender_device_id
                    );
                    // Clear any prior-cycle stall row in the same tx as the
                    // advance so a crash can't strand a stall row behind the
                    // moved cursor.
                    self.advance_cursor_past_seq(
                        sync_id,
                        batch.server_seq,
                        Some(batch.server_seq),
                    )
                    .await?;
                    total_pulled += 1;
                    continue;
                }
                // Transient verdict: the registry is unavailable or stale. Stall
                // under the budget; on exhaustion, quarantine-and-advance so the
                // batch becomes Phase 0b-replayable (and the relay is no longer
                // held off its prune floor) without ever silently dropping it.
                SenderResolution::TransientlyUnavailable(e) => {
                    let attempts = self
                        .stall_pull_batch(
                            sync_id,
                            batch.server_seq,
                            TransientPullReason::SenderUnresolved,
                        )
                        .await?;
                    if self
                        .stall_budget_exhausted(sync_id, batch.server_seq, attempts)
                        .await?
                    {
                        tracing::warn!(
                            "Sender {} unresolvable after {attempts} attempts ({e}); \
                             quarantining batch {} (replayable) and advancing",
                            envelope.sender_device_id,
                            envelope.batch_id,
                        );
                        // The stall row converts to a durable quarantine; clear
                        // it in the SAME tx as the quarantine insert + advance so
                        // the budget doesn't keep counting against a seq the
                        // cursor has now moved past (and a crash can't strand it).
                        self.quarantine_pull_batch(
                            sync_id,
                            batch,
                            PermanentPullReason::SenderUnresolved,
                            Some(batch.server_seq),
                        )
                        .await?;
                        total_pulled += 1;
                        continue;
                    }
                    // Still within budget: STALL. Leave this batch and everything
                    // after it on the page unconsumed (the page is ordered by
                    // server_seq), so the cursor stays behind it and the relay
                    // can't prune it. Earlier batches keep their advances and the
                    // push phase still runs. Signal the stall so `pull_phase`
                    // stops paging for the cycle — re-paging would re-hit this
                    // batch and bump `attempts` again within the same cycle.
                    tracing::info!(
                        "Stalling pull at seq {} (attempt {attempts}): sender {} not yet \
                         resolvable ({e})",
                        batch.server_seq,
                        envelope.sender_device_id,
                    );
                    // Emit PullStalled only here (within budget): the conversion
                    // branch above emits PullBatchQuarantined instead, so a single
                    // seq never surfaces both events in one cycle.
                    self.emit_event(SyncEvent::PullStalled {
                        server_seq: batch.server_seq,
                        reason: TransientPullReason::SenderUnresolved.as_str().to_string(),
                        attempt: attempts,
                    });
                    stalled = true;
                    break;
                }
            };

            // STEP 1b: Select the ML-DSA verification key for the EXACT generation
            // the envelope declares. The resolved current key may be a newer
            // generation (the receiver imported a rotation) or — during a not-yet-
            // propagated rotation — an older one; in either case the exact key may
            // live in device_key_history. A `None` here is a STALE-REGISTRY verdict,
            // not a forgery: the old code hard-failed the generation comparison
            // with the same opaque error as a real bad signature, then skipped-and-
            // advanced, permanently losing every batch a rotated sender pushed
            // during the propagation window. Now a generation mismatch STALLS
            // (cursor frozen, push still runs) and converts to a replayable
            // quarantine only after the retry budget, while a signature that fails
            // under a key of the matching generation stays a permanent
            // (replayable) quarantine.
            let verify_ml_dsa_pk = self
                .resolve_verification_ml_dsa_key(
                    sync_id,
                    &envelope.sender_device_id,
                    envelope.sender_ml_dsa_key_generation,
                    &sender_key_info,
                )
                .await?;
            let Some(verify_ml_dsa_pk) = verify_ml_dsa_pk else {
                // No key for the envelope's generation (current or archived) — the
                // receiver's registry is behind (or, for an older generation, the
                // key was never witnessed/archived). STALL and retry; the
                // generation propagates via Phase 0b replay or a later import.
                let attempts = self
                    .stall_pull_batch(
                        sync_id,
                        batch.server_seq,
                        TransientPullReason::StaleKeyGeneration,
                    )
                    .await?;
                if self
                    .stall_budget_exhausted(sync_id, batch.server_seq, attempts)
                    .await?
                {
                    tracing::warn!(
                        "ML-DSA generation {} for sender {} unresolvable after {attempts} \
                         attempts (local gen {}); quarantining batch {} (replayable) and advancing",
                        envelope.sender_ml_dsa_key_generation,
                        envelope.sender_device_id,
                        sender_key_info.ml_dsa_key_generation,
                        envelope.batch_id,
                    );
                    self.quarantine_pull_batch(
                        sync_id,
                        batch,
                        PermanentPullReason::StaleKeyGeneration,
                        Some(batch.server_seq),
                    )
                    .await?;
                    total_pulled += 1;
                    continue;
                }
                tracing::info!(
                    "Stalling pull at seq {} (attempt {attempts}): sender {} ML-DSA generation {} \
                     not yet resolvable (local gen {})",
                    batch.server_seq,
                    envelope.sender_device_id,
                    envelope.sender_ml_dsa_key_generation,
                    sender_key_info.ml_dsa_key_generation,
                );
                self.emit_event(SyncEvent::PullStalled {
                    server_seq: batch.server_seq,
                    reason: TransientPullReason::StaleKeyGeneration.as_str().to_string(),
                    attempt: attempts,
                });
                stalled = true;
                break;
            };
            // Clear any prior stall on this seq — the generation key resolved.
            self.clear_pull_stall_for_seq(sync_id, batch.server_seq).await?;

            // A signature that fails under the exact-generation key is a genuine
            // cryptographic verdict — quarantine the whole envelope (fail-closed
            // on apply) and advance, instead of the old silent skip-and-drop.
            // Preserving the envelope is what lets Phase 0b replay re-verify it
            // (e.g. once a later registry import supplies/archives the key).
            if let Err(e) = batch_signature::verify_batch_signature(
                envelope,
                &sender_key_info.ed25519_pk,
                &verify_ml_dsa_pk,
            ) {
                tracing::warn!(
                    "Quarantining batch {} with invalid signature from {}: {e}",
                    envelope.batch_id,
                    envelope.sender_device_id,
                );
                self.quarantine_pull_batch(
                    sync_id,
                    batch,
                    PermanentPullReason::InvalidSignature,
                    None,
                )
                .await?;
                total_pulled += 1;
                continue;
            }

            // STEP 2: Decrypt batch using the epoch key from THIS batch's epoch
            // (not "current epoch" -- pulled batches may span multiple epochs)
            let epoch_key = key_hierarchy.epoch_key(envelope.epoch as u32).map_err(|_| {
                tracing::error!(
                    batch_epoch = envelope.epoch,
                    server_seq = batch.server_seq,
                    sender_device_id = %envelope.sender_device_id,
                    known_epochs = ?key_hierarchy.known_epochs(),
                    "engine: missing epoch key — cannot decrypt batch"
                );
                CoreError::MissingEpochKey { epoch: envelope.epoch as u32 }
            })?;
            let aad = sync_aad::build_sync_aad(
                sync_id,
                &envelope.sender_device_id,
                envelope.epoch,
                &envelope.batch_id,
                &envelope.batch_kind,
            );
            let plaintext = prism_sync_crypto::aead::xchacha_decrypt_from_sync(
                epoch_key,
                &envelope.ciphertext,
                &envelope.nonce,
                &aad,
            )
            .map_err(|source| CoreError::DecryptFailed { epoch: envelope.epoch as u32, source })?;

            // STEP 3 onward (verify payload hash -> decode -> filter attribution):
            // every deterministic failure quarantines the whole envelope and
            // advances the cursor so no poison batch wedges the group, replacing
            // the old hard-Err-out-of-pull-one-page that froze the cursor (and the
            // push phase) on the same seq forever.
            if batch_signature::verify_payload_hash(envelope, &plaintext).is_err() {
                tracing::warn!(
                    batch_id = %envelope.batch_id,
                    sender_device_id = %envelope.sender_device_id,
                    "Quarantining batch with payload-hash mismatch"
                );
                self.quarantine_pull_batch(
                    sync_id,
                    batch,
                    PermanentPullReason::PayloadHashMismatch,
                    None,
                )
                .await?;
                total_pulled += 1;
                continue;
            }

            let ops = match CrdtChange::decode_batch(&plaintext) {
                Ok(ops) => ops,
                Err(e) => {
                    tracing::warn!(
                        batch_id = %envelope.batch_id,
                        sender_device_id = %envelope.sender_device_id,
                        "Quarantining undecodable batch (replayable after upgrade): {e}"
                    );
                    self.quarantine_pull_batch(
                        sync_id,
                        batch,
                        PermanentPullReason::DecodeFailed,
                        None,
                    )
                    .await?;
                    total_pulled += 1;
                    continue;
                }
            };

            let (ops, deferred) = match Self::filter_batch_ops(
                ops,
                &envelope.sender_device_id,
                self.config.max_clock_drift_ms,
            ) {
                BatchFilterOutcome::Accepted { accepted, deferred } => (accepted, deferred),
                BatchFilterOutcome::AttributionMismatch(detail) => {
                    tracing::warn!(
                        batch_id = %envelope.batch_id,
                        sender_device_id = %envelope.sender_device_id,
                        "Quarantining batch with attribution mismatch: {detail}"
                    );
                    self.quarantine_pull_batch(
                        sync_id,
                        batch,
                        PermanentPullReason::AttributionMismatch,
                        None,
                    )
                    .await?;
                    total_pulled += 1;
                    continue;
                }
            };

            // Merge phase
            self.set_state(SyncState::Merging);
            let (merged, batch_changes) = self
                .apply_remote_batch(
                    sync_id,
                    &ops,
                    &deferred,
                    batch.server_seq,
                    &envelope.sender_device_id,
                    true, // advance the cursor; this is a live pull, not Phase 0b replay
                )
                .await?;
            total_merged += merged;
            all_entity_changes.extend(batch_changes);
            total_pulled += 1;
        }

        Ok((
            PullPhaseResult {
                pulled: total_pulled,
                merged: total_merged,
                entity_changes: all_entity_changes,
                max_server_seq,
                min_acked_seq,
                stalled,
                log_regressed: false,
            },
            page_len,
        ))
    }

    /// Resolve a sender's key material from the local device registry,
    /// refreshing from the relay if the sender is unknown.
    async fn resolve_sender_public_key(
        &self,
        sync_id: &str,
        sender_device_id: &str,
    ) -> Result<SenderKeyInfo> {
        self.resolve_sender_keys_with_generation_hint(sync_id, sender_device_id, None).await
    }

    /// Resolve the ML-DSA verification key for the EXACT generation an envelope
    /// declares. Returns the resolved current record's key if its
    /// generation matches, otherwise the archived key from `device_key_history`,
    /// otherwise `None`.
    ///
    /// `None` is *not* a forgery verdict — it means the receiver does not (yet)
    /// hold a key for that generation. The caller treats it as a transient
    /// stale-registry condition (stall + retry, then quarantine), because the
    /// common cause is a rotation the receiver has not propagated. A genuine
    /// forgery surfaces only when an exact-generation key IS found and the
    /// signature fails under it.
    async fn resolve_verification_ml_dsa_key(
        &self,
        sync_id: &str,
        sender_device_id: &str,
        envelope_generation: u32,
        resolved: &SenderKeyInfo,
    ) -> Result<Option<Vec<u8>>> {
        if resolved.ml_dsa_key_generation == envelope_generation {
            return Ok(Some(resolved.ml_dsa_65_pk.clone()));
        }
        // The resolved current key is a different generation; look for the exact
        // generation in the archived key history (a superseded key kept across a
        // rotation the receiver HAS imported).
        let storage = self.storage.clone();
        let sid = sync_id.to_string();
        let dev = sender_device_id.to_string();
        let archived = tokio::task::spawn_blocking(move || {
            storage.get_archived_device_key(&sid, &dev, envelope_generation)
        })
        .await
        .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))??;
        Ok(archived)
    }

    /// Resolve sender keys, optionally checking for ML-DSA generation freshness.
    ///
    /// If `expected_generation` is `Some(n)` and the locally stored generation
    /// for this sender is less than `n`, triggers a signed registry fetch +
    /// import before returning, so that hybrid verification can proceed with
    /// the sender's current ML-DSA key.
    pub async fn resolve_sender_keys_with_generation_hint(
        &self,
        sync_id: &str,
        sender_device_id: &str,
        expected_generation: Option<u32>,
    ) -> Result<SenderKeyInfo> {
        // Stage 1: local lookup
        let storage = self.storage.clone();
        let sid = sync_id.to_string();
        let sender_id = sender_device_id.to_string();
        let record =
            tokio::task::spawn_blocking(move || storage.get_device_record(&sid, &sender_id))
                .await
                .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))??;

        if let Some(ref r) = record {
            if r.status == "active" {
                let info = pk_from_record(r)?;

                // Generation-freshness check: if the caller expects a newer
                // ML-DSA generation than we have locally, try a signed registry
                // fetch to update the key before returning.
                if let Some(expected) = expected_generation {
                    if expected > info.ml_dsa_key_generation {
                        tracing::info!(
                            sender = %sender_device_id,
                            local_gen = info.ml_dsa_key_generation,
                            expected_gen = expected,
                            "ML-DSA generation stale; fetching signed registry"
                        );
                        // Re-run Stage 2 (signed registry fetch) to try to get updated keys.
                        // If it succeeds and the generation is now sufficient, return the updated info.
                        if let Ok(updated) =
                            self.fetch_and_import_registry(sync_id, sender_device_id).await
                        {
                            if updated.ml_dsa_key_generation >= expected {
                                return Ok(updated);
                            }
                        }
                        // Re-read the device record after the refresh attempt — the import may
                        // have changed the device status (e.g., revoked it) even if the generation
                        // did not reach the expected level.  Returning stale `info` here would
                        // hand back an active key for a device that was just revoked.
                        let storage = self.storage.clone();
                        let sid = sync_id.to_string();
                        let sender_id = sender_device_id.to_string();
                        let refreshed_record = tokio::task::spawn_blocking(move || {
                            storage.get_device_record(&sid, &sender_id)
                        })
                        .await
                        .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))??;

                        return match refreshed_record {
                            Some(ref r) if r.status == "active" => pk_from_record(r),
                            Some(ref r) => {
                                tracing::warn!(
                                    "Device {} was revoked during registry refresh",
                                    sender_device_id
                                );
                                Err(CoreError::Storage(StorageError::Logic(format!(
                                    "Device {} was revoked during registry refresh (status: {})",
                                    sender_device_id, r.status
                                ))))
                            }
                            None => {
                                // Device was removed during refresh; fall through to the
                                // unknown-sender stages below by returning an error here so
                                // the caller can skip or reject the batch.
                                Err(CoreError::Storage(StorageError::Logic(format!(
                                    "Device {} disappeared during registry refresh",
                                    sender_device_id
                                ))))
                            }
                        };
                    }
                }

                return Ok(info);
            }
            tracing::warn!("Skipping batch from revoked device {}", sender_device_id);
            return Err(CoreError::Storage(StorageError::Logic(format!(
                "Device {} is revoked",
                sender_device_id
            ))));
        }

        // Unknown sender -- attempt signed registry; fail closed if unavailable
        tracing::info!(
            "Unknown sender device {}, attempting signed registry fetch",
            sender_device_id
        );

        // Stage 2: Try to fetch and verify a signed registry artifact
        match self.fetch_and_import_registry(sync_id, sender_device_id).await {
            Ok(info) => return Ok(info),
            Err(e) => {
                tracing::warn!(
                    "Signed registry fetch/import failed for sender {}: {e}",
                    sender_device_id
                );
            }
        }

        // Stage 3: Fail closed — no unverified fallback.
        // If signed registry is unavailable, the batch from this unknown
        // sender will be skipped. Legitimate devices become known through
        // pairing (import_keyring) or signed registry artifacts.
        tracing::warn!(
            "No verified registry path for unknown sender {}; skipping batch (fail closed)",
            sender_device_id
        );
        Err(CoreError::Storage(StorageError::Logic(format!(
            "Unknown device {} and no verified registry available (fail closed)",
            sender_device_id
        ))))
    }

    /// Resolve a batch sender's keys on the pull path, distinguishing a
    /// permanent revocation from a transient resolution failure.
    ///
    /// Wraps [`resolve_sender_keys_with_generation_hint`] and classifies its flat
    /// `Result` into a [`SenderResolution`]: success is `Resolved`; on failure we
    /// re-read the local registry record and return `Revoked` iff a record exists
    /// with a non-active status (the genuine permanent verdict at the
    /// known-revoked and revoked-during-refresh sites), and `TransientlyUnavailable`
    /// for everything else — network/5xx, `Ok(None)`, a stale registry missing the
    /// device, a verification/monotonicity failure. The latter set is exactly the
    /// conditions that used to skip-and-advance and lose the batch permanently;
    /// the caller now stalls on them.
    async fn resolve_sender_for_pull(
        &self,
        sync_id: &str,
        sender_device_id: &str,
        expected_generation: Option<u32>,
    ) -> SenderResolution {
        match self
            .resolve_sender_keys_with_generation_hint(
                sync_id,
                sender_device_id,
                expected_generation,
            )
            .await
        {
            Ok(info) => SenderResolution::Resolved(info),
            Err(e) => {
                // A revocation is the only permanent verdict. Everything else
                // (no artifact yet, stale registry, network/5xx, verification
                // race) is transient and must stall rather than drop. We trust
                // the local record's status over the error string: the resolver
                // re-reads the record after any refresh, so a device that was
                // revoked mid-refresh is reflected here too.
                match self.sender_is_revoked(sync_id, sender_device_id).await {
                    Ok(true) => SenderResolution::Revoked,
                    Ok(false) => SenderResolution::TransientlyUnavailable(e),
                    // A storage read failure while classifying is itself
                    // transient — never silently promote it to a permanent
                    // skip-and-advance.
                    Err(read_err) => SenderResolution::TransientlyUnavailable(read_err),
                }
            }
        }
    }

    /// Fetch signed registry, verify, import, and re-lookup a specific device.
    ///
    /// Returns the resolved `SenderKeyInfo` for `device_id` after importing the
    /// signed registry artifact. Errors if the registry fetch fails, verification
    /// fails, or the device is still not found (or not active) after import.
    async fn fetch_and_import_registry(
        &self,
        sync_id: &str,
        device_id: &str,
    ) -> Result<SenderKeyInfo> {
        match self.relay.get_signed_registry().await {
            Ok(Some(response)) => {
                // Read the last imported version for monotonicity check
                let storage = self.storage.clone();
                let sid = sync_id.to_string();
                let last_version =
                    tokio::task::spawn_blocking(move || storage.get_sync_metadata(&sid))
                        .await
                        .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))?
                        .ok()
                        .flatten()
                        .and_then(|m| m.last_imported_registry_version);

                let storage = self.storage.clone();
                let sid = sync_id.to_string();
                let blob = response.artifact_blob.clone();

                let import_result = tokio::task::spawn_blocking(move || {
                    DeviceRegistryManager::verify_and_import_signed_registry(
                        &*storage,
                        &sid,
                        &blob,
                        last_version,
                    )
                })
                .await
                .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))?;

                match import_result {
                    Ok(signed_version) => {
                        tracing::info!(
                            "Imported verified registry v{signed_version} for device {}",
                            device_id
                        );
                        // Store the signed (verified) version — not the relay response version
                        let storage = self.storage.clone();
                        let sid = sync_id.to_string();
                        let _ = tokio::task::spawn_blocking(move || {
                            let mut tx = storage.begin_tx()?;
                            tx.update_last_imported_registry_version(&sid, signed_version)?;
                            tx.commit()
                        })
                        .await
                        .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))?;

                        // Retry local lookup after verified import
                        let storage = self.storage.clone();
                        let sid = sync_id.to_string();
                        let dev_id = device_id.to_string();
                        let record = tokio::task::spawn_blocking(move || {
                            storage.get_device_record(&sid, &dev_id)
                        })
                        .await
                        .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))??;

                        if let Some(ref r) = record {
                            if r.status == "active" {
                                return pk_from_record(r);
                            }
                        }
                        // Device still not found after verified import
                        Err(CoreError::Storage(StorageError::Logic(format!(
                            "Device {} not found in signed registry",
                            device_id
                        ))))
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Signed registry verification failed for device {}: {e}",
                            device_id
                        );
                        Err(CoreError::Storage(StorageError::Logic(format!(
                            "Signed registry verification failed: {e}"
                        ))))
                    }
                }
            }
            Ok(None) => {
                tracing::debug!("No signed registry artifact available for device {}", device_id);
                Err(CoreError::Storage(StorageError::Logic(
                    "No signed registry artifact available".to_string(),
                )))
            }
            Err(e) => {
                tracing::warn!("Failed to fetch signed registry for device {}: {e}", device_id);
                Err(CoreError::from_relay(e))
            }
        }
    }

    /// Build one consumer-delivery journal row from a winning op. A delete op
    /// journals `field_name = None` / `is_delete = true` (the whole entity is
    /// tombstoned); a field write journals the field name and its encoded value.
    /// `id` is assigned by the storage AUTOINCREMENT, so the `0` here is ignored.
    fn journal_row_for_winner(
        sync_id: &str,
        op: &CrdtChange,
        server_seq: i64,
    ) -> crate::storage::ConsumerDelivery {
        crate::storage::ConsumerDelivery {
            id: 0,
            sync_id: sync_id.to_string(),
            entity_table: op.entity_table.clone(),
            entity_id: op.entity_id.clone(),
            field_name: if op.is_delete { None } else { Some(op.field_name.clone()) },
            encoded_value: if op.is_delete { None } else { Some(op.encoded_value.clone()) },
            is_delete: op.is_delete,
            server_seq,
            created_at: chrono::Utc::now(),
        }
    }

    /// `true` when this winner must be journaled for at-least-once consumer
    /// delivery. A non-delete winner whose entity ALSO has a delete winner in the
    /// same batch is subsumed by that delete (merge.rs:360 "A delete subsumes
    /// every other field"; sequential Phase B apply ends tombstoned regardless of
    /// order) — so we journal only the delete row, never the sparse field rows.
    ///
    /// This makes the per-entity journal write deterministic regardless of the
    /// HashMap iteration order of `winners`, and — crucially — guarantees a
    /// `take_undelivered_changes` chunk boundary can never split [delete, fields]
    /// for one entity into a delete chunk and a later sparse-field chunk that
    /// would resurrect the row at-least-once between acks (the FFI coalescer's
    /// absorbing rule only protects within a single chunk).
    fn winner_should_journal(op: &CrdtChange, deleted_entities: &HashSet<(String, String)>) -> bool {
        op.is_delete
            || !deleted_entities.contains(&(op.entity_table.clone(), op.entity_id.clone()))
    }

    /// Entities tombstoned by a delete winner in this batch — used to drop the
    /// subsumed sparse field rows from the journal (see `winner_should_journal`).
    fn deleted_entities_in(winners: &[CrdtChange]) -> HashSet<(String, String)> {
        winners
            .iter()
            .filter(|op| op.is_delete)
            .map(|op| (op.entity_table.clone(), op.entity_id.clone()))
            .collect()
    }

    fn entity_changes_from_winning_ops(winning_ops: &[CrdtChange]) -> Vec<EntityChange> {
        let mut change_map: HashMap<(String, String), EntityChange> = HashMap::new();
        for op in winning_ops {
            let key = (op.entity_table.clone(), op.entity_id.clone());
            let entry = change_map.entry(key).or_insert_with(|| EntityChange {
                table: op.entity_table.clone(),
                entity_id: op.entity_id.clone(),
                is_delete: false,
                fields: HashMap::new(),
            });
            if op.is_delete {
                entry.is_delete = true;
                entry.fields.clear();
            } else {
                entry.fields.insert(op.field_name.clone(), op.encoded_value.clone());
            }
        }
        change_map.into_values().collect()
    }

    async fn write_winning_ops_to_entities(&self, winning_ops: &[CrdtChange]) -> Result<()> {
        if winning_ops.is_empty() {
            return Ok(());
        }

        let mut tables_touched: HashSet<String> = HashSet::new();
        for op in winning_ops {
            tables_touched.insert(op.entity_table.clone());
        }

        for entity in &self.entities {
            if tables_touched.contains(entity.table_name()) {
                entity.begin_batch().await?;
            }
        }

        let write_result: Result<()> = async {
            for op in winning_ops {
                if let Some(entity) =
                    self.entities.iter().find(|e| e.table_name() == op.entity_table)
                {
                    if op.is_delete {
                        entity.soft_delete(&op.entity_id, &op.client_hlc).await?;
                    } else {
                        let sync_type = self
                            .schema
                            .entity(&op.entity_table)
                            .and_then(|e| e.field_by_name(&op.field_name))
                            .map(|f| f.sync_type)
                            .unwrap_or(SyncType::String);
                        let decoded =
                            match crate::schema::decode_value(&op.encoded_value, sync_type) {
                                Ok(v) => v,
                                Err(e) => {
                                    tracing::warn!(
                                        table = %op.entity_table,
                                        entity_id = %op.entity_id,
                                        field = %op.field_name,
                                        encoded_value = %op.encoded_value,
                                        "Skipping field op with type mismatch: {e}. \
                                         Dart-side quarantine will record the bad value."
                                    );
                                    continue;
                                }
                            };
                        let mut fields = HashMap::new();
                        fields.insert(op.field_name.clone(), decoded);
                        entity.write_fields(&op.entity_id, &fields, &op.client_hlc, false).await?;
                    }
                }
            }
            Ok(())
        }
        .await;

        match write_result {
            Ok(()) => {
                // Commit each touched entity, but keep the all-or-nothing batch
                // contract even if a `commit_batch` itself fails: a bare `?` here
                // would leave the still-uncommitted touched entities with their
                // `begin_batch` transactions dangling (the Err arm below never
                // runs). Track committed entities and roll back every touched
                // entity that hasn't committed yet on the first failure.
                let mut committed: Vec<&str> = Vec::new();
                for entity in &self.entities {
                    if !tables_touched.contains(entity.table_name()) {
                        continue;
                    }
                    if let Err(e) = entity.commit_batch().await {
                        for entity in &self.entities {
                            let name = entity.table_name();
                            if tables_touched.contains(name) && !committed.contains(&name) {
                                let _ = entity.rollback_batch().await;
                            }
                        }
                        return Err(e);
                    }
                    committed.push(entity.table_name());
                }
                Ok(())
            }
            Err(e) => {
                for entity in &self.entities {
                    if tables_touched.contains(entity.table_name()) {
                        let _ = entity.rollback_batch().await;
                    }
                }
                Err(e)
            }
        }
    }

    /// Replay quarantined ops that are now known to the configured schema.
    async fn replay_quarantined_ops(&self, sync_id: &str) -> Result<(u64, Vec<EntityChange>)> {
        // List + filter inside one blocking task so the reason-aware eligibility
        // gate can read the current field winner (needed for the future-HLC
        // supersede rule) without an extra round-trip. The same read
        // detects future-HLC rows that have been permanently superseded by a
        // later same-device same-field winner; those are EVICTED (deleted) here
        // so a clock-excursion device cannot accumulate dead rows that the
        // eligibility gate re-evaluates every cycle (the future-HLC backlog bound).
        let storage = self.storage.clone();
        let sid = sync_id.to_string();
        let merge_engine = self.merge_engine.clone();
        let max_clock_drift_ms = self.config.max_clock_drift_ms;
        let (replayable, superseded_op_ids): (Vec<QuarantinedOp>, Vec<String>) =
            tokio::task::spawn_blocking(move || {
                let all = storage.list_quarantined_ops(&sid)?;
                let mut out = Vec::with_capacity(all.len());
                let mut superseded = Vec::new();
                for q in all {
                    let winner = if q.reason == "future_hlc" {
                        storage
                            .get_field_version(
                                &sid,
                                &q.op.entity_table,
                                &q.op.entity_id,
                                &q.op.field_name,
                            )?
                            .map(|fv| merge::ReplayWinnerContext {
                                winning_device_id: fv.winning_device_id,
                                winning_hlc: fv.winning_hlc,
                            })
                    } else {
                        None
                    };
                    if merge::future_hlc_superseded(&q.reason, &q.op, winner.as_ref()) {
                        superseded.push(q.op_id.clone());
                        continue;
                    }
                    let schema_known = merge_engine.schema_quarantine_reason(&q.op).is_none();
                    if merge::is_replay_eligible(
                        &q.reason,
                        &q.op,
                        schema_known,
                        max_clock_drift_ms,
                        winner.as_ref(),
                    ) {
                        out.push(q);
                    }
                }
                Ok::<_, CoreError>((out, superseded))
            })
            .await
            .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))??;

        // Evict superseded future-HLC rows in their own tx (independent of any
        // replay work below) so the backlog shrinks even on a cycle with nothing
        // to replay.
        if !superseded_op_ids.is_empty() {
            let storage = self.storage.clone();
            let sid = sync_id.to_string();
            let to_evict = superseded_op_ids.clone();
            tokio::task::spawn_blocking(move || {
                let mut tx = storage.begin_tx()?;
                for op_id in &to_evict {
                    tx.delete_quarantined_op(&sid, op_id)?;
                }
                tx.commit()
            })
            .await
            .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))??;
            tracing::debug!(
                count = superseded_op_ids.len(),
                "Evicted superseded future-HLC quarantine rows"
            );
        }

        if replayable.is_empty() {
            return Ok((0, Vec::new()));
        }

        let ops: Vec<CrdtChange> = replayable.iter().map(|q| q.op.clone()).collect();
        let seq_by_op: HashMap<String, i64> =
            replayable.iter().map(|q| (q.op_id.clone(), q.server_seq)).collect();

        // Phase A: determine which now-schema-known ops win against current state.
        let storage = self.storage.clone();
        let sid = sync_id.to_string();
        let ops_vec = ops.clone();
        let merge_engine = self.merge_engine.clone();
        let seq_by_op_for_check = seq_by_op.clone();

        let (all_ops_checked, winning_ops) = tokio::task::spawn_blocking(move || {
            let mut checked: Vec<(CrdtChange, bool, i64)> = Vec::new();
            let get_fv = |sync_id: &str, table: &str, entity_id: &str, field: &str| {
                storage.get_field_version(sync_id, table, entity_id, field)
            };
            let is_applied = |op_id: &str| storage.is_op_applied(op_id);

            let outcome = merge_engine.determine_winners_with_quarantine(
                &ops_vec,
                &get_fv,
                &is_applied,
                &sid,
            )?;

            for op in &ops_vec {
                if merge_engine.schema_quarantine_reason(op).is_some() {
                    continue;
                }
                let already_applied = is_applied(&op.op_id)?;
                let server_seq = seq_by_op_for_check.get(&op.op_id).copied().unwrap_or_default();
                checked.push((op.clone(), already_applied, server_seq));
            }

            let winning_ops: Vec<CrdtChange> =
                outcome.winners.into_values().map(|w| w.op).collect();

            Ok::<_, CoreError>((checked, winning_ops))
        })
        .await
        .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))??;

        let merged_count = winning_ops.len() as u64;
        let entity_changes = Self::entity_changes_from_winning_ops(&winning_ops);

        // Phase B: write now-winning entity changes before sync bookkeeping.
        if !winning_ops.is_empty() {
            self.write_winning_ops_to_entities(&winning_ops).await?;
        }

        // Phase C: mark replayed known ops applied and remove them from quarantine.
        //
        // Delete ONLY the quarantine rows whose ops actually reached terminal
        // applied state this pass — i.e. ops that entered the checked-apply loop
        // (`all_ops_checked`). An op that passed `is_replay_eligible` but is then
        // skipped by the checked loop (e.g. a future_hlc op whose field is still
        // schema-unknown) must keep its quarantine row, or it would be lost: the
        // cursor is already past its batch, so the relay can no longer redeliver
        // it. The is_replay_eligible future_hlc arm now requires schema_known, so
        // this set should always equal `replayable`; the intersection is the
        // structural invariant that keeps that property from silently
        // regressing if a future reason re-quarantines during replay.
        let storage = self.storage.clone();
        let sid = sync_id.to_string();
        let applied_op_ids: HashSet<String> =
            all_ops_checked.iter().map(|(op, _, _)| op.op_id.clone()).collect();
        let replayed_op_ids: Vec<String> = replayable
            .into_iter()
            .map(|q| q.op_id)
            .filter(|op_id| applied_op_ids.contains(op_id))
            .collect();
        let seq_by_op_for_journal: HashMap<String, i64> = all_ops_checked
            .iter()
            .map(|(op, _, server_seq)| (op.op_id.clone(), *server_seq))
            .collect();
        tokio::task::spawn_blocking(move || {
            let mut tx = storage.begin_tx()?;

            for (op, was_already_applied, server_seq) in &all_ops_checked {
                // Replayed quarantined ops were admitted only after envelope
                // attribution validation. The persisted op device is the
                // trusted sender identity available on replay.
                debug_assert_remote_op_matches_sender(op, &op.device_id);
                if !was_already_applied {
                    tx.insert_applied_op(&AppliedOp {
                        op_id: op.op_id.clone(),
                        sync_id: sid.clone(),
                        epoch: op.epoch,
                        device_id: op.device_id.clone(),
                        client_hlc: op.client_hlc.clone(),
                        server_seq: *server_seq,
                        applied_at: chrono::Utc::now(),
                    })?;
                }
            }

            let deleted_entities = Self::deleted_entities_in(&winning_ops);
            for op in &winning_ops {
                debug_assert_remote_op_matches_sender(op, &op.device_id);
                tx.upsert_field_version(&FieldVersion {
                    sync_id: sid.clone(),
                    entity_table: op.entity_table.clone(),
                    entity_id: op.entity_id.clone(),
                    field_name: op.field_name.clone(),
                    winning_op_id: op.op_id.clone(),
                    winning_device_id: op.device_id.clone(),
                    winning_hlc: op.client_hlc.clone(),
                    winning_encoded_value: Some(op.encoded_value.clone()),
                    updated_at: chrono::Utc::now(),
                })?;
                // Journal the replayed winner alongside the quarantine delete so
                // a now-schema-known op is delivered to Dart exactly as a live
                // pull would be — its original `server_seq` is carried for order.
                // Subsumed-by-delete winners are not journaled (see the apply
                // path and `winner_should_journal`).
                if Self::winner_should_journal(op, &deleted_entities) {
                    let server_seq =
                        seq_by_op_for_journal.get(&op.op_id).copied().unwrap_or_default();
                    tx.insert_consumer_delivery(&Self::journal_row_for_winner(&sid, op, server_seq))?;
                }
            }

            for op_id in &replayed_op_ids {
                tx.delete_quarantined_op(&sid, op_id)?;
            }

            tx.commit()
        })
        .await
        .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))??;

        Ok((merged_count, entity_changes))
    }

    /// Apply a single remote batch: determine winners, write consumer data, then persist sync state.
    ///
    /// Returns `(merged_count, entity_changes)` where `entity_changes` contains the
    /// winning field values grouped by entity for consumer DB application.
    ///
    /// **CRITICAL ORDERING:** Consumer entity writes happen BEFORE sync bookkeeping commits.
    /// This ensures that if entity writes fail, sync state is not advanced -- the batch
    /// will be re-pulled and re-applied on next sync (idempotent via applied_ops check).
    /// If sync bookkeeping fails after entity writes succeed, replay is safe because
    /// the merge is idempotent and write_fields uses upsert semantics.
    /// `deferred_future_hlc` carries ops whose HLC is >60s ahead of the
    /// receiver's wall clock: they are quarantined per-op into
    /// `quarantined_ops` with reason `future_hlc` (never marked applied, never
    /// dropped) so Phase 0's reason-aware replay re-applies them with their
    /// ORIGINAL HLC the moment the local clock is within tolerance.
    #[tracing::instrument(skip(self, ops, deferred_future_hlc), err)]
    async fn apply_remote_batch(
        &self,
        sync_id: &str,
        ops: &[CrdtChange],
        deferred_future_hlc: &[CrdtChange],
        server_seq: i64,
        envelope_sender_device_id: &str,
        advance_cursor: bool,
    ) -> Result<(u64, Vec<EntityChange>)> {
        // Phase A: Determine winners (READ-ONLY -- no sync state persisted yet)
        let storage = self.storage.clone();
        let sid = sync_id.to_string();
        let ops_vec = ops.to_vec();
        let deferred_vec = deferred_future_hlc.to_vec();
        let merge_engine = self.merge_engine.clone();

        let (all_ops_checked, winning_ops, quarantined_ops) =
            tokio::task::spawn_blocking(move || {
                // Track which ops were already applied (for Phase C bookkeeping)
                let mut checked: Vec<(CrdtChange, bool)> = Vec::new();

                // Use non-transactional reads for winner determination
                let get_fv = |sync_id: &str, table: &str, entity_id: &str, field: &str| {
                    storage.get_field_version(sync_id, table, entity_id, field)
                };
                let is_applied = |op_id: &str| storage.is_op_applied(op_id);

                // Determine winners via MergeEngine
                let outcome = merge_engine.determine_winners_with_quarantine(
                    &ops_vec,
                    &get_fv,
                    &is_applied,
                    &sid,
                )?;

                // Build the checked ops list for bookkeeping
                for op in &ops_vec {
                    if merge_engine.schema_quarantine_reason(op).is_some() {
                        continue;
                    }
                    let already_applied = is_applied(&op.op_id)?;
                    checked.push((op.clone(), already_applied));
                }

                // Collect winning ops as a Vec
                let winning_ops: Vec<CrdtChange> =
                    outcome.winners.into_values().map(|w| w.op).collect();

                // Future-HLC ops deferred by `filter_batch_ops` join the
                // per-op quarantine lane with reason `future_hlc`. Skip any that
                // already landed in `applied_ops` on a prior cycle (a replayed
                // future-HLC op whose batch is re-seen) so this is idempotent.
                let mut quarantined = outcome.quarantined;
                for op in &deferred_vec {
                    if is_applied(&op.op_id)? {
                        continue;
                    }
                    quarantined.push(merge::QuarantinedChange {
                        op: op.clone(),
                        reason: merge::SchemaQuarantineReason::FutureHlc,
                    });
                }

                Ok::<_, CoreError>((checked, winning_ops, quarantined))
            })
            .await
            .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))??;

        let merged_count = winning_ops.len() as u64;

        // Build EntityChange list from winning ops, grouped by (table, entity_id).
        let entity_changes = {
            let mut change_map: HashMap<(String, String), EntityChange> = HashMap::new();
            for op in &winning_ops {
                let key = (op.entity_table.clone(), op.entity_id.clone());
                let entry = change_map.entry(key).or_insert_with(|| EntityChange {
                    table: op.entity_table.clone(),
                    entity_id: op.entity_id.clone(),
                    is_delete: false,
                    fields: HashMap::new(),
                });
                if op.is_delete {
                    entry.is_delete = true;
                    entry.fields.clear();
                } else {
                    entry.fields.insert(op.field_name.clone(), op.encoded_value.clone());
                }
            }
            change_map.into_values().collect::<Vec<_>>()
        };

        // Phase B: Write winning changes to consumer entity tables
        if !winning_ops.is_empty() {
            let mut tables_touched: HashSet<String> = HashSet::new();
            for op in &winning_ops {
                tables_touched.insert(op.entity_table.clone());
            }

            // Begin batch on all touched entities
            for entity in &self.entities {
                if tables_touched.contains(entity.table_name()) {
                    entity.begin_batch().await?;
                }
            }

            // Write fields / soft-delete for each winning op
            let write_result: Result<()> = async {
                for op in &winning_ops {
                    if let Some(entity) =
                        self.entities.iter().find(|e| e.table_name() == op.entity_table)
                    {
                        if op.is_delete {
                            entity.soft_delete(&op.entity_id, &op.client_hlc).await?;
                        } else {
                            let sync_type = self
                                .schema
                                .entity(&op.entity_table)
                                .and_then(|e| e.field_by_name(&op.field_name))
                                .map(|f| f.sync_type)
                                .unwrap_or(SyncType::String);
                            let decoded =
                                match crate::schema::decode_value(&op.encoded_value, sync_type) {
                                    Ok(v) => v,
                                    Err(e) => {
                                        tracing::warn!(
                                            table = %op.entity_table,
                                            entity_id = %op.entity_id,
                                            field = %op.field_name,
                                            encoded_value = %op.encoded_value,
                                            "Skipping field op with type mismatch: {e}. \
                                             Dart-side quarantine will record the bad value."
                                        );
                                        continue;
                                    }
                                };
                            let mut fields = HashMap::new();
                            fields.insert(op.field_name.clone(), decoded);
                            entity
                                .write_fields(
                                    &op.entity_id,
                                    &fields,
                                    &op.client_hlc,
                                    false, // is_new determined by consumer's upsert
                                )
                                .await?;
                        }
                    }
                }
                Ok(())
            }
            .await;

            match write_result {
                Ok(()) => {
                    // See `write_winning_ops_to_entities`: commit each touched
                    // entity defensively so a failing `commit_batch` rolls back
                    // the remaining touched entities' open batches instead of
                    // leaking dangling transactions (the Err arm below would not
                    // run on a bare `?`). Returning the error skips Phase C, so
                    // sync state never advances and the batch re-pulls.
                    let mut committed: Vec<&str> = Vec::new();
                    for entity in &self.entities {
                        if !tables_touched.contains(entity.table_name()) {
                            continue;
                        }
                        if let Err(e) = entity.commit_batch().await {
                            for entity in &self.entities {
                                let name = entity.table_name();
                                if tables_touched.contains(name) && !committed.contains(&name) {
                                    let _ = entity.rollback_batch().await;
                                }
                            }
                            return Err(e);
                        }
                        committed.push(entity.table_name());
                    }
                }
                Err(e) => {
                    for entity in &self.entities {
                        if tables_touched.contains(entity.table_name()) {
                            let _ = entity.rollback_batch().await;
                        }
                    }
                    // Entity writes failed -- do NOT persist sync state.
                    return Err(e);
                }
            }
        }

        // Phase C: ONLY AFTER entity writes succeed, persist sync bookkeeping.
        {
            let storage = self.storage.clone();
            let sid = sync_id.to_string();
            let ops_checked = all_ops_checked;
            let winners = winning_ops;
            let quarantined = quarantined_ops;
            let trusted_sender = envelope_sender_device_id.to_string();
            tokio::task::spawn_blocking(move || {
                let mut tx = storage.begin_tx()?;

                for quarantined in &quarantined {
                    debug_assert_remote_op_matches_sender(&quarantined.op, &trusted_sender);
                    tx.insert_quarantined_op(&QuarantinedOp {
                        sync_id: sid.clone(),
                        op_id: quarantined.op.op_id.clone(),
                        op: quarantined.op.clone(),
                        reason: quarantined.reason.as_str().to_string(),
                        server_seq,
                        quarantined_at: chrono::Utc::now(),
                    })?;
                }

                // Record all valid ops as applied (for idempotency on replay)
                for (op, was_already_applied) in &ops_checked {
                    debug_assert_remote_op_matches_sender(op, &trusted_sender);
                    if !was_already_applied {
                        tx.insert_applied_op(&AppliedOp {
                            op_id: op.op_id.clone(),
                            sync_id: sid.clone(),
                            epoch: op.epoch,
                            device_id: op.device_id.clone(),
                            client_hlc: op.client_hlc.clone(),
                            server_seq,
                            applied_at: chrono::Utc::now(),
                        })?;
                    }
                }

                // Update field_versions for winning ops only, and journal each
                // winner for at-least-once consumer delivery in the SAME tx so
                // the Rust cursor and the journal advance atomically.
                // A non-delete winner subsumed by a same-batch delete winner is
                // NOT journaled (the delete row alone tombstones the entity) so a
                // chunk boundary can never split [delete, fields] and resurrect
                // the row — see `winner_should_journal`.
                let deleted_entities = Self::deleted_entities_in(&winners);
                for op in &winners {
                    debug_assert_remote_op_matches_sender(op, &trusted_sender);
                    tx.upsert_field_version(&FieldVersion {
                        sync_id: sid.clone(),
                        entity_table: op.entity_table.clone(),
                        entity_id: op.entity_id.clone(),
                        field_name: op.field_name.clone(),
                        winning_op_id: op.op_id.clone(),
                        winning_device_id: op.device_id.clone(),
                        winning_hlc: op.client_hlc.clone(),
                        winning_encoded_value: Some(op.encoded_value.clone()),
                        updated_at: chrono::Utc::now(),
                    })?;
                    if Self::winner_should_journal(op, &deleted_entities) {
                        tx.insert_consumer_delivery(&Self::journal_row_for_winner(
                            &sid, op, server_seq,
                        ))?;
                    }
                }

                // Advance server_seq, except during Phase 0b quarantine replay:
                // a replayed batch carries its ORIGINAL (already-consumed) seq, so
                // advancing here is at best a no-op under MAX-monotonic semantics
                // and at worst confusing — gate it on the live-pull path only.
                if advance_cursor {
                    tx.update_last_pulled_seq(&sid, server_seq)?;
                }
                tx.commit()
            })
            .await
            .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))??;
        }

        Ok((merged_count, entity_changes))
    }

    /// Advance the pull cursor past a batch that is being consumed without
    /// applying anything (a self-batch, or a permanent skip-and-advance verdict
    /// such as a revoked sender). The cursor write is MAX-monotonic.
    ///
    /// `clear_stall_seq` clears a transient stall row in the SAME transaction as
    /// the advance (e.g. a Revoked verdict on a seq that previously stalled), so
    /// a crash can't leave a stall row behind a cursor that has permanently moved
    /// past it.
    async fn advance_cursor_past_seq(
        &self,
        sync_id: &str,
        server_seq: i64,
        clear_stall_seq: Option<i64>,
    ) -> Result<()> {
        let storage = self.storage.clone();
        let sid = sync_id.to_string();
        tokio::task::spawn_blocking(move || {
            let mut tx = storage.begin_tx()?;
            tx.update_last_pulled_seq(&sid, server_seq)?;
            if let Some(stall_seq) = clear_stall_seq {
                tx.clear_pull_stall(&sid, stall_seq)?;
            }
            tx.commit()
        })
        .await
        .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))??;
        Ok(())
    }

    /// Record (or bump) a transient pull stall on `server_seq`. Returns the
    /// resulting `attempts` count so the caller can compare it against the stall
    /// budget. Does NOT emit [`SyncEvent::PullStalled`] — the caller emits it only
    /// once it knows the batch is staying stalled (not converting to quarantine
    /// this cycle), so the conversion cycle emits a single `PullBatchQuarantined`
    /// rather than both events for the same seq (which a diagnostics consumer
    /// would otherwise double-count).
    ///
    /// A stall does NOT advance the cursor: the batch (and everything after it on
    /// the page) is left unconsumed so the next cycle retries from the same seq,
    /// while the already-processed earlier batches keep their advances and the
    /// push phase still runs. This is the stall discipline — a transient
    /// registry-fetch failure never lets the relay prune the batch.
    async fn stall_pull_batch(
        &self,
        sync_id: &str,
        server_seq: i64,
        reason: TransientPullReason,
    ) -> Result<i64> {
        let storage = self.storage.clone();
        let sid = sync_id.to_string();
        let reason_str = reason.as_str().to_string();
        let attempts = tokio::task::spawn_blocking(move || -> Result<i64> {
            let mut tx = storage.begin_tx()?;
            tx.record_pull_stall(&sid, server_seq, &reason_str)?;
            tx.commit()?;
            // Read back the post-increment attempts via the SyncStorage view.
            let attempts = storage
                .list_pull_stalls(&sid)?
                .into_iter()
                .find(|s| s.server_seq == server_seq)
                .map(|s| s.attempts)
                .unwrap_or(1);
            Ok(attempts)
        })
        .await
        .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))??;

        Ok(attempts)
    }

    /// Whether a stall on `server_seq` has exhausted its retry budget and must
    /// convert to quarantine-and-advance (the chosen bound: 8
    /// sync cycles or 24h wall clock, whichever trips first).
    ///
    /// `attempts` is the running `pull_stall.attempts` count; the age is read
    /// from the existing stall row's `first_seen_at` so a rarely-syncing device
    /// (fewer than the cycle budget in a day) still converts after the wall-clock
    /// ceiling rather than holding the relay off its prune floor indefinitely.
    async fn stall_budget_exhausted(
        &self,
        sync_id: &str,
        server_seq: i64,
        attempts: i64,
    ) -> Result<bool> {
        if attempts >= self.config.pull_stall_max_attempts {
            return Ok(true);
        }
        let storage = self.storage.clone();
        let sid = sync_id.to_string();
        let first_seen = tokio::task::spawn_blocking(move || -> Result<Option<DateTime<Utc>>> {
            Ok(storage
                .list_pull_stalls(&sid)?
                .into_iter()
                .find(|s| s.server_seq == server_seq)
                .map(|s| s.first_seen_at))
        })
        .await
        .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))??;
        if let Some(first_seen) = first_seen {
            let age_ms = Utc::now().signed_duration_since(first_seen).num_milliseconds();
            if age_ms >= self.config.pull_stall_max_age_ms {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Clear a transient stall row for `server_seq` ONLY if its current reason
    /// matches `reason`. Used where a seq can be stalled for more than one reason
    /// across the pull pipeline (sender resolution vs. ML-DSA generation): a site
    /// that resolves one condition must not wipe the budget another condition is
    /// still accumulating on the same seq. Idempotent (no row / different reason
    /// is a no-op).
    async fn clear_pull_stall_for_seq_if_reason(
        &self,
        sync_id: &str,
        server_seq: i64,
        reason: TransientPullReason,
    ) -> Result<()> {
        let storage = self.storage.clone();
        let sid = sync_id.to_string();
        let want = reason.as_str().to_string();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let matches = storage
                .list_pull_stalls(&sid)?
                .into_iter()
                .any(|s| s.server_seq == server_seq && s.reason == want);
            if matches {
                let mut tx = storage.begin_tx()?;
                tx.clear_pull_stall(&sid, server_seq)?;
                tx.commit()?;
            }
            Ok(())
        })
        .await
        .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))??;
        Ok(())
    }

    /// Clear any transient stall row for `server_seq` — the batch has resolved
    /// (applied) or converted to a durable quarantine, so the budget no longer
    /// applies. Idempotent.
    async fn clear_pull_stall_for_seq(&self, sync_id: &str, server_seq: i64) -> Result<()> {
        let storage = self.storage.clone();
        let sid = sync_id.to_string();
        tokio::task::spawn_blocking(move || {
            let mut tx = storage.begin_tx()?;
            tx.clear_pull_stall(&sid, server_seq)?;
            tx.commit()
        })
        .await
        .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))??;
        Ok(())
    }

    /// Durably quarantine a poison pull batch and advance the cursor past it, in
    /// one transaction, then emit [`SyncEvent::PullBatchQuarantined`].
    ///
    /// The full `SignedBatchEnvelope` is preserved so Phase 0b replay can re-run
    /// the complete pipeline once the blocking condition clears (a cross-version
    /// decode skew resolves after an app upgrade; a stale-registry signature
    /// verifies after the registry propagates). Re-quarantining an already-stored
    /// batch (same `batch_id`) preserves its accumulated `retry_count` and
    /// original `quarantined_at` rather than resetting them.
    ///
    /// `clear_stall_seq` clears a transient stall row in the SAME transaction as
    /// the quarantine insert + cursor advance (the budget-exhaustion conversion
    /// from stall to quarantine), so a crash can't leave a stall row behind a
    /// cursor that has permanently moved past the seq.
    async fn quarantine_pull_batch(
        &self,
        sync_id: &str,
        batch: &crate::relay::traits::ReceivedBatch,
        reason: PermanentPullReason,
        clear_stall_seq: Option<i64>,
    ) -> Result<()> {
        let storage = self.storage.clone();
        let sid = sync_id.to_string();
        let envelope = batch.envelope.clone();
        let server_seq = batch.server_seq;
        let reason_str = reason.as_str().to_string();
        tokio::task::spawn_blocking(move || {
            // Preserve an existing row's accumulated retry budget / first-seen
            // timestamp if this batch was already quarantined on a prior cycle
            // (read via the SyncStorage view before opening the write tx).
            let existing = storage.list_quarantined_pull_batches(&sid)?.into_iter().find(|b| {
                b.batch_id == envelope.batch_id
                    && b.sender_device_id == envelope.sender_device_id
            });
            let (retry_count, quarantined_at, last_retry_at) = match existing {
                Some(prev) => (prev.retry_count, prev.quarantined_at, prev.last_retry_at),
                None => (0, chrono::Utc::now(), None),
            };
            let mut tx = storage.begin_tx()?;
            tx.insert_quarantined_pull_batch(&QuarantinedPullBatch {
                sync_id: sid.clone(),
                batch_id: envelope.batch_id.clone(),
                server_seq,
                epoch: Some(envelope.epoch),
                sender_device_id: envelope.sender_device_id.clone(),
                envelope,
                reason: reason_str,
                retry_count,
                quarantined_at,
                last_retry_at,
            })?;
            tx.update_last_pulled_seq(&sid, server_seq)?;
            if let Some(stall_seq) = clear_stall_seq {
                tx.clear_pull_stall(&sid, stall_seq)?;
            }
            tx.commit()
        })
        .await
        .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))??;

        self.emit_event(SyncEvent::PullBatchQuarantined {
            server_seq,
            batch_id: batch.envelope.batch_id.clone(),
            sender_device_id: batch.envelope.sender_device_id.clone(),
            reason: reason.as_str().to_string(),
        });

        Ok(())
    }

    /// Phase 0b: re-run the full pull pipeline (resolve sender -> verify ->
    /// decrypt -> verify payload hash -> decode -> filter -> apply) on every
    /// durably quarantined batch, so a batch that was poison at quarantine time
    /// applies the moment its blocking condition clears.
    ///
    /// Replay never advances the cursor (`apply_remote_batch(advance_cursor =
    /// false)`): the cursor is already past these seqs. On success the quarantine
    /// row is deleted; if the sender has since been revoked the row is terminally
    /// dropped without applying (fail-closed); on an identical failure the
    /// `retry_count` is bumped so a permanently-unapplicable batch backs off
    /// instead of churning the merge engine every cycle.
    ///
    /// Each row is gated by [`quarantine_replay_eligible`] before any work runs,
    /// so a row inside its exponential backoff window is skipped entirely — no
    /// crypto, no decode, and no relay registry fetch (the sender-resolution path
    /// would otherwise hit the network for an unknown/deregistered/future-gen
    /// sender on every cycle).
    async fn replay_quarantined_pull_batches(
        &self,
        sync_id: &str,
        key_hierarchy: &prism_sync_crypto::KeyHierarchy,
    ) -> Result<(u64, Vec<EntityChange>)> {
        let storage = self.storage.clone();
        let sid = sync_id.to_string();
        let quarantined: Vec<QuarantinedPullBatch> =
            tokio::task::spawn_blocking(move || storage.list_quarantined_pull_batches(&sid))
                .await
                .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))??;

        if quarantined.is_empty() {
            return Ok((0, Vec::new()));
        }

        let mut total_merged = 0u64;
        let mut all_entity_changes: Vec<EntityChange> = Vec::new();
        let now = Utc::now();
        let backoff_base_ms = self.config.quarantine_replay_backoff_base_ms;

        for q in quarantined {
            // Reason/time-aware eligibility gate: skip a row that is still inside
            // its exponential backoff window. This must run BEFORE
            // try_replay_quarantined_batch so an ineligible row triggers no
            // crypto, no decode, and — critically — no relay registry fetch (the
            // sender-resolution path in try_replay hits the network for an
            // unknown/deregistered/future-generation sender). Without it a
            // permanently-poison row churns all of that every single cycle.
            if !quarantine_replay_eligible(now, q.retry_count, q.last_retry_at, backoff_base_ms) {
                tracing::trace!(
                    batch_id = %q.batch_id,
                    sender_device_id = %q.sender_device_id,
                    reason = %q.reason,
                    retry_count = q.retry_count,
                    "Skipping quarantined pull batch: still within replay backoff"
                );
                continue;
            }
            match self.try_replay_quarantined_batch(sync_id, key_hierarchy, &q).await {
                Ok(Some((merged, changes))) => {
                    total_merged += merged;
                    all_entity_changes.extend(changes);
                    let storage = self.storage.clone();
                    let sid = sync_id.to_string();
                    let sender = q.sender_device_id.clone();
                    let batch_id = q.batch_id.clone();
                    tokio::task::spawn_blocking(move || {
                        let mut tx = storage.begin_tx()?;
                        tx.delete_quarantined_pull_batch(&sid, &sender, &batch_id)?;
                        tx.commit()
                    })
                    .await
                    .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))??;
                }
                // Terminal discard: the sender was revoked, so nothing from the
                // batch will ever apply — drop the row instead of retrying forever.
                Ok(None) => {
                    let storage = self.storage.clone();
                    let sid = sync_id.to_string();
                    let sender = q.sender_device_id.clone();
                    let batch_id = q.batch_id.clone();
                    tracing::info!(
                        batch_id = %batch_id,
                        sender_device_id = %sender,
                        "Discarding quarantined pull batch from revoked sender"
                    );
                    tokio::task::spawn_blocking(move || {
                        let mut tx = storage.begin_tx()?;
                        tx.delete_quarantined_pull_batch(&sid, &sender, &batch_id)?;
                        tx.commit()
                    })
                    .await
                    .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))??;
                }
                // Still poison (registry not yet propagated, decoder still can't
                // parse it). Back off so it doesn't churn every cycle.
                Err(e) => {
                    tracing::debug!(
                        batch_id = %q.batch_id,
                        reason = %q.reason,
                        "Quarantined pull batch still unapplicable: {e}"
                    );
                    let storage = self.storage.clone();
                    let sid = sync_id.to_string();
                    let sender = q.sender_device_id.clone();
                    let batch_id = q.batch_id.clone();
                    tokio::task::spawn_blocking(move || {
                        let mut tx = storage.begin_tx()?;
                        tx.bump_quarantined_pull_batch_retry(&sid, &sender, &batch_id)?;
                        tx.commit()
                    })
                    .await
                    .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))??;
                }
            }
        }

        Ok((total_merged, all_entity_changes))
    }

    /// Re-run the pull pipeline for a single quarantined batch.
    ///
    /// `Ok(Some(..))` = applied; `Ok(None)` = sender revoked, discard terminally;
    /// `Err(..)` = still poison, keep the row and back off.
    async fn try_replay_quarantined_batch(
        &self,
        sync_id: &str,
        key_hierarchy: &prism_sync_crypto::KeyHierarchy,
        q: &QuarantinedPullBatch,
    ) -> Result<Option<(u64, Vec<EntityChange>)>> {
        let envelope = &q.envelope;

        // Resolve sender keys. A revoked sender is a terminal verdict: discard.
        let sender_key_info = match self
            .resolve_sender_keys_with_generation_hint(
                sync_id,
                &envelope.sender_device_id,
                Some(envelope.sender_ml_dsa_key_generation),
            )
            .await
        {
            Ok(ki) => ki,
            Err(_) => {
                if self.sender_is_revoked(sync_id, &envelope.sender_device_id).await? {
                    return Ok(None);
                }
                return Err(CoreError::Engine(format!(
                    "sender {} not yet resolvable for quarantined batch {}",
                    envelope.sender_device_id, envelope.batch_id
                )));
            }
        };

        // Generation-aware verification: resolve the exact-generation key
        // (current record or archived history) and verify under it. A `None` key
        // means the generation still has not propagated — keep the row and back
        // off (returning Err) rather than verifying against the wrong generation.
        // A `stale_key_generation` quarantine thus applies the moment the
        // gen-matching key arrives (registry import / device_key_history archive).
        let verify_ml_dsa_pk = self
            .resolve_verification_ml_dsa_key(
                sync_id,
                &envelope.sender_device_id,
                envelope.sender_ml_dsa_key_generation,
                &sender_key_info,
            )
            .await?
            .ok_or_else(|| CoreError::StaleKeyGeneration {
                device_id: envelope.sender_device_id.clone(),
                envelope_gen: envelope.sender_ml_dsa_key_generation,
                registry_gen: sender_key_info.ml_dsa_key_generation,
            })?;
        batch_signature::verify_batch_signature(
            envelope,
            &sender_key_info.ed25519_pk,
            &verify_ml_dsa_pk,
        )?;

        let epoch_key = key_hierarchy
            .epoch_key(envelope.epoch as u32)
            .map_err(|_| CoreError::MissingEpochKey { epoch: envelope.epoch as u32 })?;
        let aad = sync_aad::build_sync_aad(
            sync_id,
            &envelope.sender_device_id,
            envelope.epoch,
            &envelope.batch_id,
            &envelope.batch_kind,
        );
        let plaintext = prism_sync_crypto::aead::xchacha_decrypt_from_sync(
            epoch_key,
            &envelope.ciphertext,
            &envelope.nonce,
            &aad,
        )
        .map_err(|source| CoreError::DecryptFailed { epoch: envelope.epoch as u32, source })?;

        batch_signature::verify_payload_hash(envelope, &plaintext)?;

        let ops = CrdtChange::decode_batch(&plaintext)?;
        let (ops, deferred) = match Self::filter_batch_ops(
            ops,
            &envelope.sender_device_id,
            self.config.max_clock_drift_ms,
        ) {
            BatchFilterOutcome::Accepted { accepted, deferred } => (accepted, deferred),
            // An attribution mismatch is deterministic and can never clear, but
            // the data is fail-closed (never applied) either way — keep the row
            // so the disposition stays explicit rather than silently dropping.
            BatchFilterOutcome::AttributionMismatch(detail) => {
                return Err(CoreError::Engine(detail));
            }
        };

        self.set_state(SyncState::Merging);
        // A whole-batch quarantine replay re-runs `filter_batch_ops`; any op
        // still beyond drift tolerance is re-deferred into the per-op
        // `quarantined_ops` lane (idempotent insert), so a future-HLC op inside a
        // batch that was quarantined for a *different* reason (e.g. a stale
        // sender key that has now resolved) is not lost when the batch row clears.
        let (merged, changes) = self
            .apply_remote_batch(
                sync_id,
                &ops,
                &deferred,
                q.server_seq,
                &envelope.sender_device_id,
                false, // Phase 0b replay must never rewind/advance the cursor
            )
            .await?;
        Ok(Some((merged, changes)))
    }

    /// Whether a sender device has a local registry record with a non-active
    /// status (revoked). Used by Phase 0b replay to terminally discard batches
    /// from a device that was revoked after the batch was quarantined.
    async fn sender_is_revoked(&self, sync_id: &str, sender_device_id: &str) -> Result<bool> {
        let storage = self.storage.clone();
        let sid = sync_id.to_string();
        let sender_id = sender_device_id.to_string();
        let record =
            tokio::task::spawn_blocking(move || storage.get_device_record(&sid, &sender_id))
                .await
                .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))??;
        Ok(matches!(record, Some(r) if r.status != "active"))
    }

    /// Push phase: encrypt and push dirty local batches.
    ///
    /// **Idempotency note:** If `mark_batch_pushed` fails after the relay
    /// accepts the push, the batch will be re-pushed on the next sync cycle.
    /// The relay MUST support idempotent push by deduplicating on `batch_id`
    /// (sent via X-Batch-Id header). If the relay does not deduplicate,
    /// the merge engine handles duplicate batches gracefully via the
    /// `applied_ops` idempotency table.
    #[tracing::instrument(
        skip(self, key_hierarchy, signing_key, ml_dsa_signing_key),
        fields(sync_id, device_id),
        err
    )]
    async fn push_phase(
        &self,
        sync_id: &str,
        key_hierarchy: &prism_sync_crypto::KeyHierarchy,
        signing_key: &ed25519_dalek::SigningKey,
        ml_dsa_signing_key: Option<&prism_sync_crypto::DevicePqSigningKey>,
        device_id: &str,
        ml_dsa_key_generation: u32,
    ) -> Result<(u64, bool)> {
        // Get dirty batch IDs
        let storage = self.storage.clone();
        let sid = sync_id.to_string();
        let batch_ids = tokio::task::spawn_blocking(move || storage.get_unpushed_batch_ids(&sid))
            .await
            .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))??;

        if batch_ids.is_empty() {
            return Ok((0, false));
        }

        // Read the authoritative group epoch once at the top of the push
        // phase. Epoch rotation serializes through `handle.inner.lock()`, so
        // the group epoch cannot change mid-push; a per-batch read would be
        // redundant I/O. We use this value instead of the op's stored epoch
        // so that pending ops created before an epoch rotation are still
        // pushed at the current epoch — the relay rejects envelopes whose
        // epoch does not match `group.current_epoch`, and the envelope epoch
        // is bound into signature + AAD. Merge semantics use HLC + device_id
        // + op_id (not epoch), so re-tagging the envelope is safe.
        let storage = self.storage.clone();
        let sid = sync_id.to_string();
        let current_epoch_i32: i32 =
            tokio::task::spawn_blocking(move || storage.get_sync_metadata(&sid))
                .await
                .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))??
                .map(|m| m.current_epoch)
                .unwrap_or(0);

        let push_cap = self.config.push_batch_cap;
        let mut pushed_count = 0u64;
        let mut push_incomplete = false;

        for batch_id in &batch_ids {
            // Per-cycle push cap: stop once we've pushed `push_cap` batches,
            // flagging the remainder so the driver re-arms another cycle. This
            // bounds how long a cycle spends pushing so a large outbound backlog
            // can't starve the (Phase 1) pull. `0` disables the cap.
            if push_cap != 0 && pushed_count >= push_cap as u64 {
                push_incomplete = true;
                break;
            }

            // Load batch ops
            let storage = self.storage.clone();
            let bid = batch_id.clone();
            let ops = tokio::task::spawn_blocking(move || storage.load_batch_ops(&bid))
                .await
                .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))??;

            if ops.is_empty() {
                continue;
            }

            // Defensive `.max` handles the degenerate case where sync_metadata
            // is missing (first push) or somehow behind the stored op epoch.
            let epoch = current_epoch_i32.max(ops[0].epoch);

            // Cache entity_table / entity_id for diagnostic quarantine rows.
            // Field-write batches cover one entity. `record_delete_multi` packs
            // tombstones for MANY entities into one batch, so for those the
            // first op is only a representative label on the (diagnostic-only)
            // quarantine row — convergence keys per-op by (table, entity_id).
            let entity_table = ops[0].entity_table.clone();
            let entity_id = ops[0].entity_id.clone();

            // Convert PendingOps to CrdtChanges for encoding
            let changes: Vec<CrdtChange> = ops
                .iter()
                .map(|op| CrdtChange {
                    op_id: op.op_id.clone(),
                    batch_id: Some(op.local_batch_id.clone()),
                    entity_id: op.entity_id.clone(),
                    entity_table: op.entity_table.clone(),
                    field_name: op.field_name.clone(),
                    encoded_value: op.encoded_value.clone(),
                    client_hlc: op.client_hlc.clone(),
                    is_delete: op.is_delete,
                    device_id: op.device_id.clone(),
                    // Re-tag at the push-time epoch so the envelope and the
                    // embedded change records agree. Storage is unchanged.
                    epoch,
                    server_seq: None,
                })
                .collect();

            // Encode to JSON bytes
            let plaintext = CrdtChange::encode_batch(&changes)?;

            // Compute payload hash
            let payload_hash = batch_signature::compute_payload_hash(&plaintext);

            // Get epoch key for encryption
            let epoch_key = key_hierarchy.epoch_key(epoch as u32).map_err(|_| {
                tracing::error!(
                    push_epoch = epoch,
                    batch_id = %batch_id,
                    known_epochs = ?key_hierarchy.known_epochs(),
                    "engine: missing epoch key — cannot encrypt pending batch"
                );
                CoreError::MissingEpochKey { epoch: epoch as u32 }
            })?;

            // Build AAD and encrypt
            let aad = sync_aad::build_sync_aad(sync_id, device_id, epoch, batch_id, "ops");
            let (ciphertext, nonce) =
                prism_sync_crypto::aead::xchacha_encrypt_for_sync(epoch_key, &plaintext, &aad)
                    .map_err(|e| CoreError::Engine(format!("Encrypt failed: {e}")))?;

            // Sign the batch
            let ml_dsa_sk = ml_dsa_signing_key.ok_or_else(|| {
                CoreError::Engine("ML-DSA signing key required for hybrid batch signing".into())
            })?;
            let envelope = batch_signature::sign_batch(
                signing_key,
                ml_dsa_sk,
                sync_id,
                epoch,
                batch_id,
                "ops",
                device_id,
                ml_dsa_key_generation,
                &payload_hash,
                nonce,
                ciphertext,
            )?;

            // Measure the serialized envelope and apply the client-side body
            // guard before contacting the relay. Phase 1A's measured
            // partitioner should keep us well under this cap, but we still
            // check here so that any pathological case (oversized single
            // field, future schema changes, broken estimator) lands in
            // quarantine rather than 413-looping forever.
            let envelope_json = serde_json::to_vec(&envelope).map_err(|e| {
                CoreError::Engine(format!("failed to serialize envelope for size check: {e}"))
            })?;
            let body_bytes = envelope_json.len();

            if body_bytes > RELAY_BODY_GUARD_BYTES {
                tracing::warn!(
                    batch_id = %batch_id,
                    body_bytes,
                    guard = RELAY_BODY_GUARD_BYTES,
                    "engine: envelope exceeds client-side body guard — quarantining without push"
                );
                let error_message = format!(
                    "Envelope body {body_bytes} bytes exceeds client guard {RELAY_BODY_GUARD_BYTES}"
                );
                self.quarantine_batch_record(
                    sync_id,
                    batch_id,
                    &entity_table,
                    &entity_id,
                    body_bytes,
                    "payload_too_large_client_guard",
                    &error_message,
                )
                .await?;
                self.emit_event(SyncEvent::QuarantinedBatch {
                    batch_id: batch_id.clone(),
                    entity_table: entity_table.clone(),
                    entity_id: entity_id.clone(),
                    body_bytes,
                    error_code: "payload_too_large_client_guard".to_string(),
                    error_message,
                });
                continue;
            }

            // Push to relay
            let outgoing = OutgoingBatch { batch_id: batch_id.clone(), envelope };
            match self.relay.push_changes(outgoing).await {
                Ok(_) => {
                    // Mark batch as pushed
                    let storage = self.storage.clone();
                    let bid = batch_id.clone();
                    let sid = sync_id.to_string();
                    tokio::task::spawn_blocking(move || {
                        let mut tx = storage.begin_tx()?;
                        tx.mark_batch_pushed(&bid)?;
                        tx.delete_pushed_ops(&sid, &bid)?;
                        tx.commit()?;
                        Ok::<_, CoreError>(())
                    })
                    .await
                    .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))??;

                    pushed_count += 1;
                }
                Err(relay_err) if is_payload_too_large_error(&relay_err) => {
                    tracing::warn!(
                        batch_id = %batch_id,
                        body_bytes,
                        relay_error = %relay_err,
                        "engine: relay returned 413 — quarantining batch and continuing"
                    );
                    let error_message = relay_err.to_string();
                    self.quarantine_batch_record(
                        sync_id,
                        batch_id,
                        &entity_table,
                        &entity_id,
                        body_bytes,
                        "payload_too_large",
                        &error_message,
                    )
                    .await?;
                    self.emit_event(SyncEvent::QuarantinedBatch {
                        batch_id: batch_id.clone(),
                        entity_table: entity_table.clone(),
                        entity_id: entity_id.clone(),
                        body_bytes,
                        error_code: "payload_too_large".to_string(),
                        error_message,
                    });
                    continue;
                }
                Err(relay_err) => {
                    return Err(CoreError::from_relay(relay_err));
                }
            }
        }

        Ok((pushed_count, push_incomplete))
    }

    /// Persist a `push_quarantine` row for a batch that failed the body
    /// guard or was rejected with 413. Shared by both branches so the SQL
    /// and the tx lifecycle stay in one place.
    async fn quarantine_batch_record(
        &self,
        sync_id: &str,
        batch_id: &str,
        entity_table: &str,
        entity_id: &str,
        body_bytes: usize,
        error_code: &str,
        error_message: &str,
    ) -> Result<()> {
        let storage = self.storage.clone();
        let sid = sync_id.to_string();
        let bid = batch_id.to_string();
        let etable = entity_table.to_string();
        let eid = entity_id.to_string();
        let code = error_code.to_string();
        let msg = error_message.to_string();
        let body_i64 = body_bytes as i64;
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut tx = storage.begin_tx()?;
            tx.quarantine_batch(&sid, &bid, &etable, &eid, body_i64, &code, &msg)?;
            tx.commit()?;
            Ok(())
        })
        .await
        .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))??;
        Ok(())
    }

    // ── Snapshot operations ──

    /// Create and upload an encrypted snapshot for device pairing.
    ///
    /// The existing device calls this after generating an invite. The snapshot
    /// is encrypted with the current epoch key and uploaded with a TTL.
    ///
    /// The size of the raw zstd-compressed export is checked against
    /// `MAX_SNAPSHOT_COMPRESSED_BYTES` BEFORE any encryption or network work.
    /// Oversized state fails with `CoreError::SnapshotTooLarge { bytes }` and
    /// the relay is never contacted.
    #[allow(clippy::too_many_arguments)]
    pub async fn upload_pairing_snapshot(
        &self,
        sync_id: &str,
        key_hierarchy: &prism_sync_crypto::KeyHierarchy,
        epoch: i32,
        device_id: &str,
        signing_key: &ed25519_dalek::SigningKey,
        ml_dsa_signing_key: &prism_sync_crypto::DevicePqSigningKey,
        ml_dsa_key_generation: u32,
        ttl_secs: Option<u64>,
        for_device_id: Option<String>,
        progress: Option<SnapshotUploadProgress>,
    ) -> Result<()> {
        // 1. Export snapshot from storage (already zstd-compressed)
        let storage = self.storage.clone();
        let sid = sync_id.to_string();
        let snapshot_data = tokio::task::spawn_blocking(move || storage.export_snapshot(&sid))
            .await
            .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))??;

        // 1b. Size probe — reject oversized snapshots BEFORE encrypting or
        // contacting the relay. This is the compressed-byte gate; the outer
        // wire-byte limit is enforced relay-side.
        if snapshot_data.len() > snapshot_limits::MAX_SNAPSHOT_COMPRESSED_BYTES {
            return Err(CoreError::SnapshotTooLarge { bytes: snapshot_data.len() });
        }

        // 2. Get last pulled seq as the snapshot point
        let storage = self.storage.clone();
        let sid = sync_id.to_string();
        let server_seq = tokio::task::spawn_blocking(move || {
            let meta = storage.get_sync_metadata(&sid)?;
            Ok::<_, CoreError>(meta.map(|m| m.last_pulled_server_seq).unwrap_or(0))
        })
        .await
        .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))??;

        // 3. Encrypt with epoch key + snapshot AAD (binds metadata to ciphertext)
        let epoch_key = key_hierarchy
            .epoch_key(epoch as u32)
            .map_err(|e| CoreError::Engine(format!("no epoch key: {e}")))?;
        let batch_id = format!("snapshot-{}", chrono::Utc::now().timestamp_millis());
        let aad = crate::sync_aad::build_snapshot_aad(
            sync_id, device_id, epoch, server_seq, &batch_id, "snapshot",
        );
        let (ciphertext, nonce) =
            prism_sync_crypto::aead::xchacha_encrypt_for_sync(epoch_key, &snapshot_data, &aad)
                .map_err(|e| CoreError::Engine(format!("snapshot encrypt failed: {e}")))?;

        // 4. Compute payload hash and sign the snapshot as a batch envelope
        let payload_hash = crate::batch_signature::compute_payload_hash(&snapshot_data);
        let envelope = crate::batch_signature::sign_batch(
            signing_key,
            ml_dsa_signing_key,
            sync_id,
            epoch,
            &batch_id,
            "snapshot",
            device_id,
            ml_dsa_key_generation,
            &payload_hash,
            nonce,
            ciphertext,
        )?;

        // 5. Serialize the envelope to JSON bytes and upload
        let envelope_bytes =
            serde_json::to_vec(&envelope).map_err(|e| CoreError::Serialization(e.to_string()))?;
        // Clone before `for_device_id` is moved into `put_snapshot`;
        // the SnapshotStale arm below feeds it to the suppression matrix.
        let our_target = for_device_id.clone();
        match self
            .relay
            .put_snapshot(
                epoch,
                server_seq,
                envelope_bytes,
                ttl_secs,
                for_device_id,
                device_id.to_string(),
                progress,
            )
            .await
        {
            Ok(()) => Ok(()),
            // Route the 409 through the suppression matrix
            // (`should_suppress_stale_snapshot`) instead of letting it
            // become a generic `CoreError::Relay` event — only the
            // audience-compatible cases (both untargeted, or same
            // specific target) are success-equivalent.
            Err(crate::relay::traits::RelayError::SnapshotStale {
                current_server_seq_at,
                current_target_device_id,
            }) => {
                if should_suppress_stale_snapshot(
                    our_target.as_deref(),
                    current_target_device_id.as_deref(),
                    server_seq,
                    current_server_seq_at,
                ) {
                    tracing::debug!(
                        sync_id = %sync_id,
                        current_server_seq_at,
                        our_server_seq = server_seq,
                        our_target = ?our_target,
                        existing_target = ?current_target_device_id,
                        "snapshot upload superseded by newer server snapshot; treating as success"
                    );
                    Ok(())
                } else {
                    tracing::warn!(
                        sync_id = %sync_id,
                        current_server_seq_at,
                        our_server_seq = server_seq,
                        our_target = ?our_target,
                        existing_target = ?current_target_device_id,
                        "snapshot upload superseded with incompatible audience; propagating"
                    );
                    Err(CoreError::from_relay(crate::relay::traits::RelayError::SnapshotStale {
                        current_server_seq_at,
                        current_target_device_id,
                    }))
                }
            }
            Err(other) => Err(CoreError::from_relay(other)),
        }
    }

    /// Seed `field_versions` from pre-existing local data (first-device
    /// bootstrap, Phase A of `docs/plans/first-device-bootstrap-snapshot.md`).
    ///
    /// This is the offline prep step: the existing Drift tables are walked on
    /// the Dart side, turned into `SeedRecord`s, and handed to us. For each
    /// record we emit one HLC-stamped `field_versions` write without a
    /// `pending_op`, so nothing will be pushed to the relay. After seeding we
    /// compute the max HLC across all seeded rows and feed it back into a
    /// fresh `OpEmitter` so any subsequent `record_create` uses a strictly
    /// greater HLC. Finally we run a local-only size probe to catch
    /// oversized states before the user tries to pair.
    ///
    /// Guard invariants (all must hold, otherwise returns
    /// `CoreError::BootstrapNotAllowed`):
    /// - `count_devices_in_group(sync_id) == 1`: sole registered device.
    /// - `last_pulled_server_seq == 0`: never pulled from a relay.
    /// - `has_any_applied_ops == false`: never merged a remote op.
    pub async fn bootstrap_existing_state(
        &self,
        sync_id: &str,
        records: Vec<SeedRecord>,
    ) -> Result<BootstrapReport> {
        // ── Guard ─────────────────────────────────────────────────────────
        let storage = self.storage.clone();
        let sid = sync_id.to_string();
        let device_count =
            tokio::task::spawn_blocking(move || storage.count_devices_in_group(&sid))
                .await
                .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))??;
        if device_count != 1 {
            return Err(CoreError::BootstrapNotAllowed(format!(
                "expected exactly 1 device in registry, found {device_count}"
            )));
        }

        let storage = self.storage.clone();
        let sid = sync_id.to_string();
        let last_pulled = tokio::task::spawn_blocking(move || storage.get_sync_metadata(&sid))
            .await
            .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))??
            .map(|m| m.last_pulled_server_seq)
            .unwrap_or(0);
        if last_pulled != 0 {
            return Err(CoreError::BootstrapNotAllowed(format!(
                "last_pulled_server_seq must be 0 to bootstrap, found {last_pulled}"
            )));
        }

        let storage = self.storage.clone();
        let sid = sync_id.to_string();
        let has_applied = tokio::task::spawn_blocking(move || storage.has_any_applied_ops(&sid))
            .await
            .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))??;
        if has_applied {
            return Err(CoreError::BootstrapNotAllowed(
                "applied_ops table is non-empty; cannot bootstrap".into(),
            ));
        }

        // ── Cleanup orphan pending_ops ────────────────────────────────────
        let storage = self.storage.clone();
        let sid = sync_id.to_string();
        let removed = tokio::task::spawn_blocking(move || storage.delete_all_pending_ops(&sid))
            .await
            .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))??;
        if removed > 0 {
            tracing::info!(count = removed, "bootstrap_existing_state: cleared orphan pending_ops");
        }

        let entity_count = records.len() as u64;

        // ── Seed ──────────────────────────────────────────────────────────
        // Pull node_id and epoch from storage metadata so the emitter uses
        // the correct identity without requiring the caller to thread it
        // through. We need at least one device record to exist — the guard
        // above proved device_count == 1.
        let storage = self.storage.clone();
        let sid = sync_id.to_string();
        let devices = tokio::task::spawn_blocking(move || storage.list_device_records(&sid))
            .await
            .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))??;
        let first_device = devices
            .first()
            .ok_or_else(|| CoreError::Engine("no device record found for seed".into()))?;
        let node_id = first_device.device_id.clone();
        let registered_at = Some(first_device.registered_at);

        let storage = self.storage.clone();
        let sid = sync_id.to_string();
        let metadata = tokio::task::spawn_blocking(move || storage.get_sync_metadata(&sid))
            .await
            .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))??;
        let current_epoch = metadata.as_ref().map(|m| m.current_epoch).unwrap_or(0);

        let metadata_needs_local_device = metadata.as_ref().is_none()
            || metadata.as_ref().is_some_and(|m| m.local_device_id.is_empty());
        if metadata_needs_local_device {
            let storage = self.storage.clone();
            let sid = sync_id.to_string();
            let node_id_for_metadata = node_id.clone();
            tokio::task::spawn_blocking(move || -> Result<()> {
                let now = chrono::Utc::now();
                let metadata = match metadata {
                    Some(mut metadata) => {
                        metadata.local_device_id = node_id_for_metadata;
                        metadata.updated_at = now;
                        metadata
                    }
                    None => SyncMetadata {
                        sync_id: sid,
                        local_device_id: node_id_for_metadata,
                        current_epoch,
                        last_pulled_server_seq: 0,
                        last_pushed_at: None,
                        last_successful_sync_at: None,
                        registered_at,
                        needs_rekey: false,
                        last_imported_registry_version: None,
                        relay_log_token: None,
                        created_at: now,
                        updated_at: now,
                    },
                };
                let mut tx = storage.begin_tx()?;
                tx.upsert_sync_metadata(&metadata)?;
                tx.commit()
            })
            .await
            .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))??;
        }

        // Seed inside spawn_blocking so each table-scoped tx stays inside
        // the blocking pool and we don't reach for a tokio reactor.
        let storage_clone = self.storage.clone();
        let sync_id_owned = sync_id.to_string();
        let records_owned = records;
        let node_id_clone = node_id.clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            // Group by table so each tx touches a single table.
            let mut by_table: HashMap<String, Vec<SeedRecord>> = HashMap::new();
            for rec in records_owned {
                by_table.entry(rec.table.clone()).or_default().push(rec);
            }

            let mut emitter = OpEmitter::new(node_id_clone, sync_id_owned, current_epoch, None);

            for (_table, group) in by_table {
                for rec in group {
                    // Reuse the emitter — it ticks HLCs monotonically so
                    // every entity gets a strictly greater HLC than the
                    // previous one even though they land in their own
                    // transactions.
                    emitter.seed_fields(
                        &*storage_clone,
                        &rec.table,
                        &rec.entity_id,
                        &rec.fields,
                    )?;
                }
            }
            Ok(())
        })
        .await
        .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))??;

        // ── Size probe (local dry-run) ────────────────────────────────────
        let storage = self.storage.clone();
        let sid = sync_id.to_string();
        let blob = tokio::task::spawn_blocking(move || storage.export_snapshot(&sid))
            .await
            .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))??;
        if blob.len() > snapshot_limits::MAX_SNAPSHOT_COMPRESSED_BYTES {
            return Err(CoreError::SnapshotTooLarge { bytes: blob.len() });
        }

        Ok(BootstrapReport { entity_count, snapshot_bytes: blob.len() as u64 })
    }

    /// Acknowledge that a downloaded snapshot has been applied locally,
    /// instructing the relay to delete the stored blob. Idempotent —
    /// `RelayError::NotFound` is mapped to `Ok(())`.
    ///
    /// Older relays that predate the `DELETE /v1/sync/{id}/snapshot`
    /// endpoint respond with HTTP 405 Method Not Allowed. We fold that to
    /// `Ok(())` too and rely on the relay-side TTL to clean up the stored
    /// blob; otherwise the joiner would surface a spurious pairing error on
    /// an otherwise successful bootstrap.
    pub async fn acknowledge_snapshot_applied(&self) -> Result<()> {
        match self.relay.delete_snapshot().await {
            Ok(()) => Ok(()),
            Err(RelayError::NotFound) => Ok(()),
            Err(RelayError::Http { status: 405, .. }) => {
                tracing::debug!(
                    "Snapshot ACK not supported by legacy relay (405); snapshot will TTL-expire on the relay side."
                );
                Ok(())
            }
            Err(e) => Err(CoreError::from_relay(e)),
        }
    }

    /// Download and apply a snapshot for initial device bootstrap.
    ///
    /// Returns the number of entities restored and the entity changes for the
    /// caller to emit as `RemoteChanges` so Dart can populate its local
    /// database via the drift sync adapter.
    ///
    /// Returns `(0, [])` if no snapshot is available on the relay.
    pub async fn bootstrap_from_snapshot(
        &self,
        sync_id: &str,
        key_hierarchy: &prism_sync_crypto::KeyHierarchy,
    ) -> Result<(u64, Vec<EntityChange>)> {
        // 1. Download snapshot from relay
        let snapshot = self.relay.get_snapshot().await.map_err(CoreError::from_relay)?;

        let snapshot = match snapshot {
            Some(s) => s,
            None => return Ok((0, Vec::new())),
        };

        // 2. Deserialize the signed envelope and verify signature
        let envelope: crate::relay::traits::SignedBatchEnvelope =
            serde_json::from_slice(&snapshot.data).map_err(|e| {
                CoreError::Serialization(format!("snapshot envelope deserialization failed: {e}"))
            })?;

        // Look up the sender's key material and verify the batch signature
        let sender_key_info =
            self.resolve_sender_public_key(sync_id, &envelope.sender_device_id).await?;

        // If the sender's envelope declares a newer ML-DSA generation than
        // we have locally, try to refresh from the relay before verifying.
        let sender_key_info =
            if envelope.sender_ml_dsa_key_generation > sender_key_info.ml_dsa_key_generation {
                match self
                    .resolve_sender_keys_with_generation_hint(
                        sync_id,
                        &envelope.sender_device_id,
                        Some(envelope.sender_ml_dsa_key_generation),
                    )
                    .await
                {
                    Ok(updated) => updated,
                    Err(_) => sender_key_info, // Fall back to what we have
                }
            } else {
                sender_key_info
            };

        crate::batch_signature::verify_batch_signature_for_generation(
            &envelope,
            &sender_key_info.ed25519_pk,
            &sender_key_info.ml_dsa_65_pk,
            sender_key_info.ml_dsa_key_generation,
        )?;

        // Verify relay-reported metadata matches the signed envelope
        if snapshot.epoch != envelope.epoch {
            return Err(CoreError::Engine(format!(
                "snapshot epoch mismatch: relay reported {} but sender signed {}",
                snapshot.epoch, envelope.epoch,
            )));
        }

        // 3. Decrypt with epoch key + snapshot AAD
        let epoch_key = key_hierarchy
            .epoch_key(snapshot.epoch as u32)
            .map_err(|e| CoreError::Engine(format!("no epoch key for snapshot: {e}")))?;
        let aad = crate::sync_aad::build_snapshot_aad(
            sync_id,
            &envelope.sender_device_id,
            snapshot.epoch,
            snapshot.server_seq_at,
            &envelope.batch_id,
            &envelope.batch_kind,
        );
        let compressed = prism_sync_crypto::aead::xchacha_decrypt_from_sync(
            epoch_key,
            &envelope.ciphertext,
            &envelope.nonce,
            &aad,
        )
        .map_err(|e| CoreError::Engine(format!("snapshot decrypt failed: {e}")))?;
        crate::batch_signature::verify_payload_hash(&envelope, &compressed)?;

        let snapshot_data = Self::parse_snapshot_data(&compressed)?;
        let trusted_device_ids = self.trusted_snapshot_device_ids(sync_id, &snapshot_data).await?;
        Self::validate_snapshot_attribution(&snapshot_data, &trusted_device_ids)?;

        // 3. Import into storage AND derive the consumer-delivery journal in the
        //    SAME transaction. Build the accepted-field-versions set by
        //    re-reading post-import storage *inside the tx*, so a stale snapshot
        //    field that import skipped is excluded automatically and the import,
        //    cursor advance, and journal rows commit atomically — a kill between
        //    import-commit and Dart apply still leaves the journal listing the
        //    full accepted set for the startup drain. (This is the
        //    last stage of the import pipeline; later import gates rebase
        //    ahead of it, and re-reading post-import storage excludes whatever
        //    they rejected without extra wiring.)
        let storage = self.storage.clone();
        let sid = sync_id.to_string();
        let seq = snapshot.server_seq_at;
        let data = compressed.clone();
        let snapshot_field_versions = snapshot_data.field_versions.clone();
        let accepted_field_versions = tokio::task::spawn_blocking(move || {
            let mut tx = storage.begin_tx()?;
            tx.import_snapshot(&sid, &data)?;
            tx.update_last_pulled_seq(&sid, seq)?;

            // Re-read each snapshot field within the tx; keep only the ones
            // import actually retained (identical winner), then journal them.
            let mut accepted = Vec::new();
            for fv in snapshot_field_versions {
                let current =
                    tx.get_field_version(&sid, &fv.entity_table, &fv.entity_id, &fv.field_name)?;
                let Some(current) = current else {
                    continue;
                };
                if current.winning_op_id == fv.winning_op_id
                    && current.winning_device_id == fv.winning_device_id
                    && current.winning_hlc == fv.winning_hlc
                    && current.winning_encoded_value == fv.winning_encoded_value
                {
                    accepted.push(fv);
                }
            }

            // A tombstoned entity's non-`is_deleted` fields must reach neither the
            // delivery journal nor the EntityChange stream (C8: the journal must
            // not deliver gated rows). The delete is absorbing (merge.rs, mirrors
            // `build_entity_changes_from_snapshot_field_versions`), so delivering
            // the surviving sparse fields would (a) deliver the entity live to a
            // freshly paired device if the field rows are ordered after the
            // `is_deleted` row within a chunk, (b) resurrect it at-least-once if a
            // `take_undelivered_changes` chunk boundary lands between the delete
            // row and a later field row of the same entity, and (c) — the
            // local-tombstone hole — recreate a hard-removed local ghost when the entity is
            // tombstoned ONLY locally: a delete-unaware uploader's snapshot
            // carries the pre-delete residual fields byte-identical to local
            // storage (a delete writes only `is_deleted`), so the import gate
            // correctly SkipStale's them (no write) but they still match
            // post-import storage and would be journaled/emitted as a live upsert.
            //
            // The tombstone set therefore unions two sources, both keyed off
            // POST-IMPORT storage so later import gates are respected:
            //   1. the snapshot's own accepted `is_deleted = "true"` rows, and
            //   2. the LOCAL `is_deleted` state of every accepted entity (the
            //      local-tombstone case where the snapshot carries no `is_deleted` row at all),
            // read once with the shared NULL→tombstoned rule.
            let mut tombstoned: HashSet<(String, String)> = accepted
                .iter()
                .filter(|fv| {
                    fv.field_name == "is_deleted"
                        && fv.winning_encoded_value.as_deref() == Some("true")
                })
                .map(|fv| (fv.entity_table.clone(), fv.entity_id.clone()))
                .collect();
            let accepted_entities: HashSet<(String, String)> = accepted
                .iter()
                .map(|fv| (fv.entity_table.clone(), fv.entity_id.clone()))
                .collect();
            for (entity_table, entity_id) in &accepted_entities {
                if tombstoned.contains(&(entity_table.clone(), entity_id.clone())) {
                    continue;
                }
                let local_deleted =
                    tx.get_field_version(&sid, entity_table, entity_id, "is_deleted")?;
                let local_tombstoned = local_deleted
                    .map(|fv| is_tombstone_value(fv.winning_encoded_value.as_deref()))
                    .unwrap_or(false);
                if local_tombstoned {
                    tombstoned.insert((entity_table.clone(), entity_id.clone()));
                }
            }

            // Drop the absorbed fields once, up front, so the journal and the
            // returned accepted set (which feeds the EntityChange builder) stay in
            // lockstep — neither may carry a live upsert for a tombstoned entity.
            accepted.retain(|fv| {
                let is_delete = fv.field_name == "is_deleted"
                    && fv.winning_encoded_value.as_deref() == Some("true");
                is_delete || !tombstoned.contains(&(fv.entity_table.clone(), fv.entity_id.clone()))
            });

            for fv in &accepted {
                let is_delete = fv.field_name == "is_deleted"
                    && fv.winning_encoded_value.as_deref() == Some("true");
                tx.insert_consumer_delivery(&crate::storage::ConsumerDelivery {
                    id: 0,
                    sync_id: sid.clone(),
                    entity_table: fv.entity_table.clone(),
                    entity_id: fv.entity_id.clone(),
                    field_name: if is_delete { None } else { Some(fv.field_name.clone()) },
                    encoded_value: if is_delete {
                        None
                    } else {
                        fv.winning_encoded_value.clone()
                    },
                    is_delete,
                    server_seq: seq,
                    created_at: chrono::Utc::now(),
                })?;
            }

            tx.commit()?;
            Ok::<_, CoreError>(accepted)
        })
        .await
        .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))??;

        // 4. Build the advisory RemoteChanges payload from the same accepted set
        //    the journal carries (keep emitting it for the e2e harness, embedded
        //    consumers, and the pairing-progress denominator — the journal is now
        //    the durable source of truth, the event is just a wake-up).
        let count = accepted_field_versions
            .iter()
            .map(|fv| (fv.entity_table.clone(), fv.entity_id.clone()))
            .collect::<HashSet<_>>()
            .len() as u64;
        let entity_changes =
            Self::build_entity_changes_from_snapshot_field_versions(&accepted_field_versions);

        Ok((count, entity_changes))
    }

    /// Filter a decoded batch's ops, returning either the accepted ops or an
    /// attribution-mismatch verdict.
    ///
    /// An op attributed to a device other than the envelope sender taints the
    /// whole batch (the sender either forged it or mis-signed it) — by design
    /// this is fail-closed whole-batch rejection, surfaced as
    /// [`BatchFilterOutcome::AttributionMismatch`] so `pull_one_page` quarantines
    /// the entire envelope rather than applying any op from it. A malformed-HLC
    /// op is dropped (an unparseable HLC can never merge). A future-HLC op
    /// (>`max_clock_drift_ms` ahead of the receiver's wall clock) is NOT dropped:
    /// it is returned in `deferred` so `apply_remote_batch` can quarantine it
    /// per-op (reason `future_hlc`) and replay it with its original HLC once
    /// the local clock catches up — acceptance must not depend on which peer
    /// pulled when.
    fn filter_batch_ops(
        ops: Vec<CrdtChange>,
        sender_device_id: &str,
        max_clock_drift_ms: i64,
    ) -> BatchFilterOutcome {
        let max_clock_drift_ms = max_clock_drift_ms.max(0);
        let mut accepted = Vec::with_capacity(ops.len());
        let mut deferred = Vec::new();

        for op in ops {
            let hlc = match Hlc::from_string(&op.client_hlc) {
                Ok(hlc) => hlc,
                Err(e) => {
                    tracing::warn!(
                        op_id = %op.op_id,
                        device_id = %op.device_id,
                        client_hlc = %op.client_hlc,
                        "Dropping op with malformed HLC: {e}"
                    );
                    continue;
                }
            };

            if op.device_id != sender_device_id {
                return BatchFilterOutcome::AttributionMismatch(format!(
                    "CRDT op attribution mismatch for {}: op.device_id={} envelope.sender_device_id={}",
                    op.op_id, op.device_id, sender_device_id
                ));
            }

            if hlc.node_id != sender_device_id {
                return BatchFilterOutcome::AttributionMismatch(format!(
                    "CRDT op HLC attribution mismatch for {}: client_hlc.node_id={} envelope.sender_device_id={}",
                    op.op_id, hlc.node_id, sender_device_id
                ));
            }

            let drift_ms = hlc.future_drift_ms();
            if drift_ms > max_clock_drift_ms {
                tracing::warn!(
                    op_id = %op.op_id,
                    device_id = %op.device_id,
                    drift_ms,
                    max_ms = max_clock_drift_ms,
                    "Deferring op with excessive future HLC drift (quarantine, replay once clock catches up)"
                );
                deferred.push(op);
                continue;
            }

            accepted.push(op);
        }

        BatchFilterOutcome::Accepted { accepted, deferred }
    }

    async fn trusted_snapshot_device_ids(
        &self,
        sync_id: &str,
        snapshot: &crate::storage::SnapshotData,
    ) -> Result<HashSet<String>> {
        let storage = self.storage.clone();
        let sid = sync_id.to_string();
        let mut trusted = tokio::task::spawn_blocking(move || {
            let records = storage.list_device_records(&sid)?;
            Ok::<_, CoreError>(records.into_iter().map(|r| r.device_id).collect::<HashSet<_>>())
        })
        .await
        .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))??;

        trusted.extend(snapshot.device_registry.iter().map(|dr| dr.device_id.clone()));
        Ok(trusted)
    }

    fn validate_snapshot_attribution(
        snapshot: &crate::storage::SnapshotData,
        trusted_device_ids: &HashSet<String>,
    ) -> Result<()> {
        for fv in &snapshot.field_versions {
            if !trusted_device_ids.contains(&fv.winning_device_id) {
                return Err(CoreError::Engine(format!(
                    "snapshot field_versions references untrusted device for {}.{}.{}: winning_device_id={}",
                    fv.entity_table, fv.entity_id, fv.field_name, fv.winning_device_id
                )));
            }

            let hlc = Hlc::from_string(&fv.winning_hlc)?;
            if hlc.node_id != fv.winning_device_id {
                return Err(CoreError::Engine(format!(
                    "snapshot field_versions HLC attribution mismatch for {}.{}.{}: winning_hlc.node_id={} winning_device_id={}",
                    fv.entity_table,
                    fv.entity_id,
                    fv.field_name,
                    hlc.node_id,
                    fv.winning_device_id
                )));
            }
        }

        for ao in &snapshot.applied_ops {
            if !trusted_device_ids.contains(&ao.device_id) {
                return Err(CoreError::Engine(format!(
                    "snapshot applied_ops references untrusted device for {}: device_id={}",
                    ao.op_id, ao.device_id
                )));
            }

            let hlc = Hlc::from_string(&ao.client_hlc)?;
            if hlc.node_id != ao.device_id {
                return Err(CoreError::Engine(format!(
                    "snapshot applied_ops HLC attribution mismatch for {}: client_hlc.node_id={} device_id={}",
                    ao.op_id, hlc.node_id, ao.device_id
                )));
            }
        }

        Ok(())
    }

    fn parse_snapshot_data(compressed: &[u8]) -> Result<crate::storage::SnapshotData> {
        let json = zstd::decode_all(std::io::Cursor::new(compressed)).map_err(|e| {
            CoreError::Storage(StorageError::Logic(format!("zstd decompress failed: {e}")))
        })?;

        serde_json::from_slice(&json).map_err(CoreError::from)
    }

    fn build_entity_changes_from_snapshot_field_versions(
        field_versions: &[FieldVersionEntry],
    ) -> Vec<EntityChange> {
        // Group field_versions by (table, entity_id) into EntityChange structs
        let mut change_map: HashMap<(String, String), EntityChange> = HashMap::new();
        for fv in field_versions {
            let key = (fv.entity_table.clone(), fv.entity_id.clone());
            let entry = change_map.entry(key).or_insert_with(|| EntityChange {
                table: fv.entity_table.clone(),
                entity_id: fv.entity_id.clone(),
                is_delete: false,
                fields: HashMap::new(),
            });

            // Check for soft-delete tombstone
            if fv.field_name == "is_deleted" {
                if let Some(ref val) = fv.winning_encoded_value {
                    if val == "true" {
                        entry.is_delete = true;
                        entry.fields.clear();
                        continue;
                    }
                }
            }

            // Skip adding fields if this entity is already marked as deleted
            if entry.is_delete {
                continue;
            }

            if let Some(ref val) = fv.winning_encoded_value {
                entry.fields.insert(fv.field_name.clone(), val.clone());
            }
        }

        change_map.into_values().collect()
    }
}

/// Extract sender key material from a DeviceRecord.
fn pk_from_record(record: &DeviceRecord) -> Result<SenderKeyInfo> {
    let ed25519_pk: [u8; 32] = record.ed25519_public_key.clone().try_into().map_err(|_| {
        CoreError::Storage(StorageError::Logic("invalid ed25519 key length".into()))
    })?;
    Ok(SenderKeyInfo {
        ed25519_pk,
        ml_dsa_65_pk: record.ml_dsa_65_public_key.clone(),
        ml_dsa_key_generation: record.ml_dsa_key_generation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::RelayErrorCategory;

    fn drift_op(op_id: &str, drift_ms: i64, sender: &str) -> CrdtChange {
        let now_ms = Hlc::now_ms();
        CrdtChange::new(
            Some(op_id.to_string()),
            Some("batch".to_string()),
            "task-1".to_string(),
            "tasks".to_string(),
            "title".to_string(),
            Some("\"v\"".to_string()),
            Some(Hlc::new(now_ms + drift_ms, 0, sender).to_string()),
            false,
            Some(sender.to_string()),
            None,
            None,
        )
    }

    /// A future-HLC op is partitioned into `deferred` (for per-op
    /// quarantine), not dropped; the in-tolerance and exactly-at-boundary ops
    /// stay accepted (the drift check is strictly `>`).
    #[test]
    fn filter_batch_ops_defers_future_drift_keeps_boundary() {
        let sender = "device-sender";
        let bound = 60_000;
        let in_tolerance = drift_op("op-ok", -1_000, sender);
        let boundary = drift_op("op-boundary", bound, sender);
        let far_future = drift_op("op-future", 120_000, sender);

        let outcome = SyncEngine::filter_batch_ops(
            vec![in_tolerance, boundary, far_future],
            sender,
            bound,
        );
        match outcome {
            BatchFilterOutcome::Accepted { accepted, deferred } => {
                let acc: Vec<&str> = accepted.iter().map(|o| o.op_id.as_str()).collect();
                let def: Vec<&str> = deferred.iter().map(|o| o.op_id.as_str()).collect();
                assert_eq!(acc, vec!["op-ok", "op-boundary"]);
                assert_eq!(def, vec!["op-future"]);
            }
            BatchFilterOutcome::AttributionMismatch(d) => panic!("unexpected mismatch: {d}"),
        }
    }

    /// Relay errors with a `device_revoked` code must populate the
    /// structured metadata on `SyncResult`.
    #[test]
    fn populate_result_error_copies_relay_code_and_remote_wipe() {
        let mut result = SyncResult::default();
        let err = CoreError::Relay {
            message: "device revoked".into(),
            kind: RelayErrorCategory::Auth,
            status: Some(401),
            code: Some("device_revoked".into()),
            min_signature_version: None,
            remote_wipe: Some(true),
            source: None,
        };

        populate_result_error(&mut result, &err);

        assert_eq!(result.error.as_deref(), Some("relay error (Auth): device revoked"));
        assert_eq!(result.error_code.as_deref(), Some("device_revoked"));
        assert_eq!(result.remote_wipe, Some(true));
    }

    /// `DeviceKeyChanged` is a LOCAL engine error, not a relay response.
    /// Regression guard for Fix 4 of the 2026-04-11 robustness plan:
    /// `error_code` / `remote_wipe` must stay `None`. The key-changed
    /// case is surfaced via `SyncErrorKind::KeyChanged` instead.
    #[test]
    fn populate_result_error_does_not_set_error_code_for_device_key_changed() {
        let mut result = SyncResult::default();
        let err = CoreError::DeviceKeyChanged { device_id: "dev-a".into() };

        populate_result_error(&mut result, &err);

        assert!(
            result.error_code.is_none(),
            "DeviceKeyChanged must not leak a synthetic error_code: {:?}",
            result.error_code
        );
        assert!(
            result.remote_wipe.is_none(),
            "DeviceKeyChanged has no remote_wipe: {:?}",
            result.remote_wipe
        );
        assert_eq!(result.error_kind, Some(crate::events::SyncErrorKind::KeyChanged));
    }

    /// Local engine / storage errors must also leave the relay-scoped
    /// fields at `None`.
    #[test]
    fn populate_result_error_does_not_set_error_code_for_local_errors() {
        for err in [
            CoreError::MissingEpochKey { epoch: 2 },
            CoreError::DecryptFailed {
                epoch: 2,
                source: prism_sync_crypto::CryptoError::DecryptionFailed("bad ciphertext".into()),
            },
            CoreError::Engine("missing epoch key for push epoch 2".into()),
            CoreError::Storage(StorageError::Logic("tx aborted".into())),
        ] {
            let mut result = SyncResult::default();
            populate_result_error(&mut result, &err);
            assert!(result.error_code.is_none(), "{err:?}");
            assert!(result.remote_wipe.is_none(), "{err:?}");
        }
    }

    // ── SnapshotStale suppression matrix ─────────────────────────────

    #[test]
    fn should_suppress_stale_snapshot_untargeted_vs_untargeted_suppresses() {
        assert!(should_suppress_stale_snapshot(None, None, 42, 42));
        assert!(should_suppress_stale_snapshot(None, None, 42, 100));
    }

    /// Universal intent racing a targeted existing must propagate;
    /// the relay's GET 403s every device that doesn't match the
    /// stored target, so suppression would silently lose availability
    /// for every joiner except that one.
    #[test]
    fn should_suppress_stale_snapshot_untargeted_upload_vs_targeted_existing_propagates() {
        assert!(!should_suppress_stale_snapshot(None, Some("joiner-A"), 42, 100));
        assert!(!should_suppress_stale_snapshot(None, Some("joiner-B"), 42, 50));
    }

    #[test]
    fn should_suppress_stale_snapshot_targeted_upload_vs_untargeted_existing_propagates() {
        assert!(!should_suppress_stale_snapshot(Some("joiner-A"), None, 42, 100));
    }

    #[test]
    fn should_suppress_stale_snapshot_same_target_suppresses() {
        assert!(should_suppress_stale_snapshot(Some("joiner-A"), Some("joiner-A"), 42, 100));
    }

    /// Cross-target race: the loser's targeted snapshot is silently
    /// lost (PK on `sync_id` alone), so the losing joiner would later
    /// 403 on download.
    #[test]
    fn should_suppress_stale_snapshot_cross_target_propagates() {
        assert!(!should_suppress_stale_snapshot(Some("joiner-A"), Some("joiner-B"), 42, 100));
        assert!(!should_suppress_stale_snapshot(Some("joiner-B"), Some("joiner-A"), 42, 100));
    }

    /// Relay claims our upload is stale but cites a strictly lower
    /// seq — logically impossible. Propagate rather than silently
    /// no-op, as defense against malformed or hostile responses.
    #[test]
    fn should_suppress_stale_snapshot_rejects_seq_inversion() {
        assert!(!should_suppress_stale_snapshot(Some("joiner-A"), Some("joiner-A"), 42, 0));
        assert!(!should_suppress_stale_snapshot(None, None, 42, 0));
        assert!(!should_suppress_stale_snapshot(None, Some("joiner-A"), 42, 41));
    }

    /// Equal seqs are valid for suppression — under the `>` policy the
    /// relay legitimately rejects equal-seq uploads as stale (existing
    /// wins ties). The seq-sanity check uses `>=`, not `>`.
    #[test]
    fn should_suppress_stale_snapshot_allows_equal_seq() {
        assert!(should_suppress_stale_snapshot(None, None, 42, 42));
        assert!(should_suppress_stale_snapshot(Some("joiner-A"), Some("joiner-A"), 42, 42));
    }

    // -- Ephemeral mailbox drain -------------------------------------------

    fn drain_test_engine(relay: Arc<crate::relay::MockRelay>) -> (SyncEngine, broadcast::Receiver<SyncEvent>) {
        let storage = Arc::new(crate::storage::RusqliteSyncStorage::in_memory().unwrap());
        let schema = crate::schema::SyncSchema::builder().build();
        let engine =
            SyncEngine::new(storage, relay, vec![], schema, SyncConfig::default());
        let (tx, rx) = broadcast::channel(16);
        (engine.with_event_sink(tx), rx)
    }

    fn unlocked_kh_with(epoch: u32, key: &[u8]) -> prism_sync_crypto::KeyHierarchy {
        let mut kh = prism_sync_crypto::KeyHierarchy::new();
        kh.initialize("pw", &[1u8; 16]).unwrap();
        kh.store_epoch_key(epoch, zeroize::Zeroizing::new(key.to_vec()));
        kh
    }

    #[tokio::test]
    async fn drain_emits_decryptable_and_acks_every_drained_id() {
        let epoch_key = vec![3u8; 32];
        let kh = unlocked_kh_with(2, &epoch_key);
        let relay = Arc::new(crate::relay::MockRelay::new());

        // One decryptable (epoch 2) + one unreadable (epoch 9, no key) message.
        let mut good = crate::ephemeral::seal_envelope(
            &epoch_key, "sync-1", 2, "media_request", "blob-1", None, 0,
        )
        .unwrap();
        good.sender_device_id = "dev-2".into();
        relay.seed_ephemeral(good.clone());
        let bad = crate::ephemeral::seal_envelope(
            &epoch_key, "sync-1", 9, "media_request", "blob-2", None, 0,
        )
        .unwrap();
        relay.seed_ephemeral(bad.clone());

        let (engine, mut rx) = drain_test_engine(relay.clone());
        engine.drain_ephemeral_messages("sync-1", &kh).await;

        match rx.try_recv().unwrap() {
            SyncEvent::EphemeralMessage { sender_device_id, kind, media_id, epoch_id } => {
                assert_eq!(sender_device_id, "dev-2");
                assert_eq!(kind, "media_request");
                assert_eq!(media_id, "blob-1");
                assert_eq!(epoch_id, 2);
            }
            other => panic!("unexpected event: {other:?}"),
        }
        assert!(rx.try_recv().is_err(), "the unreadable message is skipped, not surfaced");

        let mut expected = vec![good.message_id.clone(), bad.message_id.clone()];
        expected.sort();
        assert_eq!(relay.ephemeral_acked(), expected, "both drained ids are acked");
    }

    #[tokio::test]
    async fn drain_old_relay_is_a_noop() {
        let relay = Arc::new(crate::relay::MockRelay::new());
        relay.set_ephemeral_feature_absent(true); // models a relay without the endpoint
        let kh = unlocked_kh_with(0, &[3u8; 32]);
        let (engine, mut rx) = drain_test_engine(relay.clone());

        engine.drain_ephemeral_messages("sync-1", &kh).await;

        assert!(rx.try_recv().is_err(), "no events from an old relay");
        assert!(relay.ephemeral_acked().is_empty(), "nothing acked when the feature is absent");
    }

    // ── Phase 0b quarantined-pull-batch replay backoff eligibility ──

    /// A freshly-quarantined row (never retried) is always eligible regardless of
    /// base — the first replay must run promptly.
    #[test]
    fn quarantine_replay_eligible_first_attempt_always_runs() {
        let now = Utc::now();
        assert!(quarantine_replay_eligible(now, 0, None, 30_000));
        assert!(quarantine_replay_eligible(now, 5, None, 30_000));
    }

    /// `base_ms <= 0` disables backoff entirely (eligible every cycle); used by
    /// the immediate-replay integration tests.
    #[test]
    fn quarantine_replay_eligible_zero_base_disables_backoff() {
        let now = Utc::now();
        assert!(quarantine_replay_eligible(now, 9, Some(now), 0));
        assert!(quarantine_replay_eligible(now, 9, Some(now), -1));
    }

    /// A row retried `retry_count` ago is ineligible until `base * 2^retry_count`
    /// has elapsed, and becomes eligible once it has.
    #[test]
    fn quarantine_replay_eligible_respects_exponential_window() {
        let now = Utc::now();
        let base_ms = 30_000;

        // retry_count = 1 -> window = 60s. 30s ago: still inside. 61s ago: out.
        assert!(!quarantine_replay_eligible(
            now,
            1,
            Some(now - chrono::Duration::seconds(30)),
            base_ms
        ));
        assert!(quarantine_replay_eligible(
            now,
            1,
            Some(now - chrono::Duration::seconds(61)),
            base_ms
        ));

        // retry_count = 3 -> window = 240s. 100s ago is still inside.
        assert!(!quarantine_replay_eligible(
            now,
            3,
            Some(now - chrono::Duration::seconds(100)),
            base_ms
        ));
        assert!(quarantine_replay_eligible(
            now,
            3,
            Some(now - chrono::Duration::seconds(241)),
            base_ms
        ));
    }

    /// The exponent is capped so a huge `retry_count` neither overflows nor
    /// pushes the window past the cap (`base * 2^MAX_EXP`).
    #[test]
    fn quarantine_replay_eligible_caps_the_exponent() {
        let now = Utc::now();
        let base_ms = 30_000;
        let cap_window_ms = base_ms * (1i64 << QUARANTINE_REPLAY_BACKOFF_MAX_EXP);

        // A row with an absurd retry_count uses the capped window, not 2^9999.
        let just_inside = now - chrono::Duration::milliseconds(cap_window_ms - 1_000);
        let just_outside = now - chrono::Duration::milliseconds(cap_window_ms + 1_000);
        assert!(!quarantine_replay_eligible(now, 9_999, Some(just_inside), base_ms));
        assert!(quarantine_replay_eligible(now, 9_999, Some(just_outside), base_ms));
    }

    // ── Phase B commit_batch loop is failure-safe ───────────────────
    //
    // This is a GUARD, not a reachable production bug: the FFI app registers
    // zero `SyncableEntity` impls and every in-repo `commit_batch` is
    // infallible. But the trait is a public extension point with an
    // all-or-nothing contract, so the multi-table commit loop must roll back
    // every touched-but-uncommitted entity if a later `commit_batch` fails,
    // rather than escaping on a bare `?` and leaking dangling `begin_batch`
    // transactions. These tests pin that invariant for embedded Rust consumers.

    use crate::relay::MockRelay;
    use crate::storage::RusqliteSyncStorage;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering as AtomicOrdering};

    /// A `SyncableEntity` whose `commit_batch` can be made to fail and which
    /// records every batch-lifecycle call so the test can assert the
    /// begin/commit/rollback pairing.
    struct FallibleEntity {
        table: &'static str,
        fail_commit: AtomicBool,
        begins: AtomicUsize,
        commits: AtomicUsize,
        rollbacks: AtomicUsize,
        /// Set on a successful commit; cleared on rollback, so the test can
        /// distinguish "committed" from "rolled back / never committed".
        committed: AtomicBool,
        writes: AtomicUsize,
    }

    impl FallibleEntity {
        fn new(table: &'static str) -> Self {
            Self {
                table,
                fail_commit: AtomicBool::new(false),
                begins: AtomicUsize::new(0),
                commits: AtomicUsize::new(0),
                rollbacks: AtomicUsize::new(0),
                committed: AtomicBool::new(false),
                writes: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait::async_trait]
    impl SyncableEntity for FallibleEntity {
        fn table_name(&self) -> &str {
            self.table
        }

        fn field_definitions(&self) -> &[crate::schema::SyncFieldDef] {
            &[]
        }

        async fn read_row(
            &self,
            _entity_id: &str,
        ) -> Result<Option<HashMap<String, SyncValue>>> {
            Ok(None)
        }

        async fn write_fields(
            &self,
            _entity_id: &str,
            _fields: &HashMap<String, SyncValue>,
            _hlc: &str,
            _is_new: bool,
        ) -> Result<()> {
            self.writes.fetch_add(1, AtomicOrdering::SeqCst);
            Ok(())
        }

        async fn soft_delete(&self, _entity_id: &str, _hlc: &str) -> Result<()> {
            Ok(())
        }

        async fn is_deleted(&self, _entity_id: &str) -> Result<bool> {
            Ok(false)
        }

        async fn hard_delete(&self, _entity_id: &str) -> Result<()> {
            Ok(())
        }

        async fn begin_batch(&self) -> Result<()> {
            self.begins.fetch_add(1, AtomicOrdering::SeqCst);
            // Defensive reset per the trait contract: a re-begun batch starts
            // from a clean slate even if a prior batch was left dangling.
            self.committed.store(false, AtomicOrdering::SeqCst);
            Ok(())
        }

        async fn commit_batch(&self) -> Result<()> {
            self.commits.fetch_add(1, AtomicOrdering::SeqCst);
            if self.fail_commit.load(AtomicOrdering::SeqCst) {
                return Err(CoreError::Engine(format!(
                    "injected commit failure for table {}",
                    self.table
                )));
            }
            self.committed.store(true, AtomicOrdering::SeqCst);
            Ok(())
        }

        async fn rollback_batch(&self) -> Result<()> {
            self.rollbacks.fetch_add(1, AtomicOrdering::SeqCst);
            self.committed.store(false, AtomicOrdering::SeqCst);
            Ok(())
        }
    }

    fn three_table_schema() -> SyncSchema {
        SyncSchema::builder()
            .entity("a", |e| e.field("v", SyncType::String))
            .entity("b", |e| e.field("v", SyncType::String))
            .entity("c", |e| e.field("v", SyncType::String))
            .build()
    }

    fn winning_op_for(table: &str, device: &str) -> CrdtChange {
        CrdtChange::new(
            Some(format!("op-{table}")),
            Some("batch".to_string()),
            format!("{table}-1"),
            table.to_string(),
            "v".to_string(),
            Some("\"x\"".to_string()),
            Some(Hlc::new(Hlc::now_ms(), 0, device).to_string()),
            false,
            Some(device.to_string()),
            None,
            None,
        )
    }

    /// A batch touches tables A, B, C; `commit_batch(B)` fails. A (committed
    /// before B) stays committed; B and C each receive `rollback_batch` so no
    /// `begin_batch` is left dangling, and the call returns the commit error so
    /// Phase C never advances sync state. The entities are then ordered A, B, C
    /// in `SyncEngine::entities`, so commit order is deterministic.
    #[tokio::test]
    async fn phase_b_commit_failure_rolls_back_uncommitted_touched_entities() {
        let a = Arc::new(FallibleEntity::new("a"));
        let b = Arc::new(FallibleEntity::new("b"));
        let c = Arc::new(FallibleEntity::new("c"));
        b.fail_commit.store(true, AtomicOrdering::SeqCst);

        let entities: Vec<Arc<dyn SyncableEntity>> =
            vec![a.clone(), b.clone(), c.clone()];
        let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
        let relay = Arc::new(MockRelay::new());
        let engine = SyncEngine::new(
            storage,
            relay,
            entities,
            three_table_schema(),
            SyncConfig::default(),
        );

        let winning = vec![
            winning_op_for("a", "dev"),
            winning_op_for("b", "dev"),
            winning_op_for("c", "dev"),
        ];

        let err = engine.write_winning_ops_to_entities(&winning).await.unwrap_err();
        assert!(
            err.to_string().contains("injected commit failure for table b"),
            "the original commit error must propagate, got: {err}"
        );

        // Every touched entity began exactly one batch.
        for e in [&a, &b, &c] {
            assert_eq!(e.begins.load(AtomicOrdering::SeqCst), 1, "{} begins", e.table);
        }

        // A committed (and was never rolled back); B's commit was attempted and
        // failed; C's commit was never attempted (the loop returned at B).
        assert_eq!(a.commits.load(AtomicOrdering::SeqCst), 1, "A commit attempted");
        assert!(a.committed.load(AtomicOrdering::SeqCst), "A stays committed");
        assert_eq!(a.rollbacks.load(AtomicOrdering::SeqCst), 0, "A not rolled back");

        assert_eq!(b.commits.load(AtomicOrdering::SeqCst), 1, "B commit attempted");
        assert!(!b.committed.load(AtomicOrdering::SeqCst), "B not committed");
        assert_eq!(b.rollbacks.load(AtomicOrdering::SeqCst), 1, "B rolled back");

        assert_eq!(c.commits.load(AtomicOrdering::SeqCst), 0, "C commit NOT attempted");
        assert!(!c.committed.load(AtomicOrdering::SeqCst), "C not committed");
        assert_eq!(c.rollbacks.load(AtomicOrdering::SeqCst), 1, "C rolled back");

        // The next cycle's begin_batch succeeds cleanly on all three.
        assert!(a.begin_batch().await.is_ok());
        assert!(b.begin_batch().await.is_ok());
        assert!(c.begin_batch().await.is_ok());
    }

    /// Same failure through the quarantine-replay path: a schema-known op held
    /// in `quarantined_ops` is replayed, its `write_winning_ops_to_entities`
    /// commit fails, and the error propagates so the Phase C quarantine-delete
    /// never runs — the op stays quarantined for a later retry.
    #[tokio::test]
    async fn quarantine_replay_commit_failure_keeps_op_quarantined() {
        let a = Arc::new(FallibleEntity::new("a"));
        a.fail_commit.store(true, AtomicOrdering::SeqCst);

        let entities: Vec<Arc<dyn SyncableEntity>> = vec![a.clone()];
        let storage = Arc::new(RusqliteSyncStorage::in_memory().unwrap());
        let relay = Arc::new(MockRelay::new());

        // Quarantine a now-schema-known op (reason `unknown_field` becomes
        // replay-eligible once the schema knows table+field, which it does
        // here). Insert it directly into storage before building the engine.
        let op = winning_op_for("a", "dev");
        {
            use crate::storage::SyncStorage;
            let mut tx = storage.begin_tx().unwrap();
            tx.insert_quarantined_op(&QuarantinedOp {
                sync_id: "sync".to_string(),
                op_id: op.op_id.clone(),
                op: op.clone(),
                reason: "unknown_field".to_string(),
                server_seq: 7,
                quarantined_at: Utc::now(),
            })
            .unwrap();
            tx.commit().unwrap();
        }

        let engine = SyncEngine::new(
            storage.clone(),
            relay,
            entities,
            three_table_schema(),
            SyncConfig::default(),
        );

        let err = engine.replay_quarantined_ops("sync").await.unwrap_err();
        assert!(
            err.to_string().contains("injected commit failure"),
            "replay must surface the commit error, got: {err}"
        );

        // Phase B failed, so the touched entity was rolled back, not committed.
        assert_eq!(a.rollbacks.load(AtomicOrdering::SeqCst), 1, "A rolled back");
        assert!(!a.committed.load(AtomicOrdering::SeqCst), "A not committed");

        // Phase C never ran: the op is still quarantined and not marked applied.
        let remaining = {
            use crate::storage::SyncStorage;
            storage.list_quarantined_ops("sync").unwrap()
        };
        assert_eq!(remaining.len(), 1, "op must remain quarantined for retry");
        assert_eq!(remaining[0].op_id, op.op_id);
        {
            use crate::storage::SyncStorage;
            assert!(!storage.is_op_applied(&op.op_id).unwrap(), "op not marked applied");
        }
    }
}
