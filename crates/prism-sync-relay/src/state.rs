use crate::config::Config;
use crate::db::Database;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::{mpsc, RwLock};

/// Bounded channel capacity for WebSocket notification senders.
const WS_CHANNEL_CAPACITY: usize = 64;

pub type WsSender = mpsc::Sender<String>;
/// Connection IDs prevent stale teardown from removing a replacement socket.
type WsConnections = HashMap<String, HashMap<String, (u64, WsSender)>>;

#[derive(Debug, Default)]
pub struct Metrics {
    pub changesets_pushed: AtomicU64,
    pub changesets_pulled: AtomicU64,
    pub changesets_pruned: AtomicU64,
    pub ws_notifications: AtomicU64,
    pub ws_notifications_dropped: AtomicU64,
    pub auth_failures: AtomicU64,
    pub snapshots_exchanged: AtomicU64,
    /// `PUT /snapshot` rejected with 409 `stale_snapshot_seq`. Unusual
    /// rates here flag a buggy client or a concurrency regression.
    pub snapshots_rejected_stale: AtomicU64,
    /// Targeted `PUT /snapshot` rejected with 409 `too_many_targeted_snapshots`
    /// because the group already holds the per-group cap of unexpired targeted
    /// rows. Elevated rates flag a pairing storm or stalled pairings.
    pub snapshots_rejected_targeted_cap: AtomicU64,
    /// Published file-backed snapshot rows whose on-disk blob was missing or
    /// unreadable at GET time (a partial restore, a lost volume, or a manual
    /// delete). Each one served the same snapshot-absent response as no row.
    /// Any sustained nonzero value means snapshot storage and the SQLite rows
    /// have diverged — backup/restore must carry the blob tree too.
    pub snapshots_missing_blob: AtomicU64,
    pub registrations: AtomicU64,
    pub vacuum_pages_freed: AtomicU64,
    /// Times the startup lineage check detected a regressed batch sequence (a
    /// file-level DB restore) and rotated `log_token`. Any nonzero value here is
    /// an operator-visible signal that clients were forced to reset their cursor.
    pub log_token_rotations: AtomicU64,
    /// Times the startup lineage check could not read the companion file
    /// (truncation, partial write, EACCES). Each one is a boot where shape-A
    /// restore detection was forfeited — operator-visible because the overwrite
    /// that follows destroys the evidence.
    pub lineage_companion_unreadable: AtomicU64,
    pub last_cleanup_epoch_secs: AtomicU64,
    pub media_uploads: AtomicU64,
    pub media_downloads: AtomicU64,
    pub media_bytes_uploaded: AtomicU64,
    /// Gauge (not persisted): committed/servable media rows whose on-disk file
    /// is missing, as found by the most recent reconciliation sweep. While the
    /// sweep is in dry-run/log-only mode this is the count it *would* delete —
    /// watch it to verify against the known crash-row population before enabling
    /// deletion.
    pub media_reconciliation_missing_files: AtomicU64,
    /// Pairing lease renewals that extended a lease. Bounded aggregate only — no
    /// per-rendezvous, per-IP, or per-URL labels, so the metric cannot become a
    /// pairing-activity side channel or an unbounded-cardinality sink.
    pub pairing_lease_renewed: AtomicU64,
    /// Pairing lease renewal requests rejected by the per-rendezvous failure
    /// bucket (too many failed verifier attempts for that ID).
    ///
    /// A sustained rate means someone is guessing against known rendezvous IDs;
    /// legitimate renewals are never counted here, so a nonzero value does not
    /// indicate a problem for honest ceremonies.
    pub pairing_lease_renew_rejected_rate_limited: AtomicU64,
    /// Pairing lease renewals that did not extend the lease for any other reason
    /// (unknown/expired row, no committed verifier, pre-confirmation, consumed,
    /// saturated, or a wrong secret). Deliberately undifferentiated so the
    /// metric mirrors the uniform not-found the caller sees.
    pub pairing_lease_renew_not_found: AtomicU64,
    /// Pairing lease renewal requests dropped by the per-client-IP front limiter.
    pub pairing_lease_renew_client_limited: AtomicU64,
    /// Cached gauge, refreshed after each cleanup cycle: number of pairing rows
    /// currently holding a live lease (absolute deadline set and in the future).
    /// Avoids a live DB query on every Prometheus scrape.
    pub cached_leased_pairing_sessions: AtomicU64,
    // Cached DB-state values refreshed after each cleanup cycle.
    // Avoids live DB queries on every Prometheus scrape.
    pub cached_stored_batches: AtomicU64,
    pub cached_db_size_bytes: AtomicU64,
    pub cached_freelist_pages: AtomicU64,
    /// Gauge (not persisted): nonterminal resumable-upload sessions, refreshed
    /// each cleanup cycle.
    pub cached_snapshot_upload_sessions_active: AtomicU64,
    /// Gauge (not persisted): bytes reserved by nonterminal resumable-upload
    /// sessions, refreshed each cleanup cycle.
    pub cached_snapshot_upload_reserved_bytes: AtomicU64,
    // ── Resumable snapshot upload lifecycle (aggregate only) ──────────────
    //
    // Deliberately unlabeled: no sync, device, upload, or group label. A
    // session-scoped series would be a per-user activity signal and an
    // unbounded-cardinality sink. Every value here answers an operator question
    // (resume rate, expiry rate, corruption, quota pressure) without
    // identifying anyone.
    /// Chunks durably committed (includes idempotent acknowledgments).
    pub snapshot_upload_chunks_accepted: AtomicU64,
    /// Chunk requests rejected for any reason (bounds, offset, state, expiry).
    pub snapshot_upload_chunks_rejected: AtomicU64,
    /// Bytes durably committed by accepted chunks.
    pub snapshot_upload_chunk_bytes: AtomicU64,
    /// Completions that published a snapshot.
    pub snapshot_upload_completions: AtomicU64,
    /// Admission or write rejections attributable to a quota/free-space bound.
    pub snapshot_upload_quota_rejections: AtomicU64,
    /// Completions rejected because the staged bytes did not match the
    /// create-time SHA-256. Any nonzero value deserves attention.
    pub snapshot_upload_hash_mismatch: AtomicU64,
    /// Sessions failed for staging corruption (missing or short candidate).
    /// Any nonzero value means the DB and the blob tree have diverged.
    pub snapshot_upload_staging_corrupt: AtomicU64,
    /// Sessions expired by idle or absolute TTL.
    pub snapshot_upload_expired: AtomicU64,
    /// Sessions ended by an explicit abort.
    pub snapshot_upload_aborted: AtomicU64,
    /// Sessions superseded by a newer create from the same uploader.
    pub snapshot_upload_superseded: AtomicU64,
}
impl Metrics {
    pub fn inc(&self, field: &AtomicU64) {
        field.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_by(&self, field: &AtomicU64, n: u64) {
        field.fetch_add(n, Ordering::Relaxed);
    }

    /// Restore counter values from a name→value map (loaded from SQLite).
    pub fn restore_from(&self, counters: &std::collections::HashMap<String, u64>) {
        let fields: &[(&str, &AtomicU64)] = &[
            ("changesets_pushed", &self.changesets_pushed),
            ("changesets_pulled", &self.changesets_pulled),
            ("changesets_pruned", &self.changesets_pruned),
            ("ws_notifications", &self.ws_notifications),
            ("ws_notifications_dropped", &self.ws_notifications_dropped),
            ("auth_failures", &self.auth_failures),
            ("snapshots_exchanged", &self.snapshots_exchanged),
            ("snapshots_rejected_stale", &self.snapshots_rejected_stale),
            ("snapshots_rejected_targeted_cap", &self.snapshots_rejected_targeted_cap),
            ("snapshots_missing_blob", &self.snapshots_missing_blob),
            ("registrations", &self.registrations),
            ("vacuum_pages_freed", &self.vacuum_pages_freed),
            ("log_token_rotations", &self.log_token_rotations),
            ("lineage_companion_unreadable", &self.lineage_companion_unreadable),
            ("media_uploads", &self.media_uploads),
            ("media_downloads", &self.media_downloads),
            ("media_bytes_uploaded", &self.media_bytes_uploaded),
            ("pairing_lease_renewed", &self.pairing_lease_renewed),
            (
                "pairing_lease_renew_rejected_rate_limited",
                &self.pairing_lease_renew_rejected_rate_limited,
            ),
            ("pairing_lease_renew_not_found", &self.pairing_lease_renew_not_found),
            ("pairing_lease_renew_client_limited", &self.pairing_lease_renew_client_limited),
            ("snapshot_upload_chunks_accepted", &self.snapshot_upload_chunks_accepted),
            ("snapshot_upload_chunks_rejected", &self.snapshot_upload_chunks_rejected),
            ("snapshot_upload_chunk_bytes", &self.snapshot_upload_chunk_bytes),
            ("snapshot_upload_completions", &self.snapshot_upload_completions),
            ("snapshot_upload_quota_rejections", &self.snapshot_upload_quota_rejections),
            ("snapshot_upload_hash_mismatch", &self.snapshot_upload_hash_mismatch),
            ("snapshot_upload_staging_corrupt", &self.snapshot_upload_staging_corrupt),
            ("snapshot_upload_expired", &self.snapshot_upload_expired),
            ("snapshot_upload_aborted", &self.snapshot_upload_aborted),
            ("snapshot_upload_superseded", &self.snapshot_upload_superseded),
        ];
        for (name, field) in fields {
            if let Some(&value) = counters.get(*name) {
                field.store(value, Ordering::Relaxed);
            }
        }
    }

    /// Snapshot current counter values for flushing to SQLite.
    pub fn snapshot_counters(&self) -> Vec<(&'static str, u64)> {
        vec![
            ("changesets_pushed", self.changesets_pushed.load(Ordering::Relaxed)),
            ("changesets_pulled", self.changesets_pulled.load(Ordering::Relaxed)),
            ("changesets_pruned", self.changesets_pruned.load(Ordering::Relaxed)),
            ("ws_notifications", self.ws_notifications.load(Ordering::Relaxed)),
            ("ws_notifications_dropped", self.ws_notifications_dropped.load(Ordering::Relaxed)),
            ("auth_failures", self.auth_failures.load(Ordering::Relaxed)),
            ("snapshots_exchanged", self.snapshots_exchanged.load(Ordering::Relaxed)),
            ("snapshots_rejected_stale", self.snapshots_rejected_stale.load(Ordering::Relaxed)),
            (
                "snapshots_rejected_targeted_cap",
                self.snapshots_rejected_targeted_cap.load(Ordering::Relaxed),
            ),
            ("snapshots_missing_blob", self.snapshots_missing_blob.load(Ordering::Relaxed)),
            ("registrations", self.registrations.load(Ordering::Relaxed)),
            ("vacuum_pages_freed", self.vacuum_pages_freed.load(Ordering::Relaxed)),
            ("log_token_rotations", self.log_token_rotations.load(Ordering::Relaxed)),
            (
                "lineage_companion_unreadable",
                self.lineage_companion_unreadable.load(Ordering::Relaxed),
            ),
            ("media_uploads", self.media_uploads.load(Ordering::Relaxed)),
            ("media_downloads", self.media_downloads.load(Ordering::Relaxed)),
            ("media_bytes_uploaded", self.media_bytes_uploaded.load(Ordering::Relaxed)),
            ("pairing_lease_renewed", self.pairing_lease_renewed.load(Ordering::Relaxed)),
            (
                "pairing_lease_renew_rejected_rate_limited",
                self.pairing_lease_renew_rejected_rate_limited.load(Ordering::Relaxed),
            ),
            (
                "pairing_lease_renew_not_found",
                self.pairing_lease_renew_not_found.load(Ordering::Relaxed),
            ),
            (
                "pairing_lease_renew_client_limited",
                self.pairing_lease_renew_client_limited.load(Ordering::Relaxed),
            ),
            (
                "snapshot_upload_chunks_accepted",
                self.snapshot_upload_chunks_accepted.load(Ordering::Relaxed),
            ),
            (
                "snapshot_upload_chunks_rejected",
                self.snapshot_upload_chunks_rejected.load(Ordering::Relaxed),
            ),
            (
                "snapshot_upload_chunk_bytes",
                self.snapshot_upload_chunk_bytes.load(Ordering::Relaxed),
            ),
            (
                "snapshot_upload_completions",
                self.snapshot_upload_completions.load(Ordering::Relaxed),
            ),
            (
                "snapshot_upload_quota_rejections",
                self.snapshot_upload_quota_rejections.load(Ordering::Relaxed),
            ),
            (
                "snapshot_upload_hash_mismatch",
                self.snapshot_upload_hash_mismatch.load(Ordering::Relaxed),
            ),
            (
                "snapshot_upload_staging_corrupt",
                self.snapshot_upload_staging_corrupt.load(Ordering::Relaxed),
            ),
            ("snapshot_upload_expired", self.snapshot_upload_expired.load(Ordering::Relaxed)),
            ("snapshot_upload_aborted", self.snapshot_upload_aborted.load(Ordering::Relaxed)),
            ("snapshot_upload_superseded", self.snapshot_upload_superseded.load(Ordering::Relaxed)),
        ]
    }
}

/// Per-key sliding window rate limiter.
/// Stores timestamps of recent requests per key, pruning on access.
#[derive(Clone, Default)]
pub struct RateLimiter {
    windows: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
}

impl RateLimiter {
    /// Maximum number of distinct keys tracked before new keys are rejected.
    /// Prevents unbounded memory growth from attackers using random keys.
    const MAX_TRACKED_KEYS: usize = 100_000;

    /// Check whether a request for `key` is allowed.
    /// Returns `true` if under the limit, `false` if rate-limited.
    /// Automatically prunes timestamps outside the window.
    pub fn check(&self, key: &str, max_requests: u32, window_secs: u64) -> bool {
        self.check_many(&[key], max_requests, window_secs)
    }

    /// Check whether a request for all `keys` is allowed, reserving a slot for
    /// each key atomically if so.
    pub fn check_many(&self, keys: &[&str], max_requests: u32, window_secs: u64) -> bool {
        let mut map = self.windows.lock().expect("rate limiter mutex poisoned");
        let now = Instant::now();
        let cutoff = now - std::time::Duration::from_secs(window_secs);

        let mut missing = 0usize;
        for key in keys {
            if !map.contains_key(*key) {
                missing += 1;
            }
        }
        if map.len() + missing > Self::MAX_TRACKED_KEYS {
            return false;
        }

        let mut candidates = Vec::with_capacity(keys.len());
        for key in keys {
            let timestamps = map.entry((*key).to_string()).or_default();
            timestamps.retain(|t| *t > cutoff);
            if timestamps.len() >= max_requests as usize {
                return false;
            }
            candidates.push(key.to_string());
        }

        for key in candidates {
            map.get_mut(&key).expect("key was just inserted above").push(now);
        }
        true
    }

    /// Remove entries that have no timestamps within the given window.
    /// Called periodically to prevent unbounded growth.
    pub fn prune_stale(&self, window_secs: u64) {
        let mut map = self.windows.lock().expect("rate limiter mutex poisoned");
        let cutoff = Instant::now() - std::time::Duration::from_secs(window_secs);
        map.retain(|_, timestamps| {
            timestamps.retain(|t| *t > cutoff);
            !timestamps.is_empty()
        });
    }

    /// Record one observed **failure** for `key` and report whether that key has
    /// now exceeded `max_requests` inside the window.
    ///
    /// Unlike [`Self::check`], this never *blocks* anything: it only counts. That
    /// asymmetry is the point. A limiter that both counts and gates cannot be
    /// used for a per-target failure bucket, because then a legitimate success
    /// for that target could be starved by an attacker who merely knows the
    /// target's identifier. Counting failures after the fact lets the caller
    /// report targeted brute force without ever giving garbage veto power over a
    /// request that would otherwise succeed.
    ///
    /// Returns `true` when the key is over budget. Also returns `true` when the
    /// key table is at capacity and `key` is new, since the failure cannot then
    /// be tracked and under-counting a sustained attack is the wrong default.
    pub fn record_failure(&self, key: &str, max_requests: u32, window_secs: u64) -> bool {
        let mut map = self.windows.lock().expect("rate limiter mutex poisoned");
        if !map.contains_key(key) && map.len() >= Self::MAX_TRACKED_KEYS {
            return true;
        }
        let now = Instant::now();
        let cutoff = now - std::time::Duration::from_secs(window_secs);
        let timestamps = map.entry(key.to_string()).or_default();
        timestamps.retain(|t| *t > cutoff);
        timestamps.push(now);
        timestamps.len() > max_requests as usize
    }
}

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Database>,
    pub config: Arc<Config>,
    /// Resolved snapshot storage policy (file-backed root vs. legacy inline).
    /// Decided once at startup by `Config::resolve_snapshot_storage` so no
    /// request path ever re-resolves or re-validates the raw config string.
    pub snapshot_storage: crate::config::SnapshotStorage,
    pub ws_connections: Arc<RwLock<WsConnections>>,
    /// Sequence for connection ownership checks.
    pub ws_conn_seq: Arc<AtomicU64>,
    pub metrics: Arc<Metrics>,
    pub nonce_rate_limiter: RateLimiter,
    pub revoke_rate_limiter: RateLimiter,
    pub first_device_nonce_rate_limiter: RateLimiter,
    pub first_device_registration_rate_limiter: RateLimiter,
    pub first_device_group_rate_limiter: RateLimiter,
    pub pairing_rate_limiter: RateLimiter,
    /// Front limiter for lease renewal, keyed on the **trusted-proxy-derived**
    /// client IP (`routes::client_ip_for_rate_limit`), never the raw tunnel peer.
    ///
    /// Sized above the legitimate maximum of one renewal per active ceremony per
    /// five minutes. Behind a proxy this is only meaningful with a correct
    /// `TRUSTED_PROXY_CIDRS` allowlist — see
    /// [`crate::config::Config::validate_pairing_lease_proxy_trust`].
    pub pairing_lease_renew_rate_limiter: RateLimiter,
    /// Per-rendezvous failure bucket for lease renewal, keyed on the **presented**
    /// rendezvous ID whether or not a row exists for it. Only failed verifier
    /// attempts consume it, so garbage that merely knows a rendezvous ID cannot
    /// starve the legitimate renewal of that same ID.
    pub pairing_lease_failure_limiter: RateLimiter,
    /// Per-device limiter for resumable snapshot-upload **create**. Reuses the
    /// established limiter pattern so one device cannot mint sessions in a loop;
    /// the real byte bound is the reservation ceiling, this only bounds request
    /// churn.
    pub snapshot_upload_create_rate_limiter: RateLimiter,
    /// Process-local per-upload mutation locks for the resumable snapshot-upload
    /// lifecycle.
    ///
    /// Serializes chunk, complete, abort, and expiry-sensitive mutation for one
    /// session **within this process**, which is the documented single-writer
    /// contract. The lock is held inside the blocking task through file write,
    /// file sync, and the conditional DB update, so a request cancelled by a
    /// timeout cannot let its still-running work interleave with a newer one.
    pub upload_locks: crate::routes::uploads::UploadLocks,
    pub ws_upgrade_rate_limiter: RateLimiter,
    pub sharing_fetch_rate_limiter: RateLimiter,
    pub sharing_init_rate_limiter: RateLimiter,
    pub media_upload_rate_limiter: RateLimiter,
    /// Re-supply/heal upload limiter, separate from fresh sends.
    pub media_resupply_rate_limiter: RateLimiter,
    /// Pairing-push upload limiter, keyed per pairing event/device.
    pub media_pairing_push_rate_limiter: RateLimiter,
    /// Ephemeral mailbox send limiter, keyed per sender device. The real
    /// request-storm bound for the re-supply signal lane.
    pub device_message_send_rate_limiter: RateLimiter,
    pub gif_request_rate_limiter: RateLimiter,
    pub gif_http_client: reqwest::Client,
}

impl AppState {
    /// Build state, resolving snapshot storage from the process environment.
    ///
    /// Test/bench convenience only — the production binary does **not** use this
    /// path. `main` resolves storage itself via
    /// [`crate::config::Config::resolve_snapshot_storage`] and then calls
    /// [`AppState::with_snapshot_storage`], so an explicitly demanded but
    /// unusable root aborts startup there.
    ///
    /// This constructor has no error channel and therefore cannot refuse, so on
    /// an unusable root it degrades to inline snapshot writes and logs at error
    /// level — keeping a harness with an odd `MEDIA_STORAGE_PATH` running.
    pub fn new(db: Database, config: Config) -> Self {
        let explicit = crate::config::snapshot_file_backing_explicitly_requested(|key| {
            std::env::var(key).ok()
        });
        let storage = match config.resolve_snapshot_storage(explicit) {
            Ok(storage) => storage,
            Err(error) => {
                // Reachable only when the process environment explicitly
                // demanded file backing. Degrade loudly rather than panic, since
                // this constructor has no error channel; production startup
                // refuses here instead.
                tracing::error!(
                    "SNAPSHOT_FILE_BACKING_ENABLED=true but snapshot storage validation failed \
                     ({error}); falling back to inline snapshot writes (production startup \
                     would refuse)"
                );
                crate::config::SnapshotStorage::Inline
            }
        };
        Self::with_snapshot_storage(db, config, storage)
    }

    /// Build state with an already-resolved snapshot storage policy.
    pub fn with_snapshot_storage(
        db: Database,
        config: Config,
        snapshot_storage: crate::config::SnapshotStorage,
    ) -> Self {
        let metrics = Arc::new(Metrics::default());
        let gif_http_client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(10))
            .pool_idle_timeout(Some(std::time::Duration::from_secs(90)))
            .tcp_keepalive(Some(std::time::Duration::from_secs(60)))
            .build()
            .expect("gif HTTP client should build");

        // Restore persisted counters so lifetime totals survive restarts.
        match db.with_read_conn(crate::db::load_counters) {
            Ok(counters) => metrics.restore_from(&counters),
            Err(e) => tracing::warn!("failed to load persisted counters: {e}"),
        }

        // Seed DB-state metric cache so the first scrape returns real values.
        // Cleanup runs after one full interval (~1hr), not immediately, so
        // without this the cached fields stay 0 until the first cleanup cycle.
        match db.with_read_conn(|conn| {
            let stored_batches: u64 =
                conn.query_row("SELECT COUNT(*) FROM batches", [], |r| r.get(0)).unwrap_or(0);
            let db_size_bytes: u64 = conn
                .query_row(
                    "SELECT page_count * page_size \
                     FROM pragma_page_count(), pragma_page_size()",
                    [],
                    |r| r.get(0),
                )
                .unwrap_or(0);
            let freelist_pages: u64 =
                conn.query_row("PRAGMA freelist_count;", [], |r| r.get(0)).unwrap_or(0);
            Ok::<(u64, u64, u64), rusqlite::Error>((stored_batches, db_size_bytes, freelist_pages))
        }) {
            Ok((sb, ds, fp)) => {
                metrics.cached_stored_batches.store(sb, Ordering::Relaxed);
                metrics.cached_db_size_bytes.store(ds, Ordering::Relaxed);
                metrics.cached_freelist_pages.store(fp, Ordering::Relaxed);
            }
            Err(e) => tracing::warn!("failed to seed metrics cache: {e}"),
        }

        Self {
            db: Arc::new(db),
            config: Arc::new(config),
            snapshot_storage,
            ws_connections: Arc::new(RwLock::new(HashMap::new())),
            ws_conn_seq: Arc::new(AtomicU64::new(0)),
            metrics,
            nonce_rate_limiter: RateLimiter::default(),
            revoke_rate_limiter: RateLimiter::default(),
            first_device_nonce_rate_limiter: RateLimiter::default(),
            first_device_registration_rate_limiter: RateLimiter::default(),
            first_device_group_rate_limiter: RateLimiter::default(),
            pairing_rate_limiter: RateLimiter::default(),
            pairing_lease_renew_rate_limiter: RateLimiter::default(),
            pairing_lease_failure_limiter: RateLimiter::default(),
            snapshot_upload_create_rate_limiter: RateLimiter::default(),
            upload_locks: crate::routes::uploads::UploadLocks::default(),
            ws_upgrade_rate_limiter: RateLimiter::default(),
            sharing_fetch_rate_limiter: RateLimiter::default(),
            sharing_init_rate_limiter: RateLimiter::default(),
            media_upload_rate_limiter: RateLimiter::default(),
            media_resupply_rate_limiter: RateLimiter::default(),
            media_pairing_push_rate_limiter: RateLimiter::default(),
            device_message_send_rate_limiter: RateLimiter::default(),
            gif_request_rate_limiter: RateLimiter::default(),
            gif_http_client,
        }
    }

    /// Broadcast a message to all WS connections for a sync group, excluding one device.
    pub async fn notify_devices(&self, sync_id: &str, exclude_device: Option<&str>, message: &str) {
        // Snapshot senders under the read guard, then drop the guard before
        // sending. A slow consumer with a full 64-slot channel must NOT block
        // the broadcast loop or stall register_ws/unregister_ws (which take
        // the write guard).
        let senders: Vec<(String, WsSender)> = {
            let conns = self.ws_connections.read().await;
            conns
                .get(sync_id)
                .map(|devices| {
                    devices
                        .iter()
                        .filter(|(device_id, _)| exclude_device != Some(device_id.as_str()))
                        .map(|(id, (_conn_id, sender))| (id.clone(), sender.clone()))
                        .collect()
                })
                .unwrap_or_default()
        }; // RwLock guard dropped here.

        if senders.is_empty() {
            return;
        }

        let mut dropped = 0u64;
        for (device_id, sender) in senders {
            match sender.try_send(message.to_string()) {
                Ok(_) => {}
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    dropped += 1;
                    tracing::debug!("WS channel full for device {device_id}, dropped notification");
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    dropped += 1;
                    tracing::debug!(
                        "WS channel closed for device {device_id}, dropped notification"
                    );
                }
            }
        }

        self.metrics.inc(&self.metrics.ws_notifications);
        if dropped > 0 {
            self.metrics.inc_by(&self.metrics.ws_notifications_dropped, dropped);
        }
    }

    /// Replace the current sender; pass the returned ID to [`Self::unregister_ws`].
    pub async fn register_ws(
        &self,
        sync_id: &str,
        device_id: &str,
    ) -> (mpsc::Receiver<String>, u64) {
        let conn_id = self.ws_conn_seq.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(WS_CHANNEL_CAPACITY);
        let mut conns = self.ws_connections.write().await;
        conns.entry(sync_id.to_string()).or_default().insert(device_id.to_string(), (conn_id, tx));
        (rx, conn_id)
    }

    /// Remove the sender only if this connection still owns the slot.
    pub async fn unregister_ws(&self, sync_id: &str, device_id: &str, conn_id: u64) {
        let mut conns = self.ws_connections.write().await;
        if let Some(devices) = conns.get_mut(sync_id) {
            if matches!(devices.get(device_id), Some((existing, _)) if *existing == conn_id) {
                devices.remove(device_id);
            }
            if devices.is_empty() {
                conns.remove(sync_id);
            }
        }
    }

    /// Disconnect the current sender regardless of connection ID, for revocation.
    pub async fn disconnect_ws(&self, sync_id: &str, device_id: &str) {
        let mut conns = self.ws_connections.write().await;
        if let Some(devices) = conns.get_mut(sync_id) {
            devices.remove(device_id);
            if devices.is_empty() {
                conns.remove(sync_id);
            }
        }
    }

    /// Count total connected WebSocket devices.
    pub async fn connected_device_count(&self) -> usize {
        let conns = self.ws_connections.read().await;
        conns.values().map(|d| d.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::db::Database;

    fn test_app_state() -> AppState {
        let db = Database::in_memory().expect("in-memory db");
        let config = Config::from_env();
        AppState::new(db, config)
    }

    #[tokio::test]
    async fn notify_devices_does_not_block_on_slow_consumer() {
        // The bug this fix targets: a single slow WS consumer with a full
        // channel can stall the broadcast loop for every device in the sync
        // group. The fix is `try_send` + drop-on-full. The right assertions
        // are (a) the broadcast loop never blocks regardless of consumer
        // state, and (b) dropped messages are accounted for. We do NOT
        // assert that any specific receiver gets a specific count, because
        // under bursty load `try_send` can drop on any receiver that
        // briefly fills its channel, even fast ones — that's the deliberate
        // tradeoff (fanout never blocks; clients catch up on next pull).
        let state = test_app_state();
        let sync_id = "sync-1";

        // dev_a registers but never reads — its 64-slot channel will fill up.
        let (_dev_a_rx, _) = state.register_ws(sync_id, "dev-a").await;
        // dev_b registers — we just need it to exist for the fanout loop.
        let (_dev_b_rx, _) = state.register_ws(sync_id, "dev-b").await;

        // Send 80 notifications. Without the fix, calls #65+ block on
        // dev_a's full channel for many seconds (the WS sender's
        // send().await never returns until the consumer drains). With the
        // fix (try_send + drop-on-full), all 80 calls return promptly.
        let send_start = std::time::Instant::now();
        for i in 0..80u32 {
            state.notify_devices(sync_id, None, &format!("msg-{i}")).await;
        }
        let send_elapsed = send_start.elapsed();
        assert!(
            send_elapsed < std::time::Duration::from_millis(500),
            "all 80 notify_devices calls should complete promptly (got {send_elapsed:?}); \
             the slow-consumer bug would stall this for many seconds"
        );

        // dev_a's drop counter must show that try_send dropped messages on
        // dev_a's full channel. Without the fix, the sender would have
        // blocked instead of dropping, so this counter would be 0.
        let dropped = state.metrics.ws_notifications_dropped.load(Ordering::Relaxed);
        assert!(
            dropped >= 16,
            "expected >= 16 dropped notifications for dev_a (80 sends - 64 buffer), got {dropped}"
        );
    }

    #[tokio::test]
    async fn unregister_ws_does_not_evict_a_replacement_connection() {
        let state = test_app_state();
        let sync_id = "sync-1";
        let device_id = "dev-a";

        let (_rx_a, conn_id_a) = state.register_ws(sync_id, device_id).await;
        let (mut rx_b, _conn_id_b) = state.register_ws(sync_id, device_id).await;

        // The old connection finishes after its replacement registers.
        state.unregister_ws(sync_id, device_id, conn_id_a).await;

        state.notify_devices(sync_id, None, "new_data").await;
        let message = tokio::time::timeout(std::time::Duration::from_millis(100), rx_b.recv())
            .await
            .expect("stale connection A's teardown must not remove B's live registration")
            .expect("replacement connection B's channel must remain open");
        assert_eq!(message, "new_data");
    }

    #[tokio::test]
    async fn unregister_ws_removes_the_current_connection() {
        let state = test_app_state();
        let sync_id = "sync-1";
        let device_id = "dev-a";

        let (mut rx, conn_id) = state.register_ws(sync_id, device_id).await;
        state.unregister_ws(sync_id, device_id, conn_id).await;

        assert_eq!(state.connected_device_count().await, 0);
        assert!(
            rx.recv().await.is_none(),
            "the current connection's cleanup must close its notification channel"
        );
    }

    #[tokio::test]
    async fn disconnect_ws_removes_only_the_target_current_connection() {
        let state = test_app_state();
        let sync_id = "sync-1";
        let other_sync_id = "sync-2";
        let target_device_id = "dev-a";

        let (_old_target_rx, _) = state.register_ws(sync_id, target_device_id).await;
        let (mut target_rx, _) = state.register_ws(sync_id, target_device_id).await;
        let (mut peer_rx, _) = state.register_ws(sync_id, "dev-b").await;
        let (mut other_group_rx, _) = state.register_ws(other_sync_id, target_device_id).await;

        state.disconnect_ws(sync_id, target_device_id).await;

        assert_eq!(state.connected_device_count().await, 2);
        assert!(
            target_rx.recv().await.is_none(),
            "forced teardown must close the target's current notification channel"
        );

        state.notify_devices(sync_id, None, "same-group").await;
        assert_eq!(peer_rx.recv().await, Some("same-group".to_string()));

        state.notify_devices(other_sync_id, None, "other-group").await;
        assert_eq!(other_group_rx.recv().await, Some("other-group".to_string()));
    }

    #[test]
    fn rate_limiter_allows_up_to_limit() {
        let limiter = RateLimiter::default();
        for i in 0..5 {
            assert!(limiter.check("key", 5, 60), "request {i} should be allowed");
        }
        assert!(!limiter.check("key", 5, 60), "6th request should be denied");
    }

    #[test]
    fn rate_limiter_tracks_keys_independently() {
        let limiter = RateLimiter::default();
        for _ in 0..3 {
            assert!(limiter.check("a", 3, 60));
        }
        assert!(!limiter.check("a", 3, 60));
        // Different key should still be allowed
        assert!(limiter.check("b", 3, 60));
    }

    #[test]
    fn rate_limiter_allows_after_window_expires() {
        let limiter = RateLimiter::default();
        // Use a 0-second window so timestamps expire immediately
        for _ in 0..5 {
            assert!(limiter.check("key", 5, 0));
        }
        // Window is 0s, so all previous timestamps are expired
        assert!(limiter.check("key", 5, 0));
    }

    #[test]
    fn rate_limiter_check_many_is_atomic_across_keys() {
        let limiter = RateLimiter::default();
        assert!(limiter.check_many(&["global", "ip"], 1, 60));
        assert!(!limiter.check_many(&["global", "ip"], 1, 60));

        let map = limiter.windows.lock().unwrap();
        assert_eq!(map.get("global").map(|v| v.len()), Some(1));
        assert_eq!(map.get("ip").map(|v| v.len()), Some(1));
    }

    #[test]
    fn rate_limiter_prune_stale_removes_expired() {
        let limiter = RateLimiter::default();
        limiter.check("a", 10, 0);
        limiter.check("b", 10, 0);
        // Both entries have timestamps, but with 0s window they're all expired
        limiter.prune_stale(0);
        let map = limiter.windows.lock().unwrap();
        assert!(map.is_empty(), "stale entries should be pruned");
    }

    #[test]
    fn rate_limiter_window_expiry_with_real_sleep() {
        let limiter = RateLimiter::default();
        // Use a 1-second window with a limit of 2
        assert!(limiter.check("key", 2, 1), "1st request should be allowed");
        assert!(limiter.check("key", 2, 1), "2nd request should be allowed");
        assert!(!limiter.check("key", 2, 1), "3rd request should be denied");

        // Sleep just over 1 second so the window expires
        std::thread::sleep(std::time::Duration::from_millis(1100));

        // After window expiry, the next request should be allowed
        assert!(limiter.check("key", 2, 1), "request after window expiry should be allowed");
    }

    #[test]
    fn rate_limiter_rejects_new_keys_at_capacity() {
        let limiter = RateLimiter::default();
        // Fill up to MAX_TRACKED_KEYS — we can't actually fill 100k in a test,
        // so verify the logic by directly inserting into the map.
        {
            let mut map = limiter.windows.lock().unwrap();
            for i in 0..RateLimiter::MAX_TRACKED_KEYS {
                map.insert(format!("key-{i}"), vec![Instant::now()]);
            }
        }
        // New key should be rejected
        assert!(!limiter.check("new-key", 10, 60));
        // Existing key should still work
        assert!(limiter.check("key-0", 10, 60));
    }
}
