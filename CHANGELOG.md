# Changelog

All notable changes to prism-sync are recorded here.

## [0.10.1] - 2026-05-28

Tagged for the matching `prism-app 0.10.1+10101` release. Cargo crate versions remain `0.1.1`.

### Added
- `/metrics` on prism-sync-relay surfaces `ws_notifications_total`, the total WS broadcast count, alongside the existing `ws_notifications_dropped` counter so the notification fan-out rate is observable.

### Changed
- Snapshot bootstrap now emits a single `RemoteChanges` event carrying the full snapshot entity list, so the app can use the event length as a restore-progress denominator. (Consumed by the app's onboarding snapshot-restore progress indicator.)

### Fixed
- Acknowledged batches are now pruned even for groups without a group-wide snapshot. Pruning was gated entirely on an unexpired group-wide snapshot, which clients only ever upload pairing-targeted (never group-wide for normal groups), so batch history grew without bound. The relay now prunes each group with no group-wide snapshot down to the lowest seq all non-revoked devices have acknowledged; the floor includes stale-but-not-revoked devices so a returning device is never forced to re-bootstrap, and only revocation advances the floor. Groups that do have a group-wide snapshot stay on the snapshot-gated path, so the two paths never disagree on `pruned_floor_seq`. Runs as cleanup step 7b.

## [0.10.0] - 2026-05-26

Tagged for the matching `prism-app 0.10.0+10001` release. Cargo crate versions remain `0.1.1`.

### Added
- `verify_mnemonic_pin` FFI for credential pre-flight. The app can verify a phrase + PIN locally before committing to the sync chain, and can verify a saved backup phrase + PIN without performing a restore.
- `/metrics` on prism-sync-relay surfaces `ws_notifications_dropped` and `snapshots_rejected_stale` counters alongside the existing relay metrics.

### Changed
- Stale `PUT /snapshot` requests are now suppressed via audience-aware logic: the relay drops a snapshot upload that targets a strictly older audience than the latest accepted snapshot for the same syncer, instead of accepting it and confusing downstream readers.
- Relay request authentication surfaces signed request identity mismatches as a typed error rather than a generic 401, so device-pairing diagnostics can show what was actually wrong.
- Relay WS broadcast is no longer blockable by a single slow subscriber: the broadcast path switches to `tokio::sync::broadcast` (subtle channel) and tightens WAL pragmas on the relay sqlite to avoid checkpoint stalls under contention.

### Perf
- New V7 index on `applied_ops(sync_id, server_seq)`. Speeds up the relay's per-syncer applied-ops scan that runs on every push and pull batch.

## [0.9.3] - 2026-05-20

Tagged for the matching `prism-app 0.9.3` / `0.9.4` releases. Cargo crate versions remain `0.1.1`.

### Fixed
- Pair-time signed registry snapshots now advance from the relay's current version so existing devices accept newly paired joiners after epoch or revoke activity. Signed-registry repair verifies against the trusted local registry, and pairing decrypt errors include non-secret envelope metadata for future diagnosis.
- prism-sync-relay revoke rate limit default increased from 2 to 20 per hour. Users were hitting the prior cap when retrying device revoke during sync setup hiccups in public beta; 20/hour still bounds abuse while giving real users room to recover.

## [0.9.0] - 2026-05-16

Tagged for the matching `prism-app 0.9.0+9001` release. Cargo crate versions remain `0.1.1`.

### Fixed
- `crates/prism-sync-ffi` windows build: `windows/CMakeLists.txt` now passes the cargo crate name `prism_sync_ffi` (matching `[lib]` in `crates/prism-sync-ffi/Cargo.toml` and what `linux/CMakeLists.txt` passes) instead of `prism_sync`. Cargo produced `prism_sync_ffi.dll` while cargokit's install rule looked for `prism_sync.dll`, so `cmake_install` failed with the misleading "cannot find ... File exists" wording on windows.
- Device revoke now uses the relay epoch instead of the local epoch when sealing the revoke envelope, so a stale local epoch can't leave a revoke un-applied on the relay.

## [0.1.1] - 2026-05-11

### Added
- Records that serialize larger than the relay's 1 MB envelope cap (typically PluralKit members with avatar + banner blobs) are split into multiple atomic batches via `emit_create_multi` / `emit_update_multi`, so large imports no longer get stuck retrying a single oversized envelope.
- Oversized batches that still exceed the cap after splitting are quarantined locally — the engine writes a `push_quarantine` row keyed by `local_batch_id`, emits `SyncEvent::QuarantinedBatch`, and continues pushing the rest of the cycle instead of stalling. FFI + Dart bindings expose the quarantine count.
- `repair_quarantined_batches` API (and matching FFI / Dart bindings) to recover from existing quarantine state without manual SQL. Repartitions each quarantined batch's `pending_ops` into smaller sub-batches in one transaction and returns the number of quarantine rows repaired.

### Fixed
- Small fields are emitted ahead of large fields within a batch so receivers no longer hit NOT NULL violations when a batch contains only avatar / banner blobs. `partition_fields_into_batches` previously packed descending; now sorts ascending.
- Multi-batch push order is deterministic across partitions: `emit_multi` stamps each partition with a per-index microsecond offset so the push-side `MIN(created_at)` query never lets the small-fields batch lose the FIFO race against large-blob batches.
- Push timestamps use fixed-width microseconds in `exec_insert_pending_op` and `exec_upsert_field_version`, so TEXT-ordered timestamps stay chronological across millisecond / microsecond digit-count boundaries. `query_unpushed_batch_ids` also tiebreaks on `MIN(client_hlc)` for same-microsecond batches.
