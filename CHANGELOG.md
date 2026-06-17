# Changelog

All notable changes to prism-sync are recorded here.

## [0.13.1] - 2026-06-17

Tagged for the matching `prism-app 0.13.1+13101` release. Cargo crate versions
remain `0.1.1`. The app's sync pin moves from `prism-sync v0.13.0` to
`prism-sync v0.13.1`.

### Fixed
- Raised the FFI consumer-delivery journal cap from 50,000 to 250,000 rows so
  very large restore or catch-up backlogs spill less aggressively while still
  bounding local engine state.
- Registry approval now ignores stale active entries for devices the relay has
  already auto-revoked, so pairing a new device after a 90-day revoke can clear
  the pending rekey instead of failing with a protocol conflict.

### Internal
- Added cap-boundary coverage for the consumer-delivery spill threshold.
- Added relay coverage for registering a new device while the approver still
  carries an auto-revoked peer in its registry snapshot.

## [0.13.0] - 2026-06-13

Tagged for the matching `prism-app 0.13.0+13001` release. Cargo crate versions
remain `0.1.1`.

### Added
- Relay media support: a device-message mailbox, a media-heal lane, and a
  pairing-push media lane, so a newly paired device can be sent the media it is
  missing.
- prism_sync is built as a native asset, with the iOS deployment target forwarded
  into the Rust build.

### Fixed
- Pull recovery, sync-apply atomicity, and the revocation-replay gate were
  hardened (CRDT correctness remediation waves 1 and 2; all three critical
  findings closed).
- `encode_image` applies EXIF orientation before encoding, so rotated camera
  photos are stored upright.
- The relay accepts media ids shared across sync groups, raised the mailbox
  pending cap, and no longer races cleanup against resurrected media.

## [0.12.2] - 2026-06-06

Tagged for the matching `prism-app 0.12.2+12201` release. Cargo crate
versions remain `0.1.1`.

### Fixed
- Pairing slot polling now retries transient relay failures, so setup is less
  likely to fail on a short-lived relay error while waiting for the other
  device.
- Delete tombstones are absorbing during sync merge. A stale live snapshot can
  no longer resurrect records that another peer has already deleted.

### Internal
- Added real-relay coverage for pairing snapshot restore fields and aligned the
  fixture expectations with the live-state encoding for omitted
  `is_deleted=false` fields.

## [0.12.0] - 2026-06-04

Tagged for the matching `prism-app 0.12.0+12001` release. Cargo crate versions remain `0.1.1`. The app's sync pin moves from v0.11.0 (`b99d64d`) to v0.12.0 (`00db70a`); the 0.11.x app patches kept the v0.11.0 pin.

### Added
- `read_field_value` FFI surface. Dart can read a single op field by op id without scanning the full event stream, which is the lookup primitive the app's new cross-device end-to-end sync harness uses to drive assertions against the real sync state. Paired with a spawnable localhost test-relay (`crates/prism-sync-relay/examples/test_relay.rs`) and a 256 KB pairing payload cap on that test-relay that matches the prod cap.

### Changed
- Push engine caps emissions per cycle and re-arms to drain the backlog. A large push backlog (e.g. coalesced bulk deletes, or a long-disconnected device coming back online) now paces out over multiple cycles instead of bursting in one shot and starving pull. App-side status reporting was updated to stay steady through mid-drain continuations.
- Bulk deletes coalesce into batched tombstones. The op emitter recognizes a bulk-delete intent and serializes it as a single coalesced batched-tombstone op on the wire instead of N per-row tombstones. Consumed by the app's group/field clear paths.
- The sync engine pages pull-to-head within a single sync cycle. Large pull deltas (e.g. a paired device coming back to a system after a bulk change or large import) now stream through in one cycle instead of returning early after the first page and waiting on the next cycle, so receive feels steadier rather than long-idle. No FFI symbol change.

### Fixed
- Relay no longer strands pull cursors when a device deregisters itself mid-cycle. A self-deregister that raced with prune cleanup could leave the device's pull cursor pointing at a pruned position; the relay now resolves the deregister and cursor cleanup together so the next sync cycle for any other device does not trip on the orphan cursor.
- Sync apply drops superseded quarantined ops rather than churning on un-fixable ones. Quarantined ops that have been superseded by a later op (or that are structurally un-fixable) are now dropped from the quarantine table instead of being re-attempted every apply cycle.

### Internal
- New tests cover delete-coalesce convergence, op-emitter atomicity, and the pull budget enforcement.
- Replaced an unnecessary `sort_by` with `sort_by_key` to satisfy `clippy::unnecessary_sort_by`.

## [0.11.0] - 2026-05-31

Tagged for the matching `prism-app 0.11.0+11001` release. Cargo crate versions remain `0.1.1`.

### Added
- `encode_image` FFI for cross-platform image normalization. The Dart bindings can now pass JPEG/PNG/WebP-style input through Rust, resize it to Prism's target bounds, and receive JPEG for opaque images or lossless WebP for images that use transparency. This supports Prism's encrypted bio-image pipeline consistently across desktop and mobile builds.
- `take_last_panic` FFI diagnostic hook. Panics caught across the FFI boundary are captured in a redacted last-panic slot so app-side recovery paths can log the real Rust panic location/payload while still presenting a recoverable sync error to users.

### Fixed
- Relay snapshot replacement now permits the same uploader to replace the same sequence snapshot, which keeps retry/idempotency behavior from being rejected as stale.
- Device-registry import now fails closed for unverified registry paths, and ML-DSA rotation catch-up requires a verified registry before accepting rotation state from the relay.

### Internal
- Added regression coverage for snapshot over-wire-limit handling, fronting `end_time` null/timestamp convergence, and panic-hook behavior.

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
