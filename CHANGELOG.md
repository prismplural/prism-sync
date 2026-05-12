# Changelog

All notable changes to prism-sync are recorded here.

## [0.1.1] - 2026-05-11

### Added
- Records that serialize larger than the relay's 1 MB envelope cap (typically PluralKit members with avatar + banner blobs) are split into multiple atomic batches via `emit_create_multi` / `emit_update_multi`, so large imports no longer get stuck retrying a single oversized envelope.
- Oversized batches that still exceed the cap after splitting are quarantined locally — the engine writes a `push_quarantine` row keyed by `local_batch_id`, emits `SyncEvent::QuarantinedBatch`, and continues pushing the rest of the cycle instead of stalling. FFI + Dart bindings expose the quarantine count.
- `repair_quarantined_batches` API (and matching FFI / Dart bindings) to recover from existing quarantine state without manual SQL. Repartitions each quarantined batch's `pending_ops` into smaller sub-batches in one transaction and returns the number of quarantine rows repaired.

### Fixed
- Small fields are emitted ahead of large fields within a batch so receivers no longer hit NOT NULL violations when a batch contains only avatar / banner blobs. `partition_fields_into_batches` previously packed descending; now sorts ascending.
- Multi-batch push order is deterministic across partitions: `emit_multi` stamps each partition with a per-index microsecond offset so the push-side `MIN(created_at)` query never lets the small-fields batch lose the FIFO race against large-blob batches.
- Push timestamps use fixed-width microseconds in `exec_insert_pending_op` and `exec_upsert_field_version`, so TEXT-ordered timestamps stay chronological across millisecond / microsecond digit-count boundaries. `query_unpushed_batch_ids` also tiebreaks on `MIN(client_hlc)` for same-microsecond batches.
