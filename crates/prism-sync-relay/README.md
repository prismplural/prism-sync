# prism-sync-relay

V2 relay server for prism-sync encrypted CRDT sync.

## Running

```bash
cargo run -p prism-sync-relay
```

## Configuration

All configuration via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| PORT | 8080 | Server port |
| DB_PATH | data/relay.db | SQLite database path |
| SESSION_EXPIRY_SECS | 2592000 | Session token sliding expiry, refreshed per request (30 days) |
| SESSION_MAX_AGE_SECS | 7776000 | Absolute session lifetime from last re-auth (90 days) |
| NONCE_EXPIRY_SECS | 60 | Registration nonce expiry |
| STALE_DEVICE_SECS | 2592000 | Stale device threshold (30 days) |
| SYNC_INACTIVE_TTL_SECS | 7776000 | Auto-revoke threshold (90 days) |
| CLEANUP_INTERVAL_SECS | 3600 | Background cleanup interval |
| MAX_UNPRUNED_BATCHES | 10000 | Max batches before rejecting push |
| METRICS_TOKEN | (none) | Bearer token for /metrics. Unset => loopback-only (fails closed) |
| RUST_LOG | info | Tracing log level |
| DEFAULT_REQUEST_TIMEOUT_SECS | 30 | Per-request timeout for light routes (408 on expiry) |
| SNAPSHOT_REQUEST_TIMEOUT_SECS | 300 | Per-request timeout for `PUT /snapshot` (5 min for large uploads on slow connections) |
| MEDIA_REQUEST_TIMEOUT_SECS | 120 | Per-request timeout for media upload/download (covers up to response headers; streamed download bodies continue past) |
| DEFAULT_REQUEST_CONCURRENCY | 512 | Max in-flight light requests (must be ≥ 1) |
| SNAPSHOT_UPLOAD_CONCURRENCY | 8 | Max in-flight snapshot PUTs, and a separate cap for resumable completions (must be ≥ 1) |
| MEDIA_UPLOAD_CONCURRENCY | 32 | Max in-flight media uploads/downloads (must be ≥ 1) |
| MEDIA_STORAGE_PATH | data/media | Root for media and (derived) snapshot blobs. In containers set an explicit absolute path on the persistent mount, e.g. `/data/media`. |
| SNAPSHOT_FILE_BACKING_ENABLED | (unset) | Set `true` to enable file-backed snapshot writes and require an absolute, writable persistent root. Unset or `false` keeps new snapshots inline in SQLite, even with a valid root; existing blob files remain readable. |
| TRUSTED_PROXY_CIDRS | (none) | Comma-separated CIDRs of reverse proxies/tunnels whose forwarded client-IP headers (`CF-Connecting-IP`, `X-Forwarded-For`, `Forwarded`) are trusted. Required before enabling `PAIRING_LEASE_ENABLED` in a proxy-fronted deployment. |
| PAIRING_LEASE_ENABLED | false | Offer the opaque pairing lease (v1). Dark by default. When `false`, a create request that offers lease metadata is downgraded to a fixed-TTL session with no `lease_version` echo, and `/lease/renew` returns the uniform not-found. |
| PAIRING_LEASE_MAX_CONCURRENT_SESSIONS | 256 | Global cap on concurrently leased pairing rows. Renewal of an already-leased row is never blocked by this cap. |
| PAIRING_LEASE_RENEW_RATE_LIMIT | 120 | Max lease renewals per trusted-proxy-derived client IP per window. |
| PAIRING_LEASE_RENEW_RATE_WINDOW_SECS | 60 | Window for `PAIRING_LEASE_RENEW_RATE_LIMIT`. |
| PAIRING_LEASE_FAILURE_LIMIT | 20 | Max *failed* verifier attempts per presented rendezvous ID per window. Failures are counted only; a legitimate renewal is never starved by garbage knowing the rendezvous ID. |
| PAIRING_LEASE_FAILURE_WINDOW_SECS | 60 | Window for `PAIRING_LEASE_FAILURE_LIMIT`. |

## API Endpoints

### Registration
- `GET /v1/sync/{sync_id}/register-nonce` — Get one-time registration nonce
- `POST /v1/sync/{sync_id}/register` — Register device (challenge-response)

### Sync
- `PUT /v1/sync/{sync_id}/changes` — Push signed batch envelope
- `GET /v1/sync/{sync_id}/changes?since=N&limit=100` — Pull batches (paginated)
- `GET /v1/sync/{sync_id}/snapshot` — Download snapshot
- `PUT /v1/sync/{sync_id}/snapshot` — Upload snapshot (one request; unchanged)

### Resumable Snapshot Uploads

Additive and **dark by default**: advertised through the
`snapshot_upload` capability sibling only when `SNAPSHOT_UPLOAD_ENABLED=true` *and*
file-backed snapshot storage is active. Without the capability the routes below are absent
(`404`), which is exactly what an older client treats as "feature not supported" and falls
back from. The single `PUT /snapshot` above is never affected.

```text
POST   /v1/sync/{sync_id}/snapshot/uploads                      create or recover
GET    /v1/sync/{sync_id}/snapshot/uploads/{upload_id}          status
PUT    /v1/sync/{sync_id}/snapshot/uploads/{upload_id}/chunks/{offset}
POST   /v1/sync/{sync_id}/snapshot/uploads/{upload_id}/complete complete and publish
DELETE /v1/sync/{sync_id}/snapshot/uploads/{upload_id}          abort
```

Every operation requires the normal bearer session **and** hybrid signed-request headers.
The canonical signature binds method, path, `sync_id`, device ID, body hash, timestamp, and
nonce — so `upload_id` and the decimal `offset` live in the signed path and neither an
unsigned offset nor an unsigned checksum is ever authoritative. On top of that the session
owner is re-checked against the immutable row: knowing an `upload_id` is not authority, and
a sibling device in the same group cannot operate another device's upload. Both of those
failures return the same `404 upload_not_found`, so the endpoint is not an existence oracle.

Contract summary.

- **Bounded upload work.** Chunk requests, completion requests, and control requests
  have independent budgets. Excess requests return retryable `503 upload_busy` before
  their bodies are buffered. Upload handlers retain admission while their blocking
  file/database work runs, even if the HTTP request times out. Completion uses
  `SNAPSHOT_UPLOAD_CONCURRENCY`; controls use `DEFAULT_REQUEST_CONCURRENCY`.
- **Fixed protocol shape.** Chunk size is 8 MiB and the wire maximum is 150 MiB, both
  compile-time constants rather than runtime configuration. The route body limit is the
  protocol maximum, so a restart or config change cannot wedge a live session before
  semantic validation runs.
- **Sequential, exact offsets.** New bytes are accepted only at `offset == committed_offset`.
  A wholly committed range is an idempotent retry: the relay returns its current offset
  without reading, comparing, or writing the bytes, and without refreshing expiry. Ahead-of
  and partially-overlapping offsets return `409 offset_mismatch` with the relay's offset. A
  non-final chunk that is shorter than the chunk size returns `400 chunk_too_short`, which also
  echoes the relay's offset and chunk size.
- **Durable before acknowledged.** Chunks use positioned writes (never append) followed by
  `sync_data`, and the DB offset advances only after that. A crash between the write and the
  commit is reconciled by truncating back to the committed offset on the next write.
- **Nothing is visible until it publishes.** The candidate is written to the unique name the
  completed snapshot row will reference and stays invisible until completion swaps that row
  in one writer transaction — reusing the same audience cap and `server_seq_at` staleness
  guard the single PUT uses. Completion verifies the whole file against the create-time
  SHA-256 and synchronizes the file and its directory first.
- **Reserved up front.** Create reserves the declared bytes; reservations are derived from
  nonterminal rows, so the transition that ends a session's lifecycle ends its reservation in
  the same transaction. Global, per-group, per-device, and free-space limits apply. A new
  session from the same device supersedes that device's older *active* session, but never one a
  completion already owns: while a completion is publishing, a create with a new key is refused
  with retryable `503 upload_busy` until the publication resolves.
- **Configured free-space reserve.** `SNAPSHOT_UPLOAD_FREE_SPACE_RESERVE_BYTES` is enforced on
  admission, on every accepted chunk, and again at completion. A probe that cannot read the
  volume is treated as no space (fail closed), never as permission to write.
- **`204` means published.** Completion reports success only when the published snapshot row
  actually references the staged file. A session that was superseded, aborted, or expired while
  a completion was in flight is a truthful `409 upload_failed`, never a silent success.
- **Bounded lifetime.** Idle TTL is one hour (refreshed only by an accepted new offset) with a
  four-hour absolute cap. Terminal sessions are retained for an hour so a lost
  create/complete response is answered from the recorded result rather than forcing a
  re-upload.
- **Single relay process.** The per-session mutation lock is process-local, matching the
  documented single-replica contract. Do not run multiple relay writers against one database
  and storage volume.

### Devices
- `GET /v1/sync/{sync_id}/devices` — List devices with public keys
- `DELETE /v1/sync/{sync_id}/devices/{device_id}` — Revoke or deregister
- `POST /v1/sync/{sync_id}/rekey` — Post epoch rotation artifacts
- `GET /v1/sync/{sync_id}/rekey/{device_id}` — Get wrapped epoch key
- `POST /v1/sync/{sync_id}/ack` — Acknowledge receipt

### Pairing
- `POST /v1/pairing` — Create a rendezvous. Accepts optional `lease_key_hash` (the SHA-256
  of a 32-byte secret, base64-encoded) plus `lease_version: 1`. The relay accepts **both**
  base64 alphabets — standard (`+`/`/`) and base64url (`-`/`_`), padded or unpadded — and
  requires the value to decode to exactly 32 bytes; malformed values are silently downgraded
  (no error, no echo). The core client currently emits the **standard** alphabet, which stays
  the v1 legacy canonical form. A supporting relay commits the verifier and echoes
  `"lease_version": 1`. The echo — not the `201` — is authoritative for lease support, so an
  unconfigured or older relay degrades to fixed-TTL pairing.
- `PUT`/`GET /v1/pairing/{rid}/lease_capability` — Optional, nonterminal initiator capability
  slot, posted before `pairing_init`. Unlike the terminal `credentials`/`joiner` slots it is
  never consumed, so a retrying joiner always reads the same frame.
- `POST /v1/pairing/{rid}/lease/renew` — Renew an established lease. Body is the exact
  32-byte `pairing_lease_secret` as `application/octet-stream`; authority is the secret alone
  (no bearer session, device identity, or upload linkage). Success is `204` with no body and
  no timestamp. Every rejection — unknown, expired, lease-declined, pre-confirmation,
  consumed, globally saturated, wrong secret, wrong body length, or an oversize body — is the
  *same* byte-identical `404`, so the endpoint is not a state oracle. (An oversize body is
  read under a bounded cap and collapsed to that 404 rather than answered with a distinct
  `413`.) Any failure is nonfatal to the ceremony: the client continues under the previous
  expiry.

### WebSocket
- `GET /v1/sync/{sync_id}/ws` — WebSocket (authenticated before upgrade)

### Operations
- `GET /health` — Health check
- `GET /metrics` — Prometheus metrics

Disk-space observability for file-backed snapshots and media is a **host** concern: scrape
node-exporter filesystem metrics (`node_filesystem_avail_bytes`) for the volume behind
`MEDIA_STORAGE_PATH`. The resumable snapshot upload path additionally enforces relay-side
minimum-free-space admission (`SNAPSHOT_UPLOAD_FREE_SPACE_RESERVE_BYTES`) at session create
and before each chunk write, when it is enabled; the single `PUT /snapshot` and media paths
have no such gate.
`prism_snapshots_missing_blob_total` is the relay-side signal that the blob tree and the
DB rows have diverged (e.g. a restore that missed the blob tree).

## Security

The relay only sees ciphertext — it stores encrypted blobs and never reads plaintext data. Authentication uses per-device session tokens issued via Ed25519 challenge-response.
