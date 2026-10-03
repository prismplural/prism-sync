# Self-Hosting the Prism Relay

The relay is a lightweight Rust server that stores encrypted sync data in SQLite and delivers
it to your authorized devices. It never sees your plaintext data — all it handles are encrypted
blobs that only your devices can decrypt.

Even on the official relay, your data is end-to-end encrypted and unreadable by anyone without
your password and recovery phrase. Self-hosting gives you full control over the infrastructure:
you choose where the encrypted data lives, who can access the server, and when it gets deleted.

The relay is small and efficient. It runs on anything from a Raspberry Pi to a cloud instance.

## Quick Start

1. **Pull the Docker image.**

   ```bash
   docker pull ghcr.io/prismplural/prism-relay:latest
   ```

2. **Create a directory and write a `docker-compose.yml`.**

   ```yaml
   services:
     relay:
       image: ghcr.io/prismplural/prism-relay:latest
       ports:
         - "8080:8080"
       volumes:
         - relay-data:/data
       environment:
         - FIRST_DEVICE_POW_DIFFICULTY_BITS=0
         - FIRST_DEVICE_ANDROID_ATTESTATION_ENABLED=false
         - FIRST_DEVICE_APPLE_ATTESTATION_ENABLED=false
       restart: unless-stopped

   volumes:
     relay-data:
   ```

   Or use the [docker-compose.yml](docker-compose.yml) in this directory, which includes
   security hardening (read-only root, dropped capabilities, health checks).

3. **Start the relay.**

   ```bash
   docker compose up -d
   ```

4. **Copy your registration token** from the logs. The relay auto-generates one on first boot.

   ```bash
   docker compose logs relay | grep "REGISTRATION TOKEN"
   ```

   Enter this token in the Prism app when connecting to your relay.

5. **Verify it's running.**

   ```bash
   curl http://localhost:8080/health
   # {"status":"ok"}
   ```

## Registration

The relay always requires a registration token. On first boot, if no `REGISTRATION_TOKEN`
is set, the relay auto-generates a random token, saves it to `/data/.registration-token`,
and logs it. The token persists across restarts.

**Auto-generated (default):** Leave `REGISTRATION_TOKEN` unset. Find the token in the logs.
Paired devices receive it automatically — you only enter it once.

**Custom token:** Set `REGISTRATION_TOKEN` to your own value:
```bash
echo "REGISTRATION_TOKEN=$(openssl rand -hex 32)" > .env
```

**Open:** Set `REGISTRATION_TOKEN=OPEN` for unrestricted registration. Anyone who discovers
your relay URL can create sync groups. They can't read your data, but they'll use your
storage. Only use this behind a VPN or Tailnet.

**Closed:** Set `REGISTRATION_ENABLED=false` to reject all new registrations. Use this after
all your devices are paired to lock down the relay completely.

## Reverse Proxy

The relay serves plain HTTP. For any internet-exposed deployment, put it behind a reverse
proxy for TLS.

### Caddy (recommended)

Caddy handles TLS automatically and proxies WebSocket connections without extra config.

```
sync.example.com {
  reverse_proxy localhost:8080
}
```

### nginx

nginx needs explicit WebSocket upgrade headers.

```nginx
server {
    listen 443 ssl;
    server_name sync.example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
```

### Cloudflare Tunnel

```bash
cloudflared tunnel create prism-relay
cloudflared tunnel route dns prism-relay sync.example.com
cloudflared tunnel run --url http://localhost:8080 prism-relay
```

Cloudflare's free tier has a 100-second idle timeout on WebSocket connections. The Prism
client reconnects automatically, but you may see more frequent reconnects than with a
direct proxy.

## Configuration

All environment variables with their defaults. Everything is production-ready out of the box.

### Core

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | HTTP listen port |
| `DB_PATH` | `data/relay.db` | SQLite database path |
| `RUST_LOG` | `info` | Log level (error, warn, info, debug, trace) |
| `READER_POOL_SIZE` | `4` | Read-only SQLite connection pool size |

### Registration

| Variable | Default | Description |
|----------|---------|-------------|
| `REGISTRATION_TOKEN` | *(auto-generated)* | Registration token. Set to `OPEN` for unrestricted |
| `REGISTRATION_ENABLED` | `true` | Set to `false` to disable all registration |

### Rate Limiting

| Variable | Default | Description |
|----------|---------|-------------|
| `NONCE_RATE_LIMIT` | `10` | Max registration nonces per sync group per window |
| `NONCE_RATE_WINDOW_SECS` | `60` | Nonce rate limit window |
| `REVOKE_RATE_LIMIT` | `20` | Max device revocations per group per window |
| `REVOKE_RATE_WINDOW_SECS` | `3600` | Revocation rate limit window |

### Pairing Lease

The opaque pairing lease (v1) keeps a confirmed pairing rendezvous alive while a
snapshot upload continues, without linking the rendezvous to the upload. It is
**off by default**: a relay with `PAIRING_LEASE_ENABLED=false` behaves exactly
like a pre-lease relay, so clients fall back to fixed-TTL pairing.

If anything fronts your relay (Caddy, nginx, Cloudflare Tunnel), set
`TRUSTED_PROXY_CIDRS` to the ingress ranges **before** enabling the lease.
Otherwise every renewal is rate limited by the ingress address and all users
share one bucket. A relay reached directly by clients needs no allowlist.

| Variable | Default | Description |
|----------|---------|-------------|
| `PAIRING_LEASE_ENABLED` | `false` | Offer the pairing lease. Dark by default; enabling it in a proxy-fronted deployment without `TRUSTED_PROXY_CIDRS` is refused at startup. |
| `PAIRING_LEASE_MAX_CONCURRENT_SESSIONS` | `256` | Global cap on concurrently leased pairing rows. An already-leased row always renews, even at the cap. |
| `PAIRING_LEASE_RENEW_RATE_LIMIT` | `120` | Max renewals per trusted-proxy-derived client IP per window. Sized well above the legitimate one-per-ceremony-per-five-minutes. |
| `PAIRING_LEASE_RENEW_RATE_WINDOW_SECS` | `60` | Window for the per-client-IP renewal limit. |
| `PAIRING_LEASE_FAILURE_LIMIT` | `20` | Max *failed* verifier attempts per presented rendezvous ID per window. Only failures are counted, so knowing a rendezvous ID cannot starve a legitimate renewal. |
| `PAIRING_LEASE_FAILURE_WINDOW_SECS` | `60` | Window for the per-rendezvous failure limit. |

### Maintenance

| Variable | Default | Description |
|----------|---------|-------------|
| `CLEANUP_INTERVAL_SECS` | `3600` | Background cleanup frequency |
| `SYNC_INACTIVE_TTL_SECS` | `7776000` | Auto-prune inactive groups (default: 90 days) |
| `STALE_DEVICE_SECS` | `2592000` | Mark devices stale after inactivity (30 days) |
| `SESSION_EXPIRY_SECS` | `2592000` | Session token sliding lifetime, refreshed on each request (30 days) |
| `SESSION_MAX_AGE_SECS` | `7776000` | Absolute session lifetime from last re-auth; a token older than this is rejected even if kept active (90 days) |
| `MAX_UNPRUNED_BATCHES` | `10000` | Max undelivered batches before rejecting pushes |
| `SNAPSHOT_DEFAULT_TTL_SECS` | `86400` | Ephemeral snapshot retention (24 hours) |

### Media Storage

| Variable | Default | Description |
|----------|---------|-------------|
| `MEDIA_STORAGE_PATH` | `data/media` | Directory for uploaded media. **Set this to an explicit absolute path on your persistent volume (e.g. `/data/media`)** — pair-time snapshot blobs are derived from the same parent, and a relative path can resolve under the container workdir where it is ephemeral or unwritable. |
| `MEDIA_MAX_FILE_BYTES` | `10485760` | Maximum size per upload (10 MB) |
| `MEDIA_QUOTA_BYTES_PER_GROUP` | `1073741824` | Total media per sync group (1 GB) |
| `MEDIA_RETENTION_DAYS` | `90` | Days before unreferenced media is cleaned up |
| `MEDIA_UPLOAD_RATE_LIMIT` | `10` | Max uploads per sync group per rate window |
| `MEDIA_UPLOAD_RATE_WINDOW_SECS` | `60` | Rate limit sliding window |
| `MEDIA_ORPHAN_CLEANUP_SECS` | `86400` | Interval for cleaning up orphaned media files (24 hours) |
| `SNAPSHOT_FILE_BACKING_ENABLED` | *(unset)* | Set to `true` to **require** file-backed snapshot storage and refuse startup if the derived root (`<MEDIA_STORAGE_PATH>-snapshots`) is unusable (relative, non-creatable, or unwritable). Unset or `false` keeps the legacy inline-in-SQLite snapshot path as a fallback, so an upgrade against a relative `MEDIA_STORAGE_PATH` degrades instead of failing. Set `true` on a production relay that has an absolute `MEDIA_STORAGE_PATH` so a bad root fails loudly instead of silently writing snapshots inline. |

### Resumable Snapshot Uploads

Pair-time snapshots can be uploaded in bounded, resumable chunks instead of one large
request. This keeps each request well under common reverse-proxy and CDN per-request
limits and lets an interrupted upload resume from the relay's acknowledged offset rather
than restarting at byte zero.

**It is dark by default.** Nothing changes until you set `SNAPSHOT_UPLOAD_ENABLED=true`,
and even then the relay advertises the capability only when file-backed snapshot storage is
active (which requires an absolute `MEDIA_STORAGE_PATH`; see
`SNAPSHOT_FILE_BACKING_ENABLED` above). A relay that does not advertise the capability is
indistinguishable to clients from an older relay: they use the existing single
`PUT /v1/sync/{sync_id}/snapshot`, whose behavior is unchanged.

| Variable | Default | Description |
|----------|---------|-------------|
| `SNAPSHOT_UPLOAD_ENABLED` | `false` | Offer resumable snapshot uploads. Requires file-backed snapshot storage; otherwise the capability stays withheld and the relay logs a warning at startup. |
| `SNAPSHOT_UPLOAD_GLOBAL_RESERVED_BYTES` | `2516582400` | Relay-wide ceiling on bytes reserved by **in-progress** uploads (16 × the 150 MiB wire cap). Size this from the volume behind `MEDIA_STORAGE_PATH`. |
| `SNAPSHOT_UPLOAD_GROUP_RESERVED_BYTES` | `629145600` | Per-sync-group ceiling on reserved bytes (4 × the wire cap, matching the targeted-snapshot audience cap). |
| `SNAPSHOT_UPLOAD_FREE_SPACE_RESERVE_BYTES` | `314572800` | Free space that must remain **after** an upload's declared bytes are reserved. A create or chunk write that cannot preserve this is refused. |
| `SNAPSHOT_UPLOAD_CREATE_RATE_LIMIT` | `10` | Max session-create requests per device per window. |
| `SNAPSHOT_UPLOAD_CREATE_RATE_WINDOW_SECS` | `60` | Sliding window for the create rate limit. |
| `SNAPSHOT_UPLOAD_CHUNK_CONCURRENCY` | `4` | Max simultaneous chunk writes. Excess is shed as retryable `503 upload_busy` (never a quota-coded `429`, so clients back off rather than treating it as a policy rejection). |

Behavior worth knowing before you enable it:

- **One active upload per device.** A new session from the same device supersedes that
  device's older in-progress session, releasing its reservation. A lost abort cannot poison
  later pairing attempts.
- **Sessions expire.** An idle session expires after one hour with no newly accepted
  offset; the absolute cap is four hours regardless of activity. Expiry and abandonment
  release the reservation and reclaim the staged bytes.
- **Nothing is published until completion.** Bytes are staged under
  `<MEDIA_STORAGE_PATH>-snapshots/<sync_id>/<opaque-id>` and stay invisible until the
  session completes and publishes the reference through the existing targeted-snapshot
  row. The final bytes are verified against the SHA-256 declared at create time.
- **Aggregate-only metrics.** `prism_snapshot_upload_*` metrics carry no sync, device, or
  upload label, so they cannot become a per-user activity signal. `prism_snapshot_upload_reserved_bytes`
  and `prism_snapshot_upload_sessions_active` are the two to watch against your ceilings.
- **Single relay process.** Resumable sessions rely on the documented single-replica
  contract (one process owning the SQLite database and the snapshot filesystem). Do not run
  multiple relay writers behind a shared database or storage volume.

Rollback behavior is documented under [Upgrades and rollback](#upgrades-and-rollback): a
binary predating this feature ignores the session table entirely, so a downgrade while
`SNAPSHOT_UPLOAD_ENABLED=true` simply stops advertising the capability. Already-completed
snapshots remain readable, and any incomplete session is abandoned (its staged bytes are
swept once no row references them).

### Request Timeouts and Concurrency

Each route has a wall-clock timeout. Returns `408 Request Timeout` on expiry.
Heavy upload routes have their own (much larger) timeouts because real-world
encrypted snapshots can reach 150 MB and need minutes to upload over slow
mobile links. Concurrency caps bound in-memory body buffering — the per-route
defaults are sized so the worst case fits comfortably under a 4 GB RAM budget
(8 × 150 MB snapshot uploads = 1.2 GB; 32 × 10 MB media uploads = 320 MB; light
routes are cheap).

| Variable | Default | Description |
|----------|---------|-------------|
| `DEFAULT_REQUEST_TIMEOUT_SECS` | `30` | Timeout for light routes (sync, devices, sharing, registration, health, metrics, WebSocket upgrade) |
| `SNAPSHOT_REQUEST_TIMEOUT_SECS` | `300` | Timeout for `PUT /v1/sync/{sync_id}/snapshot` (5 min — fits 150 MB at ~500 KB/s) |
| `MEDIA_REQUEST_TIMEOUT_SECS` | `120` | Timeout for media upload/download (2 min — covers request handling through response headers; streamed download bodies continue past this deadline) |
| `DEFAULT_REQUEST_CONCURRENCY` | `512` | Max simultaneous in-flight light requests. Must be ≥ 1 |
| `SNAPSHOT_UPLOAD_CONCURRENCY` | `8` | Max simultaneous in-flight snapshot PUTs. Each buffers the full body in memory. Must be ≥ 1 |
| `MEDIA_UPLOAD_CONCURRENCY` | `32` | Max simultaneous in-flight media uploads/downloads. Must be ≥ 1 |

A concurrency value of `0` is rejected at startup — a zero-permit semaphore
would queue requests forever inside `poll_ready`, where the timeout does not
apply.

### Anti-Abuse

| Variable | Default | Description |
|----------|---------|-------------|
| `FIRST_DEVICE_POW_DIFFICULTY_BITS` | `18` | Proof-of-work difficulty. Set to `0` to disable |
| `FIRST_DEVICE_ANDROID_ATTESTATION_ENABLED` | `true` | Android hardware attestation |
| `FIRST_DEVICE_APPLE_ATTESTATION_ENABLED` | `false` | Apple App Attest |

### Monitoring

| Variable | Default | Description |
|----------|---------|-------------|
| `METRICS_TOKEN` | *(unset)* | Bearer token for `/metrics`. If unset, metrics are served **only to loopback peers** (localhost / `docker exec`); off-host scrapers get 401. Set a token to scrape remotely. |
| `NODE_EXPORTER_URL` | *(unset)* | URL for node-exporter proxy at `/metrics/node` |

## Private Relay Tips

Running a relay for a single system? Simplify the config:

- `FIRST_DEVICE_POW_DIFFICULTY_BITS=0` — proof-of-work is anti-spam for public relays.
- `FIRST_DEVICE_ANDROID_ATTESTATION_ENABLED=false` — needs Google Play Services.
- `FIRST_DEVICE_APPLE_ATTESTATION_ENABLED=false` — needs Apple infrastructure.

> **Watch out:** The default inactive TTL is 90 days. If you don't use Prism for three
> months, the relay will auto-delete your sync group. Set `SYNC_INACTIVE_TTL_SECS` to
> `31536000` (1 year) or more for a private relay.

Session tokens have a 30-day sliding window (refreshed on every request) and a 90-day
absolute cap measured from the last full re-authentication. If you don't open the app for a
month, or if a token has been alive for 90 days, your device will need to re-pair. Increase
`SESSION_EXPIRY_SECS` and/or `SESSION_MAX_AGE_SECS` for a private relay.

## Kubernetes

Kubernetes manifests are in [kubernetes/](kubernetes/). The relay uses SQLite, so it
runs as a **single-replica StatefulSet**.

```bash
kubectl create namespace prism
kubectl apply -n prism -f self-host/kubernetes/
```

See the [Kubernetes README](kubernetes/README.md) for details on persistent volumes,
secrets, and ingress configuration.

## Raspberry Pi

The relay runs well on a Pi 4+ with 2 GB RAM (ARM64). Tune for low resources:

- `READER_POOL_SIZE=2`
- `MAX_UNPRUNED_BATCHES=1000`
- `MEDIA_QUOTA_BYTES_PER_GROUP=536870912` (512 MB)
- `MEDIA_MAX_FILE_BYTES=5242880` (5 MB)
- Docker memory limit: 256 Mi is plenty for a single sync group

## Backups

The database is a single SQLite file at `DB_PATH`. The simplest backup is
[Litestream](https://litestream.io/), which streams WAL changes to S3-compatible storage:

```yaml
dbs:
  - path: /data/relay.db
    replicas:
      - url: s3://your-bucket/prism-relay
```

For manual backups, use `sqlite3 /data/relay.db ".backup /path/to/backup.db"` rather than
copying the file directly.

Media files live at `MEDIA_STORAGE_PATH` (default `data/media`). Back up this directory
alongside the database. Media is encrypted ciphertext — safe to store on any backup service.

Pair-time snapshot blobs are stored as separate files alongside media, under the
`MEDIA_STORAGE_PATH` parent (`<parent>-snapshots`). Because snapshots are file-backed
rather than stored in the database, **a backup that replicates only SQLite does not
preserve snapshot blobs** — back up the `MEDIA_STORAGE_PATH` tree too, or a restored
relay can hold snapshot rows whose bytes are gone (a client then sees the snapshot as
absent and must re-pair). On startup the relay validates that the snapshot storage root
is an absolute, writable path; if it is not, the relay either refuses to start (when
`SNAPSHOT_FILE_BACKING_ENABLED=true` is set explicitly) or falls back to storing snapshot
bytes inline in SQLite.

## Upgrades and rollback

Schema migrations run automatically on boot and are idempotent, so upgrading is just a
matter of pulling the new image and restarting. Take a backup first regardless.

One migration is not reversible: the relay now stores pair-time snapshots one row per
target device, which rebuilds the `snapshots` table off its old single-key shape. Rolling
the relay binary **back** to a pre-upgrade version after this migration has run keeps
existing snapshots readable (devices still pair and pull), but snapshot **upload** fails on
the old binary until you re-upgrade or restore the database from a pre-upgrade backup. In
practice that means a downgraded relay can serve already-paired devices but cannot complete
new pairings. If you must run an older binary, restore its matching database backup.

File backing adds a second, independent rollback caveat. A binary that predates file
backing does not know about the `blob_ref` column and reads snapshot bytes only from the
inline `data` column. File-backed rows deliberately keep `data` empty (the bytes live in a
file under the snapshot storage root), so a pre-file-backing binary reads such a row as a
**zero-byte envelope** — it cannot return the snapshot, and the pairing client sees an empty
payload rather than a missing one. Legacy inline rows (`blob_ref IS NULL`, written before
file backup was enabled) keep their bytes in `data` and stay readable by both old and new
binaries. Because of this, a downgrade is only clean if every stored snapshot is still an
inline row; if any file-backed rows exist, restore the pre-upgrade database backup to match
the older binary, or re-upgrade. Snapshots are short-lived pair-time bootstrap data, so this
window closes on its own as rows expire, but do not assume a downgraded relay can serve a
snapshot written after the upgrade.

Resumable snapshot uploads add a third, narrower rollback caveat. The `snapshot_uploads`
table is additive and a pre-feature binary ignores it completely, so a downgrade is safe:
the older binary stops advertising the capability, and clients fall back to the existing
single `PUT /snapshot` — there is no schema or wire change for them to misread. Two
consequences:

- Any **in-progress** session is simply abandoned. Its staged bytes are an unreferenced
  file in the snapshot tree; the newer binary's orphan sweep reclaims it once the grace
  period passes, or you can delete the group's snapshot directory after confirming no
  pairing is active. No published snapshot depends on a staged file — a session only
  becomes readable after it publishes through the same snapshot row the single PUT uses.
- Sessions that **completed** before the downgrade are ordinary file-backed snapshot rows,
  so the file-backing caveat above applies to them, not a new one. Re-upgrading is enough
  to keep serving them; the session rows are only bookkeeping and their terminal metadata
  expires on its own.

To be explicit: there is **no** requirement to disable `SNAPSHOT_UPLOAD_ENABLED` before
rolling back, because the flag only ever controls what the running binary advertises. Set it
back to `false` on the old binary's config only if you want to be certain the capability
stays off if you later re-upgrade without review.

## Monitoring

`GET /metrics` returns Prometheus-format metrics. If `METRICS_TOKEN` is set, requests need
an `Authorization: Bearer <token>` header. If it is **unset**, the endpoint fails closed and
is served only to loopback peers (localhost / a sidecar Prometheus / `docker exec`); any
off-host request gets 401. Set a token to scrape `/metrics` from another host.

Key metrics:

- `prism_connected_devices` — active WebSocket connections
- `prism_stored_batches` — undelivered batches (should stay low)
- `prism_db_size_bytes` — database size on disk
- `prism_freelist_pages` — SQLite pages available for reuse after pruning and cleanup
- `prism_last_cleanup_timestamp_seconds` — last cleanup cycle
- `prism_snapshots_missing_blob_total` — published file-backed snapshot rows whose on-disk
  blob was missing or unreadable at read time. A sustained nonzero value means the snapshot
  storage tree and the SQLite rows have diverged (typically a restore that carried the DB but
  not the blob tree) — check your backup coverage.

Resumable snapshot upload metrics (all aggregate — none carry a sync, device, or upload
label):

- `prism_snapshot_upload_sessions_active` — in-progress upload sessions (gauge, refreshed each
  cleanup cycle)
- `prism_snapshot_upload_reserved_bytes` — bytes reserved by those sessions (gauge, refreshed
  each cleanup cycle). Watch this against `SNAPSHOT_UPLOAD_GLOBAL_RESERVED_BYTES` /
  `SNAPSHOT_UPLOAD_GROUP_RESERVED_BYTES`
- `prism_snapshot_upload_chunks_total{result}` — accepted vs. rejected chunk requests
- `prism_snapshot_upload_chunk_bytes_total` — bytes durably committed
- `prism_snapshot_upload_completions_total` — completions that published a snapshot
- `prism_snapshot_upload_quota_rejections_total` — admission/write rejections from a quota or
  free-space bound
- `prism_snapshot_upload_hash_mismatch_total` — completions rejected because the staged bytes
  did not match the create-time SHA-256. **Any nonzero value deserves attention.**
- `prism_snapshot_upload_staging_corrupt_total` — sessions failed for staging corruption
  (missing or short candidate). **Any nonzero value means the DB and blob tree have
  diverged.**
- `prism_snapshot_upload_expired_total` / `prism_snapshot_upload_aborted_total` /
  `prism_snapshot_upload_superseded_total` — sessions ended by TTL, explicit abort, or
  replacement

Alert on: reserved bytes approaching a ceiling, sustained quota rejection, active sessions
growing without completions, and any hash/staging corruption.

### Disk space observability (Phase 0)

File-backed snapshots and media both write under `MEDIA_STORAGE_PATH`, so a full volume now
means failed uploads rather than failed DB writes. Host filesystem metrics are the
observability source: scrape node-exporter's `node_filesystem_avail_bytes` /
`node_filesystem_size_bytes` for the volume backing `/data` (the root compose file already
ships a `node-exporter` service with the host rootfs mounted at `/rootfs`, and
`NODE_EXPORTER_URL` proxies a subset via `/metrics/node`). Alert on that series.

Relay-side **minimum-free-space admission** exists for the resumable snapshot upload path
only, and only when you enable it: `SNAPSHOT_UPLOAD_FREE_SPACE_RESERVE_BYTES` is checked at
session create and again before each chunk write, so a resumable upload is refused rather
than allowed to consume the volume's last bytes. The single `PUT /snapshot` path and the
media path still rely on the host filesystem signals above.

## Connecting the App

In Prism, go to Settings > Sync and enter your relay URL. If you set a registration token,
enter it when prompted. Paired devices receive the URL and token automatically.

## Building from Source

If you'd rather not use Docker:

```bash
git clone https://github.com/prismplural/prism-sync.git
cd prism-sync
cargo build --release -p prism-sync-relay
```

The binary is at `target/release/prism-sync-relay`:

```bash
PORT=8080 DB_PATH=./data/relay.db ./target/release/prism-sync-relay
```
