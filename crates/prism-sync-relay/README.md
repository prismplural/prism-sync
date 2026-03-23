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
| SESSION_EXPIRY_SECS | 2592000 | Session token expiry (30 days) |
| NONCE_EXPIRY_SECS | 60 | Registration nonce expiry |
| STALE_DEVICE_SECS | 2592000 | Stale device threshold (30 days) |
| SYNC_INACTIVE_TTL_SECS | 7776000 | Auto-revoke threshold (90 days) |
| CLEANUP_INTERVAL_SECS | 3600 | Background cleanup interval |
| MAX_UNPRUNED_BATCHES | 10000 | Max batches before rejecting push |
| METRICS_TOKEN | (none) | Optional bearer token for /metrics |
| RUST_LOG | info | Tracing log level |

## API Endpoints

### Registration
- `GET /v2/sync/{sync_id}/register-nonce` — Get one-time registration nonce
- `POST /v2/sync/{sync_id}/register` — Register device (challenge-response)

### Sync
- `PUT /v2/sync/{sync_id}/changes` — Push signed batch envelope
- `GET /v2/sync/{sync_id}/changes?since=N&limit=100` — Pull batches (paginated)
- `GET /v2/sync/{sync_id}/snapshot` — Download snapshot
- `PUT /v2/sync/{sync_id}/snapshot` — Upload snapshot

### Devices
- `GET /v2/sync/{sync_id}/devices` — List devices with public keys
- `DELETE /v2/sync/{sync_id}/devices/{device_id}` — Revoke or deregister
- `POST /v2/sync/{sync_id}/rekey` — Post epoch rotation artifacts
- `GET /v2/sync/{sync_id}/rekey/{epoch}/{device_id}` — Get wrapped epoch key
- `POST /v2/sync/{sync_id}/ack` — Acknowledge receipt

### WebSocket
- `GET /v2/sync/{sync_id}/ws` — WebSocket (message-based auth after connect)

### Operations
- `GET /health` — Health check
- `GET /metrics` — Prometheus metrics

## Security

The relay is zero-knowledge — it stores encrypted blobs and never reads plaintext data. Authentication uses per-device session tokens issued via Ed25519 challenge-response.
