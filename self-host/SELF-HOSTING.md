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
| `REVOKE_RATE_LIMIT` | `2` | Max device revocations per group per window |
| `REVOKE_RATE_WINDOW_SECS` | `3600` | Revocation rate limit window |

### Maintenance

| Variable | Default | Description |
|----------|---------|-------------|
| `CLEANUP_INTERVAL_SECS` | `3600` | Background cleanup frequency |
| `SYNC_INACTIVE_TTL_SECS` | `7776000` | Auto-prune inactive groups (default: 90 days) |
| `STALE_DEVICE_SECS` | `2592000` | Mark devices stale after inactivity (30 days) |
| `SESSION_EXPIRY_SECS` | `2592000` | Session token lifetime (30 days) |
| `MAX_UNPRUNED_BATCHES` | `10000` | Max undelivered batches before rejecting pushes |
| `SNAPSHOT_DEFAULT_TTL_SECS` | `86400` | Ephemeral snapshot retention (24 hours) |

### Media Storage

| Variable | Default | Description |
|----------|---------|-------------|
| `MEDIA_STORAGE_PATH` | `data/media` | Directory for uploaded media |
| `MEDIA_MAX_FILE_BYTES` | `10485760` | Maximum size per upload (10 MB) |
| `MEDIA_QUOTA_BYTES_PER_GROUP` | `1073741824` | Total media per sync group (1 GB) |
| `MEDIA_RETENTION_DAYS` | `90` | Days before unreferenced media is cleaned up |

### Anti-Abuse

| Variable | Default | Description |
|----------|---------|-------------|
| `FIRST_DEVICE_POW_DIFFICULTY_BITS` | `18` | Proof-of-work difficulty. Set to `0` to disable |
| `FIRST_DEVICE_ANDROID_ATTESTATION_ENABLED` | `true` | Android hardware attestation |
| `FIRST_DEVICE_APPLE_ATTESTATION_ENABLED` | `false` | Apple App Attest |

### Monitoring

| Variable | Default | Description |
|----------|---------|-------------|
| `METRICS_TOKEN` | *(unset)* | Bearer token for `/metrics`. If unset, metrics are open |

## Private Relay Tips

Running a relay for a single system? Simplify the config:

- `FIRST_DEVICE_POW_DIFFICULTY_BITS=0` — proof-of-work is anti-spam for public relays.
- `FIRST_DEVICE_ANDROID_ATTESTATION_ENABLED=false` — needs Google Play Services.
- `FIRST_DEVICE_APPLE_ATTESTATION_ENABLED=false` — needs Apple infrastructure.

> **Watch out:** The default inactive TTL is 90 days. If you don't use Prism for three
> months, the relay will auto-delete your sync group. Set `SYNC_INACTIVE_TTL_SECS` to
> `31536000` (1 year) or more for a private relay.

Session tokens last 30 days by default. If you don't open the app for a month, your device
will need to re-pair. Increase `SESSION_EXPIRY_SECS` for a private relay.

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

## Monitoring

`GET /metrics` returns Prometheus-format metrics. If `METRICS_TOKEN` is set, requests need
an `Authorization: Bearer <token>` header.

Key metrics:

- `prism_connected_devices` — active WebSocket connections
- `prism_stored_batches` — undelivered batches (should stay low)
- `prism_db_size_bytes` — database size on disk
- `prism_last_cleanup_timestamp_seconds` — last cleanup cycle

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
