use rusqlite::{params, params_from_iter, Connection, OptionalExtension, ToSql};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Data structs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct DeviceRecord {
    pub device_id: String,
    pub signing_public_key: Vec<u8>,
    pub x25519_public_key: Vec<u8>,
    pub ml_dsa_65_public_key: Vec<u8>,
    pub ml_kem_768_public_key: Vec<u8>,
    pub x_wing_public_key: Vec<u8>,
    pub epoch: i64,
    pub status: String,
    pub last_seen_at: i64,
    pub ml_dsa_key_generation: i64,
    pub prev_ml_dsa_65_public_key: Vec<u8>,
    pub prev_ml_dsa_65_expires_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct DeviceListEntry {
    pub device_id: String,
    pub signing_public_key: Vec<u8>,
    pub x25519_public_key: Vec<u8>,
    pub ml_dsa_65_public_key: Vec<u8>,
    pub ml_kem_768_public_key: Vec<u8>,
    pub x_wing_public_key: Vec<u8>,
    pub epoch: i64,
    pub status: String,
    pub ml_dsa_key_generation: i64,
}

#[derive(Debug, Clone)]
pub struct BatchEntry {
    pub server_seq: i64,
    pub sender_device_id: String,
    pub batch_id: String,
    pub epoch: i64,
    pub data: Vec<u8>,
    pub received_at: i64,
}

#[derive(Debug, Clone)]
pub struct SnapshotRecord {
    pub data: Vec<u8>,
    pub epoch: i64,
    pub server_seq_at: i64,
    pub target_device_id: Option<String>,
    pub uploaded_by_device_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RegistryStateRecord {
    pub sync_id: String,
    pub registry_version: i64,
    pub registry_hash: String,
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct PendingSharingInit {
    pub init_id: String,
    pub sender_id: String,
    pub payload: Vec<u8>,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct RegistryArtifactRecord {
    pub sync_id: String,
    pub registry_version: i64,
    pub artifact_kind: String,
    pub artifact_hash: String,
    pub artifact_blob: Vec<u8>,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct MediaRow {
    pub media_id: String,
    pub sync_id: String,
    pub device_id: String,
    pub size_bytes: i64,
    pub content_hash: String,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub deleted_at: Option<i64>,
    /// Set once the staged file has been promoted to its final path. A row with
    /// `committed_at IS NULL` is a non-servable PENDING reserve.
    pub committed_at: Option<i64>,
    /// When the PENDING reserve was taken. Used by the stale-pending reaper to
    /// reclaim abandoned reserves; `NULL` marks a legacy pre-lifecycle row.
    pub reserved_at: Option<i64>,
}

impl MediaRow {
    /// Metadata-level servable predicate (everything but on-disk file presence):
    /// committed, not soft-deleted, and not past its TTL. Shared by download,
    /// quota accounting, and (later) batch-exists so they agree on "available."
    pub fn is_servable_at(&self, now: i64) -> bool {
        self.committed_at.is_some()
            && self.deleted_at.is_none()
            && self.expires_at.map(|exp| exp > now).unwrap_or(true)
    }

    /// True for an in-flight reserve: a row written by `reserve` whose file has
    /// not been promoted yet. Such rows count toward quota but are never served.
    pub fn is_pending(&self) -> bool {
        self.committed_at.is_none() && self.deleted_at.is_none()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Current unix timestamp in seconds.
pub fn now_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

/// Generate a cryptographically random hex token (32 bytes = 64 hex chars).
fn generate_session_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// SHA-256 hash of a token string, returned as hex.
fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

fn hash_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// Database wrapper
// ---------------------------------------------------------------------------

pub struct Database {
    writer: Mutex<Connection>,
    readers: Vec<Mutex<Connection>>,
    next_reader: AtomicUsize,
}

impl Database {
    /// Open a persistent database at the given path.
    pub fn open(path: &str, reader_count: usize) -> Result<Self, rusqlite::Error> {
        if let Some(parent) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let conn = Connection::open(path)?;
        apply_pragmas(&conn)?;
        migrate(&conn)?;

        let readers = (0..reader_count)
            .map(|_| {
                let c = Connection::open(path)?;
                apply_read_pragmas(&c)?;
                Ok(Mutex::new(c))
            })
            .collect::<Result<Vec<_>, rusqlite::Error>>()?;

        Ok(Self { writer: Mutex::new(conn), readers, next_reader: AtomicUsize::new(0) })
    }

    /// Open a database for testing, backed by a temp file so multiple
    /// connections can share the same WAL.
    pub fn in_memory() -> Result<Self, rusqlite::Error> {
        let path =
            std::env::temp_dir().join(format!("prism_relay_test_{}.db", uuid::Uuid::new_v4()));
        Self::open(path.to_str().unwrap(), 2)
    }

    /// Run a blocking DB operation on the writer connection.
    /// For async contexts, wrap calls in `tokio::task::spawn_blocking`.
    pub fn with_conn<F, T>(&self, f: F) -> Result<T, rusqlite::Error>
    where
        F: FnOnce(&Connection) -> Result<T, rusqlite::Error>,
    {
        let conn = self.writer.lock().expect("writer mutex poisoned");
        f(&conn)
    }

    /// Run a read-only DB operation using a connection from the reader pool.
    /// For async contexts, wrap calls in `tokio::task::spawn_blocking`.
    pub fn with_read_conn<F, T>(&self, f: F) -> Result<T, rusqlite::Error>
    where
        F: FnOnce(&Connection) -> Result<T, rusqlite::Error>,
    {
        let idx = self.next_reader.fetch_add(1, Ordering::Relaxed) % self.readers.len();
        let conn = self.readers[idx].lock().expect("reader mutex poisoned");
        f(&conn)
    }
}

// ---------------------------------------------------------------------------
// Pragmas & migration
// ---------------------------------------------------------------------------

fn apply_pragmas(conn: &Connection) -> Result<(), rusqlite::Error> {
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA busy_timeout = 5000;
         PRAGMA foreign_keys = ON;
         PRAGMA temp_store = memory;
         PRAGMA mmap_size = 268435456;
         PRAGMA cache_size = -65536;
         PRAGMA auto_vacuum = INCREMENTAL;
         PRAGMA cell_size_check = ON;
         PRAGMA wal_autocheckpoint = 1000;
         PRAGMA journal_size_limit = 67108864;",
    )?;

    // auto_vacuum mode can only change on a newly created database. If the DB
    // was created with auto_vacuum=NONE (the default), the pragma above is
    // silently ignored and incremental_vacuum becomes a no-op. A one-time full
    // VACUUM converts the file to INCREMENTAL mode so future cleanup cycles
    // can reclaim freelist pages incrementally.
    let current_mode: i64 = conn.query_row("PRAGMA auto_vacuum;", [], |r| r.get(0)).unwrap_or(0);
    if current_mode != 2 {
        // 0 = NONE, 1 = FULL, 2 = INCREMENTAL
        tracing::warn!(
            current_mode,
            "auto_vacuum not INCREMENTAL — running one-time VACUUM to convert"
        );
        conn.execute_batch("VACUUM;")?;
    }

    Ok(())
}

fn apply_read_pragmas(conn: &Connection) -> Result<(), rusqlite::Error> {
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA busy_timeout = 5000;
         PRAGMA foreign_keys = ON;
         PRAGMA temp_store = memory;
         PRAGMA mmap_size = 268435456;
         PRAGMA cache_size = -65536;
         PRAGMA query_only = ON;
         PRAGMA cell_size_check = ON;
         PRAGMA wal_autocheckpoint = 1000;
         PRAGMA journal_size_limit = 67108864;",
    )?;
    Ok(())
}

fn migrate(conn: &Connection) -> Result<(), rusqlite::Error> {
    conn.execute_batch(
        "
        -- Sync groups
        CREATE TABLE IF NOT EXISTS sync_groups (
            sync_id           TEXT PRIMARY KEY,
            current_epoch     INTEGER NOT NULL DEFAULT 0,
            needs_rekey       INTEGER NOT NULL DEFAULT 0,
            password_version  INTEGER NOT NULL DEFAULT 0,
            pruned_floor_seq  INTEGER NOT NULL DEFAULT 0,
            created_at        INTEGER NOT NULL,
            updated_at        INTEGER NOT NULL
        );

        -- Registry state (current version/hash only; latest artifacts stored separately)
        CREATE TABLE IF NOT EXISTS registry_states (
            sync_id            TEXT PRIMARY KEY,
            registry_version   INTEGER NOT NULL DEFAULT 0,
            registry_hash      TEXT NOT NULL DEFAULT '',
            created_at         INTEGER NOT NULL,
            updated_at         INTEGER NOT NULL,
            FOREIGN KEY (sync_id) REFERENCES sync_groups(sync_id)
        );
        CREATE TABLE IF NOT EXISTS registry_state_artifacts (
            sync_id            TEXT NOT NULL,
            registry_version   INTEGER NOT NULL,
            artifact_kind      TEXT NOT NULL,
            artifact_hash      TEXT NOT NULL,
            artifact_blob      BLOB NOT NULL,
            created_at         INTEGER NOT NULL,
            PRIMARY KEY (sync_id, registry_version),
            FOREIGN KEY (sync_id) REFERENCES sync_groups(sync_id)
        );
        CREATE INDEX IF NOT EXISTS idx_registry_state_artifacts_sync_version
            ON registry_state_artifacts(sync_id, registry_version DESC);

        -- Devices
        CREATE TABLE IF NOT EXISTS devices (
            sync_id             TEXT NOT NULL,
            device_id           TEXT NOT NULL,
            signing_public_key  BLOB NOT NULL,
            x25519_public_key   BLOB NOT NULL,
            ml_dsa_65_public_key BLOB NOT NULL DEFAULT X'',
            ml_kem_768_public_key BLOB NOT NULL DEFAULT X'',
            epoch               INTEGER NOT NULL DEFAULT 0,
            status              TEXT NOT NULL DEFAULT 'active',
            registered_at       INTEGER NOT NULL,
            last_seen_at        INTEGER NOT NULL,
            revoked_at          INTEGER,
            remote_wipe         INTEGER NOT NULL DEFAULT 0,
            ml_dsa_key_generation INTEGER NOT NULL DEFAULT 0,
            prev_ml_dsa_65_public_key BLOB NOT NULL DEFAULT X'',
            prev_ml_dsa_65_expires_at INTEGER,
            PRIMARY KEY (sync_id, device_id),
            FOREIGN KEY (sync_id) REFERENCES sync_groups(sync_id)
        );
        CREATE INDEX IF NOT EXISTS idx_devices_sync_status
            ON devices(sync_id, status);

        -- Device sessions
        CREATE TABLE IF NOT EXISTS device_sessions (
            sync_id             TEXT NOT NULL,
            device_id           TEXT NOT NULL,
            session_token_hash  TEXT NOT NULL UNIQUE,
            created_at          INTEGER NOT NULL,
            last_active_at      INTEGER NOT NULL,
            expires_at          INTEGER NOT NULL,
            PRIMARY KEY (sync_id, device_id),
            FOREIGN KEY (sync_id, device_id) REFERENCES devices(sync_id, device_id)
        );
        CREATE TABLE IF NOT EXISTS revoked_device_sessions (
            sync_id             TEXT NOT NULL,
            device_id           TEXT NOT NULL,
            session_token_hash  TEXT NOT NULL UNIQUE,
            revoked_at          INTEGER NOT NULL,
            expires_at          INTEGER NOT NULL,
            PRIMARY KEY (sync_id, device_id, session_token_hash),
            FOREIGN KEY (sync_id, device_id) REFERENCES devices(sync_id, device_id)
        );
        CREATE INDEX IF NOT EXISTS idx_revoked_device_sessions_expires
            ON revoked_device_sessions(expires_at);

        -- Registration nonces
        CREATE TABLE IF NOT EXISTS registration_nonces (
            nonce       TEXT PRIMARY KEY,
            sync_id     TEXT NOT NULL,
            created_at  INTEGER NOT NULL,
            expires_at  INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_nonces_expires
            ON registration_nonces(expires_at);

        -- Signed request replay cache
        CREATE TABLE IF NOT EXISTS signed_request_nonces (
            device_id   TEXT NOT NULL,
            nonce       TEXT NOT NULL,
            expires_at  INTEGER NOT NULL,
            PRIMARY KEY (device_id, nonce)
        );
        CREATE INDEX IF NOT EXISTS idx_signed_request_nonces_expires
            ON signed_request_nonces(expires_at);

        -- Device receipts (tracks each device's last acknowledged server_seq)
        CREATE TABLE IF NOT EXISTS device_receipts (
            sync_id         TEXT NOT NULL,
            device_id       TEXT NOT NULL,
            last_acked_seq  INTEGER NOT NULL DEFAULT 0,
            updated_at      INTEGER NOT NULL,
            PRIMARY KEY (sync_id, device_id),
            FOREIGN KEY (sync_id, device_id) REFERENCES devices(sync_id, device_id)
        );
        CREATE INDEX IF NOT EXISTS idx_device_receipts_sync
            ON device_receipts(sync_id);

        -- Batches (encrypted CRDT ops)
        CREATE TABLE IF NOT EXISTS batches (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            sync_id             TEXT NOT NULL,
            epoch               INTEGER NOT NULL,
            sender_device_id    TEXT NOT NULL,
            batch_id            TEXT NOT NULL,
            data                BLOB NOT NULL,
            received_at         INTEGER NOT NULL,
            FOREIGN KEY (sync_id) REFERENCES sync_groups(sync_id)
        );
        CREATE INDEX IF NOT EXISTS idx_batches_sync_seq
            ON batches(sync_id, id);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_batches_dedup
            ON batches(sync_id, sender_device_id, batch_id);

        -- Snapshots (one per sync group, with optional TTL for ephemeral snapshots)
        CREATE TABLE IF NOT EXISTS snapshots (
            sync_id                 TEXT PRIMARY KEY,
            epoch                   INTEGER NOT NULL,
            server_seq_at           INTEGER NOT NULL DEFAULT 0,
            data                    BLOB NOT NULL,
            created_at              INTEGER NOT NULL,
            expires_at              INTEGER,
            target_device_id        TEXT,
            uploaded_by_device_id   TEXT,
            FOREIGN KEY (sync_id) REFERENCES sync_groups(sync_id)
        );

        -- Rekey artifacts (per-device wrapped epoch keys)
        CREATE TABLE IF NOT EXISTS rekey_artifacts (
            sync_id             TEXT NOT NULL,
            epoch               INTEGER NOT NULL,
            target_device_id    TEXT NOT NULL,
            wrapped_key         BLOB NOT NULL,
            created_at          INTEGER NOT NULL,
            PRIMARY KEY (sync_id, epoch, target_device_id),
            FOREIGN KEY (sync_id) REFERENCES sync_groups(sync_id)
        );

        -- Audit: revocation events
        CREATE TABLE IF NOT EXISTS revocation_events (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            sync_id             TEXT NOT NULL,
            revoker_device_id   TEXT NOT NULL,
            target_device_id    TEXT NOT NULL,
            new_epoch           INTEGER NOT NULL,
            remote_wipe         INTEGER NOT NULL DEFAULT 0,
            created_at          INTEGER NOT NULL,
            FOREIGN KEY (sync_id) REFERENCES sync_groups(sync_id)
        );
        CREATE INDEX IF NOT EXISTS idx_revocation_events_sync
            ON revocation_events(sync_id, created_at);

        -- Audit: standalone epoch rotations
        CREATE TABLE IF NOT EXISTS rekey_events (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            sync_id             TEXT NOT NULL,
            rekeyer_device_id   TEXT NOT NULL,
            new_epoch           INTEGER NOT NULL,
            created_at          INTEGER NOT NULL,
            FOREIGN KEY (sync_id) REFERENCES sync_groups(sync_id)
        );
        CREATE INDEX IF NOT EXISTS idx_rekey_events_sync
            ON rekey_events(sync_id, created_at);

        -- Password-change artifacts (per-device wrapped blobs, versioned)
        CREATE TABLE IF NOT EXISTS password_change_artifacts (
            sync_id          TEXT NOT NULL,
            version          INTEGER NOT NULL,
            target_device_id TEXT NOT NULL,
            wrapped_blob     BLOB NOT NULL,
            PRIMARY KEY (sync_id, version, target_device_id)
        );

        -- Pairing sessions (PQ hybrid device pairing ceremony)
        CREATE TABLE IF NOT EXISTS pairing_sessions (
            rendezvous_id       TEXT PRIMARY KEY,
            joiner_bootstrap    BLOB,
            pairing_init        BLOB,
            joiner_confirmation BLOB,
            credential_bundle   BLOB,
            joiner_bundle       BLOB,
            credential_bundle_consumed_at INTEGER,
            joiner_bundle_consumed_at     INTEGER,
            created_at          INTEGER NOT NULL,
            expires_at          INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_pairing_sessions_expires
            ON pairing_sessions(expires_at);

        -- Sharing identity bundles (post-quantum sharing bootstrap)
        CREATE TABLE IF NOT EXISTS sharing_identity_bundles (
            sharing_id            TEXT PRIMARY KEY,
            identity_bundle       BLOB NOT NULL,
            identity_generation   INTEGER NOT NULL DEFAULT 0,
            updated_at            INTEGER NOT NULL
        );

        -- Persistent relay-side high-water marks for sharing identity generations.
        -- These survive identity deletion so disable/re-enable cannot roll back
        -- generation for a stable sharing_id.
        CREATE TABLE IF NOT EXISTS sharing_identity_generation_floors (
            sharing_id               TEXT PRIMARY KEY,
            max_identity_generation  INTEGER NOT NULL DEFAULT 0,
            identity_bundle_hash     TEXT,
            updated_at               INTEGER NOT NULL
        );

        -- Sharing signed prekeys
        CREATE TABLE IF NOT EXISTS sharing_signed_prekeys (
            sharing_id    TEXT NOT NULL,
            device_id     TEXT NOT NULL,
            prekey_id     TEXT NOT NULL,
            prekey_bundle BLOB NOT NULL,
            created_at    INTEGER NOT NULL,
            PRIMARY KEY (sharing_id, device_id)
        );
        CREATE INDEX IF NOT EXISTS idx_sharing_prekeys_created
            ON sharing_signed_prekeys(sharing_id, created_at DESC);

        -- Sharing-init payloads (ephemeral key exchange messages)
        CREATE TABLE IF NOT EXISTS sharing_init_payloads (
            init_id          TEXT PRIMARY KEY,
            recipient_id     TEXT NOT NULL,
            sender_id        TEXT NOT NULL,
            payload          BLOB NOT NULL,
            created_at       INTEGER NOT NULL,
            consumed_at      INTEGER,
            expires_at       INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_sharing_init_recipient
            ON sharing_init_payloads(recipient_id, consumed_at);
        CREATE INDEX IF NOT EXISTS idx_sharing_init_expires
            ON sharing_init_payloads(expires_at);

        -- Sharing ID mappings (one-to-one binding between sync_id and sharing_id)
        CREATE TABLE IF NOT EXISTS sharing_id_mappings (
            sync_id     TEXT NOT NULL,
            sharing_id  TEXT NOT NULL,
            PRIMARY KEY (sync_id)
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_sharing_id_map_unique_sharing
            ON sharing_id_mappings(sharing_id);

        -- Media blob metadata
        -- Upload lifecycle: a row is PENDING while its
        -- staged file is being promoted (`committed_at IS NULL AND reserved_at`
        -- set) and COMMITTED (servable) once `committed_at` is set. `reserved_at`
        -- distinguishes a genuine in-flight reserve from a legacy pre-lifecycle
        -- row (which has `reserved_at IS NULL` and is backfilled committed).
        CREATE TABLE IF NOT EXISTS media_metadata (
            media_id      TEXT NOT NULL,
            sync_id       TEXT NOT NULL,
            device_id     TEXT NOT NULL,
            size_bytes    INTEGER NOT NULL,
            content_hash  TEXT NOT NULL,
            created_at    INTEGER NOT NULL,
            expires_at    INTEGER,
            deleted_at    INTEGER,
            committed_at  INTEGER,
            reserved_at   INTEGER,
            PRIMARY KEY (sync_id, media_id),
            FOREIGN KEY (sync_id) REFERENCES sync_groups(sync_id)
        );
        CREATE INDEX IF NOT EXISTS idx_media_sync_id ON media_metadata(sync_id);
        CREATE INDEX IF NOT EXISTS idx_media_expires ON media_metadata(expires_at) WHERE expires_at IS NOT NULL;

        -- Ephemeral signal lane: a relay-blind
        -- store-and-forward mailbox. A sender posts a small fixed-size opaque
        -- `payload` (kind + media_id live encrypted under the group epoch key);
        -- recipients drain it on their next sync. `recipient_device_id IS NULL`
        -- is a group broadcast. `message_id` is an HMAC-of-the-epoch-key dedup
        -- key, so the composite PRIMARY KEY coalesces in-window duplicates
        -- (INSERT OR IGNORE) without the relay being able to correlate it to a
        -- media_id. `epoch_id` is the only cleartext crypto hint (recipient key
        -- selection). Short TTL (`expires_at`) bounds staleness; the cleanup
        -- sweep sheds expired + fully-acked rows.
        CREATE TABLE IF NOT EXISTS device_messages (
            sync_id              TEXT NOT NULL,
            message_id           TEXT NOT NULL,
            sender_device_id     TEXT NOT NULL,
            recipient_device_id  TEXT,
            epoch_id             INTEGER NOT NULL,
            payload              BLOB NOT NULL,
            created_at           INTEGER NOT NULL,
            expires_at           INTEGER NOT NULL,
            PRIMARY KEY (sync_id, message_id),
            FOREIGN KEY (sync_id) REFERENCES sync_groups(sync_id)
        );
        -- Pending fetch: scoped to a group, filtered by recipient/broadcast and
        -- TTL.
        CREATE INDEX IF NOT EXISTS idx_device_messages_recipient
            ON device_messages(sync_id, recipient_device_id, expires_at);
        -- Per-sender pending-count cap.
        CREATE INDEX IF NOT EXISTS idx_device_messages_sender
            ON device_messages(sync_id, sender_device_id, expires_at);
        -- Cleanup sweep by TTL.
        CREATE INDEX IF NOT EXISTS idx_device_messages_expires
            ON device_messages(expires_at);

        -- Per-device acknowledgements for the mailbox above. A separate ack row
        -- per device (composite PK) means one device acking a message can never
        -- hide it from the other recipients of a broadcast — the GET-pending
        -- filter only suppresses a message for the *acking* device.
        CREATE TABLE IF NOT EXISTS device_message_acks (
            sync_id      TEXT NOT NULL,
            message_id   TEXT NOT NULL,
            device_id    TEXT NOT NULL,
            acked_at     INTEGER NOT NULL,
            PRIMARY KEY (sync_id, message_id, device_id)
        );
        ",
    )?;

    // -- Counters (persistent metrics that survive restarts) --
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS counters (
            name    TEXT PRIMARY KEY,
            value   INTEGER NOT NULL DEFAULT 0
        );",
    )?;

    // -- Incremental migrations for existing databases --
    // ALTER TABLE ADD COLUMN is a no-op if the table was freshly created above
    // with the columns already present. For pre-existing tables we need to add them.
    migrate_snapshots_ephemeral(conn)?;
    migrate_devices_remote_wipe(conn)?;
    migrate_devices_pq_columns(conn)?;
    migrate_devices_xwing_column(conn)?;
    migrate_sharing_identity_generation(conn)?;
    migrate_sharing_identity_generation_floors(conn)?;
    migrate_sync_groups_password_version(conn)?;
    migrate_sync_groups_pruned_floor_seq(conn)?;
    migrate_devices_ml_dsa_rotation(conn)?;
    migrate_pairing_session_consumed_columns(conn)?;
    migrate_media_lifecycle_columns(conn)?;
    migrate_media_metadata_sync_scoped_key(conn)?;

    Ok(())
}

/// Add the upload-lifecycle columns (`committed_at`, `reserved_at`) to an
/// existing `media_metadata` table and the per-group expired-sweep index.
///
/// Pre-lifecycle relays stored media as "metadata then file" with no notion of
/// a pending reserve, so every legacy row is effectively committed. When the
/// columns are first added we backfill `committed_at = created_at` for all
/// existing rows in a **single set-based UPDATE** inside the migration
/// transaction — never a per-row loop — so a crash mid-migration can't leave
/// legacy media half-unservable. The backfill runs only on the one-time
/// transition (guarded on the column being absent); afterwards genuine
/// new-lifecycle PENDING rows (which carry `reserved_at`) are never touched.
fn migrate_media_lifecycle_columns(conn: &Connection) -> Result<(), rusqlite::Error> {
    let has_committed_at = media_metadata_has_column(conn, "committed_at")?;
    let has_reserved_at = media_metadata_has_column(conn, "reserved_at")?;

    if !has_committed_at || !has_reserved_at {
        // Column-add(s) + legacy backfill must be ONE atomic unit: if the
        // ALTER committed but the backfill didn't (crash in between), the next
        // startup would see `committed_at` already present, skip the backfill,
        // and leave every legacy row `committed_at IS NULL` → permanently
        // unservable. Wrapping them in a single transaction makes it all-or-
        // nothing, so a retried migration always backfills.
        let tx = conn.unchecked_transaction()?;
        if !has_committed_at {
            tx.execute_batch("ALTER TABLE media_metadata ADD COLUMN committed_at INTEGER;")?;
        }
        if !has_reserved_at {
            tx.execute_batch("ALTER TABLE media_metadata ADD COLUMN reserved_at INTEGER;")?;
        }
        if !has_committed_at {
            // Backfill legacy rows exactly once. At this transition no
            // new-lifecycle PENDING rows can exist yet, so this set-based
            // UPDATE only ever promotes genuine pre-lifecycle media.
            tx.execute(
                "UPDATE media_metadata SET committed_at = created_at WHERE committed_at IS NULL",
                [],
            )?;
        }
        tx.commit()?;
    }

    // Composite partial index for the per-upload, sync-scoped expired sweep.
    // `idx_media_expires(expires_at)` alone doesn't match the `sync_id`-scoped
    // query.
    conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_media_sync_expires
             ON media_metadata (sync_id, expires_at) WHERE expires_at IS NOT NULL;",
    )?;

    Ok(())
}

fn media_metadata_has_column(conn: &Connection, column: &str) -> Result<bool, rusqlite::Error> {
    let mut stmt = conn.prepare("PRAGMA table_info(media_metadata)")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
    for row in rows {
        if row? == column {
            return Ok(true);
        }
    }
    Ok(false)
}

fn migrate_media_metadata_sync_scoped_key(conn: &Connection) -> Result<(), rusqlite::Error> {
    if media_metadata_has_sync_scoped_key(conn)? {
        ensure_media_metadata_indexes(conn)?;
        return Ok(());
    }

    let tx = conn.unchecked_transaction()?;
    tx.execute_batch(
        "ALTER TABLE media_metadata RENAME TO media_metadata_old;
         CREATE TABLE media_metadata (
            media_id      TEXT NOT NULL,
            sync_id       TEXT NOT NULL,
            device_id     TEXT NOT NULL,
            size_bytes    INTEGER NOT NULL,
            content_hash  TEXT NOT NULL,
            created_at    INTEGER NOT NULL,
            expires_at    INTEGER,
            deleted_at    INTEGER,
            committed_at  INTEGER,
            reserved_at   INTEGER,
            PRIMARY KEY (sync_id, media_id),
            FOREIGN KEY (sync_id) REFERENCES sync_groups(sync_id)
         );
         INSERT INTO media_metadata
            (media_id, sync_id, device_id, size_bytes, content_hash,
             created_at, expires_at, deleted_at, committed_at, reserved_at)
         SELECT media_id, sync_id, device_id, size_bytes, content_hash,
                created_at, expires_at, deleted_at, committed_at, reserved_at
           FROM media_metadata_old;
         DROP TABLE media_metadata_old;",
    )?;
    tx.commit()?;

    ensure_media_metadata_indexes(conn)?;
    Ok(())
}

fn media_metadata_has_sync_scoped_key(conn: &Connection) -> Result<bool, rusqlite::Error> {
    let mut stmt = conn.prepare("PRAGMA table_info(media_metadata)")?;
    let rows = stmt.query_map([], |row| Ok((row.get::<_, String>(1)?, row.get::<_, i64>(5)?)))?;
    let mut sync_pk = None;
    let mut media_pk = None;
    for row in rows {
        let (name, pk) = row?;
        match name.as_str() {
            "sync_id" => sync_pk = Some(pk),
            "media_id" => media_pk = Some(pk),
            _ => {}
        }
    }
    Ok(sync_pk == Some(1) && media_pk == Some(2))
}

fn ensure_media_metadata_indexes(conn: &Connection) -> Result<(), rusqlite::Error> {
    conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_media_sync_id ON media_metadata(sync_id);
         CREATE INDEX IF NOT EXISTS idx_media_expires
             ON media_metadata(expires_at) WHERE expires_at IS NOT NULL;
         CREATE INDEX IF NOT EXISTS idx_media_sync_expires
             ON media_metadata (sync_id, expires_at) WHERE expires_at IS NOT NULL;",
    )?;
    Ok(())
}

/// Add ephemeral snapshot columns to an existing `snapshots` table.
/// Safe to call repeatedly — checks for column existence first.
fn migrate_snapshots_ephemeral(conn: &Connection) -> Result<(), rusqlite::Error> {
    let has_expires_at = snapshot_has_column(conn, "expires_at")?;
    let has_target_device_id = snapshot_has_column(conn, "target_device_id")?;
    let has_uploaded_by_device_id = snapshot_has_column(conn, "uploaded_by_device_id")?;

    let mut alter_statements = Vec::new();
    if !has_expires_at {
        alter_statements.push("ALTER TABLE snapshots ADD COLUMN expires_at INTEGER;");
    }
    if !has_target_device_id {
        alter_statements.push("ALTER TABLE snapshots ADD COLUMN target_device_id TEXT;");
    }
    if !has_uploaded_by_device_id {
        alter_statements.push("ALTER TABLE snapshots ADD COLUMN uploaded_by_device_id TEXT;");
    }
    if !alter_statements.is_empty() {
        conn.execute_batch(&alter_statements.join("\n"))?;
    }

    conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_snapshots_expires_at
             ON snapshots (expires_at) WHERE expires_at IS NOT NULL;",
    )?;

    Ok(())
}

/// Add remote_wipe column to an existing `devices` table.
/// Safe to call repeatedly — checks for column existence first.
fn migrate_devices_remote_wipe(conn: &Connection) -> Result<(), rusqlite::Error> {
    let has_remote_wipe = device_has_column(conn, "remote_wipe")?;
    if !has_remote_wipe {
        conn.execute_batch(
            "ALTER TABLE devices ADD COLUMN remote_wipe INTEGER NOT NULL DEFAULT 0;",
        )?;
    }
    Ok(())
}

fn migrate_devices_pq_columns(conn: &Connection) -> Result<(), rusqlite::Error> {
    let has_ml_dsa = device_has_column(conn, "ml_dsa_65_public_key")?;
    let has_ml_kem = device_has_column(conn, "ml_kem_768_public_key")?;

    if !has_ml_dsa {
        conn.execute_batch(
            "ALTER TABLE devices ADD COLUMN ml_dsa_65_public_key BLOB NOT NULL DEFAULT X'';",
        )?;
    }
    if !has_ml_kem {
        conn.execute_batch(
            "ALTER TABLE devices ADD COLUMN ml_kem_768_public_key BLOB NOT NULL DEFAULT X'';",
        )?;
    }

    Ok(())
}

fn migrate_devices_xwing_column(conn: &Connection) -> Result<(), rusqlite::Error> {
    let has_xwing = device_has_column(conn, "x_wing_public_key")?;
    if !has_xwing {
        conn.execute_batch(
            "ALTER TABLE devices ADD COLUMN x_wing_public_key BLOB NOT NULL DEFAULT X'';",
        )?;
    }
    Ok(())
}

fn device_has_column(conn: &Connection, column: &str) -> Result<bool, rusqlite::Error> {
    let mut stmt = conn.prepare("PRAGMA table_info(devices)")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
    for row in rows {
        if row? == column {
            return Ok(true);
        }
    }
    Ok(false)
}

fn snapshot_has_column(conn: &Connection, column: &str) -> Result<bool, rusqlite::Error> {
    let mut stmt = conn.prepare("PRAGMA table_info(snapshots)")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
    for row in rows {
        if row? == column {
            return Ok(true);
        }
    }
    Ok(false)
}

fn sync_group_has_column(conn: &Connection, column: &str) -> Result<bool, rusqlite::Error> {
    let mut stmt = conn.prepare("PRAGMA table_info(sync_groups)")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
    for row in rows {
        if row? == column {
            return Ok(true);
        }
    }
    Ok(false)
}

fn sharing_identity_has_column(conn: &Connection, column: &str) -> Result<bool, rusqlite::Error> {
    let mut stmt = conn.prepare("PRAGMA table_info(sharing_identity_bundles)")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
    for row in rows {
        if row? == column {
            return Ok(true);
        }
    }
    Ok(false)
}

fn sharing_identity_generation_floor_has_column(
    conn: &Connection,
    column: &str,
) -> Result<bool, rusqlite::Error> {
    let mut stmt = conn.prepare("PRAGMA table_info(sharing_identity_generation_floors)")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
    for row in rows {
        if row? == column {
            return Ok(true);
        }
    }
    Ok(false)
}

fn pairing_session_has_column(conn: &Connection, column: &str) -> Result<bool, rusqlite::Error> {
    let mut stmt = conn.prepare("PRAGMA table_info(pairing_sessions)")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
    for row in rows {
        if row? == column {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Add password_version column to an existing `sync_groups` table.
/// Safe to call repeatedly — checks for column existence first.
fn migrate_sync_groups_password_version(conn: &Connection) -> Result<(), rusqlite::Error> {
    let has_password_version = sync_group_has_column(conn, "password_version")?;
    if !has_password_version {
        conn.execute_batch(
            "ALTER TABLE sync_groups ADD COLUMN password_version INTEGER NOT NULL DEFAULT 0;",
        )?;
    }
    Ok(())
}

fn migrate_sync_groups_pruned_floor_seq(conn: &Connection) -> Result<(), rusqlite::Error> {
    let has_col = sync_group_has_column(conn, "pruned_floor_seq")?;
    if !has_col {
        conn.execute_batch(
            "ALTER TABLE sync_groups ADD COLUMN pruned_floor_seq INTEGER NOT NULL DEFAULT 0;",
        )?;
    }
    Ok(())
}

fn migrate_sharing_identity_generation(conn: &Connection) -> Result<(), rusqlite::Error> {
    let has_identity_generation = sharing_identity_has_column(conn, "identity_generation")?;
    if !has_identity_generation {
        conn.execute_batch(
            "ALTER TABLE sharing_identity_bundles
             ADD COLUMN identity_generation INTEGER NOT NULL DEFAULT 0;",
        )?;
    }
    Ok(())
}

/// Add ML-DSA key rotation columns to an existing `devices` table.
/// Safe to call repeatedly — checks for column existence first.
fn migrate_devices_ml_dsa_rotation(conn: &Connection) -> Result<(), rusqlite::Error> {
    let has_gen = device_has_column(conn, "ml_dsa_key_generation")?;
    let has_prev = device_has_column(conn, "prev_ml_dsa_65_public_key")?;
    let has_expires = device_has_column(conn, "prev_ml_dsa_65_expires_at")?;

    if !has_gen {
        conn.execute_batch(
            "ALTER TABLE devices ADD COLUMN ml_dsa_key_generation INTEGER NOT NULL DEFAULT 0;",
        )?;
    }
    if !has_prev {
        conn.execute_batch(
            "ALTER TABLE devices ADD COLUMN prev_ml_dsa_65_public_key BLOB NOT NULL DEFAULT X'';",
        )?;
    }
    if !has_expires {
        conn.execute_batch("ALTER TABLE devices ADD COLUMN prev_ml_dsa_65_expires_at INTEGER;")?;
    }
    Ok(())
}

fn migrate_sharing_identity_generation_floors(conn: &Connection) -> Result<(), rusqlite::Error> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS sharing_identity_generation_floors (
             sharing_id               TEXT PRIMARY KEY,
             max_identity_generation  INTEGER NOT NULL DEFAULT 0,
             identity_bundle_hash     TEXT,
             updated_at               INTEGER NOT NULL
         );",
    )?;

    let has_bundle_hash =
        sharing_identity_generation_floor_has_column(conn, "identity_bundle_hash")?;
    if !has_bundle_hash {
        conn.execute_batch(
            "ALTER TABLE sharing_identity_generation_floors
             ADD COLUMN identity_bundle_hash TEXT;",
        )?;
    }

    conn.execute(
        "INSERT OR IGNORE INTO sharing_identity_generation_floors
             (sharing_id, max_identity_generation, identity_bundle_hash, updated_at)
         SELECT sharing_id, identity_generation, NULL, updated_at
           FROM sharing_identity_bundles",
        [],
    )?;

    conn.execute(
        "UPDATE sharing_identity_generation_floors
            SET max_identity_generation = (
                    SELECT MAX(
                        sharing_identity_generation_floors.max_identity_generation,
                        sib.identity_generation
                    )
                    FROM sharing_identity_bundles sib
                    WHERE sib.sharing_id = sharing_identity_generation_floors.sharing_id
                ),
                updated_at = MAX(
                    sharing_identity_generation_floors.updated_at,
                    COALESCE(
                        (
                            SELECT MAX(sib.updated_at)
                            FROM sharing_identity_bundles sib
                            WHERE sib.sharing_id = sharing_identity_generation_floors.sharing_id
                        ),
                        sharing_identity_generation_floors.updated_at
                    )
                )
          WHERE EXISTS (
                SELECT 1
                FROM sharing_identity_bundles sib
                WHERE sib.sharing_id = sharing_identity_generation_floors.sharing_id
          )",
        [],
    )?;

    let mut stmt = conn.prepare(
        "SELECT sharing_id, identity_bundle, identity_generation, updated_at
         FROM sharing_identity_bundles",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, u32>(2)?,
            row.get::<_, i64>(3)?,
        ))
    })?;

    for row in rows {
        let (sharing_id, identity_bundle, identity_generation, updated_at) = row?;
        conn.execute(
            "UPDATE sharing_identity_generation_floors
                SET identity_bundle_hash = CASE
                        WHEN max_identity_generation < ?2 THEN ?3
                        WHEN max_identity_generation = ?2 AND identity_bundle_hash IS NULL THEN ?3
                        ELSE identity_bundle_hash
                    END,
                    updated_at = MAX(updated_at, ?4)
              WHERE sharing_id = ?1",
            params![sharing_id, identity_generation, hash_bytes(&identity_bundle), updated_at],
        )?;
    }

    Ok(())
}

fn migrate_pairing_session_consumed_columns(conn: &Connection) -> Result<(), rusqlite::Error> {
    let has_credentials_consumed =
        pairing_session_has_column(conn, "credential_bundle_consumed_at")?;
    let has_joiner_consumed = pairing_session_has_column(conn, "joiner_bundle_consumed_at")?;

    if !has_credentials_consumed {
        conn.execute_batch(
            "ALTER TABLE pairing_sessions ADD COLUMN credential_bundle_consumed_at INTEGER;",
        )?;
    }
    if !has_joiner_consumed {
        conn.execute_batch(
            "ALTER TABLE pairing_sessions ADD COLUMN joiner_bundle_consumed_at INTEGER;",
        )?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Registry state queries
// ---------------------------------------------------------------------------

pub fn get_registry_state(
    conn: &Connection,
    sync_id: &str,
) -> Result<Option<RegistryStateRecord>, rusqlite::Error> {
    conn.query_row(
        "SELECT sync_id, registry_version, registry_hash, updated_at
         FROM registry_states
         WHERE sync_id = ?1",
        params![sync_id],
        |row| {
            Ok(RegistryStateRecord {
                sync_id: row.get(0)?,
                registry_version: row.get(1)?,
                registry_hash: row.get(2)?,
                updated_at: row.get(3)?,
            })
        },
    )
    .optional()
}

pub fn get_registry_artifact(
    conn: &Connection,
    sync_id: &str,
    registry_version: i64,
) -> Result<Option<RegistryArtifactRecord>, rusqlite::Error> {
    conn.query_row(
        "SELECT sync_id, registry_version, artifact_kind, artifact_hash, artifact_blob, created_at
         FROM registry_state_artifacts
         WHERE sync_id = ?1 AND registry_version = ?2",
        params![sync_id, registry_version],
        |row| {
            Ok(RegistryArtifactRecord {
                sync_id: row.get(0)?,
                registry_version: row.get(1)?,
                artifact_kind: row.get(2)?,
                artifact_hash: row.get(3)?,
                artifact_blob: row.get(4)?,
                created_at: row.get(5)?,
            })
        },
    )
    .optional()
}

pub fn upsert_registry_state(
    conn: &Connection,
    sync_id: &str,
    registry_version: i64,
    registry_hash: &str,
) -> Result<(), rusqlite::Error> {
    let now = now_secs();
    conn.execute(
        "INSERT INTO registry_states (sync_id, registry_version, registry_hash, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?4)
         ON CONFLICT(sync_id) DO UPDATE SET
            registry_version = excluded.registry_version,
            registry_hash = excluded.registry_hash,
            updated_at = excluded.updated_at",
        params![sync_id, registry_version, registry_hash, now],
    )?;
    Ok(())
}

pub fn store_registry_artifact(
    conn: &Connection,
    sync_id: &str,
    registry_version: i64,
    registry_hash: &str,
    artifact_kind: &str,
    artifact_blob: &[u8],
) -> Result<(), rusqlite::Error> {
    let now = now_secs();
    conn.execute(
        "INSERT INTO registry_state_artifacts (
            sync_id, registry_version, artifact_kind, artifact_hash, artifact_blob, created_at
         )
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(sync_id, registry_version) DO UPDATE SET
            artifact_kind = excluded.artifact_kind,
            artifact_hash = excluded.artifact_hash,
            artifact_blob = excluded.artifact_blob,
            created_at = excluded.created_at",
        params![sync_id, registry_version, artifact_kind, registry_hash, artifact_blob, now,],
    )?;
    Ok(())
}

/// Compare-and-set registry state. Returns `true` if the transition was applied.
#[allow(clippy::too_many_arguments)]
pub fn compare_and_set_registry_state(
    conn: &Connection,
    sync_id: &str,
    expected_version: i64,
    expected_hash: &str,
    next_version: i64,
    next_hash: &str,
    artifact_kind: Option<&str>,
    artifact_blob: Option<&[u8]>,
) -> Result<bool, rusqlite::Error> {
    if next_version <= expected_version {
        return Ok(false);
    }

    let tx = conn.unchecked_transaction()?;
    let now = now_secs();

    let current = tx
        .query_row(
            "SELECT registry_version, registry_hash
             FROM registry_states
             WHERE sync_id = ?1",
            params![sync_id],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;

    let current_matches = match current {
        Some((version, hash)) => version == expected_version && hash == expected_hash,
        None => expected_version == 0 && expected_hash.is_empty(),
    };

    if !current_matches {
        return Ok(false);
    }

    tx.execute(
        "INSERT INTO registry_states (sync_id, registry_version, registry_hash, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?4)
         ON CONFLICT(sync_id) DO UPDATE SET
            registry_version = excluded.registry_version,
            registry_hash = excluded.registry_hash,
            updated_at = excluded.updated_at",
        params![sync_id, next_version, next_hash, now],
    )?;

    if let (Some(kind), Some(blob)) = (artifact_kind, artifact_blob) {
        tx.execute(
            "INSERT INTO registry_state_artifacts (
                sync_id, registry_version, artifact_kind, artifact_hash, artifact_blob, created_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(sync_id, registry_version) DO UPDATE SET
                artifact_kind = excluded.artifact_kind,
                artifact_hash = excluded.artifact_hash,
                artifact_blob = excluded.artifact_blob,
                created_at = excluded.created_at",
            params![sync_id, next_version, kind, next_hash, blob, now],
        )?;
    }

    tx.commit()?;
    Ok(true)
}

pub fn cleanup_superseded_registry_state_artifacts(
    conn: &Connection,
) -> Result<usize, rusqlite::Error> {
    let rows = conn.execute(
        "DELETE FROM registry_state_artifacts
         WHERE NOT EXISTS (
             SELECT 1
             FROM registry_states rs
             WHERE rs.sync_id = registry_state_artifacts.sync_id
               AND rs.registry_version >= registry_state_artifacts.registry_version
         )
         OR EXISTS (
             SELECT 1
             FROM registry_states rs
             WHERE rs.sync_id = registry_state_artifacts.sync_id
               AND registry_state_artifacts.registry_version < rs.registry_version
         )",
        [],
    )?;
    Ok(rows)
}

/// Delete revoked-device tombstones only after retained history no longer references them.
pub fn cleanup_revoked_device_tombstones(
    conn: &Connection,
    retention_secs: i64,
) -> Result<usize, rusqlite::Error> {
    let cutoff = now_secs() - retention_secs;
    let mut stmt = conn.prepare(
        "SELECT d.sync_id, d.device_id
         FROM devices d
         WHERE d.status = 'revoked'
           AND d.revoked_at IS NOT NULL
           AND d.revoked_at <= ?1
           AND NOT EXISTS (
               SELECT 1 FROM device_sessions ds
               WHERE ds.sync_id = d.sync_id AND ds.device_id = d.device_id
           )
           AND NOT EXISTS (
               SELECT 1 FROM revoked_device_sessions rds
               WHERE rds.sync_id = d.sync_id AND rds.device_id = d.device_id
           )
           AND NOT EXISTS (
               SELECT 1 FROM batches b
               WHERE b.sync_id = d.sync_id AND b.sender_device_id = d.device_id
           )
           AND NOT EXISTS (
               SELECT 1 FROM snapshots s
               WHERE s.sync_id = d.sync_id
                 AND (s.target_device_id = d.device_id OR s.uploaded_by_device_id = d.device_id)
           )
           AND NOT EXISTS (
               SELECT 1 FROM rekey_artifacts r
               WHERE r.sync_id = d.sync_id AND r.target_device_id = d.device_id
           )
           AND NOT EXISTS (
               SELECT 1 FROM password_change_artifacts p
               WHERE p.sync_id = d.sync_id AND p.target_device_id = d.device_id
           )",
    )?;
    let tombstones: Vec<(String, String)> = stmt
        .query_map(params![cutoff], |row| Ok((row.get(0)?, row.get(1)?)))?
        .filter_map(|row| row.ok())
        .collect();

    let mut deleted = 0;
    for (sync_id, device_id) in tombstones {
        if delete_device(conn, &sync_id, &device_id)? {
            deleted += 1;
        }
    }
    Ok(deleted)
}

// ---------------------------------------------------------------------------
// Sync group queries
// ---------------------------------------------------------------------------

pub fn create_sync_group(
    conn: &Connection,
    sync_id: &str,
    epoch: i64,
) -> Result<bool, rusqlite::Error> {
    let now = now_secs();
    let rows = conn.execute(
        "INSERT OR IGNORE INTO sync_groups (sync_id, current_epoch, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?3)",
        params![sync_id, epoch, now],
    )?;
    Ok(rows > 0)
}

pub fn get_sync_group_epoch(
    conn: &Connection,
    sync_id: &str,
) -> Result<Option<i64>, rusqlite::Error> {
    conn.query_row(
        "SELECT current_epoch FROM sync_groups WHERE sync_id = ?1",
        params![sync_id],
        |row| row.get(0),
    )
    .optional()
}

pub fn update_sync_group_epoch(
    conn: &Connection,
    sync_id: &str,
    epoch: i64,
) -> Result<(), rusqlite::Error> {
    let now = now_secs();
    conn.execute(
        "UPDATE sync_groups SET current_epoch = ?1, updated_at = ?2 WHERE sync_id = ?3",
        params![epoch, now, sync_id],
    )?;
    Ok(())
}

pub fn set_needs_rekey(
    conn: &Connection,
    sync_id: &str,
    needs: bool,
) -> Result<(), rusqlite::Error> {
    let now = now_secs();
    conn.execute(
        "UPDATE sync_groups SET needs_rekey = ?1, updated_at = ?2 WHERE sync_id = ?3",
        params![needs as i64, now, sync_id],
    )?;
    Ok(())
}

pub fn get_needs_rekey(conn: &Connection, sync_id: &str) -> Result<Option<bool>, rusqlite::Error> {
    let raw: Option<i64> = conn
        .query_row(
            "SELECT needs_rekey FROM sync_groups WHERE sync_id = ?1",
            params![sync_id],
            |row| row.get(0),
        )
        .optional()?;
    Ok(raw.map(|v| v != 0))
}

// ---------------------------------------------------------------------------
// Device queries
// ---------------------------------------------------------------------------

pub fn register_device(
    conn: &Connection,
    sync_id: &str,
    device_id: &str,
    signing_pk: &[u8],
    x25519_pk: &[u8],
    epoch: i64,
) -> Result<(), rusqlite::Error> {
    register_device_with_pq(conn, sync_id, device_id, signing_pk, x25519_pk, &[], &[], &[], epoch)
}

#[allow(clippy::too_many_arguments)]
pub fn register_device_with_pq(
    conn: &Connection,
    sync_id: &str,
    device_id: &str,
    signing_pk: &[u8],
    x25519_pk: &[u8],
    ml_dsa_pk: &[u8],
    ml_kem_pk: &[u8],
    xwing_pk: &[u8],
    epoch: i64,
) -> Result<(), rusqlite::Error> {
    let now = now_secs();
    conn.execute(
        "INSERT INTO devices (
            sync_id, device_id, signing_public_key, x25519_public_key,
            ml_dsa_65_public_key, ml_kem_768_public_key, x_wing_public_key,
            epoch, status, registered_at, last_seen_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'active', ?9, ?9)",
        params![
            sync_id, device_id, signing_pk, x25519_pk, ml_dsa_pk, ml_kem_pk, xwing_pk, epoch, now
        ],
    )?;
    Ok(())
}

pub fn get_device(
    conn: &Connection,
    sync_id: &str,
    device_id: &str,
) -> Result<Option<DeviceRecord>, rusqlite::Error> {
    conn.query_row(
        "SELECT device_id, signing_public_key, x25519_public_key,
                ml_dsa_65_public_key, ml_kem_768_public_key, x_wing_public_key,
                epoch, status, last_seen_at,
                ml_dsa_key_generation, prev_ml_dsa_65_public_key,
                prev_ml_dsa_65_expires_at
         FROM devices
         WHERE sync_id = ?1 AND device_id = ?2",
        params![sync_id, device_id],
        |row| {
            Ok(DeviceRecord {
                device_id: row.get(0)?,
                signing_public_key: row.get(1)?,
                x25519_public_key: row.get(2)?,
                ml_dsa_65_public_key: row.get(3)?,
                ml_kem_768_public_key: row.get(4)?,
                x_wing_public_key: row.get(5)?,
                epoch: row.get(6)?,
                status: row.get(7)?,
                last_seen_at: row.get(8)?,
                ml_dsa_key_generation: row.get(9)?,
                prev_ml_dsa_65_public_key: row.get(10)?,
                prev_ml_dsa_65_expires_at: row.get(11)?,
            })
        },
    )
    .optional()
}

pub fn list_devices(
    conn: &Connection,
    sync_id: &str,
) -> Result<Vec<DeviceListEntry>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT device_id, signing_public_key, x25519_public_key,
                ml_dsa_65_public_key, ml_kem_768_public_key, x_wing_public_key,
                epoch, status, ml_dsa_key_generation
         FROM devices
         WHERE sync_id = ?1
         ORDER BY registered_at ASC",
    )?;
    let rows = stmt.query_map(params![sync_id], |row| {
        Ok(DeviceListEntry {
            device_id: row.get(0)?,
            signing_public_key: row.get(1)?,
            x25519_public_key: row.get(2)?,
            ml_dsa_65_public_key: row.get(3)?,
            ml_kem_768_public_key: row.get(4)?,
            x_wing_public_key: row.get(5)?,
            epoch: row.get(6)?,
            status: row.get(7)?,
            ml_dsa_key_generation: row.get(8)?,
        })
    })?;
    rows.collect()
}

pub fn revoke_device(
    conn: &Connection,
    sync_id: &str,
    device_id: &str,
    remote_wipe: bool,
) -> Result<bool, rusqlite::Error> {
    let now = now_secs();
    let changed = conn.execute(
        "UPDATE devices
         SET status = 'revoked', revoked_at = ?1, last_seen_at = ?1, remote_wipe = ?4
         WHERE sync_id = ?2 AND device_id = ?3 AND status = 'active'",
        params![now, sync_id, device_id, remote_wipe as i32],
    )?;
    Ok(changed > 0)
}

pub fn get_device_wipe_status(
    conn: &Connection,
    sync_id: &str,
    device_id: &str,
) -> Result<Option<bool>, rusqlite::Error> {
    let result: Option<i32> = conn
        .query_row(
            "SELECT remote_wipe FROM devices
             WHERE sync_id = ?1 AND device_id = ?2 AND status = 'revoked'",
            params![sync_id, device_id],
            |row| row.get(0),
        )
        .optional()?;
    Ok(result.map(|v| v != 0))
}

pub fn delete_device(
    conn: &Connection,
    sync_id: &str,
    device_id: &str,
) -> Result<bool, rusqlite::Error> {
    let tx = conn.unchecked_transaction()?;

    tx.execute(
        "DELETE FROM device_sessions WHERE sync_id = ?1 AND device_id = ?2",
        params![sync_id, device_id],
    )?;
    tx.execute(
        "DELETE FROM revoked_device_sessions WHERE sync_id = ?1 AND device_id = ?2",
        params![sync_id, device_id],
    )?;
    tx.execute(
        "DELETE FROM device_receipts WHERE sync_id = ?1 AND device_id = ?2",
        params![sync_id, device_id],
    )?;
    tx.execute(
        "DELETE FROM rekey_artifacts WHERE sync_id = ?1 AND target_device_id = ?2",
        params![sync_id, device_id],
    )?;
    tx.execute(
        "DELETE FROM password_change_artifacts WHERE sync_id = ?1 AND target_device_id = ?2",
        params![sync_id, device_id],
    )?;
    let deleted = tx.execute(
        "DELETE FROM devices WHERE sync_id = ?1 AND device_id = ?2",
        params![sync_id, device_id],
    )?;

    tx.commit()?;
    Ok(deleted > 0)
}

pub fn touch_device(
    conn: &Connection,
    sync_id: &str,
    device_id: &str,
) -> Result<(), rusqlite::Error> {
    let now = now_secs();
    conn.execute(
        "UPDATE devices SET last_seen_at = ?1 WHERE sync_id = ?2 AND device_id = ?3",
        params![now, sync_id, device_id],
    )?;
    Ok(())
}

pub fn count_active_devices(conn: &Connection, sync_id: &str) -> Result<u64, rusqlite::Error> {
    conn.query_row(
        "SELECT COUNT(*) FROM devices WHERE sync_id = ?1 AND status = 'active'",
        params![sync_id],
        |row| row.get(0),
    )
}

/// Rotate a device's ML-DSA key, shifting the current key to the grace slot.
///
/// Returns `true` if the rotation was applied, `false` if the device already
/// has an equal or higher generation (concurrent or replayed rotation).
pub fn rotate_device_ml_dsa(
    conn: &Connection,
    sync_id: &str,
    device_id: &str,
    new_ml_dsa_pk: &[u8],
    new_generation: i64,
    grace_expires_at: i64,
) -> Result<bool, rusqlite::Error> {
    let count = conn.execute(
        "UPDATE devices SET
            prev_ml_dsa_65_public_key = ml_dsa_65_public_key,
            prev_ml_dsa_65_expires_at = ?1,
            ml_dsa_65_public_key = ?2,
            ml_dsa_key_generation = ?3
         WHERE sync_id = ?4 AND device_id = ?5 AND ml_dsa_key_generation < ?3",
        params![grace_expires_at, new_ml_dsa_pk, new_generation, sync_id, device_id],
    )?;
    Ok(count > 0)
}

/// Clean up expired ML-DSA grace keys.
pub fn cleanup_expired_ml_dsa_grace_keys(
    conn: &Connection,
    now: i64,
) -> Result<usize, rusqlite::Error> {
    let count = conn.execute(
        "UPDATE devices SET prev_ml_dsa_65_public_key = X'', prev_ml_dsa_65_expires_at = NULL
         WHERE prev_ml_dsa_65_expires_at IS NOT NULL AND prev_ml_dsa_65_expires_at < ?1",
        [now],
    )?;
    Ok(count)
}

// ---------------------------------------------------------------------------
// Device session queries
// ---------------------------------------------------------------------------

/// Create a session for a device, returning the plaintext session token.
/// If a session already exists for this (sync_id, device_id), it is replaced.
pub fn create_session(
    conn: &Connection,
    sync_id: &str,
    device_id: &str,
    session_expiry_secs: i64,
) -> Result<String, rusqlite::Error> {
    let token = generate_session_token();
    let token_hash = hash_token(&token);
    let now = now_secs();
    let expires_at = now + session_expiry_secs;

    conn.execute(
        "INSERT INTO device_sessions (sync_id, device_id, session_token_hash, created_at, last_active_at, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?4, ?5)
         ON CONFLICT(sync_id, device_id) DO UPDATE SET
            session_token_hash = excluded.session_token_hash,
            created_at = excluded.created_at,
            last_active_at = excluded.last_active_at,
            expires_at = excluded.expires_at",
        params![sync_id, device_id, token_hash, now, expires_at],
    )?;

    Ok(token)
}

/// Move the current session for a device into the revoked-session table and
/// remove its active session.
pub fn revoke_session(
    conn: &Connection,
    sync_id: &str,
    device_id: &str,
    retention_secs: i64,
) -> Result<(), rusqlite::Error> {
    let now = now_secs();
    let expires_at = now + retention_secs;

    conn.execute(
        "INSERT INTO revoked_device_sessions (
            sync_id, device_id, session_token_hash, revoked_at, expires_at
         )
         SELECT sync_id, device_id, session_token_hash, ?3, ?4
         FROM device_sessions
         WHERE sync_id = ?1 AND device_id = ?2
         ON CONFLICT(session_token_hash) DO UPDATE SET
            revoked_at = excluded.revoked_at,
            expires_at = excluded.expires_at",
        params![sync_id, device_id, now, expires_at],
    )?;
    conn.execute(
        "DELETE FROM device_sessions WHERE sync_id = ?1 AND device_id = ?2",
        params![sync_id, device_id],
    )?;

    Ok(())
}

/// Validate a session token. Returns `(sync_id, device_id)` if valid and not expired.
///
/// Enforces **two** independent deadlines:
/// * the sliding `expires_at` window (refreshed on every request via
///   [`touch_session`]), and
/// * an absolute maximum age of `created_at + session_max_age_secs`,
///   independent of activity. A token kept warm forever by traffic still dies
///   `session_max_age_secs` after its last full re-authentication, forcing a
///   re-auth and bounding the blast radius of a leaked-but-active token.
pub fn validate_session(
    conn: &Connection,
    token: &str,
    session_max_age_secs: i64,
) -> Result<Option<(String, String)>, rusqlite::Error> {
    let token_hash = hash_token(token);
    let now = now_secs();
    conn.query_row(
        "SELECT sync_id, device_id
         FROM device_sessions
         WHERE session_token_hash = ?1
           AND expires_at > ?2
           AND created_at + ?3 > ?2",
        params![token_hash, now, session_max_age_secs],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .optional()
}

/// Validate a revoked session token. Returns `(sync_id, device_id)` if the
/// token belongs to a recently revoked device and has not expired.
pub fn validate_revoked_session(
    conn: &Connection,
    token: &str,
) -> Result<Option<(String, String)>, rusqlite::Error> {
    let token_hash = hash_token(token);
    let now = now_secs();
    conn.query_row(
        "SELECT sync_id, device_id
         FROM revoked_device_sessions
         WHERE session_token_hash = ?1 AND expires_at > ?2",
        params![token_hash, now],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .optional()
}

/// Extend the session expiry for a device (sliding window).
///
/// The sliding `expires_at` is clamped so it never extends past the absolute
/// `created_at + session_max_age_secs` deadline — keeping the stored
/// `expires_at` honest with the cap [`validate_session`] enforces, so expired
/// sessions are still eligible for cleanup.
pub fn touch_session(
    conn: &Connection,
    sync_id: &str,
    device_id: &str,
    session_expiry_secs: i64,
    session_max_age_secs: i64,
) -> Result<(), rusqlite::Error> {
    let now = now_secs();
    let sliding_expires_at = now + session_expiry_secs;
    conn.execute(
        "UPDATE device_sessions
         SET last_active_at = ?1,
             expires_at = MIN(?2, created_at + ?5)
         WHERE sync_id = ?3 AND device_id = ?4",
        params![now, sliding_expires_at, sync_id, device_id, session_max_age_secs],
    )?;
    Ok(())
}

/// Delete a device's session.
pub fn delete_session(
    conn: &Connection,
    sync_id: &str,
    device_id: &str,
) -> Result<(), rusqlite::Error> {
    conn.execute(
        "DELETE FROM device_sessions WHERE sync_id = ?1 AND device_id = ?2",
        params![sync_id, device_id],
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Registration nonce queries
// ---------------------------------------------------------------------------

/// Create a registration nonce for a sync group, returning the nonce string.
pub fn create_nonce(
    conn: &Connection,
    sync_id: &str,
    nonce_expiry_secs: i64,
) -> Result<String, rusqlite::Error> {
    let nonce = Uuid::new_v4().to_string();
    let now = now_secs();
    let expires_at = now + nonce_expiry_secs;

    conn.execute(
        "INSERT INTO registration_nonces (nonce, sync_id, created_at, expires_at)
         VALUES (?1, ?2, ?3, ?4)",
        params![nonce, sync_id, now, expires_at],
    )?;

    Ok(nonce)
}

/// Consume a nonce: validates it is not expired and belongs to the given sync_id,
/// then deletes it. Returns true if consumed successfully.
pub fn consume_nonce(
    conn: &Connection,
    nonce: &str,
    sync_id: &str,
) -> Result<bool, rusqlite::Error> {
    let now = now_secs();
    let deleted = conn.execute(
        "DELETE FROM registration_nonces
         WHERE nonce = ?1 AND sync_id = ?2 AND expires_at > ?3",
        params![nonce, sync_id, now],
    )?;
    Ok(deleted > 0)
}

/// Remove all expired nonces. Returns the number removed.
pub fn cleanup_expired_nonces(conn: &Connection) -> Result<usize, rusqlite::Error> {
    let now = now_secs();
    conn.execute("DELETE FROM registration_nonces WHERE expires_at <= ?1", params![now])
}

/// Record a signed request nonce if it has not already been seen for this
/// device within the replay window. Returns true when the nonce was accepted.
pub fn record_signed_request_nonce(
    conn: &Connection,
    device_id: &str,
    nonce: &str,
    expires_at: i64,
    now: i64,
) -> Result<bool, rusqlite::Error> {
    conn.execute(
        "DELETE FROM signed_request_nonces
         WHERE device_id = ?1 AND nonce = ?2 AND expires_at <= ?3",
        params![device_id, nonce, now],
    )?;

    let inserted = conn.execute(
        "INSERT OR IGNORE INTO signed_request_nonces (device_id, nonce, expires_at)
         VALUES (?1, ?2, ?3)",
        params![device_id, nonce, expires_at],
    )?;

    Ok(inserted > 0)
}

/// Remove expired signed request replay nonces. Returns the number removed.
pub fn cleanup_expired_signed_request_nonces(conn: &Connection) -> Result<usize, rusqlite::Error> {
    let now = now_secs();
    conn.execute("DELETE FROM signed_request_nonces WHERE expires_at <= ?1", params![now])
}

/// Remove expired revoked-session markers.
pub fn cleanup_expired_revoked_sessions(conn: &Connection) -> Result<usize, rusqlite::Error> {
    let now = now_secs();
    conn.execute("DELETE FROM revoked_device_sessions WHERE expires_at <= ?1", params![now])
}

// ---------------------------------------------------------------------------
// Batch queries
// ---------------------------------------------------------------------------

/// Insert a batch with deduplication. Returns the server_seq (rowid).
/// On duplicate `(sync_id, sender_device_id, batch_id)`, returns the existing seq.
pub fn insert_batch(
    conn: &Connection,
    sync_id: &str,
    epoch: i64,
    sender_device_id: &str,
    batch_id: &str,
    data: &[u8],
) -> Result<i64, rusqlite::Error> {
    let now = now_secs();
    let changed = conn.execute(
        "INSERT INTO batches (sync_id, epoch, sender_device_id, batch_id, data, received_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(sync_id, sender_device_id, batch_id) DO NOTHING",
        params![sync_id, epoch, sender_device_id, batch_id, data, now],
    )?;

    if changed > 0 {
        return Ok(conn.last_insert_rowid());
    }

    // Duplicate — return existing seq
    conn.query_row(
        "SELECT id FROM batches
         WHERE sync_id = ?1 AND sender_device_id = ?2 AND batch_id = ?3",
        params![sync_id, sender_device_id, batch_id],
        |row| row.get(0),
    )
}

/// Get batches since a given sequence, with pagination limit.
pub fn get_batches_since(
    conn: &Connection,
    sync_id: &str,
    since_seq: i64,
    limit: i64,
) -> Result<Vec<BatchEntry>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT id, sender_device_id, batch_id, epoch, data, received_at
         FROM batches
         WHERE sync_id = ?1 AND id > ?2
         ORDER BY id ASC
         LIMIT ?3",
    )?;
    let rows = stmt.query_map(params![sync_id, since_seq, limit], |row| {
        Ok(BatchEntry {
            server_seq: row.get(0)?,
            sender_device_id: row.get(1)?,
            batch_id: row.get(2)?,
            epoch: row.get(3)?,
            data: row.get(4)?,
            received_at: row.get(5)?,
        })
    })?;
    rows.collect()
}

/// Return the first retained batch sequence for a sync group, if any.
///
/// "Retained" means the relay has guaranteed this sync group's history from
/// `Some(seq)` onward — anything below that seq has been pruned and is no
/// longer recoverable from the op log. A `None` result means no pruning has
/// occurred for this sync group, so a client at any `since` value is allowed
/// to pull the tail (including a fresh `since=0` cursor on a brand-new group).
///
/// The value is derived from `sync_groups.pruned_floor_seq`, which tracks the
/// highest seq this relay has ever pruned for this sync group. The returned
/// "first retained" is `pruned_floor_seq + 1` — the lowest seq the relay still
/// has, equivalent to the historical `MIN(id) FROM batches`. Reading the floor
/// from `sync_groups` instead of `batches.id` avoids tying the bootstrap rule
/// to the global SQLite auto-increment, which would falsely trip the rule for
/// any new sync group whose first push is assigned a high global id.
pub fn get_first_retained_batch_seq(
    conn: &Connection,
    sync_id: &str,
) -> Result<Option<i64>, rusqlite::Error> {
    let pruned_floor = get_pruned_floor_seq(conn, sync_id)?;
    if pruned_floor > 0 {
        Ok(Some(pruned_floor + 1))
    } else {
        Ok(None)
    }
}

pub fn get_pruned_floor_seq(conn: &Connection, sync_id: &str) -> Result<i64, rusqlite::Error> {
    Ok(conn
        .query_row(
            "SELECT pruned_floor_seq FROM sync_groups WHERE sync_id = ?1",
            params![sync_id],
            |row| row.get(0),
        )
        .optional()?
        .unwrap_or(0))
}

pub fn get_latest_seq(conn: &Connection, sync_id: &str) -> Result<i64, rusqlite::Error> {
    conn.query_row(
        "SELECT COALESCE(MAX(id), 0) FROM batches WHERE sync_id = ?1",
        params![sync_id],
        |row| row.get(0),
    )
}

// ---------------------------------------------------------------------------
// Snapshot queries
// ---------------------------------------------------------------------------

/// Insert or replace the per-sync snapshot row.
///
/// Equal-seq retries from the same uploader may retarget a stranded pair
/// snapshot. Returns 1 on write and 0 when the guard rejects the upsert.
#[allow(clippy::too_many_arguments)]
pub fn upsert_snapshot(
    conn: &Connection,
    sync_id: &str,
    epoch: i64,
    server_seq_at: i64,
    data: &[u8],
    expires_at: Option<i64>,
    target_device_id: Option<&str>,
    uploaded_by_device_id: Option<&str>,
) -> Result<usize, rusqlite::Error> {
    let now = now_secs();
    let affected = conn.execute(
        "INSERT INTO snapshots (sync_id, epoch, server_seq_at, data, created_at, expires_at, target_device_id, uploaded_by_device_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
         ON CONFLICT(sync_id) DO UPDATE SET
            epoch = excluded.epoch,
            server_seq_at = excluded.server_seq_at,
            data = excluded.data,
            created_at = excluded.created_at,
            expires_at = excluded.expires_at,
            target_device_id = excluded.target_device_id,
            uploaded_by_device_id = excluded.uploaded_by_device_id
         WHERE excluded.server_seq_at > snapshots.server_seq_at
            OR (snapshots.expires_at IS NOT NULL AND snapshots.expires_at < unixepoch())
            OR (
                excluded.server_seq_at = snapshots.server_seq_at
                AND excluded.uploaded_by_device_id IS NOT NULL
                AND excluded.uploaded_by_device_id = snapshots.uploaded_by_device_id
            )",
        params![
            sync_id,
            epoch,
            server_seq_at,
            data,
            now,
            expires_at,
            target_device_id,
            uploaded_by_device_id,
        ],
    )?;
    Ok(affected)
}

/// Look up `(server_seq_at, target_device_id)` of the stored snapshot.
///
/// Used by the put-snapshot handler on a stale-upload rejection so the
/// 409 body can carry the existing target alongside its seq, which
/// drives the engine's suppression matrix. Does not filter expired
/// rows — callers invoke this immediately after a write-side rejection.
pub fn get_snapshot_seq_and_target(
    conn: &Connection,
    sync_id: &str,
) -> Result<Option<(i64, Option<String>)>, rusqlite::Error> {
    conn.query_row(
        "SELECT server_seq_at, target_device_id FROM snapshots WHERE sync_id = ?1",
        params![sync_id],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<String>>(1)?)),
    )
    .optional()
}

pub fn get_snapshot(
    conn: &Connection,
    sync_id: &str,
) -> Result<Option<SnapshotRecord>, rusqlite::Error> {
    conn.query_row(
        "SELECT data, epoch, server_seq_at, target_device_id, uploaded_by_device_id
         FROM snapshots
         WHERE sync_id = ?1
           AND (expires_at IS NULL OR expires_at >= unixepoch())",
        params![sync_id],
        |row| {
            Ok(SnapshotRecord {
                data: row.get(0)?,
                epoch: row.get(1)?,
                server_seq_at: row.get(2)?,
                target_device_id: row.get(3)?,
                uploaded_by_device_id: row.get(4)?,
            })
        },
    )
    .optional()
}

/// Delete the snapshot for a sync group. Returns `true` if a row was deleted.
pub fn delete_snapshot(conn: &Connection, sync_id: &str) -> Result<bool, rusqlite::Error> {
    let rows = conn.execute("DELETE FROM snapshots WHERE sync_id = ?1", params![sync_id])?;
    Ok(rows > 0)
}

/// Delete all snapshots whose TTL has expired. Returns the number of rows deleted.
pub fn cleanup_expired_snapshots(conn: &Connection) -> Result<usize, rusqlite::Error> {
    let rows = conn.execute(
        "DELETE FROM snapshots WHERE expires_at IS NOT NULL AND expires_at < unixepoch()",
        [],
    )?;
    Ok(rows)
}

// ---------------------------------------------------------------------------
// Device receipt and pruning queries
// ---------------------------------------------------------------------------

/// Upsert a device receipt. Uses MAX behavior so receipts only advance forward.
pub fn upsert_device_receipt(
    conn: &Connection,
    sync_id: &str,
    device_id: &str,
    confirmed_seq: i64,
) -> Result<(), rusqlite::Error> {
    let now = now_secs();
    conn.execute(
        "INSERT INTO device_receipts (sync_id, device_id, last_acked_seq, updated_at)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(sync_id, device_id) DO UPDATE SET
            last_acked_seq = MAX(device_receipts.last_acked_seq, excluded.last_acked_seq),
            updated_at = excluded.updated_at",
        params![sync_id, device_id, confirmed_seq, now],
    )?;
    Ok(())
}

/// Get the minimum acknowledged seq across all active, non-stale devices.
/// Devices whose `last_seen_at` is older than `stale_threshold_secs` are excluded.
pub fn get_min_acked_seq(
    conn: &Connection,
    sync_id: &str,
    stale_threshold_secs: i64,
) -> Result<Option<i64>, rusqlite::Error> {
    let cutoff = now_secs() - stale_threshold_secs;
    conn.query_row(
        "SELECT MIN(COALESCE(dr.last_acked_seq, 0))
         FROM devices d
         LEFT JOIN device_receipts dr
           ON d.sync_id = dr.sync_id AND d.device_id = dr.device_id
         WHERE d.sync_id = ?1 AND d.status = 'active' AND d.last_seen_at >= ?2",
        params![sync_id, cutoff],
        |row| row.get(0),
    )
}

/// Get the safe pruning sequence: min of (group-wide snapshot seq, min acked
/// seq excluding stale). Returns `None` when no unexpired group-wide snapshot
/// exists; batch pruning must never rely on ACKs alone or on snapshots that
/// only one target device can read.
pub fn get_safe_prune_seq(
    conn: &Connection,
    sync_id: &str,
    stale_threshold_secs: i64,
) -> Result<Option<i64>, rusqlite::Error> {
    let snapshot_seq: Option<i64> = conn
        .query_row(
            "SELECT server_seq_at FROM snapshots WHERE sync_id = ?1
               AND target_device_id IS NULL
               AND (expires_at IS NULL OR expires_at >= unixepoch())",
            params![sync_id],
            |row| row.get(0),
        )
        .optional()?;

    let min_acked = get_min_acked_seq(conn, sync_id, stale_threshold_secs)?;

    match (snapshot_seq, min_acked) {
        (Some(snap), Some(acked)) => Ok(Some(snap.min(acked))),
        (Some(snap), None) => Ok(Some(snap)),
        (None, _) => Ok(None),
    }
}

/// Delete batches with id < before_seq. Returns number deleted.
pub fn prune_batches_before(
    conn: &Connection,
    sync_id: &str,
    before_seq: i64,
) -> Result<usize, rusqlite::Error> {
    let n = conn.execute(
        "DELETE FROM batches WHERE sync_id = ?1 AND id < ?2",
        params![sync_id, before_seq],
    )?;
    if n > 0 && before_seq > 1 {
        // The highest seq we just pruned is `before_seq - 1`; advance the
        // floor monotonically so concurrent prune calls can't roll it back.
        conn.execute(
            "UPDATE sync_groups
             SET pruned_floor_seq = MAX(pruned_floor_seq, ?2)
             WHERE sync_id = ?1",
            params![sync_id, before_seq - 1],
        )?;
    }
    Ok(n)
}

/// Prune acknowledged batch history only for sync groups that currently have
/// an unexpired group-wide snapshot. Returns the total number of batch rows
/// deleted.
pub fn prune_batches_with_unexpired_snapshots(
    conn: &Connection,
    stale_threshold_secs: i64,
) -> Result<usize, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT sync_id
         FROM snapshots
         WHERE target_device_id IS NULL
           AND (expires_at IS NULL OR expires_at >= unixepoch())",
    )?;
    let sync_ids =
        stmt.query_map([], |row| row.get::<_, String>(0))?.collect::<Result<Vec<_>, _>>()?;

    let mut pruned = 0usize;
    for sync_id in sync_ids {
        if let Some(safe_seq) = get_safe_prune_seq(conn, &sync_id, stale_threshold_secs)? {
            pruned += prune_batches_before(conn, &sync_id, safe_seq)?;
        }
    }

    Ok(pruned)
}

/// Minimum acked seq across all non-revoked devices (`active` + `stale`), with
/// no staleness cutoff. The floor for ack-only pruning: never prune past a
/// device that could still reconnect.
///
/// `stale` is included deliberately. A device is marked `stale` at 30d but not
/// auto-revoked until 90d, and `touch_device` never flips it back to `active`;
/// excluding it would prune a returning device's history out from under it,
/// forcing a re-pair (no group-wide snapshot to bootstrap from). Only
/// revocation drops a device from the floor.
///
/// No receipt row coalesces to `0` (pins the floor until first ack). No
/// non-revoked devices yields `None` (MIN over zero rows); the caller skips it.
pub fn get_min_acked_seq_unrevoked(
    conn: &Connection,
    sync_id: &str,
) -> Result<Option<i64>, rusqlite::Error> {
    conn.query_row(
        "SELECT MIN(COALESCE(dr.last_acked_seq, 0))
         FROM devices d
         LEFT JOIN device_receipts dr
           ON d.sync_id = dr.sync_id AND d.device_id = dr.device_id
         WHERE d.sync_id = ?1 AND d.status IN ('active', 'stale')",
        params![sync_id],
        |row| row.get(0),
    )
}

/// Prune batch history for every group *without* a group-wide snapshot, down
/// to the lowest seq all non-revoked devices have acked. Returns rows deleted.
///
/// The ack-only counterpart to [`prune_batches_with_unexpired_snapshots`],
/// covering the common case where no group-wide snapshot is ever published
/// (otherwise batch history grows without bound).
///
/// Groups that have an unexpired group-wide snapshot are skipped — the
/// snapshot-gated path owns them and caps at the snapshot seq. Running both
/// would let this path advance `pruned_floor_seq` past the snapshot, stranding
/// it as a bootstrap floor (`MustBootstrapFromSnapshot` loop). Both paths share
/// the floor, so they must not disagree.
pub fn prune_batches_by_acks(conn: &Connection) -> Result<usize, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT sg.sync_id
         FROM sync_groups sg
         WHERE NOT EXISTS (
             SELECT 1 FROM snapshots s
             WHERE s.sync_id = sg.sync_id
               AND s.target_device_id IS NULL
               AND (s.expires_at IS NULL OR s.expires_at >= unixepoch())
         )",
    )?;
    let sync_ids =
        stmt.query_map([], |row| row.get::<_, String>(0))?.collect::<Result<Vec<_>, _>>()?;

    let mut pruned = 0usize;
    for sync_id in sync_ids {
        // prune_batches_before deletes id < before_seq, so +1 deletes through
        // min_acked. 0 means a device hasn't acked yet — leave history intact.
        if let Some(min_acked) = get_min_acked_seq_unrevoked(conn, &sync_id)? {
            if min_acked > 0 {
                pruned += prune_batches_before(conn, &sync_id, min_acked + 1)?;
            }
        }
    }

    Ok(pruned)
}

// ---------------------------------------------------------------------------
// Rekey artifact queries
// ---------------------------------------------------------------------------

pub fn store_rekey_artifact(
    conn: &Connection,
    sync_id: &str,
    epoch: i64,
    target_device_id: &str,
    wrapped_key: &[u8],
) -> Result<(), rusqlite::Error> {
    let now = now_secs();
    conn.execute(
        "INSERT INTO rekey_artifacts (sync_id, epoch, target_device_id, wrapped_key, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(sync_id, epoch, target_device_id) DO UPDATE SET
            wrapped_key = excluded.wrapped_key,
            created_at = excluded.created_at",
        params![sync_id, epoch, target_device_id, wrapped_key, now],
    )?;
    Ok(())
}

pub fn get_rekey_artifact(
    conn: &Connection,
    sync_id: &str,
    epoch: i64,
    target_device_id: &str,
) -> Result<Option<Vec<u8>>, rusqlite::Error> {
    conn.query_row(
        "SELECT wrapped_key
         FROM rekey_artifacts
         WHERE sync_id = ?1 AND epoch = ?2 AND target_device_id = ?3",
        params![sync_id, epoch, target_device_id],
        |row| row.get(0),
    )
    .optional()
}

pub fn insert_revocation_event(
    conn: &Connection,
    sync_id: &str,
    revoker_device_id: &str,
    target_device_id: &str,
    new_epoch: i64,
    remote_wipe: bool,
) -> Result<(), rusqlite::Error> {
    conn.execute(
        "INSERT INTO revocation_events (
            sync_id, revoker_device_id, target_device_id, new_epoch, remote_wipe, created_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            sync_id,
            revoker_device_id,
            target_device_id,
            new_epoch,
            remote_wipe as i64,
            now_secs(),
        ],
    )?;
    Ok(())
}

pub fn insert_rekey_event(
    conn: &Connection,
    sync_id: &str,
    rekeyer_device_id: &str,
    new_epoch: i64,
) -> Result<(), rusqlite::Error> {
    conn.execute(
        "INSERT INTO rekey_events (sync_id, rekeyer_device_id, new_epoch, created_at)
         VALUES (?1, ?2, ?3, ?4)",
        params![sync_id, rekeyer_device_id, new_epoch, now_secs()],
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Password change artifact queries
// ---------------------------------------------------------------------------

pub fn get_password_version(
    conn: &Connection,
    sync_id: &str,
) -> Result<Option<i64>, rusqlite::Error> {
    conn.query_row(
        "SELECT password_version FROM sync_groups WHERE sync_id = ?1",
        params![sync_id],
        |row| row.get(0),
    )
    .optional()
}

pub fn bump_password_version(
    conn: &Connection,
    sync_id: &str,
    new_version: i64,
) -> Result<(), rusqlite::Error> {
    let now = now_secs();
    conn.execute(
        "UPDATE sync_groups SET password_version = ?1, updated_at = ?2 WHERE sync_id = ?3",
        params![new_version, now, sync_id],
    )?;
    Ok(())
}

pub fn store_password_change_artifact(
    conn: &Connection,
    sync_id: &str,
    version: i64,
    target_device_id: &str,
    wrapped_blob: &[u8],
) -> Result<(), rusqlite::Error> {
    conn.execute(
        "INSERT INTO password_change_artifacts (sync_id, version, target_device_id, wrapped_blob)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(sync_id, version, target_device_id) DO UPDATE SET
            wrapped_blob = excluded.wrapped_blob",
        params![sync_id, version, target_device_id, wrapped_blob],
    )?;
    Ok(())
}

pub fn get_password_change_artifact(
    conn: &Connection,
    sync_id: &str,
    version: i64,
    target_device_id: &str,
) -> Result<Option<Vec<u8>>, rusqlite::Error> {
    conn.query_row(
        "SELECT wrapped_blob
         FROM password_change_artifacts
         WHERE sync_id = ?1 AND version = ?2 AND target_device_id = ?3",
        params![sync_id, version, target_device_id],
        |row| row.get(0),
    )
    .optional()
}

pub fn delete_password_change_artifacts_before(
    conn: &Connection,
    sync_id: &str,
    version: i64,
) -> Result<usize, rusqlite::Error> {
    conn.execute(
        "DELETE FROM password_change_artifacts WHERE sync_id = ?1 AND version < ?2",
        params![sync_id, version],
    )
}

// ---------------------------------------------------------------------------
// Cleanup queries
// ---------------------------------------------------------------------------

/// Delete a sync group and all associated data (cascading).
/// Returns the list of media_ids that were stored for this group (for disk cleanup).
pub fn delete_sync_group(conn: &Connection, sync_id: &str) -> Result<Vec<String>, rusqlite::Error> {
    let tx = conn.unchecked_transaction()?;

    // Collect media_ids before deleting rows so callers can clean up files on disk
    let mut stmt = tx.prepare("SELECT media_id FROM media_metadata WHERE sync_id = ?1")?;
    let media_ids: Vec<String> =
        stmt.query_map(params![sync_id], |row| row.get(0))?.filter_map(|r| r.ok()).collect();
    drop(stmt);

    // Clean up sharing tables via the sharing_id mapping
    let sharing_id: Option<String> = tx
        .query_row(
            "SELECT sharing_id FROM sharing_id_mappings WHERE sync_id = ?1",
            params![sync_id],
            |row| row.get(0),
        )
        .optional()?;

    if let Some(ref sid) = sharing_id {
        tx.execute("DELETE FROM sharing_signed_prekeys WHERE sharing_id = ?1", params![sid])?;
        tx.execute("DELETE FROM sharing_identity_bundles WHERE sharing_id = ?1", params![sid])?;
        tx.execute(
            "DELETE FROM sharing_identity_generation_floors WHERE sharing_id = ?1",
            params![sid],
        )?;
        tx.execute(
            "DELETE FROM sharing_init_payloads WHERE recipient_id = ?1 OR sender_id = ?1",
            params![sid],
        )?;
        tx.execute("DELETE FROM sharing_id_mappings WHERE sync_id = ?1", params![sync_id])?;
    }

    tx.execute("DELETE FROM password_change_artifacts WHERE sync_id = ?1", params![sync_id])?;
    tx.execute("DELETE FROM registry_state_artifacts WHERE sync_id = ?1", params![sync_id])?;
    tx.execute("DELETE FROM registry_states WHERE sync_id = ?1", params![sync_id])?;
    tx.execute("DELETE FROM rekey_artifacts WHERE sync_id = ?1", params![sync_id])?;
    tx.execute("DELETE FROM revocation_events WHERE sync_id = ?1", params![sync_id])?;
    tx.execute("DELETE FROM rekey_events WHERE sync_id = ?1", params![sync_id])?;
    tx.execute("DELETE FROM device_sessions WHERE sync_id = ?1", params![sync_id])?;
    tx.execute("DELETE FROM revoked_device_sessions WHERE sync_id = ?1", params![sync_id])?;
    tx.execute("DELETE FROM device_receipts WHERE sync_id = ?1", params![sync_id])?;
    tx.execute("DELETE FROM batches WHERE sync_id = ?1", params![sync_id])?;
    tx.execute("DELETE FROM snapshots WHERE sync_id = ?1", params![sync_id])?;
    tx.execute("DELETE FROM media_metadata WHERE sync_id = ?1", params![sync_id])?;
    // Ephemeral mailbox: acks first, then messages (FK to sync_groups).
    tx.execute("DELETE FROM device_message_acks WHERE sync_id = ?1", params![sync_id])?;
    tx.execute("DELETE FROM device_messages WHERE sync_id = ?1", params![sync_id])?;
    tx.execute("DELETE FROM registration_nonces WHERE sync_id = ?1", params![sync_id])?;
    tx.execute("DELETE FROM devices WHERE sync_id = ?1", params![sync_id])?;
    tx.execute("DELETE FROM sync_groups WHERE sync_id = ?1", params![sync_id])?;

    tx.commit()?;
    Ok(media_ids)
}

/// Mark devices as 'stale' if they haven't been seen within the threshold.
/// Returns number of devices marked stale.
pub fn mark_stale_devices(
    conn: &Connection,
    stale_threshold_secs: i64,
) -> Result<usize, rusqlite::Error> {
    let cutoff = now_secs() - stale_threshold_secs;
    conn.execute(
        "UPDATE devices SET status = 'stale'
         WHERE status = 'active' AND last_seen_at < ?1",
        params![cutoff],
    )
}

/// Auto-revoke devices that have been inactive beyond the revoke threshold.
/// Returns the sync_ids that had devices revoked (for rekey notification).
pub fn auto_revoke_devices(
    conn: &Connection,
    revoke_threshold_secs: i64,
) -> Result<Vec<String>, rusqlite::Error> {
    let cutoff = now_secs() - revoke_threshold_secs;
    let now = now_secs();

    // Find affected sync_ids before revoking
    let mut stmt = conn.prepare(
        "SELECT DISTINCT sync_id FROM devices
         WHERE status IN ('active', 'stale') AND last_seen_at < ?1",
    )?;
    let sync_ids: Vec<String> =
        stmt.query_map(params![cutoff], |row| row.get(0))?.filter_map(|r| r.ok()).collect();

    if !sync_ids.is_empty() {
        conn.execute(
            "UPDATE devices SET status = 'revoked', revoked_at = ?1
             WHERE status IN ('active', 'stale') AND last_seen_at < ?2",
            params![now, cutoff],
        )?;

        // Mark affected sync groups for rekey
        for sid in &sync_ids {
            set_needs_rekey(conn, sid, true)?;
        }
    }

    Ok(sync_ids)
}

/// Prune sync groups where no device has been seen within the threshold.
/// Returns number of sync groups deleted.
pub fn prune_stale_sync_groups(
    conn: &Connection,
    inactive_threshold_secs: i64,
) -> Result<usize, rusqlite::Error> {
    let cutoff = now_secs() - inactive_threshold_secs;
    let mut stmt = conn.prepare(
        "SELECT sg.sync_id
         FROM sync_groups sg
         WHERE NOT EXISTS (
             SELECT 1
             FROM devices d
             WHERE d.sync_id = sg.sync_id AND d.last_seen_at >= ?1
         )",
    )?;
    let stale_ids: Vec<String> =
        stmt.query_map(params![cutoff], |row| row.get(0))?.filter_map(|r| r.ok()).collect();

    for sync_id in &stale_ids {
        let _ = delete_sync_group(conn, sync_id)?;
    }

    Ok(stale_ids.len())
}

// ---------------------------------------------------------------------------
// Pairing sessions
// ---------------------------------------------------------------------------

/// Valid pairing slot column names.
const PAIRING_SLOTS: &[&str] =
    &["pairing_init", "joiner_confirmation", "credential_bundle", "joiner_bundle"];

fn validate_pairing_slot(slot: &str) -> Result<&'static str, rusqlite::Error> {
    PAIRING_SLOTS.iter().find(|&&s| s == slot).copied().ok_or_else(|| {
        rusqlite::Error::InvalidParameterName(format!("invalid pairing slot: {slot}"))
    })
}

/// Create a new pairing session with the given rendezvous ID and joiner bootstrap data.
pub fn create_pairing_session(
    conn: &Connection,
    rendezvous_id: &str,
    joiner_bootstrap: &[u8],
    ttl_secs: u64,
) -> Result<(), rusqlite::Error> {
    let now = now_secs();
    let expires_at = now + ttl_secs as i64;
    conn.execute(
        "INSERT INTO pairing_sessions (rendezvous_id, joiner_bootstrap, created_at, expires_at)
         VALUES (?1, ?2, ?3, ?4)",
        params![rendezvous_id, joiner_bootstrap, now, expires_at],
    )?;
    Ok(())
}

/// Get the joiner bootstrap data for a non-expired pairing session.
pub fn get_pairing_bootstrap(
    conn: &Connection,
    rendezvous_id: &str,
) -> Result<Option<Vec<u8>>, rusqlite::Error> {
    let now = now_secs();
    conn.query_row(
        "SELECT joiner_bootstrap FROM pairing_sessions
         WHERE rendezvous_id = ?1 AND expires_at > ?2",
        params![rendezvous_id, now],
        |row| row.get(0),
    )
    .optional()
}

/// Set a pairing slot column if it is currently NULL and the session is not expired.
/// Returns `true` if the update succeeded, `false` if the slot was already set or
/// the session does not exist / is expired.
pub fn set_pairing_slot(
    conn: &Connection,
    rendezvous_id: &str,
    slot: &str,
    data: &[u8],
) -> Result<bool, rusqlite::Error> {
    let col = validate_pairing_slot(slot)?;
    let now = now_secs();
    // Use a match to build the correct SQL for each column, avoiding string interpolation.
    let sql = match col {
        "pairing_init" => {
            "UPDATE pairing_sessions SET pairing_init = ?1
             WHERE rendezvous_id = ?2 AND expires_at > ?3 AND pairing_init IS NULL"
        }
        "joiner_confirmation" => {
            "UPDATE pairing_sessions SET joiner_confirmation = ?1
             WHERE rendezvous_id = ?2 AND expires_at > ?3 AND joiner_confirmation IS NULL"
        }
        "credential_bundle" => {
            "UPDATE pairing_sessions SET credential_bundle = ?1
             WHERE rendezvous_id = ?2
               AND expires_at > ?3
               AND credential_bundle IS NULL
               AND credential_bundle_consumed_at IS NULL"
        }
        "joiner_bundle" => {
            "UPDATE pairing_sessions SET joiner_bundle = ?1
             WHERE rendezvous_id = ?2
               AND expires_at > ?3
               AND joiner_bundle IS NULL
               AND joiner_bundle_consumed_at IS NULL"
        }
        _ => unreachable!(),
    };
    let changed = conn.execute(sql, params![data, rendezvous_id, now])?;
    Ok(changed > 0)
}

/// Get the value of a pairing slot column for a non-expired session.
/// Returns `None` if the session does not exist, is expired, or the slot is NULL.
pub fn get_pairing_slot(
    conn: &Connection,
    rendezvous_id: &str,
    slot: &str,
) -> Result<Option<Vec<u8>>, rusqlite::Error> {
    let col = validate_pairing_slot(slot)?;
    let now = now_secs();
    let sql = match col {
        "pairing_init" => {
            "SELECT pairing_init FROM pairing_sessions
             WHERE rendezvous_id = ?1 AND expires_at > ?2"
        }
        "joiner_confirmation" => {
            "SELECT joiner_confirmation FROM pairing_sessions
             WHERE rendezvous_id = ?1 AND expires_at > ?2"
        }
        "credential_bundle" => {
            "SELECT credential_bundle FROM pairing_sessions
             WHERE rendezvous_id = ?1 AND expires_at > ?2"
        }
        "joiner_bundle" => {
            "SELECT joiner_bundle FROM pairing_sessions
             WHERE rendezvous_id = ?1 AND expires_at > ?2"
        }
        _ => unreachable!(),
    };
    // The column may be NULL (not yet set) — query_row returns the row,
    // and row.get::<_, Option<Vec<u8>>> handles the NULL -> None mapping.
    conn.query_row(sql, params![rendezvous_id, now], |row| row.get::<_, Option<Vec<u8>>>(0))
        .optional()
        .map(|opt| opt.flatten())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairingSlotRead {
    NotSet,
    Consumed,
    Present(Vec<u8>),
}

/// Atomically read and consume a terminal pairing slot for a non-expired session.
///
/// Only `credential_bundle` and `joiner_bundle` are terminal payloads. Earlier
/// ceremony slots remain pollable because the peer may retry while waiting for
/// the next ceremony step.
pub fn take_pairing_slot(
    conn: &Connection,
    rendezvous_id: &str,
    slot: &str,
) -> Result<PairingSlotRead, rusqlite::Error> {
    let col = validate_pairing_slot(slot)?;
    let consumed_col = match col {
        "credential_bundle" => "credential_bundle_consumed_at",
        "joiner_bundle" => "joiner_bundle_consumed_at",
        _ => {
            return get_pairing_slot(conn, rendezvous_id, col).map(|value| match value {
                Some(data) => PairingSlotRead::Present(data),
                None => PairingSlotRead::NotSet,
            });
        }
    };

    let tx = conn.unchecked_transaction()?;
    let now = now_secs();
    let sql = format!(
        "SELECT {col}, {consumed_col} FROM pairing_sessions
         WHERE rendezvous_id = ?1 AND expires_at > ?2"
    );
    let current = tx
        .query_row(&sql, params![rendezvous_id, now], |row| {
            Ok((row.get::<_, Option<Vec<u8>>>(0)?, row.get::<_, Option<i64>>(1)?))
        })
        .optional()?;

    let Some((value, consumed_at)) = current else {
        tx.commit()?;
        return Ok(PairingSlotRead::NotSet);
    };

    if consumed_at.is_some() {
        tx.commit()?;
        return Ok(PairingSlotRead::Consumed);
    }

    let Some(data) = value else {
        tx.commit()?;
        return Ok(PairingSlotRead::NotSet);
    };

    let sql = format!(
        "UPDATE pairing_sessions
            SET {col} = NULL, {consumed_col} = ?1
          WHERE rendezvous_id = ?2
            AND expires_at > ?3
            AND {col} IS NOT NULL
            AND {consumed_col} IS NULL"
    );
    let changed = tx.execute(&sql, params![now, rendezvous_id, now])?;
    tx.commit()?;

    if changed == 0 {
        Ok(PairingSlotRead::Consumed)
    } else {
        Ok(PairingSlotRead::Present(data))
    }
}

/// Delete a pairing session. Returns `true` if a row was deleted.
pub fn delete_pairing_session(
    conn: &Connection,
    rendezvous_id: &str,
) -> Result<bool, rusqlite::Error> {
    let changed = conn
        .execute("DELETE FROM pairing_sessions WHERE rendezvous_id = ?1", params![rendezvous_id])?;
    Ok(changed > 0)
}

/// Delete all expired pairing sessions. Returns the number of rows deleted.
pub fn cleanup_expired_pairing_sessions(conn: &Connection) -> Result<usize, rusqlite::Error> {
    let now = now_secs();
    let deleted =
        conn.execute("DELETE FROM pairing_sessions WHERE expires_at <= ?1", params![now])?;
    Ok(deleted)
}

/// Check whether a non-expired pairing session exists for the given rendezvous ID.
pub fn pairing_session_exists(
    conn: &Connection,
    rendezvous_id: &str,
) -> Result<bool, rusqlite::Error> {
    let now = now_secs();
    conn.query_row(
        "SELECT 1 FROM pairing_sessions WHERE rendezvous_id = ?1 AND expires_at > ?2",
        params![rendezvous_id, now],
        |_| Ok(()),
    )
    .optional()
    .map(|opt| opt.is_some())
}

// ---------------------------------------------------------------------------
// Media metadata
// ---------------------------------------------------------------------------

/// Insert an immediately-committed (servable) media row.
///
/// This is the legacy/convenience path used by tests to pre-seed servable
/// media. The production upload route uses the pending→promote→finalize
/// lifecycle ([`reserve_media`] + [`finalize_media`]) instead, so an in-flight
/// upload is never servable before its file lands.
pub fn insert_media_metadata(
    conn: &Connection,
    media_id: &str,
    sync_id: &str,
    device_id: &str,
    size_bytes: i64,
    content_hash: &str,
    expires_at: Option<i64>,
) -> Result<(), rusqlite::Error> {
    let now = now_secs();
    conn.execute(
        "INSERT INTO media_metadata (media_id, sync_id, device_id, size_bytes, content_hash, created_at, expires_at, committed_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?6)",
        params![media_id, sync_id, device_id, size_bytes, content_hash, now, expires_at],
    )?;
    Ok(())
}

const MEDIA_ROW_COLUMNS: &str = "media_id, sync_id, device_id, size_bytes, content_hash, \
     created_at, expires_at, deleted_at, committed_at, reserved_at";

fn media_row_from(row: &rusqlite::Row<'_>) -> Result<MediaRow, rusqlite::Error> {
    Ok(MediaRow {
        media_id: row.get(0)?,
        sync_id: row.get(1)?,
        device_id: row.get(2)?,
        size_bytes: row.get(3)?,
        content_hash: row.get(4)?,
        created_at: row.get(5)?,
        expires_at: row.get(6)?,
        deleted_at: row.get(7)?,
        committed_at: row.get(8)?,
        reserved_at: row.get(9)?,
    })
}

pub fn get_media_metadata(
    conn: &Connection,
    sync_id: &str,
    media_id: &str,
) -> Result<Option<MediaRow>, rusqlite::Error> {
    conn.query_row(
        &format!(
            "SELECT {MEDIA_ROW_COLUMNS} FROM media_metadata WHERE sync_id = ?1 AND media_id = ?2"
        ),
        params![sync_id, media_id],
        media_row_from,
    )
    .optional()
}

/// Sum of bytes that count against a group's quota: committed-and-servable rows
/// (not soft-deleted, not past TTL) plus non-stale PENDING reserves (an
/// in-flight upload still occupies space). Expired and stale-pending rows are
/// excluded — they are about to be swept. `now`/`pending_grace_secs` define
/// "stale pending"; pass the configured grace so this matches the reaper.
pub fn get_group_media_usage_at(
    conn: &Connection,
    sync_id: &str,
    now: i64,
    pending_grace_secs: i64,
) -> Result<i64, rusqlite::Error> {
    let stale_pending_cutoff = now.saturating_sub(pending_grace_secs);
    // Two independently-gated classes count toward quota:
    //  - committed & live: not past its TTL (`expires_at` governs).
    //  - pending & non-stale: a reserve still occupying space. This is gated by
    //    `reserved_at` staleness ALONE — a pending row's `expires_at` is
    //    irrelevant (a not-yet-promoted upload still holds bytes regardless of
    //    its prospective TTL), otherwise an abandoned-but-not-yet-reaped pending
    //    row could stop counting before the reaper deletes it.
    conn.query_row(
        "SELECT COALESCE(SUM(size_bytes), 0) FROM media_metadata
         WHERE sync_id = ?1
           AND deleted_at IS NULL
           AND (
                 (committed_at IS NOT NULL AND (expires_at IS NULL OR expires_at > ?2))
              OR (committed_at IS NULL AND reserved_at >= ?3)
           )",
        params![sync_id, now, stale_pending_cutoff],
        |row| row.get(0),
    )
}

/// Back-compat wrapper: live-bytes for a group at the current time, treating
/// any pending reserve as live (grace = i64::MAX keeps callers that only need a
/// coarse "live bytes" figure working). Prefer [`get_group_media_usage_at`].
pub fn get_group_media_usage(conn: &Connection, sync_id: &str) -> Result<i64, rusqlite::Error> {
    get_group_media_usage_at(conn, sync_id, now_secs(), i64::MAX)
}

/// Live bytes of the group's *ephemeral* (TTL-bearing) media. Identical
/// accounting to [`get_group_media_usage_at`] but
/// restricted to rows with a finite `expires_at`, i.e. blobs uploaded with an
/// `X-Media-TTL` (regardless of upload class). A fresh send
/// (default retention) stores `expires_at IS NULL` and is excluded; a blob later
/// re-sent fresh has its TTL cleared (see `combine_ttl`) and correctly drops out
/// of this subset. The route uses this to enforce
/// `media_resupply_byte_ceiling_bytes` so demand-driven heal can't fill the
/// group quota faster than the short TTL sheds it.
pub fn get_group_resupply_usage_at(
    conn: &Connection,
    sync_id: &str,
    now: i64,
    pending_grace_secs: i64,
) -> Result<i64, rusqlite::Error> {
    let stale_pending_cutoff = now.saturating_sub(pending_grace_secs);
    conn.query_row(
        "SELECT COALESCE(SUM(size_bytes), 0) FROM media_metadata
         WHERE sync_id = ?1
           AND deleted_at IS NULL
           AND expires_at IS NOT NULL
           AND (
                 (committed_at IS NOT NULL AND expires_at > ?2)
              OR (committed_at IS NULL AND reserved_at >= ?3)
           )",
        params![sync_id, now, stale_pending_cutoff],
        |row| row.get(0),
    )
}

/// The decision produced by [`reserve_media_upload`] inside the reserve txn.
/// The route maps it to the on-disk action and the HTTP outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReserveOutcome {
    /// A fresh PENDING reserve is in place (insert or resurrect). The staged
    /// file must be promoted, then [`finalize_media`] called. Counts toward
    /// quota now. → HTTP 200 (committed) once promoted.
    ReservedPending,
    /// Existing committed-live row whose final file is MISSING: repair. The row
    /// stays committed (Δquota 0); promote the staged file then call
    /// [`finalize_media`] (an idempotent re-commit). → HTTP 200 (committed).
    RepairCommitted,
    /// Existing committed-live row with its file present: pure idempotent. The
    /// TTL was refreshed to max(old, new). Drop the staged file; do NOT promote.
    /// → HTTP 200 (committed).
    AlreadyServable,
    /// Another writer holds a PENDING reserve for this `media_id`. Drop staging;
    /// no success side effects. → HTTP 202 (in-progress).
    PendingInFlight,
    /// This insert/resurrect would exceed the group quota. → HTTP 507.
    QuotaExceeded,
    /// A different `content_hash` already exists for this `media_id`. → HTTP 409.
    HashConflict,
}

/// Combine an existing TTL with a newly-requested one, keeping the
/// longer-lived. `None` means "default retention" (no per-blob expiry), which
/// outlives any concrete TTL, so it dominates.
fn combine_ttl(old: Option<i64>, new: Option<i64>) -> Option<i64> {
    match (old, new) {
        (Some(a), Some(b)) => Some(a.max(b)),
        _ => None,
    }
}

/// Resolve the idempotent-upsert case table for a media upload and, for the
/// insert/resurrect/repair cases, write the PENDING/TTL state. MUST run inside
/// the caller's `IMMEDIATE` transaction so same-`media_id` writers serialize.
///
/// `final_file_present` is the route's disk check for this `media_id`'s final
/// path; it only matters for the committed-live branch (idempotent vs repair).
#[allow(clippy::too_many_arguments)]
pub fn reserve_media_upload(
    tx: &Connection,
    media_id: &str,
    sync_id: &str,
    device_id: &str,
    size_bytes: i64,
    content_hash: &str,
    new_expires_at: Option<i64>,
    quota_bytes: i64,
    now: i64,
    pending_grace_secs: i64,
    final_file_present: bool,
) -> Result<ReserveOutcome, rusqlite::Error> {
    let existing = get_media_metadata(tx, sync_id, media_id)?;

    let Some(row) = existing else {
        // No row → fresh insert. Δquota +size.
        let usage = get_group_media_usage_at(tx, sync_id, now, pending_grace_secs)?;
        if usage + size_bytes > quota_bytes {
            return Ok(ReserveOutcome::QuotaExceeded);
        }
        tx.execute(
            "INSERT INTO media_metadata
                 (media_id, sync_id, device_id, size_bytes, content_hash,
                  created_at, expires_at, deleted_at, committed_at, reserved_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, NULL, ?6)",
            params![media_id, sync_id, device_id, size_bytes, content_hash, now, new_expires_at],
        )?;
        return Ok(ReserveOutcome::ReservedPending);
    };

    // A different content for the same id is a hard conflict in every state
    // within the same sync group.
    if row.content_hash != content_hash {
        return Ok(ReserveOutcome::HashConflict);
    }

    // Same hash. An in-flight reserve owned by another writer ⇒ back off.
    if row.is_pending() {
        return Ok(ReserveOutcome::PendingInFlight);
    }

    let soft_deleted = row.deleted_at.is_some();
    let expired = row.expires_at.map(|exp| exp <= now).unwrap_or(false);

    if soft_deleted || expired {
        // Resurrect: the row currently does NOT count toward quota, so this
        // re-adds its bytes. Δquota +size.
        let usage = get_group_media_usage_at(tx, sync_id, now, pending_grace_secs)?;
        if usage + size_bytes > quota_bytes {
            return Ok(ReserveOutcome::QuotaExceeded);
        }
        tx.execute(
            "UPDATE media_metadata
                 SET device_id = ?3, size_bytes = ?4, content_hash = ?5,
                     created_at = ?6, expires_at = ?7,
                     deleted_at = NULL, committed_at = NULL, reserved_at = ?6
             WHERE sync_id = ?1 AND media_id = ?2",
            params![sync_id, media_id, device_id, size_bytes, content_hash, now, new_expires_at],
        )?;
        return Ok(ReserveOutcome::ReservedPending);
    }

    // Committed-live, same hash: idempotent (file present) or repair (missing).
    // Δquota 0 either way; refresh the TTL to the longer-lived value.
    let refreshed = combine_ttl(row.expires_at, new_expires_at);
    tx.execute(
        "UPDATE media_metadata SET expires_at = ?3 WHERE sync_id = ?1 AND media_id = ?2",
        params![sync_id, media_id, refreshed],
    )?;
    if final_file_present {
        Ok(ReserveOutcome::AlreadyServable)
    } else {
        Ok(ReserveOutcome::RepairCommitted)
    }
}

/// Mark a reserved row committed (servable) after its file has been promoted.
/// Idempotent: re-running on an already-committed row just refreshes
/// `committed_at`.
pub fn finalize_media(
    conn: &Connection,
    sync_id: &str,
    media_id: &str,
    now: i64,
) -> Result<(), rusqlite::Error> {
    conn.execute(
        "UPDATE media_metadata
            SET committed_at = ?3, reserved_at = NULL
          WHERE sync_id = ?1 AND media_id = ?2",
        params![sync_id, media_id, now],
    )?;
    Ok(())
}

/// Delete a row ONLY if it is still an uncommitted reserve. Used on the upload
/// error path to remove a [`ReserveOutcome::ReservedPending`] row whose promote
/// or finalize failed. The `committed_at IS NULL` guard makes it impossible to
/// drop a committed row (e.g. a repair that races a concurrent finalize).
pub fn delete_pending_media_row(
    conn: &Connection,
    sync_id: &str,
    media_id: &str,
) -> Result<(), rusqlite::Error> {
    conn.execute(
        "DELETE FROM media_metadata
          WHERE sync_id = ?1 AND media_id = ?2 AND committed_at IS NULL",
        params![sync_id, media_id],
    )?;
    Ok(())
}

/// Mark up to `limit` of a group's expired (committed, past-TTL) rows deleted in
/// one set-based UPDATE and return their `media_id`s so the caller can unlink
/// the files. Bounded so a single upload's always-sweep can't do unbounded
/// work; the cleanup loop is the catch-all backstop. Excludes pending rows
/// (`committed_at IS NULL`) so it never reaps an in-flight reserve.
pub fn sweep_expired_media_for_group(
    conn: &Connection,
    sync_id: &str,
    now: i64,
    limit: u32,
) -> Result<Vec<String>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "UPDATE media_metadata SET deleted_at = ?2
         WHERE sync_id = ?1
           AND media_id IN (
             SELECT media_id FROM media_metadata
             WHERE sync_id = ?1
               AND deleted_at IS NULL
               AND committed_at IS NOT NULL
               AND expires_at IS NOT NULL
               AND expires_at <= ?2
             LIMIT ?3
         )
         RETURNING media_id",
    )?;
    let ids: Vec<String> = stmt
        .query_map(params![sync_id, now, limit], |row| row.get(0))?
        .filter_map(|r| r.ok())
        .collect();
    Ok(ids)
}

pub fn mark_media_deleted(
    conn: &Connection,
    sync_id: &str,
    media_id: &str,
) -> Result<(), rusqlite::Error> {
    let now = now_secs();
    conn.execute(
        "UPDATE media_metadata SET deleted_at = ?1 WHERE sync_id = ?2 AND media_id = ?3",
        params![now, sync_id, media_id],
    )?;
    Ok(())
}

/// Find committed media that has exceeded retention and mark it deleted.
/// Returns the (sync_id, media_id) pairs for disk cleanup. Only touches
/// COMMITTED rows: in-flight/abandoned PENDING reserves are owned by
/// [`reap_stale_pending_media`], so this can never race a live upload.
///
/// Retention is governed per blob: a blob WITH a per-blob `expires_at` (a
/// short-TTL re-supply / pairing push) lives exactly until its TTL — the legacy
/// `created_at` floor does NOT apply, because a re-supply only refreshes
/// `expires_at`, and applying the `created_at` floor too would delete a
/// long-tail blob right after it was healed (its `created_at` may be years old
/// while its TTL is hours in the future). A blob WITHOUT a TTL (default
/// retention) is governed by the global `retention_days` `created_at` floor.
pub fn cleanup_expired_media(
    conn: &Connection,
    retention_days: u64,
) -> Result<Vec<(String, String)>, rusqlite::Error> {
    let now = now_secs();
    let cutoff = now - (retention_days * 86400) as i64;
    let mut stmt = conn.prepare(
        "UPDATE media_metadata SET deleted_at = ?1
         WHERE deleted_at IS NULL
           AND committed_at IS NOT NULL
           AND (
                 (expires_at IS NOT NULL AND expires_at <= ?1)
              OR (expires_at IS NULL AND created_at < ?2)
           )
         RETURNING sync_id, media_id",
    )?;
    let pairs: Vec<(String, String)> = stmt
        .query_map(params![now, cutoff], |row| Ok((row.get(0)?, row.get(1)?)))?
        .filter_map(|r| r.ok())
        .collect();
    Ok(pairs)
}

/// Filter a soft-delete sweep's `(sync_id, media_id)` pairs down to those still
/// safe to unlink — the row is gone, or still `deleted_at IS NOT NULL`. Drops
/// any pair a concurrent heal RESURRECTED (`reserve_media_upload` cleared
/// `deleted_at` and promoted a fresh file) in the gap between the soft-delete
/// txn ([`cleanup_expired_media`]) and the actual unlink, so cleanup can never
/// delete a freshly-committed file. A genuinely-stale file we conservatively
/// skip (e.g. on a transient query error) is reclaimed later by the orphan
/// sweep. Best-effort; the race window is tiny.
pub fn retain_unlinkable_media(
    conn: &Connection,
    pairs: &[(String, String)],
) -> Vec<(String, String)> {
    pairs
        .iter()
        .filter(|(sync_id, media_id)| {
            match conn.query_row(
                "SELECT deleted_at FROM media_metadata WHERE sync_id = ?1 AND media_id = ?2",
                params![sync_id, media_id],
                |row| row.get::<_, Option<i64>>(0),
            ) {
                Ok(Some(_)) => true, // still soft-deleted → safe to unlink
                Ok(None) => false,   // resurrected (deleted_at NULL) → keep the file
                Err(rusqlite::Error::QueryReturnedNoRows) => true, // row gone → unlink
                Err(_) => false,     // unknown → skip; the orphan sweep backstops
            }
        })
        .cloned()
        .collect()
}

/// Reap abandoned PENDING reserves: rows whose promote never finished
/// (`committed_at IS NULL`) and whose reserve is older than the grace window
/// (`reserved_at < now - grace`). Hard-deletes the rows and returns
/// (sync_id, media_id) pairs so the caller can unlink any leftover staging
/// AND final files. Grace must be ≫ a normal promote so a healthy in-flight
/// upload is never reaped.
pub fn reap_stale_pending_media(
    conn: &Connection,
    grace_secs: i64,
) -> Result<Vec<(String, String)>, rusqlite::Error> {
    let cutoff = now_secs() - grace_secs;
    let mut stmt = conn.prepare(
        "DELETE FROM media_metadata
         WHERE committed_at IS NULL
           AND reserved_at IS NOT NULL
           AND reserved_at < ?1
         RETURNING sync_id, media_id",
    )?;
    let pairs: Vec<(String, String)> = stmt
        .query_map(params![cutoff], |row| Ok((row.get(0)?, row.get(1)?)))?
        .filter_map(|r| r.ok())
        .collect();
    Ok(pairs)
}

/// Return `(sync_id, media_id)` for every NON-deleted row (committed or pending)
/// — the set of final files that legitimately back a row. Used by the
/// orphan-file sweep: any final file NOT in this set is reclaimable. Soft-
/// deleted rows are EXCLUDED so that a file whose unlink failed at soft-delete
/// time (transient FS error) is later reclaimed as an orphan rather than leaked
/// forever (`cleanup_expired_media` never revisits a `deleted_at IS NOT NULL`
/// row).
pub fn all_media_keys(conn: &Connection) -> Result<Vec<(String, String)>, rusqlite::Error> {
    let mut stmt =
        conn.prepare("SELECT sync_id, media_id FROM media_metadata WHERE deleted_at IS NULL")?;
    let pairs: Vec<(String, String)> =
        stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?.filter_map(|r| r.ok()).collect();
    Ok(pairs)
}

/// Return the subset of `media_ids` (scoped to `sync_id`) that the relay
/// considers servable at the metadata level — committed, not soft-deleted, not
/// past TTL — for the `batch-exists` endpoint. Metadata-only is sound after
/// the reconciliation sweep repairs legacy file-missing crash rows; heal callers
/// tolerate residual divergence by retrying after download 404s.
///
/// `media_ids` MUST be bounded by the caller (the route caps the request size).
pub fn servable_media_subset(
    conn: &Connection,
    sync_id: &str,
    media_ids: &[String],
    now: i64,
) -> Result<Vec<String>, rusqlite::Error> {
    if media_ids.is_empty() {
        return Ok(Vec::new());
    }
    use rusqlite::types::Value;
    // ?1 = sync_id, ?2 = now, ?3.. = each media_id.
    let placeholders: Vec<String> = (0..media_ids.len()).map(|i| format!("?{}", i + 3)).collect();
    let sql = format!(
        "SELECT media_id FROM media_metadata
         WHERE sync_id = ?1
           AND committed_at IS NOT NULL
           AND deleted_at IS NULL
           AND (expires_at IS NULL OR expires_at > ?2)
           AND media_id IN ({})",
        placeholders.join(", ")
    );
    let mut params: Vec<Value> = Vec::with_capacity(media_ids.len() + 2);
    params.push(Value::Text(sync_id.to_string()));
    params.push(Value::Integer(now));
    for id in media_ids {
        params.push(Value::Text(id.clone()));
    }
    let mut stmt = conn.prepare(&sql)?;
    let present: Vec<String> = stmt
        .query_map(rusqlite::params_from_iter(params.iter()), |row| row.get(0))?
        .filter_map(|r| r.ok())
        .collect();
    Ok(present)
}

/// List every row the relay currently considers servable at the metadata level
/// (committed, not soft-deleted, not past TTL) — i.e. the rows download and
/// batch-exists would claim are present. The reconciliation sweep cross-checks
/// these against on-disk files to find legacy "metadata then file" crash rows.
///
/// PENDING reserves (`committed_at IS NULL`) are excluded, so reconciliation can
/// never touch an in-flight upload (the reconciliation-vs-promote race guard).
pub fn list_servable_committed_media(
    conn: &Connection,
    now: i64,
) -> Result<Vec<(String, String)>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT sync_id, media_id FROM media_metadata
         WHERE committed_at IS NOT NULL
           AND deleted_at IS NULL
           AND (expires_at IS NULL OR expires_at > ?1)",
    )?;
    let pairs: Vec<(String, String)> = stmt
        .query_map(params![now], |row| Ok((row.get(0)?, row.get(1)?)))?
        .filter_map(|r| r.ok())
        .collect();
    Ok(pairs)
}

/// Delete all media metadata rows for a sync group.
/// Returns the media_ids for disk cleanup.
pub fn delete_media_for_sync_group(
    conn: &Connection,
    sync_id: &str,
) -> Result<Vec<String>, rusqlite::Error> {
    let mut stmt = conn.prepare("SELECT media_id FROM media_metadata WHERE sync_id = ?1")?;
    let media_ids: Vec<String> =
        stmt.query_map(params![sync_id], |row| row.get(0))?.filter_map(|r| r.ok()).collect();

    conn.execute("DELETE FROM media_metadata WHERE sync_id = ?1", params![sync_id])?;

    Ok(media_ids)
}

// ---------------------------------------------------------------------------
// Counters (persistent metrics)
// ---------------------------------------------------------------------------

/// Load persisted counter values from SQLite. Returns a map of name → value.
pub fn load_counters(conn: &Connection) -> Result<HashMap<String, u64>, rusqlite::Error> {
    let mut stmt = conn.prepare("SELECT name, value FROM counters")?;
    let rows = stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?)))?;
    let mut map = HashMap::new();
    for row in rows {
        let (name, value) = row?;
        map.insert(name, value);
    }
    Ok(map)
}

/// Flush current counter values to SQLite (upsert).
pub fn flush_counters(conn: &Connection, values: &[(&str, u64)]) -> Result<(), rusqlite::Error> {
    let mut stmt = conn.prepare(
        "INSERT INTO counters (name, value) VALUES (?1, ?2)
         ON CONFLICT(name) DO UPDATE SET value = ?2",
    )?;
    for (name, value) in values {
        stmt.execute(params![name, value])?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Sharing identity bundles
// ---------------------------------------------------------------------------

pub fn upsert_sharing_identity(
    conn: &Connection,
    sharing_id: &str,
    bundle: &[u8],
    identity_generation: u32,
    now: i64,
) -> Result<bool, rusqlite::Error> {
    let tx = conn.unchecked_transaction()?;
    let bundle_hash = hash_bytes(bundle);

    let floor: Option<(u32, Option<String>)> = tx
        .query_row(
            "SELECT max_identity_generation, identity_bundle_hash
               FROM sharing_identity_generation_floors
              WHERE sharing_id = ?1",
            params![sharing_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;

    if floor
        .as_ref()
        .is_some_and(|(current_generation, _)| identity_generation < *current_generation)
    {
        tx.rollback()?;
        return Ok(false);
    }

    if floor.as_ref().is_some_and(|(current_generation, current_hash)| {
        identity_generation == *current_generation
            && current_hash.as_deref().is_some_and(|hash| hash != bundle_hash.as_str())
    }) {
        tx.rollback()?;
        return Ok(false);
    }

    tx.execute(
        "INSERT INTO sharing_identity_generation_floors
             (sharing_id, max_identity_generation, identity_bundle_hash, updated_at)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(sharing_id) DO UPDATE SET
             max_identity_generation =
                 MAX(
                     sharing_identity_generation_floors.max_identity_generation,
                     excluded.max_identity_generation
                 ),
             identity_bundle_hash = CASE
                 WHEN excluded.max_identity_generation
                      > sharing_identity_generation_floors.max_identity_generation
                 THEN excluded.identity_bundle_hash
                 WHEN excluded.max_identity_generation
                      = sharing_identity_generation_floors.max_identity_generation
                 THEN COALESCE(
                      sharing_identity_generation_floors.identity_bundle_hash,
                      excluded.identity_bundle_hash
                 )
                 ELSE sharing_identity_generation_floors.identity_bundle_hash
             END,
             updated_at = MAX(
                 sharing_identity_generation_floors.updated_at,
                 excluded.updated_at
             )",
        params![sharing_id, identity_generation, bundle_hash, now],
    )?;

    tx.execute(
        "INSERT INTO sharing_identity_bundles
            (sharing_id, identity_bundle, identity_generation, updated_at)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(sharing_id) DO UPDATE SET
            identity_bundle = excluded.identity_bundle,
            identity_generation = excluded.identity_generation,
            updated_at = excluded.updated_at",
        params![sharing_id, bundle, identity_generation, now],
    )?;

    tx.commit()?;
    Ok(true)
}

pub fn get_sharing_identity(
    conn: &Connection,
    sharing_id: &str,
) -> Result<Option<Vec<u8>>, rusqlite::Error> {
    conn.query_row(
        "SELECT identity_bundle FROM sharing_identity_bundles WHERE sharing_id = ?1",
        params![sharing_id],
        |row| row.get(0),
    )
    .optional()
}

pub fn delete_sharing_identity(conn: &Connection, sharing_id: &str) -> Result<(), rusqlite::Error> {
    conn.execute(
        "DELETE FROM sharing_identity_bundles WHERE sharing_id = ?1",
        params![sharing_id],
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Sharing signed prekeys
// ---------------------------------------------------------------------------

pub fn upsert_sharing_prekey(
    conn: &Connection,
    sharing_id: &str,
    device_id: &str,
    prekey_id: &str,
    bundle: &[u8],
    created_at: i64,
) -> Result<(), rusqlite::Error> {
    conn.execute(
        "INSERT INTO sharing_signed_prekeys (sharing_id, device_id, prekey_id, prekey_bundle, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(sharing_id, device_id) DO UPDATE SET
            prekey_id = excluded.prekey_id,
            prekey_bundle = excluded.prekey_bundle,
            created_at = excluded.created_at",
        params![sharing_id, device_id, prekey_id, bundle, created_at],
    )?;
    Ok(())
}

/// Returns (device_id, prekey_id, prekey_bundle, created_at) for the most
/// recently created prekey belonging to an active device.
#[allow(clippy::type_complexity)]
pub fn get_best_sharing_prekey(
    conn: &Connection,
    sharing_id: &str,
) -> Result<Option<(String, String, Vec<u8>, i64)>, rusqlite::Error> {
    // Look up the sync_id for this sharing_id, then join against devices
    // to only return prekeys from active devices.
    conn.query_row(
        "SELECT sp.device_id, sp.prekey_id, sp.prekey_bundle, sp.created_at
         FROM sharing_signed_prekeys sp
         INNER JOIN sharing_id_mappings sm ON sm.sharing_id = sp.sharing_id
         INNER JOIN devices d ON d.sync_id = sm.sync_id AND d.device_id = sp.device_id
         WHERE sp.sharing_id = ?1
           AND d.status = 'active'
         ORDER BY sp.created_at DESC
         LIMIT 1",
        params![sharing_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )
    .optional()
}

/// Delete prekeys older than `max_age_secs` and return the number removed.
pub fn cleanup_stale_sharing_prekeys(
    conn: &Connection,
    max_age_secs: i64,
) -> Result<usize, rusqlite::Error> {
    let cutoff = now_secs() - max_age_secs;
    let deleted =
        conn.execute("DELETE FROM sharing_signed_prekeys WHERE created_at < ?1", params![cutoff])?;
    Ok(deleted)
}

pub fn delete_sharing_prekeys(conn: &Connection, sharing_id: &str) -> Result<(), rusqlite::Error> {
    conn.execute("DELETE FROM sharing_signed_prekeys WHERE sharing_id = ?1", params![sharing_id])?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Sharing ID mappings
// ---------------------------------------------------------------------------

/// Upsert a sync_id <-> sharing_id binding. Returns `true` if the mapping is
/// new or unchanged, `false` if there is a conflict (sync_id already maps to a
/// different sharing_id, or sharing_id already maps to a different sync_id).
pub fn upsert_sharing_id_mapping(
    conn: &Connection,
    sync_id: &str,
    sharing_id: &str,
) -> Result<bool, rusqlite::Error> {
    // Check for existing mapping by sync_id
    let existing_by_sync: Option<String> = conn
        .query_row(
            "SELECT sharing_id FROM sharing_id_mappings WHERE sync_id = ?1",
            params![sync_id],
            |row| row.get(0),
        )
        .optional()?;

    if let Some(ref existing) = existing_by_sync {
        if existing != sharing_id {
            return Ok(false); // sync_id maps to different sharing_id
        }
        return Ok(true); // same mapping already exists
    }

    // Check for existing mapping by sharing_id (unique index)
    let existing_by_sharing: Option<String> = conn
        .query_row(
            "SELECT sync_id FROM sharing_id_mappings WHERE sharing_id = ?1",
            params![sharing_id],
            |row| row.get(0),
        )
        .optional()?;

    if let Some(ref existing) = existing_by_sharing {
        if existing != sync_id {
            return Ok(false); // sharing_id maps to different sync_id
        }
        return Ok(true); // same mapping
    }

    // New mapping
    conn.execute(
        "INSERT INTO sharing_id_mappings (sync_id, sharing_id) VALUES (?1, ?2)",
        params![sync_id, sharing_id],
    )?;
    Ok(true)
}

pub fn get_sharing_id_for_sync(
    conn: &Connection,
    sync_id: &str,
) -> Result<Option<String>, rusqlite::Error> {
    conn.query_row(
        "SELECT sharing_id FROM sharing_id_mappings WHERE sync_id = ?1",
        params![sync_id],
        |row| row.get(0),
    )
    .optional()
}

pub fn get_sync_id_for_sharing_id(
    conn: &Connection,
    sharing_id: &str,
) -> Result<Option<String>, rusqlite::Error> {
    conn.query_row(
        "SELECT sync_id FROM sharing_id_mappings WHERE sharing_id = ?1",
        params![sharing_id],
        |row| row.get(0),
    )
    .optional()
}

// ---------------------------------------------------------------------------
// Sharing-init payloads
// ---------------------------------------------------------------------------

/// Insert a sharing-init payload. Returns `false` if the init_id already exists.
pub fn insert_sharing_init(
    conn: &Connection,
    init_id: &str,
    recipient_id: &str,
    sender_id: &str,
    payload: &[u8],
    ttl_secs: u64,
) -> Result<bool, rusqlite::Error> {
    let now = now_secs();
    let expires_at = now + ttl_secs as i64;
    let rows = conn.execute(
        "INSERT OR IGNORE INTO sharing_init_payloads
         (init_id, recipient_id, sender_id, payload, created_at, consumed_at, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6)",
        params![init_id, recipient_id, sender_id, payload, now, expires_at],
    )?;
    Ok(rows > 0)
}

/// Atomically select and consume all pending (unconsumed, unexpired) sharing-inits
/// for a recipient. Sets `consumed_at = now` on the returned rows.
pub fn fetch_and_consume_pending_sharing_inits(
    conn: &Connection,
    recipient_id: &str,
) -> Result<Vec<PendingSharingInit>, rusqlite::Error> {
    let now = now_secs();
    let tx = conn.unchecked_transaction()?;

    let results: Vec<PendingSharingInit> = {
        let mut stmt = tx.prepare(
            "SELECT init_id, sender_id, payload, created_at
             FROM sharing_init_payloads
             WHERE recipient_id = ?1
               AND consumed_at IS NULL
               AND expires_at > ?2
             ORDER BY created_at ASC, init_id ASC",
        )?;
        let rows = stmt
            .query_map(params![recipient_id, now], |row| {
                Ok(PendingSharingInit {
                    init_id: row.get(0)?,
                    sender_id: row.get(1)?,
                    payload: row.get(2)?,
                    created_at: row.get(3)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows
    };

    if !results.is_empty() {
        let placeholders = std::iter::repeat_n("?", results.len()).collect::<Vec<_>>().join(", ");
        let sql = format!(
            "UPDATE sharing_init_payloads
             SET consumed_at = ?
             WHERE init_id IN ({placeholders})"
        );

        let mut params: Vec<&dyn ToSql> = Vec::with_capacity(results.len() + 1);
        params.push(&now);
        for pending in &results {
            params.push(&pending.init_id);
        }

        tx.execute(&sql, params_from_iter(params))?;
    }

    tx.commit()?;
    Ok(results)
}

pub fn count_pending_sharing_inits(
    conn: &Connection,
    recipient_id: &str,
) -> Result<u32, rusqlite::Error> {
    let now = now_secs();
    conn.query_row(
        "SELECT COUNT(*) FROM sharing_init_payloads
         WHERE recipient_id = ?1
           AND consumed_at IS NULL
           AND expires_at > ?2",
        params![recipient_id, now],
        |row| row.get(0),
    )
}

/// Delete payload rows after their original replay window has expired.
/// Consumed rows are retained until `expires_at` so their `init_id`s continue
/// to reject replay for the full sharing-init TTL.
pub fn cleanup_expired_sharing_init_payloads(conn: &Connection) -> Result<usize, rusqlite::Error> {
    let now = now_secs();
    let rows = conn.execute(
        "DELETE FROM sharing_init_payloads
         WHERE expires_at <= ?1",
        params![now],
    )?;
    Ok(rows)
}

// ---------------------------------------------------------------------------
// Ephemeral signal lane / device-message mailbox
// ---------------------------------------------------------------------------

/// One pending mailbox message returned to a draining recipient.
#[derive(Debug, Clone)]
pub struct PendingDeviceMessage {
    pub message_id: String,
    pub sender_device_id: String,
    pub recipient_device_id: Option<String>,
    pub epoch_id: i64,
    pub payload: Vec<u8>,
    pub created_at: i64,
}

/// Outcome of an attempted mailbox send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceMessageSendOutcome {
    /// A new row was stored.
    Stored,
    /// An identical `(sync_id, message_id)` already existed — coalesced, no new
    /// storage. A success for the caller (the dedup key did its job).
    Coalesced,
    /// The sender already holds `max_pending` non-expired messages; rejected.
    PendingCapExceeded,
}

/// Insert one ephemeral mailbox message, deduping on the composite
/// `(sync_id, message_id)` PRIMARY KEY (`INSERT OR IGNORE`). A genuinely new id
/// is stored; an identical id coalesces with no new storage.
///
/// The per-sender pending-count cap is enforced **after** a successful insert
/// (and only for a genuinely new row), so a benign re-send of an already-stored
/// message never trips the cap. Runs in one transaction; the relay serialises
/// writes on a single writer connection, so the insert-then-count is atomic.
#[allow(clippy::too_many_arguments)]
pub fn insert_device_message(
    conn: &Connection,
    sync_id: &str,
    message_id: &str,
    sender_device_id: &str,
    recipient_device_id: Option<&str>,
    epoch_id: i64,
    payload: &[u8],
    ttl_secs: u64,
    max_pending: u32,
) -> Result<DeviceMessageSendOutcome, rusqlite::Error> {
    let now = now_secs();
    let expires_at = now + ttl_secs as i64;
    let tx = conn.unchecked_transaction()?;
    let inserted = tx.execute(
        "INSERT OR IGNORE INTO device_messages
         (sync_id, message_id, sender_device_id, recipient_device_id, epoch_id, payload, created_at, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![sync_id, message_id, sender_device_id, recipient_device_id, epoch_id, payload, now, expires_at],
    )?;
    if inserted == 0 {
        tx.commit()?;
        return Ok(DeviceMessageSendOutcome::Coalesced);
    }
    let pending: u32 = tx.query_row(
        "SELECT COUNT(*) FROM device_messages
         WHERE sync_id = ?1 AND sender_device_id = ?2 AND expires_at > ?3",
        params![sync_id, sender_device_id, now],
        |row| row.get(0),
    )?;
    if pending > max_pending {
        tx.rollback()?;
        return Ok(DeviceMessageSendOutcome::PendingCapExceeded);
    }
    tx.commit()?;
    Ok(DeviceMessageSendOutcome::Stored)
}

/// Fetch the pending mailbox for `device_id` in `sync_id`: messages addressed to
/// this device or broadcast (`recipient_device_id IS NULL`), not sent by it, not
/// expired, and not yet acked by it. Read-only — the ack is a separate explicit
/// call so a broadcast stays visible to the *other* recipients (the per-device
/// ack table is what makes that safe). Bounded by `limit`.
pub fn fetch_pending_device_messages(
    conn: &Connection,
    sync_id: &str,
    device_id: &str,
    limit: u32,
) -> Result<Vec<PendingDeviceMessage>, rusqlite::Error> {
    let now = now_secs();
    let mut stmt = conn.prepare(
        "SELECT message_id, sender_device_id, recipient_device_id, epoch_id, payload, created_at
         FROM device_messages m
         WHERE m.sync_id = ?1
           AND m.expires_at > ?2
           AND m.sender_device_id != ?3
           AND (m.recipient_device_id IS NULL OR m.recipient_device_id = ?3)
           AND NOT EXISTS (
               SELECT 1 FROM device_message_acks a
               WHERE a.sync_id = m.sync_id AND a.message_id = m.message_id AND a.device_id = ?3
           )
         ORDER BY m.created_at ASC, m.message_id ASC
         LIMIT ?4",
    )?;
    let rows = stmt
        .query_map(params![sync_id, now, device_id, limit], |row| {
            Ok(PendingDeviceMessage {
                message_id: row.get(0)?,
                sender_device_id: row.get(1)?,
                recipient_device_id: row.get(2)?,
                epoch_id: row.get(3)?,
                payload: row.get(4)?,
                created_at: row.get(5)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Record this device's acks for `message_ids`. Only acks referencing a message
/// that actually exists in this group are inserted (`WHERE EXISTS …`), so a
/// client cannot grow the ack table with arbitrary ids. Idempotent
/// (`INSERT OR IGNORE`). Returns the number of new ack rows written.
pub fn ack_device_messages(
    conn: &Connection,
    sync_id: &str,
    device_id: &str,
    message_ids: &[String],
) -> Result<usize, rusqlite::Error> {
    if message_ids.is_empty() {
        return Ok(0);
    }
    let now = now_secs();
    let tx = conn.unchecked_transaction()?;
    let mut acked = 0usize;
    {
        let mut stmt = tx.prepare(
            "INSERT OR IGNORE INTO device_message_acks (sync_id, message_id, device_id, acked_at)
             SELECT ?1, ?2, ?3, ?4
             WHERE EXISTS (
                 SELECT 1 FROM device_messages WHERE sync_id = ?1 AND message_id = ?2
             )",
        )?;
        for mid in message_ids {
            acked += stmt.execute(params![sync_id, mid, device_id, now])?;
        }
    }
    tx.commit()?;
    Ok(acked)
}

/// Sweep the mailbox: delete messages past their TTL or already fully acked,
/// then drop orphaned ack rows. Returns the number of messages deleted. The
/// short TTL is the primary bound; fully-acked deletion sheds the working set
/// earlier.
///
/// "Fully acked" means:
/// - **targeted** (`recipient_device_id` set) ⇒ that recipient has an ack row;
/// - **broadcast** (`recipient_device_id IS NULL`) ⇒ at least one eligible
///   recipient exists and *every* eligible (currently-active, non-sender) device
///   has an ack row. The condition is phrased over the device set, NOT a raw ack
///   count, so a sender acking its own broadcast — or a since-revoked device's
///   ack — can't satisfy it early and shed the message before a real recipient
///   drains it. The basis is the *current* active device set, so a recipient
///   revoked after acking only lowers the bar (it's gone — still safe), and the
///   short TTL is the real bound. A device that joins after a broadcast never
///   acks it, so the message just lingers until its TTL — fine for an advisory /
///   lossy-OK lane.
pub fn cleanup_expired_device_messages(conn: &Connection) -> Result<usize, rusqlite::Error> {
    let now = now_secs();
    let tx = conn.unchecked_transaction()?;
    let deleted = tx.execute(
        "DELETE FROM device_messages
         WHERE expires_at <= ?1
            OR (
                recipient_device_id IS NOT NULL
                AND EXISTS (
                    SELECT 1 FROM device_message_acks a
                    WHERE a.sync_id = device_messages.sync_id
                      AND a.message_id = device_messages.message_id
                      AND a.device_id = device_messages.recipient_device_id
                )
            )
            OR (
                recipient_device_id IS NULL
                -- At least one eligible recipient exists (don't shed an
                -- undeliverable broadcast early; its TTL handles that).
                AND EXISTS (
                    SELECT 1 FROM devices d
                    WHERE d.sync_id = device_messages.sync_id
                      AND d.status = 'active'
                      AND d.device_id != device_messages.sender_device_id
                )
                -- ...and no eligible recipient is still missing an ack. Phrased
                -- over the device set so a sender self-ack or a non-active
                -- device's ack can never satisfy it.
                AND NOT EXISTS (
                    SELECT 1 FROM devices d
                    WHERE d.sync_id = device_messages.sync_id
                      AND d.status = 'active'
                      AND d.device_id != device_messages.sender_device_id
                      AND NOT EXISTS (
                          SELECT 1 FROM device_message_acks a
                          WHERE a.sync_id = device_messages.sync_id
                            AND a.message_id = device_messages.message_id
                            AND a.device_id = d.device_id
                      )
                )
            )",
        params![now],
    )?;
    // Drop ack rows whose message is gone (expired, fully-acked above, or the
    // group was pruned out from under them).
    tx.execute(
        "DELETE FROM device_message_acks
         WHERE NOT EXISTS (
             SELECT 1 FROM device_messages m
             WHERE m.sync_id = device_message_acks.sync_id
               AND m.message_id = device_message_acks.message_id
         )",
        [],
    )?;
    tx.commit()?;
    Ok(deleted)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db() -> Database {
        Database::in_memory().expect("failed to create in-memory db")
    }

    #[test]
    fn pragmas_set_on_writer_connection() {
        let db = Database::in_memory().expect("failed to create in-memory db");
        db.with_conn(|conn| {
            let cell_size_check: i64 =
                conn.pragma_query_value(None, "cell_size_check", |r| r.get(0))?;
            let autocheckpoint: i64 =
                conn.pragma_query_value(None, "wal_autocheckpoint", |r| r.get(0))?;
            let size_limit: i64 =
                conn.pragma_query_value(None, "journal_size_limit", |r| r.get(0))?;
            assert_eq!(cell_size_check, 1, "cell_size_check should be ON");
            assert_eq!(autocheckpoint, 1000);
            assert_eq!(size_limit, 67_108_864);
            Ok::<_, rusqlite::Error>(())
        })
        .unwrap();
    }

    #[test]
    fn pragmas_set_on_reader_connection() {
        let db = Database::in_memory().expect("failed to create in-memory db");
        db.with_read_conn(|conn| {
            let cell_size_check: i64 =
                conn.pragma_query_value(None, "cell_size_check", |r| r.get(0))?;
            let autocheckpoint: i64 =
                conn.pragma_query_value(None, "wal_autocheckpoint", |r| r.get(0))?;
            let size_limit: i64 =
                conn.pragma_query_value(None, "journal_size_limit", |r| r.get(0))?;
            // query_only is already verified by other tests; this is additive.
            assert_eq!(cell_size_check, 1);
            assert_eq!(autocheckpoint, 1000);
            assert_eq!(size_limit, 67_108_864);
            Ok::<_, rusqlite::Error>(())
        })
        .unwrap();
    }

    #[test]
    fn test_create_sync_group_and_get_epoch() {
        let db = test_db();
        db.with_conn(|conn| {
            create_sync_group(conn, "sg1", 0)?;
            let epoch = get_sync_group_epoch(conn, "sg1")?;
            assert_eq!(epoch, Some(0));

            update_sync_group_epoch(conn, "sg1", 5)?;
            let epoch = get_sync_group_epoch(conn, "sg1")?;
            assert_eq!(epoch, Some(5));

            // Non-existent
            let epoch = get_sync_group_epoch(conn, "nonexistent")?;
            assert_eq!(epoch, None);

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn test_registry_state_compare_and_set_and_cleanup() {
        let db = test_db();
        db.with_conn(|conn| {
            create_sync_group(conn, "sg1", 0)?;

            assert!(get_registry_state(conn, "sg1")?.is_none());

            assert!(compare_and_set_registry_state(
                conn,
                "sg1",
                0,
                "",
                1,
                "hash-1",
                Some("snapshot"),
                Some(b"artifact-1"),
            )?);

            let state = get_registry_state(conn, "sg1")?.unwrap();
            assert_eq!(state.registry_version, 1);
            assert_eq!(state.registry_hash, "hash-1");

            let artifact = get_registry_artifact(conn, "sg1", 1)?.unwrap();
            assert_eq!(artifact.artifact_kind, "snapshot");
            assert_eq!(artifact.artifact_hash, "hash-1");
            assert_eq!(artifact.artifact_blob, b"artifact-1");

            // Stale compare-and-set must fail without changing current state.
            assert!(!compare_and_set_registry_state(
                conn,
                "sg1",
                0,
                "",
                2,
                "hash-2",
                Some("approval"),
                Some(b"artifact-2"),
            )?);

            // Advance successfully and leave behind a superseded artifact.
            assert!(compare_and_set_registry_state(
                conn,
                "sg1",
                1,
                "hash-1",
                2,
                "hash-2",
                Some("approval"),
                Some(b"artifact-2"),
            )?);

            assert!(get_registry_artifact(conn, "sg1", 1)?.is_some());
            assert!(get_registry_artifact(conn, "sg1", 2)?.is_some());

            let cleaned = cleanup_superseded_registry_state_artifacts(conn)?;
            assert_eq!(cleaned, 1);
            assert!(get_registry_artifact(conn, "sg1", 1)?.is_none());
            assert!(get_registry_artifact(conn, "sg1", 2)?.is_some());

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn test_register_device_and_get_device() {
        let db = test_db();
        db.with_conn(|conn| {
            create_sync_group(conn, "sg1", 0)?;

            let signing_pk = vec![1u8; 32];
            let x25519_pk = vec![2u8; 32];
            register_device(conn, "sg1", "dev1", &signing_pk, &x25519_pk, 0)?;

            let device = get_device(conn, "sg1", "dev1")?;
            assert!(device.is_some());
            let device = device.unwrap();
            assert_eq!(device.device_id, "dev1");
            assert_eq!(device.signing_public_key, signing_pk);
            assert_eq!(device.x25519_public_key, x25519_pk);
            assert_eq!(device.epoch, 0);
            assert_eq!(device.status, "active");

            // Non-existent device
            let device = get_device(conn, "sg1", "nonexistent")?;
            assert!(device.is_none());

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn test_create_session_validate_and_touch() {
        let db = test_db();
        db.with_conn(|conn| {
            create_sync_group(conn, "sg1", 0)?;
            register_device(conn, "sg1", "dev1", &[1; 32], &[2; 32], 0)?;

            // Create session with 3600s expiry
            let token = create_session(conn, "sg1", "dev1", 3600)?;
            assert_eq!(token.len(), 64); // 32 bytes hex

            // 90-day absolute cap (far larger than the sliding window below).
            let max_age = 7_776_000;

            // Validate
            let result = validate_session(conn, &token, max_age)?;
            assert_eq!(result, Some(("sg1".to_string(), "dev1".to_string())));

            // Invalid token
            let result = validate_session(conn, "invalid_token", max_age)?;
            assert!(result.is_none());

            // Touch session
            touch_session(conn, "sg1", "dev1", 7200, max_age)?;

            // Still valid
            let result = validate_session(conn, &token, max_age)?;
            assert_eq!(result, Some(("sg1".to_string(), "dev1".to_string())));

            // Delete session
            delete_session(conn, "sg1", "dev1")?;
            let result = validate_session(conn, &token, max_age)?;
            assert!(result.is_none());

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn test_session_absolute_max_age_rejects_old_session() {
        let db = test_db();
        db.with_conn(|conn| {
            create_sync_group(conn, "sg1", 0)?;
            register_device(conn, "sg1", "dev1", &[1; 32], &[2; 32], 0)?;

            // Create a session and force a far-in-the-past created_at while
            // keeping a still-future sliding expires_at (the "kept warm
            // forever" case the absolute cap is meant to catch).
            let token = create_session(conn, "sg1", "dev1", 3600)?;
            let now = now_secs();
            conn.execute(
                "UPDATE device_sessions
                 SET created_at = ?1, expires_at = ?2
                 WHERE sync_id = 'sg1' AND device_id = 'dev1'",
                params![now - 100_000, now + 3600],
            )?;

            // Under a tiny absolute cap the session is rejected despite the
            // sliding window still being open.
            assert!(validate_session(conn, &token, 60)?.is_none());

            // Under a large absolute cap it is still valid.
            assert_eq!(
                validate_session(conn, &token, 7_776_000)?,
                Some(("sg1".to_string(), "dev1".to_string()))
            );

            // touch_session must not extend expires_at past created_at + cap.
            touch_session(conn, "sg1", "dev1", 7200, 60)?;
            assert!(validate_session(conn, &token, 60)?.is_none());

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn test_revoke_session_preserves_revoked_lookup() {
        let db = test_db();
        db.with_conn(|conn| {
            create_sync_group(conn, "sg1", 0)?;
            register_device(conn, "sg1", "dev1", &[1; 32], &[2; 32], 0)?;

            let token = create_session(conn, "sg1", "dev1", 3600)?;
            revoke_session(conn, "sg1", "dev1", 3600)?;

            assert!(validate_session(conn, &token, 7_776_000)?.is_none());
            assert_eq!(
                validate_revoked_session(conn, &token)?,
                Some(("sg1".to_string(), "dev1".to_string()))
            );

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn test_create_nonce_consume_and_expired() {
        let db = test_db();
        db.with_conn(|conn| {
            create_sync_group(conn, "sg1", 0)?;

            // Create nonce with long expiry
            let nonce = create_nonce(conn, "sg1", 3600)?;
            assert!(!nonce.is_empty());

            // Wrong sync_id
            let consumed = consume_nonce(conn, &nonce, "wrong_sg")?;
            assert!(!consumed);

            // Correct consume
            let consumed = consume_nonce(conn, &nonce, "sg1")?;
            assert!(consumed);

            // Double consume fails (nonce deleted)
            let consumed = consume_nonce(conn, &nonce, "sg1")?;
            assert!(!consumed);

            // Create nonce with 0 expiry (immediately expired)
            let nonce = create_nonce(conn, "sg1", 0)?;
            // Consuming an expired nonce should fail (expires_at == now, condition is > now)
            // Since now_secs() may return the same value, use -1 to guarantee expiry
            // Actually the nonce was just created so expires_at == now. Since the check is
            // expires_at > now, it should fail.
            let consumed = consume_nonce(conn, &nonce, "sg1")?;
            assert!(!consumed);

            // Cleanup expired nonces
            let cleaned = cleanup_expired_nonces(conn)?;
            assert!(cleaned >= 1);

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn test_signed_request_nonce_replay_and_cleanup() {
        let db = test_db();
        db.with_conn(|conn| {
            let now = now_secs();

            assert!(record_signed_request_nonce(conn, "dev1", "nonce-1", now + 60, now)?);
            assert!(!record_signed_request_nonce(conn, "dev1", "nonce-1", now + 60, now)?);

            assert!(record_signed_request_nonce(conn, "dev1", "nonce-2", now + 60, now)?);
            assert!(record_signed_request_nonce(conn, "dev2", "nonce-1", now + 60, now)?);

            conn.execute(
                "INSERT INTO signed_request_nonces (device_id, nonce, expires_at)
                 VALUES (?1, ?2, ?3)",
                rusqlite::params!["dev1", "reusable", now - 1],
            )?;
            assert!(record_signed_request_nonce(conn, "dev1", "reusable", now + 60, now)?);

            conn.execute(
                "INSERT INTO signed_request_nonces (device_id, nonce, expires_at)
                 VALUES (?1, ?2, ?3)",
                rusqlite::params!["dev1", "expired", now - 1],
            )?;
            let cleaned = cleanup_expired_signed_request_nonces(conn)?;
            assert_eq!(cleaned, 1);

            let expired_count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM signed_request_nonces WHERE nonce = 'expired'",
                [],
                |row| row.get(0),
            )?;
            assert_eq!(expired_count, 0);

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn test_insert_batch_and_get_batches_since() {
        let db = test_db();
        db.with_conn(|conn| {
            create_sync_group(conn, "sg1", 0)?;

            let seq1 = insert_batch(conn, "sg1", 0, "dev1", "b1", b"data1")?;
            let seq2 = insert_batch(conn, "sg1", 0, "dev1", "b2", b"data2")?;
            let seq3 = insert_batch(conn, "sg1", 0, "dev2", "b3", b"data3")?;

            assert!(seq1 < seq2);
            assert!(seq2 < seq3);

            // Get all since 0
            let batches = get_batches_since(conn, "sg1", 0, 100)?;
            assert_eq!(batches.len(), 3);
            assert_eq!(batches[0].batch_id, "b1");
            assert_eq!(batches[1].batch_id, "b2");
            assert_eq!(batches[2].batch_id, "b3");

            // Pagination: get first 2
            let batches = get_batches_since(conn, "sg1", 0, 2)?;
            assert_eq!(batches.len(), 2);

            // Get since seq2
            let batches = get_batches_since(conn, "sg1", seq2, 100)?;
            assert_eq!(batches.len(), 1);
            assert_eq!(batches[0].batch_id, "b3");

            // Latest seq
            let latest = get_latest_seq(conn, "sg1")?;
            assert_eq!(latest, seq3);

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn test_batch_deduplication() {
        let db = test_db();
        db.with_conn(|conn| {
            create_sync_group(conn, "sg1", 0)?;

            let seq1 = insert_batch(conn, "sg1", 0, "dev1", "b1", b"data1")?;
            // Duplicate insert returns same seq
            let seq_dup = insert_batch(conn, "sg1", 0, "dev1", "b1", b"different_data")?;
            assert_eq!(seq1, seq_dup);

            // Only one batch stored
            let batches = get_batches_since(conn, "sg1", 0, 100)?;
            assert_eq!(batches.len(), 1);

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn test_upsert_snapshot_and_get() {
        let db = test_db();
        db.with_conn(|conn| {
            create_sync_group(conn, "sg1", 0)?;

            // No snapshot initially
            let snap = get_snapshot(conn, "sg1")?;
            assert!(snap.is_none());

            upsert_snapshot(conn, "sg1", 1, 10, b"snap_data", None, None, None)?;

            let snap = get_snapshot(conn, "sg1")?.unwrap();
            assert_eq!(snap.epoch, 1);
            assert_eq!(snap.server_seq_at, 10);
            assert_eq!(snap.data, b"snap_data");
            assert_eq!(snap.uploaded_by_device_id, None);

            // Upsert replaces
            upsert_snapshot(conn, "sg1", 2, 20, b"snap_data_v2", None, Some("dev2"), Some("dev1"))?;
            let snap = get_snapshot(conn, "sg1")?.unwrap();
            assert_eq!(snap.epoch, 2);
            assert_eq!(snap.server_seq_at, 20);
            assert_eq!(snap.data, b"snap_data_v2");
            assert_eq!(snap.target_device_id.as_deref(), Some("dev2"));
            assert_eq!(snap.uploaded_by_device_id.as_deref(), Some("dev1"));

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn test_device_receipt_and_min_acked_seq() {
        let db = test_db();
        db.with_conn(|conn| {
            create_sync_group(conn, "sg1", 0)?;
            register_device(conn, "sg1", "dev1", &[1; 32], &[2; 32], 0)?;
            register_device(conn, "sg1", "dev2", &[3; 32], &[4; 32], 0)?;

            // Touch devices so they're not considered stale
            touch_device(conn, "sg1", "dev1")?;
            touch_device(conn, "sg1", "dev2")?;

            upsert_device_receipt(conn, "sg1", "dev1", 10)?;
            upsert_device_receipt(conn, "sg1", "dev2", 5)?;

            // Min acked should be 5 (dev2)
            let min = get_min_acked_seq(conn, "sg1", 3600)?;
            assert_eq!(min, Some(5));

            // Advance dev2
            upsert_device_receipt(conn, "sg1", "dev2", 15)?;
            let min = get_min_acked_seq(conn, "sg1", 3600)?;
            assert_eq!(min, Some(10));

            // MAX behavior: receipt doesn't go backward
            upsert_device_receipt(conn, "sg1", "dev2", 3)?;
            let min = get_min_acked_seq(conn, "sg1", 3600)?;
            assert_eq!(min, Some(10)); // Still 10, dev2 stays at 15

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn test_prune_batches_before() {
        let db = test_db();
        db.with_conn(|conn| {
            create_sync_group(conn, "sg1", 0)?;

            let seq1 = insert_batch(conn, "sg1", 0, "dev1", "b1", b"d1")?;
            let seq2 = insert_batch(conn, "sg1", 0, "dev1", "b2", b"d2")?;
            let _seq3 = insert_batch(conn, "sg1", 0, "dev1", "b3", b"d3")?;

            // Prune before seq2 — should delete seq1 only
            let pruned = prune_batches_before(conn, "sg1", seq2)?;
            assert_eq!(pruned, 1);

            let batches = get_batches_since(conn, "sg1", 0, 100)?;
            assert_eq!(batches.len(), 2);
            assert_eq!(batches[0].server_seq, seq2);

            // Prune with seq1 again — nothing to delete
            let pruned = prune_batches_before(conn, "sg1", seq1)?;
            assert_eq!(pruned, 0);

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn test_rekey_artifact_store_and_get() {
        let db = test_db();
        db.with_conn(|conn| {
            create_sync_group(conn, "sg1", 0)?;

            let wrapped = vec![42u8; 64];
            store_rekey_artifact(conn, "sg1", 1, "dev1", &wrapped)?;

            let result = get_rekey_artifact(conn, "sg1", 1, "dev1")?;
            assert_eq!(result, Some(wrapped));

            // Non-existent
            let result = get_rekey_artifact(conn, "sg1", 1, "nonexistent")?;
            assert!(result.is_none());

            let result = get_rekey_artifact(conn, "sg1", 2, "dev1")?;
            assert!(result.is_none());

            // Upsert overwrites
            let new_wrapped = vec![99u8; 64];
            store_rekey_artifact(conn, "sg1", 1, "dev1", &new_wrapped)?;
            let result = get_rekey_artifact(conn, "sg1", 1, "dev1")?;
            assert_eq!(result, Some(new_wrapped));

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn test_delete_sync_group_cascading() {
        let db = test_db();
        db.with_conn(|conn| {
            create_sync_group(conn, "sg1", 0)?;
            register_device(conn, "sg1", "dev1", &[1; 32], &[2; 32], 0)?;
            let token = create_session(conn, "sg1", "dev1", 3600)?;
            revoke_session(conn, "sg1", "dev1", 3600)?;
            assert!(validate_revoked_session(conn, &token)?.is_some());
            upsert_device_receipt(conn, "sg1", "dev1", 5)?;
            insert_batch(conn, "sg1", 0, "dev1", "b1", b"data")?;
            upsert_snapshot(conn, "sg1", 0, 0, b"snap", None, None, None)?;
            store_rekey_artifact(conn, "sg1", 1, "dev1", &[42; 32])?;
            insert_revocation_event(conn, "sg1", "dev1", "dev2", 1, false)?;
            insert_rekey_event(conn, "sg1", "dev1", 1)?;
            upsert_registry_state(conn, "sg1", 3, "hash-3")?;
            store_registry_artifact(conn, "sg1", 3, "hash-3", "snapshot", b"registry")?;
            create_nonce(conn, "sg1", 3600)?;

            // Delete everything
            delete_sync_group(conn, "sg1")?;

            // Verify all gone
            assert_eq!(get_sync_group_epoch(conn, "sg1")?, None);
            assert!(get_device(conn, "sg1", "dev1")?.is_none());
            assert!(get_snapshot(conn, "sg1")?.is_none());
            assert_eq!(get_latest_seq(conn, "sg1")?, 0);
            assert!(get_rekey_artifact(conn, "sg1", 1, "dev1")?.is_none());
            let rev_count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM revocation_events WHERE sync_id = ?1",
                params!["sg1"],
                |row| row.get(0),
            )?;
            assert_eq!(rev_count, 0);
            let rekey_count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM rekey_events WHERE sync_id = ?1",
                params!["sg1"],
                |row| row.get(0),
            )?;
            assert_eq!(rekey_count, 0);
            assert!(get_registry_state(conn, "sg1")?.is_none());
            assert!(get_registry_artifact(conn, "sg1", 3)?.is_none());
            assert!(validate_revoked_session(conn, &token)?.is_none());

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn test_list_devices_includes_public_keys() {
        let db = test_db();
        db.with_conn(|conn| {
            create_sync_group(conn, "sg1", 0)?;

            let signing_pk = vec![10u8; 32];
            let x25519_pk = vec![20u8; 32];
            register_device(conn, "sg1", "dev1", &signing_pk, &x25519_pk, 0)?;

            let devices = list_devices(conn, "sg1")?;
            assert_eq!(devices.len(), 1);
            assert_eq!(devices[0].device_id, "dev1");
            assert_eq!(devices[0].signing_public_key, signing_pk);
            assert_eq!(devices[0].x25519_public_key, x25519_pk);

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn test_revoke_and_count_active_devices() {
        let db = test_db();
        db.with_conn(|conn| {
            create_sync_group(conn, "sg1", 0)?;
            register_device(conn, "sg1", "dev1", &[1; 32], &[2; 32], 0)?;
            register_device(conn, "sg1", "dev2", &[3; 32], &[4; 32], 0)?;

            assert_eq!(count_active_devices(conn, "sg1")?, 2);

            let revoked = revoke_device(conn, "sg1", "dev1", false)?;
            assert!(revoked);

            assert_eq!(count_active_devices(conn, "sg1")?, 1);

            // Revoking again returns false
            let revoked = revoke_device(conn, "sg1", "dev1", false)?;
            assert!(!revoked);

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn test_delete_device() {
        let db = test_db();
        db.with_conn(|conn| {
            create_sync_group(conn, "sg1", 0)?;
            register_device(conn, "sg1", "dev1", &[1; 32], &[2; 32], 0)?;
            create_session(conn, "sg1", "dev1", 3600)?;
            upsert_device_receipt(conn, "sg1", "dev1", 5)?;
            store_rekey_artifact(conn, "sg1", 1, "dev1", &[42; 32])?;

            let deleted = delete_device(conn, "sg1", "dev1")?;
            assert!(deleted);

            assert!(get_device(conn, "sg1", "dev1")?.is_none());

            // Deleting again returns false
            let deleted = delete_device(conn, "sg1", "dev1")?;
            assert!(!deleted);

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn test_cleanup_revoked_device_tombstones_waits_for_history() {
        let db = test_db();
        db.with_conn(|conn| {
            create_sync_group(conn, "sg1", 0)?;
            register_device(conn, "sg1", "dev1", &[1; 32], &[2; 32], 0)?;
            let token = create_session(conn, "sg1", "dev1", 3600)?;
            revoke_session(conn, "sg1", "dev1", 3600)?;
            assert!(validate_revoked_session(conn, &token)?.is_some());
            insert_batch(conn, "sg1", 0, "dev1", "b1", b"data")?;

            revoke_device(conn, "sg1", "dev1", false)?;
            let old = now_secs() - 10_000;
            conn.execute(
                "UPDATE devices SET revoked_at = ?1 WHERE sync_id = ?2 AND device_id = ?3",
                params![old, "sg1", "dev1"],
            )?;

            let cleaned = cleanup_revoked_device_tombstones(conn, 3600)?;
            assert_eq!(cleaned, 0, "batch history should keep tombstone alive");
            assert!(get_device(conn, "sg1", "dev1")?.is_some());

            let batches = get_batches_since(conn, "sg1", 0, 100)?;
            let before = batches
                .last()
                .map(|batch| batch.server_seq + 1)
                .unwrap_or(1);
            prune_batches_before(conn, "sg1", before)?;

            let cleaned = cleanup_revoked_device_tombstones(conn, 3600)?;
            assert_eq!(cleaned, 0, "revoked-session retention should still apply");

            let old_revoked_session = now_secs() - 10_000;
            conn.execute(
                "UPDATE revoked_device_sessions SET expires_at = ?1 WHERE sync_id = ?2 AND device_id = ?3",
                params![old_revoked_session, "sg1", "dev1"],
            )?;
            let _ = cleanup_expired_revoked_sessions(conn)?;

            let cleaned = cleanup_revoked_device_tombstones(conn, 3600)?;
            assert_eq!(cleaned, 1, "tombstone should be removed after pruning");
            assert!(get_device(conn, "sg1", "dev1")?.is_none());
            assert!(validate_revoked_session(conn, &token)?.is_none());

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn test_set_needs_rekey() {
        let db = test_db();
        db.with_conn(|conn| {
            create_sync_group(conn, "sg1", 0)?;

            // Check initial state via raw query
            let needs: i64 = conn.query_row(
                "SELECT needs_rekey FROM sync_groups WHERE sync_id = ?1",
                params!["sg1"],
                |row| row.get(0),
            )?;
            assert_eq!(needs, 0);

            set_needs_rekey(conn, "sg1", true)?;
            let needs: i64 = conn.query_row(
                "SELECT needs_rekey FROM sync_groups WHERE sync_id = ?1",
                params!["sg1"],
                |row| row.get(0),
            )?;
            assert_eq!(needs, 1);

            set_needs_rekey(conn, "sg1", false)?;
            let needs: i64 = conn.query_row(
                "SELECT needs_rekey FROM sync_groups WHERE sync_id = ?1",
                params!["sg1"],
                |row| row.get(0),
            )?;
            assert_eq!(needs, 0);

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn test_safe_prune_seq() {
        let db = test_db();
        db.with_conn(|conn| {
            create_sync_group(conn, "sg1", 0)?;
            register_device(conn, "sg1", "dev1", &[1; 32], &[2; 32], 0)?;
            register_device(conn, "sg1", "dev2", &[3; 32], &[4; 32], 0)?;
            touch_device(conn, "sg1", "dev1")?;
            touch_device(conn, "sg1", "dev2")?;

            // No snapshot, no receipts => no prune point.
            let seq = get_safe_prune_seq(conn, "sg1", 3600)?;
            assert_eq!(seq, None);

            // No snapshot, with receipts => still no prune point.
            upsert_device_receipt(conn, "sg1", "dev1", 5)?;
            upsert_device_receipt(conn, "sg1", "dev2", 8)?;
            let seq = get_safe_prune_seq(conn, "sg1", 3600)?;
            assert_eq!(seq, None);

            // Add snapshot at seq 10 — now min(snapshot=10, min_acked=5) => 5
            upsert_snapshot(conn, "sg1", 0, 10, b"snap", None, None, None)?;
            let seq = get_safe_prune_seq(conn, "sg1", 3600)?;
            assert_eq!(seq, Some(5));

            // Both acked past snapshot => safe is snapshot seq (10)
            upsert_device_receipt(conn, "sg1", "dev1", 15)?;
            upsert_device_receipt(conn, "sg1", "dev2", 20)?;
            let seq = get_safe_prune_seq(conn, "sg1", 3600)?;
            assert_eq!(seq, Some(10));

            // Delete snapshot => no prune point even with ACKs.
            delete_snapshot(conn, "sg1")?;
            let seq = get_safe_prune_seq(conn, "sg1", 3600)?;
            assert_eq!(seq, None);

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn test_safe_prune_seq_ignores_expired_snapshot() {
        let db = test_db();
        db.with_conn(|conn| {
            create_sync_group(conn, "sg1", 0)?;
            register_device(conn, "sg1", "dev1", &[1; 32], &[2; 32], 0)?;
            touch_device(conn, "sg1", "dev1")?;
            upsert_device_receipt(conn, "sg1", "dev1", 20)?;

            // Insert snapshot with expiry in the past (already expired)
            let past = now_secs() - 100;
            upsert_snapshot(conn, "sg1", 0, 5, b"snap", Some(past), None, None)?;

            // Expired snapshot should be ignored; ACKs alone do not permit pruning.
            let seq = get_safe_prune_seq(conn, "sg1", 3600)?;
            assert_eq!(seq, None);

            // Non-expired snapshot should be respected
            let future = now_secs() + 3600;
            upsert_snapshot(conn, "sg1", 0, 5, b"snap2", Some(future), None, None)?;
            let seq = get_safe_prune_seq(conn, "sg1", 3600)?;
            assert_eq!(seq, Some(5));

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn test_safe_prune_seq_no_devices() {
        let db = test_db();
        db.with_conn(|conn| {
            create_sync_group(conn, "sg1", 0)?;

            // No devices, no snapshot => None
            let seq = get_safe_prune_seq(conn, "sg1", 3600)?;
            assert_eq!(seq, None);

            // Snapshot only, no devices => uses snapshot_seq
            upsert_snapshot(conn, "sg1", 0, 10, b"snap", None, None, None)?;
            let seq = get_safe_prune_seq(conn, "sg1", 3600)?;
            assert_eq!(seq, Some(10));

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn test_create_sync_group_idempotent() {
        let db = test_db();
        db.with_conn(|conn| {
            // First call inserts the row and returns true
            let created = create_sync_group(conn, "sg1", 0)?;
            assert!(created, "first call should insert and return true");

            // Second call with same sync_id is ignored and returns false
            let created_again = create_sync_group(conn, "sg1", 0)?;
            assert!(!created_again, "second call should be ignored and return false");

            // Data remains consistent: epoch is still readable and unchanged
            let epoch = get_sync_group_epoch(conn, "sg1")?;
            assert_eq!(epoch, Some(0), "epoch should still be 0 after idempotent insert");

            // A different sync_id still works
            let other = create_sync_group(conn, "sg2", 3)?;
            assert!(other, "different sync_id should insert successfully");
            let epoch2 = get_sync_group_epoch(conn, "sg2")?;
            assert_eq!(epoch2, Some(3));

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn test_delete_snapshot() {
        let db = test_db();
        db.with_conn(|conn| {
            create_sync_group(conn, "sg1", 0)?;

            // Delete non-existent snapshot returns false
            assert!(!delete_snapshot(conn, "sg1")?);

            upsert_snapshot(conn, "sg1", 1, 10, b"data", None, None, None)?;
            assert!(get_snapshot(conn, "sg1")?.is_some());

            // Delete existing snapshot returns true
            assert!(delete_snapshot(conn, "sg1")?);
            assert!(get_snapshot(conn, "sg1")?.is_none());

            // Second delete returns false
            assert!(!delete_snapshot(conn, "sg1")?);

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn test_ephemeral_snapshot_expires() {
        let db = test_db();
        db.with_conn(|conn| {
            create_sync_group(conn, "sg1", 0)?;

            // Seq bumps across the three upserts keep this test scoped to
            // expiry semantics; the strict-newer-wins guard is exercised
            // in `tests/relay_snapshot_tests.rs`.
            let past = now_secs() - 60;
            upsert_snapshot(conn, "sg1", 1, 10, b"expired", Some(past), None, Some("dev1"))?;
            let snap = get_snapshot(conn, "sg1")?;
            assert!(snap.is_none(), "expired snapshot should not be returned");

            let future = now_secs() + 3600;
            upsert_snapshot(conn, "sg1", 1, 11, b"valid", Some(future), None, Some("dev1"))?;
            let snap = get_snapshot(conn, "sg1")?.unwrap();
            assert_eq!(snap.data, b"valid");
            assert_eq!(snap.uploaded_by_device_id.as_deref(), Some("dev1"));

            // Snapshot with no expiry (legacy) is always returned.
            upsert_snapshot(conn, "sg1", 1, 12, b"permanent", None, None, None)?;
            let snap = get_snapshot(conn, "sg1")?.unwrap();
            assert_eq!(snap.data, b"permanent");
            assert_eq!(snap.uploaded_by_device_id, None);

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn test_cleanup_expired_snapshots() {
        let db = test_db();
        db.with_conn(|conn| {
            create_sync_group(conn, "sg1", 0)?;
            create_sync_group(conn, "sg2", 0)?;
            create_sync_group(conn, "sg3", 0)?;

            let past = now_secs() - 60;
            let future = now_secs() + 3600;

            // sg1: expired snapshot
            upsert_snapshot(conn, "sg1", 1, 5, b"old", Some(past), None, Some("dev1"))?;
            // sg2: valid (future expiry)
            upsert_snapshot(conn, "sg2", 1, 5, b"new", Some(future), None, Some("dev2"))?;
            // sg3: permanent (no expiry)
            upsert_snapshot(conn, "sg3", 1, 5, b"perm", None, None, None)?;

            // Cleanup should remove only the expired one
            let cleaned = cleanup_expired_snapshots(conn)?;
            assert_eq!(cleaned, 1);

            // sg1 gone, sg2 and sg3 still present
            assert!(get_snapshot(conn, "sg1")?.is_none());
            assert!(get_snapshot(conn, "sg2")?.is_some());
            assert!(get_snapshot(conn, "sg3")?.is_some());

            // Running again removes nothing
            let cleaned = cleanup_expired_snapshots(conn)?;
            assert_eq!(cleaned, 0);

            Ok(())
        })
        .unwrap();
    }

    // ══════════════════════════════════════════════════════════════════
    // Ephemeral snapshot integration tests (Task 11)
    // ══════════════════════════════════════════════════════════════════

    /// Test 1: Ephemeral snapshot lifecycle — upload with TTL, verify data,
    /// verify auto-delete support (uploaded_by_device_id tracking).
    #[test]
    fn test_ephemeral_snapshot_lifecycle() {
        let db = test_db();
        db.with_conn(|conn| {
            create_sync_group(conn, "sg1", 0)?;
            register_device(conn, "sg1", "dev_a", &[1; 32], &[2; 32], 0)?;
            register_device(conn, "sg1", "dev_b", &[3; 32], &[4; 32], 0)?;

            let future = now_secs() + 300; // 5 minute TTL

            // Device A uploads snapshot with TTL and uploaded_by_device_id
            upsert_snapshot(
                conn,
                "sg1",
                0,
                10,
                b"snap_data",
                Some(future),
                Some("dev_b"),
                Some("dev_a"),
            )?;

            // Device B can download it (not expired)
            let snap = get_snapshot(conn, "sg1")?.unwrap();
            assert_eq!(snap.data, b"snap_data");
            assert_eq!(snap.epoch, 0);
            assert_eq!(snap.server_seq_at, 10);
            assert_eq!(snap.target_device_id.as_deref(), Some("dev_b"));
            assert_eq!(snap.uploaded_by_device_id.as_deref(), Some("dev_a"));

            // Simulate auto-delete (what the HTTP handler does after cross-device download)
            assert!(delete_snapshot(conn, "sg1")?);

            // Subsequent download returns None (404)
            let snap = get_snapshot(conn, "sg1")?;
            assert!(snap.is_none(), "snapshot should be gone after auto-delete");

            Ok(())
        })
        .unwrap();
    }

    /// Test 2: Cleanup pruning requires an unexpired snapshot even when all
    /// devices have ACKed retained history.
    #[test]
    fn test_no_snapshot_cleanup_prunes_nothing() {
        let db = test_db();
        db.with_conn(|conn| {
            create_sync_group(conn, "sg1", 0)?;
            register_device(conn, "sg1", "dev1", &[1; 32], &[2; 32], 0)?;
            register_device(conn, "sg1", "dev2", &[3; 32], &[4; 32], 0)?;
            touch_device(conn, "sg1", "dev1")?;
            touch_device(conn, "sg1", "dev2")?;

            // Push 5 batches
            let _seq1 = insert_batch(conn, "sg1", 0, "dev1", "b1", b"d1")?;
            let _seq2 = insert_batch(conn, "sg1", 0, "dev1", "b2", b"d2")?;
            let seq3 = insert_batch(conn, "sg1", 0, "dev1", "b3", b"d3")?;
            let _seq4 = insert_batch(conn, "sg1", 0, "dev1", "b4", b"d4")?;
            let seq5 = insert_batch(conn, "sg1", 0, "dev1", "b5", b"d5")?;

            // No snapshot. ACK from both devices at seq3
            upsert_device_receipt(conn, "sg1", "dev1", seq3)?;
            upsert_device_receipt(conn, "sg1", "dev2", seq3)?;

            // Safe prune seq should not exist without an unexpired snapshot.
            let safe = get_safe_prune_seq(conn, "sg1", 3600)?;
            assert_eq!(safe, None);

            // Periodic cleanup pruning must leave all batches intact.
            let pruned = prune_batches_with_unexpired_snapshots(conn, 3600)?;
            assert_eq!(pruned, 0, "cleanup must not prune without a snapshot");

            // All 5 batches remain.
            let remaining = get_batches_since(conn, "sg1", 0, 100)?;
            assert_eq!(remaining.len(), 5);

            // Advance both devices to seq5
            upsert_device_receipt(conn, "sg1", "dev1", seq5)?;
            upsert_device_receipt(conn, "sg1", "dev2", seq5)?;

            // Still no safe prune point without a snapshot.
            let safe = get_safe_prune_seq(conn, "sg1", 3600)?;
            assert_eq!(safe, None);

            let pruned = prune_batches_with_unexpired_snapshots(conn, 3600)?;
            assert_eq!(pruned, 0, "cleanup must still not prune without a snapshot");

            Ok(())
        })
        .unwrap();
    }

    /// Ack-only pruning never prunes past the slowest active device, even
    /// with no group-wide snapshot present.
    #[test]
    fn ack_prune_stops_at_slowest_active_device() {
        let db = test_db();
        db.with_conn(|conn| {
            create_sync_group(conn, "sg1", 0)?;
            register_device(conn, "sg1", "dev1", &[1; 32], &[2; 32], 0)?;
            register_device(conn, "sg1", "dev2", &[3; 32], &[4; 32], 0)?;
            touch_device(conn, "sg1", "dev1")?;
            touch_device(conn, "sg1", "dev2")?;

            let _seq1 = insert_batch(conn, "sg1", 0, "dev1", "b1", b"d1")?;
            let _seq2 = insert_batch(conn, "sg1", 0, "dev1", "b2", b"d2")?;
            let seq3 = insert_batch(conn, "sg1", 0, "dev1", "b3", b"d3")?;
            let _seq4 = insert_batch(conn, "sg1", 0, "dev1", "b4", b"d4")?;
            let seq5 = insert_batch(conn, "sg1", 0, "dev1", "b5", b"d5")?;

            // dev1 is caught up; dev2 lags at seq3.
            upsert_device_receipt(conn, "sg1", "dev1", seq5)?;
            upsert_device_receipt(conn, "sg1", "dev2", seq3)?;

            assert_eq!(get_min_acked_seq_unrevoked(conn, "sg1")?, Some(seq3));

            let pruned = prune_batches_by_acks(conn)?;
            assert_eq!(pruned, 3, "should prune only the 3 batches dev2 has acked");

            let remaining = get_batches_since(conn, "sg1", 0, 100)?;
            assert_eq!(remaining.len(), 2, "batches 4 and 5 must survive for dev2");

            Ok(())
        })
        .unwrap();
    }

    /// A still-active device that has acked nothing pins the floor at 0, so
    /// ack-only pruning deletes nothing — until the device is revoked (e.g.
    /// by `auto_revoke_devices`), after which the floor advances to the
    /// remaining device's ack.
    #[test]
    fn ack_prune_resumes_after_abandoned_device_revoked() {
        let db = test_db();
        db.with_conn(|conn| {
            create_sync_group(conn, "sg1", 0)?;
            register_device(conn, "sg1", "dev1", &[1; 32], &[2; 32], 0)?;
            register_device(conn, "sg1", "dev2", &[3; 32], &[4; 32], 0)?;
            touch_device(conn, "sg1", "dev1")?;
            touch_device(conn, "sg1", "dev2")?;

            let _seq1 = insert_batch(conn, "sg1", 0, "dev1", "b1", b"d1")?;
            let seq2 = insert_batch(conn, "sg1", 0, "dev1", "b2", b"d2")?;
            let seq3 = insert_batch(conn, "sg1", 0, "dev1", "b3", b"d3")?;

            // dev1 acked everything; dev2 never acked anything.
            upsert_device_receipt(conn, "sg1", "dev1", seq3)?;

            assert_eq!(
                get_min_acked_seq_unrevoked(conn, "sg1")?,
                Some(0),
                "an active device with no receipt pins the floor at 0"
            );
            assert_eq!(prune_batches_by_acks(conn)?, 0, "nothing prunes while dev2 lingers");
            assert_eq!(get_batches_since(conn, "sg1", 0, 100)?.len(), 3);

            // dev2 is abandoned and revoked; only dev1 remains active.
            assert!(revoke_device(conn, "sg1", "dev2", false)?);
            assert_eq!(get_min_acked_seq_unrevoked(conn, "sg1")?, Some(seq3));

            let pruned = prune_batches_by_acks(conn)?;
            assert_eq!(pruned, 3, "all dev1-acked batches prune once dev2 is gone");
            assert_eq!(get_batches_since(conn, "sg1", 0, 100)?.len(), 0);

            let _ = seq2; // referenced for clarity of the seq progression
            Ok(())
        })
        .unwrap();
    }

    /// A group with no active devices yields `None` (MIN over zero rows) and
    /// prunes nothing — orphaned-group reclamation is handled separately.
    #[test]
    fn ack_prune_skips_groups_with_no_active_devices() {
        let db = test_db();
        db.with_conn(|conn| {
            create_sync_group(conn, "sg1", 0)?;
            register_device(conn, "sg1", "dev1", &[1; 32], &[2; 32], 0)?;
            let seq1 = insert_batch(conn, "sg1", 0, "dev1", "b1", b"d1")?;
            upsert_device_receipt(conn, "sg1", "dev1", seq1)?;
            assert!(revoke_device(conn, "sg1", "dev1", false)?);

            assert_eq!(get_min_acked_seq_unrevoked(conn, "sg1")?, None);
            assert_eq!(prune_batches_by_acks(conn)?, 0);
            assert_eq!(get_batches_since(conn, "sg1", 0, 100)?.len(), 1);

            Ok(())
        })
        .unwrap();
    }

    /// Ack-only pruning must NOT touch a group that has an unexpired
    /// group-wide snapshot — otherwise it could advance pruned_floor_seq
    /// past the snapshot seq when all devices have acked beyond it, stranding
    /// the snapshot as a bootstrap floor. Those groups belong to the
    /// snapshot-gated path, which caps at the snapshot seq.
    #[test]
    fn ack_prune_skips_groups_with_group_wide_snapshot() {
        let db = test_db();
        db.with_conn(|conn| {
            create_sync_group(conn, "sg1", 0)?;
            register_device(conn, "sg1", "dev1", &[1; 32], &[2; 32], 0)?;
            register_device(conn, "sg1", "dev2", &[3; 32], &[4; 32], 0)?;
            touch_device(conn, "sg1", "dev1")?;
            touch_device(conn, "sg1", "dev2")?;

            for i in 1..=15 {
                insert_batch(conn, "sg1", 0, "dev1", &format!("b{i}"), b"d")?;
            }

            // Group-wide snapshot at seq 10 (target_device_id = NULL).
            upsert_snapshot(conn, "sg1", 0, 10, b"snap", None, None, Some("dev1"))?;

            // Both active devices have acked past the snapshot.
            upsert_device_receipt(conn, "sg1", "dev1", 15)?;
            upsert_device_receipt(conn, "sg1", "dev2", 15)?;

            // Ack-only pruning must skip this group entirely.
            let pruned = prune_batches_by_acks(conn)?;
            assert_eq!(pruned, 0, "snapshot'd group must be left to the snapshot path");
            assert_eq!(get_batches_since(conn, "sg1", 0, 100)?.len(), 15);

            // The snapshot-gated path is the one allowed to prune it, capped
            // at the snapshot seq (10): batches 1..=9 go, 10..=15 stay.
            let snap_pruned = prune_batches_with_unexpired_snapshots(conn, 3600)?;
            assert_eq!(snap_pruned, 9, "snapshot path caps pruning at the snapshot seq");
            assert_eq!(get_batches_since(conn, "sg1", 0, 100)?.len(), 6);

            Ok(())
        })
        .unwrap();
    }

    /// A `stale`-status device still pins the prune floor: it has not been
    /// revoked, so it may reconnect, and `touch_device` never resets it back
    /// to `active`. Pruning past it would force a re-pair on return. Only
    /// auto-revoke (90d) releases the floor.
    #[test]
    fn ack_prune_does_not_prune_past_stale_device() {
        let db = test_db();
        db.with_conn(|conn| {
            create_sync_group(conn, "sg1", 0)?;
            register_device(conn, "sg1", "dev1", &[1; 32], &[2; 32], 0)?;
            register_device(conn, "sg1", "dev2", &[3; 32], &[4; 32], 0)?;
            touch_device(conn, "sg1", "dev1")?;
            touch_device(conn, "sg1", "dev2")?;

            let _s1 = insert_batch(conn, "sg1", 0, "dev1", "b1", b"d")?;
            let _s2 = insert_batch(conn, "sg1", 0, "dev1", "b2", b"d")?;
            let seq3 = insert_batch(conn, "sg1", 0, "dev1", "b3", b"d")?;
            let _s4 = insert_batch(conn, "sg1", 0, "dev1", "b4", b"d")?;
            let seq5 = insert_batch(conn, "sg1", 0, "dev1", "b5", b"d")?;

            // dev1 caught up at 5; dev2 only acked 3, then goes quiet.
            upsert_device_receipt(conn, "sg1", "dev1", seq5)?;
            upsert_device_receipt(conn, "sg1", "dev2", seq3)?;

            // dev2 crosses the 30d staleness line and is marked 'stale'.
            conn.execute(
                "UPDATE devices SET last_seen_at = 0 WHERE sync_id = 'sg1' AND device_id = 'dev2'",
                [],
            )?;
            assert_eq!(mark_stale_devices(conn, 2_592_000)?, 1, "dev2 marked stale");

            // The floor still includes dev2 — prune only up to its ack (3).
            assert_eq!(get_min_acked_seq_unrevoked(conn, "sg1")?, Some(seq3));
            assert_eq!(prune_batches_by_acks(conn)?, 3);
            assert_eq!(
                get_batches_since(conn, "sg1", 0, 100)?.len(),
                2,
                "batches 4,5 retained for the stale-but-not-revoked dev2"
            );

            // Once dev2 is actually revoked (a stale device goes through
            // auto_revoke, not revoke_device which only matches 'active'),
            // the floor advances to dev1's ack.
            let revoked = auto_revoke_devices(conn, 7_776_000)?;
            assert!(revoked.contains(&"sg1".to_string()), "dev2 auto-revoked at the 90d TTL");
            assert_eq!(get_min_acked_seq_unrevoked(conn, "sg1")?, Some(seq5));
            assert_eq!(
                prune_batches_by_acks(conn)?,
                2,
                "remaining batches prune once dev2 revoked"
            );
            assert_eq!(get_batches_since(conn, "sg1", 0, 100)?.len(), 0);

            Ok(())
        })
        .unwrap();
    }

    /// `prune_batches_by_acks` processes every eligible group in one pass and
    /// returns the summed deletion count, while leaving independent groups at
    /// their own floors.
    #[test]
    fn ack_prune_handles_multiple_groups_independently() {
        let db = test_db();
        db.with_conn(|conn| {
            // Batch ids are globally monotonic, so capture the real seqs
            // each group got rather than assuming per-group 1..N.

            // Group A: one device caught up — fully prunable below its ack.
            create_sync_group(conn, "sgA", 0)?;
            register_device(conn, "sgA", "a1", &[1; 32], &[2; 32], 0)?;
            touch_device(conn, "sgA", "a1")?;
            let mut a_seqs = Vec::new();
            for i in 1..=4 {
                a_seqs.push(insert_batch(conn, "sgA", 0, "a1", &format!("a{i}"), b"d")?);
            }
            upsert_device_receipt(conn, "sgA", "a1", *a_seqs.last().unwrap())?;

            // Group B: two devices; slower one acked only its 2nd batch.
            create_sync_group(conn, "sgB", 0)?;
            register_device(conn, "sgB", "b1", &[5; 32], &[6; 32], 0)?;
            register_device(conn, "sgB", "b2", &[7; 32], &[8; 32], 0)?;
            touch_device(conn, "sgB", "b1")?;
            touch_device(conn, "sgB", "b2")?;
            let mut b_seqs = Vec::new();
            for i in 1..=4 {
                b_seqs.push(insert_batch(conn, "sgB", 0, "b1", &format!("b{i}"), b"d")?);
            }
            upsert_device_receipt(conn, "sgB", "b1", *b_seqs.last().unwrap())?;
            upsert_device_receipt(conn, "sgB", "b2", b_seqs[1])?;

            // A: prune all 4 (every device acked the last). B: prune the 2
            // below b2's ack. Total 6.
            assert_eq!(prune_batches_by_acks(conn)?, 6);
            assert_eq!(get_batches_since(conn, "sgA", 0, 100)?.len(), 0);
            assert_eq!(get_batches_since(conn, "sgB", 0, 100)?.len(), 2);

            Ok(())
        })
        .unwrap();
    }

    /// Test 3: Expired snapshot returns None.
    /// Upload with very short TTL, verify it becomes unavailable.
    #[test]
    fn test_expired_snapshot_returns_404() {
        let db = test_db();
        db.with_conn(|conn| {
            create_sync_group(conn, "sg1", 0)?;

            // Upload with expiry already in the past
            let past = now_secs() - 1;
            upsert_snapshot(
                conn,
                "sg1",
                1,
                10,
                b"expired_data",
                Some(past),
                Some("dev1"),
                Some("dev1"),
            )?;

            // Get should return None (expired)
            let snap = get_snapshot(conn, "sg1")?;
            assert!(snap.is_none(), "expired snapshot should return None");

            Ok(())
        })
        .unwrap();
    }

    /// Test 7: Legacy null TTL is preserved through operations.
    #[test]
    fn test_legacy_null_ttl_preserved() {
        let db = test_db();
        db.with_conn(|conn| {
            create_sync_group(conn, "sg1", 0)?;

            // Insert legacy snapshot with no expiry
            upsert_snapshot(conn, "sg1", 1, 10, b"legacy_data", None, None, None)?;

            // Run cleanup — should NOT delete legacy snapshot
            let cleaned = cleanup_expired_snapshots(conn)?;
            assert_eq!(cleaned, 0, "legacy snapshot should not be cleaned up");

            // Verify still accessible
            let snap = get_snapshot(conn, "sg1")?.unwrap();
            assert_eq!(snap.data, b"legacy_data");
            assert_eq!(snap.uploaded_by_device_id, None);

            Ok(())
        })
        .unwrap();
    }

    /// Test 8: Cleanup preserves non-expired snapshots.
    #[test]
    fn test_cleanup_preserves_non_expired() {
        let db = test_db();
        db.with_conn(|conn| {
            create_sync_group(conn, "sg_a", 0)?;
            create_sync_group(conn, "sg_b", 0)?;

            let future = now_secs() + 3600;
            let past = now_secs() - 3600;

            // sg_a: expires in 1 hour (valid)
            upsert_snapshot(conn, "sg_a", 1, 5, b"valid", Some(future), None, Some("dev1"))?;
            // sg_b: expired 1 hour ago
            upsert_snapshot(conn, "sg_b", 1, 5, b"expired", Some(past), None, Some("dev2"))?;

            let cleaned = cleanup_expired_snapshots(conn)?;
            assert_eq!(cleaned, 1, "only expired snapshot should be cleaned");

            // sg_a still exists
            assert!(get_snapshot(conn, "sg_a")?.is_some(), "valid snapshot should exist");
            // sg_b gone
            assert!(get_snapshot(conn, "sg_b")?.is_none(), "expired snapshot should be gone");

            Ok(())
        })
        .unwrap();
    }

    /// Test 9: get_safe_prune_seq returns min of snapshot seq and acked seq.
    #[test]
    fn test_prune_seq_min_of_snapshot_and_acked() {
        let db = test_db();
        db.with_conn(|conn| {
            create_sync_group(conn, "sg1", 0)?;
            register_device(conn, "sg1", "dev1", &[1; 32], &[2; 32], 0)?;
            touch_device(conn, "sg1", "dev1")?;

            // Snapshot at seq=50
            upsert_snapshot(conn, "sg1", 0, 50, b"snap", None, None, None)?;

            // Device acked to seq=30
            upsert_device_receipt(conn, "sg1", "dev1", 30)?;

            // min(50, 30) = 30
            let safe = get_safe_prune_seq(conn, "sg1", 3600)?;
            assert_eq!(safe, Some(30), "should be min of snapshot(50) and acked(30)");

            // Device acked to seq=60
            upsert_device_receipt(conn, "sg1", "dev1", 60)?;

            // min(50, 60) = 50
            let safe = get_safe_prune_seq(conn, "sg1", 3600)?;
            assert_eq!(safe, Some(50), "should be min of snapshot(50) and acked(60)");

            Ok(())
        })
        .unwrap();
    }

    /// Test 10: Auto-delete only for different device — verifies that
    /// uploaded_by_device_id is correctly stored and can be used by the
    /// HTTP handler to decide whether to auto-delete.
    #[test]
    fn test_auto_delete_only_for_different_device() {
        let db = test_db();
        db.with_conn(|conn| {
            create_sync_group(conn, "sg1", 0)?;
            register_device(conn, "sg1", "dev_a", &[1; 32], &[2; 32], 0)?;
            register_device(conn, "sg1", "dev_b", &[3; 32], &[4; 32], 0)?;

            let future = now_secs() + 300;

            // Device A uploads snapshot
            upsert_snapshot(conn, "sg1", 0, 10, b"snap", Some(future), None, Some("dev_a"))?;

            // Device A downloads — check uploaded_by matches (no auto-delete)
            let snap = get_snapshot(conn, "sg1")?.unwrap();
            let uploader = snap.uploaded_by_device_id.as_deref().unwrap();
            let downloading_device = "dev_a";
            let is_different = uploader != downloading_device;
            assert!(!is_different, "same device should NOT trigger auto-delete");
            // Snapshot should still exist
            assert!(get_snapshot(conn, "sg1")?.is_some());

            // Device B downloads — different device triggers auto-delete
            let snap = get_snapshot(conn, "sg1")?.unwrap();
            let uploader = snap.uploaded_by_device_id.as_deref().unwrap();
            let downloading_device = "dev_b";
            let is_different = uploader != downloading_device;
            assert!(is_different, "different device should trigger auto-delete");

            // Simulate auto-delete (as done by the HTTP handler)
            delete_snapshot(conn, "sg1")?;

            // Verify snapshot is gone
            assert!(
                get_snapshot(conn, "sg1")?.is_none(),
                "snapshot should be deleted after cross-device download"
            );

            Ok(())
        })
        .unwrap();
    }

    /// Test 13: Push batches without snapshot, verify no blocking.
    #[test]
    fn test_push_limit_without_snapshot() {
        let db = test_db();
        db.with_conn(|conn| {
            create_sync_group(conn, "sg1", 0)?;
            register_device(conn, "sg1", "dev1", &[1; 32], &[2; 32], 0)?;
            touch_device(conn, "sg1", "dev1")?;

            // Push many batches without any snapshot
            for i in 0..20 {
                insert_batch(conn, "sg1", 0, "dev1", &format!("b{i}"), b"data")?;
            }

            // Verify all 20 batches exist
            let batches = get_batches_since(conn, "sg1", 0, 100)?;
            assert_eq!(batches.len(), 20);

            // ACK some (device acked up to batch 10)
            let seq_10 = batches[9].server_seq;
            upsert_device_receipt(conn, "sg1", "dev1", seq_10)?;

            // No snapshot, so ACKs alone do not create a safe prune point.
            let safe = get_safe_prune_seq(conn, "sg1", 3600)?;
            assert_eq!(safe, None);

            let pruned = prune_batches_with_unexpired_snapshots(conn, 3600)?;
            assert_eq!(pruned, 0, "cleanup must not prune without a snapshot");

            // Can still push more
            let new_seq = insert_batch(conn, "sg1", 0, "dev1", "b_new", b"new_data")?;
            assert!(new_seq > 0, "should successfully push without pruning");

            let batches = get_batches_since(conn, "sg1", 0, 100)?;
            assert_eq!(batches.len(), 21, "20 existing + 1 new");

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn test_cleanup_expired_ml_dsa_grace_keys() {
        let db = test_db();
        db.with_conn(|conn| {
            create_sync_group(conn, "sg1", 0)?;
            let ml_dsa_pk = vec![0xAA; 1952];
            let ml_kem_pk = vec![0xBB; 1184];
            register_device_with_pq(
                conn,
                "sg1",
                "dev1",
                &[1; 32],
                &[2; 32],
                &ml_dsa_pk,
                &ml_kem_pk,
                &[],
                0,
            )?;

            // Rotate the key so the old key lands in the grace slot.
            let new_ml_dsa_pk = vec![0xCC; 1952];
            let grace_expires_at = now_secs() + 3600; // 1 hour from now
            let rotated =
                rotate_device_ml_dsa(conn, "sg1", "dev1", &new_ml_dsa_pk, 1, grace_expires_at)?;
            assert!(rotated, "rotation should apply");

            // Verify the grace key is present.
            let device = get_device(conn, "sg1", "dev1")?.expect("device exists");
            assert_eq!(device.prev_ml_dsa_65_public_key, ml_dsa_pk);
            assert_eq!(device.prev_ml_dsa_65_expires_at, Some(grace_expires_at));

            // Cleanup with "now" before the expiry — should NOT clear the grace key.
            let cleaned = cleanup_expired_ml_dsa_grace_keys(conn, now_secs())?;
            assert_eq!(cleaned, 0, "non-expired grace key should not be cleared");

            let device = get_device(conn, "sg1", "dev1")?.expect("device exists");
            assert_eq!(device.prev_ml_dsa_65_public_key, ml_dsa_pk, "grace key still present");
            assert_eq!(device.prev_ml_dsa_65_expires_at, Some(grace_expires_at));

            // Cleanup with a timestamp after the expiry — should clear the grace key.
            let cleaned = cleanup_expired_ml_dsa_grace_keys(conn, grace_expires_at + 1)?;
            assert_eq!(cleaned, 1, "expired grace key should be cleared");

            let device = get_device(conn, "sg1", "dev1")?.expect("device exists");
            assert!(device.prev_ml_dsa_65_public_key.is_empty(), "grace key should be empty");
            assert_eq!(device.prev_ml_dsa_65_expires_at, None, "expiry should be NULL");

            // The current key should be untouched.
            assert_eq!(device.ml_dsa_65_public_key, new_ml_dsa_pk);
            assert_eq!(device.ml_dsa_key_generation, 1);

            Ok(())
        })
        .unwrap();
    }

    // ── Media upload lifecycle ───────────────────────────────────────────

    /// Create a sync group so media FKs are satisfiable.
    fn media_test_db() -> Database {
        let db = test_db();
        db.with_conn(|conn| {
            create_sync_group(conn, "sg", 0)?;
            Ok(())
        })
        .unwrap();
        db
    }

    const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[test]
    fn servable_predicate_covers_all_states() {
        let now = 1_000_000;
        let base = MediaRow {
            media_id: "m".into(),
            sync_id: "sg".into(),
            device_id: "d".into(),
            size_bytes: 10,
            content_hash: HASH_A.into(),
            created_at: now,
            expires_at: None,
            deleted_at: None,
            committed_at: Some(now),
            reserved_at: None,
        };
        // committed, not deleted, no TTL → servable
        assert!(base.is_servable_at(now));
        // pending (committed_at NULL) → not servable, is_pending
        let pending = MediaRow { committed_at: None, reserved_at: Some(now), ..base.clone() };
        assert!(!pending.is_servable_at(now));
        assert!(pending.is_pending());
        // soft-deleted → not servable, not pending
        let deleted = MediaRow { deleted_at: Some(now), ..base.clone() };
        assert!(!deleted.is_servable_at(now));
        assert!(!deleted.is_pending());
        // expired → not servable
        let expired = MediaRow { expires_at: Some(now - 1), ..base.clone() };
        assert!(!expired.is_servable_at(now));
        // future TTL → servable
        let live = MediaRow { expires_at: Some(now + 1), ..base.clone() };
        assert!(live.is_servable_at(now));
    }

    /// Open an IMMEDIATE txn and run `reserve_media_upload` against it.
    fn reserve(
        db: &Database,
        media_id: &str,
        hash: &str,
        size: i64,
        ttl: Option<i64>,
        quota: i64,
        now: i64,
        file_present: bool,
    ) -> ReserveOutcome {
        db.with_conn(|conn| {
            let tx = conn.unchecked_transaction()?;
            let oc = reserve_media_upload(
                &tx,
                media_id,
                "sg",
                "d",
                size,
                hash,
                ttl,
                quota,
                now,
                300,
                file_present,
            )?;
            tx.commit()?;
            Ok(oc)
        })
        .unwrap()
    }

    fn get_media_metadata(
        conn: &Connection,
        media_id: &str,
    ) -> Result<Option<MediaRow>, rusqlite::Error> {
        super::get_media_metadata(conn, "sg", media_id)
    }

    fn finalize_media(conn: &Connection, media_id: &str, now: i64) -> Result<(), rusqlite::Error> {
        super::finalize_media(conn, "sg", media_id, now)
    }

    fn mark_media_deleted(conn: &Connection, media_id: &str) -> Result<(), rusqlite::Error> {
        super::mark_media_deleted(conn, "sg", media_id)
    }

    #[test]
    fn reserve_insert_then_finalize_is_servable() {
        let db = media_test_db();
        let now = 1_000_000;
        let oc = reserve(&db, "m1", HASH_A, 100, None, 10_000, now, false);
        assert_eq!(oc, ReserveOutcome::ReservedPending);
        // Pending → counts toward quota, not yet servable.
        db.with_read_conn(|c| {
            let row = get_media_metadata(c, "m1")?.unwrap();
            assert!(row.is_pending());
            assert!(!row.is_servable_at(now));
            assert_eq!(get_group_media_usage_at(c, "sg", now, 300)?, 100);
            Ok(())
        })
        .unwrap();
        // Finalize → servable.
        db.with_conn(|c| finalize_media(c, "m1", now)).unwrap();
        db.with_read_conn(|c| {
            let row = get_media_metadata(c, "m1")?.unwrap();
            assert!(row.is_servable_at(now));
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn reserve_same_hash_file_present_is_idempotent_and_extends_ttl() {
        let db = media_test_db();
        let now = 1_000_000;
        // Commit a row with a short TTL.
        reserve(&db, "m1", HASH_A, 100, Some(now + 3600), 10_000, now, false);
        db.with_conn(|c| finalize_media(c, "m1", now)).unwrap();
        // Re-upload identical content, file present, longer TTL.
        let oc = reserve(&db, "m1", HASH_A, 100, Some(now + 7200), 10_000, now, true);
        assert_eq!(oc, ReserveOutcome::AlreadyServable);
        db.with_read_conn(|c| {
            let row = get_media_metadata(c, "m1")?.unwrap();
            // TTL extended to the later value; Δquota 0.
            assert_eq!(row.expires_at, Some(now + 7200));
            assert_eq!(get_group_media_usage_at(c, "sg", now, 300)?, 100);
            Ok(())
        })
        .unwrap();
        // A shorter re-upload TTL must NOT shorten the existing one (max).
        reserve(&db, "m1", HASH_A, 100, Some(now + 60), 10_000, now, true);
        db.with_read_conn(|c| {
            assert_eq!(get_media_metadata(c, "m1")?.unwrap().expires_at, Some(now + 7200));
            Ok(())
        })
        .unwrap();
        // A default-retention (None) re-upload extends to "no expiry" (longest).
        reserve(&db, "m1", HASH_A, 100, None, 10_000, now, true);
        db.with_read_conn(|c| {
            assert_eq!(get_media_metadata(c, "m1")?.unwrap().expires_at, None);
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn reserve_same_hash_file_missing_is_repair_zero_quota_delta() {
        let db = media_test_db();
        let now = 1_000_000;
        reserve(&db, "m1", HASH_A, 100, None, 10_000, now, false);
        db.with_conn(|c| finalize_media(c, "m1", now)).unwrap();
        let before = db.with_read_conn(|c| get_group_media_usage_at(c, "sg", now, 300)).unwrap();
        // File reported missing → repair (promote+finalize), Δquota 0.
        let oc = reserve(&db, "m1", HASH_A, 100, None, 10_000, now, false);
        assert_eq!(oc, ReserveOutcome::RepairCommitted);
        let after = db.with_read_conn(|c| get_group_media_usage_at(c, "sg", now, 300)).unwrap();
        assert_eq!(before, after, "repair must not change quota");
    }

    #[test]
    fn reserve_different_hash_is_conflict() {
        let db = media_test_db();
        let now = 1_000_000;
        reserve(&db, "m1", HASH_A, 100, None, 10_000, now, false);
        db.with_conn(|c| finalize_media(c, "m1", now)).unwrap();
        let oc = reserve(&db, "m1", HASH_B, 100, None, 10_000, now, true);
        assert_eq!(oc, ReserveOutcome::HashConflict);
    }

    #[test]
    fn reserve_pending_same_hash_is_in_progress() {
        let db = media_test_db();
        let now = 1_000_000;
        // First writer reserves (pending, not finalized).
        assert_eq!(
            reserve(&db, "m1", HASH_A, 100, None, 10_000, now, false),
            ReserveOutcome::ReservedPending
        );
        // Second writer, same hash, while the first is in-flight → 202, no clobber.
        assert_eq!(
            reserve(&db, "m1", HASH_A, 100, None, 10_000, now, false),
            ReserveOutcome::PendingInFlight
        );
        // The pending row is unchanged (still one row, still pending).
        db.with_read_conn(|c| {
            assert!(get_media_metadata(c, "m1")?.unwrap().is_pending());
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn reserve_resurrect_after_expiry_adds_quota() {
        let db = media_test_db();
        let now = 1_000_000;
        // Commit then expire (set expires_at into the past).
        reserve(&db, "m1", HASH_A, 100, Some(now + 10), 10_000, now, false);
        db.with_conn(|c| finalize_media(c, "m1", now)).unwrap();
        let later = now + 100; // past the TTL
                               // Expired → excluded from usage, not servable.
        db.with_read_conn(|c| {
            assert_eq!(get_group_media_usage_at(c, "sg", later, 300)?, 0);
            assert!(!get_media_metadata(c, "m1")?.unwrap().is_servable_at(later));
            Ok(())
        })
        .unwrap();
        // Re-upload → resurrect (pending), Δquota +size.
        let oc = reserve(&db, "m1", HASH_A, 100, Some(later + 3600), 10_000, later, false);
        assert_eq!(oc, ReserveOutcome::ReservedPending);
        db.with_conn(|c| finalize_media(c, "m1", later)).unwrap();
        db.with_read_conn(|c| {
            assert!(get_media_metadata(c, "m1")?.unwrap().is_servable_at(later));
            assert_eq!(get_group_media_usage_at(c, "sg", later, 300)?, 100);
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn reserve_insert_over_quota_is_rejected() {
        let db = media_test_db();
        let now = 1_000_000;
        reserve(&db, "m1", HASH_A, 900, None, 1000, now, false);
        db.with_conn(|c| finalize_media(c, "m1", now)).unwrap();
        // 900 + 200 > 1000 → rejected, no row written.
        let oc = reserve(&db, "m2", HASH_B, 200, None, 1000, now, false);
        assert_eq!(oc, ReserveOutcome::QuotaExceeded);
        db.with_read_conn(|c| {
            assert!(get_media_metadata(c, "m2")?.is_none());
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn sweep_expired_ignores_pending_and_bounds_to_cap() {
        let db = media_test_db();
        let now = 1_000_000;
        // Two committed, expired rows.
        for (id, h) in [("e1", HASH_A), ("e2", HASH_B)] {
            db.with_conn(|c| {
                reserve_media_upload(
                    c,
                    id,
                    "sg",
                    "d",
                    10,
                    h,
                    Some(now - 1),
                    10_000,
                    now,
                    300,
                    false,
                )?;
                finalize_media(c, id, now - 10)?;
                Ok(())
            })
            .unwrap();
        }
        // A still-PENDING row that is "expired" by TTL but in-flight: the sweep
        // must NOT touch it (reconciliation-vs-promote race guard).
        db.with_conn(|c| {
            reserve_media_upload(
                c,
                "p1",
                "sg",
                "d",
                10,
                HASH_A,
                Some(now - 1),
                10_000,
                now,
                300,
                false,
            )
        })
        .unwrap();

        // Cap of 1 → only one expired row swept this call.
        let swept = db.with_conn(|c| sweep_expired_media_for_group(c, "sg", now, 1)).unwrap();
        assert_eq!(swept.len(), 1, "sweep bounded to cap");
        // Pending row survives.
        db.with_read_conn(|c| {
            assert!(get_media_metadata(c, "p1")?.unwrap().is_pending());
            Ok(())
        })
        .unwrap();
        // Second call sweeps the remaining expired committed row; never the pending.
        let swept2 = db.with_conn(|c| sweep_expired_media_for_group(c, "sg", now, 64)).unwrap();
        assert_eq!(swept2.len(), 1);
        db.with_read_conn(|c| {
            assert!(get_media_metadata(c, "p1")?.unwrap().is_pending());
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn stale_pending_reaper_spares_fresh_reserves() {
        let db = media_test_db();
        let now = now_secs();
        // A fresh, in-flight reserve (reserved_at = now): must NOT be reaped.
        db.with_conn(|c| {
            reserve_media_upload(c, "fresh", "sg", "d", 10, HASH_A, None, 10_000, now, 300, false)
        })
        .unwrap();
        // An abandoned reserve (reserved_at far in the past).
        db.with_conn(|c| {
            c.execute(
                "INSERT INTO media_metadata
                     (media_id, sync_id, device_id, size_bytes, content_hash, created_at, reserved_at)
                 VALUES ('stale','sg','d',10,?1,?2,?2)",
                params![HASH_B, now - 10_000],
            )?;
            Ok(())
        })
        .unwrap();

        let reaped = db.with_conn(|c| reap_stale_pending_media(c, 300)).unwrap();
        assert_eq!(reaped, vec![("sg".to_string(), "stale".to_string())]);
        db.with_read_conn(|c| {
            assert!(get_media_metadata(c, "fresh")?.is_some(), "fresh reserve must survive");
            assert!(get_media_metadata(c, "stale")?.is_none(), "stale reserve reaped");
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn cleanup_expired_media_matches_per_blob_ttl_and_spares_pending() {
        let db = media_test_db();
        let now = now_secs();
        // Committed row past its per-blob TTL → cleaned.
        db.with_conn(|c| {
            reserve_media_upload(
                c,
                "ttl",
                "sg",
                "d",
                10,
                HASH_A,
                Some(now - 5),
                10_000,
                now,
                300,
                false,
            )?;
            finalize_media(c, "ttl", now - 100)?;
            Ok(())
        })
        .unwrap();
        // In-flight pending row (committed_at NULL) → never cleaned by this path.
        db.with_conn(|c| {
            reserve_media_upload(
                c,
                "pend",
                "sg",
                "d",
                10,
                HASH_B,
                Some(now - 5),
                10_000,
                now,
                300,
                false,
            )
        })
        .unwrap();

        let cleaned = db.with_conn(|c| cleanup_expired_media(c, 90)).unwrap();
        assert_eq!(cleaned, vec![("sg".to_string(), "ttl".to_string())]);
        db.with_read_conn(|c| {
            assert!(get_media_metadata(c, "ttl")?.unwrap().deleted_at.is_some());
            assert!(get_media_metadata(c, "pend")?.unwrap().is_pending());
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn retain_unlinkable_media_spares_resurrected_rows() {
        let db = media_test_db();
        let now = now_secs();
        db.with_conn(|c| {
            // Committed then soft-deleted → still safe to unlink.
            reserve_media_upload(
                c,
                "still-del",
                "sg",
                "d",
                10,
                HASH_A,
                None,
                10_000,
                now,
                300,
                false,
            )?;
            finalize_media(c, "still-del", now)?;
            c.execute(
                "UPDATE media_metadata
                    SET deleted_at = ?1
                  WHERE sync_id = 'sg' AND media_id = 'still-del'",
                params![now],
            )?;
            // Committed-live (a heal resurrected + re-promoted it in the gap) →
            // must be spared so its fresh file is never unlinked.
            reserve_media_upload(
                c,
                "resurrected",
                "sg",
                "d",
                10,
                HASH_B,
                None,
                10_000,
                now,
                300,
                false,
            )?;
            finalize_media(c, "resurrected", now)?;
            Ok(())
        })
        .unwrap();

        let pairs = vec![
            ("sg".to_string(), "still-del".to_string()),
            ("sg".to_string(), "resurrected".to_string()),
            ("sg".to_string(), "absent".to_string()), // no row → safe to unlink
        ];
        let unlinkable = db.with_read_conn(|c| Ok(retain_unlinkable_media(c, &pairs))).unwrap();

        assert_eq!(
            unlinkable,
            vec![
                ("sg".to_string(), "still-del".to_string()),
                ("sg".to_string(), "absent".to_string()),
            ],
            "resurrected committed-live row is spared; soft-deleted + absent are unlinkable",
        );
    }

    #[test]
    fn legacy_backfill_marks_pre_lifecycle_rows_committed() {
        // Simulate a pre-lifecycle table: drop the new columns, insert a row,
        // then re-run the migration and assert committed_at backfilled.
        let db = test_db();
        db.with_conn(|conn| {
            create_sync_group(conn, "sg", 0)?;
            // Recreate the table without the lifecycle columns.
            conn.execute_batch("DROP TABLE media_metadata;")?;
            conn.execute_batch(
                "CREATE TABLE media_metadata (
                    media_id TEXT PRIMARY KEY, sync_id TEXT NOT NULL, device_id TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL, content_hash TEXT NOT NULL,
                    created_at INTEGER NOT NULL, expires_at INTEGER, deleted_at INTEGER
                );",
            )?;
            conn.execute(
                "INSERT INTO media_metadata
                     (media_id, sync_id, device_id, size_bytes, content_hash, created_at)
                 VALUES ('legacy','sg','d',10,?1,?2)",
                params![HASH_A, 12345],
            )?;
            // Re-run the lifecycle and primary-key migrations.
            migrate_media_lifecycle_columns(conn)?;
            migrate_media_metadata_sync_scoped_key(conn)?;
            assert!(media_metadata_has_sync_scoped_key(conn)?);
            let row = get_media_metadata(conn, "legacy")?.unwrap();
            assert_eq!(row.committed_at, Some(12345), "backfill committed_at = created_at");
            assert!(row.is_servable_at(99_999), "legacy row stays servable");

            create_sync_group(conn, "sg2", 0)?;
            let oc = reserve_media_upload(
                conn, "legacy", "sg2", "d2", 10, HASH_A, None, 10_000, 12346, 300, false,
            )?;
            assert_eq!(oc, ReserveOutcome::ReservedPending);
            assert!(super::get_media_metadata(conn, "sg2", "legacy")?.is_some());
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn list_servable_committed_media_excludes_pending_deleted_expired() {
        let db = media_test_db();
        let now = 1_000_000;
        db.with_conn(|c| {
            // committed-live → listed
            reserve_media_upload(c, "live", "sg", "d", 10, HASH_A, None, 10_000, now, 300, false)?;
            finalize_media(c, "live", now)?;
            // committed-live with a future TTL → listed
            reserve_media_upload(
                c,
                "live-ttl",
                "sg",
                "d",
                10,
                HASH_B,
                Some(now + 1000),
                10_000,
                now,
                300,
                false,
            )?;
            finalize_media(c, "live-ttl", now)?;
            // pending (never finalized) → excluded (reconciliation must ignore it)
            reserve_media_upload(
                c, "pending", "sg", "d", 10, HASH_A, None, 10_000, now, 300, false,
            )?;
            // expired committed → excluded
            reserve_media_upload(
                c,
                "expired",
                "sg",
                "d",
                10,
                HASH_B,
                Some(now - 1),
                10_000,
                now,
                300,
                false,
            )?;
            finalize_media(c, "expired", now)?;
            // soft-deleted → excluded
            reserve_media_upload(c, "del", "sg", "d", 10, HASH_A, None, 10_000, now, 300, false)?;
            finalize_media(c, "del", now)?;
            mark_media_deleted(c, "del")?;
            Ok(())
        })
        .unwrap();

        let mut listed = db.with_read_conn(|c| list_servable_committed_media(c, now)).unwrap();
        listed.sort();
        assert_eq!(
            listed,
            vec![
                ("sg".to_string(), "live".to_string()),
                ("sg".to_string(), "live-ttl".to_string()),
            ]
        );
    }

    #[test]
    fn reserve_cross_sync_same_media_id_is_independent() {
        let db = media_test_db();
        db.with_conn(|c| create_sync_group(c, "sg2", 0)).unwrap();
        let now = 1_000_000;
        // Group "sg" owns media_id "m" with a fixed TTL.
        db.with_conn(|c| {
            reserve_media_upload(
                c,
                "m",
                "sg",
                "d",
                10,
                HASH_A,
                Some(now + 1000),
                10_000,
                now,
                300,
                false,
            )?;
            finalize_media(c, "m", now)?;
            Ok(())
        })
        .unwrap();

        // Group "sg2" can independently upload the same media_id + hash.
        let oc = db
            .with_conn(|c| {
                let tx = c.unchecked_transaction()?;
                let oc = reserve_media_upload(
                    &tx, "m", "sg2", "d2", 10, HASH_A, None, 10_000, now, 300, true,
                )?;
                tx.commit()?;
                Ok(oc)
            })
            .unwrap();
        assert_eq!(oc, ReserveOutcome::ReservedPending);

        db.with_read_conn(|c| {
            let sg_row = get_media_metadata(c, "m")?.unwrap();
            let sg2_row = super::get_media_metadata(c, "sg2", "m")?.unwrap();
            assert_eq!(sg_row.sync_id, "sg");
            assert_eq!(sg_row.expires_at, Some(now + 1000));
            assert_eq!(sg2_row.sync_id, "sg2");
            assert!(sg2_row.is_pending());
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn cleanup_respects_future_ttl_over_created_at_floor() {
        // The whole point of re-supply: a blob with a fresh per-blob TTL must
        // survive even if its created_at is years past the global retention
        // floor (a re-upload only refreshes expires_at, not created_at).
        let db = media_test_db();
        let now = now_secs();
        let ancient = now - 365 * 86400; // ~1 year old
        db.with_conn(|c| {
            // Old created_at but a FUTURE per-blob TTL → must NOT be cleaned.
            c.execute(
                "INSERT INTO media_metadata
                     (media_id, sync_id, device_id, size_bytes, content_hash, created_at, expires_at, committed_at)
                 VALUES ('healed','sg','d',10,?1,?2,?3,?2)",
                params![HASH_A, ancient, now + 48 * 3600],
            )?;
            // Old created_at, NO TTL (default retention) → governed by floor → cleaned.
            c.execute(
                "INSERT INTO media_metadata
                     (media_id, sync_id, device_id, size_bytes, content_hash, created_at, committed_at)
                 VALUES ('stale-default','sg','d',10,?1,?2,?2)",
                params![HASH_B, ancient],
            )?;
            Ok(())
        })
        .unwrap();

        let cleaned = db.with_conn(|c| cleanup_expired_media(c, 90)).unwrap();
        assert_eq!(cleaned, vec![("sg".to_string(), "stale-default".to_string())]);
        db.with_read_conn(|c| {
            assert!(
                get_media_metadata(c, "healed")?.unwrap().deleted_at.is_none(),
                "future-TTL blob must survive its old created_at"
            );
            assert!(get_media_metadata(c, "stale-default")?.unwrap().deleted_at.is_some());
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn servable_media_subset_returns_only_servable_in_group() {
        let db = media_test_db();
        db.with_conn(|c| create_sync_group(c, "sg2", 0)).unwrap();
        let now = 1_000_000;
        db.with_conn(|c| {
            // committed-live (no TTL) and committed-live (future TTL) → present
            reserve_media_upload(c, "live", "sg", "d", 10, HASH_A, None, 10_000, now, 300, false)?;
            finalize_media(c, "live", now)?;
            reserve_media_upload(
                c,
                "live-ttl",
                "sg",
                "d",
                10,
                HASH_B,
                Some(now + 1000),
                10_000,
                now,
                300,
                false,
            )?;
            finalize_media(c, "live-ttl", now)?;
            // pending, expired, soft-deleted → absent
            reserve_media_upload(
                c, "pending", "sg", "d", 10, HASH_A, None, 10_000, now, 300, false,
            )?;
            reserve_media_upload(
                c,
                "expired",
                "sg",
                "d",
                10,
                HASH_B,
                Some(now - 1),
                10_000,
                now,
                300,
                false,
            )?;
            finalize_media(c, "expired", now)?;
            reserve_media_upload(
                c, "deleted", "sg", "d", 10, HASH_A, None, 10_000, now, 300, false,
            )?;
            finalize_media(c, "deleted", now)?;
            mark_media_deleted(c, "deleted")?;
            // same role in another group → must NOT leak across sync_id
            reserve_media_upload(
                c, "other", "sg2", "d", 10, HASH_B, None, 10_000, now, 300, false,
            )?;
            finalize_media(c, "other", now)?;
            Ok(())
        })
        .unwrap();

        let req: Vec<String> =
            ["live", "live-ttl", "pending", "expired", "deleted", "other", "nope"]
                .iter()
                .map(|s| s.to_string())
                .collect();
        let mut got = db.with_read_conn(|c| servable_media_subset(c, "sg", &req, now)).unwrap();
        got.sort();
        assert_eq!(got, vec!["live".to_string(), "live-ttl".to_string()]);
        // Empty input → empty (no all-rows query).
        assert!(db
            .with_read_conn(|c| servable_media_subset(c, "sg", &[], now))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn pending_counts_toward_quota_regardless_of_ttl() {
        // A non-stale pending reserve occupies space even if its prospective TTL
        // has nominally elapsed — quota must count it by reserved_at staleness
        // alone, or it could stop counting before the reaper deletes it.
        let db = media_test_db();
        let now = now_secs();
        db.with_conn(|c| {
            // Pending (committed_at NULL), fresh reserve, but expires_at already
            // in the past.
            c.execute(
                "INSERT INTO media_metadata
                     (media_id, sync_id, device_id, size_bytes, content_hash, created_at, expires_at, reserved_at)
                 VALUES ('p','sg','d',100,?1,?2,?3,?2)",
                params![HASH_A, now, now - 5],
            )?;
            Ok(())
        })
        .unwrap();
        // grace 300s, reserved_at = now (fresh) → counts despite past expires_at.
        assert_eq!(
            db.with_read_conn(|c| get_group_media_usage_at(c, "sg", now, 300)).unwrap(),
            100
        );
        // If the reserve were stale (reserved_at well before the cutoff) it would
        // drop out (about to be reaped).
        assert_eq!(
            db.with_read_conn(|c| get_group_media_usage_at(c, "sg", now + 10_000, 300)).unwrap(),
            0
        );
    }

    // -- Ephemeral mailbox ---------------------------------------------

    /// Create a group `g` with `devices` registered active.
    fn mailbox_group(db: &Database, devices: &[&str]) {
        db.with_conn(|conn| {
            create_sync_group(conn, "g", 0)?;
            for d in devices {
                register_device(conn, "g", d, &[1; 32], &[2; 32], 0)?;
            }
            Ok(())
        })
        .unwrap();
    }

    fn send(
        db: &Database,
        mid: &str,
        sender: &str,
        recipient: Option<&str>,
    ) -> DeviceMessageSendOutcome {
        db.with_conn(|conn| {
            insert_device_message(conn, "g", mid, sender, recipient, 0, b"payload", 3600, 100)
        })
        .unwrap()
    }

    fn pending_ids(db: &Database, device: &str) -> Vec<String> {
        db.with_read_conn(|conn| fetch_pending_device_messages(conn, "g", device, 256))
            .unwrap()
            .into_iter()
            .map(|m| m.message_id)
            .collect()
    }

    #[test]
    fn device_message_broadcast_roundtrip_excludes_sender() {
        let db = test_db();
        mailbox_group(&db, &["d1", "d2", "d3"]);
        assert_eq!(send(&db, "m1", "d1", None), DeviceMessageSendOutcome::Stored);
        // Broadcast reaches every other device, not the sender.
        assert!(pending_ids(&db, "d1").is_empty());
        assert_eq!(pending_ids(&db, "d2"), vec!["m1".to_string()]);
        assert_eq!(pending_ids(&db, "d3"), vec!["m1".to_string()]);
    }

    #[test]
    fn device_message_targeted_only_to_recipient() {
        let db = test_db();
        mailbox_group(&db, &["d1", "d2", "d3"]);
        send(&db, "m1", "d1", Some("d2"));
        assert_eq!(pending_ids(&db, "d2"), vec!["m1".to_string()]);
        assert!(pending_ids(&db, "d3").is_empty());
        assert!(pending_ids(&db, "d1").is_empty());
    }

    #[test]
    fn device_message_per_device_ack_does_not_suppress_others() {
        // Spec test: A acks a message, B must still see it (per-device ack).
        let db = test_db();
        mailbox_group(&db, &["d1", "d2", "d3"]);
        send(&db, "m1", "d1", None);
        let n = db.with_conn(|c| ack_device_messages(c, "g", "d2", &["m1".to_string()])).unwrap();
        assert_eq!(n, 1);
        assert!(pending_ids(&db, "d2").is_empty(), "d2 acked → suppressed for d2");
        assert_eq!(pending_ids(&db, "d3"), vec!["m1".to_string()], "d3 still sees it");
    }

    #[test]
    fn device_message_dedup_coalesces_same_id() {
        let db = test_db();
        mailbox_group(&db, &["d1", "d2"]);
        assert_eq!(send(&db, "dup", "d1", None), DeviceMessageSendOutcome::Stored);
        // A second send with the same message_id (even different sender) coalesces.
        assert_eq!(send(&db, "dup", "d2", None), DeviceMessageSendOutcome::Coalesced);
        let count: i64 = db
            .with_read_conn(|c| {
                c.query_row(
                    "SELECT COUNT(*) FROM device_messages WHERE message_id = 'dup'",
                    [],
                    |r| r.get(0),
                )
            })
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn device_message_pending_cap_enforced_but_dups_exempt() {
        let db = test_db();
        mailbox_group(&db, &["d1", "d2"]);
        // Cap of 2: third distinct message from d1 is rejected.
        let mk = |c: &Connection, mid: &str| {
            insert_device_message(c, "g", mid, "d1", None, 0, b"p", 3600, 2)
        };
        assert_eq!(db.with_conn(|c| mk(c, "a")).unwrap(), DeviceMessageSendOutcome::Stored);
        assert_eq!(db.with_conn(|c| mk(c, "b")).unwrap(), DeviceMessageSendOutcome::Stored);
        assert_eq!(
            db.with_conn(|c| mk(c, "c")).unwrap(),
            DeviceMessageSendOutcome::PendingCapExceeded
        );
        // Re-sending an already-stored id at the cap is a coalesce, NOT a reject.
        assert_eq!(db.with_conn(|c| mk(c, "a")).unwrap(), DeviceMessageSendOutcome::Coalesced);
        // The rejected message was not stored.
        let count: i64 = db
            .with_read_conn(|c| {
                c.query_row(
                    "SELECT COUNT(*) FROM device_messages WHERE sender_device_id = 'd1'",
                    [],
                    |r| r.get(0),
                )
            })
            .unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn device_message_ack_only_for_existing_messages() {
        // A client cannot grow the ack table with arbitrary ids.
        let db = test_db();
        mailbox_group(&db, &["d1", "d2"]);
        send(&db, "real", "d1", None);
        let n = db
            .with_conn(|c| {
                ack_device_messages(c, "g", "d2", &["real".to_string(), "bogus".to_string()])
            })
            .unwrap();
        assert_eq!(n, 1, "only the real message id is acked");
        let count: i64 = db
            .with_read_conn(|c| {
                c.query_row("SELECT COUNT(*) FROM device_message_acks", [], |r| r.get(0))
            })
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn device_message_cleanup_expired() {
        let db = test_db();
        mailbox_group(&db, &["d1", "d2"]);
        let now = now_secs();
        db.with_conn(|c| {
            c.execute(
                "INSERT INTO device_messages (sync_id, message_id, sender_device_id, recipient_device_id, epoch_id, payload, created_at, expires_at)
                 VALUES ('g', 'old', 'd1', NULL, 0, X'00', ?1, ?2)",
                params![now - 1000, now - 10],
            )?;
            Ok(())
        })
        .unwrap();
        send(&db, "fresh", "d1", None);
        let deleted = db.with_conn(cleanup_expired_device_messages).unwrap();
        assert_eq!(deleted, 1);
        assert_eq!(pending_ids(&db, "d2"), vec!["fresh".to_string()]);
    }

    #[test]
    fn device_message_cleanup_fully_acked_broadcast() {
        // Broadcast to a 3-device group (sender + 2 recipients): deleted once
        // both recipients ack.
        let db = test_db();
        mailbox_group(&db, &["d1", "d2", "d3"]);
        send(&db, "bcast", "d1", None);
        db.with_conn(|c| ack_device_messages(c, "g", "d2", &["bcast".to_string()])).unwrap();
        // Only one of two recipients acked → not yet fully acked.
        assert_eq!(db.with_conn(cleanup_expired_device_messages).unwrap(), 0);
        db.with_conn(|c| ack_device_messages(c, "g", "d3", &["bcast".to_string()])).unwrap();
        // Both recipients acked → fully acked → swept (with its ack rows).
        assert_eq!(db.with_conn(cleanup_expired_device_messages).unwrap(), 1);
        let acks: i64 = db
            .with_read_conn(|c| {
                c.query_row("SELECT COUNT(*) FROM device_message_acks", [], |r| r.get(0))
            })
            .unwrap();
        assert_eq!(acks, 0, "orphan acks cleaned with their message");
    }

    #[test]
    fn device_message_cleanup_fully_acked_targeted() {
        let db = test_db();
        mailbox_group(&db, &["d1", "d2", "d3"]);
        send(&db, "t", "d1", Some("d2"));
        // d3 acking is irrelevant (not the recipient); only d2's ack sheds it.
        db.with_conn(|c| ack_device_messages(c, "g", "d2", &["t".to_string()])).unwrap();
        assert_eq!(db.with_conn(cleanup_expired_device_messages).unwrap(), 1);
    }

    #[test]
    fn device_message_cleanup_broadcast_ignores_sender_self_ack() {
        // A sender (or colluder) must NOT be able to shed its own broadcast
        // before the real recipients drain it. Eligible recipients are d2, d3.
        let db = test_db();
        mailbox_group(&db, &["d1", "d2", "d3"]);
        send(&db, "bc", "d1", None);
        // Sender self-acks, and one real recipient acks: still not fully acked
        // (d3 hasn't), so the broadcast must survive.
        db.with_conn(|c| ack_device_messages(c, "g", "d1", &["bc".to_string()])).unwrap();
        db.with_conn(|c| ack_device_messages(c, "g", "d2", &["bc".to_string()])).unwrap();
        assert_eq!(
            db.with_conn(cleanup_expired_device_messages).unwrap(),
            0,
            "sender self-ack + one recipient must not shed the broadcast"
        );
        assert_eq!(pending_ids(&db, "d3"), vec!["bc".to_string()], "d3 can still drain it");
        // Now the last real recipient acks → fully acked → swept.
        db.with_conn(|c| ack_device_messages(c, "g", "d3", &["bc".to_string()])).unwrap();
        assert_eq!(db.with_conn(cleanup_expired_device_messages).unwrap(), 1);
    }

    #[test]
    fn device_message_cleanup_broadcast_not_shed_without_eligible_recipient() {
        // If the only other device is not active, the broadcast is undeliverable
        // *now* but must not be shed early on a zero/ack-count match — it lingers
        // until TTL (the device may return).
        let db = test_db();
        mailbox_group(&db, &["d1", "d2"]);
        db.with_conn(|c| {
            c.execute("UPDATE devices SET status = 'stale' WHERE device_id = 'd2'", [])?;
            Ok(())
        })
        .unwrap();
        send(&db, "bc", "d1", None);
        assert_eq!(
            db.with_conn(cleanup_expired_device_messages).unwrap(),
            0,
            "no eligible recipient ⇒ not fully acked ⇒ kept until TTL"
        );
    }

    #[test]
    fn device_message_deleted_with_sync_group() {
        let db = test_db();
        mailbox_group(&db, &["d1", "d2"]);
        send(&db, "m", "d1", None);
        db.with_conn(|c| ack_device_messages(c, "g", "d2", &["m".to_string()])).unwrap();
        // FK to sync_groups: deletion must remove mailbox rows first or fail.
        db.with_conn(|c| delete_sync_group(c, "g")).unwrap();
        let msgs: i64 = db
            .with_read_conn(|c| {
                c.query_row("SELECT COUNT(*) FROM device_messages", [], |r| r.get(0))
            })
            .unwrap();
        let acks: i64 = db
            .with_read_conn(|c| {
                c.query_row("SELECT COUNT(*) FROM device_message_acks", [], |r| r.get(0))
            })
            .unwrap();
        assert_eq!((msgs, acks), (0, 0));
    }
}
