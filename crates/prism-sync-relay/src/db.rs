use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
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
    pub epoch: i64,
    pub status: String,
    pub permission: String,
    pub last_seen_at: i64,
}

#[derive(Debug, Clone)]
pub struct DeviceListEntry {
    pub device_id: String,
    pub signing_public_key: Vec<u8>,
    pub x25519_public_key: Vec<u8>,
    pub epoch: i64,
    pub status: String,
    pub permission: String,
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Current unix timestamp in seconds.
pub fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
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

// ---------------------------------------------------------------------------
// Database wrapper
// ---------------------------------------------------------------------------

pub struct Database {
    conn: Arc<Mutex<Connection>>,
}

impl Database {
    /// Open a persistent database at the given path.
    pub fn open(path: &str) -> Result<Self, rusqlite::Error> {
        if let Some(parent) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let conn = Connection::open(path)?;
        apply_pragmas(&conn)?;
        migrate(&conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Open an in-memory database for testing.
    pub fn in_memory() -> Result<Self, rusqlite::Error> {
        let conn = Connection::open_in_memory()?;
        // In-memory: skip mmap/cache pragmas, but enable FK and WAL-like settings
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA busy_timeout = 5000;
             PRAGMA temp_store = memory;",
        )?;
        migrate(&conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Run a blocking DB operation on the current thread.
    /// For async contexts, wrap calls in `tokio::task::spawn_blocking`.
    pub fn with_conn<F, T>(&self, f: F) -> Result<T, rusqlite::Error>
    where
        F: FnOnce(&Connection) -> Result<T, rusqlite::Error>,
    {
        let conn = self.conn.lock().expect("db mutex poisoned");
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
         PRAGMA auto_vacuum = INCREMENTAL;",
    )
}

fn migrate(conn: &Connection) -> Result<(), rusqlite::Error> {
    conn.execute_batch(
        "
        -- Sync groups
        CREATE TABLE IF NOT EXISTS sync_groups (
            sync_id         TEXT PRIMARY KEY,
            current_epoch   INTEGER NOT NULL DEFAULT 0,
            needs_rekey     INTEGER NOT NULL DEFAULT 0,
            created_at      INTEGER NOT NULL,
            updated_at      INTEGER NOT NULL
        );

        -- Devices
        CREATE TABLE IF NOT EXISTS devices (
            sync_id             TEXT NOT NULL,
            device_id           TEXT NOT NULL,
            signing_public_key  BLOB NOT NULL,
            x25519_public_key   BLOB NOT NULL,
            epoch               INTEGER NOT NULL DEFAULT 0,
            status              TEXT NOT NULL DEFAULT 'active',
            permission          TEXT NOT NULL DEFAULT 'admin',
            registered_at       INTEGER NOT NULL,
            last_seen_at        INTEGER NOT NULL,
            revoked_at          INTEGER,
            remote_wipe         INTEGER NOT NULL DEFAULT 0,
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

        -- Registration nonces
        CREATE TABLE IF NOT EXISTS registration_nonces (
            nonce       TEXT PRIMARY KEY,
            sync_id     TEXT NOT NULL,
            created_at  INTEGER NOT NULL,
            expires_at  INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_nonces_expires
            ON registration_nonces(expires_at);

        -- Enrollment invitations
        CREATE TABLE IF NOT EXISTS enrollment_invitations (
            id                      TEXT PRIMARY KEY,
            sync_id                 TEXT NOT NULL,
            inviter_device_id       TEXT NOT NULL,
            signature               BLOB NOT NULL,
            valid_until             INTEGER NOT NULL,
            consumed_at             INTEGER,
            consumed_by_device_id   TEXT,
            created_at              INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_enrollment_valid_until
            ON enrollment_invitations(valid_until);

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
        ",
    )?;

    // -- Incremental migrations for existing databases --
    // ALTER TABLE ADD COLUMN is a no-op if the table was freshly created above
    // with the columns already present. For pre-existing tables we need to add them.
    migrate_snapshots_ephemeral(conn)?;
    migrate_devices_remote_wipe(conn)?;

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
    permission: &str,
) -> Result<(), rusqlite::Error> {
    let now = now_secs();
    conn.execute(
        "INSERT INTO devices (
            sync_id, device_id, signing_public_key, x25519_public_key,
            epoch, status, permission, registered_at, last_seen_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, 'active', ?6, ?7, ?7)",
        params![sync_id, device_id, signing_pk, x25519_pk, epoch, permission, now],
    )?;
    Ok(())
}

pub fn get_device(
    conn: &Connection,
    sync_id: &str,
    device_id: &str,
) -> Result<Option<DeviceRecord>, rusqlite::Error> {
    conn.query_row(
        "SELECT device_id, signing_public_key, x25519_public_key, epoch, status, permission, last_seen_at
         FROM devices
         WHERE sync_id = ?1 AND device_id = ?2",
        params![sync_id, device_id],
        |row| {
            Ok(DeviceRecord {
                device_id: row.get(0)?,
                signing_public_key: row.get(1)?,
                x25519_public_key: row.get(2)?,
                epoch: row.get(3)?,
                status: row.get(4)?,
                permission: row.get(5)?,
                last_seen_at: row.get(6)?,
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
        "SELECT device_id, signing_public_key, x25519_public_key, epoch, status, permission
         FROM devices
         WHERE sync_id = ?1
         ORDER BY registered_at ASC",
    )?;
    let rows = stmt.query_map(params![sync_id], |row| {
        Ok(DeviceListEntry {
            device_id: row.get(0)?,
            signing_public_key: row.get(1)?,
            x25519_public_key: row.get(2)?,
            epoch: row.get(3)?,
            status: row.get(4)?,
            permission: row.get(5)?,
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
        "DELETE FROM device_receipts WHERE sync_id = ?1 AND device_id = ?2",
        params![sync_id, device_id],
    )?;
    tx.execute(
        "DELETE FROM rekey_artifacts WHERE sync_id = ?1 AND target_device_id = ?2",
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

pub fn get_device_permission(
    conn: &Connection,
    sync_id: &str,
    device_id: &str,
) -> Result<Option<String>, rusqlite::Error> {
    conn.query_row(
        "SELECT permission FROM devices WHERE sync_id = ?1 AND device_id = ?2",
        params![sync_id, device_id],
        |row| row.get(0),
    )
    .optional()
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

/// Validate a session token. Returns `(sync_id, device_id)` if valid and not expired.
pub fn validate_session(
    conn: &Connection,
    token: &str,
) -> Result<Option<(String, String)>, rusqlite::Error> {
    let token_hash = hash_token(token);
    let now = now_secs();
    conn.query_row(
        "SELECT sync_id, device_id
         FROM device_sessions
         WHERE session_token_hash = ?1 AND expires_at > ?2",
        params![token_hash, now],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .optional()
}

/// Extend the session expiry for a device (sliding window).
pub fn touch_session(
    conn: &Connection,
    sync_id: &str,
    device_id: &str,
    session_expiry_secs: i64,
) -> Result<(), rusqlite::Error> {
    let now = now_secs();
    let expires_at = now + session_expiry_secs;
    conn.execute(
        "UPDATE device_sessions
         SET last_active_at = ?1, expires_at = ?2
         WHERE sync_id = ?3 AND device_id = ?4",
        params![now, expires_at, sync_id, device_id],
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
    conn.execute(
        "DELETE FROM registration_nonces WHERE expires_at <= ?1",
        params![now],
    )
}

// ---------------------------------------------------------------------------
// Enrollment invitation queries
// ---------------------------------------------------------------------------

pub fn consume_invitation(
    conn: &Connection,
    invitation_id: &str,
    sync_id: &str,
    inviter_device_id: &str,
    target_device_id: &str,
) -> Result<(), rusqlite::Error> {
    let now = now_secs();
    // For consumed invitations, we store them with signature as empty and valid_until as 0
    // since those fields were verified at consumption time by the caller.
    conn.execute(
        "INSERT INTO enrollment_invitations (id, sync_id, inviter_device_id, signature, valid_until, consumed_at, consumed_by_device_id, created_at)
         VALUES (?1, ?2, ?3, X'', 0, ?4, ?5, ?4)",
        params![invitation_id, sync_id, inviter_device_id, now, target_device_id],
    )?;
    Ok(())
}

pub fn is_invitation_consumed(
    conn: &Connection,
    invitation_id: &str,
) -> Result<bool, rusqlite::Error> {
    let count: u64 = conn.query_row(
        "SELECT COUNT(*) FROM enrollment_invitations WHERE id = ?1 AND consumed_at IS NOT NULL",
        params![invitation_id],
        |row| row.get(0),
    )?;
    Ok(count > 0)
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

pub fn upsert_snapshot(
    conn: &Connection,
    sync_id: &str,
    epoch: i64,
    server_seq_at: i64,
    data: &[u8],
    expires_at: Option<i64>,
    target_device_id: Option<&str>,
    uploaded_by_device_id: Option<&str>,
) -> Result<(), rusqlite::Error> {
    let now = now_secs();
    conn.execute(
        "INSERT INTO snapshots (sync_id, epoch, server_seq_at, data, created_at, expires_at, target_device_id, uploaded_by_device_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
         ON CONFLICT(sync_id) DO UPDATE SET
            epoch = excluded.epoch,
            server_seq_at = excluded.server_seq_at,
            data = excluded.data,
            created_at = excluded.created_at,
            expires_at = excluded.expires_at,
            target_device_id = excluded.target_device_id,
            uploaded_by_device_id = excluded.uploaded_by_device_id",
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
    Ok(())
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

/// Get the safe pruning sequence: min of (snapshot seq, min acked seq excluding stale).
/// If no snapshot exists (or it has expired), uses min_acked_seq alone so that
/// pruning is not blocked at steady state when no snapshot is at rest.
pub fn get_safe_prune_seq(
    conn: &Connection,
    sync_id: &str,
    stale_threshold_secs: i64,
) -> Result<Option<i64>, rusqlite::Error> {
    let snapshot_seq: Option<i64> = conn
        .query_row(
            "SELECT server_seq_at FROM snapshots WHERE sync_id = ?1
               AND (expires_at IS NULL OR expires_at >= unixepoch())",
            params![sync_id],
            |row| row.get(0),
        )
        .optional()?;

    let min_acked = get_min_acked_seq(conn, sync_id, stale_threshold_secs)?;

    match (snapshot_seq, min_acked) {
        (Some(snap), Some(acked)) => Ok(Some(snap.min(acked))),
        (Some(snap), None) => Ok(Some(snap)),
        (None, Some(acked)) => Ok(Some(acked)),
        (None, None) => Ok(None),
    }
}

/// Delete batches with id < before_seq. Returns number deleted.
pub fn prune_batches_before(
    conn: &Connection,
    sync_id: &str,
    before_seq: i64,
) -> Result<usize, rusqlite::Error> {
    conn.execute(
        "DELETE FROM batches WHERE sync_id = ?1 AND id < ?2",
        params![sync_id, before_seq],
    )
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

// ---------------------------------------------------------------------------
// Cleanup queries
// ---------------------------------------------------------------------------

/// Delete a sync group and all associated data (cascading).
pub fn delete_sync_group(conn: &Connection, sync_id: &str) -> Result<(), rusqlite::Error> {
    let tx = conn.unchecked_transaction()?;

    tx.execute(
        "DELETE FROM rekey_artifacts WHERE sync_id = ?1",
        params![sync_id],
    )?;
    tx.execute(
        "DELETE FROM enrollment_invitations WHERE sync_id = ?1",
        params![sync_id],
    )?;
    tx.execute(
        "DELETE FROM device_sessions WHERE sync_id = ?1",
        params![sync_id],
    )?;
    tx.execute(
        "DELETE FROM device_receipts WHERE sync_id = ?1",
        params![sync_id],
    )?;
    tx.execute("DELETE FROM batches WHERE sync_id = ?1", params![sync_id])?;
    tx.execute("DELETE FROM snapshots WHERE sync_id = ?1", params![sync_id])?;
    tx.execute(
        "DELETE FROM registration_nonces WHERE sync_id = ?1",
        params![sync_id],
    )?;
    tx.execute("DELETE FROM devices WHERE sync_id = ?1", params![sync_id])?;
    tx.execute(
        "DELETE FROM sync_groups WHERE sync_id = ?1",
        params![sync_id],
    )?;

    tx.commit()?;
    Ok(())
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
    let sync_ids: Vec<String> = stmt
        .query_map(params![cutoff], |row| row.get(0))?
        .filter_map(|r| r.ok())
        .collect();

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
    let stale_ids: Vec<String> = stmt
        .query_map(params![cutoff], |row| row.get(0))?
        .filter_map(|r| r.ok())
        .collect();

    for sync_id in &stale_ids {
        delete_sync_group(conn, sync_id)?;
    }

    Ok(stale_ids.len())
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
    fn test_register_device_and_get_device() {
        let db = test_db();
        db.with_conn(|conn| {
            create_sync_group(conn, "sg1", 0)?;

            let signing_pk = vec![1u8; 32];
            let x25519_pk = vec![2u8; 32];
            register_device(conn, "sg1", "dev1", &signing_pk, &x25519_pk, 0, "admin")?;

            let device = get_device(conn, "sg1", "dev1")?;
            assert!(device.is_some());
            let device = device.unwrap();
            assert_eq!(device.device_id, "dev1");
            assert_eq!(device.signing_public_key, signing_pk);
            assert_eq!(device.x25519_public_key, x25519_pk);
            assert_eq!(device.epoch, 0);
            assert_eq!(device.status, "active");
            assert_eq!(device.permission, "admin");

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
            register_device(conn, "sg1", "dev1", &[1; 32], &[2; 32], 0, "admin")?;

            // Create session with 3600s expiry
            let token = create_session(conn, "sg1", "dev1", 3600)?;
            assert_eq!(token.len(), 64); // 32 bytes hex

            // Validate
            let result = validate_session(conn, &token)?;
            assert_eq!(result, Some(("sg1".to_string(), "dev1".to_string())));

            // Invalid token
            let result = validate_session(conn, "invalid_token")?;
            assert!(result.is_none());

            // Touch session
            touch_session(conn, "sg1", "dev1", 7200)?;

            // Still valid
            let result = validate_session(conn, &token)?;
            assert_eq!(result, Some(("sg1".to_string(), "dev1".to_string())));

            // Delete session
            delete_session(conn, "sg1", "dev1")?;
            let result = validate_session(conn, &token)?;
            assert!(result.is_none());

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
            upsert_snapshot(
                conn,
                "sg1",
                2,
                20,
                b"snap_data_v2",
                None,
                Some("dev2"),
                Some("dev1"),
            )?;
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
            register_device(conn, "sg1", "dev1", &[1; 32], &[2; 32], 0, "admin")?;
            register_device(conn, "sg1", "dev2", &[3; 32], &[4; 32], 0, "admin")?;

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
            register_device(conn, "sg1", "dev1", &[1; 32], &[2; 32], 0, "admin")?;
            create_session(conn, "sg1", "dev1", 3600)?;
            upsert_device_receipt(conn, "sg1", "dev1", 5)?;
            insert_batch(conn, "sg1", 0, "dev1", "b1", b"data")?;
            upsert_snapshot(conn, "sg1", 0, 0, b"snap", None, None, None)?;
            store_rekey_artifact(conn, "sg1", 1, "dev1", &[42; 32])?;
            consume_invitation(conn, "inv1", "sg1", "dev1", "dev2")?;
            create_nonce(conn, "sg1", 3600)?;

            // Delete everything
            delete_sync_group(conn, "sg1")?;

            // Verify all gone
            assert_eq!(get_sync_group_epoch(conn, "sg1")?, None);
            assert!(get_device(conn, "sg1", "dev1")?.is_none());
            assert!(get_snapshot(conn, "sg1")?.is_none());
            assert_eq!(get_latest_seq(conn, "sg1")?, 0);
            assert!(get_rekey_artifact(conn, "sg1", 1, "dev1")?.is_none());

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn test_permission_stored_correctly() {
        let db = test_db();
        db.with_conn(|conn| {
            create_sync_group(conn, "sg1", 0)?;

            register_device(conn, "sg1", "dev1", &[1; 32], &[2; 32], 0, "admin")?;
            register_device(conn, "sg1", "dev2", &[3; 32], &[4; 32], 0, "member")?;

            let perm1 = get_device_permission(conn, "sg1", "dev1")?;
            assert_eq!(perm1, Some("admin".to_string()));

            let perm2 = get_device_permission(conn, "sg1", "dev2")?;
            assert_eq!(perm2, Some("member".to_string()));

            let perm3 = get_device_permission(conn, "sg1", "nonexistent")?;
            assert!(perm3.is_none());

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
            register_device(conn, "sg1", "dev1", &signing_pk, &x25519_pk, 0, "admin")?;

            let devices = list_devices(conn, "sg1")?;
            assert_eq!(devices.len(), 1);
            assert_eq!(devices[0].device_id, "dev1");
            assert_eq!(devices[0].signing_public_key, signing_pk);
            assert_eq!(devices[0].x25519_public_key, x25519_pk);
            assert_eq!(devices[0].permission, "admin");

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn test_revoke_and_count_active_devices() {
        let db = test_db();
        db.with_conn(|conn| {
            create_sync_group(conn, "sg1", 0)?;
            register_device(conn, "sg1", "dev1", &[1; 32], &[2; 32], 0, "admin")?;
            register_device(conn, "sg1", "dev2", &[3; 32], &[4; 32], 0, "admin")?;

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
            register_device(conn, "sg1", "dev1", &[1; 32], &[2; 32], 0, "admin")?;
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
    fn test_enrollment_invitation() {
        let db = test_db();
        db.with_conn(|conn| {
            create_sync_group(conn, "sg1", 0)?;

            assert!(!is_invitation_consumed(conn, "inv1")?);

            consume_invitation(conn, "inv1", "sg1", "dev1", "dev2")?;

            assert!(is_invitation_consumed(conn, "inv1")?);

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
            register_device(conn, "sg1", "dev1", &[1; 32], &[2; 32], 0, "admin")?;
            register_device(conn, "sg1", "dev2", &[3; 32], &[4; 32], 0, "admin")?;
            touch_device(conn, "sg1", "dev1")?;
            touch_device(conn, "sg1", "dev2")?;

            // No snapshot, no receipts => min_acked is 0 (COALESCE), so prune seq is 0
            let seq = get_safe_prune_seq(conn, "sg1", 3600)?;
            assert_eq!(seq, Some(0));

            // No snapshot, with receipts => uses min_acked_seq alone
            upsert_device_receipt(conn, "sg1", "dev1", 5)?;
            upsert_device_receipt(conn, "sg1", "dev2", 8)?;
            let seq = get_safe_prune_seq(conn, "sg1", 3600)?;
            assert_eq!(seq, Some(5));

            // Add snapshot at seq 10 — now min(snapshot=10, min_acked=5) => 5
            upsert_snapshot(conn, "sg1", 0, 10, b"snap", None, None, None)?;
            let seq = get_safe_prune_seq(conn, "sg1", 3600)?;
            assert_eq!(seq, Some(5));

            // Both acked past snapshot => safe is snapshot seq (10)
            upsert_device_receipt(conn, "sg1", "dev1", 15)?;
            upsert_device_receipt(conn, "sg1", "dev2", 20)?;
            let seq = get_safe_prune_seq(conn, "sg1", 3600)?;
            assert_eq!(seq, Some(10));

            // Delete snapshot => falls back to min_acked_seq alone (15)
            delete_snapshot(conn, "sg1")?;
            let seq = get_safe_prune_seq(conn, "sg1", 3600)?;
            assert_eq!(seq, Some(15));

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn test_safe_prune_seq_ignores_expired_snapshot() {
        let db = test_db();
        db.with_conn(|conn| {
            create_sync_group(conn, "sg1", 0)?;
            register_device(conn, "sg1", "dev1", &[1; 32], &[2; 32], 0, "admin")?;
            touch_device(conn, "sg1", "dev1")?;
            upsert_device_receipt(conn, "sg1", "dev1", 20)?;

            // Insert snapshot with expiry in the past (already expired)
            let past = now_secs() - 100;
            upsert_snapshot(conn, "sg1", 0, 5, b"snap", Some(past), None, None)?;

            // Expired snapshot should be ignored; falls back to min_acked_seq (20)
            let seq = get_safe_prune_seq(conn, "sg1", 3600)?;
            assert_eq!(seq, Some(20));

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
            assert!(
                !created_again,
                "second call should be ignored and return false"
            );

            // Data remains consistent: epoch is still readable and unchanged
            let epoch = get_sync_group_epoch(conn, "sg1")?;
            assert_eq!(
                epoch,
                Some(0),
                "epoch should still be 0 after idempotent insert"
            );

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

            // Snapshot with expiry in the past is not returned by get_snapshot
            let past = now_secs() - 60;
            upsert_snapshot(
                conn,
                "sg1",
                1,
                10,
                b"expired",
                Some(past),
                None,
                Some("dev1"),
            )?;
            let snap = get_snapshot(conn, "sg1")?;
            assert!(snap.is_none(), "expired snapshot should not be returned");

            // Snapshot with expiry in the future is returned
            let future = now_secs() + 3600;
            upsert_snapshot(
                conn,
                "sg1",
                1,
                10,
                b"valid",
                Some(future),
                None,
                Some("dev1"),
            )?;
            let snap = get_snapshot(conn, "sg1")?.unwrap();
            assert_eq!(snap.data, b"valid");
            assert_eq!(snap.uploaded_by_device_id.as_deref(), Some("dev1"));

            // Snapshot with no expiry (legacy) is always returned
            upsert_snapshot(conn, "sg1", 1, 10, b"permanent", None, None, None)?;
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
            register_device(conn, "sg1", "dev_a", &[1; 32], &[2; 32], 0, "admin")?;
            register_device(conn, "sg1", "dev_b", &[3; 32], &[4; 32], 0, "admin")?;

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

    /// Test 2: Pruning works without snapshot — push batches, ACK all from
    /// all devices, verify get_safe_prune_seq returns min_acked_seq.
    #[test]
    fn test_pruning_works_without_snapshot() {
        let db = test_db();
        db.with_conn(|conn| {
            create_sync_group(conn, "sg1", 0)?;
            register_device(conn, "sg1", "dev1", &[1; 32], &[2; 32], 0, "admin")?;
            register_device(conn, "sg1", "dev2", &[3; 32], &[4; 32], 0, "admin")?;
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

            // Safe prune seq should be seq3 (min of all acked)
            let safe = get_safe_prune_seq(conn, "sg1", 3600)?;
            assert_eq!(safe, Some(seq3));

            // Prune everything before seq3
            let pruned = prune_batches_before(conn, "sg1", seq3)?;
            assert_eq!(pruned, 2, "should prune seq1 and seq2");

            // Only 3 batches remain
            let remaining = get_batches_since(conn, "sg1", 0, 100)?;
            assert_eq!(remaining.len(), 3);
            assert_eq!(remaining[0].server_seq, seq3);

            // Advance both devices to seq5
            upsert_device_receipt(conn, "sg1", "dev1", seq5)?;
            upsert_device_receipt(conn, "sg1", "dev2", seq5)?;

            // Safe prune seq should now be seq5
            let safe = get_safe_prune_seq(conn, "sg1", 3600)?;
            assert_eq!(safe, Some(seq5));

            // Prune before seq5
            let pruned = prune_batches_before(conn, "sg1", seq5)?;
            assert_eq!(pruned, 2, "should prune seq3 and seq4");

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
            upsert_snapshot(
                conn,
                "sg_a",
                1,
                5,
                b"valid",
                Some(future),
                None,
                Some("dev1"),
            )?;
            // sg_b: expired 1 hour ago
            upsert_snapshot(
                conn,
                "sg_b",
                1,
                5,
                b"expired",
                Some(past),
                None,
                Some("dev2"),
            )?;

            let cleaned = cleanup_expired_snapshots(conn)?;
            assert_eq!(cleaned, 1, "only expired snapshot should be cleaned");

            // sg_a still exists
            assert!(
                get_snapshot(conn, "sg_a")?.is_some(),
                "valid snapshot should exist"
            );
            // sg_b gone
            assert!(
                get_snapshot(conn, "sg_b")?.is_none(),
                "expired snapshot should be gone"
            );

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
            register_device(conn, "sg1", "dev1", &[1; 32], &[2; 32], 0, "admin")?;
            touch_device(conn, "sg1", "dev1")?;

            // Snapshot at seq=50
            upsert_snapshot(conn, "sg1", 0, 50, b"snap", None, None, None)?;

            // Device acked to seq=30
            upsert_device_receipt(conn, "sg1", "dev1", 30)?;

            // min(50, 30) = 30
            let safe = get_safe_prune_seq(conn, "sg1", 3600)?;
            assert_eq!(
                safe,
                Some(30),
                "should be min of snapshot(50) and acked(30)"
            );

            // Device acked to seq=60
            upsert_device_receipt(conn, "sg1", "dev1", 60)?;

            // min(50, 60) = 50
            let safe = get_safe_prune_seq(conn, "sg1", 3600)?;
            assert_eq!(
                safe,
                Some(50),
                "should be min of snapshot(50) and acked(60)"
            );

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
            register_device(conn, "sg1", "dev_a", &[1; 32], &[2; 32], 0, "admin")?;
            register_device(conn, "sg1", "dev_b", &[3; 32], &[4; 32], 0, "admin")?;

            let future = now_secs() + 300;

            // Device A uploads snapshot
            upsert_snapshot(
                conn,
                "sg1",
                0,
                10,
                b"snap",
                Some(future),
                None,
                Some("dev_a"),
            )?;

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
            register_device(conn, "sg1", "dev1", &[1; 32], &[2; 32], 0, "admin")?;
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

            // No snapshot, so safe prune is just min_acked (seq_10)
            let safe = get_safe_prune_seq(conn, "sg1", 3600)?;
            assert_eq!(safe, Some(seq_10));

            // Prune up to acked point
            let pruned = prune_batches_before(conn, "sg1", seq_10)?;
            assert_eq!(pruned, 9, "should prune 9 batches (seq < seq_10)");

            // Can still push more
            let new_seq = insert_batch(conn, "sg1", 0, "dev1", "b_new", b"new_data")?;
            assert!(new_seq > 0, "should successfully push after pruning");

            let batches = get_batches_since(conn, "sg1", 0, 100)?;
            assert_eq!(batches.len(), 12, "11 remaining + 1 new");

            Ok(())
        })
        .unwrap();
    }
}
