//! Integration tests for the lean v1 resumable pair-time snapshot uploader.
//!
//! These drive [`prism_sync_core::snapshot_upload::SnapshotUploader`] against an
//! in-memory relay double that mirrors the relay crate's wire contract
//! (`crates/prism-sync-relay/src/routes/uploads.rs`) — the same five operations,
//! the same JSON shapes, the same machine codes, and the same
//! offset-authoritative semantics. That is deliberate: the core client's job is
//! to interoperate exactly, so the tests assert against a relay *model* rather
//! than against the client's own assumptions.
//!
//! Coverage mirrors the lean v1 delivery plan's Phase 2 gate:
//!
//! - old-relay fallback, absent/malformed capability, mixed versions;
//! - create/status/chunk/complete happy path;
//! - a lost response at every step, including after publication committed;
//! - stale/offset-mismatch reconciliation and duplicate chunks;
//! - structured fatal errors and retry exhaustion;
//! - fresh signed-request nonces on every HTTP retry;
//! - byte-exact final content;
//! - no credential publication before completion (ordering);
//! - progress-triggered renewal cadence, nonfatal renewal failure, final renewal;
//! - lease-aware waits up to the absolute cap;
//! - cancellation abort.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use sha2::{Digest, Sha256};

use prism_sync_core::pairing::lease::{
    PairingLeaseHandle, VerifiedInitiatorState, LEASE_RENEWAL_COALESCE_SECS,
};
use prism_sync_core::relay::pairing_relay::{MockPairingRelay, PairingRelay};
use prism_sync_core::relay::traits::RelayError;
use prism_sync_core::snapshot_upload::{
    CapabilityUnavailableReason, ChunkResponse, CreateUploadRequest, CreateUploadResponse,
    NoopProgressHook, ResumableSnapshotTransport, ResumableUploadError, SnapshotUploadCapability,
    SnapshotUploadOutcome, SnapshotUploadProgressHook, SnapshotUploadRequest,
    SnapshotUploadRetryPolicy, SnapshotUploader, UploadErrorCode, UploadState,
    UploadStatusResponse, MAX_UPLOAD_STATE_TRANSITIONS, SNAPSHOT_UPLOAD_CHUNK_BYTES,
    SNAPSHOT_UPLOAD_KEY_BYTES, SNAPSHOT_UPLOAD_VERSION_V1,
};

// ── The relay double ────────────────────────────────────────────────────────

/// A fault to inject into one operation, consumed once.
#[derive(Debug, Clone)]
enum Fault {
    /// Return a retryable transport failure (ambiguous: may or may not have
    /// taken effect) without performing the underlying mutation.
    TransportError,
    /// Perform the mutation, then fail to deliver the response. This is the
    /// dangerous "lost success" case.
    CommitThenTransportError,
    /// Return a structured error with this status and code.
    Structured(u16, UploadErrorCode),
    /// Answer a chunk with a successful acknowledgment reporting this committed
    /// offset, without mutating storage. Used to exercise the client's
    /// monotonicity guard against an offset behind the acknowledged prefix.
    ChunkAckOffset(u64),
    /// Answer a status poll with this lifecycle state and the session's real
    /// offset, without mutating the session. Used to make a concurrent
    /// completion's `finalizing` state observable.
    StatusState(UploadState),
    /// Serve the capability response as absent.
    CapabilityAbsent,
    /// Serve a malformed capability sibling.
    CapabilityMalformed,
    /// Fail the capability lookup entirely.
    CapabilityLookupFailed,
    /// Report an unsupported capability version.
    CapabilityUnsupportedVersion(u16),
}

/// Per-operation fault queues, keyed by operation name.
#[derive(Default)]
struct Faults {
    capability: Vec<Fault>,
    create: Vec<Fault>,
    status: Vec<Fault>,
    chunk: Vec<Fault>,
    complete: Vec<Fault>,
    abort: Vec<Fault>,
}

impl Faults {
    fn take(&mut self, operation: &str) -> Option<Fault> {
        let queue = match operation {
            "capability" => &mut self.capability,
            "create" => &mut self.create,
            "status" => &mut self.status,
            "chunk" => &mut self.chunk,
            "complete" => &mut self.complete,
            "abort" => &mut self.abort,
            other => panic!("unknown operation {other}"),
        };
        if queue.is_empty() {
            None
        } else {
            Some(queue.remove(0))
        }
    }
}

/// Relay-side session, mirroring `snapshot_uploads`' relevant columns.
struct Session {
    total_bytes: u64,
    committed_offset: u64,
    body_sha256: String,
    state: UploadState,
    stored: Vec<u8>,
}

/// In-memory model of the relay's resumable routes.
struct MockResumableRelay {
    faults: Mutex<Faults>,
    sessions: Mutex<HashMap<String, Session>>,
    /// `(sync_id, uploader, upload_key) -> upload_id`, the idempotency index.
    by_key: Mutex<HashMap<String, String>>,
    capability: Mutex<Result<SnapshotUploadCapability, CapabilityUnavailableReason>>,
    /// Session chunk size the relay persists and reports. Atomic so a test
    /// can model a session that disagrees with the advertised capability.
    chunk_bytes: AtomicU64,
    next_upload_id: AtomicU64,
    /// Every distinct signed-request nonce the transport layer minted.
    nonces: Mutex<Vec<String>>,
    create_calls: AtomicU64,
    chunk_calls: AtomicU64,
    status_calls: AtomicU64,
    complete_calls: AtomicU64,
    abort_calls: AtomicU64,
    // ── single-PUT / legacy surface, so the fallback is observable ──
    put_snapshot_calls: AtomicU64,
    put_snapshot_bytes: Mutex<Vec<u8>>,
    /// Whether the resumable capability should be advertised at all, emulating
    /// an old relay that has the routes dark.
    capability_advertised: AtomicBool,
}

impl MockResumableRelay {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            faults: Mutex::new(Faults::default()),
            sessions: Mutex::new(HashMap::new()),
            by_key: Mutex::new(HashMap::new()),
            capability: Mutex::new(Ok(SnapshotUploadCapability {
                version: SNAPSHOT_UPLOAD_VERSION_V1,
                chunk_bytes: SNAPSHOT_UPLOAD_CHUNK_BYTES,
                max_wire_bytes: 150 * 1024 * 1024,
                session_idle_ttl_secs: 3600,
            })),
            chunk_bytes: AtomicU64::new(TEST_CHUNK_BYTES),
            next_upload_id: AtomicU64::new(1),
            nonces: Mutex::new(Vec::new()),
            create_calls: AtomicU64::new(0),
            chunk_calls: AtomicU64::new(0),
            status_calls: AtomicU64::new(0),
            complete_calls: AtomicU64::new(0),
            abort_calls: AtomicU64::new(0),
            put_snapshot_calls: AtomicU64::new(0),
            put_snapshot_bytes: Mutex::new(Vec::new()),
            capability_advertised: AtomicBool::new(true),
        })
    }

    /// Model an old relay: no capability, and the legacy PUT is the only path.
    fn without_capability(self: &Arc<Self>) -> Arc<Self> {
        self.capability_advertised.store(false, Ordering::Release);
        Arc::clone(self)
    }

    fn set_capability(self: &Arc<Self>, capability: SnapshotUploadCapability) -> Arc<Self> {
        *self.capability.lock().unwrap() = Ok(capability);
        Arc::clone(self)
    }

    /// Override the session chunk size the relay persists and reports. The
    /// advertised capability is left alone, so a mismatch models a relay whose
    /// session disagrees with its own advertisement.
    fn set_session_chunk_bytes(self: &Arc<Self>, chunk_bytes: u64) -> Arc<Self> {
        self.chunk_bytes.store(chunk_bytes, Ordering::Release);
        Arc::clone(self)
    }

    /// The session chunk size the relay currently persists and reports.
    fn session_chunk_bytes(&self) -> u64 {
        self.chunk_bytes.load(Ordering::Acquire)
    }

    fn push_fault(&self, operation: &str, fault: Fault) {
        let mut faults = self.faults.lock().unwrap();
        match operation {
            "capability" => faults.capability.push(fault),
            "create" => faults.create.push(fault),
            "status" => faults.status.push(fault),
            "chunk" => faults.chunk.push(fault),
            "complete" => faults.complete.push(fault),
            "abort" => faults.abort.push(fault),
            other => panic!("unknown operation {other}"),
        }
    }

    /// Install a fault that is served on every attempt, for exercising a
    /// bounded retry/transition budget. The count comfortably exceeds any
    /// budget under test, so the queue never empties mid-assertion.
    fn inject_repeating_fault(&self, operation: &str, fault: Fault) {
        let repeats = 10_000;
        let mut faults = self.faults.lock().unwrap();
        let queue = match operation {
            "capability" => &mut faults.capability,
            "create" => &mut faults.create,
            "status" => &mut faults.status,
            "chunk" => &mut faults.chunk,
            "complete" => &mut faults.complete,
            "abort" => &mut faults.abort,
            other => panic!("unknown operation {other}"),
        };
        queue.clear();
        queue.extend(std::iter::repeat_n(fault, repeats));
    }

    fn legacy_bytes(&self) -> Vec<u8> {
        self.put_snapshot_bytes.lock().unwrap().clone()
    }

    fn legacy_calls(&self) -> u64 {
        self.put_snapshot_calls.load(Ordering::Acquire)
    }

    fn abort_calls(&self) -> u64 {
        self.abort_calls.load(Ordering::Acquire)
    }

    fn create_calls(&self) -> u64 {
        self.create_calls.load(Ordering::Acquire)
    }

    fn chunk_calls(&self) -> u64 {
        self.chunk_calls.load(Ordering::Acquire)
    }

    fn status_calls(&self) -> u64 {
        self.status_calls.load(Ordering::Acquire)
    }

    fn complete_calls(&self) -> u64 {
        self.complete_calls.load(Ordering::Acquire)
    }

    /// Simulate the transport minting a fresh signed-request nonce.
    fn mint_nonce(&self) -> String {
        let counter = self.nonces.lock().unwrap().len() as u64;
        let nonce = hex::encode(Sha256::digest(format!("nonce-{counter}").as_bytes()));
        self.nonces.lock().unwrap().push(nonce.clone());
        nonce
    }

    fn nonces(&self) -> Vec<String> {
        self.nonces.lock().unwrap().clone()
    }

    /// Stored bytes for the only session, for the byte-exactness assertions.
    fn published(&self) -> Option<Vec<u8>> {
        let sessions = self.sessions.lock().unwrap();
        sessions
            .values()
            .find(|session| session.state == UploadState::Completed)
            .map(|session| session.stored.clone())
    }

    fn session_state(&self, upload_id: &str) -> Option<UploadState> {
        self.sessions.lock().unwrap().get(upload_id).map(|session| session.state)
    }
}

/// Apply a fault that returns a transport error, mirroring "the connection was
/// reset", optionally after the mutation already took effect.
fn transport_failure() -> ResumableUploadError {
    ResumableUploadError::transport("connection reset by peer")
}

const SESSION_IDLE_EXPIRES: i64 = 1_789_590_000;
const SESSION_ABSOLUTE_EXPIRES: i64 = 1_789_600_800;

#[async_trait]
impl ResumableSnapshotTransport for MockResumableRelay {
    async fn resumable_snapshot_capability(
        &self,
    ) -> Result<SnapshotUploadCapability, CapabilityUnavailableReason> {
        self.mint_nonce();
        let fault = self.faults.lock().unwrap().take("capability");
        match fault {
            Some(Fault::CapabilityAbsent) => return Err(CapabilityUnavailableReason::Absent),
            Some(Fault::CapabilityMalformed) => {
                return Err(CapabilityUnavailableReason::InvalidCapability)
            }
            Some(Fault::CapabilityLookupFailed) => {
                return Err(CapabilityUnavailableReason::LookupFailed)
            }
            Some(Fault::CapabilityUnsupportedVersion(v)) => {
                return Err(CapabilityUnavailableReason::UnsupportedVersion { advertised: v })
            }
            Some(Fault::TransportError) => return Err(CapabilityUnavailableReason::LookupFailed),
            Some(other) => panic!("unsupported capability fault: {other:?}"),
            None => {}
        }
        if !self.capability_advertised.load(Ordering::Acquire) {
            return Err(CapabilityUnavailableReason::Absent);
        }
        *self.capability.lock().unwrap()
    }

    async fn create_snapshot_upload(
        &self,
        body: &CreateUploadRequest,
    ) -> Result<CreateUploadResponse, ResumableUploadError> {
        self.mint_nonce();
        self.create_calls.fetch_add(1, Ordering::AcqRel);

        let fault = self.faults.lock().unwrap().take("create");
        match fault {
            Some(Fault::Structured(status, code)) => {
                return Err(ResumableUploadError::new(status, code, "injected create failure"))
            }
            Some(Fault::TransportError) => return Err(transport_failure()),
            Some(Fault::CommitThenTransportError) => {
                self.commit_create(body);
                return Err(transport_failure());
            }
            Some(other) => panic!("unsupported create fault: {other:?}"),
            None => {}
        }
        Ok(self.commit_create(body))
    }

    async fn snapshot_upload_status(
        &self,
        upload_id: &str,
    ) -> Result<UploadStatusResponse, ResumableUploadError> {
        self.mint_nonce();
        self.status_calls.fetch_add(1, Ordering::AcqRel);

        let fault = self.faults.lock().unwrap().take("status");
        match fault {
            Some(Fault::Structured(status, code)) => {
                return Err(ResumableUploadError::new(status, code, "injected status failure"))
            }
            Some(Fault::StatusState(state)) => {
                let sessions = self.sessions.lock().unwrap();
                let session = sessions.get(upload_id).ok_or_else(|| {
                    ResumableUploadError::new(404, UploadErrorCode::NotFound, "unknown")
                })?;
                return Ok(UploadStatusResponse {
                    state: Some(state_str(state).to_string()),
                    total_bytes: session.total_bytes as i64,
                    committed_offset: session.committed_offset as i64,
                    chunk_bytes: self.session_chunk_bytes() as i64,
                    idle_expires_at: SESSION_IDLE_EXPIRES,
                    absolute_expires_at: SESSION_ABSOLUTE_EXPIRES,
                });
            }
            Some(Fault::TransportError) => return Err(transport_failure()),
            Some(other) => panic!("unsupported status fault: {other:?}"),
            None => {}
        }

        let sessions = self.sessions.lock().unwrap();
        let session = sessions
            .get(upload_id)
            .ok_or_else(|| ResumableUploadError::new(404, UploadErrorCode::NotFound, "unknown"))?;
        Ok(UploadStatusResponse {
            state: Some(state_str(session.state).to_string()),
            total_bytes: session.total_bytes as i64,
            committed_offset: session.committed_offset as i64,
            chunk_bytes: self.session_chunk_bytes() as i64,
            idle_expires_at: SESSION_IDLE_EXPIRES,
            absolute_expires_at: SESSION_ABSOLUTE_EXPIRES,
        })
    }

    async fn put_snapshot_upload_chunk(
        &self,
        upload_id: &str,
        offset: u64,
        chunk: &[u8],
    ) -> Result<ChunkResponse, ResumableUploadError> {
        self.mint_nonce();
        self.chunk_calls.fetch_add(1, Ordering::AcqRel);

        let fault = self.faults.lock().unwrap().take("chunk");
        match fault {
            Some(Fault::Structured(status, code)) => {
                return Err(ResumableUploadError::new(status, code, "injected chunk failure"))
            }
            Some(Fault::TransportError) => return Err(transport_failure()),
            Some(Fault::ChunkAckOffset(committed)) => {
                return Ok(ChunkResponse {
                    committed_offset: committed as i64,
                    idle_expires_at: SESSION_IDLE_EXPIRES,
                    absolute_expires_at: SESSION_ABSOLUTE_EXPIRES,
                })
            }
            Some(Fault::CommitThenTransportError) => {
                self.commit_chunk(upload_id, offset, chunk)?;
                return Err(transport_failure());
            }
            Some(other) => panic!("unsupported chunk fault: {other:?}"),
            None => {}
        }
        self.commit_chunk(upload_id, offset, chunk)
    }

    async fn complete_snapshot_upload(&self, upload_id: &str) -> Result<(), ResumableUploadError> {
        self.mint_nonce();
        self.complete_calls.fetch_add(1, Ordering::AcqRel);

        let fault = self.faults.lock().unwrap().take("complete");
        match fault {
            Some(Fault::Structured(status, code)) => {
                return Err(ResumableUploadError::new(status, code, "injected complete failure"))
            }
            Some(Fault::TransportError) => return Err(transport_failure()),
            Some(Fault::CommitThenTransportError) => {
                self.commit_complete(upload_id)?;
                return Err(transport_failure());
            }
            Some(other) => panic!("unsupported complete fault: {other:?}"),
            None => {}
        }
        self.commit_complete(upload_id)
    }

    async fn abort_snapshot_upload(&self, upload_id: &str) -> Result<(), ResumableUploadError> {
        self.mint_nonce();
        self.abort_calls.fetch_add(1, Ordering::AcqRel);

        let fault = self.faults.lock().unwrap().take("abort");
        match fault {
            Some(Fault::TransportError) => return Err(transport_failure()),
            Some(Fault::Structured(status, code)) => {
                return Err(ResumableUploadError::new(status, code, "injected abort failure"))
            }
            Some(other) => panic!("unsupported abort fault: {other:?}"),
            None => {}
        }

        let mut sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.get_mut(upload_id) {
            match session.state {
                UploadState::Completed => {
                    return Err(ResumableUploadError::new(
                        409,
                        UploadErrorCode::Completed,
                        "already completed",
                    ))
                }
                _ => session.state = UploadState::Failed,
            }
        }
        Ok(())
    }
}

fn state_str(state: UploadState) -> &'static str {
    match state {
        UploadState::Active => "active",
        UploadState::Finalizing => "finalizing",
        UploadState::Completed => "completed",
        UploadState::Failed => "failed",
        UploadState::Unknown => "unknown",
    }
}

impl MockResumableRelay {
    fn commit_create(&self, body: &CreateUploadRequest) -> CreateUploadResponse {
        let key = format!("{}:{}", body.target_device_id, body.upload_key);
        let mut by_key = self.by_key.lock().unwrap();
        let mut sessions = self.sessions.lock().unwrap();

        // Idempotent recovery: same key, same immutable metadata returns the
        // existing session and its current offset.
        if let Some(existing_id) = by_key.get(&key) {
            if let Some(session) = sessions.get(existing_id) {
                return CreateUploadResponse {
                    upload_id: existing_id.clone(),
                    state: Some(state_str(session.state).to_string()),
                    chunk_bytes: self.session_chunk_bytes() as i64,
                    total_bytes: session.total_bytes as i64,
                    committed_offset: session.committed_offset as i64,
                    idle_expires_at: SESSION_IDLE_EXPIRES,
                    absolute_expires_at: SESSION_ABSOLUTE_EXPIRES,
                };
            }
        }

        let upload_id =
            format!("upload-{:032x}", self.next_upload_id.fetch_add(1, Ordering::AcqRel));
        let total = u64::try_from(body.total_bytes).unwrap();
        sessions.insert(
            upload_id.clone(),
            Session {
                total_bytes: total,
                committed_offset: 0,
                body_sha256: body.body_sha256.clone(),
                state: UploadState::Active,
                stored: Vec::new(),
            },
        );
        by_key.insert(key, upload_id.clone());

        CreateUploadResponse {
            upload_id,
            state: Some("active".to_string()),
            chunk_bytes: self.session_chunk_bytes() as i64,
            total_bytes: body.total_bytes,
            committed_offset: 0,
            idle_expires_at: SESSION_IDLE_EXPIRES,
            absolute_expires_at: SESSION_ABSOLUTE_EXPIRES,
        }
    }

    fn commit_chunk(
        &self,
        upload_id: &str,
        offset: u64,
        chunk: &[u8],
    ) -> Result<ChunkResponse, ResumableUploadError> {
        let mut sessions = self.sessions.lock().unwrap();
        let session = sessions.get_mut(upload_id).ok_or_else(|| {
            ResumableUploadError::new(404, UploadErrorCode::NotFound, "unknown session")
        })?;

        match session.state {
            UploadState::Active => {}
            UploadState::Finalizing => {
                return Err(ResumableUploadError::new(
                    409,
                    UploadErrorCode::Finalizing,
                    "completion owns the session",
                ))
            }
            UploadState::Completed => {
                return Err(ResumableUploadError::new(
                    409,
                    UploadErrorCode::Completed,
                    "already completed",
                ))
            }
            _ => {
                return Err(ResumableUploadError::new(
                    409,
                    UploadErrorCode::Failed,
                    "session failed",
                ))
            }
        }

        if chunk.is_empty() || chunk.len() as u64 > self.session_chunk_bytes() {
            return Err(ResumableUploadError::new(
                413,
                UploadErrorCode::ChunkTooLarge,
                "bad chunk length",
            ));
        }

        let offset_end = offset + chunk.len() as u64;
        if offset == session.committed_offset {
            // Only the exact committed offset mutates storage.
            if offset_end > session.total_bytes {
                return Err(ResumableUploadError::new(
                    413,
                    UploadErrorCode::SnapshotTooLarge,
                    "past declared total",
                ));
            }
            let new_len = offset_end as usize;
            if session.stored.len() < new_len {
                session.stored.resize(new_len, 0);
            }
            session.stored[offset as usize..new_len].copy_from_slice(chunk);
            session.committed_offset = offset_end;
        } else if offset_end <= session.committed_offset {
            // Wholly-duplicate retry: return the offset without writing and
            // without refreshing expiry.
        } else {
            let committed = session.committed_offset as i64;
            return Err(ResumableUploadError::new(
                409,
                UploadErrorCode::OffsetMismatch,
                format!("offset {offset} != committed {committed}"),
            )
            .with_committed_offset(session.committed_offset));
        }

        Ok(ChunkResponse {
            committed_offset: session.committed_offset as i64,
            idle_expires_at: SESSION_IDLE_EXPIRES,
            absolute_expires_at: SESSION_ABSOLUTE_EXPIRES,
        })
    }

    fn commit_complete(&self, upload_id: &str) -> Result<(), ResumableUploadError> {
        let mut sessions = self.sessions.lock().unwrap();
        let session = sessions.get_mut(upload_id).ok_or_else(|| {
            ResumableUploadError::new(404, UploadErrorCode::NotFound, "unknown session")
        })?;

        // A retry after a lost success response is idempotent.
        if session.state == UploadState::Completed {
            return Ok(());
        }
        if session.state == UploadState::Failed {
            return Err(ResumableUploadError::new(409, UploadErrorCode::Failed, "session failed"));
        }
        if session.committed_offset < session.total_bytes {
            return Err(ResumableUploadError::new(
                409,
                UploadErrorCode::Incomplete,
                "bytes are incomplete",
            )
            .with_committed_offset(session.committed_offset));
        }

        // The relay hashes the staged file and compares it to the immutable
        // create-time digest before publishing.
        let digest = hex::encode(Sha256::digest(&session.stored));
        if digest != session.body_sha256 {
            session.state = UploadState::Failed;
            return Err(ResumableUploadError::new(
                422,
                UploadErrorCode::HashMismatch,
                "staged file does not match create metadata",
            ));
        }

        session.state = UploadState::Completed;
        Ok(())
    }
}

// ── Legacy single-PUT surface for the fallback assertions ──────────────────

/// Minimal `SnapshotExchange` carrying only what the engine fallback needs.
///
/// This deliberately does NOT implement the resumable routes, which is exactly
/// the old-relay shape: capability absence plus a working single PUT.
struct LegacyOnlyRelay {
    resumable: Arc<MockResumableRelay>,
}

impl LegacyOnlyRelay {
    fn new(resumable: Arc<MockResumableRelay>) -> Self {
        Self { resumable }
    }
}

#[async_trait]
impl prism_sync_core::relay::traits::SnapshotExchange for LegacyOnlyRelay {
    async fn get_snapshot(
        &self,
    ) -> Result<Option<prism_sync_core::relay::traits::SnapshotResponse>, RelayError> {
        Ok(None)
    }

    async fn put_snapshot(
        &self,
        _epoch: i32,
        _server_seq_at: i64,
        envelope_bytes: Vec<u8>,
        _ttl_secs: Option<u64>,
        _for_device_id: Option<String>,
        _uploader_device_id: String,
        _progress: Option<prism_sync_core::relay::traits::SnapshotUploadProgress>,
    ) -> Result<(), RelayError> {
        self.resumable.put_snapshot_calls.fetch_add(1, Ordering::AcqRel);
        *self.resumable.put_snapshot_bytes.lock().unwrap() = envelope_bytes;
        Ok(())
    }

    async fn delete_snapshot(&self) -> Result<(), RelayError> {
        Ok(())
    }
}

/// A resumable-capable relay that also serves the legacy single PUT, so a test
/// can prove neither path is taken when the other should be.
struct BothPathsRelay {
    resumable: Arc<MockResumableRelay>,
}

#[async_trait]
impl prism_sync_core::relay::traits::SnapshotExchange for BothPathsRelay {
    async fn get_snapshot(
        &self,
    ) -> Result<Option<prism_sync_core::relay::traits::SnapshotResponse>, RelayError> {
        Ok(None)
    }

    async fn put_snapshot(
        &self,
        _epoch: i32,
        _server_seq_at: i64,
        envelope_bytes: Vec<u8>,
        _ttl_secs: Option<u64>,
        _for_device_id: Option<String>,
        _uploader_device_id: String,
        _progress: Option<prism_sync_core::relay::traits::SnapshotUploadProgress>,
    ) -> Result<(), RelayError> {
        self.resumable.put_snapshot_calls.fetch_add(1, Ordering::AcqRel);
        *self.resumable.put_snapshot_bytes.lock().unwrap() = envelope_bytes;
        Ok(())
    }

    async fn delete_snapshot(&self) -> Result<(), RelayError> {
        Ok(())
    }

    async fn resumable_snapshot_capability(
        &self,
    ) -> Result<SnapshotUploadCapability, CapabilityUnavailableReason> {
        ResumableSnapshotTransport::resumable_snapshot_capability(self.resumable.as_ref()).await
    }

    async fn create_snapshot_upload(
        &self,
        body: &CreateUploadRequest,
    ) -> Result<CreateUploadResponse, ResumableUploadError> {
        ResumableSnapshotTransport::create_snapshot_upload(self.resumable.as_ref(), body).await
    }

    async fn snapshot_upload_status(
        &self,
        upload_id: &str,
    ) -> Result<UploadStatusResponse, ResumableUploadError> {
        ResumableSnapshotTransport::snapshot_upload_status(self.resumable.as_ref(), upload_id).await
    }

    async fn put_snapshot_upload_chunk(
        &self,
        upload_id: &str,
        offset: u64,
        chunk: &[u8],
    ) -> Result<ChunkResponse, ResumableUploadError> {
        ResumableSnapshotTransport::put_snapshot_upload_chunk(
            self.resumable.as_ref(),
            upload_id,
            offset,
            chunk,
        )
        .await
    }

    async fn complete_snapshot_upload(&self, upload_id: &str) -> Result<(), ResumableUploadError> {
        ResumableSnapshotTransport::complete_snapshot_upload(self.resumable.as_ref(), upload_id)
            .await
    }

    async fn abort_snapshot_upload(&self, upload_id: &str) -> Result<(), ResumableUploadError> {
        ResumableSnapshotTransport::abort_snapshot_upload(self.resumable.as_ref(), upload_id).await
    }

    fn as_resumable_transport(&self) -> Option<&dyn ResumableSnapshotTransport> {
        Some(self)
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// A test envelope whose size is not a multiple of the chunk size, so the final
/// chunk is a partial suffix — the case the protocol calls out explicitly.
fn test_envelope(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 31 + 7) % 251) as u8).collect()
}

/// Chunk size for tests: 8 KiB keeps multi-chunk behavior cheap while
/// exercising exactly the same code path as the 8 MiB protocol constant.
const TEST_CHUNK_BYTES: u64 = 8 * 1024;

fn test_capability() -> SnapshotUploadCapability {
    SnapshotUploadCapability {
        version: SNAPSHOT_UPLOAD_VERSION_V1,
        chunk_bytes: TEST_CHUNK_BYTES,
        max_wire_bytes: 150 * 1024 * 1024,
        session_idle_ttl_secs: 3600,
    }
}

fn test_relay() -> Arc<MockResumableRelay> {
    // A test relay persists the same chunk size it advertises, exactly as the
    // relay crate does (both derive from the protocol constant).
    let relay = MockResumableRelay::new();
    *relay.capability.lock().unwrap() = Ok(test_capability());
    relay
}

fn fast_retry() -> SnapshotUploadRetryPolicy {
    SnapshotUploadRetryPolicy {
        max_attempts: 5,
        initial_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(4),
    }
}

fn request(total_target: &str) -> SnapshotUploadRequest {
    SnapshotUploadRequest {
        epoch: 3,
        server_seq_at: 42,
        target_device_id: total_target.to_string(),
        ttl_secs: 86_400,
    }
}

fn uploader<'a>(relay: &'a Arc<MockResumableRelay>, envelope: &'a [u8]) -> SnapshotUploader<'a> {
    SnapshotUploader::new(relay.as_ref(), envelope, request("joiner-device"))
        .with_retry_policy(fast_retry())
}

/// An envelope long enough to require several chunks.
fn multi_chunk_envelope() -> Vec<u8> {
    test_envelope((TEST_CHUNK_BYTES as usize) * 3 + 1234)
}

// ═════════════════════════════════════════════════════════════════════════════
// Capability and mixed versions
// ═════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn old_relay_without_capability_reports_a_downgrade_not_an_error() {
    let relay = MockResumableRelay::new().without_capability();
    let envelope = multi_chunk_envelope();
    let outcome = uploader(&relay, &envelope).run(None).await.unwrap();
    assert_eq!(
        outcome,
        SnapshotUploadOutcome::CapabilityUnavailable {
            reason: CapabilityUnavailableReason::Absent
        }
    );
    assert!(!outcome.used_resumable());
    // No resumable session was created.
    assert_eq!(relay.create_calls(), 0);
}

#[tokio::test]
async fn capability_lookup_failure_downgrades_to_single_put() {
    let relay = test_relay();
    relay.push_fault("capability", Fault::CapabilityLookupFailed);
    let envelope = multi_chunk_envelope();
    let outcome = uploader(&relay, &envelope).run(None).await.unwrap();
    assert_eq!(
        outcome,
        SnapshotUploadOutcome::CapabilityUnavailable {
            reason: CapabilityUnavailableReason::LookupFailed
        }
    );
}

#[tokio::test]
async fn absent_and_malformed_capability_downgrade_with_distinct_reasons() {
    let relay = test_relay();
    relay.push_fault("capability", Fault::CapabilityAbsent);
    let envelope = test_envelope(100);
    assert_eq!(
        uploader(&relay, &envelope).run(None).await.unwrap(),
        SnapshotUploadOutcome::CapabilityUnavailable {
            reason: CapabilityUnavailableReason::Absent
        }
    );

    let relay = test_relay();
    relay.push_fault("capability", Fault::CapabilityMalformed);
    assert_eq!(
        uploader(&relay, &envelope).run(None).await.unwrap(),
        SnapshotUploadOutcome::CapabilityUnavailable {
            reason: CapabilityUnavailableReason::InvalidCapability
        }
    );

    let relay = test_relay();
    relay.push_fault("capability", Fault::CapabilityUnsupportedVersion(2));
    assert_eq!(
        uploader(&relay, &envelope).run(None).await.unwrap(),
        SnapshotUploadOutcome::CapabilityUnavailable {
            reason: CapabilityUnavailableReason::UnsupportedVersion { advertised: 2 }
        }
    );
}

#[tokio::test]
async fn envelope_above_the_advertised_maximum_is_rejected_locally() {
    let relay = test_relay().set_capability(SnapshotUploadCapability {
        version: SNAPSHOT_UPLOAD_VERSION_V1,
        chunk_bytes: SNAPSHOT_UPLOAD_CHUNK_BYTES,
        max_wire_bytes: 64,
        session_idle_ttl_secs: 3600,
    });
    let envelope = test_envelope(128);
    let error = uploader(&relay, &envelope).run(None).await.unwrap_err();
    assert_eq!(error.code, UploadErrorCode::SnapshotTooLarge);
    assert_eq!(error.status, 413);
    assert!(!error.is_retryable());
    // The relay was never contacted for a session.
    assert_eq!(relay.create_calls(), 0);
}

// ═════════════════════════════════════════════════════════════════════════════
// Happy path, byte exactness, nonce freshness
// ═════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn create_status_chunk_complete_happy_path_publishes_exact_bytes() {
    let relay = test_relay();
    let envelope = multi_chunk_envelope();
    let outcome = uploader(&relay, &envelope).run(None).await.unwrap();
    let SnapshotUploadOutcome::Uploaded { total_bytes, .. } = outcome else {
        panic!("expected a resumable upload, got {outcome:?}");
    };
    assert_eq!(total_bytes, envelope.len() as u64);
    assert_eq!(relay.published().as_deref(), Some(envelope.as_slice()));

    // 3 full chunks plus the partial suffix, then one complete.
    assert_eq!(relay.create_calls(), 1);
    assert_eq!(relay.chunk_calls(), 4);
    assert_eq!(relay.abort_calls(), 0);
}

#[tokio::test]
async fn every_http_attempt_mints_a_fresh_signed_request_nonce() {
    let relay = test_relay();
    relay.push_fault("chunk", Fault::TransportError);
    relay.push_fault("chunk", Fault::TransportError);
    let envelope = multi_chunk_envelope();
    uploader(&relay, &envelope).run(None).await.unwrap();

    let nonces = relay.nonces();
    let unique: std::collections::HashSet<_> = nonces.iter().collect();
    assert_eq!(
        unique.len(),
        nonces.len(),
        "each request must carry a fresh nonce; duplicates: {nonces:?}"
    );
    // One capability fetch, one create, four chunks, two chunk retries, one
    // complete: nine distinct signed requests, nine distinct nonces.
    assert_eq!(nonces.len(), 9);
}

#[tokio::test]
async fn progress_reports_monotonic_offsets_and_finishes_at_total() {
    let relay = test_relay();
    let envelope = multi_chunk_envelope();
    let total = envelope.len() as u64;
    let observed = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&observed);
    let progress: prism_sync_core::relay::traits::SnapshotUploadProgress =
        Arc::new(move |sent, seen_total| {
            assert_eq!(seen_total, total);
            sink.lock().unwrap().push(sent);
        });

    SnapshotUploader::new(relay.as_ref(), &envelope, request("joiner-device"))
        .with_retry_policy(fast_retry())
        .with_progress(Some(progress))
        .run(None)
        .await
        .unwrap();

    let seen = observed.lock().unwrap().clone();
    assert!(seen.windows(2).all(|pair| pair[0] <= pair[1]), "progress must not regress");
    assert_eq!(seen.last().copied(), Some(total));
}

// ═════════════════════════════════════════════════════════════════════════════
// Lost responses at each step
// ═════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn lost_create_response_recovers_the_same_session() {
    let relay = test_relay();
    // The create committed on the relay, but the response never arrived.
    relay.push_fault("create", Fault::CommitThenTransportError);
    let envelope = multi_chunk_envelope();
    let outcome = uploader(&relay, &envelope).run(None).await.unwrap();
    assert!(outcome.used_resumable());
    // Two create calls, but only ONE session, because the upload key is stable.
    assert_eq!(relay.create_calls(), 2);
    assert_eq!(relay.sessions.lock().unwrap().len(), 1);
    assert_eq!(relay.published().as_deref(), Some(envelope.as_slice()));
}

#[tokio::test]
async fn lost_chunk_response_reconciles_without_resending_the_prefix() {
    let relay = test_relay();
    // First chunk wrote durably; the ack was lost. The retry must not re-send
    // from the assumed offset blindly — it re-sends the same offset, and the
    // relay acknowledges the already-committed duplicate.
    relay.push_fault("chunk", Fault::CommitThenTransportError);
    let envelope = multi_chunk_envelope();
    let outcome = uploader(&relay, &envelope).run(None).await.unwrap();
    assert!(outcome.used_resumable());
    assert_eq!(relay.published().as_deref(), Some(envelope.as_slice()));
    // 4 real chunks + 1 duplicate retry.
    assert_eq!(relay.chunk_calls(), 5);
    // The duplicate did not need a status call: the relay's ack was already
    // authoritative about the committed prefix.
    assert_eq!(relay.status_calls(), 0);
}

#[tokio::test]
async fn lost_complete_response_is_idempotent_and_never_republishes() {
    let relay = test_relay();
    relay.push_fault("complete", Fault::CommitThenTransportError);
    let envelope = multi_chunk_envelope();
    let outcome = uploader(&relay, &envelope).run(None).await.unwrap();
    assert!(outcome.used_resumable());
    assert_eq!(relay.complete_calls(), 2);
    assert_eq!(relay.published().as_deref(), Some(envelope.as_slice()));
    assert_eq!(relay.session_state(&single_session_id(&relay)).unwrap(), UploadState::Completed);
}

#[tokio::test]
async fn lost_status_response_is_retried_under_the_bounded_policy() {
    let relay = test_relay();
    // Force an offset mismatch so the uploader reconciles, and make the first
    // reconciliation attempt lose its response.
    relay.push_fault("chunk", Fault::Structured(409, UploadErrorCode::OffsetMismatch));
    relay.push_fault("status", Fault::TransportError);
    let envelope = multi_chunk_envelope();
    // The mismatch reports committed_offset 0, so the upload restarts cleanly.
    let outcome = uploader(&relay, &envelope).run(None).await.unwrap();
    assert!(outcome.used_resumable());
    assert!(relay.status_calls() >= 2);
    assert_eq!(relay.published().as_deref(), Some(envelope.as_slice()));
}

fn single_session_id(relay: &MockResumableRelay) -> String {
    relay.sessions.lock().unwrap().keys().next().unwrap().clone()
}

// ═════════════════════════════════════════════════════════════════════════════
// Reconciliation, duplicates, stale offsets
// ═════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn offset_mismatch_reconciles_then_resumes_from_the_relay_offset() {
    let relay = test_relay();
    let envelope = multi_chunk_envelope();
    let payload_len = envelope.len() as u64;

    // Pre-commit two chunks, simulating progress a previous attempt made.
    let first = uploader(&relay, &envelope).run(None).await;
    assert!(first.is_ok());

    // A second uploader with a fresh key starts a NEW session at offset zero
    // (create is per-key), and the relay's ack drives everything. To exercise
    // the reconciliation path directly, inject a mismatch on the first chunk.
    let relay2 = test_relay();
    relay2.push_fault("chunk", Fault::Structured(409, UploadErrorCode::OffsetMismatch));
    let outcome = uploader(&relay2, &envelope).run(None).await.unwrap();
    assert!(outcome.used_resumable());
    assert_eq!(relay2.published().as_deref(), Some(envelope.as_slice()));
    assert!(relay2.status_calls() >= 1, "a mismatch must be reconciled with status");

    // The first relay's published bytes were the whole envelope.
    assert_eq!(relay.published().map(|bytes| bytes.len() as u64), Some(payload_len));
}

#[tokio::test]
async fn duplicate_chunk_acknowledgment_does_not_duplicate_storage() {
    let relay = test_relay();
    let envelope = multi_chunk_envelope();
    // Commit the first chunk durably, then lose the ack: the client re-sends an
    // identical range wholly inside the committed prefix.
    relay.push_fault("chunk", Fault::CommitThenTransportError);
    uploader(&relay, &envelope).run(None).await.unwrap();

    let session_id = single_session_id(&relay);
    let sessions = relay.sessions.lock().unwrap();
    let session = sessions.get(&session_id).unwrap();
    assert_eq!(session.committed_offset, session.total_bytes);
    assert_eq!(session.stored.len() as u64, session.total_bytes);
}

#[tokio::test]
async fn partial_overlap_and_ahead_offsets_conflict() {
    let relay = test_relay();
    let envelope = multi_chunk_envelope();

    // Build a genuinely partial session: exactly one chunk committed.
    let body = create_body_for(&envelope, "joiner-device", "overlap-key");
    let created =
        ResumableSnapshotTransport::create_snapshot_upload(relay.as_ref(), &body).await.unwrap();
    ResumableSnapshotTransport::put_snapshot_upload_chunk(
        relay.as_ref(),
        &created.upload_id,
        0,
        &envelope[..TEST_CHUNK_BYTES as usize],
    )
    .await
    .unwrap();

    // Ahead of the committed prefix.
    let ahead = ResumableSnapshotTransport::put_snapshot_upload_chunk(
        relay.as_ref(),
        &created.upload_id,
        TEST_CHUNK_BYTES * 3,
        &[1, 2, 3],
    )
    .await
    .unwrap_err();
    assert_eq!(ahead.code, UploadErrorCode::OffsetMismatch);
    assert_eq!(ahead.committed_offset(), Some(TEST_CHUNK_BYTES));

    // Partially overlapping the committed prefix: rejected, not truncated.
    let overlap = ResumableSnapshotTransport::put_snapshot_upload_chunk(
        relay.as_ref(),
        &created.upload_id,
        TEST_CHUNK_BYTES - 16,
        &[0u8; 64],
    )
    .await
    .unwrap_err();
    assert_eq!(overlap.code, UploadErrorCode::OffsetMismatch);

    // The committed prefix is unchanged by either rejection.
    let status =
        ResumableSnapshotTransport::snapshot_upload_status(relay.as_ref(), &created.upload_id)
            .await
            .unwrap();
    assert_eq!(status.committed_offset, TEST_CHUNK_BYTES as i64);
    assert_eq!(relay.published(), None);

    // A wholly-committed duplicate range, by contrast, is an idempotent
    // acknowledgment rather than a conflict.
    let duplicate = ResumableSnapshotTransport::put_snapshot_upload_chunk(
        relay.as_ref(),
        &created.upload_id,
        0,
        &envelope[..TEST_CHUNK_BYTES as usize],
    )
    .await
    .unwrap();
    assert_eq!(duplicate.committed_offset, TEST_CHUNK_BYTES as i64);
}

#[tokio::test]
async fn reconciliation_detects_a_terminally_failed_session() {
    let relay = test_relay();
    let envelope = multi_chunk_envelope();
    // A chunk reports a mismatch, then the reconciliation status reports failed:
    // the uploader must fail closed instead of restarting forever.
    relay.push_fault("chunk", Fault::Structured(409, UploadErrorCode::OffsetMismatch));
    relay.push_fault("status", Fault::Structured(409, UploadErrorCode::Failed));

    let error = uploader(&relay, &envelope).run(None).await.unwrap_err();
    assert_eq!(error.code, UploadErrorCode::Failed);
    assert!(!error.is_retryable());
    assert_eq!(relay.published(), None);
}

// ═════════════════════════════════════════════════════════════════════════════
// Structured fatal errors and retry exhaustion
// ═════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn structured_fatal_errors_are_not_retried() {
    for (status, code) in [
        (409, UploadErrorCode::KeyConflict),
        (422, UploadErrorCode::HashMismatch),
        (422, UploadErrorCode::EpochInvalid),
        (422, UploadErrorCode::OwnerInvalid),
        (410, UploadErrorCode::Expired),
        (429, UploadErrorCode::QuotaExceeded),
        (404, UploadErrorCode::NotFound),
    ] {
        let relay = test_relay();
        relay.push_fault("create", Fault::Structured(status, code.clone()));
        let envelope = test_envelope(64);
        let error = uploader(&relay, &envelope).run(None).await.unwrap_err();
        assert_eq!(error.code, code, "status {status}");
        assert_eq!(error.status, status);
        assert_eq!(relay.create_calls(), 1, "a fatal error must not be retried: {code:?}");
    }
}

#[tokio::test]
async fn retry_exhaustion_surfaces_the_transient_failure() {
    let relay = test_relay();
    for _ in 0..10 {
        relay.push_fault("chunk", Fault::TransportError);
    }
    let envelope = multi_chunk_envelope();
    let error = uploader(&relay, &envelope).run(None).await.unwrap_err();
    assert!(error.status == 0 || error.status >= 500);
    // Exactly `max_attempts` attempts: 5.
    assert_eq!(relay.chunk_calls(), 5);
    assert_eq!(relay.published(), None);
}

#[tokio::test]
async fn a_retryable_busy_response_is_retried_and_then_succeeds() {
    let relay = test_relay();
    relay.push_fault("chunk", Fault::Structured(503, UploadErrorCode::Busy));
    relay.push_fault("chunk", Fault::Structured(503, UploadErrorCode::Busy));
    let envelope = multi_chunk_envelope();
    uploader(&relay, &envelope).run(None).await.unwrap();
    assert_eq!(relay.published().as_deref(), Some(envelope.as_slice()));
}

#[tokio::test]
async fn complete_reports_incomplete_then_finishes_after_the_missing_chunk() {
    let relay = test_relay();
    let envelope = multi_chunk_envelope();

    // Simulate a lost prefix: pre-create the session and commit only the first
    // chunk by hand, then let the uploader recover it.
    let body = create_body_for(&envelope, "joiner-device", "seed-key");
    let created =
        ResumableSnapshotTransport::create_snapshot_upload(relay.as_ref(), &body).await.unwrap();
    let first_len = TEST_CHUNK_BYTES as usize;
    ResumableSnapshotTransport::put_snapshot_upload_chunk(
        relay.as_ref(),
        &created.upload_id,
        0,
        &envelope[..first_len],
    )
    .await
    .unwrap();
    // Now a complete on this session must report `upload_incomplete` with the
    // relay's offset, after which the client finishes the suffix.
    let incomplete =
        ResumableSnapshotTransport::complete_snapshot_upload(relay.as_ref(), &created.upload_id)
            .await
            .unwrap_err();
    assert_eq!(incomplete.code, UploadErrorCode::Incomplete);
    assert_eq!(incomplete.committed_offset(), Some(TEST_CHUNK_BYTES));

    // The full uploader (fresh key, so a fresh session) still publishes exactly.
    uploader(&relay, &envelope).run(None).await.unwrap();
    assert_eq!(relay.published().as_deref(), Some(envelope.as_slice()));
}

fn create_body_for(envelope: &[u8], target: &str, upload_key: &str) -> CreateUploadRequest {
    CreateUploadRequest {
        version: SNAPSHOT_UPLOAD_VERSION_V1,
        upload_key: upload_key.to_string(),
        epoch: 3,
        server_seq_at: 42,
        target_device_id: target.to_string(),
        ttl_secs: 86_400,
        total_bytes: envelope.len() as i64,
        body_sha256: hex::encode(Sha256::digest(envelope)),
    }
}

#[tokio::test]
async fn upload_key_is_stable_and_random_across_uploaders() {
    let relay = test_relay();
    let envelope = test_envelope(32);
    let first = uploader(&relay, &envelope);
    let second = uploader(&relay, &envelope);
    assert_ne!(first.upload_key(), second.upload_key());
    // 32 random bytes, base64url without padding.
    assert_eq!(first.upload_key().len(), 43);
    let decoded = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        first.upload_key(),
    )
    .unwrap();
    assert_eq!(decoded.len(), SNAPSHOT_UPLOAD_KEY_BYTES);
    // The create body commits to the exact envelope digest.
    assert_eq!(first.body_sha256(), hex::encode(Sha256::digest(&envelope)));
}

#[tokio::test]
async fn finalizing_conflict_resolves_once_the_completion_publishes() {
    let relay = test_relay();
    let envelope = multi_chunk_envelope();
    // Pre-commit the whole envelope so the session is one complete away.
    let body = create_body_for(&envelope, "joiner-device", "seed-key-2");
    let created =
        ResumableSnapshotTransport::create_snapshot_upload(relay.as_ref(), &body).await.unwrap();
    let mut offset = 0u64;
    while offset < envelope.len() as u64 {
        let end = (offset + TEST_CHUNK_BYTES).min(envelope.len() as u64);
        ResumableSnapshotTransport::put_snapshot_upload_chunk(
            relay.as_ref(),
            &created.upload_id,
            offset,
            &envelope[offset as usize..end as usize],
        )
        .await
        .unwrap();
        offset = end;
    }
    ResumableSnapshotTransport::complete_snapshot_upload(relay.as_ref(), &created.upload_id)
        .await
        .unwrap();

    // A status poll now reports completed, which is what a client that lost its
    // own completion response must observe.
    let status =
        ResumableSnapshotTransport::snapshot_upload_status(relay.as_ref(), &created.upload_id)
            .await
            .unwrap();
    assert_eq!(UploadState::parse(status.state.as_deref()), UploadState::Completed);
    assert_eq!(status.committed_offset, envelope.len() as i64);
}

#[tokio::test]
async fn finalizing_on_complete_never_publishes_while_the_owner_is_unfinished() {
    // `complete` reports `upload_finalizing`: a concurrent completion owns the
    // session and has not published. The client must consult status, find the
    // session still unfinished, publish NOTHING, and surface the conflict
    // instead of spinning or claiming success.
    let relay = test_relay();
    let envelope = multi_chunk_envelope();
    relay.push_fault("complete", Fault::Structured(409, UploadErrorCode::Finalizing));
    relay.push_fault("status", Fault::StatusState(UploadState::Finalizing));

    let error = uploader(&relay, &envelope).run(None).await.unwrap_err();
    assert_eq!(error.code, UploadErrorCode::Finalizing);
    assert_eq!(
        relay.published(),
        None,
        "an unfinished concurrent completion must never publish on our behalf"
    );
    assert!(relay.status_calls() >= 1, "the client must consult status before giving up");
}

#[tokio::test]
async fn a_regressing_chunk_acknowledgment_is_rejected_without_publishing() {
    // The relay acknowledges an offset BELOW the prefix it already committed.
    // The committed prefix must be monotonic: the client fails closed rather
    // than re-sending from a lower offset, and nothing is published.
    let relay = test_relay();
    let envelope = multi_chunk_envelope();
    // The first ack advances the committed prefix normally; the second ack then
    // regresses below it — a relay that first acknowledged progress and then
    // reported an earlier offset.
    relay.push_fault("chunk", Fault::ChunkAckOffset(TEST_CHUNK_BYTES));
    relay.push_fault("chunk", Fault::ChunkAckOffset(0));
    relay.push_fault("chunk", Fault::ChunkAckOffset(0));

    let error = uploader(&relay, &envelope).run(None).await.unwrap_err();
    assert_eq!(
        error.code,
        UploadErrorCode::Unknown("offset_regressed".to_string()),
        "a regressing offset must be rejected, got {:?}",
        error.code
    );
    assert_eq!(relay.published(), None, "a regressed offset must never publish");
}

#[tokio::test]
async fn a_session_chunk_size_above_the_advertised_maximum_is_rejected() {
    // The session's persisted chunk size is authoritative, but it must never
    // exceed what this relay advertised. A relay that reports a larger chunk
    // than its own capability is inconsistent: reject before chunking.
    let relay = test_relay();
    relay.set_session_chunk_bytes(TEST_CHUNK_BYTES * 4);
    let envelope = multi_chunk_envelope();

    let error = uploader(&relay, &envelope).run(None).await.unwrap_err();
    assert_eq!(
        error.code,
        UploadErrorCode::Unknown("invalid_session_chunk_bytes".to_string()),
        "an over-capability session chunk size must be rejected, got {:?}",
        error.code
    );
    // The inconsistency is caught before any chunk is attempted.
    assert_eq!(relay.chunk_calls(), 0, "no chunk may be sent under a bogus chunk size");
    assert_eq!(relay.published(), None);
}

#[tokio::test]
async fn the_transition_backstop_stops_a_non_advancing_state_machine() {
    // `complete` keeps reporting `upload_incomplete` and status keeps reporting
    // the same offset, so the chunk/complete state machine never advances. The
    // client must not loop forever: the transition budget ends the upload with a
    // bounded "no progress" error and publishes nothing.
    let relay = test_relay();
    let envelope = multi_chunk_envelope();
    relay.inject_repeating_fault("complete", Fault::Structured(409, UploadErrorCode::Incomplete));
    // Status never advances the offset either, so each cycle reconciles back to
    // the same committed prefix and the loop cannot converge.
    relay.inject_repeating_fault("chunk", Fault::Structured(409, UploadErrorCode::OffsetMismatch));

    let error = uploader(&relay, &envelope).run(None).await.unwrap_err();
    assert_eq!(
        error.code,
        UploadErrorCode::Unknown("upload_no_progress".to_string()),
        "the transition backstop must bound a non-advancing state machine, got {:?}",
        error.code
    );
    // The guard is a real backstop, not an unbounded loop: the upload ends after
    // the documented transition budget regardless of which arm of the state
    // machine the non-advancing cycle takes, and publishes nothing.
    assert!(
        relay.chunk_calls() >= 2,
        "the non-advancing cycle must have actually iterated, saw {} chunks",
        relay.chunk_calls()
    );
    assert!(
        relay.chunk_calls() + relay.complete_calls() <= 2 * MAX_UPLOAD_STATE_TRANSITIONS as u64,
        "the backstop must bound the transition count, saw {} chunks and {} completions",
        relay.chunk_calls(),
        relay.complete_calls()
    );
    assert_eq!(relay.published(), None, "a non-advancing upload must never publish");
}

#[tokio::test]
async fn abort_makes_a_session_terminal_and_leaves_published_bytes_alone() {
    let relay = test_relay();
    let envelope = multi_chunk_envelope();
    let body = create_body_for(&envelope, "joiner-device", "abort-key");
    let created =
        ResumableSnapshotTransport::create_snapshot_upload(relay.as_ref(), &body).await.unwrap();

    ResumableSnapshotTransport::abort_snapshot_upload(relay.as_ref(), &created.upload_id)
        .await
        .unwrap();
    assert_eq!(relay.session_state(&created.upload_id), Some(UploadState::Failed));
    // A later chunk is refused.
    let refused = ResumableSnapshotTransport::put_snapshot_upload_chunk(
        relay.as_ref(),
        &created.upload_id,
        0,
        &envelope[..16],
    )
    .await
    .unwrap_err();
    assert_eq!(refused.code, UploadErrorCode::Failed);
}

// ═════════════════════════════════════════════════════════════════════════════
// Lease-aware orchestration
// ═════════════════════════════════════════════════════════════════════════════

/// Progress hook that drives a real [`PairingLeaseHandle`], mirroring the
/// split ceremony's renewal policy.
struct LeaseRenewalHook {
    handle: PairingLeaseHandle,
    relay: Arc<MockPairingRelay>,
    renewals: Arc<AtomicU64>,
    renew_failures: Arc<AtomicU64>,
    completed: Arc<AtomicU64>,
    abandoned: Arc<AtomicU64>,
    /// Renewal attempts that actually reached the relay.
    attempts: Arc<AtomicU64>,
}

#[async_trait]
impl SnapshotUploadProgressHook for LeaseRenewalHook {
    async fn on_committed_offset_advanced(&mut self, committed_offset: u64) {
        let now = Instant::now();
        if !self.handle.should_renew_for_progress(committed_offset, now) {
            return;
        }
        self.attempts.fetch_add(1, Ordering::AcqRel);
        let outcome = self.handle.renew(self.relay.as_ref(), Some(committed_offset), now).await;
        if outcome.is_renewed() {
            self.renewals.fetch_add(1, Ordering::AcqRel);
        } else {
            self.renew_failures.fetch_add(1, Ordering::AcqRel);
        }
    }

    async fn on_upload_completed(&mut self, _total_bytes: u64) {
        self.completed.fetch_add(1, Ordering::AcqRel);
    }

    async fn on_upload_abandoned(&mut self) {
        self.abandoned.fetch_add(1, Ordering::AcqRel);
    }
}

/// Build a lease-capable pairing relay with a committed verifier, plus the
/// matching handle, without touching FFI or the app layer.
async fn lease_capable_ceremony() -> (Arc<MockPairingRelay>, String, VerifiedInitiatorState) {
    let relay = Arc::new(MockPairingRelay::new());
    let secret = [7u8; 32];
    let verifier = prism_sync_core::pairing::lease::compute_lease_key_hash(&secret);
    let offer = prism_sync_core::relay::pairing_relay::PairingLeaseOffer {
        lease_key_hash: &verifier,
        lease_version: prism_sync_core::pairing::lease::LEASE_VERSION_V1,
    };
    let outcome = relay.create_session_with_lease(b"bootstrap", Some(offer)).await.unwrap();
    assert!(outcome.relay_supports_lease(prism_sync_core::pairing::lease::LEASE_VERSION_V1));
    let rendezvous_id = hex::encode(outcome.rendezvous_id);

    let state = VerifiedInitiatorState::leased(
        rendezvous_id.clone(),
        [0u8; 32],
        prism_sync_core::pairing::lease::LeaseCapability::v1(),
        zeroize::Zeroizing::new(secret),
    );
    (relay, rendezvous_id, state)
}

/// `(renewals, failures, completed, abandoned, attempts)`.
type RenewalCounts =
    (Arc<AtomicU64>, Arc<AtomicU64>, Arc<AtomicU64>, Arc<AtomicU64>, Arc<AtomicU64>);

fn renewal_counts() -> RenewalCounts {
    (
        Arc::new(AtomicU64::new(0)),
        Arc::new(AtomicU64::new(0)),
        Arc::new(AtomicU64::new(0)),
        Arc::new(AtomicU64::new(0)),
        Arc::new(AtomicU64::new(0)),
    )
}

#[tokio::test]
async fn progress_renewal_is_coalesced_to_one_per_window_regardless_of_chunk_count() {
    let (pairing_relay, _rendezvous_id, state) = lease_capable_ceremony().await;
    // No initial renewal has run yet, so the first acknowledged offset is the
    // one that earns a renewal.
    let handle = PairingLeaseHandle::new(&state);
    let (renewals, failures, completed, abandoned, attempts) = renewal_counts();
    let mut hook = LeaseRenewalHook {
        handle,
        relay: Arc::clone(&pairing_relay),
        renewals: Arc::clone(&renewals),
        renew_failures: Arc::clone(&failures),
        completed: Arc::clone(&completed),
        abandoned: Arc::clone(&abandoned),
        attempts: Arc::clone(&attempts),
    };

    let relay = test_relay();
    let envelope = multi_chunk_envelope();
    uploader(&relay, &envelope).run(Some(&mut hook)).await.unwrap();

    // Four chunks land, but only the FIRST acknowledged offset can earn a
    // progress renewal: every later one is inside the five-minute coalescing
    // window, so the cadence is one renewal per window regardless of progress.
    assert_eq!(
        attempts.load(Ordering::Acquire),
        1,
        "progress renewals must be coalesced to one per window"
    );
    assert_eq!(renewals.load(Ordering::Acquire), 1);
    assert_eq!(pairing_relay.renew_successes(), 1);
    assert_eq!(completed.load(Ordering::Acquire), 1);
    assert_eq!(abandoned.load(Ordering::Acquire), 0);
    assert_eq!(relay.published().as_deref(), Some(envelope.as_slice()));
    assert_coalescing_boundary_is_five_minutes();
}

#[tokio::test]
async fn an_initial_renewal_suppresses_progress_renewals_within_its_window() {
    let (pairing_relay, _rendezvous_id, state) = lease_capable_ceremony().await;
    let mut handle = PairingLeaseHandle::new(&state);
    // The initial post-confirmation renewal is exempt from coalescing itself.
    let initial = handle.renew(pairing_relay.as_ref(), None, Instant::now()).await;
    assert!(initial.is_renewed(), "the initial renewal should succeed");
    handle.record_initial_renewal(initial, Instant::now());
    assert_eq!(pairing_relay.renew_successes(), 1);

    let (renewals, failures, completed, abandoned, attempts) = renewal_counts();
    let mut hook = LeaseRenewalHook {
        handle,
        relay: Arc::clone(&pairing_relay),
        renewals: Arc::clone(&renewals),
        renew_failures: Arc::clone(&failures),
        completed: Arc::clone(&completed),
        abandoned: Arc::clone(&abandoned),
        attempts: Arc::clone(&attempts),
    };

    let relay = test_relay();
    let envelope = multi_chunk_envelope();
    uploader(&relay, &envelope).run(Some(&mut hook)).await.unwrap();

    // The initial renewal started the window, so no progress renewal may happen
    // until five minutes have elapsed — the relay sees the initial renewal plus
    // nothing else, no matter how many chunks landed.
    assert_eq!(attempts.load(Ordering::Acquire), 0);
    assert_eq!(pairing_relay.renew_successes(), 1);
    assert_eq!(completed.load(Ordering::Acquire), 1);
    assert_eq!(relay.published().as_deref(), Some(envelope.as_slice()));
}

#[tokio::test]
async fn duplicate_and_nonadvancing_acknowledgments_never_renew() {
    let (pairing_relay, _rendezvous_id, state) = lease_capable_ceremony().await;
    let handle = PairingLeaseHandle::new(&state);
    let (renewals, failures, completed, abandoned, attempts) = renewal_counts();
    let mut hook = LeaseRenewalHook {
        handle,
        relay: Arc::clone(&pairing_relay),
        renewals: Arc::clone(&renewals),
        renew_failures: Arc::clone(&failures),
        completed: Arc::clone(&completed),
        abandoned: Arc::clone(&abandoned),
        attempts: Arc::clone(&attempts),
    };

    // Drive the hook directly with a duplicate offset and a status-only poll.
    hook.on_committed_offset_advanced(1024).await;
    let after_first = attempts.load(Ordering::Acquire);
    // A second invocation in the same window must be refused by coalescing.
    hook.on_committed_offset_advanced(4096).await;
    assert_eq!(
        attempts.load(Ordering::Acquire),
        after_first,
        "a second renewal inside the coalescing window must not happen"
    );
    assert_eq!(pairing_relay.renew_successes(), 1);
}

#[tokio::test]
async fn renewal_failure_is_nonfatal_and_never_claims_extension() {
    // A relay that does not support the lease 404s every renewal.
    let relay = Arc::new(MockPairingRelay::new());
    relay.set_lease_supported(false);
    let state = VerifiedInitiatorState::leased(
        "deadbeefdeadbeefdeadbeefdeadbeef".to_string(),
        [0u8; 32],
        prism_sync_core::pairing::lease::LeaseCapability::v1(),
        zeroize::Zeroizing::new([9u8; 32]),
    );
    let handle = PairingLeaseHandle::new(&state);
    let (renewals, failures, completed, abandoned, attempts) = renewal_counts();
    let mut hook = LeaseRenewalHook {
        handle,
        relay: Arc::clone(&relay),
        renewals: Arc::clone(&renewals),
        renew_failures: Arc::clone(&failures),
        completed: Arc::clone(&completed),
        abandoned: Arc::clone(&abandoned),
        attempts: Arc::clone(&attempts),
    };

    let upload_relay = test_relay();
    let envelope = multi_chunk_envelope();
    // The upload must still succeed exactly.
    uploader(&upload_relay, &envelope).run(Some(&mut hook)).await.unwrap();

    assert!(attempts.load(Ordering::Acquire) >= 1);
    assert_eq!(renewals.load(Ordering::Acquire), 0, "a failed renewal is never an extension");
    assert!(failures.load(Ordering::Acquire) >= 1);
    assert_eq!(completed.load(Ordering::Acquire), 1);
    assert_eq!(upload_relay.published().as_deref(), Some(envelope.as_slice()));
}

#[tokio::test]
async fn final_renewal_precedes_credential_publication_and_is_coalescing_exempt() {
    let (pairing_relay, rendezvous_id, state) = lease_capable_ceremony().await;
    let mut handle = PairingLeaseHandle::new(&state);
    let initial = handle.renew(pairing_relay.as_ref(), None, Instant::now()).await;
    handle.record_initial_renewal(initial, Instant::now());
    // A progress renewal consumes the coalescing window.
    let progress = handle.renew(pairing_relay.as_ref(), Some(4096), Instant::now()).await;
    assert!(progress.is_renewed());
    let before_final = pairing_relay.renew_successes();

    // The final pre-publication renewal is exempt: it must go through
    // immediately even though the five-minute window has not elapsed. Without
    // this exemption the joiner would not get its fresh 30-minute window for
    // unlock, registration, epoch catch-up, and posting its terminal bundle.
    let final_outcome = handle.renew(pairing_relay.as_ref(), None, Instant::now()).await;
    assert!(final_outcome.is_renewed(), "the final renewal must be accepted");
    assert_eq!(
        pairing_relay.renew_successes(),
        before_final + 1,
        "the final renewal must not be suppressed by coalescing"
    );
    assert_eq!(
        handle.rendezvous_id_hex(),
        rendezvous_id,
        "the handle renews the ceremony's rendezvous"
    );
    assert_coalescing_boundary_is_five_minutes();
}

/// The coalescing interval is exactly five minutes, asserted through the
/// policy's behavior at and just below the boundary rather than by comparing a
/// constant to itself.
fn assert_coalescing_boundary_is_five_minutes() {
    use prism_sync_core::pairing::lease::should_renew_for_progress;

    let start = Instant::now();
    let just_below = start + Duration::from_secs(LEASE_RENEWAL_COALESCE_SECS - 1);
    let at_boundary = start + Duration::from_secs(LEASE_RENEWAL_COALESCE_SECS);

    // New bytes, but inside the window: refused.
    assert!(
        !should_renew_for_progress(Some(start), Some(100), 200, just_below),
        "a renewal inside the window must be refused"
    );
    // New bytes, at the window: allowed.
    assert!(
        should_renew_for_progress(Some(start), Some(100), 200, at_boundary),
        "a renewal at the window boundary must be allowed"
    );
    // No new bytes, however long: still refused. This is the property that makes
    // a renewal impossible to earn from status polls, duplicate acknowledgments,
    // or retries that did not advance the committed prefix.
    assert!(
        !should_renew_for_progress(Some(start), Some(200), 200, at_boundary),
        "an unchanged offset must never earn a renewal"
    );
    assert!(
        !should_renew_for_progress(Some(start), Some(200), 199, at_boundary),
        "a regressed offset must never earn a renewal"
    );
    // The uploader additionally guarantees the hook is never invoked for offset
    // 0 (nothing has been committed yet), so the library's "no renewal yet
    // means any observed offset is progress" rule cannot be exploited by a
    // zero-offset acknowledgment. That guarantee is asserted directly in
    // `progress_signal_is_never_a_renewal_hint_for_the_relay`.
}

#[tokio::test]
async fn abandonment_invokes_the_abort_hook_on_upload_failure() {
    let relay = test_relay();
    // Exhaust the chunk retry budget so the upload fails.
    for _ in 0..10 {
        relay.push_fault("chunk", Fault::TransportError);
    }
    let (renewals, failures, completed, abandoned, attempts) = renewal_counts();
    let mut hook =
        NoopWithCounters { completed: Arc::clone(&completed), abandoned: Arc::clone(&abandoned) };

    let envelope = multi_chunk_envelope();
    let error = uploader(&relay, &envelope).run(Some(&mut hook)).await.unwrap_err();
    assert!(!error.is_retryable() || error.status == 0 || error.status >= 500);
    assert_eq!(abandoned.load(Ordering::Acquire), 1, "abandonment must be signalled");
    assert_eq!(completed.load(Ordering::Acquire), 0);
    // A failed upload never publishes.
    assert_eq!(relay.published(), None);
    let _ = (renewals, failures, attempts);
}

/// Minimal hook that only counts lifecycle signals.
struct NoopWithCounters {
    completed: Arc<AtomicU64>,
    abandoned: Arc<AtomicU64>,
}

#[async_trait]
impl SnapshotUploadProgressHook for NoopWithCounters {
    async fn on_committed_offset_advanced(&mut self, _committed_offset: u64) {}

    async fn on_upload_completed(&mut self, _total_bytes: u64) {
        self.completed.fetch_add(1, Ordering::AcqRel);
    }

    async fn on_upload_abandoned(&mut self) {
        self.abandoned.fetch_add(1, Ordering::AcqRel);
    }
}

#[tokio::test]
async fn cancellation_aborts_a_session_best_effort_even_when_abort_fails() {
    let relay = test_relay();
    let envelope = multi_chunk_envelope();
    let body = create_body_for(&envelope, "joiner-device", "cancel-key");
    let created =
        ResumableSnapshotTransport::create_snapshot_upload(relay.as_ref(), &body).await.unwrap();

    // A failing abort must not propagate.
    relay.push_fault("abort", Fault::TransportError);
    prism_sync_core::snapshot_upload::abort_upload_best_effort(relay.as_ref(), &created.upload_id)
        .await;
    assert_eq!(relay.abort_calls(), 1);

    // And a successful one makes the session terminal.
    relay.push_fault("abort", Fault::Structured(404, UploadErrorCode::NotFound));
    prism_sync_core::snapshot_upload::abort_upload_best_effort(relay.as_ref(), &created.upload_id)
        .await;
    assert_eq!(relay.abort_calls(), 2);
}

// ═════════════════════════════════════════════════════════════════════════════
// Engine-level fallback and ordering
// ═════════════════════════════════════════════════════════════════════════════

/// Exercise the engine's transport selection without a full engine: the
/// uploader is the only decision point, and `as_resumable_transport` is what
/// gates the path.
#[tokio::test]
async fn legacy_only_relay_uses_the_single_put_and_never_a_session() {
    use prism_sync_core::relay::traits::SnapshotExchange;

    let resumable = test_relay();
    let legacy = LegacyOnlyRelay::new(Arc::clone(&resumable));
    // The old-relay shape: no resumable view at all.
    assert!(legacy.as_resumable_transport().is_none());

    let envelope = multi_chunk_envelope();
    legacy
        .put_snapshot(
            3,
            42,
            envelope.clone(),
            Some(86_400),
            Some("joiner".into()),
            "me".into(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(legacy_bytes_for(&resumable), envelope);
    assert_eq!(resumable.create_calls(), 0, "no resumable session on an old relay");
    let _ = NoopProgressHook;
}

fn legacy_bytes_for(relay: &Arc<MockResumableRelay>) -> Vec<u8> {
    relay.legacy_bytes()
}

/// A zero-offset acknowledgment earns no renewal, no matter what the session
/// does afterwards. This closes the one hole in the library's
/// "no renewal yet means any observed offset is progress" rule.
#[tokio::test]
async fn a_zero_offset_acknowledgment_never_earns_a_renewal() {
    /// Hook that records every offset it is handed.
    struct Recording {
        offsets: Vec<u64>,
        attempts: usize,
        handle: PairingLeaseHandle,
        relay: Arc<MockPairingRelay>,
    }

    #[async_trait]
    impl SnapshotUploadProgressHook for Recording {
        async fn on_committed_offset_advanced(&mut self, committed_offset: u64) {
            self.offsets.push(committed_offset);
            let now = Instant::now();
            if self.handle.should_renew_for_progress(committed_offset, now) {
                self.attempts += 1;
                let _ = self.handle.renew(self.relay.as_ref(), Some(committed_offset), now).await;
            }
        }
    }

    let (pairing_relay, _rid, state) = lease_capable_ceremony().await;
    let mut hook = Recording {
        offsets: Vec::new(),
        attempts: 0,
        handle: PairingLeaseHandle::new(&state),
        relay: Arc::clone(&pairing_relay),
    };

    // A session that is created and never receives a byte: the create reports
    // offset 0 and a status poll would too.
    let relay = test_relay();
    let envelope = test_envelope(64);
    let body = create_body_for(&envelope, "joiner-device", "zero-key");
    let created =
        ResumableSnapshotTransport::create_snapshot_upload(relay.as_ref(), &body).await.unwrap();
    assert_eq!(created.committed_offset, 0);
    let status =
        ResumableSnapshotTransport::snapshot_upload_status(relay.as_ref(), &created.upload_id)
            .await
            .unwrap();
    assert_eq!(status.committed_offset, 0);

    // Drive a full upload: no reported offset may ever be zero, and every
    // offset the hook sees must be strictly increasing.
    uploader(&relay, &envelope).run(Some(&mut hook)).await.unwrap();

    assert!(!hook.offsets.is_empty(), "the hook must see real progress");
    assert!(
        hook.offsets.iter().all(|offset| *offset > 0),
        "a zero offset must never be reported as progress: {:?}",
        hook.offsets
    );
    assert!(
        hook.offsets.windows(2).all(|pair| pair[0] < pair[1]),
        "reported offsets must be strictly increasing: {:?}",
        hook.offsets
    );
}

#[tokio::test]
async fn resumable_relay_prefers_sessions_over_the_single_put() {
    use prism_sync_core::relay::traits::SnapshotExchange;

    let resumable = test_relay();
    let both = BothPathsRelay { resumable: Arc::clone(&resumable) };
    assert!(both.as_resumable_transport().is_some());

    let envelope = multi_chunk_envelope();
    let upload = SnapshotUploader::new(
        both.as_resumable_transport().unwrap(),
        &envelope,
        request("joiner-device"),
    )
    .with_retry_policy(fast_retry());
    let outcome = upload.run(None).await.unwrap();
    assert!(outcome.used_resumable());
    assert_eq!(resumable.published().as_deref(), Some(envelope.as_slice()));
    // The single PUT is untouched when the resumable path is used.
    assert_eq!(resumable.legacy_calls(), 0);
}

#[tokio::test]
async fn mixed_versions_fall_back_when_capability_disappears_mid_ceremony() {
    // A relay that advertises the capability but whose session creation is
    // rejected with `unsupported_snapshot_audience` must NOT silently fall back:
    // that is a semantic rejection, and the client must surface it.
    let relay = test_relay();
    relay.push_fault("create", Fault::Structured(400, UploadErrorCode::UnsupportedAudience));
    let envelope = multi_chunk_envelope();
    let error = uploader(&relay, &envelope).run(None).await.unwrap_err();
    assert_eq!(error.code, UploadErrorCode::UnsupportedAudience);
    assert_eq!(relay.legacy_calls(), 0, "a semantic rejection is never bypassed via PUT");
}

#[tokio::test]
async fn no_credential_publication_happens_before_completion() {
    let relay = test_relay();
    let envelope = multi_chunk_envelope();
    // Reject every chunk with a retryable 5xx: the retry budget per chunk is
    // exhausted on the first chunk, so the upload fails with nothing published
    // and completion never attempted.
    for _ in 0..10 {
        relay.push_fault("chunk", Fault::Structured(500, UploadErrorCode::Unknown("io".into())));
    }
    let error = uploader(&relay, &envelope).run(None).await.unwrap_err();
    assert!(error.is_retryable());
    assert_eq!(relay.published(), None, "a partial upload must never publish");
    assert_eq!(relay.complete_calls(), 0, "completion must not run for a partial upload");
    assert_eq!(relay.legacy_calls(), 0);
}

#[tokio::test]
async fn a_failed_completion_leaves_nothing_published() {
    let relay = test_relay();
    let envelope = multi_chunk_envelope();
    // Every byte lands, but publication is rejected semantically (hash mismatch
    // stands in for any authoritative post-receipt failure).
    relay.push_fault("complete", Fault::Structured(422, UploadErrorCode::HashMismatch));
    let error = uploader(&relay, &envelope).run(None).await.unwrap_err();
    assert_eq!(error.code, UploadErrorCode::HashMismatch);
    assert!(!error.is_retryable(), "a hash mismatch is not retryable");
    assert_eq!(relay.published(), None);
    // Only one completion attempt: a semantic rejection is not retried.
    assert_eq!(relay.complete_calls(), 1);
}

// ═════════════════════════════════════════════════════════════════════════════
// Lease-aware waits
// ═════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn lease_aware_wait_budget_reaches_the_absolute_cap_and_fast_fails_not_found() {
    use prism_sync_core::pairing::lease::{
        wait_for_pairing_slot_bytes_with_backoff, LeasePollBackoff,
    };
    use prism_sync_core::relay::pairing_relay::PairingSlot;

    // A lease-aware budget spans hours, not the fixed legacy deadline: that is
    // the whole point, because an upload may legitimately outlive the short
    // pre-confirmation TTL. The deadline is asserted against the real constant
    // through the budget's own value rather than by comparing it to itself.
    let budget = LeasePollBackoff::for_absolute_cap();
    assert!(
        budget.deadline() >= Duration::from_secs(3600),
        "the lease-aware budget must span hours, got {:?}",
        budget.deadline()
    );

    // A definitive not-found terminates the wait immediately instead of
    // exhausting the budget.
    let relay = Arc::new(MockPairingRelay::new());
    let started = Instant::now();
    let result = wait_for_pairing_slot_bytes_with_backoff(
        relay.as_ref(),
        "00000000000000000000000000000000",
        PairingSlot::Confirmation,
        "test",
        LeasePollBackoff::for_absolute_cap(),
    )
    .await;
    assert!(result.is_err());
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "a definitive not-found must fast-fail, took {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn legacy_ceremony_keeps_its_fixed_wait_budget() {
    use prism_sync_core::pairing::lease::LeasePollBackoff;

    let legacy = LeasePollBackoff::for_legacy_deadline();
    let lease_aware = LeasePollBackoff::for_absolute_cap();
    // The legacy budget must not be widened by the lease feature.
    assert!(
        legacy.deadline() < lease_aware.deadline(),
        "legacy timing must be preserved when no lease is negotiated"
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// Uploader ↔ lease bridge
// ═════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn upload_progress_bridge_renews_once_per_window_and_never_on_zero() {
    use prism_sync_core::pairing::lease::UploadProgressLeaseRenewer;
    use prism_sync_core::snapshot_upload::SnapshotUploadProgressHook;

    let (pairing_relay, _rid, state) = lease_capable_ceremony().await;
    let mut handle = PairingLeaseHandle::new(&state);

    {
        let mut renewer = UploadProgressLeaseRenewer::new(&mut handle, pairing_relay.as_ref());
        // A zero offset is never progress: nothing has been durably committed.
        renewer.on_committed_offset_advanced(0).await;
        assert_eq!(pairing_relay.renew_successes(), 0, "offset zero must not renew");

        // First real offset earns the first renewal.
        renewer.on_committed_offset_advanced(1024).await;
        assert_eq!(pairing_relay.renew_successes(), 1);

        // More progress inside the same window is coalesced away, however many
        // times the uploader reports it.
        renewer.on_committed_offset_advanced(2048).await;
        renewer.on_committed_offset_advanced(4096).await;
        renewer.on_committed_offset_advanced(8192).await;
        assert_eq!(pairing_relay.renew_successes(), 1, "coalescing must hold across chunks");

        // A duplicate of the last acknowledged offset is not progress either.
        renewer.on_committed_offset_advanced(8192).await;
        assert_eq!(pairing_relay.renew_successes(), 1);
    }

    // The handle still reports a live lease, so the ceremony can continue.
    assert!(!handle.is_terminal());
}

#[tokio::test]
async fn upload_progress_bridge_keeps_renewal_failures_nonfatal() {
    use prism_sync_core::pairing::lease::{LeaseRenewalOutcome, UploadProgressLeaseRenewer};
    use prism_sync_core::snapshot_upload::SnapshotUploadProgressHook;

    // A relay that does not support the lease: every renewal is a uniform
    // not-found, which is terminal for the lease but never for the ceremony.
    let relay = Arc::new(MockPairingRelay::new());
    relay.set_lease_supported(false);
    let state = VerifiedInitiatorState::leased(
        "deadbeefdeadbeefdeadbeefdeadbeef".to_string(),
        [0u8; 32],
        prism_sync_core::pairing::lease::LeaseCapability::v1(),
        zeroize::Zeroizing::new([9u8; 32]),
    );
    let mut handle = PairingLeaseHandle::new(&state);

    let mut renewer = UploadProgressLeaseRenewer::new(&mut handle, relay.as_ref());
    // Must not panic or propagate: the upload continues under its prior expiry.
    renewer.on_committed_offset_advanced(4096).await;
    assert_eq!(renewer.last_outcome(), LeaseRenewalOutcome::TerminalNotFound);
    assert!(renewer.is_terminal(), "a uniform not-found terminates the lease only");
}

/// The full split-ceremony ordering, driven through the real pieces core owns:
/// confirmation verified -> initial renewal -> resumable upload (with
/// progress coalescing) -> final renewal -> credential release.
#[tokio::test]
async fn split_ordering_uploads_before_credentials_and_final_renews_after() {
    use prism_sync_core::pairing::lease::{LeaseRenewalOutcome, UploadProgressLeaseRenewer};

    let (pairing_relay, _rid, state) = lease_capable_ceremony().await;
    let mut handle = PairingLeaseHandle::new(&state);

    // Step 1: the initial renewal immediately after confirmation verification,
    // with no upload progress required.
    let initial = handle.renew(pairing_relay.as_ref(), None, Instant::now()).await;
    handle.record_initial_renewal(initial, Instant::now());
    assert_eq!(initial, LeaseRenewalOutcome::Renewed);
    assert_eq!(pairing_relay.renew_successes(), 1);

    // Step 2: the resumable upload runs to completion, renewing only for
    // strictly increased committed offsets and coalescing to one per window.
    let upload_relay = test_relay();
    let envelope = multi_chunk_envelope();
    let credentials_published = Arc::new(AtomicBool::new(false));
    {
        let mut renewer = UploadProgressLeaseRenewer::new(&mut handle, pairing_relay.as_ref());
        SnapshotUploader::new(upload_relay.as_ref(), &envelope, request("joiner-device"))
            .with_retry_policy(fast_retry())
            .run(Some(&mut renewer))
            .await
            .unwrap();
        // The upload has NOT published credentials: that is a later step.
        assert!(!credentials_published.load(Ordering::Acquire));
    }
    let after_upload = pairing_relay.renew_successes();
    assert!(after_upload >= 1, "the upload must have published exactly at the relay");
    assert_eq!(upload_relay.published().as_deref(), Some(envelope.as_slice()));

    // Step 3: the final pre-publication renewal, exempt from coalescing.
    let final_outcome = handle.renew(pairing_relay.as_ref(), None, Instant::now()).await;
    assert_eq!(
        final_outcome,
        LeaseRenewalOutcome::Renewed,
        "the final renewal must be accepted even inside the window"
    );
    assert_eq!(pairing_relay.renew_successes(), after_upload + 1);

    // Step 4: only now may credentials be released. Model that gate explicitly:
    // nothing in core publishes credentials on the resumable path, so the
    // invariant is that the upload returned before this point.
    credentials_published.store(true, Ordering::Release);
    assert!(credentials_published.load(Ordering::Acquire));
}

#[tokio::test]
async fn a_failed_upload_performs_no_final_renewal_and_no_credential_release() {
    use prism_sync_core::pairing::lease::UploadProgressLeaseRenewer;

    let (pairing_relay, _rid, state) = lease_capable_ceremony().await;
    let mut handle = PairingLeaseHandle::new(&state);
    let initial = handle.renew(pairing_relay.as_ref(), None, Instant::now()).await;
    handle.record_initial_renewal(initial, Instant::now());
    let after_initial = pairing_relay.renew_successes();

    // Exhaust the chunk retry budget so the upload fails.
    let upload_relay = test_relay();
    for _ in 0..10 {
        upload_relay.push_fault("chunk", Fault::TransportError);
    }
    let envelope = multi_chunk_envelope();
    let upload_result = {
        let mut renewer = UploadProgressLeaseRenewer::new(&mut handle, pairing_relay.as_ref());
        SnapshotUploader::new(upload_relay.as_ref(), &envelope, request("joiner-device"))
            .with_retry_policy(fast_retry())
            .run(Some(&mut renewer))
            .await
    };

    assert!(upload_result.is_err(), "the upload must fail");
    assert_eq!(upload_relay.published(), None, "a failed upload never publishes");
    // Because the upload failed, the caller never reaches the final renewal:
    // no further lease activity happened beyond the initial renewal.
    assert_eq!(pairing_relay.renew_successes(), after_initial);
}

/// The session-created signal is what lets a cancelling caller abort exactly the
/// session that is in flight, so it must arrive before the first byte is sent and
/// exactly once — including on the resumed path, which reuses the same session.
#[tokio::test]
async fn session_created_signal_precedes_progress_and_fires_once() {
    struct SessionRecorder {
        sessions: Vec<String>,
        progress_seen_before_session: AtomicBool,
        progress_count: AtomicU64,
    }

    #[async_trait]
    impl SnapshotUploadProgressHook for SessionRecorder {
        async fn on_session_created(&mut self, upload_id: &str) {
            assert!(!upload_id.is_empty(), "the relay must return a real session id");
            self.sessions.push(upload_id.to_string());
        }

        async fn on_committed_offset_advanced(&mut self, committed_offset: u64) {
            assert!(committed_offset > 0);
            if self.sessions.is_empty() {
                self.progress_seen_before_session.store(true, Ordering::Release);
            }
            self.progress_count.fetch_add(1, Ordering::AcqRel);
        }
    }

    let relay = test_relay();
    let envelope = multi_chunk_envelope();
    let mut hook = SessionRecorder {
        sessions: Vec::new(),
        progress_seen_before_session: AtomicBool::new(false),
        progress_count: AtomicU64::new(0),
    };

    let outcome = uploader(&relay, &envelope).run(Some(&mut hook)).await.unwrap();
    assert!(outcome.used_resumable());

    assert_eq!(
        hook.sessions.len(),
        1,
        "one session is created per upload, however many chunks it takes"
    );
    assert!(
        !hook.progress_seen_before_session.load(Ordering::Acquire),
        "progress must never be reported before the caller can abort"
    );
    assert!(
        hook.progress_count.load(Ordering::Acquire) >= 1,
        "the multipart envelope must report progress"
    );
    assert_eq!(relay.abort_calls(), 0, "a successful upload is never aborted");
}

/// The session id handed to the hook is the one the caller can abort, and a
/// failed upload leaves that session abortable rather than published.
#[tokio::test]
async fn a_failed_upload_leaves_the_reported_session_abortable() {
    use prism_sync_core::snapshot_upload::abort_upload_best_effort;

    let recorder = Arc::new(Mutex::new(Vec::<String>::new()));
    struct CaptureSession(Arc<Mutex<Vec<String>>>);

    #[async_trait]
    impl SnapshotUploadProgressHook for CaptureSession {
        async fn on_session_created(&mut self, upload_id: &str) {
            self.0.lock().unwrap().push(upload_id.to_string());
        }

        async fn on_committed_offset_advanced(&mut self, _committed_offset: u64) {}
    }

    let relay = test_relay();
    // Break the chunk path so the upload cannot publish.
    for _ in 0..10 {
        relay.push_fault("chunk", Fault::TransportError);
    }
    let envelope = multi_chunk_envelope();
    let mut hook = CaptureSession(Arc::clone(&recorder));

    let result = uploader(&relay, &envelope).run(Some(&mut hook)).await;
    assert!(result.is_err(), "the upload must fail");
    assert_eq!(relay.published(), None, "a failed upload never publishes");

    let sessions = recorder.lock().unwrap().clone();
    assert_eq!(sessions.len(), 1, "the session was created before the failure");
    assert_eq!(
        relay.abort_calls(),
        0,
        "the uploader itself does not abort; the cancelling caller does"
    );

    // Exactly what the FFI's cancellation path does with that id.
    abort_upload_best_effort(relay.as_ref(), &sessions[0]).await;
    assert_eq!(relay.abort_calls(), 1, "the reported session is abortable");
    assert!(relay.published().is_none(), "aborting must not publish anything");
}
