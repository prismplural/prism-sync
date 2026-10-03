//! Privacy-preserving opaque pairing lease.
//!
//! Implements the initiator-side half of the pairing lease extension.
//!
//! The lease keeps a confirmed pairing rendezvous alive while useful
//! client-observed work (snapshot upload, joiner import) continues, without
//! telling the relay which upload progressed. Three parties negotiate it
//! through channels legacy peers never parse:
//!
//! 1. the joiner sends `lease_key_hash = SHA-256(pairing_lease_secret)` plus
//!    `lease_version: 1` as optional create metadata;
//! 2. a supporting relay echoes `lease_version: 1` in the create response;
//! 3. a new initiator posts an optional `lease_capability` slot **before** the
//!    unchanged legacy `pairing_init`, authenticated with the existing
//!    transcript-bound initiator→responder key.
//!
//! # Base64 alphabet for `lease_key_hash`
//!
//! The verifier travels base64-encoded. The core client emits the **standard**
//! alphabet (`+`/`/`) for compatibility with existing clients. A conforming
//! relay accepts **both** alphabets, padded or unpadded, and still requires the
//! value to decode to exactly 32 bytes, so a peer following either form reaches
//! the same lease state. See the relay's `decode_lease_key_hash`.
//!
//! The raw secret travels to the initiator only inside an extended protected
//! confirmation payload sent responder→initiator, and only when both the relay
//! echo and the authenticated capability agree on v1. Otherwise the joiner
//! sends the exact legacy 32-byte confirmation MAC.
//!
//! # Frozen encodings
//!
//! Nothing here is appended to [`PairingInit`](crate::bootstrap::PairingInit),
//! [`JoinerBootstrapRecord`](crate::bootstrap::JoinerBootstrapRecord), or
//! [`RendezvousToken`](crate::bootstrap::RendezvousToken). Those strict
//! encodings remain byte-identical; the capability is a separate self-contained
//! frame posted to its own slot, and the extended confirmation is a separate
//! self-contained frame posted to the existing `confirmation` slot.
//!
//! # Wire layout (relay parity)
//!
//! Both frames are self-authenticating and length-disjoint from the fixed
//! 32-byte legacy confirmation MAC (`LEGACY_CONFIRMATION_MAC_LEN`).
//!
//! ## `lease_capability` slot (initiator → joiner)
//!
//! ```text
//! [1B version = 0x01]
//! [16B rendezvous_id]        — binds the frame to this ceremony
//! [32B transcript_hash]      — binds every negotiated public key
//! [u16 BE capability_len]
//! [capability_len bytes: inner capability]
//! [32B HMAC-SHA256]          — key = initiator_encrypt_key
//! ```
//!
//! The inner capability is the exact frame posted by the initiator:
//!
//! ```text
//! [1B version = 0x01]
//! [1B flags]                 — bit 0: lease v1 offered
//! [u16 BE lease_version]     — 1 while bit 0 is set
//! [u16 BE frame_len]         — length of this inner frame
//! ```
//!
//! The joiner commits [`compute_lease_key_hash`] = `SHA-256(pairing_lease_secret)`
//! at create time. The inner frame is what the extended confirmation binds, so
//! the secret is released exactly when the initiator's authenticated capability
//! proves it understood and chose the negotiated version.
//!
//! ## `confirmation` slot (responder → initiator), lease v1
//!
//! ```text
//! [1B version = 0x01]
//! [24B XChaCha20-Poly1305 nonce]
//! [4B BE ciphertext_len]
//! [ciphertext + 16B Poly1305 tag]
//!```
//!
//! with AAD
//! `"PRISM_BOOTSTRAP_ENVELOPE" || 0x00 || profile || bootstrap_version || Responder
//!  || u16-BE(len) || "sync_lease_secret" || u32-BE(len) || rendezvous_id
//!  || transcript_hash || u16-BE(len) || capability_inner_frame`
//! (identical to [`EncryptedEnvelope`](crate::bootstrap::EncryptedEnvelope) plus
//! a trailing, length-prefixed capability field), plaintext = the 32 random
//! secret bytes, key = responder→initiator encryption key.
//!
//! A legacy confirmation is exactly 32 bytes, so the two framings can never be
//! confused.

use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::bootstrap::{BootstrapKeySchedule, BootstrapRole, EncryptedEnvelope, EnvelopeContext};
use crate::error::{CoreError, Result};
use crate::relay::pairing_relay::{PairingRelay, PairingSlot};
use crate::relay::traits::RelayError;

// ── Protocol constants ───────────────────────────────────────────────────────

/// Lease protocol version negotiated by all three parties.
pub const LEASE_VERSION_V1: u16 = 1;

/// Version byte for both lease frames.
pub const LEASE_FRAME_VERSION: u8 = 0x01;

/// Length of the fixed legacy confirmation MAC (unchanged).
pub const LEGACY_CONFIRMATION_MAC_LEN: usize = 32;

/// Length of the random pairing lease secret.
pub const LEASE_SECRET_LEN: usize = 32;

/// Idle expiry granted by a successful renewal (v1).
pub const LEASE_IDLE_EXTENSION_SECS: u64 = 1800;

/// Absolute, nonrenewable lease cap measured from the first valid renewal (v1).
pub const LEASE_ABSOLUTE_CAP_SECS: u64 = 14400;

/// Minimum spacing between progress-driven renewals.
pub const LEASE_RENEWAL_COALESCE_SECS: u64 = 300;

/// Deployment default cap on concurrently leased pairing rows.
///
/// Server-side only; duplicated in the relay with parity tests because the
/// relay cannot depend on this crate.
pub const LEASE_MAX_CONCURRENT_LEASED_SESSIONS: u32 = 256;

/// Exact request body length accepted by `POST /v1/pairing/{id}/lease/renew`.
pub const LEASE_RENEW_REQUEST_BODY_LEN: usize = LEASE_SECRET_LEN;

// ── Frame layout constants ───────────────────────────────────────────────────

const CAPABILITY_FRAME_PREFIX_LEN: usize = 1 + 1 + 2 + 2; // version, flags, lease_version, frame_len
const CAPABILITY_SLOT_FIXED_LEN: usize = 1 + 16 + 32 + 2 + 32; // header + HMAC tag
const CAPABILITY_HMAC_LEN: usize = 32;
const CAPABILITY_FLAG_LEASE_V1: u8 = 0x01;

/// Domain separator for the `lease_capability` slot HMAC.
const CAPABILITY_MAC_DOMAIN: &[u8] = b"PRISM_PAIRING_LEASE_CAPABILITY_V1";

/// Envelope purpose for the extended protected confirmation.
const LEASE_SECRET_PURPOSE: &[u8] = b"sync_lease_secret";

// ── Errors ───────────────────────────────────────────────────────────────────

/// Why lease negotiation did not produce a usable secret.
///
/// Every variant is a **nonfatal downgrade**: absence at any negotiation edge
/// means fixed-TTL pairing, never ceremony failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseUnavailableReason {
    /// The relay's create response carried no `lease_version` echo (old relay).
    RelayNotLeaseCapable,
    /// No `lease_capability` slot was posted, or the relay rejected/404'd it.
    CapabilityAbsent,
    /// The capability slot was present but not cryptographically valid.
    CapabilityInvalid,
    /// A capability was offered, but not for lease v1.
    VersionUnsupported,
    /// The confirmation slot held a frame that is neither legacy nor v1.
    ConfirmationFramingUnsupported,
    /// The peer sent the exact legacy 32-byte confirmation MAC, so this
    /// ceremony is fixed-TTL for both sides.
    LegacyConfirmation,
}

/// Outcome of one attempted lease renewal.
///
/// Renewal failures never abort the ceremony: the initiator continues under the
/// previously established expiry and lets ordinary rendezvous not-found from a
/// later slot operation terminate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseRenewalOutcome {
    /// The relay accepted the renewal (HTTP 204).
    Renewed,
    /// The relay returned the uniform not-found response (unknown, expired,
    /// unsupported, wrong-secret, pre-confirmation, consumed, or saturated).
    /// Terminal for lease purposes.
    TerminalNotFound,
    /// The ceremony is not lease-capable, so no renewal was attempted.
    LeaseNotNegotiated,
    /// Retryable or ambiguous transport failure. Nonfatal; the initiator keeps
    /// uploading under the current expiry and must not claim extension.
    Unavailable,
}

impl LeaseRenewalOutcome {
    /// Whether the relay confirmed an extension.
    pub fn is_renewed(self) -> bool {
        matches!(self, Self::Renewed)
    }

    /// Whether lease renewal is permanently impossible for this ceremony.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::TerminalNotFound)
    }
}

// ── Verifier ─────────────────────────────────────────────────────────────────

/// The joiner's create-time commitment: `SHA-256` over the random 32-byte
/// lease secret.
///
/// Committing at session creation is what makes the lease safe: a
/// rendezvous-ID thief can write the unauthenticated confirmation slot but
/// cannot replace the set-once verifier or learn the secret from the protected
/// confirmation payload. The renewal endpoint hashes the presented 32-byte body
/// and compares it to this value in constant time.
///
/// The returning `[u8; 32]` is the raw digest. It is base64-encoded for the wire
/// by the relay client, which uses the **standard** alphabet as the v1 legacy
/// canonical form; a conforming relay also accepts the published base64url form.
/// The digest itself, not its encoding, is what must match.
pub fn compute_lease_key_hash(lease_secret: &[u8; LEASE_SECRET_LEN]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(lease_secret);
    hasher.finalize().into()
}

// ── Capability ───────────────────────────────────────────────────────────────

/// The initiator's lease capability, versioned and self-contained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseCapability {
    /// `true` when the initiator understands the lease v1 protocol.
    pub lease_v1: bool,
}

impl LeaseCapability {
    /// A capability offering lease v1.
    pub const fn v1() -> Self {
        Self { lease_v1: true }
    }

    /// A capability that explicitly declines the lease.
    pub const fn declined() -> Self {
        Self { lease_v1: false }
    }

    /// The lease version this capability negotiates.
    pub fn lease_version(&self) -> Option<u16> {
        self.lease_v1.then_some(LEASE_VERSION_V1)
    }

    /// Encode the inner capability frame.
    ///
    /// `[1B version][1B flags][u16 BE lease_version][u16 BE frame_len]`
    ///
    /// This is the exact byte string the joiner hashes into its create-time
    /// verifier, so the encoding is part of the wire contract.
    pub fn inner_frame(&self) -> Vec<u8> {
        let frame_len = CAPABILITY_FRAME_PREFIX_LEN as u16;
        let mut buf = Vec::with_capacity(CAPABILITY_FRAME_PREFIX_LEN);
        buf.push(LEASE_FRAME_VERSION);
        buf.push(if self.lease_v1 { CAPABILITY_FLAG_LEASE_V1 } else { 0x00 });
        buf.extend_from_slice(&self.lease_version().unwrap_or(0).to_be_bytes());
        buf.extend_from_slice(&frame_len.to_be_bytes());
        buf
    }

    /// Parse an inner capability frame, rejecting trailing bytes.
    pub fn from_inner_frame(data: &[u8]) -> Option<Self> {
        if data.len() != CAPABILITY_FRAME_PREFIX_LEN {
            return None;
        }
        if data[0] != LEASE_FRAME_VERSION {
            return None;
        }
        let flags = data[1];
        let lease_version = u16::from_be_bytes([data[2], data[3]]);
        let declared_len = u16::from_be_bytes([data[4], data[5]]) as usize;
        if declared_len != CAPABILITY_FRAME_PREFIX_LEN {
            return None;
        }
        // No unknown flag bits are accepted at v1.
        if flags & !CAPABILITY_FLAG_LEASE_V1 != 0 {
            return None;
        }
        let lease_v1 = flags & CAPABILITY_FLAG_LEASE_V1 != 0;
        if lease_v1 != (lease_version == LEASE_VERSION_V1) {
            return None;
        }
        Some(Self { lease_v1 })
    }

    /// Whether the capability supports the given lease version.
    pub fn supports(&self, lease_version: u16) -> bool {
        self.lease_version() == Some(lease_version)
    }
}

/// Full `lease_capability` slot frame: capability plus transcript/ceremony
/// binding, authenticated with the initiator→responder encryption key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseCapabilityFrame {
    /// The negotiated capability.
    pub capability: LeaseCapability,
    /// The inner capability bytes that were authenticated.
    pub inner: Vec<u8>,
    /// The exact wire bytes posted to the slot.
    wire: Vec<u8>,
}

impl LeaseCapabilityFrame {
    /// Encode the full slot frame for `rendezvous_id`/`transcript_hash` under
    /// `key_schedule`.
    ///
    /// This is the exact byte string posted to the `lease_capability` slot. The
    /// MAC is a pure function of the session keys, the ceremony binding, and the
    /// inner capability, so re-encoding is deterministic.
    pub fn seal(
        key_schedule: &BootstrapKeySchedule,
        rendezvous_id: &[u8; 16],
        transcript_hash: &[u8; 32],
        capability: &LeaseCapability,
    ) -> Self {
        let inner = capability.inner_frame();
        let tag = capability_mac(key_schedule, rendezvous_id, transcript_hash, &inner);
        let mut wire = Vec::with_capacity(CAPABILITY_SLOT_FIXED_LEN + inner.len());
        wire.push(LEASE_FRAME_VERSION);
        wire.extend_from_slice(rendezvous_id);
        wire.extend_from_slice(transcript_hash);
        wire.extend_from_slice(&(inner.len() as u16).to_be_bytes());
        wire.extend_from_slice(&inner);
        wire.extend_from_slice(&tag);
        Self { capability: *capability, inner, wire }
    }

    /// The exact wire bytes posted to the `lease_capability` slot.
    pub fn to_bytes(&self) -> &[u8] {
        &self.wire
    }

    /// Verify and parse a `lease_capability` slot frame.
    ///
    /// Returns `None` for any framing or authentication failure: the joiner
    /// treats only a cryptographically valid capability as initiator support.
    pub fn open(
        key_schedule: &BootstrapKeySchedule,
        rendezvous_id: &[u8; 16],
        transcript_hash: &[u8; 32],
        data: &[u8],
    ) -> Option<Self> {
        if data.len() < CAPABILITY_SLOT_FIXED_LEN {
            return None;
        }
        if data[0] != LEASE_FRAME_VERSION {
            return None;
        }
        if &data[1..17] != rendezvous_id {
            return None;
        }
        if &data[17..49] != transcript_hash {
            return None;
        }
        let inner_len = u16::from_be_bytes([data[49], data[50]]) as usize;
        let tag_start = 51usize.checked_add(inner_len)?;
        if data.len() != tag_start + CAPABILITY_HMAC_LEN {
            return None;
        }
        let inner = &data[51..tag_start];
        let tag = &data[tag_start..];

        let expected = capability_mac(key_schedule, rendezvous_id, transcript_hash, inner);
        if !constant_time_eq(&expected, tag) {
            return None;
        }

        let capability = LeaseCapability::from_inner_frame(inner)?;
        Some(Self { capability, inner: inner.to_vec(), wire: data.to_vec() })
    }
}

fn capability_mac(
    key_schedule: &BootstrapKeySchedule,
    rendezvous_id: &[u8; 16],
    transcript_hash: &[u8; 32],
    inner: &[u8],
) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;

    let key = key_schedule.encryption_key(BootstrapRole::Initiator);
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(CAPABILITY_MAC_DOMAIN);
    mac.update(&[0x00]);
    mac.update(&[LEASE_FRAME_VERSION]);
    mac.update(rendezvous_id);
    mac.update(transcript_hash);
    mac.update(&(inner.len() as u16).to_be_bytes());
    mac.update(inner);
    mac.finalize().into_bytes().into()
}

/// Constant-time byte comparison for fixed-length authenticators.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ── Extended protected confirmation ──────────────────────────────────────────

/// A classified confirmation-slot frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfirmationFrame {
    /// The exact legacy 32-byte HMAC confirmation MAC.
    LegacyMac([u8; LEGACY_CONFIRMATION_MAC_LEN]),
    /// A lease v1 extended frame (opaque until opened).
    LeaseV1(Vec<u8>),
}

/// Classify a confirmation-slot frame by its exact length.
///
/// The framings are length-disjoint: legacy is exactly 32 bytes and v1 is at
/// least 1 + 24 + 4 + 16 + tag bytes.
pub fn classify_confirmation_frame(data: &[u8]) -> Option<ConfirmationFrame> {
    if data.len() == LEGACY_CONFIRMATION_MAC_LEN {
        let mut mac = [0u8; LEGACY_CONFIRMATION_MAC_LEN];
        mac.copy_from_slice(data);
        return Some(ConfirmationFrame::LegacyMac(mac));
    }
    if data.first() == Some(&LEASE_FRAME_VERSION) && data.len() > LEGACY_CONFIRMATION_MAC_LEN {
        return Some(ConfirmationFrame::LeaseV1(data.to_vec()));
    }
    None
}

/// Seal the extended protected confirmation carrying the lease secret.
///
/// `capability_inner` is the authenticated capability the initiator posted, so
/// the secret is released only to an initiator that proved both the transcript
/// and the negotiation choice committed at session creation.
pub fn seal_extended_confirmation(
    key_schedule: &BootstrapKeySchedule,
    rendezvous_id: &[u8],
    transcript_hash: &[u8; 32],
    capability_inner: &[u8],
    lease_secret: &[u8; LEASE_SECRET_LEN],
) -> Result<Vec<u8>> {
    let key = key_schedule.encryption_key(BootstrapRole::Responder);
    let context = EnvelopeContext {
        profile: crate::bootstrap::BootstrapProfile::SyncPairing,
        version: crate::bootstrap::BootstrapVersion::V1,
        sender_role: BootstrapRole::Responder,
        purpose: LEASE_SECRET_PURPOSE,
        session_id: rendezvous_id,
        transcript_hash,
    };
    // `EncryptedEnvelope` binds profile/version/role/purpose/session/transcript
    // in its AAD; the capability is bound by mixing it into the AEAD key below,
    // so the secret is released only to an initiator that posted exactly the
    // authenticated capability committed at session creation.
    let bound_key = bind_capability_into_key(key, capability_inner, transcript_hash)?;
    EncryptedEnvelope::seal(&bound_key, lease_secret, &context)
}

/// Verify and open an extended confirmation frame, returning the lease secret.
pub fn open_extended_confirmation(
    key_schedule: &BootstrapKeySchedule,
    rendezvous_id: &[u8],
    transcript_hash: &[u8; 32],
    capability_inner: &[u8],
    frame: &[u8],
) -> Result<Zeroizing<[u8; LEASE_SECRET_LEN]>> {
    let key = key_schedule.encryption_key(BootstrapRole::Responder);
    let bound_key = bind_capability_into_key(key, capability_inner, transcript_hash)?;
    let context = EnvelopeContext {
        profile: crate::bootstrap::BootstrapProfile::SyncPairing,
        version: crate::bootstrap::BootstrapVersion::V1,
        sender_role: BootstrapRole::Responder,
        purpose: LEASE_SECRET_PURPOSE,
        session_id: rendezvous_id,
        transcript_hash,
    };
    let plaintext = EncryptedEnvelope::open(&bound_key, frame, &context)
        .map_err(|_| CoreError::Engine("lease secret confirmation failed authentication".into()))?;
    if plaintext.len() != LEASE_SECRET_LEN {
        return Err(CoreError::Engine(format!(
            "lease secret has wrong length: expected {LEASE_SECRET_LEN}, got {}",
            plaintext.len()
        )));
    }
    let mut secret = Zeroizing::new([0u8; LEASE_SECRET_LEN]);
    secret.copy_from_slice(&plaintext[..LEASE_SECRET_LEN]);
    Ok(secret)
}

/// Derive the capability/transcript-bound AEAD key used for the secret.
///
/// Domain-separated from every other use of the responder key so the same key
/// schedule can never be confused across purposes.
fn bind_capability_into_key(
    base_key: &[u8],
    capability_inner: &[u8],
    transcript_hash: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>> {
    let info: Vec<u8> = {
        let mut info = Vec::with_capacity(LEASE_SECRET_PURPOSE.len() + 2 + capability_inner.len());
        info.extend_from_slice(LEASE_SECRET_PURPOSE);
        info.extend_from_slice(&(capability_inner.len() as u16).to_be_bytes());
        info.extend_from_slice(capability_inner);
        info
    };
    prism_sync_crypto::kdf::derive_subkey(base_key, transcript_hash, &info)
        .map_err(|e| CoreError::Engine(format!("lease key derivation failed: {e}")))
}

/// The documented AAD layout of the extended confirmation.
///
/// The envelope's real AAD comes from
/// [`EnvelopeContext`](crate::bootstrap::EnvelopeContext) and covers
/// profile/version/role/purpose/session/transcript; the capability is bound
/// through the AEAD key in [`bind_capability_into_key`]. This helper exists so
/// tests can assert the documented layout that relay-side parity work must
/// reproduce, and it is not part of the wire path.
#[cfg(test)]
fn extended_confirmation_aad(
    rendezvous_id: &[u8],
    transcript_hash: &[u8; 32],
    capability_inner: &[u8],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(
        b"PRISM_BOOTSTRAP_ENVELOPE".len()
            + 1
            + 3
            + 2
            + LEASE_SECRET_PURPOSE.len()
            + 4
            + 16
            + 32
            + 2
            + capability_inner.len(),
    );
    aad.extend_from_slice(b"PRISM_BOOTSTRAP_ENVELOPE");
    aad.push(0x00);
    aad.push(crate::bootstrap::BootstrapProfile::SyncPairing.as_byte());
    aad.push(crate::bootstrap::BootstrapVersion::V1.as_byte());
    aad.push(BootstrapRole::Responder.as_byte());
    aad.extend_from_slice(&(LEASE_SECRET_PURPOSE.len() as u16).to_be_bytes());
    aad.extend_from_slice(LEASE_SECRET_PURPOSE);
    aad.extend_from_slice(&(rendezvous_id.len() as u32).to_be_bytes());
    aad.extend_from_slice(rendezvous_id);
    aad.extend_from_slice(transcript_hash);
    aad.extend_from_slice(&(capability_inner.len() as u16).to_be_bytes());
    aad.extend_from_slice(capability_inner);
    aad
}

// ── Backoff policy ───────────────────────────────────────────────────────────

/// Bounded exponential backoff with jitter for lease-aware slot waits.
///
/// Replaces the legacy fixed 250 ms cadence for waits that can span snapshot
/// upload or joiner import. Legacy non-lease ceremonies keep their existing
/// fixed deadlines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeasePollBackoff {
    current: Duration,
    initial: Duration,
    max: Duration,
    elapsed: Duration,
    deadline: Duration,
}

impl LeasePollBackoff {
    /// Create a backoff whose total wait budget is `deadline`.
    pub const fn new(deadline: Duration) -> Self {
        Self {
            current: Duration::from_millis(250),
            initial: Duration::from_millis(250),
            max: Duration::from_secs(30),
            elapsed: Duration::ZERO,
            deadline,
        }
    }

    /// Backoff whose budget is the lease absolute cap (four hours by default).
    pub const fn for_absolute_cap() -> Self {
        Self::new(Duration::from_secs(LEASE_ABSOLUTE_CAP_SECS))
    }

    /// Backoff sized for the legacy fixed-deadline ceremony.
    pub const fn for_legacy_deadline() -> Self {
        Self::new(Duration::from_secs(300))
    }

    /// Total wait budget.
    pub fn deadline(&self) -> Duration {
        self.deadline
    }

    /// Whether the budget is exhausted.
    pub fn is_exhausted(&self) -> bool {
        self.elapsed >= self.deadline
    }

    /// Time already spent waiting.
    pub fn elapsed(&self) -> Duration {
        self.elapsed
    }

    /// The next delay, before jitter.
    pub fn next_delay(&self) -> Duration {
        self.current.min(self.deadline.saturating_sub(self.elapsed))
    }

    /// Record a completed wait and advance the exponential schedule.
    pub fn advance(&mut self, waited: Duration) {
        self.elapsed += waited;
        let doubled = self.current.checked_mul(2).unwrap_or(self.max);
        self.current = doubled.min(self.max).max(self.initial);
    }

    /// Deterministic jitter in `[0, delay/2]` derived from `entropy`.
    ///
    /// Jitter is supplied by the caller (typically the request nonce) so the
    /// policy stays pure and unit-testable. This deliberately avoids a
    /// `rand` dependency in the wait loop.
    pub fn jitter(delay: Duration, entropy: u64) -> Duration {
        let base = delay.as_millis() as u64;
        if base == 0 {
            return Duration::ZERO;
        }
        Duration::from_millis((entropy % (base / 2 + 1)).min(base))
    }
}

// ── Slot-wait policy ─────────────────────────────────────────────────────────

/// The wait policy for one pairing-slot wait.
///
/// This is the explicit, testable form of the rule the service applies: a wait
/// is lease-aware only when *this* ceremony's authenticated negotiation
/// produced lease v1. Everything else keeps the exact legacy cadence and
/// deadline, so the lease feature can never extend a ceremony that did not
/// cryptographically negotiate it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotWaitPolicy {
    /// Lease-aware bounded exponential backoff up to the lease absolute cap.
    LeaseAware(LeasePollBackoff),
    /// The unchanged fixed-cadence legacy deadline.
    Legacy,
}

impl SlotWaitPolicy {
    /// The lease-aware policy for a wait that may span upload or import.
    pub const fn lease_aware() -> Self {
        Self::LeaseAware(LeasePollBackoff::for_absolute_cap())
    }

    /// The legacy policy preserving the existing 250 ms × 1200 budget.
    pub const fn legacy() -> Self {
        Self::Legacy
    }

    /// Whether this policy permits waiting past the legacy deadline.
    pub fn is_lease_aware(self) -> bool {
        matches!(self, Self::LeaseAware(_))
    }

    /// The total wait budget this policy allows.
    pub fn deadline(self) -> Duration {
        match self {
            Self::LeaseAware(backoff) => backoff.deadline(),
            Self::Legacy => LEGACY_SLOT_WAIT_DEADLINE,
        }
    }

    /// The backoff to drive the lease-aware wait with, if any.
    pub fn backoff(self) -> Option<LeasePollBackoff> {
        match self {
            Self::LeaseAware(backoff) => Some(backoff),
            Self::Legacy => None,
        }
    }
}

/// The exact legacy slot-wait budget: 1200 attempts at a fixed 250 ms cadence.
///
/// Mirrors the fixed-cadence wait, which paces its attempts rather than
/// accumulating real elapsed time, so the budget is the product of the two
/// constants rather than a wall-clock measurement.
pub const LEGACY_SLOT_WAIT_DEADLINE: Duration = Duration::from_millis(250 * 1_200);

/// Select the slot-wait policy from the ceremony's authenticated negotiation
/// state.
///
/// `accepts_lease_v1` must be derived from cryptographic verification of this
/// ceremony's transcript, never from unauthenticated relay metadata: the
/// initiator's `lease_negotiation().is_v1()` or the joiner's
/// `lease_negotiation().is_v1()`. Both require that the relay echoed the lease
/// *and* that the peer's capability verified.
pub fn pairing_slot_wait_policy(accepts_lease_v1: bool) -> SlotWaitPolicy {
    if accepts_lease_v1 {
        SlotWaitPolicy::lease_aware()
    } else {
        SlotWaitPolicy::legacy()
    }
}

// ── Renewal policy ───────────────────────────────────────────────────────────

/// Decide whether a progress-driven renewal is due.
///
/// The initiator renews only after observing a strictly larger committed upload
/// offset, coalesced to at most one renewal per
/// [`LEASE_RENEWAL_COALESCE_SECS`]. Status requests, duplicate
/// acknowledgments, retries without new bytes, and open connections do not
/// renew.
pub fn should_renew_for_progress(
    last_renewal: Option<Instant>,
    last_renewed_offset: Option<u64>,
    committed_offset: u64,
    now: Instant,
) -> bool {
    let advanced = match last_renewed_offset {
        Some(previous) => committed_offset > previous,
        // No renewal yet: any observed offset is progress.
        None => true,
    };
    if !advanced {
        return false;
    }
    match last_renewal {
        Some(at) => now.saturating_duration_since(at).as_secs() >= LEASE_RENEWAL_COALESCE_SECS,
        None => true,
    }
}

// ── Verified initiator state / lease handle ──────────────────────────────────

/// The three-party lease negotiation result.
///
/// Lease v1 requires all three parties, and the relay cannot forge an upgrade:
/// it may suppress the optional capability and force safe downgrade, but an
/// upgrade needs the authenticated initiator capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseNegotiation {
    /// Lease version echoed by the relay's create response, if any.
    pub relay_lease_version: Option<u16>,
    /// The authenticated initiator capability, if one was posted and verified.
    pub capability: Option<LeaseCapability>,
}

impl LeaseNegotiation {
    /// No lease at all (legacy joiner, legacy initiator, or legacy relay).
    pub const fn none() -> Self {
        Self { relay_lease_version: None, capability: None }
    }

    /// The negotiated lease version, present only when every edge agrees.
    pub fn negotiated_version(&self) -> Option<u16> {
        let relay = self.relay_lease_version?;
        let capability = self.capability?;
        if relay == LEASE_VERSION_V1 && capability.lease_version() == Some(LEASE_VERSION_V1) {
            Some(LEASE_VERSION_V1)
        } else {
            None
        }
    }

    /// Whether all three parties negotiated lease v1.
    pub fn is_v1(&self) -> bool {
        self.negotiated_version() == Some(LEASE_VERSION_V1)
    }

    /// Why the lease is unavailable. Only meaningful when [`Self::is_v1`] is
    /// false; absence at any edge means fixed-TTL pairing.
    pub fn unavailable_reason(&self) -> LeaseUnavailableReason {
        match self.relay_lease_version {
            None => LeaseUnavailableReason::RelayNotLeaseCapable,
            Some(_) => match self.capability {
                None => LeaseUnavailableReason::CapabilityAbsent,
                Some(capability) if capability.lease_version().is_none() => {
                    LeaseUnavailableReason::VersionUnsupported
                }
                Some(_) => LeaseUnavailableReason::VersionUnsupported,
            },
        }
    }
}

/// Result of the confirmation half of the split initiator ceremony.
///
/// Holds only in-memory, zeroized secret-bearing state. Process-death
/// durability is explicitly out of scope.
///
/// `Debug` is deliberately **not** derived. This type carries the negotiated
/// `pairing_lease_secret`, so a derived `Debug` would print raw secret bytes
/// through any transitive `{:?}` — a log line, a panic payload, a failed test
/// assertion. [`fmt::Debug`] is implemented manually below and reduces the
/// secret to a presence marker. `Zeroizing` bounds the *stored* bytes' lifetime;
/// it does not stop a formatter from copying them into a rendered string first.
pub struct VerifiedInitiatorState {
    /// Hex rendezvous ID.
    pub rendezvous_id_hex: String,
    /// Transcript hash binding the ceremony.
    pub transcript_hash: [u8; 32],
    /// The authenticated initiator capability, when lease v1 was negotiated.
    pub capability: Option<LeaseCapability>,
    /// Why the lease was unavailable, when it was.
    pub unavailable_reason: Option<LeaseUnavailableReason>,
    /// The negotiated lease secret, when lease v1 was negotiated.
    secret: Option<Zeroizing<[u8; LEASE_SECRET_LEN]>>,
}

/// Redacted [`std::fmt::Debug`]: the lease secret is never rendered, in raw or
/// formatted form (see the type-level note above).
impl std::fmt::Debug for VerifiedInitiatorState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedInitiatorState")
            .field("rendezvous_id_hex", &self.rendezvous_id_hex)
            .field("transcript_hash", &self.transcript_hash)
            .field("capability", &self.capability)
            .field("unavailable_reason", &self.unavailable_reason)
            .field("lease_secret", &self.secret.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl VerifiedInitiatorState {
    /// No-lease state: legacy or downgraded fixed-TTL ceremony.
    pub fn fixed_ttl(
        rendezvous_id_hex: String,
        transcript_hash: [u8; 32],
        reason: LeaseUnavailableReason,
    ) -> Self {
        Self {
            rendezvous_id_hex,
            transcript_hash,
            capability: None,
            unavailable_reason: Some(reason),
            secret: None,
        }
    }

    /// Lease-capable state carrying the negotiated secret.
    pub fn leased(
        rendezvous_id_hex: String,
        transcript_hash: [u8; 32],
        capability: LeaseCapability,
        secret: Zeroizing<[u8; LEASE_SECRET_LEN]>,
    ) -> Self {
        Self {
            rendezvous_id_hex,
            transcript_hash,
            capability: Some(capability),
            unavailable_reason: None,
            secret: Some(secret),
        }
    }

    /// Whether lease v1 was negotiated by all three parties.
    pub fn is_lease_capable(&self) -> bool {
        self.secret.is_some()
    }

    /// The lease secret, when negotiated.
    pub fn lease_secret(&self) -> Option<&[u8; LEASE_SECRET_LEN]> {
        self.secret.as_deref()
    }
}

/// Progress/final renewal contract for a verified, lease-capable ceremony.
///
/// This is the hook surface a later resumable uploader (or the app/FFI layer)
/// drives. It deliberately owns no upload state and holds no bytes: it records
/// only what the privacy policy needs (last renewal time, last offset that
/// earned a renewal) so a renew failure can never be reported as an extension.
///
/// Like [`VerifiedInitiatorState`], `Debug` is deliberately **not** derived:
/// this handle carries the same `pairing_lease_secret`, so the manual
/// implementation below never renders it in raw or formatted form.
pub struct PairingLeaseHandle {
    secret: Option<Zeroizing<[u8; LEASE_SECRET_LEN]>>,
    rendezvous_id_hex: String,
    last_renewal: Option<Instant>,
    last_renewed_offset: Option<u64>,
    last_outcome: LeaseRenewalOutcome,
}

/// Redacted [`std::fmt::Debug`]: the lease secret is never rendered, in raw or
/// formatted form (see the type-level note above).
impl std::fmt::Debug for PairingLeaseHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairingLeaseHandle")
            .field("rendezvous_id_hex", &self.rendezvous_id_hex)
            .field("lease_secret", &self.secret.as_ref().map(|_| "<redacted>"))
            .field("last_renewal", &self.last_renewal)
            .field("last_renewed_offset", &self.last_renewed_offset)
            .field("last_outcome", &self.last_outcome)
            .finish()
    }
}

impl PairingLeaseHandle {
    /// Build a handle from verified ceremony state.
    pub fn new(state: &VerifiedInitiatorState) -> Self {
        Self {
            secret: state.secret.as_ref().map(|s| Zeroizing::new(**s)),
            rendezvous_id_hex: state.rendezvous_id_hex.clone(),
            last_renewal: None,
            last_renewed_offset: None,
            last_outcome: if state.is_lease_capable() {
                // Set by the initial renewal; until then no attempt has run.
                LeaseRenewalOutcome::Unavailable
            } else {
                LeaseRenewalOutcome::LeaseNotNegotiated
            },
        }
    }

    /// Whether this handle can renew at all.
    pub fn is_lease_capable(&self) -> bool {
        self.secret.is_some()
    }

    /// Hex rendezvous ID this handle renews.
    pub fn rendezvous_id_hex(&self) -> &str {
        &self.rendezvous_id_hex
    }

    /// Most recent renewal outcome.
    pub fn last_outcome(&self) -> LeaseRenewalOutcome {
        self.last_outcome
    }

    /// Whether the lease is permanently unusable for this ceremony.
    pub fn is_terminal(&self) -> bool {
        self.last_outcome.is_terminal()
    }

    /// Whether a progress-driven renewal is due for `committed_offset`.
    pub fn should_renew_for_progress(&self, committed_offset: u64, now: Instant) -> bool {
        self.is_lease_capable()
            && !self.is_terminal()
            && should_renew_for_progress(
                self.last_renewal,
                self.last_renewed_offset,
                committed_offset,
                now,
            )
    }

    /// Record the outcome of the split ceremony's initial renewal.
    ///
    /// The initial renewal is exempt from the progress/coalescing policy, so
    /// this must not be reachable through [`Self::should_renew_for_progress`]
    /// alone. It records only what happened: a failure never claims extension.
    pub fn record_initial_renewal(&mut self, outcome: LeaseRenewalOutcome, now: Instant) {
        self.last_outcome = outcome;
        if outcome.is_renewed() {
            self.last_renewal = Some(now);
        }
    }

    /// Perform one renewal and record its outcome.
    ///
    /// `offset` is `None` for the initial and final renewals, which are exempt
    /// from the coalescing interval by design.
    pub async fn renew(
        &mut self,
        relay: &dyn PairingRelay,
        offset: Option<u64>,
        now: Instant,
    ) -> LeaseRenewalOutcome {
        let Some(secret) = self.secret.as_ref().map(|s| **s) else {
            self.last_outcome = LeaseRenewalOutcome::LeaseNotNegotiated;
            return self.last_outcome;
        };
        if self.is_terminal() {
            return self.last_outcome;
        }

        let outcome = renew_pairing_lease(relay, &self.rendezvous_id_hex, &secret).await;
        self.last_outcome = outcome;
        if outcome.is_renewed() {
            self.last_renewal = Some(now);
            if let Some(offset) = offset {
                self.last_renewed_offset = Some(offset);
            }
        }
        outcome
    }
}

/// One renewal attempt over the opaque lease endpoint.
///
/// A lost success response is harmless because renewal is idempotent. Every
/// failure is nonfatal.
pub async fn renew_pairing_lease(
    relay: &dyn PairingRelay,
    rendezvous_id_hex: &str,
    lease_secret: &[u8; LEASE_SECRET_LEN],
) -> LeaseRenewalOutcome {
    match relay.renew_lease(rendezvous_id_hex, lease_secret).await {
        Ok(()) => LeaseRenewalOutcome::Renewed,
        Err(e) if is_uniform_not_found(&e) => LeaseRenewalOutcome::TerminalNotFound,
        Err(_) => LeaseRenewalOutcome::Unavailable,
    }
}

// ── Uploader bridge ──────────────────────────────────────────────────────────

/// Drives a [`PairingLeaseHandle`] from the resumable uploader's progress
/// signal.
///
/// This is the wiring that keeps the privacy rule intact: the uploader hands
/// over an acknowledged committed offset and nothing else, and this adapter
/// decides — using the shared coalescing policy — whether that offset earned a
/// renewal. The relay therefore never learns which upload is related to a
/// ceremony, whether the transfer is progressing, or how much is left.
///
/// Renewal failures are recorded on the handle and never surfaced: a lease
/// failure is nonfatal by design, and the ceremony continues under whatever
/// expiry is already in force.
pub struct UploadProgressLeaseRenewer<'a> {
    handle: &'a mut PairingLeaseHandle,
    relay: &'a dyn PairingRelay,
}

impl<'a> UploadProgressLeaseRenewer<'a> {
    /// Adapter over a lease handle and the pairing relay that renews it.
    pub fn new(handle: &'a mut PairingLeaseHandle, relay: &'a dyn PairingRelay) -> Self {
        Self { handle, relay }
    }

    /// The most recent renewal outcome observed through this adapter.
    pub fn last_outcome(&self) -> LeaseRenewalOutcome {
        self.handle.last_outcome()
    }

    /// Whether the lease is permanently unusable for this ceremony.
    pub fn is_terminal(&self) -> bool {
        self.handle.is_terminal()
    }
}

#[async_trait::async_trait]
impl crate::snapshot_upload::SnapshotUploadProgressHook for UploadProgressLeaseRenewer<'_> {
    async fn on_committed_offset_advanced(&mut self, committed_offset: u64) {
        // Offset zero is never progress, whichever side is enforcing it. The
        // uploader already never reports it; refusing it here too makes the
        // rule a property of the adapter rather than of one caller.
        if committed_offset == 0 {
            return;
        }
        let now = Instant::now();
        // Delegates the whole policy — strictly increased offset, not terminal,
        // five-minute coalescing — to the handle, so the uploader cannot widen
        // it by reporting more often.
        if !self.handle.should_renew_for_progress(committed_offset, now) {
            return;
        }
        // A failure is recorded on the handle; it is never an upload failure.
        let _ = self.handle.renew(self.relay, Some(committed_offset), now).await;
    }
}

/// Whether an error is the relay's uniform not-found response.
///
/// The relay deliberately returns the same not-found for unknown, expired,
/// unsupported, wrong-secret, pre-confirmation, consumed, and saturated
/// sessions so the endpoint is not a state oracle.
pub fn is_uniform_not_found(error: &RelayError) -> bool {
    matches!(error, RelayError::NotFound)
        || matches!(error, RelayError::Protocol { message } if message.contains("session not found"))
        || matches!(error, RelayError::Protocol { message } if message.contains("not found"))
}

// ── Lease-aware slot waiting ─────────────────────────────────────────────────

/// Wait for a pairing slot using lease-aware bounded exponential backoff.
///
/// Ends early on the relay's uniform not-found: a lease-aware wait must not
/// spin for four hours against a rendezvous that no longer exists. Legacy
/// non-lease ceremonies keep using the fixed-cadence wait.
pub async fn wait_for_pairing_slot_bytes_with_backoff(
    relay: &dyn PairingRelay,
    rendezvous_id: &str,
    slot: PairingSlot,
    description: &str,
    backoff: LeasePollBackoff,
) -> Result<Vec<u8>> {
    // Continuous relay failures still fail fast; only empty slots are
    // human/upload paced.
    const MAX_CONSECUTIVE_TRANSIENT: u32 = 20;

    let mut backoff = backoff;
    let mut consecutive_transient = 0u32;
    let mut attempt: u64 = 0;

    loop {
        match relay.get_slot(rendezvous_id, slot).await {
            Ok(Some(bytes)) => return Ok(bytes),
            Ok(None) => {
                consecutive_transient = 0;
            }
            Err(e) if is_uniform_not_found(&e) => {
                return Err(CoreError::from_relay_with_context(Some(description), e));
            }
            Err(e) if e.is_retryable() => {
                consecutive_transient += 1;
                if consecutive_transient >= MAX_CONSECUTIVE_TRANSIENT {
                    return Err(CoreError::from_relay_with_context(Some(description), e));
                }
            }
            Err(e) => return Err(CoreError::from_relay_with_context(Some(description), e)),
        }

        if backoff.is_exhausted() {
            return Err(CoreError::Engine(format!(
                "timed out waiting for {description} after {}s",
                backoff.deadline().as_secs()
            )));
        }

        let delay = backoff.next_delay();
        // Deterministic jitter without a rand dependency in the wait loop;
        // `attempt` supplies cheap, process-local entropy.
        let entropy =
            attempt.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(rendezvous_id.len() as u64);
        let jittered = delay + LeasePollBackoff::jitter(delay, entropy);
        tokio::time::sleep(jittered).await;
        backoff.advance(jittered);
        attempt = attempt.wrapping_add(1);
    }
}

/// Wait for a pairing slot under an explicit [`SlotWaitPolicy`].
///
/// This is the single production entry point for the terminal slot waits whose
/// duration is dictated by user-paced work (a snapshot upload or a joiner
/// import). The lease-aware arm reuses
/// [`wait_for_pairing_slot_bytes_with_backoff`]; the legacy arm reuses the
/// caller's existing fixed-cadence wait, so a ceremony that did not
/// cryptographically negotiate lease v1 keeps byte-identical timing and error
/// behavior.
pub async fn wait_for_pairing_slot_with_policy<Legacy, LegacyFut>(
    relay: &dyn PairingRelay,
    rendezvous_id: &str,
    slot: PairingSlot,
    description: &str,
    policy: SlotWaitPolicy,
    legacy_wait: Legacy,
) -> Result<Vec<u8>>
where
    Legacy: FnOnce() -> LegacyFut,
    LegacyFut: std::future::Future<Output = Result<Vec<u8>>>,
{
    match policy.backoff() {
        Some(backoff) => {
            wait_for_pairing_slot_bytes_with_backoff(
                relay,
                rendezvous_id,
                slot,
                description,
                backoff,
            )
            .await
        }
        None => legacy_wait().await,
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap::{BootstrapProfile, BootstrapVersion, DefaultBootstrapHandshake};
    use prism_sync_crypto::pq::hybrid_kem::XWingKem;
    use prism_sync_crypto::DeviceSecret;

    fn rng() -> getrandom::rand_core::UnwrapErr<getrandom::SysRng> {
        getrandom::rand_core::UnwrapErr(getrandom::SysRng)
    }

    /// Deterministic mirrored key schedules (both sides agree).
    fn key_schedule_pair(seed: u8) -> (BootstrapKeySchedule, BootstrapKeySchedule, [u8; 32]) {
        let dk = XWingKem::decapsulation_key_from_bytes(&[seed; 32]);
        let ek_bytes = XWingKem::encapsulation_key_bytes(&dk);
        let (ct, _) =
            DefaultBootstrapHandshake::encapsulate_to_peer(&ek_bytes, &mut rng()).unwrap();
        let s1 = DefaultBootstrapHandshake::decapsulate_from_peer(&dk, &ct).unwrap();
        let s2 = DefaultBootstrapHandshake::decapsulate_from_peer(&dk, &ct).unwrap();
        let th = [seed; 32];
        (
            BootstrapKeySchedule::derive(
                BootstrapProfile::SyncPairing,
                BootstrapVersion::V1,
                s1,
                &th,
            )
            .unwrap(),
            BootstrapKeySchedule::derive(
                BootstrapProfile::SyncPairing,
                BootstrapVersion::V1,
                s2,
                &th,
            )
            .unwrap(),
            th,
        )
    }

    const RID: [u8; 16] = [0x42; 16];

    // ── Capability framing ───────────────────────────────────────────────

    #[test]
    fn capability_inner_frame_layout_is_stable() {
        let frame = LeaseCapability::v1().inner_frame();
        assert_eq!(frame, vec![0x01, 0x01, 0x00, 0x01, 0x00, 0x06]);
        assert_eq!(frame.len(), 6);
    }

    #[test]
    fn capability_inner_frame_round_trip() {
        for capability in [LeaseCapability::v1(), LeaseCapability::declined()] {
            let frame = capability.inner_frame();
            assert_eq!(LeaseCapability::from_inner_frame(&frame), Some(capability));
        }
    }

    #[test]
    fn capability_inner_frame_rejects_trailing_bytes() {
        // Appending a byte must not be silently accepted: the joiner hashes
        // this exact frame into its verifier.
        let mut frame = LeaseCapability::v1().inner_frame();
        frame.push(0x00);
        assert_eq!(LeaseCapability::from_inner_frame(&frame), None);
    }

    #[test]
    fn capability_inner_frame_rejects_unknown_version_and_flags() {
        let mut frame = LeaseCapability::v1().inner_frame();
        frame[0] = 0x02;
        assert_eq!(LeaseCapability::from_inner_frame(&frame), None);

        let mut frame = LeaseCapability::v1().inner_frame();
        frame[1] = 0x80;
        assert_eq!(LeaseCapability::from_inner_frame(&frame), None);
    }

    #[test]
    fn capability_inner_frame_rejects_declared_length_mismatch() {
        let mut frame = LeaseCapability::v1().inner_frame();
        frame[4] = 0x00;
        frame[5] = 0x07;
        assert_eq!(LeaseCapability::from_inner_frame(&frame), None);
    }

    #[test]
    fn capability_frame_round_trip_and_transcript_binding() {
        let (ks, _, th) = key_schedule_pair(9);
        let capability = LeaseCapability::v1();
        let frame = LeaseCapabilityFrame::seal(&ks, &RID, &th, &capability);
        let wire = frame.to_bytes();

        let opened = LeaseCapabilityFrame::open(&ks, &RID, &th, wire)
            .expect("valid capability must authenticate");
        assert_eq!(opened.capability, capability);
        assert_eq!(opened.inner, capability.inner_frame());

        // A different transcript must not verify.
        let mut other_th = th;
        other_th[0] ^= 0xFF;
        assert!(LeaseCapabilityFrame::open(&ks, &RID, &other_th, wire).is_none());

        // A different rendezvous must not verify.
        let mut other_rid = RID;
        other_rid[0] ^= 0xFF;
        assert!(LeaseCapabilityFrame::open(&ks, &other_rid, &th, wire).is_none());
    }

    #[test]
    fn capability_frame_rejects_tampering_and_wrong_key() {
        let (ks, _, th) = key_schedule_pair(3);
        let frame = LeaseCapabilityFrame::seal(&ks, &RID, &th, &LeaseCapability::v1());
        let wire = frame.to_bytes();

        // Flip the inner capability body.
        let mut tampered = wire.to_vec();
        tampered[51] ^= 0x01;
        assert!(LeaseCapabilityFrame::open(&ks, &RID, &th, &tampered).is_none());

        // Flip a MAC byte.
        let mut tampered = wire.to_vec();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xFF;
        assert!(LeaseCapabilityFrame::open(&ks, &RID, &th, &tampered).is_none());

        // Truncate.
        assert!(LeaseCapabilityFrame::open(&ks, &RID, &th, &wire[..wire.len() - 1]).is_none());

        // A different session's keys must not authenticate the frame.
        let (other_ks, _, _) = key_schedule_pair(4);
        assert!(LeaseCapabilityFrame::open(&other_ks, &RID, &th, wire).is_none());
    }

    #[test]
    fn capability_frame_binds_the_negotiated_version() {
        // The extended confirmation can only be opened with the exact
        // authenticated capability, so the initiator's posted frame is bound.
        let (ks, _, th) = key_schedule_pair(21);
        let capability = LeaseCapability::v1();
        let frame = LeaseCapabilityFrame::seal(&ks, &RID, &th, &capability);
        let wire = frame.to_bytes();
        let opened = LeaseCapabilityFrame::open(&ks, &RID, &th, wire).unwrap();
        assert_eq!(opened.inner, capability.inner_frame());
    }

    #[test]
    fn lease_key_hash_is_sha256_of_the_secret() {
        let secret = [0x2Bu8; LEASE_SECRET_LEN];
        let expected: [u8; 32] = Sha256::digest(secret).into();
        assert_eq!(compute_lease_key_hash(&secret), expected);
        assert_eq!(compute_lease_key_hash(&secret).len(), 32);
        // Different secrets must not collide to the same verifier.
        assert_ne!(compute_lease_key_hash(&secret), compute_lease_key_hash(&[0x2Cu8; 32]));
    }

    // ── Extended confirmation framing ────────────────────────────────────

    #[test]
    fn legacy_and_extended_confirmation_frames_are_length_disjoint() {
        let (ks, _, th) = key_schedule_pair(5);
        let secret = [0x11u8; LEASE_SECRET_LEN];
        let inner = LeaseCapability::v1().inner_frame();
        let extended = seal_extended_confirmation(&ks, &RID, &th, &inner, &secret).unwrap();

        assert_eq!(
            classify_confirmation_frame(&[0u8; 32]),
            Some(ConfirmationFrame::LegacyMac([0u8; 32]))
        );
        assert!(extended.len() > LEGACY_CONFIRMATION_MAC_LEN);
        assert_eq!(
            classify_confirmation_frame(&extended),
            Some(ConfirmationFrame::LeaseV1(extended.clone()))
        );
        // A 31- or 33-byte frame matches neither framing.
        assert_eq!(classify_confirmation_frame(&[0u8; 31]), None);
        let mut odd = vec![0u8; 33];
        odd[0] = 0x02;
        assert_eq!(classify_confirmation_frame(&odd), None);
    }

    #[test]
    fn extended_confirmation_round_trip() {
        let (ks, _, th) = key_schedule_pair(7);
        let inner = LeaseCapability::v1().inner_frame();
        let secret = [0x5Au8; LEASE_SECRET_LEN];
        let frame = seal_extended_confirmation(&ks, &RID, &th, &inner, &secret).unwrap();

        let opened = open_extended_confirmation(&ks, &RID, &th, &inner, &frame).unwrap();
        assert_eq!(*opened, secret);
    }

    #[test]
    fn extended_confirmation_rejects_wrong_key() {
        let (ks, _, th) = key_schedule_pair(7);
        let (other_ks, _, _) = key_schedule_pair(8);
        let inner = LeaseCapability::v1().inner_frame();
        let frame = seal_extended_confirmation(&ks, &RID, &th, &inner, &[0x5Au8; 32]).unwrap();

        assert!(open_extended_confirmation(&other_ks, &RID, &th, &inner, &frame).is_err());
    }

    #[test]
    fn extended_confirmation_rejects_wrong_transcript_and_capability() {
        let (ks, _, th) = key_schedule_pair(7);
        let inner = LeaseCapability::v1().inner_frame();
        let frame = seal_extended_confirmation(&ks, &RID, &th, &inner, &[0x5Au8; 32]).unwrap();

        let mut other_th = th;
        other_th[0] ^= 0xFF;
        assert!(open_extended_confirmation(&ks, &RID, &other_th, &inner, &frame).is_err());

        // A different authenticated capability must not unlock the secret: this
        // is what stops a rendezvous-ID holder from downgrading or swapping the
        // negotiated version.
        let declined = LeaseCapability::declined().inner_frame();
        assert!(open_extended_confirmation(&ks, &RID, &th, &declined, &frame).is_err());
    }

    #[test]
    fn extended_confirmation_rejects_tampering_and_wrong_session() {
        let (ks, _, th) = key_schedule_pair(7);
        let inner = LeaseCapability::v1().inner_frame();
        let mut frame = seal_extended_confirmation(&ks, &RID, &th, &inner, &[0x5Au8; 32]).unwrap();

        let last = frame.len() - 1;
        frame[last] ^= 0xFF;
        assert!(open_extended_confirmation(&ks, &RID, &th, &inner, &frame).is_err());

        let mut other_rid = RID;
        other_rid[1] ^= 0xFF;
        let good = seal_extended_confirmation(&ks, &RID, &th, &inner, &[0x5Au8; 32]).unwrap();
        assert!(open_extended_confirmation(&ks, &other_rid, &th, &inner, &good).is_err());
    }

    #[test]
    fn extended_confirmation_rejects_wrong_secret_length() {
        let (ks, _, th) = key_schedule_pair(7);
        let inner = LeaseCapability::v1().inner_frame();
        // Seal a 31-byte payload through the same key/AAD path to prove the
        // length gate is enforced after successful authentication.
        let key =
            bind_capability_into_key(ks.encryption_key(BootstrapRole::Responder), &inner, &th)
                .unwrap();
        let context = EnvelopeContext {
            profile: BootstrapProfile::SyncPairing,
            version: BootstrapVersion::V1,
            sender_role: BootstrapRole::Responder,
            purpose: LEASE_SECRET_PURPOSE,
            session_id: &RID,
            transcript_hash: &th,
        };
        let frame = EncryptedEnvelope::seal(&key, &[0u8; 31], &context).unwrap();

        let err = open_extended_confirmation(&ks, &RID, &th, &inner, &frame)
            .expect_err("wrong secret length must be rejected");
        assert!(err.to_string().contains("wrong length"), "got: {err}");
    }

    #[test]
    fn extended_confirmation_aad_binds_capability_and_transcript() {
        let inner = LeaseCapability::v1().inner_frame();
        let aad = extended_confirmation_aad(&RID, &[0xAB; 32], &inner);
        // Layout: prefix(24B) + 0x00 + profile + version + role, then purpose.
        assert!(aad.starts_with(b"PRISM_BOOTSTRAP_ENVELOPE\x00"));
        assert_eq!(aad[24], 0x00);
        assert_eq!(aad[25], BootstrapProfile::SyncPairing.as_byte());
        assert_eq!(aad[26], BootstrapVersion::V1.as_byte());
        assert_eq!(aad[27], BootstrapRole::Responder.as_byte());
        assert!(aad.ends_with(&inner));
    }

    // ── Renewal policy ───────────────────────────────────────────────────

    #[test]
    fn progress_renewal_requires_a_strictly_larger_offset() {
        let now = Instant::now();
        // First progress renewal: allowed.
        assert!(should_renew_for_progress(None, None, 8 * 1024 * 1024, now));
        // Same offset: no renewal.
        assert!(!should_renew_for_progress(Some(now), Some(8 * 1024 * 1024), 8 * 1024 * 1024, now));
        // Smaller offset: no renewal.
        assert!(!should_renew_for_progress(Some(now), Some(8 * 1024 * 1024), 0, now));
        // Larger offset but inside the coalescing window: no renewal.
        assert!(!should_renew_for_progress(
            Some(now),
            Some(8 * 1024 * 1024),
            16 * 1024 * 1024,
            now
        ));
        // Larger offset after the window: renewal.
        assert!(should_renew_for_progress(
            Some(now),
            Some(8 * 1024 * 1024),
            16 * 1024 * 1024,
            now + Duration::from_secs(LEASE_RENEWAL_COALESCE_SECS)
        ));
    }

    #[test]
    fn progress_renewal_forbidden_without_new_bytes() {
        let now = Instant::now();
        let past = now + Duration::from_secs(LEASE_RENEWAL_COALESCE_SECS * 2);
        // Duplicate acknowledgment after the window still must not renew.
        assert!(!should_renew_for_progress(Some(now), Some(1024), 1024, past));
    }

    #[test]
    fn lease_handle_never_reports_extension_without_success() {
        let state = VerifiedInitiatorState::leased(
            "ab".repeat(16),
            [0u8; 32],
            LeaseCapability::v1(),
            Zeroizing::new([0x01u8; 32]),
        );
        let handle = PairingLeaseHandle::new(&state);
        assert!(handle.is_lease_capable());
        // No renewal has run yet, so nothing claims extension.
        assert!(!handle.last_outcome().is_renewed());
        assert!(!handle.is_terminal());
    }

    #[test]
    fn lease_handle_for_fixed_ttl_state_is_not_capable() {
        let state = VerifiedInitiatorState::fixed_ttl(
            "cd".repeat(16),
            [0u8; 32],
            LeaseUnavailableReason::RelayNotLeaseCapable,
        );
        let handle = PairingLeaseHandle::new(&state);
        assert!(!handle.is_lease_capable());
        assert_eq!(handle.last_outcome(), LeaseRenewalOutcome::LeaseNotNegotiated);
        // A fixed-TTL ceremony must never schedule a renewal.
        assert!(!handle.should_renew_for_progress(u64::MAX, Instant::now()));
    }

    #[test]
    fn uniform_not_found_classification_matches_both_shapes() {
        assert!(is_uniform_not_found(&RelayError::NotFound));
        assert!(is_uniform_not_found(&RelayError::Protocol {
            message: "session not found".into()
        }));
        assert!(!is_uniform_not_found(&RelayError::Network { message: "reset".into() }));
        assert!(!is_uniform_not_found(&RelayError::Timeout { message: "slow".into() }));
    }

    // ── Backoff ──────────────────────────────────────────────────────────

    #[test]
    fn backoff_is_exponential_bounded_and_jittered() {
        let mut backoff = LeasePollBackoff::new(Duration::from_secs(600));
        assert_eq!(backoff.next_delay(), Duration::from_millis(250));
        backoff.advance(Duration::from_millis(250));
        assert_eq!(backoff.next_delay(), Duration::from_millis(500));
        backoff.advance(Duration::from_millis(500));
        assert_eq!(backoff.next_delay(), Duration::from_millis(1000));

        // Grows to the cap and never past it.
        let mut backoff = LeasePollBackoff::for_absolute_cap();
        for _ in 0..40 {
            backoff.advance(backoff.next_delay());
        }
        assert_eq!(backoff.next_delay(), Duration::from_secs(30));
        assert_eq!(backoff.deadline(), Duration::from_secs(LEASE_ABSOLUTE_CAP_SECS));
    }

    #[test]
    fn backoff_jitter_stays_within_half_the_delay() {
        for entropy in [0u64, 1, 7, 12345, u64::MAX] {
            let delay = Duration::from_millis(1000);
            let jitter = LeasePollBackoff::jitter(delay, entropy);
            assert!(jitter <= delay / 2, "jitter {jitter:?} exceeded half of {delay:?}");
        }
        assert_eq!(LeasePollBackoff::jitter(Duration::ZERO, 5), Duration::ZERO);
    }

    #[test]
    fn legacy_deadline_backoff_preserves_existing_budget() {
        let backoff = LeasePollBackoff::for_legacy_deadline();
        assert_eq!(backoff.deadline(), Duration::from_secs(300));
        assert!(!backoff.is_exhausted());
    }

    #[test]
    fn backoff_exhausts_at_its_budget() {
        let mut backoff = LeasePollBackoff::new(Duration::from_secs(1));
        assert!(!backoff.is_exhausted());
        backoff.advance(Duration::from_secs(1));
        assert!(backoff.is_exhausted());
        assert_eq!(backoff.next_delay(), Duration::ZERO);
    }

    // ── Slot-wait policy selection ───────────────────────────────────────

    #[test]
    fn slot_wait_policy_follows_authenticated_negotiation_only() {
        // Authenticated lease v1 negotiation: the wait may span the absolute cap.
        let negotiated = pairing_slot_wait_policy(true);
        assert!(negotiated.is_lease_aware());
        assert_eq!(negotiated.deadline(), Duration::from_secs(LEASE_ABSOLUTE_CAP_SECS));

        // Anything else — legacy relay, legacy peer, absent or invalid
        // capability, a downgraded relay — keeps the exact legacy budget.
        let legacy = pairing_slot_wait_policy(false);
        assert!(!legacy.is_lease_aware());
        assert_eq!(legacy, SlotWaitPolicy::Legacy);
        assert!(legacy.backoff().is_none());
    }

    #[test]
    fn legacy_slot_wait_policy_matches_the_fixed_cadence_budget() {
        // The legacy deadline must be the product of the fixed wait's own
        // pacing constants (1200 attempts × 250 ms), so preserving behavior is a
        // property of the constants and not of a duplicated magic number.
        assert_eq!(LEGACY_SLOT_WAIT_DEADLINE, Duration::from_millis(250 * 1_200));
        assert_eq!(SlotWaitPolicy::legacy().deadline(), LEGACY_SLOT_WAIT_DEADLINE);
        // Lease support must never leave the legacy budget untouched-but-wider.
        assert!(
            SlotWaitPolicy::legacy().deadline() < SlotWaitPolicy::lease_aware().deadline(),
            "the legacy budget must stay strictly below the lease absolute cap"
        );
    }

    #[test]
    fn lease_aware_policy_carries_the_absolute_cap_backoff() {
        let policy = SlotWaitPolicy::lease_aware();
        let backoff = policy.backoff().expect("lease-aware policy carries a backoff");
        assert_eq!(backoff, LeasePollBackoff::for_absolute_cap());
        assert_eq!(backoff.deadline(), Duration::from_secs(LEASE_ABSOLUTE_CAP_SECS));
    }

    // ── Constants ────────────────────────────────────────────────────────

    #[test]
    fn lease_constants_match_the_v1_profile() {
        assert_eq!(LEASE_VERSION_V1, 1);
        assert_eq!(LEASE_FRAME_VERSION, 0x01);
        assert_eq!(LEGACY_CONFIRMATION_MAC_LEN, 32);
        assert_eq!(LEASE_SECRET_LEN, 32);
        assert_eq!(LEASE_IDLE_EXTENSION_SECS, 1800);
        assert_eq!(LEASE_ABSOLUTE_CAP_SECS, 14400);
        assert_eq!(LEASE_RENEWAL_COALESCE_SECS, 300);
        assert_eq!(LEASE_MAX_CONCURRENT_LEASED_SESSIONS, 256);
        // The renewal route's exact body limit is the raw secret length.
        assert_eq!(LEASE_RENEW_REQUEST_BODY_LEN, LEASE_SECRET_LEN);
    }

    #[test]
    fn lease_secret_is_not_derived_from_ceremony_material() {
        // The secret is caller-supplied randomness; this asserts the API shape
        // (32 raw bytes in, 32 raw bytes out) rather than a derivation.
        let secret = [0xC3u8; LEASE_SECRET_LEN];
        let (ks, _, th) = key_schedule_pair(11);
        let inner = LeaseCapability::v1().inner_frame();
        let frame = seal_extended_confirmation(&ks, &RID, &th, &inner, &secret).unwrap();
        let opened = open_extended_confirmation(&ks, &RID, &th, &inner, &frame).unwrap();
        assert_eq!(opened.as_slice(), secret.as_slice());
        // It is neither the transcript nor the confirmation key.
        assert_ne!(opened.as_slice(), th.as_slice());
        assert_ne!(opened.as_slice(), ks.confirmation_key());
    }

    #[tokio::test]
    async fn lease_secret_never_reaches_the_capability_frame() {
        // The capability slot is public to the relay; the secret must not be in it.
        let (ks, _, th) = key_schedule_pair(13);
        let secret = [0x77u8; LEASE_SECRET_LEN];
        let frame = LeaseCapabilityFrame::seal(&ks, &RID, &th, &LeaseCapability::v1());
        let wire = frame.to_bytes();
        assert!(
            !wire.windows(LEASE_SECRET_LEN).any(|w| w == secret.as_slice()),
            "capability slot must never carry the raw lease secret"
        );
        // And the joiner's verifier is not the secret itself.
        assert_ne!(compute_lease_key_hash(&secret), secret);
    }

    #[test]
    fn device_secret_is_unused_by_lease_framing() {
        // Guard against accidental device/sync linkage: framing depends only on
        // the transcript-bound bootstrap key schedule.
        let _ = DeviceSecret::generate();
        let (ks, _, th) = key_schedule_pair(17);
        let frame = LeaseCapabilityFrame::seal(&ks, &RID, &th, &LeaseCapability::v1());
        let a = frame.to_bytes().to_vec();
        let frame_again = LeaseCapabilityFrame::seal(&ks, &RID, &th, &LeaseCapability::v1());
        let b = frame_again.to_bytes().to_vec();
        assert_eq!(a, b, "framing must be a pure function of session keys and capability");
    }

    // ── Secret redaction ─────────────────────────────────────────────────

    #[test]
    fn secret_bearing_types_never_render_the_lease_secret_in_debug() {
        // Both types hand-write `Debug` rather than deriving it. A derived impl
        // would print the raw secret bytes, which leaks through any transitive
        // `{:?}` — a log line, a panic payload, a failed test assertion. This pins
        // the redaction so a future `#[derive(Debug)]` regression fails here.
        let secret_bytes = [0xABu8; LEASE_SECRET_LEN];
        let state = VerifiedInitiatorState::leased(
            "00112233445566778899aabbccddeeff".to_string(),
            [0x5Au8; 32],
            LeaseCapability::v1(),
            Zeroizing::new(secret_bytes),
        );
        let handle = PairingLeaseHandle::new(&state);

        let rendered = format!("{state:?} {handle:?}");
        assert!(
            rendered.contains("<redacted>"),
            "the redaction marker must be present: {rendered}"
        );

        // The secret must not appear in the two forms a derived Debug would use:
        // lowercase hex, and the brace-less byte-array list.
        let hex_secret = hex::encode(secret_bytes);
        assert!(
            !rendered.contains(&hex_secret),
            "Debug must never render the secret as hex: {rendered}"
        );
        let byte_list = format!("{secret_bytes:?}");
        assert!(
            !rendered.contains(byte_list.trim_matches(['[', ']'])),
            "Debug must never render the secret as a byte list: {rendered}"
        );

        // The un-redacted fields are still useful for diagnostics.
        assert!(rendered.contains("00112233445566778899aabbccddeeff"));
    }
}
