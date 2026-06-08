//! Ephemeral signal lane (media re-supply C3): crypto for the relay-blind
//! store-and-forward mailbox.
//!
//! A device that needs a missing blob (or has just uploaded one) posts a small,
//! fixed-size **opaque** message to the relay's `device_messages` mailbox; peers
//! drain it on their next sync cycle. The relay is **blind** to the message
//! contents — `kind` and `media_id` live inside an AEAD payload encrypted with
//! the group **epoch key**, and the dedup key (`message_id`) is an HMAC keyed by
//! that same epoch key. The relay sees only the routing envelope plus a
//! cleartext `epoch_id` (so a recipient can pick the right key).
//!
//! What relay-blindness buys (and what it doesn't): the relay cannot enumerate
//! *which referenced blobs a device is missing* from the request stream alone —
//! it can't dictionary-correlate the low-entropy / role-derived `media_id`s
//! because it lacks the epoch key. It does **not** make the heal unobservable:
//! the relay still sees the triggered upload + download on the media channel, so
//! timing+size can re-link a request to a concrete `media_id`. That is an
//! accepted threat model (the relay already sees every `media_id` on the media
//! channel); the win is narrow and stated as such.
//!
//! ## Dedup — keyed deterministic `message_id`
//!
//! ```text
//! message_id = HMAC(msgid_key, DOMAIN ‖ sync_id ‖ kind ‖ media_id ‖ epoch_id ‖ ⌊now / window⌋)
//! ```
//!
//! `msgid_key` is an HKDF subkey of the group epoch key (domain-separated from
//! the payload key — standard key separation; the relay possesses neither the
//! epoch key nor any derived key, so the anti-correlation property the spec
//! relies on is fully preserved). Every device in the group derives the same
//! `msgid_key` and computes the same `message_id` for the same request inside a
//! cooldown window, so the relay's composite `PRIMARY KEY(sync_id, message_id)`
//! coalesces in-window duplicates. A window-boundary double-issue is a rare,
//! harmless single duplicate. `sync_id` is folded into the MAC input (and the
//! key differs per group), so the same request in two groups yields distinct
//! ids.
//!
//! ## Epoch rotation
//!
//! The payload is encrypted with the epoch key for `epoch_id` (carried
//! cleartext in the envelope). A recipient on a newer epoch that no longer holds
//! that key — or otherwise can't decrypt — simply **skips + ACKs** the message
//! (advisory, lossy-OK); the requester re-issues under the current epoch on its
//! next tick (a new `message_id`, since `epoch_id` changed). The short mailbox
//! TTL bounds staleness.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::{CoreError, Result};

type HmacSha256 = Hmac<Sha256>;

// ── Domain separation ────────────────────────────────────────────────────────

/// HKDF `info` for the message_id MAC subkey (derived from the epoch key).
const MSGID_SUBKEY_INFO: &[u8] = b"prism_media_ephemeral_msgid_v1";
/// HKDF `info` for the payload AEAD subkey (derived from the epoch key).
const PAYLOAD_SUBKEY_INFO: &[u8] = b"prism_media_ephemeral_payload_v1";
/// Domain separator prefixed to the `message_id` MAC input.
const MSGID_DOMAIN: &[u8] = b"PRISM_MEDIA_EPHEMERAL_MSGID_V1";
/// Domain separator prefixed to the payload AEAD AAD.
const PAYLOAD_AAD_DOMAIN: &[u8] = b"PRISM_MEDIA_EPHEMERAL_PAYLOAD_V1";

// ── Tunables ─────────────────────────────────────────────────────────────────

/// Dedup window granularity (seconds): the same request issued by any device in
/// the group within one window maps to the same `message_id`. Matches the C4
/// requester's per-media cooldown. MUST be identical across all clients in a
/// group or the relay can't coalesce duplicates.
pub const EPHEMERAL_DEDUP_WINDOW_SECS: u64 = 300;

/// Fixed plaintext length (bytes) every ephemeral payload is padded to BEFORE
/// encryption, so the relay can't distinguish `media_request` from
/// `media_uploaded` (or any future kind) by ciphertext length. The ciphertext
/// the relay stores is therefore always `24 (nonce) + PLAINTEXT_LEN + 16 (tag)`
/// bytes regardless of `kind`/`media_id`. 256 comfortably fits a small `kind`
/// plus a `media_id` (≤ 36 chars today) with headroom for future fields.
const PLAINTEXT_LEN: usize = 256;

/// Truncation length (bytes) of the HMAC tag used for `message_id` → 32 hex
/// chars (matches the relay's 32-hex id validation). 128 bits of MAC output is
/// ample collision resistance for a dedup key.
const MESSAGE_ID_BYTES: usize = 16;

/// Upper bound on a `kind` label (defensive; real kinds are short ascii).
const MAX_KIND_LEN: usize = 64;
/// Upper bound on a `media_id` (relay validates ≤ 36; allow headroom).
const MAX_MEDIA_ID_LEN: usize = 128;

// ── Wire / decoded types ─────────────────────────────────────────────────────

/// The relay-facing routing envelope for one ephemeral message. The `payload`
/// is opaque ciphertext; `epoch_id` is the only cleartext crypto hint.
#[derive(Debug, Clone)]
pub struct EphemeralEnvelope {
    /// HMAC-keyed dedup id, 32 lowercase hex chars. Composite PK on the relay.
    pub message_id: String,
    /// Cleartext epoch the payload was sealed under (recipient key selection).
    pub epoch_id: u32,
    /// Sender device id. Set by the relay from the *authenticated* identity on
    /// fetch (so it's a real group member), but **not bound by the payload
    /// AAD** — it is untrusted transport metadata, not cryptographically tied to
    /// the sealed contents. A malicious relay could misattribute it. C4 must NOT
    /// use it for any security decision (e.g. only-respond-to-device-X logic);
    /// fold it into the AAD if that ever becomes a requirement. **Ignored on
    /// send** (left empty by `seal_envelope`; the relay stamps it).
    pub sender_device_id: String,
    /// Target device, or `None` for a group broadcast.
    pub recipient_device_id: Option<String>,
    /// Opaque sealed payload: `nonce ‖ ciphertext ‖ tag`, fixed length.
    pub payload: Vec<u8>,
}

/// The decrypted contents of an ephemeral message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EphemeralContent {
    /// App-level message kind (e.g. `"media_request"`, `"media_uploaded"`).
    pub kind: String,
    /// The media id this message concerns.
    pub media_id: String,
}

// ── Key derivation ───────────────────────────────────────────────────────────

fn derive_msgid_key(epoch_key: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    Ok(prism_sync_crypto::kdf::derive_subkey(epoch_key, &[], MSGID_SUBKEY_INFO)?)
}

fn derive_payload_key(epoch_key: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    Ok(prism_sync_crypto::kdf::derive_subkey(epoch_key, &[], PAYLOAD_SUBKEY_INFO)?)
}

// ── message_id ───────────────────────────────────────────────────────────────

fn mac_len_prefixed(mac: &mut HmacSha256, data: &[u8]) {
    mac.update(&(data.len() as u32).to_be_bytes());
    mac.update(data);
}

/// Compute the deterministic `message_id` for `(kind, media_id)` in the current
/// cooldown window. Pure (given `now_secs`) so it is fully testable; production
/// callers pass wall-clock seconds.
pub fn compute_message_id(
    epoch_key: &[u8],
    sync_id: &str,
    kind: &str,
    media_id: &str,
    epoch_id: u32,
    now_secs: i64,
) -> Result<String> {
    validate_fields(kind, media_id)?;
    let msgid_key = derive_msgid_key(epoch_key)?;
    // Floor division on a non-negative wall clock; clamp negatives to 0 so a
    // bogus clock can't panic. `as u64` is safe after the clamp.
    let window = (now_secs.max(0) as u64) / EPHEMERAL_DEDUP_WINDOW_SECS;

    let mut mac =
        HmacSha256::new_from_slice(&msgid_key).expect("HMAC accepts any key length");
    mac.update(MSGID_DOMAIN);
    mac.update(&[0x00]);
    mac_len_prefixed(&mut mac, sync_id.as_bytes());
    mac_len_prefixed(&mut mac, kind.as_bytes());
    mac_len_prefixed(&mut mac, media_id.as_bytes());
    mac.update(&epoch_id.to_be_bytes());
    mac.update(&window.to_be_bytes());
    let tag = mac.finalize().into_bytes();
    Ok(hex::encode(&tag[..MESSAGE_ID_BYTES]))
}

// ── payload padding ──────────────────────────────────────────────────────────

fn validate_fields(kind: &str, media_id: &str) -> Result<()> {
    if kind.is_empty() || kind.len() > MAX_KIND_LEN {
        return Err(CoreError::Engine(format!(
            "ephemeral message kind length {} out of range (1..={MAX_KIND_LEN})",
            kind.len()
        )));
    }
    if media_id.is_empty() || media_id.len() > MAX_MEDIA_ID_LEN {
        return Err(CoreError::Engine(format!(
            "ephemeral media_id length {} out of range (1..={MAX_MEDIA_ID_LEN})",
            media_id.len()
        )));
    }
    Ok(())
}

/// Encode `(kind, media_id)` into a fixed-length, zero-padded plaintext:
/// `[kind_len:u16][kind][media_id_len:u16][media_id][0x00 …]`. Trailing zero
/// padding is ignored on decode (the length prefixes are self-describing).
fn encode_padded(kind: &str, media_id: &str) -> Result<[u8; PLAINTEXT_LEN]> {
    validate_fields(kind, media_id)?;
    let needed = 2 + kind.len() + 2 + media_id.len();
    if needed > PLAINTEXT_LEN {
        return Err(CoreError::Engine(format!(
            "ephemeral payload {needed} bytes exceeds fixed size {PLAINTEXT_LEN}"
        )));
    }
    let mut buf = [0u8; PLAINTEXT_LEN];
    let mut off = 0;
    buf[off..off + 2].copy_from_slice(&(kind.len() as u16).to_be_bytes());
    off += 2;
    buf[off..off + kind.len()].copy_from_slice(kind.as_bytes());
    off += kind.len();
    buf[off..off + 2].copy_from_slice(&(media_id.len() as u16).to_be_bytes());
    off += 2;
    buf[off..off + media_id.len()].copy_from_slice(media_id.as_bytes());
    Ok(buf)
}

fn read_u16_prefixed<'a>(buf: &'a [u8], off: &mut usize) -> Result<&'a [u8]> {
    if *off + 2 > buf.len() {
        return Err(CoreError::Engine("ephemeral payload truncated (length prefix)".into()));
    }
    let len = u16::from_be_bytes([buf[*off], buf[*off + 1]]) as usize;
    *off += 2;
    if *off + len > buf.len() {
        return Err(CoreError::Engine("ephemeral payload truncated (field body)".into()));
    }
    let out = &buf[*off..*off + len];
    *off += len;
    Ok(out)
}

fn decode_padded(buf: &[u8]) -> Result<EphemeralContent> {
    let mut off = 0;
    let kind = read_u16_prefixed(buf, &mut off)?;
    let media_id = read_u16_prefixed(buf, &mut off)?;
    let kind = std::str::from_utf8(kind)
        .map_err(|_| CoreError::Engine("ephemeral kind not utf-8".into()))?
        .to_string();
    let media_id = std::str::from_utf8(media_id)
        .map_err(|_| CoreError::Engine("ephemeral media_id not utf-8".into()))?
        .to_string();
    validate_fields(&kind, &media_id)?;
    Ok(EphemeralContent { kind, media_id })
}

// ── seal / open ──────────────────────────────────────────────────────────────

/// AAD binds the sealed payload to its routing envelope: a relay that swaps a
/// payload onto a different `message_id` / `epoch_id` (or replays it into
/// another group) fails the AEAD check on open ⇒ the recipient skips + ACKs.
fn payload_aad(sync_id: &str, epoch_id: u32, message_id: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(
        PAYLOAD_AAD_DOMAIN.len() + 1 + 4 + sync_id.len() + 4 + 4 + message_id.len(),
    );
    aad.extend_from_slice(PAYLOAD_AAD_DOMAIN);
    aad.push(0x00);
    aad.extend_from_slice(&(sync_id.len() as u32).to_be_bytes());
    aad.extend_from_slice(sync_id.as_bytes());
    aad.extend_from_slice(&epoch_id.to_be_bytes());
    aad.extend_from_slice(&(message_id.len() as u32).to_be_bytes());
    aad.extend_from_slice(message_id.as_bytes());
    aad
}

/// Build a sealed envelope for `(kind, media_id)` under the group epoch key.
/// `sender_device_id` is left empty — the relay stamps the authenticated sender
/// on the receiving side.
pub fn seal_envelope(
    epoch_key: &[u8],
    sync_id: &str,
    epoch_id: u32,
    kind: &str,
    media_id: &str,
    recipient_device_id: Option<String>,
    now_secs: i64,
) -> Result<EphemeralEnvelope> {
    let message_id = compute_message_id(epoch_key, sync_id, kind, media_id, epoch_id, now_secs)?;
    let payload_key = derive_payload_key(epoch_key)?;
    let plaintext = encode_padded(kind, media_id)?;
    let aad = payload_aad(sync_id, epoch_id, &message_id);
    let payload = prism_sync_crypto::aead::xchacha_encrypt_aead(&payload_key, &plaintext, &aad)?;
    Ok(EphemeralEnvelope {
        message_id,
        epoch_id,
        sender_device_id: String::new(),
        recipient_device_id,
        payload,
    })
}

/// Open a sealed envelope with the epoch key for `envelope.epoch_id`. Returns an
/// error if the key is wrong, the AAD doesn't bind (tampered envelope / replay
/// into another group), or the plaintext is malformed — all of which the caller
/// treats as "can't decrypt ⇒ skip + ACK".
pub fn open_envelope(
    epoch_key: &[u8],
    sync_id: &str,
    envelope: &EphemeralEnvelope,
) -> Result<EphemeralContent> {
    let payload_key = derive_payload_key(epoch_key)?;
    let aad = payload_aad(sync_id, envelope.epoch_id, &envelope.message_id);
    let plaintext =
        prism_sync_crypto::aead::xchacha_decrypt_aead(&payload_key, &envelope.payload, &aad)?;
    decode_padded(&plaintext)
}

// ── drain processing ─────────────────────────────────────────────────────────

/// A drained, decrypted ephemeral message ready to surface to the app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedEphemeral {
    pub sender_device_id: String,
    pub kind: String,
    pub media_id: String,
    pub epoch_id: u32,
}

/// Process a batch of drained envelopes: decrypt each with the epoch key for its
/// `epoch_id`, returning `(messages to surface, ids to ACK)`.
///
/// **Every** drained id is acked — decryptable or not. A message we can't read
/// (a newer epoch whose key we lack, a rotated-away key, or a tampered payload)
/// is skipped *and* acked: it's advisory, and the requester re-issues under the
/// current epoch on its next tick (a fresh `message_id`). Acking it stops the
/// relay redelivering a message this device will never process. Per-device acks
/// mean this never hides the message from the *other* recipients.
///
/// A successfully-decoded message is likewise acked regardless of whether its
/// surfaced `SyncEvent::EphemeralMessage` finds a subscriber (the engine's emit
/// is best-effort and drops on a zero-receiver channel). A momentarily
/// unsubscribed app can therefore miss one delivery — fine for this lane: the
/// C4 requester re-issues on its next cadence tick.
pub fn process_ephemeral_drain(
    key_hierarchy: &prism_sync_crypto::KeyHierarchy,
    sync_id: &str,
    envelopes: &[EphemeralEnvelope],
) -> (Vec<DecodedEphemeral>, Vec<String>) {
    let mut decoded = Vec::new();
    let mut ack_ids = Vec::with_capacity(envelopes.len());
    for env in envelopes {
        ack_ids.push(env.message_id.clone());
        let Ok(epoch_key) = key_hierarchy.epoch_key(env.epoch_id) else {
            // No key for this epoch → skip + ack (lossy-OK).
            continue;
        };
        if let Ok(content) = open_envelope(epoch_key, sync_id, env) {
            decoded.push(DecodedEphemeral {
                sender_device_id: env.sender_device_id.clone(),
                kind: content.kind,
                media_id: content.media_id,
                epoch_id: env.epoch_id,
            });
        }
        // Decrypt failure (wrong/rotated key, tampered AAD, malformed) → skip,
        // but the id is already queued for ACK above.
    }
    (decoded, ack_ids)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_A: &[u8] = &[7u8; 32];
    const KEY_B: &[u8] = &[9u8; 32];

    #[test]
    fn message_id_is_32_hex_and_deterministic() {
        let a = compute_message_id(KEY_A, "sync1", "media_request", "blob-1", 3, 1000).unwrap();
        let b = compute_message_id(KEY_A, "sync1", "media_request", "blob-1", 3, 1000).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn message_id_scopes_per_group() {
        // Same request, two sync groups → distinct ids (sync_id is in the MAC
        // input). And distinct epoch keys reinforce this independently.
        let g1 = compute_message_id(KEY_A, "sync1", "media_request", "blob-1", 0, 1000).unwrap();
        let g2 = compute_message_id(KEY_A, "sync2", "media_request", "blob-1", 0, 1000).unwrap();
        assert_ne!(g1, g2);
        let k2 = compute_message_id(KEY_B, "sync1", "media_request", "blob-1", 0, 1000).unwrap();
        assert_ne!(g1, k2);
    }

    #[test]
    fn message_id_varies_by_kind_media_epoch_window() {
        let base = compute_message_id(KEY_A, "s", "media_request", "blob-1", 0, 1000).unwrap();
        let kind = compute_message_id(KEY_A, "s", "media_uploaded", "blob-1", 0, 1000).unwrap();
        let media = compute_message_id(KEY_A, "s", "media_request", "blob-2", 0, 1000).unwrap();
        let epoch = compute_message_id(KEY_A, "s", "media_request", "blob-1", 1, 1000).unwrap();
        // Next window (window = now/300): 1000/300=3, 1500/300=5.
        let window = compute_message_id(KEY_A, "s", "media_request", "blob-1", 0, 1500).unwrap();
        for other in [&kind, &media, &epoch, &window] {
            assert_ne!(&base, other);
        }
    }

    #[test]
    fn message_id_same_within_window_differs_across() {
        // 900..1199 all floor to window 3 (900/300=3, 1199/300=3); 1200 → 4.
        let w3a = compute_message_id(KEY_A, "s", "k", "m", 0, 900).unwrap();
        let w3b = compute_message_id(KEY_A, "s", "k", "m", 0, 1199).unwrap();
        let w4 = compute_message_id(KEY_A, "s", "k", "m", 0, 1200).unwrap();
        assert_eq!(w3a, w3b);
        assert_ne!(w3a, w4);
    }

    #[test]
    fn seal_open_roundtrip() {
        let env =
            seal_envelope(KEY_A, "sync1", 2, "media_request", "blob-xyz", None, 1234).unwrap();
        assert_eq!(env.epoch_id, 2);
        assert!(env.sender_device_id.is_empty());
        assert!(env.recipient_device_id.is_none());
        let content = open_envelope(KEY_A, "sync1", &env).unwrap();
        assert_eq!(content, EphemeralContent {
            kind: "media_request".into(),
            media_id: "blob-xyz".into(),
        });
    }

    #[test]
    fn payload_is_fixed_length_regardless_of_content() {
        let short = seal_envelope(KEY_A, "s", 0, "k", "m", None, 0).unwrap();
        let long = seal_envelope(
            KEY_A,
            "s",
            0,
            "media_uploaded",
            &"a".repeat(120),
            None,
            0,
        )
        .unwrap();
        // 24-byte nonce + 256-byte plaintext + 16-byte tag.
        assert_eq!(short.payload.len(), 24 + PLAINTEXT_LEN + 16);
        assert_eq!(short.payload.len(), long.payload.len());
    }

    #[test]
    fn open_with_wrong_epoch_key_fails() {
        let env = seal_envelope(KEY_A, "s", 0, "k", "m", None, 0).unwrap();
        assert!(open_envelope(KEY_B, "s", &env).is_err());
    }

    #[test]
    fn open_with_wrong_sync_id_fails() {
        // sync_id is bound via AAD: a payload replayed into another group's
        // envelope can't be opened even with the same key.
        let env = seal_envelope(KEY_A, "sync1", 0, "k", "m", None, 0).unwrap();
        assert!(open_envelope(KEY_A, "sync2", &env).is_err());
    }

    #[test]
    fn open_with_tampered_message_id_fails() {
        let mut env = seal_envelope(KEY_A, "s", 0, "k", "m", None, 0).unwrap();
        env.message_id = "0".repeat(32);
        assert!(open_envelope(KEY_A, "s", &env).is_err());
    }

    #[test]
    fn open_with_tampered_epoch_id_fails() {
        let mut env = seal_envelope(KEY_A, "s", 0, "k", "m", None, 0).unwrap();
        env.epoch_id = 1;
        assert!(open_envelope(KEY_A, "s", &env).is_err());
    }

    #[test]
    fn open_with_corrupted_payload_fails() {
        let mut env = seal_envelope(KEY_A, "s", 0, "k", "m", None, 0).unwrap();
        let last = env.payload.len() - 1;
        env.payload[last] ^= 0xff;
        assert!(open_envelope(KEY_A, "s", &env).is_err());
    }

    #[test]
    fn empty_or_oversized_fields_rejected() {
        assert!(seal_envelope(KEY_A, "s", 0, "", "m", None, 0).is_err());
        assert!(seal_envelope(KEY_A, "s", 0, "k", "", None, 0).is_err());
        assert!(seal_envelope(KEY_A, "s", 0, &"k".repeat(MAX_KIND_LEN + 1), "m", None, 0).is_err());
        assert!(
            seal_envelope(KEY_A, "s", 0, "k", &"m".repeat(MAX_MEDIA_ID_LEN + 1), None, 0).is_err()
        );
    }

    #[test]
    fn recipient_device_id_passes_through() {
        let env = seal_envelope(KEY_A, "s", 0, "k", "m", Some("dev-2".into()), 0).unwrap();
        assert_eq!(env.recipient_device_id.as_deref(), Some("dev-2"));
    }

    fn unlocked_hierarchy_with(epoch: u32, key: &[u8]) -> prism_sync_crypto::KeyHierarchy {
        let mut kh = prism_sync_crypto::KeyHierarchy::new();
        kh.initialize("pw", &[1u8; 16]).unwrap();
        kh.store_epoch_key(epoch, zeroize::Zeroizing::new(key.to_vec()));
        kh
    }

    fn with_sender(mut env: EphemeralEnvelope, sender: &str) -> EphemeralEnvelope {
        env.sender_device_id = sender.to_string();
        env
    }

    #[test]
    fn drain_emits_decryptable_and_acks_all() {
        let kh = unlocked_hierarchy_with(2, KEY_A);
        let good = with_sender(
            seal_envelope(KEY_A, "sync1", 2, "media_request", "blob-1", None, 0).unwrap(),
            "dev-x",
        );
        let (decoded, acks) = process_ephemeral_drain(&kh, "sync1", std::slice::from_ref(&good));
        assert_eq!(decoded, vec![DecodedEphemeral {
            sender_device_id: "dev-x".into(),
            kind: "media_request".into(),
            media_id: "blob-1".into(),
            epoch_id: 2,
        }]);
        assert_eq!(acks, vec![good.message_id]);
    }

    #[test]
    fn drain_skips_but_acks_unreadable_epoch() {
        // Epoch-rotation case: a message sealed under an epoch whose key this
        // device lacks is skipped *and* acked (lossy-OK; requester re-issues).
        let kh = unlocked_hierarchy_with(2, KEY_A);
        let newer =
            seal_envelope(KEY_A, "sync1", 5, "media_request", "blob-1", None, 0).unwrap(); // no key for 5
        let (decoded, acks) = process_ephemeral_drain(&kh, "sync1", std::slice::from_ref(&newer));
        assert!(decoded.is_empty());
        assert_eq!(acks, vec![newer.message_id], "skipped message is still acked");
    }

    #[test]
    fn drain_skips_but_acks_wrong_key_same_epoch() {
        // Same epoch_id, but the stored key differs (e.g. a forged/corrupt
        // payload from a different key) → can't decrypt → skip + ack.
        let kh = unlocked_hierarchy_with(2, KEY_A);
        let env = seal_envelope(KEY_B, "sync1", 2, "media_request", "blob-1", None, 0).unwrap();
        let (decoded, acks) = process_ephemeral_drain(&kh, "sync1", std::slice::from_ref(&env));
        assert!(decoded.is_empty());
        assert_eq!(acks, vec![env.message_id]);
    }

    #[test]
    fn drain_mixed_batch() {
        let kh = unlocked_hierarchy_with(2, KEY_A);
        let good = with_sender(
            seal_envelope(KEY_A, "s", 2, "media_uploaded", "b1", None, 0).unwrap(),
            "dev-a",
        );
        let unreadable = seal_envelope(KEY_A, "s", 9, "media_request", "b2", None, 0).unwrap();
        let (decoded, acks) =
            process_ephemeral_drain(&kh, "s", &[good.clone(), unreadable.clone()]);
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].media_id, "b1");
        // Both acked regardless of decryptability.
        assert_eq!(acks, vec![good.message_id, unreadable.message_id]);
    }
}
