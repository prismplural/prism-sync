//! Running SHA-256 transcript that accumulates all public handshake values
//! during a bootstrap ceremony. Both sides feed the same values in the same
//! order and derive the same 32-byte digest.

use sha2::{Digest, Sha256};

use super::{BootstrapProfile, BootstrapRole, BootstrapVersion};

/// Domain separator written at the start of every transcript.
const DOMAIN_TAG: &[u8] = b"PRISM_BOOTSTRAP";
const FIELD_KIND_VARIABLE: u8 = 0x01;
const FIELD_KIND_FIXED: u8 = 0x02;

/// A running SHA-256 hash that both sides of a bootstrap ceremony maintain
/// in lock-step. Consuming identical public values in the same order yields
/// an identical 32-byte digest used for key-schedule binding and SAS codes.
pub struct BootstrapTranscript {
    hasher: Sha256,
}

impl BootstrapTranscript {
    /// Start a new transcript with domain separator:
    /// `"PRISM_BOOTSTRAP" || 0x00 || profile_byte || version_byte`
    pub fn new(profile: BootstrapProfile, version: BootstrapVersion) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN_TAG);
        hasher.update([0x00]);
        hasher.update([profile.as_byte()]);
        hasher.update([version.as_byte()]);
        Self { hasher }
    }

    /// Append the session-binding value (e.g., rendezvous_id for sync pairing).
    /// Must be called before any peer public keys.
    pub fn append_session_id(&mut self, session_id: &[u8]) {
        self.append_bytes(b"session_id", session_id);
    }

    /// Append a role-bound variable-length field.
    ///
    /// The label is constructed as `role_prefix || "_" || label_stem` where
    /// `role_prefix` is `"initiator"` or `"responder"`.
    pub fn append_role_bytes(&mut self, role: BootstrapRole, label_stem: &[u8], data: &[u8]) {
        let label = role_label(role, label_stem);
        self.append_bytes(&label, data);
    }

    /// Append a role-bound fixed-size field.
    pub fn append_role_fixed(&mut self, role: BootstrapRole, label_stem: &[u8], data: &[u8]) {
        let label = role_label(role, label_stem);
        self.append_fixed(&label, data);
    }

    /// Append a length-prefixed variable-length field.
    ///
    /// Wire format:
    /// `u16-BE(label_len) || label || 0x01 || u32-BE(data_len) || data`
    pub fn append_bytes(&mut self, label: &[u8], data: &[u8]) {
        self.write_label(label);
        self.hasher.update([FIELD_KIND_VARIABLE]);
        self.hasher.update((data.len() as u32).to_be_bytes());
        self.hasher.update(data);
    }

    /// Append a fixed-size field (no length prefix on the data).
    ///
    /// Wire format:
    /// `u16-BE(label_len) || label || 0x02 || data`
    pub fn append_fixed(&mut self, label: &[u8], data: &[u8]) {
        self.write_label(label);
        self.hasher.update([FIELD_KIND_FIXED]);
        self.hasher.update(data);
    }

    /// Finalize and return the 32-byte transcript hash. Consumes self.
    pub fn finalize(self) -> [u8; 32] {
        self.hasher.finalize().into()
    }

    // ── internal ──

    /// Write a label: `u16-BE(label_len) || label`
    fn write_label(&mut self, label: &[u8]) {
        self.hasher.update((label.len() as u16).to_be_bytes());
        self.hasher.update(label);
    }
}

/// Build a role-prefixed label: `"initiator_" || stem` or `"responder_" || stem`.
fn role_label(role: BootstrapRole, stem: &[u8]) -> Vec<u8> {
    let prefix = match role {
        BootstrapRole::Initiator => b"initiator_" as &[u8],
        BootstrapRole::Responder => b"responder_" as &[u8],
    };
    let mut label = Vec::with_capacity(prefix.len() + stem.len());
    label.extend_from_slice(prefix);
    label.extend_from_slice(stem);
    label
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_transcript(
        profile: BootstrapProfile,
        version: BootstrapVersion,
    ) -> BootstrapTranscript {
        BootstrapTranscript::new(profile, version)
    }

    /// Same inputs produce the same hash.
    #[test]
    fn transcript_deterministic() {
        let build = || {
            let mut t = make_transcript(BootstrapProfile::SyncPairing, BootstrapVersion::V1);
            t.append_session_id(b"session-abc");
            t.append_role_bytes(BootstrapRole::Initiator, b"ek", b"init_key");
            t.append_role_bytes(BootstrapRole::Responder, b"ek", b"resp_key");
            t.finalize()
        };
        assert_eq!(build(), build());
    }

    /// Swapping two fields produces a different hash.
    #[test]
    fn transcript_field_order_matters() {
        let a = {
            let mut t = make_transcript(BootstrapProfile::SyncPairing, BootstrapVersion::V1);
            t.append_bytes(b"alpha", b"1");
            t.append_bytes(b"beta", b"2");
            t.finalize()
        };
        let b = {
            let mut t = make_transcript(BootstrapProfile::SyncPairing, BootstrapVersion::V1);
            t.append_bytes(b"beta", b"2");
            t.append_bytes(b"alpha", b"1");
            t.finalize()
        };
        assert_ne!(a, b);
    }

    /// `append_bytes(b"ab", b"cd")` ≠ `append_bytes(b"abc", b"d")`.
    #[test]
    fn transcript_label_collision_resistance() {
        let a = {
            let mut t = make_transcript(BootstrapProfile::SyncPairing, BootstrapVersion::V1);
            t.append_bytes(b"ab", b"cd");
            t.finalize()
        };
        let b = {
            let mut t = make_transcript(BootstrapProfile::SyncPairing, BootstrapVersion::V1);
            t.append_bytes(b"abc", b"d");
            t.finalize()
        };
        assert_ne!(a, b);
    }

    /// Empty data is valid and distinct from omitted.
    #[test]
    fn transcript_empty_fields() {
        let with_empty = {
            let mut t = make_transcript(BootstrapProfile::SyncPairing, BootstrapVersion::V1);
            t.append_bytes(b"field", b"");
            t.finalize()
        };
        let without = {
            let t = make_transcript(BootstrapProfile::SyncPairing, BootstrapVersion::V1);
            t.finalize()
        };
        assert_ne!(with_empty, without);
    }

    /// 1952-byte ML-DSA key and 1184-byte ML-KEM key hash correctly.
    #[test]
    fn transcript_large_pq_keys() {
        let mldsa_pk = vec![0xAA; 1952];
        let mlkem_pk = vec![0xBB; 1184];

        let mut t = make_transcript(BootstrapProfile::SyncPairing, BootstrapVersion::V1);
        t.append_session_id(b"rendezvous-1");
        t.append_role_bytes(BootstrapRole::Initiator, b"mldsa_pk", &mldsa_pk);
        t.append_role_bytes(BootstrapRole::Initiator, b"mlkem_pk", &mlkem_pk);
        t.append_role_bytes(BootstrapRole::Responder, b"mldsa_pk", &mldsa_pk);
        t.append_role_bytes(BootstrapRole::Responder, b"mlkem_pk", &mlkem_pk);
        let hash = t.finalize();

        // Determinism: rebuild and compare.
        let mut t2 = make_transcript(BootstrapProfile::SyncPairing, BootstrapVersion::V1);
        t2.append_session_id(b"rendezvous-1");
        t2.append_role_bytes(BootstrapRole::Initiator, b"mldsa_pk", &mldsa_pk);
        t2.append_role_bytes(BootstrapRole::Initiator, b"mlkem_pk", &mlkem_pk);
        t2.append_role_bytes(BootstrapRole::Responder, b"mldsa_pk", &mldsa_pk);
        t2.append_role_bytes(BootstrapRole::Responder, b"mlkem_pk", &mlkem_pk);
        assert_eq!(hash, t2.finalize());
        assert_eq!(hash.len(), 32);
    }

    /// SyncPairing ≠ RemoteSharing with same fields.
    #[test]
    fn transcript_profile_separation() {
        let build = |profile: BootstrapProfile| {
            let mut t = make_transcript(profile, BootstrapVersion::V1);
            t.append_session_id(b"same-session");
            t.append_bytes(b"payload", b"same-data");
            t.finalize()
        };
        assert_ne!(build(BootstrapProfile::SyncPairing), build(BootstrapProfile::RemoteSharing),);
    }

    /// Initiator role ≠ Responder role with the same data.
    #[test]
    fn transcript_canonical_role_mapping() {
        let build = |role: BootstrapRole| {
            let mut t = make_transcript(BootstrapProfile::SyncPairing, BootstrapVersion::V1);
            t.append_role_bytes(role, b"ek", b"key_data");
            t.finalize()
        };
        assert_ne!(build(BootstrapRole::Initiator), build(BootstrapRole::Responder),);
    }

    /// Different session IDs produce different hashes.
    #[test]
    fn transcript_session_id_binding() {
        let build = |sid: &[u8]| {
            let mut t = make_transcript(BootstrapProfile::SyncPairing, BootstrapVersion::V1);
            t.append_session_id(sid);
            t.finalize()
        };
        assert_ne!(build(b"session-a"), build(b"session-b"));
    }

    /// Fixed and variable fields with the same label must not collide.
    #[test]
    fn transcript_fixed_and_variable_fields_do_not_collide() {
        let variable = {
            let mut t = make_transcript(BootstrapProfile::SyncPairing, BootstrapVersion::V1);
            t.append_bytes(b"label", b"A");
            t.finalize()
        };
        let fixed = {
            let mut t = make_transcript(BootstrapProfile::SyncPairing, BootstrapVersion::V1);
            t.append_fixed(b"label", b"\0\0\0\x01A");
            t.finalize()
        };
        assert_ne!(variable, fixed);
    }

    /// The version byte is part of the domain separator and affects the hash.
    /// This pins the V1 domain separator so a future V2 addition is forced to
    /// produce a different transcript (or explicitly update this test).
    #[test]
    fn transcript_version_is_bound() {
        // Build a V1 transcript
        let mut t = make_transcript(BootstrapProfile::SyncPairing, BootstrapVersion::V1);
        t.append_session_id(b"session-pin");
        let v1_hash = t.finalize();

        // Manually build a transcript with a different version byte to prove
        // the version is actually mixed in.
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"PRISM_BOOTSTRAP");
        hasher.update([0x00]);
        hasher.update([BootstrapProfile::SyncPairing.as_byte()]);
        hasher.update([0xFF]); // fake "version 255"
                               // Replay the same session_id append:
                               // label: u16-BE(10) || "session_id"
        hasher.update(10u16.to_be_bytes());
        hasher.update(b"session_id");
        // field kind + data: 0x01 || u32-BE(11) || "session-pin"
        hasher.update([FIELD_KIND_VARIABLE]);
        hasher.update(11u32.to_be_bytes());
        hasher.update(b"session-pin");
        let fake_hash: [u8; 32] = hasher.finalize().into();

        assert_ne!(v1_hash, fake_hash, "version byte must affect transcript hash");
    }
}
