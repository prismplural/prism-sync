//! Confirmation codes (SAS ceremony) and public fingerprints for the
//! post-quantum bootstrap protocol.
//!
//! [`ConfirmationCode`] derives short authentication strings and HMAC
//! confirmation MACs from the bootstrap key schedule, enabling both
//! sides of a pairing ceremony to verify they share the same session.
//!
//! [`PublicFingerprint`] produces stable SHA-256 fingerprints over
//! canonical public key bundles for async TOFU (Phase 4).

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::{CoreError, Result};

use super::key_schedule::BootstrapKeySchedule;
use super::sas_words::SAS_WORDS;
use super::{BootstrapProfile, BootstrapRole, BootstrapVersion};

type HmacSha256 = Hmac<Sha256>;

// ── Domain separators ────────────────────────────────────────────────────────

const SAS_DOMAIN: &[u8] = b"PRISM_BOOTSTRAP_SAS";
const CONFIRM_DOMAIN: &[u8] = b"PRISM_BOOTSTRAP_CONFIRM_V1";
const FINGERPRINT_DOMAIN: &[u8] = b"PRISM_FINGERPRINT";

// ── ConfirmationCode ─────────────────────────────────────────────────────────

/// SAS display codes and HMAC confirmation MACs derived from the bootstrap
/// key schedule.
pub struct ConfirmationCode {
    verification_key: Zeroizing<Vec<u8>>,
    confirmation_key: Zeroizing<Vec<u8>>,
    profile: BootstrapProfile,
    version: BootstrapVersion,
    transcript_hash: [u8; 32],
}

impl ConfirmationCode {
    /// Create a new `ConfirmationCode` from the key schedule and transcript.
    pub fn new(
        profile: BootstrapProfile,
        version: BootstrapVersion,
        key_schedule: &BootstrapKeySchedule,
        transcript_hash: [u8; 32],
    ) -> Self {
        Self {
            verification_key: Zeroizing::new(key_schedule.verification_key().to_vec()),
            confirmation_key: Zeroizing::new(key_schedule.confirmation_key().to_vec()),
            profile,
            version,
            transcript_hash,
        }
    }

    /// Compute the SAS input HMAC (used for words, decimal, and fingerprint).
    fn sas_input(&self) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(&self.verification_key)
            .expect("HMAC accepts any key length");
        mac.update(SAS_DOMAIN);
        mac.update(&[0x00]);
        mac.update(&[self.profile.as_byte()]);
        mac.update(&[self.version.as_byte()]);
        mac.finalize().into_bytes().into()
    }

    /// 3-word SAS display code (e.g. "amber-canyon-frost").
    pub fn sas_words(&self) -> String {
        let hash = self.sas_input();
        let words: Vec<&str> = hash[..3].iter().map(|b| SAS_WORDS[*b as usize]).collect();
        words.join("-")
    }

    /// 6-digit decimal SAS (e.g. "472916").
    pub fn sas_decimal(&self) -> String {
        let hash = self.sas_input();
        let val = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]);
        format!("{:06}", val % 1_000_000)
    }

    /// 32-byte session fingerprint for logs.
    pub fn session_fingerprint(&self) -> [u8; 32] {
        self.sas_input()
    }

    /// Produce the confirmation MAC for this device's role.
    pub fn confirmation_mac(&self, role: BootstrapRole) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(&self.confirmation_key)
            .expect("HMAC accepts any key length");
        mac.update(CONFIRM_DOMAIN);
        mac.update(&[0x00]);
        mac.update(&[self.version.as_byte()]);
        mac.update(&[role.as_byte()]);
        mac.update(&self.transcript_hash);
        mac.finalize().into_bytes().to_vec()
    }

    /// Verify the other device's confirmation MAC.
    pub fn verify_confirmation(
        &self,
        received_mac: &[u8],
        remote_role: BootstrapRole,
    ) -> Result<()> {
        let mut mac = HmacSha256::new_from_slice(&self.confirmation_key)
            .expect("HMAC accepts any key length");
        mac.update(CONFIRM_DOMAIN);
        mac.update(&[0x00]);
        mac.update(&[self.version.as_byte()]);
        mac.update(&[remote_role.as_byte()]);
        mac.update(&self.transcript_hash);
        mac.verify_slice(received_mac).map_err(|_| {
            CoreError::Crypto(prism_sync_crypto::CryptoError::SignatureVerificationFailed(
                "confirmation MAC verification failed".into(),
            ))
        })
    }
}

// ── PublicFingerprint ────────────────────────────────────────────────────────

/// Stable SHA-256 fingerprint over canonical public key bundles.
///
/// Used for async TOFU (Trust On First Use) in Phase 4, where a device
/// can verify a remote sharing identity bundle without an interactive SAS
/// ceremony.
pub struct PublicFingerprint(pub [u8; 32]);

impl PublicFingerprint {
    /// Fingerprint canonical public fields.
    ///
    /// Uses a stable labeled public-field encoding:
    /// `u16-BE(label_len) || label || u32-BE(data_len) || data`.
    ///
    /// This is intentionally separate from bootstrap transcript framing so
    /// Phase 4 TOFU fingerprints remain stable even if transcript internals
    /// evolve.
    pub fn from_public_fields(
        profile: BootstrapProfile,
        version: BootstrapVersion,
        purpose: &[u8],
        canonical_fields: &[(&[u8], &[u8])],
    ) -> Self {
        let mut hasher = Sha256::new();

        // Domain prefix
        hasher.update(FINGERPRINT_DOMAIN);
        hasher.update([0x00]);
        hasher.update([profile.as_byte()]);
        hasher.update([version.as_byte()]);

        // Purpose (u16-BE length-prefixed)
        hasher.update((purpose.len() as u16).to_be_bytes());
        hasher.update(purpose);

        // Each (label, data) pair
        for (label, data) in canonical_fields {
            hasher.update((label.len() as u16).to_be_bytes());
            hasher.update(label);
            hasher.update((data.len() as u32).to_be_bytes());
            hasher.update(data);
        }

        Self(hasher.finalize().into())
    }

    /// The raw 32-byte fingerprint.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hex encoding of the fingerprint.
    pub fn hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use prism_sync_crypto::pq::hybrid_kem::XWingKem;

    use super::super::handshake::BootstrapHandshake;
    use super::super::key_schedule::BootstrapKeySchedule;

    fn rng() -> getrandom::rand_core::UnwrapErr<getrandom::SysRng> {
        getrandom::rand_core::UnwrapErr(getrandom::SysRng)
    }

    /// Helper: run encapsulate + decapsulate, returning a deterministic pair
    /// of key schedules from the same ciphertext (both sides agree).
    fn test_key_schedule_pair(seed: u8) -> (BootstrapKeySchedule, BootstrapKeySchedule, [u8; 32]) {
        let dk = XWingKem::decapsulation_key_from_bytes(&[seed; 32]);
        let ek_bytes = XWingKem::encapsulation_key_bytes(&dk);
        let (ct, _enc_secret) =
            BootstrapHandshake::<XWingKem>::encapsulate_to_peer(&ek_bytes, &mut rng()).unwrap();
        let s1 = BootstrapHandshake::<XWingKem>::decapsulate_from_peer(&dk, &ct).unwrap();
        let s2 = BootstrapHandshake::<XWingKem>::decapsulate_from_peer(&dk, &ct).unwrap();
        let transcript_hash = [seed; 32];
        let ks1 = BootstrapKeySchedule::derive(
            BootstrapProfile::SyncPairing,
            BootstrapVersion::V1,
            s1,
            &transcript_hash,
        )
        .unwrap();
        let ks2 = BootstrapKeySchedule::derive(
            BootstrapProfile::SyncPairing,
            BootstrapVersion::V1,
            s2,
            &transcript_hash,
        )
        .unwrap();
        (ks1, ks2, transcript_hash)
    }

    /// Helper: derive a single key schedule (non-deterministic across calls
    /// with the same seed due to encapsulate randomness).
    fn test_key_schedule(seed: u8) -> (BootstrapKeySchedule, [u8; 32]) {
        let dk = XWingKem::decapsulation_key_from_bytes(&[seed; 32]);
        let ek_bytes = XWingKem::encapsulation_key_bytes(&dk);
        let (ct, _enc_secret) =
            BootstrapHandshake::<XWingKem>::encapsulate_to_peer(&ek_bytes, &mut rng()).unwrap();
        let secret = BootstrapHandshake::<XWingKem>::decapsulate_from_peer(&dk, &ct).unwrap();
        let transcript_hash = [seed; 32];
        let ks = BootstrapKeySchedule::derive(
            BootstrapProfile::SyncPairing,
            BootstrapVersion::V1,
            secret,
            &transcript_hash,
        )
        .unwrap();
        (ks, transcript_hash)
    }

    fn make_confirmation(seed: u8) -> ConfirmationCode {
        let (ks, th) = test_key_schedule(seed);
        ConfirmationCode::new(BootstrapProfile::SyncPairing, BootstrapVersion::V1, &ks, th)
    }

    /// Make a deterministic pair of confirmations from the same shared secret.
    fn make_confirmation_pair(seed: u8) -> (ConfirmationCode, ConfirmationCode) {
        let (ks1, ks2, th) = test_key_schedule_pair(seed);
        (
            ConfirmationCode::new(
                BootstrapProfile::SyncPairing,
                BootstrapVersion::V1,
                &ks1,
                th,
            ),
            ConfirmationCode::new(
                BootstrapProfile::SyncPairing,
                BootstrapVersion::V1,
                &ks2,
                th,
            ),
        )
    }

    // ── SAS words tests ──────────────────────────────────────────────────

    #[test]
    fn sas_words_deterministic() {
        let (c1, c2) = make_confirmation_pair(42);
        assert_eq!(c1.sas_words(), c2.sas_words());
    }

    #[test]
    fn sas_decimal_deterministic() {
        let (c1, c2) = make_confirmation_pair(42);
        assert_eq!(c1.sas_decimal(), c2.sas_decimal());
    }

    #[test]
    fn sas_words_format() {
        let code = make_confirmation(7);
        let words_str = code.sas_words();
        let words: Vec<&str> = words_str.split('-').collect();
        assert_eq!(words.len(), 3, "expected 3 words, got: {words_str}");
        for word in &words {
            assert!(
                SAS_WORDS.contains(word),
                "word '{word}' not in SAS_WORDS list"
            );
        }
    }

    #[test]
    fn sas_decimal_format() {
        let code = make_confirmation(7);
        let decimal = code.sas_decimal();
        assert_eq!(decimal.len(), 6, "expected 6 digits, got: {decimal}");
        assert!(
            decimal.chars().all(|c| c.is_ascii_digit()),
            "expected all digits, got: {decimal}"
        );
    }

    #[test]
    fn sas_changes_with_different_keys() {
        let c1 = make_confirmation(1);
        let c2 = make_confirmation(2);
        // Different seeds -> different verification keys -> different SAS
        assert_ne!(c1.sas_words(), c2.sas_words());
    }

    // ── Confirmation MAC tests ───────────────────────────────────────────

    #[test]
    fn confirmation_mac_deterministic() {
        let (c1, c2) = make_confirmation_pair(42);
        assert_eq!(
            c1.confirmation_mac(BootstrapRole::Initiator),
            c2.confirmation_mac(BootstrapRole::Initiator),
        );
    }

    #[test]
    fn confirmation_mac_role_binding() {
        let code = make_confirmation(7);
        let init_mac = code.confirmation_mac(BootstrapRole::Initiator);
        let resp_mac = code.confirmation_mac(BootstrapRole::Responder);
        assert_ne!(
            init_mac, resp_mac,
            "initiator and responder MACs must differ (reflection attack prevention)"
        );
    }

    #[test]
    fn confirmation_mac_verify_succeeds() {
        let code = make_confirmation(7);
        let mac = code.confirmation_mac(BootstrapRole::Initiator);
        code.verify_confirmation(&mac, BootstrapRole::Initiator)
            .expect("valid MAC should verify");
    }

    #[test]
    fn confirmation_mac_verify_rejects_wrong_mac() {
        let code = make_confirmation(7);
        let mut mac = code.confirmation_mac(BootstrapRole::Initiator);
        mac[0] ^= 0xFF; // tamper
        let result = code.verify_confirmation(&mac, BootstrapRole::Initiator);
        assert!(result.is_err(), "tampered MAC should be rejected");
    }

    #[test]
    fn confirmation_mac_verify_rejects_wrong_role() {
        let code = make_confirmation(7);
        let init_mac = code.confirmation_mac(BootstrapRole::Initiator);
        // Verify as responder — should fail
        let result = code.verify_confirmation(&init_mac, BootstrapRole::Responder);
        assert!(
            result.is_err(),
            "initiator MAC verified as responder should fail"
        );
    }

    // ── PublicFingerprint tests ──────────────────────────────────────────

    #[test]
    fn public_fingerprint_deterministic() {
        let fp1 = PublicFingerprint::from_public_fields(
            BootstrapProfile::SyncPairing,
            BootstrapVersion::V1,
            b"sharing_identity_bundle",
            &[(b"ed25519_pk", &[1u8; 32]), (b"x25519_pk", &[2u8; 32])],
        );
        let fp2 = PublicFingerprint::from_public_fields(
            BootstrapProfile::SyncPairing,
            BootstrapVersion::V1,
            b"sharing_identity_bundle",
            &[(b"ed25519_pk", &[1u8; 32]), (b"x25519_pk", &[2u8; 32])],
        );
        assert_eq!(fp1.as_bytes(), fp2.as_bytes());
    }

    #[test]
    fn public_fingerprint_purpose_separation() {
        let fp1 = PublicFingerprint::from_public_fields(
            BootstrapProfile::SyncPairing,
            BootstrapVersion::V1,
            b"sharing_identity_bundle",
            &[(b"ed25519_pk", &[1u8; 32])],
        );
        let fp2 = PublicFingerprint::from_public_fields(
            BootstrapProfile::SyncPairing,
            BootstrapVersion::V1,
            b"different_purpose",
            &[(b"ed25519_pk", &[1u8; 32])],
        );
        assert_ne!(fp1.as_bytes(), fp2.as_bytes());
    }

    #[test]
    fn public_fingerprint_hex() {
        let fp = PublicFingerprint::from_public_fields(
            BootstrapProfile::SyncPairing,
            BootstrapVersion::V1,
            b"test",
            &[(b"key", &[0xAB; 16])],
        );
        let hex = fp.hex();
        assert_eq!(hex.len(), 64, "hex should be 64 chars");
        assert!(
            hex.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "hex should be lowercase hex: {hex}"
        );
    }

    #[test]
    fn sas_words_list_is_unique() {
        let unique_count = SAS_WORDS
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            .len();
        assert_eq!(
            unique_count,
            SAS_WORDS.len(),
            "bootstrap SAS word list must be unique"
        );
    }
}
