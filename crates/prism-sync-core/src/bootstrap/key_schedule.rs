//! Key schedule — derives directional session keys from a [`BootstrapSecret`]
//! and a transcript hash using HKDF-SHA256.
//!
//! Four independent 32-byte keys are produced:
//!
//! | Key | Purpose |
//! |-----|---------|
//! | `initiator_encrypt_key` | Encrypts initiator-to-responder payloads |
//! | `responder_encrypt_key` | Encrypts responder-to-initiator payloads |
//! | `confirmation_key` | HMAC confirmation MACs |
//! | `verification_key` | SAS / fingerprint derivation |

use zeroize::Zeroizing;

use crate::error::Result;

use super::handshake::BootstrapSecret;
use super::{BootstrapProfile, BootstrapRole, BootstrapVersion};

// ---------------------------------------------------------------------------
// Info-string builder
// ---------------------------------------------------------------------------

/// Build the HKDF info field:
/// `"prism_bootstrap" || 0x00 || profile_byte || version_byte || 0x00 || purpose`
fn build_info(profile: BootstrapProfile, version: BootstrapVersion, purpose: &[u8]) -> Vec<u8> {
    let mut info = Vec::with_capacity(15 + 1 + 1 + 1 + 1 + purpose.len());
    info.extend_from_slice(b"prism_bootstrap");
    info.push(0x00);
    info.push(profile.as_byte());
    info.push(version.as_byte());
    info.push(0x00);
    info.extend_from_slice(purpose);
    info
}

// ---------------------------------------------------------------------------
// BootstrapKeySchedule
// ---------------------------------------------------------------------------

/// Four independent session keys derived from a bootstrap shared secret.
pub struct BootstrapKeySchedule {
    initiator_encrypt_key: Zeroizing<Vec<u8>>,
    responder_encrypt_key: Zeroizing<Vec<u8>>,
    confirmation_key: Zeroizing<Vec<u8>>,
    verification_key: Zeroizing<Vec<u8>>,
}

impl BootstrapKeySchedule {
    /// Derive all session keys from the bootstrap shared secret and transcript
    /// hash.
    ///
    /// `profile` provides domain separation so that sync-pairing and
    /// remote-sharing never produce the same key schedule even with identical
    /// secrets.
    pub fn derive(
        profile: BootstrapProfile,
        version: BootstrapVersion,
        bootstrap_secret: BootstrapSecret,
        transcript_hash: &[u8; 32],
    ) -> Result<Self> {
        let ikm = bootstrap_secret.into_zeroizing();
        let salt = transcript_hash.as_slice();

        let initiator_encrypt_key = prism_sync_crypto::kdf::derive_subkey(
            ikm.as_slice(),
            salt,
            &build_info(profile, version, b"i2r_encryption"),
        )?;
        let responder_encrypt_key = prism_sync_crypto::kdf::derive_subkey(
            ikm.as_slice(),
            salt,
            &build_info(profile, version, b"r2i_encryption"),
        )?;
        let confirmation_key = prism_sync_crypto::kdf::derive_subkey(
            ikm.as_slice(),
            salt,
            &build_info(profile, version, b"confirmation"),
        )?;
        let verification_key = prism_sync_crypto::kdf::derive_subkey(
            ikm.as_slice(),
            salt,
            &build_info(profile, version, b"verification"),
        )?;

        Ok(Self {
            initiator_encrypt_key,
            responder_encrypt_key,
            confirmation_key,
            verification_key,
        })
    }

    /// Return the directional encryption key for the given sender role.
    ///
    /// - `Initiator` → initiator-to-responder key
    /// - `Responder` → responder-to-initiator key
    pub fn encryption_key(&self, sender_role: BootstrapRole) -> &[u8] {
        match sender_role {
            BootstrapRole::Initiator => &self.initiator_encrypt_key,
            BootstrapRole::Responder => &self.responder_encrypt_key,
        }
    }

    /// The confirmation key for HMAC confirmation MACs.
    pub fn confirmation_key(&self) -> &[u8] {
        &self.confirmation_key
    }

    /// The verification key for SAS and fingerprint derivation.
    pub fn verification_key(&self) -> &[u8] {
        &self.verification_key
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use prism_sync_crypto::pq::hybrid_kem::XWingKem;

    use super::super::handshake::DefaultBootstrapHandshake;

    fn rng() -> getrandom::rand_core::UnwrapErr<getrandom::SysRng> {
        getrandom::rand_core::UnwrapErr(getrandom::SysRng)
    }

    /// Helper: run a full encapsulate/decapsulate round-trip and return the
    /// shared secret (from the decapsulator side — both sides agree).
    fn make_secret(seed: u8) -> BootstrapSecret {
        let dk = XWingKem::decapsulation_key_from_bytes(&[seed; 32]);
        let ek_bytes = XWingKem::encapsulation_key_bytes(&dk);

        let (ct, _enc_secret) =
            DefaultBootstrapHandshake::encapsulate_to_peer(&ek_bytes, &mut rng()).unwrap();
        DefaultBootstrapHandshake::decapsulate_from_peer(&dk, &ct).unwrap()
    }

    /// Helper: produce a deterministic secret by encapsulating then
    /// decapsulating with the same ciphertext (no randomness after encaps).
    fn make_deterministic_pair(seed: u8) -> (BootstrapSecret, BootstrapSecret) {
        let dk = XWingKem::decapsulation_key_from_bytes(&[seed; 32]);
        let ek_bytes = XWingKem::encapsulation_key_bytes(&dk);

        let (ct, _) =
            DefaultBootstrapHandshake::encapsulate_to_peer(&ek_bytes, &mut rng()).unwrap();
        let s1 = DefaultBootstrapHandshake::decapsulate_from_peer(&dk, &ct).unwrap();
        let s2 = DefaultBootstrapHandshake::decapsulate_from_peer(&dk, &ct).unwrap();
        (s1, s2)
    }

    fn transcript(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    // -- deterministic ---------------------------------------------------------

    #[test]
    fn key_schedule_deterministic() {
        let (secret1, secret2) = make_deterministic_pair(7);
        let th = transcript(1);

        let ks1 = BootstrapKeySchedule::derive(
            BootstrapProfile::SyncPairing,
            BootstrapVersion::V1,
            secret1,
            &th,
        )
        .unwrap();
        let ks2 = BootstrapKeySchedule::derive(
            BootstrapProfile::SyncPairing,
            BootstrapVersion::V1,
            secret2,
            &th,
        )
        .unwrap();

        assert_eq!(
            ks1.encryption_key(BootstrapRole::Initiator),
            ks2.encryption_key(BootstrapRole::Initiator),
        );
        assert_eq!(
            ks1.encryption_key(BootstrapRole::Responder),
            ks2.encryption_key(BootstrapRole::Responder),
        );
        assert_eq!(ks1.confirmation_key(), ks2.confirmation_key());
        assert_eq!(ks1.verification_key(), ks2.verification_key());
    }

    // -- different secrets → different keys ------------------------------------

    #[test]
    fn key_schedule_different_secrets() {
        let s1 = make_secret(1);
        let s2 = make_secret(2);
        let th = transcript(1);

        let ks1 = BootstrapKeySchedule::derive(
            BootstrapProfile::SyncPairing,
            BootstrapVersion::V1,
            s1,
            &th,
        )
        .unwrap();
        let ks2 = BootstrapKeySchedule::derive(
            BootstrapProfile::SyncPairing,
            BootstrapVersion::V1,
            s2,
            &th,
        )
        .unwrap();

        assert_ne!(
            ks1.encryption_key(BootstrapRole::Initiator),
            ks2.encryption_key(BootstrapRole::Initiator),
        );
        assert_ne!(
            ks1.encryption_key(BootstrapRole::Responder),
            ks2.encryption_key(BootstrapRole::Responder),
        );
        assert_ne!(ks1.confirmation_key(), ks2.confirmation_key());
        assert_ne!(ks1.verification_key(), ks2.verification_key());
    }

    // -- different transcript hashes → different keys --------------------------

    #[test]
    fn key_schedule_different_transcripts() {
        let (s1, s2) = make_deterministic_pair(1);
        let th1 = transcript(1);
        let th2 = transcript(2);

        let ks1 = BootstrapKeySchedule::derive(
            BootstrapProfile::SyncPairing,
            BootstrapVersion::V1,
            s1,
            &th1,
        )
        .unwrap();
        let ks2 = BootstrapKeySchedule::derive(
            BootstrapProfile::SyncPairing,
            BootstrapVersion::V1,
            s2,
            &th2,
        )
        .unwrap();

        assert_ne!(
            ks1.encryption_key(BootstrapRole::Initiator),
            ks2.encryption_key(BootstrapRole::Initiator),
        );
    }

    // -- all 4 keys are mutually different -------------------------------------

    #[test]
    fn key_schedule_key_independence() {
        let secret = make_secret(3);
        let th = transcript(5);
        let ks = BootstrapKeySchedule::derive(
            BootstrapProfile::SyncPairing,
            BootstrapVersion::V1,
            secret,
            &th,
        )
        .unwrap();

        let keys: Vec<&[u8]> = vec![
            ks.encryption_key(BootstrapRole::Initiator),
            ks.encryption_key(BootstrapRole::Responder),
            ks.confirmation_key(),
            ks.verification_key(),
        ];

        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert_ne!(keys[i], keys[j], "key {i} == key {j}");
            }
        }
    }

    // -- profile separation ----------------------------------------------------

    #[test]
    fn key_schedule_profile_separation() {
        let (s1, s2) = make_deterministic_pair(4);
        let th = transcript(1);

        let ks_sync = BootstrapKeySchedule::derive(
            BootstrapProfile::SyncPairing,
            BootstrapVersion::V1,
            s1,
            &th,
        )
        .unwrap();
        let ks_remote = BootstrapKeySchedule::derive(
            BootstrapProfile::RemoteSharing,
            BootstrapVersion::V1,
            s2,
            &th,
        )
        .unwrap();

        assert_ne!(
            ks_sync.encryption_key(BootstrapRole::Initiator),
            ks_remote.encryption_key(BootstrapRole::Initiator),
        );
        assert_ne!(ks_sync.confirmation_key(), ks_remote.confirmation_key());
    }

    // -- all keys are exactly 32 bytes -----------------------------------------

    #[test]
    fn key_schedule_sizes() {
        let secret = make_secret(5);
        let th = transcript(1);
        let ks = BootstrapKeySchedule::derive(
            BootstrapProfile::SyncPairing,
            BootstrapVersion::V1,
            secret,
            &th,
        )
        .unwrap();

        assert_eq!(ks.encryption_key(BootstrapRole::Initiator).len(), 32);
        assert_eq!(ks.encryption_key(BootstrapRole::Responder).len(), 32);
        assert_eq!(ks.confirmation_key().len(), 32);
        assert_eq!(ks.verification_key().len(), 32);
    }

    // -- directional keys differ -----------------------------------------------

    #[test]
    fn key_schedule_directional_keys() {
        let secret = make_secret(6);
        let th = transcript(1);
        let ks = BootstrapKeySchedule::derive(
            BootstrapProfile::SyncPairing,
            BootstrapVersion::V1,
            secret,
            &th,
        )
        .unwrap();

        assert_ne!(
            ks.encryption_key(BootstrapRole::Initiator),
            ks.encryption_key(BootstrapRole::Responder),
        );
    }
}
