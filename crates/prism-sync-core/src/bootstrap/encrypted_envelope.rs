//! Versioned AEAD envelope for bootstrap ceremony payloads.
//!
//! Provides a simple wire format that wraps XChaCha20-Poly1305 ciphertext
//! with structured AAD derived from [`EnvelopeContext`]. Used to encrypt
//! credential bundles (sync pairing) and sharing-init payloads (remote sharing).

use super::{BootstrapProfile, BootstrapRole, BootstrapVersion};
use crate::error::{CoreError, Result};
use prism_sync_crypto::aead;

const NONCE_LEN: usize = 24;
const VERSION_LEN: usize = 1;
const LEN_FIELD: usize = 4;
const HEADER_LEN: usize = VERSION_LEN + NONCE_LEN + LEN_FIELD; // 29

const AAD_PREFIX: &[u8] = b"PRISM_BOOTSTRAP_ENVELOPE";

/// Structured AAD for envelope encryption/decryption.
///
/// Binds the ciphertext to a specific bootstrap session, profile, role,
/// and purpose so that envelopes cannot be replayed across contexts.
pub struct EnvelopeContext<'a> {
    pub profile: BootstrapProfile,
    pub version: BootstrapVersion,
    pub sender_role: BootstrapRole,
    pub purpose: &'a [u8],
    pub session_id: &'a [u8],
    pub transcript_hash: &'a [u8; 32],
}

impl<'a> EnvelopeContext<'a> {
    /// Build the canonical AAD byte string for AEAD binding.
    ///
    /// ```text
    /// "PRISM_BOOTSTRAP_ENVELOPE" || 0x00
    /// || profile_byte
    /// || version_byte
    /// || role_byte
    /// || u16-BE(purpose_len) || purpose
    /// || u32-BE(session_id_len) || session_id
    /// || transcript_hash (32 bytes)
    /// ```
    fn canonical_aad(&self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(
            AAD_PREFIX.len()
                + 1  // null separator
                + 3  // profile + version + role
                + 2 + self.purpose.len()
                + 4 + self.session_id.len()
                + 32,
        );
        aad.extend_from_slice(AAD_PREFIX);
        aad.push(0x00);
        aad.push(self.profile.as_byte());
        aad.push(self.version.as_byte());
        aad.push(self.sender_role.as_byte());
        aad.extend_from_slice(&(self.purpose.len() as u16).to_be_bytes());
        aad.extend_from_slice(self.purpose);
        aad.extend_from_slice(&(self.session_id.len() as u32).to_be_bytes());
        aad.extend_from_slice(self.session_id);
        aad.extend_from_slice(self.transcript_hash);
        aad
    }
}

/// Versioned AEAD envelope for bootstrap payloads.
///
/// Wire format:
/// ```text
/// [1B  version]           — 0x01
/// [24B nonce]             — XChaCha20-Poly1305 nonce
/// [4B  ciphertext_len BE] — length of ciphertext + 16B Poly1305 tag
/// [var ciphertext+tag]    — XChaCha20-Poly1305 output
/// ```
pub struct EncryptedEnvelope;

impl EncryptedEnvelope {
    /// Encrypt plaintext into the versioned envelope wire format.
    pub fn seal(key: &[u8], plaintext: &[u8], context: &EnvelopeContext) -> Result<Vec<u8>> {
        let aad = context.canonical_aad();
        let blob = aead::xchacha_encrypt_aead(key, plaintext, &aad)?;

        // blob = nonce(24) || ciphertext+tag
        let nonce = &blob[..NONCE_LEN];
        let ct_tag = &blob[NONCE_LEN..];

        let mut envelope = Vec::with_capacity(HEADER_LEN + ct_tag.len());
        envelope.push(context.version.as_byte());
        envelope.extend_from_slice(nonce);
        envelope.extend_from_slice(&(ct_tag.len() as u32).to_be_bytes());
        envelope.extend_from_slice(ct_tag);
        Ok(envelope)
    }

    /// Decrypt and verify an envelope.
    pub fn open(key: &[u8], envelope: &[u8], context: &EnvelopeContext) -> Result<Vec<u8>> {
        if envelope.len() < HEADER_LEN {
            return Err(CoreError::Crypto(prism_sync_crypto::CryptoError::DecryptionFailed(
                "envelope too short".into(),
            )));
        }

        let version = BootstrapVersion::from_byte(envelope[0]).ok_or_else(|| {
            CoreError::Crypto(prism_sync_crypto::CryptoError::DecryptionFailed(format!(
                "unknown envelope version: {}",
                envelope[0]
            )))
        })?;
        if version != context.version {
            return Err(CoreError::Crypto(prism_sync_crypto::CryptoError::DecryptionFailed(
                format!(
                    "envelope version mismatch: wire={}, context={}",
                    version.as_byte(),
                    context.version.as_byte()
                ),
            )));
        }

        let nonce = &envelope[VERSION_LEN..VERSION_LEN + NONCE_LEN];
        let len_bytes: [u8; 4] =
            envelope[VERSION_LEN + NONCE_LEN..HEADER_LEN].try_into().expect("4 bytes");
        let ct_len = u32::from_be_bytes(len_bytes) as usize;

        let remaining = envelope.len() - HEADER_LEN;
        if remaining != ct_len {
            return Err(CoreError::Crypto(prism_sync_crypto::CryptoError::DecryptionFailed(
                format!("ciphertext length mismatch: header says {ct_len}, got {remaining} bytes"),
            )));
        }

        let ct_tag = &envelope[HEADER_LEN..];

        // Reconstruct nonce || ciphertext+tag for the AEAD function
        let mut blob = Vec::with_capacity(NONCE_LEN + ct_tag.len());
        blob.extend_from_slice(nonce);
        blob.extend_from_slice(ct_tag);

        let aad = context.canonical_aad();
        let plaintext = aead::xchacha_decrypt_aead(key, &blob, &aad)?;
        Ok(plaintext)
    }

    /// Read the version byte from an envelope without decrypting.
    pub fn version(envelope: &[u8]) -> Result<BootstrapVersion> {
        if envelope.is_empty() {
            return Err(CoreError::Crypto(prism_sync_crypto::CryptoError::DecryptionFailed(
                "empty envelope".into(),
            )));
        }
        BootstrapVersion::from_byte(envelope[0]).ok_or_else(|| {
            CoreError::Crypto(prism_sync_crypto::CryptoError::DecryptionFailed(format!(
                "unknown envelope version: {}",
                envelope[0]
            )))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap::{BootstrapProfile, BootstrapRole};

    fn test_context<'a>() -> EnvelopeContext<'a> {
        EnvelopeContext {
            profile: BootstrapProfile::SyncPairing,
            version: BootstrapVersion::V1,
            sender_role: BootstrapRole::Initiator,
            purpose: b"sync_credentials",
            session_id: b"test-session-001",
            transcript_hash: &[0xAB; 32],
        }
    }

    #[test]
    fn envelope_round_trip() {
        let key = [42u8; 32];
        let plaintext = b"hello bootstrap world";
        let ctx = test_context();

        let envelope = EncryptedEnvelope::seal(&key, plaintext, &ctx).unwrap();
        let decrypted = EncryptedEnvelope::open(&key, &envelope, &ctx).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn envelope_tampered_ciphertext_rejected() {
        let key = [42u8; 32];
        let ctx = test_context();
        let mut envelope = EncryptedEnvelope::seal(&key, b"secret", &ctx).unwrap();

        // Flip a byte in the ciphertext region (after the 29-byte header)
        let last = envelope.len() - 1;
        envelope[last] ^= 0xFF;

        assert!(EncryptedEnvelope::open(&key, &envelope, &ctx).is_err());
    }

    #[test]
    fn envelope_tampered_version_rejected() {
        let key = [42u8; 32];
        let ctx = test_context();
        let mut envelope = EncryptedEnvelope::seal(&key, b"secret", &ctx).unwrap();

        // Change version byte to unknown value
        envelope[0] = 0xFF;

        assert!(EncryptedEnvelope::open(&key, &envelope, &ctx).is_err());
    }

    #[test]
    fn envelope_wrong_key_rejected() {
        let key = [42u8; 32];
        let wrong_key = [99u8; 32];
        let ctx = test_context();
        let envelope = EncryptedEnvelope::seal(&key, b"secret", &ctx).unwrap();

        assert!(EncryptedEnvelope::open(&wrong_key, &envelope, &ctx).is_err());
    }

    #[test]
    fn envelope_wrong_role_rejected() {
        let key = [42u8; 32];
        let ctx = test_context();
        let envelope = EncryptedEnvelope::seal(&key, b"secret", &ctx).unwrap();

        let wrong_ctx = EnvelopeContext { sender_role: BootstrapRole::Responder, ..test_context() };

        assert!(EncryptedEnvelope::open(&key, &envelope, &wrong_ctx).is_err());
    }

    #[test]
    fn envelope_wrong_purpose_rejected() {
        let key = [42u8; 32];
        let ctx = test_context();
        let envelope = EncryptedEnvelope::seal(&key, b"secret", &ctx).unwrap();

        let wrong_ctx = EnvelopeContext { purpose: b"wrong_purpose", ..test_context() };

        assert!(EncryptedEnvelope::open(&key, &envelope, &wrong_ctx).is_err());
    }

    #[test]
    fn envelope_wrong_session_id_rejected() {
        let key = [42u8; 32];
        let ctx = test_context();
        let envelope = EncryptedEnvelope::seal(&key, b"secret", &ctx).unwrap();

        let wrong_ctx = EnvelopeContext { session_id: b"different-session", ..test_context() };

        assert!(EncryptedEnvelope::open(&key, &envelope, &wrong_ctx).is_err());
    }

    #[test]
    fn envelope_wrong_transcript_hash_rejected() {
        let key = [42u8; 32];
        let ctx = test_context();
        let envelope = EncryptedEnvelope::seal(&key, b"secret", &ctx).unwrap();

        let wrong_hash = [0xCD; 32];
        let wrong_ctx = EnvelopeContext { transcript_hash: &wrong_hash, ..test_context() };

        assert!(EncryptedEnvelope::open(&key, &envelope, &wrong_ctx).is_err());
    }

    #[test]
    fn envelope_version_readable() {
        let key = [42u8; 32];
        let ctx = test_context();
        let envelope = EncryptedEnvelope::seal(&key, b"data", &ctx).unwrap();

        assert_eq!(EncryptedEnvelope::version(&envelope).unwrap(), BootstrapVersion::V1);
    }

    #[test]
    fn envelope_trailing_data_rejected() {
        let key = [42u8; 32];
        let ctx = test_context();
        let mut envelope = EncryptedEnvelope::seal(&key, b"secret", &ctx).unwrap();

        // Append trailing data
        envelope.push(0x00);
        envelope.push(0x01);

        assert!(EncryptedEnvelope::open(&key, &envelope, &ctx).is_err());
    }
}
