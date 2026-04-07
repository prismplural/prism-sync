//! End-to-end integration test for the bootstrap module.
//!
//! Simulates a full handshake between an initiator and a responder:
//! keygen → encapsulate → transcript → key schedule → encrypt → SAS → confirm.

#[cfg(test)]
mod tests {
    use prism_sync_crypto::pq::hybrid_kem::XWingKem;

    use crate::bootstrap::confirmation::{ConfirmationCode, PublicFingerprint};
    use crate::bootstrap::encrypted_envelope::{EncryptedEnvelope, EnvelopeContext};
    use crate::bootstrap::handshake::BootstrapHandshake;
    use crate::bootstrap::key_schedule::BootstrapKeySchedule;
    use crate::bootstrap::transcript::BootstrapTranscript;
    use crate::bootstrap::{BootstrapProfile, BootstrapRole, BootstrapVersion};

    fn rng() -> getrandom::rand_core::UnwrapErr<getrandom::SysRng> {
        getrandom::rand_core::UnwrapErr(getrandom::SysRng)
    }

    /// Full bootstrap ceremony — both sides derive the same SAS and can
    /// verify each other's confirmation MAC.
    #[test]
    fn full_bootstrap_ceremony() {
        let profile = BootstrapProfile::SyncPairing;
        let version = BootstrapVersion::V1;
        let session_id = b"rendezvous-abc-123";

        // --- Responder generates ephemeral X-Wing keypair ---
        let responder_dk = XWingKem::decapsulation_key_from_bytes(&[7u8; 32]);
        let responder_ek_bytes = XWingKem::encapsulation_key_bytes(&responder_dk);

        // --- Initiator encapsulates to responder's EK ---
        let (ciphertext, initiator_secret) =
            BootstrapHandshake::<XWingKem>::encapsulate_to_peer(&responder_ek_bytes, &mut rng())
                .unwrap();

        // --- Responder decapsulates ---
        let responder_secret =
            BootstrapHandshake::<XWingKem>::decapsulate_from_peer(&responder_dk, &ciphertext)
                .unwrap();

        // Shared secrets must agree
        assert_eq!(initiator_secret.as_bytes(), responder_secret.as_bytes());

        // --- Both sides build the same transcript ---
        let build_transcript = |ek_bytes: &[u8], ct: &[u8]| {
            let mut t = BootstrapTranscript::new(profile, version);
            t.append_session_id(session_id);
            t.append_role_fixed(BootstrapRole::Initiator, b"ed25519_pk", &[1u8; 32]);
            t.append_role_fixed(BootstrapRole::Responder, b"ed25519_pk", &[2u8; 32]);
            t.append_role_fixed(BootstrapRole::Initiator, b"x25519_pk", &[3u8; 32]);
            t.append_role_fixed(BootstrapRole::Responder, b"x25519_pk", &[4u8; 32]);
            t.append_role_bytes(BootstrapRole::Initiator, b"ml_dsa_65_pk", &[5u8; 1952]);
            t.append_role_bytes(BootstrapRole::Responder, b"ml_dsa_65_pk", &[6u8; 1952]);
            t.append_role_bytes(BootstrapRole::Initiator, b"ml_kem_768_ek", &[7u8; 1184]);
            t.append_role_bytes(BootstrapRole::Responder, b"ml_kem_768_ek", ek_bytes);
            t.append_bytes(b"kem_ciphertext", ct);
            t.append_bytes(b"relay_origin", b"wss://relay.example.com");
            t.append_fixed(b"bootstrap_commitment", &[0xABu8; 32]);
            t.finalize()
        };

        let initiator_hash = build_transcript(&responder_ek_bytes, &ciphertext);
        let responder_hash = build_transcript(&responder_ek_bytes, &ciphertext);
        assert_eq!(initiator_hash, responder_hash);

        // --- Both sides derive key schedules ---
        let initiator_ks =
            BootstrapKeySchedule::derive(profile, version, initiator_secret, &initiator_hash)
                .unwrap();
        let responder_ks =
            BootstrapKeySchedule::derive(profile, version, responder_secret, &responder_hash)
                .unwrap();

        // Keys must agree
        assert_eq!(
            initiator_ks.encryption_key(BootstrapRole::Initiator),
            responder_ks.encryption_key(BootstrapRole::Initiator),
        );
        assert_eq!(
            initiator_ks.encryption_key(BootstrapRole::Responder),
            responder_ks.encryption_key(BootstrapRole::Responder),
        );
        assert_eq!(
            initiator_ks.confirmation_key(),
            responder_ks.confirmation_key(),
        );
        assert_eq!(
            initiator_ks.verification_key(),
            responder_ks.verification_key(),
        );

        // --- Both sides derive the same SAS ---
        let initiator_confirm =
            ConfirmationCode::new(profile, version, &initiator_ks, initiator_hash);
        let responder_confirm =
            ConfirmationCode::new(profile, version, &responder_ks, responder_hash);

        assert_eq!(initiator_confirm.sas_words(), responder_confirm.sas_words());
        assert_eq!(
            initiator_confirm.sas_decimal(),
            responder_confirm.sas_decimal(),
        );
        assert_eq!(
            initiator_confirm.session_fingerprint(),
            responder_confirm.session_fingerprint(),
        );

        // --- Initiator encrypts credential bundle ---
        let credential_bundle = b"mnemonic=foo wrapped_dek=bar salt=baz epoch_key=qux";
        let i2r_context = EnvelopeContext {
            profile,
            version,
            sender_role: BootstrapRole::Initiator,
            purpose: b"sync_credentials",
            session_id,
            transcript_hash: &initiator_hash,
        };

        let envelope = EncryptedEnvelope::seal(
            initiator_ks.encryption_key(BootstrapRole::Initiator),
            credential_bundle,
            &i2r_context,
        )
        .unwrap();

        // --- Responder decrypts credential bundle ---
        let r2i_context = EnvelopeContext {
            profile,
            version,
            sender_role: BootstrapRole::Initiator,
            purpose: b"sync_credentials",
            session_id,
            transcript_hash: &responder_hash,
        };

        let plaintext = EncryptedEnvelope::open(
            responder_ks.encryption_key(BootstrapRole::Initiator),
            &envelope,
            &r2i_context,
        )
        .unwrap();

        assert_eq!(plaintext, credential_bundle);

        // --- HMAC confirmation exchange ---
        let initiator_mac = initiator_confirm.confirmation_mac(BootstrapRole::Initiator);
        let responder_mac = responder_confirm.confirmation_mac(BootstrapRole::Responder);

        // Each side verifies the other's MAC
        responder_confirm
            .verify_confirmation(&initiator_mac, BootstrapRole::Initiator)
            .expect("responder should verify initiator's MAC");
        initiator_confirm
            .verify_confirmation(&responder_mac, BootstrapRole::Responder)
            .expect("initiator should verify responder's MAC");

        // Reflection attack: initiator MAC must not verify as responder
        assert!(
            responder_confirm
                .verify_confirmation(&initiator_mac, BootstrapRole::Responder)
                .is_err(),
            "reflection attack should be rejected"
        );
    }

    /// Tampered transcript produces different SAS on both sides.
    #[test]
    fn tampered_transcript_different_sas() {
        let profile = BootstrapProfile::SyncPairing;
        let version = BootstrapVersion::V1;

        let dk = XWingKem::decapsulation_key_from_bytes(&[42u8; 32]);
        let ek_bytes = XWingKem::encapsulation_key_bytes(&dk);
        let (ct, secret1) =
            BootstrapHandshake::<XWingKem>::encapsulate_to_peer(&ek_bytes, &mut rng()).unwrap();
        let secret2 = BootstrapHandshake::<XWingKem>::decapsulate_from_peer(&dk, &ct).unwrap();

        // Honest transcript
        let mut t1 = BootstrapTranscript::new(profile, version);
        t1.append_session_id(b"session-1");
        t1.append_bytes(b"kem_ciphertext", &ct);
        let hash1 = t1.finalize();

        // Tampered transcript (different session_id)
        let mut t2 = BootstrapTranscript::new(profile, version);
        t2.append_session_id(b"session-TAMPERED");
        t2.append_bytes(b"kem_ciphertext", &ct);
        let hash2 = t2.finalize();

        assert_ne!(hash1, hash2);

        let ks1 = BootstrapKeySchedule::derive(profile, version, secret1, &hash1).unwrap();
        let ks2 = BootstrapKeySchedule::derive(profile, version, secret2, &hash2).unwrap();

        let c1 = ConfirmationCode::new(profile, version, &ks1, hash1);
        let c2 = ConfirmationCode::new(profile, version, &ks2, hash2);

        assert_ne!(c1.sas_words(), c2.sas_words());
    }

    /// Encrypted envelope rejects decryption with wrong key schedule.
    #[test]
    fn wrong_key_schedule_fails_decryption() {
        let profile = BootstrapProfile::SyncPairing;
        let version = BootstrapVersion::V1;
        let session_id = b"session-xyz";
        let transcript_hash = [99u8; 32];

        // Two different key schedules
        let dk1 = XWingKem::decapsulation_key_from_bytes(&[1u8; 32]);
        let ek1 = XWingKem::encapsulation_key_bytes(&dk1);
        let (_ct1, secret1) =
            BootstrapHandshake::<XWingKem>::encapsulate_to_peer(&ek1, &mut rng()).unwrap();
        let ks1 =
            BootstrapKeySchedule::derive(profile, version, secret1, &transcript_hash).unwrap();

        let dk2 = XWingKem::decapsulation_key_from_bytes(&[2u8; 32]);
        let ek2 = XWingKem::encapsulation_key_bytes(&dk2);
        let (_ct2, secret2) =
            BootstrapHandshake::<XWingKem>::encapsulate_to_peer(&ek2, &mut rng()).unwrap();
        let ks2 =
            BootstrapKeySchedule::derive(profile, version, secret2, &transcript_hash).unwrap();

        let context = EnvelopeContext {
            profile,
            version,
            sender_role: BootstrapRole::Initiator,
            purpose: b"test",
            session_id,
            transcript_hash: &transcript_hash,
        };

        let envelope = EncryptedEnvelope::seal(
            ks1.encryption_key(BootstrapRole::Initiator),
            b"secret data",
            &context,
        )
        .unwrap();

        // Try to open with a different key
        let result = EncryptedEnvelope::open(
            ks2.encryption_key(BootstrapRole::Initiator),
            &envelope,
            &context,
        );
        assert!(result.is_err());
    }

    /// Public fingerprint consistency across independent computations.
    #[test]
    fn public_fingerprint_stable() {
        let profile = BootstrapProfile::RemoteSharing;
        let version = BootstrapVersion::V1;

        let fields: &[(&[u8], &[u8])] =
            &[(b"ed25519_pk", &[1u8; 32]), (b"ml_dsa_65_pk", &[2u8; 1952])];

        let fp1 = PublicFingerprint::from_public_fields(
            profile,
            version,
            b"sharing_identity_bundle",
            fields,
        );
        let fp2 = PublicFingerprint::from_public_fields(
            profile,
            version,
            b"sharing_identity_bundle",
            fields,
        );

        assert_eq!(fp1.as_bytes(), fp2.as_bytes());
        assert_eq!(fp1.hex().len(), 64);

        // Different purpose → different fingerprint
        let fp3 = PublicFingerprint::from_public_fields(
            profile,
            version,
            b"signed_prekey_bundle",
            fields,
        );
        assert_ne!(fp1.as_bytes(), fp3.as_bytes());

        // Different profile → different fingerprint
        let fp4 = PublicFingerprint::from_public_fields(
            BootstrapProfile::SyncPairing,
            version,
            b"sharing_identity_bundle",
            fields,
        );
        assert_ne!(fp1.as_bytes(), fp4.as_bytes());
    }
}
