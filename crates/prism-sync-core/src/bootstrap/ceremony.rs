//! Ceremony orchestrators for the PQ hybrid device pairing protocol.
//!
//! [`JoinerCeremony`] drives the responder (joiner) side: generates keys,
//! uploads a bootstrap record, processes the initiator's `PairingInit`,
//! and exchanges encrypted credential/joiner bundles.
//!
//! [`InitiatorCeremony`] drives the initiator side: fetches the joiner's
//! bootstrap, verifies the commitment, encapsulates a shared secret,
//! and posts the `PairingInit` message.

use prism_sync_crypto::pq::hybrid_kem::XWingKem;
use prism_sync_crypto::DeviceSecret;
use std::sync::atomic::{AtomicBool, Ordering};
use zeroize::Zeroizing;

use super::pairing_models::*;
use super::pairing_transcript::build_sync_pairing_transcript;
use super::*;
use crate::error::{CoreError, Result};
use crate::relay::pairing_relay::PairingRelay;

/// Generate a CSPRNG-backed RNG suitable for `rand_core::CryptoRng`.
fn csprng() -> getrandom::rand_core::UnwrapErr<getrandom::SysRng> {
    getrandom::rand_core::UnwrapErr(getrandom::SysRng)
}

// ---------------------------------------------------------------------------
// JoinerCeremony
// ---------------------------------------------------------------------------

/// Drives the responder (joiner) side of the PQ hybrid pairing ceremony.
pub struct JoinerCeremony {
    device_secret: DeviceSecret,
    device_id: String,
    bootstrap_record: JoinerBootstrapRecord,
    /// Stored as zeroized seed bytes so we don't depend on `x_wing` types.
    xwing_dk_seed: Zeroizing<[u8; 32]>,
    rendezvous_id: [u8; 16],
    commitment: [u8; 32],
    #[allow(dead_code)]
    relay_url: String,

    // Set after processing pairing_init
    transcript_hash: Option<[u8; 32]>,
    key_schedule: Option<BootstrapKeySchedule>,
    confirmation: Option<ConfirmationCode>,
}

impl JoinerCeremony {
    /// Start the joiner ceremony: generate keys, upload bootstrap record,
    /// and return the ceremony state plus a rendezvous token for out-of-band
    /// transfer (QR code / deep link).
    pub async fn start(
        relay: &dyn PairingRelay,
        relay_url: &str,
    ) -> Result<(Self, RendezvousToken)> {
        // 1. Generate fresh device identity
        let device_secret = DeviceSecret::generate();
        let device_id = crate::node_id::generate_node_id();

        // 2. Derive keypairs
        let ed25519_kp = device_secret.ed25519_keypair(&device_id)?;
        let x25519_kp = device_secret.x25519_keypair(&device_id)?;
        let ml_dsa_65_kp = device_secret.ml_dsa_65_keypair(&device_id)?;
        // Permanent identity keys for the registry snapshot (V2).
        let permanent_ml_kem_kp = device_secret.ml_kem_768_keypair(&device_id)?;
        let permanent_xwing_kp = device_secret.xwing_keypair(&device_id)?;

        // 3. Generate ephemeral X-Wing keypair for the KEM handshake
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(seed.as_mut())
            .map_err(|e| CoreError::Engine(format!("CSPRNG failed: {e}")))?;
        let dk = XWingKem::decapsulation_key_from_bytes(&seed);
        let ek = XWingKem::encapsulation_key_bytes(&dk);

        // 4. Build bootstrap record (V2 includes permanent identity keys)
        let record = JoinerBootstrapRecord {
            version: BootstrapVersion::V2,
            device_id: device_id.clone(),
            ed25519_public_key: ed25519_kp.public_key_bytes(),
            x25519_public_key: x25519_kp.public_key_bytes(),
            ml_dsa_65_public_key: ml_dsa_65_kp.public_key_bytes(),
            xwing_ek: ek,
            permanent_ml_kem_768_public_key: permanent_ml_kem_kp.public_key_bytes().to_vec(),
            permanent_xwing_public_key: permanent_xwing_kp.encapsulation_key_bytes(),
        };
        // Drop large PQ types before the async relay call below. They are no
        // longer needed and their presence in the async state machine across
        // the .await would inflate the future size — ExpandedSigningKey<MlDsa65>
        // alone is ~48 KB — causing stack overflow on platforms with limited
        // tokio worker stacks (e.g. Android).
        drop(ml_dsa_65_kp);
        drop(permanent_ml_kem_kp);
        drop(permanent_xwing_kp);
        drop(dk);
        drop(ed25519_kp);
        drop(x25519_kp);

        // 5. Upload to relay
        let rendezvous_id = relay
            .create_session(&record.to_canonical_bytes())
            .await
            .map_err(|e| CoreError::Engine(format!("failed to create pairing session: {e}")))?;

        // 6. Build token
        let commitment = record.commitment();
        let token = RendezvousToken::new(rendezvous_id, &record, relay_url.to_string());

        Ok((
            Self {
                device_secret,
                device_id,
                bootstrap_record: record,
                xwing_dk_seed: seed,
                rendezvous_id,
                commitment,
                relay_url: relay_url.to_string(),
                transcript_hash: None,
                key_schedule: None,
                confirmation: None,
            },
            token,
        ))
    }

    /// Process the initiator's `PairingInit` message and derive the SAS
    /// display codes for user verification.
    pub fn process_pairing_init(&mut self, pairing_init_bytes: &[u8]) -> Result<SasDisplay> {
        // 1. Parse
        let init = PairingInit::from_bytes(pairing_init_bytes)
            .ok_or_else(|| CoreError::Engine("failed to parse PairingInit".into()))?;

        // 2. Reconstruct dk from seed and decapsulate
        let dk = XWingKem::decapsulation_key_from_bytes(&self.xwing_dk_seed);
        let secret = DefaultBootstrapHandshake::decapsulate_from_peer(&dk, &init.kem_ciphertext)?;

        // 3. Build initiator's public keys
        let initiator_keys = PairingPublicKeys {
            device_id: init.device_id.clone(),
            ed25519_pk: init.ed25519_public_key,
            x25519_pk: init.x25519_public_key,
            ml_dsa_65_pk: init.ml_dsa_65_public_key.clone(),
            xwing_ek: init.xwing_ek.clone(),
        };

        // 4. Build transcript
        let transcript_hash = build_sync_pairing_transcript(
            &self.rendezvous_id,
            &self.commitment,
            &initiator_keys,
            &self.bootstrap_record,
            &init.kem_ciphertext,
            &init.relay_origin,
        );

        // 5. Derive key schedule
        let key_schedule = BootstrapKeySchedule::derive(
            BootstrapProfile::SyncPairing,
            BootstrapVersion::V1,
            secret,
            &transcript_hash,
        )?;

        // 6. Build confirmation
        let confirmation = ConfirmationCode::new(
            BootstrapProfile::SyncPairing,
            BootstrapVersion::V1,
            &key_schedule,
            transcript_hash,
        );

        // 7. Verify initiator's MAC
        confirmation.verify_confirmation(&init.confirmation_mac, BootstrapRole::Initiator)?;

        // 8. Store state
        let sas =
            SasDisplay { words: confirmation.sas_words(), decimal: confirmation.sas_decimal() };
        self.transcript_hash = Some(transcript_hash);
        self.key_schedule = Some(key_schedule);
        self.confirmation = Some(confirmation);

        // 9. Return SAS display
        Ok(sas)
    }

    /// Return the joiner's confirmation MAC (responder role).
    pub fn confirmation_mac(&self) -> Result<Vec<u8>> {
        let confirmation = self
            .confirmation
            .as_ref()
            .ok_or_else(|| CoreError::Engine("confirmation not yet derived".into()))?;
        Ok(confirmation.confirmation_mac(BootstrapRole::Responder))
    }

    /// Decrypt the credential bundle sent by the initiator.
    pub fn decrypt_credentials(&self, envelope_bytes: &[u8]) -> Result<CredentialBundle> {
        let key_schedule = self
            .key_schedule
            .as_ref()
            .ok_or_else(|| CoreError::Engine("key schedule not yet derived".into()))?;
        let transcript_hash = self
            .transcript_hash
            .as_ref()
            .ok_or_else(|| CoreError::Engine("transcript hash not yet derived".into()))?;

        let key = key_schedule.encryption_key(BootstrapRole::Initiator);
        let context = EnvelopeContext {
            profile: BootstrapProfile::SyncPairing,
            version: BootstrapVersion::V1,
            sender_role: BootstrapRole::Initiator,
            purpose: b"sync_credentials",
            session_id: &self.rendezvous_id,
            transcript_hash,
        };

        let plaintext = EncryptedEnvelope::open(key, envelope_bytes, &context)?;
        let bundle: CredentialBundle = serde_json::from_slice(&plaintext)?;
        Ok(bundle)
    }

    /// Encrypt the joiner's device bundle for the initiator.
    pub fn encrypt_joiner_bundle(&self) -> Result<Vec<u8>> {
        let key_schedule = self
            .key_schedule
            .as_ref()
            .ok_or_else(|| CoreError::Engine("key schedule not yet derived".into()))?;
        let transcript_hash = self
            .transcript_hash
            .as_ref()
            .ok_or_else(|| CoreError::Engine("transcript hash not yet derived".into()))?;
        let ml_kem_768_keypair = self.device_secret.ml_kem_768_keypair(&self.device_id)?;

        let bundle = JoinerBundle {
            device_id: self.device_id.clone(),
            ed25519_public_key: self.bootstrap_record.ed25519_public_key.to_vec(),
            x25519_public_key: self.bootstrap_record.x25519_public_key.to_vec(),
            ml_dsa_65_public_key: self.bootstrap_record.ml_dsa_65_public_key.clone(),
            ml_kem_768_ek: ml_kem_768_keypair.public_key_bytes(),
        };

        let json = serde_json::to_vec(&bundle)?;
        let key = key_schedule.encryption_key(BootstrapRole::Responder);
        let context = EnvelopeContext {
            profile: BootstrapProfile::SyncPairing,
            version: BootstrapVersion::V1,
            sender_role: BootstrapRole::Responder,
            purpose: b"joiner_device_bundle",
            session_id: &self.rendezvous_id,
            transcript_hash,
        };

        EncryptedEnvelope::seal(key, &json, &context)
    }

    /// The joiner's device secret.
    pub fn device_secret(&self) -> &DeviceSecret {
        &self.device_secret
    }

    /// The joiner's device ID.
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    /// The raw 16-byte rendezvous ID.
    pub fn rendezvous_id(&self) -> &[u8; 16] {
        &self.rendezvous_id
    }

    /// Hex-encoded rendezvous ID.
    pub fn rendezvous_id_hex(&self) -> String {
        hex::encode(self.rendezvous_id)
    }
}

// ---------------------------------------------------------------------------
// InitiatorCeremony
// ---------------------------------------------------------------------------

/// Drives the initiator side of the PQ hybrid pairing ceremony.
pub struct InitiatorCeremony {
    rendezvous_id: [u8; 16],
    #[allow(dead_code)]
    commitment: [u8; 32],
    #[allow(dead_code)]
    relay_url: String,
    bootstrap_record: JoinerBootstrapRecord,
    #[allow(dead_code)]
    local_keys: PairingPublicKeys,
    transcript_hash: [u8; 32],
    key_schedule: BootstrapKeySchedule,
    confirmation: ConfirmationCode,
    joiner_confirmation_verified: AtomicBool,
    #[allow(dead_code)]
    kem_ciphertext: Vec<u8>,
}

impl InitiatorCeremony {
    /// Start the initiator ceremony: fetch the joiner's bootstrap, verify
    /// the commitment, encapsulate a shared secret, post `PairingInit`, and
    /// return the ceremony state plus SAS display codes.
    pub async fn start(
        token: RendezvousToken,
        relay: &dyn PairingRelay,
        device_secret: &DeviceSecret,
        device_id: &str,
    ) -> Result<(Self, SasDisplay)> {
        // 1. Fetch bootstrap record
        let bootstrap_bytes = relay
            .get_bootstrap(&token.rendezvous_id_hex())
            .await
            .map_err(|e| CoreError::Engine(format!("failed to fetch bootstrap: {e}")))?;

        // 2. Parse
        let record = JoinerBootstrapRecord::from_canonical_bytes(&bootstrap_bytes)
            .ok_or_else(|| CoreError::Engine("failed to parse JoinerBootstrapRecord".into()))?;

        // 3. Verify commitment (CRITICAL: catches relay key substitution)
        if !token.verify_commitment(&record) {
            return Err(CoreError::Engine(
                "bootstrap commitment mismatch: possible relay key substitution attack".into(),
            ));
        }

        // 4. Build local public keys
        let ed25519_kp = device_secret.ed25519_keypair(device_id)?;
        let x25519_kp = device_secret.x25519_keypair(device_id)?;
        let ml_dsa_65_kp = device_secret.ml_dsa_65_keypair(device_id)?;

        let mut xwing_seed = [0u8; 32];
        getrandom::fill(&mut xwing_seed)
            .map_err(|e| CoreError::Engine(format!("CSPRNG failed: {e}")))?;
        let local_xwing_dk = XWingKem::decapsulation_key_from_bytes(&xwing_seed);
        let local_xwing_ek = XWingKem::encapsulation_key_bytes(&local_xwing_dk);

        let local_keys = PairingPublicKeys {
            device_id: device_id.to_string(),
            ed25519_pk: ed25519_kp.public_key_bytes(),
            x25519_pk: x25519_kp.public_key_bytes(),
            ml_dsa_65_pk: ml_dsa_65_kp.public_key_bytes(),
            xwing_ek: local_xwing_ek,
        };
        // Drop large PQ types before the async relay call below — same reason
        // as JoinerCeremony::start: keep the future state machine small.
        drop(ml_dsa_65_kp);
        drop(local_xwing_dk);
        drop(ed25519_kp);
        drop(x25519_kp);

        // 5. Encapsulate to joiner's X-Wing ek
        let (kem_ciphertext, secret) =
            DefaultBootstrapHandshake::encapsulate_to_peer(&record.xwing_ek, &mut csprng())?;

        // 6. Build transcript
        let commitment = token.commitment;
        let transcript_hash = build_sync_pairing_transcript(
            &token.rendezvous_id,
            &commitment,
            &local_keys,
            &record,
            &kem_ciphertext,
            &token.relay_url_hint,
        );

        // 7. Derive key schedule
        let key_schedule = BootstrapKeySchedule::derive(
            BootstrapProfile::SyncPairing,
            BootstrapVersion::V1,
            secret,
            &transcript_hash,
        )?;

        // 8. Build confirmation
        let confirmation = ConfirmationCode::new(
            BootstrapProfile::SyncPairing,
            BootstrapVersion::V1,
            &key_schedule,
            transcript_hash,
        );

        // 9. Build PairingInit
        let init_mac = confirmation.confirmation_mac(BootstrapRole::Initiator);
        let init = PairingInit {
            version: BootstrapVersion::V1,
            device_id: device_id.to_string(),
            ed25519_public_key: local_keys.ed25519_pk,
            x25519_public_key: local_keys.x25519_pk,
            ml_dsa_65_public_key: local_keys.ml_dsa_65_pk.clone(),
            xwing_ek: local_keys.xwing_ek.clone(),
            kem_ciphertext: kem_ciphertext.clone(),
            confirmation_mac: init_mac,
            relay_origin: token.relay_url_hint.clone(),
        };

        // 10. Post to relay
        use crate::relay::pairing_relay::PairingSlot;
        relay
            .put_slot(&token.rendezvous_id_hex(), PairingSlot::Init, &init.to_bytes())
            .await
            .map_err(|e| CoreError::Engine(format!("failed to post PairingInit: {e}")))?;

        let sas =
            SasDisplay { words: confirmation.sas_words(), decimal: confirmation.sas_decimal() };

        Ok((
            Self {
                rendezvous_id: token.rendezvous_id,
                commitment,
                relay_url: token.relay_url_hint,
                bootstrap_record: record,
                local_keys,
                transcript_hash,
                key_schedule,
                confirmation,
                joiner_confirmation_verified: AtomicBool::new(false),
                kem_ciphertext,
            },
            sas,
        ))
    }

    /// Verify the joiner's confirmation MAC.
    pub fn verify_joiner_confirmation(&self, mac_bytes: &[u8]) -> Result<()> {
        self.confirmation.verify_confirmation(mac_bytes, BootstrapRole::Responder)?;
        self.joiner_confirmation_verified.store(true, Ordering::Release);
        Ok(())
    }

    /// Encrypt a credential bundle for the joiner.
    pub fn encrypt_credentials(&self, credentials: &CredentialBundle) -> Result<Vec<u8>> {
        if !self.joiner_confirmation_verified.load(Ordering::Acquire) {
            return Err(CoreError::Engine(
                "joiner confirmation must be verified before sending credentials".into(),
            ));
        }
        let json = serde_json::to_vec(credentials)?;
        let key = self.key_schedule.encryption_key(BootstrapRole::Initiator);
        let context = EnvelopeContext {
            profile: BootstrapProfile::SyncPairing,
            version: BootstrapVersion::V1,
            sender_role: BootstrapRole::Initiator,
            purpose: b"sync_credentials",
            session_id: &self.rendezvous_id,
            transcript_hash: &self.transcript_hash,
        };
        EncryptedEnvelope::seal(key, &json, &context)
    }

    /// Decrypt the joiner's device bundle.
    pub fn decrypt_joiner_bundle(&self, envelope_bytes: &[u8]) -> Result<JoinerBundle> {
        let key = self.key_schedule.encryption_key(BootstrapRole::Responder);
        let context = EnvelopeContext {
            profile: BootstrapProfile::SyncPairing,
            version: BootstrapVersion::V1,
            sender_role: BootstrapRole::Responder,
            purpose: b"joiner_device_bundle",
            session_id: &self.rendezvous_id,
            transcript_hash: &self.transcript_hash,
        };
        let plaintext = EncryptedEnvelope::open(key, envelope_bytes, &context)?;
        let bundle: JoinerBundle = serde_json::from_slice(&plaintext)?;
        Ok(bundle)
    }

    /// Hex-encoded rendezvous ID.
    pub fn rendezvous_id_hex(&self) -> String {
        hex::encode(self.rendezvous_id)
    }

    /// The transcript hash binding this session.
    pub fn transcript_hash(&self) -> &[u8; 32] {
        &self.transcript_hash
    }

    /// The joiner's device ID, known from the bootstrap record fetched at
    /// ceremony start. Used by the initiator to target `for_device_id` on
    /// the pairing snapshot so the joiner's subsequent
    /// `DELETE /v1/sync/{id}/snapshot` ACK passes the relay's auth check.
    pub fn joiner_device_id(&self) -> &str {
        &self.bootstrap_record.device_id
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::pairing_relay::{MockPairingRelay, PairingSlot};

    fn test_credentials() -> CredentialBundle {
        CredentialBundle {
            sync_id: "test-sync-001".to_string(),
            relay_url: "https://relay.example.com".to_string(),
            mnemonic: "word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12"
                .to_string(),
            wrapped_dek: vec![0xAA; 56],
            salt: vec![0xBB; 32],
            current_epoch: 1,
            epoch_key: vec![0xCC; 32],
            signed_keyring: vec![0xDD; 128],
            inviter_device_id: "inviter-dev".to_string(),
            inviter_ed25519_pk: vec![0xEE; 32],
            inviter_ml_dsa_65_pk: Vec::new(),
            registry_approval_signature: None,
            registration_token: None,
        }
    }

    /// Helper: run the full ceremony up to SAS verification.
    async fn run_ceremony_to_sas(
        relay: &MockPairingRelay,
    ) -> (JoinerCeremony, InitiatorCeremony, SasDisplay, SasDisplay) {
        let relay_url = "https://relay.example.com";

        // Joiner starts
        let (mut joiner, token) = JoinerCeremony::start(relay, relay_url).await.unwrap();

        // Initiator starts
        let initiator_secret = DeviceSecret::generate();
        let initiator_device_id = crate::node_id::generate_node_id();
        let (initiator, initiator_sas) =
            InitiatorCeremony::start(token, relay, &initiator_secret, &initiator_device_id)
                .await
                .unwrap();

        // Joiner processes init
        let init_bytes = relay
            .get_slot(&joiner.rendezvous_id_hex(), PairingSlot::Init)
            .await
            .unwrap()
            .expect("init slot should be populated");
        let joiner_sas = joiner.process_pairing_init(&init_bytes).unwrap();

        (joiner, initiator, joiner_sas, initiator_sas)
    }

    #[tokio::test]
    async fn full_ceremony_round_trip() {
        let relay = MockPairingRelay::new();
        let (joiner, initiator, joiner_sas, initiator_sas) = run_ceremony_to_sas(&relay).await;

        // SAS codes match
        assert_eq!(joiner_sas.words, initiator_sas.words);
        assert_eq!(joiner_sas.decimal, initiator_sas.decimal);

        // Joiner sends confirmation MAC
        let joiner_mac = joiner.confirmation_mac().unwrap();

        // Initiator verifies MAC
        initiator.verify_joiner_confirmation(&joiner_mac).unwrap();

        // Initiator encrypts credentials
        let creds = test_credentials();
        let cred_envelope = initiator.encrypt_credentials(&creds).unwrap();

        // Joiner decrypts credentials
        let decrypted_creds = joiner.decrypt_credentials(&cred_envelope).unwrap();
        assert_eq!(decrypted_creds.sync_id, creds.sync_id);
        assert_eq!(decrypted_creds.mnemonic, creds.mnemonic);
        assert_eq!(decrypted_creds.wrapped_dek, creds.wrapped_dek);

        // Joiner encrypts joiner bundle
        let joiner_envelope = joiner.encrypt_joiner_bundle().unwrap();

        // Initiator decrypts joiner bundle
        let joiner_bundle = initiator.decrypt_joiner_bundle(&joiner_envelope).unwrap();
        assert_eq!(joiner_bundle.device_id, joiner.device_id());
        assert_eq!(
            joiner_bundle.ed25519_public_key,
            joiner.bootstrap_record.ed25519_public_key.to_vec()
        );
        assert_eq!(
            joiner_bundle.ml_kem_768_ek,
            joiner
                .device_secret()
                .ml_kem_768_keypair(joiner.device_id())
                .unwrap()
                .public_key_bytes()
        );
    }

    #[tokio::test]
    async fn commitment_mismatch_aborts() {
        let relay = MockPairingRelay::new();
        let relay_url = "https://relay.example.com";

        // Joiner starts
        let (_joiner, token) = JoinerCeremony::start(&relay, relay_url).await.unwrap();

        // Construct a token with wrong commitment to simulate relay tampering
        let tampered_token = RendezvousToken {
            version: token.version,
            rendezvous_id: token.rendezvous_id,
            commitment: [0xFF; 32],
            relay_url_hint: token.relay_url_hint.clone(),
        };

        let initiator_secret = DeviceSecret::generate();
        let initiator_device_id = crate::node_id::generate_node_id();
        let result = InitiatorCeremony::start(
            tampered_token,
            &relay,
            &initiator_secret,
            &initiator_device_id,
        )
        .await;

        let err_msg = result.err().expect("should fail with commitment mismatch").to_string();
        assert!(
            err_msg.contains("commitment mismatch"),
            "expected commitment mismatch error, got: {err_msg}"
        );
    }

    #[tokio::test]
    async fn wrong_confirmation_mac_rejected() {
        let relay = MockPairingRelay::new();
        let (joiner, initiator, _, _) = run_ceremony_to_sas(&relay).await;

        let mut mac = joiner.confirmation_mac().unwrap();
        mac[0] ^= 0xFF; // tamper

        let result = initiator.verify_joiner_confirmation(&mac);
        assert!(result.is_err(), "tampered MAC should be rejected");
    }

    #[tokio::test]
    async fn credential_encryption_requires_joiner_confirmation() {
        let relay = MockPairingRelay::new();
        let (joiner, initiator, _, _) = run_ceremony_to_sas(&relay).await;

        let creds = test_credentials();
        let pre_confirm = initiator.encrypt_credentials(&creds);
        assert!(
            pre_confirm.is_err(),
            "credential encryption must be blocked before confirmation verification"
        );

        let joiner_mac = joiner.confirmation_mac().unwrap();
        initiator.verify_joiner_confirmation(&joiner_mac).unwrap();

        let post_confirm = initiator.encrypt_credentials(&creds);
        assert!(
            post_confirm.is_ok(),
            "credential encryption should succeed after confirmation verification"
        );
    }

    #[tokio::test]
    async fn credential_wrong_key_fails() {
        let relay = MockPairingRelay::new();
        let (joiner, initiator, _, _) = run_ceremony_to_sas(&relay).await;

        let joiner_mac = joiner.confirmation_mac().unwrap();
        initiator.verify_joiner_confirmation(&joiner_mac).unwrap();

        // Encrypt credentials with initiator
        let creds = test_credentials();
        let cred_envelope = initiator.encrypt_credentials(&creds).unwrap();

        // Run a second independent ceremony to get a different key schedule
        let relay2 = MockPairingRelay::new();
        let (joiner2, _, _, _) = run_ceremony_to_sas(&relay2).await;

        // Try to decrypt with the wrong joiner's key schedule
        let result = joiner2.decrypt_credentials(&cred_envelope);
        assert!(result.is_err(), "decryption with wrong key schedule should fail");

        // Correct joiner should still succeed
        let _ = joiner.decrypt_credentials(&cred_envelope).unwrap();
    }

    #[tokio::test]
    async fn both_sides_same_sas() {
        let relay = MockPairingRelay::new();
        let (_joiner, _initiator, joiner_sas, initiator_sas) = run_ceremony_to_sas(&relay).await;

        assert_eq!(joiner_sas.words, initiator_sas.words);
        assert_eq!(joiner_sas.decimal, initiator_sas.decimal);
        assert!(!joiner_sas.words.is_empty());
        assert_eq!(joiner_sas.decimal.len(), 6);
    }

    #[tokio::test]
    async fn different_sessions_different_sas() {
        let relay1 = MockPairingRelay::new();
        let (_, _, sas1_joiner, _) = run_ceremony_to_sas(&relay1).await;

        let relay2 = MockPairingRelay::new();
        let (_, _, sas2_joiner, _) = run_ceremony_to_sas(&relay2).await;

        // Different sessions should produce different SAS codes
        // (probabilistically; with 32-byte shared secrets this is certain)
        assert_ne!(
            sas1_joiner.words, sas2_joiner.words,
            "independent sessions should produce different SAS words"
        );
    }
}
