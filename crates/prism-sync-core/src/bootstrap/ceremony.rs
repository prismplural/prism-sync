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
use sha2::Digest;
use std::sync::atomic::{AtomicBool, Ordering};
use zeroize::Zeroizing;

use super::pairing_models::*;
use super::pairing_transcript::build_sync_pairing_transcript;
use super::*;
use crate::error::{CoreError, Result};
use crate::pairing::lease::{
    classify_confirmation_frame, compute_lease_key_hash, open_extended_confirmation,
    seal_extended_confirmation, ConfirmationFrame, LeaseCapability, LeaseCapabilityFrame,
    LeaseNegotiation, VerifiedInitiatorState, LEASE_SECRET_LEN, LEASE_VERSION_V1,
};
use crate::relay::pairing_relay::{PairingLeaseOffer, PairingRelay, PairingSlot};

/// Generate a CSPRNG-backed RNG suitable for `rand_core::CryptoRng`.
fn csprng() -> getrandom::rand_core::UnwrapErr<getrandom::SysRng> {
    getrandom::rand_core::UnwrapErr(getrandom::SysRng)
}

fn sas_display_from_confirmation(confirmation: &ConfirmationCode) -> SasDisplay {
    SasDisplay {
        version: PAIRING_SAS_VERSION,
        words: confirmation.sas_words(),
        word_list: confirmation.sas_word_list(),
    }
}

fn diag_hash(bytes: &[u8]) -> String {
    let digest = sha2::Sha256::digest(bytes);
    hex::encode(&digest[..8])
}

fn diag_prefix(bytes: &[u8]) -> String {
    hex::encode(&bytes[..bytes.len().min(8)])
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

    // ── Pairing lease negotiation ──
    /// Random 32-byte lease secret, generated before session creation and
    /// committed to the relay as `SHA-256(secret)`. It is delivered to the
    /// initiator only inside the extended protected confirmation, and only when
    /// all three parties negotiate lease v1. Zeroized on drop.
    lease_secret: Zeroizing<[u8; LEASE_SECRET_LEN]>,
    /// The relay's create-time lease echo. Absent on old relays, which means
    /// fixed-TTL pairing; only the response is authoritative.
    relay_lease_version: Option<u16>,
    /// The initiator's authenticated lease capability, recorded only after
    /// cryptographic verification of the optional slot. Interior mutability
    /// matches the existing `AtomicBool` pattern: the surrounding
    /// `PairingService` holds `&JoinerCeremony` across the ceremony.
    lease_capability: std::sync::Mutex<Option<LeaseCapability>>,
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

        // 5. Generate the lease secret and commit only its verifier.
        //
        // The secret is independent: never derived from or reused as a SAS
        // value, mnemonic, PIN, rendezvous ID, request-signing key, snapshot
        // key, or credential-encryption key. The relay stores only the opaque
        // SHA-256 verifier, and committing it at create time is what prevents a
        // rendezvous-ID thief from acquiring renewal authority later.
        let mut lease_secret = Zeroizing::new([0u8; LEASE_SECRET_LEN]);
        getrandom::fill(lease_secret.as_mut())
            .map_err(|e| CoreError::Engine(format!("CSPRNG failed: {e}")))?;
        let lease_key_hash = compute_lease_key_hash(&lease_secret);
        let lease_offer =
            PairingLeaseOffer { lease_key_hash: &lease_key_hash, lease_version: LEASE_VERSION_V1 };

        // 6. Upload to relay, offering the lease.
        //
        // Old relays ignore the optional fields and omit the echo, so the
        // response—not successful creation—is authoritative.
        let created = relay
            .create_session_with_lease(&record.to_canonical_bytes(), Some(lease_offer))
            .await
            .map_err(|e| CoreError::Engine(format!("failed to create pairing session: {e}")))?;
        let rendezvous_id = created.rendezvous_id;
        let relay_lease_version = created.lease_version;

        // 7. Build token
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
                lease_secret,
                relay_lease_version,
                lease_capability: std::sync::Mutex::new(None),
            },
            token,
        ))
    }

    /// Process the initiator's `PairingInit` message and derive the SAS
    /// display codes for user verification.
    pub fn process_pairing_init(&mut self, pairing_init_bytes: &[u8]) -> Result<SasDisplay> {
        // 1. Parse
        let init = PairingInit::from_bytes(pairing_init_bytes).ok_or_else(|| {
            pairing_init_parse_error(pairing_init_bytes)
                .unwrap_or_else(|| CoreError::Engine("failed to parse PairingInit".into()))
        })?;

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
            init.sas_version,
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
        let sas = sas_display_from_confirmation(&confirmation);
        self.transcript_hash = Some(transcript_hash);
        self.key_schedule = Some(key_schedule);
        self.confirmation = Some(confirmation);

        // 9. Return SAS display
        Ok(sas)
    }

    /// Fetch, verify, and record the initiator's optional lease capability.
    ///
    /// Called **after** `process_pairing_init` succeeded, because the slot is
    /// authenticated with keys derived from the transcript that only exist once
    /// `pairing_init` has been parsed and verified. Because the initiator posts
    /// the capability first, there is no empty-slot race.
    ///
    /// The relay is untrusted here: only a cryptographically valid capability
    /// counts as initiator support. A missing slot, an old relay 404, or a
    /// tampered frame all mean no lease — never a ceremony failure.
    pub async fn verify_lease_capability(&self, relay: &dyn PairingRelay) -> LeaseNegotiation {
        let (Some(key_schedule), Some(transcript_hash)) =
            (self.key_schedule.as_ref(), self.transcript_hash)
        else {
            // No verified transcript yet; the caller is out of order.
            return LeaseNegotiation::none();
        };

        let slot =
            match relay.get_slot(&self.rendezvous_id_hex(), PairingSlot::LeaseCapability).await {
                Ok(Some(bytes)) => bytes,
                // Absent, 404 from an old relay, or any transport failure: no lease.
                _ => return LeaseNegotiation::none(),
            };

        let Some(frame) =
            LeaseCapabilityFrame::open(key_schedule, &self.rendezvous_id, &transcript_hash, &slot)
        else {
            // A present-but-invalid capability is not initiator support.
            return LeaseNegotiation::none();
        };

        if let Ok(mut slot) = self.lease_capability.lock() {
            *slot = Some(frame.capability);
        }
        LeaseNegotiation {
            relay_lease_version: self.relay_lease_version,
            capability: Some(frame.capability),
        }
    }

    /// The lease negotiation as currently known.
    pub fn lease_negotiation(&self) -> LeaseNegotiation {
        LeaseNegotiation {
            relay_lease_version: self.relay_lease_version,
            capability: self.lease_capability.lock().ok().and_then(|slot| *slot),
        }
    }

    /// The lease secret this joiner created, for its own verification use.
    ///
    /// The joiner never renews on a timer; this exists so the joiner (and
    /// tests) can assert the committed verifier matches what it will accept.
    pub fn lease_secret(&self) -> &[u8; LEASE_SECRET_LEN] {
        &self.lease_secret
    }

    /// The committed lease verifier, `SHA-256(lease_secret)`.
    pub fn lease_key_hash(&self) -> [u8; 32] {
        compute_lease_key_hash(&self.lease_secret)
    }

    /// Build the confirmation-slot frame to post.
    ///
    /// Sends the extended protected payload carrying the lease secret only when
    /// both the relay echo **and** the authenticated initiator capability
    /// support lease v1. Otherwise it returns the exact legacy 32-byte
    /// confirmation MAC, byte-identical to the pre-lease protocol.
    pub fn confirmation_frame(&self) -> Result<Vec<u8>> {
        let confirmation = self
            .confirmation
            .as_ref()
            .ok_or_else(|| CoreError::Engine("confirmation not yet derived".into()))?;
        let legacy_mac = confirmation.confirmation_mac(BootstrapRole::Responder);

        if !self.lease_negotiation().is_v1() {
            return Ok(legacy_mac);
        }

        let key_schedule = self
            .key_schedule
            .as_ref()
            .ok_or_else(|| CoreError::Engine("key schedule not yet derived".into()))?;
        let transcript_hash = self
            .transcript_hash
            .as_ref()
            .ok_or_else(|| CoreError::Engine("transcript hash not yet derived".into()))?;
        let capability = self
            .lease_negotiation()
            .capability
            .ok_or_else(|| CoreError::Engine("lease capability not verified".into()))?;

        seal_extended_confirmation(
            key_schedule,
            &self.rendezvous_id,
            transcript_hash,
            &capability.inner_frame(),
            &self.lease_secret,
        )
    }

    /// Return the exact legacy confirmation MAC (responder role).
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

        let plaintext = EncryptedEnvelope::open(key, envelope_bytes, &context).map_err(|e| {
            CoreError::Engine(format!(
                "joiner failed to decrypt credentials; rid={}; transcript={}; credential_len={}; credential_version={}; credential_sha={}; err={e}",
                self.rendezvous_id_hex(),
                diag_prefix(transcript_hash),
                envelope_bytes.len(),
                envelope_bytes.first().map(|b| b.to_string()).unwrap_or_else(|| "none".into()),
                diag_hash(envelope_bytes)
            ))
        })?;
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

fn pairing_init_parse_error(pairing_init_bytes: &[u8]) -> Option<CoreError> {
    let version = *pairing_init_bytes.first()?;
    if BootstrapVersion::from_byte(version).is_none() {
        return Some(CoreError::Engine(format!(
            "unsupported PairingInit bootstrap version: {version}"
        )));
    }

    let sas_version = *pairing_init_bytes.get(1)?;
    (sas_version != PAIRING_SAS_VERSION).then(|| {
        CoreError::Engine(format!(
            "unsupported pairing SAS version: {sas_version}; expected {PAIRING_SAS_VERSION}"
        ))
    })
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

    // ── Pairing lease negotiation ──
    /// The capability offered (and, when the relay accepted it, posted) before
    /// `pairing_init`.
    lease_capability: LeaseCapability,
    /// Whether the relay accepted the optional capability slot.
    lease_capability_accepted: bool,
    /// The verified lease secret, present only after a v1 extended confirmation.
    /// Zeroized on drop.
    lease_secret: std::sync::Mutex<Option<Zeroizing<[u8; LEASE_SECRET_LEN]>>>,
    /// The negotiated lease state, set when the joiner's confirmation is
    /// verified. Interior mutability keeps the verification entry point `&self`,
    /// consistent with the existing `AtomicBool` confirmation flag.
    lease_negotiation: std::sync::Mutex<LeaseNegotiation>,
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
            PAIRING_SAS_VERSION,
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

        // 9. Post the optional lease capability BEFORE PairingInit.
        //
        // Ordering is load-bearing: a new joiner fetches this slot only after
        // parsing and authenticating the unchanged `pairing_init`, so posting
        // the capability first removes the empty-slot race. Failure to post —
        // for example a 404 from an old relay — means no lease and never aborts
        // the ceremony.
        let lease_capability = LeaseCapability::v1();
        let capability_frame = LeaseCapabilityFrame::seal(
            &key_schedule,
            &token.rendezvous_id,
            &transcript_hash,
            &lease_capability,
        );
        let lease_capability_accepted = relay
            .put_slot(
                &token.rendezvous_id_hex(),
                PairingSlot::LeaseCapability,
                capability_frame.to_bytes(),
            )
            .await
            .map(|()| true)
            .unwrap_or(false);

        // 10. Build PairingInit (unchanged frozen encoding).
        let init_mac = confirmation.confirmation_mac(BootstrapRole::Initiator);
        let init = PairingInit {
            version: BootstrapVersion::V1,
            sas_version: PAIRING_SAS_VERSION,
            device_id: device_id.to_string(),
            ed25519_public_key: local_keys.ed25519_pk,
            x25519_public_key: local_keys.x25519_pk,
            ml_dsa_65_public_key: local_keys.ml_dsa_65_pk.clone(),
            xwing_ek: local_keys.xwing_ek.clone(),
            kem_ciphertext: kem_ciphertext.clone(),
            confirmation_mac: init_mac,
            relay_origin: token.relay_url_hint.clone(),
        };

        // 11. Post to relay
        relay
            .put_slot(&token.rendezvous_id_hex(), PairingSlot::Init, &init.to_bytes())
            .await
            .map_err(|e| CoreError::Engine(format!("failed to post PairingInit: {e}")))?;

        let sas = sas_display_from_confirmation(&confirmation);

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
                lease_capability,
                lease_capability_accepted,
                lease_secret: std::sync::Mutex::new(None),
                lease_negotiation: std::sync::Mutex::new(LeaseNegotiation::none()),
            },
            sas,
        ))
    }

    /// Verify the joiner's confirmation MAC (legacy fixed-TTL path).
    pub fn verify_joiner_confirmation(&self, mac_bytes: &[u8]) -> Result<()> {
        self.confirmation.verify_confirmation(mac_bytes, BootstrapRole::Responder)?;
        self.joiner_confirmation_verified.store(true, Ordering::Release);
        Ok(())
    }

    /// Verify the joiner's confirmation-slot frame and extract the optional
    /// lease secret.
    ///
    /// Accepts either the exact legacy 32-byte MAC or the lease v1 extended
    /// frame, which are length-disjoint. Only a cryptographically valid
    /// extended frame yields a secret, and it is released only against the
    /// capability this initiator authenticated — so a rendezvous-ID holder
    /// cannot mint lease authority, and a legacy peer cannot be forged into an
    /// upgrade.
    ///
    /// Receiving an extended v1 frame is itself proof that the relay echoed
    /// lease v1: the joiner sends it only when its create response carried the
    /// echo *and* the initiator's capability verified.
    pub fn verify_joiner_confirmation_frame(&self, frame_bytes: &[u8]) -> Result<LeaseNegotiation> {
        match classify_confirmation_frame(frame_bytes) {
            Some(ConfirmationFrame::LegacyMac(mac)) => {
                self.confirmation.verify_confirmation(&mac, BootstrapRole::Responder)?;
                self.joiner_confirmation_verified.store(true, Ordering::Release);
                let negotiation = LeaseNegotiation::none();
                if let Ok(mut slot) = self.lease_negotiation.lock() {
                    *slot = negotiation;
                }
                Ok(negotiation)
            }
            Some(ConfirmationFrame::LeaseV1(frame)) => {
                let inner = self.lease_capability.inner_frame();
                let secret = open_extended_confirmation(
                    &self.key_schedule,
                    &self.rendezvous_id,
                    &self.transcript_hash,
                    &inner,
                    &frame,
                )?;
                // AEAD under the responder→initiator key over the same
                // transcript is the joiner's confirmation; an authenticated
                // extended frame therefore verifies the peer exactly as the
                // legacy MAC does.
                self.joiner_confirmation_verified.store(true, Ordering::Release);
                let negotiation = LeaseNegotiation {
                    relay_lease_version: Some(LEASE_VERSION_V1),
                    capability: Some(self.lease_capability),
                };
                if let Ok(mut slot) = self.lease_secret.lock() {
                    *slot = Some(secret);
                }
                if let Ok(mut slot) = self.lease_negotiation.lock() {
                    *slot = negotiation;
                }
                Ok(negotiation)
            }
            None => Err(CoreError::Engine(format!(
                "unrecognized confirmation-slot framing ({} bytes); expected the legacy 32-byte MAC or a lease v1 frame",
                frame_bytes.len()
            ))),
        }
    }

    /// The lease capability this initiator offered.
    pub fn lease_capability(&self) -> LeaseCapability {
        self.lease_capability
    }

    /// Whether the relay accepted the capability slot. `false` on an old relay
    /// (404) or any post failure; never fatal.
    pub fn lease_capability_accepted(&self) -> bool {
        self.lease_capability_accepted
    }

    /// The negotiated lease state, meaningful once the joiner's confirmation
    /// has been verified.
    pub fn lease_negotiation(&self) -> LeaseNegotiation {
        self.lease_negotiation.lock().map(|slot| *slot).unwrap_or_else(|_| LeaseNegotiation::none())
    }

    /// The verified lease secret, when lease v1 was negotiated.
    ///
    /// Returned by value so the caller controls the copy's lifetime; the
    /// ceremony retains (and zeroizes) its own copy.
    pub fn lease_secret(&self) -> Option<[u8; LEASE_SECRET_LEN]> {
        self.lease_secret.lock().ok().and_then(|slot| slot.as_ref().map(|s| **s))
    }

    /// Snapshot the post-confirmation half of the split ceremony.
    ///
    /// Callers hold this while producing and uploading the snapshot, then
    /// finish with [`Self::encrypt_credentials`]. It carries only in-memory,
    /// zeroized state; process-death durability is out of scope.
    pub fn verified_state(&self) -> VerifiedInitiatorState {
        let rendezvous_id_hex = hex::encode(self.rendezvous_id);
        match self.lease_secret() {
            Some(secret) => VerifiedInitiatorState::leased(
                rendezvous_id_hex,
                self.transcript_hash,
                self.lease_capability,
                Zeroizing::new(secret),
            ),
            None => VerifiedInitiatorState::fixed_ttl(
                rendezvous_id_hex,
                self.transcript_hash,
                self.lease_negotiation().unavailable_reason(),
            ),
        }
    }

    /// Whether the joiner's confirmation has been verified.
    pub fn joiner_confirmation_verified(&self) -> bool {
        self.joiner_confirmation_verified.load(Ordering::Acquire)
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
        let plaintext = EncryptedEnvelope::open(key, envelope_bytes, &context).map_err(|e| {
            CoreError::Engine(format!(
                "initiator failed to open joiner bundle envelope; rid={}; transcript={}; joiner_bundle_len={}; joiner_bundle_version={}; joiner_bundle_sha={}; err={e}",
                self.rendezvous_id_hex(),
                diag_prefix(&self.transcript_hash),
                envelope_bytes.len(),
                envelope_bytes.first().map(|b| b.to_string()).unwrap_or_else(|| "none".into()),
                diag_hash(envelope_bytes)
            ))
        })?;
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

    /// The joiner's bootstrap record, as fetched at ceremony start and
    /// cross-checked against the out-of-band rendezvous commitment in
    /// [`InitiatorCeremony::start`] (see the `verify_commitment` gate there).
    ///
    /// SECURITY: the commitment is a SHA-256 over the record's full canonical
    /// bytes — including the V2 permanent ML-KEM-768 and X-Wing identity keys —
    /// and is transferred out-of-band via the QR code / deep link, so the relay
    /// cannot substitute any field of this record without the human-verified
    /// commitment check failing. The initiator MUST author the joiner's signed
    /// registry entry (and the post-pairing wrap target) from THIS record, not
    /// from a fresh relay fetch, which carries no such binding.
    pub fn joiner_bootstrap_record(&self) -> &JoinerBootstrapRecord {
        &self.bootstrap_record
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pairing::lease::LEGACY_CONFIRMATION_MAC_LEN;
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
            epoch_keys: std::collections::BTreeMap::from([(1, vec![0xCC; 32])]),
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
        assert_eq!(joiner_sas.word_list, initiator_sas.word_list);
        assert_eq!(joiner_sas.version, PAIRING_SAS_VERSION);

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
    async fn stale_pairing_init_sas_version_fails_closed() {
        let relay = MockPairingRelay::new();
        let relay_url = "https://relay.example.com";

        let (mut joiner, token) = JoinerCeremony::start(&relay, relay_url).await.unwrap();
        let initiator_secret = DeviceSecret::generate();
        let initiator_device_id = crate::node_id::generate_node_id();
        let (_initiator, _initiator_sas) =
            InitiatorCeremony::start(token, &relay, &initiator_secret, &initiator_device_id)
                .await
                .unwrap();

        let mut init_bytes = relay
            .get_slot(&joiner.rendezvous_id_hex(), PairingSlot::Init)
            .await
            .unwrap()
            .expect("init slot should be populated");
        init_bytes[1] = PAIRING_SAS_VERSION - 1;

        let err = joiner
            .process_pairing_init(&init_bytes)
            .expect_err("unsupported SAS version must fail before SAS display");
        assert!(
            err.to_string().contains("unsupported pairing SAS version: 2; expected 3"),
            "expected parse rejection, got: {err}"
        );
        assert!(
            joiner.confirmation_mac().is_err(),
            "tampered version must not arm confirmation state"
        );
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
        assert_eq!(joiner_sas.word_list, initiator_sas.word_list);
        assert!(!joiner_sas.words.is_empty());
        assert_eq!(joiner_sas.word_list.len(), 5);
        assert_eq!(joiner_sas.words.split_whitespace().count(), 5);
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

    // ── Pairing lease integration ────────────────────────────────────────

    /// Bring a lease-capable ceremony to the point where the joiner has
    /// authenticated (or downgraded) the initiator's lease capability.
    async fn run_lease_ceremony(relay: &MockPairingRelay) -> (JoinerCeremony, InitiatorCeremony) {
        let relay_url = "https://relay.example.com";
        let (mut joiner, token) = JoinerCeremony::start(relay, relay_url).await.unwrap();
        let initiator_secret = DeviceSecret::generate();
        let initiator_device_id = crate::node_id::generate_node_id();
        let (initiator, _sas) =
            InitiatorCeremony::start(token, relay, &initiator_secret, &initiator_device_id)
                .await
                .unwrap();

        let init_bytes = relay
            .get_slot(&joiner.rendezvous_id_hex(), PairingSlot::Init)
            .await
            .unwrap()
            .expect("init slot should be populated");
        joiner.process_pairing_init(&init_bytes).unwrap();
        joiner.verify_lease_capability(relay).await;

        (joiner, initiator)
    }

    #[tokio::test]
    async fn capability_slot_read_succeeds_without_an_empty_slot_race() {
        // The initiator posts the capability BEFORE pairing_init, so a joiner
        // that reads it immediately after authenticating init always sees it.
        let relay = MockPairingRelay::new();
        let (joiner, initiator) = run_lease_ceremony(&relay).await;

        assert!(initiator.lease_capability_accepted());
        let negotiation = joiner.lease_negotiation();
        assert_eq!(negotiation.relay_lease_version, Some(LEASE_VERSION_V1));
        assert_eq!(negotiation.capability, Some(LeaseCapability::v1()));
        assert!(negotiation.is_v1());
    }

    #[tokio::test]
    async fn lease_ceremony_delivers_the_secret_to_the_initiator() {
        let relay = MockPairingRelay::new();
        let (joiner, initiator) = run_lease_ceremony(&relay).await;

        // The committed verifier is SHA-256 of the joiner's secret.
        assert_eq!(
            joiner.lease_key_hash(),
            crate::pairing::lease::compute_lease_key_hash(joiner.lease_secret())
        );

        // Extended confirmation delivers the secret, and is length-disjoint
        // from the legacy 32-byte MAC.
        let frame = joiner.confirmation_frame().unwrap();
        assert!(frame.len() > LEGACY_CONFIRMATION_MAC_LEN);

        let negotiation = initiator.verify_joiner_confirmation_frame(&frame).unwrap();
        assert!(negotiation.is_v1());
        assert_eq!(initiator.lease_secret(), Some(*joiner.lease_secret()));
        assert!(initiator.joiner_confirmation_verified());
    }

    #[tokio::test]
    async fn old_relay_downgrades_to_fixed_ttl_without_failing() {
        let relay = MockPairingRelay::new();
        relay.set_lease_supported(false);
        let (joiner, initiator) = run_lease_ceremony(&relay).await;

        // No echo and no capability: safe downgrade, not an error.
        let negotiation = joiner.lease_negotiation();
        assert_eq!(negotiation.relay_lease_version, None);
        assert_eq!(negotiation.capability, None);
        assert!(!negotiation.is_v1());
        assert!(!initiator.lease_capability_accepted());

        // The joiner sends the exact legacy 32-byte confirmation.
        let frame = joiner.confirmation_frame().unwrap();
        assert_eq!(frame.len(), LEGACY_CONFIRMATION_MAC_LEN);
        assert_eq!(frame, joiner.confirmation_mac().unwrap());

        let result = initiator.verify_joiner_confirmation_frame(&frame).unwrap();
        assert!(!result.is_v1());
        assert_eq!(initiator.lease_secret(), None);
    }

    #[tokio::test]
    async fn old_initiator_new_joiner_sends_the_exact_legacy_mac() {
        // New joiner + lease-capable relay, but no authenticated initiator
        // capability (the old-initiator shape).
        let relay = MockPairingRelay::new();
        let url = "https://relay.example.com";
        let (mut joiner, token) = JoinerCeremony::start(&relay, url).await.unwrap();

        let secret = DeviceSecret::generate();
        let device_id = crate::node_id::generate_node_id();
        let (_initiator, _sas) =
            InitiatorCeremony::start(token, &relay, &secret, &device_id).await.unwrap();

        let rid = joiner.rendezvous_id_hex();
        let init_bytes = relay.get_slot(&rid, PairingSlot::Init).await.unwrap().unwrap();
        joiner.process_pairing_init(&init_bytes).unwrap();

        // Model the legacy peer by removing the capability it would not have posted.
        relay.remove_slot_for_test(&rid, PairingSlot::LeaseCapability);
        let negotiation = joiner.verify_lease_capability(&relay).await;
        assert!(!negotiation.is_v1());
        assert_eq!(negotiation.capability, None);

        // The relay echoed v1, but without an authenticated capability the
        // joiner must still emit the legacy MAC.
        let frame = joiner.confirmation_frame().unwrap();
        assert_eq!(frame.len(), LEGACY_CONFIRMATION_MAC_LEN);
        assert_eq!(frame, joiner.confirmation_mac().unwrap());
    }

    #[tokio::test]
    async fn new_initiator_old_joiner_ignores_the_capability_slot() {
        // A new initiator always posts the optional slot. An old joiner never
        // fetches it, so the ceremony must proceed exactly as before.
        let relay = MockPairingRelay::new();
        let url = "https://relay.example.com";
        let (mut joiner, token) = JoinerCeremony::start(&relay, url).await.unwrap();
        let secret = DeviceSecret::generate();
        let device_id = crate::node_id::generate_node_id();
        let (initiator, _sas) =
            InitiatorCeremony::start(token, &relay, &secret, &device_id).await.unwrap();

        let rid = joiner.rendezvous_id_hex();
        let init_bytes = relay.get_slot(&rid, PairingSlot::Init).await.unwrap().unwrap();
        // An old joiner parses and verifies only pairing_init; it never calls
        // verify_lease_capability.
        let _sas = joiner.process_pairing_init(&init_bytes).unwrap();

        // Legacy MAC path is intact and still verifies on the new initiator.
        let legacy_mac = joiner.confirmation_mac().unwrap();
        assert_eq!(legacy_mac.len(), LEGACY_CONFIRMATION_MAC_LEN);
        let negotiation = initiator.verify_joiner_confirmation_frame(&legacy_mac).unwrap();
        assert!(!negotiation.is_v1());
        assert_eq!(initiator.lease_secret(), None);

        // The unchanged frozen formats still round-trip.
        let init = PairingInit::from_bytes(&init_bytes).expect("frozen PairingInit parses");
        assert_eq!(init.sas_version, PAIRING_SAS_VERSION);
    }

    #[tokio::test]
    async fn tampered_capability_is_not_initiator_support() {
        let relay = MockPairingRelay::new();
        let url = "https://relay.example.com";
        let (mut joiner, token) = JoinerCeremony::start(&relay, url).await.unwrap();
        let secret = DeviceSecret::generate();
        let device_id = crate::node_id::generate_node_id();
        let (_initiator, _sas) =
            InitiatorCeremony::start(token, &relay, &secret, &device_id).await.unwrap();

        let rid = joiner.rendezvous_id_hex();
        let init_bytes = relay.get_slot(&rid, PairingSlot::Init).await.unwrap().unwrap();
        joiner.process_pairing_init(&init_bytes).unwrap();

        // A malicious relay substitutes a forged capability frame.
        let mut capability =
            relay.get_slot(&rid, PairingSlot::LeaseCapability).await.unwrap().unwrap();
        let last = capability.len() - 1;
        capability[last] ^= 0xFF;
        relay.remove_slot_for_test(&rid, PairingSlot::LeaseCapability);
        relay.put_slot(&rid, PairingSlot::LeaseCapability, &capability).await.unwrap();

        let negotiation = joiner.verify_lease_capability(&relay).await;
        assert!(!negotiation.is_v1(), "a tampered capability must not upgrade");
        assert_eq!(negotiation.capability, None);
        assert_eq!(joiner.confirmation_frame().unwrap().len(), LEGACY_CONFIRMATION_MAC_LEN);
    }

    #[tokio::test]
    async fn extended_confirmation_rejects_a_different_session() {
        // A rendezvous-ID holder cannot mint lease authority: the secret is
        // released only against the capability the real initiator authenticated.
        let relay = MockPairingRelay::new();
        let (joiner, initiator) = run_lease_ceremony(&relay).await;
        let frame = joiner.confirmation_frame().unwrap();

        let other_relay = MockPairingRelay::new();
        let (_other_joiner, other_initiator) = run_lease_ceremony(&other_relay).await;

        assert!(
            other_initiator.verify_joiner_confirmation_frame(&frame).is_err(),
            "cross-session confirmation must not verify"
        );
        assert_eq!(other_initiator.lease_secret(), None);
        assert!(!other_initiator.joiner_confirmation_verified());

        // The real initiator still succeeds.
        assert!(initiator.verify_joiner_confirmation_frame(&frame).is_ok());
    }

    #[tokio::test]
    async fn tampered_extended_confirmation_yields_no_secret() {
        let relay = MockPairingRelay::new();
        let (joiner, initiator) = run_lease_ceremony(&relay).await;
        let mut frame = joiner.confirmation_frame().unwrap();

        let last = frame.len() - 1;
        frame[last] ^= 0xFF;
        assert!(initiator.verify_joiner_confirmation_frame(&frame).is_err());
        assert_eq!(initiator.lease_secret(), None);
        assert!(!initiator.joiner_confirmation_verified());
    }

    #[tokio::test]
    async fn unrecognized_confirmation_framing_is_rejected() {
        let relay = MockPairingRelay::new();
        let (_joiner, initiator) = run_lease_ceremony(&relay).await;

        // 31 bytes: neither the legacy MAC nor a v1 frame.
        let err = initiator
            .verify_joiner_confirmation_frame(&[0u8; 31])
            .expect_err("31-byte frame must be rejected");
        assert!(err.to_string().contains("unrecognized confirmation-slot framing"), "got: {err}");
    }

    #[tokio::test]
    async fn joiner_never_renews_on_a_timer() {
        // The joiner holds the secret but must not issue renewals while waiting:
        // renewal is initiator-only.
        let relay = MockPairingRelay::new();
        let (joiner, initiator) = run_lease_ceremony(&relay).await;
        initiator.verify_joiner_confirmation_frame(&joiner.confirmation_frame().unwrap()).unwrap();

        assert_eq!(relay.renew_successes(), 0, "the joiner must not renew on a timer");
    }

    #[tokio::test]
    async fn initial_renewal_requires_no_upload_progress() {
        let relay = MockPairingRelay::new();
        let (joiner, initiator) = run_lease_ceremony(&relay).await;
        let negotiation = initiator
            .verify_joiner_confirmation_frame(&joiner.confirmation_frame().unwrap())
            .unwrap();
        assert!(negotiation.is_v1());

        // Initial renewal: immediate, with no offset observed.
        let secret = initiator.lease_secret().expect("secret must be present");
        let outcome = crate::pairing::lease::renew_pairing_lease(
            &relay,
            &initiator.rendezvous_id_hex(),
            &secret,
        )
        .await;
        assert!(outcome.is_renewed(), "the initial renewal must succeed");
        assert_eq!(relay.renew_successes(), 1);
    }

    #[tokio::test]
    async fn wrong_lease_secret_cannot_renew() {
        let relay = MockPairingRelay::new();
        let (joiner, initiator) = run_lease_ceremony(&relay).await;
        initiator.verify_joiner_confirmation_frame(&joiner.confirmation_frame().unwrap()).unwrap();

        // A rendezvous-ID holder who forges the public confirmation slot still
        // cannot renew without the committed secret.
        let outcome = crate::pairing::lease::renew_pairing_lease(
            &relay,
            &initiator.rendezvous_id_hex(),
            &[0x00u8; LEASE_SECRET_LEN],
        )
        .await;
        assert!(outcome.is_terminal(), "a wrong secret must be indistinguishable not-found");
        assert_eq!(relay.renew_successes(), 0);
    }

    #[tokio::test]
    async fn unknown_rendezvous_renewal_is_uniform_not_found() {
        let relay = MockPairingRelay::new();
        let outcome = crate::pairing::lease::renew_pairing_lease(
            &relay,
            "00000000000000000000000000000000",
            &[0x11u8; LEASE_SECRET_LEN],
        )
        .await;
        assert!(outcome.is_terminal());
        assert_eq!(relay.renew_successes(), 0);
    }

    #[tokio::test]
    async fn renewal_failure_is_nonfatal_to_the_ceremony() {
        // Old relay: the ceremony completes normally and renewal simply fails.
        let relay = MockPairingRelay::new();
        relay.set_lease_supported(false);
        let (joiner, _initiator) = run_lease_ceremony(&relay).await;

        assert!(joiner.confirmation_mac().is_ok());
        let outcome = crate::pairing::lease::renew_pairing_lease(
            &relay,
            &joiner.rendezvous_id_hex(),
            joiner.lease_secret(),
        )
        .await;
        assert!(outcome.is_terminal());
        assert!(!outcome.is_renewed());
        // The ceremony state is untouched by the failed renewal.
        assert!(joiner.confirmation_mac().is_ok());
    }

    #[tokio::test]
    async fn lease_handle_drives_initial_progress_and_final_renewals() {
        let relay = MockPairingRelay::new();
        let (joiner, initiator) = run_lease_ceremony(&relay).await;
        initiator.verify_joiner_confirmation_frame(&joiner.confirmation_frame().unwrap()).unwrap();

        let state = initiator.verified_state();
        let mut handle = crate::pairing::lease::PairingLeaseHandle::new(&state);
        assert!(handle.is_lease_capable());

        // Initial renewal: exempt from progress requirements.
        let now = std::time::Instant::now();
        assert!(handle.renew(&relay, None, now).await.is_renewed());
        assert!(!handle.is_terminal());
        assert_eq!(relay.renew_successes(), 1);

        // No new bytes: no progress renewal.
        assert!(!handle.should_renew_for_progress(0, now));

        // Strictly larger offset inside the coalescing window: no renewal.
        assert!(!handle.should_renew_for_progress(8 * 1024 * 1024, now));

        // Strictly larger offset after the window: renewal.
        let later = now
            + std::time::Duration::from_secs(crate::pairing::lease::LEASE_RENEWAL_COALESCE_SECS);
        assert!(handle.should_renew_for_progress(8 * 1024 * 1024, later));
        assert!(handle.renew(&relay, Some(8 * 1024 * 1024), later).await.is_renewed());

        // Same offset again: no further renewal.
        assert!(!handle.should_renew_for_progress(8 * 1024 * 1024, later));
        assert_eq!(relay.renew_successes(), 2);

        // Final renewal is exempt from the coalescing interval.
        assert!(handle.renew(&relay, None, later).await.is_renewed());
        assert_eq!(relay.renew_successes(), 3);
    }

    #[tokio::test]
    async fn fixed_ttl_state_never_schedules_a_renewal() {
        let relay = MockPairingRelay::new();
        let (joiner, initiator) = run_lease_ceremony(&relay).await;
        let _ = initiator;
        let state = crate::pairing::lease::VerifiedInitiatorState::fixed_ttl(
            joiner.rendezvous_id_hex(),
            [0u8; 32],
            crate::pairing::lease::LeaseUnavailableReason::CapabilityAbsent,
        );
        let handle = crate::pairing::lease::PairingLeaseHandle::new(&state);

        assert!(!handle.is_lease_capable());
        assert_eq!(
            handle.last_outcome(),
            crate::pairing::lease::LeaseRenewalOutcome::LeaseNotNegotiated
        );
        assert!(!handle.should_renew_for_progress(u64::MAX, std::time::Instant::now()));
    }

    #[tokio::test]
    async fn mixed_version_ceremony_still_exchanges_credentials() {
        // Old relay: fixed TTL and the exact legacy MAC, but credentials still
        // flow, and the frozen confirmation bytes are unchanged.
        let relay = MockPairingRelay::new();
        relay.set_lease_supported(false);
        let url = "https://relay.example.com";
        let (mut joiner, token) = JoinerCeremony::start(&relay, url).await.unwrap();
        let initiator_secret = DeviceSecret::generate();
        let initiator_device_id = crate::node_id::generate_node_id();
        let (initiator, _sas) =
            InitiatorCeremony::start(token, &relay, &initiator_secret, &initiator_device_id)
                .await
                .unwrap();

        let init_bytes =
            relay.get_slot(&joiner.rendezvous_id_hex(), PairingSlot::Init).await.unwrap().unwrap();
        joiner.process_pairing_init(&init_bytes).unwrap();
        joiner.verify_lease_capability(&relay).await;

        let legacy_mac = joiner.confirmation_frame().unwrap();
        assert_eq!(legacy_mac.len(), LEGACY_CONFIRMATION_MAC_LEN);
        assert_eq!(legacy_mac, joiner.confirmation_mac().unwrap());
        assert!(!initiator.verify_joiner_confirmation_frame(&legacy_mac).unwrap().is_v1());
        assert_eq!(initiator.lease_secret(), None);

        let creds = test_credentials();
        let envelope = initiator.encrypt_credentials(&creds).unwrap();
        assert_eq!(joiner.decrypt_credentials(&envelope).unwrap().sync_id, creds.sync_id);
    }

    #[tokio::test]
    async fn lease_v1_ceremony_still_exchanges_credentials() {
        let relay = MockPairingRelay::new();
        let (joiner, initiator) = run_lease_ceremony(&relay).await;
        let negotiation = initiator
            .verify_joiner_confirmation_frame(&joiner.confirmation_frame().unwrap())
            .unwrap();
        assert!(negotiation.is_v1());

        let creds = test_credentials();
        let envelope = initiator.encrypt_credentials(&creds).unwrap();
        let decrypted = joiner.decrypt_credentials(&envelope).unwrap();
        assert_eq!(decrypted.sync_id, creds.sync_id);
        assert_eq!(decrypted.mnemonic, creds.mnemonic);
    }

    #[tokio::test]
    async fn lease_secret_never_appears_in_the_capability_slot() {
        // The capability slot is readable by the relay; the raw secret must not
        // be in it.
        let relay = MockPairingRelay::new();
        let (joiner, _initiator) = run_lease_ceremony(&relay).await;
        let capability = relay
            .get_slot(&joiner.rendezvous_id_hex(), PairingSlot::LeaseCapability)
            .await
            .unwrap()
            .unwrap();

        let secret = joiner.lease_secret();
        assert!(
            !capability.windows(LEASE_SECRET_LEN).any(|w| w == secret.as_slice()),
            "the capability slot must never carry the raw lease secret"
        );
        // Only the verifier preimage relationship exists, never the secret.
        assert_ne!(joiner.lease_key_hash(), *secret);
    }
}
