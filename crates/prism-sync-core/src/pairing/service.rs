//! High-level pairing orchestration: create and join sync groups.
//!
//! The `PairingService` wraps the relay, secure store, and crypto layers to
//! provide a simple API for multi-device pairing. The full crypto handshake
//! (SAS verification, signed keyrings) will be refined later — this module
//! establishes the API surface and basic key derivation flow.

use std::sync::Arc;
use std::time::Duration;

use crate::bootstrap::{
    CredentialBundle as BootstrapCredentialBundle, InitiatorCeremony, JoinerBootstrapRecord,
    JoinerCeremony, RendezvousToken, SasDisplay,
};
use crate::epoch::EpochManager;
use crate::error::{CoreError, Result};
use crate::pairing::models::*;
use crate::relay::pairing_relay::{PairingRelay, PairingSlot};
use crate::relay::traits::{
    FirstDeviceAdmissionProof, ProofOfWorkChallenge, ProofOfWorkSolution,
    RegistrationNonceResponse, RegistryApproval,
};
use crate::relay::SyncRelay;
use crate::secure_store::SecureStore;
use prism_sync_crypto::{mnemonic, DeviceSecret, KeyHierarchy};
use sha2::{Digest, Sha256};
use tokio::time::sleep;

const MIN_SIGNATURE_VERSION_FLOOR_KEY: &str = "min_signature_version_floor";

/// Orchestrates sync group creation and joining.
///
/// Holds shared references to the relay (for device registration) and the
/// secure store (for credential persistence).
pub struct PairingService {
    relay: Arc<dyn SyncRelay>,
    secure_store: Arc<dyn SecureStore>,
}

impl PairingService {
    /// Create a new `PairingService`.
    pub fn new(relay: Arc<dyn SyncRelay>, secure_store: Arc<dyn SecureStore>) -> Self {
        Self {
            relay,
            secure_store,
        }
    }

    fn ratchet_min_signature_version(&self, observed: Option<u8>) -> Result<()> {
        let Some(observed) = observed else {
            return Ok(());
        };

        let current = self
            .secure_store
            .get(MIN_SIGNATURE_VERSION_FLOOR_KEY)?
            .map(|bytes| {
                let value = String::from_utf8(bytes).map_err(|e| {
                    CoreError::Crypto(prism_sync_crypto::CryptoError::Serialization(format!(
                        "invalid UTF-8 in {MIN_SIGNATURE_VERSION_FLOOR_KEY}: {e}"
                    )))
                })?;
                value.parse::<u8>().map_err(|e| {
                    CoreError::Crypto(prism_sync_crypto::CryptoError::Serialization(format!(
                        "invalid integer in {MIN_SIGNATURE_VERSION_FLOOR_KEY}: {e}"
                    )))
                })
            })
            .transpose()?
            .unwrap_or(0);

        if observed > current {
            self.secure_store.set(
                MIN_SIGNATURE_VERSION_FLOOR_KEY,
                observed.to_string().as_bytes(),
            )?;
        }

        Ok(())
    }

    /// Create a new sync group (first device).
    ///
    /// 1. Generates a BIP39 mnemonic (or uses `mnemonic_override`).
    /// 2. Initializes a `KeyHierarchy` with `password + mnemonic`.
    /// 3. Generates a unique `sync_id`.
    /// 4. Builds `SyncGroupCredentials` and the first-device pairing response.
    /// 5. Generates a device identity and registers with the relay.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_sync_group(
        &self,
        password: &str,
        relay_url: &str,
        mnemonic_override: Option<String>,
        sync_id_override: Option<String>,
        nonce_response_override: Option<RegistrationNonceResponse>,
        first_device_admission_proof: Option<FirstDeviceAdmissionProof>,
        registration_token: Option<String>,
    ) -> Result<(SyncGroupCredentials, PairingResponse)> {
        // 1. Generate or accept mnemonic
        let mnemonic_str = mnemonic_override.unwrap_or_else(mnemonic::generate);
        let secret_key = mnemonic::to_bytes(&mnemonic_str).map_err(CoreError::Crypto)?;

        // 2. Initialize key hierarchy — produces wrapped DEK + salt
        let mut key_hierarchy = KeyHierarchy::new();
        let (wrapped_dek, salt) = key_hierarchy
            .initialize(password, &secret_key)
            .map_err(CoreError::Crypto)?;

        // 3. Use provided sync_id or generate one (32 random bytes, hex-encoded)
        let sync_id = sync_id_override.unwrap_or_else(EpochManager::generate_sync_id);

        // 4. Build credentials
        let credentials = SyncGroupCredentials {
            sync_id: sync_id.clone(),
            mnemonic: mnemonic_str.clone(),
            wrapped_dek: wrapped_dek.clone(),
            salt: salt.clone(),
        };

        // 5. Reuse a pending identity when the caller pre-generated one for
        // first-device admission. Otherwise generate a fresh device identity.
        let (device_secret, device_id) = self
            .load_pending_identity()?
            .unwrap_or_else(|| (DeviceSecret::generate(), crate::node_id::generate_node_id()));
        let signing_key = device_secret
            .ed25519_keypair(&device_id)
            .map_err(CoreError::Crypto)?;
        let exchange_key = device_secret
            .x25519_keypair(&device_id)
            .map_err(CoreError::Crypto)?;
        let pq_signing_key = device_secret
            .ml_dsa_65_keypair(&device_id)
            .map_err(CoreError::Crypto)?;
        let pq_kem_key = device_secret
            .ml_kem_768_keypair(&device_id)
            .map_err(CoreError::Crypto)?;

        // 5b. Pre-generate a device_id for the joining device (snapshot targeting)
        let joiner_device_id = crate::node_id::generate_node_id();

        // 6. Sign the invitation with hybrid keys (CRITICAL-1) — V3 labeled WNS
        let signing_data = build_invitation_signing_data_v2(
            &sync_id,
            relay_url,
            &wrapped_dek,
            &salt,
            &device_id,
            &signing_key.public_key_bytes(),
            &pq_signing_key.public_key_bytes(),
            Some(&joiner_device_id),
            0,
            &[],
        );
        let m_prime = prism_sync_crypto::pq::build_hybrid_message_representative(
            b"invitation",
            &signing_data,
        )
        .expect("hardcoded invitation context should be <= 255 bytes");
        let hybrid_sig = prism_sync_crypto::pq::HybridSignature {
            ed25519_sig: signing_key.sign(&m_prime),
            ml_dsa_65_sig: pq_signing_key.sign(&m_prime),
        };
        let mut invitation_wire = vec![0x03u8];
        invitation_wire.extend_from_slice(&hybrid_sig.to_bytes());
        let signed_invitation_hex = hex::encode(&invitation_wire);

        // 7. Build signed registry snapshot (typed, verifiable device records)
        let registry_snapshot = SignedRegistrySnapshot::new(vec![RegistrySnapshotEntry {
            sync_id: sync_id.clone(),
            device_id: device_id.clone(),
            ed25519_public_key: signing_key.public_key_bytes().to_vec(),
            x25519_public_key: exchange_key.public_key_bytes().to_vec(),
            ml_dsa_65_public_key: pq_signing_key.public_key_bytes(),
            ml_kem_768_public_key: pq_kem_key.public_key_bytes(),
            status: "active".into(),
            ml_dsa_key_generation: 0,
        }]);
        let signed_keyring = registry_snapshot.sign_hybrid(&signing_key, &pq_signing_key);

        // 8. Build the first-device pairing response.
        let response = PairingResponse {
            relay_url: relay_url.to_string(),
            sync_id: sync_id.clone(),
            mnemonic: mnemonic_str,
            wrapped_dek,
            salt,
            signed_invitation: signed_invitation_hex.clone(),
            signed_keyring,
            inviter_device_id: device_id.clone(),
            inviter_ed25519_pk: signing_key.public_key_bytes().to_vec(),
            inviter_ml_dsa_65_pk: pq_signing_key.public_key_bytes(),
            joiner_device_id: Some(joiner_device_id.clone()),
            current_epoch: 0,
            epoch_key: vec![],
            registry_approval_signature: None,
            registration_token,
        };

        // 9. Fetch registration nonce and build challenge-response (CRITICAL-2)
        let nonce_response = match nonce_response_override {
            Some(response) => response,
            None => self
                .relay
                .get_registration_nonce()
                .await
                .map_err(|e| CoreError::from_relay_with_context(Some("nonce fetch"), e))?,
        };
        self.ratchet_min_signature_version(nonce_response.min_signature_version)?;
        let pow_solution = solve_registration_pow(&sync_id, &device_id, &nonce_response)?;
        let nonce = nonce_response.nonce;

        // Build V2 hybrid challenge signature
        let challenge_signature = build_hybrid_challenge_signature(
            &signing_key,
            &pq_signing_key,
            &sync_id,
            &device_id,
            &nonce,
        );

        // 10. Register with relay using signed challenge
        let register_req = crate::relay::traits::RegisterRequest {
            device_id: device_id.clone(),
            signing_public_key: signing_key.public_key_bytes().to_vec(),
            x25519_public_key: exchange_key.public_key_bytes().to_vec(),
            ml_dsa_65_public_key: pq_signing_key.public_key_bytes(),
            ml_kem_768_public_key: pq_kem_key.public_key_bytes(),
            registration_challenge: challenge_signature,
            nonce,
            pow_solution,
            first_device_admission_proof,
            registry_approval: None,
        };

        let register_response = self
            .relay
            .register_device(register_req)
            .await
            .map_err(|e| CoreError::from_relay_with_context(Some("registration failed"), e))?;
        self.ratchet_min_signature_version(register_response.min_signature_version)?;

        // 11. Persist credentials and device identity to secure store
        self.secure_store.set(
            "session_token",
            register_response.device_session_token.as_bytes(),
        )?;
        self.secure_store
            .set("sync_id", credentials.sync_id.as_bytes())?;
        self.secure_store.set("relay_url", relay_url.as_bytes())?;
        self.secure_store
            .set("mnemonic", credentials.mnemonic.as_bytes())?;
        self.secure_store
            .set("wrapped_dek", &credentials.wrapped_dek)?;
        self.secure_store.set("dek_salt", &credentials.salt)?;
        self.secure_store
            .set("device_secret", device_secret.as_bytes())?;
        self.secure_store.set("device_id", device_id.as_bytes())?;
        self.secure_store.set("epoch", b"0")?;

        Ok((credentials, response))
    }

    /// Join an existing sync group (second+ device).
    ///
    /// Derives the key hierarchy from the pairing response and the user's
    /// password. The joining device must enter the *same* password that was
    /// used to create the sync group.
    ///
    /// Verifies the invitation signature and the signed registry snapshot
    /// before trusting the payload (CRITICAL-1).
    /// Registers with the relay using challenge-response (CRITICAL-2).
    ///
    /// Returns the unlocked key hierarchy and the verified registry snapshot.
    /// The caller should import the snapshot entries into storage via
    /// [`crate::device_registry::DeviceRegistryManager::import_keyring`]
    /// before starting normal sync.
    pub async fn join_sync_group(
        &self,
        response: &PairingResponse,
        password: &str,
    ) -> Result<(KeyHierarchy, SignedRegistrySnapshot)> {
        response
            .validate_epoch_fields()
            .map_err(|e| CoreError::Engine(format!("invalid pairing response: {e}")))?;

        // 1. Verify the invitation signature (CRITICAL-1)
        let inviter_pk: [u8; 32] = response
            .inviter_ed25519_pk
            .clone()
            .try_into()
            .map_err(|_| CoreError::Engine("invalid inviter public key length".into()))?;
        if response.inviter_ml_dsa_65_pk.is_empty() {
            return Err(CoreError::Engine(
                "pairing response missing inviter ML-DSA public key".into(),
            ));
        }

        let sig_bytes = prism_sync_crypto::hex::decode(&response.signed_invitation)
            .map_err(CoreError::Crypto)?;
        let signing_data = build_invitation_signing_data_v2(
            &response.sync_id,
            &response.relay_url,
            &response.wrapped_dek,
            &response.salt,
            &response.inviter_device_id,
            &inviter_pk,
            &response.inviter_ml_dsa_65_pk,
            response.joiner_device_id.as_deref(),
            response.current_epoch,
            &response.epoch_key,
        );
        verify_hybrid_invitation(
            &signing_data,
            &sig_bytes,
            &inviter_pk,
            &response.inviter_ml_dsa_65_pk,
        )?;

        // 1b. Verify and decode the signed registry snapshot
        let registry_snapshot = SignedRegistrySnapshot::verify_and_decode_hybrid(
            &response.signed_keyring,
            &inviter_pk,
            &response.inviter_ml_dsa_65_pk,
        )
        .map_err(|e| CoreError::Engine(format!("registry snapshot rejected: {e}")))?;

        // 2. Unlock key hierarchy
        let secret_key = mnemonic::to_bytes(&response.mnemonic).map_err(CoreError::Crypto)?;

        let mut key_hierarchy = KeyHierarchy::new();
        key_hierarchy
            .unlock(password, &secret_key, &response.wrapped_dek, &response.salt)
            .map_err(CoreError::Crypto)?;

        // 3. Reuse the original joiner identity when the response came from
        // a joiner-generated pairing request. Legacy invite-only flows still
        // fall back to generating a new device identity here.
        let (device_secret, device_id) = self.load_joiner_identity(response)?;
        let signing_key = device_secret
            .ed25519_keypair(&device_id)
            .map_err(CoreError::Crypto)?;
        let exchange_key = device_secret
            .x25519_keypair(&device_id)
            .map_err(CoreError::Crypto)?;
        let pq_signing_key = device_secret
            .ml_dsa_65_keypair(&device_id)
            .map_err(CoreError::Crypto)?;
        let pq_kem_key = device_secret
            .ml_kem_768_keypair(&device_id)
            .map_err(CoreError::Crypto)?;

        // 4. Fetch registration nonce and build V2 hybrid challenge (CRITICAL-2)
        let nonce_response = self
            .relay
            .get_registration_nonce()
            .await
            .map_err(|e| CoreError::from_relay_with_context(Some("nonce fetch"), e))?;
        self.ratchet_min_signature_version(nonce_response.min_signature_version)?;
        let pow_solution = solve_registration_pow(&response.sync_id, &device_id, &nonce_response)?;
        let nonce = nonce_response.nonce;

        let challenge_signature = build_hybrid_challenge_signature(
            &signing_key,
            &pq_signing_key,
            &response.sync_id,
            &device_id,
            &nonce,
        );

        // 5. Register with relay
        let registry_approval =
            response
                .registry_approval_signature
                .as_ref()
                .map(|approval_signature| RegistryApproval {
                    approver_device_id: response.inviter_device_id.clone(),
                    approver_ed25519_pk: hex::encode(&response.inviter_ed25519_pk),
                    approver_ml_dsa_65_pk: hex::encode(&response.inviter_ml_dsa_65_pk),
                    approval_signature: approval_signature.clone(),
                    signed_registry_snapshot: response.signed_keyring.clone(),
                });
        let join_register_response = self
            .relay
            .register_device(crate::relay::traits::RegisterRequest {
                device_id: device_id.clone(),
                signing_public_key: signing_key.public_key_bytes().to_vec(),
                x25519_public_key: exchange_key.public_key_bytes().to_vec(),
                ml_dsa_65_public_key: pq_signing_key.public_key_bytes(),
                ml_kem_768_public_key: pq_kem_key.public_key_bytes(),
                registration_challenge: challenge_signature,
                nonce,
                pow_solution,
                first_device_admission_proof: None,
                registry_approval,
            })
            .await
            .map_err(|e| CoreError::from_relay_with_context(Some("registration failed"), e))?;
        self.ratchet_min_signature_version(join_register_response.min_signature_version)?;

        // 6. Persist credentials to secure store (with rollback marker)
        self.secure_store
            .set("setup_rollback_marker", b"in_progress")?;
        self.secure_store.set(
            "session_token",
            join_register_response.device_session_token.as_bytes(),
        )?;
        self.secure_store
            .set("sync_id", response.sync_id.as_bytes())?;
        self.secure_store
            .set("relay_url", response.relay_url.as_bytes())?;
        self.secure_store
            .set("mnemonic", response.mnemonic.as_bytes())?;
        self.secure_store
            .set("wrapped_dek", &response.wrapped_dek)?;
        self.secure_store.set("dek_salt", &response.salt)?;
        self.secure_store
            .set("device_secret", device_secret.as_bytes())?;
        self.secure_store.set("device_id", device_id.as_bytes())?;
        let epoch_str = response.current_epoch.to_string();
        self.secure_store.set("epoch", epoch_str.as_bytes())?;

        // Store epoch key from pairing response so the joining device can
        // decrypt the current epoch immediately after join.
        if response.current_epoch > 0 && response.epoch_key.len() == 32 {
            key_hierarchy.store_epoch_key(
                response.current_epoch,
                zeroize::Zeroizing::new(response.epoch_key.clone()),
            );
            // Persist to secure store for restart recovery (base64 format)
            use base64::{engine::general_purpose::STANDARD, Engine};
            let encoded = STANDARD.encode(&response.epoch_key);
            self.secure_store.set(
                &format!("epoch_key_{}", response.current_epoch),
                encoded.as_bytes(),
            )?;
        }

        self.secure_store.delete("setup_rollback_marker")?;

        Ok((key_hierarchy, registry_snapshot))
    }

    /// Start the new Phase 3 joiner bootstrap ceremony.
    pub async fn start_bootstrap_pairing(
        &self,
        relay: &dyn PairingRelay,
        relay_url: &str,
    ) -> Result<(JoinerCeremony, RendezvousToken)> {
        let (ceremony, token) = JoinerCeremony::start(relay, relay_url).await?;
        self.secure_store
            .set("pending_device_secret", ceremony.device_secret().as_bytes())?;
        self.secure_store
            .set("pending_device_id", ceremony.device_id().as_bytes())?;
        Ok((ceremony, token))
    }

    /// Complete the joiner side of the bootstrap ceremony.
    ///
    /// The caller is expected to have already compared SAS codes.
    pub async fn complete_bootstrap_join(
        &self,
        ceremony: &JoinerCeremony,
        relay: &dyn PairingRelay,
        encrypted_credentials: &[u8],
        password: &str,
    ) -> Result<(KeyHierarchy, SignedRegistrySnapshot)> {
        // Publish our confirmation MAC before accepting credentials.
        let confirmation_mac = ceremony.confirmation_mac()?;
        relay
            .put_slot(
                &ceremony.rendezvous_id_hex(),
                PairingSlot::Confirmation,
                &confirmation_mac,
            )
            .await
            .map_err(|e| CoreError::from_relay_with_context(Some("posting confirmation"), e))?;

        let credential_bytes = if encrypted_credentials.is_empty() {
            wait_for_pairing_slot_bytes(
                relay,
                &ceremony.rendezvous_id_hex(),
                PairingSlot::Credentials,
                "credential bundle",
            )
            .await?
        } else {
            encrypted_credentials.to_vec()
        };
        let bundle = ceremony.decrypt_credentials(&credential_bytes)?;

        let inviter_pk: [u8; 32] = bundle
            .inviter_ed25519_pk
            .clone()
            .try_into()
            .map_err(|_| CoreError::Engine("invalid inviter public key length".into()))?;
        if bundle.inviter_ml_dsa_65_pk.is_empty() {
            return Err(CoreError::Engine(
                "credential bundle missing inviter ML-DSA public key".into(),
            ));
        }
        let registry_snapshot = SignedRegistrySnapshot::verify_and_decode_hybrid(
            &bundle.signed_keyring,
            &inviter_pk,
            &bundle.inviter_ml_dsa_65_pk,
        )
        .map_err(|e| CoreError::Engine(format!("registry snapshot rejected: {e}")))?;

        let secret_key = mnemonic::to_bytes(&bundle.mnemonic).map_err(CoreError::Crypto)?;
        let mut key_hierarchy = KeyHierarchy::new();
        key_hierarchy
            .unlock(password, &secret_key, &bundle.wrapped_dek, &bundle.salt)
            .map_err(CoreError::Crypto)?;

        let device_secret = ceremony.device_secret();
        let device_id = ceremony.device_id().to_string();
        let signing_key = device_secret
            .ed25519_keypair(&device_id)
            .map_err(CoreError::Crypto)?;
        let exchange_key = device_secret
            .x25519_keypair(&device_id)
            .map_err(CoreError::Crypto)?;
        let pq_signing_key = device_secret
            .ml_dsa_65_keypair(&device_id)
            .map_err(CoreError::Crypto)?;
        let pq_kem_key = device_secret
            .ml_kem_768_keypair(&device_id)
            .map_err(CoreError::Crypto)?;

        let sync_id = bundle.sync_id.clone();
        let nonce_response = self
            .relay
            .get_registration_nonce()
            .await
            .map_err(|e| CoreError::from_relay_with_context(Some("nonce fetch"), e))?;
        self.ratchet_min_signature_version(nonce_response.min_signature_version)?;
        let pow_solution = solve_registration_pow(&sync_id, &device_id, &nonce_response)?;
        let nonce = nonce_response.nonce;

        let challenge_signature = build_hybrid_challenge_signature(
            &signing_key,
            &pq_signing_key,
            &sync_id,
            &device_id,
            &nonce,
        );

        let registry_approval =
            bundle
                .registry_approval_signature
                .as_ref()
                .map(|approval_signature| RegistryApproval {
                    approver_device_id: bundle.inviter_device_id.clone(),
                    approver_ed25519_pk: hex::encode(&bundle.inviter_ed25519_pk),
                    approver_ml_dsa_65_pk: hex::encode(&bundle.inviter_ml_dsa_65_pk),
                    approval_signature: approval_signature.clone(),
                    signed_registry_snapshot: bundle.signed_keyring.clone(),
                });

        let register_response = self
            .relay
            .register_device(crate::relay::traits::RegisterRequest {
                device_id: device_id.clone(),
                signing_public_key: signing_key.public_key_bytes().to_vec(),
                x25519_public_key: exchange_key.public_key_bytes().to_vec(),
                ml_dsa_65_public_key: pq_signing_key.public_key_bytes(),
                ml_kem_768_public_key: pq_kem_key.public_key_bytes(),
                registration_challenge: challenge_signature,
                nonce,
                pow_solution,
                first_device_admission_proof: None,
                registry_approval,
            })
            .await
            .map_err(|e| CoreError::from_relay_with_context(Some("registration failed"), e))?;
        self.ratchet_min_signature_version(register_response.min_signature_version)?;

        self.secure_store
            .set("setup_rollback_marker", b"in_progress")?;
        self.secure_store.set(
            "session_token",
            register_response.device_session_token.as_bytes(),
        )?;
        self.secure_store
            .set("sync_id", bundle.sync_id.as_bytes())?;
        self.secure_store
            .set("relay_url", bundle.relay_url.as_bytes())?;
        self.secure_store
            .set("mnemonic", bundle.mnemonic.as_bytes())?;
        self.secure_store.set("wrapped_dek", &bundle.wrapped_dek)?;
        self.secure_store.set("dek_salt", &bundle.salt)?;
        self.secure_store
            .set("device_secret", device_secret.as_bytes())?;
        self.secure_store.set("device_id", device_id.as_bytes())?;
        self.secure_store
            .set("epoch", bundle.current_epoch.to_string().as_bytes())?;
        if bundle.current_epoch > 0 && !bundle.epoch_key.is_empty() {
            use base64::{engine::general_purpose::STANDARD, Engine};
            let encoded = STANDARD.encode(&bundle.epoch_key);
            self.secure_store.set(
                &format!("epoch_key_{}", bundle.current_epoch),
                encoded.as_bytes(),
            )?;
            key_hierarchy.store_epoch_key(
                bundle.current_epoch,
                zeroize::Zeroizing::new(bundle.epoch_key.clone()),
            );
        }
        if let Some(ref token) = bundle.registration_token {
            self.secure_store
                .set("registration_token", token.as_bytes())?;
        }

        let joiner_bundle_bytes = ceremony.encrypt_joiner_bundle()?;
        relay
            .put_slot(
                &ceremony.rendezvous_id_hex(),
                PairingSlot::Joiner,
                &joiner_bundle_bytes,
            )
            .await
            .map_err(|e| CoreError::from_relay_with_context(Some("posting joiner bundle"), e))?;

        self.secure_store.delete("setup_rollback_marker")?;
        self.secure_store.delete("pending_device_secret")?;
        self.secure_store.delete("pending_device_id")?;

        Ok((key_hierarchy, registry_snapshot))
    }

    /// Start the initiator side of the bootstrap ceremony.
    pub async fn start_bootstrap_initiator(
        &self,
        token: RendezvousToken,
        relay: &dyn PairingRelay,
    ) -> Result<(InitiatorCeremony, SasDisplay)> {
        let (device_secret, device_id) = self.load_current_device_identity()?;
        InitiatorCeremony::start(token, relay, &device_secret, &device_id).await
    }

    /// Complete the initiator side after SAS confirmation.
    pub async fn complete_bootstrap_initiator(
        &self,
        ceremony: &InitiatorCeremony,
        relay: &dyn PairingRelay,
        password: &str,
    ) -> Result<()> {
        // Verify the joiner's confirmation MAC before sending credentials.
        let confirmation = wait_for_pairing_slot_bytes(
            relay,
            &ceremony.rendezvous_id_hex(),
            PairingSlot::Confirmation,
            "joiner confirmation",
        )
        .await?;
        ceremony.verify_joiner_confirmation(&confirmation)?;

        let (device_secret, device_id) = self.load_current_device_identity()?;
        let signing_key = device_secret
            .ed25519_keypair(&device_id)
            .map_err(CoreError::Crypto)?;
        let exchange_key = device_secret
            .x25519_keypair(&device_id)
            .map_err(CoreError::Crypto)?;
        let pq_signing_key = device_secret
            .ml_dsa_65_keypair(&device_id)
            .map_err(CoreError::Crypto)?;
        let pq_kem_key = device_secret
            .ml_kem_768_keypair(&device_id)
            .map_err(CoreError::Crypto)?;

        let mut key_hierarchy = KeyHierarchy::new();
        let sync_id = self.load_secure_string("sync_id")?;
        let relay_url = self.load_secure_string("relay_url")?;
        let mnemonic = self.load_secure_string("mnemonic")?;
        let secret_key = mnemonic::to_bytes(&mnemonic).map_err(CoreError::Crypto)?;
        let wrapped_dek = self.load_secure_bytes("wrapped_dek")?;
        let salt = self.load_secure_bytes("dek_salt")?;
        key_hierarchy
            .unlock(password, &secret_key, &wrapped_dek, &salt)
            .map_err(CoreError::Crypto)?;
        let current_epoch = self
            .load_secure_string("epoch")?
            .parse::<u32>()
            .map_err(|e| CoreError::Engine(format!("invalid stored epoch value: {e}")))?;
        let epoch_key = self.load_epoch_key(&key_hierarchy, current_epoch)?;

        let bootstrap_bytes = relay
            .get_bootstrap(&ceremony.rendezvous_id_hex())
            .await
            .map_err(|e| CoreError::from_relay_with_context(Some("fetching bootstrap"), e))?;
        let bootstrap_record = JoinerBootstrapRecord::from_canonical_bytes(&bootstrap_bytes)
            .ok_or_else(|| CoreError::Engine("failed to parse JoinerBootstrapRecord".into()))?;

        let mut devices = self
            .relay
            .list_devices()
            .await
            .map_err(|e| CoreError::from_relay_with_context(Some("listing devices"), e))?;
        devices.retain(|device| device.status == "active");

        let mut snapshot_entries: Vec<RegistrySnapshotEntry> = devices
            .into_iter()
            .filter(|device| device.device_id != device_id)
            .map(|device| RegistrySnapshotEntry {
                sync_id: sync_id.clone(),
                device_id: device.device_id,
                ed25519_public_key: device.ed25519_public_key,
                x25519_public_key: device.x25519_public_key,
                ml_dsa_65_public_key: device.ml_dsa_65_public_key,
                ml_kem_768_public_key: device.ml_kem_768_public_key,
                status: device.status,
                ml_dsa_key_generation: device.ml_dsa_key_generation,
            })
            .collect();
        snapshot_entries.push(RegistrySnapshotEntry {
            sync_id: sync_id.clone(),
            device_id: device_id.clone(),
            ed25519_public_key: signing_key.public_key_bytes().to_vec(),
            x25519_public_key: exchange_key.public_key_bytes().to_vec(),
            ml_dsa_65_public_key: pq_signing_key.public_key_bytes(),
            ml_kem_768_public_key: pq_kem_key.public_key_bytes(),
            status: "active".into(),
            ml_dsa_key_generation: 0,
        });
        snapshot_entries.push(RegistrySnapshotEntry {
            sync_id: sync_id.clone(),
            device_id: bootstrap_record.device_id.clone(),
            ed25519_public_key: bootstrap_record.ed25519_public_key.to_vec(),
            x25519_public_key: bootstrap_record.x25519_public_key.to_vec(),
            ml_dsa_65_public_key: bootstrap_record.ml_dsa_65_public_key.clone(),
            ml_kem_768_public_key: bootstrap_record.ml_kem_768_ek().to_vec(),
            status: "active".into(),
            ml_dsa_key_generation: 0,
        });

        let registry_snapshot = SignedRegistrySnapshot::new(snapshot_entries);
        let signed_keyring = registry_snapshot.sign_hybrid(&signing_key, &pq_signing_key);

        // V3 hybrid registry approval signature (labeled WNS)
        let approval_data =
            build_registry_approval_signing_data_v2(&sync_id, &device_id, &signed_keyring);
        let m_prime_approval = prism_sync_crypto::pq::build_hybrid_message_representative(
            b"registry_approval",
            &approval_data,
        )
        .expect("hardcoded registry approval context should be <= 255 bytes");
        let hybrid_approval = prism_sync_crypto::pq::HybridSignature {
            ed25519_sig: signing_key.sign(&m_prime_approval),
            ml_dsa_65_sig: pq_signing_key.sign(&m_prime_approval),
        };
        let mut approval_wire = vec![0x03u8];
        approval_wire.extend_from_slice(&hybrid_approval.to_bytes());
        let approval_signature = hex::encode(&approval_wire);

        let credential_bundle = BootstrapCredentialBundle {
            sync_id: sync_id.clone(),
            relay_url: relay_url.clone(),
            mnemonic: mnemonic.clone(),
            wrapped_dek: wrapped_dek.clone(),
            salt: salt.clone(),
            current_epoch,
            epoch_key,
            signed_keyring: signed_keyring.clone(),
            inviter_device_id: device_id.clone(),
            inviter_ed25519_pk: signing_key.public_key_bytes().to_vec(),
            inviter_ml_dsa_65_pk: pq_signing_key.public_key_bytes(),
            registry_approval_signature: Some(approval_signature),
            registration_token: self.load_optional_secure_string("registration_token")?,
        };

        let credential_envelope = ceremony.encrypt_credentials(&credential_bundle)?;
        relay
            .put_slot(
                &ceremony.rendezvous_id_hex(),
                PairingSlot::Credentials,
                &credential_envelope,
            )
            .await
            .map_err(|e| CoreError::from_relay_with_context(Some("posting credentials"), e))?;

        let joiner_bundle_bytes = wait_for_pairing_slot_bytes(
            relay,
            &ceremony.rendezvous_id_hex(),
            PairingSlot::Joiner,
            "joiner bundle",
        )
        .await?;
        let joiner_bundle = ceremony.decrypt_joiner_bundle(&joiner_bundle_bytes)?;

        self.secure_store.set(
            "bootstrap_joiner_bundle",
            &serde_json::to_vec(&joiner_bundle)?,
        )?;
        self.secure_store.set(
            "bootstrap_joiner_device_id",
            joiner_bundle.device_id.as_bytes(),
        )?;

        let joiner_exchange = device_secret
            .x25519_keypair(&device_id)
            .map_err(CoreError::Crypto)?;
        let next_epoch = current_epoch.saturating_add(1);
        let epoch_key = EpochManager::post_rekey(
            self.relay.as_ref(),
            &mut key_hierarchy,
            next_epoch,
            &joiner_exchange,
        )
        .await?;

        self.secure_store
            .set("epoch", next_epoch.to_string().as_bytes())?;
        use base64::{engine::general_purpose::STANDARD, Engine};
        let encoded = STANDARD.encode(epoch_key.as_slice());
        self.secure_store
            .set(&format!("epoch_key_{next_epoch}"), encoded.as_bytes())?;

        relay
            .delete_session(&ceremony.rendezvous_id_hex())
            .await
            .map_err(|e| CoreError::from_relay_with_context(Some("deleting pairing session"), e))?;

        Ok(())
    }

    /// Access the underlying relay.
    pub fn relay(&self) -> &Arc<dyn SyncRelay> {
        &self.relay
    }

    /// Access the underlying secure store.
    pub fn secure_store(&self) -> &Arc<dyn SecureStore> {
        &self.secure_store
    }

    fn load_current_device_identity(&self) -> Result<(DeviceSecret, String)> {
        if let (Some(secret_bytes), Some(device_id_bytes)) = (
            self.secure_store.get("device_secret")?,
            self.secure_store.get("device_id")?,
        ) {
            let device_id = String::from_utf8(device_id_bytes).map_err(|e| {
                CoreError::Engine(format!("invalid device id in secure store: {e}"))
            })?;
            let device_secret =
                DeviceSecret::from_bytes(secret_bytes).map_err(CoreError::Crypto)?;
            return Ok((device_secret, device_id));
        }
        if let Some(identity) = self.load_pending_identity()? {
            return Ok(identity);
        }
        Err(CoreError::Engine(
            "missing device identity in secure store".into(),
        ))
    }

    fn load_secure_bytes(&self, key: &str) -> Result<Vec<u8>> {
        self.secure_store
            .get(key)?
            .ok_or_else(|| CoreError::Engine(format!("missing {key} in secure store")))
    }

    fn load_secure_string(&self, key: &str) -> Result<String> {
        let bytes = self.load_secure_bytes(key)?;
        String::from_utf8(bytes)
            .map_err(|e| CoreError::Engine(format!("invalid {key} in secure store: {e}")))
    }

    fn load_epoch_key(&self, key_hierarchy: &KeyHierarchy, epoch: u32) -> Result<Vec<u8>> {
        if epoch == 0 {
            return Ok(Vec::new());
        }

        let key_name = format!("epoch_key_{epoch}");
        if let Some(encoded) = self.secure_store.get(&key_name)? {
            use base64::{engine::general_purpose::STANDARD, Engine};
            return STANDARD.decode(&encoded).map_err(|e| {
                CoreError::Engine(format!("invalid encoded {key_name} in secure store: {e}"))
            });
        }

        Ok(key_hierarchy
            .epoch_key(epoch)
            .map_err(CoreError::Crypto)?
            .to_vec())
    }

    fn load_optional_secure_string(&self, key: &str) -> Result<Option<String>> {
        self.secure_store
            .get(key)?
            .map(|bytes| {
                String::from_utf8(bytes)
                    .map_err(|e| CoreError::Engine(format!("invalid {key} in secure store: {e}")))
            })
            .transpose()
    }

    fn load_pending_identity(&self) -> Result<Option<(DeviceSecret, String)>> {
        let pending_secret = self.secure_store.get("pending_device_secret")?;
        let pending_device_id = self.secure_store.get("pending_device_id")?;

        let Some(secret_bytes) = pending_secret else {
            return Ok(None);
        };
        let device_id_bytes = pending_device_id
            .ok_or_else(|| CoreError::Engine("missing pending device id".into()))?;
        let device_id = String::from_utf8(device_id_bytes)
            .map_err(|e| CoreError::Engine(format!("invalid pending device id: {e}")))?;
        let device_secret = DeviceSecret::from_bytes(secret_bytes).map_err(CoreError::Crypto)?;
        Ok(Some((device_secret, device_id)))
    }

    fn load_joiner_identity(&self, response: &PairingResponse) -> Result<(DeviceSecret, String)> {
        let expected_device_id = response.joiner_device_id.clone();
        if let Some((device_secret, device_id)) = self.load_pending_identity()? {
            if let Some(expected) = expected_device_id.as_deref() {
                if device_id != expected {
                    return Err(CoreError::Engine(
                        "pairing response targets a different join request".into(),
                    ));
                }
            }
            return Ok((device_secret, device_id));
        }

        if response.registry_approval_signature.is_some() {
            return Err(CoreError::Engine(
                "approved pairing response requires the original pairing request identity".into(),
            ));
        }

        let device_id = expected_device_id.unwrap_or_else(crate::node_id::generate_node_id);
        Ok((DeviceSecret::generate(), device_id))
    }
}

/// Verify a hybrid invitation signature.
///
/// Accepts only the Phase 6 V3 labeled-WNS wire format.
fn verify_hybrid_invitation(
    signing_data: &[u8],
    sig_bytes: &[u8],
    inviter_ed25519_pk: &[u8; 32],
    inviter_ml_dsa_65_pk: &[u8],
) -> Result<()> {
    let Some((&version, sig_rest)) = sig_bytes.split_first() else {
        return Err(CoreError::Engine("invitation signature too short".into()));
    };
    let hybrid_sig = prism_sync_crypto::pq::HybridSignature::from_bytes(sig_rest)
        .map_err(|e| CoreError::Engine(format!("invitation hybrid signature invalid: {e}")))?;
    match version {
        0x03 => hybrid_sig
            .verify_v3(
                signing_data,
                b"invitation",
                inviter_ed25519_pk,
                inviter_ml_dsa_65_pk,
            )
            .map_err(|e| CoreError::Engine(format!("invitation signature invalid: {e}")))?,
        _ => {
            return Err(CoreError::Engine(format!(
                "unsupported invitation signature version: 0x{version:02x}"
            )))
        }
    }
    Ok(())
}

/// Build a V3 hybrid challenge signature for relay registration.
///
/// Wire format: `[0x03][HybridSignature::to_bytes()]`
fn build_hybrid_challenge_signature(
    signing_key: &prism_sync_crypto::DeviceSigningKey,
    pq_signing_key: &prism_sync_crypto::DevicePqSigningKey,
    sync_id: &str,
    device_id: &str,
    nonce: &str,
) -> Vec<u8> {
    fn write_len_prefixed(buf: &mut Vec<u8>, data: &[u8]) {
        buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
        buf.extend_from_slice(data);
    }
    let mut challenge_data = Vec::new();
    challenge_data.extend_from_slice(b"PRISM_SYNC_CHALLENGE_V2\x00");
    write_len_prefixed(&mut challenge_data, sync_id.as_bytes());
    write_len_prefixed(&mut challenge_data, device_id.as_bytes());
    write_len_prefixed(&mut challenge_data, nonce.as_bytes());

    let m_prime = prism_sync_crypto::pq::build_hybrid_message_representative(
        b"device_challenge",
        &challenge_data,
    )
    .expect("hardcoded device challenge context should be <= 255 bytes");
    let hybrid_sig = prism_sync_crypto::pq::HybridSignature {
        ed25519_sig: signing_key.sign(&m_prime),
        ml_dsa_65_sig: pq_signing_key.sign(&m_prime),
    };
    let mut wire = vec![0x03u8];
    wire.extend_from_slice(&hybrid_sig.to_bytes());
    wire
}

fn solve_registration_pow(
    sync_id: &str,
    device_id: &str,
    nonce_response: &RegistrationNonceResponse,
) -> Result<Option<ProofOfWorkSolution>> {
    let challenge = match &nonce_response.pow_challenge {
        Some(challenge) => challenge,
        None => return Ok(None),
    };

    if challenge.algorithm != "sha256_leading_zero_bits" {
        return Err(CoreError::Engine(format!(
            "unsupported first-device admission challenge: {}",
            challenge.algorithm
        )));
    }

    let counter = find_pow_counter(sync_id, device_id, &nonce_response.nonce, challenge)?;
    Ok(Some(ProofOfWorkSolution { counter }))
}

fn find_pow_counter(
    sync_id: &str,
    device_id: &str,
    nonce: &str,
    challenge: &ProofOfWorkChallenge,
) -> Result<u64> {
    for counter in 0..=u64::MAX {
        if pow_hash_meets_difficulty(
            &compute_registration_pow_hash(sync_id, device_id, nonce, counter),
            challenge.difficulty_bits,
        ) {
            return Ok(counter);
        }
    }

    Err(CoreError::Engine(
        "failed to solve first-device admission challenge".into(),
    ))
}

fn compute_registration_pow_hash(
    sync_id: &str,
    device_id: &str,
    nonce: &str,
    counter: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"PRISM_SYNC_FIRST_DEVICE_POW_V1\x00");
    hasher.update(sync_id.as_bytes());
    hasher.update([0]);
    hasher.update(device_id.as_bytes());
    hasher.update([0]);
    hasher.update(nonce.as_bytes());
    hasher.update([0]);
    hasher.update(counter.to_be_bytes());
    hasher.finalize().into()
}

fn pow_hash_meets_difficulty(hash: &[u8; 32], difficulty_bits: u8) -> bool {
    let full_zero_bytes = (difficulty_bits / 8) as usize;
    let remaining_bits = difficulty_bits % 8;

    if hash[..full_zero_bytes].iter().any(|byte| *byte != 0) {
        return false;
    }

    if remaining_bits == 0 {
        return true;
    }

    let mask = 0xFFu8 << (8 - remaining_bits);
    hash.get(full_zero_bytes)
        .map(|byte| byte & mask == 0)
        .unwrap_or(false)
}

/// Call on app startup to clean up a partially-completed setup.
///
/// If the previous `create_sync_group` or `join_sync_group` crashed mid-write,
/// a `setup_rollback_marker` key will be present in the secure store. This
/// function removes all partial credentials and deregisters from the relay.
///
/// Returns `Ok(true)` if cleanup was performed, `Ok(false)` if no cleanup
/// was needed.
pub async fn cleanup_failed_setup(
    secure_store: &dyn SecureStore,
    relay: &dyn SyncRelay,
) -> Result<bool> {
    if secure_store.get("setup_rollback_marker")?.is_some() {
        let _ = relay.deregister().await;
        for key in [
            "sync_id",
            "relay_url",
            "mnemonic",
            "wrapped_dek",
            "dek_salt",
            "device_secret",
            "device_id",
            "setup_rollback_marker",
        ] {
            let _ = secure_store.delete(key);
        }
        return Ok(true);
    }
    Ok(false)
}

async fn wait_for_pairing_slot_bytes(
    relay: &dyn PairingRelay,
    rendezvous_id: &str,
    slot: PairingSlot,
    description: &str,
) -> Result<Vec<u8>> {
    const MAX_ATTEMPTS: usize = 200;
    for _ in 0..MAX_ATTEMPTS {
        match relay
            .get_slot(rendezvous_id, slot)
            .await
            .map_err(|e| CoreError::from_relay_with_context(Some(description), e))?
        {
            Some(bytes) => return Ok(bytes),
            None => sleep(Duration::from_millis(25)).await,
        }
    }

    Err(CoreError::Engine(format!(
        "timed out waiting for {description}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap::JoinerBundle;
    use crate::relay::pairing_relay::PairingRelay;
    use crate::relay::traits::*;
    use crate::relay::MockPairingRelay;
    use async_trait::async_trait;
    use futures_util::Stream;
    use std::collections::HashMap;
    use std::pin::Pin;
    use std::sync::Mutex;
    use tokio::time::{sleep, Duration};

    // ── Mock SecureStore ──

    #[derive(Default)]
    struct MemStore(Mutex<HashMap<String, Vec<u8>>>);

    impl SecureStore for MemStore {
        fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
            Ok(self.0.lock().unwrap().get(key).cloned())
        }
        fn set(&self, key: &str, value: &[u8]) -> Result<()> {
            self.0
                .lock()
                .unwrap()
                .insert(key.to_string(), value.to_vec());
            Ok(())
        }
        fn delete(&self, key: &str) -> Result<()> {
            self.0.lock().unwrap().remove(key);
            Ok(())
        }
        fn clear(&self) -> Result<()> {
            self.0.lock().unwrap().clear();
            Ok(())
        }
    }

    // ── Mock Relay (minimal) ──

    struct MockRelay;

    #[async_trait]
    impl SyncRelay for MockRelay {
        async fn get_registration_nonce(
            &self,
        ) -> std::result::Result<RegistrationNonceResponse, RelayError> {
            Ok(RegistrationNonceResponse {
                nonce: uuid::Uuid::new_v4().to_string(),
                pow_challenge: None,
                min_signature_version: None,
            })
        }
        async fn register_device(
            &self,
            _req: RegisterRequest,
        ) -> std::result::Result<RegisterResponse, RelayError> {
            Ok(RegisterResponse {
                device_session_token: "mock-session-token".to_string(),
                min_signature_version: None,
            })
        }
        async fn pull_changes(&self, _since: i64) -> std::result::Result<PullResponse, RelayError> {
            unimplemented!()
        }
        async fn push_changes(
            &self,
            _batch: OutgoingBatch,
        ) -> std::result::Result<i64, RelayError> {
            unimplemented!()
        }
        async fn get_snapshot(&self) -> std::result::Result<Option<SnapshotResponse>, RelayError> {
            unimplemented!()
        }
        async fn put_snapshot(
            &self,
            _epoch: i32,
            _seq: i64,
            _data: Vec<u8>,
            _ttl_secs: Option<u64>,
            _for_device_id: Option<String>,
            _sender_device_id: String,
        ) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
        async fn list_devices(&self) -> std::result::Result<Vec<DeviceInfo>, RelayError> {
            unimplemented!()
        }
        async fn revoke_device(
            &self,
            _device_id: &str,
            _remote_wipe: bool,
            _new_epoch: i32,
            _wrapped_keys: HashMap<String, Vec<u8>>,
        ) -> std::result::Result<i32, RelayError> {
            unimplemented!()
        }
        async fn post_rekey_artifacts(
            &self,
            _epoch: i32,
            _keys: HashMap<String, Vec<u8>>,
        ) -> std::result::Result<i32, RelayError> {
            unimplemented!()
        }
        async fn get_rekey_artifact(
            &self,
            _epoch: i32,
            _device_id: &str,
        ) -> std::result::Result<Option<Vec<u8>>, RelayError> {
            unimplemented!()
        }
        async fn deregister(&self) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
        async fn delete_sync_group(&self) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
        async fn ack(&self, _seq: i64) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
        async fn connect_websocket(&self) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
        async fn disconnect_websocket(&self) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
        fn notifications(&self) -> Pin<Box<dyn Stream<Item = SyncNotification> + Send>> {
            unimplemented!()
        }
        async fn rotate_ml_dsa(
            &self,
            _: &str,
            _: &[u8],
            _: u32,
            _: &prism_sync_crypto::pq::continuity_proof::MlDsaContinuityProof,
        ) -> std::result::Result<RotateMlDsaResponse, RelayError> {
            unimplemented!()
        }
        async fn upload_media(
            &self,
            _: &str,
            _: &str,
            _: Vec<u8>,
        ) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
        async fn download_media(&self, _: &str) -> std::result::Result<Vec<u8>, RelayError> {
            unimplemented!()
        }
        async fn dispose(&self) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
    }

    #[derive(Default)]
    struct BootstrapRegistryState {
        devices: Vec<DeviceInfo>,
        register_requests: Vec<RegisterRequest>,
        rekey_posts: Option<(i32, HashMap<String, Vec<u8>>)>,
    }

    #[derive(Clone, Default)]
    struct BootstrapRegistryRelay {
        state: std::sync::Arc<Mutex<BootstrapRegistryState>>,
    }

    impl BootstrapRegistryRelay {
        fn new(devices: Vec<DeviceInfo>) -> Self {
            Self {
                state: std::sync::Arc::new(Mutex::new(BootstrapRegistryState {
                    devices,
                    register_requests: Vec::new(),
                    rekey_posts: None,
                })),
            }
        }
    }

    #[async_trait]
    impl SyncRelay for BootstrapRegistryRelay {
        async fn get_registration_nonce(
            &self,
        ) -> std::result::Result<RegistrationNonceResponse, RelayError> {
            Ok(RegistrationNonceResponse {
                nonce: "bootstrap-nonce".to_string(),
                pow_challenge: None,
                min_signature_version: None,
            })
        }
        async fn register_device(
            &self,
            req: RegisterRequest,
        ) -> std::result::Result<RegisterResponse, RelayError> {
            let mut state = self.state.lock().unwrap();
            state.register_requests.push(req.clone());
            state.devices.push(DeviceInfo {
                device_id: req.device_id,
                epoch: 0,
                status: "active".to_string(),
                ed25519_public_key: req.signing_public_key,
                x25519_public_key: req.x25519_public_key,
                ml_dsa_65_public_key: req.ml_dsa_65_public_key,
                ml_kem_768_public_key: req.ml_kem_768_public_key,
                permission: None,
                ml_dsa_key_generation: 0,
            });
            Ok(RegisterResponse {
                device_session_token: "mock-session-token".to_string(),
                min_signature_version: None,
            })
        }
        async fn pull_changes(&self, _since: i64) -> std::result::Result<PullResponse, RelayError> {
            unimplemented!()
        }
        async fn push_changes(
            &self,
            _batch: OutgoingBatch,
        ) -> std::result::Result<i64, RelayError> {
            unimplemented!()
        }
        async fn get_snapshot(&self) -> std::result::Result<Option<SnapshotResponse>, RelayError> {
            unimplemented!()
        }
        async fn put_snapshot(
            &self,
            _epoch: i32,
            _seq: i64,
            _data: Vec<u8>,
            _ttl_secs: Option<u64>,
            _for_device_id: Option<String>,
            _sender_device_id: String,
        ) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
        async fn list_devices(&self) -> std::result::Result<Vec<DeviceInfo>, RelayError> {
            Ok(self.state.lock().unwrap().devices.clone())
        }
        async fn revoke_device(
            &self,
            _device_id: &str,
            _remote_wipe: bool,
            _new_epoch: i32,
            _wrapped_keys: HashMap<String, Vec<u8>>,
        ) -> std::result::Result<i32, RelayError> {
            unimplemented!()
        }
        async fn post_rekey_artifacts(
            &self,
            epoch: i32,
            keys: HashMap<String, Vec<u8>>,
        ) -> std::result::Result<i32, RelayError> {
            self.state.lock().unwrap().rekey_posts = Some((epoch, keys));
            Ok(epoch)
        }
        async fn get_rekey_artifact(
            &self,
            _epoch: i32,
            _device_id: &str,
        ) -> std::result::Result<Option<Vec<u8>>, RelayError> {
            Ok(None)
        }
        async fn deregister(&self) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
        async fn delete_sync_group(&self) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
        async fn ack(&self, _seq: i64) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
        async fn connect_websocket(&self) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
        async fn disconnect_websocket(&self) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
        fn notifications(&self) -> Pin<Box<dyn Stream<Item = SyncNotification> + Send>> {
            unimplemented!()
        }
        async fn rotate_ml_dsa(
            &self,
            _: &str,
            _: &[u8],
            _: u32,
            _: &prism_sync_crypto::pq::continuity_proof::MlDsaContinuityProof,
        ) -> std::result::Result<RotateMlDsaResponse, RelayError> {
            unimplemented!()
        }
        async fn upload_media(
            &self,
            _: &str,
            _: &str,
            _: Vec<u8>,
        ) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
        async fn download_media(&self, _: &str) -> std::result::Result<Vec<u8>, RelayError> {
            unimplemented!()
        }
        async fn dispose(&self) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn seed_bootstrap_store(
        store: &MemStore,
        device_secret: &DeviceSecret,
        device_id: &str,
        sync_id: &str,
        relay_url: &str,
        mnemonic_str: &str,
        wrapped_dek: &[u8],
        salt: &[u8],
    ) {
        store
            .set("device_secret", device_secret.as_bytes())
            .unwrap();
        store.set("device_id", device_id.as_bytes()).unwrap();
        store.set("sync_id", sync_id.as_bytes()).unwrap();
        store.set("relay_url", relay_url.as_bytes()).unwrap();
        store.set("mnemonic", mnemonic_str.as_bytes()).unwrap();
        store.set("wrapped_dek", wrapped_dek).unwrap();
        store.set("dek_salt", salt).unwrap();
        store.set("epoch", b"0").unwrap();
    }

    async fn wait_for_slot(
        relay: &dyn PairingRelay,
        rendezvous_id: &str,
        slot: PairingSlot,
    ) -> Vec<u8> {
        for _ in 0..200 {
            if let Some(bytes) = relay.get_slot(rendezvous_id, slot).await.unwrap() {
                return bytes;
            }
            sleep(Duration::from_millis(25)).await;
        }
        panic!("timed out waiting for slot {slot:?}");
    }

    #[tokio::test]
    async fn bootstrap_pairing_round_trip_and_rekey() {
        let password = "bootstrap-password";
        let relay_url = "https://relay.example.com";
        let sync_id = "sync-bootstrap-001";

        let device_secret = DeviceSecret::generate();
        let device_id = crate::node_id::generate_node_id();
        let mnemonic = mnemonic::generate();
        let secret_key = mnemonic::to_bytes(&mnemonic).unwrap();
        let mut key_hierarchy = KeyHierarchy::new();
        let (wrapped_dek, salt) = key_hierarchy.initialize(password, &secret_key).unwrap();

        let inviter_signing_key = device_secret.ed25519_keypair(&device_id).unwrap();
        let inviter_exchange_key = device_secret.x25519_keypair(&device_id).unwrap();

        let registry_relay = Arc::new(BootstrapRegistryRelay::new(vec![DeviceInfo {
            device_id: device_id.clone(),
            epoch: 0,
            status: "active".to_string(),
            ed25519_public_key: inviter_signing_key.public_key_bytes().to_vec(),
            x25519_public_key: inviter_exchange_key.public_key_bytes().to_vec(),
            ml_dsa_65_public_key: Vec::new(),
            ml_kem_768_public_key: Vec::new(),
            permission: None,
            ml_dsa_key_generation: 0,
        }]));

        let initiator_store = Arc::new(MemStore::default());
        seed_bootstrap_store(
            &initiator_store,
            &device_secret,
            &device_id,
            sync_id,
            relay_url,
            &mnemonic,
            &wrapped_dek,
            &salt,
        );
        initiator_store
            .set("registration_token", b"relay-registration-token")
            .unwrap();
        let initiator_service =
            PairingService::new(registry_relay.clone(), initiator_store.clone());

        let joiner_store = Arc::new(MemStore::default());
        let joiner_service = PairingService::new(registry_relay.clone(), joiner_store.clone());
        let joiner_service_task = PairingService::new(registry_relay.clone(), joiner_store.clone());

        let mailbox = Arc::new(MockPairingRelay::new());

        let (mut joiner, token) = joiner_service
            .start_bootstrap_pairing(mailbox.as_ref(), relay_url)
            .await
            .unwrap();
        let pending_joiner_id = String::from_utf8(
            joiner_store
                .get("pending_device_id")
                .unwrap()
                .expect("pending joiner id should be stored"),
        )
        .unwrap();
        assert_eq!(pending_joiner_id, joiner.device_id());

        let (initiator, initiator_sas) = initiator_service
            .start_bootstrap_initiator(token, mailbox.as_ref())
            .await
            .unwrap();

        let joiner_rendezvous_id = joiner.rendezvous_id_hex();
        let joiner_device_id = joiner.device_id().to_string();
        let init_bytes =
            wait_for_slot(mailbox.as_ref(), &joiner_rendezvous_id, PairingSlot::Init).await;
        let joiner_sas = joiner.process_pairing_init(&init_bytes).unwrap();
        assert_eq!(joiner_sas.words, initiator_sas.words);
        assert_eq!(joiner_sas.decimal, initiator_sas.decimal);

        let joiner_mailbox = mailbox.clone();
        let joiner_handle = tokio::spawn(async move {
            joiner_service_task
                .complete_bootstrap_join(&joiner, joiner_mailbox.as_ref(), &[], password)
                .await
                .unwrap()
        });

        initiator_service
            .complete_bootstrap_initiator(&initiator, mailbox.as_ref(), password)
            .await
            .unwrap();

        let (joiner_key_hierarchy, joiner_snapshot) = joiner_handle.await.unwrap();
        assert!(joiner_key_hierarchy.is_unlocked());
        assert!(joiner_snapshot.entries.len() >= 2);
        assert_eq!(
            String::from_utf8(
                joiner_store
                    .get("device_id")
                    .unwrap()
                    .expect("device id should be persisted")
            )
            .unwrap(),
            joiner_device_id
        );
        assert!(joiner_store.get("pending_device_secret").unwrap().is_none());
        assert!(joiner_store.get("pending_device_id").unwrap().is_none());
        assert_eq!(
            String::from_utf8(
                joiner_store
                    .get("registration_token")
                    .unwrap()
                    .expect("registration token should be persisted")
            )
            .unwrap(),
            "relay-registration-token"
        );

        let stored_joiner_bundle = initiator_store
            .get("bootstrap_joiner_bundle")
            .unwrap()
            .expect("initiator should persist joiner bundle");
        let stored_joiner_bundle: JoinerBundle =
            serde_json::from_slice(&stored_joiner_bundle).unwrap();
        assert_eq!(stored_joiner_bundle.device_id, joiner_device_id);

        {
            let state = registry_relay.state.lock().unwrap();
            assert_eq!(state.register_requests.len(), 1);
            let register_req = state.register_requests.last().unwrap();
            assert_eq!(register_req.device_id, joiner_device_id);
            assert!(register_req.registry_approval.is_some());
            assert!(!register_req
                .registry_approval
                .as_ref()
                .unwrap()
                .signed_registry_snapshot
                .is_empty());
            assert!(state.rekey_posts.is_some());
            let (next_epoch, wrapped_keys) = state.rekey_posts.as_ref().unwrap();
            assert!(*next_epoch >= 1);
            assert!(!wrapped_keys.is_empty());
        }

        let err = mailbox
            .get_bootstrap(&joiner_rendezvous_id)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("session not found"));
    }

    #[tokio::test]
    async fn bootstrap_join_fetches_credentials_when_bytes_not_supplied() {
        let password = "bootstrap-password";
        let relay_url = "https://relay.example.com";
        let sync_id = "sync-bootstrap-fetch";

        let device_secret = DeviceSecret::generate();
        let device_id = crate::node_id::generate_node_id();
        let mnemonic = mnemonic::generate();
        let secret_key = mnemonic::to_bytes(&mnemonic).unwrap();
        let mut key_hierarchy = KeyHierarchy::new();
        let (wrapped_dek, salt) = key_hierarchy.initialize(password, &secret_key).unwrap();

        let inviter_signing_key = device_secret.ed25519_keypair(&device_id).unwrap();
        let inviter_exchange_key = device_secret.x25519_keypair(&device_id).unwrap();
        let registry_relay = Arc::new(BootstrapRegistryRelay::new(vec![DeviceInfo {
            device_id: device_id.clone(),
            epoch: 0,
            status: "active".to_string(),
            ed25519_public_key: inviter_signing_key.public_key_bytes().to_vec(),
            x25519_public_key: inviter_exchange_key.public_key_bytes().to_vec(),
            ml_dsa_65_public_key: Vec::new(),
            ml_kem_768_public_key: Vec::new(),
            permission: None,
            ml_dsa_key_generation: 0,
        }]));

        let initiator_store = Arc::new(MemStore::default());
        seed_bootstrap_store(
            &initiator_store,
            &device_secret,
            &device_id,
            sync_id,
            relay_url,
            &mnemonic,
            &wrapped_dek,
            &salt,
        );
        let initiator_service = PairingService::new(registry_relay.clone(), initiator_store);
        let joiner_store = Arc::new(MemStore::default());
        let joiner_service = PairingService::new(registry_relay.clone(), joiner_store.clone());
        let joiner_service_task = PairingService::new(registry_relay.clone(), joiner_store.clone());
        let mailbox = Arc::new(MockPairingRelay::new());

        let (mut joiner, token) = joiner_service
            .start_bootstrap_pairing(mailbox.as_ref(), relay_url)
            .await
            .unwrap();
        let (initiator, initiator_sas) = initiator_service
            .start_bootstrap_initiator(token, mailbox.as_ref())
            .await
            .unwrap();

        let init_bytes = wait_for_slot(
            mailbox.as_ref(),
            &joiner.rendezvous_id_hex(),
            PairingSlot::Init,
        )
        .await;
        let joiner_sas = joiner.process_pairing_init(&init_bytes).unwrap();
        assert_eq!(joiner_sas.words, initiator_sas.words);

        let joiner_mailbox = mailbox.clone();
        let joiner_handle = tokio::spawn(async move {
            joiner_service_task
                .complete_bootstrap_join(&joiner, joiner_mailbox.as_ref(), &[], password)
                .await
                .unwrap()
        });

        initiator_service
            .complete_bootstrap_initiator(&initiator, mailbox.as_ref(), password)
            .await
            .unwrap();

        let (joiner_key_hierarchy, _) = joiner_handle.await.unwrap();
        assert!(joiner_key_hierarchy.is_unlocked());
    }

    #[tokio::test]
    async fn create_sync_group_returns_credentials_and_invite() {
        let relay = Arc::new(MockRelay);
        let store = Arc::new(MemStore::default());
        let service = PairingService::new(relay, store.clone());

        let (creds, response) = service
            .create_sync_group(
                "test-password",
                "wss://relay.example.com",
                None,
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();

        assert!(!creds.sync_id.is_empty());
        assert_eq!(creds.sync_id.len(), 64); // 32 bytes hex
        assert!(!creds.mnemonic.is_empty());
        assert!(!creds.wrapped_dek.is_empty());
        assert!(!creds.salt.is_empty());

        // Response should reference same sync_id
        assert_eq!(response.sync_id, creds.sync_id);
        assert_eq!(response.relay_url, "wss://relay.example.com");

        // Credentials should be persisted
        let stored_id = store.get("sync_id").unwrap().unwrap();
        assert_eq!(String::from_utf8(stored_id).unwrap(), creds.sync_id);
    }

    #[tokio::test]
    async fn create_sync_group_persists_device_identity() {
        let relay = Arc::new(MockRelay);
        let store = Arc::new(MemStore::default());
        let service = PairingService::new(relay, store.clone());

        let (_creds, _response) = service
            .create_sync_group(
                "test-password",
                "wss://relay.example.com",
                None,
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();

        // Device secret and device id should be persisted
        let device_secret = store.get("device_secret").unwrap();
        assert!(device_secret.is_some());
        assert_eq!(device_secret.unwrap().len(), 32);

        let device_id = store.get("device_id").unwrap();
        assert!(device_id.is_some());
        let device_id_str = String::from_utf8(device_id.unwrap()).unwrap();
        assert_eq!(device_id_str.len(), 12); // node_id is 12 hex chars
    }

    #[tokio::test]
    async fn join_sync_group_unlocks_key_hierarchy() {
        let relay = Arc::new(MockRelay);
        let store = Arc::new(MemStore::default());
        let service = PairingService::new(relay, store.clone());

        // Create a sync group first to get valid credentials
        let (_creds, response) = service
            .create_sync_group(
                "my-password",
                "wss://relay.example.com",
                None,
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();

        // Now join using the pairing response
        let join_store = Arc::new(MemStore::default());
        let join_service = PairingService::new(Arc::new(MockRelay), join_store.clone());

        let (kh, snapshot) = join_service
            .join_sync_group(&response, "my-password")
            .await
            .unwrap();

        assert!(kh.is_unlocked());
        // Should be able to derive database key
        assert!(kh.database_key().is_ok());
        // Verified snapshot should contain the inviter device
        assert_eq!(snapshot.entries.len(), 1);
        assert_eq!(snapshot.entries[0].status, "active");
    }

    #[tokio::test]
    async fn join_with_wrong_password_fails() {
        let relay = Arc::new(MockRelay);
        let store = Arc::new(MemStore::default());
        let service = PairingService::new(relay, store);

        let (_creds, response) = service
            .create_sync_group(
                "correct-password",
                "wss://relay.example.com",
                None,
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();

        let join_store = Arc::new(MemStore::default());
        let join_service = PairingService::new(Arc::new(MockRelay), join_store);

        let result = join_service.join_sync_group(&response, "wrong-password").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn join_rejects_invalid_epoch_fields_before_mutating_state() {
        let join_store = Arc::new(MemStore::default());
        let join_service = PairingService::new(Arc::new(MockRelay), join_store.clone());

        let response = PairingResponse {
            relay_url: "wss://relay.example.com".into(),
            sync_id: "not-checked-yet".into(),
            mnemonic: mnemonic::generate(),
            wrapped_dek: vec![0x42; 72],
            salt: vec![0x13; 32],
            signed_invitation: hex::encode([0xBB; 64]),
            signed_keyring: vec![0xCC; 200],
            inviter_device_id: "device-001".into(),
            inviter_ed25519_pk: vec![0xAA; 32],
            inviter_ml_dsa_65_pk: Vec::new(),
            joiner_device_id: Some("abcdef123456".to_string()),
            current_epoch: 1,
            epoch_key: vec![],
            registry_approval_signature: None,
            registration_token: None,
        };

        let err = match join_service.join_sync_group(&response, "irrelevant").await {
            Ok(_) => panic!("invalid epoch-bearing response should be rejected"),
            Err(err) => err,
        };
        assert!(
            format!("{err}").contains("invalid pairing response"),
            "unexpected error: {err}"
        );
        assert!(join_store.get("setup_rollback_marker").unwrap().is_none());
        assert!(join_store.get("device_id").unwrap().is_none());
    }

    #[tokio::test]
    async fn create_with_custom_mnemonic() {
        let relay = Arc::new(MockRelay);
        let store = Arc::new(MemStore::default());
        let service = PairingService::new(relay, store);

        let custom = mnemonic::generate();
        let (creds, _invite) = service
            .create_sync_group(
                "pw",
                "wss://relay.example.com",
                Some(custom.clone()),
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();

        assert_eq!(creds.mnemonic, custom);
    }

    #[tokio::test]
    async fn invitation_sign_and_verify_roundtrip() {
        let relay = Arc::new(MockRelay);
        let store = Arc::new(MemStore::default());
        let service = PairingService::new(relay, store);

        let (_creds, resp) = service
            .create_sync_group(
                "test-pw",
                "wss://relay.example.com",
                None,
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();

        // The signed_invitation should be non-empty (hex-encoded V3 hybrid signature)
        assert!(!resp.signed_invitation.is_empty());

        // The inviter fields should be populated
        assert!(!resp.inviter_device_id.is_empty());
        assert_eq!(resp.inviter_ed25519_pk.len(), 32);
        assert!(!resp.inviter_ml_dsa_65_pk.is_empty());

        // Verify the V3 hybrid invitation signature manually
        let inviter_pk: [u8; 32] = resp.inviter_ed25519_pk.clone().try_into().unwrap();
        let signing_data = build_invitation_signing_data_v2(
            &resp.sync_id,
            &resp.relay_url,
            &resp.wrapped_dek,
            &resp.salt,
            &resp.inviter_device_id,
            &inviter_pk,
            &resp.inviter_ml_dsa_65_pk,
            resp.joiner_device_id.as_deref(),
            resp.current_epoch,
            &resp.epoch_key,
        );
        let sig_bytes = prism_sync_crypto::hex::decode(&resp.signed_invitation).unwrap();
        verify_hybrid_invitation(
            &signing_data,
            &sig_bytes,
            &inviter_pk,
            &resp.inviter_ml_dsa_65_pk,
        )
        .unwrap();
    }

    #[test]
    fn v2_hybrid_invitation_wire_rejected() {
        let secret = DeviceSecret::generate();
        let device_id = "inviter-v2";
        let signing_key = secret.ed25519_keypair(device_id).unwrap();
        let pq_signing_key = secret.ml_dsa_65_keypair(device_id).unwrap();
        let inviter_pk = signing_key.public_key_bytes();
        let inviter_ml_dsa_pk = pq_signing_key.public_key_bytes();

        let signing_data = build_invitation_signing_data_v2(
            "sync-v2",
            "wss://relay.example.com",
            b"wrapped-dek",
            b"salt",
            device_id,
            &inviter_pk,
            &inviter_ml_dsa_pk,
            Some("joiner-v2"),
            0,
            &[],
        );
        let legacy_sig = prism_sync_crypto::pq::HybridSignature {
            ed25519_sig: signing_key.sign(&signing_data),
            ml_dsa_65_sig: pq_signing_key.sign(&signing_data),
        };
        let mut legacy_wire = vec![0x02u8];
        legacy_wire.extend_from_slice(&legacy_sig.to_bytes());

        let err =
            verify_hybrid_invitation(&signing_data, &legacy_wire, &inviter_pk, &inviter_ml_dsa_pk)
                .unwrap_err();
        assert!(err
            .to_string()
            .contains("unsupported invitation signature version"));
    }

    #[tokio::test]
    async fn tampered_invitation_rejected() {
        let relay = Arc::new(MockRelay);
        let store = Arc::new(MemStore::default());
        let service = PairingService::new(relay, store);

        let (_creds, response) = service
            .create_sync_group(
                "test-pw",
                "wss://relay.example.com",
                None,
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();

        // Tamper with the sync_id in the response
        let mut tampered = response.clone();
        tampered.sync_id = "tampered-sync-id".into();

        let join_store = Arc::new(MemStore::default());
        let join_service = PairingService::new(Arc::new(MockRelay), join_store);

        let result = join_service.join_sync_group(&tampered, "test-pw").await;
        let err_msg = match result {
            Err(e) => format!("{e}"),
            Ok(_) => panic!("expected error for tampered invitation"),
        };
        assert!(
            err_msg.contains("signature invalid"),
            "expected signature error, got: {err_msg}"
        );
    }

    #[tokio::test]
    async fn wrong_inviter_key_rejected() {
        let relay = Arc::new(MockRelay);
        let store = Arc::new(MemStore::default());
        let service = PairingService::new(relay, store);

        let (_creds, response) = service
            .create_sync_group(
                "test-pw",
                "wss://relay.example.com",
                None,
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();

        // Replace the inviter's public key with a different key
        let mut tampered = response.clone();
        let fake_secret = DeviceSecret::generate();
        let fake_key = fake_secret.ed25519_keypair("fake").unwrap();
        tampered.inviter_ed25519_pk = fake_key.public_key_bytes().to_vec();

        let join_store = Arc::new(MemStore::default());
        let join_service = PairingService::new(Arc::new(MockRelay), join_store);

        let result = join_service.join_sync_group(&tampered, "test-pw").await;
        let err_msg = match result {
            Err(e) => format!("{e}"),
            Ok(_) => panic!("expected error for wrong inviter key"),
        };
        assert!(
            err_msg.contains("signature invalid"),
            "expected signature error, got: {err_msg}"
        );
    }

    #[test]
    fn solve_registration_pow_returns_counter_for_supported_challenge() {
        let nonce_response = RegistrationNonceResponse {
            nonce: "test-nonce-12345".to_string(),
            pow_challenge: Some(ProofOfWorkChallenge {
                algorithm: "sha256_leading_zero_bits".to_string(),
                difficulty_bits: 8,
            }),
            min_signature_version: None,
        };

        let solution = solve_registration_pow("sync-id", "device-id", &nonce_response)
            .unwrap()
            .expect("PoW solution should be present");
        let hash = compute_registration_pow_hash(
            "sync-id",
            "device-id",
            &nonce_response.nonce,
            solution.counter,
        );

        assert!(pow_hash_meets_difficulty(&hash, 8));
    }

    #[test]
    fn solve_registration_pow_rejects_unsupported_challenge_algorithm() {
        let nonce_response = RegistrationNonceResponse {
            nonce: "test-nonce-12345".to_string(),
            pow_challenge: Some(ProofOfWorkChallenge {
                algorithm: "argon2id".to_string(),
                difficulty_bits: 8,
            }),
            min_signature_version: None,
        };

        let err = solve_registration_pow("sync-id", "device-id", &nonce_response).unwrap_err();
        assert!(
            format!("{err}").contains("unsupported first-device admission challenge"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn challenge_signature_present_in_registration() {
        // Use a relay that captures the registration request
        use std::sync::Mutex as StdMutex;

        struct CapturingRelay {
            captured_req: StdMutex<Option<RegisterRequest>>,
        }

        #[async_trait]
        impl SyncRelay for CapturingRelay {
            async fn get_registration_nonce(
                &self,
            ) -> std::result::Result<RegistrationNonceResponse, RelayError> {
                Ok(RegistrationNonceResponse {
                    nonce: "test-nonce-12345".to_string(),
                    pow_challenge: None,
                    min_signature_version: None,
                })
            }
            async fn register_device(
                &self,
                req: RegisterRequest,
            ) -> std::result::Result<RegisterResponse, RelayError> {
                *self.captured_req.lock().unwrap() = Some(req);
                Ok(RegisterResponse {
                    device_session_token: "mock-token".to_string(),
                    min_signature_version: None,
                })
            }
            async fn pull_changes(&self, _: i64) -> std::result::Result<PullResponse, RelayError> {
                unimplemented!()
            }
            async fn push_changes(&self, _: OutgoingBatch) -> std::result::Result<i64, RelayError> {
                unimplemented!()
            }
            async fn get_snapshot(
                &self,
            ) -> std::result::Result<Option<SnapshotResponse>, RelayError> {
                unimplemented!()
            }
            async fn put_snapshot(
                &self,
                _: i32,
                _: i64,
                _: Vec<u8>,
                _: Option<u64>,
                _: Option<String>,
                _: String,
            ) -> std::result::Result<(), RelayError> {
                unimplemented!()
            }
            async fn list_devices(&self) -> std::result::Result<Vec<DeviceInfo>, RelayError> {
                unimplemented!()
            }
            async fn revoke_device(
                &self,
                _: &str,
                _: bool,
                _: i32,
                _: HashMap<String, Vec<u8>>,
            ) -> std::result::Result<i32, RelayError> {
                unimplemented!()
            }
            async fn post_rekey_artifacts(
                &self,
                _: i32,
                _: HashMap<String, Vec<u8>>,
            ) -> std::result::Result<i32, RelayError> {
                unimplemented!()
            }
            async fn get_rekey_artifact(
                &self,
                _: i32,
                _: &str,
            ) -> std::result::Result<Option<Vec<u8>>, RelayError> {
                unimplemented!()
            }
            async fn deregister(&self) -> std::result::Result<(), RelayError> {
                unimplemented!()
            }
            async fn delete_sync_group(&self) -> std::result::Result<(), RelayError> {
                unimplemented!()
            }
            async fn ack(&self, _: i64) -> std::result::Result<(), RelayError> {
                unimplemented!()
            }
            async fn connect_websocket(&self) -> std::result::Result<(), RelayError> {
                unimplemented!()
            }
            async fn disconnect_websocket(&self) -> std::result::Result<(), RelayError> {
                unimplemented!()
            }
            fn notifications(&self) -> Pin<Box<dyn Stream<Item = SyncNotification> + Send>> {
                unimplemented!()
            }
            async fn rotate_ml_dsa(
                &self,
                _: &str,
                _: &[u8],
                _: u32,
                _: &prism_sync_crypto::pq::continuity_proof::MlDsaContinuityProof,
            ) -> std::result::Result<RotateMlDsaResponse, RelayError> {
                unimplemented!()
            }
            async fn upload_media(
                &self,
                _: &str,
                _: &str,
                _: Vec<u8>,
            ) -> std::result::Result<(), RelayError> {
                unimplemented!()
            }
            async fn download_media(&self, _: &str) -> std::result::Result<Vec<u8>, RelayError> {
                unimplemented!()
            }
            async fn dispose(&self) -> std::result::Result<(), RelayError> {
                unimplemented!()
            }
        }

        let relay = Arc::new(CapturingRelay {
            captured_req: StdMutex::new(None),
        });
        let store = Arc::new(MemStore::default());
        let service = PairingService::new(relay.clone(), store);

        let (_creds, _invite) = service
            .create_sync_group(
                "pw",
                "wss://relay.example.com",
                None,
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();

        let captured = relay.captured_req.lock().unwrap();
        let req = captured.as_ref().expect("registration request captured");

        // Challenge signature should be V3 hybrid format: [0x03][HybridSignature]
        assert_eq!(req.registration_challenge[0], 0x03);
        // HybridSignature = 4B ed_len + 64B ed_sig + 4B ml_len + 3309B ml_sig = 3381
        // plus 1B version prefix = 3382
        assert_eq!(req.registration_challenge.len(), 3382);
        // Nonce should be the one we returned
        assert_eq!(req.nonce, "test-nonce-12345");
        assert!(req.pow_solution.is_none());
    }

    #[tokio::test]
    async fn join_existing_group_uses_pending_identity_and_registry_approval() {
        use std::sync::Mutex as StdMutex;

        struct CapturingRelay {
            captured_req: StdMutex<Option<RegisterRequest>>,
        }

        #[async_trait]
        impl SyncRelay for CapturingRelay {
            async fn get_registration_nonce(
                &self,
            ) -> std::result::Result<RegistrationNonceResponse, RelayError> {
                Ok(RegistrationNonceResponse {
                    nonce: "join-nonce".to_string(),
                    pow_challenge: None,
                    min_signature_version: None,
                })
            }
            async fn register_device(
                &self,
                req: RegisterRequest,
            ) -> std::result::Result<RegisterResponse, RelayError> {
                *self.captured_req.lock().unwrap() = Some(req);
                Ok(RegisterResponse {
                    device_session_token: "mock-token".to_string(),
                    min_signature_version: None,
                })
            }
            async fn pull_changes(&self, _: i64) -> std::result::Result<PullResponse, RelayError> {
                unimplemented!()
            }
            async fn push_changes(&self, _: OutgoingBatch) -> std::result::Result<i64, RelayError> {
                unimplemented!()
            }
            async fn get_snapshot(
                &self,
            ) -> std::result::Result<Option<SnapshotResponse>, RelayError> {
                unimplemented!()
            }
            async fn put_snapshot(
                &self,
                _: i32,
                _: i64,
                _: Vec<u8>,
                _: Option<u64>,
                _: Option<String>,
                _: String,
            ) -> std::result::Result<(), RelayError> {
                unimplemented!()
            }
            async fn list_devices(&self) -> std::result::Result<Vec<DeviceInfo>, RelayError> {
                unimplemented!()
            }
            async fn revoke_device(
                &self,
                _: &str,
                _: bool,
                _: i32,
                _: HashMap<String, Vec<u8>>,
            ) -> std::result::Result<i32, RelayError> {
                unimplemented!()
            }
            async fn post_rekey_artifacts(
                &self,
                _: i32,
                _: HashMap<String, Vec<u8>>,
            ) -> std::result::Result<i32, RelayError> {
                unimplemented!()
            }
            async fn get_rekey_artifact(
                &self,
                _: i32,
                _: &str,
            ) -> std::result::Result<Option<Vec<u8>>, RelayError> {
                unimplemented!()
            }
            async fn deregister(&self) -> std::result::Result<(), RelayError> {
                unimplemented!()
            }
            async fn delete_sync_group(&self) -> std::result::Result<(), RelayError> {
                unimplemented!()
            }
            async fn ack(&self, _: i64) -> std::result::Result<(), RelayError> {
                unimplemented!()
            }
            async fn connect_websocket(&self) -> std::result::Result<(), RelayError> {
                unimplemented!()
            }
            async fn disconnect_websocket(&self) -> std::result::Result<(), RelayError> {
                unimplemented!()
            }
            fn notifications(&self) -> Pin<Box<dyn Stream<Item = SyncNotification> + Send>> {
                unimplemented!()
            }
            async fn rotate_ml_dsa(
                &self,
                _: &str,
                _: &[u8],
                _: u32,
                _: &prism_sync_crypto::pq::continuity_proof::MlDsaContinuityProof,
            ) -> std::result::Result<RotateMlDsaResponse, RelayError> {
                unimplemented!()
            }
            async fn upload_media(
                &self,
                _: &str,
                _: &str,
                _: Vec<u8>,
            ) -> std::result::Result<(), RelayError> {
                unimplemented!()
            }
            async fn download_media(&self, _: &str) -> std::result::Result<Vec<u8>, RelayError> {
                unimplemented!()
            }
            async fn dispose(&self) -> std::result::Result<(), RelayError> {
                unimplemented!()
            }
        }

        let inviter_secret = DeviceSecret::generate();
        let inviter_device_id = "inviter-001".to_string();
        let inviter_signing_key = inviter_secret.ed25519_keypair(&inviter_device_id).unwrap();
        let inviter_exchange_key = inviter_secret.x25519_keypair(&inviter_device_id).unwrap();
        let inviter_pq_signing_key = inviter_secret.ml_dsa_65_keypair(&inviter_device_id).unwrap();
        let inviter_pq_kem_key = inviter_secret.ml_kem_768_keypair(&inviter_device_id).unwrap();

        let joiner_secret = DeviceSecret::generate();
        let joiner_device_id = "joiner-001".to_string();
        let joiner_signing_key = joiner_secret.ed25519_keypair(&joiner_device_id).unwrap();
        let joiner_exchange_key = joiner_secret.x25519_keypair(&joiner_device_id).unwrap();
        let joiner_pq_signing_key = joiner_secret.ml_dsa_65_keypair(&joiner_device_id).unwrap();
        let joiner_pq_kem_key = joiner_secret.ml_kem_768_keypair(&joiner_device_id).unwrap();

        let snapshot = SignedRegistrySnapshot::new(vec![
            RegistrySnapshotEntry {
                sync_id: "sync-approved".into(),
                device_id: inviter_device_id.clone(),
                ed25519_public_key: inviter_signing_key.public_key_bytes().to_vec(),
                x25519_public_key: inviter_exchange_key.public_key_bytes().to_vec(),
                ml_dsa_65_public_key: inviter_pq_signing_key.public_key_bytes(),
                ml_kem_768_public_key: inviter_pq_kem_key.public_key_bytes(),
                status: "active".into(),
                ml_dsa_key_generation: 0,
            },
            RegistrySnapshotEntry {
                sync_id: "sync-approved".into(),
                device_id: joiner_device_id.clone(),
                ed25519_public_key: joiner_signing_key.public_key_bytes().to_vec(),
                x25519_public_key: joiner_exchange_key.public_key_bytes().to_vec(),
                ml_dsa_65_public_key: joiner_pq_signing_key.public_key_bytes(),
                ml_kem_768_public_key: joiner_pq_kem_key.public_key_bytes(),
                status: "active".into(),
                ml_dsa_key_generation: 0,
            },
        ]);
        let signed_keyring = snapshot.sign_hybrid(&inviter_signing_key, &inviter_pq_signing_key);
        let approval_data =
            build_registry_approval_signing_data_v2("sync-approved", &inviter_device_id, &signed_keyring);
        let approval_m_prime = prism_sync_crypto::pq::build_hybrid_message_representative(
            b"registry_approval",
            &approval_data,
        )
        .unwrap();
        let hybrid_approval = prism_sync_crypto::pq::HybridSignature {
            ed25519_sig: inviter_signing_key.sign(&approval_m_prime),
            ml_dsa_65_sig: inviter_pq_signing_key.sign(&approval_m_prime),
        };
        let mut approval_wire = vec![0x03u8];
        approval_wire.extend_from_slice(&hybrid_approval.to_bytes());
        let approval_signature = hex::encode(&approval_wire);

        let mnemonic = mnemonic::generate();
        let secret_key = mnemonic::to_bytes(&mnemonic).unwrap();
        let mut key_hierarchy = KeyHierarchy::new();
        let (wrapped_dek, salt) = key_hierarchy
            .initialize("test-password", &secret_key)
            .unwrap();
        let signing_data = build_invitation_signing_data_v2(
            "sync-approved",
            "wss://relay.example.com",
            &wrapped_dek,
            &salt,
            &inviter_device_id,
            &inviter_signing_key.public_key_bytes(),
            &inviter_pq_signing_key.public_key_bytes(),
            Some(&joiner_device_id),
            0,
            &[],
        );
        let invitation_m_prime = prism_sync_crypto::pq::build_hybrid_message_representative(
            b"invitation",
            &signing_data,
        )
        .unwrap();
        let invitation_sig = prism_sync_crypto::pq::HybridSignature {
            ed25519_sig: inviter_signing_key.sign(&invitation_m_prime),
            ml_dsa_65_sig: inviter_pq_signing_key.sign(&invitation_m_prime),
        };
        let mut invitation_wire = vec![0x03u8];
        invitation_wire.extend_from_slice(&invitation_sig.to_bytes());

        let response = PairingResponse {
            relay_url: "wss://relay.example.com".into(),
            sync_id: "sync-approved".into(),
            mnemonic,
            wrapped_dek,
            salt,
            signed_invitation: hex::encode(&invitation_wire),
            signed_keyring: signed_keyring.clone(),
            inviter_device_id: inviter_device_id.clone(),
            inviter_ed25519_pk: inviter_signing_key.public_key_bytes().to_vec(),
            inviter_ml_dsa_65_pk: inviter_pq_signing_key.public_key_bytes(),
            joiner_device_id: Some(joiner_device_id.clone()),
            current_epoch: 0,
            epoch_key: vec![],
            registry_approval_signature: Some(approval_signature.clone()),
            registration_token: None,
        };

        let relay = Arc::new(CapturingRelay {
            captured_req: StdMutex::new(None),
        });
        let store = Arc::new(MemStore::default());
        store
            .set("pending_device_secret", joiner_secret.as_bytes())
            .unwrap();
        store
            .set("pending_device_id", joiner_device_id.as_bytes())
            .unwrap();
        let service = PairingService::new(relay.clone(), store);

        let (_kh, verified_snapshot) = service
            .join_sync_group(&response, "test-password")
            .await
            .unwrap();
        assert_eq!(verified_snapshot.entries.len(), 2);

        let captured = relay.captured_req.lock().unwrap();
        let req = captured.as_ref().expect("registration request captured");
        assert_eq!(req.device_id, joiner_device_id);
        assert_eq!(
            req.signing_public_key,
            joiner_signing_key.public_key_bytes().to_vec()
        );
        assert_eq!(
            req.x25519_public_key,
            joiner_exchange_key.public_key_bytes().to_vec()
        );
        let approval = req
            .registry_approval
            .as_ref()
            .expect("registry approval present");
        assert_eq!(approval.approver_device_id, inviter_device_id);
        assert_eq!(
            approval.approver_ed25519_pk,
            hex::encode(inviter_signing_key.public_key_bytes())
        );
        assert_eq!(approval.approval_signature, approval_signature);
        assert_eq!(approval.signed_registry_snapshot, signed_keyring);
    }

    #[tokio::test]
    async fn approved_pairing_requires_pending_joiner_identity() {
        let inviter_secret = DeviceSecret::generate();
        let inviter_device_id = "inviter-001".to_string();
        let inviter_signing_key = inviter_secret.ed25519_keypair(&inviter_device_id).unwrap();
        let inviter_exchange_key = inviter_secret.x25519_keypair(&inviter_device_id).unwrap();
        let inviter_pq_signing_key = inviter_secret.ml_dsa_65_keypair(&inviter_device_id).unwrap();
        let inviter_pq_kem_key = inviter_secret.ml_kem_768_keypair(&inviter_device_id).unwrap();

        let joiner_device_id = "joiner-001".to_string();
        let joiner_secret = DeviceSecret::generate();
        let joiner_signing_key = joiner_secret.ed25519_keypair(&joiner_device_id).unwrap();
        let joiner_exchange_key = joiner_secret.x25519_keypair(&joiner_device_id).unwrap();
        let joiner_pq_signing_key = joiner_secret.ml_dsa_65_keypair(&joiner_device_id).unwrap();
        let joiner_pq_kem_key = joiner_secret.ml_kem_768_keypair(&joiner_device_id).unwrap();

        let snapshot = SignedRegistrySnapshot::new(vec![
            RegistrySnapshotEntry {
                sync_id: "sync-approved".into(),
                device_id: inviter_device_id.clone(),
                ed25519_public_key: inviter_signing_key.public_key_bytes().to_vec(),
                x25519_public_key: inviter_exchange_key.public_key_bytes().to_vec(),
                ml_dsa_65_public_key: inviter_pq_signing_key.public_key_bytes(),
                ml_kem_768_public_key: inviter_pq_kem_key.public_key_bytes(),
                status: "active".into(),
                ml_dsa_key_generation: 0,
            },
            RegistrySnapshotEntry {
                sync_id: "sync-approved".into(),
                device_id: joiner_device_id.clone(),
                ed25519_public_key: joiner_signing_key.public_key_bytes().to_vec(),
                x25519_public_key: joiner_exchange_key.public_key_bytes().to_vec(),
                ml_dsa_65_public_key: joiner_pq_signing_key.public_key_bytes(),
                ml_kem_768_public_key: joiner_pq_kem_key.public_key_bytes(),
                status: "active".into(),
                ml_dsa_key_generation: 0,
            },
        ]);
        let signed_keyring = snapshot.sign_hybrid(&inviter_signing_key, &inviter_pq_signing_key);
        let approval_data =
            build_registry_approval_signing_data_v2("sync-approved", &inviter_device_id, &signed_keyring);
        let approval_m_prime = prism_sync_crypto::pq::build_hybrid_message_representative(
            b"registry_approval",
            &approval_data,
        )
        .unwrap();
        let hybrid_approval = prism_sync_crypto::pq::HybridSignature {
            ed25519_sig: inviter_signing_key.sign(&approval_m_prime),
            ml_dsa_65_sig: inviter_pq_signing_key.sign(&approval_m_prime),
        };
        let mut approval_wire = vec![0x03u8];
        approval_wire.extend_from_slice(&hybrid_approval.to_bytes());
        let approval_signature = hex::encode(&approval_wire);

        let mnemonic = mnemonic::generate();
        let secret_key = mnemonic::to_bytes(&mnemonic).unwrap();
        let mut key_hierarchy = KeyHierarchy::new();
        let (wrapped_dek, salt) = key_hierarchy
            .initialize("test-password", &secret_key)
            .unwrap();
        let signing_data = build_invitation_signing_data_v2(
            "sync-approved",
            "wss://relay.example.com",
            &wrapped_dek,
            &salt,
            &inviter_device_id,
            &inviter_signing_key.public_key_bytes(),
            &inviter_pq_signing_key.public_key_bytes(),
            Some(&joiner_device_id),
            0,
            &[],
        );
        let invitation_m_prime = prism_sync_crypto::pq::build_hybrid_message_representative(
            b"invitation",
            &signing_data,
        )
        .unwrap();
        let invitation_sig = prism_sync_crypto::pq::HybridSignature {
            ed25519_sig: inviter_signing_key.sign(&invitation_m_prime),
            ml_dsa_65_sig: inviter_pq_signing_key.sign(&invitation_m_prime),
        };
        let mut invitation_wire = vec![0x03u8];
        invitation_wire.extend_from_slice(&invitation_sig.to_bytes());

        let response = PairingResponse {
            relay_url: "wss://relay.example.com".into(),
            sync_id: "sync-approved".into(),
            mnemonic,
            wrapped_dek,
            salt,
            signed_invitation: hex::encode(&invitation_wire),
            signed_keyring,
            inviter_device_id,
            inviter_ed25519_pk: inviter_signing_key.public_key_bytes().to_vec(),
            inviter_ml_dsa_65_pk: inviter_pq_signing_key.public_key_bytes(),
            joiner_device_id: Some(joiner_device_id),
            current_epoch: 0,
            epoch_key: vec![],
            registry_approval_signature: Some(approval_signature),
            registration_token: None,
        };

        let service = PairingService::new(Arc::new(MockRelay), Arc::new(MemStore::default()));
        let err = match service.join_sync_group(&response, "test-password").await {
            Ok(_) => panic!("approved pairing without pending identity should fail"),
            Err(err) => err,
        };
        assert!(
            err.to_string()
                .contains("requires the original pairing request identity"),
            "unexpected error: {err}",
        );
    }
}
