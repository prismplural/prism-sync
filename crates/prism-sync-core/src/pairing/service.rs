//! High-level pairing orchestration: create and join sync groups.
//!
//! The `PairingService` wraps the relay, secure store, and crypto layers to
//! provide a simple API for multi-device pairing. The full crypto handshake
//! (SAS verification, signed keyrings) will be refined later — this module
//! establishes the API surface and basic key derivation flow.

use std::sync::Arc;
use std::time::Duration;

use crate::bootstrap::{
    CredentialBundle as BootstrapCredentialBundle, InitiatorCeremony, JoinerCeremony,
    RendezvousToken, SasDisplay,
};
use crate::epoch::EpochManager;
use crate::error::{CoreError, Result};
use crate::pairing::models::*;
use crate::relay::pairing_relay::{PairingRelay, PairingSlot};
use crate::relay::traits::{
    DeviceInfo, FirstDeviceAdmissionProof, ProofOfWorkChallenge, ProofOfWorkSolution,
    RegistrationNonceResponse, RegistryApproval, SignedRegistryResponse,
};
use crate::relay::SyncRelay;
use crate::secure_store::SecureStore;
use prism_sync_crypto::pq::hybrid_signature_contexts;
use prism_sync_crypto::{mnemonic, DeviceSecret, KeyHierarchy};
use sha2::{Digest, Sha256};
use tokio::time::sleep;

const MIN_SIGNATURE_VERSION_FLOOR_KEY: &str = "min_signature_version_floor";
const SIGNATURE_VERSION_SOURCE_FLOOR: u8 = 0x03;
#[cfg(test)]
const SUPPORTED_SIGNATURE_VERSION: u8 = 0x03;

fn diag_hash(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(&digest[..8])
}

fn diag_prefix(bytes: &[u8]) -> String {
    hex::encode(&bytes[..bytes.len().min(8)])
}

/// Orchestrates sync group creation and joining.
///
/// Holds a shared reference to the secure store (for credential persistence).
/// Relay connections are passed in or built via closures at call sites, because
/// the joiner doesn't know the sync_id until the credential bundle is decrypted.
pub struct PairingService {
    secure_store: Arc<dyn SecureStore>,
}

impl PairingService {
    /// Create a new `PairingService`.
    pub fn new(secure_store: Arc<dyn SecureStore>) -> Self {
        Self { secure_store }
    }

    fn stored_min_signature_version_floor(&self) -> Result<Option<u8>> {
        self.secure_store
            .get(MIN_SIGNATURE_VERSION_FLOOR_KEY)?
            .map(|bytes| {
                let value = String::from_utf8(bytes).map_err(|e| {
                    CoreError::Serialization(format!(
                        "invalid UTF-8 in {MIN_SIGNATURE_VERSION_FLOOR_KEY}: {e}"
                    ))
                })?;
                value.parse::<u8>().map_err(|e| {
                    CoreError::Serialization(format!(
                        "invalid integer in {MIN_SIGNATURE_VERSION_FLOOR_KEY}: {e}"
                    ))
                })
            })
            .transpose()
    }

    fn ratchet_min_signature_version(&self, observed: Option<u8>) -> Result<()> {
        let required =
            observed.unwrap_or(SIGNATURE_VERSION_SOURCE_FLOOR).max(SIGNATURE_VERSION_SOURCE_FLOOR);
        let current = self.stored_min_signature_version_floor()?.unwrap_or(0);
        if required > current {
            self.secure_store
                .set(MIN_SIGNATURE_VERSION_FLOOR_KEY, required.to_string().as_bytes())?;
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
    ///
    /// The `relay_builder` closure constructs a `SyncRelay` after the sync_id is
    /// resolved (from `sync_id_override` or freshly generated). Parameters:
    /// `(sync_id, device_id, registration_token)`.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_sync_group<F>(
        &self,
        password: &str,
        relay_url: &str,
        mnemonic_override: Option<&str>,
        sync_id_override: Option<String>,
        nonce_response_override: Option<RegistrationNonceResponse>,
        first_device_admission_proof: Option<FirstDeviceAdmissionProof>,
        registration_token: Option<String>,
        relay_builder: F,
    ) -> Result<(SyncGroupCredentials, PairingResponse)>
    where
        F: FnOnce(&str, &str, Option<&str>) -> Result<Arc<dyn SyncRelay>> + Send,
    {
        // 1. Generate or accept mnemonic. Borrow caller-provided mnemonic text
        // instead of taking ownership so FFI callers can keep their input copy
        // inside a Zeroizing buffer.
        let generated_mnemonic;
        let mnemonic_str = match mnemonic_override {
            Some(value) => value,
            None => {
                generated_mnemonic = mnemonic::generate();
                generated_mnemonic.as_str()
            }
        };
        let secret_key = mnemonic::to_bytes(mnemonic_str).map_err(CoreError::Crypto)?;

        // 2. Initialize key hierarchy — produces wrapped DEK + salt
        let mut key_hierarchy = KeyHierarchy::new();
        let (wrapped_dek, salt) =
            key_hierarchy.initialize(password, &secret_key).map_err(CoreError::Crypto)?;

        // 3. Use provided sync_id or generate one (32 random bytes, hex-encoded)
        let sync_id = sync_id_override.unwrap_or_else(EpochManager::generate_sync_id);

        // 4. Build credentials
        let credentials = SyncGroupCredentials {
            sync_id: sync_id.clone(),
            mnemonic: mnemonic_str.to_string(),
            wrapped_dek: wrapped_dek.clone(),
            salt: salt.clone(),
        };

        // 5. Reuse a pending identity when the caller pre-generated one for
        // first-device admission. Otherwise generate a fresh device identity.
        let (device_secret, device_id) = self
            .load_pending_identity()?
            .unwrap_or_else(|| (DeviceSecret::generate(), crate::node_id::generate_node_id()));
        let signing_key = device_secret.ed25519_keypair(&device_id).map_err(CoreError::Crypto)?;
        let exchange_key = device_secret.x25519_keypair(&device_id).map_err(CoreError::Crypto)?;
        let pq_signing_key =
            device_secret.ml_dsa_65_keypair(&device_id).map_err(CoreError::Crypto)?;
        let pq_kem_key = device_secret.ml_kem_768_keypair(&device_id).map_err(CoreError::Crypto)?;
        let xwing_key = device_secret.xwing_keypair(&device_id).map_err(CoreError::Crypto)?;

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
            hybrid_signature_contexts::INVITATION,
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
        // First-device bootstrap signs at the new floor with an explicit
        // commitment to epoch 0 so the registry is anchored to the local
        // epoch ratchet from inception. See Phase 3 prerequisite in
        // docs/plans/sync-pairing-reset-hardening.md.
        let registry_version = SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING;
        let epoch_key_hashes = build_epoch_key_hashes(&key_hierarchy)?;
        let registry_snapshot = SignedRegistrySnapshot::new_with_epoch_binding(
            vec![RegistrySnapshotEntry {
                sync_id: sync_id.clone(),
                device_id: device_id.clone(),
                ed25519_public_key: signing_key.public_key_bytes().to_vec(),
                x25519_public_key: exchange_key.public_key_bytes().to_vec(),
                ml_dsa_65_public_key: pq_signing_key.public_key_bytes(),
                ml_kem_768_public_key: pq_kem_key.public_key_bytes(),
                x_wing_public_key: xwing_key.encapsulation_key_bytes(),
                status: "active".into(),
                ml_dsa_key_generation: 0,
                remote_wipe: false,
            }],
            registry_version,
            0,
            epoch_key_hashes,
        );
        let signed_keyring = registry_snapshot.sign_hybrid(&signing_key, &pq_signing_key);

        // 8. Build the first-device pairing response.
        let response = PairingResponse {
            relay_url: relay_url.to_string(),
            sync_id: sync_id.clone(),
            mnemonic: mnemonic_str.to_string(),
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

        // 9. Build relay with real sync_id
        let relay = relay_builder(&sync_id, &device_id, response.registration_token.as_deref())?;

        // 10. Fetch registration nonce and build challenge-response (CRITICAL-2)
        let nonce_response = match nonce_response_override {
            Some(response) => response,
            None => relay
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

        // 11. Register with relay using signed challenge
        let register_req = crate::relay::traits::RegisterRequest {
            device_id: device_id.clone(),
            signing_public_key: signing_key.public_key_bytes().to_vec(),
            x25519_public_key: exchange_key.public_key_bytes().to_vec(),
            ml_dsa_65_public_key: pq_signing_key.public_key_bytes(),
            ml_kem_768_public_key: pq_kem_key.public_key_bytes(),
            x_wing_public_key: xwing_key.encapsulation_key_bytes(),
            registration_challenge: challenge_signature,
            nonce,
            pow_solution,
            first_device_admission_proof,
            registry_approval: None,
        };

        let register_response = relay
            .register_device(register_req)
            .await
            .map_err(|e| CoreError::from_relay_with_context(Some("registration failed"), e))?;
        self.ratchet_min_signature_version(register_response.min_signature_version)?;

        // 11. Persist credentials and device identity to secure store
        self.secure_store
            .set("session_token", register_response.device_session_token.as_bytes())?;
        self.secure_store.set("sync_id", credentials.sync_id.as_bytes())?;
        self.secure_store.set("relay_url", relay_url.as_bytes())?;
        // Mnemonic is an offline backup credential — it is returned in
        // `credentials.mnemonic` for the caller to display once during setup,
        // but deliberately NOT persisted to the secure store. Change-PIN and
        // device-pairing flows re-prompt the user to type it from their saved
        // backup.
        self.secure_store.set("wrapped_dek", &credentials.wrapped_dek)?;
        self.secure_store.set("dek_salt", &credentials.salt)?;
        self.secure_store.set("device_secret", device_secret.as_bytes())?;
        self.secure_store.set("device_id", device_id.as_bytes())?;
        self.secure_store.set("epoch", b"0")?;
        self.secure_store.delete("pending_device_secret")?;
        self.secure_store.delete("pending_device_id")?;

        Ok((credentials, response))
    }

    /// Start the new Phase 3 joiner bootstrap ceremony.
    pub async fn start_bootstrap_pairing(
        &self,
        relay: &dyn PairingRelay,
        relay_url: &str,
    ) -> Result<(JoinerCeremony, RendezvousToken)> {
        let (ceremony, token) = JoinerCeremony::start(relay, relay_url).await?;
        self.secure_store.set("pending_device_secret", ceremony.device_secret().as_bytes())?;
        self.secure_store.set("pending_device_id", ceremony.device_id().as_bytes())?;
        Ok((ceremony, token))
    }

    /// Complete the joiner side of the bootstrap ceremony.
    ///
    /// The caller is expected to have already compared SAS codes.
    ///
    /// The `relay_builder` closure constructs a `SyncRelay` after the credential
    /// bundle is decrypted and the real sync_id is known. Parameters:
    /// `(sync_id, device_id, registration_token)`.
    pub async fn complete_bootstrap_join<F>(
        &self,
        ceremony: &JoinerCeremony,
        relay: &dyn PairingRelay,
        encrypted_credentials: &[u8],
        password: &str,
        relay_builder: F,
    ) -> Result<(KeyHierarchy, SignedRegistrySnapshot)>
    where
        F: FnOnce(&str, &str, Option<&str>) -> Result<Arc<dyn SyncRelay>> + Send,
    {
        // Publish our confirmation MAC before accepting credentials.
        let confirmation_mac = ceremony.confirmation_mac()?;
        relay
            .put_slot(&ceremony.rendezvous_id_hex(), PairingSlot::Confirmation, &confirmation_mac)
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
        verify_bundle_epoch_anchor(
            &registry_snapshot,
            bundle.current_epoch,
            &bundle.epoch_key,
            &key_hierarchy,
        )?;

        let device_secret = ceremony.device_secret();
        let device_id = ceremony.device_id().to_string();
        let signing_key = device_secret.ed25519_keypair(&device_id).map_err(CoreError::Crypto)?;
        let exchange_key = device_secret.x25519_keypair(&device_id).map_err(CoreError::Crypto)?;
        let pq_signing_key =
            device_secret.ml_dsa_65_keypair(&device_id).map_err(CoreError::Crypto)?;
        let pq_kem_key = device_secret.ml_kem_768_keypair(&device_id).map_err(CoreError::Crypto)?;
        let xwing_key = device_secret.xwing_keypair(&device_id).map_err(CoreError::Crypto)?;

        let sync_id = bundle.sync_id.clone();

        // Validate sync_id format before building relay (client-side check)
        if sync_id.len() != 64 || !sync_id.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(CoreError::Engine(format!(
                "credential bundle contains invalid sync_id: {sync_id}"
            )));
        }

        // Verify all registry snapshot entries have matching sync_id
        for entry in &registry_snapshot.entries {
            if entry.sync_id != sync_id {
                return Err(CoreError::Engine(format!(
                    "registry snapshot entry sync_id mismatch: expected {sync_id}, got {}",
                    entry.sync_id
                )));
            }
        }

        // Prefer a registration token the joiner seeded into its own secure
        // store (typed on the "Join an existing group" screen) over the one
        // the initiator propagated in the credential bundle. The joiner's
        // intent wins because:
        //   - If an existing device was paired before tokens were persisted
        //     in secure_store (older app versions), its bundle has None.
        //   - If the relay's required token has rotated since the initiator
        //     paired, the bundle carries a stale value.
        // In either case the joiner can unblock themselves by typing the
        // current token instead of re-pairing every device.
        let seeded_token = self.load_optional_secure_string("registration_token")?;
        let effective_token: Option<String> =
            seeded_token.clone().or_else(|| bundle.registration_token.clone());

        // Build relay with real sync_id
        let registration_relay = relay_builder(&sync_id, &device_id, effective_token.as_deref())?;

        let nonce_response = registration_relay
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
            bundle.registry_approval_signature.as_ref().map(|approval_signature| {
                RegistryApproval {
                    approver_device_id: bundle.inviter_device_id.clone(),
                    approver_ed25519_pk: hex::encode(&bundle.inviter_ed25519_pk),
                    approver_ml_dsa_65_pk: hex::encode(&bundle.inviter_ml_dsa_65_pk),
                    approval_signature: approval_signature.clone(),
                    signed_registry_snapshot: bundle.signed_keyring.clone(),
                }
            });

        let register_response = registration_relay
            .register_device(crate::relay::traits::RegisterRequest {
                device_id: device_id.clone(),
                signing_public_key: signing_key.public_key_bytes().to_vec(),
                x25519_public_key: exchange_key.public_key_bytes().to_vec(),
                ml_dsa_65_public_key: pq_signing_key.public_key_bytes(),
                ml_kem_768_public_key: pq_kem_key.public_key_bytes(),
                x_wing_public_key: xwing_key.encapsulation_key_bytes(),
                registration_challenge: challenge_signature,
                nonce,
                pow_solution,
                first_device_admission_proof: None,
                registry_approval,
            })
            .await
            .map_err(|e| CoreError::from_relay_with_context(Some("registration failed"), e))?;
        self.ratchet_min_signature_version(register_response.min_signature_version)?;

        self.secure_store.set("setup_rollback_marker", b"in_progress")?;
        self.secure_store
            .set("session_token", register_response.device_session_token.as_bytes())?;
        self.secure_store.set("sync_id", bundle.sync_id.as_bytes())?;
        self.secure_store.set("relay_url", bundle.relay_url.as_bytes())?;
        // Intentionally not persisting `bundle.mnemonic`: the recovery phrase
        // is an offline backup credential. The joiner already has it in
        // memory from the credential bundle and uses it transiently to
        // unlock. Users will re-type it from their saved backup when needed
        // (change-PIN, pair-new-device).
        self.secure_store.set("wrapped_dek", &bundle.wrapped_dek)?;
        self.secure_store.set("dek_salt", &bundle.salt)?;
        self.secure_store.set("device_secret", device_secret.as_bytes())?;
        self.secure_store.set("device_id", device_id.as_bytes())?;
        self.secure_store.set("epoch", bundle.current_epoch.to_string().as_bytes())?;
        if bundle.current_epoch > 0 && bundle.epoch_key.len() == 32 {
            use base64::{engine::general_purpose::STANDARD, Engine};
            let encoded = STANDARD.encode(&bundle.epoch_key);
            self.secure_store
                .set(&format!("epoch_key_{}", bundle.current_epoch), encoded.as_bytes())?;
            key_hierarchy.store_epoch_key(
                bundle.current_epoch,
                zeroize::Zeroizing::new(bundle.epoch_key.clone()),
            );
        }
        // Persist whichever token we actually used so this device can initiate
        // future pairings. If the joiner seeded a value, it's already in the
        // secure store; we only need to write the bundle's token when nothing
        // was seeded. Never overwrite a joiner-seeded value with the bundle's —
        // the joiner's typed intent should win (see effective_token above).
        if seeded_token.is_none() {
            if let Some(ref token) = bundle.registration_token {
                self.secure_store.set("registration_token", token.as_bytes())?;
            }
        }

        let latest_registry_snapshot = fetch_and_verify_latest_join_registry(
            registration_relay.as_ref(),
            &registry_snapshot,
            bundle.current_epoch,
        )
        .await?;
        verify_epoch_key_hash_in_snapshot(
            &latest_registry_snapshot,
            bundle.current_epoch,
            &bundle.epoch_key,
            &key_hierarchy,
        )?;

        // Install the initiator's full epoch-key history. The bundle's
        // signed registry commits a hash for every epoch the initiator holds, so
        // each entry is verified against `registry_snapshot` BEFORE it is
        // persisted; a single mismatch aborts the pairing fail-closed (the
        // partial setup is rolled back via `setup_rollback_marker`), consistent
        // with the epoch-binding posture from commit 1455805. Holding every
        // epoch's key lets this joiner decrypt retained batches at any epoch
        // above its bootstrap cursor — quarantine only has to cover keys that
        // arrive later.
        install_bundle_epoch_keys(
            self.secure_store.as_ref(),
            &mut key_hierarchy,
            &bundle.epoch_keys,
            bundle.current_epoch,
            &registry_snapshot,
        )?;

        let final_registry_snapshot =
            if latest_registry_snapshot.current_epoch > bundle.current_epoch {
                let catch_up = EpochManager::catch_up_epoch_keys(
                    registration_relay.as_ref(),
                    &mut key_hierarchy,
                    self.secure_store.as_ref(),
                    device_secret,
                    &device_id,
                    bundle.current_epoch,
                    latest_registry_snapshot.current_epoch,
                    &latest_registry_snapshot.epoch_key_hashes,
                )
                .await
                .map_err(|e| {
                    classify_joiner_catch_up_error(
                        bundle.current_epoch,
                        latest_registry_snapshot.current_epoch,
                        e,
                    )
                })?;
                if catch_up.recovered_through < latest_registry_snapshot.current_epoch {
                    return Err(CoreError::EpochMismatch {
                        local_epoch: catch_up.recovered_through,
                        relay_epoch: latest_registry_snapshot.current_epoch,
                        message: "joiner could not recover all relay epoch keys".into(),
                    });
                }
                latest_registry_snapshot
            } else {
                latest_registry_snapshot
            };

        let joiner_bundle_bytes = ceremony.encrypt_joiner_bundle()?;
        relay
            .put_slot(&ceremony.rendezvous_id_hex(), PairingSlot::Joiner, &joiner_bundle_bytes)
            .await
            .map_err(|e| CoreError::from_relay_with_context(Some("posting joiner bundle"), e))?;

        self.secure_store.delete("setup_rollback_marker")?;
        self.secure_store.delete("pending_device_secret")?;
        self.secure_store.delete("pending_device_id")?;

        Ok((key_hierarchy, final_registry_snapshot))
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
    ///
    /// The `sync_relay` is used for relay operations that require the real
    /// sync_id (e.g., listing devices, posting rekey artifacts). The
    /// `pairing_relay` handles ceremony slot exchange (no sync_id needed).
    ///
    /// `mnemonic` is the inviter's BIP39 recovery phrase. It is required
    /// because the recovery phrase is never persisted to the secure store —
    /// the caller must obtain it from the user (typed from their offline
    /// backup) and pass it through. The phrase is included in the encrypted
    /// credential bundle shipped to the joiner so the joiner can Argon2-
    /// unlock, and is zeroized once that bundle has been constructed.
    /// On success returns the `registry_version` of the signed registry this
    /// device just published to the relay during the ceremony. The FFI caller
    /// uses it to ratchet this (long-lived inviter) device's
    /// `last_imported_registry_version` freshness baseline forward — the
    /// `PairingService` itself has no `SyncStorage` handle, so the ratchet lives
    /// at the call site where storage is available.
    pub async fn complete_bootstrap_initiator(
        &self,
        ceremony: &InitiatorCeremony,
        pairing_relay: &dyn PairingRelay,
        password: &str,
        mnemonic: &str,
        sync_relay: &dyn SyncRelay,
        storage: &dyn crate::storage::SyncStorage,
    ) -> Result<i64> {
        let rendezvous_id = ceremony.rendezvous_id_hex();
        let transcript_prefix = diag_prefix(ceremony.transcript_hash());

        // Verify the joiner's confirmation MAC before sending credentials.
        let confirmation = wait_for_pairing_slot_bytes(
            pairing_relay,
            &rendezvous_id,
            PairingSlot::Confirmation,
            "joiner confirmation",
        )
        .await?;
        let confirmation_hash = diag_hash(&confirmation);
        ceremony.verify_joiner_confirmation(&confirmation).map_err(|e| {
            CoreError::Engine(format!(
                "initiator joiner confirmation verification failed; rid={rendezvous_id}; transcript={transcript_prefix}; confirmation_len={}; confirmation_sha={confirmation_hash}; err={e}",
                confirmation.len()
            ))
        })?;

        let (device_secret, device_id) = self.load_current_device_identity()?;
        let signing_key = device_secret.ed25519_keypair(&device_id).map_err(CoreError::Crypto)?;
        let exchange_key = device_secret.x25519_keypair(&device_id).map_err(CoreError::Crypto)?;
        let pq_kem_key = device_secret.ml_kem_768_keypair(&device_id).map_err(CoreError::Crypto)?;
        let xwing_key = device_secret.xwing_keypair(&device_id).map_err(CoreError::Crypto)?;

        let mut key_hierarchy = KeyHierarchy::new();
        let sync_id = self.load_secure_string("sync_id")?;
        let relay_url = self.load_secure_string("relay_url")?;
        // `mnemonic` is supplied by the caller — the recovery phrase is never
        // persisted to the secure store. Derive the secret key in-memory and
        // rely on `secret_key`'s `Zeroizing<Vec<u8>>` wrapper to scrub the
        // bytes when this function returns.
        let secret_key = mnemonic::to_bytes(mnemonic).map_err(CoreError::Crypto)?;
        let wrapped_dek = self.load_secure_bytes("wrapped_dek")?;
        let salt = self.load_secure_bytes("dek_salt")?;
        key_hierarchy
            .unlock(password, &secret_key, &wrapped_dek, &salt)
            .map_err(CoreError::Crypto)?;
        let mut current_epoch = self
            .load_secure_string("epoch")?
            .parse::<u32>()
            .map_err(|e| CoreError::Engine(format!("invalid stored epoch value: {e}")))?;

        // After a successful `revoke_and_rekey`, post_rekey, or epoch
        // recovery, the new epoch key is persisted to secure_store as
        // `epoch_key_{N}` (see commit_recovered_epoch_material) but
        // `KeyHierarchy::unlock` only seeds epoch 0. Without restoring
        // the higher-epoch keys here, `build_epoch_key_hashes` below
        // would only commit to epoch 0, and the joiner would reject the
        // bundle with "epoch_key_hashes missing entry for current_epoch".
        self.restore_persisted_epoch_keys(&mut key_hierarchy, current_epoch)?;

        // NOTE: the joiner's bootstrap record is NOT re-fetched from the relay
        // here. A second fetch carries no binding to the out-of-band rendezvous
        // commitment the human verified, so a malicious relay could swap the
        // joiner's permanent keys on it. The joiner's identity keys are instead
        // taken from `ceremony.joiner_bootstrap_record()` below, which was
        // commitment-checked in `InitiatorCeremony::start`.
        let mut devices = sync_relay
            .list_devices()
            .await
            .map_err(|e| CoreError::from_relay_with_context(Some("listing devices"), e))?;
        devices.retain(|device| device.status == "active");
        let current_signed_registry = sync_relay
            .get_signed_registry()
            .await
            .map_err(|e| CoreError::from_relay_with_context(Some("fetching signed registry"), e))?;
        let next_registry_version = next_pairing_registry_version(
            current_signed_registry.as_ref().map(|response| response.registry_version),
        );

        let current_device =
            devices.iter().find(|device| device.device_id == device_id).ok_or_else(|| {
                CoreError::Engine("current device missing from active relay device list".into())
            })?;
        let current_ml_dsa_generation = current_device.ml_dsa_key_generation;
        let relay_epoch = current_device.epoch.max(0) as u32;
        let pq_signing_key = device_secret
            .ml_dsa_65_keypair_v(&device_id, current_ml_dsa_generation)
            .map_err(CoreError::Crypto)?;

        if relay_epoch > current_epoch {
            let registry_response = current_signed_registry.clone().ok_or_else(|| {
                CoreError::Engine(format!(
                    "relay epoch {relay_epoch} is ahead of local epoch {current_epoch}, but no signed registry is available"
                ))
            })?;
            let snapshot = SignedRegistrySnapshot::verify_and_decode_hybrid(
                &registry_response.artifact_blob,
                &signing_key.public_key_bytes(),
                &pq_signing_key.public_key_bytes(),
            )
            .map_err(|e| {
                CoreError::Engine(format!(
                    "signed registry verification failed during epoch catch-up: {e}"
                ))
            })?;
            if snapshot.registry_version < SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING {
                return Err(CoreError::Engine(format!(
                    "signed registry version {} cannot prove epoch catch-up keys",
                    snapshot.registry_version
                )));
            }
            if snapshot.current_epoch < relay_epoch {
                return Err(CoreError::Engine(format!(
                    "signed registry current_epoch {} lags relay epoch {relay_epoch}",
                    snapshot.current_epoch
                )));
            }
            let current_entry =
                snapshot.entries.iter().find(|entry| entry.device_id == device_id).ok_or_else(
                    || {
                        CoreError::Engine(
                            "signed registry missing current device during epoch catch-up".into(),
                        )
                    },
                )?;
            if current_entry.status != "active" {
                return Err(CoreError::Engine(format!(
                    "signed registry marks current device as {} during epoch catch-up",
                    current_entry.status
                )));
            }

            let target_epoch = snapshot.current_epoch.max(relay_epoch);
            let result = EpochManager::catch_up_epoch_keys(
                sync_relay,
                &mut key_hierarchy,
                self.secure_store.as_ref(),
                &device_secret,
                &device_id,
                current_epoch,
                target_epoch,
                &snapshot.epoch_key_hashes,
            )
            .await?;
            current_epoch = result.recovered_through;
        }
        let epoch_key = self.load_epoch_key(&key_hierarchy, current_epoch)?;

        // SECURITY (C2): existing-device identity keys must come from a
        // signature-verified source, never the raw `relay.list_devices()` — a
        // relay that swaps a device's X-Wing key there would otherwise get the
        // new epoch key wrapped to an attacker key. Source: the relay's latest
        // signed registry, hybrid-verified against locally-pinned records (None
        // → no existing peers, i.e. a first pairing).
        let verified_existing: std::collections::HashMap<String, RegistrySnapshotEntry> =
            match current_signed_registry.as_ref() {
                Some(response) => {
                    let verified = crate::device_registry::DeviceRegistryManager::verify_signed_registry_snapshot(
                        storage,
                        &sync_id,
                        &response.artifact_blob,
                    )
                    .map_err(|e| {
                        CoreError::Engine(format!(
                            "failed to verify relay signed registry while authoring pairing snapshot: {e}"
                        ))
                    })?;
                    verified
                        .entries
                        .into_iter()
                        .filter(|entry| entry.status == "active")
                        .map(|entry| (entry.device_id.clone(), entry))
                        .collect()
                }
                None => std::collections::HashMap::new(),
            };

        let joiner_device_id = ceremony.joiner_device_id().to_string();
        // Author existing-device entries directly from the verified set, never
        // `relay.list_devices()` — so a relay can neither inject a peer absent
        // from any signed registry nor drop one by omission. A legit member not
        // yet in the latest signed registry just isn't in THIS rekey (it gets the
        // key at the next inclusive rotation); it never aborts the pairing.
        let mut snapshot_entries: Vec<RegistrySnapshotEntry> = verified_existing
            .values()
            .filter(|entry| entry.device_id != device_id && entry.device_id != joiner_device_id)
            .cloned()
            .collect();
        // Deterministic ordering for a stable signed-snapshot byte layout
        // (HashMap iteration order is otherwise unspecified).
        snapshot_entries.sort_by(|a, b| a.device_id.cmp(&b.device_id));
        snapshot_entries.push(RegistrySnapshotEntry {
            sync_id: sync_id.clone(),
            device_id: device_id.clone(),
            ed25519_public_key: signing_key.public_key_bytes().to_vec(),
            x25519_public_key: exchange_key.public_key_bytes().to_vec(),
            ml_dsa_65_public_key: pq_signing_key.public_key_bytes(),
            ml_kem_768_public_key: pq_kem_key.public_key_bytes(),
            x_wing_public_key: xwing_key.encapsulation_key_bytes(),
            status: "active".into(),
            ml_dsa_key_generation: current_ml_dsa_generation,
            remote_wipe: false,
        });
        // SECURITY (B): author the joiner entry from the bootstrap record that
        // was cross-checked against the out-of-band rendezvous commitment in
        // `InitiatorCeremony::start`, NOT from a fresh relay fetch. The
        // commitment is a SHA-256 over the record's full canonical bytes —
        // including the V2 permanent ML-KEM-768 and X-Wing identity keys — and is
        // delivered via the QR code / deep link the human scanned, so the relay
        // cannot swap the joiner's permanent X-Wing key without the
        // verify_commitment check failing. Once full key-equality is enabled on
        // the wrap below, this permanent X-Wing key becomes an encryption target,
        // so its provenance must be the SAS/QR-bound record. (The joiner's
        // verified permanent X-Wing equals the key it registers with — both are
        // `device_secret.xwing_keypair(device_id)` — so legitimate joins still
        // pass the wrap's byte-for-byte equality check.)
        let joiner_record = ceremony.joiner_bootstrap_record();
        // Require V2 bootstrap records which carry the joiner's permanent
        // identity keys (ML-KEM-768 and X-Wing derived from DeviceSecret).
        // The ephemeral xwing_ek in the bootstrap record is for the KEM
        // handshake only — using it as the registry identity key causes a
        // device_identity_mismatch when the joiner registers with its
        // permanent keys.
        if joiner_record.permanent_ml_kem_768_public_key.is_empty()
            || joiner_record.permanent_xwing_public_key.is_empty()
        {
            return Err(CoreError::Engine(
                "bootstrap record missing permanent identity keys (V2 required for pairing)".into(),
            ));
        }
        snapshot_entries.push(RegistrySnapshotEntry {
            sync_id: sync_id.clone(),
            device_id: joiner_record.device_id.clone(),
            ed25519_public_key: joiner_record.ed25519_public_key.to_vec(),
            x25519_public_key: joiner_record.x25519_public_key.to_vec(),
            ml_dsa_65_public_key: joiner_record.ml_dsa_65_public_key.clone(),
            ml_kem_768_public_key: joiner_record.permanent_ml_kem_768_public_key.clone(),
            x_wing_public_key: joiner_record.permanent_xwing_public_key.clone(),
            status: "active".into(),
            ml_dsa_key_generation: 0,
            remote_wipe: false,
        });

        // Bind the local epoch ratchet into the signed registry: the
        // initiator commits to the epoch it believes itself to be in and to a
        // hash of every epoch key it currently holds. Joiners and (in later
        // phases) reconciliation paths use this to detect a malicious relay
        // that fabricates registry/epoch state. The snapshot version advances
        // with the relay registry so existing devices accept the newly added
        // joiner when they fetch the signed registry before applying its ops.
        let epoch_key_hashes = build_epoch_key_hashes(&key_hierarchy)?;
        // Belt-and-suspenders: catch the bug where the inviter ships a
        // snapshot with current_epoch > 0 but no epoch_key_hash for it.
        // The joiner's deserializer rejects the same shape, but failing
        // here gives a clearer error tied to the inviter's own state
        // (and avoids posting a malformed bundle to the relay at all).
        if !epoch_key_hashes.contains_key(&current_epoch) {
            return Err(CoreError::Engine(format!(
                "inviter key_hierarchy is missing epoch {current_epoch} — \
                 cannot sign registry snapshot whose current_epoch is {current_epoch}",
            )));
        }
        let registry_snapshot = SignedRegistrySnapshot::new_with_epoch_binding(
            snapshot_entries,
            next_registry_version,
            current_epoch,
            epoch_key_hashes,
        );
        let signed_keyring = registry_snapshot.sign_hybrid(&signing_key, &pq_signing_key);

        // V3 hybrid registry approval signature (labeled WNS)
        let approval_data =
            build_registry_approval_signing_data_v2(&sync_id, &device_id, &signed_keyring);
        let m_prime_approval = prism_sync_crypto::pq::build_hybrid_message_representative(
            hybrid_signature_contexts::REGISTRY_APPROVAL,
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

        // Ship every epoch key the initiator holds (1..=current_epoch) so the
        // joiner can decrypt retained batches at any epoch above its bootstrap
        // cursor — not just `current_epoch`. Each entry is committed by the
        // `epoch_key_hashes` already bound into the signed registry above, and
        // the joiner re-verifies every entry against that hash before persisting.
        // Epoch 0 is omitted: it is DEK-derived locally, never raw on the wire.
        let mut bundle_epoch_keys = std::collections::BTreeMap::new();
        for (epoch, key) in key_hierarchy.epoch_keys_iter().map_err(CoreError::Crypto)? {
            if epoch != 0 {
                bundle_epoch_keys.insert(epoch, key.to_vec());
            }
        }

        let credential_bundle = BootstrapCredentialBundle {
            sync_id: sync_id.clone(),
            relay_url: relay_url.clone(),
            mnemonic: mnemonic.to_string(),
            wrapped_dek: wrapped_dek.clone(),
            salt: salt.clone(),
            current_epoch,
            epoch_key,
            epoch_keys: bundle_epoch_keys,
            signed_keyring: signed_keyring.clone(),
            inviter_device_id: device_id.clone(),
            inviter_ed25519_pk: signing_key.public_key_bytes().to_vec(),
            inviter_ml_dsa_65_pk: pq_signing_key.public_key_bytes(),
            registry_approval_signature: Some(approval_signature),
            registration_token: self.load_optional_secure_string("registration_token")?,
        };

        let credential_envelope = ceremony.encrypt_credentials(&credential_bundle)?;
        pairing_relay
            .put_slot(&rendezvous_id, PairingSlot::Credentials, &credential_envelope)
            .await
            .map_err(|e| CoreError::from_relay_with_context(Some("posting credentials"), e))?;

        let joiner_bundle_bytes = wait_for_pairing_slot_bytes(
            pairing_relay,
            &rendezvous_id,
            PairingSlot::Joiner,
            "joiner bundle",
        )
        .await?;
        let joiner_bundle_hash = diag_hash(&joiner_bundle_bytes);
        let joiner_bundle_version =
            joiner_bundle_bytes.first().map(|b| b.to_string()).unwrap_or_else(|| "none".into());
        let _joiner_bundle = ceremony.decrypt_joiner_bundle(&joiner_bundle_bytes).map_err(|e| {
            CoreError::Engine(format!(
                "initiator failed to decrypt joiner bundle; rid={rendezvous_id}; transcript={transcript_prefix}; expected_joiner_device={}; confirmation_len={}; confirmation_sha={confirmation_hash}; joiner_bundle_len={}; joiner_bundle_version={joiner_bundle_version}; joiner_bundle_sha={joiner_bundle_hash}; err={e}",
                ceremony.joiner_device_id(),
                confirmation.len(),
                joiner_bundle_bytes.len()
            ))
        })?;

        let next_epoch = current_epoch.saturating_add(1);
        // SECURITY: the rekey wrap is driven entirely by the verified signed
        // snapshot — both recipients and the `pinned` cross-check come from
        // `registry_snapshot.entries`, so `relay.list_devices()` has no say in who
        // is wrapped or to which key. Recipients == pinned by construction, so the
        // byte-for-byte equality check in `prepare_wrapped_keys_for_devices` passes
        // and the key is wrapped to exactly the verified set (incl. self).
        let recipients: Vec<DeviceInfo> = registry_snapshot
            .entries
            .iter()
            .map(|e| DeviceInfo {
                device_id: e.device_id.clone(),
                // `epoch`/`permission` are unused by the wrap; synthesize them.
                epoch: 0,
                status: e.status.clone(),
                ed25519_public_key: e.ed25519_public_key.clone(),
                x25519_public_key: e.x25519_public_key.clone(),
                ml_dsa_65_public_key: e.ml_dsa_65_public_key.clone(),
                ml_kem_768_public_key: e.ml_kem_768_public_key.clone(),
                x_wing_public_key: e.x_wing_public_key.clone(),
                permission: None,
                ml_dsa_key_generation: e.ml_dsa_key_generation,
                needs_rekey: false,
            })
            .collect();
        let pinned: Vec<crate::storage::DeviceRecord> = registry_snapshot
            .entries
            .iter()
            .map(|e| crate::storage::DeviceRecord {
                sync_id: e.sync_id.clone(),
                device_id: e.device_id.clone(),
                ed25519_public_key: e.ed25519_public_key.clone(),
                x25519_public_key: e.x25519_public_key.clone(),
                ml_dsa_65_public_key: e.ml_dsa_65_public_key.clone(),
                ml_kem_768_public_key: e.ml_kem_768_public_key.clone(),
                x_wing_public_key: e.x_wing_public_key.clone(),
                status: e.status.clone(),
                registered_at: chrono::Utc::now(),
                revoked_at: None,
                ml_dsa_key_generation: e.ml_dsa_key_generation,
            })
            .collect();
        let (next_epoch_key, wrapped_keys) =
            EpochManager::prepare_wrapped_keys_for_devices(&recipients, next_epoch, None, &pinned)?;
        let next_epoch_key_array: [u8; 32] =
            next_epoch_key.as_slice().try_into().map_err(|_| {
                CoreError::Engine(format!(
                    "generated epoch key for epoch {next_epoch} has invalid length"
                ))
            })?;
        let mut next_epoch_hashes = build_epoch_key_hashes(&key_hierarchy)?;
        next_epoch_hashes.insert(next_epoch, compute_epoch_key_hash(&next_epoch_key_array));
        let post_rekey_registry_snapshot = SignedRegistrySnapshot::new_with_epoch_binding(
            registry_snapshot.entries.clone(),
            registry_snapshot.registry_version,
            next_epoch,
            next_epoch_hashes,
        );
        let signed_post_rekey_registry =
            post_rekey_registry_snapshot.sign_hybrid(&signing_key, &pq_signing_key);
        let epoch_key = EpochManager::post_prepared_rekey(
            sync_relay,
            &mut key_hierarchy,
            &device_id,
            next_epoch,
            next_epoch_key,
            wrapped_keys,
            Some(&signed_post_rekey_registry),
        )
        .await?;

        self.secure_store.set("epoch", next_epoch.to_string().as_bytes())?;
        use base64::{engine::general_purpose::STANDARD, Engine};
        let encoded = STANDARD.encode(epoch_key.as_slice());
        self.secure_store.set(&format!("epoch_key_{next_epoch}"), encoded.as_bytes())?;

        pairing_relay
            .delete_session(&rendezvous_id)
            .await
            .map_err(|e| CoreError::from_relay_with_context(Some("deleting pairing session"), e))?;
        self.secure_store.delete("bootstrap_joiner_bundle")?;
        self.secure_store.delete("bootstrap_joiner_device_id")?;

        // The published registry's version — the caller ratchets the inviter's
        // freshness baseline to it. `post_rekey_registry_snapshot` carries
        // the same `registry_version` as the bundle registry, which is
        // `next_registry_version`.
        Ok(next_registry_version)
    }

    /// Access the underlying secure store.
    pub fn secure_store(&self) -> &Arc<dyn SecureStore> {
        &self.secure_store
    }

    fn load_current_device_identity(&self) -> Result<(DeviceSecret, String)> {
        if let (Some(secret_bytes), Some(device_id_bytes)) =
            (self.secure_store.get("device_secret")?, self.secure_store.get("device_id")?)
        {
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
        Err(CoreError::Engine("missing device identity in secure store".into()))
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
        if let Some(stored) = self.secure_store.get(&key_name)? {
            return Self::decode_persisted_epoch_key(&key_name, stored);
        }

        Ok(key_hierarchy.epoch_key(epoch).map_err(CoreError::Crypto)?.to_vec())
    }

    /// Restore every persisted `epoch_key_{N}` (1..=current_epoch) from the
    /// secure store into the in-memory [`KeyHierarchy`].
    ///
    /// `KeyHierarchy::unlock` only seeds epoch 0 from the DEK. Higher-epoch
    /// keys live in the secure store after each `revoke_and_rekey`,
    /// `post_rekey`, or epoch-recovery commit (see
    /// `commit_recovered_epoch_material`). This restore is required before
    /// any path that needs to expose `epoch_key_hashes` for epochs > 0 —
    /// notably [`Self::complete_bootstrap_initiator`], which signs a
    /// snapshot whose `epoch_key_hashes` must include the bundle's
    /// `current_epoch` or the joiner rejects the bundle.
    ///
    /// Missing keys are silently skipped — an epoch may legitimately have
    /// no persisted entry on a device that joined after that epoch's
    /// rekey but caught up at a higher epoch in one step. Malformed keys
    /// are an error: a corrupt persisted entry shouldn't be silently
    /// dropped.
    fn restore_persisted_epoch_keys(
        &self,
        key_hierarchy: &mut KeyHierarchy,
        current_epoch: u32,
    ) -> Result<()> {
        for epoch in 1..=current_epoch {
            let key_name = format!("epoch_key_{epoch}");
            let Some(stored) = self.secure_store.get(&key_name)? else {
                continue;
            };
            let decoded = Self::decode_persisted_epoch_key(&key_name, stored)?;
            key_hierarchy.store_epoch_key(epoch, zeroize::Zeroizing::new(decoded));
        }
        Ok(())
    }

    /// Tolerant decode shared by [`Self::load_epoch_key`] and
    /// [`Self::restore_persisted_epoch_keys`]: try base64 first, then fall
    /// back to raw bytes. `sync_service.rs` historically wrote raw bytes
    /// while the bootstrap/rekey paths write base64, so we accept both.
    fn decode_persisted_epoch_key(key_name: &str, stored: Vec<u8>) -> Result<Vec<u8>> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        if let Ok(decoded) = STANDARD.decode(&stored) {
            if decoded.len() == 32 {
                return Ok(decoded);
            }
        }
        if stored.len() == 32 {
            return Ok(stored);
        }
        Err(CoreError::Engine(format!(
            "invalid {key_name} in secure store: expected 32-byte key, got {} bytes",
            stored.len()
        )))
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
}

/// Build the per-epoch commitment map carried in
/// [`SignedRegistrySnapshot::epoch_key_hashes`] from every epoch key the
/// local key hierarchy currently holds.
///
/// Anchors the signed registry to the device's local epoch ratchet so a
/// malicious relay cannot fabricate registry/epoch state during pairing
/// reconciliation.
fn build_epoch_key_hashes(
    key_hierarchy: &KeyHierarchy,
) -> Result<std::collections::BTreeMap<u32, [u8; 32]>> {
    let entries = key_hierarchy.epoch_keys_iter().map_err(CoreError::Crypto)?;
    let mut out = std::collections::BTreeMap::new();
    for (epoch, key) in entries {
        out.insert(epoch, compute_epoch_key_hash(key));
    }
    Ok(out)
}

fn next_pairing_registry_version(relay_registry_version: Option<i64>) -> i64 {
    relay_registry_version
        .map(|version| version + 1)
        .unwrap_or(SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING)
        .max(SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING)
}

fn verify_bundle_epoch_anchor(
    snapshot: &SignedRegistrySnapshot,
    bundle_epoch: u32,
    bundle_epoch_key: &[u8],
    key_hierarchy: &KeyHierarchy,
) -> Result<()> {
    if snapshot.registry_version < SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING {
        return Err(CoreError::EpochMismatch {
            local_epoch: bundle_epoch,
            relay_epoch: snapshot.current_epoch,
            message: format!(
                "credential bundle signed registry version {} cannot prove epoch keys",
                snapshot.registry_version
            ),
        });
    }
    if snapshot.current_epoch != bundle_epoch {
        return Err(CoreError::EpochMismatch {
            local_epoch: bundle_epoch,
            relay_epoch: snapshot.current_epoch,
            message: "credential bundle epoch does not match signed registry epoch".into(),
        });
    }
    verify_epoch_key_hash_in_snapshot(snapshot, bundle_epoch, bundle_epoch_key, key_hierarchy)
}

fn verify_epoch_key_hash_in_snapshot(
    snapshot: &SignedRegistrySnapshot,
    epoch: u32,
    epoch_key: &[u8],
    key_hierarchy: &KeyHierarchy,
) -> Result<()> {
    let expected_hash =
        snapshot.epoch_key_hashes.get(&epoch).ok_or_else(|| CoreError::EpochKeyMismatch {
            epoch,
            message: "signed registry is missing this epoch hash".into(),
        })?;
    let key = if epoch_key.is_empty() && epoch == 0 {
        key_hierarchy.epoch_key(0).map_err(CoreError::Crypto)?
    } else {
        epoch_key
    };
    let key: [u8; 32] = key.try_into().map_err(|_| CoreError::EpochKeyMismatch {
        epoch,
        message: format!("credential bundle epoch key has length {}, expected 32", key.len()),
    })?;
    let actual_hash = compute_epoch_key_hash(&key);
    if actual_hash != *expected_hash {
        return Err(CoreError::EpochKeyMismatch {
            epoch,
            message: "local epoch key does not match signed registry hash".into(),
        });
    }
    Ok(())
}

/// Verify and persist every historical epoch key carried in a credential
/// bundle. Epoch 0 (DEK-derived) and `current_epoch` (already handled by
/// the single-key block) are skipped. Each entry is checked against
/// `registry_snapshot.epoch_key_hashes` before it is written; a mismatched or
/// malformed key aborts fail-closed so a malicious or corrupted bundle can
/// never seed an unverified epoch key into the hierarchy.
fn install_bundle_epoch_keys(
    secure_store: &dyn SecureStore,
    key_hierarchy: &mut KeyHierarchy,
    epoch_keys: &std::collections::BTreeMap<u32, Vec<u8>>,
    current_epoch: u32,
    registry_snapshot: &SignedRegistrySnapshot,
) -> Result<()> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    for (&epoch, key) in epoch_keys {
        if epoch == 0 || epoch == current_epoch {
            continue;
        }
        if key.len() != 32 {
            return Err(CoreError::EpochKeyMismatch {
                epoch,
                message: format!("bundle epoch key has length {}, expected 32", key.len()),
            });
        }
        verify_epoch_key_hash_in_snapshot(registry_snapshot, epoch, key, key_hierarchy)?;
        let encoded = STANDARD.encode(key);
        secure_store.set(&format!("epoch_key_{epoch}"), encoded.as_bytes())?;
        key_hierarchy.store_epoch_key(epoch, zeroize::Zeroizing::new(key.clone()));
    }
    Ok(())
}

async fn fetch_and_verify_latest_join_registry(
    relay: &dyn SyncRelay,
    bundle_snapshot: &SignedRegistrySnapshot,
    bundle_epoch: u32,
) -> Result<SignedRegistrySnapshot> {
    let response = relay
        .get_signed_registry()
        .await
        .map_err(|e| CoreError::from_relay_with_context(Some("fetching signed registry"), e))?
        .ok_or_else(|| CoreError::EpochMismatch {
            local_epoch: bundle_epoch,
            relay_epoch: bundle_epoch,
            message: "relay did not provide a signed registry after join registration".into(),
        })?;
    let latest = verify_signed_registry_with_bundle_anchors(&response, bundle_snapshot)?;
    if latest.registry_version < SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING {
        return Err(CoreError::EpochMismatch {
            local_epoch: bundle_epoch,
            relay_epoch: latest.current_epoch,
            message: format!(
                "latest signed registry version {} cannot prove epoch keys",
                latest.registry_version
            ),
        });
    }
    if latest.current_epoch < bundle_epoch {
        return Err(CoreError::EpochMismatch {
            local_epoch: bundle_epoch,
            relay_epoch: latest.current_epoch,
            message: "latest signed registry is behind credential bundle epoch".into(),
        });
    }
    if !latest.epoch_key_hashes.contains_key(&latest.current_epoch) {
        return Err(CoreError::EpochKeyMismatch {
            epoch: latest.current_epoch,
            message: "latest signed registry missing current epoch key hash".into(),
        });
    }
    Ok(latest)
}

fn verify_signed_registry_with_bundle_anchors(
    response: &SignedRegistryResponse,
    bundle_snapshot: &SignedRegistrySnapshot,
) -> Result<SignedRegistrySnapshot> {
    let mut last_error = None;
    for entry in bundle_snapshot.entries.iter().filter(|entry| entry.status == "active") {
        let Ok(ed25519_pk) = <[u8; 32]>::try_from(entry.ed25519_public_key.as_slice()) else {
            continue;
        };
        if entry.ml_dsa_65_public_key.is_empty() {
            continue;
        }
        match SignedRegistrySnapshot::verify_and_decode_hybrid(
            &response.artifact_blob,
            &ed25519_pk,
            &entry.ml_dsa_65_public_key,
        ) {
            Ok(snapshot) => return Ok(snapshot),
            Err(error) => last_error = Some(error),
        }
    }

    Err(CoreError::EpochMismatch {
        local_epoch: bundle_snapshot.current_epoch,
        relay_epoch: bundle_snapshot.current_epoch,
        message: format!(
            "latest signed registry could not be verified by any credential bundle device key{}",
            last_error.map(|e| format!(": {e}")).unwrap_or_default()
        ),
    })
}

fn classify_joiner_catch_up_error(
    local_epoch: u32,
    relay_epoch: u32,
    error: CoreError,
) -> CoreError {
    let message = error.to_string();
    if message.contains("hash mismatch") || message.contains("missing epoch_key_hash") {
        CoreError::EpochKeyMismatch {
            epoch: relay_epoch,
            message: format!("joiner epoch catch-up could not verify recovered key: {message}"),
        }
    } else {
        CoreError::EpochMismatch {
            local_epoch,
            relay_epoch,
            message: format!("joiner epoch catch-up failed: {message}"),
        }
    }
}

/// Verify a hybrid invitation signature.
///
/// Accepts only the Phase 6 V3 labeled-WNS wire format.
#[cfg(test)]
fn verify_hybrid_invitation(
    signing_data: &[u8],
    sig_bytes: &[u8],
    inviter_ed25519_pk: &[u8; 32],
    inviter_ml_dsa_65_pk: &[u8],
) -> Result<()> {
    let Some((&version, sig_rest)) = sig_bytes.split_first() else {
        return Err(CoreError::Engine("invitation signature too short".into()));
    };
    enforce_wire_signature_floor(version, SIGNATURE_VERSION_SOURCE_FLOOR)?;
    let hybrid_sig = prism_sync_crypto::pq::HybridSignature::from_bytes(sig_rest)
        .map_err(|e| CoreError::Engine(format!("invitation hybrid signature invalid: {e}")))?;
    match version {
        SUPPORTED_SIGNATURE_VERSION => hybrid_sig
            .verify_v3(
                signing_data,
                hybrid_signature_contexts::INVITATION,
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

#[cfg(test)]
fn enforce_wire_signature_floor(wire_signature_version: u8, stored_floor: u8) -> Result<()> {
    let required = stored_floor.max(SIGNATURE_VERSION_SOURCE_FLOOR);
    if wire_signature_version < required {
        return Err(CoreError::Engine(format!(
            "wire signature version 0x{wire_signature_version:02x} is below required floor 0x{required:02x}"
        )));
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
        hybrid_signature_contexts::DEVICE_CHALLENGE,
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

    Err(CoreError::Engine("failed to solve first-device admission challenge".into()))
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
    hash.get(full_zero_bytes).map(|byte| byte & mask == 0).unwrap_or(false)
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
        // A failed join may have written `epoch` + `epoch_key_{1..N}`; clear them
        // too. The persisted `epoch` is the highest N written (0 if missing).
        let highest_epoch = secure_store
            .get("epoch")
            .ok()
            .flatten()
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .and_then(|raw| raw.trim().parse::<u32>().ok())
            .unwrap_or(0);
        for epoch in 1..=highest_epoch {
            let _ = secure_store.delete(&format!("epoch_key_{epoch}"));
        }
        let _ = secure_store.delete("epoch");
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
    // Pairing is human-paced, so a transient relay error (timeout/network/5xx) is
    // recoverable — re-poll it like an empty slot. Abort only on a fatal error or
    // too many consecutive transient failures (relay unreachable).
    const MAX_CONSECUTIVE_TRANSIENT: u32 = 5;
    let mut consecutive_transient = 0u32;
    for _ in 0..MAX_ATTEMPTS {
        match relay.get_slot(rendezvous_id, slot).await {
            Ok(Some(bytes)) => return Ok(bytes),
            Ok(None) => {
                consecutive_transient = 0;
                sleep(Duration::from_millis(25)).await;
            }
            Err(e) if e.is_retryable() => {
                consecutive_transient += 1;
                if consecutive_transient >= MAX_CONSECUTIVE_TRANSIENT {
                    return Err(CoreError::from_relay_with_context(Some(description), e));
                }
                sleep(Duration::from_millis(25)).await;
            }
            Err(e) => return Err(CoreError::from_relay_with_context(Some(description), e)),
        }
    }

    Err(CoreError::Engine(format!("timed out waiting for {description}")))
}

#[cfg(test)]
mod tests {
    use super::*;
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
            self.0.lock().unwrap().insert(key.to_string(), value.to_vec());
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

    // ── Flaky pairing relay (transient-error injection) ──
    //
    // Serves a configurable number of transient (retryable) relay errors before
    // returning the slot, or a fatal (non-retryable) error. Used to prove the
    // pairing poll loop rides out transient relay failures instead of aborting
    // the whole ceremony on the first blip — the "one network timeout kills
    // pairing" regression.
    struct FlakyPairingRelay {
        transient_failures_remaining: Mutex<u32>,
        slot_payload: Option<Vec<u8>>,
        fatal: bool,
    }

    impl FlakyPairingRelay {
        fn transient_then_ok(failures: u32, payload: Vec<u8>) -> Self {
            Self {
                transient_failures_remaining: Mutex::new(failures),
                slot_payload: Some(payload),
                fatal: false,
            }
        }

        fn always_fatal() -> Self {
            Self {
                transient_failures_remaining: Mutex::new(0),
                slot_payload: None,
                fatal: true,
            }
        }
    }

    #[async_trait]
    impl PairingRelay for FlakyPairingRelay {
        async fn create_session(
            &self,
            _joiner_bootstrap: &[u8],
        ) -> std::result::Result<[u8; 16], RelayError> {
            unimplemented!("not exercised by wait_for_pairing_slot_bytes tests")
        }
        async fn get_bootstrap(
            &self,
            _rendezvous_id: &str,
        ) -> std::result::Result<Vec<u8>, RelayError> {
            unimplemented!("not exercised by wait_for_pairing_slot_bytes tests")
        }
        async fn put_slot(
            &self,
            _rendezvous_id: &str,
            _slot: PairingSlot,
            _data: &[u8],
        ) -> std::result::Result<(), RelayError> {
            unimplemented!("not exercised by wait_for_pairing_slot_bytes tests")
        }
        async fn get_slot(
            &self,
            _rendezvous_id: &str,
            _slot: PairingSlot,
        ) -> std::result::Result<Option<Vec<u8>>, RelayError> {
            if self.fatal {
                return Err(RelayError::NotFound);
            }
            let mut remaining = self.transient_failures_remaining.lock().unwrap();
            if *remaining > 0 {
                *remaining -= 1;
                return Err(RelayError::Timeout {
                    message: "synthetic transient timeout".to_string(),
                });
            }
            Ok(self.slot_payload.clone())
        }
        async fn delete_session(
            &self,
            _rendezvous_id: &str,
        ) -> std::result::Result<(), RelayError> {
            unimplemented!("not exercised by wait_for_pairing_slot_bytes tests")
        }
    }

    #[tokio::test]
    async fn wait_for_pairing_slot_bytes_rides_out_transient_relay_errors() {
        // Three transient relay timeouts in a row, then the slot lands. The old
        // loop aborted on the first error (`map_err(..)?`); the fixed loop must
        // re-poll and ultimately return the payload.
        let relay = FlakyPairingRelay::transient_then_ok(3, b"pairing-init-bytes".to_vec());
        let result =
            wait_for_pairing_slot_bytes(&relay, "rendezvous-hex", PairingSlot::Init, "PairingInit")
                .await;
        assert_eq!(result.unwrap(), b"pairing-init-bytes".to_vec());
    }

    #[tokio::test]
    async fn wait_for_pairing_slot_bytes_aborts_on_fatal_relay_error() {
        // A non-retryable error (e.g. the rendezvous session expired) must still
        // fail fast rather than spinning out the full attempt budget.
        let relay = FlakyPairingRelay::always_fatal();
        let result =
            wait_for_pairing_slot_bytes(&relay, "rendezvous-hex", PairingSlot::Init, "PairingInit")
                .await;
        assert!(result.is_err(), "fatal relay error should abort the wait");
    }

    // ── Mock Relay (minimal) ──

    struct MockRelay;

    #[async_trait]
    impl SyncTransport for MockRelay {
        async fn pull_changes(&self, _since: i64) -> std::result::Result<PullResponse, RelayError> {
            unimplemented!()
        }
        async fn push_changes(
            &self,
            _batch: OutgoingBatch,
        ) -> std::result::Result<i64, RelayError> {
            unimplemented!()
        }
        async fn ack(&self, _seq: i64) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
    }
    #[async_trait]
    impl DeviceRegistry for MockRelay {
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
        async fn list_devices(&self) -> std::result::Result<Vec<DeviceInfo>, RelayError> {
            unimplemented!()
        }
        async fn revoke_device(
            &self,
            _: &str,
            _: bool,
            _: i32,
            _: HashMap<String, Vec<u8>>,
            _: Option<&[u8]>,
        ) -> std::result::Result<i32, RelayError> {
            unimplemented!()
        }
        async fn deregister(&self) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
        async fn rotate_ml_dsa(
            &self,
            _: &str,
            _: &[u8],
            _: u32,
            _: &prism_sync_crypto::pq::continuity_proof::MlDsaContinuityProof,
            _: Option<&[u8]>,
        ) -> std::result::Result<RotateMlDsaResponse, RelayError> {
            unimplemented!()
        }
        async fn get_signed_registry(
            &self,
        ) -> std::result::Result<Option<SignedRegistryResponse>, RelayError> {
            Ok(None)
        }
        async fn put_signed_registry(&self, _: &[u8]) -> std::result::Result<i64, RelayError> {
            Ok(0)
        }
    }
    #[async_trait]
    impl EpochManagement for MockRelay {
        async fn post_rekey_artifacts(
            &self,
            _: i32,
            _: HashMap<String, Vec<u8>>,
            _: Option<&[u8]>,
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
    }
    #[async_trait]
    impl SnapshotExchange for MockRelay {
        async fn get_snapshot(&self) -> std::result::Result<Option<SnapshotResponse>, RelayError> {
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
            _: Option<crate::relay::traits::SnapshotUploadProgress>,
        ) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
        async fn delete_snapshot(&self) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
    }
    #[async_trait]
    impl MediaRelay for MockRelay {
        async fn upload_media(
            &self,
            _: &str,
            _: &str,
            _: Vec<u8>,
            _: Option<u64>,
        ) -> std::result::Result<MediaUploadOutcome, RelayError> {
            unimplemented!()
        }
        async fn download_media(&self, _: &str) -> std::result::Result<Vec<u8>, RelayError> {
            unimplemented!()
        }
        async fn batch_exists(
            &self,
            _: &[String],
        ) -> std::result::Result<Vec<String>, RelayError> {
            unimplemented!()
        }
        async fn send_ephemeral(
            &self,
            _: &crate::ephemeral::EphemeralEnvelope,
        ) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
        async fn fetch_pending_ephemeral(
            &self,
        ) -> std::result::Result<Vec<crate::ephemeral::EphemeralEnvelope>, RelayError> {
            unimplemented!()
        }
        async fn ack_ephemeral(
            &self,
            _: &[String],
        ) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
    }
    #[async_trait]
    impl SyncRelay for MockRelay {
        async fn delete_sync_group(&self) -> std::result::Result<(), RelayError> {
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
        async fn dispose(&self) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
    }

    /// Helper: build a relay-builder closure that always returns a MockRelay.
    fn mock_relay_builder(
    ) -> impl FnOnce(&str, &str, Option<&str>) -> Result<Arc<dyn SyncRelay>> + Send {
        |_sync_id, _device_id, _token| Ok(Arc::new(MockRelay) as Arc<dyn SyncRelay>)
    }

    #[derive(Default)]
    struct BootstrapRegistryState {
        devices: Vec<DeviceInfo>,
        register_requests: Vec<RegisterRequest>,
        rekey_posts: Option<(i32, HashMap<String, Vec<u8>>)>,
        rekey_artifacts: HashMap<(i32, String), Vec<u8>>,
        signed_registry: Option<SignedRegistryResponse>,
        advance_after_artifact_fetch: Option<(i32, i32)>,
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
                    rekey_artifacts: HashMap::new(),
                    signed_registry: None,
                    advance_after_artifact_fetch: None,
                })),
            }
        }

        fn insert_rekey_artifact(&self, epoch: i32, device_id: &str, artifact: Vec<u8>) {
            self.state
                .lock()
                .unwrap()
                .rekey_artifacts
                .insert((epoch, device_id.to_string()), artifact);
        }

        fn set_signed_registry(&self, signed_registry: SignedRegistryResponse) {
            self.state.lock().unwrap().signed_registry = Some(signed_registry);
        }

        fn advance_active_devices_after_artifact_fetch(&self, trigger_epoch: i32, new_epoch: i32) {
            self.state.lock().unwrap().advance_after_artifact_fetch =
                Some((trigger_epoch, new_epoch));
        }
    }

    #[async_trait]
    impl SyncTransport for BootstrapRegistryRelay {
        async fn pull_changes(&self, _since: i64) -> std::result::Result<PullResponse, RelayError> {
            unimplemented!()
        }
        async fn push_changes(
            &self,
            _batch: OutgoingBatch,
        ) -> std::result::Result<i64, RelayError> {
            unimplemented!()
        }
        async fn ack(&self, _seq: i64) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
    }
    #[async_trait]
    impl DeviceRegistry for BootstrapRegistryRelay {
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
            if let Some(approval) = &req.registry_approval {
                let registry_version = state
                    .signed_registry
                    .as_ref()
                    .map(|registry| registry.registry_version + 1)
                    .unwrap_or(SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING);
                state.signed_registry = Some(SignedRegistryResponse {
                    registry_version,
                    artifact_blob: approval.signed_registry_snapshot.clone(),
                    artifact_kind: "signed_registry_snapshot".to_string(),
                });
            }
            state.devices.push(DeviceInfo {
                device_id: req.device_id,
                epoch: 0,
                status: "active".to_string(),
                ed25519_public_key: req.signing_public_key,
                x25519_public_key: req.x25519_public_key,
                ml_dsa_65_public_key: req.ml_dsa_65_public_key,
                ml_kem_768_public_key: req.ml_kem_768_public_key,
                x_wing_public_key: req.x_wing_public_key,
                permission: None,
                ml_dsa_key_generation: 0,
                needs_rekey: false,
            });
            Ok(RegisterResponse {
                device_session_token: "mock-session-token".to_string(),
                min_signature_version: None,
            })
        }
        async fn list_devices(&self) -> std::result::Result<Vec<DeviceInfo>, RelayError> {
            Ok(self.state.lock().unwrap().devices.clone())
        }
        async fn revoke_device(
            &self,
            _: &str,
            _: bool,
            _: i32,
            _: HashMap<String, Vec<u8>>,
            _: Option<&[u8]>,
        ) -> std::result::Result<i32, RelayError> {
            unimplemented!()
        }
        async fn deregister(&self) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
        async fn rotate_ml_dsa(
            &self,
            _: &str,
            _: &[u8],
            _: u32,
            _: &prism_sync_crypto::pq::continuity_proof::MlDsaContinuityProof,
            _: Option<&[u8]>,
        ) -> std::result::Result<RotateMlDsaResponse, RelayError> {
            unimplemented!()
        }
        async fn get_signed_registry(
            &self,
        ) -> std::result::Result<Option<SignedRegistryResponse>, RelayError> {
            Ok(self.state.lock().unwrap().signed_registry.clone())
        }
        async fn put_signed_registry(
            &self,
            signed_registry_snapshot: &[u8],
        ) -> std::result::Result<i64, RelayError> {
            let mut state = self.state.lock().unwrap();
            let registry_version = state
                .signed_registry
                .as_ref()
                .map(|registry| registry.registry_version + 1)
                .unwrap_or(SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING);
            state.signed_registry = Some(SignedRegistryResponse {
                registry_version,
                artifact_blob: signed_registry_snapshot.to_vec(),
                artifact_kind: "signed_registry_snapshot".to_string(),
            });
            Ok(registry_version)
        }
    }
    #[async_trait]
    impl EpochManagement for BootstrapRegistryRelay {
        async fn post_rekey_artifacts(
            &self,
            epoch: i32,
            keys: HashMap<String, Vec<u8>>,
            signed_registry_snapshot: Option<&[u8]>,
        ) -> std::result::Result<i32, RelayError> {
            let mut state = self.state.lock().unwrap();
            let current_epoch = state
                .devices
                .iter()
                .filter(|device| device.status == "active")
                .map(|device| device.epoch)
                .max()
                .unwrap_or(0);
            if epoch <= current_epoch {
                return Err(RelayError::Protocol {
                    message: format!(
                        "stale rekey epoch {epoch}; relay is already at epoch {current_epoch}"
                    ),
                });
            }
            for device in &mut state.devices {
                if device.status == "active" {
                    device.epoch = epoch;
                }
            }
            for (device_id, artifact) in &keys {
                state.rekey_artifacts.insert((epoch, device_id.clone()), artifact.clone());
            }
            if let Some(snapshot) = signed_registry_snapshot {
                let registry_version = state
                    .signed_registry
                    .as_ref()
                    .map(|registry| registry.registry_version)
                    .unwrap_or(SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING);
                state.signed_registry = Some(SignedRegistryResponse {
                    registry_version,
                    artifact_blob: snapshot.to_vec(),
                    artifact_kind: "signed_registry_snapshot".to_string(),
                });
            }
            state.rekey_posts = Some((epoch, keys));
            Ok(epoch)
        }
        async fn get_rekey_artifact(
            &self,
            epoch: i32,
            device_id: &str,
        ) -> std::result::Result<Option<Vec<u8>>, RelayError> {
            let mut state = self.state.lock().unwrap();
            let artifact = state.rekey_artifacts.get(&(epoch, device_id.to_string())).cloned();
            if artifact.is_some() {
                if let Some((trigger_epoch, new_epoch)) = state.advance_after_artifact_fetch {
                    if epoch == trigger_epoch {
                        for device in &mut state.devices {
                            if device.status == "active" {
                                device.epoch = new_epoch;
                            }
                        }
                        state.advance_after_artifact_fetch = None;
                    }
                }
            }
            Ok(artifact)
        }
    }
    #[async_trait]
    impl SnapshotExchange for BootstrapRegistryRelay {
        async fn get_snapshot(&self) -> std::result::Result<Option<SnapshotResponse>, RelayError> {
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
            _: Option<crate::relay::traits::SnapshotUploadProgress>,
        ) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
        async fn delete_snapshot(&self) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
    }
    #[async_trait]
    impl MediaRelay for BootstrapRegistryRelay {
        async fn upload_media(
            &self,
            _: &str,
            _: &str,
            _: Vec<u8>,
            _: Option<u64>,
        ) -> std::result::Result<MediaUploadOutcome, RelayError> {
            unimplemented!()
        }
        async fn download_media(&self, _: &str) -> std::result::Result<Vec<u8>, RelayError> {
            unimplemented!()
        }
        async fn batch_exists(
            &self,
            _: &[String],
        ) -> std::result::Result<Vec<String>, RelayError> {
            unimplemented!()
        }
        async fn send_ephemeral(
            &self,
            _: &crate::ephemeral::EphemeralEnvelope,
        ) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
        async fn fetch_pending_ephemeral(
            &self,
        ) -> std::result::Result<Vec<crate::ephemeral::EphemeralEnvelope>, RelayError> {
            unimplemented!()
        }
        async fn ack_ephemeral(
            &self,
            _: &[String],
        ) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
    }
    #[async_trait]
    impl SyncRelay for BootstrapRegistryRelay {
        async fn delete_sync_group(&self) -> std::result::Result<(), RelayError> {
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
        async fn dispose(&self) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
    }

    fn seed_bootstrap_store(
        store: &MemStore,
        device_secret: &DeviceSecret,
        device_id: &str,
        sync_id: &str,
        relay_url: &str,
        wrapped_dek: &[u8],
        salt: &[u8],
    ) {
        // Note: no mnemonic is written to the store — the recovery phrase is
        // not a persisted credential. `complete_bootstrap_initiator` receives
        // it as a parameter from the caller (who would have prompted the user
        // to type it from their offline backup).
        store.set("device_secret", device_secret.as_bytes()).unwrap();
        store.set("device_id", device_id.as_bytes()).unwrap();
        store.set("sync_id", sync_id.as_bytes()).unwrap();
        store.set("relay_url", relay_url.as_bytes()).unwrap();
        store.set("wrapped_dek", wrapped_dek).unwrap();
        store.set("dek_salt", salt).unwrap();
        store.set("epoch", b"0").unwrap();
    }

    /// Build an in-memory `SyncStorage` pinned with the inviter's own device
    /// record so that `complete_bootstrap_initiator` can verify the relay's
    /// signed registry against a locally-trusted anchor (the inviter is the
    /// signer of the snapshot it just authored). In production the inviter's own
    /// record is always present locally; this mirrors that for tests.
    fn initiator_storage_with_self(
        sync_id: &str,
        device_secret: &DeviceSecret,
        device_id: &str,
        ml_dsa_generation: u32,
    ) -> Arc<dyn crate::storage::SyncStorage> {
        let storage: Arc<dyn crate::storage::SyncStorage> =
            Arc::new(crate::storage::RusqliteSyncStorage::in_memory().unwrap());
        let signing_key = device_secret.ed25519_keypair(device_id).unwrap();
        let exchange_key = device_secret.x25519_keypair(device_id).unwrap();
        let pq_signing_key =
            device_secret.ml_dsa_65_keypair_v(device_id, ml_dsa_generation).unwrap();
        let pq_kem_key = device_secret.ml_kem_768_keypair(device_id).unwrap();
        let xwing_key = device_secret.xwing_keypair(device_id).unwrap();
        let record = crate::storage::DeviceRecord {
            sync_id: sync_id.to_string(),
            device_id: device_id.to_string(),
            ed25519_public_key: signing_key.public_key_bytes().to_vec(),
            x25519_public_key: exchange_key.public_key_bytes().to_vec(),
            ml_dsa_65_public_key: pq_signing_key.public_key_bytes(),
            ml_kem_768_public_key: pq_kem_key.public_key_bytes(),
            x_wing_public_key: xwing_key.encapsulation_key_bytes(),
            status: "active".into(),
            registered_at: chrono::Utc::now(),
            revoked_at: None,
            ml_dsa_key_generation: ml_dsa_generation,
        };
        crate::device_registry::DeviceRegistryManager::pin_device(
            storage.as_ref(),
            sync_id,
            &record,
        )
        .unwrap();
        storage
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

    fn build_v2_artifact(
        receiver_xwing: &prism_sync_crypto::DeviceXWingKey,
        epoch_key: &[u8],
        epoch: u32,
        device_id: &str,
    ) -> Vec<u8> {
        use prism_sync_crypto::pq::hybrid_kem::XWingKem;

        let ek_bytes = receiver_xwing.encapsulation_key_bytes();
        let ek = XWingKem::encapsulation_key_from_bytes(&ek_bytes).unwrap();
        let mut rng = getrandom::rand_core::UnwrapErr(getrandom::SysRng);
        let (ciphertext, shared_secret_raw) = XWingKem::encapsulate(&ek, &mut rng);
        let shared_secret = zeroize::Zeroizing::new(shared_secret_raw);

        let mut salt = Vec::with_capacity(4 + device_id.len());
        salt.extend_from_slice(&epoch.to_le_bytes());
        salt.extend_from_slice(device_id.as_bytes());
        let wrap_key =
            prism_sync_crypto::kdf::derive_subkey(&shared_secret, &salt, b"prism_epoch_rekey_v2")
                .unwrap();
        let aad = crate::epoch::build_rekey_artifact_aad(epoch, device_id);
        let encrypted_epoch_key =
            prism_sync_crypto::aead::xchacha_encrypt_aead(&wrap_key, epoch_key, &aad).unwrap();

        let mut artifact = Vec::with_capacity(1 + ciphertext.len() + encrypted_epoch_key.len());
        artifact.push(0x02);
        artifact.extend_from_slice(&ciphertext);
        artifact.extend_from_slice(&encrypted_epoch_key);
        artifact
    }

    #[tokio::test]
    async fn bootstrap_joiner_catches_up_when_relay_registry_advanced() {
        let password = "bootstrap-password";
        let relay_url = "https://relay.example.com";
        let sync_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        let inviter_secret = DeviceSecret::generate();
        let inviter_device_id = crate::node_id::generate_node_id();
        let mnemonic = mnemonic::generate();
        let secret_key = mnemonic::to_bytes(&mnemonic).unwrap();
        let mut inviter_hierarchy = KeyHierarchy::new();
        let (wrapped_dek, salt) = inviter_hierarchy.initialize(password, &secret_key).unwrap();
        let epoch_0_key: [u8; 32] = inviter_hierarchy.epoch_key(0).unwrap().try_into().unwrap();
        let epoch_1_key = [0x77u8; 32];

        let inviter_signing_key = inviter_secret.ed25519_keypair(&inviter_device_id).unwrap();
        let inviter_exchange_key = inviter_secret.x25519_keypair(&inviter_device_id).unwrap();
        let inviter_pq_signing_key = inviter_secret.ml_dsa_65_keypair(&inviter_device_id).unwrap();
        let inviter_pq_kem_key = inviter_secret.ml_kem_768_keypair(&inviter_device_id).unwrap();
        let inviter_xwing_key = inviter_secret.xwing_keypair(&inviter_device_id).unwrap();

        let joiner_store = Arc::new(MemStore::default());
        let joiner_service = PairingService::new(joiner_store.clone());
        let mailbox = Arc::new(MockPairingRelay::new());
        let (mut joiner, token) =
            joiner_service.start_bootstrap_pairing(mailbox.as_ref(), relay_url).await.unwrap();
        let (initiator, _sas) =
            InitiatorCeremony::start(token, mailbox.as_ref(), &inviter_secret, &inviter_device_id)
                .await
                .unwrap();
        let init_bytes =
            wait_for_slot(mailbox.as_ref(), &joiner.rendezvous_id_hex(), PairingSlot::Init).await;
        joiner.process_pairing_init(&init_bytes).unwrap();
        initiator.verify_joiner_confirmation(&joiner.confirmation_mac().unwrap()).unwrap();

        let joiner_secret = joiner.device_secret();
        let joiner_device_id = joiner.device_id().to_string();
        let joiner_signing_key = joiner_secret.ed25519_keypair(&joiner_device_id).unwrap();
        let joiner_exchange_key = joiner_secret.x25519_keypair(&joiner_device_id).unwrap();
        let joiner_pq_signing_key = joiner_secret.ml_dsa_65_keypair(&joiner_device_id).unwrap();
        let joiner_pq_kem_key = joiner_secret.ml_kem_768_keypair(&joiner_device_id).unwrap();
        let joiner_xwing_key = joiner_secret.xwing_keypair(&joiner_device_id).unwrap();

        let entries = vec![
            RegistrySnapshotEntry {
                sync_id: sync_id.to_string(),
                device_id: inviter_device_id.clone(),
                ed25519_public_key: inviter_signing_key.public_key_bytes().to_vec(),
                x25519_public_key: inviter_exchange_key.public_key_bytes().to_vec(),
                ml_dsa_65_public_key: inviter_pq_signing_key.public_key_bytes(),
                ml_kem_768_public_key: inviter_pq_kem_key.public_key_bytes(),
                x_wing_public_key: inviter_xwing_key.encapsulation_key_bytes(),
                status: "active".to_string(),
                ml_dsa_key_generation: 0,
                remote_wipe: false,
            },
            RegistrySnapshotEntry {
                sync_id: sync_id.to_string(),
                device_id: joiner_device_id.clone(),
                ed25519_public_key: joiner_signing_key.public_key_bytes().to_vec(),
                x25519_public_key: joiner_exchange_key.public_key_bytes().to_vec(),
                ml_dsa_65_public_key: joiner_pq_signing_key.public_key_bytes(),
                ml_kem_768_public_key: joiner_pq_kem_key.public_key_bytes(),
                x_wing_public_key: joiner_xwing_key.encapsulation_key_bytes(),
                status: "active".to_string(),
                ml_dsa_key_generation: 0,
                remote_wipe: false,
            },
        ];

        let mut bundle_hashes = std::collections::BTreeMap::new();
        bundle_hashes.insert(0, compute_epoch_key_hash(&epoch_0_key));
        let bundle_snapshot = SignedRegistrySnapshot::new_with_epoch_binding(
            entries.clone(),
            SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING,
            0,
            bundle_hashes,
        );
        let credential_bundle = BootstrapCredentialBundle {
            sync_id: sync_id.to_string(),
            relay_url: relay_url.to_string(),
            mnemonic: mnemonic.clone(),
            wrapped_dek: wrapped_dek.clone(),
            salt: salt.clone(),
            current_epoch: 0,
            epoch_key: Vec::new(),
            epoch_keys: std::collections::BTreeMap::new(),
            signed_keyring: bundle_snapshot
                .sign_hybrid(&inviter_signing_key, &inviter_pq_signing_key),
            inviter_device_id: inviter_device_id.clone(),
            inviter_ed25519_pk: inviter_signing_key.public_key_bytes().to_vec(),
            inviter_ml_dsa_65_pk: inviter_pq_signing_key.public_key_bytes(),
            registry_approval_signature: None,
            registration_token: None,
        };
        let encrypted_credentials = initiator.encrypt_credentials(&credential_bundle).unwrap();

        let registry_relay = Arc::new(BootstrapRegistryRelay::new(vec![DeviceInfo {
            device_id: inviter_device_id.clone(),
            epoch: 1,
            status: "active".to_string(),
            ed25519_public_key: inviter_signing_key.public_key_bytes().to_vec(),
            x25519_public_key: inviter_exchange_key.public_key_bytes().to_vec(),
            ml_dsa_65_public_key: inviter_pq_signing_key.public_key_bytes(),
            ml_kem_768_public_key: inviter_pq_kem_key.public_key_bytes(),
            x_wing_public_key: inviter_xwing_key.encapsulation_key_bytes(),
            permission: None,
            ml_dsa_key_generation: 0,
            needs_rekey: false,
        }]));
        registry_relay.insert_rekey_artifact(
            1,
            &joiner_device_id,
            build_v2_artifact(&joiner_xwing_key, &epoch_1_key, 1, &joiner_device_id),
        );
        let mut latest_hashes = std::collections::BTreeMap::new();
        latest_hashes.insert(0, compute_epoch_key_hash(&epoch_0_key));
        latest_hashes.insert(1, compute_epoch_key_hash(&epoch_1_key));
        let latest_snapshot = SignedRegistrySnapshot::new_with_epoch_binding(
            entries,
            SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING,
            1,
            latest_hashes,
        );
        registry_relay.set_signed_registry(SignedRegistryResponse {
            registry_version: SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING,
            artifact_blob: latest_snapshot
                .sign_hybrid(&inviter_signing_key, &inviter_pq_signing_key),
            artifact_kind: "signed_registry_snapshot".to_string(),
        });

        let (joiner_hierarchy, returned_snapshot) = joiner_service
            .complete_bootstrap_join(
                &joiner,
                mailbox.as_ref(),
                &encrypted_credentials,
                password,
                |_sync_id, _device_id, _token| Ok(registry_relay as Arc<dyn SyncRelay>),
            )
            .await
            .unwrap();

        assert_eq!(returned_snapshot.current_epoch, 1);
        assert!(joiner_hierarchy.has_epoch_key(1));
        assert_eq!(joiner_store.get("epoch").unwrap().unwrap(), b"1");
        assert!(joiner_store.get("epoch_key_1").unwrap().is_some());
    }

    #[tokio::test]
    async fn bootstrap_joiner_fails_loud_when_advanced_epoch_artifact_missing() {
        let password = "bootstrap-password";
        let relay_url = "https://relay.example.com";
        let sync_id = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

        let inviter_secret = DeviceSecret::generate();
        let inviter_device_id = crate::node_id::generate_node_id();
        let mnemonic = mnemonic::generate();
        let secret_key = mnemonic::to_bytes(&mnemonic).unwrap();
        let mut inviter_hierarchy = KeyHierarchy::new();
        let (wrapped_dek, salt) = inviter_hierarchy.initialize(password, &secret_key).unwrap();
        let epoch_0_key: [u8; 32] = inviter_hierarchy.epoch_key(0).unwrap().try_into().unwrap();
        let epoch_1_key = [0x88u8; 32];

        let inviter_signing_key = inviter_secret.ed25519_keypair(&inviter_device_id).unwrap();
        let inviter_exchange_key = inviter_secret.x25519_keypair(&inviter_device_id).unwrap();
        let inviter_pq_signing_key = inviter_secret.ml_dsa_65_keypair(&inviter_device_id).unwrap();
        let inviter_pq_kem_key = inviter_secret.ml_kem_768_keypair(&inviter_device_id).unwrap();
        let inviter_xwing_key = inviter_secret.xwing_keypair(&inviter_device_id).unwrap();

        let joiner_store = Arc::new(MemStore::default());
        let joiner_service = PairingService::new(joiner_store.clone());
        let mailbox = Arc::new(MockPairingRelay::new());
        let (mut joiner, token) =
            joiner_service.start_bootstrap_pairing(mailbox.as_ref(), relay_url).await.unwrap();
        let (initiator, _sas) =
            InitiatorCeremony::start(token, mailbox.as_ref(), &inviter_secret, &inviter_device_id)
                .await
                .unwrap();
        let init_bytes =
            wait_for_slot(mailbox.as_ref(), &joiner.rendezvous_id_hex(), PairingSlot::Init).await;
        joiner.process_pairing_init(&init_bytes).unwrap();
        initiator.verify_joiner_confirmation(&joiner.confirmation_mac().unwrap()).unwrap();

        let joiner_secret = joiner.device_secret();
        let joiner_device_id = joiner.device_id().to_string();
        let joiner_signing_key = joiner_secret.ed25519_keypair(&joiner_device_id).unwrap();
        let joiner_exchange_key = joiner_secret.x25519_keypair(&joiner_device_id).unwrap();
        let joiner_pq_signing_key = joiner_secret.ml_dsa_65_keypair(&joiner_device_id).unwrap();
        let joiner_pq_kem_key = joiner_secret.ml_kem_768_keypair(&joiner_device_id).unwrap();
        let joiner_xwing_key = joiner_secret.xwing_keypair(&joiner_device_id).unwrap();

        let entries = vec![
            RegistrySnapshotEntry {
                sync_id: sync_id.to_string(),
                device_id: inviter_device_id.clone(),
                ed25519_public_key: inviter_signing_key.public_key_bytes().to_vec(),
                x25519_public_key: inviter_exchange_key.public_key_bytes().to_vec(),
                ml_dsa_65_public_key: inviter_pq_signing_key.public_key_bytes(),
                ml_kem_768_public_key: inviter_pq_kem_key.public_key_bytes(),
                x_wing_public_key: inviter_xwing_key.encapsulation_key_bytes(),
                status: "active".to_string(),
                ml_dsa_key_generation: 0,
                remote_wipe: false,
            },
            RegistrySnapshotEntry {
                sync_id: sync_id.to_string(),
                device_id: joiner_device_id.clone(),
                ed25519_public_key: joiner_signing_key.public_key_bytes().to_vec(),
                x25519_public_key: joiner_exchange_key.public_key_bytes().to_vec(),
                ml_dsa_65_public_key: joiner_pq_signing_key.public_key_bytes(),
                ml_kem_768_public_key: joiner_pq_kem_key.public_key_bytes(),
                x_wing_public_key: joiner_xwing_key.encapsulation_key_bytes(),
                status: "active".to_string(),
                ml_dsa_key_generation: 0,
                remote_wipe: false,
            },
        ];

        let mut bundle_hashes = std::collections::BTreeMap::new();
        bundle_hashes.insert(0, compute_epoch_key_hash(&epoch_0_key));
        let bundle_snapshot = SignedRegistrySnapshot::new_with_epoch_binding(
            entries.clone(),
            SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING,
            0,
            bundle_hashes,
        );
        let credential_bundle = BootstrapCredentialBundle {
            sync_id: sync_id.to_string(),
            relay_url: relay_url.to_string(),
            mnemonic,
            wrapped_dek,
            salt,
            current_epoch: 0,
            epoch_key: Vec::new(),
            epoch_keys: std::collections::BTreeMap::new(),
            signed_keyring: bundle_snapshot
                .sign_hybrid(&inviter_signing_key, &inviter_pq_signing_key),
            inviter_device_id: inviter_device_id.clone(),
            inviter_ed25519_pk: inviter_signing_key.public_key_bytes().to_vec(),
            inviter_ml_dsa_65_pk: inviter_pq_signing_key.public_key_bytes(),
            registry_approval_signature: None,
            registration_token: None,
        };
        let encrypted_credentials = initiator.encrypt_credentials(&credential_bundle).unwrap();

        let registry_relay = Arc::new(BootstrapRegistryRelay::new(vec![DeviceInfo {
            device_id: inviter_device_id.clone(),
            epoch: 1,
            status: "active".to_string(),
            ed25519_public_key: inviter_signing_key.public_key_bytes().to_vec(),
            x25519_public_key: inviter_exchange_key.public_key_bytes().to_vec(),
            ml_dsa_65_public_key: inviter_pq_signing_key.public_key_bytes(),
            ml_kem_768_public_key: inviter_pq_kem_key.public_key_bytes(),
            x_wing_public_key: inviter_xwing_key.encapsulation_key_bytes(),
            permission: None,
            ml_dsa_key_generation: 0,
            needs_rekey: false,
        }]));
        let mut latest_hashes = std::collections::BTreeMap::new();
        latest_hashes.insert(0, compute_epoch_key_hash(&epoch_0_key));
        latest_hashes.insert(1, compute_epoch_key_hash(&epoch_1_key));
        let latest_snapshot = SignedRegistrySnapshot::new_with_epoch_binding(
            entries,
            SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING,
            1,
            latest_hashes,
        );
        registry_relay.set_signed_registry(SignedRegistryResponse {
            registry_version: SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING,
            artifact_blob: latest_snapshot
                .sign_hybrid(&inviter_signing_key, &inviter_pq_signing_key),
            artifact_kind: "signed_registry_snapshot".to_string(),
        });

        let err = match joiner_service
            .complete_bootstrap_join(
                &joiner,
                mailbox.as_ref(),
                &encrypted_credentials,
                password,
                |_sync_id, _device_id, _token| Ok(registry_relay as Arc<dyn SyncRelay>),
            )
            .await
        {
            Ok(_) => panic!("expected epoch mismatch"),
            Err(err) => err,
        };

        assert!(
            matches!(err, CoreError::EpochMismatch { local_epoch: 0, relay_epoch: 1, .. }),
            "unexpected error: {err:?}"
        );
        assert!(
            mailbox
                .get_slot(&joiner.rendezvous_id_hex(), PairingSlot::Joiner)
                .await
                .unwrap()
                .is_none(),
            "joiner must not acknowledge pairing before verified epoch catch-up"
        );
        assert!(joiner_store.get("epoch_key_1").unwrap().is_none());
        assert_eq!(joiner_store.get("epoch").unwrap().unwrap(), b"0");
        let _ = joiner_xwing_key;
    }

    #[tokio::test]
    async fn bootstrap_pairing_round_trip_and_rekey() {
        let password = "bootstrap-password";
        let relay_url = "https://relay.example.com";
        let sync_id = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";

        let device_secret = DeviceSecret::generate();
        let device_id = crate::node_id::generate_node_id();
        let current_generation = 5;
        let mnemonic = mnemonic::generate();
        let secret_key = mnemonic::to_bytes(&mnemonic).unwrap();
        let mut key_hierarchy = KeyHierarchy::new();
        let (wrapped_dek, salt) = key_hierarchy.initialize(password, &secret_key).unwrap();

        let inviter_signing_key = device_secret.ed25519_keypair(&device_id).unwrap();
        let inviter_exchange_key = device_secret.x25519_keypair(&device_id).unwrap();
        let inviter_pq_signing_key =
            device_secret.ml_dsa_65_keypair_v(&device_id, current_generation).unwrap();
        // The inviter is itself a recipient of the post-pairing rekey wrap, so
        // its relay-advertised X-Wing key must match the (real) key the initiator
        // authors into the signed snapshot from its local DeviceSecret — otherwise
        // the now-enforced byte-for-byte key-equality check correctly rejects it.
        let inviter_pq_kem_key = device_secret.ml_kem_768_keypair(&device_id).unwrap();
        let inviter_xwing_key = device_secret.xwing_keypair(&device_id).unwrap();

        let registry_relay = Arc::new(BootstrapRegistryRelay::new(vec![DeviceInfo {
            device_id: device_id.clone(),
            epoch: 0,
            status: "active".to_string(),
            ed25519_public_key: inviter_signing_key.public_key_bytes().to_vec(),
            x25519_public_key: inviter_exchange_key.public_key_bytes().to_vec(),
            ml_dsa_65_public_key: inviter_pq_signing_key.public_key_bytes(),
            ml_kem_768_public_key: inviter_pq_kem_key.public_key_bytes(),
            x_wing_public_key: inviter_xwing_key.encapsulation_key_bytes(),
            permission: None,
            ml_dsa_key_generation: current_generation,
            needs_rekey: false,
        }]));

        let initiator_store = Arc::new(MemStore::default());
        seed_bootstrap_store(
            &initiator_store,
            &device_secret,
            &device_id,
            sync_id,
            relay_url,
            &wrapped_dek,
            &salt,
        );
        initiator_store.set("registration_token", b"relay-registration-token").unwrap();
        let initiator_service = PairingService::new(initiator_store.clone());

        let joiner_store = Arc::new(MemStore::default());
        let joiner_service = PairingService::new(joiner_store.clone());
        let joiner_service_task = PairingService::new(joiner_store.clone());

        let mailbox = Arc::new(MockPairingRelay::new());

        let (mut joiner, token) =
            joiner_service.start_bootstrap_pairing(mailbox.as_ref(), relay_url).await.unwrap();
        let pending_joiner_id = String::from_utf8(
            joiner_store
                .get("pending_device_id")
                .unwrap()
                .expect("pending joiner id should be stored"),
        )
        .unwrap();
        assert_eq!(pending_joiner_id, joiner.device_id());

        let (initiator, initiator_sas) =
            initiator_service.start_bootstrap_initiator(token, mailbox.as_ref()).await.unwrap();

        let joiner_rendezvous_id = joiner.rendezvous_id_hex();
        let joiner_device_id = joiner.device_id().to_string();
        let init_bytes =
            wait_for_slot(mailbox.as_ref(), &joiner_rendezvous_id, PairingSlot::Init).await;
        let joiner_sas = joiner.process_pairing_init(&init_bytes).unwrap();
        assert_eq!(joiner_sas.words, initiator_sas.words);
        assert_eq!(joiner_sas.word_list, initiator_sas.word_list);

        let joiner_mailbox = mailbox.clone();
        let joiner_relay = registry_relay.clone();
        let joiner_handle = tokio::spawn(async move {
            joiner_service_task
                .complete_bootstrap_join(
                    &joiner,
                    joiner_mailbox.as_ref(),
                    &[],
                    password,
                    |sync_id, device_id, _token| {
                        assert_eq!(
                            sync_id.len(),
                            64,
                            "relay-builder must receive real 64-hex sync_id, got: {sync_id}"
                        );
                        assert!(
                            sync_id.chars().all(|c| c.is_ascii_hexdigit()),
                            "sync_id must be hex"
                        );
                        assert!(!device_id.is_empty(), "device_id must not be empty");
                        Ok(joiner_relay as Arc<dyn SyncRelay>)
                    },
                )
                .await
                .unwrap()
        });

        let initiator_storage =
            initiator_storage_with_self(sync_id, &device_secret, &device_id, current_generation);
        initiator_service
            .complete_bootstrap_initiator(
                &initiator,
                mailbox.as_ref(),
                password,
                &mnemonic,
                registry_relay.as_ref(),
                initiator_storage.as_ref(),
            )
            .await
            .unwrap();

        let (joiner_key_hierarchy, joiner_snapshot) = joiner_handle.await.unwrap();
        assert!(joiner_key_hierarchy.is_unlocked());
        assert!(joiner_snapshot.entries.len() >= 2);
        assert_eq!(
            String::from_utf8(
                joiner_store.get("device_id").unwrap().expect("device id should be persisted")
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

        assert!(initiator_store.get("bootstrap_joiner_bundle").unwrap().is_none());
        assert!(initiator_store.get("bootstrap_joiner_device_id").unwrap().is_none());

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

            let approval =
                register_req.registry_approval.as_ref().expect("registry approval present");
            let inviter_pk: [u8; 32] = inviter_signing_key.public_key_bytes();
            let snapshot = SignedRegistrySnapshot::verify_and_decode_hybrid(
                &approval.signed_registry_snapshot,
                &inviter_pk,
                &inviter_pq_signing_key.public_key_bytes(),
            )
            .unwrap();
            let current_entry = snapshot
                .entries
                .iter()
                .find(|entry| entry.device_id == device_id)
                .expect("current device entry should be present");
            assert_eq!(current_entry.ml_dsa_key_generation, current_generation);
        }

        let err = mailbox.get_bootstrap(&joiner_rendezvous_id).await.unwrap_err();
        assert!(err.to_string().contains("session not found"));
    }

    /// NEGATIVE TEST 1 (C2 / existing-device X-Wing swap + relay injection).
    ///
    /// The pairing rekey is driven ENTIRELY by the verified signed registry, so
    /// the relay's unsigned `list_devices()` has no influence on who is wrapped or
    /// to which key. This test proves two relay manipulations are both neutralized
    /// WITHOUT aborting the legitimate pairing:
    ///   (a) SWAP: an existing peer (present in the signed registry + local store
    ///       with its TRUE key) is returned by `list_devices()` with a SWAPPED
    ///       X-Wing key → the peer is still wrapped, but to the TRUE key from the
    ///       verified snapshot; the relay's swapped key is ignored.
    ///   (b) INJECT: `list_devices()` includes an extra "active" device that is
    ///       NOT in any signed registry → that device receives NO wrapped key (it
    ///       is never a recipient).
    /// Before this change the relay list drove the wrap; (a) would have been
    /// wrapped to the attacker key (membership-only) or aborted the pairing
    /// (relay-list-cross-checked), and (b) would have aborted the pairing.
    #[tokio::test]
    async fn bootstrap_initiator_ignores_relay_swapped_existing_device_xwing() {
        let password = "bootstrap-password";
        let relay_url = "https://relay.example.com";
        let sync_id = "d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5";

        let device_secret = DeviceSecret::generate();
        let device_id = crate::node_id::generate_node_id();
        let current_generation = 5;
        let mnemonic = mnemonic::generate();
        let secret_key = mnemonic::to_bytes(&mnemonic).unwrap();
        let mut key_hierarchy = KeyHierarchy::new();
        let (wrapped_dek, salt) = key_hierarchy.initialize(password, &secret_key).unwrap();

        let inviter_signing_key = device_secret.ed25519_keypair(&device_id).unwrap();
        let inviter_exchange_key = device_secret.x25519_keypair(&device_id).unwrap();
        let inviter_pq_signing_key =
            device_secret.ml_dsa_65_keypair_v(&device_id, current_generation).unwrap();
        let inviter_pq_kem_key = device_secret.ml_kem_768_keypair(&device_id).unwrap();
        let inviter_xwing_key = device_secret.xwing_keypair(&device_id).unwrap();

        // A pre-existing peer device, with its TRUE identity keys.
        let peer_secret = DeviceSecret::generate();
        let peer_device_id = crate::node_id::generate_node_id();
        let peer_signing_key = peer_secret.ed25519_keypair(&peer_device_id).unwrap();
        let peer_exchange_key = peer_secret.x25519_keypair(&peer_device_id).unwrap();
        let peer_pq_signing_key = peer_secret.ml_dsa_65_keypair(&peer_device_id).unwrap();
        let peer_pq_kem_key = peer_secret.ml_kem_768_keypair(&peer_device_id).unwrap();
        let peer_xwing_key_true = peer_secret.xwing_keypair(&peer_device_id).unwrap();
        let peer_xwing_true = peer_xwing_key_true.encapsulation_key_bytes();
        // An attacker-controlled X-Wing key the relay tries to substitute (swap).
        let attacker_secret = DeviceSecret::generate();
        let attacker_xwing =
            attacker_secret.xwing_keypair("attacker").unwrap().encapsulation_key_bytes();
        assert_ne!(peer_xwing_true, attacker_xwing);

        // A relay-injected device that exists in NO signed registry.
        let injected_secret = DeviceSecret::generate();
        let injected_device_id = crate::node_id::generate_node_id();
        let injected_signing_key = injected_secret.ed25519_keypair(&injected_device_id).unwrap();
        let injected_exchange_key = injected_secret.x25519_keypair(&injected_device_id).unwrap();
        let injected_pq_signing_key =
            injected_secret.ml_dsa_65_keypair(&injected_device_id).unwrap();
        let injected_pq_kem_key = injected_secret.ml_kem_768_keypair(&injected_device_id).unwrap();
        let injected_xwing =
            injected_secret.xwing_keypair(&injected_device_id).unwrap().encapsulation_key_bytes();

        let peer_true_entry = RegistrySnapshotEntry {
            sync_id: sync_id.to_string(),
            device_id: peer_device_id.clone(),
            ed25519_public_key: peer_signing_key.public_key_bytes().to_vec(),
            x25519_public_key: peer_exchange_key.public_key_bytes().to_vec(),
            ml_dsa_65_public_key: peer_pq_signing_key.public_key_bytes(),
            ml_kem_768_public_key: peer_pq_kem_key.public_key_bytes(),
            x_wing_public_key: peer_xwing_true.clone(),
            status: "active".to_string(),
            ml_dsa_key_generation: 0,
            remote_wipe: false,
        };
        let inviter_entry = RegistrySnapshotEntry {
            sync_id: sync_id.to_string(),
            device_id: device_id.clone(),
            ed25519_public_key: inviter_signing_key.public_key_bytes().to_vec(),
            x25519_public_key: inviter_exchange_key.public_key_bytes().to_vec(),
            ml_dsa_65_public_key: inviter_pq_signing_key.public_key_bytes(),
            ml_kem_768_public_key: inviter_pq_kem_key.public_key_bytes(),
            x_wing_public_key: inviter_xwing_key.encapsulation_key_bytes(),
            status: "active".to_string(),
            ml_dsa_key_generation: current_generation,
            remote_wipe: false,
        };

        // Relay's UNSIGNED device list: inviter (true), peer with a SWAPPED key,
        // plus an INJECTED device absent from any signed registry.
        let registry_relay = Arc::new(BootstrapRegistryRelay::new(vec![
            DeviceInfo {
                device_id: device_id.clone(),
                epoch: 0,
                status: "active".to_string(),
                ed25519_public_key: inviter_signing_key.public_key_bytes().to_vec(),
                x25519_public_key: inviter_exchange_key.public_key_bytes().to_vec(),
                ml_dsa_65_public_key: inviter_pq_signing_key.public_key_bytes(),
                ml_kem_768_public_key: inviter_pq_kem_key.public_key_bytes(),
                x_wing_public_key: inviter_xwing_key.encapsulation_key_bytes(),
                permission: None,
                ml_dsa_key_generation: current_generation,
                needs_rekey: false,
            },
            DeviceInfo {
                device_id: peer_device_id.clone(),
                epoch: 0,
                status: "active".to_string(),
                ed25519_public_key: peer_signing_key.public_key_bytes().to_vec(),
                x25519_public_key: peer_exchange_key.public_key_bytes().to_vec(),
                ml_dsa_65_public_key: peer_pq_signing_key.public_key_bytes(),
                ml_kem_768_public_key: peer_pq_kem_key.public_key_bytes(),
                x_wing_public_key: attacker_xwing.clone(), // SWAPPED
                permission: None,
                ml_dsa_key_generation: 0,
                needs_rekey: false,
            },
            DeviceInfo {
                device_id: injected_device_id.clone(),
                epoch: 0,
                status: "active".to_string(), // INJECTED: not in any signed registry
                ed25519_public_key: injected_signing_key.public_key_bytes().to_vec(),
                x25519_public_key: injected_exchange_key.public_key_bytes().to_vec(),
                ml_dsa_65_public_key: injected_pq_signing_key.public_key_bytes(),
                ml_kem_768_public_key: injected_pq_kem_key.public_key_bytes(),
                x_wing_public_key: injected_xwing.clone(),
                permission: None,
                ml_dsa_key_generation: 0,
                needs_rekey: false,
            },
        ]));

        // Relay's SIGNED registry: inviter + peer, both with TRUE keys, signed by
        // the inviter. This is the trusted source the initiator authors from. The
        // injected device is deliberately absent.
        let mut epoch_key_hashes = std::collections::BTreeMap::new();
        let epoch_0_key: [u8; 32] = key_hierarchy.epoch_key(0).unwrap().try_into().unwrap();
        epoch_key_hashes.insert(0, compute_epoch_key_hash(&epoch_0_key));
        let signed = SignedRegistrySnapshot::new_with_epoch_binding(
            vec![inviter_entry.clone(), peer_true_entry.clone()],
            SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING,
            0,
            epoch_key_hashes,
        );
        registry_relay.set_signed_registry(SignedRegistryResponse {
            registry_version: SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING,
            artifact_blob: signed.sign_hybrid(&inviter_signing_key, &inviter_pq_signing_key),
            artifact_kind: "signed_registry_snapshot".to_string(),
        });

        // Local pinned registry: inviter + peer, both TRUE. The verification of
        // the relay's signed registry is anchored against these records.
        let initiator_storage =
            initiator_storage_with_self(sync_id, &device_secret, &device_id, current_generation);
        crate::device_registry::DeviceRegistryManager::pin_device(
            initiator_storage.as_ref(),
            sync_id,
            &crate::storage::DeviceRecord {
                sync_id: sync_id.to_string(),
                device_id: peer_device_id.clone(),
                ed25519_public_key: peer_signing_key.public_key_bytes().to_vec(),
                x25519_public_key: peer_exchange_key.public_key_bytes().to_vec(),
                ml_dsa_65_public_key: peer_pq_signing_key.public_key_bytes(),
                ml_kem_768_public_key: peer_pq_kem_key.public_key_bytes(),
                x_wing_public_key: peer_xwing_true.clone(),
                status: "active".into(),
                registered_at: chrono::Utc::now(),
                revoked_at: None,
                ml_dsa_key_generation: 0,
            },
        )
        .unwrap();

        let initiator_store = Arc::new(MemStore::default());
        seed_bootstrap_store(
            &initiator_store,
            &device_secret,
            &device_id,
            sync_id,
            relay_url,
            &wrapped_dek,
            &salt,
        );
        initiator_store.set("registration_token", b"relay-registration-token").unwrap();
        let initiator_service = PairingService::new(initiator_store.clone());

        let joiner_store = Arc::new(MemStore::default());
        let joiner_service = PairingService::new(joiner_store.clone());
        let joiner_service_task = PairingService::new(joiner_store.clone());
        let mailbox = Arc::new(MockPairingRelay::new());

        let (mut joiner, token) =
            joiner_service.start_bootstrap_pairing(mailbox.as_ref(), relay_url).await.unwrap();
        let joiner_device_id = joiner.device_id().to_string();
        let (initiator, initiator_sas) =
            initiator_service.start_bootstrap_initiator(token, mailbox.as_ref()).await.unwrap();

        let joiner_rendezvous_id = joiner.rendezvous_id_hex();
        let init_bytes =
            wait_for_slot(mailbox.as_ref(), &joiner_rendezvous_id, PairingSlot::Init).await;
        let joiner_sas = joiner.process_pairing_init(&init_bytes).unwrap();
        assert_eq!(joiner_sas.words, initiator_sas.words);

        let joiner_mailbox = mailbox.clone();
        let joiner_relay = registry_relay.clone();
        let joiner_handle = tokio::spawn(async move {
            joiner_service_task
                .complete_bootstrap_join(
                    &joiner,
                    joiner_mailbox.as_ref(),
                    &[],
                    password,
                    |_sync_id, _device_id, _token| Ok(joiner_relay as Arc<dyn SyncRelay>),
                )
                .await
                .unwrap()
        });

        // The pairing SUCCEEDS — the relay's swap and injection are simply ignored.
        initiator_service
            .complete_bootstrap_initiator(
                &initiator,
                mailbox.as_ref(),
                password,
                &mnemonic,
                registry_relay.as_ref(),
                initiator_storage.as_ref(),
            )
            .await
            .expect("pairing must succeed; relay list manipulations are ignored");

        let _ = joiner_handle.await.unwrap();

        let state = registry_relay.state.lock().unwrap();

        // The posted signed snapshot carries the peer's TRUE X-Wing key, not the
        // relay's swapped key.
        let register_req = state.register_requests.last().expect("joiner registered");
        let approval =
            register_req.registry_approval.as_ref().expect("registry approval present");
        let snapshot = SignedRegistrySnapshot::verify_and_decode_hybrid(
            &approval.signed_registry_snapshot,
            &inviter_signing_key.public_key_bytes(),
            &inviter_pq_signing_key.public_key_bytes(),
        )
        .unwrap();
        let peer_entry = snapshot
            .entries
            .iter()
            .find(|e| e.device_id == peer_device_id)
            .expect("peer entry present in signed snapshot");
        assert_eq!(
            peer_entry.x_wing_public_key, peer_xwing_true,
            "peer entry must carry the TRUE X-Wing key, not the relay-swapped one"
        );
        assert_ne!(peer_entry.x_wing_public_key, attacker_xwing);
        // The injected device is NOT in the signed snapshot.
        assert!(
            !snapshot.entries.iter().any(|e| e.device_id == injected_device_id),
            "relay-injected device must not appear in the signed snapshot"
        );

        // The rekey was posted, and wraps to exactly the verified set: the peer
        // (TRUE key) and the joiner are recipients; the injected device is not.
        let (_epoch, wrapped_keys) =
            state.rekey_posts.as_ref().expect("rekey must have been posted");
        assert!(
            wrapped_keys.contains_key(&peer_device_id),
            "peer must receive a wrapped epoch key (to its TRUE X-Wing key)"
        );
        assert!(
            wrapped_keys.contains_key(&joiner_device_id),
            "joiner must receive a wrapped epoch key"
        );
        assert!(
            !wrapped_keys.contains_key(&injected_device_id),
            "relay-injected device must NOT receive a wrapped epoch key"
        );
    }

    /// NEGATIVE TEST 2 (joiner permanent X-Wing swap on the relay bootstrap).
    ///
    /// After the ceremony has bound the joiner's bootstrap record to the
    /// out-of-band rendezvous commitment, the relay tampers the stored bootstrap
    /// bytes, swapping the joiner's permanent X-Wing key. The initiator must
    /// author the joiner's signed-registry entry (and therefore the wrap target)
    /// from the commitment-verified ceremony record, NOT from the relay's
    /// tampered bootstrap — so the posted snapshot carries the joiner's TRUE
    /// permanent X-Wing key and the swap is ignored.
    #[tokio::test]
    async fn bootstrap_initiator_ignores_relay_tampered_joiner_bootstrap() {
        let password = "bootstrap-password";
        let relay_url = "https://relay.example.com";
        let sync_id = "e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6";

        let device_secret = DeviceSecret::generate();
        let device_id = crate::node_id::generate_node_id();
        let current_generation = 5;
        let mnemonic = mnemonic::generate();
        let secret_key = mnemonic::to_bytes(&mnemonic).unwrap();
        let mut key_hierarchy = KeyHierarchy::new();
        let (wrapped_dek, salt) = key_hierarchy.initialize(password, &secret_key).unwrap();

        let inviter_signing_key = device_secret.ed25519_keypair(&device_id).unwrap();
        let inviter_exchange_key = device_secret.x25519_keypair(&device_id).unwrap();
        let inviter_pq_signing_key =
            device_secret.ml_dsa_65_keypair_v(&device_id, current_generation).unwrap();
        let inviter_pq_kem_key = device_secret.ml_kem_768_keypair(&device_id).unwrap();
        let inviter_xwing_key = device_secret.xwing_keypair(&device_id).unwrap();

        let registry_relay = Arc::new(BootstrapRegistryRelay::new(vec![DeviceInfo {
            device_id: device_id.clone(),
            epoch: 0,
            status: "active".to_string(),
            ed25519_public_key: inviter_signing_key.public_key_bytes().to_vec(),
            x25519_public_key: inviter_exchange_key.public_key_bytes().to_vec(),
            ml_dsa_65_public_key: inviter_pq_signing_key.public_key_bytes(),
            ml_kem_768_public_key: inviter_pq_kem_key.public_key_bytes(),
            x_wing_public_key: inviter_xwing_key.encapsulation_key_bytes(),
            permission: None,
            ml_dsa_key_generation: current_generation,
            needs_rekey: false,
        }]));

        let initiator_store = Arc::new(MemStore::default());
        seed_bootstrap_store(
            &initiator_store,
            &device_secret,
            &device_id,
            sync_id,
            relay_url,
            &wrapped_dek,
            &salt,
        );
        initiator_store.set("registration_token", b"relay-registration-token").unwrap();
        let initiator_service = PairingService::new(initiator_store.clone());

        let joiner_store = Arc::new(MemStore::default());
        let joiner_service = PairingService::new(joiner_store.clone());
        let joiner_service_task = PairingService::new(joiner_store.clone());
        let mailbox = Arc::new(MockPairingRelay::new());

        let (mut joiner, token) =
            joiner_service.start_bootstrap_pairing(mailbox.as_ref(), relay_url).await.unwrap();
        let joiner_rendezvous_id = joiner.rendezvous_id_hex();
        let joiner_device_id = joiner.device_id().to_string();

        // Capture the joiner's TRUE permanent X-Wing key from the genuine
        // bootstrap record the relay holds before tampering.
        let genuine_bootstrap_bytes =
            mailbox.get_bootstrap(&joiner_rendezvous_id).await.unwrap();
        let genuine_record = crate::bootstrap::JoinerBootstrapRecord::from_canonical_bytes(
            &genuine_bootstrap_bytes,
        )
        .unwrap();
        let joiner_true_xwing = genuine_record.permanent_xwing_public_key.clone();
        assert!(!joiner_true_xwing.is_empty());

        let (initiator, initiator_sas) =
            initiator_service.start_bootstrap_initiator(token, mailbox.as_ref()).await.unwrap();

        let init_bytes =
            wait_for_slot(mailbox.as_ref(), &joiner_rendezvous_id, PairingSlot::Init).await;
        let joiner_sas = joiner.process_pairing_init(&init_bytes).unwrap();
        assert_eq!(joiner_sas.words, initiator_sas.words);

        // The relay now tampers the stored bootstrap record, swapping the
        // joiner's permanent X-Wing (and ML-KEM) keys for attacker-controlled
        // ones. The commitment the human verified is NOT updated.
        let attacker_secret = DeviceSecret::generate();
        let attacker_xwing = attacker_secret
            .xwing_keypair("attacker")
            .unwrap()
            .encapsulation_key_bytes();
        let attacker_ml_kem =
            attacker_secret.ml_kem_768_keypair("attacker").unwrap().public_key_bytes();
        assert_ne!(joiner_true_xwing, attacker_xwing);
        let mut tampered_record = genuine_record.clone();
        tampered_record.permanent_xwing_public_key = attacker_xwing.clone();
        tampered_record.permanent_ml_kem_768_public_key = attacker_ml_kem;
        mailbox.tamper_bootstrap(&joiner_rendezvous_id, tampered_record.to_canonical_bytes());

        let joiner_mailbox = mailbox.clone();
        let joiner_relay = registry_relay.clone();
        let joiner_handle = tokio::spawn(async move {
            joiner_service_task
                .complete_bootstrap_join(
                    &joiner,
                    joiner_mailbox.as_ref(),
                    &[],
                    password,
                    |_sync_id, _device_id, _token| Ok(joiner_relay as Arc<dyn SyncRelay>),
                )
                .await
                .unwrap()
        });

        let initiator_storage =
            initiator_storage_with_self(sync_id, &device_secret, &device_id, current_generation);
        initiator_service
            .complete_bootstrap_initiator(
                &initiator,
                mailbox.as_ref(),
                password,
                &mnemonic,
                registry_relay.as_ref(),
                initiator_storage.as_ref(),
            )
            .await
            .expect("pairing must succeed using the commitment-verified joiner record");

        let _ = joiner_handle.await.unwrap();

        // The posted signed registry must carry the joiner's TRUE permanent
        // X-Wing key, proving the initiator ignored the relay's tampered
        // bootstrap record.
        let state = registry_relay.state.lock().unwrap();
        let register_req = state.register_requests.last().expect("joiner registered");
        let approval =
            register_req.registry_approval.as_ref().expect("registry approval present");
        let snapshot = SignedRegistrySnapshot::verify_and_decode_hybrid(
            &approval.signed_registry_snapshot,
            &inviter_signing_key.public_key_bytes(),
            &inviter_pq_signing_key.public_key_bytes(),
        )
        .unwrap();
        let joiner_entry = snapshot
            .entries
            .iter()
            .find(|e| e.device_id == joiner_device_id)
            .expect("joiner entry present in signed snapshot");
        assert_eq!(
            joiner_entry.x_wing_public_key, joiner_true_xwing,
            "joiner entry must use the commitment-verified key, not the relay-tampered one"
        );
        assert_ne!(joiner_entry.x_wing_public_key, attacker_xwing);
    }

    #[tokio::test]
    async fn bootstrap_initiator_catches_up_before_rekey_when_relay_ahead() {
        let password = "bootstrap-password";
        let relay_url = "https://relay.example.com";
        let sync_id = "c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4";

        let device_secret = DeviceSecret::generate();
        let device_id = crate::node_id::generate_node_id();
        let current_generation = 5;
        let mnemonic = mnemonic::generate();
        let secret_key = mnemonic::to_bytes(&mnemonic).unwrap();
        let mut key_hierarchy = KeyHierarchy::new();
        let (wrapped_dek, salt) = key_hierarchy.initialize(password, &secret_key).unwrap();

        let inviter_signing_key = device_secret.ed25519_keypair(&device_id).unwrap();
        let inviter_exchange_key = device_secret.x25519_keypair(&device_id).unwrap();
        let inviter_pq_signing_key =
            device_secret.ml_dsa_65_keypair_v(&device_id, current_generation).unwrap();
        let inviter_pq_kem_key = device_secret.ml_kem_768_keypair(&device_id).unwrap();
        let inviter_xwing_key = device_secret.xwing_keypair(&device_id).unwrap();

        let epoch_0_key: [u8; 32] = key_hierarchy.epoch_key(0).unwrap().try_into().unwrap();
        let epoch_1_key = [0x11u8; 32];
        let epoch_2_key = [0x22u8; 32];

        let registry_relay = Arc::new(BootstrapRegistryRelay::new(vec![DeviceInfo {
            device_id: device_id.clone(),
            epoch: 2,
            status: "active".to_string(),
            ed25519_public_key: inviter_signing_key.public_key_bytes().to_vec(),
            x25519_public_key: inviter_exchange_key.public_key_bytes().to_vec(),
            ml_dsa_65_public_key: inviter_pq_signing_key.public_key_bytes(),
            ml_kem_768_public_key: inviter_pq_kem_key.public_key_bytes(),
            x_wing_public_key: inviter_xwing_key.encapsulation_key_bytes(),
            permission: None,
            ml_dsa_key_generation: current_generation,
            needs_rekey: false,
        }]));
        registry_relay.insert_rekey_artifact(
            1,
            &device_id,
            build_v2_artifact(&inviter_xwing_key, &epoch_1_key, 1, &device_id),
        );
        registry_relay.insert_rekey_artifact(
            2,
            &device_id,
            build_v2_artifact(&inviter_xwing_key, &epoch_2_key, 2, &device_id),
        );

        let mut epoch_key_hashes = std::collections::BTreeMap::new();
        epoch_key_hashes.insert(0, compute_epoch_key_hash(&epoch_0_key));
        epoch_key_hashes.insert(1, compute_epoch_key_hash(&epoch_1_key));
        epoch_key_hashes.insert(2, compute_epoch_key_hash(&epoch_2_key));
        let registry_snapshot = SignedRegistrySnapshot::new_with_epoch_binding(
            vec![RegistrySnapshotEntry {
                sync_id: sync_id.to_string(),
                device_id: device_id.clone(),
                ed25519_public_key: inviter_signing_key.public_key_bytes().to_vec(),
                x25519_public_key: inviter_exchange_key.public_key_bytes().to_vec(),
                ml_dsa_65_public_key: inviter_pq_signing_key.public_key_bytes(),
                ml_kem_768_public_key: inviter_pq_kem_key.public_key_bytes(),
                x_wing_public_key: inviter_xwing_key.encapsulation_key_bytes(),
                status: "active".to_string(),
                ml_dsa_key_generation: current_generation,
                remote_wipe: false,
            }],
            SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING,
            2,
            epoch_key_hashes,
        );
        registry_relay.set_signed_registry(SignedRegistryResponse {
            registry_version: SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING,
            artifact_blob: registry_snapshot
                .sign_hybrid(&inviter_signing_key, &inviter_pq_signing_key),
            artifact_kind: "signed_registry_snapshot".to_string(),
        });

        let initiator_store = Arc::new(MemStore::default());
        seed_bootstrap_store(
            &initiator_store,
            &device_secret,
            &device_id,
            sync_id,
            relay_url,
            &wrapped_dek,
            &salt,
        );
        initiator_store.set("registration_token", b"relay-registration-token").unwrap();
        let initiator_service = PairingService::new(initiator_store.clone());

        let joiner_store = Arc::new(MemStore::default());
        let joiner_service = PairingService::new(joiner_store.clone());
        let joiner_service_task = PairingService::new(joiner_store.clone());
        let mailbox = Arc::new(MockPairingRelay::new());

        let (mut joiner, token) =
            joiner_service.start_bootstrap_pairing(mailbox.as_ref(), relay_url).await.unwrap();
        let (initiator, initiator_sas) =
            initiator_service.start_bootstrap_initiator(token, mailbox.as_ref()).await.unwrap();

        let joiner_rendezvous_id = joiner.rendezvous_id_hex();
        let init_bytes =
            wait_for_slot(mailbox.as_ref(), &joiner_rendezvous_id, PairingSlot::Init).await;
        let joiner_sas = joiner.process_pairing_init(&init_bytes).unwrap();
        assert_eq!(joiner_sas.words, initiator_sas.words);
        assert_eq!(joiner_sas.word_list, initiator_sas.word_list);

        let joiner_mailbox = mailbox.clone();
        let joiner_relay = registry_relay.clone();
        let joiner_handle = tokio::spawn(async move {
            joiner_service_task
                .complete_bootstrap_join(
                    &joiner,
                    joiner_mailbox.as_ref(),
                    &[],
                    password,
                    |_sync_id, _device_id, _token| Ok(joiner_relay as Arc<dyn SyncRelay>),
                )
                .await
                .unwrap()
        });

        let initiator_storage =
            initiator_storage_with_self(sync_id, &device_secret, &device_id, current_generation);
        initiator_service
            .complete_bootstrap_initiator(
                &initiator,
                mailbox.as_ref(),
                password,
                &mnemonic,
                registry_relay.as_ref(),
                initiator_storage.as_ref(),
            )
            .await
            .unwrap();

        let (joiner_key_hierarchy, joiner_snapshot) = joiner_handle.await.unwrap();
        assert!(joiner_key_hierarchy.is_unlocked());
        assert_eq!(joiner_snapshot.current_epoch, 2);

        assert!(initiator_store.get("epoch_key_1").unwrap().is_some());
        assert!(initiator_store.get("epoch_key_2").unwrap().is_some());
        assert_eq!(initiator_store.get("epoch").unwrap().unwrap(), b"3");

        let post_rekey_registry_blob = {
            let state = registry_relay.state.lock().unwrap();
            let (next_epoch, wrapped_keys) = state.rekey_posts.as_ref().unwrap();
            assert_eq!(*next_epoch, 3);
            assert!(wrapped_keys.contains_key(&device_id));
            state.signed_registry.as_ref().unwrap().artifact_blob.clone()
        };
        let post_rekey_snapshot = SignedRegistrySnapshot::verify_and_decode_hybrid(
            &post_rekey_registry_blob,
            &inviter_signing_key.public_key_bytes(),
            &inviter_pq_signing_key.public_key_bytes(),
        )
        .unwrap();
        assert_eq!(post_rekey_snapshot.current_epoch, 3);
        assert!(post_rekey_snapshot.epoch_key_hashes.contains_key(&3));

        let err = mailbox.get_bootstrap(&joiner_rendezvous_id).await.unwrap_err();
        assert!(err.to_string().contains("session not found"));
    }

    #[tokio::test]
    async fn bootstrap_initiator_stops_before_rekey_when_catch_up_artifact_missing() {
        let password = "bootstrap-password";
        let relay_url = "https://relay.example.com";
        let sync_id = "d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5";

        let device_secret = DeviceSecret::generate();
        let device_id = crate::node_id::generate_node_id();
        let current_generation = 5;
        let mnemonic = mnemonic::generate();
        let secret_key = mnemonic::to_bytes(&mnemonic).unwrap();
        let mut key_hierarchy = KeyHierarchy::new();
        let (wrapped_dek, salt) = key_hierarchy.initialize(password, &secret_key).unwrap();

        let inviter_signing_key = device_secret.ed25519_keypair(&device_id).unwrap();
        let inviter_exchange_key = device_secret.x25519_keypair(&device_id).unwrap();
        let inviter_pq_signing_key =
            device_secret.ml_dsa_65_keypair_v(&device_id, current_generation).unwrap();
        let inviter_pq_kem_key = device_secret.ml_kem_768_keypair(&device_id).unwrap();
        let inviter_xwing_key = device_secret.xwing_keypair(&device_id).unwrap();

        let epoch_0_key: [u8; 32] = key_hierarchy.epoch_key(0).unwrap().try_into().unwrap();
        let epoch_1_key = [0x11u8; 32];
        let epoch_2_key = [0x22u8; 32];

        let registry_relay = Arc::new(BootstrapRegistryRelay::new(vec![DeviceInfo {
            device_id: device_id.clone(),
            epoch: 2,
            status: "active".to_string(),
            ed25519_public_key: inviter_signing_key.public_key_bytes().to_vec(),
            x25519_public_key: inviter_exchange_key.public_key_bytes().to_vec(),
            ml_dsa_65_public_key: inviter_pq_signing_key.public_key_bytes(),
            ml_kem_768_public_key: inviter_pq_kem_key.public_key_bytes(),
            x_wing_public_key: inviter_xwing_key.encapsulation_key_bytes(),
            permission: None,
            ml_dsa_key_generation: current_generation,
            needs_rekey: false,
        }]));
        registry_relay.insert_rekey_artifact(
            1,
            &device_id,
            build_v2_artifact(&inviter_xwing_key, &epoch_1_key, 1, &device_id),
        );

        let mut epoch_key_hashes = std::collections::BTreeMap::new();
        epoch_key_hashes.insert(0, compute_epoch_key_hash(&epoch_0_key));
        epoch_key_hashes.insert(1, compute_epoch_key_hash(&epoch_1_key));
        epoch_key_hashes.insert(2, compute_epoch_key_hash(&epoch_2_key));
        let registry_snapshot = SignedRegistrySnapshot::new_with_epoch_binding(
            vec![RegistrySnapshotEntry {
                sync_id: sync_id.to_string(),
                device_id: device_id.clone(),
                ed25519_public_key: inviter_signing_key.public_key_bytes().to_vec(),
                x25519_public_key: inviter_exchange_key.public_key_bytes().to_vec(),
                ml_dsa_65_public_key: inviter_pq_signing_key.public_key_bytes(),
                ml_kem_768_public_key: inviter_pq_kem_key.public_key_bytes(),
                x_wing_public_key: inviter_xwing_key.encapsulation_key_bytes(),
                status: "active".to_string(),
                ml_dsa_key_generation: current_generation,
                remote_wipe: false,
            }],
            SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING,
            2,
            epoch_key_hashes,
        );
        registry_relay.set_signed_registry(SignedRegistryResponse {
            registry_version: SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING,
            artifact_blob: registry_snapshot
                .sign_hybrid(&inviter_signing_key, &inviter_pq_signing_key),
            artifact_kind: "signed_registry_snapshot".to_string(),
        });

        let initiator_store = Arc::new(MemStore::default());
        seed_bootstrap_store(
            &initiator_store,
            &device_secret,
            &device_id,
            sync_id,
            relay_url,
            &wrapped_dek,
            &salt,
        );
        let initiator_service = PairingService::new(initiator_store.clone());

        let joiner_store = Arc::new(MemStore::default());
        let joiner_service = PairingService::new(joiner_store);
        let mailbox = Arc::new(MockPairingRelay::new());

        let (mut joiner, token) =
            joiner_service.start_bootstrap_pairing(mailbox.as_ref(), relay_url).await.unwrap();
        let (initiator, initiator_sas) =
            initiator_service.start_bootstrap_initiator(token, mailbox.as_ref()).await.unwrap();

        let joiner_rendezvous_id = joiner.rendezvous_id_hex();
        let init_bytes =
            wait_for_slot(mailbox.as_ref(), &joiner_rendezvous_id, PairingSlot::Init).await;
        let joiner_sas = joiner.process_pairing_init(&init_bytes).unwrap();
        assert_eq!(joiner_sas.words, initiator_sas.words);
        assert_eq!(joiner_sas.word_list, initiator_sas.word_list);
        let confirmation = joiner.confirmation_mac().unwrap();
        mailbox
            .put_slot(&joiner_rendezvous_id, PairingSlot::Confirmation, &confirmation)
            .await
            .unwrap();

        let initiator_storage =
            initiator_storage_with_self(sync_id, &device_secret, &device_id, current_generation);
        let err = initiator_service
            .complete_bootstrap_initiator(
                &initiator,
                mailbox.as_ref(),
                password,
                &mnemonic,
                registry_relay.as_ref(),
                initiator_storage.as_ref(),
            )
            .await
            .unwrap_err();

        assert!(err.to_string().contains("no rekey artifact for epoch 2"));
        assert!(initiator_store.get("epoch_key_1").unwrap().is_some());
        assert!(initiator_store.get("epoch_key_2").unwrap().is_none());
        assert_eq!(initiator_store.get("epoch").unwrap().unwrap(), b"1");
        assert!(registry_relay.state.lock().unwrap().rekey_posts.is_none());
    }

    #[tokio::test]
    async fn bootstrap_initiator_does_not_write_next_epoch_on_toctou_rekey_reject() {
        let password = "bootstrap-password";
        let relay_url = "https://relay.example.com";
        let sync_id = "e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6";

        let device_secret = DeviceSecret::generate();
        let device_id = crate::node_id::generate_node_id();
        let current_generation = 5;
        let mnemonic = mnemonic::generate();
        let secret_key = mnemonic::to_bytes(&mnemonic).unwrap();
        let mut key_hierarchy = KeyHierarchy::new();
        let (wrapped_dek, salt) = key_hierarchy.initialize(password, &secret_key).unwrap();

        let inviter_signing_key = device_secret.ed25519_keypair(&device_id).unwrap();
        let inviter_exchange_key = device_secret.x25519_keypair(&device_id).unwrap();
        let inviter_pq_signing_key =
            device_secret.ml_dsa_65_keypair_v(&device_id, current_generation).unwrap();
        let inviter_pq_kem_key = device_secret.ml_kem_768_keypair(&device_id).unwrap();
        let inviter_xwing_key = device_secret.xwing_keypair(&device_id).unwrap();

        let epoch_0_key: [u8; 32] = key_hierarchy.epoch_key(0).unwrap().try_into().unwrap();
        let epoch_1_key = [0x11u8; 32];
        let epoch_2_key = [0x22u8; 32];

        let registry_relay = Arc::new(BootstrapRegistryRelay::new(vec![DeviceInfo {
            device_id: device_id.clone(),
            epoch: 2,
            status: "active".to_string(),
            ed25519_public_key: inviter_signing_key.public_key_bytes().to_vec(),
            x25519_public_key: inviter_exchange_key.public_key_bytes().to_vec(),
            ml_dsa_65_public_key: inviter_pq_signing_key.public_key_bytes(),
            ml_kem_768_public_key: inviter_pq_kem_key.public_key_bytes(),
            x_wing_public_key: inviter_xwing_key.encapsulation_key_bytes(),
            permission: None,
            ml_dsa_key_generation: current_generation,
            needs_rekey: false,
        }]));
        registry_relay.insert_rekey_artifact(
            1,
            &device_id,
            build_v2_artifact(&inviter_xwing_key, &epoch_1_key, 1, &device_id),
        );
        registry_relay.insert_rekey_artifact(
            2,
            &device_id,
            build_v2_artifact(&inviter_xwing_key, &epoch_2_key, 2, &device_id),
        );
        registry_relay.advance_active_devices_after_artifact_fetch(2, 3);

        let mut epoch_key_hashes = std::collections::BTreeMap::new();
        epoch_key_hashes.insert(0, compute_epoch_key_hash(&epoch_0_key));
        epoch_key_hashes.insert(1, compute_epoch_key_hash(&epoch_1_key));
        epoch_key_hashes.insert(2, compute_epoch_key_hash(&epoch_2_key));
        let registry_snapshot = SignedRegistrySnapshot::new_with_epoch_binding(
            vec![RegistrySnapshotEntry {
                sync_id: sync_id.to_string(),
                device_id: device_id.clone(),
                ed25519_public_key: inviter_signing_key.public_key_bytes().to_vec(),
                x25519_public_key: inviter_exchange_key.public_key_bytes().to_vec(),
                ml_dsa_65_public_key: inviter_pq_signing_key.public_key_bytes(),
                ml_kem_768_public_key: inviter_pq_kem_key.public_key_bytes(),
                x_wing_public_key: inviter_xwing_key.encapsulation_key_bytes(),
                status: "active".to_string(),
                ml_dsa_key_generation: current_generation,
                remote_wipe: false,
            }],
            SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING,
            2,
            epoch_key_hashes,
        );
        registry_relay.set_signed_registry(SignedRegistryResponse {
            registry_version: SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING,
            artifact_blob: registry_snapshot
                .sign_hybrid(&inviter_signing_key, &inviter_pq_signing_key),
            artifact_kind: "signed_registry_snapshot".to_string(),
        });

        let initiator_store = Arc::new(MemStore::default());
        seed_bootstrap_store(
            &initiator_store,
            &device_secret,
            &device_id,
            sync_id,
            relay_url,
            &wrapped_dek,
            &salt,
        );
        let initiator_service = PairingService::new(initiator_store.clone());

        let joiner_store = Arc::new(MemStore::default());
        let joiner_service = PairingService::new(joiner_store.clone());
        let joiner_service_task = PairingService::new(joiner_store);
        let mailbox = Arc::new(MockPairingRelay::new());

        let (mut joiner, token) =
            joiner_service.start_bootstrap_pairing(mailbox.as_ref(), relay_url).await.unwrap();
        let (initiator, initiator_sas) =
            initiator_service.start_bootstrap_initiator(token, mailbox.as_ref()).await.unwrap();

        let joiner_rendezvous_id = joiner.rendezvous_id_hex();
        let init_bytes =
            wait_for_slot(mailbox.as_ref(), &joiner_rendezvous_id, PairingSlot::Init).await;
        let joiner_sas = joiner.process_pairing_init(&init_bytes).unwrap();
        assert_eq!(joiner_sas.words, initiator_sas.words);
        assert_eq!(joiner_sas.word_list, initiator_sas.word_list);

        let joiner_mailbox = mailbox.clone();
        let joiner_relay = registry_relay.clone();
        let joiner_handle = tokio::spawn(async move {
            joiner_service_task
                .complete_bootstrap_join(
                    &joiner,
                    joiner_mailbox.as_ref(),
                    &[],
                    password,
                    |_sync_id, _device_id, _token| Ok(joiner_relay as Arc<dyn SyncRelay>),
                )
                .await
                .unwrap()
        });

        let initiator_storage =
            initiator_storage_with_self(sync_id, &device_secret, &device_id, current_generation);
        let err = initiator_service
            .complete_bootstrap_initiator(
                &initiator,
                mailbox.as_ref(),
                password,
                &mnemonic,
                registry_relay.as_ref(),
                initiator_storage.as_ref(),
            )
            .await
            .unwrap_err();
        let _ = joiner_handle.await.unwrap();

        assert!(err.to_string().contains("stale rekey epoch 3"), "unexpected error: {err}");
        assert!(initiator_store.get("epoch_key_1").unwrap().is_some());
        assert!(initiator_store.get("epoch_key_2").unwrap().is_some());
        assert!(initiator_store.get("epoch_key_3").unwrap().is_none());
        assert_eq!(initiator_store.get("epoch").unwrap().unwrap(), b"2");
        assert!(registry_relay.state.lock().unwrap().rekey_posts.is_none());
    }

    #[tokio::test]
    async fn bootstrap_join_fetches_credentials_when_bytes_not_supplied() {
        let password = "bootstrap-password";
        let relay_url = "https://relay.example.com";
        let sync_id = "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3";

        let device_secret = DeviceSecret::generate();
        let device_id = crate::node_id::generate_node_id();
        let mnemonic = mnemonic::generate();
        let secret_key = mnemonic::to_bytes(&mnemonic).unwrap();
        let mut key_hierarchy = KeyHierarchy::new();
        let (wrapped_dek, salt) = key_hierarchy.initialize(password, &secret_key).unwrap();

        let inviter_signing_key = device_secret.ed25519_keypair(&device_id).unwrap();
        let inviter_exchange_key = device_secret.x25519_keypair(&device_id).unwrap();
        // Real inviter identity keys: the inviter is a recipient of the
        // post-pairing rekey wrap, so its relay-advertised X-Wing key must match
        // the key the initiator authors into the signed snapshot (now enforced by
        // byte-for-byte key-equality).
        let inviter_pq_signing_key = device_secret.ml_dsa_65_keypair(&device_id).unwrap();
        let inviter_pq_kem_key = device_secret.ml_kem_768_keypair(&device_id).unwrap();
        let inviter_xwing_key = device_secret.xwing_keypair(&device_id).unwrap();
        let registry_relay = Arc::new(BootstrapRegistryRelay::new(vec![DeviceInfo {
            device_id: device_id.clone(),
            epoch: 0,
            status: "active".to_string(),
            ed25519_public_key: inviter_signing_key.public_key_bytes().to_vec(),
            x25519_public_key: inviter_exchange_key.public_key_bytes().to_vec(),
            ml_dsa_65_public_key: inviter_pq_signing_key.public_key_bytes(),
            ml_kem_768_public_key: inviter_pq_kem_key.public_key_bytes(),
            x_wing_public_key: inviter_xwing_key.encapsulation_key_bytes(),
            permission: None,
            ml_dsa_key_generation: 0,
            needs_rekey: false,
        }]));

        let initiator_store = Arc::new(MemStore::default());
        seed_bootstrap_store(
            &initiator_store,
            &device_secret,
            &device_id,
            sync_id,
            relay_url,
            &wrapped_dek,
            &salt,
        );
        let initiator_service = PairingService::new(initiator_store);
        let joiner_store = Arc::new(MemStore::default());
        let joiner_service = PairingService::new(joiner_store.clone());
        let joiner_service_task = PairingService::new(joiner_store.clone());
        let mailbox = Arc::new(MockPairingRelay::new());

        let (mut joiner, token) =
            joiner_service.start_bootstrap_pairing(mailbox.as_ref(), relay_url).await.unwrap();
        let (initiator, initiator_sas) =
            initiator_service.start_bootstrap_initiator(token, mailbox.as_ref()).await.unwrap();

        let init_bytes =
            wait_for_slot(mailbox.as_ref(), &joiner.rendezvous_id_hex(), PairingSlot::Init).await;
        let joiner_sas = joiner.process_pairing_init(&init_bytes).unwrap();
        assert_eq!(joiner_sas.words, initiator_sas.words);

        let joiner_mailbox = mailbox.clone();
        let joiner_relay = registry_relay.clone();
        let joiner_handle = tokio::spawn(async move {
            joiner_service_task
                .complete_bootstrap_join(
                    &joiner,
                    joiner_mailbox.as_ref(),
                    &[],
                    password,
                    |sync_id, device_id, _token| {
                        assert_eq!(
                            sync_id.len(),
                            64,
                            "relay-builder must receive real 64-hex sync_id, got: {sync_id}"
                        );
                        assert!(
                            sync_id.chars().all(|c| c.is_ascii_hexdigit()),
                            "sync_id must be hex"
                        );
                        assert!(!device_id.is_empty(), "device_id must not be empty");
                        Ok(joiner_relay as Arc<dyn SyncRelay>)
                    },
                )
                .await
                .unwrap()
        });

        let initiator_storage =
            initiator_storage_with_self(sync_id, &device_secret, &device_id, 0);
        initiator_service
            .complete_bootstrap_initiator(
                &initiator,
                mailbox.as_ref(),
                password,
                &mnemonic,
                registry_relay.as_ref(),
                initiator_storage.as_ref(),
            )
            .await
            .unwrap();

        let (joiner_key_hierarchy, _) = joiner_handle.await.unwrap();
        assert!(joiner_key_hierarchy.is_unlocked());
    }

    #[tokio::test]
    async fn create_sync_group_returns_credentials_and_invite() {
        let store = Arc::new(MemStore::default());
        let service = PairingService::new(store.clone());

        let (creds, response) = service
            .create_sync_group(
                "test-password",
                "wss://relay.example.com",
                None,
                None,
                None,
                None,
                None,
                mock_relay_builder(),
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
        let store = Arc::new(MemStore::default());
        let service = PairingService::new(store.clone());
        let pending_secret = DeviceSecret::generate();
        let pending_device_id = "abc123def456";
        store.set("pending_device_secret", pending_secret.as_bytes()).unwrap();
        store.set("pending_device_id", pending_device_id.as_bytes()).unwrap();

        let (_creds, _response) = service
            .create_sync_group(
                "test-password",
                "wss://relay.example.com",
                None,
                None,
                None,
                None,
                None,
                mock_relay_builder(),
            )
            .await
            .unwrap();

        // Device secret and device id should be persisted
        let device_secret = store.get("device_secret").unwrap();
        assert!(device_secret.is_some());
        assert_eq!(device_secret.unwrap(), pending_secret.as_bytes());

        let device_id = store.get("device_id").unwrap();
        assert!(device_id.is_some());
        let device_id_str = String::from_utf8(device_id.unwrap()).unwrap();
        assert_eq!(device_id_str, pending_device_id);
        assert!(store.get("pending_device_secret").unwrap().is_none());
        assert!(store.get("pending_device_id").unwrap().is_none());
    }

    #[tokio::test]
    async fn create_with_custom_mnemonic() {
        let store = Arc::new(MemStore::default());
        let service = PairingService::new(store);

        let custom = mnemonic::generate();
        let (creds, _invite) = service
            .create_sync_group(
                "pw",
                "wss://relay.example.com",
                Some(custom.as_str()),
                None,
                None,
                None,
                None,
                mock_relay_builder(),
            )
            .await
            .unwrap();

        assert_eq!(creds.mnemonic, custom);
    }

    #[tokio::test]
    async fn invitation_sign_and_verify_roundtrip() {
        let store = Arc::new(MemStore::default());
        let service = PairingService::new(store);

        let (_creds, resp) = service
            .create_sync_group(
                "test-pw",
                "wss://relay.example.com",
                None,
                None,
                None,
                None,
                None,
                mock_relay_builder(),
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
        assert!(err.to_string().contains("below required floor"));
    }

    #[test]
    fn min_signature_version_omitted_relay_floor_ratchets_to_source_floor() {
        let store = Arc::new(MemStore::default());
        let service = PairingService::new(store.clone());

        service.ratchet_min_signature_version(None).unwrap();

        assert_eq!(
            String::from_utf8(store.get(MIN_SIGNATURE_VERSION_FLOOR_KEY).unwrap().unwrap())
                .unwrap(),
            SIGNATURE_VERSION_SOURCE_FLOOR.to_string()
        );
    }

    #[test]
    fn min_signature_version_omitted_relay_floor_does_not_lower_stored_floor() {
        let store = Arc::new(MemStore::default());
        store.set(MIN_SIGNATURE_VERSION_FLOOR_KEY, b"4").unwrap();
        let service = PairingService::new(store.clone());

        service.ratchet_min_signature_version(None).unwrap();

        assert_eq!(
            String::from_utf8(store.get(MIN_SIGNATURE_VERSION_FLOOR_KEY).unwrap().unwrap())
                .unwrap(),
            "4"
        );
    }

    #[tokio::test]
    async fn tampered_invitation_rejected() {
        // This test verified that join_sync_group rejected tampered invitations.
        // Since join_sync_group was removed (replaced by the ceremony-based flow),
        // we verify the underlying verification helper directly.
        let store = Arc::new(MemStore::default());
        let service = PairingService::new(store);

        let (_creds, response) = service
            .create_sync_group(
                "test-pw",
                "wss://relay.example.com",
                None,
                None,
                None,
                None,
                None,
                mock_relay_builder(),
            )
            .await
            .unwrap();

        // Tamper with the sync_id in the response
        let mut tampered = response.clone();
        tampered.sync_id = "tampered-sync-id".into();

        let inviter_pk: [u8; 32] = tampered.inviter_ed25519_pk.clone().try_into().unwrap();
        let sig_bytes = prism_sync_crypto::hex::decode(&tampered.signed_invitation).unwrap();
        let signing_data = build_invitation_signing_data_v2(
            &tampered.sync_id,
            &tampered.relay_url,
            &tampered.wrapped_dek,
            &tampered.salt,
            &tampered.inviter_device_id,
            &inviter_pk,
            &tampered.inviter_ml_dsa_65_pk,
            tampered.joiner_device_id.as_deref(),
            tampered.current_epoch,
            &tampered.epoch_key,
        );
        let result = verify_hybrid_invitation(
            &signing_data,
            &sig_bytes,
            &inviter_pk,
            &tampered.inviter_ml_dsa_65_pk,
        );
        let err_msg = match result {
            Err(e) => format!("{e}"),
            Ok(_) => panic!("expected error for tampered invitation"),
        };
        assert!(err_msg.contains("signature invalid"), "expected signature error, got: {err_msg}");
    }

    #[tokio::test]
    async fn wrong_inviter_key_rejected() {
        let store = Arc::new(MemStore::default());
        let service = PairingService::new(store);

        let (_creds, response) = service
            .create_sync_group(
                "test-pw",
                "wss://relay.example.com",
                None,
                None,
                None,
                None,
                None,
                mock_relay_builder(),
            )
            .await
            .unwrap();

        // Replace the inviter's public key with a different key
        let mut tampered = response.clone();
        let fake_secret = DeviceSecret::generate();
        let fake_key = fake_secret.ed25519_keypair("fake").unwrap();
        tampered.inviter_ed25519_pk = fake_key.public_key_bytes().to_vec();

        let inviter_pk: [u8; 32] = tampered.inviter_ed25519_pk.clone().try_into().unwrap();
        let sig_bytes = prism_sync_crypto::hex::decode(&tampered.signed_invitation).unwrap();
        let signing_data = build_invitation_signing_data_v2(
            &tampered.sync_id,
            &tampered.relay_url,
            &tampered.wrapped_dek,
            &tampered.salt,
            &tampered.inviter_device_id,
            &inviter_pk,
            &tampered.inviter_ml_dsa_65_pk,
            tampered.joiner_device_id.as_deref(),
            tampered.current_epoch,
            &tampered.epoch_key,
        );
        let result = verify_hybrid_invitation(
            &signing_data,
            &sig_bytes,
            &inviter_pk,
            &tampered.inviter_ml_dsa_65_pk,
        );
        let err_msg = match result {
            Err(e) => format!("{e}"),
            Ok(_) => panic!("expected error for wrong inviter key"),
        };
        assert!(err_msg.contains("signature invalid"), "expected signature error, got: {err_msg}");
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
        impl SyncTransport for CapturingRelay {
            async fn pull_changes(&self, _: i64) -> std::result::Result<PullResponse, RelayError> {
                unimplemented!()
            }
            async fn push_changes(&self, _: OutgoingBatch) -> std::result::Result<i64, RelayError> {
                unimplemented!()
            }
            async fn ack(&self, _: i64) -> std::result::Result<(), RelayError> {
                unimplemented!()
            }
        }
        #[async_trait]
        impl DeviceRegistry for CapturingRelay {
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
            async fn list_devices(&self) -> std::result::Result<Vec<DeviceInfo>, RelayError> {
                unimplemented!()
            }
            async fn revoke_device(
                &self,
                _: &str,
                _: bool,
                _: i32,
                _: HashMap<String, Vec<u8>>,
                _: Option<&[u8]>,
            ) -> std::result::Result<i32, RelayError> {
                unimplemented!()
            }
            async fn deregister(&self) -> std::result::Result<(), RelayError> {
                unimplemented!()
            }
            async fn rotate_ml_dsa(
                &self,
                _: &str,
                _: &[u8],
                _: u32,
                _: &prism_sync_crypto::pq::continuity_proof::MlDsaContinuityProof,
                _: Option<&[u8]>,
            ) -> std::result::Result<RotateMlDsaResponse, RelayError> {
                unimplemented!()
            }
            async fn get_signed_registry(
                &self,
            ) -> std::result::Result<Option<SignedRegistryResponse>, RelayError> {
                Ok(None)
            }
            async fn put_signed_registry(&self, _: &[u8]) -> std::result::Result<i64, RelayError> {
                Ok(0)
            }
        }
        #[async_trait]
        impl EpochManagement for CapturingRelay {
            async fn post_rekey_artifacts(
                &self,
                _: i32,
                _: HashMap<String, Vec<u8>>,
                _: Option<&[u8]>,
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
        }
        #[async_trait]
        impl SnapshotExchange for CapturingRelay {
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
                _: Option<crate::relay::traits::SnapshotUploadProgress>,
            ) -> std::result::Result<(), RelayError> {
                unimplemented!()
            }
            async fn delete_snapshot(&self) -> std::result::Result<(), RelayError> {
                unimplemented!()
            }
        }
        #[async_trait]
        impl MediaRelay for CapturingRelay {
            async fn upload_media(
                &self,
                _: &str,
                _: &str,
                _: Vec<u8>,
                _: Option<u64>,
            ) -> std::result::Result<MediaUploadOutcome, RelayError> {
                unimplemented!()
            }
            async fn download_media(&self, _: &str) -> std::result::Result<Vec<u8>, RelayError> {
                unimplemented!()
            }
            async fn batch_exists(
                &self,
                _: &[String],
            ) -> std::result::Result<Vec<String>, RelayError> {
                unimplemented!()
            }
            async fn send_ephemeral(
                &self,
                _: &crate::ephemeral::EphemeralEnvelope,
            ) -> std::result::Result<(), RelayError> {
                unimplemented!()
            }
            async fn fetch_pending_ephemeral(
                &self,
            ) -> std::result::Result<Vec<crate::ephemeral::EphemeralEnvelope>, RelayError> {
                unimplemented!()
            }
            async fn ack_ephemeral(
                &self,
                _: &[String],
            ) -> std::result::Result<(), RelayError> {
                unimplemented!()
            }
        }
        #[async_trait]
        impl SyncRelay for CapturingRelay {
            async fn delete_sync_group(&self) -> std::result::Result<(), RelayError> {
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
            async fn dispose(&self) -> std::result::Result<(), RelayError> {
                unimplemented!()
            }
        }

        let relay = Arc::new(CapturingRelay { captured_req: StdMutex::new(None) });
        let store = Arc::new(MemStore::default());
        let service = PairingService::new(store);

        let relay_clone = relay.clone();
        let (_creds, _invite) = service
            .create_sync_group(
                "pw",
                "wss://relay.example.com",
                None,
                None,
                None,
                None,
                None,
                |_sync_id, _device_id, _token| Ok(relay_clone as Arc<dyn SyncRelay>),
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

    // Tests for `join_sync_group` (legacy pre-ceremony flow) were removed
    // along with the method. The ceremony-based flow is tested by
    // `bootstrap_pairing_round_trip_and_rekey` and
    // `bootstrap_join_fetches_credentials_when_bytes_not_supplied`.
    // External integration tests in `tests/consumer_api.rs` and
    // `tests/pairing_failures.rs` also exercise the legacy flow for
    // backwards compatibility and are kept intact.

    #[test]
    fn next_pairing_registry_version_advances_relay_version() {
        assert_eq!(next_pairing_registry_version(Some(4)), 5);
    }

    #[test]
    fn next_pairing_registry_version_uses_floor_without_registry() {
        assert_eq!(
            next_pairing_registry_version(None),
            SIGNED_REGISTRY_VERSION_MIN_WITH_EPOCH_BINDING
        );
    }

    /// Unit test for the helper itself: post-revoke / post-rekey flows
    /// persist `epoch_key_{N}` to the secure store, but a freshly-unlocked
    /// `KeyHierarchy` only has epoch 0. The helper must restore each
    /// persisted epoch key into the hierarchy so downstream consumers
    /// (`build_epoch_key_hashes`, etc.) see the full set.
    #[test]
    fn restore_persisted_epoch_keys_loads_secure_store_entries() {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let store = Arc::new(MemStore::default());
        // Mix base64 and raw to exercise the tolerant decode (the bootstrap
        // path writes base64; sync_service.rs historically wrote raw).
        let key1 = [0xAAu8; 32];
        let key2 = [0xBBu8; 32];
        let key3 = [0xCCu8; 32];
        store.set("epoch_key_1", STANDARD.encode(key1).as_bytes()).unwrap();
        store.set("epoch_key_2", &key2).unwrap();
        store.set("epoch_key_3", STANDARD.encode(key3).as_bytes()).unwrap();

        let service = PairingService::new(store.clone());
        let mut hierarchy = KeyHierarchy::new();
        // Unlock so epoch 0 is present and the hierarchy accepts writes.
        let mnemonic = mnemonic::generate();
        let secret_key = mnemonic::to_bytes(&mnemonic).unwrap();
        hierarchy.initialize("pw", &secret_key).unwrap();

        service.restore_persisted_epoch_keys(&mut hierarchy, 3).unwrap();

        let restored: std::collections::BTreeMap<u32, [u8; 32]> = hierarchy
            .epoch_keys_iter()
            .unwrap()
            .into_iter()
            .map(|(epoch, key)| (epoch, *key))
            .collect();
        // Expect epoch 0 (from initialize) plus 1/2/3 from secure store.
        assert!(restored.contains_key(&0));
        assert_eq!(restored.get(&1), Some(&key1));
        assert_eq!(restored.get(&2), Some(&key2));
        assert_eq!(restored.get(&3), Some(&key3));
    }

    /// Regression test for the silent post-revoke pairing failure: the
    /// inviter's `complete_bootstrap_initiator` used to build a fresh
    /// `KeyHierarchy` containing only epoch 0, then sign a snapshot with
    /// `current_epoch` taken from the secure store (e.g. 1 after a
    /// `revoke_and_rekey`). The resulting bundle's `epoch_key_hashes` map
    /// only had an entry for epoch 0, so the joiner rejected it with
    /// "registry epoch_key_hashes missing entry for current_epoch 1".
    ///
    /// Mirrors `bootstrap_pairing_round_trip_and_rekey` but seeds the
    /// initiator at epoch=1 with a persisted `epoch_key_1`, simulating
    /// the state after a successful `revoke_and_rekey`.
    #[tokio::test]
    async fn bootstrap_initiator_includes_post_revoke_epoch_in_snapshot() {
        let password = "bootstrap-password";
        let relay_url = "https://relay.example.com";
        let sync_id = "f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1";

        let device_secret = DeviceSecret::generate();
        let device_id = crate::node_id::generate_node_id();
        let current_generation = 5;
        let mnemonic = mnemonic::generate();
        let secret_key = mnemonic::to_bytes(&mnemonic).unwrap();
        let mut key_hierarchy = KeyHierarchy::new();
        let (wrapped_dek, salt) = key_hierarchy.initialize(password, &secret_key).unwrap();

        let inviter_signing_key = device_secret.ed25519_keypair(&device_id).unwrap();
        let inviter_exchange_key = device_secret.x25519_keypair(&device_id).unwrap();
        let inviter_pq_signing_key =
            device_secret.ml_dsa_65_keypair_v(&device_id, current_generation).unwrap();
        let inviter_pq_kem_key = device_secret.ml_kem_768_keypair(&device_id).unwrap();
        let inviter_xwing_key = device_secret.xwing_keypair(&device_id).unwrap();

        // Relay reports the inviter at epoch 1 (matches local) — no
        // catch-up branch will run, so the bug fires if it's still there.
        let inviter_info = DeviceInfo {
            device_id: device_id.clone(),
            epoch: 1,
            status: "active".to_string(),
            ed25519_public_key: inviter_signing_key.public_key_bytes().to_vec(),
            x25519_public_key: inviter_exchange_key.public_key_bytes().to_vec(),
            ml_dsa_65_public_key: inviter_pq_signing_key.public_key_bytes(),
            ml_kem_768_public_key: inviter_pq_kem_key.public_key_bytes(),
            x_wing_public_key: inviter_xwing_key.encapsulation_key_bytes(),
            permission: None,
            ml_dsa_key_generation: current_generation,
            needs_rekey: false,
        };
        let registry_relay = Arc::new(BootstrapRegistryRelay::new(vec![inviter_info.clone()]));

        // Seed initiator store at epoch=1 with persisted epoch_key_1, the
        // shape `revoke_and_rekey` leaves behind.
        let initiator_store = Arc::new(MemStore::default());
        seed_bootstrap_store(
            &initiator_store,
            &device_secret,
            &device_id,
            sync_id,
            relay_url,
            &wrapped_dek,
            &salt,
        );
        initiator_store.set("epoch", b"1").unwrap();
        let epoch_1_key = [0x77u8; 32];
        {
            use base64::{engine::general_purpose::STANDARD, Engine};
            initiator_store.set("epoch_key_1", STANDARD.encode(epoch_1_key).as_bytes()).unwrap();
        }
        initiator_store.set("registration_token", b"relay-registration-token").unwrap();
        let mut current_epoch_hashes = build_epoch_key_hashes(&key_hierarchy).unwrap();
        current_epoch_hashes.insert(1, compute_epoch_key_hash(&epoch_1_key));
        let current_registry = SignedRegistrySnapshot::new_with_epoch_binding(
            vec![RegistrySnapshotEntry {
                sync_id: sync_id.to_string(),
                device_id: inviter_info.device_id.clone(),
                ed25519_public_key: inviter_info.ed25519_public_key.clone(),
                x25519_public_key: inviter_info.x25519_public_key.clone(),
                ml_dsa_65_public_key: inviter_info.ml_dsa_65_public_key.clone(),
                ml_kem_768_public_key: inviter_info.ml_kem_768_public_key.clone(),
                x_wing_public_key: inviter_info.x_wing_public_key.clone(),
                status: inviter_info.status.clone(),
                ml_dsa_key_generation: inviter_info.ml_dsa_key_generation,
                remote_wipe: false,
            }],
            4,
            1,
            current_epoch_hashes,
        );
        registry_relay.set_signed_registry(SignedRegistryResponse {
            registry_version: 4,
            artifact_blob: current_registry
                .sign_hybrid(&inviter_signing_key, &inviter_pq_signing_key),
            artifact_kind: "signed_registry_snapshot".to_string(),
        });
        let initiator_service = PairingService::new(initiator_store.clone());

        let joiner_store = Arc::new(MemStore::default());
        let joiner_service = PairingService::new(joiner_store.clone());
        let joiner_service_task = PairingService::new(joiner_store.clone());

        let mailbox = Arc::new(MockPairingRelay::new());

        let (mut joiner, token) =
            joiner_service.start_bootstrap_pairing(mailbox.as_ref(), relay_url).await.unwrap();
        let (initiator, initiator_sas) =
            initiator_service.start_bootstrap_initiator(token, mailbox.as_ref()).await.unwrap();

        let joiner_rendezvous_id = joiner.rendezvous_id_hex();
        let init_bytes =
            wait_for_slot(mailbox.as_ref(), &joiner_rendezvous_id, PairingSlot::Init).await;
        let joiner_sas = joiner.process_pairing_init(&init_bytes).unwrap();
        assert_eq!(joiner_sas.words, initiator_sas.words);

        let joiner_mailbox = mailbox.clone();
        let joiner_relay = registry_relay.clone();
        let joiner_handle = tokio::spawn(async move {
            joiner_service_task
                .complete_bootstrap_join(
                    &joiner,
                    joiner_mailbox.as_ref(),
                    &[],
                    password,
                    |_sync_id, _device_id, _token| Ok(joiner_relay as Arc<dyn SyncRelay>),
                )
                .await
                .unwrap()
        });

        let initiator_storage =
            initiator_storage_with_self(sync_id, &device_secret, &device_id, current_generation);
        initiator_service
            .complete_bootstrap_initiator(
                &initiator,
                mailbox.as_ref(),
                password,
                &mnemonic,
                registry_relay.as_ref(),
                initiator_storage.as_ref(),
            )
            .await
            .expect("post-revoke initiator must produce a valid bundle");

        // The joiner accepts the bundle iff the inviter's snapshot
        // includes `epoch_key_hashes[current_epoch]`. Pre-fix, this would
        // have panicked with "registry epoch_key_hashes missing entry for
        // current_epoch 1".
        let (_joiner_key_hierarchy, joiner_snapshot) = joiner_handle.await.unwrap();
        assert_eq!(
            joiner_snapshot.registry_version, 5,
            "pairing a new device must advance the signed registry version"
        );
        // Bundle's current_epoch reflects the post-rekey advance (initiator
        // bumps to next_epoch after registering the joiner).
        assert!(joiner_snapshot.current_epoch >= 1);
        assert!(
            joiner_snapshot.epoch_key_hashes.contains_key(&joiner_snapshot.current_epoch),
            "joiner snapshot missing epoch_key_hash for its own current_epoch {}",
            joiner_snapshot.current_epoch
        );
        // The pre-revoke epoch (1) must also be retained in the hash map
        // — the inviter committed to BOTH epoch 0 and epoch 1, even though
        // only epoch 1 is "current".
        assert!(
            joiner_snapshot.epoch_key_hashes.contains_key(&1),
            "joiner snapshot missing epoch_key_hash for the pre-rekey epoch 1"
        );
        assert_eq!(
            joiner_snapshot.epoch_key_hashes.get(&1),
            Some(&compute_epoch_key_hash(&epoch_1_key)),
            "epoch_key_hash for epoch 1 must hash the persisted post-revoke key"
        );
    }

    /// Helper coverage: a registry-verified set of history keys is persisted
    /// to the secure store and stored in the hierarchy; epoch 0 and the current
    /// epoch are skipped (handled elsewhere).
    #[test]
    fn install_bundle_epoch_keys_persists_verified_history() {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let store = MemStore::default();
        let mut hierarchy = KeyHierarchy::new();
        let mnemonic = mnemonic::generate();
        let secret_key = mnemonic::to_bytes(&mnemonic).unwrap();
        hierarchy.initialize("pw", &secret_key).unwrap();

        let key1 = vec![0xA1u8; 32];
        let key2 = vec![0xA2u8; 32];
        let key3 = vec![0xA3u8; 32];
        let mut hashes = std::collections::BTreeMap::new();
        hashes.insert(0, compute_epoch_key_hash(hierarchy.epoch_key(0).unwrap().try_into().unwrap()));
        hashes.insert(1, compute_epoch_key_hash(&[0xA1u8; 32]));
        hashes.insert(2, compute_epoch_key_hash(&[0xA2u8; 32]));
        hashes.insert(3, compute_epoch_key_hash(&[0xA3u8; 32]));
        let snapshot =
            SignedRegistrySnapshot::new_with_epoch_binding(Vec::new(), 1, 3, hashes);

        let bundle_keys = std::collections::BTreeMap::from([
            (1u32, key1.clone()),
            (2u32, key2.clone()),
            (3u32, key3.clone()),
        ]);
        // current_epoch == 3 is handled by the single-key block, so only 1 and 2
        // should be installed here.
        install_bundle_epoch_keys(&store, &mut hierarchy, &bundle_keys, 3, &snapshot).unwrap();

        for (epoch, key) in [(1u32, &key1), (2u32, &key2)] {
            let stored = store.get(&format!("epoch_key_{epoch}")).unwrap().unwrap();
            assert_eq!(STANDARD.decode(stored).unwrap(), *key);
            assert_eq!(hierarchy.epoch_key(epoch).unwrap(), key.as_slice());
        }
        assert!(
            store.get("epoch_key_3").unwrap().is_none(),
            "current_epoch key must be skipped here (single-key block owns it)"
        );
    }

    /// Fail-closed: a history key whose hash does not match the signed
    /// registry aborts and persists nothing for that epoch.
    #[test]
    fn install_bundle_epoch_keys_rejects_hash_mismatch_fail_closed() {
        let store = MemStore::default();
        let mut hierarchy = KeyHierarchy::new();
        let mnemonic = mnemonic::generate();
        let secret_key = mnemonic::to_bytes(&mnemonic).unwrap();
        hierarchy.initialize("pw", &secret_key).unwrap();

        let good = vec![0xB1u8; 32];
        let tampered = vec![0xFFu8; 32];
        let mut hashes = std::collections::BTreeMap::new();
        // Registry commits to the GOOD key for epoch 1.
        hashes.insert(1, compute_epoch_key_hash(&[0xB1u8; 32]));
        let snapshot =
            SignedRegistrySnapshot::new_with_epoch_binding(Vec::new(), 1, 2, hashes);

        // Bundle ships the tampered key.
        let bundle_keys = std::collections::BTreeMap::from([(1u32, tampered)]);
        let err =
            install_bundle_epoch_keys(&store, &mut hierarchy, &bundle_keys, 2, &snapshot).unwrap_err();
        assert!(
            matches!(err, CoreError::EpochKeyMismatch { epoch: 1, .. }),
            "expected epoch-1 mismatch, got {err:?}"
        );
        assert!(
            store.get("epoch_key_1").unwrap().is_none(),
            "nothing must be persisted for the rejected epoch"
        );
        assert!(!hierarchy.has_epoch_key(1), "rejected key must not enter the hierarchy");
        // Sanity: the good key would have verified.
        let _ = good;
    }

    /// End-to-end: an initiator at epoch 3 holding keys 1..3 ships a bundle
    /// whose `epoch_keys` is {1,2,3}; the joiner installs and persists all of
    /// them after hash verification against the bundle's signed registry.
    #[tokio::test]
    async fn bootstrap_carries_full_epoch_key_history() {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let password = "bootstrap-password";
        let relay_url = "https://relay.example.com";
        let sync_id = "f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2";

        let device_secret = DeviceSecret::generate();
        let device_id = crate::node_id::generate_node_id();
        let current_generation = 5;
        let mnemonic = mnemonic::generate();
        let secret_key = mnemonic::to_bytes(&mnemonic).unwrap();
        let mut key_hierarchy = KeyHierarchy::new();
        let (wrapped_dek, salt) = key_hierarchy.initialize(password, &secret_key).unwrap();

        let inviter_signing_key = device_secret.ed25519_keypair(&device_id).unwrap();
        let inviter_exchange_key = device_secret.x25519_keypair(&device_id).unwrap();
        let inviter_pq_signing_key =
            device_secret.ml_dsa_65_keypair_v(&device_id, current_generation).unwrap();
        let inviter_pq_kem_key = device_secret.ml_kem_768_keypair(&device_id).unwrap();
        let inviter_xwing_key = device_secret.xwing_keypair(&device_id).unwrap();

        // Relay reports the inviter at epoch 3 (matches local) — no catch-up.
        let inviter_info = DeviceInfo {
            device_id: device_id.clone(),
            epoch: 3,
            status: "active".to_string(),
            ed25519_public_key: inviter_signing_key.public_key_bytes().to_vec(),
            x25519_public_key: inviter_exchange_key.public_key_bytes().to_vec(),
            ml_dsa_65_public_key: inviter_pq_signing_key.public_key_bytes(),
            ml_kem_768_public_key: inviter_pq_kem_key.public_key_bytes(),
            x_wing_public_key: inviter_xwing_key.encapsulation_key_bytes(),
            permission: None,
            ml_dsa_key_generation: current_generation,
            needs_rekey: false,
        };
        let registry_relay = Arc::new(BootstrapRegistryRelay::new(vec![inviter_info.clone()]));

        // Seed the initiator at epoch 3 with persisted epoch_key_1..3, the shape
        // three successive rekeys leave behind.
        let initiator_store = Arc::new(MemStore::default());
        seed_bootstrap_store(
            &initiator_store,
            &device_secret,
            &device_id,
            sync_id,
            relay_url,
            &wrapped_dek,
            &salt,
        );
        initiator_store.set("epoch", b"3").unwrap();
        let epoch_1_key = [0x71u8; 32];
        let epoch_2_key = [0x72u8; 32];
        let epoch_3_key = [0x73u8; 32];
        initiator_store
            .set("epoch_key_1", STANDARD.encode(epoch_1_key).as_bytes())
            .unwrap();
        initiator_store
            .set("epoch_key_2", STANDARD.encode(epoch_2_key).as_bytes())
            .unwrap();
        initiator_store
            .set("epoch_key_3", STANDARD.encode(epoch_3_key).as_bytes())
            .unwrap();
        initiator_store.set("registration_token", b"relay-registration-token").unwrap();

        let mut current_epoch_hashes = build_epoch_key_hashes(&key_hierarchy).unwrap();
        current_epoch_hashes.insert(1, compute_epoch_key_hash(&epoch_1_key));
        current_epoch_hashes.insert(2, compute_epoch_key_hash(&epoch_2_key));
        current_epoch_hashes.insert(3, compute_epoch_key_hash(&epoch_3_key));
        let current_registry = SignedRegistrySnapshot::new_with_epoch_binding(
            vec![RegistrySnapshotEntry {
                sync_id: sync_id.to_string(),
                device_id: inviter_info.device_id.clone(),
                ed25519_public_key: inviter_info.ed25519_public_key.clone(),
                x25519_public_key: inviter_info.x25519_public_key.clone(),
                ml_dsa_65_public_key: inviter_info.ml_dsa_65_public_key.clone(),
                ml_kem_768_public_key: inviter_info.ml_kem_768_public_key.clone(),
                x_wing_public_key: inviter_info.x_wing_public_key.clone(),
                status: inviter_info.status.clone(),
                ml_dsa_key_generation: inviter_info.ml_dsa_key_generation,
                remote_wipe: false,
            }],
            4,
            3,
            current_epoch_hashes,
        );
        registry_relay.set_signed_registry(SignedRegistryResponse {
            registry_version: 4,
            artifact_blob: current_registry
                .sign_hybrid(&inviter_signing_key, &inviter_pq_signing_key),
            artifact_kind: "signed_registry_snapshot".to_string(),
        });
        let initiator_service = PairingService::new(initiator_store.clone());

        let joiner_store = Arc::new(MemStore::default());
        let joiner_service = PairingService::new(joiner_store.clone());
        let joiner_service_task = PairingService::new(joiner_store.clone());

        let mailbox = Arc::new(MockPairingRelay::new());

        let (mut joiner, token) =
            joiner_service.start_bootstrap_pairing(mailbox.as_ref(), relay_url).await.unwrap();
        let (initiator, initiator_sas) =
            initiator_service.start_bootstrap_initiator(token, mailbox.as_ref()).await.unwrap();

        let joiner_rendezvous_id = joiner.rendezvous_id_hex();
        let init_bytes =
            wait_for_slot(mailbox.as_ref(), &joiner_rendezvous_id, PairingSlot::Init).await;
        let joiner_sas = joiner.process_pairing_init(&init_bytes).unwrap();
        assert_eq!(joiner_sas.words, initiator_sas.words);

        let joiner_mailbox = mailbox.clone();
        let joiner_relay = registry_relay.clone();
        let joiner_handle = tokio::spawn(async move {
            joiner_service_task
                .complete_bootstrap_join(
                    &joiner,
                    joiner_mailbox.as_ref(),
                    &[],
                    password,
                    |_sync_id, _device_id, _token| Ok(joiner_relay as Arc<dyn SyncRelay>),
                )
                .await
                .unwrap()
        });

        let initiator_storage =
            initiator_storage_with_self(sync_id, &device_secret, &device_id, current_generation);
        initiator_service
            .complete_bootstrap_initiator(
                &initiator,
                mailbox.as_ref(),
                password,
                &mnemonic,
                registry_relay.as_ref(),
                initiator_storage.as_ref(),
            )
            .await
            .expect("initiator at epoch 3 must produce a valid bundle");

        let (_joiner_key_hierarchy, _joiner_snapshot) = joiner_handle.await.unwrap();

        // The joiner persisted every epoch key the initiator held, each verified
        // against the bundle's signed registry before install.
        for (epoch, key) in
            [(1u32, epoch_1_key), (2u32, epoch_2_key), (3u32, epoch_3_key)]
        {
            let stored = joiner_store
                .get(&format!("epoch_key_{epoch}"))
                .unwrap()
                .unwrap_or_else(|| panic!("joiner missing epoch_key_{epoch}"));
            assert_eq!(
                STANDARD.decode(stored).unwrap(),
                key.to_vec(),
                "joiner persisted epoch_key_{epoch} does not match the initiator's key"
            );
        }
    }
}
