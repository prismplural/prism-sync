//! Recipient side of the PQ hybrid remote sharing bootstrap protocol.
//!
//! [`SharingRecipient`] drives the responder flow: manages prekey rotation,
//! processes incoming sharing-init messages, and derives the same pairwise
//! secret as the sender.

use prism_sync_crypto::pq::hybrid_kem::XWingKem;
use zeroize::{Zeroize, Zeroizing};

use super::confirmation::ConfirmationCode;
use super::encrypted_envelope::{EncryptedEnvelope, EnvelopeContext};
use super::handshake::DefaultBootstrapHandshake;
use super::key_schedule::BootstrapKeySchedule;
use super::prekey_store::PrekeyStore;
use super::sharing_identity::{
    derive_sharing_ed25519_keypair, derive_sharing_identity_seed, derive_sharing_ml_dsa_keypair,
};
use super::sharing_models::{SharingIdentityBundle, SharingInit, SharingInitPayload};
use super::sharing_transcript::build_sharing_transcript;
use super::{BootstrapProfile, BootstrapRole, BootstrapVersion};
use crate::error::{CoreError, Result};
use crate::relay::sharing_relay::SharingRelay;
use crate::secure_store::SecureStore;

// ---------------------------------------------------------------------------
// SharingRecipient
// ---------------------------------------------------------------------------

/// Drives the recipient (responder) side of the remote sharing bootstrap.
pub struct SharingRecipient {
    identity: SharingIdentityBundle,
    sharing_id: String,
    ed25519_sk: ed25519_dalek::SigningKey,
    ml_dsa_sk: ml_dsa::ExpandedSigningKey<ml_dsa::MlDsa65>,
    prekey_store: PrekeyStore,
}

/// Result of processing a sharing-init message.
#[derive(Debug)]
pub struct ProcessedSharingInit {
    /// The derived pairwise secret (32 bytes).
    pub pairwise_secret: Zeroizing<Vec<u8>>,
    /// The sender's identity bundle.
    pub sender_identity: SharingIdentityBundle,
    /// The sender's display name.
    pub display_name: String,
    /// The scopes offered by the sender.
    pub offered_scopes: Vec<String>,
    /// The unique init_id for this sharing-init.
    pub init_id: String,
}

impl SharingRecipient {
    /// Construct a `SharingRecipient` from DEK and sharing identity parameters.
    pub fn from_dek(
        dek: &[u8],
        sharing_id: &str,
        sharing_id_bytes: &[u8; 16],
        identity_generation: u32,
    ) -> Result<Self> {
        Self::from_dek_with_prekey_store(
            dek,
            sharing_id,
            sharing_id_bytes,
            identity_generation,
            PrekeyStore::new(),
        )
    }

    pub fn from_dek_with_prekey_store(
        dek: &[u8],
        sharing_id: &str,
        sharing_id_bytes: &[u8; 16],
        identity_generation: u32,
        prekey_store: PrekeyStore,
    ) -> Result<Self> {
        let seed = derive_sharing_identity_seed(dek, sharing_id_bytes, identity_generation)?;
        let mut seed_arr = [0u8; 32];
        seed_arr.copy_from_slice(&seed);

        let (ed25519_sk, ed25519_pk) = derive_sharing_ed25519_keypair(&seed_arr)?;
        let (ml_dsa_sk, ml_dsa_pk) = derive_sharing_ml_dsa_keypair(&seed_arr)?;
        seed_arr.zeroize();

        let identity = SharingIdentityBundle::sign(
            sharing_id.to_string(),
            identity_generation,
            ed25519_pk,
            ml_dsa_pk,
            &ed25519_sk,
            &ml_dsa_sk,
        );

        Ok(Self {
            identity,
            sharing_id: sharing_id.to_string(),
            ed25519_sk,
            ml_dsa_sk,
            prekey_store,
        })
    }

    pub fn load_from_secure_store(
        dek: &[u8],
        sharing_id: &str,
        sharing_id_bytes: &[u8; 16],
        identity_generation: u32,
        secure_store: &dyn SecureStore,
    ) -> Result<Self> {
        let prekey_store = PrekeyStore::load(secure_store)?;
        Self::from_dek_with_prekey_store(
            dek,
            sharing_id,
            sharing_id_bytes,
            identity_generation,
            prekey_store,
        )
    }

    /// The recipient's sharing identity bundle.
    pub fn identity(&self) -> &SharingIdentityBundle {
        &self.identity
    }

    /// The recipient's sharing_id.
    pub fn sharing_id(&self) -> &str {
        &self.sharing_id
    }

    /// Mutable access to the prekey store (for testing / direct manipulation).
    pub fn prekey_store(&self) -> &PrekeyStore {
        &self.prekey_store
    }

    /// Mutable access to the prekey store.
    pub fn prekey_store_mut(&mut self) -> &mut PrekeyStore {
        &mut self.prekey_store
    }

    pub fn save_prekey_store(&self, secure_store: &dyn SecureStore) -> Result<()> {
        self.prekey_store.save(secure_store)
    }

    /// Ensure the current prekey is fresh. If not, rotate and upload to relay.
    pub async fn ensure_prekey_fresh(
        &mut self,
        relay: &dyn SharingRelay,
        device_id: &str,
        now: i64,
    ) -> Result<()> {
        if self.prekey_store.needs_rotation(now) {
            let signed_prekey =
                self.prekey_store
                    .rotate(&self.ed25519_sk, &self.ml_dsa_sk, device_id, now)?;

            relay
                .publish_prekey(
                    &self.sharing_id,
                    device_id,
                    &signed_prekey.prekey_id,
                    &signed_prekey.to_bytes(),
                )
                .await
                .map_err(|e| CoreError::Engine(format!("failed to publish prekey: {e}")))?;
        }
        Ok(())
    }

    pub async fn ensure_prekey_fresh_and_persist(
        &mut self,
        relay: &dyn SharingRelay,
        secure_store: &dyn SecureStore,
        device_id: &str,
        now: i64,
    ) -> Result<()> {
        let needs_rotation = self.prekey_store.needs_rotation(now);
        self.ensure_prekey_fresh(relay, device_id, now).await?;
        if needs_rotation {
            self.prekey_store.save(secure_store)?;
        }
        Ok(())
    }

    /// Process an incoming sharing-init message.
    ///
    /// # Arguments
    ///
    /// * `sharing_init_bytes` — the raw bytes of the `SharingInit` wire format
    /// * `init_id` — the init_id from the relay (for replay checking)
    /// * `existing_relationship_sharing_ids` — sharing_ids of already-established relationships
    /// * `seen_init_ids` — previously processed init_ids (for replay detection)
    pub fn process_sharing_init(
        &self,
        sharing_init_bytes: &[u8],
        init_id: &str,
        existing_relationship_sharing_ids: &[&str],
        seen_init_ids: &[&str],
    ) -> Result<ProcessedSharingInit> {
        // 1. Replay check
        if seen_init_ids.contains(&init_id) {
            return Err(CoreError::Engine(format!(
                "replay detected: init_id {init_id} already processed"
            )));
        }

        // 2. Parse SharingInit
        let sharing_init = SharingInit::from_bytes(sharing_init_bytes)
            .ok_or_else(|| CoreError::Engine("failed to parse SharingInit".into()))?;

        // Verify init_id matches
        if sharing_init.init_id != init_id {
            return Err(CoreError::Engine(format!(
                "init_id mismatch: expected {init_id}, got {}",
                sharing_init.init_id
            )));
        }

        // 3. Verify sender identity signature
        sharing_init
            .sender_identity
            .verify()
            .map_err(|e| CoreError::Engine(format!("sender identity signature invalid: {e}")))?;

        // 4. Look up dk seed for target prekey
        let dk_seed = self
            .prekey_store
            .get_dk_seed(&sharing_init.target_prekey_id)
            .ok_or_else(|| {
                CoreError::Engine(format!(
                    "unknown prekey_id: {}",
                    sharing_init.target_prekey_id
                ))
            })?;

        // Reconstruct the X-Wing decapsulation key from seed
        let dk = XWingKem::decapsulation_key_from_bytes(dk_seed);

        // 5. Decapsulate
        let bootstrap_secret =
            DefaultBootstrapHandshake::decapsulate_from_peer(&dk, &sharing_init.kem_ciphertext)?;

        // 6. Get the prekey's ek for transcript building
        let prekey_xwing_ek = self
            .prekey_store
            .get_ek(&sharing_init.target_prekey_id)
            .ok_or_else(|| {
                CoreError::Engine(format!(
                    "missing ek for prekey_id: {}",
                    sharing_init.target_prekey_id
                ))
            })?;

        // 7. Build transcript (same as sender)
        let transcript_hash = build_sharing_transcript(
            &sharing_init.init_id,
            &sharing_init.sender_identity,
            &self.identity,
            &sharing_init.sender_ephemeral_ek,
            prekey_xwing_ek,
            &sharing_init.kem_ciphertext,
            &sharing_init.target_prekey_id,
        );

        // 8. Derive key schedule (same as sender)
        let key_schedule = BootstrapKeySchedule::derive(
            BootstrapProfile::RemoteSharing,
            BootstrapVersion::V1,
            bootstrap_secret,
            &transcript_hash,
        )?;

        // 9. Derive pairwise_secret and payload_encryption_key (same as sender)
        let pairwise_secret = prism_sync_crypto::kdf::derive_subkey(
            key_schedule.encryption_key(BootstrapRole::Initiator),
            &transcript_hash,
            b"prism_sharing_pairwise_v1",
        )?;

        let payload_encryption_key = prism_sync_crypto::kdf::derive_subkey(
            key_schedule.encryption_key(BootstrapRole::Initiator),
            &transcript_hash,
            b"prism_sharing_init_payload_v1",
        )?;

        // 10. Verify sender's confirmation MAC
        let confirmation = ConfirmationCode::new(
            BootstrapProfile::RemoteSharing,
            BootstrapVersion::V1,
            &key_schedule,
            transcript_hash,
        );
        confirmation
            .verify_confirmation(&sharing_init.confirmation_mac, BootstrapRole::Initiator)?;

        // 11. Decrypt inner payload
        let context = EnvelopeContext {
            profile: BootstrapProfile::RemoteSharing,
            version: BootstrapVersion::V1,
            sender_role: BootstrapRole::Initiator,
            purpose: b"sharing_init_payload",
            session_id: sharing_init.init_id.as_bytes(),
            transcript_hash: &transcript_hash,
        };
        let plaintext = EncryptedEnvelope::open(
            &payload_encryption_key,
            &sharing_init.encrypted_payload,
            &context,
        )?;
        let payload: SharingInitPayload = serde_json::from_slice(&plaintext)?;

        if payload.sender_sharing_id != sharing_init.sender_identity.sharing_id {
            return Err(CoreError::Engine(format!(
                "sender_sharing_id mismatch: signed identity={}, encrypted payload={}",
                sharing_init.sender_identity.sharing_id, payload.sender_sharing_id
            )));
        }

        // 12. Duplicate relationship check — use the outer signed identity after
        //     confirming the encrypted payload agrees with it.
        if existing_relationship_sharing_ids
            .contains(&sharing_init.sender_identity.sharing_id.as_str())
        {
            return Err(CoreError::Engine(format!(
                "duplicate relationship: already have relationship with sender {}",
                sharing_init.sender_identity.sharing_id
            )));
        }

        Ok(ProcessedSharingInit {
            pairwise_secret,
            sender_identity: sharing_init.sender_identity,
            display_name: payload.display_name,
            offered_scopes: payload.offered_scopes,
            init_id: sharing_init.init_id,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::mock_sharing_relay::MockSharingRelay;
    use std::collections::HashMap;
    use std::sync::Mutex;

    const TEST_DEK_SENDER: [u8; 32] = [0xAA; 32];
    const TEST_DEK_RECIPIENT: [u8; 32] = [0xBB; 32];

    #[derive(Default)]
    struct MemStore {
        data: Mutex<HashMap<String, Vec<u8>>>,
    }

    impl SecureStore for MemStore {
        fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
            Ok(self.data.lock().unwrap().get(key).cloned())
        }

        fn set(&self, key: &str, value: &[u8]) -> Result<()> {
            self.data
                .lock()
                .unwrap()
                .insert(key.to_string(), value.to_vec());
            Ok(())
        }

        fn delete(&self, key: &str) -> Result<()> {
            self.data.lock().unwrap().remove(key);
            Ok(())
        }

        fn clear(&self) -> Result<()> {
            self.data.lock().unwrap().clear();
            Ok(())
        }
    }

    fn sender_sharing_id_bytes() -> [u8; 16] {
        [0x11; 16]
    }
    fn recipient_sharing_id_bytes() -> [u8; 16] {
        [0x22; 16]
    }
    fn sender_sharing_id() -> String {
        hex::encode(sender_sharing_id_bytes())
    }
    fn recipient_sharing_id() -> String {
        hex::encode(recipient_sharing_id_bytes())
    }

    /// Set up a recipient with a fresh prekey published to the relay.
    async fn setup_recipient(relay: &MockSharingRelay, now: i64) -> SharingRecipient {
        let rid = recipient_sharing_id();
        let mut recipient =
            SharingRecipient::from_dek(&TEST_DEK_RECIPIENT, &rid, &recipient_sharing_id_bytes(), 0)
                .unwrap();

        // Publish identity to relay
        relay
            .publish_identity(&rid, &recipient.identity().to_bytes())
            .await
            .unwrap();

        // Rotate prekey and publish
        recipient
            .ensure_prekey_fresh(relay, "recipient-device-1", now)
            .await
            .unwrap();

        recipient
    }

    fn make_sender() -> super::super::sharing_sender::SharingSender {
        let sid = sender_sharing_id();
        super::super::sharing_sender::SharingSender::from_dek(
            &TEST_DEK_SENDER,
            &sid,
            &sender_sharing_id_bytes(),
            0,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn full_round_trip_same_pairwise_secret() {
        let relay = MockSharingRelay::new();
        let now = 1_700_000_000i64;

        let recipient = setup_recipient(&relay, now).await;
        let sender = make_sender();

        // Sender initiates
        let rid = recipient_sharing_id();
        let result = sender
            .initiate(&relay, &rid, "Alice", vec!["read:members".into()], now)
            .await
            .unwrap();

        // Extract the sharing-init from the relay
        relay.set_sharing_id(&rid);
        let pending = relay.fetch_pending_inits().await.unwrap();
        assert_eq!(pending.len(), 1);

        // Recipient processes
        let processed = recipient
            .process_sharing_init(&pending[0].payload, &pending[0].init_id, &[], &[])
            .unwrap();

        // Pairwise secrets match
        assert_eq!(*result.pairwise_secret, *processed.pairwise_secret);
        assert_eq!(processed.display_name, "Alice");
        assert_eq!(processed.offered_scopes, vec!["read:members".to_string()]);
        assert_eq!(processed.init_id, result.init_id);
    }

    #[tokio::test]
    async fn invalid_sender_identity_rejected() {
        let relay = MockSharingRelay::new();
        let now = 1_700_000_000i64;

        let recipient = setup_recipient(&relay, now).await;
        let sender = make_sender();

        let rid = recipient_sharing_id();
        let _result = sender
            .initiate(&relay, &rid, "Alice", vec![], now)
            .await
            .unwrap();

        relay.set_sharing_id(&rid);
        let pending = relay.fetch_pending_inits().await.unwrap();
        assert_eq!(pending.len(), 1);

        // Tamper with the payload (corrupt the sender identity signature)
        let mut tampered = pending[0].payload.clone();
        // The identity bundle is embedded within the SharingInit.
        // Corrupt a byte deep in the payload to invalidate the sender identity sig.
        if tampered.len() > 50 {
            tampered[50] ^= 0xFF;
        }

        let result = recipient.process_sharing_init(&tampered, &pending[0].init_id, &[], &[]);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn stale_prekey_sender_rejects() {
        let relay = MockSharingRelay::new();
        let now = 1_700_000_000i64;

        // Set up recipient with a prekey created 31 days ago
        let rid = recipient_sharing_id();
        let mut recipient =
            SharingRecipient::from_dek(&TEST_DEK_RECIPIENT, &rid, &recipient_sharing_id_bytes(), 0)
                .unwrap();

        let old_time = now - (31 * 24 * 3600);
        relay
            .publish_identity(&rid, &recipient.identity().to_bytes())
            .await
            .unwrap();
        recipient
            .ensure_prekey_fresh(&relay, "device-1", old_time)
            .await
            .unwrap();

        let sender = make_sender();
        let result = sender.initiate(&relay, &rid, "Alice", vec![], now).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("stale"), "expected stale error, got: {err}");
    }

    #[tokio::test]
    async fn unknown_prekey_id_recipient_fails() {
        let relay = MockSharingRelay::new();
        let now = 1_700_000_000i64;

        let mut recipient = setup_recipient(&relay, now).await;
        let sender = make_sender();

        let rid = recipient_sharing_id();
        let _result = sender
            .initiate(&relay, &rid, "Alice", vec![], now)
            .await
            .unwrap();

        relay.set_sharing_id(&rid);
        let pending = relay.fetch_pending_inits().await.unwrap();

        // Rotate the recipient's prekey via ensure_prekey_fresh (simulates rotation)
        // and then prune the old one to simulate the grace period having expired.
        // Use a time far enough in the future to trigger rotation (>7 days).
        recipient
            .ensure_prekey_fresh(&relay, "device-1", now + 8 * 24 * 3600)
            .await
            .unwrap();
        // Force prune all previous (simulate expired grace period)
        recipient.prekey_store_mut().prune_expired(now + 1_000_000);

        let result =
            recipient.process_sharing_init(&pending[0].payload, &pending[0].init_id, &[], &[]);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown prekey_id"),
            "expected unknown prekey_id error, got: {err}"
        );
    }

    #[tokio::test]
    async fn replay_detection_rejects_duplicate() {
        let relay = MockSharingRelay::new();
        let now = 1_700_000_000i64;

        let recipient = setup_recipient(&relay, now).await;
        let sender = make_sender();

        let rid = recipient_sharing_id();
        let _result = sender
            .initiate(&relay, &rid, "Alice", vec![], now)
            .await
            .unwrap();

        relay.set_sharing_id(&rid);
        let pending = relay.fetch_pending_inits().await.unwrap();

        // First process succeeds
        let processed = recipient
            .process_sharing_init(&pending[0].payload, &pending[0].init_id, &[], &[])
            .unwrap();

        // Second process with same init_id fails (replay)
        let result2 = recipient.process_sharing_init(
            &pending[0].payload,
            &pending[0].init_id,
            &[],
            &[processed.init_id.as_str()],
        );
        assert!(result2.is_err());
        let err = result2.unwrap_err().to_string();
        assert!(err.contains("replay"), "expected replay error, got: {err}");
    }

    #[tokio::test]
    async fn duplicate_relationship_rejected() {
        let relay = MockSharingRelay::new();
        let now = 1_700_000_000i64;

        let recipient = setup_recipient(&relay, now).await;
        let sender = make_sender();
        let sid = sender_sharing_id();

        let rid = recipient_sharing_id();
        let _result = sender
            .initiate(&relay, &rid, "Alice", vec![], now)
            .await
            .unwrap();

        relay.set_sharing_id(&rid);
        let pending = relay.fetch_pending_inits().await.unwrap();

        // Process with existing relationship for this sender
        let result = recipient.process_sharing_init(
            &pending[0].payload,
            &pending[0].init_id,
            &[sid.as_str()],
            &[],
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("duplicate relationship"),
            "expected duplicate relationship error, got: {err}"
        );
    }

    #[tokio::test]
    async fn confirmation_mac_tampered_rejected() {
        let relay = MockSharingRelay::new();
        let now = 1_700_000_000i64;

        let recipient = setup_recipient(&relay, now).await;
        let sender = make_sender();

        let rid = recipient_sharing_id();
        let _result = sender
            .initiate(&relay, &rid, "Alice", vec![], now)
            .await
            .unwrap();

        relay.set_sharing_id(&rid);
        let pending = relay.fetch_pending_inits().await.unwrap();

        // Parse the SharingInit, tamper with confirmation_mac, re-serialize
        let mut sharing_init = SharingInit::from_bytes(&pending[0].payload).unwrap();
        sharing_init.confirmation_mac[0] ^= 0xFF;
        let tampered_bytes = sharing_init.to_bytes();

        let result = recipient.process_sharing_init(&tampered_bytes, &pending[0].init_id, &[], &[]);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("confirmation MAC"),
            "expected confirmation MAC error, got: {err}"
        );
    }

    #[tokio::test]
    async fn sender_sharing_id_mismatch_rejected() {
        let relay = MockSharingRelay::new();
        let now = 1_700_000_000i64;

        let recipient = setup_recipient(&relay, now).await;
        let sender = make_sender();

        let rid = recipient_sharing_id();
        let _result = sender
            .initiate(&relay, &rid, "Alice", vec!["read:members".into()], now)
            .await
            .unwrap();

        relay.set_sharing_id(&rid);
        let pending = relay.fetch_pending_inits().await.unwrap();
        let mut sharing_init = SharingInit::from_bytes(&pending[0].payload).unwrap();

        let dk = XWingKem::decapsulation_key_from_bytes(
            recipient
                .prekey_store()
                .get_dk_seed(&sharing_init.target_prekey_id)
                .unwrap(),
        );
        let bootstrap_secret =
            DefaultBootstrapHandshake::decapsulate_from_peer(&dk, &sharing_init.kem_ciphertext)
                .unwrap();
        let prekey_xwing_ek = recipient
            .prekey_store()
            .get_ek(&sharing_init.target_prekey_id)
            .unwrap();
        let transcript_hash = build_sharing_transcript(
            &sharing_init.init_id,
            &sharing_init.sender_identity,
            recipient.identity(),
            &sharing_init.sender_ephemeral_ek,
            prekey_xwing_ek,
            &sharing_init.kem_ciphertext,
            &sharing_init.target_prekey_id,
        );
        let key_schedule = BootstrapKeySchedule::derive(
            BootstrapProfile::RemoteSharing,
            BootstrapVersion::V1,
            bootstrap_secret,
            &transcript_hash,
        )
        .unwrap();
        let payload_encryption_key = prism_sync_crypto::kdf::derive_subkey(
            key_schedule.encryption_key(BootstrapRole::Initiator),
            &transcript_hash,
            b"prism_sharing_init_payload_v1",
        )
        .unwrap();
        let context = EnvelopeContext {
            profile: BootstrapProfile::RemoteSharing,
            version: BootstrapVersion::V1,
            sender_role: BootstrapRole::Initiator,
            purpose: b"sharing_init_payload",
            session_id: sharing_init.init_id.as_bytes(),
            transcript_hash: &transcript_hash,
        };

        let plaintext = EncryptedEnvelope::open(
            &payload_encryption_key,
            &sharing_init.encrypted_payload,
            &context,
        )
        .unwrap();
        let mut payload: SharingInitPayload = serde_json::from_slice(&plaintext).unwrap();
        payload.sender_sharing_id = "ff".repeat(16);
        let tampered_plaintext = serde_json::to_vec(&payload).unwrap();
        sharing_init.encrypted_payload =
            EncryptedEnvelope::seal(&payload_encryption_key, &tampered_plaintext, &context)
                .unwrap();

        let err = recipient
            .process_sharing_init(&sharing_init.to_bytes(), &pending[0].init_id, &[], &[])
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("sender_sharing_id mismatch"),
            "expected sender_sharing_id mismatch error, got: {err}"
        );
    }

    #[tokio::test]
    async fn delayed_init_to_previous_prekey_survives_restart() {
        let relay = MockSharingRelay::new();
        let secure_store = MemStore::default();
        let now = 1_700_000_000i64;
        let rid = recipient_sharing_id();

        let mut recipient =
            SharingRecipient::from_dek(&TEST_DEK_RECIPIENT, &rid, &recipient_sharing_id_bytes(), 0)
                .unwrap();
        relay
            .publish_identity(&rid, &recipient.identity().to_bytes())
            .await
            .unwrap();
        recipient
            .ensure_prekey_fresh_and_persist(&relay, &secure_store, "recipient-device-1", now)
            .await
            .unwrap();

        let sender = make_sender();
        let sender_result = sender
            .initiate(&relay, &rid, "Alice", vec!["read:members".into()], now + 1)
            .await
            .unwrap();

        recipient
            .ensure_prekey_fresh_and_persist(
                &relay,
                &secure_store,
                "recipient-device-1",
                now + 8 * 24 * 3600,
            )
            .await
            .unwrap();

        let reloaded = SharingRecipient::load_from_secure_store(
            &TEST_DEK_RECIPIENT,
            &rid,
            &recipient_sharing_id_bytes(),
            0,
            &secure_store,
        )
        .unwrap();

        relay.set_sharing_id(&rid);
        let pending = relay.fetch_pending_inits().await.unwrap();
        assert_eq!(pending.len(), 1);

        let processed = reloaded
            .process_sharing_init(&pending[0].payload, &pending[0].init_id, &[], &[])
            .unwrap();

        assert_eq!(*sender_result.pairwise_secret, *processed.pairwise_secret);
        assert_eq!(processed.display_name, "Alice");
        assert_eq!(processed.offered_scopes, vec!["read:members".to_string()]);
    }

    #[tokio::test]
    async fn different_pairs_different_pairwise_secrets() {
        let relay = MockSharingRelay::new();
        let now = 1_700_000_000i64;

        let _recipient = setup_recipient(&relay, now).await;

        // Sender 1
        let sender1 = make_sender();
        let rid = recipient_sharing_id();
        let result1 = sender1
            .initiate(&relay, &rid, "Alice", vec![], now)
            .await
            .unwrap();

        // Sender 2 (different DEK)
        let sid2 = "cc".repeat(16);
        let sender2 = super::super::sharing_sender::SharingSender::from_dek(
            &[0xCC; 32],
            &sid2,
            &[0xCC; 16],
            0,
        )
        .unwrap();
        let result2 = sender2
            .initiate(&relay, &rid, "Bob", vec![], now)
            .await
            .unwrap();

        // Different pairwise secrets
        assert_ne!(*result1.pairwise_secret, *result2.pairwise_secret);
    }
}
