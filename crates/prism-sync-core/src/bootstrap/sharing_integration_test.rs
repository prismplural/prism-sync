//! End-to-end integration tests for the PQ hybrid remote sharing bootstrap.
//!
//! These tests exercise the full sharing protocol flow using the
//! `MockSharingRelay`. Each test builds the protocol steps from the
//! underlying primitives (identity derivation, KEM handshake, transcript,
//! key schedule, envelope, confirmation) to validate the security properties
//! documented in Phase 4.
//!
//! Once `SharingSender`, `SharingRecipient`, and `PrekeyStore` land,
//! these tests should be updated to use those higher-level APIs directly.

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey as Ed25519SigningKey;
    use ml_dsa::MlDsa65;
    use zeroize::Zeroizing;

    use prism_sync_crypto::pq::hybrid_kem::XWingKem;

    use crate::bootstrap::confirmation::ConfirmationCode;
    use crate::bootstrap::encrypted_envelope::{EncryptedEnvelope, EnvelopeContext};
    use crate::bootstrap::handshake::{BootstrapHandshake, DefaultBootstrapHandshake};
    use crate::bootstrap::key_schedule::BootstrapKeySchedule;
    use crate::bootstrap::sharing_identity::{
        derive_sharing_ed25519_keypair, derive_sharing_identity_seed, derive_sharing_ml_dsa_keypair,
    };
    use crate::bootstrap::sharing_models::{
        SharingIdentityBundle, SharingInit, SharingInitPayload, SignedPrekey,
    };
    use crate::bootstrap::sharing_transcript::build_sharing_transcript;
    use crate::bootstrap::sharing_trust::{evaluate_identity, TrustDecision};
    use crate::bootstrap::transcript::BootstrapTranscript;
    use crate::bootstrap::{BootstrapProfile, BootstrapRole, BootstrapVersion};
    use crate::relay::mock_sharing_relay::MockSharingRelay;
    use crate::relay::sharing_relay::SharingRelay;

    type SenderResult = Result<(Vec<u8>, Zeroizing<Vec<u8>>, String), crate::error::CoreError>;
    type RecipientResult = Result<
        (Zeroizing<Vec<u8>>, String, Vec<String>, SharingIdentityBundle),
        crate::error::CoreError,
    >;

    fn rng() -> getrandom::rand_core::UnwrapErr<getrandom::SysRng> {
        getrandom::rand_core::UnwrapErr(getrandom::SysRng)
    }

    /// Generate a random 32-byte DEK.
    fn random_dek() -> Vec<u8> {
        let mut buf = [0u8; 32];
        getrandom::fill(&mut buf).unwrap();
        buf.to_vec()
    }

    /// Generate a random sharing_id as a 16-byte hex string.
    fn random_sharing_id() -> (String, [u8; 16]) {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).unwrap();
        (hex::encode(bytes), bytes)
    }

    /// Derive identity keys from DEK + sharing_id bytes.
    struct DerivedIdentity {
        bundle: SharingIdentityBundle,
        ed25519_sk: Ed25519SigningKey,
        ml_dsa_sk: ml_dsa::ExpandedSigningKey<MlDsa65>,
        sharing_id: String,
    }

    fn derive_identity(
        dek: &[u8],
        sharing_id: &str,
        sharing_id_bytes: &[u8; 16],
    ) -> DerivedIdentity {
        let seed = derive_sharing_identity_seed(dek, sharing_id_bytes, 0).unwrap();
        let mut seed_arr = [0u8; 32];
        seed_arr.copy_from_slice(&seed);

        let (ed25519_sk, ed25519_pk) = derive_sharing_ed25519_keypair(&seed_arr).unwrap();
        let (ml_dsa_sk, ml_dsa_pk) = derive_sharing_ml_dsa_keypair(&seed_arr).unwrap();

        let bundle = SharingIdentityBundle::sign(
            sharing_id.to_string(),
            0,
            ed25519_pk,
            ml_dsa_pk,
            &ed25519_sk,
            &ml_dsa_sk,
        );

        DerivedIdentity { bundle, ed25519_sk, ml_dsa_sk, sharing_id: sharing_id.to_string() }
    }

    /// Generate a signed prekey for a given identity.
    fn generate_signed_prekey(
        identity: &DerivedIdentity,
        device_id: &str,
        prekey_id: &str,
        created_at: i64,
    ) -> (SignedPrekey, Vec<u8>) {
        // Generate X-Wing keypair from random seed
        let mut dk_seed = [0u8; 32];
        getrandom::fill(&mut dk_seed).unwrap();
        let dk = XWingKem::decapsulation_key_from_bytes(&dk_seed);
        let ek_bytes = XWingKem::encapsulation_key_bytes(&dk);

        let prekey = SignedPrekey::sign(
            prekey_id.to_string(),
            device_id.to_string(),
            ek_bytes,
            created_at,
            &identity.ed25519_sk,
            &identity.ml_dsa_sk,
        );

        // Return the prekey and the DK seed (so tests can decapsulate)
        (prekey, dk_seed.to_vec())
    }

    /// Perform the sender side of the sharing protocol.
    /// Returns (SharingInit bytes, pairwise_secret, init_id, sender_ephemeral_ek).
    fn sender_initiate(
        sender: &DerivedIdentity,
        recipient_identity_bytes: &[u8],
        recipient_prekey_bytes: &[u8],
        display_name: &str,
        offered_scopes: &[String],
    ) -> SenderResult {
        // Parse recipient identity and prekey
        let recipient_identity = SharingIdentityBundle::from_bytes(recipient_identity_bytes)
            .ok_or_else(|| {
                crate::error::CoreError::Engine("Failed to parse recipient identity".into())
            })?;
        let recipient_prekey =
            SignedPrekey::from_bytes(recipient_prekey_bytes).ok_or_else(|| {
                crate::error::CoreError::Engine("Failed to parse recipient prekey".into())
            })?;

        // Verify identity self-signature
        recipient_identity.verify()?;

        // Verify prekey signature against identity
        recipient_prekey.verify(&recipient_identity)?;

        // Check prekey freshness
        let now = chrono::Utc::now().timestamp();
        if !recipient_prekey.is_fresh(now) {
            return Err(crate::error::CoreError::Engine("Prekey is stale".into()));
        }

        // Generate ephemeral X-Wing keypair
        let mut eph_seed = [0u8; 32];
        getrandom::fill(&mut eph_seed).unwrap();
        let eph_dk = XWingKem::decapsulation_key_from_bytes(&eph_seed);
        let sender_ephemeral_ek = XWingKem::encapsulation_key_bytes(&eph_dk);

        // Encapsulate to recipient's prekey
        let (kem_ciphertext, bootstrap_secret) =
            DefaultBootstrapHandshake::encapsulate_to_peer(&recipient_prekey.xwing_ek, &mut rng())?;

        // Generate init_id
        let mut init_id_bytes = [0u8; 16];
        getrandom::fill(&mut init_id_bytes).unwrap();
        let init_id = hex::encode(init_id_bytes);

        // Build transcript
        let transcript_hash = build_sharing_transcript(
            &init_id,
            &sender.bundle,
            &recipient_identity,
            &sender_ephemeral_ek,
            &recipient_prekey.xwing_ek,
            &kem_ciphertext,
            &recipient_prekey.prekey_id,
        );

        // Derive key schedule
        let key_schedule = BootstrapKeySchedule::derive(
            BootstrapProfile::RemoteSharing,
            BootstrapVersion::V1,
            bootstrap_secret,
            &transcript_hash,
        )?;

        // Derive pairwise secret and payload key via HKDF (matching production)
        let pairwise_secret = prism_sync_crypto::kdf::derive_subkey(
            key_schedule.encryption_key(BootstrapRole::Initiator),
            &transcript_hash,
            b"prism_sharing_pairwise_v1",
        )?;

        let payload_key = prism_sync_crypto::kdf::derive_subkey(
            key_schedule.encryption_key(BootstrapRole::Initiator),
            &transcript_hash,
            b"prism_sharing_init_payload_v1",
        )?;

        // Compute confirmation MAC
        let confirmation = ConfirmationCode::new(
            BootstrapProfile::RemoteSharing,
            BootstrapVersion::V1,
            &key_schedule,
            transcript_hash,
        );
        let mac = confirmation.confirmation_mac(BootstrapRole::Initiator);
        let mut confirmation_mac = [0u8; 32];
        confirmation_mac.copy_from_slice(&mac);

        // Encrypt inner payload
        let payload = SharingInitPayload {
            display_name: display_name.to_string(),
            offered_scopes: offered_scopes.to_vec(),
            sender_sharing_id: sender.sharing_id.clone(),
        };
        let payload_json = serde_json::to_vec(&payload).unwrap();

        let envelope_context = EnvelopeContext {
            profile: BootstrapProfile::RemoteSharing,
            version: BootstrapVersion::V1,
            sender_role: BootstrapRole::Initiator,
            purpose: b"sharing_init_payload",
            session_id: init_id.as_bytes(),
            transcript_hash: &transcript_hash,
        };

        let encrypted_payload =
            EncryptedEnvelope::seal(&payload_key, &payload_json, &envelope_context)?;

        // Build SharingInit
        let sharing_init = SharingInit {
            version: BootstrapVersion::V1,
            init_id: init_id.clone(),
            sender_identity: sender.bundle.clone(),
            sender_ephemeral_ek: sender_ephemeral_ek.to_vec(),
            kem_ciphertext,
            target_prekey_id: recipient_prekey.prekey_id.clone(),
            confirmation_mac,
            encrypted_payload,
        };

        let init_bytes = sharing_init.to_bytes();
        Ok((init_bytes, pairwise_secret, init_id))
    }

    /// Perform the recipient side of the sharing protocol.
    /// Returns (pairwise_secret, display_name, offered_scopes, sender_identity).
    fn recipient_process(
        recipient: &DerivedIdentity,
        dk_seed: &[u8],
        sharing_init_bytes: &[u8],
        init_id: &str,
        existing_relationships: &[String],
        seen_init_ids: &[String],
    ) -> RecipientResult {
        // Replay check
        if seen_init_ids.contains(&init_id.to_string()) {
            return Err(crate::error::CoreError::Engine("Duplicate init_id (replay)".into()));
        }

        // Parse SharingInit
        let sharing_init = SharingInit::from_bytes(sharing_init_bytes)
            .ok_or_else(|| crate::error::CoreError::Engine("Failed to parse SharingInit".into()))?;

        // Verify sender identity self-signature
        sharing_init.sender_identity.verify()?;

        // Duplicate relationship check
        if existing_relationships.contains(&sharing_init.sender_identity.sharing_id) {
            return Err(crate::error::CoreError::Engine(
                "Duplicate relationship: sender already in existing_relationships".into(),
            ));
        }

        // Look up decapsulation key for target prekey
        let mut dk_seed_arr = [0u8; 32];
        dk_seed_arr.copy_from_slice(&dk_seed[..32]);
        let dk = XWingKem::decapsulation_key_from_bytes(&dk_seed_arr);

        // Decapsulate
        let bootstrap_secret =
            DefaultBootstrapHandshake::decapsulate_from_peer(&dk, &sharing_init.kem_ciphertext)?;

        // Derive the recipient's prekey EK for transcript
        let recipient_prekey_ek = XWingKem::encapsulation_key_bytes(&dk);

        // Build transcript
        let transcript_hash = build_sharing_transcript(
            &sharing_init.init_id,
            &sharing_init.sender_identity,
            &recipient.bundle,
            &sharing_init.sender_ephemeral_ek,
            &recipient_prekey_ek,
            &sharing_init.kem_ciphertext,
            &sharing_init.target_prekey_id,
        );

        // Derive key schedule
        let key_schedule = BootstrapKeySchedule::derive(
            BootstrapProfile::RemoteSharing,
            BootstrapVersion::V1,
            bootstrap_secret,
            &transcript_hash,
        )?;

        // Derive pairwise secret and payload key via HKDF (matching production)
        let pairwise_secret = prism_sync_crypto::kdf::derive_subkey(
            key_schedule.encryption_key(BootstrapRole::Initiator),
            &transcript_hash,
            b"prism_sharing_pairwise_v1",
        )?;

        let payload_key = prism_sync_crypto::kdf::derive_subkey(
            key_schedule.encryption_key(BootstrapRole::Initiator),
            &transcript_hash,
            b"prism_sharing_init_payload_v1",
        )?;

        // Verify sender's confirmation MAC
        let confirmation = ConfirmationCode::new(
            BootstrapProfile::RemoteSharing,
            BootstrapVersion::V1,
            &key_schedule,
            transcript_hash,
        );
        confirmation
            .verify_confirmation(&sharing_init.confirmation_mac, BootstrapRole::Initiator)?;

        // Decrypt inner payload
        let envelope_context = EnvelopeContext {
            profile: BootstrapProfile::RemoteSharing,
            version: BootstrapVersion::V1,
            sender_role: BootstrapRole::Initiator,
            purpose: b"sharing_init_payload",
            session_id: sharing_init.init_id.as_bytes(),
            transcript_hash: &transcript_hash,
        };

        let payload_json = EncryptedEnvelope::open(
            &payload_key,
            &sharing_init.encrypted_payload,
            &envelope_context,
        )?;

        let payload: SharingInitPayload = serde_json::from_slice(&payload_json)?;

        Ok((
            pairwise_secret,
            payload.display_name,
            payload.offered_scopes,
            sharing_init.sender_identity,
        ))
    }

    // ── Test 1: full_sharing_flow ─────────────────────────────────────────

    #[tokio::test]
    async fn full_sharing_flow() {
        let relay = MockSharingRelay::new();

        // Create sender and recipient
        let dek_a = random_dek();
        let (sid_a, sid_a_bytes) = random_sharing_id();
        let sender = derive_identity(&dek_a, &sid_a, &sid_a_bytes);

        let dek_b = random_dek();
        let (sid_b, sid_b_bytes) = random_sharing_id();
        let recipient = derive_identity(&dek_b, &sid_b, &sid_b_bytes);

        // Recipient publishes identity + prekey
        relay.publish_identity(&sid_b, &recipient.bundle.to_bytes()).await.unwrap();

        let now = chrono::Utc::now().timestamp();
        let (prekey, dk_seed) = generate_signed_prekey(&recipient, "device-b", "prekey-1", now);
        relay.publish_prekey(&sid_b, "device-b", "prekey-1", &prekey.to_bytes()).await.unwrap();

        // Sender fetches prekey bundle
        let (identity_bytes, prekey_bytes) =
            relay.fetch_prekey_bundle(&sid_b).await.unwrap().expect("bundle should exist");

        // Sender initiates
        let (init_bytes, sender_pairwise, init_id) = sender_initiate(
            &sender,
            &identity_bytes,
            &prekey_bytes,
            "Alice",
            &["read:members".to_string(), "read:fronting".to_string()],
        )
        .unwrap();

        // Upload to relay
        relay.upload_sharing_init(&init_id, &sid_b, &sid_a, &init_bytes).await.unwrap();

        // Recipient fetches and processes
        relay.set_sharing_id(&sid_b);
        let pending = relay.fetch_pending_inits().await.unwrap();
        assert_eq!(pending.len(), 1);

        let (recipient_pairwise, display_name, offered_scopes, sender_identity) =
            recipient_process(
                &recipient,
                &dk_seed,
                &pending[0].payload,
                &pending[0].init_id,
                &[],
                &[],
            )
            .unwrap();

        // Both sides derived the same pairwise secret
        assert_eq!(*sender_pairwise, *recipient_pairwise);
        assert_eq!(sender_pairwise.len(), 32);

        // Payload was decrypted correctly
        assert_eq!(display_name, "Alice");
        assert_eq!(offered_scopes, vec!["read:members", "read:fronting"]);

        // Sender identity matches
        assert_eq!(sender_identity.sharing_id, sid_a);
    }

    // ── Test 2: recipient_offline_flow ────────────────────────────────────

    #[tokio::test]
    async fn recipient_offline_flow() {
        let relay = MockSharingRelay::new();

        let dek_a = random_dek();
        let (sid_a, sid_a_bytes) = random_sharing_id();
        let sender = derive_identity(&dek_a, &sid_a, &sid_a_bytes);

        let dek_b = random_dek();
        let (sid_b, sid_b_bytes) = random_sharing_id();
        let recipient = derive_identity(&dek_b, &sid_b, &sid_b_bytes);

        // Recipient publishes identity + prekey (then goes "offline")
        relay.publish_identity(&sid_b, &recipient.bundle.to_bytes()).await.unwrap();

        let now = chrono::Utc::now().timestamp();
        let (prekey, dk_seed) = generate_signed_prekey(&recipient, "device-b", "pk-1", now);
        relay.publish_prekey(&sid_b, "device-b", "pk-1", &prekey.to_bytes()).await.unwrap();

        // Sender fetches and initiates while recipient is offline
        let (identity_bytes, prekey_bytes) =
            relay.fetch_prekey_bundle(&sid_b).await.unwrap().unwrap();

        let (init_bytes, sender_pairwise, init_id) = sender_initiate(
            &sender,
            &identity_bytes,
            &prekey_bytes,
            "Alice (offline test)",
            &["read:members".to_string()],
        )
        .unwrap();

        relay.upload_sharing_init(&init_id, &sid_b, &sid_a, &init_bytes).await.unwrap();

        // Recipient comes "online" later and fetches
        relay.set_sharing_id(&sid_b);
        let pending = relay.fetch_pending_inits().await.unwrap();
        assert_eq!(pending.len(), 1);

        let (recipient_pairwise, display_name, _, _) = recipient_process(
            &recipient,
            &dk_seed,
            &pending[0].payload,
            &pending[0].init_id,
            &[],
            &[],
        )
        .unwrap();

        assert_eq!(*sender_pairwise, *recipient_pairwise);
        assert_eq!(display_name, "Alice (offline test)");

        // Second fetch returns empty (consumed)
        let pending2 = relay.fetch_pending_inits().await.unwrap();
        assert!(pending2.is_empty());
    }

    // ── Test 3: prekey_rotation_during_sharing ────────────────────────────

    #[tokio::test]
    async fn prekey_rotation_during_sharing() {
        let relay = MockSharingRelay::new();

        let dek_a = random_dek();
        let (sid_a, sid_a_bytes) = random_sharing_id();
        let sender = derive_identity(&dek_a, &sid_a, &sid_a_bytes);

        let dek_b = random_dek();
        let (sid_b, sid_b_bytes) = random_sharing_id();
        let recipient = derive_identity(&dek_b, &sid_b, &sid_b_bytes);

        // Recipient publishes identity + prekey A
        relay.publish_identity(&sid_b, &recipient.bundle.to_bytes()).await.unwrap();

        let now = chrono::Utc::now().timestamp();
        let (prekey_a, dk_seed_a) = generate_signed_prekey(&recipient, "device-b", "pk-a", now);
        relay.publish_prekey(&sid_b, "device-b", "pk-a", &prekey_a.to_bytes()).await.unwrap();

        // Sender fetches prekey A
        let (identity_bytes, prekey_bytes) =
            relay.fetch_prekey_bundle(&sid_b).await.unwrap().unwrap();

        // Recipient rotates to prekey B (prekey A enters grace period)
        let (_prekey_b, _dk_seed_b) =
            generate_signed_prekey(&recipient, "device-b", "pk-b", now + 1);
        relay.publish_prekey(&sid_b, "device-b", "pk-b", &_prekey_b.to_bytes()).await.unwrap();

        // Sender initiates using prekey A (already fetched)
        let (init_bytes, sender_pairwise, init_id) = sender_initiate(
            &sender,
            &identity_bytes,
            &prekey_bytes,
            "Alice",
            &["read:members".to_string()],
        )
        .unwrap();

        relay.upload_sharing_init(&init_id, &sid_b, &sid_a, &init_bytes).await.unwrap();

        // Recipient processes using prekey A's DK seed (grace period active)
        relay.set_sharing_id(&sid_b);
        let pending = relay.fetch_pending_inits().await.unwrap();
        assert_eq!(pending.len(), 1);

        let (recipient_pairwise, _, _, _) = recipient_process(
            &recipient,
            &dk_seed_a,
            &pending[0].payload,
            &pending[0].init_id,
            &[],
            &[],
        )
        .unwrap();

        // Both sides agree on the pairwise secret
        assert_eq!(*sender_pairwise, *recipient_pairwise);
    }

    // ── Test 4: stale_prekey_rejected ─────────────────────────────────────

    #[tokio::test]
    async fn stale_prekey_rejected() {
        let relay = MockSharingRelay::new();

        let dek_a = random_dek();
        let (sid_a, sid_a_bytes) = random_sharing_id();
        let sender = derive_identity(&dek_a, &sid_a, &sid_a_bytes);

        let dek_b = random_dek();
        let (sid_b, sid_b_bytes) = random_sharing_id();
        let recipient = derive_identity(&dek_b, &sid_b, &sid_b_bytes);

        // Recipient publishes identity
        relay.publish_identity(&sid_b, &recipient.bundle.to_bytes()).await.unwrap();

        // Create a prekey with created_at 31 days ago
        let now = chrono::Utc::now().timestamp();
        let stale_time = now - (31 * 24 * 60 * 60);
        let (stale_prekey, _dk_seed) =
            generate_signed_prekey(&recipient, "device-b", "pk-stale", stale_time);
        relay
            .publish_prekey(&sid_b, "device-b", "pk-stale", &stale_prekey.to_bytes())
            .await
            .unwrap();

        // Sender fetches
        let (identity_bytes, prekey_bytes) =
            relay.fetch_prekey_bundle(&sid_b).await.unwrap().unwrap();

        // Sender should reject the stale prekey
        let result = sender_initiate(&sender, &identity_bytes, &prekey_bytes, "Alice", &[]);

        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("stale") || err_msg.contains("Stale"),
            "Error should mention staleness: {err_msg}"
        );
    }

    // ── Test 5: identity_tampered ─────────────────────────────────────────

    #[tokio::test]
    async fn identity_tampered() {
        let relay = MockSharingRelay::new();

        let dek_a = random_dek();
        let (sid_a, sid_a_bytes) = random_sharing_id();
        let sender = derive_identity(&dek_a, &sid_a, &sid_a_bytes);

        let dek_b = random_dek();
        let (sid_b, sid_b_bytes) = random_sharing_id();
        let recipient = derive_identity(&dek_b, &sid_b, &sid_b_bytes);

        // Publish valid identity, then tamper with it on the relay
        let mut identity_bytes = recipient.bundle.to_bytes();
        // Tamper with a byte in the ed25519 public key region
        // Wire format: [1B version][2B sid_len][sid bytes][4B generation][32B ed25519_pk]...
        let sid_len = u16::from_be_bytes([identity_bytes[1], identity_bytes[2]]) as usize;
        let ed25519_pk_offset = 1 + 2 + sid_len + 4;
        identity_bytes[ed25519_pk_offset] ^= 0xFF;

        relay.publish_identity(&sid_b, &identity_bytes).await.unwrap();

        let now = chrono::Utc::now().timestamp();
        let (prekey, _dk_seed) = generate_signed_prekey(&recipient, "device-b", "pk-1", now);
        relay.publish_prekey(&sid_b, "device-b", "pk-1", &prekey.to_bytes()).await.unwrap();

        // Sender fetches
        let (fetched_identity, fetched_prekey) =
            relay.fetch_prekey_bundle(&sid_b).await.unwrap().unwrap();

        // Sender should detect tampered identity (signature verification fails)
        let result = sender_initiate(&sender, &fetched_identity, &fetched_prekey, "Alice", &[]);

        assert!(result.is_err());
    }

    // ── Test 6: replay_sharing_init ───────────────────────────────────────

    #[tokio::test]
    async fn replay_sharing_init() {
        let relay = MockSharingRelay::new();

        let dek_a = random_dek();
        let (sid_a, sid_a_bytes) = random_sharing_id();
        let sender = derive_identity(&dek_a, &sid_a, &sid_a_bytes);

        let dek_b = random_dek();
        let (sid_b, sid_b_bytes) = random_sharing_id();
        let recipient = derive_identity(&dek_b, &sid_b, &sid_b_bytes);

        relay.publish_identity(&sid_b, &recipient.bundle.to_bytes()).await.unwrap();

        let now = chrono::Utc::now().timestamp();
        let (prekey, dk_seed) = generate_signed_prekey(&recipient, "device-b", "pk-1", now);
        relay.publish_prekey(&sid_b, "device-b", "pk-1", &prekey.to_bytes()).await.unwrap();

        let (identity_bytes, prekey_bytes) =
            relay.fetch_prekey_bundle(&sid_b).await.unwrap().unwrap();

        let (init_bytes, _sender_pairwise, init_id) = sender_initiate(
            &sender,
            &identity_bytes,
            &prekey_bytes,
            "Alice",
            &["read:members".to_string()],
        )
        .unwrap();

        // First processing succeeds
        let result1 = recipient_process(&recipient, &dk_seed, &init_bytes, &init_id, &[], &[]);
        assert!(result1.is_ok());

        // Replay with same init_id in seen_init_ids should be rejected
        let result2 = recipient_process(
            &recipient,
            &dk_seed,
            &init_bytes,
            &init_id,
            &[],
            std::slice::from_ref(&init_id),
        );
        assert!(result2.is_err());
        let err_msg = format!("{}", result2.unwrap_err());
        assert!(
            err_msg.contains("replay") || err_msg.contains("Duplicate"),
            "Error should mention replay/duplicate: {err_msg}"
        );
    }

    // ── Test 7: duplicate_relationship_rejected ───────────────────────────

    #[tokio::test]
    async fn duplicate_relationship_rejected() {
        let relay = MockSharingRelay::new();

        let dek_a = random_dek();
        let (sid_a, sid_a_bytes) = random_sharing_id();
        let sender = derive_identity(&dek_a, &sid_a, &sid_a_bytes);

        let dek_b = random_dek();
        let (sid_b, sid_b_bytes) = random_sharing_id();
        let recipient = derive_identity(&dek_b, &sid_b, &sid_b_bytes);

        relay.publish_identity(&sid_b, &recipient.bundle.to_bytes()).await.unwrap();

        let now = chrono::Utc::now().timestamp();
        let (prekey, dk_seed) = generate_signed_prekey(&recipient, "device-b", "pk-1", now);
        relay.publish_prekey(&sid_b, "device-b", "pk-1", &prekey.to_bytes()).await.unwrap();

        let (identity_bytes, prekey_bytes) =
            relay.fetch_prekey_bundle(&sid_b).await.unwrap().unwrap();

        // First sharing flow succeeds
        let (init_bytes_1, _, init_id_1) = sender_initiate(
            &sender,
            &identity_bytes,
            &prekey_bytes,
            "Alice",
            &["read:members".to_string()],
        )
        .unwrap();

        let (_, _, _, sender_identity) =
            recipient_process(&recipient, &dk_seed, &init_bytes_1, &init_id_1, &[], &[]).unwrap();

        // Second attempt from same sender should be rejected
        // (sender's sharing_id is now in existing_relationships)
        let (init_bytes_2, _, init_id_2) = sender_initiate(
            &sender,
            &identity_bytes,
            &prekey_bytes,
            "Alice again",
            &["read:members".to_string()],
        )
        .unwrap();

        let result = recipient_process(
            &recipient,
            &dk_seed,
            &init_bytes_2,
            &init_id_2,
            std::slice::from_ref(&sender_identity.sharing_id),
            &[init_id_1],
        );
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("Duplicate relationship") || err_msg.contains("existing"),
            "Error should mention duplicate relationship: {err_msg}"
        );
    }

    // ── Test 8: key_change_warning ────────────────────────────────────────

    #[test]
    fn key_change_warning() {
        let dek_a = random_dek();
        let (sid_a, sid_a_bytes) = random_sharing_id();

        // First identity at generation 0
        let identity_gen0 = derive_identity(&dek_a, &sid_a, &sid_a_bytes);
        let pinned_bytes = identity_gen0.bundle.to_bytes();

        // Re-derive with generation 1 (simulating key rotation)
        let seed_gen1 = derive_sharing_identity_seed(&dek_a, &sid_a_bytes, 1).unwrap();
        let mut seed_arr = [0u8; 32];
        seed_arr.copy_from_slice(&seed_gen1);
        let (ed25519_sk_1, ed25519_pk_1) = derive_sharing_ed25519_keypair(&seed_arr).unwrap();
        let (ml_dsa_sk_1, ml_dsa_pk_1) = derive_sharing_ml_dsa_keypair(&seed_arr).unwrap();
        let bundle_gen1 = SharingIdentityBundle::sign(
            sid_a.clone(),
            1,
            ed25519_pk_1,
            ml_dsa_pk_1,
            &ed25519_sk_1,
            &ml_dsa_sk_1,
        );
        let new_bytes = bundle_gen1.to_bytes();

        // Unverified relationship: should warn
        let decision = evaluate_identity(Some(&pinned_bytes), &new_bytes, false);
        assert_eq!(decision, TrustDecision::WarnKeyChange);

        // Verified relationship: should block
        let decision = evaluate_identity(Some(&pinned_bytes), &new_bytes, true);
        assert_eq!(decision, TrustDecision::BlockKeyChange);

        // Same identity should accept
        let decision = evaluate_identity(Some(&pinned_bytes), &pinned_bytes, true);
        assert_eq!(decision, TrustDecision::Accept);
    }

    // ── Test 9: pairwise_secret_isolation ─────────────────────────────────

    #[tokio::test]
    async fn pairwise_secret_isolation() {
        let relay = MockSharingRelay::new();

        // Recipient B
        let dek_b = random_dek();
        let (sid_b, sid_b_bytes) = random_sharing_id();
        let recipient = derive_identity(&dek_b, &sid_b, &sid_b_bytes);

        relay.publish_identity(&sid_b, &recipient.bundle.to_bytes()).await.unwrap();

        let now = chrono::Utc::now().timestamp();
        let (prekey, dk_seed) = generate_signed_prekey(&recipient, "device-b", "pk-1", now);
        relay.publish_prekey(&sid_b, "device-b", "pk-1", &prekey.to_bytes()).await.unwrap();

        let (identity_bytes, prekey_bytes) =
            relay.fetch_prekey_bundle(&sid_b).await.unwrap().unwrap();

        // Sender A -> Recipient B
        let dek_a = random_dek();
        let (sid_a, sid_a_bytes) = random_sharing_id();
        let sender_a = derive_identity(&dek_a, &sid_a, &sid_a_bytes);

        let (init_bytes_ab, _, init_id_ab) =
            sender_initiate(&sender_a, &identity_bytes, &prekey_bytes, "Alice", &[]).unwrap();

        let (pairwise_ab, _, _, _) =
            recipient_process(&recipient, &dk_seed, &init_bytes_ab, &init_id_ab, &[], &[]).unwrap();

        // Sender C -> Recipient B (need fresh prekey since DK is per-session)
        // Re-publish prekey so sender C can fetch it
        let (prekey2, dk_seed2) = generate_signed_prekey(&recipient, "device-b", "pk-2", now);
        relay.publish_prekey(&sid_b, "device-b", "pk-2", &prekey2.to_bytes()).await.unwrap();

        let (identity_bytes2, prekey_bytes2) =
            relay.fetch_prekey_bundle(&sid_b).await.unwrap().unwrap();

        let dek_c = random_dek();
        let (sid_c, sid_c_bytes) = random_sharing_id();
        let sender_c = derive_identity(&dek_c, &sid_c, &sid_c_bytes);

        let (init_bytes_cb, _, init_id_cb) =
            sender_initiate(&sender_c, &identity_bytes2, &prekey_bytes2, "Charlie", &[]).unwrap();

        let (pairwise_cb, _, _, _) =
            recipient_process(&recipient, &dk_seed2, &init_bytes_cb, &init_id_cb, &[], &[])
                .unwrap();

        // Pairwise secrets must be independent
        assert_ne!(*pairwise_ab, *pairwise_cb);
    }

    // ── Test 10: profile_separation ───────────────────────────────────────

    #[test]
    fn profile_separation() {
        // Build a sharing transcript and a sync pairing transcript with
        // contrived identical field values. The profile byte in the domain
        // separator ensures they produce different hashes.
        let sharing_hash = {
            let mut t =
                BootstrapTranscript::new(BootstrapProfile::RemoteSharing, BootstrapVersion::V1);
            t.append_session_id(b"same-session-id");
            t.append_role_bytes(BootstrapRole::Initiator, b"ed25519_pk", &[0x11; 32]);
            t.append_role_bytes(BootstrapRole::Responder, b"ed25519_pk", &[0x22; 32]);
            t.append_bytes(b"kem_ciphertext", &[0x33; 1120]);
            t.finalize()
        };
        let pairing_hash = {
            let mut t =
                BootstrapTranscript::new(BootstrapProfile::SyncPairing, BootstrapVersion::V1);
            t.append_session_id(b"same-session-id");
            t.append_role_bytes(BootstrapRole::Initiator, b"ed25519_pk", &[0x11; 32]);
            t.append_role_bytes(BootstrapRole::Responder, b"ed25519_pk", &[0x22; 32]);
            t.append_bytes(b"kem_ciphertext", &[0x33; 1120]);
            t.finalize()
        };

        assert_ne!(
            sharing_hash, pairing_hash,
            "RemoteSharing and SyncPairing transcripts must differ"
        );

        // Also verify key schedule separation with the same secret
        let dk = XWingKem::decapsulation_key_from_bytes(&[42u8; 32]);
        let ek_bytes = XWingKem::encapsulation_key_bytes(&dk);
        let (ct, _) =
            BootstrapHandshake::<XWingKem>::encapsulate_to_peer(&ek_bytes, &mut rng()).unwrap();
        let s1 = BootstrapHandshake::<XWingKem>::decapsulate_from_peer(&dk, &ct).unwrap();
        let s2 = BootstrapHandshake::<XWingKem>::decapsulate_from_peer(&dk, &ct).unwrap();

        let ks_sharing = BootstrapKeySchedule::derive(
            BootstrapProfile::RemoteSharing,
            BootstrapVersion::V1,
            s1,
            &sharing_hash,
        )
        .unwrap();
        let ks_pairing = BootstrapKeySchedule::derive(
            BootstrapProfile::SyncPairing,
            BootstrapVersion::V1,
            s2,
            &pairing_hash,
        )
        .unwrap();

        assert_ne!(
            ks_sharing.encryption_key(BootstrapRole::Initiator),
            ks_pairing.encryption_key(BootstrapRole::Initiator),
        );
        assert_ne!(ks_sharing.confirmation_key(), ks_pairing.confirmation_key(),);
    }

    // ── Test 11: confirmation_mac_binding ──────────────────────────────────

    #[tokio::test]
    async fn confirmation_mac_binding() {
        let relay = MockSharingRelay::new();

        let dek_a = random_dek();
        let (sid_a, sid_a_bytes) = random_sharing_id();
        let sender = derive_identity(&dek_a, &sid_a, &sid_a_bytes);

        let dek_b = random_dek();
        let (sid_b, sid_b_bytes) = random_sharing_id();
        let recipient = derive_identity(&dek_b, &sid_b, &sid_b_bytes);

        relay.publish_identity(&sid_b, &recipient.bundle.to_bytes()).await.unwrap();

        let now = chrono::Utc::now().timestamp();
        let (prekey, dk_seed) = generate_signed_prekey(&recipient, "device-b", "pk-1", now);
        relay.publish_prekey(&sid_b, "device-b", "pk-1", &prekey.to_bytes()).await.unwrap();

        let (identity_bytes, prekey_bytes) =
            relay.fetch_prekey_bundle(&sid_b).await.unwrap().unwrap();

        let (init_bytes, _, init_id) = sender_initiate(
            &sender,
            &identity_bytes,
            &prekey_bytes,
            "Alice",
            &["read:members".to_string()],
        )
        .unwrap();

        // Tamper with the kem_ciphertext in the serialized SharingInit.
        // Parse the init, modify the ciphertext, and re-serialize.
        let parsed = SharingInit::from_bytes(&init_bytes).unwrap();

        // Re-build with tampered ciphertext
        let mut tampered_ct = parsed.kem_ciphertext.clone();
        tampered_ct[0] ^= 0xFF;

        let tampered_init = SharingInit {
            version: parsed.version,
            init_id: parsed.init_id.clone(),
            sender_identity: parsed.sender_identity.clone(),
            sender_ephemeral_ek: parsed.sender_ephemeral_ek.clone(),
            kem_ciphertext: tampered_ct,
            target_prekey_id: parsed.target_prekey_id.clone(),
            confirmation_mac: parsed.confirmation_mac,
            encrypted_payload: parsed.encrypted_payload.clone(),
        };

        let tampered_bytes = tampered_init.to_bytes();

        // Recipient processes tampered init — should fail
        // (decapsulation will produce different shared secret,
        // leading to different key schedule, so MAC verification fails)
        let result = recipient_process(&recipient, &dk_seed, &tampered_bytes, &init_id, &[], &[]);

        assert!(result.is_err(), "Tampered kem_ciphertext should cause MAC verification failure");
    }

    // ── Additional relay-level test: duplicate init_id on relay ────────────

    #[tokio::test]
    async fn relay_rejects_duplicate_init_id() {
        let relay = MockSharingRelay::new();

        relay.upload_sharing_init("init-dup", "bob", "alice", b"payload-1").await.unwrap();

        let result = relay.upload_sharing_init("init-dup", "bob", "alice", b"payload-2").await;

        assert!(result.is_err(), "Relay should reject duplicate init_id");
    }
}
