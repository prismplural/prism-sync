//! Sender side of the PQ hybrid remote sharing bootstrap protocol.
//!
//! [`SharingSender`] drives the initiator flow: fetches the recipient's
//! prekey bundle, performs hybrid KEM encapsulation, derives the pairwise
//! secret, and uploads the encrypted sharing-init to the relay.

use prism_sync_crypto::pq::hybrid_kem::XWingKem;
use zeroize::{Zeroize, Zeroizing};

use super::confirmation::ConfirmationCode;
use super::encrypted_envelope::{EncryptedEnvelope, EnvelopeContext};
use super::handshake::DefaultBootstrapHandshake;
use super::key_schedule::BootstrapKeySchedule;
use super::sharing_identity::{
    derive_sharing_ed25519_keypair, derive_sharing_identity_seed, derive_sharing_ml_dsa_keypair,
};
use super::sharing_models::{SharingIdentityBundle, SharingInit, SharingInitPayload, SignedPrekey};
use super::sharing_transcript::build_sharing_transcript;
use super::{BootstrapProfile, BootstrapRole, BootstrapVersion};
use crate::error::{CoreError, Result};
use crate::relay::sharing_relay::SharingRelay;

// ---------------------------------------------------------------------------
// SharingSender
// ---------------------------------------------------------------------------

/// Drives the sender (initiator) side of the remote sharing bootstrap.
pub struct SharingSender {
    identity: SharingIdentityBundle,
    sharing_id: String,
    #[allow(dead_code)]
    ed25519_sk: ed25519_dalek::SigningKey,
    #[allow(dead_code)]
    ml_dsa_sk: ml_dsa::ExpandedSigningKey<ml_dsa::MlDsa65>,
}

/// Result of a successful sharing-init operation.
#[derive(Debug)]
pub struct SharingInitResult {
    /// The derived pairwise secret (32 bytes).
    pub pairwise_secret: Zeroizing<Vec<u8>>,
    /// The unique init_id for this sharing-init.
    pub init_id: String,
    /// The recipient's identity bundle.
    pub recipient_identity: SharingIdentityBundle,
}

impl SharingSender {
    /// Construct a `SharingSender` from DEK and sharing identity parameters.
    ///
    /// Deterministically derives the Ed25519 + ML-DSA-65 identity keypairs
    /// from the DEK, sharing_id, and identity_generation.
    pub fn from_dek(
        dek: &[u8],
        sharing_id: &str,
        sharing_id_bytes: &[u8; 16],
        identity_generation: u32,
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
        })
    }

    /// The sender's sharing identity bundle.
    pub fn identity(&self) -> &SharingIdentityBundle {
        &self.identity
    }

    /// Initiate a remote sharing session with the given recipient.
    ///
    /// This is the core sender protocol:
    /// 1. Fetch recipient prekey bundle from relay
    /// 2. Verify identity + prekey signatures and freshness
    /// 3. Perform hybrid KEM encapsulation
    /// 4. Derive pairwise secret and payload encryption key
    /// 5. Build and upload encrypted sharing-init
    pub async fn initiate(
        &self,
        relay: &dyn SharingRelay,
        recipient_sharing_id: &str,
        display_name: &str,
        offered_scopes: Vec<String>,
        now: i64,
    ) -> Result<SharingInitResult> {
        // 1. Fetch prekey bundle
        let (identity_bytes, prekey_bytes) = relay
            .fetch_prekey_bundle(recipient_sharing_id)
            .await
            .map_err(|e| CoreError::Engine(format!("failed to fetch prekey bundle: {e}")))?
            .ok_or_else(|| {
                CoreError::Engine(format!(
                    "no prekey bundle found for sharing_id: {recipient_sharing_id}"
                ))
            })?;

        // 2. Parse identity and prekey
        let recipient_identity = SharingIdentityBundle::from_bytes(&identity_bytes)
            .ok_or_else(|| CoreError::Engine("failed to parse recipient identity bundle".into()))?;
        let prekey = SignedPrekey::from_bytes(&prekey_bytes)
            .ok_or_else(|| CoreError::Engine("failed to parse recipient signed prekey".into()))?;

        // 3. Verify identity bundle signature
        recipient_identity
            .verify()
            .map_err(|e| CoreError::Engine(format!("recipient identity signature invalid: {e}")))?;

        if recipient_identity.sharing_id != recipient_sharing_id {
            return Err(CoreError::Engine(format!(
                "relay returned identity bundle for unexpected sharing_id: expected {recipient_sharing_id}, got {}",
                recipient_identity.sharing_id
            )));
        }

        // 4. Verify prekey signature against identity
        prekey
            .verify(&recipient_identity)
            .map_err(|e| CoreError::Engine(format!("recipient prekey signature invalid: {e}")))?;

        // 5. Check prekey freshness
        if !prekey.is_fresh(now) {
            return Err(CoreError::Engine(
                "recipient prekey is stale or too far in the future".into(),
            ));
        }

        // 6. Generate ephemeral X-Wing keypair
        let mut eph_seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(eph_seed.as_mut())
            .map_err(|e| CoreError::Engine(format!("CSPRNG failed: {e}")))?;
        let eph_dk = XWingKem::decapsulation_key_from_bytes(&eph_seed);
        let sender_ephemeral_ek = XWingKem::encapsulation_key_bytes(&eph_dk);
        // Drop the ephemeral DK before the relay .await below — it's no longer
        // needed and holding it across the await inflates the async state machine.
        drop(eph_dk);

        // 7. Encapsulate to recipient's prekey xwing_ek
        let mut rng = getrandom::rand_core::UnwrapErr(getrandom::SysRng);
        let (kem_ciphertext, bootstrap_secret) =
            DefaultBootstrapHandshake::encapsulate_to_peer(&prekey.xwing_ek, &mut rng)?;

        // 8. Generate init_id: 16 random bytes, hex-encoded
        let mut init_id_bytes = [0u8; 16];
        getrandom::fill(&mut init_id_bytes)
            .map_err(|e| CoreError::Engine(format!("CSPRNG failed: {e}")))?;
        let init_id = hex::encode(init_id_bytes);

        // 9. Build transcript
        let transcript_hash = build_sharing_transcript(
            &init_id,
            &self.identity,
            &recipient_identity,
            &sender_ephemeral_ek,
            &prekey.xwing_ek,
            &kem_ciphertext,
            &prekey.prekey_id,
        );

        // 10. Derive key schedule
        let key_schedule = BootstrapKeySchedule::derive(
            BootstrapProfile::RemoteSharing,
            BootstrapVersion::V1,
            bootstrap_secret,
            &transcript_hash,
        )?;

        // 11. Derive pairwise_secret and payload_encryption_key via HKDF
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

        // 12. Build confirmation MAC
        let confirmation = ConfirmationCode::new(
            BootstrapProfile::RemoteSharing,
            BootstrapVersion::V1,
            &key_schedule,
            transcript_hash,
        );
        let mac = confirmation.confirmation_mac(BootstrapRole::Initiator);
        let mut confirmation_mac = [0u8; 32];
        confirmation_mac.copy_from_slice(&mac);

        // 13. Encrypt inner payload
        let inner_payload = SharingInitPayload {
            display_name: display_name.to_string(),
            offered_scopes: offered_scopes.clone(),
            sender_sharing_id: self.sharing_id.clone(),
        };
        let inner_json = serde_json::to_vec(&inner_payload)?;
        let context = EnvelopeContext {
            profile: BootstrapProfile::RemoteSharing,
            version: BootstrapVersion::V1,
            sender_role: BootstrapRole::Initiator,
            purpose: b"sharing_init_payload",
            session_id: init_id.as_bytes(),
            transcript_hash: &transcript_hash,
        };
        let encrypted_payload =
            EncryptedEnvelope::seal(&payload_encryption_key, &inner_json, &context)?;

        // 14. Build SharingInit
        let sharing_init = SharingInit {
            version: BootstrapVersion::V1,
            init_id: init_id.clone(),
            sender_identity: self.identity.clone(),
            sender_ephemeral_ek,
            kem_ciphertext,
            target_prekey_id: prekey.prekey_id.clone(),
            confirmation_mac,
            encrypted_payload,
        };

        // 15. Serialize and upload
        let canonical_bytes = sharing_init.to_bytes();
        relay
            .upload_sharing_init(
                &init_id,
                recipient_sharing_id,
                &self.sharing_id,
                &canonical_bytes,
            )
            .await
            .map_err(|e| CoreError::Engine(format!("failed to upload sharing init: {e}")))?;

        Ok(SharingInitResult {
            pairwise_secret,
            init_id,
            recipient_identity,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::mock_sharing_relay::MockSharingRelay;

    const TEST_DEK_SENDER: [u8; 32] = [0xAA; 32];
    const TEST_DEK_RECIPIENT: [u8; 32] = [0xBB; 32];

    fn sender_sharing_id_bytes() -> [u8; 16] {
        [0x11; 16]
    }

    fn sender_sharing_id() -> String {
        hex::encode(sender_sharing_id_bytes())
    }

    fn make_sender() -> SharingSender {
        let sid = sender_sharing_id();
        SharingSender::from_dek(&TEST_DEK_SENDER, &sid, &sender_sharing_id_bytes(), 0).unwrap()
    }

    #[tokio::test]
    async fn recipient_bundle_sharing_id_mismatch_rejected() {
        let relay = MockSharingRelay::new();
        let now = 1_700_000_000i64;
        let requested_sharing_id = "22".repeat(16);
        let actual_sharing_id = "33".repeat(16);
        let actual_sharing_id_bytes = [0x33; 16];

        let seed =
            derive_sharing_identity_seed(&TEST_DEK_RECIPIENT, &actual_sharing_id_bytes, 0).unwrap();
        let mut seed_arr = [0u8; 32];
        seed_arr.copy_from_slice(&seed);

        let (ed25519_sk, ed25519_pk) = derive_sharing_ed25519_keypair(&seed_arr).unwrap();
        let (ml_dsa_sk, ml_dsa_pk) = derive_sharing_ml_dsa_keypair(&seed_arr).unwrap();
        seed_arr.fill(0);

        let identity = SharingIdentityBundle::sign(
            actual_sharing_id,
            0,
            ed25519_pk,
            ml_dsa_pk,
            &ed25519_sk,
            &ml_dsa_sk,
        );

        let prekey_dk = XWingKem::decapsulation_key_from_bytes(&[0x44; 32]);
        let prekey = SignedPrekey::sign(
            "pk-1".to_string(),
            "device-1".to_string(),
            XWingKem::encapsulation_key_bytes(&prekey_dk),
            now,
            &ed25519_sk,
            &ml_dsa_sk,
        );

        relay
            .publish_identity(&requested_sharing_id, &identity.to_bytes())
            .await
            .unwrap();
        relay
            .publish_prekey(
                &requested_sharing_id,
                "device-1",
                &prekey.prekey_id,
                &prekey.to_bytes(),
            )
            .await
            .unwrap();

        let sender = make_sender();
        let err = sender
            .initiate(&relay, &requested_sharing_id, "Alice", vec![], now)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("unexpected sharing_id"),
            "expected sharing_id mismatch error, got: {err}"
        );
    }
}
