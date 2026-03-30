//! High-level pairing orchestration: create and join sync groups.
//!
//! The `PairingService` wraps the relay, secure store, and crypto layers to
//! provide a simple API for multi-device pairing. The full crypto handshake
//! (SAS verification, signed keyrings) will be refined later — this module
//! establishes the API surface and basic key derivation flow.

use std::sync::Arc;

use crate::epoch::EpochManager;
use crate::error::{CoreError, Result};
use crate::pairing::models::*;
use crate::relay::SyncRelay;
use crate::secure_store::SecureStore;
use prism_sync_crypto::{mnemonic, DeviceSecret, DeviceSigningKey, KeyHierarchy};

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

    /// Create a new sync group (first device).
    ///
    /// 1. Generates a BIP39 mnemonic (or uses `mnemonic_override`).
    /// 2. Initializes a `KeyHierarchy` with `password + mnemonic`.
    /// 3. Generates a unique `sync_id`.
    /// 4. Builds `SyncGroupCredentials` and an `Invite`.
    /// 5. Generates a device identity and registers with the relay.
    pub async fn create_sync_group(
        &self,
        password: &str,
        relay_url: &str,
        mnemonic_override: Option<String>,
        sync_id_override: Option<String>,
    ) -> Result<(SyncGroupCredentials, Invite)> {
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

        // 5. Generate device identity
        let device_secret = DeviceSecret::generate();
        let device_id = crate::node_id::generate_node_id();
        let signing_key = device_secret
            .ed25519_keypair(&device_id)
            .map_err(CoreError::Crypto)?;
        let exchange_key = device_secret
            .x25519_keypair(&device_id)
            .map_err(CoreError::Crypto)?;

        // 5b. Pre-generate a device_id for the joining device (snapshot targeting)
        let joiner_device_id = crate::node_id::generate_node_id();

        // 6. Sign the invitation with the inviter's Ed25519 key (CRITICAL-1)
        let signing_data = build_invitation_signing_data(
            &sync_id,
            relay_url,
            &wrapped_dek,
            &salt,
            &device_id,
            &signing_key.public_key_bytes(),
            Some(&joiner_device_id),
            0,
            &[],
        );
        let signature = signing_key.sign(&signing_data);
        let signed_invitation_payload = crate::relay::traits::SignedInvitationPayload {
            sync_id: sync_id.clone(),
            relay_url: relay_url.to_string(),
            wrapped_dek: hex::encode(&wrapped_dek),
            salt: hex::encode(&salt),
            inviter_device_id: device_id.clone(),
            inviter_ed25519_pk: hex::encode(signing_key.public_key_bytes()),
            signature: hex::encode(&signature),
            joiner_device_id: Some(joiner_device_id.clone()),
            current_epoch: 0,
            epoch_key_hex: String::new(),
        };
        let signed_invitation_hex = hex::encode(&signature);

        // 7. Build signed keyring (JSON device records signed by inviter)
        let keyring_json = serde_json::to_vec(&serde_json::json!([{
            "sync_id": &sync_id,
            "device_id": &device_id,
            "ed25519_public_key": signing_key.public_key_bytes().to_vec(),
            "x25519_public_key": exchange_key.public_key_bytes().to_vec(),
            "status": "active",
        }]))
        .unwrap_or_default();
        let keyring_signature = signing_key.sign(&keyring_json);
        let signed_keyring = [keyring_signature, keyring_json].concat();

        // 8. Build PairingResponse for the Invite
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
            joiner_device_id: Some(joiner_device_id.clone()),
            current_epoch: 0,
            epoch_key: vec![],
        };

        // 9. Fetch registration nonce and build challenge-response (CRITICAL-2)
        let nonce = self
            .relay
            .get_registration_nonce()
            .await
            .map_err(|e| CoreError::Relay {
                message: format!("nonce fetch: {e}"),
                kind: crate::error::RelayErrorCategory::Network,
                status: None,
            })?;

        // Build canonical challenge data matching the relay's verification format:
        // "PRISM_SYNC_CHALLENGE_V1" || 0x00 || len_prefixed(sync_id) || len_prefixed(device_id) || len_prefixed(nonce)
        let mut challenge_data = Vec::new();
        challenge_data.extend_from_slice(b"PRISM_SYNC_CHALLENGE_V1\x00");
        fn write_len_prefixed(buf: &mut Vec<u8>, data: &[u8]) {
            buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
            buf.extend_from_slice(data);
        }
        write_len_prefixed(&mut challenge_data, sync_id.as_bytes());
        write_len_prefixed(&mut challenge_data, device_id.as_bytes());
        write_len_prefixed(&mut challenge_data, nonce.as_bytes());
        let challenge_signature = signing_key.sign(&challenge_data);

        // 10. Register with relay using signed challenge
        let register_req = crate::relay::traits::RegisterRequest {
            device_id: device_id.clone(),
            signing_public_key: signing_key.public_key_bytes().to_vec(),
            x25519_public_key: exchange_key.public_key_bytes().to_vec(),
            registration_challenge: challenge_signature,
            nonce,
            signed_invitation: Some(signed_invitation_payload),
        };

        let register_response = self
            .relay
            .register_device(register_req)
            .await
            .map_err(|e| CoreError::Relay {
                message: format!("registration failed: {e}"),
                kind: crate::error::RelayErrorCategory::Other,
                status: None,
            })?;

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

        Ok((credentials, Invite::new(response)))
    }

    /// Join an existing sync group (second+ device).
    ///
    /// Derives the key hierarchy from the pairing response and the user's
    /// password. The joining device must enter the *same* password that was
    /// used to create the sync group.
    ///
    /// Verifies the invitation signature before trusting the payload (CRITICAL-1).
    /// Registers with the relay using challenge-response (CRITICAL-2).
    pub async fn join_sync_group(
        &self,
        response: &PairingResponse,
        password: &str,
    ) -> Result<KeyHierarchy> {
        response
            .validate_epoch_fields()
            .map_err(|e| CoreError::Engine(format!("invalid pairing response: {e}")))?;

        // 1. Verify the invitation signature (CRITICAL-1)
        let inviter_pk: [u8; 32] = response
            .inviter_ed25519_pk
            .clone()
            .try_into()
            .map_err(|_| CoreError::Engine("invalid inviter public key length".into()))?;

        let signing_data = build_invitation_signing_data(
            &response.sync_id,
            &response.relay_url,
            &response.wrapped_dek,
            &response.salt,
            &response.inviter_device_id,
            &inviter_pk,
            response.joiner_device_id.as_deref(),
            response.current_epoch,
            &response.epoch_key,
        );

        let sig_bytes = prism_sync_crypto::hex::decode(&response.signed_invitation)
            .map_err(CoreError::Crypto)?;

        DeviceSigningKey::verify(&inviter_pk, &signing_data, &sig_bytes)
            .map_err(|e| CoreError::Engine(format!("invitation signature invalid: {e}")))?;

        // 2. Unlock key hierarchy
        let secret_key = mnemonic::to_bytes(&response.mnemonic).map_err(CoreError::Crypto)?;

        let mut key_hierarchy = KeyHierarchy::new();
        key_hierarchy
            .unlock(password, &secret_key, &response.wrapped_dek, &response.salt)
            .map_err(CoreError::Crypto)?;

        // 3. Generate device identity for this (joining) device
        let device_secret = DeviceSecret::generate();
        let device_id = response
            .joiner_device_id
            .clone()
            .unwrap_or_else(crate::node_id::generate_node_id);
        let signing_key = device_secret
            .ed25519_keypair(&device_id)
            .map_err(CoreError::Crypto)?;
        let exchange_key = device_secret
            .x25519_keypair(&device_id)
            .map_err(CoreError::Crypto)?;

        // 4. Fetch registration nonce and build challenge-response (CRITICAL-2)
        let nonce = self
            .relay
            .get_registration_nonce()
            .await
            .map_err(|e| CoreError::Relay {
                message: format!("nonce fetch: {e}"),
                kind: crate::error::RelayErrorCategory::Network,
                status: None,
            })?;

        // Build canonical challenge data matching the relay's verification format
        let mut challenge_data = Vec::new();
        challenge_data.extend_from_slice(b"PRISM_SYNC_CHALLENGE_V1\x00");
        fn write_len_prefixed_join(buf: &mut Vec<u8>, data: &[u8]) {
            buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
            buf.extend_from_slice(data);
        }
        write_len_prefixed_join(&mut challenge_data, response.sync_id.as_bytes());
        write_len_prefixed_join(&mut challenge_data, device_id.as_bytes());
        write_len_prefixed_join(&mut challenge_data, nonce.as_bytes());
        let challenge_signature = signing_key.sign(&challenge_data);

        // 5. Register with relay
        let join_invitation = crate::relay::traits::SignedInvitationPayload {
            sync_id: response.sync_id.clone(),
            relay_url: response.relay_url.clone(),
            wrapped_dek: hex::encode(&response.wrapped_dek),
            salt: hex::encode(&response.salt),
            inviter_device_id: response.inviter_device_id.clone(),
            inviter_ed25519_pk: hex::encode(&response.inviter_ed25519_pk),
            signature: response.signed_invitation.clone(),
            joiner_device_id: response.joiner_device_id.clone(),
            current_epoch: response.current_epoch,
            epoch_key_hex: hex::encode(&response.epoch_key),
        };
        let join_register_response = self
            .relay
            .register_device(crate::relay::traits::RegisterRequest {
                device_id: device_id.clone(),
                signing_public_key: signing_key.public_key_bytes().to_vec(),
                x25519_public_key: exchange_key.public_key_bytes().to_vec(),
                registration_challenge: challenge_signature,
                nonce,
                signed_invitation: Some(join_invitation),
            })
            .await
            .map_err(|e| CoreError::Relay {
                message: format!("registration failed: {e}"),
                kind: crate::error::RelayErrorCategory::Other,
                status: None,
            })?;

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

        Ok(key_hierarchy)
    }

    /// Access the underlying relay.
    pub fn relay(&self) -> &Arc<dyn SyncRelay> {
        &self.relay
    }

    /// Access the underlying secure store.
    pub fn secure_store(&self) -> &Arc<dyn SecureStore> {
        &self.secure_store
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::traits::*;
    use async_trait::async_trait;
    use futures_util::Stream;
    use std::collections::HashMap;
    use std::pin::Pin;
    use std::sync::Mutex;

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
        async fn get_registration_nonce(&self) -> std::result::Result<String, RelayError> {
            Ok(uuid::Uuid::new_v4().to_string())
        }
        async fn register_device(
            &self,
            _req: RegisterRequest,
        ) -> std::result::Result<RegisterResponse, RelayError> {
            Ok(RegisterResponse {
                device_session_token: "mock-session-token".to_string(),
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
        async fn dispose(&self) -> std::result::Result<(), RelayError> {
            unimplemented!()
        }
    }

    #[tokio::test]
    async fn create_sync_group_returns_credentials_and_invite() {
        let relay = Arc::new(MockRelay);
        let store = Arc::new(MemStore::default());
        let service = PairingService::new(relay, store.clone());

        let (creds, invite) = service
            .create_sync_group("test-password", "wss://relay.example.com", None, None)
            .await
            .unwrap();

        assert!(!creds.sync_id.is_empty());
        assert_eq!(creds.sync_id.len(), 64); // 32 bytes hex
        assert!(!creds.mnemonic.is_empty());
        assert!(!creds.wrapped_dek.is_empty());
        assert!(!creds.salt.is_empty());

        // Invite should reference same sync_id
        assert_eq!(invite.response().sync_id, creds.sync_id);
        assert_eq!(invite.response().relay_url, "wss://relay.example.com");

        // Credentials should be persisted
        let stored_id = store.get("sync_id").unwrap().unwrap();
        assert_eq!(String::from_utf8(stored_id).unwrap(), creds.sync_id);
    }

    #[tokio::test]
    async fn create_sync_group_persists_device_identity() {
        let relay = Arc::new(MockRelay);
        let store = Arc::new(MemStore::default());
        let service = PairingService::new(relay, store.clone());

        let (_creds, _invite) = service
            .create_sync_group("test-password", "wss://relay.example.com", None, None)
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
        let (_creds, invite) = service
            .create_sync_group("my-password", "wss://relay.example.com", None, None)
            .await
            .unwrap();

        // Now join using the invite's response
        let join_store = Arc::new(MemStore::default());
        let join_service = PairingService::new(Arc::new(MockRelay), join_store.clone());

        let kh = join_service
            .join_sync_group(invite.response(), "my-password")
            .await
            .unwrap();

        assert!(kh.is_unlocked());
        // Should be able to derive database key
        assert!(kh.database_key().is_ok());
    }

    #[tokio::test]
    async fn join_with_wrong_password_fails() {
        let relay = Arc::new(MockRelay);
        let store = Arc::new(MemStore::default());
        let service = PairingService::new(relay, store);

        let (_creds, invite) = service
            .create_sync_group("correct-password", "wss://relay.example.com", None, None)
            .await
            .unwrap();

        let join_store = Arc::new(MemStore::default());
        let join_service = PairingService::new(Arc::new(MockRelay), join_store);

        let result = join_service
            .join_sync_group(invite.response(), "wrong-password")
            .await;
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
            joiner_device_id: Some("abcdef123456".to_string()),
            current_epoch: 1,
            epoch_key: vec![],
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
            .create_sync_group("pw", "wss://relay.example.com", Some(custom.clone()), None)
            .await
            .unwrap();

        assert_eq!(creds.mnemonic, custom);
    }

    #[tokio::test]
    async fn invitation_sign_and_verify_roundtrip() {
        let relay = Arc::new(MockRelay);
        let store = Arc::new(MemStore::default());
        let service = PairingService::new(relay, store);

        let (_creds, invite) = service
            .create_sync_group("test-pw", "wss://relay.example.com", None, None)
            .await
            .unwrap();

        let resp = invite.response();

        // The signed_invitation should be non-empty (hex-encoded Ed25519 signature)
        assert!(!resp.signed_invitation.is_empty());
        assert_eq!(resp.signed_invitation.len(), 128); // 64-byte signature hex-encoded

        // The inviter fields should be populated
        assert!(!resp.inviter_device_id.is_empty());
        assert_eq!(resp.inviter_ed25519_pk.len(), 32);

        // Verify the signature manually
        let inviter_pk: [u8; 32] = resp.inviter_ed25519_pk.clone().try_into().unwrap();
        let signing_data = build_invitation_signing_data(
            &resp.sync_id,
            &resp.relay_url,
            &resp.wrapped_dek,
            &resp.salt,
            &resp.inviter_device_id,
            &inviter_pk,
            resp.joiner_device_id.as_deref(),
            resp.current_epoch,
            &resp.epoch_key,
        );
        let sig_bytes = prism_sync_crypto::hex::decode(&resp.signed_invitation).unwrap();
        DeviceSigningKey::verify(&inviter_pk, &signing_data, &sig_bytes).unwrap();
    }

    #[tokio::test]
    async fn tampered_invitation_rejected() {
        let relay = Arc::new(MockRelay);
        let store = Arc::new(MemStore::default());
        let service = PairingService::new(relay, store);

        let (_creds, invite) = service
            .create_sync_group("test-pw", "wss://relay.example.com", None, None)
            .await
            .unwrap();

        // Tamper with the sync_id in the response
        let mut tampered = invite.response().clone();
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

        let (_creds, invite) = service
            .create_sync_group("test-pw", "wss://relay.example.com", None, None)
            .await
            .unwrap();

        // Replace the inviter's public key with a different key
        let mut tampered = invite.response().clone();
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

    #[tokio::test]
    async fn challenge_signature_present_in_registration() {
        // Use a relay that captures the registration request
        use std::sync::Mutex as StdMutex;

        struct CapturingRelay {
            captured_req: StdMutex<Option<RegisterRequest>>,
        }

        #[async_trait]
        impl SyncRelay for CapturingRelay {
            async fn get_registration_nonce(&self) -> std::result::Result<String, RelayError> {
                Ok("test-nonce-12345".to_string())
            }
            async fn register_device(
                &self,
                req: RegisterRequest,
            ) -> std::result::Result<RegisterResponse, RelayError> {
                *self.captured_req.lock().unwrap() = Some(req);
                Ok(RegisterResponse {
                    device_session_token: "mock-token".to_string(),
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
            .create_sync_group("pw", "wss://relay.example.com", None, None)
            .await
            .unwrap();

        let captured = relay.captured_req.lock().unwrap();
        let req = captured.as_ref().expect("registration request captured");

        // Challenge signature should be 64 bytes (Ed25519)
        assert_eq!(req.registration_challenge.len(), 64);
        // Nonce should be the one we returned
        assert_eq!(req.nonce, "test-nonce-12345");
        // signed_invitation should be present
        assert!(req.signed_invitation.is_some());
    }
}
