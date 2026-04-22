use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use async_trait::async_trait;
use chrono::Utc;

use super::sharing_relay::{PendingSharingInit, SharingRelay};
use super::traits::RelayError;

struct StoredInit {
    init_id: String,
    recipient_id: String,
    sender_id: String,
    payload: Vec<u8>,
    created_at: i64,
    consumed: bool,
}

struct MockSharingRelayState {
    /// sharing_id -> identity_bundle
    identities: HashMap<String, Vec<u8>>,
    /// (sharing_id, device_id) -> (prekey_id, prekey_bundle)
    prekeys: HashMap<(String, String), (String, Vec<u8>)>,
    init_payloads: Vec<StoredInit>,
    consumed_init_ids: HashSet<String>,
    /// The sharing_id of the "authenticated user" — used to resolve
    /// which pending inits belong to the caller in `fetch_pending_inits`.
    sharing_id: Option<String>,
}

/// In-memory mock implementation of [`SharingRelay`] for unit tests.
pub struct MockSharingRelay {
    state: Mutex<MockSharingRelayState>,
}

impl MockSharingRelay {
    /// Create a new empty mock sharing relay.
    pub fn new() -> Self {
        Self {
            state: Mutex::new(MockSharingRelayState {
                identities: HashMap::new(),
                prekeys: HashMap::new(),
                init_payloads: Vec::new(),
                consumed_init_ids: HashSet::new(),
                sharing_id: None,
            }),
        }
    }

    /// Set the sharing_id that the "authenticated user" resolves to.
    /// This is used by `fetch_pending_inits` to determine which payloads
    /// to return (those where `recipient_id` matches this sharing_id).
    pub fn set_sharing_id(&self, id: &str) {
        self.state.lock().unwrap().sharing_id = Some(id.to_string());
    }
}

impl Default for MockSharingRelay {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SharingRelay for MockSharingRelay {
    async fn publish_identity(
        &self,
        sharing_id: &str,
        identity_bundle: &[u8],
    ) -> Result<(), RelayError> {
        let mut state = self.state.lock().unwrap();
        state.identities.insert(sharing_id.to_string(), identity_bundle.to_vec());
        Ok(())
    }

    async fn publish_prekey(
        &self,
        sharing_id: &str,
        device_id: &str,
        prekey_id: &str,
        prekey_bundle: &[u8],
    ) -> Result<(), RelayError> {
        let mut state = self.state.lock().unwrap();
        state.prekeys.insert(
            (sharing_id.to_string(), device_id.to_string()),
            (prekey_id.to_string(), prekey_bundle.to_vec()),
        );
        Ok(())
    }

    async fn fetch_prekey_bundle(
        &self,
        sharing_id: &str,
    ) -> Result<Option<(Vec<u8>, Vec<u8>)>, RelayError> {
        let state = self.state.lock().unwrap();

        let identity_bundle = match state.identities.get(sharing_id) {
            Some(bundle) => bundle.clone(),
            None => return Ok(None),
        };

        // Find the first prekey for this sharing_id.
        let prekey_bundle = state
            .prekeys
            .iter()
            .find(|((sid, _), _)| sid == sharing_id)
            .map(|(_, (_, bundle))| bundle.clone());

        match prekey_bundle {
            Some(bundle) => Ok(Some((identity_bundle, bundle))),
            None => Ok(None),
        }
    }

    async fn upload_sharing_init(
        &self,
        init_id: &str,
        recipient_id: &str,
        sender_id: &str,
        payload: &[u8],
    ) -> Result<(), RelayError> {
        let mut state = self.state.lock().unwrap();

        // Reject duplicate init_id.
        if state.consumed_init_ids.contains(init_id)
            || state.init_payloads.iter().any(|p| p.init_id == init_id)
        {
            return Err(RelayError::Protocol { message: format!("Duplicate init_id: {init_id}") });
        }

        state.init_payloads.push(StoredInit {
            init_id: init_id.to_string(),
            recipient_id: recipient_id.to_string(),
            sender_id: sender_id.to_string(),
            payload: payload.to_vec(),
            created_at: Utc::now().timestamp(),
            consumed: false,
        });

        Ok(())
    }

    async fn fetch_pending_inits(&self) -> Result<Vec<PendingSharingInit>, RelayError> {
        let mut state = self.state.lock().unwrap();

        let sharing_id = state.sharing_id.clone().ok_or_else(|| RelayError::Auth {
            message: "MockSharingRelay: sharing_id not set (call set_sharing_id first)".to_string(),
        })?;

        let mut result = Vec::new();
        for init in state.init_payloads.iter_mut() {
            if init.recipient_id == sharing_id && !init.consumed {
                result.push(PendingSharingInit {
                    init_id: init.init_id.clone(),
                    sender_id: init.sender_id.clone(),
                    payload: init.payload.clone(),
                    created_at: init.created_at,
                });
                init.consumed = true;
            }
        }

        // Track consumed IDs.
        for p in &result {
            state.consumed_init_ids.insert(p.init_id.clone());
        }

        Ok(result)
    }

    async fn remove_identity(&self) -> Result<(), RelayError> {
        let mut state = self.state.lock().unwrap();

        let sharing_id = state.sharing_id.clone().ok_or_else(|| RelayError::Auth {
            message: "MockSharingRelay: sharing_id not set (call set_sharing_id first)".to_string(),
        })?;

        state.identities.remove(&sharing_id);
        state.prekeys.retain(|(sid, _), _| sid != &sharing_id);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn publish_identity_and_fetch() {
        let relay = MockSharingRelay::new();
        let identity = b"identity-bundle-data";
        let prekey = b"prekey-bundle-data";

        relay.publish_identity("alice", identity).await.unwrap();
        relay.publish_prekey("alice", "device-1", "prekey-1", prekey).await.unwrap();

        let bundle = relay.fetch_prekey_bundle("alice").await.unwrap();
        assert!(bundle.is_some());
        let (id_bytes, pk_bytes) = bundle.unwrap();
        assert_eq!(id_bytes, identity);
        assert_eq!(pk_bytes, prekey);
    }

    #[tokio::test]
    async fn fetch_nonexistent_returns_none() {
        let relay = MockSharingRelay::new();
        let bundle = relay.fetch_prekey_bundle("nonexistent").await.unwrap();
        assert!(bundle.is_none());
    }

    #[tokio::test]
    async fn fetch_identity_without_prekey_returns_none() {
        let relay = MockSharingRelay::new();
        relay.publish_identity("alice", b"identity").await.unwrap();

        // Identity exists but no prekey — returns None.
        let bundle = relay.fetch_prekey_bundle("alice").await.unwrap();
        assert!(bundle.is_none());
    }

    #[tokio::test]
    async fn upload_and_fetch_pending_inits() {
        let relay = MockSharingRelay::new();
        relay.set_sharing_id("bob");

        relay.upload_sharing_init("init-1", "bob", "alice", b"encrypted-payload").await.unwrap();

        let pending = relay.fetch_pending_inits().await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].init_id, "init-1");
        assert_eq!(pending[0].sender_id, "alice");
        assert_eq!(pending[0].payload, b"encrypted-payload");
    }

    #[tokio::test]
    async fn fetch_pending_marks_consumed() {
        let relay = MockSharingRelay::new();
        relay.set_sharing_id("bob");

        relay.upload_sharing_init("init-1", "bob", "alice", b"payload").await.unwrap();

        // First fetch returns the payload.
        let pending = relay.fetch_pending_inits().await.unwrap();
        assert_eq!(pending.len(), 1);

        // Second fetch returns empty (already consumed).
        let pending = relay.fetch_pending_inits().await.unwrap();
        assert!(pending.is_empty());
    }

    #[tokio::test]
    async fn duplicate_init_id_rejected() {
        let relay = MockSharingRelay::new();

        relay.upload_sharing_init("init-1", "bob", "alice", b"payload-1").await.unwrap();

        let result = relay.upload_sharing_init("init-1", "bob", "alice", b"payload-2").await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), RelayError::Protocol { .. }));
    }

    #[tokio::test]
    async fn remove_identity_clears_everything() {
        let relay = MockSharingRelay::new();
        relay.set_sharing_id("alice");

        relay.publish_identity("alice", b"identity").await.unwrap();
        relay.publish_prekey("alice", "device-1", "pk-1", b"prekey").await.unwrap();

        // Verify data exists.
        // Note: fetch_prekey_bundle is unauthenticated, doesn't need set_sharing_id.
        let bundle = relay.fetch_prekey_bundle("alice").await.unwrap();
        assert!(bundle.is_some());

        // Remove identity.
        relay.remove_identity().await.unwrap();

        // Identity and prekeys should be gone.
        let bundle = relay.fetch_prekey_bundle("alice").await.unwrap();
        assert!(bundle.is_none());
    }

    #[tokio::test]
    async fn pending_inits_only_for_configured_sharing_id() {
        let relay = MockSharingRelay::new();
        relay.set_sharing_id("bob");

        // Upload inits for different recipients.
        relay.upload_sharing_init("init-1", "bob", "alice", b"for-bob").await.unwrap();
        relay.upload_sharing_init("init-2", "charlie", "alice", b"for-charlie").await.unwrap();

        // Only bob's init should be returned.
        let pending = relay.fetch_pending_inits().await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].init_id, "init-1");
    }

    #[tokio::test]
    async fn publish_identity_replaces_existing() {
        let relay = MockSharingRelay::new();

        relay.publish_identity("alice", b"bundle-v1").await.unwrap();
        relay.publish_identity("alice", b"bundle-v2").await.unwrap();
        relay.publish_prekey("alice", "d1", "pk1", b"prekey").await.unwrap();

        let (identity, _) = relay.fetch_prekey_bundle("alice").await.unwrap().unwrap();
        assert_eq!(identity, b"bundle-v2");
    }
}
