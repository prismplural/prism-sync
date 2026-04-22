use std::sync::Arc;

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use prism_sync_crypto::DeviceSecret;
use zeroize::Zeroizing;

use crate::epoch::decapsulate_and_decrypt_artifact;
use crate::error::{CoreError, Result};
use crate::relay::SyncRelay;
use crate::secure_store::SecureStore;
use crate::storage::{StorageError, SyncStorage};

#[derive(Debug, Clone, Copy)]
pub(crate) struct RecoveryCommitToken {
    pub previous_epoch: i32,
}

#[async_trait]
pub(crate) trait EpochRecoverer: Send + Sync {
    async fn recover(&self, epoch: u32) -> Result<Zeroizing<Vec<u8>>>;

    async fn commit_recovered_epoch(
        &self,
        epoch: u32,
        key_bytes: &[u8],
    ) -> Result<RecoveryCommitToken>;

    async fn rollback_recovered_epoch(&self, epoch: u32, token: RecoveryCommitToken) -> Result<()>;
}

pub(crate) struct KeyHierarchyRecoverer {
    relay: Arc<dyn SyncRelay>,
    storage: Arc<dyn SyncStorage>,
    secure_store: Arc<dyn SecureStore>,
    device_secret: DeviceSecret,
    sync_id: String,
    device_id: String,
}

impl KeyHierarchyRecoverer {
    pub(crate) fn new(
        relay: Arc<dyn SyncRelay>,
        storage: Arc<dyn SyncStorage>,
        secure_store: Arc<dyn SecureStore>,
        device_secret: &DeviceSecret,
        sync_id: String,
        device_id: String,
    ) -> Result<Self> {
        Ok(Self {
            relay,
            storage,
            secure_store,
            device_secret: DeviceSecret::from_bytes(device_secret.as_bytes().to_vec())?,
            sync_id,
            device_id,
        })
    }
}

#[async_trait]
impl EpochRecoverer for KeyHierarchyRecoverer {
    async fn recover(&self, epoch: u32) -> Result<Zeroizing<Vec<u8>>> {
        let xwing = self.device_secret.xwing_keypair(&self.device_id)?;
        let artifact =
            self.relay.get_rekey_artifact(epoch as i32, &self.device_id).await?.ok_or_else(
                || {
                    CoreError::Storage(StorageError::Logic(format!(
                        "no rekey artifact for epoch {epoch}"
                    )))
                },
            )?;
        decapsulate_and_decrypt_artifact(&artifact, &xwing, epoch, &self.device_id)
    }

    async fn commit_recovered_epoch(
        &self,
        epoch: u32,
        key_bytes: &[u8],
    ) -> Result<RecoveryCommitToken> {
        commit_recovered_epoch_material(
            self.storage.clone(),
            self.secure_store.clone(),
            &self.sync_id,
            epoch,
            key_bytes,
        )
        .await
    }

    async fn rollback_recovered_epoch(&self, epoch: u32, token: RecoveryCommitToken) -> Result<()> {
        rollback_recovered_epoch_material(
            self.storage.clone(),
            self.secure_store.clone(),
            &self.sync_id,
            epoch,
            token,
        )
        .await
    }
}

pub(crate) fn persist_epoch_key(
    secure_store: &dyn SecureStore,
    epoch: u32,
    key_bytes: &[u8],
) -> Result<()> {
    let store_key = format!("epoch_key_{epoch}");
    let encoded = STANDARD.encode(key_bytes);
    secure_store.set(&store_key, encoded.as_bytes())
}

pub(crate) fn persist_epoch_cache(secure_store: &dyn SecureStore, epoch: i32) -> Result<()> {
    secure_store.set("epoch", epoch.to_string().as_bytes())
}

pub(crate) fn load_cached_epoch(secure_store: &dyn SecureStore) -> Result<Option<i32>> {
    let Some(bytes) = secure_store.get("epoch")? else {
        return Ok(None);
    };
    let raw = String::from_utf8(bytes).map_err(|e| {
        CoreError::Storage(StorageError::Logic(format!("invalid cached epoch utf8: {e}")))
    })?;
    let epoch = raw.parse::<i32>().map_err(|e| {
        CoreError::Storage(StorageError::Logic(format!("invalid cached epoch value: {e}")))
    })?;
    Ok(Some(epoch))
}

pub(crate) async fn commit_recovered_epoch_material(
    storage: Arc<dyn SyncStorage>,
    secure_store: Arc<dyn SecureStore>,
    sync_id: &str,
    epoch: u32,
    key_bytes: &[u8],
) -> Result<RecoveryCommitToken> {
    let sync_id_owned = sync_id.to_string();
    let storage_for_read = storage.clone();
    let previous_epoch = tokio::task::spawn_blocking(move || {
        Ok::<_, CoreError>(
            storage_for_read.get_sync_metadata(&sync_id_owned)?.map(|meta| meta.current_epoch),
        )
    })
    .await
    .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))??;
    let previous_epoch = match previous_epoch {
        Some(epoch) => epoch,
        None => load_cached_epoch(secure_store.as_ref())?.unwrap_or(0),
    };

    persist_epoch_key(secure_store.as_ref(), epoch, key_bytes)?;
    persist_epoch_cache(secure_store.as_ref(), epoch as i32)?;

    let sync_id_owned = sync_id.to_string();
    let storage_for_write = storage.clone();
    let write_result = tokio::task::spawn_blocking(move || {
        let mut tx = storage_for_write.begin_tx()?;
        tx.update_current_epoch(&sync_id_owned, epoch as i32)?;
        tx.commit()
    })
    .await
    .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))?;

    if let Err(error) = write_result {
        let _ = secure_store.delete(&format!("epoch_key_{epoch}"));
        let _ = persist_epoch_cache(secure_store.as_ref(), previous_epoch);
        return Err(error);
    }

    Ok(RecoveryCommitToken { previous_epoch })
}

pub(crate) async fn rollback_recovered_epoch_material(
    storage: Arc<dyn SyncStorage>,
    secure_store: Arc<dyn SecureStore>,
    sync_id: &str,
    epoch: u32,
    token: RecoveryCommitToken,
) -> Result<()> {
    secure_store.delete(&format!("epoch_key_{epoch}"))?;
    persist_epoch_cache(secure_store.as_ref(), token.previous_epoch)?;

    let sync_id_owned = sync_id.to_string();
    tokio::task::spawn_blocking(move || {
        let mut tx = storage.begin_tx()?;
        tx.update_current_epoch(&sync_id_owned, token.previous_epoch)?;
        tx.commit()
    })
    .await
    .map_err(|e| CoreError::Storage(StorageError::Logic(e.to_string())))??;

    Ok(())
}
