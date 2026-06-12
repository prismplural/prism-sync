//! Epoch rotation and rekey.
//!
//! When a device is revoked, the sync group rotates to a new epoch with a
//! fresh epoch key. The revoking device posts per-device wrapped epoch keys
//! to the relay so that remaining devices can recover the new key. Revoked
//! devices never receive a wrapped key for the new epoch.
//!
//! ## Artifact format (version 2)
//!
//! ```text
//! byte 0:       version = 0x02
//! bytes 1-1120: X-Wing ciphertext (1120 bytes)
//! bytes 1121+:  XChaCha20-Poly1305(epoch_key, AAD = v2|epoch|device_id) (~72 bytes)
//! Total: ~1193 bytes
//! ```

use std::collections::{BTreeMap, HashMap};

use crate::error::{CoreError, Result};
use crate::pairing::{compute_epoch_key_hash, SignedRegistrySnapshot};
use crate::recovery::{persist_epoch_cache, persist_epoch_key};
use crate::relay::{DeviceInfo, SyncRelay};
use crate::secure_store::SecureStore;
use crate::storage::{DeviceRecord, StorageError};
use prism_sync_crypto::{DeviceSecret, DeviceXWingKey, KeyHierarchy};
use zeroize::Zeroizing;

/// Proof that an epoch key is safe to install. Private fields → the only ways
/// to construct one are the two constructors below.
pub(crate) struct VerifiedEpochKey {
    epoch: u32,
    key: Zeroizing<Vec<u8>>,
}

impl VerifiedEpochKey {
    /// Locally generated — trusted by origin.
    pub(crate) fn generated(epoch: u32, key: Zeroizing<Vec<u8>>) -> Self {
        Self { epoch, key }
    }

    /// Adopted from a relay artifact — MUST match a signature-verified registry hash.
    /// `snapshot` MUST be a value the caller already obtained via
    /// `DeviceRegistryManager::verify_signed_registry_snapshot` (signature-checked).
    pub(crate) fn verify(
        epoch: u32,
        key: Zeroizing<Vec<u8>>,
        snapshot: &SignedRegistrySnapshot,
    ) -> Result<Self> {
        let arr: [u8; 32] = key.as_slice().try_into().map_err(|_| {
            CoreError::Crypto(prism_sync_crypto::CryptoError::InvalidKeyMaterial(format!(
                "epoch {epoch} key has unexpected length {}",
                key.len()
            )))
        })?;
        let expected = snapshot.epoch_key_hashes.get(&epoch).ok_or_else(|| {
            CoreError::Engine(format!(
                "signed registry has no epoch_key_hash for epoch {epoch}"
            ))
        })?;
        if compute_epoch_key_hash(&arr) != *expected {
            return Err(CoreError::Engine(format!(
                "epoch {epoch} key hash mismatch vs signed registry — refusing to install"
            )));
        }
        Ok(Self { epoch, key })
    }
}

/// The ONLY core installer for epoch>0 keys.
pub(crate) fn install_epoch_key(kh: &mut KeyHierarchy, vk: VerifiedEpochKey) {
    kh.store_epoch_key(vk.epoch, vk.key);
}

/// Classification of the relay's 400 responses to a standalone `/rekey`, used by
/// the rekey-needed reaction to decide between retrying (the active set
/// moved) and reconciling (a peer already rotated).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RekeyConflict {
    /// `wrapped_keys must match active device set exactly` — the survivor set
    /// changed between our list and the relay's check; rebuild and retry.
    SurvivorSetMismatch,
    /// `Rekey epoch must be current_epoch + 1` — another responder already
    /// advanced the epoch; reconcile rather than retry.
    EpochMismatch,
    /// Anything else — propagate unchanged.
    Other,
}

/// Match the relay's standalone-rekey 400 bodies by their (stable) message text.
/// Both arrive as `CoreError::Relay { source: RelayError::Protocol { message } }`
/// because the HTTP transport maps an un-structured 400 to `Protocol`.
fn classify_rekey_conflict(error: &CoreError) -> RekeyConflict {
    let message = error.to_string();
    if message.contains("wrapped_keys must match the active device set exactly") {
        RekeyConflict::SurvivorSetMismatch
    } else if message.contains("Rekey epoch must be current_epoch + 1") {
        RekeyConflict::EpochMismatch
    } else {
        RekeyConflict::Other
    }
}

/// X-Wing ciphertext size in bytes.
const XWING_CT_LEN: usize = 1120;
/// Artifact version byte.
const ARTIFACT_VERSION: u8 = 0x02;
/// Minimum artifact length: 1 version byte + 1120 ciphertext bytes.
const MIN_ARTIFACT_LEN: usize = 1 + XWING_CT_LEN;
/// Defensive upper bound for v2 artifacts.
const MAX_ARTIFACT_LEN: usize = 1536;

pub(crate) fn build_rekey_artifact_aad(epoch: u32, device_id: &str) -> Vec<u8> {
    format!("prism_epoch_rekey_v2|{epoch}|{device_id}").into_bytes()
}

/// Decapsulate and decrypt a v2 rekey artifact into a raw epoch key.
pub(crate) fn decapsulate_and_decrypt_artifact(
    artifact: &[u8],
    xwing: &DeviceXWingKey,
    epoch: u32,
    device_id: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    // 1. Verify version byte
    if artifact.first() != Some(&ARTIFACT_VERSION) {
        return Err(CoreError::Crypto(prism_sync_crypto::CryptoError::DecryptionFailed(format!(
            "unsupported rekey artifact version: {}",
            artifact.first().copied().unwrap_or(0)
        ))));
    }

    // 2. Validate artifact length
    if artifact.len() < MIN_ARTIFACT_LEN {
        return Err(CoreError::Crypto(prism_sync_crypto::CryptoError::DecryptionFailed(format!(
            "rekey artifact too short: {} bytes (minimum {})",
            artifact.len(),
            MIN_ARTIFACT_LEN
        ))));
    }
    if artifact.len() > MAX_ARTIFACT_LEN {
        return Err(CoreError::Crypto(prism_sync_crypto::CryptoError::DecryptionFailed(format!(
            "rekey artifact too large: {} bytes (maximum {})",
            artifact.len(),
            MAX_ARTIFACT_LEN
        ))));
    }

    // 3. Extract ciphertext and encrypted epoch key
    let ciphertext = &artifact[1..1 + XWING_CT_LEN];
    let encrypted_epoch_key = &artifact[1 + XWING_CT_LEN..];

    // 4. Decapsulate: recover shared secret
    let shared_secret = xwing.decapsulate(ciphertext).map_err(CoreError::Crypto)?;

    // 5. Derive unwrap key via HKDF — salt binds epoch + device_id to prevent
    //    artifact replay across epochs or devices.
    let mut salt = Vec::with_capacity(4 + device_id.len());
    salt.extend_from_slice(&epoch.to_le_bytes());
    salt.extend_from_slice(device_id.as_bytes());
    let unwrap_key =
        prism_sync_crypto::kdf::derive_subkey(&shared_secret, &salt, b"prism_epoch_rekey_v2")
            .map_err(CoreError::Crypto)?;

    // 6. Decrypt epoch key with AAD binding the inner AEAD to epoch + device.
    let aad = build_rekey_artifact_aad(epoch, device_id);
    let epoch_key_bytes =
        prism_sync_crypto::aead::xchacha_decrypt_aead(&unwrap_key, encrypted_epoch_key, &aad)
            .map_err(CoreError::Crypto)?;

    Ok(Zeroizing::new(epoch_key_bytes))
}

/// Stateless helper for epoch rotation operations.
pub struct EpochManager;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochCatchUpResult {
    pub start_epoch: u32,
    pub relay_epoch: u32,
    pub recovered_through: u32,
}

impl EpochManager {
    /// Handle an epoch rotation event: fetch the new epoch key from the relay,
    /// unwrap it via X-Wing KEM + HKDF, and store it in the key hierarchy.
    ///
    /// This is called when the local device receives an `EpochRotated` or
    /// `DeviceRevoked` notification. The relay holds a per-device wrapped
    /// epoch key (v2 format) that was posted by the device that initiated the
    /// revocation.
    ///
    /// `registry` MUST be a signature-verified [`SignedRegistrySnapshot`]
    /// (obtained via `DeviceRegistryManager::verify_signed_registry_snapshot`).
    /// The decapsulated key is installed only if it is byte-for-byte bound to
    /// `registry.epoch_key_hashes[new_epoch]` — otherwise this returns `Err`
    /// and nothing is installed.
    pub async fn handle_rotation(
        relay: &dyn SyncRelay,
        key_hierarchy: &mut KeyHierarchy,
        new_epoch: u32,
        device_id: &str,
        xwing_key: &DeviceXWingKey,
        registry: &SignedRegistrySnapshot,
    ) -> Result<()> {
        let artifact =
            relay.get_rekey_artifact(new_epoch as i32, device_id).await?.ok_or_else(|| {
                CoreError::Storage(StorageError::Logic(format!(
                    "no rekey artifact for epoch {new_epoch}"
                )))
            })?;
        let epoch_key_bytes =
            decapsulate_and_decrypt_artifact(&artifact, xwing_key, new_epoch, device_id)?;

        // 7. Verify the decapsulated key against the signature-verified
        //    registry hash before installing — a malicious relay must not be
        //    able to inject an attacker-chosen epoch key via this path.
        let vk = VerifiedEpochKey::verify(new_epoch, epoch_key_bytes, registry)?;
        install_epoch_key(key_hierarchy, vk);
        Ok(())
    }

    /// Generate a fresh epoch key and wrap it for all active devices, optionally
    /// excluding one target device (for atomic revocation).
    ///
    /// Returns `(epoch_key, wrapped_keys)` where `wrapped_keys` maps device_id
    /// to a v2 artifact blob. The sender does not need to provide its own key —
    /// encapsulation uses only the recipient's X-Wing public key.
    pub async fn prepare_wrapped_keys(
        relay: &dyn SyncRelay,
        new_epoch: u32,
        excluded_device_id: Option<&str>,
        pinned: &[DeviceRecord],
    ) -> Result<(Zeroizing<Vec<u8>>, HashMap<String, Vec<u8>>)> {
        // 1. List active devices from relay
        let devices = relay.list_devices().await.map_err(|e| {
            CoreError::Storage(StorageError::Logic(format!("failed to list devices: {e}")))
        })?;

        Self::prepare_wrapped_keys_for_devices(&devices, new_epoch, excluded_device_id, pinned)
    }

    /// Wrap a fresh epoch key for each surviving relay-listed device, but only
    /// after cross-checking every recipient against the locally-pinned device
    /// registry `pinned` (obtained via `DeviceRegistryManager::list_devices`).
    ///
    /// A device is wrapped to ONLY if it is present in `pinned`, its pinned
    /// `status` is `active`, AND its pinned `x_wing_public_key` matches the
    /// relay-supplied one byte-for-byte. Any active recipient that is unknown to
    /// `pinned`, that the pinned registry records as revoked, or whose key
    /// differs, is a hard `Err` — an injected/swapped/un-revoked recipient must
    /// abort the whole rotation rather than being silently skipped.
    ///
    /// The pinned-status gate is the client-side enforcement of an explicit user
    /// revocation: the pinned registry deliberately retains
    /// `status == "revoked"` entries, so a lying relay that re-lists an
    /// explicitly-revoked device as `active` (carrying its still-registered
    /// X-Wing key, which the relay holds) cannot steer a new-epoch wrap artifact
    /// to it. Relay-asserted 90d auto-revocation is unavoidably honest-relay-only
    /// (the relay alone knows last-seen time, and an auto-revoked device's pinned
    /// record is still `active`); registry-asserted explicit revocation is, after
    /// this gate, enforced here regardless of what the relay claims.
    #[allow(clippy::type_complexity)]
    pub fn prepare_wrapped_keys_for_devices(
        devices: &[DeviceInfo],
        new_epoch: u32,
        excluded_device_id: Option<&str>,
        pinned: &[DeviceRecord],
    ) -> Result<(Zeroizing<Vec<u8>>, HashMap<String, Vec<u8>>)> {
        // 1. Generate a random 32-byte epoch key
        let mut epoch_key_bytes = Zeroizing::new([0u8; 32]);
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, epoch_key_bytes.as_mut());

        // 2. For each active surviving device, wrap the epoch key via X-Wing KEM
        let mut wrapped_keys: HashMap<String, Vec<u8>> = HashMap::with_capacity(devices.len());
        for device in devices {
            if device.status != "active" {
                continue;
            }
            if excluded_device_id.is_some_and(|excluded| excluded == device.device_id) {
                continue;
            }

            // Reject any recipient the pinned registry never committed.
            let pinned_device = pinned
                .iter()
                .find(|p| p.device_id == device.device_id)
                .ok_or_else(|| {
                    CoreError::Engine(format!(
                        "refusing rekey: relay-listed device {} is not in the pinned registry",
                        device.device_id
                    ))
                })?;
            // Reject any recipient the pinned registry records as revoked even if
            // the relay relists it as active — a lying relay must not be able to
            // undo an explicit user revocation by steering the new epoch key to a
            // revoked (e.g. stolen) device.
            if pinned_device.status != "active" {
                return Err(CoreError::Engine(format!(
                    "refusing rekey: device {} is {} in the pinned registry but relay reports active",
                    device.device_id, pinned_device.status
                )));
            }
            if pinned_device.x_wing_public_key != device.x_wing_public_key {
                return Err(CoreError::Engine(format!(
                    "refusing rekey: x_wing_public_key for device {} differs from pinned registry",
                    device.device_id
                )));
            }

            if device.x_wing_public_key.is_empty() {
                tracing::warn!(
                    device_id = %device.device_id,
                    "prepare_wrapped_keys: skipping device with empty x_wing_public_key"
                );
                continue;
            }

            // Parse the recipient's encapsulation key — skip on failure so one
            // corrupt device doesn't abort the entire rotation for everyone.
            let ek = match prism_sync_crypto::pq::hybrid_kem::XWingKem::encapsulation_key_from_bytes(
                &device.x_wing_public_key,
            ) {
                Ok(ek) => ek,
                Err(e) => {
                    tracing::warn!(
                        device_id = %device.device_id,
                        error = %e,
                        "prepare_wrapped_keys: skipping device with invalid x_wing_public_key"
                    );
                    continue;
                }
            };

            // Encapsulate: generate ciphertext + shared secret
            let mut rng = getrandom::rand_core::UnwrapErr(getrandom::SysRng);
            let (ciphertext, shared_secret_raw) =
                prism_sync_crypto::pq::hybrid_kem::XWingKem::encapsulate(&ek, &mut rng);
            let shared_secret = Zeroizing::new(shared_secret_raw);

            // Derive wrap key via HKDF — salt binds epoch + device_id
            let mut salt = Vec::with_capacity(4 + device.device_id.len());
            salt.extend_from_slice(&new_epoch.to_le_bytes());
            salt.extend_from_slice(device.device_id.as_bytes());
            let wrap_key = prism_sync_crypto::kdf::derive_subkey(
                &shared_secret,
                &salt,
                b"prism_epoch_rekey_v2",
            )
            .map_err(CoreError::Crypto)?;

            // Encrypt epoch key for this device; AAD binds the inner AEAD to
            // the same epoch + device context as the HKDF salt.
            let aad = build_rekey_artifact_aad(new_epoch, &device.device_id);
            let encrypted_epoch_key = prism_sync_crypto::aead::xchacha_encrypt_aead(
                &wrap_key,
                epoch_key_bytes.as_ref(),
                &aad,
            )
            .map_err(CoreError::Crypto)?;

            // Build v2 artifact: 0x02 || ciphertext || encrypted_epoch_key
            let mut artifact = Vec::with_capacity(1 + ciphertext.len() + encrypted_epoch_key.len());
            artifact.push(ARTIFACT_VERSION);
            artifact.extend_from_slice(&ciphertext);
            artifact.extend_from_slice(&encrypted_epoch_key);

            wrapped_keys.insert(device.device_id.clone(), artifact);
        }

        Ok((Zeroizing::new(epoch_key_bytes.to_vec()), wrapped_keys))
    }

    /// Standalone non-revoking epoch rotation: upload wrapped artifacts for all
    /// active devices and store the new epoch key locally.
    pub async fn post_rekey(
        relay: &dyn SyncRelay,
        key_hierarchy: &mut KeyHierarchy,
        device_id: &str,
        new_epoch: u32,
        pinned: &[DeviceRecord],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let (epoch_key, wrapped_keys) =
            Self::prepare_wrapped_keys(relay, new_epoch, None, pinned).await?;
        Self::post_prepared_rekey(
            relay,
            key_hierarchy,
            device_id,
            new_epoch,
            epoch_key,
            wrapped_keys,
            None,
        )
        .await
    }

    pub async fn post_prepared_rekey(
        relay: &dyn SyncRelay,
        key_hierarchy: &mut KeyHierarchy,
        device_id: &str,
        new_epoch: u32,
        epoch_key: Zeroizing<Vec<u8>>,
        wrapped_keys: HashMap<String, Vec<u8>>,
        signed_registry_snapshot: Option<&[u8]>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let committed_epoch = match relay
            .post_rekey_artifacts(new_epoch as i32, wrapped_keys, signed_registry_snapshot)
            .await
        {
            Ok(epoch) if epoch == new_epoch as i32 => new_epoch,
            Ok(epoch) => {
                return Err(CoreError::Storage(StorageError::Logic(format!(
                    "relay committed unexpected rekey epoch {epoch}, expected {new_epoch}"
                ))));
            }
            Err(relay_error) => {
                let error = CoreError::from_relay(relay_error);
                // An old relay 409ing the needs_rekey'd standalone rekey
                // committed nothing — surface the retryable upgrade-pending error
                // directly (a pairing caller backs off and retries) without an
                // ambiguous-commit reconcile that would always come back false.
                if error.is_relay_upgrade_pending() {
                    return Err(error);
                }
                if !error.is_retryable() {
                    return Err(error);
                }
                if !Self::reconcile_post_rekey_commit(relay, device_id, new_epoch).await {
                    return Err(error);
                }

                tracing::info!(
                    device_id = %device_id,
                    epoch = new_epoch,
                    "post_rekey: reconciled ambiguous relay failure after remote commit"
                );
                new_epoch
            }
        };

        // Locally generated key — trusted by origin, installed via the
        // core chokepoint.
        let vk = VerifiedEpochKey::generated(committed_epoch, Zeroizing::new(epoch_key.to_vec()));
        install_epoch_key(key_hierarchy, vk);

        Ok(epoch_key)
    }

    pub async fn catch_up_epoch_keys(
        relay: &dyn SyncRelay,
        key_hierarchy: &mut KeyHierarchy,
        secure_store: &dyn SecureStore,
        device_secret: &DeviceSecret,
        device_id: &str,
        local_epoch: u32,
        relay_epoch: u32,
        epoch_key_hashes: &BTreeMap<u32, [u8; 32]>,
    ) -> Result<EpochCatchUpResult> {
        let mut recovered_through = local_epoch;
        if relay_epoch <= local_epoch {
            return Ok(EpochCatchUpResult {
                start_epoch: local_epoch,
                relay_epoch,
                recovered_through,
            });
        }

        let xwing = device_secret.xwing_keypair(device_id)?;

        for epoch in local_epoch.saturating_add(1)..=relay_epoch {
            let expected_hash = epoch_key_hashes.get(&epoch).ok_or_else(|| {
                CoreError::Engine(format!(
                    "signed registry missing epoch_key_hash for epoch {epoch}"
                ))
            })?;

            let key_bytes = if key_hierarchy.has_epoch_key(epoch) {
                Zeroizing::new(key_hierarchy.epoch_key(epoch)?.to_vec())
            } else {
                let artifact =
                    relay.get_rekey_artifact(epoch as i32, device_id).await?.ok_or_else(|| {
                        CoreError::Storage(StorageError::Logic(format!(
                            "no rekey artifact for epoch {epoch}"
                        )))
                    })?;
                decapsulate_and_decrypt_artifact(&artifact, &xwing, epoch, device_id)?
            };

            let key_array: [u8; 32] = key_bytes.as_slice().try_into().map_err(|_| {
                CoreError::Crypto(prism_sync_crypto::CryptoError::InvalidKeyMaterial(format!(
                    "epoch {epoch} key has unexpected length {}",
                    key_bytes.len()
                )))
            })?;
            let actual_hash = compute_epoch_key_hash(&key_array);
            if actual_hash != *expected_hash {
                return Err(CoreError::Engine(format!(
                    "epoch key hash mismatch for epoch {epoch}"
                )));
            }

            persist_epoch_key(secure_store, epoch, &key_array)?;
            if !key_hierarchy.has_epoch_key(epoch) {
                key_hierarchy.store_epoch_key(epoch, Zeroizing::new(key_array.to_vec()));
            }
            persist_epoch_cache(secure_store, epoch as i32)?;
            recovered_through = epoch;
        }

        Ok(EpochCatchUpResult { start_epoch: local_epoch, relay_epoch, recovered_through })
    }

    async fn reconcile_post_rekey_commit(
        relay: &dyn SyncRelay,
        device_id: &str,
        expected_epoch: u32,
    ) -> bool {
        let devices = match relay.list_devices().await {
            Ok(devices) => devices,
            Err(error) => {
                tracing::warn!(
                    device_id = %device_id,
                    epoch = expected_epoch,
                    error = %error,
                    "post_rekey: reconciliation failed to list devices"
                );
                return false;
            }
        };

        let Some(self_device) = devices.iter().find(|device| device.device_id == device_id) else {
            tracing::warn!(
                device_id = %device_id,
                epoch = expected_epoch,
                "post_rekey: reconciliation could not find local device in relay registry"
            );
            return false;
        };

        if self_device.status != "active" || self_device.epoch != expected_epoch as i32 {
            tracing::info!(
                device_id = %device_id,
                epoch = expected_epoch,
                relay_status = %self_device.status,
                relay_epoch = self_device.epoch,
                "post_rekey: reconciliation did not prove local device advanced"
            );
            return false;
        }

        match relay.get_rekey_artifact(expected_epoch as i32, device_id).await {
            Ok(Some(_)) => true,
            Ok(None) => {
                tracing::info!(
                    device_id = %device_id,
                    epoch = expected_epoch,
                    "post_rekey: reconciliation found no local rekey artifact"
                );
                false
            }
            Err(error) => {
                tracing::warn!(
                    device_id = %device_id,
                    epoch = expected_epoch,
                    error = %error,
                    "post_rekey: reconciliation failed to fetch local rekey artifact"
                );
                false
            }
        }
    }

    /// React to a relay `needs_rekey` signal: drive one standalone rekey
    /// that advances the epoch and clears the relay's flag.
    ///
    /// `pinned` is the active device set from a freshly imported, signature-
    /// verified registry — it is the authority for who may receive a wrapped
    /// key (the relay device list is only cross-checked against it), so the
    /// auto-revoked device, which appears `revoked` in a fresh registry, is
    /// provably excluded. `current_epoch` is the relay's current epoch; the new
    /// epoch is `current_epoch + 1`.
    ///
    /// Outcomes:
    /// - 200: epoch advanced, flag cleared; returns the installed epoch key.
    /// - survivor-set-mismatch 400 (`wrapped_keys must match the active device
    ///   set exactly`): the active set changed under us (a concurrent revoke/join).
    ///   Re-list the relay devices once and retry — exactly one retry, then the
    ///   error surfaces.
    /// - epoch-mismatch 400 (`Rekey epoch must be current_epoch + 1`): another
    ///   responder already rotated. Treat as concurrently resolved: if the relay
    ///   shows our device advanced past the epoch we tried, reconcile silently
    ///   (multi-responder dedup falls out of the epoch+1 CAS); otherwise refresh
    ///   and recurse so we re-target the now-current epoch.
    pub async fn post_rekey_for_needed(
        relay: &dyn SyncRelay,
        key_hierarchy: &mut KeyHierarchy,
        device_id: &str,
        pinned: &[DeviceRecord],
        current_epoch: u32,
        signed_registry_snapshot: Option<&[u8]>,
    ) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let new_epoch = current_epoch.saturating_add(1);

        for attempt in 0..2 {
            let devices = relay.list_devices().await.map_err(|e| {
                CoreError::Storage(StorageError::Logic(format!("failed to list devices: {e}")))
            })?;

            // Re-check the flag the relay reports against this fresh list: an
            // honest relay clears `needs_rekey` in the same tx that commits the
            // winning rotation, so a responder that processes the frame after a
            // peer already rotated sees it `false` and no-ops here instead of
            // committing a needless epoch+2 rotation (the epoch CAS only dedups
            // SAME-epoch races). This also bounds a lying relay's frame spam — a
            // relay can keep broadcasting `rekey_needed` but cannot make us
            // rotate while it reports the flag cleared.
            if !devices.iter().any(|d| d.needs_rekey) {
                tracing::debug!(
                    device_id = %device_id,
                    "rekey-needed: relay no longer reports needs_rekey; nothing to do"
                );
                return Ok(None);
            }

            let (epoch_key, wrapped_keys) = Self::prepare_wrapped_keys_for_devices(
                &devices, new_epoch, None, pinned,
            )?;

            match Self::post_prepared_rekey(
                relay,
                key_hierarchy,
                device_id,
                new_epoch,
                epoch_key,
                wrapped_keys,
                signed_registry_snapshot,
            )
            .await
            {
                Ok(key) => return Ok(Some(key)),
                Err(error) => match classify_rekey_conflict(&error) {
                    RekeyConflict::SurvivorSetMismatch if attempt == 0 => {
                        tracing::info!(
                            device_id = %device_id,
                            epoch = new_epoch,
                            "rekey-needed: survivor-set mismatch, refreshing device list and retrying once"
                        );
                        continue;
                    }
                    RekeyConflict::EpochMismatch => {
                        // A peer already rotated to `new_epoch` (or beyond). If
                        // the relay proves our device advanced, this signal is
                        // satisfied — dedup. Otherwise the epoch moved further
                        // and there is nothing more for us to do here either; the
                        // EpochRotated path recovers the key.
                        if Self::reconcile_post_rekey_commit(relay, device_id, new_epoch).await {
                            tracing::info!(
                                device_id = %device_id,
                                epoch = new_epoch,
                                "rekey-needed: epoch already advanced by a peer; reconciled"
                            );
                        } else {
                            tracing::info!(
                                device_id = %device_id,
                                epoch = new_epoch,
                                "rekey-needed: epoch moved on; deferring to epoch-recovery path"
                            );
                        }
                        return Ok(None);
                    }
                    _ => return Err(error),
                },
            }
        }

        Ok(None)
    }

    /// Generate a new sync_id: 32 random bytes, hex-encoded (64 chars).
    pub fn generate_sync_id() -> String {
        let mut bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
        hex::encode(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_sync_id_is_64_hex_chars() {
        let id = EpochManager::generate_sync_id();
        assert_eq!(id.len(), 64);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn generate_sync_id_is_unique() {
        let id1 = EpochManager::generate_sync_id();
        let id2 = EpochManager::generate_sync_id();
        assert_ne!(id1, id2);
    }

    // Integration tests for handle_rotation and post_rekey using mock relay.

    use crate::relay::traits::*;
    use crate::secure_store::SecureStore;
    use async_trait::async_trait;
    use futures_util::Stream;
    use prism_sync_crypto::DeviceSecret;
    use std::collections::HashMap;
    use std::pin::Pin;
    use std::sync::Mutex;

    #[derive(Clone, Copy)]
    enum PostRekeyBehavior {
        Success,
        CommitThenNetworkError,
        NetworkErrorBeforeCommit,
        AdvanceWithoutArtifactThenNetworkError,
        /// First POST returns the survivor-set-mismatch 400; the second
        /// (after the reaction re-lists devices) succeeds — exercises retry-once.
        SurvivorMismatchThenSuccess,
        /// A peer already rotated to the target epoch. POST returns the
        /// epoch-mismatch 400; the device row is pre-advanced + an artifact is
        /// pre-stored so `reconcile_post_rekey_commit` proves the commit.
        EpochMismatchPeerCommitted,
    }

    struct MockRelay {
        artifact: Option<Vec<u8>>,
        devices: Mutex<Vec<DeviceInfo>>,
        artifacts: Mutex<HashMap<(i32, String), Vec<u8>>>,
        artifact_error_epoch: Mutex<Option<i32>>,
        #[allow(clippy::type_complexity)]
        posted_artifacts: Mutex<Option<(i32, HashMap<String, Vec<u8>>)>>,
        post_rekey_behavior: PostRekeyBehavior,
        post_rekey_calls: Mutex<usize>,
    }

    impl MockRelay {
        fn new_with_artifact(artifact: Option<Vec<u8>>) -> Self {
            Self {
                artifact,
                devices: Mutex::new(Vec::new()),
                artifacts: Mutex::new(HashMap::new()),
                artifact_error_epoch: Mutex::new(None),
                posted_artifacts: Mutex::new(None),
                post_rekey_behavior: PostRekeyBehavior::Success,
                post_rekey_calls: Mutex::new(0),
            }
        }

        fn new_with_devices(devices: Vec<DeviceInfo>) -> Self {
            Self::new_with_devices_and_behavior(devices, PostRekeyBehavior::Success)
        }

        fn new_with_devices_and_behavior(
            devices: Vec<DeviceInfo>,
            post_rekey_behavior: PostRekeyBehavior,
        ) -> Self {
            Self {
                artifact: None,
                devices: Mutex::new(devices),
                artifacts: Mutex::new(HashMap::new()),
                artifact_error_epoch: Mutex::new(None),
                posted_artifacts: Mutex::new(None),
                post_rekey_behavior,
                post_rekey_calls: Mutex::new(0),
            }
        }

        fn advance_active_devices(&self, epoch: i32) {
            for device in self.devices.lock().unwrap().iter_mut() {
                if device.status == "active" {
                    device.epoch = epoch;
                }
            }
        }

        fn commit_rekey(&self, epoch: i32, keys: HashMap<String, Vec<u8>>) {
            self.advance_active_devices(epoch);
            let mut artifacts = self.artifacts.lock().unwrap();
            for (device_id, artifact) in keys {
                artifacts.insert((epoch, device_id), artifact);
            }
        }

        fn insert_artifact(&self, epoch: i32, device_id: &str, artifact: Vec<u8>) {
            self.artifacts.lock().unwrap().insert((epoch, device_id.to_string()), artifact);
        }

        fn set_artifact_error_epoch(&self, epoch: i32) {
            *self.artifact_error_epoch.lock().unwrap() = Some(epoch);
        }

        fn lost_response_error() -> RelayError {
            RelayError::Network { message: "response lost after commit".to_string() }
        }
    }

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
        ) -> std::result::Result<crate::relay::traits::RegistrationNonceResponse, RelayError>
        {
            Ok(crate::relay::traits::RegistrationNonceResponse {
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
                device_session_token: "mock-token".to_string(),
                min_signature_version: None,
            })
        }
        async fn list_devices(&self) -> std::result::Result<Vec<DeviceInfo>, RelayError> {
            Ok(self.devices.lock().unwrap().clone())
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
            epoch: i32,
            keys: HashMap<String, Vec<u8>>,
            _signed_registry_snapshot: Option<&[u8]>,
        ) -> std::result::Result<i32, RelayError> {
            *self.posted_artifacts.lock().unwrap() = Some((epoch, keys.clone()));
            let call = {
                let mut c = self.post_rekey_calls.lock().unwrap();
                *c += 1;
                *c
            };
            match self.post_rekey_behavior {
                PostRekeyBehavior::Success => {
                    self.commit_rekey(epoch, keys);
                    Ok(epoch)
                }
                PostRekeyBehavior::CommitThenNetworkError => {
                    self.commit_rekey(epoch, keys);
                    Err(Self::lost_response_error())
                }
                PostRekeyBehavior::NetworkErrorBeforeCommit => Err(Self::lost_response_error()),
                PostRekeyBehavior::AdvanceWithoutArtifactThenNetworkError => {
                    self.advance_active_devices(epoch);
                    Err(Self::lost_response_error())
                }
                PostRekeyBehavior::SurvivorMismatchThenSuccess => {
                    if call == 1 {
                        Err(RelayError::Protocol {
                            message: "HTTP 400: wrapped_keys must match the active device set exactly"
                                .to_string(),
                        })
                    } else {
                        self.commit_rekey(epoch, keys);
                        Ok(epoch)
                    }
                }
                PostRekeyBehavior::EpochMismatchPeerCommitted => {
                    // A peer already advanced to `epoch`: pre-advance the device
                    // and store our artifact so reconciliation proves the commit.
                    self.commit_rekey(epoch, keys);
                    Err(RelayError::Protocol {
                        message: "HTTP 400: Rekey epoch must be current_epoch + 1".to_string(),
                    })
                }
            }
        }
        async fn get_rekey_artifact(
            &self,
            epoch: i32,
            device_id: &str,
        ) -> std::result::Result<Option<Vec<u8>>, RelayError> {
            if *self.artifact_error_epoch.lock().unwrap() == Some(epoch) {
                return Err(RelayError::Network {
                    message: format!("artifact fetch failed for epoch {epoch}"),
                });
            }
            Ok(self
                .artifacts
                .lock()
                .unwrap()
                .get(&(epoch, device_id.to_string()))
                .cloned()
                .or_else(|| self.artifact.clone()))
        }
    }

    #[async_trait]
    impl SnapshotExchange for MockRelay {
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
            _progress: Option<crate::relay::traits::SnapshotUploadProgress>,
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

    /// Build a v2 artifact: sender encapsulates a known epoch key for the receiver.
    fn build_v2_artifact(
        receiver_xwing: &DeviceXWingKey,
        epoch_key: &[u8],
        epoch: u32,
        device_id: &str,
    ) -> Vec<u8> {
        use prism_sync_crypto::pq::hybrid_kem::XWingKem;

        let ek_bytes = receiver_xwing.encapsulation_key_bytes();
        let ek = XWingKem::encapsulation_key_from_bytes(&ek_bytes).unwrap();
        let mut rng = getrandom::rand_core::UnwrapErr(getrandom::SysRng);
        let (ciphertext, shared_secret_raw) = XWingKem::encapsulate(&ek, &mut rng);
        let shared_secret = Zeroizing::new(shared_secret_raw);

        let mut salt = Vec::with_capacity(4 + device_id.len());
        salt.extend_from_slice(&epoch.to_le_bytes());
        salt.extend_from_slice(device_id.as_bytes());
        let wrap_key =
            prism_sync_crypto::kdf::derive_subkey(&shared_secret, &salt, b"prism_epoch_rekey_v2")
                .unwrap();
        let aad = build_rekey_artifact_aad(epoch, device_id);
        let encrypted_epoch_key =
            prism_sync_crypto::aead::xchacha_encrypt_aead(&wrap_key, epoch_key, &aad).unwrap();

        let mut artifact = Vec::with_capacity(1 + ciphertext.len() + encrypted_epoch_key.len());
        artifact.push(ARTIFACT_VERSION);
        artifact.extend_from_slice(&ciphertext);
        artifact.extend_from_slice(&encrypted_epoch_key);
        artifact
    }

    fn build_legacy_v2_artifact_without_aad(
        receiver_xwing: &DeviceXWingKey,
        epoch_key: &[u8],
        epoch: u32,
        device_id: &str,
    ) -> Vec<u8> {
        use prism_sync_crypto::pq::hybrid_kem::XWingKem;

        let ek_bytes = receiver_xwing.encapsulation_key_bytes();
        let ek = XWingKem::encapsulation_key_from_bytes(&ek_bytes).unwrap();
        let mut rng = getrandom::rand_core::UnwrapErr(getrandom::SysRng);
        let (ciphertext, shared_secret_raw) = XWingKem::encapsulate(&ek, &mut rng);
        let shared_secret = Zeroizing::new(shared_secret_raw);

        let mut salt = Vec::with_capacity(4 + device_id.len());
        salt.extend_from_slice(&epoch.to_le_bytes());
        salt.extend_from_slice(device_id.as_bytes());
        let wrap_key =
            prism_sync_crypto::kdf::derive_subkey(&shared_secret, &salt, b"prism_epoch_rekey_v2")
                .unwrap();
        let encrypted_epoch_key =
            prism_sync_crypto::aead::xchacha_encrypt(&wrap_key, epoch_key).unwrap();

        let mut artifact = Vec::with_capacity(1 + ciphertext.len() + encrypted_epoch_key.len());
        artifact.push(ARTIFACT_VERSION);
        artifact.extend_from_slice(&ciphertext);
        artifact.extend_from_slice(&encrypted_epoch_key);
        artifact
    }

    fn epoch_hashes(entries: &[(u32, [u8; 32])]) -> BTreeMap<u32, [u8; 32]> {
        entries.iter().map(|(epoch, key)| (*epoch, compute_epoch_key_hash(key))).collect()
    }

    /// Build a signed-registry snapshot committing a single epoch's key hash.
    /// `verify` does not re-check the signature, so tests construct the snapshot
    /// directly with no signing needed.
    fn single_epoch_snapshot(epoch: u32, key: &[u8; 32]) -> SignedRegistrySnapshot {
        SignedRegistrySnapshot::new_with_epoch_binding(
            vec![],
            0,
            epoch,
            BTreeMap::from([(epoch, compute_epoch_key_hash(key))]),
        )
    }

    /// Mirror a relay `DeviceInfo` list into pinned `DeviceRecord`s. Tests where
    /// the pinned registry agrees with the relay use this to satisfy the wrap
    /// intersection.
    fn pinned_from_devices(devices: &[DeviceInfo]) -> Vec<DeviceRecord> {
        devices
            .iter()
            .map(|d| DeviceRecord {
                sync_id: "test-sync".to_string(),
                device_id: d.device_id.clone(),
                ed25519_public_key: d.ed25519_public_key.clone(),
                x25519_public_key: d.x25519_public_key.clone(),
                ml_dsa_65_public_key: d.ml_dsa_65_public_key.clone(),
                ml_kem_768_public_key: d.ml_kem_768_public_key.clone(),
                x_wing_public_key: d.x_wing_public_key.clone(),
                status: d.status.clone(),
                registered_at: chrono::Utc::now(),
                revoked_at: None,
                ml_dsa_key_generation: d.ml_dsa_key_generation,
            })
            .collect()
    }

    // The active devices carry `needs_rekey: true` — the relay mirrors the
    // group-level flag onto every device entry, and the rekey-needed reaction
    // no-ops unless it sees the flag still set on the fresh list.
    fn make_devices(
        sender_secret: &DeviceSecret,
        receiver_secret: &DeviceSecret,
    ) -> Vec<DeviceInfo> {
        let sender_xwing = sender_secret.xwing_keypair("sender").unwrap();
        let receiver_xwing = receiver_secret.xwing_keypair("receiver").unwrap();
        let revoked_secret = DeviceSecret::generate();
        let revoked_xwing = revoked_secret.xwing_keypair("revoked-dev").unwrap();

        vec![
            DeviceInfo {
                device_id: "sender".to_string(),
                epoch: 1,
                status: "active".to_string(),
                ed25519_public_key: vec![],
                x25519_public_key: vec![],
                ml_dsa_65_public_key: vec![],
                ml_kem_768_public_key: vec![],
                x_wing_public_key: sender_xwing.encapsulation_key_bytes(),
                permission: None,
                ml_dsa_key_generation: 0,
                needs_rekey: true,
            },
            DeviceInfo {
                device_id: "receiver".to_string(),
                epoch: 1,
                status: "active".to_string(),
                ed25519_public_key: vec![],
                x25519_public_key: vec![],
                ml_dsa_65_public_key: vec![],
                ml_kem_768_public_key: vec![],
                x_wing_public_key: receiver_xwing.encapsulation_key_bytes(),
                permission: None,
                ml_dsa_key_generation: 0,
                needs_rekey: true,
            },
            DeviceInfo {
                device_id: "revoked-dev".to_string(),
                epoch: 1,
                status: "revoked".to_string(),
                ed25519_public_key: vec![],
                x25519_public_key: vec![],
                ml_dsa_65_public_key: vec![],
                ml_kem_768_public_key: vec![],
                x_wing_public_key: revoked_xwing.encapsulation_key_bytes(),
                permission: None,
                ml_dsa_key_generation: 0,
                needs_rekey: false,
            },
        ]
    }

    #[tokio::test]
    async fn handle_rotation_unwraps_and_stores_epoch_key() {
        let receiver_secret = DeviceSecret::generate();
        let receiver_xwing = receiver_secret.xwing_keypair("receiver").unwrap();

        // Sender builds v2 artifact for receiver at epoch 5
        let epoch_key = vec![0xABu8; 32];
        let key_arr: [u8; 32] = epoch_key.as_slice().try_into().unwrap();
        let artifact = build_v2_artifact(&receiver_xwing, &epoch_key, 5, "receiver");
        let snapshot = single_epoch_snapshot(5, &key_arr);

        let relay = MockRelay::new_with_artifact(Some(artifact));
        let mut kh = KeyHierarchy::new();
        kh.initialize("password", &[1u8; 16]).unwrap();

        EpochManager::handle_rotation(&relay, &mut kh, 5, "receiver", &receiver_xwing, &snapshot)
            .await
            .unwrap();

        assert!(kh.has_epoch_key(5));
        assert_eq!(kh.epoch_key(5).unwrap(), &epoch_key);
    }

    #[test]
    fn decapsulate_rejects_legacy_rekey_artifact_without_inner_aad() {
        let receiver_secret = DeviceSecret::generate();
        let receiver_xwing = receiver_secret.xwing_keypair("receiver").unwrap();
        let epoch_key = vec![0xABu8; 32];
        let artifact =
            build_legacy_v2_artifact_without_aad(&receiver_xwing, &epoch_key, 5, "receiver");

        let result = decapsulate_and_decrypt_artifact(&artifact, &receiver_xwing, 5, "receiver");

        assert!(result.is_err(), "legacy no-AAD artifact must not decrypt under v2 AAD");
    }

    #[test]
    fn rekey_artifact_aad_binds_epoch_and_device() {
        let aad = build_rekey_artifact_aad(5, "receiver");
        assert_ne!(aad, build_rekey_artifact_aad(6, "receiver"));
        assert_ne!(aad, build_rekey_artifact_aad(5, "other-device"));
    }

    #[tokio::test]
    async fn handle_rotation_missing_artifact_errors() {
        let relay = MockRelay::new_with_artifact(None);
        let mut kh = KeyHierarchy::new();
        kh.initialize("password", &[1u8; 16]).unwrap();

        let secret = DeviceSecret::generate();
        let xwing = secret.xwing_keypair("dev-a").unwrap();
        let snapshot = single_epoch_snapshot(5, &[0u8; 32]);

        let result =
            EpochManager::handle_rotation(&relay, &mut kh, 5, "dev-a", &xwing, &snapshot).await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("no rekey artifact"), "got: {msg}");
    }

    #[tokio::test]
    async fn handle_rotation_rejects_unknown_version() {
        // Build an artifact with version 0x03
        let mut bad_artifact = vec![0x03u8];
        bad_artifact.extend_from_slice(&[0u8; XWING_CT_LEN + 40]);

        let relay = MockRelay::new_with_artifact(Some(bad_artifact));
        let mut kh = KeyHierarchy::new();
        kh.initialize("password", &[1u8; 16]).unwrap();

        let secret = DeviceSecret::generate();
        let xwing = secret.xwing_keypair("dev-a").unwrap();
        let snapshot = single_epoch_snapshot(5, &[0u8; 32]);

        let result =
            EpochManager::handle_rotation(&relay, &mut kh, 5, "dev-a", &xwing, &snapshot).await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("unsupported rekey artifact version"), "got: {msg}");
    }

    #[tokio::test]
    async fn handle_rotation_rejects_short_artifact() {
        // Artifact with correct version but too short (missing ciphertext)
        let short_artifact = vec![ARTIFACT_VERSION, 0x00, 0x01];

        let relay = MockRelay::new_with_artifact(Some(short_artifact));
        let mut kh = KeyHierarchy::new();
        kh.initialize("password", &[1u8; 16]).unwrap();

        let secret = DeviceSecret::generate();
        let xwing = secret.xwing_keypair("dev-a").unwrap();
        let snapshot = single_epoch_snapshot(5, &[0u8; 32]);

        let result =
            EpochManager::handle_rotation(&relay, &mut kh, 5, "dev-a", &xwing, &snapshot).await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("rekey artifact too short"), "got: {msg}");
    }

    #[tokio::test]
    async fn post_rekey_wraps_for_active_devices_only() {
        let sender_secret = DeviceSecret::generate();
        let receiver_secret = DeviceSecret::generate();
        let receiver_xwing = receiver_secret.xwing_keypair("receiver").unwrap();

        let devices = make_devices(&sender_secret, &receiver_secret);
        let pinned = pinned_from_devices(&devices);
        let relay = MockRelay::new_with_devices(devices);

        let mut kh = KeyHierarchy::new();
        kh.initialize("password", &[1u8; 16]).unwrap();

        EpochManager::post_rekey(&relay, &mut kh, "sender", 2, &pinned).await.unwrap();

        let posted = relay.posted_artifacts.lock().unwrap();
        let (epoch, keys) = posted.as_ref().unwrap();
        assert_eq!(*epoch, 2);
        // Should have wrapped keys for sender and receiver, not revoked-dev
        assert_eq!(keys.len(), 2);
        assert!(keys.contains_key("sender"));
        assert!(keys.contains_key("receiver"));
        assert!(!keys.contains_key("revoked-dev"));

        // Verify receiver can decapsulate the v2 artifact
        let artifact = &keys["receiver"];
        assert_eq!(artifact[0], ARTIFACT_VERSION);
        assert!(artifact.len() >= MIN_ARTIFACT_LEN);

        let ciphertext = &artifact[1..1 + XWING_CT_LEN];
        let encrypted_epoch_key = &artifact[1 + XWING_CT_LEN..];

        let shared_secret = receiver_xwing.decapsulate(ciphertext).unwrap();
        let mut salt = Vec::new();
        salt.extend_from_slice(&2u32.to_le_bytes());
        salt.extend_from_slice(b"receiver");
        let unwrap_key =
            prism_sync_crypto::kdf::derive_subkey(&shared_secret, &salt, b"prism_epoch_rekey_v2")
                .unwrap();
        let aad = build_rekey_artifact_aad(2, "receiver");
        let decrypted =
            prism_sync_crypto::aead::xchacha_decrypt_aead(&unwrap_key, encrypted_epoch_key, &aad)
                .unwrap();
        assert_eq!(decrypted.len(), 32);

        // Verify decrypted epoch key matches what was stored in the hierarchy
        let stored_key = kh.epoch_key(2).unwrap();
        assert_eq!(decrypted, stored_key, "decrypted key should match stored epoch key");
    }

    // ── rekey-needed reaction ──

    /// The reaction wraps the new epoch key for exactly the active set (the
    /// revoked registry entry is excluded), advances the epoch, and installs the
    /// key locally on the first try.
    #[tokio::test]
    async fn rekey_needed_reaction_wraps_active_set_and_advances() {
        let sender_secret = DeviceSecret::generate();
        let receiver_secret = DeviceSecret::generate();
        let devices = make_devices(&sender_secret, &receiver_secret);
        let pinned = pinned_from_devices(&devices);
        let relay = MockRelay::new_with_devices(devices);

        let mut kh = KeyHierarchy::new();
        kh.initialize("password", &[1u8; 16]).unwrap();

        let installed =
            EpochManager::post_rekey_for_needed(&relay, &mut kh, "sender", &pinned, 1, None)
                .await
                .expect("reaction should succeed");
        assert!(installed.is_some(), "reaction installed a new epoch key");
        assert!(kh.has_epoch_key(2), "epoch 2 key installed locally");

        let posted = relay.posted_artifacts.lock().unwrap();
        let (epoch, keys) = posted.as_ref().unwrap();
        assert_eq!(*epoch, 2);
        // Active set only: sender + receiver, never the revoked device.
        assert!(keys.contains_key("sender"));
        assert!(keys.contains_key("receiver"));
        assert!(!keys.contains_key("revoked-dev"), "revoked device gets no wrapped key");
        assert_eq!(*relay.post_rekey_calls.lock().unwrap(), 1, "no retry on the happy path");
    }

    /// A survivor-set-mismatch 400 triggers exactly one re-list-and-retry, then
    /// succeeds.
    #[tokio::test]
    async fn rekey_needed_reaction_retries_once_on_survivor_mismatch() {
        let sender_secret = DeviceSecret::generate();
        let receiver_secret = DeviceSecret::generate();
        let devices = make_devices(&sender_secret, &receiver_secret);
        let pinned = pinned_from_devices(&devices);
        let relay = MockRelay::new_with_devices_and_behavior(
            devices,
            PostRekeyBehavior::SurvivorMismatchThenSuccess,
        );

        let mut kh = KeyHierarchy::new();
        kh.initialize("password", &[1u8; 16]).unwrap();

        let installed =
            EpochManager::post_rekey_for_needed(&relay, &mut kh, "sender", &pinned, 1, None)
                .await
                .expect("reaction should recover after one retry");
        assert!(installed.is_some());
        assert!(kh.has_epoch_key(2));
        assert_eq!(
            *relay.post_rekey_calls.lock().unwrap(),
            2,
            "exactly one retry on survivor-set mismatch"
        );
    }

    /// An epoch-mismatch 400 (a peer already rotated) resolves silently via
    /// `reconcile_post_rekey_commit` — no error, no second attempt.
    #[tokio::test]
    async fn rekey_needed_reaction_reconciles_on_epoch_mismatch() {
        let sender_secret = DeviceSecret::generate();
        let receiver_secret = DeviceSecret::generate();
        let devices = make_devices(&sender_secret, &receiver_secret);
        let pinned = pinned_from_devices(&devices);
        let relay = MockRelay::new_with_devices_and_behavior(
            devices,
            PostRekeyBehavior::EpochMismatchPeerCommitted,
        );

        let mut kh = KeyHierarchy::new();
        kh.initialize("password", &[1u8; 16]).unwrap();

        let installed =
            EpochManager::post_rekey_for_needed(&relay, &mut kh, "sender", &pinned, 1, None)
                .await
                .expect("epoch-mismatch must reconcile, not error");
        assert!(installed.is_none(), "no local key installed — a peer owns the rotation");
        assert_eq!(
            *relay.post_rekey_calls.lock().unwrap(),
            1,
            "epoch mismatch reconciles without a retry"
        );
    }

    /// When the relay no longer reports `needs_rekey` on the fresh list (an
    /// honest relay clears it the moment a peer's rotation commits), a responder
    /// processing a late frame no-ops instead of posting a redundant epoch+2
    /// rotation. This also bounds a lying relay's `rekey_needed` frame spam.
    #[tokio::test]
    async fn rekey_needed_reaction_noops_when_flag_already_cleared() {
        let sender_secret = DeviceSecret::generate();
        let receiver_secret = DeviceSecret::generate();
        let mut devices = make_devices(&sender_secret, &receiver_secret);
        for d in devices.iter_mut() {
            d.needs_rekey = false;
        }
        let pinned = pinned_from_devices(&devices);
        let relay = MockRelay::new_with_devices(devices);

        let mut kh = KeyHierarchy::new();
        kh.initialize("password", &[1u8; 16]).unwrap();

        let installed =
            EpochManager::post_rekey_for_needed(&relay, &mut kh, "sender", &pinned, 1, None)
                .await
                .expect("a cleared flag is a benign no-op, not an error");
        assert!(installed.is_none(), "nothing to rotate when the flag is already cleared");
        assert!(!kh.has_epoch_key(2), "no epoch advanced");
        assert_eq!(
            *relay.post_rekey_calls.lock().unwrap(),
            0,
            "no rekey posted when the relay reports the flag cleared"
        );
    }

    #[tokio::test]
    async fn post_rekey_reconciles_commit_after_lost_response() {
        let sender_secret = DeviceSecret::generate();
        let receiver_secret = DeviceSecret::generate();
        let devices = make_devices(&sender_secret, &receiver_secret);
        let pinned = pinned_from_devices(&devices);
        let relay = MockRelay::new_with_devices_and_behavior(
            devices,
            PostRekeyBehavior::CommitThenNetworkError,
        );

        let mut kh = KeyHierarchy::new();
        kh.initialize("password", &[1u8; 16]).unwrap();

        let returned_key = EpochManager::post_rekey(&relay, &mut kh, "sender", 2, &pinned)
            .await
            .expect("committed relay state should reconcile lost response");

        assert!(kh.has_epoch_key(2));
        assert_eq!(kh.epoch_key(2).unwrap(), returned_key.as_slice());
    }

    #[tokio::test]
    async fn post_rekey_errors_when_lost_response_did_not_commit() {
        let sender_secret = DeviceSecret::generate();
        let receiver_secret = DeviceSecret::generate();
        let devices = make_devices(&sender_secret, &receiver_secret);
        let pinned = pinned_from_devices(&devices);
        let relay = MockRelay::new_with_devices_and_behavior(
            devices,
            PostRekeyBehavior::NetworkErrorBeforeCommit,
        );

        let mut kh = KeyHierarchy::new();
        kh.initialize("password", &[1u8; 16]).unwrap();

        let result = EpochManager::post_rekey(&relay, &mut kh, "sender", 2, &pinned).await;

        assert!(result.is_err(), "uncommitted ambiguous failure must remain an error");
        assert!(!kh.has_epoch_key(2), "uncommitted epoch key should not be stored locally");
    }

    #[tokio::test]
    async fn post_rekey_errors_when_reconciled_artifact_is_absent() {
        let sender_secret = DeviceSecret::generate();
        let receiver_secret = DeviceSecret::generate();
        let devices = make_devices(&sender_secret, &receiver_secret);
        let pinned = pinned_from_devices(&devices);
        let relay = MockRelay::new_with_devices_and_behavior(
            devices,
            PostRekeyBehavior::AdvanceWithoutArtifactThenNetworkError,
        );

        let mut kh = KeyHierarchy::new();
        kh.initialize("password", &[1u8; 16]).unwrap();

        let result = EpochManager::post_rekey(&relay, &mut kh, "sender", 2, &pinned).await;

        assert!(result.is_err(), "advanced epoch without artifact must not reconcile");
        assert!(!kh.has_epoch_key(2), "unconfirmed epoch key should not be stored locally");
    }

    #[tokio::test]
    async fn catch_up_epoch_keys_recovers_and_advances_secure_epoch() {
        let device_secret = DeviceSecret::generate();
        let device_id = "sender";
        let xwing = device_secret.xwing_keypair(device_id).unwrap();
        let epoch_1_key = [0x11u8; 32];
        let epoch_2_key = [0x22u8; 32];

        let relay = MockRelay::new_with_artifact(None);
        relay.insert_artifact(1, device_id, build_v2_artifact(&xwing, &epoch_1_key, 1, device_id));
        relay.insert_artifact(2, device_id, build_v2_artifact(&xwing, &epoch_2_key, 2, device_id));

        let mut kh = KeyHierarchy::new();
        kh.initialize("password", &[1u8; 16]).unwrap();
        let store = MemStore::default();
        let hashes = epoch_hashes(&[(1, epoch_1_key), (2, epoch_2_key)]);

        let result = EpochManager::catch_up_epoch_keys(
            &relay,
            &mut kh,
            &store,
            &device_secret,
            device_id,
            0,
            2,
            &hashes,
        )
        .await
        .unwrap();

        assert_eq!(
            result,
            EpochCatchUpResult { start_epoch: 0, relay_epoch: 2, recovered_through: 2 }
        );
        assert_eq!(kh.epoch_key(1).unwrap(), &epoch_1_key);
        assert_eq!(kh.epoch_key(2).unwrap(), &epoch_2_key);
        assert!(store.get("epoch_key_1").unwrap().is_some());
        assert!(store.get("epoch_key_2").unwrap().is_some());
        assert_eq!(store.get("epoch").unwrap().unwrap(), b"2");
    }

    #[tokio::test]
    async fn catch_up_epoch_keys_stops_before_missing_artifact_epoch() {
        let device_secret = DeviceSecret::generate();
        let device_id = "sender";
        let xwing = device_secret.xwing_keypair(device_id).unwrap();
        let epoch_1_key = [0x11u8; 32];
        let epoch_2_key = [0x22u8; 32];

        let relay = MockRelay::new_with_artifact(None);
        relay.insert_artifact(1, device_id, build_v2_artifact(&xwing, &epoch_1_key, 1, device_id));

        let mut kh = KeyHierarchy::new();
        kh.initialize("password", &[1u8; 16]).unwrap();
        let store = MemStore::default();
        let hashes = epoch_hashes(&[(1, epoch_1_key), (2, epoch_2_key)]);

        let result = EpochManager::catch_up_epoch_keys(
            &relay,
            &mut kh,
            &store,
            &device_secret,
            device_id,
            0,
            2,
            &hashes,
        )
        .await;

        assert!(result.is_err(), "missing epoch 2 artifact should fail");
        assert_eq!(kh.epoch_key(1).unwrap(), &epoch_1_key);
        assert!(!kh.has_epoch_key(2));
        assert!(store.get("epoch_key_1").unwrap().is_some());
        assert!(store.get("epoch_key_2").unwrap().is_none());
        assert_eq!(store.get("epoch").unwrap().unwrap(), b"1");
    }

    #[tokio::test]
    async fn catch_up_epoch_keys_advances_verified_prefix_on_mid_loop_network_error() {
        let device_secret = DeviceSecret::generate();
        let device_id = "sender";
        let xwing = device_secret.xwing_keypair(device_id).unwrap();
        let epoch_1_key = [0x11u8; 32];
        let epoch_2_key = [0x22u8; 32];

        let relay = MockRelay::new_with_artifact(None);
        relay.insert_artifact(1, device_id, build_v2_artifact(&xwing, &epoch_1_key, 1, device_id));
        relay.insert_artifact(2, device_id, build_v2_artifact(&xwing, &epoch_2_key, 2, device_id));
        relay.set_artifact_error_epoch(2);

        let mut kh = KeyHierarchy::new();
        kh.initialize("password", &[1u8; 16]).unwrap();
        let store = MemStore::default();
        let hashes = epoch_hashes(&[(1, epoch_1_key), (2, epoch_2_key)]);

        let result = EpochManager::catch_up_epoch_keys(
            &relay,
            &mut kh,
            &store,
            &device_secret,
            device_id,
            0,
            2,
            &hashes,
        )
        .await;

        assert!(result.is_err(), "epoch 2 network error should fail catch-up");
        assert_eq!(kh.epoch_key(1).unwrap(), &epoch_1_key);
        assert!(!kh.has_epoch_key(2));
        assert!(store.get("epoch_key_1").unwrap().is_some());
        assert!(store.get("epoch_key_2").unwrap().is_none());
        assert_eq!(store.get("epoch").unwrap().unwrap(), b"1");
    }

    #[tokio::test]
    async fn catch_up_epoch_keys_rejects_hash_mismatch_without_advancing_epoch() {
        let device_secret = DeviceSecret::generate();
        let device_id = "sender";
        let xwing = device_secret.xwing_keypair(device_id).unwrap();
        let epoch_1_key = [0x11u8; 32];
        let epoch_2_key = [0x22u8; 32];
        let wrong_epoch_2_key = [0x33u8; 32];

        let relay = MockRelay::new_with_artifact(None);
        relay.insert_artifact(1, device_id, build_v2_artifact(&xwing, &epoch_1_key, 1, device_id));
        relay.insert_artifact(2, device_id, build_v2_artifact(&xwing, &epoch_2_key, 2, device_id));

        let mut kh = KeyHierarchy::new();
        kh.initialize("password", &[1u8; 16]).unwrap();
        let store = MemStore::default();
        let hashes = epoch_hashes(&[(1, epoch_1_key), (2, wrong_epoch_2_key)]);

        let result = EpochManager::catch_up_epoch_keys(
            &relay,
            &mut kh,
            &store,
            &device_secret,
            device_id,
            0,
            2,
            &hashes,
        )
        .await;

        assert!(result.is_err(), "hash mismatch should fail");
        assert_eq!(kh.epoch_key(1).unwrap(), &epoch_1_key);
        assert!(!kh.has_epoch_key(2));
        assert!(store.get("epoch_key_2").unwrap().is_none());
        assert_eq!(store.get("epoch").unwrap().unwrap(), b"1");
    }

    #[tokio::test]
    async fn catch_up_epoch_keys_requires_signed_hash_for_each_epoch() {
        let device_secret = DeviceSecret::generate();
        let device_id = "sender";
        let xwing = device_secret.xwing_keypair(device_id).unwrap();
        let epoch_1_key = [0x11u8; 32];
        let epoch_2_key = [0x22u8; 32];

        let relay = MockRelay::new_with_artifact(None);
        relay.insert_artifact(1, device_id, build_v2_artifact(&xwing, &epoch_1_key, 1, device_id));
        relay.insert_artifact(2, device_id, build_v2_artifact(&xwing, &epoch_2_key, 2, device_id));

        let mut kh = KeyHierarchy::new();
        kh.initialize("password", &[1u8; 16]).unwrap();
        let store = MemStore::default();
        let hashes = epoch_hashes(&[(1, epoch_1_key)]);

        let result = EpochManager::catch_up_epoch_keys(
            &relay,
            &mut kh,
            &store,
            &device_secret,
            device_id,
            0,
            2,
            &hashes,
        )
        .await;

        assert!(result.is_err(), "missing signed hash for epoch 2 should fail");
        assert_eq!(kh.epoch_key(1).unwrap(), &epoch_1_key);
        assert!(!kh.has_epoch_key(2));
        assert!(store.get("epoch_key_2").unwrap().is_none());
        assert_eq!(store.get("epoch").unwrap().unwrap(), b"1");
    }

    #[tokio::test]
    async fn handle_rotation_rejects_corrupted_ciphertext() {
        // Valid version byte, valid length, but zeroed ciphertext — decapsulation fails
        let mut bad_artifact = vec![ARTIFACT_VERSION];
        bad_artifact.extend_from_slice(&[0u8; XWING_CT_LEN]);
        bad_artifact.extend_from_slice(&[0u8; 72]); // fake encrypted epoch key

        let relay = MockRelay::new_with_artifact(Some(bad_artifact));
        let mut kh = KeyHierarchy::new();
        kh.initialize("password", &[1u8; 16]).unwrap();

        let secret = DeviceSecret::generate();
        let xwing = secret.xwing_keypair("dev-a").unwrap();
        let snapshot = single_epoch_snapshot(5, &[0u8; 32]);

        let result =
            EpochManager::handle_rotation(&relay, &mut kh, 5, "dev-a", &xwing, &snapshot).await;
        assert!(result.is_err(), "corrupted ciphertext should fail decapsulation");
    }

    #[tokio::test]
    async fn handle_rotation_rejects_wrong_decapsulation_key() {
        // Build artifact for device B, try to decapsulate with device C's key
        let secret_b = DeviceSecret::generate();
        let xwing_b = secret_b.xwing_keypair("device-b").unwrap();
        let secret_c = DeviceSecret::generate();
        let xwing_c = secret_c.xwing_keypair("device-c").unwrap();

        let epoch_key = vec![0xCDu8; 32];
        let key_arr: [u8; 32] = epoch_key.as_slice().try_into().unwrap();
        let artifact = build_v2_artifact(&xwing_b, &epoch_key, 5, "device-b");
        let snapshot = single_epoch_snapshot(5, &key_arr);

        let relay = MockRelay::new_with_artifact(Some(artifact));
        let mut kh = KeyHierarchy::new();
        kh.initialize("password", &[1u8; 16]).unwrap();

        // Device C tries to use device B's artifact
        let result =
            EpochManager::handle_rotation(&relay, &mut kh, 5, "device-c", &xwing_c, &snapshot)
                .await;
        assert!(result.is_err(), "wrong DK should fail to recover epoch key");
    }

    #[tokio::test]
    async fn prepare_wrapped_keys_skips_invalid_ek() {
        // One device has valid X-Wing EK, another has garbage (non-empty, wrong length)
        let valid_secret = DeviceSecret::generate();
        let valid_xwing = valid_secret.xwing_keypair("valid-dev").unwrap();

        let devices = vec![
            DeviceInfo {
                device_id: "valid-dev".to_string(),
                epoch: 1,
                status: "active".to_string(),
                ed25519_public_key: vec![],
                x25519_public_key: vec![],
                ml_dsa_65_public_key: vec![],
                ml_kem_768_public_key: vec![],
                x_wing_public_key: valid_xwing.encapsulation_key_bytes(),
                permission: None,
                ml_dsa_key_generation: 0,
                needs_rekey: false,
            },
            DeviceInfo {
                device_id: "bad-dev".to_string(),
                epoch: 1,
                status: "active".to_string(),
                ed25519_public_key: vec![],
                x25519_public_key: vec![],
                ml_dsa_65_public_key: vec![],
                ml_kem_768_public_key: vec![],
                x_wing_public_key: vec![0u8; 100], // wrong length
                permission: None,
                ml_dsa_key_generation: 0,
                needs_rekey: false,
            },
        ];
        // Pinned registry agrees with the relay (same keys) so the intersection
        // passes; the bad device is then skipped on the EK-parse failure.
        let pinned = pinned_from_devices(&devices);
        let relay = MockRelay::new_with_devices(devices);

        let (_, wrapped_keys) = EpochManager::prepare_wrapped_keys(&relay, 1, None, &pinned)
            .await
            .expect("should succeed despite one bad device");

        // Valid device gets a key, bad device is skipped
        assert!(wrapped_keys.contains_key("valid-dev"), "valid device should get wrapped key");
        assert!(!wrapped_keys.contains_key("bad-dev"), "bad device should be skipped");
    }

    #[tokio::test]
    async fn post_rekey_stores_epoch_key_in_hierarchy() {
        let sender_secret = DeviceSecret::generate();
        let receiver_secret = DeviceSecret::generate();

        let devices = make_devices(&sender_secret, &receiver_secret);
        let pinned = pinned_from_devices(&devices);
        let relay = MockRelay::new_with_devices(devices);

        let mut kh = KeyHierarchy::new();
        kh.initialize("password", &[1u8; 16]).unwrap();

        // Epoch 2 key should not exist yet
        assert!(!kh.has_epoch_key(2));

        let returned_key =
            EpochManager::post_rekey(&relay, &mut kh, "sender", 2, &pinned).await.unwrap();

        // Epoch 2 key should now be stored in the hierarchy
        assert!(kh.has_epoch_key(2));
        let stored_key = kh.epoch_key(2).unwrap();
        assert_eq!(stored_key, &*returned_key);
        assert_eq!(stored_key.len(), 32);
    }

    /// A relay that injects an extra "active" recipient absent from the pinned
    /// registry must abort the whole rotation — never silently wrap to it.
    #[test]
    fn prepare_wrapped_keys_rejects_injected_recipient_absent_from_pinned() {
        let pinned_secret = DeviceSecret::generate();
        let pinned_xwing = pinned_secret.xwing_keypair("pinned-dev").unwrap();
        let injected_secret = DeviceSecret::generate();
        let injected_xwing = injected_secret.xwing_keypair("injected-dev").unwrap();

        let pinned_device = DeviceInfo {
            device_id: "pinned-dev".to_string(),
            epoch: 1,
            status: "active".to_string(),
            ed25519_public_key: vec![],
            x25519_public_key: vec![],
            ml_dsa_65_public_key: vec![],
            ml_kem_768_public_key: vec![],
            x_wing_public_key: pinned_xwing.encapsulation_key_bytes(),
            permission: None,
            ml_dsa_key_generation: 0,
            needs_rekey: false,
        };
        // Pinned registry knows only the legitimate device.
        let pinned = pinned_from_devices(std::slice::from_ref(&pinned_device));

        // Relay list adds an attacker-controlled "active" device.
        let relay_devices = vec![
            pinned_device,
            DeviceInfo {
                device_id: "injected-dev".to_string(),
                epoch: 1,
                status: "active".to_string(),
                ed25519_public_key: vec![],
                x25519_public_key: vec![],
                ml_dsa_65_public_key: vec![],
                ml_kem_768_public_key: vec![],
                x_wing_public_key: injected_xwing.encapsulation_key_bytes(),
                permission: None,
                ml_dsa_key_generation: 0,
                needs_rekey: false,
            },
        ];

        let result = EpochManager::prepare_wrapped_keys_for_devices(&relay_devices, 1, None, &pinned);
        let err = result.expect_err("injected recipient must abort the rotation");
        assert!(
            err.to_string().contains("not in the pinned registry"),
            "unexpected error: {err}"
        );
    }

    /// A relay that swaps a known device's X-Wing key (key differs from the
    /// pinned record) must abort the rotation, not wrap to the swapped key.
    #[test]
    fn prepare_wrapped_keys_rejects_swapped_xwing_key() {
        let real_secret = DeviceSecret::generate();
        let real_xwing = real_secret.xwing_keypair("dev").unwrap();
        let attacker_secret = DeviceSecret::generate();
        let attacker_xwing = attacker_secret.xwing_keypair("dev").unwrap();

        // Pinned record holds the REAL key.
        let pinned = pinned_from_devices(&[DeviceInfo {
            device_id: "dev".to_string(),
            epoch: 1,
            status: "active".to_string(),
            ed25519_public_key: vec![],
            x25519_public_key: vec![],
            ml_dsa_65_public_key: vec![],
            ml_kem_768_public_key: vec![],
            x_wing_public_key: real_xwing.encapsulation_key_bytes(),
            permission: None,
            ml_dsa_key_generation: 0,
            needs_rekey: false,
        }]);

        // Relay swaps in the attacker's X-Wing key for the same device_id.
        let relay_devices = vec![DeviceInfo {
            device_id: "dev".to_string(),
            epoch: 1,
            status: "active".to_string(),
            ed25519_public_key: vec![],
            x25519_public_key: vec![],
            ml_dsa_65_public_key: vec![],
            ml_kem_768_public_key: vec![],
            x_wing_public_key: attacker_xwing.encapsulation_key_bytes(),
            permission: None,
            ml_dsa_key_generation: 0,
            needs_rekey: false,
        }];

        let result = EpochManager::prepare_wrapped_keys_for_devices(&relay_devices, 1, None, &pinned);
        let err = result.expect_err("swapped X-Wing key must abort the rotation");
        assert!(
            err.to_string().contains("differs from pinned registry"),
            "unexpected error: {err}"
        );
    }

    /// A lying relay that re-lists an explicitly-revoked device as `active`
    /// (carrying its original registered X-Wing key, which the relay holds) must
    /// not be able to steer a new-epoch wrap artifact to it. The pinned registry
    /// records the device as `revoked` (the pin retains explicit revoked
    /// entries), so the rotation aborts rather than undoing the user's
    /// revocation. This is the unattended-rekey-reaction analogue of the
    /// stolen-device scenario.
    #[test]
    fn prepare_wrapped_keys_rejects_pinned_revoked_relisted_active() {
        let secret = DeviceSecret::generate();
        let xwing = secret.xwing_keypair("dev").unwrap();

        // Pinned record marks the device REVOKED (an explicit user revocation),
        // even though its registered X-Wing key is still on file.
        let pinned = pinned_from_devices(&[DeviceInfo {
            device_id: "dev".to_string(),
            epoch: 1,
            status: "revoked".to_string(),
            ed25519_public_key: vec![],
            x25519_public_key: vec![],
            ml_dsa_65_public_key: vec![],
            ml_kem_768_public_key: vec![],
            x_wing_public_key: xwing.encapsulation_key_bytes(),
            permission: None,
            ml_dsa_key_generation: 0,
            needs_rekey: false,
        }]);

        // The relay lies: it reports the same device as `active` with the same
        // (genuine, still-registered) X-Wing key, so presence and key-equality
        // both pass — only the pinned-status gate stops it.
        let relay_devices = vec![DeviceInfo {
            device_id: "dev".to_string(),
            epoch: 1,
            status: "active".to_string(),
            ed25519_public_key: vec![],
            x25519_public_key: vec![],
            ml_dsa_65_public_key: vec![],
            ml_kem_768_public_key: vec![],
            x_wing_public_key: xwing.encapsulation_key_bytes(),
            permission: None,
            ml_dsa_key_generation: 0,
            needs_rekey: false,
        }];

        let result = EpochManager::prepare_wrapped_keys_for_devices(&relay_devices, 1, None, &pinned);
        let err = result.expect_err("a pinned-revoked recipient must abort the rotation");
        assert!(
            err.to_string().contains("revoked in the pinned registry"),
            "unexpected error: {err}"
        );
    }

    /// Positive control: when the relay list matches the pinned registry, the
    /// wrap succeeds and produces an artifact for the surviving device.
    #[test]
    fn prepare_wrapped_keys_accepts_relay_list_matching_pinned() {
        let secret = DeviceSecret::generate();
        let xwing = secret.xwing_keypair("dev").unwrap();

        let device = DeviceInfo {
            device_id: "dev".to_string(),
            epoch: 1,
            status: "active".to_string(),
            ed25519_public_key: vec![],
            x25519_public_key: vec![],
            ml_dsa_65_public_key: vec![],
            ml_kem_768_public_key: vec![],
            x_wing_public_key: xwing.encapsulation_key_bytes(),
            permission: None,
            ml_dsa_key_generation: 0,
            needs_rekey: false,
        };
        let pinned = pinned_from_devices(std::slice::from_ref(&device));
        let relay_devices = vec![device];

        let (_key, wrapped) =
            EpochManager::prepare_wrapped_keys_for_devices(&relay_devices, 1, None, &pinned)
                .expect("matching relay/pinned should wrap");
        assert!(wrapped.contains_key("dev"), "surviving device should get a wrapped key");
    }

    /// `handle_rotation` must refuse and install nothing when the signed
    /// registry carries NO `epoch_key_hashes` entry for the epoch — distinct
    /// from the hash-mismatch case (here there is no committed hash at all).
    #[tokio::test]
    async fn handle_rotation_rejects_when_registry_lacks_epoch_hash() {
        let receiver_secret = DeviceSecret::generate();
        let receiver_xwing = receiver_secret.xwing_keypair("receiver").unwrap();

        // Real artifact wrapping a valid key, but the signed registry commits a
        // DIFFERENT epoch (7), so there is no epoch_key_hashes[5] to bind to.
        let epoch_key = vec![0xABu8; 32];
        let artifact = build_v2_artifact(&receiver_xwing, &epoch_key, 5, "receiver");
        let snapshot = single_epoch_snapshot(7, &[0x22u8; 32]);

        let relay = MockRelay::new_with_artifact(Some(artifact));
        let mut kh = KeyHierarchy::new();
        kh.initialize("password", &[1u8; 16]).unwrap();

        let result =
            EpochManager::handle_rotation(&relay, &mut kh, 5, "receiver", &receiver_xwing, &snapshot)
                .await;
        let err = result.expect_err("missing epoch hash must be refused");
        assert!(
            err.to_string().contains("no epoch_key_hash for epoch 5"),
            "unexpected error: {err}"
        );
        assert!(!kh.has_epoch_key(5), "no key may be installed when the hash is uncommitted");
    }
}
