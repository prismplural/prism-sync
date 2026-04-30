use crate::relay::traits::RelayError;
use crate::storage::StorageError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("HLC parse error: {0}")]
    HlcParse(String),

    #[error("HLC clock drift exceeded: drift={drift_ms}ms, max={max_ms}ms, device={device_id}")]
    ClockDrift { drift_ms: i64, max_ms: i64, device_id: String },

    #[error("storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("schema error: {0}")]
    Schema(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("relay error ({kind:?}): {message}")]
    Relay {
        message: String,
        kind: RelayErrorCategory,
        status: Option<u16>,
        code: Option<String>,
        min_signature_version: Option<u8>,
        remote_wipe: Option<bool>,
        #[source]
        source: Option<RelayError>,
    },

    #[error("device {device_id} key changed")]
    DeviceKeyChanged { device_id: String },

    #[error("missing epoch key for epoch {epoch}")]
    MissingEpochKey { epoch: u32 },

    #[error("epoch mismatch: local_epoch={local_epoch}, relay_epoch={relay_epoch}: {message}")]
    EpochMismatch { local_epoch: u32, relay_epoch: u32, message: String },

    #[error("epoch key mismatch for epoch {epoch}: {message}")]
    EpochKeyMismatch { epoch: u32, message: String },

    #[error("decrypt failed for epoch {epoch}: {source}")]
    DecryptFailed {
        epoch: u32,
        #[source]
        source: prism_sync_crypto::CryptoError,
    },

    #[error("engine error: {0}")]
    Engine(String),

    #[error("crypto error: {0}")]
    Crypto(#[from] prism_sync_crypto::CryptoError),

    #[error("unknown entity table: {0}")]
    UnknownTable(String),

    #[error("unknown field: {table}.{field}")]
    UnknownField { table: String, field: String },

    /// First-device bootstrap was invoked on a handle that is not in the
    /// pre-first-sync "sole device" state. The string names the specific
    /// guard condition that failed.
    #[error("bootstrap not allowed: {0}")]
    BootstrapNotAllowed(String),

    /// Local snapshot probe produced a zstd-compressed blob larger than
    /// `MAX_SNAPSHOT_COMPRESSED_BYTES`. Reported to the caller before any
    /// upload is attempted.
    #[error("snapshot too large: {bytes} bytes exceeds compressed limit")]
    SnapshotTooLarge { bytes: usize },
}

/// Coarse relay error classification for retry logic.
#[derive(Debug, Clone, PartialEq)]
pub enum RelayErrorCategory {
    Network,
    Auth,
    DeviceIdentityMismatch,
    Server,
    Protocol,
    Other,
}

impl CoreError {
    pub fn from_relay(error: RelayError) -> Self {
        Self::from_relay_with_context(None, error)
    }

    pub fn from_relay_with_context(context: Option<&str>, error: RelayError) -> Self {
        let message = match context {
            Some(context) => format!("{context}: {error}"),
            None => error.to_string(),
        };

        let (kind, status, code, min_signature_version, remote_wipe) = match error {
            RelayError::Network { .. } | RelayError::Timeout { .. } => {
                (RelayErrorCategory::Network, None, None, None, None)
            }
            RelayError::Server { status_code, .. } => {
                (RelayErrorCategory::Server, Some(status_code), None, None, None)
            }
            RelayError::Auth { .. } => (RelayErrorCategory::Auth, None, None, None, None),
            RelayError::UpgradeRequired { min_signature_version, .. } => (
                RelayErrorCategory::Auth,
                Some(403),
                Some("upgrade_required".to_string()),
                Some(min_signature_version),
                None,
            ),
            RelayError::DeviceIdentityMismatch { .. } => (
                RelayErrorCategory::DeviceIdentityMismatch,
                None,
                Some("device_identity_mismatch".to_string()),
                None,
                None,
            ),
            RelayError::DeviceRevoked { remote_wipe } => (
                RelayErrorCategory::Auth,
                None,
                Some("device_revoked".to_string()),
                None,
                Some(remote_wipe),
            ),
            RelayError::MustBootstrapFromSnapshot { .. } => (
                RelayErrorCategory::Protocol,
                Some(409),
                Some("must_bootstrap_from_snapshot".to_string()),
                None,
                None,
            ),
            RelayError::Protocol { .. }
            | RelayError::EpochRotation { .. }
            | RelayError::ClockSkew { .. }
            | RelayError::KeyChanged { .. } => {
                (RelayErrorCategory::Protocol, None, None, None, None)
            }
            RelayError::NotFound => (RelayErrorCategory::Server, Some(404), None, None, None),
            RelayError::Forbidden { .. } => (RelayErrorCategory::Auth, Some(403), None, None, None),
            RelayError::Http { status, .. } => {
                (RelayErrorCategory::Server, Some(status), None, None, None)
            }
        };

        CoreError::Relay {
            message,
            kind,
            status,
            code,
            min_signature_version,
            remote_wipe,
            source: Some(error),
        }
    }

    /// Whether this error is transient and the operation should be retried.
    ///
    /// Only relay-level `Network` and `Server` errors are retryable.
    /// Auth failures, protocol errors, device revocations, and all local
    /// errors (storage, crypto, schema) are permanent.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            CoreError::Relay { kind: RelayErrorCategory::Network | RelayErrorCategory::Server, .. }
        )
    }
}

impl From<RelayError> for CoreError {
    fn from(error: RelayError) -> Self {
        Self::from_relay(error)
    }
}

impl From<rusqlite::Error> for CoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Storage(StorageError::Sqlite(error))
    }
}

pub type Result<T> = std::result::Result<T, CoreError>;

#[cfg(test)]
mod tests {
    use super::{CoreError, RelayErrorCategory};
    use crate::relay::traits::RelayError;

    #[test]
    fn from_relay_preserves_device_identity_mismatch_code() {
        let error = CoreError::from_relay(RelayError::DeviceIdentityMismatch {
            message: "keys do not match".into(),
        });

        assert!(matches!(
            error,
            CoreError::Relay {
                kind: RelayErrorCategory::DeviceIdentityMismatch,
                code: Some(ref code),
                remote_wipe: None,
                ..
            } if code == "device_identity_mismatch"
        ));
    }

    #[test]
    fn from_relay_preserves_device_revoked_remote_wipe() {
        let error = CoreError::from_relay(RelayError::DeviceRevoked { remote_wipe: true });

        assert!(matches!(
            error,
            CoreError::Relay {
                kind: RelayErrorCategory::Auth,
                code: Some(ref code),
                remote_wipe: Some(true),
                ..
            } if code == "device_revoked"
        ));
    }

    #[test]
    fn from_relay_preserves_must_bootstrap_from_snapshot_code() {
        let error = CoreError::from_relay(RelayError::MustBootstrapFromSnapshot {
            since_seq: 2,
            first_retained_seq: 5,
            message: "bootstrap".into(),
        });

        assert!(matches!(
            error,
            CoreError::Relay {
                kind: RelayErrorCategory::Protocol,
                status: Some(409),
                code: Some(ref code),
                remote_wipe: None,
                ..
            } if code == "must_bootstrap_from_snapshot"
        ));
    }
}
