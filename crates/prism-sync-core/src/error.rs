use crate::relay::traits::RelayError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("HLC parse error: {0}")]
    HlcParse(String),

    #[error("HLC clock drift exceeded: drift={drift_ms}ms, max={max_ms}ms, device={device_id}")]
    ClockDrift {
        drift_ms: i64,
        max_ms: i64,
        device_id: String,
    },

    #[error("storage error: {0}")]
    Storage(String),

    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

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
        remote_wipe: Option<bool>,
    },

    #[error("device {device_id} key changed")]
    DeviceKeyChanged { device_id: String },

    #[error("engine error: {0}")]
    Engine(String),

    #[error("crypto error: {0}")]
    Crypto(#[from] prism_sync_crypto::CryptoError),

    #[error("unknown entity table: {0}")]
    UnknownTable(String),

    #[error("unknown field: {table}.{field}")]
    UnknownField { table: String, field: String },
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

        let (kind, status, code, remote_wipe) = match error {
            RelayError::Network { .. } | RelayError::Timeout { .. } => {
                (RelayErrorCategory::Network, None, None, None)
            }
            RelayError::Server { status_code, .. } => {
                (RelayErrorCategory::Server, Some(status_code), None, None)
            }
            RelayError::Auth { .. } => (RelayErrorCategory::Auth, None, None, None),
            RelayError::DeviceIdentityMismatch { .. } => (
                RelayErrorCategory::DeviceIdentityMismatch,
                None,
                Some("device_identity_mismatch".to_string()),
                None,
            ),
            RelayError::DeviceRevoked { remote_wipe } => (
                RelayErrorCategory::Auth,
                None,
                Some("device_revoked".to_string()),
                Some(remote_wipe),
            ),
            RelayError::Protocol { .. }
            | RelayError::EpochRotation { .. }
            | RelayError::ClockSkew { .. }
            | RelayError::KeyChanged { .. } => (RelayErrorCategory::Protocol, None, None, None),
        };

        CoreError::Relay {
            message,
            kind,
            status,
            code,
            remote_wipe,
        }
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
}
