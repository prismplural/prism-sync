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
    },

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
    Server,
    Protocol,
    Other,
}

pub type Result<T> = std::result::Result<T, CoreError>;
