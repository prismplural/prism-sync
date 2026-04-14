use thiserror::Error;

/// Errors returned by prism-sync-crypto operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("key hierarchy is locked — call initialize() or unlock() first")]
    Locked,

    #[error("encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("invalid key material: {0}")]
    InvalidKeyMaterial(String),

    #[error("KDF failed: {0}")]
    KdfFailed(String),

    #[error("invalid mnemonic: {0}")]
    InvalidMnemonic(String),

    #[error("hex decode failed: {0}")]
    HexDecode(#[from] hex::FromHexError),

    #[error("serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("signature verification failed: {0}")]
    SignatureVerificationFailed(String),
}

pub type Result<T> = std::result::Result<T, CryptoError>;
