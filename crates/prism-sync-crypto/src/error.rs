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

    #[error("hex decode error: {0}")]
    HexDecode(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("signature verification failed: {0}")]
    SignatureVerificationFailed(String),
}

pub type Result<T> = std::result::Result<T, CryptoError>;
