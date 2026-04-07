pub mod aead;
pub mod device_identity;
pub mod error;
pub mod hex;
pub mod kdf;
pub mod key_hierarchy;
pub mod mnemonic;
pub mod pq;

pub use device_identity::{
    DeviceExchangeKey, DevicePqKemKey, DevicePqSigningKey, DeviceSecret, DeviceSigningKey,
};
pub use error::CryptoError;
pub use key_hierarchy::KeyHierarchy;

/// Generate cryptographically secure random bytes.
pub fn random_bytes(len: usize) -> Vec<u8> {
    use rand::{rngs::OsRng, RngCore};
    let mut buf = vec![0u8; len];
    OsRng.fill_bytes(&mut buf);
    buf
}
