use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{CryptoError, Result};
use crate::kdf;

/// Per-device secret (32 bytes from CSPRNG). Stored in SecureStore.
/// Never leaves the device. Never derived from the shared DEK.
#[derive(ZeroizeOnDrop)]
pub struct DeviceSecret {
    secret: Vec<u8>,
}

impl DeviceSecret {
    pub fn generate() -> Self {
        let mut secret = vec![0u8; 32];
        OsRng.fill_bytes(&mut secret);
        Self { secret }
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidKeyMaterial(format!(
                "device secret must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        Ok(Self { secret: bytes })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.secret
    }

    /// Derive Ed25519 signing keypair.
    /// HKDF: ikm=device_secret, salt=device_id, info="prism_device_ed25519"
    pub fn ed25519_keypair(&self, device_id: &str) -> Result<DeviceSigningKey> {
        let seed = kdf::derive_subkey(&self.secret, device_id.as_bytes(), b"prism_device_ed25519")?;
        let mut seed_arr = [0u8; 32];
        seed_arr.copy_from_slice(&seed);
        let signing_key = SigningKey::from_bytes(&seed_arr);
        seed_arr.zeroize();
        Ok(DeviceSigningKey { signing_key })
    }

    /// Derive X25519 key exchange keypair.
    /// HKDF: ikm=device_secret, salt=device_id, info="prism_device_x25519"
    pub fn x25519_keypair(&self, device_id: &str) -> Result<DeviceExchangeKey> {
        let seed = kdf::derive_subkey(&self.secret, device_id.as_bytes(), b"prism_device_x25519")?;
        let mut seed_arr = [0u8; 32];
        seed_arr.copy_from_slice(&seed);
        let secret_key = StaticSecret::from(seed_arr);
        seed_arr.zeroize();
        let public_key = X25519PublicKey::from(&secret_key);
        Ok(DeviceExchangeKey {
            secret_key,
            public_key,
        })
    }
}

/// Ed25519 signing key for batch signatures, registration challenges, SAS.
pub struct DeviceSigningKey {
    signing_key: SigningKey,
}

impl DeviceSigningKey {
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.signing_key.sign(message).to_bytes().to_vec()
    }

    /// Consume this wrapper and return the inner [`ed25519_dalek::SigningKey`].
    pub fn into_signing_key(self) -> SigningKey {
        self.signing_key
    }

    pub fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8]) -> Result<()> {
        let verifying_key = VerifyingKey::from_bytes(public_key)
            .map_err(|e| CryptoError::InvalidKeyMaterial(format!("invalid public key: {e}")))?;
        let sig = Signature::from_slice(signature)
            .map_err(|e| CryptoError::InvalidKeyMaterial(format!("invalid signature: {e}")))?;
        verifying_key.verify(message, &sig).map_err(|_| {
            CryptoError::SignatureVerificationFailed("Ed25519 signature does not match".into())
        })
    }
}

/// X25519 key exchange key for pairing and rekey artifact wrapping.
pub struct DeviceExchangeKey {
    secret_key: StaticSecret,
    public_key: X25519PublicKey,
}

impl DeviceExchangeKey {
    pub fn public_key_bytes(&self) -> [u8; 32] {
        *self.public_key.as_bytes()
    }

    pub fn diffie_hellman(&self, peer_public_key: &[u8; 32]) -> Vec<u8> {
        let peer = X25519PublicKey::from(*peer_public_key);
        self.secret_key.diffie_hellman(&peer).to_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_device_secret() {
        let secret = DeviceSecret::generate();
        assert_eq!(secret.as_bytes().len(), 32);
    }

    #[test]
    fn different_secrets_each_time() {
        let s1 = DeviceSecret::generate();
        let s2 = DeviceSecret::generate();
        assert_ne!(s1.as_bytes(), s2.as_bytes());
    }

    #[test]
    fn from_bytes_roundtrip() {
        let original = DeviceSecret::generate();
        let bytes = original.as_bytes().to_vec();
        let restored = DeviceSecret::from_bytes(bytes.clone()).unwrap();
        assert_eq!(restored.as_bytes(), &bytes);
    }

    #[test]
    fn from_bytes_wrong_length_fails() {
        assert!(DeviceSecret::from_bytes(vec![0u8; 16]).is_err());
    }

    #[test]
    fn ed25519_keypair_deterministic() {
        let secret = DeviceSecret::from_bytes(vec![42u8; 32]).unwrap();
        let kp1 = secret.ed25519_keypair("device_abc").unwrap();
        let kp2 = secret.ed25519_keypair("device_abc").unwrap();
        assert_eq!(kp1.public_key_bytes(), kp2.public_key_bytes());
    }

    #[test]
    fn ed25519_different_devices_different_keys() {
        let secret = DeviceSecret::from_bytes(vec![42u8; 32]).unwrap();
        let kp1 = secret.ed25519_keypair("device_a").unwrap();
        let kp2 = secret.ed25519_keypair("device_b").unwrap();
        assert_ne!(kp1.public_key_bytes(), kp2.public_key_bytes());
    }

    #[test]
    fn ed25519_sign_and_verify() {
        let secret = DeviceSecret::generate();
        let kp = secret.ed25519_keypair("my_device").unwrap();
        let message = b"hello, world!";
        let signature = kp.sign(message);
        assert_eq!(signature.len(), 64);
        DeviceSigningKey::verify(&kp.public_key_bytes(), message, &signature).unwrap();
    }

    #[test]
    fn ed25519_wrong_message_fails() {
        let secret = DeviceSecret::generate();
        let kp = secret.ed25519_keypair("my_device").unwrap();
        let signature = kp.sign(b"correct");
        assert!(DeviceSigningKey::verify(&kp.public_key_bytes(), b"wrong", &signature).is_err());
    }

    #[test]
    fn x25519_keypair_deterministic() {
        let secret = DeviceSecret::from_bytes(vec![42u8; 32]).unwrap();
        let kp1 = secret.x25519_keypair("device_abc").unwrap();
        let kp2 = secret.x25519_keypair("device_abc").unwrap();
        assert_eq!(kp1.public_key_bytes(), kp2.public_key_bytes());
    }

    #[test]
    fn x25519_diffie_hellman() {
        let secret_a = DeviceSecret::generate();
        let secret_b = DeviceSecret::generate();
        let kp_a = secret_a.x25519_keypair("device_a").unwrap();
        let kp_b = secret_b.x25519_keypair("device_b").unwrap();
        let shared_a = kp_a.diffie_hellman(&kp_b.public_key_bytes());
        let shared_b = kp_b.diffie_hellman(&kp_a.public_key_bytes());
        assert_eq!(shared_a, shared_b);
        assert_eq!(shared_a.len(), 32);
    }
}
