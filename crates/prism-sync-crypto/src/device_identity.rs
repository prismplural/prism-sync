use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use ml_dsa::MlDsa65;
use ml_kem::MlKem768;
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

    /// Derive ML-DSA-65 signing keypair (generation 0).
    /// HKDF: ikm=device_secret, salt=device_id, info="prism_device_ml_dsa_65"
    /// Uses `ExpandedSigningKey` which implements `ZeroizeOnDrop`.
    pub fn ml_dsa_65_keypair(&self, device_id: &str) -> Result<DevicePqSigningKey> {
        self.ml_dsa_65_keypair_v(device_id, 0)
    }

    /// Derive a versioned ML-DSA-65 signing keypair for key rotation.
    ///
    /// - Generation 0: info = `"prism_device_ml_dsa_65"` (backward-compatible)
    /// - Generation N>0: info = `"prism_device_ml_dsa_65_v{N}"`
    pub fn ml_dsa_65_keypair_v(
        &self,
        device_id: &str,
        generation: u32,
    ) -> Result<DevicePqSigningKey> {
        let info: Vec<u8> = if generation == 0 {
            b"prism_device_ml_dsa_65".to_vec()
        } else {
            format!("prism_device_ml_dsa_65_v{generation}")
                .into_bytes()
        };
        let seed = kdf::derive_subkey(&self.secret, device_id.as_bytes(), &info)?;
        let mut seed_arr = ml_dsa::B32::try_from(seed.as_slice())
            .map_err(|_| CryptoError::KdfFailed("ML-DSA seed length mismatch".into()))?;
        let signing_key = ml_dsa::ExpandedSigningKey::<MlDsa65>::from_seed(&seed_arr);
        seed_arr.zeroize();
        Ok(DevicePqSigningKey { signing_key })
    }

    /// Derive ML-KEM-768 key encapsulation keypair.
    /// HKDF: ikm=device_secret, salt=device_id, info="prism_device_ml_kem_768"
    pub fn ml_kem_768_keypair(&self, device_id: &str) -> Result<DevicePqKemKey> {
        let seed_bytes = kdf::derive_subkey_long(
            &self.secret,
            device_id.as_bytes(),
            b"prism_device_ml_kem_768",
            64,
        )?;
        let mut seed = ml_kem::Seed::try_from(seed_bytes.as_slice())
            .map_err(|_| CryptoError::KdfFailed("ML-KEM seed length mismatch".into()))?;
        let dk = ml_kem::DecapsulationKey::<MlKem768>::from_seed(core::mem::take(&mut seed));
        seed.zeroize();
        Ok(DevicePqKemKey {
            decapsulation_key: dk,
        })
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
#[derive(ZeroizeOnDrop)]
pub struct DeviceExchangeKey {
    secret_key: StaticSecret,
    #[zeroize(skip)]
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

/// ML-DSA-65 signing key for post-quantum signatures.
/// Uses `ExpandedSigningKey` which implements `ZeroizeOnDrop` for secret material.
pub struct DevicePqSigningKey {
    signing_key: ml_dsa::ExpandedSigningKey<MlDsa65>,
}

impl DevicePqSigningKey {
    /// Access the inner `ExpandedSigningKey` (e.g. for `HybridSignature::sign_v3`).
    pub fn as_signing_key(&self) -> &ml_dsa::ExpandedSigningKey<MlDsa65> {
        &self.signing_key
    }

    /// Get the encoded verifying (public) key bytes (1952 bytes).
    pub fn public_key_bytes(&self) -> Vec<u8> {
        let vk = self.signing_key.verifying_key();
        let encoded = vk.encode();
        AsRef::<[u8]>::as_ref(&encoded).to_vec()
    }

    /// Sign a message, returning the ML-DSA-65 signature.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        use ml_dsa::signature::Signer;
        let sig = self.signing_key.sign(message);
        let sig_bytes = sig.encode();
        AsRef::<[u8]>::as_ref(&sig_bytes).to_vec()
    }

    /// Verify a ML-DSA-65 signature against a public key.
    pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
        use ml_dsa::signature::Verifier;

        let enc = ml_dsa::EncodedVerifyingKey::<MlDsa65>::try_from(public_key).map_err(|_| {
            CryptoError::InvalidKeyMaterial("invalid ML-DSA-65 public key length".into())
        })?;
        let vk = ml_dsa::VerifyingKey::<MlDsa65>::decode(&enc);

        let sig = ml_dsa::Signature::<MlDsa65>::try_from(signature)
            .map_err(|_| CryptoError::InvalidKeyMaterial("invalid ML-DSA-65 signature".into()))?;

        vk.verify(message, &sig).map_err(|_| {
            CryptoError::SignatureVerificationFailed("ML-DSA-65 signature does not match".into())
        })
    }
}

/// ML-KEM-768 key encapsulation key.
pub struct DevicePqKemKey {
    decapsulation_key: ml_kem::DecapsulationKey<MlKem768>,
}

impl DevicePqKemKey {
    /// Get the encoded encapsulation (public) key bytes (1184 bytes).
    pub fn public_key_bytes(&self) -> Vec<u8> {
        use ml_kem::KeyExport;
        self.decapsulation_key
            .encapsulation_key()
            .to_bytes()
            .to_vec()
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

    #[test]
    fn ml_dsa_65_keypair_deterministic() {
        let secret = DeviceSecret::from_bytes(vec![42u8; 32]).unwrap();
        let kp1 = secret.ml_dsa_65_keypair("device_abc").unwrap();
        let kp2 = secret.ml_dsa_65_keypair("device_abc").unwrap();
        assert_eq!(kp1.public_key_bytes(), kp2.public_key_bytes());
    }

    #[test]
    fn ml_dsa_65_different_devices_different_keys() {
        let secret = DeviceSecret::from_bytes(vec![42u8; 32]).unwrap();
        let kp1 = secret.ml_dsa_65_keypair("device_a").unwrap();
        let kp2 = secret.ml_dsa_65_keypair("device_b").unwrap();
        assert_ne!(kp1.public_key_bytes(), kp2.public_key_bytes());
    }

    #[test]
    fn ml_dsa_65_sign_and_verify() {
        let secret = DeviceSecret::generate();
        let kp = secret.ml_dsa_65_keypair("my_device").unwrap();
        let message = b"hello, world!";
        let signature = kp.sign(message);
        DevicePqSigningKey::verify(&kp.public_key_bytes(), message, &signature).unwrap();
    }

    #[test]
    fn ml_dsa_65_wrong_message_fails() {
        let secret = DeviceSecret::generate();
        let kp = secret.ml_dsa_65_keypair("my_device").unwrap();
        let signature = kp.sign(b"correct");
        assert!(DevicePqSigningKey::verify(&kp.public_key_bytes(), b"wrong", &signature).is_err());
    }

    #[test]
    fn ml_dsa_65_public_key_size() {
        let secret = DeviceSecret::generate();
        let kp = secret.ml_dsa_65_keypair("test").unwrap();
        assert_eq!(kp.public_key_bytes().len(), 1952);
    }

    #[test]
    fn ml_kem_768_keypair_deterministic() {
        let secret = DeviceSecret::from_bytes(vec![42u8; 32]).unwrap();
        let kp1 = secret.ml_kem_768_keypair("device_abc").unwrap();
        let kp2 = secret.ml_kem_768_keypair("device_abc").unwrap();
        assert_eq!(kp1.public_key_bytes(), kp2.public_key_bytes());
    }

    #[test]
    fn ml_kem_768_different_devices_different_keys() {
        let secret = DeviceSecret::from_bytes(vec![42u8; 32]).unwrap();
        let kp1 = secret.ml_kem_768_keypair("device_a").unwrap();
        let kp2 = secret.ml_kem_768_keypair("device_b").unwrap();
        assert_ne!(kp1.public_key_bytes(), kp2.public_key_bytes());
    }

    #[test]
    fn ml_kem_768_public_key_size() {
        let secret = DeviceSecret::generate();
        let kp = secret.ml_kem_768_keypair("test").unwrap();
        assert_eq!(kp.public_key_bytes().len(), 1184);
    }

    #[test]
    fn secret_key_types_impl_zeroize_on_drop() {
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

        assert_zeroize_on_drop::<DeviceSecret>();
        assert_zeroize_on_drop::<ed25519_dalek::SigningKey>();
        assert_zeroize_on_drop::<ml_dsa::ExpandedSigningKey<MlDsa65>>();
        assert_zeroize_on_drop::<ml_kem::DecapsulationKey<MlKem768>>();
        assert_zeroize_on_drop::<DeviceExchangeKey>();
    }

    #[test]
    fn ml_dsa_65_keypair_v_generation_0_matches_original() {
        let secret = DeviceSecret::generate();
        let original = secret.ml_dsa_65_keypair("device_abc").unwrap();
        let versioned = secret.ml_dsa_65_keypair_v("device_abc", 0).unwrap();
        assert_eq!(original.public_key_bytes(), versioned.public_key_bytes());
    }

    #[test]
    fn ml_dsa_65_keypair_v_different_generations_differ() {
        let secret = DeviceSecret::generate();
        let gen0 = secret.ml_dsa_65_keypair_v("device_abc", 0).unwrap();
        let gen1 = secret.ml_dsa_65_keypair_v("device_abc", 1).unwrap();
        let gen2 = secret.ml_dsa_65_keypair_v("device_abc", 2).unwrap();
        assert_ne!(gen0.public_key_bytes(), gen1.public_key_bytes());
        assert_ne!(gen1.public_key_bytes(), gen2.public_key_bytes());
        assert_ne!(gen0.public_key_bytes(), gen2.public_key_bytes());
    }

    #[test]
    fn ml_dsa_65_keypair_v_deterministic() {
        let secret = DeviceSecret::generate();
        let a = secret.ml_dsa_65_keypair_v("device_abc", 1).unwrap();
        let b = secret.ml_dsa_65_keypair_v("device_abc", 1).unwrap();
        assert_eq!(a.public_key_bytes(), b.public_key_bytes());
    }
}
