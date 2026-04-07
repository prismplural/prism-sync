//! Shared KEM boundary — the only layer that turns public bootstrap key
//! material into the shared secret consumed by the key schedule.
//!
//! Wraps the `HybridKem` trait from `prism-sync-crypto` so that upper layers
//! (key schedule, transcript, confirmation) never touch raw KEM types.

use core::marker::PhantomData;

use prism_sync_crypto::pq::hybrid_kem::{HybridKem, XWingKem};
use zeroize::Zeroizing;

use crate::error::{CoreError, Result};

// ---------------------------------------------------------------------------
// BootstrapSecret
// ---------------------------------------------------------------------------

/// Typed wrapper for the raw shared secret from a KEM operation.
///
/// Created only by [`BootstrapHandshake`], consumed only by
/// `BootstrapKeySchedule`.  The inner bytes are zeroized on drop.
pub struct BootstrapSecret(Zeroizing<Vec<u8>>);

impl BootstrapSecret {
    /// View the raw shared-secret bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consume the wrapper, returning the zeroizing container.
    pub fn into_zeroizing(self) -> Zeroizing<Vec<u8>> {
        self.0
    }
}

// ---------------------------------------------------------------------------
// BootstrapHandshake
// ---------------------------------------------------------------------------

/// Shared KEM boundary — encapsulates/decapsulates through the [`HybridKem`]
/// trait without exposing raw KEM types to the rest of the bootstrap stack.
pub struct BootstrapHandshake<K: HybridKem>(PhantomData<K>);

impl<K: HybridKem> BootstrapHandshake<K> {
    /// Parse the peer's serialised encapsulation key and encapsulate to it.
    ///
    /// Returns `(ciphertext_bytes, shared_secret)`.
    pub fn encapsulate_to_peer<R: rand_core::CryptoRng + ?Sized>(
        peer_ek_bytes: &[u8],
        rng: &mut R,
    ) -> Result<(Vec<u8>, BootstrapSecret)> {
        let ek = K::encapsulation_key_from_bytes(peer_ek_bytes).map_err(CoreError::Crypto)?;
        let (ct, ss) = K::encapsulate(&ek, rng);
        Ok((ct, BootstrapSecret(Zeroizing::new(ss))))
    }

    /// Decapsulate the peer's ciphertext with the local decapsulation key.
    pub fn decapsulate_from_peer(
        local_dk: &K::DecapsulationKey,
        ciphertext: &[u8],
    ) -> Result<BootstrapSecret> {
        let ss = K::decapsulate(local_dk, ciphertext).map_err(CoreError::Crypto)?;
        Ok(BootstrapSecret(Zeroizing::new(ss)))
    }
}

/// Concrete type alias wired to X-Wing (X25519 + ML-KEM-768).
pub type DefaultBootstrapHandshake = BootstrapHandshake<XWingKem>;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use prism_sync_crypto::pq::hybrid_kem::XWingKem;

    fn rng() -> getrandom::rand_core::UnwrapErr<getrandom::SysRng> {
        getrandom::rand_core::UnwrapErr(getrandom::SysRng)
    }

    #[test]
    fn encapsulate_decapsulate_agreement() {
        let dk = XWingKem::decapsulation_key_from_bytes(&[42u8; 32]);
        let ek_bytes = XWingKem::encapsulation_key_bytes(&dk);

        let (ct, secret_enc) =
            DefaultBootstrapHandshake::encapsulate_to_peer(&ek_bytes, &mut rng()).unwrap();
        let secret_dec = DefaultBootstrapHandshake::decapsulate_from_peer(&dk, &ct).unwrap();

        assert_eq!(secret_enc.as_bytes(), secret_dec.as_bytes());
    }

    #[test]
    fn malformed_ciphertext_rejected() {
        let dk = XWingKem::decapsulation_key_from_bytes(&[42u8; 32]);
        let result = DefaultBootstrapHandshake::decapsulate_from_peer(&dk, &[0xFFu8; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn malformed_ek_rejected() {
        let result = DefaultBootstrapHandshake::encapsulate_to_peer(&[0xFFu8; 10], &mut rng());
        assert!(result.is_err());
    }

    #[test]
    fn bootstrap_secret_is_32_bytes() {
        let dk = XWingKem::decapsulation_key_from_bytes(&[42u8; 32]);
        let ek_bytes = XWingKem::encapsulation_key_bytes(&dk);

        let (_ct, secret) =
            DefaultBootstrapHandshake::encapsulate_to_peer(&ek_bytes, &mut rng()).unwrap();
        assert_eq!(secret.as_bytes().len(), 32);
    }

    #[test]
    fn different_keys_different_secrets() {
        let dk1 = XWingKem::decapsulation_key_from_bytes(&[1u8; 32]);
        let dk2 = XWingKem::decapsulation_key_from_bytes(&[2u8; 32]);

        let ek1_bytes = XWingKem::encapsulation_key_bytes(&dk1);
        let ek2_bytes = XWingKem::encapsulation_key_bytes(&dk2);

        let (_ct1, secret1) =
            DefaultBootstrapHandshake::encapsulate_to_peer(&ek1_bytes, &mut rng()).unwrap();
        let (_ct2, secret2) =
            DefaultBootstrapHandshake::encapsulate_to_peer(&ek2_bytes, &mut rng()).unwrap();

        assert_ne!(secret1.as_bytes(), secret2.as_bytes());
    }
}
