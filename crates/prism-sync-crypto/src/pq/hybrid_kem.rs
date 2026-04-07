//! X-Wing hybrid KEM wrapper (X25519 + ML-KEM-768).
//!
//! Wraps the `x-wing` crate behind a trait to allow swapping if the
//! crate or IETF draft changes. The pinned `x-wing` crate currently targets
//! draft-connolly-cfrg-xwing-kem-06, so upgrades should be reviewed against
//! newer draft revisions before being adopted.

use crate::error::{CryptoError, Result};
use x_wing::kem::{Decapsulate, Decapsulator, Encapsulate};
use x_wing::{KeyExport, KeyInit};

/// Shared secret from a KEM operation (32 bytes).
pub type SharedSecret = Vec<u8>;

/// Trait for pluggable hybrid KEM backends.
pub trait HybridKem {
    type DecapsulationKey;
    type EncapsulationKey;

    /// Create a decapsulation key from 32 raw bytes.
    fn decapsulation_key_from_bytes(bytes: &[u8; 32]) -> Self::DecapsulationKey;

    /// Get the encapsulation (public) key bytes from a decapsulation key.
    fn encapsulation_key_bytes(dk: &Self::DecapsulationKey) -> Vec<u8>;

    /// Parse an encapsulation key from bytes.
    fn encapsulation_key_from_bytes(bytes: &[u8]) -> Result<Self::EncapsulationKey>;

    /// Encapsulate using the provided RNG.
    fn encapsulate<R: rand_core::CryptoRng + ?Sized>(
        ek: &Self::EncapsulationKey,
        rng: &mut R,
    ) -> (Vec<u8>, SharedSecret);

    /// Recover the shared secret from a ciphertext.
    fn decapsulate(dk: &Self::DecapsulationKey, ciphertext: &[u8]) -> Result<SharedSecret>;
}

/// X-Wing hybrid KEM combining X25519 + ML-KEM-768.
///
/// The decapsulation key is 32 bytes (expanded internally via SHAKE256).
/// The encapsulation key is 1216 bytes (1184 ML-KEM-768 + 32 X25519).
/// The ciphertext is 1120 bytes (1088 ML-KEM-768 + 32 X25519).
pub struct XWingKem;

impl HybridKem for XWingKem {
    type DecapsulationKey = x_wing::DecapsulationKey;
    type EncapsulationKey = x_wing::EncapsulationKey;

    fn decapsulation_key_from_bytes(bytes: &[u8; 32]) -> Self::DecapsulationKey {
        x_wing::DecapsulationKey::new(bytes.into())
    }

    fn encapsulation_key_bytes(dk: &Self::DecapsulationKey) -> Vec<u8> {
        dk.encapsulation_key().to_bytes().to_vec()
    }

    fn encapsulation_key_from_bytes(bytes: &[u8]) -> Result<Self::EncapsulationKey> {
        x_wing::EncapsulationKey::try_from(bytes)
            .map_err(|_| CryptoError::InvalidKeyMaterial("invalid X-Wing encapsulation key".into()))
    }

    fn encapsulate<R: rand_core::CryptoRng + ?Sized>(
        ek: &Self::EncapsulationKey,
        rng: &mut R,
    ) -> (Vec<u8>, SharedSecret) {
        let (ct, ss) = ek.encapsulate_with_rng(rng);
        let ct_bytes: &[u8] = AsRef::<[u8]>::as_ref(&ct);
        (ct_bytes.to_vec(), ss.as_slice().to_vec())
    }

    fn decapsulate(dk: &Self::DecapsulationKey, ciphertext: &[u8]) -> Result<SharedSecret> {
        let ct = x_wing::Ciphertext::try_from(ciphertext).map_err(|_| {
            CryptoError::DecryptionFailed("invalid X-Wing ciphertext length".into())
        })?;
        let ss = dk.decapsulate(&ct);
        Ok(ss.as_slice().to_vec())
    }
}

impl XWingKem {
    /// Create a decapsulation key from 32 raw bytes.
    pub fn decapsulation_key_from_bytes(bytes: &[u8; 32]) -> x_wing::DecapsulationKey {
        <Self as HybridKem>::decapsulation_key_from_bytes(bytes)
    }

    /// Get the encapsulation (public) key bytes from a decapsulation key.
    pub fn encapsulation_key_bytes(dk: &x_wing::DecapsulationKey) -> Vec<u8> {
        <Self as HybridKem>::encapsulation_key_bytes(dk)
    }

    /// Parse an encapsulation key from bytes.
    pub fn encapsulation_key_from_bytes(bytes: &[u8]) -> Result<x_wing::EncapsulationKey> {
        <Self as HybridKem>::encapsulation_key_from_bytes(bytes)
    }

    /// Encapsulate using the provided RNG.
    pub fn encapsulate<R: rand_core::CryptoRng + ?Sized>(
        ek: &x_wing::EncapsulationKey,
        rng: &mut R,
    ) -> (Vec<u8>, SharedSecret) {
        <Self as HybridKem>::encapsulate(ek, rng)
    }

    /// Recover the shared secret from a ciphertext.
    pub fn decapsulate(dk: &x_wing::DecapsulationKey, ciphertext: &[u8]) -> Result<SharedSecret> {
        <Self as HybridKem>::decapsulate(dk, ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::convert::Infallible;

    fn rng() -> getrandom::rand_core::UnwrapErr<getrandom::SysRng> {
        getrandom::rand_core::UnwrapErr(getrandom::SysRng)
    }

    struct FixedRng {
        bytes: [u8; 64],
        offset: usize,
    }

    impl FixedRng {
        fn from_hex(hex: &str) -> Self {
            let bytes = crate::hex::decode(hex).unwrap();
            let bytes: [u8; 64] = bytes.try_into().unwrap();
            Self { bytes, offset: 0 }
        }
    }

    impl rand_core::TryRng for FixedRng {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> core::result::Result<u32, Self::Error> {
            let mut buf = [0u8; 4];
            self.try_fill_bytes(&mut buf)
                .expect("fixed RNG cannot fail");
            Ok(u32::from_le_bytes(buf))
        }

        fn try_next_u64(&mut self) -> core::result::Result<u64, Self::Error> {
            let mut buf = [0u8; 8];
            self.try_fill_bytes(&mut buf)
                .expect("fixed RNG cannot fail");
            Ok(u64::from_le_bytes(buf))
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), Self::Error> {
            let end = self.offset + dest.len();
            dest.copy_from_slice(&self.bytes[self.offset..end]);
            self.offset = end;
            Ok(())
        }
    }

    impl rand_core::TryCryptoRng for FixedRng {}

    #[test]
    fn xwing_round_trip() {
        let dk = XWingKem::decapsulation_key_from_bytes(&[42u8; 32]);
        let ek_bytes = XWingKem::encapsulation_key_bytes(&dk);
        let ek = XWingKem::encapsulation_key_from_bytes(&ek_bytes).unwrap();

        let (ct, ss_enc) = XWingKem::encapsulate(&ek, &mut rng());
        let ss_dec = XWingKem::decapsulate(&dk, &ct).unwrap();

        assert_eq!(ss_enc, ss_dec);
        assert_eq!(ss_enc.len(), 32);
    }

    #[test]
    fn xwing_deterministic_key() {
        let dk1 = XWingKem::decapsulation_key_from_bytes(&[42u8; 32]);
        let dk2 = XWingKem::decapsulation_key_from_bytes(&[42u8; 32]);
        assert_eq!(
            XWingKem::encapsulation_key_bytes(&dk1),
            XWingKem::encapsulation_key_bytes(&dk2),
        );
    }

    #[test]
    fn xwing_different_keys_different_ek() {
        let dk1 = XWingKem::decapsulation_key_from_bytes(&[1u8; 32]);
        let dk2 = XWingKem::decapsulation_key_from_bytes(&[2u8; 32]);
        assert_ne!(
            XWingKem::encapsulation_key_bytes(&dk1),
            XWingKem::encapsulation_key_bytes(&dk2),
        );
    }

    #[test]
    fn xwing_key_sizes() {
        let dk = XWingKem::decapsulation_key_from_bytes(&[42u8; 32]);
        let ek_bytes = XWingKem::encapsulation_key_bytes(&dk);
        assert_eq!(ek_bytes.len(), 1216); // 1184 ML-KEM + 32 X25519

        let ek = XWingKem::encapsulation_key_from_bytes(&ek_bytes).unwrap();
        let (ct, _ss) = XWingKem::encapsulate(&ek, &mut rng());
        assert_eq!(ct.len(), 1120); // 1088 ML-KEM + 32 X25519
    }

    #[test]
    fn xwing_wrong_ciphertext_fails() {
        let dk = XWingKem::decapsulation_key_from_bytes(&[42u8; 32]);
        // Too short
        assert!(XWingKem::decapsulate(&dk, &[0u8; 10]).is_err());
    }

    #[test]
    fn xwing_wrong_ek_fails() {
        assert!(XWingKem::encapsulation_key_from_bytes(&[0u8; 10]).is_err());
    }

    #[test]
    fn xwing_trait_round_trip() {
        let dk = <XWingKem as HybridKem>::decapsulation_key_from_bytes(&[42u8; 32]);
        let ek_bytes = <XWingKem as HybridKem>::encapsulation_key_bytes(&dk);
        let ek = <XWingKem as HybridKem>::encapsulation_key_from_bytes(&ek_bytes).unwrap();

        let (ct, ss_enc) = <XWingKem as HybridKem>::encapsulate(&ek, &mut rng());
        let ss_dec = <XWingKem as HybridKem>::decapsulate(&dk, &ct).unwrap();

        assert_eq!(ss_enc, ss_dec);
    }

    #[test]
    fn xwing_matches_draft_vector_1() {
        let seed_hex = "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26";
        let eseed_hex = concat!(
            "3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2",
            "35b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2",
        );
        let expected_pk_hex = concat!(
            "e2236b35a8c24b39b10aa1323a96a919a2ced88400633a7b07131713fc14b2b5",
            "b19cfc3da5fa1a92c49f25513e0fd30d6b1611c9ab9635d7086727a4b7d21d34",
            "244e66969cf15b3b2a785329f61b096b277ea037383479a6b556de7231fe4b7f",
            "a9c9ac24c0699a0018a5253401bacfa905ca816573e56a2d2e067e9b7287533b",
            "a13a937dedb31fa44baced40769923610034ae31e619a170245199b3c5c39864",
            "859fe1b4c9717a07c30495bdfb98a0a002ccf56c1286cef5041dede3c44cf16b",
            "f562c7448518026b3d8b9940680abd38a1575fd27b58da063bfac32c39c30869",
            "374c05c1aeb1898b6b303cc68be455346ee0af699636224a148ca2aea1046311",
            "1c709f69b69c70ce8538746698c4c60a9aef0030c7924ceec42a5d36816f545e",
            "ae13293460b3acb37ea0e13d70e4aa78686da398a8397c08eaf96882113fe4f7",
            "bad4da40b0501e1c753efe73053c87014e8661c33099afe8bede414a5b1aa27d",
            "8392b3e131e9a70c1055878240cad0f40d5fe3cdf85236ead97e2a97448363b2",
            "808caafd516cd25052c5c362543c2517e4acd0e60ec07163009b6425fc32277a",
            "cee71c24bab53ed9f29e74c66a0a3564955998d76b96a9a8b50d1635a4d7a67e",
            "b42df5644d330457293a8042f53cc7a69288f17ed55827e82b28e82665a86a14",
            "fbd96645eca8172c044f83bc0d8c0b4c8626985631ca87af829068f1358963cb",
            "333664ca482763ba3b3bb208577f9ba6ac62c25f76592743b64be519317714cb",
            "4102cb7b2f9a25b2b4f0615de31decd9ca55026d6da0b65111b16fe52feed8a4",
            "87e144462a6dba93728f500b6ffc49e515569ef25fed17aff520507368253525",
            "860f58be3be61c964604a6ac814e6935596402a520a4670b3d284318866593d1",
            "5a4bb01c35e3e587ee0c67d2880d6f2407fb7a70712b838deb96c5d7bf2b44bc",
            "f6038ccbe33fbcf51a54a584fe90083c91c7a6d43d4fb15f48c60c2fd66e0a8a",
            "ad4ad64e5c42bb8877c0ebec2b5e387c8a988fdc23beb9e16c8757781e0a1499",
            "c61e138c21f216c29d076979871caa6942bafc090544bee99b54b16cb9a9a364",
            "d6246d9f42cce53c66b59c45c8f9ae9299a75d15180c3c952151a91b7a107724",
            "29dc4cbae6fcc622fa8018c63439f890630b9928db6bb7f9438ae4065ed34d73",
            "d486f3f52f90f0807dc88dfdd8c728e954f1ac35c06c000ce41a0582580e3bb5",
            "7b672972890ac5e7988e7850657116f1b57d0809aaedec0bede1ae148148311c",
            "6f7e317346e5189fb8cd635b986f8c0bdd27641c584b778b3a911a80be1c9692",
            "ab8e1bbb12839573cce19df183b45835bbb55052f9fc66a1678ef2a36dea7841",
            "1e6c8d60501b4e60592d13698a943b509185db912e2ea10be06171236b327c71",
            "716094c964a68b03377f513a05bcd99c1f346583bb052977a10a12adfc758034",
            "e5617da4c1276585e5774e1f3b9978b09d0e9c44d3bc86151c43aad185712717",
            "340223ac381d21150a04294e97bb13bbda21b5a182b6da969e19a7fd072737fa",
            "8e880a53c2428e3d049b7d2197405296ddb361912a7bcf4827ced611d0c7a7da",
            "104dde4322095339f64a61d5bb108ff0bf4d780cae509fb22c256914193ff734",
            "9042581237d522828824ee3bdfd07fb03f1f942d2ea179fe722f06cc03de5b69",
            "859edb06eff389b27dce59844570216223593d4ba32d9abac8cd049040ef6534",
        );
        let expected_ct_hex = concat!(
            "b83aa828d4d62b9a83ceffe1d3d3bb1ef31264643c070c5798927e41fb07914a",
            "273f8f96e7826cd5375a283d7da885304c5de0516a0f0654243dc5b97f8bfeb8",
            "31f68251219aabdd723bc6512041acbaef8af44265524942b902e68ffd23221c",
            "da70b1b55d776a92d1143ea3a0c475f63ee6890157c7116dae3f62bf72f60acd",
            "2bb8cc31ce2ba0de364f52b8ed38c79d719715963a5dd3842d8e8b43ab704e47",
            "59b5327bf027c63c8fa857c4908d5a8a7b88ac7f2be394d93c3706ddd4e698cc",
            "6ce370101f4d0213254238b4a2e8821b6e414a1cf20f6c1244b699046f5a01ca",
            "a0a1a55516300b40d2048c77cc73afba79afeea9d2c0118bdf2adb8870dc328c",
            "5516cc45b1a2058141039e2c90a110a9e16b318dfb53bd49a126d6b73f215787",
            "517b8917cc01cabd107d06859854ee8b4f9861c226d3764c87339ab16c3667d2",
            "f49384e55456dd40414b70a6af841585f4c90c68725d57704ee8ee7ce6e2f9be",
            "582dbee985e038ffc346ebfb4e22158b6c84374a9ab4a44e1f91de5aac5197f8",
            "9bc5e5442f51f9a5937b102ba3beaebf6e1c58380a4a5fedce4a4e5026f88f52",
            "8f59ffd2db41752b3a3d90efabe463899b7d40870c530c8841e8712b733668ed",
            "033adbfafb2d49d37a44d4064e5863eb0af0a08d47b3cc888373bc05f7a33b84",
            "1bc2587c57eb69554e8a3767b7506917b6b70498727f16eac1a36ec8d8cfaf75",
            "1549f2277db277e8a55a9a5106b23a0206b4721fa9b3048552c5bd5b594d6e24",
            "7f38c18c591aea7f56249c72ce7b117afcc3a8621582f9cf71787e183dee0936",
            "7976e98409ad9217a497df888042384d7707a6b78f5f7fb8409e3b5351753734",
            "61b776002d799cbad62860be70573ecbe13b246e0da7e93a52168e0fb6a9756b",
            "895ef7f0147a0dc81bfa644b088a9228160c0f9acf1379a2941cd28c06ebc80e",
            "44e17aa2f8177010afd78a97ce0868d1629ebb294c5151812c583daeb8868522",
            "0f4da9118112e07041fcc24d5564a99fdbde28869fe0722387d7a9a4d16e1cc8",
            "555917e09944aa5ebaaaec2cf62693afad42a3f518fce67d273cc6c9fb5472b3",
            "80e8573ec7de06a3ba2fd5f931d725b493026cb0acbd3fe62d00e4c790d965d7",
            "a03a3c0b4222ba8c2a9a16e2ac658f572ae0e746eafc4feba023576f08942278",
            "a041fb82a70a595d5bacbf297ce2029898a71e5c3b0d1c6228b485b1ade509b3",
            "5fbca7eca97b2132e7cb6bc465375146b7dceac969308ac0c2ac89e7863eb894",
            "3015b24314cafb9c7c0e85fe543d56658c213632599efabfc1ec49dd8c88547b",
            "b2cc40c9d38cbd3099b4547840560531d0188cd1e9c23a0ebee0a03d5577d66b",
            "1d2bcb4baaf21cc7fef1e03806ca96299df0dfbc56e1b2b43e4fc20c37f834c4",
            "af62127e7dae86c3c25a2f696ac8b589dec71d595bfbe94b5ed4bc07d800b330",
            "796fda89edb77be0294136139354eb8cd37591578f9c600dd9be8ec6219fdd50",
            "7adf3397ed4d68707b8d13b24ce4cd8fb22851bfe9d632407f31ed6f7cb1600d",
            "e56f17576740ce2a32fc5145030145cfb97e63e0e41d354274a079d3e6fb2e15",
        );
        let expected_ss_hex = "d2df0522128f09dd8e2c92b1e905c793d8f57a54c3da25861f10bf4ca613e384";

        let seed_bytes: [u8; 32] = crate::hex::decode(seed_hex).unwrap().try_into().unwrap();
        let expected_pk = crate::hex::decode(expected_pk_hex).unwrap();
        let expected_ct = crate::hex::decode(expected_ct_hex).unwrap();
        let expected_ss = crate::hex::decode(expected_ss_hex).unwrap();

        let dk = XWingKem::decapsulation_key_from_bytes(&seed_bytes);
        let ek_bytes = XWingKem::encapsulation_key_bytes(&dk);
        assert_eq!(ek_bytes, expected_pk);

        let ek = XWingKem::encapsulation_key_from_bytes(&ek_bytes).unwrap();
        let mut rng = FixedRng::from_hex(eseed_hex);
        let (ct, ss_enc) = XWingKem::encapsulate(&ek, &mut rng);
        assert_eq!(ct, expected_ct);
        assert_eq!(ss_enc, expected_ss);

        let ss_dec = XWingKem::decapsulate(&dk, &ct).unwrap();
        assert_eq!(ss_dec, expected_ss);
    }
}
