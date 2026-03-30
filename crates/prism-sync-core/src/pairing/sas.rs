//! SAS (Short Authentication String) verification protocol.
//!
//! Provides transcript-bound verification codes so that two devices pairing
//! over an untrusted channel can confirm they are talking to each other (and
//! not to a MITM). Both sides compute a deterministic hash over all public
//! pairing parameters, then display a human-readable code derived from that
//! hash. If the codes match, both sides sign the transcript and exchange
//! signatures for cryptographic confirmation.

use sha2::{Digest, Sha256};

use prism_sync_crypto::DeviceSigningKey;

use crate::error::{CoreError, Result};

// ── Word list (256 words, one per byte value) ──────────────────────────────

/// A compact 256-word list used to render SAS display codes.
/// Each byte of the transcript hash indexes into this list, giving
/// 3 words from the first 3 bytes (24 bits of entropy — ~16 million
/// combinations, well above the ~65 k needed for pairing safety).
const SAS_WORDS: [&str; 256] = [
    "acorn",
    "alpine",
    "amber",
    "anchor",
    "apple",
    "arctic",
    "arrow",
    "atlas",
    "aurora",
    "badge",
    "bamboo",
    "barrel",
    "beacon",
    "birch",
    "bloom",
    "bolt",
    "branch",
    "brave",
    "breeze",
    "bridge",
    "bronze",
    "brook",
    "brush",
    "cabin",
    "candle",
    "canyon",
    "castle",
    "cedar",
    "chain",
    "chalk",
    "cherry",
    "cliff",
    "cloud",
    "cobalt",
    "comet",
    "copper",
    "coral",
    "crane",
    "creek",
    "crest",
    "crown",
    "crystal",
    "cypress",
    "dagger",
    "dawn",
    "delta",
    "desert",
    "dew",
    "dock",
    "dolphin",
    "dove",
    "dragon",
    "drift",
    "dusk",
    "eagle",
    "earth",
    "echo",
    "elm",
    "ember",
    "falcon",
    "fern",
    "field",
    "flame",
    "flint",
    "flood",
    "flora",
    "forge",
    "fossil",
    "frost",
    "galaxy",
    "garden",
    "garnet",
    "gate",
    "glacier",
    "glen",
    "globe",
    "gorge",
    "grain",
    "grape",
    "grove",
    "harbor",
    "hawk",
    "hazel",
    "heath",
    "heron",
    "holly",
    "honey",
    "horn",
    "hyacinth",
    "ice",
    "indigo",
    "iris",
    "iron",
    "island",
    "ivory",
    "ivy",
    "jade",
    "jasper",
    "jewel",
    "juniper",
    "kale",
    "kelp",
    "kernel",
    "kettle",
    "kindle",
    "knoll",
    "lake",
    "larch",
    "lark",
    "laurel",
    "lava",
    "leaf",
    "lemon",
    "light",
    "lily",
    "linden",
    "lotus",
    "lunar",
    "maple",
    "marble",
    "marsh",
    "meadow",
    "mesa",
    "mint",
    "mist",
    "moon",
    "moss",
    "nectar",
    "nest",
    "noble",
    "north",
    "nova",
    "nutmeg",
    "oak",
    "oasis",
    "ocean",
    "olive",
    "onyx",
    "opal",
    "orbit",
    "orchid",
    "osprey",
    "otter",
    "palm",
    "pearl",
    "pebble",
    "pepper",
    "peridot",
    "petal",
    "phoenix",
    "pine",
    "plum",
    "pond",
    "prism",
    "pulse",
    "quartz",
    "rain",
    "raven",
    "reef",
    "ridge",
    "river",
    "robin",
    "rock",
    "rose",
    "ruby",
    "sage",
    "sand",
    "sapphire",
    "seed",
    "shadow",
    "shell",
    "shore",
    "silk",
    "silver",
    "slate",
    "snow",
    "spark",
    "spruce",
    "star",
    "steel",
    "stone",
    "storm",
    "stream",
    "summit",
    "sun",
    "swan",
    "thorn",
    "thunder",
    "tide",
    "tiger",
    "timber",
    "topaz",
    "torch",
    "trail",
    "tulip",
    "tundra",
    "turquoise",
    "valley",
    "velvet",
    "vine",
    "violet",
    "walnut",
    "wave",
    "wheat",
    "willow",
    "wind",
    "wolf",
    "wren",
    "yarrow",
    "yew",
    "zeal",
    "zenith",
    "zinc",
    "acacia",
    "agate",
    "almond",
    "aspen",
    "basalt",
    "bay",
    "birdsong",
    "blaze",
    "blossom",
    "cairn",
    "cinder",
    "clover",
    "cobble",
    "condor",
    "crimson",
    "dahlia",
    "dune",
    "egret",
    "ember",
    "fennel",
    "fig",
    "garland",
    "ginger",
    "granite",
    "hawthorn",
    "hemlock",
    "hive",
    "horizon",
    "icicle",
    "jasmine",
    "kestrel",
    "lantern",
    "lavender",
    "lichen",
    "loom",
    "magnolia",
    "marigold",
    "myrtle",
    "nettle",
    "nimbus",
    "obsidian",
    "oregano",
    "pecan",
];

/// Prefix for the SAS transcript binary format.
const SAS_PREFIX: &[u8] = b"PRISM_SYNC_SAS_V1";

/// Build the SAS transcript hash from all pairing parameters.
///
/// The hash is computed over a deterministic binary encoding:
/// ```text
/// "PRISM_SYNC_SAS_V1" || 0x00
/// || len_prefixed(sync_id)
/// || len_prefixed(initiator_device_id)
/// || len_prefixed(responder_device_id)
/// || initiator_ed25519_pk (32 bytes, raw)
/// || responder_ed25519_pk (32 bytes, raw)
/// || initiator_x25519_pk  (32 bytes, raw)
/// || responder_x25519_pk  (32 bytes, raw)
/// || invitation_nonce      (variable, raw)
/// || len_prefixed(relay_origin)
/// || protocol_version      (2 bytes, big-endian u16)
/// ```
///
/// `len_prefixed` means `u32-be(len) || bytes`.
#[allow(clippy::too_many_arguments)]
pub fn compute_sas_transcript(
    sync_id: &str,
    initiator_device_id: &str,
    responder_device_id: &str,
    initiator_ed25519_pk: &[u8; 32],
    responder_ed25519_pk: &[u8; 32],
    initiator_x25519_pk: &[u8; 32],
    responder_x25519_pk: &[u8; 32],
    invitation_nonce: &[u8],
    relay_origin: &str,
    protocol_version: u16,
) -> [u8; 32] {
    let mut hasher = Sha256::new();

    // Domain separator
    hasher.update(SAS_PREFIX);
    hasher.update(b"\x00");

    // Length-prefixed string fields
    write_len_prefixed(&mut hasher, sync_id.as_bytes());
    write_len_prefixed(&mut hasher, initiator_device_id.as_bytes());
    write_len_prefixed(&mut hasher, responder_device_id.as_bytes());

    // Raw public keys (fixed 32-byte fields — no length prefix needed)
    hasher.update(initiator_ed25519_pk);
    hasher.update(responder_ed25519_pk);
    hasher.update(initiator_x25519_pk);
    hasher.update(responder_x25519_pk);

    // Invitation nonce (variable length, raw — not length-prefixed per spec)
    hasher.update(invitation_nonce);

    // Relay origin (length-prefixed)
    write_len_prefixed(&mut hasher, relay_origin.as_bytes());

    // Protocol version (big-endian u16)
    hasher.update(protocol_version.to_be_bytes());

    hasher.finalize().into()
}

/// Write a length-prefixed byte slice: `u32-be(len) || data`.
fn write_len_prefixed(hasher: &mut Sha256, data: &[u8]) {
    hasher.update((data.len() as u32).to_be_bytes());
    hasher.update(data);
}

/// Convert the first 3 bytes of a transcript hash into a human-readable
/// display code (3 words separated by dashes).
///
/// Each byte selects a word from the 256-word `SAS_WORDS` list, yielding
/// 24 bits of entropy (~16.7 million combinations).
pub fn sas_display_code(transcript_hash: &[u8; 32]) -> String {
    let words: Vec<&str> = transcript_hash[..3]
        .iter()
        .map(|b| SAS_WORDS[*b as usize])
        .collect();
    words.join("-")
}

/// SAS verification state machine.
///
/// Holds the transcript hash and both devices' Ed25519 public keys so that
/// either side can:
/// 1. Display the code (`display_code`)
/// 2. Sign the transcript to confirm (`confirm_signature`)
/// 3. Verify the other device's signature (`verify_confirmation`)
pub struct SasVerification {
    transcript_hash: [u8; 32],
    initiator_ed25519_pk: [u8; 32],
    responder_ed25519_pk: [u8; 32],
}

impl SasVerification {
    /// Create a new `SasVerification` from the computed transcript hash and
    /// both devices' Ed25519 public keys.
    pub fn new(
        transcript_hash: [u8; 32],
        initiator_ed25519_pk: [u8; 32],
        responder_ed25519_pk: [u8; 32],
    ) -> Self {
        Self {
            transcript_hash,
            initiator_ed25519_pk,
            responder_ed25519_pk,
        }
    }

    /// The human-readable SAS display code (3 dash-separated words).
    pub fn display_code(&self) -> String {
        sas_display_code(&self.transcript_hash)
    }

    /// Sign the transcript hash with this device's Ed25519 key to confirm
    /// that the displayed code was accepted.
    pub fn confirm_signature(&self, signing_key: &DeviceSigningKey) -> Vec<u8> {
        signing_key.sign(&self.transcript_hash)
    }

    /// Verify the other device's confirmation signature.
    ///
    /// `is_initiator` indicates the *signer's* role:
    /// - `true`  → the signature was produced by the **initiator**
    /// - `false` → the signature was produced by the **responder**
    pub fn verify_confirmation(&self, signature: &[u8], is_initiator: bool) -> Result<()> {
        let pk = if is_initiator {
            &self.initiator_ed25519_pk
        } else {
            &self.responder_ed25519_pk
        };
        DeviceSigningKey::verify(pk, &self.transcript_hash, signature).map_err(CoreError::Crypto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prism_sync_crypto::DeviceSecret;

    /// Fixed inputs for deterministic tests.
    #[allow(clippy::type_complexity)]
    fn test_params() -> (
        String,   // sync_id
        String,   // initiator_device_id
        String,   // responder_device_id
        [u8; 32], // initiator_ed25519_pk
        [u8; 32], // responder_ed25519_pk
        [u8; 32], // initiator_x25519_pk
        [u8; 32], // responder_x25519_pk
        Vec<u8>,  // invitation_nonce
        String,   // relay_origin
        u16,      // protocol_version
    ) {
        (
            "sync-abc-123".into(),
            "device-initiator".into(),
            "device-responder".into(),
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
            [4u8; 32],
            vec![0xDE, 0xAD, 0xBE, 0xEF],
            "wss://relay.example.com".into(),
            1u16,
        )
    }

    #[test]
    fn transcript_is_deterministic() {
        let (sid, idev, rdev, ied, red, ix, rx, nonce, relay, ver) = test_params();
        let h1 = compute_sas_transcript(
            &sid, &idev, &rdev, &ied, &red, &ix, &rx, &nonce, &relay, ver,
        );
        let h2 = compute_sas_transcript(
            &sid, &idev, &rdev, &ied, &red, &ix, &rx, &nonce, &relay, ver,
        );
        assert_eq!(h1, h2);
    }

    #[test]
    fn transcript_changes_with_different_input() {
        let (sid, idev, rdev, ied, red, ix, rx, nonce, relay, ver) = test_params();
        let h1 = compute_sas_transcript(
            &sid, &idev, &rdev, &ied, &red, &ix, &rx, &nonce, &relay, ver,
        );
        // Change sync_id
        let h2 = compute_sas_transcript(
            "different-sync",
            &idev,
            &rdev,
            &ied,
            &red,
            &ix,
            &rx,
            &nonce,
            &relay,
            ver,
        );
        assert_ne!(h1, h2);

        // Change protocol version
        let h3 =
            compute_sas_transcript(&sid, &idev, &rdev, &ied, &red, &ix, &rx, &nonce, &relay, 2);
        assert_ne!(h1, h3);
    }

    #[test]
    fn display_code_has_three_words() {
        let (sid, idev, rdev, ied, red, ix, rx, nonce, relay, ver) = test_params();
        let hash = compute_sas_transcript(
            &sid, &idev, &rdev, &ied, &red, &ix, &rx, &nonce, &relay, ver,
        );
        let code = sas_display_code(&hash);
        let words: Vec<&str> = code.split('-').collect();
        assert_eq!(words.len(), 3, "display code should be 3 words: {code}");
        // Each word should be from the word list
        for word in &words {
            assert!(
                SAS_WORDS.contains(word),
                "word '{word}' not in SAS_WORDS list"
            );
        }
    }

    #[test]
    fn display_code_is_deterministic() {
        let (sid, idev, rdev, ied, red, ix, rx, nonce, relay, ver) = test_params();
        let hash = compute_sas_transcript(
            &sid, &idev, &rdev, &ied, &red, &ix, &rx, &nonce, &relay, ver,
        );
        let code1 = sas_display_code(&hash);
        let code2 = sas_display_code(&hash);
        assert_eq!(code1, code2);
    }

    #[test]
    fn confirm_and_verify_roundtrip() {
        let secret_init = DeviceSecret::from_bytes(vec![10u8; 32]).unwrap();
        let secret_resp = DeviceSecret::from_bytes(vec![20u8; 32]).unwrap();
        let signing_init = secret_init.ed25519_keypair("initiator-dev").unwrap();
        let signing_resp = secret_resp.ed25519_keypair("responder-dev").unwrap();

        let transcript_hash = compute_sas_transcript(
            "sync-123",
            "initiator-dev",
            "responder-dev",
            &signing_init.public_key_bytes(),
            &signing_resp.public_key_bytes(),
            &[3u8; 32],
            &[4u8; 32],
            &[0xCA, 0xFE],
            "wss://relay.test",
            1,
        );

        let verification = SasVerification::new(
            transcript_hash,
            signing_init.public_key_bytes(),
            signing_resp.public_key_bytes(),
        );

        // Initiator signs and responder verifies
        let init_sig = verification.confirm_signature(&signing_init);
        verification
            .verify_confirmation(&init_sig, true)
            .expect("initiator signature should verify");

        // Responder signs and initiator verifies
        let resp_sig = verification.confirm_signature(&signing_resp);
        verification
            .verify_confirmation(&resp_sig, false)
            .expect("responder signature should verify");
    }

    #[test]
    fn verify_rejects_wrong_signature() {
        let secret_init = DeviceSecret::from_bytes(vec![10u8; 32]).unwrap();
        let secret_resp = DeviceSecret::from_bytes(vec![20u8; 32]).unwrap();
        let signing_init = secret_init.ed25519_keypair("initiator-dev").unwrap();
        let signing_resp = secret_resp.ed25519_keypair("responder-dev").unwrap();

        let transcript_hash = [42u8; 32];

        let verification = SasVerification::new(
            transcript_hash,
            signing_init.public_key_bytes(),
            signing_resp.public_key_bytes(),
        );

        // Responder signs but we claim it's the initiator's signature
        let resp_sig = verification.confirm_signature(&signing_resp);
        let result = verification.verify_confirmation(&resp_sig, true);
        assert!(result.is_err(), "should reject wrong key's signature");
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let secret = DeviceSecret::from_bytes(vec![10u8; 32]).unwrap();
        let signing = secret.ed25519_keypair("dev").unwrap();

        let verification = SasVerification::new([42u8; 32], signing.public_key_bytes(), [0u8; 32]);

        let mut sig = verification.confirm_signature(&signing);
        // Tamper with the signature
        sig[0] ^= 0xFF;
        let result = verification.verify_confirmation(&sig, true);
        assert!(result.is_err(), "should reject tampered signature");
    }

    #[test]
    fn sas_verification_display_code_matches_standalone() {
        let hash = [100u8; 32];
        let v = SasVerification::new(hash, [0u8; 32], [0u8; 32]);
        assert_eq!(v.display_code(), sas_display_code(&hash));
    }
}
