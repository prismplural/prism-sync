#![no_main]
use libfuzzer_sys::fuzz_target;

use prism_sync_crypto::DeviceSigningKey;

fuzz_target!(|data: &[u8]| {
    // Feed arbitrary bytes as (public_key || signature || message).
    // The goal is to verify that Ed25519 verification never panics on
    // malformed input — it should always return Err for garbage data.

    if data.len() < 96 {
        // Need at least 32 (pubkey) + 64 (signature) = 96 bytes
        return;
    }

    let (pubkey_bytes, rest) = data.split_at(32);
    let (sig_bytes, message) = rest.split_at(64);

    let pubkey: [u8; 32] = pubkey_bytes.try_into().unwrap();
    let _ = DeviceSigningKey::verify(&pubkey, message, sig_bytes);
});
