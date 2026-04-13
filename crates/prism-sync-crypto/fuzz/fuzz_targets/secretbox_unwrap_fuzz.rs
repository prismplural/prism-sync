#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Feed arbitrary bytes as wrapped DEK material.
    // secretbox_unwrap expects nonce(24) + ciphertext+MAC(>=16) = 40 bytes minimum.
    // Should always return Err for garbage data, never panic.

    if data.len() < 32 {
        // Split data into key material and wrapped blob
        return;
    }

    let (key_bytes, wrapped) = data.split_at(32);
    let _ = prism_sync_crypto::aead::secretbox_unwrap(key_bytes, wrapped);

    // Also try with a fixed key and the full data as wrapped blob
    let fixed_key = [0xABu8; 32];
    let _ = prism_sync_crypto::aead::secretbox_unwrap(&fixed_key, data);
});
