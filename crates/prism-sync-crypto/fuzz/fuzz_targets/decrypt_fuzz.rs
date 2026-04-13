#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Feed arbitrary bytes as ciphertext with a fixed test key.
    // The goal is to verify xchacha_decrypt never panics on malformed input.
    // It should always return Err for garbage data, never panic or UB.

    // xchacha_decrypt expects nonce(24) + ciphertext(>=16), so minimum 40 bytes.
    // With shorter input it should return Err cleanly.
    let key = [0x42u8; 32];
    let _ = prism_sync_crypto::aead::xchacha_decrypt(&key, data);

    // Also fuzz xchacha_decrypt_aead with garbage AAD
    let _ = prism_sync_crypto::aead::xchacha_decrypt_aead(&key, data, b"fuzz-aad");

    // Also fuzz secretbox_unwrap
    let _ = prism_sync_crypto::aead::secretbox_unwrap(&key, data);
});
