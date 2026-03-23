use prism_sync_crypto::{aead, hex, mnemonic, DeviceSecret, DeviceSigningKey, KeyHierarchy};

#[test]
fn full_key_lifecycle() {
    // 1. Generate secret key (BIP39)
    let mnemonic_str = mnemonic::generate();
    assert_eq!(mnemonic_str.split_whitespace().count(), 12);
    let secret_key = mnemonic::to_bytes(&mnemonic_str).unwrap();
    assert_eq!(secret_key.len(), 16);

    // 2. Initialize key hierarchy
    let mut kh = KeyHierarchy::new();
    let (wrapped_dek, salt) = kh.initialize("my_password", &secret_key).unwrap();
    assert!(kh.is_unlocked());

    // 3. Derive keys
    let epoch0_key = kh.epoch_key(0).unwrap().to_vec();
    let db_key = kh.database_key().unwrap();
    let invite_secret = kh.group_invite_secret().unwrap();
    assert_eq!(epoch0_key.len(), 32);
    assert_eq!(db_key.len(), 32);
    assert_eq!(invite_secret.len(), 32);

    // 4. Encrypt some data with the epoch 0 key
    let plaintext = b"sensitive sync data";
    let aad = b"prism_sync|test_sync|device_1|0|batch_1|ops";
    let encrypted = aead::xchacha_encrypt_aead(&epoch0_key, plaintext, aad).unwrap();

    // 5. Decrypt it back
    let decrypted = aead::xchacha_decrypt_aead(&epoch0_key, &encrypted, aad).unwrap();
    assert_eq!(decrypted, plaintext);

    // 6. Lock and verify we can't access keys
    kh.lock();
    assert!(!kh.is_unlocked());
    assert!(kh.epoch_key(0).is_err());

    // 7. Unlock again and verify same keys
    kh.unlock("my_password", &secret_key, &wrapped_dek, &salt)
        .unwrap();
    assert_eq!(kh.epoch_key(0).unwrap(), &epoch0_key);
    assert_eq!(*kh.database_key().unwrap(), *db_key);

    // 8. Change password and verify same keys
    let (new_wrapped, new_salt) = kh.change_password("new_password", &secret_key).unwrap();
    kh.lock();
    kh.unlock("new_password", &secret_key, &new_wrapped, &new_salt)
        .unwrap();
    assert_eq!(kh.epoch_key(0).unwrap(), &epoch0_key);

    // 9. Data encrypted before password change is still decryptable
    let decrypted2 = aead::xchacha_decrypt_aead(&epoch0_key, &encrypted, aad).unwrap();
    assert_eq!(decrypted2, plaintext);
}

#[test]
fn device_identity_independent_of_dek() {
    let device_secret = DeviceSecret::generate();
    let signing_key = device_secret.ed25519_keypair("device_123").unwrap();
    let _exchange_key = device_secret.x25519_keypair("device_123").unwrap();

    // Sign and verify
    let message = b"registration challenge data";
    let signature = signing_key.sign(message);
    DeviceSigningKey::verify(&signing_key.public_key_bytes(), message, &signature).unwrap();

    // Device keys differ from DEK-derived keys
    let mut kh = KeyHierarchy::new();
    let secret_key = mnemonic::to_bytes(&mnemonic::generate()).unwrap();
    kh.initialize("password", &secret_key).unwrap();
    assert_ne!(
        signing_key.public_key_bytes().to_vec(),
        kh.epoch_key(0).unwrap()
    );
}

#[test]
fn hex_roundtrip_with_keys() {
    let mut kh = KeyHierarchy::new();
    let secret_key = vec![1u8; 16];
    kh.initialize("password", &secret_key).unwrap();
    let epoch0 = kh.epoch_key(0).unwrap();
    let hex_str = hex::encode(epoch0);
    let decoded = hex::decode(&hex_str).unwrap();
    assert_eq!(decoded, epoch0);
}
