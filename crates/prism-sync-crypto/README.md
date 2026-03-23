# prism-sync-crypto

Standalone cryptographic primitives for prism-sync. This crate has zero sync awareness -- it provides pure cryptographic building blocks that the sync engine (`prism-sync-core`) composes into a complete system.

## Modules

| Module | Purpose |
|--------|---------|
| `aead` | XChaCha20-Poly1305 (sync data) + XSalsa20-Poly1305 (DEK wrapping) |
| `kdf` | Argon2id (password -> MEK) + HKDF-SHA256 (subkey derivation) |
| `key_hierarchy` | Full key lifecycle: initialize, unlock, lock, change password, epoch keys |
| `device_identity` | Per-device Ed25519 (signing) + X25519 (key exchange) from CSPRNG |
| `mnemonic` | BIP39 12-word mnemonic generation, validation, byte conversion |
| `hex` | Hex encoding/decoding utilities |
| `error` | `CryptoError` type with variants for each failure mode |

## Key Hierarchy

```
Password + SecretKey (BIP39 mnemonic bytes)
    |
    v
Argon2id (64 MiB, 3 iterations, parallelism=1, 16-byte random salt)
    |
    v
MEK (Master Encryption Key, 32 bytes)
    |
    |── wraps ──> DEK (Data Encryption Key, 32 bytes, random CSPRNG)
    |              via XSalsa20-Poly1305 (secretbox)
    |              wire format: nonce (24 bytes) || ciphertext+MAC
    |
    v
DEK derives subkeys via HKDF-SHA256:
    |
    |── HKDF(ikm=DEK, salt=epoch.to_be_bytes(), info="epoch_sync\0")
    |       └── Epoch 0 sync key (32 bytes)
    |
    |── HKDF(ikm=DEK, salt=[], info="prism_database_key")
    |       └── Database encryption key (32 bytes)
    |
    |── HKDF(ikm=DEK, salt=[], info="prism_group_invite")
            └── Group invitation secret (32 bytes)
```

### Password change

Changing the password only re-wraps the DEK under a new MEK. The DEK itself does not change, so no data re-encryption is needed. `KeyHierarchy::change_password()` returns a new `(wrapped_dek, salt)` pair to persist.

### Epoch keys

- Epoch 0 is deterministically derived from the DEK via HKDF.
- Higher epochs (1, 2, ...) are generated via X25519 DH during epoch rotation (handled by `prism-sync-core`) and stored via `KeyHierarchy::store_epoch_key()`.
- `KeyHierarchy::epoch_key(n)` retrieves any cached epoch key.
- `export_epoch_keys()` / `import_epoch_keys()` support persistence of runtime key state.

## Device Identity

Per-device keys are generated from a `DeviceSecret` (32 bytes from CSPRNG), **never derived from the shared DEK**. This ensures one device's compromise does not expose another device's keys.

```rust
let device_secret = DeviceSecret::generate();  // 32 random bytes

// Ed25519 signing key (for batch signatures, registration, SAS)
let signing = device_secret.ed25519_keypair("device_abc")?;
signing.sign(message);
DeviceSigningKey::verify(&pubkey, message, &signature)?;

// X25519 key exchange (for pairing, epoch key wrapping)
let exchange = device_secret.x25519_keypair("device_abc")?;
let shared_secret = exchange.diffie_hellman(&peer_public_key);
```

Both keypairs are derived deterministically from `HKDF(ikm=device_secret, salt=device_id, info=purpose)`, so they are stable across app restarts as long as the device secret is persisted.

## AEAD Primitives

### XChaCha20-Poly1305 (sync data encryption)

```rust
use prism_sync_crypto::aead;

// Basic encrypt/decrypt (nonce || ciphertext+MAC)
let blob = aead::xchacha_encrypt(&key, b"plaintext")?;
let plaintext = aead::xchacha_decrypt(&key, &blob)?;

// With Additional Authenticated Data
let blob = aead::xchacha_encrypt_aead(&key, b"plaintext", b"aad")?;
let plaintext = aead::xchacha_decrypt_aead(&key, &blob, b"aad")?;

// Sync-specific: returns (ciphertext+MAC, nonce) separately
let (ct, nonce) = aead::xchacha_encrypt_for_sync(&key, b"ops", b"aad")?;
let plaintext = aead::xchacha_decrypt_from_sync(&key, &ct, &nonce, b"aad")?;
```

- 24-byte random nonce (generated per encryption)
- Wire format: `nonce (24 bytes) || ciphertext || MAC (16 bytes)`
- Total overhead: 40 bytes per encryption

### XSalsa20-Poly1305 (DEK wrapping)

```rust
// Wrap DEK under MEK
let wrapped = aead::secretbox_wrap(&mek, &dek)?;
let dek = aead::secretbox_unwrap(&mek, &wrapped)?;
```

- Used exclusively for wrapping the DEK under the MEK
- Same wire format: `nonce (24 bytes) || ciphertext || MAC (16 bytes)`

## Zeroize Guarantees

All sensitive key material uses `Zeroizing<Vec<u8>>` from the `zeroize` crate:

- MEK is `Zeroizing` and auto-cleaned after use in `derive_mek()`
- DEK is stored as `Zeroizing<Vec<u8>>` in `KeyHierarchy`
- All epoch keys are `Zeroizing<Vec<u8>>`
- HKDF subkey outputs are `Zeroizing<Vec<u8>>`
- `DeviceSecret` derives `ZeroizeOnDrop`
- `KeyHierarchy::lock()` explicitly zeros DEK and clears all epoch keys
- `KeyHierarchy::drop()` auto-zeros everything

## Cross-Language Compatibility

Crypto operations are verified against the Dart/libsodium implementation:

- Argon2id parameters match exactly (64 MiB, 3 iterations, parallelism=1)
- HKDF-SHA256 uses `None` salt for empty salt (matches PointyCastle behavior)
- XSalsa20-Poly1305 wire format is identical to libsodium secretbox
- Cross-language test vectors can be run with:
  ```bash
  cargo test -p prism-sync-crypto --test cross_language_vectors -- --ignored
  ```

## Example: Full Key Lifecycle

```rust
use prism_sync_crypto::KeyHierarchy;

// First-time setup
let mut kh = KeyHierarchy::new();
let (wrapped_dek, salt) = kh.initialize("password", &secret_key_bytes)?;
// Persist wrapped_dek and salt to secure storage

// Use derived keys while unlocked
let epoch_key = kh.epoch_key(0)?;           // 32 bytes
let db_key = kh.database_key()?;            // 32 bytes (Zeroizing)
let invite = kh.group_invite_secret()?;     // 32 bytes (Zeroizing)

// Lock (zeros all key material)
kh.lock();
assert!(!kh.is_unlocked());

// Subsequent unlock
kh.unlock("password", &secret_key_bytes, &wrapped_dek, &salt)?;
assert!(kh.is_unlocked());

// Change password (re-wraps DEK, no data re-encryption)
let (new_wrapped, new_salt) = kh.change_password("new_password", &secret_key_bytes)?;
```
