use bip39::{Language, Mnemonic};

use crate::error::{CryptoError, Result};

/// Generate a new 12-word BIP39 mnemonic (128-bit entropy).
pub fn generate() -> String {
    let mnemonic = Mnemonic::generate_in(Language::English, 12)
        .expect("12-word mnemonic generation should never fail");
    mnemonic.to_string()
}

/// Convert a BIP39 mnemonic to its 16-byte entropy.
pub fn to_bytes(mnemonic_str: &str) -> Result<Vec<u8>> {
    let mnemonic = Mnemonic::parse_in(Language::English, mnemonic_str)
        .map_err(|e| CryptoError::InvalidMnemonic(e.to_string()))?;
    Ok(mnemonic.to_entropy())
}

/// Convert 16-byte entropy back to a BIP39 mnemonic.
pub fn from_bytes(bytes: &[u8]) -> Result<String> {
    if bytes.len() != 16 {
        return Err(CryptoError::InvalidMnemonic(format!(
            "expected 16 bytes of entropy, got {}",
            bytes.len()
        )));
    }
    let mnemonic =
        Mnemonic::from_entropy(bytes).map_err(|e| CryptoError::InvalidMnemonic(e.to_string()))?;
    Ok(mnemonic.to_string())
}

/// Validate that a string is a valid BIP39 mnemonic.
pub fn is_valid(mnemonic_str: &str) -> bool {
    Mnemonic::parse_in(Language::English, mnemonic_str).is_ok()
}

/// Generate human-readable backup text containing the mnemonic.
pub fn backup_text(mnemonic_str: &str, generated_at: &str) -> String {
    format!(
        "PRISM SYNC SECRET KEY BACKUP\n\
         Generated: {generated_at}\n\
         \n\
         Your secret key (12 words):\n\
         {mnemonic_str}\n\
         \n\
         IMPORTANT:\n\
         - Store this in a safe place\n\
         - Anyone with these words can access your data\n\
         - You will need this key + your password to recover your data"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_12_words() {
        let mnemonic = generate();
        assert_eq!(mnemonic.split_whitespace().count(), 12);
    }

    #[test]
    fn to_bytes_returns_16_bytes() {
        let mnemonic = generate();
        let bytes = to_bytes(&mnemonic).unwrap();
        assert_eq!(bytes.len(), 16);
    }

    #[test]
    fn roundtrip_mnemonic_bytes() {
        let mnemonic = generate();
        let bytes = to_bytes(&mnemonic).unwrap();
        let recovered = from_bytes(&bytes).unwrap();
        assert_eq!(mnemonic, recovered);
    }

    #[test]
    fn different_mnemonics_each_time() {
        let a = generate();
        let b = generate();
        assert_ne!(a, b);
    }

    #[test]
    fn valid_mnemonic_passes() {
        let mnemonic = generate();
        assert!(is_valid(&mnemonic));
    }

    #[test]
    fn invalid_mnemonic_fails() {
        assert!(!is_valid("not a valid mnemonic phrase at all nope"));
    }

    #[test]
    fn to_bytes_invalid_returns_error() {
        assert!(to_bytes("invalid words here").is_err());
    }
}
