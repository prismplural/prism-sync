use crate::error::{CryptoError, Result};

/// Encode bytes to lowercase hex string.
pub fn encode(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Decode hex string to bytes.
pub fn decode(hex_str: &str) -> Result<Vec<u8>> {
    hex::decode(hex_str).map_err(|e| CryptoError::HexDecode(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_empty() {
        assert_eq!(encode(&[]), "");
    }

    #[test]
    fn encode_bytes() {
        assert_eq!(encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    #[test]
    fn decode_valid_hex() {
        assert_eq!(decode("deadbeef").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn decode_empty() {
        assert_eq!(decode("").unwrap(), vec![]);
    }

    #[test]
    fn decode_invalid_hex() {
        assert!(decode("not_hex!").is_err());
    }

    #[test]
    fn roundtrip() {
        let bytes = vec![1, 2, 3, 255, 0, 128];
        assert_eq!(decode(&encode(&bytes)).unwrap(), bytes);
    }
}
