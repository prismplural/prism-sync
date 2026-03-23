use uuid::Uuid;

/// Generate a 12-character hex node ID from UUID v4.
///
/// Takes the first 6 bytes of a UUID v4 and hex-encodes them,
/// producing a 12-character lowercase hex string.
///
/// This matches the Dart implementation's node ID format.
pub fn generate_node_id() -> String {
    let uuid = Uuid::new_v4();
    let bytes = uuid.as_bytes();
    // Take first 6 bytes -> 12 hex chars
    hex::encode(&bytes[..6])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn generates_12_char_hex_string() {
        let id = generate_node_id();
        assert_eq!(id.len(), 12);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn generates_lowercase_hex() {
        let id = generate_node_id();
        assert_eq!(id, id.to_lowercase());
    }

    #[test]
    fn generates_unique_ids() {
        let ids: HashSet<String> = (0..100).map(|_| generate_node_id()).collect();
        assert_eq!(ids.len(), 100);
    }
}
