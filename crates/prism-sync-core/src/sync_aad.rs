/// Build the Additional Authenticated Data (AAD) string for sync encryption.
///
/// Format: `prism_sync|{sync_id}|{device_id}|{epoch}|{batch_id}|{batch_kind}`
///
/// This prevents cross-sync-group replay attacks and ensures batch integrity.
/// The AAD is fed to XChaCha20-Poly1305 during encryption and must match
/// exactly during decryption.
pub fn build_sync_aad(
    sync_id: &str,
    device_id: &str,
    epoch: i32,
    batch_id: &str,
    batch_kind: &str,
) -> Vec<u8> {
    format!("prism_sync|{sync_id}|{device_id}|{epoch}|{batch_id}|{batch_kind}").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aad_format() {
        let aad = build_sync_aad("sync-123", "device-abc", 0, "batch-456", "ops");
        let aad_str = String::from_utf8(aad).unwrap();
        assert_eq!(aad_str, "prism_sync|sync-123|device-abc|0|batch-456|ops");
    }

    #[test]
    fn aad_snapshot_kind() {
        let aad = build_sync_aad("s1", "d1", 2, "b1", "snapshot");
        let aad_str = String::from_utf8(aad).unwrap();
        assert_eq!(aad_str, "prism_sync|s1|d1|2|b1|snapshot");
    }

    #[test]
    fn different_sync_ids_produce_different_aads() {
        let aad1 = build_sync_aad("sync-a", "d1", 0, "b1", "ops");
        let aad2 = build_sync_aad("sync-b", "d1", 0, "b1", "ops");
        assert_ne!(aad1, aad2);
    }

    #[test]
    fn different_epochs_produce_different_aads() {
        let aad1 = build_sync_aad("s1", "d1", 0, "b1", "ops");
        let aad2 = build_sync_aad("s1", "d1", 1, "b1", "ops");
        assert_ne!(aad1, aad2);
    }

    #[test]
    fn different_devices_produce_different_aads() {
        let aad1 = build_sync_aad("s1", "device-a", 0, "b1", "ops");
        let aad2 = build_sync_aad("s1", "device-b", 0, "b1", "ops");
        assert_ne!(aad1, aad2);
    }
}
