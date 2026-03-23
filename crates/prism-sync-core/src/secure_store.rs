use crate::error::Result;

/// Secure storage for keys and credentials — platform-specific.
/// Implemented by prism_sync_flutter (iOS Keychain / Android Keystore).
pub trait SecureStore: Send + Sync {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;
    fn set(&self, key: &str, value: &[u8]) -> Result<()>;
    fn delete(&self, key: &str) -> Result<()>;
    fn clear(&self) -> Result<()>;
}
