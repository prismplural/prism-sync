use std::collections::HashMap;

use crate::error::Result;

/// Secure storage for keys and credentials — platform-specific.
/// Implemented by prism_sync_flutter (iOS Keychain / Android Keystore).
pub trait SecureStore: Send + Sync {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;
    fn set(&self, key: &str, value: &[u8]) -> Result<()>;
    fn delete(&self, key: &str) -> Result<()>;
    fn clear(&self) -> Result<()>;

    /// Return all stored entries as a snapshot, or `None` if enumeration is
    /// not supported (e.g. the platform keychain).
    ///
    /// This is an opt-in extension used by `drain_secure_store` to export
    /// dynamic keys (such as `epoch_key_*` or `runtime_keys_*`) that are
    /// not in the static allow-list. The default impl returns `Ok(None)` so
    /// existing platform-keychain-backed implementations don't have to
    /// implement enumeration; the drain code falls back to the explicit
    /// allow-list path when enumeration is unavailable.
    ///
    /// **Production invariant:** any `SecureStore` impl used by the FFI
    /// runtime (currently `MemorySecureStore` in `prism-sync-ffi/src/api.rs`)
    /// MUST override this method to return `Some(...)`. The default
    /// `Ok(None)` causes `drain_secure_store` to fall back to a hardcoded
    /// allow-list that does NOT cover all dynamic key families
    /// (`epoch_key_*`, `runtime_keys_*`). If you introduce a new production
    /// impl without overriding `snapshot()`, epoch-key persistence across
    /// app restarts will silently break — this is the specific bug that
    /// `docs/plans/sync-robustness-and-epoch-persistence.md` was written
    /// to fix.
    ///
    /// The default exists only for object-safety and for hypothetical
    /// keychain-backed impls that genuinely cannot enumerate (iOS Keychain,
    /// Android Keystore). No such impl exists in the Rust crate today; all
    /// platform keychain work lives on the Dart side and crosses FFI as
    /// seed/drain calls.
    fn snapshot(&self) -> Result<Option<HashMap<String, Vec<u8>>>> {
        Ok(None)
    }
}
