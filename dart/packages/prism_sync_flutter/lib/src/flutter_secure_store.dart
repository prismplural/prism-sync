import 'dart:typed_data';

/// Abstract interface for secure key/value storage.
///
/// Concrete implementation in the app uses `flutter_secure_storage` to bridge
/// platform-native secure storage (Keychain on iOS/macOS,
/// EncryptedSharedPreferences on Android) to the Rust `SecureStore` trait
/// via the FFI layer.
abstract class SecureStore {
  /// Read a value by key. Returns null if the key does not exist.
  Future<Uint8List?> get(String key);

  /// Write a value for the given key, overwriting any existing value.
  Future<void> set(String key, Uint8List value);

  /// Delete a value by key. No-op if the key does not exist.
  Future<void> delete(String key);

  /// Delete all stored values.
  Future<void> clear();
}
