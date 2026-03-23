import 'types.dart';

/// Dart client for the prism-sync encrypted CRDT sync engine.
///
/// Placeholder implementation — will be backed by flutter_rust_bridge
/// bindings that call into the Rust `prism-sync-ffi` crate.
class PrismSyncClient {
  // TODO: Wire to Rust FFI via flutter_rust_bridge

  /// Initialize the sync engine for first-time setup.
  ///
  /// Derives the master encryption key from [password] and [secretKey],
  /// generates the DEK, and stores wrapped keys in secure storage.
  Future<void> initialize(String password, List<int> secretKey) async {
    throw UnimplementedError('Requires flutter_rust_bridge codegen');
  }

  /// Unlock the sync engine on subsequent launches.
  ///
  /// Derives the master encryption key and unwraps the stored DEK.
  Future<void> unlock(String password, List<int> secretKey) async {
    throw UnimplementedError('Requires flutter_rust_bridge codegen');
  }

  /// Lock the sync engine, clearing all runtime keys from memory.
  void lock() {
    throw UnimplementedError('Requires flutter_rust_bridge codegen');
  }

  /// Whether the sync engine is currently unlocked and operational.
  bool get isUnlocked =>
      throw UnimplementedError('Requires flutter_rust_bridge codegen');

  /// Trigger a sync cycle (push pending ops, pull remote changes).
  Future<SyncResult> sync() async {
    throw UnimplementedError('Requires flutter_rust_bridge codegen');
  }

  /// Record a local mutation to be synced.
  void recordMutation({
    required String table,
    required String entityId,
    required String mutationType,
    Map<String, dynamic>? fields,
  }) {
    throw UnimplementedError('Requires flutter_rust_bridge codegen');
  }

  /// Stream of sync events (started, completed, errors, remote changes).
  Stream<SyncEvent> get events =>
      throw UnimplementedError('Requires flutter_rust_bridge codegen');

  /// Current sync status.
  SyncStatus status() {
    throw UnimplementedError('Requires flutter_rust_bridge codegen');
  }

  /// Generate a new BIP39 secret key.
  static String generateSecretKey() {
    throw UnimplementedError('Requires flutter_rust_bridge codegen');
  }
}
