import 'types.dart';

/// Dart client stub for the prism-sync encrypted CRDT sync engine.
///
/// The real integration uses flutter_rust_bridge-generated bindings in
/// `prism_sync/lib/generated/`. This stub exists for the package's public API
/// surface and is not used at runtime.
class PrismSyncClient {

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
