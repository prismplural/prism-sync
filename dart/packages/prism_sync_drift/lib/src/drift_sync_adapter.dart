import 'drift_sync_entity.dart';

/// Adapter that bridges Drift tables to prism-sync's SyncableEntity.
///
/// Each [DriftSyncEntity] describes how to read/write a single Drift table
/// for sync purposes. The adapter coordinates applying remote changes and
/// reading local state for push operations.
class DriftSyncAdapter {
  /// The registered syncable entities (one per Drift table).
  final List<DriftSyncEntity> entities;

  DriftSyncAdapter({required this.entities});

  /// Look up the entity configuration for a given table name.
  DriftSyncEntity? entityForTable(String tableName) {
    for (final entity in entities) {
      if (entity.tableName == tableName) return entity;
    }
    return null;
  }

  /// Apply a set of field changes from a remote sync operation.
  ///
  /// Delegates to the appropriate [DriftSyncEntity] based on [table].
  Future<void> applyFields(
    String table,
    String entityId,
    Map<String, dynamic> fields,
  ) async {
    final entity = entityForTable(table);
    if (entity == null) {
      throw ArgumentError('No sync entity registered for table: $table');
    }
    await entity.applyFields(entityId, fields);
  }

  /// Hard-delete an entity that was tombstone-deleted remotely.
  Future<void> hardDelete(String table, String entityId) async {
    final entity = entityForTable(table);
    if (entity == null) {
      throw ArgumentError('No sync entity registered for table: $table');
    }
    await entity.hardDelete(entityId);
  }
}
