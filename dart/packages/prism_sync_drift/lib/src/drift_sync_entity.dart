import 'dart:async';

/// Configuration for syncing a single Drift table.
///
/// Each instance maps a Drift table to the callbacks prism-sync needs
/// for reading, writing, and deleting entity data during sync operations.
class DriftSyncEntity {
  /// The name of the Drift table (must match the sync schema).
  final String tableName;

  /// Convert a Drift row into a map of sync field names to values.
  final Map<String, dynamic> Function(dynamic row) toSyncFields;

  /// Apply remote field changes to a local row (upsert).
  final Future<void> Function(String id, Map<String, dynamic> fields)
      applyFields;

  /// Permanently remove a row (after remote tombstone deletion).
  final Future<void> Function(String id) hardDelete;

  /// Read a single row by ID, returning its sync fields or null if missing.
  final Future<Map<String, dynamic>?> Function(String id) readRow;

  /// Check whether a row is soft-deleted (isDeleted flag).
  final Future<bool> Function(String id) isDeleted;

  DriftSyncEntity({
    required this.tableName,
    required this.toSyncFields,
    required this.applyFields,
    required this.hardDelete,
    required this.readRow,
    required this.isDeleted,
  });
}
