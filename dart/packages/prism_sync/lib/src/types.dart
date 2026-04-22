import 'dart:typed_data';

import 'package:meta/meta.dart';

// ---------------------------------------------------------------------------
// SyncValue — mirrors prism-sync-core's SyncValue enum
// ---------------------------------------------------------------------------

/// A value that can be synced across devices.
///
/// Each variant maps to the Rust `SyncValue` enum in prism-sync-core.
sealed class SyncValue {
  const SyncValue();

  factory SyncValue.string(String value) = SyncString;
  factory SyncValue.int_(int value) = SyncInt;
  factory SyncValue.bool_(bool value) = SyncBool;
  factory SyncValue.dateTime(DateTime value) = SyncDateTime;
  factory SyncValue.blob(Uint8List value) = SyncBlob;
  const factory SyncValue.null_() = SyncNull;
}

class SyncString extends SyncValue {
  final String value;
  const SyncString(this.value);

  @override
  String toString() => 'SyncValue.string($value)';
}

class SyncInt extends SyncValue {
  final int value;
  const SyncInt(this.value);

  @override
  String toString() => 'SyncValue.int($value)';
}

class SyncBool extends SyncValue {
  final bool value;
  const SyncBool(this.value);

  @override
  String toString() => 'SyncValue.bool($value)';
}

class SyncDateTime extends SyncValue {
  final DateTime value;
  const SyncDateTime(this.value);

  @override
  String toString() => 'SyncValue.dateTime($value)';
}

class SyncBlob extends SyncValue {
  final Uint8List value;
  const SyncBlob(this.value);

  @override
  String toString() => 'SyncValue.blob(${value.length} bytes)';
}

class SyncNull extends SyncValue {
  const SyncNull();

  @override
  String toString() => 'SyncValue.null';
}

// ---------------------------------------------------------------------------
// SyncEvent — mirrors prism-sync-core's SyncEvent enum
// ---------------------------------------------------------------------------

/// Events emitted during sync operations.
sealed class SyncEvent {
  const SyncEvent();
}

/// Sync cycle has started.
class SyncStarted extends SyncEvent {
  const SyncStarted();
}

/// Sync cycle completed successfully.
class SyncCompleted extends SyncEvent {
  final int pulled;
  final int merged;
  final int pushed;
  final Duration duration;
  const SyncCompleted({
    required this.pulled,
    required this.merged,
    required this.pushed,
    required this.duration,
  });
}

/// Snapshot download progress during first-sync bootstrap.
class SnapshotProgress extends SyncEvent {
  final int received;
  final int total;
  const SnapshotProgress({required this.received, required this.total});
}

/// An error occurred during sync.
class SyncErrorEvent extends SyncEvent {
  final SyncErrorKind kind;
  final String message;
  final bool retryable;
  const SyncErrorEvent({
    required this.kind,
    required this.message,
    required this.retryable,
  });
}

/// Remote changes were merged into local state.
class RemoteChanges extends SyncEvent {
  final ChangeSet changes;
  const RemoteChanges({required this.changes});
}

/// A new device joined the sync group.
class DeviceJoined extends SyncEvent {
  final String deviceId;
  const DeviceJoined({required this.deviceId});
}

/// A device was revoked from the sync group.
class DeviceRevoked extends SyncEvent {
  final String deviceId;
  const DeviceRevoked({required this.deviceId});
}

/// The epoch was rotated (new epoch number).
class EpochRotated extends SyncEvent {
  final int newEpoch;
  const EpochRotated({required this.newEpoch});
}

// ---------------------------------------------------------------------------
// SyncResult — summary of a completed sync cycle
// ---------------------------------------------------------------------------

/// Result of a successful sync cycle.
@immutable
class SyncResult {
  /// Number of batches pushed to the relay.
  final int pushed;

  /// Number of batches pulled from the relay.
  final int pulled;

  /// Number of ops that won the merge (were applied).
  final int merged;

  /// Duration of the sync cycle.
  final Duration duration;

  const SyncResult({
    required this.pushed,
    required this.pulled,
    this.merged = 0,
    this.duration = Duration.zero,
  });

  @override
  String toString() =>
      'SyncResult(pushed: $pushed, pulled: $pulled, merged: $merged)';
}

// ---------------------------------------------------------------------------
// SyncErrorKind
// ---------------------------------------------------------------------------

/// Categories of sync errors — mirrors Rust `SyncErrorKind`.
enum SyncErrorKind {
  /// Network connectivity issue.
  network,

  /// Authentication / key error.
  auth,

  /// Device identity no longer matches the registered device.
  deviceIdentityMismatch,

  /// Server returned an error.
  server,

  /// Epoch rotation error.
  epochRotation,

  /// Protocol violation.
  protocol,

  /// Clock skew too large.
  clockSkew,

  /// Key changed unexpectedly.
  keyChanged,

  /// Request timed out.
  timeout,
}

// ---------------------------------------------------------------------------
// SyncStatus
// ---------------------------------------------------------------------------

/// Current status of the sync engine.
@immutable
class SyncStatus {
  /// Whether the engine is currently unlocked and operational.
  final bool isUnlocked;

  /// Whether a sync cycle is currently in progress.
  final bool isSyncing;

  /// Whether connected to the relay server.
  final bool isConnected;

  /// Number of pending local operations waiting to be pushed.
  final int pendingOps;

  /// Timestamp of the last successful sync.
  final DateTime? lastSyncAt;

  /// Last error encountered, if any.
  final String? lastError;

  const SyncStatus({
    required this.isUnlocked,
    required this.isSyncing,
    required this.isConnected,
    this.pendingOps = 0,
    this.lastSyncAt,
    this.lastError,
  });

  @override
  String toString() =>
      'SyncStatus(unlocked: $isUnlocked, syncing: $isSyncing, '
      'connected: $isConnected, pending: $pendingOps)';
}

// ---------------------------------------------------------------------------
// ChangeSet — a batch of field changes for a single entity
// ---------------------------------------------------------------------------

/// A set of field-level changes for a single entity.
@immutable
class ChangeSet {
  /// The table / entity type name.
  final String table;

  /// The entity ID.
  final String entityId;

  /// Field name to value mapping.
  final Map<String, SyncValue> fields;

  /// The HLC timestamp of this change.
  final String hlc;

  /// Whether this represents a deletion.
  final bool isDelete;

  const ChangeSet({
    required this.table,
    required this.entityId,
    required this.fields,
    required this.hlc,
    this.isDelete = false,
  });

  @override
  String toString() =>
      'ChangeSet($table/$entityId, ${fields.length} fields, delete: $isDelete)';
}
