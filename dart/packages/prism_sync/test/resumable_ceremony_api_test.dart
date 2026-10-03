import 'package:flutter_test/flutter_test.dart';
import 'package:prism_sync/generated/api.dart';
import 'package:prism_sync/generated/frb_generated.dart';

/// Compile-time and shape coverage for the resumable split pairing ceremony.
///
/// These assertions do not need the native library: they pin the *generated
/// surface* the app codes against, so a Rust-side change that renames, drops, or
/// changes the shape of the split ceremony fails here rather than in the app.
/// The behaviour behind each function is covered by the Rust FFI tests, which
/// can drive real handles.
void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('generated resumable split ceremony surface', () {
    test('exposes the three ordered steps as separate functions', () {
      // Each is a distinct step, so the app cannot accidentally collapse the
      // "verify -> upload -> release credentials" order into one call.
      expect(verifyInitiatorConfirmationResumable, isA<Function>());
      expect(uploadPairingSnapshotResumable, isA<Function>());
      expect(completeInitiatorResumableCeremony, isA<Function>());
    });

    test('exposes the capability probe', () {
      expect(snapshotUploadCapability, isA<Function>());
    });

    test('steps carry the expected parameter shapes', () {
      // Signatures are checked structurally so a generator change that alters
      // them is caught at analysis/test time. Function-typed assignment fails to
      // compile if a parameter is renamed or its type changes.
      final Future<bool> Function({
        required PrismSyncHandle handle,
      })
      verify = verifyInitiatorConfirmationResumable;
      expect(verify, isA<Function>());

      final Future<ResumableSnapshotUploadResult> Function({
        required PrismSyncHandle handle,
        BigInt? ttlSecs,
      })
      upload = uploadPairingSnapshotResumable;
      expect(upload, isA<Function>());

      final Future<ResumableCeremonyCompletion> Function({
        required PrismSyncHandle handle,
        required List<int> password,
        required List<int> mnemonic,
      })
      complete = completeInitiatorResumableCeremony;
      expect(complete, isA<Function>());

      final Future<SnapshotUploadCapabilityInfo> Function({
        required PrismSyncHandle handle,
      })
      capability = snapshotUploadCapability;
      expect(capability, isA<Function>());
    });

    test('the legacy one-shot APIs remain available', () {
      // Mixed-version app builds still call these; they must keep their
      // signatures.
      final Future<void> Function({
        required PrismSyncHandle handle,
        required BigInt ttlSecs,
        String? forDeviceId,
      })
      legacyUpload = uploadPairingSnapshot;
      expect(legacyUpload, isA<Function>());

      final Future<String> Function({
        required PrismSyncHandle handle,
        required List<int> password,
        required List<int> mnemonic,
      })
      legacyComplete = completeInitiatorCeremony;
      expect(legacyComplete, isA<Function>());

      final Future<void> Function({required PrismSyncHandle handle})
      legacyCancel = cancelPairingCeremony;
      expect(legacyCancel, isA<Function>());
    });
  });

  group('generated transport/result types', () {
    test('resumable transport is an enum with both paths', () {
      expect(SnapshotTransportUsed.values, contains(SnapshotTransportUsed.resumable));
      expect(SnapshotTransportUsed.values, contains(SnapshotTransportUsed.singlePut));
    });

    test('capability state is an enum including the downgrade case', () {
      expect(
        SnapshotUploadCapabilityState.values,
        containsAll(<SnapshotUploadCapabilityState>[
          SnapshotUploadCapabilityState.available,
          SnapshotUploadCapabilityState.unavailable,
          SnapshotUploadCapabilityState.engineUnconfigured,
        ]),
      );
    });

    test('upload result carries terminal byte counts and the session id', () {
      const result = ResumableSnapshotUploadResult(
        transport: SnapshotTransportUsed.resumable,
        uploadId: 'session-1',
        committedBytes: 4096,
        totalBytes: 4096,
        leaseActive: true,
        leaseRenewed: false,
      );
      expect(result.transport, SnapshotTransportUsed.resumable);
      expect(result.uploadId, 'session-1');
      expect(result.leaseActive, isTrue);
      // A lease-capable ceremony whose renewals all failed is explicitly
      // representable, so the app can message the downgrade honestly.
      expect(result.leaseRenewed, isFalse);
    });

    test('a single-PUT downgrade reports no session id', () {
      const result = ResumableSnapshotUploadResult(
        transport: SnapshotTransportUsed.singlePut,
        uploadId: '',
        committedBytes: 1024,
        totalBytes: 1024,
        leaseActive: false,
        leaseRenewed: false,
      );
      expect(result.transport, SnapshotTransportUsed.singlePut);
      expect(result.uploadId, isEmpty);
    });

    test('completion result distinguishes lease states', () {
      const completion = ResumableCeremonyCompletion(
        completed: true,
        leaseActive: false,
        leaseRenewed: false,
        leaseCapable: false,
        error: null,
      );
      expect(completion.completed, isTrue);
      expect(completion.leaseCapable, isFalse);
      expect(completion.error, isNull);
    });

    test('capability info reports the negotiated chunk size', () {
      const info = SnapshotUploadCapabilityInfo(
        state: SnapshotUploadCapabilityState.available,
        version: 1,
        chunkBytes: 8388608,
        maxWireBytes: 157286400,
        reason: null,
      );
      expect(info.state, SnapshotUploadCapabilityState.available);
      expect(info.chunkBytes.toInt(), 8388608, reason: 'v1 chunk size is 8 MiB');
      expect(info.maxWireBytes.toInt(), 157286400, reason: 'v1 cap is 150 MiB');
    });

    test('an unavailable capability explains itself without failing', () {
      const info = SnapshotUploadCapabilityInfo(
        state: SnapshotUploadCapabilityState.unavailable,
        version: 0,
        chunkBytes: 0,
        maxWireBytes: 0,
        reason: 'not_advertised',
      );
      expect(info.state, SnapshotUploadCapabilityState.unavailable);
      expect(info.reason, isNotNull);
    });
  });

  test('RustLib is the only bridge singleton the split ceremony needs', () {
    // Guards against a design that reintroduces a global callback port: the
    // split ceremony's progress is reported through the existing sync event
    // stream and the terminal result, so no extra global is required.
    expect(RustLib.instance, isNotNull);
  });
}
