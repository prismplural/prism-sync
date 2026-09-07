import 'dart:async';

import 'package:prism_sync_drift/prism_sync_drift.dart';
import 'package:test/test.dart';

DriftSyncEntity entity({
  required String tableName,
  required Future<void> Function(String id, Map<String, dynamic> fields)
      applyFields,
  required Future<void> Function(String id) hardDelete,
}) {
  return DriftSyncEntity(
    tableName: tableName,
    toSyncFields: (_) => const {},
    applyFields: applyFields,
    hardDelete: hardDelete,
    readRow: (_) async => null,
    isDeleted: (_) async => false,
  );
}

void main() {
  group('DriftSyncAdapter', () {
    test('routes field application to the matching entity and awaits it', () async {
      final completed = Completer<void>();
      final calls = <String>[];
      final adapter = DriftSyncAdapter(
        entities: [
          entity(
            tableName: 'members',
            applyFields: (id, fields) async {
              calls.add('$id:${fields['name']}');
              await completed.future;
            },
            hardDelete: (_) async {},
          ),
          entity(
            tableName: 'groups',
            applyFields: (_, __) async => fail('wrong entity was selected'),
            hardDelete: (_) async {},
          ),
        ],
      );

      var adapterCompleted = false;
      final applying = adapter.applyFields('members', 'member-1', {'name': 'Ada'}).then((_) {
        adapterCompleted = true;
      });
      await Future<void>.delayed(Duration.zero);
      expect(calls, ['member-1:Ada']);
      expect(adapterCompleted, isFalse);

      completed.complete();
      await applying;
      expect(adapterCompleted, isTrue);
    });

    test('rejects unknown tables for apply and hard delete', () async {
      final adapter = DriftSyncAdapter(
        entities: [
          entity(
            tableName: 'members',
            applyFields: (_, __) async {},
            hardDelete: (_) async {},
          ),
        ],
      );

      final matcher = isA<ArgumentError>().having(
        (error) => error.message,
        'message',
        contains('No sync entity registered for table: unknown'),
      );
      await expectLater(adapter.applyFields('unknown', 'id', const {}), throwsA(matcher));
      await expectLater(adapter.hardDelete('unknown', 'id'), throwsA(matcher));
    });

    test('routes hard deletes and awaits their completion', () async {
      final completed = Completer<void>();
      final deleted = <String>[];
      final adapter = DriftSyncAdapter(
        entities: [
          entity(
            tableName: 'members',
            applyFields: (_, __) async {},
            hardDelete: (id) async {
              deleted.add(id);
              await completed.future;
            },
          ),
        ],
      );

      var adapterCompleted = false;
      final deleting = adapter.hardDelete('members', 'member-1').then((_) {
        adapterCompleted = true;
      });
      await Future<void>.delayed(Duration.zero);
      expect(deleted, ['member-1']);
      expect(adapterCompleted, isFalse);

      completed.complete();
      await deleting;
      expect(adapterCompleted, isTrue);
    });

    test('propagates callback failures unchanged', () async {
      final applyFailure = StateError('apply failed');
      final deleteFailure = StateError('delete failed');
      final adapter = DriftSyncAdapter(
        entities: [
          entity(
            tableName: 'members',
            applyFields: (_, __) => Future<void>.error(applyFailure),
            hardDelete: (_) => Future<void>.error(deleteFailure),
          ),
        ],
      );

      await expectLater(
        adapter.applyFields('members', 'member-1', const {}),
        throwsA(same(applyFailure)),
      );
      await expectLater(
        adapter.hardDelete('members', 'member-1'),
        throwsA(same(deleteFailure)),
      );
    });
  });
}
