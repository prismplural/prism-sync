import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:prism_sync/prism_sync.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  test('package exports compile', () {
    expect(SyncErrorKind.protocol.name, 'protocol');
  });
}
