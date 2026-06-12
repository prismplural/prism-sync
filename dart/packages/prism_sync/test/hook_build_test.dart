import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

void main() {
  test('build hook skips when code assets are not requested', () async {
    final tempDir = await Directory.systemTemp.createTemp(
      'prism_sync_hook_build_test_',
    );
    addTearDown(() async {
      if (await tempDir.exists()) {
        await tempDir.delete(recursive: true);
      }
    });

    final sharedDir = Directory.fromUri(tempDir.uri.resolve('shared/'));
    await sharedDir.create(recursive: true);
    final inputFile = File.fromUri(tempDir.uri.resolve('input.json'));
    final outputFile = File.fromUri(tempDir.uri.resolve('output.json'));

    await inputFile.writeAsString(
      jsonEncode({
        'assets': <String, Object?>{},
        'config': {'build_asset_types': <String>[], 'linking_enabled': false},
        'out_dir_shared': sharedDir.uri.toFilePath(),
        'out_file': outputFile.path,
        'package_name': 'prism_sync',
        'package_root': Directory.current.absolute.uri.toFilePath(),
        'user_defines': <String, Object?>{},
      }),
    );

    final result = await Process.run(_dartExecutable(), [
      'hook/build.dart',
      '--config=${inputFile.path}',
    ], workingDirectory: Directory.current.path);

    expect(
      result.exitCode,
      0,
      reason: 'stdout:\n${result.stdout}\nstderr:\n${result.stderr}',
    );
    expect(
      result.stdout,
      contains('buildCodeAssets is false; skipping build of Rust code assets'),
    );
  });
}

String _dartExecutable() {
  final flutterRoot = Platform.environment['FLUTTER_ROOT'];
  if (flutterRoot != null && flutterRoot.isNotEmpty) {
    final flutterDart = File('$flutterRoot/bin/cache/dart-sdk/bin/dart');
    if (flutterDart.existsSync()) {
      return flutterDart.path;
    }
  }

  return Platform.resolvedExecutable;
}
