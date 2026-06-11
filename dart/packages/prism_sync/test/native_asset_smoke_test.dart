import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart';
import 'package:prism_sync/generated/api.dart';
import 'package:prism_sync/generated/frb_generated.dart';

const _frbAssetId = 'package:prism_sync/generated/frb_generated.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test('loads bundled Rust native asset', () async {
    await RustLib.init(externalLibrary: _nativeAssetLibraryForTest());
    addTearDown(RustLib.dispose);

    final mnemonic = await generateSecretKey();

    expect(mnemonic.trim().split(RegExp(r'\s+')), hasLength(12));
  }, timeout: const Timeout(Duration(minutes: 2)));
}

ExternalLibrary _nativeAssetLibraryForTest() {
  final manifestFile = File(
    'build/native_assets/${Platform.operatingSystem}/native_assets.json',
  );
  final manifest = jsonDecode(manifestFile.readAsStringSync()) as Map;
  final nativeAssets = manifest['native-assets'] as Map;

  for (final assetsForArch in nativeAssets.values.cast<Map>()) {
    final entry = assetsForArch[_frbAssetId] as List?;
    if (entry != null && entry.length == 2 && entry.first == 'absolute') {
      return ExternalLibrary.open(entry.last as String);
    }
  }

  throw StateError('Native asset $_frbAssetId was not found in $manifestFile');
}
