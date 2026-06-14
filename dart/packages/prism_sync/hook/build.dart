import 'dart:io';

import 'package:code_assets/code_assets.dart';
import 'package:hooks/hooks.dart';
import 'package:native_toolchain_rust/native_toolchain_rust.dart';

void main(List<String> args) async {
  await build(args, (input, output) async {
    await RustBuilder(
      assetName: 'generated/frb_generated.dart',
      cratePath: '../../../crates/prism-sync-ffi',
      extraCargoEnvironmentVariables: input.config.buildCodeAssets
          ? _cargoEnvironmentFor(input.config.code)
          : const {},
    ).run(input: input, output: output);
  });
}

Map<String, String> _cargoEnvironmentFor(CodeConfig codeConfig) {
  if (codeConfig.targetOS == OS.iOS) {
    final deploymentTarget = Platform.environment['IPHONEOS_DEPLOYMENT_TARGET'];
    final configuredTarget = '${codeConfig.iOS.targetVersion}.0';
    return {
      'IPHONEOS_DEPLOYMENT_TARGET':
          deploymentTarget == null || deploymentTarget.isEmpty
          ? configuredTarget
          : deploymentTarget,
    };
  }

  // Windows: link a prebuilt OpenSSL instead of vendoring it. SQLCipher
  // otherwise builds OpenSSL from source, whose deeply nested object paths
  // overflow Windows' 260-char MAX_PATH under .dart_tool/hooks_runner. This map
  // is the only channel that reaches openssl-sys's build script — RustBuilder
  // doesn't forward the ambient environment — so the hook discovers OpenSSL
  // itself rather than relying on env vars set by the build wrapper.
  if (codeConfig.targetOS == OS.windows) {
    final dir =
        Platform.environment['OPENSSL_DIR']?.ifEmpty() ??
        _firstExistingDir(const [
          r'C:\Program Files\OpenSSL',
          r'C:\Program Files\OpenSSL-Win64',
        ]);
    if (dir != null) {
      // openssl-sys links `libcrypto.lib`; the installer names the static libs
      // `*_static.lib` under lib\VC\x64\MD. Copy them to the expected names.
      final mdDir = '$dir\\lib\\VC\\x64\\MD';
      final libDir = Directory.systemTemp.createTempSync('prism_openssl_').path;
      File('$mdDir\\libcrypto_static.lib').copySync('$libDir\\libcrypto.lib');
      File('$mdDir\\libssl_static.lib').copySync('$libDir\\libssl.lib');
      return {
        'OPENSSL_NO_VENDOR': '1',
        'OPENSSL_STATIC': '1',
        'OPENSSL_DIR': dir,
        'OPENSSL_LIB_DIR': libDir,
        'OPENSSL_INCLUDE_DIR': '$dir\\include',
      };
    }
  }

  return const {};
}

extension on String {
  String? ifEmpty() => isEmpty ? null : this;
}

String? _firstExistingDir(List<String> candidates) {
  for (final dir in candidates) {
    if (Directory(dir).existsSync()) return dir;
  }
  return null;
}
