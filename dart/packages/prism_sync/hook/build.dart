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

  if (codeConfig.targetOS == OS.windows) {
    final environment = _selectedEnvironment(const [
      'DAV1D_NO_PKG_CONFIG',
      'PKG_CONFIG',
      'PKG_CONFIG_ALLOW_SYSTEM_CFLAGS',
      'PKG_CONFIG_ALLOW_SYSTEM_LIBS',
      'PKG_CONFIG_LIBDIR',
      'PKG_CONFIG_PATH',
      'PKG_CONFIG_SYSROOT_DIR',
    ]);

    final dav1dPkgConfigDir =
        Platform.environment['PKG_CONFIG_PATH']?.ifEmpty() ??
        _firstExistingFileParent(const [
          r'C:\vcpkg\installed\x64-windows-static\lib\pkgconfig\dav1d.pc',
          r'C:\vcpkg\installed\x64-windows\lib\pkgconfig\dav1d.pc',
        ]);
    if (dav1dPkgConfigDir != null) {
      environment.addAll({
        'PKG_CONFIG_PATH': dav1dPkgConfigDir,
        'PKG_CONFIG_ALLOW_SYSTEM_CFLAGS': '1',
        'PKG_CONFIG_ALLOW_SYSTEM_LIBS': '1',
      });
    }

    // Windows: link a prebuilt OpenSSL instead of vendoring it. SQLCipher
    // otherwise builds OpenSSL from source, whose deeply nested object paths
    // overflow Windows' 260-char MAX_PATH under .dart_tool/hooks_runner.
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
      environment.addAll({
        'OPENSSL_NO_VENDOR': '1',
        'OPENSSL_STATIC': '1',
        'OPENSSL_DIR': dir,
        'OPENSSL_LIB_DIR': libDir,
        'OPENSSL_INCLUDE_DIR': '$dir\\include',
      });
    }
    return environment;
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

String? _firstExistingFileParent(List<String> candidates) {
  for (final path in candidates) {
    final file = File(path);
    if (file.existsSync()) return file.parent.path;
  }
  return null;
}

Map<String, String> _selectedEnvironment(List<String> names) {
  return {
    for (final name in names)
      if (Platform.environment[name]?.isNotEmpty ?? false)
        name: Platform.environment[name]!,
  };
}
