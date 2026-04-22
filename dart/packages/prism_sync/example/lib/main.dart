import 'package:flutter/material.dart';
import 'package:prism_sync/prism_sync.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    final sampleKind = SyncErrorKind.protocol;
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(title: const Text('prism_sync example')),
        body: Center(child: Text('Package loaded. Sample kind: $sampleKind')),
      ),
    );
  }
}
