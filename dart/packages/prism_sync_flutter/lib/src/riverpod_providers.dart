/// Riverpod providers for prism-sync.
///
/// Placeholder — requires `flutter_riverpod` dependency.
///
/// When the Flutter dependency is added, this file will export:
///
/// ```dart
/// import 'package:flutter_riverpod/flutter_riverpod.dart';
/// import 'package:prism_sync/prism_sync.dart';
///
/// /// Core PrismSync instance provider.
/// /// Override in app's ProviderScope with a configured PrismSyncClient.
/// final prismSyncProvider = Provider<PrismSyncClient>((ref) {
///   throw UnimplementedError('Override in app with ProviderScope');
/// });
///
/// /// Reactive stream of sync events.
/// final syncEventsProvider = StreamProvider<SyncEvent>((ref) {
///   return ref.watch(prismSyncProvider).events;
/// });
///
/// /// Current sync status (derived from latest event).
/// final syncStatusProvider = Provider<SyncStatus>((ref) {
///   return ref.watch(prismSyncProvider).status();
/// });
/// ```
