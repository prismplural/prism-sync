# prism-sync-ffi

FFI layer that bridges `prism-sync-core` and `prism-sync-crypto` to Dart/Flutter via [flutter_rust_bridge](https://github.com/aspect-build/flutter_rust_bridge) v2.

## Purpose

Flutter/Dart cannot directly call Rust trait methods or hold trait objects. This crate provides a flat, primitive-type-only API surface that flutter_rust_bridge can generate Dart bindings for. All complex Rust types (trait objects, generics, closures) are hidden behind opaque handles and JSON serialization.

## How Codegen Works

1. Define public functions in `src/api.rs` using only FFI-safe types
2. Run `flutter_rust_bridge_codegen generate` from the workspace root
3. Generated files appear in `dart/packages/prism_sync/lib/generated/`
4. Dart calls the generated functions, which route through FRB to the Rust implementations

```bash
# After changing src/api.rs:
flutter_rust_bridge_codegen generate
```

Never edit files in `dart/packages/prism_sync/lib/generated/` manually -- they are overwritten on each codegen run.

## API Surface

### Construction
| Function | Description |
|----------|-------------|
| `create_prism_sync(relay_url, db_path, allow_insecure, schema_json, use_memory_store)` | Build and configure a PrismSync instance, returns `PrismSyncHandle` |

### Key Lifecycle
| Function | Description |
|----------|-------------|
| `initialize(handle, password, secret_key)` | First-time setup: generate DEK, wrap under password |
| `unlock(handle, password, secret_key)` | Subsequent launches: unwrap DEK |
| `lock(handle)` | Zero all key material from memory |
| `is_unlocked(handle)` | Check if keys are available |
| `generate_secret_key()` | Generate new BIP39 12-word mnemonic |
| `database_key(handle)` | Derive database encryption key |
| `change_password(handle, old_password, new_password, secret_key)` | Re-wrap DEK under new password |

### Mutation Recording
| Function | Description |
|----------|-------------|
| `record_create(handle, table, entity_id, fields_json)` | Record entity creation |
| `record_update(handle, table, entity_id, changed_fields_json)` | Record field updates |
| `record_delete(handle, table, entity_id)` | Record soft delete (tombstone) |

### Sync Control
| Function | Description |
|----------|-------------|
| `sync_now(handle)` | Trigger full sync cycle, returns JSON result |
| `on_resume(handle)` | Catch-up sync if stale (>5s since last sync) |
| `set_auto_sync(handle, enabled, debounce_ms, retry_delay_ms, max_retries)` | Configure auto-sync |
| `status(handle)` | Get current sync status as JSON |
| `poll_event(handle)` | Poll for next sync event (JSON or None) |

### Pairing
| Function | Description |
|----------|-------------|
| `create_sync_group(handle, password, relay_url)` | Create a new sync group, returns sync metadata JSON |
| `prepare_pending_device_identity(handle)` | Persist a pending joiner identity before relay-based pairing |
| `create_pairing_session(handle)` | Create initiator-side relay rendezvous metadata |
| `start_joiner_pairing(handle, relay_url, rendezvous_token)` | Start the relay-based joiner ceremony |
| `start_initiator_pairing(handle, rendezvous_token)` | Start the relay-based initiator ceremony |
| `poll_pairing_status(handle, rendezvous_token)` | Poll pairing state until SAS/credentials are ready |
| `complete_pairing(handle, rendezvous_token, sas_confirmed, password)` | Complete the relay-based pairing ceremony |

### Device Management
| Function | Description |
|----------|-------------|
| `list_devices(handle, sync_id, device_id, session_token)` | List devices as JSON array |
| `revoke_device(handle, sync_id, device_id, session_token, target_device_id)` | Revoke a device |

## Opaque Types

### PrismSyncHandle

The primary opaque handle that Dart holds as `RustOpaqueInterface`:

```rust
pub struct PrismSyncHandle {
    inner: Arc<tokio::sync::Mutex<PrismSync>>,
    relay_url: String,
    allow_insecure: bool,
}
```

- `tokio::sync::Mutex` (not `std::sync::Mutex`) so async methods can hold the lock across `.await` points
- Compile-time `Send + Sync` assertions
- `relay_url` and `allow_insecure` stored for constructing `ServerRelay` instances on the Rust side

### MemorySecureStore

An in-memory `SecureStore` implementation backed by `HashMap`, exposed for testing:

```dart
final store = await MemorySecureStore.newInstance();
```

In production, the real `SecureStore` is provided by `prism_sync_flutter` which bridges to platform Keychain/Keystore.

## Design Constraints

### No trait objects across FFI
Dart cannot hold `dyn SyncRelay` or `dyn SecureStore`. Instead:
- `PrismSyncHandle` wraps everything internally
- Relay connections are constructed on the Rust side from primitive parameters via `build_relay()`
- Device management functions take `(sync_id, device_id, session_token)` as primitives

### JSON for complex data
- Schema definitions: JSON string parsed by `parse_schema_json()`
- Field values: JSON string parsed by `parse_fields_json()`
- Sync results, status, events: serialized to JSON on the Rust side
- Device lists: serialized to JSON array

### Async via tokio
All async FFI functions use `tokio::sync::Mutex` to safely hold the lock across await points. The tokio runtime is managed by flutter_rust_bridge.

## Schema JSON Format

```json
{
  "entities": {
    "members": {
      "fields": {
        "name": "String",
        "age": "Int",
        "active": "Bool",
        "avatar": "Blob",
        "created_at": "DateTime"
      }
    }
  }
}
```

Supported types: `String`, `Int`, `Bool`, `DateTime`, `Blob`.

## Regenerating Bindings

After any change to `src/api.rs`:

```bash
flutter_rust_bridge_codegen generate
```

This updates:
- `src/frb_generated.rs` (Rust side)
- `dart/packages/prism_sync/lib/generated/api.dart` (Dart side)
- `dart/packages/prism_sync/lib/generated/frb_generated.dart` (Dart side)

Private functions (not `pub`) and internal helpers are automatically excluded from codegen.
