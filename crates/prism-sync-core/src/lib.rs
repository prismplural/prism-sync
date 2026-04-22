//! # prism-sync-core
//!
//! Encrypted CRDT sync engine with end-to-end encryption.
//!
//! **Privacy model:** The relay server cannot read field-level data content
//! (encrypted with XChaCha20-Poly1305). The server does see sync group
//! membership, device identifiers, epoch numbers, batch sizes, and
//! timing patterns. This is comparable to Signal's metadata exposure.
//! See the threat model section of the design spec for full details.

pub mod batch_signature;
pub mod bootstrap;
pub mod client;
pub mod crdt_change;
pub mod debug_log;
pub mod device_registry;
pub mod engine;
pub mod epoch;
pub mod error;
pub mod events;
pub mod hlc;
pub mod node_id;
pub mod op_emitter;
pub mod pairing;
pub mod pruning;
mod recovery;
pub mod relay;
pub mod runtime;
pub mod runtime_keys;
pub mod schema;
pub mod secure_store;
pub mod storage;
pub mod sync_aad;
pub mod sync_service;
pub mod syncable_entity;

pub use client::{KeyMode, PrismSync, PrismSyncBuilder, SyncStatus};
pub use crdt_change::{CrdtChange, BULK_RESET_FIELD};
pub use debug_log::SyncDebugLog;
pub use device_registry::DeviceRegistryManager;
pub use epoch::EpochManager;
pub use error::{CoreError, RelayErrorCategory, Result};
pub use events::{event_channel, ChangeSet, EntityChange, SyncError, SyncErrorKind, SyncEvent};
pub use hlc::Hlc;
pub use node_id::generate_node_id;
pub use op_emitter::{OpEmitter, DELETED_FIELD};
pub use pairing::service::{cleanup_failed_setup, PairingService};
pub use pruning::{PruneResult, TombstonePruner};
pub use runtime::background_runtime;
pub use schema::{
    decode_value, encode_value, SyncEntityDef, SyncFieldDef, SyncSchema, SyncType, SyncValue,
};
pub use secure_store::SecureStore;
pub use storage::{
    AppliedOp, DeviceRecord, FieldVersion, PendingOp, SyncMetadata, SyncStorage, SyncStorageTx,
};
pub use sync_service::{
    spawn_auto_sync_task, spawn_notification_handler, AutoSyncConfig, SyncService, SyncTrigger,
};
pub use syncable_entity::SyncableEntity;
