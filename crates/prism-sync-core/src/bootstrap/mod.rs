//! Shared bootstrap substrate for PQ hybrid handshakes.
//!
//! Provides protocol-agnostic handshake mechanics used by both sync pairing
//! (Phase 3) and remote sharing bootstrap (Phase 4). Does not depend on
//! pairing models, relay traits, or secure store.

pub mod ceremony;
pub mod confirmation;
pub mod encrypted_envelope;
pub mod handshake;
mod integration_test;
pub mod key_schedule;
pub mod pairing_models;
pub mod pairing_transcript;
pub mod prekey_store;
mod sas_words;
pub mod sharing_identity;
#[cfg(test)]
mod sharing_integration_test;
pub mod sharing_models;
pub mod sharing_recipient;
pub mod sharing_sender;
pub mod sharing_transcript;
pub mod sharing_trust;
pub mod transcript;

pub use ceremony::{InitiatorCeremony, JoinerCeremony};
pub use confirmation::{ConfirmationCode, PublicFingerprint};
pub use encrypted_envelope::{EncryptedEnvelope, EnvelopeContext};
pub use handshake::{BootstrapHandshake, BootstrapSecret, DefaultBootstrapHandshake};
pub use key_schedule::BootstrapKeySchedule;
pub use pairing_models::{
    CredentialBundle, JoinerBootstrapRecord, JoinerBundle, PairingInit, PairingPublicKeys,
    RendezvousToken, SasDisplay,
};
pub use pairing_transcript::build_sync_pairing_transcript;
pub use prekey_store::PrekeyStore;
pub use sharing_identity::{
    derive_sharing_ed25519_keypair, derive_sharing_identity_seed, derive_sharing_ml_dsa_keypair,
};
pub use sharing_models::{
    SharingIdentityBundle, SharingInit, SharingInitPayload, SharingPrekeyBundle,
    SharingRelationship, SignedPrekey as SharingSignedPrekey,
};
pub use sharing_recipient::{ProcessedSharingInit, SharingRecipient};
pub use sharing_sender::{SharingInitResult, SharingSender};
pub use sharing_transcript::build_sharing_transcript;
pub use transcript::BootstrapTranscript;

/// Protocol version for the bootstrap handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BootstrapVersion {
    /// PQ hybrid bootstrap, initial version
    V1 = 1,
}

impl BootstrapVersion {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::V1),
            _ => None,
        }
    }

    pub fn as_byte(self) -> u8 {
        self as u8
    }
}

/// Bootstrap profile — determines domain separation for transcript,
/// key derivation, and envelope AAD.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BootstrapProfile {
    /// Interactive sync device pairing (co-present SAS ceremony)
    SyncPairing = 1,
    /// Asynchronous remote sharing bootstrap (prekey-based)
    RemoteSharing = 2,
}

impl BootstrapProfile {
    pub fn as_byte(self) -> u8 {
        self as u8
    }
}

/// Role in the bootstrap ceremony.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BootstrapRole {
    /// The side that initiated the bootstrap ceremony
    Initiator = 1,
    /// The side that responded to the bootstrap ceremony
    Responder = 2,
}

impl BootstrapRole {
    pub fn as_byte(self) -> u8 {
        self as u8
    }
}
