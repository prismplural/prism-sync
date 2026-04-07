//! Shared bootstrap substrate for PQ hybrid handshakes.
//!
//! Provides protocol-agnostic handshake mechanics used by both sync pairing
//! (Phase 3) and remote sharing bootstrap (Phase 4). Does not depend on
//! pairing models, relay traits, or secure store.

pub mod confirmation;
pub mod encrypted_envelope;
pub mod handshake;
mod integration_test;
pub mod key_schedule;
mod sas_words;
pub mod transcript;

pub use confirmation::{ConfirmationCode, PublicFingerprint};
pub use encrypted_envelope::{EncryptedEnvelope, EnvelopeContext};
pub use handshake::{BootstrapHandshake, BootstrapSecret, DefaultBootstrapHandshake};
pub use key_schedule::BootstrapKeySchedule;
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
