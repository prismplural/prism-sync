//! Sharing bootstrap transcript builder.
//!
//! Constructs a deterministic [`BootstrapTranscript`] from both sides' public
//! material during the PQ hybrid remote sharing bootstrap. Both sides call
//! [`build_sharing_transcript`] with identical arguments to produce the same
//! 32-byte digest.

use super::sharing_models::SharingIdentityBundle;
use super::transcript::BootstrapTranscript;
use super::{BootstrapProfile, BootstrapRole, BootstrapVersion};

/// Build the remote sharing transcript from both sides' public material.
///
/// Both sides call this with identical arguments to produce the same hash,
/// which is used for key-schedule binding and confirmation MAC derivation.
///
/// # Arguments
///
/// * `init_id` — unique session identifier for this sharing bootstrap
/// * `sender_identity` — the initiator's sharing identity bundle
/// * `recipient_identity` — the responder's sharing identity bundle
/// * `sender_ephemeral_ek` — initiator's ephemeral X-Wing encapsulation key (1216 bytes)
/// * `recipient_prekey_ek` — responder's signed prekey X-Wing encapsulation key (1216 bytes)
/// * `kem_ciphertext` — KEM ciphertext (1120 bytes)
/// * `target_prekey_id` — the prekey ID targeted by this init
pub fn build_sharing_transcript(
    init_id: &str,
    sender_identity: &SharingIdentityBundle,
    recipient_identity: &SharingIdentityBundle,
    sender_ephemeral_ek: &[u8],
    recipient_prekey_ek: &[u8],
    kem_ciphertext: &[u8],
    target_prekey_id: &str,
) -> [u8; 32] {
    let mut t = BootstrapTranscript::new(BootstrapProfile::RemoteSharing, BootstrapVersion::V1);

    // Field order per Phase 4 plan section 4.4
    t.append_session_id(init_id.as_bytes());
    t.append_role_bytes(
        BootstrapRole::Initiator,
        b"sharing_id",
        sender_identity.sharing_id.as_bytes(),
    );
    t.append_role_bytes(
        BootstrapRole::Responder,
        b"sharing_id",
        recipient_identity.sharing_id.as_bytes(),
    );
    t.append_role_fixed(
        BootstrapRole::Initiator,
        b"ed25519_pk",
        &sender_identity.ed25519_public_key,
    );
    t.append_role_fixed(
        BootstrapRole::Responder,
        b"ed25519_pk",
        &recipient_identity.ed25519_public_key,
    );
    t.append_role_bytes(
        BootstrapRole::Initiator,
        b"ml_dsa_65_pk",
        &sender_identity.ml_dsa_65_public_key,
    );
    t.append_role_bytes(
        BootstrapRole::Responder,
        b"ml_dsa_65_pk",
        &recipient_identity.ml_dsa_65_public_key,
    );
    t.append_role_bytes(
        BootstrapRole::Initiator,
        b"ephemeral_ek",
        sender_ephemeral_ek,
    );
    t.append_role_bytes(
        BootstrapRole::Responder,
        b"signed_prekey_ek",
        recipient_prekey_ek,
    );
    t.append_bytes(b"kem_ciphertext", kem_ciphertext);
    t.append_bytes(b"target_prekey_id", target_prekey_id.as_bytes());

    t.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap::BootstrapVersion;

    const ML_DSA_65_PK_LEN: usize = 1952;
    const XWING_EK_LEN: usize = 1216;
    const KEM_CIPHERTEXT_LEN: usize = 1120;

    fn sample_sender_identity() -> SharingIdentityBundle {
        SharingIdentityBundle {
            version: BootstrapVersion::V1,
            sharing_id: "sender-sharing-id".to_string(),
            identity_generation: 0,
            ed25519_public_key: [0x11; 32],
            ml_dsa_65_public_key: vec![0x22; ML_DSA_65_PK_LEN],
            signature: vec![0x33; 100],
        }
    }

    fn sample_recipient_identity() -> SharingIdentityBundle {
        SharingIdentityBundle {
            version: BootstrapVersion::V1,
            sharing_id: "recipient-sharing-id".to_string(),
            identity_generation: 0,
            ed25519_public_key: [0x44; 32],
            ml_dsa_65_public_key: vec![0x55; ML_DSA_65_PK_LEN],
            signature: vec![0x66; 100],
        }
    }

    fn build_hash(
        init_id: &str,
        sender: &SharingIdentityBundle,
        recipient: &SharingIdentityBundle,
        sender_eph_ek: &[u8],
        recipient_pk_ek: &[u8],
        kem_ct: &[u8],
        target_pk_id: &str,
    ) -> [u8; 32] {
        build_sharing_transcript(
            init_id,
            sender,
            recipient,
            sender_eph_ek,
            recipient_pk_ek,
            kem_ct,
            target_pk_id,
        )
    }

    #[test]
    fn transcript_deterministic() {
        let sender = sample_sender_identity();
        let recipient = sample_recipient_identity();
        let eph_ek = vec![0x77; XWING_EK_LEN];
        let pk_ek = vec![0x88; XWING_EK_LEN];
        let ct = vec![0x99; KEM_CIPHERTEXT_LEN];

        let h1 = build_hash(
            "init-001",
            &sender,
            &recipient,
            &eph_ek,
            &pk_ek,
            &ct,
            "prekey-001",
        );
        let h2 = build_hash(
            "init-001",
            &sender,
            &recipient,
            &eph_ek,
            &pk_ek,
            &ct,
            "prekey-001",
        );
        assert_eq!(h1, h2);
    }

    #[test]
    fn transcript_changes_with_different_init_id() {
        let sender = sample_sender_identity();
        let recipient = sample_recipient_identity();
        let eph_ek = vec![0x77; XWING_EK_LEN];
        let pk_ek = vec![0x88; XWING_EK_LEN];
        let ct = vec![0x99; KEM_CIPHERTEXT_LEN];

        let h1 = build_hash(
            "init-001",
            &sender,
            &recipient,
            &eph_ek,
            &pk_ek,
            &ct,
            "prekey-001",
        );
        let h2 = build_hash(
            "init-002",
            &sender,
            &recipient,
            &eph_ek,
            &pk_ek,
            &ct,
            "prekey-001",
        );
        assert_ne!(h1, h2);
    }

    #[test]
    fn transcript_changes_with_different_sender_key() {
        let sender = sample_sender_identity();
        let recipient = sample_recipient_identity();
        let eph_ek = vec![0x77; XWING_EK_LEN];
        let pk_ek = vec![0x88; XWING_EK_LEN];
        let ct = vec![0x99; KEM_CIPHERTEXT_LEN];

        let mut sender2 = sample_sender_identity();
        sender2.ed25519_public_key = [0xFF; 32];

        let h1 = build_hash(
            "init-001",
            &sender,
            &recipient,
            &eph_ek,
            &pk_ek,
            &ct,
            "prekey-001",
        );
        let h2 = build_hash(
            "init-001",
            &sender2,
            &recipient,
            &eph_ek,
            &pk_ek,
            &ct,
            "prekey-001",
        );
        assert_ne!(h1, h2);
    }

    #[test]
    fn transcript_changes_with_different_recipient_key() {
        let sender = sample_sender_identity();
        let recipient = sample_recipient_identity();
        let eph_ek = vec![0x77; XWING_EK_LEN];
        let pk_ek = vec![0x88; XWING_EK_LEN];
        let ct = vec![0x99; KEM_CIPHERTEXT_LEN];

        let mut recipient2 = sample_recipient_identity();
        recipient2.ml_dsa_65_public_key = vec![0xEE; ML_DSA_65_PK_LEN];

        let h1 = build_hash(
            "init-001",
            &sender,
            &recipient,
            &eph_ek,
            &pk_ek,
            &ct,
            "prekey-001",
        );
        let h2 = build_hash(
            "init-001",
            &sender,
            &recipient2,
            &eph_ek,
            &pk_ek,
            &ct,
            "prekey-001",
        );
        assert_ne!(h1, h2);
    }

    #[test]
    fn transcript_changes_with_different_ciphertext() {
        let sender = sample_sender_identity();
        let recipient = sample_recipient_identity();
        let eph_ek = vec![0x77; XWING_EK_LEN];
        let pk_ek = vec![0x88; XWING_EK_LEN];

        let h1 = build_hash(
            "init-001",
            &sender,
            &recipient,
            &eph_ek,
            &pk_ek,
            &vec![0x99; KEM_CIPHERTEXT_LEN],
            "prekey-001",
        );
        let h2 = build_hash(
            "init-001",
            &sender,
            &recipient,
            &eph_ek,
            &pk_ek,
            &vec![0xFF; KEM_CIPHERTEXT_LEN],
            "prekey-001",
        );
        assert_ne!(h1, h2);
    }

    #[test]
    fn transcript_changes_with_different_ephemeral_ek() {
        let sender = sample_sender_identity();
        let recipient = sample_recipient_identity();
        let pk_ek = vec![0x88; XWING_EK_LEN];
        let ct = vec![0x99; KEM_CIPHERTEXT_LEN];

        let h1 = build_hash(
            "init-001",
            &sender,
            &recipient,
            &vec![0x77; XWING_EK_LEN],
            &pk_ek,
            &ct,
            "prekey-001",
        );
        let h2 = build_hash(
            "init-001",
            &sender,
            &recipient,
            &vec![0xAA; XWING_EK_LEN],
            &pk_ek,
            &ct,
            "prekey-001",
        );
        assert_ne!(h1, h2);
    }

    #[test]
    fn transcript_changes_with_different_target_prekey_id() {
        let sender = sample_sender_identity();
        let recipient = sample_recipient_identity();
        let eph_ek = vec![0x77; XWING_EK_LEN];
        let pk_ek = vec![0x88; XWING_EK_LEN];
        let ct = vec![0x99; KEM_CIPHERTEXT_LEN];

        let h1 = build_hash(
            "init-001",
            &sender,
            &recipient,
            &eph_ek,
            &pk_ek,
            &ct,
            "prekey-001",
        );
        let h2 = build_hash(
            "init-001",
            &sender,
            &recipient,
            &eph_ek,
            &pk_ek,
            &ct,
            "prekey-002",
        );
        assert_ne!(h1, h2);
    }

    #[test]
    fn transcript_differs_from_sync_pairing() {
        // The sharing transcript uses BootstrapProfile::RemoteSharing,
        // while pairing uses BootstrapProfile::SyncPairing.
        // Even with structurally similar inputs, the domain separation
        // ensures different hashes.
        use crate::bootstrap::transcript::BootstrapTranscript;

        let sharing_hash = {
            let mut t =
                BootstrapTranscript::new(BootstrapProfile::RemoteSharing, BootstrapVersion::V1);
            t.append_session_id(b"same-session");
            t.append_bytes(b"data", b"same-data");
            t.finalize()
        };
        let pairing_hash = {
            let mut t =
                BootstrapTranscript::new(BootstrapProfile::SyncPairing, BootstrapVersion::V1);
            t.append_session_id(b"same-session");
            t.append_bytes(b"data", b"same-data");
            t.finalize()
        };
        assert_ne!(sharing_hash, pairing_hash);
    }

    #[test]
    fn transcript_changes_with_swapped_roles() {
        let sender = sample_sender_identity();
        let recipient = sample_recipient_identity();
        let eph_ek = vec![0x77; XWING_EK_LEN];
        let pk_ek = vec![0x88; XWING_EK_LEN];
        let ct = vec![0x99; KEM_CIPHERTEXT_LEN];

        let h1 = build_hash(
            "init-001",
            &sender,
            &recipient,
            &eph_ek,
            &pk_ek,
            &ct,
            "prekey-001",
        );
        // Swap sender and recipient
        let h2 = build_hash(
            "init-001",
            &recipient,
            &sender,
            &eph_ek,
            &pk_ek,
            &ct,
            "prekey-001",
        );
        assert_ne!(h1, h2);
    }
}
