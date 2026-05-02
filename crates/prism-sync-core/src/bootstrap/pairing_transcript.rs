//! Sync pairing transcript builder.
//!
//! Constructs a deterministic [`BootstrapTranscript`] from both sides' public
//! material during the PQ hybrid pairing ceremony. Both sides call
//! [`build_sync_pairing_transcript`] with identical arguments to produce the
//! same 32-byte digest.

use super::pairing_models::{JoinerBootstrapRecord, PairingPublicKeys};
use super::transcript::BootstrapTranscript;
use super::{BootstrapProfile, BootstrapRole, BootstrapVersion};

/// Build the sync pairing transcript from both sides' public material.
///
/// Both sides call this with identical arguments to produce the same hash,
/// which is then used for key-schedule binding and SAS code derivation.
pub fn build_sync_pairing_transcript(
    rendezvous_id: &[u8; 16],
    commitment: &[u8; 32],
    sas_version: u8,
    initiator: &PairingPublicKeys,
    responder: &JoinerBootstrapRecord,
    kem_ciphertext: &[u8],
    relay_origin: &str,
) -> [u8; 32] {
    let mut t = BootstrapTranscript::new(BootstrapProfile::SyncPairing, BootstrapVersion::V1);

    // Field order per Phase 3 plan section 3.2
    t.append_session_id(rendezvous_id);
    t.append_fixed(b"pairing_sas_version", &[sas_version]);
    t.append_role_bytes(BootstrapRole::Initiator, b"device_id", initiator.device_id.as_bytes());
    t.append_role_bytes(BootstrapRole::Responder, b"device_id", responder.device_id.as_bytes());
    t.append_role_fixed(BootstrapRole::Initiator, b"ed25519_pk", &initiator.ed25519_pk);
    t.append_role_fixed(BootstrapRole::Responder, b"ed25519_pk", &responder.ed25519_public_key);
    t.append_role_fixed(BootstrapRole::Initiator, b"x25519_pk", &initiator.x25519_pk);
    t.append_role_fixed(BootstrapRole::Responder, b"x25519_pk", &responder.x25519_public_key);
    t.append_role_bytes(BootstrapRole::Initiator, b"ml_dsa_65_pk", &initiator.ml_dsa_65_pk);
    t.append_role_bytes(BootstrapRole::Responder, b"ml_dsa_65_pk", &responder.ml_dsa_65_public_key);
    // SAS v3 binds the full atomic X-Wing EK, not only its ML-KEM prefix.
    t.append_role_bytes(BootstrapRole::Initiator, b"xwing_ek", &initiator.xwing_ek);
    t.append_role_bytes(BootstrapRole::Responder, b"xwing_ek", &responder.xwing_ek);
    t.append_bytes(b"kem_ciphertext", kem_ciphertext);
    t.append_bytes(b"relay_origin", relay_origin.as_bytes());
    t.append_fixed(b"bootstrap_commitment", commitment);

    t.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap::{BootstrapVersion, PAIRING_SAS_VERSION};

    const ML_DSA_65_PK_LEN: usize = 1952;
    const ML_KEM_768_EK_LEN: usize = 1184;
    const XWING_EK_LEN: usize = 1216;

    fn sample_initiator() -> PairingPublicKeys {
        PairingPublicKeys {
            device_id: "initiator-device".to_string(),
            ed25519_pk: [0x11; 32],
            x25519_pk: [0x22; 32],
            ml_dsa_65_pk: vec![0x33; ML_DSA_65_PK_LEN],
            xwing_ek: vec![0x44; XWING_EK_LEN],
        }
    }

    fn sample_responder() -> JoinerBootstrapRecord {
        JoinerBootstrapRecord {
            version: BootstrapVersion::V1,
            device_id: "responder-device".to_string(),
            ed25519_public_key: [0x55; 32],
            x25519_public_key: [0x66; 32],
            ml_dsa_65_public_key: vec![0x77; ML_DSA_65_PK_LEN],
            xwing_ek: vec![0x88; XWING_EK_LEN],
            permanent_ml_kem_768_public_key: vec![],
            permanent_xwing_public_key: vec![],
        }
    }

    fn build_hash(
        rendezvous_id: &[u8; 16],
        commitment: &[u8; 32],
        initiator: &PairingPublicKeys,
        responder: &JoinerBootstrapRecord,
        kem_ciphertext: &[u8],
        relay_origin: &str,
    ) -> [u8; 32] {
        build_sync_pairing_transcript(
            rendezvous_id,
            commitment,
            PAIRING_SAS_VERSION,
            initiator,
            responder,
            kem_ciphertext,
            relay_origin,
        )
    }

    #[test]
    fn transcript_deterministic() {
        let rid = [0x42; 16];
        let commit = [0xAB; 32];
        let init = sample_initiator();
        let resp = sample_responder();
        let ct = vec![0x99; 1120];

        let h1 = build_hash(&rid, &commit, &init, &resp, &ct, "https://relay.example.com");
        let h2 = build_hash(&rid, &commit, &init, &resp, &ct, "https://relay.example.com");
        assert_eq!(h1, h2);
    }

    #[test]
    fn transcript_changes_with_different_session_id() {
        let commit = [0xAB; 32];
        let init = sample_initiator();
        let resp = sample_responder();
        let ct = vec![0x99; 1120];

        let h1 = build_hash(&[0x01; 16], &commit, &init, &resp, &ct, "https://relay.example.com");
        let h2 = build_hash(&[0x02; 16], &commit, &init, &resp, &ct, "https://relay.example.com");
        assert_ne!(h1, h2);
    }

    #[test]
    fn transcript_changes_with_different_commitment() {
        let rid = [0x42; 16];
        let init = sample_initiator();
        let resp = sample_responder();
        let ct = vec![0x99; 1120];

        let h1 = build_hash(&rid, &[0xAA; 32], &init, &resp, &ct, "https://relay.example.com");
        let h2 = build_hash(&rid, &[0xBB; 32], &init, &resp, &ct, "https://relay.example.com");
        assert_ne!(h1, h2);
    }

    #[test]
    fn transcript_changes_with_different_sas_version() {
        let rid = [0x42; 16];
        let commit = [0xAB; 32];
        let init = sample_initiator();
        let resp = sample_responder();
        let ct = vec![0x99; 1120];

        let h1 = build_sync_pairing_transcript(
            &rid,
            &commit,
            PAIRING_SAS_VERSION,
            &init,
            &resp,
            &ct,
            "https://relay.example.com",
        );
        let h2 = build_sync_pairing_transcript(
            &rid,
            &commit,
            PAIRING_SAS_VERSION.saturating_add(1),
            &init,
            &resp,
            &ct,
            "https://relay.example.com",
        );
        assert_ne!(h1, h2);
    }

    #[test]
    fn transcript_changes_with_different_initiator_key() {
        let rid = [0x42; 16];
        let commit = [0xAB; 32];
        let resp = sample_responder();
        let ct = vec![0x99; 1120];

        let init1 = sample_initiator();
        let mut init2 = sample_initiator();
        init2.ed25519_pk = [0xFF; 32]; // modify one key

        let h1 = build_hash(&rid, &commit, &init1, &resp, &ct, "https://relay.example.com");
        let h2 = build_hash(&rid, &commit, &init2, &resp, &ct, "https://relay.example.com");
        assert_ne!(h1, h2);
    }

    #[test]
    fn transcript_changes_with_different_initiator_xwing_suffix() {
        let rid = [0x42; 16];
        let commit = [0xAB; 32];
        let resp = sample_responder();
        let ct = vec![0x99; 1120];

        let init1 = sample_initiator();
        let mut init2 = sample_initiator();
        init2.xwing_ek[ML_KEM_768_EK_LEN] ^= 0xFF;

        let h1 = build_hash(&rid, &commit, &init1, &resp, &ct, "https://relay.example.com");
        let h2 = build_hash(&rid, &commit, &init2, &resp, &ct, "https://relay.example.com");
        assert_ne!(h1, h2);
    }

    #[test]
    fn transcript_changes_with_different_responder_xwing_suffix() {
        let rid = [0x42; 16];
        let commit = [0xAB; 32];
        let init = sample_initiator();
        let ct = vec![0x99; 1120];

        let resp1 = sample_responder();
        let mut resp2 = sample_responder();
        resp2.xwing_ek[ML_KEM_768_EK_LEN] ^= 0xFF;

        let h1 = build_hash(&rid, &commit, &init, &resp1, &ct, "https://relay.example.com");
        let h2 = build_hash(&rid, &commit, &init, &resp2, &ct, "https://relay.example.com");
        assert_ne!(h1, h2);
    }

    #[test]
    fn transcript_changes_with_different_ciphertext() {
        let rid = [0x42; 16];
        let commit = [0xAB; 32];
        let init = sample_initiator();
        let resp = sample_responder();

        let h1 =
            build_hash(&rid, &commit, &init, &resp, &vec![0x99; 1120], "https://relay.example.com");
        let h2 =
            build_hash(&rid, &commit, &init, &resp, &vec![0xFF; 1120], "https://relay.example.com");
        assert_ne!(h1, h2);
    }

    #[test]
    fn transcript_changes_with_swapped_roles() {
        let rid = [0x42; 16];
        let commit = [0xAB; 32];
        let ct = vec![0x99; 1120];

        // Normal order
        let init = sample_initiator();
        let resp = sample_responder();
        let h1 = build_hash(&rid, &commit, &init, &resp, &ct, "https://relay.example.com");

        // Swap: use responder's keys as initiator, initiator's as responder
        let swapped_init = PairingPublicKeys {
            device_id: resp.device_id.clone(),
            ed25519_pk: resp.ed25519_public_key,
            x25519_pk: resp.x25519_public_key,
            ml_dsa_65_pk: resp.ml_dsa_65_public_key.clone(),
            xwing_ek: resp.xwing_ek.clone(),
        };
        let swapped_resp = JoinerBootstrapRecord {
            version: BootstrapVersion::V1,
            device_id: init.device_id.clone(),
            ed25519_public_key: init.ed25519_pk,
            x25519_public_key: init.x25519_pk,
            ml_dsa_65_public_key: init.ml_dsa_65_pk.clone(),
            xwing_ek: init.xwing_ek.clone(),
            permanent_ml_kem_768_public_key: vec![],
            permanent_xwing_public_key: vec![],
        };
        let h2 = build_hash(
            &rid,
            &commit,
            &swapped_init,
            &swapped_resp,
            &ct,
            "https://relay.example.com",
        );
        assert_ne!(h1, h2);
    }
}
