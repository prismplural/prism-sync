use sha2::{Digest, Sha256};

const REGISTRATION_KEY_BUNDLE_CONTEXT: &[u8] = b"PRISM_SYNC_REGISTRATION_KEY_BUNDLE_V1\x00";

pub(crate) fn compute_registration_key_bundle_hash(
    signing_pk: &[u8],
    x25519_pk: &[u8],
    ml_dsa_pk: &[u8],
    ml_kem_pk: &[u8],
    xwing_pk: &[u8],
) -> [u8; 32] {
    fn write_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
        hasher.update((bytes.len() as u32).to_be_bytes());
        hasher.update(bytes);
    }

    let mut hasher = Sha256::new();
    hasher.update(REGISTRATION_KEY_BUNDLE_CONTEXT);
    write_len_prefixed(&mut hasher, signing_pk);
    write_len_prefixed(&mut hasher, x25519_pk);
    write_len_prefixed(&mut hasher, ml_dsa_pk);
    write_len_prefixed(&mut hasher, ml_kem_pk);
    write_len_prefixed(&mut hasher, xwing_pk);
    hasher.finalize().into()
}

pub(crate) fn compute_attestation_challenge(
    context: &[u8],
    sync_id: &str,
    device_id: &str,
    nonce: &str,
    registration_key_bundle_hash: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(context);
    hasher.update(sync_id.as_bytes());
    hasher.update([0]);
    hasher.update(device_id.as_bytes());
    hasher.update([0]);
    hasher.update(nonce.as_bytes());
    hasher.update([0]);
    hasher.update(registration_key_bundle_hash);
    hasher.finalize().into()
}
