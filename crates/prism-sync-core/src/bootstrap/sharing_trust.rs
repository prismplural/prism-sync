//! Trust evaluation for sharing identity bundles.
//!
//! Implements Trust-On-First-Use (TOFU) with key-change detection for
//! peer sharing identities in the post-quantum sharing bootstrap protocol.

use super::{
    sharing_models::SharingIdentityBundle, BootstrapProfile, BootstrapVersion, PublicFingerprint,
};

/// Trust decision for a sharing identity evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustDecision {
    /// First contact or keys match the pinned identity. Safe to proceed.
    Accept,
    /// Keys differ from pinned identity, but the relationship was not previously
    /// verified. The app should show a warning but allow the user to accept.
    WarnKeyChange,
    /// Keys differ from pinned identity, and the relationship WAS previously
    /// verified. The app MUST block the operation and require re-verification.
    BlockKeyChange,
}

/// Trust decision that also distinguishes replayed older generations from a
/// normal identity rotation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenerationAwareTrustDecision {
    /// First contact or keys match the pinned identity. Safe to proceed.
    Accept,
    /// Keys differ from the pinned identity, but the relationship was not
    /// previously verified.
    WarnKeyChange,
    /// Keys differ from the pinned identity, and the relationship was
    /// previously verified.
    BlockKeyChange,
    /// The incoming identity claims the expected `sharing_id`, but its
    /// `identity_generation` is lower than the highest generation previously
    /// accepted for that `sharing_id`.
    RejectStaleGenerationReplay,
    /// The incoming identity does not claim the expected `sharing_id`.
    RejectSharingIdMismatch,
    /// The incoming identity bytes are malformed and could not be parsed.
    RejectMalformedIdentity,
}

/// Evaluate trust for a peer's sharing identity.
///
/// - `pinned_identity_bytes`: if `Some`, the previously pinned
///   `SharingIdentityBundle` canonical bytes. If `None`, this is a first
///   contact (TOFU).
/// - `new_identity_bytes`: the canonical bytes of the `SharingIdentityBundle`
///   being evaluated.
/// - `is_verified`: whether the pinned identity was explicitly verified
///   (SAS/QR).
///
/// Comparison uses the signed-content prefix of the canonical wire bytes
/// (version, sharing_id, identity_generation, ed25519_pk, ml_dsa_65_pk).
/// This deliberately includes `identity_generation` — a rotation that changes
/// keys but keeps `sharing_id` stable will be detected as a key change.
///
/// Parsing failures are treated as key changes (fail-closed).
pub fn evaluate_identity(
    pinned_identity_bytes: Option<&[u8]>,
    new_identity_bytes: &[u8],
    is_verified: bool,
) -> TrustDecision {
    match pinned_identity_bytes {
        None => TrustDecision::Accept, // first contact, TOFU
        Some(pinned) => {
            // Extract signed content from both bundles.
            // If parsing fails for either, treat as key change (fail-closed).
            let pinned_content = extract_signed_content(pinned);
            let new_content = extract_signed_content(new_identity_bytes);

            match (pinned_content, new_content) {
                (Some(p), Some(n)) if p == n => TrustDecision::Accept,
                (Some(_), Some(_)) => {
                    // Signed content differs — keys changed.
                    if is_verified {
                        TrustDecision::BlockKeyChange
                    } else {
                        TrustDecision::WarnKeyChange
                    }
                }
                _ => {
                    // Parsing failed for at least one bundle — fail-closed.
                    if is_verified {
                        TrustDecision::BlockKeyChange
                    } else {
                        TrustDecision::WarnKeyChange
                    }
                }
            }
        }
    }
}

/// Evaluate trust for a peer's sharing identity while enforcing a generation
/// floor for the expected `sharing_id`.
///
/// This is intended for call sites that track the highest previously accepted
/// `identity_generation` for each `sharing_id` and want to reject stale replay
/// attempts before classifying the identity as a normal key rotation.
///
/// The new identity is parsed and validated up front. If its claimed
/// `sharing_id` does not match `expected_sharing_id`, or if the wire encoding
/// is malformed, the identity is rejected immediately.
pub fn evaluate_identity_with_generation_floor(
    pinned_identity_bytes: Option<&[u8]>,
    new_identity_bytes: &[u8],
    expected_sharing_id: &str,
    highest_accepted_generation: Option<u32>,
    is_verified: bool,
) -> GenerationAwareTrustDecision {
    let metadata = match SharingIdentityBundle::parse_metadata(new_identity_bytes) {
        Some(metadata) => metadata,
        None => return GenerationAwareTrustDecision::RejectMalformedIdentity,
    };

    if metadata.sharing_id != expected_sharing_id {
        return GenerationAwareTrustDecision::RejectSharingIdMismatch;
    }

    if let Some(highest_generation) = highest_accepted_generation {
        if metadata.identity_generation < highest_generation {
            return GenerationAwareTrustDecision::RejectStaleGenerationReplay;
        }
    }

    match evaluate_identity(pinned_identity_bytes, new_identity_bytes, is_verified) {
        TrustDecision::Accept => GenerationAwareTrustDecision::Accept,
        TrustDecision::WarnKeyChange => GenerationAwareTrustDecision::WarnKeyChange,
        TrustDecision::BlockKeyChange => GenerationAwareTrustDecision::BlockKeyChange,
    }
}

/// Extract the signed-content prefix from a `SharingIdentityBundle`'s
/// canonical wire bytes.
///
/// Wire format:
/// ```text
/// [1B  version]
/// [2B  sharing_id_len BE][sharing_id UTF-8]
/// [4B  identity_generation BE]
/// [32B ed25519_public_key]
/// [2B  ml_dsa_65_pk_len BE][ml_dsa_65_public_key]
/// [4B  signature_len BE][signature]      ← excluded from signed content
/// ```
///
/// Returns the bytes before the trailing `[4B sig_len][sig]`, or `None` if
/// the format is invalid.
fn extract_signed_content(bundle_bytes: &[u8]) -> Option<&[u8]> {
    SharingIdentityBundle::signed_content_from_bytes(bundle_bytes)
}

/// Compute the public fingerprint for a `SharingIdentityBundle`.
///
/// Returns a 64-character lowercase hex string suitable for out-of-band
/// comparison. Uses [`PublicFingerprint`] with purpose
/// `"sharing_identity_bundle"`.
///
/// The fingerprint includes `identity_generation`, so a key rotation
/// produces a different fingerprint even for the same `sharing_id`.
pub fn compute_sharing_fingerprint(
    sharing_id: &str,
    identity_generation: u32,
    ed25519_public_key: &[u8; 32],
    ml_dsa_65_public_key: &[u8],
) -> String {
    let fp = PublicFingerprint::from_public_fields(
        BootstrapProfile::RemoteSharing,
        BootstrapVersion::V1,
        b"sharing_identity_bundle",
        &[
            (b"sharing_id", sharing_id.as_bytes()),
            (b"identity_generation", &identity_generation.to_be_bytes()),
            (b"ed25519_pk", ed25519_public_key),
            (b"ml_dsa_65_pk", ml_dsa_65_public_key),
        ],
    );
    fp.hex()
}

/// Compare two fingerprint strings for equality.
///
/// Fingerprints are public data displayed to users for out-of-band
/// verification, so timing side-channels are not a concern here.
pub fn compare_fingerprints(a: &str, b: &str) -> bool {
    a == b
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build minimal valid wire-format bytes for a `SharingIdentityBundle`.
    fn make_test_bundle_bytes(
        sharing_id: &str,
        generation: u32,
        ed25519_pk: &[u8; 32],
        ml_dsa_pk: &[u8],
    ) -> Vec<u8> {
        const TEST_ML_DSA_65_PK_LEN: usize = 1952;

        let mut buf = Vec::new();
        buf.push(1u8); // version V1
        let sid_bytes = sharing_id.as_bytes();
        buf.extend_from_slice(&(sid_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(sid_bytes);
        buf.extend_from_slice(&generation.to_be_bytes());
        buf.extend_from_slice(ed25519_pk);
        let mut normalized_ml_dsa_pk = vec![0u8; TEST_ML_DSA_65_PK_LEN];
        if !ml_dsa_pk.is_empty() {
            for (index, byte) in normalized_ml_dsa_pk.iter_mut().enumerate() {
                *byte = ml_dsa_pk[index % ml_dsa_pk.len()];
            }
        }
        buf.extend_from_slice(&(normalized_ml_dsa_pk.len() as u16).to_be_bytes());
        buf.extend_from_slice(&normalized_ml_dsa_pk);
        // Dummy signature (4B len + 64B dummy sig)
        let dummy_sig = vec![0xABu8; 64];
        buf.extend_from_slice(&(dummy_sig.len() as u32).to_be_bytes());
        buf.extend_from_slice(&dummy_sig);
        buf
    }

    // ── Trust evaluation tests ──────────────────────────────────────

    #[test]
    fn test_first_contact_accept() {
        let new_bytes = make_test_bundle_bytes("alice", 1, &[1u8; 32], &[2u8; 48]);
        assert_eq!(
            evaluate_identity(None, &new_bytes, false),
            TrustDecision::Accept
        );
    }

    #[test]
    fn test_same_keys_accept() {
        let bundle = make_test_bundle_bytes("alice", 1, &[1u8; 32], &[2u8; 48]);
        assert_eq!(
            evaluate_identity(Some(&bundle), &bundle, false),
            TrustDecision::Accept
        );
        assert_eq!(
            evaluate_identity(Some(&bundle), &bundle, true),
            TrustDecision::Accept
        );
    }

    #[test]
    fn test_changed_keys_unverified_warn() {
        let pinned = make_test_bundle_bytes("alice", 1, &[1u8; 32], &[2u8; 48]);
        let new = make_test_bundle_bytes("alice", 1, &[9u8; 32], &[2u8; 48]);
        assert_eq!(
            evaluate_identity(Some(&pinned), &new, false),
            TrustDecision::WarnKeyChange
        );
    }

    #[test]
    fn test_changed_keys_verified_block() {
        let pinned = make_test_bundle_bytes("alice", 1, &[1u8; 32], &[2u8; 48]);
        let new = make_test_bundle_bytes("alice", 1, &[9u8; 32], &[2u8; 48]);
        assert_eq!(
            evaluate_identity(Some(&pinned), &new, true),
            TrustDecision::BlockKeyChange
        );
    }

    #[test]
    fn test_generation_change_detected() {
        // Same keys but different generation — should be detected as change.
        let pinned = make_test_bundle_bytes("alice", 1, &[1u8; 32], &[2u8; 48]);
        let new = make_test_bundle_bytes("alice", 2, &[1u8; 32], &[2u8; 48]);
        assert_eq!(
            evaluate_identity(Some(&pinned), &new, false),
            TrustDecision::WarnKeyChange
        );
    }

    #[test]
    fn test_malformed_pinned_treated_as_change() {
        let garbage = vec![0xFF, 0x01]; // too short to parse
        let new = make_test_bundle_bytes("alice", 1, &[1u8; 32], &[2u8; 48]);
        // Unverified → Warn
        assert_eq!(
            evaluate_identity(Some(&garbage), &new, false),
            TrustDecision::WarnKeyChange
        );
        // Verified → Block
        assert_eq!(
            evaluate_identity(Some(&garbage), &new, true),
            TrustDecision::BlockKeyChange
        );
    }

    #[test]
    fn test_malformed_new_treated_as_change() {
        let pinned = make_test_bundle_bytes("alice", 1, &[1u8; 32], &[2u8; 48]);
        let garbage = vec![0xFF, 0x01];
        assert_eq!(
            evaluate_identity(Some(&pinned), &garbage, false),
            TrustDecision::WarnKeyChange
        );
        assert_eq!(
            evaluate_identity(Some(&pinned), &garbage, true),
            TrustDecision::BlockKeyChange
        );
    }

    #[test]
    fn test_different_signature_same_signed_content() {
        // Two bundles with same identity fields but different signatures
        // should be treated as the same identity (Accept).
        let bundle_a = make_test_bundle_bytes("alice", 1, &[1u8; 32], &[2u8; 48]);
        let mut bundle_b = bundle_a.clone();
        // Change the last byte of the signature in bundle_b
        let last = bundle_b.len() - 1;
        bundle_b[last] ^= 0xFF;
        assert_eq!(
            evaluate_identity(Some(&bundle_a), &bundle_b, true),
            TrustDecision::Accept
        );
    }

    #[test]
    fn test_generation_aware_stale_generation_rejected() {
        let pinned = make_test_bundle_bytes("alice", 2, &[1u8; 32], &[2u8; 48]);
        let stale = make_test_bundle_bytes("alice", 1, &[9u8; 32], &[8u8; 48]);

        assert_eq!(
            evaluate_identity_with_generation_floor(Some(&pinned), &stale, "alice", Some(2), false),
            GenerationAwareTrustDecision::RejectStaleGenerationReplay
        );
    }

    #[test]
    fn test_generation_aware_higher_generation_is_normal_key_change() {
        let pinned = make_test_bundle_bytes("alice", 1, &[1u8; 32], &[2u8; 48]);
        let rotated = make_test_bundle_bytes("alice", 2, &[9u8; 32], &[8u8; 48]);

        assert_eq!(
            evaluate_identity_with_generation_floor(
                Some(&pinned),
                &rotated,
                "alice",
                Some(1),
                false
            ),
            GenerationAwareTrustDecision::WarnKeyChange
        );
        assert_eq!(
            evaluate_identity_with_generation_floor(
                Some(&pinned),
                &rotated,
                "alice",
                Some(1),
                true
            ),
            GenerationAwareTrustDecision::BlockKeyChange
        );
    }

    #[test]
    fn test_generation_aware_sharing_id_mismatch_rejected() {
        let new = make_test_bundle_bytes("mallory", 1, &[1u8; 32], &[2u8; 48]);

        assert_eq!(
            evaluate_identity_with_generation_floor(None, &new, "alice", None, false),
            GenerationAwareTrustDecision::RejectSharingIdMismatch
        );
    }

    #[test]
    fn test_generation_aware_malformed_new_rejected() {
        let malformed = vec![0xFF, 0x01];

        assert_eq!(
            evaluate_identity_with_generation_floor(None, &malformed, "alice", None, false),
            GenerationAwareTrustDecision::RejectMalformedIdentity
        );
    }

    #[test]
    fn test_generation_aware_exact_match_still_accepts() {
        let bundle = make_test_bundle_bytes("alice", 2, &[1u8; 32], &[2u8; 48]);

        assert_eq!(
            evaluate_identity_with_generation_floor(Some(&bundle), &bundle, "alice", Some(2), true),
            GenerationAwareTrustDecision::Accept
        );
    }

    // ── extract_signed_content tests ────────────────────────────────

    #[test]
    fn test_extract_signed_content_valid() {
        let bundle = make_test_bundle_bytes("test-id", 42, &[3u8; 32], &[4u8; 100]);
        let content = extract_signed_content(&bundle).expect("should parse valid bundle");
        // Signed content = everything except the trailing [4B sig_len][64B sig]
        assert_eq!(content.len(), bundle.len() - 4 - 64);
    }

    #[test]
    fn test_extract_signed_content_empty() {
        assert!(extract_signed_content(&[]).is_none());
    }

    #[test]
    fn test_extract_signed_content_truncated() {
        // Just a version byte and partial sharing_id length
        assert!(extract_signed_content(&[1, 0]).is_none());
    }

    #[test]
    fn test_extract_signed_content_bad_sig_len() {
        // Build valid content but corrupt the total length so sig doesn't match
        let mut bundle = make_test_bundle_bytes("x", 1, &[0u8; 32], &[0u8; 10]);
        // Append extra byte to make the sig_len check fail
        bundle.push(0xFF);
        assert!(extract_signed_content(&bundle).is_none());
    }

    // ── Fingerprint tests ───────────────────────────────────────────

    #[test]
    fn test_fingerprint_determinism() {
        let fp1 = compute_sharing_fingerprint("alice", 1, &[1u8; 32], &[2u8; 48]);
        let fp2 = compute_sharing_fingerprint("alice", 1, &[1u8; 32], &[2u8; 48]);
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_fingerprint_changes_with_different_key() {
        let fp1 = compute_sharing_fingerprint("alice", 1, &[1u8; 32], &[2u8; 48]);
        let fp2 = compute_sharing_fingerprint("alice", 1, &[9u8; 32], &[2u8; 48]);
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_fingerprint_changes_with_different_generation() {
        let fp1 = compute_sharing_fingerprint("alice", 1, &[1u8; 32], &[2u8; 48]);
        let fp2 = compute_sharing_fingerprint("alice", 2, &[1u8; 32], &[2u8; 48]);
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_fingerprint_changes_with_different_sharing_id() {
        let fp1 = compute_sharing_fingerprint("alice", 1, &[1u8; 32], &[2u8; 48]);
        let fp2 = compute_sharing_fingerprint("bob", 1, &[1u8; 32], &[2u8; 48]);
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_fingerprint_length() {
        let fp = compute_sharing_fingerprint("alice", 1, &[1u8; 32], &[2u8; 48]);
        assert_eq!(fp.len(), 64);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_compare_fingerprints_equal() {
        let fp = compute_sharing_fingerprint("alice", 1, &[1u8; 32], &[2u8; 48]);
        assert!(compare_fingerprints(&fp, &fp));
    }

    #[test]
    fn test_compare_fingerprints_different() {
        let fp1 = compute_sharing_fingerprint("alice", 1, &[1u8; 32], &[2u8; 48]);
        let fp2 = compute_sharing_fingerprint("bob", 1, &[1u8; 32], &[2u8; 48]);
        assert!(!compare_fingerprints(&fp1, &fp2));
    }

    #[test]
    fn test_fingerprint_changes_with_different_ml_dsa_key() {
        let fp1 = compute_sharing_fingerprint("alice", 1, &[1u8; 32], &[2u8; 48]);
        let fp2 = compute_sharing_fingerprint("alice", 1, &[1u8; 32], &[9u8; 48]);
        assert_ne!(fp1, fp2);
    }
}
