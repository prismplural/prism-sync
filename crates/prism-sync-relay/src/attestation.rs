use base64::Engine;
use sha2::{Digest, Sha256};
use x509_parser::oid_registry::Oid;
use x509_parser::prelude::*;

use crate::config::Config;

const ANDROID_KEY_ATTESTATION_EXTENSION_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17];
const ANDROID_ATTESTATION_CONTEXT: &[u8] = b"PRISM_SYNC_ANDROID_ATTEST_V1\x00";
const SECURITY_LEVEL_TRUSTED_ENVIRONMENT: i64 = 1;
const SECURITY_LEVEL_STRONGBOX: i64 = 2;
const VERIFIED_BOOT_STATE_VERIFIED: i64 = 0;
const VERIFIED_BOOT_STATE_SELF_SIGNED: i64 = 1;
const ROOT_OF_TRUST_TAG: u64 = 704;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FirstDeviceAdmissionKind {
    StockAndroid,
    GrapheneOs,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedAndroidAttestation {
    pub kind: FirstDeviceAdmissionKind,
    pub verified_boot_key: Vec<u8>,
}

pub(crate) fn compute_android_attestation_challenge(
    sync_id: &str,
    device_id: &str,
    nonce: &str,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ANDROID_ATTESTATION_CONTEXT);
    hasher.update(sync_id.as_bytes());
    hasher.update([0]);
    hasher.update(device_id.as_bytes());
    hasher.update([0]);
    hasher.update(nonce.as_bytes());
    hasher.finalize().into()
}

pub(crate) fn verify_android_key_attestation(
    sync_id: &str,
    device_id: &str,
    nonce: &str,
    certificate_chain: &[String],
    config: &Config,
) -> Result<VerifiedAndroidAttestation, String> {
    if !config.first_device_android_attestation_enabled {
        return Err("android attestation disabled".into());
    }
    if certificate_chain.len() < 2 {
        return Err("android attestation requires a certificate chain".into());
    }

    let certs = certificate_chain
        .iter()
        .map(|entry| decode_base64_der(entry))
        .collect::<Result<Vec<_>, _>>()?;
    let trusted_roots = config
        .first_device_android_attestation_trust_roots_pem
        .iter()
        .map(|pem| decode_pem_certificate(pem))
        .collect::<Result<Vec<_>, _>>()?;

    if !trusted_roots.iter().any(|root| certs.last() == Some(root)) {
        return Err("android attestation root is not trusted".into());
    }

    let mut parsed = Vec::with_capacity(certs.len());
    for cert_der in &certs {
        let (_, cert) = parse_x509_certificate(cert_der)
            .map_err(|e| format!("invalid attestation certificate: {e}"))?;
        parsed.push(cert);
    }

    for window in parsed.windows(2) {
        let cert = &window[0];
        let issuer = &window[1];
        cert.verify_signature(Some(issuer.public_key()))
            .map_err(|e| format!("invalid attestation certificate signature: {e}"))?;
    }
    parsed
        .last()
        .ok_or_else(|| "android attestation chain is empty".to_string())?
        .verify_signature(None)
        .map_err(|e| format!("invalid attestation root signature: {e}"))?;

    let expected_challenge = compute_android_attestation_challenge(sync_id, device_id, nonce);
    let extension_oid = Oid::from(ANDROID_KEY_ATTESTATION_EXTENSION_OID)
        .expect("android key attestation extension OID is valid");

    let leaf = parsed
        .first()
        .ok_or_else(|| "android attestation chain is empty".to_string())?;
    for cert in parsed.iter().skip(1) {
        if cert.extensions().iter().any(|ext| ext.oid == extension_oid) {
            return Err(
                "android attestation extension must only appear in the leaf certificate".into(),
            );
        }
    }
    let extension_value = leaf
        .extensions()
        .iter()
        .find(|ext| ext.oid == extension_oid)
        .map(|ext| ext.value.to_vec())
        .ok_or_else(|| "android attestation extension missing".to_string())?;

    let description = parse_android_key_description(&extension_value)?;
    if description.attestation_challenge != expected_challenge {
        return Err("android attestation challenge mismatch".into());
    }
    if !matches!(
        description.attestation_security_level,
        SECURITY_LEVEL_TRUSTED_ENVIRONMENT | SECURITY_LEVEL_STRONGBOX
    ) {
        return Err("android attestation is not hardware-backed".into());
    }
    if !matches!(
        description.keymaster_security_level,
        SECURITY_LEVEL_TRUSTED_ENVIRONMENT | SECURITY_LEVEL_STRONGBOX
    ) {
        return Err("android attestation keymaster is not hardware-backed".into());
    }
    if !description.root_of_trust.device_locked {
        return Err("android attestation device is unlocked".into());
    }
    let is_graphene = config
        .grapheneos_verified_boot_key_allowlist
        .iter()
        .any(|entry| {
            hex::decode(entry)
                .map(|bytes| bytes == description.root_of_trust.verified_boot_key)
                .unwrap_or(false)
        });

    let admission_kind = match description.root_of_trust.verified_boot_state {
        VERIFIED_BOOT_STATE_VERIFIED => Some(FirstDeviceAdmissionKind::StockAndroid),
        VERIFIED_BOOT_STATE_SELF_SIGNED if is_graphene => {
            Some(FirstDeviceAdmissionKind::GrapheneOs)
        }
        VERIFIED_BOOT_STATE_SELF_SIGNED => {
            return Err("android attestation self-signed boot key is not allowlisted".into());
        }
        _ => None,
    }
    .ok_or_else(|| "android attestation device is not in verified boot state".to_string())?;

    Ok(VerifiedAndroidAttestation {
        kind: admission_kind,
        verified_boot_key: description.root_of_trust.verified_boot_key,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AndroidKeyDescription {
    attestation_security_level: i64,
    keymaster_security_level: i64,
    attestation_challenge: [u8; 32],
    root_of_trust: RootOfTrust,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RootOfTrust {
    verified_boot_key: Vec<u8>,
    device_locked: bool,
    verified_boot_state: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DerClass {
    Universal,
    Application,
    ContextSpecific,
    Private,
}

#[derive(Clone, Copy, Debug)]
struct DerTlv<'a> {
    class: DerClass,
    constructed: bool,
    tag: u64,
    value: &'a [u8],
}

fn parse_android_key_description(input: &[u8]) -> Result<AndroidKeyDescription, String> {
    let sequence = parse_sequence_exact(input, "android attestation key description")?;
    if sequence.len() < 8 {
        return Err("android attestation key description is truncated".into());
    }

    let attestation_security_level = read_integer(&sequence[1])?;
    let keymaster_security_level = read_integer(&sequence[3])?;
    let attestation_challenge = read_octet_string_fixed::<32>(&sequence[4])?;
    let hardware_enforced =
        expect_sequence_contents(&sequence[7], "android attestation hardwareEnforced")?;
    let root_of_trust = parse_root_of_trust(hardware_enforced)?;

    Ok(AndroidKeyDescription {
        attestation_security_level,
        keymaster_security_level,
        attestation_challenge,
        root_of_trust,
    })
}

fn parse_root_of_trust(items: Vec<DerTlv<'_>>) -> Result<RootOfTrust, String> {
    let root = items
        .iter()
        .find(|item| {
            item.class == DerClass::ContextSpecific
                && item.constructed
                && item.tag == ROOT_OF_TRUST_TAG
        })
        .ok_or_else(|| "android attestation rootOfTrust missing".to_string())?;
    let fields = parse_explicit_sequence_contents(root, "android attestation rootOfTrust")?;
    if fields.len() < 3 {
        return Err("android attestation rootOfTrust is truncated".into());
    }

    Ok(RootOfTrust {
        verified_boot_key: read_octet_string(&fields[0])?,
        device_locked: read_boolean(&fields[1])?,
        verified_boot_state: read_integer(&fields[2])?,
    })
}

fn parse_sequence_exact<'a>(input: &'a [u8], label: &str) -> Result<Vec<DerTlv<'a>>, String> {
    let sequence = parse_exact_tlv(input, label)?;
    expect_sequence_contents(&sequence, label)
}

fn parse_explicit_sequence_contents<'a>(
    tlv: &DerTlv<'a>,
    label: &str,
) -> Result<Vec<DerTlv<'a>>, String> {
    if !tlv.constructed {
        return Err(format!("{label} is not explicitly tagged"));
    }
    let inner = parse_exact_tlv(tlv.value, label)?;
    expect_sequence_contents(&inner, label)
}

fn expect_sequence_contents<'a>(tlv: &DerTlv<'a>, label: &str) -> Result<Vec<DerTlv<'a>>, String> {
    if tlv.class != DerClass::Universal || tlv.tag != 16 {
        return Err(format!("{label} is not a sequence"));
    }
    parse_sequence_contents(tlv.value, label)
}

fn parse_sequence_contents<'a>(
    mut input: &'a [u8],
    label: &str,
) -> Result<Vec<DerTlv<'a>>, String> {
    let mut items = Vec::new();
    while !input.is_empty() {
        let (item, rest) = parse_tlv(input, label)?;
        items.push(item);
        input = rest;
    }
    Ok(items)
}

fn parse_exact_tlv<'a>(input: &'a [u8], label: &str) -> Result<DerTlv<'a>, String> {
    let (tlv, rest) = parse_tlv(input, label)?;
    if !rest.is_empty() {
        return Err(format!("{label} has trailing bytes"));
    }
    Ok(tlv)
}

fn parse_tlv<'a>(input: &'a [u8], label: &str) -> Result<(DerTlv<'a>, &'a [u8]), String> {
    if input.is_empty() {
        return Err(format!("invalid {label} DER: encountered empty buffer"));
    }

    let (class, constructed, tag, mut offset) = parse_identifier(input, label)?;
    let (length, length_len) = parse_length(
        input
            .get(offset..)
            .ok_or_else(|| format!("invalid {label} DER: truncated length"))?,
        label,
    )?;
    offset += length_len;
    let end = offset
        .checked_add(length)
        .ok_or_else(|| format!("invalid {label} DER: length overflow"))?;
    if end > input.len() {
        return Err(format!("invalid {label} DER: truncated value"));
    }

    Ok((
        DerTlv {
            class,
            constructed,
            tag,
            value: &input[offset..end],
        },
        &input[end..],
    ))
}

fn parse_identifier(input: &[u8], label: &str) -> Result<(DerClass, bool, u64, usize), String> {
    let first = *input
        .first()
        .ok_or_else(|| format!("invalid {label} DER: missing identifier"))?;
    let class = match first >> 6 {
        0 => DerClass::Universal,
        1 => DerClass::Application,
        2 => DerClass::ContextSpecific,
        _ => DerClass::Private,
    };
    let constructed = first & 0b0010_0000 != 0;
    let initial_tag = (first & 0b0001_1111) as u64;
    if initial_tag != 0b0001_1111 {
        return Ok((class, constructed, initial_tag, 1));
    }

    let mut tag = 0u64;
    let mut index = 1usize;
    loop {
        let byte = *input
            .get(index)
            .ok_or_else(|| format!("invalid {label} DER: truncated high-tag number"))?;
        tag = tag
            .checked_mul(128)
            .and_then(|value| value.checked_add((byte & 0x7f) as u64))
            .ok_or_else(|| format!("invalid {label} DER: tag overflow"))?;
        index += 1;
        if byte & 0x80 == 0 {
            break;
        }
    }
    Ok((class, constructed, tag, index))
}

fn parse_length(input: &[u8], label: &str) -> Result<(usize, usize), String> {
    let first = *input
        .first()
        .ok_or_else(|| format!("invalid {label} DER: missing length"))?;
    if first & 0x80 == 0 {
        return Ok((first as usize, 1));
    }

    let length_len = (first & 0x7f) as usize;
    if length_len == 0 {
        return Err(format!(
            "invalid {label} DER: indefinite lengths are unsupported"
        ));
    }
    let bytes = input
        .get(1..1 + length_len)
        .ok_or_else(|| format!("invalid {label} DER: truncated length"))?;
    let mut length = 0usize;
    for byte in bytes {
        length = length
            .checked_mul(256)
            .and_then(|value| value.checked_add(*byte as usize))
            .ok_or_else(|| format!("invalid {label} DER: length overflow"))?;
    }
    Ok((length, 1 + length_len))
}

fn read_integer(block: &DerTlv<'_>) -> Result<i64, String> {
    if block.class != DerClass::Universal || block.tag != 2 {
        return Err("android attestation expected integer".into());
    }
    let mut bytes = block.value;
    if bytes.is_empty() {
        return Err("android attestation expected integer".into());
    }
    if bytes[0] & 0x80 != 0 {
        return Err("android attestation negative integer is unsupported".into());
    }
    if bytes.len() > 1 && bytes[0] == 0 {
        bytes = &bytes[1..];
    }
    if bytes.len() > 8 {
        return Err("android attestation integer out of range".into());
    }

    let mut value = 0i64;
    for byte in bytes {
        value = value
            .checked_mul(256)
            .and_then(|current| current.checked_add(*byte as i64))
            .ok_or_else(|| "android attestation integer out of range".to_string())?;
    }
    Ok(value)
}

fn read_boolean(block: &DerTlv<'_>) -> Result<bool, String> {
    if block.class != DerClass::Universal || block.tag != 1 || block.value.len() != 1 {
        return Err("android attestation expected boolean".into());
    }
    Ok(block.value[0] != 0)
}

fn read_octet_string(block: &DerTlv<'_>) -> Result<Vec<u8>, String> {
    if block.class != DerClass::Universal || block.tag != 4 {
        return Err("android attestation expected octet string".into());
    }
    Ok(block.value.to_vec())
}

fn read_octet_string_fixed<const N: usize>(block: &DerTlv<'_>) -> Result<[u8; N], String> {
    let bytes = read_octet_string(block)?;
    bytes
        .try_into()
        .map_err(|_| "android attestation challenge has invalid length".into())
}

fn decode_base64_der(value: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|e| format!("invalid base64 attestation certificate: {e}"))
}

fn decode_pem_certificate(pem: &str) -> Result<Vec<u8>, String> {
    let body = pem
        .lines()
        .filter(|line| !line.starts_with("-----BEGIN") && !line.starts_with("-----END"))
        .collect::<String>();
    base64::engine::general_purpose::STANDARD
        .decode(body)
        .map_err(|e| format!("invalid PEM trust anchor: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use rcgen::{CertificateParams, CustomExtension, IsCa, KeyPair};

    fn encode_der(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    fn make_test_root() -> (rcgen::Certificate, KeyPair) {
        let mut params = CertificateParams::new(vec!["Key Attestation CA".into()]).unwrap();
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let key_pair = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        (cert, key_pair)
    }

    fn build_attestation_extension(
        challenge: [u8; 32],
        verified_boot_key: &[u8],
        verified_boot_state: i64,
    ) -> Vec<u8> {
        use simple_asn1::{to_der, ASN1Block, ASN1Class, BigInt};

        let root = ASN1Block::Sequence(
            0,
            vec![
                ASN1Block::OctetString(0, verified_boot_key.to_vec()),
                ASN1Block::Boolean(0, true),
                ASN1Block::Integer(0, BigInt::from(verified_boot_state)),
                ASN1Block::OctetString(0, vec![0u8; 32]),
            ],
        );
        let auth_list = ASN1Block::Sequence(
            0,
            vec![ASN1Block::Explicit(
                ASN1Class::ContextSpecific,
                0,
                ROOT_OF_TRUST_TAG.into(),
                Box::new(root),
            )],
        );
        let key_description = ASN1Block::Sequence(
            0,
            vec![
                ASN1Block::Integer(0, BigInt::from(3)),
                ASN1Block::Integer(0, BigInt::from(SECURITY_LEVEL_TRUSTED_ENVIRONMENT)),
                ASN1Block::Integer(0, BigInt::from(4)),
                ASN1Block::Integer(0, BigInt::from(SECURITY_LEVEL_TRUSTED_ENVIRONMENT)),
                ASN1Block::OctetString(0, challenge.to_vec()),
                ASN1Block::OctetString(0, vec![]),
                ASN1Block::Sequence(0, vec![]),
                auth_list,
            ],
        );
        to_der(&key_description).unwrap()
    }

    fn test_config(root_pem: String, grapheneos_keys: Vec<String>) -> Config {
        Config {
            port: 0,
            db_path: ":memory:".into(),
            invite_ttl_secs: 86400,
            sync_inactive_ttl_secs: 7_776_000,
            stale_device_secs: 2_592_000,
            cleanup_interval_secs: 3600,
            max_unpruned_batches: 10_000,
            metrics_token: None,
            session_expiry_secs: 3600,
            nonce_expiry_secs: 60,
            first_device_pow_difficulty_bits: 8,
            nonce_rate_limit: 100,
            nonce_rate_window_secs: 60,
            revoke_rate_limit: 100,
            revoke_rate_window_secs: 60,
            signed_request_max_skew_secs: 60,
            signed_request_nonce_window_secs: 120,
            snapshot_default_ttl_secs: 86400,
            revoked_tombstone_retention_secs: 2_592_000,
            reader_pool_size: 2,
            node_exporter_url: None,
            first_device_apple_attestation_enabled: true,
            first_device_apple_attestation_trust_roots_pem: vec![root_pem.clone()],
            first_device_apple_attestation_allowed_app_ids: vec![
                "TEAMID.com.prism.prism_plurality".into(),
            ],
            first_device_android_attestation_enabled: true,
            first_device_android_attestation_trust_roots_pem: vec![root_pem],
            grapheneos_verified_boot_key_allowlist: grapheneos_keys,
            registration_token: None,
            registration_enabled: true,
        }
    }

    #[test]
    fn parse_android_key_description_extracts_root_of_trust() {
        let challenge = compute_android_attestation_challenge("sync", "device", "nonce");
        let description = parse_android_key_description(&build_attestation_extension(
            challenge,
            &[0x42; 32],
            VERIFIED_BOOT_STATE_VERIFIED,
        ))
        .unwrap();

        assert_eq!(description.attestation_challenge, challenge);
        assert_eq!(description.root_of_trust.verified_boot_key, vec![0x42; 32]);
        assert!(description.root_of_trust.device_locked);
        assert_eq!(
            description.root_of_trust.verified_boot_state,
            VERIFIED_BOOT_STATE_VERIFIED
        );
    }

    #[test]
    fn verify_android_key_attestation_accepts_graphene_allowlisted_boot_key() {
        let challenge = compute_android_attestation_challenge("sync", "device", "nonce");
        let verified_boot_key = vec![0xAA; 32];
        let (root_cert, root_key) = make_test_root();

        let mut leaf_params = CertificateParams::new(vec!["leaf".into()]).unwrap();
        leaf_params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                ANDROID_KEY_ATTESTATION_EXTENSION_OID,
                build_attestation_extension(
                    challenge,
                    &verified_boot_key,
                    VERIFIED_BOOT_STATE_SELF_SIGNED,
                ),
            ));
        let leaf_key = KeyPair::generate().unwrap();
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &root_cert, &root_key)
            .unwrap();

        let result = verify_android_key_attestation(
            "sync",
            "device",
            "nonce",
            &[encode_der(leaf_cert.der()), encode_der(root_cert.der())],
            &test_config(root_cert.pem(), vec![hex::encode(&verified_boot_key)]),
        )
        .unwrap();

        assert_eq!(result.kind, FirstDeviceAdmissionKind::GrapheneOs);
    }

    #[test]
    fn verify_android_key_attestation_rejects_challenge_mismatch() {
        let (root_cert, root_key) = make_test_root();
        let mut leaf_params = CertificateParams::new(vec!["leaf".into()]).unwrap();
        leaf_params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                ANDROID_KEY_ATTESTATION_EXTENSION_OID,
                build_attestation_extension([0x11; 32], &[0x22; 32], VERIFIED_BOOT_STATE_VERIFIED),
            ));
        let leaf_key = KeyPair::generate().unwrap();
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &root_cert, &root_key)
            .unwrap();

        let err = verify_android_key_attestation(
            "sync",
            "device",
            "nonce",
            &[encode_der(leaf_cert.der()), encode_der(root_cert.der())],
            &test_config(root_cert.pem(), vec![]),
        )
        .unwrap_err();

        assert!(err.contains("challenge mismatch"));
    }

    #[test]
    fn verify_android_key_attestation_rejects_extension_in_root_certificate() {
        let challenge = compute_android_attestation_challenge("sync", "device", "nonce");
        let verified_boot_key = vec![0xBB; 32];
        let mut root_params = CertificateParams::new(vec!["Key Attestation CA".into()]).unwrap();
        root_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        root_params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                ANDROID_KEY_ATTESTATION_EXTENSION_OID,
                build_attestation_extension(
                    challenge,
                    &verified_boot_key,
                    VERIFIED_BOOT_STATE_VERIFIED,
                ),
            ));
        let root_key = KeyPair::generate().unwrap();
        let root_cert = root_params.self_signed(&root_key).unwrap();

        let leaf_params = CertificateParams::new(vec!["leaf".into()]).unwrap();
        let leaf_key = KeyPair::generate().unwrap();
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &root_cert, &root_key)
            .unwrap();

        let err = verify_android_key_attestation(
            "sync",
            "device",
            "nonce",
            &[encode_der(leaf_cert.der()), encode_der(root_cert.der())],
            &test_config(root_cert.pem(), vec![]),
        )
        .unwrap_err();

        assert!(err.contains("extension must only appear"));
    }
}
