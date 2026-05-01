use base64::Engine;
use ciborium::Value;
use sha2::{Digest, Sha256};
use simple_asn1::{from_der, ASN1Block};
use std::collections::HashSet;
use std::io::Cursor;
use x509_parser::oid_registry::Oid;
use x509_parser::prelude::*;

use crate::config::Config;
use crate::registration_binding;

const APPLE_APP_ATTESTATION_EXTENSION_OID: &[u64] = &[1, 2, 840, 113635, 100, 8, 2];
const APPLE_APP_ATTESTATION_CONTEXT: &[u8] = b"PRISM_SYNC_APPLE_APP_ATTEST_V2\x00";
const APPLE_APP_ATTESTATION_FMT: &str = "apple-appattest";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FirstDeviceAdmissionKind {
    AppleAppAttest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedAppleAttestation {
    pub kind: FirstDeviceAdmissionKind,
    pub matched_app_id: Option<String>,
    pub key_id: String,
}

pub(crate) fn compute_apple_attestation_challenge(
    sync_id: &str,
    device_id: &str,
    nonce: &str,
    registration_key_bundle_hash: &[u8; 32],
) -> [u8; 32] {
    registration_binding::compute_attestation_challenge(
        APPLE_APP_ATTESTATION_CONTEXT,
        sync_id,
        device_id,
        nonce,
        registration_key_bundle_hash,
    )
}

pub(crate) fn verify_apple_app_attest(
    sync_id: &str,
    device_id: &str,
    nonce: &str,
    registration_key_bundle_hash: &[u8; 32],
    key_id: &str,
    attestation_object: &str,
    config: &Config,
) -> Result<VerifiedAppleAttestation, String> {
    if !config.first_device_apple_attestation_enabled {
        return Err("apple attestation disabled".into());
    }

    let expected_challenge = compute_apple_attestation_challenge(
        sync_id,
        device_id,
        nonce,
        registration_key_bundle_hash,
    );
    let attestation_bytes = decode_base64_der(attestation_object)?;
    let cbor_value = decode_attestation_cbor(&attestation_bytes)?;
    let attestation = parse_attestation_object(&cbor_value)?;
    if attestation.fmt != APPLE_APP_ATTESTATION_FMT {
        return Err("apple attestation fmt is not apple-appattest".into());
    }

    let expected_nonce = apple_certificate_nonce(&attestation.auth_data, &expected_challenge);

    let certs = attestation
        .certificate_chain
        .iter()
        .map(|entry| decode_base64_der(entry))
        .collect::<Result<Vec<_>, _>>()?;
    let trusted_roots = config
        .first_device_apple_attestation_trust_roots_pem
        .iter()
        .map(|pem| decode_pem_certificate(pem))
        .collect::<Result<Vec<_>, _>>()?;
    if certs.len() < 2 {
        return Err("apple attestation requires a certificate chain".into());
    }
    if !trusted_roots.iter().any(|root| certs.last() == Some(root)) {
        return Err("apple attestation root is not trusted".into());
    }

    let mut parsed = Vec::with_capacity(certs.len());
    for cert_der in &certs {
        let (_, cert) = parse_x509_certificate(cert_der)
            .map_err(|e| format!("invalid apple attestation certificate: {e}"))?;
        parsed.push(cert);
    }
    for window in parsed.windows(2) {
        let cert = &window[0];
        let issuer = &window[1];
        cert.verify_signature(Some(issuer.public_key()))
            .map_err(|e| format!("invalid apple attestation certificate signature: {e}"))?;
    }
    parsed
        .last()
        .ok_or_else(|| "apple attestation chain is empty".to_string())?
        .verify_signature(None)
        .map_err(|e| format!("invalid apple attestation root signature: {e}"))?;

    let leaf = parsed.first().ok_or_else(|| "apple attestation chain is empty".to_string())?;
    for cert in parsed.iter().skip(1) {
        if cert.extensions().iter().any(|ext| ext.oid == apple_extension_oid()) {
            return Err(
                "apple attestation extension must only appear in the leaf certificate".into()
            );
        }
    }
    let leaf_extension = leaf
        .extensions()
        .iter()
        .find(|ext| ext.oid == apple_extension_oid())
        .ok_or_else(|| "apple attestation extension missing".to_string())?;
    let extension_nonce = parse_apple_certificate_nonce(leaf_extension.value)?;
    if extension_nonce != expected_nonce {
        return Err("apple attestation challenge mismatch".into());
    }

    let matched_app_id = match_allowed_app_id(
        &attestation.auth_data,
        &config.first_device_apple_attestation_allowed_app_ids,
    )?;
    let credential_id = parse_credential_id(&attestation.auth_data)?;
    if !key_id_matches_credential_id(key_id, &credential_id) {
        return Err("apple attestation key_id mismatch".into());
    }

    Ok(VerifiedAppleAttestation {
        kind: FirstDeviceAdmissionKind::AppleAppAttest,
        matched_app_id,
        key_id: key_id.to_owned(),
    })
}

#[derive(Debug)]
struct ParsedAttestationObject {
    fmt: String,
    auth_data: Vec<u8>,
    certificate_chain: Vec<String>,
}

fn decode_attestation_cbor(bytes: &[u8]) -> Result<Value, String> {
    let mut cursor = Cursor::new(bytes);
    let value: Value = ciborium::de::from_reader(&mut cursor)
        .map_err(|e| format!("invalid apple attestation CBOR: {e}"))?;
    if cursor.position() != bytes.len() as u64 {
        return Err("invalid apple attestation CBOR: trailing data".into());
    }
    Ok(value)
}

fn parse_attestation_object(value: &Value) -> Result<ParsedAttestationObject, String> {
    let map = checked_text_key_map(value, "apple attestation object")?;

    let fmt = map
        .iter()
        .find_map(|(key, value)| match (key, value) {
            (Value::Text(name), Value::Text(fmt)) if name == "fmt" => Some(fmt.clone()),
            _ => None,
        })
        .ok_or_else(|| "apple attestation fmt missing".to_string())?;
    let auth_data = map
        .iter()
        .find_map(|(key, value)| match (key, value) {
            (Value::Text(name), Value::Bytes(bytes)) if name == "authData" => Some(bytes.clone()),
            _ => None,
        })
        .ok_or_else(|| "apple attestation authData missing".to_string())?;
    let att_stmt = map
        .iter()
        .find_map(|(key, value)| match (key, value) {
            (Value::Text(name), value) if name == "attStmt" => Some(value),
            _ => None,
        })
        .ok_or_else(|| "apple attestation attStmt missing".to_string())?;
    let att_stmt = checked_text_key_map(att_stmt, "apple attestation attStmt")?;
    let certificate_chain = att_stmt
        .iter()
        .find_map(|(key, value)| match (key, value) {
            (Value::Text(name), Value::Array(certs)) if name == "x5c" => Some(certs),
            _ => None,
        })
        .ok_or_else(|| "apple attestation x5c missing".to_string())?
        .iter()
        .map(|value| match value {
            Value::Bytes(bytes) => Ok(base64::engine::general_purpose::STANDARD.encode(bytes)),
            _ => Err("apple attestation x5c entries must be byte strings".to_string()),
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(ParsedAttestationObject { fmt, auth_data, certificate_chain })
}

fn checked_text_key_map<'a>(
    value: &'a Value,
    context: &str,
) -> Result<&'a Vec<(Value, Value)>, String> {
    let entries = match value {
        Value::Map(entries) => entries,
        _ => return Err(format!("{context} is not a CBOR map")),
    };

    let mut seen = HashSet::new();
    for (key, _) in entries {
        let Value::Text(name) = key else {
            return Err(format!("{context} contains non-text key"));
        };
        if !seen.insert(name.as_str()) {
            return Err(format!("{context} contains duplicate key {name}"));
        }
    }

    Ok(entries)
}

fn apple_certificate_nonce(auth_data: &[u8], client_data_hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(auth_data);
    hasher.update(client_data_hash);
    hasher.finalize().into()
}

fn match_allowed_app_id(
    auth_data: &[u8],
    allowed_app_ids: &[String],
) -> Result<Option<String>, String> {
    if allowed_app_ids.is_empty() {
        return Ok(None);
    }

    let rp_id_hash = parse_rp_id_hash(auth_data)?;
    allowed_app_ids
        .iter()
        .find(|app_id| Sha256::digest(app_id.as_bytes()).as_slice() == rp_id_hash)
        .cloned()
        .map(Some)
        .ok_or_else(|| "apple attestation app_id is not allowlisted".to_string())
}

fn parse_rp_id_hash(auth_data: &[u8]) -> Result<&[u8], String> {
    auth_data.get(..32).ok_or_else(|| "apple authData truncated".to_string())
}

fn parse_credential_id(auth_data: &[u8]) -> Result<Vec<u8>, String> {
    if auth_data.len() < 37 {
        return Err("apple authData truncated".into());
    }
    let flags = auth_data[32];
    if flags & 0x40 == 0 {
        return Err("apple authData missing attested credential data".into());
    }

    let mut offset = 37;
    if auth_data.len() < offset + 16 + 2 {
        return Err("apple authData truncated".into());
    }
    offset += 16;
    let credential_len = u16::from_be_bytes([auth_data[offset], auth_data[offset + 1]]) as usize;
    offset += 2;
    let end = offset
        .checked_add(credential_len)
        .ok_or_else(|| "apple authData credential length overflow".to_string())?;
    if auth_data.len() < end {
        return Err("apple authData credential id truncated".into());
    }
    Ok(auth_data[offset..end].to_vec())
}

fn key_id_matches_credential_id(key_id: &str, credential_id: &[u8]) -> bool {
    decode_apple_key_id_candidates(key_id)
        .iter()
        .any(|candidate| candidate.as_slice() == credential_id)
}

fn decode_apple_key_id_candidates(key_id: &str) -> Vec<Vec<u8>> {
    let trimmed = key_id.trim();
    let mut candidates = Vec::new();

    if let Ok(bytes) = hex::decode(trimmed) {
        candidates.push(bytes);
    }

    for engine in [
        &base64::engine::general_purpose::STANDARD,
        &base64::engine::general_purpose::STANDARD_NO_PAD,
        &base64::engine::general_purpose::URL_SAFE,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ] {
        if let Ok(bytes) = engine.decode(trimmed) {
            candidates.push(bytes);
        }
    }

    candidates.push(trimmed.as_bytes().to_vec());
    candidates
}

fn decode_base64_der(value: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|e| format!("invalid base64 apple attestation value: {e}"))
}

fn parse_apple_certificate_nonce(input: &[u8]) -> Result<[u8; 32], String> {
    let blocks =
        from_der(input).map_err(|e| format!("invalid apple attestation extension DER: {e}"))?;
    let sequence = match blocks.first() {
        Some(ASN1Block::Sequence(_, items)) => items,
        _ => return Err("apple attestation extension is not a sequence".into()),
    };
    if sequence.len() != 1 {
        return Err("apple attestation extension has unexpected shape".into());
    }
    let nonce = match &sequence[0] {
        ASN1Block::OctetString(_, bytes) => bytes.clone(),
        _ => return Err("apple attestation extension nonce is not an octet string".into()),
    };
    nonce.try_into().map_err(|_| "apple attestation extension nonce has invalid length".into())
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

fn apple_extension_oid() -> Oid<'static> {
    Oid::from(APPLE_APP_ATTESTATION_EXTENSION_OID)
        .expect("apple app attestation extension OID is valid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use rcgen::{CertificateParams, CustomExtension, IsCa, KeyPair};

    fn make_test_root() -> (rcgen::Certificate, KeyPair) {
        let mut params = CertificateParams::new(vec!["Apple App Attest CA".into()]).unwrap();
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let key_pair = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        (cert, key_pair)
    }

    fn build_auth_data(app_id: &str, credential_id: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&Sha256::digest(app_id.as_bytes()));
        data.push(0x41);
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&[0u8; 16]);
        data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
        data.extend_from_slice(credential_id);
        data.extend_from_slice(&[0u8; 65]);
        data
    }

    fn build_apple_app_attest(key_id: &[u8], attestation_object: Vec<u8>) -> (String, String) {
        (
            base64::engine::general_purpose::STANDARD.encode(key_id),
            base64::engine::general_purpose::STANDARD.encode(attestation_object),
        )
    }

    fn minimal_attestation_value() -> Value {
        Value::Map(vec![
            (Value::Text("fmt".into()), Value::Text(APPLE_APP_ATTESTATION_FMT.into())),
            (Value::Text("authData".into()), Value::Bytes(vec![0; 37])),
            (
                Value::Text("attStmt".into()),
                Value::Map(vec![(Value::Text("x5c".into()), Value::Array(vec![]))]),
            ),
        ])
    }

    fn encode_cbor(value: &Value) -> Vec<u8> {
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(value, &mut encoded).unwrap();
        encoded
    }

    fn test_config(root_pem: String, allowed_app_ids: Vec<String>) -> Config {
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
            ws_upgrade_rate_limit: 20,
            ws_upgrade_rate_window_secs: 60,
            trusted_proxy_cidrs: vec![],
            signed_request_max_skew_secs: 60,
            signed_request_nonce_window_secs: 120,
            snapshot_default_ttl_secs: 86400,
            revoked_tombstone_retention_secs: 2_592_000,
            reader_pool_size: 2,
            node_exporter_url: None,
            first_device_apple_attestation_enabled: true,
            first_device_apple_attestation_trust_roots_pem: vec![root_pem],
            first_device_apple_attestation_allowed_app_ids: allowed_app_ids,
            first_device_android_attestation_enabled: true,
            first_device_android_attestation_trust_roots_pem: vec![],
            grapheneos_verified_boot_key_allowlist: vec![],
            registration_token: None,
            registration_enabled: true,
            pairing_session_ttl_secs: 300,
            pairing_session_rate_limit: 5,
            pairing_session_max_payload_bytes: 32768,
            sharing_init_ttl_secs: 604800,
            sharing_init_max_payload_bytes: 65536,
            sharing_identity_max_bytes: 8192,
            sharing_prekey_max_bytes: 4096,
            sharing_fetch_rate_limit: 100,
            sharing_init_rate_limit: 100,
            sharing_init_max_pending: 50,
            prekey_upload_max_age_secs: 604800,
            prekey_serve_max_age_secs: 2_592_000,
            prekey_max_future_skew_secs: 300,
            min_signature_version: 3,
            media_storage_path: "data/media".into(),
            media_max_file_bytes: 10_485_760,
            media_quota_bytes_per_group: 1_073_741_824,
            media_retention_days: 90,
            media_upload_rate_limit: 100,
            media_upload_rate_window_secs: 60,
            media_orphan_cleanup_secs: 86400,
            gif_provider_mode: crate::config::GifProviderMode::Disabled,
            gif_public_base_url: None,
            gif_prism_base_url: None,
            gif_api_base_url: "https://api.klipy.com".into(),
            gif_api_key: None,
            gif_http_timeout_secs: 15,
            gif_request_rate_limit: 20,
            gif_request_rate_window_secs: 60,
            gif_query_max_len: 200,
        }
    }

    #[test]
    fn verify_apple_app_attest_accepts_valid_attestation() {
        let app_id = "TEAMID.com.prism.prism_plurality";
        let key_id = [0xAB; 16];
        let key_bundle_hash = [0x5A; 32];
        let challenge =
            compute_apple_attestation_challenge("sync", "device", "nonce", &key_bundle_hash);
        let auth_data = build_auth_data(app_id, &key_id);
        let nonce = apple_certificate_nonce(&auth_data, &challenge);
        let (root_cert, root_key) = make_test_root();

        let mut leaf_params = CertificateParams::new(vec!["leaf".into()]).unwrap();
        leaf_params.custom_extensions.push(CustomExtension::from_oid_content(
            APPLE_APP_ATTESTATION_EXTENSION_OID,
            {
                use simple_asn1::{to_der, ASN1Block};
                to_der(&ASN1Block::Sequence(0, vec![ASN1Block::OctetString(0, nonce.to_vec())]))
                    .unwrap()
            },
        ));
        let leaf_key = KeyPair::generate().unwrap();
        let leaf_cert = leaf_params.signed_by(&leaf_key, &root_cert, &root_key).unwrap();

        let attestation_value = Value::Map(vec![
            (Value::Text("fmt".into()), Value::Text(APPLE_APP_ATTESTATION_FMT.into())),
            (Value::Text("authData".into()), Value::Bytes(auth_data)),
            (
                Value::Text("attStmt".into()),
                Value::Map(vec![(
                    Value::Text("x5c".into()),
                    Value::Array(vec![
                        Value::Bytes(leaf_cert.der().to_vec()),
                        Value::Bytes(root_cert.der().to_vec()),
                    ]),
                )]),
            ),
        ]);
        let mut attestation_object = Vec::new();
        ciborium::ser::into_writer(&attestation_value, &mut attestation_object).unwrap();

        let (key_id, attestation_object) = build_apple_app_attest(&key_id, attestation_object);
        let verified = verify_apple_app_attest(
            "sync",
            "device",
            "nonce",
            &key_bundle_hash,
            &key_id,
            &attestation_object,
            &test_config(root_cert.pem(), vec![app_id.to_string()]),
        )
        .unwrap();

        assert_eq!(verified.kind, FirstDeviceAdmissionKind::AppleAppAttest);
        assert_eq!(verified.matched_app_id.as_deref(), Some(app_id));
    }

    #[test]
    fn parse_attestation_object_rejects_duplicate_top_level_fmt() {
        let value = Value::Map(vec![
            (Value::Text("fmt".into()), Value::Text(APPLE_APP_ATTESTATION_FMT.into())),
            (Value::Text("fmt".into()), Value::Text("none".into())),
            (Value::Text("authData".into()), Value::Bytes(vec![0; 37])),
            (
                Value::Text("attStmt".into()),
                Value::Map(vec![(Value::Text("x5c".into()), Value::Array(vec![]))]),
            ),
        ]);

        let err = parse_attestation_object(&value).unwrap_err();

        assert!(err.contains("duplicate key fmt"), "{err}");
    }

    #[test]
    fn parse_attestation_object_rejects_duplicate_nested_x5c() {
        let value = Value::Map(vec![
            (Value::Text("fmt".into()), Value::Text(APPLE_APP_ATTESTATION_FMT.into())),
            (Value::Text("authData".into()), Value::Bytes(vec![0; 37])),
            (
                Value::Text("attStmt".into()),
                Value::Map(vec![
                    (Value::Text("x5c".into()), Value::Array(vec![])),
                    (Value::Text("x5c".into()), Value::Array(vec![])),
                ]),
            ),
        ]);

        let err = parse_attestation_object(&value).unwrap_err();

        assert!(err.contains("duplicate key x5c"), "{err}");
    }

    #[test]
    fn decode_attestation_cbor_rejects_trailing_bytes() {
        let mut encoded = encode_cbor(&minimal_attestation_value());
        encoded.push(0);

        let err = decode_attestation_cbor(&encoded).unwrap_err();

        assert!(err.contains("trailing data"), "{err}");
    }
}
