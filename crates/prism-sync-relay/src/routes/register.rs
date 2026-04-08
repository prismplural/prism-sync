use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

use crate::{
    apple_attestation,
    attestation::{self, FirstDeviceAdmissionKind},
    auth, db,
    errors::AppError,
    state::AppState,
};

const POW_ALGORITHM: &str = "sha256_leading_zero_bits";

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/sync/{sync_id}/register-nonce", get(get_register_nonce))
        .route("/v1/sync/{sync_id}/register", post(register_device))
}

// ---------------------------------------------------------------------------
// GET /v1/sync/{sync_id}/register-nonce
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct NonceResponse {
    nonce: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pow_challenge: Option<PowChallenge>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PowChallenge {
    algorithm: String,
    difficulty_bits: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PowSolution {
    counter: u64,
}

async fn get_register_nonce(
    State(state): State<AppState>,
    Path(sync_id): Path<String>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    check_registration_access(&state, &headers)?;

    if !auth::is_valid_sync_id(&sync_id) {
        return Err(AppError::BadRequest("Invalid sync ID"));
    }

    let db = state.db.clone();
    let sid = sync_id.clone();
    let is_first_device = tokio::task::spawn_blocking(move || {
        db.with_conn(|conn| Ok(db::get_sync_group_epoch(conn, &sid)?.is_none()))
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| AppError::Internal(e.to_string()))?;

    if !state.nonce_rate_limiter.check(
        &sync_id,
        state.config.nonce_rate_limit,
        state.config.nonce_rate_window_secs,
    ) {
        return Err(AppError::TooManyRequests);
    }

    if is_first_device {
        if let Some(client_ip) = client_ip_key(&headers) {
            let limiter = &state.first_device_nonce_rate_limiter;
            let keys = ["global", client_ip.as_str()];
            if !limiter.check_many(
                &keys,
                state.config.first_device_nonce_rate_limit(),
                state.config.first_device_nonce_rate_window_secs(),
            ) {
                return Err(AppError::TooManyRequests);
            }
        }
    }

    let nonce_expiry = state.config.nonce_expiry_secs as i64;
    let first_device_pow_difficulty_bits = state.config.first_device_pow_difficulty_bits;
    let db = state.db.clone();
    let sid = sync_id.clone();

    let (nonce, pow_challenge) = tokio::task::spawn_blocking(move || {
        db.with_conn(|conn| {
            let nonce = db::create_nonce(conn, &sid, nonce_expiry)?;
            let pow_challenge = if first_device_pow_difficulty_bits > 0 {
                Some(PowChallenge {
                    algorithm: POW_ALGORITHM.to_string(),
                    difficulty_bits: first_device_pow_difficulty_bits,
                })
            } else {
                None
            };
            Ok((nonce, pow_challenge))
        })
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| AppError::Internal(e.to_string()))?;

    tracing::debug!(
        sync_id = %&sync_id[..16],
        has_pow_challenge = pow_challenge.is_some(),
        "Registration nonce issued"
    );

    Ok(axum::Json(NonceResponse {
        nonce,
        pow_challenge,
    }))
}

// ---------------------------------------------------------------------------
// POST /v1/sync/{sync_id}/register
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct RegisterRequest {
    device_id: String,
    signing_public_key: String,
    x25519_public_key: String,
    #[serde(default)]
    ml_dsa_65_public_key: String,
    #[serde(default)]
    ml_kem_768_public_key: String,
    registration_challenge: String,
    nonce: String,
    #[serde(default)]
    pow_solution: Option<PowSolution>,
    #[serde(default)]
    first_device_admission_proof: Option<FirstDeviceAdmissionProof>,
    #[serde(default)]
    registry_approval: Option<RegistryApproval>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum FirstDeviceAdmissionProof {
    AndroidKeyAttestation {
        certificate_chain: Vec<String>,
    },
    AppleAppAttest {
        key_id: String,
        attestation_object: String,
    },
}

#[derive(Deserialize, Clone)]
struct RegistryApproval {
    approver_device_id: String,
    approver_ed25519_pk: String,
    #[allow(dead_code)]
    #[serde(default)]
    approver_ml_dsa_65_pk: String,
    approval_signature: String,
    signed_registry_snapshot: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RegistrySnapshotEntry {
    sync_id: String,
    device_id: String,
    ed25519_public_key: Vec<u8>,
    x25519_public_key: Vec<u8>,
    #[serde(default)]
    ml_dsa_65_public_key: Vec<u8>,
    #[serde(default)]
    ml_kem_768_public_key: Vec<u8>,
    status: String,
}

#[derive(Serialize)]
struct RegisterResponse {
    device_session_token: String,
}

async fn register_device(
    State(state): State<AppState>,
    Path(sync_id): Path<String>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<RegisterRequest>,
) -> Result<impl IntoResponse, AppError> {
    check_registration_access(&state, &headers)?;

    if !auth::is_valid_sync_id(&sync_id) {
        return Err(AppError::BadRequest("Invalid sync ID"));
    }

    if !auth::is_valid_device_id(&body.device_id) {
        return Err(AppError::BadRequest("Invalid device_id"));
    }

    // Decode public keys from hex
    let signing_pk = hex::decode(&body.signing_public_key)
        .map_err(|_| AppError::BadRequest("Invalid signing_public_key hex"))?;
    if signing_pk.len() != 32 {
        return Err(AppError::BadRequest("signing_public_key must be 32 bytes"));
    }
    let x25519_pk = hex::decode(&body.x25519_public_key)
        .map_err(|_| AppError::BadRequest("Invalid x25519_public_key hex"))?;
    if x25519_pk.len() != 32 {
        return Err(AppError::BadRequest("x25519_public_key must be 32 bytes"));
    }
    let ml_dsa_pk = if body.ml_dsa_65_public_key.is_empty() {
        Vec::new()
    } else {
        let decoded = hex::decode(&body.ml_dsa_65_public_key)
            .map_err(|_| AppError::BadRequest("Invalid ml_dsa_65_public_key hex"))?;
        if decoded.len() != 1952 {
            return Err(AppError::BadRequest(
                "ml_dsa_65_public_key must be 1952 bytes",
            ));
        }
        decoded
    };
    let ml_kem_pk = if body.ml_kem_768_public_key.is_empty() {
        Vec::new()
    } else {
        let decoded = hex::decode(&body.ml_kem_768_public_key)
            .map_err(|_| AppError::BadRequest("Invalid ml_kem_768_public_key hex"))?;
        if decoded.len() != 1184 {
            return Err(AppError::BadRequest(
                "ml_kem_768_public_key must be 1184 bytes",
            ));
        }
        decoded
    };

    // Decode the challenge signature from hex
    let challenge_sig = hex::decode(&body.registration_challenge)
        .map_err(|_| AppError::BadRequest("Invalid registration_challenge hex"))?;

    tracing::debug!(
        sync_id = %&sync_id[..16],
        device_id = %&body.device_id[..8.min(body.device_id.len())],
        has_registry_approval = body.registry_approval.is_some(),
        "Register request"
    );

    // ML-DSA-65 public key is now required for registration
    if ml_dsa_pk.is_empty() {
        return Err(AppError::BadRequest("ML-DSA-65 public key is required"));
    }

    // Verify hybrid challenge signature (V2/V3)
    if !auth::verify_hybrid_challenge(
        &signing_pk,
        &ml_dsa_pk,
        &sync_id,
        &body.device_id,
        &body.nonce,
        &challenge_sig,
    ) {
        tracing::warn!(
            sync_id = %&sync_id[..16],
            device_id = %&body.device_id[..8.min(body.device_id.len())],
            has_pq_keys = !ml_dsa_pk.is_empty(),
            "Registration rejected: challenge verification failed"
        );
        return Err(AppError::Unauthorized);
    }

    let db = state.db.clone();
    let session_expiry = state.config.session_expiry_secs as i64;
    let sid = sync_id.clone();
    let device_id = body.device_id.clone();
    let nonce = body.nonce.clone();
    let pow_solution = body.pow_solution.clone();
    let first_device_admission_proof = body.first_device_admission_proof.clone();
    let registry_approval = body.registry_approval.clone();
    let first_device_pow_difficulty_bits = state.config.first_device_pow_difficulty_bits;
    let client_ip = client_ip_key(&headers);
    let first_device_registration_rate_limit = state.config.first_device_registration_rate_limit();
    let first_device_registration_rate_window_secs =
        state.config.first_device_registration_rate_window_secs();
    let first_device_group_rate_limit = state.config.first_device_group_rate_limit();
    let first_device_group_rate_window_secs = state.config.first_device_group_rate_window_secs();
    let first_device_registration_limiter = state.first_device_registration_rate_limiter.clone();
    let first_device_group_limiter = state.first_device_group_rate_limiter.clone();
    let config = state.config.clone();

    let result = tokio::task::spawn_blocking(move || {
        db.with_conn(|conn| {
            let outcome = do_register(
                conn,
                &sid,
                &device_id,
                &nonce,
                &signing_pk,
                &x25519_pk,
                &ml_dsa_pk,
                &ml_kem_pk,
                registry_approval,
                pow_solution,
                first_device_admission_proof,
                first_device_pow_difficulty_bits,
                session_expiry,
                client_ip,
                config.as_ref(),
                first_device_registration_limiter,
                first_device_registration_rate_limit,
                first_device_registration_rate_window_secs,
                first_device_group_limiter,
                first_device_group_rate_limit,
                first_device_group_rate_window_secs,
            );
            // We tunnel the outcome through rusqlite::Error to satisfy with_conn's signature
            Ok(outcome)
        })
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e: rusqlite::Error| AppError::Internal(e.to_string()))?;

    let token = result?;

    tracing::debug!(
        sync_id = %&sync_id[..16],
        device_id = %&body.device_id[..8.min(body.device_id.len())],
        "Register completed successfully"
    );

    Ok((
        axum::http::StatusCode::CREATED,
        axum::Json(RegisterResponse {
            device_session_token: token,
        }),
    ))
}

fn check_registration_access(state: &AppState, headers: &HeaderMap) -> Result<(), AppError> {
    if !state.config.registration_enabled {
        return Err(AppError::Forbidden("Registration is disabled"));
    }
    if let Some(expected_token) = &state.config.registration_token {
        let provided = headers
            .get("X-Registration-Token")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        use subtle::ConstantTimeEq;
        let expected_hash = Sha256::digest(expected_token.as_bytes());
        let provided_hash = Sha256::digest(provided.as_bytes());
        if bool::from(expected_hash.ct_eq(&provided_hash)) {
            // match — continue
        } else {
            return Err(AppError::Forbidden("Invalid registration token"));
        }
    }
    Ok(())
}

/// Core registration logic, runs inside a DB connection lock.
#[allow(clippy::too_many_arguments)]
fn do_register(
    conn: &rusqlite::Connection,
    sync_id: &str,
    device_id: &str,
    nonce: &str,
    signing_pk: &[u8],
    x25519_pk: &[u8],
    ml_dsa_pk: &[u8],
    ml_kem_pk: &[u8],
    registry_approval: Option<RegistryApproval>,
    pow_solution: Option<PowSolution>,
    first_device_admission_proof: Option<FirstDeviceAdmissionProof>,
    first_device_pow_difficulty_bits: u8,
    session_expiry: i64,
    client_ip: Option<String>,
    config: &crate::config::Config,
    first_device_registration_limiter: crate::state::RateLimiter,
    first_device_registration_rate_limit: u32,
    first_device_registration_rate_window_secs: u64,
    first_device_group_limiter: crate::state::RateLimiter,
    first_device_group_rate_limit: u32,
    first_device_group_rate_window_secs: u64,
) -> Result<String, AppError> {
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let mut created_new_group = false;
    let mut new_device_added = false;
    let mut registry_artifact_kind: Option<&str> = None;
    let mut registry_artifact_blob: Option<Vec<u8>> = None;

    // Consume nonce (one-time use, checks expiry)
    let consumed =
        db::consume_nonce(&tx, nonce, sync_id).map_err(|e| AppError::Internal(e.to_string()))?;
    if !consumed {
        return Err(AppError::BadRequest("Invalid or expired nonce"));
    }

    let is_first_device = db::get_sync_group_epoch(&tx, sync_id)
        .map_err(|e| AppError::Internal(e.to_string()))?
        .is_none();

    if is_first_device {
        if let Some(client_ip) = client_ip.as_deref() {
            let rate_keys = ["global", client_ip];
            if !first_device_registration_limiter.check_many(
                &rate_keys,
                first_device_registration_rate_limit,
                first_device_registration_rate_window_secs,
            ) {
                return Err(AppError::TooManyRequests);
            }
            if !first_device_group_limiter.check_many(
                &rate_keys,
                first_device_group_rate_limit,
                first_device_group_rate_window_secs,
            ) {
                return Err(AppError::TooManyRequests);
            }
        }

        let platform_proof_valid = match first_device_admission_proof.as_ref() {
            Some(proof) => {
                verify_first_device_admission_proof(sync_id, device_id, nonce, proof, config)
                    .is_ok()
            }
            None => false,
        };

        if !platform_proof_valid && first_device_pow_difficulty_bits > 0 {
            let pow_solution = pow_solution.ok_or(AppError::FirstDeviceAdmissionRequired)?;
            if !verify_first_device_pow(
                sync_id,
                device_id,
                nonce,
                &pow_solution,
                first_device_pow_difficulty_bits,
            ) {
                tracing::warn!(
                    sync_id = %&sync_id[..16],
                    device_id = %&device_id[..8.min(device_id.len())],
                    "Registration rejected: invalid first-device PoW solution"
                );
                return Err(AppError::FirstDeviceAdmissionInvalid);
            }
        }

        // First device: create the sync group, no invitation needed
        tracing::debug!(
            sync_id = %&sync_id[..16],
            "Creating new sync group (first device)"
        );
        let created = db::create_sync_group(&tx, sync_id, 0)
            .map_err(|e| AppError::Internal(e.to_string()))?;
        created_new_group = created;
        if !created {
            // Another request created the group between our check and insert;
            // treat this as an existing group — require registry approval.
            let approval = registry_approval.as_ref().ok_or(AppError::Unauthorized)?;
            let artifact = verify_registry_approval(
                &tx, sync_id, device_id, signing_pk, x25519_pk, ml_dsa_pk, ml_kem_pk, approval,
            )?;
            registry_artifact_kind = Some("registry_approval");
            registry_artifact_blob = Some(artifact);
        }
    } else {
        // Existing group: require registry approval.
        let approval = registry_approval.as_ref().ok_or(AppError::Unauthorized)?;
        let artifact = verify_registry_approval(
            &tx, sync_id, device_id, signing_pk, x25519_pk, ml_dsa_pk, ml_kem_pk, approval,
        )?;
        registry_artifact_kind = Some("registry_approval");
        registry_artifact_blob = Some(artifact);
    }

    // Check if device already exists
    if let Some(existing) =
        db::get_device(&tx, sync_id, device_id).map_err(|e| AppError::Internal(e.to_string()))?
    {
        if existing.status != "active" {
            return Err(AppError::Forbidden("Device has been revoked"));
        }
        if existing.signing_public_key != signing_pk
            || existing.x25519_public_key != x25519_pk
            || existing.ml_dsa_65_public_key != ml_dsa_pk
            || existing.ml_kem_768_public_key != ml_kem_pk
        {
            tracing::warn!(
                sync_id = %&sync_id[..16],
                device_id = %&device_id[..8.min(device_id.len())],
                signing_key_mismatch = existing.signing_public_key != signing_pk,
                x25519_key_mismatch = existing.x25519_public_key != x25519_pk,
                ml_dsa_key_mismatch = existing.ml_dsa_65_public_key != ml_dsa_pk,
                ml_kem_key_mismatch = existing.ml_kem_768_public_key != ml_kem_pk,
                "Registration rejected: existing device keys do not match stored identity"
            );
            return Err(AppError::DeviceIdentityMismatch);
        }
        tracing::debug!(
            sync_id = %&sync_id[..16],
            device_id = %&device_id[..8.min(device_id.len())],
            "Existing device re-registered"
        );
    } else {
        // Register new device
        let epoch = db::get_sync_group_epoch(&tx, sync_id)
            .map_err(|e| AppError::Internal(e.to_string()))?
            .unwrap_or(0);
        tracing::debug!(
            sync_id = %&sync_id[..16],
            device_id = %&device_id[..8.min(device_id.len())],
            epoch,
            "New device registered"
        );
        db::register_device_with_pq(
            &tx, sync_id, device_id, signing_pk, x25519_pk, ml_dsa_pk, ml_kem_pk, epoch,
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;
        new_device_added = true;

        // Initialize device receipt
        db::upsert_device_receipt(&tx, sync_id, device_id, 0)
            .map_err(|e| AppError::Internal(e.to_string()))?;
    }

    if created_new_group || new_device_added {
        sync_registry_state_with_current_devices(
            &tx,
            sync_id,
            registry_artifact_kind,
            registry_artifact_blob.as_deref(),
        )?;
    }

    // Create session token
    let token = db::create_session(&tx, sync_id, device_id, session_expiry)
        .map_err(|e| AppError::Internal(e.to_string()))?;

    // Clean up expired nonces opportunistically
    let _ = db::cleanup_expired_nonces(&tx);

    tx.commit().map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(token)
}

fn verify_first_device_pow(
    sync_id: &str,
    device_id: &str,
    nonce: &str,
    solution: &PowSolution,
    difficulty_bits: u8,
) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(b"PRISM_SYNC_FIRST_DEVICE_POW_V1\x00");
    hasher.update(sync_id.as_bytes());
    hasher.update([0]);
    hasher.update(device_id.as_bytes());
    hasher.update([0]);
    hasher.update(nonce.as_bytes());
    hasher.update([0]);
    hasher.update(solution.counter.to_be_bytes());

    has_leading_zero_bits(&hasher.finalize(), difficulty_bits)
}

fn verify_first_device_admission_proof(
    sync_id: &str,
    device_id: &str,
    nonce: &str,
    proof: &FirstDeviceAdmissionProof,
    config: &crate::config::Config,
) -> Result<(), AppError> {
    match proof {
        FirstDeviceAdmissionProof::AndroidKeyAttestation { certificate_chain } => {
            let verification = attestation::verify_android_key_attestation(
                sync_id,
                device_id,
                nonce,
                certificate_chain,
                config,
            )
            .map_err(|_| AppError::FirstDeviceAdmissionInvalid)?;

            tracing::debug!(
                sync_id = %&sync_id[..16],
                device_id = %&device_id[..8.min(device_id.len())],
                admission_kind = match verification.kind {
                    FirstDeviceAdmissionKind::StockAndroid => "stock_android",
                    FirstDeviceAdmissionKind::GrapheneOs => "grapheneos",
                },
                "First-device Android attestation accepted"
            );
            Ok(())
        }
        FirstDeviceAdmissionProof::AppleAppAttest {
            key_id,
            attestation_object,
        } => {
            let verification = apple_attestation::verify_apple_app_attest(
                sync_id,
                device_id,
                nonce,
                key_id,
                attestation_object,
                config,
            )
            .map_err(|_| AppError::FirstDeviceAdmissionInvalid)?;

            tracing::debug!(
                sync_id = %&sync_id[..16],
                device_id = %&device_id[..8.min(device_id.len())],
                matched_app_id = verification
                    .matched_app_id
                    .as_deref()
                    .unwrap_or("unconfigured"),
                "First-device Apple App Attest accepted"
            );
            Ok(())
        }
    }
}

fn has_leading_zero_bits(hash: &[u8], difficulty_bits: u8) -> bool {
    let full_zero_bytes = (difficulty_bits / 8) as usize;
    let remaining_bits = difficulty_bits % 8;

    if hash.len() < full_zero_bytes {
        return false;
    }

    if hash[..full_zero_bytes].iter().any(|byte| *byte != 0) {
        return false;
    }

    if remaining_bits == 0 {
        return true;
    }

    let mask = 0xFFu8 << (8 - remaining_bits);
    hash.get(full_zero_bytes)
        .map(|byte| byte & mask == 0)
        .unwrap_or(false)
}

fn client_ip_key(headers: &HeaderMap) -> Option<String> {
    for header_name in [
        #[cfg(feature = "test-helpers")]
        "x-test-client-ip",
        "cf-connecting-ip",
        "x-forwarded-for",
        "x-real-ip",
        "forwarded",
    ] {
        if let Some(value) = headers.get(header_name).and_then(|v| v.to_str().ok()) {
            let candidate = if header_name == "forwarded" {
                value
                    .split(';')
                    .find_map(|part| part.trim().strip_prefix("for="))
                    .unwrap_or(value)
            } else {
                value.split(',').next().unwrap_or(value)
            };
            let trimmed = candidate.trim().trim_matches('"');
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }

    None
}

#[allow(clippy::too_many_arguments)]
fn verify_registry_approval(
    conn: &rusqlite::Connection,
    sync_id: &str,
    device_id: &str,
    signing_pk: &[u8],
    x25519_pk: &[u8],
    ml_dsa_pk: &[u8],
    ml_kem_pk: &[u8],
    approval: &RegistryApproval,
) -> Result<Vec<u8>, AppError> {
    let approver_ed25519_pk = hex::decode(&approval.approver_ed25519_pk)
        .map_err(|_| AppError::BadRequest("Invalid approver_ed25519_pk hex"))?;
    let approver_pk_bytes: [u8; 32] = approver_ed25519_pk
        .try_into()
        .map_err(|_| AppError::BadRequest("approver_ed25519_pk must be 32 bytes"))?;
    let approver_ml_dsa_pk = if approval.approver_ml_dsa_65_pk.is_empty() {
        Vec::new()
    } else {
        hex::decode(&approval.approver_ml_dsa_65_pk)
            .map_err(|_| AppError::BadRequest("Invalid approver_ml_dsa_65_pk hex"))?
    };
    let approval_signature_bytes = hex::decode(&approval.approval_signature)
        .map_err(|_| AppError::BadRequest("Invalid approval_signature hex"))?;

    // Only accept V3 hybrid approval signatures
    let version_byte = approval_signature_bytes.first().copied();
    if version_byte != Some(0x03) {
        return Err(AppError::BadRequest(
            "V3 hybrid approval signature required",
        ));
    }

    let sig_rest = &approval_signature_bytes[1..];
    let hybrid_sig = prism_sync_crypto::pq::HybridSignature::from_bytes(sig_rest)
        .map_err(|_| AppError::BadRequest("Invalid hybrid approval_signature"))?;
    let mut approval_data = Vec::new();
    approval_data.extend_from_slice(b"PRISM_SYNC_REGISTRY_APPROVAL_V2\x00");
    write_len_prefixed(&mut approval_data, sync_id.as_bytes());
    write_len_prefixed(&mut approval_data, approval.approver_device_id.as_bytes());
    write_len_prefixed(&mut approval_data, &approval.signed_registry_snapshot);
    hybrid_sig
        .verify_v3(
            &approval_data,
            b"registry_approval",
            &approver_pk_bytes,
            &approver_ml_dsa_pk,
        )
        .map_err(|_| AppError::Unauthorized)?;

    let snapshot_entries = verify_registry_snapshot(
        &approval.signed_registry_snapshot,
        &approver_pk_bytes,
        &approver_ml_dsa_pk,
    )?;
    let snapshot_map = snapshot_entries_by_device(snapshot_entries, sync_id)?;

    let approver_entry = snapshot_map
        .get(&approval.approver_device_id)
        .ok_or(AppError::Unauthorized)?;
    if approver_entry.status != "active"
        || approver_entry.ed25519_public_key != approver_pk_bytes
        || approver_entry.ml_dsa_65_public_key != approver_ml_dsa_pk
    {
        return Err(AppError::Unauthorized);
    }

    let approver = db::get_device(conn, sync_id, &approval.approver_device_id)
        .map_err(|e| AppError::Internal(e.to_string()))?
        .ok_or(AppError::Unauthorized)?;
    if approver.status != "active"
        || approver.signing_public_key != approver_pk_bytes
        || approver.x25519_public_key != approver_entry.x25519_public_key
        || approver.ml_dsa_65_public_key != approver_ml_dsa_pk
        || approver.ml_kem_768_public_key != approver_entry.ml_kem_768_public_key
    {
        return Err(AppError::Unauthorized);
    }

    let approved_device = snapshot_map.get(device_id).ok_or(AppError::Unauthorized)?;
    if approved_device.status != "active" {
        return Err(AppError::Unauthorized);
    }
    if approved_device.ed25519_public_key != signing_pk
        || approved_device.x25519_public_key != x25519_pk
        || approved_device.ml_dsa_65_public_key != ml_dsa_pk
        || approved_device.ml_kem_768_public_key != ml_kem_pk
    {
        return Err(AppError::DeviceIdentityMismatch);
    }

    let current_entries = current_registry_entries(conn, sync_id)?;
    let mut remaining = snapshot_map;
    for current in &current_entries {
        let Some(snapshot_entry) = remaining.remove(&current.device_id) else {
            return Err(AppError::Conflict("Stale registry approval"));
        };
        if snapshot_entry.ed25519_public_key != current.ed25519_public_key
            || snapshot_entry.x25519_public_key != current.x25519_public_key
            || snapshot_entry.ml_dsa_65_public_key != current.ml_dsa_65_public_key
            || snapshot_entry.ml_kem_768_public_key != current.ml_kem_768_public_key
            || snapshot_entry.status != current.status
        {
            return Err(AppError::Conflict("Stale registry approval"));
        }
    }

    match remaining.len() {
        // New device: snapshot has exactly one entry not yet in the registry
        1 if remaining.contains_key(device_id) => Ok(approval.signed_registry_snapshot.clone()),
        // Re-registration: device already in registry, all entries matched
        0 => Ok(approval.signed_registry_snapshot.clone()),
        _ => Err(AppError::Conflict(
            "Registry approval must add exactly one device",
        )),
    }
}

fn verify_registry_snapshot(
    signed_snapshot: &[u8],
    approver_ed25519_pk: &[u8; 32],
    approver_ml_dsa_pk: &[u8],
) -> Result<Vec<RegistrySnapshotEntry>, AppError> {
    // Only accept V3 hybrid format
    let first = signed_snapshot.first().copied();
    if first != Some(0x03) {
        return Err(AppError::BadRequest(
            "V3 hybrid signed registry snapshot required",
        ));
    }

    verify_registry_snapshot_hybrid(signed_snapshot, approver_ed25519_pk, approver_ml_dsa_pk)
}

fn verify_registry_snapshot_hybrid(
    signed_snapshot: &[u8],
    approver_ed25519_pk: &[u8; 32],
    approver_ml_dsa_pk: &[u8],
) -> Result<Vec<RegistrySnapshotEntry>, AppError> {
    use prism_sync_crypto::pq::HybridSignature;

    // Wire format: [version][HybridSignature::to_bytes()][JSON]
    let Some((&version, remaining)) = signed_snapshot.split_first() else {
        return Err(AppError::BadRequest("signed_registry_snapshot too short"));
    };

    // Parse the length-prefixed hybrid signature to find JSON start
    if remaining.len() < 8 {
        return Err(AppError::BadRequest("signed_registry_snapshot too short"));
    }
    let ed_len = u32::from_le_bytes(remaining[0..4].try_into().unwrap()) as usize;
    if remaining.len() < 4 + ed_len + 4 {
        return Err(AppError::BadRequest("signed_registry_snapshot truncated"));
    }
    let ml_len_offset = 4 + ed_len;
    let ml_len = u32::from_le_bytes(
        remaining[ml_len_offset..ml_len_offset + 4]
            .try_into()
            .unwrap(),
    ) as usize;
    let signature_len = ml_len_offset + 4 + ml_len;
    if remaining.len() <= signature_len {
        return Err(AppError::BadRequest(
            "signed_registry_snapshot missing JSON payload",
        ));
    }

    let signature = HybridSignature::from_bytes(&remaining[..signature_len])
        .map_err(|_| AppError::BadRequest("Invalid hybrid registry snapshot signature"))?;
    let json_bytes = &remaining[signature_len..];

    let mut signing_data =
        Vec::with_capacity(b"PRISM_SYNC_REGISTRY_V2\x00".len() + json_bytes.len());
    signing_data.extend_from_slice(b"PRISM_SYNC_REGISTRY_V2\x00");
    signing_data.extend_from_slice(json_bytes);

    // Only V3 is accepted (V2 sunset)
    if version != 0x03 {
        return Err(AppError::Unauthorized);
    }
    signature
        .verify_v3(
            &signing_data,
            b"registry_snapshot",
            approver_ed25519_pk,
            approver_ml_dsa_pk,
        )
        .map_err(|_| AppError::Unauthorized)?;

    let entries: Vec<RegistrySnapshotEntry> = serde_json::from_slice(json_bytes)
        .map_err(|_| AppError::BadRequest("Invalid signed_registry_snapshot JSON"))?;
    Ok(entries)
}

fn snapshot_entries_by_device(
    entries: Vec<RegistrySnapshotEntry>,
    expected_sync_id: &str,
) -> Result<HashMap<String, RegistrySnapshotEntry>, AppError> {
    let mut by_device = HashMap::with_capacity(entries.len());
    for mut entry in entries {
        if !auth::is_valid_sync_id(&entry.sync_id) {
            return Err(AppError::BadRequest("Registry snapshot sync_id is invalid"));
        }
        if entry.sync_id != expected_sync_id {
            return Err(AppError::BadRequest("Registry snapshot sync_id mismatch"));
        }
        entry.status = normalize_registry_status(&entry.status)?.to_string();
        if by_device.insert(entry.device_id.clone(), entry).is_some() {
            return Err(AppError::BadRequest(
                "Duplicate device_id in registry snapshot",
            ));
        }
    }
    Ok(by_device)
}

fn current_registry_entries(
    conn: &rusqlite::Connection,
    sync_id: &str,
) -> Result<Vec<RegistrySnapshotEntry>, AppError> {
    let devices = db::list_devices(conn, sync_id).map_err(|e| AppError::Internal(e.to_string()))?;
    devices
        .into_iter()
        .map(|device| {
            Ok(RegistrySnapshotEntry {
                sync_id: sync_id.to_string(),
                device_id: device.device_id,
                ed25519_public_key: device.signing_public_key,
                x25519_public_key: device.x25519_public_key,
                ml_dsa_65_public_key: device.ml_dsa_65_public_key,
                ml_kem_768_public_key: device.ml_kem_768_public_key,
                status: normalize_registry_status(&device.status)?.to_string(),
            })
        })
        .collect()
}

fn sync_registry_state_with_current_devices(
    conn: &rusqlite::Connection,
    sync_id: &str,
    artifact_kind: Option<&str>,
    artifact_blob: Option<&[u8]>,
) -> Result<(), AppError> {
    let current_entries = current_registry_entries(conn, sync_id)?;
    let registry_json = canonical_registry_json(&current_entries)?;
    let registry_hash = hash_registry_json(&registry_json);
    let current_state =
        db::get_registry_state(conn, sync_id).map_err(|e| AppError::Internal(e.to_string()))?;

    let version = match current_state {
        Some(state) if state.registry_hash == registry_hash => state.registry_version,
        Some(state) => state.registry_version + 1,
        None => 1,
    };

    db::upsert_registry_state(conn, sync_id, version, &registry_hash)
        .map_err(|e| AppError::Internal(e.to_string()))?;

    if let (Some(kind), Some(blob)) = (artifact_kind, artifact_blob) {
        db::store_registry_artifact(conn, sync_id, version, &registry_hash, kind, blob)
            .map_err(|e| AppError::Internal(e.to_string()))?;
    }

    Ok(())
}

fn canonical_registry_json(entries: &[RegistrySnapshotEntry]) -> Result<Vec<u8>, AppError> {
    let mut sorted = entries.to_vec();
    sorted.sort_by(|a, b| a.device_id.cmp(&b.device_id));
    serde_json::to_vec(&sorted).map_err(|e| AppError::Internal(e.to_string()))
}

fn hash_registry_json(json: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(json);
    hex::encode(hasher.finalize())
}

fn normalize_registry_status(status: &str) -> Result<&'static str, AppError> {
    match status {
        "active" | "stale" => Ok("active"),
        "revoked" => Ok("revoked"),
        _ => Err(AppError::BadRequest("Invalid registry snapshot status")),
    }
}

fn write_len_prefixed(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}
