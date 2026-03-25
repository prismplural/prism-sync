use axum::{
    extract::{Path, State},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};

use crate::{auth, db, errors::AppError, state::AppState};

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
}

async fn get_register_nonce(
    State(state): State<AppState>,
    Path(sync_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    if !auth::is_valid_sync_id(&sync_id) {
        return Err(AppError::BadRequest("Invalid sync ID"));
    }

    // Per-sync_id rate limiting: prevent nonce exhaustion attacks.
    if !state.nonce_rate_limiter.check(
        &sync_id,
        state.config.nonce_rate_limit,
        state.config.nonce_rate_window_secs,
    ) {
        return Err(AppError::TooManyRequests);
    }

    let nonce_expiry = state.config.nonce_expiry_secs as i64;
    let db = state.db.clone();
    let sid = sync_id.clone();

    let nonce = tokio::task::spawn_blocking(move || {
        db.with_conn(|conn| db::create_nonce(conn, &sid, nonce_expiry))
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| AppError::Internal(e.to_string()))?;

    tracing::debug!(
        sync_id = %&sync_id[..16],
        "Registration nonce issued"
    );

    Ok(axum::Json(NonceResponse { nonce }))
}

// ---------------------------------------------------------------------------
// POST /v1/sync/{sync_id}/register
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct RegisterRequest {
    device_id: String,
    signing_public_key: String,
    x25519_public_key: String,
    registration_challenge: String,
    nonce: String,
    #[serde(default)]
    signed_invitation: Option<SignedInvitation>,
}

#[derive(Deserialize, Clone)]
struct SignedInvitation {
    sync_id: String,
    relay_url: String,
    wrapped_dek: String,
    salt: String,
    inviter_device_id: String,
    inviter_ed25519_pk: String,
    signature: String,
    #[serde(default)]
    joiner_device_id: Option<String>,
    #[serde(default)]
    current_epoch: Option<u32>,
    #[serde(default)]
    epoch_key_hex: Option<String>,
}

#[derive(Serialize)]
struct RegisterResponse {
    device_session_token: String,
}

async fn register_device(
    State(state): State<AppState>,
    Path(sync_id): Path<String>,
    axum::Json(body): axum::Json<RegisterRequest>,
) -> Result<impl IntoResponse, AppError> {
    if !auth::is_valid_sync_id(&sync_id) {
        return Err(AppError::BadRequest("Invalid sync ID"));
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

    // Decode the challenge signature from hex
    let challenge_sig = hex::decode(&body.registration_challenge)
        .map_err(|_| AppError::BadRequest("Invalid registration_challenge hex"))?;

    tracing::debug!(
        sync_id = %&sync_id[..16],
        device_id = %&body.device_id[..8.min(body.device_id.len())],
        has_invitation = body.signed_invitation.is_some(),
        "Register request"
    );

    // Verify Ed25519 challenge: proves the client holds the private key
    if !auth::verify_ed25519_challenge(
        &signing_pk,
        &sync_id,
        &body.device_id,
        &body.nonce,
        &challenge_sig,
    ) {
        tracing::warn!(
            sync_id = %&sync_id[..16],
            device_id = %&body.device_id[..8.min(body.device_id.len())],
            "Registration rejected: Ed25519 challenge verification failed"
        );
        return Err(AppError::Unauthorized);
    }

    let db = state.db.clone();
    let session_expiry = state.config.session_expiry_secs as i64;
    let sid = sync_id.clone();
    let device_id = body.device_id.clone();
    let nonce = body.nonce.clone();
    let invitation = body.signed_invitation.clone();

    let result = tokio::task::spawn_blocking(move || {
        db.with_conn(|conn| {
            let outcome = do_register(
                conn,
                &sid,
                &device_id,
                &nonce,
                &signing_pk,
                &x25519_pk,
                invitation,
                session_expiry,
            );
            // We tunnel the outcome through rusqlite::Error to satisfy with_conn's signature
            Ok(outcome)
        })
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e: rusqlite::Error| AppError::Internal(e.to_string()))?;

    let token = result?;

    state.metrics.inc(&state.metrics.registrations);

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

/// Core registration logic, runs inside a DB connection lock.
#[allow(clippy::too_many_arguments)]
fn do_register(
    conn: &rusqlite::Connection,
    sync_id: &str,
    device_id: &str,
    nonce: &str,
    signing_pk: &[u8],
    x25519_pk: &[u8],
    invitation: Option<SignedInvitation>,
    session_expiry: i64,
) -> Result<String, AppError> {
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| AppError::Internal(e.to_string()))?;

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
        // First device: create the sync group, no invitation needed
        tracing::debug!(
            sync_id = %&sync_id[..16],
            "Creating new sync group (first device)"
        );
        let created = db::create_sync_group(&tx, sync_id, 0)
            .map_err(|e| AppError::Internal(e.to_string()))?;
        if !created {
            // Another request created the group between our check and insert;
            // treat this as an existing group — invitation is required.
            let inv = invitation.as_ref().ok_or(AppError::Unauthorized)?;
            verify_signed_invitation(&tx, sync_id, inv)?;
        }
    } else {
        // Existing group: invitation is required
        let inv = invitation.ok_or(AppError::Unauthorized)?;
        verify_signed_invitation(&tx, sync_id, &inv)?;
    }

    // Check if device already exists
    if let Some(existing) =
        db::get_device(&tx, sync_id, device_id).map_err(|e| AppError::Internal(e.to_string()))?
    {
        if existing.status != "active" {
            return Err(AppError::Forbidden("Device has been revoked"));
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
        let permission = "admin";
        tracing::debug!(
            sync_id = %&sync_id[..16],
            device_id = %&device_id[..8.min(device_id.len())],
            epoch,
            "New device registered"
        );
        db::register_device(
            &tx, sync_id, device_id, signing_pk, x25519_pk, epoch, permission,
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;

        // Initialize device receipt
        db::upsert_device_receipt(&tx, sync_id, device_id, 0)
            .map_err(|e| AppError::Internal(e.to_string()))?;
    }

    // Create session token
    let token = db::create_session(&tx, sync_id, device_id, session_expiry)
        .map_err(|e| AppError::Internal(e.to_string()))?;

    // Clean up expired nonces opportunistically
    let _ = db::cleanup_expired_nonces(&tx);

    tx.commit().map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(token)
}

/// Verify a signed invitation for an existing sync group.
fn verify_signed_invitation(
    conn: &rusqlite::Connection,
    sync_id: &str,
    inv: &SignedInvitation,
) -> Result<(), AppError> {
    // 1. Verify the invitation's sync_id matches
    if inv.sync_id != sync_id {
        return Err(AppError::BadRequest("Invitation sync_id mismatch"));
    }

    // 2. Look up the inviter device
    let inviter = db::get_device(conn, sync_id, &inv.inviter_device_id)
        .map_err(|e| AppError::Internal(e.to_string()))?
        .ok_or(AppError::Unauthorized)?;
    if inviter.status != "active" {
        return Err(AppError::Unauthorized);
    }

    // 3. Decode invitation fields from hex
    let wrapped_dek = hex::decode(&inv.wrapped_dek)
        .map_err(|_| AppError::BadRequest("Invalid wrapped_dek hex"))?;
    let salt = hex::decode(&inv.salt).map_err(|_| AppError::BadRequest("Invalid salt hex"))?;
    let inviter_ed25519_pk = hex::decode(&inv.inviter_ed25519_pk)
        .map_err(|_| AppError::BadRequest("Invalid inviter_ed25519_pk hex"))?;
    let inviter_pk_bytes: [u8; 32] = inviter_ed25519_pk
        .try_into()
        .map_err(|_| AppError::BadRequest("inviter_ed25519_pk must be 32 bytes"))?;
    let signature = hex::decode(&inv.signature)
        .map_err(|_| AppError::BadRequest("Invalid invitation signature hex"))?;

    // 4. Verify that the inviter's public key in the invitation matches what's in the DB
    if inviter.signing_public_key != inviter_pk_bytes.as_slice() {
        return Err(AppError::Unauthorized);
    }

    // 5. Decode epoch fields (backwards-compatible defaults for older clients)
    let current_epoch = inv.current_epoch.unwrap_or(0);
    let epoch_key_bytes = inv
        .epoch_key_hex
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(hex::decode)
        .transpose()
        .map_err(|_| AppError::BadRequest("Invalid epoch_key_hex hex"))?
        .unwrap_or_default();
    if current_epoch > 0 && epoch_key_bytes.len() != 32 {
        return Err(AppError::BadRequest(
            "Invitation epoch_key_hex must be 32 bytes when current_epoch > 0",
        ));
    }
    if current_epoch == 0 && !epoch_key_bytes.is_empty() {
        return Err(AppError::BadRequest(
            "Invitation epoch_key_hex must be empty when current_epoch == 0",
        ));
    }

    let group_epoch = db::get_sync_group_epoch(conn, sync_id)
        .map_err(|e| AppError::Internal(e.to_string()))?
        .unwrap_or(0);
    if current_epoch as i64 != group_epoch {
        tracing::warn!(
            sync_id = %&sync_id[..16],
            inviter = %&inv.inviter_device_id[..8.min(inv.inviter_device_id.len())],
            invitation_epoch = current_epoch,
            group_epoch,
            "Invitation epoch mismatch"
        );
        return Err(AppError::Unauthorized);
    }

    // 6. Reconstruct canonical signing data and verify Ed25519 signature
    let signing_data = auth::build_invitation_signing_data(
        sync_id,
        &inv.relay_url,
        &wrapped_dek,
        &salt,
        &inv.inviter_device_id,
        &inviter_pk_bytes,
        inv.joiner_device_id.as_deref(),
        current_epoch,
        &epoch_key_bytes,
    );
    if !auth::verify_invitation_signature(&inviter.signing_public_key, &signing_data, &signature) {
        tracing::warn!(
            sync_id = %&sync_id[..16],
            inviter = %&inv.inviter_device_id[..8.min(inv.inviter_device_id.len())],
            "Invitation signature verification failed"
        );
        return Err(AppError::Unauthorized);
    }

    Ok(())
}
