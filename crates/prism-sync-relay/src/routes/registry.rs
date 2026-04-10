use axum::{
    body::Bytes,
    extract::{Extension, Path, State},
    http::HeaderMap,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::{db, errors::AppError, state::AppState};

use super::{verify_signed_request, AuthIdentity};

// ---------------------------------------------------------------------------
// routes
// ---------------------------------------------------------------------------

pub fn routes() -> Router<AppState> {
    Router::new().route(
        "/v1/sync/{sync_id}/registry",
        get(get_registry).put(put_registry),
    )
}

// ---------------------------------------------------------------------------
// get_registry — GET /v1/sync/{sync_id}/registry
// ---------------------------------------------------------------------------

async fn get_registry(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthIdentity>,
    Path(path_sync_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    if path_sync_id != auth.sync_id {
        return Err(AppError::Forbidden("sync_id mismatch"));
    }

    let db = state.db.clone();
    let sync_id = auth.sync_id.clone();

    let (registry_state, artifact) = tokio::task::spawn_blocking(move || {
        db.with_read_conn(|conn| {
            let state = db::get_registry_state(conn, &sync_id)?;
            let artifact = match &state {
                Some(s) => db::get_registry_artifact(conn, &sync_id, s.registry_version)?,
                None => None,
            };
            Ok((state, artifact))
        })
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| AppError::Internal(e.to_string()))?;

    let b64 = base64::engine::general_purpose::STANDARD;

    // Return 404 when no registry state or no artifact exists, so the client
    // can distinguish "no artifact" from "artifact present".
    let Some(state) = registry_state else {
        return Err(AppError::NotFound);
    };
    let Some(artifact) = artifact else {
        return Err(AppError::NotFound);
    };

    // Field names must match SignedRegistryResponse on the client:
    // { registry_version, artifact_blob (base64), artifact_kind }
    Ok(Json(serde_json::json!({
        "registry_version": state.registry_version,
        "artifact_blob": b64.encode(&artifact.artifact_blob),
        "artifact_kind": artifact.artifact_kind,
    })))
}

// ---------------------------------------------------------------------------
// put_registry — PUT /v1/sync/{sync_id}/registry
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct PutRegistryRequest {
    signed_registry_snapshot: String, // base64-encoded
}

#[derive(Serialize)]
struct PutRegistryResponse {
    registry_version: i64,
}

async fn put_registry(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(auth_identity): Extension<AuthIdentity>,
    Path(path_sync_id): Path<String>,
    body: Bytes,
) -> Result<impl IntoResponse, AppError> {
    if path_sync_id != auth_identity.sync_id {
        return Err(AppError::Forbidden("sync_id mismatch"));
    }

    // Verify signed request
    verify_signed_request(
        &state,
        &auth_identity,
        &headers,
        "PUT",
        &format!("/v1/sync/{}/registry", path_sync_id),
        &body,
    )?;

    // Parse request body
    let req: PutRegistryRequest =
        serde_json::from_slice(&body).map_err(|_| AppError::BadRequest("Invalid JSON body"))?;

    // Decode base64
    let b64 = base64::engine::general_purpose::STANDARD;
    let artifact_blob = b64
        .decode(&req.signed_registry_snapshot)
        .map_err(|_| AppError::BadRequest("Invalid base64 in signed_registry_snapshot"))?;

    // Size cap: 512KB
    if artifact_blob.len() > 512 * 1024 {
        return Err(AppError::BadRequest(
            "signed_registry_snapshot too large (max 512KB)",
        ));
    }

    let db = state.db.clone();
    let sync_id = auth_identity.sync_id.clone();

    let version = tokio::task::spawn_blocking(move || {
        db.with_conn(|conn| Ok(do_put_registry(conn, &sync_id, &artifact_blob)))
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| AppError::Internal(e.to_string()))??;

    Ok(Json(PutRegistryResponse {
        registry_version: version,
    }))
}

fn do_put_registry(
    conn: &rusqlite::Connection,
    sync_id: &str,
    artifact_blob: &[u8],
) -> Result<i64, AppError> {
    use super::register::sync_registry_state_with_current_devices;

    sync_registry_state_with_current_devices(
        conn,
        sync_id,
        Some("signed_registry_snapshot"),
        Some(artifact_blob),
    )?;

    let state =
        db::get_registry_state(conn, sync_id).map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(state.map(|s| s.registry_version).unwrap_or(0))
}
