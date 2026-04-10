use axum::{
    extract::{Extension, Path, State},
    http::HeaderMap,
    response::IntoResponse,
    routing::get,
    Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::Serialize;

use crate::{db, errors::AppError, state::AppState};

use super::{verify_signed_request, AuthIdentity};

pub fn routes() -> Router<AppState> {
    Router::new().route("/v1/sync/{sync_id}/registry", get(get_registry))
}

#[derive(Serialize)]
struct RegistryResponse {
    registry_version: i64,
    artifact_blob: String, // base64-encoded
    artifact_kind: String,
}

async fn get_registry(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(auth_identity): Extension<AuthIdentity>,
    Path(path_sync_id): Path<String>,
    body: axum::body::Bytes,
) -> Result<impl IntoResponse, AppError> {
    // Defense-in-depth: verify path sync_id matches authenticated identity
    if path_sync_id != auth_identity.sync_id {
        return Err(AppError::Forbidden("sync_id mismatch"));
    }

    // Verify signed request (same pattern as other signed endpoints)
    verify_signed_request(
        &state,
        &auth_identity,
        &headers,
        "GET",
        &format!("/v1/sync/{}/registry", path_sync_id),
        &body,
    )?;

    let db = state.db.clone();
    let sync_id = auth_identity.sync_id.clone();

    let result = tokio::task::spawn_blocking(move || {
        db.with_read_conn(|conn| {
            // Get current registry state
            let registry_state = db::get_registry_state(conn, &sync_id)?;
            let Some(state) = registry_state else {
                return Ok(None);
            };

            // Get the artifact for the current version
            let artifact =
                db::get_registry_artifact(conn, &sync_id, state.registry_version)?;
            Ok(artifact.map(|a| (state.registry_version, a)))
        })
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| AppError::Internal(e.to_string()))?;

    match result {
        Some((version, artifact)) => Ok(axum::Json(RegistryResponse {
            registry_version: version,
            artifact_blob: BASE64.encode(&artifact.artifact_blob),
            artifact_kind: artifact.artifact_kind,
        })
        .into_response()),
        None => Err(AppError::NotFound),
    }
}
