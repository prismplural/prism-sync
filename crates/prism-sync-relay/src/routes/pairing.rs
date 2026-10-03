use axum::{
    body::Bytes,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post, put},
    Router,
};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use crate::{
    config::{
        PAIRING_LEASE_RENEW_MAX_BODY_BYTES, PAIRING_LEASE_SECRET_LEN, PAIRING_LEASE_VERSION_V1,
    },
    db::{self, PairingLeaseRenewOutcome, PairingLeaseVerifier, PairingSlotRead},
    errors::AppError,
    state::AppState,
};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/pairing", axum::routing::post(create_session))
        .route("/v1/pairing/{rendezvous_id}/bootstrap", get(get_bootstrap))
        .route("/v1/pairing/{rendezvous_id}/init", put(put_init).get(get_init))
        .route(
            "/v1/pairing/{rendezvous_id}/confirmation",
            put(put_confirmation).get(get_confirmation),
        )
        .route("/v1/pairing/{rendezvous_id}/credentials", put(put_credentials).get(get_credentials))
        .route("/v1/pairing/{rendezvous_id}/joiner", put(put_joiner).get(get_joiner))
        // Optional, nonterminal initiator lease capability. Posted *before* the
        // legacy `init` slot so a new joiner that fetches it only after
        // authenticating `pairing_init` can never observe an empty-slot race.
        // Old relays 404 this path; old joiners never fetch it.
        .route(
            "/v1/pairing/{rendezvous_id}/lease_capability",
            put(put_lease_capability).get(get_lease_capability),
        )
        // Opaque lease renewal: authority is the 32-byte secret in the body and
        // nothing else — no bearer session, no device identity, no upload
        // linkage. Every failure mode answers with one byte-identical 404.
        //
        // No `DefaultBodyLimit` layer here: the handler itself reads the body
        // through a bounded `to_bytes` call so an over-length body yields the
        // *same* uniform 404 the semantic length check produces, instead of a
        // layer's distinct 413. See `renew_lease`.
        .route("/v1/pairing/{rendezvous_id}/lease/renew", post(renew_lease))
        .route("/v1/pairing/{rendezvous_id}", delete(delete_session))
}

/// Exact request-body length for lease renewal.
///
/// This is the **semantic** limit: the body must be exactly this many bytes or
/// the request is rejected with the uniform not-found response.
const PAIRING_LEASE_RENEW_BODY_LEN: usize = crate::config::PAIRING_LEASE_RENEW_REQUEST_BODY_LEN;

/// The single response body every rejected lease renewal returns.
///
/// Uniformity is the security property, not a formatting choice: unknown,
/// expired, lease-declined, pre-confirmation, consumed, saturated, wrong-secret,
/// and wrong-length attempts must be **byte-identical**, or the endpoint becomes
/// a state oracle that tells an attacker whether a rendezvous ID exists and where
/// it is in its lifecycle. This literal is compared in tests.
const PAIRING_LEASE_RENEW_REJECT_BODY: &str = "Not Found";

/// Build the uniform lease-renewal rejection response.
///
/// Kept as one function so every rejection path — including the two limiter
/// paths — provably shares one implementation.
fn lease_renew_not_found() -> axum::response::Response {
    (StatusCode::NOT_FOUND, PAIRING_LEASE_RENEW_REJECT_BODY).into_response()
}

// ---------------------------------------------------------------------------
// POST /v1/pairing — create a new pairing session
// ---------------------------------------------------------------------------

/// `POST /v1/pairing` request body.
///
/// `lease_key_hash` / `lease_version` are **optional** additive v1 fields. An
/// older client omits them, and an older relay ignores them; in both directions
/// the request stays valid. `#[serde(default)]` plus an untyped
/// `serde_json::Value` for the hash means even a malformed lease value cannot
/// fail deserialization of an otherwise-good create — the lease is simply not
/// committed and no version is echoed.
#[derive(Deserialize)]
struct CreateSessionRequest {
    joiner_bootstrap: String,
    /// `SHA-256(pairing_lease_secret)` as base64, 32 bytes when decoded. The
    /// relay accepts **both** the standard alphabet (`+`/`/`) the core client
    /// emits today and the published base64url alphabet (`-`/`_`), padded or
    /// unpadded — see [`decode_lease_key_hash`]. Left untyped so a wrong-typed
    /// value downgrades instead of 422ing the whole ceremony.
    #[serde(default)]
    lease_key_hash: Option<serde_json::Value>,
    /// Requested lease version. v1 is the only supported value.
    #[serde(default)]
    lease_version: Option<u16>,
}

/// `POST /v1/pairing` response.
///
/// `lease_version` is present **only** when the relay committed the joiner's
/// verifier. The echo is authoritative: a successful 201 with no echo means
/// fixed-TTL pairing, which is why an old relay (which ignores the request
/// fields) is indistinguishable from a relay that declined the lease.
#[derive(Serialize)]
struct CreateSessionResponse {
    rendezvous_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    lease_version: Option<u16>,
}

/// Decode a create-time `lease_key_hash` in every base64 form v1 permits.
///
/// The published v1 contract names base64url, while the shipped core client
/// emits standard base64 (`BASE64 = STANDARD` in `pairing_relay.rs`). A relay
/// that accepted only one alphabet would silently downgrade every peer using the
/// other, and a downgrade is indistinguishable from a relay that has no lease
/// support at all — so the loss would be invisible. The relay therefore accepts
/// both alphabets, padded and unpadded, exactly as the engines implement them:
///
/// - `STANDARD` — the core client's current emission (v1 legacy canonical);
/// - `URL_SAFE` — the published base64url form, padded;
/// - `STANDARD_NO_PAD` / `URL_SAFE_NO_PAD` — the unpadded forms.
///
/// A candidate must decode to **exactly** [`PAIRING_LEASE_SECRET_LEN`] bytes.
/// Anything else — wrong alphabet, bad padding, or any other length — returns
/// `None`, and the caller downgrades the offer. A malformed value is never
/// echoed back: the silent downgrade *is* the specified response.
fn decode_lease_key_hash(raw: &str) -> Option<[u8; PAIRING_LEASE_SECRET_LEN]> {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};

    // All four engines share the one `GeneralPurpose` type, so they iterate as a
    // single array. The alphabets are disjoint on `+`/`/` vs `-`/`_`, and the
    // padded engines require canonical padding while the no-pad engines reject
    // it, so at most one candidate can ever match a given string.
    for engine in [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD] {
        if let Ok(decoded) = engine.decode(raw) {
            if let Ok(verifier) = <[u8; PAIRING_LEASE_SECRET_LEN]>::try_from(decoded.as_slice()) {
                return Some(verifier);
            }
        }
    }
    None
}

/// Resolve a create request's optional lease offer to a verifier to commit.
///
/// Returns `None` for every downgrade case, in which order the checks run. A
/// downgrade is always safe: the rendezvous is still created as an ordinary
/// fixed-TTL session and the response echoes no version, so the joiner sends the
/// legacy confirmation MAC and the ceremony proceeds unchanged.
///
/// Rejection is deliberately **not** used. The spec makes the response echo, not
/// the HTTP status, authoritative for lease support, so a joiner that offered
/// lease metadata against a relay that cannot honor it must still get its
/// rendezvous. Refusing the create would break the ceremony over an optional
/// optimization.
///
/// Downgrade cases:
///
/// - the relay has the lease disabled (`enabled` false — the capability gate);
/// - the request carried no `lease_key_hash`;
/// - `lease_version` is present and is not [`PAIRING_LEASE_VERSION_V1`];
/// - the hash is not a string, or is not valid base64 in any accepted alphabet
///   (standard or base64url, padded or unpadded), or does not decode to exactly
///   32 bytes.
fn resolve_lease_offer(
    enabled: bool,
    lease_version: Option<u16>,
    lease_key_hash: Option<&serde_json::Value>,
) -> Option<[u8; PAIRING_LEASE_SECRET_LEN]> {
    if !enabled {
        return None;
    }

    // An explicitly unsupported version is not a silent downgrade opportunity:
    // a future v2 client must not be told "no lease" in a way it might misread,
    // but here "no echo" is exactly the specified downgrade signal, so v2-against-
    // v1 relay lands on fixed-TTL pairing.
    if let Some(version) = lease_version {
        if version != PAIRING_LEASE_VERSION_V1 {
            return None;
        }
    }

    let raw = lease_key_hash?.as_str()?;
    decode_lease_key_hash(raw)
}

async fn create_session(
    State(state): State<AppState>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    axum::Json(body): axum::Json<CreateSessionRequest>,
) -> Result<impl IntoResponse, AppError> {
    // Rate limit by the actual peer address. Pairing rendezvous IDs are bearer
    // capabilities, so spoofable forwarded headers are not trusted here.
    if !state.pairing_rate_limiter.check(
        &client_ip_key(peer_addr),
        state.config.pairing_session_rate_limit,
        60,
    ) {
        return Err(AppError::TooManyRequests);
    }

    // Decode and validate bootstrap data
    let bootstrap_data = base64::engine::general_purpose::STANDARD
        .decode(&body.joiner_bootstrap)
        .map_err(|_| AppError::BadRequest("Invalid base64 in joiner_bootstrap"))?;

    if bootstrap_data.len() > state.config.pairing_session_max_payload_bytes {
        return Err(AppError::PayloadTooLarge("joiner_bootstrap too large"));
    }

    // Optional lease commitment. A malformed or unsupported offer is a silent
    // downgrade to fixed-TTL pairing (no echo), never a create failure — the
    // response echo is what the client treats as authoritative.
    let lease_verifier = resolve_lease_offer(
        state.config.pairing_lease_supported(),
        body.lease_version,
        body.lease_key_hash.as_ref(),
    );

    // Generate rendezvous_id (128-bit CSPRNG, hex-encoded)
    let rendezvous_id = {
        use rand::RngCore;
        let mut bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        hex::encode(bytes)
    };

    let db = state.db.clone();
    let rid = rendezvous_id.clone();
    let ttl = state.config.pairing_session_ttl_secs;

    tokio::task::spawn_blocking(move || {
        db.with_conn(|conn| {
            db::create_pairing_session_with_lease(
                conn,
                &rid,
                &bootstrap_data,
                ttl,
                lease_verifier.as_ref(),
            )
        })
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| AppError::Internal(e.to_string()))?;

    // The echoed version is derived from the verifier we actually committed, not
    // from what the client asked for, so the echo cannot claim support we did
    // not store.
    let lease_version = lease_verifier.map(|_| PAIRING_LEASE_VERSION_V1);

    // Rendezvous IDs are bearer capabilities, so log only a prefix — never the
    // full ID, and never the verifier or any lease material.
    tracing::debug!(
        rendezvous_id = %&rendezvous_id[..8],
        lease_version = ?lease_version,
        "Pairing session created"
    );

    Ok((StatusCode::CREATED, axum::Json(CreateSessionResponse { rendezvous_id, lease_version })))
}

// ---------------------------------------------------------------------------
// GET /v1/pairing/{rendezvous_id}/bootstrap
// ---------------------------------------------------------------------------

async fn get_bootstrap(
    State(state): State<AppState>,
    Path(rendezvous_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let db = state.db.clone();
    let rid = rendezvous_id.clone();

    let bootstrap = tokio::task::spawn_blocking(move || {
        db.with_conn(|conn| db::get_pairing_bootstrap(conn, &rid))
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| AppError::Internal(e.to_string()))?;

    match bootstrap {
        Some(data) => {
            let encoded = base64::engine::general_purpose::STANDARD.encode(&data);
            Ok((StatusCode::OK, encoded).into_response())
        }
        None => Err(AppError::NotFound),
    }
}

// ---------------------------------------------------------------------------
// PUT/GET slot helpers
// ---------------------------------------------------------------------------

async fn put_slot(
    state: AppState,
    rendezvous_id: String,
    slot: &'static str,
    body: Bytes,
) -> Result<impl IntoResponse, AppError> {
    if body.len() > state.config.pairing_session_max_payload_bytes {
        return Err(AppError::PayloadTooLarge("Payload too large"));
    }

    let db = state.db.clone();
    let rid = rendezvous_id.clone();
    let data = body.to_vec();

    // First check if the session exists at all
    let exists = {
        let db = state.db.clone();
        let rid = rid.clone();
        tokio::task::spawn_blocking(move || {
            db.with_conn(|conn| db::pairing_session_exists(conn, &rid))
        })
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?
        .map_err(|e| AppError::Internal(e.to_string()))?
    };

    if !exists {
        return Err(AppError::NotFound);
    }

    let updated = tokio::task::spawn_blocking(move || {
        db.with_conn(|conn| db::set_pairing_slot(conn, &rid, slot, &data))
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| AppError::Internal(e.to_string()))?;

    if updated {
        Ok(StatusCode::NO_CONTENT.into_response())
    } else {
        // Session exists but slot already set
        Err(AppError::Conflict("Slot already set"))
    }
}

async fn get_slot(
    state: AppState,
    rendezvous_id: String,
    slot: &'static str,
) -> Result<impl IntoResponse, AppError> {
    let db = state.db.clone();
    let rid = rendezvous_id.clone();

    // Check if session exists
    let exists = {
        let db = state.db.clone();
        let rid2 = rid.clone();
        tokio::task::spawn_blocking(move || {
            db.with_conn(|conn| db::pairing_session_exists(conn, &rid2))
        })
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?
        .map_err(|e| AppError::Internal(e.to_string()))?
    };

    if !exists {
        return Err(AppError::NotFound);
    }

    let value = tokio::task::spawn_blocking(move || {
        db.with_conn(|conn| {
            if is_terminal_pairing_slot(slot) {
                db::take_pairing_slot(conn, &rid, slot)
            } else {
                db::get_pairing_slot(conn, &rid, slot).map(|value| match value {
                    Some(data) => PairingSlotRead::Present(data),
                    None => PairingSlotRead::NotSet,
                })
            }
        })
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| AppError::Internal(e.to_string()))?;

    match value {
        PairingSlotRead::Present(data) => Ok((StatusCode::OK, data).into_response()),
        PairingSlotRead::NotSet => Ok(StatusCode::NO_CONTENT.into_response()),
        PairingSlotRead::Consumed => Err(AppError::NotFound),
    }
}

fn is_terminal_pairing_slot(slot: &str) -> bool {
    matches!(slot, "credential_bundle" | "joiner_bundle")
}

// ---------------------------------------------------------------------------
// Slot route handlers
// ---------------------------------------------------------------------------

async fn put_init(
    State(state): State<AppState>,
    Path(rendezvous_id): Path<String>,
    body: Bytes,
) -> Result<impl IntoResponse, AppError> {
    put_slot(state, rendezvous_id, "pairing_init", body).await
}

async fn get_init(
    State(state): State<AppState>,
    Path(rendezvous_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    get_slot(state, rendezvous_id, "pairing_init").await
}

async fn put_confirmation(
    State(state): State<AppState>,
    Path(rendezvous_id): Path<String>,
    body: Bytes,
) -> Result<impl IntoResponse, AppError> {
    put_slot(state, rendezvous_id, "joiner_confirmation", body).await
}

async fn get_confirmation(
    State(state): State<AppState>,
    Path(rendezvous_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    get_slot(state, rendezvous_id, "joiner_confirmation").await
}

async fn put_credentials(
    State(state): State<AppState>,
    Path(rendezvous_id): Path<String>,
    body: Bytes,
) -> Result<impl IntoResponse, AppError> {
    put_slot(state, rendezvous_id, "credential_bundle", body).await
}

async fn get_credentials(
    State(state): State<AppState>,
    Path(rendezvous_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    get_slot(state, rendezvous_id, "credential_bundle").await
}

async fn put_joiner(
    State(state): State<AppState>,
    Path(rendezvous_id): Path<String>,
    body: Bytes,
) -> Result<impl IntoResponse, AppError> {
    put_slot(state, rendezvous_id, "joiner_bundle", body).await
}

async fn get_joiner(
    State(state): State<AppState>,
    Path(rendezvous_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    get_slot(state, rendezvous_id, "joiner_bundle").await
}

// ---------------------------------------------------------------------------
// Lease capability slot (optional, nonterminal)
// ---------------------------------------------------------------------------

/// `PUT /v1/pairing/{rid}/lease_capability`
///
/// The initiator posts its lease capability here **before** the legacy
/// `pairing_init`. Uses the same generic slot handling as every ceremony slot:
/// set-once, non-expiring on write, and — unlike the two terminal payload slots —
/// never consumed on read, so a retrying joiner always sees the same frame
/// instead of a spurious 404.
///
/// Posting is best-effort from the client's perspective: an old relay 404s this
/// path and the ceremony simply proceeds without a lease.
async fn put_lease_capability(
    State(state): State<AppState>,
    Path(rendezvous_id): Path<String>,
    body: Bytes,
) -> Result<impl IntoResponse, AppError> {
    put_slot(state, rendezvous_id, "lease_capability", body).await
}

/// `GET /v1/pairing/{rid}/lease_capability`
///
/// Repeatable read of the optional capability slot. Returns 204 while unset (a
/// joiner that somehow reads early sees "no capability", never an error) and the
/// exact stored bytes once posted.
async fn get_lease_capability(
    State(state): State<AppState>,
    Path(rendezvous_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    get_slot(state, rendezvous_id, "lease_capability").await
}

// ---------------------------------------------------------------------------
// POST /v1/pairing/{rendezvous_id}/lease/renew
// ---------------------------------------------------------------------------

/// `POST /v1/pairing/{rid}/lease/renew`
///
/// Authority for this endpoint is the 32-byte `pairing_lease_secret` in the body
/// and **nothing else**. There is no bearer session, no device identity, no
/// signature, and no upload/snapshot linkage — deliberately, because the whole
/// point of the lease is that the relay learns only "someone holding an opaque
/// secret asked for more time", never which upload it relates to. The rendezvous
/// ID in the path is a lookup key, not a capability: knowing it is not enough to
/// renew, and a rendezvous-ID thief cannot obtain the secret.
///
/// # Uniformity
///
/// Every rejection — unknown row, expired row, legacy/lease-declined row with no
/// committed verifier, pre-confirmation, consumed terminal slot, global leased
/// cap reached, wrong secret, wrong body length, an over-cap body, client-IP rate
/// limited, or per-rendezvous failure bucket exhausted — returns the *same*
/// [`lease_renew_not_found`] response. That is the anti-oracle property: an
/// attacker probing rendezvous IDs learns nothing about existence or state from
/// the response, and neither does a client that lost a race.
///
/// # Success
///
/// `204 No Content` with no body and no timestamp. The relay deliberately does
/// not return an expiry: the client needs only success or expiry, and returning
/// server timing would leak lease metadata for no client benefit. A lost 204 is
/// harmless because renewal is idempotent.
///
/// # Failure is nonfatal client-side
///
/// By core contract every renewal failure — including this uniform 404 — is
/// nonfatal to the ceremony: the initiator continues under the previously
/// established `expires_at` and lets ordinary rendezvous not-found from a later
/// slot operation terminate. Nothing here asserts the lease was extended.
async fn renew_lease(
    State(state): State<AppState>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(rendezvous_id): Path<String>,
    request: axum::extract::Request,
) -> Result<axum::response::Response, AppError> {
    // Cheap gate first: an unsupported relay behaves exactly like an old relay.
    // Placed before any limiter work so a dark deployment adds no state.
    if !state.config.pairing_lease_supported() {
        return Ok(lease_renew_not_found());
    }

    // Front limiter, keyed on the trusted-proxy-derived client IP — never the raw
    // tunnel peer, which behind Cloudflare Tunnel would be one address for every
    // user. `client_ip_for_rate_limit` applies the `TRUSTED_PROXY_CIDRS`
    // allowlist, so a spoofed `CF-Connecting-IP` from an untrusted peer is
    // ignored and the peer address is used instead.
    let client_ip = super::client_ip_for_rate_limit(&headers, peer_addr, &state.config);
    if !state.pairing_lease_renew_rate_limiter.check(
        &client_ip,
        state.config.pairing_lease.renew_rate_limit,
        state.config.pairing_lease_renew_rate_window_secs(),
    ) {
        state.metrics.inc(&state.metrics.pairing_lease_renew_client_limited);
        return Ok(lease_renew_not_found());
    }

    // Read the body under an explicit transport bound and collapse every read
    // failure — including an over-cap body — to the same uniform 404. An
    // extractor that signalled "too large" with its own status (axum's 413, or a
    // layer's 413) would be a *distinct* response, re-introducing exactly the
    // shape oracle the uniform not-found removes. The cap both bounds buffering
    // (memory safety is preserved; it is not removed) and keeps the response
    // shape identical across every wrong-length case.
    let body =
        match axum::body::to_bytes(request.into_body(), PAIRING_LEASE_RENEW_MAX_BODY_BYTES).await {
            Ok(bytes) => bytes,
            Err(_) => {
                // An oversize body is a failed verifier attempt like any other: count
                // it against the presented ID's failure bucket, then answer
                // uniformly.
                record_lease_failure(&state, &rendezvous_id);
                return Ok(lease_renew_not_found());
            }
        };

    // Semantic body check. The bound above only limits buffering, so every
    // plausible body-size mistake (31, 33, 64 bytes) reaches this point and is
    // answered with the same uniform not-found a wrong secret gets.
    //
    // A wrong-length body counts as a failed verifier attempt: it is exactly the
    // kind of probe the failure bucket exists to bound.
    if body.len() != PAIRING_LEASE_RENEW_BODY_LEN {
        record_lease_failure(&state, &rendezvous_id);
        return Ok(lease_renew_not_found());
    }

    // The array conversion is infallible given the length check above, but is
    // written as a checked conversion so a future change to either constant
    // cannot silently truncate a secret.
    let secret: [u8; PAIRING_LEASE_SECRET_LEN] = match body.as_ref().try_into() {
        Ok(secret) => secret,
        Err(_) => {
            record_lease_failure(&state, &rendezvous_id);
            return Ok(lease_renew_not_found());
        }
    };

    // Hash + constant-time compare happen inside the DB call
    // (`PairingLeaseVerifier::Secret`), under the sole writer mutex, so the
    // presented secret is never compared against a row state a concurrent writer
    // already changed, and no caller-side boolean can be replayed into a stale
    // decision.
    let db = state.db.clone();
    let rid = rendezvous_id.clone();
    let max_leased = state.config.pairing_lease_max_concurrent_sessions();
    let outcome = tokio::task::spawn_blocking(move || {
        db.with_conn(|conn| {
            db::renew_pairing_lease(conn, &rid, PairingLeaseVerifier::Secret(&secret), max_leased)
        })
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| AppError::Internal(e.to_string()))?;

    match outcome {
        PairingLeaseRenewOutcome::Renewed { .. } => {
            // Bounded aggregate only: no rendezvous ID, IP, or timing is
            // recorded, and nothing about the related upload is learned.
            state.metrics.inc(&state.metrics.pairing_lease_renewed);
            tracing::debug!("Pairing lease renewed");
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        PairingLeaseRenewOutcome::Saturated | PairingLeaseRenewOutcome::NotFound => {
            // This is the only path that touches the per-rendezvous failure
            // budget: a request that failed verification. Because the budget is
            // *observed* here rather than consulted before the attempt, an
            // attacker who knows a rendezvous ID can never spend the legitimate
            // initiator's admission for that ID — their garbage is counted, but
            // it never gates the real renewal.
            //
            // `Saturated` is counted identically so no metric separates "global
            // cap reached" from "wrong secret", and neither outcome differs on
            // the wire.
            record_lease_failure(&state, &rendezvous_id);
            Ok(lease_renew_not_found())
        }
    }
}

/// Count one failed lease-verifier attempt against the presented rendezvous ID.
///
/// The key is derived from the *presented* ID uniformly, whether or not a row
/// exists for it, so the bucket cannot be used to distinguish real IDs from
/// invented ones by observing whether counting happened. Nothing is written to
/// the DB and no ID is logged.
///
/// The bucket key is a fixed-size, domain-separated SHA-256 digest of the
/// presented segment, never the raw segment itself. The segment is
/// attacker-controlled path data, so retaining it verbatim would let one request
/// with a multi-megabyte "rendezvous ID" plant a multi-megabyte map key; hashing
/// caps every key at [`PAIRING_LEASE_FAILURE_KEY_DIGEST_LEN`] bytes (64 lowercase
/// hex chars) regardless of input. The digest stays deterministic, so repeated
/// probes of one ID still share a bucket and legitimate failed-attempt semantics
/// are unchanged.
fn record_lease_failure(state: &AppState, rendezvous_id: &str) {
    let over_budget = state.pairing_lease_failure_limiter.record_failure(
        &lease_failure_bucket_key(rendezvous_id),
        state.config.pairing_lease.failure_limit,
        state.config.pairing_lease_failure_window_secs(),
    );
    if over_budget {
        state.metrics.inc(&state.metrics.pairing_lease_renew_rejected_rate_limited);
    } else {
        state.metrics.inc(&state.metrics.pairing_lease_renew_not_found);
    }
}

/// Length in bytes of the per-rendezvous failure-bucket key: a hex-encoded
/// SHA-256 digest.
const PAIRING_LEASE_FAILURE_KEY_DIGEST_LEN: usize = 64;

/// Domain-separation prefix for the failure-bucket key digest.
///
/// Kept byte-identical to the pre-hardening literal so the key space does not
/// shift: the digest is taken over `"lease-renew-failure:{rendezvous_id}"`, which
/// is exactly the string the map key used to be. The digest therefore only
/// *bounds* the key — it does not re-partition buckets.
const PAIRING_LEASE_FAILURE_KEY_DOMAIN: &str = "lease-renew-failure";

/// Derive the fixed-size failure-bucket key for a presented rendezvous ID.
///
/// Exposed within the crate so tests can assert that arbitrarily large or
/// malformed inputs still yield a bounded key. See [`record_lease_failure`] for
/// why the raw segment must never be the key.
pub(crate) fn lease_failure_bucket_key(rendezvous_id: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(PAIRING_LEASE_FAILURE_KEY_DOMAIN.as_bytes());
    hasher.update(b":");
    hasher.update(rendezvous_id.as_bytes());
    let key = hex::encode(hasher.finalize());
    // Fixed by construction (SHA-256 → 32 bytes → 64 hex chars). Pinning it here
    // keeps the test-visible constant and the real output from drifting.
    debug_assert_eq!(key.len(), PAIRING_LEASE_FAILURE_KEY_DIGEST_LEN);
    key
}

// ---------------------------------------------------------------------------
// DELETE /v1/pairing/{rendezvous_id}
// ---------------------------------------------------------------------------

async fn delete_session(
    State(state): State<AppState>,
    Path(rendezvous_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let db = state.db.clone();
    let rid = rendezvous_id;

    tokio::task::spawn_blocking(move || {
        db.with_conn(|conn| db::delete_pairing_session(conn, &rid))
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn client_ip_key(peer_addr: SocketAddr) -> String {
    peer_addr.ip().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};

    /// A 32-byte value whose standard and URL-safe encodings genuinely differ.
    ///
    /// `0xFB, 0xFF` encode to `+/` in the standard alphabet and `-_` in the
    /// URL-safe one, so a relay that only understood one alphabet would decode
    /// the other to `None` and silently downgrade the offer. Both encodings of
    /// this value must therefore be accepted and round-trip to the same bytes.
    const PLUS_SLASH_BYTES: [u8; 32] = [
        0xFB, 0xFF, 0xFB, 0xFF, 0xFB, 0xFF, 0xFB, 0xFF, 0xFB, 0xFF, 0xFB, 0xFF, 0xFB, 0xFF, 0xFB,
        0xFF, 0xFB, 0xFF, 0xFB, 0xFF, 0xFB, 0xFF, 0xFB, 0xFF, 0xFB, 0xFF, 0xFB, 0xFF, 0xFB, 0xFF,
        0xFB, 0xFF,
    ];

    #[test]
    fn standard_and_url_safe_encodings_of_the_probe_bytes_differ() {
        // Guards the test fixture itself: if a future base64 bump made these
        // encodings identical, the dual-alphabet tests below would pass
        // vacuously.
        assert_ne!(
            STANDARD.encode(PLUS_SLASH_BYTES),
            URL_SAFE.encode(PLUS_SLASH_BYTES),
            "the fixture must exercise `+`/`/` vs `-`/`_`"
        );
        assert!(STANDARD.encode(PLUS_SLASH_BYTES).contains('+'));
        assert!(STANDARD.encode(PLUS_SLASH_BYTES).contains('/'));
        assert!(URL_SAFE.encode(PLUS_SLASH_BYTES).contains('-'));
        assert!(URL_SAFE.encode(PLUS_SLASH_BYTES).contains('_'));
    }

    #[test]
    fn lease_key_hash_accepts_all_four_base64_forms() {
        for engine_encoded in [
            STANDARD.encode(PLUS_SLASH_BYTES),
            STANDARD_NO_PAD.encode(PLUS_SLASH_BYTES),
            URL_SAFE.encode(PLUS_SLASH_BYTES),
            URL_SAFE_NO_PAD.encode(PLUS_SLASH_BYTES),
        ] {
            assert_eq!(
                decode_lease_key_hash(&engine_encoded),
                Some(PLUS_SLASH_BYTES),
                "every accepted alphabet must decode identically: {engine_encoded}"
            );
        }
    }

    #[test]
    fn lease_key_hash_requires_exactly_32_bytes_in_every_alphabet() {
        // `try_from` requires the exact length, so any other byte count — in any
        // alphabet — must downgrade rather than truncate or pad.
        for len in [0usize, 16, 31, 33, 64, 256] {
            let bytes = vec![0x41u8; len];
            for encoded in [
                STANDARD.encode(&bytes),
                STANDARD_NO_PAD.encode(&bytes),
                URL_SAFE.encode(&bytes),
                URL_SAFE_NO_PAD.encode(&bytes),
            ] {
                assert_eq!(
                    decode_lease_key_hash(&encoded),
                    None,
                    "{len}-byte value must be rejected: {encoded}"
                );
            }
        }
    }

    #[test]
    fn lease_key_hash_rejects_malformed_and_mixed_alphabet_values() {
        for malformed in [
            "",
            "not!base64!!",
            "====",
            // 32 bytes' worth of standard padding is only valid padded; a
            // no-pad engine must not silently accept a padded string and vice
            // versa, and a mixed-alphabet string matches neither.
            "AAAA+///AAA-___AAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ] {
            assert_eq!(
                decode_lease_key_hash(malformed),
                None,
                "malformed input must downgrade with no echo: {malformed}"
            );
        }
    }

    #[test]
    fn failure_bucket_key_is_bounded_for_any_input() {
        // A hostile, multi-megabyte path segment must not become a multi-megabyte
        // map key. The digest key is a fixed 64 hex chars for any input length.
        let huge = "a".repeat(4 * 1024 * 1024);
        let medium = "a".repeat(65536);
        for input in [
            "",
            "x",
            "0123456789abcdef0123456789abcdef",
            medium.as_str(),
            huge.as_str(),
            "!!! not a rendezvous id !!!",
        ] {
            let key = lease_failure_bucket_key(input);
            assert_eq!(
                key.len(),
                PAIRING_LEASE_FAILURE_KEY_DIGEST_LEN,
                "the key must be a fixed size regardless of input length"
            );
            assert!(
                key.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
                "the key must be lowercase hex"
            );
        }
    }

    #[test]
    fn failure_bucket_key_is_deterministic_and_id_separating() {
        // Same ID ⇒ same bucket (so repeated probes accumulate and a legitimate
        // failure semantics are preserved); different IDs ⇒ different buckets (so
        // one ID's failures never gate another's).
        assert_eq!(lease_failure_bucket_key("abc"), lease_failure_bucket_key("abc"));
        assert_ne!(lease_failure_bucket_key("abc"), lease_failure_bucket_key("abd"));

        // The domain separation is over the exact legacy literal, so the digest
        // only bounds the key and does not re-partition buckets.
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"lease-renew-failure:abc");
        assert_eq!(lease_failure_bucket_key("abc"), hex::encode(hasher.finalize()));
    }
}
