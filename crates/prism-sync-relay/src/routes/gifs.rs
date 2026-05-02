use std::net::SocketAddr;
use std::time::Duration;

use axum::{
    body::Body,
    extract::{ConnectInfo, Extension, Path, Query, State},
    http::{HeaderValue, Response, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};

use crate::{
    config::{Config, GifProviderMode},
    errors::AppError,
    state::AppState,
};

use super::AuthIdentity;

const DEFAULT_GIF_LIMIT: u32 = 30;
const MAX_GIF_LIMIT: u32 = 50;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GifServiceCapabilities {
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_base_url: Option<String>,
    pub media_proxy_enabled: bool,
}

#[derive(Debug, Serialize)]
pub struct CapabilitiesResponse {
    pub gifs: GifServiceCapabilities,
}

#[derive(Debug, Deserialize)]
pub struct GifQuery {
    pub q: Option<String>,
    pub per_page: Option<u32>,
}

pub async fn get_capabilities(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthIdentity>,
    Path(path_sync_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    if path_sync_id != auth.sync_id {
        return Err(AppError::Forbidden("sync_id mismatch"));
    }

    Ok(Json(CapabilitiesResponse { gifs: gif_capabilities(&state.config) }))
}

pub async fn get_trending(
    State(state): State<AppState>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    Query(query): Query<GifQuery>,
) -> Result<Response<Body>, AppError> {
    enforce_gif_proxy_access(&state, peer_addr)?;
    proxy_gif_request(&state, build_upstream_uri(&state.config, None, query.per_page)?).await
}

pub async fn search_gifs(
    State(state): State<AppState>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    Query(query): Query<GifQuery>,
) -> Result<Response<Body>, AppError> {
    enforce_gif_proxy_access(&state, peer_addr)?;
    let trimmed = query.q.unwrap_or_default().trim().to_string();
    if trimmed.is_empty() {
        return proxy_gif_request(&state, build_upstream_uri(&state.config, None, query.per_page)?)
            .await;
    }

    let bounded_query = trimmed.chars().take(state.config.gif_query_max_len).collect::<String>();
    proxy_gif_request(
        &state,
        build_upstream_uri(&state.config, Some(bounded_query), query.per_page)?,
    )
    .await
}

fn gif_capabilities(config: &Config) -> GifServiceCapabilities {
    let api_base_url = match config.gif_provider_mode {
        GifProviderMode::Disabled => None,
        GifProviderMode::SelfHosted => {
            if config.gif_api_key.is_some() {
                Some(config.gif_public_base_url.clone().unwrap_or_else(|| "/v1/gifs".to_string()))
            } else {
                None
            }
        }
        GifProviderMode::PrismHosted => config.gif_prism_base_url.clone(),
    };

    GifServiceCapabilities {
        enabled: api_base_url.is_some(),
        api_base_url,
        media_proxy_enabled: false,
    }
}

fn enforce_gif_proxy_access(state: &AppState, peer_addr: SocketAddr) -> Result<(), AppError> {
    if state.config.gif_provider_mode != GifProviderMode::SelfHosted
        || state.config.gif_api_key.is_none()
    {
        return Err(AppError::NotFound);
    }

    let key = format!("gif:{}", peer_addr.ip());
    if !state.gif_request_rate_limiter.check(
        &key,
        state.config.gif_request_rate_limit,
        state.config.gif_request_rate_window_secs,
    ) {
        return Err(AppError::TooManyRequests);
    }

    Ok(())
}

fn build_upstream_uri(
    config: &Config,
    query: Option<String>,
    per_page: Option<u32>,
) -> Result<reqwest::Url, AppError> {
    let api_key = config.gif_api_key.as_deref().ok_or(AppError::NotFound)?;
    let limit = per_page.unwrap_or(DEFAULT_GIF_LIMIT).clamp(1, MAX_GIF_LIMIT);
    let path = if query.is_some() {
        format!("{}/api/v1/{api_key}/gifs/search", config.gif_api_base_url)
    } else {
        format!("{}/api/v1/{api_key}/gifs/trending", config.gif_api_base_url)
    };
    let mut url = reqwest::Url::parse(&path)
        .map_err(|_| AppError::Internal("invalid GIF API base URL".into()))?;
    url.query_pairs_mut()
        .append_pair("per_page", &limit.to_string())
        .append_pair("page", "1")
        .append_pair("content_filter", "medium");
    if let Some(query) = query {
        url.query_pairs_mut().append_pair("q", &query);
    }
    Ok(url)
}

async fn proxy_gif_request(
    state: &AppState,
    url: reqwest::Url,
) -> Result<Response<Body>, AppError> {
    let response = state
        .gif_http_client
        .get(url)
        .header("Accept", "application/json")
        .header("User-Agent", "PrismRelay/1.0")
        .timeout(Duration::from_secs(state.config.gif_http_timeout_secs))
        .send()
        .await
        .map_err(|e| {
            if e.is_timeout() {
                AppError::Internal("GIF provider request timed out".into())
            } else {
                AppError::Internal("GIF provider request failed".into())
            }
        })?;

    if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
        return Err(AppError::TooManyRequests);
    }
    if !response.status().is_success() {
        return Err(AppError::Internal(format!(
            "GIF provider returned upstream status {}",
            response.status().as_u16()
        )));
    }

    let body = response
        .bytes()
        .await
        .map_err(|_| AppError::Internal("Failed to read GIF provider response".into()))?;

    Response::builder()
        .status(StatusCode::OK)
        .header(axum::http::header::CONTENT_TYPE, HeaderValue::from_static("application/json"))
        .header(axum::http::header::CACHE_CONTROL, HeaderValue::from_static("private, max-age=60"))
        .body(Body::from(body))
        .map_err(|e| AppError::Internal(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> Config {
        let mut config = Config::from_env();
        config.gif_provider_mode = GifProviderMode::Disabled;
        config.gif_public_base_url = None;
        config.gif_prism_base_url = None;
        config.gif_api_base_url = "https://api.klipy.com".into();
        config.gif_api_key = None;
        config.gif_http_timeout_secs = 15;
        config.gif_request_rate_limit = 20;
        config.gif_request_rate_window_secs = 60;
        config.gif_query_max_len = 200;
        config
    }

    #[test]
    fn capabilities_disable_gifs_when_provider_is_disabled() {
        let config = test_config();
        assert_eq!(
            gif_capabilities(&config),
            GifServiceCapabilities {
                enabled: false,
                api_base_url: None,
                media_proxy_enabled: false,
            }
        );
    }

    #[test]
    fn capabilities_use_public_base_url_for_self_hosted_proxy() {
        let mut config = test_config();
        config.gif_provider_mode = GifProviderMode::SelfHosted;
        config.gif_api_key = Some("relay-secret".into());
        config.gif_public_base_url = Some("/custom/gifs".into());

        assert_eq!(
            gif_capabilities(&config),
            GifServiceCapabilities {
                enabled: true,
                api_base_url: Some("/custom/gifs".into()),
                media_proxy_enabled: false,
            }
        );
    }

    #[test]
    fn capabilities_use_prism_hosted_base_url_when_advertised() {
        let mut config = test_config();
        config.gif_provider_mode = GifProviderMode::PrismHosted;
        config.gif_prism_base_url = Some("https://gif.prism.app/v1/gifs".into());

        assert_eq!(
            gif_capabilities(&config),
            GifServiceCapabilities {
                enabled: true,
                api_base_url: Some("https://gif.prism.app/v1/gifs".into()),
                media_proxy_enabled: false,
            }
        );
    }

    #[test]
    fn build_upstream_uri_clamps_limit_and_includes_query() {
        let mut config = test_config();
        config.gif_api_key = Some("relay-secret".into());

        let url = build_upstream_uri(&config, Some("cats".into()), Some(500)).unwrap();

        assert_eq!(url.path(), "/api/v1/relay-secret/gifs/search");
        assert_eq!(url.query_pairs().find(|(k, _)| k == "q").unwrap().1, "cats");
        assert_eq!(url.query_pairs().find(|(k, _)| k == "per_page").unwrap().1, "50");
        assert_eq!(url.query_pairs().find(|(k, _)| k == "page").unwrap().1, "1");
    }

    #[test]
    fn build_upstream_uri_defaults_to_trending() {
        let mut config = test_config();
        config.gif_api_key = Some("relay-secret".into());

        let url = build_upstream_uri(&config, None, None).unwrap();

        assert_eq!(url.path(), "/api/v1/relay-secret/gifs/trending");
        assert_eq!(url.query_pairs().find(|(k, _)| k == "per_page").unwrap().1, "30");
    }
}
