//! HTTP layer: `GET /v1/info` and `POST /v1/grants` exactly as
//! `docs/CASHIER_API.md` specifies, plus `GET /healthz` for the process
//! supervisor.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;

use crate::cashu::{token_key, SwapError, Swapper, TokenSummary};
use crate::config::{Config, Offer};
use crate::grant::{IssuedGrant, Issuer};
use crate::store::{State as TokenState, Store};

/// Tokens are a few kilobytes; anything larger is not a purchase.
const MAX_BODY_BYTES: usize = 64 * 1024;

pub struct AppState {
    pub config: Config,
    pub issuer: Issuer,
    pub swapper: Box<dyn Swapper>,
    /// One mutex around the store serializes token handling; the swap is
    /// awaited under it so two concurrent requests for the same token cannot
    /// both reach the mint. Throughput is bounded by mint latency, which is
    /// fine for a service selling a few packs a minute.
    pub store: Mutex<Store>,
    pub clock: Box<dyn Fn() -> u64 + Send + Sync>,
}

#[derive(Serialize)]
struct InfoResponse<'a> {
    service: &'static str,
    version: u32,
    cashier_pubkey_hex: String,
    mints: &'a [String],
    offers: &'a [Offer],
    grant_ttl_secs: u64,
}

#[derive(Deserialize)]
pub struct GrantRequest {
    pub offer: Offer,
    pub token: String,
}

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub error: &'static str,
    pub message: String,
}

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub body: ErrorBody,
}

impl ApiError {
    fn new(status: StatusCode, error: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            body: ErrorBody {
                error,
                message: message.into(),
            },
        }
    }
    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_request", message)
    }
    pub fn wrong_amount(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "wrong_amount", message)
    }
    pub fn mint_not_accepted(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "mint_not_accepted", message)
    }
    pub fn token_rejected(message: impl Into<String>) -> Self {
        Self::new(StatusCode::PAYMENT_REQUIRED, "token_rejected", message)
    }
    pub fn mint_unavailable(message: impl Into<String>) -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, "mint_unavailable", message)
    }
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", message)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(self.body)).into_response()
    }
}

pub fn build_router(state: Arc<AppState>) -> Router {
    let allow_origin = if state.config.cors_origins.is_empty() {
        AllowOrigin::any()
    } else {
        AllowOrigin::list(
            state
                .config
                .cors_origins
                .iter()
                .filter_map(|o| HeaderValue::from_str(o).ok()),
        )
    };
    let cors = CorsLayer::new()
        .allow_origin(allow_origin)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([header::CONTENT_TYPE])
        .max_age(std::time::Duration::from_secs(3600));
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/info", get(info))
        .route("/v1/grants", post(grants))
        .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
        .layer(cors)
        .with_state(state)
}

async fn info(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let body = InfoResponse {
        service: "bitcoinpir-cashier",
        version: 1,
        cashier_pubkey_hex: state.issuer.public_key_hex(),
        mints: &state.config.mints,
        offers: &state.config.offers,
        grant_ttl_secs: state.issuer.ttl_secs(),
    };
    Json(serde_json::to_value(body).expect("info serializes"))
}

async fn grants(
    State(state): State<Arc<AppState>>,
    body: Result<Json<GrantRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<IssuedGrant>, ApiError> {
    let Json(request) = body.map_err(|e| ApiError::invalid_request(format!("body: {e}")))?;
    let offer = state
        .config
        .find_offer(&request.offer)
        .cloned()
        .ok_or_else(|| ApiError::invalid_request("unknown offer"))?;
    let encoded = request.token.trim();
    let summary =
        TokenSummary::parse(encoded).map_err(|e| ApiError::invalid_request(e.to_string()))?;
    if !state.config.accepts_mint(&summary.mint) {
        return Err(ApiError::mint_not_accepted(format!(
            "{} is not an accepted mint",
            summary.mint
        )));
    }
    if summary.unit != offer.unit || summary.amount != offer.amount {
        return Err(ApiError::wrong_amount(format!(
            "token is worth {} {}, offer costs {} {}",
            summary.amount, summary.unit, offer.amount, offer.unit
        )));
    }
    let key = token_key(&summary.secrets);
    let key_hex = hex::encode(key);
    let now = (state.clock)();

    let mut store = state.store.lock().await;
    let previous = store.get(&key_hex).cloned();
    if let Some(TokenState::Issued { grant, .. }) = &previous {
        if grant.expires_at > now {
            if grant.credits != offer.credits {
                return Err(ApiError::invalid_request(
                    "this token already bought a different pack; the original grant stands",
                ));
            }
            tracing::info!(grant_id = %grant.grant_id_hex, "replaying grant for a token seen before");
            return Ok(Json(grant.clone()));
        }
    }
    let outcome_unknown_before = matches!(previous, Some(TokenState::Pending { .. }));
    if !outcome_unknown_before {
        store
            .record(&key_hex, TokenState::Pending { first_seen: now })
            .map_err(|e| ApiError::internal(format!("store: {e}")))?;
    }
    let received = match state.swapper.receive(&summary, encoded).await {
        Ok(received) => received,
        Err(SwapError::Rejected(message)) => {
            if outcome_unknown_before {
                tracing::error!(token_key = %key_hex, %message,
                    "mint rejects a token whose earlier swap outcome was unknown; reconcile manually");
                return Err(ApiError::token_rejected(format!(
                    "the mint rejects this token and an earlier attempt's outcome is unknown (key {key_hex}); contact the operator"
                )));
            }
            store
                .record(
                    &key_hex,
                    TokenState::Failed {
                        at: now,
                        reason: message.clone(),
                    },
                )
                .map_err(|e| ApiError::internal(format!("store: {e}")))?;
            return Err(ApiError::token_rejected(message));
        }
        Err(SwapError::Unavailable(message)) => {
            if !outcome_unknown_before {
                store
                    .record(
                        &key_hex,
                        TokenState::Failed {
                            at: now,
                            reason: message.clone(),
                        },
                    )
                    .map_err(|e| ApiError::internal(format!("store: {e}")))?;
            }
            return Err(ApiError::mint_unavailable(message));
        }
        Err(SwapError::Unknown(message)) => {
            tracing::warn!(token_key = %key_hex, %message, "swap outcome unknown; keeping pending marker");
            return Err(ApiError::mint_unavailable(message));
        }
    };
    if received < offer.amount {
        tracing::warn!(token_key = %key_hex, received, face = offer.amount, "mint credited less than face value (input fees)");
    }
    let (issued, _bytes) = state
        .issuer
        .issue(&key, offer.credits, now)
        .map_err(|e| ApiError::internal(format!("sign: {e}")))?;
    store
        .record(
            &key_hex,
            TokenState::Issued {
                grant: issued.clone(),
                received,
                mint: summary.mint.clone(),
                unit: summary.unit.clone(),
            },
        )
        .map_err(|e| ApiError::internal(format!("store: {e}")))?;
    tracing::info!(grant_id = %issued.grant_id_hex, credits = issued.credits, received, mint = %summary.mint, "grant issued");
    Ok(Json(issued))
}
