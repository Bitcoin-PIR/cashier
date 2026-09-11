//! HTTP layer: `GET /v1/info` and `POST /v1/grants` exactly as
//! `docs/CASHIER_API.md` specifies, `GET /v2/info` and `POST /v2/redeem`
//! as `docs/CREDITS.md` specifies, plus `GET /healthz` for the process
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

use ed25519_dalek::VerifyingKey;
use pir_credit::issuer::{
    IssuerInfoV2, OfferV2, RateCardEntryV2, RedeemRequestV1, RedeemResponseV1,
    CREDIT_PRESENT_KIND_ARC, CREDIT_PRESENT_KIND_CASHU, ISSUER_API_VERSION,
};

use crate::cashu::{token_key, SwapError, Swapper, TokenSummary};
use crate::config::{Config, Costs, Offer};
use crate::grant::{IssuedGrant, Issuer};
use crate::redeem::{verify_request, RedeemEvent, RedeemStore};
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
    /// Replay index and settlement ledger of `POST /v2/redeem`. Locked
    /// after `store`, never before it.
    pub redeem_store: Mutex<RedeemStore>,
    /// Operator keys whose certified servers may redeem (from
    /// `operator_pubkeys`).
    pub operator_keys: Vec<VerifyingKey>,
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
    costs: &'a Costs,
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
    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthorized", message)
    }
    pub fn unsupported_kind(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "unsupported_kind", message)
    }
    pub fn already_redeemed(message: impl Into<String>) -> Self {
        Self::new(StatusCode::PAYMENT_REQUIRED, "already_redeemed", message)
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
        .route("/v2/info", get(info_v2))
        .route("/v2/redeem", post(redeem))
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
        costs: &state.config.costs,
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

/// `GET /v2/info` (docs/CREDITS.md): the credits contract parameters,
/// sat-priced offers, and the informational rate card.
async fn info_v2(State(state): State<Arc<AppState>>) -> Json<IssuerInfoV2> {
    let gas = state.config.gas.params();
    Json(IssuerInfoV2 {
        service: "bitcoinpir-cashier".to_owned(),
        version: ISSUER_API_VERSION,
        credit_sat: gas.credit_sat,
        gas_per_credit: gas.gas_per_credit,
        base_gas_per_frame: gas.base_gas_per_frame,
        egress_gas_per_mb: gas.egress_gas_per_mb,
        mints: state.config.mints.clone(),
        offers: state
            .config
            .offers
            .iter()
            .filter(|offer| offer.unit == "sat")
            .map(|offer| OfferV2 {
                credits: u64::from(offer.credits),
                sat: offer.amount,
            })
            .collect(),
        arc: None,
        rate_card: state
            .config
            .rate_card
            .iter()
            .map(|entry| RateCardEntryV2 {
                flow: entry.flow.clone(),
                credits: entry.credits,
            })
            .collect(),
    })
}

/// `POST /v2/redeem` (docs/CREDITS.md): authenticate the server, settle
/// every item, book the value, answer with signed gas. All or nothing: an
/// item the mint refuses fails the whole request and nothing is booked.
async fn redeem(
    State(state): State<Arc<AppState>>,
    body: Result<Json<RedeemRequestV1>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<RedeemResponseV1>, ApiError> {
    let Json(request) = body.map_err(|e| ApiError::invalid_request(format!("body: {e}")))?;
    let now = (state.clock)();
    let verified = verify_request(
        &request,
        &state.operator_keys,
        now,
        state.config.redeem_max_skew_secs,
    )?;
    let gas = state.config.gas.params();

    // Lock order: token store first, redeem store second (see AppState).
    let mut store = state.store.lock().await;
    let mut redeem_store = state.redeem_store.lock().await;
    if let Some(answer) = redeem_store.answer(&verified.server_id, &verified.nonce_hex) {
        tracing::info!(server_id = %verified.server_id, "replaying a redeem answer for a nonce seen before");
        return Ok(Json(answer));
    }

    let mut gas_added: u64 = 0;
    let mut sat_value: u64 = 0;
    let mut items_accepted: u32 = 0;
    for (kind, payload) in &verified.items {
        match *kind {
            CREDIT_PRESENT_KIND_CASHU => {
                let encoded = std::str::from_utf8(payload)
                    .map_err(|_| ApiError::invalid_request("Cashu token is not UTF-8"))?
                    .trim();
                let summary = TokenSummary::parse(encoded)
                    .map_err(|e| ApiError::invalid_request(e.to_string()))?;
                if !state.config.accepts_mint(&summary.mint) {
                    return Err(ApiError::mint_not_accepted(format!(
                        "{} is not an accepted mint",
                        summary.mint
                    )));
                }
                if summary.unit != "sat" {
                    return Err(ApiError::wrong_amount(format!(
                        "token unit {} is not sat",
                        summary.unit
                    )));
                }
                let key_hex = hex::encode(token_key(&summary.secrets));
                match store.get(&key_hex) {
                    Some(TokenState::Issued { .. }) => {
                        return Err(ApiError::already_redeemed(
                            "this token already bought a session grant",
                        ));
                    }
                    Some(TokenState::Redeemed { server_id, .. }) => {
                        return Err(ApiError::already_redeemed(format!(
                            "this token was already redeemed through {server_id}"
                        )));
                    }
                    Some(TokenState::Pending { .. }) => {
                        tracing::error!(token_key = %key_hex,
                            "token with an unknown earlier swap outcome presented again; reconcile manually");
                        return Err(ApiError::token_rejected(format!(
                            "an earlier attempt with this token has an unknown outcome (key {key_hex}); contact the operator"
                        )));
                    }
                    Some(TokenState::Failed { .. }) | None => {}
                }
                store
                    .record(&key_hex, TokenState::Pending { first_seen: now })
                    .map_err(|e| ApiError::internal(format!("store: {e}")))?;
                let received = match state.swapper.receive(&summary, encoded).await {
                    Ok(received) => received,
                    Err(SwapError::Rejected(message)) => {
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
                        store
                            .record(
                                &key_hex,
                                TokenState::Failed {
                                    at: now,
                                    reason: message.clone(),
                                },
                            )
                            .map_err(|e| ApiError::internal(format!("store: {e}")))?;
                        return Err(ApiError::mint_unavailable(message));
                    }
                    Err(SwapError::Unknown(message)) => {
                        tracing::warn!(token_key = %key_hex, %message, "swap outcome unknown; keeping pending marker");
                        return Err(ApiError::mint_unavailable(message));
                    }
                };
                if received == 0 {
                    return Err(ApiError::token_rejected(
                        "the mint credited nothing for this token",
                    ));
                }
                store
                    .record(
                        &key_hex,
                        TokenState::Redeemed {
                            server_id: verified.server_id.clone(),
                            received,
                            mint: summary.mint.clone(),
                            unit: summary.unit.clone(),
                        },
                    )
                    .map_err(|e| ApiError::internal(format!("store: {e}")))?;
                gas_added = gas_added.saturating_add(gas.sats_to_gas(received));
                sat_value = sat_value.saturating_add(received);
                items_accepted += 1;
            }
            CREDIT_PRESENT_KIND_ARC => {
                return Err(ApiError::unsupported_kind(
                    "ARC presentations are not accepted by this cashier yet",
                ));
            }
            other => {
                return Err(ApiError::invalid_request(format!(
                    "unknown presentation kind {other}"
                )));
            }
        }
    }

    let preimage =
        RedeemResponseV1::signing_preimage(&verified.nonce, gas_added, sat_value, items_accepted);
    let issuer_signature_hex = hex::encode(state.issuer.sign(&preimage));
    let event = RedeemEvent {
        server_id: verified.server_id.clone(),
        nonce_hex: verified.nonce_hex.clone(),
        unix_time: now,
        gas_added,
        sat_value,
        items_accepted,
        issuer_signature_hex,
    };
    let answer = event.response();
    redeem_store
        .record(event)
        .map_err(|e| ApiError::internal(format!("redeem store: {e}")))?;
    tracing::info!(server_id = %verified.server_id, gas_added, sat_value, items_accepted, "redeemed");
    Ok(Json(answer))
}
