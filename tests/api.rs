//! HTTP contract tests with a fake mint. Nothing here touches the network.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use bpir_cashier::api::{build_router, AppState};
use bpir_cashier::cashu::{token_key, SwapError, Swapper, TokenSummary};
use bpir_cashier::config::{Config, Offer};
use bpir_cashier::grant::Issuer;
use bpir_cashier::store::{State as TokenState, Store};
use http_body_util::BodyExt;
use pir_session_grant::{SessionGrant, TrustedIssuers};
use tokio::sync::Mutex;
use tower::ServiceExt;

const MINT: &str = "https://mint.example";

/// Scripted mint: answers per call from a queue, records every token it saw.
struct FakeSwapper {
    script: StdMutex<Vec<Result<u64, SwapError>>>,
    seen: StdMutex<Vec<String>>,
}

impl FakeSwapper {
    fn new(script: Vec<Result<u64, SwapError>>) -> Self {
        Self {
            script: StdMutex::new(script),
            seen: StdMutex::new(Vec::new()),
        }
    }
}

#[async_trait::async_trait]
impl Swapper for FakeSwapper {
    async fn receive(&self, _summary: &TokenSummary, encoded: &str) -> Result<u64, SwapError> {
        self.seen.lock().unwrap().push(encoded.to_string());
        let mut script = self.script.lock().unwrap();
        if script.is_empty() {
            panic!("fake mint called more often than scripted");
        }
        script.remove(0)
    }
}

struct Harness {
    app: axum::Router,
    state: Arc<AppState>,
    _dir: tempfile::TempDir,
}

fn config(dir: &std::path::Path) -> Config {
    toml::from_str(&format!(
        r#"
        listen = "127.0.0.1:0"
        grant_key_path = "{0}/grant.key"
        wallet_seed_path = "{0}/wallet.seed"
        wallet_db_path = "{0}/wallet.sqlite"
        store_path = "{0}/grants.jsonl"
        mints = ["{MINT}"]
        grant_ttl_secs = 3600
        cors_origins = ["https://www.bitcoinpir.org"]
        [[offers]]
        credits = 1000
        amount = 210
        unit = "sat"
        [[offers]]
        credits = 5000
        amount = 900
        unit = "sat"
        [[offers]]
        credits = 1200
        amount = 210
        unit = "sat"
        "#,
        dir.display()
    ))
    .unwrap()
}

static CLOCK: AtomicU64 = AtomicU64::new(1_800_000_000);

fn harness(script: Vec<Result<u64, SwapError>>) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    harness_in(dir, script)
}

fn harness_in(dir: tempfile::TempDir, script: Vec<Result<u64, SwapError>>) -> Harness {
    let config = config(dir.path());
    let store = Store::open(&config.store_path).unwrap();
    let state = Arc::new(AppState {
        config,
        issuer: Issuer::new(&[5u8; 32], 3600),
        swapper: Box::new(FakeSwapper::new(script)),
        store: Mutex::new(store),
        clock: Box::new(|| CLOCK.load(Ordering::SeqCst)),
    });
    Harness {
        app: build_router(Arc::clone(&state)),
        state,
        _dir: dir,
    }
}

fn offer(credits: u32, amount: u64) -> Offer {
    Offer {
        credits,
        amount,
        unit: "sat".into(),
    }
}

fn fake_token(amounts: &[u64]) -> String {
    bpir_cashier_test_token(MINT, "sat", amounts)
}

/// Same construction as `cashu::test_support::fake_token` (that helper is
/// `cfg(test)` inside the crate, so integration tests rebuild it here).
fn bpir_cashier_test_token(mint: &str, unit: &str, amounts: &[u64]) -> String {
    use cdk::mint_url::MintUrl;
    use cdk::nuts::{CurrencyUnit, Id, Proof, PublicKey, Token};
    use cdk::secret::Secret;
    use cdk::Amount;
    use std::str::FromStr;
    let keyset = Id::from_str("00ffd48b8f5ecf80").unwrap();
    let c =
        PublicKey::from_hex("02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2")
            .unwrap();
    let proofs: Vec<Proof> = amounts
        .iter()
        .map(|a| Proof::new(Amount::from(*a), keyset, Secret::generate(), c))
        .collect();
    Token::new(
        MintUrl::from_str(mint).unwrap(),
        proofs,
        None,
        CurrencyUnit::from_str(unit).unwrap(),
    )
    .to_string()
}

async fn post_grant(
    app: &axum::Router,
    offer: &Offer,
    token: &str,
) -> (StatusCode, serde_json::Value) {
    let body = serde_json::json!({ "offer": offer, "token": token }).to_string();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/grants")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

#[tokio::test]
async fn info_lists_pubkey_mints_offers_and_ttl_with_cors() {
    let h = harness(vec![]);
    let response = h
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/info")
                .header(header::ORIGIN, "https://www.bitcoinpir.org")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .unwrap(),
        "https://www.bitcoinpir.org"
    );
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["service"], "bitcoinpir-cashier");
    assert_eq!(v["version"], 1);
    assert_eq!(v["cashier_pubkey_hex"], h.state.issuer.public_key_hex());
    assert_eq!(v["mints"], serde_json::json!([MINT]));
    assert_eq!(v["offers"].as_array().unwrap().len(), 3);
    assert_eq!(
        v["offers"][0],
        serde_json::json!({"credits": 1000, "amount": 210, "unit": "sat"})
    );
    assert_eq!(v["grant_ttl_secs"], 3600);
    assert_eq!(
        v["costs"],
        serde_json::json!({"frame": 1, "harmony_hint_set": 150})
    );
}

#[tokio::test]
async fn paid_token_yields_a_verifiable_grant_and_replays_idempotently() {
    let h = harness(vec![Ok(210)]);
    let token = fake_token(&[128, 64, 16, 2]);
    let (status, body) = post_grant(&h.app, &offer(1000, 210), &token).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["credits"], 1000);
    assert_eq!(body["issued_at"], 1_800_000_000u64);
    assert_eq!(body["expires_at"], 1_800_003_600u64);
    let grant_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        body["grant_base64"].as_str().unwrap(),
    )
    .unwrap();
    let grant = SessionGrant::decode(&grant_bytes).unwrap();
    let issuers = TrustedIssuers::new(&[h.state.issuer.public_key()]).unwrap();
    let verified = grant.verify(&issuers, 1_800_000_100).unwrap();
    assert_eq!(verified.credits, 1000);
    assert_eq!(hex::encode(verified.grant_id), body["grant_id_hex"]);
    let summary = TokenSummary::parse(&token).unwrap();
    assert_eq!(
        body["grant_id_hex"],
        hex::encode(&token_key(&summary.secrets)[..16])
    );

    // Same token again: same grant, mint not consulted (the script is empty).
    let (status2, body2) = post_grant(&h.app, &offer(1000, 210), &token).await;
    assert_eq!(status2, StatusCode::OK);
    assert_eq!(body2, body);
    // Same token, a pack of another price: the face-value check fires first.
    let (status3, body3) = post_grant(&h.app, &offer(5000, 900), &token).await;
    assert_eq!(status3, StatusCode::BAD_REQUEST);
    assert_eq!(body3["error"], "wrong_amount");
    // Same token, same price but more credits: refused, the original grant stands.
    let (status4, body4) = post_grant(&h.app, &offer(1200, 210), &token).await;
    assert_eq!(status4, StatusCode::BAD_REQUEST);
    assert_eq!(body4["error"], "invalid_request");
    let (status5, body5) = post_grant(&h.app, &offer(1000, 210), &token).await;
    assert_eq!((status5, body5), (StatusCode::OK, body));
}

#[tokio::test]
async fn validation_errors_never_reach_the_mint() {
    let h = harness(vec![]);
    let (s, b) = post_grant(&h.app, &offer(1000, 210), "cashuBgarbage").await;
    assert_eq!(
        (s, b["error"].as_str().unwrap()),
        (StatusCode::BAD_REQUEST, "invalid_request")
    );
    let (s, b) = post_grant(&h.app, &offer(1000, 211), &fake_token(&[211])).await;
    assert_eq!(
        (s, b["error"].as_str().unwrap()),
        (StatusCode::BAD_REQUEST, "invalid_request"),
        "unknown offer"
    );
    let (s, b) = post_grant(&h.app, &offer(1000, 210), &fake_token(&[200])).await;
    assert_eq!(
        (s, b["error"].as_str().unwrap()),
        (StatusCode::BAD_REQUEST, "wrong_amount")
    );
    let (s, b) = post_grant(
        &h.app,
        &offer(1000, 210),
        &bpir_cashier_test_token("https://other.example", "sat", &[210]),
    )
    .await;
    assert_eq!(
        (s, b["error"].as_str().unwrap()),
        (StatusCode::BAD_REQUEST, "mint_not_accepted")
    );
    let (s, b) = post_grant(
        &h.app,
        &offer(1000, 210),
        &bpir_cashier_test_token(MINT, "usd", &[210]),
    )
    .await;
    assert_eq!(
        (s, b["error"].as_str().unwrap()),
        (StatusCode::BAD_REQUEST, "wrong_amount")
    );
    let malformed = h
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/grants")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
    assert!(h.state.store.lock().await.get("anything").is_none());
}

#[tokio::test]
async fn mint_rejection_and_outage_map_to_402_and_503_and_allow_retry() {
    let h = harness(vec![
        Err(SwapError::Unavailable("connection refused".into())),
        Err(SwapError::Rejected("Token already spent".into())),
        Ok(210),
    ]);
    let token = fake_token(&[210]);
    let (s, b) = post_grant(&h.app, &offer(1000, 210), &token).await;
    assert_eq!(
        (s, b["error"].as_str().unwrap()),
        (StatusCode::SERVICE_UNAVAILABLE, "mint_unavailable")
    );
    let (s, b) = post_grant(&h.app, &offer(1000, 210), &token).await;
    assert_eq!(
        (s, b["error"].as_str().unwrap()),
        (StatusCode::PAYMENT_REQUIRED, "token_rejected")
    );
    // A later attempt (e.g. the mint recovered a pending state) may still succeed.
    let (s, _) = post_grant(&h.app, &offer(1000, 210), &token).await;
    assert_eq!(s, StatusCode::OK);
    let key = hex::encode(token_key(&TokenSummary::parse(&token).unwrap().secrets));
    assert!(matches!(
        h.state.store.lock().await.get(&key),
        Some(TokenState::Issued { .. })
    ));
}

#[tokio::test]
async fn unknown_outcome_keeps_the_pending_marker_and_is_reported_honestly() {
    let h = harness(vec![
        Err(SwapError::Unknown("timeout".into())),
        Err(SwapError::Rejected("Token already spent".into())),
    ]);
    let token = fake_token(&[210]);
    let (s, b) = post_grant(&h.app, &offer(1000, 210), &token).await;
    assert_eq!(
        (s, b["error"].as_str().unwrap()),
        (StatusCode::SERVICE_UNAVAILABLE, "mint_unavailable")
    );
    let key = hex::encode(token_key(&TokenSummary::parse(&token).unwrap().secrets));
    assert!(matches!(
        h.state.store.lock().await.get(&key),
        Some(TokenState::Pending { .. })
    ));
    let (s, b) = post_grant(&h.app, &offer(1000, 210), &token).await;
    assert_eq!(
        (s, b["error"].as_str().unwrap()),
        (StatusCode::PAYMENT_REQUIRED, "token_rejected")
    );
    assert!(b["message"].as_str().unwrap().contains("unknown"));
    assert!(matches!(
        h.state.store.lock().await.get(&key),
        Some(TokenState::Pending { .. })
    ));
}

#[tokio::test]
async fn issued_grants_survive_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let token = fake_token(&[210]);
    let first = {
        let h = harness_in(dir, vec![Ok(210)]);
        let (s, b) = post_grant(&h.app, &offer(1000, 210), &token).await;
        assert_eq!(s, StatusCode::OK);
        // Reopen the same directory: the harness owns the TempDir, so hand it back.
        (b, h._dir)
    };
    let h = harness_in(first.1, vec![]);
    let (s, b) = post_grant(&h.app, &offer(1000, 210), &token).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b, first.0);
}
