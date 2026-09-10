//! BitcoinPIR cashier: sells Ed25519 [session grants] for Cashu ecash.
//!
//! The HTTP contract (`GET /v1/info`, `POST /v1/grants`, error codes,
//! idempotency) is `docs/CASHIER_API.md` in the Bitcoin-PIR/Bitcoin-PIR
//! repository; the grant format is the `pir-session-grant` crate from the
//! same repository, pinned here by git revision so the cashier and the PIR
//! servers can never disagree on the bytes.
//!
//! Request flow for `POST /v1/grants`:
//!
//! 1. validate the body: a listed offer and a parseable `cashuB…` token;
//! 2. summarize the token offline (mint, unit, face value, proof secrets)
//!    and reject anything that is not exactly the offer at an accepted mint;
//! 3. derive the idempotency key from the proof secrets and replay an
//!    unexpired grant already issued for that token;
//! 4. record a `pending` marker, swap (receive) the token at the mint through
//!    the [`cashu::Swapper`], and only after the mint accepted it sign and
//!    persist the grant.
//!
//! [session grants]: https://github.com/Bitcoin-PIR/Bitcoin-PIR/blob/main/docs/SESSION_GRANTS.md

pub mod api;
pub mod arc;
pub mod cashu;
pub mod config;
pub mod grant;
pub mod redeem;
pub mod store;

/// Unix seconds now. The grant crate takes the clock as a parameter; this is
/// the only place the cashier reads it.
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
