//! TOML configuration. Everything an operator decides lives here; nothing is
//! hard-coded in the binary except the contract itself.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// One purchasable pack, exactly as `GET /v1/info` lists it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Offer {
    /// Credits the grant carries (one credit per query-bearing frame).
    pub credits: u32,
    /// Price in `unit`.
    pub amount: u64,
    /// Cashu currency unit, e.g. `sat`.
    pub unit: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Socket the HTTP server binds. Put a reverse proxy or a Cloudflare
    /// tunnel in front; the cashier speaks plain HTTP.
    pub listen: SocketAddr,
    /// 32-byte Ed25519 seed (raw, or 64 hex characters) that signs grants.
    /// The PIR servers pin the matching public key.
    pub grant_key_path: PathBuf,
    /// 64-byte seed (raw, or 128 hex characters) for the Cashu wallet keys.
    pub wallet_seed_path: PathBuf,
    /// SQLite file the Cashu wallet keeps its proofs in.
    pub wallet_db_path: PathBuf,
    /// Append-only JSON-lines file recording every token seen and every
    /// grant issued (idempotency and operator reconciliation).
    pub store_path: PathBuf,
    /// Mints whose ecash is accepted (https only).
    pub mints: Vec<String>,
    /// Packs on sale.
    pub offers: Vec<Offer>,
    /// Lifetime stamped on issued grants. The PIR servers refuse grants
    /// living longer than 30 days.
    #[serde(default = "default_ttl")]
    pub grant_ttl_secs: u64,
    /// Browser origins allowed by CORS. Empty means any origin, which is
    /// safe because the API uses no cookies and no ambient credentials.
    #[serde(default)]
    pub cors_origins: Vec<String>,
    /// Prices the PIR servers charge, published in `GET /v1/info` as
    /// `costs`. Informational: the servers enforce their own flags
    /// (`--session-grant-hint-credits`); keep both in step.
    #[serde(default)]
    pub costs: Costs,
    /// Credits contract parameters published in `GET /v2/info` and used to
    /// turn redeemed sats into gas (`docs/CREDITS.md`).
    #[serde(default)]
    pub gas: GasConfig,
    /// Operator identity keys (64 hex) whose certified servers may redeem
    /// here. Empty keeps `POST /v2/redeem` refused.
    #[serde(default)]
    pub operator_pubkeys: Vec<String>,
    /// Tolerated difference between a redeem request's clock and ours.
    #[serde(default = "default_redeem_skew")]
    pub redeem_max_skew_secs: u64,
    /// Append-only JSON-lines log of every redemption (replay index and
    /// settlement ledger). Defaults to `redeem.jsonl` next to `store_path`.
    #[serde(default)]
    pub redeem_store_path: Option<PathBuf>,
    /// Worst-case prices published in `GET /v2/info` as `rate_card`
    /// (informational; the servers meter gas).
    #[serde(default = "default_rate_card")]
    pub rate_card: Vec<RateCardEntry>,
}

/// The `[gas]` table: `pir_credit::GasParams` with the 2026-09 defaults.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GasConfig {
    #[serde(default = "default_credit_sat")]
    pub credit_sat: u64,
    #[serde(default = "default_gas_per_credit")]
    pub gas_per_credit: u64,
    #[serde(default = "default_base_gas_per_frame")]
    pub base_gas_per_frame: u64,
    #[serde(default = "default_egress_gas_per_mb")]
    pub egress_gas_per_mb: u64,
}

impl GasConfig {
    pub fn params(&self) -> pir_credit::GasParams {
        pir_credit::GasParams {
            credit_sat: self.credit_sat,
            gas_per_credit: self.gas_per_credit,
            base_gas_per_frame: self.base_gas_per_frame,
            egress_gas_per_mb: self.egress_gas_per_mb,
        }
    }
}

impl Default for GasConfig {
    fn default() -> Self {
        let p = pir_credit::GasParams::PRODUCTION_2026_09;
        Self {
            credit_sat: p.credit_sat,
            gas_per_credit: p.gas_per_credit,
            base_gas_per_frame: p.base_gas_per_frame,
            egress_gas_per_mb: p.egress_gas_per_mb,
        }
    }
}

fn default_credit_sat() -> u64 {
    pir_credit::GasParams::PRODUCTION_2026_09.credit_sat
}

fn default_gas_per_credit() -> u64 {
    pir_credit::GasParams::PRODUCTION_2026_09.gas_per_credit
}

fn default_base_gas_per_frame() -> u64 {
    pir_credit::GasParams::PRODUCTION_2026_09.base_gas_per_frame
}

fn default_egress_gas_per_mb() -> u64 {
    pir_credit::GasParams::PRODUCTION_2026_09.egress_gas_per_mb
}

fn default_redeem_skew() -> u64 {
    300
}

/// One `[[rate_card]]` line.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateCardEntry {
    pub flow: String,
    pub credits: u64,
}

fn default_rate_card() -> Vec<RateCardEntry> {
    [
        ("onion_single_address", 10),
        ("harmony_fresh_client", 5),
        ("dpf_single_address", 2),
        ("oram_single_address", 1),
    ]
    .into_iter()
    .map(|(flow, credits)| RateCardEntry {
        flow: flow.to_owned(),
        credits,
    })
    .collect()
}

/// Credits per metered unit, mirrored from the servers' flags.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Costs {
    /// One query-bearing request frame.
    #[serde(default = "default_frame_cost")]
    pub frame: u32,
    /// One HarmonyPIR hint set (`--session-grant-hint-credits`).
    #[serde(default = "default_hint_set_cost")]
    pub harmony_hint_set: u32,
}

fn default_frame_cost() -> u32 {
    1
}

fn default_hint_set_cost() -> u32 {
    150
}

impl Default for Costs {
    fn default() -> Self {
        Self {
            frame: default_frame_cost(),
            harmony_hint_set: default_hint_set_cost(),
        }
    }
}

fn default_ttl() -> u64 {
    86_400
}

/// Server-side maximum lifetime, mirrored from `pir_session_grant`, minus the
/// tolerated clock skew so a grant issued at the limit still verifies.
pub const MAX_GRANT_TTL_SECS: u64 =
    pir_session_grant::MAX_LIFETIME_SECS - pir_session_grant::MAX_CLOCK_SKEW_SECS;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("read {0}: {1}")]
    Read(PathBuf, std::io::Error),
    #[error("parse {0}: {1}")]
    Parse(PathBuf, toml::de::Error),
    #[error("{0}")]
    Invalid(String),
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text =
            std::fs::read_to_string(path).map_err(|e| ConfigError::Read(path.to_path_buf(), e))?;
        let config: Config =
            toml::from_str(&text).map_err(|e| ConfigError::Parse(path.to_path_buf(), e))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.mints.is_empty() {
            return Err(ConfigError::Invalid(
                "mints must list at least one mint".into(),
            ));
        }
        for mint in &self.mints {
            if !mint.starts_with("https://") || mint.len() <= "https://".len() {
                return Err(ConfigError::Invalid(format!(
                    "mint is not an https URL: {mint}"
                )));
            }
            if mint.ends_with('/') {
                return Err(ConfigError::Invalid(format!(
                    "mint URL must not end with a slash (tokens carry it without one): {mint}"
                )));
            }
        }
        if self.offers.is_empty() {
            return Err(ConfigError::Invalid(
                "offers must list at least one pack".into(),
            ));
        }
        for offer in &self.offers {
            if offer.credits == 0 || offer.amount == 0 || offer.unit.is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "offer has a zero field: {offer:?}"
                )));
            }
        }
        let mut seen = std::collections::BTreeSet::new();
        for offer in &self.offers {
            if !seen.insert((offer.credits, offer.amount, offer.unit.clone())) {
                return Err(ConfigError::Invalid(format!(
                    "offer listed twice: {offer:?}"
                )));
            }
        }
        if self.grant_ttl_secs == 0 || self.grant_ttl_secs > MAX_GRANT_TTL_SECS {
            return Err(ConfigError::Invalid(format!(
                "grant_ttl_secs must be 1..={MAX_GRANT_TTL_SECS}"
            )));
        }
        if self.costs.frame == 0 || self.costs.harmony_hint_set == 0 {
            return Err(ConfigError::Invalid("costs must be positive".into()));
        }
        self.gas
            .params()
            .validate()
            .map_err(|e| ConfigError::Invalid(format!("gas: {e}")))?;
        for key in &self.operator_pubkeys {
            let bytes = hex::decode(key).map_err(|_| {
                ConfigError::Invalid(format!("operator_pubkeys: {key:?} is not hex"))
            })?;
            let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
                ConfigError::Invalid(format!("operator_pubkeys: {key:?} is not 32 bytes"))
            })?;
            ed25519_dalek::VerifyingKey::from_bytes(&bytes).map_err(|_| {
                ConfigError::Invalid(format!("operator_pubkeys: {key:?} is not an Ed25519 key"))
            })?;
        }
        if self.redeem_max_skew_secs == 0 || self.redeem_max_skew_secs > 3600 {
            return Err(ConfigError::Invalid(
                "redeem_max_skew_secs must be 1..=3600".into(),
            ));
        }
        for entry in &self.rate_card {
            if entry.flow.is_empty() || entry.credits == 0 {
                return Err(ConfigError::Invalid(format!(
                    "rate_card entry has an empty field: {entry:?}"
                )));
            }
        }
        for origin in &self.cors_origins {
            if !(origin.starts_with("https://") || origin.starts_with("http://localhost")) {
                return Err(ConfigError::Invalid(format!(
                    "cors origin is not https: {origin}"
                )));
            }
        }
        Ok(())
    }

    /// The listed offer equal to `candidate`, if any. Offers are compared by
    /// value, never by index, so a client cannot pay for one pack and name
    /// another.
    pub fn find_offer(&self, candidate: &Offer) -> Option<&Offer> {
        self.offers.iter().find(|o| *o == candidate)
    }

    pub fn accepts_mint(&self, mint: &str) -> bool {
        let normalized = mint.trim_end_matches('/');
        self.mints.iter().any(|m| m == normalized)
    }

    /// Parsed `operator_pubkeys` (validated by [`Config::validate`]).
    pub fn operator_keys(&self) -> Vec<ed25519_dalek::VerifyingKey> {
        self.operator_pubkeys
            .iter()
            .filter_map(|key| {
                let bytes: [u8; 32] = hex::decode(key).ok()?.try_into().ok()?;
                ed25519_dalek::VerifyingKey::from_bytes(&bytes).ok()
            })
            .collect()
    }

    /// `redeem_store_path`, or `redeem.jsonl` next to `store_path`.
    pub fn redeem_store_path(&self) -> PathBuf {
        self.redeem_store_path
            .clone()
            .unwrap_or_else(|| self.store_path.with_file_name("redeem.jsonl"))
    }
}

/// Read a secret seed file that holds either `len` raw bytes or `2*len` hex
/// characters (optionally newline-terminated), as `bpir-admin keygen` and
/// `head -c 64 /dev/urandom` produce.
pub fn read_seed_file(path: &Path, len: usize) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
    let raw = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let raw = zeroize::Zeroizing::new(raw);
    if raw.len() == len {
        return Ok(raw);
    }
    let text = std::str::from_utf8(&raw).map_err(|_| {
        format!(
            "{} is neither {len} raw bytes nor {} hex characters",
            path.display(),
            2 * len
        )
    })?;
    let decoded = hex::decode(text.trim()).map_err(|_| {
        format!(
            "{} is neither {len} raw bytes nor {} hex characters",
            path.display(),
            2 * len
        )
    })?;
    if decoded.len() != len {
        return Err(format!(
            "{} decodes to {} bytes, expected {len}",
            path.display(),
            decoded.len()
        ));
    }
    Ok(zeroize::Zeroizing::new(decoded))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Config {
        toml::from_str(
            r#"
            listen = "127.0.0.1:8095"
            grant_key_path = "grant.key"
            wallet_seed_path = "wallet.seed"
            wallet_db_path = "wallet.sqlite"
            store_path = "grants.jsonl"
            mints = ["https://mint.example"]
            [[offers]]
            credits = 1000
            amount = 210
            unit = "sat"
            "#,
        )
        .unwrap()
    }

    #[test]
    fn sample_validates_with_defaults() {
        let c = sample();
        c.validate().unwrap();
        assert_eq!(c.grant_ttl_secs, 86_400);
        assert!(c.cors_origins.is_empty());
        assert_eq!(
            c.costs,
            Costs {
                frame: 1,
                harmony_hint_set: 150
            }
        );
        assert!(c.accepts_mint("https://mint.example/"));
        assert!(!c.accepts_mint("https://other.example"));
        assert!(c
            .find_offer(&Offer {
                credits: 1000,
                amount: 210,
                unit: "sat".into()
            })
            .is_some());
        assert!(c
            .find_offer(&Offer {
                credits: 1000,
                amount: 211,
                unit: "sat".into()
            })
            .is_none());
    }

    #[test]
    fn rejects_bad_values() {
        let mut c = sample();
        c.mints = vec!["http://mint.example".into()];
        assert!(c.validate().is_err());
        let mut c = sample();
        c.grant_ttl_secs = MAX_GRANT_TTL_SECS + 1;
        assert!(c.validate().is_err());
        let mut c = sample();
        c.offers.push(c.offers[0].clone());
        assert!(c.validate().is_err());
        let mut c = sample();
        c.offers[0].credits = 0;
        assert!(c.validate().is_err());
        let mut c = sample();
        c.costs.harmony_hint_set = 0;
        assert!(c.validate().is_err());
    }

    #[test]
    fn seed_file_accepts_raw_and_hex() {
        let dir = tempfile::tempdir().unwrap();
        let raw = dir.path().join("raw");
        std::fs::write(&raw, [7u8; 32]).unwrap();
        assert_eq!(read_seed_file(&raw, 32).unwrap().as_slice(), &[7u8; 32]);
        let hexf = dir.path().join("hex");
        std::fs::write(&hexf, format!("{}\n", hex::encode([9u8; 32]))).unwrap();
        assert_eq!(read_seed_file(&hexf, 32).unwrap().as_slice(), &[9u8; 32]);
        assert!(read_seed_file(&hexf, 64).is_err());
    }
}
