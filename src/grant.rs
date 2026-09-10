//! Grant issuance: a thin, deterministic wrapper over
//! `pir_session_grant::GrantSigner`.
//!
//! The grant id is derived from the paid token (see [`crate::cashu::token_key`])
//! so that a replayed request for the same token maps to the same id, and ids
//! stay unique across cashier restarts without any counter.

use ed25519_dalek::{Signer, SigningKey};
use pir_session_grant::{GrantSigner, PublicKey, SessionGrant, GRANT_ID_LEN, SESSION_GRANT_LEN};
use serde::{Deserialize, Serialize};

/// Fields the client echoes back and checks against the offer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuedGrant {
    pub grant_base64: String,
    pub grant_id_hex: String,
    pub credits: u32,
    pub issued_at: u64,
    pub expires_at: u64,
}

pub struct Issuer {
    signer: GrantSigner,
    /// The same seed as an Ed25519 key for signing redeem answers
    /// (`docs/CREDITS.md`), so servers pin one key for both contracts.
    answer_key: SigningKey,
    ttl_secs: u64,
}

impl Issuer {
    pub fn new(seed: &[u8; 32], ttl_secs: u64) -> Self {
        Self {
            signer: GrantSigner::from_seed(seed),
            answer_key: SigningKey::from_bytes(seed),
            ttl_secs,
        }
    }

    /// Sign arbitrary bytes (a redeem answer preimage) with the issuer key.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.answer_key.sign(message).to_bytes()
    }

    pub fn public_key(&self) -> PublicKey {
        self.signer.public_key()
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.signer.public_key())
    }

    pub fn ttl_secs(&self) -> u64 {
        self.ttl_secs
    }

    /// Sign a grant for `credits`, valid from `now` for the configured TTL,
    /// with the id taken from the first 16 bytes of `token_key`.
    pub fn issue(
        &self,
        token_key: &[u8; 32],
        credits: u32,
        now: u64,
    ) -> Result<(IssuedGrant, [u8; SESSION_GRANT_LEN]), pir_session_grant::GrantError> {
        let mut grant_id = [0u8; GRANT_ID_LEN];
        grant_id.copy_from_slice(&token_key[..GRANT_ID_LEN]);
        let expires_at = now.saturating_add(self.ttl_secs);
        let grant: SessionGrant = self.signer.issue(grant_id, now, expires_at, credits)?;
        let bytes = grant.encode();
        Ok((
            IssuedGrant {
                grant_base64: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    bytes,
                ),
                grant_id_hex: hex::encode(grant_id),
                credits,
                issued_at: now,
                expires_at,
            },
            bytes,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pir_session_grant::TrustedIssuers;

    #[test]
    fn issued_grant_verifies_under_the_public_key_and_is_deterministic_per_token() {
        let issuer = Issuer::new(&[3u8; 32], 3600);
        let key = [0xabu8; 32];
        let (a, bytes_a) = issuer.issue(&key, 1000, 1_800_000_000).unwrap();
        let (b, bytes_b) = issuer.issue(&key, 1000, 1_800_000_000).unwrap();
        assert_eq!(a, b);
        assert_eq!(bytes_a, bytes_b);
        assert_eq!(a.grant_id_hex, hex::encode(&key[..16]));
        assert_eq!(a.expires_at, a.issued_at + 3600);
        let grant = SessionGrant::decode(&bytes_a).unwrap();
        let issuers = TrustedIssuers::new(&[issuer.public_key()]).unwrap();
        let verified = grant.verify(&issuers, 1_800_000_100).unwrap();
        assert_eq!(verified.credits, 1000);
        let other = TrustedIssuers::new(&[[9u8; 32]]).unwrap();
        assert!(grant.verify(&other, 1_800_000_100).is_err());
    }
}
