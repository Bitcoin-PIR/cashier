//! ARC credentials as credits (docs/CREDITS.md "ARC parameters"): per-epoch
//! issuer keys derived from one master seed, blind issuance for
//! `POST /v2/credentials`, and presentation verification for kind-2 items
//! of `POST /v2/redeem`. Epochs, contexts, and the payload codec come from
//! `pir_credit::arc` so the clients agree byte for byte.

use arc::group::serialize_element;
use arc::{
    create_credential_response, verify_presentation, CredentialRequest, Presentation,
    ServerPrivateKey, ServerPublicKey,
};
use hkdf::Hkdf;
use pir_credit::arc::{
    epoch_accepted, epoch_at, epoch_valid_until, presentation_context, request_context,
};
use pir_credit::issuer::ArcInfoV2;
use sha2::Sha256;
use zeroize::Zeroizing;

const KEY_DERIVATION_SALT: &[u8] = b"BPIR-ARC-EPOCH-KEYS-V1";

#[derive(Debug, thiserror::Error)]
pub enum ArcError {
    #[error("malformed ARC {0}: {1}")]
    Malformed(&'static str, String),
    #[error("ARC presentation does not verify: {0}")]
    Invalid(String),
}

/// The issuer side of ARC for every epoch.
pub struct ArcIssuer {
    seed: Zeroizing<[u8; 32]>,
    epoch_secs: u64,
    grace_secs: u64,
    presentation_limit: u32,
}

impl ArcIssuer {
    pub fn new(seed: [u8; 32], epoch_secs: u64, grace_secs: u64, presentation_limit: u32) -> Self {
        Self {
            seed: Zeroizing::new(seed),
            epoch_secs,
            grace_secs,
            presentation_limit,
        }
    }

    pub fn presentation_limit(&self) -> u32 {
        self.presentation_limit
    }

    pub fn current_epoch(&self, now: u64) -> u32 {
        epoch_at(now, self.epoch_secs)
    }

    pub fn accepts(&self, epoch: u32, now: u64) -> bool {
        epoch_accepted(epoch, now, self.epoch_secs, self.grace_secs)
    }

    pub fn valid_until(&self, epoch: u32) -> u64 {
        epoch_valid_until(epoch, self.epoch_secs, self.grace_secs)
    }

    /// The epoch's keys: four scalars from HKDF-SHA256(seed) with the epoch
    /// and the scalar index in the info string, re-drawn on the rare output
    /// that is not a valid nonzero scalar.
    fn keys(&self, epoch: u32) -> (ServerPrivateKey, ServerPublicKey) {
        let hkdf = Hkdf::<Sha256>::new(Some(KEY_DERIVATION_SALT), self.seed.as_ref());
        let mut scalars = Vec::with_capacity(4);
        for index in 0u8..4 {
            let mut attempt = 0u8;
            loop {
                let mut info = Vec::with_capacity(6);
                info.extend_from_slice(&epoch.to_le_bytes());
                info.push(index);
                info.push(attempt);
                let mut okm = Zeroizing::new([0u8; 32]);
                hkdf.expand(&info, okm.as_mut())
                    .expect("32 bytes is a valid HKDF output length");
                if let Ok(scalar) = arc::group::deserialize_scalar(okm.as_ref()) {
                    if arc::group::serialize_scalar(&scalar) != [0u8; 32] {
                        scalars.push(scalar);
                        break;
                    }
                }
                attempt = attempt
                    .checked_add(1)
                    .expect("a valid scalar within 256 draws");
            }
        }
        let sk = ServerPrivateKey {
            x0: scalars[0],
            x1: scalars[1],
            x2: scalars[2],
            x0_blinding: scalars[3],
        };
        let pk = sk.public_key();
        (sk, pk)
    }

    pub fn public_key_hex(&self, epoch: u32) -> String {
        hex::encode(self.keys(epoch).1.to_bytes())
    }

    /// The `arc` section of `GET /v2/info` at `now`.
    pub fn info(&self, now: u64) -> ArcInfoV2 {
        let epoch = self.current_epoch(now);
        ArcInfoV2 {
            epoch,
            presentation_limit: self.presentation_limit,
            issuer_public_key_hex: self.public_key_hex(epoch),
            presentation_context_hex: hex::encode(presentation_context(epoch)),
            valid_until: self.valid_until(epoch),
        }
    }

    /// Answer a blinded credential request under `epoch`'s keys.
    pub fn issue(&self, epoch: u32, request: &[u8]) -> Result<Vec<u8>, ArcError> {
        let request = CredentialRequest::from_bytes(request)
            .map_err(|e| ArcError::Malformed("credential request", e.to_string()))?;
        let (sk, pk) = self.keys(epoch);
        let response = create_credential_response(&sk, &pk, &request, &mut rand_core::OsRng)
            .map_err(|e| ArcError::Invalid(e.to_string()))?;
        Ok(response.to_bytes().to_vec())
    }

    /// Verify one presentation under `epoch`; returns its tag (hex) for the
    /// double-spend set.
    pub fn verify(&self, epoch: u32, presentation: &[u8]) -> Result<String, ArcError> {
        let limit = u64::from(self.presentation_limit);
        let presentation = Presentation::from_bytes(presentation, limit)
            .map_err(|e| ArcError::Malformed("presentation", e.to_string()))?;
        let (sk, pk) = self.keys(epoch);
        let tag = verify_presentation(
            &sk,
            &pk,
            &request_context(epoch),
            &presentation_context(epoch),
            &presentation,
            limit,
        )
        .map_err(|e| ArcError::Invalid(e.to_string()))?;
        Ok(hex::encode(serialize_element(&tag)))
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    //! A client, for tests: request, finalize, present.
    use super::*;
    use arc::{create_credential_request, finalize_credential, make_presentation_state, present};

    pub struct TestClient {
        state: arc::presentation::PresentationState,
    }

    impl TestClient {
        /// Blinded request bytes plus the secrets to finish with.
        pub fn request(epoch: u32) -> (arc::ClientSecrets, Vec<u8>) {
            let (secrets, request) =
                create_credential_request(&request_context(epoch), &mut rand_core::OsRng).unwrap();
            (secrets, request.to_bytes().to_vec())
        }

        pub fn finish(
            secrets: &arc::ClientSecrets,
            public_key_hex: &str,
            request: &[u8],
            response: &[u8],
            epoch: u32,
            limit: u32,
        ) -> Self {
            let pk = ServerPublicKey::from_bytes(&hex::decode(public_key_hex).unwrap()).unwrap();
            let request = CredentialRequest::from_bytes(request).unwrap();
            let response = arc::CredentialResponse::from_bytes(response).unwrap();
            let credential = finalize_credential(secrets, &pk, &request, &response).unwrap();
            Self {
                state: make_presentation_state(
                    credential,
                    &presentation_context(epoch),
                    u64::from(limit),
                ),
            }
        }

        pub fn present(&mut self) -> Vec<u8> {
            let (next, _nonce, presentation) = present(&self.state, &mut rand_core::OsRng).unwrap();
            self.state = next;
            presentation.to_bytes()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::TestClient;
    use super::*;

    fn issuer() -> ArcIssuer {
        ArcIssuer::new([7u8; 32], 90 * 86_400, 30 * 86_400, 100)
    }

    #[test]
    fn keys_are_deterministic_per_epoch_and_differ_across_epochs_and_seeds() {
        let a = issuer();
        assert_eq!(a.public_key_hex(231), a.public_key_hex(231));
        assert_ne!(a.public_key_hex(231), a.public_key_hex(232));
        assert_ne!(
            a.public_key_hex(231),
            ArcIssuer::new([8u8; 32], 1, 1, 100).public_key_hex(231)
        );
        assert_eq!(a.public_key_hex(231).len(), 99 * 2);
        let info = a.info(1_800_000_000);
        assert_eq!(info.epoch, 231);
        assert_eq!(info.presentation_limit, 100);
        assert_eq!(info.issuer_public_key_hex, a.public_key_hex(231));
        assert_eq!(
            info.presentation_context_hex,
            hex::encode(presentation_context(231))
        );
        assert_eq!(info.valid_until, 232 * 90 * 86_400 + 30 * 86_400);
    }

    #[test]
    fn issued_credentials_present_up_to_the_limit_with_unique_tags() {
        let issuer = ArcIssuer::new([7u8; 32], 90 * 86_400, 30 * 86_400, 4);
        let epoch = 231;
        let (secrets, request) = TestClient::request(epoch);
        let response = issuer.issue(epoch, &request).unwrap();
        let mut client = TestClient::finish(
            &secrets,
            &issuer.public_key_hex(epoch),
            &request,
            &response,
            epoch,
            4,
        );
        let mut tags = std::collections::HashSet::new();
        for _ in 0..4 {
            let presentation = client.present();
            let tag = issuer.verify(epoch, &presentation).unwrap();
            assert!(tags.insert(tag), "tags are unique per nonce");
            // The same bytes verify again: replay detection is the tag set's job.
            assert!(issuer.verify(epoch, &presentation).is_ok());
            // Under another epoch's keys and contexts they do not.
            assert!(issuer.verify(epoch + 1, &presentation).is_err());
        }
        assert!(issuer.verify(epoch, &[0u8; 10]).is_err());
        assert!(issuer.issue(epoch, &[0u8; 10]).is_err());
    }
}
