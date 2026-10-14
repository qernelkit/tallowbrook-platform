//! Service-to-service tokens shared with the reporting service. Both sides hold the same secret
//! from the environment (`LEDGER_SERVICE_TOKEN_SECRET`); tokens are short-lived and scoped.

use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

use super::TokenError;

/// Lifetime of a service token.
pub const SERVICE_TOKEN_SECS: u64 = 300;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub iat: u64,
    pub exp: u64,
    pub scope: String,
}

impl ServiceClaims {
    pub fn has_scope(&self, wanted: &str) -> bool {
        self.scope.split_whitespace().any(|s| s == wanted)
    }
}

pub struct ServiceTokens {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    issuer: String,
    audience: String,
}

impl ServiceTokens {
    pub fn from_env(issuer: &str, audience: &str) -> Result<Self, TokenError> {
        let shared = std::env::var("LEDGER_SERVICE_TOKEN_SECRET")
            .map_err(|_| TokenError::NoServiceSecret)?;
        Ok(Self {
            encoding_key: EncodingKey::from_secret(shared.as_bytes()),
            decoding_key: DecodingKey::from_secret(shared.as_bytes()),
            issuer: issuer.to_owned(),
            audience: audience.to_owned(),
        })
    }

    /// Token the ledger presents to the reporting service.
    pub fn mint(&self, scope: &str, now: u64) -> Result<String, TokenError> {
        let header = Header::default();
        let claims = ServiceClaims {
            iss: self.issuer.clone(),
            sub: "ledger".to_owned(),
            aud: self.audience.clone(),
            iat: now,
            exp: now + SERVICE_TOKEN_SECS,
            scope: scope.to_owned(),
        };
        Ok(encode(&header, &claims, &self.encoding_key)?)
    }

    /// Checks a token the reporting service presents to the ledger.
    pub fn check(&self, token: &str, own_audience: &str) -> Result<ServiceClaims, TokenError> {
        let mut validation = Validation::default();
        validation.set_audience(&[own_audience]);
        let data = decode::<ServiceClaims>(token, &self.decoding_key, &validation)?;
        Ok(data.claims)
    }
}
