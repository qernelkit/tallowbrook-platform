//! Tokens issued by the ops console, presented when the console calls the ledger on behalf of a
//! support engineer (read-only views, period-close checklists).

use std::fs;

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde::Deserialize;

use super::{Role, TokenError};
use crate::settings::AuthSettings;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ConsoleClaims {
    pub iss: String,
    pub sub: String,
    pub exp: u64,
    pub ticket: Option<String>,
    #[serde(default)]
    pub roles: Vec<Role>,
}

pub struct ConsoleTokens {
    key: DecodingKey,
    issuer: String,
}

impl ConsoleTokens {
    pub fn load(auth: &AuthSettings) -> Result<Self, TokenError> {
        let pem = fs::read(&auth.console_token_key)?;
        Ok(Self {
            key: DecodingKey::from_ec_pem(&pem)?,
            issuer: auth.console_issuer.clone(),
        })
    }

    pub fn check(&self, token: &str) -> Result<ConsoleClaims, TokenError> {
        let mut validation = Validation::new(Algorithm::ES256);
        validation.algorithms = vec![Algorithm::ES256, Algorithm::ES384];
        validation.set_issuer(&[&self.issuer]);
        let data = decode::<ConsoleClaims>(token, &self.key, &validation)?;
        let mut claims = data.claims;
        // Approvals only ever come from operator sessions, never from support tooling.
        claims.roles.retain(|r| *r != Role::Approver);
        Ok(claims)
    }
}
