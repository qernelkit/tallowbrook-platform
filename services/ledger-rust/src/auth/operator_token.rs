//! Operator session tokens. The ledger issues them when an operator logs in at a console, and
//! checks them on every console request.

use std::fs;

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

use super::{Role, TokenError};
use crate::settings::AuthSettings;

pub const OPERATOR_TOKEN_ALG: Algorithm = Algorithm::EdDSA;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperatorClaims {
    pub iss: String,
    pub sub: String,
    pub iat: u64,
    pub exp: u64,
    pub console: String,
    pub roles: Vec<Role>,
}

impl OperatorClaims {
    pub fn require(&self, role: Role) -> Result<(), TokenError> {
        if self.roles.contains(&role) || self.roles.contains(&Role::Admin) {
            Ok(())
        } else {
            Err(TokenError::MissingRole(role))
        }
    }
}

pub struct OperatorTokens {
    encoding: EncodingKey,
    decoding: DecodingKey,
    issuer: String,
    session_secs: u64,
}

impl OperatorTokens {
    pub fn load(auth: &AuthSettings) -> Result<Self, TokenError> {
        let issuing_pem = fs::read(&auth.operator_token_key)?;
        let checking_pem = fs::read(&auth.operator_token_verifier)?;
        Ok(Self {
            encoding: EncodingKey::from_ed_pem(&issuing_pem)?,
            decoding: DecodingKey::from_ed_pem(&checking_pem)?,
            issuer: auth.issuer.clone(),
            session_secs: auth.operator_session_secs,
        })
    }

    pub fn issue(
        &self,
        operator: &str,
        console: &str,
        roles: Vec<Role>,
        now: u64,
    ) -> Result<String, TokenError> {
        let claims = OperatorClaims {
            iss: self.issuer.clone(),
            sub: operator.to_owned(),
            iat: now,
            exp: now + self.session_secs,
            console: console.to_owned(),
            roles,
        };
        Ok(encode(
            &Header::new(OPERATOR_TOKEN_ALG),
            &claims,
            &self.encoding,
        )?)
    }

    pub fn check(&self, token: &str) -> Result<OperatorClaims, TokenError> {
        let mut validation = Validation::new(OPERATOR_TOKEN_ALG);
        validation.set_issuer(&[&self.issuer]);
        validation.leeway = 30;
        let data = decode::<OperatorClaims>(token, &self.decoding, &validation)?;
        Ok(data.claims)
    }
}
