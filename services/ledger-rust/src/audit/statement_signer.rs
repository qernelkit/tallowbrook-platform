//! Signs period-end balance statements for the external auditors. The auditors check the
//! signature against the key in our audit engagement letter.

use std::fs;
use std::path::Path;

use ring::rand::SystemRandom;
use ring::signature::{self, EcdsaKeyPair};
use serde::Serialize;

use crate::model::{AccountId, Currency, Period};

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("cannot read the statement key file: {0}")]
    Read(#[from] std::io::Error),
    #[error("the statement key file is not a usable key document")]
    BadKey,
    #[error("signing the balance statement failed")]
    Sign,
    #[error("cannot encode the balance statement: {0}")]
    Encode(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize)]
pub struct BalanceLine {
    pub account: AccountId,
    pub currency: Currency,
    pub closing_minor: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct BalanceStatement {
    pub instance: String,
    pub auditor: String,
    pub period: Period,
    pub lines: Vec<BalanceLine>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SignedStatement {
    pub statement: BalanceStatement,
    pub signature: Vec<u8>,
}

pub struct AuditStatementSigner {
    key: EcdsaKeyPair,
    rng: SystemRandom,
}

impl AuditStatementSigner {
    pub fn load(path: &Path) -> Result<Self, AuditError> {
        let pkcs8 = fs::read(path)?;
        let rng = SystemRandom::new();
        let key =
            EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, &pkcs8, &rng)
                .map_err(|_| AuditError::BadKey)?;
        Ok(Self { key, rng })
    }

    pub fn sign(&self, statement: BalanceStatement) -> Result<SignedStatement, AuditError> {
        let body = serde_json::to_vec(&statement)?;
        let sig = self
            .key
            .sign(&self.rng, &body)
            .map_err(|_| AuditError::Sign)?;
        Ok(SignedStatement {
            statement,
            signature: sig.as_ref().to_vec(),
        })
    }
}
