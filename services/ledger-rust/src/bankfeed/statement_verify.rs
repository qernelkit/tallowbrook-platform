//! Statement files are signed by the bank. Each bank uses its own signature format, configured in
//! `[[bankfeed.banks]] statement_signature`; the bank's public key is installed as a DER file.

use std::collections::BTreeMap;
use std::fs;

use ring::signature;
use serde::Deserialize;

use crate::settings::BankProfile;

/// Signature format a bank uses for its statement files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StatementSigFormat {
    RsaPkcs1Sha256,
    RsaPssSha256,
    EcdsaP384Sha384,
}

impl StatementSigFormat {
    fn verification(self) -> &'static dyn signature::VerificationAlgorithm {
        match self {
            StatementSigFormat::RsaPkcs1Sha256 => &signature::RSA_PKCS1_2048_8192_SHA256,
            StatementSigFormat::RsaPssSha256 => &signature::RSA_PSS_2048_8192_SHA256,
            StatementSigFormat::EcdsaP384Sha384 => &signature::ECDSA_P384_SHA384_ASN1,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StatementVerifyError {
    #[error("cannot read the statement key of bank {bank}: {source}")]
    Key {
        bank: String,
        source: std::io::Error,
    },
    #[error("no statement key for bank {0}")]
    UnknownBank(String),
    #[error("statement {statement} from bank {bank} has a bad signature")]
    BadSignature { bank: String, statement: String },
}

struct BankKey {
    format: StatementSigFormat,
    der: Vec<u8>,
}

/// Holds every configured bank's statement key.
pub struct StatementVerifier {
    keys: BTreeMap<String, BankKey>,
}

impl StatementVerifier {
    pub fn load(banks: &[BankProfile]) -> Result<Self, StatementVerifyError> {
        let mut keys = BTreeMap::new();
        for bank in banks {
            let der =
                fs::read(&bank.statement_key).map_err(|source| StatementVerifyError::Key {
                    bank: bank.code.clone(),
                    source,
                })?;
            let format = bank.statement_signature;
            keys.insert(bank.code.clone(), BankKey { format, der });
        }
        Ok(Self { keys })
    }

    pub fn verify(
        &self,
        bank: &str,
        statement: &str,
        body: &[u8],
        sig: &[u8],
    ) -> Result<(), StatementVerifyError> {
        let key = self
            .keys
            .get(bank)
            .ok_or_else(|| StatementVerifyError::UnknownBank(bank.to_owned()))?;
        let bank_key = signature::UnparsedPublicKey::new(key.format.verification(), &key.der);
        bank_key
            .verify(body, sig)
            .map_err(|_| StatementVerifyError::BadSignature {
                bank: bank.to_owned(),
                statement: statement.to_owned(),
            })
    }

    pub fn banks(&self) -> impl Iterator<Item = &str> {
        self.keys.keys().map(String::as_str)
    }
}
