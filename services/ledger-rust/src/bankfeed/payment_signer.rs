//! Signs outbound payment files. Each bank checks the detached signature against the key we
//! registered with it; the key file is installed by the deploy pipeline.

use std::fs;
use std::path::Path;

use ring::rand::SystemRandom;
use ring::signature::{self, RsaKeyPair};

use crate::model::Currency;

#[derive(Debug, thiserror::Error)]
pub enum PaymentError {
    #[error("cannot read the payment key file: {0}")]
    Read(#[from] std::io::Error),
    #[error("payment key rejected: {0}")]
    BadKey(String),
    #[error("signing the payment file failed")]
    Sign,
    #[error("payment file has no lines")]
    Empty,
}

/// One credit transfer in a payment file.
#[derive(Debug, Clone)]
pub struct PaymentLine {
    pub end_to_end_id: String,
    pub creditor_name: String,
    pub creditor_iban: String,
    pub amount_minor: i64,
    pub currency: Currency,
    pub remittance: String,
}

/// Renders the payment file in the semicolon format the banks accept.
pub fn render(
    debtor_iban: &str,
    execution_date: &str,
    lines: &[PaymentLine],
) -> Result<Vec<u8>, PaymentError> {
    if lines.is_empty() {
        return Err(PaymentError::Empty);
    }
    let mut out = format!("PAY;{debtor_iban};{execution_date};{}\n", lines.len());
    for l in lines {
        out.push_str(&format!(
            "CRT;{};{};{};{};{};{}\n",
            l.end_to_end_id,
            l.creditor_name.replace(';', " "),
            l.creditor_iban,
            l.amount_minor,
            l.currency,
            l.remittance.replace(';', " ")
        ));
    }
    let total: i64 = lines.iter().map(|l| l.amount_minor).sum();
    out.push_str(&format!("END;{total}\n"));
    Ok(out.into_bytes())
}

pub struct PaymentSigner {
    key: RsaKeyPair,
    rng: SystemRandom,
}

impl PaymentSigner {
    pub fn load(path: &Path) -> Result<Self, PaymentError> {
        let der = fs::read(path)?;
        let key = RsaKeyPair::from_pkcs8(&der).map_err(|e| PaymentError::BadKey(e.to_string()))?;
        Ok(Self {
            key,
            rng: SystemRandom::new(),
        })
    }

    /// Detached signature over the rendered payment file.
    pub fn sign(&self, file: &[u8]) -> Result<Vec<u8>, PaymentError> {
        let mut sig = vec![0u8; self.key.public().modulus_len()];
        self.key
            .sign(&signature::RSA_PSS_SHA256, &self.rng, file, &mut sig)
            .map_err(|_| PaymentError::Sign)?;
        Ok(sig)
    }
}
