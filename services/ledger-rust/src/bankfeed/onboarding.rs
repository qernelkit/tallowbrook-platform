//! Per-bank onboarding. For each bank we generate an onboarding key, register its public half in
//! the bank's partner portal, and the bank answers with our version-2 callback secret wrapped to
//! that key. The secret is then stored for `callback_auth`.

use std::fs;
use std::path::{Path, PathBuf};

use rsa::pkcs8::EncodePublicKey;
use rsa::rand_core::OsRng;
use rsa::sha2::Sha256;
use rsa::{Oaep, RsaPrivateKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum OnboardingError {
    #[error("onboarding key operation failed: {0}")]
    Key(#[from] rsa::Error),
    #[error("cannot encode the onboarding key: {0}")]
    Encode(String),
    #[error("enrolment reply is for bank {got}, expected {expected}")]
    WrongBank { expected: String, got: String },
    #[error("onboarding i/o: {0}")]
    Io(#[from] std::io::Error),
}

/// Sent to the bank's partner portal.
#[derive(Debug, Clone, Serialize)]
pub struct EnrolmentRequest {
    pub bank: String,
    pub partner: String,
    pub onboarding_key_der: Vec<u8>,
}

/// The bank's answer.
#[derive(Debug, Clone, Deserialize)]
pub struct EnrolmentReply {
    pub bank: String,
    pub wrapped_callback_secret: Vec<u8>,
}

pub struct BankOnboarding {
    bank: String,
    key: RsaPrivateKey,
}

impl BankOnboarding {
    pub fn begin(bank: &str, partner: &str) -> Result<(Self, EnrolmentRequest), OnboardingError> {
        let key = RsaPrivateKey::new(&mut OsRng, 3072)?;
        let onboarding_key_der = key
            .to_public_key()
            .to_public_key_der()
            .map_err(|e| OnboardingError::Encode(e.to_string()))?
            .into_vec();
        let request = EnrolmentRequest {
            bank: bank.to_owned(),
            partner: partner.to_owned(),
            onboarding_key_der,
        };
        Ok((
            Self {
                bank: bank.to_owned(),
                key,
            },
            request,
        ))
    }

    /// Unwraps the callback secret from the bank's reply.
    pub fn complete(&self, enrolment: &EnrolmentReply) -> Result<Vec<u8>, OnboardingError> {
        if enrolment.bank != self.bank {
            return Err(OnboardingError::WrongBank {
                expected: self.bank.clone(),
                got: enrolment.bank.clone(),
            });
        }
        let callback_secret = self
            .key
            .decrypt(Oaep::new::<Sha256>(), &enrolment.wrapped_callback_secret)?;
        log::info!("bank {} onboarding complete", self.bank);
        Ok(callback_secret)
    }
}

/// Where a bank's callback secret is kept between restarts.
pub fn secret_path(dir: &Path, bank: &str) -> PathBuf {
    dir.join(format!("{bank}.callback"))
}

pub fn store_secret(dir: &Path, bank: &str, secret: &[u8]) -> Result<(), OnboardingError> {
    fs::create_dir_all(dir)?;
    fs::write(secret_path(dir, bank), hex::encode(secret))?;
    Ok(())
}

pub fn load_secret(dir: &Path, bank: &str) -> Result<Option<Vec<u8>>, OnboardingError> {
    match fs::read_to_string(secret_path(dir, bank)) {
        Ok(text) => Ok(hex::decode(text.trim()).ok()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}
