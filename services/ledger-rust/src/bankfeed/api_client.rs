//! Open-banking API requests. Our banks' APIs require each request to carry a signature over the
//! method, path, date and body, made with the request key we registered with them.

use std::fs;
use std::path::Path;

use base64::prelude::*;
use p256::ecdsa::Signature;
use p256::ecdsa::signature::Signer;
use p256::pkcs8::DecodePrivateKey;

#[derive(Debug, thiserror::Error)]
pub enum ApiClientError {
    #[error("cannot read the request key file: {0}")]
    Read(#[from] std::io::Error),
    #[error("the request key file is not a usable key document")]
    BadKey,
}

/// Headers to add to an outgoing bank API request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedHeaders {
    pub date: String,
    pub key_id: String,
    pub signature: String,
}

pub struct BankApiSigner {
    request_key: p256::ecdsa::SigningKey,
    key_id: String,
}

impl BankApiSigner {
    pub fn load(path: &Path, key_id: &str) -> Result<Self, ApiClientError> {
        let pem = fs::read_to_string(path)?;
        let request_key =
            p256::ecdsa::SigningKey::from_pkcs8_pem(&pem).map_err(|_| ApiClientError::BadKey)?;
        Ok(Self {
            request_key,
            key_id: key_id.to_owned(),
        })
    }

    fn signing_string(method: &str, path: &str, date: &str, body: &[u8]) -> Vec<u8> {
        let mut out = format!("{}\n{}\n{}\n", method.to_ascii_uppercase(), path, date).into_bytes();
        out.extend_from_slice(body);
        out
    }

    pub fn sign(&self, method: &str, path: &str, date: &str, body: &[u8]) -> SignedHeaders {
        let message = Self::signing_string(method, path, date, body);
        let signature: Signature = self.request_key.sign(&message);
        SignedHeaders {
            date: date.to_owned(),
            key_id: self.key_id.clone(),
            signature: BASE64_STANDARD.encode(signature.to_der().as_bytes()),
        }
    }
}
