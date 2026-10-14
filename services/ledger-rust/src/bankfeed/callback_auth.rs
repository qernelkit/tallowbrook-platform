//! Authenticates bank callbacks (payment status, statement-ready notifications).
//!
//! Banks on callback version 1 send `X-Bank-Tag: v1=<hex>` computed over the shared secret
//! followed by the body. Version 2 sends `X-Bank-Tag: v2=<hex>`, a keyed MAC whose secret the
//! bank hands over during onboarding.

use std::collections::BTreeMap;

use ring::{digest, hmac};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CallbackError {
    #[error("callback from unknown bank {0}")]
    UnknownBank(String),
    #[error("missing or malformed tag header")]
    BadHeader,
    #[error("bank {bank} is on callback version {configured}, header is version {sent}")]
    WrongVersion {
        bank: String,
        configured: u8,
        sent: u8,
    },
    #[error("callback tag does not match")]
    BadTag,
}

struct BankSecret {
    version: u8,
    secret: Vec<u8>,
}

#[derive(Default)]
pub struct CallbackAuth {
    banks: BTreeMap<String, BankSecret>,
}

/// Splits `v1=abcd…` into the version and the decoded tag.
fn parse_header(header: &str) -> Result<(u8, Vec<u8>), CallbackError> {
    let (version, tag_hex) = header
        .trim()
        .split_once('=')
        .ok_or(CallbackError::BadHeader)?;
    let version = match version {
        "v1" => 1,
        "v2" => 2,
        _ => return Err(CallbackError::BadHeader),
    };
    let tag = hex::decode(tag_hex).map_err(|_| CallbackError::BadHeader)?;
    Ok((version, tag))
}

fn same_bytes(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn check_v1(secret: &[u8], body: &[u8], tag: &[u8]) -> Result<(), CallbackError> {
    let mut keyed = Vec::with_capacity(secret.len() + body.len());
    keyed.extend_from_slice(secret);
    keyed.extend_from_slice(body);
    let expected = digest::digest(&digest::SHA256, &keyed);
    if same_bytes(expected.as_ref(), tag) {
        Ok(())
    } else {
        Err(CallbackError::BadTag)
    }
}

fn check_v2(secret: &[u8], body: &[u8], tag: &[u8]) -> Result<(), CallbackError> {
    let key = hmac::Key::new(hmac::HMAC_SHA512, secret);
    hmac::verify(&key, body, tag).map_err(|_| CallbackError::BadTag)
}

impl CallbackAuth {
    /// Registers (or replaces) a bank's callback secret.
    pub fn set_secret(&mut self, bank: &str, version: u8, secret: Vec<u8>) {
        self.banks
            .insert(bank.to_owned(), BankSecret { version, secret });
    }

    pub fn check(&self, bank: &str, header: &str, body: &[u8]) -> Result<(), CallbackError> {
        let entry = self
            .banks
            .get(bank)
            .ok_or_else(|| CallbackError::UnknownBank(bank.to_owned()))?;
        let (sent, tag) = parse_header(header)?;
        if sent != entry.version {
            return Err(CallbackError::WrongVersion {
                bank: bank.to_owned(),
                configured: entry.version,
                sent,
            });
        }
        match sent {
            1 => check_v1(&entry.secret, body, &tag),
            _ => check_v2(&entry.secret, body, &tag),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_parsing() {
        assert_eq!(parse_header("v2=00ff").unwrap(), (2, vec![0x00, 0xff]));
        assert_eq!(parse_header("v3=00"), Err(CallbackError::BadHeader));
        assert_eq!(parse_header("nonsense"), Err(CallbackError::BadHeader));
    }

    #[test]
    fn version_must_match_configuration() {
        let mut auth = CallbackAuth::default();
        let secret = std::process::id().to_be_bytes().to_vec();
        auth.set_secret("meridian-trust", 1, secret);
        assert!(matches!(
            auth.check("meridian-trust", "v2=00", b"{}"),
            Err(CallbackError::WrongVersion { .. })
        ));
    }
}
