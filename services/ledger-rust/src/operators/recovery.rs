//! Operator recovery kits. When an operator console is enrolled, the operator prints a recovery
//! kit: their room member key and console enrolment, sealed under a recovery passphrase that is
//! written on the printout and kept in the treasury safe. A replacement laptop is restored from
//! the kit instead of re-running the approver ceremony.
//!
//! Kit file: magic "TBRK", salt (16), IV (12), sealed body; the operator id is associated data.

use std::num::NonZeroU32;

use ring::rand::{SecureRandom, SystemRandom};
use ring::{aead, pbkdf2};
use serde::{Deserialize, Serialize};

const MAGIC: &[u8; 4] = b"TBRK";
const SALT_LEN: usize = 16;
const KIT_KDF_ITERATIONS: u32 = 210_000;

/// Words in a generated recovery passphrase.
pub const PASSPHRASE_WORDS: usize = 8;

#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    #[error("recovery kit is malformed")]
    Malformed,
    #[error("wrong recovery passphrase or damaged kit")]
    Unseal,
    #[error("cannot encode the kit body: {0}")]
    Encode(#[from] serde_json::Error),
    #[error("random source failed")]
    Random,
}

impl From<ring::error::Unspecified> for RecoveryError {
    fn from(_: ring::error::Unspecified) -> Self {
        RecoveryError::Random
    }
}

/// What a kit restores.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoveryKit {
    pub operator: String,
    pub console_id: String,
    pub member_scheme: u16,
    pub member_private: Vec<u8>,
    pub member_public: Vec<u8>,
    pub enrolled_at: u64,
}

fn kit_cipher(passphrase: &str, salt: &[u8]) -> Result<aead::LessSafeKey, RecoveryError> {
    let iterations = NonZeroU32::new(KIT_KDF_ITERATIONS).ok_or(RecoveryError::Malformed)?;
    let mut derived = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA512,
        iterations,
        salt,
        normalise(passphrase).as_bytes(),
        &mut derived,
    );
    let kit_key = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &derived)?;
    Ok(aead::LessSafeKey::new(kit_key))
}

/// Passphrases are typed back from paper: case and spacing must not matter.
fn normalise(passphrase: &str) -> String {
    let lower = passphrase.to_lowercase();
    lower.split_whitespace().collect::<Vec<_>>().join(" ")
}

impl RecoveryKit {
    pub fn seal(&self, passphrase: &str, rng: &SystemRandom) -> Result<Vec<u8>, RecoveryError> {
        let mut salt = [0u8; SALT_LEN];
        let mut iv = [0u8; aead::NONCE_LEN];
        rng.fill(&mut salt)?;
        rng.fill(&mut iv)?;
        let mut body = serde_json::to_vec(self)?;
        kit_cipher(passphrase, &salt)?.seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(iv),
            aead::Aad::from(self.operator.as_bytes()),
            &mut body,
        )?;
        let mut out = MAGIC.to_vec();
        out.extend_from_slice(&salt);
        out.extend_from_slice(&iv);
        out.extend_from_slice(&body);
        Ok(out)
    }

    pub fn open(
        kit: &[u8],
        operator: &str,
        passphrase: &str,
    ) -> Result<RecoveryKit, RecoveryError> {
        let header = MAGIC.len() + SALT_LEN + aead::NONCE_LEN;
        if kit.len() < header || &kit[..4] != MAGIC {
            return Err(RecoveryError::Malformed);
        }
        let salt = &kit[4..4 + SALT_LEN];
        let iv: [u8; aead::NONCE_LEN] = kit[4 + SALT_LEN..header]
            .try_into()
            .map_err(|_| RecoveryError::Malformed)?;
        let mut body = kit[header..].to_vec();
        let plain = kit_cipher(passphrase, salt)?
            .open_in_place(
                aead::Nonce::assume_unique_for_key(iv),
                aead::Aad::from(operator.as_bytes()),
                &mut body,
            )
            .map_err(|_| RecoveryError::Unseal)?;
        let restored: RecoveryKit = serde_json::from_slice(plain)?;
        if restored.operator != operator {
            return Err(RecoveryError::Malformed);
        }
        Ok(restored)
    }
}

#[cfg(test)]
mod tests {
    use super::normalise;

    #[test]
    fn passphrase_normalisation() {
        assert_eq!(normalise("  Three  WORDS\there "), "three words here");
    }
}
