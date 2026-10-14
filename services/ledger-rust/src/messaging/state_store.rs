//! Operator consoles keep their room state (member key, group secrets) on the operator's laptop.
//! The state file is sealed under a key derived from the operator's passphrase, so a stolen
//! laptop does not give access to the treasury room.
//!
//! File layout: version (1), salt (16), IV (24), sealed state.

use std::fs;
use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, Generate, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

type StateCipher = XChaCha20Poly1305;

const FILE_VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const IV_LEN: usize = 24;

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("state file i/o: {0}")]
    Io(#[from] std::io::Error),
    #[error("passphrase key derivation failed: {0}")]
    Derive(#[from] argon2::Error),
    #[error("state file is malformed")]
    Malformed,
    #[error("wrong passphrase or damaged state file")]
    Unseal,
}

pub struct StateStore {
    dir: PathBuf,
}

/// Derives the state key from the passphrase and builds the cipher for it.
fn state_cipher(passphrase: &[u8], salt: &[u8]) -> Result<StateCipher, StateError> {
    let kdf = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(65_536, 3, 1, Some(32))?,
    );
    let mut state_key = [0u8; 32];
    kdf.hash_password_into(passphrase, salt, &mut state_key)?;
    let cipher = StateCipher::new_from_slice(&state_key).map_err(|_| StateError::Malformed)?;
    Ok(cipher)
}

impl StateStore {
    pub fn new(dir: &Path) -> Self {
        Self {
            dir: dir.to_owned(),
        }
    }

    fn path(&self, operator: &str) -> PathBuf {
        self.dir.join(format!("{operator}.state"))
    }

    pub fn save(&self, operator: &str, passphrase: &str, state: &[u8]) -> Result<(), StateError> {
        let salt = <[u8; SALT_LEN]>::generate();
        let iv = XNonce::generate();
        let sealer = state_cipher(passphrase.as_bytes(), &salt)?;
        let sealed = sealer.encrypt(&iv, state).map_err(|_| StateError::Unseal)?;
        let mut file = Vec::with_capacity(1 + SALT_LEN + IV_LEN + sealed.len());
        file.push(FILE_VERSION);
        file.extend_from_slice(&salt);
        file.extend_from_slice(&iv);
        file.extend_from_slice(&sealed);
        fs::write(self.path(operator), file)?;
        Ok(())
    }

    pub fn load(&self, operator: &str, passphrase: &str) -> Result<Vec<u8>, StateError> {
        let file = fs::read(self.path(operator))?;
        if file.len() < 1 + SALT_LEN + IV_LEN || file[0] != FILE_VERSION {
            return Err(StateError::Malformed);
        }
        let (salt, rest) = file[1..].split_at(SALT_LEN);
        let (iv, sealed) = rest.split_at(IV_LEN);
        let iv = XNonce::try_from(iv).map_err(|_| StateError::Malformed)?;
        let opener = state_cipher(passphrase.as_bytes(), salt)?;
        opener.decrypt(&iv, sealed).map_err(|_| StateError::Unseal)
    }

    pub fn forget(&self, operator: &str) -> Result<(), StateError> {
        match fs::remove_file(self.path(operator)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}
