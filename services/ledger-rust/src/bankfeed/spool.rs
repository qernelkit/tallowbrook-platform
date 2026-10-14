//! Fetched statement files wait in an on-disk spool until the importer has posted them. The spool
//! sits on a shared volume, so files are sealed with the spool key from the environment
//! (`LEDGER_SPOOL_KEY`, 32 hex characters).
//!
//! Spool file: IV (12) followed by the sealed statement; the file name is the associated data.

use std::fs;
use std::path::PathBuf;

use ring::aead;
use ring::rand::{SecureRandom, SystemRandom};

#[derive(Debug, thiserror::Error)]
pub enum SpoolError {
    #[error("spool i/o: {0}")]
    Io(#[from] std::io::Error),
    #[error("LEDGER_SPOOL_KEY is missing or not 32 hex characters")]
    NoKey,
    #[error("spool file {0} is damaged")]
    Damaged(String),
    #[error("spool sealing failed")]
    Seal,
}

impl From<ring::error::Unspecified> for SpoolError {
    fn from(_: ring::error::Unspecified) -> Self {
        SpoolError::Seal
    }
}

pub struct Spool {
    dir: PathBuf,
    spool_key: [u8; 16],
    rng: SystemRandom,
}

impl Spool {
    pub fn open(dir: PathBuf) -> Result<Self, SpoolError> {
        let hex_key = std::env::var("LEDGER_SPOOL_KEY").map_err(|_| SpoolError::NoKey)?;
        let mut spool_key = [0u8; 16];
        hex::decode_to_slice(hex_key.trim(), &mut spool_key).map_err(|_| SpoolError::NoKey)?;
        fs::create_dir_all(&dir)?;
        Ok(Self {
            dir,
            spool_key,
            rng: SystemRandom::new(),
        })
    }

    fn spool_cipher(&self) -> Result<aead::LessSafeKey, SpoolError> {
        let key = aead::UnboundKey::new(&aead::AES_128_GCM, &self.spool_key)?;
        Ok(aead::LessSafeKey::new(key))
    }

    fn name(bank: &str, statement_id: &str) -> String {
        format!("{bank}--{statement_id}.stmt")
    }

    pub fn put(&self, bank: &str, statement_id: &str, raw: &[u8]) -> Result<(), SpoolError> {
        let name = Self::name(bank, statement_id);
        let mut iv = [0u8; aead::NONCE_LEN];
        self.rng.fill(&mut iv)?;
        let mut sealed = raw.to_vec();
        self.spool_cipher()?.seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(iv),
            aead::Aad::from(name.as_bytes()),
            &mut sealed,
        )?;
        let mut file = iv.to_vec();
        file.extend_from_slice(&sealed);
        fs::write(self.dir.join(&name), file)?;
        Ok(())
    }

    pub fn take(&self, bank: &str, statement_id: &str) -> Result<Vec<u8>, SpoolError> {
        let name = Self::name(bank, statement_id);
        let path = self.dir.join(&name);
        let file = fs::read(&path)?;
        if file.len() < aead::NONCE_LEN {
            return Err(SpoolError::Damaged(name));
        }
        let (iv, sealed) = file.split_at(aead::NONCE_LEN);
        let iv: [u8; aead::NONCE_LEN] = iv.try_into().expect("split at the IV length");
        let mut buf = sealed.to_vec();
        let plain = self
            .spool_cipher()?
            .open_in_place(
                aead::Nonce::assume_unique_for_key(iv),
                aead::Aad::from(name.as_bytes()),
                &mut buf,
            )
            .map_err(|_| SpoolError::Damaged(name.clone()))?
            .to_vec();
        fs::remove_file(&path)?;
        Ok(plain)
    }

    /// Statement files still waiting, as (bank, statement id).
    pub fn pending(&self) -> Result<Vec<(String, String)>, SpoolError> {
        let mut out = Vec::new();
        for entry in fs::read_dir(&self.dir)? {
            let name = entry?.file_name().to_string_lossy().into_owned();
            if let Some(stem) = name.strip_suffix(".stmt")
                && let Some((bank, id)) = stem.split_once("--")
            {
                out.push((bank.to_owned(), id.to_owned()));
            }
        }
        out.sort();
        Ok(out)
    }
}
