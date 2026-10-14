//! Writes passphrase-protected statement bundles.
//!
//! Bundle layout: magic "TBSX", format (1), sealing format id (1), salt (16), IV (12), then the
//! sealed payload. The payload is the manifest followed by each file, length-prefixed. The
//! sealing format is configured as `[export] bundle_cipher` and recorded in the header so
//! older bundles stay readable.

use std::num::NonZeroU32;

use ring::rand::{SecureRandom, SystemRandom};
use ring::{aead, pbkdf2};

use super::bundle_manifest::{self, BundledFile};

const MAGIC: &[u8; 4] = b"TBSX";
const FORMAT: u8 = 1;
const SALT_LEN: usize = 16;

const EXPORT_KDF_ITERATIONS: u32 = 600_000;

#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    #[error("unknown bundle format {0:?} in [export] settings")]
    UnknownFormat(String),
    #[error("bundle would hold {0} statements, the limit is {1}")]
    TooLarge(usize, usize),
    #[error("passphrase must be at least 12 characters")]
    ShortPassphrase,
    #[error("cannot encode the manifest: {0}")]
    Manifest(#[from] serde_json::Error),
    #[error("sealing the bundle failed")]
    Seal,
}

impl From<ring::error::Unspecified> for ExportError {
    fn from(_: ring::error::Unspecified) -> Self {
        ExportError::Seal
    }
}

/// Maps the configured name to the sealing algorithm and the format id written in the header.
fn bundle_cipher(name: &str) -> Result<(&'static aead::Algorithm, u8), ExportError> {
    match name {
        "aes-256-gcm" => Ok((&aead::AES_256_GCM, 1)),
        "chacha20-poly1305" => Ok((&aead::CHACHA20_POLY1305, 2)),
        other => Err(ExportError::UnknownFormat(other.to_owned())),
    }
}

fn bundle_key(
    passphrase: &str,
    salt: &[u8],
    algorithm: &'static aead::Algorithm,
) -> Result<aead::LessSafeKey, ExportError> {
    let iterations = NonZeroU32::new(EXPORT_KDF_ITERATIONS).ok_or(ExportError::Seal)?;
    let mut key = vec![0u8; algorithm.key_len()];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        salt,
        passphrase.as_bytes(),
        &mut key,
    );
    let unbound = aead::UnboundKey::new(algorithm, &key)?;
    Ok(aead::LessSafeKey::new(unbound))
}

pub struct BundleWriter {
    format_id: u8,
    algorithm: &'static aead::Algorithm,
    max_statements: usize,
    instance: String,
    rng: SystemRandom,
}

impl BundleWriter {
    pub fn new(
        format_name: &str,
        max_statements: usize,
        instance: &str,
    ) -> Result<Self, ExportError> {
        let (algorithm, format_id) = bundle_cipher(format_name)?;
        Ok(Self {
            format_id,
            algorithm,
            max_statements,
            instance: instance.to_owned(),
            rng: SystemRandom::new(),
        })
    }

    fn payload(&self, files: &[BundledFile], now: u64) -> Result<Vec<u8>, ExportError> {
        let manifest = bundle_manifest::build(files, now, &self.instance);
        let manifest_json = serde_json::to_vec_pretty(&manifest)?;
        let mut out = Vec::new();
        for (name, bytes) in std::iter::once(("manifest.json", manifest_json.as_slice()))
            .chain(files.iter().map(|f| (f.name.as_str(), f.bytes.as_slice())))
        {
            out.extend_from_slice(&(name.len() as u16).to_be_bytes());
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            out.extend_from_slice(bytes);
        }
        Ok(out)
    }

    /// Packs and seals `files` under `passphrase`.
    pub fn write(
        &self,
        files: &[BundledFile],
        passphrase: &str,
        now: u64,
    ) -> Result<Vec<u8>, ExportError> {
        if files.len() > self.max_statements {
            return Err(ExportError::TooLarge(files.len(), self.max_statements));
        }
        if passphrase.chars().count() < 12 {
            return Err(ExportError::ShortPassphrase);
        }
        let mut salt = [0u8; SALT_LEN];
        let mut iv = [0u8; aead::NONCE_LEN];
        self.rng.fill(&mut salt)?;
        self.rng.fill(&mut iv)?;

        let mut header = MAGIC.to_vec();
        header.push(FORMAT);
        header.push(self.format_id);
        header.extend_from_slice(&salt);
        header.extend_from_slice(&iv);

        let key = bundle_key(passphrase, &salt, self.algorithm)?;
        let mut sealed = self.payload(files, now)?;
        key.seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(iv),
            aead::Aad::from(header.as_slice()),
            &mut sealed,
        )?;
        header.extend_from_slice(&sealed);
        log::info!("statement bundle with {} files written", files.len());
        Ok(header)
    }
}
