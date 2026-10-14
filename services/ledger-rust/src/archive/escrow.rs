//! Wraps the archive master secret for the external escrow agent. The agent can recover the
//! archive with its own private key if Tallowbrook loses the archive key-encryption key.

use std::fs;
use std::path::PathBuf;

use ml_kem::Encapsulate;
use ml_kem::pkcs8::DecodePublicKey;
use ring::aead;
use ring::rand::{SecureRandom, SystemRandom};
use serde::Serialize;

use super::keys::{ESCROW_LABEL, period_key};
use super::{ArchiveError, EscrowKey};
use crate::settings::ArchiveSettings;

/// What the escrow agent receives. All fields are hex in the JSON file.
#[derive(Debug, Serialize)]
pub struct EscrowPackage {
    pub instance: String,
    pub created_at: u64,
    pub encapsulated: String,
    pub salt: String,
    pub iv: String,
    pub wrapped_secret: String,
}

/// Wraps `master` to the agent's key and drops the package into the escrow directory.
pub fn deposit(
    settings: &ArchiveSettings,
    instance: &str,
    master: &[u8],
    now: u64,
    rng: &SystemRandom,
) -> Result<PathBuf, ArchiveError> {
    let pem = fs::read_to_string(&settings.escrow_agent_key)?;
    let agent_key = EscrowKey::from_public_key_pem(&pem)
        .map_err(|_| ArchiveError::BadKey(settings.escrow_agent_key.clone()))?;
    let (encapsulated, shared) = agent_key.encapsulate();

    let mut salt = [0u8; 32];
    let mut iv = [0u8; aead::NONCE_LEN];
    rng.fill(&mut salt).map_err(|_| ArchiveError::Random)?;
    rng.fill(&mut iv).map_err(|_| ArchiveError::Random)?;

    let key = aead::LessSafeKey::new(period_key(shared.as_slice(), &salt, ESCROW_LABEL)?);
    let mut wrapped = master.to_vec();
    key.seal_in_place_append_tag(
        aead::Nonce::assume_unique_for_key(iv),
        aead::Aad::from(instance.as_bytes()),
        &mut wrapped,
    )?;

    let package = EscrowPackage {
        instance: instance.to_owned(),
        created_at: now,
        encapsulated: hex::encode(encapsulated.as_slice()),
        salt: hex::encode(salt),
        iv: hex::encode(iv),
        wrapped_secret: hex::encode(&wrapped),
    };
    let path = settings.escrow_drop.join(format!("{instance}-{now}.json"));
    fs::write(&path, serde_json::to_vec_pretty(&package)?)?;
    log::info!("escrow package written to {}", path.display());
    Ok(path)
}
