//! Archive of closed accounting periods. When a period closes, its journal is sealed into one
//! archive file under a key derived for that period from the archive master secret. The master
//! secret is held under the archive key-encryption key, and a copy is wrapped for the external
//! escrow agent so the archive survives the loss of our own key.

pub mod escrow;
pub mod kek;
pub mod keys;
pub mod period_seal;

use std::path::PathBuf;

use crate::model::Period;

/// The escrow agent's public key; the master secret is wrapped to it on every rotation.
pub type EscrowKey = ml_kem::EncapsulationKey1024;

/// Index entry for one sealed period.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ArchivedPeriod {
    pub period: Period,
    pub file: PathBuf,
    pub salt: [u8; 32],
    pub sealed_at: u64,
    pub batches: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum ArchiveError {
    #[error("archive i/o: {0}")]
    Io(#[from] std::io::Error),
    #[error("cannot load archive key {0}")]
    BadKey(PathBuf),
    #[error("stored master secret blob is malformed")]
    BadBlob,
    #[error("key derivation failed")]
    Derivation,
    #[error("archive file for {0} is malformed")]
    Format(Period),
    #[error("archive file for {0} failed authentication")]
    Tampered(Period),
    #[error("random source failed")]
    Random,
    #[error("cannot encode escrow package: {0}")]
    Encode(#[from] serde_json::Error),
}

impl From<ring::error::Unspecified> for ArchiveError {
    fn from(_: ring::error::Unspecified) -> Self {
        ArchiveError::Derivation
    }
}
