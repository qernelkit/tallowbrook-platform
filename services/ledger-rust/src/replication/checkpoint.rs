//! Sync checkpoints. After a branch sync session the head office returns a signed checkpoint:
//! the last batch it accepted from the branch and the Merkle root over that batch. Branch
//! ledgers prune their outbox up to the checkpoint.

use std::fs;
use std::path::Path;

use ed25519_dalek::Signer;
use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum CheckpointError {
    #[error("cannot read the checkpoint seed file: {0}")]
    Read(#[from] std::io::Error),
    #[error("checkpoint seed file must hold exactly 32 bytes")]
    BadSeed,
}

#[derive(Debug, Clone, Serialize)]
pub struct Checkpoint {
    pub branch: String,
    pub last_batch: u64,
    pub merkle_root: Vec<u8>,
    pub issued_at: u64,
}

impl Checkpoint {
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.branch.len());
        out.extend_from_slice(b"TBCP");
        out.extend_from_slice(&(self.branch.len() as u16).to_be_bytes());
        out.extend_from_slice(self.branch.as_bytes());
        out.extend_from_slice(&self.last_batch.to_be_bytes());
        out.extend_from_slice(&self.merkle_root);
        out.extend_from_slice(&self.issued_at.to_be_bytes());
        out
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SignedCheckpoint {
    pub checkpoint: Checkpoint,
    pub signature: Vec<u8>,
}

pub struct CheckpointSigner {
    key: ed25519_dalek::SigningKey,
}

impl CheckpointSigner {
    pub fn load(seed_file: &Path) -> Result<Self, CheckpointError> {
        let raw = fs::read(seed_file)?;
        let seed: [u8; 32] = raw
            .as_slice()
            .try_into()
            .map_err(|_| CheckpointError::BadSeed)?;
        let checkpoint_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        Ok(Self {
            key: checkpoint_key,
        })
    }

    pub fn sign(&self, checkpoint: Checkpoint) -> SignedCheckpoint {
        let payload = checkpoint.canonical_bytes();
        let signature = self.key.sign(&payload).to_bytes().to_vec();
        SignedCheckpoint {
            checkpoint,
            signature,
        }
    }
}
