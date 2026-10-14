//! Checks batches that branch ledgers post over the sync link. A branch signs each batch with its
//! own key; the head office keeps the branch keys in the branch registry.

use base64::prelude::*;
use ring::signature;
use serde::Deserialize;

use crate::journal::batch::batch_digest;
use crate::model::{BatchSource, JournalBatch};

#[derive(Debug, Clone, Deserialize)]
pub struct BranchLedger {
    pub code: String,
    pub depot: String,
    pub public_key: Vec<u8>,
    pub active: bool,
}

/// A batch as a branch ledger posts it.
#[derive(Debug, Clone, Deserialize)]
pub struct PostedBatch {
    pub batch: JournalBatch,
    pub signature_b64: String,
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("batch {0} is not marked as a branch batch")]
    NotBranch(u64),
    #[error("unknown branch {0:?}")]
    UnknownBranch(String),
    #[error("branch {0} is suspended")]
    Suspended(String),
    #[error("batch signature is not valid base64: {0}")]
    Encoding(#[from] base64::DecodeError),
    #[error("batch {batch} from branch {branch}: signature does not verify")]
    Rejected { batch: u64, branch: String },
}

#[derive(Debug, Default)]
pub struct BranchRegistry {
    branches: Vec<BranchLedger>,
}

impl BranchRegistry {
    pub fn new(branches: Vec<BranchLedger>) -> Self {
        Self { branches }
    }

    pub fn get(&self, code: &str) -> Option<&BranchLedger> {
        self.branches.iter().find(|b| b.code == code)
    }

    pub fn active(&self) -> impl Iterator<Item = &BranchLedger> {
        self.branches.iter().filter(|b| b.active)
    }

    /// Accepts a posted batch if it comes from an active branch and its signature verifies.
    pub fn check(&self, posted: &PostedBatch) -> Result<(), VerifyError> {
        let batch = &posted.batch;
        if batch.source != BatchSource::Branch {
            return Err(VerifyError::NotBranch(batch.id));
        }
        let branch = self
            .get(&batch.branch)
            .ok_or_else(|| VerifyError::UnknownBranch(batch.branch.clone()))?;
        if !branch.active {
            return Err(VerifyError::Suspended(branch.code.clone()));
        }
        let value = batch_digest(batch);
        let signature = BASE64_STANDARD.decode(&posted.signature_b64)?;
        let branch_key = signature::UnparsedPublicKey::new(&signature::ED25519, &branch.public_key);
        if branch_key.verify(value.as_ref(), &signature).is_err() {
            log::warn!(
                "batch {} from branch {}: Ed25519 signature rejected",
                batch.id,
                branch.code
            );
            return Err(VerifyError::Rejected {
                batch: batch.id,
                branch: branch.code.clone(),
            });
        }
        log::debug!("batch {} from branch {} accepted", batch.id, branch.code);
        Ok(())
    }
}
