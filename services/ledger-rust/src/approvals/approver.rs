//! The approver side of an approval round, run in the approver's console session.
//!
//! Round 1: the approver commits to fresh nonces for a pending batch.
//! Round 2: after reviewing the batch, the approver signs the batch digest with their share.

use std::collections::BTreeMap;

use frost_ed25519 as frost;
use frost_ed25519::keys::{KeyPackage, SecretShare};
use frost_ed25519::round1::{SigningCommitments, SigningNonces};
use frost_ed25519::round2::SignatureShare;
use frost_ed25519::{Identifier, SigningPackage};
use rand::rngs::OsRng;

use crate::journal::batch::batch_digest;
use crate::model::JournalBatch;

#[derive(Debug, thiserror::Error)]
pub enum ApproverError {
    #[error("key share is not valid: {0}")]
    Share(#[source] frost_ed25519::Error),
    #[error("no commitment outstanding for batch {0}")]
    NoCommitment(u64),
    #[error("the signing request does not match batch {0}")]
    WrongBatch(u64),
    #[error("signing round failed: {0}")]
    Round(#[source] frost_ed25519::Error),
}

pub struct Approver {
    pub name: String,
    key_package: KeyPackage,
    pending: BTreeMap<u64, SigningNonces>,
}

impl Approver {
    /// Opens the approver's envelope (already decoded into a share).
    pub fn from_share(name: &str, secret_share: SecretShare) -> Result<Self, ApproverError> {
        let key_package =
            frost::keys::KeyPackage::try_from(secret_share).map_err(ApproverError::Share)?;
        Ok(Self {
            name: name.to_owned(),
            key_package,
            pending: BTreeMap::new(),
        })
    }

    pub fn identifier(&self) -> Identifier {
        *self.key_package.identifier()
    }

    /// Round 1 for one batch.
    pub fn commit(&mut self, batch_id: u64) -> SigningCommitments {
        let signing_share = self.key_package.signing_share();
        let (nonces, commitments) = frost::round1::commit(signing_share, &mut OsRng);
        self.pending.insert(batch_id, nonces);
        commitments
    }

    /// Round 2: refuses to sign anything but the digest of the batch the approver reviewed.
    pub fn approve(
        &mut self,
        batch: &JournalBatch,
        signing_package: &SigningPackage,
    ) -> Result<SignatureShare, ApproverError> {
        let expected = batch_digest(batch);
        if signing_package.message().as_slice() != expected.as_ref() {
            return Err(ApproverError::WrongBatch(batch.id));
        }
        let nonces = self
            .pending
            .remove(&batch.id)
            .ok_or(ApproverError::NoCommitment(batch.id))?;
        let share = frost::round2::sign(signing_package, &nonces, &self.key_package)
            .map_err(ApproverError::Round)?;
        log::info!("approver {} signed batch {}", self.name, batch.id);
        Ok(share)
    }

    /// Drops the nonces of a batch that was withdrawn before round 2.
    pub fn abandon(&mut self, batch_id: u64) {
        self.pending.remove(&batch_id);
    }
}
