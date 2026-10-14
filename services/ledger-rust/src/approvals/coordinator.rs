//! The coordinator runs in ledgerd. It opens a round for a held batch, collects commitments from
//! the approvers, hands out the signing request, and combines the returned shares.

use std::collections::BTreeMap;

use frost_ed25519 as frost;
use frost_ed25519::keys::PublicKeyPackage;
use frost_ed25519::round1::SigningCommitments;
use frost_ed25519::round2::SignatureShare;
use frost_ed25519::{Identifier, Signature, SigningPackage};

use super::THRESHOLD;
use super::signature_state::ApprovalStep;
use crate::journal::batch::batch_digest;
use crate::model::JournalBatch;

#[derive(Debug, thiserror::Error)]
pub enum CoordinatorError {
    #[error("no approval round for batch {0}")]
    NoRound(u64),
    #[error("batch {batch}: {have} of {THRESHOLD} commitments so far")]
    NotEnoughCommitments { batch: u64, have: usize },
    #[error("batch {0}: signing request not issued yet")]
    NotIssued(u64),
    #[error("batch {0}: combining shares failed: {1}")]
    Combine(u64, #[source] frost_ed25519::Error),
}

/// Combined treasury approval for a batch.
#[derive(Debug, Clone)]
pub struct Approval {
    pub batch_id: u64,
    pub signature: Signature,
    pub approvers: Vec<Identifier>,
}

struct Round {
    value: Vec<u8>,
    step: ApprovalStep,
    commitments: BTreeMap<Identifier, SigningCommitments>,
    request: Option<SigningPackage>,
    shares: BTreeMap<Identifier, SignatureShare>,
}

pub struct Coordinator {
    pubkey_package: PublicKeyPackage,
    rounds: BTreeMap<u64, Round>,
}

impl Coordinator {
    pub fn new(pubkey_package: PublicKeyPackage) -> Self {
        Self {
            pubkey_package,
            rounds: BTreeMap::new(),
        }
    }

    pub fn open(&mut self, batch: &JournalBatch) {
        let value = batch_digest(batch).as_ref().to_vec();
        self.rounds.insert(
            batch.id,
            Round {
                value,
                step: ApprovalStep::Proposed,
                commitments: BTreeMap::new(),
                request: None,
                shares: BTreeMap::new(),
            },
        );
    }

    pub fn step(&self, batch_id: u64) -> Option<ApprovalStep> {
        self.rounds.get(&batch_id).map(|r| r.step)
    }

    pub fn add_commitment(
        &mut self,
        batch_id: u64,
        approver: Identifier,
        commitments: SigningCommitments,
    ) -> Result<(), CoordinatorError> {
        let round = self
            .rounds
            .get_mut(&batch_id)
            .ok_or(CoordinatorError::NoRound(batch_id))?;
        round.commitments.insert(approver, commitments);
        Ok(())
    }

    /// Issues the signing request once enough approvers have committed.
    pub fn request(&mut self, batch_id: u64) -> Result<SigningPackage, CoordinatorError> {
        let round = self
            .rounds
            .get_mut(&batch_id)
            .ok_or(CoordinatorError::NoRound(batch_id))?;
        if round.commitments.len() < usize::from(THRESHOLD) {
            return Err(CoordinatorError::NotEnoughCommitments {
                batch: batch_id,
                have: round.commitments.len(),
            });
        }
        let commitments = round.commitments.clone();
        let signing_package = frost::SigningPackage::new(commitments, round.value.as_ref());
        round.request = Some(signing_package.clone());
        round.step = round.step.advance();
        Ok(signing_package)
    }

    pub fn add_share(
        &mut self,
        batch_id: u64,
        approver: Identifier,
        share: SignatureShare,
    ) -> Result<(), CoordinatorError> {
        let round = self
            .rounds
            .get_mut(&batch_id)
            .ok_or(CoordinatorError::NoRound(batch_id))?;
        round.shares.insert(approver, share);
        Ok(())
    }

    /// Combines the shares and checks the result against the treasury group key.
    pub fn finish(&mut self, batch_id: u64) -> Result<Approval, CoordinatorError> {
        let round = self
            .rounds
            .get_mut(&batch_id)
            .ok_or(CoordinatorError::NoRound(batch_id))?;
        let signing_package = round
            .request
            .as_ref()
            .ok_or(CoordinatorError::NotIssued(batch_id))?;
        let shares = &round.shares;
        let approval = frost::aggregate(signing_package, shares, &self.pubkey_package)
            .map_err(|e| CoordinatorError::Combine(batch_id, e))?;
        self.pubkey_package
            .verifying_key()
            .verify(&round.value, &approval)
            .map_err(|e| CoordinatorError::Combine(batch_id, e))?;
        round.step = round.step.advance();
        let approvers = shares.keys().copied().collect();
        log::info!("batch {batch_id} approved by {} approvers", shares.len());
        Ok(Approval {
            batch_id,
            signature: approval,
            approvers,
        })
    }
}
