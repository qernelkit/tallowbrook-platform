//! Where a held batch is in the approval workflow, as shown in the operator console.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStep {
    /// Held: waiting for approvers to pick it up.
    Proposed,
    /// Approvers are reviewing and returning their shares.
    Signature,
    /// Approved and posted to the journal.
    Posted,
}

impl ApprovalStep {
    pub fn advance(self) -> ApprovalStep {
        match self {
            ApprovalStep::Proposed => ApprovalStep::Signature,
            ApprovalStep::Signature | ApprovalStep::Posted => ApprovalStep::Posted,
        }
    }

    pub fn is_open(self) -> bool {
        self != ApprovalStep::Posted
    }

    pub fn label(self) -> &'static str {
        match self {
            ApprovalStep::Proposed => "waiting for approvers",
            ApprovalStep::Signature => "collecting approvals",
            ApprovalStep::Posted => "posted",
        }
    }
}
