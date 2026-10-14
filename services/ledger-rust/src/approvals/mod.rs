//! Treasury approvals. A batch whose largest line is at or above the approval threshold is held
//! until two of the three treasury approvers have signed it; the coordinator combines their
//! shares into one signature that verifies under the treasury group key.

pub mod approver;
pub mod coordinator;
pub mod dealer;
pub mod signature_state;

use crate::journal::posting::largest_line;
use crate::model::JournalBatch;

/// Treasury approvers holding a key share.
pub const APPROVERS: u16 = 3;

/// Shares needed to approve a batch.
pub const THRESHOLD: u16 = 2;

pub use signature_state::ApprovalStep;

/// Whether a batch has to wait for treasury approval before it is posted.
pub fn needs_approval(batch: &JournalBatch, threshold_minor: i64) -> bool {
    largest_line(batch) >= threshold_minor
}
