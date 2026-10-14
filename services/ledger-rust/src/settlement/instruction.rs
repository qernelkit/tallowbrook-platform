//! The settlement instruction model and its canonical bytes.

use serde::{Deserialize, Serialize};

use crate::model::{Currency, Period};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstructionKind {
    /// Release escrowed freight charges to the carrier.
    Release,
    /// Return escrowed charges to the shipper after a cancelled consignment.
    Refund,
    /// Hold the escrow while a dispute is open.
    Hold,
}

impl InstructionKind {
    fn code(self) -> u8 {
        match self {
            InstructionKind::Release => 1,
            InstructionKind::Refund => 2,
            InstructionKind::Hold => 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementInstruction {
    pub contract: String,
    pub sequence: u64,
    pub kind: InstructionKind,
    pub consignment: String,
    pub payee: String,
    pub amount_minor: i64,
    pub currency: Currency,
    pub period: Period,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum InstructionError {
    #[error("amount must be positive")]
    NonPositive,
    #[error("amount {0} is above the per-instruction limit")]
    OverLimit(i64),
    #[error("consignment reference is empty")]
    NoConsignment,
}

impl SettlementInstruction {
    pub fn check(&self, max_minor: i64) -> Result<(), InstructionError> {
        if self.amount_minor <= 0 {
            return Err(InstructionError::NonPositive);
        }
        if self.amount_minor > max_minor {
            return Err(InstructionError::OverLimit(self.amount_minor));
        }
        if self.consignment.trim().is_empty() {
            return Err(InstructionError::NoConsignment);
        }
        Ok(())
    }

    /// Canonical bytes, in the order the escrow contract reads them.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        for part in [&self.contract, &self.consignment, &self.payee] {
            out.extend_from_slice(&(part.len() as u16).to_be_bytes());
            out.extend_from_slice(part.as_bytes());
        }
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.push(self.kind.code());
        out.extend_from_slice(&self.amount_minor.to_be_bytes());
        out.extend_from_slice(self.currency.as_str().as_bytes());
        out.extend_from_slice(&self.period.year.to_be_bytes());
        out.push(self.period.month);
        out
    }
}
