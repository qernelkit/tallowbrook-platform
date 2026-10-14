//! Settlement instructions for the freight-escrow contract. The ledger signs each instruction with
//! the settlement wallet; the web side submits it.

pub mod instruction;
pub mod wallet;

pub use instruction::{InstructionKind, SettlementInstruction};
pub use wallet::{SettlementWallet, SignedInstruction};
