//! The settlement wallet signs instructions for the freight-escrow contract. The contract checks
//! the recoverable signature against the wallet address it was deployed with.

use std::fs;
use std::path::Path;

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use k256::sha2::{Digest, Sha256};
use serde::Serialize;

use super::instruction::SettlementInstruction;

#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    #[error("cannot read the wallet key file: {0}")]
    Read(#[from] std::io::Error),
    #[error("the wallet key file is not a usable key document")]
    BadKey,
    #[error("signature does not recover to a wallet")]
    Unrecoverable,
}

/// An instruction with its 65-byte recoverable signature (r || s || v).
#[derive(Debug, Clone, Serialize)]
pub struct SignedInstruction {
    pub instruction: SettlementInstruction,
    pub signature: Vec<u8>,
}

pub struct SettlementWallet {
    key: k256::ecdsa::SigningKey,
}

/// The value the contract checks: a hash of the canonical instruction bytes.
fn instruction_prehash(instruction: &SettlementInstruction) -> [u8; 32] {
    let prehash = Sha256::digest(&instruction.canonical_bytes());
    prehash.into()
}

impl SettlementWallet {
    pub fn from_secret(secret: k256::SecretKey) -> Self {
        Self {
            key: k256::ecdsa::SigningKey::from(secret),
        }
    }

    /// Loads the wallet from the SEC1 key file configured as `settlement.wallet_key`.
    pub fn from_sec1_pem(path: &Path) -> Result<Self, WalletError> {
        let pem = fs::read_to_string(path)?;
        let secret = k256::SecretKey::from_sec1_pem(&pem).map_err(|_| WalletError::BadKey)?;
        Ok(Self::from_secret(secret))
    }

    /// The wallet's public point, SEC1-compressed.
    pub fn public_sec1(&self) -> Vec<u8> {
        self.key.verifying_key().to_sec1_bytes().to_vec()
    }

    pub fn sign(&self, instruction: &SettlementInstruction) -> SignedInstruction {
        let prehash = instruction_prehash(instruction);
        let (signature, recovery) = self.key.sign_prehash_recoverable(&prehash);
        let mut bytes = signature.to_bytes().to_vec();
        bytes.push(recovery.to_byte());
        SignedInstruction {
            instruction: instruction.clone(),
            signature: bytes,
        }
    }

    /// Recovers the signing wallet's public point from a signed instruction.
    pub fn recover(signed: &SignedInstruction) -> Result<Vec<u8>, WalletError> {
        let (rs, v) = signed
            .signature
            .split_last_chunk::<1>()
            .ok_or(WalletError::Unrecoverable)?;
        let signature = Signature::from_slice(rs).map_err(|_| WalletError::Unrecoverable)?;
        let recovery = RecoveryId::from_byte(v[0]).ok_or(WalletError::Unrecoverable)?;
        let prehash = instruction_prehash(&signed.instruction);
        let point = VerifyingKey::recover_from_prehash(&prehash, &signature, recovery)
            .map_err(|_| WalletError::Unrecoverable)?;
        Ok(point.to_sec1_bytes().to_vec())
    }
}
