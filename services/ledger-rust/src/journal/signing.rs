//! Signs journal batches posted by this ledger. Branch ledgers and the reporting service check
//! these signatures before they trust a batch.

use std::fs;
use std::path::Path;

use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::Serialize;

use crate::journal::batch::batch_digest;
use crate::model::JournalBatch;

#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    #[error("cannot read the batch signing key file: {0}")]
    Read(#[from] std::io::Error),
    #[error("the batch signing key file is not a usable key document")]
    BadKey,
}

/// A batch signature as stored next to the batch and sent to subscribers.
#[derive(Debug, Clone, Serialize)]
pub struct BatchSignature {
    pub batch_id: u64,
    pub key_id: String,
    pub signature: Vec<u8>,
}

pub struct BatchSigner {
    key: Ed25519KeyPair,
    key_id: String,
}

impl BatchSigner {
    /// Loads the signing key that the deploy pipeline installs on the host.
    pub fn load(path: &Path) -> Result<Self, SigningError> {
        let pkcs8 = fs::read(path)?;
        let key_pair = Ed25519KeyPair::from_pkcs8(&pkcs8).map_err(|_| SigningError::BadKey)?;
        let key_id = key_id_of(key_pair.public_key().as_ref());
        log::info!("batch signer loaded, key id {key_id}");
        Ok(Self {
            key: key_pair,
            key_id,
        })
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Public half, published to branch ledgers in the ledger's key directory.
    pub fn verifying_bytes(&self) -> Vec<u8> {
        self.key.public_key().as_ref().to_vec()
    }

    pub fn sign(&self, batch: &JournalBatch) -> BatchSignature {
        let value = batch_digest(batch);
        let sig = self.key.sign(value.as_ref());
        BatchSignature {
            batch_id: batch.id,
            key_id: self.key_id.clone(),
            signature: sig.as_ref().to_vec(),
        }
    }
}

/// Key ids are the first eight bytes of the public half, in hex.
fn key_id_of(public: &[u8]) -> String {
    hex::encode(&public[..8.min(public.len())])
}
