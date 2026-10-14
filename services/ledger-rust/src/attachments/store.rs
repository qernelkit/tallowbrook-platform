//! Content-addressed attachment store. Files are named by the hash of their contents and spread
//! over shard directories; storing the same receipt twice keeps one copy.

use std::fs;
use std::path::PathBuf;

use twox_hash::XxHash64;

use super::kind::{self, AttachmentKind};

/// Shard selection uses the xxHash default seed. Changing it moves every file to another shard.
const SHARD_SEED: u64 = 0;

#[derive(Debug, thiserror::Error)]
pub enum AttachmentError {
    #[error("attachment store i/o: {0}")]
    Io(#[from] std::io::Error),
    #[error("attachment type not accepted: {0}")]
    Rejected(&'static str),
    #[error("attachment {0} not found")]
    NotFound(String),
    #[error("attachment is larger than {0} bytes")]
    TooLarge(usize),
}

/// Largest attachment we accept (25 MiB).
pub const MAX_BYTES: usize = 25 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stored {
    pub address: String,
    pub kind: AttachmentKind,
    pub shard: u64,
    pub size: usize,
}

pub struct AttachmentStore {
    root: PathBuf,
    shard_count: u64,
}

impl AttachmentStore {
    pub fn new(root: PathBuf, shard_count: u64) -> Self {
        Self {
            root,
            shard_count: shard_count.max(1),
        }
    }

    fn path_for(&self, shard: u64, address: &str) -> PathBuf {
        self.root.join(format!("{shard:02x}")).join(address)
    }

    pub fn put(&self, bytes: &[u8]) -> Result<Stored, AttachmentError> {
        if bytes.len() > MAX_BYTES {
            return Err(AttachmentError::TooLarge(MAX_BYTES));
        }
        let kind = kind::sniff(bytes).map_err(AttachmentError::Rejected)?;
        let address = blake3::hash(bytes);
        let hex = address.to_hex().to_string();
        let shard = XxHash64::oneshot(SHARD_SEED, address.as_bytes()) % self.shard_count;
        let path = self.path_for(shard, &hex);
        if !path.exists() {
            fs::create_dir_all(path.parent().expect("shard directory"))?;
            fs::write(&path, bytes)?;
        }
        Ok(Stored {
            address: hex,
            kind,
            shard,
            size: bytes.len(),
        })
    }

    /// Reads an attachment by address. The shard is recomputed from the address.
    pub fn get(&self, address: &str) -> Result<Vec<u8>, AttachmentError> {
        let mut raw = [0u8; 32];
        hex::decode_to_slice(address, &mut raw)
            .map_err(|_| AttachmentError::NotFound(address.to_owned()))?;
        let shard = XxHash64::oneshot(SHARD_SEED, &raw) % self.shard_count;
        fs::read(self.path_for(shard, address)).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => AttachmentError::NotFound(address.to_owned()),
            _ => e.into(),
        })
    }
}
