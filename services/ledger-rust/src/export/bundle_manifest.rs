//! manifest.json inside a statement bundle: one entry per bundled file with its size and a
//! checksum the recipient can check after opening the bundle.

use ring::digest;
use serde::Serialize;

/// A file going into a bundle.
#[derive(Debug, Clone)]
pub struct BundledFile {
    pub name: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ManifestEntry {
    pub name: String,
    pub size: usize,
    pub checksum: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Manifest {
    pub format: u32,
    pub created_at: u64,
    pub generated_by: String,
    pub files: Vec<ManifestEntry>,
}

pub fn entry_for(file: &BundledFile) -> ManifestEntry {
    let checksum = digest::digest(&digest::SHA512, &file.bytes);
    ManifestEntry {
        name: file.name.clone(),
        size: file.bytes.len(),
        checksum: hex::encode(checksum.as_ref()),
    }
}

pub fn build(files: &[BundledFile], created_at: u64, instance: &str) -> Manifest {
    Manifest {
        format: 1,
        created_at,
        generated_by: format!("tallowbrook-ledger {instance}"),
        files: files.iter().map(entry_for).collect(),
    }
}
