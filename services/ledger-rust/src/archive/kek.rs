//! Loads the archive key-encryption key and recovers the archive master secret from the blob
//! stored next to the archive. The key file is installed by the deploy pipeline and only
//! readable by the ledger service account.

use std::fmt;
use std::fs;

use ml_kem::Decapsulate;
use ml_kem::pkcs8::DecodePrivateKey;

use super::ArchiveError;
use crate::settings::ArchiveSettings;

/// The archive master secret. Kept out of `Debug` output and logs.
pub struct MasterSecret(Vec<u8>);

impl MasterSecret {
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for MasterSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MasterSecret(..)")
    }
}

/// Recovers the archive master secret.
pub fn recover_master_secret(settings: &ArchiveSettings) -> Result<MasterSecret, ArchiveError> {
    let pem = fs::read_to_string(&settings.kek)?;
    let kek = ml_kem::DecapsulationKey768::from_pkcs8_pem(&pem)
        .map_err(|_| ArchiveError::BadKey(settings.kek.clone()))?;
    let stored_ct = fs::read(&settings.master_secret_blob)?;
    let shared = kek
        .decapsulate_slice(&stored_ct)
        .map_err(|_| ArchiveError::BadBlob)?;
    log::info!("archive master secret recovered");
    Ok(MasterSecret(shared.to_vec()))
}
