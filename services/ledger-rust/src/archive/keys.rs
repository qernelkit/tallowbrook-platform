//! Per-period archive keys, derived from the archive master secret.

use ring::{aead, hkdf};

use super::ArchiveError;

/// Label for the key that seals a closed period's journal.
pub const PERIOD_LABEL: &[u8] = b"tallowbrook ledger archive period v1";

/// Label for the key that wraps the master secret for the escrow agent.
pub const ESCROW_LABEL: &[u8] = b"tallowbrook ledger archive escrow v1";

/// Derives the sealing key for one period (or for the escrow copy) from `secret`.
///
/// `salt_bytes` is the random salt stored in the period's index entry, so re-sealing a period
/// after a correction never reuses a key.
pub fn period_key(
    secret: &[u8],
    salt_bytes: &[u8],
    label: &[u8],
) -> Result<aead::UnboundKey, ArchiveError> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, salt_bytes);
    let prk = salt.extract(secret);
    let info = [label];
    let okm = prk.expand(&info, &aead::AES_256_GCM)?;
    Ok(aead::UnboundKey::from(okm))
}
