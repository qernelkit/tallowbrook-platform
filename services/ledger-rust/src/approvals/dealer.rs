//! The treasury key ceremony. Run once per approver rotation on the offline ceremony laptop: it
//! creates one key share per approver and the group public key the coordinator verifies against.
//! Each share is written to its own envelope file and the laptop is wiped afterwards.

use std::fs;
use std::path::{Path, PathBuf};

use frost_ed25519 as frost;
use frost_ed25519::keys::PublicKeyPackage;
use rand::rngs::OsRng;

use super::{APPROVERS, THRESHOLD};

#[derive(Debug, thiserror::Error)]
pub enum CeremonyError {
    #[error("expected {APPROVERS} approvers, got {0}")]
    WrongApproverCount(usize),
    #[error("share generation failed: {0}")]
    Shares(#[from] frost_ed25519::Error),
    #[error("cannot write envelope {path}: {source}")]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
}

/// Output of a ceremony: where each approver's envelope went, and the group key package.
pub struct Ceremony {
    pub envelopes: Vec<(String, PathBuf)>,
    pub pubkey_package: PublicKeyPackage,
}

/// Generates the shares and writes one envelope per approver into `out_dir`.
pub fn run(approvers: &[String], out_dir: &Path) -> Result<Ceremony, CeremonyError> {
    if approvers.len() != usize::from(APPROVERS) {
        return Err(CeremonyError::WrongApproverCount(approvers.len()));
    }
    let (shares, pubkey_package) = frost::keys::generate_with_dealer(
        APPROVERS,
        THRESHOLD,
        frost::keys::IdentifierList::Default,
        &mut OsRng,
    )?;
    let mut envelopes = Vec::with_capacity(approvers.len());
    for (name, (_, share)) in approvers.iter().zip(shares) {
        let path = out_dir.join(format!("{name}.share"));
        let bytes = share.serialize()?;
        fs::write(&path, bytes).map_err(|source| CeremonyError::Write {
            path: path.clone(),
            source,
        })?;
        log::info!("wrote envelope for approver {name}");
        envelopes.push((name.clone(), path));
    }
    Ok(Ceremony {
        envelopes,
        pubkey_package,
    })
}
