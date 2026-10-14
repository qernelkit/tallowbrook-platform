//! Transport security for the ledger: the ledger listener (branches and operator consoles), the
//! admin listener, and the outbound clients for bank feeds and the DR replica.

pub mod admin_listener;
pub mod clients;
pub mod policy;
pub mod server;

use std::path::{Path, PathBuf};

use rustls::RootCertStore;
use rustls::pki_types::pem::{Error as PemError, PemObject};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::settings::TlsSettings;

#[derive(Debug, thiserror::Error)]
pub enum ListenerError {
    #[error("cannot load {path}: {source}")]
    Load { path: PathBuf, source: PemError },
    #[error("listener configuration rejected: {0}")]
    Config(#[from] rustls::Error),
    #[error("client verifier configuration rejected: {0}")]
    Verifier(#[from] rustls::server::VerifierBuilderError),
}

fn load_err(path: &Path, source: PemError) -> ListenerError {
    ListenerError::Load {
        path: path.to_owned(),
        source,
    }
}

/// The ledger's own chain and key, presented by both listeners and by the replica client.
pub fn load_identity(
    settings: &TlsSettings,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), ListenerError> {
    let chain_path = &settings.cert_chain;
    let chain = CertificateDer::pem_file_iter(chain_path)
        .and_then(|certs| certs.collect::<Result<Vec<_>, _>>())
        .map_err(|e| load_err(chain_path, e))?;
    let key_path = &settings.private_key;
    let key = PrivateKeyDer::from_pem_file(key_path).map_err(|e| load_err(key_path, e))?;
    Ok((chain, key))
}

/// Trust anchors from a PEM bundle.
pub fn load_roots(path: &Path) -> Result<RootCertStore, ListenerError> {
    let mut roots = RootCertStore::empty();
    for anchor in CertificateDer::pem_file_iter(path).map_err(|e| load_err(path, e))? {
        roots.add(anchor.map_err(|e| load_err(path, e))?)?;
    }
    log::debug!("{} trust anchors from {}", roots.len(), path.display());
    Ok(roots)
}
