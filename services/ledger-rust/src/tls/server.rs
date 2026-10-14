//! The ledger listener. Branch ledgers and operator consoles connect with client certificates
//! issued by the internal issuing CA; nothing else is accepted.

use std::sync::Arc;

use rustls::crypto::CryptoProvider;
use rustls::crypto::aws_lc_rs::{self, kx_group};
use rustls::server::WebPkiClientVerifier;
use rustls::{ServerConfig, version};

use super::{ListenerError, load_identity, load_roots, policy};
use crate::settings::TlsSettings;

/// ALPN ids the listener speaks: the posting API and the branch sync protocol.
const ALPN: [&[u8]; 2] = [b"tbledger/2", b"tbsync/1"];

fn listener_provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: policy::LEDGER_TLS13_SUITES.to_vec(),
        kx_groups: vec![
            kx_group::X25519MLKEM768,
            kx_group::X25519,
            kx_group::SECP256R1,
        ],
        ..aws_lc_rs::default_provider()
    }
}

/// Builds the listener configuration from the `[tls]` settings.
pub fn ledger_listener(settings: &TlsSettings) -> Result<Arc<ServerConfig>, ListenerError> {
    let provider = Arc::new(listener_provider());
    let (chain, key) = load_identity(settings)?;
    let client_roots = Arc::new(load_roots(&settings.client_ca)?);
    let verifier =
        WebPkiClientVerifier::builder_with_provider(client_roots, provider.clone()).build()?;
    log::info!("ledger listener: TLS 1.3 only, X25519MLKEM768 preferred");
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&version::TLS13])?
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)?;
    config.alpn_protocols = ALPN.iter().map(|p| p.to_vec()).collect();
    config.max_early_data_size = 0;
    Ok(Arc::new(config))
}

/// Which protocol a connection negotiated, for routing after accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    PostingApi,
    BranchSync,
}

pub fn route(alpn: Option<&[u8]>) -> Option<Route> {
    match alpn? {
        b"tbledger/2" => Some(Route::PostingApi),
        b"tbsync/1" => Some(Route::BranchSync),
        _ => None,
    }
}
