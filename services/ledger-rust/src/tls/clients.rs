//! Outbound clients: bank feeds and the DR replica link.

use std::sync::Arc;

use rustls::crypto::CryptoProvider;
use rustls::crypto::aws_lc_rs::{self, kx_group};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, version};

use super::{ListenerError, load_identity, load_roots, policy};
use crate::settings::{ReplicationSettings, TlsSettings};

/// The bank APIs are public endpoints with public certificates; we trust the egress root bundle
/// and leave everything else to the library.
pub fn bank_feed_client(settings: &TlsSettings) -> Result<Arc<ClientConfig>, ListenerError> {
    let roots = load_roots(&settings.bank_feed_roots)?;
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// The DR replica sits on our own network and is issued by our CA. The link carries full journal
/// snapshots, so it gets our suite policy and the larger key-exchange groups only.
pub fn replica_client(settings: &TlsSettings) -> Result<Arc<ClientConfig>, ListenerError> {
    let provider = Arc::new(CryptoProvider {
        cipher_suites: policy::LEDGER_TLS13_SUITES.to_vec(),
        kx_groups: vec![kx_group::MLKEM1024, kx_group::X25519MLKEM768],
        ..aws_lc_rs::default_provider()
    });
    let roots = load_roots(&settings.client_ca)?;
    let (chain, key) = load_identity(settings)?;
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&version::TLS13])?
        .with_root_certificates(roots)
        .with_client_auth_cert(chain, key)?;
    Ok(Arc::new(config))
}

/// Host name the replica certificate is checked against.
pub fn replica_name(replication: &ReplicationSettings) -> Option<ServerName<'static>> {
    ServerName::try_from(replication.replica_host.clone()).ok()
}

/// Host name for a bank API base URL such as `https://api.bank.example/v3`.
pub fn bank_host(api_base: &str) -> Option<ServerName<'static>> {
    let rest = api_base.split_once("://").map_or(api_base, |(_, r)| r);
    let host = rest.split(['/', ':']).next()?;
    ServerName::try_from(host.to_owned()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bank_host_strips_scheme_and_path() {
        let name = bank_host("https://api.harbor-national.example/v3").unwrap();
        assert_eq!(name.to_str(), "api.harbor-national.example");
    }
}
