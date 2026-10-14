//! The admin listener serves health and metrics to the platform's monitoring on localhost. It
//! uses the ledger's own certificate and the library defaults; no client certificates.

use std::sync::Arc;

use rustls::ServerConfig;

use super::{ListenerError, load_identity};
use crate::settings::TlsSettings;

/// Paths the admin listener answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminPath {
    Health,
    Ready,
    Metrics,
}

impl AdminPath {
    pub fn parse(path: &str) -> Option<AdminPath> {
        match path {
            "/healthz" => Some(AdminPath::Health),
            "/readyz" => Some(AdminPath::Ready),
            "/metrics" => Some(AdminPath::Metrics),
            _ => None,
        }
    }
}

pub fn admin_listener(settings: &TlsSettings) -> Result<Arc<ServerConfig>, ListenerError> {
    let (chain, key) = load_identity(settings)?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)?;
    log::info!("admin listener configured on {}", settings.admin_listen);
    Ok(Arc::new(config))
}
