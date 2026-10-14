//! The alerts room. The ledger bot creates it at start-up and posts operational alerts (stuck
//! approvals, failed bank polls, sync gaps); on-call staff join from their consoles.

use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use serde::Serialize;

use super::signer::ProviderSigner;
use super::{RoomError, group_err};

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Page,
}

#[derive(Debug, Serialize)]
struct Alert<'a> {
    severity: Severity,
    source: &'a str,
    text: &'a str,
    at: u64,
}

pub struct AlertsRoom {
    provider: OpenMlsRustCrypto,
    signer: ProviderSigner,
    config: MlsGroupCreateConfig,
    group: MlsGroup,
    identity: String,
    min_severity: Severity,
}

impl AlertsRoom {
    pub fn create(identity: &str) -> Result<Self, RoomError> {
        let provider = OpenMlsRustCrypto::default();
        let config = MlsGroupCreateConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();
        let scheme = config.ciphersuite().signature_algorithm();
        let signer = ProviderSigner::generate(provider.crypto(), scheme)?;
        let credential = CredentialWithKey {
            credential: BasicCredential::new(identity.as_bytes().to_vec()).into(),
            signature_key: signer.public().into(),
        };
        let group = MlsGroup::new(&provider, &signer, &config, credential).map_err(group_err)?;
        log::info!("alerts room created by {identity}");
        Ok(Self {
            provider,
            signer,
            config,
            group,
            identity: identity.to_owned(),
            min_severity: Severity::Warning,
        })
    }

    /// The bot's key package, published so other rooms can invite the bot.
    pub fn bot_key_package(&self) -> Result<KeyPackage, RoomError> {
        let credential = CredentialWithKey {
            credential: BasicCredential::new(self.identity.as_bytes().to_vec()).into(),
            signature_key: self.signer.public().into(),
        };
        let bundle = KeyPackage::builder()
            .build(
                self.config.ciphersuite(),
                &self.provider,
                &self.signer,
                credential,
            )
            .map_err(group_err)?;
        Ok(bundle.key_package().clone())
    }

    pub fn set_min_severity(&mut self, severity: Severity) {
        self.min_severity = severity;
    }

    /// Posts an alert; returns the encoded message, or `None` if it is below the threshold.
    pub fn post(
        &mut self,
        severity: Severity,
        source: &str,
        text: &str,
        at: u64,
    ) -> Result<Option<Vec<u8>>, RoomError> {
        if severity < self.min_severity {
            log::debug!("alert from {source} below room threshold: {text}");
            return Ok(None);
        }
        let body = serde_json::to_vec(&Alert {
            severity,
            source,
            text,
            at,
        })?;
        let message = self
            .group
            .create_message(&self.provider, &self.signer, &body)
            .map_err(group_err)?;
        Ok(Some(message.to_bytes().map_err(group_err)?))
    }
}
