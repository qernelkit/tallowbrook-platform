//! `ledger.toml`, deserialised. Every path is opened by the module that needs it; this module only
//! parses and sanity-checks values.

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::bankfeed::statement_verify::StatementSigFormat;

#[derive(Debug, Clone, Deserialize)]
pub struct Settings {
    pub ledger: LedgerSettings,
    pub tls: TlsSettings,
    pub replication: ReplicationSettings,
    pub archive: ArchiveSettings,
    pub settlement: SettlementSettings,
    pub auth: AuthSettings,
    pub export: ExportSettings,
    pub operators: OperatorSettings,
    pub audit: AuditSettings,
    pub notify: NotifySettings,
    pub attachments: AttachmentSettings,
    pub messaging: MessagingSettings,
    pub bankfeed: BankFeedSettings,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LedgerSettings {
    pub instance: String,
    pub data_dir: PathBuf,
    pub approval_threshold_minor: i64,
    pub journal_signing_key: PathBuf,
    pub checkpoint_seed: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsSettings {
    pub listen: SocketAddr,
    pub admin_listen: SocketAddr,
    pub cert_chain: PathBuf,
    pub private_key: PathBuf,
    pub client_ca: PathBuf,
    pub bank_feed_roots: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ReplicationSettings {
    pub replica_host: String,
    pub replica_port: u16,
    pub snapshot_interval_secs: u64,
    pub branch_sync_window_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ArchiveSettings {
    pub directory: PathBuf,
    pub kek: PathBuf,
    pub master_secret_blob: PathBuf,
    pub escrow_agent_key: PathBuf,
    pub escrow_drop: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SettlementSettings {
    pub wallet_key: PathBuf,
    pub contract: String,
    pub max_instruction_minor: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthSettings {
    pub issuer: String,
    pub operator_token_key: PathBuf,
    pub operator_token_verifier: PathBuf,
    pub operator_session_secs: u64,
    pub console_issuer: String,
    pub console_token_key: PathBuf,
    pub reporting_audience: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ExportSettings {
    pub staging_dir: PathBuf,
    pub bundle_cipher: String,
    pub max_statements: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OperatorSettings {
    pub recovery_dir: PathBuf,
    pub pin_file: PathBuf,
    pub state_dir: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuditSettings {
    pub statement_key: PathBuf,
    pub auditors: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NotifySettings {
    pub webhook_timeout_ms: u64,
    pub targets: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AttachmentSettings {
    pub root: PathBuf,
    pub shard_count: u64,
    pub link_ttl_secs: u64,
    pub public_base: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MessagingSettings {
    pub operator_room: String,
    pub alerts_room: String,
    pub bot_identity: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BankFeedSettings {
    pub spool_dir: PathBuf,
    pub payment_key: PathBuf,
    pub api_request_key: PathBuf,
    pub onboarding_dir: PathBuf,
    pub poll_interval_secs: u64,
    pub banks: Vec<BankProfile>,
}

/// One bank we fetch statements from and send payment files to.
#[derive(Debug, Clone, Deserialize)]
pub struct BankProfile {
    pub code: String,
    pub name: String,
    pub api_base: String,
    pub statement_signature: StatementSigFormat,
    pub statement_key: PathBuf,
    pub callback_version: u8,
    pub settlement_account: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum SettingsError {
    #[error("cannot read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid settings in {path}: {source}")]
    Parse {
        path: PathBuf,
        source: toml::de::Error,
    },
    #[error("invalid settings: {0}")]
    Invalid(String),
}

impl Settings {
    pub fn load(path: &Path) -> Result<Settings, SettingsError> {
        let text = fs::read_to_string(path).map_err(|source| SettingsError::Read {
            path: path.to_owned(),
            source,
        })?;
        let settings: Settings = toml::from_str(&text).map_err(|source| SettingsError::Parse {
            path: path.to_owned(),
            source,
        })?;
        settings.validate()?;
        Ok(settings)
    }

    fn validate(&self) -> Result<(), SettingsError> {
        if self.ledger.approval_threshold_minor <= 0 {
            return Err(SettingsError::Invalid(
                "ledger.approval_threshold_minor must be positive".into(),
            ));
        }
        if self.attachments.shard_count == 0 {
            return Err(SettingsError::Invalid(
                "attachments.shard_count must be at least 1".into(),
            ));
        }
        let mut codes: Vec<&str> = self
            .bankfeed
            .banks
            .iter()
            .map(|b| b.code.as_str())
            .collect();
        codes.sort_unstable();
        if codes.windows(2).any(|w| w[0] == w[1]) {
            return Err(SettingsError::Invalid(
                "duplicate bank code in bankfeed.banks".into(),
            ));
        }
        for bank in &self.bankfeed.banks {
            if !matches!(bank.callback_version, 1 | 2) {
                return Err(SettingsError::Invalid(format!(
                    "bank {}: callback_version must be 1 or 2",
                    bank.code
                )));
            }
        }
        Ok(())
    }

    pub fn bank(&self, code: &str) -> Option<&BankProfile> {
        self.bankfeed.banks.iter().find(|b| b.code == code)
    }
}
