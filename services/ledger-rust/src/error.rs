//! The crate-level error that `ledgerd` reports. Each module has its own error enum; this one
//! only wraps them so `main` can use `?` across modules.

use crate::approvals::coordinator::CoordinatorError;
use crate::archive::ArchiveError;
use crate::auth::TokenError;
use crate::journal::posting::PostingError;
use crate::journal::signing::SigningError;
use crate::messaging::RoomError;
use crate::settings::SettingsError;
use crate::storage::StoreError;
use crate::tls::ListenerError;

#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error(transparent)]
    Settings(#[from] SettingsError),
    #[error(transparent)]
    Posting(#[from] PostingError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Signing(#[from] SigningError),
    #[error(transparent)]
    Listener(#[from] ListenerError),
    #[error(transparent)]
    Rooms(#[from] RoomError),
    #[error(transparent)]
    Archive(#[from] ArchiveError),
    #[error(transparent)]
    Tokens(#[from] TokenError),
    #[error(transparent)]
    Approvals(#[from] CoordinatorError),
    #[error("transport: {0}")]
    Transport(#[from] TransportError),
    #[error("malformed request: {0}")]
    Request(#[from] serde_json::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("connection closed")]
    Closed,
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
}

impl LedgerError {
    /// Exit code for `ledgerd`: configuration problems are 2, everything else 1.
    pub fn exit_code(&self) -> u8 {
        match self {
            LedgerError::Settings(_) | LedgerError::Listener(_) => 2,
            _ => 1,
        }
    }
}
