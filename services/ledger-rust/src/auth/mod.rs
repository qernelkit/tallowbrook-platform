//! Bearer tokens: operator sessions issued by the ledger, tokens issued by the ops console, and
//! service-to-service tokens shared with the reporting service.

pub mod console_token;
pub mod operator_token;
pub mod service_token;

use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("cannot read token key file: {0}")]
    Read(#[from] std::io::Error),
    #[error("token rejected: {0}")]
    Rejected(#[from] jsonwebtoken::errors::Error),
    #[error("token is missing role {0:?}")]
    MissingRole(Role),
    #[error("LEDGER_SERVICE_TOKEN_SECRET is not set")]
    NoServiceSecret,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Viewer,
    Poster,
    Approver,
    PeriodClose,
    Admin,
}
