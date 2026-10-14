//! Tallowbrook ledger: the double-entry journal, treasury approvals, the period archive, bank
//! feeds, and the operator rooms.
//!
//! The crate has no network runtime of its own. It builds listener configurations, room messages
//! and signed payloads, and hands bytes to a [`Transport`]; the transports live in the platform
//! repository.

#![forbid(unsafe_code)]

pub mod api;
pub mod approvals;
pub mod archive;
pub mod attachments;
pub mod audit;
pub mod auth;
pub mod bankfeed;
pub mod crypto_fmt;
pub mod depots;
pub mod error;
pub mod export;
pub mod hashing;
pub mod journal;
pub mod messaging;
pub mod model;
pub mod notify;
pub mod operators;
pub mod query;
pub mod replication;
pub mod settings;
pub mod settlement;
pub mod storage;
pub mod telemetry;
pub mod tls;

pub use error::{LedgerError, TransportError};

/// Where an outgoing message goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Destination {
    Client(u64),
    Branch(String),
    Room(String),
    Webhook(String),
}

/// Byte transport between ledgerd and the outside world.
pub trait Transport {
    /// Next inbound request from client `id`, or `None` when the transport is shut down.
    fn receive(&mut self) -> Result<Option<(u64, Vec<u8>)>, TransportError>;
    fn send(&mut self, to: Destination, bytes: Vec<u8>) -> Result<(), TransportError>;
}
