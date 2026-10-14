//! Depot gateways: the regional depots receive a sealed reconciliation report after each close.

pub mod report_seal;

pub use report_seal::{DepotGateway, SealedReport, seal_report};
