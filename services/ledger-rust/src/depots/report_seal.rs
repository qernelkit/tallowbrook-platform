//! Seals the nightly reconciliation report for a depot gateway.
//!
//! Each gateway registers a static public value in the depot registry. For every report the
//! ledger makes a one-off key pair, agrees a shared value with the gateway's, derives the report
//! key from it and seals the report. The gateway needs only the report and its own secret.

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, Generate, KeyInit, Nonce, Payload};
use hkdf::Hkdf;
use k256::sha2::Sha256;
use serde::Serialize;
use x25519_dalek::{EphemeralSecret, PublicKey};

/// Context string bound into the report key.
const REPORT_INFO: &[u8] = b"tallowbrook depot reconciliation report v1";

#[derive(Debug, thiserror::Error)]
pub enum ReportSealError {
    #[error("report key derivation failed")]
    Derivation,
    #[error("sealing the report for depot {0} failed")]
    Seal(String),
}

/// A depot gateway as listed in the depot registry.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct DepotGateway {
    pub depot: String,
    pub endpoint: String,
    pub report_key: [u8; 32],
}

/// What is pushed to the gateway.
#[derive(Debug, Clone, Serialize)]
pub struct SealedReport {
    pub depot: String,
    pub report_id: [u8; 16],
    pub sender_value: [u8; 32],
    pub iv: Vec<u8>,
    pub sealed: Vec<u8>,
}

pub fn seal_report(
    depot: &DepotGateway,
    report_id: [u8; 16],
    report: &[u8],
) -> Result<SealedReport, ReportSealError> {
    let ephemeral = EphemeralSecret::random();
    let sender_value = PublicKey::from(&ephemeral);
    let gateway_key = PublicKey::from(depot.report_key);
    let shared = ephemeral.diffie_hellman(&gateway_key);

    let hk = Hkdf::<Sha256>::new(Some(&report_id), shared.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(REPORT_INFO, &mut okm)
        .map_err(|_| ReportSealError::Derivation)?;

    let cipher = Aes256Gcm::new_from_slice(&okm).map_err(|_| ReportSealError::Derivation)?;
    let iv = Nonce::<Aes256Gcm>::generate();
    let sealed = cipher
        .encrypt(
            &iv,
            Payload {
                msg: report,
                aad: depot.depot.as_bytes(),
            },
        )
        .map_err(|_| ReportSealError::Seal(depot.depot.clone()))?;

    log::info!(
        "sealed reconciliation report for depot {} ({} bytes)",
        depot.depot,
        report.len()
    );
    Ok(SealedReport {
        depot: depot.depot.clone(),
        report_id,
        sender_value: sender_value.to_bytes(),
        iv: iv.to_vec(),
        sealed,
    })
}
