//! Signed webhooks for downstream consumers (reporting, warehouse). Each delivery carries
//! `Ledger-Signature: t=<unix time>,v1=<hex tag>` over `<unix time>.<body>`; consumers reject
//! deliveries older than five minutes.

use ring::hmac;
use serde::Serialize;

/// Event types we deliver.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    BatchPosted,
    BatchHeld,
    PeriodClosed,
    StatementImported,
}

#[derive(Debug, Clone, Serialize)]
pub struct Event<'a> {
    pub kind: EventKind,
    pub batch_id: Option<u64>,
    pub period: Option<&'a str>,
    pub at: u64,
}

/// A delivery ready for the HTTP client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebhookDelivery {
    pub target: String,
    pub body: Vec<u8>,
    pub signature_header: String,
}

#[derive(Debug, thiserror::Error)]
pub enum WebhookError {
    #[error("LEDGER_WEBHOOK_SECRET is not set")]
    NoSecret,
    #[error("cannot encode event: {0}")]
    Encode(#[from] serde_json::Error),
}

pub struct WebhookSigner {
    secret: Vec<u8>,
}

impl WebhookSigner {
    pub fn from_env() -> Result<Self, WebhookError> {
        let secret = std::env::var("LEDGER_WEBHOOK_SECRET").map_err(|_| WebhookError::NoSecret)?;
        Ok(Self {
            secret: secret.into_bytes(),
        })
    }

    fn header(&self, timestamp: u64, body: &[u8]) -> String {
        let signed_payload = [timestamp.to_string().as_bytes(), b".", body].concat();
        let key = hmac::Key::new(hmac::HMAC_SHA256, &self.secret);
        let tag = hmac::sign(&key, &signed_payload);
        let signature_header = format!("t={timestamp},v1={}", hex::encode(tag.as_ref()));
        signature_header
    }

    pub fn deliveries(
        &self,
        targets: &[String],
        event: &Event<'_>,
    ) -> Result<Vec<WebhookDelivery>, WebhookError> {
        let body = serde_json::to_vec(event)?;
        let signature_header = self.header(event.at, &body);
        Ok(targets
            .iter()
            .map(|target| WebhookDelivery {
                target: target.clone(),
                body: body.clone(),
                signature_header: signature_header.clone(),
            })
            .collect())
    }
}
