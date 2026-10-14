//! Notifications to downstream consumers.

pub mod webhook;

pub use webhook::{WebhookDelivery, WebhookSigner};
