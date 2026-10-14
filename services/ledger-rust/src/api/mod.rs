//! Request handling helpers shared by the posting API.

pub mod idempotency;

pub use idempotency::{IdempotencyCache, Outcome};
