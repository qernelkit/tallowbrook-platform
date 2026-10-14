//! The journal: double-entry validation, batch encoding, signing and Merkle proofs.

pub mod batch;
pub mod merkle;
pub mod posting;
pub mod signing;
pub mod verify;

pub use batch::batch_digest;
pub use posting::{Chart, PostingError, validate};
