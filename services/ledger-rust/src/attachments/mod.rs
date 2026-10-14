//! Invoice and receipt attachments, stored by content address and served through signed,
//! expiring download links.

pub mod kind;
pub mod links;
pub mod store;

pub use links::LinkSigner;
pub use store::AttachmentStore;
