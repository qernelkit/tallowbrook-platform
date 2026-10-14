//! Signed, expiring download links for attachments, so the web console can hand a link to a
//! carrier without giving it an account. Links look like
//! `<public base>/<address>?exp=<unix time>&sig=<hex>`.

use hkdf::hmac::{Hmac, KeyInit, Mac};
use k256::sha2::Sha256;

type LinkMac = Hmac<Sha256>;

/// Context for deriving the link key from the attachment master secret.
const LINK_KEY_CONTEXT: &str = "tallowbrook ledger 2026-03 attachment download links";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LinkError {
    #[error("link has expired")]
    Expired,
    #[error("link tag is malformed")]
    Malformed,
    #[error("link tag does not match")]
    BadTag,
    #[error("LEDGER_LINK_SECRET is not set")]
    NoSecret,
}

pub struct LinkSigner {
    master_secret: Vec<u8>,
    public_base: String,
    ttl_secs: u64,
}

impl LinkSigner {
    pub fn from_env(public_base: &str, ttl_secs: u64) -> Result<Self, LinkError> {
        let master_secret = std::env::var("LEDGER_LINK_SECRET").map_err(|_| LinkError::NoSecret)?;
        Ok(Self {
            master_secret: master_secret.into_bytes(),
            public_base: public_base.trim_end_matches('/').to_owned(),
            ttl_secs,
        })
    }

    fn mac_for(&self, address: &str, expires: u64) -> LinkMac {
        let link_key = blake3::derive_key(LINK_KEY_CONTEXT, &self.master_secret);
        let mut mac = LinkMac::new_from_slice(&link_key).expect("any key length is accepted");
        mac.update(address.as_bytes());
        mac.update(b"\n");
        mac.update(&expires.to_be_bytes());
        mac
    }

    pub fn link(&self, address: &str, now: u64) -> String {
        let expires = now + self.ttl_secs;
        let tag = self.mac_for(address, expires).finalize().into_bytes();
        format!(
            "{}/{address}?exp={expires}&sig={}",
            self.public_base,
            hex::encode(tag)
        )
    }

    pub fn check(
        &self,
        address: &str,
        expires: u64,
        tag_hex: &str,
        now: u64,
    ) -> Result<(), LinkError> {
        if now > expires {
            return Err(LinkError::Expired);
        }
        let tag = hex::decode(tag_hex).map_err(|_| LinkError::Malformed)?;
        self.mac_for(address, expires)
            .verify_slice(&tag)
            .map_err(|_| LinkError::BadTag)
    }
}
