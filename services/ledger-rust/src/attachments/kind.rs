//! Sniffs the type of an uploaded attachment from its first bytes. Only documents and images are
//! accepted; people regularly upload certificates and key files by mistake when a bank asks for
//! "the file", and those must never end up in the invoice store.

const PEM_CERTIFICATE_PREFIX: &[u8] = b"-----BEGIN CERTIFICATE-----";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachmentKind {
    Pdf,
    Png,
    Jpeg,
    Tiff,
}

impl AttachmentKind {
    pub fn mime(self) -> &'static str {
        match self {
            AttachmentKind::Pdf => "application/pdf",
            AttachmentKind::Png => "image/png",
            AttachmentKind::Jpeg => "image/jpeg",
            AttachmentKind::Tiff => "image/tiff",
        }
    }
}

pub fn sniff(bytes: &[u8]) -> Result<AttachmentKind, &'static str> {
    if bytes.starts_with(PEM_CERTIFICATE_PREFIX) {
        return Err("certificate files are not attachments");
    }
    if bytes.starts_with(b"-----") {
        return Err("armoured key files are not attachments");
    }
    match bytes {
        [b'%', b'P', b'D', b'F', ..] => Ok(AttachmentKind::Pdf),
        [0x89, b'P', b'N', b'G', ..] => Ok(AttachmentKind::Png),
        [0xff, 0xd8, 0xff, ..] => Ok(AttachmentKind::Jpeg),
        [b'I', b'I', 0x2a, 0x00, ..] | [b'M', b'M', 0x00, 0x2a, ..] => Ok(AttachmentKind::Tiff),
        _ => Err("unsupported file type"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniffs_documents() {
        assert_eq!(sniff(b"%PDF-1.7\n"), Ok(AttachmentKind::Pdf));
        assert!(sniff(b"plain text").is_err());
    }
}
