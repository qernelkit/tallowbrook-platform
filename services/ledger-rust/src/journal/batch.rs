//! Canonical batch encoding, the batch digest, and the framing used in batch files.
//!
//! The canonical encoding is what everybody signs, so it must never change for an existing
//! format version: fields in a fixed order, integers big-endian, strings length-prefixed.

use ring::digest;

use crate::model::{BatchSource, JournalBatch, Side};

/// Format version written in front of every canonical body.
pub const CANONICAL_VERSION: u8 = 2;

/// Magic bytes at the start of every frame in a batch file.
pub const FRAME_MAGIC: &[u8; 4] = b"TBJB";

/// magic (4) + body length (4) + frame CRC (4)
pub const FRAME_HEADER_LEN: usize = 12;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FrameError {
    #[error("frame is shorter than its header")]
    Truncated,
    #[error("frame does not start with the batch file magic")]
    BadMagic,
    #[error("frame body is {actual} bytes, header says {expected}")]
    LengthMismatch { expected: usize, actual: usize },
    #[error("frame checksum mismatch (torn write?)")]
    ChecksumMismatch,
}

/// A batch encoded once, with the two values derived from that encoding.
pub struct EncodedBatch {
    pub canonical: Vec<u8>,
    pub digest: digest::Digest,
    pub frame_crc: u32,
}

/// Encodes a batch and derives its digest and frame checksum from the same bytes, so the batch
/// file and the signatures always describe the same body.
pub fn encode(batch: &JournalBatch) -> EncodedBatch {
    let canonical = canonical_bytes(batch);
    let digest = digest::digest(&digest::SHA384, &canonical);
    let frame_crc = crc32fast::hash(&canonical);
    EncodedBatch {
        canonical,
        digest,
        frame_crc,
    }
}

/// The value that the batch signer, branch ledgers and treasury approvers sign.
pub fn batch_digest(batch: &JournalBatch) -> digest::Digest {
    encode(batch).digest
}

/// Frames an encoded batch for appending to a batch file.
pub fn frame(encoded: &EncodedBatch) -> Vec<u8> {
    let mut out = Vec::with_capacity(FRAME_HEADER_LEN + encoded.canonical.len());
    out.extend_from_slice(FRAME_MAGIC);
    out.extend_from_slice(&(encoded.canonical.len() as u32).to_be_bytes());
    out.extend_from_slice(&encoded.frame_crc.to_be_bytes());
    out.extend_from_slice(&encoded.canonical);
    out
}

/// Splits one frame off the front of `buf`, returning the canonical body and the rest.
pub fn unframe(buf: &[u8]) -> Result<(&[u8], &[u8]), FrameError> {
    if buf.len() < FRAME_HEADER_LEN {
        return Err(FrameError::Truncated);
    }
    if &buf[..4] != FRAME_MAGIC {
        return Err(FrameError::BadMagic);
    }
    let len = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize;
    let stored_crc = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
    let rest = &buf[FRAME_HEADER_LEN..];
    if rest.len() < len {
        return Err(FrameError::LengthMismatch {
            expected: len,
            actual: rest.len(),
        });
    }
    let (body, tail) = rest.split_at(len);
    if crc32fast::hash(body) != stored_crc {
        return Err(FrameError::ChecksumMismatch);
    }
    Ok((body, tail))
}

/// Canonical encoding of a batch.
pub fn canonical_bytes(batch: &JournalBatch) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + batch.lines.len() * 48);
    out.push(CANONICAL_VERSION);
    out.extend_from_slice(&batch.id.to_be_bytes());
    out.extend_from_slice(&batch.period.year.to_be_bytes());
    out.push(batch.period.month);
    out.push(source_code(batch.source));
    put_str(&mut out, &batch.branch);
    out.extend_from_slice(&batch.created_at.to_be_bytes());
    out.extend_from_slice(&(batch.lines.len() as u32).to_be_bytes());
    for line in &batch.lines {
        out.extend_from_slice(&line.account.0.to_be_bytes());
        out.push(match line.side {
            Side::Debit => b'D',
            Side::Credit => b'C',
        });
        out.extend_from_slice(&line.amount_minor.to_be_bytes());
        out.extend_from_slice(line.currency.as_str().as_bytes());
        put_str(&mut out, &line.reference);
    }
    out
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u16).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
}

fn source_code(source: BatchSource) -> u8 {
    match source {
        BatchSource::Storefront => 1,
        BatchSource::Carrier => 2,
        BatchSource::Depot => 3,
        BatchSource::Branch => 4,
        BatchSource::Manual => 9,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AccountId, Currency, JournalLine, Period};

    fn sample() -> JournalBatch {
        JournalBatch {
            id: 7,
            period: Period::new(2026, 9).unwrap(),
            source: BatchSource::Carrier,
            branch: String::new(),
            created_at: 1_790_000_000,
            lines: vec![JournalLine {
                account: AccountId(1200),
                side: Side::Debit,
                amount_minor: 1250,
                currency: Currency::GBP,
                reference: "CN-88".into(),
            }],
        }
    }

    #[test]
    fn canonical_encoding_starts_with_version_and_id() {
        let bytes = canonical_bytes(&sample());
        assert_eq!(bytes[0], CANONICAL_VERSION);
        assert_eq!(&bytes[1..9], &7u64.to_be_bytes());
    }

    #[test]
    fn unframe_rejects_bad_magic() {
        let mut buf = vec![0u8; FRAME_HEADER_LEN];
        buf[..4].copy_from_slice(b"XXXX");
        assert_eq!(unframe(&buf), Err(FrameError::BadMagic));
    }
}
