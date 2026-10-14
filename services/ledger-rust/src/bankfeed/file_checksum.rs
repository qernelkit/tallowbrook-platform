//! Statement files carry a 40-hex checksum of everything before the trailer line. Banks compute it
//! the way their mainframe batch jobs always have; we check it before the signature so a
//! truncated download is reported as such.

use ring::digest;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ChecksumError {
    #[error("trailer checksum is not 40 hex characters")]
    Malformed,
    #[error("trailer checksum does not match the file (truncated download?)")]
    Mismatch,
}

pub fn check_trailer(body: &[u8], trailer_hex: &str) -> Result<(), ChecksumError> {
    if trailer_hex.len() != 40 {
        return Err(ChecksumError::Malformed);
    }
    let expected = hex::decode(trailer_hex).map_err(|_| ChecksumError::Malformed)?;
    let actual = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, body);
    if actual.as_ref() == expected.as_slice() {
        Ok(())
    } else {
        Err(ChecksumError::Mismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_trailer_is_malformed() {
        assert_eq!(check_trailer(b"x", "abcd"), Err(ChecksumError::Malformed));
    }

    #[test]
    fn non_hex_trailer_is_malformed() {
        let t = "z".repeat(40);
        assert_eq!(check_trailer(b"x", &t), Err(ChecksumError::Malformed));
    }
}
