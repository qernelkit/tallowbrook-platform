//! Formatting helpers for the operator console: digests and key identifiers are shown as
//! colon-separated upper-case hex, and long values are shortened in tables.

/// Formats bytes as `AA:BB:CC:…`.
pub fn fingerprint_hex(bytes: &[u8]) -> String {
    let hex = hex::encode_upper(bytes);
    hex.as_bytes()
        .chunks(2)
        .map(|pair| std::str::from_utf8(pair).unwrap_or("??"))
        .collect::<Vec<_>>()
        .join(":")
}

/// First twelve characters of a hex string, for table columns.
pub fn short_digest(hex: &str) -> &str {
    let end = hex
        .char_indices()
        .nth(12)
        .map(|(i, _)| i)
        .unwrap_or(hex.len());
    &hex[..end]
}

/// Lower-case hex without separators, as stored in batch files and logs.
pub fn plain_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn colon_separated() {
        assert_eq!(fingerprint_hex(&[0xde, 0xad, 0x01]), "DE:AD:01");
    }

    #[test]
    fn short_values_are_untouched() {
        assert_eq!(short_digest("abc"), "abc");
        assert_eq!(short_digest("0123456789abcdef"), "0123456789ab");
    }
}
