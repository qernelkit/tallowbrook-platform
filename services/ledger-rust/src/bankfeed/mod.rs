//! Bank feeds: statement files fetched from our banks, payment files sent to them, bank
//! callbacks, and the per-bank onboarding.
//!
//! A statement file is a semicolon-separated text file:
//!
//! ```text
//! HDR;<bank code>;<account>;<statement id>;<YYYY-MM-DD>
//! ENT;<booked YYYY-MM-DD>;<amount minor>;<currency>;<reference>;<counterparty>
//! ...
//! TRL;<entry count>;<40 hex trailer checksum>
//! ```

pub mod api_client;
pub mod callback_auth;
pub mod dedupe;
pub mod file_checksum;
pub mod onboarding;
pub mod payment_signer;
pub mod spool;
pub mod statement_verify;

use crate::model::Currency;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StatementError {
    #[error("statement file is not UTF-8")]
    Encoding,
    #[error("line {0}: unexpected record")]
    Record(usize),
    #[error("line {line}: bad field {field}")]
    Field { line: usize, field: &'static str },
    #[error("statement has {actual} entries, trailer says {declared}")]
    Count { declared: usize, actual: usize },
    #[error("statement has no trailer")]
    NoTrailer,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatementEntry {
    pub booked: String,
    pub amount_minor: i64,
    pub currency: Currency,
    pub reference: String,
    pub counterparty: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatementFile {
    pub bank: String,
    pub account: String,
    pub statement_id: String,
    pub date: String,
    pub entries: Vec<StatementEntry>,
    /// Everything before the trailer line, as received.
    pub body: Vec<u8>,
    pub trailer_hex: String,
}

impl StatementFile {
    pub fn parse(raw: &[u8]) -> Result<StatementFile, StatementError> {
        let text = std::str::from_utf8(raw).map_err(|_| StatementError::Encoding)?;
        let mut header: Option<Vec<&str>> = None;
        let mut entries = Vec::new();
        let mut body_len = 0;
        for (i, line) in text.split_inclusive('\n').enumerate() {
            let n = i + 1;
            let fields: Vec<&str> = line.trim_end_matches(['\r', '\n']).split(';').collect();
            match fields.first().copied() {
                Some("HDR") if header.is_none() && fields.len() == 5 => header = Some(fields),
                Some("ENT") if header.is_some() && fields.len() == 6 => {
                    entries.push(StatementEntry {
                        booked: fields[1].to_owned(),
                        amount_minor: fields[2].parse().map_err(|_| StatementError::Field {
                            line: n,
                            field: "amount",
                        })?,
                        currency: fields[3].parse().map_err(|_| StatementError::Field {
                            line: n,
                            field: "currency",
                        })?,
                        reference: fields[4].to_owned(),
                        counterparty: fields[5].to_owned(),
                    });
                }
                Some("TRL") if fields.len() == 3 => {
                    let declared: usize = fields[1].parse().map_err(|_| StatementError::Field {
                        line: n,
                        field: "count",
                    })?;
                    if declared != entries.len() {
                        return Err(StatementError::Count {
                            declared,
                            actual: entries.len(),
                        });
                    }
                    let header = header.ok_or(StatementError::Record(1))?;
                    return Ok(StatementFile {
                        bank: header[1].to_owned(),
                        account: header[2].to_owned(),
                        statement_id: header[3].to_owned(),
                        date: header[4].to_owned(),
                        entries,
                        body: raw[..body_len].to_vec(),
                        trailer_hex: fields[2].to_owned(),
                    });
                }
                _ => return Err(StatementError::Record(n)),
            }
            body_len += line.len();
        }
        Err(StatementError::NoTrailer)
    }

    /// Body with line endings normalised and the header's statement id removed, so the same
    /// statement re-sent under a new id or with CRLF line endings compares equal.
    pub fn normalised_body(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.body.len());
        for entry in &self.entries {
            out.extend_from_slice(entry.booked.as_bytes());
            out.push(b';');
            out.extend_from_slice(entry.amount_minor.to_string().as_bytes());
            out.push(b';');
            out.extend_from_slice(entry.currency.as_str().as_bytes());
            out.push(b';');
            out.extend_from_slice(entry.reference.trim().as_bytes());
            out.push(b'\n');
        }
        out
    }

    /// Net movement per currency, for the reconciliation report.
    pub fn net_minor(&self, currency: Currency) -> i64 {
        self.entries
            .iter()
            .filter(|e| e.currency == currency)
            .map(|e| e.amount_minor)
            .sum()
    }
}
