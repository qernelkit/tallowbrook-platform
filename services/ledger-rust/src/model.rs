//! Core ledger types: accounts, periods, postings, journal lines and batches.
//!
//! Amounts are always integer minor units (cents, pence) in the currency of the line. Nothing in
//! the ledger uses floating point.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// A general-ledger account number from the chart of accounts (1000-9999).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AccountId(pub u32);

impl AccountId {
    pub const MIN: u32 = 1000;
    pub const MAX: u32 = 9999;

    pub fn new(number: u32) -> Option<Self> {
        (Self::MIN..=Self::MAX)
            .contains(&number)
            .then_some(Self(number))
    }

    /// Assets and expenses carry a debit balance; everything else carries a credit balance.
    pub fn normal_side(self) -> Side {
        match self.0 / 1000 {
            1 | 5 | 6 | 7 => Side::Debit,
            _ => Side::Credit,
        }
    }
}

impl fmt::Display for AccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for AccountId {
    type Err = ModelError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let n: u32 = s
            .trim()
            .parse()
            .map_err(|_| ModelError::BadAccount(s.to_owned()))?;
        AccountId::new(n).ok_or_else(|| ModelError::BadAccount(s.to_owned()))
    }
}

/// ISO 4217 currency code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Currency([u8; 3]);

impl Currency {
    pub const EUR: Currency = Currency(*b"EUR");
    pub const GBP: Currency = Currency(*b"GBP");
    pub const USD: Currency = Currency(*b"USD");

    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).unwrap_or("???")
    }
}

impl FromStr for Currency {
    type Err = ModelError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = s.as_bytes();
        if bytes.len() != 3 || !bytes.iter().all(u8::is_ascii_uppercase) {
            return Err(ModelError::BadCurrency(s.to_owned()));
        }
        Ok(Currency([bytes[0], bytes[1], bytes[2]]))
    }
}

impl TryFrom<String> for Currency {
    type Error = ModelError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl From<Currency> for String {
    fn from(c: Currency) -> String {
        c.as_str().to_owned()
    }
}

impl fmt::Display for Currency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An accounting period (calendar month).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Period {
    pub year: u16,
    pub month: u8,
}

impl Period {
    pub fn new(year: u16, month: u8) -> Option<Self> {
        (1..=12).contains(&month).then_some(Period { year, month })
    }

    pub fn next(self) -> Period {
        if self.month == 12 {
            Period {
                year: self.year + 1,
                month: 1,
            }
        } else {
            Period {
                year: self.year,
                month: self.month + 1,
            }
        }
    }
}

impl fmt::Display for Period {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04}-{:02}", self.year, self.month)
    }
}

impl FromStr for Period {
    type Err = ModelError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (y, m) = s
            .split_once('-')
            .ok_or_else(|| ModelError::BadPeriod(s.to_owned()))?;
        let year = y.parse().map_err(|_| ModelError::BadPeriod(s.to_owned()))?;
        let month = m.parse().map_err(|_| ModelError::BadPeriod(s.to_owned()))?;
        Period::new(year, month).ok_or_else(|| ModelError::BadPeriod(s.to_owned()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Side {
    Debit,
    Credit,
}

/// One business event as the posting clients send it: move `amount` from one account to another.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Posting {
    pub reference: String,
    pub debit: AccountId,
    pub credit: AccountId,
    pub amount_minor: i64,
    pub currency: Currency,
    pub memo: Option<String>,
}

impl Posting {
    /// The debit/credit account pair, used to group postings by flow in reports.
    pub fn keypair(&self) -> (AccountId, AccountId) {
        (self.debit, self.credit)
    }

    /// Expands the posting into its two journal lines.
    pub fn lines(&self) -> [JournalLine; 2] {
        [
            JournalLine {
                account: self.debit,
                side: Side::Debit,
                amount_minor: self.amount_minor,
                currency: self.currency,
                reference: self.reference.clone(),
            },
            JournalLine {
                account: self.credit,
                side: Side::Credit,
                amount_minor: self.amount_minor,
                currency: self.currency,
                reference: self.reference.clone(),
            },
        ]
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalLine {
    pub account: AccountId,
    pub side: Side,
    pub amount_minor: i64,
    pub currency: Currency,
    pub reference: String,
}

impl JournalLine {
    /// Signed amount: debits positive, credits negative.
    pub fn signed_minor(&self) -> i64 {
        match self.side {
            Side::Debit => self.amount_minor,
            Side::Credit => -self.amount_minor,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchSource {
    Storefront,
    Carrier,
    Depot,
    Branch,
    Manual,
}

/// A group of journal lines that is validated, signed and posted together.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalBatch {
    pub id: u64,
    pub period: Period,
    pub source: BatchSource,
    /// Branch code for batches posted by a branch ledger; empty for head-office batches.
    pub branch: String,
    pub created_at: u64,
    pub lines: Vec<JournalLine>,
}

impl JournalBatch {
    pub fn total_debits(&self, currency: Currency) -> i64 {
        self.lines
            .iter()
            .filter(|l| l.currency == currency && l.side == Side::Debit)
            .map(|l| l.amount_minor)
            .sum()
    }

    pub fn currencies(&self) -> Vec<Currency> {
        let mut out: Vec<Currency> = self.lines.iter().map(|l| l.currency).collect();
        out.sort();
        out.dedup();
        out
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ModelError {
    #[error("not a ledger account number: {0:?}")]
    BadAccount(String),
    #[error("not an ISO 4217 currency code: {0:?}")]
    BadCurrency(String),
    #[error("not a period (expected YYYY-MM): {0:?}")]
    BadPeriod(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn period_rolls_over_the_year() {
        let dec = Period::new(2026, 12).unwrap();
        assert_eq!(dec.next(), Period::new(2027, 1).unwrap());
        assert_eq!("2026-09".parse::<Period>().unwrap().to_string(), "2026-09");
    }

    #[test]
    fn account_numbers_are_range_checked() {
        assert!(AccountId::new(999).is_none());
        assert_eq!("1200".parse::<AccountId>().unwrap(), AccountId(1200));
        assert_eq!(AccountId(1200).normal_side(), Side::Debit);
        assert_eq!(AccountId(2100).normal_side(), Side::Credit);
    }
}
