//! Double-entry rules. A batch is accepted only if, per currency, its debits equal its credits,
//! every line names an open account, and no amount is zero or negative.

use std::collections::BTreeMap;

use crate::hashing::AccountIndex;
use crate::model::{AccountId, BatchSource, Currency, JournalBatch, JournalLine, Period, Posting};

/// Largest number of journal lines in one batch; bigger uploads are split by the client.
pub const MAX_LINES_PER_BATCH: usize = 5_000;

/// Largest single amount we accept without a manual journal (10 million in minor units).
pub const MAX_LINE_AMOUNT_MINOR: i64 = 1_000_000_000;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PostingError {
    #[error("batch has no lines")]
    Empty,
    #[error("batch has {0} lines, the limit is {MAX_LINES_PER_BATCH}")]
    TooManyLines(usize),
    #[error("line {index}: amount must be positive, got {amount}")]
    NonPositiveAmount { index: usize, amount: i64 },
    #[error("line {index}: amount {amount} is above the per-line limit")]
    AmountTooLarge { index: usize, amount: i64 },
    #[error("line {index}: account {account} is not open")]
    UnknownAccount { index: usize, account: AccountId },
    #[error("line {index}: account {account} is closed for period {period}")]
    ClosedAccount {
        index: usize,
        account: AccountId,
        period: Period,
    },
    #[error("{currency}: debits {debits} do not equal credits {credits}")]
    Unbalanced {
        currency: Currency,
        debits: i64,
        credits: i64,
    },
    #[error("posting {0}: debit and credit account are the same")]
    SelfTransfer(String),
}

/// Lifecycle of an account in the chart of accounts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountState {
    Open,
    /// Closed from this period on; earlier periods may still be adjusted.
    ClosedFrom(Period),
}

/// The subset of the chart of accounts that posting validation needs.
#[derive(Debug, Default)]
pub struct Chart {
    accounts: AccountIndex<AccountState>,
}

impl Chart {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn open(&mut self, account: AccountId) {
        self.accounts.insert(account, AccountState::Open);
    }

    pub fn close_from(&mut self, account: AccountId, period: Period) {
        self.accounts
            .insert(account, AccountState::ClosedFrom(period));
    }

    fn check(&self, index: usize, account: AccountId, period: Period) -> Result<(), PostingError> {
        match self.accounts.get(&account) {
            None => Err(PostingError::UnknownAccount { index, account }),
            Some(AccountState::Open) => Ok(()),
            Some(AccountState::ClosedFrom(closed)) if period >= *closed => {
                Err(PostingError::ClosedAccount {
                    index,
                    account,
                    period,
                })
            }
            Some(AccountState::ClosedFrom(_)) => Ok(()),
        }
    }
}

/// Totals per currency, used both for validation and for the batch summary in the console.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Totals {
    pub per_currency: BTreeMap<Currency, (i64, i64)>,
}

impl Totals {
    pub fn of(lines: &[JournalLine]) -> Totals {
        let mut per_currency: BTreeMap<Currency, (i64, i64)> = BTreeMap::new();
        for line in lines {
            let entry = per_currency.entry(line.currency).or_default();
            if line.signed_minor() >= 0 {
                entry.0 += line.amount_minor;
            } else {
                entry.1 += line.amount_minor;
            }
        }
        Totals { per_currency }
    }

    pub fn is_balanced(&self) -> bool {
        self.per_currency.values().all(|(d, c)| d == c)
    }
}

/// Validates a batch against the double-entry rules and the chart of accounts.
pub fn validate(batch: &JournalBatch, chart: &Chart) -> Result<Totals, PostingError> {
    if batch.lines.is_empty() {
        return Err(PostingError::Empty);
    }
    if batch.lines.len() > MAX_LINES_PER_BATCH {
        return Err(PostingError::TooManyLines(batch.lines.len()));
    }
    for (index, line) in batch.lines.iter().enumerate() {
        if line.amount_minor <= 0 {
            return Err(PostingError::NonPositiveAmount {
                index,
                amount: line.amount_minor,
            });
        }
        if line.amount_minor > MAX_LINE_AMOUNT_MINOR {
            return Err(PostingError::AmountTooLarge {
                index,
                amount: line.amount_minor,
            });
        }
        chart.check(index, line.account, batch.period)?;
    }
    let totals = Totals::of(&batch.lines);
    for (currency, (debits, credits)) in &totals.per_currency {
        if debits != credits {
            return Err(PostingError::Unbalanced {
                currency: *currency,
                debits: *debits,
                credits: *credits,
            });
        }
    }
    Ok(totals)
}

/// Builds a batch from client postings. Each posting becomes a debit line and a credit line.
pub fn batch_from_postings(
    id: u64,
    period: Period,
    source: BatchSource,
    created_at: u64,
    postings: &[Posting],
) -> Result<JournalBatch, PostingError> {
    let mut lines = Vec::with_capacity(postings.len() * 2);
    for posting in postings {
        if posting.debit == posting.credit {
            return Err(PostingError::SelfTransfer(posting.reference.clone()));
        }
        lines.extend(posting.lines());
    }
    Ok(JournalBatch {
        id,
        period,
        source,
        branch: String::new(),
        created_at,
        lines,
    })
}

/// Largest single line in the batch, which decides whether treasury approval is needed.
pub fn largest_line(batch: &JournalBatch) -> i64 {
    batch
        .lines
        .iter()
        .map(|l| l.amount_minor)
        .max()
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Side;

    fn line(account: u32, side: Side, amount: i64) -> JournalLine {
        JournalLine {
            account: AccountId(account),
            side,
            amount_minor: amount,
            currency: Currency::EUR,
            reference: "INV-1001".into(),
        }
    }

    fn chart() -> Chart {
        let mut chart = Chart::new();
        chart.open(AccountId(1200));
        chart.open(AccountId(4000));
        chart
    }

    fn batch(lines: Vec<JournalLine>) -> JournalBatch {
        JournalBatch {
            id: 1,
            period: Period::new(2026, 9).unwrap(),
            source: BatchSource::Storefront,
            branch: String::new(),
            created_at: 0,
            lines,
        }
    }

    #[test]
    fn balanced_batch_is_accepted() {
        let b = batch(vec![
            line(1200, Side::Debit, 4_999),
            line(4000, Side::Credit, 4_999),
        ]);
        assert!(validate(&b, &chart()).unwrap().is_balanced());
    }

    #[test]
    fn unbalanced_batch_is_rejected() {
        let b = batch(vec![
            line(1200, Side::Debit, 5_000),
            line(4000, Side::Credit, 4_999),
        ]);
        assert!(matches!(
            validate(&b, &chart()),
            Err(PostingError::Unbalanced { .. })
        ));
    }

    #[test]
    fn closed_account_rejects_later_periods() {
        let mut c = chart();
        c.close_from(AccountId(4000), Period::new(2026, 7).unwrap());
        let b = batch(vec![
            line(1200, Side::Debit, 10),
            line(4000, Side::Credit, 10),
        ]);
        assert!(matches!(
            validate(&b, &c),
            Err(PostingError::ClosedAccount { .. })
        ));
    }
}
