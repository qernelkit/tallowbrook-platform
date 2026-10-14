//! Double-entry posting rules, exercised through the public API.

use ledger::approvals::needs_approval;
use ledger::journal::posting::{Chart, PostingError, batch_from_postings, largest_line, validate};
use ledger::model::{AccountId, BatchSource, Currency, Period, Posting};

fn chart() -> Chart {
    let mut chart = Chart::new();
    for n in [1200, 2100, 4000, 5100] {
        chart.open(AccountId(n));
    }
    chart
}

fn posting(reference: &str, debit: u32, credit: u32, amount: i64, currency: Currency) -> Posting {
    Posting {
        reference: reference.into(),
        debit: AccountId(debit),
        credit: AccountId(credit),
        amount_minor: amount,
        currency,
        memo: None,
    }
}

fn september() -> Period {
    Period::new(2026, 9).unwrap()
}

#[test]
fn postings_always_balance() {
    let postings = vec![
        posting("INV-2001", 1200, 4000, 12_500, Currency::EUR),
        posting("INV-2002", 1200, 4000, 3_100, Currency::GBP),
        posting("CN-77", 5100, 2100, 880, Currency::EUR),
    ];
    let batch = batch_from_postings(1, september(), BatchSource::Storefront, 0, &postings).unwrap();
    assert_eq!(batch.lines.len(), 6);
    let totals = validate(&batch, &chart()).unwrap();
    assert!(totals.is_balanced());
    assert_eq!(totals.per_currency.len(), 2);
}

#[test]
fn self_transfer_is_refused() {
    let postings = vec![posting("ADJ-1", 1200, 1200, 10, Currency::EUR)];
    let err = batch_from_postings(2, september(), BatchSource::Manual, 0, &postings).unwrap_err();
    assert_eq!(err, PostingError::SelfTransfer("ADJ-1".into()));
}

#[test]
fn unknown_account_is_refused() {
    let postings = vec![posting("INV-9", 1200, 4999, 10, Currency::EUR)];
    let batch = batch_from_postings(3, september(), BatchSource::Carrier, 0, &postings).unwrap();
    assert!(matches!(
        validate(&batch, &chart()),
        Err(PostingError::UnknownAccount { .. })
    ));
}

#[test]
fn zero_amount_is_refused() {
    let postings = vec![posting("INV-0", 1200, 4000, 0, Currency::EUR)];
    let batch = batch_from_postings(4, september(), BatchSource::Depot, 0, &postings).unwrap();
    assert!(matches!(
        validate(&batch, &chart()),
        Err(PostingError::NonPositiveAmount { .. })
    ));
}

#[test]
fn large_batches_need_approval() {
    let postings = vec![
        posting("PAY-1", 2100, 1200, 2_499_999, Currency::EUR),
        posting("PAY-2", 2100, 1200, 2_500_000, Currency::EUR),
    ];
    let batch = batch_from_postings(5, september(), BatchSource::Manual, 0, &postings).unwrap();
    assert_eq!(largest_line(&batch), 2_500_000);
    assert!(needs_approval(&batch, 2_500_000));
    assert!(!needs_approval(&batch, 2_500_001));
}
