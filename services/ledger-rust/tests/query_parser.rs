//! Auditor query parsing and evaluation.

use ledger::model::Period;
use ledger::query::{BatchState, BatchSummary, Filter, Query, QueryError, matches, parse};

fn summary() -> BatchSummary {
    BatchSummary {
        accounts: vec![1200, 4000],
        period: Period::new(2026, 9).unwrap(),
        state: BatchState::Signed,
        branch: "dover".into(),
        largest_line_minor: 3_000_000,
    }
}

#[test]
fn simple_filter() {
    assert_eq!(
        parse("account:1200").unwrap(),
        Query::Filter(Filter::Account(1200))
    );
}

#[test]
fn and_binds_tighter_than_or() {
    let q = parse("status:held OR account:1200 AND period:2026-09").unwrap();
    assert!(matches!(q, Query::Or(_, _)));
    assert!(matches(&q, &summary()));
}

#[test]
fn not_and_parentheses() {
    let q = parse("NOT (branch:dover OR branch:felixstowe)").unwrap();
    assert!(!matches(&q, &summary()));
    let q = parse("status:signed AND NOT branch:felixstowe").unwrap();
    assert!(matches(&q, &summary()));
}

#[test]
fn amount_comparisons() {
    assert!(matches(&parse("amount>=2500000").unwrap(), &summary()));
    assert!(!matches(&parse("amount<=2500000").unwrap(), &summary()));
}

#[test]
fn errors_are_reported() {
    assert_eq!(parse("account:"), Err(QueryError::End));
    assert!(matches!(parse("account:1200 AND"), Err(QueryError::End)));
    assert!(matches!(
        parse("period:2026-13"),
        Err(QueryError::BadPeriod(_))
    ));
    assert!(matches!(parse("account:1200 $"), Err(QueryError::Lex(_))));
}
