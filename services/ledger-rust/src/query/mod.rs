//! The auditor query language, used in the audit portal to select journal batches:
//!
//! ```text
//! account:1200 AND period:2026-09
//! status:signed AND NOT branch:dover
//! (status:held OR amount>=2500000) AND period:2026-10
//! ```

pub mod parser;
pub mod tokens;

pub use parser::{BatchState, BatchSummary, Filter, Query, QueryError, matches, parse};
