//! Detects a statement file imported twice. Banks re-send statements under a new file name or
//! statement id after an outage; posting one twice would double every entry.

use std::collections::HashMap;

use ring::digest;

use super::StatementFile;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirstSeen {
    pub bank: String,
    pub statement_id: String,
}

#[derive(Debug, Default)]
pub struct DedupeIndex {
    seen: HashMap<Vec<u8>, FirstSeen>,
}

impl DedupeIndex {
    /// Records the statement and returns where it was first seen if it is a repeat.
    pub fn check_and_record(&mut self, statement: &StatementFile) -> Option<FirstSeen> {
        let content_id = digest::digest(&digest::SHA512_256, &statement.normalised_body());
        let key = content_id.as_ref().to_vec();
        if let Some(first) = self.seen.get(&key) {
            log::warn!(
                "statement {} from {} repeats {} from {}",
                statement.statement_id,
                statement.bank,
                first.statement_id,
                first.bank
            );
            return Some(first.clone());
        }
        self.seen.insert(
            key,
            FirstSeen {
                bank: statement.bank.clone(),
                statement_id: statement.statement_id.clone(),
            },
        );
        None
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}
