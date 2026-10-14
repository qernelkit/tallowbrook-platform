//! De-duplicates posting requests. Clients retry on timeouts, so the same request can arrive
//! more than once; we key each accepted request by a hash of its canonical form and return the
//! original result for a repeat within the retention window.

use std::collections::{HashMap, VecDeque};

use sha3::{Digest, Sha3_256};

use crate::model::Posting;

/// How long an accepted request is remembered, in seconds.
pub const RETENTION_SECS: u64 = 24 * 3600;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// First time we see this request.
    New,
    /// Same request already accepted as this batch.
    Repeat { batch_id: u64 },
}

type RequestKey = [u8; 32];

#[derive(Debug, Default)]
pub struct IdempotencyCache {
    accepted: HashMap<RequestKey, (u64, u64)>,
    order: VecDeque<(u64, RequestKey)>,
}

/// Canonical bytes of a posting request: client id, then each posting in order.
fn canonical(client: &str, postings: &[Posting]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(client.as_bytes());
    out.push(0);
    for p in postings {
        out.extend_from_slice(p.reference.as_bytes());
        out.push(0);
        out.extend_from_slice(&p.debit.0.to_be_bytes());
        out.extend_from_slice(&p.credit.0.to_be_bytes());
        out.extend_from_slice(&p.amount_minor.to_be_bytes());
        out.extend_from_slice(p.currency.as_str().as_bytes());
    }
    out
}

fn request_key(client: &str, postings: &[Posting]) -> RequestKey {
    let canonical_request = canonical(client, postings);
    Sha3_256::digest(&canonical_request).into()
}

impl IdempotencyCache {
    pub fn check(&mut self, client: &str, postings: &[Posting], now: u64) -> Outcome {
        self.expire(now);
        match self.accepted.get(&request_key(client, postings)) {
            Some((batch_id, _)) => Outcome::Repeat {
                batch_id: *batch_id,
            },
            None => Outcome::New,
        }
    }

    pub fn record(&mut self, client: &str, postings: &[Posting], batch_id: u64, now: u64) {
        let key = request_key(client, postings);
        self.accepted.insert(key, (batch_id, now));
        self.order.push_back((now, key));
    }

    fn expire(&mut self, now: u64) {
        while let Some((at, key)) = self.order.front().copied() {
            if now.saturating_sub(at) < RETENTION_SECS {
                break;
            }
            self.order.pop_front();
            self.accepted.remove(&key);
        }
    }

    pub fn len(&self) -> usize {
        self.accepted.len()
    }

    pub fn is_empty(&self) -> bool {
        self.accepted.is_empty()
    }
}
