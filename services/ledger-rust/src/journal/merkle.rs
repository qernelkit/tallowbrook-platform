//! Merkle root over the journal lines of a batch, so an auditor can be shown that one line is part
//! of a signed batch without receiving the whole batch.
//!
//! Leaves and interior nodes are domain-separated with a one-byte prefix (0x00 / 0x01). An odd
//! node at the end of a level is promoted unchanged.

use ring::digest;

use crate::model::JournalLine;

const NODE_HASH: &digest::Algorithm = &digest::SHA256;

const LEAF_PREFIX: u8 = 0x00;
const INTERIOR_PREFIX: u8 = 0x01;

/// One step of an inclusion proof: the sibling value and whether it sits on the left.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofStep {
    pub sibling: Vec<u8>,
    pub sibling_on_left: bool,
}

fn leaf(line: &JournalLine) -> Vec<u8> {
    let mut ctx = digest::Context::new(NODE_HASH);
    ctx.update(&[LEAF_PREFIX]);
    ctx.update(&line.account.0.to_be_bytes());
    ctx.update(&line.amount_minor.to_be_bytes());
    ctx.update(line.currency.as_str().as_bytes());
    ctx.update(line.reference.as_bytes());
    ctx.finish().as_ref().to_vec()
}

fn interior(left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut ctx = digest::Context::new(NODE_HASH);
    ctx.update(&[INTERIOR_PREFIX]);
    ctx.update(left);
    ctx.update(right);
    ctx.finish().as_ref().to_vec()
}

fn next_level(level: &[Vec<u8>]) -> Vec<Vec<u8>> {
    level
        .chunks(2)
        .map(|pair| match pair {
            [l, r] => interior(l, r),
            [single] => single.clone(),
            _ => unreachable!("chunks(2) yields one or two items"),
        })
        .collect()
}

/// Root over the lines in batch order. `None` for an empty batch.
pub fn root(lines: &[JournalLine]) -> Option<Vec<u8>> {
    let mut level: Vec<Vec<u8>> = lines.iter().map(leaf).collect();
    if level.is_empty() {
        return None;
    }
    while level.len() > 1 {
        level = next_level(&level);
    }
    level.pop()
}

/// Inclusion proof for the line at `index`.
pub fn prove(lines: &[JournalLine], index: usize) -> Option<Vec<ProofStep>> {
    if index >= lines.len() {
        return None;
    }
    let mut level: Vec<Vec<u8>> = lines.iter().map(leaf).collect();
    let mut position = index;
    let mut steps = Vec::new();
    while level.len() > 1 {
        let sibling = position ^ 1;
        if sibling < level.len() {
            steps.push(ProofStep {
                sibling: level[sibling].clone(),
                sibling_on_left: sibling < position,
            });
        }
        level = next_level(&level);
        position /= 2;
    }
    Some(steps)
}

/// Recomputes the root from one line and its proof.
pub fn root_from_proof(line: &JournalLine, steps: &[ProofStep]) -> Vec<u8> {
    steps.iter().fold(leaf(line), |acc, step| {
        if step.sibling_on_left {
            interior(&step.sibling, &acc)
        } else {
            interior(&acc, &step.sibling)
        }
    })
}
