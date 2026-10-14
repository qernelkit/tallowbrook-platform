//! Seals and opens the archive file of a closed period.
//!
//! File layout: magic "TBAR", format version, year (u16), month, nonce (12), sealed journal.
//! The header up to and including the nonce is authenticated as associated data.

use std::fs;
use std::path::Path;

use ring::aead;
use ring::rand::{SecureRandom, SystemRandom};

use super::keys::{PERIOD_LABEL, period_key};
use super::{ArchiveError, ArchivedPeriod};
use crate::model::Period;

const MAGIC: &[u8; 4] = b"TBAR";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 4 + 1 + 2 + 1 + aead::NONCE_LEN;

fn header(period: Period, iv: &[u8; aead::NONCE_LEN]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN);
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&period.year.to_be_bytes());
    out.push(period.month);
    out.extend_from_slice(iv);
    out
}

/// Seals `journal` (the period's batch file) and writes it to `entry.file`.
pub fn seal_period(
    master: &[u8],
    entry: &ArchivedPeriod,
    journal: &[u8],
    rng: &SystemRandom,
) -> Result<(), ArchiveError> {
    let key = aead::LessSafeKey::new(period_key(master, &entry.salt, PERIOD_LABEL)?);
    let mut iv = [0u8; aead::NONCE_LEN];
    rng.fill(&mut iv).map_err(|_| ArchiveError::Random)?;
    let head = header(entry.period, &iv);
    let mut body = journal.to_vec();
    key.seal_in_place_append_tag(
        aead::Nonce::assume_unique_for_key(iv),
        aead::Aad::from(head.as_slice()),
        &mut body,
    )?;
    let mut file = head;
    file.extend_from_slice(&body);
    write_atomically(&entry.file, &file)?;
    log::info!("sealed archive for {} ({} bytes)", entry.period, file.len());
    Ok(())
}

/// Opens a sealed period for an auditor request or a restatement.
pub fn open_period(master: &[u8], entry: &ArchivedPeriod) -> Result<Vec<u8>, ArchiveError> {
    let file = fs::read(&entry.file)?;
    if file.len() < HEADER_LEN || &file[..4] != MAGIC || file[4] != VERSION {
        return Err(ArchiveError::Format(entry.period));
    }
    let (head, sealed) = file.split_at(HEADER_LEN);
    let mut iv = [0u8; aead::NONCE_LEN];
    iv.copy_from_slice(&head[HEADER_LEN - aead::NONCE_LEN..]);
    let key = aead::LessSafeKey::new(period_key(master, &entry.salt, PERIOD_LABEL)?);
    let mut body = sealed.to_vec();
    let plain = key
        .open_in_place(
            aead::Nonce::assume_unique_for_key(iv),
            aead::Aad::from(head),
            &mut body,
        )
        .map_err(|_| ArchiveError::Tampered(entry.period))?;
    Ok(plain.to_vec())
}

fn write_atomically(path: &Path, bytes: &[u8]) -> Result<(), ArchiveError> {
    let tmp = path.with_extension("partial");
    fs::write(&tmp, bytes)?;
    fs::rename(&tmp, path)?;
    Ok(())
}
