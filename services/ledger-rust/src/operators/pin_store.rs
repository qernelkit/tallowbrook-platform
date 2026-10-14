//! Operator console PINs. The console asks for the PIN before approving a batch; we store PHC
//! strings only and lock a console after repeated failures.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use serde::{Deserialize, Serialize};

/// Consecutive failures before an operator is locked out until treasury unlocks them.
pub const MAX_FAILURES: u32 = 5;

#[derive(Debug, thiserror::Error)]
pub enum PinError {
    #[error("PIN must be 6 to 8 digits")]
    Format,
    #[error("PIN store i/o: {0}")]
    Io(#[from] std::io::Error),
    #[error("PIN store file is malformed: {0}")]
    Malformed(#[from] serde_json::Error),
    #[error("hashing the PIN failed")]
    Hash,
    #[error("operator {0} has no PIN")]
    NoPin(String),
    #[error("operator {0} is locked")]
    Locked(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PinRecord {
    phc: String,
    failures: u32,
    changed_at: u64,
}

pub struct PinStore {
    path: PathBuf,
    records: BTreeMap<String, PinRecord>,
}

fn pin_hasher() -> Argon2<'static> {
    Argon2::default()
}

fn check_format(pin: &str) -> Result<(), PinError> {
    let ok = (6..=8).contains(&pin.len()) && pin.bytes().all(|b| b.is_ascii_digit());
    if ok { Ok(()) } else { Err(PinError::Format) }
}

impl PinStore {
    pub fn open(path: &Path) -> Result<Self, PinError> {
        let records = match fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(e.into()),
        };
        Ok(Self {
            path: path.to_owned(),
            records,
        })
    }

    fn persist(&self) -> Result<(), PinError> {
        let tmp = self.path.with_extension("tmp");
        fs::write(&tmp, serde_json::to_vec_pretty(&self.records)?)?;
        fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    pub fn set(&mut self, operator: &str, pin: &str, now: u64) -> Result<(), PinError> {
        check_format(pin)?;
        let phc = pin_hasher()
            .hash_password(pin.as_bytes())
            .map_err(|_| PinError::Hash)?
            .to_string();
        self.records.insert(
            operator.to_owned(),
            PinRecord {
                phc,
                failures: 0,
                changed_at: now,
            },
        );
        self.persist()
    }

    /// Checks a PIN. Returns `Ok(false)` for a wrong PIN and counts the failure.
    pub fn check(&mut self, operator: &str, pin: &str) -> Result<bool, PinError> {
        let record = self
            .records
            .get_mut(operator)
            .ok_or_else(|| PinError::NoPin(operator.to_owned()))?;
        if record.failures >= MAX_FAILURES {
            return Err(PinError::Locked(operator.to_owned()));
        }
        let ok = pin_hasher()
            .verify_password(pin.as_bytes(), record.phc.as_str())
            .is_ok();
        record.failures = if ok { 0 } else { record.failures + 1 };
        if !ok {
            log::warn!(
                "wrong PIN for operator {operator} ({} failures)",
                record.failures
            );
        }
        self.persist()?;
        Ok(ok)
    }

    pub fn unlock(&mut self, operator: &str) -> Result<(), PinError> {
        if let Some(record) = self.records.get_mut(operator) {
            record.failures = 0;
        }
        self.persist()
    }
}

#[cfg(test)]
mod tests {
    use super::check_format;

    #[test]
    fn pin_format() {
        let digits = |n: usize| "7".repeat(n);
        assert!(check_format(&digits(6)).is_ok());
        assert!(check_format(&digits(5)).is_err());
        assert!(check_format(&format!("{}a", digits(5))).is_err());
    }
}
