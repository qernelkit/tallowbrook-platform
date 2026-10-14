//! Composite keys for the ledger's key-value indexes. Every key starts with a one-byte table
//! prefix and encodes integers big-endian, so that byte order equals logical order and range
//! scans over an account or a period are contiguous.

use crate::model::{AccountId, Period};

/// Table prefixes.
pub mod table {
    pub const BALANCE: u8 = b'B';
    pub const BATCH: u8 = b'J';
    pub const LINE: u8 = b'L';
    pub const PERIOD_STATE: u8 = b'P';
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    #[error("key has the wrong table prefix")]
    Table,
    #[error("key is {0} bytes, expected {1}")]
    Length(usize, usize),
    #[error("key holds an invalid account or period")]
    Value,
}

const BALANCE_KEY_LEN: usize = 1 + 4 + 2 + 1;

/// Balance key for an account in a period: `B | account | year | month`.
pub fn encode_key(account: &AccountId, period: Period) -> Vec<u8> {
    let mut key = Vec::with_capacity(BALANCE_KEY_LEN);
    key.push(table::BALANCE);
    key.extend_from_slice(&account.0.to_be_bytes());
    key.extend_from_slice(&period.year.to_be_bytes());
    key.push(period.month);
    key
}

pub fn decode_balance_key(key: &[u8]) -> Result<(AccountId, Period), KeyError> {
    if key.len() != BALANCE_KEY_LEN {
        return Err(KeyError::Length(key.len(), BALANCE_KEY_LEN));
    }
    if key[0] != table::BALANCE {
        return Err(KeyError::Table);
    }
    let account = u32::from_be_bytes([key[1], key[2], key[3], key[4]]);
    let year = u16::from_be_bytes([key[5], key[6]]);
    let account = AccountId::new(account).ok_or(KeyError::Value)?;
    let period = Period::new(year, key[7]).ok_or(KeyError::Value)?;
    Ok((account, period))
}

/// Range covering every period of one account, `[start, end)`.
pub fn account_range(account: &AccountId) -> (Vec<u8>, Vec<u8>) {
    let mut start = vec![table::BALANCE];
    start.extend_from_slice(&account.0.to_be_bytes());
    let mut end = vec![table::BALANCE];
    end.extend_from_slice(&(account.0 + 1).to_be_bytes());
    (start, end)
}

/// Batch key: `J | batch id`.
pub fn batch_key(batch_id: u64) -> [u8; 9] {
    let mut key = [0u8; 9];
    key[0] = table::BATCH;
    key[1..].copy_from_slice(&batch_id.to_be_bytes());
    key
}

/// Journal line key: `L | partition | batch id | line index`.
pub fn line_key(partition: u16, batch_id: u64, index: u32) -> [u8; 15] {
    let mut key = [0u8; 15];
    key[0] = table::LINE;
    key[1..3].copy_from_slice(&partition.to_be_bytes());
    key[3..11].copy_from_slice(&batch_id.to_be_bytes());
    key[11..].copy_from_slice(&index.to_be_bytes());
    key
}

/// Period state key: `P | year | month`.
pub fn period_state_key(period: Period) -> [u8; 4] {
    let y = period.year.to_be_bytes();
    [table::PERIOD_STATE, y[0], y[1], period.month]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn balance_keys_round_trip() {
        let account = AccountId(4000);
        let period = Period::new(2026, 9).unwrap();
        let key = encode_key(&account, period);
        assert_eq!(decode_balance_key(&key), Ok((account, period)));
    }

    #[test]
    fn byte_order_follows_period_order() {
        let account = AccountId(1200);
        let sep = encode_key(&account, Period::new(2026, 9).unwrap());
        let oct = encode_key(&account, Period::new(2026, 10).unwrap());
        let jan = encode_key(&account, Period::new(2027, 1).unwrap());
        assert!(sep < oct && oct < jan);
    }

    #[test]
    fn account_range_contains_all_periods() {
        let account = AccountId(1200);
        let (start, end) = account_range(&account);
        let key = encode_key(&account, Period::new(2030, 12).unwrap());
        assert!(start.as_slice() <= key.as_slice() && key.as_slice() < end.as_slice());
    }

    #[test]
    fn wrong_table_is_rejected() {
        let mut key = encode_key(&AccountId(1200), Period::new(2026, 1).unwrap());
        key[0] = table::BATCH;
        assert_eq!(decode_balance_key(&key), Err(KeyError::Table));
    }
}
