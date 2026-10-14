//! In-memory indexes keyed by account, and the routing of accounts to journal partitions.
//!
//! These maps hold balances and account metadata that never leave the process, so a fast
//! non-keyed hasher is the right trade-off.

use std::hash::{Hash, Hasher};

use rustc_hash::{FxHashMap, FxHasher};

use crate::model::{AccountId, Currency};

/// Number of journal partitions. Changing it moves accounts between partitions, which needs a
/// storage migration.
pub const PARTITIONS: u16 = 64;

/// In-memory balance index.
pub type AccountIndex<V> = FxHashMap<AccountId, V>;

/// Running balances per account and currency, in minor units.
pub type BalanceIndex = AccountIndex<FxHashMap<Currency, i64>>;

/// The journal partition that owns an account's lines.
pub fn partition_for(account: &AccountId) -> u16 {
    let mut hasher = FxHasher::default();
    account.hash(&mut hasher);
    (hasher.finish() % u64::from(PARTITIONS)) as u16
}

/// Applies a signed amount to the running balance of an account.
pub fn apply(index: &mut BalanceIndex, account: AccountId, currency: Currency, signed_minor: i64) {
    *index
        .entry(account)
        .or_default()
        .entry(currency)
        .or_insert(0) += signed_minor;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partition_is_stable_and_in_range() {
        let a = AccountId(1200);
        assert_eq!(partition_for(&a), partition_for(&a));
        assert!(partition_for(&AccountId(9999)) < PARTITIONS);
    }

    #[test]
    fn balances_accumulate() {
        let mut index = BalanceIndex::default();
        apply(&mut index, AccountId(1200), Currency::EUR, 500);
        apply(&mut index, AccountId(1200), Currency::EUR, -200);
        assert_eq!(index[&AccountId(1200)][&Currency::EUR], 300);
    }
}
