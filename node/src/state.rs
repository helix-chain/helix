//! Chain state storage.
//!
//! `Storage` is a synchronous trait so that a RocksDB-backed implementation
//! can be slotted in at v0.2 (feature-gated) without touching callers.
//! v0.1 ships only `InMemoryStorage`.

use std::collections::BTreeMap;

use alloy_primitives::{Address, B256, Bytes, U256};

/// Minimal account record tracked by the devnet.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Account {
    pub balance: U256,
    pub nonce: u64,
    /// Contract bytecode (empty for EOAs).
    pub code: Bytes,
}

/// Synchronous state + chain storage abstraction.
///
/// v0.2 TODO: `RocksDbStorage` behind a `rocksdb` cargo feature implementing
/// this exact trait (column families: accounts / storage / blocks / receipts).
pub trait Storage: Send + 'static {
    fn account(&self, addr: &Address) -> Option<Account>;
    fn set_account(&mut self, addr: Address, account: Account);
    fn storage_slot(&self, addr: &Address, slot: &U256) -> U256;
    fn set_storage_slot(&mut self, addr: Address, slot: U256, value: U256);
    /// Snapshot of all accounts (used to seed simulation databases).
    fn all_accounts(&self) -> Vec<(Address, Account)>;
    /// Snapshot of all storage slots.
    fn all_storage(&self) -> Vec<((Address, U256), U256)>;
}

/// v0.1 default backend: plain in-memory maps.
#[derive(Debug, Default, Clone)]
pub struct InMemoryStorage {
    accounts: BTreeMap<Address, Account>,
    storage: BTreeMap<(Address, U256), U256>,
}

impl InMemoryStorage {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Storage for InMemoryStorage {
    fn account(&self, addr: &Address) -> Option<Account> {
        self.accounts.get(addr).cloned()
    }

    fn set_account(&mut self, addr: Address, account: Account) {
        self.accounts.insert(addr, account);
    }

    fn storage_slot(&self, addr: &Address, slot: &U256) -> U256 {
        self.storage
            .get(&(*addr, *slot))
            .copied()
            .unwrap_or_default()
    }

    fn set_storage_slot(&mut self, addr: Address, slot: U256, value: U256) {
        self.storage.insert((addr, slot), value);
    }

    fn all_accounts(&self) -> Vec<(Address, Account)> {
        self.accounts
            .iter()
            .map(|(addr, acc)| (*addr, acc.clone()))
            .collect()
    }

    fn all_storage(&self) -> Vec<((Address, U256), U256)> {
        self.storage.iter().map(|(k, v)| (*k, *v)).collect()
    }
}

/// Keccak-256 helper re-exported for block/tx hashing.
pub fn keccak(data: &[u8]) -> B256 {
    alloy_primitives::keccak256(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;

    #[test]
    fn in_memory_storage_roundtrip() {
        let mut store = InMemoryStorage::new();
        let addr = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");

        assert!(store.account(&addr).is_none());
        store.set_account(
            addr,
            Account {
                balance: U256::from(5u64),
                nonce: 7,
                code: Bytes::new(),
            },
        );
        let acc = store.account(&addr).expect("account stored");
        assert_eq!(acc.balance, U256::from(5u64));
        assert_eq!(acc.nonce, 7);

        let slot = U256::from(1u64);
        assert_eq!(store.storage_slot(&addr, &slot), U256::ZERO);
        store.set_storage_slot(addr, slot, U256::from(99u64));
        assert_eq!(store.storage_slot(&addr, &slot), U256::from(99u64));

        assert_eq!(store.all_accounts().len(), 1);
        assert_eq!(store.all_storage().len(), 1);
    }
}
