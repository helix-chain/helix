//! Block / transaction / receipt types and the chain container.

use std::collections::HashMap;

use alloy_consensus::TxEnvelope;
use alloy_primitives::{Address, B256, Bytes, U256};

use crate::state::{InMemoryStorage, Storage, keccak};

/// A transaction admitted to the mempool, with recovered sender.
#[derive(Debug, Clone)]
pub struct PendingTx {
    pub hash: B256,
    pub from: Address,
    pub envelope: TxEnvelope,
}

/// Minimal devnet block.
#[derive(Debug, Clone)]
pub struct Block {
    pub number: u64,
    pub timestamp: u64,
    pub parent_hash: B256,
    pub hash: B256,
    pub tx_hashes: Vec<B256>,
}

impl Block {
    pub fn genesis() -> Self {
        Self {
            number: 0,
            timestamp: 0,
            parent_hash: B256::ZERO,
            hash: keccak(b"helix-devnet-genesis"),
            tx_hashes: Vec::new(),
        }
    }

    /// Deterministic devnet block hash: keccak(number ‖ parent ‖ timestamp ‖ tx hashes).
    pub fn seal(number: u64, parent_hash: B256, timestamp: u64, tx_hashes: &[B256]) -> B256 {
        let mut buf = Vec::with_capacity(8 + 32 + 8 + tx_hashes.len() * 32);
        buf.extend_from_slice(&number.to_be_bytes());
        buf.extend_from_slice(parent_hash.as_slice());
        buf.extend_from_slice(&timestamp.to_be_bytes());
        for h in tx_hashes {
            buf.extend_from_slice(h.as_slice());
        }
        keccak(&buf)
    }
}

/// Execution receipt for one transaction.
#[derive(Debug, Clone)]
pub struct Receipt {
    pub tx_hash: B256,
    pub block_number: u64,
    pub block_hash: B256,
    pub transaction_index: u64,
    pub from: Address,
    pub to: Option<Address>,
    pub contract_address: Option<Address>,
    pub gas_used: u64,
    /// Running gas total within the block, up to and including this tx.
    pub cumulative_gas_used: u64,
    /// 1 = success, 0 = reverted/halted.
    pub status: u64,
    pub output: Bytes,
}

/// The single shared chain object (behind `Arc<Mutex<_>>` at runtime).
pub struct Chain {
    pub chain_id: u64,
    pub storage: Box<dyn Storage>,
    pub blocks: Vec<Block>,
    pub receipts: HashMap<B256, Receipt>,
}

impl Chain {
    pub fn new(chain_id: u64, alloc: Vec<(Address, U256)>) -> Self {
        let mut storage = InMemoryStorage::new();
        for (addr, balance) in alloc {
            storage.set_account(
                addr,
                crate::state::Account {
                    balance,
                    ..Default::default()
                },
            );
        }
        Self {
            chain_id,
            storage: Box::new(storage),
            blocks: vec![Block::genesis()],
            receipts: HashMap::new(),
        }
    }

    pub fn head(&self) -> &Block {
        self.blocks.last().expect("chain always has genesis")
    }

    pub fn balance_of(&self, addr: &Address) -> U256 {
        self.storage
            .account(addr)
            .map(|a| a.balance)
            .unwrap_or_default()
    }
}
