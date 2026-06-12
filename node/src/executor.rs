//! Revm-backed transaction execution.
//!
//! The chain state lives in our own `Storage`; for each block (or eth_call)
//! we materialise a `CacheDB` seeded from that storage, run transactions,
//! then fold the committed changes back into `Storage`.

use alloy_consensus::transaction::Transaction as _;
use alloy_primitives::{Address, Bytes, TxKind, U256};
use anyhow::{Context as _, Result, anyhow};
use revm::context::result::{ExecutionResult, Output};
use revm::context::{BlockEnv, TxEnv};
use revm::database::{CacheDB, EmptyDB};
use revm::state::AccountInfo;
use revm::{Context, ExecuteCommitEvm, ExecuteEvm, MainBuilder, MainContext};

use crate::chain::{Block, Chain, PendingTx, Receipt};
use crate::state::Account;

/// Devnet gas limit per transaction & per block. Kept under revm's per-tx
/// gas cap (2^24 = 16,777,216, latest-hardfork rule) — generous enough for a
/// zero-fee devnet.
pub const GAS_LIMIT: u64 = 16_000_000;

/// Seed a fresh `CacheDB` from the chain's current storage snapshot.
fn build_db(chain: &Chain) -> CacheDB<EmptyDB> {
    let mut db = CacheDB::new(EmptyDB::default());
    for (addr, acc) in chain.storage.all_accounts() {
        let code = if acc.code.is_empty() {
            None
        } else {
            Some(revm::state::Bytecode::new_raw(acc.code.clone()))
        };
        let info = AccountInfo {
            balance: acc.balance,
            nonce: acc.nonce,
            code_hash: code
                .as_ref()
                .map(|c| c.hash_slow())
                .unwrap_or(revm::primitives::KECCAK_EMPTY),
            code,
            ..Default::default()
        };
        db.insert_account_info(addr, info);
    }
    for ((addr, slot), value) in chain.storage.all_storage() {
        // Accounts were inserted above, so this only fails for orphan slots.
        let _ = db.insert_account_storage(addr, slot, value);
    }
    db
}

fn block_env(number: u64, timestamp: u64) -> BlockEnv {
    BlockEnv {
        number: U256::from(number),
        timestamp: U256::from(timestamp),
        gas_limit: GAS_LIMIT,
        basefee: 0,
        ..Default::default()
    }
}

fn tx_env(chain_id: u64, tx: &PendingTx) -> TxEnv {
    let env = &tx.envelope;
    TxEnv {
        caller: tx.from,
        gas_limit: env.gas_limit().min(GAS_LIMIT),
        gas_price: 0,
        gas_priority_fee: None,
        kind: env.kind(),
        value: env.value(),
        data: env.input().clone(),
        nonce: env.nonce(),
        chain_id: Some(chain_id),
        ..Default::default()
    }
}

/// Write every account revm touched back into our `Storage`.
fn persist(chain: &mut Chain, db: &CacheDB<EmptyDB>) {
    for (addr, db_acc) in db.cache.accounts.iter() {
        let info = &db_acc.info;
        let code = info
            .code
            .as_ref()
            .map(|c| c.original_bytes())
            .unwrap_or_default();
        chain.storage.set_account(
            *addr,
            Account {
                balance: info.balance,
                nonce: info.nonce,
                code,
            },
        );
        for (slot, value) in db_acc.storage.iter() {
            chain.storage.set_storage_slot(*addr, *slot, *value);
        }
    }
}

/// Execute `txs` against the chain head, producing the next block + receipts.
pub fn execute_block(chain: &mut Chain, txs: Vec<PendingTx>, timestamp: u64) -> Result<Block> {
    let number = chain.head().number + 1;
    let parent_hash = chain.head().hash;
    let mut db = build_db(chain);

    let mut tx_hashes = Vec::with_capacity(txs.len());
    let mut receipts = Vec::with_capacity(txs.len());
    // Dropped (invalid) txs must not leave gaps: index/cumulative gas track
    // only transactions that actually made it into the block.
    let mut cumulative_gas = 0u64;

    for tx in txs.iter() {
        let mut evm = Context::mainnet()
            .with_db(&mut db)
            .modify_cfg_chained(|cfg| cfg.chain_id = chain.chain_id)
            .modify_block_chained(|b| *b = block_env(number, timestamp))
            .build_mainnet();

        let result = match evm.transact_commit(tx_env(chain.chain_id, tx)) {
            Ok(res) => res,
            Err(err) => {
                // Invalid tx (bad nonce, insufficient funds, …): skip it, keep the block going.
                tracing::warn!(tx_hash = %tx.hash, %err, "dropping invalid transaction");
                continue;
            }
        };

        let status = if result.is_success() { 1u64 } else { 0u64 };
        let gas_used = result.tx_gas_used();
        let output = match &result {
            ExecutionResult::Success { output, .. } => output.data().clone(),
            ExecutionResult::Revert { output, .. } => output.clone(),
            ExecutionResult::Halt { .. } => Bytes::new(),
        };

        let contract_address = match &result {
            ExecutionResult::Success {
                output: Output::Create(_, addr),
                ..
            } => *addr,
            _ => None,
        };

        let to = match tx.envelope.kind() {
            TxKind::Call(addr) => Some(addr),
            TxKind::Create => None,
        };

        cumulative_gas += gas_used;
        receipts.push(Receipt {
            tx_hash: tx.hash,
            block_number: number,
            block_hash: alloy_primitives::B256::ZERO, // sealed below
            transaction_index: tx_hashes.len() as u64,
            from: tx.from,
            to,
            contract_address,
            gas_used,
            cumulative_gas_used: cumulative_gas,
            status,
            output,
        });
        tx_hashes.push(tx.hash);
    }

    persist(chain, &db);

    let hash = Block::seal(number, parent_hash, timestamp, &tx_hashes);
    for receipt in &mut receipts {
        receipt.block_hash = hash;
        chain.receipts.insert(receipt.tx_hash, receipt.clone());
    }

    let block = Block {
        number,
        timestamp,
        parent_hash,
        hash,
        tx_hashes,
    };
    chain.blocks.push(block.clone());
    Ok(block)
}

/// Read-only `eth_call` against the latest state (nothing is persisted).
pub fn call(chain: &Chain, from: Address, to: Address, data: Bytes, value: U256) -> Result<Bytes> {
    let head = chain.head();
    let mut db = build_db(chain);

    let mut evm = Context::mainnet()
        .with_db(&mut db)
        .modify_cfg_chained(|cfg| {
            cfg.chain_id = chain.chain_id;
            // eth_call convenience: don't reject on nonce/balance bookkeeping —
            // a value-bearing probe from an unfunded (e.g. default zero) address
            // must still simulate, matching standard eth_call semantics.
            cfg.disable_nonce_check = true;
            cfg.disable_balance_check = true;
        })
        .modify_block_chained(|b| *b = block_env(head.number, head.timestamp))
        .build_mainnet();

    let env = TxEnv {
        caller: from,
        gas_limit: GAS_LIMIT,
        gas_price: 0,
        kind: TxKind::Call(to),
        value,
        data,
        chain_id: Some(chain.chain_id),
        // nonce check disabled in cfg; current account nonce is fine.
        ..Default::default()
    };

    let result = evm
        .transact(env)
        .map_err(|e| anyhow!("eth_call execution error: {e}"))?
        .result;

    match result {
        ExecutionResult::Success { output, .. } => Ok(output.data().clone()),
        ExecutionResult::Revert { output, .. } => {
            Err(anyhow!("execution reverted: 0x{}", hex::encode(&output)))
        }
        ExecutionResult::Halt { reason, .. } => Err(anyhow!("execution halted: {reason:?}")),
    }
    .context("eth_call failed")
}
