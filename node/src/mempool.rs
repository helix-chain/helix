//! FIFO transaction pool with zero-fee admission rules and the security-hook
//! call site (spec §1: hook runs BEFORE a transaction enters the pool).

use std::collections::VecDeque;
use std::sync::Arc;

use alloy_consensus::TxEnvelope;
use alloy_consensus::transaction::SignerRecoverable;
use alloy_consensus::transaction::Transaction as _;
use alloy_primitives::B256;
use thiserror::Error;

use crate::chain::PendingTx;
use crate::hook::{HookVerdict, SecurityHook, TxView};

#[derive(Debug, Error)]
pub enum AdmitError {
    #[error("invalid signature: {0}")]
    Signature(String),
    #[error("devnet only accepts zero-fee transactions (gas_price / max_fee must be 0)")]
    NonZeroFee,
    #[error("wrong chain id (expected {expected})")]
    ChainId { expected: u64 },
    #[error("transaction rejected by security hook")]
    HookRejected,
    #[error("transaction already pending")]
    Duplicate,
}

pub struct Mempool {
    chain_id: u64,
    queue: VecDeque<PendingTx>,
    hook: Arc<dyn SecurityHook>,
}

impl Mempool {
    pub fn new(chain_id: u64, hook: Arc<dyn SecurityHook>) -> Self {
        Self {
            chain_id,
            queue: VecDeque::new(),
            hook,
        }
    }

    /// Validate and admit a decoded transaction. Returns its hash.
    pub fn admit(&mut self, envelope: TxEnvelope) -> Result<B256, AdmitError> {
        let from = envelope
            .recover_signer()
            .map_err(|e| AdmitError::Signature(e.to_string()))?;

        // Zero-fee rule (spec §1): legacy gas_price == 0, or EIP-1559 max fees == 0.
        if envelope.max_fee_per_gas() != 0 {
            return Err(AdmitError::NonZeroFee);
        }

        // Legacy pre-EIP-155 txs carry no chain id; everything else must match.
        if let Some(id) = envelope.chain_id()
            && id != self.chain_id
        {
            return Err(AdmitError::ChainId {
                expected: self.chain_id,
            });
        }

        let hash = *envelope.hash();
        if self.queue.iter().any(|p| p.hash == hash) {
            return Err(AdmitError::Duplicate);
        }

        // Security hook gate — must run before the tx is queued.
        let view = TxView {
            hash,
            from,
            to: envelope.to(),
            input_len: envelope.input().len(),
        };
        if self.hook.inspect(&view) == HookVerdict::Reject {
            return Err(AdmitError::HookRejected);
        }

        self.queue.push_back(PendingTx {
            hash,
            from,
            envelope,
        });
        Ok(hash)
    }

    /// Drain every pending transaction in FIFO order for block production.
    pub fn drain(&mut self) -> Vec<PendingTx> {
        self.queue.drain(..).collect()
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}
