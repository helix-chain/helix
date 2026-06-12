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
    #[error("pre-EIP-155 transactions without a chain id are replay-unsafe and not accepted")]
    MissingChainId,
    #[error("transaction type not supported on this devnet (EIP-4844 blob / EIP-7702 set-code)")]
    UnsupportedType,
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
        // Blob (4844) and set-code (7702) txs carry semantics the v0.1
        // executor would silently drop — reject instead of mis-executing.
        if matches!(envelope, TxEnvelope::Eip4844(_) | TxEnvelope::Eip7702(_)) {
            return Err(AdmitError::UnsupportedType);
        }

        let from = envelope
            .recover_signer()
            .map_err(|e| AdmitError::Signature(e.to_string()))?;

        // Zero-fee rule (spec §1): legacy gas_price == 0, or EIP-1559 max fees == 0.
        if envelope.max_fee_per_gas() != 0 {
            return Err(AdmitError::NonZeroFee);
        }

        // Require a matching EIP-155 chain id. Pre-155 legacy txs carry no chain
        // id and are cross-chain replayable, so they are refused on this devnet.
        match envelope.chain_id() {
            Some(id) if id == self.chain_id => {}
            Some(_) => {
                return Err(AdmitError::ChainId {
                    expected: self.chain_id,
                });
            }
            None => return Err(AdmitError::MissingChainId),
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

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use alloy_consensus::{SignableTransaction, TxLegacy};
    use alloy_primitives::{TxKind, U256, address};
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;

    use super::*;
    use crate::hook::{CountingHook, PassthroughHook};

    /// Anvil/Hardhat well-known dev key #0 (public test key, devnet only).
    const DEV_KEY_0: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    const CHAIN_ID: u64 = 2026;

    struct RejectingHook;

    impl SecurityHook for RejectingHook {
        fn inspect(&self, _tx: &TxView) -> HookVerdict {
            HookVerdict::Reject
        }
    }

    fn signed_legacy(gas_price: u128) -> TxEnvelope {
        let signer: PrivateKeySigner = DEV_KEY_0.parse().expect("dev key");
        let tx = TxLegacy {
            chain_id: Some(CHAIN_ID),
            nonce: 0,
            gas_price,
            gas_limit: 21_000,
            to: TxKind::Call(address!("70997970C51812dc3A010C7d01b50e0d17dc79C8")),
            value: U256::from(1u64),
            input: Default::default(),
        };
        let sig = signer.sign_hash_sync(&tx.signature_hash()).expect("sign");
        tx.into_signed(sig).into()
    }

    /// AC-6 ordering proof: a rejecting hook keeps the tx OUT of the queue —
    /// the gate runs before admission, not at block production.
    #[test]
    fn rejecting_hook_blocks_admission() {
        let mut pool = Mempool::new(CHAIN_ID, Arc::new(RejectingHook));
        let result = pool.admit(signed_legacy(0));
        assert!(matches!(result, Err(AdmitError::HookRejected)));
        assert!(pool.is_empty(), "rejected tx must never enter the queue");
    }

    /// Fee validation runs before the hook: a fee-paying tx is refused
    /// without the hook ever seeing it.
    #[test]
    fn non_zero_fee_rejected_before_hook() {
        let hook = Arc::new(CountingHook::default());
        let mut pool = Mempool::new(CHAIN_ID, hook.clone());
        let result = pool.admit(signed_legacy(1_000_000_000));
        assert!(matches!(result, Err(AdmitError::NonZeroFee)));
        assert_eq!(hook.seen.load(Ordering::SeqCst), 0);
        assert!(pool.is_empty());
    }

    #[test]
    fn passthrough_admits_zero_fee_tx() {
        let mut pool = Mempool::new(CHAIN_ID, Arc::new(PassthroughHook));
        let hash = pool.admit(signed_legacy(0)).expect("zero-fee admitted");
        assert_eq!(pool.len(), 1);
        let drained = pool.drain();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].hash, hash);
        assert!(pool.is_empty());
    }

    /// A pre-EIP-155 legacy tx (no chain id) — replay-unsafe, must be refused.
    fn signed_legacy_no_chainid() -> TxEnvelope {
        let signer: PrivateKeySigner = DEV_KEY_0.parse().expect("dev key");
        let tx = TxLegacy {
            chain_id: None,
            nonce: 0,
            gas_price: 0,
            gas_limit: 21_000,
            to: TxKind::Call(address!("70997970C51812dc3A010C7d01b50e0d17dc79C8")),
            value: U256::from(1u64),
            input: Default::default(),
        };
        let sig = signer.sign_hash_sync(&tx.signature_hash()).expect("sign");
        tx.into_signed(sig).into()
    }

    #[test]
    fn pre_eip155_tx_rejected() {
        let mut pool = Mempool::new(CHAIN_ID, Arc::new(PassthroughHook));
        let result = pool.admit(signed_legacy_no_chainid());
        assert!(matches!(result, Err(AdmitError::MissingChainId)));
        assert!(
            pool.is_empty(),
            "replay-unsafe tx must never enter the queue"
        );
    }
}
