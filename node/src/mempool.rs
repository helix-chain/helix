//! FIFO transaction pool with zero-fee admission rules.
//!
//! The security hook is invoked by the RPC layer (`rpc.rs`) BETWEEN cheap
//! validation and enqueueing — outside the mempool lock — so this module no
//! longer owns or calls the hook. Admission is a two-step handshake:
//! [`Mempool::validate`] (stateless, lock-free) then
//! [`Mempool::admit_validated`] (touches the queue, under lock).

use std::collections::VecDeque;

use alloy_consensus::TxEnvelope;
use alloy_consensus::transaction::SignerRecoverable;
use alloy_consensus::transaction::Transaction as _;
use alloy_primitives::B256;
use thiserror::Error;

use crate::chain::PendingTx;
use crate::hook::TxView;

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
    #[error("transaction already pending")]
    Duplicate,
}

pub struct Mempool {
    queue: VecDeque<PendingTx>,
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}

impl Mempool {
    pub fn new() -> Self {
        Self {
            queue: VecDeque::new(),
        }
    }

    /// Stateless, lock-free validation: decode-level checks that do not touch
    /// the queue. Returns the hook's `TxView` plus the `PendingTx` ready to
    /// enqueue. The caller runs the security hook on the `TxView` (outside any
    /// lock) before calling [`Mempool::admit_validated`].
    pub fn validate(
        chain_id: u64,
        envelope: TxEnvelope,
    ) -> Result<(TxView, PendingTx), AdmitError> {
        // Blob (4844) and set-code (7702) txs carry semantics the v0.1 executor
        // would silently drop — reject instead of mis-executing.
        if matches!(envelope, TxEnvelope::Eip4844(_) | TxEnvelope::Eip7702(_)) {
            return Err(AdmitError::UnsupportedType);
        }

        let from = envelope
            .recover_signer()
            .map_err(|e| AdmitError::Signature(e.to_string()))?;

        // Zero-fee rule: legacy gas_price == 0, or EIP-1559 max fees == 0.
        if envelope.max_fee_per_gas() != 0 {
            return Err(AdmitError::NonZeroFee);
        }

        // Require a matching EIP-155 chain id. Pre-155 legacy txs carry no chain
        // id and are cross-chain replayable, so they are refused on this devnet.
        match envelope.chain_id() {
            Some(id) if id == chain_id => {}
            Some(_) => return Err(AdmitError::ChainId { expected: chain_id }),
            None => return Err(AdmitError::MissingChainId),
        }

        let hash = *envelope.hash();
        let view = TxView {
            hash,
            from,
            to: envelope.to(),
            is_create: envelope.kind().is_create(),
            value: envelope.value(),
            input: envelope.input().clone(),
        };
        let pending = PendingTx {
            hash,
            from,
            envelope,
        };
        Ok((view, pending))
    }

    /// Enqueue a validated transaction (after the security hook has allowed it).
    /// Rejects same-block duplicates; cross-block replay is stopped by the nonce
    /// check at execution, not here.
    pub fn admit_validated(&mut self, pending: PendingTx) -> Result<B256, AdmitError> {
        if self.queue.iter().any(|p| p.hash == pending.hash) {
            return Err(AdmitError::Duplicate);
        }
        let hash = pending.hash;
        self.queue.push_back(pending);
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
    use alloy_consensus::{SignableTransaction, TxLegacy};
    use alloy_primitives::{TxKind, U256, address};
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;

    use super::*;

    /// Anvil/Hardhat well-known dev key #0 (public test key, devnet only).
    const DEV_KEY_0: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    const CHAIN_ID: u64 = 2026;

    fn signed_legacy(gas_price: u128, chain_id: Option<u64>) -> TxEnvelope {
        let signer: PrivateKeySigner = DEV_KEY_0.parse().expect("dev key");
        let tx = TxLegacy {
            chain_id,
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

    #[test]
    fn validate_accepts_zero_fee_then_enqueue() {
        let (view, pending) =
            Mempool::validate(CHAIN_ID, signed_legacy(0, Some(CHAIN_ID))).expect("zero-fee");
        assert!(!view.is_create, "call tx, not create");
        let mut pool = Mempool::new();
        let hash = pool.admit_validated(pending).expect("enqueued");
        assert_eq!(pool.len(), 1);
        let drained = pool.drain();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].hash, hash);
        assert!(pool.is_empty());
    }

    #[test]
    fn non_zero_fee_rejected() {
        let result = Mempool::validate(CHAIN_ID, signed_legacy(1_000_000_000, Some(CHAIN_ID)));
        assert!(matches!(result, Err(AdmitError::NonZeroFee)));
    }

    /// A pre-EIP-155 legacy tx (no chain id) is replay-unsafe and refused.
    #[test]
    fn pre_eip155_tx_rejected() {
        let result = Mempool::validate(CHAIN_ID, signed_legacy(0, None));
        assert!(matches!(result, Err(AdmitError::MissingChainId)));
    }

    #[test]
    fn wrong_chain_id_rejected() {
        let result = Mempool::validate(CHAIN_ID, signed_legacy(0, Some(9999)));
        assert!(matches!(result, Err(AdmitError::ChainId { .. })));
    }

    #[test]
    fn duplicate_rejected_within_block() {
        let mut pool = Mempool::new();
        let (_, p1) = Mempool::validate(CHAIN_ID, signed_legacy(0, Some(CHAIN_ID))).unwrap();
        let (_, p2) = Mempool::validate(CHAIN_ID, signed_legacy(0, Some(CHAIN_ID))).unwrap();
        pool.admit_validated(p1).expect("first admitted");
        assert!(matches!(
            pool.admit_validated(p2),
            Err(AdmitError::Duplicate)
        ));
        assert_eq!(pool.len(), 1);
    }
}
