//! Security hook — the HELIX differentiator seam.
//!
//! Every transaction passes through a `SecurityHook` BEFORE entering the
//! mempool. v0.1 ships `PassthroughHook` (allow + log). v0.2 TODO: an
//! implementation that consults the mismatch detector / immune library
//! (Python MVP at repo root) and rejects or flags risky transactions.

use alloy_primitives::{Address, B256};

/// Verdict returned by a security hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookVerdict {
    Allow,
    Reject,
}

/// Transaction summary handed to hooks (kept small on purpose; extend in v0.2).
#[derive(Debug, Clone)]
pub struct TxView {
    pub hash: B256,
    pub from: Address,
    pub to: Option<Address>,
    pub input_len: usize,
}

/// Synchronous hook invoked before a transaction is admitted to the mempool.
pub trait SecurityHook: Send + Sync + 'static {
    fn inspect(&self, tx: &TxView) -> HookVerdict;
}

/// v0.1 default: allow everything, log the sighting.
#[derive(Debug, Default)]
pub struct PassthroughHook;

impl SecurityHook for PassthroughHook {
    fn inspect(&self, tx: &TxView) -> HookVerdict {
        tracing::info!(
            tx_hash = %tx.hash,
            from = %tx.from,
            to = ?tx.to,
            input_len = tx.input_len,
            "security-hook: passthrough allow"
        );
        HookVerdict::Allow
    }
}

/// Test helper: counts inspected transactions (AC-6).
#[derive(Debug, Default)]
pub struct CountingHook {
    pub seen: std::sync::atomic::AtomicUsize,
}

impl SecurityHook for CountingHook {
    fn inspect(&self, _tx: &TxView) -> HookVerdict {
        self.seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        HookVerdict::Allow
    }
}
