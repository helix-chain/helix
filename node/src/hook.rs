//! Security hook — the HELIX differentiator seam.
//!
//! Every transaction passes through a `SecurityHook` BEFORE entering the
//! mempool. The hook is invoked OUTSIDE the mempool lock (see `rpc.rs`), on the
//! blocking pool, so a slow implementation cannot stall the async runtime or
//! serialize admissions.
//!
//! v0.1 shipped `PassthroughHook` (allow + log). v0.2 (task B1) adds
//! [`crate::immune::ImmuneHook`] — a fast, deterministic immune-signature gate.
//! A later task wires the ML `mismatch_detector.py` as an ADVISORY deploy-time
//! sidecar (non-deterministic, never a consensus-relevant admission gate).

use alloy_primitives::{Address, B256, Bytes, U256};

/// Graded risk level, mirroring the detector's LOW/MEDIUM/HIGH/CRITICAL output
/// so a future detector-backed hook maps onto the same verdict type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Verdict returned by a security hook.
///
/// A graded superset of v0.1's binary allow/reject: `Flag` admits the tx but
/// records an advisory signal, `Reject` blocks it. This lets a detector-backed
/// hook express "admit but alert" without a breaking trait change later.
#[derive(Debug, Clone, PartialEq)]
pub enum HookVerdict {
    Allow,
    Flag {
        risk: RiskLevel,
        score: f64,
        reason: String,
    },
    Reject {
        risk: RiskLevel,
        reason: String,
    },
}

impl HookVerdict {
    pub fn is_reject(&self) -> bool {
        matches!(self, HookVerdict::Reject { .. })
    }
}

/// Transaction summary handed to hooks. Carries enough to run a runtime
/// signature check: the calldata / creation bytecode, the kind, and the value.
#[derive(Debug, Clone)]
pub struct TxView {
    pub hash: B256,
    pub from: Address,
    pub to: Option<Address>,
    pub is_create: bool,
    pub value: U256,
    pub input: Bytes,
}

/// Synchronous hook invoked before a transaction is admitted to the mempool.
/// Kept sync on purpose: the call site runs it via `spawn_blocking` outside the
/// mempool lock, so a blocking implementation (e.g. a detector sidecar call)
/// does not require the trait itself to be async.
pub trait SecurityHook: Send + Sync + 'static {
    fn inspect(&self, tx: &TxView) -> HookVerdict;
}

/// Allow everything, log the sighting.
#[derive(Debug, Default)]
pub struct PassthroughHook;

impl SecurityHook for PassthroughHook {
    fn inspect(&self, tx: &TxView) -> HookVerdict {
        tracing::info!(
            tx_hash = %tx.hash,
            from = %tx.from,
            to = ?tx.to,
            input_len = tx.input.len(),
            "security-hook: passthrough allow"
        );
        HookVerdict::Allow
    }
}

/// Test helper: counts inspected transactions.
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
