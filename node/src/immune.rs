//! Deterministic immune-signature gate (v0.2, task B1).
//!
//! Unlike the ML `mismatch_detector.py` (source-level, non-deterministic — to
//! be wired later as an ADVISORY deploy-time sidecar), this is a fast,
//! deterministic, consensus-safe RUNTIME check: it matches a transaction's
//! calldata / creation bytecode against a fixed table of known-malicious
//! signatures. Determinism is required so that, in a future multi-node phase,
//! every node reaches the same admission decision — a fuzzy ML score must never
//! gate admission (see audit §5 on consensus safety).

use crate::hook::{HookVerdict, RiskLevel, SecurityHook, TxView};

/// A deterministic attack signature: a byte prefix matched against the
/// transaction input (calldata for calls, init bytecode for creates).
#[derive(Debug, Clone)]
pub struct Signature {
    pub name: &'static str,
    pub risk: RiskLevel,
    pub prefix: &'static [u8],
}

/// Seed signatures — a PLACEHOLDER demo table. In Phase 2 these are generated
/// from the immune library (`immune_library_500.json`) as exact bytecode /
/// 4-byte-selector signatures, not hand-written.
pub const SEED_SIGNATURES: &[Signature] = &[Signature {
    name: "demo:blocked-selector(0xdeadbeef)",
    risk: RiskLevel::Critical,
    prefix: &[0xde, 0xad, 0xbe, 0xef],
}];

/// Runtime immune gate backed by a fixed signature table.
#[derive(Debug)]
pub struct ImmuneHook {
    signatures: &'static [Signature],
}

impl ImmuneHook {
    pub fn new() -> Self {
        Self {
            signatures: SEED_SIGNATURES,
        }
    }

    pub fn with_signatures(signatures: &'static [Signature]) -> Self {
        Self { signatures }
    }
}

impl Default for ImmuneHook {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityHook for ImmuneHook {
    fn inspect(&self, tx: &TxView) -> HookVerdict {
        for sig in self.signatures {
            if tx.input.starts_with(sig.prefix) {
                tracing::warn!(
                    tx_hash = %tx.hash,
                    signature = sig.name,
                    "security-hook: immune signature match — rejecting"
                );
                return HookVerdict::Reject {
                    risk: sig.risk,
                    reason: format!("immune signature match: {}", sig.name),
                };
            }
        }
        HookVerdict::Allow
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{Address, B256, Bytes, U256};

    use super::*;

    fn view(input: Vec<u8>) -> TxView {
        TxView {
            hash: B256::ZERO,
            from: Address::ZERO,
            to: None,
            is_create: true,
            value: U256::ZERO,
            input: Bytes::from(input),
        }
    }

    #[test]
    fn rejects_matching_signature() {
        let hook = ImmuneHook::new();
        let verdict = hook.inspect(&view(vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]));
        assert!(verdict.is_reject(), "0xdeadbeef prefix must be rejected");
    }

    #[test]
    fn allows_clean_input() {
        let hook = ImmuneHook::new();
        let verdict = hook.inspect(&view(vec![0x60, 0x00, 0x60, 0x00]));
        assert_eq!(verdict, HookVerdict::Allow);
    }
}
