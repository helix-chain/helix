//! Genesis allocation for the HELIX devnet.
//!
//! The three accounts below are the industry-wide well-known Anvil/Hardhat
//! development keys. They are intentionally public and must NEVER hold value
//! on any real network. Spec §1 forbids generating new private keys here.

use alloy_primitives::{Address, U256, address};

/// Well-known Anvil/Hardhat dev accounts (index 0..2).
pub const DEV_ACCOUNTS: [Address; 3] = [
    address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
    address!("70997970C51812dc3A010C7d01b50e0d17dc79C8"),
    address!("3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"),
];

/// Pre-funded balance per dev account: 1,000,000 HLX (18 decimals).
pub fn genesis_balance() -> U256 {
    U256::from(1_000_000u64) * U256::from(10u64).pow(U256::from(18u64))
}

/// HELIX hard cap (Tokenomics v2.0 §2.1): 1,000,000,000 HLX — the economic
/// model's single "constitutional invariant", enforced at the consensus layer
/// in Phase 3. v0.1 mints nothing beyond genesis, so this only anchors the
/// allocation; any future PoI emission must keep total supply ≤ this value.
pub fn max_supply() -> U256 {
    U256::from(1_000_000_000u64) * U256::from(10u64).pow(U256::from(18u64))
}

/// (address, balance) pairs applied to state at block 0.
pub fn genesis_alloc() -> Vec<(Address, U256)> {
    let alloc: Vec<(Address, U256)> = DEV_ACCOUNTS
        .iter()
        .map(|addr| (*addr, genesis_balance()))
        .collect();
    let total = alloc.iter().fold(U256::ZERO, |acc, (_, bal)| acc + *bal);
    // assert (not debug_assert): the 1B hard cap is the economic model's
    // constitutional invariant — it must hold in --release builds too, not
    // just debug/test (debug_assert is compiled out under --release).
    assert!(
        total <= max_supply(),
        "genesis allocation ({total}) exceeds the HLX hard cap ({})",
        max_supply()
    );
    alloc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_prefunds_three_dev_accounts() {
        let alloc = genesis_alloc();
        assert_eq!(alloc.len(), 3);
        let expected = U256::from(1_000_000u64) * U256::from(10u64).pow(U256::from(18u64));
        for (_, balance) in alloc {
            assert_eq!(balance, expected);
        }
    }

    #[test]
    fn genesis_total_within_hard_cap() {
        let total = genesis_alloc()
            .iter()
            .fold(U256::ZERO, |acc, (_, bal)| acc + *bal);
        assert!(total <= max_supply());
        // 3 accounts × 1,000,000 HLX = 3,000,000 HLX, far under the 1B cap.
        let expected = U256::from(3_000_000u64) * U256::from(10u64).pow(U256::from(18u64));
        assert_eq!(total, expected);
    }
}
