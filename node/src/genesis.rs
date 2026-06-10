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

/// (address, balance) pairs applied to state at block 0.
pub fn genesis_alloc() -> Vec<(Address, U256)> {
    DEV_ACCOUNTS
        .iter()
        .map(|addr| (*addr, genesis_balance()))
        .collect()
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
}
