//! HPL spike client library.
//!
//! A thin JSON-RPC client that deploys the WrappedPoint (wTEST) test-point
//! token to a local HELIX devnet and reads balances via `eth_call balanceOf`.
//!
//! Spike scope = **deploy + balance only**. No issue/redeem/ledger app, no
//! real loyalty points, no real payments, no HLX fees. Unrelated to any HLX
//! token sale. The library makes no regulatory claim.

pub mod abi;
pub mod bytecode;
pub mod client;
