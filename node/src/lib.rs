//! helix-node — HELIX Chain single-node devnet (v0.1).
//!
//! Library surface consumed by the `helix-node` binary and the e2e tests.
//! Architecture seams for v0.2+: [`state::Storage`] (RocksDB backend) and
//! [`hook::SecurityHook`] (mismatch-detector / immune-library integration).

pub mod chain;
pub mod config;
pub mod executor;
pub mod genesis;
pub mod hook;
pub mod immune;
pub mod mempool;
pub mod node;
pub mod rpc;
pub mod state;
