//! Node configuration derived from CLI flags.

use clap::Parser;

/// HELIX devnet chain id (arbitrary value, see spec §1).
pub const CHAIN_ID: u64 = 2026;

/// HELIX Node v0.1 — single-node devnet.
#[derive(Debug, Clone, Parser)]
#[command(name = "helix-node", version, about = "HELIX Chain devnet node v0.1")]
pub struct Cli {
    /// Run as a local development chain (required in v0.1).
    #[arg(long)]
    pub dev: bool,

    /// Seconds between blocks.
    #[arg(long, default_value_t = 2)]
    pub block_time: u64,

    /// JSON-RPC listen port (0 = ephemeral, used by tests).
    #[arg(long, default_value_t = 8545)]
    pub port: u16,
}

/// Resolved runtime configuration.
#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub chain_id: u64,
    pub block_time_secs: u64,
    pub rpc_port: u16,
}

impl NodeConfig {
    pub fn from_cli(cli: &Cli) -> Self {
        Self {
            chain_id: CHAIN_ID,
            block_time_secs: cli.block_time.max(1),
            rpc_port: cli.port,
        }
    }

    /// Configuration used by in-process tests: ephemeral port, fast blocks.
    pub fn test() -> Self {
        Self {
            chain_id: CHAIN_ID,
            block_time_secs: 1,
            rpc_port: 0,
        }
    }
}
