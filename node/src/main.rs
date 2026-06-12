//! helix-node v0.1 — HELIX Chain single-node devnet.
//!
//! Usage: `cargo run --release -- --dev [--block-time 2] [--port 8545]`

use std::sync::Arc;

use anyhow::{Result, bail};
use clap::Parser;

use helix_node::config::{Cli, NodeConfig};
use helix_node::immune::ImmuneHook;
use helix_node::node;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let cli = Cli::parse();
    if !cli.dev {
        bail!("v0.1 only supports devnet mode — start with `helix-node --dev`");
    }

    let config = NodeConfig::from_cli(&cli);
    let handle = node::start(config, Arc::new(ImmuneHook::new())).await?;

    tracing::info!("press Ctrl+C to stop");
    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down…");
    handle.shutdown().await;
    tracing::info!("bye");
    Ok(())
}
