//! HPL spike CLI — deploy the WrappedPoint (wTEST) test-point token to a local
//! HELIX devnet and read balances. Scope = `deploy` + `balance` only.
//!
//! Not connected to real loyalty points, real payments, or HLX fees; unrelated
//! to any HLX token sale; makes no regulatory claim.

use alloy_primitives::{Address, Bytes};
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use hpl::abi;
use hpl::bytecode::WRAPPED_POINT_CREATION_BYTECODE;
use hpl::client::{DEV_KEY_0, RpcClient};

#[derive(Parser)]
#[command(name = "hpl", about = "HELIX Points Layer spike — deploy + balance")]
struct Cli {
    /// HELIX devnet JSON-RPC endpoint.
    #[arg(long, global = true, default_value = "http://127.0.0.1:8545")]
    rpc: String,
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Deploy WrappedPoint (wTEST) and print the contract address. Assumes a
    /// fresh devnet (deployer nonce 0) unless `--nonce` is given.
    Deploy {
        #[arg(long, default_value_t = 0)]
        nonce: u64,
    },
    /// Read `balanceOf(account)` on a deployed WrappedPoint via `eth_call`.
    Balance { contract: String, account: String },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let client = RpcClient::new(cli.rpc.clone());

    match cli.cmd {
        Command::Deploy { nonce } => {
            let code = hex::decode(WRAPPED_POINT_CREATION_BYTECODE)
                .context("decode embedded WrappedPoint bytecode")?;
            let addr = client.deploy(DEV_KEY_0, Bytes::from(code), nonce).await?;
            println!("{addr}");
        }
        Command::Balance { contract, account } => {
            let contract: Address = contract.parse().context("parse <contract> address")?;
            let account: Address = account.parse().context("parse <account> address")?;
            let out = client
                .eth_call(contract, abi::encode_balance_of(account))
                .await?;
            println!("{}", abi::decode_uint256(&out)?);
        }
    }
    Ok(())
}
