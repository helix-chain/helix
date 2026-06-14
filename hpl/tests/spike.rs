//! Spike integration test: boot a real HELIX devnet in-process, deploy
//! WrappedPoint through the hpl client, and read balances via `eth_call`.
//! Proves the on-chain points primitive deploys and is readable on HELIX,
//! end to end. The node crate is consumed read-only (dev-dependency); it is
//! not modified.

use std::sync::Arc;

use alloy_primitives::{Address, Bytes, U256, address};

use helix_node::hook::CountingHook;
use helix_node::{config::NodeConfig, node};

use hpl::abi;
use hpl::bytecode::WRAPPED_POINT_CREATION_BYTECODE;
use hpl::client::{DEV_KEY_0, RpcClient};

/// Dev account #0 = the deployer; the constructor assigns the fixed initial supply here.
const DEPLOYER: Address = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
/// Dev account #1 = an untouched account; should hold zero wTEST.
const OTHER: Address = address!("70997970C51812dc3A010C7d01b50e0d17dc79C8");

#[tokio::test]
async fn deploy_then_balance_reads_initial_supply() {
    let handle = node::start(NodeConfig::test(), Arc::new(CountingHook::default()))
        .await
        .expect("node starts");
    let client = RpcClient::new(format!("http://{}", handle.rpc_addr));

    // Sanity: we are talking to the HELIX devnet (chain id 2026).
    assert_eq!(client.chain_id().await.unwrap(), 2026);

    let code = Bytes::from(hex::decode(WRAPPED_POINT_CREATION_BYTECODE).unwrap());
    let contract = client
        .deploy(DEV_KEY_0, code, 0)
        .await
        .expect("deploy wTEST");

    // The deployer holds the constructor-assigned 1,000,000 wTEST...
    let out = client
        .eth_call(contract, abi::encode_balance_of(DEPLOYER))
        .await
        .unwrap();
    assert_eq!(
        abi::decode_uint256(&out).unwrap(),
        U256::from(1_000_000u64),
        "deployer balance = constructor initial supply"
    );

    // ...and an untouched account holds zero.
    let out = client
        .eth_call(contract, abi::encode_balance_of(OTHER))
        .await
        .unwrap();
    assert_eq!(abi::decode_uint256(&out).unwrap(), U256::ZERO, "other = 0");

    handle.shutdown().await;
}
