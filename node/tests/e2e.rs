//! End-to-end tests: boot a real node in-process, drive it over HTTP JSON-RPC.
//!
//! Covers the build-spec (V1.1) acceptance criteria plus the v0.2 immune gate
//! (note: the engineering spec v1.0 has no AC numbering — these AC ids are ours):
//! - all six RPC methods respond with JSON-RPC 2.0 shapes
//! - zero-fee transfer included in next block, exact balance change, status=1
//! - contract deployment + eth_call returns the expected value
//! - SecurityHook observes every transaction before pool admission (CountingHook)
//! - the deterministic immune gate rejects a matching-signature transaction

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use alloy_consensus::{SignableTransaction, TxEnvelope, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, TxKind, U256, address, hex};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use serde_json::{Value, json};

use helix_node::config::{CHAIN_ID, NodeConfig};
use helix_node::genesis;
use helix_node::hook::CountingHook;
use helix_node::node;

/// Anvil/Hardhat well-known dev key #0 (public test key, devnet only).
const DEV_KEY_0: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const DEV_ADDR_0: Address = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
const DEV_ADDR_1: Address = address!("70997970C51812dc3A010C7d01b50e0d17dc79C8");

/// Init code that deploys a 10-byte runtime returning the constant 42:
/// PUSH10 <runtime> PUSH1 0 MSTORE PUSH1 10 PUSH1 22 RETURN
/// runtime: PUSH1 0x2a PUSH1 0 MSTORE PUSH1 32 PUSH1 0 RETURN
const DEPLOY_RETURN_42: &str = "69602a60005260206000f3600052600a6016f3";

async fn rpc(client: &reqwest::Client, url: &str, method: &str, params: Value) -> Value {
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    let resp: Value = client
        .post(url)
        .json(&body)
        .send()
        .await
        .expect("rpc send")
        .json()
        .await
        .expect("rpc json");
    assert_eq!(resp["jsonrpc"], "2.0", "JSON-RPC 2.0 envelope: {resp}");
    resp
}

async fn rpc_result(client: &reqwest::Client, url: &str, method: &str, params: Value) -> Value {
    let resp = rpc(client, url, method, params).await;
    assert!(
        resp.get("error").is_none(),
        "unexpected rpc error: {}",
        resp["error"]
    );
    resp["result"].clone()
}

fn sign_legacy(key: &str, tx: TxLegacy) -> Vec<u8> {
    let signer: PrivateKeySigner = key.parse().expect("dev key parses");
    let sig = signer
        .sign_hash_sync(&tx.signature_hash())
        .expect("sign tx");
    let envelope: TxEnvelope = tx.into_signed(sig).into();
    let mut raw = Vec::new();
    envelope.encode_2718(&mut raw);
    raw
}

async fn wait_for_receipt(client: &reqwest::Client, url: &str, tx_hash: &str) -> Value {
    for _ in 0..100 {
        let result = rpc_result(client, url, "eth_getTransactionReceipt", json!([tx_hash])).await;
        if !result.is_null() {
            return result;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("receipt for {tx_hash} not found within timeout");
}

fn parse_u256_hex(value: &Value) -> U256 {
    let s = value.as_str().expect("hex string");
    U256::from_str_radix(s.trim_start_matches("0x"), 16).expect("valid hex quantity")
}

#[tokio::test]
async fn e2e_transfer_deploy_call_and_hook() {
    let hook = Arc::new(CountingHook::default());
    let handle = node::start(NodeConfig::test(), hook.clone())
        .await
        .expect("node starts");
    let url = format!("http://{}", handle.rpc_addr);
    let client = reqwest::Client::new();

    // --- AC-3: basic methods ------------------------------------------------
    let chain_id = rpc_result(&client, &url, "eth_chainId", json!([])).await;
    assert_eq!(parse_u256_hex(&chain_id), U256::from(CHAIN_ID));

    let block0 = rpc_result(&client, &url, "eth_blockNumber", json!([])).await;
    assert!(block0.as_str().unwrap().starts_with("0x"));

    let genesis_balance = genesis::genesis_balance();
    let bal = rpc_result(
        &client,
        &url,
        "eth_getBalance",
        json!([format!("{DEV_ADDR_0}"), "latest"]),
    )
    .await;
    assert_eq!(parse_u256_hex(&bal), genesis_balance, "genesis prefund");

    // --- AC-4: zero-fee transfer --------------------------------------------
    let transfer_value = U256::from(7u64) * U256::from(10u64).pow(U256::from(17u64)); // 0.7 HLX
    let raw = sign_legacy(
        DEV_KEY_0,
        TxLegacy {
            chain_id: Some(CHAIN_ID),
            nonce: 0,
            gas_price: 0,
            gas_limit: 21_000,
            to: TxKind::Call(DEV_ADDR_1),
            value: transfer_value,
            input: Default::default(),
        },
    );
    let tx_hash = rpc_result(
        &client,
        &url,
        "eth_sendRawTransaction",
        json!([format!("0x{}", hex::encode(&raw))]),
    )
    .await;
    let receipt = wait_for_receipt(&client, &url, tx_hash.as_str().unwrap()).await;
    assert_eq!(receipt["status"], "0x1", "transfer succeeds: {receipt}");
    assert_eq!(
        receipt["from"].as_str().unwrap().to_lowercase(),
        format!("{DEV_ADDR_0}").to_lowercase()
    );

    // Zero-fee devnet: balances move by exactly `value`.
    let sender = rpc_result(
        &client,
        &url,
        "eth_getBalance",
        json!([format!("{DEV_ADDR_0}")]),
    )
    .await;
    let receiver = rpc_result(
        &client,
        &url,
        "eth_getBalance",
        json!([format!("{DEV_ADDR_1}")]),
    )
    .await;
    assert_eq!(
        parse_u256_hex(&sender),
        genesis_balance - transfer_value,
        "sender = genesis - value (no gas fee)"
    );
    assert_eq!(
        parse_u256_hex(&receiver),
        genesis_balance + transfer_value,
        "receiver = genesis + value"
    );

    let head = rpc_result(&client, &url, "eth_blockNumber", json!([])).await;
    assert!(
        parse_u256_hex(&head) > U256::ZERO,
        "blocks are being produced"
    );

    // --- AC-5: deploy + eth_call ---------------------------------------------
    let raw = sign_legacy(
        DEV_KEY_0,
        TxLegacy {
            chain_id: Some(CHAIN_ID),
            nonce: 1,
            gas_price: 0,
            gas_limit: 300_000,
            to: TxKind::Create,
            value: U256::ZERO,
            input: hex::decode(DEPLOY_RETURN_42).unwrap().into(),
        },
    );
    let tx_hash = rpc_result(
        &client,
        &url,
        "eth_sendRawTransaction",
        json!([format!("0x{}", hex::encode(&raw))]),
    )
    .await;
    let receipt = wait_for_receipt(&client, &url, tx_hash.as_str().unwrap()).await;
    assert_eq!(receipt["status"], "0x1", "deploy succeeds: {receipt}");
    let contract = receipt["contractAddress"]
        .as_str()
        .expect("create receipt carries contractAddress")
        .to_string();

    let output = rpc_result(
        &client,
        &url,
        "eth_call",
        json!([{ "to": contract, "data": "0x" }, "latest"]),
    )
    .await;
    assert_eq!(
        parse_u256_hex(&output),
        U256::from(42u64),
        "contract returns 42"
    );

    // --- AC-6: security hook saw both transactions before admission ----------
    assert_eq!(
        hook.seen.load(Ordering::SeqCst),
        2,
        "hook inspected every admitted tx"
    );

    handle.shutdown().await;
}

#[tokio::test]
async fn rejects_non_zero_fee_and_unknown_method() {
    let hook = Arc::new(CountingHook::default());
    let handle = node::start(NodeConfig::test(), hook.clone())
        .await
        .expect("node starts");
    let url = format!("http://{}", handle.rpc_addr);
    let client = reqwest::Client::new();

    // Non-zero gas price must be rejected at admission (zero-fee devnet rule).
    let raw = sign_legacy(
        DEV_KEY_0,
        TxLegacy {
            chain_id: Some(CHAIN_ID),
            nonce: 0,
            gas_price: 1_000_000_000,
            gas_limit: 21_000,
            to: TxKind::Call(DEV_ADDR_1),
            value: U256::from(1u64),
            input: Default::default(),
        },
    );
    let resp = rpc(
        &client,
        &url,
        "eth_sendRawTransaction",
        json!([format!("0x{}", hex::encode(&raw))]),
    )
    .await;
    let message = resp["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("zero-fee"),
        "non-zero fee rejected: {resp}"
    );
    assert_eq!(hook.seen.load(Ordering::SeqCst), 0, "rejected before hook");

    // Unknown method → -32601.
    let resp = rpc(&client, &url, "eth_getLogs", json!([])).await;
    assert_eq!(resp["error"]["code"], -32601);

    handle.shutdown().await;
}

#[tokio::test]
async fn immune_gate_rejects_matching_signature() {
    use helix_node::immune::ImmuneHook;

    let handle = node::start(NodeConfig::test(), Arc::new(ImmuneHook::new()))
        .await
        .expect("node starts");
    let url = format!("http://{}", handle.rpc_addr);
    let client = reqwest::Client::new();

    // A tx whose calldata starts with the demo immune signature 0xdeadbeef is
    // rejected at admission by the deterministic gate — it never reaches a block.
    let raw = sign_legacy(
        DEV_KEY_0,
        TxLegacy {
            chain_id: Some(CHAIN_ID),
            nonce: 0,
            gas_price: 0,
            gas_limit: 100_000,
            to: TxKind::Call(DEV_ADDR_1),
            value: U256::ZERO,
            input: hex::decode("deadbeef00").unwrap().into(),
        },
    );
    let resp = rpc(
        &client,
        &url,
        "eth_sendRawTransaction",
        json!([format!("0x{}", hex::encode(&raw))]),
    )
    .await;
    let message = resp["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("immune signature match"),
        "malicious tx rejected by immune gate: {resp}"
    );

    // A clean tx (no signature match), reusing nonce 0, is admitted and mined.
    let raw = sign_legacy(
        DEV_KEY_0,
        TxLegacy {
            chain_id: Some(CHAIN_ID),
            nonce: 0,
            gas_price: 0,
            gas_limit: 21_000,
            to: TxKind::Call(DEV_ADDR_1),
            value: U256::from(1u64),
            input: Default::default(),
        },
    );
    let tx_hash = rpc_result(
        &client,
        &url,
        "eth_sendRawTransaction",
        json!([format!("0x{}", hex::encode(&raw))]),
    )
    .await;
    let receipt = wait_for_receipt(&client, &url, tx_hash.as_str().unwrap()).await;
    assert_eq!(receipt["status"], "0x1", "clean tx mined: {receipt}");

    handle.shutdown().await;
}
