//! Thin JSON-RPC client for the HELIX devnet (the 6-method surface) plus the
//! zero-fee legacy-tx signing the node expects.
//!
//! The signing recipe mirrors `node/tests/e2e.rs::sign_legacy`, kept here so
//! the binary does not depend on the node's test code. The node has no
//! `eth_getTransactionCount`, so callers manage nonces themselves (the spike
//! deploys once at nonce 0 against a fresh devnet).

use std::time::Duration;

use alloy_consensus::{SignableTransaction, TxEnvelope, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, Bytes, TxKind, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use anyhow::{Context, Result, anyhow};
use serde_json::{Value, json};

/// HELIX devnet chain id. Matches `helix_node::config::CHAIN_ID` (2026 / 0x7ea);
/// kept as a literal so this client stays decoupled from the node crate.
pub const CHAIN_ID: u64 = 2026;

/// Anvil/Hardhat well-known dev key #0 — intentionally public, **devnet only**.
/// Address: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266. Never use on a real
/// network. (Same key the node's genesis pre-funds and e2e tests sign with.)
pub const DEV_KEY_0: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

/// Generous deploy gas, comfortably under the node's per-tx cap (2^24) and
/// enough for the WrappedPoint constructor. Zero-fee devnet → costs nothing.
const DEPLOY_GAS_LIMIT: u64 = 3_000_000;

/// Receipt polling: 100 tries × 200ms ≈ 20s (matches e2e).
const RECEIPT_TRIES: u32 = 100;
const RECEIPT_INTERVAL: Duration = Duration::from_millis(200);

pub struct RpcClient {
    http: reqwest::Client,
    url: String,
}

impl RpcClient {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            http: reqwest::Client::new(),
            url: url.into(),
        }
    }

    /// One JSON-RPC call. Returns the `result` value, or an error if the node
    /// replied with a JSON-RPC `error` object.
    async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let resp: Value = self
            .http
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("rpc send {method}"))?
            .json()
            .await
            .with_context(|| format!("rpc decode {method}"))?;
        if let Some(e) = resp.get("error").filter(|e| !e.is_null()) {
            return Err(anyhow!("rpc error on {method}: {e}"));
        }
        Ok(resp.get("result").cloned().unwrap_or(Value::Null))
    }

    /// `eth_chainId` as a u64 — a cheap liveness/identity probe.
    pub async fn chain_id(&self) -> Result<u64> {
        let r = self.call("eth_chainId", json!([])).await?;
        let s = r
            .as_str()
            .ok_or_else(|| anyhow!("chainId not a hex string"))?;
        u64::from_str_radix(s.trim_start_matches("0x"), 16).context("parse chainId")
    }

    /// Sign a zero-fee legacy tx and submit it; returns the tx-hash string.
    async fn send_signed(&self, key: &str, tx: TxLegacy) -> Result<String> {
        let raw = sign_legacy(key, tx)?;
        let r = self
            .call(
                "eth_sendRawTransaction",
                json!([format!("0x{}", hex::encode(&raw))]),
            )
            .await?;
        r.as_str()
            .map(str::to_string)
            .ok_or_else(|| anyhow!("sendRawTransaction did not return a hash: {r}"))
    }

    /// Poll `eth_getTransactionReceipt` until it appears or the timeout elapses.
    async fn wait_for_receipt(&self, tx_hash: &str) -> Result<Value> {
        for _ in 0..RECEIPT_TRIES {
            let r = self
                .call("eth_getTransactionReceipt", json!([tx_hash]))
                .await?;
            if !r.is_null() {
                return Ok(r);
            }
            tokio::time::sleep(RECEIPT_INTERVAL).await;
        }
        Err(anyhow!(
            "no receipt for {tx_hash} within timeout — the node drops invalid txs \
             silently after returning the hash; check nonce / gas / chain_id"
        ))
    }

    /// Deploy creation `bytecode` from `key`'s account at `nonce`; returns the
    /// created contract address.
    pub async fn deploy(&self, key: &str, bytecode: Bytes, nonce: u64) -> Result<Address> {
        let tx = TxLegacy {
            chain_id: Some(CHAIN_ID),
            nonce,
            gas_price: 0,
            gas_limit: DEPLOY_GAS_LIMIT,
            to: TxKind::Create,
            value: U256::ZERO,
            input: bytecode,
        };
        let tx_hash = self.send_signed(key, tx).await?;
        let receipt = self.wait_for_receipt(&tx_hash).await?;
        let status = receipt["status"].as_str().unwrap_or("0x0");
        if status != "0x1" {
            return Err(anyhow!("deploy reverted (status {status}): {receipt}"));
        }
        receipt["contractAddress"]
            .as_str()
            .ok_or_else(|| anyhow!("create receipt has no contractAddress: {receipt}"))?
            .parse::<Address>()
            .context("parse contractAddress")
    }

    /// Read-only `eth_call` against `to` with `data`; returns the raw output.
    pub async fn eth_call(&self, to: Address, data: Vec<u8>) -> Result<Vec<u8>> {
        let r = self
            .call(
                "eth_call",
                json!([
                    { "to": format!("{to}"), "data": format!("0x{}", hex::encode(&data)) },
                    "latest"
                ]),
            )
            .await?;
        let s = r
            .as_str()
            .ok_or_else(|| anyhow!("eth_call result not a string: {r}"))?;
        hex::decode(s.trim_start_matches("0x")).context("decode eth_call output")
    }
}

/// Sign a legacy transaction with a hex private key, returning EIP-2718 raw
/// bytes ready for `eth_sendRawTransaction`. Replicates the node e2e recipe.
pub fn sign_legacy(key: &str, tx: TxLegacy) -> Result<Vec<u8>> {
    let signer: PrivateKeySigner = key.parse().context("parse dev private key")?;
    let sig = signer
        .sign_hash_sync(&tx.signature_hash())
        .context("sign tx")?;
    let envelope: TxEnvelope = tx.into_signed(sig).into();
    let mut raw = Vec::new();
    envelope.encode_2718(&mut raw);
    Ok(raw)
}
