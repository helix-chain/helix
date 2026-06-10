//! Minimal JSON-RPC 2.0 surface (spec §1): eth_chainId, eth_blockNumber,
//! eth_getBalance, eth_sendRawTransaction, eth_getTransactionReceipt, eth_call.
//!
//! Single POST endpoint, no batch support (documented in node/README.md).

use std::sync::Arc;

use alloy_consensus::TxEnvelope;
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::{Address, B256, Bytes, U256};
use axum::routing::post;
use axum::{Json, Router, extract::State};
use serde_json::{Value, json};
use tokio::sync::Mutex;

use crate::chain::{Chain, Receipt};
use crate::executor;
use crate::mempool::Mempool;

#[derive(Clone)]
pub struct AppState {
    pub chain: Arc<Mutex<Chain>>,
    pub mempool: Arc<Mutex<Mempool>>,
}

pub fn router(chain: Arc<Mutex<Chain>>, mempool: Arc<Mutex<Mempool>>) -> Router {
    Router::new()
        .route("/", post(handle))
        .with_state(AppState { chain, mempool })
}

// --- JSON-RPC plumbing ----------------------------------------------------

fn ok(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn err(id: Value, code: i64, message: impl Into<String>) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message.into() } })
}

const INVALID_PARAMS: i64 = -32602;
const METHOD_NOT_FOUND: i64 = -32601;
const SERVER_ERROR: i64 = -32000;

fn hex_u64(value: u64) -> String {
    format!("0x{value:x}")
}

fn hex_u256(value: U256) -> String {
    format!("0x{value:x}")
}

fn parse_address(value: &Value) -> Result<Address, String> {
    value
        .as_str()
        .ok_or_else(|| "expected hex string".to_string())?
        .parse::<Address>()
        .map_err(|e| format!("invalid address: {e}"))
}

fn parse_bytes(value: &Value) -> Result<Bytes, String> {
    let s = value
        .as_str()
        .ok_or_else(|| "expected hex string".to_string())?;
    let raw = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(raw)
        .map(Bytes::from)
        .map_err(|e| format!("invalid hex: {e}"))
}

fn parse_b256(value: &Value) -> Result<B256, String> {
    value
        .as_str()
        .ok_or_else(|| "expected hex string".to_string())?
        .parse::<B256>()
        .map_err(|e| format!("invalid hash: {e}"))
}

fn parse_u256(value: &Value) -> Result<U256, String> {
    let s = value
        .as_str()
        .ok_or_else(|| "expected hex string".to_string())?;
    U256::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16)
        .map_err(|e| format!("invalid quantity: {e}"))
}

fn receipt_json(receipt: &Receipt) -> Value {
    json!({
        "transactionHash": format!("{}", receipt.tx_hash),
        "transactionIndex": hex_u64(receipt.transaction_index),
        "blockNumber": hex_u64(receipt.block_number),
        "blockHash": format!("{}", receipt.block_hash),
        "from": format!("{}", receipt.from),
        "to": receipt.to.map(|a| format!("{a}")),
        "contractAddress": receipt.contract_address.map(|a| format!("{a}")),
        "gasUsed": hex_u64(receipt.gas_used),
        "cumulativeGasUsed": hex_u64(receipt.gas_used),
        "status": hex_u64(receipt.status),
        "logs": [],
        "logsBloom": format!("0x{}", "00".repeat(256)),
        "type": "0x0",
        "effectiveGasPrice": "0x0",
    })
}

// --- Handler ----------------------------------------------------------------

async fn handle(State(state): State<AppState>, Json(req): Json<Value>) -> Json<Value> {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = req.get("method").and_then(Value::as_str).unwrap_or("");
    let params = req
        .get("params")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let response = match method {
        "eth_chainId" => {
            let chain = state.chain.lock().await;
            ok(id, json!(hex_u64(chain.chain_id)))
        }
        "eth_blockNumber" => {
            let chain = state.chain.lock().await;
            ok(id, json!(hex_u64(chain.head().number)))
        }
        "eth_getBalance" => match params.first().map(parse_address) {
            Some(Ok(addr)) => {
                // Block tag (params[1]) accepted but only "latest" semantics in v0.1.
                let chain = state.chain.lock().await;
                ok(id, json!(hex_u256(chain.balance_of(&addr))))
            }
            Some(Err(e)) => err(id, INVALID_PARAMS, e),
            None => err(id, INVALID_PARAMS, "missing address param"),
        },
        "eth_sendRawTransaction" => match params.first().map(parse_bytes) {
            Some(Ok(raw)) => match TxEnvelope::decode_2718(&mut raw.as_ref()) {
                Ok(envelope) => {
                    let mut pool = state.mempool.lock().await;
                    match pool.admit(envelope) {
                        Ok(hash) => ok(id, json!(format!("{hash}"))),
                        Err(e) => err(id, SERVER_ERROR, e.to_string()),
                    }
                }
                Err(e) => err(id, INVALID_PARAMS, format!("tx decode failed: {e}")),
            },
            Some(Err(e)) => err(id, INVALID_PARAMS, e),
            None => err(id, INVALID_PARAMS, "missing raw tx param"),
        },
        "eth_getTransactionReceipt" => match params.first().map(parse_b256) {
            Some(Ok(hash)) => {
                let chain = state.chain.lock().await;
                match chain.receipts.get(&hash) {
                    Some(receipt) => ok(id, receipt_json(receipt)),
                    None => ok(id, Value::Null),
                }
            }
            Some(Err(e)) => err(id, INVALID_PARAMS, e),
            None => err(id, INVALID_PARAMS, "missing tx hash param"),
        },
        "eth_call" => {
            let Some(call_obj) = params.first().and_then(Value::as_object) else {
                return Json(err(id, INVALID_PARAMS, "missing call object"));
            };
            let to = match call_obj.get("to").map(parse_address) {
                Some(Ok(addr)) => addr,
                _ => return Json(err(id, INVALID_PARAMS, "missing/invalid 'to'")),
            };
            let from = match call_obj.get("from").map(parse_address) {
                Some(Ok(addr)) => addr,
                Some(Err(e)) => return Json(err(id, INVALID_PARAMS, e)),
                None => Address::ZERO,
            };
            let data = match call_obj
                .get("data")
                .or_else(|| call_obj.get("input"))
                .map(parse_bytes)
            {
                Some(Ok(bytes)) => bytes,
                Some(Err(e)) => return Json(err(id, INVALID_PARAMS, e)),
                None => Bytes::new(),
            };
            let value = match call_obj.get("value").map(parse_u256) {
                Some(Ok(v)) => v,
                Some(Err(e)) => return Json(err(id, INVALID_PARAMS, e)),
                None => U256::ZERO,
            };
            let chain = state.chain.lock().await;
            match executor::call(&chain, from, to, data, value) {
                Ok(output) => ok(id, json!(format!("0x{}", hex::encode(&output)))),
                Err(e) => err(id, SERVER_ERROR, e.to_string()),
            }
        }
        _ => err(id, METHOD_NOT_FOUND, format!("method '{method}' not found")),
    };

    Json(response)
}
