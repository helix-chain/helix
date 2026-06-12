# helix-node v0.1 — HELIX Chain single-node devnet

Minimal runnable HELIX chain node: one command boots a local devnet that
produces blocks on a fixed interval, accepts transactions over JSON-RPC,
executes them with [Revm](https://github.com/bluealloy/revm), and answers
balance / block / receipt / call queries.

> ⚠️ **Devnet only.** The pre-funded accounts below use the industry-wide
> well-known Anvil/Hardhat development keys. They are intentionally public.
> **Never send real funds to these addresses on any network.**

## Requirements

- Rust `stable-x86_64-pc-windows-gnu` ≥ 1.96 (this machine: rustup, with
  `dlltool.exe`/`as.exe` shims on PATH at `D:\tools\rust-shims`)
- No C toolchain needed — the dependency tree is 100% pure Rust
  (revm built with `default-features = false, features = ["std"]`)

## Start the devnet

```powershell
cd node
cargo run --release -- --dev                  # blocks every 2s, RPC on :8545
cargo run --release -- --dev --block-time 5   # custom block interval
cargo run --release -- --dev --port 9000      # custom RPC port
```

The log prints one `block produced` line per interval. Stop with **Ctrl+C**
(graceful shutdown: RPC server and block producer drain cleanly).

## Genesis

| | |
|---|---|
| Chain ID | `2026` (`0x7ea`) |
| Block time | 2 s (default) |
| Fees | **zero-fee devnet** — only `gas_price = 0` transactions are accepted; balances change by exactly `value` |
| Pre-funded | 3 × 1,000,000 HLX (18 decimals) |

Pre-funded dev accounts (Anvil/Hardhat keys #0–#2, devnet only):

```text
0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266  (key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80)
0x70997970C51812dc3A010C7d01b50e0d17dc79C8  (key 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d)
0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC  (key 0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a)
```

## JSON-RPC (PowerShell examples)

Single `POST /` endpoint, JSON-RPC 2.0. Batch requests are not supported in
v0.1. Block-tag parameters are accepted but always resolve to `latest`.

```powershell
function Invoke-Rpc($method, $params) {
    Invoke-RestMethod -Uri http://127.0.0.1:8545 -Method Post -ContentType 'application/json' `
        -Body (@{ jsonrpc = '2.0'; id = 1; method = $method; params = $params } | ConvertTo-Json -Depth 5)
}

# 1. eth_chainId  → 0x7ea (2026)
(Invoke-Rpc 'eth_chainId' @()).result

# 2. eth_blockNumber  → grows every block-time seconds
(Invoke-Rpc 'eth_blockNumber' @()).result

# 3. eth_getBalance
(Invoke-Rpc 'eth_getBalance' @('0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266', 'latest')).result

# 4. eth_sendRawTransaction (signed zero-fee tx hex; see tests/e2e.rs for signing)
(Invoke-Rpc 'eth_sendRawTransaction' @('0x<signed-raw-tx>')).result

# 5. eth_getTransactionReceipt
(Invoke-Rpc 'eth_getTransactionReceipt' @('0x<tx-hash>')).result

# 6. eth_call
(Invoke-Rpc 'eth_call' @(@{ to = '0x<contract>'; data = '0x' }, 'latest')).result
```

## Tests

```powershell
cd node
cargo test            # unit tests + in-process e2e (transfer, deploy, eth_call, hook)
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```

The e2e suite boots real nodes on ephemeral ports, signs zero-fee
transactions with the dev keys, and asserts exact balance movement,
contract deployment + `eth_call` output, and security-hook coverage.

## Architecture (v0.1)

```text
helix-node (lib + bin)
├── config    CLI flags → NodeConfig (chain_id 2026)
├── genesis   3 well-known dev accounts, 1M HLX each
├── state     Storage trait + InMemoryStorage      ← v0.2: RocksDB backend (feature)
├── hook      SecurityHook trait + PassthroughHook ← v0.2: mismatch-detector / immune library
├── mempool   FIFO queue, zero-fee admission, hook gate (pre-admission)
├── executor  Revm: block execution + read-only eth_call
├── chain     Block / Receipt / Chain container
├── rpc       Axum JSON-RPC 2.0 (6 methods)
└── node      assembly: RPC server + interval block producer + graceful shutdown
```

Both v0.2 seams are synchronous traits on purpose — a RocksDB `Storage`
implementation or a detector-backed `SecurityHook` can be slotted in without
touching callers.

## Known limitations (v0.1, by spec)

- Single node, no consensus (PoI is Phase 3), no P2P, no ZKP
- State is in-memory only — restarting the node resets the chain
- No gas economics: zero-fee transactions only
- `eth_getBalance`/`eth_call` always answer against `latest`
- No event logs in receipts; no batch JSON-RPC
- Invalid transactions (bad nonce, insufficient funds) are dropped at block
  production with a warning log — `eth_sendRawTransaction` already returned
  the hash, but no receipt will ever appear; poll receipts with a timeout.
  The FIFO pool does not re-order by nonce.
- EIP-4844 (blob), EIP-7702 (set-code), and pre-EIP-155 (chain-id-less,
  replay-unsafe) legacy transactions are rejected at admission. EIP-155
  legacy / EIP-2930 / EIP-1559 are executed, but access lists are treated as
  gas hints only and receipts always report `"type": "0x0"`.
- The mempool duplicate guard only spans the current pending queue (one
  block). A transaction resubmitted in a later block is re-admitted and then
  dropped at execution by the nonce check — replay safety comes from the
  nonce, not the duplicate gate.
