# hpl — HELIX Points Layer (spike)

A minimal proof that the HPL **WrappedPoint** (`wTEST`) test-point token can be
deployed to the local HELIX devnet and read back over JSON-RPC.

> **Spike scope = `deploy` + `balance` only.** No issue/redeem/ledger app, no
> real loyalty points, no real payments, no HLX fees, unrelated to any HLX
> token sale. `WrappedPoint.sol` is a **local spike/demo contract, not a
> production standard** (no OpenZeppelin, unaudited). It has **no
> `mint`/`transfer`/`burn`** entrypoint — balances are fixed once in the
> constructor and immutable thereafter, so the deployed contract surface
> matches this scope exactly. Makes no regulatory claim.

## Layout

```
hpl/
├── contracts/WrappedPoint.sol   minimal deploy+balance point token (decimals 0)
└── src/
    ├── bytecode.rs   embedded creation bytecode (solc 0.8.26) + source SHA256
    ├── abi.rs        balanceOf(address) encode / uint256 decode
    ├── client.rs     6-method JSON-RPC client + zero-fee legacy-tx signing
    └── main.rs       CLI: deploy | balance
```

The `constructor` assigns an initial **1,000,000 wTEST** to the deployer (dev
account #0), so a fresh `deploy` is immediately balance-readable — there is no
`mint` function, and balances never change after deployment.

## Run

```powershell
# 1. boot the HELIX devnet (separate terminal), RPC on :8545
cd node
cargo run --release -- --dev

# 2. deploy wTEST → prints the contract address (assumes a fresh devnet, nonce 0)
cd hpl
cargo run -- deploy

# 3. read the deployer's balance (should be 1000000)
cargo run -- balance <contract-address> 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
```

`--rpc <url>` overrides the endpoint; `deploy --nonce <n>` overrides the nonce
(needed if the deployer account already sent transactions on the running node).

## Test

```powershell
cd hpl
cargo test                                  # boots a node in-process, deploys, asserts balance
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```

## Regenerating the bytecode

`src/bytecode.rs` embeds the compiled output so the demo needs no toolchain at
runtime. To rebuild after editing `WrappedPoint.sol`, use a local solc 0.8.26
binary; it is not required at runtime and is not committed:

```powershell
solc --bin --optimize --optimize-runs 200 --metadata-hash none contracts\WrappedPoint.sol
```

Replace `WRAPPED_POINT_CREATION_BYTECODE` and update the SHA256 in the header.
