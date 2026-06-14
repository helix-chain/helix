//! Creation bytecode for `hpl/contracts/WrappedPoint.sol` (the wTEST token).
//!
//! Source file  : hpl/contracts/WrappedPoint.sol
//! Source SHA256 : 5D437625893DEBFF49C25328A9B194F05BC088F592B4EE7DBE36AAD4603605DE
//! Compiler      : solc 0.8.26+commit.8a97fa7a.Windows.msvc
//! Command       : solc --bin --optimize --optimize-runs 200 --metadata-hash none WrappedPoint.sol
//!
//! `--metadata-hash none` strips the trailing CBOR metadata / IPFS hash that
//! solc appends by default. That tail embeds source-path- and environment-
//! dependent bytes, so without the flag a fresh recompile differs from this
//! constant in its last ~41 bytes. With the flag, recompiling the unchanged
//! source yields this exact constant on any machine / path (verified identical
//! across two junction paths to the same source).
//!
//! Use a local solc 0.8.26 binary to regenerate this bytecode; the compiler is
//! not required at runtime and is not committed. Recompile with the exact
//! command above, then replace the constant below and update the SHA256.

/// Hex creation bytecode (no `0x` prefix) emitted by the compile documented
/// above. `deploy` sends this as the `TxKind::Create` input. The contract
/// surface is intentionally limited to `deploy` + `balanceOf`: the runtime
/// dispatch table holds only name/symbol/decimals/totalSupply/balanceOf, with
/// no mint/transfer/burn selector (re-verify with the compile command above).
pub const WRAPPED_POINT_CREATION_BYTECODE: &str = "6080604052348015600e575f80fd5b50620f42405f81815533815260016020526040902055610186806100315f395ff3fe608060405234801561000f575f80fd5b5060043610610055575f3560e01c806306fdde031461005957806318160ddd1461009c578063313ce567146100b257806370a08231146100cb57806395d89b41146100f3575b5f80fd5b6100866040518060400160405280600e81526020016d1214130815195cdd08141bda5b9d60921b81525081565b6040516100939190610117565b60405180910390f35b6100a45f5481565b604051908152602001610093565b6100b95f81565b60405160ff9091168152602001610093565b6100a46100d936600461014c565b6001600160a01b03165f9081526001602052604090205490565b610086604051806040016040528060058152602001641dd51154d560da1b81525081565b602081525f82518060208401528060208501604085015e5f604082850101526040601f19601f83011684010191505092915050565b5f6020828403121561015c575f80fd5b81356001600160a01b0381168114610172575f80fd5b939250505056fea164736f6c634300081a000a";
