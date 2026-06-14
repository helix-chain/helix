// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @title  WrappedPoint — HPL spike test point token (wTEST)
/// @notice LOCAL HPL SPIKE / DEMO ONLY. NOT a production contract standard:
///         it deliberately does not use OpenZeppelin, is unaudited, and
///         implements only the minimal surface the spike needs — **deploy +
///         balanceOf**. Do not deploy to any real network.
/// @dev    Scope is intentionally limited to deploy + balance. There is NO
///         mint / transfer / burn / issue / redeem / ledger / transferable-
///         point capability: balances are fixed once in the constructor and
///         are immutable thereafter, so the deployed surface matches the
///         spike's documented scope exactly (no scope drift). Any such
///         capability belongs to a later, separately-reviewed HPL MVP — not
///         this spike.
///
///         Not connected to any real loyalty points, real payments, or HLX
///         fees. Unrelated to any HLX token sale. No regulatory claim is made
///         by this code — classification of any real point/value instrument is
///         a matter for qualified counsel, not this demo.
contract WrappedPoint {
    string public constant name = "HPL Test Point";
    string public constant symbol = "wTEST";
    uint8 public constant decimals = 0;

    uint256 public totalSupply;
    mapping(address => uint256) private _balances;

    /// @dev Assigns a fixed initial supply to the deployer so a fresh deploy is
    ///      immediately readable via `balanceOf` — the spike exercises only
    ///      `deploy` then `balance <deployer>`, with no separate mint tx. This
    ///      constructor is the sole code path that ever writes a balance.
    constructor() {
        uint256 initial = 1_000_000;
        totalSupply = initial;
        _balances[msg.sender] = initial;
    }

    /// @notice The only externally callable function: read an account's balance.
    function balanceOf(address account) external view returns (uint256) {
        return _balances[account];
    }
}
