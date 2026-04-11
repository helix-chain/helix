// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @notice Simple safe ERC-20 token
contract SafeToken {
    string public name = "Safe Token";
    string public symbol = "SAFE";
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    /// @notice Transfer tokens to recipient
    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    /// @notice Approve spender for amount
    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }
}
