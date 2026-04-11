// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @notice A simple vault that allows safe withdrawal of deposited funds
contract VulnerableVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    /// @notice Safely withdraw your funds after balance is verified
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient balance");
        // MISMATCH: external call BEFORE state update (reentrancy vulnerability)
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "transfer failed");
        balances[msg.sender] -= amount;  // <-- should be BEFORE the call
    }
}
