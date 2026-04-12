// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title MinimalProxyFactory
 * @notice EIP-1167 clone factory. Creates minimal proxy contracts that
 *         delegatecall to a single fixed implementation.
 *         This is a SAFE, gas-efficient pattern used by Pudgy Penguins,
 *         Gnosis Safe, and many NFT collections.
 * @dev The clone bytecode is 45 bytes and costs ~37K gas to deploy.
 */
contract MinimalProxyFactory {
    address public immutable implementation;
    address public owner;
    address[] public clones;

    event CloneCreated(address indexed clone, uint256 index);

    modifier onlyOwner() {
        require(msg.sender == owner, "MinimalProxyFactory: not owner");
        _;
    }

    constructor(address implementation_) {
        require(implementation_ != address(0), "MinimalProxyFactory: zero implementation");
        require(implementation_.code.length > 0, "MinimalProxyFactory: not a contract");
        implementation = implementation_;
        owner = msg.sender;
    }

    /// @notice Create a new EIP-1167 minimal proxy clone.
    /// @return clone The address of the newly created clone.
    function createClone() external returns (address clone) {
        clone = _deployClone(implementation);
        clones.push(clone);
        emit CloneCreated(clone, clones.length - 1);
    }

    /// @notice Create a clone and initialize it.
    /// @param initData ABI-encoded initializer call data.
    /// @return clone The address of the newly created clone.
    function createCloneWithInit(bytes calldata initData) external returns (address clone) {
        clone = _deployClone(implementation);
        clones.push(clone);
        emit CloneCreated(clone, clones.length - 1);

        (bool success, ) = clone.call(initData);
        require(success, "MinimalProxyFactory: initialization failed");
    }

    /// @notice Create a clone using CREATE2 for deterministic address.
    /// @param salt Salt for CREATE2.
    /// @return clone The address of the newly created clone.
    function createCloneDeterministic(bytes32 salt) external returns (address clone) {
        clone = _deployCloneDeterministic(implementation, salt);
        clones.push(clone);
        emit CloneCreated(clone, clones.length - 1);
    }

    /// @notice Predict the address of a deterministic clone.
    function predictDeterministicAddress(bytes32 salt) external view returns (address) {
        bytes32 bytecodeHash = keccak256(_getCloneBytecode(implementation));
        return address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(bytes1(0xff), address(this), salt, bytecodeHash)
                    )
                )
            )
        );
    }

    /// @notice Returns the total number of clones created.
    function cloneCount() external view returns (uint256) {
        return clones.length;
    }

    /// @notice Check if an address is a known clone.
    function isClone(address query) external view returns (bool) {
        for (uint256 i = 0; i < clones.length; i++) {
            if (clones[i] == query) return true;
        }
        return false;
    }

    // --- Internal ---

    function _deployClone(address impl) internal returns (address clone) {
        bytes memory bytecode = _getCloneBytecode(impl);
        assembly {
            clone := create(0, add(bytecode, 0x20), mload(bytecode))
        }
        require(clone != address(0), "MinimalProxyFactory: clone deploy failed");
    }

    function _deployCloneDeterministic(address impl, bytes32 salt)
        internal
        returns (address clone)
    {
        bytes memory bytecode = _getCloneBytecode(impl);
        assembly {
            clone := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
        }
        require(clone != address(0), "MinimalProxyFactory: clone deploy failed");
    }

    /// @dev EIP-1167 minimal proxy bytecode.
    function _getCloneBytecode(address impl) internal pure returns (bytes memory) {
        return abi.encodePacked(
            hex"3d602d80600a3d3981f3363d3d373d3d3d363d73",
            impl,
            hex"5af43d82803e903d91602b57fd5bf3"
        );
    }
}
