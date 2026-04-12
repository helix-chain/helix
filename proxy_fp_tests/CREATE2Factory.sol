// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title CREATE2Factory
 * @notice Deterministic contract deployment using CREATE2.
 *         Allows pre-computing deployment addresses before deployment.
 *         This is a SAFE, standard pattern used by Uniswap, Safe, etc.
 * @dev Uses assembly for CREATE2 opcode. Access controlled deployment.
 */
contract CREATE2Factory {
    address public owner;
    mapping(address => bool) public deployers;
    mapping(address => bool) public deployed;

    event ContractDeployed(address indexed deployedAddress, bytes32 indexed salt);
    event DeployerAdded(address indexed deployer);
    event DeployerRemoved(address indexed deployer);

    modifier onlyAuthorized() {
        require(
            msg.sender == owner || deployers[msg.sender],
            "CREATE2Factory: not authorized"
        );
        _;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "CREATE2Factory: not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /// @notice Deploy a contract using CREATE2.
    /// @param salt Unique salt for deterministic address.
    /// @param bytecode The contract creation bytecode.
    /// @return addr The address of the deployed contract.
    function deploy(bytes32 salt, bytes memory bytecode)
        external
        onlyAuthorized
        returns (address addr)
    {
        require(bytecode.length > 0, "CREATE2Factory: empty bytecode");

        assembly {
            addr := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
        }
        require(addr != address(0), "CREATE2Factory: deployment failed");
        require(!deployed[addr], "CREATE2Factory: already deployed");

        deployed[addr] = true;
        emit ContractDeployed(addr, salt);
    }

    /// @notice Deploy a contract with constructor arguments.
    /// @param salt Unique salt.
    /// @param bytecode Contract creation bytecode.
    /// @param constructorArgs ABI-encoded constructor arguments.
    /// @return addr The deployed contract address.
    function deployWithArgs(
        bytes32 salt,
        bytes memory bytecode,
        bytes memory constructorArgs
    ) external onlyAuthorized returns (address addr) {
        bytes memory creationCode = abi.encodePacked(bytecode, constructorArgs);
        require(creationCode.length > 0, "CREATE2Factory: empty bytecode");

        assembly {
            addr := create2(0, add(creationCode, 0x20), mload(creationCode), salt)
        }
        require(addr != address(0), "CREATE2Factory: deployment failed");

        deployed[addr] = true;
        emit ContractDeployed(addr, salt);
    }

    /// @notice Pre-compute the address of a CREATE2 deployment.
    /// @param salt The salt to use.
    /// @param bytecodeHash The keccak256 of the creation bytecode.
    /// @return The predicted address.
    function computeAddress(bytes32 salt, bytes32 bytecodeHash)
        external
        view
        returns (address)
    {
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

    /// @notice Add an authorized deployer.
    function addDeployer(address deployer) external onlyOwner {
        require(deployer != address(0), "CREATE2Factory: zero address");
        deployers[deployer] = true;
        emit DeployerAdded(deployer);
    }

    /// @notice Remove an authorized deployer.
    function removeDeployer(address deployer) external onlyOwner {
        deployers[deployer] = false;
        emit DeployerRemoved(deployer);
    }

    /// @notice Transfer ownership.
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "CREATE2Factory: zero owner");
        owner = newOwner;
    }
}
