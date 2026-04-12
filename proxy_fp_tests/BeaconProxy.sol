// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title UpgradeableBeacon
 * @notice Beacon contract that stores a single implementation address.
 *         Multiple BeaconProxy instances point to this beacon.
 *         Only owner can upgrade. Standard OpenZeppelin pattern.
 */
contract UpgradeableBeacon {
    address public implementation;
    address public owner;

    event Upgraded(address indexed implementation);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    modifier onlyOwner() {
        require(msg.sender == owner, "UpgradeableBeacon: caller is not the owner");
        _;
    }

    constructor(address implementation_, address owner_) {
        require(implementation_ != address(0), "UpgradeableBeacon: zero implementation");
        require(implementation_.code.length > 0, "UpgradeableBeacon: not a contract");
        require(owner_ != address(0), "UpgradeableBeacon: zero owner");
        implementation = implementation_;
        owner = owner_;
    }

    /// @notice Upgrade the implementation stored in the beacon.
    function upgradeTo(address newImplementation) external onlyOwner {
        require(newImplementation != address(0), "UpgradeableBeacon: zero implementation");
        require(newImplementation.code.length > 0, "UpgradeableBeacon: not a contract");
        require(newImplementation != implementation, "UpgradeableBeacon: same implementation");
        implementation = newImplementation;
        emit Upgraded(newImplementation);
    }

    /// @notice Transfer ownership of the beacon.
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "UpgradeableBeacon: zero owner");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
}

/**
 * @title BeaconProxy
 * @notice Proxy that reads its implementation from an UpgradeableBeacon.
 *         All calls are delegated to the implementation returned by the beacon.
 *         This is a SAFE pattern — upgrade control is centralized at the beacon.
 */
contract BeaconProxy {
    // EIP-1967 beacon slot: keccak256('eip1967.proxy.beacon') - 1
    bytes32 private constant BEACON_SLOT =
        0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50;

    event BeaconUpgraded(address indexed beacon);

    constructor(address beacon_, bytes memory data_) {
        require(beacon_ != address(0), "BeaconProxy: zero beacon");
        require(beacon_.code.length > 0, "BeaconProxy: beacon not a contract");
        _setBeacon(beacon_);
        emit BeaconUpgraded(beacon_);

        if (data_.length > 0) {
            address impl = UpgradeableBeacon(beacon_).implementation();
            (bool success, ) = impl.delegatecall(data_);
            require(success, "BeaconProxy: initialization failed");
        }
    }

    fallback() external payable {
        address beacon;
        bytes32 slot = BEACON_SLOT;
        assembly {
            beacon := sload(slot)
        }
        address impl = UpgradeableBeacon(beacon).implementation();

        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    receive() external payable {}

    function _setBeacon(address beacon_) internal {
        bytes32 slot = BEACON_SLOT;
        assembly {
            sstore(slot, beacon_)
        }
    }
}
