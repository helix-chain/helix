// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title TransparentProxy
 * @notice EIP-1967 compliant transparent proxy pattern.
 *         Admin calls go to proxy logic; non-admin calls delegatecall to implementation.
 *         This is a SAFE, standard pattern used by OpenZeppelin, Aave, Compound, etc.
 * @dev Storage slots follow EIP-1967 to avoid collisions.
 */
contract TransparentProxy {
    // EIP-1967 storage slots (computed as keccak256('eip1967.proxy.implementation') - 1)
    bytes32 private constant IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    bytes32 private constant ADMIN_SLOT =
        0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;

    event Upgraded(address indexed implementation);
    event AdminChanged(address indexed previousAdmin, address indexed newAdmin);

    modifier onlyAdmin() {
        require(msg.sender == _getAdmin(), "TransparentProxy: caller is not admin");
        _;
    }

    constructor(address implementation_, address admin_) {
        require(implementation_ != address(0), "TransparentProxy: zero implementation");
        require(admin_ != address(0), "TransparentProxy: zero admin");
        _setImplementation(implementation_);
        _setAdmin(admin_);
    }

    /// @notice Upgrade the implementation. Only callable by admin.
    function upgradeTo(address newImplementation) external onlyAdmin {
        require(newImplementation != address(0), "TransparentProxy: zero implementation");
        require(newImplementation != _getImplementation(), "TransparentProxy: same implementation");
        _setImplementation(newImplementation);
        emit Upgraded(newImplementation);
    }

    /// @notice Change the admin. Only callable by current admin.
    function changeAdmin(address newAdmin) external onlyAdmin {
        require(newAdmin != address(0), "TransparentProxy: zero admin");
        address previousAdmin = _getAdmin();
        _setAdmin(newAdmin);
        emit AdminChanged(previousAdmin, newAdmin);
    }

    /// @notice Returns the current implementation address.
    function implementation() external view onlyAdmin returns (address) {
        return _getImplementation();
    }

    /// @notice Returns the current admin address.
    function admin() external view onlyAdmin returns (address) {
        return _getAdmin();
    }

    /// @dev Fallback: delegatecall to implementation for non-admin callers.
    fallback() external payable {
        require(msg.sender != _getAdmin(), "TransparentProxy: admin cannot fallback");
        _delegate(_getImplementation());
    }

    receive() external payable {
        require(msg.sender != _getAdmin(), "TransparentProxy: admin cannot fallback");
        _delegate(_getImplementation());
    }

    // --- Internal helpers ---

    function _delegate(address impl) internal {
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    function _getImplementation() internal view returns (address impl) {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            impl := sload(slot)
        }
    }

    function _setImplementation(address newImplementation) internal {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            sstore(slot, newImplementation)
        }
    }

    function _getAdmin() internal view returns (address adm) {
        bytes32 slot = ADMIN_SLOT;
        assembly {
            adm := sload(slot)
        }
    }

    function _setAdmin(address newAdmin) internal {
        bytes32 slot = ADMIN_SLOT;
        assembly {
            sstore(slot, newAdmin)
        }
    }
}
