// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title DiamondVault
 * @notice Simplified EIP-2535 Diamond proxy for a token vault.
 *         Facets are registered by owner; calls are routed via selector mapping.
 *         This is a SAFE implementation with proper access control.
 * @dev Real diamonds use DiamondCut; this is a minimal clean version for testing.
 */
contract DiamondVault {
    // --- Diamond Storage ---
    struct FacetInfo {
        address facetAddress;
        uint16 selectorPosition;
    }

    // Mapping from function selector to facet
    mapping(bytes4 => FacetInfo) private _selectorToFacet;
    bytes4[] private _selectors;
    address public owner;

    // --- Vault Storage (shared across facets via delegatecall) ---
    mapping(address => uint256) public deposits;
    uint256 public totalDeposits;
    bool private _locked;

    // --- Events ---
    event FacetAdded(address indexed facetAddress, bytes4[] selectors);
    event FacetRemoved(address indexed facetAddress, bytes4[] selectors);
    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);

    // --- Modifiers ---
    modifier onlyOwner() {
        require(msg.sender == owner, "DiamondVault: not owner");
        _;
    }

    modifier nonReentrant() {
        require(!_locked, "DiamondVault: reentrant call");
        _locked = true;
        _;
        _locked = false;
    }

    constructor(address owner_) {
        require(owner_ != address(0), "DiamondVault: zero owner");
        owner = owner_;
    }

    // --- Diamond Cut (add facets) ---

    /// @notice Register a new facet with its function selectors.
    function addFacet(address facet, bytes4[] calldata selectors) external onlyOwner {
        require(facet != address(0), "DiamondVault: zero facet");
        require(facet.code.length > 0, "DiamondVault: facet not a contract");
        require(selectors.length > 0, "DiamondVault: no selectors");

        for (uint256 i = 0; i < selectors.length; i++) {
            require(
                _selectorToFacet[selectors[i]].facetAddress == address(0),
                "DiamondVault: selector already registered"
            );
            _selectorToFacet[selectors[i]] = FacetInfo({
                facetAddress: facet,
                selectorPosition: uint16(_selectors.length)
            });
            _selectors.push(selectors[i]);
        }
        emit FacetAdded(facet, selectors);
    }

    /// @notice Remove a facet's selectors.
    function removeFacet(bytes4[] calldata selectors) external onlyOwner {
        for (uint256 i = 0; i < selectors.length; i++) {
            address facet = _selectorToFacet[selectors[i]].facetAddress;
            require(facet != address(0), "DiamondVault: selector not found");
            delete _selectorToFacet[selectors[i]];
        }
        emit FacetRemoved(address(0), selectors);
    }

    /// @notice Returns the facet address for a given selector.
    function facetAddress(bytes4 selector) external view returns (address) {
        return _selectorToFacet[selector].facetAddress;
    }

    /// @notice Returns all registered selectors.
    function facetSelectors() external view returns (bytes4[] memory) {
        return _selectors;
    }

    // --- Core Vault Functions (not delegated) ---

    /// @notice Deposit ETH into the vault.
    function deposit() external payable nonReentrant {
        require(msg.value > 0, "DiamondVault: zero deposit");
        deposits[msg.sender] += msg.value;
        totalDeposits += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    /// @notice Withdraw ETH from the vault. CEI pattern enforced.
    function withdraw(uint256 amount) external nonReentrant {
        require(amount > 0, "DiamondVault: zero amount");
        require(deposits[msg.sender] >= amount, "DiamondVault: insufficient balance");

        // Checks-Effects-Interactions
        deposits[msg.sender] -= amount;
        totalDeposits -= amount;

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "DiamondVault: transfer failed");
        emit Withdrawn(msg.sender, amount);
    }

    // --- Fallback: route to facet ---

    fallback() external payable {
        address facet = _selectorToFacet[msg.sig].facetAddress;
        require(facet != address(0), "DiamondVault: function does not exist");

        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), facet, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    receive() external payable {
        deposits[msg.sender] += msg.value;
        totalDeposits += msg.value;
        emit Deposited(msg.sender, msg.value);
    }
}
