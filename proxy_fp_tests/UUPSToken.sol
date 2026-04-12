// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title UUPSToken
 * @notice UUPS (EIP-1822) upgradeable ERC-20 token with proper access control.
 *         Upgrade logic lives in the implementation, not the proxy.
 *         This is a SAFE pattern used by OpenZeppelin UUPS contracts.
 * @dev Uses initializer pattern instead of constructor for proxy compatibility.
 */
contract UUPSToken {
    // EIP-1967 implementation slot
    bytes32 private constant IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    // --- ERC-20 State ---
    string public name;
    string public symbol;
    uint8 public constant decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    // --- Upgrade State ---
    address public owner;
    bool private _initialized;

    // --- Events ---
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Upgraded(address indexed implementation);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    // --- Modifiers ---
    modifier onlyOwner() {
        require(msg.sender == owner, "UUPSToken: caller is not the owner");
        _;
    }

    modifier initializer() {
        require(!_initialized, "UUPSToken: already initialized");
        _initialized = true;
        _;
    }

    /// @notice Initialize the token (called once via proxy).
    function initialize(
        string memory name_,
        string memory symbol_,
        uint256 initialSupply_,
        address owner_
    ) external initializer {
        require(owner_ != address(0), "UUPSToken: zero owner");
        name = name_;
        symbol = symbol_;
        owner = owner_;
        totalSupply = initialSupply_;
        balanceOf[owner_] = initialSupply_;
        emit Transfer(address(0), owner_, initialSupply_);
    }

    // --- ERC-20 Functions ---

    function transfer(address to, uint256 amount) external returns (bool) {
        require(to != address(0), "UUPSToken: transfer to zero address");
        require(balanceOf[msg.sender] >= amount, "UUPSToken: insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(to != address(0), "UUPSToken: transfer to zero address");
        require(balanceOf[from] >= amount, "UUPSToken: insufficient balance");
        require(allowance[from][msg.sender] >= amount, "UUPSToken: insufficient allowance");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }

    // --- UUPS Upgrade ---

    /// @notice Upgrade to a new implementation. Only owner can call.
    function upgradeTo(address newImplementation) external onlyOwner {
        require(newImplementation != address(0), "UUPSToken: zero implementation");
        require(newImplementation.code.length > 0, "UUPSToken: not a contract");
        _setImplementation(newImplementation);
        emit Upgraded(newImplementation);
    }

    /// @notice Transfer ownership.
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "UUPSToken: zero owner");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    function _setImplementation(address newImplementation) internal {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            sstore(slot, newImplementation)
        }
    }
}
