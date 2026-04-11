"""
HELIX B2′-b — Mainnet Blue-Chip Contract Sources
Version: V1.0.01_202604120027

4 contracts preserving real structural features for FP regression testing.
These are structurally faithful representations, not verbatim copies.

Sources:
  WETH9  — Canonical Wrapped Ether (0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2)
  DAI    — MakerDAO Dai Stablecoin (0x6B175474E89094C44Da98b954EedeAC495271d0F)
  USDT   — Tether USD (0xdAC17F958D2ee523a2206206994597C13D831ec7)
  USDC   — Circle FiatTokenV2_2 (0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48)
"""

# ─────────────────────────────────────────────
# 1. WETH9 — Canonical Wrapped Ether
# Features: deposit/withdraw, payable fallback, .transfer() external call
# Note: .transfer() has 2300 gas stipend (reentrancy-safe in practice)
# ─────────────────────────────────────────────

WETH9_SOURCE = '''
// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.4.18;

/// @title Wrapped Ether standard implementation
contract WETH9 {
    string public name     = "Wrapped Ether";
    string public symbol   = "WETH";
    uint8  public decimals = 18;

    mapping (address => uint)                       public balanceOf;
    mapping (address => mapping (address => uint))  public allowance;

    event Deposit(address indexed dst, uint wad);
    event Withdrawal(address indexed src, uint wad);
    event Approval(address indexed src, address indexed guy, uint wad);
    event Transfer(address indexed src, address indexed dst, uint wad);

    /// @notice Deposit ETH and receive WETH
    function deposit() public payable {
        balanceOf[msg.sender] += msg.value;
        Deposit(msg.sender, msg.value);
    }

    /// @notice Withdraw WETH back to ETH
    function withdraw(uint wad) public {
        require(balanceOf[msg.sender] >= wad);
        balanceOf[msg.sender] -= wad;
        msg.sender.transfer(wad);
        Withdrawal(msg.sender, wad);
    }

    /// @notice Get total WETH supply (equals contract ETH balance)
    function totalSupply() public view returns (uint) {
        return this.balance;
    }

    /// @notice Approve spender for wad amount
    function approve(address guy, uint wad) public returns (bool) {
        allowance[msg.sender][guy] = wad;
        Approval(msg.sender, guy, wad);
        return true;
    }

    /// @notice Transfer wad to dst
    function transfer(address dst, uint wad) public returns (bool) {
        return transferFrom(msg.sender, dst, wad);
    }

    /// @notice Transfer wad from src to dst
    function transferFrom(address src, address dst, uint wad) public returns (bool) {
        require(balanceOf[src] >= wad);

        if (src != msg.sender && allowance[src][msg.sender] != uint(-1)) {
            require(allowance[src][msg.sender] >= wad);
            allowance[src][msg.sender] -= wad;
        }

        balanceOf[src] -= wad;
        balanceOf[dst] += wad;

        Transfer(src, dst, wad);

        return true;
    }

    function() public payable {
        deposit();
    }
}
'''

# ─────────────────────────────────────────────
# 2. DAI — MakerDAO Dai Stablecoin
# Features: auth modifier, permit (EIP-2612), rely/deny governance
# ─────────────────────────────────────────────

DAI_SOURCE = '''
// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.5.12;

/// @title Dai Stablecoin — Multi-Collateral Dai
contract Dai {
    string  public constant name     = "Dai Stablecoin";
    string  public constant symbol   = "DAI";
    string  public constant version  = "1";
    uint8   public constant decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256)                      public balanceOf;
    mapping (address => mapping (address => uint256))  public allowance;
    mapping (address => uint256)                      public nonces;
    mapping (address => uint256)                      public wards;

    event Approval(address indexed src, address indexed guy, uint wad);
    event Transfer(address indexed src, address indexed dst, uint wad);

    // --- Auth ---
    modifier auth {
        require(wards[msg.sender] == 1, "Dai/not-authorized");
        _;
    }

    /// @notice Grant authorization to usr
    function rely(address usr) external auth {
        wards[usr] = 1;
    }

    /// @notice Revoke authorization from usr
    function deny(address usr) external auth {
        wards[usr] = 0;
    }

    // --- ERC20 ---

    /// @notice Transfer tokens to dst
    function transfer(address dst, uint wad) external returns (bool) {
        return transferFrom(msg.sender, dst, wad);
    }

    /// @notice Transfer tokens from src to dst
    function transferFrom(address src, address dst, uint wad) public returns (bool) {
        require(balanceOf[src] >= wad, "Dai/insufficient-balance");
        if (src != msg.sender && allowance[src][msg.sender] != uint256(-1)) {
            require(allowance[src][msg.sender] >= wad, "Dai/insufficient-allowance");
            allowance[src][msg.sender] -= wad;
        }
        balanceOf[src] -= wad;
        balanceOf[dst] += wad;
        emit Transfer(src, dst, wad);
        return true;
    }

    /// @notice Mint new Dai (authorized only)
    function mint(address usr, uint wad) external auth {
        balanceOf[usr] += wad;
        totalSupply    += wad;
        emit Transfer(address(0), usr, wad);
    }

    /// @notice Burn Dai from usr
    function burn(address usr, uint wad) external {
        require(balanceOf[usr] >= wad, "Dai/insufficient-balance");
        if (usr != msg.sender && allowance[usr][msg.sender] != uint256(-1)) {
            require(allowance[usr][msg.sender] >= wad, "Dai/insufficient-allowance");
            allowance[usr][msg.sender] -= wad;
        }
        balanceOf[usr] -= wad;
        totalSupply    -= wad;
        emit Transfer(usr, address(0), wad);
    }

    /// @notice Approve spender
    function approve(address usr, uint wad) external returns (bool) {
        allowance[msg.sender][usr] = wad;
        emit Approval(msg.sender, usr, wad);
        return true;
    }

    // --- EIP-2612 Permit ---

    /// @notice Gasless approval via signed permit
    function permit(
        address holder, address spender,
        uint256 nonce, uint256 expiry,
        bool allowed,
        uint8 v, bytes32 r, bytes32 s
    ) external {
        require(expiry == 0 || now <= expiry, "Dai/permit-expired");
        require(nonce == nonces[holder]++, "Dai/invalid-nonce");
        bytes32 digest = keccak256(abi.encodePacked(
            "\\x19\\x01", holder, spender, nonce, expiry, allowed
        ));
        require(holder == ecrecover(digest, v, r, s), "Dai/invalid-permit");
        uint wad = allowed ? uint256(-1) : 0;
        allowance[holder][spender] = wad;
        emit Approval(holder, spender, wad);
    }
}
'''

# ─────────────────────────────────────────────
# 3. USDT — Tether Token (Legacy Solidity style)
# Features: Ownable, Pausable, fee mechanism, blacklist, old Solidity
# ─────────────────────────────────────────────

USDT_SOURCE = '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.4.17;

/// @title Tether USD Token
contract TetherToken {
    string  public name;
    string  public symbol;
    uint    public decimals;
    uint    public _totalSupply;

    address public owner;
    bool    public paused = false;

    uint public basisPointsRate = 0;
    uint public maximumFee = 0;

    mapping (address => uint)                       public balances;
    mapping (address => mapping (address => uint))  public allowed;
    mapping (address => bool)                       public isBlackListed;

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    modifier whenNotPaused() {
        require(!paused);
        _;
    }

    // --- Owner functions ---

    /// @notice Pause all transfers
    function pause() public onlyOwner {
        paused = true;
    }

    /// @notice Unpause transfers
    function unpause() public onlyOwner {
        paused = false;
    }

    /// @notice Transfer ownership
    function transferOwnership(address newOwner) public onlyOwner {
        if (newOwner != address(0)) {
            owner = newOwner;
        }
    }

    // --- ERC20 with fee ---

    /// @notice Transfer tokens with optional fee deduction
    function transfer(address _to, uint _value) public whenNotPaused {
        require(!isBlackListed[msg.sender]);
        uint fee = (_value * basisPointsRate) / 10000;
        if (fee > maximumFee) {
            fee = maximumFee;
        }
        uint sendAmount = _value - fee;
        balances[msg.sender] -= _value;
        balances[_to] += sendAmount;
        if (fee > 0) {
            balances[owner] += fee;
        }
    }

    /// @notice Transfer tokens from sender with optional fee
    function transferFrom(address _from, address _to, uint _value) public whenNotPaused {
        require(!isBlackListed[_from]);
        require(_value <= allowed[_from][msg.sender]);
        uint fee = (_value * basisPointsRate) / 10000;
        if (fee > maximumFee) {
            fee = maximumFee;
        }
        uint sendAmount = _value - fee;
        balances[_from] -= _value;
        balances[_to] += sendAmount;
        if (fee > 0) {
            balances[owner] += fee;
        }
        allowed[_from][msg.sender] -= _value;
    }

    /// @notice Approve spender
    function approve(address _spender, uint _value) public {
        allowed[msg.sender][_spender] = _value;
    }

    /// @notice Get balance
    function balanceOf(address who) public view returns (uint) {
        return balances[who];
    }

    // --- Supply management ---

    /// @notice Issue new tokens to owner
    function issue(uint amount) public onlyOwner {
        balances[owner] += amount;
        _totalSupply += amount;
    }

    /// @notice Redeem tokens from owner
    function redeem(uint amount) public onlyOwner {
        require(_totalSupply >= amount);
        require(balances[owner] >= amount);
        _totalSupply -= amount;
        balances[owner] -= amount;
    }

    // --- Blacklist ---

    /// @notice Add address to blacklist
    function addBlackList(address _evilUser) public onlyOwner {
        isBlackListed[_evilUser] = true;
    }

    /// @notice Remove address from blacklist
    function removeBlackList(address _clearedUser) public onlyOwner {
        isBlackListed[_clearedUser] = false;
    }

    /// @notice Destroy tokens of blacklisted address
    function destroyBlackFunds(address _blackListedUser) public onlyOwner {
        require(isBlackListed[_blackListedUser]);
        uint dirtyFunds = balances[_blackListedUser];
        balances[_blackListedUser] = 0;
        _totalSupply -= dirtyFunds;
    }

    /// @notice Set fee parameters
    function setParams(uint newBasisPoints, uint newMaxFee) public onlyOwner {
        require(newBasisPoints < 20);
        require(newMaxFee < 50);
        basisPointsRate = newBasisPoints;
        maximumFee = newMaxFee * (10 ** decimals);
    }
}
'''

# ─────────────────────────────────────────────
# 4. USDC — Circle FiatTokenV2_2
# Features: Proxy/implementation pattern, role-based access (minter/pauser/blacklister),
#           initialize(), configureMinter(), multi-modifier stacking
# ─────────────────────────────────────────────

USDC_SOURCE = '''
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.6.12;

/// @title FiatToken V2.2 — USD Coin implementation
/// @notice Implementation contract behind USDC proxy
contract FiatTokenV2_2 {
    string  public name;
    string  public symbol;
    uint8   public decimals;
    uint256 public totalSupply;

    address public owner;
    address public pauser;
    address public blacklister;
    address public masterMinter;

    bool internal _paused;
    bool internal _initialized;

    mapping(address => uint256)                      internal _balances;
    mapping(address => mapping(address => uint256))  internal _allowed;
    mapping(address => bool)                         internal _blacklisted;
    mapping(address => bool)                         internal _minters;
    mapping(address => uint256)                      internal _minterAllowed;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Mint(address indexed minter, address indexed to, uint256 amount);
    event Burn(address indexed burner, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "Ownable: caller is not the owner");
        _;
    }

    modifier onlyMinters() {
        require(_minters[msg.sender], "FiatToken: caller is not a minter");
        _;
    }

    modifier onlyPauser() {
        require(msg.sender == pauser, "FiatToken: caller is not the pauser");
        _;
    }

    modifier whenNotPaused() {
        require(!_paused, "Pausable: paused");
        _;
    }

    modifier notBlacklisted(address account) {
        require(!_blacklisted[account], "Blacklistable: account is blacklisted");
        _;
    }

    // --- Initialization (proxy pattern) ---

    /// @notice Initialize the token (called once via proxy)
    function initialize(
        string memory tokenName,
        string memory tokenSymbol,
        uint8 tokenDecimals,
        address newMasterMinter,
        address newPauser,
        address newBlacklister,
        address newOwner
    ) public {
        require(!_initialized, "FiatToken: contract is already initialized");
        name = tokenName;
        symbol = tokenSymbol;
        decimals = tokenDecimals;
        masterMinter = newMasterMinter;
        pauser = newPauser;
        blacklister = newBlacklister;
        owner = newOwner;
        _initialized = true;
    }

    // --- ERC20 ---

    /// @notice Transfer tokens safely
    function transfer(address to, uint256 value)
        external
        whenNotPaused
        notBlacklisted(msg.sender)
        notBlacklisted(to)
        returns (bool)
    {
        require(to != address(0), "ERC20: transfer to the zero address");
        require(value <= _balances[msg.sender], "ERC20: transfer amount exceeds balance");
        _balances[msg.sender] -= value;
        _balances[to] += value;
        emit Transfer(msg.sender, to, value);
        return true;
    }

    /// @notice Transfer tokens from one address to another
    function transferFrom(address from, address to, uint256 value)
        external
        whenNotPaused
        notBlacklisted(msg.sender)
        notBlacklisted(from)
        notBlacklisted(to)
        returns (bool)
    {
        require(to != address(0), "ERC20: transfer to the zero address");
        require(value <= _balances[from], "ERC20: transfer amount exceeds balance");
        require(value <= _allowed[from][msg.sender], "ERC20: transfer amount exceeds allowance");
        _balances[from] -= value;
        _balances[to] += value;
        _allowed[from][msg.sender] -= value;
        emit Transfer(from, to, value);
        return true;
    }

    /// @notice Approve spender
    function approve(address spender, uint256 value)
        external
        whenNotPaused
        notBlacklisted(msg.sender)
        notBlacklisted(spender)
        returns (bool)
    {
        _allowed[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    // --- Minting / Burning ---

    /// @notice Mint new tokens (authorized minters only)
    function mint(address to, uint256 amount)
        external
        whenNotPaused
        onlyMinters
        notBlacklisted(msg.sender)
        notBlacklisted(to)
        returns (bool)
    {
        require(to != address(0), "FiatToken: mint to the zero address");
        require(amount > 0, "FiatToken: mint amount not greater than 0");
        require(amount <= _minterAllowed[msg.sender], "FiatToken: mint amount exceeds minterAllowance");
        _minterAllowed[msg.sender] -= amount;
        totalSupply += amount;
        _balances[to] += amount;
        emit Mint(msg.sender, to, amount);
        emit Transfer(address(0), to, amount);
        return true;
    }

    /// @notice Burn tokens from caller (minters only)
    function burn(uint256 amount)
        external
        whenNotPaused
        onlyMinters
        notBlacklisted(msg.sender)
    {
        require(amount > 0, "FiatToken: burn amount not greater than 0");
        require(_balances[msg.sender] >= amount, "FiatToken: burn amount exceeds balance");
        totalSupply -= amount;
        _balances[msg.sender] -= amount;
        emit Burn(msg.sender, amount);
        emit Transfer(msg.sender, address(0), amount);
    }

    // --- Minter management ---

    /// @notice Configure a minter with allowance
    function configureMinter(address minter, uint256 minterAllowedAmount)
        external
        returns (bool)
    {
        require(msg.sender == masterMinter, "FiatToken: caller is not the masterMinter");
        _minters[minter] = true;
        _minterAllowed[minter] = minterAllowedAmount;
        return true;
    }

    /// @notice Remove a minter
    function removeMinter(address minter) external returns (bool) {
        require(msg.sender == masterMinter, "FiatToken: caller is not the masterMinter");
        _minters[minter] = false;
        _minterAllowed[minter] = 0;
        return true;
    }

    // --- Blacklist ---

    /// @notice Blacklist an account
    function blacklist(address account) external {
        require(msg.sender == blacklister, "Blacklistable: caller is not the blacklister");
        _blacklisted[account] = true;
    }

    /// @notice Remove account from blacklist
    function unBlacklist(address account) external {
        require(msg.sender == blacklister, "Blacklistable: caller is not the blacklister");
        _blacklisted[account] = false;
    }

    // --- Pause ---

    /// @notice Pause all transfers
    function pause() external onlyPauser {
        _paused = true;
    }

    /// @notice Unpause transfers
    function unpause() external onlyPauser {
        _paused = false;
    }

    // --- Ownership ---

    /// @notice Transfer ownership to new owner
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        owner = newOwner;
    }

    /// @notice Update master minter
    function updateMasterMinter(address newMasterMinter) external onlyOwner {
        require(newMasterMinter != address(0), "FiatToken: new masterMinter is the zero address");
        masterMinter = newMasterMinter;
    }

    /// @notice Update blacklister
    function updateBlacklister(address newBlacklister) external onlyOwner {
        require(newBlacklister != address(0), "FiatToken: new blacklister is the zero address");
        blacklister = newBlacklister;
    }

    /// @notice Update pauser
    function updatePauser(address newPauser) external onlyOwner {
        require(newPauser != address(0), "FiatToken: new pauser is the zero address");
        pauser = newPauser;
    }
}
'''

# ─────────────────────────────────────────────
# Registry (used by runner)
# ─────────────────────────────────────────────

CONTRACTS = {
    "WETH9": WETH9_SOURCE,
    "DAI": DAI_SOURCE,
    "USDT": USDT_SOURCE,
    "USDC": USDC_SOURCE,
}
