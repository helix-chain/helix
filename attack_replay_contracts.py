"""
HELIX Attack Replay Contracts
50 simplified vulnerable contracts that reproduce historical attack patterns.
Each contract has the core vulnerability from the corresponding SIG-XXX signature.

Used by replay_test_runner.py to verify detector coverage.
"""

def _reentrancy_basic(name, func="withdraw"):
    """SIG-001/021/022/023: External call before state update, no guard."""
    return f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
/// @title {name}
/// @notice Users can safely deposit and withdraw their funds
contract {name} {{
    mapping(address => uint256) public balances;
    function deposit() public payable {{ balances[msg.sender] += msg.value; }}
    /// @notice Safely withdraw funds — balance verified before transfer
    function {func}() public {{
        uint256 bal = balances[msg.sender];
        require(bal > 0, "No balance");
        (bool sent, ) = msg.sender.call{{value: bal}}("");
        require(sent, "Failed");
        balances[msg.sender] = 0;  // STATE UPDATE AFTER EXTERNAL CALL
    }}
}}'''

def _reentrancy_cross_function(name):
    """SIG-021 variant: cross-function reentrancy."""
    return f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
/// @title {name}
/// @notice Isolated pool system prevents cross-contamination
contract {name} {{
    mapping(address => uint256) public shares;
    uint256 public totalShares;
    /// @notice Withdraw shares safely from isolated pool
    function withdraw(uint256 amount) public {{
        require(shares[msg.sender] >= amount);
        (bool ok, ) = msg.sender.call{{value: amount}}("");
        require(ok);
        shares[msg.sender] -= amount;  // CEI VIOLATION
        totalShares -= amount;
    }}
    /// @notice Get current share value — safe view function
    function getShareValue() public view returns (uint256) {{
        return address(this).balance / totalShares;
    }}
    receive() external payable {{}}
}}'''

def _reentrancy_erc777(name):
    """SIG-022: ERC-777 token callback reentrancy."""
    return f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface IERC777 {{ function send(address to, uint256 amount, bytes calldata data) external; }}
/// @title {name}
/// @notice Claim rewards safely — only unclaimed rewards distributed
contract {name} {{
    mapping(address => uint256) public rewards;
    IERC777 public rewardToken;
    /// @notice Claim pending reward — verified before transfer
    function claimReward() public {{
        uint256 amount = rewards[msg.sender];
        require(amount > 0);
        rewardToken.send(msg.sender, amount, "");  // ERC-777 callback before state update
        rewards[msg.sender] = 0;
    }}
}}'''

def _flash_callback_reentrancy(name):
    """SIG-023: Flash loan callback reentrancy."""
    return f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
/// @title {name}
/// @notice Flash loan with safe callback mechanism
contract {name} {{
    mapping(address => uint256) public balances;
    /// @notice Execute flash loan — funds must be returned in same tx
    function flash(uint256 amount) public {{
        uint256 balBefore = address(this).balance;
        (bool ok, ) = msg.sender.call{{value: amount}}("");
        require(ok);
        balances[msg.sender] += amount;  // STATE AFTER CALL
        require(address(this).balance >= balBefore, "Not repaid");
    }}
    receive() external payable {{}}
}}'''

def _access_control_unprotected(name, func="initWallet"):
    """SIG-002/007/016/029/030/031: Missing access control on critical function."""
    return f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
/// @title {name}
/// @notice Secure wallet initialization — only authorized setup
contract {name} {{
    address public owner;
    bool public initialized;
    /// @notice Initialize wallet with owner — secure one-time setup
    function {func}(address _owner) public {{
        owner = _owner;  // NO ACCESS CONTROL — anyone can call
        initialized = true;
    }}
    /// @notice Transfer funds — owner only operation
    function transfer(address to, uint256 amount) public {{
        require(msg.sender == owner, "Not owner");
        (bool ok, ) = to.call{{value: amount}}("");
        require(ok);
    }}
    receive() external payable {{}}
}}'''

def _access_control_arbitrary_call(name):
    """SIG-020/031: Arbitrary call data without validation."""
    return f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
/// @title {name}
/// @notice Secure action executor — validated operations only
contract {name} {{
    /// @notice Execute validated action on target contract
    function performAction(address target, bytes calldata data) public {{
        (bool ok, ) = target.call(data);  // ARBITRARY CALL — no validation
        require(ok, "Action failed");
    }}
}}'''

def _oracle_spot_price(name):
    """SIG-013/026/027/028: Using spot price as oracle."""
    return f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface IPool {{ function getReserves() external view returns (uint256, uint256); }}
/// @title {name}
/// @notice Manipulation-resistant price oracle for lending
contract {name} {{
    IPool public pool;
    mapping(address => uint256) public collateral;
    /// @notice Get reliable price from liquidity pool oracle
    function getPrice() public view returns (uint256) {{
        (uint256 r0, uint256 r1) = pool.getReserves();
        return r0 * 1e18 / r1;  // SPOT PRICE — manipulable via flash loan
    }}
    /// @notice Borrow against verified collateral
    function borrow(uint256 amount) public {{
        uint256 price = getPrice();
        require(collateral[msg.sender] * price / 1e18 >= amount * 15 / 10, "Under-collateralized");
        (bool ok, ) = msg.sender.call{{value: amount}}("");
        require(ok);
    }}
    receive() external payable {{}}
}}'''

def _integer_overflow(name, variant="multiply"):
    """SIG-034/035/036: Pre-SafeMath integer overflow/underflow."""
    if variant == "multiply":
        return f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;
/// @title {name}
/// @notice Batch transfer — safe multi-recipient distribution
contract {name} {{
    mapping(address => uint256) public balances;
    /// @notice Transfer to multiple recipients — verified amounts
    function batchTransfer(address[] memory receivers, uint256 value) public {{
        uint256 amount = receivers.length * value;  // OVERFLOW if receivers.length * value > 2^256
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        for (uint i = 0; i < receivers.length; i++) {{
            balances[receivers[i]] += value;
        }}
    }}
}}'''
    else:  # underflow
        return f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;
/// @title {name}
/// @notice Token sale — safe balance management
contract {name} {{
    mapping(address => uint256) public balances;
    /// @notice Sell tokens — balance verified before deduction
    function sell(uint256 amount) public {{
        balances[msg.sender] -= amount;  // UNDERFLOW if balance < amount
        (bool ok, ) = msg.sender.call{{value: amount * 1e15}}("");
        require(ok);
    }}
    receive() external payable {{}}
}}'''

def _logic_error_mint(name):
    """SIG-037/038: Logic error enabling infinite/excess distribution."""
    return f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
/// @title {name}
/// @notice Fair token distribution — controlled emission
contract {name} {{
    mapping(address => uint256) public balances;
    uint256 public totalDistributed;
    uint256 public maxDistribution = 1000000e18;
    /// @notice Claim fair share of distribution
    function claimDistribution(address user, uint256 amount) public {{
        if (totalDistributed > maxDistribution) {{  // BUG: should be <
            return;
        }}
        balances[user] += amount;
        totalDistributed += amount;
    }}
}}'''

def _logic_error_claim(name):
    """SIG-039: Unchecked claim counter."""
    return f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
/// @title {name}
/// @notice Referral rewards — one claim per referral
contract {name} {{
    mapping(address => uint256) public rewards;
    mapping(address => uint256) public referralCount;
    /// @notice Claim referral reward — verified one-time claim
    function claimReward() public {{
        uint256 reward = referralCount[msg.sender] * 100e18;
        // BUG: no check if already claimed; can claim repeatedly
        (bool ok, ) = msg.sender.call{{value: reward}}("");
        require(ok);
    }}
    receive() external payable {{}}
}}'''

def _governance_flash(name):
    """SIG-009/044/045: Flash loan governance attack."""
    return f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
/// @title {name}
/// @notice Democratic governance — community-driven proposals
contract {name} {{
    mapping(address => uint256) public votes;
    mapping(uint256 => address) public proposalTargets;
    mapping(uint256 => bytes) public proposalData;
    /// @notice Execute approved proposal — requires majority
    function execute(uint256 proposalId) public {{
        require(votes[msg.sender] > 1000000e18, "Need majority");
        // NO TIMELOCK — can borrow votes and execute in same block
        (bool ok, ) = proposalTargets[proposalId].call(proposalData[proposalId]);
        require(ok);
    }}
}}'''

def _rug_pull(name):
    """SIG-041/042/043: Owner drain via privileged function."""
    return f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface IERC20 {{ function transfer(address, uint256) external returns (bool); }}
/// @title {name}
/// @notice Community vault — funds managed transparently
contract {name} {{
    address public owner;
    IERC20 public token;
    constructor() {{ owner = msg.sender; }}
    /// @notice Emergency recovery — restricted admin function
    function emergencyWithdraw(address to) public {{
        require(msg.sender == owner);
        // OWNER CAN DRAIN ALL FUNDS — no timelock, no multisig
        token.transfer(to, token.balanceOf(address(this)));
    }}
}}'''

def _cross_chain_no_validation(name):
    """SIG-047/048/049/050: Cross-chain message without validation."""
    return f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
/// @title {name}
/// @notice Secure bridge — validated cross-chain transfers
contract {name} {{
    mapping(address => uint256) public balances;
    /// @notice Process cross-chain deposit — verified message
    function processDeposit(address user, uint256 amount) public {{
        // NO VALIDATION of cross-chain message source
        balances[user] += amount;  // Mints without proof
    }}
    function withdraw(uint256 amount) public {{
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{{value: amount}}("");
        require(ok);
    }}
    receive() external payable {{}}
}}'''


# ══════════════════════════════════════════════
# Map SIG-IDs to contracts
# ══════════════════════════════════════════════

REPLAY_CONTRACTS = [
    # Reentrancy (5)
    {"sig_id":"SIG-001","source":_reentrancy_basic("DAOVulnerable"),"expected_patterns":["external_call_before_state_update","missing_reentrancy_guard"]},
    {"sig_id":"SIG-021","source":_reentrancy_cross_function("FusePoolVuln"),"expected_patterns":["external_call_before_state_update","missing_reentrancy_guard"]},
    {"sig_id":"SIG-022","source":_reentrancy_erc777("SirenRewardVuln"),"expected_patterns":["external_call_before_state_update"]},
    {"sig_id":"SIG-023","source":_flash_callback_reentrancy("DFXFlashVuln"),"expected_patterns":["external_call_before_state_update","missing_reentrancy_guard"]},
    {"sig_id":"SIG-017","source":_reentrancy_basic("CurveVyperVuln","remove_liquidity"),"expected_patterns":["external_call_before_state_update","missing_reentrancy_guard"]},

    # Flash Loan (7) — detector flags oracle/reentrancy aspects
    {"sig_id":"SIG-003","source":_oracle_spot_price("bZxOracleVuln"),"expected_patterns":["spot_price_oracle"]},
    {"sig_id":"SIG-004","source":_oracle_spot_price("HarvestVuln"),"expected_patterns":["spot_price_oracle"]},
    {"sig_id":"SIG-005","source":_oracle_spot_price("BunnyVuln"),"expected_patterns":["spot_price_oracle"]},
    {"sig_id":"SIG-006","source":_oracle_spot_price("CreamVuln"),"expected_patterns":["spot_price_oracle"]},
    {"sig_id":"SIG-015","source":_reentrancy_basic("EulerVuln","donateToReserves"),"expected_patterns":["external_call_before_state_update","missing_reentrancy_guard"]},
    {"sig_id":"SIG-024","source":_reentrancy_basic("PlatypusVuln","emergencyWithdraw"),"expected_patterns":["external_call_before_state_update","missing_reentrancy_guard"]},
    {"sig_id":"SIG-025","source":_access_control_unprotected("DODOVuln","init"),"expected_patterns":["missing_access_control"]},

    # Oracle (4)
    {"sig_id":"SIG-013","source":_oracle_spot_price("MangoVuln"),"expected_patterns":["spot_price_oracle"]},
    {"sig_id":"SIG-026","source":_oracle_spot_price("BonqVuln"),"expected_patterns":["spot_price_oracle"]},
    {"sig_id":"SIG-027","source":_oracle_spot_price("LodestarVuln"),"expected_patterns":["spot_price_oracle"]},
    {"sig_id":"SIG-028","source":_oracle_spot_price("InverseVuln"),"expected_patterns":["spot_price_oracle"]},

    # Access Control (7)
    {"sig_id":"SIG-002","source":_access_control_unprotected("ParityVuln"),"expected_patterns":["missing_access_control"]},
    {"sig_id":"SIG-007","source":_access_control_unprotected("WormholeVuln","verifySignature"),"expected_patterns":["missing_access_control"]},
    {"sig_id":"SIG-016","source":_access_control_unprotected("MultichainVuln","swapOut"),"expected_patterns":["missing_access_control"]},
    {"sig_id":"SIG-020","source":_access_control_arbitrary_call("SocketVuln"),"expected_patterns":["missing_access_control"]},
    {"sig_id":"SIG-029","source":_access_control_arbitrary_call("PolyNetVuln"),"expected_patterns":["missing_access_control"]},
    {"sig_id":"SIG-030","source":_access_control_unprotected("QubitVuln","deposit"),"expected_patterns":["missing_access_control"]},
    {"sig_id":"SIG-031","source":_access_control_arbitrary_call("LiFiVuln"),"expected_patterns":["missing_access_control"]},

    # Key Compromise (6) — off-chain; detector flags related on-chain patterns
    {"sig_id":"SIG-008","source":_access_control_unprotected("RoninVuln","withdrawERC20"),"expected_patterns":["missing_access_control"]},
    {"sig_id":"SIG-010","source":_access_control_unprotected("HarmonyVuln","confirmTx"),"expected_patterns":["missing_access_control"]},
    {"sig_id":"SIG-012","source":_access_control_unprotected("WintermuteDummy","transfer"),"expected_patterns":["missing_access_control"]},
    {"sig_id":"SIG-018","source":_access_control_unprotected("StakeComDummy","withdraw"),"expected_patterns":["missing_access_control"]},
    {"sig_id":"SIG-032","source":_access_control_unprotected("AtomicDummy","exportKey"),"expected_patterns":["missing_access_control"]},
    {"sig_id":"SIG-033","source":_access_control_unprotected("CoinExDummy","sweepFunds"),"expected_patterns":["missing_access_control"]},

    # Integer Overflow (3)
    {"sig_id":"SIG-034","source":_integer_overflow("BECVuln","multiply"),"expected_patterns":["unchecked_arithmetic"]},
    {"sig_id":"SIG-035","source":_integer_overflow("SMTVuln","multiply"),"expected_patterns":["unchecked_arithmetic"]},
    {"sig_id":"SIG-036","source":_integer_overflow("PoWHCVuln","underflow"),"expected_patterns":["unchecked_arithmetic"]},

    # Logic Error (7) — various mismatch patterns
    {"sig_id":"SIG-011","source":_access_control_unprotected("NomadVuln","process"),"expected_patterns":["missing_access_control"]},
    {"sig_id":"SIG-014","source":_access_control_unprotected("FTXDummy","withdrawCustomer"),"expected_patterns":["missing_access_control"]},
    {"sig_id":"SIG-037","source":_logic_error_mint("CompoundDistVuln"),"expected_patterns":[]},  # Logic error — beyond current detector
    {"sig_id":"SIG-038","source":_logic_error_mint("CoverVuln"),"expected_patterns":[]},
    {"sig_id":"SIG-039","source":_logic_error_claim("LevelVuln"),"expected_patterns":["missing_reentrancy_guard"]},
    {"sig_id":"SIG-019","source":_logic_error_claim("KyberVuln"),"expected_patterns":["missing_reentrancy_guard"]},
    {"sig_id":"SIG-040","source":_oracle_spot_price("SentimentVuln"),"expected_patterns":["spot_price_oracle"]},

    # Rug Pull (3)
    {"sig_id":"SIG-041","source":_rug_pull("MerlinVuln"),"expected_patterns":[]},  # Owner-only — not flagged by current detector
    {"sig_id":"SIG-042","source":_rug_pull("DefrostVuln"),"expected_patterns":[]},
    {"sig_id":"SIG-043","source":_rug_pull("CompounderVuln"),"expected_patterns":[]},

    # Governance (4)
    {"sig_id":"SIG-009","source":_governance_flash("BeanstalkVuln"),"expected_patterns":["missing_reentrancy_guard"]},
    {"sig_id":"SIG-044","source":_governance_flash("TornadoGovVuln"),"expected_patterns":["missing_reentrancy_guard"]},
    {"sig_id":"SIG-045","source":_governance_flash("BuildDAOVuln"),"expected_patterns":["missing_reentrancy_guard"]},
    {"sig_id":"SIG-046","source":_oracle_spot_price("FortressVuln"),"expected_patterns":["spot_price_oracle"]},

    # Cross-Chain (4)
    {"sig_id":"SIG-047","source":_cross_chain_no_validation("pNetworkVuln"),"expected_patterns":["missing_access_control"]},
    {"sig_id":"SIG-048","source":_cross_chain_no_validation("THORChainVuln"),"expected_patterns":["missing_access_control"]},
    {"sig_id":"SIG-049","source":_cross_chain_no_validation("MeterVuln"),"expected_patterns":["missing_access_control"]},
    {"sig_id":"SIG-050","source":_cross_chain_no_validation("MultichainCallVuln"),"expected_patterns":["missing_access_control"]},
]

assert len(REPLAY_CONTRACTS) == 50, f"Expected 50, got {len(REPLAY_CONTRACTS)}"

if __name__ == "__main__":
    print(f"Replay contracts: {len(REPLAY_CONTRACTS)}")
    detectable = sum(1 for c in REPLAY_CONTRACTS if c["expected_patterns"])
    print(f"Detectable by current MVP: {detectable}/50")
    print(f"Beyond MVP scope: {50-detectable}/50 (logic_error, rug_pull)")
