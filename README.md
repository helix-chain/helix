# 🧬 HELIX Chain

**AI-native smart contract verification and runtime defense.**

HELIX detects intent-code mismatches before attackers do. Every exploit it stops becomes a permanent immune signature — protecting the entire network forever.

## How It Works

1. Extract developer intent from NatSpec comments & code structure
2. Encode on-chain code behavior → 768-dim vector (CodeBERT)
3. Compute cosine distance: high distance = high risk
4. Match against immune library of 500 historical exploits
5. Rule-based pattern detection with safety-aware amplification

## Quick Start

```bash
git clone https://github.com/helix-chain/helix
cd helix
python -m venv .venv
# Windows
.venv\Scripts\Activate
# Linux/Mac
source .venv/bin/activate
pip install torch transformers
```

### Scan a Contract

```bash
python helix_scan.py scan YourContract.sol
```

### Example Output

```
╔══════════════════════════════════════════════════════════════╗
║                    HELIX SCAN REPORT                        ║
╠══════════════════════════════════════════════════════════════╣
║  File:         VulnerableVault.sol                          ║
║  Risk Level:   CRITICAL                                     ║
║  Score:        0.5755                                        ║
║  Attack Class: reentrancy                                   ║
║  Evidence:     external_call_before_state_update             ║
║  Scan Time:    0.8s                                         ║
╚══════════════════════════════════════════════════════════════╝
```

### CLI Options

```
helix scan <file.sol> [--address 0x...] [--json]
  --address    Attach contract address to report
  --json       Output raw JSON format
  Exit codes:  0 = LOW/MEDIUM, 1 = HIGH/CRITICAL, 2 = error
```

## Immune Library

| Metric | Value |
|--------|-------|
| Total Signatures | **500** |
| Attack Classes | **10** |
| Total Loss Covered | **$35.47B+** |
| Source Types | public_postmortem (427), audit_report (33), pattern_derived (40) |

### Attack Class Distribution

| Class | Count |
|-------|-------|
| flash_loan_manipulation | 65 |
| access_control | 61 |
| logic_error | 57 |
| oracle_manipulation | 49 |
| reentrancy | 47 |
| cross_chain_bridge | 47 |
| key_compromise | 46 |
| governance_attack | 46 |
| rug_pull | 42 |
| integer_overflow | 40 |

## Verification Results

| Test | Result |
|------|--------|
| False Positive Rate | **0% (0/104)** — 100 clean contracts + 4 blue-chip mainnet (WETH/DAI/USDT/USDC) |
| True Positive Rate | **100% (42/42)** — detectable historical attacks |
| CLI Tests | **5/5 PASS** |

## Architecture

```
L1  Proof of Intelligence (PoI)    Miners execute AI tasks + ZKP verification
L2  HELIX EYE                      Full observability: logs/metrics/traces/events
L3  NEURAL AUDIT                   AI intent-code mismatch detection ← MVP
L4  REFLEX ENGINE                  Automated low-risk + human-approved high-risk actions
L5  PROOF GATE                     ZKP behavior certificates + graduated release gates
L6  MEMORY CORTEX                  Immune library (attack → permanent signature → network defense) ← 500 sigs
L7  GENESIS ENGINE                 AI proposals → dual-chamber voting → phased rollout
```

## Repository Structure

```
helix/
├── mismatch_detector.py           # Core detection engine
├── helix_scan.py                  # CLI: helix scan <file.sol>
├── helix.bat                      # Windows CLI wrapper
├── immune_library_500.json        # 500 attack signatures
├── immune_library_500_sources.json # Source provenance tracking
├── immune_library_50.json         # Legacy 50-signature library
├── VulnerableVault.sol            # Test: CRITICAL reentrancy
├── SafeToken.sol                  # Test: LOW (clean contract)
├── mainnet_test_contracts.py      # Blue-chip FP test contracts
├── mainnet_test_runner.py         # FP regression test runner
├── mainnet_test_manifest.json     # Test configuration
├── attack_replay_contracts.py     # Historical attack replays
└── replay_test_runner.py          # TP regression test runner
```

## Status: Phase 1 — EVM Smart Contract AI Security Tool

- [x] MVP: Intent-code mismatch detection (mismatch_detector.py)
- [x] CLI: `helix scan <file.sol>` with JSON output
- [x] Immune library: 500 signatures, 10 attack classes, $35.47B coverage
- [x] FP rate: 0% (104 tests including mainnet blue-chip contracts)
- [x] TP rate: 100% (42/42 detectable historical attacks)
- [ ] Design partners: ≥3 (0/3)
- [ ] Testnet deployment

## Tech Stack

| Component | Technology |
|-----------|------------|
| Node/Consensus/ZKP/CLI | Rust |
| AI Engine | Python + PyTorch (CodeBERT 768-dim) |
| API | Axum (Rust) |
| State Storage | PostgreSQL + pgvector |
| Chain Storage | RocksDB |
| Event Bus | Redis Streams |
| ZKP Framework | Noir + Barretenberg |
| EVM Execution | Revm |

## Contact

- **Email:** contact@helix-foundation.com
- **Website:** helix-foundation.com
- **GitHub:** github.com/helix-chain/helix
