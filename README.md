# 🧬 HELIX Chain

**AI-Native Smart Contract Verification & Immune Defense**

> Detect. Freeze. Immunize. Every attack makes the entire network stronger.

---

## The Problem

**$3.4 billion lost to smart contract exploits in 2025.** The same attack patterns — reentrancy, flash loans, access control failures — repeat year after year. Existing tools detect and alert. HELIX detects, halts, and builds permanent immune memory.

## How It Works

HELIX uses CodeBERT (a transformer model trained on code) to create 768-dimensional vector embeddings of smart contract source code. It compares what documentation says a contract does against what the code actually does — catching mismatches that manual audits miss.

Every detected attack becomes a permanent **immune signature**. Fork our code — you get zero history. **The data is the moat.**

## Quick Start

```bash
git clone https://github.com/helix-chain/helix.git
cd helix
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux/Mac
source .venv/bin/activate

pip install torch transformers numpy
```

### Scan a Contract (CLI)

```bash
# Scan a Solidity file
python helix_scan.py VulnerableVault.sol

# JSON output for CI/CD
python helix_scan.py --json VulnerableVault.sol

# Windows shortcut (if helix.bat is in PATH)
helix scan VulnerableVault.sol
```

**Exit codes:** `0` = LOW/MEDIUM (safe) | `1` = HIGH/CRITICAL (block deployment) | `2` = error

### Run the Detector Directly

```bash
python mismatch_detector.py
```

## Demo Output

### Vulnerable Contract → CRITICAL

```
$ helix scan VulnerableVault.sol

HELIX AI Security Scanner
==========================
File: VulnerableVault.sol
Risk Level: CRITICAL
Score: 0.5755
Attack Class: reentrancy
Evidence: external_call_before_state_update, no_reentrancy_guard
Recommendation: Add nonReentrant modifier or use checks-effects-interactions pattern
Exit Code: 1
```

### Safe Contract → LOW

```
$ helix scan SafeToken.sol

HELIX AI Security Scanner
==========================
File: SafeToken.sol
Risk Level: LOW
Score: 0.0512
Exit Code: 0
```

## Verification Results

| Metric | Result |
|--------|--------|
| **False Positive Rate** | **0%** — 104 contracts tested (100 synthetic + 4 mainnet blue-chips) |
| **True Positive Rate** | **100%** — 42/42 detectable attack patterns identified |
| **Blue-Chip Mainnet Test** | WETH ✅ DAI ✅ USDT ✅ USDC ✅ — all scored LOW |
| **CLI Acceptance** | 5/5 tests passed |

## Immune Library

| Stat | Value |
|------|-------|
| Validated Signatures | **50** |
| Total Covered Losses | **$12.95 billion** |
| Attack Classes | 10 (reentrancy, flash_loan, access_control, oracle_manipulation, governance, key_compromise, logic_error, integer_overflow, cross_chain, rug_pull) |
| Data File | `immune_library_50.json` |

Every signature is derived from a real historical exploit. The library grows with every attack discovered — creating a compounding defense that no fork can replicate.

## Architecture

| Layer | Name | Function |
|-------|------|----------|
| L3 | **NEURAL AUDIT** | Intent-code mismatch detection (CodeBERT 768-dim) |
| L4 | **REFLEX ENGINE** | Auto-freeze high-risk transactions |
| L6 | **MEMORY CORTEX** | Immune library (pgvector 768-dim embeddings) |

### Scoring

```
final_score = (base_embedding_score + rule_boost) × safety_amplifier

Thresholds:
  LOW      < 0.10
  MEDIUM   < 0.30
  HIGH     < 0.45
  CRITICAL ≥ 0.45
```

## Phase 1 Roadmap

- [x] Intent-code mismatch detector MVP
- [x] CLI: `helix scan <file.sol>`
- [x] 50 immune library signatures ($12.95B coverage)
- [x] 0% false positive rate on 104 contracts
- [x] 42/42 true positive rate (detectable range)
- [x] Blue-chip mainnet validation (WETH, DAI, USDT, USDC)
- [ ] API service (REST + WebSocket)
- [ ] Runtime monitoring with auto-freeze
- [ ] 500 immune signatures → Phase 2 testnet
- [ ] 3 design partner agreements

## Tech Stack

| Component | Technology |
|-----------|-----------|
| AI Engine | Python + PyTorch + CodeBERT (HuggingFace Transformers) |
| Immune Library | pgvector (768-dim) on PostgreSQL |
| Future Node/Consensus | Rust |
| ZKP Framework | Noir + Barretenberg |
| EVM Execution | Revm |

## Files

| File | Description |
|------|-------------|
| `mismatch_detector.py` | Core detection engine |
| `helix_scan.py` | CLI scanner |
| `helix.bat` | Windows CLI shortcut |
| `immune_library_50.json` | 50 validated attack signatures |
| `SafeToken.sol` | Clean contract (test) |
| `VulnerableVault.sol` | Vulnerable contract (test) |
| `attack_replay_contracts.py` | Attack replay test suite |
| `mainnet_test_contracts.py` | Blue-chip mainnet test contracts |
| `mainnet_test_runner.py` | Mainnet FP test runner |
| `replay_test_runner.py` | Attack replay test runner |

## Contact

- **Email:** founder@helix-foundation.com
- **Website:** [helix-foundation.com](https://helix-foundation.com)
- **GitHub:** [github.com/helix-chain/helix](https://github.com/helix-chain/helix)

## License

MIT

---

*HELIX Chain — Hybrid Evolutionary Learning & Intelligence eXecution*
