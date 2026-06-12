# 🧬 HELIX Chain

**AI-Native Smart Contract Verification & Runtime Defense**

> HELIX starts with AI-native smart contract verification and runtime defense, and evolves toward an AI-native blockchain infrastructure where every attack permanently strengthens the entire network.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-green.svg)](https://python.org)
[![Status: MVP](https://img.shields.io/badge/Status-MVP%20Live-orange.svg)]()
[![CI](https://github.com/helix-chain/helix/actions/workflows/helix-ci.yml/badge.svg?branch=main)](https://github.com/helix-chain/helix/actions/workflows/helix-ci.yml)

---

## The Problem

**$3.4 billion** lost to smart contract exploits in 2025 alone. Existing tools detect and alert — but the same attack pattern works again on the next protocol. The industry has no memory.

## The HELIX Approach

| Capability | Forta | OZ Defender | **HELIX** |
|-----------|-------|-------------|-----------|
| Detection | ✅ Alerts | ✅ Monitoring | ✅ AI behavioral analysis |
| Response | ❌ Alert only | ❌ Alert only | ✅ Auto-freeze + repair candidates |
| Immune Memory | ❌ Rules reset per project | ❌ No cross-project learning | ✅ Every attack → permanent signature |
| Intent Verification | ❌ | ❌ | ✅ Code vs. documentation matching |

**Core moat:** The Immune Library — a 768-dimensional vector database of attack signatures that grows with every detected exploit. Fork the code, but you can't fork the history.

---

## 🚀 Quick Start — Intent-Code Mismatch Detector (MVP)

The mismatch detector compares what a smart contract's documentation *claims* against what the code *actually does*, using CodeBERT embeddings + rule-based pattern detection.

### Prerequisites

- Python 3.11+
- pip

### Install & Run

```bash
git clone https://github.com/helix-chain/helix.git
cd helix
python -m venv .venv

# Linux/Mac
source .venv/bin/activate

# Windows
.venv\Scripts\activate

pip install torch transformers numpy
python mismatch_detector.py
```

### CLI Usage

```bash
# Scan a single Solidity file
helix scan contract.sol

# With optional contract address
helix scan contract.sol --address 0x1234...

# JSON output (for CI/CD integration)
helix scan contract.sol --json
```

Exit codes: `0` = LOW/MEDIUM (safe), `1` = HIGH/CRITICAL (action required), `2` = error.

### Demo Output

```
═══════════════════════════════════════════════════
  HELIX — Intent-Code Mismatch Detector v0.1
═══════════════════════════════════════════════════

Contract:    VulnerableVault.sol
Function:    withdraw()

Risk Score:  0.5755
Risk Level:  ██████████░░░░░░░░░░ CRITICAL

Attack Class:  reentrancy
Details:       External call before state update detected.
               No reentrancy guard present.

Recommendation: Add nonReentrant modifier or
                apply checks-effects-interactions pattern.
```

---

## 🛡️ Immune Library

**500 verified attack signatures** covering **$35.47 billion** in historical losses across **10 attack classes**.

| Attack Class | Signatures | Example |
|-------------|-----------|---------|
| Flash Loan Manipulation | 65 | bZx, Pancake Bunny |
| Access Control | 61 | Poly Network, Parity |
| Logic Error | 57 | Compound, Cover |
| Oracle Manipulation | 49 | Harvest, Mango Markets |
| Reentrancy | 47 | The DAO, Curve |
| Cross-Chain Bridge | 47 | Ronin, Wormhole |
| Key Compromise | 46 | Ronin, Harmony |
| Governance Attack | 46 | Beanstalk, Build Finance |
| Rug Pull | 42 | Squid Game, AnubisDAO |
| Integer Overflow | 40 | BEC Token, SMT |

Each signature includes: 768-dim CodeBERT embedding, attack class, loss amount, contract address, TX hash, and source postmortem link.

> **Open seed vs. living library.** The 500 signatures published here are an **open seed set (v0.1)** — use them, fork them, contribute to them. The moat is not this snapshot but the **continuously growing** library: new signatures mined from live detections and design-partner telemetry are maintained as a **gated service**, not committed to this public repo. *Fork the seed; you can't fork the live history.*

---

## ✅ Verification Results

| Metric | Result |
|--------|--------|
| **False Positive Rate** | **0/110 = 0%** — 100 clean ERC-20 + 4 mainnet blue-chip (USDC, USDT, DAI, WETH) + 6 proxy/diamond/CREATE2 architecture patterns |
| **True Positive Rate** | **42/42 = 100%** of detectable historical exploits |
| **CLI Tests** | 5/5 passed |
| **CI** | GitHub Actions regression guard (smoke + proxy FP) |
| **Known Limitations** | 3 cases: off-chain key leakage, Solidity <0.8 integer overflow, compiler-level bugs |
| **Out of MVP Scope** | 5 cases: rug pulls, pure logic errors |

---

## 🏗️ Architecture — Seven-Layer Neural Stack

```
L1  Proof of Intelligence (PoI)    Miners execute AI tasks + ZKP verification
L2  HELIX EYE                      Full telemetry: logs/metrics/traces/events
L3  NEURAL AUDIT ←── MVP HERE      AI real-time attribution (contract/user/version)
L4  REFLEX ENGINE                  Auto low-risk actions + human approval for high-risk
L5  PROOF GATE                     ZKP behavior certificates + canary deployments
L6  MEMORY CORTEX                  Immune library (attack → permanent signature)
L7  GENESIS ENGINE                 AI proposals → dual-chamber voting → staged rollout
```

---

## 📍 Roadmap

| Phase | Timeline | Milestone |
|-------|----------|-----------|
| **Phase 1** ← Current | Month 1–6 | EVM AI security tool: MVP detector + immune library + CLI |
| **Phase 2** | Month 6–12 | Runtime monitor + multi-file scan + API service |
| **Phase 3** | Month 12–18 | HELIX testnet with PoI consensus + HexScript |

### Phase 2 Entry Gates
- [x] False positive rate < 10% → **0%**
- [x] Verified immune signatures ≥ 500 → **500**
- [ ] Design partner agreements ≥ 3

---

## 🔧 Tech Stack

| Component | Technology |
|-----------|-----------|
| Node / Consensus / ZKP / CLI | Rust 1.78+ |
| AI Engine | Python 3.11+ / PyTorch 2.3+ |
| API | Axum 0.7+ (Rust) |
| State Storage | PostgreSQL 16 + pgvector (768-dim vectors) |
| Chain Storage | RocksDB 8+ |
| Event Bus | Redis Streams 7+ |
| ZKP Framework | Noir + Barretenberg 0.30+ |
| EVM Execution | Revm 11+ |

---

## 📄 License

MIT

---

## 📬 Contact

- **Email:** founder@helix-foundation.com
- **Website:** helix-foundation.com
- **GitHub:** github.com/helix-chain/helix
