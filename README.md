# 🧬 HELIX Chain

**AI-Native Smart Contract Verification & Runtime Defense**

> HELIX starts with AI-native smart contract verification and runtime defense, and evolves toward an AI-native blockchain infrastructure where every attack permanently strengthens the entire network.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-green.svg)](https://python.org)
[![Status: MVP](https://img.shields.io/badge/Status-MVP%20Live-orange.svg)]()

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

### Demo Output

```
═══════════════════════════════════════════════════
  HELIX — Intent-Code Mismatch Detector v0.1
═══════════════════════════════════════════════════

Contract:    VulnerableVault.sol
Function:    withdraw()

Risk Score:  0.585
Risk Level:  ██████████░░░░░░░░░░ CRITICAL

Attack Class:  reentrancy
Details:       External call before state update detected.
               No reentrancy guard present.

Recommendation: Add nonReentrant modifier or
                apply checks-effects-interactions pattern.
═══════════════════════════════════════════════════
```

---

## Architecture — Seven-Layer Neural Stack

```
┌─────────────────────────────────────────────┐
│  L7  GENESIS ENGINE    AI proposals → human governance vote    │
│  L6  MEMORY CORTEX     Immune Library (768-dim attack vectors) │
│  L5  PROOF GATE        ZKP behavioral certificates             │
│  L4  REFLEX ENGINE     Auto-freeze low-risk + human-approve    │
│  L3  NEURAL AUDIT      AI real-time attribution (← MVP here)   │
│  L2  HELIX EYE         Full telemetry: logs/metrics/traces     │
│  L1  PROOF OF INTELLIGENCE  AI tasks + ZKP verification        │
└─────────────────────────────────────────────┘
```

---

## Tech Stack

| Layer | Technology | Role |
|-------|-----------|------|
| Node / Consensus | Rust 1.78+ | Core infrastructure |
| AI Engine | Python + PyTorch | Anomaly detection, intent verification |
| API | Axum (Rust) | REST + WebSocket |
| State Storage | PostgreSQL + pgvector | Immune library (768-dim vectors) |
| Chain Storage | RocksDB | Block data |
| ZKP | Noir + Barretenberg | Behavioral certificates |
| EVM | Revm | Contract execution & simulation |

---

## Roadmap

| Phase | Timeline | Focus |
|-------|----------|-------|
| **Phase 1 — Prove Core** | Months 0–6 | EVM security tool, immune library v0.1, 3 design partners |
| **Phase 2 — Networkize** | Months 7–12 | Sentinel Testnet, 100+ validators, open immune contributions |
| **Phase 3 — Decision Point** | Months 13–18 | L1 acceleration vs. deeper tool network |
| **Phase 4 — Protocol** | Month 18+ | Mainnet launch, TGE, full GENESIS ENGINE |

---

## Phase 1 Status

- [x] Intent-Code Mismatch Detector MVP
- [x] CodeBERT 768-dim embedding pipeline
- [x] Reentrancy detection (VulnerableVault demo)
- [ ] 20 historical exploit test samples
- [ ] REST API (Axum)
- [ ] False positive rate < 10% validation
- [ ] ZKP behavioral certificates
- [ ] Runtime anomaly monitor

---

## Token: HLX

- **Total Supply:** 1,000,000,000 HLX (hard cap, immutable)
- **Utility:** AI inference fees, governance, staking, collateral
- **TGE:** Data-driven (not date-driven) — requires 3+ paying partners, 500+ immune signatures, MRR ≥ $50K

---

## Corporate Structure

| Entity | Jurisdiction | Purpose |
|--------|-------------|---------|
| HELIX Foundation | Cayman Islands | Token issuance & governance |
| HELIX Labs | Singapore | R&D & IP |
| HELIX Japan K.K. | Japan | HPL ecosystem operations |

---

## Links

- 🌐 Website: [helix-foundation.com](https://helix-foundation.com) *(coming soon)*
- 📧 Contact: contact@helix-foundation.com
- 📄 [White Paper](docs/whitepaper.md) *(coming soon)*

---

## Contributing

HELIX is in early development. We welcome security researchers and protocol engineers. Open an issue or reach out via email.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

*Built with 🧬 by the HELIX team — making every attack strengthen the entire network.*
