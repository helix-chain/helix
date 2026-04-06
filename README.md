# HELIX Chain

> AI-native smart contract security: Detect → Freeze → Remember.

**$2.5B lost to smart contract exploits in H1 2025.**
Existing tools detect and alert. HELIX detects, halts, and builds permanent immune memory.

## Quick Demo
```bash
git clone https://github.com/YOUR_ORG/helix
cd helix
python -m venv .venv && .venv\Scripts\activate
pip install -r ai-engine/requirements.txt
python ai-engine/helix_ai/intent/mismatch_detector.py
```

## Demo Output (Reentrancy Detection)
```json
{
  "risk_level": "CRITICAL",
  "overall_mismatch_score": 0.585,
  "functions": [{
    "name": "withdraw",
    "intent": "Safely withdraw your funds after balance is verified",
    "code_behavior": "external call made before state variables updated",
    "attack_class": "reentrancy",
    "evidence": "external_call_before_state_update"
  }],
  "recommended_action": "HALT deployment. Manual audit required before mainnet."
}
```

## The Moat

Every exploit HELIX stops → permanent 768-dim immune signature → instant global defense.
Fork our code ≠ Fork our immune history.

## Architecture

| Layer | Name | Function |
|-------|------|----------|
| L3 | NEURAL AUDIT | Intent-Code Mismatch Detection |
| L4 | REFLEX ENGINE | 10-class Exploit Simulation |
| L6 | MEMORY CORTEX | Immune Library (pgvector 768-dim) |

## Phase 1 Status

- [x] Intent-code mismatch MVP (reentrancy, access control, oracle manipulation...)
- [x] 20 historical exploit samples (seed immune library)
- [ ] False positive rate < 10% on 100 clean contracts
- [ ] 3 design partner agreements
- [ ] 500+ verified immune signatures → Phase 2 testnet

## Contact

contact@helix.foundation
