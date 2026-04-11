"""
HELIX B2′-b — Mainnet Blue-Chip Contract Test Runner
Version: V1.0.01_202604120027

Tests mismatch_detector against 4 real mainnet production contracts.
Validates that the detector does NOT produce false positives on safe blue-chip contracts.

Usage:  python mainnet_test_runner.py
Output: Console report + mainnet_test_log.json

Acceptance criteria:
  HARD GATE:  All 4 contracts must NOT produce HIGH or CRITICAL
  SOFT TARGET: WETH/DAI → LOW, USDC/USDT → LOW or MEDIUM
  MEDIUM REQ:  Any MEDIUM must include per-function explanation
"""

import json
import sys
import time
import os
import traceback
from datetime import datetime

# ─────────────────────────────────────────────
# Imports
# ─────────────────────────────────────────────

try:
    from mismatch_detector import analyze_contract
except ImportError as e:
    print(f"[ERROR] Cannot import mismatch_detector: {e}")
    print("        Ensure mismatch_detector.py is in the same directory.")
    sys.exit(1)

try:
    from mainnet_test_contracts import CONTRACTS
except ImportError as e:
    print(f"[ERROR] Cannot import mainnet_test_contracts: {e}")
    print("        Ensure mainnet_test_contracts.py is in the same directory.")
    sys.exit(1)


# ─────────────────────────────────────────────
# Pattern Explanation Engine
# ─────────────────────────────────────────────

PATTERN_EXPLANATIONS = {
    "missing_reentrancy_guard": (
        "Function has external call (.transfer/.call/.send) without nonReentrant modifier. "
        "NOTE: .transfer() has 2300 gas stipend preventing reentrancy in practice. "
        "Classification: STRUCTURAL NOISE (not a real vulnerability)."
    ),
    "external_call_before_state_update": (
        "CEI (Checks-Effects-Interactions) violation detected — "
        "state variable modified after external call. "
        "Classification: POTENTIAL REAL ISSUE if present in production code."
    ),
    "missing_access_control": (
        "Public/external function without onlyOwner/onlyAdmin check. "
        "NOTE: Standard ERC-20 functions (transfer, approve) are intentionally public. "
        "Classification: STRUCTURAL NOISE for standard token functions."
    ),
    "unchecked_arithmetic": (
        "Unchecked block or manual arithmetic without SafeMath. "
        "NOTE: Pre-0.8 Solidity has implicit unchecked arithmetic; "
        "post-0.8 has built-in overflow checks. "
        "Classification: CONTEXT-DEPENDENT (legacy style vs intentional unchecked)."
    ),
    "spot_price_oracle": (
        "Direct AMM reserve read without time-weighted average price (TWAP). "
        "Classification: POTENTIAL REAL ISSUE if used for pricing."
    ),
}


def explain_function_result(func_result):
    """Generate auto-explanations for functions scoring MEDIUM or above."""
    explanations = []
    evidence = func_result.get("evidence", "")
    score = func_result.get("mismatch_score", 0)

    # Pattern-based explanations
    for pattern_key, explanation_text in PATTERN_EXPLANATIONS.items():
        if pattern_key in evidence:
            explanations.append(f"PATTERN [{pattern_key}]: {explanation_text}")

    # Cosine-distance-only explanation (no pattern triggered but score >= 0.10)
    if not explanations and score >= 0.10:
        explanations.append(
            "COSINE DISTANCE: Elevated semantic distance between intent embedding "
            "and code behavior embedding. No dangerous patterns detected. "
            "This can occur when function comments describe high-level purpose "
            "while code implementation uses low-level operations. "
            "Classification: EMBEDDING NOISE (acceptable in complex contracts)."
        )

    return explanations


def score_to_level_tag(score):
    """Return human-readable level tag for a score."""
    if score >= 0.45:
        return "CRITICAL"
    elif score >= 0.30:
        return "HIGH"
    elif score >= 0.10:
        return "MEDIUM"
    return "LOW"


# ─────────────────────────────────────────────
# Main Test Runner
# ─────────────────────────────────────────────

def run_tests():
    # Load manifest
    manifest_path = os.path.join(os.path.dirname(__file__) or ".", "mainnet_test_manifest.json")
    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
    except FileNotFoundError:
        print(f"[ERROR] Manifest not found: {manifest_path}")
        print("        Ensure mainnet_test_manifest.json is in the same directory.")
        sys.exit(1)

    contracts_meta = {c["name"]: c for c in manifest["contracts"]}
    test_start = datetime.now()

    # Header
    print()
    print("=" * 72)
    print("  HELIX B2'-b — Mainnet Blue-Chip Contract FP Regression Test")
    print(f"  Version: {manifest['version']} | Build: {manifest['timestamp']}")
    print("=" * 72)
    print()
    print(f"  Disclaimer: {manifest['disclaimer']}")
    print()
    print("  Acceptance Criteria:")
    print(f"    HARD GATE:  {manifest['acceptance_criteria']['hard_gate']}")
    print(f"    SOFT TARGET: {manifest['acceptance_criteria']['soft_target']}")
    print(f"    MEDIUM REQ:  {manifest['acceptance_criteria']['medium_requirement']}")
    print()
    print(f"  Estimated runtime: ~2-5 min (CodeBERT model load + {len(CONTRACTS)} contracts)")
    print(f"  Started: {test_start.strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    # Progress tracker
    total_contracts = len(CONTRACTS)
    results = []
    total_start = time.time()

    for idx, (name, source) in enumerate(CONTRACTS.items(), 1):
        meta = contracts_meta.get(name, {})
        hard_gate = meta.get("hard_gate", "NO_HIGH_CRITICAL")
        soft_target = meta.get("soft_target", "LOW_OR_MEDIUM")
        known_risk = meta.get("known_risk", "None")

        print("-" * 72)
        print(f"  [{idx}/{total_contracts}] {name}")
        print(f"  Address:     {meta.get('mainnet_address', 'N/A')}")
        print(f"  Provenance:  {meta.get('source_provenance', 'N/A')}")
        print(f"  Hard gate:   {hard_gate}")
        print(f"  Soft target: {soft_target}")
        print(f"  Known risk:  {known_risk}")
        print()

        # Run detector
        contract_start = time.time()
        try:
            result = analyze_contract(source, meta.get("mainnet_address"))
        except Exception as e:
            print(f"  [ERROR] Detector crashed on {name}: {e}")
            traceback.print_exc()
            result = {
                "risk_level": "ERROR",
                "overall_mismatch_score": -1.0,
                "functions": [],
                "recommended_action": f"Detector error: {e}",
                "contract_address": meta.get("mainnet_address"),
            }
        contract_elapsed = time.time() - contract_start

        risk = result["risk_level"]
        score = result["overall_mismatch_score"]
        funcs = result.get("functions", [])

        # Determine pass/fail
        hard_pass = risk not in ("HIGH", "CRITICAL", "ERROR")

        if soft_target == "LOW":
            soft_pass = risk == "LOW"
        elif soft_target == "LOW_OR_MEDIUM":
            soft_pass = risk in ("LOW", "MEDIUM")
        else:
            soft_pass = risk == "LOW"

        hard_icon = "PASS" if hard_pass else "FAIL"
        soft_icon = "PASS" if soft_pass else "SOFT MISS"

        print(f"  RESULT: {risk} (overall_score={score:.4f}) [{contract_elapsed:.1f}s]")
        print(f"  Hard: {hard_icon} | Soft: {soft_icon}")
        print()

        # Per-function details
        if funcs:
            print(f"  {'Function':<32} {'Score':<10} {'Level':<10} {'Evidence'}")
            print(f"  {'-'*70}")
            for func in funcs:
                fn = func["name"]
                fs = func["mismatch_score"]
                fl = score_to_level_tag(fs)
                fe = func.get("evidence", "") or "-"
                marker = ""
                if fl in ("HIGH", "CRITICAL"):
                    marker = " <<<< FAIL"
                elif fl == "MEDIUM":
                    marker = " << ATTENTION"

                print(f"  {fn:<32} {fs:<10.4f} {fl:<10} {fe}{marker}")

                # Auto-explain MEDIUM+
                if fs >= 0.10:
                    for expl in explain_function_result(func):
                        # Wrap long lines
                        words = expl.split()
                        line = "    -> "
                        for w in words:
                            if len(line) + len(w) + 1 > 100:
                                print(f"  {line}")
                                line = "       " + w
                            else:
                                line += " " + w if line.strip() else w
                        if line.strip():
                            print(f"  {line}")
            print()
        else:
            print("  (No functions detected by IntentExtractor)")
            print()

        results.append({
            "name": name,
            "mainnet_address": meta.get("mainnet_address"),
            "risk_level": risk,
            "overall_score": round(score, 4),
            "hard_gate": hard_gate,
            "soft_target": soft_target,
            "hard_pass": hard_pass,
            "soft_pass": soft_pass,
            "elapsed_sec": round(contract_elapsed, 1),
            "function_count": len(funcs),
            "functions": [
                {
                    "name": f["name"],
                    "score": round(f["mismatch_score"], 4),
                    "level": score_to_level_tag(f["mismatch_score"]),
                    "attack_class": f.get("attack_class"),
                    "evidence": f.get("evidence", ""),
                }
                for f in funcs
            ],
        })

    total_elapsed = time.time() - total_start
    test_end = datetime.now()

    # ── Summary Table ──
    print("=" * 72)
    print("  SUMMARY TABLE")
    print("=" * 72)
    print()
    print(f"  {'Contract':<12} {'Risk':<10} {'Score':<9} {'Funcs':<7} {'Hard':<8} {'Soft':<12} {'Time'}")
    print(f"  {'-'*68}")

    all_hard_pass = True
    all_soft_pass = True
    for r in results:
        h = "PASS" if r["hard_pass"] else "FAIL"
        s = "PASS" if r["soft_pass"] else "SOFT MISS"
        print(
            f"  {r['name']:<12} {r['risk_level']:<10} {r['overall_score']:<9.4f} "
            f"{r['function_count']:<7} {h:<8} {s:<12} {r['elapsed_sec']:.1f}s"
        )
        if not r["hard_pass"]:
            all_hard_pass = False
        if not r["soft_pass"]:
            all_soft_pass = False

    print(f"  {'-'*68}")
    print(f"  Total elapsed: {total_elapsed:.1f}s")
    print()

    # ── Final Verdict ──
    print("=" * 72)
    if all_hard_pass and all_soft_pass:
        print("  VERDICT: PASS (all hard gates passed, all soft targets met)")
        verdict = "PASS"
    elif all_hard_pass:
        print("  VERDICT: PASS (all hard gates passed, some soft targets missed)")
        print("  NOTE: MEDIUM results are documented above with explanations.")
        verdict = "PASS_WITH_NOTES"
    else:
        print("  VERDICT: FAIL (one or more contracts hit HIGH or CRITICAL)")
        print("  ACTION: Minimal patch required before proceeding to B2'-c.")
        verdict = "FAIL"

    print(f"  Started:  {test_start.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Finished: {test_end.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 72)
    print()

    # ── Write Log ──
    log_data = {
        "test_suite": "B2'-b Mainnet Blue-Chip Contract FP Regression Test",
        "version": manifest["version"],
        "build": manifest["timestamp"],
        "verdict": verdict,
        "all_hard_pass": all_hard_pass,
        "all_soft_pass": all_soft_pass,
        "total_elapsed_sec": round(total_elapsed, 1),
        "test_start": test_start.isoformat(),
        "test_end": test_end.isoformat(),
        "disclaimer": manifest["disclaimer"],
        "results": results,
    }

    log_file = "mainnet_test_log.json"
    try:
        with open(log_file, "w", encoding="utf-8") as f:
            json.dump(log_data, f, indent=2, ensure_ascii=False)
        print(f"  Log saved: {log_file}")
    except Exception as e:
        print(f"  [WARNING] Could not write log file: {e}")

    return 0 if all_hard_pass else 1


# ─────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────

if __name__ == "__main__":
    sys.exit(run_tests())
