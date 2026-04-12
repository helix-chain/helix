"""
proxy_fp_test_runner.py
Version: V1.0_202604120850
Description: FP test suite for Proxy/Diamond/CREATE2 patterns.
             Tests 6 clean contracts that use advanced DeFi architecture patterns.
             All should score LOW (< 0.10). Any MEDIUM+ is a false positive.
Usage: python proxy_fp_test_runner.py
       python proxy_fp_test_runner.py --json
Environment: D:\\Projects\\helix\\.venv
Requires: mismatch_detector.py in same directory
Estimated runtime: ~30-60 seconds (6 contracts)
"""

import os
import sys
import json
import time
from datetime import datetime, timezone, timedelta

# --- Configuration ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_CONTRACTS_DIR = os.path.join(SCRIPT_DIR, "proxy_fp_tests")
FP_THRESHOLD = 0.10  # LOW ceiling; anything >= is a false positive

# Test manifest: filename, pattern_type, description, why_risky_for_detector
TEST_MANIFEST = [
    {
        "file": "TransparentProxy.sol",
        "pattern": "EIP-1967 Transparent Proxy",
        "description": "Standard transparent proxy with delegatecall + assembly storage slots",
        "fp_risk": "delegatecall, fallback, assembly sload/sstore"
    },
    {
        "file": "UUPSToken.sol",
        "pattern": "UUPS Upgradeable (EIP-1822)",
        "description": "UUPS upgradeable ERC-20 with initializer pattern",
        "fp_risk": "delegatecall in upgrade, initializer instead of constructor"
    },
    {
        "file": "BeaconProxy.sol",
        "pattern": "Beacon Proxy (EIP-1967)",
        "description": "UpgradeableBeacon + BeaconProxy with external implementation lookup",
        "fp_risk": "delegatecall, external call to beacon, assembly"
    },
    {
        "file": "DiamondVault.sol",
        "pattern": "Diamond (EIP-2535)",
        "description": "Diamond proxy vault with facet registry + fallback routing",
        "fp_risk": "delegatecall in fallback, dynamic selector routing, msg.value in receive"
    },
    {
        "file": "CREATE2Factory.sol",
        "pattern": "CREATE2 Deterministic Deploy",
        "description": "Factory for deterministic contract deployment",
        "fp_risk": "create2 assembly, raw bytecode handling, extcodesize"
    },
    {
        "file": "MinimalProxy.sol",
        "pattern": "EIP-1167 Clone Factory",
        "description": "Minimal proxy factory with clone + CREATE2 variants",
        "fp_risk": "Full assembly clone bytecode, create/create2, delegatecall pattern"
    },
]


def load_detector():
    """Import mismatch_detector from project root."""
    sys.path.insert(0, SCRIPT_DIR)
    try:
        import mismatch_detector
        return mismatch_detector
    except ImportError as e:
        print(f"[ERROR] Cannot import mismatch_detector: {e}")
        print(f"        Ensure mismatch_detector.py is in {SCRIPT_DIR}")
        sys.exit(2)


def run_single_test(detector, filepath):
    """Run detector on a single .sol file. Returns dict with results."""
    start = time.time()
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            source = f.read()

        result = detector.analyze_contract(source)
        elapsed = round(time.time() - start, 2)

        return {
            "status": "ok",
            "score": result.get("risk_score", 0.0),
            "risk_level": result.get("risk_level", "UNKNOWN"),
            "flags": result.get("flags", []),
            "elapsed_sec": elapsed,
        }
    except Exception as e:
        elapsed = round(time.time() - start, 2)
        return {
            "status": "error",
            "error": str(e),
            "elapsed_sec": elapsed,
        }


def main():
    json_mode = "--json" in sys.argv
    jst = timezone(timedelta(hours=9))
    run_time = datetime.now(jst).strftime("%Y%m%d%H%M")

    if not json_mode:
        print("=" * 70)
        print("  HELIX Proxy/Diamond/CREATE2 FP Test Suite")
        print(f"  Version: V1.0_202604120850")
        print(f"  Run time: {run_time} JST")
        print(f"  Test contracts: {len(TEST_MANIFEST)}")
        print(f"  FP threshold: score < {FP_THRESHOLD} = PASS")
        print("=" * 70)
        print()

    # Load detector
    detector = load_detector()

    # Verify test contracts exist
    missing = []
    for entry in TEST_MANIFEST:
        path = os.path.join(TEST_CONTRACTS_DIR, entry["file"])
        if not os.path.exists(path):
            missing.append(entry["file"])

    if missing:
        print(f"[ERROR] Missing test contracts in {TEST_CONTRACTS_DIR}:")
        for m in missing:
            print(f"  - {m}")
        sys.exit(2)

    # Run tests
    results = []
    total_start = time.time()
    fp_count = 0
    pass_count = 0
    error_count = 0

    for i, entry in enumerate(TEST_MANIFEST, 1):
        filepath = os.path.join(TEST_CONTRACTS_DIR, entry["file"])

        if not json_mode:
            print(f"[{i}/{len(TEST_MANIFEST)}] {entry['file']} ({entry['pattern']})")
            print(f"  FP risk factors: {entry['fp_risk']}")

        result = run_single_test(detector, filepath)

        record = {
            "index": i,
            "file": entry["file"],
            "pattern": entry["pattern"],
            "description": entry["description"],
            "fp_risk_factors": entry["fp_risk"],
            **result,
        }

        if result["status"] == "error":
            error_count += 1
            verdict = "ERROR"
        elif result["score"] >= FP_THRESHOLD:
            fp_count += 1
            verdict = "FAIL (FALSE POSITIVE)"
        else:
            pass_count += 1
            verdict = "PASS"

        record["verdict"] = verdict
        results.append(record)

        if not json_mode:
            if result["status"] == "ok":
                print(f"  Score: {result['score']:.4f} | Level: {result['risk_level']} | {verdict}")
                if result["flags"]:
                    print(f"  Flags: {', '.join(result['flags'])}")
            else:
                print(f"  {verdict}: {result.get('error', 'unknown')}")
            print(f"  Time: {result['elapsed_sec']}s")
            print()

    total_elapsed = round(time.time() - total_start, 2)

    # Summary
    summary = {
        "suite": "proxy_diamond_create2_fp_test",
        "version": "V1.0_202604120850",
        "run_timestamp_jst": run_time,
        "total_contracts": len(TEST_MANIFEST),
        "passed": pass_count,
        "false_positives": fp_count,
        "errors": error_count,
        "fp_rate": f"{fp_count}/{len(TEST_MANIFEST)}",
        "fp_rate_pct": round(fp_count / len(TEST_MANIFEST) * 100, 1) if TEST_MANIFEST else 0,
        "total_elapsed_sec": total_elapsed,
        "fp_threshold": FP_THRESHOLD,
        "overall_verdict": "PASS" if fp_count == 0 and error_count == 0 else "FAIL",
    }

    if json_mode:
        output = {"summary": summary, "results": results}
        print(json.dumps(output, indent=2, ensure_ascii=False))
    else:
        print("=" * 70)
        print("  SUMMARY")
        print("=" * 70)
        print(f"  Total:           {summary['total_contracts']}")
        print(f"  Passed:          {summary['passed']}")
        print(f"  False Positives: {summary['false_positives']}")
        print(f"  Errors:          {summary['errors']}")
        print(f"  FP Rate:         {summary['fp_rate']} ({summary['fp_rate_pct']}%)")
        print(f"  Total Time:      {summary['total_elapsed_sec']}s")
        print(f"  Verdict:         {summary['overall_verdict']}")
        print("=" * 70)

        if fp_count > 0:
            print()
            print("  ⚠ FALSE POSITIVES DETECTED — detector needs safety-aware patches")
            print("  FP contracts:")
            for r in results:
                if r["verdict"] == "FAIL (FALSE POSITIVE)":
                    print(f"    - {r['file']}: score={r['score']:.4f} ({r['risk_level']})")
                    print(f"      Pattern: {r['pattern']}")
                    if r.get("flags"):
                        print(f"      Flags: {', '.join(r['flags'])}")

    # Save JSON report
    report_filename = f"proxy_fp_test_report_{run_time}.json"
    report_path = os.path.join(SCRIPT_DIR, report_filename)
    try:
        report_data = {"summary": summary, "results": results}
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        if not json_mode:
            print(f"\n  Report saved: {report_filename}")
    except Exception as e:
        if not json_mode:
            print(f"\n  [WARN] Could not save report: {e}")

    # Exit code: 0 = all pass, 1 = FP detected, 2 = errors
    if error_count > 0:
        sys.exit(2)
    elif fp_count > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
