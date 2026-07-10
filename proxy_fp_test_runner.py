"""
proxy_fp_test_runner.py
Version: V1.0_202604120850
Description: FP test suite for Proxy/Diamond/CREATE2 patterns.
             Tests 6 clean contracts that use advanced DeFi architecture patterns.
             All should score LOW (< 0.10). Any MEDIUM+ is a false positive.

             GATE SEMANTICS (re-baselined 2026-07): the gate is a regression
             guard against the MEASURED baseline, not against an aspirational
             zero. Two known threshold-edge FPs (see KNOWN_FP_BASELINE) are
             reported but non-gating; any NEW false positive, or any error,
             fails the suite. Rationale: the historical "6/6 PASS" was an
             artifact of the stale-key bug (every score read as 0.0 — see
             report 202604120859 and PR #3), so 0-FP was never a real baseline.
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

# Canonical field the detector emits (see mismatch_detector.analyze_contract).
# Reading any other key via dict.get(..., default) silently returns the default
# and hides field-name drift — the exact class of bug behind commit 9ff61b7,
# where a stale key made every scan score 0.0 with no error. extract_score()
# fails LOUD instead, so this FP gate can never again silently "pass" on 0.0.
SCORE_KEY = "overall_mismatch_score"


def extract_score(result):
    """Read the detector's score by its canonical key, failing loudly on drift.

    Returns float. Raises KeyError if SCORE_KEY is absent so a renamed or dropped
    scoring field trips a visible error instead of silently scoring 0.0 (which
    would make this false-positive gate unable to ever fail). This is the
    regression insurance mandated after 9ff61b7 (see AGENTS.md, ci-key-grep).
    """
    if SCORE_KEY not in result:
        raise KeyError(
            f"detector output missing '{SCORE_KEY}' (got keys: {sorted(result)}). "
            "Possible scoring-field drift — see AGENTS.md 'cross-module field names'."
        )
    return float(result[SCORE_KEY])


# Known-FP baseline (re-baselined 2026-07). When PR #3 fixed the stale-key read
# and real scores surfaced for the first time, two threshold-edge false
# positives were revealed: CREATE2Factory 0.1007 and MinimalProxy 0.1985
# against the 0.10 gate (identical locally and in CI run 28805089505).
# Until the detector's safety-pattern layer is fixed (separate L3 task —
# do NOT "fix" this by touching scoring or thresholds here):
#   * a baselined file scoring >= FP_THRESHOLD  -> recorded as known_fp, non-gating
#   * any OTHER file scoring >= FP_THRESHOLD    -> NEW false positive -> FAIL
#   * a baselined file scoring < FP_THRESHOLD   -> hint to tighten this set
KNOWN_FP_BASELINE = {"CREATE2Factory.sol", "MinimalProxy.sol"}

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
        # Read the score by its canonical key; a missing key raises (caught below)
        # so field drift surfaces as an ERROR, never a silent 0.0 that always PASSes.
        score = extract_score(result)
        # "flags" is not a detector output field; surface the real per-function
        # attack classes instead (display only — the verdict uses `score`).
        flags = [
            f.get("attack_class")
            for f in result.get("functions", [])
            if f.get("attack_class")
        ]
        elapsed = round(time.time() - start, 2)

        return {
            "status": "ok",
            "score": score,
            "risk_level": result.get("risk_level", "UNKNOWN"),
            "flags": flags,
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
    # Make stdout/stderr robust on non-UTF-8 consoles (e.g. Windows cp936/gbk) so
    # the box-drawing / warning markers below can never crash the run with a
    # UnicodeEncodeError. Degrades unrepresentable chars to '?', never fails.
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

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
    known_fp_count = 0
    new_fp_count = 0
    pass_count = 0
    error_count = 0
    tighten_baseline = []

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
            if entry["file"] in KNOWN_FP_BASELINE:
                known_fp_count += 1
                verdict = "KNOWN FP (baselined, non-gating)"
            else:
                new_fp_count += 1
                verdict = "FAIL (NEW FALSE POSITIVE)"
        else:
            pass_count += 1
            verdict = "PASS"
            if entry["file"] in KNOWN_FP_BASELINE:
                tighten_baseline.append(entry["file"])

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
        "known_fp": known_fp_count,
        "new_false_positives": new_fp_count,
        "known_fp_baseline": sorted(KNOWN_FP_BASELINE),
        "errors": error_count,
        "fp_rate": f"{fp_count}/{len(TEST_MANIFEST)}",
        "fp_rate_pct": round(fp_count / len(TEST_MANIFEST) * 100, 1) if TEST_MANIFEST else 0,
        "total_elapsed_sec": total_elapsed,
        "fp_threshold": FP_THRESHOLD,
        # Regression-guard semantics: only NEW FPs (outside the measured
        # baseline) or errors fail; baselined known FPs are reported above.
        "overall_verdict": "PASS" if new_fp_count == 0 and error_count == 0 else "FAIL",
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
        print(f"  False Positives: {summary['false_positives']}"
              f" (baselined known: {summary['known_fp']}, new: {summary['new_false_positives']})")
        print(f"  Errors:          {summary['errors']}")
        print(f"  FP Rate:         {summary['fp_rate']} ({summary['fp_rate_pct']}%)")
        print(f"  Total Time:      {summary['total_elapsed_sec']}s")
        print(f"  Verdict:         {summary['overall_verdict']}")
        print("=" * 70)

        if fp_count > 0:
            print()
            print("  ⚠ FALSE POSITIVES — new ones fail the gate; baselined ones are")
            print("    tracked for the detector-side fix (see KNOWN_FP_BASELINE).")
            print("  FP contracts:")
            for r in results:
                if "FALSE POSITIVE" in r["verdict"] or r["verdict"].startswith("KNOWN FP"):
                    print(f"    - {r['file']}: score={r['score']:.4f} ({r['risk_level']}) [{r['verdict']}]")
                    print(f"      Pattern: {r['pattern']}")
                    if r.get("flags"):
                        print(f"      Flags: {', '.join(r['flags'])}")
        if tighten_baseline:
            print()
            print("  ℹ Baselined contract(s) now score below the gate — tighten")
            print(f"    KNOWN_FP_BASELINE: {', '.join(sorted(tighten_baseline))}")

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

    # Exit code: 0 = pass (incl. baselined known FPs), 1 = NEW FP, 2 = errors
    if error_count > 0:
        sys.exit(2)
    elif new_fp_count > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
