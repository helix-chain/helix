"""
ci_smoke_test.py
Version: V1.0_202604120942
Description: Minimal CI smoke test for mismatch_detector regression guard.
             Validates two invariants:
               1. SafeToken.sol → LOW (clean contract, no false positive)
               2. VulnerableVault.sol → CRITICAL (known vulnerable, true positive)
             Exit 0 = PASS, Exit 1 = FAIL, Exit 2 = ERROR
Usage: python ci_smoke_test.py [--json]
"""

import os
import sys
import json
import time
from datetime import datetime, timezone, timedelta

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

TESTS = [
    {
        "file": "SafeToken.sol",
        "expected_level": "LOW",
        "expected_max_score": 0.10,
        "role": "clean_contract_fp_guard",
    },
    {
        "file": "VulnerableVault.sol",
        "expected_level": "CRITICAL",
        "expected_min_score": 0.45,
        "role": "vulnerable_contract_tp_guard",
    },
]


def main():
    json_mode = "--json" in sys.argv
    jst = timezone(timedelta(hours=9))
    run_time = datetime.now(jst).strftime("%Y%m%d%H%M")

    sys.path.insert(0, SCRIPT_DIR)
    try:
        import mismatch_detector
    except ImportError as e:
        print(f"[ERROR] Cannot import mismatch_detector: {e}")
        sys.exit(2)

    results = []
    all_pass = True
    total_start = time.time()

    for t in TESTS:
        filepath = os.path.join(SCRIPT_DIR, t["file"])
        if not os.path.exists(filepath):
            results.append({"file": t["file"], "status": "error", "error": "file not found"})
            all_pass = False
            continue

        with open(filepath, "r", encoding="utf-8") as f:
            source = f.read()

        start = time.time()
        try:
            res = mismatch_detector.analyze_contract(source)
            elapsed = round(time.time() - start, 2)
        except Exception as e:
            results.append({"file": t["file"], "status": "error", "error": str(e), "elapsed_sec": round(time.time() - start, 2)})
            all_pass = False
            continue

        score = res.get("risk_score", 0.0)
        level = res.get("risk_level", "UNKNOWN")
        passed = True
        reason = ""

        if "expected_level" in t and t["role"] == "clean_contract_fp_guard":
            if score >= t["expected_max_score"]:
                passed = False
                reason = f"score {score:.4f} >= {t['expected_max_score']} (false positive)"
            if level not in ("LOW",):
                passed = False
                reason = f"level {level} != LOW (false positive)"

        if "expected_level" in t and t["role"] == "vulnerable_contract_tp_guard":
            if score < t["expected_min_score"]:
                passed = False
                reason = f"score {score:.4f} < {t['expected_min_score']} (missed detection)"
            if level != "CRITICAL":
                passed = False
                reason = f"level {level} != CRITICAL (missed detection)"

        if not passed:
            all_pass = False

        results.append({
            "file": t["file"],
            "role": t["role"],
            "status": "ok",
            "score": score,
            "risk_level": level,
            "passed": passed,
            "reason": reason if not passed else "as expected",
            "elapsed_sec": elapsed,
        })

    total_elapsed = round(time.time() - total_start, 2)

    report = {
        "suite": "ci_smoke_test",
        "version": "V1.0_202604120942",
        "run_timestamp_jst": run_time,
        "total_tests": len(TESTS),
        "passed": sum(1 for r in results if r.get("passed", False)),
        "failed": sum(1 for r in results if r.get("status") == "ok" and not r.get("passed", False)),
        "errors": sum(1 for r in results if r.get("status") == "error"),
        "total_elapsed_sec": total_elapsed,
        "overall_verdict": "PASS" if all_pass else "FAIL",
        "results": results,
    }

    if json_mode:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print("=" * 60)
        print("  HELIX CI Smoke Test")
        print(f"  Version: V1.0_202604120942")
        print(f"  Run: {run_time} JST")
        print("=" * 60)
        for r in results:
            status = "✅ PASS" if r.get("passed") else "❌ FAIL" if r.get("status") == "ok" else "⚠ ERROR"
            print(f"  {r['file']}: {status}")
            if r.get("status") == "ok":
                print(f"    Score: {r['score']:.4f} | Level: {r['risk_level']} | {r['reason']}")
            elif r.get("error"):
                print(f"    Error: {r['error']}")
        print("=" * 60)
        print(f"  Verdict: {report['overall_verdict']} ({report['passed']}/{report['total_tests']} passed)")
        print(f"  Time: {total_elapsed}s")
        print("=" * 60)

    # Save report
    report_path = os.path.join(SCRIPT_DIR, f"ci_smoke_report_{run_time}.json")
    try:
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
    except Exception:
        pass

    sys.exit(0 if all_pass else 1)


if __name__ == "__main__":
    main()
