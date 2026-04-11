"""
HELIX Attack Replay Verification Runner
Version: V1.0.01_202604120000
Purpose: Run all 50 historical attack contracts through mismatch_detector
         and measure true positive detection rate.

Usage:
  cd D:\\Projects\\helix
  .venv\\Scripts\\activate
  python replay_test_runner.py

Output:
  - Console summary with detection rates
  - replay_test_report_{timestamp}.json
"""

import json
import time
import sys
import os
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from attack_replay_contracts import REPLAY_CONTRACTS

# Known limitations — these SIGs cannot be detected by current MVP
KNOWN_UNDETECTABLE = {
    "SIG-012": "Off-chain key compromise (vanity address) — no on-chain pattern",
    "SIG-034": "Pre-Solidity 0.8 integer overflow — no unchecked{} keyword",
    "SIG-035": "Pre-Solidity 0.8 integer overflow — no unchecked{} keyword",
}

# SIGs beyond MVP scope (rug_pull, pure logic_error)
BEYOND_MVP = {"SIG-037", "SIG-038", "SIG-041", "SIG-042", "SIG-043"}


def run_replay():
    print("=" * 60)
    print("  HELIX Attack Replay Verification")
    print("  50 Historical Attacks × mismatch_detector")
    print("=" * 60)
    print()
    print("Loading detector...")

    try:
        from mismatch_detector import IntentCodeMismatchDetector, ContractInput
    except ImportError as e:
        print(f"ERROR: {e}")
        sys.exit(1)

    detector = IntentCodeMismatchDetector()
    print("Model loaded. Running replay...\n")

    results = []
    detected = 0
    missed = 0
    beyond_count = 0
    known_miss = 0
    start = time.time()

    for i, contract in enumerate(REPLAY_CONTRACTS):
        sid = contract["sig_id"]
        source = contract["source"]
        expected = contract["expected_patterns"]

        is_beyond = sid in BEYOND_MVP
        is_known_miss = sid in KNOWN_UNDETECTABLE

        try:
            ci = ContractInput(source_code=source, contract_address=f"0xREPLAY_{sid}")
            report = detector.analyze(ci)

            score = report.overall_mismatch_score
            risk = report.risk_level
            patterns_found = []
            for fr in report.function_reports:
                if getattr(fr, 'attack_class', None):
                    patterns_found.append(fr.attack_class)

            # Detection = score >= MEDIUM (0.10) or any attack_class identified
            is_detected = risk in ("MEDIUM", "HIGH", "CRITICAL") or len(patterns_found) > 0

            result = {
                "sig_id": sid,
                "score": round(score, 4),
                "risk_level": risk,
                "patterns_found": patterns_found,
                "expected_patterns": expected,
                "detected": is_detected,
                "is_beyond_mvp": is_beyond,
                "is_known_limitation": is_known_miss,
            }

        except Exception as e:
            result = {
                "sig_id": sid,
                "score": -1,
                "risk_level": "ERROR",
                "patterns_found": [],
                "expected_patterns": expected,
                "detected": False,
                "error": str(e),
                "is_beyond_mvp": is_beyond,
                "is_known_limitation": is_known_miss,
            }

        results.append(result)

        if is_beyond:
            beyond_count += 1
            status = "BEYOND"
            marker = "⬜"
        elif is_known_miss:
            known_miss += 1
            status = "KNOWN"
            marker = "⚠️"
        elif result["detected"]:
            detected += 1
            status = "HIT"
            marker = "✅"
        else:
            missed += 1
            status = "MISS"
            marker = "❌"

        print(f"  [{i+1:3d}/50] {marker} {sid}  score={result['score']:.4f}  {result['risk_level']:<10s}  {status}")

    elapsed = time.time() - start

    # Summary
    detectable = 50 - beyond_count - known_miss
    hit_rate = detected / detectable * 100 if detectable > 0 else 0

    print()
    print("=" * 60)
    print("  RESULTS")
    print("=" * 60)
    print(f"  Total attacks:           50")
    print(f"  Beyond MVP scope:        {beyond_count} (rug_pull, logic_error)")
    print(f"  Known limitations:       {known_miss} (off-chain, pre-0.8)")
    print(f"  Detectable scope:        {detectable}")
    print()
    print(f"  DETECTED:                {detected} / {detectable}")
    print(f"  HIT RATE:                {hit_rate:.1f}%")
    print(f"  MISSED:                  {missed}")
    print(f"  Time:                    {elapsed:.1f}s")

    if missed > 0:
        print(f"\n  Missed attacks:")
        for r in results:
            if not r["detected"] and not r["is_beyond_mvp"] and not r["is_known_limitation"]:
                print(f"    {r['sig_id']}: score={r['score']} risk={r['risk_level']} expected={r['expected_patterns']}")

    # Save report
    jst = timezone(timedelta(hours=9))
    ts = datetime.now(jst).strftime("%Y%m%d%H%M")

    report = {
        "test_name": "HELIX Attack Replay Verification",
        "version": "V1.0.01",
        "timestamp_jst": ts,
        "summary": {
            "total_attacks": 50,
            "beyond_mvp": beyond_count,
            "known_limitations": known_miss,
            "detectable_scope": detectable,
            "detected": detected,
            "hit_rate_pct": round(hit_rate, 2),
            "missed": missed,
            "elapsed_seconds": round(elapsed, 1),
        },
        "known_limitations": KNOWN_UNDETECTABLE,
        "results": results,
    }

    path = f"replay_test_report_{ts}.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"\n  Report: {path}")
    print("=" * 60)
    return report


if __name__ == "__main__":
    run_replay()
