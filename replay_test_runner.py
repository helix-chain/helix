"""
HELIX Attack Replay Verification Runner
Purpose: replay the historical attack contracts through mismatch_detector.

Usage:
  python replay_test_runner.py

Output:
  - Per-contract progress and a gate summary
  - replay_test_report_{timestamp}.json in the current directory
"""

import json
import os
import sys
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from attack_replay_contracts import REPLAY_CONTRACTS

# Known limitations: these signatures cannot be detected by the current MVP.
KNOWN_UNDETECTABLE = {
    "SIG-012": "Off-chain key compromise (vanity address) — no on-chain pattern",
    "SIG-034": "Pre-Solidity 0.8 integer overflow — no unchecked{} keyword",
    "SIG-035": "Pre-Solidity 0.8 integer overflow — no unchecked{} keyword",
}

# Signatures outside MVP scope (rug_pull and pure logic_error).
BEYOND_MVP = {"SIG-037", "SIG-038", "SIG-041", "SIG-042", "SIG-043"}

# Measured with the real model, torch 2.12.1+cpu, 2026-10. These 20
# detectable signatures were flagged but their expected pattern was not found.
PATTERN_GAP_BASELINE = {
    "SIG-002", "SIG-007", "SIG-008", "SIG-010", "SIG-011",
    "SIG-014", "SIG-016", "SIG-018", "SIG-020", "SIG-025",
    "SIG-029", "SIG-030", "SIG-031", "SIG-032", "SIG-033",
    "SIG-036", "SIG-047", "SIG-048", "SIG-049", "SIG-050",
}


def _known_map(values):
    if isinstance(values, dict):
        return dict(values)
    return {sig_id: "Injected known limitation" for sig_id in values}


def _validate_integrity(contracts, beyond_mvp, known_ids, pattern_gap_baseline):
    issues = []
    sig_ids = []
    for index, contract in enumerate(contracts):
        if not isinstance(contract, dict) or not contract.get("sig_id"):
            issues.append(f"contract at index {index} has no sig_id")
        else:
            sig_ids.append(contract["sig_id"])

    seen = set()
    duplicates = set()
    for sig_id in sig_ids:
        if sig_id in seen:
            duplicates.add(sig_id)
        seen.add(sig_id)
    if duplicates:
        issues.append("duplicate sig_ids: " + ", ".join(sorted(duplicates)))

    contract_ids = set(sig_ids)
    unknown_beyond = set(beyond_mvp) - contract_ids
    if unknown_beyond:
        issues.append(
            "BEYOND_MVP contains unknown signature ids: "
            + ", ".join(sorted(unknown_beyond))
        )

    unknown_known = set(known_ids) - contract_ids
    if unknown_known:
        issues.append(
            "KNOWN_UNDETECTABLE contains unknown signature ids: "
            + ", ".join(sorted(unknown_known))
        )

    overlap = set(beyond_mvp) & set(known_ids)
    if overlap:
        issues.append(
            "BEYOND_MVP and KNOWN_UNDETECTABLE overlap: "
            + ", ".join(sorted(overlap))
        )

    detectable_ids = contract_ids - set(beyond_mvp) - set(known_ids)
    outside_baseline = set(pattern_gap_baseline) - detectable_ids
    if outside_baseline:
        issues.append(
            "PATTERN_GAP_BASELINE must be a subset of detectable signature ids: "
            + ", ".join(sorted(outside_baseline))
        )
    return issues


def _patterns_in_evidence(function_reports, risk_pattern_names):
    found = set()
    for function_report in function_reports:
        evidence = getattr(function_report, "evidence", "") or ""
        for token in evidence.split(";"):
            pattern_name = token.strip()
            if pattern_name in risk_pattern_names:
                found.add(pattern_name)
    return sorted(found)


def _evaluate_replay(
    contracts,
    detector,
    contract_input_factory,
    risk_pattern_names,
    beyond_mvp,
    known_ids,
    pattern_gap_baseline,
):
    results = []
    for contract in contracts:
        sig_id = contract["sig_id"]
        expected = list(contract.get("expected_patterns") or [])
        is_beyond = sig_id in beyond_mvp
        is_known = sig_id in known_ids

        try:
            contract_input = contract_input_factory(
                source_code=contract["source"],
                contract_address=f"0xREPLAY_{sig_id}",
            )
            report = detector.analyze(contract_input)

            score = report.overall_mismatch_score
            risk = report.risk_level
            function_reports = report.function_reports
            patterns_found = [
                function_report.attack_class
                for function_report in function_reports
                if getattr(function_report, "attack_class", None)
            ]
            patterns_found_in_evidence = _patterns_in_evidence(
                function_reports, risk_pattern_names
            )

            # Keep the historical flagged-risk metric unchanged.
            is_detected = risk in ("MEDIUM", "HIGH", "CRITICAL") or bool(patterns_found)
            pattern_confirmed = bool(
                expected and (set(expected) & set(patterns_found_in_evidence))
            )
            result = {
                "sig_id": sig_id,
                "score": round(score, 4),
                "risk_level": risk,
                "patterns_found": patterns_found,
                "expected_patterns": expected,
                "detected": is_detected,
                "is_beyond_mvp": is_beyond,
                "is_known_limitation": is_known,
                "patterns_found_in_evidence": patterns_found_in_evidence,
                "pattern_confirmed": pattern_confirmed,
            }
        except Exception as error:
            result = {
                "sig_id": sig_id,
                "score": -1,
                "risk_level": "ERROR",
                "patterns_found": [],
                "expected_patterns": expected,
                "detected": False,
                "error": str(error),
                "is_beyond_mvp": is_beyond,
                "is_known_limitation": is_known,
                "patterns_found_in_evidence": [],
                "pattern_confirmed": False,
            }
        results.append(result)

    beyond_count = sum(result["is_beyond_mvp"] for result in results)
    known_count = sum(result["is_known_limitation"] for result in results)
    detectable_results = [
        result
        for result in results
        if not result["is_beyond_mvp"] and not result["is_known_limitation"]
    ]
    detected = sum(result["detected"] for result in detectable_results)
    missed = sum(
        not result["detected"] and "error" not in result
        for result in detectable_results
    )
    detector_errors = sum("error" in result for result in results)
    pattern_confirmed = sum(
        result["detected"] and result["pattern_confirmed"]
        for result in detectable_results
    )

    pattern_gap_baselined = 0
    pattern_gap_new = 0
    for result in detectable_results:
        if (
            result["detected"]
            and result["expected_patterns"]
            and not result["pattern_confirmed"]
        ):
            if result["sig_id"] in pattern_gap_baseline:
                pattern_gap_baselined += 1
            else:
                pattern_gap_new += 1

    detectable_scope = len(results) - beyond_count - known_count
    hit_rate = detected / detectable_scope * 100 if detectable_scope else 0
    exit_code = 2 if detector_errors else (
        1 if missed or pattern_gap_new else 0
    )
    summary = {
        "total_attacks": len(contracts),
        "beyond_mvp": beyond_count,
        "known_limitations": known_count,
        "detectable_scope": detectable_scope,
        "detected": detected,
        "hit_rate_pct": round(hit_rate, 2),
        "missed": missed,
        "elapsed_seconds": 0.0,
        "pattern_confirmed": pattern_confirmed,
        "pattern_gap_baselined": pattern_gap_baselined,
        "pattern_gap_new": pattern_gap_new,
        "errors": detector_errors,
        "exit_code": exit_code,
    }
    return results, summary


def _empty_summary(contracts, beyond_mvp, known_ids, *, errors, exit_code):
    beyond_count = sum(contract.get("sig_id") in beyond_mvp for contract in contracts)
    known_count = sum(contract.get("sig_id") in known_ids for contract in contracts)
    detectable_scope = len(contracts) - beyond_count - known_count
    return {
        "total_attacks": len(contracts),
        "beyond_mvp": beyond_count,
        "known_limitations": known_count,
        "detectable_scope": detectable_scope,
        "detected": 0,
        "hit_rate_pct": 0.0,
        "missed": 0,
        "elapsed_seconds": 0.0,
        "pattern_confirmed": 0,
        "pattern_gap_baselined": 0,
        "pattern_gap_new": 0,
        "errors": errors,
        "exit_code": exit_code,
    }


def get_exit_code(report):
    """Return the process verdict carried by a replay report."""
    return int(report["summary"]["exit_code"])


def _print_summary(report):
    summary = report["summary"]
    detectable = summary["detectable_scope"]
    print()
    print("=" * 60)
    print("  RESULTS")
    print("=" * 60)
    print(f"  Total attacks:           {summary['total_attacks']}")
    print(f"  Beyond MVP scope:        {summary['beyond_mvp']}")
    print(f"  Known limitations:       {summary['known_limitations']}")
    print(f"  Detectable scope:        {detectable}")
    print()
    print(
        f"  DETECTED {summary['detected']}/{detectable} "
        "(flagged risky, legacy metric)"
    )
    print(f"  PATTERN-CONFIRMED {summary['pattern_confirmed']}/{detectable}")
    print(f"  baselined gaps: {summary['pattern_gap_baselined']}")
    print(f"  NEW gaps: {summary['pattern_gap_new']}")
    print(f"  MISSED: {summary['missed']}")
    print(f"  ERRORS: {summary['errors']}")
    print(
        f"  VERDICT: {'PASS' if summary['exit_code'] == 0 else 'FAIL'} "
        f"(exit code {summary['exit_code']})"
    )
    print(f"  HIT RATE: {summary['hit_rate_pct']:.1f}%")
    print(f"  Time:                    {summary['elapsed_seconds']:.1f}s")


def _write_report(report, report_dir):
    jst = timezone(timedelta(hours=9))
    timestamp = datetime.now(jst).strftime("%Y%m%d%H%M")
    report["timestamp_jst"] = timestamp
    filename = f"replay_test_report_{timestamp}.json"
    path = Path(report_dir) / filename if report_dir is not None else Path(filename)
    with path.open("w", encoding="utf-8") as report_file:
        json.dump(report, report_file, indent=2, ensure_ascii=False)
    print(f"\n  Report: {path}")
    print("=" * 60)


def run_replay(
    contracts=None,
    detector=None,
    report_dir=None,
    beyond_mvp=None,
    known_undetectable=None,
    pattern_gap_baseline=None,
    exit_code_callback=None,
):
    # Keep console output safe on Windows consoles with a legacy encoding.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    contracts = list(REPLAY_CONTRACTS if contracts is None else contracts)
    beyond_mvp = set(BEYOND_MVP if beyond_mvp is None else beyond_mvp)
    known_map = _known_map(
        KNOWN_UNDETECTABLE if known_undetectable is None else known_undetectable
    )
    known_ids = set(known_map)
    pattern_gap_baseline = set(
        PATTERN_GAP_BASELINE
        if pattern_gap_baseline is None
        else pattern_gap_baseline
    )

    print("=" * 60)
    print("  HELIX Attack Replay Verification")
    print(f"  {len(contracts)} Historical Attacks x mismatch_detector")
    print("=" * 60)
    print()
    print("Loading detector...")

    integrity_issues = _validate_integrity(
        contracts, beyond_mvp, known_ids, pattern_gap_baseline
    )
    if integrity_issues:
        for issue in integrity_issues:
            print(f"  INTEGRITY ERROR: {issue}")
        summary = _empty_summary(
            contracts,
            beyond_mvp,
            known_ids,
            errors=len(integrity_issues),
            exit_code=2,
        )
        report = {
            "test_name": "HELIX Attack Replay Verification",
            "version": "V1.0.01",
            "timestamp_jst": "",
            "summary": summary,
            "known_limitations": known_map,
            "results": [],
        }
        _print_summary(report)
        _write_report(report, report_dir)
        if exit_code_callback is not None:
            exit_code_callback(2)
        return report

    try:
        # Import remains lazy so this module loads without torch.
        from mismatch_detector import (
            CodeEncoder,
            ContractInput,
            IntentCodeMismatchDetector,
        )
    except ImportError as error:
        print(f"ERROR: {error}")
        summary = _empty_summary(
            contracts, beyond_mvp, known_ids, errors=1, exit_code=2
        )
        report = {
            "test_name": "HELIX Attack Replay Verification",
            "version": "V1.0.01",
            "timestamp_jst": "",
            "summary": summary,
            "known_limitations": known_map,
            "results": [],
        }
        _print_summary(report)
        _write_report(report, report_dir)
        if exit_code_callback is not None:
            exit_code_callback(2)
        return report

    if detector is None:
        try:
            detector = IntentCodeMismatchDetector()
        except Exception as error:
            print(f"ERROR: detector initialization failed: {error}")
            summary = _empty_summary(
                contracts, beyond_mvp, known_ids, errors=1, exit_code=2
            )
            report = {
                "test_name": "HELIX Attack Replay Verification",
                "version": "V1.0.01",
                "timestamp_jst": "",
                "summary": summary,
                "known_limitations": known_map,
                "results": [],
            }
            _print_summary(report)
            _write_report(report, report_dir)
            if exit_code_callback is not None:
                exit_code_callback(2)
            return report

    print("Model loaded. Running replay.\n")
    start = time.time()
    results, summary = _evaluate_replay(
        contracts,
        detector,
        ContractInput,
        set(CodeEncoder.RISK_PATTERNS),
        beyond_mvp,
        known_ids,
        pattern_gap_baseline,
    )
    summary["elapsed_seconds"] = round(time.time() - start, 1)

    for index, result in enumerate(results, start=1):
        if "error" in result:
            status = "ERROR"
        elif result["is_beyond_mvp"]:
            status = "BEYOND"
        elif result["is_known_limitation"]:
            status = "KNOWN"
        elif result["detected"]:
            status = "HIT"
        else:
            status = "MISS"

        expected_note = (
            "pattern=n/a"
            if not result["expected_patterns"]
            else (
                "pattern=confirmed"
                if result["pattern_confirmed"]
                else "pattern=gap"
            )
        )
        print(
            f"  [{index:3d}/{len(contracts)}] [{status}] {result['sig_id']}  "
            f"score={result['score']:.4f}  {result['risk_level']:<10s}  "
            f"{expected_note}"
        )
        if (
            result["sig_id"] in pattern_gap_baseline
            and result["pattern_confirmed"]
        ):
            print(
                f"    TIGHTEN BASELINE: {result['sig_id']} is now "
                "pattern-confirmed."
            )

    report = {
        "test_name": "HELIX Attack Replay Verification",
        "version": "V1.0.01",
        "timestamp_jst": "",
        "summary": summary,
        "known_limitations": known_map,
        "results": results,
    }
    _print_summary(report)

    missed_results = [
        result
        for result in results
        if not result["detected"]
        and "error" not in result
        and not result["is_beyond_mvp"]
        and not result["is_known_limitation"]
    ]
    if missed_results:
        print()
        print("  Missed attacks:")
        for result in missed_results:
            print(
                f"    {result['sig_id']}: score={result['score']} "
                f"risk={result['risk_level']} "
                f"expected={result['expected_patterns']}"
            )

    error_results = [result for result in results if "error" in result]
    if error_results:
        print()
        print("  Detector errors:")
        for result in error_results:
            print(f"    {result['sig_id']}: {result['error']}")

    _write_report(report, report_dir)
    if exit_code_callback is not None:
        exit_code_callback(summary["exit_code"])
    return report


def main():
    report = run_replay()
    sys.exit(get_exit_code(report))


if __name__ == "__main__":
    main()
