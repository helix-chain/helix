"""
HELIX CLI — helix scan <file.sol>
Version: V1.0_202604120106

Minimal CLI wrapper for the Intent-Code Mismatch Detector.
Imports analyze_contract() from the same directory's mismatch_detector.py.

Usage:
    helix scan <file.sol> [--address 0x...] [--json]
    helix scan --help

Exit codes:
    0 = LOW or MEDIUM (safe to proceed)
    1 = HIGH or CRITICAL (action required)
    2 = Runtime error / argument error / file error
"""

import sys
import os
import time
import json

# ── Ensure import from same directory (not ai-engine or other paths) ──
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if _SCRIPT_DIR not in sys.path:
    sys.path.insert(0, _SCRIPT_DIR)

try:
    from mismatch_detector import analyze_contract
except ImportError as e:
    print(f"[ERROR] Cannot import mismatch_detector from {_SCRIPT_DIR}: {e}")
    sys.exit(2)


VERSION = "V1.0_202604120106"

HELP_TEXT = f"""
HELIX Intent-Code Mismatch Detector CLI  {VERSION}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Usage:
    helix scan <file.sol> [--address 0x...] [--json]
    python helix_scan.py scan <file.sol> [--address 0x...] [--json]

Options:
    --address 0x...   Attach contract address to report
    --json            Output raw JSON instead of human-readable summary

Exit codes:
    0   LOW or MEDIUM — safe to proceed
    1   HIGH or CRITICAL — manual review required
    2   Runtime error (bad arguments, file not found, etc.)

Examples:
    helix scan VulnerableVault.sol
    helix scan Token.sol --address 0xA0b8...eB48 --json
"""


def parse_args(argv):
    """Minimal argument parser. Returns (sol_path, address, json_mode) or exits."""
    args = argv[1:]  # strip script name

    # Strip 'scan' subcommand if present
    if args and args[0] == "scan":
        args = args[1:]

    if not args or args[0] in ("--help", "-h"):
        print(HELP_TEXT)
        sys.exit(0)

    sol_path = None
    address = None
    json_mode = False

    i = 0
    while i < len(args):
        if args[i] == "--address" and i + 1 < len(args):
            address = args[i + 1]
            i += 2
        elif args[i] == "--json":
            json_mode = True
            i += 1
        elif args[i].startswith("--"):
            print(f"[ERROR] Unknown option: {args[i]}")
            sys.exit(2)
        elif sol_path is None:
            sol_path = args[i]
            i += 1
        else:
            print(f"[ERROR] Unexpected argument: {args[i]}")
            sys.exit(2)

    if sol_path is None:
        print("[ERROR] No .sol file specified.")
        print("  Usage: helix scan <file.sol> [--address 0x...] [--json]")
        sys.exit(2)

    return sol_path, address, json_mode


def validate_file(sol_path):
    """Validate the .sol file exists and is readable. Returns source code or exits."""
    if not os.path.isfile(sol_path):
        print(f"[ERROR] File not found: {sol_path}")
        sys.exit(2)

    if not sol_path.lower().endswith(".sol"):
        print(f"[WARNING] File does not have .sol extension: {sol_path}")
        print("         Proceeding anyway...")

    try:
        with open(sol_path, "r", encoding="utf-8") as f:
            source = f.read()
    except Exception as e:
        print(f"[ERROR] Cannot read file: {e}")
        sys.exit(2)

    if not source.strip():
        print(f"[ERROR] File is empty: {sol_path}")
        sys.exit(2)

    return source


def print_human_report(result, elapsed):
    """Print human-readable formatted report."""
    risk = result["risk_level"]
    score = result["overall_mismatch_score"]
    funcs = result.get("functions", [])

    # Risk level color hint (for terminals that support it)
    risk_marker = {"LOW": ".", "MEDIUM": "~", "HIGH": "!", "CRITICAL": "!!!"}

    print()
    print(f"  HELIX Scan Result")
    print(f"  ━━━━━━━━━━━━━━━━")
    print(f"  Risk Level : {risk} {risk_marker.get(risk, '')}")
    print(f"  Score      : {score:.4f}")
    print(f"  Action     : {result.get('recommended_action', 'N/A')}")
    if result.get("contract_address"):
        print(f"  Address    : {result['contract_address']}")
    print(f"  Functions  : {len(funcs)} analyzed")
    print(f"  Time       : {elapsed:.1f}s")
    print()

    if funcs:
        print(f"  {'Function':<30} {'Score':<9} {'Level':<10} {'Class':<18} Evidence")
        print(f"  {'─'*90}")
        for f in funcs:
            fs = f["mismatch_score"]
            level = "CRITICAL" if fs >= 0.45 else "HIGH" if fs >= 0.30 else "MEDIUM" if fs >= 0.10 else "LOW"
            cls = f.get("attack_class") or "-"
            ev = f.get("evidence") or "-"
            print(f"  {f['name']:<30} {fs:<9.4f} {level:<10} {cls:<18} {ev}")
        print()


def main():
    sol_path, address, json_mode = parse_args(sys.argv)
    source = validate_file(sol_path)

    if not json_mode:
        print(f"  Scanning: {sol_path}")

    start = time.time()
    try:
        result = analyze_contract(source, address)
    except Exception as e:
        print(f"[ERROR] Detector failed: {e}")
        sys.exit(2)
    elapsed = time.time() - start

    # Output
    if json_mode:
        result["scan_file"] = sol_path
        result["scan_elapsed_sec"] = round(elapsed, 1)
        result["cli_version"] = VERSION
        print(json.dumps(result, indent=2))
    else:
        print_human_report(result, elapsed)

    # Exit code
    risk = result.get("risk_level", "LOW")
    if risk in ("HIGH", "CRITICAL"):
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
