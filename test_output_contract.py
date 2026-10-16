"""
test_output_contract.py
Version: V1.0

Regression guard for the detector's OUTPUT DATA CONTRACT — the field names that
cross module boundaries between mismatch_detector.analyze_contract() (producer)
and the test runners / CLI (consumers).

Why this exists
---------------
Commit 9ff61b7 renamed `risk_score` -> `overall_mismatch_score` in the producer,
but a consumer kept reading the old key via dict.get(..., 0.0). The .get()
returned the default, so every scan silently scored 0.0 — no exception, no test
failure. proxy_fp_test_runner.py carried the same latent bug (read "risk_score"),
which made its false-positive CI gate unable to ever fail.

These tests make that class of bug LOUD:
  * assert the producer still emits the canonical score/risk keys,
  * assert the consumer helper reads the producer's output correctly,
  * assert a drifted output (missing the canonical key) RAISES, never 0.0,
  * assert no active runner still reads a legacy/unknown score key.

Runs WITHOUT torch/transformers: the CodeBERT embedder is stubbed, so this is a
fast, dependency-light gate suitable for pre-commit and CI.

Run:  python test_output_contract.py
"""

import contextlib
import io
import json
import os
import re
import sys
import tempfile
import unittest
from unittest import mock

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

import numpy as np

import mismatch_detector as md
import proxy_fp_test_runner as pf
import helix_scan

# A contract whose comments claim safety while the code has a reentrancy CEI
# violation — exercises the additive pattern boost path in the real detector.
VULN_SOURCE = md.DEMO_CONTRACT

CLEAN_SOURCE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @notice Standard token balance bookkeeping
contract Clean {
    mapping(address => uint256) public balances;

    /// @notice Read the caller's balance
    function myBalance() external view returns (uint256) {
        return balances[msg.sender];
    }
}
"""

# Active files that consume analyze_contract()'s output. Backups (*.bak*,
# *backup*) and frozen versioned snapshots (p0a_verify_*) are intentionally
# excluded — they are frozen history and must not be edited.
CONSUMER_FILES = [
    "mismatch_detector.py",
    "proxy_fp_test_runner.py",
    "ci_smoke_test.py",
    "mainnet_test_runner.py",
    "helix_scan.py",
    "replay_test_runner.py",
]


def _stub_embedder():
    """Replace CodeBERT with a deterministic vector so no model/network is needed."""
    md.HelixEmbedder._load_model = lambda self: None
    md.HelixEmbedder.embed = lambda self, text: np.ones(768, dtype=np.float64)


class TestOutputContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _stub_embedder()

    def test_producer_emits_canonical_keys(self):
        """analyze_contract() must expose the canonical score + risk keys."""
        for src in (VULN_SOURCE, CLEAN_SOURCE):
            result = md.analyze_contract(src)
            self.assertIn(
                pf.SCORE_KEY, result,
                f"producer dropped canonical key '{pf.SCORE_KEY}' — field drift",
            )
            self.assertIn("risk_level", result)
            self.assertIn("functions", result)
            score = result[pf.SCORE_KEY]
            self.assertIsInstance(score, float)
            self.assertGreaterEqual(score, 0.0)
            self.assertLessEqual(score, 1.0)

    def test_consumer_reads_producer_score(self):
        """The consumer helper must read exactly what the producer wrote."""
        result = md.analyze_contract(VULN_SOURCE)
        self.assertEqual(pf.extract_score(result), float(result[pf.SCORE_KEY]))

    def test_field_drift_fails_loud(self):
        """A drifted output (legacy/absent key) must RAISE, never silently 0.0.

        This is the exact 9ff61b7 scenario: the old code did
        result.get("risk_score", 0.0) and returned 0.0 for this input.
        """
        legacy = {"risk_score": 0.9, "risk_level": "CRITICAL"}
        with self.assertRaises(KeyError):
            pf.extract_score(legacy)

    def test_no_active_runner_reads_score_unsafely(self):
        """No active consumer may read the score via a stale key OR a masking default.

        Both patterns reproduce the 9ff61b7 silent-0.0 bug and are forbidden:
          * a legacy key:                     .get("risk_score" ...) / ["risk_score"]
          * the canonical key with a default: .get("overall_mismatch_score", <x>)
            — a renamed/dropped field then returns the default instead of raising.
        The score must be read fail-loud (subscript, or a helper that raises).
        """
        legacy_key = re.compile(
            r"""\.get\(\s*['"]risk_score['"]|\[\s*['"]risk_score['"]\s*\]"""
        )
        # A trailing comma after the key means a default is supplied, which
        # silently masks field drift: .get("overall_mismatch_score", <default>).
        soft_default = re.compile(r"""\.get\(\s*['"]overall_mismatch_score['"]\s*,""")
        offenders = []
        for fname in CONSUMER_FILES:
            path = os.path.join(SCRIPT_DIR, fname)
            with open(path, encoding="utf-8") as f:
                src = f.read()
            if legacy_key.search(src):
                offenders.append(f"{fname}: reads legacy 'risk_score'")
            if soft_default.search(src):
                offenders.append(
                    f"{fname}: reads 'overall_mismatch_score' with a default "
                    "(soft 0.0 masks drift — read by subscript instead)"
                )
        self.assertEqual(
            offenders, [],
            f"unsafe score reads in active runner(s): {offenders}",
        )


def _valid_result(risk_level="LOW", **overrides):
    """Build a well-formed analyze_contract() output dict, then apply overrides."""
    result = {
        "risk_level": risk_level,
        "overall_mismatch_score": 0.5,
        "functions": [{
            "name": "f",
            "intent": "f",
            "code_behavior": "standard function implementation",
            "mismatch_score": 0.5,
            "attack_class": None,
            "evidence": "",
        }],
        "recommended_action": "x",
        "contract_address": None,
    }
    result.update(overrides)
    return result


def _drop_key(key, **kwargs):
    """A well-formed output with one canonical key removed (drift case)."""
    result = _valid_result(kwargs.pop("risk_level", "CRITICAL"), **kwargs)
    del result[key]
    return result


class TestCliExitContract(unittest.TestCase):
    """The CLI must fail LOUD (exit 2) when the detector output contract drifts.

    9ff61b7-class field drift: if analyze_contract() ever drops `risk_level`,
    `main()` used `result.get("risk_level", "LOW")` and exited 0 = "safe to
    proceed" even for a CRITICAL contract.  Any value outside
    LOW/MEDIUM/HIGH/CRITICAL also exited 0.  In human mode a missing key raised
    an uncaught KeyError -> exit 1, which means "HIGH/CRITICAL", not "error".
    Validation must happen right after analyze_contract() returns and before the
    report / the JSON is printed, so a drifted result exits 2.  What lands on
    stdout is exactly pinned per mode: `--json` -> "" (empty); human mode ->
    only the progress line "Scanning: <path>" that helix_scan.py prints
    before analyze_contract() runs (the detector-exception path also starts
    with it) - never a report header and never a score.
    """

    def setUp(self):
        # One-line .sol file written via tempfile (never into the source dir).
        fd, self._sol_path = tempfile.mkstemp(suffix=".sol")
        os.close(fd)
        with open(self._sol_path, "w", encoding="utf-8") as f:
            f.write("pragma solidity ^0.8.0;\ncontract C {}\n")
        self.addCleanup(os.remove, self._sol_path)

    def _run_cli(self, result, json_mode):
        """Drive helix_scan.main() in-process with a stubbed detector."""
        argv = ["helix_scan.py", "scan", self._sol_path]
        if json_mode:
            argv.append("--json")
        out, err = io.StringIO(), io.StringIO()
        code = None
        with mock.patch.object(helix_scan, "analyze_contract", return_value=result), \
                mock.patch.object(sys, "argv", argv), \
                contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(err):
            try:
                helix_scan.main()
            except SystemExit as e:
                code = e.code
        return code, out.getvalue(), err.getvalue()

    # -- drift cases: 3 drifts x 2 modes = 6 sub-tests --------------------
    # Each drift is the same runtime-error class, so exit is 2 and stdout is
    # exactly what helix_scan.py's own flow leaves there BEFORE validation:
    #   * --json    -> "" (the JSON is only printed after validation)
    #   * human     -> "  Scanning: <path>\n" and nothing derived from the
    #     result (no report header, no score, no action line).
    # The human expectation is built from the very temp .sol path handed to
    # argv, so a hardcoded path can never satisfy it.
    def test_drift_contract_per_mode(self):
        """Both modes x all three drifts: exit 2, exact stdout, loud stderr."""
        drifts = (
            ("risk_level missing", _drop_key("risk_level"), True, "risk_level"),
            ("risk_level UNKNOWN", _valid_result("UNKNOWN"), False, "risk_level"),
            (
                "overall_mismatch_score missing",
                _drop_key("overall_mismatch_score", risk_level="CRITICAL"),
                False,
                "overall_mismatch_score",
            ),
        )
        expected_human_out = "  Scanning: %s\n" % self._sol_path
        for label, result, json_default, key in drifts:
            for json_mode in (True, False):
                with self.subTest(drift=label, json=json_mode):
                    code, out, err = self._run_cli(result, json_mode=json_mode)
                    tag = "%s / %s" % (label, "--json" if json_mode else "human")
                    self.assertEqual(code, 2, tag)
                    self.assertEqual(
                        out, "" if json_mode else expected_human_out, tag
                    )
                    self.assertIn("[ERROR]", err, tag)
                    self.assertIn(key, err, tag)

    def test_drift_human_missing_risk_level_exits_2(self):
        """Legacy name kept: human mode, missing risk_level -> exit 2, stdout
        is only the Scanning progress line (never a report header)."""
        result = _drop_key("risk_level")
        code, out, err = self._run_cli(result, json_mode=False)
        self.assertEqual(code, 2)
        self.assertEqual(out, "  Scanning: %s\n" % self._sol_path)
        self.assertNotIn("HELIX Scan Result", out)
        self.assertIn("[ERROR]", err)
        self.assertIn("risk_level", err)

    def test_drift_json_missing_risk_level_exits_2(self):
        """Legacy name kept: --json, missing risk_level -> exit 2, stdout empty."""
        code, out, err = self._run_cli(_drop_key("risk_level"), json_mode=True)
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertIn("[ERROR]", err)
        self.assertIn("risk_level", err)

    def test_empty_function_list_exits_2_whatever_the_message(self):
        """A result with no analysed functions is never a verdict, whatever the
        accompanying recommended_action text says: exit 2, nothing on stdout
        derived from the result, and a loud stderr line."""
        expected_human_out = "  Scanning: %s\n" % self._sol_path
        for message in ("No analyzable Solidity functions detected.", "x", ""):
            for json_mode in (True, False):
                with self.subTest(message=message, json=json_mode):
                    result = _valid_result("LOW", functions=[], recommended_action=message)
                    code, out, err = self._run_cli(result, json_mode=json_mode)
                    self.assertEqual(code, 2)
                    self.assertEqual(out, "" if json_mode else expected_human_out)
                    self.assertIn("[ERROR]", err)

    def test_invalid_value_json_exits_2(self):
        """Legacy name kept: --json, unknown risk_level -> exit 2, stdout empty."""
        code, out, err = self._run_cli(_valid_result("UNKNOWN"), json_mode=True)
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertIn("[ERROR]", err)
        self.assertIn("risk_level", err)

    def test_drift_json_missing_score_exits_2(self):
        """Legacy name kept: --json, missing score -> exit 2, stdout empty."""
        result = _drop_key("overall_mismatch_score", risk_level="CRITICAL")
        code, out, err = self._run_cli(result, json_mode=True)
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertIn("[ERROR]", err)
        self.assertIn("overall_mismatch_score", err)

    # -- positive controls: a valid result keeps today's exit codes -------
    def test_positive_controls_json(self):
        for risk, expected in (("LOW", 0), ("MEDIUM", 0), ("HIGH", 1), ("CRITICAL", 1)):
            with self.subTest(risk=risk):
                code, out, err = self._run_cli(_valid_result(risk), json_mode=True)
                self.assertEqual(code, expected)
                payload = json.loads(out)
                self.assertEqual(payload["risk_level"], risk)

    def test_positive_controls_human(self):
        for risk, expected in (("LOW", 0), ("MEDIUM", 0), ("HIGH", 1), ("CRITICAL", 1)):
            with self.subTest(risk=risk):
                code, out, err = self._run_cli(_valid_result(risk), json_mode=False)
                self.assertEqual(code, expected)
                self.assertIn("HELIX Scan Result", out)

    # -- static: the CLI must not read risk_level with a masking default --
    def test_cli_reads_risk_level_fail_loud(self):
        """helix_scan.py must not read risk_level via .get(key, <default>)."""
        soft_default = re.compile(r"""\.get\(\s*['"]risk_level['"]\s*,""")
        path = os.path.join(SCRIPT_DIR, "helix_scan.py")
        with open(path, encoding="utf-8") as f:
            src = f.read()
        self.assertIsNone(
            soft_default.search(src),
            "helix_scan.py reads risk_level with a default - soft value masks "
            "field drift (read by subscript after validation instead)",
        )


# ─────────────────────────────────────────────
# Reentrancy-guard exemption regression (M5b)
# ─────────────────────────────────────────────
#
# Source: E:/ai-work/agent-output/commander/runs/w2_04_m5_review_sol_202610141047/
#         evidence_keep/attack_matrix.json  (name, source, old_flagged,
#         new_suppressed)  x  .../evidence_keep/compilation_matrix.json
#         (name, compiler_exit, valid — valid = compiles with solc 0.8.20)
# Review run: w2_04_m5_review_sol_202610141047 (L3 review of PR
#         helix-chain/helix#9, which proposed exempting
#         `missing_reentrancy_guard` for calls to a contract created in the
#         same function).  PR #9 was REJECTED: the review produced compiled
#         Solidity counter-examples where the detector on `main` correctly
#         reports `missing_reentrancy_guard` on the function `run` and the
#         exempted detector does not.
# Selection rule: every case in attack_matrix.json with
#         old_flagged == True AND valid == True in compilation_matrix.json.
#         The four old_flagged-but-invalid cases (unmatched_quote,
#         unmatched_comment, receiver_this_direct, array_new_not_contract —
#         solc errors) are excluded: they do not compile, so they cannot
#         carry a compiled counter-example.  delegatecall_only and
#         staticcall_only are excluded because old_flagged was already False.
# Selected count: 22 from attack_matrix.json (15 of them new_suppressed ==
#         True — the cases an exemption would hide) + fresh_reentrant_child
#         (P1-9, kept in a separate review file) = 23.
#
# These cases are pinned against the CURRENT `main` detector (no exemption),
# so any future re-introduction of the exemption turns this file RED.  The
# assertion is made through the real call chain
# `IntentCodeMismatchDetector.analyze()` (not `CodeEncoder.summarize`
# directly): `analyze()` builds one `FunctionMismatch` per analyzed function
# with `code_summary = self._patterns_to_text(code_patterns)`, and
# `_patterns_to_text` maps `missing_reentrancy_guard` to the text
# "no reentrancy protection modifier".  Binding to `analyze()` keeps the test
# honest if the way `summarize` is called ever changes (extra parameters,
# contract source, ...).
REENTRANCY_BYPASS_CASES = (
    # branch_not_taken (old_flagged=True, valid=True, new_suppressed=True)
    (
        'branch_not_taken',
        "pragma solidity ^0.8.20;\ncontract Child {}\ncontract Factory { \nfunction run(address target, bool cond, uint n, bytes calldata data) external {\naddress v = target; if (cond) { v = address(new Child()); } v.call(data);\n}\n\n}\n",
    ),
    # branch_latest_new (old_flagged=True, valid=True, new_suppressed=True)
    (
        'branch_latest_new',
        "pragma solidity ^0.8.20;\ncontract Child {}\ncontract Factory { \nfunction run(address target, bool cond, uint n, bytes calldata data) external {\naddress v; if (cond) { v = target; } else { v = address(new Child()); } v.call(data);\n}\n\n}\n",
    ),
    # loop_zero (old_flagged=True, valid=True, new_suppressed=True)
    (
        'loop_zero',
        "pragma solidity ^0.8.20;\ncontract Child {}\ncontract Factory { \nfunction run(address target, bool cond, uint n, bytes calldata data) external {\naddress v = target; for (uint i=0; i<n; ++i) { v = address(new Child()); } v.call(data);\n}\n\n}\n",
    ),
    # assembly_sload (old_flagged=True, valid=True, new_suppressed=False)
    (
        'assembly_sload',
        "pragma solidity ^0.8.20;\ncontract Child {}\ncontract Factory { \nfunction run(address target, bool cond, uint n, bytes calldata data) external {\naddress v = address(new Child()); assembly { v := sload(0) } v.call(data);\n}\n\n}\n",
    ),
    # helper_different_return (old_flagged=True, valid=True, new_suppressed=False)
    (
        'helper_different_return',
        "pragma solidity ^0.8.20;\ncontract Child {}\ncontract Factory { \nfunction run(address target, bool cond, uint n, bytes calldata data) external {\naddress v = make(target); v.call(data);\n}\nfunction make(address target) internal returns (address) { address made = address(new Child()); return target; }\n}\n",
    ),
    # helper_early_target (old_flagged=True, valid=True, new_suppressed=True)
    (
        'helper_early_target',
        "pragma solidity ^0.8.20;\ncontract Child {}\ncontract Factory { \nfunction run(address target, bool cond, uint n, bytes calldata data) external {\naddress v = make(target,cond); v.call(data);\n}\nfunction make(address target,bool cond) internal returns (address) { if (cond) return target; return address(new Child()); }\n}\n",
    ),
    # helper_named_return_override (old_flagged=True, valid=True, new_suppressed=True)
    (
        'helper_named_return_override',
        "pragma solidity ^0.8.20;\ncontract Child {}\ncontract Factory { \nfunction run(address target, bool cond, uint n, bytes calldata data) external {\naddress v = make(target,cond); v.call(data);\n}\nfunction make(address target,bool cond) internal returns (address v) { v=address(new Child()); if(cond) return v; return target; }\n}\n",
    ),
    # helper_conditional_assignment (old_flagged=True, valid=True, new_suppressed=True)
    (
        'helper_conditional_assignment',
        "pragma solidity ^0.8.20;\ncontract Child {}\ncontract Factory { \nfunction run(address target, bool cond, uint n, bytes calldata data) external {\naddress v = make(target,cond); v.call(data);\n}\nfunction make(address target,bool cond) internal returns (address v) { v=target; if(cond) v=address(new Child()); }\n}\n",
    ),
    # helper_overload (old_flagged=True, valid=True, new_suppressed=True)
    (
        'helper_overload',
        "pragma solidity ^0.8.20;\ncontract Child {}\ncontract Factory { \nfunction run(address target, bool cond, uint n, bytes calldata data) external {\naddress v = make(target); v.call(data);\n}\nfunction make(uint n) internal returns (address) { return address(new Child()); }\nfunction make(address target) internal pure returns (address) { return target; }\n}\n",
    ),
    # shadowed_nested (old_flagged=True, valid=True, new_suppressed=True)
    (
        'shadowed_nested',
        "pragma solidity ^0.8.20;\ncontract Child {}\ncontract Factory { \nfunction run(address target, bool cond, uint n, bytes calldata data) external {\naddress v=target; { address v=address(new Child()); } v.call(data);\n}\n\n}\n",
    ),
    # sibling_scope_name (old_flagged=True, valid=True, new_suppressed=False)
    (
        'sibling_scope_name',
        "pragma solidity ^0.8.20;\ncontract Child {}\ncontract Factory { \nfunction run(address target, bool cond, uint n, bytes calldata data) external {\n{ address v=address(new Child()); } { address v; assembly { v := calldataload(4) } v.call(data); }\n}\n\n}\n",
    ),
    # conditional_expression (old_flagged=True, valid=True, new_suppressed=False)
    (
        'conditional_expression',
        "pragma solidity ^0.8.20;\ncontract Child {}\ncontract Factory { \nfunction run(address target, bool cond, uint n, bytes calldata data) external {\naddress v = cond ? address(new Child()) : target; v.call(data);\n}\n\n}\n",
    ),
    # cr_only_comment (old_flagged=True, valid=True, new_suppressed=True)
    (
        'cr_only_comment',
        "pragma solidity ^0.8.20;\ncontract Child {}\ncontract Factory { \nfunction run(address target, bool cond, uint n, bytes calldata data) external {\n// comment\r target.call(data);\n}\n\n}\n",
    ),
    # valid_escaped_string (old_flagged=True, valid=True, new_suppressed=False)
    (
        'valid_escaped_string',
        "pragma solidity ^0.8.20;\ncontract Child {}\ncontract Factory { \nfunction run(address target, bool cond, uint n, bytes calldata data) external {\nstring memory s = \"quoted \\\" v=address(new Child());\"; target.call(data);\n}\n\n}\n",
    ),
    # receiver_this (old_flagged=True, valid=True, new_suppressed=False)
    (
        'receiver_this',
        "pragma solidity ^0.8.20;\ncontract Child {}\ncontract Factory { address public v;\nfunction run(address target, bool cond, uint n, bytes calldata data) external {\naddress v=address(new Child()); this.v().call(data);\n}\n\n}\n",
    ),
    # receiver_struct (old_flagged=True, valid=True, new_suppressed=False)
    (
        'receiver_struct',
        "pragma solidity ^0.8.20;\ncontract Child {}\ncontract Factory { struct Box { address v; } Box box;\nfunction run(address target, bool cond, uint n, bytes calldata data) external {\naddress v=address(new Child()); box.v.call(data);\n}\n\n}\n",
    ),
    # fresh_plus_delegatecall (old_flagged=True, valid=True, new_suppressed=True)
    (
        'fresh_plus_delegatecall',
        "pragma solidity ^0.8.20;\ncontract Child {}\ncontract Factory { \nfunction run(address target, bool cond, uint n, bytes calldata data) external {\naddress v=address(new Child()); v.call(data); target.delegatecall(data);\n}\n\n}\n",
    ),
    # fresh_plus_staticcall (old_flagged=True, valid=True, new_suppressed=True)
    (
        'fresh_plus_staticcall',
        "pragma solidity ^0.8.20;\ncontract Child {}\ncontract Factory { \nfunction run(address target, bool cond, uint n, bytes calldata data) external {\naddress v=address(new Child()); v.call(data); target.staticcall(data);\n}\n\n}\n",
    ),
    # state_mutated_by_helper (old_flagged=True, valid=True, new_suppressed=True)
    (
        'state_mutated_by_helper',
        "pragma solidity ^0.8.20;\ncontract Child {}\ncontract Factory { address v;\nfunction run(address target, bool cond, uint n, bytes calldata data) external {\nv=address(new Child()); redirect(target); v.call(data);\n}\nfunction redirect(address target) internal { v=target; }\n}\n",
    ),
    # state_mutated_by_sstore (old_flagged=True, valid=True, new_suppressed=True)
    (
        'state_mutated_by_sstore',
        "pragma solidity ^0.8.20;\ncontract Child {}\ncontract Factory { address v;\nfunction run(address target, bool cond, uint n, bytes calldata data) external {\nv=address(new Child()); assembly { sstore(v.slot, target) } v.call(data);\n}\n\n}\n",
    ),
    # helper_unrelated_contract (old_flagged=True, valid=True, new_suppressed=True)
    (
        'helper_unrelated_contract',
        "pragma solidity ^0.8.20;\ncontract Child {}\ncontract Decoy { function make(address) internal returns(address) { return address(new Child()); } }\ncontract Factory { function run(address target, bytes calldata data) external { address v=make(target); v.call(data); } function make(address target) internal pure returns(address) { return target; } }",
    ),
    # nested_call_options (old_flagged=True, valid=True, new_suppressed=True)
    (
        'nested_call_options',
        "pragma solidity ^0.8.20;\ncontract Factory {\nstruct Info { uint amount; }\nfunction amount(Info memory info) internal pure returns(uint) { return info.amount; }\nfunction run(address target, bytes calldata data) external {\n    target.call{value: amount(Info({amount: 0}))}(data);\n}\n}\n",
    ),
    # fresh_reentrant_child (review P1-9, the decisive case: the receiver really
    # IS created in this function, yet its receive() calls back into the
    # caller). Tracked outside attack_matrix.json in the review run; source:
    # w2_04_m5_review_sol_202610141047/evidence_keep/snippets/
    # fresh_reentrant_child.sol (compiled with solc 0.8.20, valid).
    (
        'fresh_reentrant_child',
        '// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\ninterface IRelay { function onPayout() external payable; }\ncontract Child {\n    address immutable relay;\n    constructor(address r) { relay=r; }\n    receive() external payable { IRelay(relay).onPayout{value:msg.value}(); }\n}\ncontract Factory {\n    uint public remaining = 1 ether;\n    receive() external payable {}\n    function run(address relay) external {\n        require(remaining > 0);\n        address v = address(new Child(relay));\n        (bool ok,) = v.call{value:remaining}("");\n        require(ok);\n        remaining = 0;\n    }\n}\ncontract Attacker is IRelay {\n    Factory immutable victim;\n    uint public callbacks;\n    constructor(Factory f) { victim=f; }\n    function attack() external { victim.run(address(this)); }\n    function onPayout() external payable { if (++callbacks < 2) victim.run(address(this)); }\n}\n',
    ),)


class TestReentrancyGuardNoExemption(unittest.TestCase):
    """Permanent regression: no exemption may hide these reentrancy bypasses.

    Each case is a compiled (solc 0.8.20) Solidity counter-example from the
    rejected helix#9 review.  On `main` the detector MUST report
    `missing_reentrancy_guard` for the function `run`; an exemption that
    suppresses any of these cases turns CI red.
    """

    @classmethod
    def setUpClass(cls):
        # Reuse the one existing stub (defined at module level) — no second
        # CodeBERT replacement is added.
        _stub_embedder()

    def test_run_function_reports_missing_reentrancy_guard(self):
        """Every selected case: `run`'s code_summary carries the guard finding."""
        self.assertEqual(len(REENTRANCY_BYPASS_CASES), 23)

        # The `cr_only_comment` case really contains a carriage return, and it
        # is carried as an explicit "\r" escape so this file stays LF-only.
        cr_case = dict(REENTRANCY_BYPASS_CASES)["cr_only_comment"]
        self.assertIn("\r", cr_case)
        self.assertNotIn("\n\r", cr_case)

        for name, source in REENTRANCY_BYPASS_CASES:
            with self.subTest(case=name):
                detector = md.IntentCodeMismatchDetector()
                report = detector.analyze(
                    md.ContractInput(source_code=source, contract_address=None)
                )
                run_reports = [
                    r for r in report.function_reports if r.function_name == "run"
                ]
                self.assertTrue(
                    run_reports,
                    "case %r: no FunctionMismatch named 'run' was produced — the "
                    "analyze() call chain no longer reaches this function. "
                    "Analysed functions: %r"
                    % (name, [r.function_name for r in report.function_reports]),
                )
                code_summary = run_reports[0].code_summary
                self.assertIn(
                    "no reentrancy protection modifier",
                    code_summary,
                    "case %r: `run` is no longer flagged as missing a reentrancy "
                    "guard — code_summary=%r. This case is a compiled "
                    "counter-example from the rejected helix#9 exemption review; "
                    "hiding it is the regression this test guards against."
                    % (name, code_summary),
                )


def _assert_risk_labels_match_producer(producer, rust_labels, test_case):
    scores = [index / 1000 for index in range(1001)]
    scores.extend(
        [
            0.0999999,
            0.1,
            0.2999999,
            0.3,
            0.4499999,
            0.45,
            0.9999999,
            1.0,
            -0.5,
            1.5,
            10.0,
        ]
    )
    producer_labels = {
        producer._score_to_risk(score).upper() for score in scores
    }
    test_case.assertSetEqual(
        {label.upper() for label in rust_labels},
        producer_labels,
    )


class TestRustConsumerContract(unittest.TestCase):
    """Keep the Rust wire schema aligned with the Python report producer."""

    @classmethod
    def setUpClass(cls):
        _stub_embedder()

    @staticmethod
    def _required_rust_fields(source, struct_name):
        match = re.search(
            rf"(?m)^\s*pub\s+struct\s+{re.escape(struct_name)}\s*\{{"
            rf"(?P<body>[\s\S]*?)^\s*\}}",
            source,
        )
        if match is None:
            raise AssertionError(f"Rust struct {struct_name} was not found")

        required = []
        pending_default = False
        lines = match.group("body").splitlines()
        index = 0
        while index < len(lines):
            line = lines[index].strip()
            index += 1
            if not line or line.startswith("//"):
                continue
            if line.startswith("#"):
                attribute = [line]
                while "]" not in attribute[-1] and index < len(lines):
                    attribute.append(lines[index].strip())
                    index += 1
                pending_default = bool(
                    re.search(
                        r"#\s*\[\s*serde\s*\([\s\S]*?\bdefault\b",
                        " ".join(attribute),
                    )
                )
                continue

            field = re.match(r"pub\s+([A-Za-z_]\w*)\s*:", line)
            if field:
                if not pending_default:
                    required.append(field.group(1))
                pending_default = False
            else:
                pending_default = False

        if not required:
            raise AssertionError(f"Rust struct {struct_name} has no parsed fields")
        return required

    def test_required_fields_and_risk_labels_match_python_producer(self):
        rust_path = os.path.join(SCRIPT_DIR, "node", "src", "detector.rs")
        with open(rust_path, encoding="utf-8") as rust_file:
            rust_source = rust_file.read()

        report_fields = self._required_rust_fields(rust_source, "DetectorReport")
        finding_fields = self._required_rust_fields(rust_source, "FunctionFinding")

        risk_method = re.search(
            r"\bpub\s+fn\s+risk\s*\(\s*&\s*self\s*\)\s*"
            r"->\s*Option\s*<\s*RiskLevel\s*>\s*\{"
            r"(?P<body>[\s\S]*?)^\s*\}",
            rust_source,
            re.MULTILINE,
        )
        self.assertIsNotNone(risk_method, "Rust DetectorReport::risk() was not found")
        rust_labels = set(
            re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"\s*=>', risk_method.group("body"))
        )
        self.assertTrue(rust_labels, "no string-literal risk match arms were found")

        result = md.analyze_contract(VULN_SOURCE)
        for field in report_fields:
            self.assertIn(field, result, f"Rust-required report field {field!r} is absent")

        self.assertTrue(result["functions"], "producer returned no function findings")
        for finding in result["functions"]:
            for field in finding_fields:
                self.assertIn(
                    field,
                    finding,
                    f"Rust-required function field {field!r} is absent from {finding!r}",
                )

        producer = md.IntentCodeMismatchDetector()
        _assert_risk_labels_match_producer(producer, rust_labels, self)

    def test_risk_label_sweep_rejects_producer_only_label(self):
        producer = md.IntentCodeMismatchDetector()
        rust_labels = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        original_score_to_risk = md.IntentCodeMismatchDetector._score_to_risk

        def score_with_extra_label(instance, score):
            if score > 0.90:
                return "EXTREME"
            return original_score_to_risk(instance, score)

        try:
            md.IntentCodeMismatchDetector._score_to_risk = score_with_extra_label
            with self.assertRaises(AssertionError) as error:
                _assert_risk_labels_match_producer(producer, rust_labels, self)
            self.assertIn("EXTREME", str(error.exception))
        finally:
            md.IntentCodeMismatchDetector._score_to_risk = original_score_to_risk


if __name__ == "__main__":
    unittest.main(verbosity=2)
