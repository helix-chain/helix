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
        "functions": [],
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
    before analyze_contract() runs (the same line every runtime-error path
    leaves behind) - never a report header and never a score.
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
