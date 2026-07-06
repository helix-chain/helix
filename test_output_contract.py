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

import os
import re
import sys
import unittest

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

import numpy as np

import mismatch_detector as md
import proxy_fp_test_runner as pf

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
