"""Torch-free tests for replay_test_runner's exit and pattern gate."""

import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import ModuleType, SimpleNamespace
from inspect import signature
from unittest.mock import patch

import replay_test_runner as gate
from attack_replay_contracts import REPLAY_CONTRACTS
from mismatch_detector import CodeEncoder


RISK_PATTERN_NAMES = set(CodeEncoder.RISK_PATTERNS)


def contract(sig_id, expected_patterns):
    return {
        "sig_id": sig_id,
        "source": f"contract source for {sig_id}",
        "expected_patterns": list(expected_patterns),
    }


def function_report(evidence="", attack_class=None):
    return SimpleNamespace(evidence=evidence, attack_class=attack_class)


class FakeDetector:
    """Return configured model-like reports without loading the model."""

    def __init__(self, outcomes):
        self.outcomes = outcomes
        self.calls = []

    def analyze(self, contract_input):
        sig_id = contract_input.contract_address.removeprefix("0xREPLAY_")
        self.calls.append(sig_id)
        outcome = self.outcomes[sig_id]
        if isinstance(outcome, BaseException):
            raise outcome
        return SimpleNamespace(
            overall_mismatch_score=outcome.get("score", 0.25),
            risk_level=outcome.get("risk_level", "HIGH"),
            function_reports=outcome.get("function_reports", []),
        )


class FakeContractInput:
    def __init__(self, source_code, contract_address=None):
        self.source_code = source_code
        self.contract_address = contract_address


def run_original_compat(contracts, detector, report_dir, beyond_mvp, known_undetectable):
    """Test-only adapter for the original runner, which has no injection API."""
    original_state = (
        gate.REPLAY_CONTRACTS,
        gate.BEYOND_MVP,
        gate.KNOWN_UNDETECTABLE,
    )
    gate.REPLAY_CONTRACTS = list(contracts)
    gate.BEYOND_MVP = set(beyond_mvp)
    gate.KNOWN_UNDETECTABLE = {
        sig_id: "Injected known limitation" for sig_id in known_undetectable
    }

    fake_module = ModuleType("mismatch_detector")
    fake_module.ContractInput = FakeContractInput
    fake_module.IntentCodeMismatchDetector = lambda: detector
    module_sentinel = object()
    previous_module = sys.modules.get("mismatch_detector", module_sentinel)
    sys.modules["mismatch_detector"] = fake_module
    old_cwd = Path.cwd()
    try:
        os.chdir(report_dir)
        report = gate.run_replay()
    finally:
        os.chdir(old_cwd)
        gate.REPLAY_CONTRACTS, gate.BEYOND_MVP, gate.KNOWN_UNDETECTABLE = original_state
        if previous_module is module_sentinel:
            sys.modules.pop("mismatch_detector", None)
        else:
            sys.modules["mismatch_detector"] = previous_module

    # The original implementation has no gate; model its effective process code.
    report["summary"]["exit_code"] = 0
    return report


class ReplayGateTests(unittest.TestCase):
    def run_gate(
        self,
        contracts,
        outcomes,
        *,
        beyond_mvp=(),
        known_undetectable=(),
        pattern_gap_baseline=(),
    ):
        detector = FakeDetector(outcomes)
        with tempfile.TemporaryDirectory(prefix="replay-gate-") as temp_dir:
            report_dir = Path(temp_dir) / "reports"
            report_dir.mkdir()
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                if "contracts" in signature(gate.run_replay).parameters:
                    report = gate.run_replay(
                        contracts=contracts,
                        detector=detector,
                        report_dir=report_dir,
                        beyond_mvp=set(beyond_mvp),
                        known_undetectable=set(known_undetectable),
                        pattern_gap_baseline=set(pattern_gap_baseline),
                    )
                else:
                    report = run_original_compat(
                        contracts,
                        detector,
                        report_dir,
                        beyond_mvp,
                        known_undetectable,
                    )
            saved_reports = list(report_dir.glob("replay_test_report_*.json"))
            self.assertEqual(len(saved_reports), 1, "report must be written under report_dir")
            self.assertEqual(saved_reports[0].parent, report_dir)
            return report, stdout.getvalue(), detector

    def assert_exit_code(self, report, expected):
        self.assertEqual(report["summary"]["exit_code"], expected)

    def test_all_detectable_and_patterns_confirmed_uses_contract_count(self):
        contracts = [
            contract("SIG-T1", ["missing_reentrancy_guard"]),
            contract("SIG-T2", ["external_call_before_state_update"]),
            contract("SIG-T3", ["spot_price_oracle"]),
        ]
        outcomes = {
            "SIG-T1": {"function_reports": [function_report("missing_reentrancy_guard")]},
            "SIG-T2": {"function_reports": [function_report("external_call_before_state_update")]},
            "SIG-T3": {"function_reports": [function_report("spot_price_oracle")]},
        }

        report, output, _ = self.run_gate(contracts, outcomes)

        self.assert_exit_code(report, 0)
        self.assertEqual(report["summary"]["total_attacks"], 3)
        self.assertEqual(report["summary"]["detectable_scope"], 3)
        self.assertEqual(report["summary"]["detected"], 3)
        self.assertEqual(report["summary"]["pattern_confirmed"], 3)
        self.assertIn("DETECTED 3/3", output)
        self.assertIn("PATTERN-CONFIRMED 3/3", output)

    def test_detectable_miss_exits_one_and_lists_signature(self):
        sig_id = "SIG-MISS"
        report, output, _ = self.run_gate(
            [contract(sig_id, ["missing_reentrancy_guard"])],
            {sig_id: {"risk_level": "LOW", "function_reports": [function_report()]}},
        )

        self.assert_exit_code(report, 1)
        self.assertEqual(report["summary"]["missed"], 1)
        self.assertIn(sig_id, output)
        self.assertIn("MISSED: 1", output)

    def test_detector_exception_on_detectable_contract_exits_two(self):
        sig_id = "SIG-ERROR"
        report, output, _ = self.run_gate(
            [contract(sig_id, ["missing_reentrancy_guard"])],
            {sig_id: RuntimeError("detector crashed")},
        )

        self.assert_exit_code(report, 2)
        self.assertEqual(report["summary"]["errors"], 1)
        self.assertIn("detector crashed", report["results"][0]["error"])
        self.assertIn("ERRORS: 1", output)

    def test_detector_exception_on_beyond_mvp_contract_exits_two(self):
        sig_id = "SIG-BEYOND-ERROR"
        report, output, _ = self.run_gate(
            [contract(sig_id, [])],
            {sig_id: RuntimeError("beyond detector crashed")},
            beyond_mvp={sig_id},
        )

        self.assert_exit_code(report, 2)
        self.assertEqual(report["summary"]["errors"], 1)
        self.assertIn("beyond detector crashed", report["results"][0]["error"])
        self.assertIn("ERRORS: 1", output)

    def test_new_detected_pattern_gap_fails_and_baselined_gap_does_not(self):
        sig_id = "SIG-GAP"
        contracts = [contract(sig_id, ["missing_access_control"])]
        outcomes = {
            sig_id: {
                "risk_level": "HIGH",
                "function_reports": [function_report("spot_price_oracle")],
            }
        }

        new_report, new_output, _ = self.run_gate(contracts, outcomes)
        self.assert_exit_code(new_report, 1)
        self.assertEqual(new_report["summary"]["pattern_gap_new"], 1)
        self.assertIn("NEW gaps: 1", new_output)

        baseline_report, baseline_output, _ = self.run_gate(
            contracts, outcomes, pattern_gap_baseline={sig_id}
        )
        self.assert_exit_code(baseline_report, 0)
        self.assertEqual(baseline_report["summary"]["pattern_gap_baselined"], 1)
        self.assertEqual(baseline_report["summary"]["pattern_gap_new"], 0)
        self.assertIn("baselined gaps: 1", baseline_output)

    def test_confirmed_baseline_gap_prints_tighten_hint(self):
        sig_id = "SIG-TIGHTEN"
        report, output, _ = self.run_gate(
            [contract(sig_id, ["missing_access_control"])],
            {sig_id: {"function_reports": [function_report("missing_access_control")]}},
            pattern_gap_baseline={sig_id},
        )

        self.assert_exit_code(report, 0)
        self.assertIn("TIGHTEN BASELINE", output)
        self.assertIn(sig_id, output)

    def test_empty_expected_patterns_are_not_pattern_gaps(self):
        sig_id = "SIG-N-A"
        report, output, _ = self.run_gate(
            [contract(sig_id, [])],
            {sig_id: {"risk_level": "LOW", "function_reports": [function_report()]}},
            beyond_mvp={sig_id},
        )

        self.assert_exit_code(report, 0)
        self.assertFalse(report["results"][0]["pattern_confirmed"])
        self.assertEqual(report["summary"]["pattern_gap_baselined"], 0)
        self.assertEqual(report["summary"]["pattern_gap_new"], 0)
        self.assertEqual(report["summary"]["missed"], 0)
        self.assertIn("n/a", output)

    def test_integrity_rejects_unknown_beyond_mvp_id(self):
        report, output, detector = self.run_gate(
            [contract("SIG-KNOWN", ["missing_reentrancy_guard"])],
            {"SIG-KNOWN": {"function_reports": [function_report("missing_reentrancy_guard")]}},
            beyond_mvp={"SIG-UNKNOWN"},
        )

        self.assert_exit_code(report, 2)
        self.assertEqual(detector.calls, [])
        self.assertIn("SIG-UNKNOWN", output)
        self.assertIn("INTEGRITY ERROR", output)

    def test_integrity_rejects_duplicate_sig_ids(self):
        duplicate = contract("SIG-DUP", ["missing_reentrancy_guard"])
        report, output, detector = self.run_gate(
            [duplicate, duplicate],
            {"SIG-DUP": {"function_reports": [function_report("missing_reentrancy_guard")]}},
        )

        self.assert_exit_code(report, 2)
        self.assertEqual(detector.calls, [])
        self.assertIn("SIG-DUP", output)
        self.assertIn("duplicate", output.lower())

    def test_integrity_rejects_baseline_outside_detectable_set(self):
        sig_id = "SIG-EXCLUDED"
        report, output, detector = self.run_gate(
            [contract(sig_id, ["missing_reentrancy_guard"])],
            {sig_id: {"function_reports": [function_report("missing_reentrancy_guard")] }},
            beyond_mvp={sig_id},
            pattern_gap_baseline={sig_id},
        )

        self.assert_exit_code(report, 2)
        self.assertEqual(detector.calls, [])
        self.assertIn("PATTERN_GAP_BASELINE", output)
        self.assertIn(sig_id, output)

    def test_evidence_parsing_keeps_only_real_pattern_names(self):
        sig_id = "SIG-PARSE"
        evidence = (
            "missing_reentrancy_guard; external_call_before_state_update; "
            "Similar to X (reentrancy, $1 loss); invented_pattern"
        )
        report, _, _ = self.run_gate(
            [contract(sig_id, ["missing_reentrancy_guard"])],
            {sig_id: {"function_reports": [function_report(evidence)]}},
        )

        self.assertEqual(
            set(report["results"][0]["patterns_found_in_evidence"]),
            {"missing_reentrancy_guard", "external_call_before_state_update"},
        )
        self.assertTrue(report["results"][0]["pattern_confirmed"])
        self.assertTrue(RISK_PATTERN_NAMES.issuperset(report["results"][0]["patterns_found_in_evidence"]))

    def test_real_pattern_gap_baseline_matches_real_detectable_contracts(self):
        if not hasattr(gate, "PATTERN_GAP_BASELINE"):
            self.skipTest("the original runner has no measured pattern-gap baseline")
        expected_baseline = {
            "SIG-002", "SIG-007", "SIG-008", "SIG-010", "SIG-011",
            "SIG-014", "SIG-016", "SIG-018", "SIG-020", "SIG-025",
            "SIG-029", "SIG-030", "SIG-031", "SIG-032", "SIG-033",
            "SIG-036", "SIG-047", "SIG-048", "SIG-049", "SIG-050",
        }
        contract_ids = {item["sig_id"] for item in REPLAY_CONTRACTS}
        detectable_ids = contract_ids - set(gate.BEYOND_MVP) - set(gate.KNOWN_UNDETECTABLE)
        contracts_by_id = {item["sig_id"]: item for item in REPLAY_CONTRACTS}

        self.assertEqual(gate.PATTERN_GAP_BASELINE, expected_baseline)
        self.assertEqual(len(gate.PATTERN_GAP_BASELINE), 20)
        self.assertTrue(gate.PATTERN_GAP_BASELINE <= detectable_ids)
        self.assertTrue(all(contracts_by_id[sig_id]["expected_patterns"] for sig_id in gate.PATTERN_GAP_BASELINE))

    def test_main_exits_with_report_exit_code(self):
        if not hasattr(gate, "main"):
            self.skipTest("the original runner has no main() exit-code adapter")
        with patch.object(gate, "run_replay", return_value={"summary": {"exit_code": 3}}):
            with self.assertRaises(SystemExit) as raised:
                gate.main()
        self.assertEqual(raised.exception.code, 3)


if __name__ == "__main__":
    unittest.main()
