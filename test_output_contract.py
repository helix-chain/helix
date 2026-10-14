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


class TestFreshTargetReentrancy(unittest.TestCase):
    """Freshly created targets do not create an untrusted reentrancy edge."""

    # Literal evidence from E:/ai-work/agent-output/commander/runs/w2_04_m5_rca_ds_202610140939/probe/decomposition.json.
    RCA_MISSING_GUARD_PAIRS = [('SIG-001', 'withdraw'),
 ('SIG-021', 'withdraw'),
 ('SIG-022', 'send'),
 ('SIG-022', 'claimReward'),
 ('SIG-023', 'flash'),
 ('SIG-017', 'remove_liquidity'),
 ('SIG-003', 'getReserves'),
 ('SIG-003', 'borrow'),
 ('SIG-004', 'getReserves'),
 ('SIG-004', 'borrow'),
 ('SIG-005', 'getReserves'),
 ('SIG-005', 'borrow'),
 ('SIG-006', 'getReserves'),
 ('SIG-006', 'borrow'),
 ('SIG-015', 'donateToReserves'),
 ('SIG-024', 'emergencyWithdraw'),
 ('SIG-025', 'transfer'),
 ('SIG-013', 'getReserves'),
 ('SIG-013', 'borrow'),
 ('SIG-026', 'getReserves'),
 ('SIG-026', 'borrow'),
 ('SIG-027', 'getReserves'),
 ('SIG-027', 'borrow'),
 ('SIG-028', 'getReserves'),
 ('SIG-028', 'borrow'),
 ('SIG-002', 'transfer'),
 ('SIG-007', 'transfer'),
 ('SIG-016', 'transfer'),
 ('SIG-020', 'performAction'),
 ('SIG-029', 'performAction'),
 ('SIG-030', 'transfer'),
 ('SIG-031', 'performAction'),
 ('SIG-008', 'transfer'),
 ('SIG-010', 'transfer'),
 ('SIG-018', 'transfer'),
 ('SIG-032', 'transfer'),
 ('SIG-033', 'transfer'),
 ('SIG-036', 'sell'),
 ('SIG-011', 'transfer'),
 ('SIG-014', 'transfer'),
 ('SIG-039', 'claimReward'),
 ('SIG-019', 'claimReward'),
 ('SIG-040', 'getReserves'),
 ('SIG-040', 'borrow'),
 ('SIG-009', 'execute'),
 ('SIG-044', 'execute'),
 ('SIG-045', 'execute'),
 ('SIG-046', 'getReserves'),
 ('SIG-046', 'borrow'),
 ('SIG-047', 'withdraw'),
 ('SIG-048', 'withdraw'),
 ('SIG-049', 'withdraw'),
 ('SIG-050', 'withdraw')]
    RCA_OTHER_REPLAY_PATTERNS = [('SIG-001', 'deposit', {}),
 ('SIG-021', 'getShareValue', {}),
 ('SIG-017', 'deposit', {}),
 ('SIG-003', 'getPrice', {'spot_price_oracle': True}),
 ('SIG-004', 'getPrice', {'spot_price_oracle': True}),
 ('SIG-005', 'getPrice', {'spot_price_oracle': True}),
 ('SIG-006', 'getPrice', {'spot_price_oracle': True}),
 ('SIG-015', 'deposit', {}),
 ('SIG-024', 'deposit', {}),
 ('SIG-025', 'init', {}),
 ('SIG-013', 'getPrice', {'spot_price_oracle': True}),
 ('SIG-026', 'getPrice', {'spot_price_oracle': True}),
 ('SIG-027', 'getPrice', {'spot_price_oracle': True}),
 ('SIG-028', 'getPrice', {'spot_price_oracle': True}),
 ('SIG-002', 'initWallet', {}),
 ('SIG-007', 'verifySignature', {}),
 ('SIG-016', 'swapOut', {}),
 ('SIG-030', 'deposit', {}),
 ('SIG-008', 'withdrawERC20', {}),
 ('SIG-010', 'confirmTx', {}),
 ('SIG-012', 'transfer', {}),
 ('SIG-018', 'withdraw', {}),
 ('SIG-032', 'exportKey', {}),
 ('SIG-033', 'sweepFunds', {}),
 ('SIG-034', 'batchTransfer', {}),
 ('SIG-035', 'batchTransfer', {}),
 ('SIG-011', 'process', {}),
 ('SIG-014', 'withdrawCustomer', {}),
 ('SIG-037', 'claimDistribution', {}),
 ('SIG-038', 'claimDistribution', {}),
 ('SIG-040', 'getPrice', {'spot_price_oracle': True}),
 ('SIG-041', 'transfer', {}),
 ('SIG-041', 'emergencyWithdraw', {}),
 ('SIG-042', 'transfer', {}),
 ('SIG-042', 'emergencyWithdraw', {}),
 ('SIG-043', 'transfer', {}),
 ('SIG-043', 'emergencyWithdraw', {}),
 ('SIG-046', 'getPrice', {'spot_price_oracle': True}),
 ('SIG-047', 'processDeposit', {}),
 ('SIG-048', 'processDeposit', {}),
 ('SIG-049', 'processDeposit', {}),
 ('SIG-050', 'processDeposit', {})]

    @classmethod
    def setUpClass(cls):
        cls.encoder = md.CodeEncoder()
        cls.extractor = md.IntentCodeMismatchDetector()

    def _summarize(self, function_source, contract_source=None):
        # RED runs against the original one-argument API; candidate runs also exercise helper resolution.
        import inspect
        params = inspect.signature(self.encoder.summarize).parameters
        if contract_source is not None and "contract_source" in params:
            return self.encoder.summarize(function_source, contract_source=contract_source)
        return self.encoder.summarize(function_source)

    def _summarize_function(self, contract_source, function_name, helper_source=True):
        function_source = self.extractor._extract_function_body(contract_source, function_name)
        self.assertTrue(function_source, f"could not extract {function_name}")
        return self._summarize(
            function_source,
            contract_source if helper_source else None,
        )

    def test_p1_minimal_proxy_deploy_then_initialize_is_fresh(self):
        path = os.path.join(SCRIPT_DIR, "proxy_fp_tests", "MinimalProxy.sol")
        with open(path, encoding="utf-8") as f:
            contract_source = f.read()
        function_source = self.extractor._extract_function_body(
            contract_source, "createCloneWithInit"
        )
        self.assertTrue(function_source)
        patterns = self._summarize(function_source, contract_source)
        self.assertNotIn("missing_reentrancy_guard", patterns)

    def test_p2_new_expression_target_is_fresh(self):
        source = """
        contract Child {}
        contract Factory {
            function initialize(bytes memory data) external returns (bool) {
                address c = address(new Child());
                (bool ok,) = c.call(data);
                return ok;
            }
        }
        """
        patterns = self._summarize_function(source, "initialize")
        self.assertNotIn("missing_reentrancy_guard", patterns)

    def test_p3_inline_create2_target_is_fresh(self):
        source = """
        contract Factory {
            function initialize(bytes memory data, bytes memory code, bytes32 salt)
                external returns (bool)
            {
                address c;
                assembly { c := create2(0, add(code, 32), mload(code), salt) }
                (bool ok,) = c.call(data);
                return ok;
            }
        }
        """
        patterns = self._summarize_function(source, "initialize")
        self.assertNotIn("missing_reentrancy_guard", patterns)

    def test_p4_same_source_creation_helper_is_fresh(self):
        source = """
        contract Factory {
            function run(address impl, bytes calldata data) external {
                address c = _deployClone(impl);
                (bool ok,) = c.call(data);
                require(ok);
            }
            function _deployClone(address) internal returns (address clone) {
                assembly { clone := create(0, 0, 0) }
            }
        }
        """
        patterns = self._summarize_function(source, "run")
        self.assertNotIn("missing_reentrancy_guard", patterns)

    def test_p5_two_level_same_source_creation_helper_is_fresh(self):
        source = """
        contract Factory {
            function run(address impl, bytes calldata data) external {
                address c = _middle(impl);
                (bool ok,) = c.call(data);
                require(ok);
            }
            function _middle(address impl) internal returns (address clone) {
                clone = _create(impl);
            }
            function _create(address) internal returns (address clone) {
                assembly { clone := create2(0, 0, 0, 0) }
            }
        }
        """
        patterns = self._summarize_function(source, "run")
        self.assertNotIn("missing_reentrancy_guard", patterns)

    def test_p6_address_and_payable_wrapped_targets_are_fresh(self):
        source = """
        contract Child {}
        contract Factory {
            function initialize(bytes memory data) external {
                address c = address(new Child());
                address(c).call(data);
                payable(c).call(data);
            }
        }
        """
        patterns = self._summarize_function(source, "initialize")
        self.assertNotIn("missing_reentrancy_guard", patterns)

    def test_d1_parameter_target_is_not_fresh(self):
        source = "contract C { function run(address target, bytes calldata data) external { target.call(data); } }"
        self.assertIn("missing_reentrancy_guard", self._summarize_function(source, "run"))

    def test_d2_reassignment_after_creation_is_not_fresh(self):
        source = """
        contract Factory {
            function run(address impl, address target, bytes calldata data) external {
                address c = _deployClone(impl);
                c = target;
                c.call(data);
            }
            function _deployClone(address) internal returns (address clone) {
                assembly { clone := create(0, 0, 0) }
            }
        }
        """
        self.assertIn("missing_reentrancy_guard", self._summarize_function(source, "run"))

    def test_d3_lookup_helper_is_not_creation(self):
        source = """
        contract Factory {
            address stored;
            function run(address impl, bytes calldata data) external {
                address c = _lookup(impl);
                c.call(data);
            }
            function _lookup(address) internal view returns (address) { return stored; }
        }
        """
        self.assertIn("missing_reentrancy_guard", self._summarize_function(source, "run"))

    def test_d4_call_on_different_variable_is_not_fresh(self):
        source = """
        contract Child {}
        contract Factory {
            function run(address d, bytes calldata data) external {
                address c = address(new Child());
                d.call(data);
            }
        }
        """
        self.assertIn("missing_reentrancy_guard", self._summarize_function(source, "run"))

    def test_d5_creation_in_comment_and_string_is_ignored(self):
        source = """
        contract C {
            function run(bytes calldata data) external {
                // address c = address(new Child());
                string memory decoy = "address c = address(new Child());";
                c.call(data);
            }
        }
        """
        self.assertIn("missing_reentrancy_guard", self._summarize_function(source, "run"))

    def test_d6_every_call_is_checked(self):
        source = """
        contract Child {}
        contract C {
            function run(address target, bytes calldata data) external {
                address c = address(new Child());
                c.call(data);
                target.call(data);
            }
        }
        """
        self.assertIn("missing_reentrancy_guard", self._summarize_function(source, "run"))

    def test_d7_three_level_helper_chain_exceeds_resolution_limit(self):
        source = """
        contract Child {}
        contract Factory {
            function run(address impl, bytes calldata data) external {
                address c = _f(impl);
                c.call(data);
            }
            function _f(address impl) internal returns (address) { return _g(impl); }
            function _g(address impl) internal returns (address) { return _h(impl); }
            function _h(address) internal returns (address) { return address(new Child()); }
        }
        """
        self.assertIn("missing_reentrancy_guard", self._summarize_function(source, "run"))

    def test_d8_helper_is_unresolved_without_contract_source(self):
        source = """
        contract Factory {
            function run(address impl, bytes calldata data) external {
                address c = _deployClone(impl);
                c.call(data);
            }
            function _deployClone(address) internal returns (address clone) {
                assembly { clone := create(0, 0, 0) }
            }
        }
        """
        self.assertIn(
            "missing_reentrancy_guard",
            self._summarize_function(source, "run", helper_source=False),
        )

    def test_d9_tuple_target_is_not_accepted_as_creation(self):
        source = """
        contract Child {}
        contract Factory {
            function run(bytes calldata data) external {
                address c;
                (, c) = (true, address(new Child()));
                c.call(data);
            }
        }
        """
        self.assertIn("missing_reentrancy_guard", self._summarize_function(source, "run"))

    def test_d10_tuple_reassignment_cancels_freshness(self):
        source = """
        contract Child {}
        contract Factory {
            function run(address target, bytes calldata data) external {
                address c = address(new Child());
                (, c) = (true, target);
                c.call(data);
            }
        }
        """
        self.assertIn("missing_reentrancy_guard", self._summarize_function(source, "run"))

    def test_r1_all_replay_guard_dependencies_and_other_patterns_match_rca(self):
        from attack_replay_contracts import REPLAY_CONTRACTS

        self.assertEqual(53, len(self.RCA_MISSING_GUARD_PAIRS))
        sources = {item["sig_id"]: item["source"] for item in REPLAY_CONTRACTS}
        for sig_id, function_name in self.RCA_MISSING_GUARD_PAIRS:
            source = sources[sig_id]
            function_source = self.extractor._extract_function_body(source, function_name)
            self.assertTrue(function_source, f"{sig_id}:{function_name} source missing")
            patterns = self._summarize(function_source, source)
            self.assertIn(
                "missing_reentrancy_guard", patterns,
                f"fix suppressed RCA replay dependency {sig_id}:{function_name}",
            )

        self.assertEqual(42, len(self.RCA_OTHER_REPLAY_PATTERNS))
        for sig_id, function_name, expected_patterns in self.RCA_OTHER_REPLAY_PATTERNS:
            source = sources[sig_id]
            function_source = self.extractor._extract_function_body(source, function_name)
            self.assertTrue(function_source, f"{sig_id}:{function_name} source missing")
            actual_patterns = self._summarize(function_source, source)
            self.assertEqual(
                expected_patterns, actual_patterns,
                f"unexpected pattern drift for {sig_id}:{function_name}",
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
