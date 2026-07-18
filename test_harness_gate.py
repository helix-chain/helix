"""
test_harness_gate.py
Version: V1.2

Probe self-test for the deterministic harness gate (.ci/harness_check.py +
.ci/harness_rules.yaml). Proves the gate actually BITES: dangerous staged
content and disclosure-boundary / schema-drift violations must FAIL, and a
clean tree must PASS. Without this, "we have a gate" is unproven — a broken
rule or a checker regression could silently let bad content through (the same
class of false-green the gate itself exists to prevent).

Runs WITHOUT torch/transformers (stdlib only), like test_output_contract.py, so
it is cheap enough to run in CI / pre-commit. It is designed to be wired into
CI as its own step (see the Makefile `harness-selftest` target); until then it
is runnable directly. It exercises the SHIPPED checker + SHIPPED rules (invoked
by their real repo paths against throwaway temp git repos), so it also
regression-guards the helix-specific rules (gated-file names, RPC-key pattern,
canonical-score-key required_pattern) and the no-PyYAML minimal-parser path that
CI actually uses (the gate runs before torch/transformers are installed).

Every FAIL test asserts a rule-specific token in the output, not merely a
non-zero exit code, so a checker that fails for an UNRELATED reason (a crash, an
argparse error) cannot masquerade as a passing probe.

Run:  python test_harness_gate.py
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
HARNESS = os.path.join(SCRIPT_DIR, ".ci", "harness_check.py")
RULES = os.path.join(SCRIPT_DIR, ".ci", "harness_rules.yaml")

# A .gitignore that satisfies the rules' sensitive_paths ignore-gate, so `staged`
# probes are isolated from the (separate) ignore-gate check.
GITIGNORE = "\n".join([
    "_gated/", ".env", "CLAUDE.md", "CODE_MAP.md", "AGENTS.md", "docs/",
    ".claude/", "hpl_ledger.json", "signature_pipeline/", "attack_replays_gated/",
    "30_outputs/", ".relay/", "",
])


def _git(repo, *args):
    """Run a git command in repo, raising on failure (never uses `git add -A`)."""
    subprocess.run(
        ["git", "-C", repo, *args],
        check=True, capture_output=True, text=True,
        encoding="utf-8", errors="replace",
    )


def _run_gate(repo, cmd, extra_env=None):
    """Invoke the SHIPPED harness checker via its real CLI. Returns (rc, output).

    Encoding is pinned (utf-8/replace) so the checker's CJK [PASS]/[FAIL] lines
    can never raise a UnicodeEncodeError in capture and mask the real exit code.
    """
    proc = subprocess.run(
        [sys.executable, HARNESS, cmd, "--rules", RULES, "--repo", repo],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        env=extra_env,
    )
    return proc.returncode, (proc.stdout + proc.stderr)


class HarnessGateProbe(unittest.TestCase):
    def setUp(self):
        # Python-managed temp dir (no shell rm -rf); torn down in tearDown.
        self.repo = tempfile.mkdtemp(prefix="helix_harness_probe_")
        _git(self.repo, "init", "-q")
        _git(self.repo, "config", "user.email", "probe@test.local")
        _git(self.repo, "config", "user.name", "probe")
        self._write(".gitignore", GITIGNORE)

    def tearDown(self):
        # shutil.rmtree is a Python call, not a shell recursive delete.
        shutil.rmtree(self.repo, ignore_errors=True)

    def _write(self, rel, content):
        path = os.path.join(self.repo, rel)
        os.makedirs(os.path.dirname(path) or self.repo, exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(content)
        return path

    def _stage(self, rel, force=False):
        args = ["add"] + (["-f"] if force else []) + [rel]
        _git(self.repo, *args)

    # --- dangerous staged content must FAIL (exit 1) ----------------------

    def test_staged_dotenv_fails(self):
        """A staged .env (forbidden_staged_names) must fail the gate."""
        self._write(".env", "SECRET=supersecretvalue\n")
        self._stage(".env", force=True)  # .env is gitignored -> force to stage
        rc, out = _run_gate(self.repo, "staged")
        self.assertEqual(rc, 1, f"expected FAIL on staged .env; out=\n{out}")
        self.assertIn(".env", out)

    def test_staged_secret_token_fails(self):
        """A staged file with a secret-like token must fail (SECRET_RX 'sk-')."""
        # Assemble the token at runtime so THIS test file carries no scannable
        # literal — otherwise the harness grep (and GitHub secret scanning) would
        # flag the fixture in the test source itself. See _rpc url note below.
        token = "sk-" + "abcdefghij1234567890abcd"
        self._write("config.txt", f"api = '{token}'\n")
        self._stage("config.txt")
        rc, out = _run_gate(self.repo, "staged")
        self.assertEqual(rc, 1, f"expected FAIL on staged secret token; out=\n{out}")
        # Assert the INTENDED rule fired, not merely some non-zero exit.
        self.assertIn("sk- API key", out)

    def test_staged_gated_moat_file_fails(self):
        """A force-staged gated immune-library file must fail (helix rule)."""
        self._write("immune_live.json", "{}\n")
        self._stage("immune_live.json", force=True)
        rc, out = _run_gate(self.repo, "staged")
        self.assertEqual(rc, 1, f"expected FAIL on gated moat file; out=\n{out}")
        self.assertIn("immune_live.json", out)

    def test_staged_rpc_key_url_fails(self):
        """A staged hosted-RPC URL carrying a key must fail (helix rule)."""
        # Split right after "infura.io/" so the literal in THIS source never
        # matches the RPC forbidden_pattern (which needs the host + >=12 key
        # chars contiguous); the runtime concat rebuilds the real leak string.
        url = "https://mainnet.infura.io/" + "v3/9aa3d95b3bc440fa88ea12eaa4456161"
        self._write("rpc.txt", f"RPC={url}\n")
        self._stage("rpc.txt")
        rc, out = _run_gate(self.repo, "staged")
        self.assertEqual(rc, 1, f"expected FAIL on RPC-key URL; out=\n{out}")
        # Assert the INTENDED rule fired (the RPC pattern echoes "infura").
        self.assertIn("infura", out)

    # --- disclosure-boundary ignore gate ----------------------------------

    def test_ignore_gate_flags_unignored_sensitive_path(self):
        """Public repo: a sensitive_path not covered by .gitignore must fail."""
        # Overwrite .gitignore so `_gated/` is NOT ignored -> leak risk.
        self._write(".gitignore", ".env\n")
        rc, out = _run_gate(self.repo, "ignore")
        self.assertEqual(rc, 1, f"expected FAIL: _gated/ not ignored; out=\n{out}")
        self.assertIn("_gated", out)

    # --- schema-drift (ci-key-grep / 9ff61b7) -----------------------------

    def test_grep_required_key_drift_fails(self):
        """Renaming the canonical scoring key must fail the required_pattern."""
        # Emit the wrong (legacy) key -> the emission-anchored required_pattern misses.
        self._write("mismatch_detector.py", 'def a():\n    return {"risk_score": 0.0}\n')
        self._write("proxy_fp_test_runner.py", 'SCORE_KEY = "overall_mismatch_score"\n')
        self._stage("mismatch_detector.py")
        self._stage("proxy_fp_test_runner.py")
        rc, out = _run_gate(self.repo, "grep")
        self.assertEqual(rc, 1, f"expected FAIL on canonical-key drift; out=\n{out}")
        self.assertIn("overall_mismatch_score", out)

    def test_minimal_parser_catches_drift(self):
        """The no-PyYAML minimal parser (the actual CI path — the gate runs
        before torch/transformers/PyYAML are installed) must still parse the
        helix required_patterns and catch canonical-key drift."""
        self._write("mismatch_detector.py", 'def a():\n    return {"risk_score": 0.0}\n')
        self._write("proxy_fp_test_runner.py", 'SCORE_KEY = "overall_mismatch_score"\n')
        self._stage("mismatch_detector.py")
        self._stage("proxy_fp_test_runner.py")
        # Shim that makes `import yaml` raise -> checker falls back to minimal parser.
        shim = tempfile.mkdtemp(prefix="helix_noyaml_")
        try:
            with open(os.path.join(shim, "yaml.py"), "w", encoding="utf-8") as f:
                f.write('raise ImportError("forced no-yaml for probe")\n')
            env = dict(os.environ)
            env["PYTHONPATH"] = shim + os.pathsep + env.get("PYTHONPATH", "")
            rc, out = _run_gate(self.repo, "grep", extra_env=env)
        finally:
            shutil.rmtree(shim, ignore_errors=True)
        self.assertEqual(rc, 1, f"expected FAIL under minimal parser; out=\n{out}")
        self.assertIn("overall_mismatch_score", out)

    # --- service_role secret rule, under BOTH parser paths ----------------

    def _seed_canonical_keys(self):
        """Stage the canonical-key anchor files so a `grep` run's only possible
        failure is the forbidden_pattern under test, not a required_pattern miss."""
        self._write("mismatch_detector.py", 'def a():\n    return {"overall_mismatch_score": 0.0}\n')
        self._write("proxy_fp_test_runner.py", 'SCORE_KEY = "overall_mismatch_score"\n')
        self._stage("mismatch_detector.py")
        self._stage("proxy_fp_test_runner.py")

    def _service_role_line(self):
        """A service_role JWT assignment, assembled at runtime so this test file
        carries no scannable literal (it must not trip the very rule it tests)."""
        return "service_role" + ": " + "eyJ" + "hbGciOiJIUzI1NiJ9.cGF5bG9hZA.c2ln\n"

    def test_service_role_secret_in_tracked_file_fails(self):
        """A service_role JWT in a tracked file must fail grep (default parser)."""
        self._seed_canonical_keys()
        self._write("creds.txt", self._service_role_line())
        self._stage("creds.txt")
        rc, out = _run_gate(self.repo, "grep")
        self.assertEqual(rc, 1, f"expected FAIL on service_role secret; out=\n{out}")
        self.assertIn("service_role", out)

    def test_service_role_secret_caught_under_minimal_parser(self):
        """The same catch must hold under the no-PyYAML minimal parser (CI's real
        path). This is the exact regression the parser-stability fix closes: the
        old double-quoted rule degraded to a literal-backslash pattern here and
        silently never fired."""
        self._seed_canonical_keys()
        self._write("creds.txt", self._service_role_line())
        self._stage("creds.txt")
        shim = tempfile.mkdtemp(prefix="helix_noyaml_")
        try:
            with open(os.path.join(shim, "yaml.py"), "w", encoding="utf-8") as f:
                f.write('raise ImportError("forced no-yaml for probe")\n')
            env = dict(os.environ)
            env["PYTHONPATH"] = shim + os.pathsep + env.get("PYTHONPATH", "")
            rc, out = _run_gate(self.repo, "grep", extra_env=env)
        finally:
            shutil.rmtree(shim, ignore_errors=True)
        self.assertEqual(rc, 1, f"expected FAIL under minimal parser; out=\n{out}")
        self.assertIn("service_role", out)

    # --- negative controls: clean content must PASS (exit 0) --------------

    def test_clean_staged_content_passes(self):
        """Benign staged content must pass the staged gate."""
        self._write("notes.md", "# Notes\nAll good here.\n")
        self._stage("notes.md")
        rc, out = _run_gate(self.repo, "staged")
        self.assertEqual(rc, 0, f"expected PASS on clean staged file; out=\n{out}")

    def test_clean_tree_passes_all(self):
        """A tree with proper .gitignore + canonical keys must pass `all`."""
        self._write("mismatch_detector.py", 'def a():\n    return {"overall_mismatch_score": 0.0}\n')
        self._write("proxy_fp_test_runner.py", 'SCORE_KEY = "overall_mismatch_score"\n')
        self._stage("mismatch_detector.py")
        self._stage("proxy_fp_test_runner.py")
        rc, out = _run_gate(self.repo, "all")
        self.assertEqual(rc, 0, f"expected PASS on clean tree; out=\n{out}")


if __name__ == "__main__":
    if not (os.path.isfile(HARNESS) and os.path.isfile(RULES)):
        print(f"[ERROR] harness not found: {HARNESS} / {RULES}", file=sys.stderr)
        sys.exit(2)
    unittest.main(verbosity=2)
