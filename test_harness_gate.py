"""
test_harness_gate.py
Version: V1.5

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
canonical-score-key required_patterns) and the no-PyYAML minimal-parser path that
CI actually uses (the gate runs before torch/transformers are installed).

Every FAIL test asserts a rule-specific token in the output, not merely a
non-zero exit code, so a checker that fails for an UNRELATED reason (a crash, an
argparse error) cannot masquerade as a passing probe.

V1.3 additions (M2 hardening — consumer read-site anchors)
----------------------------------------------------------
The required_patterns list grew five entries (see .ci/harness_rules.yaml). Two
things follow, and both are tested here:

  * Every probe that seeds a subset of the anchored files would now fail for the
    WRONG reason (a missing peer file), so `_seed_canonical_keys()` seeds ALL
    anchored files from a single minimal-seed dict (`MINIMAL_SEEDS`).
  * A synthetic mini-file can show the regex compiles; it cannot show the regex
    matches the REAL code. `RealTreeAnchorProbe` therefore copies the REAL
    consumer files into a temp git repo and drives the shipped checker over
    them: a positive control (unmodified real copies -> rc 0) plus one bait per
    anchor. Each bait replaces the real read site with a drift/soft-default form
    and must flip the gate red, naming EXACTLY the mutated file.

V1.3 fix round 1 (M2, closes the sol review's P1-1 and P1-2)
-----------------------------------------------------------------------------
P1-1  The rules anchored the emitted dict key and the dataclass field, but not
      the SERIALIZATION read that turns a MismatchReport into the dict every
      consumer sees (mismatch_detector.py L512,
      `"overall_mismatch_score": round(report.overall_mismatch_score, 4)`,
      inside analyze_contract()). A maintainer rewriting that one line as
      `round(getattr(report, "risk_score", 0.0), 4)` keeps the field and the key
      while silently emitting 0.0 to every consumer — the 9ff61b7 silent-0.0
      class, one line upstream. A seventh required_patterns entry now binds that
      read site, and two baits below drive it on the REAL mismatch_detector.py
      so the probe proves the anchor bites (not merely that it compiles).

P1-2  The two old drift tests replaced mismatch_detector.py with a dict carrying
      NEITHER the dataclass field NOR the emitted key, so a failure could come
      from either anchor and removing the emission rule still left them green.
      They now keep the field AND the serialization read and break ONLY the
      emitted dict key, they assert the single FAIL line names that exact rule,
      and a negative control (`test_emission_rule_removed_fixture_is_green`)
      deletes the emission rule from a rules COPY and shows the same fixture
      goes green — i.e. the two drift tests depend on the emission rule and on
      nothing else.

D)  Every bait loop runs each iteration in a subTest, so the first failing bait
    no longer hides the ones after it.

Run:  python test_harness_gate.py

V1.4 additions (F1/F2 fail-closed hardening)
--------------------------------------------
Adds regression probes for path-scoped checker/rules exemptions, README and
same-basename decoys (including built-in secret fallbacks), tracked-file read
errors, Git command errors and return-code semantics, explicit rules-file
failures, the portable missing-default-rules skip, and a real-tree positive
control. Secret-shaped test data is assembled at runtime.

V1.5 additions (path handling and cleanup)
-------------------------------------------
Adds coverage for NUL-delimited Git path lists, literal pathspecs, Unicode
names, invalid UTF-8 paths, default rules directories, and read-only Git-tree
cleanup.
"""

import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import unittest.mock

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

def _retry_readonly_removal(function, path, exc_info):
    """rmtree error handler: clear the read-only bit and retry the removal.

    rmtree also reports a file that vanished before it could be unlinked (for
    example a lock file that git's background maintenance removed first). That
    path is already gone, which is the goal, so it is not an error.
    """
    reported = exc_info[1] if isinstance(exc_info, tuple) else exc_info
    if isinstance(reported, FileNotFoundError):
        return
    try:
        os.chmod(path, stat.S_IREAD | stat.S_IWRITE | stat.S_IEXEC)
        function(path)
    except FileNotFoundError:
        return


def _remove_tree(path):
    if os.path.lexists(path):
        if sys.version_info >= (3, 12):
            shutil.rmtree(path, onexc=_retry_readonly_removal)
        else:
            shutil.rmtree(path, onerror=_retry_readonly_removal)


HARNESS = os.path.join(SCRIPT_DIR, ".ci", "harness_check.py")
RULES = os.path.join(SCRIPT_DIR, ".ci", "harness_rules.yaml")

# A .gitignore that satisfies the rules' sensitive_paths ignore-gate, so `staged`
# probes are isolated from the (separate) ignore-gate check.
GITIGNORE = "\n".join([
    "_gated/", ".env", "CLAUDE.md", "CODE_MAP.md", "AGENTS.md", "docs/",
    ".claude/", "hpl_ledger.json", "signature_pipeline/", "attack_replays_gated/",
    "30_outputs/", ".relay/", "",
])

# --- minimal valid seed for EVERY file carrying a required_pattern ----------
# One place only: a probe that seeds a subset fails for a reason it did not
# intend (an unseeded *peer* anchor), which is a false red and hides the bait.
# Keys are the rule file names; values are minimal content that satisfies each
# anchor's access form (dataclass field / attribute read / quoted dict
# subscript). Add a key here whenever a new required_patterns entry is added.
MINIMAL_SEEDS = {
    "mismatch_detector.py": 'def a():\n    return {"overall_mismatch_score": 0.0}\n',
    "proxy_fp_test_runner.py": 'SCORE_KEY = "overall_mismatch_score"\n',
    "replay_test_runner.py": "score = report.overall_mismatch_score\n",
    "mainnet_test_runner.py": 'score = result["overall_mismatch_score"]\n',
    "ci_smoke_test.py": 'score = res["overall_mismatch_score"]\n',
    "helix_scan.py": 'score = result["overall_mismatch_score"]\n',
}

# Seed that also carries the dataclass field line the mismatch_detector anchor
# binds (the plain dict-key seed above satisfies the OLD emission anchor only).
# The real line carries a trailing annotation comment; the anchor only needs
# `overall_mismatch_score: float`, so the seed keeps a comment tail to mirror
# the real file (and to prove the anchor is not fooled by a trailing comment).
DATACLASS_FIELD_LINE = "    overall_mismatch_score: float          # 0.0 (aligned) \u2192 1.0 (severe mismatch)\n"
MINIMAL_SEEDS["mismatch_detector.py"] = (
    "from dataclasses import dataclass\n"
    "@dataclass\n"
    "class MismatchReport:\n"
    + DATACLASS_FIELD_LINE
    # The body must ALSO satisfy the P1-1 serialization anchor: like the real
    # analyze_contract() at mismatch_detector.py L512, it reads the attribute off
    # a MismatchReport and rounds it into the emitted dict. A bare
    # `{"overall_mismatch_score": 0.0}` literal (the old seed) satisfies the two
    # key anchors but NOT the read-site anchor, so every `_seed_canonical_keys`
    # probe would go red for a peer reason instead of the one under test.
    + 'def a():\n    return {"overall_mismatch_score": round(report.overall_mismatch_score, 4)}\n'
)

# The real consumer files RealTreeAnchorProbe copies into its temp repo.
REAL_CONSUMER_FILES = [
    "mismatch_detector.py",
    "replay_test_runner.py",
    "mainnet_test_runner.py",
    "ci_smoke_test.py",
    "helix_scan.py",
    "proxy_fp_test_runner.py",
]

# One bait per anchor: (file, exact text to replace, its occurrence count,
# replacement, the one file the gate MUST name as `required 未满足: <file>`).
BAITS = [
    (
        "mainnet_test_runner.py",
        'score = result["overall_mismatch_score"]', 1,
        'score = result["risk_score"]',
        "mainnet_test_runner.py",
    ),
    (
        "ci_smoke_test.py",
        'score = res["overall_mismatch_score"]', 1,
        'score = res.get("overall_mismatch_score", 0.0)',
        "ci_smoke_test.py",
    ),
    (
        "helix_scan.py",
        'score = result["overall_mismatch_score"]', 1,
        'score = result.get("overall_mismatch_score", 0.0)',
        "helix_scan.py",
    ),
    (
        "replay_test_runner.py",
        "score = report.overall_mismatch_score", 1,
        'score = getattr(report, "overall_mismatch_score", 0.0)',
        "replay_test_runner.py",
    ),
    (
        "replay_test_runner.py",
        "score = report.overall_mismatch_score", 1,
        "score = report.mismatch_score  # report.overall_mismatch_score",
        "replay_test_runner.py",
    ),
    (
        # The real tree is CRLF; this bait is EOL-agnostic (the `_mutate` hook
        # below translates the bare \n to the file's own line ending).
        "mismatch_detector.py",
        DATACLASS_FIELD_LINE, 1,
        DATACLASS_FIELD_LINE.replace("overall_mismatch_score", "mismatch_score"),
        "mismatch_detector.py",
        True,
    ),
    # --- P1-1 baits: the SERIALIZATION read at mismatch_detector.py L512 ------
    # Both keep the dataclass field (L31) and leave the emitted dict KEY in
    # place; only the read that produces the value changes. Neither is caught
    # without the P1-1 rule (see probe/red_old_rules.txt).
    (
        "mismatch_detector.py",
        "round(report.overall_mismatch_score, 4)", 1,
        'round(getattr(report, "risk_score", 0.0), 4)',
        "mismatch_detector.py",
    ),
    (
        "mismatch_detector.py",
        "round(report.overall_mismatch_score, 4)", 1,
        'round(getattr(report, "overall_mismatch_score", 0.0), 4)',
        "mismatch_detector.py",
    ),
]

NOYAML_SHIM_BODY = 'raise ImportError("forced no-yaml for probe")\n'


_PENDING_TEST_ADDS = {}


def _flush_test_adds(repo):
    key = os.path.normcase(os.path.abspath(repo))
    paths = _PENDING_TEST_ADDS.pop(key, [])
    if paths:
        subprocess.run(
            ["git", "-C", repo, "add", "--", *paths],
            check=True, capture_output=True, text=True,
            encoding="utf-8", errors="replace",
        )


def _git(repo, *args):
    """Run a git command in repo; batch explicit single-path adds until a gate."""
    if args and args[0] == "add" and "-f" not in args and "--force" not in args:
        paths = list(args[args.index("--") + 1:]) if "--" in args else [
            arg for arg in args[1:] if arg not in ("-f", "--force")
        ]
        if len(paths) == 1 and paths[0] not in (".", "-A", "--all"):
            key = os.path.normcase(os.path.abspath(repo))
            _PENDING_TEST_ADDS.setdefault(key, []).extend(paths)
            return
    _flush_test_adds(repo)
    subprocess.run(
        ["git", "-C", repo, *args],
        check=True, capture_output=True, text=True,
        encoding="utf-8", errors="replace",
    )
    if args and args[0] == "init":
        # A commit can start git's detached background maintenance, which writes
        # and removes files under .git/objects while the test tears the repo
        # down. Fixture repos never need it.
        for key, value in (("maintenance.auto", "false"), ("gc.auto", "0")):
            subprocess.run(
                ["git", "-C", repo, "config", key, value],
                check=True, capture_output=True, text=True,
                encoding="utf-8", errors="replace",
            )


def _run_gate(repo, cmd, extra_env=None, rules=None):
    """Invoke the SHIPPED checker module through its CLI parser in-process.
    Returns (rc, output); preserving the same argv/output contract avoids
    repeated interpreter startup in the exhaustive real-tree bait loops.

    Encoding is pinned (utf-8/replace) so the checker's CJK [PASS]/[FAIL] lines
    can never raise a UnicodeEncodeError in capture and mask the real exit code.
    `rules` defaults to the SHIPPED RULES, so every pre-existing call site keeps
    running the real rule file; a caller may point at a mutated COPY instead
    (used by the P1-2 negative control), which is why this is an optional
    parameter rather than a second near-identical helper.
    """
    _flush_test_adds(repo)
    from contextlib import nullcontext, redirect_stderr, redirect_stdout
    from io import StringIO
    from unittest.mock import patch

    module = getattr(_run_gate, "_module", None)
    if module is None:
        import importlib.util
        spec = importlib.util.spec_from_file_location("harness_gate_cli", HARNESS)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        _run_gate._module = module

    old_argv, old_path = sys.argv[:], sys.path[:]
    previous_yaml = sys.modules.pop("yaml", None)
    env = extra_env if extra_env is not None else os.environ
    pythonpath = env.get("PYTHONPATH", "")
    if pythonpath:
        sys.path[:0] = [p for p in pythonpath.split(os.pathsep) if p]
    sys.argv = [HARNESS, cmd, "--rules", rules or RULES, "--repo", repo]
    output, errors = StringIO(), StringIO()
    env_patch = patch.dict(os.environ, extra_env, clear=True) if extra_env is not None else nullcontext()
    try:
        with env_patch, redirect_stdout(output), redirect_stderr(errors):
            try:
                rc = module.main()
            except SystemExit as exc:
                rc = exc.code or 0
    finally:
        sys.argv, sys.path = old_argv, old_path
        sys.modules.pop("yaml", None)
        if previous_yaml is not None:
            sys.modules["yaml"] = previous_yaml
    return rc, output.getvalue() + errors.getvalue()


def _noyaml_env():
    """Return (env, shim_dir) forcing the checker's no-PyYAML minimal parser.

    The shim dir holds a yaml.py that raises ImportError, so `import yaml`
    inside _load_rules falls back to the built-in minimal parser — the path CI
    really uses (the gate runs before PyYAML is installed). Caller removes
    shim_dir in a finally block.
    """
    shim = tempfile.mkdtemp(prefix="helix_noyaml_")
    with open(os.path.join(shim, "yaml.py"), "w", encoding="utf-8") as f:
        f.write(NOYAML_SHIM_BODY)
    env = dict(os.environ)
    env["PYTHONPATH"] = shim + os.pathsep + env.get("PYTHONPATH", "")
    return env, shim


def _fail_lines(out):
    """The `required 未满足: ...` FAIL lines, verbatim (one per unmet anchor)."""
    return [ln for ln in out.splitlines() if "required 未满足:" in ln]


def _missing_required(out):
    """Set of rel paths the checker named as `required 未满足` (the FAIL lines)."""
    return set(re.findall(r"required 未满足: (\S+)", out))


def _rule_lines(path):
    """The required_patterns list items of a rules file, as (file, pattern).

    Read straight out of the rule FILE (never hardcoded), so an assertion built
    on these strings fails the moment the rule they describe is removed or
    renamed. Split on the FIRST `::`, exactly like `cmd_grep` does.
    """
    out = []
    with open(path, "r", encoding="utf-8", newline="") as f:
        for raw in f:
            s = raw.split("#", 1)[0].strip()
            if not s.startswith("- "):
                continue
            item = s[2:].strip().strip("\"'")
            if "::" in item:
                out.append(tuple(item.split("::", 1)))
    return out


# A mismatch_detector.py anchor counts as the EMISSION rule when its regex
# requires the QUOTED canonical key immediately followed by a colon — i.e. it
# binds the `"overall_mismatch_score": ` output surface and nothing else. The
# dataclass-field anchor (`...\\s*float\\b`) and the P1-1 serialization anchor
# (`...\\breport\\.overall_mismatch_score\\b`) both carry the token but neither
# matches this shape, which is what makes the identification unambiguous.
# The quote characters a YAML scalar may be wrapped in; the emission anchor
# binds the key in either form. Assembled from chr() so this test source
# stays readable (no quadruple-escaped quote soup).
_QUOTES = chr(34) + chr(39)
# The EMISSION anchor's regex, as the LITERAL text a pattern must contain:
# a quote, the canonical key, a quote, then the regex escape for whitespace
# followed by '*:' . re.escape is applied to that tail so the backslash and
# the '*' are compared as characters, not as regex metacharacters.
_EMISSION_TAIL = chr(92) + 's*:'
_EMISSION_RULE_RX = re.compile(
    "^[" + re.escape(_QUOTES) + "]overall_mismatch_score["
    + re.escape(_QUOTES) + "]" + re.escape(_EMISSION_TAIL)
)

def _emission_rules(rules_path):
    """ALL required_patterns entries binding the emitted dict key (quoted key +
    colon) for mismatch_detector.py. Empty when the rule has been removed —
    which is exactly what the P1-2 negative control asserts."""
    return [
        (f, p) for f, p in _rule_lines(rules_path)
        if f == "mismatch_detector.py" and _EMISSION_RULE_RX.match(p)
    ]


def _emission_rule(rules_path):
    """The (file, pattern) pair of the EMISSION rule — the required_patterns
    entry that binds the emitted dict key (quoted key + colon), as opposed to
    the dataclass field declaration or the P1-1 serialization read.

    Asserts the rule EXISTS: every caller except the negative control wants the
    shipped tree's rule, and a silent None there would turn the assertion that
    depends on it into a vacuous pass.
    """
    cands = _emission_rules(rules_path)
    assert len(cands) == 1, (
        f"expected exactly ONE mismatch_detector.py required_pattern binding the "
        f"emitted dict key (quoted key + colon), found {cands} — read the rules "
        f"file"
    )
    return cands[0]


def _drift_fixture(seeds):
    """MINIMAL_SEEDS["mismatch_detector.py"] with ONLY the emitted dict key
    renamed (`{"overall_mismatch_score":` -> `{"risk_score":`) — the dataclass
    field and the serialization read both survive untouched.

    Built from the seed at runtime (never retyped) so it cannot silently drift
    away from the seed it is derived from.
    """
    text = seeds["mismatch_detector.py"]
    old = '{"overall_mismatch_score": round('
    new = '{"risk_score": round('
    found = text.count(old)
    assert found == 1, (
        f"drift fixture anchor {old!r} occurs {found}x in the mismatch_detector "
        f"seed, expected 1x — update this probe, never skip it"
    )
    return text.replace(old, new, 1)


# The emission rule's regex text, as a LITERAL, so the P1-2 negative control can
# reason about that rule even when the rules file in its own directory has had
# the rule removed (which is precisely what that fixture creates). It is
# deliberately NOT re-derived from RULES at run time — under
# probe/red_no_emission RULES is the mutated copy, so reading it back would be
# circular. The shipped-rules binding of this literal is asserted directly in
# test_emission_rule_is_exactly_the_literal (green in the overlay run).
EMISSION_PATTERN = '"overall_mismatch_score"\\s*:'


def _rules_without_emission(src_rules, pattern=None):
    """Copy src_rules and drop exactly the emission rule line. Returns the path.

    `pattern` is the emission regex text to remove; when omitted it is read out
    of src_rules. The removal is count-asserted: if the emission rule is ever
    restated or renamed this raises, instead of quietly producing a rules copy
    that still contains the rule (which would make the negative control
    vacuous).
    """
    with open(src_rules, "r", encoding="utf-8", newline="") as f:
        text = f.read()
    pat = pattern if pattern is not None else _emission_rule(src_rules)[1]
    line = f"- 'mismatch_detector.py::{pat}'"
    found = text.count(line)
    assert found <= 1, (
        f"emission rule line {line!r} occurs {found}x in {src_rules}, expected "
        f"at most 1x — the negative control cannot say what it removed"
    )
    if found == 0:
        # The source already lacks the rule (running inside the red_no_emission
        # probe dir). The copy is then trivially emission-rule-less, which is
        # the state the caller asserts; the removal is a no-op, not a silent
        # failure of a test that meant to mutate something.
        assert not _emission_rules(src_rules), (
            f"{src_rules} contains an emission rule that the literal form "
            f"{line!r} does not match — re-sync this helper"
        )
    path = os.path.join(tempfile.mkdtemp(prefix="helix_rules_noemission_"),
                        os.path.basename(src_rules))
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(text.replace(line, "", 1))
    return path


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
        _remove_tree(self.repo)

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
        """Renaming ONLY the emitted dict key must fail the required_pattern.

        The dataclass field and the serialization read stay intact, so this can
        only be the EMISSION rule firing — not a peer anchor on the same file.
        """
        rc, out = self._run_drift_fixture()
        self.assertEqual(rc, 1, f"expected FAIL on canonical-key drift; out=\n{out}")
        self.assertIn("overall_mismatch_score", out)
        # The failure must be attributed to the file this test broke, not a peer.
        self.assertIn("required 未满足: mismatch_detector.py", out)
        self._assert_failure_is_the_emission_rule(out)

    def test_minimal_parser_catches_drift(self):
        """The no-PyYAML minimal parser (the actual CI path — the gate runs
        before torch/transformers/PyYAML are installed) must still parse the
        helix required_patterns and catch canonical-key drift."""
        env, shim = _noyaml_env()
        try:
            rc, out = self._run_drift_fixture(extra_env=env)
        finally:
            _remove_tree(shim)
        self.assertEqual(rc, 1, f"expected FAIL under minimal parser; out=\n{out}")
        self.assertIn("overall_mismatch_score", out)
        self.assertIn("required 未满足: mismatch_detector.py", out)
        self._assert_failure_is_the_emission_rule(out)

    def test_emission_rule_is_exactly_the_literal(self):
        """EMISSION_PATTERN must be the SHIPPED emission rule, verbatim.

        The P1-2 drift tests and the negative control both key off this literal;
        if the rule in .ci/harness_rules.yaml is ever reworded, this fails here
        (loudly, and in the overlay run) instead of the drift assertions quietly
        comparing against a stale string.
        """
        found = _emission_rules(RULES)
        if not found:
            self.skipTest(
                "this rules file carries no emission rule (it IS the mutated "
                "copy under probe/red_no_emission) — the literal-vs-shipped "
                "binding is asserted in the overlay run"
            )
        self.assertEqual(len(found), 1)
        rel, pat = found[0]
        self.assertEqual(rel, "mismatch_detector.py")
        self.assertEqual(
            pat, EMISSION_PATTERN,
            "EMISSION_PATTERN no longer matches the shipped emission rule — "
            "re-sync it with .ci/harness_rules.yaml",
        )

    def test_emission_rule_removed_fixture_is_green(self):
        """P1-2 negative control: with the EMISSION rule deleted, the SAME drift
        fixture goes GREEN — the property that proves
        `test_grep_required_key_drift_fails` / `test_minimal_parser_catches_drift`
        depend on the emission rule and on nothing else.

        Only the emission rule is deleted from a COPY; the fixture itself is
        unchanged (it still keeps the dataclass field and the serialization read
        and changes nothing but the emitted dict key).
        """
        # The emission PATTERN comes from the pristine rules text captured at
        # import time (EMISSION_PATTERN), NOT from RULES: under
        # probe/red_no_emission the rules in this very directory are the
        # emission-rule-less copy, so reading the pattern back out of RULES there
        # would be circular. The mutation is still applied to a fresh copy of
        # RULES, and _rules_without_emission count-asserts the line it drops.
        emission_pat = EMISSION_PATTERN
        no_emit = _rules_without_emission(RULES, pattern=emission_pat)
        try:
            # The copy must be a REAL mutation, not a truncated rules file: the
            # emission rule is gone while the OTHER mismatch_detector.py anchors
            # survive, and the copy lost exactly one rule overall.
            with open(no_emit, "r", encoding="utf-8", newline="") as f:
                copy_text = f.read()
            self.assertNotIn(
                emission_pat, copy_text,
                "the negative-control rules copy still contains the emission rule",
            )
            self.assertEqual(_emission_rules(no_emit), [],
                             "the emission rule is still parsed out of the copy")
            # The copy must equal the source MINUS (at most) the one emission
            # rule: the overlay run drops it (n -> n-1); the red_no_emission
            # probe dir already lacks it, so the drop is a no-op (n -> n).
            src_rules_n = len(_rule_lines(RULES))
            self.assertEqual(
                len(_rule_lines(no_emit)),
                src_rules_n - (1 if _emission_rules(RULES) else 0),
                "the copy must drop exactly the emission rule and nothing else",
            )
            self.assertIn(
                "mismatch_detector.py", [f for f, _ in _rule_lines(no_emit)],
                "the copy must still anchor mismatch_detector.py by its OTHER rules",
            )
            rc, out = self._run_drift_fixture(rules=no_emit)
            self.assertEqual(
                rc, 0,
                f"WITHOUT the emission rule this drift fixture must be green — a "
                f"red here means some OTHER anchor caught the emitted-key rename "
                f"and the two drift tests are not isolated; out=\n{out}",
            )
            self.assertIn("[PASS]", out)
        finally:
            _remove_tree(os.path.dirname(no_emit))

    # --- service_role secret rule, under BOTH parser paths ----------------

    def _seed_canonical_keys(self, overrides=None):
        """Stage EVERY anchored file with minimal valid content, so a later
        `grep` run's only possible failure is the one under test — not an
        unfilled peer anchor (which would be a false red).

        `overrides` replaces a seed by rule file name; a caller that seeds a
        broken file writes it after staging the rest.
        """
        seeds = dict(MINIMAL_SEEDS)
        seeds.update(overrides or {})
        for rel in MINIMAL_SEEDS:          # stage the whole anchored set
            if rel not in (overrides or {}):
                self._write(rel, seeds[rel])
                self._stage(rel)
        if overrides:
            for rel in overrides:
                self._write(rel, overrides[rel])

    def _assert_failure_is_the_emission_rule(self, out):
        """Tie the drift failure to the EMISSION rule specifically.

        P1-2: the old assertions (`exit 1`, the token `overall_mismatch_score`,
        the file name) were satisfied by ANY anchor on mismatch_detector.py, so
        they stayed green after the emission rule was deleted. Require instead:
          * exactly ONE `required 未满足:` line in the whole output,
          * it names mismatch_detector.py,
          * it echoes the EMISSION pattern text (read from the rules FILE, so
            this assertion fails if that rule is removed or reworded).
        """
        rel, pat = "mismatch_detector.py", EMISSION_PATTERN
        fails = _fail_lines(out)
        self.assertEqual(
            len(fails), 1,
            f"expected exactly ONE unmet required_pattern, got {len(fails)}: "
            f"{fails} — the fixture must isolate the emission rule; out=\n{out}",
        )
        self.assertIn(f"required 未满足: {rel}", fails[0])
        self.assertIn(pat, fails[0])

    def _run_drift_fixture(self, rules=None, extra_env=None):
        """Seed every anchored file, break ONLY the emitted dict key in
        mismatch_detector.py, run `grep`, and return (rc, out).

        The overrides keep MINIMAL_SEEDS[mismatch_detector.py] whole (dataclass
        field + serialization read) and change nothing but the emitted key, so
        the ONLY anchor that can fail is the emission anchor. `extra_env` carries
        the no-yaml shim for the minimal-parser (CI path) variant.
        """
        self._seed_canonical_keys(overrides={
            "mismatch_detector.py": _drift_fixture(MINIMAL_SEEDS),
        })
        self._stage("mismatch_detector.py")
        return _run_gate(self.repo, "grep", extra_env=extra_env, rules=rules)

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
        env, shim = _noyaml_env()
        try:
            rc, out = _run_gate(self.repo, "grep", extra_env=env)
        finally:
            _remove_tree(shim)
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
        """A tree with proper .gitignore + ALL anchored files must pass `all`."""
        self._seed_canonical_keys()
        rc, out = _run_gate(self.repo, "all")
        self.assertEqual(rc, 0, f"expected PASS on clean tree; out=\n{out}")


class RealTreeAnchorProbe(unittest.TestCase):
    """Drive the shipped checker over the REAL consumer files, not mini-files.

    A synthetic seed proves a regex compiles and fires on invented text; it does
    NOT prove the anchor matches the code that actually ships. This class copies
    the real files into a fresh temp git repo and:

      a) positive control — unmodified real copies must give rc 0, i.e. every
         anchor in the shipped rules matches the shipped code;
      b) one bait per anchor — each single-line drift/soft-default edit must
         give rc 1 AND name EXACTLY the mutated file as `required 未满足: <f>`,
         and no other file. Because each bait mutates ONE file, `missing` must
         equal {mutated} exactly — a peer miss (a false red) fails the test.

    Both parser paths are exercised: default (PyYAML when importable) and the
    forced minimal parser (the CI path).
    """

    def setUp(self):
        self.repo = tempfile.mkdtemp(prefix="helix_realtree_")
        _git(self.repo, "init", "-q")
        _git(self.repo, "config", "user.email", "probe@test.local")
        _git(self.repo, "config", "user.name", "probe")
        with open(os.path.join(self.repo, ".gitignore"), "w", encoding="utf-8",
                  newline="\n") as f:
            f.write(GITIGNORE)
        for rel in REAL_CONSUMER_FILES:
            src = os.path.join(SCRIPT_DIR, rel)
            self.assertTrue(os.path.isfile(src), f"missing real file: {src}")
            shutil.copyfile(src, os.path.join(self.repo, rel))
        for rel in REAL_CONSUMER_FILES:
            _git(self.repo, "add", "--", rel)

    def tearDown(self):
        _remove_tree(self.repo)

    def _path(self, rel):
        return os.path.join(self.repo, rel)

    def _read(self, rel):
        with open(self._path(rel), "r", encoding="utf-8", newline="") as f:
            return f.read()

    def _write(self, rel, text):
        with open(self._path(rel), "w", encoding="utf-8", newline="") as f:
            f.write(text)

    def _restore_all(self):
        """Re-copy every real consumer file (undo a bait) and re-stage."""
        for rel in REAL_CONSUMER_FILES:
            shutil.copyfile(os.path.join(SCRIPT_DIR, rel), self._path(rel))
            _git(self.repo, "add", "--", rel)

    def _mutate(self, rel, old, count, new, eol_agnostic=False):
        """Replace `old` with `new` in rel, asserting EXACTLY `count` hits first.

        A count mismatch is a hard failure, never a silent skip: a bait that no
        longer matches the real code would otherwise pass vacuously. With
        `eol_agnostic` the bait strings use a bare \\n and are translated to the
        file's own line ending before counting (the tracked tree is CRLF).
        """
        text = self._read(rel)
        if eol_agnostic:
            eol = "\r\n" if "\r\n" in text else "\n"
            old = old.replace("\r\n", "\n").replace("\n", eol)
            new = new.replace("\r\n", "\n").replace("\n", eol)
        found = text.count(old)
        self.assertEqual(
            found, count,
            f"bait text {old!r} occurs {found}x in {rel}, expected {count}x — "
            f"the real read site drifted; update this probe (never skip it)",
        )
        self._write(rel, text.replace(old, new, count))
        _git(self.repo, "add", "--", rel)

    def _both_parsers(self):
        """Yield (label, env) — default parser, then the forced minimal parser."""
        yield "default", None
        env, shim = _noyaml_env()
        try:
            yield "minimal", env
        finally:
            _remove_tree(shim)

    def test_a_positive_control_real_files_pass_both_parsers(self):
        """(a) The unmodified REAL consumer files must satisfy every anchor."""
        for label, env in self._both_parsers():
            rc, out = _run_gate(self.repo, "grep", extra_env=env)
            self.assertEqual(
                rc, 0,
                f"[{label} parser] anchors do NOT match the real tree; out=\n{out}",
            )

    def test_b_every_bait_flips_the_gate_red_on_exactly_its_file(self):
        """(b) Each drift/soft-default bait must fail, naming only its own file."""
        for label, env in self._both_parsers():
            for i, bait in enumerate(BAITS):
                rel, old, count, new, expected = bait[:5]
                ea = bait[5] if len(bait) > 5 else False
                # One subTest per bait: the FIRST failing bait used to abort the
                # loop and hide every bait after it (review P1-1/P2 observation).
                with self.subTest(parser=label, bait=f"b{i} {rel}"):
                    self._restore_all()
                    self._mutate(rel, old, count, new, ea)
                    rc, out = _run_gate(self.repo, "grep", extra_env=env)
                    tag = f"[{label} parser] bait in {rel}"
                    self.assertEqual(rc, 1, f"{tag}: expected FAIL; out=\n{out}")
                    self.assertIn("required 未满足", out, f"{tag}: no FAIL line; out=\n{out}")
                    self.assertIn(
                        f"required 未满足: {expected}", out,
                        f"{tag}: FAIL must name {expected}; out=\n{out}",
                    )
                    missing = _missing_required(out)
                    self.assertEqual(
                        missing, {expected},
                        f"{tag}: gate flagged {sorted(missing)}, expected only "
                        f"[{expected}] — a peer anchor is a false red",
                    )

    def test_b2_soft_default_baits_never_read_a_stale_or_defaulted_score(self):
        """The `.get(..., 0.0)` baits are the exact 9ff61b7 silent-0.0 class; the
        subscript anchors must reject them under both parsers."""
        # `.get(...)` and `getattr(...)` are the same bug shape: the score is
        # read in a way that yields a default instead of failing loud. Both
        # P1-1 baits carry `getattr(`, so they are covered here too.
        soft = [b for b in BAITS if ".get(" in b[3] or "getattr(" in b[3]]
        self.assertGreaterEqual(len(soft), 4, "expected >=4 soft-default baits")
        for label, env in self._both_parsers():
            for i, bait in enumerate(soft):
                rel, old, count, new, expected = bait[:5]
                ea = bait[5] if len(bait) > 5 else False
                with self.subTest(parser=label, bait=f"soft{i} {rel}"):
                    self._restore_all()
                    self._mutate(rel, old, count, new, ea)
                    rc, out = _run_gate(self.repo, "grep", extra_env=env)
                    self.assertEqual(
                        rc, 1,
                        f"[{label} parser] soft-default bait in {rel} stayed green "
                        f"(silent-0.0 class); out=\n{out}",
                    )
                    self.assertEqual(_missing_required(out), {expected})

    def test_b3_commented_correct_read_does_not_satisfy_the_anchor(self):
        """A bait whose correct text survives ONLY inside a trailing comment must
        still fail: `(?m)^[^\x23\n]*` requires the match on a comment-free line."""
        bait = [b for b in BAITS if "# report.overall_mismatch_score" in b[3]][0]
        rel, old, count, new, expected = bait[:5]
        ea = bait[5] if len(bait) > 5 else False
        for label, env in self._both_parsers():
            with self.subTest(parser=label, bait=f"comment {rel}"):
                self._restore_all()
                self._mutate(rel, old, count, new, ea)
                rc, out = _run_gate(self.repo, "grep", extra_env=env)
                self.assertEqual(rc, 1, f"[{label} parser] commented read stayed green; out=\n{out}")
                self.assertEqual(_missing_required(out), {expected})


class FailClosedHarnessProbe(unittest.TestCase):
    """F1/F2 regression probes; every fixture lives under one temp root that
    tearDownClass removes (same convention as the other probe classes)."""

    MARKER = "HELIX_" + "HARNESS_SCAN_MARKER"
    _modules = {}

    @classmethod
    def tearDownClass(cls):
        # shutil.rmtree is a Python call on our own mkdtemp() root, not a shell delete.
        _remove_tree(cls.probe)

    @classmethod
    def setUpClass(cls):
        cls.probe = tempfile.mkdtemp(prefix="helix_failclosed_root_")
        cls.repo = tempfile.mkdtemp(prefix="helix_failclosed_", dir=cls.probe)
        cls.control_dir = os.path.join(cls.repo, ".ci")
        cls.decoy_dir = os.path.join(cls.repo, "sub")
        os.makedirs(cls.control_dir)
        os.makedirs(cls.decoy_dir)
        cls.checker = os.path.join(cls.control_dir, "harness_check.py")
        cls.rules = os.path.join(cls.control_dir, "harness_rules.yaml")
        shutil.copyfile(HARNESS, cls.checker)
        # The actual checker file carries the forbidden marker, proving that
        # only the checker script in use receives the exact-path exemption.
        with open(cls.checker, "a", encoding="utf-8", newline="\n") as f:
            f.write("# " + cls.MARKER + "\n")
        with open(cls.rules, "w", encoding="utf-8", newline="\n") as f:
            f.write("forbidden_patterns:\n  - " + cls.MARKER + "\n")
        payload = cls.MARKER + "\n"
        fixtures = {
            "README.md": payload,
            "sub/README.md": payload,
            "sub/harness_rules.yaml": payload,
            "sub/harness_check.py": payload,
        }
        for rel, content in fixtures.items():
            with open(os.path.join(cls.repo, rel), "w", encoding="utf-8",
                      newline="\n") as f:
                f.write(content)
        _git(cls.repo, "init", "-q")
        _git(cls.repo, "add", "--", ".ci/harness_check.py",
             ".ci/harness_rules.yaml", "README.md", "sub/README.md",
             "sub/harness_rules.yaml", "sub/harness_check.py")

        # A clean control repo isolates the legitimate in-use files so the
        # positive exemption controls pass even while the decoys above are red.
        cls.control_repo = tempfile.mkdtemp(prefix="helix_exemptions_", dir=cls.probe)
        control_ci = os.path.join(cls.control_repo, ".ci")
        os.makedirs(control_ci)
        control_checker = os.path.join(control_ci, "harness_check.py")
        control_rules = os.path.join(control_ci, "harness_rules.yaml")
        shutil.copyfile(HARNESS, control_checker)
        with open(control_checker, "a", encoding="utf-8", newline="\n") as f:
            f.write("# " + cls.MARKER + "\n")
        with open(control_rules, "w", encoding="utf-8", newline="\n") as f:
            f.write("forbidden_patterns:\n  - " + cls.MARKER + "\n")
        _git(cls.control_repo, "init", "-q")
        _git(cls.control_repo, "add", "--", ".ci/harness_check.py",
             ".ci/harness_rules.yaml")

        # A separate clean repo exercises grep's built-in secret fallbacks
        # without the harmless forbidden-pattern markers from the decoy repo.
        cls.secret_repo = tempfile.mkdtemp(prefix="helix_secret_grep_", dir=cls.probe)
        secret_ci = os.path.join(cls.secret_repo, ".ci")
        os.makedirs(secret_ci)
        cls.secret_checker = os.path.join(secret_ci, "harness_check.py")
        cls.secret_rules = os.path.join(secret_ci, "harness_rules.yaml")
        shutil.copyfile(HARNESS, cls.secret_checker)
        with open(cls.secret_rules, "w", encoding="utf-8", newline="\n") as f:
            f.write("forbidden_patterns:\n  - " + cls.MARKER + "\n")
        os.makedirs(os.path.join(cls.secret_repo, "sub"))
        for rel in ["README.md", "sub/README.md"]:
            with open(os.path.join(cls.secret_repo, rel), "w", encoding="utf-8",
                      newline="\n") as f:
                f.write("plain README text\n")
        _git(cls.secret_repo, "init", "-q")
        _git(cls.secret_repo, "add", "--", ".ci/harness_check.py",
             ".ci/harness_rules.yaml", "README.md", "sub/README.md")

    @classmethod
    def _module(cls, script=None):
        import importlib.util

        path = os.path.abspath(script or HARNESS)
        if path not in cls._modules:
            spec = importlib.util.spec_from_file_location(
                "harness_check_failclosed_" + str(len(cls._modules)), path,
            )
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            cls._modules[path] = module
        return cls._modules[path]

    @classmethod
    def _run(cls, repo, cmd, script=None, rules=None, cwd=None, extra_env=None):
        from contextlib import nullcontext, redirect_stdout
        from io import StringIO
        from unittest.mock import patch

        _flush_test_adds(repo)
        script = os.path.abspath(script or HARNESS)
        module = cls._module(script)
        args = [script, cmd]
        if rules is not None:
            args.extend(["--rules", rules])
        args.extend(["--repo", repo])
        old_cwd, old_argv = os.getcwd(), sys.argv[:]
        output = StringIO()
        env_patch = patch.dict(os.environ, extra_env, clear=True) if extra_env is not None else nullcontext()
        try:
            os.chdir(cwd or SCRIPT_DIR)
            sys.argv = args
            with env_patch, redirect_stdout(output):
                rc = module.main()
        finally:
            sys.argv = old_argv
            os.chdir(old_cwd)
        return rc, output.getvalue()

    @unittest.skipUnless(os.name == "nt", "requires Windows drive-letter paths")
    def test_checker_outside_repo_drive_is_not_an_exemption(self):
        module = self._module(HARNESS)
        helper = getattr(module, "_is_exempt_file", None)
        self.assertTrue(callable(helper), "checker must use normalized path exemptions")
        if not callable(helper):
            return
        script_drive = os.path.splitdrive(os.path.abspath(HARNESS))[0].upper()
        repo_drive = next(letter for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                          if letter + ":" != script_drive)
        repo = repo_drive + ":\\helix_cross_drive_probe"
        rules = os.path.join(repo, ".ci", "harness_rules.yaml")
        try:
            exempt = module._is_exempt_file(repo, "README.md", rules)
        except ValueError as exc:
            self.fail(f"checker outside the repo drive must not be exempt or raise: {exc}")
        self.assertFalse(exempt)

    def _assert_decoys_named(self, stage, out):
        expected = [
            "README.md", "sub/README.md", "sub/harness_rules.yaml",
            "sub/harness_check.py",
        ]
        for rel in expected:
            with self.subTest(stage=stage, rel=rel):
                self.assertIn(f"[FAIL:{stage}] {rel}:", out)
                self.assertIn(self.MARKER, out)

    def test_a_staged_scans_readme_and_same_basename_decoys(self):
        rc, out = self._run(
            self.repo, "staged", script=self.checker, rules=self.rules,
            cwd=self.repo,
        )
        self._assert_decoys_named("staged", out)
        for rel in [".ci/harness_rules.yaml", ".ci/harness_check.py"]:
            with self.subTest(exempt=rel):
                self.assertNotIn(f"[FAIL:staged] {rel}:", out)
        self.assertEqual(rc, 1, f"expected staged FAIL; out=\n{out}")

    def test_a_grep_scans_readme_and_same_basename_decoys(self):
        rc, out = self._run(
            self.repo, "grep", script=self.checker, rules=self.rules,
            cwd=self.repo,
        )
        self._assert_decoys_named("grep", out)
        for rel in [".ci/harness_rules.yaml", ".ci/harness_check.py"]:
            with self.subTest(exempt=rel):
                self.assertNotIn(f"[FAIL:grep] {rel}:", out)
        self.assertEqual(rc, 1, f"expected grep FAIL; out=\n{out}")

    def test_a_grep_scans_builtin_secret_fallbacks_in_readmes(self):
        token = "s" + "k" + "-" + "A" * 24
        for rel in ["README.md", "sub/README.md"]:
            with open(os.path.join(self.secret_repo, rel), "a", encoding="utf-8",
                      newline="") as f:
                f.write(token + "\n")
        rc, out = self._run(
            self.secret_repo, "grep", script=self.secret_checker,
            rules=self.secret_rules, cwd=self.secret_repo,
        )
        self.assertEqual(rc, 1, f"expected grep FAIL on runtime token; out=\n{out}")
        self.assertIn("API key", out)
        self.assertNotIn(token, out)
        for rel in ["README.md", "sub/README.md"]:
            with self.subTest(rel=rel):
                self.assertIn(f"[FAIL:grep] {rel}:", out)

    def test_b_rules_file_exemption_uses_its_exact_path(self):
        rc, out = self._run(
            self.control_repo, "grep",
            script=os.path.join(self.control_repo, ".ci", "harness_check.py"),
            rules=os.path.join(self.control_repo, ".ci", "harness_rules.yaml"),
            cwd=self.control_repo,
        )
        self.assertEqual(rc, 0, f"the exact in-use files must be exempt; out=\n{out}")
        self.assertIn("[PASS]", out)
        self.assertNotIn("[FAIL:grep] .ci/harness_rules.yaml:", out)
        self.assertNotIn("[FAIL:grep] .ci/harness_check.py:", out)

    def test_b_equivalent_rules_spelling_keeps_the_same_exemption(self):
        rc, out = self._run(
            self.control_repo, "grep",
            script=os.path.join(self.control_repo, ".ci", "harness_check.py"),
            rules="./.ci/../.ci/harness_rules.yaml", cwd=self.control_repo,
        )
        self.assertEqual(rc, 0, f"equivalent path spelling must retain exemption; out=\n{out}")
        self.assertIn("[PASS]", out)
        self.assertNotIn("[FAIL:grep] .ci/harness_rules.yaml:", out)
        self.assertNotIn("[FAIL:grep] .ci/harness_check.py:", out)

    def test_c_git_failures_fail_closed_for_all_gates_and_missing_git(self):
        repo = tempfile.mkdtemp(prefix="helix_nongit_", dir=self.probe)
        rc, out = self._run(repo, "all", rules=RULES)
        self.assertEqual(rc, 1, f"all gates on non-git repo must fail; out=\n{out}")
        for stage in ["staged", "ignore", "grep"]:
            with self.subTest(stage=stage):
                line = next((item for item in out.splitlines()
                             if item.startswith(f"[FAIL:{stage}]")), "")
                self.assertIn("git error", line.lower())

        empty_path = tempfile.mkdtemp(prefix="helix_no_git_path_", dir=self.probe)
        env = os.environ.copy()
        env["PATH"] = empty_path
        rc, out = self._run(
            self.repo, "staged", script=self.checker, rules=self.rules,
            cwd=self.repo, extra_env=env,
        )
        self.assertEqual(rc, 1, f"missing git binary must fail; out=\n{out}")
        self.assertIn("git", out.lower())

    def test_c_grep_reports_non_missing_tracked_read_errors(self):
        import builtins

        checker = self._module(self.secret_checker)
        readme = os.path.abspath(os.path.join(self.secret_repo, "README.md"))
        previous_open = checker.__dict__.get("open")

        def denied_open(path, *args, **kwargs):
            if os.path.abspath(os.fspath(path)) == readme:
                raise PermissionError("probe read denied")
            return builtins.open(path, *args, **kwargs)

        checker.open = denied_open
        try:
            # Keep the two-argument call compatible with the original gate;
            # the checker receives its exact in-use rules path from main().
            fails = checker.cmd_grep(
                self.secret_repo, {"forbidden_patterns": [self.MARKER]},
            )
        finally:
            if previous_open is None:
                del checker.open
            else:
                checker.open = previous_open
        self.assertTrue(any("README.md" in item and "probe read denied" in item
                            for item in fails), f"read error was skipped; fails={fails}")

    def test_d_check_ignore_uses_rc_not_stderr(self):
        from types import SimpleNamespace

        checker = self._module(HARNESS)
        original_run = checker.subprocess.run
        statuses = iter([1, 0, 128])
        calls = []

        def fake_run(argv, **kwargs):
            calls.append(list(argv))
            return SimpleNamespace(
                returncode=next(statuses), stdout="",
                stderr="warning: cannot read global excludes file",
            )

        rules = {"is_public_repo": True, "sensitive_paths": ["private.txt"]}
        checker.subprocess.run = fake_run
        try:
            with self.subTest(rc=1):
                fails = checker.cmd_ignore(self.repo, rules)
                self.assertTrue(any("private.txt" in item for item in fails))
            with self.subTest(rc=0):
                self.assertEqual(checker.cmd_ignore(self.repo, rules), [])
            with self.subTest(rc=128):
                self.assertTrue(hasattr(checker, "GitError"), "GitError must be defined")
                if hasattr(checker, "GitError"):
                    with self.assertRaises(checker.GitError):
                        checker.cmd_ignore(self.repo, rules)
        finally:
            checker.subprocess.run = original_run
        self.assertTrue(calls)
        for argv in calls:
            self.assertIn("check-ignore", argv)
            self.assertIn("-q", argv)
            self.assertIn("--", argv)

    def test_e_explicit_missing_and_empty_rules_fail(self):
        repo = tempfile.mkdtemp(prefix="helix_rules_repo_", dir=self.probe)
        missing = os.path.join(self.probe, "explicit_missing_rules.yaml")
        empty = os.path.join(self.probe, "explicit_empty_rules.yaml")
        with open(empty, "w", encoding="utf-8", newline="\n") as f:
            f.write("")
        for rules in [missing, empty]:
            with self.subTest(rules=rules):
                rc, out = self._run(repo, "grep", rules=rules)
                self.assertEqual(rc, 1, f"explicit invalid rules must fail; out=\n{out}")
                self.assertIn("[FAIL:rules]", out)
                self.assertIn("rules", out.lower())

    def test_e_missing_default_rules_keeps_the_portable_skip(self):
        repo = tempfile.mkdtemp(prefix="helix_no_default_rules_", dir=self.probe)
        rc, out = self._run(repo, "grep")
        self.assertEqual(rc, 0, f"missing implicit default should skip; out=\n{out}")
        self.assertIn("[harness]", out)
        self.assertIn("exit 0", out)

    def test_f_real_tree_passes_all(self):
        repo = tempfile.mkdtemp(prefix="helix_real_tree_", dir=self.probe)
        # "Real tree" = the files git tracks here, never the raw working directory
        # (which holds .git, caches, build output, local-only docs ...).
        listing = subprocess.run(
            ["git", "-C", SCRIPT_DIR, "ls-files"], capture_output=True, text=True,
            encoding="utf-8", errors="replace",
        )
        if listing.returncode != 0 or not listing.stdout.strip():
            self.skipTest("not a git checkout: tracked-file listing unavailable")
        files = sorted(rel for rel in listing.stdout.splitlines() if rel.strip())
        for rel in files:
            src = os.path.join(SCRIPT_DIR, *rel.split("/"))
            if not os.path.isfile(src):
                continue  # tracked but deleted in this working tree
            dst = os.path.join(repo, *rel.split("/"))
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copyfile(src, dst)
        files = [rel for rel in files if os.path.isfile(os.path.join(repo, *rel.split("/")))]
        _git(repo, "init", "-q")
        _git(repo, "config", "user.email", "probe@test.local")
        _git(repo, "config", "user.name", "probe")
        _git(repo, "add", "--", *files)
        _git(repo, "commit", "-qm", "clean real-tree baseline")
        script = os.path.join(repo, ".ci", "harness_check.py")
        rc, out = self._run(
            repo, "all", script=script, rules=".ci/harness_rules.yaml", cwd=repo,
        )
        self.assertEqual(rc, 0, f"the real tree must pass all gates; out=\n{out}")
        self.assertIn("[PASS]", out)


    def _new_path_repo(self):
        repo = tempfile.mkdtemp(prefix="helix_path_names_", dir=self.probe)
        ci = os.path.join(repo, ".ci")
        os.makedirs(ci)
        checker = os.path.join(ci, "harness_check.py")
        rules = os.path.join(ci, "harness_rules.yaml")
        shutil.copyfile(HARNESS, checker)
        with open(rules, "w", encoding="utf-8", newline="\n") as f:
            f.write("forbidden_patterns:\n  - " + self.MARKER + "\n")
        _git(repo, "init", "-q")
        _git(repo, "config", "user.email", "probe@test.local")
        _git(repo, "config", "user.name", "probe")
        _git(repo, "add", "--", ".ci/harness_check.py", ".ci/harness_rules.yaml")
        _git(repo, "commit", "-qm", "path scan baseline")
        return repo, checker, rules

    def _write_path_file(self, repo, name, content):
        path = os.path.join(repo, name)
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(content)

    def _commit_path_file(self, repo, name, content, message):
        self._write_path_file(repo, name, content)
        _git(repo, "add", "--", name)
        _git(repo, "commit", "-qm", message)

    def _stage_marker_path(self, name):
        repo, checker, rules = self._new_path_repo()
        self._write_path_file(repo, name, self.MARKER + "\n")
        _git(repo, "add", "--", name)
        return self._run(repo, "staged", script=checker, rules=rules, cwd=repo)

    def test_staged_non_ascii_path_reports_the_forbidden_content(self):
        name = "\u79d8\u5bc6.txt"
        rc, out = self._stage_marker_path(name)
        self.assertEqual(rc, 1, f"expected staged content failure; out=\n{out}")
        self.assertIn(f"[FAIL:staged] {name}:", out)
        self.assertIn(self.MARKER, out)

    def test_staged_space_path_reports_the_forbidden_content(self):
        name = "file with spaces.txt"
        rc, out = self._stage_marker_path(name)
        self.assertEqual(rc, 1, f"expected staged content failure; out=\n{out}")
        self.assertIn(f"[FAIL:staged] {name}:", out)
        self.assertIn(self.MARKER, out)

    def test_staged_bracket_path_uses_a_literal_pathspec(self):
        name = "a[1].txt"
        repo, checker, rules = self._new_path_repo()
        try:
            self._write_path_file(repo, name, self.MARKER + "\n")
        except OSError as exc:
            self.skipTest(f"platform cannot create bracket path: {exc}")
        _git(repo, "add", "--", name)
        module = self._module(checker)
        original_run = module.subprocess.run
        calls = []

        def record_run(argv, **kwargs):
            calls.append(list(argv))
            return original_run(argv, **kwargs)

        module.subprocess.run = record_run
        try:
            rc, out = self._run(repo, "staged", script=checker, rules=rules, cwd=repo)
        finally:
            module.subprocess.run = original_run
        self.assertEqual(rc, 1, f"expected staged content failure; out=\n{out}")
        self.assertIn(f"[FAIL:staged] {name}:", out)
        self.assertIn(self.MARKER, out)
        diff_calls = [argv for argv in calls if "diff" in argv and "-U0" in argv]
        self.assertTrue(
            any("--literal-pathspecs" in argv and argv.index("--literal-pathspecs") < argv.index("diff")
                for argv in diff_calls),
            f"per-file diff must use literal pathspecs; calls={diff_calls}",
        )

    def test_staged_forbidden_name_rule_matches_non_ascii_path(self):
        repo, checker, rules = self._new_path_repo()
        name = "\u79d8\u5bc6.txt"
        with open(rules, "w", encoding="utf-8", newline="\n") as f:
            f.write(
                "forbidden_patterns:\n  - " + self.MARKER
                + "\nforbidden_staged_names:\n  - " + name + "\n"
            )
        self._write_path_file(repo, name, "plain text\n")
        _git(repo, "add", "--", name)
        rc, out = self._run(repo, "staged", script=checker, rules=rules, cwd=repo)
        self.assertEqual(rc, 1, f"expected forbidden staged name; out=\n{out}")
        self.assertIn("\u7981\u7528\u6587\u4ef6\u88ab\u6682\u5b58", out)
        self.assertIn(name, out)

    def test_grep_non_ascii_path_reports_forbidden_content(self):
        repo, checker, rules = self._new_path_repo()
        name = "\u9690\u85cf\u5185\u5bb9.txt"
        self._commit_path_file(repo, name, self.MARKER + "\n", "add marked path")
        rc, out = self._run(repo, "grep", script=checker, rules=rules, cwd=repo)
        self.assertEqual(rc, 1, f"expected tracked content failure; out=\n{out}")
        self.assertIn(f"[FAIL:grep] {name}:", out)
        self.assertIn(self.MARKER, out)

    def test_grep_harmless_non_ascii_path_passes(self):
        repo, checker, rules = self._new_path_repo()
        name = "\u666e\u901a\u6587\u4ef6.txt"
        self._commit_path_file(repo, name, "plain text\n", "add harmless path")
        rc, out = self._run(repo, "grep", script=checker, rules=rules, cwd=repo)
        self.assertEqual(rc, 0, f"harmless tracked path must pass; out=\n{out}")
        self.assertIn("[PASS]", out)
        self.assertNotIn(f"[FAIL:grep] {name}:", out)

    def test_grep_ascii_path_control_passes(self):
        repo, checker, rules = self._new_path_repo()
        self._commit_path_file(repo, "plain.txt", "plain text\n", "add ASCII path")
        rc, out = self._run(repo, "grep", script=checker, rules=rules, cwd=repo)
        self.assertEqual(rc, 0, f"harmless ASCII path must pass; out=\n{out}")
        self.assertIn("[PASS]", out)

    @unittest.skipUnless(os.name == "posix", "the platform cannot create raw-byte filenames")
    def test_invalid_utf8_path_fails_closed_in_staged_and_grep(self):
        repo, checker, rules = self._new_path_repo()
        raw_name = b"bad_\xff.txt"
        path = os.fsencode(repo) + os.sep.encode() + raw_name
        fd = os.open(path, os.O_CREAT | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(b"plain text\n")
        name = os.fsdecode(raw_name)
        _git(repo, "add", "--", name)
        byte_token = raw_name.hex()
        rc, out = self._run(repo, "staged", script=checker, rules=rules, cwd=repo)
        self.assertEqual(rc, 1, f"invalid staged path must fail closed; out=\n{out}")
        self.assertIn("invalid UTF-8", out)
        self.assertIn(byte_token, out)
        _git(repo, "commit", "-qm", "add byte path")
        rc, out = self._run(repo, "grep", script=checker, rules=rules, cwd=repo)
        self.assertEqual(rc, 1, f"invalid tracked path must fail closed; out=\n{out}")
        self.assertIn("invalid UTF-8", out)
        self.assertIn(byte_token, out)

    def test_default_rules_directory_fails_clearly(self):
        repo, checker, _ = self._new_path_repo()
        os.mkdir(os.path.join(repo, "harness_rules.yaml"))
        rc, out = self._run(repo, "grep", script=checker, cwd=repo)
        self.assertEqual(rc, 1, f"a default rules directory must fail; out=\n{out}")
        self.assertIn("[FAIL:rules]", out)
        self.assertIn("regular file", out)

    def test_cleanup_removes_a_committed_git_tree(self):
        repo = tempfile.mkdtemp(prefix="helix_cleanup_repo_")
        self.addCleanup(_remove_tree, repo)
        _git(repo, "init", "-q")
        _git(repo, "config", "user.email", "probe@test.local")
        _git(repo, "config", "user.name", "probe")
        with open(os.path.join(repo, "committed.txt"), "w", encoding="utf-8",
                  newline="\n") as f:
            f.write("committed data\n")
        _git(repo, "add", "--", "committed.txt")
        _git(repo, "commit", "-qm", "create cleanup fixture")
        _remove_tree(repo)
        self.assertFalse(os.path.exists(repo), "the committed repository tree must be removed")


class CleanupHelperRaceTests(unittest.TestCase):
    """The cleanup helper must tolerate a path that another process removed first.

    shutil.rmtree reports every OSError to its handler, including the
    FileNotFoundError for a file that vanished between listing and unlinking.
    Git's background maintenance does exactly that to .git/objects/maintenance.lock,
    so a path that is already gone counts as removed.
    """

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="helix_cleanup_race_")
        self.addCleanup(shutil.rmtree, self.root, True)

    def _missing(self):
        return os.path.join(self.root, "already_removed.lock")

    def _make_file(self, *parts):
        path = os.path.join(self.root, *parts)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write("x")
        return path

    def test_handler_treats_a_vanished_path_as_removed(self):
        def must_not_retry(path):
            raise AssertionError("a vanished path must not be retried")

        gone = FileNotFoundError(2, "No such file or directory", self._missing())
        for label, reported in (
            ("exc_info tuple", (FileNotFoundError, gone, None)),
            ("exception instance", gone),
        ):
            with self.subTest(label):
                self.assertIsNone(
                    _retry_readonly_removal(must_not_retry, self._missing(), reported)
                )

    def test_handler_treats_a_path_removed_after_chmod_as_removed(self):
        target = self._make_file("vanishes_during_retry.lock")

        def removed_by_someone_else(path):
            raise FileNotFoundError(2, "No such file or directory", path)

        denied = PermissionError(13, "Permission denied", target)
        self.assertIsNone(_retry_readonly_removal(removed_by_someone_else, target, denied))

    def test_handler_still_raises_errors_other_than_a_vanished_path(self):
        target = self._make_file("stays_locked.lock")

        def still_denied(path):
            raise PermissionError(13, "Permission denied", path)

        denied = PermissionError(13, "Permission denied", target)
        with self.assertRaises(PermissionError):
            _retry_readonly_removal(still_denied, target, denied)

    def test_remove_tree_survives_a_file_deleted_by_another_process(self):
        # Reproduces the failure on interpreters whose rmtree reports a vanished
        # file to the handler; where rmtree ignores it by itself this passes
        # without exercising the handler (the tests above cover the handler).
        self._make_file("tree", "objects", "maintenance.lock")
        self._make_file("tree", "objects", "pack.idx")
        tree = os.path.join(self.root, "tree")

        real_unlink = os.unlink

        def unlink_after_another_process_won(path, *args, **kwargs):
            real_unlink(path, *args, **kwargs)
            if os.path.basename(os.fspath(path)) == "maintenance.lock":
                raise FileNotFoundError(2, "No such file or directory", os.fspath(path))

        with unittest.mock.patch("os.unlink", unlink_after_another_process_won):
            _remove_tree(tree)
        self.assertFalse(os.path.exists(tree), "the tree must be removed despite the race")

    def test_fixture_repos_disable_background_maintenance(self):
        repo = tempfile.mkdtemp(prefix="helix_cleanup_cfg_")
        self.addCleanup(_remove_tree, repo)
        _git(repo, "init", "-q")
        for key, expected in (("maintenance.auto", "false"), ("gc.auto", "0")):
            got = subprocess.run(
                ["git", "-C", repo, "config", "--local", "--get", key],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
            ).stdout.strip()
            self.assertEqual(got, expected, f"{key} must be {expected} in fixture repos")


if __name__ == "__main__":
    if not (os.path.isfile(HARNESS) and os.path.isfile(RULES)):
        print(f"[ERROR] harness not found: {HARNESS} / {RULES}", file=sys.stderr)
        sys.exit(2)
    unittest.main(verbosity=2)
