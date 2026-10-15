# SESSION_STATE — 04-helix

WORKLINE_STATUS: PAUSED | 无在跑工作；模块化第 2 批按 D-0126 暂停（01/22 上线优先）；官网修正稿已部署（OT-20261014-037 已完成）；main=a918559 CI 全绿 | D-0126, OT-20261014-037

> Public status stub for the work-line progress card (reads the default branch). Kept minimal on purpose: this repo is public, so no internal planning, paths or tickets beyond the IDs on the line above. Overwrite at the end of each work session; not versioned. Last updated: 2026-10-16 01:52 JST.

## Verified state (2026-10-16)

- `main` = `a918559`; push CI on `main` is green (Smoke + FP Regression, Rust Guard).
- Current metrics: see **Verification Results** in `README.md` (not repeated here, to avoid stale copies).
- Nothing is in progress. No open pull requests.

## Done since 2026-10-13

- #6, #11 — Makefile help text and README wording aligned with the proxy runner's real semantics. MinimalProxy (0.1985) is described as a benign idiom the detector correctly flags; CREATE2Factory (0.1007) remains a baselined threshold-edge false positive.
- #7 — harness `required_patterns` anchor every hop of the score data path (dataclass field, serialization read, replay/mainnet/smoke/CLI readers); `test_harness_gate.py` proves the anchors bite under both YAML parser paths.
- #8 — `helix scan` exits 2 (not a silent 0) when the detector output contract drifts.
- #10 — 23 compiled reentrancy counter-examples pinned as regression tests, so an exemption that hides them turns CI red.
- #9 (exemption for calls to a contract created in the same function) was reviewed and closed: a freshly created contract can still call back, so there is no safe minimal fix without changing the scoring approach.
- Homepage metrics were aligned with the README and deployed on 2026-10-14.

## Remaining

- Homepage proxy card still reads "2 known FPs tracked"; update together with the next homepage change (deploy needs Owner confirmation).
- A real fix for the two baselined proxy findings needs per-function state-write (CEI) analysis, i.e. a scoring change — Owner decision required before any work starts.
- Phase 2 entry gates: see `README.md` (design partner gate still open).
- GitHub reports 3 low-severity Dependabot alerts on the default branch (not triaged).
