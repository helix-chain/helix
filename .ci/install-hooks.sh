#!/bin/sh
# Install HELIX git hooks from their tracked sources (.ci/) into .git/hooks/.
#
# .git/hooks/ is not tracked by git, so a fresh clone has NO hooks until this
# runs. Idempotent — safe to re-run. Invoke from anywhere inside the repo:
#     sh .ci/install-hooks.sh
# (Also exposed as `make install-hooks`.)
set -e

root="$(git rev-parse --show-toplevel)"
cd "$root"
src="$root/.ci/pre-commit"
# Resolve the real hooks dir (honors core.hooksPath, worktrees, submodules)
# instead of hardcoding .git/hooks; --git-path is relative to CWD, hence cd above.
hooks_dir="$(git rev-parse --git-path hooks)"
dst="$hooks_dir/pre-commit"

if [ ! -f "$src" ]; then
  echo "[install-hooks] tracked hook source not found: $src" >&2
  exit 1
fi

mkdir -p "$hooks_dir"
if [ -f "$dst" ]; then
  echo "[install-hooks] overwriting existing hook at $dst"
fi
cp "$src" "$dst"
# chmod may be a no-op on Windows filesystems; ignore failure there.
chmod +x "$dst" 2>/dev/null || true
echo "[install-hooks] installed pre-commit hook -> $dst"
echo "[install-hooks] verify with:  git rev-parse --show-toplevel && sh .ci/pre-commit"
