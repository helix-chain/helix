#!/usr/bin/env python3
"""harness_check.py — BV Harness Gate 确定性验证检查器 (read-only / stdlib-only)

Module ③「确定性验证拦截网」的可移植核心（_LESSONS §二十二 / Harness Engineering 硬约束）。
本地 git pre-commit 与远端 CI 都调它。
- read-only：只读 git / 文件，绝不写盘、不 commit、不联网。
- stdlib-only：无第三方依赖（本机 pre-commit/gitleaks 未装也能跑）。
- 规则来自 <repo>/harness_rules.yaml（见 project_rules.example.yaml）；无规则文件 = 跳过(exit 0)。

子命令（有违规则 exit 1，用于 hook/CI 拦截）：
  staged   暂存区：禁用文件名 + 暂存内容 forbidden_patterns + 轻量 secret 兜底正则
  ignore   公开仓泄密闸：sensitive_paths 是否被 .gitignore 命中（未命中=会被 git add . 暂存）
  grep     全跟踪文件的 forbidden / required pattern
  all      聚合上面全部，任一失败 exit 1

⚠️ 本地 hook 可被 `git commit --no-verify` 绕过 → 必须同时配 CI required checks + GitHub push protection。
⚠️ 轻量 secret 正则是【兜底】、不是 gitleaks 替代（会误报/漏报）；真扫在 CI 用 gitleaks-action。
"""
import argparse, fnmatch, os, re, subprocess, sys

MAX_BYTES = 2_000_000


class GitError(RuntimeError):
    """A Git command failed, could not start, or timed out."""

# 轻量 secret 正则（FALLBACK ONLY — 非 gitleaks 替代）
SECRET_RX = [
    (re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----'), 'private key block'),
    (re.compile(r'\bsk-[A-Za-z0-9]{20,}\b'), 'sk- API key'),
    (re.compile(r'\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b'), 'GitHub token'),
    (re.compile(r'\bAKIA[0-9A-Z]{16}\b'), 'AWS access key id'),
    (re.compile(r'(?i)service_role["\']?\s*[:=]\s*["\']?eyJ'), 'supabase service_role JWT'),
    (re.compile(r'(?i)(secret|password|passwd|api[_-]?key)\s*[:=]\s*["\'][^"\']{8,}["\']'),
     'generic secret assignment'),
]


def _load_rules(path):
    """装了 PyYAML 用它；否则用内置最小解析器（扁平 schema：key -> 标量 / 字符串列表）。"""
    if not (path and os.path.isfile(path)):
        return {}
    try:
        import yaml
        with open(path, encoding='utf-8') as f:
            return yaml.safe_load(f) or {}
    except ImportError:
        pass
    rules, cur = {}, None
    with open(path, encoding='utf-8') as f:
        for raw in f:
            line = raw.split('#', 1)[0].rstrip()
            if not line.strip():
                continue
            m_item = re.match(r'^\s+-\s+(.*)$', line)
            m_key = re.match(r'^(\S[^:]*):\s*(.*)$', line)
            if m_item and cur:
                if isinstance(rules.get(cur), list):
                    rules[cur].append(m_item.group(1).strip().strip('"\''))
            elif m_key:
                cur = m_key.group(1).strip()
                v = m_key.group(2).strip().strip('"\'')
                if v == '':
                    rules[cur] = []
                elif v.lower() in ('true', 'false'):
                    rules[cur] = (v.lower() == 'true')
                else:
                    rules[cur] = v
    return rules


def _git(repo, *a, allow_returncodes=()):
    try:
        r = subprocess.run(['git', '-C', repo, *a], capture_output=True, text=True,
                           encoding='utf-8', errors='replace', timeout=60)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise GitError(f'{e}') from e
    allowed = {0, *allow_returncodes}
    if r.returncode not in allowed:
        detail = (r.stderr or '').strip() or (r.stdout or '').strip()
        if not detail:
            detail = f'exit code {r.returncode}'
        raise GitError(detail)
    return r


def _git_bytes(repo, *a, allow_returncodes=(), literal_pathspecs=False):
    argv = ['git']
    if literal_pathspecs:
        argv.append('--literal-pathspecs')
    argv.extend(['-C', repo, *a])
    try:
        r = subprocess.run(argv, capture_output=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise GitError(f'{e}') from e
    allowed = {0, *allow_returncodes}
    if r.returncode not in allowed:
        detail = (r.stderr or b'').decode('utf-8', errors='replace').strip()
        if not detail:
            detail = (r.stdout or b'').decode('utf-8', errors='replace').strip()
        if not detail:
            detail = f'exit code {r.returncode}'
        raise GitError(detail)
    return r


def _nul_paths(output, fails):
    raw_paths = output.split(b'\0')
    if raw_paths and raw_paths[-1] == b'':
        raw_paths.pop()
    paths = []
    for raw in raw_paths:
        if not raw:
            continue
        try:
            paths.append(raw.decode('utf-8'))
        except UnicodeDecodeError:
            fails.append(f'invalid UTF-8 path (hex): {raw.hex()}')
    return paths


def _is_exempt_file(repo, file_path, rules_path):
    """Match only the in-repo rules file and this checker by normalized path."""
    repo_abs = os.path.abspath(os.path.normpath(repo))

    def normalized_rel(path, relative_to_repo=False):
        raw = os.fspath(path).replace('\\', os.sep).replace('/', os.sep)
        if not os.path.isabs(raw):
            base = repo_abs if relative_to_repo else os.getcwd()
            raw = os.path.join(base, raw)
        absolute = os.path.abspath(os.path.normpath(raw))
        rel = os.path.relpath(absolute, repo_abs)
        return os.path.normcase(os.path.normpath(rel)).replace('\\', '/')

    def inside_repo(rel):
        return rel != '..' and not rel.startswith('../') and not os.path.isabs(rel)

    target = normalized_rel(file_path, relative_to_repo=True)
    allowed = set()
    for candidate in (rules_path, __file__):
        if candidate:
            try:
                rel = normalized_rel(candidate)
            except ValueError:
                # Windows cannot compute a relative path across drive letters;
                # that candidate is outside this repo and is not exempt.
                continue
            if inside_repo(rel):
                allowed.add(rel)
    return inside_repo(target) and target in allowed


def cmd_staged(repo, rules, rules_path=None):
    fails = []
    files = _nul_paths(
        _git_bytes(repo, 'diff', '--cached', '--name-only', '-z').stdout, fails,
    )
    names = rules.get('forbidden_staged_names', [])
    forb = rules.get('forbidden_patterns', [])
    for f in files:
        base = os.path.basename(f)
        for pat in names:
            if fnmatch.fnmatch(base, pat) or fnmatch.fnmatch(f, pat):
                fails.append(f'禁用文件被暂存: {f} (匹配 {pat})')
        if _is_exempt_file(repo, f, rules_path):
            continue
        diff = _git_bytes(
            repo, 'diff', '--cached', '-U0', '--', f, literal_pathspecs=True,
        ).stdout.decode('utf-8', errors='replace')
        added = '\n'.join(l[1:] for l in diff.splitlines()
                          if l.startswith('+') and not l.startswith('+++'))
        for pat in forb:
            try:
                hit = re.search(pat, added)
            except re.error:
                hit = pat in added
            if hit:
                fails.append(f'{f}: 暂存内容含 forbidden_pattern /{pat}/')
        for rx, label in SECRET_RX:
            if rx.search(added):
                fails.append(f'{f}: 疑似 secret（兜底正则·非 gitleaks）: {label}')
    return fails


def cmd_ignore(repo, rules):
    fails = []
    public = bool(rules.get('is_public_repo', False))
    for p in rules.get('sensitive_paths', []):
        result = _git(repo, 'check-ignore', '-q', '--', p, allow_returncodes={1})
        ignored = result.returncode == 0
        if not ignored:
            if public:
                fails.append(f'敏感路径未被 .gitignore 命中: {p} （公开仓 → git add . 会暂存 → 泄密）')
            else:
                fails.append(f'[warn·私有仓] 敏感路径未被 ignore: {p}')
    return fails


def cmd_grep(repo, rules, rules_path=None):
    fails = []
    forb = rules.get('forbidden_patterns', [])
    tracked = _nul_paths(_git_bytes(repo, 'ls-files', '-z').stdout, fails)
    for f in tracked:
        if _is_exempt_file(repo, f, rules_path):
            continue
        full = os.path.join(repo, f)
        try:
            if os.stat(full).st_size > MAX_BYTES:
                continue
            with open(full, encoding='utf-8', errors='replace') as fobj:
                content = fobj.read()
        except FileNotFoundError:
            continue
        except (OSError, ValueError) as e:
            fails.append(f'{f}: 无法读取跟踪文件: {e}')
            continue
        for pat in forb:
            try:
                if re.search(pat, content):
                    fails.append(f'{f}: 含 forbidden_pattern /{pat}/')
            except re.error:
                pass
        for rx, label in SECRET_RX:
            if rx.search(content):
                fails.append(f'{f}: 疑似 secret（兜底正则·非 gitleaks）: {label}')
    for spec in rules.get('required_patterns', []):
        if '::' not in spec:
            continue
        relf, pat = spec.split('::', 1)
        full = os.path.join(repo, relf)
        ok = False
        if os.path.isfile(full):
            try:
                with open(full, encoding='utf-8', errors='replace') as fobj:
                    ok = bool(re.search(pat, fobj.read()))
            except (OSError, re.error):
                ok = False
        if not ok:
            fails.append(f'required 未满足: {relf} 缺 /{pat}/')
    return fails


def main():
    ap = argparse.ArgumentParser(description='BV Harness Gate 确定性检查器 (read-only / stdlib)')
    ap.add_argument('cmd', choices=['staged', 'ignore', 'grep', 'all'])
    ap.add_argument('--repo', default='.')
    ap.add_argument('--rules', default=None, help='规则文件；默认 <repo>/harness_rules.yaml')
    args = ap.parse_args()
    repo = os.path.abspath(args.repo)
    explicit_rules = args.rules is not None
    rules_path = args.rules if explicit_rules else os.path.join(repo, 'harness_rules.yaml')
    if not os.path.exists(rules_path):
        if not explicit_rules:
            print(f'[harness] 无规则文件（{rules_path}）→ 跳过 (exit 0)。见 project_rules.example.yaml')
            return 0
        print(f'[FAIL:rules] rules file not found: {rules_path}')
        return 1
    if not os.path.isfile(rules_path):
        print(f'[FAIL:rules] rules path is not a regular file: {rules_path}')
        return 1
    try:
        rules = _load_rules(rules_path)
    except Exception as e:
        print(f'[FAIL:rules] rules file could not be loaded: {e}')
        return 1
    if not isinstance(rules, dict) or not rules:
        print(f'[FAIL:rules] rules file is empty or invalid: {rules_path}')
        return 1
    funcs = {'staged': cmd_staged, 'ignore': cmd_ignore, 'grep': cmd_grep}
    stages = ['staged', 'ignore', 'grep'] if args.cmd == 'all' else [args.cmd]
    fails = []
    for stage in stages:
        try:
            if stage in ('staged', 'grep'):
                stage_fails = funcs[stage](repo, rules, rules_path)
            else:
                stage_fails = funcs[stage](repo, rules)
            fails.extend((stage, message) for message in stage_fails)
        except GitError as e:
            fails.append((stage, f'git error: {e}'))
    print(f'# harness_check {args.cmd}  repo={repo}  rules={os.path.basename(rules_path)}')
    if not fails:
        print('[PASS] 无违规')
        return 0
    for stage, m in fails:
        print(f'[FAIL:{stage}] {m}')
    print(f'\n{len(fails)} 处违规 → 拦截。（本地可 --no-verify 绕过，但 CI required checks 会再拦）')
    return 1


if __name__ == '__main__':
    sys.exit(main())
