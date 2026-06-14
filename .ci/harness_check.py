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

SELF_FILES = {'harness_rules.yaml', 'project_rules.example.yaml', 'harness_check.py',
              'README.md', 'ci-harness.snippet.yml', 'pre-commit.hook.ps1'}
MAX_BYTES = 2_000_000

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


def _git(repo, *a):
    try:
        r = subprocess.run(['git', '-C', repo, *a], capture_output=True, text=True,
                           encoding='utf-8', errors='replace', timeout=60)
        out = r.stdout or ''
        if r.returncode and r.stderr and not out:
            out = r.stderr
        return out
    except Exception as e:
        return f'(git 错误: {e})'


def cmd_staged(repo, rules):
    fails = []
    files = [l for l in _git(repo, 'diff', '--cached', '--name-only').splitlines() if l.strip()]
    names = rules.get('forbidden_staged_names', [])
    forb = rules.get('forbidden_patterns', [])
    for f in files:
        base = os.path.basename(f)
        for pat in names:
            if fnmatch.fnmatch(base, pat) or fnmatch.fnmatch(f, pat):
                fails.append(f'禁用文件被暂存: {f} (匹配 {pat})')
        if base in SELF_FILES:
            continue
        diff = _git(repo, 'diff', '--cached', '-U0', '--', f)
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
        ignored = bool(_git(repo, 'check-ignore', '-v', p).strip())
        if not ignored:
            if public:
                fails.append(f'敏感路径未被 .gitignore 命中: {p} （公开仓 → git add . 会暂存 → 泄密）')
            else:
                fails.append(f'[warn·私有仓] 敏感路径未被 ignore: {p}')
    return fails


def cmd_grep(repo, rules):
    fails = []
    forb = rules.get('forbidden_patterns', [])
    if forb:
        tracked = [l for l in _git(repo, 'ls-files').splitlines() if l.strip()]
        for f in tracked:
            if os.path.basename(f) in SELF_FILES:
                continue
            full = os.path.join(repo, f)
            if not os.path.isfile(full) or os.path.getsize(full) > MAX_BYTES:
                continue
            try:
                content = open(full, encoding='utf-8', errors='replace').read()
            except OSError:
                continue
            for pat in forb:
                try:
                    if re.search(pat, content):
                        fails.append(f'{f}: 含 forbidden_pattern /{pat}/')
                except re.error:
                    pass
    for spec in rules.get('required_patterns', []):
        if '::' not in spec:
            continue
        relf, pat = spec.split('::', 1)
        full = os.path.join(repo, relf)
        ok = False
        if os.path.isfile(full):
            try:
                ok = bool(re.search(pat, open(full, encoding='utf-8', errors='replace').read()))
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
    rules_path = args.rules or os.path.join(repo, 'harness_rules.yaml')
    rules = _load_rules(rules_path)
    if not rules:
        print(f'[harness] 无规则文件（{rules_path}）→ 跳过 (exit 0)。见 project_rules.example.yaml')
        return 0
    funcs = {'staged': cmd_staged, 'ignore': cmd_ignore, 'grep': cmd_grep}
    stages = ['staged', 'ignore', 'grep'] if args.cmd == 'all' else [args.cmd]
    fails = [(s, m) for s in stages for m in funcs[s](repo, rules)]
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
