"""DEPRECATED / DANGEROUS — DO NOT RUN.

One-shot 2026-04 migration script, retained only as historical record.
Running it rewrites the IntentExtractor block inside mismatch_detector.py via a
hardcoded search-and-replace. The ``old`` pattern below no longer matches the
current detector, so today this is a no-op, but it must never be executed and is
not a live module. See CODE_MAP.md and AGENTS.md §3.
"""
import os
import re
import sys

if os.environ.get("HELIX_ALLOW_LEGACY_PATCH") != "1":
    print(
        "[fix_extractor.py] DEPRECATED one-shot migration - refusing to run. "
        "Retained for history only; this is not a live module."
    )
    sys.exit(0)

with open("mismatch_detector.py", "r", encoding="utf-8") as f:
    code = f.read()

old = '''    NATSPEC_PATTERNS = [
        r"@notice\\s+(.+)",
        r"@dev\\s+(.+)",
        r"///\\s+(.+)",
        r"/\\*\\*\\s*\\n\\s*\\*\\s+(.+)",
    ]

    def extract(self, source_code: str) -> dict[str, str]:
        """
        Returns: {function_name: intent_description}
        Example: {"withdraw": "safely withdraw user funds after updating balance"}
        """
        import re
        results = {}
        # Extract function blocks with their preceding NatSpec
        func_pattern = r"((?:///.*\\n|/\\*\\*[\\s\\S]*?\\*/\\s*)?)function\\s+(\\w+)\\s*\\("
        for match in re.finditer(func_pattern, source_code):
            natspec_block = match.group(1)
            func_name = match.group(2)
            intent_parts = []
            for pattern in self.NATSPEC_PATTERNS:
                intent_parts += re.findall(pattern, natspec_block)
            intent_text = " ".join(intent_parts).strip()
            if not intent_text:
                # Fall back to function name as minimal intent signal
                intent_text = func_name.replace("_", " ")
            results[func_name] = intent_text
        return results'''

new = '''    def extract(self, source_code: str) -> dict[str, str]:
        import re
        results = {}
        # Match function with ALL preceding comment lines
        func_pattern = r"((?:[ \\t]*///[^\\n]*\\n|[ \\t]*/\\*[\\s\\S]*?\\*/[ \\t]*\\n)*)[ \\t]*function\\s+(\\w+)\\s*\\("
        for match in re.finditer(func_pattern, source_code):
            comment_block = match.group(1)
            func_name = match.group(2)
            # Extract meaningful text from NatSpec
            parts = re.findall(r"@notice\\s+(.+)|@dev\\s+(.+)|///\\s*(.+)", comment_block)
            intent_parts = [p[0] or p[1] or p[2] for p in parts if any(p)]
            intent_text = " ".join(intent_parts).strip()
            if not intent_text and comment_block:
                # Strip comment markers and get raw text
                raw = re.sub(r"[/*@]|\\bparam\\b|\\breturns\\b", " ", comment_block)
                intent_text = " ".join(raw.split())[:200]
            if not intent_text:
                intent_text = func_name.replace("_", " ")
            results[func_name] = intent_text
        return results'''

if old in code:
    code = code.replace(old, new)
    with open("mismatch_detector.py", "w", encoding="utf-8") as f:
        f.write(code)
    print("Fixed!")
else:
    print("Pattern not found - need manual edit")
