"""
HELIX AI Engine — Intent-Code Mismatch Detector (MVP v0.1)
Layer: L3 NEURAL AUDIT
Phase: 1 (EVM Smart Contract AI Security Tool)

Tech stack: Python 3.11 + PyTorch 2.3 + sentence-transformers + pgvector
"""

from dataclasses import dataclass, field
from functools import lru_cache
from typing import Optional
import numpy as np


# ─────────────────────────────────────────────
# 1. Data Structures
# ─────────────────────────────────────────────

@dataclass
class ContractInput:
    """Input to the mismatch detector."""
    source_code: str           # Solidity source (with NatSpec comments)
    bytecode: Optional[str] = None    # EVM bytecode hex (if source unavailable)
    contract_address: Optional[str] = None
    chain_id: int = 1          # Default: Ethereum mainnet


@dataclass
class MismatchReport:
    """Output: detailed mismatch analysis."""
    contract_address: Optional[str]
    overall_mismatch_score: float          # 0.0 (aligned) → 1.0 (severe mismatch)
    risk_level: str                        # LOW / MEDIUM / HIGH / CRITICAL
    function_reports: list = field(default_factory=list)
    immune_matches: list = field(default_factory=list)  # Similar historical attacks
    recommended_action: str = ""
    false_positive_confidence: float = 0.0


@dataclass
class FunctionMismatch:
    """Per-function mismatch detail."""
    function_name: str
    intent_text: str       # Extracted from NatSpec / comments
    code_summary: str      # Extracted from AST / bytecode
    mismatch_score: float  # Cosine distance between embeddings
    attack_class: Optional[str] = None  # e.g. "reentrancy"
    evidence: str = ""


# ─────────────────────────────────────────────
# 2. Intent Extractor
# ─────────────────────────────────────────────

def mask_comments_and_strings(source: str) -> str:
    """Blank comments and string contents without changing source offsets."""
    masked = list(source)
    length = len(source)
    index = 0
    line_terminators = "\r\n\v\f\x85\u2028\u2029"

    def blank(position: int) -> None:
        if source[position] not in line_terminators:
            masked[position] = " "

    while index < length:
        if source.startswith("//", index):
            end = index
            while end < length and source[end] not in line_terminators:
                end += 1
            for position in range(index, end):
                blank(position)
            index = end
            continue

        if source.startswith("/*", index):
            end = source.find("*/", index + 2)
            stop = length if end < 0 else end + 2
            for position in range(index, stop):
                blank(position)
            index = stop
            continue

        quote = source[index]
        if quote not in "\"'":
            index += 1
            continue

        masked_end = index + 1
        while masked_end < length and source[masked_end].isspace():
            masked_end += 1
        if masked_end < length and source[masked_end] == quote:
            index = masked_end + 1
            continue

        index += 1
        while index < length:
            char = source[index]
            if char == "\\":
                blank(index)
                if index + 1 >= length:
                    index += 1
                    break
                if source[index + 1] == "\r":
                    if index + 2 < length and source[index + 2] == "\n":
                        index += 3
                    else:
                        index += 2
                    continue
                if source[index + 1] == "\n":
                    index += 2
                    continue
                if source[index + 1] in line_terminators:
                    index += 1
                    break
                blank(index + 1)
                index += 2
                continue
            if char == quote:
                index += 1
                break
            if char in line_terminators:
                break
            blank(index)
            index += 1

    return "".join(masked)


@dataclass(frozen=True)
class FunctionUnit:
    """A named Solidity function definition or declaration span."""
    name: str
    kind: str
    start: int
    body_offset: int
    end: int
    has_body: bool


def _extract_function_units_from_masked(masked_source: str) -> tuple[FunctionUnit, ...]:
    """Extract named and special function units from masked source."""
    import re

    identifier_pattern = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
    token_pattern = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*|\S")
    tokens = [(match.group(), match.start(), match.end())
              for match in token_pattern.finditer(masked_source)]
    parentheses = {}
    braces = {}
    paren_stack = []
    brace_stack = []

    for token_index, (value, _, _) in enumerate(tokens):
        if value == "(":
            paren_stack.append(token_index)
        elif value == ")" and paren_stack:
            opening = paren_stack.pop()
            parentheses[opening] = token_index
        elif value == "{":
            brace_stack.append(token_index)
        elif value == "}" and brace_stack:
            opening = brace_stack.pop()
            braces[opening] = token_index

    # The forward walk from a token is the same whichever header started it, so
    # its result is remembered for every token it passed: each token is walked
    # once even when many headers lack a terminator.
    terminator_from = {}

    def find_terminator(parameter_close: int):
        cursor = parameter_close + 1
        walked = []
        result = None
        while cursor < len(tokens):
            if cursor in terminator_from:
                result = terminator_from[cursor]
                break
            walked.append(cursor)
            value = tokens[cursor][0]
            if value == "(":
                close = parentheses.get(cursor)
                if close is None:
                    break
                cursor = close + 1
                continue
            if value in (")", "}"):
                break
            if value in ("{", ";"):
                result = cursor
                break
            cursor += 1
        for position in walked:
            terminator_from[position] = result
        return result

    external_before = [0]
    for value, _, _ in tokens:
        external_before.append(external_before[-1] + (value == "external"))

    def make_unit(name: str, kind: str, start_index: int, terminator: int):
        value, body_offset, term_end = tokens[terminator]
        if value == ";":
            return FunctionUnit(
                name=name, kind=kind, start=tokens[start_index][1],
                body_offset=body_offset, end=term_end, has_body=False,
            )
        closing = braces.get(terminator)
        end_offset = len(masked_source) if closing is None else tokens[closing][2]
        return FunctionUnit(
            name=name, kind=kind, start=tokens[start_index][1],
            body_offset=body_offset, end=end_offset, has_body=True,
        )

    units = []
    for token_index, (value, start_offset, _) in enumerate(tokens):
        if value == "function":
            if token_index + 2 < len(tokens):
                name_token = tokens[token_index + 1]
                opening = token_index + 2
                if (identifier_pattern.fullmatch(name_token[0])
                        and tokens[opening][0] == "("):
                    parameter_close = parentheses.get(opening)
                    if parameter_close is not None:
                        terminator = find_terminator(parameter_close)
                        if terminator is not None:
                            units.append(make_unit(name_token[0], "function", token_index, terminator))
                    continue

            if token_index + 1 < len(tokens) and tokens[token_index + 1][0] == "(":
                previous_character = tokens[token_index - 1][0][-1] if token_index else ""
                if previous_character in ("{", "}", ";", ""):
                    opening = token_index + 1
                    parameter_close = parentheses.get(opening)
                    if parameter_close is not None:
                        terminator = find_terminator(parameter_close)
                        if (terminator is not None and tokens[terminator][0] == "{"):
                            units.append(make_unit("fallback", "fallback", token_index, terminator))
            continue

        if value not in ("receive", "fallback"):
            continue
        if token_index:
            previous = tokens[token_index - 1][0]
            if previous == "." or identifier_pattern.fullmatch(previous):
                continue
        if token_index + 1 >= len(tokens) or tokens[token_index + 1][0] != "(":
            continue
        opening = token_index + 1
        parameter_close = parentheses.get(opening)
        if parameter_close is None:
            continue
        terminator = find_terminator(parameter_close)
        if terminator is None or tokens[terminator][0] != "{":
            continue
        if external_before[terminator] == external_before[parameter_close + 1]:
            continue  # the header between the parameters and the body has no external
        units.append(make_unit(value, value, token_index, terminator))

    units.sort(key=lambda unit: unit.start)
    return tuple(units)


@lru_cache(maxsize=16)
def _source_index(source: str) -> tuple[str, tuple[FunctionUnit, ...]]:
    """Cache the masked source and its parsed function units for one input."""
    masked = mask_comments_and_strings(source)
    return masked, _extract_function_units_from_masked(masked)


@lru_cache(maxsize=16)
def _first_bodies(source: str) -> dict:
    """Map each name to its first unit with a body (one pass per input)."""
    first = {}
    for unit in _source_index(source)[1]:
        if unit.has_body and unit.name not in first:
            first[unit.name] = unit
    return first


def extract_function_units(source: str) -> tuple[FunctionUnit, ...]:
    """Return named function definitions and declarations in source order."""
    return _source_index(source)[1]


def _doc_comment_block(gap: str) -> str:
    """Return the documentation comments that end right before a definition.

    gap is the text between the preceding code and the definition, so it holds
    only comments and whitespace. The result is the text that the earlier
    regular expression captured with re.search:

        ((?:[ \\t]*///[^\\n]*\\n|[ \\t]*/\\*[\\s\\S]*?\\*/[ \\t]*\\r?\\n)*)[ \\t]*$

    i.e. the run of items starting at the leftmost position from which the rest
    of the gap splits into items (a /// line, or anything from /* to a */ that
    is followed by blanks and a line break) and trailing blanks. The regex can
    backtrack exponentially when the split fails; here every position is
    decided once, from the end, so the work is linear in the gap length.
    """
    length = len(gap)
    # Where the run of items must end: before the trailing blanks, or, because
    # $ also matches just before a final line feed, before a blank last line.
    boundary = length
    if gap.endswith("\n"):
        last_line = gap.rfind("\n", 0, length - 1) + 1
        if gap[last_line:length - 1].strip(" \t") == "":
            boundary = last_line
    else:
        while boundary > 0 and gap[boundary - 1] in " \t":
            boundary -= 1
    if boundary == 0 or gap[boundary - 1] != "\n":
        return ""

    # splits_from[i]: gap[i:] is a sequence of items followed by trailing blanks.
    splits_from = [False] * (length + 3)
    for index in range(boundary, length + 1):
        splits_from[index] = True
    # block_end_from[i]: some "*/ blanks [CR] LF" whose "*/" starts at >= i ends
    # exactly where the rest of the gap splits.
    block_end_from = [False] * (length + 3)
    next_line_feed = [length] * (length + 1)
    after_blanks = list(range(length + 1))
    line_feed = length
    for index in range(length - 1, -1, -1):
        if gap[index] == "\n":
            line_feed = index
        next_line_feed[index] = line_feed
        if gap[index] in " \t":
            after_blanks[index] = after_blanks[index + 1]

    for index in range(boundary - 1, -1, -1):
        ends_here = False
        if gap.startswith("*/", index):
            cursor = after_blanks[index + 2]
            if cursor < length and gap[cursor] == "\r":
                cursor += 1
            ends_here = cursor < length and gap[cursor] == "\n" and splits_from[cursor + 1]
        block_end_from[index] = ends_here or block_end_from[index + 1]

        start = after_blanks[index]
        if gap.startswith("///", start):
            line_end = next_line_feed[start]
            if line_end < length and splits_from[line_end + 1]:
                splits_from[index] = True
                continue
        if gap.startswith("/*", start) and block_end_from[start + 2]:
            splits_from[index] = True

    first = next(index for index in range(length + 1) if splits_from[index])
    return gap[first:boundary] if first < boundary else ""


class IntentExtractor:
    """
    Extracts human intent from Solidity NatSpec comments and function names.
    Uses regex + CodeBERT tokenizer for structured extraction.
    """

    def extract(self, source_code: str) -> dict[str, str]:
        import re
        results = {}
        masked, units = _source_index(source_code)
        for unit in units:
            if not unit.has_body:
                continue
            # Only the comments and whitespace between the preceding code and
            # this definition can document it. Reading that gap (instead of the
            # whole prefix) keeps extraction linear and keeps string contents out.
            gap_start = unit.start
            while gap_start > 0 and masked[gap_start - 1].isspace():
                gap_start -= 1
            comment_block = _doc_comment_block(source_code[gap_start:unit.start])
            parts = re.findall(r"@notice\s+(.+)|@dev\s+(.+)|///\s*(.+)", comment_block)
            intent_parts = [p[0] or p[1] or p[2] for p in parts if any(p)]
            intent_text = " ".join(intent_parts).strip()
            if not intent_text and comment_block:
                raw = re.sub(r"[/*@]|\bparam\b|\breturns\b", " ", comment_block)
                intent_text = " ".join(raw.split())[:200]
            if not intent_text:
                intent_text = unit.name.replace("_", " ")
            results[unit.name] = intent_text
        return results


# ─────────────────────────────────────────────
# 3. Code Encoder
# ─────────────────────────────────────────────

class CodeEncoder:
    """
    Encodes Solidity function bodies to semantic vectors.
    Extracts control-flow patterns: external calls, state updates, modifiers.
    """

    RISK_PATTERNS = {
        "external_call_before_state_update": [
            r"\.call\{",
            r"\.transfer\(",
            r"\.send\(",
        ],
        "missing_reentrancy_guard": [
            r"\.call\{",
            r"\.call\(",
            r"\.send\(",
        ],
        "unchecked_arithmetic": [
            r"unchecked\s*\{",
            r"\+=.*\d+",  # simplified
        ],
        "missing_access_control": [
            r"function\s+\w+\s*\([^)]*\)\s*(?:external|public)\s*(?!.*onlyOwner)",
        ],
        "spot_price_oracle": [
            r"\.getReserves\(",
            r"price0CumulativeLast",
            r"token0\.balanceOf",
        ],
    }

    def summarize(self, function_source: str) -> dict:
        """
        Returns pattern matches found in function body.
        Used as symbolic representation before embedding.
        """
        import re
        function_source = mask_comments_and_strings(function_source)
        found_patterns = {}

        # Split: full function (for safety checks) vs body (for risk patterns)
        brace_idx = function_source.find('{')
        body_only = function_source[brace_idx+1:] if brace_idx >= 0 else function_source

        # --- Safety checks on FULL function (includes modifiers in signature) ---
        has_reentrancy_guard = bool(
            re.search(r'nonReentrant|ReentrancyGuard', function_source, re.IGNORECASE)
        )
        if re.search(r'require\s*\(\s*!?\s*_locked', body_only):
            has_reentrancy_guard = True
        if re.search(r'_locked\s*=\s*true', body_only, re.IGNORECASE):
            has_reentrancy_guard = True

        ext_positions = [m.start() for m in re.finditer(
            r'\.call\{|\.call\(|\.transfer\(|\.send\(', body_only)]
        has_ext = len(ext_positions) > 0

        # CEI violation: storage write AFTER last external call
        has_cei_violation = False
        if has_ext:
            last_ext = max(ext_positions)
            post_call = body_only[last_ext:]
            has_cei_violation = bool(re.search(
                r'\b\w+\s*\[[^\]]*\]\s*[-+]?=\s*(?!=)', post_call
            ))

        has_access_control = bool(re.search(
            r'onlyOwner|onlyAdmin|require\s*\(\s*msg\.sender\s*==\s*\w+|require\s*\(\s*isOwner',
            function_source, re.IGNORECASE
        ))

        # --- Risk patterns on BODY ONLY (not function signature!) ---
        for pattern_name, regexes in self.RISK_PATTERNS.items():
            for regex in regexes:
                if re.search(regex, body_only, re.IGNORECASE):
                    if pattern_name == 'external_call_before_state_update':
                        if not has_cei_violation or has_reentrancy_guard:
                            continue
                    elif pattern_name == 'missing_reentrancy_guard':
                        if has_reentrancy_guard or not ext_positions:
                            continue
                    elif pattern_name == 'missing_access_control':
                        if has_access_control:
                            continue
                    found_patterns[pattern_name] = True
                    break
        return found_patterns


# ─────────────────────────────────────────────
# 4. Embedding Engine
# ─────────────────────────────────────────────

class HelixEmbedder:
    """
    768-dimensional embeddings using sentence-transformers.
    Model: 'microsoft/codebert-base' fine-tuned on Solidity + attack descriptions.
    
    Phase 1 (MVP): Use pre-trained codebert-base without fine-tuning.
    Phase 2: Fine-tune on 500+ immune signatures.
    """

    MODEL_NAME = "microsoft/codebert-base"

    def __init__(self):
        self._model = None  # Lazy load

    def _load_model(self):
        if self._model is None:
            from transformers import AutoTokenizer, AutoModel
            import torch
            self._tokenizer = AutoTokenizer.from_pretrained(self.MODEL_NAME)
            self._model = AutoModel.from_pretrained(self.MODEL_NAME)
            self._model.eval()

    def embed(self, text: str) -> np.ndarray:
        """Returns 768-dim numpy vector."""
        self._load_model()
        import torch
        inputs = self._tokenizer(
            text, return_tensors="pt",
            max_length=512, truncation=True, padding=True
        )
        with torch.no_grad():
            outputs = self._model(**inputs)
        # Mean pooling over token embeddings
        embedding = outputs.last_hidden_state.mean(dim=1).squeeze().numpy()
        return embedding  # shape: (768,)

    def cosine_distance(self, vec_a: np.ndarray, vec_b: np.ndarray) -> float:
        """Returns 0.0 (identical) to 1.0 (opposite)."""
        norm_a = np.linalg.norm(vec_a)
        norm_b = np.linalg.norm(vec_b)
        if norm_a == 0 or norm_b == 0:
            return 1.0
        cosine_sim = np.dot(vec_a, vec_b) / (norm_a * norm_b)
        return float(1.0 - cosine_sim)


# ─────────────────────────────────────────────
# 5. Immune Library Interface
# ─────────────────────────────────────────────

class ImmuneLibrary:
    """
    pgvector-backed immune signature store.
    Stores 768-dim attack embeddings; queries by cosine similarity.
    
    Schema (PostgreSQL + pgvector):
        CREATE TABLE immune_signatures (
            id          SERIAL PRIMARY KEY,
            sig_id      TEXT UNIQUE,
            attack_class TEXT,
            protocol    TEXT,
            loss_usd    BIGINT,
            embedding   vector(768),
            metadata    JSONB
        );
        CREATE INDEX ON immune_signatures
            USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100);
    """

    def __init__(self, db_url: str = "postgresql://localhost/helix"):
        self.db_url = db_url
        self._conn = None

    def connect(self):
        import psycopg2
        from pgvector.psycopg2 import register_vector
        self._conn = psycopg2.connect(self.db_url)
        register_vector(self._conn)

    def search_similar(
        self,
        query_embedding: np.ndarray,
        top_k: int = 5,
        threshold: float = 0.3
    ) -> list[dict]:
        """
        Returns top-K most similar historical attacks.
        threshold: cosine distance cutoff (lower = more similar).
        """
        if self._conn is None:
            return []  # Graceful degradation when DB unavailable
        cursor = self._conn.cursor()
        cursor.execute("""
            SELECT sig_id, attack_class, protocol, loss_usd,
                   embedding <=> %s AS distance, metadata
            FROM immune_signatures
            WHERE embedding <=> %s < %s
            ORDER BY distance ASC
            LIMIT %s
        """, (query_embedding, query_embedding, threshold, top_k))
        rows = cursor.fetchall()
        return [
            {
                "sig_id": row[0],
                "attack_class": row[1],
                "protocol": row[2],
                "loss_usd": row[3],
                "distance": float(row[4]),
                "metadata": row[5],
            }
            for row in rows
        ]

    def insert_signature(self, sig_id: str, attack_class: str, protocol: str,
                          loss_usd: int, embedding: np.ndarray, metadata: dict):
        """Permanent immune memory: once added, never deleted."""
        cursor = self._conn.cursor()
        cursor.execute("""
            INSERT INTO immune_signatures (sig_id, attack_class, protocol, loss_usd, embedding, metadata)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (sig_id) DO NOTHING
        """, (sig_id, attack_class, protocol, loss_usd, embedding, metadata))
        self._conn.commit()


# ─────────────────────────────────────────────
# 6. Mismatch Detector (Core)
# ─────────────────────────────────────────────

class IntentCodeMismatchDetector:
    """
    HELIX L3 NEURAL AUDIT — Main detection engine.
    
    Algorithm:
    1. Extract intent per function (NatSpec → embedding)
    2. Encode code behavior per function (AST patterns → embedding)
    3. Compute cosine distance (intent vs. code)
    4. Query immune library for similar historical attacks
    5. Combine scores → MismatchReport
    """

    # Tunable thresholds (calibrated on 20-sample seed set)
    MISMATCH_THRESHOLD_HIGH = 0.45
    MISMATCH_THRESHOLD_MEDIUM = 0.30
    MISMATCH_THRESHOLD_LOW = 0.10

    def __init__(self, immune_library: Optional[ImmuneLibrary] = None):
        self.intent_extractor = IntentExtractor()
        self.code_encoder = CodeEncoder()
        self.embedder = HelixEmbedder()
        self.immune_lib = immune_library

    def analyze(self, contract: ContractInput) -> MismatchReport:
        """
        Main entry point. Returns MismatchReport.
        """
        if not contract.source_code:
            return self._bytecode_fallback(contract)

        # Step 1: Extract intent per function
        intent_map = self.intent_extractor.extract(contract.source_code)

        # Step 2: Encode code patterns per function
        function_reports = []
        for func_name, intent_text in intent_map.items():
            func_source = self._extract_function_body(contract.source_code, func_name)
            code_patterns = self.code_encoder.summarize(func_source)
            code_text = self._patterns_to_text(code_patterns)

            # Step 3: Embed both sides
            intent_vec = self.embedder.embed(intent_text)
            code_vec = self.embedder.embed(code_text if code_text else func_name)

            # Step 4: Cosine distance
            base_score = self.embedder.cosine_distance(intent_vec, code_vec)

            # Rule-based boost: additive, safety-filtered patterns only
            DANGEROUS_PATTERNS = {
                "external_call_before_state_update": 0.30,
                "missing_access_control": 0.20,
                "spot_price_oracle": 0.20,
                "missing_reentrancy_guard": 0.15,
                "unchecked_arithmetic": 0.15,
            }
            pattern_boost = sum(
                DANGEROUS_PATTERNS.get(p, 0) for p in code_patterns
            )

            # Safety claim amplifies ONLY when dangerous patterns confirmed
            safety_keywords = ["safe", "secur", "protect", "verified", "only", "prevent"]
            safety_claimed = any(kw in intent_text.lower() for kw in safety_keywords)
            amplifier = 1.2 if (safety_claimed and pattern_boost > 0) else 1.0

            mismatch_score = min(1.0, (base_score + pattern_boost) * amplifier)

            # Step 5: Immune library lookup
            immune_matches = []
            if self.immune_lib and mismatch_score > self.MISMATCH_THRESHOLD_LOW:
                combined_vec = (intent_vec + code_vec) / 2
                immune_matches = self.immune_lib.search_similar(combined_vec, top_k=3)

            attack_class = self._infer_attack_class(code_patterns, immune_matches)

            function_reports.append(FunctionMismatch(
                function_name=func_name,
                intent_text=intent_text,
                code_summary=code_text,
                mismatch_score=mismatch_score,
                attack_class=attack_class,
                evidence=self._build_evidence(code_patterns, immune_matches),
            ))

        # Step 6: Aggregate
        if not function_reports:
            return MismatchReport(
                contract_address=contract.contract_address,
                overall_mismatch_score=0.0,
                risk_level="LOW",
                recommended_action="No analyzable Solidity functions detected. Manual review recommended.",
            )

        overall_score = max(r.mismatch_score for r in function_reports)
        risk_level = self._score_to_risk(overall_score)

        return MismatchReport(
            contract_address=contract.contract_address,
            overall_mismatch_score=overall_score,
            risk_level=risk_level,
            function_reports=function_reports,
            immune_matches=[m for r in function_reports for m in (r.attack_class and [] or [])],
            recommended_action=self._recommend(risk_level),
        )

    # ── Helpers ──────────────────────────────

    def _extract_function_body(self, source: str, func_name: str) -> str:
        """Return the masked source slice for the first named function body."""
        masked, _ = _source_index(source)
        unit = _first_bodies(source).get(func_name)
        return masked[unit.start:unit.end] if unit else ""

    def _patterns_to_text(self, patterns: dict) -> str:
        """Convert code pattern dict to natural language for embedding."""
        if not patterns:
            return "standard function implementation"
        descriptions = {
            "external_call_before_state_update": "external call made before state variables updated",
            "missing_reentrancy_guard": "no reentrancy protection modifier",
            "unchecked_arithmetic": "arithmetic operations without overflow checking",
            "missing_access_control": "function accessible without ownership check",
            "spot_price_oracle": "price read from spot AMM reserve without time-weighted average",
        }
        return "; ".join(descriptions.get(p, p) for p in patterns.keys())

    def _infer_attack_class(self, patterns: dict, immune_matches: list) -> Optional[str]:
        pattern_to_class = {
            "external_call_before_state_update": "reentrancy",
            "missing_access_control": "access_control",
            "spot_price_oracle": "oracle_manipulation",
            "unchecked_arithmetic": "integer_overflow",
        }
        for pattern, cls in pattern_to_class.items():
            if pattern in patterns:
                return cls
        if immune_matches:
            return immune_matches[0].get("attack_class")
        return None

    def _score_to_risk(self, score: float) -> str:
        if score >= self.MISMATCH_THRESHOLD_HIGH:
            return "CRITICAL"
        elif score >= self.MISMATCH_THRESHOLD_MEDIUM:
            return "HIGH"
        elif score >= self.MISMATCH_THRESHOLD_LOW:
            return "MEDIUM"
        return "LOW"

    def _recommend(self, risk_level: str) -> str:
        actions = {
            "CRITICAL": "HALT deployment. Manual audit required before mainnet.",
            "HIGH": "Flag for human review. Do not deploy without audit.",
            "MEDIUM": "Additional testing recommended. Consider formal verification.",
            "LOW": "Proceed with standard review process.",
        }
        return actions.get(risk_level, "")

    def _build_evidence(self, patterns: dict, immune_matches: list) -> str:
        parts = list(patterns.keys())
        if immune_matches:
            parts.append(f"Similar to {immune_matches[0].get('protocol')} "
                         f"({immune_matches[0].get('attack_class')}, "
                         f"${immune_matches[0].get('loss_usd', 0):,} loss)")
        return "; ".join(parts)

    def _bytecode_fallback(self, contract: ContractInput) -> MismatchReport:
        """When source unavailable, analyze bytecode patterns only."""
        return MismatchReport(
            contract_address=contract.contract_address,
            overall_mismatch_score=0.0,
            risk_level="LOW",
            recommended_action="Source code required for full intent-code analysis.",
        )


# ─────────────────────────────────────────────
# 7. CLI Entry Point
# ─────────────────────────────────────────────

def analyze_contract(source_code: str, address: str = None) -> dict:
    """
    Convenience wrapper for CLI and API use.
    Returns JSON-serializable dict.
    """
    detector = IntentCodeMismatchDetector()  # No immune lib for Phase 0
    contract = ContractInput(source_code=source_code, contract_address=address)
    report = detector.analyze(contract)

    return {
        "contract_address": report.contract_address,
        "risk_level": report.risk_level,
        "overall_mismatch_score": round(report.overall_mismatch_score, 4),
        "recommended_action": report.recommended_action,
        "functions": [
            {
                "name": f.function_name,
                "intent": f.intent_text,
                "code_behavior": f.code_summary,
                "mismatch_score": round(f.mismatch_score, 4),
                "attack_class": f.attack_class,
                "evidence": f.evidence,
            }
            for f in report.function_reports
        ],
    }


# ─────────────────────────────────────────────
# 8. Quick Demo (run: python mismatch_detector.py)
# ─────────────────────────────────────────────

DEMO_CONTRACT = '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @notice A simple vault that allows safe withdrawal of deposited funds
contract VulnerableVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    /// @notice Safely withdraw your funds after balance is verified
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient balance");
        // MISMATCH: external call BEFORE state update (reentrancy vulnerability)
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "transfer failed");
        balances[msg.sender] -= amount;  // <-- should be BEFORE the call
    }
}
'''

if __name__ == "__main__":
    import json
    print("HELIX Intent-Code Mismatch Detector — Demo Run")
    print("=" * 60)
    result = analyze_contract(DEMO_CONTRACT, "0xDEMO_CONTRACT")
    print(json.dumps(result, indent=2))
    print()
    print(f"Risk Level: {result['risk_level']}")
    print(f"Recommendation: {result['recommended_action']}")
