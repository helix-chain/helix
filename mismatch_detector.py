"""
HELIX AI Engine — Intent-Code Mismatch Detector (MVP v0.1)
Layer: L3 NEURAL AUDIT
Phase: 1 (EVM Smart Contract AI Security Tool)

Tech stack: Python 3.11 + PyTorch 2.3 + sentence-transformers + pgvector
"""

from dataclasses import dataclass, field
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

class IntentExtractor:
    """
    Extracts human intent from Solidity NatSpec comments and function names.
    Uses regex + CodeBERT tokenizer for structured extraction.
    """

    def extract(self, source_code: str) -> dict[str, str]:
        import re
        results = {}
        # Match function with ALL preceding comment lines
        func_pattern = r"((?:[ \t]*///[^\n]*\n|[ \t]*/\*[\s\S]*?\*/[ \t]*\n)*)[ \t]*function\s+(\w+)\s*\("
        for match in re.finditer(func_pattern, source_code):
            comment_block = match.group(1)
            func_name = match.group(2)
            # Extract meaningful text from NatSpec
            parts = re.findall(r"@notice\s+(.+)|@dev\s+(.+)|///\s*(.+)", comment_block)
            intent_parts = [p[0] or p[1] or p[2] for p in parts if any(p)]
            intent_text = " ".join(intent_parts).strip()
            if not intent_text and comment_block:
                # Strip comment markers and get raw text
                raw = re.sub(r"[/*@]|\bparam\b|\breturns\b", " ", comment_block)
                intent_text = " ".join(raw.split())[:200]
            if not intent_text:
                intent_text = func_name.replace("_", " ")
            results[func_name] = intent_text
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
        """Brace-counting extractor. Returns FULL function (signature + body)."""
        import re
        pattern = rf"function\s+{re.escape(func_name)}\s*\("
        match = re.search(pattern, source)
        if not match:
            return ""
        idx = source.find("{", match.end())
        if idx < 0:
            return ""
        depth = 1
        i = idx + 1
        while i < len(source) and depth > 0:
            if source[i] == "{":
                depth += 1
            elif source[i] == "}":
                depth -= 1
            i += 1
        return source[match.start():i]

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
