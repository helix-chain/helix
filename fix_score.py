with open("mismatch_detector.py", "r", encoding="utf-8") as f:
    code = f.read()

old = '''            mismatch_score = self.embedder.cosine_distance(intent_vec, code_vec)'''

new = '''            base_score = self.embedder.cosine_distance(intent_vec, code_vec)

            # Rule-based boost: known dangerous patterns detected in code
            DANGEROUS_PATTERNS = {
                "external_call_before_state_update": 0.45,
                "missing_access_control": 0.40,
                "spot_price_oracle": 0.38,
                "missing_reentrancy_guard": 0.25,
                "unchecked_arithmetic": 0.30,
            }
            pattern_boost = max(
                (DANGEROUS_PATTERNS.get(p, 0) for p in code_patterns),
                default=0.0
            )

            # Safety claim in intent amplifies the mismatch
            safety_keywords = ["safe", "secur", "protect", "verified", "only", "prevent"]
            safety_claimed = any(kw in intent_text.lower() for kw in safety_keywords)
            amplifier = 1.3 if safety_claimed else 1.0

            mismatch_score = min(1.0, max(base_score, pattern_boost) * amplifier)'''

if old in code:
    code = code.replace(old, new)
    with open("mismatch_detector.py", "w", encoding="utf-8") as f:
        f.write(code)
    print("Fixed!")
else:
    print("Not found")
