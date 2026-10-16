"""Torch-free regression tests for Solidity extraction behavior."""
import unittest

import mismatch_detector


class CommentAndStringMaskTests(unittest.TestCase):
    def test_mask_preserves_offsets_and_is_idempotent(self):
        mask = getattr(mismatch_detector, "mask_comments_and_strings", None)
        self.assertTrue(callable(mask), "source masking helper is missing")
        source = (
            'string memory text = "comment markers // and /* stay literal"; '
            '// quote inside comment: " ignored\n'
            "string memory other = 'quote \" and // are literal'; "
            '/* quote inside block: " and comment marks // */\n'
        )
        masked = mask(source)
        self.assertEqual(len(masked), len(source))
        self.assertEqual(
            [index for index, char in enumerate(masked) if char == "\n"],
            [index for index, char in enumerate(source) if char == "\n"],
        )
        self.assertEqual(mask(masked), masked)

        first_quote = source.index('"comment markers')
        first_close = source.index('"', first_quote + 1)
        self.assertEqual(masked[first_quote], '"')
        self.assertEqual(masked[first_close], '"')
        self.assertTrue(all(char == " " for char in masked[first_quote + 1:first_close]))

        line_comment = source.index('// quote inside comment')
        line_end = source.index("\n", line_comment)
        self.assertTrue(all(char == " " for char in masked[line_comment:line_end]))
        block_comment = source.index('/* quote inside block')
        block_end = source.index('*/', block_comment) + 2
        self.assertTrue(all(char == " " for char in masked[block_comment:block_end]))

    def test_escaped_quotes_do_not_end_a_string(self):
        mask = mismatch_detector.mask_comments_and_strings
        source = r'''label = "say \"hi\" // not a comment"; owner = msg.sender; note = 'it\'s // still text'; x = 1;'''
        masked = mask(source)
        self.assertEqual(len(masked), len(source))
        self.assertIn("owner = msg.sender;", masked)
        self.assertIn("x = 1;", masked)
        self.assertNotIn("not a comment", masked)
        self.assertNotIn("still text", masked)
        self.assertNotIn("hi", masked)
        self.assertEqual(mask(masked), masked)

    def test_mask_handles_continuations_and_unterminated_literals(self):
        mask = getattr(mismatch_detector, "mask_comments_and_strings", None)
        self.assertTrue(callable(mask), "source masking helper is missing")
        continued = 'string memory value = "first\\\nsecond";\n'
        masked = mask(continued)
        self.assertEqual(len(masked), len(continued))
        self.assertEqual(masked.count("\n"), continued.count("\n"))
        self.assertEqual(masked[continued.index('"')], '"')
        self.assertEqual(masked[continued.rindex('"')], '"')
        self.assertTrue(all(char == " " for char in masked[continued.index('"') + 1:continued.rindex('"')] if char != "\n"))
        self.assertEqual(mask(masked), masked)
        self.assertIn("second", mask('value = "unterminated\nsecond line;'))
        open_block = 'value; /* unfinished\nstring " and braces }'
        masked_block = mask(open_block)
        self.assertEqual(len(masked_block), len(open_block))
        self.assertTrue(all(char in (" ", "\n") for char in masked_block[open_block.index("/*"):]))
        self.assertEqual(mask(masked_block), masked_block)

    def test_unicode_line_terminators_survive_and_end_comments_and_strings(self):
        mask = mismatch_detector.mask_comments_and_strings
        for separator in ("\v", "\f", "\x85", "\u2028", "\u2029"):
            with self.subTest(separator=repr(separator)):
                comment_source = "// hidden" + separator + "function visible;\n"
                comment_masked = mask(comment_source)
                self.assertEqual(comment_masked[comment_source.index(separator)], separator)
                self.assertIn("function visible;", comment_masked)

                block_source = "/* hidden" + separator + " text */"
                block_masked = mask(block_source)
                self.assertEqual(block_masked[block_source.index(separator)], separator)

                string_source = 'value = "hidden' + separator + "function visible;"
                string_masked = mask(string_source)
                self.assertEqual(string_masked[string_source.index(separator)], separator)
                self.assertIn("function visible;", string_masked)
                self.assertEqual(mask(string_masked), string_masked)


class CommentIndependentRiskTests(unittest.TestCase):
    def setUp(self):
        self.encoder = mismatch_detector.CodeEncoder()

    def _withdraw(self, annotation):
        return f'''function withdraw() external {{
            {annotation}
            (bool ok, ) = msg.sender.call{{value: 1}}("");
            require(ok);
            balances[msg.sender] = 0;
        }}'''

    def test_comments_and_strings_do_not_create_reentrancy_guards(self):
        for annotation in (
            "// nonReentrant",
            "/* nonReentrant */",
            'string memory note = "nonReentrant";',
        ):
            with self.subTest(annotation=annotation):
                patterns = self.encoder.summarize(self._withdraw(annotation))
                self.assertIn("external_call_before_state_update", patterns)
                self.assertIn("missing_reentrancy_guard", patterns)

    def test_real_modifier_still_suppresses_reentrancy_patterns(self):
        source = self._withdraw("").replace(
            "function withdraw() external", "function withdraw() external nonReentrant"
        )
        patterns = self.encoder.summarize(source)
        self.assertNotIn("external_call_before_state_update", patterns)
        self.assertNotIn("missing_reentrancy_guard", patterns)

    def test_comment_only_external_call_does_not_create_a_pattern(self):
        source = '''function safe() external {
            // msg.sender.call{value: amount}("");
            balances[msg.sender] = amount;
        }'''
        patterns = self.encoder.summarize(source)
        self.assertNotIn("external_call_before_state_update", patterns)
        self.assertNotIn("missing_reentrancy_guard", patterns)


class FunctionBodyBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.detector = mismatch_detector.IntentCodeMismatchDetector()

    def test_comment_and_string_braces_do_not_truncate_the_body(self):
        source = '''contract Vault {
            struct Item { uint256 value; }
            mapping(address => uint256) balances;
            function withdraw() external {
                // }
                string memory first = "bad }";
                string memory second = '}';
                /* } */
                unchecked { balances[msg.sender] += 1; }
                assembly { let local := 1 }
                Item memory item = Item({value: 1});
                (bool ok, ) = msg.sender.call{value: 1}("");
                balances[msg.sender] = 0;
            }
            function after() external { balances[msg.sender] = 2; }
        }'''
        body = self.detector._extract_function_body(source, "withdraw")
        self.assertTrue(body.endswith("}"))
        self.assertIn("balances[msg.sender] = 0;", body)
        self.assertNotIn("function after", body)
        patterns = self.detector.code_encoder.summarize(body)
        self.assertIn("external_call_before_state_update", patterns)

    def test_nested_code_braces_are_balanced(self):
        source = '''contract Vault {
            struct Item { uint256 value; }
            function update() external {
                unchecked { balances[msg.sender] += 1; }
                assembly { let local := 1 }
                Item memory item = Item({value: 1});
                balances[msg.sender] = 2;
            }
            function after() external { balances[msg.sender] = 3; }
        }'''
        body = self.detector._extract_function_body(source, "update")
        self.assertIn("Item memory item", body)
        self.assertIn("balances[msg.sender] = 2;", body)
        self.assertNotIn("function after", body)


class NamedFunctionUnitTests(unittest.TestCase):
    def _units(self, source):
        extract = getattr(mismatch_detector, "extract_function_units", None)
        self.assertTrue(callable(extract), "function unit extractor is missing")
        return extract(source)

    def test_interface_declarations_are_bodyless_and_have_no_intent(self):
        source = '''interface IPair {
            /// @notice Read the reserve values from the pair.
            function getReserves() external view returns (uint112, uint112);
        }'''
        units = self._units(source)
        reserves = [unit for unit in units if unit.name == "getReserves"]
        self.assertEqual(len(reserves), 1)
        self.assertFalse(reserves[0].has_body)
        self.assertEqual(reserves[0].kind, "function")
        self.assertNotIn("getReserves", mismatch_detector.IntentExtractor().extract(source))
        self.assertEqual(
            mismatch_detector.IntentCodeMismatchDetector()._extract_function_body(source, "getReserves"),
            "",
        )

    def test_contract_definition_after_interface_declaration_uses_its_own_body(self):
        source = '''interface IPair {
            /// @notice Interface declaration intent.
            function getReserves() external view returns (uint112, uint112);
        }
        contract Pair {
            /// @notice Read the implemented reserve values.
            function getReserves() external view returns (uint112, uint112) {
                return (reserve0, reserve1);
            }
            function after() external { reserve0 = 1; }
        }'''
        reserves = [unit for unit in self._units(source) if unit.name == "getReserves"]
        self.assertEqual([unit.has_body for unit in reserves], [False, True])
        body = mismatch_detector.IntentCodeMismatchDetector()._extract_function_body(source, "getReserves")
        self.assertIn("return (reserve0, reserve1);", body)
        self.assertNotIn("function after", body)
        self.assertEqual(
            mismatch_detector.IntentExtractor().extract(source)["getReserves"],
            "@notice Read the implemented reserve values.",
        )

    def test_same_name_definitions_use_the_first_body_and_the_last_intent(self):
        """Current policy, unchanged from earlier versions: one report per name,
        built from the first body and the last definition's comment. Overloads
        and overrides are therefore not analysed separately; pinned so that any
        change to this policy is deliberate."""
        source = '''contract A {
            /// @notice First withdraw.
            function withdraw(uint256 amount) external { balances[msg.sender] -= amount; }
            /// @notice Second withdraw.
            function withdraw() external { total = 0; }
        }'''
        body = mismatch_detector.IntentCodeMismatchDetector()._extract_function_body(source, "withdraw")
        self.assertIn("balances[msg.sender] -= amount", body)
        self.assertNotIn("total = 0", body)
        self.assertEqual(
            mismatch_detector.IntentExtractor().extract(source)["withdraw"],
            "@notice Second withdraw.",
        )

    def test_abstract_virtual_declaration_is_not_an_implementation(self):
        source = '''abstract contract Base {
            /// @notice Update abstract state.
            function update(uint256 value) public virtual;
        }
        contract Derived {
            function other() external { value = 1; }
        }'''
        units = [unit for unit in self._units(source) if unit.name == "update"]
        self.assertEqual(len(units), 1)
        self.assertFalse(units[0].has_body)
        self.assertNotIn("update", mismatch_detector.IntentExtractor().extract(source))
        self.assertEqual(
            mismatch_detector.IntentCodeMismatchDetector()._extract_function_body(source, "update"),
            "",
        )


class SpecialFunctionTests(unittest.TestCase):
    def _units(self, source):
        extract=getattr(mismatch_detector, "extract_function_units", None)
        self.assertTrue(callable(extract), "function unit extractor is missing")
        return extract(source)

    def test_receive_fallback_and_legacy_fallback_are_units(self):
        source='''contract Wallet {
            mapping(address => uint256) balances;
            receive() external payable {
                (bool ok, ) = msg.sender.call{value: 1}("");
                balances[msg.sender] = 0;
            }
            fallback() external payable { balances[msg.sender] = 1; }
            function () payable { balances[msg.sender] = 2; }
            function helper() external { receive(); fallback(); }
            function (uint256) external callback;
        }'''
        units=self._units(source)
        special=[unit for unit in units if unit.kind in ("receive", "fallback")]
        self.assertEqual([unit.name for unit in special], ["receive", "fallback", "fallback"])
        self.assertTrue(all(unit.has_body for unit in special))
        receive_body=mismatch_detector.IntentCodeMismatchDetector()._extract_function_body(source, "receive")
        patterns=mismatch_detector.CodeEncoder().summarize(receive_body)
        self.assertIn("external_call_before_state_update", patterns)
        self.assertIn("missing_reentrancy_guard", patterns)
        intents=mismatch_detector.IntentExtractor().extract(source)
        self.assertIn("receive", intents)
        self.assertIn("fallback", intents)

    def test_calls_and_function_type_variables_are_not_units(self):
        source='''contract Wallet {
            function helper() external {
                receive();
                fallback();
                this.receive();
            }
            function (uint256) external callback;
        }'''
        units=self._units(source)
        special=[unit for unit in units if unit.kind in ("receive", "fallback")]
        self.assertEqual(special, [])
        self.assertEqual([unit.name for unit in units], ["helper"])

    def test_a_call_followed_by_a_control_block_is_not_a_special_function_unit(self):
        """Inside inline assembly a Yul function may be called receive; a call
        of it followed by an if block must not look like a receive definition
        (no external keyword between the parameters and the brace)."""
        source = '''contract C {
            function run() external {
                assembly {
                    /// @notice safe helper
                    function receive() -> r { r := 1 }
                    let x := receive()
                    if x { mstore(0, 0) }
                }
            }
        }'''
        units = self._units(source)
        self.assertEqual([unit.name for unit in units], ["run", "receive"])
        self.assertEqual(mismatch_detector.IntentExtractor().extract(source)["receive"], "@notice safe helper")

    def test_cli_reports_an_empty_scan_as_an_error(self):
        import subprocess
        import sys
        import tempfile
        from pathlib import Path

        repo=Path(__file__).resolve().parent
        with tempfile.TemporaryDirectory() as temp_dir:
            source_path=Path(temp_dir) / "empty.sol"
            source_path.write_text("contract Empty {}", encoding="utf-8")
            proc=subprocess.run(
                [sys.executable, str(repo / "helix_scan.py"), "--json", str(source_path)],
                cwd=repo, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(proc.stdout, "")
        self.assertTrue(proc.stderr.startswith("[ERROR]"), proc.stderr)
        self.assertIn("no analysable functions were found", proc.stderr.lower())
        self.assertIn("nothing was scanned", proc.stderr.lower())


class RiskPatternKeyTests(unittest.TestCase):
    def test_risk_pattern_keys_keep_the_required_order(self):
        expected = [
            "external_call_before_state_update",
            "missing_reentrancy_guard",
            "unchecked_arithmetic",
            "missing_access_control",
            "spot_price_oracle",
        ]
        self.assertEqual(list(mismatch_detector.CodeEncoder.RISK_PATTERNS), expected)


def _documented_functions(count):
    lines = ["contract Many {"]
    for index in range(count):
        lines.append(f"    /// @notice Update slot {index}")
        lines.append(f"    function update{index}(uint256 value) external {{ slots[{index}] = value; }}")
    lines.append("}")
    return "\n".join(lines)


def _best_time(action, source, repeats=3):
    """Best of a few timings of action(source). Each run gets a distinct copy of
    the source (a unique trailing comment), so the per-source cache cannot hide
    the work being measured."""
    import time

    best = None
    for run in range(repeats):
        fresh = f"{source}\n// timing run {run} {time.perf_counter_ns()}\n"
        started = time.perf_counter()
        action(fresh)
        elapsed = time.perf_counter() - started
        best = elapsed if best is None else min(best, elapsed)
    return best


class SummarizeGrowthTests(unittest.TestCase):
    def test_comment_inside_require_grows_linearly(self):
        """Masking turns a comment into spaces; the guard checks must stay linear
        on a long run of them (a comment inside require( is valid Solidity)."""
        summarize = mismatch_detector.CodeEncoder().summarize

        def build(kilobytes):
            comment = "/*" + "x" * (kilobytes * 1024) + "*/"
            return "function f() external { require(" + comment + " ok); balance = 0; }"

        small_time = _best_time(summarize, build(8), repeats=2)
        large_time = _best_time(summarize, build(32), repeats=2)
        self.assertLess(
            large_time, 10 * small_time + 0.05,
            f"8 KB comment {small_time:.3f}s, 32 KB comment {large_time:.3f}s",
        )

    def test_whitespace_run_after_require_grows_linearly(self):
        summarize = mismatch_detector.CodeEncoder().summarize

        def build(kilobytes):
            return "function f() external { require(" + " " * (kilobytes * 1024) + "ok); balance = 0; }"

        small_time = _best_time(summarize, build(8), repeats=2)
        large_time = _best_time(summarize, build(32), repeats=2)
        self.assertLess(
            large_time, 10 * small_time + 0.05,
            f"8 KB blanks {small_time:.3f}s, 32 KB blanks {large_time:.3f}s",
        )

    def test_locked_guard_spellings_are_still_recognised(self):
        summarize = mismatch_detector.CodeEncoder().summarize
        call = '(bool ok, ) = msg.sender.call{value: 1}(""); balances[msg.sender] = 0;'
        for guard in ("require(!_locked);", "require( ! _locked);", "require(_locked == false);",
                      "require(\n    !_locked\n);", "require(_locked);"):
            with self.subTest(guard=guard):
                patterns = summarize("function f() external { " + guard + " " + call + " }")
                self.assertNotIn("external_call_before_state_update", patterns)
        for not_guard in ("require(!unlocked);", "require(ok);", "require(!!_locked);"):
            with self.subTest(not_guard=not_guard):
                patterns = summarize("function f() external { " + not_guard + " " + call + " }")
                self.assertIn("external_call_before_state_update", patterns)


class IntentExtractionTests(unittest.TestCase):
    def test_intent_extraction_time_grows_linearly_with_function_count(self):
        extract = mismatch_detector.IntentExtractor().extract
        small, large = _documented_functions(500), _documented_functions(2000)
        intents = extract(large)
        self.assertEqual(len(intents), 2000)
        self.assertEqual(intents["update1999"], "@notice Update slot 1999")
        small_time = _best_time(extract, small)
        large_time = _best_time(extract, large)
        # Four times the input: about 4x when linear, 16x when quadratic.
        self.assertLess(
            large_time, 10 * small_time + 0.1,
            f"500 functions {small_time:.3f}s, 2000 functions {large_time:.3f}s",
        )

    def test_unit_extraction_grows_linearly_on_unterminated_headers(self):
        extract = mismatch_detector.extract_function_units
        for label, line in (
            ("named", "    function f{index}(uint256 a) external"),
            ("receive", "    receive() external payable ,"),
        ):
            with self.subTest(header=label):
                def build(count):
                    rows = ["contract Broken {"]
                    rows.extend(line.format(index=index) for index in range(count))
                    rows.append("}")
                    return "\n".join(rows)

                small_time = _best_time(extract, build(1000))
                large_time = _best_time(extract, build(4000))
                self.assertLess(
                    large_time, 10 * small_time + 0.05,
                    f"1000 headers {small_time:.3f}s, 4000 headers {large_time:.3f}s",
                )

    def test_body_lookup_per_function_grows_linearly(self):
        import time

        detector = mismatch_detector.IntentCodeMismatchDetector()

        def lookup_time(count):
            # A distinct text per call: the per-source cache is keyed by equal
            # text, and an equal but separate string would be compared in full
            # on every lookup, which is not what this test measures.
            source = _documented_functions(count) + f"\n// body lookup {time.perf_counter_ns()}\n"
            names = [unit.name for unit in mismatch_detector.extract_function_units(source)]
            detector._extract_function_body(source, names[0])  # parse once, outside the timing
            best = None
            for _ in range(3):
                started = time.perf_counter()
                for name in names:
                    detector._extract_function_body(source, name)
                elapsed = time.perf_counter() - started
                best = elapsed if best is None else min(best, elapsed)
            return best

        small_time, large_time = lookup_time(1000), lookup_time(4000)
        self.assertLess(
            large_time, 10 * small_time + 0.02,
            f"1000 lookups {small_time:.4f}s, 4000 lookups {large_time:.4f}s",
        )

    def test_doc_comment_block_matches_the_reference_expression(self):
        """The linear scan returns what the earlier regular expression captured
        (re.search on the gap), checked on deterministic random comment gaps
        that are small enough for the expression itself to stay fast."""
        import random
        import re

        reference = re.compile(
            r"((?:[ \t]*///[^\n]*\n|[ \t]*/\*[\s\S]*?\*/[ \t]*\n)*)[ \t]*\Z"
        )
        pieces = [
            "/// note\n", "    /// @notice Safe\n", "/* block */\n", "  /** @dev doc */\n",
            "/* a */ /* b */\n", "// plain\n", "\n", "    ", "\t", "/* multi\n line */\n",
            "/// with /* inside\n", "/* end */\r\n", "//// four\n", "/* x */ // y\n",
            "/* no newline */", " ",
        ]
        rng = random.Random(7)
        for _ in range(3000):
            gap = "\n" + "".join(rng.choice(pieces) for _ in range(rng.randint(0, 6)))
            gap += " " * rng.randint(0, 4)
            match = reference.search(gap)
            expected = match.group(1) if match else ""
            self.assertEqual(mismatch_detector._doc_comment_block(gap), expected, repr(gap))

    def test_doc_comment_needs_to_touch_the_definition(self):
        """A blank line between a doc comment and the definition ends the
        association, whatever the indentation or line ending. The earlier
        expression behaved this way for LF files; CRLF files must agree."""
        layouts = {
            "directly above, column 0": "/// @notice Safely withdraw\nfunction withdraw() external { b = 0; }\n",
            "directly above, indented": "contract A {\n    /// @notice Safely withdraw\n    function withdraw() external { b = 0; }\n}\n",
            "one blank line, column 0": "/// @notice Safely withdraw\n\nfunction withdraw() external { b = 0; }\n",
            "one blank line, indented": "contract A {\n    /// @notice Safely withdraw\n\n    function withdraw() external { b = 0; }\n}\n",
            "two blank lines, column 0": "/// @notice Safely withdraw\n\n\nfunction withdraw() external { b = 0; }\n",
        }
        expected = {
            "directly above, column 0": "@notice Safely withdraw",
            "directly above, indented": "@notice Safely withdraw",
            "one blank line, column 0": "withdraw",
            "one blank line, indented": "withdraw",
            "two blank lines, column 0": "withdraw",
        }
        extract = mismatch_detector.IntentExtractor().extract
        for name, source in layouts.items():
            for ending, text in (("LF", source), ("CRLF", source.replace("\n", "\r\n"))):
                with self.subTest(layout=name, line_ending=ending):
                    self.assertEqual(extract(text)["withdraw"], expected[name])

    def test_block_doc_comment_followed_by_blanks_before_the_line_break(self):
        for blanks in (" ", "\t", "  \t "):
            with self.subTest(blanks=repr(blanks)):
                source = (
                    "contract A {\n"
                    f"    /** @notice Safely withdraw your balance */{blanks}\n"
                    "    function withdraw() external { b = 0; }\n"
                    "}\n"
                )
                intent = mismatch_detector.IntentExtractor().extract(source)["withdraw"]
                self.assertIn("Safely withdraw your balance", intent)

    def test_untagged_comment_intent_is_cut_at_200_characters(self):
        words = " ".join(f"w{index}" for index in range(100))
        source = f"contract A {{\n    /* {words} */\n    function f() external {{ b = 0; }}\n}}\n"
        intent = mismatch_detector.IntentExtractor().extract(source)["f"]
        self.assertEqual(len(intent), 200)
        self.assertTrue(words.startswith(intent))

    def test_a_header_without_a_body_does_not_make_the_next_header_a_unit(self):
        source = "contract C { function a() function b() } }"
        names = [unit.name for unit in mismatch_detector.extract_function_units(source)]
        self.assertEqual(names, [])

    def test_comment_run_time_grows_linearly_with_its_length(self):
        extract = mismatch_detector.IntentExtractor().extract

        def build(lines_per_gap):
            rows = ["contract Notes {"]
            for index in range(20):
                rows.extend(f"    /* retired helper {index}.{line} */" for line in range(lines_per_gap))
                rows.append("    // lint-disable-next-line")
                rows.append(f"    function update{index}(uint256 value) external {{ slot = value; }}")
            rows.append("}")
            return "\n".join(rows)

        times = {lines: _best_time(extract, build(lines)) for lines in (20, 40, 80)}
        # Four times the comment lines: about 4x when linear, 16x when quadratic.
        self.assertLess(
            times[80], 8 * times[20] + 0.01,
            "comment lines 20/40/80: " + ", ".join(f"{times[k]:.4f}s" for k in (20, 40, 80)),
        )

    def test_many_comment_lines_before_a_function_stay_fast(self):
        import time

        lines = ["contract Notes {"]
        lines.extend(f"    /* retired helper {index} */" for index in range(20))
        lines.append("    // lint-disable-next-line")
        lines.append("    function update(uint256 value) external { slot = value; }")
        lines.append("}")
        source = "\n".join(lines)
        started = time.perf_counter()
        intents = mismatch_detector.IntentExtractor().extract(source)
        elapsed = time.perf_counter() - started
        self.assertIn("update", intents)
        self.assertLess(elapsed, 2.0, f"20 block-comment lines took {elapsed:.1f}s")

    def test_block_natspec_followed_by_crlf_is_not_associated_as_before(self):
        """Unchanged behaviour, pinned on purpose: a block comment whose line
        ends in CR LF is not taken as documentation when the text is passed to
        the API as is (the CLI reads files in text mode, which turns CR LF into
        LF first). Associating it would change the intent text, and with it the
        score, of CRLF sources compared with earlier versions."""
        source = (
            "contract Vault {\r\n"
            "    /** @notice Safely withdraw funds */\r\n"
            "    function withdraw() external { balance = 0; }\r\n"
            "}\r\n"
        )
        extract = mismatch_detector.IntentExtractor().extract
        self.assertEqual(extract(source)["withdraw"], "withdraw")
        self.assertEqual(extract(source.replace("\r\n", "\n"))["withdraw"], "Safely withdraw funds */")
        triple_slash = source.replace("/** @notice Safely withdraw funds */", "/// @notice Safely withdraw funds")
        self.assertEqual(extract(triple_slash)["withdraw"], "@notice Safely withdraw funds")

    def test_undocumented_function_intent_is_its_name(self):
        source = '''contract Plain {
            function _withdraw_all() external { total = 0; }
            function getPrice() external view returns (uint256) { return price; }
        }'''
        intents = mismatch_detector.IntentExtractor().extract(source)
        self.assertEqual(intents["_withdraw_all"], " withdraw all")
        self.assertEqual(intents["getPrice"], "getPrice")

    def test_comment_like_text_inside_a_string_does_not_become_intent(self):
        source = '''contract Labels {
            string public label = "x /// not documentation";
            function update(uint256 value) external { slot = value; }
        }'''
        self.assertEqual(mismatch_detector.IntentExtractor().extract(source)["update"], "update")

if __name__ == "__main__":
    unittest.main()