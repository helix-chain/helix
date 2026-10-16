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
        self.assertIn("second", mask('value = "unterminated\nsecond line;'))
        open_block = 'value; /* unfinished\nstring " and braces }'
        masked_block = mask(open_block)
        self.assertEqual(len(masked_block), len(open_block))
        self.assertTrue(all(char in (" ", "\n") for char in masked_block[open_block.index("/*"):]))
        self.assertEqual(mask(masked_block), masked_block)


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


if __name__ == "__main__":
    unittest.main()