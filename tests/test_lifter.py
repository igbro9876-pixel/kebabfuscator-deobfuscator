"""Regression tests for the Kebabfuscator v1 lift pass (readable Lua output)."""

import re
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SAMPLES = PROJECT_ROOT / 'samples'
sys.path.insert(0, str(PROJECT_ROOT / 'deobfuscator'))

import lift
import vm
from deobfuscator import lift_source as deobfuscator_lift_source


def lifted_main(filename='sample.lua'):
    data = vm.assemble((SAMPLES / filename).read_text(encoding='utf-8-sig'))
    return lift.Lifter(data).lift().get('main', '')


class LifterTests(unittest.TestCase):
    """The lift must stay semantic-neutral and read like human source."""

    def test_output_has_no_filler_local_names(self):
        main = lifted_main()
        # every local keeps either an evidence name or the stable x<n> form
        self.assertIsNone(
            re.search(r'^\s*local v[0-9]+\b', main, re.MULTILINE),
            'filler v-name locals survived the cleanup passes')

    def test_output_keeps_entry_behaviour(self):
        main = lifted_main()
        self.assertIn('print("hi")', main)
        self.assertNotIn('UNHANDLED', main)
        self.assertNotIn('unhandled op', main)
        # the guard chain and its consumer survive as plain Lua
        self.assertIn('return true', main)
        self.assertIn('return false', main)
        self.assertIn('local a = {}', main)
        self.assertIn('a[1] = b', main)

    def test_guards_render_as_single_conditions(self):
        main = lifted_main()
        # or-chains fold into one `if`, not nested recheck branches
        self.assertIn('if typeof == nil or typeof(game) ~= "Instance"', main)
        self.assertTrue(
            re.search(r'if Instance == nil or task == nil', main),
            'the service availability guard lost its folded form')

    def test_single_use_closures_inline_into_calls(self):
        main = lifted_main()
        # `local ok = pcall(function() ... end)` - not pcall(xN)
        self.assertTrue(
            re.search(r'pcall\(function\(\)', main),
            'single-use closures did not inline into their call')

    def test_literals_lift_to_luau_dialect(self):
        main = lifted_main()
        self.assertIn('(2.5 // 1)', main)   # Luau integer division, verbatim
        self.assertNotRegex(main, r'-- unhandled unop o=')
        self.assertNotRegex(main, r'K\[')   # no raw K table references

    def test_randomized_image_lifts_with_its_dispatch_and_loop(self):
        source = (SAMPLES / 'samplekebab.txt_obf (2).lua').read_text(
            encoding='utf-8-sig'
        )
        output = deobfuscator_lift_source(source)
        self.assertTrue(output.startswith(
            '-- oh my days deobfuscated this obfuscator with this special '
            'deobfuscator so insane\n'
        ))
        self.assertIn('while true do', output)
        self.assertNotRegex(output, r'^\s*local v[0-9]+\b')
        self.assertNotIn('UNHANDLED', output)


if __name__ == '__main__':
    unittest.main()
