"""Regression tests for the Kebabfuscator v1 command-line deobfuscator."""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SAMPLES = PROJECT_ROOT / 'samples'
sys.path.insert(0, str(PROJECT_ROOT / 'deobfuscator'))

import keb
import names
from deobfuscator import (antitamper_source, deobfuscate_source, lua_quote)


class DeobfuscatorTests(unittest.TestCase):
    def test_compact_and_formatted_sources_decode_all_string_tables(self):
        outputs = []
        for filename in ('sample.lua', 'sample beautified.lua'):
            with self.subTest(filename=filename):
                source = (SAMPLES / filename).read_text(encoding='utf-8-sig')
                result = deobfuscate_source(source)
                self.assertEqual(result.blobs, 14)
                self.assertEqual(result.strings, 287)
                self.assertIn('K[2] = "print"', result.source)
                self.assertIn('K[3] = "hi"', result.source)
                constants = keb.Constants(source)
                constants.extract_jm()
                blobs = keb.StringTables(source).find_blobs(constants.ev)
                for blob in blobs:
                    self.assertNotIn(blob.payload, result.source)
                    self.assertNotIn(blob.index, result.source)
                self.assertNotRegex(
                    result.source,
                    r'K\s*\[\s*\w+\s*\[\s*\w+\s*\]\s*\]\s*=\s*Nx58\s*\(',
                )
                outputs.append((result.blobs, result.strings))
        self.assertEqual(outputs[0], outputs[1])

    def test_lua_strings_are_escaped_without_changing_content(self):
        self.assertEqual(lua_quote('A\n"\\\x01'), '"A\\n\\"\\\\\\001"')

    def test_identifier_renaming_skips_lua_comments_and_long_strings(self):
        source = (
            'local jm1 = 1 -- jm1 stays in comment\n'
            'local quoted = "jm1"\n'
            'local long = [==[jm1 ]=] remains text]==]\n'
            '--[=[jm1 stays in long comment]=]\n'
        )
        renamed = names._rename_outside_strings(source, {'jm1': 'seed'})
        self.assertIn('local seed = 1 -- jm1 stays in comment', renamed)
        self.assertIn('local quoted = "jm1"', renamed)
        self.assertIn('[==[jm1 ]=] remains text]==]', renamed)
        self.assertIn('--[=[jm1 stays in long comment]=]', renamed)
        stripped = names._strip_strings(source)
        self.assertNotIn('remains text', stripped)
        self.assertNotIn('stays in long comment', stripped)

    def test_cli_refuses_to_overwrite_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / 'sample.lua'
            original = (SAMPLES / 'sample.lua').read_bytes()
            source.write_bytes(original)
            completed = subprocess.run(
                [
                    sys.executable,
                    str(PROJECT_ROOT / 'deobfuscator' / 'deobfuscator.py'),
                    str(source),
                    '--output',
                    str(source),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn('output file must differ', completed.stderr)
            self.assertEqual(source.read_bytes(), original)

    def test_randomized_identifiers_decode_all_string_tables(self):
        source = (SAMPLES / 'samplekebab.txt_obf (2).lua').read_text(
            encoding='utf-8-sig'
        )
        result = deobfuscate_source(source)
        self.assertEqual((result.blobs, result.strings), (15, 327))
        self.assertTrue(
            result.source.startswith(
                '-- oh my days deobfuscated this obfuscator with this special '
                'deobfuscator so insane\n'
            )
        )
        self.assertNotRegex(
            result.source,
            r'K\s*\[\s*\w+\s*\[\s*\w+\s*\]\s*\]\s*=\s*Nx58\s*\(',
        )

    def test_antitamper_mode_extracts_only_the_guard_closure(self):
        source = (SAMPLES / 'samplekebab.txt_obf (2).lua').read_text(
            encoding='utf-8-sig'
        )
        output = antitamper_source(source)
        self.assertTrue(output.startswith(
            '-- oh my days deobfuscated this obfuscator with this special '
            'deobfuscator so insane\n'
        ))
        self.assertIn('local antitamper = function()', output)
        self.assertIn('_G.lune ~= nil', output)
        self.assertIn('game:GetService("RunService"):IsRunning()', output)
        self.assertTrue(output.endswith('return antitamper\n'))
        self.assertNotIn('SendAsync("67")', output)

    def test_directory_cli_writes_deobfuscated_lua(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            input_dir = root / 'input'
            output_dir = root / 'output'
            input_dir.mkdir()
            (input_dir / 'sample.lua').write_bytes(
                (SAMPLES / 'sample.lua').read_bytes()
            )
            completed = subprocess.run(
                [
                    sys.executable,
                    str(PROJECT_ROOT / 'deobfuscator' / 'deobfuscator.py'),
                    str(input_dir),
                    '--output',
                    str(output_dir),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            output = (output_dir / 'sample.lua').read_text(encoding='utf-8')
            self.assertIn('K[2] = "print"', output)
            self.assertIn('287 strings', completed.stdout)


if __name__ == '__main__':
    unittest.main()
