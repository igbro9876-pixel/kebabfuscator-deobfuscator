#!/usr/bin/env python3
"""Statically deobfuscate Kebabfuscator v1 Lua files.

The decoder recovers the embedded string tables without executing the Lua
input, then replaces each encrypted string-table loop with plaintext Lua
assignments. A directory can be supplied to process all Lua files beneath it.
"""

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import keb
import names

SIGNATURE = ('-- oh my days deobfuscated this obfuscator with this special '
             'deobfuscator so insane\n')
PASS4_HEADER = SIGNATURE


class DeobfuscationError(ValueError):
    """Raised when a source file is not a supported or complete input."""


@dataclass
class DeobfuscationResult:
    source: str
    blobs: int
    strings: int


def lift_source(source: str) -> str:
    """Pass 4: lift the recovered VM bytecode back to readable Lua source.

    Runs the full static pipeline (constants -> loader -> VM assembly -> lift)
    and returns the main chunk's clean Lua equivalent.  Raises
    DeobfuscationError when the file is not a supported Kebabfuscator v1 VM
    image or the lift cannot be completed.
    """
    try:
        source, _roles = names.canonicalize(source)
        import lift as _lift
        opcode_map = Path(__file__).resolve().with_name('opcode_map.txt')
        lifted, _data = _lift.lift_source(str(source), str(opcode_map))
    except DeobfuscationError:
        raise
    except Exception as error:                      # noqa: BLE001 - CLI report
        raise DeobfuscationError('lift failed: %s' % error) from error
    if not lifted.get('main'):
        raise DeobfuscationError('no entry chunk found in the VM image')
    return PASS4_HEADER + lifted['main'] + '\n'


def antitamper_source(source: str) -> str:
    """Extract the lifted entry chunk's anti-tamper closure as a Lua module."""
    lifted = lift_source(source)
    anchor = re.search(r'\blocal\s+b\s*=\s*function\s*\(', lifted)
    if anchor is None:
        raise DeobfuscationError('could not find the anti-tamper closure')

    tokens = re.finditer(
        r'--[^\r\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|'
        r'[A-Za-z_][A-Za-z0-9_]*|.',
        lifted[anchor.start():],
        re.DOTALL,
    )
    depth = 0
    close_end = None
    for token in tokens:
        value = token.group(0)
        if value.isspace() or value.startswith('--') \
                or value[0] in ('"', "'"):
            continue
        if value in ('function', 'if', 'do', 'repeat'):
            depth += 1
        elif value in ('end', 'until'):
            depth -= 1
            if depth == 0:
                close_end = anchor.start() + token.end()
                break
    if close_end is None:
        raise DeobfuscationError('anti-tamper closure is unterminated')

    closure = lifted[anchor.start():close_end]
    closure = re.sub(r'\blocal\s+b\s*=', 'local antitamper =', closure, count=1)
    return PASS4_HEADER + closure + '\nreturn antitamper\n'


def lua_quote(value: str) -> str:
    """Quote bytes as a portable Lua string literal."""
    result = ['"']
    for char in value:
        code = ord(char)
        if char == '"':
            result.append('\\"')
        elif char == '\\':
            result.append('\\\\')
        elif char == '\n':
            result.append('\\n')
        elif char == '\r':
            result.append('\\r')
        elif char == '\t':
            result.append('\\t')
        elif code < 32 or code > 126:
            result.append('\\%03d' % code)
        else:
            result.append(char)
    result.append('"')
    return ''.join(result)


def _matching_paren(source: str, opening: int) -> int:
    """Return the closing parenthesis matching ``source[opening]``."""
    if opening >= len(source) or source[opening] != '(':
        return -1
    depth = 0
    index = opening
    while index < len(source):
        char = source[index]
        if char in ('"', "'"):
            quote = char
            index += 1
            while index < len(source):
                if source[index] == '\\':
                    index += 2
                elif source[index] == quote:
                    break
                else:
                    index += 1
        elif char == '(':
            depth += 1
        elif char == ')':
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return -1


def _loop_replacement(source: str, anchor: re.Match, blob: keb.Blob,
                      strings: Dict[int, str]) -> Tuple[int, int, str]:
    """Build a plaintext replacement for one K[IDX[VAR]] = Nx58(...) loop."""
    variable = anchor.group('var')
    index_name = blob.idx_var
    loop_starts = list(re.finditer(
        r'\bfor\s+' + re.escape(variable) + r'\s*=', source[:anchor.start()]
    ))
    if not loop_starts:
        raise DeobfuscationError(
            'decode assignment for %s has no matching for-loop' % blob.data_var
        )
    loop_start = loop_starts[-1].start()
    header = re.match(
        r'\bfor\s+' + re.escape(variable) +
        r'\s*=\s*.*?,\s*#\s*' + re.escape(index_name) +
        r'\s*,.*?\s+do\b',
        source[loop_start:anchor.start()],
        re.DOTALL,
    )
    if header is None:
        raise DeobfuscationError(
            'could not parse the decode loop for %s' % blob.data_var
        )

    call_open = source.find('(', anchor.start())
    call_close = _matching_paren(source, call_open)
    if call_close < 0:
        raise DeobfuscationError(
            'unterminated Nx58 call for %s' % blob.data_var
        )
    end_match = re.match(r'\s*end\b', source[call_close + 1:])
    if end_match is None:
        raise DeobfuscationError(
            'decode loop for %s contains unsupported extra statements'
            % blob.data_var
        )
    loop_end = call_close + 1 + end_match.end()

    line_start = source.rfind('\n', 0, loop_start) + 1
    prefix = source[line_start:loop_start]
    indent = prefix if prefix.isspace() else ''
    statements = [
        '%sK[%d] = %s' % (indent, key, lua_quote(value))
        for key, value in sorted(strings.items())
    ]
    replacement = '\n'.join(statements)
    return loop_start, loop_end, replacement


def _declaration_spans(source: str, variable: str,
                       function: str) -> List[Tuple[int, int]]:
    """Locate local payload/index declarations for an encrypted blob."""
    pattern = re.compile(
        r'\blocal\s+' + re.escape(variable) + r'\s*=\s*' +
        re.escape(function) + r'\s*\('
    )
    spans = []
    for match in pattern.finditer(source):
        opening = source.find('(', match.start(), match.end())
        closing = _matching_paren(source, opening)
        if closing < 0:
            raise DeobfuscationError(
                'unterminated %s declaration for %s' % (function, variable)
            )
        spans.append((match.start(), closing + 1))
    return spans


def deobfuscate_source(source: str) -> DeobfuscationResult:
    """Recover and inline every supported Kebabfuscator v1 string table."""
    source, _roles = names.canonicalize(source)
    constants = keb.Constants(source)
    constants.extract_jm()
    if len([name for name in constants.values if re.fullmatch(r'jm\d+', name)]) < 32:
        raise DeobfuscationError('could not recover all 32 Kebabfuscator seed constants')

    try:
        alphabet = constants.build_er60()
        km2 = constants.build_km2()
        c864 = constants.build_c864()
    except (KeyError, ValueError, IndexError) as error:
        raise DeobfuscationError('could not reconstruct the string decryption keys: %s'
                                 % error) from error

    tables_parser = keb.StringTables(source)
    blobs = tables_parser.find_blobs(constants.ev)
    if not blobs:
        raise DeobfuscationError(
            'no supported oE55/CA56/Nx58 string tables were found'
        )

    try:
        tables = tables_parser.decode_all(
            constants.values, alphabet, km2, c864, blobs
        )
    except (KeyError, ValueError, IndexError, TypeError) as error:
        raise DeobfuscationError('failed to decrypt the string tables: %s'
                                 % error) from error
    replacements: List[Tuple[int, int, str]] = []
    replaced_blobs = set()
    for anchor in keb.LOOP_ANCHOR_RE.finditer(source):
        pair = next(
            (blob for blob in blobs
             if blob.idx_var == anchor.group('idx')
             and blob.data_var == anchor.group('data')),
            None,
        )
        if pair is None:
            continue
        replacements.append(_loop_replacement(
            source, anchor, pair, tables.get(pair.idx_var, {})
        ))
        replaced_blobs.add((pair.data_var, pair.idx_var))

    expected = {(blob.data_var, blob.idx_var) for blob in blobs}
    if replaced_blobs != expected:
        missing = ', '.join(data for data, _ in sorted(expected - replaced_blobs))
        raise DeobfuscationError(
            'could not replace every encrypted string table (missing loops: %s)'
            % missing
        )

    for blob in blobs:
        replacements.extend(
            (start, end, '')
            for start, end in _declaration_spans(source, blob.data_var, 'oE55')
        )
        replacements.extend(
            (start, end, '')
            for start, end in _declaration_spans(source, blob.idx_var, 'CA56')
        )

    result = source
    for start, end, replacement in sorted(replacements, reverse=True):
        result = result[:start] + replacement + result[end:]

    decoded_count = sum(len(table) for table in tables.values())
    header = SIGNATURE
    return DeobfuscationResult(header + result, len(blobs), decoded_count)


def _process_file(input_path: Path, output_path: Path, lift: bool = False,
                  antitamper: bool = False) \
        -> DeobfuscationResult:
    if input_path.resolve() == output_path.resolve():
        raise DeobfuscationError('output file must differ from input file')
    try:
        source = input_path.read_text(encoding='utf-8-sig')
    except UnicodeError as error:
        raise DeobfuscationError('input is not valid UTF-8: %s' % error) from error
    if antitamper:
        text = antitamper_source(source)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(text, encoding='utf-8')
        result = deobfuscate_source(source)
        result.source = text
        return result
    if lift:
        text = lift_source(source)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(text, encoding='utf-8')
        # counts are taken from the string tables for a consistent report
        result = deobfuscate_source(source)
        result.source = text
        return result
    result = deobfuscate_source(source)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(result.source, encoding='utf-8')
    return result


def _lua_files(directory: Path, recursive: bool, output_dir: Path) -> List[Path]:
    candidates = directory.rglob('*.lua') if recursive else directory.glob('*.lua')
    files = []
    output_root = output_dir.resolve()
    for path in sorted(candidates):
        try:
            path.resolve().relative_to(output_root)
        except ValueError:
            files.append(path)
    return files


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description='Statically deobfuscate Kebabfuscator v1 Lua files.'
    )
    parser.add_argument('input', type=Path, help='Lua file or directory of Lua files')
    parser.add_argument(
        '-o', '--output', type=Path,
        help='output Lua file, or output directory when input is a directory',
    )
    parser.add_argument(
        '--no-recursive', action='store_true',
        help='do not search subdirectories when input is a directory',
    )
    output_mode = parser.add_mutually_exclusive_group()
    output_mode.add_argument(
        '--lift', action='store_true',
        help='emit fully lifted Lua (pass 4) instead of the '
             'string-table-recovered form',
    )
    output_mode.add_argument(
        '--antitamper', action='store_true',
        help='extract the anti-tamper closure as a standalone Lua module',
    )
    args = parser.parse_args(argv)

    input_path = args.input
    if not input_path.exists():
        print('error: input does not exist: %s' % input_path, file=sys.stderr)
        return 2

    if input_path.is_file():
        suffix = ('.antitamper.lua' if args.antitamper else
                  '.lifted.lua' if args.lift else '.deobfuscated.lua')
        output_path = args.output or input_path.with_name(input_path.stem
                                                          + suffix)
        try:
            result = _process_file(input_path, output_path, lift=args.lift,
                                   antitamper=args.antitamper)
        except (OSError, ValueError, KeyError) as error:
            print('error: %s: %s' % (input_path, error), file=sys.stderr)
            return 1
        print('Deobfuscated %s -> %s (%d blobs, %d strings)' %
              (input_path, output_path, result.blobs, result.strings))
        return 0

    if not input_path.is_dir():
        print('error: input must be a Lua file or directory', file=sys.stderr)
        return 2

    resolved_input = input_path.resolve()
    default_suffix = ('.antitamper' if args.antitamper else
                      '.lifted' if args.lift else '.deobfuscated')
    output_dir = args.output or resolved_input.with_name(
        resolved_input.name + default_suffix
    )
    if output_dir.resolve() == resolved_input:
        print('error: output directory must differ from input directory',
              file=sys.stderr)
        return 2
    files = _lua_files(input_path, not args.no_recursive, output_dir)
    if not files:
        print('error: no Lua files found in %s' % input_path, file=sys.stderr)
        return 1

    failed = 0
    for file_path in files:
        # directory mode keeps the original file name inside the output tree
        destination = output_dir / file_path.relative_to(input_path)
        try:
            result = _process_file(file_path, destination, lift=args.lift,
                                   antitamper=args.antitamper)
        except (OSError, ValueError, KeyError) as error:
            failed += 1
            print('error: %s: %s' % (file_path, error), file=sys.stderr)
            continue
        print('Deobfuscated %s -> %s (%d blobs, %d strings)' %
              (file_path, destination, result.blobs, result.strings))
    if failed:
        print('%d of %d files failed' % (failed, len(files)), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
