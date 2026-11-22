"""Kebabfuscator v1 static deobfuscator core.

Implements the constant extraction and the crypto primitives
(``oE55`` base-85 decoder, ``Nx58`` stream cipher, ``CA56`` wrapper)
in pure Python so the obfuscated source can be decoded statically.
"""

import re
import sys
from typing import Any, Dict, List, Optional, Tuple

import names
from newdeob import (  # noqa: F401  (re-exported for convenience)
    LuaExpressionError,
    LuaExpressionEvaluator,
    LuaSourceParser,
)

MASK32 = 0xFFFFFFFF


def band(a: int, b: int) -> int:
    return a & b


def bxor(a: int, b: int) -> int:
    return (a ^ b) & MASK32


def rshift(a: int, b: int) -> int:
    return (a & MASK32) >> (b & 31)


def lshift(a: int, b: int) -> int:
    return (a << (b & 31)) & MASK32


# ---------------------------------------------------------------------------
# Expression evaluation over the raw (single-line) obfuscated source
# ---------------------------------------------------------------------------

class SourceScanner:
    """Locates ``local NAME = <value>`` statements in the flattened source."""

    LOCAL_RE = re.compile(r'local\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?!=)')

    def __init__(self, source: str):
        self.source = source
        self.parser = LuaSourceParser(source)

    def value_end(self, start: int) -> int:
        """Return the offset just past the value expression starting at ``start``."""
        src = self.source
        i = start
        depth = 0
        n = len(src)
        while i < n:
            ch = src[i]
            if ch in '"\'':
                i += 1
                while i < n:
                    if src[i] == '\\':
                        i += 2
                        continue
                    if src[i] == ch:
                        break
                    i += 1
                i += 1
                continue
            if ch in '([{':
                depth += 1
            elif ch in ')]}':
                depth -= 1
                if depth == 0:
                    return i + 1
            elif depth == 0 and src.startswith('local ', i):
                return i
            i += 1
        return i

    def find(self, name: str) -> Optional[int]:
        """Offset of the value of the *last* ``local <name> =`` statement."""
        best = None
        for m in self.LOCAL_RE.finditer(self.source):
            if m.group(1) == name:
                best = m.end()
        return best

    def read_expression(self, name: str) -> Optional[str]:
        off = self.find(name)
        if off is None:
            return None
        end = self.value_end(off)
        return self.source[off:end].strip()

    def read_table(self, name: str) -> Optional[List[str]]:
        off = self.find(name)
        if off is None:
            return None
        i = off
        while i < len(self.source) and self.source[i] in ' \t\r\n':
            i += 1
        if i >= len(self.source) or self.source[i] != '{':
            return None
        self.parser.pos = i
        body = self.parser.read_balanced()
        return self.parser.split_top_level(body)

    def read_string_literal(self, name: str) -> Optional[str]:
        """Read a quoted Lua string literal assigned to ``name``."""
        off = self.find(name)
        if off is None:
            return None
        i = off
        while i < len(self.source) and self.source[i] in ' \t\r\n':
            i += 1
        if i >= len(self.source) or self.source[i] not in '"\'':
            return None
        self.parser.pos = i + 1
        return self.parser.read_string()

    def read_call_string(self, name: str, func: str) -> Optional[str]:
        """Read the first string argument of ``local <name> = <func>("...")``."""
        off = self.find(name)
        if off is None:
            return None
        i = self.source.find('(', off)
        if i == -1:
            return None
        i += 1
        while i < len(self.source) and self.source[i] in ' \t\r\n':
            i += 1
        if i >= len(self.source) or self.source[i] not in '"\'':
            return None
        self.parser.pos = i + 1
        return self.parser.read_string()


# ---------------------------------------------------------------------------
# Constant extraction
# ---------------------------------------------------------------------------

JM_NAMES = ['jm%d' % i for i in range(1, 33)]


class Constants:
    """Holds every concrete value recovered from the obfuscated source."""

    def __init__(self, source: str):
        self.source, self.roles = names.canonicalize(source)
        self.scanner = SourceScanner(self.source)
        self.ev = LuaExpressionEvaluator()
        self.values: Dict[str, Any] = {}

    # -- helpers -------------------------------------------------------------

    def eval_expr(self, expr: str) -> Any:
        return self.ev.try_evaluate(expr, None)

    def eval_at(self, offset: int) -> Any:
        end = self.scanner.value_end(offset)
        return self.eval_expr(self.source[offset:end].strip())

    def register(self, name: str, value: Any) -> None:
        self.values[name] = value
        self.ev.register(name, value)

    def get(self, name: str, default: Any = None) -> Any:
        return self.values.get(name, default)

    # -- passes --------------------------------------------------------------

    def extract_jm(self) -> Dict[str, Any]:
        """Evaluate the 32 ``jm*`` seed constants."""
        for name in JM_NAMES:
            expr = self.scanner.read_expression(name)
            if expr is None:
                continue
            value = self.eval_expr(expr)
            if value is not None:
                self.register(name, value)
        if 'local function Nx58(' in self.source:
            self.values['_nx58_slots'] = self.build_nx58_slots()
        if 'local function CA56(' in self.source:
            self.values['_ca56_weights'] = self.build_ca56_weights()
        return dict(self.values)

    def extract_scalars(self, names: List[str]) -> Dict[str, Any]:
        """Evaluate simple scalar assignments (``local X = <expr>``)."""
        for name in names:
            expr = self.scanner.read_expression(name)
            if expr is None:
                continue
            value = self.eval_expr(expr)
            if value is not None:
                self.register(name, value)
        return dict(self.values)

    # -- alphabet / key material --------------------------------------------

    def build_er60(self) -> Dict[str, int]:
        """Rebuild the custom base-85 alphabet table ``Er60``."""
        string_name = 'jB59'
        ranges = re.finditer(
            r'for\s+(\w+)\s*=\s*\(([^()]*)\)\s*,\s*\(([^()]*)\)'
            r'\s+do\s+' + re.escape(string_name) + r'\s*=\s*'
            + re.escape(string_name)
            + r'\s*\.\.\s*string\.char\(\1\)\s*end',
            self.source,
        )
        codes = []
        for match in ranges:
            start = self.eval_expr(match.group(2))
            end = self.eval_expr(match.group(3))
            if start is None or end is None:
                raise ValueError('cannot evaluate alphabet range')
            codes.extend(range(int(start), int(end) + 1))
        extra = self.scanner.read_table('yL61')
        if extra is None:
            raise ValueError('yL61 alphabet codes not found')
        codes.extend(char_codes(extra, self.ev))

        m = re.search(
            r'Er60\s*\[\s*' + re.escape(string_name)
            + r'\s*:\s*sub\s*\(\s*\w+\s*,\s*\w+\s*\)\s*\]'
            r'\s*=\s*\w+\s*-\s*\(([^()]*)\)',
            self.source,
        )
        if m is None:
            raise ValueError('Er60 alphabet offset not found')
        offset = self.eval_expr(m.group(1))
        if offset is None:
            raise ValueError('cannot evaluate Er60 alphabet offset')
        return {chr(code): index - int(offset)
                for index, code in enumerate(codes, start=1)}

    def build_wx1(self) -> bytes:
        """Rebuild the ``Wx1`` key seed (a ``string.char(...)`` call)."""
        raw = self.scanner.read_expression('Wx1')
        if raw is None:
            raise ValueError('Wx1 not found')
        inner = raw[raw.index('(') + 1:raw.rindex(')')]
        parts = self.scanner.parser.split_top_level(inner)
        codes = char_codes(parts, self.ev)
        return bytes(code & 0xFF for code in codes)

    def build_km2(self) -> int:
        """Evaluate the source's chained-byte-key loop."""
        m = re.search(
            r'local\s+Km2\s*=\s*\(([^()]*)\)\s+for\s+(\w+)\s*=\s*'
            r'\(([^()]*)\)\s*,\s*\(([^()]*)\)\s*,\s*\(([^()]*)\)\s+'
            r'do\s+Km2\s*=\s*Km2\s*\*\s*\(([^()]*)\)\s*\+\s*'
            r'\(\s*string\.byte\s*\(\s*Wx1\s*,\s*\2\s*\+\s*'
            r'\(([^()]*)\)\s*\)\s*==\s*\(([^()]*)\)\s+and\s+'
            r'\(([^()]*)\)\s+or\s+\(([^()]*)\)\s*\)\s*end',
            self.source,
        )
        if m is None:
            raise ValueError('Km2 derivation loop not found')
        wx1 = self.build_wx1()
        values = [self.eval_expr(m.group(i))
                  for i in (1, 3, 4, 5, 6, 7, 8, 9, 10)]
        if any(value is None for value in values):
            raise ValueError('cannot evaluate Km2 derivation loop')
        (initial, start, end, step, multiplier, byte_offset, target,
         when_equal, otherwise) = values
        km2 = int(initial)
        for index in range(int(start), int(end) + 1, int(step)):
            byte_index = index + int(byte_offset)
            if byte_index < 1 or byte_index > len(wx1):
                raise ValueError('Km2 loop reads Wx1[%d] outside the key' %
                                 byte_index)
            byte = wx1[byte_index - 1]
            km2 = km2 * int(multiplier) + (
                int(when_equal) if byte == int(target) else int(otherwise)
            )
        return km2

    def build_tk6(self) -> Dict[str, int]:
        """Rebuild the ``tK6`` character table from the ``P94`` table."""
        codes = char_codes(self.scanner.read_table('P94') or [], self.ev)
        text = ''.join(chr(code & 0xFF) for code in codes)
        m = re.search(
            r'tK6\s*\[\s*string\.sub\s*\(\s*kP5\s*,\s*\w+\s*,\s*'
            r'\w+\s*\)\s*\]\s*=\s*\w+\s*-\s*\(([^()]*)\)',
            self.source,
        )
        if m is None:
            raise ValueError('tK6 character-table offset not found')
        offset = self.eval_expr(m.group(1))
        if offset is None:
            raise ValueError('cannot evaluate tK6 character-table offset')
        return {ch: index - int(offset) for index, ch in enumerate(text, start=1)}

    def build_c864(self) -> int:
        """Derive the ``c864`` XOR key used by the string blobs."""
        expr = self.scanner.read_expression('c864')
        if expr is None:
            raise ValueError('c864 not found')
        value = self.eval_expr(expr)
        if value is None:
            raise ValueError('cannot evaluate c864')
        return int(value)

    def build_qf16(self) -> int:
        """Derive the ``qf16`` constant (the VM instruction seed)."""
        m = re.search(
            r'local\s+qf16\s*=\s*bit32\.band\s*\(\s*bit32\.bxor\s*'
            r'\(\s*(\w+)\s*\*\s*\(([^()]*)\)\s*,\s*(\w+)\s*\+\s*'
            r'(\w+)\s*\)\s*,\s*\(([^()]*)\)\s*\)',
            self.source,
        )
        if m is None:
            raise ValueError('qf16 not found')
        yj11 = self.eval_expr(self.scanner.read_expression(m.group(1)) or '')
        multiplier = self.eval_expr(m.group(2))
        vf12 = self.eval_expr(self.scanner.read_expression(m.group(3)) or '')
        ka13 = self.eval_expr(self.scanner.read_expression(m.group(4)) or '')
        mask = self.eval_expr(m.group(5))
        values = (yj11, multiplier, vf12, ka13, mask)
        if any(value is None for value in values):
            raise ValueError('cannot evaluate qf16 formula')
        return band(bxor(int(yj11) * int(multiplier),
                         int(vf12) + int(ka13)), int(mask))

    def build_nx58_slots(self) -> Dict[str, int]:
        """Read the cipher's arithmetic slots from its fixed source shape."""
        start = self.source.find('local function Nx58(')
        end = self.source.find('local function oE55(', start)
        if start < 0 or end < 0:
            raise ValueError('Nx58 source shape not found')
        expressions = list(re.finditer(r'\(([^()]*)\)', self.source[start:end]))
        positions = {
            'sch_mask': 2, 'sd_shift': 3, 'st_ix': 4, 'st_len': 5,
            'st_mask': 6, 'st_zero': 7, 'st_fallback_ix': 8,
            'st_fallback_len': 9, 'st_fallback_add': 10,
            'st_fallback_mask': 11, 'st_inner_zero': 12,
            'st_inner_reset': 13, 'ky_shift': 14, 'ky_ix': 15,
            'ky_len': 16, 'ky_st': 17, 'ky_mask': 18,
            'ky_zero': 19, 'ky_fallback_st': 20, 'ky_fallback_ix': 21,
            'ky_fallback_add': 22, 'ky_fallback_mask': 23,
            'ky_inner_zero': 24, 'ky_inner_reset': 25,
            'sch_branch': 26, 'primary_start': 27, 'nz_st': 28,
            'nz_pv': 29, 'nz_ky': 30, 'nz_ix': 31, 'nz_p': 32,
            'nz_add': 33, 'nz_mask': 34, 'nz_scale': 35,
            'nz_offset': 36, 'nz_final_mask': 37, 'primary_byte_mask': 39,
            'primary_st_nz': 42, 'primary_st_st': 43,
            'primary_st_mask': 44, 'alternate_start': 45,
            'alternate_st': 46, 'alternate_pv': 47, 'alternate_ky': 48,
            'alternate_ix': 49, 'alternate_p': 50, 'alternate_add': 51,
            'alternate_mask': 52, 'alternate_byte_mask': 54,
            'alternate_pv_mask': 55, 'alternate_st_p': 56,
            'alternate_st_add': 57, 'alternate_st_mask': 58,
        }
        if len(expressions) <= max(positions.values()):
            raise ValueError('incomplete Nx58 arithmetic slots')
        slots = {}
        for name, index in positions.items():
            value = self.eval_expr(expressions[index].group(1))
            if value is None:
                raise ValueError('cannot evaluate Nx58 slot %s' % name)
            slots[name] = int(value)
        return slots

    def build_ca56_weights(self) -> Tuple[int, int, int]:
        """Read the three byte-place weights used by the CA56 index decoder."""
        m = re.search(
            r'local\s+a\s*,\s*c\s*,\s*d\s*,\s*e\s*=\s*string\.byte\s*'
            r'\(\s*b\s*,\s*i\s*,\s*i\s*\+\s*\([^()]*\)\s*\)\s*'
            r'o\s*\[\s*#o\s*\+\s*\([^()]*\)\s*\]\s*=\s*a\s*\*\s*'
            r'\(([^()]*)\)\s*\+\s*c\s*\*\s*\(([^()]*)\)\s*\+\s*'
            r'd\s*\*\s*\(([^()]*)\)\s*\+\s*e',
            self.source,
            re.DOTALL,
        )
        if m is None:
            raise ValueError('CA56 byte-fold expression not found')
        values = [self.eval_expr(m.group(i)) for i in range(1, 4)]
        if any(value is None for value in values):
            raise ValueError('cannot evaluate CA56 byte-fold weights')
        return tuple(int(value) for value in values)


def oE55_decode(data: str, alphabet: Dict[str, int]) -> str:
    """Reimplementation of the ``oE55`` base-85 style decoder."""
    out = bytearray()
    for i in range(0, len(data), 5):
        a = alphabet.get(data[i], 0)
        b = alphabet.get(data[i + 1], 0) if i + 1 < len(data) else 0
        c = alphabet.get(data[i + 2], 0) if i + 2 < len(data) else 0
        d = alphabet.get(data[i + 3], 0) if i + 3 < len(data) else 0
        e = alphabet.get(data[i + 4], 0) if i + 4 < len(data) else 0
        n = a * 52200625 + b * 614125 + c * 7225 + d * 85 + e
        out.append((n >> 24) % 256)
        out.append((n >> 16) % 256)
        out.append((n >> 8) % 256)
        out.append(n & 255)
    return out.decode('latin-1')


def char_codes(expr_list: List[str], ev: LuaExpressionEvaluator) -> List[int]:
    """Evaluate a list of numeric expressions into character codes."""
    codes = []
    for item in expr_list:
        value = ev.try_evaluate(item, None)
        if value is None:
            raise ValueError('cannot evaluate %r' % (item,))
        codes.append(int(value))
    return codes


def unquote(literal: str) -> str:
    """Decode a Lua string literal (including its surrounding quotes)."""
    body = literal[1:-1]
    out = bytearray()
    i = 0
    while i < len(body):
        ch = body[i]
        if ch == '\\' and i + 1 < len(body):
            nxt = body[i + 1]
            mapping = {'n': 10, 't': 9, 'r': 13, 'a': 7, 'b': 8,
                       'f': 12, 'v': 11, '\\': 92, '"': 34, "'": 39}
            if nxt in mapping:
                out.append(mapping[nxt])
                i += 2
                continue
            if nxt == 'x':
                out.append(int(body[i + 2:i + 4], 16))
                i += 4
                continue
            if nxt.isdigit():
                digits = ''
                j = i + 1
                while j < len(body) and body[j].isdigit() and len(digits) < 3:
                    digits += body[j]
                    j += 1
                out.append(int(digits) & 0xFF)
                i = j
                continue
            out.append(ord(nxt))
            i += 2
            continue
        out.extend(ch.encode('latin-1', 'replace'))
        i += 1
    return out.decode('latin-1')


class Nx58:
    """Reimplementation of the ``Nx58`` stream cipher."""
    def __init__(self, constants: Dict[str, Any], km2: int):
        self.jm = constants
        self.km2 = km2
        self.slots = constants['_nx58_slots']

    def decrypt(self, data: bytes, sd: int, ix: int) -> bytes:
        jm = self.jm
        s = self.slots
        sd = bxor(sd, self.km2)
        length = len(data)
        sch = band(sd, s['sch_mask'])
        sd = rshift(sd, s['sd_shift'])

        st = band(bxor(sd, ix * s['st_ix']) + length * s['st_len'],
                  s['st_mask'])
        if st == s['st_zero']:
            st = band(ix * s['st_fallback_ix']
                      + length * s['st_fallback_len']
                      + s['st_fallback_add'], s['st_fallback_mask'])
            if st == s['st_inner_zero']:
                st = s['st_inner_reset']

        ky = band(bxor(bxor(rshift(sd, s['ky_shift']), ix * s['ky_ix']),
                       bxor(length * s['ky_len'], st * s['ky_st'])),
                  s['ky_mask'])
        if ky == s['ky_zero']:
            ky = band(st * s['ky_fallback_st']
                      + ix * s['ky_fallback_ix'] + s['ky_fallback_add'],
                      s['ky_fallback_mask'])
            if ky == s['ky_inner_zero']:
                ky = s['ky_inner_reset']

        pv = ky
        out = bytearray()
        if sch == s['sch_branch']:
            for p in range(s['primary_start'], length + 1):
                nz = band(st * s['nz_st'] + pv * s['nz_pv']
                          + ky * s['nz_ky'] + ix * s['nz_ix']
                          + p * s['nz_p'] + s['nz_add'], s['nz_mask'])
                nz = band(nz * s['nz_scale'] + s['nz_offset'],
                          s['nz_final_mask'])
                byte = data[p - 1] if p - 1 < length else 0
                out.append(band(byte - st - nz, s['primary_byte_mask']))
                pv = byte
                st = band(byte + nz * s['primary_st_nz']
                          + st * s['primary_st_st'] + ky + ix + p,
                          s['primary_st_mask'])
        else:
            for p in range(s['alternate_start'], length + 1):
                t = band(st * s['alternate_st'] + pv * s['alternate_pv']
                         + ky * s['alternate_ky'] + ix * s['alternate_ix']
                         + p * s['alternate_p'] + s['alternate_add'],
                         s['alternate_mask'])
                byte = data[p - 1] if p - 1 < length else 0
                out.append(band(byte - t, s['alternate_byte_mask']))
                pv = band(byte + t, s['alternate_pv_mask'])
                st = band(st + byte + p * s['alternate_st_p']
                          + s['alternate_st_add'], s['alternate_st_mask'])
        return bytes(out)


def CA56_decode(data: bytes, constants: Dict[str, Any]) -> List[int]:
    """Reimplementation of the ``CA56`` helper: base-85 -> 4-byte integers.

    ``CA56`` re-uses the ``oE55`` decoder and then folds every 4 bytes into a
    single integer, producing the index table used by the string blobs.
    """
    jm = constants
    weights = jm['_ca56_weights']
    out: List[int] = []
    for i in range(0, len(data), 4):
        a = data[i] if i < len(data) else 0
        c = data[i + 1] if i + 1 < len(data) else 0
        d = data[i + 2] if i + 2 < len(data) else 0
        e = data[i + 3] if i + 3 < len(data) else 0
        out.append(a * weights[0] + c * weights[1] + d * weights[2] + e)
    return out


# ---------------------------------------------------------------------------
# String blob extraction
# ---------------------------------------------------------------------------

# A Lua arithmetic sub-expression that may contain one level of parentheses.
OFF_EXPR = r'(?:[^()\[\]]|\([^()]*\))+?'

# ``local DATA = oE55("...")`` - the encrypted payload of a blob.
BLOB_RE = re.compile(
    r'local\s+(?P<data>\w+)\s*=\s*oE55\s*\(\s*'
    r'(?P<dstr>"(?:[^"\\]|\\.)*")\s*\)',
    re.DOTALL,
)

# ``local IDX = CA56("...")`` - the encrypted index table of a blob.
CA56_RE = re.compile(
    r'local\s+(?P<idx>\w+)\s*=\s*CA56\s*\(\s*'
    r'(?P<istr>"(?:[^"\\]|\\.)*")\s*\)',
    re.DOTALL,
)

# Anchor of the decode loop that populates the global string table ``K``.
# Every blob in the sample follows this exact shape:
#
#   for VAR = START, #IDX, STEP do
#     K[IDX[VAR]] = Nx58(DATA:sub(IDX[VAR+O1],
#                               IDX[VAR+O2] + IDX[VAR+O3] - SUB),
#                           bit32.bxor(IDX[VAR+O4], c864),
#                           IDX[VAR+O5])
#   end
LOOP_ANCHOR_RE = re.compile(
    r'K\s*\[\s*(?P<idx>\w+)\s*\[\s*(?P<var>\w+)\s*\]\s*\]\s*=\s*'
    r'Nx58\s*\(\s*(?P<data>\w+)\s*:\s*sub\s*\('
)

# The Nx58 call argument, e.g. ``IDX[VAR + (0*55+1*18-17)]``.
IDX_SLOT_RE = re.compile(
    r'^\s*(?P<idx>\w+)\[\s*(?P<var>\w+)\s*\+\s*(?P<off>.+?)\s*\]\s*$'
)

# The Nx58 call argument, e.g. ``bit32.bxor(IDX[VAR + (0*332+3)], c864)``.
BXOR_RE = re.compile(
    r'^\s*bit32\.bxor\(\s*(?P<idx>\w+)\[\s*(?P<var>\w+)\s*\+\s*'
    r'(?P<off>.+?)\s*\]\s*,\s*c864\s*\)\s*$'
)

# The ``for`` header of the decode loop.
FOR_HEADER_RE = re.compile(
    r'for\s+(?P<var>\w+)\s*=\s*(?P<start>.*?),\s*#(?P<idx>\w+)\s*,'
)

# The Nx58 call argument, e.g. ``IDX[VAR + (16929-16925)]``.
IDX_REF_RE = re.compile(
    r'(?P<idx>\w+)\[\s*(?P<var>\w+)\s*\+\s*(?P<off>\([^()]*\)|[\w]+)\s*\]'
)


class Blob:
    """One decoded string blob: a payload plus its index table."""

    def __init__(self, data_var: str, idx_var: str, payload: str, index: str,
                 offsets: Dict[str, int]):
        self.data_var = data_var
        self.idx_var = idx_var
        self.payload = payload
        self.index = index
        self.offsets = offsets


class StringTables:
    """Decodes every ``oE55``/``CA56``/``Nx58`` string blob in the source."""

    def __init__(self, source: str):
        self.source = source
        self.scanner = SourceScanner(source)

    def find_blobs(self, ev: LuaExpressionEvaluator) -> List[Blob]:
        """Locate and pair up every ``oE55`` payload with its ``CA56`` table.

        Pairing is anchored on the decode loop that populates the global
        string table ``K``::

            for VAR = START, #IDX, STEP do
                K[IDX[VAR]] = Nx58(DATA:sub(...), ...)
            end

        The loop names both the payload variable (``DATA``) and the index
        table variable (``IDX``) directly, so the pair can be resolved by
        name.  Searching for the ``CA56`` call in a fixed-size window after
        the ``oE55`` call is *not* reliable: the length of the encrypted
        index literal is unrelated to the length of the encrypted payload,
        so a window sized from the payload silently skips blobs whose
        index table is longer than the payload (this dropped the large
        ``JZ123``/``Xf124`` pair).
        """
        ca56_by_name: Dict[str, str] = {}
        for m in CA56_RE.finditer(self.source):
            ca56_by_name[m.group('idx')] = m.group('istr')

        payload_by_name: Dict[str, str] = {}
        for m in BLOB_RE.finditer(self.source):
            payload_by_name[m.group('data')] = m.group('dstr')

        blobs: List[Blob] = []
        for anchor in LOOP_ANCHOR_RE.finditer(self.source):
            idx_var = anchor.group('idx')
            data_var = anchor.group('data')
            index_literal = ca56_by_name.get(idx_var)
            payload_literal = payload_by_name.get(data_var)
            if index_literal is None or payload_literal is None:
                continue
            offsets = self._parse_loop(self.source, anchor, idx_var, ev)
            blobs.append(Blob(data_var, idx_var, payload_literal,
                              index_literal, offsets))
        return blobs

    def _parse_loop(self, source: str, anchor: "re.Match", idx_var: str,
                    ev: LuaExpressionEvaluator) -> Dict[str, int]:
        """Resolve the index-table offsets used by the Nx58 decode loop.

        The loop body is a single assignment, so the window extends from the
        ``for`` header up to a fixed distance past the anchor.  Offsets are
        restricted to the loop's own index table variable, which is unique
        per blob, so neighbouring loops cannot contribute stray references.
        """
        prefix = source[:anchor.start()]
        headers = list(re.finditer(r'for\s+\w+\s*=\s*', prefix))
        start = headers[-1].start() if headers else anchor.start()
        window = source[start:anchor.end() + 600]

        offsets: Dict[str, int] = {}
        for m in IDX_REF_RE.finditer(window):
            if m.group('idx') != idx_var:
                continue
            value = ev.try_evaluate(m.group('off'), None)
            if value is None:
                continue
            offsets[str(int(value))] = int(value)
        return offsets

    def decode_all(self, constants: Dict[str, Any], alphabet: Dict[str, int],
                   km2: int, c864: int,
                   blobs: List[Blob]) -> Dict[str, Dict[Any, str]]:
        """Decode every blob into ``{key: plaintext}`` mappings.

        Each ``CA56`` index blob holds 5 integers per record:

            key, start, length, sd, ix

        and the plaintext is ``Nx58(payload:sub(start, start+length-1),
        sd ^ c864, ix)``.
        """
        cipher = Nx58(constants, km2)
        tables: Dict[str, Dict[Any, str]] = {}
        for blob in blobs:
            payload = oE55_decode(unquote(blob.payload), alphabet).encode('latin-1')
            index_raw = oE55_decode(unquote(blob.index), alphabet).encode('latin-1')
            indexes = CA56_decode(index_raw, constants)
            table: Dict[Any, str] = {}
            for base in range(0, len(indexes) - 4, 5):
                key = indexes[base]
                start = indexes[base + 1]
                length = indexes[base + 2]
                sd = bxor(indexes[base + 3], c864)
                ix = indexes[base + 4]
                if start < 1 or length < 1:
                    continue
                chunk = payload[start - 1:start - 1 + length]
                plain = cipher.decrypt(chunk, sd, ix)
                table[key] = plain.decode('latin-1')
            tables[blob.idx_var] = table
        return tables
