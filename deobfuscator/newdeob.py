#!/usr/bin/env python3
"""
Kebabfuscator v1 Deobfuscator
==============================

Deobfuscates Lua files protected by Kebabfuscator v1.

Usage:
    python deobfuscator.py <input.lua> [output.lua]

The tool performs the following passes:

  1. CONSTANTS - evaluates the ``jm*`` constant table hidden in the
                 obfuscated source into concrete integers.
  2. KEYS     - recomputes the derived keys (``Km2``, ``c864``,
                 ``qf16``) and the custom base85 alphabet (``Er60``).
  3. STRINGS  - decrypts every embedded string blob using the
                 reconstructed crypto routines (``oE55``, ``Nx58``,
                 ``CA56``, ``Ox20``).
  4. VM       - disassembles the custom bytecode executed by the
                 ``c435`` interpreter into a readable listing.

The anti-tamper / integrity check is extracted into ``anti_tamper.lua``.
"""

import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

# =============================================================================
# BIT32 OPERATIONS (Lua 5.1 compatible)
# =============================================================================

def bit32_band(a: int, b: int) -> int:
    return a & b


def bit32_bxor(a: int, b: int) -> int:
    return a ^ b


def bit32_bnot(a: int) -> int:
    return (~a) & 0xFFFFFFFF


def bit32_bor(a: int, b: int) -> int:
    return a | b


def bit32_lshift(a: int, b: int) -> int:
    return (a << b) & 0xFFFFFFFF


def bit32_rshift(a: int, b: int) -> int:
    return (a >> b) & 0xFFFFFFFF


MASK32 = 0xFFFFFFFF


# =============================================================================
# LUA EXPRESSION EVALUATOR
# =============================================================================

class LuaExpressionError(Exception):
    """Raised when an expression cannot be evaluated."""


TOKEN_RE = re.compile(r"""
    (?P<number>\d+\.\d+|\d+)
  | (?P<string>"(?:[^"\\]|\\.)*")
  | (?P<name>[A-Za-z_][A-Za-z0-9_]*)
  | (?P<op>\.\.|==|~=|<=|>=|[-+*/%^#<>=~(){}\[\],;:.])
  | (?P<space>\s+)
""", re.VERBOSE)


class LuaExpressionEvaluator:
    """Recursive-descent evaluator for the arithmetic Kebabfuscator uses
    to hide its constants.

    Understands integer/float arithmetic, string concatenation, the unary
    length operator ``#``, unary minus/bitwise-not, and the handful of
    string/bit32 library functions the obfuscator relies on.
    """

    def __init__(self, constants: Optional[Dict[str, Any]] = None):
        self.constants: Dict[str, Any] = dict(constants or {})
        self.tokens: List[Tuple[str, str]] = []
        self.pos = 0

    # -- public API ----------------------------------------------------------

    def register(self, name: str, value: Any) -> None:
        self.constants[name] = value

    def evaluate(self, expr: str) -> Any:
        self.tokens = self._tokenize(expr)
        self.pos = 0
        value = self._parse_expr()
        if self.pos != len(self.tokens):
            raise LuaExpressionError("Trailing input in expression: %r" % (expr,))
        return value

    def try_evaluate(self, expr: str, default: Any = None) -> Any:
        """Evaluate ``expr``; return ``default`` when it cannot be resolved."""
        try:
            return self.evaluate(expr)
        except (LuaExpressionError, KeyError, IndexError, TypeError, ValueError):
            return default

    # -- tokenizer -----------------------------------------------------------

    @staticmethod
    def _tokenize(expr: str) -> List[Tuple[str, str]]:
        tokens: List[Tuple[str, str]] = []
        pos = 0
        while pos < len(expr):
            m = TOKEN_RE.match(expr, pos)
            if not m:
                raise LuaExpressionError("Cannot tokenize at %r" % (expr[pos:pos + 20],))
            pos = m.end()
            kind = m.lastgroup
            if kind == 'space':
                continue
            tokens.append((kind, m.group()))
        return tokens

    # -- helpers -------------------------------------------------------------

    def _peek(self) -> Optional[Tuple[str, str]]:
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return None

    def _accept(self, value: str) -> bool:
        tok = self._peek()
        if tok and tok[0] == 'op' and tok[1] == value:
            self.pos += 1
            return True
        return False

    def _expect(self, value: str) -> None:
        if not self._accept(value):
            raise LuaExpressionError("Expected %r" % (value,))

    @staticmethod
    def _tostr(value: Any) -> str:
        if isinstance(value, str):
            return value
        if isinstance(value, bool):
            return 'true' if value else 'false'
        if isinstance(value, float) and value.is_integer():
            return str(int(value))
        return str(value)


    @staticmethod
    def _arith(a: Any, b: Any, op: str) -> Any:
        if op == '+':
            if isinstance(a, str) or isinstance(b, str):
                return LuaExpressionEvaluator._tostr(a) + LuaExpressionEvaluator._tostr(b)
            return a + b
        if op == '-':
            return a - b
        if op == '*':
            return a * b
        if op == '/':
            if b == 0:
                return 0
            if isinstance(a, int) and isinstance(b, int):
                return a // b
            return a / b
        if op == '%':
            if b == 0:
                return 0
            return a % b
        raise LuaExpressionError("Unsupported operator %r" % (op,))

    # -- parser --------------------------------------------------------------

    def _parse_expr(self) -> Any:
        left = self._parse_term()
        while True:
            if self._accept('+'):
                left = self._arith(left, self._parse_term(), '+')
            elif self._accept('-'):
                left = self._arith(left, self._parse_term(), '-')
            elif self._accept('..'):
                left = self._tostr(left) + self._tostr(self._parse_term())
            else:
                return left

    def _parse_term(self) -> Any:
        left = self._parse_unary()
        while True:
            if self._accept('*'):
                left = self._arith(left, self._parse_unary(), '*')
            elif self._accept('/'):
                left = self._arith(left, self._parse_unary(), '/')
            elif self._accept('%'):
                left = self._arith(left, self._parse_unary(), '%')
            else:
                return left

    def _parse_unary(self) -> Any:
        if self._accept('-'):
            return self._arith(0, self._parse_unary(), '-')
        if self._accept('#'):
            return len(self._tostr(self._parse_unary()))
        if self._accept('~'):
            return bit32_bnot(int(self._parse_unary()))
        return self._parse_primary()

    def _parse_primary(self) -> Any:
        tok = self._peek()
        if tok is None:
            raise LuaExpressionError("Unexpected end of expression")
        kind, text = tok
        if kind == 'number':
            self.pos += 1
            return float(text) if '.' in text else int(text)
        if kind == 'string':
            self.pos += 1
            return self._decode_string(text)
        if kind == 'name':
            self.pos += 1
            # Lua allows dotted / indexed access: string.rep, string["char"]
            parts = [text]
            while True:
                nxt = self._peek()
                if nxt and nxt[0] == 'op' and nxt[1] == '.':
                    self.pos += 1
                    tok2 = self._peek()
                    if tok2 is None or tok2[0] != 'name':
                        raise LuaExpressionError("Expected name after '.'")
                    self.pos += 1
                    parts.append(tok2[1])
                    continue
                if nxt and nxt[0] == 'op' and nxt[1] == '[':
                    self.pos += 1
                    key = self._parse_expr()
                    self._expect(']')
                    parts.append(self._tostr(key))
                    continue
                break
            name = '.'.join(parts)
            nxt = self._peek()
            if nxt and nxt[0] == 'op' and nxt[1] == '(':
                self.pos += 1
                return self._call(name)
            if name in self.constants:
                return self.constants[name]
            raise LuaExpressionError("Unknown identifier: %s" % name)
        if kind == 'op' and text == '(':
            self.pos += 1
            value = self._parse_expr()
            self._expect(')')
            return value
        raise LuaExpressionError("Unexpected token: %r" % (text,))

    def _call(self, name: str) -> Any:
        args: List[Any] = []
        if not self._accept(')'):
            while True:
                args.append(self._parse_expr())
                if self._accept(','):
                    continue
                self._expect(')')
                break
        return self._invoke(name, args)

    def _invoke(self, name: str, args: List[Any]) -> Any:
        if name == 'string.byte':
            if len(args) == 1:
                text = self._tostr(args[0])
                if not text:
                    raise LuaExpressionError("string.byte() of empty string")
                return ord(text[0])
            text = self._tostr(args[0])
            index = int(args[1]) if len(args) > 1 else 1
            if index < 1 or index > len(text):
                raise LuaExpressionError("string.byte() index out of range")
            return ord(text[index - 1])
        if name == 'string.char':
            return ''.join(chr(int(a) & 0xFF) for a in args)
        if name == 'string.rep':
            return self._tostr(args[0]) * int(args[1])
        if name == 'string.sub':
            text = self._tostr(args[0])
            start = int(args[1]) if len(args) > 1 else 1
            stop = int(args[2]) if len(args) > 2 else -1
            if start < 0:
                start = len(text) + start + 1
            if stop < 0:
                stop = len(text) + stop + 1
            return text[start - 1:stop]
        if name == 'tonumber':
            value = args[0]
            if len(args) > 1:
                return int(str(value), int(args[1]))
            if isinstance(value, (int, float)):
                return value
            try:
                return int(str(value))
            except ValueError:
                try:
                    return float(str(value))
                except ValueError:
                    return None
        if name == 'bit32.band':
            return self._fold(args, bit32_band)
        if name == 'bit32.bor':
            return self._fold(args, bit32_bor)
        if name == 'bit32.bxor':
            return self._fold(args, bit32_bxor)
        if name == 'bit32.bnot':
            return bit32_bnot(int(args[0]))
        if name == 'bit32.lshift':
            return bit32_lshift(int(args[0]), int(args[1]))
        if name == 'bit32.rshift':
            return bit32_rshift(int(args[0]), int(args[1]))
        if name == 'math.floor':
            return int(args[0]) // 1
        if name == 'math.abs':
            return abs(args[0])
        raise LuaExpressionError("Unsupported function: %s" % name)

    @staticmethod
    def _fold(args: List[Any], fn) -> int:
        if not args:
            raise LuaExpressionError("Missing arguments")
        result = int(args[0])
        for arg in args[1:]:
            result = fn(result, int(arg))
        return result

    @staticmethod
    def _decode_string(literal: str) -> str:
        body = literal[1:-1]
        out: List[str] = []
        i = 0
        escapes = {'n': '\n', 't': '\t', 'r': '\r', 'a': '\a', 'b': '\b',
                   'f': '\f', 'v': '\v', '\\': '\\', '"': '"', "'": "'", '\n': '\n'}
        while i < len(body):
            ch = body[i]
            if ch == '\\' and i + 1 < len(body):
                nxt = body[i + 1]
                if nxt in escapes:
                    out.append(escapes[nxt])
                    i += 2
                    continue
                if nxt == 'x':
                    out.append(chr(int(body[i + 2:i + 4], 16)))
                    i += 4
                    continue
                if nxt.isdigit():
                    j = i + 1
                    digits = ''
                    while j < len(body) and body[j].isdigit() and len(digits) < 3:
                        digits += body[j]
                        j += 1
                    out.append(chr(int(digits)))
                    i = j
                    continue
            out.append(ch)
            i += 1
        return ''.join(out)


# =============================================================================
# SOURCE PARSER
# =============================================================================

class LuaSourceParser:
    """Extracts top-level assignments and tables from obfuscated Lua source.

    The obfuscator emits everything on one enormous line, so the parser
    works on the raw character stream rather than on lines.
    """

    def __init__(self, source: str):
        self.source = source
        self.pos = 0
        self.length = len(source)

    # -- low level scanning --------------------------------------------------

    def skip_space(self) -> None:
        while self.pos < self.length:
            ch = self.source[self.pos]
            if ch in ' \t\r\n':
                self.pos += 1
            elif self.source.startswith('--', self.pos):
                if self.source.startswith('--[[', self.pos):
                    end = self.source.find(']]', self.pos + 4)
                    self.pos = self.length if end == -1 else end + 2
                else:
                    end = self.source.find('\n', self.pos)
                    self.pos = self.length if end == -1 else end + 1
            else:
                return

    def read_string(self) -> str:
        """Read a Lua string literal (quote char already consumed)."""
        quote = self.source[self.pos - 1]
        out: List[str] = []
        while self.pos < self.length:
            ch = self.source[self.pos]
            if ch == '\\':
                nxt = self.source[self.pos + 1] if self.pos + 1 < self.length else ''
                mapping = {'n': '\n', 't': '\t', 'r': '\r', 'a': '\a', 'b': '\b',
                           'f': '\f', 'v': '\v', '\\': '\\', '"': '"', "'": "'"}
                if nxt in mapping:
                    out.append(mapping[nxt])
                    self.pos += 2
                    continue
                if nxt == 'x':
                    out.append(chr(int(self.source[self.pos + 2:self.pos + 4], 16)))
                    self.pos += 4
                    continue
                if nxt.isdigit():
                    digits = ''
                    j = self.pos + 1
                    while j < self.length and self.source[j].isdigit() and len(digits) < 3:
                        digits += self.source[j]
                        j += 1
                    out.append(chr(int(digits)))
                    self.pos = j
                    continue
                out.append(nxt)
                self.pos += 2
                continue
            if ch == quote:
                self.pos += 1
                break
            out.append(ch)
            self.pos += 1
        return ''.join(out)

    def read_balanced(self) -> str:
        """Read a balanced ``(...)``/``{...}`` region, returning its contents."""
        opener = self.source[self.pos]
        closer = ')' if opener == '(' else '}'
        depth = 0
        start = self.pos
        while self.pos < self.length:
            ch = self.source[self.pos]
            if ch in '"\'':
                self.pos += 1
                self.read_string()
                continue
            if ch == opener:
                depth += 1
            elif ch == closer:
                depth -= 1
                if depth == 0:
                    self.pos += 1
                    return self.source[start + 1:self.pos - 1]
            self.pos += 1
        return self.source[start + 1:]


    def split_top_level(self, text: str) -> List[str]:
        """Split a table body on top-level commas."""
        parts: List[str] = []
        depth = 0
        current: List[str] = []
        i = 0
        while i < len(text):
            ch = text[i]
            if ch in '"\'':
                j = i + 1
                while j < len(text):
                    if text[j] == '\\':
                        j += 2
                        continue
                    if text[j] == ch:
                        break
                    j += 1
                current.append(text[i:j + 1])
                i = j + 1
                continue
            if ch in '([{':
                depth += 1
            elif ch in ')]}':
                depth -= 1
            elif ch == ',' and depth == 0:
                parts.append(''.join(current).strip())
                current = []
                i += 1
                continue
            current.append(ch)
            i += 1
        tail = ''.join(current).strip()
        if tail:
            parts.append(tail)
        return parts


# =============================================================================
# CONSTANT EXTRACTION
# =============================================================================

ASSIGN_RE = re.compile(r'local\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?!=)')


class KebabfuscatorConstants:
    """Extracts and evaluates the obfuscator's hidden constant table."""

    def __init__(self, source: str):
        self.source = source
        self.parser = LuaSourceParser(source)
        self.evaluator = LuaExpressionEvaluator()
        self.scalars: Dict[str, Any] = {}
        self.tables: Dict[str, List[Any]] = {}
        self.raw: Dict[str, str] = {}

    def extract(self) -> None:
        """Scan the whole source for ``local NAME = <expr|table>`` patterns."""
        source = self.source
        for match in ASSIGN_RE.finditer(source):
            name = match.group(1)
            value_start = match.end()
            self._parse_value(name, value_start)

    def _parse_value(self, name: str, start: int) -> None:
        source = self.source
        idx = start
        while idx < len(source) and source[idx] in ' \t\r\n':
            idx += 1
        if idx >= len(source):
            return
        ch = source[idx]
        if ch == '{':
            self.parser.pos = idx
            body = self.parser.read_balanced()
            self.raw[name] = body
            self.tables[name] = self.parser.split_top_level(body)
            return
        # scalar expression: read until the next top-level separator
        end = self._find_expression_end(idx)
        expr = source[idx:end].strip()
        if not expr:
            return
        self.raw[name] = expr
        value = self.evaluator.try_evaluate(expr, None)
        if value is not None:
            self.scalars[name] = value
            self.evaluator.register(name, value)

    # Keywords that open a block; each is closed by a matching ``end``.
    BLOCK_OPENERS = ('function', 'if', 'for', 'while', 'repeat')

    def _find_expression_end(self, start: int) -> int:
        """Find the end of a scalar expression.

        The expression ends at a top-level comma or at the next top-level
        ``local`` statement.  Block keywords are tracked so that expressions
        containing a nested ``function`` body are handled correctly.
        """
        source = self.source
        depth = 0          # ( [ { nesting
        blocks = 0         # function/if/for/while/repeat nesting
        i = start
        length = len(source)
        while i < length:
            ch = source[i]
            if ch in '"\'':
                quote = ch
                i += 1
                while i < length:
                    if source[i] == '\\':
                        i += 2
                        continue
                    if source[i] == quote:
                        break
                    i += 1
                i += 1
                continue
            if ch.isalpha() or ch == '_':
                j = i
                while j < length and (source[j].isalnum() or source[j] == '_'):
                    j += 1
                word = source[i:j]
                if blocks == 0 and depth == 0 and word == 'local':
                    return i
                if word in self.BLOCK_OPENERS:
                    if word == 'if' and source[max(0, i - 5):i].endswith('else'):
                        pass
                    else:
                        blocks += 1
                elif word == 'until':
                    blocks = max(0, blocks - 1)
                elif word == 'end':
                    blocks = max(0, blocks - 1)
                i = j
                continue
            if ch in '([{':
                depth += 1
            elif ch in ')]}':
                depth -= 1
            elif depth == 0 and blocks == 0 and ch == ',':
                return i
            i += 1
        return i
