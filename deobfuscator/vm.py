"""Kebabfuscator v1 VM layer: loader mini-VM, bc19 stream reader,
opcode map and disassembler.

Everything here is verified against the real-Lua oracle (mz_oracle2.lua):
  - loader digit streams reproduce the exact Mz25 tables,
  - w(p) = Ww(digits[5p-4..5p]) ^ JN10(3p) matches every bc19 read,
  - op = w(p) ^ NS14(p) lands in the known dispatch opcode set.
"""
import re

import names
from newdeob import LuaExpressionEvaluator
from keb import Constants, SourceScanner, oE55_decode, unquote, Nx58, band, bxor, rshift

M32 = 0xFFFFFFFF

# --- folded VM constants (sample-verified; see fold scripts) ----------------
P847_SHIFT, P847_MASK, P847_ADD = 8, 0xFF, 1
CA44_HI_SHIFT, CA44_LO_MASK = 16, 0xFFFF
J10_SEED = 19217134 * 92 + 19        # H77
J10_MULT = 34904 - 6038              # Tz8
J10_ADD = 108 + 47 * 413 - 373       # DQ9
J10_SHIFT = 3
J10_MASK = 44739242 * 48 + 2 * 19 - 7    # 0x7FFFFFFF
J9_P_MULT = 3
J9_C_MULT = 4093
NS14_MULT = 17 * 562 - 409           # 9145
NS14_ADD = 0 * 855 + 806             # 806
NS14_KA = None                        # jm23 + 7*462 - 232 (filled from jm)
NS14_MASK = 8388607


class VMParameters:
    """Per-image values recovered from the loader and dispatcher source."""

    def __init__(self, constants: Constants = None):
        self.j10_seed = J10_SEED
        self.j10_mult = J10_MULT
        self.j10_add = J10_ADD
        self.j10_shift = J10_SHIFT
        self.j10_mask = J10_MASK
        self.j9_p_mult = J9_P_MULT
        self.j9_c_mult = J9_C_MULT
        self.ns14_mult = NS14_MULT
        self.ns14_add = NS14_ADD
        self.ns14_ka = 3123
        self.ns14_shift = 2
        self.ns14_mask = NS14_MASK
        self.p847_shift = P847_SHIFT
        self.p847_mask = P847_MASK
        self.p847_add = P847_ADD
        self.ca44_shift = CA44_HI_SHIFT
        self.ca44_mask = CA44_LO_MASK
        self.oh48_step = 1
        self.ly43_step = 1
        self.ca44_step = 1
        self.pq28 = 33424516 * 39 + 6 * 3 - 2
        if constants is None:
            return

        roles = names.resolve(constants.source)

        def evaluate(expression):
            value = constants.eval_expr(expression)
            if value is None:
                raise ValueError('cannot evaluate VM formula %r' % expression)
            return int(value)

        def role_expression(role):
            if role not in roles:
                raise ValueError('VM source role %s not found' % role)
            return roles[role]

        def scalar(role):
            expression = constants.scanner.read_expression(role)
            if expression is None:
                raise ValueError('VM constant %s not found' % role)
            return evaluate(expression)

        self.j10_seed = scalar('H77')
        self.j10_mult = scalar('Tz8')
        self.j10_add = scalar('DQ9')
        self.j10_shift = evaluate(role_expression('_jn10_shift'))
        self.j10_mask = evaluate(role_expression('_jn10_mask'))
        self.j9_p_mult = evaluate(role_expression('_j915_p'))
        self.j9_c_mult = evaluate(role_expression('_j915_c'))
        self.ns14_mult = scalar('Yj11')
        self.ns14_add = scalar('vf12')
        self.ns14_ka = scalar('ka13')
        self.ns14_shift = evaluate(role_expression('_ns14_shift'))
        self.ns14_mask = evaluate(role_expression('_ns14_mask'))
        self.p847_shift = evaluate(role_expression('_p847_shift'))
        self.p847_mask = evaluate(role_expression('_p847_mask'))
        self.p847_add = evaluate(role_expression('_p847_add'))
        self.ca44_shift = evaluate(role_expression('_ca44_shift'))
        self.ca44_mask = evaluate(role_expression('_ca44_mask'))
        self.ca44_step = evaluate(role_expression('_ca44_step'))
        self.oh48_step = evaluate(role_expression('_oh48_step'))
        self.ly43_step = evaluate(role_expression('_ly43_step'))
        self.pq28 = scalar('Pq28')

    def jn10(self, i: int) -> int:
        return (((self.j10_seed + i * self.j10_mult) & M32)
                ^ (((i >> self.j10_shift) + self.j10_add) & M32)) \
            & self.j10_mask

    def j915(self, p: int, c: int) -> int:
        return self.jn10(p * self.j9_p_mult + c * self.j9_c_mult)

    def ns14(self, p: int) -> int:
        return band(bxor(self.ns14_mult * p + self.ns14_add,
                         (p >> self.ns14_shift) + self.ns14_ka),
                    self.ns14_mask)

    def p847(self, value: int) -> int:
        return band(bxor(value, value >> self.p847_shift),
                    self.p847_mask) + self.p847_add


DEFAULT_PARAMETERS = VMParameters()


def JN10(i: int, parameters: VMParameters = None) -> int:
    return (parameters or DEFAULT_PARAMETERS).jn10(i)


def j915(p: int, c: int, parameters: VMParameters = None) -> int:
    return (parameters or DEFAULT_PARAMETERS).j915(p, c)


def ns14(p: int, ka: int = None, parameters: VMParameters = None) -> int:
    if parameters is not None:
        return parameters.ns14(p)
    if ka is None:
        ka = NS14_KA if NS14_KA is not None else 3123
    return band(bxor(NS14_MULT * p + NS14_ADD,
                     (p >> 2) + ka), NS14_MASK)


def p847(v: int, parameters: VMParameters = None) -> int:
    return (parameters or DEFAULT_PARAMETERS).p847(v)


def ww18(digits, q: int) -> int:
    """Ww18(b, q): pack digits b[q+1 .. q+5] into a 32-bit word."""
    v = 0
    for i in range(1, 6):
        v = (v * 92 + digits.get(q + i, 0)) & M32
    return v


def pw17(digits, q: int, w: int) -> None:
    """pW17(b, q, w): unpack w into digits b[q+1 .. q+5]."""
    v = w
    for k in range(5, 0, -1):
        d = v % 92
        digits[q + k] = d
        v = (v - d) // 92


# ---------------------------------------------------------------------------
# Loader mini-VM
# ---------------------------------------------------------------------------

LOAD_LOAD = 0x40000


class Loader:
    """Replays the Ox20-drived Mz25 loader (verified against the Lua oracle)."""

    OP_NEWGLOBAL = 242562
    OP_APPEND = 736642
    OP_XORSEED = 688345
    OP_NEWTABLE = 677282
    OP_BREAK = 59619

    def __init__(self, source: str, constants: Constants,
                 parameters: VMParameters = None):
        self.src = constants.source
        self.c = constants
        self.parameters = parameters or VMParameters(constants)
        opcodes = self._loader_opcodes()
        self.OP_NEWTABLE = opcodes['newtable']
        self.OP_APPEND = opcodes['append']
        self.OP_XORSEED = opcodes['xorseed']
        self.OP_NEWGLOBAL = opcodes['newglobal']
        self.OP_BREAK = opcodes['break']
        self.jm = constants.values
        self.ev = constants.ev
        self.tk6 = constants.build_tk6()
        self.qf16 = constants.build_qf16()
        self.c864 = constants.build_c864()
        self.km2 = constants.build_km2()
        self.tables = {}          # name(int) -> digit dict
        self.m521 = {}            # stream word -> {'name': str}
        self.globals = {}         # global name -> registration info

    def _loader_opcodes(self) -> dict:
        loader_start = self.src.find('local Pq28=')
        start = self.src.find('while true do', loader_start)
        end = self.src.find('local function c435(', start)
        if start < 0 or end < 0:
            raise ValueError('loader dispatch source shape not found')
        body = self.src[start:end]
        opcode_var = re.match(
            r'while\s+true\s+do\s+local\s+(\w+)\s*=\s*bit32\.bxor\s*\(',
            body,
        )
        if opcode_var is None:
            raise ValueError('loader opcode variable not found')
        branches = list(re.finditer(
            r'if\s+' + re.escape(opcode_var.group(1))
            + r'\s*==\s*\(([^()]*)\)\s+then',
            body,
        ))
        roles = {}
        for index, match in enumerate(branches):
            stop = branches[index + 1].start() if index + 1 < len(branches) \
                else len(body)
            branch = body[match.end():stop]
            if 'pW17(' in branch:
                role = 'append'
            elif 'M521[s]={' in branch and 'Nx58(' in branch:
                role = 'newglobal'
            elif re.search(r'\w+\s*=\{\}\s*Mz25\[', branch):
                role = 'newtable'
            elif re.search(r'Pq28\s*=\s*bit32\.bxor\s*\(\s*Pq28\s*,'
                           r'\s*Ox20\s*\(\s*Bk23\s*,', branch):
                role = 'xorseed'
            elif re.search(r'\bbreak\b', branch):
                role = 'break'
            else:
                raise ValueError('unrecognized loader dispatch branch')
            if role in roles:
                raise ValueError('duplicate loader opcode role %s' % role)
            opcode = self.c.eval_expr(match.group(1))
            if not isinstance(opcode, (int, float)) or int(opcode) != opcode:
                raise ValueError('cannot evaluate loader opcode %r'
                                 % match.group(1))
            roles[role] = int(opcode)
        expected = {'newtable', 'append', 'xorseed', 'newglobal', 'break'}
        if set(roles) != expected:
            raise ValueError('incomplete loader dispatch opcodes: %s'
                             % ', '.join(sorted(expected - set(roles))))
        return roles

    # -- Ox20 over a *string* stream ---------------------------------------
    def ox_str(self, text: str, box: list) -> int:
        v = 0
        for _ in range(5):
            d = self.tk6.get(text[box[0] - 1], 0)   # jm24-59 == 0
            v = v * 92 + d
            box[0] += 1
        return v

    # -- string literal helpers -------------------------------------------
    @staticmethod
    def _read_lit(source: str, name: str) -> str:
        i = source.find('local %s=' % name)
        if i < 0:
            raise ValueError('missing %s literal' % name)
        i += len('local %s=' % name)
        while source[i] in ' \t\r\n':
            i += 1
        if source[i] == '(':
            i = source.find('"', i + 1)
        else:
            while source[i] not in '"\'':
                i += 1
        i += 1  # consume opening quote
        out = []
        while True:
            ch = source[i]
            if ch == '"':
                break
            if ch == '\\':
                nxt = source[i + 1]
                mp = {'n': '\n', 't': '\t', 'r': '\r', '\\': '\\',
                      '"': '"', "'": "'"}
                out.append(mp.get(nxt, nxt))
                i += 2
                continue
            out.append(ch)
            i += 1
        return ''.join(out)

    def run(self) -> dict:
        src = self.src
        mt22_lit = self._read_lit(src, 'Mt22')
        bk23 = self._read_lit(src, 'Bk23')
        yn24 = self._read_lit(src, 'YN24')

        alphabet = self.c.build_er60()
        mt22 = oE55_decode(unquote('"' + mt22_lit + '"'), alphabet)

        cipher = Nx58(self.jm, self.km2)
        bk_pos = [1]
        yn_pos = [1]
        pq28 = self.parameters.pq28
        ga29 = None

        def bk_read():
            return self.ox_str(bk23, bk_pos)

        def yn_read():
            return self.ox_str(yn24, yn_pos)

        while True:
            op = bxor(bk_read(), self.qf16)
            if op == self.OP_NEWTABLE:
                ga29 = {}
                self.tables[bk_read()] = ga29
            elif op == self.OP_APPEND:
                count = bk_read()
                for _ in range(count):
                    w = bxor(yn_read(), pq28)
                    pq28 = self.parameters.jn10(pq28)
                    pw17(ga29, len(ga29), w)   # pW17(b, q=#b): digits q+1..q+5
            elif op == self.OP_XORSEED:
                pq28 = bxor(pq28, bk_read())
            elif op == self.OP_NEWGLOBAL:
                s = bk_read()
                f = bk_read()
                l = bk_read()
                d = bxor(bk_read(), self.c864)
                x = bk_read()
                chunk = mt22[f - 1: f + l - 1]
                name = cipher.decrypt(chunk.encode('latin-1'), d, x)
                self.m521[s] = name.decode('latin-1')
            elif op == self.OP_BREAK:
                break
            else:
                raise ValueError('unknown loader op %r at bk pos %d'
                                 % (op, bk_pos[0]))
        return self.tables


# ---------------------------------------------------------------------------
# c435 opcode map (parsed from the folded dispatch tree)
# ---------------------------------------------------------------------------

# CALL / RETURN bodies are truncated in opcode_map.txt; the real bodies are:
#   CALL  : pair(f,na) imm(nr) [na arg regs] ; RT={CC36[f](unpack(AT,1,na))}
#           [nr dst regs]
#   CALLS : pair(f,na) imm(nr) [na arg regs] pair(sT,sA) imm(sB) ;
#           spread sT[si], si=sA..sB ; RT={CC36[f](unpack(AT,1,ncur))}
#           [nr dst regs]
#   RETN  : imm(nv) [nv arg regs] ; qx45=true (VM exits)

# semantic families; per-op params carry the folded constants of the branch
OPS = {}          # op value -> (kind, params)


def _fold_numbers(text: str, ev) -> str:
    """Fold every parenthesised integer/jm expression in a branch body."""
    pat = re.compile(r'\(([^()]*)\)')
    for _ in range(80):
        changed = False
        def repl(m):
            nonlocal changed
            if re.fullmatch(r'\s*-?\d+\s*', m.group(1)):
                return m.group(0)
            val = ev.try_evaluate(m.group(1), None)
            if isinstance(val, int):
                changed = True
                return '(%d)' % val
            if isinstance(val, float) and val == int(val):
                changed = True
                return '(%d)' % int(val)
            return m.group(0)
        text = pat.sub(repl, text)
        if not changed:
            break
    text = re.sub(r'\((\d+)\)', r'\1', text)   # unwrap single-number parens
    return text


def parse_opcode_map(path: str, ev) -> int:
    """Parse opcode_map.txt into OPS with all folded branch constants."""
    text = open(path, encoding='utf-8').read()
    parsed = 0
    OPS.clear()
    for chunk in text.split('=== op ')[1:]:
        head = chunk.split('===')[0]
        body = chunk.split('===', 1)[1]
        op = int(head.strip())
        if _register_opcode(op, body, ev):
            parsed += 1
    return parsed


def _register_opcode(op: int, body: str, ev) -> bool:
    body = _fold_numbers(body, ev)
    body = re.sub(r'NL46=P847\(op\)', '', body)
    body = re.sub(r' ?R549\[\w+\]=R549\[\w+\]?[^ \n{]*', '', body)
    body = body.replace(' else break', '').replace('else break', '')
    body = re.sub(r'\s+', ' ', body).strip()
    kind, params = classify_body(' ' + body)
    if kind is None:
        return False
    OPS[op] = (kind, params)
    return True


def ops_from_source(source: str, ev) -> int:
    """Extract opcode branches from this image's dispatch chain."""
    OPS.clear()
    branch = re.compile(
        r'if\s+op\s*==\s*(\([^()]*\)|-?\d+)\s+then(.*?)\s+else\s+break\s+end',
        re.DOTALL,
    )
    matched = 0
    for match in branch.finditer(source):
        value = ev.try_evaluate(match.group(1), None)
        if not isinstance(value, (int, float)) or int(value) != value:
            raise ValueError('cannot evaluate dispatcher opcode %r'
                             % match.group(1))
        matched += 1
        if not _register_opcode(int(value), match.group(2), ev):
            raise ValueError('unrecognized dispatcher body for opcode %d'
                             % int(value))
    if matched == 0:
        raise ValueError('no opcode branches found in dispatcher')
    return matched


N = r'-?\d+'


def classify_body(b: str):
    """Map a folded branch body to (kind, params)."""
    def n(group):
        return int(group.group(1)) if isinstance(group.group(1), str) else None

    m = re.fullmatch(r' local r,f=Ca44\(\)if CC36\[f\]==nil then CC36\[r\]=(-?\d+) else CC36\[r\]=CC36\[f\]end', b)
    if m:
        return 'MOVE', {'nil_default': int(m.group(1))}
    m = re.fullmatch(r' local r,f=Ca44\(\)CC36\[r\]=CC36\[f\]', b)
    if m:
        return 'MOVE', {'nil_default': None}
    m = re.fullmatch(r' local r,b=Ca44\(\)CC36\[r\]=CC36\[b\]\[(%s)\]' % N, b)
    if m:
        return 'GETI', {'const': int(m.group(1))}
    m = re.fullmatch(r' local r=LY43\(\) ?CC36\[r\]=nil', b)
    if m:
        return 'LOADNIL', {}
    m = re.fullmatch(r' local r=LY43\(\)local t=\{\}t\[(%s)\]=r CC36\[r\]=t' % N, b)
    if m:
        return 'LTAB', {}
    m = re.fullmatch(r' local r=LY43\(\)CC36\[r\]=\{\}', b)
    if m:
        return 'TABLE0', {}
    m = re.fullmatch(r' local b,f=Ca44\(\)CC36\[b\]\[(%s)\]=CC36\[f\]' % N, b)
    if m:
        return 'STI', {'const': int(m.group(1))}
    m = re.fullmatch(r' local r,f=Ca44\(\)if f==(%s) then CC36\[r\]=\{\} ?else CC36\[r\]=\{CC36\[f\]\} ?end' % N, b)
    if m:
        return 'TABLE1', {'empty_if': int(m.group(1))}
    m = re.fullmatch(r' local r,f=Ca44\(\)local o=LY43\(\)CC36\[r\]=bit32\.band\(CC36\[f\] ?or (%s),o\)' % N, b)
    if m:
        return 'ANDI', {'default': int(m.group(1))}
    m = re.fullmatch(r' local r,f=Ca44\(\)local q=bit32\.band\(bit32\.bxor\(CC36\[f\] ?or (%s),LY43\(\)\),(%s)\)CC36\[r\]=q' % (N, N), b)
    if not m:
        m = re.fullmatch(r' local r,f=Ca44\(\)local a=bit32\.bxor\(CC36\[f\] ?or (%s),LY43\(\)\)CC36\[r\]=bit32\.band\(a,(%s)\)' % (N, N), b)
    if m:
        return 'XORIM', {'default': int(m.group(1)), 'mask': int(m.group(2))}
    m = re.fullmatch(r' local r=LY43\(\)local n=(%s) for i=(%s),(%s) do n=n\+i(?: end.*)?' % (N, N, N), b)
    if m:
        init, start, limit = int(m.group(1)), int(m.group(2)), int(m.group(3))
        return 'LOADK', {'value': init + sum(range(start, limit + 1))}
    m = re.fullmatch(r' local r,v=Ca44\(\)CC36\[r\]=\(v==(%s)\)' % N, b)
    if m:
        return 'LBOOL', {'test': int(m.group(1))}
    m = re.fullmatch(r' local r,v=Ca44\(\)CC36\[r\]=\(CC36\[v\]==nil\)', b)
    if m:
        return 'TNIL', {}
    m = re.fullmatch(r' local r,ixr=Ca44\(\)CC36\[r\]=Gq38\[CC36\[ixr\]\]', b)
    if m:
        return 'VARG', {}
    m = re.fullmatch(r' local r=LY43\(\)CC36\[r\]=#Gq38', b)
    if m:
        return 'VLEN', {}
    m = re.fullmatch(r' local r,a=Ca44\(\)local o=LY43\(\)local A=CC36\[a\]local v(?: if[^A]*then v=(?:not A|-A|#A|bit32\.bnot\(A\)))* CC36\[r\]=v(?: will-not-match)?', b)
    if not m:
        m = re.fullmatch(r' local r,a=Ca44\(\)local o=LY43\(\)local A=CC36\[a\]local v .*?end CC36\[r\]=v', b)
    if m:
        table = {int(o): op_s for o, op_s in
                 re.findall(r'o==(%s) then v=(not A|-A|#A|bit32\.bnot\(A\))' % N, b)}
        return 'UNOP', {'ops': table}
    m = re.fullmatch(r' local r,a=Ca44\(\)local b,o=Ca44\(\)local A=CC36\[a\]local B=CC36\[b\]local v .*?end CC36\[r\]=v', b)
    if m:
        table = {int(o): op_s for o, op_s in re.findall(
            r'o==(%s) then v=(A or B|A and B|A==B|A~=B|A<B|A>B|A<=B|A>=B|bit32\.bor\(A,B\)|bit32\.bxor\(A,B\)|bit32\.band\(A,B\)|bit32\.rshift\(A,B\)|bit32\.lshift\(A,B\)|A\.\.B|A\+B|A-B|A\*B|A/B|A%%B|A//B|A\^B)' % N, b)}
        return 'BINOP', {'ops': table}
    m = re.fullmatch(r' local r,t=Ca44\(\)local k=LY43\(\)CC36\[r\]=CC36\[t\]\[CC36\[k\]\]', b)
    if m:
        return 'GT', {}
    m = re.fullmatch(r' local t,k=Ca44\(\)local v=LY43\(\)CC36\[t\]\[CC36\[k\]\]=CC36\[v\]', b)
    if m:
        return 'ST', {}
    m = re.fullmatch(r' local x,f=Ca44\(\)SM39\[x\]\[(%s)\]=CC36\[f\]' % N, b)
    if m:
        return 'UST', {'slot': int(m.group(1))}
    m = re.fullmatch(r' local r,x=Ca44\(\)CC36\[r\]=SM39\[x\]\[(%s)\]' % N, b)
    if m:
        return 'UGT', {'slot': int(m.group(1))}
    m = re.fullmatch(r' local r,s=Ca44\(\)local t=M521\[s\]local v=t\[(%s)\]if v==nil and t\[(%s)\] then v=t\[\d+\]\(\)if v~=nil then t\[\d+\]=v end end CC36\[r\]=v' % (N, N), b)
    if m:
        return 'G521', {}
    m = re.fullmatch(r' local r,k=Ca44\(\)local e=\(getfenv and getfenv\(\)\) ?or _G CC36\[r\]=e\[kS41\(k\)\]', b)
    if m:
        return 'GETG', {}
    m = re.fullmatch(r' local k,r=Ca44\(\)local e=\(getfenv and getfenv\(\)\) ?or _G e\[kS41\(k\)\]=CC36\[r\]', b)
    if m:
        return 'SETG', {}
    m = re.fullmatch(r' local r,k=Ca44\(\)CC36\[r\]=kS41\(k\)', b)
    if m:
        return 'GETK', {}
    m = re.fullmatch(r' local r,t=Ca44\(\)if not CC36\[r\]then hN42=t end', b)
    if m:
        return 'CJF', {}
    m = re.fullmatch(r' local r,t=Ca44\(\)if CC36\[r\]then hN42=t end', b)
    if m:
        return 'CJT', {}
    m = re.fullmatch(r' local t=LY43\(\)hN42=t', b)
    if m:
        return 'JMP', {}
    m = re.fullmatch(r' local r,px=Ca44\(\)CC36\[r\]=Z654\[px\]\(CC36,SM39\)', b)
    if m:
        return 'CLOS', {}
    if b.startswith(' local f,na=Ca44()local nr=LY43()local AT={}'):
        if 'local sT,sA=Ca44()' in b:
            return 'CALLS', {}
        return 'CALL', {}
    if b.startswith(' local nv=LY43()') and 'J151=nv' in b:
        return 'RETN', {}
    return None, None


class Stream:
    """The bc19 self-modifying word stream for one prototype."""

    def __init__(self, digits: dict, parameters: VMParameters = None):
        self.digits = dict(digits)
        self.counts = {}
        self.parameters = parameters or DEFAULT_PARAMETERS

    def word(self, p: int) -> int:
        """bc19 reader at word position p (1-based)."""
        q = 5 * p - 5
        c = self.counts.get(p, 0)
        raw = ww18(self.digits, q)
        w = (raw ^ self.parameters.j915(p, c)) & M32
        # self-modification: rewrite the same window with the next-visit key
        pw17(self.digits, q,
             (w ^ self.parameters.j915(p, c + 1)) & M32)
        self.counts[p] = c + 1
        return w

    @property
    def length(self) -> int:
        return len(self.digits) // 5


# ---------------------------------------------------------------------------
# Disassembler
# ---------------------------------------------------------------------------

def fmt_num(v):
    """Pretty-print a numeric constant."""
    if isinstance(v, float) and v == int(v):
        return '%d' % int(v)
    return repr(v)


class Instr:
    __slots__ = ('pc', 'op', 'kind', 'params', 'fields', 'next_pc')

    def __init__(self, pc, op, kind, params):
        self.pc = pc          # word position of the opcode itself
        self.op = op
        self.kind = kind
        self.params = params
        self.fields = {}      # decoded operand fields (per family)
        self.next_pc = pc + 1

    def text(self, kvals=None, gnames=None):
        f, p = self.fields, self.params
        R = lambda i: 'R%d' % (i,)
        if self.kind == 'MOVE':
            return '%s = R%d%s' % (R(f['r']), f['f'],
                '   (nil->%s)' % p['nil_default'] if p.get('nil_default') is not None else '')
        if self.kind == 'GETI':
            return '%s = R%d[%d]' % (R(f['r']), f['b'], p['const'])
        if self.kind == 'LOADNIL':
            return '%s = nil' % R(f['r'])
        if self.kind == 'LTAB':
            return '%s = {%d}' % (R(f['r']), f['r'])
        if self.kind == 'TABLE0':
            return '%s = {}' % R(f['r'])
        if self.kind == 'TABLE1':
            return '%s = {} or {R%d}' % (R(f['r']), f['f'])
        if self.kind == 'ANDI':
            return '%s = (R%d or %d) & imm' % (R(f['r']), f['f'], p['default'])
        if self.kind == 'XORIM':
            return '%s = ((R%d or %d) ^ imm) & %d' % (R(f['r']), f['f'],
                                                      p['default'], p['mask'])
        if self.kind == 'LOADK':
            return '%s = %s' % (R(f['r']), fmt_num(p['value']))
        if self.kind == 'LBOOL':
            return '%s = %s' % (R(f['r']),
                                'true' if f['v'] == p.get('test', 1) else 'false')
        if self.kind == 'TNIL':
            return '%s = (R%d == nil)' % (R(f['r']), f['v'])
        if self.kind == 'VARG':
            return '%s = VARG[R%d]' % (R(f['r']), f['ixr'])
        if self.kind == 'VLEN':
            return '%s = #VARG' % R(f['r'])
        if self.kind == 'UNOP':
            u = p['ops'].get(f['o'], '?o%d' % f['o'])
            u = {'not A': 'not ', '-A': '-', '#A': '#',
                 'bit32.bnot(A)': '~'}.get(u, u)
            return '%s = %sR%d' % (R(f['r']), u, f['a'])
        if self.kind == 'BINOP':
            sym = p['ops'].get(f['o'], '?o%d' % f['o'])
            sym = {'A or B': ' or ', 'A and B': ' and ',
                   'A==B': '==', 'A~=B': '~=', 'A<B': '<',
                   'A>B': '>', 'A<=B': '<=', 'A>=B': '>=',
                   'bit32.bor(A,B)': '|', 'bit32.bxor(A,B)': '~',
                   'bit32.band(A,B)': '&', 'bit32.rshift(A,B)': '>>',
                   'bit32.lshift(A,B)': '<<', 'A..B': '..', 'A+B': '+',
                   'A-B': '-', 'A*B': '*', 'A/B': '/', 'A%B': '%',
                   'A//B': '//', 'A^B': '^'}.get(sym, sym)
            return '%s = R%d %s R%d' % (R(f['r']), f['a'],
                                        p['ops'].get(f['o'], '?o%d' % f['o']), f['b'])
        if self.kind == 'GT':
            return '%s = R%d[R%d]' % (R(f['r']), f['t'], f['k'])
        if self.kind == 'ST':
            return 'R%d[R%d] = R%d' % (f['t'], f['k'], f['v'])
        if self.kind == 'STI':
            return 'R%d[%d] = R%d' % (f['b'], p['const'], f['f'])
        if self.kind == 'UST':
            return 'UPVAL[%d][1] = R%d' % (f['x'], f['f'])
        if self.kind == 'UGT':
            return '%s = UPVAL[%d][1]' % (R(f['r']), f['x'])
        if self.kind == 'G521':
            name = (gnames or {}).get(f['s'], 'G%d' % f['s'])
            return '%s = <G> %s' % (R(f['r']), name)
        if self.kind == 'GETG':
            k = f['k']
            kval = kscan(kvals, k)
            return '%s = <E> %s' % (R(f['r']), kval)
        if self.kind == 'SETG':
            k = f['k']
            kval = kscan(kvals, k)
            return '<E> %s = R%d' % (kval, f['r'])
        if self.kind == 'GETK':
            k = f['k']
            return '%s = K%d{%s}' % (R(f['r']), k, kscan(kvals, k, raw=True))
        if self.kind == 'CJF':
            return 'if not R%d then pc = %d' % (f['r'], f['t'])
        if self.kind == 'CJT':
            return 'if R%d then pc = %d' % (f['r'], f['t'])
        if self.kind == 'JMP':
            return 'pc = %d' % f['t']
        if self.kind == 'CALL':
            args = ' '.join(str(a) for a in f['args'])
            dsts = ' '.join(str(d) for d in f['dsts'])
            return '%s = R%d(%s)  args[%d]=%s  -> %d rets to %s' % (
                dsts, f['f'], args, f['na'], args, f['nr'], dsts)
        if self.kind == 'CALLS':
            return '%s = R%d(%s spread R%d[%s..%s])  -> rets %s' % (
                ' '.join(str(d) for d in f['dsts']), f['f'],
                ' '.join(str(a) for a in f['args']), f['sT'], f['sA'], f['sB'],
                ' '.join(str(d) for d in f['dsts']))
        if self.kind == 'CLOS':
            return '%s = closure(proto %d)' % (R(f['r']), f['px'])
        if self.kind == 'RETN':
            return 'return %s' % (' '.join(str(r) for r in f['args']))
        return '%r %r' % (self.kind, self.params)


def kscan(kvals, k, raw=False):
    """Render a K-table reference."""
    if kvals is None:
        return 'K[%d]' % k
    if k in kvals:
        v = kvals[k]
        return repr(v)
    return 'K[%d]?[missing]' % k


def decode_stream(stream: Stream, limit: int = None) -> list:
    """Discover and decode the whole reachable CFG from pc=1.

    Basic-block walk: a run ends on JMP / RETN / UNKNOWN / visiting an
    already-decoded pc (CFG merge).  CJT/CJF spawn a second successor at
    their absolute target; JMP continues at its target.
    """
    by_pc = {}
    pending = [1]
    seen = set()
    steps = 0
    max_steps = limit or 10_000_000

    def decode_run(pc, sink):
        nonlocal steps
        parameters = stream.parameters
        while pc is not None and 1 <= pc <= stream.length and steps < max_steps:
            if pc in by_pc:          # CFG merge point
                return
            steps += 1
            w0 = stream.word(pc)
            op = (w0 ^ parameters.ns14(pc)) & M32
            entry = OPS.get(op)
            wordno = pc
            pc += parameters.oh48_step
            if entry is None:
                instr = Instr(wordno, op, 'UNKNOWN', {})
                instr.fields = {'op': op}
                by_pc[wordno] = instr
                sink.append(instr)
                return
            kind, params = entry
            instr = Instr(wordno, op, kind, params)
            n46 = parameters.p847(op)
            pair_state = {}

            def pair():
                nonlocal pc
                w = (stream.word(pc) ^ n46) & M32
                pc += parameters.ca44_step
                return (w >> parameters.ca44_shift,
                        w & parameters.ca44_mask)

            def imm():
                nonlocal pc
                w = (stream.word(pc) ^ n46) & M32
                pc += parameters.ly43_step
                return w

            if kind in ('MOVE', 'GETI', 'ANDI', 'XORIM', 'LBOOL', 'TNIL',
                        'VARG', 'G521', 'GETG', 'SETG', 'GETK', 'CJF', 'CJT',
                        'GT', 'ST', 'STI', 'UGT', 'UST', 'CLOS'):
                a, b = pair()
                instr.fields = _fields_for(kind, a, b, imm)
            elif kind == 'TABLE1':
                a, b = pair()
                instr.fields = {'r': a, 'f': b}
            elif kind in ('LOADNIL', 'LTAB', 'TABLE0', 'VLEN'):
                instr.fields = {'r': imm()}
            elif kind == 'UNOP':
                a, b = pair()
                instr.fields = {'r': a, 'a': b, 'o': imm()}
            elif kind == 'BINOP':
                a, b = pair()
                c, d = pair()
                instr.fields = {'r': a, 'a': b, 'b': c, 'o': d}
            elif kind == 'JMP':
                instr.fields = {'t': imm()}
                pc = instr.fields['t']
            elif kind == 'CALL':
                f, na = pair()
                nr = imm()
                args = [imm() for _ in range(na)]
                dsts = [imm() for _ in range(nr)]
                instr.fields = {'f': f, 'na': na, 'nr': nr,
                                'args': args, 'dsts': dsts}
            elif kind == 'CALLS':
                f, na = pair()
                nr = imm()
                args = [imm() for _ in range(na)]
                sT, sA = pair()
                sB = imm()
                dsts = [imm() for _ in range(nr)]
                instr.fields = {'f': f, 'na': na, 'nr': nr, 'args': args,
                                'sT': sT, 'sA': sA, 'sB': sB, 'dsts': dsts}
            elif kind == 'RETN':
                nv = imm()
                args = [imm() for _ in range(nv)]
                instr.fields = {'nv': nv, 'args': args}
                instr.next_pc = None
                by_pc[wordno] = instr
                sink.append(instr)
                return
            else:
                instr.fields = {'op': op}
                by_pc[wordno] = instr
                sink.append(instr)
                return
            instr.next_pc = pc
            by_pc[wordno] = instr
            sink.append(instr)
            if kind in ('CJT', 'CJF'):
                target = instr.fields['t']
                if target not in seen and target not in pending:
                    seen.add(target)
                    pending.append(target)

    def _fields_for(kind, a, b, imm):
        if kind in ('CJT', 'CJF'):
            return {'r': a, 't': b}
        if kind == 'STI':
            return {'b': a, 'f': b}
        if kind == 'ST':
            return {'t': a, 'k': b, 'v': imm()}
        if kind == 'CLOS':
            return {'r': a, 'px': b}
        if kind == 'GT':
            return {'r': a, 't': b, 'k': imm()}
        if kind == 'G521':
            return {'r': a, 's': b}
        if kind == 'UGT':
            return {'r': a, 'x': b}
        if kind == 'UST':
            return {'x': a, 'f': b}
        if kind == 'SETG':
            return {'k': a, 'r': b}
        if kind in ('GETG', 'GETK'):
            return {'r': a, 'k': b}
        if kind in ('ANDI', 'XORIM'):
            return {'r': a, 'f': b, 'o': imm()}
        if kind == 'VARG':
            return {'r': a, 'ixr': b}
        if kind in ('LBOOL', 'TNIL'):
            return {'r': a, 'v': b}
        if kind == 'GETI':
            return {'r': a, 'b': b}
        return {'r': a, 'f': b}

    seen.add(1)
    sink = []
    while pending:
        decode_run(pending.pop(0), sink)
    out = [by_pc[k] for k in sorted(by_pc)]
    return out


def print_listing(instrs, title=''):
    print('--- listing', title, '---')
    for it in instrs:
        print('%6d  [%-8s pc+%d] %s' % (it.pc, it.kind,
                                        (it.next_pc - it.pc) if it.next_pc and it.next_pc is not None else -1,
                                        it.text()))


# ---------------------------------------------------------------------------
# Prototype metadata: register init, K constants (numbers + strings), upvalues
# ---------------------------------------------------------------------------

KASSIGN_RE = re.compile(r'K\[\(([^()]*)\)\]\s*=\s*([^ ]+)')
BLOB_CALL_RE = re.compile(r'local\s+(\w+)\s*=\s*oE55\("([^"]*)"\)')
IDX_CALL_RE = re.compile(r'local\s+(\w+)\s*=\s*CA56\("([^"]*)"\)')
REGLINE_RE = re.compile(r'\b(\w)\1?\[|')  # placeholder, replaced below
REG_INIT_RE = re.compile(r'(\w+)\[\(([^()]*)\)\]\s*=\s*\(([^()]*)\)')


def build_protos(source: str, constants=None) -> dict:
    """Extract per-proto metadata from the Z654[...] definitions."""
    src = source
    starts = [m.start() for m in re.finditer(r'Z654\[\(', src)]
    defs = []
    for k, s in enumerate(starts):
        e = starts[k + 1] if k + 1 < len(starts) else len(src)
        seg = src[s:e]
        if 'function(' not in seg:
            continue          # entry-point call, not a definition
        if re.search(r'Z654\[\(.*?\)\]\s*\(nil,nil\)\(\.\.\.\)', seg) and k == len(starts) - 1 and len(seg) < 400:
            continue
        defs.append((k + 1, s, e, seg))
    protos = {}
    for n, s, e, seg in defs:
        info = {'span': (s, e), 'kvals': {}, 'reg_init': {}, 'upvals': [],
                'blob': None}
        # --- K numeric entries (before the blob's oE55 literal) -------------
        blobm = BLOB_CALL_RE.search(seg)
        ktext = seg[seg.find('if K==nil'):]
        if blobm:
            ktext = ktext[:ktext.find('local ' + blobm.group(1))]
        for m in KASSIGN_RE.finditer(ktext):
            key = constants.ev.try_evaluate(m.group(1), None)
            val_expr = m.group(2)
            val = constants.ev.try_evaluate(val_expr, None)
            if key is None or val is None:
                info['kvals'].setdefault('unparsed', []).append(
                    (val_expr, key, val))
                continue
            info['kvals'][int(key)] = float(val)
        # --- blob (string) constants ---------------------------------------
        if blobm:
            data_var, payload_lit = blobm.group(1), blobm.group(2)
            idxm = IDX_CALL_RE.search(seg)
            if idxm:
                idx_var, idx_lit = idxm.group(1), idxm.group(2)
                info['blob'] = (data_var, idx_var, payload_lit, idx_lit)
        # --- register init --------------------------------------------------
        rm = re.search(r'local (\w+)=\{\} (\w+)\[\(([^()]*)\)\]=\(([^()]*)\)',
                       seg[seg.find('pN65['):] if 'pN65[' in seg else seg)
        regvar = None
        mm = re.search(r'local (\w+)=\{\}\(?(?:local )?', seg[max(0, seg.find('=K end')):])
        fr = re.findall(r'(\w+)\[(\w+|\([^()]*\))\]=(\(\)?[^ ]+)', seg)
        # simpler: find the reg-init block known pattern 'activity'
        for m in re.finditer(r'local (\w+)=\{\}\1\[\(([^()]*)\)\]=(\(\)|\([^()]*\)|[\d.]+)\1?\[\(([^()]*)\)\]=(\(\)|\([^()]*\)|[\d.]+)', seg):
            info['reg_init'][int(constants.ev.try_evaluate(m.group(2), None))] =                 float(constants.ev.try_evaluate(m.group(3).strip('()'), None))
        # generic: all 'x[y]=z' lines right after 'local Xx={}' up to Gq38
        m0 = re.search(r'local (\w+)=\{\}\s*((?:\1\[[^\]]+\]=[^ ]+ )+)', seg)
        if m0:
            rv = m0.group(1)
            for kv in re.finditer(re.escape(rv) + r'\[((?:[^\[\]]*|\([^)]*\))+)\]=((?:\([^)]*\))|[\d.]+)', m0.group(2)):
                key = constants.ev.try_evaluate(kv.group(1), None)
                if key is None:
                    continue
                info['reg_init'][int(key)] = float(constants.ev.try_evaluate(kv.group(2).strip('()'), None) or 0)
            regvar = rv
        info['regvar'] = regvar
        # --- upvalue captures (may capture constants too) ---------------------
        for m in re.finditer(r'local (\w+)=\{\}\s*\1\[\(([^()]*)\)\]=(?:\(\)|\([^()]*\)|[\d.]+)', seg):
            info['reg_init'][int(constants.ev.try_evaluate(m.group(2), None))] = 0.0
        for m in re.finditer(r'local (\w+)=\{\}\s*\1\[\(([^()]*)\)\]=(\w+)\[\(([^()]*)\)\]', seg):
            info['upvals'].append((int(constants.ev.try_evaluate(m.group(2), None)),
                                   int(constants.ev.try_evaluate(m.group(4), None)),
                                   m.group(3)))
        # --- which Mz25 table this proto uses --------------------------------
        mmz = re.search(r'=Mz25\[\(([^()]*)\)\]', seg)
        info['table'] = int(constants.ev.try_evaluate(mmz.group(1), None)) if mmz else None
        protos[n] = info
    return protos


# ---------------------------------------------------------------------------
# Full assembly: loader + opcode map + proto metadata + string tables
# ---------------------------------------------------------------------------


def assemble(source: str, opcode_map_path: str = 'opcode_map.txt') -> dict:
    """Run every static layer and return a rich script description."""
    source, _roles = names.canonicalize(source)
    c = Constants(source)
    c.extract_jm()
    parameters = VMParameters(c)
    ops_from_source(source, c.ev)
    loader = Loader(source, c, parameters)
    tables = loader.run()
    protos = build_protos(source, c)

    alphabet = c.build_er60()
    km2 = c.build_km2()
    c864 = c.build_c864()

    from keb import StringTables
    sp = StringTables(source)
    blobs = sp.find_blobs(c.ev)
    string_tables = sp.decode_all(c.values, alphabet, km2, c864, blobs)

    # blob loop anchors sit inside one Z654 def span -> that proto's K strings
    anchor_to_proto = {}
    for n, info in protos.items():
        s, e = info['span']
        import keb as _keb
        for anchor in _keb.LOOP_ANCHOR_RE.finditer(source):
            if s <= anchor.start() < e:
                anchor_to_proto[anchor.group('idx')] = n
    for n, info in protos.items():
        info['strings'] = {}
    for blob in blobs:
        n = anchor_to_proto.get(blob.idx_var)
        if n is not None:
            protos[n]['strings'] = string_tables.get(blob.idx_var, {})

    # merged K tables per proto (numbers first, strings override where absent)
    for n, info in protos.items():
        merged = {}
        merged.update({int(k): v for k, v in info['kvals'].items()
                       if isinstance(k, int)})
        merged.update({int(k): v for k, v in info['strings'].items()})
        info['k'] = merged

    streams = {n: Stream(tables[info['table']], parameters)
               for n, info in protos.items()}
    instrs = {n: decode_stream(streams[n]) for n in sorted(protos)}
    return {'constants': c, 'parameters': parameters, 'loader': loader, 'tables': tables,
            'protos': protos, 'streams': streams, 'instrs': instrs}
