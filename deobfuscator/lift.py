# -*- coding: utf-8 -*-
"""
Lifter: VM disassembly -> clean Lua source (pass 4 of the deobfuscator).

Decode strategy, all static (no Lua execution):

- The streams contain only *forward* CJT/CJF jumps (verified during decoding),
  so every conditional compiles to ``if COND then <body> end`` followed by the
  merge code. Nested conditionals recurse with a register-state snapshot per
  branch body.
- A register holds either an inline pure expression or a materialized local
  ``vN``.  Pure ops (GETK/G521/LBOOL/LOADNIL/TNIL/UNOP/BINOP/GT/GETI/MOVE and
  the box-table ops) inline; side-effecting ops (CALL/CALLS/CLOS) always
  materialize (``local vN = call()``).
- Table constructions table-initialize as variables (not inline ``{}``) so the
  *identity* of created tables is preserved, and subsequent GETI/SIT access
  reuses the same object.
- At every conditional the registers written anywhere in the branch body are
  hoisted before the ``if`` (``local vN = <pure pre-if expr>`` or a bare
  ``local vN``).  Reads after the merge therefore see which value the taken
  path assigned - exactly the VM's persistent CC36 register semantics.
- ``ST``/``STI`` force materialization of the table register first.
- Method calls (``obj:Name(args)``) come from GT metadata (``ind_t``/``ind_key``
  captured when the callee was read) combined with the CALL whose first
  argument is the indexed object; the object is then dropped from args.
- Upvalues: a child proto's UGT/UST refer to the parent register named by the
  capture list; the parent materializes that register before creating the
  closure so the emitted function closes over a real local.
- Output targets Luau (Roblox): ``//`` and ``table.unpack`` are emitted as-is,
  since Kebabfuscator v1 outputs require Luau anyway (the ``2.5 // 1`` version
  gate proves the intended host is Luau).

Post passes for cleanliness:
- box peephole at source level: ``{X}[1]`` resolves to ``X`` whenever the box
  was built by an immediately preceding single-element TABLE1;
- unused-``local vN`` deletion (only when the initializer has no call).
"""
import re
import sys

import vm
from vm import fmt_num

INDENT = '    '

# op value -> (kind, params) lives in vm.OPS after parse_opcode_map ran.
# Gate on a load guard is kept minimal: importing lift alone does not decode.

def lift_source(source: str, opcode_map_path: str = 'opcode_map.txt') -> dict:
    """Full pipeline: assemble the VM image, then lift every proto."""
    data = vm.assemble(source, opcode_map_path)
    lifter = Lifter(data)
    return lifter.lift(), data


def lua_quote(s: str) -> str:
    """Render a Lua string literal with escapes (keeps output ASCII-safe)."""
    out = []
    for ch in s:
        if ch == '"':
            out.append('\\"')
        elif ch == '\\':
            out.append('\\\\')
        elif ch == '\n':
            out.append('\\n')
        elif ch == '\r':
            out.append('\\r')
        elif ch == '\t':
            out.append('\\t')
        elif ord(ch) < 32 or ord(ch) > 126:
            out.append('\\%03d' % ord(ch))
        else:
            out.append(ch)
    return '"%s"' % ''.join(out)


IDENT_OK = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')

# Lua keywords that may not follow '.' as a field name
KEYWORDS = {'and', 'break', 'do', 'else', 'elseif', 'end', 'false', 'for',
            'function', 'if', 'in', 'local', 'nil', 'not', 'or', 'repeat',
            'return', 'then', 'true', 'until', 'while'}


def field_ref(obj_text: str, key: str, is_const_str: bool) -> str:
    """Render obj[key] with a constant key."""
    if is_const_str and IDENT_OK.match(key) and key not in KEYWORDS:
        return '%s.%s' % (obj_text, key)
    if is_const_str:
        return '%s[%s]' % (obj_text, lua_quote(key))
    return '%s[%s]' % (obj_text, key)


def strip_outer_parens(s: str) -> str:
    """Remove redundant outer parentheses (balanced at the ends)."""
    s = s.strip()
    while len(s) >= 2 and s[0] == '(' and s[-1] == ')':
        depth = 0
        for i, ch in enumerate(s):
            if ch == '(':
                depth += 1
            elif ch == ')':
                depth -= 1
                if depth == 0:
                    break
        else:  # unbalanced - bail out
            break
        if depth != 0:
            break
        s = s[1:-1].strip()
    return s


def _balanced(s: str) -> bool:
    depth = 0
    for ch in s:
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
            if depth < 0:
                return False
    return depth == 0


def unparen1(s: str) -> str:
    """Strip exactly one balanced outer paren pair, if it spans the text.

    `(a ~= nil)` -> `a ~= nil`; `(a) + (b)` is left alone because the first
    pair already closes midway through the text.
    """
    s = s.strip()
    if len(s) >= 2 and s[0] == '(' and s[-1] == ')':
        depth = 1
        for ch in s[1:-1]:
            if ch == '(':
                depth += 1
            elif ch == ')':
                depth -= 1
                if depth == 0:
                    return s        # the pair closes too early: not a wrapper
        return s[1:-1].strip()
    return s


SIMPLE_EMBED = re.compile(
    r'^[A-Za-z_][A-Za-z0-9_]*'
    r'([.:][A-Za-z_][A-Za-z0-9_]*|\[[^]]+\])*$')


def embed(text: str) -> str:
    """Prepare a sub-expression for use as an index base / callee."""
    t = strip_outer_parens(text)
    if SIMPLE_EMBED.match(t) or t.endswith(')') or t.endswith(']'):
        return t
    return '(%s)' % t


def atomize(text: str) -> str:
    """Wrap a sub-expression in parentheses unless it is a lone atom."""
    t = strip_outer_parens(text)
    if SIMPLE_EMBED.match(t) or re.fullmatch(r'-?\d+(\.\d+)?', t) \
            or t.startswith('"') or t.endswith(']'):
        return t
    return '(%s)' % t


def is_pure_text(rhs: str) -> bool:
    """True when an initializer provably has no side effects (no calls)."""
    return '(' not in rhs


class Entry:
    """A register's current expression state."""
    __slots__ = ('mode', 'text', 'meta')

    def __init__(self, mode, text, meta=None):
        self.mode = mode          # 'expr' | 'var'
        self.text = text
        self.meta = meta or {}

    def clone(self):
        return Entry(self.mode, self.text, dict(self.meta))


# ---------------- human-style variable naming ----------------
#
# VM register numbers are meaningless, so every register gets a readable
# local name.  Evidence comes from the instruction stream: the class built
# by `Instance.new("Part")`, the service fetched by
# `game:GetService("RunService")`, the property a value is stored into
# (`Size = size`), `require("@lune/fs")` path tails, `pcall` result pairs.
# Registers without evidence get short filler names (a, b, c...).

RESERVED = set(KEYWORDS) | {
    # host globals and VM modules that must never be shadowed by a local
    '_G', 'print', 'type', 'typeof', 'pcall', 'select', 'setmetatable',
    'require', 'loadstring', 'unpack', 'game', 'workspace', 'Instance',
    'Vector3', 'CFrame', 'Enum', 'coroutine', 'task', 'bit32', 'debug',
    'Random', 'settings', 'table', 'string', 'math', 'os', 'io',
}


def lower_camel(s: str) -> str:
    return s[:1].lower() + s[1:] if s else s


def sanitize_name(s):
    """Candidate name -> Lua identifier, or None when unusable."""
    if not isinstance(s, str):
        return None
    s = re.sub(r'[^A-Za-z0-9_]', '', s)
    if not IDENT_OK.match(s) or s in RESERVED:
        return None
    return s


class NamePool:
    """Assigns unique local names for one proto scope."""

    def __init__(self, forbidden):
        self.used = set(forbidden)
        self._letters = list('abcdefghijklmnopqrstuvwxyz')
        self._li = 0
        self.map = {}

    def register(self, reg, preferred=None):
        """Bind reg to a name; returns it (also returns self.map[reg])."""
        if reg in self.map:
            return self.map[reg]
        name = sanitize_name(preferred)
        if name is None or name in self.used:
            base = name
            name = None
            k = 2
            while name is None and base is not None:
                if '%s%d' % (base, k) not in self.used:
                    name = '%s%d' % (base, k)
                k += 1
        while name is None:
            while self._li < len(self._letters):
                cand = self._letters[self._li]
                self._li += 1
                if cand not in self.used:
                    name = cand
                    break
            if name is None:
                k = 1
                while 'x%d' % k in self.used:
                    k += 1
                name = 'x%d' % k
        self.used.add(name)
        self.map[reg] = name
        return name


UNARY_TXT = {'not A': 'not ', '-A': '-', '#A': '#', 'bit32.bnot(A)': '~'}
BIN_TXT = {'A or B': ' or ', 'A and B': ' and ', 'A==B': '==', 'A~=B': '~=',
           'A<B': '<', 'A>B': '>', 'A<=B': '<=', 'A>=B': '>=',
           'bit32.bor(A,B)': '|', 'bit32.bxor(A,B)': '~',
           'bit32.band(A,B)': '&', 'bit32.rshift(A,B)': '>>',
           'bit32.lshift(A,B)': '<<', 'A..B': '..', 'A+B': '+',
           'A-B': '-', 'A*B': '*', 'A/B': '/', 'A%B': '%',
           'A//B': '//', 'A^B': '^'}


def def_regs(it):
    """Registers written by an instruction."""
    f = it.fields
    k = it.kind
    if k in ('MOVE', 'GETI', 'LOADNIL', 'LTAB', 'TABLE0', 'TABLE1', 'ANDI',
             'XORIM', 'LOADK', 'LBOOL', 'TNIL', 'VARG', 'VLEN', 'UNOP',
             'BINOP', 'GT', 'G521', 'UGT', 'GETG', 'GETK', 'CLOS'):
        return {f['r']}
    if k in ('ST', 'STI', 'UST', 'SETG'):
        return set()          # mutations, not defs
    if k in ('CALL', 'CALLS'):
        return set(f['dsts'])
    return set()


def written_regs(by_pc, lo, hi):
    """Over-approximate: registers written by any instruction with pc in [lo, hi)."""
    s = set()
    for pc in range(lo, hi):
        it = by_pc.get(pc)
        if it is not None:
            s |= def_regs(it)
    return s


def operand_regs(it):
    """Registers READ by an instruction (def families untouched readers)."""
    f = it.fields
    k = it.kind
    if k == 'MOVE':
        return {f['f']}
    if k == 'GETI':
        return {f['b']}
    if k == 'STI':
        return {f['b'], f['f']}
    if k == 'GT':
        return {f['t'], f['k']}
    if k == 'ST':
        return {f['t'], f['k'], f['v']}
    if k in ('BINOP',):
        return {f['a'], f['b']}
    if k == 'UNOP':
        return {f['a']}
    if k in ('ANDI', 'XORIM'):
        return {f['f']}
    if k == 'TNIL':
        return {f['v']}
    if k in ('CALL', 'CALLS'):
        return {f['f']} | set(f['args'])
    if k in ('CJT', 'CJF'):
        return {f['r']}
    if k == 'RETN':
        return set(f.get('args', []))
    if k == 'UST':
        return {f['f']}
    if k == 'TABLE1':
        return {f['f']}
    if k == 'VARG':
        return {f['ixr']}
    return set()


def used_after(by_pc, merge):
    """Registers read by any instruction located at pc >= merge (over-approx)."""
    s = set()
    for pc, it in by_pc.items():
        if pc >= merge:
            s |= operand_regs(it)
    return s


def mutated_bases(by_pc, lo, hi):
    """Table/box registers whose *contents* are mutated in [lo, hi).

    ST/STI/UST change the object a register points at rather than the register
    itself; after a conditional, such a register may no longer be described by
    its inline form, so the merge state must demote it to a plain variable.
    """
    s = set()
    for pc in range(lo, hi):
        it = by_pc.get(pc)
        if it is None:
            continue
        f = it.fields
        if it.kind == 'ST':
            s.add(f['t'])
        elif it.kind == 'STI':
            s.add(f['b'])
    return s


class Ctx:
    """Rendering state for one proto (with copy-on-branch snapshots)."""

    def __init__(self, data, px, names=None):
        self.d = data
        self.px = px
        self.info = data['protos'][px]
        self.by_pc = {it.pc: it for it in data['instrs'][px]}
        self.names = names or {}
        self.inline_calls = False
        self.upmap = {}
        self.active_loops = set()
        self.regmap = {}
        self.mutated = set()
        self.declared = set()

    def snapshot(self):
        c = Ctx.__new__(Ctx)
        c.d, c.px, c.info, c.by_pc = self.d, self.px, self.info, self.by_pc
        c.names = self.names
        c.inline_calls = self.inline_calls
        c.upmap = self.upmap.copy()
        c.active_loops = set(self.active_loops)
        c.regmap = {r: e.clone() for r, e in self.regmap.items()}
        c.mutated = set(self.mutated)
        c.declared = set(self.declared)
        return c

    def first_pc(self):
        return min(self.by_pc)


class Lifter:

    def __init__(self, data):
        self.d = data
        self.loops = {}
        for px, instrs in data['instrs'].items():
            loops = {}
            for backedge in instrs:
                if backedge.kind != 'JMP' or backedge.fields['t'] >= backedge.pc:
                    continue
                header = backedge.fields['t']
                guards = [
                    it for it in instrs
                    if header <= it.pc < backedge.pc
                    and it.kind in ('CJT', 'CJF')
                    and it.fields['t'] > backedge.pc
                ]
                if len(guards) != 1:
                    raise ValueError(
                        'unsupported loop shape in proto %d at pc %d'
                        % (px, header)
                    )
                if header in loops:
                    raise ValueError(
                        'multiple backedges for loop in proto %d at pc %d'
                        % (px, header)
                    )
                loops[header] = (backedge, guards[0])
            self.loops[px] = loops
        # who creates which closure: child px -> (parent px, parent reg)
        self.makers = {}
        for n, instrs in data['instrs'].items():
            for it in instrs:
                if it.kind == 'CLOS':
                    self.makers[it.fields['px']] = (n, it.fields['r'])
        # register-name plans per proto (ancestors planned before children,
        # and children reserve every visible ancestor name)
        self.nmap = {}
        anc = {}

        def ancestors(px):
            if px not in anc:
                parent = self.makers.get(px)
                anc[px] = [] if parent is None \
                    else ancestors(parent[0]) + [parent[0]]
            return anc[px]

        order = sorted(self.d['protos'],
                       key=lambda p: (len(ancestors(p)), p))
        for px in order:
            forbidden = set()
            for a in ancestors(px):
                forbidden |= set(self.nmap[a].values())
            self.nmap[px] = self.build_names(px, forbidden)
        # registers that become upvalue slots of closures made *inside* a
        # proto; such registers must never lose their local declaration
        self.captured = {}
        for child, info in self.d['protos'].items():
            maker = self.makers.get(child)
            if maker is None:
                continue
            parent_px = maker[0]
            regs = self.captured.setdefault(parent_px, set())
            for _slot, preg, _tag in info['upvals']:
                regs.add(preg)
        # how many times each register is assigned (for box folding)
        self.def_counts = {}
        for n, instrs in data['instrs'].items():
            counts = {}
            for it in instrs:
                for r in def_regs(it):
                    counts[r] = counts.get(r, 0) + 1
            self.def_counts[n] = counts

    def vn(self, ctx, reg):
        """Local Lua name for a register in ctx's own scope."""
        return ctx.names.get(reg) or ('v%d' % reg)

    def upval_decl(self, ctx, slot):
        """(text, parent_reg) for reading upvalue -> parent scope."""
        for s, preg, _tag in ctx.info['upvals']:
            if s == slot:
                parent_px = self.makers[ctx.px][0]
                names = self.nmap.get(parent_px, {})
                return '%s[1]' % names.get(preg, 'v%d' % preg), preg
        return None, None

    def build_names(self, px, forbidden):
        """Evidence-driven name plan for one proto."""
        info = self.d['protos'][px]
        by_pc = {it.pc: it for it in self.d['instrs'][px]}
        kinfo = info['k']

        def kstr(idx):
            v = kinfo.get(idx)
            return v if isinstance(v, str) else None

        defs = {}
        for it in by_pc.values():
            for r in def_regs(it):
                defs.setdefault(r, []).append(it.pc)

        def def_before(pc, reg):
            cand = [p for p in defs.get(reg, []) if p < pc]
            return by_pc.get(max(cand)) if cand else None

        pool = NamePool(forbidden)
        vec3_dst = set()
        for pc in sorted(by_pc):
            it = by_pc[pc]
            f = it.fields
            k = it.kind
            if k == 'CALL':
                dsts = f['dsts']
                callee = def_before(pc, f['f'])
                args = f['args'] or []
                a0idx = 0
                if callee is not None and callee.kind == 'GT' and len(args) > 1 \
                        and args[0] == callee.fields['t']:
                    a0idx = 1          # method call: args[0] is the self object
                a0 = args[a0idx] if len(args) > a0idx else None
                a0d = def_before(pc, a0) if a0 is not None else None
                a0s = kstr(a0d.fields['k']) \
                    if a0d is not None and a0d.kind == 'GETK' else None
                base_name = None
                if callee is not None and callee.kind == 'GT':
                    g5 = def_before(pc, callee.fields['t'])
                    if g5 is not None and g5.kind == 'G521':
                        base_name = self.gname(g5.fields['s'])
                    # the GT's key field is a register: resolve its GETK const
                    keydef = def_before(pc, callee.fields['k'])
                    key = kstr(keydef.fields['k']) \
                        if keydef is not None and keydef.kind == 'GETK' \
                        else None
                    if base_name == 'game' and key == 'GetService' and a0s:
                        pool.register(dsts[0], a0s)          # service: Pascal
                    elif base_name == 'Instance' and key == 'new' and a0s:
                        pool.register(dsts[0], lower_camel(a0s))
                    elif base_name == 'Vector3' and key == 'new':
                        vec3_dst.add(dsts[0])
                elif callee is not None and callee.kind == 'G521':
                    g = self.gname(callee.fields['s'])
                    if g == 'require' and a0s:
                        tail = a0s.rsplit('/', 1)[-1].lstrip('@')
                        pool.register(dsts[0], tail)         # 'fs', not '@lu'
                    elif g == 'pcall':
                        pool.register(dsts[0], 'ok')
                        if len(dsts) > 1:
                            pool.register(dsts[1], 'err')
                    elif g == 'setmetatable' and len(args) >= 2:
                        pool.register(args[0], 'tbl')
                        pool.register(args[1], 'mt')
                elif callee is None and a0s and a0s.startswith('@lune/'):
                    tail = a0s.rsplit('/', 1)[-1].lstrip('@')
                    pool.register(dsts[0], tail)
            elif k == 'ST':
                keydef = def_before(pc, f['k'])     # the key field is a reg
                key = kstr(keydef.fields['k']) \
                    if keydef is not None and keydef.kind == 'GETK' else None
                if key and len(key) <= 24 and IDENT_OK.match(key):
                    pool.register(f['v'], lower_camel(key))
        for pc in sorted(by_pc):
            for r in sorted(def_regs(by_pc[pc])):
                pool.register(r)
        return pool.map

    # ---------------- expression helpers ----------------
    def rtext(self, ctx, reg):
        """Text of a register's current value (inline expr or var)."""
        e = ctx.regmap.get(reg)
        if e is None:
            return self.vn(ctx, reg)
        return e.text

    def ktext(self, ctx, key):
        """K-table value as (text, is_const); info['k'] is merged."""
        v = ctx.info['k'].get(key)
        if isinstance(v, str):
            return lua_quote(v), True
        if isinstance(v, (int, float)):
            return fmt_num(v), True
        return 'nil', True

    def gname(self, s):
        return self.d['loader'].m521.get(s) or 'G%d' % s

    # ---------------- statement emission core ----------------
    def declare_var(self, ctx, lines, reg, init, meta=None):
        """Make reg a materialized local var holding init."""
        name = self.vn(ctx, reg)
        cur = ctx.regmap.get(reg)
        if name in ctx.declared:
            if init is not None and not (cur is not None
                                         and cur.mode == 'var'
                                         and cur.text == init):
                lines.extend(('%s = %s' % (name, init)).split('\n'))
        else:
            if init is None:
                lines.append('local %s' % name)
            else:
                lines.extend(('local %s = %s' % (name, init)).split('\n'))
            ctx.declared.add(name)
        ctx.regmap[reg] = Entry('var', name, meta or {})
        ctx.mutated.add(reg)

    def emit_assign(self, ctx, lines, reg, expr, meta=None, side_effect=False):
        """Assign expr to reg, inlining when safe or materializing."""
        cur = ctx.regmap.get(reg)
        if side_effect or reg in ctx.mutated or (cur is not None
                                                 and cur.mode == 'var'):
            self.declare_var(ctx, lines, reg, expr, meta)
        else:
            ctx.regmap[reg] = Entry('expr', expr, meta or {})

    # ---------------- main recursive renderer ----------------
    def render(self, ctx, start, stops):
        """Render instructions starting at start until a pc in stops.

        Returns *unprefixed* lines; the caller indents.  Stops on RETN
        (returns) or on a merge pc (returns without emitting it).
        """
        lines = []
        pc = start
        guard = 0
        while pc is not None and pc not in stops and guard < 500000:
            guard += 1
            it = ctx.by_pc.get(pc)
            if it is None:
                break
            f = it.fields
            k = it.kind

            loop = self.loops.get(ctx.px, {}).get(pc)
            if loop is not None and pc not in ctx.active_loops:
                pc = self.emit_loop(ctx, lines, pc, loop, stops)
                continue

            if k == 'RETN':
                args = [self.rtext(ctx, r) for r in f.get('args', [])]
                if args:
                    lines.append('return %s' % ', '.join(args))
                else:
                    lines.append('return')
                return lines

            if k in ('CJT', 'CJF'):
                merged = self.try_fold_guard(ctx, lines, it, stops)
                if merged is not None:
                    pc = merged
                    continue
                self.emit_branch(ctx, lines, it, stops)
                pc = f['t']  # all jumps are forward: target == merge
                continue

            if k == 'JMP':            # unconditional: skip the dead region
                pc = f['t']
                continue

            self.emit_stmt(ctx, lines, it)
            pc = it.next_pc
        return lines

    def emit_loop(self, ctx, lines, header, loop, stops):
        backedge, guard = loop
        exit_pc = guard.fields['t']
        lo = header
        hi = backedge.pc
        written = written_regs(ctx.by_pc, lo, hi) & used_after(
            ctx.by_pc, exit_pc
        )
        written |= mutated_bases(ctx.by_pc, lo, hi) & used_after(
            ctx.by_pc, exit_pc
        )
        self.hoist(ctx, lines, written)

        loop_ctx = ctx.snapshot()
        loop_ctx.active_loops.add(header)
        prefix = self.render(loop_ctx, header, stops | {guard.pc})
        condition = self.rtext(loop_ctx, guard.fields['r'])
        body = self.render(
            loop_ctx, guard.next_pc, stops | {backedge.pc, exit_pc}
        )
        exit_condition = '(%s)' % condition
        if guard.kind == 'CJF':
            exit_condition = 'not ' + exit_condition
        lines.append('while true do')
        lines.extend(INDENT + line for line in prefix)
        lines.append(INDENT + 'if %s then break end' % exit_condition)
        lines.extend(INDENT + line for line in body)
        lines.append('end')

        for reg in written:
            ctx.regmap[reg] = Entry('var', self.vn(ctx, reg))
            ctx.mutated.add(reg)
        return exit_pc

    # ---------------- humanisation: short-circuit guard folding ----------------
    #
    # The VM compiled "if A or B or C then return true end" (and the "and"
    # twin, sometimes with a register bridge) into:
    #   cond reg N = first condition
    #   recheck branch: if <N holds?> then N = next condition (end)
    #   [optional bridge: M = N]
    #   ... repeat ...
    #   final branch on the last register: if N then return true end
    # This folds the whole chain back into one condition expression.

    FOLD_KINDS = {'MOVE', 'GETK', 'G521', 'LOADNIL', 'LOADK', 'LBOOL',
                  'BINOP', 'UNOP', 'GT', 'GETI', 'TNIL', 'CALL'}

    def _read_counts(self, px):
        if not hasattr(self, '_rreads'):
            self._rreads = {}
        cache = self._rreads
        if px not in cache:
            counts = {}
            for it2 in self.d['instrs'][px]:
                for r in operand_regs(it2):
                    counts[r] = counts.get(r, 0) + 1
            cache[px] = counts
        return cache[px]

    def _recompute_expr(self, ctx, n, lo, hi):
        """Validate [lo, hi) as a pure recompute of register n.

        Returns (cond_text, temps, next_pc) or None.  Calls and closures are
        allowed because they are re-rendered inline (evaluated once, inside
        the folded guard condition - exactly when the recheck body ran).
        """
        by_pc = ctx.by_pc
        body = [by_pc[p] for p in sorted(k for k in by_pc if lo <= k < hi)]
        if not body or any(b2.kind not in self.FOLD_KINDS for b2 in body):
            return None
        temps = set()
        last = body[-1]
        if last.kind == 'MOVE':
            if last.fields['r'] != n:
                return None
            src = last.fields['f']
            if src == n:
                return None
            temps.add(src)
        elif n not in def_regs(last):
            return None
        for b2 in body[:-1]:
            t = def_regs(b2)
            if b2.kind == 'CALL' and len(b2.fields['dsts']) != 1:
                return None
            temps |= t - {n}
        if n in temps or len(temps) > 16:
            return None
        counts = self._read_counts(ctx.px)
        for t in temps:
            # the temp's every read must happen inside this body
            if counts.get(t, 0) != 1 \
                    or not any(t in operand_regs(b2) for b2 in body):
                return None
        if any(n in operand_regs(b2) for b2 in body):
            return None        # recompute must not depend on n itself
        sctx = ctx.snapshot()
        sctx.inline_calls = True
        scratch = []
        for b2 in body:
            self.emit_stmt(sctx, scratch, b2)
        if scratch or sctx.regmap.get(n) is None \
                or sctx.regmap[n].mode != 'expr':
            return None
        text = sctx.regmap[n].text
        if '\n' in text:
            return None            # closures etc. cannot join a cond line
        return text, temps

    def try_fold_guard(self, ctx, lines, it, stops):
        """Fold recheck-branch chains into one `if A op B op C` guard.

        The VM compiled guarded self-checks as: compute a cond reg N; a
        recheck branch whose body recomputes N; an optional MOVE bridge
        M = N; further rechecks; and a final branch on the last cond reg
        (usually `return true`).  The whole chain folds back into one
        condition when every consumed register's global read count equals
        exactly the reads the pattern performs - those registers are then
        provably dead after the fold, so nothing else can observe it.
        """
        by_pc = ctx.by_pc
        counts = self._read_counts(ctx.px)
        start_r = it.fields['r']
        cur = ctx.regmap.get(start_r)
        if cur is None:
            return None
        c1 = cur.text
        # `MOVE M = N` immediately before the first branch: the VM compiled
        # `x = a; if a then x = b end` for `x = a and b`, so the rechecks
        # rewrite the copy register while the tests still look at N.
        pre_m = None
        prevs = [p for p in by_pc if p < it.pc]
        if prevs:
            pv = by_pc[max(prevs)]
            if pv.kind == 'MOVE' and pv.fields['f'] == start_r \
                    and pv.fields['r'] != start_r \
                    and counts.get(pv.fields['r'], 0) <= 2:
                pre_m = pv
        if cur.mode != 'expr' and pre_m is None:
            return None
        pc = it.pc
        cur_n = start_r
        segments = []                    # (text, kind), rechecks after C1
        pattern_reads = {start_r: 0}
        seen_temps = set()
        final = None
        inversions = 0
        if pre_m is not None:
            pattern_reads[start_r] = 2   # pre-bridge copy read + branch test
            cur_n = pre_m.fields['r']
            pattern_reads[cur_n] = pattern_reads.get(cur_n, 0)
            fall, target = it.next_pc, it.fields['t']
            if fall >= target:
                return None
            got = self._recompute_expr(ctx, cur_n, fall, target)
            if got is None or (got[1] & seen_temps):
                return None
            seen_temps |= got[1]
            segments.append((got[0], it.kind))
            pc = target
        for _step in range(64):
            here = by_pc.get(pc)
            if here is None:
                return None
            if here.kind in ('CJT', 'CJF') and here.fields['r'] == cur_n:
                fall, target = here.next_pc, here.fields['t']
                if fall < target:
                    got = self._recompute_expr(ctx, cur_n, fall, target)
                    if got is not None:
                        text, temps = got
                        if not (temps & seen_temps):
                            seen_temps |= temps
                            segments.append((text, here.kind))
                            pattern_reads[cur_n] += 1
                            pc = target
                            continue
                # body not a recompute -> this branch is the final consumer
                if not segments:
                    return None      # first branch must yield a recheck
                pattern_reads[cur_n] += 1
                final = (pc, here)
                break
            if here.kind == 'MOVE' and here.fields['f'] == cur_n \
                    and here.fields['r'] != cur_n:
                nxt = by_pc.get(here.next_pc)
                if nxt is not None and nxt.kind in ('CJT', 'CJF') \
                        and nxt.fields['r'] == here.fields['r']:
                    pattern_reads[cur_n] += 1
                    cur_n = here.fields['r']
                    pattern_reads.setdefault(cur_n, 0)
                    pc = here.next_pc
                    continue
            # `q = not M` between the last recheck and the final consumer:
            # the consumer tests q, so fold the negation into the value
            if here.kind == 'UNOP' and here.fields['a'] == cur_n \
                    and (UNARY_TXT.get(here.params['ops']
                                      .get(here.fields['o'], '')) or ''
                         ).strip() == 'not':
                nxt = by_pc.get(here.next_pc)
                if nxt is not None and nxt.kind in ('CJT', 'CJF') \
                        and nxt.fields['r'] == here.fields['r']:
                    pattern_reads[cur_n] += 1
                    cur_n = here.fields['r']
                    pattern_reads.setdefault(cur_n, 0)
                    inversions += 1
                    pc = here.next_pc
                    continue
            return None
        end_pc, consumer = final
        # every consumed register must be read nowhere else in the proto
        if any(counts.get(r, 0) != v for r, v in pattern_reads.items()):
            return None
        if self.captured.get(ctx.px, set()) & set(pattern_reads):
            return None
        # left-assoc join; parenthesize the accumulated value when the
        # operator changes so Lua's `and`-before-`or` precedence holds
        value = unparen1(c1)
        prev_op = None
        for text, kind in segments:
            op2 = ' or ' if kind == 'CJT' else ' and '
            if prev_op is not None and prev_op != op2:
                value = '(%s)' % value
            value = value + op2 + unparen1(text)
            prev_op = op2
        if inversions % 2 == 1:
            value = 'not (%s)' % value     # consumed `q = not M` step
        ctx.regmap[cur_n] = Entry('expr', '(%s)' % value)
        self.emit_branch(ctx, lines, consumer, stops)
        return consumer.fields['t']

    def emit_branch(self, ctx, lines, it, stops):
        """Compile one forward CJT/CJF into `if COND then <body> end`."""
        f = it.fields
        fall, target = it.next_pc, f['t']
        cond = self.rtext(ctx, f['r'])
        # "then" runs on the fall-through path (the jump skips it)
        base = unparen1(cond)
        if it.kind == 'CJT':
            cond_txt = 'not %s' % base if _atom_expr(base) \
                else 'not %s' % atomize(cond)
        else:
            cond_txt = base
        if cond_txt.startswith('not not '):
            cond_txt = cond_txt[8:]     # fold `not not X` -> `X`
        elif cond_txt.startswith('not (not ') and cond_txt.endswith(')'):
            inner = cond_txt[9:-1]
            if _balanced(inner):
                cond_txt = inner        # fold `not (not X)` -> `X`
        if fall >= target:
            return                       # empty branch: nothing to execute
        wr = written_regs(ctx.by_pc, fall, target) & used_after(ctx.by_pc,
                                                                target)
        wr |= mutated_bases(ctx.by_pc, fall, target) & used_after(ctx.by_pc,
                                                                  target)
        self.hoist(ctx, lines, wr)
        body_ctx = ctx.snapshot()
        body = self.render(body_ctx, fall, stops | {target})
        if body:
            lines.append('if %s then' % cond_txt)
            lines.extend(INDENT + b for b in body)
            lines.append('end')
        for r in sorted(wr):
            ctx.regmap[r] = Entry('var', self.vn(ctx, r))
            ctx.mutated.add(r)

    def hoist(self, ctx, lines, regs):
        """Materialize pre-if values of branch-written registers.

        Skips registers that are already live variables in scope (mutated or
        var-mode entries).  Fresh registers become bare locals initialised to
        nil, matching the VM's zero-initialized registers.
        """
        for r in sorted(regs):
            name = self.vn(ctx, r)
            e = ctx.regmap.get(r)
            if r in ctx.mutated or (e is not None and e.mode == 'var'):
                continue      # already a live variable in scope
            if e is not None and e.text is not None:
                init = e.text
            else:
                init = None
            self.declare_var(ctx, lines, r, init)
            ctx.regmap[r] = Entry('var', name)

    # ---------------- per-instruction families ----------------
    def emit_stmt(self, ctx, lines, it):
        f = it.fields
        k = it.kind
        # NOTE: every def family routes through emit_assign so that a register
        # which already exists as a materialized variable (hoisted/mutated)
        # receives a real `vN = expr` statement instead of silently losing it.
        if k == 'MOVE':
            src = self.rtext(ctx, f['f'])
            src_e = ctx.regmap.get(f['f'])
            self.emit_assign(ctx, lines, f['r'], src,
                             dict(src_e.meta) if src_e else {})
        elif k == 'GETK':
            kt, is_const = self.ktext(ctx, f['k'])
            kk = ctx.info['k'].get(f['k'])
            self.emit_assign(ctx, lines, f['r'], kt,
                             {'const_str': is_const and isinstance(kk, str)})
        elif k == 'G521':
            self.emit_assign(ctx, lines, f['r'], self.gname(f['s']),
                             {'const_str': True})
        elif k == 'LOADNIL':
            self.emit_assign(ctx, lines, f['r'], 'nil')
        elif k == 'LBOOL':
            val = 'true' if f['v'] == it.params.get('test', 1) else 'false'
            self.emit_assign(ctx, lines, f['r'], val)
        elif k == 'TNIL':
            t = self.rtext(ctx, f['v'])
            self.emit_assign(ctx, lines, f['r'], '(%s == nil)' % t)
        elif k == 'LOADK':
            self.emit_assign(ctx, lines, f['r'], fmt_num(it.params['value']))
        elif k in ('ANDI', 'XORIM'):
            ft = atomize(self.rtext(ctx, f['f']))
            d = fmt_num(it.params['default'])
            o = fmt_num(f['o'])
            if k == 'ANDI':
                expr = 'bit32.band(%s or %s, %s)' % (ft, d, o)
            else:
                mask = fmt_num(it.params['mask'])
                expr = 'bit32.band(bit32.bxor(%s or %s, %s), %s)' % (ft, d, o, mask)
            self.emit_assign(ctx, lines, f['r'], expr)
        elif k in ('TABLE0', 'TABLE1'):
            # Fresh table identity must survive: materialize as a variable.
            if k == 'TABLE1' and f['f'] != 0:
                src = self.rtext(ctx, f['f'])
                src_e = ctx.regmap.get(f['f'])
                self.emit_assign(ctx, lines, f['r'], '{%s}' % src,
                                 {'elem': src, 'elem_reg': f['f'],
                                  'elem_var': src_e is not None
                                  and src_e.mode == 'var'},
                                 side_effect=True)
            else:
                self.emit_assign(ctx, lines, f['r'], '{}', {}, side_effect=True)
        elif k == 'LTAB':
            # Body: r=imm; t={} ; t[r_written] = old CC36[r]; CC36[r] = t.
            # Not present in the sample stream; keep a faithful fallback.
            old = self.rtext(ctx, f['r'])
            name = self.vn(ctx, f['r'])
            lines.append('local %s = {[%d] = %s}' % (name, f['r'], old))
            ctx.declared.add(name)
            ctx.regmap[f['r']] = Entry('var', name)
            ctx.mutated.add(f['r'])
        elif k == 'GETI':
            elem = self.box_elem(ctx, f['b'], it.params['const'])
            if elem is not None:
                self.emit_assign(ctx, lines, f['r'], elem)
            else:
                base = self.index_base(ctx, f['b'])
                self.emit_assign(ctx, lines, f['r'],
                                 '%s[%d]' % (base, it.params['const']))
        elif k == 'GT':
            base = self.index_base(ctx, f['t'])
            key, is_const = self.key_text(ctx, f['k'])
            if is_const:
                expr = field_ref(base, key, True)
                meta = {'ind_reg': f['t'], 'ind_key': key}
            else:
                expr = '%s[%s]' % (base, key)
                meta = {}
            self.emit_assign(ctx, lines, f['r'], expr, meta)
        elif k == 'ST':
            self.remat_before(ctx, lines, f['t'])
            base = self.index_base(ctx, f['t'])
            key, is_const = self.key_text(ctx, f['k'])
            lhs = field_ref(base, key, True) if is_const \
                else '%s[%s]' % (base, key)
            lines.append('%s = %s' % (lhs, atomize(self.rtext(ctx, f['v']))))
            ctx.mutated.add(f['t'])
            ctx.regmap[f['t']] = Entry('var', self.vn(ctx, f['t']))
        elif k == 'STI':
            self.remat_before(ctx, lines, f['b'])
            base = self.index_base(ctx, f['b'])
            lines.append('%s[%d] = %s'
                         % (base, it.params['const'],
                            atomize(self.rtext(ctx, f['f']))))
            ctx.mutated.add(f['b'])
            ctx.regmap[f['b']] = Entry('var', self.vn(ctx, f['b']))
        elif k == 'UNOP':
            a = atomize(self.rtext(ctx, f['a']))
            u = UNARY_TXT.get(it.params['ops'].get(f['o'], ''))
            if u is None:
                lines.append('-- unhandled unop o=%d' % f['o'])
                u = ''
            op = u if u.endswith(' ') or u in ('-', '#', '~') else u + ' '
            self.emit_assign(ctx, lines, f['r'], '(%s%s)' % (op, a))
        elif k == 'BINOP':
            a = self.rtext(ctx, f['a'])
            b = self.rtext(ctx, f['b'])
            sym = BIN_TXT.get(it.params['ops'].get(f['o'], ''), '?')
            self.emit_assign(ctx, lines, f['r'], '(%s %s %s)' % (a, sym, b))
        elif k == 'CALL':
            self.emit_call(ctx, lines, it)
        elif k == 'CALLS':
            self.emit_calls(ctx, lines, it)
        elif k == 'CLOS':
            self.emit_clos(ctx, lines, it)
        elif k == 'UGT':
            if f['x'] in ctx.upmap:
                # one-cell upvalue boxes collapse to the parent variable
                self.emit_assign(ctx, lines, f['r'], ctx.upmap[f['x']])
            else:
                self.emit_assign(ctx, lines, f['r'],
                                 self.upval_decl(ctx, f['x'])[0])
        elif k == 'UST':
            preg = self.upval_decl(ctx, f['x'])[0]
            lines.append('%s = %s' % (preg, atomize(self.rtext(ctx, f['f']))))
            ctx.mutated.add(preg)
        elif k == 'GETG':
            kt, _ = self.ktext(ctx, f['k'])
            self.emit_assign(ctx, lines, f['r'], '_G[%s]' % kt)
        elif k == 'SETG':
            kt, _ = self.ktext(ctx, f['k'])
            lines.append('_G[%s] = %s' % (kt, atomize(self.rtext(ctx, f['r']))))
        elif k == 'VARG':
            self.emit_assign(ctx, lines, f['r'],
                             '(select(%s, ...))' % atomize(self.rtext(ctx, f['ixr'])))
        elif k == 'VLEN':
            self.emit_assign(ctx, lines, f['r'], "select('#', ...)")
        else:
            lines.append('-- UNHANDLED %s %s' % (k, f))

    # ---------------- helpers used by the families ----------------
    def box_elem(self, ctx, base_reg, const):
        """Single-element box peephole: {X}[const] == X when const == 1."""
        if const != 1:
            return None
        e = ctx.regmap.get(base_reg)
        if e is not None and e.meta.get('elem') is not None:
            return e.meta['elem']
        return None

    def index_base(self, ctx, reg):
        return embed(self.rtext(ctx, reg))

    def key_text(self, ctx, reg):
        """Key held in a register: ('name', True) when a const string literal.

        GETK loads the key register with a quoted literal; GT/ST then index
        with it, so `R8["Shape"]` should render as the dot-form `R8.Shape`.
        """
        s = self.rtext(ctx, reg)
        e = ctx.regmap.get(reg)
        if (e is not None and e.mode == 'expr' and e.meta.get('const_str')
                and len(s) >= 2 and s[0] == '"' and s[-1] == '"'):
            return s[1:-1], True
        return s, False

    def remat_before(self, ctx, lines, reg):
        """If reg holds an inline expr but is about to be mutated, materialize."""
        e = ctx.regmap.get(reg)
        if e is None or e.mode == 'var':
            if e is not None and reg not in ctx.mutated:
                ctx.mutated.add(reg)
            return
        self.declare_var(ctx, lines, reg, e.text, dict(e.meta))

    # ---------------- calls ----------------
    def emit_call(self, ctx, lines, it):
        f = it.fields
        callee_e = ctx.regmap.get(f['f'])
        callee = self.rtext(ctx, f['f'])
        args = [self.rtext(ctx, a) for a in f['args']]
        meth = False
        if (callee_e is not None and callee_e.mode == 'expr'
                and callee_e.meta.get('ind_reg') is not None
                and f['args'] and f['args'][0] == callee_e.meta['ind_reg']):
            # method call: the indexed object is argument #1
            key = callee_e.meta['ind_key']
            callee = '%s:%s' % (self.rtext(ctx, f['args'][0]), key)
            meth = True
        argtxt = ', '.join(atomize(a) for a in (args[1:] if meth else args))
        call = '%s(%s)' % (embed(callee), argtxt)
        if f['nr'] == 0:
            lines.append(call)
        else:
            self.emit_call_dsts(ctx, lines, f['dsts'], call)

    def emit_call_dsts(self, ctx, lines, dsts, call):
        names = [self.vn(ctx, d) for d in dsts]
        if getattr(ctx, 'inline_calls', False):
            for d in dsts:
                ctx.regmap[d] = Entry('expr', call)
            return True                       # folded: inlined into a guard
        if len(names) == 1:
            self.emit_assign(ctx, lines, dsts[0], call, side_effect=True)
            return False
        if all(nm in ctx.declared for nm in names):
            lines.append('%s = %s' % (', '.join(names), call))
            for i, d in enumerate(dsts):
                ctx.regmap[d] = Entry('var', names[i])
            return False
        lines.append('local %s = %s' % (', '.join(names), call))
        for i, d in enumerate(dsts):
            ctx.declared.add(names[i])
            ctx.regmap[d] = Entry('var', names[i])
        return False

    def emit_calls(self, ctx, lines, it):
        f = it.fields
        callee = self.rtext(ctx, f['f'])
        args = [self.rtext(ctx, a) for a in f['args']]
        spread = 'table.unpack(%s, %s, %s)' % (
            self.index_base(ctx, f['sT']),
            atomize(self.rtext(ctx, f['sA'])),
            atomize(self.rtext(ctx, f['sB'])))
        argtxt = ', '.join(atomize(a) for a in args)
        full_args = ('%s, %s' % (argtxt, spread)) if argtxt else spread
        call = '%s(%s)' % (embed(callee), full_args)
        if f['nr'] == 0:
            lines.append(call)
        else:
            self.emit_call_dsts(ctx, lines, f['dsts'], call)

    # ---------------- closures ----------------
    def emit_clos(self, ctx, lines, it):
        f = it.fields
        child_info = self.d['protos'][f['px']]
        child_instrs = self.d['instrs'][f['px']]
        upmap = {}
        for slot, preg, _tag in child_info['upvals']:
            # Guarantee the captured parent registers are real locals now.
            e = ctx.regmap.get(preg)
            if e is None or e.mode == 'expr':
                self.remat_before(ctx, lines, preg)
            # one-cell `{src}` boxes: let the child read src directly, then
            # the (unread) box declaration is dropped by the cleanup pass.
            # Safe when: element reference is a plain variable, its source
            # register is assigned exactly once, and the child never writes
            # the upvalue slot.
            e = ctx.regmap.get(preg)
            if e is None or e.mode != 'var':
                continue
            elem = e.meta.get('elem')
            if elem is None or not IDENT_OK.match(elem) \
                    or not e.meta.get('elem_var'):
                continue
            counts = self.def_counts.get(ctx.px, {})
            if counts.get(e.meta.get('elem_reg', -1), 0) != 1:
                continue
            if any(i2.kind == 'UST' and i2.fields['x'] == slot
                   for i2 in child_instrs):
                continue
            upmap[slot] = elem
        cctx = Ctx(self.d, f['px'], names=self.nmap.get(f['px'], {}))
        cctx.upmap = upmap
        body = self.render(cctx, cctx.first_pc(), set())
        # clean the child body BEFORE embedding: the cleanup passes are
        # line-based and sibling protos reuse filler names, so scope-local
        # cleanup is both cheaper and safer here
        body = clean_output('\n'.join(body)).split('\n')
        text = 'function()\n' + '\n'.join(INDENT + b for b in body) + '\nend'
        self.emit_assign(ctx, lines, f['r'], text, side_effect=True)

    # ---------------- top level ----------------
    def lift(self):
        texts = {}
        original_limit = sys.getrecursionlimit()
        required_limit = max(
            original_limit,
            sum(len(instrs) for instrs in self.d['instrs'].values()) * 8 + 1000,
        )
        if required_limit > original_limit:
            sys.setrecursionlimit(required_limit)
        try:
            for px in sorted(self.d['protos']):
                ctx = Ctx(self.d, px, names=self.nmap.get(px, {}))
                body = self.render(ctx, ctx.first_pc(), set())
                texts[px] = clean_output('\n'.join(body))
        finally:
            if required_limit > original_limit:
                sys.setrecursionlimit(original_limit)
        entries = [px for px in sorted(self.d['protos']) if px not in self.makers]
        return {'protos': texts, 'entry': entries[0] if entries else None,
                'main': texts.get(entries[0]) if entries else ''}


# ---------------- output cleanup passes ----------------

def strip_unused_locals(text: str) -> str:
    # Pass A: turn discarded-result call assignments into plain statements.
    #          `local a[, b] = <call>` where no name is used afterwards.
    lines = text.split('\n')
    changed = True
    while changed:
        changed = False
        for i, ln in enumerate(lines):
            m = re.match(r'^(\s*)local (\w+(?:, \w+)*) = (.+)$', ln)
            if not m:
                continue
            name_list = [n.strip() for n in m.group(2).split(',')]
            rhs = m.group(3)
            # only convert call statements; never bare values / table literals
            if not re.match(r'^[\w\.\:\[\]\"]+\s*\(', rhs):
                continue
            if any(re.search(r'\b%s\b' % re.escape(n), l2)
                   for n in name_list
                   for j, l2 in enumerate(lines) if j != i):
                continue
            lines[i] = m.group(1) + rhs
            changed = True
            break
    # Pass B: delete unused declarations.
    lines = '\n'.join(lines).split('\n')
    changed = True
    while changed:
        changed = False
        for i, ln in enumerate(lines):
            m = re.match(r'^(\s*)local (\w+)(?: = (.+))?$', ln)
            if not m:
                continue
            name, rhs = m.group(2), m.group(3)
            if rhs is not None and not is_pure_init(rhs):
                continue
            if rhs is not None and re.search(r'\b%s\b' % re.escape(name), rhs):
                continue
            uses = sum(1 for l2 in lines
                       if re.search(r'\b%s\b' % re.escape(name), l2))
            if uses == 1:
                del lines[i]
                changed = True
                break
    # Pass C: merge `local base = x` + `base.Prop = ...` copy chains into
    #         writes on x directly (register copies alias the same object).
    changed = True
    while changed:
        changed = False
        for i, ln in enumerate(lines):
            m = re.match(r'^(\s*)local (\w+) = (\w+)$', ln)
            if not m:
                continue
            alias, src = m.group(2), m.group(3)
            if alias == src:
                continue
            uses = [(j, l2) for j, l2 in enumerate(lines)
                    if j != i and re.search(r'\b%s\b' % re.escape(alias), l2)]
            if not uses or not all(
                    re.match(r'^(\s*)%s([.\[])' % re.escape(alias), l2)
                    for _j, l2 in uses):
                continue
            for j, l2 in uses:
                lines[j] = re.sub(
                    r'^(\s*)%s' % re.escape(alias),
                    r'\g<1>%s' % src, l2)
            del lines[i]
            changed = True
            break
    # Pass E: splice a single-use closure into its only call site, e.g.
    #         `local fn = function() ... end` + `local ok = pcall(fn)` becomes
    #         `local ok = pcall(function() ... end)` with the same capture
    #         scope (the use follows the closure's `end` immediately).
    echanged = True
    while echanged:
        echanged = False
        for i, ln in enumerate(lines):
            md = re.match(r'^(\s*)local (\w+) = function\(\)$', ln)
            if not md:
                continue
            indent, name = md.groups()
            j = None
            for k2 in range(i + 1, len(lines)):
                if lines[k2] == indent + 'end':
                    j = k2
                    break
                if lines[k2].startswith(indent + 'end'):
                    break          # scope closed before our closure's end
            if j is None:
                continue
            if any(re.search(r'\b%s\b' % re.escape(name), b2)
                   for b2 in lines[i + 1:j]):
                continue
            uses = [(u, l2) for u, l2 in enumerate(lines)
                    if u != i and u > j
                    and re.search(r'\b%s\b' % re.escape(name), l2)]
            if len(uses) != 1 or uses[0][0] != j + 1:
                continue
            uline = uses[0][1]
            # splice forms: `local ns = callee(X)`, bare `callee(X)`,
            # `return callee(X)` and `if [not] callee(X) then`
            pre, post = None, None
            mu = re.match(r'^(\s*)local ([\w, ]+?) = ([\w\.]+)\(%s\)$'
                          % re.escape(name), uline)
            if mu:
                cindent, prefix, callee = mu.group(1), 'local %s = ' \
                    % mu.group(2), mu.group(3)
            else:
                mu = re.match(r'^(\s*)if (not )?([\w\.]+)\(%s\) then$'
                              % re.escape(name), uline)
                if mu:
                    cindent, callee = mu.group(1), mu.group(3)
                    prefix = 'if %s' % ('not ' if mu.group(2) else '')
                    post = ' then'
                else:
                    mu = re.match(r'^(\s*)(return )?([\w\.]+)\(%s\)$'
                                  % re.escape(name), uline)
                    if mu:
                        cindent, callee = mu.group(1), mu.group(3)
                        prefix = mu.group(2) or ''
                    else:
                        continue
            if callee == 'function':
                continue
            lines[i] = indent + prefix + callee + '(function()'
            lines[j] = indent + 'end)' + (post or '')
            del lines[j + 1]
            echanged = True
            break
    # Pass D: inline `local x = init` + its single adjacent use.  In
    #         straight-line code the initializer's evaluation order is
    #         unchanged, and one-use guarantee keeps no other reader behind.
    dchanged = True
    while dchanged:
        dchanged = False
        for i, ln in enumerate(lines):
            m = re.match(r'^(\s*)local (\w+) = (.+)$', ln)
            if not m:
                continue
            name, init = m.group(2), m.group(3)
            if init.startswith('function') or init.startswith('{') \
                    or re.search(r'\b%s\b' % re.escape(name), init):
                continue
            pat = re.compile(r'\b%s\b' % re.escape(name))
            hits = [j for j, l2 in enumerate(lines)
                    if j != i and pat.search(l2)]
            if len(hits) != 1 or hits[0] != i + 1:
                continue
            j = hits[0]
            mt2 = pat.search(lines[j])
            if mt2 is None:
                continue
            repl = init if _atom_expr(init) else '(%s)' % init
            lines[j] = lines[j][:mt2.start()] + repl + lines[j][mt2.end():]
            del lines[i]
            dchanged = True
            break
    return '\n'.join(lines)


_PURE_TABLE = re.compile(r'^\{[^{}]*\}$')
_CALL_IN = re.compile(r'[\w\)\]]\s*\(')


def is_pure_init(rhs: str) -> bool:
    """True when an initializer provably has no side effects.

    Plain expressions keep the parent rule (no parens at all); short table
    constructors are also pure when their contents contain no call syntax
    (allocation alone is unobservable in Lua).
    """
    if is_pure_text(rhs):
        return True
    if _PURE_TABLE.match(rhs) and not _CALL_IN.search(rhs[1:-1]):
        return True
    return False


def _atom_expr(s: str) -> bool:
    """True when s can splice unwrapped into any expression position.

    That means: a call/field/index chain (or literal) with no operators at
    paren-depth 0 - only identifiers, the dot/colon/index/call suffixes and
    balanced groups.  An optional leading `not ` keeps boolean guards clean.
    """
    if s.startswith('not '):
        return _atom_expr(s[4:])
    depth = 0
    for ch in s:
        if ch in '([{':
            depth += 1
        elif ch in ')]}':
            depth -= 1
            if depth < 0:
                return False
        elif depth == 0 and not (ch.isalnum() or ch in '._:"'):
            return False
    return depth == 0


def clean_output(text: str) -> str:
    text = strip_outer_parens_pass(text)
    text = strip_unused_locals(text)
    return text


# only collapse parentheses that are pure groupings, never call-syntax:
# the char before '(' must not continue an identifier/call ('x(', '.(', ':('...)
_CALL_GUARD = re.compile(r'(?<![\w\.\:\)\]])\((\w+|true|false|nil)\)')


def strip_outer_parens_pass(text: str) -> str:
    return _CALL_GUARD.sub(r'\1', text)
