"""Identifier canonicalization for Kebabfuscator v1 outputs.

Every obfuscator run regenerates its internal identifiers (the 32 seed
constants, the crypto helper functions, the VM register/stream/table names)
while keeping the *structure* of the emitted program identical.  This module
recognises each identifier's role from its unique structural context and
rewrites the source so the rest of the decoder can keep using the canonical
names the pipeline was built around:

    seeds      jm1..jm32 + jm<letter> block (f,s,t,u,w)
    crypto     oE55 (base85), CA56 (index fold), Nx58 (stream cipher),
               rc57 (cipher over base85 input), j915 (self-mod key),
               JN10 (chained RNG), NS14 (dispatch key), pW17/Ww18
               (digit pack/unpack), bc19 (stream reader), Ox20 (char decode)
    loader     Mz25 (digit tables), Pq28 (loader RNG seed), Mt22 (name
               payload), Bk23/YN24 (op streams), M521 (global-name slots),
               pN65 (string tables), Z654 (closure table)
    keys       Km2 (chained byte key), Wx1 (key bytes), c864 (blob XOR)
    char set   P94 (code table), kP5 (char string), tK6 (char map),
               yL61 (extra alphabet codes), jB59 (alphabet string),
               Er60 (alphabet map), qf16 (VM op seed), H77/Tz8/DQ9
               (JN10 constants), Yj11/vf12/ka13 (NS14 constants)
    VM         c435 (dispatcher) with parameters CC36, r837, Gq38, SM39,
               M521, Ln40, R549 and locals kS41, hN42, NL46, P847, OH48,
               LY43, Ca44, qx45, Gg50, J151, Te52

Recognition anchors on fixed text shapes that are identical between runs;
only the identifiers themselves differ.  Encrypted string payloads are never
rewritten (renaming bytes inside an encrypted blob would corrupt the data).
"""

import re

SEED_COUNT = 32
SEED_LETTERS = ('f', 's', 't', 'u', 'w')


def resolve(source: str) -> dict:
    """Map canonical role names to the identifiers used in ``source``.

    Roles the source does not exhibit are simply absent, so callers can
    handle partial synthetic files.  A raised ``ValueError`` means the file
    no longer matches the obfuscator template the decoder understands.
    """
    r: dict = {}

    # -- numeric seed family -------------------------------------------------
    first_pos: dict = {}
    for m in re.finditer(r'\blocal ([A-Za-z_][A-Za-z0-9_]*)\s*=', source):
        first_pos.setdefault(m.group(1), m.start())
    split: dict = {}
    for nm, pos in first_pos.items():
        mm = re.fullmatch(r'([A-Za-z_]+?)(\d+)', nm)
        if mm:
            split.setdefault(mm.group(1), {})[int(mm.group(2))] = pos
    seed_names: set = set()
    for family, members in split.items():
        if all(index in members for index in range(1, SEED_COUNT + 1)):
            for index in members:
                seed_names.add(family + str(index))
            for letter in SEED_LETTERS:
                if family + letter in first_pos:
                    seed_names.add(family + letter)
    for pfx, members in split.items():
        if all(index in members for index in range(1, SEED_COUNT + 1)):
            r['SEED_PREFIX'] = pfx
            break
    pfx = r.get('SEED_PREFIX')
    if pfx:
        for letter in SEED_LETTERS:
            if pfx + letter in first_pos:
                r['jm' + letter] = pfx + letter

    # -- base-85 decoder and the index fold -----------------------------------
    m = re.search(r'local function (\w+)\(s\)local o=\{\}for i=\(', source)
    if m:
        r['oE55'] = m.group(1)
    if 'oE55' in r:
        m = re.search(r'local function (\w+)\(s\)local b=' +
                      re.escape(r['oE55']) + r'\(s\)local o=\{\}for i=\(',
                      source)
        if m:
            r['CA56'] = m.group(1)

    # -- stream cipher functions ----------------------------------------------
    m = re.search(r'local function (\w+)\(b,sd,ix\) sd=bit32\.bxor\(sd,(\w+)\)'
                  r' local ln=#b', source)
    if m:
        r['Nx58'] = m.group(1)
        r.setdefault('Km2', m.group(2))
    m = re.search(r'local function (\w+)\(b,sd,ix\) sd=bit32\.bxor\(sd,\w+\)'
                  r' b=(\w+)\(b\) local ln=#b', source)
    if m:
        r['rc57'] = m.group(1)
        r.setdefault('oE55', m.group(2))

    # -- stream reader helpers -------------------------------------------------
    m = re.search(r'local function (\w+)\(b,n\)return function\(p\)', source)
    if m:
        r['bc19'] = m.group(1)
    m = re.search(r'local function (\w+)\(b,p\)local v=', source)
    if m:
        r['Ww18'] = m.group(1)
    m = re.search(r'local function (\w+)\(b,q,w\)local v=w', source)
    if m:
        r['pW17'] = m.group(1)

    # -- char table (tK6 family) -----------------------------------------------
    m = re.search(r'local (\w+)="" local (\w+)=\{\} for (\w+)=\([^()]*\),'
                  r'#(\w+) do \1=\1\.\.string\.char\(\4\[\3\]\) ?end for '
                  r'\3=\([^()]*\),#\1 do \2\[string\.sub\(\1,\3,\3\)\]='
                  r'\3-\(([^()]*)\) ?end', source)
    if m:
        r['kP5'] = m.group(1)
        r['tK6'] = m.group(2)
        r['P94'] = m.group(4)

    # -- alphabet string, extra codes, alphabet map ------------------------------
    m = re.search(r'local (\w+)="" for (\w+)=\([^()]*\),\([^()]*\)'
                  r' do \1=\1\.\.string\.char\(\2\) ?end', source)
    if m:
        r['jB59'] = m.group(1)
        jba = re.escape(m.group(1))
        m = re.search(r'local (\w+)=\{([^{}]+)\} for (\w+)=\([^()]*\),#\1 do '
                      r'%s=%s\.\.string\.char\(\1\[\3\]\) ?end' % (jba, jba),
                      source)
        if m:
            r['yL61'] = m.group(1)
        m = re.search(r'local (\w+)=\{\} for \w+=\([^()]*\),#' + jba +
                      r' do \1\[%s:sub\(\w+,\w+\)\]=\w+-\(([^()]*)\) ?end'
                      % jba, source)
        if m:
            r['Er60'] = m.group(1)

    # -- char-decode helper used by the loader mini-VM ---------------------------
    if 'tK6' in r:
        tka = re.escape(r['tK6'])
        m = re.search(r'local function (\w+)\(t,s\)local v=.{0,260}?' + tka +
                      r'\[string\.sub\(t,', source)
        if m:
            r['Ox20'] = m.group(1)

    # -- chained RNG (JN10) + its three constants ---------------------------------
    m = re.search(r'local function (\w+)\(i\)local v=bit32\.band\(bit32\.'
                  r'bxor\((\w+)\+\(i\*(\w+)\),bit32\.rshift\(i,\(([^()]*)\)'
                  r'\)\+(\w+)\),\(([^()]*)\)\)return v end', source)
    if m:
        r['JN10'] = m.group(1)
        r['H77'] = m.group(2)
        r['Tz8'] = m.group(3)
        r['DQ9'] = m.group(5)
        r['_jn10_shift'] = m.group(4)
        r['_jn10_mask'] = m.group(6)

    # -- dispatch key (NS14) + its three constants --------------------------------
    m = re.search(r'local (\w+)=\([^()]*\) local (\w+)=\([^()]*\) local '
                  r'(\w+)=\([^()]*\) local function (\w+)\(p\)local v='
                  r'bit32\.band\(bit32\.bxor\(\1\*p\+\2,bit32\.rshift\(p,'
                  r'\(([^()]*)\)\)\+\3\),\(([^()]*)\)\)return v end', source)
    if m:
        r['Yj11'] = m.group(1)
        r['vf12'] = m.group(2)
        r['ka13'] = m.group(3)
        r['NS14'] = m.group(4)
        r['_ns14_shift'] = m.group(5)
        r['_ns14_mask'] = m.group(6)

    # -- self-modification key (j915) --------------------------------------------
    if 'JN10' in r:
        m = re.search(r'local function (\w+)\(p,c\)return ' +
                      re.escape(r['JN10']) +
                      r'\(p\*\(([^()]*)\)\+c\*\(([^()]*)\)\)end', source)
        if m:
            r['j915'] = m.group(1)
            r['_j915_p'] = m.group(2)
            r['_j915_c'] = m.group(3)

    # -- VM operator seed + blob XOR key -------------------------------------------
    m = re.search(r'local (\w+)=bit32\.band\(bit32\.bxor\((\w+)\*\(([^()]*)\),'
                  r'\w+\+\w+\),\(([^()]*)\)\)', source)
    if m:
        r['qf16'] = m.group(1)
        r['_qf16_mult'] = m.group(3)
        r['_qf16_mask'] = m.group(4)
    i = source.find('string.byte(string.char(')
    while i > 0:
        j = source.rfind('local ', 0, i)
        m = re.match(r'local (\w+)\s*=', source[j:])
        if m and j + 900 > i and m.group(1) not in seed_names:
            r['c864'] = m.group(1)
            break
        i = source.find('string.byte(string.char(', i + 1)
        if i == -1:
            break

    # -- key bytes + the chained byte key -------------------------------------------
    m = re.search(r'end return\(function\(\.\.\.\)local (\w+)=string\.char\(',
                  source)
    if m:
        r['Wx1'] = m.group(1)
    m = re.search(r'local (\w+)=\([^()]*\) for (\w+)=\([^()]*\),\([^()]*\),'
                  r'\([^()]*\) do \1=\1\*\([^()]*\)\+\(string\.byte\((\w+),'
                  r'\2\+\([^()]*\)\)==\(([^()]*)\) and \(([^()]*)\) or '
                  r'\(([^()]*)\)\) ?end', source)
    if m:
        if 'Wx1' in r and m.group(3) != r['Wx1']:
            raise ValueError('Km2 loop byte table %r does not match Wx1 %r'
                             % (m.group(3), r['Wx1']))
        r.setdefault('Wx1', m.group(3))
        r['Km2'] = m.group(1)
        r['_km2_target'] = m.group(4)
        r['_km2_then'] = m.group(5)
        r['_km2_else'] = m.group(6)

    # -- the dispatcher ---------------------------------------------------------------
    m = re.search(r'local function (\w+)\((\w+),(\w+),(\w+),(\w+),(\w+),'
                  r'(\w+),(\w+)\) local function (\w+)\(k\)local v=\3\[k\]'
                  r'if type\(v\)=="function"then v=v\(\)\3\[k\]=v end '
                  r'return v end', source)
    if m:
        r['c435'] = m.group(1)
        r['CC36'] = m.group(2)
        r['r837'] = m.group(3)
        r['Gq38'] = m.group(4)
        r['SM39'] = m.group(5)
        r['M521'] = m.group(6)
        r['Ln40'] = m.group(7)
        r['R549'] = m.group(8)
        r['kS41'] = m.group(9)
        window = source[m.end():m.end() + 2100]

        m = re.search(r'local (\w+)=\([^()]*\) local (\w+)=\([^()]*\) local '
                      r'function (\w+)\(v\)return bit32\.band\(bit32\.bxor'
                      r'\(v,bit32\.rshift\(v,\(([^()]*)\)\)\),\(([^()]*)\)\)'
                      r'\+\(([^()]*)\) end', window)
        if m:
            r['hN42'] = m.group(1)
            r['NL46'] = m.group(2)
            r['P847'] = m.group(3)
            r['_p847_shift'] = m.group(4)
            r['_p847_mask'] = m.group(5)
            r['_p847_add'] = m.group(6)
        m = re.search(r'local function (\w+)\(\)local w=\w+\(\w+\)\w+=\w+\+'
                      r'\(([^()]*)\) return w end local function (\w+)\(\)'
                      r'local w=\w+\(\w+\)\w+=\w+\+\(([^()]*)\) return '
                      r'bit32\.bxor\(w,(\w+)\)end', window)
        if m:
            r['OH48'] = m.group(1)
            r['_oh48_step'] = m.group(2)
            r['LY43'] = m.group(3)
            r['_ly43_step'] = m.group(4)
        if 'NL46' in r:
            m = re.search(r'local function (\w+)\(\)local w=(\w+)\((\w+)\)'
                          r'\3=\3\+\(([^()]*)\) ?\w+=bit32\.bxor\(w,' +
                          re.escape(r['NL46']) +
                          r'\) ?return bit32\.rshift\(w,\(([^()]*)\)\),'
                          r'bit32\.band\(w,\(([^()]*)\)\) ?', window)
            if m:
                r['Ca44'] = m.group(1)
                r['hN42'] = m.group(3)
                r['_ca44_step'] = m.group(4)
                r['_ca44_shift'] = m.group(5)
                r['_ca44_mask'] = m.group(6)
        m = re.search(r'local (\w+)=false local (\w+)=\{\} local (\w+)='
                      r'\(([^()]*)\)', window)
        if m:
            r['qx45'] = m.group(1)
            r['Gg50'] = m.group(2)
            r['J151'] = m.group(3)
        m = re.search(r'local (\w+)=\([^()]*\) while\(\w+\*\w+\+\w+\)%'
                      r'\([^()]*\)==\([^()]*\) do', window)
        if m:
            r['Te52'] = m.group(1)

    # -- closure table / string tables ---------------------------------------------
    # The pair of empty tables ``local A={} local B={}`` is unique across the
    # file (runs may place other code between them and related definitions);
    # they hold the closure table and the string tables.
    m = re.search(r'local (\w+)=\{\} local (\w+)=\{\}', _strip_strings(source))
    if m:
        r['Z654'] = m.group(1)
        r['pN65'] = m.group(2)

    # -- global-name slot table + the name payload -----------------------------------
    if 'oE55' in r:
        m = re.search(r'local (\w+)=\{\} local (\w+)=' + re.escape(r['oE55']) +
                      r'\("', source)
        if m:
            r['M521'] = m.group(1)
            r['Mt22'] = m.group(2)
            # the op streams follow the name payload
            lit = re.search(r'local %s=%s\("' % (re.escape(r['Mt22']),
                                                 re.escape(r['oE55'])), source)
            if lit:
                i = _literal_end(source, lit.end() - 1)
                m = re.compile(r'local (\w+)=""').search(source, i)
                if m is None:
                    m = re.compile(r'local (\w+)="').search(source, i)
                if m:
                    r['Bk23'] = m.group(1)
                    i = _literal_end(source, m.end() - 1)
                    m = re.compile(r'local (\w+)=""').search(source, i)
                    if m is None:
                        m = re.compile(r'local (\w+)="').search(source, i)
                    if m:
                        r['YN24'] = m.group(1)

    # -- loader tables + RNG seed ------------------------------------------------------
    m = re.search(r'local (\w+)=\{\} local \w+=\{\([^()]*\)\} local \w+='
                  r'\{\([^()]*\)\} local (\w+)=\(', source)
    if m:
        r['Mz25'] = m.group(1)
        r['Pq28'] = m.group(2)

    return r


def _literal_end(source: str, open_quote: int) -> int:
    """Return the index of the closing quote of the literal opened at
    ``open_quote`` (which must point at the quote character)."""
    i = open_quote + 1
    n = len(source)
    while i < n:
        c = source[i]
        if c == '\\':
            i += 2
            continue
        if c == source[open_quote]:
            return i
        i += 1
    raise ValueError('unterminated string literal at %d' % open_quote)


def _long_bracket_end(source: str, opening: int):
    """Return the end of a Lua long string/comment, or None if not an opener."""
    match = re.match(r'\[(=*)\[', source[opening:])
    if match is None:
        return None
    closing = ']' + match.group(1) + ']'
    end = source.find(closing, opening + match.end())
    if end < 0:
        raise ValueError('unterminated long string/comment at %d' % opening)
    return end + len(closing)


def _protected_end(source: str, index: int):
    """Return the end of a string or comment beginning at index."""
    if source[index] in ('"', "'"):
        return _literal_end(source, index) + 1
    if source[index] == '[':
        return _long_bracket_end(source, index)
    if source.startswith('--', index):
        long_end = _long_bracket_end(source, index + 2)
        if long_end is not None:
            return long_end
        end = source.find('\n', index + 2)
        return len(source) if end < 0 else end
    return None


def canonicalize(source: str):
    """Rewrite ``source`` so obfuscator-internal names use canonical ones.

    Returns ``(renamed_source, roles)``.  Identifiers the file already
    spells canonically are untouched; string literal contents are never
    rewritten.
    """
    roles = resolve(source)

    retained: set = set()
    mapping: dict = {}
    prefix = roles.get('SEED_PREFIX')
    if prefix:
        for index in range(1, SEED_COUNT + 1):
            canonical = 'jm%d' % index
            retained.add(canonical)
            found = prefix + str(index)
            if found != canonical:
                mapping[found] = canonical
        for letter in SEED_LETTERS:
            canonical = 'jm' + letter
            retained.add(canonical)
            found = roles.get(canonical)
            if found and found != canonical:
                mapping[found] = canonical

    for canonical, found in roles.items():
        if canonical in ('SEED_PREFIX',) or canonical.startswith('_'):
            continue
        if not isinstance(found, str) or not re.fullmatch(
                r'[A-Za-z_][A-Za-z0-9_]*', found):
            continue
        retained.add(canonical)
        if found == canonical:
            continue
        if found in mapping:
            if mapping[found] == canonical:
                continue
            raise ValueError('identifier %r used for %r and %r'
                             % (found, mapping[found], canonical))
        mapping[found] = canonical

    if not mapping:
        return source, roles

    if '\x00' in source:
        raise ValueError('source already contains NUL markers')

    # every canonical target must be unused in the source outside string
    # literals, otherwise two different objects would end up sharing a name
    code = _strip_strings(source)
    for canonical in set(mapping.values()):
        if re.search(r'(?<![\w])%s(?![\w])' % re.escape(canonical), code):
            raise ValueError('canonical name %r already exists in source'
                             % canonical)

    renamed = _rename_outside_strings(source, mapping)
    return renamed, roles


def _strip_strings(source: str) -> str:
    """Blank strings and comments to prevent false source-pattern matches."""
    parts = []
    i = 0
    n = len(source)
    while i < n:
        end = _protected_end(source, i)
        if end is None:
            parts.append(source[i])
            i += 1
            continue
        protected = source[i:end]
        parts.append(''.join('\n' if ch == '\n' else ' '
                             for ch in protected))
        i = end
    return ''.join(parts)


def _rename_outside_strings(source: str, mapping: dict) -> str:
    """Apply ``mapping`` to identifier tokens outside string literals."""
    def span_rename(text: str) -> str:
        if not mapping:
            return text

        def repl(m):
            name = m.group(0)
            if name in mapping:
                return '\x00%s\x00' % mapping[name]
            return name

        return re.sub(r'[A-Za-z_][A-Za-z0-9_]*', repl, text)

    parts = []
    i = 0
    n = len(source)
    code_start = 0
    while i < n:
        end = _protected_end(source, i)
        if end is not None:
            parts.append(span_rename(source[code_start:i]))
            parts.append(source[i:end])
            i = end
            code_start = i
        else:
            i += 1
    parts.append(span_rename(source[code_start:]))
    # each marker already carries the canonical name, so unwrapping is a
    # plain scan-over (markers are emitted in balanced pairs)
    return ''.join(parts).replace('\x00', '')
