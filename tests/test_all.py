"""Decode all prototypes and summarize."""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / 'deobfuscator'))

import vm
import keb

src = (PROJECT_ROOT / 'samples' / 'sample.lua').read_text(encoding='utf-8-sig')
c = keb.Constants(src)
c.extract_jm()
vm.parse_opcode_map(str(PROJECT_ROOT / 'deobfuscator' / 'opcode_map.txt'), c.ev)
print('ops parsed:', len(vm.OPS))

loader = vm.Loader(src, c)
tables = loader.run()
gnames = loader.m521

badprotos = []
for tname in sorted(tables):
    st = vm.Stream(tables[tname])
    instrs = vm.decode_stream(st)
    kinds = {}
    unknowns = []
    maxpc = max(it.pc for it in instrs)
    for it in instrs:
        kinds[it.kind] = kinds.get(it.kind, 0) + 1
        if it.kind == 'UNKNOWN':
            unknowns.append((it.pc, it.op))
    last = instrs[-1]
    print('proto %-3s len=%-5d instrs=%-5d read=%-5d/%d  last=%-7s  unknowns=%s'
          % (tname, st.length, len(instrs), maxpc, st.length, last.kind,
             unknowns[:4] if unknowns else '-'))
    if unknowns:
        badprotos.append(tname)
    print('        kinds:', dict(sorted(kinds.items(), key=lambda kv: -kv[1])))
print()
print('protos with unknowns:', badprotos)
print('globals:', gnames)
