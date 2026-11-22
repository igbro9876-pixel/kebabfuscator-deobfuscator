"""Decode prototype streams with the verified loader + bc19 + opcode map."""
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / 'deobfuscator'))

import vm

src = (PROJECT_ROOT / 'samples' / 'sample.lua').read_text(encoding='utf-8-sig')
c = vm.Constants(src)
c.extract_jm()
vm.parse_opcode_map(str(PROJECT_ROOT / 'deobfuscator' / 'opcode_map.txt'), c.ev)
print('ops parsed:', len(vm.OPS))

loader = vm.Loader(src, c)
tables = loader.run()

# decode proto 1 (44 words) first
for tname in (1, 12, 14, 11, 10):
    st = vm.Stream(tables[tname])
    instrs = vm.decode_stream(st)
    print()
    vm.print_listing(instrs, title='proto %s (len %d words)' % (tname, st.length))
    # report memory: words actually read (1..max pc)
    read = max(it.pc for it in instrs) + 1
    print('inverse: read', read, 'of', st.length, 'words; instrs', len(instrs))
