"""Run vm.Loader and compare against the real-Lua Mz25 tables."""
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SAMPLES = PROJECT_ROOT / 'samples'
sys.path.insert(0, str(PROJECT_ROOT / 'deobfuscator'))

import vm

src = (SAMPLES / 'sample.lua').read_text(encoding='utf-8-sig')
c = vm.Constants(src)
c.extract_jm()
loader = vm.Loader(src, c)
tables = loader.run()

oracle = json.loads((SAMPLES / 'mz_oracle.json').read_text(encoding='utf-8'))
total_bad = 0
for name in sorted(tables, key=str):
    mine = tables[name]
    got = oracle.get(str(name))
    if got is None:
        print('table', name, 'NOT in oracle')
        total_bad += 1
        continue
    mism = 0
    for k, v in got.items():
        if mine.get(int(k), None) != int(v):
            mism += 1
    extra = [k for k in mine if str(k) not in got]
    status = 'OK' if (mism == 0 and not extra) else 'MISMATCH'
    print('table %-4s size %6d  mismatched %d  extra %s  -> %s'
          % (name, len(mine), mism, len(extra), status))
    total_bad += mism + len(extra)
print('globals recovered:', len(loader.m521))
for k in sorted(loader.m521):
    n = loader.m521[k]
    print('  M521[%d] = %r' % (k, n))
print('TOTAL BAD:', total_bad)
