#!/usr/bin/env python3
"""Every-entry test: each SLEIGH constructor in data/languages/*.sinc must be used by at least one
decoded instruction of the corpora (DumpSlots.java constructor lists), so that no constructor is
shadowed or unreachable ("both undefined" in the differential test cannot hide it).

  entry_check.py <languages-dir> <constructors.txt> [...]
"""
import glob
import os
import re
import sys

langs = sys.argv[1]
used = set()
for f in sys.argv[2:]:
    used |= {l.strip() for l in open(f) if l.strip()}
defined = []
for path in sorted(glob.glob(os.path.join(langs, '*.sinc'))):
    name = os.path.basename(path)
    for n, line in enumerate(open(path), 1):
        if re.match(r'^(:|[A-Za-z_]\w*:)\S*.*\bis\b', line) and not line.startswith('#'):
            defined.append((f'{name}:{n}', line.strip()[:100]))
missing = [(k, t) for k, t in defined if k not in used]
print(f'{len(defined) - len(missing)}/{len(defined)} constructors reached')
for k, t in missing:
    print(f'  NOT REACHED {k}: {t}')
sys.exit(1 if missing else 0)
