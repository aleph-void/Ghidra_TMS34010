#!/usr/bin/env python3
"""Compare a Ghidra listing (RealCheck.java: "<address> <bytes> <text>") with MAME unidasm output
(bit addresses) at the same addresses, and optionally with a gspa listing of the source.

  listing_check.py <ghidra.lst> <mame.txt> [gspa.lst]
"""
import re
import sys
from collections import Counter, defaultdict

sys.path.insert(0, __import__('os').path.dirname(__file__))
import compare as C        # noqa: E402
import asm_check as A      # noqa: E402

g = {}
for line in open(sys.argv[1]):
    a, b, t = line.rstrip('\n').split(' ', 2)
    g[int(a, 16)] = (len(b) // 2, t, b)
mm = {}
for line in open(sys.argv[2]):
    m = re.match(r'^([0-9a-f]+): ((?:[0-9a-f]{4} )+)\s*(.*)$', line.rstrip('\n') + ' ')
    if m:
        mm[int(m.group(1), 16)] = (len(m.group(2).split()) * 2, m.group(3).strip())
c, d = Counter(), defaultdict(list)
for a in sorted(g):
    glen, gtext, gb = g[a]
    mlen, mtext = mm.get(a * 8, (0, 'missing'))
    mn, mops = C.norm_mame(mtext)
    gn, gops = C.norm_ghidra(gtext)
    ok = mn == gn and len(mops) == len(gops) and mlen == glen
    if ok:
        for k, (x, y) in enumerate(zip(mops, gops)):
            last = C.is_branch(mn) and k == len(mops) - 1
            if last and (mn == 'CALLA' or mn.startswith('JA')):
                last = 'abs'
            ok = ok and C.tok_eq(x, y, last)
    op = int(gb[2:4] + gb[0:2], 16)
    if not ok and (op & 0xffe0) == 0x07e0 and mn == 'MOVE' and gn == 'MOVB':
        c['explained (MAME prints MOVB @a,Rd as MOVE)'] += 1
    elif ok:
        c['identical'] += 1
    else:
        c['different'] += 1
        d['mame'].append(f'{a:x} mame "{mtext}" ghidra "{gtext}"')
print(f'vs MAME: {sum(c.values())} instructions: {dict(c)}')
for e in d['mame'][:20]:
    print('  ' + e)
if len(sys.argv) > 3:
    ins, labels = A.parse_listing(sys.argv[3])
    src = {a // 8: s for a, w, s in ins}
    cs = Counter()
    for a in sorted(g):
        if a not in src:
            cs['no source line'] += 1
            continue
        sn, sops = A.norm_src(src[a], labels)
        gn, gops = C.norm_ghidra(g[a][1])
        if sn == 'DSJ' and gn == 'DSJS':
            sn = 'DSJS'
        ok = sn == gn and len(sops) == len(gops) and all(A.src_tok_eq(x, y, False) for x, y in zip(sops, gops))
        cs['identical' if ok else 'different'] += 1
        if not ok:
            d['src'].append(f'{a:x} src "{src[a]}" ghidra "{g[a][1]}"')
    print(f'vs source: {dict(cs)}')
    for e in d['src'][:20]:
        print('  ' + e)
