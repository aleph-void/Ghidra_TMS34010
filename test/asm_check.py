#!/usr/bin/env python3
"""Assembler corpus check: gspa listing vs Ghidra decode vs MAME disassembly.

  asm_check.py image <listing> <out.bin> <addrs.txt>     build the raw image (Ghidra address =
                                                           bit address / 8) and the address list
  asm_check.py check <listing> <ghidra.txt> <mame.txt|->  compare ('-': source only)

The MAME file is unidasm output over the code region (-basepc = start bit address). For each
instruction the source line from the listing is also compared with Ghidra's text (aliases,
number bases, label targets and gspa's DSJ-to-DSJS shortening normalised).
"""
import re
import sys
from collections import Counter, defaultdict

sys.path.insert(0, __import__('os').path.dirname(__file__))
import compare as C  # noqa: E402


SYMS = {}


def parse_listing(path):
    ins, labels = [], {}
    for line in open(path):
        em = re.match(r'^ {10}([0-9A-F]{8}) +(\w+)\s*=', line)
        if em:
            SYMS[em.group(2).upper()] = int(em.group(1), 16)
            continue
        m = re.match(r'^([0-9A-F]{8}) ((?:[0-9A-F]{4} ?)*)\s*\t?(.*)$', line.rstrip('\n'))
        if not m:
            continue
        addr = int(m.group(1), 16)
        words = m.group(2).split()
        src = m.group(3).split(';')[0].strip()
        lm = re.match(r'^(\w+):\s*(.*)$', src)
        if lm:
            labels[lm.group(1).upper()] = addr
            SYMS[lm.group(1).upper()] = addr
            src = lm.group(2)
        if words and src and not src.startswith('.'):
            ins.append([addr, words, src])
        elif words and ins and not src:
            ins[-1][1] += words      # continuation line of a long instruction
    return ins, labels


ALIAS = {'LO': 'C', 'B': 'C', 'HS': 'NC', 'NB': 'NC', 'Z': 'EQ', 'NZ': 'NE'}


def norm_src(src, labels):
    m = re.match(r'(\S+)\s*(.*)$', src)
    mn, rest = m.group(1).upper(), m.group(2)
    ops = [o.strip() for o in C.split_ops(rest)] if rest else []
    jm = re.fullmatch(r'J([RA])(\w+)', mn)
    if jm and mn != 'JUMP':
        mn = 'J' + jm.group(1) + ALIAS.get(jm.group(2), jm.group(2))
    if ops and ops[-1].upper() in ('L', 'W') and mn not in ('FILL', 'PIXBLT', 'LINE'):
        if ops[-1].upper() == 'L' and mn.startswith('JR'):
            mn = 'JA' + mn[2:]            # gspa: JRcc label,L assembles the absolute JAcc
        ops = ops[:-1]
    if mn == 'XOR' and len(ops) == 2 and ops[0].upper() == ops[1].upper():
        mn, ops = 'CLR', ops[1:]
    if mn in ('ADD', 'SUB', 'CMP', 'AND', 'ANDN', 'OR', 'XOR', 'MOVE', 'BTST', 'SLA', 'SLL', 'SRA', 'SRL', 'RL') \
            and len(ops) >= 2 and is_expr(ops[0]):
        generic = mn in ('ADD', 'SUB', 'MOVE')
        mn = {'ADD': 'ADDI', 'SUB': 'SUBI', 'CMP': 'CMPI', 'AND': 'ANDI', 'ANDN': 'ANDNI', 'OR': 'ORI',
              'XOR': 'XORI', 'MOVE': 'MOVI'}.get(mn, mn)
        ops = [str(num_src(ops[0]))] + ops[1:]
        if generic and 1 <= num_src(ops[0]) <= 32:
            mn = mn[:-1] + 'K'       # gspa picks the 5-bit form for small constants
    if mn in ('ADDK', 'SUBK') and num_src(ops[0]) == 1:
        mn, ops = ('INC' if mn == 'ADDK' else 'DEC'), ops[1:]
    if mn == 'ANDNI':
        v = num_src(ops[0])
        mn, ops = 'ANDI', [str(~v & 0xffffffff)] + ops[1:]
    ops = [o if not is_expr(o) or o.upper() in labels else str(num_src(o)) for o in ops]
    ops = [re.sub(r'@(.+)', lambda m: '@' + str(num_src(m.group(1))), o) for o in ops]
    ops = [re.sub(r'\(([^)]*)\)', lambda m: '(' + str(num_src(m.group(1))) + ')', o) for o in ops]
    if mn == 'RETS' and ops and num_src(ops[0]) == 0:
        ops = []
    ops = [re.sub(r'^\*-', '-*', o) for o in ops]       # gspa also writes -*Rd as *-Rd
    if mn == 'MOVE' and any(o[:1] in '*@-' for o in ops) and ops[-1] not in ('0', '1'):
        ops.append('0')
    if mn in ('SEXT', 'ZEXT', 'EXGF') and len(ops) == 1:
        ops.append('0')
    out = []
    for o in ops:
        u = o.upper()
        if u in labels:
            out.append(('label', labels[u]))
        else:
            out.append(u)
    return mn, out


def num_src(t):
    t = t.strip()
    if re.fullmatch(r'-?\d+', t):
        return int(t)
    if re.fullmatch(r'-?\$[0-9A-Fa-f]+', t):
        return -int(t[2:], 16) if t.startswith('-') else int(t[1:], 16)
    e = re.sub(r'\$([0-9A-Fa-f]+)', r'0x\1', t)
    e = re.sub(r'\b0[xX][0-9A-Fa-f]+\b|[A-Za-z_]\w*',
               lambda m: m.group(0) if m.group(0)[:2].lower() == '0x' else str(SYMS[m.group(0).upper()]), e)
    return int(eval(e, {'__builtins__': {}}))


def is_expr(t):
    t = t.strip()
    if re.fullmatch(r'\*?-?\*?(?:[ab]\d+|sp)\+?(\.xy)?(\(.*\))?', t, re.I) or t[:1] in '@*' or t.startswith('-*'):
        return False
    return bool(re.search(r'[\d$]', t)) or any(w.upper() in SYMS for w in re.findall(r'[A-Za-z_]\w*', t))


def src_tok_eq(s, g, branch):
    if isinstance(s, tuple):
        n = C.num(g)
        return n is not None and (n * 8 - s[1]) % (1 << 32) == 0
    pat = r'-?0x[0-9a-fA-F]+|\$[0-9A-F]+|[A-Za-z_]+\d*|-?\d+|\S'
    ts = re.findall(pat, s)
    tg = re.findall(pat, g)
    if len(ts) != len(tg):
        return False
    for x, y in zip(ts, tg):
        if re.fullmatch(r'\$[0-9A-F]+|-?\d+', x):
            ny = C.num(y)
            if ny is None:
                return False
            nx = num_src(x)
            if (nx - ny) % (1 << 32) and not ((nx - ny) % (1 << 16) == 0 and abs(nx) < (1 << 16)):
                return False
        elif x.upper() != y.upper():
            return False
    return True


def main():
    if sys.argv[1] == 'image':
        ins, _ = parse_listing(sys.argv[2])
        end = max(a + 16 * len(w) for a, w, _ in ins) // 8
        img = bytearray(end)
        with open(sys.argv[4], 'w') as f:
            for a, w, _ in ins:
                for i, x in enumerate(w):
                    v = int(x, 16)
                    img[a // 8 + 2 * i] = v & 0xff
                    img[a // 8 + 2 * i + 1] = v >> 8
                f.write(f'{a // 8:x}\n')
        open(sys.argv[3], 'wb').write(img)
        print(f'{len(ins)} instructions, code from bit {ins[0][0]:X}h')
        return
    ins, labels = parse_listing(sys.argv[2])
    g = {}
    for line in open(sys.argv[3]):
        off, ln, text = line.rstrip('\n').split(' ', 2)
        g[int(off, 16)] = (int(ln), text)
    mm = {}
    for line in (open(sys.argv[4]) if sys.argv[4] != '-' else []):
        m = re.match(r'^([0-9a-f]+): ((?:[0-9a-f]{4} )+)\s*(.*)$', line.rstrip('\n') + ' ')
        if m:
            mm[int(m.group(1), 16)] = (len(m.group(2).split()) * 2, m.group(3).strip())
    cm, cs = Counter(), Counter()
    dm, ds = defaultdict(list), defaultdict(list)
    for a, words, src in ins:
        glen, gtext = g[a // 8]
        if 2 * len(words) != glen:
            cs['length'] += 1
            ds['length'].append(f'{a:x} {src} -> {gtext}')
            continue
        gn, gops = C.norm_ghidra(gtext)
        if sys.argv[4] != '-':      # vs MAME
            mlen, mtext = mm.get(a, (0, 'missing'))
            mn, mops = C.norm_mame(mtext)
            ok = mn == gn and len(mops) == len(gops) and mlen == glen
            if ok:
                for k, (x, y) in enumerate(zip(mops, gops)):
                    last = C.is_branch(mn) and k == len(mops) - 1
                    if last and (mn == 'CALLA' or mn.startswith('JA')):
                        last = 'abs'
                    if not C.tok_eq(x, y, last):
                        ok = False
            if not ok and (int(words[0], 16) & 0xffe0) == 0x07e0 and mn == 'MOVE' and gn == 'MOVB':
                cm['explained (MAME prints MOVB @a,Rd as MOVE)'] += 1
            elif not ok and (int(words[0], 16) & 0xfbe0) == 0x2800 and mtext.split()[1].startswith('20h'):
                cm['explained (MAME prints SRA/SRL 0 as 20h)'] += 1
            elif ok:
                cm['agree'] += 1
            else:
                cm['difference'] += 1
                dm[gn].append(f'{a:x} mame "{mtext}" ghidra "{gtext}"')
        # vs source
        sn, sops = norm_src(src, labels)
        if sn == 'DSJ' and gn == 'DSJS':
            sn = 'DSJS'
            cs['assembler shortened DSJ to DSJS'] += 1
        if (int(words[0], 16) & 0xffe0) == 0x0ce0:
            cs['explained (gspa encodes SUBI IW,Rd with Rd other than A0 as 0CE0h|Rd)'] += 1
            ds['gspa SUBI bug'].append(f'{a:x} {words[0]} {src} -> {gtext}')
            continue
        ok = sn == gn and len(sops) == len(gops)
        if ok:
            for x, y in zip(sops, gops):
                if not src_tok_eq(x, y, False):
                    ok = False
        if ok:
            cs['agree'] += 1
        else:
            cs['difference'] += 1
            ds[sn].append(f'{a:x} src "{src}" ghidra "{gtext}"')
    if cm:
        print(f'vs MAME:   {dict(cm)}')
    for k in dm:
        print(f'  {len(dm[k])} {k}: ' + '; '.join(dm[k][:3]))
    print(f'vs source: {dict(cs)}')
    for k in ds:
        print(f'  {len(ds[k])} {k}: ' + '; '.join(ds[k][:3]))


if __name__ == '__main__':
    main()
