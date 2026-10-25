#!/usr/bin/env python3
"""Compare Ghidra slot decodes (DumpSlots.java) with MAME unidasm output for a slot corpus.

  compare.py <ghidra.txt> <mame.txt> [slot-bytes] [--list N]

Normalisations (display conventions only, each counted):
  - MAME prints branch/call targets as bit addresses, Ghidra as byte (Ghidra) addresses: the
    Ghidra target is multiplied by 8.
  - MAME's JR/JA without condition is JRUC/JAUC; "*Rd,XY" is TI's "*Rd.XY".
  - MAME compresses MMTM/MMFM register runs (A0-A3); both lists are expanded.
  - Numbers are compared by value; a 16-bit immediate MAME prints unsigned and Ghidra signed
    compares equal modulo 2^16.
Agreement classes: exact text after normalisation, both invalid, or a difference. Differences are
bucketed by mnemonic and reason.
"""
import re
import sys
from collections import Counter, defaultdict

BRANCHES = {'CALLA', 'CALLR', 'DSJ', 'DSJEQ', 'DSJNE', 'DSJS'}


def is_branch(m):
    return m in BRANCHES or m.startswith('JR') or m.startswith('JA')


def num(tok):
    t = tok.strip()
    neg = t.startswith('-')
    if neg:
        t = t[1:]
    if re.fullmatch(r'0x[0-9a-fA-F]+', t):
        v = int(t, 16)
    elif re.fullmatch(r'[0-9A-F]+h', t):
        v = int(t[:-1], 16)
    elif re.fullmatch(r'[0-9]+', t):
        v = int(t)
    else:
        return None
    return -v if neg else v


def expand_list(ops):
    out = []
    for o in ops:
        m = re.fullmatch(r'([AB])(\d+)-([AB])?(\d+|SP)', o)
        if m:
            f = m.group(1)
            a = int(m.group(2))
            b = 15 if m.group(4) == 'SP' else int(m.group(4))
            out += [('SP' if i == 15 else f'{f}{i}') for i in range(a, b + 1)]
        else:
            out.append(o)
    return out


def split_ops(s):
    # split on commas outside parentheses
    out, depth, cur = [], 0, ''
    for ch in s:
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
        if ch == ',' and depth == 0:
            out.append(cur)
            cur = ''
        else:
            cur += ch
    if cur:
        out.append(cur)
    return [o.strip() for o in out]


def norm_mame(text):
    m = re.match(r'(\S+)\s*(.*)$', text.strip())
    mn, rest = m.group(1), m.group(2)
    if mn in ('JR', 'JA') or re.fullmatch(r'J[RA]', mn):
        pass
    # MAME pads the condition: "JRP    ..." / "JR     ..." (UC)
    if mn == 'JR':
        mn = 'JRUC'
    elif mn == 'JA':
        mn = 'JAUC'
    rest = re.sub(r'(\*(?:[AB]\d+|SP)),XY', r'\1.XY', rest)
    ops = split_ops(rest) if rest else []
    if mn in ('MMTM', 'MMFM'):
        ops = ops[:1] + expand_list(ops[1:])
    return mn, ops


def norm_ghidra(text):
    m = re.match(r'(\S+)\s*(.*)$', text.strip())
    mn, rest = m.group(1).upper(), m.group(2)
    ops = split_ops(rest) if rest else []
    return mn, ops


def tok_eq(a, b, scale_branch):
    """Compare one operand (MAME a, Ghidra b)."""
    if a == b:
        return True
    # numbers possibly embedded: compare token streams
    pat = r'-?0x[0-9a-fA-F]+|[0-9A-F]+h\b|[A-Za-z_]+\d*|\d+|\S'
    ta = re.findall(pat, a)
    tb = re.findall(pat, b)
    if len(ta) != len(tb):
        return False
    for x, y in zip(ta, tb):
        nx, ny = num(x), num(y)
        if nx is not None and ny is not None:
            if scale_branch:
                ny *= 8
                if scale_branch == 'abs':
                    nx &= ~0xf
            if (nx - ny) % (1 << 32) == 0 or (nx - ny) % (1 << 16) == 0 and abs(nx) < (1 << 16) and abs(ny) < (1 << 16):
                continue
            return False
        if x.upper() != y.upper():
            return False
    return True


def load_mame(path, slot_bits):
    res = {}
    for line in open(path):
        m = re.match(r'^([0-9a-f]+): ((?:[0-9a-f]{4} )+)\s*(.*)$', line.rstrip('\n') + ' ')
        if not m:
            continue
        addr = int(m.group(1), 16)
        if addr % slot_bits:
            continue
        words = m.group(2).split()
        res[addr // slot_bits] = (len(words) * 2, m.group(3).strip(), words[0])
    return res


def load_core(path):
    reserved = set()
    for line in open(path):
        if line.startswith('#'):
            continue
        r, fn = line.split()
        a, b = (int(x, 16) for x in r.split('-'))
        if fn in ('unimpl', 'illop'):
            reserved.update(range(a >> 4, (b >> 4) + 1))
    return reserved


def load_ghidra(path, slot):
    res = {}
    for line in open(path):
        off, ln, text = line.rstrip('\n').split(' ', 2)
        res[int(off, 16) // slot] = (int(ln), text)
    return res


def main():
    gpath, mpath = sys.argv[1], sys.argv[2]
    slot = int(sys.argv[3]) if len(sys.argv) > 3 and not sys.argv[3].startswith('--') else 18
    nlist = 0
    if '--list' in sys.argv:
        nlist = int(sys.argv[sys.argv.index('--list') + 1])
    g = load_ghidra(gpath, slot)
    import os
    reserved = load_core(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'mame_core_table.txt'))
    mm = load_mame(mpath, slot * 8)
    c = Counter()
    diffs = defaultdict(list)
    for i in sorted(g):
        glen, gtext = g[i]
        mlen, mtext, op = mm[i]
        mbad = mtext.startswith('DW ')
        gbad = gtext.startswith('BAD')
        if mbad and gbad:
            c['both invalid'] += 1
            continue
        if gbad and (int(op, 16) >> 4) in reserved:
            c['explained'] += 1
            diffs['explained: MAME disassembles an opcode its CPU core treats as reserved ' + mtext.split()[0]].append(f'{op}: mame "{mtext}"')
            continue
        if mbad or gbad:
            key = ('ghidra-only' if mbad else 'mame-only') + ' ' + (gtext.split()[0] if mbad else mtext.split()[0])
            c['difference'] += 1
            diffs[key].append(f'{op}: mame "{mtext}" ghidra "{gtext}"')
            continue
        mn, mops = norm_mame(mtext)
        gn, gops = norm_ghidra(gtext)
        if mn in ('SRA', 'SRL') and (int(op, 16) & 0xfbe0) == 0x2800 and mops[0] == '20h' and gops[0] == '0x0':
            # count field 0: MAME prints 32 (32 - field) but its core shifts by (-field) & 31 = 0
            c['explained'] += 1
            diffs['explained: MAME prints SRA/SRL K with a count field of 0 as 20h (the CPU shifts by 0)'].append(f'{op}: mame "{mtext}" ghidra "{gtext}"')
            continue
        if (int(op, 16) & 0xffe0) == 0x07e0 and mn == 'MOVE' and gn == 'MOVB' and len(mops) == len(gops) \
                and all(tok_eq(a, b, False) for a, b in zip(mops, gops)):
            # MAME's disassembler prints MOVB @SAddress,Rd (07E0h) as MOVE; its core runs MOVB
            c['explained'] += 1
            diffs['explained: MAME prints MOVB @SAddress,Rd (07E0h) as MOVE'].append(f'{op}: mame "{mtext}" ghidra "{gtext}"')
            continue
        ok = mn == gn and len(mops) == len(gops)
        if ok:
            br = is_branch(mn)
            for k, (a, b) in enumerate(zip(mops, gops)):
                last = br and k == len(mops) - 1
                if last and (mn == 'CALLA' or mn.startswith('JA')):
                    last = 'abs'
                if not tok_eq(a, b, last):
                    ok = False
                    break
        if ok and mlen != glen:
            ok = False
            diffs[f'length {mn}'].append(f'{op}: mame {mlen} "{mtext}" ghidra {glen} "{gtext}"')
            c['difference'] += 1
            continue
        if ok:
            c['agree'] += 1
        else:
            c['difference'] += 1
            diffs[f'text {mn}'].append(f'{op}: mame "{mtext}" ghidra "{gtext}"')
    total = sum(c.values())
    agree = c['agree'] + c['both invalid']
    print(f'{agree}/{total} agree ({100.0 * agree / total:.2f} %): {c["agree"]} same instruction, '
          f'{c["both invalid"]} both invalid, {c["explained"]} explained, {c["difference"]} differences')
    for k in sorted(diffs, key=lambda k: -len(diffs[k])):
        print(f'  {len(diffs[k]):6d} {k}')
        for e in diffs[k][:nlist]:
            print(f'           {e}')


if __name__ == '__main__':
    main()
