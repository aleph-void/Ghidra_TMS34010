#!/usr/bin/env python3
"""Assembler corpus for the TMS34010 decode test: every instruction form gspa (NetBSD's TMS34010
assembler, usr.sbin/gspa) accepts, with random operands, as one gspa source file.

  gen_asm.py <out.asm> [count-per-form]

Branch targets are labels placed within reach. The listing gspa writes (-l) gives the bit
address, words and source line of each instruction; asm_check.py compares Ghidra's decode of
each one with the source and with MAME's disassembly.
"""
import random
import sys

rng = random.Random(34010)
N = int(sys.argv[2]) if len(sys.argv) > 2 else 12


def reg(f=None):
    f = f or rng.choice('ab')
    i = rng.randrange(16)
    return ('sp' if i == 15 else f'{f}{i}'), f


def pair():
    f = rng.choice('ab')
    return reg(f)[0], reg(f)[0]


def imm16():
    return rng.randrange(-32768, 32768)


def imm32():
    return rng.getrandbits(32)


def hexv(v):
    return f'${v & 0xffffffff:X}'


def addr():
    return hexv(rng.getrandbits(32))


lines = ['\t.org\t$100000']
lab = 0


def emit(s):
    lines.append('\t' + s)


two = ['add', 'addc', 'sub', 'subb', 'cmp', 'and', 'andn', 'or', 'xor', 'divs', 'divu', 'mpys', 'mpyu',
       'sla', 'sll', 'sra', 'srl', 'rl', 'lmo', 'mods', 'modu', 'addxy', 'subxy', 'cmpxy', 'cpw', 'cvxyl',
       'movx', 'movy', 'drav', 'btst', 'move']
one = ['abs', 'neg', 'negb', 'not', 'exgpc', 'getpc', 'jump', 'getst', 'putst', 'call', 'rev', 'clr',
       'inc', 'dec']
none = ['nop', 'clrc', 'setc', 'dint', 'eint', 'popst', 'pushst', 'reti', 'emu']
conds = ['uc', 'p', 'ls', 'hi', 'lt', 'ge', 'le', 'gt', 'c', 'nc', 'eq', 'ne', 'v', 'nv', 'n', 'nn',
         'lo', 'hs', 'z', 'nz', 'b', 'nb']

for blk in range(N):
    lines.append(f'K{blk}:')
    for m in two:
        emit(f'{m}\t{",".join(pair())}')
    for m in one:
        emit(f'{m}\t{reg()[0]}')
    for m in none:
        emit(m)
    r = reg()[0]
    for m, v in (('addk', rng.randrange(1, 33)), ('subk', rng.randrange(1, 33)), ('movk', rng.randrange(1, 33)),
                 ('btst', rng.randrange(32)), ('sla', rng.randrange(32)), ('sll', rng.randrange(32)),
                 ('sra', rng.randrange(32)), ('srl', rng.randrange(32)), ('rl', rng.randrange(32))):
        emit(f'{m}\t{v},{reg()[0]}')
    for m in ('addi', 'cmpi', 'movi', 'subi'):
        # gspa encodes the 16-bit SUBI wrongly unless Rd is A0 (see GHIDRA-RARE.md)
        emit(f'{m}\t{imm16()},{"a0" if m == "subi" else reg()[0]}')
        emit(f'{m}\t{hexv(imm32())},{reg()[0]},l')
    for m in ('andi', 'andni', 'ori', 'xori'):
        emit(f'{m}\t{hexv(imm32())},{reg()[0]}')
    emit(f'sext\t{reg()[0]},{rng.randrange(2)}')
    emit(f'zext\t{reg()[0]},{rng.randrange(2)}')
    emit(f'exgf\t{reg()[0]},{rng.randrange(2)}')
    emit(f'setf\t{rng.randrange(1, 33)},{rng.randrange(2)},{rng.randrange(2)}')
    emit(f'rets\t{rng.randrange(32)}')
    emit(f'trap\t{rng.randrange(32)}')
    f = rng.choice('ab')
    regs = sorted(rng.sample(range(15), rng.randrange(1, 6)))
    emit(f'mmtm\t{reg(f)[0]},' + ','.join(f'{f}{i}' for i in regs))
    emit(f'mmfm\t{reg(f)[0]},' + ','.join(f'{f}{i}' for i in regs))
    # field moves
    F = rng.randrange(2)
    s, d = pair()
    o1, o2 = imm16(), imm16()
    for form in (f'{s},*{d}', f'*{s},{d}', f'*{s},*{d}', f'{s},*{d}+', f'*{s}+,{d}', f'*{s}+,*{d}+',
                 f'{s},-*{d}', f'-*{s},{d}', f'-*{s},-*{d}', f'{s},*{d}({o1})', f'*{s}({o1}),{d}',
                 f'*{s}({o1}),*{d}({o2})', f'*{s}({o1}),*{d}+', f'{s},@{addr()}', f'@{addr()},{d}',
                 f'@{addr()},@{addr()}', f'@{addr()},*{d}+'):
        emit(f'move\t{form},{F}')
    a, b = pair()
    emit(f'move\t{a},{"b" if a[0] == "a" else "a"}{rng.randrange(15)}')
    for form in (f'{s},*{d}', f'*{s},{d}', f'*{s},*{d}', f'{s},*{d}({o1})', f'*{s}({o1}),{d}',
                 f'*{s}({o1}),*{d}({o2})', f'{s},@{addr()}', f'@{addr()},{d}', f'@{addr()},@{addr()}'):
        emit(f'movb\t{form}')
    for form in (f'{s},*{d}', f'{s},*{d}.xy', f'*{s},{d}', f'*{s}.xy,{d}', f'*{s},*{d}', f'*{s}.xy,*{d}.xy'):
        emit(f'pixt\t{form}')
    for sd in ('l,l', 'l,xy', 'xy,l', 'xy,xy', 'b,l', 'b,xy'):
        emit(f'pixblt\t{sd}')
    emit('fill\tl')
    emit('fill\txy')
    emit(f'line\t{rng.randrange(2)}')
    # flow: short/long relative, absolute, calls, dsj
    lab += 1
    L = f'L{lab}'
    emit(f'jr{rng.choice(conds)}\t{L},l')
    emit(f'ja{rng.choice(conds)}\t{L}')
    emit(f'dsjeq\t{reg()[0]},{L}')
    emit(f'dsjne\t{reg()[0]},{L}')
    emit(f'dsjs\t{reg()[0]},{L}')
    emit(f'callr\t{L}')
    emit(f'calla\t{L}')
    lines.append(f'{L}:')
    emit(f'dsjs\t{reg()[0]},{L}')
    emit(f'dsj\t{reg()[0]},{L}')
    emit(f'dsj\t{reg()[0]},K{blk}')
    emit(f'jr{rng.choice(conds)}\t{L}')
    emit(f'jr{rng.choice(conds)}\tK{blk},l')

open(sys.argv[1], 'w').write('\n'.join(lines) + '\n')
