#!/usr/bin/env python3
"""P-code semantic tests for Ghidra's emulator (EmuCheck.java), TMS34010.

  emu_tests.py <outdir> [--break N]   -> emu.bin, emu.txt

Each test is a short instruction sequence at its own 0x100-byte-aligned Ghidra address, ending in
a JRUC to itself (the stop address). Expected values were worked out by hand from the TMS34010
User's Guide (several are the guide's own examples, marked "UG"). All addresses in registers are
bit addresses; @addr in an expectation is a Ghidra (byte) address = bit address / 8. SP starts
at 60000h (byte C000h), ST at 00000010h. Data area: byte 8000h (bit 40000h).
--break N makes the expectation of test N wrong (to show that a wrong expectation fails).
"""
import struct
import sys

M = 0xffffffff


def R(name):
    if name == 'SP':
        return None, 15
    return (1 if name[0] == 'B' else 0), int(name[1:])


def rr(base, rs, rd):
    fs, s = R(rs)
    fd, d = R(rd)
    f = fd if fd is not None else (fs or 0)
    return [base | (s << 5) | (f << 4) | d]


def r1(base, rd):
    f, d = R(rd)
    return [base | ((f or 0) << 4) | d]


def kr(base, k, rd):
    f, d = R(rd)
    return [base | ((k & 31) << 5) | ((f or 0) << 4) | d]


def lohi(v):
    return [v & 0xffff, (v >> 16) & 0xffff]


ADD = lambda s, d: rr(0x4000, s, d)
ADDC = lambda s, d: rr(0x4200, s, d)
SUB = lambda s, d: rr(0x4400, s, d)
SUBB = lambda s, d: rr(0x4600, s, d)
CMP = lambda s, d: rr(0x4800, s, d)
BTSTR = lambda s, d: rr(0x4a00, s, d)
MOVE = lambda s, d: rr(0x4c00, s, d)
MOVEX = lambda s, d: rr(0x4e00, s, d.replace('B', 'A') if s[0] == 'B' else d.replace('B', 'A'))
AND = lambda s, d: rr(0x5000, s, d)
ANDN = lambda s, d: rr(0x5200, s, d)
OR = lambda s, d: rr(0x5400, s, d)
XOR = lambda s, d: rr(0x5600, s, d)
DIVS = lambda s, d: rr(0x5800, s, d)
DIVU = lambda s, d: rr(0x5a00, s, d)
MPYS = lambda s, d: rr(0x5c00, s, d)
MPYU = lambda s, d: rr(0x5e00, s, d)
SLA = lambda s, d: rr(0x6000, s, d)
SLL = lambda s, d: rr(0x6200, s, d)
SRA = lambda s, d: rr(0x6400, s, d)
SRL = lambda s, d: rr(0x6600, s, d)
RL = lambda s, d: rr(0x6800, s, d)
LMO = lambda s, d: rr(0x6a00, s, d)
MODS = lambda s, d: rr(0x6c00, s, d)
MODU = lambda s, d: rr(0x6e00, s, d)
ADDXY = lambda s, d: rr(0xe000, s, d)
SUBXY = lambda s, d: rr(0xe200, s, d)
CMPXY = lambda s, d: rr(0xe400, s, d)
CPW = lambda s, d: rr(0xe600, s, d)
CVXYL = lambda s, d: rr(0xe800, s, d)
MOVX = lambda s, d: rr(0xec00, s, d)
MOVY = lambda s, d: rr(0xee00, s, d)
PIXT_RI = lambda s, d: rr(0xf800, s, d)
ADDK = lambda k, d: kr(0x1000, k, d)
SUBK = lambda k, d: kr(0x1400, k, d)
MOVK = lambda k, d: kr(0x1800, k, d)
BTSTK = lambda b, d: kr(0x1c00, 31 - b, d)
SLAK = lambda k, d: kr(0x2000, k, d)
SLLK = lambda k, d: kr(0x2400, k, d)
SRAK = lambda k, d: kr(0x2800, 32 - k, d)
SRLK = lambda k, d: kr(0x2c00, 32 - k, d)
RLK = lambda k, d: kr(0x3000, k, d)
ABS = lambda d: r1(0x0380, d)
NEG = lambda d: r1(0x03a0, d)
NEGB = lambda d: r1(0x03c0, d)
NOT = lambda d: r1(0x03e0, d)
EXGPC = lambda d: r1(0x0120, d)
GETPC = lambda d: r1(0x0140, d)
JUMP = lambda d: r1(0x0160, d)
GETST = lambda d: r1(0x0180, d)
PUTST = lambda d: r1(0x01a0, d)
CALL = lambda d: r1(0x0920, d)
REV = lambda d: r1(0x0020, d)
SEXT = lambda d, f: r1(0x0500 | (f << 9), d)
ZEXT = lambda d, f: r1(0x0520 | (f << 9), d)
EXGF = lambda d, f: r1(0xd500 | (f << 9), d)
MOVI = lambda v, d: r1(0x09c0, d) + [v & 0xffff]
MOVIL = lambda v, d: r1(0x09e0, d) + lohi(v)
ADDIL = lambda v, d: r1(0x0b20, d) + lohi(v)
CMPI = lambda v, d: r1(0x0b40, d) + [~v & 0xffff]
CMPIL = lambda v, d: r1(0x0b60, d) + lohi(~v & M)
ANDI = lambda v, d: r1(0x0b80, d) + lohi(~v & M)
ORI = lambda v, d: r1(0x0ba0, d) + lohi(v)
XORI = lambda v, d: r1(0x0bc0, d) + lohi(v)
SUBI = lambda v, d: r1(0x0be0, d) + [~v & 0xffff]
SETF = lambda fs, fe, f: [0x0540 | (f << 9) | (fe << 5) | (fs & 31)]
MMTM = lambda d, regs: r1(0x0980, d) + [sum(1 << (15 - int(r[1:])) for r in regs)]
MMFM = lambda d, regs: r1(0x09a0, d) + [sum(1 << int(r[1:]) for r in regs)]
MV_RN = lambda s, d, f: rr(0x8000 | (f << 9), s, d)
MV_NR = lambda s, d, f: rr(0x8400 | (f << 9), s, d)
MV_NIR = lambda s, d, f: rr(0x9400 | (f << 9), s, d)
MV_RDN = lambda s, d, f: rr(0xa000 | (f << 9), s, d)
MV_RNO = lambda s, d, o, f: rr(0xb000 | (f << 9), s, d) + [o & 0xffff]
MV_NOR = lambda s, d, o, f: rr(0xb400 | (f << 9), s, d) + [o & 0xffff]
MOVB_RN = lambda s, d: rr(0x8c00, s, d)
MOVB_NR = lambda s, d: rr(0x8e00, s, d)
MV_RA = lambda s, a, f: r1(0x0580 | (f << 9), s) + lohi(a)
MV_AR = lambda a, d, f: r1(0x05a0 | (f << 9), d) + lohi(a)
MV_AA = lambda a, b, f: [0x05c0 | (f << 9)] + lohi(a) + lohi(b)
MOVB_AR = lambda a, d: r1(0x07e0, d) + lohi(a)
NOP, CLRC, SETC, DINT, EINT = [0x0300], [0x0320], [0x0de0], [0x0360], [0x0d60]
PUSHST, POPST, RETI = [0x01e0], [0x01c0], [0x0940]
FILL_L = [0x0fc0]
FILL_XY = [0x0fe0]
LINE0 = [0xdf1a]
PIXBLT_LL = [0x0f00]
PIXT_RIXY = lambda s, d: rr(0xf000, s, d)
RETS = lambda n=0: [0x0960 | n]
TRAP = lambda n: [0x0900 | n]
CC = {'UC': 0, 'P': 1, 'LS': 2, 'HI': 3, 'LT': 4, 'GE': 5, 'LE': 6, 'GT': 7, 'C': 8, 'NC': 9,
      'EQ': 10, 'NE': 11, 'V': 12, 'NV': 13, 'N': 14, 'NN': 15}


class Asm:
    """Two-pass assembler for one test: items are word lists or callables of (pc, labels)."""

    def __init__(self, base):
        self.base = base

    def build(self, items):
        labels, out = {}, []
        for pass_ in (0, 1):
            pc = self.base
            out = []
            for it in items:
                if isinstance(it, str):
                    labels[it] = pc
                    continue
                w = it(pc, labels) if callable(it) else it
                out += w
                pc += 2 * len(w)
        return out, labels


def jr(cc, lab):     # short relative: displacement in words from the next instruction
    return lambda pc, L: [0xc000 | (CC[cc] << 8) | (((L.get(lab, pc + 2) - (pc + 2)) // 2) & 0xff)]


def jrl(cc, lab):    # long relative
    return lambda pc, L: [0xc000 | (CC[cc] << 8), ((L.get(lab, pc + 4) - (pc + 4)) // 2) & 0xffff]


def ja(cc, lab):
    return lambda pc, L: [0xc080 | (CC[cc] << 8)] + lohi(L.get(lab, 0) * 8)


def calla(lab):
    return lambda pc, L: [0x0d5f] + lohi(L.get(lab, 0) * 8)


def callr(lab):
    return lambda pc, L: [0x0d3f, ((L.get(lab, pc + 4) - (pc + 4)) // 2) & 0xffff]


def dsj(op, rd, lab):
    base = {'DSJ': 0x0d80, 'DSJEQ': 0x0da0, 'DSJNE': 0x0dc0}[op]
    return lambda pc, L: r1(base, rd) + [((L.get(lab, pc + 4) - (pc + 4)) // 2) & 0xffff]


def dsjs(rd, lab):
    def f(pc, L):
        d = (L.get(lab, pc + 2) - (pc + 2)) // 2
        return kr(0x3800 | ((1 << 10) if d < 0 else 0), abs(d), rd)
    return f


def movil_label(lab, rd):
    return lambda pc, L: r1(0x09e0, rd) + lohi(L.get(lab, 0) * 8)


def stop():
    return lambda pc, L: [0xc0ff]   # JRUC to itself


ST0 = 0x10
# implied operands of the User's Guide PIXT XY examples (DPTCH 800h, CONVDP 14h, PSIZE 4)
PXY = {'A0': 6, 'B3': 0x800, 'B4': 0x20000, 'B5': 0x00300020, 'B6': 0x00500142,
       ('@18000028', 2): 0x14, ('@1800002a', 2): 4}
# FILL XY examples: DADDR 520007h, DPTCH 100h, OFFSET 10000h (+30000h), WSTART 30000Ch,
# WEND 530014h, DYDX 30012h, COLOR1 FFFFFFFFh, CONVDP 17h, PSIZE 4; rows of nibbles 0..F 0..F
ROW = 0xfedcba9876543210
PB = {'B1': 0x100, 'B3': 0x100, 'B7': 0x00010004, ('@1800002a', 2): 16,
      ('@8000', 8): 0x0004000300020001, ('@8008', 2): 0}
LN = {'B0': 0xfffffffb, 'B2': 0, 'B4': 0x40000, 'B5': 0, 'B6': 2, 'B7': 5, 'B9': 0x1234, 'B10': 6,
      'B11': 0x00010001, 'B12': 1, 'B13': M, ('@18000028', 2): 0x17, ('@1800002a', 2): 16}
FXY = {'B2': 0x00520007, 'B3': 0x100, 'B4': 0x40000, 'B5': 0x0030000c, 'B6': 0x00530014,
       'B7': 0x00030012, 'B9': 0xffffffff, ('@18000028', 2): 0x17, ('@1800002a', 2): 4,
       ('@8a40', 8): ROW, ('@8a48', 8): ROW, ('@8a60', 8): ROW, ('@8a68', 8): ROW,
       ('@8a80', 8): ROW, ('@8a88', 8): ROW}
D = 0x8000           # data area (byte); bit address 0x40000

# (name, items, init, expect). init/expect: register -> value, or ('@addr', size) -> value
T = [
    ('add_ug', [ADD('A1', 'A0')], {'A1': M, 'A0': M}, {'A0': 0xfffffffe, 'N': 1, 'C': 1, 'Z': 0, 'V': 0}),
    ('add_ovf_ug', [ADD('A1', 'A0')], {'A1': 0x7fffffff, 'A0': 1}, {'A0': 0x80000000, 'N': 1, 'C': 0, 'Z': 0, 'V': 1}),
    ('add_zero_ug', [ADD('A1', 'A0')], {'A1': M, 'A0': 1}, {'A0': 0, 'N': 0, 'C': 1, 'Z': 1, 'V': 0}),
    ('addc_ug', [SETC, ADDC('A1', 'A0')], {'A1': M, 'A0': M}, {'A0': M, 'N': 1, 'C': 1, 'Z': 0, 'V': 0}),
    ('addc2_ug', [SETC, ADDC('A1', 'A0')], {'A1': M, 'A0': 0x80000000}, {'A0': 0x80000000, 'N': 1, 'C': 1, 'Z': 0, 'V': 0}),
    ('addc_cin_carry', [SETC, ADDC('A1', 'A0')], {'A1': M, 'A0': 0}, {'A0': 0, 'N': 0, 'C': 1, 'Z': 1, 'V': 0}),
    ('addk_addi', [ADDK(32, 'B1'), ADDIL(0x10000, 'B1')], {'B1': 0xfffffff0}, {'B1': 0x10010, 'C': 0}),
    ('sub', [SUB('A1', 'A0')], {'A0': 5, 'A1': 7}, {'A0': 0xfffffffe, 'N': 1, 'C': 1, 'Z': 0, 'V': 0}),
    ('sub_ovf', [SUB('A1', 'A0')], {'A0': 0x80000000, 'A1': 1}, {'A0': 0x7fffffff, 'N': 0, 'C': 0, 'Z': 0, 'V': 1}),
    ('subb', [SETC, SUBB('A1', 'A0')], {'A0': 5, 'A1': 5}, {'A0': M, 'N': 1, 'C': 1, 'Z': 0, 'V': 0}),
    ('subb_bin_borrow', [SETC, SUBB('A1', 'A0')], {'A0': 0, 'A1': M}, {'A0': 0, 'C': 1, 'Z': 1}),
    ('subi_iw', [SUBI(3, 'A0')], {'A0': 10}, {'A0': 7, 'N': 0, 'C': 0, 'Z': 0, 'V': 0}),
    ('subk', [SUBK(32, 'A0')], {'A0': 0x10}, {'A0': 0xfffffff0, 'N': 1, 'C': 1}),
    ('cmpi_iw', [CMPI(5, 'A0')], {'A0': 5}, {'A0': 5, 'Z': 1, 'N': 0, 'C': 0, 'V': 0}),
    ('cmpi_il', [CMPIL(0x12345678, 'A0')], {'A0': 0x12345677}, {'Z': 0, 'N': 1, 'C': 1, 'V': 0}),
    ('neg_min', [NEG('A0')], {'A0': 0x80000000}, {'A0': 0x80000000, 'N': 1, 'C': 1, 'Z': 0, 'V': 1}),
    ('negb', [SETC, NEGB('A0')], {'A0': 0}, {'A0': M, 'N': 1, 'C': 1, 'Z': 0, 'V': 0}),
    ('abs_ug', [ABS('A1')], {'A1': 0x80000001, 'ST': 0x40000010}, {'A1': 0x7fffffff, 'N': 0, 'C': 1, 'Z': 0, 'V': 0}),
    ('abs_min_ug', [ABS('A1')], {'A1': 0x80000000}, {'A1': 0x80000000, 'N': 1, 'Z': 0, 'V': 1}),
    ('abs_pos_ug', [ABS('A1')], {'A1': 1}, {'A1': 1, 'N': 1, 'Z': 0, 'V': 0}),
    ('abs_zero_ug', [ABS('A1')], {'A1': 0}, {'A1': 0, 'N': 0, 'Z': 1, 'V': 0}),
    ('logic', [AND('A1', 'A0'), ANDN('A2', 'A3'), OR('A1', 'A6'), XOR('A4', 'A4'), NOT('A7')],
     {'A0': 0xf0f0, 'A1': 0xff00, 'A2': 0xff, 'A3': 0xffff, 'A4': 0x1234, 'A6': 0x0f, 'A7': M},
     {'A0': 0xf000, 'A3': 0xff00, 'A6': 0xff0f, 'A4': 0, 'A7': 0, 'Z': 1}),
    ('andi', [ANDI(0x0000ff00, 'A0')], {'A0': 0x12345678}, {'A0': 0x5600, 'Z': 0}),
    ('ori_xori', [ORI(0x80000000, 'A0'), XORI(M, 'A1')], {'A0': 1, 'A1': 0x0f}, {'A0': 0x80000001, 'A1': 0xfffffff0, 'Z': 0}),
    ('btst_k', [BTSTK(3, 'A0')], {'A0': 8}, {'Z': 0}),
    ('btst_r', [BTSTR('A1', 'A2')], {'A1': 0x21, 'A2': 1}, {'Z': 1}),
    ('sla_ovf', [SLAK(1, 'A0')], {'A0': 0x40000000}, {'A0': 0x80000000, 'C': 0, 'V': 1, 'N': 1, 'Z': 0}),
    ('sla_carry', [SLAK(4, 'A0')], {'A0': 0x12345678}, {'A0': 0x23456780, 'C': 1, 'V': 1, 'N': 0, 'Z': 0}),
    ('sla_noovf', [SLA('A1', 'A0')], {'A0': 0xfffffff0, 'A1': 3}, {'A0': 0xffffff80, 'C': 1, 'V': 0, 'N': 1}),
    ('sll_r', [SLL('A1', 'A0')], {'A0': 0x80000001, 'A1': 0x24}, {'A0': 0x10, 'C': 0, 'Z': 0}),
    ('sra_k', [SRAK(4, 'A0')], {'A0': 0x80000018}, {'A0': 0xf8000001, 'C': 1, 'N': 1, 'Z': 0}),
    ('srl_r', [SRL('A1', 'A0')], {'A0': 0x80000018, 'A1': 0xfffffffc}, {'A0': 0x08000001, 'C': 1, 'Z': 0}),
    ('srl_k_zero', [SRLK(1, 'A0')], {'A0': 1}, {'A0': 0, 'C': 1, 'Z': 1}),
    ('rl_k', [RLK(8, 'A0')], {'A0': 0x12345678}, {'A0': 0x34567812, 'C': 0, 'Z': 0}),
    ('rl_r', [RL('A1', 'A0')], {'A0': 0xf0000000, 'A1': 4}, {'A0': 0xf, 'C': 1, 'Z': 0}),
    ('mpys', [MPYS('A1', 'A0')], {'A0': 0xfffffffe, 'A1': 3}, {'A0': M, 'A1': 0xfffffffa, 'N': 1, 'Z': 0}),
    ('mpys_fs1_8', [SETF(8, 0, 1), MPYS('A2', 'A4')], {'A2': 0xff, 'A4': 5}, {'A4': M, 'A5': 0xfffffffb, 'N': 1}),
    ('mpyu', [MPYU('A2', 'A4')], {'A2': M, 'A4': M}, {'A4': 0xfffffffe, 'A5': 1, 'Z': 0}),
    ('divs_64', [DIVS('A2', 'A0')], {'A0': 1, 'A1': 0, 'A2': 3}, {'A0': 0x55555555, 'A1': 1, 'N': 0, 'Z': 0, 'V': 0}),
    ('divs_odd', [DIVS('A2', 'A1')], {'A1': 0xfffffff9, 'A2': 2}, {'A1': 0xfffffffd, 'N': 1, 'V': 0}),
    ('divu_ovf', [DIVU('A2', 'A0')], {'A0': 5, 'A1': 0, 'A2': 5}, {'A0': 5, 'A1': 0, 'V': 1, 'Z': 0}),
    ('divs_zero', [DIVS('A2', 'A1')], {'A1': 7, 'A2': 0}, {'A1': 7, 'V': 1, 'N': 0, 'Z': 0}),
    ('mods', [MODS('A2', 'A1')], {'A1': 0xfffffff9, 'A2': 2}, {'A1': M, 'N': 1, 'V': 0}),
    ('modu', [MODU('A2', 'A1')], {'A1': M, 'A2': 10}, {'A1': 5, 'Z': 0, 'V': 0}),
    ('lmo', [LMO('A1', 'A0')], {'A1': 0x10000}, {'A0': 15, 'Z': 0}),
    ('lmo_zero', [LMO('A1', 'A0')], {'A1': 0, 'A0': 5}, {'A0': 0, 'Z': 1}),
    ('sext_zext', [SETF(8, 0, 0), SEXT('A0', 0), ZEXT('A1', 0)], {'A0': 0x12345680, 'A1': 0xffffff00},
     {'A0': 0xffffff80, 'A1': 0, 'Z': 1, 'N': 1}),
    ('movi_movk', [MOVI(0xfffe, 'A0'), MOVK(32, 'A1'), MOVK(5, 'A2')], {}, {'A0': 0xfffffffe, 'A1': 32, 'A2': 5, 'N': 1, 'Z': 0, 'V': 0}),
    ('move_cross', [MOVEX('A3', 'B4')], {'A3': 0, 'B4': 7}, {'B4': 0, 'Z': 1, 'N': 0}),
    ('movx_movy', [MOVX('A1', 'A0'), MOVY('A1', 'A2')], {'A0': 0x11112222, 'A1': 0x33334444, 'A2': 0x55556666},
     {'A0': 0x11114444, 'A2': 0x33336666}),
    ('field_store_bit5', [SETF(12, 0, 0), MV_RN('A0', 'A1', 0)], {'A0': 0xabc, 'A1': 0x40005}, {('@8000', 4): 0x00015780}),
    ('field_load_sext', [SETF(12, 1, 0), MV_NR('A1', 'A2', 0)], {'A1': 0x40005, ('@8000', 4): 0x00015780},
     {'A2': 0xfffffabc, 'N': 1, 'Z': 0, 'V': 0}),
    ('field_postinc', [SETF(16, 0, 0), MV_NIR('A1', 'A2', 0)], {'A1': 0x40000, ('@8000', 2): 0x8001},
     {'A2': 0x8001, 'A1': 0x40010, 'N': 0}),
    ('field_predec_32', [SETF(0, 0, 0), MV_RDN('A0', 'A1', 0)], {'A0': 0xdeadbeef, 'A1': 0x40020},
     {'A1': 0x40000, ('@8000', 4): 0xdeadbeef}),
    ('field_offset', [SETF(16, 0, 0), MV_RNO('A0', 'A1', 0x10, 0), MV_NOR('A1', 'A2', 0x10, 0)], {'A0': 0x1234, 'A1': 0x40000},
     {('@8002', 2): 0x1234, 'A2': 0x1234}),
    ('field_neg_offset', [MV_NOR('A1', 'A2', -0x20, 1)], {'A1': 0x40020, ('@8000', 4): 0x89abcdef}, {'A2': 0x89abcdef, 'N': 1}),
    ('movb_unaligned', [MOVB_RN('A0', 'A1'), MOVB_NR('A1', 'A2')], {'A0': 0x1f5, 'A1': 0x40004, ('@8000', 2): 0xffff},
     {('@8000', 2): 0xff5f, 'A2': 0xfffffff5, 'N': 1}),
    ('move_abs', [MV_RA('A0', 0x40010, 1), MV_AR(0x40010, 'A1', 1)], {'A0': 0x11223344}, {('@8002', 4): 0x11223344, 'A1': 0x11223344, 'N': 0}),
    ('move_abs_abs', [SETF(16, 0, 0), MV_AA(0x40000, 0x40020, 0)], {('@8000', 2): 0xbeef}, {('@8004', 2): 0xbeef}),
    ('movb_abs', [MOVB_AR(0x40008, 'A0')], {('@8000', 2): 0x8000}, {'A0': 0xffffff80, 'N': 1}),
    ('mmtm_mmfm', [MMTM('SP', ['A0', 'A1']), XOR('A0', 'A0'), XOR('A1', 'A1'), MMFM('SP', ['A0', 'A1'])],
     {'A0': 0x11111111, 'A1': 0x22222222},
     {'A0': 0x11111111, 'A1': 0x22222222, 'SP': 0x60000, ('@bff8', 4): 0x22222222, ('@bffc', 4): 0x11111111}),
    ('calla_rets', [calla('sub'), MOVK(1, 'A5'), jr('UC', 'end'), 'sub', MOVK(7, 'A0'), RETS(), 'end'],
     {}, {'A0': 7, 'A5': 1, 'SP': 0x60000, ('@bffc', 4): None}),
    ('callr_rets2', [callr('sub'), jr('UC', 'end'), 'sub', MOVK(3, 'A0'), RETS(2), 'end'],
     {}, {'A0': 3, 'SP': 0x60020}),
    ('call_rd', [movil_label('sub', 'A1'), CALL('A1'), MOVK(2, 'A3'), jr('UC', 'end'), 'sub', MOVK(9, 'A2'), RETS(), 'end'],
     {}, {'A2': 9, 'A3': 2, 'SP': 0x60000}),
    ('trap_reti', [TRAP(5), MOVK(4, 'A4'), jr('UC', 'end'), 'h', MOVK(3, 'A0'), GETST('A1'), RETI, 'end'],
     {'ST': 0x40000010, ('@1fffffe8', 4): 'h'}, {'A0': 3, 'A1': 0x10, 'A4': 4, 'ST': 0x40000010, 'SP': 0x60000}),
    ('pushst_popst', [PUSHST, SETC, POPST], {}, {'ST': 0x10, ('@bffc', 4): 0x10, 'SP': 0x60000}),
    ('putst_getst', [PUTST('A0'), GETST('A1')], {'A0': 0xa0200845}, {'A1': 0xa0200845, 'N': 1, 'Z': 1, 'C': 0, 'IE': 1, 'FE1': 1}),
    ('exgf0_ug', [EXGF('A5', 0)], {'A5': 0xffffffc0, 'ST': 0xf0000fff}, {'A5': 0x3f, 'ST': 0xf0000fc0}),
    ('exgf1_ug', [EXGF('A5', 1)], {'A5': 0xffffffc0, 'ST': 0xf0000fff}, {'A5': 0x3f, 'ST': 0xf000003f}),
    ('dsj_loop', [MOVK(5, 'A0'), XOR('A1', 'A1'), 'l', ADDK(2, 'A1'), dsj('DSJ', 'A0', 'l')], {}, {'A0': 0, 'A1': 10}),
    ('dsjs_loop', [MOVK(4, 'A0'), XOR('A1', 'A1'), 'l', ADDK(3, 'A1'), dsjs('A0', 'l')], {}, {'A0': 0, 'A1': 12}),
    ('dsjeq_taken', [XOR('A2', 'A2'), MOVK(3, 'A0'), dsj('DSJEQ', 'A0', 't'), MOVK(1, 'A4'), 't', MOVK(1, 'A3')], {},
     {'A0': 2, 'A3': 1, 'A4': 0}),
    ('dsjne_skip', [XOR('A2', 'A2'), MOVK(3, 'A0'), dsj('DSJNE', 'A0', 't'), MOVK(1, 'A4'), 't', MOVK(1, 'A3')], {},
     {'A0': 3, 'A3': 1, 'A4': 1}),
    ('jr_signed', [CMP('A1', 'A0'), jr('LT', 's1'), MOVK(1, 'A2'), 's1', jr('GT', 's2'), MOVK(1, 'A4'), 's2', MOVK(2, 'A3')],
     {'A0': 5, 'A1': 7}, {'A2': 0, 'A3': 2, 'A4': 1}),
    ('jr_unsigned', [CMP('A1', 'A0'), jr('HI', 's1'), MOVK(1, 'A2'), 's1', jr('LS', 's2'), MOVK(1, 'A4'), 's2'],
     {'A0': 0xffffffff, 'A1': 1}, {'A2': 0, 'A4': 1}),
    ('jr_long_ja', [jrl('UC', 'a'), MOVK(1, 'A2'), 'a', ja('UC', 'b'), MOVK(1, 'A3'), 'b', ja('NE', 'c'), MOVK(1, 'A4'), 'c'],
     {'ST': 0x20000010}, {'A2': 0, 'A3': 0, 'A4': 1}),
    ('getpc_jump', [GETPC('A0'), 'n', movil_label('t', 'A1'), JUMP('A1'), MOVK(1, 'A2'), 't'], {},
     {'A0': 'n', 'A2': 0}),
    ('exgpc', [movil_label('sub', 'A1'), EXGPC('A1'), 'ret', jr('UC', 'end'), 'sub', MOVK(1, 'A2'), EXGPC('A1'), 'end'],
     {}, {'A2': 1, 'A1': 'end'}),
    ('addxy', [ADDXY('A1', 'A0')], {'A0': 0x0001ffff, 'A1': 0x00010001}, {'A0': 0x00020000, 'N': 1, 'C': 0, 'Z': 0, 'V': 0}),
    ('subxy', [SUBXY('A1', 'A0')], {'A0': 0x00050005, 'A1': 0x00070003}, {'A0': 0xfffe0002, 'N': 0, 'C': 1, 'Z': 0, 'V': 0}),
    ('cmpxy', [CMPXY('A1', 'A0')], {'A0': 0x00050005, 'A1': 0x00050007}, {'A0': 0x00050005, 'N': 0, 'V': 1, 'Z': 1, 'C': 0}),
    ('cpw', [CPW('A1', 'A0')], {'A1': 0x00080030, 'B5': 0x00100010, 'B6': 0x00200020}, {'A0': 0xc0, 'V': 1}),
    ('cvxyl', [CVXYL('A1', 'A0')], {'A1': 0x00030005, 'B4': 0x100, ('@18000028', 2): 0x14, ('@1800002a', 2): 8},
     {'A0': 0x1928}),
    ('rev_misc', [REV('A0'), EINT, SETC, CLRC, DINT, SETC], {}, {'A0': 8, 'C': 1, 'IE': 0}),
    ('pixt_ug', [PIXT_RI('A0', 'A1')], {'A0': 6, 'A1': 0x40008, ('@1800002a', 2): 4}, {('@8000', 2): 0x0600}),
    ('pixt_xor_ug', [PIXT_RI('A0', 'A1')], {'A0': 6, 'A1': 0x40008, ('@1800002a', 2): 4, ('@18000016', 2): 0x2800,
                                            ('@8000', 2): 0x0300}, {('@8000', 2): 0x0500}),
    ('pixt_pmask_ug', [PIXT_RI('A0', 'A1')], {'A0': 6, 'A1': 0x40008, ('@1800002a', 2): 4, ('@1800002c', 2): 0xaaaa},
     {('@8000', 2): 0x0400}),
    ('fill_ug', [FILL_L],
     {'B2': 0x40010, 'B3': 0x80, 'B7': 0x0002000d, 'B9': 0x30303030, ('@1800002a', 2): 8,
      ('@8000', 8): 0x7766554433221100, ('@8008', 8): 0xffeeddccbbaa9988,
      ('@8010', 8): 0x7766554433221100, ('@8018', 8): 0xffeeddccbbaa9988},
     {('@8000', 8): 0x3030303030301100, ('@8008', 8): 0xff30303030303030,
      ('@8010', 8): 0x3030303030301100, ('@8018', 8): 0xff30303030303030, 'B2': 0x400f8}),
    # PIXT Rs,*Rd.XY window examples (UG 12-217) with OFFSET moved to put the pixel at bit 40508h
    ('pixt_xy_w3_in_ug', [PIXT_RIXY('A0', 'A1')], {**PXY, 'A1': 0x00400142, ('@18000016', 2): 0xc0},
     {('@80a0', 2): 0x0600, 'V': 0}),
    ('pixt_xy_w3_out_ug', [PIXT_RIXY('A0', 'A1')], {**PXY, 'A1': 0x00400143, ('@18000016', 2): 0xc0},
     {('@80a0', 2): 0, 'V': 1, ('@18000024', 2): 0}),
    ('pixt_xy_w2_out_ug', [PIXT_RIXY('A0', 'A1')], {**PXY, 'A1': 0x00400143, ('@18000016', 2): 0x80},
     {('@80a0', 2): 0, 'V': 1, ('@18000024', 2): 0x800}),
    # FILL XY examples 4 (W=3 clip) and 5 (plane mask), UG 12-87, OFFSET moved by 30000h
    ('fill_xy_clip_ug', [FILL_XY], {**FXY, ('@18000016', 2): 0xc0},
     {('@8a40', 8): 0xffffba9876543210, ('@8a48', 8): 0xfedcba98765fffff,
      ('@8a60', 8): 0xffffba9876543210, ('@8a68', 8): 0xfedcba98765fffff,
      ('@8a80', 8): ROW, ('@8a88', 8): ROW, 'V': 1}),
    ('fill_xy_pmask_ug', [FILL_XY], {**FXY, ('@1800002c', 2): 0x8888},
     {('@8a40', 8): 0xffffffff76543210, ('@8a48', 8): 0xfedcba9f77777777,
      ('@8a60', 8): 0xffffffff76543210, ('@8a68', 8): 0xfedcba9f77777777,
      ('@8a80', 8): 0xffffffff76543210, ('@8a88', 8): 0xfedcba9f77777777}),
    # LINE window modes (UG 12-101), horizontal line y=0, x=0..5, window x=0..2, PSIZE 16
    ('line_w2_abort', [LINE0], {**LN, ('@18000016', 2): 0x80},
     {('@8000', 8): 0x0000123412341234, 'V': 1, ('@18000024', 2): 0x800, 'B10': 3, 'B2': 3, 'B0': 0xfffffffb}),
    ('line_w1_hit', [LINE0], {**LN, ('@18000016', 2): 0x40},
     {('@8000', 8): 0, 'V': 0, ('@18000024', 2): 0x800, 'B10': 6, 'B2': 0}),
    ('line_w3_clip', [LINE0], {**LN, ('@18000016', 2): 0xc0},
     {('@8000', 8): 0x0000123412341234, ('@8008', 4): 0, 'V': 1, ('@18000024', 2): 0, 'B10': 0, 'B2': 6}),
    # PIXBLT L,L overlapping copy one pixel to the right (PSIZE 16): forward (PBH=0) smears the
    # first pixel; right-to-left (PBH=1, corners one pixel past the right edge) moves the row
    ('pixblt_ll_fwd', [PIXBLT_LL], {**PB, 'B0': 0x40000, 'B2': 0x40010},
     {('@8000', 8): 0x0001000100010001, ('@8008', 2): 1, 'B0': 0x40100, 'B2': 0x40110}),
    ('pixblt_ll_pbh', [PIXBLT_LL], {**PB, 'B0': 0x40040, 'B2': 0x40050, ('@18000016', 2): 0x100},
     {('@8000', 8): 0x0003000200010001, ('@8008', 2): 4}),
]


def fmt(items, labels):
    out = []
    for k, v in items.items():
        if k in ('CPIN', 'CPOUT', 'CPCMD'):     # coprocessor lists (TMS34020), passed as written
            out.append(f'{k}={v}')
            continue
        if isinstance(v, str):
            v = labels[v] * 8
        if v is None:
            continue
        if isinstance(k, tuple):
            out.append(f'{k[0]}:{k[1]}={v & ((1 << (8 * k[1])) - 1):x}')
        else:
            out.append(f'{k}={v & M:x}')
    return ','.join(out) if out else '-'


def write(T, out, brk, first=0, prefix='emu'):
    """Writes <prefix>.bin and <prefix>.txt; test i is at Ghidra address first + 100h * i."""
    img = bytearray(first + 0x100 * len(T))
    lines = []
    for i, (name, items, init, exp) in enumerate(T):
        base = first + 0x100 * i
        words, labels = Asm(base).build(list(items) + ['__stop', stop()])
        assert len(words) * 2 <= 0x100, name
        struct.pack_into(f'<{len(words)}H', img, base, *words)
        ex = dict(exp)
        for k, v in exp.items():
            if v is None and isinstance(k, tuple):
                ex[k] = None
        if name == 'calla_rets':
            ex[('@bffc', 4)] = (base + 6) * 8          # return address pushed by CALLA (3 words)
        if i == brk:
            k = next(iter(ex))
            ex[k] = (labels[ex[k]] * 8 if isinstance(ex[k], str) else ex[k]) ^ 1
        lines.append(f'{name} {base:x} {labels["__stop"]:x} {fmt(init, labels)} {fmt(ex, labels)}')

    open(f'{out}/{prefix}.bin', 'wb').write(img)
    open(f'{out}/{prefix}.txt', 'w').write('\n'.join(lines) + '\n')
    print(f'{len(T)} tests')


if __name__ == '__main__':
    write(T, sys.argv[1], int(sys.argv[sys.argv.index('--break') + 1]) if '--break' in sys.argv else -1)
