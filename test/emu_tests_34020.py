#!/usr/bin/env python3
"""P-code semantic tests for Ghidra's emulator (EmuCheck.java), TMS34020.

  emu_tests_34020.py <outdir> [--break N]   -> emu20.bin, emu20.txt

The TMS34020-only instructions and the TMS34010 instructions whose behaviour the TMS34020 changes
(REV, MMTM's N flag, PIXT to a register leaving V alone, transparency modes, 32-bit pixels, plane
mask and colours, CONVxP pitch conversion, the LINE pattern). Expected values were worked out by
hand from the TMS34020 User's Guide (TI 2564006-9721, 1990); tests named *_ug use the guide's own
examples. MAME's TMS34020 core implements only a few of these instructions (CMPK, RMO, RPIX,
ADDXYI, BLMOVE, CLIP, CVDXYL for the B file, SETCDP), so it is no oracle here.

Conventions as in emu_tests.py (bit addresses in registers, @addr = Ghidra byte address). The
tests start at Ghidra address 1000h; addresses below are free for the TRAPL vectors of negative
trap numbers (TRAPL -1 uses bit address 0). Coprocessor tests use EmuCheck's CPIN/CPOUT/CPCMD
(a coprocessor that returns queued values and records what it receives).
"""
import sys

from emu_tests import (M, R, rr, r1, kr, lohi, jr, stop, write, ADD, XOR, MOVK, GETST, SETF, MMTM, CVXYL,
                       PIXT_RI, REV, RETI, FILL_L)

CMPK = lambda k, d: kr(0x3400, k, d)
RMO = lambda s, d: rr(0x7a00, s, d)
SWAPF = lambda s, d: rr(0x7e00, s, d)
ADDXYI = lambda v, d: r1(0x0c00, d) + lohi(v)
CVSXYL = lambda s, d: rr(0xea00, s, d)
CVDXYL = lambda d: r1(0x0a80, d)
CVMXYL = lambda d: r1(0x0a60, d)
RPIX = lambda d: r1(0x0280, d)
EXGPS = lambda d: r1(0x02a0, d)
GETPS = lambda d: r1(0x02c0, d)
PIXT_IR = lambda s, d: rr(0xfa00, s, d)
SETCSP, SETCDP, SETCMP = [0x0251], [0x0273], [0x02fb]
IDLE, MWAIT = [0x0040], [0x0080]
BLMOVE = lambda s, d: [0x00f0 | (s << 1) | d]
TRAPL = lambda n: [0x080f, n & 0xffff]
RETM, CLIP = [0x0860], [0x08f2]
VLCOL, PFILL, VFILL, VBLT = [0x0a00], [0x0a37], [0x0a57], [0x0857]
FPIXEQ, FPIXNE = [0x0abb], [0x0adb]
LINIT = [0x0c57]
PIXBLT_LML, TFILL = [0x0e1a], [0x0efa]
FLINE0, FLINE1, LINE0 = [0xde1a], [0xde9a], [0xdf1a]


def regx(name):     # register field of a coprocessor instruction word: R bit and number
    f, n = R(name)
    return ((f or 0) << 4) | n


def cpx(id_, cmd, size=0, low=0):
    return lohi((id_ << 29) | (cmd << 8) | (size << 7) | low)


CEXEC = lambda size, cmd, id_: [0x0600] + cpx(id_, cmd, size)
CMOVGC1 = lambda rs, cmd, id_: r1(0x0620, rs) + cpx(id_, cmd)
CMOVGC2 = lambda rs1, rs2, size, cmd, id_: r1(0x0640, rs1) + cpx(id_, cmd, size, regx(rs2))
CMOVCS = lambda cmd, id_: [0x0660] + cpx(id_, cmd, 0, 1)
CMOVCG = lambda rd1, rd2, size, cmd, id_: r1(0x0660, rd1) + cpx(id_, cmd, size, regx(rd2))
CMOVMC_INC = lambda rs, n, size, cmd, id_: [0x0680 | (n & 31)] + cpx(id_, cmd, size, regx(rs))
CMOVMC_DEC = lambda rs, n, size, cmd, id_: [0x0820 | (n & 31)] + cpx(id_, cmd, size, regx(rs))
CMOVMC_REG = lambda rs, rd, size, cmd, id_: r1(0x06e0, rd) + cpx(id_, cmd, size, regx(rs))
CMOVCM_INC = lambda rd, n, size, cmd, id_: r1(0x06a0, rd) + cpx(id_, cmd, size, n & 31)
CMOVCM_DEC = lambda rd, n, size, cmd, id_: r1(0x06c0, rd) + cpx(id_, cmd, size, n & 31)

PS = '@1800002a'
CTL = '@18000016'
CONVSP, CONVDP, CONVMP, PMASK = '@18000026', '@18000028', '@18000030', '@1800002c'
# horizontal line y=0, x=0..5 (as emu_tests.py's LINE tests), PSIZE 16, DPTCH 100h
LN = {'B0': 0xfffffffb, 'B2': 0, 'B4': 0x40000, 'B5': 0, 'B6': 2, 'B7': 5, 'B9': 0x1234, 'B10': 6,
      'B11': 0x00010001, 'B12': 1, (CONVDP, 2): 0x17, (PS, 2): 16}
FL = {'B2': 0x40000, (CONVDP, 2): 0x17, (PS, 2): 16, 'B8': 0x5555, 'B9': 0x1234}
TF = {(PS, 2): 16, (CONVDP, 2): 0x17, 'B3': 0x100, 'B4': 0x40000, 'B0': 0x10000, 'B7': 0x40000,
      'B11': 0, 'B1': 0x8000, 'B10': 0xffff0000, 'B9': 0x77777777}
PF = {(PS, 2): 4, (CONVDP, 2): 0x17, 'B3': 0x100, 'B4': 0x40000, 'B13': 0xa5, 'B8': 0, 'B9': M}
WIN = {'B5': 0, 'B6': 0x00ff00ff}

T = [
    # --- arithmetic, bit search, swap ---
    ('cmpk_ug1', [CMPK(1, 'A0')], {'A0': 2}, {'A0': 2, 'N': 0, 'C': 0, 'Z': 0, 'V': 0}),
    ('cmpk_ug2', [CMPK(2, 'A0')], {'A0': 2}, {'N': 0, 'C': 0, 'Z': 1, 'V': 0}),
    ('cmpk_ug3', [CMPK(32, 'A0')], {'A0': 0}, {'N': 1, 'C': 1, 'Z': 0, 'V': 0}),
    ('cmpk_ug5', [CMPK(1, 'A0')], {'A0': 0x80000000}, {'N': 0, 'C': 0, 'Z': 0, 'V': 1}),
    ('rmo_ug', [RMO('A0', 'A1')], {'A0': 0x08000000, 'ST': 0x20000010}, {'A1': 0x1b, 'Z': 0}),
    ('rmo_zero_ug', [RMO('A0', 'A1')], {'A0': 0, 'A1': 5}, {'A1': 0, 'Z': 1}),
    ('rmo_bit31_ug', [RMO('B0', 'B1')], {'B0': 0x80000000}, {'B1': 0x1f, 'Z': 0}),
    ('addxyi_ug', [ADDXYI(0xffffffff, 'A0')], {'A0': 0x00020001}, {'A0': 0x00010000, 'N': 1, 'C': 0, 'Z': 0, 'V': 0}),
    ('addxyi_ug2', [ADDXYI(0xffff0000, 'A0')], {'A0': 0x00010000}, {'A0': 0, 'N': 1, 'C': 0, 'Z': 1, 'V': 0}),
    ('swapf_testset_ug', [SETF(1, 0, 0), SWAPF('A1', 'A0')], {'A0': 1, 'A1': 0x40003, ('@8000', 2): 0},
     {('@8000', 2): 0x0008, 'A0': 0, 'Z': 1, 'N': 0, 'V': 0}),
    ('swapf_field_sext', [SETF(8, 1, 0), SWAPF('A1', 'A0')], {'A0': 0x12, 'A1': 0x40004, ('@8000', 4): 0x00000f80},
     {('@8000', 4): 0x00000120, 'A0': 0xfffffff8, 'N': 1, 'Z': 0, 'V': 0}),
    ('rev_34020', [REV('A0')], {}, {'A0': 0x11}),
    ('mmtm_n_pos', [MMTM('SP', ['A0'])], {'A0': 7}, {'N': 1, 'SP': 0x5ffe0, ('@bffc', 4): 7}),
    ('mmtm_n_neg', [MMTM('A1', ['A0'])], {'A1': 0x80000040, 'ST': 0x80000010}, {'N': 0, 'A1': 0x80000020}),
    # --- program control ---
    ('trapl_m1_ug', [TRAPL(-1), MOVK(4, 'A4'), jr('UC', 'end'), 'h', MOVK(3, 'A0'), GETST('A1'), RETI, 'end'],
     {'ST': 0x40000010, ('@0', 4): 'h'}, {'A0': 3, 'A1': 0x10, 'A4': 4, 'ST': 0x40000010, 'SP': 0x60000}),
    ('trapl_33_ug', [TRAPL(33), MOVK(4, 'A4'), jr('UC', 'end'), 'h', MOVK(3, 'A0'), RETI, 'end'],
     {('@1fffff78', 4): 'h'}, {'A0': 3, 'A4': 4, 'SP': 0x60000}),
    ('trapl_push', [TRAPL(31), 'r'], {'ST': 0xc0000010, ('@1fffff80', 4): '__stop'},
     {'SP': 0x5ffc0, ('@bffc', 4): 'r', ('@bff8', 4): 0xc0000010, 'ST': 0x10}),
    ('retm_ug', [RETM, MOVK(1, 'A2'), 'r', MOVK(2, 'A3')],
     {'SP': 0x5ffc0, ('@bff8', 4): 0xc0000010, ('@bffc', 4): 'r'}, {'A2': 0, 'A3': 2, 'SP': 0x60000, 'ST': 0xc0000010}),
    ('idle_mwait', [IDLE, MOVK(1, 'A0'), MWAIT, MOVK(2, 'A1')], {}, {'A0': 1, 'A1': 2}),
    # --- block move ---
    ('blmove_aligned', [BLMOVE(0, 0)], {'B0': 0x40000, 'B2': 0x40100, 'B7': 0x40, ('@8000', 8): 0x1122334455667788},
     {('@8020', 8): 0x1122334455667788, 'B0': 0x40040, 'B2': 0x40140, 'B7': 0}),
    ('blmove_bits', [BLMOVE(1, 1)], {'B0': 0x40004, 'B2': 0x40103, 'B7': 12, ('@8000', 2): 0xabcd, ('@8020', 2): 0},
     {('@8020', 2): 0x55e0, 'B0': 0x40010, 'B2': 0x4010f, 'B7': 0}),
    ('blmove_40bits', [BLMOVE(1, 1)], {'B0': 0x40004, 'B2': 0x40108, 'B7': 40, ('@8000', 8): 0x0123456789abcdef},
     {('@8020', 8): 0x000056789abcde00, 'B0': 0x4002c, 'B2': 0x40130, 'B7': 0}),
    # --- pixel size, pitch and conversions ---
    ('exgps_getps_ug', [EXGPS('A0'), GETPS('A1')], {'A0': 1, (PS, 2): 8}, {'A0': 8, 'A1': 1, (PS, 2): 1}),
    ('rpix8_ug', [RPIX('A0')], {'A0': 0x12345634, (PS, 2): 8}, {'A0': 0x34343434}),
    ('rpix4_ug', [RPIX('B8')], {'B8': 0x1234567a, (PS, 2): 4}, {'B8': 0xaaaaaaaa}),
    ('rpix1_2_16_32', [RPIX('A0'), EXGPS('A4'), RPIX('A1'), EXGPS('A5'), RPIX('A2'), EXGPS('A6'), RPIX('A3')],
     {'A0': 3, 'A1': 6, 'A2': 0x1234beef, 'A3': 0x89abcdef, 'A4': 2, 'A5': 16, 'A6': 32, (PS, 2): 1},
     {'A0': M, 'A1': 0xaaaaaaaa, 'A2': 0xbeefbeef, 'A3': 0x89abcdef}),
    ('setcxp_ug', [SETCDP, SETCSP, SETCMP], {'B3': 0x1000, 'B1': 0x1400, 'B11': 0x19},
     {(CONVDP, 2): 0x13, (CONVSP, 2): 0x1513, (CONVMP, 2): 0}),
    ('setcxp_ug2', [SETCDP, SETCSP, SETCMP], {'B3': 0x400, 'B1': 0x8000, 'B11': 0x1400},
     {(CONVDP, 2): 0x15, (CONVSP, 2): 0x10, (CONVMP, 2): 0x1513}),
    ('cvdxyl_ug1', [SETCDP, MWAIT, CVDXYL('B2')], {'B3': 0x1000, 'B4': 0x100, (PS, 2): 4, 'B2': 0x00010001},
     {'B2': 0x1104, (CONVDP, 2): 0x13}),
    ('cvdxyl_ug2', [SETCDP, MWAIT, CVDXYL('B2')], {'B3': 0x1400, 'B4': 0, (PS, 2): 8, 'B2': 0x00010001},
     {'B2': 0x1408, (CONVDP, 2): 0x1513}),
    ('cvdxyl_ug3', [SETCDP, MWAIT, CVDXYL('A7')], {'B3': 0xe0, (PS, 2): 16, 'A4': 0xff300000, 'A7': 0x00010001},
     {'A7': 0xff3000f0, (CONVDP, 2): 0}),
    ('cvmxyl_ug2', [SETCMP, MWAIT, CVMXYL('B10')], {'B11': 0x1400, 'B10': 0x00010001}, {'B10': 0x1401}),
    ('cvmxyl_ug3', [SETCMP, MWAIT, CVMXYL('B10')], {'B11': 0xe0, 'B10': 0x00010001}, {'B10': 0xe1}),
    ('cvsxyl_ug', [CVSXYL('A0', 'A1')], {'A0': 0x100, 'A1': 0x00010001, (CONVSP, 2): 0x13, (PS, 2): 8}, {'A1': 0x1108}),
    ('cvxyl_ug', [CVXYL('A0', 'A1')], {'A0': 0x00400030, (PS, 2): 16, (CONVDP, 2): 0x14}, {'A1': 0x00020300}),
    ('cvxyl_two_powers', [CVXYL('A1', 'A0')], {'A1': 0x00020003, (PS, 2): 8, (CONVDP, 2): 0x1513}, {'A0': 0x2818}),
    ('cvxyl_any_pitch', [CVXYL('A1', 'A0')], {'A1': 0x00020003, (PS, 2): 8, 'B3': 0xe0}, {'A0': 0x1d8}),
    # --- clipping and line setup ---
    ('clip_inside', [CLIP], {**WIN, 'B2': 0x00100010, 'B7': 0x00050005, 'ST': 0x30000010},
     {'B2': 0x00100010, 'B7': 0x00050005, 'Z': 0, 'V': 0}),
    ('clip_partial', [CLIP], {'B2': 0x00100010, 'B7': 0x00200020, 'B5': 0x00180008, 'B6': 0x001f0027},
     {'B2': 0x00180010, 'B7': 0x00080018, 'Z': 0, 'V': 1}),
    ('clip_outside', [CLIP], {'B2': 0x00100010, 'B7': 0x00050005, 'B5': 0x00200020, 'B6': 0x00300030},
     {'B2': 0x00100010, 'B7': 0x00050005, 'Z': 1, 'V': 1}),
    ('linit_xmajor', [LINIT], {**WIN, 'B2': 0x00010002, 'B7': 0x0003000a},
     {'B0': 0xfffffffc, 'B7': 0x00020008, 'B10': 9, 'B11': 0x00010001, 'B12': 1, 'N': 0, 'Z': 0, 'C': 0, 'V': 0}),
    ('linit_ymajor_neg', [LINIT], {'B2': 0x00050005, 'B7': 0x00000003, 'B5': 0x00040004, 'B6': 0x00100010},
     {'B0': M, 'B7': 0x00020005, 'B10': 6, 'B11': M, 'B12': 0xffff0000, 'N': 0, 'Z': 0, 'C': 0, 'V': 1}),
    ('linit_vertical_reject', [LINIT], {'B2': 0x00000001, 'B7': 0x00050001, 'B5': 0x00000004, 'B6': 0x00100010},
     {'B0': 0xfffffffb, 'B7': 5, 'B10': 6, 'B11': 0x00010000, 'B12': 0x00010000, 'N': 1, 'Z': 0, 'C': 1, 'V': 1}),
    # --- lines ---
    ('fline0_pattern', [FLINE0], {**FL, 'B7': 2, 'B0': 0xfffffffe, 'B10': 3, 'B11': 0x00010001, 'B12': 1, 'B13': 5},
     {('@8000', 8): 0x0000123455551234, 'B2': 0x40030, 'B0': 0xfffffffe, 'B10': 0, 'B13': 0xa0000000}),
    ('fline1_diagonal', [FLINE1], {**FL, 'B7': 0x00010001, 'B0': 1, 'B10': 2, 'B11': 0x00010001, 'B12': 1, 'B13': M},
     {('@8000', 2): 0x1234, ('@8022', 2): 0x1234, 'B2': 0x40220, 'B0': 1, 'B10': 0}),
    ('line_pattern', [LINE0], {**LN, 'B13': 2, 'B8': 0x5555},
     {('@8000', 8): 0x5555555512345555, ('@8008', 4): 0x55555555, 'B13': 0x08000000, 'B10': 0, 'B2': 6, 'V': 0}),
    # --- fills and transfers ---
    ('pfill_xy', [PFILL], {**PF, 'B2': 0, 'B7': 0x00010008}, {('@8000', 4): 0xf0f00f0f}),
    ('pfill_xy_offset', [PFILL], {**PF, 'B2': 1, 'B7': 0x00010003, ('@8000', 4): 0x11111111}, {('@8000', 4): 0x11110f01}),
    ('tfill_row', [TFILL], dict(TF), {('@8000', 8): 0x7777777777770000, 'B0': 0x18000, 'B7': 0x30000, 'B11': 0x10000, 'B2': 1}),
    ('tfill_w3', [TFILL], {**TF, (CTL, 2): 0xc0, 'B5': 0, 'B6': 2}, {('@8000', 8): 0x0000777777770000, 'B11': 0x10000}),
    ('fpixeq_up', [FPIXEQ], {(PS, 2): 8, 'B10': 0x40000, 'B11': 5, 'B8': 0x33333333, ('@8000', 8): 0x0000004433221100},
     {'B10': 0x40020, 'B11': 1, 'Z': 1}),
    ('fpixne_down', [FPIXNE], {(PS, 2): 8, 'B10': 0x40028, 'B11': 0xfffffffb, 'B8': 0x55555555,
                               ('@8000', 8): 0x0000005555125555}, {'B10': 0x40010, 'B11': 0xfffffffe, 'Z': 1}),
    ('fpixeq_none', [FPIXEQ], {(PS, 2): 8, 'B10': 0x40000, 'B11': 2, 'B8': 0x77777777, 'ST': 0x20000010},
     {'B10': 0x40010, 'B11': 0, 'Z': 0}),
    ('pixblt_lml', [PIXBLT_LML], {(PS, 2): 16, 'B0': 0x40000, ('@8000', 8): 0x0004000300020001, 'B2': 0x40100,
                                  'B1': 0x100, 'B3': 0x100, 'B7': 0x00010004, 'B10': 0x40200, ('@8040', 2): 0x000a, 'B11': 0x100},
     {('@8020', 8): 0x0004000000020000, 'B0': 0x40100, 'B2': 0x40200, 'B10': 0x40300}),
    ('vlcol_vfill', [VLCOL, XOR('B9', 'B9'), VFILL], {(PS, 2): 8, 'B9': 0x5a5a5a5a, 'B2': 0x40008, 'B3': 0x40, 'B7': 0x00020003},
     {('@8000', 8): 0x000000005a5a5a00, ('@8008', 8): 0x000000005a5a5a00, 'VCOLOR': 0x5a5a5a5a}),
    ('vfill_pmask', [VLCOL, VFILL], {(PS, 2): 8, 'B9': 0x5a5a5a5a, 'B2': 0x40008, 'B3': 0x40, 'B7': 0x00010003,
                                     (PMASK, 4): 0xf0f0f0f0, ('@8000', 4): M}, {('@8000', 4): 0xfafafaff}),
    ('vblt', [VLCOL, VBLT], {(PS, 2): 8, 'B9': 0x77777777, 'B0': 0x40000, ('@8000', 2): 5, ('@8002', 2): 2, 'B1': 0x10,
                             'B2': 0x40100, 'B3': 0x40, 'B7': 0x00020004},
     {('@8020', 4): 0x00770077, ('@8028', 4): 0x00007700}),
    # --- changed TMS34010 behaviour ---
    ('pixt_ir_v_kept', [PIXT_IR('A1', 'A0')], {'ST': 0x10000010, (PS, 2): 4, 'A1': 0x40008, 'A0': 9}, {'A0': 0, 'V': 1}),
    ('transp_src_color0', [PIXT_RI('A0', 'A1')], {'A0': 6, 'A1': 0x40008, (PS, 2): 4, (CTL, 2): 0x21, 'B8': 0x66666666,
                                                  ('@8000', 2): 0x0300}, {('@8000', 2): 0x0300}),
    ('transp_src_other', [PIXT_RI('A0', 'A1')], {'A0': 5, 'A1': 0x40008, (PS, 2): 4, (CTL, 2): 0x21, 'B8': 0x66666666,
                                                 ('@8000', 2): 0x0300}, {('@8000', 2): 0x0500}),
    ('transp_dst_color0', [PIXT_RI('A0', 'A1')], {'A0': 6, 'A1': 0x40008, (PS, 2): 4, (CTL, 2): 0x25, 'B8': 0x33333333,
                                                  ('@8000', 2): 0x0300}, {('@8000', 2): 0x0300}),
    ('transp_dst_other', [PIXT_RI('A0', 'A1')], {'A0': 6, 'A1': 0x40008, (PS, 2): 4, (CTL, 2): 0x25, 'B8': 0x44444444,
                                                 ('@8000', 2): 0x0300}, {('@8000', 2): 0x0600}),
    ('transp_result0', [PIXT_RI('A0', 'A1')], {'A0': 3, 'A1': 0x40008, (PS, 2): 4, (CTL, 2): 0x2820,
                                               ('@8000', 2): 0x0300}, {('@8000', 2): 0x0300}),
    ('pixel32_pmask32', [PIXT_RI('A0', 'A1')], {'A0': 0xdeadbeef, 'A1': 0x40020, (PS, 2): 32, (PMASK, 4): 0xffff0000,
                                                ('@8004', 4): 0x11111111}, {('@8004', 4): 0x1111beef}),
    ('adds32_saturates', [PIXT_RI('A0', 'A1')], {'A0': 0x20, 'A1': 0x40020, (PS, 2): 32, (CTL, 2): 0x4400,
                                                 ('@8004', 4): 0xfffffff0}, {('@8004', 4): M}),
    ('add32_wraps', [PIXT_RI('A0', 'A1')], {'A0': 0x20, 'A1': 0x40020, (PS, 2): 32, (CTL, 2): 0x4000,
                                            ('@8004', 4): 0xfffffff0}, {('@8004', 4): 0x10}),
    ('fill_l_32bpp', [FILL_L], {(PS, 2): 32, 'B2': 0x40000, 'B3': 0x40, 'B7': 0x00010002, 'B9': 0x01020304},
     {('@8000', 8): 0x0102030401020304}),
    # --- coprocessor interface (TMS34020 side) ---
    ('cexec_long', [CEXEC(0, 0x69005, 3)], {}, {'CPCMD': '3:69005:0'}),
    ('cexec_short', [[0xd805, 0x1234]], {}, {'CPCMD': '0:24682:1'}),
    ('cmovgc_one', [CMOVGC1('B5', 0x123, 2)], {'B5': 0x89abcdef}, {'CPOUT': '89abcdef', 'CPCMD': '2:123:0'}),
    ('cmovgc_two', [CMOVGC2('A0', 'B3', 1, 0x77, 1)], {'A0': 0xa0, 'B3': 0xb3}, {'CPOUT': 'a0:b3', 'CPCMD': '1:77:1'}),
    ('cmovcs', [CMOVCS(5, 0)], {'CPIN': 'a0000000'}, {'N': 1, 'C': 0, 'Z': 1, 'V': 0, 'CPCMD': '0:5:0'}),
    ('cmovcg_one', [CMOVCG('A3', 'A2', 0, 9, 0)], {'CPIN': '0:5', 'A2': 0x77, 'A3': 0x99}, {'A3': 0, 'A2': 0x77, 'Z': 1, 'N': 0}),
    ('cmovcg_two', [CMOVCG('A1', 'A2', 1, 9, 0)], {'CPIN': '12345678:80000000', 'ST': 0x10000010},
     {'A1': 0x12345678, 'A2': 0x80000000, 'N': 1, 'Z': 0, 'V': 0}),
    ('cmovmc_postinc', [CMOVMC_INC('A0', 3, 0, 0x40, 0)],
     {'A0': 0x40000, ('@8000', 4): 0x11111111, ('@8004', 4): 0x22222222, ('@8008', 4): 0x33333333},
     {'CPOUT': '11111111:22222222:33333333', 'A0': 0x40060}),
    ('cmovmc_unaligned', [CMOVMC_INC('A0', 1, 0, 0x40, 0)], {'A0': 0x40004, ('@8000', 8): 0x0000000123456789},
     {'CPOUT': '12345678', 'A0': 0x40024}),
    ('cmovmc_predec', [CMOVMC_DEC('A1', 2, 0, 0x40, 0)], {'A1': 0x40040, ('@8000', 4): 0xaaaa, ('@8004', 4): 0xbbbb},
     {'CPOUT': 'bbbb:aaaa', 'A1': 0x40000}),
    ('cmovmc_regcount', [CMOVMC_REG('B1', 'B3', 0, 0x40, 0)], {'B1': 0x40000, 'B3': 0x22, ('@8000', 4): 0x11111111,
                                                                ('@8004', 4): 0x22222222}, {'CPOUT': '11111111:22222222', 'B1': 0x40040}),
    ('cmovcm_postinc', [CMOVCM_INC('A0', 2, 0, 0x40, 0)], {'A0': 0x40000, 'CPIN': 'cafe:f00d'},
     {('@8000', 4): 0xcafe, ('@8004', 4): 0xf00d, 'A0': 0x40040}),
    ('cmovcm_predec', [CMOVCM_DEC('A0', 2, 0, 0x40, 0)], {'A0': 0x40040, 'CPIN': 'cafe:f00d'},
     {('@8004', 4): 0xcafe, ('@8000', 4): 0xf00d, 'A0': 0x40000}),
]

if __name__ == '__main__':
    write(T, sys.argv[1], int(sys.argv[sys.argv.index('--break') + 1]) if '--break' in sys.argv else -1,
          first=0x1000, prefix='emu20')
