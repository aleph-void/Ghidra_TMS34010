#!/usr/bin/env python3
"""TI assembler cross-check and COFF loader test helpers.

The assembler corpus (gen_asm.py, gspa syntax) is also assembled with TI's own GSP COFF
assembler and linker (GSPA/GSPLNK v1.04, 1986, MS-DOS; not redistributable, run under DOSBox).
Their object (.OBJ, relocatable) and executable (.OUT) are imported with the module's COFF loader
and each instruction is checked against the source line, as asm_check.py does for gspa.

  ti_coff.py asm <gspa.s> <ti.s> <TI.ASM>      corpus -> gspa-syntax copy with the few forms TI v1.04
                                                lacks replaced, and the same in TI syntax (CRLF)
  ti_coff.py listing <TI.LST> <ti.s> <base> <out.lst>
                                                TI listing -> gspa-style listing (bit address + base,
                                                words, source line from ti.s) for asm_check.py
  ti_coff.py text <coff> <out.bin>              raw .text section bytes; prints its bit address
"""
import re
import struct
import sys


def to_ti(line):
    # gspa syntax -> TI GSPA v1.04 syntax
    line = re.sub(r'\$([0-9A-Fa-f]+)', lambda m: '0' + m.group(1).upper() + 'h', line)
    line = re.sub(r'\b([ab]\d{1,2}|sp)\b', lambda m: m.group(1).upper(), line)
    m = re.match(r'(\s*)(pixblt|fill)\s+(.*)$', line)
    if m:
        line = f'{m.group(1)}{m.group(2)}\t{m.group(3).upper()}'
    return line.replace('\t.org\t0100000h', '\t.text')


def fix(line):
    # forms TI v1.04 does not take, rewritten in gspa syntax (same line count)
    if re.match(r'\s*rev\b', line):
        return '\tnop'                                  # no REV in v1.04
    m = re.match(r'(\s*)jr(\w+)\s+(\w+),l$', line)
    if m:
        return f'{m.group(1)}ja{m.group(2)}\t{m.group(3)}'  # what gspa assembles for JRcc l,L
    m = re.match(r'(\s*)(mpys|mpyu|divs|divu)\s+(\w+),(b14|a14)$', line)
    if m:                                               # v1.04 rejects the pair B14/A14 (SP)
        return f'{m.group(1)}{m.group(2)}\t{m.group(3)},{m.group(4)[0]}12'
    return line


def main():
    if sys.argv[1] == 'asm':
        lines = [fix(x) for x in open(sys.argv[2]).read().split('\n')]
        open(sys.argv[3], 'w').write('\n'.join(lines))
        open(sys.argv[4], 'w', newline='\r\n').write('\n'.join(to_ti(x) for x in lines))
        return
    if sys.argv[1] == 'listing':
        src = open(sys.argv[3]).read().split('\n')
        base = int(sys.argv[4], 16)
        out, cur = [], None
        for line in open(sys.argv[2], encoding='latin-1'):
            line = line.rstrip('\r\n')
            m = re.match(r'^ (\d{4}) ([0-9A-F]{8}) {5}([0-9A-F]{4})?', line)
            c = re.match(r'^ {6}([0-9A-F]{8}) +([0-9A-F]{4}|[0-9A-F]{8})\'? *$', line)
            if m:
                cur = [int(m.group(2), 16) + base, [m.group(3)] if m.group(3) else [],
                       src[int(m.group(1)) - 1]]
                out.append(cur)
            elif c and cur:
                w = c.group(2)
                cur[1] += [w] if len(w) == 4 else [w[4:], w[:4]]
        with open(sys.argv[5], 'w') as f:
            for a, w, s in out:
                f.write(f'{a & 0xffffffff:08X} {" ".join(w):<15}{s}\n')
        return
    if sys.argv[1] == 'text':
        d = open(sys.argv[2], 'rb').read()
        magic, nsec, _, _, _, opt, _ = struct.unpack_from('<HHIIIHH', d)
        assert magic == 0x90, hex(magic)
        for i in range(nsec):
            o = 20 + opt + 40 * i
            name = d[o:o + 8].rstrip(b'\0').decode()
            paddr, vaddr, size, ptr = struct.unpack_from('<IIII', d, o + 8)
            if name == '.text':
                open(sys.argv[3], 'wb').write(d[ptr:ptr + size // 8])
                print(f'{paddr:X}')
                return
        sys.exit('no .text')


if __name__ == '__main__':
    main()
