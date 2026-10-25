#!/usr/bin/env python3
"""NetBSD grf_ultms.c (tmscode[]: blocks of <count>, <bit address hi>, <lo>, <count words>)
-> raw image of bit addresses FFA00000h-FFA2FFFFh, i.e. Ghidra addresses 1FF40000h-1FF45FFFh.
The two vector blocks outside that range (reset and NMI, both FFA00000h) are reported.

  ultms2bin.py <grf_ultms.c> <out.bin>
"""
import re
import sys

BASE, END = 0xFFA00000, 0xFFA30000
words = [int(x, 0) for x in re.findall(r'\b(?:0x[0-9a-fA-F]+|\d+)\b',
                                         open(sys.argv[1]).read().split('{', 1)[1].split('}')[0])]
img = bytearray((END - BASE) // 8)
i = 0
while words[i]:
    n, addr = words[i], (words[i + 1] << 16) | words[i + 2]
    data = words[i + 3:i + 3 + n]
    if BASE <= addr < END:
        for k, w in enumerate(data):
            o = (addr - BASE) // 8 + 2 * k
            img[o:o + 2] = bytes((w & 0xff, w >> 8))
        print(f'block {addr:08X}h: {n} words')
    else:
        print(f'vector {addr:08X}h -> {data[1] << 16 | data[0]:08X}h')
    i += 3 + n
open(sys.argv[2], 'wb').write(img)
