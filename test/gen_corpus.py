#!/usr/bin/env python3
"""Decode corpora for the TMS34010 differential test.

Every record is a 9-word (18-byte) slot: the opcode word, four extension words and four NOPs
(0300h). An instruction is at most 5 words long, so whatever the extension words decode as when
the opcode is shorter, a linear sweep (MAME unidasm) is back in step at the next slot; the
Ghidra side decodes only the slot starts.

  table.bin  every 16-bit opcode 0000h-FFFFh once, extension words random (65,536 slots)
  fuzz.bin   50,000 random opcode words with random extension words (seeded)
  special.bin  encodings the random extension words almost never produce: TMS34020 CMOVCS
             (0660h with a second word whose low byte is 01h), each with random command bits

  gen_corpus.py <outdir>
"""
import random
import struct
import sys

SLOT_WORDS = 9
NOP = 0x0300


def slot(rng, op):
    return [op] + [rng.getrandbits(16) for _ in range(4)] + [NOP] * 4


def write(path, ops, rng):
    with open(path, 'wb') as f:
        for op in ops:
            f.write(struct.pack('<9H', *slot(rng, op)))


def main():
    out = sys.argv[1]
    rng = random.Random(34010)
    write(f'{out}/table.bin', range(0x10000), rng)
    rng = random.Random(340100)
    write(f'{out}/fuzz.bin', [rng.getrandbits(16) for _ in range(50000)], rng)
    rng = random.Random(34020)
    with open(f'{out}/special.bin', 'wb') as f:
        for _ in range(64):
            f.write(struct.pack('<9H', 0x0660, (rng.getrandbits(8) << 8) | 0x01, rng.getrandbits(16),
                                rng.getrandbits(16), rng.getrandbits(16), *[NOP] * 4))


if __name__ == '__main__':
    main()
