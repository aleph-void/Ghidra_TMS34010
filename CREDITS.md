# Credits: TMS34010 module

This is a community SLEIGH module that Ghidra-Rare imported, tested and fixed. The original
processor module was written by its author below; Ghidra-Rare's changes are listed after.

## Upstream

| | |
|---|---|
| Source | [ZPaul2Fresh8/Ghidra_TMS34010](https://github.com/ZPaul2Fresh8/Ghidra_TMS34010), commit `a92e9b4ee89eb3d1955a2edcd105fa402a9d4b5e` (2026-10-25) |
| Ghidra-Rare fork | [aleph-void/Ghidra_TMS34010](https://github.com/aleph-void/Ghidra_TMS34010/tree/ghidra-rare), branch `ghidra-rare` |
| License | Apache-2.0 (`LICENSE.md`, added by the author on 2026-10-25; `LICENSE` is the same text) |
| Original author | ZPaul2Fresh8 ([@ZPaul2Fresh8](https://github.com/ZPaul2Fresh8)): the TMS34010 SLEIGH specification, processor and compiler specs, and the symbol import scripts (2022-2026) |

Ghidra-Rare's changes are separate commits on branch `ghidra-rare` of a fork of the upstream
repository, on top of its full history, so the original license and authorship are preserved.

## References and test data (not redistributed unless noted)

- MAME's TMS34010 disassembler and core (`src/devices/cpu/tms34010`, BSD-3-Clause, Alex
  Pasadyn and Zsolt Vasvari): the decode oracle (`unidasm`, MAME 0.285) and a semantic reference.
  `test/mame_core_table.txt` lists which opcodes MAME's core implements (opcode ranges and
  handler names from `34010tbl.hxx`).
- Texas Instruments, *TMS34010 User's Guide* (SPVU001A, 1988) and *TMS34010 C Compiler
  Reference Guide* (1988): instruction semantics, status bits, graphics operations, the C
  calling convention. Many emulator expectations are the guide's own examples.
- Texas Instruments, *TMS34020 User's Guide* (2564006-9721, 1990): the successor's instruction
  forms, semantics and changed graphics behavior. MAME's TMS34020 disassembler was used as a
  black-box decode reference; no MAME source was copied into the language.
- [birdybro/TMS34010_sv](https://github.com/birdybro/TMS34010_sv) (MIT, Kevin Coleman): the 137
  graphics test programs with MAME-recorded results that `test/run-tests.sh` downloads (pinned),
  and its documented reading of the User's Guide for PIXBLT/FILL completion registers, PBH/PBV
  corner handling and window modes (`docs/assumptions.md`), which this module follows.
- NetBSD (BSD-2-Clause): `gspa`, Paul Mackerras' TMS34010 assembler (`usr.sbin/gspa`), built by
  `test/build-gspa.sh` for the assembler corpus; and `grf_ultms.c`/`grf_ultms.g`, Ignatios
  Souvatzis' A2410 board program, the real-code sample (`test/fetch-real-samples.sh`).

## Ghidra-Rare changes

1. **Module layout.** The language files moved to `data/languages`, the scripts to
   `ghidra_scripts`, and an empty `Module.manifest` was added, so the repository installs as an
   extension. No content changes in that commit.
2. **Instruction set rewritten** (`tms34010.slaspec`, `tms34010.sinc`, `tms34010_mm.sinc`,
   `tms34010_gfx.sinc`, generator `tools/gen_mm.py`). The original decoded about 86 % of
   the opcode map like MAME (8,486 opcodes differed) and most constructors had empty or
   placeholder p-code. Now:
   - Every opcode MAME's core implements decodes, with MAME's operand order and TI's syntax,
     and reserved opcodes are rejected: 0 unexplained differences from MAME on all 65,536
     opcodes and 50,000 random slots; 330/330 constructors reached.
   - Memory model: a Ghidra address is the bit address / 8 (the old spec masked absolute
     targets to 1 MB). Field moves read and write exactly the field's bits at any bit address
     using FS/FE from ST; byte moves likewise.
   - Full p-code: flags as the User's Guide defines them, shifts, multiply/divide with
     register pairs and FS1, field and byte moves in every addressing mode, MMTM/MMFM, calls,
     returns, traps, ST, DSJ*, XY instructions, PIXT, DRAV, CPW, CVXYL, LINE, FILL and all six
     PIXBLTs with pixel processing, transparency, plane masking, window modes and PBH/PBV.
   - Upstream sinc TODOs fixed: JRcc long and DSJS targets, ANDNI, SETF field size 0 = 32,
     the MOVE @a,@b constraint error, JUMP through a register.
   - Found by the every-entry test: an unreachable condition-code entry was dropped.
3. **Processor and compiler specs.** The pspec did not load in Ghidra 12 (invalid elements) and
   described a Midway T-unit memory map at bit addresses used as byte addresses. It now declares
   the I/O registers (a volatile block at bit C0000000h = 18000000h with their names) and the
   trap vector labels. The cspec follows the TMS34010 C compiler: A8 returns values, all other
   registers are preserved, SP is the system stack, compiler data sizes.
4. **Scripts.** `ImportSymbols.py`/`ImportSymbols_Py3.py` map bit addresses to Ghidra addresses
   without the 1 MB mask and label every symbol. New `TMS34010Vectors.java` marks the trap
   vectors of a raw image and creates functions at their targets.
5. **README.md**: Ghidra-Rare notes, install steps, the address mapping, and the status of the
   original "incomplete" note.
6. **TMS34020 and TI COFF.** Added the successor language, its 64 I/O registers and graphics
   behavior, plus a loader for TI GSPA/GSPLNK COFF objects and executables. The TMS34020
   instruction set was checked against MAME and with 80 hand-computed emulator sequences;
   the COFF loader was checked on relocatable and linked assembler-corpus files.

Ghidra-Rare additions (not upstream): `GHIDRA-RARE.md`, `CREDITS.md`, `LICENSE` (copy of
`LICENSE.md`), `build.gradle`, `extension.properties`, `.gitignore`, `.github/`, `test/` and
`tools/`.
