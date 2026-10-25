> **Ghidra-Rare fork.** This branch adds tested fixes, release builds for the three newest Ghidra
> releases and test suites; see [GHIDRA-RARE.md](GHIDRA-RARE.md) for the test results and
> remaining gaps, and [CREDITS.md](CREDITS.md) for the original author and every change.
> Prebuilt zips for Ghidra 12.1.3, 12.1.4 and 12.2 are on this fork's
> [Releases page](https://github.com/aleph-void/Ghidra_TMS34010/releases). The original README
> follows; the sections marked *Ghidra-Rare* were added.

# Ghidra_TMS34010
A processor module of the Texas Instruments TMS34010 processor for Ghidra.

~~Current status is incomplete, some semantics are still needed to be finished as well as other fixes.~~

*Ghidra-Rare:* fixed on this branch. Every instruction decodes like MAME's TMS34010
disassembler (all 65,536 opcodes checked) and has p-code, including field moves at any bit
address and the graphics instructions (PIXT, DRAV, LINE, FILL, PIXBLT). See
[GHIDRA-RARE.md](GHIDRA-RARE.md) for the tests and the remaining gaps.

12/27/2022 - Added python script for importing symbols into Ghidra.

*Ghidra-Rare:* the scripts are in `ghidra_scripts/`. `ImportSymbols_Py3.py` runs under
PyGhidra (Ghidra 12 has no Jython by default). Both now place a symbol at its bit address / 8
(see below) instead of masking it to 1 MB. `TMS34010Vectors.java` marks the trap vectors of an
imported ROM and creates functions at their targets.

## Installing (*Ghidra-Rare*)

This branch targets Ghidra 12.1.4 and is built and tested on 12.1.3, 12.1.4 and 12.2. Download
the zip for your Ghidra version from the [Releases page](https://github.com/aleph-void/Ghidra_TMS34010/releases),
then in Ghidra choose *File > Install Extensions*, add the zip, and restart Ghidra. To build it
yourself, run `gradle buildExtension` with `GHIDRA_INSTALL_DIR` set.

The language is `tms34010:LE:32:default`.

## Addresses (*Ghidra-Rare*)

The TMS34010 addresses memory in bits; Ghidra addresses bytes. In this module **a Ghidra address
is the TMS34010 bit address divided by 8**. Import a ROM image as a raw binary at its bit address
/ 8, for example a program ROM at FF800000h goes at 1FF00000h. The I/O registers (bit
C0000000h) appear at 18000000h, and the trap vectors (bit FFFFFFE0h downwards) at 1FFFFFFCh
downwards. Registers keep bit addresses, as on the chip.
