#!/usr/bin/env bash
# TMS34010 module tests that need no non-redistributable input:
#   1. compile the .slaspec (and report the .sla size)
#   2. decode corpora vs MAME's disassembler: every opcode 0000h-FFFFh with random extension
#      words, and 50,000 random slots (gen_corpus.py, DumpSlots.java, compare.py)
#   3. every-entry test: every SLEIGH constructor is used by some decoded instruction
#   4. assembler corpus: every instruction form NetBSD's gspa accepts, random operands, compared
#      with the source and with MAME (gen_asm.py, asm_check.py); skipped without GSPA
#   5. p-code emulator tests (emu_tests.py, EmuCheck.java); one deliberately broken run must fail
#   6. graphics vectors: 137 MIT-licensed programs from github.com/birdybro/TMS34010_sv whose
#      final state MAME recorded, run in Ghidra's emulator (GfxCheck.java)
#
#   test/run-tests.sh [workdir]
#
# Environment:
#   GHIDRA_INSTALL_DIR  Ghidra 12.1.x whose Ghidra/Processors/TMS34010 is (a symlink to) this module
#   UNIDASM             MAME's unidasm (default: unidasm on PATH; MAME 0.285 was used)
#   GSPA                gspa binary (test/build-gspa.sh builds one); optional
#   TMPDIR              where throw-away Ghidra projects go (must not be under a dot-directory)
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
MOD=$(cd "$HERE/.." && pwd)
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
UNIDASM=${UNIDASM:-unidasm}
W=$(mkdir -p "${1:-tms34010-test-work}" && cd "${1:-tms34010-test-work}" && pwd)
cd "$W"
gs() { "$HERE/ghidra-script.sh" raw tms34010:LE:32:default "$@"; }

echo "== compiling SLEIGH"
(cd "$MOD/data/languages" && "$GHIDRA_INSTALL_DIR/support/sleigh" tms34010.slaspec 2>&1 |
	grep -E "^(ERROR|Error)" || true)
ls -la "$MOD"/data/languages/*.sla | awk '{print "   " $9 ": " $5 " bytes"}'

echo "== decode corpora vs MAME ($UNIDASM -arch tms34010)"
python3 "$HERE/gen_corpus.py" .
for c in table fuzz; do
	"$UNIDASM" $c.bin -arch tms34010 >m_$c.txt
	gs $c.bin DumpSlots.java "$W/g_$c.txt" 18 "$W/ctor_$c.txt"
	python3 "$HERE/compare.py" g_$c.txt m_$c.txt 18 >cmp_$c.txt
	echo "-- $c: $(head -1 cmp_$c.txt)"
	sed -n '2,$p' cmp_$c.txt | sed 's/^/   /'
done

echo "== every-entry decode test"
python3 "$HERE/entry_check.py" "$MOD/data/languages" ctor_table.txt ctor_fuzz.txt | sed 's/^/   /'

echo "== assembler corpus (gspa)"
if [[ -n ${GSPA:-} ]]; then
	python3 "$HERE/gen_asm.py" asm.s 12
	"$GSPA" -o asm.hex -l asm.lst asm.s
	python3 "$HERE/asm_check.py" image asm.lst asm.bin asm_addrs.txt | sed 's/^/   /'
	gs asm.bin DumpAt.java "$W/asm_addrs.txt" "$W/g_asm.txt"
	python3 -c "import sys; d=open('asm.bin','rb').read(); open('asm_code.bin','wb').write(d[0x20000:])"
	"$UNIDASM" asm_code.bin -arch tms34010 -basepc 100000 >m_asm.txt
	python3 "$HERE/asm_check.py" check asm.lst g_asm.txt m_asm.txt | sed 's/^/   /'
	printf '\t.org\t$1000\n\tsubi\t3,a0\n\tsubi\t3,a1\n' >gspa_subi.s
	"$GSPA" -o /dev/null -l gspa_subi.lst gspa_subi.s
	echo "   gspa SUBI bug: $(grep -i subi gspa_subi.lst | awk '{print $2"h "$4" "$5}' | paste -sd ';')"
else
	echo "   skipped (set GSPA; test/build-gspa.sh builds NetBSD's gspa)"
fi

echo "== p-code emulator tests"
python3 "$HERE/emu_tests.py" . >/dev/null
gs emu.bin EmuCheck.java "$W/emu.txt" "$W/emu_res.txt"
echo "   $(tail -1 emu_res.txt)"
grep FAIL emu_res.txt | sed 's/^/   /' || true
python3 "$HERE/emu_tests.py" . --break 40 >/dev/null
gs emu.bin EmuCheck.java "$W/emu.txt" "$W/emu_res_break.txt"
echo "   with test 40's expectation made wrong: $(tail -1 emu_res_break.txt); $(grep FAIL emu_res_break.txt)"
python3 "$HERE/emu_tests.py" . >/dev/null

echo "== graphics vectors (birdybro/TMS34010_sv, MIT, MAME-recorded results)"
SV=https://raw.githubusercontent.com/birdybro/TMS34010_sv/ef1b02eaee5569651616ce10405d2df8ed9f99b8/sim/vectors
fetch() { # name sha256
	[[ -s $1 ]] || curl -fsSL --retry 3 -o "$1" "$SV/$1"
	echo "$2  $1" | sha256sum -c --quiet -
}
fetch mame_graphics_vectors.txt f90c526298a2e169d7a6eb26c9d61c08c1f40ad002802ac34e78f6f739932b9e
fetch mame_graphics_expected.txt 70715148412c17dbc37eda5d1c138f2e6d9fb8b7f651fec6673a9e5285bfb4d3
head -c 8192 /dev/zero >blank.bin
gs blank.bin GfxCheck.java "$W/mame_graphics_vectors.txt" "$W/mame_graphics_expected.txt" "$W/gfx.txt"
echo "   $(tail -1 gfx.txt)"
grep -v -E ' OK|^graphics' gfx.txt | sed 's/^/   /' || true
