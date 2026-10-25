#!/usr/bin/env bash
# TMS34010 module tests that need no non-redistributable input:
#   1. compile the .slaspec (and report the .sla size)
#   2. decode corpora vs MAME's disassembler: every opcode 0000h-FFFFh with random extension
#      words, and 50,000 random slots (gen_corpus.py, DumpSlots.java, compare.py)
#   3. every-entry test: every SLEIGH constructor is used by some decoded instruction (run after
#      the TMS34020 corpora, over both languages)
#   4. assembler corpus: every instruction form NetBSD's gspa accepts, random operands, compared
#      with the source and with MAME (gen_asm.py, asm_check.py); skipped without GSPA
#   4b. TI COFF: the same corpus as assembled and linked by TI's own GSPA/GSPLNK v1.04 (test/coff/,
#      rebuilt by build-ti-coff.sh), imported with the module's COFF loader (relocatable .obj and
#      linked .out); every instruction checked against the source line, the .out also vs MAME
#   5. p-code emulator tests (emu_tests.py, EmuCheck.java); one deliberately broken run must fail
#   5b. decompiler: a TI-C-style function (arguments on the A14 bit-addressed stack) decompiled with
#      the default compiler spec and with "tic" (FS1 = 32 at entry, TI C compiler convention)
#   6. graphics vectors: 137 MIT-licensed programs from github.com/birdybro/TMS34010_sv whose
#      final state MAME recorded, run in Ghidra's emulator (GfxCheck.java)
#   7. TMS34020 (tms34020:LE:32:default): the decode corpora vs unidasm -arch tms34020, the
#      every-entry test over both languages, and the TMS34020 emulator tests (emu_tests_34020.py)
#
#   test/run-tests.sh [workdir]
#
# Environment:
#   GHIDRA_INSTALL_DIR  Ghidra 12.1.x whose Ghidra/Processors/TMS34010 is (a symlink to) this module
#   UNIDASM             MAME's unidasm (default: unidasm on PATH; MAME 0.285 was used)
#   GSPA                gspa binary (test/build-gspa.sh builds one); optional
#   The COFF step needs the module's Java part: an installed extension, or test/build-jar.sh for a
#   linked development copy.
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
for l in tms34010 tms34020; do
	(cd "$MOD/data/languages" && "$GHIDRA_INSTALL_DIR/support/sleigh" $l.slaspec 2>&1 |
		grep -E "^(ERROR|Error)" || true)
done
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

echo "== TI COFF (TI GSPA/GSPLNK v1.04 output of the corpus, Tms340CoffLoader)"
python3 "$HERE/gen_asm.py" asm.s 12
python3 "$HERE/ti_coff.py" asm asm.s ti.s ti.asm
cmp -s ti.asm <(sed 's/$/\r/' "$HERE/coff/c.asm") || echo "   note: test/coff/c.asm differs from the generated corpus (rebuild with build-ti-coff.sh)"
for k in obj out; do
	python3 "$HERE/ti_coff.py" listing "$HERE/coff/c.lst" ti.s "$([[ $k == out ]] && echo FF800000 || echo 0)" ti_$k.lst
	python3 "$HERE/asm_check.py" image ti_$k.lst /dev/null ti_${k}_addrs.txt >/dev/null
	"$HERE/ghidra-script.sh" coff - "$HERE/coff/c.$k" DumpAt.java "$W/ti_${k}_addrs.txt" "$W/g_ti_$k.txt"
done
python3 "$HERE/ti_coff.py" text "$HERE/coff/c.out" ti_text.bin >ti_text_pc.txt
"$UNIDASM" ti_text.bin -arch tms34010 -basepc "$(cat ti_text_pc.txt)" >m_ti_out.txt
echo "   c.obj (relocatable, $(grep -c "'" "$HERE/coff/c.lst") relocations applied by the loader):"
python3 "$HERE/asm_check.py" check ti_obj.lst g_ti_obj.txt - | sed 's/^/     /'
echo "   c.out (linked, .text at bit FF800000h):"
python3 "$HERE/asm_check.py" check ti_out.lst g_ti_out.txt m_ti_out.txt | sed 's/^/     /'

echo "== p-code emulator tests"
python3 "$HERE/emu_tests.py" . >/dev/null
gs emu.bin EmuCheck.java "$W/emu.txt" "$W/emu_res.txt"
echo "   $(tail -1 emu_res.txt)"
grep FAIL emu_res.txt | sed 's/^/   /' || true
python3 "$HERE/emu_tests.py" . --break 40 >/dev/null
gs emu.bin EmuCheck.java "$W/emu.txt" "$W/emu_res_break.txt"
echo "   with test 40's expectation made wrong: $(tail -1 emu_res_break.txt); $(grep FAIL emu_res_break.txt)"
python3 "$HERE/emu_tests.py" . >/dev/null

echo "== decompiler: TI C field size convention (compiler spec tic)"
python3 -c "import sys; open('dc.bin','wb').write(bytes(0x20000) + bytes.fromhex(sys.argv[1]))" \
	8f096400cd4da9b7e0ffaab7c0ff4941a8b7a0ff2841eeb78000af0900266209cfa360180e9240180e9220180e925f0d000010008807000004006009
for c in default tic; do
	CSPEC=$c "$HERE/ghidra-script.sh" raw tms34010:LE:32:default dc.bin Decomp.java "$W/dc_$c.c" 0x20000 0x2002e
	echo "   $c: $(grep -c . dc_$c.c) lines, FS1 references: $(grep -c FS1 dc_$c.c || true); $(grep -m1 'return' dc_$c.c | sed 's/^ *//' | cut -c1-80)"
done

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

echo "== TMS34020: decode corpora vs MAME ($UNIDASM -arch tms34020)"
gs20() { "$HERE/ghidra-script.sh" raw tms34020:LE:32:default "$@"; }
for c in table fuzz special; do
	"$UNIDASM" $c.bin -arch tms34020 >m20_$c.txt
	gs20 $c.bin DumpSlots.java "$W/g20_$c.txt" 18 "$W/ctor20_$c.txt"
	python3 "$HERE/compare.py" g20_$c.txt m20_$c.txt 18 --core mame_core_table_34020.txt >cmp20_$c.txt
	echo "-- $c: $(head -1 cmp20_$c.txt)"
	sed -n '2,$p' cmp20_$c.txt | sed 's/^/   /'
done
echo "== every-entry decode test (both languages)"
python3 "$HERE/entry_check.py" "$MOD/data/languages" ctor_table.txt ctor_fuzz.txt ctor20_table.txt ctor20_fuzz.txt \
	ctor20_special.txt | sed 's/^/   /'
echo "== TMS34020 p-code emulator tests"
python3 "$HERE/emu_tests_34020.py" . >/dev/null
gs20 emu20.bin EmuCheck.java "$W/emu20.txt" "$W/emu20_res.txt"
echo "   $(tail -1 emu20_res.txt)"
grep FAIL emu20_res.txt | sed 's/^/   /' || true
python3 "$HERE/emu_tests_34020.py" . --break 30 >/dev/null
gs20 emu20.bin EmuCheck.java "$W/emu20.txt" "$W/emu20_res_break.txt"
echo "   with test 30's expectation made wrong: $(tail -1 emu20_res_break.txt); $(grep FAIL emu20_res_break.txt)"
python3 "$HERE/emu_tests_34020.py" . >/dev/null
