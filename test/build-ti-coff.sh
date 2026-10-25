#!/usr/bin/env bash
# Rebuild test/coff/ (the TI-assembled copy of the assembler corpus) with TI's GSP COFF assembler
# and linker, GSPA.EXE/GSPLNK.EXE v1.04 (1986, MS-DOS, Texas Instruments; not redistributable and
# not included), run headless under DOSBox.
#   TI_GSP=<dir with GSPA.EXE and GSPLNK.EXE> test/build-ti-coff.sh
# Writes test/coff/c.asm (TI syntax), c.lst, c.obj (relocatable) and c.out (linked, .text at bit
# FF800000h, .data at 0). The source is gen_asm.py's corpus with seed and count as in
# run-tests.sh; ti_coff.py rewrites the few forms v1.04 lacks.
set -euo pipefail
: "${TI_GSP:?set TI_GSP to the directory holding GSPA.EXE and GSPLNK.EXE}"
HERE=$(cd "$(dirname "$0")" && pwd)
D=$(mktemp -d "${TMPDIR:-/tmp}/ti-gsp.XXXXXX")
trap 'rm -rf "$D"' EXIT
cp "$TI_GSP/GSPA.EXE" "$TI_GSP/GSPLNK.EXE" "$D/"
python3 "$HERE/gen_asm.py" "$D/asm.s" 12
python3 "$HERE/ti_coff.py" asm "$D/asm.s" "$D/ti.s" "$D/C.ASM"
printf '%s\r\n' C.OBJ '-o C.OUT' '-m C.MAP' MEMORY '{' \
	' ROM: origin = 0FF800000h, length = 100000h' ' RAM: origin = 00000000h, length = 100000h' \
	'}' SECTIONS '{' ' .text : {} > ROM' ' .data : {} > RAM' '}' >"$D/C.CMD"
printf '[sdl]\noutput=surface\n' >"$D/run.conf"
SDL_VIDEODRIVER=dummy SDL_AUDIODRIVER=dummy timeout 300 dosbox -conf "$D/run.conf" \
	-c "mount c $D" -c "c:" -c "GSPA C.ASM C.OBJ C.LST > A.TXT" -c "GSPLNK C.CMD > L.TXT" \
	-c "exit" >/dev/null 2>&1 || true
tr -d '\r' <"$D/A.TXT" | tail -1
[[ -s $D/C.OUT ]] || { cat "$D/A.TXT" "$D/L.TXT" >&2; exit 1; }
tr -d '\r' <"$D/C.ASM" >"$HERE/coff/c.asm"
tr -d '\r' <"$D/C.LST" | sed 's/[0-9][0-9]:[0-9][0-9]:[0-9][0-9] [0-9]\{4\}$//' >"$HERE/coff/c.lst"
cp "$D/C.OBJ" "$HERE/coff/c.obj"
cp "$D/C.OUT" "$HERE/coff/c.out"
ls -la "$HERE/coff"
