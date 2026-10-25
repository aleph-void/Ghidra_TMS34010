#!/usr/bin/env bash
# Real TMS34010 code: NetBSD's A2410 graphics-board program (grf_ultms, BSD-2-Clause; fetch with
# test/fetch-real-samples.sh). Imported headless as a raw image at bit address FFA00000h
# (Ghidra 1FF40000h) with the reset vector's target as entry point, auto-analysed and
# decompiled; every instruction Ghidra found is compared with MAME's disassembly at the same
# address and, when GSPA is set, with the assembler source (grf_ultms.g assembled by gspa).
#
#   test/real-binaries.sh [samples-dir] [workdir]
#
# Environment: GHIDRA_INSTALL_DIR, UNIDASM (default unidasm), GSPA (optional), TMPDIR,
#   DECOMP_TIMEOUT (seconds per function, default 60)
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
UNIDASM=${UNIDASM:-unidasm}
SAMPLES=$(cd "${1:-real-samples}" && pwd)
W=$(mkdir -p "${2:-real-work}" && cd "${2:-real-work}" && pwd)
n=a2410-ultms
P=$(mktemp -d "${TMPDIR:-/tmp}/tms34010-real.XXXXXX")
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$P" p -import "$SAMPLES/$n.bin" \
	-loader BinaryLoader -loader-baseAddr 0x1ff40000 -processor tms34010:LE:32:default \
	-scriptPath "$HERE" -preScript SeedEntries.java 0x1ff40000 \
	-postScript RealCheck.java "$W/$n.sum" "$W/$n.lst" "$W/$n.c" "${DECOMP_TIMEOUT:-60}" \
	-deleteProject >"$W/$n.log" 2>&1 || { tail -20 "$W/$n.log" >&2; }
rm -rf "$P"
echo "-- $n (raw, bit address FFA00000h)"
grep -E "^(language|functions|instructions|bad-instruction|error bookmarks|decompile|functions whose)" \
	"$W/$n.sum" | sed 's/^/   /'
python3 -c "import sys; d=open(sys.argv[1],'rb').read(); open(sys.argv[2],'wb').write(d[:0x2000])" \
	"$SAMPLES/$n.bin" "$W/$n.code"
"$UNIDASM" "$W/$n.code" -arch tms34010 -basepc ffa00000 >"$W/$n.mame"
SRC=()
if [[ -n ${GSPA:-} ]]; then
	"$GSPA" -o "$W/$n.hex" -l "$W/$n.src.lst" "$SAMPLES/grf_ultms.g"
	SRC=("$W/$n.src.lst")
fi
python3 "$HERE/listing_check.py" "$W/$n.lst" "$W/$n.mame" "${SRC[@]}" | sed 's/^/   /'
echo "(full outputs: $W/$n.{sum,lst,c,mame,log})"
