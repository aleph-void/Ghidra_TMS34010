#!/usr/bin/env bash
# Import a file into a throw-away headless Ghidra project and run one postScript from test/.
#   test/ghidra-script.sh raw <language-id> <file> <Script.java> [script args...]
# The project directory must not be under a dot-directory (Ghidra refuses those): set TMPDIR.
set -euo pipefail
MODE=$1 LANG_ID=$2
BIN=$(readlink -f "$3")
SCRIPT=$4
shift 4
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
HERE=$(cd "$(dirname "$0")" && pwd)
PROJ=$(mktemp -d "${TMPDIR:-/tmp}/tms34010-gs.XXXXXX")
trap 'rm -rf "$PROJ"' EXIT
IMP=()
[[ $MODE == raw ]] && IMP=(-loader BinaryLoader -processor "$LANG_ID" -noanalysis)
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$PROJ" p -import "$BIN" "${IMP[@]}" \
	-scriptPath "$HERE" -postScript "$SCRIPT" "$@" -deleteProject >"$PROJ/log.txt" 2>&1 ||
	{ tail -40 "$PROJ/log.txt" >&2; exit 1; }
if grep -qE "SCRIPT ERROR|Exception" "$PROJ/log.txt"; then
	grep -E -A5 "SCRIPT ERROR|Exception" "$PROJ/log.txt" | head -40 >&2
	exit 1
fi
