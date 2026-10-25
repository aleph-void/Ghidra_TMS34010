#!/usr/bin/env bash
# Compile the module's Java part (TMS340 COFF loader) into lib/TMS34010.jar with javac, for a
# development install where the module directory is linked into Ghidra/Processors.
# (gradle buildExtension does the same for release zips.) JAVAC overrides the compiler.
set -euo pipefail
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
MOD=$(cd "$(dirname "$0")/.." && pwd)
JAVAC=${JAVAC:-javac}
CLS=$(mktemp -d "${TMPDIR:-/tmp}/tms340-cls.XXXXXX")
trap 'rm -rf "$CLS"' EXIT
CP=$(find "$GHIDRA_INSTALL_DIR/Ghidra/Framework" "$GHIDRA_INSTALL_DIR/Ghidra/Features/Base" \
	-path '*/lib/*.jar' | tr '\n' ':')
"$JAVAC" -nowarn --release 21 -cp "$CP" -d "$CLS" $(find "$MOD/src/main/java" -name '*.java')
mkdir -p "$MOD/lib"
jar cf "$MOD/lib/TMS34010.jar" -C "$CLS" .
