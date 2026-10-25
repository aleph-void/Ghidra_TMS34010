#!/usr/bin/env bash
# Download the freely licensed real TMS34010 code used by test/real-binaries.sh. Nothing is
# committed; files land in <dest> (default ./real-samples) and are checked against pinned SHA-256.
#
#   test/fetch-real-samples.sh [dest]
#
# NetBSD (pinned commit 5b0e0d59, BSD-2-Clause, (c) 1995 Ignatios Souvatzis):
#   grf_ultms.c  the TMS34010 code the NetBSD/amiga kernel uploads to the University of Lowell
#                A2410 graphics board (ite console support), as a C array of address blocks
#   grf_ultms.g  its assembler source, for NetBSD's gspa assembler (usr.sbin/gspa)
# test/ultms2bin.py turns grf_ultms.c into a raw image (Ghidra address = bit address / 8).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
DEST=${1:-real-samples}
mkdir -p "$DEST"
cd "$DEST"
NB=https://raw.githubusercontent.com/NetBSD/src/5b0e0d5997518246c017c6577adcb59be12d0a79
fetch() { # url out sha256
	if [[ ! -s $2 ]]; then
		curl -fsSL --retry 3 -o "$2.part" "$1"
		mv "$2.part" "$2"
	fi
	echo "$3  $2" | sha256sum -c --quiet - || { echo "SHA-256 mismatch: $2" >&2; exit 1; }
}
fetch $NB/sys/arch/amiga/dev/grf_ultms.c grf_ultms.c 39f70a254186101064e44e7e24d9b4e72fdbaa5c4e6fae6d0ce55157b33267d8
fetch $NB/sys/arch/amiga/dev/grf_ultms.g grf_ultms.g 586b9470b86d780cb7c478b85ce59c78895da2f5f65c3ae4f4b2cd593eefe3e6
python3 -I "$HERE/ultms2bin.py" grf_ultms.c a2410-ultms.bin
echo "samples in $(pwd)"
