#!/usr/bin/env bash
# Build NetBSD's TMS34010 assembler gspa (usr.sbin/gspa, BSD license, Paul Mackerras) on Linux.
#   test/build-gspa.sh <dest-dir>      -> <dest-dir>/gspa
# Needs gcc and bison. Sources are fetched from NetBSD at a pinned commit.
set -euo pipefail
DEST=$(mkdir -p "$1" && cd "$1" && pwd)
NB=https://raw.githubusercontent.com/NetBSD/src/5b0e0d5997518246c017c6577adcb59be12d0a79/usr.sbin/gspa/gspa
S=$(mktemp -d)
trap 'rm -rf "$S"' EXIT
cd "$S"
for f in gsp_act.c gsp_ass.h gsp_code.h gsp_eval.c gsp_gram.y gsp_inst.c gsp_lex.c gsp_out.c \
	gsp_pseu.c gsp_sym.c gspa.c; do
	curl -fsSL --retry 3 -o "$f" "$NB/$f"
done
mkdir inc
cat > compat.h <<'H'
#include <sys/cdefs.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#ifndef __RCSID
#define __RCSID(x)
#endif
#ifndef __dead
#define __dead __attribute__((__noreturn__))
#endif
#ifndef __printflike
#define __printflike(a,b) __attribute__((__format__(__printf__,a,b)))
#endif
#ifndef __unused
#define __unused __attribute__((__unused__))
#endif
size_t strlcpy(char *, const char *, size_t);
H
cat > inc/util.h <<'H'
#include <stdlib.h>
#include <string.h>
#include <err.h>
static inline void *emalloc(size_t n) { void *p = malloc(n); if (!p) err(1, "malloc"); return p; }
H
cat > compat.c <<'C'
#include <string.h>
size_t strlcpy(char *d, const char *s, size_t n) { size_t l = strlen(s); if (n) { size_t c = l >= n ? n - 1 : l; memcpy(d, s, c); d[c] = 0; } return l; }
C
bison -y -d -o gsp_gram.c gsp_gram.y 2>/dev/null
gcc -O1 -w -std=gnu89 -include compat.h -I. -Iinc -o "$DEST/gspa" gspa.c gsp_out.c gsp_sym.c \
	gsp_lex.c gsp_act.c gsp_eval.c gsp_inst.c gsp_pseu.c gsp_gram.c compat.c
echo "built $DEST/gspa"
