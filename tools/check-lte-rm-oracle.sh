#!/usr/bin/env bash
#
# Cross-check tools/lte_phy.py's turbo rate matching (TS 36.212 5.1.4.1)
# against turbofec, an independent C implementation.
#
# This check is NOT part of tools/run-selftests.sh, because it needs network
# access and a C compiler. Run it by hand when the rate matcher changes.
#
# Why it exists: the constants in tools/lte_phy.py were transcribed from the
# specification, and a transcription can be self-consistently wrong. The
# vectors carried in the selftest were computed from the same reading, so
# they cannot independently confirm it. turbofec is a separate codebase that
# implements the same clause, and agreeing with it over a wide sweep of D, E
# and rv is real evidence rather than a restatement.
#
# Licensing: turbofec is GPLv3. It is fetched into a temporary directory
# OUTSIDE this repository and never committed. Do not vendor it, and do not
# copy its source into this tree.
#
# The sweep covers N_cb = K_w only. turbofec's forward path hardcodes
# N_cb = K_w unless compiled with TX_MODE_3/TX_MODE_4, so the soft-buffer
# truncation case is not covered here; that case rests on the k_0 table in
# the selftest. This is a real gap in the coverage and is stated rather than
# papered over.
#
# Usage:  ./tools/check-lte-rm-oracle.sh [workdir]
# Exit:   0 all cases agree, 1 mismatch found, 2 could not set up the oracle.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="${1:-${TMPDIR:-/tmp}/imsisting-lte-rm-oracle}"

# Guard: the fetched GPL source must never land inside the repository.
case "$(cd "$(dirname "$WORK")" && pwd)/$(basename "$WORK")" in
    "$ROOT"/*)
        echo "refusing to fetch GPLv3 source into the repository: $WORK" >&2
        exit 2
        ;;
esac

command -v gcc >/dev/null || { echo "gcc not found" >&2; exit 2; }
command -v curl >/dev/null || { echo "curl not found" >&2; exit 2; }

mkdir -p "$WORK"
cd "$WORK"

BASE="https://raw.githubusercontent.com/ttsou/turbofec/master"

# fetch <path-in-repo> <local-path>. The header must keep its turbofec/
# directory, because turbo_rate_match.c includes it as "turbofec/rate_match.h".
fetch() {
    mkdir -p "$(dirname "$2")"
    if [ ! -s "$2" ]; then
        echo "fetching $1" >&2
        curl -sfL "$BASE/$1" -o "$2" || { echo "fetch failed: $1" >&2; exit 2; }
    fi
}

fetch src/turbo_rate_match.c turbo_rate_match.c
fetch include/turbofec/rate_match.h turbofec/rate_match.h
fetch src/turbo_enc.c turbo_enc.c
fetch src/turbo_int.h turbo_int.h
fetch include/turbofec/turbo.h turbofec/turbo.h

cat > drv.c <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include "turbofec/rate_match.h"

/* Marker input d_j = ((7j) mod 5) mod 2, identical in all three streams so
   that a stream mix-up changes the output. */
int main(int argc, char **argv) {
    int D = atoi(argv[1]), E = atoi(argv[2]), rv = atoi(argv[3]), j;
    static signed char d0[7000], d1[7000], d2[7000], e[30000];
    struct lte_rate_matcher *m;
    struct lte_rate_matcher_io io;
    for (j = 0; j < D; j++) {
        signed char v = (signed char)(((7 * j) % 5) % 2);
        d0[j] = d1[j] = d2[j] = v;
    }
    m = lte_rate_matcher_alloc();
    io.D = D; io.E = E; io.d[0] = d0; io.d[1] = d1; io.d[2] = d2; io.e = e;
    if (lte_rate_match_fw(m, &io, rv)) { fprintf(stderr, "turbofec error\n"); return 1; }
    for (j = 0; j < E; j++) printf("%d", e[j] & 1);
    printf("\n");
    return 0;
}
EOF

gcc -O1 -I. -o drv drv.c turbo_rate_match.c -lm || { echo "build failed" >&2; exit 2; }

# The whole chain: turbofec's own turbo encoder feeding its own rate matcher.
# Comparing against this checks the encoder, the 3K+12 -> d0/d1/d2 split, and
# the rate matcher together, so the round-robin tail deal is covered end to
# end rather than only by the stream vector in the selftest.
cat > drv_chain.c <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include "turbofec/turbo.h"
#include "turbofec/rate_match.h"

int main(int argc, char **argv) {
    int K = atoi(argv[1]), E = atoi(argv[2]), rv = atoi(argv[3]), i;
    static uint8_t in[6144], d0[6200], d1[6200], d2[6200];
    static signed char s0[6200], s1[6200], s2[6200], e[30000];
    struct lte_turbo_code code;
    struct lte_rate_matcher *m;
    struct lte_rate_matcher_io io;

    code.n = 2; code.k = 4; code.len = K; code.rgen = 013; code.gen = 015;
    for (i = 0; i < K; i++) in[i] = (uint8_t)(1 - (i % 2));

    /* Returns the number of output bits on success, not 0, so only a
       negative return is an error. */
    if (lte_turbo_encode(&code, in, d0, d1, d2) < 0) {
        fprintf(stderr, "turbofec encode error\n"); return 1;
    }
    for (i = 0; i < K + 4; i++) {
        s0[i] = (signed char)d0[i]; s1[i] = (signed char)d1[i]; s2[i] = (signed char)d2[i];
    }
    m = lte_rate_matcher_alloc();
    io.D = K + 4; io.E = E; io.d[0] = s0; io.d[1] = s1; io.d[2] = s2; io.e = e;
    if (lte_rate_match_fw(m, &io, rv)) { fprintf(stderr, "turbofec rm error\n"); return 1; }

    for (i = 0; i < K + 4; i++) printf("%d", d0[i] & 1);
    printf(" ");
    for (i = 0; i < K + 4; i++) printf("%d", d1[i] & 1);
    printf(" ");
    for (i = 0; i < K + 4; i++) printf("%d", d2[i] & 1);
    printf(" ");
    for (i = 0; i < E; i++) printf("%d", e[i] & 1);
    printf("\n");
    return 0;
}
EOF

gcc -O1 -I. -o drv_chain drv_chain.c turbo_enc.c turbo_rate_match.c -lm \
    || { echo "chain build failed" >&2; exit 2; }

python3 - "$ROOT" <<'PYEOF'
import subprocess, sys
root = sys.argv[1]
sys.path.insert(0, root + "/tools")
import lte_phy as L

bad = 0
n = 0
for D in (44, 68, 100, 148, 260, 612, 1540, 3100, 6176):
    for E in (40, 100, 1234, 4800):
        for rv in range(4):
            d = [(7 * j) % 5 % 2 for j in range(D)]
            mine = "".join(str(b) for b in L.lte_rate_match(d, d, d, E, rv=rv))
            ref = subprocess.run(["./drv", str(D), str(E), str(rv)],
                                 capture_output=True, text=True).stdout.strip()
            n += 1
            if mine != ref:
                bad += 1
                print("MISMATCH D=%d E=%d rv=%d" % (D, E, rv))
                print("  lte_phy %s" % mine[:70])
                print("  turbofec %s" % ref[:70])
print("compared %d cases (D x E x rv, N_cb = K_w): %d mismatches" % (n, bad))

# ---- the full chain, encoder included -------------------------------------
chain_bad = 0
chain_n = 0
for K in (40, 48, 512, 1024, 6144):
    inp = [1 - (i % 2) for i in range(K)]
    t0, t1, t2 = L.turbo_encode_split(inp, K)
    for E in (100, 1234, 4800):
        for rv in range(4):
            mine = "".join(str(b) for b in L.lte_rate_match(t0, t1, t2, E, rv=rv))
            out = subprocess.run(["./drv_chain", str(K), str(E), str(rv)],
                                 capture_output=True, text=True).stdout.strip()
            ref_s0, ref_s1, ref_s2, ref_e = out.split()
            chain_n += 1
            if "".join(map(str, t0)) != ref_s0:
                chain_bad += 1
                print("SPLIT d0 MISMATCH K=%d" % K)
            if "".join(map(str, t1)) != ref_s1:
                chain_bad += 1
                print("SPLIT d1 MISMATCH K=%d" % K)
                print("  lte_phy %s" % "".join(map(str, t1))[:70])
                print("  turbofec %s" % ref_s1[:70])
            if "".join(map(str, t2)) != ref_s2:
                chain_bad += 1
                print("SPLIT d2 MISMATCH K=%d" % K)
                print("  lte_phy %s" % "".join(map(str, t2))[:70])
                print("  turbofec %s" % ref_s2[:70])
            if mine != ref_e:
                chain_bad += 1
                print("CHAIN MISMATCH K=%d E=%d rv=%d" % (K, E, rv))
                print("  lte_phy %s" % mine[:70])
                print("  turbofec %s" % ref_e[:70])
print("compared %d full chains (turbo encode + split + rate match, "
      "K x E x rv): %d mismatches" % (chain_n, chain_bad))

sys.exit(1 if (bad or chain_bad) else 0)
PYEOF
