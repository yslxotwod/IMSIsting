#!/usr/bin/env bash
#
# Cross-check the generated NB-IoT RRC codec (tools/asn1gen.py --family nbiot +
# tools/lte_per.py) against pycrate, and check that the committed table is what
# the generator actually emits.
#
# Not part of tools/run-selftests.sh: it needs pycrate, which is an optional
# dependency (modules/00_deps.sh), and a couple of minutes. Run it by hand when
# the generator, the engine, or tools/lte_rrc_nb_layout.py changes.
#
# Why a second family and a second check: an LTE SIB1 does not reference
# SIB1-NB, so no closure of the LTE roots reaches the NB message set. The set is
# in the same pycrate namespace list, which is why 45_iot could claim to decode
# SIB1-NB for months while slicing hex at fixed character offsets -- the schema
# was present and the table had never been asked to include it.
#
# == What is checked ==
#
#   1. Provenance. The generator is run into a scratch directory and the result
#      is compared, byte for byte, with the committed table. Without this the
#      committed file could drift from the generator and every downstream test
#      would still pass, because they all read the committed file.
#
#   2. Random differential. tools/lte-per-oracle/verify_per.py builds values
#      from pycrate's own object graph -- deliberately not from the table under
#      test -- encodes with both codecs, compares bit for bit, and round-trips
#      through our decoder.
#
#   3. Zero-case detection. The random generator reports zero cases for a type
#      it cannot build, rather than failing. A type with zero cases is
#      unverified, and this reports that as a failure of the check.
#
# pycrate is a *reading* of TS 36.331, not the specification. Agreeing with it
# is strong evidence and is not proof.
#
# Licensing: pycrate is LGPL v2.1+. Build-time oracle only; no pycrate source is
# copied into this repository and the emitted table imports nothing at all.

set -u

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PY=${LTE_ORACLE_PY:-/home/ysl/.lte-oracles/venv/bin/python}
WORK=${LTE_NB_ORACLE_DIR:-/tmp/lte-nb-oracle}
COMMITTED="$REPO/tools/lte_rrc_nb_layout.py"

if [ ! -x "$PY" ]; then
    printf 'SKIP  no oracle interpreter at %s\n' "$PY" >&2
    printf '      set LTE_ORACLE_PY to a python that has pycrate installed\n' >&2
    exit 2
fi

"$PY" -c 'import pycrate_asn1dir' 2>/dev/null || {
    printf 'SKIP  %s does not have pycrate installed\n' "$PY" >&2
    exit 2
}

mkdir -p "$WORK" || exit 2
rc=0

printf '== generating the NB-IoT layout table from the oracle\n'
if ! "$PY" "$REPO/tools/asn1gen.py" --family nbiot \
        --out "$WORK/lte_rrc_nb_layout.py"; then
    printf 'FAIL  the generator did not run\n' >&2
    exit 1
fi
printf '\n'

printf '== the committed table is what the generator emits\n'
if [ ! -f "$COMMITTED" ]; then
    printf 'FAIL  %s does not exist; the module decodes against a missing table\n' \
        "$COMMITTED" >&2
    rc=1
elif ! diff -q <(sed '/^Generated: /d' "$COMMITTED") \
                <(sed '/^Generated: /d' "$WORK/lte_rrc_nb_layout.py") >/dev/null; then
    printf 'FAIL  %s differs from the generator output.\n' "$COMMITTED" >&2
    printf '      Either the file was edited by hand, or the generator changed\n' >&2
    printf '      and the table was not regenerated. Regenerate it:\n' >&2
    printf '        %s tools/asn1gen.py --family nbiot\n' "$PY" >&2
    printf '      then run this check again.\n' >&2
    diff -u <(sed '/^Generated: /d' "$COMMITTED") \
            <(sed '/^Generated: /d' "$WORK/lte_rrc_nb_layout.py") | head -40 >&2
    rc=1
else
    printf 'ok    committed table matches the generator (%s bytes, generated %s)\n' \
        "$(wc -c < "$COMMITTED")" \
        "$(sed -n 's/^Generated: //p' "$COMMITTED")"
fi
printf '\n'

printf '== random differential against pycrate\n'
set +e
"$PY" "$REPO/tools/lte-per-oracle/verify_per.py" \
    --table "$WORK/lte_rrc_nb_layout.py" --per "$REPO/tools/lte_per.py" \
    --cases "${LTE_NB_CASES:-25}" 2>&1 | tee "$WORK/random.txt"
drc=${PIPESTATUS[0]}
set -e
[ "$drc" -eq 0 ] || rc=1

# Zero cases is not a pass -- the same rule as the LTE check.
UNVERIFIED=$(grep -E '^  [A-Za-z0-9_]+ +0 case' "$WORK/random.txt" || true)
SKIPPED=$(grep -E ': not in the oracle module, skipped' "$WORK/random.txt" || true)
if [ -n "$UNVERIFIED" ] || [ -n "$SKIPPED" ]; then
    printf '\nFAIL  these root types are in the table but were never checked:\n' >&2
    [ -z "$UNVERIFIED" ] || printf '%s\n' "$UNVERIFIED" >&2
    [ -z "$SKIPPED" ] || printf '%s\n' "$SKIPPED" >&2
    printf '      zero cases is not a pass. A root the random generator cannot\n' >&2
    printf '      build a value for needs a hand-built known-answer vector.\n' >&2
    rc=1
fi
printf '\n'

if [ "$rc" -eq 0 ]; then
    printf 'RESULT  PASS  the NB-IoT table is the generator output and agrees with pycrate\n'
else
    printf 'RESULT  FAIL\n' >&2
fi
exit "$rc"
