#!/usr/bin/env bash
#
# Cross-check the generated LTE RRC codec (tools/asn1gen.py + tools/lte_per.py)
# against pycrate, an independent ASN.1 PER implementation.
#
# This check is NOT part of tools/run-selftests.sh: it needs pycrate, which is
# an optional dependency at modules/00_deps.sh:197, and a few minutes. Run it by
# hand when the generator, the engine, or the generated table changes.
#
# Why it exists: the point of the generated table is that the *shipped* codec
# carries no pycrate at all, so pycrate stays the independent thing we assert
# against instead of becoming the thing we ship. That property is only worth
# anything if the assertion is actually run, and run over enough values to reach
# the corners. A hand-written vector derived from the same reading of the
# specification as the codec proves nothing.
#
# == What is checked ==
#
#   1. Random differential. tools/lte-per-oracle/verify_per.py generates values
#      from pycrate's own object graph -- deliberately NOT from the table under
#      test, which would assume the thing being checked -- encodes each value
#      with both codecs, compares bit for bit, and round-trips it through our
#      decoder.
#
#   2. Hand-built cases for SIB9 to SIB13. The random generator cannot yet build
#      a value pycrate accepts for every type, and when it cannot it reports
#      ZERO cases for that type rather than failing. A type with zero cases is
#      unverified; this tree has already been bitten once by reading a green run
#      as coverage it did not have. verify_per.py's summary is inspected below
#      for any type that produced nothing, and that is reported as a failure of
#      the check rather than passed over.
#
# == What it does NOT cover, stated rather than papered over ==
#
#   * The 1031 emitted types are exercised only where the root types reach. A
#     leaf that is wrong and unreachable from the sampled roots is invisible
#     here.
#   * pycrate is a *reading* of TS 36.331, not the specification. Agreeing with
#     it is strong evidence and is not proof; where the two could differ, the
#     specification governs.
#
# Licensing: pycrate is LGPL v2.1+. It is used as a build-time oracle only. No
# pycrate source is copied into this repository and the emitted table imports
# nothing at all. Do not vendor it.

set -u

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PY=${LTE_ORACLE_PY:-/home/ysl/.lte-oracles/venv/bin/python}
WORK=${LTE_SIB_ORACLE_DIR:-/tmp/lte-sib-oracle}

# The full root set. SIB12 and SIB13 appear under their Rel-9 names because
# TS 36.331 never defines them unsuffixed -- pycrate's hasattr() returns False
# for the plain name and reads as "the oracle does not have this type".
ROOTS="SystemInformationBlockType1,SystemInformationBlockType2"
ROOTS="$ROOTS,SystemInformationBlockType3,SystemInformationBlockType4"
ROOTS="$ROOTS,SystemInformationBlockType5,SystemInformationBlockType6"
ROOTS="$ROOTS,SystemInformationBlockType7,SystemInformationBlockType8"
ROOTS="$ROOTS,SystemInformationBlockType9,SystemInformationBlockType10"
ROOTS="$ROOTS,SystemInformationBlockType11,SystemInformationBlockType12-r9"
ROOTS="$ROOTS,SystemInformationBlockType13-r9"
ROOTS="$ROOTS,RRCConnectionReconfiguration,INTER.HandoverCommand"
ROOTS=$(printf '%s' "$ROOTS" | tr -d '\n')

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

printf '== generating the layout table from the oracle\n'
if ! "$PY" "$REPO/tools/asn1gen.py" --types "$ROOTS" \
        --out "$WORK/lte_rrc_layout.py"; then
    printf 'FAIL  the generator did not run\n' >&2
    exit 1
fi
printf '\n'

printf '== random differential against pycrate\n'
set +e
"$PY" "$REPO/tools/lte-per-oracle/verify_per.py" \
    --table "$WORK/lte_rrc_layout.py" --per "$REPO/tools/lte_per.py" \
    --cases "${LTE_SIB_CASES:-25}" 2>&1 | tee "$WORK/random.txt"
drc=${PIPESTATUS[0]}
set -e
[ "$drc" -eq 0 ] || rc=1

# A root type that yielded no cases was not checked, whatever the totals say.
# Catch it here rather than letting the summary read as coverage.
#
# The character class must include digits. The first version of this check used
# [A-Za-z_]+ and therefore never matched "SystemInformationBlockType1" -- so
# four unverified types (SIB1, SIB2, SIB3, SIB5) sat underneath a run that
# printed "all codec checks agree with pycrate". A detector that cannot match
# the names it is looking for is worse than no detector, because it manufactures
# confidence in exactly the state it was written to catch.
# Roots the random generator cannot build values for, but which the hand-built
# checker below does cover. Subtract them so the gap reported is the real one:
# overstating coverage is the dangerous direction, but overstating the *gap*
# trains the reader to ignore the check.
HAND_COVERED="SystemInformationBlockType9 SystemInformationBlockType10"
HAND_COVERED="$HAND_COVERED SystemInformationBlockType11"
HAND_COVERED="$HAND_COVERED SystemInformationBlockType12_r9"
HAND_COVERED="$HAND_COVERED SystemInformationBlockType13_r9"

UNVERIFIED=$(grep -E '^  [A-Za-z0-9_]+ +0 case' "$WORK/random.txt" \
    | awk -v covered="$HAND_COVERED" '
        { for (i = 1; i <= split(covered, c, " "); i++) if ($1 == c[i]) next }
        { print }' || true)
SKIPPED=$(grep -E ': not in the oracle module, skipped' "$WORK/random.txt" || true)
if [ -n "$UNVERIFIED" ] || [ -n "$SKIPPED" ]; then
    printf '\nFAIL  these root types are in the table but were never checked:\n' >&2
    [ -z "$UNVERIFIED" ] || printf '%s\n' "$UNVERIFIED" >&2
    [ -z "$SKIPPED" ] || printf '%s\n' "$SKIPPED" >&2
    printf '      zero cases is not a pass. To verify them: build values pycrate\n' >&2
    printf '      accepts for SIB1/2/3/5, and for HandoverCommand look the type up\n' >&2
    printf '      in the sibling module EUTRA_InterNodeDefinitions, which is where\n' >&2
    printf '      TS 36.331 actually defines it.\n' >&2
    rc=1
fi
printf '\n'

printf '== hand-built cases for SIB9 to SIB13\n'
set +e
"$PY" "$REPO/tools/lte-sib-oracle/handcheck_sib913.py" \
    --table "$WORK/lte_rrc_layout.py" --per "$REPO/tools/lte_per.py" 2>&1 \
    | tee "$WORK/hand.txt"
hrc=${PIPESTATUS[0]}
set -e
[ "$hrc" -eq 0 ] || rc=1
if grep -q 'skipped [1-9]' "$WORK/hand.txt"; then
    printf '\nFAIL  a hand-built case was rejected by pycrate and so was never\n' >&2
    printf '      checked; fix the value rather than counting it as a pass\n' >&2
    rc=1
fi

printf '\n'
if [ "$rc" -eq 0 ]; then
    printf 'all codec checks agree with pycrate\n'
else
    printf 'CODEC CHECKS FAILED\n' >&2
fi
exit "$rc"
