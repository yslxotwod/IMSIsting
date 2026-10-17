#!/usr/bin/env bash
# OTA security coding checks (ETSI TS 102 225 SPI/KIc/KID).
#
# Two modules code the same fields -- modules/41_ota_sms.sh builds a Command
# Header, modules/16_sim.sh parses one -- so they are checked against a single
# independent statement of the bit positions, and against pySim, which is a
# separate implementation of the same clause:
#
#   1. check_ota_coding.py -- the SPI first and second octets over an
#      exhaustive sweep, and the KIc/KID key set, mode and algorithm family
#      over a sampled sweep, all compared to the layout this checker states
#      from the clause's own prose. Where pySim is importable its SPI and KIC
#      encoders have to agree too.
#
# The clause's printed table interleaves its rows, so the layout is pinned by
# two statements in the same text: the command's integrity field is named
# "SPI1.b2b1", and "SPI2.b4b3 shall be set to the same value as SPI1.b2b1"
# when the response carries the same protection. Reading the table top to
# bottom instead produces an SPI that reports ciphering on a clear payload.
#
# The checker also runs a two-sided control: scratch copies of both modules
# with the bit positions deliberately put back the wrong way must make it fail.
#
# Exit 0 all agree, 1 a disagreement, 2 the check could not run.
set -uo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ORACLE_PY="${OTA_ORACLE_PY:-/home/ysl/.ota-oracles/venv/bin/python}"

if [[ ! -x "$ORACLE_PY" ]]; then
    echo "SKIP	no oracle interpreter at $ORACLE_PY (set OTA_ORACLE_PY)" >&2
    exit 2
fi
for f in "$ROOT/modules/41_ota_sms.sh" "$ROOT/modules/16_sim.sh"; do
    if [[ ! -f "$f" ]]; then
        echo "FAIL	$f is missing" >&2
        exit 1
    fi
done

rc=0
echo "== OTA SPI / KIc / KID coding vs the clause and pySim =="
out=$("$ORACLE_PY" "$ROOT/tools/ota-oracle/check_ota_coding.py" --negctl 2>&1)
trc=$?
printf '%s\n' "$out" | grep -E '^(CASES|MISMATCHES|RESULT|NEGCTL)' | tail -n 10
if (( trc != 0 )); then
    rc=1
    printf '%s\n' "$out" | grep -E 'FAIL|MISMATCH|MISSED' | head -n 20 >&2
fi

if (( rc == 0 )); then
    echo
    echo "all OTA coding checks agree with the clause and pySim"
fi
exit "$rc"
