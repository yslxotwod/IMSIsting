#!/usr/bin/env bash
# APDU coding checks (ISO/IEC 7816-4 §5.1 cases, §5.1.4 SW1 classes).
#
# modules/16_sim.sh builds command APDUs, parses them back and labels status
# words, and until this check existed all three were only asserted against the
# module's own selftest -- a field that moved in both the builder and the
# parser agreed with itself and stayed green. Two such fields were in fact
# wrong when this was written:
#
#   case 4E  Le given as 0000 (65536) was encoded correctly but reported as
#            le 0, while the same request with no data (case 2E) reported
#            65536. A caller reading the field saw a zero-length read.
#   6C xx    the label read "wrong Le: retry with Le=xx" with no severity
#            word, although SW1=6C is a checking error in the clause and the
#            module's own generic 6C.. fallback said "error:".
#
# check_apdu_build.py states the seven cases and the SW1 class table from the
# clause, encodes them itself, and compares what the module produces; pySim's
# parse_command_apdu is the second implementation for the four short cases.
# It also round-trips every case through --parse-apdu. Scratch copies of the
# module with a field put back must make it fail.
#
# Exit 0 all agree, 1 a disagreement, 2 the check could not run.
set -uo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ORACLE_PY="${APDU_ORACLE_PY:-${SIM_ORACLE_PY:-${OTA_ORACLE_PY:-/home/ysl/.ota-oracles/venv/bin/python}}}"

if [[ ! -x "$ORACLE_PY" ]]; then
    echo "SKIP	no oracle interpreter at $ORACLE_PY (set APDU_ORACLE_PY)" >&2
    exit 2
fi
if [[ ! -f "$ROOT/modules/16_sim.sh" ]]; then
    echo "FAIL	$ROOT/modules/16_sim.sh is missing" >&2
    exit 1
fi

rc=0
echo "== APDU coding (ISO/IEC 7816-4 §5.1, §5.1.4) vs pySim =="
out=$("$ORACLE_PY" "$ROOT/tools/apdu-oracle/check_apdu_build.py" --negctl 2>&1)
trc=$?
printf '%s\n' "$out" | grep -E '^(CASES|MISMATCHES|RESULT|NEGCTL)' | tail -n 12
if (( trc != 0 )); then
    rc=1
    printf '%s\n' "$out" | grep -E 'MISMATCH|MISSED|SKIP|ERROR' | head -n 20 >&2
fi

if (( rc == 0 )); then
    echo
    echo "all APDU coding checks agree with the clause and pySim"
fi
exit "$rc"
