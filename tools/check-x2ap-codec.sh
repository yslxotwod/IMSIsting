#!/usr/bin/env bash
# X2AP codec checks (TS 36.423 §9.1-§9.3; X.691 §13-§16).
#
# tools/x2ap_asn1.py writes the X2AP two base stations exchange. A wrong IE
# number there claims the wrong network and the wrong cell, and a wrong bit
# layout produces a message that dissects without an error and means something
# else -- so the tool is checked against the clause and a second
# implementation, never against itself.
#
# check_x2ap_codec.py states the clause: the X2AP-PDU choice of §9.1 with its
# InitiatingMessage, the criticality octet of §9.3, the container's extension
# bit and sixteen-bit count, the IE ids (ServedCells 20, GlobalENB-ID 21), the
# eight-bit (n-1) count of ServedCells, the two preambles that share one run,
# pCI as an aligned two-octet integer, the ECGI whose 28-bit cell id is NOT
# padded before the TAC, the three-bit PLMN count, and the mode, EARFCN and
# bandwidth fields after it. It encodes the same values through pycrate
# 0.8.1's pycrate_asn1dir.X2AP and requires the octets to match, then asks
# pycrate to read the tool's octets back to the same values.
#
# Four defects put back into a scratch copy of the tool must each make the
# check fail: an alignment inserted between the cell id and the TAC, the item
# preamble given its own octet, the PLMN count widened to eight bits, and the
# bandwidth nibble widened to five.
#
# Exit 0 all agree, 1 a disagreement, 2 the check could not run.
set -uo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ORACLE_PY="${X2AP_ORACLE_PY:-${LTE_ORACLE_PY:-/home/ysl/.lte-oracles/venv/bin/python}}"

if [[ ! -x "$ORACLE_PY" ]]; then
    echo "SKIP	no oracle interpreter at $ORACLE_PY (set X2AP_ORACLE_PY)" >&2
    exit 2
fi
if [[ ! -f "$ROOT/tools/x2ap_asn1.py" ]]; then
    echo "FAIL	$ROOT/tools/x2ap_asn1.py is missing" >&2
    exit 1
fi

rc=0
echo "== X2AP vs the clauses and pycrate =="
out=$("$ORACLE_PY" "$ROOT/tools/x2ap-oracle/check_x2ap_codec.py" --negctl 2>&1)
trc=$?
printf '%s\n' "$out" | grep -E '^(CASES|MISMATCHES|RESULT|NEGCTL)' | tail -n 12
if (( trc != 0 )); then
    rc=1
    printf '%s\n' "$out" | grep -E 'MISMATCH|MISSED|UNRUNNABLE|ERROR' | head -n 20 >&2
fi

if (( rc == 0 )); then
    echo
    echo "the X2AP envelope, IE ids, cell layout and bandwidths agree"
fi
exit "$rc"
