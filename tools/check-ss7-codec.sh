#!/usr/bin/env bash
# SS7 / MAP codec checks for modules/26_ss7_map.sh
# (ITU-T Q.704 2.2, Q.713 1.4/3.4, Q.773 3.1/3.3, TS 29.002 17.5/17.7,
#  TS 23.003 3.3).
#
# The interconnect side speaks MTP3, SCCP, TCAP and MAP, and every field an
# operator reads off a capture is a bit in one of those headers: the point
# codes in the label, the address indicator's routing bit, the pointer that
# says where the called party address starts, the operation code inside a
# TCAP invoke, the SS-Code inside a RegisterSS argument. Get one wrong and the
# capture still decodes -- it just names a different operation or a different
# subscriber, which is worse than refusing to decode.
#
# check_ss7_codec.py states the clauses -- the label layout, the address
# indicator, the UDT layout and its three pointers, the SSN registry, the
# operation and error code spaces, the SS-Code registry, the TCAP tags and
# component types, TBCD -- and drives the module through its own command line,
# comparing against encoders written from the clause text and, where Wireshark
# is installed, against its dissector. Seven defects put back into a scratch
# copy must each make it fail.
#
# Exit 0 all agree, 1 a disagreement, 2 the check could not run.
set -uo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ORACLE_PY="${SS7_ORACLE_PY:-${OTA_ORACLE_PY:-python3}}"

if ! command -v "$ORACLE_PY" >/dev/null 2>&1; then
    echo "SKIP	no oracle interpreter at $ORACLE_PY (set SS7_ORACLE_PY)" >&2
    exit 2
fi
if [[ ! -f "$ROOT/modules/26_ss7_map.sh" ]]; then
    echo "FAIL	$ROOT/modules/26_ss7_map.sh is missing" >&2
    exit 1
fi

rc=0
echo "== SS7 / MAP codec vs the clauses and Wireshark =="
out=$("$ORACLE_PY" "$ROOT/tools/ss7-oracle/check_ss7_codec.py" \
          --module "$ROOT/modules/26_ss7_map.sh" --negctl 2>&1)
trc=$?
printf '%s\n' "$out" | grep -E '^(CASES|MISMATCHES|RESULT|NEGCTL|NOTE)' | tail -n 16
if (( trc != 0 )); then
    rc=1
    printf '%s\n' "$out" | grep -E 'MISMATCH|MISSED|FAIL|ERROR' | head -n 20 >&2
fi

if (( rc == 0 )); then
    echo
    echo "the MTP3 label, the SCCP addresses and pointers, the MAP operation,"
    echo "error and SS-Code registries and the TCAP components agree"
fi
exit "$rc"
