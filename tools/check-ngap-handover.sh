#!/usr/bin/env bash
# N2 handover chain checks (TS 38.413 §9.1.4.2, §9.1.4.3, §9.2.3).
#
# tools/ngap_handover.py encodes the three messages an N2 handover is made of --
# HandoverRequired, HandoverCommand and HandoverNotify -- and a wrong octet
# there hands a subscriber to the wrong cell, or to the wrong PLMN, without
# anything reporting an error. So the tool is checked against the clause and a
# second implementation, never against itself.
#
# check_ngap_handover.py re-encodes the same values through pycrate 0.8.1's
# pycrate_asn1dir.NGAP (compiled from the ASN.1 of §9.3) and requires the
# octets to be identical; it reads the tool's octets back to the same values;
# it asks tshark 4.2.2 to name each message, its procedure code and its IEs out
# of a capture whose SCTP and IP wrappers this tree writes by hand (text2pcap
# cannot frame a bare PDU); and it makes the tool refuse the things the clause
# forbids -- a session list inside HandoverNotify, a two-octet TAC, a gNB
# identity wider than its width field.
#
# Four defects put back into a scratch copy of the tool must each make the
# check fail: GlobalRANNodeID's index widened to three bits, a SEQUENCE OF
# count that forgot its lower bound, HandoverNotify given PathSwitchRequest's
# procedure code, and UserLocationInformation left at reject where HandoverNotify
# gives it ignore.
#
# Exit 0 all agree, 1 a disagreement, 2 the check could not run.
set -uo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ORACLE_PY="${NGAP_ORACLE_PY:-${LTE_ORACLE_PY:-/home/ysl/.lte-oracles/venv/bin/python}}"

if [[ ! -x "$ORACLE_PY" ]]; then
    echo "SKIP	no oracle interpreter at $ORACLE_PY (set NGAP_ORACLE_PY)" >&2
    exit 2
fi
if [[ ! -f "$ROOT/tools/ngap_handover.py" ]]; then
    echo "FAIL	$ROOT/tools/ngap_handover.py is missing" >&2
    exit 1
fi

rc=0
echo "== N2 handover chain vs the clauses, pycrate and tshark =="
out=$("$ORACLE_PY" "$ROOT/tools/ngap-oracle/check_ngap_handover.py" --negctl 2>&1)
trc=$?
printf '%s\n' "$out" | grep -E '^(CASES|MISMATCHES|RESULT)' | tail -n 12
if (( trc != 0 )); then
    rc=1
    printf '%s\n' "$out" | grep -E 'FAIL|MISSED|UNRUNNABLE|ERROR|UNRUNNABLE' | head -n 20 >&2
fi

if (( rc == 0 )); then
    echo
    echo "the three handover messages agree with the clause, pycrate and tshark"
fi
exit "$rc"
