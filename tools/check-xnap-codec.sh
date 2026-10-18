#!/usr/bin/env bash
# XnAP codec checks (TS 38.423 §9.1, §9.3, §9.2.x; X.691 §13-§14).
#
# tools/xnap_asn1.py writes the XnSetupRequest two NG-RAN nodes exchange. A
# wrong IE number there hands the peer's identity or its tracking area to the
# wrong field, and a wrong bit width produces a message that dissects without
# complaint and says something else -- so the tool is checked against the
# clause and a second implementation, never against itself.
#
# check_xnap_codec.py states the clause: the XnAP-PDU choice of §9.1 with its
# preamble-free InitiatingMessage, the criticality encoding of §9.3, the
# extensible SEQUENCE (SIZE(0..65535)) container with its sixteen-bit count,
# the ProtocolIE-Field layout, the IE ids (4, 14, 75), the GlobalNG-RANNode-ID
# choice with the four-bit length of length before the identifier, the AMF
# region list count, the TAI list's one-octet count and its two-bit item
# preamble, the FOUR-bit broadcastPLMN count, and the SIXTEEN-bit
# tAISliceSupport-List count whose eleven-bit S-NSSAI items are not padded
# between them (sst is eight unaligned bits).
#
# Three defects put back into a copy of the tool's octets must each make the
# check fail: the slice count narrowed to eight bits, the broadcast PLMN count
# widened to eight, and the slice items padded to an octet boundary.
#
# Exit 0 all agree, 1 a disagreement, 2 the check could not run.
set -uo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ORACLE_PY="${XNAP_ORACLE_PY:-${LTE_ORACLE_PY:-/home/ysl/.lte-oracles/venv/bin/python}}"

if [[ ! -x "$ORACLE_PY" ]]; then
    echo "SKIP	no oracle interpreter at $ORACLE_PY (set XNAP_ORACLE_PY)" >&2
    exit 2
fi
if [[ ! -f "$ROOT/tools/xnap_asn1.py" ]]; then
    echo "FAIL	$ROOT/tools/xnap_asn1.py is missing" >&2
    exit 1
fi

rc=0
echo "== XnAP vs the clauses and pycrate =="
out=$("$ORACLE_PY" "$ROOT/tools/xnap-oracle/check_xnap_codec.py" --negctl 2>&1)
trc=$?
printf '%s\n' "$out" | grep -E '^(CASES|MISMATCHES|RESULT|NEGCTL)' | tail -n 12
if (( trc != 0 )); then
    rc=1
    printf '%s\n' "$out" | grep -E 'MISMATCH|MISSED|UNRUNNABLE|ERROR' | head -n 20 >&2
fi

echo
echo "== the tool's own vectors =="
if ! "$ROOT/tools/xnap_asn1.py" selftest | tail -n 1 | grep -q PASS; then
    rc=1
    echo "FAIL	the tool's selftest does not pass" >&2
fi

if (( rc == 0 )); then
    echo
    echo "the XnAP envelope, IE ids, gNB-ID length and the slice layout agree"
fi
exit "$rc"
