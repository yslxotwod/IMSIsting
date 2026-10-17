#!/usr/bin/env bash
# NGAP codec checks (TS 38.413 §9.1, §9.3; X.691 §13-§14).
#
# tools/ngap_asn1.py writes the NGAP a gNB sends an AMF. A wrong IE number
# there puts a subscriber's identity or a tracking area into the wrong field,
# and a wrong bit layout produces a message that dissects without an error and
# means something else -- so the tool is checked against the clause and a
# second implementation, never against itself.
#
# check_ngap_codec.py states the clause: the NGAP-PDU choice of §9.1 with its
# InitiatingMessage (no SEQUENCE preamble), the criticality encoding of §9.3,
# the SEQUENCE (SIZE(0..65535)) container with its extension bit and
# sixteen-bit count, the ProtocolIE-Field layout, the IE ids, the APER
# constrained-INTEGER width rule of X.691 §13.2.2 (two bits for a 32-bit
# range, three for the 40-bit AMF UE id), the TAI list's four-bit count and
# shared preamble bit, the three-octet 5G TAC, and the bit-field run inside
# UEPagingIdentity. It encodes the same values through pycrate 0.8.1's
# pycrate_asn1dir.NGAP and requires the octets to match, then asks pycrate to
# read the tool's octets back to the same values.
#
# Four defects put back into a scratch copy of the tool must each make the
# check fail: the INTEGER length field widened to S1AP's two bits, the
# container count narrowed to one octet, the TAC narrowed to the 4G width, and
# the TAI list's preamble bit moved below the alignment.
#
# Exit 0 all agree, 1 a disagreement, 2 the check could not run.
set -uo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ORACLE_PY="${NGAP_ORACLE_PY:-${LTE_ORACLE_PY:-/home/ysl/.lte-oracles/venv/bin/python}}"

if [[ ! -x "$ORACLE_PY" ]]; then
    echo "SKIP	no oracle interpreter at $ORACLE_PY (set NGAP_ORACLE_PY)" >&2
    exit 2
fi
if [[ ! -f "$ROOT/tools/ngap_asn1.py" ]]; then
    echo "FAIL	$ROOT/tools/ngap_asn1.py is missing" >&2
    exit 1
fi

rc=0
echo "== NGAP vs the clauses and pycrate =="
out=$("$ORACLE_PY" "$ROOT/tools/ngap-oracle/check_ngap_codec.py" --negctl 2>&1)
trc=$?
printf '%s\n' "$out" | grep -E '^(CASES|MISMATCHES|RESULT|NEGCTL)' | tail -n 12
if (( trc != 0 )); then
    rc=1
    printf '%s\n' "$out" | grep -E 'MISMATCH|MISSED|UNRUNNABLE|ERROR' | head -n 20 >&2
fi

if (( rc == 0 )); then
    echo
    echo "the NGAP envelope, IE ids, INTEGER widths and 5G TAC agree"
fi
exit "$rc"
