#!/usr/bin/env bash
# RANAP codec checks (TS 25.413 §9.1, §9.1.5, §9.2.1, §9.3; X.691 §13-§14).
#
# tools/ranap_asn1.py writes the one RANAP message this tree can compose: the
# InitialUE-Message a rogue Home NodeB hands the core so it will serve a
# subscriber whose NAS arrived over an access point it did not authorise. A
# wrong procedure code is not cosmetic -- the octets stay well formed and the
# core reads them as a different procedure; a wrong domain bit files a packet
# connection as a circuit-switched call; a wrong location area attaches the
# subscriber to the wrong cell. So the tool is checked against the clause and
# against a second implementation, never against itself.
#
# check_ranap_codec.py states the clause: the RANAP-PDU choice of §9.1 with
# its preamble-free InitiatingMessage, the criticality encoding of §9.3, the
# container with its sixteen-bit count and the ProtocolIE-Field layout, the
# four mandatory IEs of InitialUE-Message, the IE ids (3, 15, 16, 58), the
# procedure code 19 that `tshark -G values` gives for id-InitialUE-Message,
# the non-extensible CN-DomainIndicator whose index is ONE bit (so ps-domain
# is 0x80), the LAI/SAI presence bit before its aligned octets, and the
# NAS-PDU octet string with its two-octet determinant above 127.
#
# Four defects put back into a copy of the tool must each make the check fail:
# the procedure code written as 1 (a well-formed Iu-ReleaseCommand), the domain
# indicator given an extension bit, the LAI without its presence bit, and the
# NAS written without its determinant.
#
# Exit 0 all agree, 1 a disagreement, 2 the check could not run.
set -uo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ORACLE_PY="${RANAP_ORACLE_PY:-${LTE_ORACLE_PY:-/home/ysl/.lte-oracles/venv/bin/python}}"

if [[ ! -x "$ORACLE_PY" ]]; then
    echo "SKIP	no oracle interpreter at $ORACLE_PY (set RANAP_ORACLE_PY)" >&2
    exit 2
fi
if [[ ! -f "$ROOT/tools/ranap_asn1.py" ]]; then
    echo "FAIL	$ROOT/tools/ranap_asn1.py is missing" >&2
    exit 1
fi

rc=0
echo "== RANAP vs the clauses and pycrate =="
out=$("$ORACLE_PY" "$ROOT/tools/ranap-oracle/check_ranap_codec.py" --negctl 2>&1)
trc=$?
printf '%s\n' "$out" | grep -E '^(CASES|MISMATCHES|RESULT|NEGCTL)' | tail -n 12
if (( trc != 0 )); then
    rc=1
    printf '%s\n' "$out" | grep -E 'MISMATCH|MISSED|UNRUNNABLE|ERROR' | head -n 20 >&2
fi

echo
echo "== the tool's own vectors =="
if ! "$ROOT/tools/ranap_asn1.py" selftest | tail -n 2 | grep -q '^RESULT	PASS'; then
    rc=1
    echo "FAIL	the tool's selftest does not pass" >&2
fi

if (( rc == 0 )); then
    echo
    echo "the RANAP envelope, IE ids, domain bit and length determinants agree"
fi
exit "$rc"
