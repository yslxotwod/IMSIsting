#!/usr/bin/env bash
# RUA codec checks (TS 25.468 §9.1, §9.2, §9.3; X.691 §13-§14).
#
# tools/rua_asn1.py writes the two RUA messages a Home NodeB uses to open an
# Iuh signalling connection and to hand the core a RANAP message. A wrong
# Establishment-Cause bit is not cosmetic: it makes the core file a normal
# call as an emergency call, which changes priority, charging and what the
# operator's dashboards alert on. A wrong length determinant makes the core
# read the first RANAP octet as the length of the rest. So the tool is checked
# against the clause and a second implementation, never against itself.
#
# check_rua_codec.py states the clause: the RUA-PDU choice of §9.1 with its
# preamble-free InitiatingMessage, the criticality encoding of §9.3, the
# extensible container with its sixteen-bit count, the ProtocolIE-Field
# layout, the procedure codes (Connect 1, DirectTransfer 2), the IE ids (3, 4,
# 6), the 24-bit Context-ID, the extensible Establishment-Cause whose index is
# ONE bit (so normal-call is 0x40), and the RANAP-Message octet string with
# its two-octet length determinant above 127.
#
# Four defects put back into a copy of the tool must each make the check fail:
# the cause index widened to three bits, the context id widened to 32 bits,
# the RANAP written without its determinant, and the long determinant cut to
# one octet.
#
# Exit 0 all agree, 1 a disagreement, 2 the check could not run.
set -uo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ORACLE_PY="${RUA_ORACLE_PY:-${LTE_ORACLE_PY:-/home/ysl/.lte-oracles/venv/bin/python}}"

if [[ ! -x "$ORACLE_PY" ]]; then
    echo "SKIP	no oracle interpreter at $ORACLE_PY (set RUA_ORACLE_PY)" >&2
    exit 2
fi
if [[ ! -f "$ROOT/tools/rua_asn1.py" ]]; then
    echo "FAIL	$ROOT/tools/rua_asn1.py is missing" >&2
    exit 1
fi

rc=0
echo "== RUA vs the clauses and pycrate =="
out=$("$ORACLE_PY" "$ROOT/tools/rua-oracle/check_rua_codec.py" --negctl 2>&1)
trc=$?
printf '%s\n' "$out" | grep -E '^(CASES|MISMATCHES|RESULT|NEGCTL)' | tail -n 12
if (( trc != 0 )); then
    rc=1
    printf '%s\n' "$out" | grep -E 'MISMATCH|MISSED|UNRUNNABLE|ERROR' | head -n 20 >&2
fi

echo
echo "== the tool's own vectors =="
if ! "$ROOT/tools/rua_asn1.py" selftest | tail -n 2 | grep -q '^RESULT	PASS'; then
    rc=1
    echo "FAIL	the tool's selftest does not pass" >&2
fi

if (( rc == 0 )); then
    echo
    echo "the RUA envelope, IE ids, Establishment-Cause bit and length"\
"determinants agree"
fi
exit "$rc"
