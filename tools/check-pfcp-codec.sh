#!/usr/bin/env bash
# PFCP codec checks (TS 29.244 §7.2.2, §8.1.2; Table 7.3-1, Table 8.1.2-1).
#
# modules/13_nr_core.sh reads PFCP off N4/Sxb, where a 5G core hands the user
# plane a subscriber's forwarding, QoS and quota rules. An IE number that is
# off by a few names a forwarding rule as a QoS rule, and a message type that
# is off turns a session modification into a session establishment -- the sort
# of reading nobody notices until the traffic does not move.
#
# check_pfcp_codec.py states the clause: the header of §7.2.2.1 with its S and
# MP flags, the two message classes of §7.2.2.2-§7.2.2.3, the message type
# registry of Table 7.3-1, the IE layout of §8.1.2 (including the V flag and
# the Enterprise ID) and the IE registry of Table 8.1.2-1, with the grouped
# rule IEs of §7.5 entered. It sweeps every message type and every IE type,
# builds frames the module has to read back field by field, and compares with
# pycrate's PFCP decoder as the second implementation. Five defects put back
# into a scratch copy of the module must each make this check fail.
#
# Exit 0 all agree, 1 a disagreement, 2 the check could not run.
set -uo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ORACLE_PY="${PFCP_ORACLE_PY:-${OTA_ORACLE_PY:-/home/ysl/.ota-oracles/venv/bin/python}}"

if [[ ! -x "$ORACLE_PY" ]]; then
    echo "SKIP	no oracle interpreter at $ORACLE_PY (set PFCP_ORACLE_PY)" >&2
    exit 2
fi
if [[ ! -f "$ROOT/modules/13_nr_core.sh" ]]; then
    echo "FAIL	$ROOT/modules/13_nr_core.sh is missing" >&2
    exit 1
fi

rc=0
echo "== PFCP vs the clauses and pycrate =="
out=$("$ORACLE_PY" "$ROOT/tools/pfcp-oracle/check_pfcp_codec.py" --negctl 2>&1)
trc=$?
printf '%s\n' "$out" | grep -E '^(CASES|MISMATCHES|RESULT|NEGCTL|NOTE)' | tail -n 12
if (( trc != 0 )); then
    rc=1
    printf '%s\n' "$out" | grep -E 'MISMATCH|MISSED|FAIL|ERROR' | head -n 20 >&2
fi

if (( rc == 0 )); then
    echo
    echo "the PFCP header, message types, IE registry and grouped rule IEs agree"
fi
exit "$rc"
