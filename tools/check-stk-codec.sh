#!/usr/bin/env bash
# Check the STK proactive command against pySim (TS 31.111 6.4.4 / TS 102 223 8.6).
#
# The Command Details value is command number, type of command, command
# qualifier; modules/52_stk.sh used to write type, qualifier, zero. This runs
# the differential check and then its two-sided control, which puts the old
# octet order, a swapped Device Identities and a dropped command number back
# into a scratch copy of the module and requires each to be caught.
#
# Exit 0 pass, 1 mismatch, 2 cannot run (no oracle interpreter or no pySim).
set -o pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ORACLE_PY="${STK_ORACLE_PY:-/home/ysl/.ota-oracles/venv/bin/python}"

if [[ ! -x "$ORACLE_PY" ]]; then
    printf 'SKIP\tno oracle interpreter at %s (set STK_ORACLE_PY)\n' "$ORACLE_PY" >&2
    exit 2
fi

out=$(STK_MODULE="${STK_MODULE:-$ROOT/modules/52_stk.sh}" "$ORACLE_PY" "$ROOT/tools/stk-oracle/check_stk_command.py" 2>&1)
rc=$?
printf '%s\n' "$out" | tail -4
if (( rc != 0 )); then
    if (( rc == 2 )); then
        printf 'SKIP\tpySim not importable\n' >&2
        exit 2
    fi
    printf '%s\n' "$out" | grep -E 'MISMATCH|ERROR' >&2
    exit 1
fi

STK_MODULE="${STK_MODULE:-$ROOT/modules/52_stk.sh}" "$ORACLE_PY" "$ROOT/tools/stk-oracle/check_stk_command.py" --negctl 2>&1 | tail -4
nrc=${PIPESTATUS[0]}
if (( nrc != 0 )); then
    printf 'ERROR\tthe two-sided control did not catch every reintroduced defect\n' >&2
    exit 1
fi
printf '\nall STK command checks agree with pySim\n'
