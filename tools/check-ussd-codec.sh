#!/usr/bin/env bash
# GSM 7-bit alphabet and MMI/SS grammar checks (TS 23.038 §6.2.1, TS 22.030 §5.3).
#
# Two modules carry the same 7-bit default alphabet -- modules/38_ussd.sh packs
# and unpacks USSD text, modules/41_ota_sms.sh packs and unpacks TP-UD -- and
# they did not read it the same way:
#
#   38_ussd  a hand-picked subset ("only what a USSD string carries"): 'è',
#            '¥', '_', '€' and every bracketed character were refused on
#            encode, and 26 septets decoded to '?' -- a silent substitution in
#            a function whose own comment promised a hard error.
#   41_ota_sms  '\' encoded as its identity code 92 where the clause puts it
#            behind ESC (27,47), and a form feed had no encode arm at all, so
#            the same text took a different wire form from the one the table
#            names.
#
# 38_ussd's MMI parser also refused *43# -- the SI-less activate shape, the way
# call waiting is switched on -- because its pattern demanded a '*' after the
# service code, while #SC# and ##SC# already accepted their SI-less shape.
#
# check_ussd_codec.py states the alphabet and the start-string grammar from the
# two clauses, sweeps all 125 printable septets and the ten extension
# characters through both modules in both directions, and checks the MMI forms;
# scratch copies of the module with each defect put back must make it fail.
#
# Exit 0 all agree, 1 a disagreement, 2 the check could not run.
set -uo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ORACLE_PY="${USSD_ORACLE_PY:-${OTA_ORACLE_PY:-/home/ysl/.ota-oracles/venv/bin/python}}"

if [[ ! -x "$ORACLE_PY" ]]; then
    echo "SKIP	no oracle interpreter at $ORACLE_PY (set USSD_ORACLE_PY)" >&2
    exit 2
fi
for m in modules/38_ussd.sh modules/41_ota_sms.sh; do
    if [[ ! -f "$ROOT/$m" ]]; then
        echo "FAIL	$ROOT/$m is missing" >&2
        exit 1
    fi
done

rc=0
echo "== GSM 7-bit alphabet and MMI grammar vs the clauses =="
out=$("$ORACLE_PY" "$ROOT/tools/ussd-oracle/check_ussd_codec.py" --negctl 2>&1)
trc=$?
printf '%s\n' "$out" | grep -E '^(CASES|MISMATCHES|RESULT|NEGCTL)' | tail -n 10
if (( trc != 0 )); then
    rc=1
    printf '%s\n' "$out" | grep -E 'MISMATCH|MISSED|SKIP' | head -n 20 >&2
fi

if (( rc == 0 )); then
    echo
    echo "both modules read the 7-bit alphabet and the MMI strings the way the clauses write them"
fi
exit "$rc"
