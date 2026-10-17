#!/usr/bin/env bash
# LPP (TS 37.355) codec checks.
#
# One differential check, run with the oracle interpreter because pycrate is the
# independent implementation it compares against:
#
#   1. check_lpp_position.py -- the forged position report, bit for bit, over
#      fixed boundary cases and a random grid sample. It also runs a two-sided
#      control: two deliberately broken copies of tools/lpp_layout.py, each of
#      which has to make the differential fail. A check that cannot fail is not
#      a check.
#
# The table itself (tools/lpp_layout.py) is generated, not written:
#
#   /home/ysl/.lte-oracles/venv/bin/python tools/asn1gen.py --family lpp \
#       --out tools/lpp_layout.py
#
# Exit 0 all agree, 1 a disagreement, 2 the check could not run (no pycrate).
set -uo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ORACLE_PY="${LTE_ORACLE_PY:-/home/ysl/.lte-oracles/venv/bin/python}"
RANDOM_N="${LPP_RANDOM:-200}"

if [[ ! -x "$ORACLE_PY" ]]; then
    echo "SKIP	no oracle interpreter at $ORACLE_PY (set LTE_ORACLE_PY)" >&2
    exit 2
fi
if [[ ! -f "$ROOT/tools/lpp_layout.py" ]]; then
    echo "FAIL	tools/lpp_layout.py is missing; regenerate it with:
  $ORACLE_PY tools/asn1gen.py --family lpp --out tools/lpp_layout.py" >&2
    exit 1
fi

rc=0
echo "== LPP position report vs pycrate (${RANDOM_N} random cases) =="
out=$("$ORACLE_PY" "$ROOT/tools/lpp-oracle/check_lpp_position.py" \
        --random "$RANDOM_N" --negctl 2>&1)
trc=$?
printf '%s\n' "$out" | tail -n 4
if (( trc != 0 )); then
    rc=1
    printf '%s\n' "$out" | grep -E 'FAIL|MISMATCH' | head -n 20 >&2
fi

if (( rc == 0 )); then
    echo
    echo "all LPP codec checks agree with pycrate"
fi
exit "$rc"
