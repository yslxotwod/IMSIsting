#!/usr/bin/env bash
# GTPv2-C and GTPv1-U codec checks (TS 29.274 §5.1/§8, TS 29.281 §5.1/§5.2).
#
# modules/11_lte_core.sh reads the core network's own headers, so a wrong
# field order, a wrong registry row or a digit read with a count octet that
# the clause never puts there is not cosmetics: the analyst reads a
# subscriber identity or a tunnel endpoint out of it.
#
# check_gtp_codec.py states the two clauses -- version and flag bits in octet
# 1, Length as the count of the octets after the first four, TBCD identities
# with no count octet, the ULI identity order, the F-TEID interface type as
# six bits, the RAT table, and for GTP-U the extension-header chain with its
# comprehension bits -- builds the frames from that statement, and compares
# what the module prints field by field.  The message-type and IE-type
# registries are swept over all 256 values.  pycrate's GTPv2 decoder is the
# second implementation.  Five defects put back into a scratch copy of the
# module must each make this check fail.
#
# Exit 0 all agree, 1 a disagreement, 2 the check could not run.
set -uo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ORACLE_PY="${GTP_ORACLE_PY:-${OTA_ORACLE_PY:-/home/ysl/.ota-oracles/venv/bin/python}}"

if [[ ! -x "$ORACLE_PY" ]]; then
    echo "SKIP	no oracle interpreter at $ORACLE_PY (set GTP_ORACLE_PY)" >&2
    exit 2
fi
if [[ ! -f "$ROOT/modules/11_lte_core.sh" ]]; then
    echo "FAIL	$ROOT/modules/11_lte_core.sh is missing" >&2
    exit 1
fi

rc=0
echo "== GTPv2-C and GTPv1-U vs the clauses and pycrate =="
out=$("$ORACLE_PY" "$ROOT/tools/gtp-oracle/check_gtp_codec.py" --negctl 2>&1)
trc=$?
printf '%s\n' "$out" | grep -E '^(CASES|MISMATCHES|RESULT|NEGCTL|pycrate)' | tail -n 12
if (( trc != 0 )); then
    rc=1
    printf '%s\n' "$out" | grep -E 'MISMATCH|MISSED|ERROR' | head -n 20 >&2
fi

if (( rc == 0 )); then
    echo
    echo "the GTP headers, registries and identities agree with the clauses and pycrate"
fi
exit "$rc"
