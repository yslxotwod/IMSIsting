#!/usr/bin/env bash
# HPACK and HTTP/2 framing checks for modules/40_sba_pivot.sh
# (RFC 7541 §2.3, §4, §5.1, §5.2, §6, Appendix A/B; RFC 7540 §6.2, §6.10).
#
# The SBI is HTTP/2 JSON, and every request on it starts with a HEADERS frame
# whose header block is HPACK-compressed. Without HPACK a capture shows the
# frame type and nothing else: not the :path that names the service, not the
# authorization that says whose token it carries. So the module has to decode
# the header block, and the decoding has to be the clause's, not a guess.
#
# check_hpack.py states the clauses -- the static table of Appendix A, the
# Huffman codes of Appendix B, the integer and string encodings of §5, the
# four representations and the dynamic table of §4 and §6, and the padding
# and priority fields of RFC 7540 §6.2/§6.10 -- and compares what the module
# decodes with the `hpack` library on the same block, plus the Appendix C
# examples. Six defects put back into a scratch copy must each make it fail.
#
# Exit 0 all agree, 1 a disagreement, 2 the check could not run.
set -uo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ORACLE_PY="${SBA_ORACLE_PY:-${OTA_ORACLE_PY:-/home/ysl/.ota-oracles/venv/bin/python}}"

if [[ ! -x "$ORACLE_PY" ]]; then
    echo "SKIP	no oracle interpreter at $ORACLE_PY (set SBA_ORACLE_PY)" >&2
    exit 2
fi
if ! "$ORACLE_PY" -c 'import hpack' >/dev/null 2>&1; then
    echo "SKIP	the oracle interpreter has no hpack module (pip install hpack)" >&2
    exit 2
fi
if [[ ! -f "$ROOT/modules/40_sba_pivot.sh" ]]; then
    echo "FAIL	$ROOT/modules/40_sba_pivot.sh is missing" >&2
    exit 1
fi

rc=0
echo "== HPACK and HTTP/2 framing vs the clauses and hpack =="
out=$("$ORACLE_PY" "$ROOT/tools/sba-oracle/check_hpack.py" --module "$ROOT/modules/40_sba_pivot.sh" --negctl 2>&1)
trc=$?
printf '%s\n' "$out" | grep -E '^(CASES|MISMATCHES|RESULT|NEGCTL|NOTE)' | tail -n 14
if (( trc != 0 )); then
    rc=1
    printf '%s\n' "$out" | grep -E 'MISMATCH|MISSED|FAIL|ERROR' | head -n 20 >&2
fi

if (( rc == 0 )); then
    echo
    echo "the HPACK static table, Huffman codes, representations and frames agree"
fi
exit "$rc"
