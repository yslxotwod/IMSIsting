#!/usr/bin/env bash
# Diameter / S6a-S6d codec checks (RFC 6733 §3, §4, §7.1; TS 29.272 §7).
#
# modules/11_lte_core.sh reads an HSS-facing protocol, so a wrong registry row
# or a wrong AVP number is not cosmetics: the analyst reads a subscriber
# identity, a cancellation type or a result code out of it, and a forged
# request that names the wrong AVP is a request the HSS ignores.
#
# check_diameter_codec.py states the clauses -- the 20-octet header and its
# flag bits, the AVP layout with the vendor form and the padding, TS 29.272's
# application identifier, command codes and AVP registry, TS 29.230's 3GPP
# registries, and the result codes of RFC 6733 §7.1 against the 3GPP ones of
# TS 29.272 §7.4 -- builds the messages from that statement, and compares
# what the module prints field by field.  Every AVP code, application
# identifier and command code in the registries is swept, and the three
# forged requests are decoded back to the AVPs the clause requires.  Wireshark
# (its Diameter dissector and its dictionaries) is the second implementation.
# Five defects put back into a scratch copy of the module must each make this
# check fail.
#
# Exit 0 all agree, 1 a disagreement, 2 the check could not run.
set -uo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ORACLE_PY="${DIAMETER_ORACLE_PY:-${OTA_ORACLE_PY:-/home/ysl/.ota-oracles/venv/bin/python}}"

if [[ ! -x "$ORACLE_PY" ]]; then
    echo "SKIP	no oracle interpreter at $ORACLE_PY (set DIAMETER_ORACLE_PY)" >&2
    exit 2
fi
if [[ ! -f "$ROOT/modules/11_lte_core.sh" ]]; then
    echo "FAIL	$ROOT/modules/11_lte_core.sh is missing" >&2
    exit 1
fi

rc=0
echo "== Diameter and S6a/S6d vs the clauses and Wireshark =="
out=$("$ORACLE_PY" "$ROOT/tools/diameter-oracle/check_diameter_codec.py" --negctl 2>&1)
trc=$?
printf '%s\n' "$out" | grep -E '^(CASES|MISMATCHES|RESULT|NEGCTL|tshark	NOTE)' | tail -n 14
if (( trc != 0 )); then
    rc=1
    printf '%s\n' "$out" | grep -E 'MISMATCH|MISSED|FAIL|ERROR' | head -n 20 >&2
fi

if (( rc == 0 )); then
    echo
    echo "the Diameter header, AVP registry, S6a/S6d commands and result codes agree"
fi
exit "$rc"
