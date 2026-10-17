#!/usr/bin/env bash
# TS 102 225 §5.2 Response Packet checks (RPL, RHL, status, CC, response data).
#
# modules/41_ota_sms.sh --parse-resp-sms reads the card's answer to an OTA
# command, but it was only asserted against the module's own selftest -- the
# one implementation it could agree with by accident. Writing this check is how
# the module's selftest vectors were replaced by pySim's: three of its 3DES
# response packets decode to the same status, CC verdict and CompactRemoteResp
# here as in pySim.
#
# check_ota_response.py states the response packet from TS 102 225 table 3 and
# table 4 -- RPL counts from the RHL octet to the end of the response data
# including padding, RHL from the TAR to the end of the RC/CC/DS, RHI is null
# in the SMS form, ciphering covers CNTR..response data and the CC is
# calculated first over the packet up to the response data, UDH included --
# assembles responses with its own 3DES and compares what the module prints,
# field by field. pySim's SMS response decoder is the second implementation.
# Five defects put back into a scratch copy of the module must make it fail.
#
# Exit 0 all agree, 1 a disagreement, 2 the check could not run.
set -uo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ORACLE_PY="${OTA_RESP_ORACLE_PY:-${OTA_ORACLE_PY:-/home/ysl/.ota-oracles/venv/bin/python}}"

if [[ ! -x "$ORACLE_PY" ]]; then
    echo "SKIP	no oracle interpreter at $ORACLE_PY (set OTA_RESP_ORACLE_PY)" >&2
    exit 2
fi
if [[ ! -f "$ROOT/modules/41_ota_sms.sh" ]]; then
    echo "FAIL	$ROOT/modules/41_ota_sms.sh is missing" >&2
    exit 1
fi

rc=0
echo "== TS 102 225 response packet vs the clause and pySim =="
out=$("$ORACLE_PY" "$ROOT/tools/ota-oracle/check_ota_response.py" --negctl 2>&1)
trc=$?
printf '%s\n' "$out" | grep -E '^(CASES|MISMATCHES|RESULT|NEGCTL)' | tail -n 12
if (( trc != 0 )); then
    rc=1
    printf '%s\n' "$out" | grep -E 'MISMATCH|MISSED|SKIP|ERROR' | head -n 20 >&2
fi

if (( rc == 0 )); then
    echo
    echo "the response packet agrees with the clause and pySim"
fi
exit "$rc"
