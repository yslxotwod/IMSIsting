#!/usr/bin/env bash
# TS 31.115 §4.2 secured packet checks (CPL, CHL, SPI, KIc, KID, CC, cipher).
#
# modules/41_ota_sms.sh --packet-sms builds the packet the SPI asks for and
# --parse-packet-sms undoes it, but both were only asserted against the
# module's own selftest. Writing this check found two things the selftest
# could not: the packet's hex fields came out in two cases at once (the header
# and the keys upper, the cipher text and the CC lower, because xxd prints
# lower), and --parse-packet-sms echoed the input case for some fields but not
# others.
#
# check_ota_packet.py states the packet from TS 102 225 table 1 and TS 31.115
# §4.2 -- CPL counts from the CHL octet to the end of the secured data, CHL
# counts from the SPI to the end of the RC/CC/DS -- assembles it with its own
# DES3 and compares what the module emits, field by field and byte for byte;
# pySim's TS 31.115 encoder and its CC signer are the second implementation.
# Four defects put back into a scratch copy of the module must make it fail.
#
# pySim's own encoder drops the two CPL octets when the packet is not
# ciphered, while its decoder always reads them -- encoder and decoder
# disagree there -- so the comparison against pySim folds the CPL out for
# those cases and says so.
#
# Exit 0 all agree, 1 a disagreement, 2 the check could not run.
set -uo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ORACLE_PY="${OTA_PACKET_ORACLE_PY:-${OTA_ORACLE_PY:-/home/ysl/.ota-oracles/venv/bin/python}}"

if [[ ! -x "$ORACLE_PY" ]]; then
    echo "SKIP	no oracle interpreter at $ORACLE_PY (set OTA_PACKET_ORACLE_PY)" >&2
    exit 2
fi
if [[ ! -f "$ROOT/modules/41_ota_sms.sh" ]]; then
    echo "FAIL	$ROOT/modules/41_ota_sms.sh is missing" >&2
    exit 1
fi

rc=0
echo "== TS 31.115 secured command packet vs the clause and pySim =="
out=$("$ORACLE_PY" "$ROOT/tools/ota-oracle/check_ota_packet.py" --negctl 2>&1)
trc=$?
printf '%s\n' "$out" | grep -E '^(CASES|MISMATCHES|RESULT|NEGCTL)' | tail -n 12
if (( trc != 0 )); then
    rc=1
    printf '%s\n' "$out" | grep -E 'MISMATCH|MISSED|SKIP|ERROR' | head -n 20 >&2
fi

if (( rc == 0 )); then
    echo
    echo "the secured packet agrees with the clause and pySim"
fi
exit "$rc"
