#!/usr/bin/env bash
# IKEv2 and EAP-AKA checks for modules/36_vowifi.sh
# (RFC 7296 §3.1-§3.3; RFC 4187 §8.1, §11; RFC 9048 §8.2).
#
# VoWiFi is IKEv2 to an ePDG, and the identity that rides in it is an IMSI.
# A capture is unreadable without the payload chain, the SA proposals and the
# EAP-AKA exchange, so the module has to decode those three layers to the
# clause, not to a memory of them.
#
# check_vowifi_codec.py states the clauses -- the header of RFC 7296 3.1, the
# generic payload header of 3.2, the SA/proposal/transform bodies of 3.3.1 and
# 3.3.2, the EAP-AKA packet and subtypes of RFC 4187 8.1 and 11, and the
# AT_KDF_INPUT / AT_KDF / AT_BIDDING attributes RFC 9048 8.2 defines -- then
# compares what the module decodes with the IANA registry rows and with
# Wireshark's dissector on frames built from the same clause text. Seven
# defects put back into a scratch copy must each make it fail.
#
# Exit 0 all agree, 1 a disagreement, 2 the check could not run.
set -uo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ORACLE_PY="${VOWIFI_ORACLE_PY:-${SBA_ORACLE_PY:-${OTA_ORACLE_PY:-/home/ysl/.ota-oracles/venv/bin/python}}}"

if [[ ! -x "$ORACLE_PY" ]]; then
    echo "SKIP	no oracle interpreter at $ORACLE_PY (set VOWIFI_ORACLE_PY)" >&2
    exit 2
fi
if [[ ! -f "$ROOT/modules/36_vowifi.sh" ]]; then
    echo "FAIL	$ROOT/modules/36_vowifi.sh is missing" >&2
    exit 1
fi

rc=0
echo "== IKEv2 and EAP-AKA vs the clauses, the registry and Wireshark =="
out=$("$ORACLE_PY" "$ROOT/tools/vowifi-oracle/check_vowifi_codec.py" \
      --module "$ROOT/modules/36_vowifi.sh" --negctl 2>&1)
trc=$?
printf '%s\n' "$out" | grep -E '^(NOTE|CASES|MISMATCHES|RESULT)'
printf '%s\n' "$out" | grep -E '^NEGCTL-CAUGHT' 
if (( trc != 0 )); then
    rc=1
    printf '%s\n' "$out" | grep -E 'MISMATCH|MISSED|FAIL|ERROR' | head -n 20 >&2
fi

if (( rc == 0 )); then
    echo
    echo "the IKEv2 payload chain, SA bodies and EAP-AKA attributes agree"
fi
exit "$rc"
