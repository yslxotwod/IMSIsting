#!/usr/bin/env bash
# SIP (RFC 3261) builder checks for modules/30_volte_ims.sh.
#
# One check, two independent readers:
#
#   1. check_sip_build.py -- re-derives the invariants from the emitted bytes
#      with code that shares nothing with the module (CRLF endings, one
#      header/body separator, the mandatory headers, Content-Length equal to
#      the body) and compares every field tshark's SIP dissector reports
#      against what we asked the builder to put there. Four message kinds plus
#      the spoofed REGISTER the module sends on its own.
#
#   2. A control: a message that passed both readers is broken six ways -- LF
#      endings, no Via, a short Content-Length, a duplicated Content-Length, no
#      separator, and a note printed after an honest Content-Length: 0 -- and
#      each break has to be caught. The last one is the defect this check was
#      written for: the module used to put a diagnostics line in the datagram.
#
# tshark is the third party; without it the check cannot run and says so
# (exit 2) rather than passing silently.
#
# Exit 0 all agree, 1 a disagreement, 2 the check could not run.
set -uo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v tshark >/dev/null 2>&1; then
    echo "SKIP	no tshark (apt install tshark); it is the independent dissector" >&2
    exit 2
fi
if [[ ! -f "$ROOT/tools/sip-oracle/check_sip_build.py" ]]; then
    echo "FAIL	tools/sip-oracle/check_sip_build.py is missing" >&2
    exit 1
fi

echo "== SIP builder vs tshark, and vs the bytes =="
out=$(python3 "$ROOT/tools/sip-oracle/check_sip_build.py" 2>&1)
rc=$?
printf '%s\n' "$out" | tail -n 4
exit "$rc"
