#!/usr/bin/env bash
# Check the NAS messages `32_nas_signaling --build-nas` builds against an
# outside implementation.
#
# Why this exists: a builder that only agrees with itself is exactly the class
# of defect this tree has had to repair twice -- a hand-rolled decoder that
# sliced hex at fixed offsets, and a set of message tables whose assertions
# carried the same wrong values as the code. So every EPS vector is built by
# the module's own CLI, wrapped in a GSMTAP LTE NAS packet, and decoded by
# tshark; what tshark calls the message and its IEs is what the module claimed.
#
# Exit codes:
#   0  every EPS vector decodes as claimed
#   1  a mismatch (the module is wrong, or the oracle moved)
#   2  SKIP -- tshark is absent. Not a pass: the summary says so.
#
# The 5GS vectors are reported UNVERIFIED by the checker, with the reason: no
# GSMTAP payload type carries 5G NAS in Wireshark 4.2.2 and `nas-5gs` cannot be
# bound to a UDP port, so the 5GS message type numbers rest on tshark's own
# value table rather than on a decoded message.
#
# Usage: tools/check-nas-vectors.sh [-v]
set -uo pipefail

ROOT=$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PY="${PYTHON:-python3}"

if ! command -v "$PY" >/dev/null 2>&1; then
    printf 'SKIP\tno %s on PATH\n' "$PY"
    exit 2
fi
if ! command -v tshark >/dev/null 2>&1; then
    printf 'SKIP\ttshark is not on PATH, so no outside implementation can decode the built messages\n'
    exit 2
fi

"$PY" "$ROOT/tools/nas-oracle/check_nas_built.py" "$@"
rc=$?
case "$rc" in
    0|1|2) exit "$rc" ;;
    *)     exit 1 ;;
esac
