#!/usr/bin/env bash
# check-scp03t.sh — is the SCP03t derivation the spec's, or just its own?
#
# SGP.22's profile transport rides SCP03t, which is GlobalPlatform SCP03 with the
# session keys derived by the Annex D 4.1.5 counter-mode KDF. The derivation in
# tools/scp03t.py is one implementation; `cryptography`'s CMAC is the same code
# family as that file, so agreeing with itself proves nothing. This check hands
# the same KDF inputs to `openssl mac ... CMAC` -- an implementation that shares
# no code with this tree -- and compares every derived value.
#
# Exit codes:
#   0  every value matches the outside implementation
#   1  a mismatch (this tree is wrong, or the derivation moved)
#   2  SKIP -- openssl is absent or has no `mac` command. Not a pass: the
#      summary says so, because a suite that reports PASS without its oracle is
#      the failure this script exists to prevent.
#
# Usage: tools/check-scp03t.sh [-v]
set -uo pipefail

ROOT=$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PY="${PYTHON:-python3}"

if ! command -v "$PY" >/dev/null 2>&1; then
    printf 'SKIP\tno %s on PATH\n' "$PY"
    exit 2
fi
if ! command -v openssl >/dev/null 2>&1; then
    printf 'SKIP\topenssl is not on PATH, so no outside CMAC can check the derivation\n'
    exit 2
fi
if ! printf '' | openssl mac -macopt cipher:AES-128-CBC \
        -macopt hexkey:00000000000000000000000000000000 CMAC >/dev/null 2>&1; then
    printf 'SKIP\tthis openssl has no `mac` command; the outside CMAC oracle needs openssl 3\n'
    exit 2
fi

"$PY" "$ROOT/tools/scp03t.py" --selfcheck
rc=$?
case "$rc" in
    0) printf 'RESULT\tPASS\n'; exit 0 ;;
    *) printf 'RESULT\tFAIL(%s)\n' "$rc"; exit 1 ;;
esac
