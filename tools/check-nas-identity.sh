#!/usr/bin/env bash
# Referee for tools/nas_identity.py: pycrate encodes the same element and
# tshark dissects the same octets inside an S1AP InitialUEMessage.
set -uo pipefail

here="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd -P "$here/.." && pwd)"
py="${NAS_ORACLE_PY:-${LTE_ORACLE_PY:-/home/ysl/.lte-oracles/venv/bin/python}}"

if [[ ! -x "$py" ]]; then
    printf 'ASSERTION\tinterpreter\tSKIP\t%s is not executable\n' "$py"
    printf 'RESULT\tSKIP no pycrate interpreter; nothing was compared\n'
    exit 0
fi

rc=0
"$py" "$here/nas-oracle/check_nas_identity.py" --negctl || rc=$?
printf '\n'
python3 "$here/nas_identity.py" selftest || rc=$?
exit "$rc"
