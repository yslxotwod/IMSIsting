#!/usr/bin/env bash
# SIM identity codec checks (EF_ICCID, EF_IMSI -- TS 31.102 §4.2.1, §4.2.2).
#
# modules/16_sim.sh decodes both records, and each of those decoders carried a
# field that is not in the clause:
#
#   ICCID  a "0x98 marker octet" to skip before the digits. EF_ICCID is ten
#          octets of plain swapped BCD, so 98 68 is the digits 8 9 8 6; the
#          marker shortened every ICCID by two digits and shifted the country,
#          the issuer and the check digit behind it.
#   IMSI   no handling of the parity nibble. The octet after the length byte
#          holds the parity of the digit count in its low nibble and the first
#          digit in its high one, so after the nibble swap the parity is the
#          leading character -- read as a digit, the IMSI 310260123456789
#          became 9310260123456789, which is MCC 931 and "unknown" instead of
#          MCC 310, United States.
#
# check_sim_identity.py states both layouts from the clause, encodes records
# from that statement, and compares what the module decodes; where pySim is
# importable its encoders are the second implementation and must agree. The
# check is two-sided: scratch copies of the module with either defect put back
# must make it fail.
#
# Exit 0 all agree, 1 a disagreement, 2 the check could not run.
set -uo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ORACLE_PY="${SIM_ORACLE_PY:-${OTA_ORACLE_PY:-/home/ysl/.ota-oracles/venv/bin/python}}"

if [[ ! -x "$ORACLE_PY" ]]; then
    echo "SKIP	no oracle interpreter at $ORACLE_PY (set SIM_ORACLE_PY)" >&2
    exit 2
fi
if [[ ! -f "$ROOT/modules/16_sim.sh" ]]; then
    echo "FAIL	$ROOT/modules/16_sim.sh is missing" >&2
    exit 1
fi

rc=0
echo "== SIM identity codecs (EF_ICCID / EF_IMSI) vs the clause and pySim =="
out=$("$ORACLE_PY" "$ROOT/tools/sim-oracle/check_sim_identity.py" --negctl 2>&1)
trc=$?
printf '%s\n' "$out" | grep -E '^(CASES|MISMATCHES|RESULT|NEGCTL)' | tail -n 10
if (( trc != 0 )); then
    rc=1
    printf '%s\n' "$out" | grep -E 'MISMATCH|MISSED|SKIP' | head -n 20 >&2
fi

if (( rc == 0 )); then
    echo
    echo "all SIM identity checks agree with the clause and pySim"
fi
exit "$rc"
