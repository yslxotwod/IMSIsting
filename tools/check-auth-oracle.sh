#!/usr/bin/env bash
# Check tools/nas_auth_oracle.py against a referee that is not itself.
#
# The cause tables are the one part of the oracle that cannot be checked by
# running it: a table compared against itself agrees with itself.  Wireshark's
# dissectors carry the same two registries -- the EMM causes as Diameter
# RAN-NAS carries them, and the 5GMM causes as the NAS-5GS dissector carries
# them -- so every cause this tree names is compared, by number, against the
# name tshark prints for that number.
#
# Exits 0 only when every tabulated cause agrees AND the tool's own vectors
# pass.  A cause the tool tabulates that tshark does not know is a mismatch;
# a cause tshark knows that the tool does not tabulate is reported as a count,
# because the table claims the authentication-relevant causes, not the whole
# registry.
set -u

cd "$(dirname "$0")/.." || exit 2

TSHARK=${TSHARK:-/usr/bin/tshark}
TOOL=tools/nas_auth_oracle.py

if [ ! -x "$TSHARK" ]; then
  echo "SKIP no tshark at $TSHARK"
  exit 0
fi

tmp=$(mktemp -d) || exit 2
trap 'rm -rf "$tmp"' EXIT

"$TSHARK" -G values 2>/dev/null \
  | awk -F'\t' '$1=="V" && $2=="diameter.3gpp.ran_nas.emm_cause" {print $3"\t"$4}' \
  | sort -n > "$tmp/emm.tsv"

"$TSHARK" -G values 2>/dev/null \
  | awk -F'\t' '$1=="V" && $2=="nas-5gs.mm.5gmm_cause" {print $3"\t"$4}' \
  | sort -n > "$tmp/5gs.tsv"

if [ ! -s "$tmp/emm.tsv" ] || [ ! -s "$tmp/5gs.tsv" ]; then
  echo "FAIL tshark returned no cause registry (emm $(wc -l < "$tmp/emm.tsv"), 5gs $(wc -l < "$tmp/5gs.tsv"))"
  exit 1
fi

python3 - "$tmp" "$TOOL" <<'PY'
import subprocess
import sys

tmp, tool = sys.argv[1], sys.argv[2]

def tshark_table(path):
    table = {}
    with open(path) as handle:
        for line in handle:
            number, _, name = line.rstrip("\n").partition("\t")
            if not number or not name:
                continue
            table[int(number)] = name.strip()
    return table

def tool_table(gen):
    out = subprocess.run([sys.executable, tool, "causes", "--gen", gen],
                         capture_output=True, text=True)
    if out.returncode != 0:
        raise SystemExit("FAIL the tool refused 'causes --gen %s': %s"
                         % (gen, out.stderr.strip()))
    table = {}
    current = {}
    for line in out.stdout.splitlines():
        if not line.strip():
            if "cause" in current and "name" in current:
                table[int(current["cause"])] = current["name"]
            current = {}
            continue
        key, _, value = line.partition("\t")
        current[key] = value
    if "cause" in current and "name" in current:
        table[int(current["cause"])] = current["name"]
    return table

emm = tshark_table(tmp + "/emm.tsv")
fivegs = tshark_table(tmp + "/5gs.tsv")
mine_eps = tool_table("eps")
mine_5gs = tool_table("5gs")

checks = 0
mismatches = []

for gen, mine, referee in (("eps", mine_eps, emm), ("5gs", mine_5gs, fivegs)):
    for number in sorted(mine):
        checks += 1
        theirs = referee.get(number)
        if theirs is None:
            mismatches.append("%s %d: the tool names %r, tshark has no such cause"
                              % (gen, number, mine[number]))
        elif theirs != mine[number]:
            mismatches.append("%s %d: the tool says %r, tshark says %r"
                              % (gen, number, mine[number], theirs))

print("ASSERTION\temm-registry-present\t%s" % ("PASS" if len(emm) >= 30 else "FAIL"))
print("ASSERTION\t5gs-registry-present\t%s" % ("PASS" if len(fivegs) >= 20 else "FAIL"))
print("ASSERTION\tcauses-compared %d\t%s"
      % (checks, "PASS" if not mismatches else "FAIL"))
for line in mismatches:
    print("MISMATCH\t%s" % line)

# The four causes the oracle exists for had better be in both directions.
for number in (2, 20, 21, 23):
    ok = number in mine_eps and number in emm
    print("ASSERTION\temm-%d-known-to-both\t%s" % (number, "PASS" if ok else "FAIL"))
for number in (20, 21):
    ok = number in mine_5gs and number in fivegs
    print("ASSERTION\t5gs-%d-known-to-both\t%s" % (number, "PASS" if ok else "FAIL"))

print("TABULATED\teps %d\tof %d\t5gs %d\tof %d"
      % (len(mine_eps), len(emm), len(mine_5gs), len(fivegs)))

sys.exit(1 if mismatches else 0)
PY
rc=$?
if [ "$rc" -ne 0 ]; then
  echo "RESULT FAIL cause tables disagree with tshark"
  exit "$rc"
fi

python3 "$TOOL" selftest || exit $?
echo "RESULT PASS cause tables agree with tshark; vectors pass"
