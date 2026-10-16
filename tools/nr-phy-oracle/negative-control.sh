#!/usr/bin/env bash
#
# Negative control for tools/nr-phy-oracle/cmp_nr_sync.py.
#
# A check that has never failed has not been shown to be able to fail. This
# script takes modules/12_nr_air.sh, puts the ORIGINAL LTE-STYLE SSS BACK
# into a scratch copy -- the seeding bug this oracle was written to catch --
# and requires the comparator to reject it.
#
# The bug, exactly as it was: nair_sss_sequence() seeded x0 with the PSS
# initialisation [0 1 1 0 1 1 1] and x1 all-ones, and gave x1 x0's tap
# (i+4, i) instead of its own (i+1, i). That is TS 36.211 6.11.2.1 (LTE)
# applied to a TS 38.211 7.4.2.3 (NR) clause. It produced a well-formed
# 127-chip +/-1 sequence that disagreed with the clause for every one of
# the 1008 cell identities, and the module's own selftest passed anyway,
# because generator and vector came from the same misreading.
#
# If this script stops failing -- because the comparator cannot see the
# reintroduced bug, or because the substitution below no longer matches --
# it says so and exits non-zero. Silence is not success here.
#
# Usage:  ./tools/nr-phy-oracle/negative-control.sh [python]
#
#   python   interpreter to run the comparator with (default: pick the
#            venv if one exists, else python3). py3gpp is NOT required:
#            the spec reference alone catches this bug.

set -uo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SRC="$ROOT/modules/12_nr_air.sh"
CMP="$ROOT/tools/nr-phy-oracle/cmp_nr_sync.py"
WORK="${TMPDIR:-/tmp}/imsisting-nr-negctl.$$"
N="${1:-30}"          # cell identities to feed it; enough to fail loudly

cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

[[ -f "$SRC" ]] || { printf 'error: module missing: %s\n' "$SRC" >&2; exit 2; }
[[ -f "$CMP" ]] || { printf 'error: comparator missing: %s\n' "$CMP" >&2; exit 2; }

mkdir -p "$WORK" || exit 2
DOCTORED="$WORK/12_nr_air.lte-sss.sh"

# Interpreter: same precedence as tools/check-nr-phy-oracle.sh, so the
# negative control exercises the path the real run uses.
VENV="${TMPDIR:-/tmp}/imsisting-nr-phy-oracle/venv"
if [[ -x "$VENV/bin/python" ]]; then PY="$VENV/bin/python"; else PY="python3"; fi

printf '== NR PHY oracle negative control\n'
printf '   source : %s\n' "$SRC"
printf '   scratch: %s\n' "$DOCTORED"
printf '   python : %s\n\n' "$PY"

# ── reintroduce the bug, and prove we actually reintroduced it ──────────
python3 - "$SRC" "$DOCTORED" <<'PYEOF'
import sys

src, dst = sys.argv[1], sys.argv[2]
text = open(src, encoding="utf-8").read()

# The two seeding blocks, as they appear when correct.
wrong_x0 = (
    "        x0[0]=0; x0[1]=1; x0[2]=1; x0[3]=0; x0[4]=1; x0[5]=1; x0[6]=1\n"
)
right_x0 = (
    "        x0[0]=1\n"
    "        for (i = 1; i < 7; i++) x0[i] = 0\n"
)
wrong_x1 = (
    "        x1[0]=1; x1[1]=1; x1[2]=1; x1[3]=1; x1[4]=1; x1[5]=1; x1[6]=1\n"
    "        for (i = 0; i <= 119; i++) x1[i+7] = (x1[i+4] + x1[i]) % 2\n"
)
right_x1 = (
    "        x1[0]=1\n"
    "        for (i = 1; i < 7; i++) x1[i] = 0\n"
    "        for (i = 0; i <= 119; i++) x1[i+7] = (x1[i+1] + x1[i]) % 2\n"
)

# Only touch the SSS function; a stray match elsewhere would mean these
# strings are no longer unique to the place we think they are.
start = text.find("nair_sss_sequence() {")
if start < 0:
    sys.exit("negative-control: nair_sss_sequence() not found in %s" % src)
end = text.find("\n}\n", start)
if end < 0:
    sys.exit("negative-control: end of nair_sss_sequence() not found")
end += len("\n}\n")

body = text[start:end]
for right, wrong, label in (
    (right_x0, wrong_x0, "x0 initialisation"),
    (right_x1, wrong_x1, "x1 initialisation and tap"),
):
    n = body.count(right)
    if n != 1:
        sys.exit(
            "negative-control: the correct %s block appears %d times in "
            "nair_sss_sequence(), expected exactly 1.\n"
            "The function has been edited; update the anchors in this "
            "negative control so it still reintroduces the real bug."
            % (label, n)
        )
    body = body.replace(right, wrong)

open(dst, "w", encoding="utf-8").write(text[:start] + body + text[end:])
print("   reintroduced: LTE seeding (x0=PSS init, x1=all ones, x1 tap i+4)")
PYEOF
rc=$?
[[ $rc -eq 0 ]] || { printf '\nnegative-control: could not build the doctored module\n' >&2; exit 2; }

# ── the doctored module must be rejected ────────────────────────────────
printf '\n-- running the comparator against the doctored module\n\n'
out="$("$PY" "$CMP" --module "$DOCTORED" --limit "$N" 2>&1)"
rc=$?
printf '%s\n' "$out"

printf '\n'
if [[ $rc -eq 0 ]]; then
    printf 'NEGATIVE CONTROL: FAIL -- the comparator ACCEPTED a module with the\n'
    printf '  LTE SSS seeding bug. The oracle cannot see the bug it exists to\n'
    printf '  catch, so its pass on the real module means nothing.\n' >&2
    exit 1
fi
if ! printf '%s' "$out" | grep -q 'MISMATCHES: [1-9]'; then
    printf 'NEGATIVE CONTROL: FAIL -- comparator exited %d but reported no\n' "$rc"
    printf '  mismatch. Check whether it failed for an unrelated reason.\n' >&2
    exit 1
fi

printf 'NEGATIVE CONTROL: PASS -- the comparator rejects the reintroduced\n'
printf '  LTE SSS seeding bug, so its pass on the real module is meaningful.\n'
exit 0
