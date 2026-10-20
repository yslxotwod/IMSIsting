#!/usr/bin/env bash
#
# tools/check-umts-phy.sh -- known-answer and invariant checks for
# tools/umts_phy.py.
#
# Why this exists: a spreading/scrambling generator is the easiest place in
# this tree to commit the mistake docs/SESSION_HANDOFF.md 16 records -- a wrong
# tap, a wrong code index or a wrong phase all give output of the right length,
# the right modulation and the wrong sequence. So every expected value below is
# either TRANSCRIBED FROM THE STANDARD or labelled for what it is:
#
#   known answer   a vector the clause prints, re-transcribed into this file
#                  from the clause text rather than imported from the tool, so
#                  a typo in either file is caught by the other:
#                    TS 25.213 4.3.1.1 Figure 4   OVSF Cch,2,k and Cch,4,k
#                    TS 25.213 5.2.3.1             the PSC's a sequence and
#                                                  its 16 block signs, the b
#                                                  sequence and the z block
#                                                  signs, H8 by recursion
#                    TS 25.213 5.2.3.2 Table 4     groups 0, 3, 63
#                    TS 25.211 5.3.3.1 Figure 13, 5.3.3.5 Figure 18
#                    TS 25.213 5.2                  38400 chips/frame from
#                                                  2560 chips/slot x 15 slots
#                  The clause defines the scrambling code by two bit recursions
#                  and prints no chips of it, and no third-party table of those
#                  chips is quotable here, so there is no external chip vector
#                  for it and this file does not pretend there is one. Its
#                  checks are the cross-check below instead.
#
#   cross-check    the scrambling code and the 16 SSCs are recomputed by a
#                  second implementation written here from the same clause,
#                  without numpy and without importing the tool's helpers, and
#                  compared chip by chip. That catches a wrong tap, a wrong
#                  phase offset, a wrong Hadamard row or a wrong index -- but
#                  it is one reading of the clause against another, so those
#                  cases are labelled `xc`, never `known-answer`.
#
#   invariant      properties the clause fixes but does not enumerate: x and y
#                  are maximal-length sequences of the printed polynomials (the
#                  cycle closes after 2^18-1 clocks, which only happens with the
#                  right taps), the complex code is drawn from {+-1+-j}, the
#                  emitted pattern repeats every 38400 chips, the descrambled
#                  pilot is one constant symbol, OVSF codes at one SF are
#                  mutually orthogonal, and the file sizes are the container
#                  sizes. Labelled `invariant`.
#
#   negation       the last block corrupts a copy of the generator and requires
#                  the comparison code that passes above to FAIL on it. A suite
#                  that cannot fail proves nothing; this is the control that
#                  shows it can. See the comment there.
#
# Exit: 0 every check passed, 1 a check failed, 2 cannot run (no python3, no
# numpy -- reported as SKIP, never as a pass).
#
set -u

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
TOOL="$HERE/umts_phy.py"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/check-umts-phy.XXXXXX") || exit 2
trap 'rm -rf "$WORK"' EXIT

NTOT=0
NPASS=0
NBAD=0

chk() {
    local n="$1" got="$2" want="$3"
    NTOT=$((NTOT + 1))
    if [[ "$got" == "$want" ]]; then
        printf '%s\tPASS\n' "$n"
        NPASS=$((NPASS + 1))
    else
        printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"
        NBAD=$((NBAD + 1))
    fi
}

# One TSV row the tool printed: `tsv <file> <key>`.
tsv() {
    awk -F'\t' -v k="$2" '$1 == k { print $2; exit }' "$1"
}

# Run the tool, keep code and both streams so a case can assert rc/ERROR/WHY.
run() {
    local out="$1"
    shift
    python3 "$TOOL" "$@" >"$WORK/$out.tsv" 2>"$WORK/$out.err"
    printf '%s' "$?"
}

# Cases produced by the helper scripts below arrive as name<TAB>got<TAB>want,
# so the pass/fail arithmetic stays in chk() and the reporting is uniform.
consume() {
    local f="$1"
    local n g w seen=0
    if [[ ! -s "$f" ]]; then
        chk "$(basename "$f" .tsv)-emitted" missing present
        return
    fi
    while IFS=$'\t' read -r n g w; do
        [[ -z "$n" ]] && continue
        chk "$n" "$g" "$w"
        seen=1
    done <"$f"
    [[ $seen -eq 1 ]] || chk "$(basename "$f" .tsv)-emitted" empty present
}

# A helper that dies must fail loudly instead of silently passing.
helper() {
    local out="$1"
    shift
    python3 "$@" >"$WORK/$out.tsv" 2>"$WORK/$out.err"
    if [[ -s "$WORK/$out.err" ]]; then
        chk "helper-$out-ran" "$(head -1 "$WORK/$out.err")" ok
    fi
    consume "$WORK/$out.tsv"
}

skip_all() {
    printf 'SKIP\t%s\n' "$1"
    printf 'RESULT\tSKIP\n'
    exit 2
}

command -v python3 >/dev/null 2>&1 || skip_all "no python3 on PATH"
python3 -c 'import numpy' >/dev/null 2>&1 ||
    skip_all "numpy is not importable: umts_phy.py needs it, so nothing was tested (this is not a pass)"
[[ -f "$TOOL" ]] || skip_all "tools/umts_phy.py not found next to this script"

# ---------------------------------------------------------------------------
# the second implementation: one reading of the clause, written here
# ---------------------------------------------------------------------------

cat >"$WORK/ref.py" <<'PY'
"""Reference transcription of TS 25.213 5.2.2/5.2.3 and 5.2.3.1.

No numpy, no import of the tool: the point is a second reading of the same
clause. Every literal is copied from the clause text, not from
tools/umts_phy.py.
"""

# TS 25.213 5.2.3.1 prints a in full, then the 16 block signs of
# Cpsc = (1+j) <a, a, a, -a, -a, a, -a, -a, a, a, a, -a, a, -a, a, a>.
A = (1, 1, 1, 1, 1, 1, -1, -1, 1, -1, 1, -1, 1, -1, -1, 1)
PSC_BLOCKS = (1, 1, 1, -1, -1, 1, -1, -1, 1, 1, 1, -1, 1, -1, 1, 1)
# b = <a_1..a_8, -a_9..-a_16> and z = <b, b, b, -b, b, b, -b, -b, b, -b, b,
# -b, -b, -b, -b, -b> (5.2.3.1).
B = (1, 1, 1, 1, 1, 1, -1, -1, -1, 1, -1, 1, -1, 1, 1, -1)
SSC_BLOCKS = (1, 1, 1, -1, 1, 1, -1, -1, 1, -1, 1, -1, -1, -1, -1, -1)
# TS 25.213 5.2.3.2 Table 4, groups 0, 3 and 63 in full (SSC numbers 1..16).
GROUP0 = (1, 1, 2, 8, 9, 10, 15, 8, 10, 16, 2, 7, 15, 7, 16)
GROUP1 = (1, 1, 5, 16, 7, 3, 14, 16, 3, 10, 5, 12, 14, 12, 10)
GROUP63 = (9, 12, 10, 15, 13, 14, 9, 14, 15, 11, 11, 13, 12, 16, 10)

L = (1 << 18) - 1          # 2^18 - 1 = 262143, the Gold period (5.2.3)
Q_OFFSET = 131072          # S_dl,n(i) = Z_n(i) + j Z_n(i + 131072)


def psc():
    """Cpsc, 256 chips, from the printed a sequence and block signs."""
    return [(1 + 1j) * A[k % 16] * PSC_BLOCKS[k // 16] for k in range(256)]


def hadamard(rows):
    """H_k by the recursion in 5.2.3.1, as raw lists of +-1."""
    h = [[1]]
    while len(h) < rows:
        h = [r + r for r in h] + [r + [-v for v in r] for r in h]
    return h


def ssc():
    """Cssc,k for k = 1..16: (1+j) * <h_m(i) * z(i)>, m = 16*(k-1)."""
    z = [B[i % 16] * SSC_BLOCKS[i // 16] for i in range(256)]
    h = hadamard(256)
    return [[(1 + 1j) * h[16 * (k - 1)][i] * z[i] for i in range(256)]
            for k in range(1, 17)]


_GOLD = None


def gold():
    """x and y exactly as 5.2.2 states them: bit recursions, both mod 2.

    Memoised because every case that needs the code needs the same 262143-bit
    pair, and rebuilding it per case is what made this script slow.
    """
    global _GOLD
    if _GOLD is None:
        _GOLD = _build_gold()
    return _GOLD


def _build_gold():
    x = [0] * L
    y = [1] * L
    x[0] = 1
    for i in range(L - 18):
        x[i + 18] = x[i + 7] ^ x[i]
        y[i + 18] = y[i + 10] ^ y[i + 7] ^ y[i + 5] ^ y[i]
    return x, y


def scrambling(psc_number, chips):
    """S_dl,n(i) = Z_n(i) + j Z_n((i + 131072) mod 2^18-1), n = 16*psc."""
    n = 16 * psc_number
    x, y = gold()
    out = []
    for i in range(chips):
        zi = x[(i + n) % L] ^ y[i]
        zq = x[(i + n + Q_OFFSET) % L] ^ y[i]
        out.append((1 - 2 * zi) + 1j * (1 - 2 * zq))
    return out


def agree(got, want, tol=1e-4):
    """Chips that match; a count, never an exception."""
    if len(got) != len(want):
        return 0
    return sum(1 for a, b in zip(got, want) if abs(complex(a) - complex(b)) <= tol)


def as_int(seq):
    """+1/-1 from a sequence of real numbers (the tool may return floats)."""
    return [1 if float(v) > 0 else -1 for v in seq]
PY

# ---------------------------------------------------------------------------
# 1. discovery: what the tool says it can and cannot generate
# ---------------------------------------------------------------------------

rc=$(run list list)
chk "list-exits-0" "$rc" "0"
for row in "carrier:p-cpich" "carrier:sch" "carrier:both" \
           "limit:pulse-shaping" "limit:amplitude" \
           "refused:p-ccpch" "refused:s-cpich" "refused:dpch"; do
    chk "list-names-$row" "$(grep -c "^${row}"$'\t' "$WORK/list.tsv")" "1"
done
chk "list-limit-rows" "$(grep -c '^limit:' "$WORK/list.tsv")" "4"
chk "list-refused-rows" "$(grep -c '^refused:' "$WORK/list.tsv")" "4"

rc=$(run missout gen --carrier p-cpich)
chk "usage-missing-out-rc" "$rc" "2"
chk "usage-missing-out-error" "$(grep -c '^ERROR'$'\t' "$WORK/missout.err")" "1"

rc=$(run badcarrier gen --carrier qpsk --out "$WORK/x.bin")
chk "usage-bad-carrier-rc" "$rc" "2"
chk "usage-bad-carrier-why" "$(grep -c '^WHY'$'\t' "$WORK/badcarrier.err")" "1"

rc=$(run badfmt gen --carrier p-cpich --out "$WORK/x.bin" --format cs16)
chk "usage-bad-format-rc" "$rc" "2"

rc=$(run badrate gen --carrier p-cpich --out "$WORK/x.bin" --rate 3840001)
chk "usage-odd-rate-rc" "$rc" "2"
chk "usage-odd-rate-why-resampler" \
    "$(grep -ci 'resampl' "$WORK/badrate.err")" "1"

rc=$(run badchip gen --carrier p-cpich --out "$WORK/x.bin" --chip-rate 7680000)
chk "usage-other-chip-rate-rc" "$rc" "2"
chk "usage-other-chip-rate-why-25.213" \
    "$(grep -c '25\.213' "$WORK/badchip.err")" "1"

rc=$(run badpsc gen --carrier p-cpich --out "$WORK/x.bin" --psc 512)
chk "usage-psc-out-of-range-rc" "$rc" "2"

rc=$(run badsecs gen --carrier sch --out "$WORK/x.bin" --rate 8 \
         --seconds 0.0100005)
chk "usage-part-chip-seconds-rc" "$rc" "2"

# A refused component must name itself: ERROR and WHY, rc 2, and no file.
for carrier in s-cpich p-ccpch dpch hs-dsch; do
    rc=$(run "ref" gen --carrier "$carrier" --out "$WORK/ref-$carrier.bin")
    chk "refused-$carrier-rc" "$rc" "2"
    chk "refused-$carrier-error" \
        "$(grep -c '^ERROR'$'\t' "$WORK/ref.err")" "1"
    chk "refused-$carrier-why" "$(grep -c '^WHY'$'\t' "$WORK/ref.err")" "1"
    chk "refused-$carrier-no-file" \
        "$([[ -e "$WORK/ref-$carrier.bin" ]] && echo wrote || echo absent)" \
        "absent"
done

# ---------------------------------------------------------------------------
# 2. known answer: the OVSF code tree -- TS 25.213 4.3.1.1, Figure 4
# ---------------------------------------------------------------------------

cat >"$WORK/ovsf_cases.py" <<'PY'
import importlib.util
import sys

sys.path.insert(0, sys.argv[2])
import ref                                # noqa: E402

spec = importlib.util.spec_from_file_location("umts_phy_t1", sys.argv[1])
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


def emit(name, got, want):
    sys.stdout.write("%s\t%s\t%s\n" % (name, got, want))


# Figure 4 prints these six code words in full.
FIG4 = (
    ("cch2-0", 2, 0, (1, 1)),
    ("cch2-1", 2, 1, (1, -1)),
    ("cch4-0", 4, 0, (1, 1, 1, 1)),
    ("cch4-1", 4, 1, (1, 1, -1, -1)),
    ("cch4-2", 4, 2, (1, -1, 1, -1)),
    ("cch4-3", 4, 3, (1, -1, -1, 1)),
)
for name, sf, k, want in FIG4:
    got = ref.as_int(tool.ovsf(sf, k))
    n = sum(1 for a, b in zip(got, want) if a == b)
    emit("known-answer-ovsf-" + name, "%d/%d" % (n, len(want)),
         "%d/%d" % (len(want), len(want)))

# The printed recurrence: Cch,2(n+1),2r = (Cch,2n,r, Cch,2n,r) and
# Cch,2(n+1),2r+1 = (Cch,2n,r, -Cch,2n,r). Checked at two arbitrary parents,
# because a tree that is right at SF 2 and 4 can still be wrong at SF 128.
for parent_sf, r in ((8, 5), (64, 37)):
    up = ref.as_int(tool.ovsf(parent_sf, r))
    even = ref.as_int(tool.ovsf(parent_sf * 2, 2 * r))
    odd = ref.as_int(tool.ovsf(parent_sf * 2, 2 * r + 1))
    want_even = up + up
    want_odd = up + [-v for v in up]
    emit("invariant-ovsf-parent-%d-%d-even" % (parent_sf, r),
         "%d/%d" % (sum(1 for a, b in zip(even, want_even) if a == b),
                    len(want_even)), "%d/%d" % (len(want_even), len(want_even)))
    emit("invariant-ovsf-parent-%d-%d-odd" % (parent_sf, r),
         "%d/%d" % (sum(1 for a, b in zip(odd, want_odd) if a == b),
                    len(want_odd)), "%d/%d" % (len(want_odd), len(want_odd)))

# The two codes the standard fixes by name (TS 25.213 5.2.1): P-CPICH is
# Cch,256,0 -- all ones -- and P-CCPCH is Cch,256,1, the first half +1 and the
# second half -1.
lone = ref.as_int(tool.ovsf(256, 0))
emit("known-answer-cch256-0-all-ones",
     "%d/256" % sum(1 for v in lone if v == 1), "256/256")
second = ref.as_int(tool.ovsf(256, 1))
want = [1] * 128 + [-1] * 128
emit("known-answer-cch256-1-half-negated",
     "%d/256" % sum(1 for a, b in zip(second, want) if a == b), "256/256")

# invariant: every code at one SF is orthogonal to every other code at that SF
# (a property of the tree, not a table). The Gram matrix is one product, so the
# test costs milliseconds instead of a Python double loop.
import numpy as np

gram = np.array([ref.as_int(tool.ovsf(256, k)) for k in range(256)],
                dtype=np.int32)
g = gram @ gram.T
off = np.abs(g[~np.eye(256, dtype=bool)])
emit("invariant-ovsf-orthogonal-sf256-worst-overlap", str(int(off.max())), "0")
emit("invariant-ovsf-diagonal-is-sf",
     "%d distinct/%d" % (len(set(np.diag(g).tolist())), int(np.diag(g)[0])),
     "1 distinct/256")
emit("invariant-ovsf-length-cch256-7", str(len(tool.ovsf(256, 7))), "256")

# A code index out of range must be refused, not wrapped: Cch,4,k has k < 4.
try:
    tool.ovsf(4, 4)
    emit("invariant-ovsf-rejects-k4-at-sf4", "accepted", "refused")
except (ValueError, IndexError):
    emit("invariant-ovsf-rejects-k4-at-sf4", "refused", "refused")
PY

helper ovsf "$WORK/ovsf_cases.py" "$TOOL" "$WORK"

# ---------------------------------------------------------------------------
# 3. known answer: P-SCH and S-SCH -- TS 25.213 5.2.3.1 and Table 4
# ---------------------------------------------------------------------------

cat >"$WORK/sch_cases.py" <<'PY'
import importlib.util
import sys

sys.path.insert(0, sys.argv[2])
import ref                                # noqa: E402

spec = importlib.util.spec_from_file_location("umts_phy_t2", sys.argv[1])
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


def emit(name, got, want):
    sys.stdout.write("%s\t%s\t%s\n" % (name, got, want))


want = ref.psc()
got = tool.psc_code()
emit("known-answer-psc-256-chips", "%d/256" % ref.agree(got, want), "256/256")
emit("known-answer-psc-length", str(len(got)), "256")

# "complex-valued with identical real and imaginary components" (5.2.3.1), so
# real(i) == imag(i) for every chip, and every chip has |c| = sqrt(2).
same = sum(1 for c in got if abs(complex(c).real - complex(c).imag) < 1e-9)
emit("invariant-psc-real-equals-imag", "%d/256" % same, "256/256")
mods = sorted(set(round(abs(complex(c)), 6) for c in got))
emit("invariant-psc-constant-modulus", str(mods), str([1.414214]))

want_ssc = ref.ssc()
got_ssc = tool.ssc_codes()
emit("known-answer-ssc-count", str(len(got_ssc)), "16")
for k in (1, 8, 16):
    emit("known-answer-ssc-%d-256-chips" % k,
         "%d/256" % ref.agree(got_ssc[k - 1], want_ssc[k - 1]), "256/256")

# The 16 SSCs must be distinct 256-chip codes, or the S-SCH cannot carry 64
# code groups (5.2.3.2).
keys = set(tuple((round(c.real, 6), round(c.imag, 6)) for c in code)
           for code in got_ssc)
emit("invariant-ssc-distinct", str(len(keys)), "16")
PY

helper sch "$WORK/sch_cases.py" "$TOOL" "$WORK"

# The S-SCH slot mapping, on emitted chips: 25.211 5.3.3.5 says every slot
# carries the same 256-chip P-SCH plus that slot's S-SCH from Table 4, and
# 5.2.2's list of scrambled channels does not include the SCH, so no Gold code
# reaches these chips. psc 0 is group 0, psc 384 is group 3.
cat >"$WORK/slots_cases.py" <<'PY'
import importlib.util
import sys

import numpy as np

sys.path.insert(0, sys.argv[2])
import ref                                # noqa: E402

spec = importlib.util.spec_from_file_location("umts_phy_t3", sys.argv[1])
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


def emit(name, got, want):
    sys.stdout.write("%s\t%s\t%s\n" % (name, got, want))


work = sys.argv[3]
want_ssc = ref.ssc()
cp = ref.psc()
w = float(tool.W_PSCH)                # the modelled weight, from the tool
sign = float(tool.SCH_SIGN)
for psc, row in ((0, ref.GROUP0), (8, ref.GROUP1), (504, ref.GROUP63)):
    x = np.fromfile(work + "/sch-%d.cf32" % psc, dtype="<c8")
    bad = 0
    for slot in range(15):
        start = slot * 2560
        got = [complex(v) for v in x[start:start + 256]]
        k = row[slot]
        want = [sign * w * (cp[i] + want_ssc[k - 1][i]) for i in range(256)]
        bad += 256 - ref.agree(got, want, tol=2e-6)
    emit("known-answer-sch-slot-map-psc%d-3840-chips" % psc,
         "%d/3840" % (3840 - bad), "3840/3840")
PY

# The three files that case reads, at 1 sample per chip with the headroom
# scale divided back out, so the comparison is against raw chip values.
for psc in 0 8 504; do
    python3 "$TOOL" gen --carrier sch --psc "$psc" --rate 1 --seconds 0.01 \
        --out "$WORK/sch-$psc.raw" >"$WORK/sch-$psc.tsv" 2>&1 ||
        chk "gen-sch-psc$psc" "rc!=0" "0"
    sc=$(tsv "$WORK/sch-$psc.tsv" peak_scale)
    python3 - "$WORK/sch-$psc.raw" "$WORK/sch-$psc.cf32" "$sc" <<'PY'
import sys

import numpy as np

raw, out, scale = sys.argv[1], sys.argv[2], float(sys.argv[3])
x = np.fromfile(raw, dtype="<c8") / scale
np.asarray(x, "<c8").tofile(out)
PY
done

helper slots "$WORK/slots_cases.py" "$TOOL" "$WORK" "$WORK"

# ---------------------------------------------------------------------------
# 4. cross-check: the scrambling code -- TS 25.213 5.2.2/5.2.3
# ---------------------------------------------------------------------------

cat >"$WORK/scramble_cases.py" <<'PY'
import importlib.util
import sys

sys.path.insert(0, sys.argv[2])
import ref                                # noqa: E402

spec = importlib.util.spec_from_file_location("umts_phy_t4", sys.argv[1])
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


def emit(name, got, want):
    sys.stdout.write("%s\t%s\t%s\n" % (name, got, want))


CHIPS = 64
for psc in (0, 1, 255, 511):
    want = ref.scrambling(psc, CHIPS)
    got = tool.scrambling_code(psc, CHIPS)
    emit("xc-scrambling-psc%d-%d-chips" % (psc, CHIPS),
         "%d/%d" % (ref.agree(got, want, tol=1e-9), CHIPS),
         "%d/%d" % (CHIPS, CHIPS))

# invariant: x and y are maximal-length sequences of the printed polynomials.
# A wrong tap shortens the cycle, so after 2^18-18 clocks the next bit would no
# longer close back onto x(0) = 1. That is the cheapest way to catch a tap that
# was guessed rather than read, and the clause prints the taps precisely so
# that this test can exist.
x, y = tool.gold_sequences()
L = (1 << 18) - 1
emit("invariant-gold-length", str(len(x)), str(L))
nxt_x = int(x[L - 18 + 7] ^ x[L - 18])
nxt_y = int(y[L - 18 + 10] ^ y[L - 18 + 7] ^ y[L - 18 + 5] ^ y[L - 18])
emit("invariant-x-cycle-closes-at-2^18-1", "%d/%d" % (nxt_x, int(x[0])),
     "1/1")
emit("invariant-y-cycle-closes-at-2^18-1", "%d/%d" % (nxt_y, int(y[0])),
     "1/1")
emit("invariant-x-initial-conditions",
     "%d/18" % sum(1 for i in range(18) if int(x[i]) == (1 if i == 0 else 0)),
     "18/18")
emit("invariant-y-initial-conditions",
     "%d/18" % sum(1 for i in range(18) if int(y[i]) == 1), "18/18")
emit("invariant-x-ne-y",
     str(int(any(int(a) != int(b) for a, b in zip(x, y)))), "1")

# The complex code: both components come from the same Z_n family, so every
# chip is one of the four unit-modulus points (5.2.3).
code = tool.scrambling_code(7, 38400)
alpha = set(complex(round(v.real, 9), round(v.imag, 9)) for v in code)
emit("invariant-scrambling-four-phases", str(len(alpha)), "4")
# The complex code is not unit modulus: its I and Q components are each
# +-1 independently, so every chip has |c| = sqrt(2) (5.2.3 composes
# S_dl,n(i) = Z_n(i) + j Z_n(i + 131072) from two real Gold sequences).
emit("invariant-scrambling-constant-modulus",
     "%.6f" % max(abs(c) for c in alpha), "1.414214")
# "the pattern from phase 0 up to the phase of 38399 is repeated" (5.2.3): the
# emitter must tile the same 38400-chip pattern, and the Gold period (262143)
# is not the repeat period.
emit("invariant-scrambling-frame-pattern-length", str(len(code)), "38400")
PY

helper scramble "$WORK/scramble_cases.py" "$TOOL" "$WORK"

# invariant: the emitted file repeats its frame, which is what makes the code
# phase claim in the TSV ("every frame carries the same pattern") checkable.
cat >"$WORK/repeat_cases.py" <<'PY'
import sys

import numpy as np

work = sys.argv[1]
x = np.fromfile(work + "/ten.cf32", dtype="<c8")
same = int(np.array_equal(x[:38400], x[38400:76800]))
sys.stdout.write("invariant-file-frame-repeats\t%d\t1\n" % same)
peak = float(np.max(np.abs(x)))
sys.stdout.write("invariant-file-peak-at-full-scale\t%.6f\t1.000000\n" % peak)
PY

# ---------------------------------------------------------------------------
# 5. known answer: frame arithmetic -- TS 25.211 5, TS 25.213 5.2
# ---------------------------------------------------------------------------

rc=$(run one gen --carrier p-cpich --out "$WORK/one.cf32" --rate 3840000 \
         --seconds 0.01)
chk "gen-one-frame-rc" "$rc" "0"
chk "arith-chip-rate-25.213" "$(tsv "$WORK/one.tsv" chip_rate)" "3840000"
chk "arith-chips-per-slot-25.211" "$(tsv "$WORK/one.tsv" chips_per_slot)" "2560"
chk "arith-slots-per-frame-25.211" \
    "$(python3 -c 'print(38400 // 2560)')" "15"
chk "arith-chips-per-frame" "$(tsv "$WORK/one.tsv" chips_per_frame)" "38400"
chk "arith-frame-seconds-25.211" "$(tsv "$WORK/one.tsv" frame_seconds)" \
    "0.010000"
chk "arith-one-frame-chips" "$(tsv "$WORK/one.tsv" chips)" "38400"
chk "arith-one-frame-samples" "$(tsv "$WORK/one.tsv" samples)" "38400"
chk "arith-chip-samples" "$(tsv "$WORK/one.tsv" chip_samples)" "1"
chk "arith-rate" "$(tsv "$WORK/one.tsv" rate)" "3840000"
chk "arith-psc" "$(tsv "$WORK/one.tsv" psc)" "0"
chk "arith-scrambling-code" "$(tsv "$WORK/one.tsv" scrambling_code)" "0"
chk "arith-pilot-code-25.213-5.2.1" "$(tsv "$WORK/one.tsv" pilot_code)" \
    "Cch,256,0"
chk "arith-sch-sign-25.211-5.3.3.5" "$(tsv "$WORK/one.tsv" sch_sign)" "-1"
chk "arith-limit-rows-in-summary" "$(grep -c '^limit'$'\t' "$WORK/one.tsv")" "8"

# 2560 chips/slot x 15 slots = 38400 chips/frame, 10 ms frame, 3.84 Mcps.
chk "arith-38400-div-3840000-is-10ms" \
    "$(python3 -c 'print("%.3f" % (38400 / 3840000.0 * 1000))')" "10.000"
chk "arith-2560-x15" "$(python3 -c 'print(2560 * 15)')" "38400"
chk "arith-100ms-is-ten-frames" \
    "$(python3 -c 'print(int(0.1 * 3840000) // 38400)')" "10"

# 10 frames = 384000 chips = exactly 0.1 s at 3.84 Mcps, no residue.
rc=$(run ten gen --carrier p-cpich --out "$WORK/ten.cf32" --rate 3840000 \
         --seconds 0.1)
chk "gen-ten-frames-rc" "$rc" "0"
chk "arith-ten-frames-chips" "$(tsv "$WORK/ten.tsv" chips)" "384000"
chk "arith-ten-frames-frames" "$(tsv "$WORK/ten.tsv" frames)" "10.000000"
chk "arith-ten-frames-seconds" "$(tsv "$WORK/ten.tsv" seconds)" "0.100000000"
helper repeat "$WORK/repeat_cases.py" "$WORK"

# oversampling is an integer multiple of the chip rate, in both spellings.
rc=$(run os gen --carrier sch --out "$WORK/os.cf32" --rate 8 --seconds 0.01)
chk "gen-eight-sps-rc" "$rc" "0"
chk "arith-eight-sps-chip-samples" "$(tsv "$WORK/os.tsv" chip_samples)" "8"
chk "arith-eight-sps-rate" "$(tsv "$WORK/os.tsv" rate)" "30720000"
chk "arith-eight-sps-samples" "$(tsv "$WORK/os.tsv" samples)" "307200"
rc=$(run hz gen --carrier sch --out "$WORK/hz.cf32" --rate 30720000 \
         --seconds 0.01)
chk "arith-hz-rate-form-rc" "$rc" "0"
chk "arith-hz-rate-form-chip-samples" "$(tsv "$WORK/hz.tsv" chip_samples)" "8"
chk "arith-hz-rate-form-samples" "$(tsv "$WORK/hz.tsv" samples)" "307200"
chk "invariant-zero-order-hold" \
    "$(python3 - "$WORK/os.cf32" <<'PY'
import sys

import numpy as np

x = np.fromfile(sys.argv[1], dtype="<c8")
print("held" if np.array_equal(x[0::8], x[1::8]) and np.array_equal(x[0::8], x[7::8]) else "shaped")
PY
)" "held"

# ---------------------------------------------------------------------------
# 6. known answer: the containers -- modules/33_jamming_detect.sh's writer
# ---------------------------------------------------------------------------

for fmt in cf32 ci16 cu8; do
    rc=$(run "fmt-$fmt" gen --carrier p-cpich --out "$WORK/fmt-$fmt.bin" \
             --format "$fmt" --rate 1 --seconds 0.01)
    chk "gen-$fmt-rc" "$rc" "0"
    size=$(wc -c <"$WORK/fmt-$fmt.bin")
    case $fmt in
        cf32) want=$((38400 * 8)) ;;
        ci16) want=$((38400 * 4)) ;;
        cu8)  want=$((38400 * 2)) ;;
    esac
    chk "bytes-$fmt-on-disk" "$size" "$want"
    chk "bytes-$fmt-in-summary" "$(tsv "$WORK/fmt-$fmt.tsv" bytes)" "$want"
    case $fmt in
        cf32) full="1.0000" ;;
        ci16) full="32767.0000" ;;
        cu8)  full="127.5000" ;;
    esac
    chk "peak-full-scale-$fmt" "$(tsv "$WORK/fmt-$fmt.tsv" peak_full_scale)" \
        "$full"
done

# The quantisers on a hand-computed vector. Chips in this tool are +-1+-j, so
# these three values are the whole alphabet a reader will meet: (1+1j), 0 and
# (-1-1j). The expected bytes are worked out from the formulas in
# modules/33_jamming_detect.sh, not from the tool's own output.
cat >"$WORK/quant_cases.py" <<'PY'
import importlib.util
import struct
import sys

spec = importlib.util.spec_from_file_location("umts_phy_t5", sys.argv[1])
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


def emit(name, got, want):
    sys.stdout.write("%s\t%s\t%s\n" % (name, got, want))


x = [1 + 1j, 0 + 0j, -1 - 1j]
# cf32 is np.asarray(x, '<c8'): little-endian float32 pairs, no scaling.
emit("known-answer-quantise-cf32-bytes", tool.quantise(x, "cf32").hex(),
     struct.pack("<6f", 1.0, 1.0, 0.0, 0.0, -1.0, -1.0).hex())
# ci16 is round(x*32767) clipped to [-32768, 32767].
emit("known-answer-quantise-ci16-bytes", tool.quantise(x, "ci16").hex(),
     struct.pack("<6h", 32767, 32767, 0, 0, -32767, -32767).hex())
# cu8 is round(x*127+127.5) clipped to [0, 255]: 1*127+127.5 = 254.5 rounds
# to 254 (numpy's round-half-to-even) and 127.5 rounds to 128, which is the
# convention the consumer reads back with (d - 127.5)/127.5.
emit("known-answer-quantise-cu8-bytes", tool.quantise(x, "cu8").hex(),
     bytes([254, 254, 128, 128, 0, 0]).hex())
# Round trip through the consumer's own reader: cu8 -> (d - 127.5)/127.5 must
# land within one quantisation step of the sample that was written.
import numpy as np

q = np.frombuffer(tool.quantise(x, "cu8"), dtype=np.uint8).reshape(-1, 2)
back = (q[:, 0] - 127.5) / 127.5 + 1j * ((q[:, 1] - 127.5) / 127.5)
err = max(abs(back[i] - x[i]) for i in range(3))
emit("known-answer-cu8-round-trip", "%.4f" % err, "0.0111")
PY
helper quant "$WORK/quant_cases.py" "$TOOL"

# invariant: the summary is not decoration -- peak_written must equal the peak
# measured in the file it names, and the byte count must match the file.
cat >"$WORK/peak_cases.py" <<'PY'
import sys

import numpy as np

work = sys.argv[1]
rows = {}
for line in open(work + "/one.tsv"):
    k, v = line.rstrip("\n").split("\t", 1)
    rows.setdefault(k, v)
x = np.fromfile(work + "/one.cf32", dtype="<c8")
sys.stdout.write("invariant-summary-peak-matches-file\t%.6f\t%.6f\n"
                 % (float(np.max(np.abs(x))), float(rows["peak_written"])))
sys.stdout.write("invariant-summary-bytes-match-file\t%d\t%s\n"
                 % (len(x) * 8, rows["bytes"]))
PY
helper peak "$WORK/peak_cases.py" "$WORK"

# invariant: the pilot is constant after descrambling with the code the tool
# reports, so the emitted pilot really is the phase reference it claims.
cat >"$WORK/pilot_cases.py" <<'PY'
import importlib.util
import sys

import numpy as np

spec = importlib.util.spec_from_file_location("umts_phy_t6", sys.argv[1])
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)

x = np.fromfile(sys.argv[2] + "/one.cf32", dtype="<c8")[:38400]
descrambled = set(np.round(x / (float(tool.W_CPICH) * (1 + 1j)
                                * tool.scrambling_code(0)), 6))
sys.stdout.write("invariant-descrambled-pilot-constant\t%d unique\t1 unique\n"
                 % len(descrambled))
PY
helper pilot "$WORK/pilot_cases.py" "$TOOL" "$WORK"

# invariant: --carrier both is the sum of the two single carriers, after the
# headroom scales the tool reports are divided out. This binds the combining
# step to the per-channel outputs rather than trusting the sum blindly.
for c in p-cpich sch both; do
    python3 "$TOOL" gen --carrier "$c" --out "$WORK/c-$c.bin" --rate 1 \
        --seconds 0.01 >"$WORK/c-$c.tsv" 2>&1 ||
        chk "gen-combining-$c" "rc!=0" "0"
done
cat >"$WORK/both_cases.py" <<'PY'
import sys

import numpy as np

work = sys.argv[1]


def scale(name):
    for line in open(work + "/" + name):
        k, v = line.rstrip("\n").split("\t", 1)
        if k == "peak_scale":
            return float(v)
    raise SystemExit("no peak_scale row in " + name)


pilot = np.fromfile(work + "/c-p-cpich.bin", dtype="<c8") / scale("c-p-cpich.tsv")
sch = np.fromfile(work + "/c-sch.bin", dtype="<c8") / scale("c-sch.tsv")
both = np.fromfile(work + "/c-both.bin", dtype="<c8") / scale("c-both.tsv")
same = int(np.allclose(both, pilot + sch, atol=2e-6))
sys.stdout.write("invariant-both-is-pilot-plus-sch\t%d\t1\n" % same)
PY
helper both "$WORK/both_cases.py" "$WORK"

# ---------------------------------------------------------------------------
# 7. negation control: the suite must be able to fail
# ---------------------------------------------------------------------------

# Corrupt one constant in a COPY of the generator -- the 131072-chip I/Q phase
# offset of S_dl,n(i) = Z_n(i) + j Z_n((i + 131072) mod 2^18-1) becomes 131071
# -- then re-run the SAME cross-check file (scramble_cases.py, the one that
# reports 0 mismatches a few lines above) against the corrupted copy and
# require it to report that the scrambling codes are wrong. This is the control
# that makes the green run mean something: a suite whose comparator could not
# fail would pass both.
#
# It proves three things at once: the cross-check binds on the generator rather
# than on a re-statement of it, the comparison is chip-level (a wrong Gold
# phase moves many chips, not the length or the modulation), and the file the
# healthy run produced was not accidentally reused.
mismatch() {
    awk -F'\t' '$2 != $3 { n++ } END { print n + 0 }' "$1"
}
cp "$TOOL" "$WORK/corrupt.py"
sed -i 's/^GOLD_Q_OFFSET = 1 << 17/GOLD_Q_OFFSET = (1 << 17) - 1/' \
    "$WORK/corrupt.py"
if ! grep -q '^GOLD_Q_OFFSET = (1 << 17) - 1' "$WORK/corrupt.py"; then
    # The sed did not land, so the control itself is broken and must not pass.
    chk "negation-control-corruption-applied" "not-applied" "applied"
else
    chk "negation-control-corruption-applied" "applied" "applied"
    chk "negation-control-baseline-mismatches" "$(mismatch "$WORK/scramble.tsv")" "0"
    python3 "$WORK/scramble_cases.py" "$WORK/corrupt.py" "$WORK" \
        >"$WORK/corrupt.tsv" 2>"$WORK/corrupt.err"
    chk "negation-control-corrupt-run-quiet" "$(wc -l <"$WORK/corrupt.err")" "0"
    chk "negation-control-corrupt-scrambling-mismatches" \
        "$(awk -F'\t' '$1 ~ /^xc-scrambling/ && $2 != $3 { n++ }
                       END { print n + 0 }' "$WORK/corrupt.tsv")" "4"
    chk "negation-control-corrupt-invariants-still-pass" \
        "$(awk -F'\t' '$1 ~ /^invariant/ && $2 != $3 { n++ }
                       END { print n + 0 }' "$WORK/corrupt.tsv")" "0"
    chk "negation-control-corrupt-summary-not-empty" \
        "$([[ -s "$WORK/corrupt.tsv" ]] && echo rows || echo empty)" "rows"
    cat >"$WORK/negate_cases.py" <<'PY'
import importlib.util
import sys

sys.path.insert(0, sys.argv[2])
import ref                                # noqa: E402

spec = importlib.util.spec_from_file_location("umts_phy_corrupt", sys.argv[1])
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


def emit(name, got, want):
    sys.stdout.write("%s\t%s\t%s\n" % (name, got, want))


CHIPS = 64
want = ref.scrambling(0, CHIPS)
got = tool.scrambling_code(0, CHIPS)
n = ref.agree(got, want, tol=1e-9)
emit("negation-control-wrong-phase-offset",
     "detected" if n != CHIPS else "missed", "detected")
# The comparator must also flag a single flipped chip, not only wholesale
# disagreement: that is what makes "detected" mean chips were compared.
one = list(want)
one[17] = -one[17]
emit("negation-control-one-chip-flip",
     "detected" if ref.agree(one, want) != CHIPS else "missed", "detected")
PY
    helper negate "$WORK/negate_cases.py" "$WORK/corrupt.py" "$WORK"
fi

# ---------------------------------------------------------------------------

printf 'checks\t%d\n' "$NTOT"
printf 'passed\t%d\n' "$NPASS"
printf 'failed\t%d\n' "$NBAD"
printf 'RESULT\t%s\n' "$([[ $NBAD -eq 0 ]] && echo PASS || echo "FAIL($NBAD)")"
[[ $NBAD -eq 0 ]] || exit 1
exit 0
