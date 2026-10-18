#!/usr/bin/env bash
#
# Check tools/phy_seqs.py against outside answers -- published vectors where
# one exists, structural invariants (labelled `invariant`) where none does.
#
# Why this exists: docs/SESSION_HANDOFF.md 16 records three defects that passed
# their own tests because the test asserted the same misreading the code
# carried -- A5/1 with the wrong taps, an NR-ARFCN raster asserted only at a
# band edge, an S6a table of 270 assertions repeating the same wrong values.
# A sequence generator is the easiest place in this tree to commit that
# mistake: a wrong G2 delay sign, a wrong ZC root, a wrong c_init all produce
# output that is the right length, the right modulus, the right order of
# magnitude, and wrong. So the primary oracle here is external:
#
#   published    IS-GPS-200N Table 3-Ia: the "Code Delay Chips (C/A)" column
#                and the "First 10 Chips Octal (C/A)" column, PRN 1..32, read
#                from the ICD itself (archive.org copy of IS-GPS-200N). The
#                octal convention is the ICD's own note: first digit is the
#                first chip, last three are conventional octal of the other 9.
#                A sign error in the G2 delay reproduces neither column.
#
#   published    TS 36.211 Table 5.7.2-2, N_CS for formats 0-3, unrestricted
#                set, zeroCorrelationZoneConfig 0..15 -- 16 values, printed by
#                the tool as the `ncs` row for each zone.
#
#   published    TS 36.211 6.10.4.1 c_init and 6.10.4.2 k, transcribed from the
#                clause and compared value by value against the tool; plus the
#                clause's own 2^28 * floor(N_ID_PRS/512) leading term, which
#                --pci cannot reach, so it is exercised directly.
#
#   continuity   tools/lte_phy.py already implements the TS 36.211 7.2 Gold
#                generator that PRS needs and the CRS c_init that the PRS
#                c_init must equal for N_ID_PRS < 512. The tool IMPORTS that
#                generator rather than writing a second one; this check asserts
#                the import is real, the bits agree, and the two c_inits agree
#                over a sweep. That is the rule docs/SESSION_HANDOFF.md sets:
#                do not keep two conventions of the same quantity.
#
#   invariant    Where nothing external can be stated -- constant modulus of
#                the ZC sequence, its periodic autocorrelation, the GPS
#                three-valued autocorrelation (-65, -1, 63), distinctness of
#                the 32 C/A codes, zero-order-hold tiling, the diagonal PRS
#                offset pattern, guard zeros, CP == tail -- the row says
#                `invariant`, because these catch a wrong formula but cannot
#                prove the right one.
#
# What it does NOT claim: no vector for the PRACH preamble itself (3GPP does
# not publish one, and the tool's own formula is the only reader of 5.7.2 here),
# no published PRS vector (same reason), and nothing about the GPS codes above
# PRN 32 (IS-GPS-200N Table 3-Ib defines those by initial G2 setting, which the
# tool does not implement).
#
# Exit: 0 every check passed, 1 a check failed, 2 SKIP -- python3 or numpy is
# absent. A SKIP is not a pass and prints RESULT SKIP, never PASS.

set -u

ROOT=$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PY=${PYTHON:-python3}
TOOL="$ROOT/tools/phy_seqs.py"

if ! command -v "$PY" >/dev/null 2>&1; then
    printf 'SKIP\tno %s on PATH\n' "$PY"
    printf 'RESULT SKIP\n'
    exit 2
fi
if ! "$PY" -c 'import numpy' >/dev/null 2>&1; then
    printf 'SKIP\t%s cannot import numpy, so phy_seqs.py cannot run\n' "$PY"
    printf 'RESULT SKIP\n'
    exit 2
fi
if [ ! -f "$TOOL" ]; then
    printf 'SKIP\t%s is missing\n' "$TOOL"
    printf 'RESULT SKIP\n'
    exit 2
fi

WORK=$(mktemp -d "${TMPDIR:-/tmp}/imsisting-phy-seqs.XXXXXX") || exit 2
trap 'rm -rf "$WORK"' EXIT HUP INT TERM

PYTHONPATH="$ROOT/tools${PYTHONPATH:+:$PYTHONPATH}" \
    PYTHON="$PY" \
    PHY_SEQS_TOOL="$TOOL" \
    CHECK_WORK="$WORK" \
    "$PY" - <<'PYEOF'
import os
import subprocess
import sys

import numpy as np

TOOL = os.environ["PHY_SEQS_TOOL"]
WORK = os.environ["CHECK_WORK"]
PY = os.environ["PYTHON"]

sys.path.insert(0, os.path.dirname(os.path.abspath(TOOL)))
import phy_seqs           # noqa: E402
import lte_phy            # noqa: E402

FAILS = []
CHECKS = [0]

# The CLI contract's rows, accumulating over every successful gen run below;
# a sequence that omits `formula_ref`, or neither `repeat` nor `structure`,
# breaks the consumer even when the samples are right.
REQUIRED_ROWS = ("seq", "out", "format", "rate", "samples", "seconds", "bytes",
                 "peak_full_scale", "formula_ref")
MISSING_ROWS = []


def ok(label, detail=""):
    CHECKS[0] += 1
    print("ok\t%s%s" % (label, ("\t" + detail) if detail else ""))


def bad(label, detail=""):
    CHECKS[0] += 1
    FAILS.append(label)
    print("FAIL\t%s%s" % (label, ("\t" + detail) if detail else ""))


def check(label, cond, detail=""):
    ok(label, detail) if cond else bad(label, detail)
    return cond


def path(name):
    return os.path.join(WORK, name)


def run(*args):
    return subprocess.run([PY, TOOL] + list(args),
                          capture_output=True, text=True)


def gen(args, expect=0, label=None):
    """Run `gen`, insist on the exit code, return (TSV dict, stderr)."""
    proc = run("gen", *args)
    tag = label or " ".join(args)
    if not check("rc=%d\t%s" % (expect, tag), proc.returncode == expect,
                 "rc=%d stderr=%r" % (proc.returncode, proc.stderr.strip())):
        return {}, proc.stderr
    if expect != 0:
        return {}, proc.stderr
    if not check("stdout-parses\t%s" % tag, "\t" in proc.stdout):
        return {}, proc.stderr
    tsv = {}
    for line in proc.stdout.splitlines():
        if not line:
            continue
        if line.count("\t") != 1:
            bad("tsv-one-tab\t%s" % tag, repr(line))
            return {}, proc.stderr
        key, value = line.split("\t")
        if not key or not value:
            bad("tsv-no-empty-field\t%s" % tag, repr(line))
            return {}, proc.stderr
        if key in tsv:
            bad("tsv-unique-key\t%s" % tag, key)
        tsv[key] = value
    for key in REQUIRED_ROWS:
        if key not in tsv:
            MISSING_ROWS.append((tag, key))
    if "repeat" not in tsv and "structure" not in tsv:
        MISSING_ROWS.append((tag, "repeat|structure"))
    return tsv, proc.stderr


def read_cf32(name):
    return np.fromfile(path(name), dtype="<c8")


def file_size(name):
    return os.path.getsize(path(name))


# ---------------------------------------------------------------------------
# 0. `list` has to name every sequence and its clause.
# ---------------------------------------------------------------------------

proc = run("list")
check("list-rc0", proc.returncode == 0, "rc=%d" % proc.returncode)
lines = [l for l in proc.stdout.splitlines() if l]
check("list-three-sequences", len(lines) == 3, "%d lines" % len(lines))
for name, clause in (("gps-ca", "IS-GPS-200"), ("prach", "36.211 5.7"),
                     ("prs", "36.211 6.10.4")):
    hit = [l for l in lines if l.split("\t")[0] == name]
    check("list-row\t%s" % name, len(hit) == 1,
          "rows=%d" % len(hit))
    if hit:
        check("list-clause\t%s" % name, clause in hit[0],
              hit[0][:120])

# ---------------------------------------------------------------------------
# 1. GPS L1 C/A.
# ---------------------------------------------------------------------------

# IS-GPS-200N Table 3-Ia, "Code Delay Chips (C/A)", PRN 1..32, read from the
# ICD. This column is the G2 delay d in ca(i) = G1(i) XOR G2(i - d).
GPS_DELAY = [5, 6, 7, 8, 17, 18, 139, 140, 141, 251, 252, 254, 255, 256,
             257, 258, 469, 470, 471, 472, 473, 474, 509, 512, 513, 514,
             515, 516, 859, 860, 861, 862]

# IS-GPS-200N Table 3-Ia, "First 10 Chips Octal (C/A)", PRN 1..32. The ICD's
# note: the first digit is the first chip (always '1' here), the last three
# digits are the conventional octal of the remaining nine chips.
GPS_FIRST10 = ["1440", "1620", "1710", "1744", "1133", "1455", "1131", "1454",
               "1626", "1504", "1642", "1750", "1764", "1772", "1775", "1776",
               "1156", "1467", "1633", "1715", "1746", "1763", "1063", "1706",
               "1743", "1761", "1770", "1774", "1127", "1453", "1625", "1712"]

CHIP_RATE = 1023000
ONE_CODE = 1023.0 / CHIP_RATE          # 1023 chips of time
codes = {}

for prn in range(1, 33):
    tag = "gps-ca prn=%d" % prn
    tsv, _ = gen(["--seq", "gps-ca", "--prn", str(prn), "--rate",
                  str(CHIP_RATE), "--secs", repr(ONE_CODE), "--format",
                  "cf32", "--out", path("g%d.cf32" % prn)], label=tag)
    if not tsv:
        continue
    check("published-g2-delay\t%s" % tag,
          tsv.get("g2_delay_chips") == str(GPS_DELAY[prn - 1]),
          "tool=%r ICD=%d" % (tsv.get("g2_delay_chips"), GPS_DELAY[prn - 1]))
    check("samples-is-1023\t%s" % tag, tsv.get("samples") == "1023",
          tsv.get("samples", "?"))
    check("bytes-consistent\t%s" % tag,
          tsv.get("bytes") == str(1023 * 8)
          and file_size("g%d.cf32" % prn) == 1023 * 8,
          "tsv=%s file=%d" % (tsv.get("bytes"), file_size("g%d.cf32" % prn)))
    check("chip-rate-hz\t%s" % tag, tsv.get("chip_rate_hz") == "1023000")
    check("peak-full-scale\t%s" % tag, tsv.get("peak_full_scale") == "1.0000")
    x = read_cf32("g%d.cf32" % prn)
    chips = (x.real < 0).astype(int)          # +1 -> 0, -1 -> 1
    codes[prn] = tuple(chips.tolist())
    # published first-ten-chips octal, rebuilt the way the ICD writes it
    bits = chips[:10]
    got = str(bits[0]) + format(int("".join(str(b) for b in bits[1:]), 2),
                                "o").zfill(3)
    check("published-first10\t%s" % tag, got == GPS_FIRST10[prn - 1],
          "tool=%s ICD=%s" % (got, GPS_FIRST10[prn - 1]))
    check("invariant-values-pm1\t%s" % tag,
          np.array_equal(np.abs(x.real), np.ones(1023))
          and np.all(x.imag == 0), "unique=%r" % np.unique(x.real))

check("published-distinct-codes", len(set(codes.values())) == 32,
      "%d distinct" % len(set(codes.values())))

# invariant: the C/A autocorrelation takes only 1023, 63, -1, -65 at integer
# lags. A wrong G2 delay still gives +-1 chips and still gives 32 distinct
# codes, so this is the structural test that a delay slip does not break --
# which is why the published columns above are the ones that decide.
ac_bad = []
for prn in (1, 2, 17, 23, 32):
    s = 1.0 - 2.0 * np.asarray(codes[prn], dtype=np.float64)
    ac = np.fft.ifft(np.abs(np.fft.fft(s)) ** 2).real
    ac = np.round(ac).astype(int)
    if ac[0] != 1023 or set(ac[1:].tolist()) - {-65, -1, 63}:
        ac_bad.append((prn, int(ac[0]), sorted(set(ac[1:].tolist()))))
check("invariant-autocorrelation-3-valued", not ac_bad, repr(ac_bad))

# invariant: zero-order hold. At twice the chip rate every chip must occupy
# exactly two equal samples, and the code must start over at 1023 chips.
tsv, _ = gen(["--seq", "gps-ca", "--prn", "1", "--rate", str(2 * CHIP_RATE),
              "--secs", repr(2 * ONE_CODE), "--out", path("g2x.cf32")],
             label="gps-ca zoh")
if tsv:
    x2 = read_cf32("g2x.cf32")
    s = 1.0 - 2.0 * np.asarray(codes[1], dtype=np.float64)
    check("invariant-zoh-two-samples-per-chip",
          np.array_equal(x2[0::2], x2[1::2])
          and np.array_equal(x2[0::2], np.tile(s, 2).astype(np.complex64)))
    check("repeat-period", np.array_equal(x2[:2046], np.tile(x2, 1)[:2046])
          and tsv.get("samples") == "4092" and tsv.get("bytes") == "32736",
          "samples=%s" % tsv.get("samples"))
    check("zoh-rows", "repeat" in tsv and "1023000" in tsv.get("repeat", ""),
          tsv.get("repeat", "")[:80])

# format byte-compatibility with modules/33_jamming_detect.sh: re-quantise the
# cf32 file with that module's formulas and demand the ci16 and cu8 files
# match byte for byte.
tsv32, _ = gen(["--seq", "gps-ca", "--prn", "5", "--rate", str(CHIP_RATE),
                "--secs", repr(ONE_CODE), "--out", path("f32.cf32")],
               label="gps-ca format cf32")
if tsv32:
    x = read_cf32("f32.cf32")
    for fmt, item in (("ci16", 4), ("cu8", 2)):
        tsv, _ = gen(["--seq", "gps-ca", "--prn", "5", "--rate",
                      str(CHIP_RATE), "--secs", repr(ONE_CODE), "--format",
                      fmt, "--out", path("f." + fmt)],
                     label="gps-ca format %s" % fmt)
        if not tsv:
            continue
        raw = np.fromfile(path("f." + fmt),
                          dtype="<i2" if fmt == "ci16" else np.uint8)
        if fmt == "ci16":
            want = np.empty(2 * x.size, dtype="<i2")
            want[0::2] = np.clip(np.round(x.real * 32767.0), -32768, 32767)
            want[1::2] = np.clip(np.round(x.imag * 32767.0), -32768, 32767)
            scale = "32767.0000"
        else:
            want = np.empty(2 * x.size, dtype=np.uint8)
            want[0::2] = np.clip(np.round(x.real * 127.0 + 127.5), 0, 255)
            want[1::2] = np.clip(np.round(x.imag * 127.0 + 127.5), 0, 255)
            scale = "127.5000"
        check("format-%s-bytes-equal-consumer" % fmt,
              tsv.get("bytes") == str(x.size * item)
              and file_size("f." + fmt) == x.size * item
              and np.array_equal(raw, want),
              "file=%d want=%d" % (file_size("f." + fmt), x.size * item))
        check("format-%s-peak-full-scale" % fmt,
              tsv.get("peak_full_scale") == scale, tsv.get("peak_full_scale"))

# refusals: exit 2 on a bad argument, exit 1 on an unwritable path
for label, args in (
        ("gps-ca prn=0", ["--seq", "gps-ca", "--prn", "0"]),
        ("gps-ca prn=33", ["--seq", "gps-ca", "--prn", "33"]),
        ("gps-ca prn=abc", ["--seq", "gps-ca", "--prn", "abc"]),
        ("unknown seq", ["--seq", "lte-crs"]),
        ("bad format", ["--seq", "gps-ca", "--format", "cf64"]),
        ("bad rate 0", ["--seq", "gps-ca", "--rate", "0"]),
        ("bad rate abc", ["--seq", "gps-ca", "--rate", "abc"]),
        ("bad secs", ["--seq", "gps-ca", "--secs", "-1"]),
):
    gen(args + ["--out", path("never.raw")], expect=2, label="refuse " + label)
gen(["--seq", "gps-ca", "--out", "/proc/phy-seqs-cannot-write"], expect=1,
    label="io-failure")
gen(["--seq", "gps-ca"], expect=2, label="refuse missing --out")

# ---------------------------------------------------------------------------
# 2. LTE PRACH.
# ---------------------------------------------------------------------------

# TS 36.211 Table 5.7.2-2, N_CS for preamble formats 0-3, unrestricted set,
# indexed by zeroCorrelationZoneConfig 0..15.
PRACH_NCS = [0, 13, 15, 18, 22, 26, 32, 38, 46, 59, 76, 93, 119, 167, 279, 419]
RA_RATE = 1048750                      # 839 samples / 800 us, exactly

for zone, ncs in enumerate(PRACH_NCS):
    tag = "prach ncs_zone=%d" % zone
    tsv, _ = gen(["--seq", "prach", "--preamble", "25", "--ncs", str(zone),
                  "--rate", str(RA_RATE), "--secs", "0.001", "--out",
                  path("p%d.cf32" % zone)], label=tag)
    if not tsv:
        continue
    check("published-ncs\t%s" % tag, tsv.get("ncs") == str(ncs),
          "tool=%s Table 5.7.2-2=%d" % (tsv.get("ncs"), ncs))
    check("ncs-zone-echo\t%s" % tag, tsv.get("ncs_zone") == str(zone))
    check("format0-timing\t%s" % tag,
          tsv.get("preamble_format") == "0"
          and tsv.get("n_ra_hz") == "1048750"
          and tsv.get("cp_samples") == "108"
          and tsv.get("seq_samples") == "839"
          and tsv.get("guard_samples") == "102"
          and tsv.get("subframe_samples") == "1049"
          and tsv.get("samples") == "1049",
          "cp=%s seq=%s guard=%s samples=%s" % (
              tsv.get("cp_samples"), tsv.get("seq_samples"),
              tsv.get("guard_samples"), tsv.get("samples")))

# the ZC sequence itself: exponent, modulus, period, and its autocorrelation
u = 25
tsv, _ = gen(["--seq", "prach", "--preamble", str(u), "--ncs", "0",
              "--rate", str(RA_RATE), "--secs", "0.001", "--out",
              path("pz.cf32")], label="prach zc u=25")
if tsv:
    x = read_cf32("pz.cf32")
    cp = int(tsv["cp_samples"])
    seq_n = int(tsv["seq_samples"])
    seq = x[cp:cp + seq_n]
    n = np.arange(839)
    want = np.exp(-1j * np.pi * u * n * (n + 1.0) / 839.0)
    check("invariant-zc-formula", np.abs(seq - want).max() < 1e-6,
          "max|diff|=%.3g" % np.abs(seq - want).max())
    check("invariant-constant-modulus",
          np.abs(np.abs(seq) - 1.0).max() < 1e-6,
          "max||x|-1|=%.3g" % np.abs(np.abs(seq) - 1.0).max())
    ac = np.array([np.vdot(seq, np.roll(seq, k)) / 839.0
                   for k in (0, 1, 2, 7, 100, 838)])
    check("invariant-zc-autocorrelation",
          abs(ac[0] - 1.0) < 1e-5 and np.abs(ac[1:]).max() < 1e-5,
          "|R|=%.3g..%.3g" % (np.abs(ac[1:]).min(), np.abs(ac[1:]).max()))
    check("invariant-guard-zero",
          np.all(x[cp + seq_n:] == 0), "guard nonzero")
    check("invariant-cp-is-tail",
          np.abs(x[:cp] - seq[seq_n - cp:]).max() == 0.0)
    # stability: the same index twice gives the same bytes
    tsv2, _ = gen(["--seq", "prach", "--preamble", str(u), "--ncs", "0",
                   "--rate", str(RA_RATE), "--secs", "0.001", "--out",
                   path("pz2.cf32")], label="prach stable rerun")
    same = open(path("pz.cf32"), "rb").read() == open(path("pz2.cf32"),
                                                     "rb").read()
    check("invariant-stable-across-runs", same)

# cyclic shift: N_CS = 13 (zone 1), v = 3 -> C_v = 39
tsv, _ = gen(["--seq", "prach", "--preamble", "25", "--ncs", "1", "--v", "3",
              "--rate", str(RA_RATE), "--secs", "0.001", "--out",
              path("pcv.cf32")], label="prach cv")
if tsv:
    check("published-cv", tsv.get("cv") == "39", "cv=%s" % tsv.get("cv"))
    x = read_cf32("pcv.cf32")
    cp = int(tsv["cp_samples"])
    seq = x[cp:cp + int(tsv["seq_samples"])]
    n = np.arange(839)
    base = np.exp(-1j * np.pi * 25 * n * (n + 1.0) / 839.0)
    want = base[(n + 39) % 839]
    check("invariant-cv-shift", np.abs(seq - want).max() < 1e-6,
          "max|diff|=%.3g" % np.abs(seq - want).max())

# The jamming waveform code runs at 20 Msps, so the resampler -- not just the
# identity case at N_RA -- has to be right. invariant: the tool's contract is a
# band-limited zero-pad (the 839-tone preamble placed at baseband, high bins
# empty, gain n_out/N_ZC), so the DFT of the emitted sequence must be exactly
# the 839-point DFT in the retained bins and exactly zero elsewhere. A
# zero-order hold would leave image energy outside them and fail this.
tsv, _ = gen(["--seq", "prach", "--preamble", "25", "--ncs", "0", "--rate",
              "20000000", "--secs", "0.001", "--out", path("p20.cf32")],
             label="prach resampled 20 Msps")
if tsv:
    check("resample-timing-20msps",
          tsv.get("rate") == "20000000" and tsv.get("cp_samples") == "2062"
          and tsv.get("seq_samples") == "16000"
          and tsv.get("guard_samples") == "1938"
          and tsv.get("samples") == "20000"
          and tsv.get("n_ra_hz") == "1048750",
          "cp=%s seq=%s guard=%s" % (tsv.get("cp_samples"),
                                     tsv.get("seq_samples"),
                                     tsv.get("guard_samples")))
    x = read_cf32("p20.cf32")
    cp, seq_n = 2062, 16000
    seq = x[cp:cp + seq_n]
    check("resample-guard-zero", np.all(x[cp + seq_n:] == 0))
    check("resample-cp-is-tail",
          np.array_equal(x[:cp], seq[seq_n - cp:].astype(np.complex64)))
    n = np.arange(839)
    base = np.exp(-1j * np.pi * 25 * n * (n + 1.0) / 839.0)
    spec = np.fft.fft(base)
    S = np.fft.fft(seq.astype(np.complex128)) / (seq_n / 839.0)
    want = np.zeros(seq_n, dtype=np.complex128)
    want[:420] = spec[:420]
    want[-419:] = spec[420:]
    rel = np.abs(S - want).max() / np.abs(spec).max()
    check("invariant-resample-is-fft-zero-pad", rel < 1e-6,
          "max rel image=%.3g" % rel)
    check("invariant-resample-839-tones",
          int(np.count_nonzero(np.abs(S) > 1e-6 * np.abs(spec).max())) == 839)

for label, args in (
        ("prach preamble=0", ["--seq", "prach", "--preamble", "0"]),
        ("prach preamble=839", ["--seq", "prach", "--preamble", "839"]),
        ("prach ncs=16", ["--seq", "prach", "--ncs", "16"]),
        ("prach ncs=-1", ["--seq", "prach", "--ncs", "-1"]),
        ("prach v=1 with N_CS=0", ["--seq", "prach", "--v", "1"]),
        ("prach v=64 with N_CS=13", ["--seq", "prach", "--ncs", "1", "--v",
                                     "64"]),
        ("prach rate too low", ["--seq", "prach", "--rate", "500"]),
):
    gen(args + ["--out", path("never.raw")], expect=2, label="refuse " + label)

# ---------------------------------------------------------------------------
# 3. LTE PRS.
# ---------------------------------------------------------------------------

def cinit_published(ns, l, n_id_prs):
    """TS 36.211 6.10.4.1, transcribed from the clause."""
    lo = n_id_prs % 512
    return (2 ** 28 * (n_id_prs // 512)
            + 2 ** 10 * (7 * (ns + 1) + l + 1) * (2 * lo + 1)
            + 2 * lo + 1)                       # N_CP = 1, normal CP


def k_published(n_rb_dl, n_rb_prs, l, m, v_shift):
    """TS 36.211 6.10.4.2, normal CP, no frequency hopping, transcribed."""
    return 6 * m + (n_rb_dl - n_rb_prs) + (6 - l + v_shift) % 6


sweep = [(ns, l, pci) for ns in (0, 1, 5, 19) for l in (1, 2, 3, 5, 6)
         for pci in (0, 1, 7, 100, 503, 600, 4095)]
bad_cinit = [s for s in sweep if phy_seqs.prs_cinit(*s) != cinit_published(*s)]
check("published-cinit-formula", not bad_cinit,
      "%d of %d differ, e.g. %r" % (len(bad_cinit), len(sweep), bad_cinit[:3]))

bad_term = [n for n in (512, 600, 4095)
            if phy_seqs.prs_cinit(0, 3, n) - cinit_published(0, 3, n) != 0
            or phy_seqs.prs_cinit(0, 3, n) - (2 ** 28 * (n // 512))
            != cinit_published(0, 3, n) - (2 ** 28 * (n // 512))]
check("published-cinit-leading-term", not bad_term, repr(bad_term))

# continuity with tools/lte_phy.py: the PRS seed for a PCI must be that file's
# own CRS seed, and the bits must be its own Gold generator -- not a copy.
check("continuity-imports-lte_phy",
      getattr(phy_seqs, "lte_phy", None) is lte_phy)
crs_bad = [(ns, l, pci) for ns in (0, 1, 9, 19) for l in (1, 2, 3, 5, 6)
           for pci in (0, 1, 3, 100, 503)
           if phy_seqs.prs_cinit(ns, l, pci) != lte_phy.crs_cinit(ns, l, pci)]
check("continuity-cinit-equals-crs-cinit", not crs_bad,
      "%d differ, e.g. %r" % (len(crs_bad), crs_bad[:3]))

gold_bad = []
for ns, l, pci in ((0, 3, 0), (0, 3, 7), (1, 2, 100), (19, 6, 503)):
    seed = phy_seqs.prs_cinit(ns, l, pci)
    got = phy_seqs.prs_sequence(seed)
    bits = lte_phy.gold_sequence(seed, 440)
    want_re = (1.0 - 2.0 * np.asarray(bits[0::2], dtype=np.float64)) / np.sqrt(2)
    want_im = (1.0 - 2.0 * np.asarray(bits[1::2], dtype=np.float64)) / np.sqrt(2)
    if (np.abs(got.real - want_re).max() > 1e-6
            or np.abs(got.imag - want_im).max() > 1e-6):
        gold_bad.append((ns, l, pci))
check("continuity-gold-bits-equal-lte_phy", not gold_bad, repr(gold_bad))

tsv, _ = gen(["--seq", "prs", "--pci", "7", "--secs", "0.01", "--out",
              path("r.cf32")], label="prs pci=7")
if tsv:
    check("prs-frame-geometry",
          tsv.get("symbols_per_frame") == "80"
          and tsv.get("re_per_symbol") == "220"
          and tsv.get("samples_per_frame") == "17600"
          and tsv.get("samples") == "17600"
          and tsv.get("rate") == "1760000"
          and tsv.get("bytes") == str(17600 * 8)
          and file_size("r.cf32") == 17600 * 8,
          "samples=%s rate=%s" % (tsv.get("samples"), tsv.get("rate")))
    check("prs-cinit-row", tsv.get("cinit_ns0_l3")
          == str(cinit_published(0, 3, 7)),
          "tool=%s want=%d" % (tsv.get("cinit_ns0_l3"),
                               cinit_published(0, 3, 7)))
    check("prs-rate-honesty",
          tsv.get("requested_rate") == "20000000"
          and tsv.get("samples_are", "").startswith("the QPSK sequence")
          and "no OFDM grid" in tsv.get("rate_note", ""))
    check("prs-samples-not-grid",
          "no IFFT" in tsv.get("samples_are", ""))
    x = read_cf32("r.cf32")
    check("invariant-constant-modulus",
          np.abs(np.abs(x) - 1.0).max() < 1e-6,
          "max||r|-1|=%.3g" % np.abs(np.abs(x) - 1.0).max())
    q = 1.0 / np.sqrt(2.0)
    check("invariant-qpsk-constellation",
          np.abs(np.abs(x.real) - q).max() < 1e-6
          and np.abs(np.abs(x.imag) - q).max() < 1e-6)
    # first symbol of the frame: r(ns=0, l=3) from the clause's own seed
    seed = cinit_published(0, 3, 7)
    bits = lte_phy.gold_sequence(seed, 440)
    want = ((1.0 - 2.0 * np.asarray(bits[0::2], dtype=np.float64))
            + 1j * (1.0 - 2.0 * np.asarray(bits[1::2], dtype=np.float64))) \
        / np.sqrt(2.0)
    check("published-sequence-first-symbol",
          np.abs(x[:220] - want).max() < 1e-6,
          "max|diff|=%.3g" % np.abs(x[:220] - want).max())

    remap = tsv.get("mapping_file", "")
    check("prs-mapping-file-written", remap and os.path.getsize(remap) > 0,
          remap)
    rows = []
    if remap and os.path.exists(remap):
        for line in open(remap):
            if line.startswith("#") or line.startswith("ns_parity"):
                continue
            parts = line.rstrip("\n").split("\t")
            if len(parts) == 5:
                rows.append(tuple(int(v) for v in parts))
    check("prs-mapping-rows", len(rows) == int(tsv.get("mapping_rows", "0"))
          and len(rows) == 1600, "%d rows" % len(rows))
    v_shift = 7 % 6
    badk = []
    for ns_parity, l, m, mprime, k in rows:
        if (k != k_published(100, 100, l, m, v_shift)
                or mprime != m + 110 - 100
                or not 0 <= k <= 12 * 100 - 1):
            badk.append((ns_parity, l, m, k))
    check("published-k-formula", not badk,
          "%d bad, e.g. %r" % (len(badk), badk[:3]))
    per_sym = {}
    for ns_parity, l, m, mprime, k in rows:
        per_sym.setdefault((ns_parity, l), []).append(k)
    shape_bad = [key for key, ks in per_sym.items() if len(ks) != 200]
    check("invariant-200-re-per-symbol", not shape_bad, repr(shape_bad))
    pattern_bad = []
    for (ns_parity, l), ks in per_sym.items():
        want_mod = (6 - l + v_shift) % 6
        if (sorted(ks) != ks or any((k - ks[0]) % 6 for k in ks)
                or any(k % 6 != want_mod for k in ks)):
            pattern_bad.append((ns_parity, l, want_mod,
                                [k % 6 for k in ks[:3]]))
    check("published-diagonal-k-pattern", not pattern_bad, repr(pattern_bad))
    check("prs-l-sets", set(per_sym) == {(0, 3), (0, 5), (0, 6),
                                         (1, 1), (1, 2), (1, 3), (1, 5),
                                         (1, 6)}, repr(sorted(per_sym)))

# a narrower PRS bandwidth: N_RB_PRS = 25 in a 100-RB cell, so the map must
# start 75 PRBs up and read r from m' = m + 85.
tsv, _ = gen(["--seq", "prs", "--pci", "7", "--n-rb-prs", "25",
              "--n-rb-dl", "100", "--secs", "0.01", "--out",
              path("r25.cf32")], label="prs n_rb_prs=25")
if tsv:
    check("prs-bandwidth-rows",
          tsv.get("k_offset") == "75" and tsv.get("m_prime_offset") == "85"
          and tsv.get("n_rb_prs") == "25")
    remap = tsv["mapping_file"]
    rows = [tuple(int(v) for v in line.split("\t")) for line in open(remap)
            if not (line.startswith("#") or line.startswith("ns_parity"))]
    bad = [(l, m, k) for ns_parity, l, m, mprime, k in rows
           if k != k_published(100, 25, l, m, 1) or mprime != m + 85]
    check("prs-narrow-k-formula", not bad and len(rows) == 400,
          "%d rows, %d bad" % (len(rows), len(bad)))

for label, args in (
        ("prs pci=504", ["--seq", "prs", "--pci", "504"]),
        ("prs pci=-1", ["--seq", "prs", "--pci", "-1"]),
        ("prs n_rb_prs=7", ["--seq", "prs", "--n-rb-prs", "7"]),
        ("prs n_rb_prs>n_rb_dl", ["--seq", "prs", "--n-rb-prs", "50",
                                  "--n-rb-dl", "25"]),
):
    gen(args + ["--out", path("never.raw")], expect=2, label="refuse " + label)

# ---------------------------------------------------------------------------
# summary
# ---------------------------------------------------------------------------

check("tsv-required-rows", not MISSING_ROWS,
      "%d missing, e.g. %r" % (len(MISSING_ROWS), MISSING_ROWS[:4]))

if FAILS:
    print("summary\tchecks=%d pass=%d fail=%d"
          % (CHECKS[0], CHECKS[0] - len(FAILS), len(FAILS)))
    print("RESULT FAIL(%d)" % len(FAILS))
    sys.exit(1)
print("summary\tchecks=%d pass=%d fail=0" % (CHECKS[0], CHECKS[0]))
print("RESULT PASS")
sys.exit(0)
PYEOF
rc=$?
case "$rc" in
    0|1|2) exit "$rc" ;;
    *)     exit 1 ;;
esac
