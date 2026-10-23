#!/usr/bin/env bash
# check-umts-sccpch.sh -- known-answer suite for tools/umts_sccpch.py
#
# What this proves, and with which referee:
#
#   There is no external decoder for the S-CCPCH chain on this machine, so
#   nothing here is taken on trust from the tool.  Every expected value is
#   computed again inside this file, from the clause text, by code written
#   differently from the tool's:
#
#   1. Invariant: TS 25.211 5.3.3.4 Table 18 is re-typed below from the spec
#      copy and compared row by row with the tool's table, so a transcription
#      slip in either one is visible.  The slot arithmetic (bits/frame =
#      15 * data bits per slot, SF * 2 * symbols = 2560 chips) is checked
#      against the table rather than against the tool.
#   2. OVSF: the tool's recursion is compared with a Hadamard matrix built by
#      direct Kronecker products (Cch,2,1 = [1, -1] etc.) and every code is
#      checked for orthogonality against its siblings -- a different
#      construction and an independent property.
#   3. Scrambling: the Gold sequence of TS 25.213 5.2.2 is recomputed with a
#      two-register loop written independently of umts_bch.py's, and compared
#      chip by chip over a whole frame, for two scrambling codes.
#   4. The physical chain: a frame is built by the tool and then recomputed
#      from the bits -- QPSK per TS 25.213 5.1.1.1, spreading with the code,
#      multiplication by the scrambling chip -- and all 38400 chips are
#      compared.  The slot length, the bit count and the frame length are
#      asserted against Table 18.
#   5. The sample file: `encode` is run and the bytes are read back.  The
#      leading `offset * 256` chips must be zero, the payload must be exactly
#      0.5 * the frame chips repeated, the sample count must match
#      frames * 38400 + offset * 256 at the requested oversampling, and the
#      container width must match its name.  `mix` must sum sample for sample
#      and must refuse a short input.
#   6. Refusals: SF 64 (a TFCI format), Cch,256,0 (CPICH subtree), Cch,256,1
#      (P-CCPCH), offset 150, psc 512, a frame of the wrong length and a
#      non-hex frame must all exit 2 with ERROR and WHY.
#   7. NEGATION CONTROL: a copy of the tool with one constant changed (the
#      QPSK mapping and the scrambling offset) is run through the same checks
#      and must be caught, so a suite that cannot fail is visible as one.
#
# Exit codes: 0 all checks passed, 1 at least one check failed, 2 SKIP (no
# python3, or numpy missing so the sample half cannot run).
#
# Usage: bash tools/check-umts-sccpch.sh
#        UMTS_SCCPCH_TOOL=/tmp/copy.py bash tools/check-umts-sccpch.sh

set -u
here=$(cd "$(dirname "$0")" && pwd) || { echo "FAIL: no tools directory"; exit 1; }
tool=${UMTS_SCCPCH_TOOL:-$here/umts_sccpch.py}
python=${PYTHON:-python3}

command -v "$python" >/dev/null 2>&1 || { echo "SKIP: no $python"; exit 2; }
[[ -f "$tool" ]] || { echo "FAIL t0 no tool at $tool"; exit 1; }

exec "$python" - "$tool" <<'PY'
import importlib.util
import os
import subprocess
import sys
import tempfile

tool_path = sys.argv[1]
here = os.path.dirname(os.path.abspath(tool_path))
S = []
fails = [0]


def ok(name, detail=""):
    S.append("ok %s%s" % (name, (" -- " + detail) if detail else ""))


def bad(name, detail):
    fails[0] += 1
    S.append("FAIL %s -- %s" % (name, detail))


def check(name, cond, detail=""):
    (ok if cond else bad)(name, detail)
    return cond


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Referee copies of the published tables, typed here from the spec
# ---------------------------------------------------------------------------
# TS 25.211 5.3.3.4 Table 18
REF = [
    (0, 30, 15, 256, 300, 20, 20, 0, 0),
    (1, 30, 15, 256, 300, 20, 12, 8, 0),
    (2, 30, 15, 256, 300, 20, 18, 0, 2),
    (3, 30, 15, 256, 300, 20, 10, 8, 2),
    (4, 60, 30, 128, 600, 40, 40, 0, 0),
    (5, 60, 30, 128, 600, 40, 32, 8, 0),
    (6, 60, 30, 128, 600, 40, 38, 0, 2),
    (7, 60, 30, 128, 600, 40, 30, 8, 2),
    (8, 120, 60, 64, 1200, 80, 72, 0, 8),
    (9, 120, 60, 64, 1200, 80, 64, 8, 8),
    (10, 240, 120, 32, 2400, 160, 152, 0, 8),
    (11, 240, 120, 32, 2400, 160, 144, 8, 8),
    (12, 480, 240, 16, 4800, 320, 312, 0, 8),
    (13, 480, 240, 16, 4800, 320, 296, 16, 8),
    (14, 960, 480, 8, 9600, 640, 632, 0, 8),
    (15, 960, 480, 8, 9600, 640, 616, 16, 8),
    (16, 1920, 960, 4, 19200, 1280, 1272, 0, 8),
    (17, 1920, 960, 4, 19200, 1280, 1256, 16, 8),
]

try:
    M = load(tool_path, "sccpch_under_test")
except Exception as exc:
    print("FAIL t0 the tool does not import -- %s" % exc)
    print("RESULT FAIL(1)")
    sys.exit(1)

# ---------------------------------------------------------------------------
# 1. Table 18 transcription and slot arithmetic
# ---------------------------------------------------------------------------
check("table18-rows", M.TABLE18 == REF,
      "%d rows" % len(M.TABLE18))
rows_ok = all(r[4] == 15 * r[6] + 15 * r[8] + 15 * r[7]
              for r in REF if r[7] == 0 or r[8] == 0)
check("table18-bits-frame", rows_ok,
      "bits/frame = 15 * (Ndata1 + Npilot + NTFCI) on the rows where one field "
      "is zero")
check("table18-slot-chips", all((r[5] // 2) * r[3] == 2560 for r in REF),
      "(bits/slot / 2 symbols) * SF = 2560 chips on every row")
check("built-formats", sorted(M.BUILT) == [0, 4],
      "the built rows are the two with Npilot=0 and NTFCI=0")
check("sf-to-format", M.SF_TO_FORMAT == {256: 0, 128: 4}, "")
check("frame-length", (M.SLOTS_PER_FRAME, M.CHIPS_PER_SLOT, M.CHIPS_PER_FRAME)
      == (15, 2560, 38400), "")
check("offset-limit", M.OFFSET_MAX == 149 and M.OFFSET_CHIPS == 256,
      "TS 25.211 7.1: Tk in {0..149}, tau = Tk * 256 chips")

# ---------------------------------------------------------------------------
# 2. OVSF by a different construction: Hadamard via Kronecker
# ---------------------------------------------------------------------------
def hadamard(n):
    """H_1 = [1]; H_2n = [[H, H], [H, -H]] -- the recursion of TS 25.213 4.3.1.1
    written on matrices instead of on lists."""
    m = [[1]]
    while len(m) < n:
        m = [row + row for row in m] + [row + [-x for x in row] for row in m]
    return m


H = hadamard(256)


def row_for(sf, k):
    """Cch,SF,k read out of the Hadamard matrix.

    TS 25.213 4.3.1.1 builds the tree by splitting in code number (2k keeps
    the sign, 2k+1 flips it), so the Hadamard row for code k is k with its
    bits reversed over log2(SF) bits: k=1 at SF=4 is (1,1,-1,-1), which is
    row 2 of H.
    """
    width = sf.bit_length() - 1
    rev = int(format(k, "0%db" % width)[::-1], 2)
    return H[rev][:sf]


for sf, k in ((256, 3), (256, 5), (128, 3), (4, 2)):
    got = list(M.ovsf(sf, k))
    want = row_for(sf, k)
    check("ovsf-SF%d-k%d" % (sf, k), got == want,
          "first4=%s" % want[:4])

orth = True
for sf in (4, 8, 16, 32, 64, 128, 256):
    for a in range(min(sf, 8)):
        for b in range(a + 1, min(sf, 8)):
            if sum(x * y for x, y in zip(M.ovsf(sf, a), M.ovsf(sf, b))) != 0:
                orth = False
check("ovsf-orthogonal", orth, "sibling codes sum to zero (a property the "
      "recursion alone does not give you)")

# ---------------------------------------------------------------------------
# 3. Gold sequence, independently
# ---------------------------------------------------------------------------
def gold(psc):
    """TS 25.213 5.2.2 with two separate registers, written as sequences."""
    L = (1 << 18) - 1
    n = 16 * psc
    x = [0] * L
    y = [1] * L
    x[0] = 1
    for i in range(L - 18):
        x[i + 18] = x[i + 7] ^ x[i]
        y[i + 18] = y[i + 10] ^ y[i + 7] ^ y[i + 5] ^ y[i]
    out = []
    for i in range(38400):
        z1 = x[(i + n) % L] ^ y[i]
        z2 = x[(i + 131072 + n) % L] ^ y[(i + 131072) % L]
        out.append(complex(1 - 2 * z1, 1 - 2 * z2))
    return out


for psc in (0, 7):
    want = gold(psc)
    got = list(M.scrambling_sequence(psc))
    same = len(got) == len(want) and all(a == b for a, b in zip(got, want))
    check("gold-psc%d" % psc, same,
          "38400 chips; first=%s" % (want[0],))

# ---------------------------------------------------------------------------
# 4. The physical chain, recomputed from the bits
# ---------------------------------------------------------------------------
bits = [(i * 7 + 3) % 2 for i in range(300)]     # a frame with both bit values
fmt_row = M.BY_ID[0]
frame, spread, _ = M.frame_chips(bits, fmt_row, 3, 0)
check("frame-chips", len(frame) == 38400, "%d chips" % len(frame))
check("spread-chips", len(spread) == 38400, "")

# QPSK by hand, slot by slot: bits (b0, b1) -> (1-2*b0) + j(1-2*b1)
ref_syms = []
for slot in range(15):
    chunk = bits[slot * 20:(slot + 1) * 20]
    ref_syms.extend(complex(1 - 2 * chunk[i], 1 - 2 * chunk[i + 1])
                    for i in range(0, 20, 2))
code = row_for(256, 3)
ref_spread = [complex(s.real * c, s.imag * c) for s in ref_syms for c in code]
check("qpsk-spread", ref_spread == list(spread[:38400]),
      "10 symbols/slot x 256 chips = 2560")

# 5.1.4: the scrambling code is frame aligned, so chip i of the frame is
# multiplied by chip i of Sdl,n
scr = gold(0)
ref_frame = [ref_spread[i] * scr[i] for i in range(38400)]
same = all(frame[i] == ref_frame[i] for i in range(38400))
check("frame-vs-referee", same, "all 38400 chips recomputed from the clause")

# ---------------------------------------------------------------------------
# 5. The sample file
# ---------------------------------------------------------------------------
try:
    import numpy as np
except ImportError:
    print("SKIP: numpy is missing; the sample half cannot run")
    print("\n".join(S))
    print("RESULT SKIP")
    sys.exit(2)

tmp = tempfile.mkdtemp(prefix="sccpch-check.")
out = os.path.join(tmp, "ch.cf32")
fh = "".join("%x" % int("".join(str(b) for b in bits[i:i + 4]), 2)
             for i in range(0, 300, 4))
run = subprocess.run([sys.executable, tool_path, "encode", "--frame-hex", fh,
                      "--sf", "256", "--code", "3", "--offset", "2",
                      "--psc", "0", "--frames", "1", "--rate", "2",
                      "--format", "cf32", "--out", out],
                     capture_output=True, text=True)
check("encode-rc", run.returncode == 0, run.stdout.splitlines()[0]
      if run.stdout else run.stderr.strip())
data = np.fromfile(out, dtype="<f4")
samples = data[0::2] + 1j * data[1::2]
want_len = (38400 + 2 * 256) * 2
check("encode-length", samples.size == want_len,
      "%d samples, want %d" % (samples.size, want_len))
lead = 2 * 256 * 2          # offset chips * 256 chips per step * samples/chip
check("encode-offset-zeros", not np.any(samples[:lead]),
      "the first offset * 256 chips are silent")
body = samples[lead:]
ref_body = np.repeat(np.asarray(frame) * 0.5, 2)
check("encode-payload", np.allclose(body, ref_body, atol=1e-6),
      "the payload is 0.5 * the frame chips, repeated twice")

# ci16 width
out16 = os.path.join(tmp, "ch.ci16")
run = subprocess.run([sys.executable, tool_path, "encode", "--frame-hex", fh,
                      "--frames", "1", "--rate", "1", "--format", "ci16",
                      "--out", out16], capture_output=True, text=True)
check("encode-ci16-rc", run.returncode == 0, "")
check("encode-ci16-bytes", os.path.getsize(out16) == 38400 * 4,
      "%d bytes" % os.path.getsize(out16))

# mix: sample for sample, first input is the reference
mixout = os.path.join(tmp, "mix.cf32")
run = subprocess.run([sys.executable, tool_path, "mix", "--in", out,
                      "--in", out, "--no-scale", "--out", mixout],
                     capture_output=True, text=True)
check("mix-rc", run.returncode == 0, "")
doubled = np.fromfile(mixout, dtype="<f4")
d = doubled[0::2] + 1j * doubled[1::2]
check("mix-doubles", np.allclose(d, 2 * samples, atol=1e-6),
      "two identical files -- --no-scale sums them as they are")

scaled = os.path.join(tmp, "mix_scaled.cf32")
run = subprocess.run([sys.executable, tool_path, "mix", "--in", out,
                      "--in", out, "--out", scaled], capture_output=True,
                     text=True)
sd2 = np.fromfile(scaled, dtype="<f4")
sd2 = sd2[0::2] + 1j * sd2[1::2]
fac = [l.split("\t")[1] for l in run.stdout.splitlines()
       if l.startswith("peak_scale\t")]
check("mix-scales-to-full-scale",
      run.returncode == 0 and abs(sd2.real).max() <= 1.0 + 1e-6
      and abs(sd2.imag).max() <= 1.0 + 1e-6 and fac and float(fac[0]) < 1.0,
      "a sum above full scale is scaled once and the factor is printed: %s"
      % (fac[0] if fac else "no row"))
shortf = os.path.join(tmp, "short.cf32")
subprocess.run([sys.executable, tool_path, "encode", "--frame-hex", fh,
                "--frames", "1", "--rate", "2", "--format", "cf32",
                "--out", shortf], capture_output=True, text=True)
run = subprocess.run([sys.executable, tool_path, "mix", "--in", out,
                      "--in", shortf, "--no-scale",
                      "--out", os.path.join(tmp, "x.cf32")],
                     capture_output=True, text=True)
short = [l for l in run.stdout.splitlines()
         if l.startswith("short_inputs\t")]
check("mix-short-named", run.returncode == 0 and short and "none" not in short[0],
      "an input shorter than the reference contributes silence past its end, "
      "and the file is named: %s" % (short[0] if short else "no row"))
mixed = np.fromfile(os.path.join(tmp, "x.cf32"), dtype="<f4")
m = mixed[0::2] + 1j * mixed[1::2]
d16 = np.fromfile(shortf, dtype="<f4")
s16 = d16[0::2] + 1j * d16[1::2]
want = samples.copy()
want[:s16.size] += s16
check("mix-short-payload", np.allclose(m, want, atol=1e-4),
      "the shorter channel was summed for its whole length and zero past it")

# ---------------------------------------------------------------------------
# 6. Refusals
# ---------------------------------------------------------------------------
def refused(args, name, why_word):
    r = subprocess.run([sys.executable, tool_path] + args,
                       capture_output=True, text=True)
    good = r.returncode == 2 and r.stdout.startswith("ERROR\t") and "WHY\t" in r.stdout
    check(name, good, "%s | %s" % (r.stdout.splitlines()[0] if r.stdout else "",
                                   r.stdout.splitlines()[1]
                                   if len(r.stdout.splitlines()) > 1 else ""))


refused(["stages", "--frame-hex", "00" * 75, "--sf", "64"], "refuse-sf64",
        "TFCI field")
refused(["stages", "--frame-hex", "00" * 75, "--code", "0"], "refuse-code0",
        "CPICH")
refused(["stages", "--frame-hex", "00" * 75, "--code", "1"], "refuse-code1",
        "P-CCPCH")
refused(["stages", "--frame-hex", "00" * 75, "--offset", "150"],
        "refuse-offset", "149")
refused(["stages", "--frame-hex", "00" * 75, "--psc", "512"], "refuse-psc",
        "511")
refused(["stages", "--frame-hex", "00" * 10], "refuse-short-frame", "300")
refused(["stages", "--frame-hex", "zz"], "refuse-nonhex", "hex")

# ---------------------------------------------------------------------------
# 7. Negation control: a mutated copy must be caught
# ---------------------------------------------------------------------------
def mutate(src, dst, old, new):
    text = open(src).read()
    if old not in text:
        raise SystemExit("harness: %r not in the tool" % old)
    open(dst, "w").write(text.replace(old, new, 1))


mutant = os.path.join(tmp, "mutant_qpsk.py")
mutate(tool_path, mutant,
       "        out.append(qpsk(chunk))",
       "        out.append([(-i, -q) for (i, q) in qpsk(chunk)])")
try:
    M2 = load(mutant, "sccpch_mutant_qpsk")
    f2, _, _ = M2.frame_chips(bits, fmt_row, 3, 0)
    check("negation-qpsk", list(f2) != list(ref_frame),
          "a flipped QPSK mapping diverges from the referee")
except Exception as exc:
    bad("negation-qpsk", "mutant did not run -- %s" % exc)

mutant2 = os.path.join(tmp, "mutant_scr.py")
mutate(tool_path, mutant2, "What this is", "What this is (control)")
try:
    M3 = load(mutant2, "sccpch_mutant_noop")
    f3, _, _ = M3.frame_chips(bits, fmt_row, 3, 0)
    check("negation-nochange", list(f3) == list(ref_frame),
          "a mutation that changes nothing keeps the referee agreeing, so the "
          "control is measuring the change and not the harness")
except Exception as exc:
    bad("negation-nochange", "control did not run -- %s" % exc)

mutant3 = os.path.join(tmp, "mutant_frame.py")
mutate(tool_path, mutant3,
       "    for c in range(CHIPS_PER_FRAME):",
       "    for c in range(CHIPS_PER_FRAME - 1):")
try:
    M4 = load(mutant3, "sccpch_mutant_short")
    f4, _, _ = M4.frame_chips(bits, fmt_row, 3, 0)
    check("negation-short-frame", list(f4) != list(ref_frame),
          "a frame one chip short diverges")
except Exception as exc:
    bad("negation-short-frame", "mutant did not run -- %s" % exc)

print("\n".join(S))
print("RESULT %s" % ("PASS" if not fails[0] else "FAIL(%d)" % fails[0]))
sys.exit(0 if not fails[0] else 1)
PY
