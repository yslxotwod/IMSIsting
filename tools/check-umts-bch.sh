#!/usr/bin/env bash
# Known-answer tests for tools/umts_bch.py.
#
# The chain has no external decoder on this machine, so nothing here is taken
# on trust from the tool: every expected value is computed again, in this
# file, from the clause that defines it, by different code --
#
#   * the CRC by writing the long division of TS 25.212 4.2.1.1 out bit by bit
#     (the tool runs an integer shift register instead),
#   * the convolutional code by a hand-written 9-stage shift register of the
#     generator exponents of TS 25.212 4.2.3.1 (the tool taps an integer),
#   * the rate matching output both by a literal 4.2.7.5 loop and by the
#     closed form of the same e/e_plus/e_minus arithmetic, plus the length
#     arithmetic of 4.2.7.2/4.2.7.2.1.3,
#   * the 2nd interleaving by filling an actual 30-column matrix (4.2.11),
#   * the P-CCPCH chips from the slot structure of TS 25.211 5.3.3.3, the
#     OVSF recursion of TS 25.213 4.3.1.1, the Gold recursion of 5.2.2 and the
#     QPSK mapping of 5.1.1.1,
#
# and then compared against what the tool prints and writes.  The negation
# controls at the end corrupt one constant inside a copy of the check's own
# logic and prove that the comparison notices, i.e. that these tests can fail.
#
# Output: "ok NN name" / "FAIL NN name -- detail" per test, then
# "RESULT PASS" or "RESULT FAIL(n)".  Exit 0 on PASS, 1 on FAIL, 2 on SKIP.

set -u

here=$(cd "$(dirname "$0")" && pwd) || { echo "FAIL: no tools directory"; exit 1; }
# UMTS_BCH_TOOL lets a copy of the tool be tested instead of the workspace one;
# it is how the negation control below is demonstrated end to end.
tool=${UMTS_BCH_TOOL:-$here/umts_bch.py}
python=${PYTHON:-python3}

command -v "$python" >/dev/null 2>&1 || { echo "SKIP: no $python"; exit 2; }
if ! "$python" -c 'import numpy' >/dev/null 2>&1; then
    echo "SKIP: numpy is missing; the sample writer needs it"
    exit 2
fi
if [ ! -f "$tool" ]; then
    echo "FAIL: $tool is missing"
    echo "RESULT FAIL(1)"
    exit 1
fi

exec "$python" - "$tool" <<'PY'
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile

import numpy as np

TOOL = sys.argv[1]
WORK = tempfile.mkdtemp(prefix="umts-bch-check.")

OK = 0
FAILS = []


def ok(name):
    global OK
    OK += 1
    print("ok %02d %s" % (OK, name))


def bad(name, detail):
    FAILS.append(name)
    print("FAIL %02d %s -- %s" % (OK + len(FAILS), name, detail))


def expect(name, cond, detail=""):
    if cond:
        ok(name)
    else:
        bad(name, detail or "assertion failed")
    return bool(cond)


def expect_eq(name, got, want):
    if got == want:
        return expect(name, True)
    return expect(name, False, "got %r, want %r" % (got, want))


def run_tool(tool, *args):
    p = subprocess.run([sys.executable, tool] + [str(a) for a in args],
                       capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


def run(*args):
    return run_tool(TOOL, *args)


def read_tsv(out):
    rows = []
    for line in out.splitlines():
        if not line.strip():
            continue
        key, _, value = line.partition("\t")
        rows.append((key, value))
    return rows


def tsv_map(rows):
    m = {}
    for k, v in rows:
        if k not in m:
            m[k] = v
        elif isinstance(m[k], list):
            m[k].append(v)
        else:
            m[k] = [m[k], v]
    return m


STAGE_RE = re.compile(r"^([0-9a-f]*) bits=(\d+) ref=(.*)$")


def stage_bits(rows):
    """Every `stage:<name>` row as a list of bits, with its declared length."""
    out = {}
    for k, v in rows:
        if not k.startswith("stage:"):
            continue
        m = STAGE_RE.match(v)
        if not m:
            raise SystemExit("FAIL: cannot parse stage row %r -> %r" % (k, v))
        h, n, _ref = m.group(1), int(m.group(2)), m.group(3)
        val = int(h, 16) if h else 0
        if len(h) * 4 < n:
            raise SystemExit("FAIL: stage %s declares %d bits in %d hex digits"
                             % (k, n, len(h)))
        out[k[len("stage:"):]] = [(val >> (n - 1 - i)) & 1 for i in range(n)]
    return out


def bits_of_hex(h):
    n = len(h) * 4
    v = int(h, 16)
    return [(v >> (n - 1 - i)) & 1 for i in range(n)]


# ---------------------------------------------------------------------------
# The clauses, re-derived here.
# ---------------------------------------------------------------------------

SLOTS = 15
CHIPS_SLOT = 2560
OFF = 256
NDATA1 = 18
NDATA2 = 0
DATA_CHIPS = CHIPS_SLOT - OFF
BITS_SLOT = NDATA1 + NDATA2
BITS_FRAME = BITS_SLOT * SLOTS                      # TS 25.211 5.3.3.3
SF = 256
CODE = 1
TB_BITS = 24
CRC_BITS = 16
TAIL = 8


def poly_from_terms(terms, deg):
    """Coefficient list, degree `deg` down to 0, of sum D**t."""
    return [1 if (deg - k) in terms else 0 for k in range(deg + 1)]


def mod_g(dividend, g):
    """Remainder of `dividend` modulo `g`, both coefficient lists MSB first."""
    rem = list(dividend)
    for i in range(len(rem) - len(g) + 1):
        if rem[i]:
            for j in range(len(g)):
                rem[i + j] ^= g[j]
    return rem[len(rem) - (len(g) - 1):]


CRC16_TERMS = (16, 12, 5, 0)        # TS 25.212 4.2.1.1: D16+D12+D5+1


def crc_parity(tb, terms=CRC16_TERMS):
    """TS 25.212 4.2.1.1: p1..p16, coefficient order D15..D0."""
    g = poly_from_terms(terms, CRC_BITS)
    return mod_g(list(tb) + [0] * CRC_BITS, g)


def crc_attach(tb, terms=CRC16_TERMS, reverse=True):
    """TS 25.212 4.2.1.2: b_k = p_(Li+1-(k-Ai)) for the parity bits."""
    p = crc_parity(tb, terms)
    return list(tb) + (list(reversed(p)) if reverse else list(p))


# TS 25.212 4.2.3.1: 561 octal and 753 octal written as D exponents.
G0_EXP = (8, 6, 5, 4, 0)             # 1 + D4 + D5 + D6 + D8
G1_EXP = (8, 7, 6, 5, 3, 1, 0)       # 1 + D + D3 + D5 + D6 + D7 + D8


def conv_encode(bits, g0=G0_EXP, g1=G1_EXP, k=9, tail=TAIL):
    """Hand-written K=9 shift register; sr[0] is the current input bit."""
    sr = [0] * k
    out = []
    for b in list(bits) + [0] * tail:
        sr = [b] + sr[:k - 1]
        out.append(sum(sr[d] for d in g0) % 2)
        out.append(sum(sr[d] for d in g1) % 2)
    return out


def rate_params():
    """TS 25.212 4.2.7.2, 4.2.7.2.1.1, 4.2.7.2.1.3, 4.2.7 formula (1)/(2)."""
    n = (TB_BITS + CRC_BITS + TAIL) * 2          # 4.2.3.1 output length
    ndata = 1 * 15 * (NDATA1 + NDATA2)           # 4.2.7.2, P = 1
    rm = 1                                       # 4.2.13.6: arbitrary
    z = (rm * n * ndata) // (rm * n)             # 4.2.7 formula (1)
    dn = z - 0 - n                               # 4.2.7 formula (2)
    return {
        "N": n, "Ndata": ndata, "Z": z, "dN": dn, "dN_max": dn,
        "e_ini": 1, "e_plus": 2 * n, "e_minus": 2 * dn,
        "G": n + dn, "X": n, "N_max": n,
    }


def rate_match_loop(x, prm):
    """TS 25.212 4.2.7.5 repetition branch, counting copies per input bit."""
    e = prm["e_ini"]
    out = []
    for b in x:
        copies = 1
        e -= prm["e_minus"]
        while e <= 0:
            copies += 1
            e += prm["e_plus"]
        out.extend([b] * copies)
    return out


def rate_match_closed(x, prm):
    """Same arithmetic, closed form: with e_ini = 1 the extras after m bits
    are ceil(m * e_minus / e_plus), i.e. ceil(29*m/16) here."""
    num = prm["e_minus"]
    den = prm["e_plus"]
    prev = 0
    out = []
    for m, b in enumerate(x, 1):
        cur = -((-num * m) // den)               # ceil(num*m/den)
        out.extend([b] * (1 + cur - prev))
        prev = cur
    return out


def ilv2_matrix(u, perm=None):
    """TS 25.212 4.2.11, on an actual matrix."""
    c2 = 30
    r2 = int(math.ceil(len(u) / float(c2)))
    mat = [[None] * c2 for _ in range(r2)]
    for k, b in enumerate(u):
        mat[k // c2][k % c2] = b
    if perm is None:
        perm = [0, 20, 10, 5, 15, 25, 3, 13, 23, 8, 18, 28, 1, 11, 21,
                6, 16, 26, 4, 14, 24, 19, 9, 29, 12, 2, 7, 22, 27, 17]
    out = []
    for j in range(c2):
        for r in range(r2):
            v = mat[r][perm[j]]
            if v is not None:
                out.append(v)
    return out


def ovsf_tree(sf, index):
    """TS 25.213 4.3.1.1, generated level by level from the index bits."""
    code = [1]
    depth = int(math.log2(sf))
    for level in range(depth):
        bit = (index >> (depth - 1 - level)) & 1
        lower = code if bit == 0 else [-c for c in code]
        code = code + lower
    return code


def gold_rails(psc, chips=SLOTS * CHIPS_SLOT):
    """TS 25.213 5.2.2 Rails Zn(i) and Zn((i+131072) mod (2^18-1))."""
    period = (1 << 18) - 1
    n = 16 * psc
    x = [0] * period
    y = [0] * period
    x[0] = 1
    for i in range(18):
        y[i] = 1
    for i in range(period - 18):
        x[i + 18] = x[i + 7] ^ x[i]
        y[i + 18] = y[i + 10] ^ y[i + 7] ^ y[i + 5] ^ y[i]
    si = []
    sq = []
    for i in range(chips):
        si.append(1 if (x[(i + n) % period] ^ y[i]) == 0 else -1)
        j = (i + 131072) % period
        sq.append(1 if (x[(j + n) % period] ^ y[j]) == 0 else -1)
    return si, sq


def frame_samples(ilv_bits, psc=0):
    """P-CCPCH frame from the slot structure, the OVSF code, QPSK and the
    frame-aligned scrambling code of TS 25.213 5.1.4."""
    syms = [(1.0 if ilv_bits[2 * m] == 0 else -1.0,
             1.0 if ilv_bits[2 * m + 1] == 0 else -1.0)
            for m in range(len(ilv_bits) // 2)]
    code = ovsf_tree(SF, CODE)
    spread = []
    for i, q in syms:
        for c in code:
            spread.append(complex(i * c, q * c))
    si, sq = gold_rails(psc)
    frame = [0j] * (SLOTS * CHIPS_SLOT)
    k = 0
    for slot in range(SLOTS):
        base = slot * CHIPS_SLOT + OFF
        for c in range(DATA_CHIPS):
            frame[base + c] = spread[k] * complex(si[base + c],
                                                  sq[base + c]) * 0.5
            k += 1
    return frame, spread


def read_samples(path, fmt):
    if fmt == "cf32":
        return np.fromfile(path, dtype="<c8")
    raw = np.fromfile(path, dtype="<i2" if fmt == "ci16" else np.uint8)
    if fmt == "ci16":
        return np.array(raw[0::2] + 1j * raw[1::2], dtype=np.complex128)
    return np.array((raw[0::2].astype(np.float64) - 127.5) / 127.0
                    + 1j * (raw[1::2].astype(np.float64) - 127.5) / 127.0)


WORKED = "012345"
tb = bits_of_hex(WORKED)
prm = rate_params()
crc = crc_attach(tb)
conv = conv_encode(crc)
rm = rate_match_loop(conv, prm)
ilv = ilv2_matrix(rm)
want_frame, want_spread = frame_samples(ilv, 0)

# ---------------------------------------------------------------------------
# 1. list
# ---------------------------------------------------------------------------

rc, out, err = run("list")
rows = read_tsv(out)
m = tsv_map(rows)
expect("list exits 0", rc == 0 and err == "", "rc=%d err=%r" % (rc, err))
expect("list names the built chain and the refused gaps",
       any(k == "chain" for k, _ in rows) and any(k == "refused" for k, _ in rows)
       and any(k == "limit" for k, _ in rows),
       "keys: %s" % sorted(set(k for k, _ in rows)))
expect("list carries the clause numbers of the chain",
       any("4.2.7.5" in v for k, v in rows if k == "chain")
       and any("5.3.3.3" in v for k, v in rows if k == "note"),
       "no clause references found")

# ---------------------------------------------------------------------------
# 2. stages: the bit vectors
# ---------------------------------------------------------------------------

rc, out, err = run("stages", "--bch-hex", WORKED)
STROWS = read_tsv(out)
st = stage_bits(STROWS)
expect("stages exits 0", rc == 0 and err == "", "rc=%d err=%r" % (rc, err))
expect_eq("stages carries the transport block verbatim", st.get("tb"), tb)

g = poly_from_terms(CRC16_TERMS, CRC_BITS)
rem = mod_g(list(tb) + [0] * CRC_BITS, g)
expect_eq("stage crc equals the long division of 4.2.1.1",
          st.get("crc"), list(tb) + list(reversed(rem)))
expect("4.2.1.1 divisibility: block*D^16 + p1..p16 has zero remainder",
       mod_g(list(tb) + rem, g) == [0] * CRC_BITS,
       "remainder %r" % mod_g(list(tb) + rem, g))
expect("4.2.1.2 transmits the parity bits in the p16..p1 order",
       st.get("crc", [0] * 39 + [1])[24:] == list(reversed(rem)),
       "tail %r" % (st.get("crc") or [None] * 40)[24:])

expect_eq("stage conv equals the 9-stage shift register of 4.2.3.1",
          st.get("conv"), conv)
sr = [0] * 9
for b in tb + rem:
    sr = [b] + sr[:8]
for _ in range(TAIL):
    sr = [0] + sr[:8]
expect("8 tail bits flush the encoder register back to zero",
       sr == [0] * 9, "register %r" % sr)

expect_eq("rate matching length is N_i,* + dN_i,* of 4.2.7.2.1.3",
          len(st.get("ratematch", [])), prm["N"] + prm["dN"])
expect("4.2.7.2 parameter arithmetic closes",
       prm["Ndata"] == 270 and prm["dN"] == 174 and prm["G"] == 270
       and prm["e_plus"] == 192 and prm["e_minus"] == 348,
       str(prm))
params = {k[len("param:"):]: v for k, v in STROWS if k.startswith("param:")}
expect("stages reports the 4.2.7.2.1.3 parameters it used",
       params.get("Ndata_star") == "270" and params.get("delta_N") == "174"
       and params.get("e_plus") == "192" and params.get("e_minus") == "348"
       and params.get("e_ini") == "1",
       str(params))
expect_eq("stage ratematch equals the literal 4.2.7.5 loop",
          st.get("ratematch"), rm)
expect_eq("stage ratematch equals the closed form of the same arithmetic",
          st.get("ratematch"), rate_match_closed(conv, prm))

expect_eq("stage ilv2 equals the 4.2.11 matrix interleaver",
          st.get("ilv2"), ilv)
expect("4.2.11 row count R2 = 9 for U = 270",
       int(math.ceil(len(rm) / 30.0)) == 9, "R2 from U=%d" % len(rm))

slots = [st.get("slot%02d" % s) for s in range(SLOTS)]
expect("stages splits the frame into 15 slots of 18 bits",
       all(s is not None and len(s) == BITS_SLOT for s in slots),
       "lengths %r" % [None if s is None else len(s) for s in slots])
flat = [b for s in slots for b in (s or [])]
expect_eq("4.2.12.2 maps the bits in ascending order", flat, ilv)

qpsk_i = st.get("qpsk_i") or []
qpsk_q = st.get("qpsk_q") or []
expect("QPSK rows are 135 symbols on I and on Q",
       len(qpsk_i) == len(ilv) // 2 and len(qpsk_q) == len(ilv) // 2,
       "len %d / %d" % (len(qpsk_i), len(qpsk_q)))
expect("5.1.1.1 maps even bits to I and odd bits to Q",
       qpsk_i == [0 if ilv[2 * k] == 0 else 1 for k in range(len(ilv) // 2)]
       and qpsk_q == [0 if ilv[2 * k + 1] == 0 else 1
                      for k in range(len(ilv) // 2)])

# ---------------------------------------------------------------------------
# 3. chip level stages
# ---------------------------------------------------------------------------

code = ovsf_tree(SF, CODE)
expect("Cch,256,1 is 256 chips of 128 +1 then 128 -1",
       code == [1] * 128 + [-1] * 128)
expect("Cch,256,1 is orthogonal to Cch,256,0",
       sum(a * b for a, b in zip(code, ovsf_tree(SF, 0))) == 0)

spread_bits = []
for i, q in [(1.0 if ilv[2 * k] == 0 else -1.0,
              1.0 if ilv[2 * k + 1] == 0 else -1.0)
             for k in range(len(ilv) // 2)]:
    for c in code:
        spread_bits.append(0 if i * c > 0 else 1)
expect_eq("stage spread_i is the 5.1.2 spread of the QPSK symbols",
          st.get("spread_i"), spread_bits)
expect("the spread frame is 15 slots of 9 symbols of 256 chips",
       len(st.get("spread_i") or []) == SLOTS * DATA_CHIPS == 34560,
       "len %r" % (None if not st.get("spread_i")
                   else len(st.get("spread_i"))))

si, sq = gold_rails(0)
expect_eq("stage scrambling_i is the Zn(i) rail of 5.2.2",
          st.get("scrambling_i"), [0 if v > 0 else 1 for v in si])
expect_eq("stage scrambling_q is the Zn(i+131072) rail of 5.2.2",
          st.get("scrambling_q"), [0 if v > 0 else 1 for v in sq])
expect("Sdl,n has magnitude sqrt(2) on every chip",
       all(si[i] * si[i] + sq[i] * sq[i] == 2 for i in range(len(si))))

# ---------------------------------------------------------------------------
# 4. encode: files and waveform
# ---------------------------------------------------------------------------

for fmt, item in (("cf32", 8), ("ci16", 4), ("cu8", 2)):
    path = os.path.join(WORK, "f.%s" % fmt)
    rc, out, err = run("encode", "--bch-hex", WORKED, "--out", path,
                       "--format", fmt)
    rows = read_tsv(out)
    m = tsv_map(rows)
    expect("encode %s exits 0" % fmt, rc == 0 and err == "",
           "rc=%d err=%r" % (rc, err))
    expect_eq("encode %s sample count is frames*15*2560" % fmt,
              int(m.get("samples", -1)), SLOTS * CHIPS_SLOT)
    expect_eq("encode %s byte count matches the container" % fmt,
              int(m.get("bytes", -1)), int(m.get("samples", 0)) * item)
    expect_eq("encode %s writes the declared byte count" % fmt,
              os.path.getsize(path), int(m.get("bytes", 0)))
    expect_eq("encode %s reports the peak full scale" % fmt,
              m.get("peak_full_scale"), {"cf32": "1.0000", "ci16": "32767.0000",
                                        "cu8": "127.5000"}[fmt])
    got = read_samples(path, fmt)
    if fmt == "cf32":
        expect("cf32 waveform equals the clause-by-clause recomputation",
               got.size == len(want_frame)
               and bool(np.all(np.abs(got - np.asarray(want_frame)) == 0)),
               "max diff %r" % (float(np.max(np.abs(
                   got - np.asarray(want_frame)))) if got.size == len(want_frame)
                   else "size %d vs %d" % (got.size, len(want_frame))))

    hexrow = m.get("hex") or ""
    nibbles = len(hexrow) * 4
    word = int(hexrow, 16) if hexrow else 0
    allbits = [(word >> (nibbles - 1 - k)) & 1 for k in range(nibbles)]
    expect_eq("encode %s reports the 270-bit 4.2.11 output in its hex row" % fmt,
              allbits[nibbles - len(ilv):], ilv)
    if fmt == "cf32":
        d = got
        off_ok = True
        on_ok = True
        for s in range(SLOTS):
            base = s * CHIPS_SLOT + OFF
            gap = d[s * CHIPS_SLOT:base]
            if not bool(np.all(gap == 0)):
                off_ok = False
            window = d[base:base + DATA_CHIPS]
            if not bool(np.all((np.abs(window.real) == 1)
                               | (np.abs(window.imag) == 1))):
                on_ok = False
        expect("the 15 x 256 SCH gaps of 5.3.3.3 are silent", off_ok)
        expect("the 15 x 2304 data chips sit at a full-scale component", on_ok)
        expect("the dataless gaps are the only zeros",
               int(np.sum(d == 0)) == SLOTS * OFF,
               "%d zeros" % int(np.sum(d == 0)))

# extra frames and sample rates
p2 = os.path.join(WORK, "two.cf32")
rc, out, err = run("encode", "--bch-hex", WORKED, "--out", p2, "--frames", "2")
m2 = tsv_map(read_tsv(out))
d2 = read_samples(p2, "cf32")
expect("2 frames contain frame 0 twice",
       rc == 0 and d2.size == 2 * len(want_frame)
       and bool(np.all(d2[:len(want_frame)] == d2[len(want_frame):]))
       and bool(np.all(np.abs(d2[:len(want_frame)]
                              - np.asarray(want_frame)) == 0)),
       "rc=%d size=%d" % (rc, d2.size))
expect_eq("frames row counts frames", m2.get("frames"), "2")

p3 = os.path.join(WORK, "sps4.cf32")
rc, out, err = run("encode", "--bch-hex", WORKED, "--out", p3, "--rate", "4")
d3 = read_samples(p3, "cf32")
expect("--rate 4 holds every chip flat four times",
       rc == 0 and d3.size == 4 * len(want_frame)
       and bool(np.all(d3.reshape(-1, 4) == d3.reshape(-1, 4)[:, :1]))
       and bool(np.all(np.abs(d3.reshape(-1, 4)[:, 0]
                              - np.asarray(want_frame)) == 0)),
       "rc=%d size=%d" % (rc, d3.size))

# a different scrambling code
other, _ = frame_samples(ilv, 511)
p4 = os.path.join(WORK, "psc.cf32")
rc, out, err = run("encode", "--bch-hex", WORKED, "--out", p4, "--psc", "511")
d4 = read_samples(p4, "cf32")
m4 = tsv_map(read_tsv(out))
expect_eq("--psc 511 reports scrambling code 16*511", m4.get("scrambling_code"),
          "8176")
expect("--psc 511 changes the waveform to the 5.2.2 code n=8176",
       rc == 0 and bool(np.all(np.abs(d4 - np.asarray(other)) == 0)),
       "rc=%d" % rc)
expect("different primary codes give different chips",
       bool(np.any(d4 != read_samples(os.path.join(WORK, "f.cf32"), "cf32"))))

# the MIB is repeated once per MIB period (80 ms), not in every frame of a
# SIB cycle: a file built for a whole S-CCPCH cycle has to carry the block in
# its own frames and silence elsewhere, or the same MIB lands in every TTI
p5 = os.path.join(WORK, "period.cf32")
rc, out, err = run("encode", "--bch-hex", WORKED, "--out", p5, "--frames", "8",
                   "--at-start", "2", "--period", "8")
m5 = tsv_map(read_tsv(out))
d5 = read_samples(p5, "cf32")
expect("--frames 8 --at-start 2 --period 8 exits 0", rc == 0, "rc=%d" % rc)
expect_eq("the placement is printed", (m5.get("at_start"), m5.get("period")),
          ("2", "8"))
expect_eq("one frame of the eight is written", m5.get("frames_written"), "1")
expect_eq("the file still holds every frame", int(m5.get("samples", -1)),
          8 * SLOTS * CHIPS_SLOT)
expect("frame 2 is the BCH and the other seven are silent",
       bool(np.all(d5[2 * len(want_frame):3 * len(want_frame)]
                   == np.asarray(want_frame)))
       and not bool(np.any(d5[:2 * len(want_frame)]))
       and not bool(np.any(d5[3 * len(want_frame):])),
       "zeros %d" % int(np.sum(d5 == 0)))

p6 = os.path.join(WORK, "period2.cf32")
rc, out, err = run("encode", "--bch-hex", WORKED, "--out", p6, "--frames", "4",
                   "--at-start", "0", "--period", "2")
m6 = tsv_map(read_tsv(out))
d6 = read_samples(p6, "cf32")
expect_eq("--period 2 writes two of four frames", m6.get("frames_written"), "2")
expect("--period 2 puts the block in frames 0 and 2",
       bool(np.all(d6[0:len(want_frame)] == np.asarray(want_frame)))
       and bool(np.all(d6[2 * len(want_frame):3 * len(want_frame)]
                       == np.asarray(want_frame)))
       and not bool(np.any(d6[len(want_frame):2 * len(want_frame)]))
       and not bool(np.any(d6[3 * len(want_frame):])))

# ---------------------------------------------------------------------------
# 5. refusals and usage
# ---------------------------------------------------------------------------

def refuse(name, args, needle=None):
    rc, out, err = run(*args)
    good = (rc == 2 and "ERROR\t" in err and "WHY\t" in err
            and (needle is None or needle in err))
    return expect(name, good, "rc=%d err=%r" % (rc, err))


refuse("a 20-bit transport block is refused", ["encode", "--bch-hex", "12345",
                                               "--out", os.path.join(WORK, "x")],
       "24 bits")
refuse("a non-hex transport block is refused",
       ["stages", "--bch-hex", "zzzzzz"], "not hexadecimal")
refuse("--psc 512 is refused", ["encode", "--bch-hex", WORKED, "--out",
                                os.path.join(WORK, "x"), "--psc", "512"])
refuse("--rate 0 is refused", ["encode", "--bch-hex", WORKED, "--out",
                               os.path.join(WORK, "x"), "--rate", "0"])
refuse("--frames 0 is refused", ["encode", "--bch-hex", WORKED, "--out",
                                 os.path.join(WORK, "x"), "--frames", "0"])
refuse("--format qpsk is refused",
       ["encode", "--bch-hex", WORKED, "--out", os.path.join(WORK, "x"),
        "--format", "qpsk"])
refuse("--out /dev/stdout is refused", ["encode", "--bch-hex", WORKED,
                                        "--out", "/dev/stdout"])
rc, out, err = run("frobnicate")
expect("an unknown command exits 2", rc == 2, "rc=%d" % rc)
rc, out, err = run()
expect("no command exits 2", rc == 2, "rc=%d" % rc)

rc, out, err = run("stages", "--bch-hex", WORKED)
expect("stages carries a limit row for every assumption",
       sum(1 for k, _ in read_tsv(out) if k == "limit") >= 4,
       "%d limit rows" % sum(1 for k, _ in read_tsv(out) if k == "limit"))

# ---------------------------------------------------------------------------
# 6. negation control: corrupt one constant in a copy of this file's logic
# ---------------------------------------------------------------------------

corrupt_g1 = conv_encode(crc, g1=(8, 7, 6, 5, 3, 1))          # dropped D^0 tap
expect("NEGATION: flipping G1's constant breaks the conv comparison",
       corrupt_g1 != conv and corrupt_g1 != st.get("conv"),
       "a corrupted G1 still matches the tool, so the conv test cannot fail")

corrupt_crc = crc_attach(tb, terms=(16, 12, 5))               # dropped +1
expect("NEGATION: dropping the CRC's low-order term breaks the CRC comparison",
       corrupt_crc != crc and corrupt_crc != st.get("crc"),
       "a corrupted CRC polynomial still matches the tool")

corrupt_rm = rate_match_loop(conv, dict(prm, e_minus=prm["e_minus"] + 2))
expect("NEGATION: a corrupted e_minus changes the rate-matched vector",
       corrupt_rm != rm and len(corrupt_rm) != len(rm),
       "corrupted e_minus did not change the pattern")

corrupt_ilv = ilv2_matrix(rm, perm=list(range(30)))
expect("NEGATION: dropping Table 7 changes the 2nd interleaver output",
       corrupt_ilv != ilv)

corrupt_code = [1] * 256
expect("NEGATION: the wrong channelisation code gives different chips",
       corrupt_code != code)


def run_mutant(old_text, new_text):
    """A copy of the tool with one constant changed, run on the same input."""
    src = open(TOOL).read()
    if src.count(old_text) != 1:
        return None
    path = os.path.join(WORK, "mutant.py")
    with open(path, "w") as fh:
        fh.write(src.replace(old_text, new_text))
    rc, out, err = run_tool(path, "stages", "--bch-hex", WORKED)
    return rc, stage_bits(read_tsv(out))


mut = run_mutant("G1 = 0o753", "G1 = 0o751")
expect("NEGATION: a one-bit change to G1 inside the tool fails the conv test",
       mut is not None and mut[0] == 0
       and mut[1].get("conv") != conv
       and mut[1].get("conv") != st.get("conv")
       and mut[1].get("ratematch") != st.get("ratematch"),
       "mutant run did not diverge, so the conv assertion is not load bearing")

mut = run_mutant("GCRC16 = 0b10001000000100001", "GCRC16 = 0b10001000000100000")
expect("NEGATION: dropping the CRC's +1 inside the tool fails the CRC test",
       mut is not None and mut[0] == 0
       and mut[1].get("crc") != st.get("crc")
       and mut[1].get("crc") != list(tb) + list(reversed(rem)),
       "mutant run did not diverge, so the CRC assertion is not load bearing")

mut = run_mutant("GCRC16 = 0b10001000000100001", "GCRC16 = 0b10001000000100001")
expect("NEGATION control: an unmodified copy still matches (no false negative)",
       mut is not None and mut[0] == 0 and mut[1].get("crc") == st.get("crc")
       and mut[1].get("conv") == conv)

# ---------------------------------------------------------------------------
# result
# ---------------------------------------------------------------------------

if FAILS:
    print("RESULT FAIL(%d)" % len(FAILS))
    print("work directory kept for inspection: %s" % WORK)
    sys.exit(1)
shutil.rmtree(WORK, ignore_errors=True)
print("RESULT PASS")
PY
