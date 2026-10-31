#!/usr/bin/env python3
"""lte_prach — find LTE PRACH preambles in a captured waveform.

An LTE capture is not annotated either. A UE that wants a cell sends a random
access preamble, and nothing in the capture says which preamble was sent: the
sequence is one of the 64 the cell's SIB2 allocated, built from a Zadoff-Chu root
that SIB2 also named, and cyclic-shifted by a step SIB2 also named. This tool
recovers the timing and the cyclic shift from the waveform, given those two
SIB2 facts, and refuses to guess them.

Everything here is TS 36.211:
  §5.7.2   the preamble: x_u(n) = exp(-j*pi*u*n*(n+1)/N_ZC), N_ZC = 839 for
           preamble formats 0-3, and x_{u,v}(n) = x_u((n + C_v) mod N_ZC)
  Table 5.7.2-2  N_CS from zeroCorrelationZoneConfig (the unrestricted set)
  Table 5.7.2-4  logical rootSequenceIndex -> physical root u
  §5.7.1 Table 5.7.1-1  TCP and TSEQ per preamble format, in Ts = 1/30720 us

The method is the one a base station uses: take one TSEQ-long window, transform
it, keep the 839 subcarriers the preamble occupies, multiply by the conjugate of
the root sequence, inverse-transform. A preamble on the air puts all of its
energy into one bin of that 839-point profile; noise spreads it evenly. The
metric is therefore peak-over-mean of the profile, in dB, and a threshold on it
means the same thing in a quiet capture and a loud one.

The verdict is `detected` or `unobserved`, and unobserved is not zero: a capture
with no preamble in it may be the wrong band, the wrong rate, a window that
misses the PRACH's six resource blocks, or a receiver tuned to nothing, and none
of those is evidence that no UE transmitted.
"""
import math
import os
import sys

try:
    import numpy as np
except ImportError:  # pragma: no cover - the module refuses instead
    np = None

# TS 36.211 §5.7.2: formats 0-3 use a length-839 Zadoff-Chu sequence.
N_ZC = 839
TS_SEC = 1.0 / 30720000.0

# TS 36.211 Table 5.7.1-1: TCP and TSEQ in Ts, per preamble format.
FORMATS = {
    0: (3168, 24576),
    1: (21024, 24576),
    2: (6240, 49152),
    3: (21024, 49152),
}

# TS 36.211 Table 5.7.2-2, unrestricted set: N_CS per zeroCorrelationZoneConfig.
NCS_TABLE = (0, 13, 15, 18, 22, 26, 32, 38, 46, 59, 76, 93, 119, 167, 279, 419)

# TS 36.211 Table 5.7.2-4 lists 838 roots in an order that is not the identity.
# Only the first 456 entries (0..455) are certain here, and they are the
# identity: u == rootSequenceIndex. Above that this tree does not carry the
# table, so it refuses rather than inventing the pairing.
ROOT_IDENTITY_MAX = 455


def die(msg, code=2):
    sys.stderr.write("ERROR\t%s\n" % msg)
    sys.exit(code)


def row(*v):
    sys.stdout.write("\t".join(str(x) for x in v) + "\n")


def zc_sequence(u):
    """x_u(n) = exp(-j*pi*u*n*(n+1)/N_ZC), 0 <= n <= N_ZC-1 (TS 36.211 5.7.2)."""
    n = np.arange(N_ZC, dtype=np.float64)
    return np.exp(-1j * math.pi * float(u) * n * (n + 1.0) / N_ZC)


def shifted(u, cv):
    """x_{u,v}(n) = x_u((n + C_v) mod N_ZC): a cyclic shift, not a delay."""
    x = zc_sequence(u)
    cv = int(cv) % N_ZC
    return np.roll(x, -cv)


def ncs_of(config):
    config = int(config)
    if config < 0 or config > 15:
        die("zeroCorrelationZoneConfig is 0..15 (TS 36.331 prach-Config)")
    return NCS_TABLE[config]


def preambles_per_root(ncs):
    """How many of the 64 preambles one root sequence can carry.

    With N_CS = 0 there is no cyclic shift at all: each root carries exactly one
    preamble and 64 roots are needed (TS 36.211 §5.7.2). Otherwise the shifts are
    C_v = v*N_CS for v = 0..floor(N_ZC/N_CS)-1.
    """
    if ncs <= 0:
        return 1
    return int(N_ZC // ncs)


def read_iq(path, fmt):
    formats = {"cf32": ("<f4", 1.0, 0.0), "ci16": ("<i2", 32768.0, 0.0),
               "cu8": ("u1", 127.5, 127.5)}
    if fmt not in formats:
        die("unknown format %r (cf32, ci16, cu8)" % fmt)
    dtype, scale, offset = formats[fmt]
    if not os.path.isfile(path):
        die("no such capture: %s" % path, 1)
    dt = np.dtype(dtype)
    with open(path, "rb") as fh:
        raw = fh.read()
    usable = len(raw) - (len(raw) % (dt.itemsize * 2))
    if usable <= 0:
        die("capture holds no complete IQ pair", 1)
    arr = np.frombuffer(raw[:usable], dtype=dt).astype(np.float64)
    z = (arr - offset) / scale
    return z[0::2] + 1j * z[1::2]


def papr_db(z, start, n_fft, k0, conj):
    """Peak-over-mean of the 839-point delay profile for one window.

    Returns (papr_db, profile_index). The index is not the cyclic shift itself:
    the sequence is mapped to the subcarriers as x_{u,v}(n) = x_u((n+C_v) mod
    N_ZC) (TS 36.211 5.7.3), so the product of the received subcarriers with the
    conjugate root has the phase -j*pi*u*(2*n*C_v + C_v^2 + C_v)/N_ZC. That is a
    linear ramp in n, and its inverse transform is therefore a single bin at
    index u*C_v mod N_ZC. cmd_detect inverts that multiplication to recover C_v.
    A window that starts delta samples late adds a ramp of delta*839/n_fft bins.
    """
    win = z[start:start + n_fft]
    if win.size < n_fft:
        return -math.inf, -1
    y = np.fft.fft(win)[k0:k0 + N_ZC]
    prof = np.abs(np.fft.ifft(y * conj)) ** 2
    mean = float(prof.mean())
    if mean <= 0.0:
        return -math.inf, -1
    idx = int(np.argmax(prof))
    return 10.0 * math.log10(float(prof[idx]) / mean), idx


def scan_offsets(n_fft, centre):
    """Every resource-block-aligned k0 inside the capture, for --scan.

    The preamble occupies six resource blocks (72 subcarriers) inside a wider
    carrier, so the offset SIB2 calls prach-FreqOffset is a multiple of 12
    subcarriers. When the capture is wide enough that the PRACH may sit anywhere
    in it, these are the hypotheses worth trying.
    """
    out = []
    k = int(centre) % 12
    while k + N_ZC <= n_fft:
        out.append(k)
        k += 12
    return out


def cmd_ncs(argv):
    if not argv:
        die("ncs needs a zeroCorrelationZoneConfig of 0..15")
    config = int(argv[0])
    ncs = ncs_of(config)
    per_root = preambles_per_root(ncs)
    row("zcc", config)
    row("n_cs", ncs)
    row("preambles_per_root", per_root)
    row("roots_for_64", -(-64 // per_root))
    row("shift_set", ("v*%d for v=0..%d" % (ncs, per_root - 1))
        if ncs > 0 else "none: one preamble per root")
    row("ref", "TS 36.211 Table 5.7.2-2 (unrestricted set, formats 0-3)")
    return 0


def cmd_sequence(argv):
    if not argv:
        die("sequence needs a physical root u of 1..838")
    u = int(argv[0])
    if u < 1 or u > N_ZC - 1:
        die("the physical root u is 1..838 for N_ZC = 839")
    cv = 0
    if len(argv) > 1:
        cv = int(argv[1])
    x = shifted(u, cv)
    mag = np.abs(x)
    row("n_zc", N_ZC)
    row("root_u", u)
    row("cyclic_shift_cv", cv % N_ZC)
    row("length", x.size)
    row("unit_modulus", "yes" if np.allclose(mag, 1.0, atol=1e-9) else "no")
    # A cyclic shift must not change the set of magnitudes, only their order.
    row("shift_is_cyclic",
        "yes" if np.allclose(np.abs(zc_sequence(u)), mag, atol=1e-9) else "no")
    row("first4_real", " ".join("%.6f" % v for v in x[:4].real))
    row("first4_imag", " ".join("%.6f" % v for v in x[:4].imag))
    row("ref", "TS 36.211 5.7.2: x_u(n) = exp(-j*pi*u*n*(n+1)/N_ZC)")
    return 0


def cmd_synth(argv):
    """Write a capture with a preamble at a known offset.

    A detector that cannot find the preamble this tool put there on purpose has
    not been tested, so the fixture is generated from the same two SIB2 facts a
    real cell would have broadcast and the offset is the assertion.
    """
    if not argv:
        die("synth needs an output path")
    path = argv[0]
    opts = {"rate": "1920000", "root": "25", "zcc": "12", "shift": "0",
            "offset": "0", "snr-db": "20", "fmt": "cf32", "samples": "38400",
            "format": "0", "k0": ""}
    args = argv[1:]
    i = 0
    while i < len(args):
        key = args[i][2:] if args[i].startswith("--") else ""
        if key not in opts:
            die("synth does not take %r" % args[i])
        if i + 1 >= len(args):
            die("%s needs a value" % args[i])
        opts[key] = args[i + 1]
        i += 2
    fs = float(opts["rate"])
    fmt_code = int(opts["format"])
    if fmt_code not in FORMATS:
        die("preamble format must be 0, 1, 2 or 3 for the long sequence")
    u = int(opts["root"])
    ncs = ncs_of(opts["zcc"])
    v = int(opts["shift"])
    if ncs > 0 and v >= preambles_per_root(ncs):
        die("shift %d is outside the %d shifts N_CS=%d allows"
            % (v, preambles_per_root(ncs), ncs))
    cp_ts, seq_ts = FORMATS[fmt_code]
    n_fft = int(round(fs * seq_ts * TS_SEC))
    if n_fft < N_ZC:
        die("a %.0f Hz capture gives %d subcarriers at 1.25 kHz and the "
            "839-length sequence alone needs %d" % (fs, n_fft, N_ZC), 1)
    k0 = int(opts["k0"]) if opts["k0"] else n_fft // 2 - N_ZC // 2
    if k0 < 0 or k0 + N_ZC > n_fft:
        die("k0 must leave all 839 subcarriers inside the %d-point transform"
            % n_fft)

    grid = np.zeros(n_fft, dtype=np.complex128)
    grid[k0:k0 + N_ZC] = shifted(u, v * ncs)
    seq = np.fft.ifft(grid) * n_fft / math.sqrt(N_ZC)
    cp = int(round(fs * cp_ts * TS_SEC))
    wave = np.concatenate((seq[-cp:], seq)) if cp > 0 else seq

    total = int(opts["samples"])
    at = int(opts["offset"])
    rng = np.random.default_rng(20240101)
    snr = float(opts["snr-db"])
    sigma = 10.0 ** (-snr / 20.0)
    z = (rng.standard_normal(total) + 1j * rng.standard_normal(total)) * sigma
    end = min(total, at + wave.size)
    z[at:end] += wave[:end - at]

    scale, offset, dtype = {"cf32": (1.0, 0.0, "<f4"),
                            "ci16": (32768.0, 0.0, "<i2"),
                            "cu8": (127.5, 127.5, "u1")}[opts["fmt"]]
    if dtype == "u1":
        data = np.empty(2 * z.size, dtype=dtype)
        data[0::2] = np.clip(np.round(z.real * scale + offset), 0, 255)
        data[1::2] = np.clip(np.round(z.imag * scale + offset), 0, 255)
    else:
        data = np.empty(2 * z.size, dtype=dtype)
        data[0::2] = np.round(z.real * scale + offset)
        data[1::2] = np.round(z.imag * scale + offset)
    with open(path, "wb") as fh:
        fh.write(data.tobytes())

    row("capture", path)
    row("role", "synthetic fixture: proves the correlator, not a real capture")
    row("samples", total)
    row("rate_hz", "%.0f" % fs)
    row("preamble_format", fmt_code)
    row("n_fft", n_fft)
    row("cp_samples", cp)
    row("preamble_at", at)
    row("sequence_at", at + max(cp, 0))
    row("root_u", u)
    row("zcc", opts["zcc"])
    row("n_cs", ncs)
    row("shift_v", v)
    row("cv", (v * ncs) % N_ZC)
    row("snr_db", opts["snr-db"])
    row("k0", k0)
    return 0


def cmd_detect(argv):
    if not argv:
        die("detect needs a capture path")
    path = argv[0]
    opts = {"rate": "", "fmt": "cf32", "threshold-db": "20.0", "format": "0",
            "root": "", "physical-root": "", "zcc": "", "k0": "",
            "scan": "", "max-peaks": "3"}
    args = argv[1:]
    i = 0
    while i < len(args):
        key = args[i][2:] if args[i].startswith("--") else ""
        if key not in opts:
            die("detect does not take %r" % args[i])
        if key == "scan":
            opts["scan"] = "1"
            i += 1
            continue
        if i + 1 >= len(args):
            die("%s needs a value" % args[i])
        opts[key] = args[i + 1]
        i += 2

    if not opts["rate"]:
        die("--rate is required: TSEQ is a duration, and the window it implies "
            "is rate * TSEQ samples")
    fs = float(opts["rate"])
    fmt_code = int(opts["format"])
    if fmt_code not in FORMATS:
        die("preamble format must be 0, 1, 2 or 3 (the long sequence, N_ZC=839)")
    if not opts["zcc"]:
        die("--zcc is required: zeroCorrelationZoneConfig from SIB2 decides the "
            "cyclic-shift step, and without it the 64 preambles of one root "
            "cannot be told apart")
    if not (opts["root"] or opts["physical-root"]):
        die("--root (SIB2 rootSequenceIndex) or --physical-root is required: "
            "the sequence on the air is one specific ZC root and no capture "
            "carries that index")
    ncs = ncs_of(opts["zcc"])
    if opts["physical-root"]:
        u = int(opts["physical-root"])
        if u < 1 or u > N_ZC - 1:
            die("--physical-root must be 1..838")
        logical = -1
    else:
        logical = int(opts["root"])
        if logical < 0 or logical > N_ZC - 1:
            die("--root must be 0..838")
        if logical > ROOT_IDENTITY_MAX:
            die("rootSequenceIndex %d maps through TS 36.211 Table 5.7.2-4, "
                "whose 838 entries this tree does not carry; only 0..%d are "
                "certain (u == the index). Pass --physical-root to state the "
                "root u directly." % (logical, ROOT_IDENTITY_MAX))
        u = logical

    cp_ts, seq_ts = FORMATS[fmt_code]
    n_fft = int(round(fs * seq_ts * TS_SEC))
    if n_fft < N_ZC:
        die("a %.0f Hz capture gives %d subcarriers at 1.25 kHz and the "
            "839-length sequence alone needs %d: capture at least %.0f Hz"
            % (fs, n_fft, N_ZC, N_ZC * 1.25e3), 1)
    centre = n_fft // 2 - N_ZC // 2
    k0 = int(opts["k0"]) if opts["k0"] else centre
    if k0 < 0 or k0 + N_ZC > n_fft:
        die("--k0 must leave all 839 subcarriers inside the %d-point transform"
            % n_fft, 2)

    z = read_iq(path, opts["fmt"])
    if z.size < n_fft * 2:
        row("verdict", "unobserved")
        row("reason", "too-short: %d samples is under two TSEQ windows of %d, "
                      "so a peak would be a coincidence rather than a detection"
                      % (z.size, n_fft))
        return 1

    conj = np.conj(zc_sequence(u))
    step = max(1, n_fft // 4)
    starts = list(range(0, z.size - n_fft + 1, step))
    coarse = [(papr_db(z, s, n_fft, k0, conj)[0], s) for s in starts]
    coarse.sort(reverse=True)

    best_db, best_start, best_k0, best_idx = -math.inf, -1, k0, -1
    hypotheses = [k0]
    if opts["scan"]:
        hypotheses = scan_offsets(n_fft, centre)
    for _, s in coarse[:3]:
        for cand in hypotheses:
            d, idx = papr_db(z, s, n_fft, cand, conj)
            if d > best_db:
                best_db, best_start, best_k0, best_idx = d, s, cand, idx
    # The window start is only known to +-step after the coarse pass; a second
    # pass at one-sample resolution is what turns it into a timing offset.
    for s in range(max(0, best_start - step), min(z.size - n_fft, best_start + step) + 1):
        d, idx = papr_db(z, s, n_fft, best_k0, conj)
        if d > best_db:
            best_db, best_start, best_idx = d, s, idx

    threshold = float(opts["threshold-db"])
    row("capture", path)
    row("samples", z.size)
    row("rate_hz", "%.0f" % fs)
    row("preamble_format", fmt_code)
    row("tcp_ts", cp_ts)
    row("tseq_ts", seq_ts)
    row("tseq_us", "%.3f" % (seq_ts * TS_SEC * 1e6))
    row("n_fft", n_fft)
    row("n_zc", N_ZC)
    row("root_logical", logical if logical >= 0 else "unobserved")
    row("root_u", u)
    row("zcc", opts["zcc"])
    row("n_cs", ncs)
    row("preambles_per_root", preambles_per_root(ncs))
    row("k0", best_k0)
    row("k0_source", "argument" if opts["k0"] else
        ("scanned" if opts["scan"] else "centred"))
    row("threshold_db", "%.1f" % threshold)
    if best_db < threshold:
        row("best_papr_db", "%.2f" % best_db)
        row("verdict", "unobserved")
        row("reason", "no-preamble-above-threshold: nothing in this capture "
                      "looked like a root-%d preamble at %.0f Hz, which is what "
                      "the wrong band, the wrong rate, or a window that misses "
                      "the PRACH's six resource blocks all look like" % (u, fs))
        return 1

    raw = best_idx % N_ZC
    cv = (raw * pow(u, -1, N_ZC)) % N_ZC
    row("peak0_window", best_start)
    row("peak0_window_us", "%.3f" % (best_start / fs * 1e6))
    row("peak0_index", raw)
    row("peak0_index_relation", "index = u*cv mod %d, inverted here with u=%d"
        % (N_ZC, u))
    row("peak0_papr_db", "%.2f" % best_db)
    row("peak0_cv", cv)
    row("peak0_cv_basis",
        "u*cv mod 839 recovered from the profile bin; valid when the window is "
        "aligned to the preamble start, which the refinement above approximates")
    if ncs > 0:
        row("peak0_shift_v", cv // ncs if cv % ncs == 0 else "unobserved")
        row("peak0_on_shift_grid", "yes" if cv % ncs == 0 else "no")
    else:
        row("peak0_shift_v", "unobserved")
        row("peak0_on_shift_grid", "n/a")
    row("verdict", "detected")
    return 0


def main(argv):
    if np is None:
        die("numpy is not available; the correlator needs it")
    if not argv or argv[0] in ("-h", "--help"):
        sys.stderr.write(__doc__)
        return 2
    cmd, args = argv[0], argv[1:]
    if cmd == "ncs":
        return cmd_ncs(args)
    if cmd == "sequence":
        return cmd_sequence(args)
    if cmd == "synth":
        return cmd_synth(args)
    if cmd == "detect":
        return cmd_detect(args)
    sys.stderr.write(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
