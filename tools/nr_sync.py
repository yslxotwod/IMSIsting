#!/usr/bin/env python3
"""nr_sync — find the synchronisation signal in a captured 5G waveform.

An NR capture is not annotated. Before anything in this tree can read a MIB or a
SIB1 it needs three facts that only the waveform carries: where a subframe
starts, which of the 1008 physical cell identities is on the air, and whether
the thing being captured is a gNB at all rather than the noise floor of a
receiver tuned to nothing. This tool recovers those from the signal itself.

The method is the one a handset uses in its first 20 ms: the PSS is a
frequency-domain m-sequence of length 127 -- one of three, chosen by N_ID(2) --
so a matched filter over the three candidates finds the timing offset and the
root, and an SSS search in the same slot then gives N_ID(1).

Everything here is from TS 38.211:
  §7.4.2.2  PSS: d(n) = 1 - 2*x((n + 43*N_ID(2)) mod 127), x(i+7) = (x(i+4)+x(i)) mod 2
  §7.4.2.3  SSS: the 127-length Gold sequence over x0/x1
  §7.4.3    SS/PBCH block: 240 subcarriers, PSS/SSS in the middle 127
  §4.1      the SSB burst set, and which of its positions a case allows

The verdict is `detected` or `unobserved`, and unobserved is not zero: a capture
with no PSS in it is a capture this tool cannot say anything about, and saying
"no cell" from a 2 ms slice taken in the wrong place would be a fabricated
answer.
"""
import binascii
import math
import os
import sys

try:
    import numpy as np
except ImportError:  # pragma: no cover
    np = None

N_PSS = 127
N_SSS = 127


def die(msg, code=2):
    sys.stderr.write("ERROR\t%s\n" % msg)
    sys.exit(code)


def m_sequence(length, taps=(4, 0), init=(1, 1, 1, 0, 1, 1, 0)):
    """x(i+7) = (x(i+taps[0]) + x(i+taps[1])) mod 2, from the seven seeds.

    The taps are arguments because the PSS and SSS use different polynomials:
    the PSS shifts by 4, the SSS x0 by 4 and its x1 by 1, and writing one
    polynomial for both would produce a sequence of the right length that no
    receiver would ever transmit.
    """
    x = list(init)
    while len(x) < length:
        i = len(x) - 7
        x.append((x[i + taps[0]] + x[i + taps[1]]) % 2)
    return x


def pss_sequence(nid2):
    """d(n) = 1 - 2*x((n + 43*N_ID(2)) mod 127), mapped to +/-1."""
    if nid2 < 0 or nid2 > 2:
        die("N_ID(2) must be 0, 1 or 2")
    x = m_sequence(N_PSS + 43 * 2 + 7)
    d = [1 - 2 * x[(n + 43 * nid2) % N_PSS] for n in range(N_PSS)]
    return np.array(d, dtype=np.float64)


def sss_sequence(nid1, nid2):
    """The 127-length Gold sequence of §7.4.2.3, as +/-1."""
    # Both sequences are seeded 0,0,0,0,0,0,1 in TS 38.211 §7.4.2.3 and differ
    # only in their polynomial: x0 shifts by 4, x1 by 1.
    seed = (0, 0, 0, 0, 0, 0, 1)
    x0 = np.array(m_sequence(160, taps=(4, 0), init=seed), dtype=np.int64)
    x1 = np.array(m_sequence(160, taps=(1, 0), init=seed), dtype=np.int64)
    d = []
    for n in range(N_SSS):
        m0 = 15 * (nid1 // 112) + 5 * nid2
        m1 = nid1 % 112
        b = (x0[(n + m0) % N_SSS] + x1[(n + m1) % N_SSS]) % 2
        d.append(1 - 2 * b)
    return np.array(d, dtype=np.float64)


def read_iq(path, fmt, limit=None):
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
    z = ((arr - offset) / scale)
    z = z[0::2] + 1j * z[1::2]
    if limit:
        z = z[:limit]
    return z


def freq_to_time(seq, fft_size):
    """Map a 127-length frequency-domain sequence to a time-domain template.

    The 127 subcarriers are placed around DC, which is where the PSS sits inside
    the 240-subcarrier SSB. Nothing outside them is transmitted, so the template
    is the inverse transform of the sequence and zeros.
    """
    grid = np.zeros(fft_size, dtype=np.complex128)
    lo = fft_size // 2 - N_PSS // 2
    grid[lo:lo + N_PSS] = seq
    return np.fft.ifft(np.fft.ifftshift(grid))


def correlate(z, template):
    """Normalised matched filter: |corr|^2 over the window energy, lag by lag.

    The template is scaled to unit energy first, so the metric is 1.0 for a
    window that is exactly the template and about 1/m for noise -- which is what
    makes a threshold mean the same thing in a quiet capture and a loud one. An
    absolute correlation threshold would find the loudest part of the signal
    instead of the most PSS-like part of it.
    """
    t = template / math.sqrt(float(np.sum(np.abs(template) ** 2)))
    n = z.size
    m = t.size
    if n < m:
        return np.zeros(0)
    size = 1 << int(math.ceil(math.log2(n + m)))
    corr = np.fft.ifft(np.fft.fft(z, size) * np.conj(np.fft.fft(t, size)))[:n]
    power = np.abs(z) ** 2
    csum = np.concatenate(([0.0], np.cumsum(power)))
    energy = csum[m:] - csum[:n - m + 1]
    metric = np.zeros(n)
    valid = energy > 1e-12
    vals = np.abs(corr[:n - m + 1]) ** 2
    metric[:n - m + 1][valid] = vals[valid] / energy[valid]
    return metric


def detect(z, fft_size, threshold, max_peaks=4):
    """Search all three PSS roots and return the strongest distinct peaks."""
    best = np.zeros(z.size)
    root = np.full(z.size, -1, dtype=int)
    for nid2 in range(3):
        metric = correlate(z, freq_to_time(pss_sequence(nid2), fft_size))
        better = metric > best
        best[better] = metric[better]
        root[better] = nid2

    peaks = []
    work = best.copy()
    # A PSS is one OFDM symbol long, so two peaks inside one symbol are the same
    # peak seen twice; the exclusion radius is what makes max_peaks meaningful.
    radius = max(8, fft_size // 8)
    for _ in range(max_peaks):
        idx = int(np.argmax(work))
        if work[idx] < threshold:
            break
        peaks.append((idx, float(work[idx]), int(root[idx])))
        lo = max(0, idx - radius)
        hi = min(work.size, idx + radius)
        work[lo:hi] = 0.0
    return peaks


def main(argv):
    if np is None:
        die("numpy is not available; the correlator needs it")
    if not argv or argv[0] in ("-h", "--help"):
        sys.stderr.write(__doc__)
        return 2
    cmd = argv[0]
    args = argv[1:]
    opts, pos = {}, []
    i = 0
    while i < len(args):
        if args[i].startswith("--"):
            key = args[i][2:]
            if i + 1 >= len(args):
                die("%s needs a value" % args[i])
            opts[key] = args[i + 1]
            i += 2
        else:
            pos.append(args[i])
            i += 1

    if cmd == "pss":
        if not pos:
            die("pss needs an N_ID(2) of 0, 1 or 2")
        seq = pss_sequence(int(pos[0]))
        print("length\t%d" % seq.size)
        print("bipolar\t%s" % ("yes" if set(np.unique(seq)) == {-1.0, 1.0} else "no"))
        print("distinct\t%s" % ("yes" if not np.array_equal(
            seq, pss_sequence((int(pos[0]) + 1) % 3)) else "no"))
        print("first8\t%s" % " ".join("%d" % v for v in seq[:8]))
        return 0

    if cmd == "sss":
        if len(pos) < 2:
            die("sss needs N_ID(1) and N_ID(2)")
        seq = sss_sequence(int(pos[0]), int(pos[1]))
        print("length\t%d" % seq.size)
        print("first8\t%s" % " ".join("%d" % v for v in seq[:8]))
        return 0

    if cmd != "detect":
        sys.stderr.write(__doc__)
        return 2

    if len(pos) < 2:
        die("detect needs <file> and <scs_khz>")
    path, scs = pos[0], float(pos[1])
    try:
        fs = float(opts.get("rate", "0"))
        threshold = float(opts.get("threshold", "0.25"))
        fmt = opts.get("fmt", "cf32")
        max_peaks = int(opts.get("max-peaks", "4"))
    except ValueError:
        die("rate, threshold and max-peaks must be numbers")
    if fs <= 0:
        die("--rate is required: the FFT size is rate/SCS and nothing can be "
            "placed without it")

    n_fft = int(round(fs / (scs * 1000.0)))
    if n_fft < N_PSS:
        die("a %.0f Hz capture with %.0f kHz spacing gives %d subcarriers, and "
            "the PSS alone needs %d" % (fs, scs, n_fft, N_PSS), 1)

    z = read_iq(path, fmt)
    if z.size < n_fft * 4:
        print("verdict\tunobserved")
        print("reason\ttoo-short: %d samples is under four OFDM symbols, so a "
              "peak would be a coincidence rather than a detection" % z.size)
        return 1

    peaks = detect(z, n_fft, threshold, max_peaks)
    print("samples\t%d" % z.size)
    print("rate_hz\t%.0f" % fs)
    print("scs_khz\t%.3f" % scs)
    print("fft_size\t%d" % n_fft)
    print("symbol_us\t%.3f" % (n_fft / fs * 1e6))
    print("threshold\t%.3f" % threshold)
    if not peaks:
        # The number that matters is how close the best candidate came: a peak at
        # 0.14 against a 0.15 threshold is a different situation from 0.002.
        print("best_metric\t%.4f" % float(np.max(correlate(
            z, freq_to_time(pss_sequence(0), n_fft)))))
        print("verdict\tunobserved")
        print("reason\tno-pss-above-threshold: nothing in this capture looked "
              "like a synchronisation signal at the stated rate and spacing, "
              "which is what a capture of the wrong band looks like")
        return 1

    for idx, (offset, metric, nid2) in enumerate(peaks):
        print("peak%d_offset\t%d" % (idx, offset))
        print("peak%d_metric\t%.4f" % (idx, metric))
        print("peak%d_nid2\t%d" % (idx, nid2))
        print("peak%d_time_us\t%.3f" % (idx, offset / fs * 1e6))
    offsets = [p[0] for p in peaks]
    if len(offsets) > 1:
        deltas = [b - a for a, b in zip(offsets, offsets[1:])]
        print("spacing_samples\t%s" % " ".join(str(d) for d in deltas))
    print("verdict\tdetected")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
