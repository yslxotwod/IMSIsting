#!/usr/bin/env python3
"""sdr_calib — measure an SDR's clock error, and an amplifier's compression point.

Two instruments, both of which exist because a number without its own error bar
is a guess:

  tone  recovers the frequency of a carrier from recorded IQ and states the
        resolution it achieved. An SDR's sample clock is a crystal, so its error
        is a parts-per-million figure, and every frequency the radio is tuned to
        inherits it. On a 1.9 GHz carrier one ppm is 1.9 kHz — wider than an LTE
        subcarrier — which is why a capture that looks wrong is often tuned
        wrong rather than decoded wrong.

  gain  finds the 1 dB compression point from a gain-versus-power table: the
        gain at which the output stops tracking the input. Past that point a
        receiver's reported power is its own distortion, and every measurement
        built on it is a measurement of the amplifier.

Both verbs refuse with a named reason rather than returning a number they
cannot support: too few samples to resolve the offset, no peak above the noise,
a peak sitting on the edge of the search window (the real offset could be
anywhere beyond it), or a gain table that never compresses. The verdict is
`measured` or `unobserved`, and `unobserved` is not zero.

Usage:
    sdr_calib.py tone <file> <fmt> <rate_hz> <carrier_hz> [--window-hz N]
      The capture is baseband: the carrier sits at 0 Hz, carrier_hz only sets
      the divisor that turns a measured offset into parts per million.
    sdr_calib.py gain <csv> [--ref-db DB]
    sdr_calib.py synth <file> <fmt> <rate_hz> <carrier_hz> <ppm> [--samples N]
                     [--snr-db DB] [--noise-only]
      synth writes the capture the tests measure; --noise-only drops the carrier
      so the refusal path is exercised against noise and not against a tone.

Formats: cf32 (complex float32), ci16 (complex int16), cu8 (rtl-sdr offset
binary). Rows are tab-separated key/value, one per line, verdict last.
"""
import csv
import math
import os
import sys

try:
    import numpy as np
except ImportError:  # pragma: no cover - the module reports this by name
    np = None

FORMATS = {
    # name -> (dtype, scale, offset, complex?)
    "cf32": ("<f4", 1.0, 0.0, True),
    "ci16": ("<i2", 32768.0, 0.0, True),
    "cu8": ("u1", 127.5, 127.5, True),
}


def die(msg, code=2):
    sys.stderr.write("ERROR\t%s\n" % msg)
    sys.exit(code)


def need_numpy():
    if np is None:
        die("numpy is not available; the estimator needs it", 2)


def read_iq(path, fmt, limit=None):
    """Read interleaved IQ as a complex vector, scaled to about +/-1."""
    if fmt not in FORMATS:
        die("unknown format %r (cf32, ci16, cu8)" % fmt)
    dtype, scale, offset, _c = FORMATS[fmt]
    if not os.path.isfile(path):
        die("no such capture: %s" % path, 1)
    dt = np.dtype(dtype)
    with open(path, "rb") as fh:
        raw = fh.read()
    usable = len(raw) - (len(raw) % (dt.itemsize * 2))
    if usable <= 0:
        die("capture holds no complete IQ pair", 1)
    arr = np.frombuffer(raw[:usable], dtype=dt).astype(np.float64)
    arr = (arr - offset) / scale
    z = arr[0::2] + 1j * arr[1::2]
    if limit is not None:
        z = z[:limit]
    return z


def wrap_hz(freq, fs):
    """Fold a 0..fs frequency into -fs/2..fs/2."""
    if freq > fs / 2.0:
        freq -= fs
    return freq


def tone(fpath, fmt, fs, carrier, window_hz):
    z = read_iq(fpath, fmt)
    n = z.size
    if n < 4096:
        out = [
            ("format", fmt), ("samples", n), ("verdict", "unobserved"),
            ("reason", "too-few-samples: %d sample(s), 4096 is the floor a "
                       "frequency estimate needs to mean anything" % n),
        ]
        return out, 1

    # A Hann window keeps a strong neighbour off the peak we are measuring;
    # the rectangular window leaks, and the leak lands exactly where a small
    # offset is being read.
    win = np.hanning(n)
    spec = np.fft.fftshift(np.fft.fft(z * win))
    power = np.abs(spec) ** 2
    bin_hz = fs / n

    # Only the bins inside the search window are candidates: an offset larger
    # than the window is not a small clock error, it is a different carrier.
    # The capture is baseband: after downconversion the carrier sits at 0 Hz,
    # and carrier_hz is used only to turn a measured offset into ppm. Searching
    # around carrier/bin_hz instead would look for a tone that downconversion
    # already removed.
    centre = n // 2
    half = max(1, int(round(window_hz / bin_hz)))
    lo = max(0, centre - half)
    hi = min(n, centre + half + 1)
    if hi <= lo:
        return [("format", fmt), ("samples", n), ("verdict", "unobserved"),
                ("reason", "search window is empty at this rate")], 1

    seg = power[lo:hi]
    peak = int(np.argmax(seg)) + lo
    peak_power = power[peak]
    # The floor is the median of the SEARCH WINDOW, not of the whole spectrum:
    # an out-of-band carrier would otherwise set the reference and hide an
    # in-band one, and the window is the only part the question is about.
    floor = float(np.median(seg))
    snr_db = 10.0 * math.log10(peak_power / floor) if floor > 0 else 0.0

    # 15 dB, not 6: the maximum of N noise bins already sits about 11 dB above
    # their median for N ~ 1000, so a 6 dB floor would call pure noise a peak.
    if snr_db < 15.0:
        return [("format", fmt), ("samples", n), ("bin_hz", "%.4f" % bin_hz),
                ("snr_db", "%.2f" % snr_db), ("verdict", "unobserved"),
                ("reason", "no-peak-above-noise: strongest bin is %.2f dB over "
                           "the window median, and 15 dB is the floor a peak "
                           "has to clear before its position means anything "
                           "(the maximum of 1000 noise bins already sits ~11 dB "
                           "up)" % snr_db)], 1

    # Sub-bin refinement: three points around the maximum, parabola in dB.
    # Without this the answer quantises to one bin, which at 2 Msps and 65536
    # samples is 31 Hz -- a larger error than the error being measured.
    delta = 0.0
    if 0 < peak < n - 1:
        a, b, c = (10.0 * math.log10(max(power[peak - 1], 1e-30)),
                   10.0 * math.log10(max(power[peak], 1e-30)),
                   10.0 * math.log10(max(power[peak + 1], 1e-30)))
        denom = (a - 2.0 * b + c)
        if denom != 0:
            delta = 0.5 * (a - c) / denom
            delta = max(-0.5, min(0.5, delta))

    # fftshift puts DC at n/2, so the frequency of a bin index is
    # (index - n/2) * bin_hz, with the interpolated part added on.
    offset = (peak - n / 2 + delta) * bin_hz
    ppm = offset / carrier * 1e6 if carrier else 0.0

    edge = (peak <= lo or peak >= hi - 1)
    rows = [
        ("format", fmt),
        ("samples", n),
        ("rate_hz", "%.6f" % fs),
        ("carrier_hz", "%.6f" % carrier),
        ("bin_hz", "%.6f" % bin_hz),
        ("resolution_hz", "%.6f" % (bin_hz * 0.5)),
        ("offset_hz", "%.4f" % offset),
        ("ppm", "%.4f" % ppm),
        ("snr_db", "%.2f" % snr_db),
    ]
    if edge:
        rows += [
            ("verdict", "unobserved"),
            ("reason", "peak-at-window-edge: the strongest bin is at the edge of "
                       "the %g Hz search window, so the true offset may lie "
                       "outside it -- widen --window-hz and measure again"
                       % window_hz),
        ]
        return rows, 1
    rows += [
        ("verdict", "measured"),
        ("note", "an offset this size moves a 1.9 GHz carrier by %.1f Hz"
                 % (ppm * 1900.0)),
    ]
    return rows, 0


def gain(fpath, ref_db):
    if not os.path.isfile(fpath):
        die("no such gain table: %s" % fpath, 1)
    rows_in = []
    with open(fpath, newline="") as fh:
        for rec in csv.reader(fh, delimiter=","):
            if not rec or rec[0].lstrip().startswith("#"):
                continue
            try:
                rows_in.append((float(rec[0]), float(rec[1])))
            except (ValueError, IndexError):
                die("gain table row is not '<gain_db>,<out_db>': %r" % (rec,), 1)
    if len(rows_in) < 3:
        return [("rows", len(rows_in)), ("verdict", "unobserved"),
                ("reason", "too-few-rows: a compression point needs the linear "
                           "region and the knee, so at least three points")], 1
    rows_in.sort()

    # The reference gain is the low-gain end, taken from the data rather than
    # assumed: the first row is the only one guaranteed to be below the knee.
    g0, p0 = rows_in[0]
    slope = None
    if len(rows_in) > 1 and rows_in[1][0] != g0:
        slope = (rows_in[1][1] - p0) / (rows_in[1][0] - g0)
    if slope is None or slope <= 0:
        return [("rows", len(rows_in)), ("verdict", "unobserved"),
                ("reason", "no-positive-slope: the first two points do not show "
                           "output rising with gain, so there is no linear "
                           "region to compare against")], 1

    compressed = None
    for g, p in rows_in:
        expected = p0 + slope * (g - g0)
        if p < expected - ref_db:
            compressed = (g, p, expected)
            break

    out = [
        ("rows", len(rows_in)),
        ("ref_db", "%.2f" % ref_db),
        ("linear_slope", "%.4f" % slope),
        ("gain_min_db", "%.2f" % g0),
        ("gain_max_db", "%.2f" % rows_in[-1][0]),
    ]
    if compressed is None:
        out += [
            ("verdict", "unobserved"),
            ("reason", "never-compresses: across %.1f dB of gain the output "
                       "stayed within %.1f dB of the straight line, so the knee "
                       "is above the highest gain in this table"
                       % (rows_in[-1][0] - g0, ref_db)),
        ]
        return out, 1
    g, p, expected = compressed
    out += [
        ("compression_gain_db", "%.2f" % g),
        ("output_at_knee_db", "%.2f" % p),
        ("shortfall_db", "%.2f" % (expected - p)),
        ("verdict", "measured"),
        ("note", "above this gain the output no longer tracks the input, so a "
                 "power reading taken there is the amplifier, not the signal"),
    ]
    return out, 0


def synth(fpath, fmt, fs, carrier, ppm, samples, snr_db, noise_only=False):
    n = samples
    if n < 4096:
        die("--samples below 4096 cannot be measured back", 2)
    offset = carrier * ppm * 1e-6
    t = np.arange(n) / fs
    if noise_only:
        # A file with no carrier in it at all, so the refusal path is exercised
        # against noise rather than against a tone the estimator was tuned for.
        z = np.zeros(n, dtype=complex)
        if snr_db is None:
            snr_db = 0.0
    else:
        z = np.exp(2j * math.pi * offset * t)
    if snr_db is not None:
        sigma = math.sqrt(0.5 / (10 ** (snr_db / 10.0)))
        z = z + sigma * (np.random.default_rng(20260101).standard_normal(n)
                         + 1j * np.random.default_rng(20260102).standard_normal(n))
    dtype, scale, off, _c = FORMATS[fmt]
    if fmt == "cf32":
        data = np.empty(2 * n, dtype="<f4")
        data[0::2] = z.real
        data[1::2] = z.imag
    elif fmt == "ci16":
        data = np.empty(2 * n, dtype="<i2")
        data[0::2] = np.clip(z.real * scale, -32768, 32767).astype("<i2")
        data[1::2] = np.clip(z.imag * scale, -32768, 32767).astype("<i2")
    else:
        data = np.empty(2 * n, dtype="u1")
        data[0::2] = np.clip(z.real * scale + off, 0, 255).astype("u1")
        data[1::2] = np.clip(z.imag * scale + off, 0, 255).astype("u1")
    with open(fpath, "wb") as fh:
        fh.write(data.tobytes())
    return [("wrote", fpath), ("samples", n), ("tone_offset_hz", "%.4f" % offset),
            ("ppm", "%.4f" % ppm), ("verdict", "synthesized")], 0


def emit(rows):
    for k, v in rows:
        print("%s\t%s" % (k, v))


def main(argv):
    if not argv:
        sys.stderr.write(__doc__)
        return 2
    cmd = argv[0]
    args = argv[1:]
    opts, pos = {}, []
    i = 0
    while i < len(args):
        a = args[i]
        if a.startswith("--"):
            key = a[2:]
            if i + 1 >= len(args):
                die("%s needs a value" % a)
            opts[key] = args[i + 1]
            i += 2
        else:
            pos.append(a)
            i += 1

    need_numpy()

    if cmd == "tone":
        if len(pos) < 4:
            die("tone needs <file> <fmt> <rate_hz> <carrier_hz>")
        try:
            fs = float(pos[2])
            carrier = float(pos[3])
            window = float(opts.get("window-hz", "50000"))
        except ValueError:
            die("rate, carrier and window must be numbers")
        rows, rc = tone(pos[0], pos[1], fs, carrier, window)
    elif cmd == "gain":
        if not pos:
            die("gain needs <csv>")
        try:
            ref = float(opts.get("ref-db", "1.0"))
        except ValueError:
            die("--ref-db must be a number")
        rows, rc = gain(pos[0], ref)
    elif cmd == "synth":
        if len(pos) < 5:
            die("synth needs <file> <fmt> <rate_hz> <carrier_hz> <ppm>")
        try:
            fs = float(pos[2])
            carrier = float(pos[3])
            ppm = float(pos[4])
            samples = int(opts.get("samples", "65536"))
            snr = opts.get("snr-db")
            snr = float(snr) if snr is not None else None
        except ValueError:
            die("rate, carrier, ppm and samples must be numbers")
        rows, rc = synth(pos[0], pos[1], fs, carrier, ppm, samples, snr,
                         noise_only=("noise-only" in opts))
    else:
        sys.stderr.write(__doc__)
        return 2
    emit(rows)
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
