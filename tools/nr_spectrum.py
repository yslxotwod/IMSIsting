#!/usr/bin/env python3
"""A plain spectrum/occupancy view of an IQ capture.

`tools/nr_sync.py` answers "is there a synchronisation signal here". This answers
the question that comes before it: what does the band look like at all — where
is the noise floor, how much of the band carries energy, and which parts of it
carry energy for what fraction of the time. No correlation, no cell identity,
nothing that could be mistaken for a detection.

Method, and where each number comes from:

  * Welch periodogram: Hann window, 50 % overlap, averaged |FFT|^2 per bin. The
    estimator is the standard one (Welch 1967); the window and overlap are the
    conventional choice for a spectrum-monitoring display.
  * The noise floor is the *median* of the averaged PSD in dB, not the mean: a
    narrowband carrier occupies few bins, so the median stays on the noise while
    the mean would be dragged up by exactly the emission being looked for.
  * Occupied bandwidth is the 99 % energy band, the definition spectrum
    monitoring uses for occupied bandwidth (ITU-R SM.328 annex 1 / SM.443): the
    narrowest span that holds `--edge-pct` of the total power, computed from the
    cumulative sum of the PSD.
  * A bin is "occupied" when its averaged power exceeds noise floor + margin.
    The margin is a choice, not a standard: it is printed with every result so
    a later reader can see what "occupied" meant.
  * Duty cycle per segment is the fraction of time windows in which that
    segment's strongest bin was above the same threshold — the same notion
    `33_jamming_detect.sh --occupancy` uses.

Levels are dBFS (relative to the capture's own full scale). Nothing here knows
the receiver's gain, so no row is in dBm and none claims to be.

Three answers, kept apart:
  measured   the numbers above, from the samples
  unobserved nothing to measure (too few samples, or a capture with no
             variation at all) — printed with a reason and exit 1
"""

import argparse
import os
import sys

import numpy as np

# IQ sample formats, matching tools/nr_sync.py: the same captures feed both
# tools, so a file that the sync detector reads must read here too.
FORMATS = {
    "cf32": ("<f4", 1.0, 0.0),     # interleaved float32 I/Q, full scale 1.0
    "ci16": ("<i2", 32768.0, 0.0),  # interleaved int16, full scale 32768
    "cu8":  ("u1", 127.5, 127.5),  # interleaved uint8, offset binary
}


def die(msg, code=2):
    sys.stderr.write("ERROR\t%s\n" % msg)
    return code


def read_iq(path, fmt, limit=None):
    """Read interleaved IQ as complex64. Raises ValueError on a bad file."""
    if fmt not in FORMATS:
        raise ValueError("format must be one of %s" % ", ".join(sorted(FORMATS)))
    dtype, scale, offset = FORMATS[fmt]
    itemsize = np.dtype(dtype).itemsize
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        raise ValueError(str(exc))
    if size < itemsize * 2:
        raise ValueError("the file holds %d bytes, which is not even one IQ "
                         "sample in %s" % (size, fmt))
    count = size // itemsize
    count -= count % 2
    if limit:
        count = min(count, int(limit) * 2)
    raw = np.fromfile(path, dtype=dtype, count=count)
    iq = (raw.astype(np.float32) - np.float32(offset)) / np.float32(scale)
    return (iq[0::2] + 1j * iq[1::2]).astype(np.complex64)


def welch_psd(z, n_fft):
    """Hann-windowed, 50 %-overlapped, averaged power spectral density.

    Returns (psd_linear, windows) where psd_linear is fftshifted so index 0 is
    the most negative frequency, and `windows` is how many segments were
    averaged (the number that makes the floor estimate trustworthy).
    """
    step = n_fft // 2
    if z.size < n_fft:
        return None, 0
    starts = range(0, z.size - n_fft + 1, step)
    win = np.hanning(n_fft).astype(np.float32)
    # Normalise the window so a full-scale sine reads 0 dBFS, not 6 dB down: the
    # coherent gain of a Hann window is its mean.
    win_gain = float(np.sum(win)) / n_fft
    acc = np.zeros(n_fft, dtype=np.float64)
    n_win = 0
    for s in starts:
        seg = z[s:s + n_fft] * win
        spec = np.fft.fftshift(np.fft.fft(seg))
        acc += (spec.real.astype(np.float64) ** 2
                + spec.imag.astype(np.float64) ** 2)
        n_win += 1
    if n_win == 0:
        return None, 0
    acc /= n_win
    # A full-scale complex tone has |X_k|^2 = (sum w)^2 at its bin, so dividing
    # by that squares it to exactly 1.0 (0 dBFS). For white noise the result is
    # sigma^2 * sum(w^2) / (sum w)^2, i.e. the sample power spread over the bins.
    acc /= float(np.sum(win)) ** 2
    return acc, n_win


def to_db(p):
    return 10.0 * np.log10(np.maximum(p, 1e-30))


def occupied_bandwidth(psd, edge_pct, bin_hz):
    """The narrowest span holding `edge_pct` of the total power.

    ITU-R SM.328 annex 1 states occupied bandwidth as the width of a frequency
    band such that the power outside it is the stated fraction (1 % for a 99 %
    criterion). Computed on the averaged PSD, then centred on the band itself.
    """
    total = float(np.sum(psd))
    if total <= 0.0:
        return None
    cum = np.cumsum(psd) / total
    keep = edge_pct / 100.0
    lo_frac = (1.0 - keep) / 2.0
    lo = int(np.searchsorted(cum, lo_frac))
    hi = int(np.searchsorted(cum, 1.0 - lo_frac))
    hi = min(hi, psd.size - 1)
    width_bins = (hi - lo) + 1
    return lo, hi, width_bins * bin_hz


def segment_table(db, n_fft, bin_hz, floor_db, margin, per_window_peak=None):
    """Split the band into even segments and report each one.

    `per_window_peak` (windows x segments) turns the picture into an occupancy
    view: how often, not just how loud, each part of the band carried energy.
    """
    n_seg = 16  # a raster a person can read; not a standard, printed as-is
    edges = np.linspace(0, n_fft, n_seg + 1).astype(int)
    rows = []
    thr = floor_db + margin
    for i in range(n_seg):
        lo, hi = int(edges[i]), int(edges[i + 1])
        if hi <= lo:
            continue
        seg = db[lo:hi]
        peak = float(np.max(seg))
        loud = float(np.sum(seg > thr))
        duty = None
        if per_window_peak is not None and per_window_peak.shape[0]:
            duty = 100.0 * float(np.mean(per_window_peak[:, i] > thr))
        rows.append({
            "lo_hz": (lo - n_fft // 2) * bin_hz,
            "hi_hz": (hi - n_fft // 2) * bin_hz,
            "peak_db": peak,
            "bins_above": loud,
            "bins": hi - lo,
            "duty_pct": duty,
        })
    return rows


def per_window_segment_peaks(z, n_fft, n_seg):
    """Per-window maximum per segment, so duty cycle is per time window."""
    step = n_fft // 2
    win = np.hanning(n_fft).astype(np.float32)
    edges = np.linspace(0, n_fft, n_seg + 1).astype(int)
    out = []
    for s in range(0, max(0, z.size - n_fft + 1), step):
        seg = z[s:s + n_fft] * win
        spec = np.fft.fftshift(np.fft.fft(seg))
        p = spec.real.astype(np.float64) ** 2 + spec.imag.astype(np.float64) ** 2
        p /= float(np.sum(win)) ** 2
        db = to_db(p)
        out.append([float(np.max(db[edges[i]:edges[i + 1]]))
                    for i in range(n_seg)])
    return np.asarray(out) if out else np.zeros((0, n_seg))


def main(argv):
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("path")
    ap.add_argument("--rate", type=float, required=False, default=None)
    ap.add_argument("--fmt", default="cf32")
    ap.add_argument("--bins", type=int, default=1024)
    ap.add_argument("--margin-db", type=float, default=6.0)
    ap.add_argument("--edge-pct", type=float, default=99.0)
    ap.add_argument("--limit", type=int, default=None)
    try:
        args = ap.parse_args(argv)
    except SystemExit:
        return 2

    if args.rate is None or args.rate <= 0:
        return die("--rate is needed: bin width, occupied bandwidth and every "
                   "frequency offset are scaled by the sample rate", 2)
    if args.edge_pct <= 0 or args.edge_pct >= 100:
        return die("--edge-pct is a percentage of the total power, so it must be "
                   "between 0 and 100", 2)
    if args.bins < 64:
        return die("--bins must be at least 64: a coarser FFT could not resolve "
                   "a GSM channel, let alone an NR carrier", 2)

    n_fft = 1 << int(np.floor(np.log2(args.bins)))
    try:
        z = read_iq(args.path, args.fmt, args.limit)
    except ValueError as exc:
        return die(str(exc), 2)

    # The caller prints the capture row (as nr_sync.py's caller does); this tool
    # reports what it measured, not which file it was told to open.
    print("format\t%s" % args.fmt)
    print("rate_hz\t%.0f" % args.rate)
    print("samples\t%d" % z.size)
    print("duration_s\t%.6f" % (z.size / args.rate))

    if z.size < n_fft:
        print("fft_requested\t%d" % args.bins)
        print("verdict\tunobserved")
        print("reason\ttoo-short: %d samples is less than one %d-bin window, so "
              "there is no spectrum to show" % (z.size, n_fft))
        return 1
    # A capture of a constant (an all-zero file, or a receiver stuck on DC) has
    # no spectrum worth reporting. Saying so is the point: a flat line drawn from
    # no variation is not a quiet band.
    if float(np.max(np.abs(z))) == 0.0:
        print("verdict\tunobserved")
        print("reason\tno-signal-at-all: every sample is zero, so a floor and an "
              "occupancy measured here would describe the file, not the band")
        return 1

    psd, n_win = welch_psd(z, n_fft)
    if psd is None or n_win == 0:
        print("verdict\tunobserved")
        print("reason\ttoo-short: no complete window could be formed")
        return 1

    db = to_db(psd)
    floor_db = float(np.median(db))
    mean_db = float(np.mean(db))
    peak_idx = int(np.argmax(db))
    peak_db = float(db[peak_idx])
    bin_hz = args.rate / float(n_fft)
    thr = floor_db + args.margin_db

    print("fft_size\t%d" % n_fft)
    print("windows\t%d" % n_win)
    print("bin_hz\t%.4f" % bin_hz)
    print("window\tHann, 50 % overlap, averaged (Welch)\n".rstrip("\n"))
    print("units\tdBFS (relative to the capture's full scale; no gain is known here)")
    print("noise_floor_db\t%.2f" % floor_db)
    print("noise_floor_estimator\tmedian of the averaged PSD (robust to a narrowband carrier)")
    print("mean_db\t%.2f" % mean_db)
    print("peak_db\t%.2f" % peak_db)
    print("peak_offset_hz\t%.0f" % ((peak_idx - n_fft // 2) * bin_hz))
    print("peak_margin_db\t%.2f" % (peak_db - floor_db))
    print("margin_db\t%.2f" % args.margin_db)
    print("threshold_db\t%.2f" % thr)
    print("threshold_note\tthe margin is a choice, not a standard: it is printed so "
          "'occupied' has a stated meaning")

    band = occupied_bandwidth(psd, args.edge_pct, bin_hz)
    above = int(np.sum(db > thr))
    print("edge_pct\t%.1f" % args.edge_pct)
    print("occupied_bw_hz\t%.0f" % (band[2] if band else 0.0))
    if band:
        print("occupied_low_hz\t%.0f" % ((band[0] - n_fft // 2) * bin_hz))
        print("occupied_high_hz\t%.0f" % ((band[1] - n_fft // 2) * bin_hz))
    print("occupied_definition\tITU-R SM.328 annex 1: the narrowest band holding "
          "the stated percentage of total power")
    print("bins_above_threshold\t%d" % above)
    print("bins\t%d" % n_fft)
    print("occupancy_pct\t%.1f" % (100.0 * above / float(n_fft)))

    # The occupancy view: per-segment peaks per time window.
    pw = per_window_segment_peaks(z, n_fft, 16)
    rows = segment_table(db, n_fft, bin_hz, floor_db, args.margin_db, pw)
    print("segments\t%d" % len(rows))
    for i, r in enumerate(rows):
        duty = "unobserved" if r["duty_pct"] is None else "%.1f" % r["duty_pct"]
        print("seg%d_low_hz\t%.0f" % (i, r["lo_hz"]))
        print("seg%d_high_hz\t%.0f" % (i, r["hi_hz"]))
        print("seg%d_peak_db\t%.2f" % (i, r["peak_db"]))
        print("seg%d_duty_pct\t%s" % (i, duty))
        print("seg%d_bins_above\t%d/%d" % (i, r["bins_above"], r["bins"]))
    busiest = max(rows, key=lambda r: (r["duty_pct"] or 0.0, r["peak_db"])) if rows else None
    if busiest is not None:
        print("busiest_seg_low_hz\t%.0f" % busiest["lo_hz"])
        print("busiest_seg_duty_pct\t%s"
              % ("unobserved" if busiest["duty_pct"] is None
                 else "%.1f" % busiest["duty_pct"]))

    if above == 0:
        # Grey, and named as grey: the band is flat at this threshold, which is a
        # measurement of the capture and not a statement that the band is clear.
        print("emission\tnone-above-threshold")
        print("verdict\tspectrum_measured_flat")
        print("reason\tno bin rose %.1f dB above the floor: this capture shows no "
              "emission at the stated rate and margin, which is also what a "
              "capture of the wrong band looks like" % args.margin_db)
        return 0
    print("emission\t%d bins above floor+margin" % above)
    print("verdict\tspectrum_measured")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
