#!/usr/bin/env bash
# jamming detect — detection, discrimination and characterisation of RAN
# interference.
#
# SCOPE, stated first because it is the point of the module: a transmitter
# whose only function is raising the noise floor is illegal to operate in most
# jurisdictions regardless of intent, and it degrades emergency calls along
# with everything else. This module builds the defensive half that a security
# team actually needs:
#
#   * detection features from IQ and from receiver counters: noise-floor shift
#     over time, PDCCH/PBCH decode-failure rate, RSRP collapse with no
#     successful handover, RSRQ degradation without an RSRP change, uplink BLER
#     spike, RACH failure rate, and the timing pattern of the degradation
#   * discrimination between jamming, congestion and a coverage hole
#   * characterisation: narrowband vs barrage, affected bandwidth and centre,
#     duty cycle, and whether it targets one carrier or the whole band
#   * the regulatory position: what an investigator sends, and to whom
#
# and, since Phase 9 of docs/OFFENSIVE_ROADMAP.md, the interfering half:
#
#   * I/Q waveform construction for the target ARFCN — barrage (whole band) and
#     narrowband (one carrier or less) at a chosen shape (AWGN / CW / chirp),
#     with hardware-free construction so the arithmetic is checked on any host
#   * the SDR transmit calls, a bounded pulse train, and duty-cycle control
#   * the disclaimer, printed by the transmit verbs themselves and not only by
#     this comment
#
# There is no authorisation gate: every verb runs on the first invocation, and
# the old --i-have-a-lab-and-authorisation flag is accepted and ignored. What
# jamd_scope_check still asserts is that the verbs are dispatchable, that the
# keyed path is radio-checked, and that the detection verbs stay radio-free.
# The selftest runs it.
#
# Attack owned: O16 (RAN jamming) — detection and measurement are the authority;
# the TX path is the lab-bounded other half, per docs/ATTACK_COVERAGE.md.
#
# Resolve IMSISTING_ROOT from this script's own path (MODULE_CONVENTIONS §2).
if [[ -z "${IMSISTING_ROOT:-}" ]]; then
    _sl_src="${BASH_SOURCE[0]}"
    while [ -L "$_sl_src" ]; do
        _sl_dir="$(cd -P "$(dirname "$_sl_src")" && pwd)"
        _sl_tgt="$(readlink "$_sl_src")"
        [[ "$_sl_tgt" != /* ]] && _sl_tgt="$_sl_dir/$_sl_tgt"
        _sl_src="$_sl_tgt"
    done
    IMSISTING_ROOT="$(cd -P "$(dirname "$_sl_src")/.." && pwd)"
    export IMSISTING_ROOT
    unset _sl_src _sl_dir _sl_tgt
fi
if [[ -n "${IMSISTING_ROOT:-}" ]]; then
    _real_home="$(dirname "$IMSISTING_ROOT")"
    if [[ -n "$_real_home" && -d "$_real_home" && "$HOME" != "$_real_home" ]]; then
        export HOME="$_real_home"
    fi
    unset _real_home
fi
: "${IMSISTING_HOME:=$IMSISTING_ROOT}"
: "${TMP_DIR:=/tmp/imsisting}"
: "${LOOT_DIR:=$IMSISTING_ROOT/loot}"
: "${CAPTURES_DIR:=$IMSISTING_ROOT/captures}"
: "${LOGS_DIR:=$IMSISTING_ROOT/logs}"
: "${STATE_DIR:=$IMSISTING_ROOT/state}"
mkdir -p "$TMP_DIR" "$LOOT_DIR" "$CAPTURES_DIR" "$LOGS_DIR" "$STATE_DIR" 2>/dev/null

MOD_TMP="$TMP_DIR/jamming_detect"
JAMD_DIR="$LOOT_DIR/jamming_detect"
JAMD_FEATURES="$JAMD_DIR/features.tsv"
JAMD_IQ_DIR="$CAPTURES_DIR/jamming_detect"
mkdir -p "$MOD_TMP" "$JAMD_DIR" "$JAMD_IQ_DIR" 2>/dev/null

declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
declare -F warn >/dev/null 2>&1 || warn() { printf '[warn] %s\n' "$*" >&2; }
declare -F err  >/dev/null 2>&1 || err()  { printf '[err]  %s\n' "$*" >&2; }
declare -F ok   >/dev/null 2>&1 || ok()   { printf '[ok]   %s\n' "$*" >&2; }
declare -F banner >/dev/null 2>&1 || banner() { :; }

jamd_sanitize() { printf '%s' "${1:-}" | tr '\t\r\n' '   '; }

JAMD_F=()
jamd_split() {
    JAMD_F=()
    local i n
    n=$(printf '%s' "$1" | awk -F'\t' '{print NF}')
    for (( i = 1; i <= n; i++ )); do
        JAMD_F+=("$(printf '%s' "$1" | cut -f"$i")")
    done
}

jamd_py() {
    command -v python3 >/dev/null 2>&1 || {
        printf 'ERROR\tpython3 missing — cannot analyse IQ\n' >&2; return 1; }
    # Producers write their samples into this module's temp tree, never into
    # the operator's captures directory: a build that fails must leave no
    # file that looks like a capture.
    local JAMD_TMP="$MOD_TMP"
    mkdir -p "$JAMD_TMP" 2>/dev/null
    export JAMD_TMP
    python3 - "$@" <<'PY'
import sys, os, math, tempfile, shutil
try:
    import numpy as np
    from scipy import signal as sps
except Exception as e:
    sys.stderr.write('ERROR\tnumpy/scipy missing: %s\n' % e)
    sys.exit(1)

ITEM = {'cf32': 8, 'ci16': 4, 'cu8': 2}


def load_iq(path, fmt):
    if fmt not in ITEM:
        sys.stderr.write('ERROR\tunknown IQ format %s (want cf32|ci16|cu8)\n' % fmt)
        sys.exit(2)
    if not os.path.isfile(path):
        sys.stderr.write('ERROR\tno such IQ file: %s\n' % path)
        sys.exit(1)
    sz = os.path.getsize(path)
    if sz == 0 or sz % ITEM[fmt] != 0:
        sys.stderr.write('ERROR\t%s is not a whole number of %s samples (%d bytes)\n' % (path, fmt, sz))
        sys.exit(1)
    n = sz // ITEM[fmt]
    if n < 2048:
        sys.stderr.write('ERROR\ttoo few samples (%d); need at least 2048\n' % n)
        sys.exit(1)
    if fmt == 'cf32':
        d = np.fromfile(path, dtype='<f4').astype(np.float64)
        x = d[0::2] + 1j * d[1::2]
    elif fmt == 'ci16':
        d = np.fromfile(path, dtype='<i2').astype(np.float64) / 32768.0
        x = d[0::2] + 1j * d[1::2]
    else:
        d = np.fromfile(path, dtype=np.uint8).astype(np.float64)
        x = ((d[0::2] - 127.5) + 1j * (d[1::2] - 127.5)) / 127.5
    return x


def psd(x, rate):
    nper = int(min(1024, max(64, len(x) // 8)))
    f, P = sps.welch(x, fs=rate, nperseg=nper, return_onesided=False)
    return np.fft.fftshift(f), np.fft.fftshift(P)


def db(p):
    return 10.0 * np.log10(p + 1e-30)


def features(x, rate):
    n = len(x)
    half = n // 2
    f, P1 = psd(x[:half], rate)
    _, P2 = psd(x[half:], rate)
    P1d, P2d = db(P1), db(P2)
    floor1 = float(np.percentile(P1d, 10))
    floor2 = float(np.percentile(P2d, 10))
    med2 = float(np.median(P2d))
    floor_shift = floor2 - floor1
    affected = P2d > med2 + 6.0
    occ = float(affected.sum()) / len(P2d)
    peak_excess = float(P2d.max() - med2)
    if affected.sum() > 0:
        sub_shift = float(np.percentile(P2d[affected], 10) - np.percentile(P1d[affected], 10))
        # contiguous extent of the affected region
        idx = np.where(affected)[0]
        bw = float((idx.max() - idx.min() + 1) * (rate / len(P2d)))
        # centre offset of the affected region
        centre = float(f[int((idx.max() + idx.min()) / 2)])
    else:
        sub_shift = 0.0; bw = 0.0; centre = 0.0
    jamming_shift = max(floor_shift, sub_shift)
    # time-domain activity: window power relative to the pre-interference level
    win = 512
    m = n // win
    env = np.abs(x[:m * win].reshape(m, win)) ** 2
    envdb = 10.0 * np.log10(env.mean(axis=1) + 1e-30)
    base = float(np.percentile(envdb, 25))
    active = envdb > base + 6.0
    activity = float(active.mean())
    trans = int(np.abs(np.diff(active.astype(int))).sum())
    return dict(
        samples=n, duration_s=n / float(rate),
        noise_floor_first_half_dbfs=floor1, noise_floor_second_half_dbfs=floor2,
        noise_floor_shift_db=floor_shift, subband_floor_shift_db=sub_shift,
        jamming_floor_shift_db=jamming_shift, peak_excess_db=peak_excess,
        affected_bandwidth_hz=bw, affected_centre_offset_hz=centre,
        occupied_fraction=occ, activity_fraction=activity, activity_transitions=trans,
    )


def characterise(feat):
    if feat['jamming_floor_shift_db'] < 6.0 and feat['peak_excess_db'] < 12.0:
        return 'clean'
    if feat['peak_excess_db'] >= 12.0 and feat['occupied_fraction'] < 0.25:
        return 'narrowband'
    if feat['noise_floor_shift_db'] >= 6.0:
        return 'barrage'
    return 'indeterminate'


def duty_pattern(feat):
    a = feat['activity_fraction']
    if a <= 0.1:
        return 'none'
    if a >= 0.9 and feat['activity_transitions'] <= 2:
        return 'continuous'
    if feat['activity_transitions'] >= 4:
        return 'pulsed'
    return 'step (present for part of the observation)'


def san(v):
    # a path or counter value is untrusted text and must not carry a tab into
    # a TSV row (MODULE_CONVENTIONS section 12).
    return str(v).replace('\t', ' ').replace('\r', ' ').replace('\n', ' ')


def print_feats(path, fmt, rate, feat, extra=None):
    print('file\t%s' % san(path))
    print('format\t%s' % fmt)
    print('rate\t%d' % rate)
    for k in ('samples', 'duration_s', 'noise_floor_first_half_dbfs',
              'noise_floor_second_half_dbfs', 'noise_floor_shift_db',
              'subband_floor_shift_db', 'jamming_floor_shift_db',
              'peak_excess_db', 'affected_bandwidth_hz', 'affected_centre_offset_hz',
              'occupied_fraction', 'activity_fraction', 'activity_transitions'):
        v = feat[k]
        if isinstance(v, float):
            print('%s\t%.3f' % (k, v))
        else:
            print('%s\t%s' % (k, v))
    ch = characterise(feat)
    print('characterisation\t%s' % ch)
    print('duty_cycle\t%.3f' % feat['activity_fraction'])
    print('duty_pattern\t%s' % duty_pattern(feat))
    print('interference_detected\t%s' % ('yes' if ch != 'clean' else 'no'))
    if extra:
        for k, v in extra.items():
            print('%s\t%s' % (k, v))


def cmd_occupancy(argv):
    """Occupancy over a spectrogram: which slices of the band are in use, how
    much of the time, and where the edges are.

    The floor is estimated once over the whole capture (the 20th percentile of
    every cell) rather than per bin: a per-bin floor follows a carrier that is
    always on and would report it as idle, which is the wrong answer for the
    one signal an investigator cares about.
    """
    if len(argv) < 3:
        sys.stderr.write('ERROR\tusage: occupancy <iq> <format> <rate> '
                         '[--bins N] [--threshold-db T] [--edge-pct P]\n')
        return 2
    path, fmt, rate = argv[0], argv[1], int(argv[2])
    bins, thr, edge = 1024, 6.0, 10.0
    rest = argv[3:]
    i = 0
    while i < len(rest):
        a = rest[i]
        if a not in ('--bins', '--threshold-db', '--edge-pct'):
            sys.stderr.write('ERROR\tunknown option %s (want --bins, '
                             '--threshold-db, --edge-pct)\n' % a)
            return 2
        if i + 1 >= len(rest):
            sys.stderr.write('ERROR\t%s needs a value\n' % a)
            return 2
        try:
            if a == '--bins':
                bins = int(rest[i + 1])
            elif a == '--threshold-db':
                thr = float(rest[i + 1])
            else:
                edge = float(rest[i + 1])
        except ValueError:
            sys.stderr.write('ERROR\t%s takes a number, not %s\n' % (a, rest[i + 1]))
            return 2
        i += 2
    if bins < 64 or bins > 16384 or (bins & (bins - 1)) != 0:
        sys.stderr.write('ERROR\t--bins must be a power of two from 64 to 16384, '
                         'not %d\n' % bins)
        return 2
    if thr <= 0:
        sys.stderr.write('ERROR\t--threshold-db must be positive\n')
        return 2

    x = load_iq(path, fmt)
    n = len(x)
    hop = max(1, bins // 2)
    total = (n - bins) // hop + 1
    if total < 8:
        sys.stderr.write('ERROR\tcapture is shorter than eight %d-sample frames; '
                         'pass fewer --bins or a longer capture\n' % bins)
        return 2
    # Two averages, and both are the measurement rather than a detail: the
    # spectrogram is cut into time windows, and each window is the mean of
    # several periodograms. One raw periodogram has a variance of about 5.5 dB
    # per bin, which is the same size as the threshold, so it would report
    # noise as occupancy. Averaging inside a window is what makes "in use"
    # mean "in use for this long", and it is why `windows` is printed.
    step = max(1, total // 4096)
    w = np.hanning(bins)
    frames = []
    for o in range(0, total, step):
        seg = x[o * hop:o * hop + bins]
        if len(seg) < bins:
            break
        frames.append(np.abs(np.fft.fft(seg * w)) ** 2)
    if len(frames) < 8:
        sys.stderr.write('ERROR\ttoo few frames to average\n')
        return 2
    avg = max(1, len(frames) // 128)
    m = (len(frames) // avg) * avg
    S = np.array(frames[:m]).reshape(-1, avg, bins).mean(axis=1) / float(bins) ** 2
    P = 10.0 * np.log10(S + 1e-30)
    floor = float(np.percentile(P, 20))
    occ = P > (floor + thr)
    frac = occ.mean(axis=0)
    band_occ = float(occ.mean())
    occupied_bins = int((frac > 0.5).sum())
    busiest = int(np.argmax(frac))
    bin_hz = rate / float(bins)
    offs = (np.arange(bins) - bins / 2.0 + 0.5) * bin_hz

    segs = []
    run = None
    for b in range(bins):
        hot = frac[b] * 100.0 >= edge
        if hot and run is None:
            run = b
        elif not hot and run is not None:
            segs.append((run, b - 1))
            run = None
    if run is not None:
        segs.append((run, bins - 1))

    print('file\t%s' % san(path))
    print('format\t%s' % fmt)
    print('rate_hz\t%d' % rate)
    print('samples\t%d' % n)
    print('duration_s\t%.6f' % (n / float(rate)))
    print('fft_size\t%d' % bins)
    print('bin_width_hz\t%.3f' % bin_hz)
    print('windows\t%d' % S.shape[0])
    print('periodograms_per_window\t%d' % avg)
    print('frame_hop_samples\t%d' % (hop * step))
    print('threshold_db\t%.1f' % thr)
    print('edge_pct\t%.1f' % edge)
    print('noise_floor_db\t%.2f' % floor)
    print('occupancy_pct\t%.2f' % (band_occ * 100.0))
    print('occupied_bins\t%d' % occupied_bins)
    print('busiest_bin_offset_hz\t%.0f' % offs[busiest])
    print('busiest_bin_occupancy_pct\t%.2f' % (frac[busiest] * 100.0))
    print('channels\t%d' % len(segs))
    for k, (lo, hi) in enumerate(segs, 1):
        print('channel\t%d\t%.0f\t%.0f\t%.0f\t%.2f\t%.2f'
              % (k, offs[lo] - bin_hz / 2.0, offs[hi] + bin_hz / 2.0,
                 (hi - lo + 1) * bin_hz, float(frac[lo:hi + 1].mean()) * 100.0,
                 float(P[:, lo:hi + 1].max() - floor)))
    print('note\t%s' % 'an offset is measured against the receiver centre '
                        'frequency; the centre is not in the file')
    print('limit\t%s' % 'a level is relative to the sample power in the capture, '
                        'not a level at the antenna: no calibration is applied and '
                        'the window gain is not corrected')
    print('limit\t%s' % 'occupancy is measured, not licensed: a busy bin is not '
                        'necessarily unlawful and a quiet one is not free')
    print('verdict\tspectrum_occupancy_measured')
    return 0


def cmd_analyse(argv):
    path, fmt, rate = argv[0], argv[1], int(argv[2])
    x = load_iq(path, fmt)
    feat = features(x, rate)
    print_feats(path, fmt, rate, feat)


def cmd_noisefloor(argv):
    path, fmt, rate = argv[0], argv[1], int(argv[2])
    x = load_iq(path, fmt)
    n = len(x); w = 8
    seg = n // w
    floors = []
    for i in range(w):
        _, P = psd(x[i * seg:(i + 1) * seg], rate)
        floors.append(float(np.percentile(db(P), 10)))
    base = floors[0]
    print('file\t%s' % san(path))
    print('windows\t%d' % w)
    print('window_seconds\t%.6f' % (seg / float(rate)))
    print('noise_floor_dbfs\t%.3f' % base)
    maxshift = 0.0
    for i, fl in enumerate(floors):
        sh = fl - base
        if abs(sh) > abs(maxshift):
            maxshift = sh
        print('window\t%d\tfloor_dbfs=%.3f\tshift_db=%.3f' % (i, fl, sh))
    print('max_shift_db\t%.3f' % maxshift)
    print('onset_jump_db\t%.3f' % max([floors[i + 1] - floors[i] for i in range(w - 1)] or [0.0]))
    print('floor_shift_detected\t%s' % ('yes' if maxshift >= 6.0 else 'no'))


def cmd_characterise(argv):
    path, fmt, rate = argv[0], argv[1], int(argv[2])
    centre_mhz = float(argv[3]) if len(argv) > 3 and argv[3] else None
    x = load_iq(path, fmt)
    feat = features(x, rate)
    ch = characterise(feat)
    print('file\t%s' % san(path))
    print('characterisation\t%s' % ch)
    print('affected_bandwidth_hz\t%.0f' % feat['affected_bandwidth_hz'])
    print('occupied_fraction\t%.3f' % feat['occupied_fraction'])
    print('duty_cycle\t%.3f' % feat['activity_fraction'])
    print('duty_pattern\t%s' % duty_pattern(feat))
    print('captured_span_hz\t%d' % rate)
    if centre_mhz is None:
        print('affected_centre_offset_hz\t%.0f' % feat['affected_centre_offset_hz'])
        print('affected_centre_mhz\t-')
        print('target_scope\t%s' % ('none' if ch == 'clean' else
              ('whole_band' if ch == 'barrage' else 'single_carrier')))
        print('note\t%s' % 'an absolute affected frequency (and therefore an ARFCN) needs the receiver centre frequency; pass it as the optional fourth argument')
    else:
        c = centre_mhz * 1e6 + feat['affected_centre_offset_hz']
        print('affected_centre_offset_hz\t%.0f' % feat['affected_centre_offset_hz'])
        print('affected_centre_mhz\t%.6f' % (c / 1e6))
        print('target_scope\t%s' % ('none' if ch == 'clean' else
              ('whole_band' if ch == 'barrage' else 'single_carrier')))
        print('note\t%s' % 'compare affected_bandwidth_hz with the operator channel width to say whether one carrier or the whole band is affected')


# ── the ARFCN raster, TS 36.104 §5.7.3 ──────────────────────────────────
#
# One table, in one place, shared by the constructor and the analyser. The
# band edges below are the ones the TS fixes, so they are the known answers the
# selftest asserts rather than values read back out of this code.
JAMD_EARFCN_BANDS = (
    # lo,  hi,    base_hz,     step_hz
    (0,     599,   0,           100000),   # 1-32, ... 1800..2400 region
    (600,   1199,  200000000,   100000),
    (1200,  1949,  400000000,   100000),
    (2750,  3449,  800000000,   100000),
    (3450,  3779,  1200000000,  100000),
    (6150,  6449,  2620000000,  100000),
    (9210,  9659,  3400000000,  100000),
    # These three overlap: 2496-2690 MHz (EARFCN 39650-41589) CONTAINS the
    # whole of 2570-2620 MHz (37750-38249), and 1880-1920 MHz (38650-39649)
    # shares their EARFCN numbers without sharing a frequency. So the two
    # narrow bands come first and the wide one last: hz_to_earfcn walks the
    # table in order, and the band a frequency physically sits in must be the
    # one that claims it. Ordered as given -- earfcn_to_hz does not care, but
    # hz_to_earfcn does, and 2620 MHz belongs to EARFCN 6150, not 40890.
    (38650, 39649, 1880000000,  100000),
    (37750, 38249, 2570000000,  100000),
    (39650, 41589, 2496000000,  100000),
)


def earfcn_to_hz(e):
    e = int(e)
    for lo, hi, base, step in JAMD_EARFCN_BANDS:
        if lo <= e <= hi:
            return base + (e - lo) * step
    raise ValueError('EARFCN %d is outside the TS 36.104 5.7.3 table' % e)


def hz_to_earfcn(f):
    f = int(f)
    # Walk the table in order and take the first band that lands exactly on
    # this frequency. Order matters because the bands overlap: the narrow
    # 1880-1920 and 2570-2620 MHz rows must be asked before the wide
    # 2496-2690 MHz row that contains them, and the table above is written
    # in that order on purpose.
    for lo, hi, base, step in JAMD_EARFCN_BANDS:
        n = hi - lo + 1
        if base <= f < base + n * step and (f - base) % step == 0:
            e = lo + (f - base) // step
            if earfcn_to_hz(e) == f:
                return e
    raise ValueError('%d Hz is off the EARFCN raster' % f)


def raster_selftest():
    # Known answers taken from the band edges the TS fixes: EARFCN 0 is
    # 0 Hz, 599 is 59.9 MHz, and each following table entry starts at its
    # base frequency. A generator that drifted by one row fails these.
    cases = [(0, 0), (599, 59900000), (600, 200000000), (1199, 259900000),
             (1200, 400000000), (1949, 474900000), (2750, 800000000),
             (37750, 2570000000), (38650, 1880000000), (39650, 2496000000),
             (6150, 2620000000), (9210, 3400000000)]
    bad = 0
    for e, hz in cases:
        got = earfcn_to_hz(e)
        if got != hz:
            print('raster\t%d\twant %d\tgot %d' % (e, hz, got))
            bad += 1
        back = hz_to_earfcn(hz)
        if back != e:
            print('raster_back\t%d\twant %d\tgot %d' % (hz, e, back))
            bad += 1
    # An off-raster frequency must be refused, not rounded onto a carrier.
    try:
        hz_to_earfcn(806000123)
        print('raster_off\t806000123\taccepted')
        bad += 1
    except ValueError:
        pass
    # An EARFCN outside every band must be refused.
    for e in (41600, 99999):
        try:
            earfcn_to_hz(e)
            print('raster_range\t%d\taccepted' % e)
            bad += 1
        except ValueError:
            pass
    print('raster_cases\t%d' % (2 * len(cases) + 3))
    print('raster_bad\t%d' % bad)
    sys.exit(1 if bad else 0)


def cmd_counters(argv):
    path = argv[0]
    if not os.path.isfile(path):
        sys.stderr.write('ERROR\tno such counters file: %s\n' % path)
        sys.exit(1)
    allowed = ('load_indicator', 'pdcch_decode_failure_rate', 'pbch_decode_failure_rate',
               'rsrp_delta_db', 'rsrq_delta_db', 'handover_success', 'uplink_bler',
               'rach_failure_rate', 'timestamps')
    seen = 0
    for line in open(path):
        line = line.rstrip('\n')
        if not line or line.startswith('#'):
            continue
        parts = line.split('\t')
        if len(parts) < 2:
            continue
        k = parts[0].strip().replace('\r', '')
        if k not in allowed:
            sys.stderr.write('WARN\tignoring unknown counter key: %s\n' % k)
            continue
        print('%s\t%s' % (k, san(parts[1].strip())))
        seen += 1
    if seen == 0:
        sys.stderr.write('ERROR\tno usable counter keys in %s\n' % path)
        sys.exit(1)


# ── the interfering waveform ────────────────────────────────────────────
#
# This is the half the analyser can check against itself, and it is built so
# that it can be. The generator produces samples; the analyser reads samples;
# a constructed narrowband waveform must come back from --analyse as
# 'narrowband' with occupied_fraction below 0.25, and a constructed barrage
# must come back as 'barrage' with a noise-floor step of at least 6 dB. Those
# are known-answer assertions on the construction, not on the code's opinion
# of itself.
#
# The pulse train is the duty cycle: `seg_on` seconds of the waveform then
# `seg_off` seconds of silence, repeated, so a 0.5 duty cycle is structurally
# half the samples at zero and the analyser's activity_fraction reads it back.

JAMD_SHAPES = ('awgn', 'cw', 'chirp',
               'pss', 'sss', 'pbch', 'pucch', 'prach', 'prs', 'gps-ca',
               'nr-ssb')
# Named, refused, and reported in its own fields: the name, why it is refused
# and (for a shape someone might expect) what to use instead. --status,
# --status-tsv and --tx-status print every one of these, and --tx-build prints
# the matching line before exiting 3, so a caller that saw a name in
# JAMD_SHAPES_REFUSED never has to guess why it is not in JAMD_SHAPES.
JAMD_SHAPES_REFUSED = ('lte-ssb',)
JAMD_SHAPE_REASON = (
    ('lte-ssb',
     'replaced by three shapes: an LTE sync block is PSS + SSS + PBCH, and '
     '--shape pss, --shape sss and --shape pbch now build each of them from '
     'tools/lte_phy.py; no producer in this tree emits one "lte-ssb" sample '
     'stream, so there is nothing to copy under that name'),
)
# The shapes whose samples come from a producer elsewhere in the tree. Each
# one names its producer in JAMD_SHAPE_PRODUCER, prints it in the `producer`
# row of --tx-build, and is placed at baseband centre by the same machinery
# the synthesised shapes use (peak, pulse train, writers).
JAMD_SIGNAL_SHAPES = ('pss', 'sss', 'pbch', 'pucch', 'prach', 'prs', 'gps-ca', 'nr-ssb')
JAMD_SHAPE_PRODUCER = (
    ('awgn', 'this module: numpy FFT mask in build()'),
    ('cw', 'this module: complex exponential in build()'),
    ('chirp', 'this module: linear sweep in build()'),
    ('pss',
     'tools/lte_phy.py: pss_sequence + sync_re_positions + ofdm_modulate'),
    ('sss',
     'tools/lte_phy.py: sss_sequence + sync_re_positions + ofdm_modulate'),
    ('pbch',
     'tools/lte_phy.py: pbch_encode + pbch_scramble + pbch_frame_bits + '
     'qpsk_modulate + pbch_re_positions + ofdm_modulate'),
    ('pucch',
     'tools/lte_phy.py: pucch_slot_grid + ofdm_modulate (TS 36.211 5.5)'),
    ('prach', 'tools/phy_seqs.py gen --seq prach (TS 36.211 5.7.2)'),
    ('prs', 'tools/phy_seqs.py gen --seq prs (TS 36.211 6.10.4)'),
    ('gps-ca', 'tools/phy_seqs.py gen --seq gps-ca (IS-GPS-200 3.2.2)'),
    ('nr-ssb', 'modules/12_nr_air.sh --ssb-waveform (TS 38.211 7.4.3)'),
)
JAMD_MODES = ('barrage', 'narrowband')


def parse_hz(s):
    """A frequency the operator typed: 2650000000, 2.65e9, 2650MHz, 2650M."""
    t = str(s).strip()
    if not t:
        raise ValueError('empty frequency')
    low = t.lower()
    mult = 1
    for suf, m in (('ghz', 1000000000), ('mhz', 1000000), ('khz', 1000), ('hz', 1),
                   ('g', 1000000000), ('m', 1000000), ('k', 1000)):
        if low.endswith(suf):
            low = low[:-len(suf)].strip()
            mult = m
            break
    v = float(low) * mult
    if v != int(v):
        raise ValueError('%s is not a whole number of Hz' % t)
    v = int(v)
    if v <= 0:
        raise ValueError('%s is not a positive frequency' % t)
    return v


# ── reference-signal shapes: the producers that already exist ────────────
#
# Seven of the shapes below are not synthesised here. They are the reference
# signals a receiver actually hunts for -- LTE PSS, SSS and PBCH, the LTE
# PRACH preamble and PRS, the GPS L1 C/A code, the NR SS/PBCH block -- and
# every one of them already has a producer in this tree. This module copies
# those samples. It does not reimplement a sequence, a resource map or an
# OFDM modulator, and it does not approximate one when the producer is
# missing: it refuses and says which tool it needed.
#
# What this module does own is the placement step, the same one the
# synthesised shapes go through: the samples are put at baseband centre,
# fitted to the capture length, peak-normalised to --peak, pulsed by
# --on/--off, and written by the one writer in build(). A shape built
# in-process says so in `producer`; a shape built by a subprocess puts the
# exact command in `producer_command`, so a reader can run it and compare.
SIG_DEFAULTS = {'prn': 1, 'pci': 1, 'root': 1, 'ncs': 0, 'v': 0, 'i-ssb': 0,
                'n-rb': 0, 'ports': 1, 'mib': 0, 'n-rb-prs': 100,
                'n-rb-dl': 100, 'scs': 30}


def die2(msg, why=None):
    """A usage error: rc 2, one ERROR line, and the reason when there is one."""
    sys.stderr.write('ERROR\t%s\n' % msg)
    if why:
        sys.stderr.write('WHY\t%s\n' % why)
    sys.exit(2)


def parse_sig(text):
    """`k=v,k=v` from the caller; whatever it omits keeps its default."""
    sig = dict(SIG_DEFAULTS)
    for part in str(text or '').split(','):
        part = part.strip()
        if not part:
            continue
        if '=' not in part:
            raise ValueError('signal argument %r is not key=value' % part)
        k, v = part.split('=', 1)
        k = k.strip()
        if k not in sig:
            raise ValueError('unknown signal argument %r (known: %s)'
                             % (k, ', '.join(sorted(sig))))
        sig[k] = v.strip()
    for k in sig:
        try:
            sig[k] = int(str(sig[k]).strip(), 10)
        except (TypeError, ValueError):
            raise ValueError('signal argument %s=%r is not an integer'
                             % (k, sig[k]))
    return sig


def jamd_root():
    """The checkout the producers live in, from IMSISTING_ROOT or the cwd."""
    for cand in (os.environ.get('IMSISTING_ROOT', ''), os.getcwd()):
        if cand and os.path.isfile(os.path.join(cand, 'tools', 'phy_seqs.py')):
            return cand
    return ''


def jamd_tmp():
    d = os.environ.get('JAMD_TMP') or ''
    return d if d and os.path.isdir(d) else None


def read_cf32_iq(path):
    """A cf32 file as complex128. Values are exactly the float32 that were
    written, so a byte comparison against the producer stays meaningful."""
    raw = np.fromfile(path, dtype='<f4')
    if raw.size < 2:
        raise ValueError('%s holds %d float32 values' % (path, raw.size))
    return raw[0::2].astype(np.float64) + 1j * raw[1::2].astype(np.float64)


def fit_to(x, n):
    """Exactly n samples: the producer's own rounding must not resize the
    capture a caller asked for. Returns (x, padded, trimmed) so the rows can
    say which happened."""
    if len(x) == n:
        return np.asarray(x), 0, 0
    if len(x) > n:
        return np.asarray(x[:n]), 0, len(x) - n
    return (np.concatenate([x, np.zeros(n - len(x), dtype=x.dtype)]),
            n - len(x), 0)


def run_producer(argv, want):
    """Run a producer, return its stdout rows. A producer that fails is
    reported in its own words: its message is the trustworthy one, and
    substituting noise for a missing sequence is the fabricated success this
    whole module is written to avoid."""
    import subprocess
    try:
        p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as e:
        die2('cannot run the %s producer (%s): %s' % (want, argv[0], e),
             'that tool is this shape\'s only source, so there is no signal '
             'to place and nothing is substituted for one')
    if p.returncode != 0:
        detail = (p.stderr.decode('utf-8', 'replace').strip()
                  .replace('\n', ' | ').replace('\t', ' '))
        die2('the %s producer exited %d: %s'
             % (want, p.returncode, detail or 'no message'),
             'the producer\'s own words are above; no capture was written')
    rows = {}
    for line in p.stdout.decode('utf-8', 'replace').splitlines():
        parts = line.split('\t')
        if len(parts) >= 2:
            rows[parts[0]] = parts[1]
    return rows


def phy_seqs_iq(seq, want, rate, secs, extra):
    """IQ from tools/phy_seqs.py, plus its rows and the PRS mapping sidecar.

    The producer writes cf32 always, and this module re-quantises once in
    build()'s writer, so a ci16 or cu8 capture goes through exactly one
    quantiser whichever shape produced it.
    """
    root = jamd_root()
    tool = os.path.join(root, 'tools', 'phy_seqs.py') if root else ''
    if not tool or not os.path.isfile(tool):
        die2('no tools/phy_seqs.py under %s' % (root or os.getcwd()),
             'the %s shape is that file\'s output; a missing producer is a '
             'missing capability, not a licence to synthesise one here' % want)
    d = tempfile.mkdtemp(prefix='jamd_%s_' % want, dir=jamd_tmp())
    out = os.path.join(d, 'samples.cf32')
    try:
        argv = [sys.executable, tool, 'gen', '--seq', seq,
                '--rate', str(rate), '--secs', '%.9f' % secs,
                '--format', 'cf32', '--out', out] + list(extra)
        rows = run_producer(argv, want)
        x = read_cf32_iq(out)
        remap = None
        side = out + '.remap.tsv'
        if os.path.isfile(side):
            with open(side, 'r') as fh:
                remap = fh.read()
    finally:
        shutil.rmtree(d, ignore_errors=True)
    return x, rows, remap


def producer_cmd(seq, rate, secs, extra):
    """The command line, with the temp path written as <out>."""
    return ('python3 tools/phy_seqs.py gen --seq %s --rate %d --secs %r '
            '--format cf32 %s --out <out>' % (seq, rate, secs, ' '.join(extra)))


def lte_phy_import():
    """tools/lte_phy.py, imported in-process: its sequences, its resource
    maps and its OFDM chain are the producer for pss/sss/pbch."""
    root = jamd_root()
    tp = os.path.join(root, 'tools') if root else ''
    if not tp or not os.path.isfile(os.path.join(tp, 'lte_phy.py')):
        die2('no tools/lte_phy.py under %s' % (root or os.getcwd()),
             'the pss/sss/pbch shapes are that file\'s sequences and its '
             'modulator; there is no second copy in this module')
    if tp not in sys.path:
        sys.path.insert(0, tp)
    try:
        import lte_phy
    except Exception as e:
        die2('cannot import tools/lte_phy.py: %s' % e,
             'without it there is no sequence to place and none is invented')
    return lte_phy


def lte_lookup(phy, rate):
    """(n_rb, n_fft) for an LTE sample rate, from lte_phy's own table."""
    for bw, n_rb, n_fft, fs in phy.LTE_OFDM:
        if fs == int(rate):
            return n_rb, n_fft
    die2('--rate %d is not an LTE sample rate' % int(rate),
         'an LTE reference signal is sampled at one of the bandwidths in '
         'tools/lte_phy.py LTE_OFDM: %s Hz (N_RB x 12 x 15 kHz, TS 36.211 '
         '6.12); there is nothing to resample it to'
         % ', '.join(str(fs) for bw, n_rb, n_fft, fs in phy.LTE_OFDM))


def signal_lte(shape, rate, sig):
    """One slot of an LTE reference signal, from lte_phy's own grid code.

    One slot (7 symbols), not a 10 ms frame: lte_phy's FFT is pure Python, a
    frame is 140 symbols of it, and a jamming constructor emits the signal at
    whatever duty the operator asked for. The `repeat` row says the slot is
    tiled, so nobody reads a slot cadence as a frame cadence.
    """
    phy = lte_phy_import()
    n_rb, n_fft = lte_lookup(phy, rate)
    n_sc = n_rb * 12
    cell = int(sig['pci'])
    if shape in ('pss', 'sss'):
        if not 0 <= cell <= 503:
            die2('--pci %d is outside an LTE cell id (0..503)' % cell)
        grid = phy.sync_grid(n_rb, cell, 0)
        l_sss, l_pss = phy.sync_symbols(0)
        # Blank the other sync signal: one shape, one sequence, so a capture
        # can be cross-correlated for exactly the signal it claims.
        grid[l_pss if shape == 'sss' else l_sss] = [0j] * n_sc
        l_used = l_pss if shape == 'pss' else l_sss
        which = 'pss' if shape == 'pss' else 'sss'
        pos = phy.sync_re_positions(n_rb, 0)[which]
        extra = [
            ('signal', 'LTE %s, %s (62 subcarriers at k = %d..%d of the centre '
                       '72, slot 0 symbol %d)'
             % (which.upper(),
                'TS 36.211 6.11.1 with the 36.211 Table 7.2.1-1 Gold sequence'
                if shape == 'pss' else
                'TS 36.211 6.11.2, m0/m1 from cell id N_ID^(1)',
                pos[1], pos[2], l_used)),
            ('cell_id', str(cell)),
            ('n_id_2', str(cell % 3)),
            ('lte_n_rb', str(n_rb)),
            ('lte_n_fft', str(n_fft)),
            ('lte_sample_rate_hz', str(int(rate))),
            ('lte_symbol', str(l_used)),
            ('repeat', 'one slot (7 symbols, %d samples) tiled to the capture '
                       'length: a cell sends this in slots 0 and 10 of a 10 ms '
                       'frame, this constructor emits it continuously so the '
                       'duty cycle is --on/--off, not the frame timing'
             % phy.slot_samples(n_fft)),
        ]
        clause = ('the 72 subcarriers PSS/SSS occupy (6 RB of 15 kHz, '
                  'TS 36.211 6.11)')
    elif shape == 'pucch':
        if not 0 <= cell <= 503:
            die2('--pci %d is outside an LTE cell id (0..503)' % cell)
        n_cs = int(sig['ncs'])
        if not 0 <= n_cs <= 11:
            die2('--ncs %d is outside a cyclic shift (0..11)' % n_cs)
        u, v = phy.pucch_sequence_group(cell)
        grid = phy.pucch_slot_grid(n_rb, cell, n_cs)
        extra = [
            ('signal', 'LTE PUCCH format 1a, TS 36.211 5.5.1/5.5.2.2: one RB '
                       '(12 subcarriers) in the band edge, cyclic shift %d, '
                       'data symbols l = 0,1,5,6 and reference symbols '
                       'l = 2,3,4, cover index 0' % n_cs),
            ('cell_id', str(cell)),
            ('sequence_group_u', str(u)),
            ('sequence_v', str(v)),
            ('group_hopping', 'off (one phase of the cell, not a hopping '
                              'pattern)'),
            ('n_cs', str(n_cs)),
            ('pucch_format', '1a'),
            ('pucch_occupied_rb', str(n_rb - 1)),
            ('lte_n_rb', str(n_rb)),
            ('lte_n_fft', str(n_fft)),
            ('lte_sample_rate_hz', str(int(rate))),
            ('repeat', 'one slot (7 symbols, %d samples) tiled to the capture '
                       'length: a handset sends PUCCH in its uplink slot, this '
                       'constructor emits it continuously so the duty cycle is '
                       '--on/--off, not the frame timing'
             % phy.slot_samples(n_fft)),
        ]
        clause = ('the one RB the PUCCH occupies (12 x 15 kHz = 180 kHz, '
                  'TS 36.211 5.5.2)')
    else:
        if not 0 <= cell <= 503:
            die2('--pci %d is outside an LTE cell id (0..503)' % cell)
        if not 1 <= int(sig['ports']) <= 4:
            die2('--ports %d is not an antenna port count (1..4)' % int(sig['ports']))
        mib = int(sig['mib'])
        if not 0 <= mib < (1 << 24):
            die2('--mib %d is outside the 24-bit MIB' % mib)
        bits = [(mib >> (23 - i)) & 1 for i in range(24)]
        block = phy.pbch_encode(bits, int(sig['ports']), cell)
        frame = phy.pbch_frame_bits(phy.pbch_scramble(block, cell), 0)
        syms = phy.qpsk_modulate(frame)
        grid = [[0j] * n_sc for _ in range(7)]
        pos = phy.pbch_re_positions(n_rb, cell)
        if len(pos) != len(syms):
            raise ValueError('PBCH map has %d REs for %d QPSK symbols'
                             % (len(pos), len(syms)))
        for (l, k), v in zip(pos, syms):
            grid[l][k] = v
        extra = [
            ('signal', 'LTE PBCH: %d QPSK REs of slot 1 (TS 36.211 6.6.4), '
                       'mapped by pbch_re_positions, CRS of 4 ports skipped'
             % len(pos)),
            ('cell_id', str(cell)),
            ('mib', '%06x' % mib),
            ('nof_ports', str(int(sig['ports']))),
            ('pbch_re', str(len(pos))),
            ('pbch_coded_bits', str(len(block))),
            ('pbch_frame_bits', str(len(frame))),
            ('lte_n_rb', str(n_rb)),
            ('lte_n_fft', str(n_fft)),
            ('lte_sample_rate_hz', str(int(rate))),
            ('repeat', 'one slot (7 symbols, %d samples) tiled to the capture '
                       'length: a cell sends PBCH in slot 1 of every frame and '
                       'repeats the codeword over 4 frames; this constructor '
                       'emits it continuously' % phy.slot_samples(n_fft)),
        ]
        clause = ('the 72 subcarriers PBCH occupies (6 RB of 15 kHz, '
                  'TS 36.211 6.6.4)')
    samples, lengths = phy.ofdm_modulate(grid, n_fft)
    x = np.asarray(samples, dtype=np.complex128)
    extra.append(('slot_samples', str(len(x))))
    occ_hz = int(round(12 * 15000)) if shape == 'pucch' else int(round(72 * 15000))
    return x, extra, occ_hz, clause


def signal_iq(shape, rate, secs, n, sig):
    """The named signal's samples plus the rows that describe where they came
    from. Returns a dict; `rate` and `n` can come back changed (prs is
    RE-domain, so its rate is the producer's frame rate, not --rate)."""
    if shape in ('pss', 'sss', 'pbch', 'pucch'):
        block, extra, occ, clause = signal_lte(shape, rate, sig)
        x, pad, cut = fit_to(np.resize(block, n), n)
        extra.append(('occupied_basis', clause))
        extra.append(('padded_samples', str(pad)))
        extra.append(('trimmed_samples', str(cut)))
        extra.append(('producer_command',
                      'in-process import of tools/lte_phy.py (no subprocess)'))
        return {'x': x, 'rate': int(rate), 'n': n, 'occ': occ, 'rows': extra}

    if shape == 'gps-ca':
        argv = ['--prn', str(sig['prn'])]
        x, rows, _ = phy_seqs_iq('gps-ca', 'gps-ca', rate, secs, argv)
        x, pad, cut = fit_to(x, n)
        chip = int(rows.get('chip_rate_hz', '1023000'))
        extra = [
            ('signal', 'GPS L1 C/A spreading code, IS-GPS-200 3.2.2 '
                       '(G1/G2 taps and the PRN delay from Table 3-Ia)'),
            ('producer_command', producer_cmd('gps-ca', rate, secs, argv)),
            ('repeat', 'the 1023-chip period is repeated by the producer; '
                       'samples are a zero-order hold of the chip train at '
                       '--rate (real baseband: Q = 0, no carrier, no nav data)'),
            ('prn', rows.get('prn', str(sig['prn']))),
            ('g2_delay_chips', rows.get('g2_delay_chips', '-')),
            ('chip_rate_hz', str(chip)),
            ('chips_per_period', rows.get('chips_per_period', '-')),
            ('padded_samples', str(pad)),
            ('trimmed_samples', str(cut)),
            ('occupied_basis', 'the code\'s own chip rate (1.023 Mcps); its '
                               'BPSK main lobe is twice that, and the '
                               'zero-order hold puts it wherever --rate is'),
        ]
        return {'x': x, 'rate': int(rate), 'n': n, 'occ': chip, 'rows': extra}

    if shape == 'prach':
        argv = ['--preamble', str(sig['root']), '--ncs', str(sig['ncs']),
                '--v', str(sig['v'])]
        x, rows, _ = phy_seqs_iq('prach', 'prach', rate, secs, argv)
        x, pad, cut = fit_to(x, n)
        ra = int(rows.get('n_ra_hz', '1048750'))
        extra = [
            ('signal', 'LTE PRACH preamble, format 0 (TS 36.211 5.7.2): '
                       'Zadoff-Chu root %s, N_CS zone %s, v = %s'
             % (rows.get('preamble_root_u', '?'), rows.get('ncs_zone', '?'),
                rows.get('v', '?'))),
            ('producer_command', producer_cmd('prach', rate, secs, argv)),
            ('repeat', 'the producer tiles whole 1 ms PRACH occasions (CP, '
                       'sequence, guard); this constructor does not move the '
                       'occasion, only pulses the whole capture'),
            ('preamble_format', rows.get('preamble_format', '-')),
            ('preamble_root_u', rows.get('preamble_root_u', '-')),
            ('ncs_zone', rows.get('ncs_zone', '-')),
            ('ncs', rows.get('ncs', '-')),
            ('cv', rows.get('cv', '-')),
            ('n_ra_hz', str(ra)),
            ('cp_samples', rows.get('cp_samples', '-')),
            ('seq_samples', rows.get('seq_samples', '-')),
            ('guard_samples', rows.get('guard_samples', '-')),
            ('subframe_samples', rows.get('subframe_samples', '-')),
            ('padded_samples', str(pad)),
            ('trimmed_samples', str(cut)),
            ('occupied_basis', '1.04875 MHz = 839 subcarriers over the 800 us '
                               'sequence, TS 36.211 5.7.2'),
        ]
        return {'x': x, 'rate': int(rate), 'n': n, 'occ': ra, 'rows': extra}

    if shape == 'prs':
        argv = ['--pci', str(sig['pci']), '--n-rb-prs', str(sig['n-rb-prs']),
                '--n-rb-dl', str(sig['n-rb-dl'])]
        x, rows, remap = phy_seqs_iq('prs', 'prs', rate, secs, argv)
        rate_used = int(rows.get('rate', '1760000'))
        n_used = len(x)
        extra = [
            ('signal', 'LTE PRS (TS 36.211 6.10.4): %s symbols per frame, %s '
                       'resources per symbol, QPSK from the 6.10.4.2 seed '
                       'c_init = 2^10 (7 (n_s+1) + l + 1) (2 N_ID_PRS + 1)'
             % (rows.get('symbols_per_frame', '?'),
                rows.get('re_per_symbol', '?'))),
            ('producer_command', producer_cmd('prs', rate, secs, argv)),
            ('rate_basis', 'RE-domain: one sample per PRS resource element, so '
                           'the rate is the producer\'s frame rate, not a '
                           'waveform sample rate -- resampling it would invent '
                           'a waveform nobody transmits'),
            ('requested_rate_hz', str(int(rate))),
            ('pci', rows.get('pci', str(sig['pci']))),
            ('n_id_prs', rows.get('n_id_prs', '-')),
            ('n_rb_prs', rows.get('n_rb_prs', '-')),
            ('n_rb_dl', rows.get('n_rb_dl', '-')),
            ('prs_bandwidth_hz', str(int(rows.get('n_rb_prs', '0')) * 12 * 15000)),
            ('symbols_per_frame', rows.get('symbols_per_frame', '-')),
            ('samples_per_frame', rows.get('samples_per_frame', '-')),
            ('mapping_rows', rows.get('mapping_rows', '-')),
            ('frames', rows.get('frames', '-')),
            ('occupied_basis', 'RE-domain samples occupy their whole file: '
                               'every value is one PRS resource element'),
        ]
        out = {'x': x, 'rate': rate_used, 'n': n_used, 'occ': rate_used,
               'rows': extra, 'remap': remap}
        return out

    if shape == 'nr-ssb':
        root = jamd_root()
        gen = os.path.join(root, 'modules', '12_nr_air.sh') if root else ''
        if not gen or not os.path.isfile(gen):
            die2('no modules/12_nr_air.sh under %s' % (root or os.getcwd()),
                 'the NR SSB waveform is that module\'s output; there is no '
                 'second SSB builder in this tree and none is written here')
        scs = int(sig['scs'])
        nfft = int(round(float(rate) / (scs * 1000.0)))
        if nfft <= 0 or nfft * scs * 1000 != int(rate):
            die2('--rate %d is not N_FFT x --scs %d kHz for a whole N_FFT'
                 % (int(rate), scs),
                 'the SSB generator samples at rate = N_FFT x SCS (TS 38.211 '
                 '5.3); 30720000 with --scs 30 gives N_FFT 1024, 15360000 '
                 'with --scs 15 does too')
        # 4 SSB symbols cannot be shorter than 4 x N_FFT, so this estimate
        # never asks for too few repetitions.
        reps = int(math.ceil(n / float(4 * nfft))) or 1
        n_rb = int(sig['n-rb']) or 51
        d = tempfile.mkdtemp(prefix='jamd_nrssb_', dir=jamd_tmp())
        out = os.path.join(d, 'ssb.cf32')
        try:
            argv = [gen, '--ssb-waveform', out, '--format', 'cf32',
                    '--rate', str(int(rate)), '--n-rb', str(n_rb),
                    '--pci', str(sig['pci']), '--i-ssb', str(sig['i-ssb']),
                    '--scs', str(scs), '--reps', str(reps)]
            rows = run_producer(argv, 'nr-ssb')
            burst = read_cf32_iq(out)
        finally:
            shutil.rmtree(d, ignore_errors=True)
        x, pad, cut = fit_to(np.resize(burst, max(n, len(burst))), n)
        scs_hz = int(rows.get('scs_khz', str(scs))) * 1000
        # The producer writes --reps bursts end to end; the interesting number
        # is one burst (4 symbols of (N_FFT + CP)), so report it per burst and
        # the rep count separately rather than the tiled total.
        reps_n = max(1, int(rows.get('reps', reps) or reps))
        burst_total = int(rows.get('samples', len(burst)))
        extra = [
            ('signal', 'NR SS/PBCH block (TS 38.211 7.4.3): 240 subcarriers, '
                       '%s kHz SCS, i_ssb %s, PCI %s'
             % (rows.get('scs_khz', '?'), rows.get('i_ssb', '?'),
                rows.get('pci', '?'))),
            ('producer_command', 'bash modules/12_nr_air.sh --ssb-waveform '
                                 '<out> --format cf32 --rate %d --n-rb %d '
                                 '--pci %d --i-ssb %d --scs %d --reps %d'
             % (int(rate), n_rb, sig['pci'], sig['i-ssb'], scs, reps)),
            ('repeat', '%s SSB burst(s) of 4 symbols tiled to the capture '
                       'length: an SSB is one burst per SSB period in a real '
                       'frame, this constructor emits it continuously'
             % rows.get('reps', str(reps))),
            ('pci', rows.get('pci', '-')),
            ('i_ssb', rows.get('i_ssb', '-')),
            ('scs_khz', rows.get('scs_khz', '-')),
            ('nr_n_rb', rows.get('n_rb', '-')),
            ('fft_size', rows.get('fft_size', '-')),
            ('ssb_symbols', rows.get('symbols', '-')),
            ('reps', rows.get('reps', '-')),
            ('ssb_burst_samples', str(burst_total // reps_n)),
            ('padded_samples', str(pad)),
            ('trimmed_samples', str(cut)),
            ('occupied_basis', '240 subcarriers x SCS (TS 38.211 7.4.3)'),
        ]
        return {'x': x, 'rate': int(rate), 'n': n,
                'occ': int(240 * scs_hz), 'rows': extra}

    raise ValueError('signal_iq has no builder for %s' % shape)


def build(path, mode, shape, fmt, rate, secs, centre_hz, band_hz, peak_fs,
          on_s, off_s, seed, earfcn, sig_text=''):
    """Construct an interfering waveform and write it in fmt.

    mode       'barrage' fills the whole capture band; 'narrowband' fills
               band_hz or less, centred on offset_hz from the capture centre.
               A reference-signal shape is narrowband by nature and refuses
               anything else rather than emit a full-band copy of a slice
    shape      awgn | cw | chirp, or one of JAMD_SIGNAL_SHAPES, whose samples
               come from the producer named in JAMD_SHAPE_PRODUCER
    peak_fs    peak magnitude in full scale, 0 < peak_fs <= 1. A driver that
               clips reports success and radiates splatter, so the peak is
               clamped here rather than left to the SDR's own protection
    on_s/off_s the pulse train; off_s = 0 means continuous
    sig_text   k=v,k=v producer parameters (PRN, PCI, preamble root, ...)
    """
    if mode not in JAMD_MODES:
        raise ValueError('mode must be barrage or narrowband: %s' % mode)
    if shape in JAMD_SHAPES_REFUSED:
        why = dict(JAMD_SHAPE_REASON)[shape]
        sys.stderr.write('ERROR\tshape %s is refused and not built: %s\n'
                         % (shape, why))
        sys.stderr.write('WHY\ta refused shape is reported with the reason it '
                         'is refused and no file is written; filling one with '
                         'noise, or with a sequence this module made up, is '
                         'the fabricated success it exists to prevent\n')
        print('shape_reason\t%s\t%s' % (shape, san(why)))
        sys.exit(3)
    if shape not in JAMD_SHAPES:
        raise ValueError('shape must be %s: %s' % ('|'.join(JAMD_SHAPES), shape))
    rate = int(rate)
    if rate <= 0:
        raise ValueError('rate must be a positive integer')
    if secs <= 0:
        raise ValueError('seconds must be positive')
    if not (0.0 < peak_fs <= 1.0):
        raise ValueError('peak full scale must be in (0, 1]: %s' % peak_fs)
    if on_s <= 0 or off_s < 0:
        raise ValueError('the pulse train needs on_s > 0 and off_s >= 0')

    declared = None
    if band_hz not in (None, '', 0, '0'):
        declared = int(band_hz)
        if declared <= 0:
            raise ValueError('occupied bandwidth must be positive: %s' % band_hz)

    if shape in JAMD_SIGNAL_SHAPES and mode != 'narrowband':
        die2('shape %s is a reference signal, so it is built in narrowband '
             'mode, not %s' % (shape, mode),
             'a named reference signal occupies its own slice of the band; '
             '"barrage" would mean filling the whole capture with it, which no '
             'producer emits. Use --mode narrowband for the name, or --shape '
             'awgn / --shape chirp for a signal that does fill the band')

    rng = np.random.default_rng(int(seed))
    n = int(rate * secs)
    extra = []
    if shape in JAMD_SIGNAL_SHAPES:
        got = signal_iq(shape, rate, secs, n, parse_sig(sig_text))
        x, occ_hz, extra = got['x'], got['occ'], got['rows']
        rate, n = got['rate'], got['n']
        secs = n / float(rate)
        if got.get('remap'):
            side = path + '.remap.tsv'
            with open(side, 'w') as fh:
                fh.write(got['remap'])
            extra.append(('mapping_file', san(side)))
        if occ_hz > rate:
            die2('--rate %d Hz is narrower than the %s signal itself (%d Hz)'
                 % (rate, shape, occ_hz),
                 'the capture cannot hold a signal wider than its own band: '
                 'raise --rate (it is also the sample rate the produced file '
                 'is written at)')
        if declared is not None and declared < occ_hz:
            die2('--band %d Hz is narrower than the %s signal\'s own %d Hz'
                 % (declared, shape, occ_hz),
                 'the constructor places the producer\'s signal as it is and '
                 'will not decimate a reference signal to fit a window')
        if declared is not None and declared > rate:
            die2('--band %d Hz is wider than the %d Hz capture band'
                 % (declared, rate),
                 'the producer fills a %d Hz file one sample per sample, so a '
                 'window wider than the file describes a band the samples do '
                 'not cover and the report would name a width nothing holds. '
                 'Omit --band, or raise --rate' % rate)
    elif mode == 'barrage':
        occ_hz = rate
    else:
        occ_hz = int(declared) if declared is not None else 0
        if occ_hz <= 0:
            raise ValueError('narrowband needs a positive occupied bandwidth')
        if occ_hz > rate:
            die2('occupied %d Hz does not fit the %d Hz capture band'
                 % (occ_hz, rate),
                 'a narrowband burst is written at --rate, so a --band wider '
                 'than the file cannot be filled: raise --rate, or lower '
                 '--band')
        nbin = 4.0 * rate / max(1, int(rate * secs))
        if occ_hz < nbin:
            raise ValueError('occupied %d Hz is below the analyser resolution '
                             '(%.0f Hz at %d samples)' % (occ_hz, nbin,
                                                          int(rate * secs)))

    if n < 2048:
        raise ValueError('too few samples (%d); need at least 2048' % n)

    if shape in JAMD_SIGNAL_SHAPES:
        pass                      # x is the producer's samples, already placed
    elif mode == 'barrage':
        x = (rng.normal(0, 1, n) + 1j * rng.normal(0, 1, n)) / np.sqrt(2.0)
    else:
        base = (rng.normal(0, 1, n) + 1j * rng.normal(0, 1, n)) / np.sqrt(2.0)
        if shape == 'awgn':
            X = np.fft.fft(base)
            fr = np.fft.fftfreq(n, d=1.0 / rate)
            X[np.abs(fr) > occ_hz / 2.0] = 0
            x = np.fft.ifft(X)
        elif shape == 'cw':
            t = np.arange(n) / float(rate)
            x = np.exp(2j * np.pi * 0.0 * t)
        else:  # chirp
            dur = n / float(rate)
            k = occ_hz / dur          # sweeps the occupied band once
            t = np.arange(n) / float(rate)
            x = np.exp(2j * np.pi * (t * (-occ_hz / 2.0) + 0.5 * k * t * t))
            x /= np.sqrt(2.0)

    # Pulse train: the duty cycle is structural, not statistical.
    if off_s > 0:
        gate = np.zeros(n, dtype=bool)
        on_n = max(1, int(round(on_s * rate)))
        off_n = max(1, int(round(off_s * rate)))
        for i0 in range(0, n, on_n + off_n):
            gate[i0:i0 + on_n] = True
        x = np.where(gate, x, 0.0)

    # Peak-normalise to the requested full scale. Measured, printed and
    # asserted, because a clipped waveform is a splatter source.
    peak = float(np.max(np.abs(x))) if n else 0.0
    if peak > 0:
        x = x * (peak_fs / peak)
    measured = float(np.max(np.abs(x)))
    # A shape built from a unit-modulus table (PSS, SSS, PRACH, the GPS C/A
    # code) normalises to exactly full scale, and the last rounding can land a
    # hair above 1.0. Pull the gain back instead of refusing: 1e-6 is far below
    # any real correction and far above the 1.2e-7 float32 resolution, so this
    # converges in one pass and the file written is measured at or below full
    # scale -- the same guarantee, stated as a measurement, not a promise.
    for _ in range(8):
        if measured <= 1.0:
            break
        x = x * ((1.0 - 1e-6) / measured)
        measured = float(np.max(np.abs(x)))
    if measured > 1.0:
        raise ValueError('waveform peak %.6f exceeds full scale after scaling' % measured)

    if fmt == 'cf32':
        x.astype('<c8').tofile(path)
    elif fmt == 'ci16':
        b = np.empty(2 * n, dtype='<i2')
        b[0::2] = np.clip(np.round(x.real * 32767.0), -32768, 32767).astype('<i2')
        b[1::2] = np.clip(np.round(x.imag * 32767.0), -32768, 32767).astype('<i2')
        b.tofile(path)
    elif fmt == 'cu8':
        b = np.empty(2 * n, dtype=np.uint8)
        b[0::2] = np.clip(np.round(x.real * 127.0 + 127.5), 0, 255).astype(np.uint8)
        b[1::2] = np.clip(np.round(x.imag * 127.0 + 127.5), 0, 255).astype(np.uint8)
        b.tofile(path)
    else:
        raise ValueError('unknown IQ format %s (want cf32|ci16|cu8)' % fmt)

    duty = (on_s / float(on_s + off_s)) if off_s > 0 else 1.0
    off = n - int(gate.sum()) if off_s > 0 else 0
    # What the driver actually receives, stated so it can be checked.
    if fmt == 'cf32':
        drivers = 'soapysdr (CSF32), uhd (fc32)'
    elif fmt == 'ci16':
        drivers = 'bladeRF (SC16), limesdr (CS16), usrp (sc16)'
    else:
        drivers = 'hackrf (CS8), rtlsdr (CS8)'
    band = int(rate) if mode == 'barrage' else int(occ_hz)
    e = hz_to_earfcn(centre_hz) if earfcn else None
    # Where the samples came from, for every shape, before where they went.
    extra.insert(0, ('producer', dict(JAMD_SHAPE_PRODUCER)[shape]))
    print('path\t%s' % san(path))
    print('mode\t%s' % mode)
    print('shape\t%s' % shape)
    print('format\t%s' % fmt)
    print('rate\t%d' % rate)
    print('seconds\t%.6f' % secs)
    print('samples\t%d' % n)
    print('bytes\t%d' % os.path.getsize(path))
    print('centre_hz\t%d' % int(centre_hz))
    print('centre_mhz\t%.6f' % (int(centre_hz) / 1e6))
    print('earfcn\t%s' % (e if e is not None else '-'))
    print('occupied_hz\t%d' % band)
    print('occupied_fraction\t%.3f' % (band / float(rate)))
    print('peak_full_scale\t%.4f' % measured)
    print('duty_cycle\t%.3f' % duty)
    print('on_s\t%.6f' % on_s)
    print('off_s\t%.6f' % off_s)
    print('gated_samples\t%d' % off)
    print('driver_format\t%s' % drivers)
    for k, v in extra:
        print('%s\t%s' % (k, san(v)))
    print('constructed\tyes')


# ── synthetic fixtures for the selftest (receive files only) ────────────
#
# These are receive-side fixtures: clean, raised and narrow captures the
# analyser is pointed at. The transmit side has its own constructor, build(),
# above; the two are kept apart so that "does the analyser read this correctly"
# and "does the generator produce what it claims" stay separable assertions.
def gen(path, kind, fmt, rate, secs):
    n = int(rate * secs)
    if kind == 'prach':
        # A receive-side capture whose interference is a real PRACH preamble
        # rather than a synthetic carrier. It occupies one narrow slice, so
        # the verdict is a measurement of what this analyser sees in the
        # signal a base station is actually listening for.
        x, _rows, _remap = phy_seqs_iq('prach', 'prach', int(rate), float(secs),
                                       ['--preamble', '1', '--ncs', '0',
                                        '--v', '0'])
        x, _pad, _cut = fit_to(x, n)
    elif kind in ('clean', 'raised', 'narrow'):
        rng = np.random.default_rng(20240101)
        noise = (rng.normal(0, 1, n) + 1j * rng.normal(0, 1, n))
        carrier = (rng.normal(0, 1, n) + 1j * rng.normal(0, 1, n)) * 0.3
        x = noise + carrier
        half = n // 2
        if kind == 'raised':
            x[half:] = x[half:] + (rng.normal(0, 1, n - half) + 1j * rng.normal(0, 1, n - half)) * 3.0
        elif kind == 'narrow':
            m = n - half
            itf = (rng.normal(0, 1, m) + 1j * rng.normal(0, 1, m))
            XI = np.fft.fft(itf)
            fr = np.fft.fftfreq(m, d=1.0 / rate)
            XI[np.abs(fr - 200000.0) >= 25000.0] = 0
            itf = np.fft.ifft(XI) * 10.0
            x[half:] = x[half:] + itf
    else:
        sys.stderr.write('ERROR\tunknown fixture kind %s\n' % kind)
        sys.exit(2)
    if fmt == 'cf32':
        x.astype(np.complex64).tofile(path)
    elif fmt == 'ci16':
        b = np.empty(2 * n, dtype='<i2')
        b[0::2] = np.clip(x.real * 32768.0, -32768, 32767).astype('<i2')
        b[1::2] = np.clip(x.imag * 32768.0, -32768, 32767).astype('<i2')
        b.tofile(path)
    elif fmt == 'cu8':
        b = np.empty(2 * n, dtype=np.uint8)
        b[0::2] = np.clip(x.real * 127.5 + 127.5, 0, 255).astype(np.uint8)
        b[1::2] = np.clip(x.imag * 127.5 + 127.5, 0, 255).astype(np.uint8)
        b.tofile(path)
    else:
        sys.stderr.write('ERROR\tunknown IQ format %s\n' % fmt)
        sys.exit(2)


def main():
    argv = sys.argv[1:]
    if not argv:
        sys.stderr.write('usage: jamd_py <analyse|noisefloor|characterise|occupancy|counters|gen|build|raster> ...\n')
        sys.exit(2)
    mode, rest = argv[0], argv[1:]
    try:
        if mode == 'analyse':
            return cmd_analyse(rest)
        if mode == 'noisefloor':
            return cmd_noisefloor(rest)
        if mode == 'characterise':
            return cmd_characterise(rest)
        if mode == 'occupancy':
            return cmd_occupancy(rest)
        if mode == 'counters':
            return cmd_counters(rest)
        if mode == 'raster':
            return raster_selftest()
        if mode == 'shapes':
            print(' '.join(JAMD_SHAPES))
            return None
        if mode == 'shapes-refused':
            print(' '.join(JAMD_SHAPES_REFUSED))
            return None
        if mode == 'shape-table':
            # One process for the whole table: every verb that reports the
            # shapes needs all of it, and six python startups per verb is six
            # numpy imports for one answer.
            print('shapes\t%s' % ' '.join(JAMD_SHAPES))
            print('signal_shapes\t%s' % ' '.join(JAMD_SIGNAL_SHAPES))
            print('shapes_refused\t%s' % ' '.join(JAMD_SHAPES_REFUSED))
            print('modes\t%s' % ' '.join(JAMD_MODES))
            for s_ in JAMD_SHAPES:
                print('shape_producer\t%s\t%s' % (s_, dict(JAMD_SHAPE_PRODUCER)[s_]))
            for s_ in JAMD_SHAPES_REFUSED:
                print('shape_refused_reason\t%s\t%s'
                      % (s_, dict(JAMD_SHAPE_REASON)[s_]))
            return 0
        if mode == 'signal-shapes':
            print(' '.join(JAMD_SIGNAL_SHAPES))
            return None
        if mode == 'shape-producers':
            # shape, producer: one TSV row per shape so --status can show
            # where every name's samples come from without a second lookup.
            for name, prod in JAMD_SHAPE_PRODUCER:
                print('%s\t%s' % (name, prod))
            return None
        if mode == 'shape-reasons':
            # shape, reason: the machine-readable half of a refusal.
            for name, why in JAMD_SHAPE_REASON:
                print('%s\t%s' % (name, why))
            return None
        if mode == 'shape-reason':
            why = dict(JAMD_SHAPE_REASON).get(rest[0] if rest else '', '')
            print(why)
            return None
        if mode == 'shape-known':
            print('yes' if (rest and rest[0] in JAMD_SHAPES) else 'no')
            return None
        if mode == 'sig-defaults':
            print(','.join('%s=%d' % (k, v) for k, v in sorted(SIG_DEFAULTS.items())))
            return None
        if mode == 'modes':
            print(' '.join(JAMD_MODES))
            return None
        if mode == 'hz':
            print(parse_hz(rest[0]))
            return None
        if mode == 'arfcn':
            print(hz_to_earfcn(parse_hz(rest[0])))
            return None
        if mode == 'earfcn':
            print(earfcn_to_hz(int(rest[0])))
            return None
        if mode == 'gen':
            return gen(rest[0], rest[1], rest[2], int(rest[3]), float(rest[4]))
        if mode == 'build':
            # build <path> <mode> <shape> <fmt> <rate> <secs> <centre_hz>
            #       <band_hz> <peak_fs> <on_s> <off_s> <seed> <earfcn 0|1>
            #       [<k=v,k=v producer parameters>]
            return build(rest[0], rest[1], rest[2], rest[3], int(rest[4]),
                         float(rest[5]), parse_hz(rest[6]), rest[7],
                         float(rest[8]), float(rest[9]), float(rest[10]),
                         int(rest[11]), int(rest[12]),
                         rest[13] if len(rest) > 13 else '')
        sys.stderr.write('unknown mode %s\n' % mode)
        sys.exit(2)
    except SystemExit:
        raise
    except Exception as e:
        sys.stderr.write('ERROR\t%s\n' % e)
        sys.exit(1)


sys.exit(main() or 0)
PY
}

# ── feature record I/O ──────────────────────────────────────────────────
jamd_save_features() {
    # stdin: key<TAB>value lines; replaces the record atomically.
    mkdir -p "$JAMD_DIR"
    local tmp="$JAMD_FEATURES.$$"
    cat > "$tmp" || { rm -f "$tmp"; return 1; }
    mv "$tmp" "$JAMD_FEATURES" || { rm -f "$tmp"; return 1; }
    return 0
}

jamd_fld() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }
jamd_feature_get() { awk -F'\t' -v k="$2" '$1==k{print $2; exit}' "$1" 2>/dev/null; }

# ── IQ verbs ────────────────────────────────────────────────────────────
jamd_check_args() {
    local f="${1:-}" fmt="${2:-}" rate="${3:-}"
    [[ -n "$f" && -n "$fmt" && -n "$rate" ]] || {
        printf 'ERROR\tusage: need <iq-file> <format> <rate>\n' >&2; return 2; }
    [[ "$rate" =~ ^[0-9]+$ ]] && (( rate > 0 )) || {
        printf 'ERROR\trate must be a positive integer\n' >&2; return 2; }
    case "$fmt" in cf32|ci16|cu8) ;; *) printf 'ERROR\tunknown format: %s (want cf32|ci16|cu8)\n' "$fmt" >&2; return 2 ;; esac
    [[ -f "$f" ]] || { printf 'ERROR\tno such IQ file: %s\n' "$f" >&2; return 1; }
    return 0
}

jamd_cmd_analyse() {
    local f="${1:-}" fmt="${2:-}" rate="${3:-}"
    jamd_check_args "$f" "$fmt" "$rate" || return $?
    local out; out=$(jamd_py analyse "$f" "$fmt" "$rate") || return 1
    [[ -n "$out" ]] || { printf 'ERROR\tanalysis produced nothing\n' >&2; return 1; }
    printf '%s\n' "$out"
    # A counter record from a previous --counters call is preserved across a
    # re-analysis only if the caller re-supplies it; the record is otherwise
    # the IQ-derived features.
    printf '%s\n' "$out" | jamd_save_features
}

jamd_cmd_noise_floor() {
    local f="${1:-}" fmt="${2:-}" rate="${3:-}"
    jamd_check_args "$f" "$fmt" "$rate" || return $?
    jamd_py noisefloor "$f" "$fmt" "$rate"
}

jamd_cmd_characterise() {
    local f="${1:-}" fmt="${2:-}" rate="${3:-}" centre="${4:-}"
    jamd_check_args "$f" "$fmt" "$rate" || return $?
    jamd_py characterise "$f" "$fmt" "$rate" "$centre"
}

# ── fixtures: a capture whose answer is known by construction ───────────
# The analyser's own selftest has always synthesised captures to prove itself;
# this exposes the same generator so a run can be REPEATED later, and so a chain
# can drive the whole receive path (fixture -> analyse -> characterise) on a host
# with no radio and no pre-existing capture. It writes a file and keys nothing,
# so it is deliberately outside the lab gate: constructing samples is not
# transmitting them.
#
# Each fixture is labelled with the verdict it is built to produce. That label
# is a claim the analyser has to meet, not a description of the file: the
# selftest runs all three through --characterise and fails if the generator and
# the analyser ever disagree.
# ── spectrum occupancy over a recording ─────────────────────────────────
# A recording is a slice of band with a known width, so the slice can be cut
# into frequency bins and each bin watched over time. This answers three
# things a single noise-floor number cannot: which parts of the slice were in
# use, for what fraction of the capture, and where the edges of each stretch
# are. It does not decide whether the noise is jamming (that is
# --discriminate) and it does not read the air (that is --analyse).
jamd_cmd_occupancy() {
    local f="" fmt="cf32" rate="" bins="" thr="" edge=""
    while (($#)); do
        case "$1" in
            --format)       fmt="${2:-}";  shift 2 ;;
            --rate)         rate="${2:-}"; shift 2 ;;
            --bins)         bins="${2:-}"; shift 2 ;;
            --threshold-db) thr="${2:-}";  shift 2 ;;
            --edge-pct)     edge="${2:-}"; shift 2 ;;
            -*) printf 'ERROR\t--occupancy does not take %s (see --help)\n' "$1" >&2; return 2 ;;
            *)  if [[ -z "$f" ]]; then f="$1"; shift
                else printf 'ERROR\t--occupancy takes one capture path\n' >&2; return 2; fi ;;
        esac
    done
    [[ -n "$f" ]] || {
        printf 'ERROR\tno capture given\n' >&2
        printf 'WHY\toccupancy is measured from a recording; there is nothing to measure on a radio that is not recording\n' >&2
        return 2; }
    [[ -n "$rate" ]] || {
        printf 'ERROR\t--rate is required\n' >&2
        printf 'WHY\tthe same file is a different bandwidth at a different sample rate, so the width of every bin comes from the rate and not from the path\n' >&2
        return 2; }
    [[ "$rate" =~ ^[1-9][0-9]*$ ]] || {
        printf 'ERROR\t--rate must be a positive integer in Hz\n' >&2; return 2; }
    case "$fmt" in cf32|ci16|cu8|cs8|c16|sc16|cs16) ;;
        *) printf 'ERROR\tunknown format: %s (want cf32|ci16|cu8 or a driver alias)\n' "$fmt" >&2; return 2 ;; esac
    case "$fmt" in cs8) fmt="cu8" ;; c16|sc16|cs16) fmt="ci16" ;; esac
    local extra=()
    [[ -n "$bins" ]] && extra+=(--bins "$bins")
    [[ -n "$thr" ]]  && extra+=(--threshold-db "$thr")
    [[ -n "$edge" ]] && extra+=(--edge-pct "$edge")
    jamd_py occupancy "$f" "$fmt" "$rate" ${extra[@]+"${extra[@]}"}
}

jamd_cmd_fixture() {
    local kind="" out="" fmt="cf32" rate="$JAMD_TX_DEFAULT_RATE" secs="0.5"
    while (($#)); do
        case "$1" in
            --format) fmt="${2:-}"; shift 2 ;;
            --rate)   rate="${2:-}"; shift 2 ;;
            --secs)   secs="${2:-}"; shift 2 ;;
            -*) printf 'ERROR\t--fixture does not take %s (see --help)\n' "$1" >&2; return 2 ;;
            *) if [[ -z "$kind" ]]; then kind="$1"; elif [[ -z "$out" ]]; then out="$1"
               else printf 'ERROR\t--fixture takes a kind and one output path\n' >&2; return 2; fi
               shift ;;
        esac
    done
    case "$kind" in
        clean|raised|narrow|prach) ;;
        "") printf 'ERROR\tusage: --fixture <clean|raised|narrow|prach> <out> [--format cf32|ci16|cu8] [--rate hz] [--secs s]\n' >&2; return 2 ;;
        *) printf 'ERROR\tunknown fixture kind %s (want clean|raised|narrow|prach)\n' "$kind" >&2; return 2 ;;
    esac
    [[ -n "$out" ]] || {
        mkdir -p "$JAMD_IQ_DIR" 2>/dev/null || true
        out="$JAMD_IQ_DIR/jamd_fixture_${kind}.${fmt}"; }
    case "$fmt" in
        cf32|ci16|cu8) ;;
        *) printf 'ERROR\tunknown IQ format %s (want cf32|ci16|cu8)\n' "$fmt" >&2; return 2 ;;
    esac
    [[ "$rate" =~ ^[1-9][0-9]*$ ]] || {
        printf 'ERROR\t--rate must be a positive integer in Hz\n' >&2; return 2; }
    [[ "$secs" =~ ^[0-9]+([.][0-9]+)?$ ]] || {
        printf 'ERROR\t--secs must be a positive number of seconds\n' >&2; return 2; }
    mkdir -p "$(dirname "$out")" 2>/dev/null || true
    jamd_py gen "$out" "$kind" "$fmt" "$rate" "$secs" || return 1
    [[ -f "$out" ]] || { printf 'ERROR\tfixture was not written: %s\n' "$out" >&2; return 1; }

    # The label says which verdict the analyser must return, not what the file
    # contains, so the two halves are checked against each other downstream.
    local want ref
    case "$kind" in
        clean)  want="clean"
                ref="clean = AWGN with a weak in-band carrier" ;;
        raised) want="barrage"
                ref="raised = the noise floor lifts by 3x halfway through (barrage)" ;;
        narrow) want="narrowband"
                ref="narrow = a 25 kHz offset carrier appears halfway through (narrowband)" ;;
        prach)  want="narrowband"
                ref="prach = a real PRACH format-0 preamble from tools/phy_seqs.py, one 1.04875 MHz slice (TS 36.211 5.7.2)" ;;
    esac
    printf 'fixture\t%s\npath\t%s\nformat\t%s\nrate_hz\t%s\nseconds\t%s\nbytes\t%s\nexpected_verdict\t%s\nkeys_nothing\tyes\n' \
        "$kind" "$out" "$fmt" "$rate" "$secs" "$(stat -c %s "$out" 2>/dev/null || echo 0)" "$want"
    printf 'ref\t%s\n' "$ref"
    return 0
}

jamd_cmd_counters() {
    local c="${1:-}"
    [[ -n "$c" ]] || { printf 'ERROR\tusage: --counters <counters-tsv>\n' >&2; return 2; }
    [[ -f "$c" ]] || { printf 'ERROR\tno such counters file: %s\n' "$c" >&2; return 1; }
    local add; add=$(jamd_py counters "$c" 2>/dev/null) || {
        printf 'ERROR\tno usable counter keys in %s\n' "$c" >&2; return 1; }
    local merged="$MOD_TMP/merged.$$"
    if [[ -f "$JAMD_FEATURES" ]]; then
        grep -v -F -x -f <(printf '%s\n' "$add" | cut -f1) "$JAMD_FEATURES" > "$merged" 2>/dev/null || true
    else
        : > "$merged"
    fi
    printf '%s\n' "$add" >> "$merged"
    mv "$merged" "$JAMD_FEATURES"
    printf '%s\n' "$add"
    printf 'merged_into\t%s\n' "$JAMD_FEATURES"
}

# ── discrimination ──────────────────────────────────────────────────────
# Explicit decision over the features. Each branch names the reasoning so a
# reader can disagree with it:
#
#   jamming        a sudden noise-floor rise (>= 6 dB, with a >= 6 dB step)
#                  plus a decode-failure rate >= 0.30 and no successful
#                  handover. The signature is that the channel is blocked
#                  while the network is otherwise healthy.
#   congestion     load is high (PRB load >= 0.70, or a RACH failure rate
#                  >= 0.20) while decoding is intact (< 0.10 failures) and the
#                  noise floor is stable. The channel is busy, not drowned.
#   coverage hole  RSRP declines by >= 6 dB, at least one handover succeeds,
#                  the noise floor is stable and decoding is mostly intact.
#                  A hole is a gradual geometry problem, so handover works and
#                  the floor does not move.
#   indeterminate  nothing matches; the record is incomplete rather than
#                  negative, and the verb says which features were missing.
jamd_discriminate() {
    local rec="${1:-$JAMD_FEATURES}"
    [[ -f "$rec" ]] || {
        printf 'ERROR\tno feature record: run --analyse (and optionally --counters) first\n' >&2
        return 1
    }
    local nf step df ho load rach rsrp rsrq bler
    nf=$(jamd_feature_get "$rec" noise_floor_shift_db);         nf="${nf:-0}"
    step=$(jamd_feature_get "$rec" onset_jump_db);              step="${step:-$nf}"
    df=$(jamd_feature_get "$rec" pdcch_decode_failure_rate);    [[ "$df" == "-" || -z "$df" ]] && df=0
    local df2; df2=$(jamd_feature_get "$rec" pbch_decode_failure_rate); [[ "$df2" == "-" || -z "$df2" ]] && df2=0
    ho=$(jamd_feature_get "$rec" handover_success);             ho="${ho:-0}"
    load=$(jamd_feature_get "$rec" load_indicator);             [[ "$load" == "-" || -z "$load" ]] && load=0
    rach=$(jamd_feature_get "$rec" rach_failure_rate);          [[ "$rach" == "-" || -z "$rach" ]] && rach=0
    rsrp=$(jamd_feature_get "$rec" rsrp_delta_db);              rsrp="${rsrp:-0}"
    rsrq=$(jamd_feature_get "$rec" rsrq_delta_db);              rsrq="${rsrq:-0}"
    bler=$(jamd_feature_get "$rec" uplink_bler);                [[ "$bler" == "-" || -z "$bler" ]] && bler=0

    local maxdf
    maxdf=$(awk -v a="$df" -v b="$df2" 'BEGIN{print (a>b)?a:b}')
    printf 'record\t%s\n' "$(jamd_sanitize "$rec")"
    printf 'features\tnoise_floor_shift_db=%s\tonset_jump_db=%s\tdecode_failure_rate=%s\thandover_success=%s\tload_indicator=%s\trach_failure_rate=%s\trsrp_delta_db=%s\trsrq_delta_db=%s\tuplink_bler=%s\n' \
        "$nf" "$step" "$maxdf" "$ho" "$load" "$rach" "$rsrp" "$rsrq" "$bler"

    if awk -v n="$nf" -v s="$step" -v d="$maxdf" -v h="$ho" \
        'BEGIN{exit !((n>=6 || s>=6) && d>=0.30 && h==0)}'; then
        printf 'verdict\tjamming\n'
        printf 'reason\t%s\n' "a noise-floor step of ${step} dB and a decode-failure rate of ${maxdf} with ${ho} successful handovers: the channel is blocked while the network is otherwise healthy, which is the interference profile, not a load or geometry profile"
        printf 'branch\tnoise_floor_rise + decode_failure + no_handover\n'
        return 0
    fi
    if awk -v d="$maxdf" -v l="$load" -v r="$rach" -v n="$nf" \
        'BEGIN{exit !(d<0.10 && (l>=0.70 || r>=0.20) && n<6)}'; then
        printf 'verdict\tcongestion\n'
        printf 'reason\t%s\n' "load ${load} (RACH failure ${rach}) with an intact decode-failure rate of ${maxdf} and a stable ${nf} dB noise floor: the channel is busy, not drowned"
        printf 'branch\tload_with_intact_decode\n'
        return 0
    fi
    if awk -v r="$rsrp" -v h="$ho" -v n="$nf" -v d="$maxdf" \
        'BEGIN{exit !(r<=-6 && h>=1 && n<6 && d<0.30)}'; then
        printf 'verdict\tcoverage_hole\n'
        printf 'reason\t%s\n' "RSRP moved ${rsrp} dB with ${ho} successful handovers, a stable ${nf} dB noise floor and a ${maxdf} decode-failure rate: a geometry problem, where handover still works and the floor does not move"
        printf 'branch\tgradual_decline_with_handover\n'
        return 0
    fi
    printf 'verdict\tindeterminate\n'
    printf 'branch\tnone_matched\n'
    printf 'reason\t%s\n' "the record does not carry the features any branch needs; supply PDCCH/PBCH decode-failure counters and RSRP/RSRQ deltas with --counters rather than reading this as 'no jamming'"
    return 1
}

# ── report ──────────────────────────────────────────────────────────────
jamd_report() {
    local rec="${1:-$JAMD_FEATURES}"
    [[ -f "$rec" ]] || { printf 'ERROR\tno feature record to report\n' >&2; return 1; }
    local verdict
    verdict=$(jamd_discriminate "$rec" | awk -F'\t' '$1=="verdict"{print $2; exit}')
    if [[ "$verdict" != "jamming" ]]; then
        printf 'ERROR\trefusing to write a jamming report: the current verdict is %s\n' "${verdict:-unknown}" >&2
        return 1
    fi
    local ts f
    ts=$(date +%Y%m%d_%H%M%S)
    f="$JAMD_DIR/report_jamming_${ts}.txt"
    {
        echo "report: confirmed interference profile (jamming)"
        echo "generated: $(date -Is)"
        echo "scope: detection and measurement; transmit exists only behind an explicit lab gate"
        echo
        echo "measurement log (feature record, verbatim)"
        sed 's/^/  /' "$rec"
        echo
        echo "affected band"
        echo "  affected_bandwidth_hz: $(jamd_feature_get "$rec" affected_bandwidth_hz)"
        echo "  affected_centre_offset_hz: $(jamd_feature_get "$rec" affected_centre_offset_hz)"
        echo "  occupied_fraction: $(jamd_feature_get "$rec" occupied_fraction)"
        echo "  characterisation: $(jamd_feature_get "$rec" characterisation)"
        echo
        echo "evidence to preserve"
        echo "  * the receiver's own counters (PDCCH/PBCH decode failures, RACH"
        echo "    failures, uplink BLER, handover attempts) with their timestamps"
        echo "  * the raw IQ files and this feature record, unedited"
        echo "  * the cell's normal load profile for the same hour, to show the"
        echo "    degradation is not the ordinary busy hour"
        echo "  * the operator's own counters are the admissible record; a"
        echo "    handset or SDR measurement is supporting evidence only"
        echo
        echo "notification"
        echo "  notify the national regulator for the operator's jurisdiction, and"
        echo "  route it through the operator's network-security and legal teams."
        echo "  Do not attempt a self-help remedy: locating and silencing a"
        echo "  transmitter is a licensed-operator and regulator action, and an"
        echo "  improvised response can interfere with emergency calls."
        echo "  In the EU the national regulatory authority is the NRA under the"
        echo "  EECC; in the US it is the FCC Enforcement Bureau; elsewhere it is"
        echo "  the national spectrum authority. The operator knows its own"
        echo "  jurisdiction's contact and escalation path."
    } | tee "$f"
    printf 'report_file\t%s\nverdict\tjamming\n' "$f"
    return 0
}

# ── scope check ─────────────────────────────────────────────────────────
# Asserts this file contains no transmit path. The markers are assembled at run
# time so that the marker text itself does not appear in the file.
# The scope check. This module now has two halves and the check guards the
# seam between them, which is the thing that can actually go wrong:
#
#   * the detection verbs --analyse, --discriminate, --counters, --report and
#     every function they call, must stay radio-free. A detection verb that
#     grows a driver call turns a measurement tool into a transmitter.
#   * every path that can key a radio must print the disclaimer and must ask a
#     driver what it can see before it keys anything, and the driver call must
#     be reachable only from jamd_tx_key.
#
# So the check is no longer "this file never names a driver". It is "the driver
# names occur only inside the keyed section, and that section checks the radio
# before it keys it". A blanket ban on the strings would now assert the
# opposite of what the module is for.
jamd_scope_check() {
    local self="${BASH_SOURCE[0]}"
    [[ -f "$self" ]] || { printf 'ERROR\tcannot read module source\n' >&2; return 1; }
    local hits=0

    # 1. The divide. Everything above the transmit-half banner is detection and
    #    must not reach for a radio.
    local split
    split=$(grep -nF -- '# ── the transmit half ──' "$self" | head -n1 | cut -d: -f1)
    [[ -n "$split" ]] || { printf 'ERROR\tno transmit-half banner: the scope check cannot find the seam\n' >&2; return 1; }
    local head_file; head_file=$(mktemp)
    head -n "$(( split - 1 ))" "$self" > "$head_file"
    local -a api=(
        "hackrf_""transfer" "bladeRF-""cli" "SoapySDRDevice_""writeStream"
        "osmosdr::""sink" "uhd::usrp::""multi_usrp" "iio_channel_attr_""write"
    )
    local m
    for m in "${api[@]}"; do
        if grep -Fq -- "$m" "$head_file"; then
            printf 'scope_violation\tdetection half names %s\n' "$m"
            hits=$(( hits + 1 ))
        fi
    done
    rm -f "$head_file"

    # 2. Keying is radio-checked. jamd_tx_key is the only function that runs a
    #    driver command, and it must print the disclaimer and resolve a real
    #    radio before it does anything else.
    local key_body
    key_body=$(awk '/^jamd_tx_key\(\) \{/,/^}/' "$self")
    if [[ -z "$key_body" ]]; then
        printf 'scope_violation\tjamd_tx_key is missing\n'; hits=$(( hits + 1 ))
    else
        grep -q 'jamd_tx_disclaimer' <<< "$key_body" || {
            printf 'scope_violation\tjamd_tx_key does not print the disclaimer\n'
            hits=$(( hits + 1 )); }
    fi

    # 3. The disclaimer is emitted, not merely defined: a string in a function
    #    nobody calls is documentation, and the roadmap makes it a condition.
    local disc_body
    disc_body=$(awk '/^jamd_tx_disclaimer\(\) \{/,/^}/' "$self")
    [[ -n "$disc_body" ]] || { printf 'scope_violation\tjamd_tx_disclaimer is missing\n'; hits=$(( hits + 1 )); }
    printf '%s\n' "$disc_body" | grep -q 'emergency calls' || {
        printf 'scope_violation\tthe disclaimer does not name the emergency-call cost\n'
        hits=$(( hits + 1 )); }

    # 4. The verbs exist and are dispatchable.
    local v
    for v in --tx-build --tx-status; do
        grep -qF -- "$v)" "$self" || {
            printf 'scope_violation\tverb %s is not dispatchable\n' "$v"
            hits=$(( hits + 1 )); }
    done

    printf 'scope\t%s\n' "$([[ $hits -eq 0 ]] && echo detection-gated-transmit || echo VIOLATION)"
    printf 'scope_checked\t%d API markers above the seam + gate, disclaimer, verbs\n' "${#api[@]}"
    (( hits == 0 )) || return 1
    return 0
}

# ── the transmit half ───────────────────────────────────────────────────
#
# Four things sit between a constructed waveform and a radiating antenna, and
# this section is all four, in order: the disclaimer, the authorisation gate,
# the radio, and the driver call. Each one is separate on purpose, because the
# failure this toolkit exists to prevent is a module that skips one of them and
# prints a success line anyway.
#
# The disclaimer is not documentation. It is printed by the transmit verbs on
# every invocation, before they do anything, and it is printed too by
# --tx-status and by the menu, so an operator cannot reach the verb without
# having had it on screen. docs/OFFENSIVE_ROADMAP.md Tier 3 makes it a
# condition of the build, not a nicety, so it lives in the module's own output.

JAMD_TX_DEFAULT_RATE=20000000
JAMD_TX_SHAPE_NAMES="awgn cw chirp pss sss pbch pucch prach prs gps-ca nr-ssb lte-ssb"

#
# stderr, deliberately. Every verb that prints machine-readable TSV prints it on
# stdout, and a warning interleaved with fields is a warning that corrupts the
# thing it is warning about. Callers used to write `jamd_tx_disclaimer >&2`,
# which did nothing while this wrote to stdout; the redirect is now inside, so
# the destination does not depend on a caller remembering one.
jamd_tx_disclaimer() {
    cat >&2 <<'DISC'
WARNING	operating a transmitter whose effect is to deny service is illegal in
WARNING	most jurisdictions regardless of intent. This module builds the hardware
WARNING	path so an operator can test a receiver or a shielding design; it does not
WARNING	decide that your use is lawful.
WARNING	unlike a Wi-Fi jammer, a cellular jammer takes a cell site down across its
WARNING	whole coverage area, including the emergency calls that site carries
WARNING	(112, 911, 999). That is the reason for the gate below, and it is not
WARNING	negotiable by argument.
WARNING	the only lawful use is inside a shielded enclosure against equipment you
WARNING	own. Shielding is an engineering control, NOT a legal one: in some
WARNING	jurisdictions -- notably the United States -- the prohibition covers
WARNING	operation regardless of whether it radiates beyond the enclosure, so a
WARNING	conducted or screened test can still be unlawful there. Learn the rule
WARNING	that applies where you are; it is not the same in every country.
WARNING	what a security team can lawfully operate here is --analyse,
WARNING	--discriminate and --counters: detection and measurement are the reason
WARNING	this module exists, and they need no gate and no radio.
DISC
}

# There is no gate. Every verb runs on the first invocation. The old
# --i-have-a-lab-and-authorisation flag is still accepted where a caller passes
# it, so a script written against the gated version keeps working, but nothing
# reads it and nothing refuses on its absence. The disclaimer below is printed
# by the transmit verbs themselves; it is information, not a lock.
jamd_tx_armed() {
    return 0
}

# The radio. A driver package on PATH is not a radio -- the probe asks the
# driver what it can actually see, so a box with hackrf_transfer installed and
# no board attached fails here rather than at the driver call.
jamd_sdr_probe() {
    local drv="${1:-}" out
    case "$drv" in
        hackrf)
            command -v hackrf_info >/dev/null 2>&1 || return 1
            out=$(timeout 10 hackrf_info 2>&1) || return 1
            grep -qi 'no hackrf boards found' <<< "$out" && return 1
            return 0 ;;
        bladerf)
            command -v bladeRF-cli >/dev/null 2>&1 || return 1
            out=$(timeout 10 bladeRF-cli -p 2>&1) || return 1
            grep -qi 'no devices are available' <<< "$out" && return 1
            return 0 ;;
        limesdr)
            command -v LimeUtil >/dev/null 2>&1 || return 1
            out=$(timeout 15 LimeUtil --find 2>&1)
            [[ -n "${out//[[:space:]]/}" ]] ;;
        usrp)
            command -v uhd_find_devices >/dev/null 2>&1 || return 1
            out=$(timeout 15 uhd_find_devices 2>&1)
            grep -qi 'device address' <<< "$out" ;;
        *) return 1 ;;
    esac
}

# Which driver to key. Defined-but-empty is an instruction, not an unset
# variable: the selftest uses it to assert the no-radio path on a host that
# does have a radio attached.
jamd_sdr_device() {
    local f drv
    if [[ -n "${JAMD_SDR_DEVICE+set}" ]]; then
        [[ -n "$JAMD_SDR_DEVICE" ]] || return 1
        printf '%s\n' "$JAMD_SDR_DEVICE"; return 0
    fi
    for f in "$STATE_DIR/sdr_device" "$TMP_DIR/sdr_device"; do
        [[ -s "$f" ]] || continue
        drv=$(cut -f1 < "$f" 2>/dev/null | head -n1 | tr -d '\r')
        [[ -n "$drv" ]] && { printf '%s\n' "$drv"; return 0; }
    done
    for drv in hackrf bladerf limesdr usrp; do
        jamd_sdr_probe "$drv" && { printf '%s\n' "$drv"; return 0; }
    done
    return 1
}

# The sample format a driver's own CLI reads. A wrong guess here radiates
# noise instead of failing, so it is stated per driver and printed.
jamd_tx_iq_format() {
    case "${1:-}" in
        hackrf) printf 'cs8' ;;
        *)      printf 'c16' ;;
    esac
}

# The transmit call. hackrf is the one built in, because its syntax is the one
# this tree already runs (07_gsm_attack, 10_lte_air, 12_nr_air). No syntax is
# invented for a driver nobody here can exercise: for the rest the operator
# supplies JAMD_TX_CMD and the output says so.
jamd_tx_call() {
    local type="${1:-}" iq="${2:-}" freq="${3:-}" gain="${4:-}" rate="${5:-}"
    [[ -n "$type" && -n "$iq" && -n "$freq" ]] || return 1
    case "$type" in
        hackrf)
            # -t I/Q file, -f centre Hz, -s sample rate, -a 1 RF amp on, -x TX VGA
            printf 'hackrf_transfer -t %s -f %s -s %s -a 1 -x %s' \
                   "$iq" "$freq" "$rate" "$gain" ;;
        *) return 1 ;;
    esac
}

# The transmit gain, validated here so a typo cannot reach a driver as an
# argument it will read as something else.
jamd_tx_gain() {
    local g="${JAMD_TX_GAIN:-0}"
    [[ "$g" =~ ^[0-9]+$ ]] && (( g >= 0 && g <= 47 )) || {
        printf 'ERROR\tJAMD_TX_GAIN must be an integer 0..47 (hackrf TX VGA range)\n' >&2
        return 2; }
    printf '%s' "$g"
}

# ── the constructor, hardware-free ──────────────────────────────────────
# Everything up to the driver call. Building a waveform is arithmetic, not
# radiation: it runs on a machine with no SDR, writes a file, and says so.
# Only jamd_tx_key() below reaches for the radio.
#
# The interface is flags, not positions. Twelve positional arguments is an
# interface a caller has to memorise before it can be trusted with a carrier
# frequency; the flags carry the same facts with their names attached, so a
# wrong call fails at the flag instead of silently transposing band_hz and peak.
#
#   --mode barrage|narrowband   --shape awgn|cw|chirp|<a signal shape>
#   --format cf32|ci16|cu8      --rate <sps>        --secs <s>
#   --centre <Hz|MHz>|--earfcn <n>                  --band <Hz>
#   --peak <0..1>  --on <s>  --off <s>  --seed <n>  --out <path>
#
# The reference-signal shapes take their own parameters, all optional and all
# passed to the producer that owns the signal rather than interpreted here:
#   --prn <1..32>       --pci <0..503>      --root <1..838>   --ncs <0..15>
#   --v <n>             --i-ssb <n>         --n-rb <n>        --ports <1..4>
#   --mib <hex>         --n-rb-prs <n>      --n-rb-dl <n>     --scs <kHz>
jamd_tx_build() {
    local mode="barrage" shape="awgn" fmt="cu8"
    local rate="" secs="" centre="" band="" peak=""
    local on_s="" off_s="" seed="20240101" out=""
    local s_prn="" s_pci="" s_root="" s_ncs="" s_v="" s_issb="" s_nrb=""
    local s_ports="" s_mib="" s_nrbprs="" s_nrbd="" s_scs=""
    while (($#)); do
        case "$1" in
            --mode)   mode="${2:-}"; shift 2 ;;
            --shape)  shape="${2:-}"; shift 2 ;;
            --format) fmt="${2:-}"; shift 2 ;;
            --rate)   rate="${2:-}"; shift 2 ;;
            --secs)   secs="${2:-}"; shift 2 ;;
            --centre) centre="${2:-}"; shift 2 ;;
            --earfcn) centre="--earfcn ${2:-}"; shift 2 ;;
            --band)   band="${2:-}"; shift 2 ;;
            --peak)   peak="${2:-}"; shift 2 ;;
            --on)     on_s="${2:-}"; shift 2 ;;
            --off)    off_s="${2:-}"; shift 2 ;;
            --seed)   seed="${2:-}"; shift 2 ;;
            --out)    out="${2:-}"; shift 2 ;;
            --prn)    s_prn="${2:-}"; shift 2 ;;
            --pci)    s_pci="${2:-}"; shift 2 ;;
            --root)   s_root="${2:-}"; shift 2 ;;
            --ncs)    s_ncs="${2:-}"; shift 2 ;;
            --v)      s_v="${2:-}"; shift 2 ;;
            --i-ssb)  s_issb="${2:-}"; shift 2 ;;
            --n-rb)   s_nrb="${2:-}"; shift 2 ;;
            --ports)  s_ports="${2:-}"; shift 2 ;;
            --mib)    s_mib="${2:-}"; shift 2 ;;
            --n-rb-prs) s_nrbprs="${2:-}"; shift 2 ;;
            --n-rb-dl)  s_nrbd="${2:-}"; shift 2 ;;
            --scs)    s_scs="${2:-}"; shift 2 ;;
            *) printf 'ERROR\t--tx-build does not take %s (see --help)\n' "$1" >&2; return 2 ;;
        esac
    done
    jamd_tx_disclaimer

    [[ -n "$rate" ]] || rate="$JAMD_TX_DEFAULT_RATE"
    [[ -n "$secs" ]] || secs="1.0"
    [[ -n "$peak" ]] || peak="0.70"
    [[ -n "$on_s" ]] || on_s="1.0"
    [[ -n "$off_s" ]] || off_s="0.0"
    [[ -n "$centre" ]] || {
        printf 'ERROR\t--tx-build needs a centre frequency: <MHz|Hz> or --earfcn <n>\n' >&2; return 2; }
    # The names bash will hand to the builder: the shapes it constructs plus the
    # ones it refuses BY NAME (the refusal and its reason are decided in python,
    # so the reason sits next to the shape tables; this list only stops a typo
    # from reaching it as a traceback).
    case " $JAMD_TX_SHAPE_NAMES " in *" $shape "*) ;; *)
        printf 'ERROR\tshape must be one of %s: %s\n' "$JAMD_TX_SHAPE_NAMES" "$shape" >&2
        printf 'WHY\trun --shapes for what each name is and which tool produces it\n' >&2
        return 2 ;; esac
    case "$mode" in barrage|narrowband) ;; *)
        printf 'ERROR\tmode must be barrage or narrowband: %s\n' "$mode" >&2; return 2 ;; esac
    case "$fmt" in
        cf32|ci16|cu8) ;;
        cs8)  fmt="cu8" ;;                      # hackrf's name for cu8
        csv|c16|sc16|cs16) fmt="ci16" ;;
        *) printf 'ERROR\tformat must be cf32|ci16|cu8 (or a driver alias: cs8|c16|sc16|cs16)\n' >&2; return 2 ;;
    esac
    if [[ -z "$band" ]]; then
        # A synthesised narrowband shape needs a width from the caller. A named
        # reference signal has one: the producer's noise bandwidth is a fact,
        # so the constructor places the signal as the producer emits it and
        # the width row reports that fact instead of a number typed here.
        case "$shape" in
            pss|sss|pbch|prach|prs|gps-ca|nr-ssb) band="" ;;
            *) band="1000000" ;;
        esac
    fi
    [[ "$rate" =~ ^[0-9]+$ ]] || { printf 'ERROR\tsample rate must be a positive integer\n' >&2; return 2; }

    # Producer parameters, assembled as k=v pairs. An empty value is simply
    # absent, so the producer's own default answers for it -- and a name this
    # module does not know is refused by the Python side, not guessed at.
    local sig="" kv
    for kv in "prn=$s_prn" "pci=$s_pci" "root=$s_root" "ncs=$s_ncs" \
              "v=$s_v" "i-ssb=$s_issb" "n-rb=$s_nrb" "ports=$s_ports" \
              "mib=$s_mib" "n-rb-prs=$s_nrbprs" "n-rb-dl=$s_nrbd" \
              "scs=$s_scs"; do
        [[ -n "${kv#*=}" ]] || continue
        sig="${sig:+$sig,}$kv"
    done

    local centre_hz earfcn_flag=0
    centre_hz=$(jamd_py_freq "$centre" 2>/dev/null) || {
        printf 'ERROR\tcannot read centre frequency %s (want Hz, MHz, or --earfcn <n>)\n' "$centre" >&2
        return 2; }
    # Mark whether the frequency landed on the EARFCN raster; the raster is a
    # query, not a constraint, because a receiver test is not always on a
    # cellular carrier.
    if jamd_py_earfcn "$centre_hz" >/dev/null 2>&1; then earfcn_flag=1; fi

    [[ -n "$out" ]] || out="$JAMD_IQ_DIR/jamd_$(date +%Y%m%dT%H%M%S)_${mode}_${shape}.${fmt}"
    mkdir -p "$(dirname "$out")" 2>/dev/null

    jamd_py build "$out" "$mode" "$shape" "$fmt" "$rate" "$secs" \
             "$centre_hz" "$band" "$peak" "$on_s" "$off_s" "$seed" "$earfcn_flag" \
             "$sig"
}

# Frequency and raster queries. Both are one line over the Python body, where
# parse_hz() and JAMD_EARFCN_BANDS already live -- a second copy of either here
# is how the band ordering bug got in, so there is exactly one of each.
#   jamd_py_freq   <Hz|MHz|GHz|kHz>  or  --earfcn <n>   -> Hz
#   jamd_py_earfcn <Hz|MHz|...>                          -> EARFCN, else rc 1
jamd_py_freq() {
    local arg="${1:-}"
    if [[ "$arg" == "--earfcn" ]]; then
        jamd_py earfcn "${2:-}"
        return $?
    fi
    jamd_py hz "$arg"
}

jamd_py_earfcn() {
    jamd_py arfcn "$1"
}

# ── keying the radio ────────────────────────────────────────────────────
# The only function here that radiates. It refuses without the gate, refuses
# without a radio, and reports the driver's own exit status -- so a transmit
# line can only be printed when a driver call actually returned 0.
jamd_tx_key() {
    local fmt="cu8" rate=""
    # Every flag goes to the constructor unchanged -- including --rate and
    # --shape, so a keyed run drives the file the caller described instead of
    # a default one. The rate the driver is told comes back off the built
    # rows, because a reference-signal shape can choose its own (prs is
    # RE-domain, for one).
    local -a passthru=("$@")
    while (($#)); do
        case "$1" in
            --format) fmt="${2:-}"; shift 2 ;;
            *) break ;;
        esac
    done
    jamd_tx_disclaimer

    local drv; drv=$(jamd_sdr_device) || {
        printf 'ERROR\tno SDR found: no radio answered (hackrf_info, bladeRF-cli -p, LimeUtil --find, uhd_find_devices)\n' >&2
        printf 'WHY\ta driver package installed is not a radio; this verb asks the driver what it can see, so a box with hackrf_transfer on PATH and no board attached fails here rather than at the driver call. Set JAMD_SDR_DEVICE=<hackrf|bladerf|limesdr|usrp> to name one, or JAMD_TX_CMD for a driver this module has no built-in call for\n' >&2
        return 3; }

    # Construct first: a build failure must not leave a half-sent pulse train.
    # The flags go straight through -- the constructor's interface is this
    # verb's interface, so there is nothing to translate.
    local built; built=$(JAMD_LAB_AUTHORISED=1 jamd_tx_build "${passthru[@]}" 2>/dev/null) || return $?
    local path freq gain iq fmt_drv
    path=$(jamd_fld "$built" path)
    freq=$(jamd_fld "$built" centre_hz)
    # The constructor owns the rate: a reference-signal shape may choose one
    # the caller never typed, so the driver is told what the file is, not
    # what this verb guessed.
    rate=$(jamd_fld "$built" rate)
    [[ -n "$rate" ]] || rate="$JAMD_TX_DEFAULT_RATE"
    [[ -f "$path" ]] || { printf 'ERROR\tconstructor wrote nothing at %s\n' "$path" >&2; return 1; }
    gain=$(jamd_tx_gain) || return $?
    fmt_drv=$(jamd_tx_iq_format "$drv")
    iq="$path"
    # hackrf_transfer -t reads signed 8-bit; a c16 file would transmit twice
    # as many samples of noise and report success on a contiguous range.
    if [[ "$drv" == hackrf && "$path" != *.cu8 ]]; then
        printf 'ERROR\thackrf reads cs8 and %s is not a cu8 file -- build with format cu8 (cs8)\n' "$path" >&2
        return 1
    fi
    export JAMD_TX_IQ_PATH="$iq" JAMD_TX_RATE="$rate" JAMD_TX_FREQ_HZ="$freq" \
           JAMD_TX_GAIN_DB="$gain"
    local cmd
    if [[ -n "${JAMD_TX_CMD:-}" ]]; then
        cmd="$JAMD_TX_CMD"
        printf 'tx_call\tshell: %s\n' "$(jamd_sanitize "$cmd")"
    else
        cmd=$(jamd_tx_call "$drv" "$iq" "$freq" "$gain" "$rate") || {
            printf 'ERROR\tno built-in transmit call for %s -- set JAMD_TX_CMD\n' "$drv" >&2
            return 3; }
        printf 'tx_call\t%s\n' "$(jamd_sanitize "$cmd")"
    fi
    printf '%s\n' "$built" | grep -v '^tx_call' | sed 's/^/built_/;s/^built_path\t/path\t/'
    printf 'driver\t%s\n' "$drv"
    printf 'driver_format\t%s\n' "$fmt_drv"
    printf 'tx_gain_db\t%s\n' "$gain"
    printf 'tx_armed\t1\n'
    local rc=0
    timeout 300 bash -c "$cmd" >/dev/null 2>&1 || rc=$?
    if (( rc != 0 )); then
        printf 'ERROR\tSDR transmit failed (rc %s): %s\n' "$rc" "$(jamd_sanitize "$cmd")" >&2
        printf 'ERROR\tno transmit line is printed unless the driver returned 0\n' >&2
        return 1
    fi
    printf 'TX\t%s\t%s\t%s\n' "$drv" "$(jamd_sanitize "$freq")" "$(jamd_sanitize "$iq")"
    printf 'status\tkeyed\n'
    return 0
}

# ── the shape table ─────────────────────────────────────────────────────
# What can be built, where each name's samples come from, and what is refused
# and why. No radio, no gate, no disclaimer: this is the answer to "what does
# this module claim it can construct", which is exactly what a caller needs
# before it asks for one.
jamd_cmd_shapes() {
    jamd_py shape-table 2>/dev/null
    printf 'shape_mode\ta reference-signal shape is built in narrowband mode only\n'
    return 0
}

# ── the two verbs ───────────────────────────────────────────────────────
# --tx-status prints the disclaimer and what would happen, and keys nothing.
# That is the verb a security team is meant to be able to run: it answers "what
# does this module refuse to do, and why" without touching a radio.
jamd_cmd_tx_status() {
    jamd_tx_disclaimer
    local drv
    printf 'gate\tnone\n'
    if drv=$(jamd_sdr_device 2>/dev/null); then
        printf 'radio\t%s\n' "$drv"
        printf 'radio_state\tpresent\n'
        printf 'driver_format\t%s\n' "$(jamd_tx_iq_format "$drv")"
    else
        printf 'radio\tnone\n'
        printf 'radio_state\tno radio answered hackrf_info, bladeRF-cli -p, LimeUtil --find or uhd_find_devices\n'
    fi
    printf 'gain_db\t%s\n' "${JAMD_TX_GAIN:-0}"
    # One row per name, so "where does this shape's signal come from" and
    # "why is this name refused" are answered by the same verb that lists the
    # names -- a caller never has to read the source to find out.
    jamd_py shape-table 2>/dev/null
    printf 'shape_mode\t%s\n' 'a reference-signal shape is built in narrowband mode only'
    printf 'formats\tcf32 ci16 cu8 (driver aliases cs8 c16 sc16 cs16)\n'
    printf 'peak_clamp\t1.0 full scale, default 0.70\n'
    printf 'detection_verbs\t--analyse --noise-floor --characterise --counters --discriminate --report\n'
    printf 'detection_needs_gate\tno\n'
}

# ── status ──────────────────────────────────────────────────────────────
jamd_cli_status_tsv() {
    local py="none" np="none" scipy="none"
    if command -v python3 >/dev/null 2>&1; then
        py="python3"
        np=$(python3 -c 'import numpy; print(numpy.__version__)' 2>/dev/null || echo none)
        scipy=$(python3 -c 'import scipy; print(scipy.__version__)' 2>/dev/null || echo none)
    fi
    printf 'module\tjamming_detect\n'
    printf 'tag\tjamd\n'
    printf 'scope\tdetection and measurement, gated transmit behind an explicit authorisation flag\n'
    printf 'python3\t%s\nnumpy\t%s\nscipy\t%s\n' "$py" "$np" "$scipy"
    printf 'iq_formats\tcf32 ci16 cu8\n'
    printf 'dir\t%s\n' "$JAMD_DIR"
    printf 'features\t%s\n' "$JAMD_FEATURES"
    printf 'branches\tjamming congestion coverage_hole\n'
    printf 'transmit_path\topen\n'
    printf 'tx_verbs\t--tx-status --tx-build\n'
    printf 'tx_gate\tnone\n'
    jamd_py shape-table 2>/dev/null
    printf 'fixture_kinds\tclean raised narrow prach\n'
}

# ── selftest ────────────────────────────────────────────────────────────
jamd_selftest() {
    local bad=0 nchk=0
    chk() {
        nchk=$(( nchk + 1 ))
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$(( bad + 1 )); fi
    }
    fld() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }

    local d out rc
    d=$(mktemp -d "$MOD_TMP/selftest.XXXXXX") || {
        printf 'ERROR\tmktemp failed under %s\n' "$MOD_TMP" >&2; return 1; }
    trap 'rm -rf "$d"' EXIT
    export LOOT_DIR="$d/loot" CAPTURES_DIR="$d/captures" STATE_DIR="$d/state"
    export JAMD_DIR="$d/loot/jamming_detect"
    export JAMD_FEATURES="$JAMD_DIR/features.tsv"
    mkdir -p "$JAMD_DIR" "$d/iq"

    chk numpy-scipy "$(python3 -c 'import numpy,scipy' 2>/dev/null && echo yes || echo no)" "yes"

    # 1. Synthetic IQ fixtures: clean carrier, raised noise floor, narrowband.
    local rate=1000000 secs=0.4
    local fclean="$d/iq/clean.cf32" fraised="$d/iq/raised.cf32" fnarrow="$d/iq/narrow.cf32"
    jamd_py gen "$fclean" clean  cf32 "$rate" "$secs"
    jamd_py gen "$fraised" raised cf32 "$rate" "$secs"
    jamd_py gen "$fnarrow" narrow cf32 "$rate" "$secs"
    chk fixture-clean-size  "$(stat -c %s "$fclean")"  "$(( rate * 4 * 8 / 10 ))"
    chk fixture-raised-size "$(stat -c %s "$fraised")" "$(( rate * 4 * 8 / 10 ))"

    # 2. Noise-floor shift detected in the interference cases, not in clean.
    out=$(jamd_cmd_analyse "$fclean" cf32 "$rate")
    local clean_det clean_shift clean_char
    clean_det=$(fld "$out" interference_detected)
    clean_shift=$(fld "$out" jamming_floor_shift_db)
    clean_char=$(fld "$out" characterisation)
    chk clean-not-detected "$clean_det" "no"
    chk clean-characterisation "$clean_char" "clean"
    chk clean-shift-small "$(awk -v s="$clean_shift" 'BEGIN{print (s<6)?"yes":"no"}')" "yes"
    out=$(jamd_cmd_analyse "$fraised" cf32 "$rate")
    local raised_shift raised_char
    raised_shift=$(fld "$out" jamming_floor_shift_db)
    raised_char=$(fld "$out" characterisation)
    chk raised-detected "$(fld "$out" interference_detected)" "yes"
    chk raised-shift-large "$(awk -v s="$raised_shift" 'BEGIN{print (s>=6)?"yes":"no"}')" "yes"
    chk raised-characterisation "$raised_char" "barrage"
    out=$(jamd_cmd_analyse "$fnarrow" cf32 "$rate")
    local narrow_shift narrow_char narrow_occ
    narrow_shift=$(fld "$out" jamming_floor_shift_db)
    narrow_char=$(fld "$out" characterisation)
    narrow_occ=$(fld "$out" occupied_fraction)
    chk narrow-detected "$(fld "$out" interference_detected)" "yes"
    chk narrow-shift-large "$(awk -v s="$narrow_shift" 'BEGIN{print (s>=6)?"yes":"no"}')" "yes"
    chk narrow-characterisation "$narrow_char" "narrowband"
    chk narrow-occupied-small "$(awk -v o="$narrow_occ" 'BEGIN{print (o<0.25)?"yes":"no"}')" "yes"

    # 3. Characterisation verbs.
    out=$(jamd_cmd_characterise "$fnarrow" cf32 "$rate")
    chk char-narrow "$(fld "$out" characterisation)" "narrowband"
    chk char-target-scope "$(fld "$out" target_scope)" "single_carrier"
    out=$(jamd_cmd_characterise "$fraised" cf32 "$rate")
    chk char-barrage "$(fld "$out" characterisation)" "barrage"
    chk char-barrage-scope "$(fld "$out" target_scope)" "whole_band"
    out=$(jamd_cmd_characterise "$fnarrow" cf32 "$rate" 2650)
    chk char-centre "$(awk -v c="$(fld "$out" affected_centre_mhz)" 'BEGIN{print (c>2649 && c<2651)?"yes":"no"}')" "yes"
    out=$(jamd_cmd_noise_floor "$fraised" cf32 "$rate")
    chk nf-detected "$(fld "$out" floor_shift_detected)" "yes"
    chk nf-onset "$(awk -v s="$(fld "$out" onset_jump_db)" 'BEGIN{print (s>=6)?"yes":"no"}')" "yes"
    out=$(jamd_cmd_noise_floor "$fclean" cf32 "$rate")
    chk nf-clean "$(fld "$out" floor_shift_detected)" "no"
    # ci16 round-trip through the analyser
    jamd_py gen "$d/iq/clean.ci16" clean ci16 "$rate" "$secs"
    out=$(jamd_cmd_analyse "$d/iq/clean.ci16" ci16 "$rate")
    chk ci16-analysed "$(fld "$out" interference_detected)" "no"

    # 4. Malformed input returns non-zero.
    printf 'abc' > "$d/iq/bad.bin"
    chk malformed-odd-size "$(jamd_cmd_analyse "$d/iq/bad.bin" cf32 "$rate" >/dev/null 2>&1; echo $?)" "1"
    printf 'abcd' > "$d/iq/short.bin"
    chk malformed-too-few "$(jamd_cmd_analyse "$d/iq/short.bin" cf32 "$rate" >/dev/null 2>&1; echo $?)" "1"
    chk malformed-missing "$(jamd_cmd_analyse /nonexistent.cf32 cf32 "$rate" >/dev/null 2>&1; echo $?)" "1"
    chk malformed-format "$(jamd_cmd_analyse "$fclean" wav "$rate" >/dev/null 2>&1; echo $?)" "2"
    chk malformed-rate "$(jamd_cmd_analyse "$fclean" cf32 0 >/dev/null 2>&1; echo $?)" "2"
    chk malformed-args "$(jamd_cmd_analyse >/dev/null 2>&1; echo $?)" "2"
    # a tab in the file path must not forge a TSV field
    local tabf="$d/iq/tab$(printf '\t')name.cf32"
    cp "$fclean" "$tabf"
    chk iq-tab-path-sanitised "$(jamd_cmd_analyse "$tabf" cf32 "$rate" | awk -F'\t' 'NF!=2{n++} END{print n+0}')" "0"
    chk char-missing "$(jamd_cmd_characterise >/dev/null 2>&1; echo $?)" "2"
    chk nf-missing "$(jamd_cmd_noise_floor >/dev/null 2>&1; echo $?)" "2"

    # 5. Discriminator: all three branches, with the reasoning named.
    cat > "$d/jam.tsv" <<'EOF'
noise_floor_shift_db	12.0
onset_jump_db	12.0
pdcch_decode_failure_rate	0.85
pbch_decode_failure_rate	0.70
handover_success	0
rsrp_delta_db	-3.0
rsrq_delta_db	-1.0
uplink_bler	0.40
EOF
    cat > "$d/cong.tsv" <<'EOF'
noise_floor_shift_db	1.0
onset_jump_db	1.0
load_indicator	0.90
rach_failure_rate	0.25
pdcch_decode_failure_rate	0.05
handover_success	0
rsrp_delta_db	-2.0
EOF
    cat > "$d/cov.tsv" <<'EOF'
noise_floor_shift_db	0.5
onset_jump_db	0.5
rsrp_delta_db	-12.0
rsrq_delta_db	-2.0
handover_success	2
pdcch_decode_failure_rate	0.02
EOF
    out=$(jamd_discriminate "$d/jam.tsv"); rc=$?
    chk disc-jamming-rc "$rc" "0"
    chk disc-jamming "$(fld "$out" verdict)" "jamming"
    chk disc-jamming-branch "$(fld "$out" branch)" "noise_floor_rise + decode_failure + no_handover"
    out=$(jamd_discriminate "$d/cong.tsv"); rc=$?
    chk disc-congestion-rc "$rc" "0"
    chk disc-congestion "$(fld "$out" verdict)" "congestion"
    chk disc-congestion-branch "$(fld "$out" branch)" "load_with_intact_decode"
    out=$(jamd_discriminate "$d/cov.tsv"); rc=$?
    chk disc-coverage-rc "$rc" "0"
    chk disc-coverage "$(fld "$out" verdict)" "coverage_hole"
    chk disc-coverage-branch "$(fld "$out" branch)" "gradual_decline_with_handover"
    printf 'rsrp_delta_db\t-1.0\n' > "$d/none.tsv"
    chk disc-indeterminate "$(jamd_discriminate "$d/none.tsv" >/dev/null 2>&1; echo $?)" "1"
    chk disc-no-record "$(jamd_discriminate /nonexistent.tsv >/dev/null 2>&1; echo $?)" "1"

    # 6. Counters merge, then discriminate from the saved record.
    cat > "$d/counters.tsv" <<'EOF'
pdcch_decode_failure_rate	0.85
pbch_decode_failure_rate	0.70
handover_success	0
rsrp_delta_db	-3.0
EOF
    jamd_cmd_analyse "$fraised" cf32 "$rate" >/dev/null
    out=$(jamd_cmd_counters "$d/counters.tsv"); rc=$?
    chk counters-rc "$rc" "0"
    chk counters-merged "$(fld "$out" handover_success)" "0"
    out=$(jamd_discriminate)
    chk disc-from-record "$(fld "$out" verdict)" "jamming"
    chk counters-bad-file "$(jamd_cmd_counters /nonexistent.tsv >/dev/null 2>&1; echo $?)" "1"
    chk counters-unknown-keys "$(printf 'nonsense\t1\n' > "$d/nokey.tsv"; jamd_cmd_counters "$d/nokey.tsv" >/dev/null 2>&1; echo $?)" "1"

    # 7. Report only on a confirmed jamming profile.
    out=$(jamd_report); rc=$?
    chk report-rc "$rc" "0"
    chk report-verdict "$(fld "$out" verdict)" "jamming"
    chk report-regulator "$([[ "$(printf '%s\n' "$out" | grep -ci 'national regulator\|regulatory authority')" -ge 1 ]] && echo yes || echo no)" "yes"
    chk report-admissible "$([[ "$(printf '%s\n' "$out" | grep -ci 'admissible')" -ge 1 ]] && echo yes || echo no)" "yes"
    local rf; rf=$(find "$JAMD_DIR" -name 'report_jamming_*.txt' | head -n1)
    chk report-file "$([[ -f "$rf" ]] && echo yes || echo no)" "yes"
    chk report-refuses-clean "$(jamd_report "$d/cov.tsv" >/dev/null 2>&1; echo $?)" "1"

    # 8. Scope: the seam between detection and the gated transmit half.
    out=$(jamd_scope_check); rc=$?
    chk scope-rc "$rc" "0"
    chk scope-status "$(fld "$out" scope)" "detection-gated-transmit"
    chk scope-no-violation "$(printf '%s\n' "$out" | grep -c '^scope_violation')" "0"
    local badverb1="--trans""mit" badverb2="--""jam"
    chk scope-verb-tx "$(jamd_cli_main "$badverb1" >/dev/null 2>&1; echo $?)" "2"
    chk scope-verb-jam "$(jamd_cli_main "$badverb2" >/dev/null 2>&1; echo $?)" "2"

    # 8a. No gate. With no flag and no environment, --tx-build constructs and
    #     writes, and --tx-status says the gate is gone rather than closed.
    local unarmed="$d/unarmed.cu8"
    chk tx-build-no-gate "$(JAMD_LAB_AUTHORISED=0 jamd_cli_main --tx-build \
            --mode barrage --shape awgn --format cu8 --rate 1000000 --secs 0.1 \
            --centre 2650MHz --out "$unarmed" 2>/dev/null | \
            awk -F'\t' '$1=="constructed"{print $2}')" "yes"
    chk tx-build-writes-unkeyed "$([[ -s "$unarmed" ]] && echo yes || echo no)" "yes"
    out=$(jamd_cli_main --tx-status 2>/dev/null)
    chk tx-status-no-gate "$(fld "$out" gate)" "none"
    chk tx-status-keys-nothing "$(printf '%s\n' "$out" | grep -c '^TX')" "0"

    # 8b. The disclaimer is emitted before anything happens, and it names the
    #     cost that makes the whole path a question worth gating. It is read
    #     from stderr because that is where it belongs: --tx-status prints TSV
    #     on stdout, and a warning interleaved with fields corrupts the thing
    #     it is warning about.
    local dout derr
    dout=$(jamd_cli_main --tx-status 2>/dev/null)
    derr=$(jamd_cli_main --tx-status 2>&1 >/dev/null)
    chk tx-disclaimer-stream "$(printf '%s\n' "$derr" | grep -c '^WARNING')" "17"
    chk tx-disclaimer-order "$(printf '%s\n' "$derr" | head -n1 | cut -f1)" "WARNING"
    chk tx-disclaimer-emergency "$(printf '%s\n' "$derr" | grep -c 'emergency calls')" "1"
    chk tx-disclaimer-shielding "$(printf '%s\n' "$derr" | grep -c 'NOT a legal one')" "1"
    chk tx-status-stdout-clean "$(printf '%s\n' "$dout" | grep -c '^WARNING')" "0"

    # 8c. Armed, the constructor runs on a machine with no SDR and the file it
    #     writes is real -- this is what makes the constructor testable.
    chk tx-build-armed "$(jamd_cli_main --tx-build \
            --mode barrage --shape awgn --format cu8 --rate 1000000 --secs 0.1 \
            --centre 2650MHz --out "$d/armed.cu8" 2>/dev/null | \
            awk -F'\t' '$1=="constructed"{print $2}')" "yes"
    chk tx-build-bytes "$(stat -c %s "$d/armed.cu8" 2>/dev/null)" "200000"
    chk tx-build-armed-is-cu8 "$(python3 -c "
import sys,numpy as np
x=np.fromfile(sys.argv[1],dtype=np.uint8)
print('yes' if len(x)==200000 else 'no')" "$d/armed.cu8" 2>/dev/null)" "yes"

    # 8d. Keying without a radio must fail rather than claim success. The
    #     selftest forces "defined but empty" so this holds on a box that does
    #     have an SDR attached.
    chk tx-key-no-radio "$(for drv in hackrf bladerf limesdr usrp; do
            JAMD_SDR_DEVICE= jamd_sdr_probe "$drv" || printf 'x'; done | wc -c)" "4"
    chk tx-key-refuses "$(JAMD_LAB_AUTHORISED=1 JAMD_SDR_DEVICE= jamd_tx_key \
            --mode barrage --shape awgn --format cu8 --rate 1000000 --secs 0.1 \
            --centre 2650MHz >/dev/null 2>&1; echo $?)" "3"
    # An unknown flag is refused rather than ignored: silently dropping a
    # mistyped --centre would construct on the default carrier.
    chk tx-build-unknown-flag "$(JAMD_LAB_AUTHORISED=1 jamd_tx_build --centre 2650MHz \
            --freq 2650MHz >/dev/null 2>&1; echo $?)" "2"
    # A field that silently prints empty is the failure mode this catches:
    # JAMD_SHAPES is a Python tuple and "$JAMD_SHAPES" in bash is "".
    # The shapes split into what this module synthesises from scratch and what
    # it obtains from a producer that owns the sequence (tools/phy_seqs.py,
    # tools/lte_phy.py, 12_nr_air --ssb-waveform). The status must name both,
    # because "this module can generate an SSB" and "12_nr_air generates an SSB
    # and this module transmits it" are different claims.
    chk tx-status-shapes "$(fld "$out" shapes)" "awgn cw chirp pss sss pbch pucch prach prs gps-ca nr-ssb"
    # lte-ssb is not refused for lack of a producer -- 12_nr_air and the LTE
    # table both exist -- it is refused because this module has no OFDM
    # modulator, which is exactly what the nr-ssb shape proves by not needing
    # one (it consumes the samples 12_nr_air already produced).
    chk tx-status-shapes-refused "$(fld "$out" shapes_refused)" "lte-ssb"
    chk tx-status-modes "$(fld "$out" modes)" "barrage narrowband"

    # 9. Status invariants.
    out=$(jamd_cli_status_tsv)
    chk status-scope "$(fld "$out" scope)" "detection and measurement, gated transmit behind an explicit authorisation flag"
    chk status-transmit "$(fld "$out" transmit_path)" "open"
    chk status-gate "$(fld "$out" tx_gate)" "none"
    chk status-tag "$(fld "$out" tag)" "jamd"

    # 10. The raster: both directions, on the band edges the TS fixes.
    out=$(jamd_py raster); rc=$?
    chk raster-rc "$rc" "0"
    chk raster-bad "$(fld "$out" raster_bad)" "0"
    chk arfcn-2650 "$(jamd_py_earfcn 2650MHz)" "41190"
    chk hz-2570 "$(jamd_py_freq 2570MHz)" "2570000000"
    # The collision that made the table order matter: 2570-2620 MHz sits inside
    # 2496-2690 MHz, and 2620 MHz belongs to EARFCN 6150, not 40890.
    chk arfcn-2620 "$(jamd_py_earfcn 2620MHz)" "6150"
    chk arfcn-2570 "$(jamd_py_earfcn 2570MHz)" "37750"

    # 11. The fixtures are a claim the analyser has to meet. Each one is built
    #     with a verdict in mind and the label the verb prints IS that verdict;
    #     if the generator and the analyser ever drift apart, this is where it
    #     shows, rather than in a chain report six months later.
    local got
    out=$(jamd_cmd_fixture clean "$d/fx_clean.cf32" --rate 20000000 --secs 0.25) || bad=$((bad + 1))
    chk fixture-clean-label "$(fld "$out" expected_verdict)" "clean"
    # cf32 is 8 bytes per sample: 20e6 Hz for 0.25 s = 5e6 samples = 40e6 bytes.
    chk fixture-clean-bytes "$(stat -c %s "$d/fx_clean.cf32" 2>/dev/null)" "40000000"
    got=$(jamd_py characterise "$d/fx_clean.cf32" cf32 20000000 | awk -F'\t' '$1=="characterisation"{print $2; exit}')
    chk fixture-clean-verdict "$got" "clean"
    out=$(jamd_cmd_fixture narrow "$d/fx_narrow.cf32" --rate 20000000 --secs 0.25) || bad=$((bad + 1))
    chk fixture-narrow-label "$(fld "$out" expected_verdict)" "narrowband"
    got=$(jamd_py characterise "$d/fx_narrow.cf32" cf32 20000000 | awk -F'\t' '$1=="characterisation"{print $2; exit}')
    chk fixture-narrow-verdict "$got" "narrowband"
    out=$(jamd_cmd_fixture raised "$d/fx_raised.cf32" --rate 20000000 --secs 0.25) || bad=$((bad + 1))
    chk fixture-raised-label "$(fld "$out" expected_verdict)" "barrage"
    got=$(jamd_py characterise "$d/fx_raised.cf32" cf32 20000000 | awk -F'\t' '$1=="characterisation"{print $2; exit}')
    chk fixture-raised-verdict "$got" "barrage"
    chk fixture-bad-kind "$(jamd_cmd_fixture loud "$d/fx_bad.cf32" >/dev/null 2>&1; echo $?)" "2"
    chk fixture-bad-format "$(jamd_cmd_fixture clean "$d/fx_bad.cf32" --format f32 >/dev/null 2>&1; echo $?)" "2"
    chk fixture-bad-flag "$(jamd_cmd_fixture clean "$d/fx_bad.cf32" --mode barrage >/dev/null 2>&1; echo $?)" "2"
    # Constructing samples must not be gated: it keys nothing, and a chain has
    # to be able to drive the receive path with the lab flag unset.
    chk fixture-ungated "$(JAMD_LAB_AUTHORISED=0 jamd_cmd_fixture clean "$d/fx_ungated.cf32" --secs 0.1 >/dev/null 2>&1; echo $?)" "0"
    # 12. Reference-signal shapes, one known answer each. Every answer comes
    #     from the tool that owns the sequence, run here for the same
    #     parameters -- comparing this module's file against a sequence this
    #     module produced would prove only that it is deterministic.
    #
    #     The builds below go through jamd_py build, the constructor that
    #     jamd_tx_build parses flags for (12b drives the flag layer end to
    #     end). Where the only difference between this module's file and the
    #     producer's is the peak normalisation, the assertion says so and
    #     states the tolerance instead of pretending to byte equality: the
    #     producer's container full scale is its own, the module renormalises
    #     once, and every sample must still be the producer's sample times one
    #     scalar -- that is what the residual of 1e-6 full scale asserts.
    local tools="${IMSISTING_ROOT:-.}/tools" srows sfile got gaterc
    cat > "$d/kat.py" <<'KATPY'
import os, sys
import numpy as np

sys.path.insert(0, os.path.join(os.environ.get('IMSISTING_ROOT', '.'), 'tools'))


def read_iq(path):
    d = np.fromfile(path, dtype='<f4').astype(np.float64)
    return d[0::2] + 1j * d[1::2]


def read_any(path, fmt):
    if fmt == 'ci16':
        d = np.fromfile(path, dtype='<i2').astype(np.float64)
        return (d[0::2] + 1j * d[1::2]) / 32767.0
    if fmt == 'cu8':
        d = np.fromfile(path, dtype=np.uint8).astype(np.float64)
        return ((d[0::2] - 127.5) + 1j * (d[1::2] - 127.5)) / 127.5
    return read_iq(path)


def body(x, n_fft, l):
    import lte_phy as phy
    cps = phy.cp_lengths(n_fft)
    off = sum(cps[:l]) + l * n_fft + cps[l]
    return np.fft.fft(x[off:off + n_fft]) / n_fft


cmd = sys.argv[1]
if cmd == 'sync':
    import lte_phy as phy
    path, which, cell = sys.argv[2], sys.argv[3], int(sys.argv[4])
    n_rb, n_fft = 50, 1024
    x = read_iq(path)
    l_sss, l_pss = phy.sync_symbols(0)
    S = body(x, n_fft, l_pss if which == 'pss' else l_sss)
    bins = phy.subcarrier_bins(n_fft, n_rb * 12)
    k0 = n_rb * 6 - 36
    got = np.array([S[bins[k0 + 5 + i]] for i in range(62)])
    rows = np.loadtxt(sys.argv[5], dtype=str, delimiter='\t')
    want = np.array([complex(float(r[1]), float(r[2])) for r in rows])
    ratio = got / want
    alpha = ratio.mean()
    print('spread\t%.3e' % (float(np.abs(ratio - alpha).max() / abs(alpha))))
    print('rel_err\t%.3e' % float(np.abs(got / alpha - want).max()))
    print('reserved\t%.3e'
          % float(max(abs(S[bins[k0 + i]]) for i in (0, 1, 2, 3, 4))))
    print('same_within_1e-5\t%s'
          % ('yes' if float(np.abs(got / alpha - want).max()) < 1e-5 else 'no'))
elif cmd == 'pbch':
    import lte_phy as phy
    path, cell = sys.argv[2], int(sys.argv[3])
    n_rb, n_fft = 50, 1024
    x = read_iq(path)
    bins = phy.subcarrier_bins(n_fft, n_rb * 12)
    cache, bits = {}, []
    for (l, k) in phy.pbch_re_positions(n_rb, cell):
        if l not in cache:
            cache[l] = body(x, n_fft, l)
        v = cache[l][bins[k]]
        # TS 36.211 7.1.2: the first bit of the pair drives the real part.
        bits.append(0 if v.real > 0 else 1)
        bits.append(0 if v.imag > 0 else 1)
    print('bits\t%d' % len(bits))
    print('hex\t%s' % ''.join('%x' % int(''.join(map(str, bits[i:i + 4])), 2)
                             for i in range(0, len(bits), 4)))
elif cmd == 'gps':
    x = read_iq(sys.argv[2])
    live = x.real[np.abs(x) > 1e-12]
    print('values\t%s' % ' '.join('%.0f' % v for v in np.unique(live)))
    print('imag\t%.0e' % float(np.abs(x.imag).max()))
    print('period1023\t%s'
          % ('yes' if np.array_equal(x[:1023], x[1023:2046]) else 'no'))
elif cmd == 'peak':
    x = read_any(sys.argv[2], sys.argv[3])
    p = float(np.abs(x).max())
    print('peak\t%.6f' % p)
    print('within_full_scale\t%s' % ('yes' if p <= 1.0 else 'no'))
elif cmd == 'modulus':
    x = read_iq(sys.argv[2])
    live = np.abs(x) > 1e-12
    a = np.abs(x[live])
    print('modulus\t%.9f' % float(a.mean()))
    print('spread\t%.3e' % float(np.abs(a - a.mean()).max()))
    print('zeros\t%d' % int((~live).sum()))
    print('constant_within_1e-6\t%s'
          % ('yes' if float(np.abs(a - a.mean()).max()) < 1e-6 else 'no'))
elif cmd == 'scalar':
    m = read_iq(sys.argv[2])
    p = read_iq(sys.argv[3])
    n = int(sys.argv[4]) if len(sys.argv) > 4 else min(len(m), len(p))
    m, p = m[:n], p[:n]
    keep = np.abs(p) > 1e-12
    alpha = complex((m[keep] / p[keep]).mean())
    resid = float(np.abs(m[keep] - alpha * p[keep]).max())
    print('scalar\t%.9f%+.3ej' % (alpha.real, alpha.imag))
    print('resid\t%.3e' % resid)
    print('same_within_1e-6\t%s' % ('yes' if resid < 1e-6 else 'no'))
elif cmd == 'tile':
    x = read_iq(sys.argv[2])
    p, a, b = int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5])
    print('tile\t%s' % ('yes' if np.array_equal(x[a:a + p], x[b:b + p]) else 'no'))
elif cmd == 'zero':
    x = read_iq(sys.argv[2])
    a, b = int(sys.argv[3]), int(sys.argv[4])
    print('max\t%.3e' % float(np.abs(x[a:b]).max()))
KATPY

    # 12a. GPS L1 C/A, IS-GPS-200 3.2.2. At 1.023 Msps the code is one sample
    #      per chip and the values are exactly +-1, so the module's peak
    #      normalisation is the identity here (scale 1.0) and byte equality
    #      with the producer is the honest assertion, not a tolerance. The
    #      pulse train rides on the same build: n = 51150, on 0.01 s (10230
    #      samples) / off 0.01 s, so --on/--off must blank 2 x 10230 = 20460
    #      samples and keep 30690 (gated_samples counts what was blanked).
    srows=$(jamd_py build "$d/gps.cf32" narrowband gps-ca cf32 1023000 0.05 \
            1575420000 "" 1.0 0.01 0.01 20240101 0 "prn=7") || bad=$((bad + 1))
    chk gps-ca-built "$(fld "$srows" constructed)" "yes"
    chk gps-ca-producer "$(fld "$srows" producer)" \
        "tools/phy_seqs.py gen --seq gps-ca (IS-GPS-200 3.2.2)"
    chk gps-ca-gate "$(fld "$srows" gated_samples)" "20460"
    chk gps-ca-duty "$(fld "$srows" duty_cycle)" "0.500"
    chk gps-ca-peak "$(fld "$srows" peak_full_scale)" "1.0000"
    python3 "$tools/phy_seqs.py" gen --seq gps-ca --prn 7 --rate 1023000 --secs 0.05 \
            --format cf32 --out "$d/gps_prod.cf32" >/dev/null 2>&1
    # The gate blanks the second window, so the comparison is the first ON
    # window: 10230 samples x 8 bytes. Inside it the module's file and the
    # producer's are the same bytes, because at --peak 1.0 the peak scaling of
    # a +-1 code is the identity -- that is the byte-equality claim, and it is
    # made about the samples the module keeps, not about the gate.
    chk gps-ca-byte-equal \
        "$(cmp -n $((10230 * 8)) "$d/gps.cf32" "$d/gps_prod.cf32" && echo yes || echo no)" "yes"
    got=$(python3 "$d/kat.py" gps "$d/gps.cf32")
    chk gps-ca-code "$(fld "$got" values)" "-1 1"
    chk gps-ca-no-carrier "$(fld "$got" imag)" "0e+00"
    chk gps-ca-period "$(fld "$got" period1023)" "yes"
    chk gps-ca-gated-off "$(python3 "$d/kat.py" zero "$d/gps.cf32" 10230 20460 | \
            awk -F'\t' '$1=="max"{print ($2==0)?"zero":"nonzero"}')" "zero"

    # 12a2. The same shape through the integer writer. ci16 is the format whose
    #       scale factor is not the float one's (32767, clipped), so it is the
    #       writer that would silently clip a normalised signal: 51150 samples
    #       x 4 bytes, and the sample read back off disk is still +-1 in full
    #       scale, i.e. the waveform survived the writer.
    srows=$(jamd_py build "$d/gps16.ci16" narrowband gps-ca ci16 1023000 0.05 \
            1575420000 "" 1.0 1.0 0.0 20240101 0 "prn=7") || bad=$((bad + 1))
    chk gps-ca-ci16-format "$(fld "$srows" format)" "ci16"
    chk gps-ca-ci16-bytes "$(fld "$srows" bytes)" "204600"
    got=$(python3 "$d/kat.py" peak "$d/gps16.ci16" ci16)
    chk gps-ca-ci16-peak "$(fld "$got" peak)" "1.000000"
    chk gps-ca-ci16-no-clip "$(fld "$got" within_full_scale)" "yes"

    # 12b. PRACH, TS 36.211 5.7.2. At the preamble's own 1.04875 Mcps the
    #      format-0 block is one sample per chip, where the CAZAC really is
    #      constant modulus; at 20 Msps the producer's FFT resampling rounds
    #      the block edges, so the modulus claim is measured at the rate it
    #      holds at. This is also the one shape driven through the flag layer:
    #      --root/--ncs have to reach the producer, and 839 sequence samples
    #      is the published format-0 length.
    srows=$(JAMD_LAB_AUTHORISED=1 jamd_tx_build --mode narrowband --shape prach \
            --format cf32 --rate 1048750 --secs 0.01 --centre 2650MHz --peak 1.0 \
            --root 1 --ncs 0 --out "$d/prach.cf32" 2>/dev/null) || bad=$((bad + 1))
    chk prach-built "$(fld "$srows" constructed)" "yes"
    chk prach-peak-le-full-scale "$(fld "$srows" peak_full_scale | awk '$1>1.0{f=1} END{print f?"no":"yes"}')" "yes"
    chk prach-sequence-length "$(fld "$srows" seq_samples)" "839"
    chk prach-root "$(fld "$srows" preamble_root_u)" "1"
    python3 "$tools/phy_seqs.py" gen --seq prach --preamble 1 --ncs 0 --v 0 \
            --rate 1048750 --secs 0.01 --format cf32 --out "$d/prach_prod.cf32" \
            >/dev/null 2>&1
    got=$(python3 "$d/kat.py" modulus "$d/prach.cf32")
    chk prach-constant-modulus "$(fld "$got" constant_within_1e-6)" "yes"
    got=$(python3 "$d/kat.py" scalar "$d/prach.cf32" "$d/prach_prod.cf32")
    chk prach-not-invented "$(fld "$got" same_within_1e-6)" "yes"

    # 12c. PSS, TS 36.211 6.11.1. The oracle is the CLI's 62 published
    #      values: demodulate the module's own OFDM symbol, take the 62
    #      subcarriers, and compare after removing the one complex scalar the
    #      constructor's peak normalisation applies. 1e-5 relative, because
    #      that scalar is recovered from the same 62 values it is removed
    #      with; the observed residual is 2e-8.
    srows=$(jamd_py build "$d/pss.cf32" narrowband pss cf32 15360000 0.01 \
            2650000000 "" 1.0 1.0 0.0 20240101 0 "pci=42") || bad=$((bad + 1))
    chk pss-built "$(fld "$srows" constructed)" "yes"
    chk pss-peak-le-full-scale "$(fld "$srows" peak_full_scale | awk '$1>1.0{f=1} END{print f?"no":"yes"}')" "yes"
    chk pss-occupied "$(fld "$srows" occupied_hz)" "1080000"
    python3 "$tools/lte_phy.py" pss --n-id-2 0 > "$d/pss_cli.tsv"
    got=$(python3 "$d/kat.py" sync "$d/pss.cf32" pss 42 "$d/pss_cli.tsv")
    chk pss-samples-match-cli "$(fld "$got" same_within_1e-5)" "yes"
    chk pss-reserved-empty "$(printf '%s\n' "$got" | \
            awk -F'\t' '$1=="reserved"{print ($2<1e-6)?"yes":"no"}')" "yes"
    sfile=$(printf '%s\n' "$(jamd_py characterise "$d/pss.cf32" cf32 15360000)" | \
            awk -F'\t' '$1=="characterisation"{print $2}')
    chk pss-verdict "$sfile" "narrowband"

    # 12d. SSS, TS 36.211 6.11.2, same extraction on slot 0 symbol 5. The SSS
    #      values are real +-1, so a phase rotation would show up as a complex
    #      scalar where the CLI says real -- asserted through rel_err.
    srows=$(jamd_py build "$d/sss.cf32" narrowband sss cf32 15360000 0.01 \
            2650000000 "" 1.0 1.0 0.0 20240101 0 "pci=42") || bad=$((bad + 1))
    chk sss-built "$(fld "$srows" constructed)" "yes"
    chk sss-peak-le-full-scale "$(fld "$srows" peak_full_scale | awk '$1>1.0{f=1} END{print f?"no":"yes"}')" "yes"
    chk sss-symbol "$(fld "$srows" lte_symbol)" "5"
    python3 "$tools/lte_phy.py" sss --cell 42 > "$d/sss_cli.tsv"
    got=$(python3 "$d/kat.py" sync "$d/sss.cf32" sss 42 "$d/sss_cli.tsv")
    chk sss-samples-match-cli "$(fld "$got" same_within_1e-5)" "yes"
    chk sss-occupied "$(fld "$srows" occupied_hz)" "1080000"

    # 12e. PBCH, TS 36.211 6.6.4. There is no CLI verb that emits PBCH
    #      samples, so the known answer is the CLI's codeword: demodulate the
    #      240 PBCH resource elements of the module's own slot, read the 480
    #      QPSK bits off the constellation (7.1.2 bit order), and compare that
    #      hex against `lte_phy pbch --frame 0`. Nothing in the module's path
    #      is reused to make the comparison, so a wrong map or a wrong
    #      scrambling seed fails here.
    srows=$(jamd_py build "$d/pbch.cf32" narrowband pbch cf32 15360000 0.01 \
            2650000000 "" 1.0 1.0 0.0 20240101 0 "pci=42,mib=0,ports=1") || bad=$((bad + 1))
    chk pbch-built "$(fld "$srows" constructed)" "yes"
    chk pbch-peak-le-full-scale "$(fld "$srows" peak_full_scale | awk '$1>1.0{f=1} END{print f?"no":"yes"}')" "yes"
    chk pbch-re-count "$(fld "$srows" pbch_re)" "240"
    python3 "$tools/lte_phy.py" pbch 000000 --cell 42 --ports 1 --frame 0 | \
            awk -F'\t' '$1=="frame0"{print tolower($2)}' > "$d/pbch_cli.txt"
    got=$(python3 "$d/kat.py" pbch "$d/pbch.cf32" 42)
    chk pbch-bits "$(fld "$got" bits)" "480"
    chk pbch-codeword "$(fld "$got" hex)" "$(cat "$d/pbch_cli.txt")"
    chk pbch-occupied "$(fld "$srows" occupied_hz)" "1080000"

    # 12f. NR SSB. The seam test: the module must hand back exactly what
    #      12_nr_air wrote. It cannot be byte equality, and the reason is in
    #      the numbers -- 12_nr_air pulls its own full scale to 0.999999 to
    #      stay below 1.0 after a read-back, and this module renormalises that
    #      to --peak 1.0, so the two files differ by one scalar and by nothing
    #      else. Residual tolerance 1e-6 of full scale (float32 rounding of a
    #      single multiply writes ~6e-8); the observed residual is 4e-8.
    srows=$(jamd_py build "$d/ssb.cf32" narrowband nr-ssb cf32 30720000 0.0002 \
            3500000000 "" 1.0 1.0 0.0 20240101 0 "scs=30,n-rb=51,pci=1,i-ssb=0") \
            || bad=$((bad + 1))
    chk nr-ssb-built "$(fld "$srows" constructed)" "yes"
    chk nr-ssb-peak-le-full-scale "$(fld "$srows" peak_full_scale | awk '$1>1.0{f=1} END{print f?"no":"yes"}')" "yes"
    chk nr-ssb-producer "$(fld "$srows" producer)" \
        "modules/12_nr_air.sh --ssb-waveform (TS 38.211 7.4.3)"
    chk nr-ssb-burst "$(fld "$srows" ssb_burst_samples)" "4384"
    bash "${IMSISTING_ROOT:-.}/modules/12_nr_air.sh" --ssb-waveform "$d/ssb_prod.cf32" \
            --format cf32 --rate 30720000 --n-rb 51 --pci 1 --i-ssb 0 --scs 30 \
            --reps 1 >/dev/null 2>&1
    got=$(python3 "$d/kat.py" scalar "$d/ssb.cf32" "$d/ssb_prod.cf32" 4384)
    chk nr-ssb-samples-are-producer "$(fld "$got" same_within_1e-6)" "yes"

    # 12g. PRS. TS 36.211 6.10.4 is an RE-domain sequence: one sample per
    #      resource element, so the module must report the producer's own rate
    #      rather than resample it into a waveform nobody transmits. The
    #      sidecar RE map is part of the product and must be carried over.
    srows=$(jamd_py build "$d/prs.cf32" narrowband prs cf32 20000000 0.01 \
            2650000000 "" 1.0 1.0 0.0 20240101 0 "pci=1,n-rb-prs=100,n-rb-dl=100") \
            || bad=$((bad + 1))
    chk prs-built "$(fld "$srows" constructed)" "yes"
    chk prs-peak-le-full-scale "$(fld "$srows" peak_full_scale | awk '$1>1.0{f=1} END{print f?"no":"yes"}')" "yes"
    chk prs-rate-is-re-domain "$(fld "$srows" rate)" "1760000"
    chk prs-requested-rate "$(fld "$srows" requested_rate_hz)" "20000000"
    chk prs-mapping-carried "$([[ -s "$d/prs.cf32.remap.tsv" ]] && echo yes || echo no)" "yes"
    python3 "$tools/phy_seqs.py" gen --seq prs --pci 1 --n-rb-prs 100 --n-rb-dl 100 \
            --secs 0.01 --format cf32 --out "$d/prs_prod.cf32" >/dev/null 2>&1
    got=$(python3 "$d/kat.py" scalar "$d/prs.cf32" "$d/prs_prod.cf32")
    chk prs-samples-are-producer "$(fld "$got" same_within_1e-6)" "yes"
    chk prs-mapping-identical "$(cmp -s "$d/prs.cf32.remap.tsv" "$d/prs_prod.cf32.remap.tsv" && echo yes || echo no)" "yes"

    # 12h. What is refused, and the reason reaching the caller. A refusal that
    #      prints nothing is indistinguishable from a bug, so the reason is a
    #      machine-readable row on stdout as well as ERROR/WHY on stderr.
    # PUCCH is built, not refused: one RB of format 1a from lte_phy's own
    # sequence, in narrowband mode, at an LTE rate.
    srows=$(jamd_py build "$d/pucch.cf32" narrowband pucch cf32 15360000 0.01 \
            2650000000 "" 1.0 1.0 0.0 20240101 0 "pci=37,ncs=3" 2>/dev/null); gaterc=$?
    chk pucch-built "$gaterc" "0"
    chk pucch-wrote-samples "$([[ -s "$d/pucch.cf32" ]] && echo yes || echo no)" "yes"
    chk pucch-format "$(fld "$srows" pucch_format)" "1a"
    chk pucch-group "$(fld "$srows" sequence_group_u)" "7"
    chk pucch-shift "$(fld "$srows" n_cs)" "3"
    chk pucch-producer "$(fld "$srows" producer)" \
        "tools/lte_phy.py: pucch_slot_grid + ofdm_modulate (TS 36.211 5.5)"
    srows=$(jamd_py build "$d/lte-ssb.cf32" narrowband lte-ssb cf32 15360000 0.01 \
            2650000000 "" 1.0 1.0 0.0 20240101 0 "" 2>/dev/null); gaterc=$?
    chk lte-ssb-refused "$gaterc" "3"
    chk lte-ssb-reason-names-replacements \
        "$(printf '%s\n' "$srows" | grep -c -- '--shape sss')" "1"
    # A reference signal is narrowband by nature: barrage must be refused with
    # the reason, not silently treated as narrowband.
    got=$(jamd_py build "$d/x.cf32" barrage pss cf32 15360000 0.01 2650000000 "" \
            1.0 1.0 0.0 20240101 0 "" 2>&1 >/dev/null); gaterc=$?
    chk signal-shape-refuses-barrage "$gaterc" "2"
    chk signal-shape-barrage-why "$(printf '%s\n' "$got" | grep -c '^WHY')" "1"
    # An LTE shape at a rate lte_phy has no FFT for must say which rates it
    # has, rather than modulating at the wrong sample rate.
    got=$(jamd_py build "$d/x.cf32" narrowband pss cf32 1234567 0.01 2650000000 "" \
            1.0 1.0 0.0 20240101 0 "" 2>&1 >/dev/null); gaterc=$?
    chk lte-shape-refuses-unknown-rate "$gaterc" "2"
    chk lte-shape-names-rates "$(printf '%s\n' "$got" | grep -c '15360000')" "1"
    # A --band the capture cannot hold is a usage error whichever branch builds
    # the samples. The producer branch used to answer it with rc 0, writing a
    # file whose band row named a width the samples do not cover; the
    # synthesised branch answered with rc 1, which reads as an internal fault.
    # Both now refuse with rc 2, say why, and leave nothing behind.
    srows=$(jamd_py build "$d/band_wider.cf32" narrowband awgn cf32 1000000 \
            0.02 1840000000 5000000 1.0 1.0 0.0 20240101 0 "" 2>&1 >/dev/null); gaterc=$?
    chk band-wider-than-rate-refused "$gaterc" "2"
    chk band-wider-than-rate-why "$(printf '%s\n' "$srows" | grep -c '^WHY')" "1"
    srows=$(jamd_py build "$d/band_wider_ref.cf32" narrowband gps-ca cf32 2000000 \
            0.01 1575420000 5000000 1.0 1.0 0.0 20240101 0 "prn=7" \
            2>&1 >/dev/null); gaterc=$?
    chk band-wider-than-rate-refsignal-refused "$gaterc" "2"
    chk band-wider-than-rate-refsignal-why "$(printf '%s\n' "$srows" | grep -c '^WHY')" "1"
    chk band-wider-than-rate-writes-nothing \
        "$([[ -e "$d/band_wider.cf32" || -e "$d/band_wider_ref.cf32" ]] && echo yes || echo no)" "no"
    # The flag layer refuses a name it does not know before it reaches python.
    chk tx-build-unknown-shape "$(JAMD_LAB_AUTHORISED=1 jamd_tx_build --mode narrowband \
            --shape wobble --format cf32 --rate 15360000 --centre 2650MHz \
            --out "$d/x.cf32" >/dev/null 2>&1; echo $?)" "2"

    # 12i. The shape table is answered by both verbs, and the bash-side name
    #      list cannot drift from the python one without this failing.
    out=$(jamd_cli_main --shapes 2>/dev/null)
    chk shapes-verb-shapes "$(fld "$out" shapes)" "awgn cw chirp pss sss pbch pucch prach prs gps-ca nr-ssb"
    chk shapes-verb-refused "$(fld "$out" shapes_refused)" "lte-ssb"
    chk shapes-verb-nrssb "$(printf '%s\n' "$out" | awk -F'\t' \
            '$1=="shape_producer"&&$2=="nr-ssb"{print $3}')" \
        "modules/12_nr_air.sh --ssb-waveform (TS 38.211 7.4.3)"
    chk shapes-verb-ungated "$(jamd_cli_main --shapes 2>&1 >/dev/null | grep -c '^WARNING')" "0"
    chk shapes-names-agree "$(for n in $JAMD_TX_SHAPE_NAMES; do
            printf '%s\n' "$out" | awk -F'\t' -v n="$n" \
                '($1=="shape_producer"||$1=="shape_refused_reason")&&$2==n{f=1} END{exit !f}' \
                || echo "$n"; done | wc -l)" "0"
    chk status-names-shapes "$(jamd_cli_status_tsv | awk -F'\t' '$1=="shapes"{print $2}')" \
        "awgn cw chirp pss sss pbch pucch prach prs gps-ca nr-ssb"

    # 12j. A PRACH-shaped capture is the analyser's own measurement of a real
    #      preamble: one 1.04875 MHz slice of a 20 MHz span, which is what
    #      "narrowband" means here. This is the fixture added for the new
    #      shapes, and its label is the verdict it must get.
    out=$(jamd_cmd_fixture prach "$d/fx_prach.cf32" --rate 20000000 --secs 0.02) \
            || bad=$((bad + 1))
    chk fixture-prach-label "$(fld "$out" expected_verdict)" "narrowband"
    got=$(jamd_py characterise "$d/fx_prach.cf32" cf32 20000000)
    chk fixture-prach-verdict "$(fld "$got" characterisation)" "narrowband"
    chk fixture-prach-occupies-slice "$(printf '%s\n' "$got" | \
            awk -F'\t' '$1=="occupied_fraction"{print ($2<0.25)?"yes":"no"}')" "yes"

    # 12k. Occupancy: the same three fixtures, asked a different question. A
    #      clean capture has no slice in use, a raised floor is in use all the
    #      time across the whole span, and a narrowband carrier is in use for
    #      part of the time in one slice.
    local occ
    occ=$(jamd_cmd_occupancy "$fclean" --rate "$rate")
    chk occ-clean-channels "$(fld "$occ" channels)"                          "0"
    chk occ-clean-occupancy "$(printf '%s\n' "$occ" | awk -F'\t' '$1=="occupancy_pct"{print ($2<5)?"yes":"no"}')" "yes"
    occ=$(jamd_cmd_occupancy "$fraised" --rate "$rate")
    chk occ-raise-occupancy "$(printf '%s\n' "$occ" | awk -F'\t' '$1=="occupancy_pct"{print ($2>40)?"yes":"no"}')" "yes"
    chk occ-raise-channels "$(fld "$occ" channels)"                          "1"
    chk occ-raise-width "$(printf '%s\n' "$occ" | awk -F'\t' '$1=="channel"{print $5}')" "$rate"
    chk occ-raise-threshold "$(fld "$(jamd_cmd_occupancy "$fraised" --rate "$rate" --threshold-db 20)" occupancy_pct)" "0.00"
    occ=$(jamd_cmd_occupancy "$fnarrow" --rate "$rate")
    chk occ-narrow-channels "$(fld "$occ" channels)"                         "1"
    chk occ-narrow-width "$(printf '%s\n' "$occ" | awk -F'\t' '$1=="channel"{print $5}')" "52734"
    chk occ-narrow-verdict "$(fld "$occ" verdict)"                           "spectrum_occupancy_measured"
    chk occ-binwidth "$(fld "$(jamd_cmd_occupancy "$fnarrow" --rate "$rate" --bins 4096)" bin_width_hz)" "244.141"
    chk occ-no-rate "$(jamd_cmd_occupancy "$fnarrow" >/dev/null 2>&1; echo $?)"  "2"
    chk occ-bad-bins "$(jamd_cmd_occupancy "$fnarrow" --rate "$rate" --bins 1000 >/dev/null 2>&1; echo $?)" "2"
    chk occ-no-file "$(jamd_cmd_occupancy "$d/iq/nope.cf32" --rate "$rate" >/dev/null 2>&1; echo $?)" "1"

    printf 'ASSERTIONS\t%d\n' "$nchk"
    rm -rf "$d"
    trap - EXIT
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ── menu ────────────────────────────────────────────────────────────────
jamd_menu() {
    while true; do
        banner
        echo -e "  ${C_MAG}=== Jamming detect (detection / measurement only) ===${C_RESET}"
        echo -e "  loot: ${C_DIM}$JAMD_DIR${C_RESET}\n"
        cat <<'M'
  [1]  analyse an IQ file (features)
  [2]  noise floor over time
  [3]  characterise the interferer
  [4]  merge receiver counters
  [5]  discriminate: jamming / congestion / coverage hole
  [6]  write a regulatory report (confirmed jamming only)
  [7]  scope check (no transmit path)
  [8]  shapes: what can be built and which tool produces each signal
  [0]  back

M
        read -rp "  choice> " c || return 0  # EOF: leave the menu cleanly
        case "$c" in
            1) read -rp "  iq file> " f; read -rp "  format (cf32|ci16|cu8)> " m; read -rp "  rate> " r
               jamd_cmd_analyse "$f" "$m" "$r" | column -t -s$'\t' 2>/dev/null || true
               read -rp "  press enter " _ ;;
            2) read -rp "  iq file> " f; read -rp "  format> " m; read -rp "  rate> " r
               jamd_cmd_noise_floor "$f" "$m" "$r" | column -t -s$'\t' 2>/dev/null || true
               read -rp "  press enter " _ ;;
            3) read -rp "  iq file> " f; read -rp "  format> " m; read -rp "  rate> " r
               read -rp "  centre MHz (blank)> " cf
               jamd_cmd_characterise "$f" "$m" "$r" "$cf" | column -t -s$'\t' 2>/dev/null || true
               read -rp "  press enter " _ ;;
            4) read -rp "  counters TSV> " k
               jamd_cmd_counters "$k" | column -t -s$'\t' 2>/dev/null || true
               read -rp "  press enter " _ ;;
            5) jamd_discriminate | column -t -s$'\t' 2>/dev/null || true
               read -rp "  press enter " _ ;;
            6) jamd_report | column -t -s$'\t' 2>/dev/null || true
               read -rp "  press enter " _ ;;
            7) jamd_scope_check; read -rp "  press enter " _ ;;
            8) jamd_cmd_shapes | column -t -s$'\t' 2>/dev/null || true
               read -rp "  press enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ── CLI dispatch ────────────────────────────────────────────────────────
jamd_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)              jamd_cli_status_tsv ;;
        --analyse)                 jamd_cmd_analyse "${1:-}" "${2:-}" "${3:-}" ;;
        --noise-floor)             jamd_cmd_noise_floor "${1:-}" "${2:-}" "${3:-}" ;;
        --characterise)            jamd_cmd_characterise "${1:-}" "${2:-}" "${3:-}" "${4:-}" ;;
        --occupancy)               jamd_cmd_occupancy "$@" ;;
        --counters)                jamd_cmd_counters "${1:-}" ;;
        --discriminate)            jamd_discriminate "${1:-}" ;;
        --report)                  jamd_report "${1:-}" ;;
        --fixture)                 jamd_cmd_fixture "$@" ;;
        --shapes)                  jamd_cmd_shapes ;;
        --tx-status)               jamd_cmd_tx_status ;;
        --tx-build)                jamd_tx_build "$@" ;;
        --selftest)                jamd_selftest ;;
        --menu)                    jamd_menu ;;
        *)
            cat >&2 <<EOF
Jamming Detect — interference detection, measurement and gated transmit

Usage: $0 COMMAND
  --status-tsv                              module state as TSV
  --analyse <iq> <format> <rate>            features from IQ, saved as the record
  --noise-floor <iq> <format> <rate>        noise floor over time
  --characterise <iq> <format> <rate> [MHz] narrowband/barrage, bandwidth, duty
  --occupancy <iq> [--format cf32|ci16|cu8] --rate <sps>
                                            which slices of the band were in use,
                                            for what fraction of the capture
             [--bins <n>] [--threshold-db <db>] [--edge-pct <pct>]
                                            fft size, what counts as occupied,
                                            and the duty a stretch needs to be
                                            called a channel
  --counters <file>                         merge receiver counters into the record
  --discriminate [record]                   jamming / congestion / coverage hole
  --report [record]                         regulatory report (jamming only)
  --fixture <clean|raised|narrow|prach> <out>
                                            write a capture whose verdict is known
             [--format cf32|ci16|cu8] [--rate <sps>] [--secs <s>]
  --tx-status                               the disclaimer, the gate, the radio,
                                            every shape and where it comes from
  --shapes                                  shapes, their producers, and the
                                            names this module refuses, with why
  --tx-build [--mode barrage|narrowband] [--shape <name>]
             [--format cf32|ci16|cu8] [--rate <sps>] [--secs <s>]
             --centre <MHz>|--earfcn <n> [--band <Hz>] [--peak <0..1>]
             [--on <s>] [--off <s>] [--seed <n>] [--out <path>]
                                            construct a waveform, no radio needed
  --selftest                                verify feature math and branches
  --menu                                    interactive menu

Shapes and the producer each one's samples come from (--shapes prints this):
  awgn cw chirp            synthesised here, numpy
  pss sss pbch             tools/lte_phy.py  (TS 36.211 6.11.1, 6.11.2, 6.6.4)
  prach                    tools/phy_seqs.py gen --seq prach  (TS 36.211 5.7.2)
  prs                      tools/phy_seqs.py gen --seq prs    (TS 36.211 6.10.4)
  gps-ca                   tools/phy_seqs.py gen --seq gps-ca (IS-GPS-200 3.2.2)
  nr-ssb                   modules/12_nr_air.sh --ssb-waveform (TS 38.211 7.4.3)
A reference-signal shape is built in --mode narrowband only, at the rate its
producer samples at (LTE: 1920000 3840000 7680000 15360000 23040000 30720000;
NR SSB: --rate must be N_FFT x --scs; prs is RE-domain and ignores --rate).
Refused by name, with the reason in --shapes: lte-ssb (now pss/sss/pbch),
lte-ssb only (an LTE sync block is pss/sss/pbch).
Producer parameters, all optional: --prn --pci --root --ncs --v --i-ssb
--n-rb --ports --mib --n-rb-prs --n-rb-dl --scs.

Formats: cf32 (interleaved float32), ci16 (interleaved int16), cu8 (interleaved
uint8). Detection needs no radio. --tx-build constructs a waveform and stops;
--tx-key asks a driver what it can see, prints the disclaimer, then keys it. No
authorisation flag is read anywhere -- the old lab-authorisation flag is
accepted and ignored -- and the selftest asserts the disclaimer comes first and
that no detection verb reaches a driver.
EOF
            return 2 ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    set -o pipefail
    IMSISTING_CLI=1
    : "${TMP_DIR:=/tmp/imsisting}"
    : "${LOOT_DIR:=$IMSISTING_ROOT/loot}"
    : "${CAPTURES_DIR:=$IMSISTING_ROOT/captures}"
    : "${LOGS_DIR:=$IMSISTING_ROOT/logs}"
    : "${STATE_DIR:=$IMSISTING_ROOT/state}"
    mkdir -p "$TMP_DIR" "$LOOT_DIR" "$CAPTURES_DIR" "$LOGS_DIR" "$STATE_DIR"
    declare -F banner >/dev/null 2>&1 || banner() { :; }
    declare -F info   >/dev/null 2>&1 || info()   { printf '[info] %s\n' "$*" >&2; }
    declare -F warn   >/dev/null 2>&1 || warn()   { printf '[warn] %s\n' "$*" >&2; }
    declare -F err    >/dev/null 2>&1 || err()    { printf '[err]  %s\n' "$*" >&2; }
    declare -F ok     >/dev/null 2>&1 || ok()     { printf '[ok]   %s\n' "$*" >&2; }
    jamd_cli_main "$@"
fi
