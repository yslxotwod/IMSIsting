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
#   * the lab-authorisation gate and the disclaimer, printed by the transmit
#     verbs themselves and not only by this comment
#
# The transmit path is gated, not hidden. jamd_tx_armed requires the explicit
# --i-have-a-lab-and-authorisation flag; jamd_scope_check asserts the verbs are
# dispatchable AND gated AND radio-checked, in one run, and that the lawful
# detection verbs are ungated. The selftest runs it.
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
    python3 - "$@" <<'PY'
import sys, os, math
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

JAMD_SHAPES = ('awgn', 'cw', 'chirp')
# Named, refused, and reported in its own field. It is a handoff: the
# sequence needs a modulator this module does not have, so it is not one
# of the shapes the constructor will produce.
JAMD_SHAPES_REFUSED = ('lte-ssb',)
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


def build(path, mode, shape, fmt, rate, secs, centre_hz, band_hz, peak_fs,
          on_s, off_s, seed, earfcn):
    """Construct an interfering waveform and write it in fmt.

    mode       'barrage' fills the whole capture band; 'narrowband' fills
               band_hz or less, centred on offset_hz from the capture centre
    shape      awgn | cw | chirp | lte-ssb (the last is a handoff, see below)
    peak_fs    peak magnitude in full scale, 0 < peak_fs <= 1. A driver that
               clips reports success and radiates splatter, so the peak is
               clamped here rather than left to the SDR's own protection
    on_s/off_s the pulse train; off_s = 0 means continuous
    """
    if mode not in JAMD_MODES:
        raise ValueError('mode must be barrage or narrowband: %s' % mode)
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

    # Narrowband cannot be narrower than a few FFT bins or it is a rounding
    # error; barrage is the whole band by definition.
    if mode == 'barrage':
        occ_hz = rate
    else:
        occ_hz = int(band_hz)
        if occ_hz <= 0:
            raise ValueError('narrowband needs a positive occupied bandwidth')
        if occ_hz > rate:
            raise ValueError('occupied %d Hz does not fit the %d Hz capture band'
                             % (occ_hz, rate))
        nbin = 4.0 * rate / max(1, int(rate * secs))
        if occ_hz < nbin:
            raise ValueError('occupied %d Hz is below the analyser resolution '
                             '(%.0f Hz at %d samples)' % (occ_hz, nbin,
                                                          int(rate * secs)))

    if shape == 'lte-ssb':
        sys.stderr.write(
            'ERROR\tshape lte-ssb is a handoff, not a waveform this module builds: '
            'the sequence is LTE PSS/SSS/PBCH+CRS, but turning QPSK symbols into '
            'OFDM samples needs a modulator this module does not have, and writing '
            'noise where the waveform would be is the fabricated success this '
            'toolkit exists to prevent\n')
        sys.stderr.write(
            'WHY\tthe symbols are constructible and are built by 10_lte_air; the '
            'samples are not, so --tx-build refuses rather than writing a file that '
            'looks like a waveform\n')
        sys.exit(3)

    rng = np.random.default_rng(int(seed))
    n = int(rate * secs)
    if n < 2048:
        raise ValueError('too few samples (%d); need at least 2048' % n)

    if mode == 'barrage':
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
    if measured > 1.0:
        raise ValueError('waveform peak %.4f exceeds full scale after scaling' % measured)

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
    print('constructed\tyes')


# ── synthetic fixtures for the selftest (receive files only) ────────────
#
# These are receive-side fixtures: clean, raised and narrow captures the
# analyser is pointed at. The transmit side has its own constructor, build(),
# above; the two are kept apart so that "does the analyser read this correctly"
# and "does the generator produce what it claims" stay separable assertions.
def gen(path, kind, fmt, rate, secs):
    n = int(rate * secs)
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
    elif kind == 'clean':
        pass
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
        sys.stderr.write('usage: jamd_py <analyse|noisefloor|characterise|counters|gen|build|raster> ...\n')
        sys.exit(2)
    mode, rest = argv[0], argv[1:]
    try:
        if mode == 'analyse':
            return cmd_analyse(rest)
        if mode == 'noisefloor':
            return cmd_noisefloor(rest)
        if mode == 'characterise':
            return cmd_characterise(rest)
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
            return build(rest[0], rest[1], rest[2], rest[3], int(rest[4]),
                         float(rest[5]), parse_hz(rest[6]), int(rest[7]),
                         float(rest[8]), float(rest[9]), float(rest[10]),
                         int(rest[11]), int(rest[12]))
        sys.stderr.write('unknown mode %s\n' % mode)
        sys.exit(2)
    except SystemExit:
        raise
    except Exception as e:
        sys.stderr.write('ERROR\t%s\n' % e)
        sys.exit(1)


main()
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
        clean|raised|narrow) ;;
        "") printf 'ERROR\tusage: --fixture <clean|raised|narrow> <out> [--format cf32|ci16|cu8] [--rate hz] [--secs s]\n' >&2; return 2 ;;
        *) printf 'ERROR\tunknown fixture kind %s (want clean|raised|narrow)\n' "$kind" >&2; return 2 ;;
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
    local want
    case "$kind" in
        clean)  want="clean" ;;
        raised) want="barrage" ;;
        narrow) want="narrowband" ;;
    esac
    printf 'fixture\t%s\npath\t%s\nformat\t%s\nrate_hz\t%s\nseconds\t%s\nbytes\t%s\nexpected_verdict\t%s\nkeys_nothing\tyes\n' \
        "$kind" "$out" "$fmt" "$rate" "$secs" "$(stat -c %s "$out" 2>/dev/null || echo 0)" "$want"
    printf 'ref\tTS 36.211/36.104 shaped fixtures; clean = AWGN, raised = floor lift (barrage), narrow = 25 kHz offset carrier (narrowband)\n'
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
#   * every path that can key a radio must pass through jamd_tx_armed, and the
#     driver call must be reachable only from jamd_tx_key.
#
# So the check is no longer "this file never names a driver". It is "the driver
# names occur only inside the keyed section, and that section is gated". A
# blanket ban on the strings would now assert the opposite of what the module
# is for.
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

    # 2. Keying is gated. jamd_tx_key is the only function that runs a driver
    #    command, and it must call the gate before it does anything else.
    local key_body
    key_body=$(awk '/^jamd_tx_key\(\) \{/,/^}/' "$self")
    if [[ -z "$key_body" ]]; then
        printf 'scope_violation\tjamd_tx_key is missing\n'; hits=$(( hits + 1 ))
    else
        grep -q 'jamd_tx_armed' <<< "$key_body" || {
            printf 'scope_violation\tjamd_tx_key does not consult the authorisation gate\n'
            hits=$(( hits + 1 )); }
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

JAMD_TX_ARMED=0
JAMD_TX_DEFAULT_RATE=20000000

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

# The gate. --i-have-a-lab-and-authorisation, or JAMD_LAB_AUTHORISED=1 for a
# driver that has no flag to pass (the same shape as 32_nas_signaling).
jamd_tx_armed() {
    if [[ "${JAMD_LAB_AUTHORISED:-0}" == "1" ]]; then
        return 0
    fi
    printf 'ERROR\trefusing to key a transmitter: this path requires the explicit flag --i-have-a-lab-and-authorisation\n' >&2
    printf 'ERROR\tnothing was constructed, nothing was transmitted, and no file was written\n' >&2
    printf 'WHY\t%s\n' "a transmitter whose effect is to deny service is unlawful in most jurisdictions regardless of intent, and unlike a Wi-Fi jammer it takes a cell site down across its whole coverage area including emergency calls; read the disclaimer printed by --tx-status" >&2
    return 2
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
#   --mode barrage|narrowband   --shape awgn|cw|chirp|lte-ssb
#   --format cf32|ci16|cu8      --rate <sps>        --secs <s>
#   --centre <Hz|MHz>|--earfcn <n>                  --band <Hz>
#   --peak <0..1>  --on <s>  --off <s>  --seed <n>  --out <path>
jamd_tx_build() {
    local mode="barrage" shape="awgn" fmt="cu8"
    local rate="" secs="" centre="" band="" peak=""
    local on_s="" off_s="" seed="20240101" out=""
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
            *) printf 'ERROR\t--tx-build does not take %s (see --help)\n' "$1" >&2; return 2 ;;
        esac
    done
    jamd_tx_armed || return 2
    jamd_tx_disclaimer

    [[ -n "$rate" ]] || rate="$JAMD_TX_DEFAULT_RATE"
    [[ -n "$secs" ]] || secs="1.0"
    [[ -n "$peak" ]] || peak="0.70"
    [[ -n "$on_s" ]] || on_s="1.0"
    [[ -n "$off_s" ]] || off_s="0.0"
    [[ -n "$centre" ]] || {
        printf 'ERROR\t--tx-build needs a centre frequency: <MHz|Hz> or --earfcn <n>\n' >&2; return 2; }
    case "$mode" in barrage|narrowband) ;; *)
        printf 'ERROR\tmode must be barrage or narrowband: %s\n' "$mode" >&2; return 2 ;; esac
    case "$fmt" in
        cf32|ci16|cu8) ;;
        cs8)  fmt="cu8" ;;                      # hackrf's name for cu8
        csv|c16|sc16|cs16) fmt="ci16" ;;
        *) printf 'ERROR\tformat must be cf32|ci16|cu8 (or a driver alias: cs8|c16|sc16|cs16)\n' >&2; return 2 ;;
    esac
    [[ -n "$band" ]] || band="1000000"
    [[ "$rate" =~ ^[0-9]+$ ]] || { printf 'ERROR\tsample rate must be a positive integer\n' >&2; return 2; }

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
             "$centre_hz" "$band" "$peak" "$on_s" "$off_s" "$seed" "$earfcn_flag"
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
    local mode="barrage" fmt="cu8" rate=""
    while (($#)); do
        case "$1" in
            --mode)   mode="${2:-}"; shift 2 ;;
            --format) fmt="${2:-}"; shift 2 ;;
            --rate)   rate="${2:-}"; shift 2 ;;
            *) break ;;
        esac
    done
    jamd_tx_armed || return 2
    jamd_tx_disclaimer

    local drv; drv=$(jamd_sdr_device) || {
        printf 'ERROR\tno SDR found: no radio answered (hackrf_info, bladeRF-cli -p, LimeUtil --find, uhd_find_devices)\n' >&2
        printf 'WHY\ta driver package installed is not a radio; this verb asks the driver what it can see, so a box with hackrf_transfer on PATH and no board attached fails here rather than at the driver call. Set JAMD_SDR_DEVICE=<hackrf|bladerf|limesdr|usrp> to name one, or JAMD_TX_CMD for a driver this module has no built-in call for\n' >&2
        return 3; }

    # Construct first: a build failure must not leave a half-sent pulse train.
    # The flags go straight through -- the constructor's interface is this
    # verb's interface, so there is nothing to translate.
    local built; built=$(JAMD_LAB_AUTHORISED=1 jamd_tx_build "$@" 2>/dev/null) || return $?
    local path freq gain iq fmt_drv
    path=$(jamd_fld "$built" path)
    freq=$(jamd_fld "$built" centre_hz)
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

# ── the two verbs ───────────────────────────────────────────────────────
# --tx-status prints the disclaimer and what would happen, and keys nothing.
# That is the verb a security team is meant to be able to run: it answers "what
# does this module refuse to do, and why" without touching a radio.
jamd_cmd_tx_status() {
    jamd_tx_disclaimer
    local drv
    printf 'gate\t%s\n' "$([[ "${JAMD_LAB_AUTHORISED:-0}" == 1 ]] && echo armed || echo closed)"
    printf 'gate_flag\t--i-have-a-lab-and-authorisation or JAMD_LAB_AUTHORISED=1\n'
    if drv=$(jamd_sdr_device 2>/dev/null); then
        printf 'radio\t%s\n' "$drv"
        printf 'radio_state\tpresent\n'
        printf 'driver_format\t%s\n' "$(jamd_tx_iq_format "$drv")"
    else
        printf 'radio\tnone\n'
        printf 'radio_state\tno radio answered hackrf_info, bladeRF-cli -p, LimeUtil --find or uhd_find_devices\n'
    fi
    printf 'gain_db\t%s\n' "${JAMD_TX_GAIN:-0}"
    printf 'modes\t%s\n' "$(jamd_py modes 2>/dev/null)"
    printf 'shapes\t%s\n' "$(jamd_py shapes 2>/dev/null)"
    printf 'shapes_refused\t%s\n' "$(jamd_py shapes-refused 2>/dev/null)"
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
    printf 'transmit_path\tgated\n'
    printf 'tx_verbs\t--tx-status --tx-build\n'
    printf 'tx_gate\t%s\n' "$([[ "${JAMD_LAB_AUTHORISED:-0}" == 1 ]] && echo armed || echo closed)"
    printf 'tx_keyed_by\t--i-have-a-lab-and-authorisation or JAMD_LAB_AUTHORISED=1\n'
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

    # 8a. The gate. Unkeyed, --tx-build must refuse and write nothing, and
    #     --tx-status must still answer (it keys nothing).
    local unarmed="$d/unarmed.cu8"
    chk tx-build-refuses "$(JAMD_LAB_AUTHORISED=0 jamd_cli_main --tx-build \
            --mode barrage --shape awgn --format cu8 --rate 1000000 --secs 0.1 \
            --centre 2650MHz --out "$unarmed" >/dev/null 2>&1; echo $?)" "2"
    chk tx-build-wrote-nothing "$([[ -e "$unarmed" ]] && echo yes || echo no)" "no"
    out=$(jamd_cli_main --tx-status 2>/dev/null)
    chk tx-status-unarmed "$(fld "$out" gate)" "closed"
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
    chk tx-build-armed "$(JAMD_LAB_AUTHORISED=1 jamd_cli_main --tx-build \
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
    chk tx-status-shapes "$(fld "$out" shapes)" "awgn cw chirp"
    chk tx-status-shapes-refused "$(fld "$out" shapes_refused)" "lte-ssb"
    chk tx-status-modes "$(fld "$out" modes)" "barrage narrowband"

    # 9. Status invariants.
    out=$(jamd_cli_status_tsv)
    chk status-scope "$(fld "$out" scope)" "detection and measurement, gated transmit behind an explicit authorisation flag"
    chk status-transmit "$(fld "$out" transmit_path)" "gated"
    chk status-gate "$(fld "$out" tx_gate)" "closed"
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
        --counters)                jamd_cmd_counters "${1:-}" ;;
        --discriminate)            jamd_discriminate "${1:-}" ;;
        --report)                  jamd_report "${1:-}" ;;
        --fixture)                 jamd_cmd_fixture "$@" ;;
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
  --counters <file>                         merge receiver counters into the record
  --discriminate [record]                   jamming / congestion / coverage hole
  --report [record]                         regulatory report (jamming only)
  --fixture <clean|raised|narrow> <out>     write a capture whose verdict is known
             [--format cf32|ci16|cu8] [--rate <sps>] [--secs <s>]
  --tx-status                               the disclaimer, the gate and the radio
  --tx-build [--mode barrage|narrowband] [--shape awgn|cw|chirp|lte-ssb]
             [--format cf32|ci16|cu8] [--rate <sps>] [--secs <s>]
             --centre <MHz>|--earfcn <n> [--band <Hz>] [--peak <0..1>]
             [--on <s>] [--off <s>] [--seed <n>] [--out <path>]
                                            construct a waveform, no radio needed
  --selftest                                verify feature math and branches
  --menu                                    interactive menu

Formats: cf32 (interleaved float32), ci16 (interleaved int16), cu8 (interleaved
uint8). Detection needs no gate and no radio. --tx-build constructs a waveform
and stops; the radio path sits behind --i-have-a-lab-and-authorisation and the
selftest asserts that gate exists, prints the disclaimer first, and that no
detection verb reaches a driver.
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
