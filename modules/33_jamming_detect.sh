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
# There is no transmit path in this file. jamd_scope_check asserts that, and
# the selftest runs it.
#
# Attack owned: O16 (RAN jamming) — detection and measurement only, per
# docs/ATTACK_COVERAGE.md.
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

# ── IQ / feature engine (python3 + numpy + scipy) ───────────────────────
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


# ── synthetic fixtures for the selftest (receive files only) ────────────
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
        sys.stderr.write('usage: jamd_py <analyse|noisefloor|characterise|counters|gen> ...\n')
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
        if mode == 'gen':
            return gen(rest[0], rest[1], rest[2], int(rest[3]), float(rest[4]))
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
        echo "scope: detection and measurement only; this module has no transmit path"
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
jamd_scope_check() {
    local self="${BASH_SOURCE[0]}"
    [[ -f "$self" ]] || { printf 'ERROR\tcannot read module source\n' >&2; return 1; }
    local -a markers=(
        "hackrf_""transfer"
        "bladeRF-""cli"
        "SoapySDRDevice_""writeStream"
        "osmosdr::""sink"
        "uhd::usrp::""multi_usrp"
        "gr::blocks::""vector_source"
        "iio_channel_attr_""write"
        "--trans""mit"
        "--t""x-""gain"
        "--wave""form"
        "--""jam"
    )
    local m hits=0
    for m in "${markers[@]}"; do
        if grep -Fq -- "$m" "$self"; then
            printf 'scope_violation\t%s\n' "$m"
            hits=$(( hits + 1 ))
        fi
    done
    # No verb that emits on a radio may be dispatchable.
    local v
    for v in "--trans""mit" "--t""x" "--""jam" "--""jammer"; do
        if grep -Fq -- "$v" "$self"; then
            printf 'scope_violation\tverb %s\n' "$v"
            hits=$(( hits + 1 ))
        fi
    done
    printf 'scope\t%s\n' "$([[ $hits -eq 0 ]] && echo detection-and-measurement-only || echo VIOLATION)"
    printf 'scope_checked\t%d API markers + 4 verb patterns\n' "${#markers[@]}"
    (( hits == 0 )) || return 1
    return 0
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
    printf 'scope\tdetection and measurement only\n'
    printf 'python3\t%s\nnumpy\t%s\nscipy\t%s\n' "$py" "$np" "$scipy"
    printf 'iq_formats\tcf32 ci16 cu8\n'
    printf 'dir\t%s\n' "$JAMD_DIR"
    printf 'features\t%s\n' "$JAMD_FEATURES"
    printf 'branches\tjamming congestion coverage_hole\n'
    printf 'transmit_path\tnone\n'
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

    # 8. Scope: no transmit path.
    out=$(jamd_scope_check); rc=$?
    chk scope-rc "$rc" "0"
    chk scope-status "$(fld "$out" scope)" "detection-and-measurement-only"
    chk scope-no-violation "$(printf '%s\n' "$out" | grep -c '^scope_violation')" "0"
    local badverb1="--trans""mit" badverb2="--""jam"
    chk scope-verb-tx "$(jamd_cli_main "$badverb1" >/dev/null 2>&1; echo $?)" "2"
    chk scope-verb-jam "$(jamd_cli_main "$badverb2" >/dev/null 2>&1; echo $?)" "2"

    # 9. Status invariants.
    out=$(jamd_cli_status_tsv)
    chk status-scope "$(fld "$out" scope)" "detection and measurement only"
    chk status-transmit "$(fld "$out" transmit_path)" "none"
    chk status-tag "$(fld "$out" tag)" "jamd"

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
        --selftest)                jamd_selftest ;;
        --menu)                    jamd_menu ;;
        *)
            cat >&2 <<EOF
Jamming Detect — interference detection and measurement (no transmit path)

Usage: $0 COMMAND
  --status-tsv                              module state as TSV
  --analyse <iq> <format> <rate>            features from IQ, saved as the record
  --noise-floor <iq> <format> <rate>        noise floor over time
  --characterise <iq> <format> <rate> [MHz] narrowband/barrage, bandwidth, duty
  --counters <file>                         merge receiver counters into the record
  --discriminate [record]                   jamming / congestion / coverage hole
  --report [record]                         regulatory report (jamming only)
  --selftest                                verify feature math and branches
  --menu                                    interactive menu

Formats: cf32 (interleaved float32), ci16 (interleaved int16), cu8 (interleaved
uint8). This module detects and measures; it has no transmit path, and the
selftest asserts that.
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
