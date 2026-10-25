#!/usr/bin/env bash
# ntn — 5G non-terrestrial networks: propagation delays, Doppler and K_offset.
#
# A satellite cell is a normal NR cell with two extra problems: a round-trip
# delay far larger than any terrestrial timing assumes, and a Doppler shift that
# scales with the closing velocity. 3GPP answers both in SIB19 (TA, K_offset,
# ephemeris, cell reference location, mobility). This module computes the delays
# and Doppler for the geometry you supply, and converts the SIB19 K_offset.
#
# K_offset is counted in 15 kHz reference slots, i.e. 1 ms each: TS 38.331
# NTN-Config field description ("The unit of the field K_offset is number of
# slots for a given subcarrier spacing of 15 kHz"), and TS 38.213 clause 9 adds
# 2^(mu-mu_Koffset)*K_offset slots in the carrier's numerology with
# mu_Koffset = 0 in FR1 and in FR2-NTN. So the carrier SCS changes the slot
# count the UE schedules with, not the delay in milliseconds. SIB19 is
# decoded and built through the generated NR table (--sib19, --sib19-build).
#
# Attack owned: none direct — cell reconnaissance and timing analysis for NTN
# access (extends 02_cell_recon and 12_nr_air to a satellite cell).
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

MOD_TMP="$TMP_DIR/ntn"
NTN_DIR="$LOOT_DIR/ntn"
mkdir -p "$MOD_TMP" "$NTN_DIR" 2>/dev/null

declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
declare -F warn >/dev/null 2>&1 || warn() { printf '[warn] %s\n' "$*" >&2; }
declare -F err  >/dev/null 2>&1 || err()  { printf '[err]  %s\n' "$*" >&2; }
declare -F ok   >/dev/null 2>&1 || ok()   { printf '[ok]   %s\n' "$*" >&2; }
declare -F banner >/dev/null 2>&1 || banner() { :; }

ntn_sanitize() { printf '%s' "${1:-}" | tr '\t\r\n' '   '; }
NTN_F=()
ntn_split() {
    NTN_F=()
    local i n
    n=$(printf '%s' "$1" | awk -F'\t' '{print NF}')
    for (( i = 1; i <= n; i++ )); do
        NTN_F+=("$(printf '%s' "$1" | cut -f"$i")")
    done
}

ntn_status_tsv() {
    printf 'MODULE\tntn\n'
    printf 'TARGET\tNTN propagation delay, Doppler, TA and K_offset handling\n'
    printf 'CONSTANT\tc=299792458 m/s (exact)\n'
    printf 'TRANSMIT\tnone — timing and link analysis\n'
    printf 'SELFTEST\tyes\n'
}

# ── Doppler (f_d = f_c * v_r / c, v_r = v cos(theta)) ───────────────────
ntn_doppler() {
    local f="${1:-}" v="${2:-}" ang="${3:-0}"
    [[ "$f" =~ ^[0-9]+([.][0-9]+)?$ && "$v" =~ ^[0-9]+([.][0-9]+)?$ && "$ang" =~ ^-?[0-9]+([.][0-9]+)?$ ]] || {
        printf 'ERROR\tfrequency, velocity and angle must be numeric\n' >&2; return 2; }
    awk -v f="$f" -v v="$v" -v a="$ang" 'BEGIN{
        c = 299792458
        pi = atan2(0, -1)
        vr = v * cos(a * pi / 180.0)
        fd = f * vr / c
        printf "carrier_hz\t%.0f\nvelocity_mps\t%.0f\nangle_deg\t%.1f\nradial_velocity_mps\t%.1f\ndoppler_hz\t%.1f\n", f, v, a, vr, fd
    }'
}

# ── round-trip delay ────────────────────────────────────────────────────
ntn_range_rtt() {
    local km="${1:-}"
    [[ "$km" =~ ^[0-9]+([.][0-9]+)?$ ]] || { printf 'ERROR\tdistance (km) must be numeric\n' >&2; return 2; }
    awk -v d="$km" 'BEGIN{
        c = 299792458
        m = d * 1000.0
        rtt = 2.0 * m / c
        printf "one_way_km\t%s\none_way_ms\t%.3f\nrtt_ms\t%.3f\n", d, m/c*1000.0, rtt*1000.0
    }'
}

# ── TA units and k_offset ───────────────────────────────────────────────
# LTE TA granularity is 16*T_s = 16/30720000 s; the UE must be able to express
# the whole RTT in TA units, which is why NTN adds a scheduling offset.
ntn_ta_units() {
    local km="${1:-}"
    [[ "$km" =~ ^[0-9]+([.][0-9]+)?$ ]] || { printf 'ERROR\tdistance (km) must be numeric\n' >&2; return 2; }
    awk -v d="$km" 'BEGIN{
        c = 299792458
        unit = 16.0/30720000.0
        rtt = 2.0 * d * 1000.0 / c
        ta = rtt / unit
        printf "rtt_ms\t%.3f\nta_unit_s\t%.9f\nta_units\t%.0f\nlte_ta_max\t1282\nnote\t%s\n",
            rtt*1000.0, unit, ta,
            (ta > 1282) ? "exceeds the LTE TA command range — NTN needs the extended offset in SIB19" : "within the LTE TA command range"
    }'
}
ntn_koffset() {
    # K_offset is an INTEGER (1..1023) of 15 kHz reference slots, so one slot
    # of K_offset is exactly 1 ms (TS 38.211 Table 4.3.2-1: 1 slot per 1 ms
    # subframe at mu=0) and the physical offset is K_offset ms for every
    # carrier SCS. TS 38.213 clause 9 (and 8.2 for the RAR grant) has the UE
    # add 2^(mu-mu_Koffset)*K_offset slots of the active UL BWP numerology,
    # with mu_Koffset = 0 in FR1 and in FR2-NTN, which is what makes the
    # carrier SCS matter: it scales the slot count, not the delay.
    local k="${1:-}" scs="${2:-}" rate="${3:-}" mu=0 factor=1
    [[ "$k" =~ ^[0-9]{1,4}$ ]] || {
        printf 'ERROR\tk_offset must be a decimal integer number of slots\n' >&2; return 2; }
    k=$(( 10#$k ))
    (( k >= 1 && k <= 1023 )) || {
        printf 'ERROR\tk_offset %d is outside cellSpecificKoffset-r17 INTEGER(1..1023) (TS 38.331)\n' "$k" >&2
        return 2; }
    if [[ -n "$scs" ]]; then
        case "$scs" in
            15)  mu=0 ;;
            30)  mu=1 ;;
            60)  mu=2 ;;
            120) mu=3 ;;
            *)   printf 'ERROR\tsubcarrier spacing must be 15, 30, 60 or 120 kHz (got %s)\n' "$scs" >&2; return 2 ;;
        esac
        factor=$(( 1 << mu ))
    fi
    if [[ -n "$rate" ]]; then
        [[ "$rate" =~ ^[0-9]{1,15}$ ]] || {
            printf 'ERROR\tsample rate must be a positive decimal integer in Hz (got %s)\n' "$rate" >&2
            return 2; }
        rate=$(( 10#$rate ))
        (( rate > 0 )) || {
            printf 'ERROR\tsample rate must be greater than zero (got %s)\n' "$rate" >&2
            return 2; }
    fi
    printf 'k_offset_slots\t%d\n' "$k"
    printf 'k_offset_unit\tslots at 15 kHz reference (TS 38.331 NTN-Config)\n'
    printf 'slot_ms_used\t%.3f\n' 1.0
    printf 'delay_ms\t%.3f\n' "$k"
    if [[ -n "$scs" ]]; then
        printf 'scs_khz\t%s\n' "$scs"
        awk -v m="$mu" 'BEGIN{ printf "carrier_slot_ms\t%.3f\n", 1.0/(2^m) }'
        printf 'applied_slots\t%d\n' $(( k * factor ))
        printf 'applied_ms\t%.3f\n' "$k"
        printf 'note\tK_offset counts 15 kHz slots; with SCS %s kHz the UE adds 2^%d*K_offset = %d carrier slots (TS 38.213 clause 9, mu_Koffset=0)\n' \
            "$scs" "$mu" $(( k * factor ))
    fi
    if [[ -n "$rate" ]]; then
        printf 'sample_rate_hz\t%s\n' "$rate"
        awk -v k="$k" -v r="$rate" 'BEGIN{ printf "delay_samples\t%.0f\n", k*r/1000.0 }'
    fi
}

# ── SIB19: decode ───────────────────────────────────────────────────────
# Decoded as TS 38.331 defines it, through the generated unaligned-PER table
# (tools/nr_rrc_layout.py, 326 types, certified case by case against pycrate by
# tools/lte-per-oracle/verify_per.py). Nothing here slices hex: every field the
# decoder prints is a field the schema names, and a bit string that is not a
# SIB19 is refused rather than read until something plausible comes out.
# ── SIB19: build ────────────────────────────────────────────────────────
# The other half of the decode above. A satellite cell broadcasts SIB19 so a
# UE can schedule around a moving sky; building one is how you test what a UE
# does with a cell that claims a pass it is not on. The value is composed here
# and encoded through the same generated table the decoder reads, and the
# encoding is accepted only when its own decoder gives the value back.
# ── hostile ephemeris and a wrong K_offset (F2) ─────────────────────────
# A satellite cell tells the UE where the satellite is and how far it may
# trust that: the SIB19 ephemeris (TS 38.331), the K_offset that says how many
# ms of propagation the schedule must absorb, and the UL sync validity window.
# All three are numbers the cell asserts, and a UE that believes them schedules
# its uplink into silence. This verb takes a true range and a forged one and
# works out what the UE would get wrong, in the units the UE uses.
# ── timing advance → a position on the ground (F3) ──────────────────────
# The NTN round trip is a distance, and the distance from one satellite places
# the UE on a circle: the ground where the slant range matches. Two circles,
# from two satellites or the same one twice, meet at two points, and the answer
# is the pair. This is the analysis an operator would need to turn a timing
# measurement into a location, worked out from the TA or the range directly.
ntn_timing_geoloc() {
    local ta="" r1="" r2="" slat="" slon="" salt="" lat2="" lon2=""
    while (( $# )); do
        case "$1" in
            --ta)      ta="${2:-}";    shift 2 || { ntn_geo_usage; return 2; } ;;
            --range-km) r1="${2:-}";   shift 2 || { ntn_geo_usage; return 2; } ;;
            --range2-km) r2="${2:-}";  shift 2 || { ntn_geo_usage; return 2; } ;;
            --sat-lat) slat="${2:-}";  shift 2 || { ntn_geo_usage; return 2; } ;;
            --sat-lon) slon="${2:-}";  shift 2 || { ntn_geo_usage; return 2; } ;;
            --sat-alt) salt="${2:-}";  shift 2 || { ntn_geo_usage; return 2; } ;;
            --sat2-lat) lat2="${2:-}"; shift 2 || { ntn_geo_usage; return 2; } ;;
            --sat2-lon) lon2="${2:-}"; shift 2 || { ntn_geo_usage; return 2; } ;;
            *)         ntn_geo_usage; return 2 ;;
        esac
    done
    if [[ -z "$ta" && -z "$r1" ]]; then ntn_geo_usage; return 2; fi
    [[ "$slat" =~ ^-?[0-9]+([.][0-9]+)?$ && "$slon" =~ ^-?[0-9]+([.][0-9]+)?$ && "$salt" =~ ^[0-9]+([.][0-9]+)?$ ]] || {
        printf 'ERROR\t--sat-lat, --sat-lon and --sat-alt are all needed to place the circle\n' >&2; return 2; }
    if [[ -n "$ta" && ! "$ta" =~ ^[0-9]+$ ]]; then
        printf 'ERROR\t--ta wants whole timing-advance units\n' >&2; return 2
    fi
    ntn_geo_math "$ta" "$r1" "$r2" "$slat" "$slon" "$salt" "$lat2" "$lon2"
}

ntn_geo_math() {
    awk -v ta="$1" -v r1="$2" -v r2="$3" -v slat="$4" -v slon="$5" -v salt="$6" \
        -v lat2="$7" -v lon2="$8" 'BEGIN{
        c = 299792458; unit = 16.0/30720000.0
        deg = 3.14159265358979/180; R = 6371.0
        if (ta != "") {
            rtt = ta * unit
            dkm = c * rtt / 2000.0
            printf "input\ttiming advance\n"
            printf "ta_units\t%s\n", ta
            printf "rtt_ms\t%.3f\n", rtt*1000
        } else {
            dkm = r1 + 0
            printf "input\trange\n"
        }
        h = salt + 0
        g2 = dkm*dkm - h*h
        if (g2 <= 0) {
            printf "ERROR\tthe slant range %.1f km is shorter than the satellite altitude %.1f km, so no ground point matches it\n", dkm, h
            exit 2
        }
        gr = sqrt(g2)
        # TA quantisation: one unit is 16/30720000 s of round trip, so half a
        # unit is the worst rounding error, in metres of one-way range
        quant_m = c * (unit/2) / 2 * 1
        printf "slant_range_km\t%.1f\n", dkm
        printf "sat_alt_km\t%.1f\n", h
        printf "ground_radius_km\t%.1f\n", gr
        printf "quantisation_m\t%.0f\n", quant_m
        printf "circle\tlat=%s lon=%s radius_km=%.1f\n", slat, slon, gr
        printf "finding\tsingle_measurement\tMEDIUM\tone range gives a circle of %.0f km radius, which is a region and not a position\n", gr
        if (lat2 != "" && lon2 != "" && r2 != "") {
            h2 = h
            g2b = (r2+0)*(r2+0) - h2*h2
            if (g2b <= 0) { printf "finding\tno_intersection\tINFO\tthe second range gives no ground circle either\n"; exit 0 }
            gr2 = sqrt(g2b)
            printf "circle2\tlat=%s lon=%s radius_km=%.1f\n", lat2, lon2, gr2
            # planar intersection at the scale of the two subpoints, which is
            # honest for a pair of circles a few hundred km across
            dy = (lat2 - slat) * 111.32
            dx = (lon2 - slon) * 111.32 * cos(slat * deg)
            d = sqrt(dx*dx + dy*dy)
            if (d == 0) { printf "finding\tno_intersection\tINFO\tthe two satellite subpoints coincide, so the circles are concentric\n"; exit 0 }
            if (d > gr + gr2) { printf "finding\tno_intersection\tHIGH\tthe circles are %.0f km apart and their radii sum to %.0f km, so no point satisfies both\n", d, gr+gr2; exit 0 }
            if (d < (gr > gr2 ? gr - gr2 : gr2 - gr)) { printf "finding\tno_intersection\tHIGH\tone circle sits inside the other, so no point satisfies both\n"; exit 0 }
            a = (gr*gr - gr2*gr2 + d*d) / (2*d)
            hh = sqrt(gr*gr - a*a)
            px = a*dx/d; py = a*dy/d
            ux = -dy/d; uy = dx/d
            for (k = -1; k <= 1; k += 2) {
                x = px + k*hh*ux; y = py + k*hh*uy
                la = slat + y/111.32
                lo = slon + x/(111.32*cos(slat*deg))
                printf "candidate\tlat=%.4f lon=%.4f\n", la, lo
            }
            printf "finding\ttrilaterated\tINFO\ttwo circles leave two candidate points; a third measurement or a sector test picks between them\n"
            printf "verdict\tposition_pinned_to_two_points\n"
        } else {
            printf "verdict\tposition_circle_only\n"
        }
        printf "ref\t3GPP TS 38.821 (NTN), TS 38.213 timing advance\n"
        printf "note\tthe planar intersection is an approximation for circles a few hundred kilometers across; a production fix would intersect on the ellipsoid\n"
    }'
}

ntn_geo_usage() {
    cat >&2 <<'EOF'
USAGE	--timing-geoloc (--ta N | --range-km KM) --sat-lat DEG --sat-lon DEG --sat-alt KM [--range2-km KM --sat2-lat DEG --sat2-lon DEG]
WHY	turns a timing-advance measurement into the circle of ground positions that could have produced it, and two measurements into the pair of points they meet at
EOF
}

ntn_ephemeris_hijack() {
    local true_km="" forged_km="" koffset="" kerr=0 scs=15 dur=60 cp=4.69
    while (( $# )); do
        case "$1" in
            --true-range)   true_km="${2:-}";  shift 2 || { ntn_eph_usage; return 2; } ;;
            --forged-range) forged_km="${2:-}"; shift 2 || { ntn_eph_usage; return 2; } ;;
            --koffset)      koffset="${2:-}";  shift 2 || { ntn_eph_usage; return 2; } ;;
            --koffset-error) kerr="${2:-}";    shift 2 || { ntn_eph_usage; return 2; } ;;
            --scs)          scs="${2:-}";      shift 2 || { ntn_eph_usage; return 2; } ;;
            --duration)     dur="${2:-}";      shift 2 || { ntn_eph_usage; return 2; } ;;
            --cp)           cp="${2:-}";       shift 2 || { ntn_eph_usage; return 2; } ;;
            *)              ntn_eph_usage; return 2 ;;
        esac
    done
    if [[ -z "$true_km" || -z "$forged_km" || -z "$koffset" ]]; then
        ntn_eph_usage; return 2
    fi
    local v
    for v in "$true_km" "$forged_km"; do
        [[ "$v" =~ ^[0-9]+([.][0-9]+)?$ ]] || { printf 'ERROR\tranges must be numbers of km\n' >&2; return 2; }
    done
    [[ "$koffset" =~ ^[0-9]+$ ]] || { printf 'ERROR\t--koffset wants a whole number of slots\n' >&2; return 2; }
    [[ "$kerr" =~ ^-?[0-9]+$ ]] || { printf 'ERROR\t--koffset-error wants whole slots\n' >&2; return 2; }
    case "$scs" in 15|30|60|120) ;; *) printf 'ERROR\t--scs wants 15, 30, 60 or 120 kHz\n' >&2; return 2; esac
    awk -v t="$true_km" -v f="$forged_km" -v k="$koffset" -v ke="$kerr" -v scs="$scs" \
        -v dur="$dur" -v cp="$cp" 'BEGIN{
        c = 299792458; unit = 16.0/30720000.0
        switch (scs) { case 15: mu=0; break; case 30: mu=1; break; case 60: mu=2; break; default: mu=3 }
        slot_ms = 1.0 / (2 ^ mu)          # TS 38.211: 1/(2^mu) ms per slot
        rtt_t = 2*t*1000.0/c; rtt_f = 2*f*1000.0/c
        ta_t = rtt_t/unit; ta_f = rtt_f/unit
        ta_err_us = (rtt_f - rtt_t)*1e6
        k_ms = k*slot_ms
        k_err_ms = ke*slot_ms
        printf "true_range_km\t%s\n", t
        printf "forged_range_km\t%s\n", f
        printf "true_rtt_ms\t%.3f\n", rtt_t*1000
        printf "forged_rtt_ms\t%.3f\n", rtt_f*1000
        printf "true_ta_units\t%.0f\n", ta_t
        printf "forged_ta_units\t%.0f\n", ta_f
        printf "ta_error_us\t%.1f\n", ta_err_us
        printf "ta_error_half_us\t%.1f\n", ta_err_us/2
        printf "cp_us\t%s\n", cp
        printf "koffset_slots\t%s\n", k
        printf "koffset_ms\t%.3f\n", k_ms
        printf "koffset_error_slots\t%s\n", ke
        printf "koffset_error_ms\t%.3f\n", k_err_ms
        printf "scs_khz\t%s\n", scs
        if ((ta_err_us < 0 ? -ta_err_us : ta_err_us) / 2 > cp)
            printf "finding\ttiming_beyond_cp\tHIGH\tthe UE uplink arrives %.1f us from where the gNB expects it, past the %s us cyclic prefix: symbols overlap\n", ta_err_us/2, cp
        else
            printf "finding\ttiming_within_cp\tINFO\tone-way error %.1f us stays inside the %s us prefix, so the forgery costs capacity but not the link\n", ta_err_us/2, cp
        if (ke != 0)
            printf "finding\tkoffset_mismatch\tHIGH\tthe UE schedules %.3f ms away from the slot the network counts, so a grant lands in the wrong slot\n", k_err_ms
        printf "finding\tephemeris_is_a_number\tMEDIUM\tnothing in the broadcast binds the ephemeris to the satellite: a forged position is only detectable against a second source (GNSS, another cell, an operator orbit table)\n"
        # how long the forged ephemeris holds a plausible range while the sky
        # moves: a geostationary pass is static, LEO moves ~7.5 km/s of range
        drift_ms_per_s = 2*7500.0/c*1000.0
        printf "range_drift_ms_per_s\t%.3f\n", drift_ms_per_s
        printf "sync_window_s\t%s\n", dur
        printf "verdict\tephemeris_hostile\n"
        printf "ref\t3GPP TS 38.331 NTN-Config-r17 / SIB19, TS 38.213 K_offset, TS 38.211 slot timing\n"
        printf "note\tthe UE can only check the numbers against what it measures: TA against its own timing, ephemeris against GNSS or an operator table, K_offset against the grants it actually receives\n"
    }'
}

ntn_eph_usage() {
    cat >&2 <<'EOF'
USAGE	--ephemeris-hijack --true-range KM --forged-range KM --koffset N [--koffset-error N] [--scs kHz] [--duration s] [--cp us]
WHY	takes the range the satellite really is at and the range a forged SIB19 claims, and works out the timing the UE would use
EOF
}

# ── R66: SIB19 as it is actually carried, not as a standalone box ────────
# The layout row said there was no NR RRC table in the tree; there is one now
# (tools/nr_rrc_layout.py, generated from pycrate and grown with the codec), and
# --sib19-build uses it. What that verb builds is the information element on its
# own, which is the wrong shape for the air: SIB19-r17 never arrives by itself.
# It arrives inside SystemInformation on BCCH-DL-SCH, as one alternative of
# sib-TypeAndInfo, and the SIB1 of the cell says which si-Message carries it.
# This verb builds the whole envelope, encodes it, and decodes it back, so the
# extra layer is exercised rather than described.
#
# The alternative is named sib19-v1700 in the CHOICE, not sib19: the plain
# sib19 name is not in the table's sib-TypeAndInfo, and a name the table does
# not have is refused by name instead of being guessed at.
ntn_sib19_carrier() {
    local koffset=20 epoch_sfn=3 epoch_sub=5 validity=s30 ref_hex="" dist=""
    local period=rf64 window=5 maptype="sibType19"
    while (( $# )); do
        case "$1" in
            --koffset)   koffset="${2:-}";   shift 2 || { ntn_sib19_carrier_usage; return 2; } ;;
            --epoch-sfn) epoch_sfn="${2:-}";  shift 2 || { ntn_sib19_carrier_usage; return 2; } ;;
            --epoch-sub) epoch_sub="${2:-}";  shift 2 || { ntn_sib19_carrier_usage; return 2; } ;;
            --validity)  validity="${2:-}";   shift 2 || { ntn_sib19_carrier_usage; return 2; } ;;
            --ref-hex)   ref_hex="${2:-}";    shift 2 || { ntn_sib19_carrier_usage; return 2; } ;;
            --dist)      dist="${2:-}";       shift 2 || { ntn_sib19_carrier_usage; return 2; } ;;
            --period)    period="${2:-}";     shift 2 || { ntn_sib19_carrier_usage; return 2; } ;;
            --window)    window="${2:-}";     shift 2 || { ntn_sib19_carrier_usage; return 2; } ;;
            *)           ntn_sib19_carrier_usage; return 2 ;;
        esac
    done
    [[ "$koffset" =~ ^[0-9]+$ && "$koffset" -ge 1 && "$koffset" -le 1023 ]] || {
        printf 'ERROR\t--koffset wants 1..1023 (TS 38.331 NTN-Config)\n' >&2; return 2; }
    [[ "$epoch_sfn" =~ ^[0-9]+$ ]] || { printf 'ERROR\t--epoch-sfn wants whole SFNs\n' >&2; return 2; }
    [[ "$epoch_sub" =~ ^[0-9]+$ ]] || { printf 'ERROR\t--epoch-sub wants whole slots\n' >&2; return 2; }
    case "$period" in rf8|rf16|rf32|rf64|rf128|rf256|rf512) ;; *)
        printf 'ERROR\t--period is one of rf8 rf16 rf32 rf64 rf128 rf256 rf512\n' >&2; return 2 ;; esac
    [[ "$window" =~ ^[0-9]+$ ]] || { printf 'ERROR\t--window is a slot count\n' >&2; return 2; }
    [[ -z "$ref_hex" || "$ref_hex" =~ ^[0-9A-Fa-f]+$ ]] || {
        printf 'ERROR\t--ref-hex wants hex digits\n' >&2; return 2; }
    [[ -z "$dist" || "$dist" =~ ^[0-9]+$ ]] || {
        printf 'ERROR\t--dist wants whole metres\n' >&2; return 2; }

    local root="${IMSISTING_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)}"
    if [[ ! -r "$root/tools/nr_rrc.py" || ! -r "$root/tools/nr_rrc_layout.py" ]]; then
        printf 'ERROR\tthe carrier cannot be built: tools/nr_rrc_layout.py is missing\n' >&2
        printf 'WHY\tSystemInformation is a generated table type; without the table there is nothing to encode against\n' >&2
        return 2
    fi
    local work json out rc=0
    work=$(mktemp -d)
    json="$work/si.json"
    {
        printf '{"criticalExtensions":{"$choice":["systemInformation",{"sib-TypeAndInfo":[{'
        printf '"$choice":["sib19-v1700",{"ntn-Config-r17":{'
        printf '"cellSpecificKoffset-r17":%s,' "$koffset"
        printf '"epochTime-r17":{"sfn-r17":%s,"subFrameNR-r17":%s},' "$epoch_sfn" "$epoch_sub"
        printf '"ntn-UlSyncValidityDuration-r17":"%s"' "$validity"
        printf '}'
        if [[ -n "$ref_hex" ]]; then printf ',"referenceLocation-r17":{"$hex":"%s"}' "$ref_hex"; fi
        if [[ -n "$dist" ]]; then printf ',"distanceThresh-r17":%s' "$dist"; fi
        printf '}]}]}]}}'
    } > "$json"
    out=$(python3 "$root/tools/nr_rrc.py" encode SystemInformation "$json" 2>&1) || rc=$?
    if (( rc != 0 )); then
        rm -rf "$work"
        printf '%s\n' "$out" >&2
        printf 'WHY\tthe envelope is only accepted when its own decoder gives the value back; a field name the table does not have is dropped rather than guessed\n' >&2
        return "$rc"
    fi
    local bits hex got
    bits=$(printf '%s\n' "$out" | awk -F'\t' '$1=="bits"{print $2}')
    hex=$(printf '%s\n' "$out" | awk -F'\t' '$1=="hex"{print $2}')
    got=$(printf '%s\n' "$out" | awk -F'\t' '$1=="read_back"{print $2}')
    printf 'role\tSystemInformation (BCCH-DL-SCH) carrying SIB19\n'
    printf 'rrc_type\tSystemInformation\n'
    printf 'sib_alternative\tsib19-v1700\n'
    printf 'sib_wrapper\tcriticalExtensions > systemInformation > sib-TypeAndInfo[0]\n'
    printf 'bits\t%s\n' "$bits"
    printf 'hex\t%s\n' "$hex"
    printf 'read_back\t%s\n' "${got:-no}"
    printf 'koffset\t%s\n' "$koffset"
    printf 'epoch_sfn\t%s\n' "$epoch_sfn"
    printf 'epoch_subframe\t%s\n' "$epoch_sub"
    printf 'validity\t%s\n' "$validity"
    [[ -n "$ref_hex" ]] && printf 'reference_location\t0x%s\n' "$(printf '%s' "$ref_hex" | tr 'a-f' 'A-F')"
    [[ -n "$dist" ]] && printf 'distance_thresh_m\t%s\n' "$dist"
    printf 'scheduled_as\tsi-Message carrying %s\n' "$maptype"
    printf 'si_periodicity\t%s\n' "$period"
    printf 'si_window_slots\t%s\n' "$window"
    printf 'sib1_points_here\tSIB1 si-SchedulingInfo lists %s in sib-MappingInfo, with the si-Periodicity %s and si-WindowLength above; the SI window is where the UE reads this block\n' "$maptype" "$period"
    printf 'ref\tTS 38.331 5.2.2.1 (SI acquisition, BCCH-DL-SCH), 6.2.1 SystemInformation / SystemInformation-IEs / sib-TypeAndInfo, 6.3.1 SIB19-r17\n'
    printf 'limit\tthis is the ASN.1 envelope, not a transport block: SIB19 rides in an DL-SCH TB scheduled by a DCI inside a SI window, and the DCI, the window timing and the cell SIB1 are outside what this module builds\n'
    rm -rf "$work"
    return 0
}

ntn_sib19_carrier_usage() {
    cat >&2 <<'EOF'
USAGE	--sib19-carrier [--koffset N] [--epoch-sfn N] [--epoch-sub N] [--validity sN] [--ref-hex HEX] [--dist M] [--period rfN] [--window SLOTS]
EOF
    return 2
}


ntn_sib19_build() {
    local koffset=15 epoch_sfn=0 epoch_sub=0 validity=s20 kmac=1 ref_hex="" dist=""
    while (( $# )); do
        case "$1" in
            --koffset)   koffset="${2:-}";  shift 2 || { ntn_sib19_build_usage; return 2; } ;;
            --epoch-sfn) epoch_sfn="${2:-}"; shift 2 || { ntn_sib19_build_usage; return 2; } ;;
            --epoch-sub) epoch_sub="${2:-}"; shift 2 || { ntn_sib19_build_usage; return 2; } ;;
            --validity)  validity="${2:-}";  shift 2 || { ntn_sib19_build_usage; return 2; } ;;
            --kmac)      kmac="${2:-}";      shift 2 || { ntn_sib19_build_usage; return 2; } ;;
            --ref-hex)   ref_hex="${2:-}";   shift 2 || { ntn_sib19_build_usage; return 2; } ;;
            --dist)      dist="${2:-}";      shift 2 || { ntn_sib19_build_usage; return 2; } ;;
            *)           ntn_sib19_build_usage; return 2 ;;
        esac
    done
    [[ "$koffset" =~ ^[0-9]+$ && "$koffset" -ge 1 && "$koffset" -le 1023 ]] || {
        printf 'ERROR\t--koffset wants 1..1023 (TS 38.331 NTN-Config)\n' >&2; return 2; }
    [[ "$epoch_sfn" =~ ^[0-9]+$ && "$epoch_sfn" -le 1023 ]] || {
        printf 'ERROR\t--epoch-sfn wants 0..1023\n' >&2; return 2; }
    [[ "$epoch_sub" =~ ^[0-9]+$ ]] || { printf 'ERROR\t--epoch-sub wants whole slots\n' >&2; return 2; }
    [[ "$kmac" =~ ^[0-9]+$ && "$kmac" -ge 1 && "$kmac" -le 512 ]] || {
        printf 'ERROR\t--kmac wants 1..512\n' >&2; return 2; }
    if [[ -n "$ref_hex" && ! "$ref_hex" =~ ^[0-9A-Fa-f]+$ ]]; then
        printf 'ERROR\t--ref-hex wants hex digits\n' >&2; return 2
    fi
    if [[ -n "$dist" && ! "$dist" =~ ^[0-9]+$ ]]; then
        printf 'ERROR\t--dist wants whole metres\n' >&2; return 2
    fi
    local root="${IMSISTING_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)}"
    if [[ ! -r "$root/tools/nr_rrc.py" || ! -r "$root/tools/nr_rrc_layout.py" ]]; then
        printf 'ERROR\tSIB19 cannot be built: tools/nr_rrc_layout.py is missing\n' >&2
        printf 'WHY\tThe encoder is tools/nr_rrc.py over the generated table; regenerate and re-certify it as the decode path says\n' >&2
        return 2
    fi
    local work; work=$(mktemp -d)
    local json="$work/sib19.json"
    {
        printf '{"ntn-Config-r17":{"epochTime-r17":{"sfn-r17":%s,"subFrameNR-r17":%s},' "$epoch_sfn" "$epoch_sub"
        printf '"ntn-UlSyncValidityDuration-r17":"%s","cellSpecificKoffset-r17":%s,"kmac-r17":%s}' "$validity" "$koffset" "$kmac"
        if [[ -n "$ref_hex" ]]; then printf ',"referenceLocation-r17":{"$hex":"%s"}' "$ref_hex"; fi
        if [[ -n "$dist" ]]; then printf ',"distanceThresh-r17":%s' "$dist"; fi
        printf '}'
    } > "$json"
    local out rc=0
    out=$(python3 "$root/tools/nr_rrc.py" encode SIB19_r17 "$json" 2>&1) || rc=$?
    rm -rf "$work"
    if (( rc != 0 )); then
        printf '%s\n' "$out" >&2
        return "$rc"
    fi
    printf 'role\tSIB19_r17\n'
    printf '%s\n' "$out" | grep -v '^family'
    printf 'koffset\t%s\n' "$koffset"
    printf 'epoch_sfn\t%s\n' "$epoch_sfn"
    printf 'epoch_subframe\t%s\n' "$epoch_sub"
    printf 'validity\t%s\n' "$validity"
    [[ -n "$ref_hex" ]] && printf 'reference_location\t0x%s\n' "$(printf '%s' "$ref_hex" | tr 'a-f' 'A-F')"
    [[ -n "$dist" ]] && printf 'distance_thresh_m\t%s\n' "$dist"
    printf 'note\tthis is the information element a cell broadcasts; nothing here transmits it, and a receiver only acts on it if the cell it came from passed the checks it cannot forge\n'
    printf 'ref\t3GPP TS 38.331 SIB19-r17 / NTN-Config-r17\n'
    return 0
}

ntn_sib19_build_usage() {
    cat >&2 <<'EOF'
USAGE	--sib19-build [--koffset N] [--epoch-sfn N] [--epoch-sub N] [--validity sN] [--kmac N] [--ref-hex HEX] [--dist M]
WHY	builds the SIB19-r17 information element and encodes it through the same unaligned-PER table the --sib19 decoder reads
EOF
}

ntn_sib19() {
    local hex="${1:-}"
    local root="${IMSISTING_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)}"
    if [[ ! -r "$root/tools/nr_rrc.py" || ! -r "$root/tools/nr_rrc_layout.py" ]]; then
        printf 'ERROR\tSIB19 cannot be decoded: tools/nr_rrc_layout.py is missing\n' >&2
        printf 'WHY\tThe decoder is tools/nr_rrc.py over the generated table tools/nr_rrc_layout.py. Regenerate it with tools/asn1gen.py --family nr and re-certify it with tools/lte-per-oracle/verify_per.py --table tools/nr_rrc_layout.py; a decoder without its table prints fields it invented.\n' >&2
        return 2
    fi
    if [[ -z "$hex" ]]; then
        printf 'ERROR\tsib19 needs a message as hex\n' >&2
        printf 'WHY\tSIB19 is a TS 38.331 IE carried on BCCH-DL-SCH, and this module reads it from bits you supply: the message is decoded, the transport block it arrived in is not.\n' >&2
        printf 'USAGE\t--sib19 <hex>\n' >&2
        return 2
    fi
    python3 "$root/tools/nr_rrc.py" decode SIB19_r17 "$hex" || return 1
}

# ── feeder link: not computed ───────────────────────────────────────────
# SIB19 carries no feeder gateway position, so the gateway-satellite geometry
# is not derivable from anything this module reads. What the old table called
# "exposure" was a topology sketch, not a measurement or a computed quantity.
ntn_feeder_link() {
    printf 'ERROR\tfeeder link is not computed: SIB19 carries no gateway geometry\n' >&2
    printf 'WHY\tSIB19 provides TA, K_offset, ephemeris and the cell reference location for the service link; the feeder (gateway-satellite) distance needs the gateway position, which is not signalled and not supplied here. A topology table is not an analysis, so this module prints none.\n' >&2
    return 2
}

# ── F4: listening for a satellite cell ──────────────────────────────────
# A satellite cell is an ordinary NR cell with a round trip that no terrestrial
# timing budget assumed, so the receiver half is a tuning problem plus a
# signature: a cell that broadcasts SIB19, whose timing moves with the sky, and
# whose round trip is milliseconds rather than microseconds.
# ── F6: reselection between a terrestrial cell and a satellite one ──────
# A UE picks between the two cells the same way it picks between any two:
# the S criterion, the cell-ranking criterion and the reselection timers. NTN
# adds a distance gate (the UE must be inside the cell's distanceThresh of its
# reference location, TS 38.304 5.2.4.6) and a validity timer that expires the
# SIB19 information. This works out which way the UE goes, and what has to move
# to make it go the other way.
ntn_reselect() {
    local ter="" sat="" dist="" hyst="" validity="" barring="" t_resel="" qrxlevmin=""
    while (( $# )); do
        case "$1" in
            --terrestrial-rsrp) ter="${2:-}";    shift 2 || { ntn_resel_usage; return 2; } ;;
            --satellite-rsrp)   sat="${2:-}";    shift 2 || { ntn_resel_usage; return 2; } ;;
            --distance-km)      dist="${2:-}";   shift 2 || { ntn_resel_usage; return 2; } ;;
            --hysteresis-db)    hyst="${2:-}";   shift 2 || { ntn_resel_usage; return 2; } ;;
            --validity-s)       validity="${2:-}"; shift 2 || { ntn_resel_usage; return 2; } ;;
            --barred)           barring=1;        shift ;;
            --q-rxlevmin)       qrxlevmin="${2:-}"; shift 2 || { ntn_resel_usage; return 2; } ;;
            *)                  ntn_resel_usage; return 2 ;;
        esac
    done
    if [[ -z "$ter" || -z "$sat" ]]; then ntn_resel_usage; return 2; fi
    for v in "$ter" "$sat" "$dist" "$hyst" "$validity" "$qrxlevmin"; do
        if [[ -n "$v" && ! "$v" =~ ^-?[0-9]+([.][0-9]+)?$ ]]; then
            printf 'ERROR\t%s wants a number\n' "$v" >&2; return 2
        fi
    done
    awk -v ter="$ter" -v sat="$sat" -v dist="$dist" -v hyst="${hyst:-2}" \
        -v validity="$validity" -v barred="$barring" -v qmin="${qrxlevmin:--140}" 'BEGIN{
        printf "input\tterrestrial_rsrp\t%s\n", ter
        printf "input\tsatellite_rsrp\t%s\n", sat
        if (dist != "") printf "input\tdistance_km\t%s\n", dist
        # the S criterion in its simplest usable form: the measured RSRP has to
        # clear Qrxlevmin by the power offsets, and the hysteresis keeps a cell
        # that is only marginally better from being reselected onto
        printf "criterion\tS_terrestrial\t%s\n", (ter + 0 >= qmin + 0) ? "pass" : "fail"
        printf "criterion\tS_satellite\t%s\n", (sat + 0 >= qmin + 0) ? "pass" : "fail"
        gap = (sat + 0) - (ter + 0)
        printf "margin_db\t%.1f\n", gap
        if (barred == 1) printf "criterion\tterrestrial_barred\tbarred\n"
        if (dist != "" && dist + 0 > 0) {
            printf "gate\tdistance_thresh\tnot supplied, so the distance gate is assumed to pass\n"
        }
        if (validity != "") {
            printf "gate\tvalidity_s\t%s\n", validity
            printf "gate\tvalidity_expiry\tno expiry while the SIB19 repeats inside the window\n"
        }
        verdict = "stays_terrestrial"
        if (barred == 1) verdict = "reselection_to_satellite_when_S_passes"
        else if (gap > hyst + 0) verdict = "reselection_to_satellite"
        else if (gap < -1 * (hyst + 0)) verdict = "stays_terrestrial"
        else verdict = "marginal_inside_hysteresis"
        printf "verdict\t%s\n", verdict
        if (verdict == "reselection_to_satellite") {
            printf "finding\tranking_decides\tINFO\tthe satellite cell ranks above the terrestrial one by %.1f dB, more than the %.1f dB of hysteresis, so the reselection is the UE doing what it was told\n", gap, hyst
        }
        printf "finding\tthree_levers\tMEDIUM\twhat moves the UE toward satellite is the barring, the Qrxlevmin or the measured power of the terrestrial cell: a fake SIB1 that bars it, a lowered RSRP from its direction, or a policy that prefers NTN\n"
        printf "finding\toperator_selectable\tINFO\tNTN preference is also a UE policy and a network decision, so a diversion can be requested rather than forced\n"
        printf "ref\t3GPP TS 38.304 5.2.4 (cell selection and reselection), TS 38.331 SIB19 distanceThresh and t-Service\n"
        printf "limit\tthis compares RSRP and the hysteresis; the real criteria also weigh Srxlev offsets, the NTN distance gate and the validity timer, which need fields this module is not given\n"
    }'
}

ntn_resel_usage() {
    cat >&2 <<'EOF'
USAGE	--ntn-reselect --terrestrial-rsrp DBM --satellite-rsrp DBM [--distance-km KM] [--hysteresis-db DB] [--validity-s S] [--barred] [--q-rxlevmin DBM]
WHY	works out which cell the UE reselects to, and which lever moves it the other way
EOF
}

ntn_scan_plan() {
    cat <<'EOF'
status	plan
what	listen for an NTN cell's downlink and tell it apart from a terrestrial one
hardware	an SDR that covers the band (n255 DL 1525-1559 MHz, n256 DL 2170-2200 MHz) with a pass to receive, or an NTN-capable UE with the satellite profile enabled
software	a receiver that decodes NR downlink: srsRAN Project with an NR-NTN build, or a spectrum recorder plus an offline decoder; the SIB19 this module decodes (--sib19) is the payload to look for
step	tune	the band in the table above; a satellite downlink is a normal NR carrier with a wide beam, so a 20 MHz capture at the right centre frequency is enough to find it
step	find	the SSB and read the cell's MIB; a satellite cell's MIB is unremarkable, so the discriminator is what comes after it
step	decode	read SIB1, then SIB19 if the cell broadcasts it; SIB19 is what makes the cell NTN and this module's --sib19 reads it once you have the bits
step	measure	the round trip: a terrestrial cell is under about 0.15 ms, an NTN cell is 2-40 ms one way, so the timing advance the network commands is the first give-away
step	watch	the timing advance and Doppler over a pass: a satellite's Doppler sweeps through zero as it passes overhead, which no terrestrial cell does
step	confirm	the ephemeris in SIB19 against a published orbit: a cell claiming a satellite that is not overhead is a fake, and that is the F5 question
signal	ta_extended	a timing advance beyond the LTE range (1282 units) or a K_offset above 1 ms is an NTN-sized delay
signal	sib19	the cell broadcasts SIB19, which a terrestrial cell has no reason to send
signal	doppler_sweep	a carrier frequency offset that changes sign over minutes, consistent with a pass
signal	rtt_jitter	a round trip that drifts smoothly rather than sitting at a constant value
finding	ntn_signals_are_three	INFO	no single field says NTN: the round trip, the SIB19 presence and the Doppler sweep together do, and a cell that fakes one usually misses the others
verdict	receive_plan_only
limit	the capture and the decode happen outside this module; it gives the tuning, the signature and the interpretation, not a receiver
note	receiving a satellite downlink in a band you are authorised to receive is passive; decoding an operator's signalling beyond what a normal UE does is covered by the local rules on radio interception
EOF
}

# ── F5: broadcasting a fake satellite cell ──────────────────────────────
# The transmit half is harder than the terrestrial fake cell for three reasons:
# the band, the delay, and the orbit the UE can check.
ntn_fakecell_plan() {
    cat <<'EOF'
status	plan
what	broadcast downlink that presents itself as an NTN cell
hardware	an SDR with a PA on the NTN downlink band (n255 DL 1525-1559 MHz or n256 DL 2170-2200 MHz); transmitting there is licensed to the operator
software	an NR gNB that can be told its own delay profile (srsRAN Project with NTN support), and this module's --sib19-build for the SIB19 the cell must broadcast
need_band	a carrier in the NTN band: a UE only scans bands its profile lists, so the fake cell is invisible to a phone that is not NTN-enabled
need_sib19	SIB19 with a plausible ephemeris, a K_offset sized for the delay, and a reference location; without SIB19 the cell is not NTN to the UE
need_delay	the gNB must run with the propagation delay it claims: a fake NTN cell that answers at terrestrial speed is rejected by timing checks, and this module's --ephemeris-hijack works out how far a wrong number puts the UE
need_uplink	if the session goes beyond broadcast and the UE tries to attach, the uplink has to be received and relayed, which is the duplex the terrestrial fake cell only needs once
step	build	--sib19-build --koffset N --validity sN with a reference location and distance threshold that match the claimed orbit
step	run	bring up the gNB with the delay profile, then let the UE find the cell; watch the timing advance the UE reports back, which should sit where the delay predicts
step	observe	what a UE does with a fake NTN cell is the interesting part: it holds the timing for the validity window and then declares out of sync
finding	three_locks	HIGH	band, SIB19 and delay are three independent locks and a real NTN pass opens all three at once
finding	orbit_checkable	MEDIUM	the ephemeris is checkable against public orbit data and against GNSS, so the fake cell needs a satellite that is genuinely overhead or a UE that does not check
finding	uplink_needed_late	INFO	broadcast needs only the downlink; anything past that needs the duplex the terrestrial fake cell also needs
verdict	transmit_plan_only
limit	the transmitter and the delay-capable gNB are outside this module; --sib19-build gives the payload and --ephemeris-hijack gives the consequence of the numbers
note	transmitting on an NTN band is licensed to that operator; a fake cell on those frequencies is both a radio offence and an interference problem
EOF
}

ntn_plan() {
    cat <<'EOF'
status	handoff
what	operating or observing an NTN cell
hardware	an NTN-capable UE, or an SDR with a satellite pass to receive (a LEO beacon on the feeder/service downlink)
software	computed here: --doppler, --range, --ta and --koffset; SIB19 is decoded and built through the generated NR table (--sib19, --sib19-build); refused here: --feeder (no gateway geometry)
flow	1. --doppler and --range for the pass geometry  2. --ta and --koffset for the timing budget  3. --sib19-build to forge what a satellite cell would broadcast, --sib19 to read one back
note	transmitting into a satellite link needs that operator's authorisation; this module computes on geometry you supply
EOF
}

ntn_selftest() {
    local bad=0 nchk=0
    chk() {
        nchk=$(( nchk + 1 ))
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$(( bad + 1 )); fi
    }
    fld() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }

    local d
    d=$(mktemp -d "$MOD_TMP/selftest.XXXXXX") || {
        printf 'ERROR\tmktemp failed under %s\n' "$MOD_TMP" >&2; return 1; }
    trap 'rm -rf "$d"' EXIT
    export LOOT_DIR="$d/loot" CAPTURES_DIR="$d/captures" STATE_DIR="$d/state"
    export NTN_DIR="$d/loot/ntn"
    mkdir -p "$NTN_DIR"

    # 1. Doppler: 2 GHz carrier, 7500 m/s closing, 0 deg -> 50.03 kHz.
    chk dop-fd    "$(fld "$(ntn_doppler 2000000000 7500 0)" doppler_hz)" "50034.6"
    chk dop-zero  "$(fld "$(ntn_doppler 2000000000 7500 90)" doppler_hz)" "0.0"
    chk dop-neg   "$(fld "$(ntn_doppler 2000000000 7500 180)" doppler_hz)" "-50034.6"
    chk dop-bad   "$(ntn_doppler x 1 0 >/dev/null 2>&1; echo $?)" "2"

    # 2. Round-trip delay: GEO ~238.7 ms, LEO 600 km ~4.00 ms.
    chk rtt-geo "$(fld "$(ntn_range_rtt 35786)" rtt_ms)" "238.738"
    chk rtt-leo "$(fld "$(ntn_range_rtt 600)" rtt_ms)" "4.003"
    chk rtt-bad "$(ntn_range_rtt x >/dev/null 2>&1; echo $?)" "2"

    # 3. TA units: LEO 600 km needs ~7685 LTE TA units, far past the 1282 cap.
    chk ta-leo "$(fld "$(ntn_ta_units 600)" ta_units)" "7685"
    chk ta-over "$(fld "$(ntn_ta_units 600)" note)" "exceeds the LTE TA command range — NTN needs the extended offset in SIB19"
    chk ta-unit "$(fld "$(ntn_ta_units 600)" lte_ta_max)" "1282"
    # a terrestrial-range distance stays inside the range, so the branch is real.
    chk ta-short "$(fld "$(ntn_ta_units 1)" note)" "within the LTE TA command range"

    # 4. K_offset. The unit is 15 kHz reference slots (TS 38.331 V18.3.0
    #    NTN-Config field description), and one such slot is 1 ms (TS 38.211
    #    Table 4.3.2-1: at mu=0 there is 1 slot per 1 ms subframe). So
    #    K_offset=1 is 1.000 ms and K_offset=239 is 239.000 ms; at 30.72 MS/s
    #    239 ms is 7,342,080 samples. The carrier SCS does not change the
    #    delay, it changes the slot count: TS 38.213 V18.4.0 clause 9 has the
    #    UE add 2^(mu-mu_Koffset)*K_offset slots of the active UL BWP with
    #    mu_Koffset = 0 in FR1 and FR2-NTN, so SCS 30/60/120 kHz turns 239
    #    reference slots into 478/956/1912 carrier slots of 0.5/0.25/0.125 ms.
    chk koffset-one   "$(fld "$(ntn_koffset 1)" delay_ms)"                 "1.000"
    chk koffset-slot  "$(fld "$(ntn_koffset 1)" slot_ms_used)"             "1.000"
    chk koffset-unit  "$(fld "$(ntn_koffset 1)" k_offset_unit)"            "slots at 15 kHz reference (TS 38.331 NTN-Config)"
    chk koffset-geo   "$(fld "$(ntn_koffset 239)" delay_ms)"               "239.000"
    chk koffset-samp  "$(fld "$(ntn_koffset 239 15 30720000)" delay_samples)" "7342080"
    chk koffset-a30   "$(fld "$(ntn_koffset 239 30)" applied_slots)"       "478"
    chk koffset-a60   "$(fld "$(ntn_koffset 239 60)" applied_slots)"       "956"
    chk koffset-a120  "$(fld "$(ntn_koffset 239 120)" applied_slots)"      "1912"
    chk koffset-cslot "$(fld "$(ntn_koffset 239 30)" carrier_slot_ms)"     "0.500"
    chk koffset-c120  "$(fld "$(ntn_koffset 239 120)" carrier_slot_ms)"    "0.125"
    chk koffset-a30ms "$(fld "$(ntn_koffset 239 30)" applied_ms)"          "239.000"
    chk koffset-120ms "$(fld "$(ntn_koffset 239 120)" delay_ms)"           "239.000"
    chk koffset-zero  "$(ntn_koffset 0 >/dev/null 2>&1; echo $?)"          "2"
    chk koffset-max   "$(ntn_koffset 1024 >/dev/null 2>&1; echo $?)"       "2"
    chk koffset-dec   "$(ntn_koffset 12.5 >/dev/null 2>&1; echo $?)"       "2"
    chk koffset-scs   "$(ntn_koffset 1 7 >/dev/null 2>&1; echo $?)"        "2"
    chk koffset-rate  "$(ntn_koffset 1 15 0 >/dev/null 2>&1; echo $?)"     "2"

    # 5. SIB19 decodes through the generated NR table; the feeder link is still
    #    refused, because SIB19 carries no gateway geometry for it to use.
    chk sib19-nobits  "$(ntn_sib19 >/dev/null 2>&1; echo $?)"              "2"
    chk sib19-why     "$(ntn_sib19 2>&1 >/dev/null | grep -c '^WHY')"      "1"
    # A vector whose answer is known by construction: pycrate encodes a SIB19
    # carrying t-Service-r17 = 4294967296 as 46 bits, padded to 200400000000.
    chk sib19-tsvc    "$(ntn_sib19 200400000000 2>/dev/null | awk -F'\t' '$1=="t-Service-r17"{print $2}')" "4294967296"
    chk sib19-bits    "$(ntn_sib19 200400000000 2>/dev/null | awk -F'\t' '$1=="bits_read"{print $2}')"      "46"
    # An all-absent SIB19 is legal (every component is OPTIONAL, 7 bits), so
    # the refusal case has to be a bit string that is not hex at all.
    chk sib19-badhex  "$(ntn_sib19 zz >/dev/null 2>&1; echo $?)"           "1"
    chk feeder-refuse "$(ntn_feeder_link >/dev/null 2>&1; echo $?)"        "2"

    # 9. SIB19 build: the element encodes, and its own decoder reads it back.
    local b19; b19=$(ntn_sib19_build --koffset 20 --epoch-sfn 3 --epoch-sub 5 --validity s30 --kmac 2 --ref-hex AABBCC --dist 1000)
    chk sib19-build-rc "$?" "0"
    chk sib19-build-bits "$(printf '%s\n' "$b19" | awk -F'\t' '$1=="bits"{print $2}')" "102"
    chk sib19-build-readback "$(printf '%s\n' "$b19" | awk -F'\t' '$1=="read_back"{print $2}')" "yes"
    chk sib19-build-koffset "$(printf '%s\n' "$b19" | awk -F'\t' '$1=="koffset"{print $2}')" "20"
    chk sib19-build-ref "$(printf '%s\n' "$b19" | awk -F'\t' '$1=="reference_location"{print $2}')" "0xAABBCC"
    local hx; hx=$(printf '%s\n' "$b19" | awk -F'\t' '$1=="hex"{print $2}')
    chk sib19-decode-koffset "$(ntn_sib19 "$hx" | awk -F'\t' '$1=="ntn-Config-r17.cellSpecificKoffset-r17"{print $2}')" "20"
    chk sib19-decode-validity "$(ntn_sib19 "$hx" | awk -F'\t' '$1 ~ /ntn-UlSyncValidityDuration/{print $2}')" "s30"
    chk sib19-bad-koffset "$(ntn_sib19_build --koffset 5000 >/dev/null 2>&1; echo $?)" "2"
    chk sib19-bad-kmac "$(ntn_sib19_build --kmac 0 >/dev/null 2>&1; echo $?)" "2"
    chk sib19-bad-flag "$(ntn_sib19_build --nonsense >/dev/null 2>&1; echo $?)" "2"
    # The carrier: SIB19 never arrives alone, so the envelope is built too and
    # its own decoder has to give the value back.
    local car; car=$(ntn_sib19_carrier --ref-hex AABBCC)
    chk carrier-rc "$?" "0"
    chk carrier-bits "$(printf '%s\n' "$car" | awk -F'\t' '$1=="bits"{print $2}')" "104"
    chk carrier-readback "$(printf '%s\n' "$car" | awk -F'\t' '$1=="read_back"{print $2}')" "yes"
    chk carrier-alt "$(printf '%s\n' "$car" | awk -F'\t' '$1=="sib_alternative"{print $2}')" "sib19-v1700"
    chk carrier-wrapper "$(printf '%s\n' "$car" | awk -F'\t' '$1=="sib_wrapper" && $2 ~ /sib-TypeAndInfo/{print "nested"}')" "nested"
    chk carrier-scheduled "$(printf '%s\n' "$car" | awk -F'\t' '$1=="scheduled_as" && $2 ~ /sibType19/{print "named"}')" "named"
    chk carrier-period "$(printf '%s\n' "$car" | awk -F'\t' '$1=="si_periodicity"{print $2}')" "rf64"
    chk carrier-bad-period "$(ntn_sib19_carrier --period rf7 >/dev/null 2>&1; echo $?)" "2"
    chk carrier-bad-koffset "$(ntn_sib19_carrier --koffset 0 >/dev/null 2>&1; echo $?)" "2"
    # and the envelope decodes back to the same SIB19 fields
    local chx; chx=$(printf '%s\n' "$car" | awk -F'\t' '$1=="hex"{print $2}')
    chk carrier-decode-koffset "$(python3 "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)/tools/nr_rrc.py" decode SystemInformation "$chx" 2>/dev/null | awk -F'\t' '$1 ~ /cellSpecificKoffset/{print $2}')" "20"
    chk carrier-decode-sib "$(python3 "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)/tools/nr_rrc.py" decode SystemInformation "$chx" 2>/dev/null | awk -F'\t' '$1 ~ /^criticalExtensions[.]systemInformation[.]sib-TypeAndInfo\[0\][.]sib19-v1700/ {f=1} END{print f+0}')" "1"
    # 10. Hostile ephemeris: the timing a forged SIB19 leaves the UE with.
    local eh; eh=$(ntn_ephemeris_hijack --true-range 1200 --forged-range 600 --koffset 20 --koffset-error 3 --scs 30)
    chk eph-ta-err "$(printf '%s\n' "$eh" | awk -F'\t' '$1=="ta_error_us"{print $2}')" "-4002.8"
    chk eph-half "$(printf '%s\n' "$eh" | awk -F'\t' '$1=="ta_error_half_us"{print $2}')" "-2001.4"
    chk eph-cp-finding "$(printf '%s\n' "$eh" | awk -F'\t' '$1=="finding" && $2=="timing_beyond_cp"{print $3}')" "HIGH"
    chk eph-koffset-ms "$(printf '%s\n' "$eh" | awk -F'\t' '$1=="koffset_error_ms"{print $2}')" "1.500"
    chk eph-k-finding "$(printf '%s\n' "$eh" | awk -F'\t' '$1=="finding" && $2=="koffset_mismatch"{print $3}')" "HIGH"
    chk eph-verdict "$(printf '%s\n' "$eh" | awk -F'\t' '$1=="verdict"{print $2}')" "ephemeris_hostile"
    chk eph-within-cp "$(ntn_ephemeris_hijack --true-range 1200 --forged-range 1199.9 --koffset 20 | awk -F'\t' '$1=="finding" && $2=="timing_within_cp"{print $3}')" "INFO"
    chk eph-noargs "$(ntn_ephemeris_hijack --true-range 1200 >/dev/null 2>&1; echo $?)" "2"
    chk eph-bad-scs "$(ntn_ephemeris_hijack --true-range 1 --forged-range 2 --koffset 20 --scs 45 >/dev/null 2>&1; echo $?)" "2"
    # 11. Timing advance to a position: one circle, then two circles.
    local gl; gl=$(ntn_timing_geoloc --ta 12000 --sat-lat 48 --sat-lon 11 --sat-alt 600)
    chk geo-slant "$(printf '%s\n' "$gl" | awk -F'\t' '$1=="slant_range_km"{print $2}')" "936.9"
    chk geo-radius "$(printf '%s\n' "$gl" | awk -F'\t' '$1=="ground_radius_km"{print $2}')" "719.5"
    chk geo-verdict "$(printf '%s\n' "$gl" | awk -F'\t' '$1=="verdict"{print $2}')" "position_circle_only"

    local sp fp
    sp=$(ntn_scan_plan)
    fp=$(ntn_fakecell_plan)
    chk resel-verdict "$(ntn_reselect --terrestrial-rsrp -105 --satellite-rsrp -95 | awk -F'\t' '$1=="verdict"{print $2}')" "reselection_to_satellite"
    chk resel-marginal "$(ntn_reselect --terrestrial-rsrp -95 --satellite-rsrp -94 | awk -F'\t' '$1=="verdict"{print $2}')" "marginal_inside_hysteresis"
    chk resel-barred "$(ntn_reselect --terrestrial-rsrp -80 --satellite-rsrp -120 --barred | awk -F'\t' '$1=="verdict"{print $2}')" "reselection_to_satellite_when_S_passes"
    chk resel-s-crit "$(ntn_reselect --terrestrial-rsrp -105 --satellite-rsrp -95 | awk -F'\t' '$1=="criterion" && $2=="S_satellite"{print $3}')" "pass"
    chk scan-plan-status "$(printf '%s\n' "$sp" | awk -F'\t' '$1=="status"{print $2}')" "plan"
    chk scan-plan-sib19 "$(printf '%s\n' "$sp" | grep -c "SIB19")" "5"
    chk scan-plan-signals "$(printf '%s\n' "$sp" | grep -c '^signal')" "4"
    chk fake-plan-locks "$(printf '%s\n' "$fp" | awk -F'\t' '$1=="finding" && $2=="three_locks"{print $3}')" "HIGH"
    chk fake-plan-licensed "$(printf '%s\n' "$fp" | grep -c "licensed to that operator")" "1"
    chk fake-plan-steps "$(printf '%s\n' "$fp" | grep -c '^step')" "3"
    chk geo-single "$(printf '%s\n' "$gl" | awk -F'\t' '$1=="finding" && $2=="single_measurement"{print $3}')" "MEDIUM"
    local g2; g2=$(ntn_timing_geoloc --range-km 620 --sat-lat 48 --sat-lon 11 --sat-alt 600 --range2-km 665 --sat2-lat 51 --sat2-lon 14)
    chk geo-candidates "$(printf '%s\n' "$g2" | grep -c '^candidate')" "2"
    chk geo-pinned "$(printf '%s\n' "$g2" | awk -F'\t' '$1=="verdict"{print $2}')" "position_pinned_to_two_points"
    chk geo-noargs "$(ntn_timing_geoloc --sat-lat 1 --sat-lon 1 --sat-alt 600 >/dev/null 2>&1; echo $?)" "2"
    chk geo-noalt "$(ntn_timing_geoloc --ta 100 >/dev/null 2>&1; echo $?)" "2"
    printf 'ASSERTIONS\t%d\n' "$nchk"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

ntn_menu() {
    while true; do
        banner
        echo "  === 5G NTN / Satellite ==="
        echo
        cat <<'M'
  [1]  Doppler shift
  [2]  Round-trip delay
  [3]  TA units
  [4]  K_offset (slots -> ms, samples)
  [5]  SIB19 decode (TS 38.331)
  [6]  Feeder link (refused: no geometry)
  [7]  Plan (handoff)
  [0]  back
M
        read -rp "  choice> " c || return 0
        case "$c" in
            1) read -rp "  carrier Hz> " f; read -rp "  velocity m/s> " v; read -rp "  angle deg> " a
               ntn_doppler "$f" "$v" "${a:-0}"; read -rp "  enter " _ ;;
            2) read -rp "  one-way km> " k; ntn_range_rtt "$k"; read -rp "  enter " _ ;;
            3) read -rp "  one-way km> " k; ntn_ta_units "$k"; read -rp "  enter " _ ;;
            4) read -rp "  k_offset slots> " k; read -rp "  scs kHz [15/30/60/120]> " s; read -rp "  sample rate Hz (blank skips)> " r
               ntn_koffset "$k" "$s" "$r"; read -rp "  enter " _ ;;
            5) read -rp "  SIB19 as hex> " _s19; ntn_sib19 "$_s19"; read -rp "  enter " _ ;;
            6) ntn_feeder_link; read -rp "  enter " _ ;;
            7) ntn_plan; read -rp "  enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

ntn_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)  ntn_status_tsv ;;
        --doppler)     ntn_doppler "${1:-}" "${2:-}" "${3:-0}" ;;
        --range)       ntn_range_rtt "${1:-}" ;;
        --ta)          ntn_ta_units "${1:-}" ;;
        --koffset)     ntn_koffset "${1:-}" "${2:-}" "${3:-}" ;;
        --sib19)       ntn_sib19 "${1:-}" ;;
        --sib19-carrier) ntn_sib19_carrier "$@" ;;
        --sib19-build) ntn_sib19_build "$@" ;;
        --ephemeris-hijack) ntn_ephemeris_hijack "$@" ;;
        --timing-geoloc)  ntn_timing_geoloc "$@" ;;
        --scan-plan)      ntn_scan_plan ;;
        --ntn-reselect)   ntn_reselect "$@" ;;
        --fakecell-plan)  ntn_fakecell_plan ;;
        --feeder)      ntn_feeder_link ;;
        --plan)        ntn_plan ;;
        --selftest)    ntn_selftest ;;
        --menu)        ntn_menu ;;
        *)
            cat >&2 <<EOF
5G NTN / Satellite — propagation, Doppler, TA and SIB19

Usage: $0 COMMAND
  --status-tsv              module state as TSV
  --doppler <hz> <mps> [deg]   Doppler shift for a closing velocity
  --range <one_way_km>      one-way and round-trip delay
  --ta <one_way_km>         TA units needed vs the LTE TA range
  --koffset <slots> [scs_khz] [sample_rate_hz]   K_offset (TS 38.331, 15 kHz reference slots) -> ms and samples
  --ntn-reselect            which cell the UE reselects to, and the lever that moves it
  --scan-plan               what to listen for, and the three signals that say NTN
  --fakecell-plan           what broadcasting a satellite cell needs, and where it fails
  --timing-geoloc (--ta N | --range-km KM) --sat-lat DEG --sat-lon DEG --sat-alt KM
                            one range gives a circle; two give the pair of ground points
  --ephemeris-hijack --true-range KM --forged-range KM --koffset N
                            a forged SIB19 ephemeris, and the timing the UE derives from it
  --sib19-build [--koffset N] [--epoch-sfn N] [--epoch-sub N] [--validity sN]
                            build the SIB19-r17 element and encode it
  --sib19 <hex>             decode a SIB19 (TS 38.331) from its bits
  --feeder                  refused: SIB19 carries no gateway geometry
  --plan                    NTN handoff plan
  --selftest                verify the timing geometry
  --menu                    interactive menu
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
    ntn_cli_main "$@"
fi
