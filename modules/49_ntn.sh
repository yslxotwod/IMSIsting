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
# count the UE schedules with, not the delay in milliseconds. SIB19 itself is
# not decoded here: this tree has no NR RRC ASN.1 layout table.
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
        --sib19-build) ntn_sib19_build "$@" ;;
        --ephemeris-hijack) ntn_ephemeris_hijack "$@" ;;
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
