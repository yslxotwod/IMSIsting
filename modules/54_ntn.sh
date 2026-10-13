#!/usr/bin/env bash
# ntn — 5G non-terrestrial networks: propagation delays, Doppler and SIB19.
#
# A satellite cell is a normal NR cell with two extra problems: a round-trip
# delay far larger than any terrestrial timing assumes, and a Doppler shift that
# scales with the closing velocity. 3GPP answers both in SIB19 (TA, k_offset,
# ephemeris, cell reference location, mobility). This module computes the delays
# and Doppler, models k_offset, and lays out the feeder/service link exposure.
#
# Attack owned: none direct — cell reconnaissance and timing analysis for NTN
# access (extends 02_cell_recon and 16_nr_air to a satellite cell).
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
    printf 'TARGET\tNTN propagation delay, Doppler, TA and SIB19 handling\n'
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
    local rtt_ms="${1:-}"
    [[ "$rtt_ms" =~ ^[0-9]+([.][0-9]+)?$ ]] || { printf 'ERROR\trtt (ms) must be numeric\n' >&2; return 2; }
    awk -v r="$rtt_ms" 'BEGIN{
        slot_ms = 1.0
        print "scs_khz\t15"
        printf "slot_ms\t%.1f\n", slot_ms
        k = r
        ko = int(k/slot_ms); if (ko*slot_ms < k) ko++
        printf "k_offset_min\t%d\n", ko
        printf "note\tk_offset must at least cover the round-trip delay so the UE can apply TA before the slot is scheduled\n"
    }'
}

ntn_sib19() {
    cat <<'EOF'
field	meaning
ta_common	cell-level timing advance applied before the UE is scheduled
k_offset	scheduling offset that covers the propagation delay
ephemeris	orbital state: ECEF position/velocity or orbital elements
cell_reference_location	on-earth reference point for distance-based TA
mobility	trajectory parameters for a moving cell (LEO/MEO)
EOF
}
ntn_feeder_link() {
    cat <<'EOF'
link	endpoints	exposure
feeder	gateway <-> satellite	ground-to-space; the gateway is the trust anchor and the long-haul backhaul
service	satellite <-> UE	user link; the satellite is a shared relay, so co-channel traffic is co-located
EOF
}

ntn_plan() {
    cat <<'EOF'
status	handoff
what	operating or observing an NTN cell
hardware	an NTN-capable UE, or an SDR with a satellite pass to receive (a LEO beacon on the feeder/service downlink)
software	a channel simulator with a Doppler model for the return path; SIB19 decoder on the receive side
flow	1. --doppler and --range for the pass geometry  2. --ta and --koffset for the timing budget  3. --sib19 for the fields to decode
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

    # 4. k_offset must cover the RTT: GEO 238.74 ms -> 239 slots at 15 kHz.
    chk koffset-geo "$(fld "$(ntn_koffset 238.74)" k_offset_min)" "239"
    chk koffset-ms  "$(fld "$(ntn_koffset 4.003)" k_offset_min)" "5"

    # 5. Tables.
    chk sib19-koffset "$(ntn_sib19 | awk -F'\t' '$1=="k_offset"{print ($2 ~ /propagation delay/)?"ok":"no"}')" "ok"
    chk feeder-gw "$(ntn_feeder_link | awk -F'\t' '$1=="feeder"{print ($3 ~ /trust anchor/)?"ok":"no"}')" "ok"

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
  [4]  k_offset
  [5]  SIB19 field reference
  [6]  Feeder / service link reference
  [7]  Plan (handoff)
  [0]  back
M
        read -rp "  choice> " c || return 0
        case "$c" in
            1) read -rp "  carrier Hz> " f; read -rp "  velocity m/s> " v; read -rp "  angle deg> " a
               ntn_doppler "$f" "$v" "${a:-0}"; read -rp "  enter " _ ;;
            2) read -rp "  one-way km> " k; ntn_range_rtt "$k"; read -rp "  enter " _ ;;
            3) read -rp "  one-way km> " k; ntn_ta_units "$k"; read -rp "  enter " _ ;;
            4) read -rp "  rtt ms> " r; ntn_koffset "$r"; read -rp "  enter " _ ;;
            5) ntn_sib19; read -rp "  enter " _ ;;
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
        --koffset)     ntn_koffset "${1:-}" ;;
        --sib19)       ntn_sib19 ;;
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
  --koffset <rtt_ms>        minimum scheduling offset (slots, 15 kHz)
  --sib19                   SIB19 field reference
  --feeder                  feeder/service link exposure
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
