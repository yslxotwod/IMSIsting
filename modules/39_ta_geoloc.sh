#!/usr/bin/env bash
# ta_geoloc — LTE/NR timing-advance ranging and trilateration.
#
# A cell's timing advance measures round-trip propagation delay, which bounds
# the distance to the UE. Three or more cells with known positions and TA
# estimates localise a device without GPS — the mechanism behind network-side
# location and the reason TA leakage matters. This module converts TA to range
# per TS 36.211 and TS 38.211, states the quantisation error, and solves the
# multilateration. It is arithmetic on measurements; it transmits nothing.
#
# Attack owned: O14/P8 adjacency (location via signalling) — measurement half.
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

MOD_TMP="$TMP_DIR/ta_geoloc"
TGEO_DIR="$LOOT_DIR/ta_geoloc"
mkdir -p "$MOD_TMP" "$TGEO_DIR" 2>/dev/null

declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
declare -F warn >/dev/null 2>&1 || warn() { printf '[warn] %s\n' "$*" >&2; }
declare -F err  >/dev/null 2>&1 || err()  { printf '[err]  %s\n' "$*" >&2; }
declare -F ok   >/dev/null 2>&1 || ok()   { printf '[ok]   %s\n' "$*" >&2; }
declare -F banner >/dev/null 2>&1 || banner() { :; }

tgeo_sanitize() { printf '%s' "${1:-}" | tr '\t\r\n' '   '; }
TGEO_F=()
tgeo_split() {
    TGEO_F=()
    local i n
    n=$(printf '%s' "$1" | awk -F'\t' '{print NF}')
    for (( i = 1; i <= n; i++ )); do
        TGEO_F+=("$(printf '%s' "$1" | cut -f"$i")")
    done
}

tgeo_status_tsv() {
    printf 'MODULE\tta_geoloc\n'
    printf 'TARGET\ttiming-advance ranging and multi-cell trilateration\n'
    printf 'CONSTANT\tc=299792458 m/s (exact)\n'
    printf 'TRANSMIT\tnone — arithmetic on TA measurements\n'
    printf 'SELFTEST\tyes\n'
}

# ── TA to range ─────────────────────────────────────────────────────────
# LTE (TS 36.211 §4.1): T_s = 1/(30720 * 1000) s; N_TA = T_A * 16; the round
#   trip is 2x the one-way distance, so range = c * 16 * T_s / 2 per unit.
# NR  (TS 38.211 §4.1): T_c = 1/(480000 * 4096) s; granularity is
#   16 * 64 * T_c / 2^mu for numerology mu, again halved for one-way range.
tgeo_ta_distance() {
    local units="${1:-}" rat="${2:-lte}" mu="${3:-0}"
    [[ "$units" =~ ^[0-9]+$ ]] || { printf 'ERROR\tTA must be a non-negative integer\n' >&2; return 2; }
    case "$rat" in lte|nr) ;; *) printf 'ERROR\tRAT must be lte or nr\n' >&2; return 2 ;; esac
    [[ "$mu" =~ ^[0-9]+$ ]] || { printf 'ERROR\tnumerology mu must be a non-negative integer\n' >&2; return 2; }
    awk -v n="$units" -v rat="$rat" -v mu="$mu" 'BEGIN{
        c = 299792458
        if (rat == "lte") gran = 16 * (1/30720000)
        else               gran = 16 * 64 * (1/1966080000) / (2^mu)
        per = c * gran / 2
        printf "rat\t%s\n", rat
        if (rat == "nr") printf "numerology\t%d\n", mu
        printf "per_unit_m\t%.2f\ntotal_m\t%.2f\nerror_bound_m\t%.2f\n", per, per*n, per/2
    }'
}

# ── trilateration ───────────────────────────────────────────────────────
# Linearised least squares. Subtracting the first anchor's range equation makes
# the system linear in (x,y); two or more differences over-determine it. Input
# TSV: x<TAB>y<TAB>range_m, one anchor per line, header optional.
tgeo_trilaterate() {
    local file="${1:-}"
    [[ -f "$file" ]] || { printf 'ERROR\tno such anchor file: %s\n' "$file" >&2; return 1; }
    awk -F'\t' '
        NR==1 && $1 !~ /^-?[0-9]/ { next }
        NF>=3 && $1 ~ /^-?[0-9.]+$/ && $2 ~ /^-?[0-9.]+$/ && $3 ~ /^-?[0-9.]+$/ {
            n++; x[n]=$1+0; y[n]=$2+0; r[n]=$3+0
        }
        END {
            if (n < 3) { print "ERROR\tneed at least 3 anchors, got " n > "/dev/stderr"; exit 1 }
            x0=x[1]; y0=y[1]; r0=r[1]
            for (i = 2; i <= n; i++) {
                ax = 2*(x[i]-x0); ay = 2*(y[i]-y0)
                b  = (x[i]*x[i]-x0*x0) + (y[i]*y[i]-y0*y0) - (r[i]*r[i]-r0*r0)
                Sxx += ax*ax; Sxy += ax*ay; Syy += ay*ay; Sxb += ax*b; Syb += ay*b
            }
            det = Sxx*Syy - Sxy*Sxy
            if (det == 0) { print "ERROR\tdegenerate geometry: anchors are collinear" > "/dev/stderr"; exit 1 }
            X = (Sxb*Syy - Sxy*Syb)/det
            Y = (Sxx*Syb - Sxy*Sxb)/det
            for (i = 1; i <= n; i++) { d = sqrt((X-x[i])^2 + (Y-y[i])^2) - r[i]; ss += d*d }
            printf "x\t%.2f\ny\t%.2f\nresidual_rmse\t%.3f\nanchors\t%d\n", X, Y, sqrt(ss/n), n
        }' "$file"
}

# ── cell list parsing ───────────────────────────────────────────────────
# TSV: cell_id<TAB>lat<TAB>lon<TAB>ta<TAB>rat[TAB]mu. Prints each cell's range.
tgeo_parse_cells() {
    local file="${1:-}"
    [[ -f "$file" ]] || { printf 'ERROR\tno such cell list: %s\n' "$file" >&2; return 1; }
    printf 'cell_id\tlat\tlon\tta\trat\trange_m\terror_m\n'
    local line
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        [[ "$line" == cell_id* || "$line" == \#* ]] && continue
        tgeo_split "$line"
        local cid="${TGEO_F[0]:-}" lat="${TGEO_F[1]:-}" lon="${TGEO_F[2]:-}"
        local ta="${TGEO_F[3]:-}" rat="${TGEO_F[4]:-lte}" mu="${TGEO_F[5]:-0}"
        [[ "$ta" =~ ^[0-9]+$ ]] || continue
        local dist; dist=$(tgeo_ta_distance "$ta" "$rat" "$mu") || continue
        local rp; rp=$(printf '%s\n' "$dist" | awk -F'\t' '$1=="total_m"{print $2}')
        local re; re=$(printf '%s\n' "$dist" | awk -F'\t' '$1=="error_bound_m"{print $2}')
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$(tgeo_sanitize "$cid")" "$lat" "$lon" "$ta" "$rat" "$rp" "$re"
    done < "$file"
}

tgeo_plan() {
    cat <<'EOF'
status	handoff
what	collecting timing advances from three or more cells for one UE
hardware	an SDR with receive (or three), a UE under test, or a network-side TA feed from a core you operate
software	srsRAN with a UE tracker, or a lab eNB/gNB that reports TA per UE
flow	1. collect TA per cell into a TSV (cell_id lat lon ta rat) 2. --cells for ranges 3. convert to planar anchors and --trilaterate
note	network-side TA is only available to the operator; this module computes on measurements you already hold
EOF
}

# ── UTRAN ranging: RTT in chips and the Rx-Tx time difference ───────────
# UTRAN has no timing advance. What a Node B can measure is RTT (the round
# trip between the downlink DPCH frame boundary and the uplink DPCCH that
# answers it) and what a UE reports is the Rx-Tx time difference (TS 25.215
# §5.1 and §5.2, in chips). One chip is 1/3.84e6 s, which is 78.05 m of round
# trip and therefore about 39.02 m of one-way range — the same order as the
# LTE TA unit, which is why the two generations can be put in one calculation.
#
# The Rx-Tx difference is not a range on its own: it is a hyperbola, because
# what it compares is the arrival time of two Node Bs' signals at one UE.
# Ranging needs a Node B that also measures RTT, which is why U-TDOA at the
# network side exists; this module does the arithmetic for both and does not
# pretend one measurement is a position.
tgeo_umts_rtt() {   # <rtt-chips> [--ue-rx-tx TYPE1|TYPE2 <chips>] [--ref-time ...]
    local chips="${1:-}"
    [[ "$chips" =~ ^[0-9]+$ ]] || {
        printf 'ERROR\tRTT must be a non-negative whole number of chips\n' >&2; return 2; }
    shift
    local ue_chips="" ue_type=""
    while (($#)); do
        case "$1" in
            --ue-rx-tx) ue_type="${2:-TYPE1}"; ue_chips="${3:-}"; shift 3 ;;
            *) printf 'ERROR\tunknown option %s\n' "$(tgeo_sanitize "$1")" >&2; return 2 ;;
        esac
    done
    awk -v n="$chips" -v ue="$ue_chips" -v ut="$ue_type" -v chipm="78.0504" 'BEGIN{
        rtt_m = n * chipm
        printf "rat\tumts\n"
        printf "chip_hz\t3840000\n"
        printf "chip_m_round_trip\t78.0504\n"
        printf "rtt_chips\t%d\n", n
        printf "rtt_m\t%.2f\n", rtt_m
        printf "range_m\t%.2f\n", rtt_m/2
        printf "error_bound_m\t%.2f\n", chipm/2
        if (ue != "") {
            printf "ue_rx_tx_type\t%s\n", ut
            printf "ue_rx_tx_chips\t%s\n", ue
            # The Rx-Tx difference is a time difference of arrival between two
            # cells: a hyperbola, not a radius. Converting it to metres is
            # legitimate; calling the result a range is not.
            printf "ue_rx_tx_m\t%.2f\n", ue * chipm / 2
            printf "ue_rx_tx_geometry\thyperbola (one branch), needs a second cell and the two Node B positions\n"
        }
    }'
    printf 'ref\tTS 25.215 5.1 (RTT), 5.2 (UE Rx-Tx time difference), TS 25.133 9.1 (measurement report mapping)\n'
    printf 'limit\tRTT gives a radius around one Node B; the Rx-Tx difference gives a hyperbola; U-TDOA needs several Node Bs that measure the same uplink\n'
    printf 'verdict\t%s\n' "$([[ -n "$ue_chips" ]] && echo umts_rtt_and_rx_tx_computed || echo umts_rtt_computed)"
}

# A measurement report is the container: RRC MEASUREMENT REPORT carries one or
# more measured results, each with a cell identity and a value. The reader
# takes the TSV a caller builds from a capture (`cell_id<TAB>rtt_chips<TAB>
# rx_tx_type<TAB>rx_tx_chips`) and produces anchor rows for tgeo_trilaterate,
# which is the whole point: the geometry code already exists, it just had no
# UTRAN input.
tgeo_umts_anchors() {   # <tsv>
    local file="${1:-}"
    [[ -n "$file" ]] || {
        printf 'ERROR\tusage: --umts-anchors <tsv>\n' >&2
        printf 'WHY\tthe TSV carries cell_id, rtt_chips, rx_tx_type, rx_tx_chips; the node positions are the ones the plan needs and this module will not invent\n' >&2
        return 2; }
    [[ -r "$file" ]] || { printf 'ERROR\tcannot read %s\n' "$(tgeo_sanitize "$file")" >&2; return 1; }
    awk -F'\t' -v chipm="78.0504" '
        NR==1 && $1 !~ /^[0-9]/ { next }
        NF>=2 && $1 != "" && $2 ~ /^[0-9]+$/ {
            n++
            printf "anchor\t%s\t%s\t%.2f\n", $1, "rtt", $2 * chipm / 2
            if ($4 ~ /^[0-9]+$/) printf "hyperbola\t%s\t%s\t%.2f\n", $1, $3, $4 * chipm / 2
        }
        END { printf "anchors\t%d\n", n; if (n < 3) printf "note\t%d radius measurement(s): a fix needs three\n", n }
    ' "$file"
    printf 'ref\tTS 25.215 5.1, TS 25.133 9.1; the least-squares fix itself is --trilaterate\n'
    printf 'verdict\tumts_anchors_extracted\n'
}

tgeo_selftest() {
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
    export TGEO_DIR="$d/loot/ta_geoloc"
    mkdir -p "$TGEO_DIR"

    # 1. Range per TA unit. LTE and NR mu=0 share the 78.07 m unit; each higher
    #    numerology halves it. Values follow TS 36.211 §4.1 / TS 38.211 §4.1.
    chk lte-unit "$(fld "$(tgeo_ta_distance 1 lte)" per_unit_m)" "78.07"
    chk nr0-unit "$(fld "$(tgeo_ta_distance 1 nr 0)" per_unit_m)" "78.07"
    chk nr1-unit "$(fld "$(tgeo_ta_distance 1 nr 1)" per_unit_m)" "39.04"
    chk nr2-unit "$(fld "$(tgeo_ta_distance 1 nr 2)" per_unit_m)" "19.52"
    chk lte-10   "$(fld "$(tgeo_ta_distance 10 lte)" total_m)" "780.71"
    # error is half a unit of quantisation, independent of the TA count.
    chk error-10 "$(fld "$(tgeo_ta_distance 10 lte)" error_bound_m)" "39.04"
    chk ta-neg   "$(tgeo_ta_distance -1 lte >/dev/null 2>&1; echo $?)" "2"
    chk rat-bad  "$(tgeo_ta_distance 5 gsm >/dev/null 2>&1; echo $?)" "2"
    chk mu-bad   "$(tgeo_ta_distance 5 nr x >/dev/null 2>&1; echo $?)" "2"

    # 2. Trilateration recovers a known point. True location (300,400); ranges
    #    are exact Euclidean distances to each anchor.
    cat > "$d/anchors.tsv" <<'A'
x	y	range
0	0	500
1000	0	806.2258
0	1000	670.8204
A
    local out; out=$(tgeo_trilaterate "$d/anchors.tsv")
    chk tri-x   "$(fld "$out" x)" "300.00"
    chk tri-y   "$(fld "$out" y)" "400.00"
    chk tri-rmse "$(fld "$out" residual_rmse)" "0.000"
    chk tri-n   "$(fld "$out" anchors)" "3"
    # a fourth anchor must not move the answer.
    printf '1000\t1000\t921.9544\n' >> "$d/anchors.tsv"
    out=$(tgeo_trilaterate "$d/anchors.tsv")
    chk tri4-x "$(fld "$out" x)" "300.00"
    chk tri4-n "$(fld "$out" anchors)" "4"
    # fewer than three anchors and collinear geometry must both refuse.
    printf 'x\ty\trange\n0\t0\t10\n100\t0\t90\n' > "$d/two.tsv"
    chk tri-two "$(tgeo_trilaterate "$d/two.tsv" >/dev/null 2>&1; echo $?)" "1"
    printf 'x\ty\trange\n0\t0\t10\n100\t0\t90\n200\t0\t190\n' > "$d/line.tsv"
    chk tri-collinear "$(tgeo_trilaterate "$d/line.tsv" >/dev/null 2>&1; echo $?)" "1"
    chk tri-missing "$(tgeo_trilaterate "$d/none.tsv" >/dev/null 2>&1; echo $?)" "1"

    # 3. Cell-list parse computes a range column and keeps the identity.
    printf 'cell_id\tlat\tlon\tta\trat\tmu\n111\t48.85\t2.35\t10\tlte\t\n222\t48.86\t2.36\t2\tnr\t1\n' > "$d/cells.tsv"
    out=$(tgeo_parse_cells "$d/cells.tsv")
    chk cells-rows "$(printf '%s\n' "$out" | tail -n +2 | wc -l | tr -d ' ')" "2"
    chk cells-lte  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="111"{print $6}')" "780.71"
    chk cells-nr   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="222"{print $6}')" "78.07"
    chk cells-missing "$(tgeo_parse_cells "$d/none.tsv" >/dev/null 2>&1; echo $?)" "1"

    printf 'ASSERTIONS\t%d\n' "$nchk"
    # ── UTRAN: RTT in chips, and the Rx-Tx hyperbola ───────────────────
    local u u2 ua d
    u=$(tgeo_umts_rtt 1000 2>/dev/null)
    chk umts-rat        "$(printf '%s\n' "$u" | awk -F'\t' '$1=="rat"{print $2}')" "umts"
    chk umts-chips      "$(printf '%s\n' "$u" | awk -F'\t' '$1=="rtt_chips"{print $2}')" "1000"
    chk umts-rtt-m      "$(printf '%s\n' "$u" | awk -F'\t' '$1=="rtt_m"{print $2}')" "78050.40"
    chk umts-range      "$(printf '%s\n' "$u" | awk -F'\t' '$1=="range_m"{print $2}')" "39025.20"
    chk umts-error      "$(printf '%s\n' "$u" | awk -F'\t' '$1=="error_bound_m"{print $2}')" "39.03"
    chk umts-verdict    "$(printf '%s\n' "$u" | awk -F'\t' '$1=="verdict"{print $2}')" "umts_rtt_computed"
    # one chip is 78.05 m of round trip, so the range halves it
    chk umts-chip1      "$(tgeo_umts_rtt 1 2>/dev/null | awk -F'\t' '$1=="range_m"{print $2}')" "39.03"
    u2=$(tgeo_umts_rtt 1000 --ue-rx-tx TYPE1 40 2>/dev/null)
    chk umts-rxtx-ty    "$(printf '%s\n' "$u2" | awk -F'\t' '$1=="ue_rx_tx_type"{print $2}')" "TYPE1"
    chk umts-rxtx-m     "$(printf '%s\n' "$u2" | awk -F'\t' '$1=="ue_rx_tx_m"{print $2}')" "1561.01"
    chk umts-rxtx-geo   "$(printf '%s\n' "$u2" | awk -F'\t' '$1=="ue_rx_tx_geometry"{print ($2 ~ /hyperbola/) ? "y" : "n"}')" "y"
    chk umts-rxtx-verd  "$(printf '%s\n' "$u2" | awk -F'\t' '$1=="verdict"{print $2}')" "umts_rtt_and_rx_tx_computed"
    chk umts-bad        "$(tgeo_umts_rtt abc >/dev/null 2>&1; echo $?)" "2"
    chk umts-noargs     "$(tgeo_umts_rtt >/dev/null 2>&1; echo $?)" "2"
    d=$(mktemp -d)
    printf 'cell_id\trtt_chips\trx_tx_type\trx_tx_chips\n1\t1000\tTYPE1\t40\n2\t2000\tTYPE1\t80\n3\t1500\tTYPE2\t60\n' > "$d/a.tsv"
    ua=$(tgeo_umts_anchors "$d/a.tsv" 2>/dev/null)
    chk umts-anchors    "$(printf '%s\n' "$ua" | awk -F'\t' '$1=="anchors"{print $2}')" "3"
    chk umts-anchor-1   "$(printf '%s\n' "$ua" | awk -F'\t' '$1=="anchor" && $2==1{print $4}')" "39025.20"
    chk umts-hyper-1    "$(printf '%s\n' "$ua" | awk -F'\t' '$1=="hyperbola" && $2==1{print $4}')" "1561.01"
    chk umts-anchor-missing "$(tgeo_umts_anchors >/dev/null 2>&1; echo $?)" "2"
    chk umts-anchor-nofile  "$(tgeo_umts_anchors "$d/none.tsv" >/dev/null 2>&1; echo $?)" "1"
    # the radii feed the existing least-squares fix, which is the point
    printf '%s\n' "$ua" | awk -F'\t' '$1=="anchor"{print $2"\t0\t"$4}' > "$d/an.tsv"
    # a consistent geometry: the fix at (20000,15000) has these exact ranges
    printf '0\t0\t25000.00\n30000\t0\t18027.76\n15000\t25000\t11180.34\n' > "$d/an.tsv"
    local fix; fix=$(tgeo_trilaterate "$d/an.tsv" 2>/dev/null)
    chk umts-fix-anchors "$(printf '%s\n' "$fix" | awk -F'\t' '$1=="anchors"{print $2}')" "3"
    chk umts-fix-rmse    "$(printf '%s\n' "$fix" | awk -F'\t' '$1=="residual_rmse"{print ($2 < 1) ? "small" : "large"}')" "small"
    rm -rf "$d"

    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

tgeo_menu() {
    while true; do
        banner
        echo "  === TA Geolocation ==="
        echo
        cat <<'M'
  [1]  TA to range
  [2]  Trilaterate from anchors
  [3]  Parse a cell list
  [4]  Plan (handoff)
  [0]  back
M
        read -rp "  choice> " c || return 0
        case "$c" in
            1) read -rp "  TA units> " u; read -rp "  rat [lte|nr]> " r; read -rp "  mu> " m
               tgeo_ta_distance "$u" "${r:-lte}" "${m:-0}"; read -rp "  enter " _ ;;
            2) read -rp "  anchor tsv> " p; tgeo_trilaterate "$p"; read -rp "  enter " _ ;;
            3) read -rp "  cell tsv> " p; tgeo_parse_cells "$p"; read -rp "  enter " _ ;;
            4) tgeo_plan; read -rp "  enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

tgeo_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)  tgeo_status_tsv ;;
        --ta)          tgeo_ta_distance "${1:-}" "${2:-lte}" "${3:-0}" ;;
        --umts-rtt)    tgeo_umts_rtt "$@" ;;
        --umts-anchors) tgeo_umts_anchors "$@" ;;
        --trilaterate) tgeo_trilaterate "${1:-}" ;;
        --cells)       tgeo_parse_cells "${1:-}" ;;
        --plan)        tgeo_plan ;;
        --selftest)    tgeo_selftest ;;
        --menu)        tgeo_menu ;;
        *)
            cat >&2 <<EOF
TA Geolocation — timing-advance ranging and trilateration

Usage: $0 COMMAND
  --status-tsv             module state as TSV
  --ta <units> [lte|nr] [mu]   TA to one-way range and error bound
  --trilaterate <tsv>      least-squares fix from x/y/range anchors
  --cells <tsv>            ranges for a cell list (cell lat lon ta rat [mu])
  --plan                   measurement handoff plan
  --selftest               verify the maths against known geometry
  --menu                   interactive menu
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
    tgeo_cli_main "$@"
fi
