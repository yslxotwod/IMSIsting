#!/usr/bin/env bash
# cell recon — survey GSM / UMTS / LTE / NR cells from the air or from capture
#
# Reference module for IMSIsting. It carries the full contract: self-locate
# header, shared TMP_DIR, TSV output with untrusted text sanitised, hardware
# guards that name the missing radio, a --selftest that runs with no radio,
# and a CLI dispatch that never prints success on failure.
#
# Resolve IMSISTING_ROOT from this script's own path so state and loot land in
# the project tree even when launched standalone via pkexec (no launcher env).
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

# Under pkexec HOME=/root even though we write to the invoking user's tree.
# Reset HOME so $HOME-relative defaults resolve to the real user.
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

MOD_TMP="$TMP_DIR/cell_recon"
CREC_DIR="$LOOT_DIR/cell_recon"
CREC_CELLS="$CREC_DIR/cells.tsv"
mkdir -p "$MOD_TMP" "$CREC_DIR" 2>/dev/null

# Shared cross-module state — other modules read these.
CREC_SDR="${TMP_DIR}/sdr_device"
CREC_ARFCN="${TMP_DIR}/target_arfcn"
CREC_PLMN="${TMP_DIR}/target_plmn"

# ── sanitisation ────────────────────────────────────────────────────────
# Any string that reaches a TSV row is untrusted: a network can carry an
# operator name containing a tab and forge an entire row in a consumer that
# splits on tab. Tabs, CR and LF become spaces at the point of output.
crec_sanitize() {
    printf '%s' "${1:-}" | tr '\t\r\n' '   '
}

# Split a TSV line into the global array CREC_F, preserving empty fields.
# `read` with IFS=tab treats tab as whitespace and collapses runs of it, so a
# row with an empty column shifts every field after it. `cut -f` does not, so
# the line is split that way. This bit the pcap path, where tshark emits empty
# fields for every layer a given frame does not carry.
CREC_F=()
crec_split() {
    CREC_F=()
    local i n
    n=$(printf '%s' "$1" | awk -F'\t' '{print NF}')
    for (( i = 1; i <= n; i++ )); do
        CREC_F+=("$(printf '%s' "$1" | cut -f"$i")")
    done
}

# ── band / ARFCN tables ─────────────────────────────────────────────────
# GSM ARFCN -> uplink MHz.  GSM900: F = 890 + 0.2*N (N=1..124)
#                          GSM1800: F = 1710 + 0.2*(N-511) (N=512..885)
#                          GSM850: F = 824 + 0.2*N (N=128..251)
#                          GSM1900: F = 1850 + 0.2*(N-512) (N=512..810)
crec_gsm_arfcn_to_mhz() {
    local arfcn="$1"
    [[ "$arfcn" =~ ^[0-9]+$ ]] || return 1
    if (( arfcn >= 1 && arfcn <= 124 )); then
        awk -v n="$arfcn" 'BEGIN{printf "%.1f", 890 + 0.2*n}'
    elif (( arfcn >= 128 && arfcn <= 251 )); then
        awk -v n="$arfcn" 'BEGIN{printf "%.1f", 824 + 0.2*n}'
    elif (( arfcn >= 512 && arfcn <= 885 )); then
        awk -v n="$arfcn" 'BEGIN{printf "%.1f", 1710 + 0.2*(n-511)}'
    elif (( arfcn >= 512 && arfcn <= 810 )); then
        awk -v n="$arfcn" 'BEGIN{printf "%.1f", 1850 + 0.2*(n-512)}'
    else
        return 1
    fi
}

# LTE EARFCN -> downlink MHz.  F = F_low + 0.1*(N - N_offs)
# Table of the bands that matter for survey work; extended on request.
crec_lte_earfcn_to_mhz() {
    local earfcn="$1"
    [[ "$earfcn" =~ ^[0-9]+$ ]] || return 1
    awk -v n="$earfcn" 'BEGIN{
        # band -> low_MHz, n_offs, range_lo, range_hi
        split("1 2110 0 0 599|2 1930 600 600 1199|3 1805 1200 1200 1949|" \
              "4 2110 1950 1950 2399|5 869 2400 2400 2649|7 2620 2750 2750 3449|" \
              "8 925 3450 3450 3799|20 791 6150 6150 6449|28 758 9210 9210 9659|" \
              "38 2570 37750 37750 38249|40 2300 38650 38650 39649|41 2496 39650 39650 41589",
              bands, "|")
        for (i = 1; i <= length(bands); i++) {
            split(bands[i], b, " ")
            if (n >= b[4] && n <= b[5]) {
                printf "%.1f", b[2] + 0.1*(n - b[3]); exit
            }
        }
        exit 1
    }'
}

# NR-ARFCN -> downlink MHz.  TS 38.104 Table 5.4.2.1-1.
#
# The raster is PIECEWISE, not a constant: 5 kHz below 3 GHz, 15 kHz from 3 to
# 24.25 GHz, 60 kHz above. An earlier version applied 5 kHz everywhere, which
# is correct only at a band edge (where the offset term is zero) and drifts by
# up to 300 MHz inside n77/n78/n79. That version passed its own selftest because
# the only ARFCN it checked was the degenerate one.
#
#   F = F_ref_offs + dF * (N - N_ref_offs)
crec_nr_arfcn_to_mhz() {
    local arfcn="$1"
    [[ "$arfcn" =~ ^[0-9]+$ ]] || return 1
    awk -v n="$arfcn" 'BEGIN{
        if      (n <= 599999)  printf "%.3f", 0        + 0.005 * (n - 0)
        else if (n <= 2016666) printf "%.3f", 3000     + 0.015 * (n - 600000)
        else if (n <= 3279165) printf "%.3f", 24250.08 + 0.060 * (n - 2016667)
        else exit 1
    }'
}

# NR band name from an ARFCN, by the per-band N window (TS 38.104 Table
# 5.4.2.1-1). Separate from the frequency maths, which needs no band.
crec_nr_band_of_arfcn() {
    local arfcn="$1"
    [[ "$arfcn" =~ ^[0-9]+$ ]] || return 1
    awk -v n="$arfcn" 'BEGIN{
        split("n1 422000 431999|n2 386000 398999|n3 361000 376999|" \
              "n5 173800 178799|n7 524000 538999|n8 185000 192999|" \
              "n20 158200 166199|n28 151600 160599|n41 499200 537999|" \
              "n77 620000 680000|n78 620000 680000|n79 693334 733333|" \
              "n257 2054166 2104165|n258 2016667 2070832|n260 2229166 2279165|" \
              "n261 2070833 2084999",
              bands, "|")
        # n77/n78 share 620000-680000 and n257/n258 overlap, so an ARFCN can
        # name more than one band. Report every match rather than picking one:
        # a caller that needs a single band must supply the frequency too.
        hit = 0
        for (i = 1; i <= length(bands); i++) {
            split(bands[i], b, " ")
            if (n >= b[2] && n <= b[3]) { printf "%s%s", (hit ? " " : ""), b[1]; hit = 1 }
        }
        if (!hit) exit 1
        printf "\n"
    }'
}

# ── PLMN decode ─────────────────────────────────────────────────────────
# MCC/MNC -> operator. A representative table, not the full ITU list: enough
# that a survey reads as names instead of digits. Unknown PLMNs are reported
# as the raw MCC-MNC, which is the honest answer.
crec_plmn_name() {
    local plmn="$1"
    case "$plmn" in
        208-01) echo "Orange FR" ;;
        208-10) echo "SFR FR" ;;
        208-15) echo "Free Mobile FR" ;;
        208-20) echo "Bouygues FR" ;;
        262-01) echo "Telekom DE" ;;
        262-02) echo "Vodafone DE" ;;
        262-03) echo "O2 DE" ;;
        234-10) echo "O2 UK" ;;
        234-15) echo "Vodafone UK" ;;
        234-30) echo "EE UK" ;;
        234-33) echo "EE UK" ;;
        310-260) echo "T-Mobile US" ;;
        310-410) echo "AT&T US" ;;
        311-480) echo "Verizon US" ;;
        204-04) echo "Vodafone NL" ;;
        204-08) echo "KPN NL" ;;
        204-16) echo "T-Mobile NL" ;;
        214-01) echo "Vodafone ES" ;;
        214-03) echo "Movistar ES" ;;
        214-07) echo "Orange ES" ;;
        222-01) echo "TIM IT" ;;
        222-10) echo "Vodafone IT" ;;
        222-88) echo "WindTre IT" ;;
        228-01) echo "Swisscom CH" ;;
        228-02) echo "Sunrise CH" ;;
        228-03) echo "Salt CH" ;;
        505-01) echo "Telstra AU" ;;
        505-02) echo "Optus AU" ;;
        505-03) echo "Vodafone AU" ;;
        440-10) echo "NTT docomo JP" ;;
        440-20) echo "SoftBank JP" ;;
        450-05) echo "SK Telecom KR" ;;
        460-00) echo "China Mobile" ;;
        460-01) echo "China Unicom" ;;
        *)      echo "unknown" ;;
    esac
}

# MCC -> country. Representative set covering the operator table above plus
# the common roaming cases.
crec_mcc_country() {
    case "${1:-}" in
        208) echo "France" ;;        262) echo "Germany" ;;
        234|235) echo "United Kingdom" ;; 310|311|312|313|314|315|316) echo "United States" ;;
        204) echo "Netherlands" ;;   214) echo "Spain" ;;
        222) echo "Italy" ;;         228) echo "Switzerland" ;;
        505) echo "Australia" ;;     440|441) echo "Japan" ;;
        450) echo "South Korea" ;;   460) echo "China" ;;
        240|242|244|246|248) echo "Nordics" ;;
        404|405|406) echo "India" ;; 724) echo "Brazil" ;;
        *)   echo "unknown" ;;
    esac
}

# ── generation from RAT ─────────────────────────────────────────────────
crec_gen_of_rat() {
    case "${1:-}" in
        GSM|GERAN|2G)   echo "2G" ;;
        UMTS|UTRAN|3G)  echo "3G" ;;
        LTE|EUTRAN|4G)  echo "4G" ;;
        NR|5G)          echo "5G" ;;
        *)              echo "?" ;;
    esac
}

# ── hardware guards ─────────────────────────────────────────────────────
# Each guard names the missing radio. An empty result is not an answer.
crec_find_sdr() {
    local d
    for d in hackrf bladerf limesdr usrp b200 b210; do
        case "$d" in
            hackrf)  command -v hackrf_info  >/dev/null 2>&1 && { echo "hackrf";  return 0; } ;;
            bladerf) command -v bladeRF-cli  >/dev/null 2>&1 && { echo "bladerf"; return 0; } ;;
            limesdr) command -v LimeUtil     >/dev/null 2>&1 && { echo "limesdr"; return 0; } ;;
            usrp)    command -v uhd_find_devices >/dev/null 2>&1 && { echo "usrp"; return 0; } ;;
        esac
    done
    # rtl-sdr is receive-only: usable for passive survey, never for transmit.
    command -v rtl_test >/dev/null 2>&1 && { echo "rtlsdr"; return 0; }
    return 1
}

crec_find_gsm_scanner() {
    for t in grgsm_scanner grgsm_livemon; do
        command -v "$t" >/dev/null 2>&1 && { echo "$t"; return 0; }
    done
    return 1
}

crec_find_lte_scanner() {
    for t in srsran srsenb nr-uesoftmodem gnb; do
        command -v "$t" >/dev/null 2>&1 && { echo "$t"; return 0; }
    done
    return 1
}

crec_find_celltower_tool() {
    for t in cellmgr Gammu gammu; do
        command -v "$t" >/dev/null 2>&1 && { echo "$t"; return 0; }
    done
    return 1
}

# ── scan backends ───────────────────────────────────────────────────────
# A survey writes one TSV row per cell:
#   rat  gen  arfcn  freq_mhz  plmn  mcc  mnc  operator  country  cell_id
#   tac_lac  band  rsrp_dbm  cipher  source  ts
crec_row() {
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$(crec_sanitize "${1:-}")"  "$(crec_sanitize "${2:-}")" \
        "$(crec_sanitize "${3:-}")"  "$(crec_sanitize "${4:-}")" \
        "$(crec_sanitize "${5:-}")"  "$(crec_sanitize "${6:-}")" \
        "$(crec_sanitize "${7:-}")"  "$(crec_sanitize "${8:-}")" \
        "$(crec_sanitize "${9:-}")"  "$(crec_sanitize "${10:-}")" \
        "$(crec_sanitize "${11:-}")" "$(crec_sanitize "${12:-}")" \
        "$(crec_sanitize "${13:-}")" "$(crec_sanitize "${14:-}")" \
        "$(crec_sanitize "${15:-}")" "$(crec_sanitize "${16:-}")"
}

crec_header() {
    printf 'rat\tgen\tarfcn\tfreq_mhz\tplmn\tmcc\tmnc\toperator\tcountry\tcell_id\ttac_lac\tband\trsrp_dbm\tcipher\tsource\tts\n'
}

# GSM survey via gr-gsm. Emits CellInfo lines the parser below consumes.
crec_scan_gsm() {
    local tool; tool=$(crec_find_gsm_scanner) || {
        printf 'ERROR\tno GSM scanner — install gr-gsm (grgsm_scanner)\n' >&2
        return 1
    }
    local band="${1:-GSM900}" out
    info "GSM survey on $band with $tool (~30s)..."
    case "$band" in
        GSM900)  out=$(timeout 30 "$tool" -b GSM900  2>/dev/null) ;;
        GSM1800) out=$(timeout 30 "$tool" -b DCS1800 2>/dev/null) ;;
        GSM850)  out=$(timeout 30 "$tool" -b GSM850  2>/dev/null) ;;
        GSM1900) out=$(timeout 30 "$tool" -b PCS1900 2>/dev/null) ;;
        *)       out=$(timeout 30 "$tool" 2>/dev/null) ;;
    esac
    [[ -z "$out" ]] && { printf 'ERROR\tGSM survey returned nothing — is the SDR attached?\n' >&2; return 1; }
    printf '%s\n' "$out"
}

# Parse a grgsm_scanner-style line into a TSV row.
# Observed shape: "ARFCN: 42, Freq: 931.4M, CID: 1234, LAC: 5678, MCC: 208, MNC: 01, ..."
crec_parse_gsm_line() {
    local line="$1"
    local arfcn freq cid lac mcc mnc
    arfcn=$(sed -n 's/.*ARFCN:[[:space:]]*\([0-9]*\).*/\1/p' <<<"$line")
    freq=$(sed -n 's/.*Freq:[[:space:]]*\([0-9.]*\).*/\1/p' <<<"$line")
    cid=$(sed -n 's/.*CID:[[:space:]]*\([0-9]*\).*/\1/p' <<<"$line")
    lac=$(sed -n 's/.*LAC:[[:space:]]*\([0-9]*\).*/\1/p' <<<"$line")
    mcc=$(sed -n 's/.*MCC:[[:space:]]*\([0-9]*\).*/\1/p' <<<"$line")
    mnc=$(sed -n 's/.*MNC:[[:space:]]*\([0-9]*\).*/\1/p' <<<"$line")
    [[ -z "$arfcn" ]] && return 1
    [[ -z "$freq" ]] && freq=$(crec_gsm_arfcn_to_mhz "$arfcn")
    local plmn="" op="" ctry=""
    if [[ -n "$mcc" && -n "$mnc" ]]; then
        plmn="${mcc}-${mnc}"
        op=$(crec_plmn_name "$plmn")
        ctry=$(crec_mcc_country "$mcc")
    fi
    crec_row "GSM" "2G" "$arfcn" "$freq" "$plmn" "$mcc" "$mnc" \
             "$op" "$ctry" "$cid" "$lac" "" "" "" "grgsm"
}

# LTE survey via srsRAN cell search, or a cell_info TSV if the user has one.
crec_scan_lte() {
    local tool; tool=$(crec_find_lte_scanner) || {
        printf 'ERROR\tno LTE scanner — install srsRAN (srsran / cell_search)\n' >&2
        return 1
    }
    info "LTE cell search with $tool (~30s)..."
    local out
    out=$(timeout 30 cell_search -b 7 2>/dev/null || timeout 30 "$tool" --cell_search 2>/dev/null)
    [[ -z "$out" ]] && { printf 'ERROR\tLTE cell search returned nothing — is the SDR attached and on band?\n' >&2; return 1; }
    printf '%s\n' "$out"
}

# Parse a cell_search line: "Found CELL ... pci=..., earfcn=..., plmn=20801, ..."
crec_parse_lte_line() {
    local line="$1"
    local earfcn pci plmn tac cell
    earfcn=$(sed -n 's/.*earfcn[=:][[:space:]]*\([0-9]*\).*/\1/p' <<<"$line")
    pci=$(sed -n 's/.*pci[=:][[:space:]]*\([0-9]*\).*/\1/p' <<<"$line")
    plmn=$(sed -n 's/.*plmn[=:][[:space:]]*\([0-9]*\).*/\1/p' <<<"$line")
    tac=$(sed -n 's/.*tac[=:][[:space:]]*\([0-9]*\).*/\1/p' <<<"$line")
    cell=$(sed -n 's/.*cell_id[=:][[:space:]]*\([0-9]*\).*/\1/p' <<<"$line")
    [[ -z "$earfcn" ]] && return 1
    local freq; freq=$(crec_lte_earfcn_to_mhz "$earfcn")
    local mcc="" mnc="" p=""
    if [[ "$plmn" =~ ^[0-9]{5,6}$ ]]; then
        mcc="${plmn:0:3}"; mnc="${plmn:3}"
        p="${mcc}-${mnc}"
    fi
    crec_row "LTE" "4G" "$earfcn" "$freq" "$p" "$mcc" "$mnc" \
             "$([[ -n "$p" ]] && crec_plmn_name "$p")" \
             "$([[ -n "$mcc" ]] && crec_mcc_country "$mcc")" \
             "${cell:-$pci}" "$tac" "" "" "" "srsran"
}

# ── capture-driven survey (no radio required) ───────────────────────────
# If a GSMTAP pcap is on disk, the survey can be built entirely from it.
# This is the path that works on any machine.
crec_scan_pcap() {
    local pcap="${1:-}"
    [[ -n "$pcap" && -f "$pcap" ]] || {
        printf 'ERROR\tno such capture: %s\n' "${pcap:-<none>}" >&2
        return 1
    }
    command -v tshark >/dev/null 2>&1 || {
        printf 'ERROR\tno tshark — install wireshark-cli to read captures\n' >&2
        return 1
    }
    info "surveying capture $pcap..."
    local n=0
    # GSMTAP carries the raw GSM/LTE message plus a type tag. The cell
    # identity fields land in gsmtap.* and the RRC/NAS layer.
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        crec_split "$line"
        rat="${CREC_F[0]:-}"; arfcn="${CREC_F[1]:-}"; plmn="${CREC_F[2]:-}"
        cid="${CREC_F[3]:-}"; tac="${CREC_F[4]:-}"
        [[ -z "$arfcn" ]] && continue
        local gen freq mcc mnc
        gen=$(crec_gen_of_rat "$rat")
        case "$gen" in
            2G) freq=$(crec_gsm_arfcn_to_mhz "$arfcn") ;;
            4G) freq=$(crec_lte_earfcn_to_mhz "$arfcn") ;;
            5G) freq=$(crec_nr_arfcn_to_mhz "$arfcn") ;;
            *)  freq="" ;;
        esac
        mcc=""; mnc=""
        [[ "$plmn" =~ ^([0-9]{3})([0-9]{2,3})$ ]] && { mcc="${BASH_REMATCH[1]}"; mnc="${BASH_REMATCH[2]}"; }
        crec_row "$rat" "$gen" "$arfcn" "$freq" \
                 "$([[ -n "$mcc" ]] && echo "${mcc}-${mnc}")" "$mcc" "$mnc" \
                 "$([[ -n "$mcc" ]] && crec_plmn_name "${mcc}-${mnc}")" \
                 "$([[ -n "$mcc" ]] && crec_mcc_country "$mcc")" \
                 "$cid" "$tac" "" "" "" "pcap"
        n=$((n + 1))
    done < <(tshark -r "$pcap" -T fields \
                -e gsmtap.type -e gsmtap.arfcn -e e212.mcc -e e212.mnc \
                -e gsm_a.cell_identity -e gsm_a.lac 2>/dev/null | head -500)
    [[ "$n" -eq 0 ]] && { printf 'ERROR\tno cell records found in %s\n' "$pcap" >&2; return 1; }
    info "$n cell records"
}

# ── persistence ─────────────────────────────────────────────────────────
crec_init_store() {
    mkdir -p "$CREC_DIR"
    [[ -f "$CREC_CELLS" ]] || crec_header > "$CREC_CELLS"
}

crec_store_rows() {
    # Rows arrive on stdin. The store keeps its own single header.
    crec_init_store
    local line
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        [[ "$line" == rat$'\t'* ]] && continue   # drop a repeated header
        printf '%s\n' "$line" >> "$CREC_CELLS"
    done
}

crec_cell_count() {
    [[ -f "$CREC_CELLS" ]] || { echo 0; return; }
    local n; n=$(tail -n +2 "$CREC_CELLS" 2>/dev/null | grep -c . || true)
    echo "${n:-0}"
}

crec_list_cells() {
    # An empty store still carries its header, so file size proves nothing.
    # The count is the only honest test.
    if [[ "$(crec_cell_count)" -eq 0 ]]; then
        warn "no cells surveyed yet"
        return 1
    fi
    crec_header
    tail -n +2 "$CREC_CELLS" | sort -u -k3,3n
}

crec_clear_cells() {
    crec_init_store
    crec_header > "$CREC_CELLS"
    ok "survey cleared"
}

crec_export_cells() {
    local ts; ts=$(date +%Y%m%d_%H%M%S)
    local out="$CREC_DIR/survey_${ts}.tsv"
    [[ "$(crec_cell_count)" -gt 0 ]] || { warn "nothing to export"; return 1; }
    cp "$CREC_CELLS" "$out"
    ok "exported to $out"
}

# ── CLI verbs ───────────────────────────────────────────────────────────
crec_cli_status_tsv() {
    local sdr scanner cells
    sdr=$(crec_find_sdr) || sdr="none"
    scanner=$(crec_find_gsm_scanner) || scanner="none"
    cells=$(crec_cell_count)
    printf 'sdr\t%s\n'          "$sdr"
    printf 'gsm_scanner\t%s\n'  "$scanner"
    printf 'lte_scanner\t%s\n'  "$(crec_find_lte_scanner || echo none)"
    printf 'cells\t%s\n'        "$cells"
    printf 'dir\t%s\n'          "$CREC_DIR"
    printf 'store\t%s\n'        "$CREC_CELLS"
}

crec_cmd_list_tsv() {
    # Same trap as crec_list_cells: a header-only store is empty, not present.
    if [[ "$(crec_cell_count)" -eq 0 ]]; then
        printf 'ERROR\tno survey store; run a scan first\n' >&2
        return 1
    fi
    tail -n +2 "$CREC_CELLS"
}

crec_cmd_scan() {
    local rat="${1:-gsm}" band="${2:-}"
    local rc=0
    case "$rat" in
        gsm)
            crec_init_store
            crec_scan_gsm "${band:-GSM900}" | while IFS= read -r l; do
                crec_parse_gsm_line "$l" || true
            done | crec_store_rows
            rc=${PIPESTATUS[0]} ;;
        lte)
            crec_init_store
            crec_scan_lte | while IFS= read -r l; do
                crec_parse_lte_line "$l" || true
            done | crec_store_rows
            rc=${PIPESTATUS[0]} ;;
        pcap)
            crec_init_store
            crec_scan_pcap "$band" | crec_store_rows
            rc=${PIPESTATUS[0]} ;;
        *)  printf 'ERROR\tunknown rat: %s (want gsm|lte|pcap)\n' "$rat" >&2; return 2 ;;
    esac
    local n; n=$(crec_cell_count)
    if [[ "$rc" -ne 0 ]]; then
        printf 'ERROR\tscan failed (rc=%s)\n' "$rc" >&2
        return "$rc"
    fi
    printf 'OK\t%s\n' "$n"
}

crec_cmd_arfcn() {
    local rat="${1:-}" n="${2:-}"
    [[ -n "$rat" && -n "$n" ]] || { printf 'ERROR\tusage: --arfcn <gsm|lte|nr> <N>\n' >&2; return 2; }
    local f rc=0
    case "$rat" in
        gsm) f=$(crec_gsm_arfcn_to_mhz "$n") || rc=1 ;;
        lte) f=$(crec_lte_earfcn_to_mhz "$n") || rc=1 ;;
        nr)  f=$(crec_nr_arfcn_to_mhz "$n") || rc=1 ;;
        *)   printf 'ERROR\tunknown rat: %s\n' "$rat" >&2; return 2 ;;
    esac
    if [[ "$rc" -ne 0 || -z "$f" ]]; then
        printf 'ERROR\tarfcn %s out of range for %s\n' "$n" "$rat" >&2
        return 1
    fi
    printf 'rat\t%s\narfcn\t%s\nfreq_mhz\t%s\n' "$rat" "$n" "$f"
}

crec_cmd_plmn() {
    local plmn="${1:-}"
    [[ "$plmn" =~ ^[0-9]{3}-?[0-9]{2,3}$ ]] || {
        printf 'ERROR\tusage: --plmn <MCC-MNC>\n' >&2; return 2
    }
    plmn="${plmn/-/}"
    local mcc="${plmn:0:3}" mnc="${plmn:3}"
    printf 'plmn\t%s-%s\nmcc\t%s\nmnc\t%s\noperator\t%s\ncountry\t%s\n' \
        "$mcc" "$mnc" "$mcc" "$mnc" \
        "$(crec_plmn_name "${mcc}-${mnc}")" "$(crec_mcc_country "$mcc")"
}

# ── selftest — no radio, no root, no network ────────────────────────────
crec_selftest() {
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad + 1)); fi
    }
    fld() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }

    local d out rc
    d=$(mktemp -d "$MOD_TMP/selftest.XXXXXX") || {
        printf 'ERROR\tmktemp failed under %s\n' "$MOD_TMP" >&2; return 1; }
    export LOOT_DIR="$d/loot"
    export CREC_DIR="$d/loot/cell_recon"
    export CREC_CELLS="$CREC_DIR/cells.tsv"

    # 1. ARFCN arithmetic against the 3GPP formulas, byte-exact.
    chk gsm-arfcn-1    "$(crec_gsm_arfcn_to_mhz 1)"     "890.2"
    chk gsm-arfcn-124  "$(crec_gsm_arfcn_to_mhz 124)"   "914.8"
    chk gsm-arfcn-512  "$(crec_gsm_arfcn_to_mhz 512)"   "1710.2"
    chk gsm-arfcn-885  "$(crec_gsm_arfcn_to_mhz 885)"   "1784.8"
    chk lte-earfcn-0   "$(crec_lte_earfcn_to_mhz 0)"    "2110.0"
    chk lte-earfcn-6300 "$(crec_lte_earfcn_to_mhz 6300)" "806.0"
    # The raster is piecewise. Test points INSIDE each segment, not just at a
    # band edge, because at an edge the offset term vanishes and a wrong raster
    # still gives the right answer.
    chk nr-arfcn-428000 "$(crec_nr_arfcn_to_mhz 428000)" "2140.000"   # <3 GHz, 5 kHz
    chk nr-arfcn-620000 "$(crec_nr_arfcn_to_mhz 620000)" "3300.000"   # band edge
    chk nr-arfcn-632628 "$(crec_nr_arfcn_to_mhz 632628)" "3489.420"   # inside n78
    chk nr-arfcn-653333 "$(crec_nr_arfcn_to_mhz 653333)" "3799.995"   # n78 top
    chk nr-arfcn-693334 "$(crec_nr_arfcn_to_mhz 693334)" "4400.010"   # n79 bottom
    chk nr-arfcn-2054166 "$(crec_nr_arfcn_to_mhz 2054166)" "26500.020" # FR2 n257
    chk nr-arfcn-oob    "$(crec_nr_arfcn_to_mhz 99999999 >/dev/null 2>&1; echo $?)" "1"
    chk nr-band-n41     "$(crec_nr_band_of_arfcn 500000)" "n41"
    chk nr-band-n79     "$(crec_nr_band_of_arfcn 700000)" "n79"
    # n77/n78 share an ARFCN window; the ambiguity is reported, not resolved.
    chk nr-band-ambig   "$(crec_nr_band_of_arfcn 632628)" "n77 n78"
    chk nr-band-none    "$(crec_nr_band_of_arfcn 123456 >/dev/null 2>&1; echo $?)" "1"

    # 2. Out-of-range must fail, not guess.
    chk gsm-arfcn-range   "$(crec_gsm_arfcn_to_mhz 9999 >/dev/null 2>&1; echo $?)" "1"
    chk gsm-arfcn-nonnum  "$(crec_gsm_arfcn_to_mhz abc >/dev/null 2>&1; echo $?)"  "1"
    chk lte-earfcn-range  "$(crec_lte_earfcn_to_mhz 99999 >/dev/null 2>&1; echo $?)" "1"

    # 3. PLMN lookup and the honest unknown.
    chk plmn-known   "$(crec_plmn_name 208-01)"  "Orange FR"
    chk plmn-unknown "$(crec_plmn_name 999-99)"  "unknown"
    chk mcc-country  "$(crec_mcc_country 262)"   "Germany"
    chk mcc-unknown  "$(crec_mcc_country 999)"   "unknown"

    # 4. Generation mapping.
    chk gen-gsm  "$(crec_gen_of_rat GSM)"  "2G"
    chk gen-lte  "$(crec_gen_of_rat LTE)"  "4G"
    chk gen-nr   "$(crec_gen_of_rat NR)"   "5G"
    chk gen-junk "$(crec_gen_of_rat XYZ)"  "?"

    # 5. TSV row shape: exactly 16 fields, and an operator name carrying a
    #    tab must not be able to forge a second row.
    crec_init_store
    local row
    row=$(crec_row "LTE" "4G" "6300" "806.0" "208-01" "208" "01" \
                  "Orange FR" "France" "123" "456" "" "" "" "selftest")
    chk row-fields   "$(printf '%s' "$row" | awk -F'\t' '{print NF}')" "16"
    chk row-rat      "$(printf '%s' "$row" | cut -f1)" "LTE"
    chk row-freq     "$(printf '%s' "$row" | cut -f4)" "806.0"

    local evil
    evil=$(crec_row "LTE" "4G" "1" "2" "3" "4" "5" $'Evil\tOperator\tRow' "9" "10" "11" "" "" "" "selftest")
    chk row-tab-injection "$(printf '%s' "$evil" | awk -F'\t' '{print NF}')" "16"

    # 6. Parse a real grgsm_scanner-shaped line.
    local parsed
    parsed=$(crec_parse_gsm_line \
      "ARFCN: 42, Freq: 931.4M, CID: 1234, LAC: 5678, MCC: 208, MNC: 01, CCCH: 0")
    chk parse-gsm-fields "$(printf '%s' "$parsed" | awk -F'\t' '{print NF}')" "16"
    chk parse-gsm-arfcn  "$(printf '%s' "$parsed" | cut -f3)" "42"
    chk parse-gsm-freq   "$(printf '%s' "$parsed" | cut -f4)" "931.4"
    chk parse-gsm-cid    "$(printf '%s' "$parsed" | cut -f10)" "1234"
    chk parse-gsm-op     "$(printf '%s' "$parsed" | cut -f8)" "Orange FR"
    chk parse-gsm-bad    "$(crec_parse_gsm_line 'not a cell line' >/dev/null 2>&1; echo $?)" "1"

    # 7. Parse a cell_search-shaped line.
    parsed=$(crec_parse_lte_line "Found CELL pci=123, earfcn=6300, plmn=20801, tac=456, cell_id=99")
    chk parse-lte-fields "$(printf '%s' "$parsed" | awk -F'\t' '{print NF}')" "16"
    chk parse-lte-rat    "$(printf '%s' "$parsed" | cut -f1)" "LTE"
    chk parse-lte-freq   "$(printf '%s' "$parsed" | cut -f4)" "806.0"
    chk parse-lte-plmn   "$(printf '%s' "$parsed" | cut -f5)" "208-01"
    chk parse-lte-bad    "$(crec_parse_lte_line 'nope' >/dev/null 2>&1; echo $?)" "1"

    # 8. Store: header exactly once, dedupe on read, count honest.
    #    Two *distinct* cells, plus one exact duplicate that sort -u must
    #    collapse, plus a stray header that must be dropped on write.
    local row2
    row2=$(crec_row "GSM" "2G" "42" "931.4" "208-01" "208" "01" \
                   "Orange FR" "France" "1234" "5678" "" "" "" "selftest")
    printf '%s\n%s\n%s\n' "$row" "$row2" "$row" | crec_store_rows
    crec_header | crec_store_rows           # a stray header must be dropped
    chk store-count       "$(crec_cell_count)" "3"
    chk store-header-once "$(grep -c '^rat' "$CREC_CELLS")" "1"
    chk list-tsv-rows     "$(crec_cmd_list_tsv | grep -c .)" "3"
    # list is deduped: the repeated LTE row collapses to one.
    chk list-rows         "$(crec_list_cells | tail -n +2 | grep -c .)" "2"

    # 9. Empty store must be an error, not an empty success.
    crec_clear_cells >/dev/null 2>&1
    chk clear-count     "$(crec_cell_count)" "0"
    chk list-empty-rc   "$(crec_cmd_list_tsv >/dev/null 2>&1; echo $?)" "1"
    chk export-empty-rc "$(crec_export_cells >/dev/null 2>&1; echo $?)"  "1"

    # 10. Verb validation.
    chk arfcn-missing-args "$(crec_cmd_arfcn >/dev/null 2>&1; echo $?)" "2"
    chk arfcn-bad-rat      "$(crec_cmd_arfcn watts 5 >/dev/null 2>&1; echo $?)" "2"
    chk plmn-bad           "$(crec_cmd_plmn "nope" >/dev/null 2>&1; echo $?)" "2"
    chk scan-bad-rat       "$(crec_cmd_scan nope >/dev/null 2>&1; echo $?)" "2"
    chk scan-pcap-nofile   "$(crec_cmd_scan pcap /nonexistent.pcap >/dev/null 2>&1; echo $?)" "1"

    out=$(crec_cmd_arfcn lte 6300); rc=$?
    chk arfcn-rc    "$rc" "0"
    chk arfcn-freq  "$(fld "$out" freq_mhz)" "806.0"
    out=$(crec_cmd_plmn 208-01)
    chk plmn-op     "$(fld "$out" operator)" "Orange FR"
    chk plmn-country "$(fld "$out" country)" "France"

    # 11. Status TSV contract. SDR presence is environment-dependent, so
    #     only the invariant fields are asserted.
    out=$(crec_cli_status_tsv)
    chk status-dir   "$(fld "$out" dir)"   "$CREC_DIR"
    chk status-store "$(fld "$out" store)" "$CREC_CELLS"
    chk status-cells "$(fld "$out" cells)" "0"

    rm -rf "$d"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ── menu ────────────────────────────────────────────────────────────────
crec_menu() {
    while true; do
        banner
        echo -e "  ${C_MAG}=== cell recon ===${C_RESET}"
        echo -e "  sdr:   ${C_GRN}$(crec_find_sdr || echo none)${C_RESET}"
        echo -e "  cells: ${C_GRN}$(crec_cell_count)${C_RESET}"
        echo -e "  store: ${C_DIM}$CREC_CELLS${C_RESET}\n"
        cat << 'M'
  [1]  GSM survey (900 MHz, ~30s)
  [2]  GSM survey (1800 MHz)
  [3]  LTE cell search
  [4]  survey from a GSMTAP pcap
  [5]  list surveyed cells
  [6]  export survey to loot
  [7]  clear survey
  [8]  ARFCN -> frequency
  [9]  PLMN -> operator
  [0]  back

M
        read -rp "  choice> " c || return 0  # EOF: leave the menu cleanly
        case "$c" in
            1) crec_cmd_scan gsm GSM900; read -rp "  press enter " _ ;;
            2) crec_cmd_scan gsm GSM1800; read -rp "  press enter " _ ;;
            3) crec_cmd_scan lte; read -rp "  press enter " _ ;;
            4)
                read -rp "  pcap path> " p
                crec_init_store
                crec_scan_pcap "$p" | crec_store_rows
                read -rp "  press enter " _ ;;
            5) crec_list_cells | column -t -s$'\t' 2>/dev/null || crec_list_cells
               read -rp "  press enter " _ ;;
            6) crec_export_cells; sleep 1 ;;
            7) crec_clear_cells; sleep 1 ;;
            8)
                read -rp "  rat (gsm|lte|nr)> " r
                read -rp "  arfcn> " n
                crec_cmd_arfcn "$r" "$n" | column -t -s$'\t' 2>/dev/null || crec_cmd_arfcn "$r" "$n"
                read -rp "  press enter " _ ;;
            9)
                read -rp "  plmn (MCC-MNC)> " p
                crec_cmd_plmn "$p" | column -t -s$'\t' 2>/dev/null || crec_cmd_plmn "$p"
                read -rp "  press enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ── shared radio target ─────────────────────────────────────────────────
# The cellular modules agree on a target kept in $TMP_DIR (target_arfcn,
# target_plmn). Nothing ever wrote those files, so picking a cell in the GUI
# could not affect what the next module acted on, and the GUI had no target
# to show. These two verbs give that shared state a writer and a reader.

crec_target_store() {
    local rat="${1:-}" arfcn="${2:-}" plmn="${3:-}"
    mkdir -p "$TMP_DIR" 2>/dev/null || true
    printf '%s\n' "$rat"   > "$TMP_DIR/target_rat"   2>/dev/null || true
    printf '%s\n' "$arfcn" > "$TMP_DIR/target_arfcn" 2>/dev/null || true
    printf '%s\n' "$plmn"  > "$TMP_DIR/target_plmn"  2>/dev/null || true
    printf 'rat\t%s\narfcn\t%s\nplmn\t%s\n' "$rat" "$arfcn" "$plmn"
}

crec_cmd_set_target() {
    local rat="${1:-}" arfcn="${2:-}" plmn="${3:-}"
    # All three empty means "forget the target", which is what the GUI's Clear
    # sends. Removing the files matters: leaving them behind would show no
    # target in the panel while every module still read the old one.
    if [[ -z "$rat" && -z "$arfcn" && -z "$plmn" ]]; then
        rm -f "$TMP_DIR/target_rat" "$TMP_DIR/target_arfcn" \
              "$TMP_DIR/target_plmn" 2>/dev/null || true
        printf 'selected\tno\n'
        return 0
    fi
    [[ -n "$rat" && -n "$arfcn" ]] || {
        printf 'ERROR\tusage: --set-target <rat> <arfcn> <plmn>\n' >&2
        return 2
    }
    crec_target_store "$rat" "$arfcn" "$plmn"
}

crec_cmd_target_tsv() {
    local rat="" arfcn="" plmn=""
    [[ -f "$TMP_DIR/target_rat"   ]] && rat=$(tr -d '[:space:]'   < "$TMP_DIR/target_rat")
    [[ -f "$TMP_DIR/target_arfcn" ]] && arfcn=$(tr -d '[:space:]' < "$TMP_DIR/target_arfcn")
    [[ -f "$TMP_DIR/target_plmn"  ]] && plmn=$(tr -d '[:space:]'  < "$TMP_DIR/target_plmn")
    if [[ -z "${rat}${arfcn}${plmn}" ]]; then
        printf 'selected\tno\n'
        return 1
    fi
    printf 'selected\tyes\nrat\t%s\narfcn\t%s\nplmn\t%s\n' "$rat" "$arfcn" "$plmn"
}

# ── CLI dispatch ────────────────────────────────────────────────────────
crec_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)   crec_cli_status_tsv ;;
        --list-tsv)     crec_cmd_list_tsv ;;
        --scan)         crec_cmd_scan "${1:-gsm}" "${2:-}" ;;
        --arfcn)        crec_cmd_arfcn "${1:-}" "${2:-}" ;;
        --plmn)         crec_cmd_plmn "${1:-}" ;;
        --set-target)   crec_cmd_set_target "${1:-}" "${2:-}" "${3:-}" ;;
        --target-tsv)   crec_cmd_target_tsv ;;
        --export)       crec_export_cells ;;
        --clear)        crec_clear_cells ;;
        --list)         crec_list_cells ;;
        --selftest)     crec_selftest ;;
        --menu)         crec_menu ;;
        *)
            cat >&2 <<EOF
Cell Recon — survey GSM/UMTS/LTE/NR cells

Usage: $0 COMMAND
  --status-tsv              tool and store state as TSV
  --scan <gsm|lte|pcap> [BAND|PCAP]   run a survey
  --list-tsv                surveyed cells as TSV
  --list                    surveyed cells, sorted for reading
  --arfcn <gsm|lte|nr> <N>  ARFCN/EARFCN to downlink MHz
  --plmn <MCC-MNC>          PLMN to operator and country
  --set-target <rat> <arfcn> <plmn>   record the shared radio target
  --target-tsv              current shared radio target as TSV
  --export                  copy the survey into loot/
  --clear                   empty the survey store
  --selftest                verify parsers and tables without a radio
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
    crec_cli_main "$@"
fi
