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
# The ARFCN raster alone does not name the band: 512..810 is valid for both
# DCS1800 and PCS1900, and only the operator (or the 0x8000 PCS flag in a
# GSMTAP header) knows which. So the band is resolved first, and the numeric
# ranges are stated once, here.
#
#   GSM900   1..124    uplink F = 890  + 0.2*N        duplex +45
#   GSM850   128..251  uplink F = 824  + 0.2*N        duplex +45
#   DCS1800  512..885  uplink F = 1710 + 0.2*(N-511)  duplex +95
#   PCS1900  512..810  uplink F = 1850 + 0.2*(N-512)  duplex +80
#
# ARFCN 0 and the 975..1023 range are the GSM900 extension band; they are left
# out on purpose rather than mapped by a guess.
crec_gsm_arfcn_band() {
    local arfcn="$1" hint="${2:-}"
    [[ "$arfcn" =~ ^[0-9]+$ ]] || return 1
    case "$hint" in
        pcs|1900|pcs1900) (( arfcn >= 512 && arfcn <= 810 )) && { echo pcs1900; return 0; }; return 1 ;;
        dcs|1800|dcs1800) (( arfcn >= 512 && arfcn <= 885 )) && { echo dcs1800; return 0; }; return 1 ;;
    esac
    if   (( arfcn >= 1   && arfcn <= 124 )); then echo gsm900
    elif (( arfcn >= 128 && arfcn <= 251 )); then echo gsm850
    elif (( arfcn >= 512 && arfcn <= 885 )); then echo dcs1800
    elif (( arfcn >= 512 && arfcn <= 810 )); then echo pcs1900
    else return 1
    fi
}

# MHz the downlink sits above the uplink for a band.
crec_gsm_duplex_mhz() {
    case "$1" in
        gsm900|gsm850) echo 45 ;;
        dcs1800)       echo 95 ;;
        pcs1900)       echo 80 ;;
        *)             return 1 ;;
    esac
}

# GSM ARFCN -> uplink MHz. Same call shape and same numbers as always; the
# optional second argument only breaks the 1800/1900 tie.
crec_gsm_arfcn_to_mhz() {
    local arfcn="$1" hint="${2:-}" band
    band=$(crec_gsm_arfcn_band "$arfcn" "$hint") || return 1
    case "$band" in
        gsm900)  awk -v n="$arfcn" 'BEGIN{printf "%.1f", 890 + 0.2*n}' ;;
        gsm850)  awk -v n="$arfcn" 'BEGIN{printf "%.1f", 824 + 0.2*n}' ;;
        dcs1800) awk -v n="$arfcn" 'BEGIN{printf "%.1f", 1710 + 0.2*(n-511)}' ;;
        pcs1900) awk -v n="$arfcn" 'BEGIN{printf "%.1f", 1850 + 0.2*(n-512)}' ;;
        *)       return 1 ;;
    esac
}

# The frequency a receiver has to sit on to hear this ARFCN in that direction.
crec_gsm_arfcn_to_mhz_dir() {
    local arfcn="$1" dir="${2:-ul}" hint="${3:-}" band ul dup
    band=$(crec_gsm_arfcn_band "$arfcn" "$hint") || return 1
    ul=$(crec_gsm_arfcn_to_mhz "$arfcn" "$band") || return 1
    [[ "$dir" == "dl" || "$dir" == "downlink" ]] || { printf '%s' "$ul"; return 0; }
    dup=$(crec_gsm_duplex_mhz "$band") || return 1
    awk -v f="$ul" -v d="$dup" 'BEGIN{printf "%.1f", f + d}'
}

# The LTE band raster, written down once. Two readers need it: the frequency
# lookup (F = F_low + 0.1*(N - N_offs)) and the band NAME. Keeping the numbers
# in one function is what stops a band being added to the frequency table and
# never reaching the inventory, which would then report a measured channel as
# belonging to no band at all.
#
#   band  low_MHz  N_offs  N_lo  N_hi
#
# printf rather than a here-document on purpose: the separator has to be a real
# tab, and `awk -F'\t'` under mawk matches a literal backslash-t (AGENTS.md §11).
crec_lte_band_raster() {
    printf '1\t2110\t0\t0\t599\n'
    printf '2\t1930\t600\t600\t1199\n'
    printf '3\t1805\t1200\t1200\t1949\n'
    printf '4\t2110\t1950\t1950\t2399\n'
    printf '5\t869\t2400\t2400\t2649\n'
    printf '7\t2620\t2750\t2750\t3449\n'
    printf '8\t925\t3450\t3450\t3799\n'
    printf '20\t791\t6150\t6150\t6449\n'
    printf '28\t758\t9210\t9210\t9659\n'
    printf '38\t2570\t37750\t37750\t38249\n'
    printf '40\t2300\t38650\t38650\t39649\n'
    printf '41\t2496\t39650\t39650\t41589\n'
}

# LTE EARFCN -> downlink MHz.
crec_lte_earfcn_to_mhz() {
    local earfcn="$1"
    [[ "$earfcn" =~ ^[0-9]+$ ]] || return 1
    crec_lte_band_raster | awk -F'\t' -v n="$earfcn" '
        $4 <= n && n <= $5 { printf "%.1f", $2 + 0.1*(n - $3); hit = 1; exit }
        END { if (!hit) exit 1 }'
}

# EARFCN -> band name. A survey backend that does not report the band is not
# the same as a channel that belongs to no band: the raster decides it, so the
# band is derivable and does not have to be reported as unobserved.
crec_lte_band_of_earfcn() {
    local earfcn="$1"
    [[ "$earfcn" =~ ^[0-9]+$ ]] || return 1
    crec_lte_band_raster | awk -F'\t' -v n="$earfcn" '
        $4 <= n && n <= $5 { print $1; hit = 1; exit }
        END { if (!hit) exit 1 }'
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
# The register-backed answer, with the three states the toolkit insists on:
#   <name>            the MCC/MNC is in the downloaded register
#   unknown           the register was read and has no such assignment
#   unknown (silent)  nobody ran tools/fetch-reference-data.sh, so nothing
#                     was read -- an unobserved answer, not a negative one
#
# A hardcoded table used to sit here: 31 PLMNs and 20 MCCs. Every survey
# outside Western Europe read "unknown" and the field looked like it was
# answering when it was only guessing. The table now lives in
# data/public/plmn.tsv, rebuilt by tools/fetch-reference-data.sh.
crec_refdata="${IMSISTING_ROOT:-$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}/tools/lib/refdata.sh"
if [[ -r "$crec_refdata" ]]; then
    # shellcheck source=tools/lib/refdata.sh
    source "$crec_refdata"
fi

crec_plmn_registry() {  # <mcc> <mnc> -> "operator<TAB>country"
    declare -F refdata_plmn >/dev/null 2>&1 || return 1
    local out; out=$(refdata_plmn "${1:-}" "${2:-}") || return 1
    local state="${out%%$'\t'*}"
    local rest="${out#*$'\t'}"
    [[ "$state" == "ok" ]] || return 1
    printf '%s' "$rest"
}

crec_plmn_name() {
    local plmn="$1" mcc="" mnc="" got
    [[ "$plmn" =~ ^([0-9]{3})-?([0-9]{2,3})$ ]] || { printf 'unknown'; return 0; }
    mcc="${BASH_REMATCH[1]}"; mnc="${BASH_REMATCH[2]}"
    if got=$(crec_plmn_registry "$mcc" "$mnc"); then
        printf '%s' "${got%%$'\t'*}"
        return 0
    fi
    if declare -F refdata_plmn >/dev/null 2>&1 && [[ -f "${REFDATA_PUBLIC:-}/plmn.tsv" ]]; then
        printf 'unknown'
    else
        printf 'unknown (silent)'
    fi
}

# MCC -> country, from the same register: the country of any of that MCC's
# assignments. Still returns "unknown (silent)" when nothing was downloaded,
# because "this MCC is unassigned" and "I have no register" are not the same.
crec_mcc_country() {
    local mcc="${1:-}" file got
    [[ "$mcc" =~ ^[0-9]{3}$ ]] || { printf 'unknown'; return 0; }
    file="${REFDATA_PUBLIC:-}/plmn.tsv"
    if [[ -f "$file" ]]; then
        got=$(awk -F'\t' -v mcc="$mcc" 'NR > 1 && $1 == mcc { print $3; exit }' "$file" 2>/dev/null)
        if [[ -n "$got" ]]; then printf '%s' "$got"; else printf 'unknown'; fi
        return 0
    fi
    printf 'unknown (silent)'
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

# ── inventory export ────────────────────────────────────────────────────
# A survey is worth what another tool can do with it. The store stays a TSV
# because that is the cheapest thing for this module to append to, but the
# consumers of a cell list are a spreadsheet (csv), a map (kml, geojson), a
# network mapper (nmap) and a script — none of which want to be taught this
# module's header. One verb writes all of them.
#
# Each format names what it is missing instead of writing a half file. A CSV
# with no rows, a KML with no placemarks and an nmap fragment with no hosts all
# read as a successful export of an empty world, which is the one answer this
# toolkit exists not to give.

# Every format asks this one question first, for the same reason: the cheapest
# wrong answer in this module is a well-formed file that describes nothing, and
# a caller cannot tell it from a survey that found nothing.
crec_export_need_cells() {
    if [[ "$(crec_cell_count)" -gt 0 ]]; then return 0; fi
    printf 'MISSING\tsurveyed cells\n' >&2
    printf 'WHY\tthe store holds no observation rows yet, and a file exported from nothing cannot be told apart from a survey that found nothing — run --scan, --node or a pcap survey first\n' >&2
    return 1
}

# Where this export is going. Named survey_<ts>.<ext> like the TSV copy always
# was, so four formats of one survey sort together in the loot directory.
crec_export_out() {
    local ts; ts=$(date +%Y%m%d_%H%M%S)
    printf '%s/survey_%s.%s' "$CREC_DIR" "$ts" "$1"
}

# An operator name is whatever the network advertised, and an & in it turns a
# KML or an nmap fragment into a file no consumer will open.
crec_xml_escape() {
    printf '%s' "${1:-}" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' \
                                  -e 's/"/\&quot;/g' -e "s/'/\&apos;/g"
}

# Tabs, CR and LF cannot reach a stored row: crec_sanitize replaces them before
# the row is written. What is left to protect in a JSON string is the backslash
# and the quote, either of which turns an operator name into a broken file.
crec_json_escape() {
    printf '%s' "${1:-}" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

# One TSV row on stdin -> one CSV line on stdout. Quoted where a field could
# break the row: the row shape is the contract the consumer parses, and an
# operator name carrying a comma silently shifts every column after it.
crec_csv_line() {
    awk -F'\t' '{
        line = ""
        for (i = 1; i <= NF; i++) {
            f = $i
            if (f ~ /[,"]/) { gsub(/"/, "\"\"", f); f = "\"" f "\"" }
            line = line (i > 1 ? "," : "") f
        }
        print line
    }'
}

# The frequency of an ARFCN in whichever raster owns that RAT. A node report and
# an old store both carry empty columns for fields their source never had, and
# an export still has to say what channel the cell is on rather than "unknown"
# next to an ARFCN the module already knows how to place.
crec_arfcn_freq() {   # <rat> <arfcn>
    local rat="${1:-}" arfcn="${2:-}"
    [[ "$arfcn" =~ ^[0-9]+$ ]] || return 1
    case "$(crec_gen_of_rat "$rat")" in
        2G) crec_gsm_arfcn_to_mhz "$arfcn" ;;
        4G) crec_lte_earfcn_to_mhz "$arfcn" ;;
        5G) crec_nr_arfcn_to_mhz "$arfcn" ;;
        *)  return 1 ;;
    esac
}

# The band a stored row belongs to: <rat> <arfcn> <band column>.
#
# The store's own band column wins when a backend filled it; when it is empty
# the band is derived from the ARFCN by the same raster the frequency came
# from. An ARFCN that names MORE than one band is reported as the list it is
# (GSM 512..810 is DCS1800 or PCS1900, and n77/n78 share a window) rather than
# resolved by a guess: the bands sit tens of MHz apart and which one it is
# decides where a receiver has to be parked. A caller that needs one band
# counts that row as ambiguous instead of inventing an answer.
crec_row_band() {
    local rat="${1:-}" arfcn="${2:-}" col="${3:-}" b
    if [[ -n "$col" ]]; then printf '%s' "$col"; return 0; fi
    [[ "$arfcn" =~ ^[0-9]+$ ]] || return 1
    case "$(crec_gen_of_rat "$rat")" in
        2G)
            (( arfcn >= 512 && arfcn <= 810 )) && { printf 'dcs1800 pcs1900'; return 0; }
            b=$(crec_gsm_arfcn_band "$arfcn") || return 1
            printf '%s' "$b" ;;
        4G) b=$(crec_lte_band_of_earfcn "$arfcn") || return 1; printf '%s' "$b" ;;
        5G) b=$(crec_nr_band_of_arfcn "$arfcn") || return 1; printf '%s' "$b" ;;
        *)  return 1 ;;
    esac
}

# ── the position join ───────────────────────────────────────────────────
# Where the receiver stood is not in the store. The TSV contract has no
# coordinate column, and inventing one would put a position on a row that never
# had a fix — so an export that needs coordinates joins the cells against a
# positions file instead, and refuses when there is none.
#
# Two files can supply that join, in this order:
#   1. $CREC_DIR/positions.tsv        this module's own sidecar, columns
#                                     rat arfcn cell_id lat lon source
#   2. $LOOT_DIR/tower_map/points.tsv  what 04_tower_map stamped on these same
#                                     cells when it surveyed through this module
#
# The key is (rat, arfcn, cell_id) and not the PLMN: a cell heard before its
# PLMN was decoded still has to be placeable on a map.
crec_positions_file() {   # -> "kind<TAB>path", or non-zero when there is none
    local side="$CREC_DIR/positions.tsv"
    local tmap="$LOOT_DIR/tower_map/points.tsv"
    if [[ -f "$side" ]] && tail -n +2 "$side" 2>/dev/null | grep -q .; then
        printf 'sidecar\t%s' "$side"; return 0
    fi
    if [[ -f "$tmap" ]] && tail -n +2 "$tmap" 2>/dev/null | grep -q .; then
        printf 'tower_map\t%s' "$tmap"; return 0
    fi
    return 1
}

# The join canonicalised to rat<TAB>arfcn<TAB>cell_id<TAB>lat<TAB>lon. A row
# whose coordinate is not a number is dropped here rather than at the writer: a
# positions file with "n/a" in a latitude must not reach a KML or a GeoJSON and
# make the whole file unparseable.
crec_positions_rows() {
    local src kind path
    src=$(crec_positions_file) || return 1
    kind="${src%%$'\t'*}"; path="${src#*$'\t'}"
    case "$kind" in
        sidecar)
            tail -n +2 "$path" | awk -F'\t' '
                NF >= 5 && $4 ~ /^-?[0-9]+(\.[0-9]+)?$/ && $5 ~ /^-?[0-9]+(\.[0-9]+)?$/ {
                    printf "%s\t%s\t%s\t%s\t%s\n", $1, $2, $3, $4, $5 }' ;;
        tower_map)
            tail -n +2 "$path" | awk -F'\t' '
                NF >= 10 && $2 ~ /^-?[0-9]+(\.[0-9]+)?$/ && $3 ~ /^-?[0-9]+(\.[0-9]+)?$/ {
                    printf "%s\t%s\t%s\t%s\t%s\n", $6, $8, $10, $2, $3 }' ;;
        *) return 1 ;;
    esac
}

# "lat<TAB>lon" for one cell, or non-zero. Scanned per call because the join is
# a survey rather than a tower database, and an index would be one more thing
# to keep in step with the file it indexes.
crec_position_of() {   # <rat> <arfcn> <cell_id>
    crec_positions_rows 2>/dev/null | awk -F'\t' -v r="${1:-}" -v a="${2:-}" -v c="${3:-}" '
        $1 == r && $2 == a && $3 == c { printf "%s\t%s", $4, $5; hit = 1; exit }
        END { if (!hit) exit 1 }'
}

# Distinct cells, not distinct rows: <rat> <arfcn> <plmn> <cell_id>. A cell
# heard forty times in one survey is one cell with forty observations, and an
# inventory that counts rows reports a street as a network.
crec_cell_identities() {
    tail -n +2 "$CREC_CELLS" 2>/dev/null | cut -f1,3,5,10 | sort -u
}

# CSV, because the cells are already a table and a spreadsheet is the tool most
# people reach for. Written as real CSV — quoted where a field would break the
# row — rather than a copy of the TSV with the tabs renamed, which is what the
# bare --export does and what a spreadsheet reads as a single column.
crec_export_csv() {
    crec_export_need_cells || return 1
    local out line; out=$(crec_export_out csv)
    {
        crec_header | crec_csv_line
        tail -n +2 "$CREC_CELLS" | grep . | while IFS= read -r line; do
            printf '%s\n' "$line" | crec_csv_line
        done
    } > "$out"
    printf 'OK\t%s\n' "$out"
}

# KML, because a cell survey ends on a map. One placemark per cell, with the
# band, the ARFCN and the PCI in the description so a pin explains itself to
# whoever opens the file without this toolkit. A cell with no position cannot
# be placed: it is counted in a NOTE, and a store where nothing at all is
# placeable is refused rather than written out as an empty map.
crec_export_kml() {
    crec_export_need_cells || return 1
    local src
    src=$(crec_positions_file) || {
        printf 'MISSING\tposition fix for the cells\n' >&2
        printf 'WHY\tKML places each cell at a coordinate and the survey store has no coordinate column, so either survey through 04_tower_map (which stamps a fix on these same cells) or write %s/positions.tsv\n' "$CREC_DIR" >&2
        return 1
    }
    local bodyf; bodyf="$MOD_TMP/export_kml.$$"
    : > "$bodyf"
    local placed=0 unplaced=0 line
    local -A seen=()
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        crec_split "$line"
        local rat="${CREC_F[0]:-}" gen="${CREC_F[1]:-}" arfcn="${CREC_F[2]:-}"
        local freq="${CREC_F[3]:-}" plmn="${CREC_F[4]:-}" op="${CREC_F[7]:-}"
        local cell="${CREC_F[9]:-}" bandc="${CREC_F[11]:-}" rsrp="${CREC_F[12]:-}"
        local key="$rat|$arfcn|$plmn|$cell" latlon lat lon band
        [[ -n "${seen[$key]:-}" ]] && continue
        seen[$key]=1
        if ! latlon=$(crec_position_of "$rat" "$arfcn" "$cell"); then
            unplaced=$((unplaced + 1)); continue
        fi
        lat="${latlon%%$'\t'*}"; lon="${latlon#*$'\t'}"
        band=$(crec_row_band "$rat" "$arfcn" "$bandc" 2>/dev/null || true)
        [[ -n "$freq" ]] || freq=$(crec_arfcn_freq "$rat" "$arfcn" 2>/dev/null || true)
        {
            printf '    <Placemark>\n'
            printf '      <name>%s %s</name>\n' \
                "$(crec_xml_escape "$rat")" "$(crec_xml_escape "${cell:-unidentified}")"
            printf '      <description>%s</description>\n' \
                "$(crec_xml_escape "rat=$rat gen=$gen band=${band:-unobserved} arfcn=${arfcn:-unobserved} freq=${freq:-unobserved}MHz pci=${cell:-unobserved} plmn=${plmn:-unobserved} rsrp=${rsrp:-unobserved} operator=${op:-unobserved}")"
            printf '      <styleUrl>#cell</styleUrl>\n'
            printf '      <Point><coordinates>%s,%s,0</coordinates></Point>\n' "$lon" "$lat"
            printf '    </Placemark>\n'
        } >> "$bodyf"
        placed=$((placed + 1))
    done < <(tail -n +2 "$CREC_CELLS")
    if (( placed == 0 )); then
        rm -f "$bodyf"
        printf 'MISSING\tposition fix for at least one cell in the store\n' >&2
        printf 'WHY\t%s has rows but none of them match a cell this store knows, so every placemark would be missing and the file would be an empty map\n' "${src#*$'\t'}" >&2
        return 1
    fi
    local out; out=$(crec_export_out kml)
    {
        printf '<?xml version="1.0" encoding="UTF-8"?>\n'
        printf '<kml xmlns="http://www.opengis.net/kml/2.2">\n'
        printf '  <Document>\n'
        printf '    <name>IMSIsting cell inventory</name>\n'
        printf '    <description>%s cell(s) placed, %s without a position, positions from %s, generated %s</description>\n' \
            "$placed" "$unplaced" "${src%%$'\t'*}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf '    <Style id="cell"><IconStyle><color>ffd9b34f</color><scale>0.8</scale>'
        printf '<Icon><href>http://maps.google.com/mapfiles/kml/shapes/placemark_circle.png</href></Icon>'
        printf '</IconStyle></Style>\n'
        cat "$bodyf"
        printf '  </Document>\n'
        printf '</kml>\n'
    } > "$out"
    rm -f "$bodyf"
    printf 'OK\t%s\n' "$out"
    printf 'positions\t%s\t%s\n' "${src%%$'\t'*}" "${src#*$'\t'}"
    if (( unplaced > 0 )); then
        printf 'NOTE\t%s of %s cell(s) had no position and are not on the map\n' \
            "$unplaced" "$((placed + unplaced))"
    fi
    return 0
}

# GeoJSON, because a map is a consumer of this store and nothing here should be
# map-shaped only for Google. One Point feature per cell. The properties are the
# store's own columns, read from the store's own header line, so a column added
# to the survey contract cannot be exported under a name this function invented.
crec_export_geojson() {
    crec_export_need_cells || return 1
    local src
    src=$(crec_positions_file) || {
        printf 'MISSING\tposition fix for the cells\n' >&2
        printf 'WHY\ta GeoJSON Point is a coordinate and the survey store has no coordinate column, so either survey through 04_tower_map or write %s/positions.tsv\n' "$CREC_DIR" >&2
        return 1
    }
    local -a keys=()
    local k
    while IFS= read -r k; do
        [[ -n "$k" ]] && keys+=("$k")
    done < <(head -1 "$CREC_CELLS" 2>/dev/null | tr '\t' '\n')
    if (( ${#keys[@]} == 0 )); then
        printf 'MISSING\tstore header\n' >&2
        printf 'WHY\tthe feature properties are named after the store columns, and this store has no header line to read those names from\n' >&2
        return 1
    fi
    local bodyf; bodyf="$MOD_TMP/export_geojson.$$"
    : > "$bodyf"
    local placed=0 unplaced=0 line
    local -A seen=()
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        crec_split "$line"
        local rat="${CREC_F[0]:-}" arfcn="${CREC_F[2]:-}"
        local plmn="${CREC_F[4]:-}" cell="${CREC_F[9]:-}"
        local key="$rat|$arfcn|$plmn|$cell" latlon lat lon
        [[ -n "${seen[$key]:-}" ]] && continue
        seen[$key]=1
        if ! latlon=$(crec_position_of "$rat" "$arfcn" "$cell"); then
            unplaced=$((unplaced + 1)); continue
        fi
        lat="${latlon%%$'\t'*}"; lon="${latlon#*$'\t'}"
        local props="" i
        for i in "${!keys[@]}"; do
            props="$props${props:+,}\"$(crec_json_escape "${keys[$i]}")\":\"$(crec_json_escape "${CREC_F[$i]:-}")\""
        done
        {
            (( placed > 0 )) && printf ',\n'
            printf '{"type":"Feature","geometry":{"type":"Point","coordinates":[%s,%s]},' "$lon" "$lat"
            printf '"properties":{%s}}' "$props"
        } >> "$bodyf"
        placed=$((placed + 1))
    done < <(tail -n +2 "$CREC_CELLS")
    if (( placed == 0 )); then
        rm -f "$bodyf"
        printf 'MISSING\tposition fix for at least one cell in the store\n' >&2
        printf 'WHY\t%s has rows but none of them match a cell this store knows, so the FeatureCollection would carry no features\n' "${src#*$'\t'}" >&2
        return 1
    fi
    local out; out=$(crec_export_out geojson)
    {
        printf '{"type":"FeatureCollection","generator":"IMSIsting 02_cell_recon",'
        printf '"positions_from":"%s",' "$(crec_json_escape "${src%%$'\t'*}")"
        printf '"features":[\n'
        cat "$bodyf"
        printf '\n]}\n'
    } > "$out"
    rm -f "$bodyf"
    printf 'OK\t%s\n' "$out"
    printf 'positions\t%s\t%s\n' "${src%%$'\t'*}" "${src#*$'\t'}"
    if (( unplaced > 0 )); then
        printf 'NOTE\t%s of %s cell(s) had no position and have no feature\n' \
            "$unplaced" "$((placed + unplaced))"
    fi
    return 0
}

# nmap's XML, because the usual consumer of a cell list is a network mapper and
# this is the shape it already reads. Nothing is invented for the cells — they
# are not IP hosts, so there is no address, no port and no MAC to make up. One
# <host> per cell: the identity in <hostnames>, the measurement in a host
# script, which is where a mapper already looks for facts that are not a port
# scan.
crec_export_nmap() {
    crec_export_need_cells || return 1
    local bodyf; bodyf="$MOD_TMP/export_nmap.$$"
    : > "$bodyf"
    local n=0 line
    local -A seen=()
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        crec_split "$line"
        local rat="${CREC_F[0]:-}" gen="${CREC_F[1]:-}" arfcn="${CREC_F[2]:-}"
        local freq="${CREC_F[3]:-}" plmn="${CREC_F[4]:-}" mcc="${CREC_F[5]:-}"
        local mnc="${CREC_F[6]:-}" op="${CREC_F[7]:-}" ctry="${CREC_F[8]:-}"
        local cell="${CREC_F[9]:-}" tac="${CREC_F[10]:-}" bandc="${CREC_F[11]:-}"
        local rsrp="${CREC_F[12]:-}" cipher="${CREC_F[13]:-}" srcd="${CREC_F[14]:-}"
        local ts="${CREC_F[15]:-}"
        local key="$rat|$arfcn|$plmn|$cell" band label summary
        [[ -n "${seen[$key]:-}" ]] && continue
        seen[$key]=1
        band=$(crec_row_band "$rat" "$arfcn" "$bandc" 2>/dev/null || true)
        [[ -n "$freq" ]] || freq=$(crec_arfcn_freq "$rat" "$arfcn" 2>/dev/null || true)
        label="$rat-${plmn:-noplmn}-${cell:-nocell}"
        summary="$rat ${plmn:-noplmn} cell ${cell:-unidentified} band=${band:-unobserved} arfcn=${arfcn:-unobserved} freq=${freq:-unobserved}MHz rsrp=${rsrp:-unobserved}"
        {
            printf '<host>\n'
            printf '  <status state="up" reason="cell-observed"/>\n'
            printf '  <hostnames><hostname name="%s" type="user"/></hostnames>\n' \
                "$(crec_xml_escape "$label")"
            printf '  <hostscript>\n'
            printf '    <script id="cell-recon" output="%s">\n' "$(crec_xml_escape "$summary")"
            printf '      <elem key="rat">%s</elem>\n'      "$(crec_xml_escape "$rat")"
            printf '      <elem key="gen">%s</elem>\n'      "$(crec_xml_escape "$gen")"
            printf '      <elem key="arfcn">%s</elem>\n'    "$(crec_xml_escape "$arfcn")"
            printf '      <elem key="freq_mhz">%s</elem>\n' "$(crec_xml_escape "$freq")"
            printf '      <elem key="plmn">%s</elem>\n'     "$(crec_xml_escape "$plmn")"
            printf '      <elem key="mcc">%s</elem>\n'      "$(crec_xml_escape "$mcc")"
            printf '      <elem key="mnc">%s</elem>\n'      "$(crec_xml_escape "$mnc")"
            printf '      <elem key="operator">%s</elem>\n' "$(crec_xml_escape "$op")"
            printf '      <elem key="country">%s</elem>\n'  "$(crec_xml_escape "$ctry")"
            printf '      <elem key="cell_id">%s</elem>\n'  "$(crec_xml_escape "$cell")"
            printf '      <elem key="tac_lac">%s</elem>\n'  "$(crec_xml_escape "$tac")"
            printf '      <elem key="band">%s</elem>\n'     "$(crec_xml_escape "${band:-unobserved}")"
            printf '      <elem key="rsrp_dbm">%s</elem>\n' "$(crec_xml_escape "$rsrp")"
            printf '      <elem key="cipher">%s</elem>\n'   "$(crec_xml_escape "$cipher")"
            printf '      <elem key="source">%s</elem>\n'   "$(crec_xml_escape "$srcd")"
            printf '      <elem key="ts">%s</elem>\n'       "$(crec_xml_escape "$ts")"
            printf '    </script>\n'
            printf '  </hostscript>\n'
            printf '</host>\n'
        } >> "$bodyf"
        n=$((n + 1))
    done < <(tail -n +2 "$CREC_CELLS")
    local out; out=$(crec_export_out xml)
    {
        printf '<?xml version="1.0" encoding="UTF-8"?>\n'
        printf '<!-- IMSIsting 02_cell_recon cell inventory: %s cell(s), generated %s.\n' "$n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf '     Cells are not network hosts. Each <host> carries a cell identity in\n'
        printf '     <hostnames> and its measurement in a host script, so a consumer that\n'
        printf '     walks host/script reads exactly what the store TSV holds. -->\n'
        printf '<nmaprun scanner="imsisting-cell-recon" args="--export nmap" start="%s">\n' "$(date +%s)"
        cat "$bodyf"
        printf '<runstats><finished time="%s" timestr="%s"/><hosts up="%s" down="0" total="%s"/></runstats>\n' \
            "$(date +%s)" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$n" "$n"
        printf '</nmaprun>\n'
    } > "$out"
    rm -f "$bodyf"
    printf 'OK\t%s\n' "$out"
    printf 'hosts\t%s\n' "$n"
}

# One export verb with the format as its argument, because the caller knows the
# format and the module should not grow a verb per format: five export buttons
# for one job is five places for a label to lie about what it wrote.
crec_cmd_export() {
    local fmt="${1:-tsv}"
    case "$fmt" in
        tsv)     crec_export_cells ;;
        csv)     crec_export_csv ;;
        kml)     crec_export_kml ;;
        geojson) crec_export_geojson ;;
        nmap)    crec_export_nmap ;;
        *)
            printf 'ERROR\tunknown export format: %s\n' "$(crec_sanitize "$fmt")" >&2
            printf 'ERROR\twant one of: tsv csv kml geojson nmap\n' >&2
            return 2 ;;
    esac
}

# ── inventory ───────────────────────────────────────────────────────────
# Everything that consumes this store asks the same five questions before it can
# decide what to do: how many cells, which bands, whose networks, which of them
# have a position and which do not. Answering those by hand out of the TSV is
# where "it looked like one cell" comes from, so this verb answers them once.
#
# The rule the shape is built on: a count of zero and a dimension nobody
# measured must not look alike. Where the store cannot answer, the row says
# unobserved and carries the reason, so nothing downstream can read silence as
# "none found".
crec_cmd_inventory() {
    crec_export_need_cells || return 1
    local n distinct reasons=""
    n=$(crec_cell_count)
    printf 'cells\t%s\n' "$n"
    distinct=$(crec_cell_identities | grep -c . || true)
    printf 'distinct_cells\t%s\n' "${distinct:-0}"

    # Bands, counted over distinct ARFCNs rather than rows: one channel heard
    # forty times is one band.
    local -A bseen=()
    local pair btok unobs=0 amb=0
    while IFS= read -r pair; do
        [[ -n "$pair" ]] || continue
        crec_split "$pair"
        btok=$(crec_row_band "${CREC_F[0]:-}" "${CREC_F[1]:-}" "${CREC_F[2]:-}" 2>/dev/null || true)
        if [[ -z "$btok" ]];      then unobs=$((unobs + 1))
        elif [[ "$btok" == *" "* ]]; then amb=$((amb + 1))
        else bseen[$btok]=1; fi
    done < <(tail -n +2 "$CREC_CELLS" | cut -f1,3,12 | sort -u)
    if (( ${#bseen[@]} > 0 )); then
        printf 'distinct_bands\t%s\n' "${#bseen[@]}"
    else
        printf 'distinct_bands\tunobserved\tevery ARFCN in the store falls outside the band rasters this module carries, so the number of bands cannot be counted\n'
        reasons="$reasons DISTINCT_BANDS"
    fi
    printf 'bands_unobserved\t%s\n' "$unobs"
    printf 'bands_ambiguous\t%s\n' "$amb"

    # Networks. A row with no PLMN is not a row with an unknown network: it is
    # a row where nobody decoded who the cell belongs to.
    local withplmn dplmn
    withplmn=$(tail -n +2 "$CREC_CELLS" | awk -F'\t' '$5 != ""' | grep -c . || true)
    dplmn=$(tail -n +2 "$CREC_CELLS" | awk -F'\t' '$5 != "" { print $5 }' | sort -u | grep -c . || true)
    if [[ "${dplmn:-0}" -gt 0 ]]; then
        printf 'distinct_plmns\t%s\n' "$dplmn"
    else
        printf 'distinct_plmns\tunobserved\tno row in the store carries a PLMN, so the store cannot say whose networks these cells belong to\n'
        reasons="$reasons DISTINCT_PLMNS"
    fi
    printf 'plmn_unobserved\t%s\n' "$(( n - ${withplmn:-0} ))"

    # Positions, answered from the join and never from a placeholder.
    local psrc
    if psrc=$(crec_positions_file); then
        printf 'position_source\t%s:%s\n' "${psrc%%$'\t'*}" "${psrc#*$'\t'}"
        local wf=0 wn=0 ident
        while IFS= read -r ident; do
            [[ -n "$ident" ]] || continue
            crec_split "$ident"
            if crec_position_of "${CREC_F[0]:-}" "${CREC_F[1]:-}" "${CREC_F[3]:-}" >/dev/null 2>&1
            then wf=$((wf + 1)); else wn=$((wn + 1)); fi
        done < <(crec_cell_identities)
        printf 'with_fix\t%s\n' "$wf"
        printf 'without_fix\t%s\n' "$wn"
    else
        printf 'position_source\tunobserved\n'
        printf 'with_fix\tunobserved\n'
        printf 'without_fix\tunobserved\n'
        printf 'position_reason\tno position join: the store has no coordinate column, and neither %s/positions.tsv nor %s/tower_map/points.tsv holds a fix\n' \
            "$CREC_DIR" "$LOOT_DIR"
        reasons="$reasons POSITIONS"
    fi

    if [[ -n "$reasons" ]]; then
        printf 'verdict\tunobserved\t%s could not be measured from this store; every other row was counted from recorded observations\n' "${reasons# }"
    else
        printf 'verdict\tmeasured\tevery dimension above was counted from recorded observations and a position join\n'
    fi
    return 0
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
    # A node is a survey source, so its availability belongs in the status the
    # GUI reads: "no SDR here" is a different page when four nodes are online.
    printf 'node_source\t%s\n' \
        "$([[ -f "$IMSISTING_ROOT/tools/node_source.py" ]] && echo yes || echo no)"
    # The MCC/MNC register decides whether a decoded PLMN gets a name at all.
    # Its absence is reported here rather than discovered row by row: a survey
    # of unnamed operators and a survey with no register look identical in a
    # store that only holds numbers.
    if declare -F refdata_status_line >/dev/null 2>&1; then
        refdata_status_line | awk -F'\t' \
            '$1 == "public/plmn.tsv" { printf "plmn_register\t%s\n", $2 }'
    else
        printf 'plmn_register\tsilent\n'
    fi
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

# ── survey through a fleet node ─────────────────────────────────────────
# A node is a source like the SDR or the capture file, and which of the three a
# survey came from is written into the row's source column rather than left for
# the reader to remember. What a node can deliver depends on what it is: a box
# with the toolkit runs the same survey there and its store is copied back, a
# handset reports the cells it can see, and a dongle reports one serving cell.
# tools/node_source.py owns that difference and refuses when a device cannot
# answer in this module's shape.
crec_cmd_node() {
    local name="${1:-}"
    [[ -n "$name" ]] || { printf 'ERROR\tusage: --node <name>\n' >&2; return 2; }
    local src="$IMSISTING_ROOT/tools/node_source.py"
    [[ -f "$src" ]] || {
        printf 'ERROR\tnode_source.py is missing\n'
        printf 'WHY\twithout it a node is a name with no way to ask it for cells\n'
        return 2
    }
    command -v python3 >/dev/null 2>&1 || {
        printf 'ERROR\tno python3\nWHY\tthe node readers are not shell work\n' >&2
        return 2
    }
    local rows rc
    rows=$(python3 "$src" cells "$name" 2>"$MOD_TMP/node_source.err")
    rc=$?
    if [[ "$rc" -ne 0 ]]; then
        cat "$MOD_TMP/node_source.err" >&2
        return "$rc"
    fi
    [[ -n "$rows" ]] || {
        printf 'ERROR\t%s returned no cells\n' "$name" >&2
        printf 'WHY\tan empty answer is not a survey; run one on the node first\n' >&2
        return 1
    }
    crec_init_store
    printf '%s\n' "$rows" | crec_store_rows
    local n; n=$(crec_cell_count)
    printf 'OK\t%s\n' "$n"
}

crec_cmd_arfcn() {
    local rat="${1:-}" n="${2:-}" dir="${3:-}" hint="${4:-}"
    [[ -n "$rat" && -n "$n" ]] || { printf 'ERROR\tusage: --arfcn <gsm|lte|nr> <N> [ul|dl] [pcs|dcs]\n' >&2; return 2; }
    local f rc=0 band=""
    case "$rat" in
        gsm)
            # The optional direction is the difference between hearing the
            # cell and hearing the phone: on the uplink the duplex split sits
            # between them, so a receiver parked on the wrong one sees nothing.
            [[ -z "$dir" ]] && dir=ul
            case "$dir" in
                ul|uplink)   dir=ul ;;
                dl|downlink) dir=dl ;;
                pcs|dcs|pcs1900|dcs1800) band="$dir"; dir=ul ;;
                *) printf 'ERROR\tunknown direction: %s (ul or dl)\n' "$dir" >&2; return 2 ;;
            esac
            [[ -n "$hint" ]] && band="$hint"
            f=$(crec_gsm_arfcn_to_mhz_dir "$n" "$dir" "$band") || rc=1
            ;;
        lte) f=$(crec_lte_earfcn_to_mhz "$n") || rc=1; dir=dl ;;
        nr)  f=$(crec_nr_arfcn_to_mhz "$n") || rc=1; dir=dl ;;
        *)   printf 'ERROR\tunknown rat: %s\n' "$rat" >&2; return 2 ;;
    esac
    if [[ "$rc" -ne 0 || -z "$f" ]]; then
        printf 'ERROR\tarfcn %s out of range for %s\n' "$n" "$rat" >&2
        return 1
    fi
    printf 'rat\t%s\narfcn\t%s\nfreq_mhz\t%s\n' "$rat" "$n" "$f"
    [[ "$rat" == "gsm" ]] && printf 'band\t%s\ndirection\t%s\n' \
        "$(crec_gsm_arfcn_band "$n" "$band")" "$dir"
    return 0
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
    chk plmn-known   "$(crec_plmn_name 208-01)"  "Orange"
    # The register answers through the shared loader; a machine without the
    # download must say so rather than claiming the PLMN is unassigned.
    chk plmn-state   "$(refdata_plmn 208 01 | cut -f1)" "ok"
    chk plmn-missing "$(REFDATA_PUBLIC=/nonexistent refdata_plmn 208 01 | cut -f1)" "silent"
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
    chk parse-gsm-op     "$(printf '%s' "$parsed" | cut -f8)" "Orange"
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
    chk node-missing-arg   "$(crec_cmd_node >/dev/null 2>&1; echo $?)" "2"
    chk node-unknown       "$(crec_cmd_node no-such-node >/dev/null 2>&1; echo $?)" "2"
    # A node that has surveyed nothing is a handoff, not an empty survey: the
    # caller has to run a survey there before this verb means anything.
    local _nodebook="$MOD_TMP/node-book"
    mkdir -p "$_nodebook"
    printf 'name\thost\tport\ttransport\tclass\trole\tcaps\tallow\tadded\tlast_seen\tstatus\tdetail\n' > "$_nodebook/nodes.tsv"
    printf 'selfnode\tlocalhost\t\tlocal\tsdr\tsensor\t\t-\t%s\t%s\tONLINE\t\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$_nodebook/nodes.tsv"
    chk node-empty-store   "$(CASEBOOK_DIR="$_nodebook" crec_cmd_node selfnode >/dev/null 2>&1; echo $?)" "3"

    out=$(crec_cmd_arfcn lte 6300); rc=$?
    chk arfcn-rc    "$rc" "0"
    chk arfcn-freq  "$(fld "$out" freq_mhz)" "806.0"
    out=$(crec_cmd_plmn 208-01)
    chk plmn-op     "$(fld "$out" operator)" "Orange"
    chk plmn-country "$(fld "$out" country)" "France"

    # 11. Status TSV contract. SDR presence is environment-dependent, so
    #     only the invariant fields are asserted.
    out=$(crec_cli_status_tsv)
    chk status-dir   "$(fld "$out" dir)"   "$CREC_DIR"
    chk status-store "$(fld "$out" store)" "$CREC_CELLS"
    chk status-cells "$(fld "$out" cells)" "0"

    # 12. Inventory export. The formats are the point of the verb, so each one
    #     is parsed back instead of trusted: a consumer needs a file that opens
    #     and carries the cell, not merely a file that was written.
    export STATE_DIR="$d/state"
    mkdir -p "$STATE_DIR" 2>/dev/null || true

    # 12a. An empty store refuses every format by name, and refuses *without*
    #      leaving a file behind that reads as a survey which found nothing.
    chk export-empty-csv   "$(crec_cmd_export csv    >/dev/null 2>&1; echo $?)" "1"
    chk export-empty-kml   "$(crec_cmd_export kml    >/dev/null 2>&1; echo $?)" "1"
    chk export-empty-geo   "$(crec_cmd_export geojson >/dev/null 2>&1; echo $?)" "1"
    chk export-empty-nmap  "$(crec_cmd_export nmap   >/dev/null 2>&1; echo $?)" "1"
    chk export-empty-inv   "$(crec_cmd_inventory     >/dev/null 2>&1; echo $?)" "1"
    chk export-bad-format  "$(crec_cmd_export wat    >/dev/null 2>&1; echo $?)" "2"
    chk export-empty-files "$(ls "$CREC_DIR"/*.csv "$CREC_DIR"/*.kml \
                                  "$CREC_DIR"/*.geojson "$CREC_DIR"/*.xml 2>/dev/null | grep -c . || true)" "0"
    chk export-empty-why   "$(crec_cmd_export csv 2>&1 | grep -c '^MISSING	')" "1"
    chk export-empty-why2  "$(crec_cmd_export csv 2>&1 | grep -c '^WHY	')"     "1"

    # 12b. Fixture: three rows that are two cells (one cell heard twice), two
    #      bands and two PLMNs. The counts below only mean something if the
    #      store has something to collapse.
    local fx1 fx2
    fx1=$(crec_row "LTE" "4G" "6300" "806.0" "208-01" "208" "01" \
                  "Orange FR" "France" "123" "456" "" "" "" "selftest")
    fx2=$(crec_row "NR" "5G" "500000" "2500.000" "262-01" "262" "01" \
                  "Telekom DE" "Germany" "77" "" "" "" "" "selftest")
    printf '%s\n%s\n%s\n' "$fx1" "$fx2" "$fx1" | crec_store_rows
    chk fixture-rows "$(crec_cell_count)" "3"

    # 12c. Band derivation, including the ARFCN that names two bands. A guess
    #      between DCS1800 and PCS1900 puts a receiver 140 MHz off.
    chk band-lte-20    "$(crec_row_band LTE 6300 '')"   "20"
    chk band-nr-41     "$(crec_row_band NR  500000 '')" "n41"
    chk band-gsm-9     "$(crec_row_band GSM 42 '')"     "gsm900"
    chk band-gsm-ambig "$(crec_row_band GSM 690 '')"    "dcs1800 pcs1900"
    chk band-outside   "$(crec_row_band GSM 1000 '' >/dev/null 2>&1; echo $?)" "1"
    chk band-from-col  "$(crec_row_band LTE 6300 'b99')" "b99"
    chk freq-from-row  "$(crec_arfcn_freq LTE 6300)"     "806.0"

    # 12d. Inventory with no position join: the counts it can make are
    #      measured, and the ones it cannot are unobserved rather than zero.
    out=$(crec_cmd_inventory); rc=$?
    chk inv-rc          "$rc" "0"
    chk inv-cells       "$(fld "$out" cells)" "3"
    chk inv-distinct    "$(fld "$out" distinct_cells)" "2"
    chk inv-bands       "$(fld "$out" distinct_bands)" "2"
    chk inv-bands-unobs "$(fld "$out" bands_unobserved)" "0"
    chk inv-plmns       "$(fld "$out" distinct_plmns)" "2"
    chk inv-fix-unobs   "$(fld "$out" with_fix)" "unobserved"
    chk inv-nofix-unobs "$(fld "$out" without_fix)" "unobserved"
    chk inv-verdict-unobs "$(printf '%s\n' "$out" | awk -F'\t' '$1=="verdict"{print $2}')" "unobserved"
    chk inv-verdict-why   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="verdict"{print ($3 ~ /POSITIONS/)}')" "1"

    # 12e. A map with no coordinate has to be refused, not written empty.
    chk kml-no-fix-rc   "$(crec_cmd_export kml     >/dev/null 2>&1; echo $?)" "1"
    chk geo-no-fix-rc   "$(crec_cmd_export geojson >/dev/null 2>&1; echo $?)" "1"
    chk kml-no-fix-file "$(ls "$CREC_DIR"/*.kml 2>/dev/null | grep -c . || true)"     "0"
    chk geo-no-fix-file "$(ls "$CREC_DIR"/*.geojson 2>/dev/null | grep -c . || true)" "0"

    # 12f. CSV: real CSV, not a renamed TSV. A field carrying a comma must be
    #      quoted or every column after it shifts.
    chk csv-quote       "$(printf 'a\tb,c\n' | crec_csv_line)" 'a,"b,c"'
    chk csv-quote-inner "$(printf 'x\tsay "hi"\n' | crec_csv_line)" 'x,"say ""hi"""'
    out=$(crec_cmd_export csv); rc=$?
    chk export-csv-rc "$rc" "0"
    local csvp kmlp geop nmp
    csvp=$(printf '%s\n' "$out" | awk -F'\t' '$1=="OK"{print $2}')
    chk export-csv-exists "$([[ -f "$csvp" ]] && echo yes)" "yes"
    chk export-csv-rows   "$(tail -n +2 "$csvp" | grep -c .)" "3"
    chk export-csv-cols   "$(head -1 "$csvp" | awk -F',' '{print NF}')" "16"

    # 12g. nmap XML: a host per cell, nothing invented for it — no address, no
    #      port — and the measurement where a mapper looks for one.
    out=$(crec_cmd_export nmap); rc=$?
    chk export-nmap-rc "$rc" "0"
    nmp=$(printf '%s\n' "$out" | awk -F'\t' '$1=="OK"{print $2}')
    chk export-nmap-hosts  "$(grep -c '^<host>' "$nmp")" "2"
    chk export-nmap-script "$(grep -c 'script id="cell-recon"' "$nmp")" "2"
    chk export-nmap-rat    "$(grep -c '<elem key="rat">LTE</elem>' "$nmp")" "1"
    chk export-nmap-band   "$(grep -c '<elem key="band">20</elem>' "$nmp")" "1"
    chk export-nmap-stats  "$(grep -c 'hosts up="2" down="0" total="2"' "$nmp")" "1"
    chk export-nmap-noaddr "$(grep -c '<address' "$nmp" || true)" "0"
    if command -v python3 >/dev/null 2>&1; then
        chk export-nmap-xml "$(python3 -c 'import sys,xml.etree.ElementTree as E
E.parse(sys.argv[1]); print("ok")' "$nmp" 2>/dev/null)" "ok"
    fi

    # 12h. With a position sidecar the same store gains the join. One of the
    #      two cells has a fix, one does not, and the summary says so.
    printf 'rat\tarfcn\tcell_id\tlat\tlon\tsource\n' > "$CREC_DIR/positions.tsv"
    printf 'LTE\t6300\t123\t51.5\t-0.12\tgps\n'     >> "$CREC_DIR/positions.tsv"
    out=$(crec_cmd_inventory)
    chk inv-src        "$(fld "$out" position_source)" "sidecar:$CREC_DIR/positions.tsv"
    chk inv-fix        "$(fld "$out" with_fix)" "1"
    chk inv-nofix      "$(fld "$out" without_fix)" "1"
    chk inv-verdict-ok "$(printf '%s\n' "$out" | awk -F'\t' '$1=="verdict"{print $2}')" "measured"

    # 12i. KML: one placemark per placeable cell, the band and ARFCN in the
    #      description so the pin explains itself, and a NOTE for the cell it
    #      could not place.
    out=$(crec_cmd_export kml); rc=$?
    chk export-kml-rc "$rc" "0"
    kmlp=$(printf '%s\n' "$out" | awk -F'\t' '$1=="OK"{print $2}')
    chk export-kml-placemarks "$(grep -c '<Placemark>' "$kmlp")" "1"
    chk export-kml-coord      "$(grep -c '<coordinates>-0.12,51.5,0</coordinates>' "$kmlp")" "1"
    chk export-kml-band       "$(grep -c 'band=20' "$kmlp")" "1"
    chk export-kml-arfcn      "$(grep -c 'arfcn=6300' "$kmlp")" "1"
    chk export-kml-pci        "$(grep -c 'pci=123' "$kmlp")" "1"
    chk export-kml-note       "$(printf '%s\n' "$out" | grep -c '^NOTE	')" "1"
    if command -v python3 >/dev/null 2>&1; then
        chk export-kml-xml "$(python3 -c 'import sys,xml.etree.ElementTree as E
E.parse(sys.argv[1]); print("ok")' "$kmlp" 2>/dev/null)" "ok"
    fi

    # 12j. GeoJSON: the properties are the store's own columns, spelled the way
    #      the store spells them, so a consumer can join back on them.
    out=$(crec_cmd_export geojson); rc=$?
    chk export-geo-rc "$rc" "0"
    geop=$(printf '%s\n' "$out" | awk -F'\t' '$1=="OK"{print $2}')
    chk export-geo-features "$(grep -c '"type":"Feature"' "$geop")" "1"
    chk export-geo-point    "$(grep -c '"coordinates":\[-0.12,51.5\]' "$geop")" "1"
    chk export-geo-prop-rat "$(grep -c '"rat":"LTE"' "$geop")" "1"
    chk export-geo-prop-band "$(grep -c '"band":""' "$geop")" "1"
    chk export-geo-unplaced "$(printf '%s\n' "$out" | grep -c '^NOTE	')" "1"
    if command -v python3 >/dev/null 2>&1; then
        chk export-geo-json "$(python3 -c 'import json,sys
json.load(open(sys.argv[1])); print("ok")' "$geop" 2>/dev/null)" "ok"
    fi

    # 12k. The tower_map fallback: a second source for the same join, taken
    #      only when the sidecar is absent, so one file cannot silently win.
    rm -f "$CREC_DIR/positions.tsv"
    mkdir -p "$LOOT_DIR/tower_map"
    printf 'ts\tlat\tlon\talt_m\tspeed_mps\trat\tgen\tarfcn\tplmn\tcell_id\trsrp_dbm\toperator\n' \
        > "$LOOT_DIR/tower_map/points.tsv"
    printf '2024-01-01T00:00:00Z\t48.2\t11.5\t\t\tNR\t5G\t500000\t262-01\t77\t-90\tTelekom\n' \
        >> "$LOOT_DIR/tower_map/points.tsv"
    out=$(crec_cmd_inventory)
    chk inv-tmap-src   "$(fld "$out" position_source)" "tower_map:$LOOT_DIR/tower_map/points.tsv"
    chk inv-tmap-fix   "$(fld "$out" with_fix)" "1"
    chk inv-tmap-nofix "$(fld "$out" without_fix)" "1"

    # 12l. Ambiguity and the unobservable band count. Neither may be resolved
    #      by a guess, and neither may be reported as a zero.
    printf '%s\n' "$(crec_row GSM 2G 690 1745.0 '' '' '' '' '' 4321 '')" | crec_store_rows
    out=$(crec_cmd_inventory)
    chk inv-ambig      "$(fld "$out" bands_ambiguous)" "1"
    chk inv-plmn-unobs "$(fld "$out" plmn_unobserved)" "1"
    cp "$CREC_CELLS" "$d/cells.keep"
    printf '%s\n' "$(crec_header)" > "$CREC_CELLS"
    printf '%s\n' "$(crec_row GSM 2G 1000 935.0 '' '' '' '' '' 4321 '')" >> "$CREC_CELLS"
    out=$(crec_cmd_inventory)
    chk inv-bands-none   "$(fld "$out" distinct_bands)" "unobserved"
    chk inv-plmns-none   "$(fld "$out" distinct_plmns)" "unobserved"
    chk inv-verdict-none "$(printf '%s\n' "$out" | awk -F'\t' '$1=="verdict"{print $2}')" "unobserved"
    chk inv-no-zero-lie  "$(printf '%s\n' "$out" | grep -c 'distinct_bands	0$' || true)" "0"
    cp "$d/cells.keep" "$CREC_CELLS"

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
  [6]  export survey (tsv|csv|kml|geojson|nmap)
  [7]  clear survey
  [8]  ARFCN -> frequency
  [9]  PLMN -> operator
  [i]  cell inventory summary
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
            6)
                read -rp "  format (tsv|csv|kml|geojson|nmap)> " f
                crec_cmd_export "$f" || true
                read -rp "  press enter " _ ;;
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
            i|I)
                crec_cmd_inventory | column -t -s$'\t' 2>/dev/null || true
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
        --node)         crec_cmd_node "${1:-}" ;;
        --arfcn)        crec_cmd_arfcn "${1:-}" "${2:-}" "${3:-}" "${4:-}" ;;
        --plmn)         crec_cmd_plmn "${1:-}" ;;
        --set-target)   crec_cmd_set_target "${1:-}" "${2:-}" "${3:-}" ;;
        --target-tsv)   crec_cmd_target_tsv ;;
        --export)       crec_cmd_export "${1:-}" ;;
        --inventory)    crec_cmd_inventory ;;
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
  --node <name>             survey through a fleet node instead of this radio
  --list-tsv                surveyed cells as TSV
  --list                    surveyed cells, sorted for reading
  --arfcn <gsm|lte|nr> <N>  ARFCN/EARFCN to downlink MHz
  --plmn <MCC-MNC>          PLMN to operator and country
  --set-target <rat> <arfcn> <plmn>   record the shared radio target
  --target-tsv              current shared radio target as TSV
  --export [tsv|csv|kml|geojson|nmap]   write the survey into loot/
  --inventory               count cells, bands, PLMNs and fixes the store
                            holds, and name the ones it cannot measure
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
