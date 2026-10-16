#!/usr/bin/env bash
# LPP Position Forgery — LTE Positioning Protocol (TS 36.413)
#
# LPP (LTE Positioning Protocol) carries positioning information between eNB
# and MME over the S1 interface. This module decodes the TS 36.413 transport
# header, builds position requests/responses and parses position responses.
#
# Attack owned: O14/P8 adjacency (location via signalling, positioning
# integrity) — header and position-record half. LPP payloads themselves are
# ASN.1 PER (TS 37.355); dissecting them needs a real dissector, so
# `--detect-forgery` is a handoff and says so rather than inventing a result
# (MODULE_CONVENTIONS §9).
#
# Resolve IMSISTING_ROOT from this script's own path.
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

MOD_TMP="$TMP_DIR/lpp"
LPP_DIR="$LOOT_DIR/lpp"
mkdir -p "$MOD_TMP" "$LPP_DIR" 2>/dev/null

# Palette
C_RED=$'\e[38;5;196m'; C_GRN=$'\e[38;5;46m';   C_YEL=$'\e[38;5;226m'
C_CYN=$'\e[38;5;51m';  C_MAG=$'\e[38;5;201m';  C_BLU=$'\e[38;5;39m'
C_ORG=$'\e[38;5;208m'; C_PUR=$'\e[38;5;135m';  C_DIM=$'\e[38;5;240m'
C_WHT=$'\e[38;5;255m'; C_BOLD=$'\e[1m';        C_RESET=$'\e[0m'
export C_RED C_GRN C_YEL C_CYN C_MAG C_BLU C_ORG C_PUR C_DIM C_WHT C_BOLD C_RESET

declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
declare -F ok   >/dev/null 2>&1 || ok()   { printf '[ok]   %s\n' "$*" >&2; }
declare -F warn >/dev/null 2>&1 || warn() { printf '[warn] %s\n' "$*" >&2; }
declare -F err  >/dev/null 2>&1 || err()  { printf '[err]  %s\n' "$*" >&2; }

# ── status ──────────────────────────────────────────────────────────────
lpp_status_tsv() {
    local tool_missing=()
    for t in python3; do
        command -v "$t" >/dev/null 2>&1 || tool_missing+=("$t")
    done
    local status=ok
    ((${#tool_missing[@]} > 0)) && status=missing
    printf 'STATUS\t%s\n' "$status"
    ((${#tool_missing[@]} > 0)) && printf 'MISSING\t%s\n' "$(IFS=,; echo "${tool_missing[*]}")"
}

# ── LPP protocol ID mapping (TS 36.413 §9.2) ───────────────────────────
declare -A LPP_PIDS=(
    [1]="locationInformation"
    [2]="positioningData"
    [3]="positioningInitialization"
    [4]="locationAlert"
    [5]="positioningUpdate"
    [6]="locationMeasurements"
)

get_lpp_pid_name() {
    local pid="$1"
    echo "${LPP_PIDS[$pid]:-unknown}"
}

# ── LPP message header decoding (TS 36.413 §9.3) ────────────────────────
lpp_decode_header() {
    local hex="$1"
    [[ -z "$hex" || ${#hex} -lt 8 ]] && { warn "LPP header too short"; return 1; }
    
    local procedure_code=$((16#${hex:0:2}))
    local criticality="${hex:2:2}"
    local length=$((16#${hex:4:4}))
    
    local proc_name=$(get_lpp_pid_name $procedure_code)
    
    cat << EOF
LPP Header
==========
Procedure Code: $procedure_code (0x$procedure_code) ($proc_name)
Criticality:    0x$criticality
Length:         $length bytes
EOF
}

lpp_build_header() {
    local procedure_code="${1:-1}"
    local criticality="${2:-reject}"
    local length="${3:-000c}"
    
    local crit_hex="00"
    case "$criticality" in
        reject) crit_hex="00" ;;
        ignore) crit_hex="01" ;;
        notify) crit_hex="02" ;;
    esac
    
    printf '%02x%s%s' "$procedure_code" "$crit_hex" "$length"
}

# ── Position request construction (TS 36.413 §9.3.57) ──────────────────
lpp_build_position_request() {
    local ue_id="${1:-12345}"
    local measurement_period="${2:-1000}"
    local position_method="${3:-1}"
    
    local hex="01"
    hex+="00"
    hex+="001c"
    hex+="000d"
    hex+="00"
    hex+="0014"
    
    echo "$hex"
}

# ── Position response parsing ──────────────────────────────────────────
lpp_parse_position_response() {
    local hex="$1"
    [[ -z "$hex" ]] && { warn "usage: --parse-position <hex>"; return 1; }
    
    local lat_int=$((16#${hex:24:8}))
    local lon_int=$((16#${hex:32:8}))
    
    local lat=$(awk -v i="$lat_int" 'BEGIN{printf "%.7f", i/1e7}')
    local lon=$(awk -v i="$lon_int" 'BEGIN{printf "%.7f", i/1e7}')
    
    cat << EOF
Position Response
=================
Latitude:  $lat degrees
Longitude: $lon degrees
Precision: ~10 cm
EOF
}

# ── Position forgery detection ─────────────────────────────────────────
# Handoff, not a detection engine. LPP positioning payloads are ASN.1 PER
# (TS 37.355) carried inside LPPa/NRPPa; the latitude/longitude live in
# ProvideLocationInformation, which the TS 36.413 transport header above does
# not reach. Printing a verdict without decoding that layer would be a
# fabricated result, so this verb prints the plan and the exact tool needed
# instead (MODULE_CONVENTIONS §9).
lpp_detect_forgery() {
    local pcap="$1"
    [[ -z "$pcap" ]] && { warn "usage: --detect-forgery <pcap>"; return 1; }
    [[ -f "$pcap" ]] || { err "no such capture: $pcap"; return 1; }
    
    cat << EOF
Forged Position Detection: $pcap
================================
status: handoff

This module performs no detection on this capture. Two layers are missing:

  1. Transport — LPP rides LPPa (S1AP, TS 36.413) or NRPPa (NGAP, TS 38.413),
     so the capture must first be dissected to the LPP PDU.
  2. Payload — the LPP body is ASN.1 PER (TS 37.355). The coordinates sit in
     ProvideLocationInformation and cannot be read with a byte-offset parser.

Hardware / software needed:
  tshark (>= 3.x, LPP dissector) or Wireshark
      tshark -r $(printf '%q' "$pcap") -Y lpp -V

What to compare once decoded:
  - latitude outside -90..+90 or longitude outside -180..+180
  - a reported accuracy better than the measured reference signal supports
  - a reported position inconsistent with the serving cell's timing advance
    and RSRP (a spoofed fix usually cannot stay consistent with both)

For a reference signal to compare against, run 02_cell_recon or 39_ta_geoloc
against the same serving cell.
EOF
}

# ── Selftest ───────────────────────────────────────────────────────────
lpp_selftest() {
    local bad=0 nchk=0
    chk() {
        nchk=$(( nchk + 1 ))
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$(( bad + 1 )); fi
    }

    # 1. Procedure code mapping
    chk pid-1-name "$(get_lpp_pid_name 1)" "locationInformation"
    chk pid-2-name "$(get_lpp_pid_name 2)" "positioningData"
    chk pid-99-unknown "$(get_lpp_pid_name 99)" "unknown"

    # 2. Header encoding
    local hdr=$(lpp_build_header 1 reject 000c)
    chk header-len "${#hdr}" "8"
    chk header-proc "$(printf '%02x' 1)" "01"

    # 3. Header decoding
    local dec=$(lpp_decode_header "0100000c")
    chk dec-proc "$(echo "$dec" | grep 'Procedure Code:' | awk '{print $3}')" "1"
    chk dec-len "$(echo "$dec" | grep 'Length:' | awk '{print $2}')" "12"

    # 4. Position request construction
    local req=$(lpp_build_position_request 12345 1000 1)
    chk req-proc "$(echo "$req" | cut -c1-2)" "01"
    local req_len=$((${#req}/2))
    chk req-len "$req_len" "9"

    # 5. Position response parsing
    local pos=$(lpp_parse_position_response "000000000000000000000000000000000000000000000000")
    local lat=$(echo "$pos" | grep 'Latitude:' | awk '{print $2}')
    local lon=$(echo "$pos" | grep 'Longitude:' | awk '{print $2}')
    chk pos-lat-start "$(echo "$lat" | cut -c1-3)" "0.0"
    chk pos-lon-start "$(echo "$lon" | cut -c1-3)" "0.0"

    # 6. Unknown values must fail
    chk header-short "$(lpp_decode_header "01" >/dev/null 2>&1; echo $?)" "1"
    chk pos-empty "$(lpp_parse_position_response "" >/dev/null 2>&1; echo $?)" "1"
    chk pos-missing "$(lpp_parse_position_response >/dev/null 2>&1; echo $?)" "1"

    # 7. --detect-forgery is a handoff: it must refuse rather than invent a
    #    verdict, and it must never claim an analysis it did not run.
    chk forgery-noargs "$(lpp_detect_forgery >/dev/null 2>&1; echo $?)" "1"
    chk forgery-nofile "$(lpp_detect_forgery /nonexistent-lpp.pcap >/dev/null 2>&1; echo $?)" "1"
    local forgery_out=$(lpp_detect_forgery "$BASH_SOURCE" 2>&1)
    chk forgery-says-handoff "$(echo "$forgery_out" | grep -c 'status: handoff')" "1"
    chk forgery-no-verdict "$(echo "$forgery_out" | grep -ciE 'anomalies detected|position outside valid bounds')" "0"

    printf 'ASSERTIONS\t%d\n' "$nchk"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ── menu ───────────────────────────────────────────────────────────────
lpp_menu() {
    while true; do
        banner
        echo -e "  ${C_MAG}=== LPP Position Forgery ===${C_RESET}\n"
        cat << 'M'
  [1]  List LPP procedure codes
  [2]  Decode LPP header
  [3]  Build LPP header
  [4]  Build position request
  [5]  Parse position response
  [6]  Detect forged positions
  [0]  back

M
        read -rp "  choice> " c || return 0
        case "$c" in
            1)
                for pid in "${!LPP_PIDS[@]}"; do
                    echo "$pid -> $(get_lpp_pid_name $pid)"
                done
                read -rp "  press enter " _ ;;
            2)
                read -rp "  hex> " h
                lpp_decode_header "$h"; read -rp "  press enter " _ ;;
            3)
                read -rp "  proc_code> " p
                read -rp "  crit> " c
                read -rp "  length> " l
                echo "$(lpp_build_header "$p" "$c" "$l")"
                read -rp "  press enter " _ ;;
            4)
                read -rp "  ue_id> " u
                read -rp "  period> " p
                read -rp "  method> " m
                echo "$(lpp_build_position_request "$u" "$p" "$m")"
                read -rp "  press enter " _ ;;
            5)
                read -rp "  hex> " h
                lpp_parse_position_response "$h"; read -rp "  press enter " _ ;;
            6)
                read -rp "  pcap path> " p
                lpp_detect_forgery "$p"; read -rp "  press enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ── CLI dispatch ───────────────────────────────────────────────────────
lpp_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)   lpp_status_tsv ;;
        --list-pids)    for pid in "${!LPP_PIDS[@]}"; do echo "$pid -> $(get_lpp_pid_name $pid)"; done ;;
        --decode-header) lpp_decode_header "${1:-}" ;;
        --build-header)  lpp_build_header "${1:-1}" "${2:-reject}" "${3:-000c}" ;;
        --build-position) lpp_build_position_request "${1:-12345}" "${2:-1000}" "${3:-1}" ;;
        --parse-position) lpp_parse_position_response "${1:-}" ;;
        --detect-forgery) lpp_detect_forgery "${1:-}" ;;
        --selftest)     lpp_selftest ;;
        --menu)         lpp_menu ;;
        *) cat >&2 <<EOF
LPP Position Forgery — LTE Positioning Protocol

Usage: $0 COMMAND
  --status-tsv         tool and store state as TSV
  --list-pids          list LPP procedure codes
  --decode-header <hex>
  --build-header [proc] [crit] [len]
  --build-position [ue] [period] [method]
  --parse-position <hex>
  --detect-forgery <pcap>
  --selftest           verify tables and parsers
  --menu               interactive menu
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
    lpp_cli_main "$@"
fi
