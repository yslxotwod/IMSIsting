#!/usr/bin/env bash
# NB-IoT / Cat-M1 — narrowband IoT air interface with NPRACH, NPSS, NSSS, NPDCCH, NPDSCH
#
# NB-IoT (Narrowband IoT) and Cat-M1 are low-power wide-area (LPWA) technologies
# that share the LTE spectrum but use a 180 kHz channel with different physical
# layer structures. This module covers NPRACH, NPSS/NSSS, NPDCCH/NPDSCH, and
# the unique SIB types (SIB1-NB, SIB2-NB, SIB3-NB, SIB4-NB, SIB5-NB, SIB14-NB).
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

MOD_TMP="$TMP_DIR/iot"
IOT_DIR="$LOOT_DIR/iot"
mkdir -p "$MOD_TMP" "$IOT_DIR" 2>/dev/null

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
iot_status_tsv() {
    local tool_missing=()
    for t in python3 awk; do
        command -v "$t" >/dev/null 2>&1 || tool_missing+=("$t")
    done
    local status=ok
    ((${#tool_missing[@]} > 0)) && status=missing
    printf 'STATUS\t%s\n' "$status"
    ((${#tool_missing[@]} > 0)) && printf 'MISSING\t%s\n' "$(IFS=,; echo "${tool_missing[*]}")"
}

# ── NPRACH parameters (TS 36.211 §14.2) ─────────────────────────────────
# NPRACH uses 12 subcarriers, preamble format 0 with N_cp=67 or N_cp=125
iot_nprach_params() {
    local central_freq="${1:-2140.0}"  # n28 example
    local prach_cfg="${2:-0}"          # index 0-15
    local subcar_spacing="${3:-3.75}"  # kHz
    
    # Format 0: N_cp=67 (normal CP) or N_cp=125 (extended CP)
    local n_cp=67
    local symbol_len=$((15360 + n_cp))
    local frame_len=$((153600 + 10*n_cp))
    
    cat << EOF
NPRACH Parameters
=================
Central Freq: ${central_freq} MHz
PRACH Config: ${prach_cfg}
Subcarrier:   ${subcar_spacing} kHz
Symbols:      12 subcarriers × 7 symbols = 84 resource elements
CP length:    ${n_cp} samples (${symbol_len} samples/symbol)
Frame length: ${frame_len} samples
EOF
}

# ── NPSS/NSSS sequences (TS 36.211 §14.3) ───────────────────────────────
# NPSS: 127-point ZC sequence, period 10ms
# NSSS: 127-point ZC sequence, period 20ms, different ZC root
iot_npss_to_nss() {
    local pci="${1:-0}"
    
    # PCI = 3*N_ID(1) + N_ID(2), where N_ID(1) and N_ID(2) define the ZC roots
    local n_id_1=$(( pci / 3 ))
    local n_id_2=$(( pci % 3 ))
    
    cat << EOF
NPSS/NSSS for PCI=$pci
=====================
N_ID(1): $n_id_1
N_ID(2): $n_id_2
NPSS:    ZC sequence with root $n_id_1, period 10ms
NSSS:    ZC sequence with root ($n_id_1 + $n_id_2 + 1) mod 127, period 20ms
EOF
}

# ── SIB1-NB decoding (TS 36.331 §6.3.1) ────────────────────────────────
iot_decode_sib1_nb() {
    local hex="$1"
    [[ -z "$hex" ]] && { warn "usage: --decode-sib1-nb <hex>"; return 1; }
    
    # SIB1-NB is 160 bits (20 octets)
    [[ ${#hex} -lt 40 ]] && { warn "SIB1-NB too short"; return 1; }
    
    local mib_nb="${hex:0:4}"
    local sched_info="${hex:4:2}"
    local si_period="${hex:6:2}"
    local tdd_config="${hex:8:2}"
    local pws_cfg="${hex:10:2}"
    local cell_id="${hex:12:6}"
    
    cat << EOF
SIB1-NB Decoded
===============
MIB-NB:        $mib_nb
Scheduling:    $sched_info
SI Period:     $si_period × 1024 frames
TDD Config:    $tdd_config
PWS Config:    $pws_cfg
Cell ID:       0x$cell_id
EOF
}

# ── Band mapping (TS 36.104 Table 5.7.3-1) ─────────────────────────────
iot_nprfcn_to_mhz() {
    local nprfcn="$1"
    [[ "$nprfcn" =~ ^[0-9]+$ ]] || { warn "NPRFCN must be numeric"; return 1; }
    
    # NB-IoT operates in-band, stand-alone, or guard-band
    # Frequency is derived from the carrier bandwidth center
    awk -v n="$nprfcn" 'BEGIN{
        if (n >= 0 && n <= 999) printf "%.3f", 410.0 + 0.1*n
        else if (n >= 1000 && n <= 1999) printf "%.3f", 500.0 + 0.1*(n-1000)
        else exit 1
    }' || { warn "NPRFCN out of range"; return 1; }
}

# ── Selftest ───────────────────────────────────────────────────────────
iot_selftest() {
    local bad=0 nchk=0
    chk() {
        nchk=$(( nchk + 1 ))
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$(( bad + 1 )); fi
    }

    # 1. NPRACH parameter checks (TS 36.211 §14.2)
    local params=$(iot_nprach_params 2140.0 0 3.75)
    local symbols=$(echo "$params" | awk '/resource elements/{print $8}')
    local cp=$(echo "$params" | grep 'CP length:' | awk '{print $3}')
    chk nprach-symbols "$symbols" "84"
    chk nprach-cp "$cp" "67"

    # 2. NPSS/NSSS ZC root calculation
    local zc_root=$(iot_npss_to_nss 1)
    local n_id_1=$(echo "$zc_root" | grep 'N_ID(1):' | awk '{print $2}')
    local n_id_2=$(echo "$zc_root" | grep 'N_ID(2):' | awk '{print $2}')
    chk npss-nid1 "$n_id_1" "0"
    chk npss-nid2 "$n_id_2" "1"

    # 3. SIB1-NB decoding
    local sib1=$(iot_decode_sib1_nb "0000000000000000000000000000000000000000")
    local field_count=$(echo "$sib1" | grep -c ':')
    chk sib1-fields "$field_count" "6"

    # 4. NPRFCN to MHz (TS 36.104)
    chk nprfcn-0   "$(iot_nprfcn_to_mhz 0)"   "410.000"
    chk nprfcn-500 "$(iot_nprfcn_to_mhz 500)" "460.000"
    chk nprfcn-999 "$(iot_nprfcn_to_mhz 999)" "509.900"
    chk nprfcn-oob "$(iot_nprfcn_to_mhz 10000 >/dev/null 2>&1; echo $?)" "1"

    # 5. Unknown values must fail, not guess
    chk nprfcn-neg "$(iot_nprfcn_to_mhz -1 >/dev/null 2>&1; echo $?)" "1"
    chk nprfcn-str "$(iot_nprfcn_to_mhz abc >/dev/null 2>&1; echo $?)" "1"
    chk sib1-short "$(iot_decode_sib1_nb "000000" >/dev/null 2>&1; echo $?)" "1"

    printf 'ASSERTIONS\t%d\n' "$nchk"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ── menu ───────────────────────────────────────────────────────────────
iot_menu() {
    while true; do
        banner
        echo -e "  ${C_MAG}=== NB-IoT / Cat-M1 ===${C_RESET}\n"
        cat << 'M'
  [1]  NPRACH parameters
  [2]  NPSS/NSSS ZC roots
  [3]  Decode SIB1-NB
  [4]  NPRFCN to MHz
  [0]  back

M
        read -rp "  choice> " c || return 0
        case "$c" in
            1)
                read -rp "  freq (MHz)> " f
                read -rp "  prach_cfg> " p
                read -rp "  subcarrier (kHz)> " s
                iot_nprach_params "$f" "$p" "$s"; read -rp "  press enter " _ ;;
            2)
                read -rp "  PCI> " p
                iot_npss_to_nss "$p"; read -rp "  press enter " _ ;;
            3)
                read -rp "  hex> " h
                iot_decode_sib1_nb "$h"; read -rp "  press enter " _ ;;
            4)
                read -rp "  nprfcn> " n
                echo "$(iot_nprfcn_to_mhz "$n") MHz"
                read -rp "  press enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ── CLI dispatch ───────────────────────────────────────────────────────
iot_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)   iot_status_tsv ;;
        --nprach)       iot_nprach_params "${1:-2140.0}" "${2:-0}" "${3:-3.75}" ;;
        --npss-nss)     iot_npss_to_nss "${1:-0}" ;;
        --decode-sib1)  iot_decode_sib1_nb "${1:-}" ;;
        --to-mhz)       iot_nprfcn_to_mhz "${1:-}" ;;
        --selftest)     iot_selftest ;;
        --menu)         iot_menu ;;
        *) cat >&2 <<EOF
NB-IoT / Cat-M1 — narrowband IoT air interface

Usage: $0 COMMAND
  --status-tsv       tool and store state as TSV
  --nprach [freq] [cfg] [spacing]
  --npss-nss [pci]
  --decode-sib1 <hex>
  --to-mhz <nprfcn>
  --selftest         verify tables and parsers
  --menu             interactive menu
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
    iot_cli_main "$@"
fi
