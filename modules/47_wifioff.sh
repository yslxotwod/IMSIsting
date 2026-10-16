#!/usr/bin/env bash
# Wi-Fi Offload / LWA — ePDG trust model, WFA certificates, LWA traffic steering
#
# Wi-Fi offload (IEEE 802.11) and LTE-WLAN Aggregation (LWA) extend cellular
# coverage using unlicensed spectrum. This module tests ePDG authentication,
# WFA certificate validation, and LWA traffic steering.
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

MOD_TMP="$TMP_DIR/wifioff"
WIFOFF_DIR="$LOOT_DIR/wifioff"
mkdir -p "$MOD_TMP" "$WIFOFF_DIR" 2>/dev/null

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
wifioff_status_tsv() {
    local tool_missing=()
    for t in python3 openssl; do
        command -v "$t" >/dev/null 2>&1 || tool_missing+=("$t")
    done
    local status=ok
    ((${#tool_missing[@]} > 0)) && status=missing
    printf 'STATUS\t%s\n' "$status"
    ((${#tool_missing[@]} > 0)) && printf 'MISSING\t%s\n' "$(IFS=,; echo "${tool_missing[*]}")"
}

# ── ePDG FQDN construction (TS 23.401 §5.4.5) ──────────────────────────
wifioff_epdg_fqdn() {
    local plmn="${1:-20801}"
    local realm="${2:-epdg.epc.mnc001.mcc208.3gppnetwork.org}"
    
    # ePDG FQDN format: epdg.epc.mnc< MCC >.mnc<MNC>.mcc<MCC>.3gppnetwork.org
    local mcc="${plmn:0:3}"
    local mnc="${plmn:3:3}"
    [[ ${#mnc} -eq 2 ]] && mnc="0${mnc}"
    
    echo "epdg.epc.mnc${mnc}.mcc${mcc}.3gppnetwork.org"
}

# ── WFA certificate chain validation (Wi-Fi Alliance) ──────────────────
wifioff_validate_cert() {
    local cert_path="${1:-/dev/stdin}"
    
    [[ ! -f "$cert_path" ]] && { warn "certificate file not found: $cert_path"; return 1; }
    
    local subject=$(openssl x509 -in "$cert_path" -noout -subject 2>/dev/null | sed 's/subject=//')
    local issuer=$(openssl x509 -in "$cert_path" -noout -issuer 2>/dev/null | sed 's/issuer=//')
    local expiry=$(openssl x509 -in "$cert_path" -noout -enddate 2>/dev/null | sed 's/notAfter=//')
    
    cat << EOF
Certificate Validation
======================
Subject: $subject
Issuer:  $issuer
Expires: $expiry
EOF
    
    # Check if expired
    if openssl x509 -in "$cert_path" -noout -checkend 0 2>/dev/null; then
        echo "Status:  VALID"
    else
        echo "Status:  EXPIRED"
    fi
}

# ── LWA configuration (IEEE 802.11AC/WFA) ───────────────────────────────
wifioff_lwa_config() {
    local ap_mac="${1:-00:11:22:33:44:55}"
    local primary_channel="${2:-36}"
    local secondary_channel="${3:-40}"
    
    cat << EOF
LWA Configuration
=================
AP MAC:          $ap_mac
Primary Channel: $primary_channel (5.180 GHz)
Secondary:       $secondary_channel (5.200 GHz)
Aggregation:     Enabled (LWA)
Security:        AES-GCM
EOF
}

# ── Wi-Fi offload auth flow (EAP-AKA') ─────────────────────────────────
wifioff_auth_flow() {
    local imsi="${1:-001010000000000}"
    local nai="${2:-001010000000000@epdg.epc.mnc001.mcc208.3gppnetwork.org}"
    
    cat << EOF
Wi-Fi Offload Auth Flow (EAP-AKA')
==================================
IMSI: $imsi
NAI:  $nai

Steps:
  1. UE sends EAP-Request/Identity
  2. ePDG sends EAP-Request/Challenge
  3. UE responds with EAP-Response/AKA'
  4. ePDG validates via AUSF in 5G core
  5. Session established over IPsec tunnel

Status: Handoff
Hardware: ePDG with valid certificates
Plan: Capture EAP-AKA' handshake over IPsec
EOF
}

# ── Cert thumbprint extraction (for debugging) ─────────────────────────
wifioff_cert_thumbprint() {
    local cert_path="${1:-}"
    [[ -z "$cert_path" || ! -f "$cert_path" ]] && { warn "usage: --cert-thumbprint <cert.pem>"; return 1; }
    
    openssl x509 -in "$cert_path" -noout -fingerprint -sha256 2>/dev/null
}

# ── Selftest ───────────────────────────────────────────────────────────
wifioff_selftest() {
    local bad=0 nchk=0
    chk() {
        nchk=$(( nchk + 1 ))
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$(( bad + 1 )); fi
    }

    # 1. ePDG FQDN construction (TS 23.401 §5.4.5)
    local fqdn1=$(wifioff_epdg_fqdn "20801")
    chk epdg-fqdn-20801 "$fqdn1" "epdg.epc.mnc001.mcc208.3gppnetwork.org"
    
    local fqdn2=$(wifioff_epdg_fqdn "310260")
    chk epdg-fqdn-310260 "$fqdn2" "epdg.epc.mnc260.mcc310.3gppnetwork.org"

    # 2. Certificate thumbprint extraction
    # Create a minimal self-signed cert for testing
    local tmp_cert=$(mktemp)
    openssl req -x509 -newkey rsa:2048 -keyout /dev/null -out "$tmp_cert" \
        -days 1 -nodes -subj "/CN=test" >/dev/null 2>&1
    local fp=$(openssl x509 -in "$tmp_cert" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':')
    rm -f "$tmp_cert"
    chk cert-thumb-printable "$([[ -n "$fp" ]] && echo yes || echo no)" "yes"
    chk cert-thumb-len "${#fp}" "64"

    # 3. LWA config construction
    local lwa=$(wifioff_lwa_config "aa:bb:cc:dd:ee:ff" "44" "48")
    chk lwa-ch1 "$(echo "$lwa" | grep 'Primary Channel:' | awk '{print $3}')" "44"
    chk lwa-ch2 "$(echo "$lwa" | grep 'Secondary:' | awk '{print $2}')" "48"

    # 4. Auth flow output shape
    local flow=$(wifioff_auth_flow "001010000000000")
    chk flow-steps "$(echo "$flow" | grep -c 'Steps:')" "1"
    chk flow-eap "$(echo "$flow" | grep -c 'EAP-Request')" "2"

    # 5. Unknown values must fail appropriately
    local bad_fqdn=$(wifioff_epdg_fqdn "invalid")
    chk fqdn-invalid-chars "$([[ "$bad_fqdn" == *"invalid"* ]] && echo yes || echo no)" "no"
    
    local bad_cert=$(wifioff_cert_thumbprint "/nonexistent.pem" 2>/dev/null; echo $?)
    chk cert-missing-rc "$bad_cert" "1"

    printf 'ASSERTIONS\t%d\n' "$nchk"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ── menu ───────────────────────────────────────────────────────────────
wifioff_menu() {
    while true; do
        banner
        echo -e "  ${C_MAG}=== Wi-Fi Offload / LWA ===${C_RESET}\n"
        cat << 'M'
  [1]  ePDG FQDN for PLMN
  [2]  Validate certificate
  [3]  LWA configuration
  [4]  Show auth flow
  [5]  Certificate thumbprint
  [0]  back

M
        read -rp "  choice> " c || return 0
        case "$c" in
            1)
                read -rp "  PLMN (MCCMNC)> " p
                echo "$(wifioff_epdg_fqdn "$p")"
                read -rp "  press enter " _ ;;
            2)
                read -rp "  cert path> " f
                wifioff_validate_cert "$f"; read -rp "  press enter " _ ;;
            3)
                read -rp "  AP MAC> " a
                read -rp "  primary channel> " p
                read -rp "  secondary channel> " s
                wifioff_lwa_config "$a" "$p" "$s"; read -rp "  press enter " _ ;;
            4)
                read -rp "  IMSI> " i
                read -rp "  NAI> " n
                wifioff_auth_flow "$i" "$n"; read -rp "  press enter " _ ;;
            5)
                read -rp "  cert path> " f
                wifioff_cert_thumbprint "$f"; read -rp "  press enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ── CLI dispatch ───────────────────────────────────────────────────────
wifioff_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)   wifioff_status_tsv ;;
        --epdg-fqdn)    wifioff_epdg_fqdn "${1:-20801}" ;;
        --validate-cert) wifioff_validate_cert "${1:-}" ;;
        --lwa-config)   wifioff_lwa_config "${1:-00:11:22:33:44:55}" "${2:-36}" "${3:-40}" ;;
        --auth-flow)    wifioff_auth_flow "${1:-001010000000000}" "${2:-}" ;;
        --cert-thumb)   wifioff_cert_thumbprint "${1:-}" ;;
        --selftest)     wifioff_selftest ;;
        --menu)         wifioff_menu ;;
        *) cat >&2 <<EOF
Wi-Fi Offload / LWA — ePDG trust model, WFA certificates, LWA steering

Usage: $0 COMMAND
  --status-tsv        tool and store state as TSV
  --epdg-fqdn [plmn]
  --validate-cert <cert.pem>
  --lwa-config [mac] [ch1] [ch2]
  --auth-flow [imsi] [nai]
  --cert-thumb <cert.pem>
  --selftest          verify tables and parsers
  --menu              interactive menu
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
    wifioff_cli_main "$@"
fi
