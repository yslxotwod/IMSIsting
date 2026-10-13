#!/usr/bin/env bash
# gprs — GPRS/EDGE packet core: GEA ciphering, APN coding and PDP context.
#
# The circuit-switched half of 2G is covered by 10_gsm_air; the packet-switched
# half is its own stack. This module covers the GEA ciphering family (the GPRS
# equivalent of A5), the APN coding and PDP context of TS 24.008/TS 23.003, the
# Gb/SGSN trust model, and a GEA-downgrade detector. Everything here is
# protocol work from the published specs; the air-interface step is a handoff.
#
# Attack owned: 2G packet-switched (O5/O4 adjacency) — codec and detection half.
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

MOD_TMP="$TMP_DIR/gprs"
GPRS_DIR="$LOOT_DIR/gprs"
mkdir -p "$MOD_TMP" "$GPRS_DIR" 2>/dev/null

declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
declare -F warn >/dev/null 2>&1 || warn() { printf '[warn] %s\n' "$*" >&2; }
declare -F err  >/dev/null 2>&1 || err()  { printf '[err]  %s\n' "$*" >&2; }
declare -F ok   >/dev/null 2>&1 || ok()   { printf '[ok]   %s\n' "$*" >&2; }
declare -F banner >/dev/null 2>&1 || banner() { :; }

gprs_sanitize() { printf '%s' "${1:-}" | tr '\t\r\n' '   '; }
GPRS_F=()
gprs_split() {
    GPRS_F=()
    local i n
    n=$(printf '%s' "$1" | awk -F'\t' '{print NF}')
    for (( i = 1; i <= n; i++ )); do
        GPRS_F+=("$(printf '%s' "$1" | cut -f"$i")")
    done
}
gprs_str2hex() { local s="${1:-}" out="" i; for (( i=0; i<${#s}; i++ )); do printf -v c '%02x' "'${s:i:1}"; out+="$c"; done; printf '%s' "$out"; }
gprs_hex2str() { local h="${1:-}"; printf '%b' "$(printf '%s' "$h" | sed 's/../\\x&/g')"; }

gprs_status_tsv() {
    printf 'MODULE\tgprs\n'
    printf 'TARGET\tGPRS/EDGE GEA ciphering, APN coding, PDP context, downgrade\n'
    printf 'TRANSMIT\tnone — codec and detection\n'
    printf 'SELFTEST\tyes\n'
}

# ── GEA ciphering family (TS 43.020 / TS 44.064) ────────────────────────
gprs_gea_table() {
    cat <<'EOF'
algo	key_bits	status
GEA0	0	no encryption — user data is sent in the clear
GEA1	64	related to the A5/2 family; considered broken
GEA2	64	KASUMI-based, 64-bit key
GEA3	64	KASUMI-based with an extendable key
GEA4	128	later, stronger GEA
EOF
}
gprs_gea_name() {
    case "$1" in
        0) echo "GEA0 (no encryption)" ;;
        1) echo "GEA1 (weak, A5/2 family)" ;;
        2) echo "GEA2 (KASUMI)" ;;
        3) echo "GEA3 (KASUMI, extendable key)" ;;
        4) echo "GEA4 (128-bit)" ;;
        *) echo "unknown GEA — never classified as safe" ;;
    esac
}

# ── APN coding (TS 23.003 §9.1) ─────────────────────────────────────────
# A DNS-style name: each label prefixed by its length octet, no trailing root.
# Worked anchor: "internet" -> 08 696e7465726e6574.
gprs_apn_encode() {
    local apn="${1:-}"
    [[ -n "$apn" ]] || { printf 'ERROR\tempty APN\n' >&2; return 2; }
    local IFS='.' out="" label lhex
    for label in $apn; do
        [[ -n "$label" ]] || { printf 'ERROR\tempty APN label\n' >&2; return 2; }
        (( ${#label} <= 63 )) || { printf 'ERROR\tAPN label longer than 63 octets\n' >&2; return 2; }
        [[ "$label" =~ ^[A-Za-z0-9-]+$ ]] || { printf 'ERROR\tAPN label has an invalid character: %s\n' "$label" >&2; return 2; }
        lhex=$(gprs_str2hex "$label")
        printf -v lc '%02x' "${#label}"
        out+="${lc}${lhex}"
    done
    printf '%s\n' "$out"
}
gprs_apn_decode() {
    local h="${1:-}"
    h=$(printf '%s' "$h" | tr -d ' \t\r\n:.-' | sed 's/^0x//I' | tr 'A-F' 'a-f')
    [[ "$h" =~ ^[0-9a-f]+$ && $(( ${#h} % 2 )) -eq 0 ]] || { printf 'ERROR\tnot even-length hex\n' >&2; return 2; }
    local out="" off=0
    while (( off*2 < ${#h} )); do
        local len=$(( 16#${h:$((off*2)):2} ))
        (( len > 0 && len <= 63 )) || { printf 'ERROR\tbad APN label length %d at octet %d\n' "$len" "$off" >&2; return 1; }
        (( (off+1+len)*2 <= ${#h} )) || { printf 'ERROR\tAPN label runs past the end\n' >&2; return 1; }
        out+="$(gprs_hex2str "${h:$(((off+1)*2)):$((len*2))}")."
        off=$(( off + 1 + len ))
    done
    printf '%s\n' "${out%.}"
}

# ── PDP context (TS 24.008 §10.5.6) ─────────────────────────────────────
gprs_pdp_type_name() {
    case "$1" in
        01) echo "PPP" ;;
        21) echo "IPv4" ;;
        57) echo "IPv6" ;;
        8D) echo "IPv4v6" ;;
        *) echo "unknown PDP type — never classified as valid" ;;
    esac
}
gprs_apn_ie() {
    local apn="${1:-}"
    local body; body=$(gprs_apn_encode "$apn") || return 2
    printf -v lc '%02x' "$(( ${#body} / 2 ))"
    printf 'IEI\t28\nlength\t%s\nvalue\t%s\nie\t28%s%s\n' "$lc" "$body" "$lc" "$body"
}
gprs_pdp_type_ie() {
    local t="${1:-21}"
    printf 'IEI\t11\nlength\t01\nvalue\t%s\nname\t%s\nie\t1101%s\n' "$t" "$(gprs_pdp_type_name "$t")" "$t"
}

# ── GEA downgrade detection ─────────────────────────────────────────────
gprs_gea_downgrade() {
    local offered="${1:-}" selected="${2:-}"
    [[ -n "$offered" && "$selected" =~ ^[0-4]$ ]] || { printf 'ERROR\tusage: --gea-downgrade <offered,csv> <selected 0-4>\n' >&2; return 2; }
    local best=0 a
    local IFS=','
    for a in $offered; do
        [[ "$a" =~ ^[0-4]$ ]] || { printf 'ERROR\tnot a GEA index: %s\n' "$a" >&2; return 2; }
        (( a > best )) && best=$a
    done
    printf 'offered\t%s\nselected\t%s\nselected_name\t%s\nbest_offered\t%s\n' \
        "$offered" "$selected" "$(gprs_gea_name "$selected")" "$(gprs_gea_name "$best")"
    if (( selected == 0 )); then
        printf 'verdict\tDOWNGRADE — the network selected GEA0; user data is unprotected\n'
    elif (( selected < best )); then
        printf 'verdict\tWEAKER — a stronger GEA (%s) was offered but %s was selected\n' "$(gprs_gea_name "$best")" "$(gprs_gea_name "$selected")"
    else
        printf 'verdict\tok — the strongest offered GEA was selected\n'
    fi
}

gprs_plan() {
    cat <<'EOF'
status	handoff
what	capturing or injecting on the Gb or Gn interface
hardware	an SDR for the Um/Gb air interface, or a lab SGSN/GGSN (Osmocom SGSN) on a Gb/IP link
software	Osmocom osmo-sgsn, osmo-ggsn, a packet capture point, and a USIM with GPRS data
flow	1. encode the APN/PDP context here  2. capture the Attach/PDP activation  3. --gea-downgrade over the offered vs selected GEA
note	the air interface needs a BTS and a licence; this module works on captures and configurations you hold
EOF
}

gprs_selftest() {
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
    export GPRS_DIR="$d/loot/gprs"
    mkdir -p "$GPRS_DIR"

    # 1. APN coding (TS 23.003 §9.1). "internet" -> 08 69 6e 74 65 72 6e 65 74.
    chk apn-internet "$(gprs_apn_encode internet)" "08696e7465726e6574"
    chk apn-two "$(gprs_apn_encode internet.telekom)" "08696e7465726e65740774656c656b6f6d"
    chk apn-decode "$(gprs_apn_decode 08696e7465726e65740774656c656b6f6d)" "internet.telekom"
    chk apn-round "$(gprs_apn_decode "$(gprs_apn_encode operator.mnc001.mcc001.gprs)")" "operator.mnc001.mcc001.gprs"
    chk apn-empty "$(gprs_apn_encode '' >/dev/null 2>&1; echo $?)" "2"
    chk apn-badchar "$(gprs_apn_encode 'in ternet' >/dev/null 2>&1; echo $?)" "2"
    chk apn-badlen "$(gprs_apn_decode 09696e7465726e6574 >/dev/null 2>&1; echo $?)" "1"

    # 2. PDP types (TS 29.060 §7.7.1).
    chk pdp-ipv4 "$(gprs_pdp_type_name 21)" "IPv4"
    chk pdp-ipv6 "$(gprs_pdp_type_name 57)" "IPv6"
    chk pdp-ipv4v6 "$(gprs_pdp_type_name 8D)" "IPv4v6"
    chk pdp-ppp "$(gprs_pdp_type_name 01)" "PPP"
    chk pdp-unknown "$(gprs_pdp_type_name FF)" "unknown PDP type — never classified as valid"
    chk apn-ie "$(fld "$(gprs_apn_ie internet)" ie)" "280908696e7465726e6574"
    chk pdp-ie "$(fld "$(gprs_pdp_type_ie 21)" ie)" "110121"

    # 3. GEA table and downgrade detection.
    chk gea0 "$(gprs_gea_table | awk -F'\t' '$1=="GEA0"{print $3}')" "no encryption — user data is sent in the clear"
    chk gea4 "$(gprs_gea_table | awk -F'\t' '$1=="GEA4"{print $2}')" "128"
    chk gea-name "$(gprs_gea_name 1)" "GEA1 (weak, A5/2 family)"
    chk gea-unknown "$(gprs_gea_name 9)" "unknown GEA — never classified as safe"
    chk gea-downgrade0 "$(fld "$(gprs_gea_downgrade 1,2,3 0)" verdict)" "DOWNGRADE — the network selected GEA0; user data is unprotected"
    chk gea-weaker "$(gprs_gea_downgrade 1,2,3 2 | awk -F'\t' '$1=="verdict"{print ($2 ~ /WEAKER/)?"weaker":"ok"}')" "weaker"
    chk gea-ok "$(gprs_gea_downgrade 1,2,3 3 | awk -F'\t' '$1=="verdict"{print ($2 ~ /^ok/)?"ok":"no"}')" "ok"
    chk gea-bad "$(gprs_gea_downgrade 9 1 >/dev/null 2>&1; echo $?)" "2"

    printf 'ASSERTIONS\t%d\n' "$nchk"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

gprs_menu() {
    while true; do
        banner
        echo "  === GPRS / EDGE ==="
        echo
        cat <<'M'
  [1]  GEA cipher reference
  [2]  Encode an APN
  [3]  Decode an APN
  [4]  Build the APN / PDP-type IEs
  [5]  GEA downgrade check
  [6]  Plan (handoff)
  [0]  back
M
        read -rp "  choice> " c || return 0
        case "$c" in
            1) gprs_gea_table; read -rp "  enter " _ ;;
            2) read -rp "  apn> " a; gprs_apn_encode "$a"; read -rp "  enter " _ ;;
            3) read -rp "  apn hex> " h; gprs_apn_decode "$h"; read -rp "  enter " _ ;;
            4) read -rp "  apn> " a; read -rp "  pdp type hex> " t; gprs_apn_ie "$a"; gprs_pdp_type_ie "${t:-21}"; read -rp "  enter " _ ;;
            5) read -rp "  offered csv> " o; read -rp "  selected> " s; gprs_gea_downgrade "$o" "$s"; read -rp "  enter " _ ;;
            6) gprs_plan; read -rp "  enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

gprs_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)   gprs_status_tsv ;;
        --gea-table)    gprs_gea_table ;;
        --gea)          gprs_gea_name "${1:-}" ;;
        --apn-encode)   gprs_apn_encode "${1:-}" ;;
        --apn-decode)   gprs_apn_decode "${1:-}" ;;
        --apn-ie)       gprs_apn_ie "${1:-}" ;;
        --pdp-ie)       gprs_pdp_type_ie "${1:-21}" ;;
        --gea-downgrade) gprs_gea_downgrade "${1:-}" "${2:-}" ;;
        --plan)         gprs_plan ;;
        --selftest)     gprs_selftest ;;
        --menu)         gprs_menu ;;
        *)
            cat >&2 <<EOF
GPRS / EDGE — GEA ciphering, APN coding, PDP context

Usage: $0 COMMAND
  --status-tsv                 module state as TSV
  --gea-table                  the GEA cipher family
  --gea <n>                    name one GEA
  --apn-encode <apn>           TS 23.003 §9.1 label coding
  --apn-decode <hex>           decode a coded APN
  --apn-ie <apn>               APN information element
  --pdp-ie <type_hex>          PDP type information element
  --gea-downgrade <csv> <n>    offered vs selected GEA
  --plan                       Gb/Gn lab handoff plan
  --selftest                   verify the codecs and the detector
  --menu                       interactive menu
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
    gprs_cli_main "$@"
fi
