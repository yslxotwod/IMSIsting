#!/usr/bin/env bash
# ussd — Unstructured Supplementary Service Data: MMI parsing and 7-bit packing.
#
# USSD is a session-oriented cousin of SMS that carries the *#...# menu strings
# a handset sends to the network. It is a real, under-audited surface: an
# inbound USSD or SIM-Toolkit string that contains a trigger sequence can start
# a new supplementary-service transaction without the subscriber's intent
# (USSD/STK injection). This module builds and parses USSD at the octet level
# from TS 23.038 and TS 24.090, and detects that injection pattern.
#
# Attack owned: O14 adjacency (subscriber steering via signalling) — protocol
# codec plus detection. The transmit step is a handoff.
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

MOD_TMP="$TMP_DIR/ussd"
USSD_DIR="$LOOT_DIR/ussd"
mkdir -p "$MOD_TMP" "$USSD_DIR" 2>/dev/null

declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
declare -F warn >/dev/null 2>&1 || warn() { printf '[warn] %s\n' "$*" >&2; }
declare -F err  >/dev/null 2>&1 || err()  { printf '[err]  %s\n' "$*" >&2; }
declare -F ok   >/dev/null 2>&1 || ok()   { printf '[ok]   %s\n' "$*" >&2; }
declare -F banner >/dev/null 2>&1 || banner() { :; }

ussd_sanitize() { printf '%s' "${1:-}" | tr '\t\r\n' '   '; }
USSD_F=()
ussd_split() {
    USSD_F=()
    local i n
    n=$(printf '%s' "$1" | awk -F'\t' '{print NF}')
    for (( i = 1; i <= n; i++ )); do
        USSD_F+=("$(printf '%s' "$1" | cut -f"$i")")
    done
}
ussd_norm_hex() { printf '%s' "${1:-}" | tr -d ' \t\r\n:.-' | sed 's/^0x//I' | tr 'A-F' 'a-f'; }

# ── GSM 7-bit default alphabet (TS 23.038 §6.2.1) ───────────────────────
# Only the printable subset a USSD/MMI string actually carries is mapped; the
# remainder is the extension escape and locale characters. A character outside
# the table is a hard error, never silently replaced.
ussd_septet_of_char() {
    local ch="${1:-}"
    case "$ch" in
        ' ') printf '32'; return 0 ;;
        [0-9]) printf '%d' "$(( $(printf '%d' "'$ch") ))"; return 0 ;;
        [A-Z]) printf '%d' "$(( $(printf '%d' "'$ch") ))"; return 0 ;;
        [a-z]) printf '%d' "$(( $(printf '%d' "'$ch") ))"; return 0 ;;
        '!') printf '33';; '"') printf '34';; '#') printf '35';; '%') printf '37';;
        '&') printf '38';; "'") printf '39';; '(') printf '40';; ')') printf '41';;
        '*') printf '42';; '+') printf '43';; ',') printf '44';; '-') printf '45';;
        '.') printf '46';; '/') printf '47';; ':') printf '58';; ';') printf '59';;
        '<') printf '60';; '=') printf '61';; '>') printf '62';; '?') printf '63';;
        *) printf 'ERROR\tcharacter not in the 7-bit default alphabet: %s\n' "$ch" >&2; return 2 ;;
    esac
    return 0
}
ussd_char_of_septet() {
    local s="${1:-0}"
    case "$s" in
        0)  printf '@' ;;
        1)  printf '£' ;;
        2)  printf '$' ;;
        10) printf '\n' ;;
        13) printf '\r' ;;
        27) printf '\033' ;;
        36) printf '¤' ;;
        64) printf '¡' ;;
        91) printf 'Ä' ;;
        92) printf 'Ö' ;;
        93) printf 'Ñ' ;;
        94) printf 'Ü' ;;
        95) printf '§' ;;
        96) printf '¿' ;;
        123) printf 'ä' ;;
        124) printf 'ö' ;;
        125) printf 'ñ' ;;
        126) printf 'ü' ;;
        *)  if (( s >= 32 && s <= 126 )); then printf "\\$(printf '%03o' "$s")"; else printf '?' ; fi ;;
    esac
}

# ── 7-bit packing (TS 23.038 §6.1.2.1) ──────────────────────────────────
ussd_pack() {
    local text="${1:-}"
    local n=${#text}
    (( n > 0 )) || { printf 'ERROR\tempty string\n' >&2; return 2; }
    local nbytes=$(( (n * 7 + 7) / 8 ))
    local out=() i
    for (( i = 0; i < nbytes; i++ )); do out[i]=0; done
    for (( i = 0; i < n; i++ )); do
        local s; s=$(ussd_septet_of_char "${text:i:1}") || return 2
        local bitpos=$(( i * 7 )) byte=$(( i * 7 / 8 )) shift=$(( i * 7 % 8 ))
        out[byte]=$(( out[byte] | ((s << shift) & 0xFF) ))
        if (( shift > 1 )); then
            out[byte+1]=$(( out[byte+1] | (s >> (8 - shift)) ))
        fi
    done
    printf '%02x' "${out[@]}"
}
ussd_unpack() {
    local hex; hex=$(ussd_norm_hex "${1:-}")
    local count="${2:-0}"
    [[ -n "$hex" && "$hex" =~ ^[0-9a-f]+$ && $(( ${#hex} % 2 )) -eq 0 ]] || {
        printf 'ERROR\tnot even-length hex\n' >&2; return 2; }
    local nbytes=$(( ${#hex} / 2 ))
    local b=() i
    for (( i = 0; i < nbytes; i++ )); do b[i]=$(( 16#${hex:$((i*2)):2} )); done
    local nseptets=$(( nbytes * 8 / 7 ))
    (( count > 0 && count < nseptets )) && nseptets=$count
    for (( i = 0; i < nseptets; i++ )); do
        local bitpos=$(( i * 7 )) byte=$(( i * 7 / 8 )) shift=$(( i * 7 % 8 ))
        local val=$(( b[byte] >> shift ))
        if (( shift > 1 )); then
            val=$(( val | (b[byte+1] << (8 - shift)) ))
        fi
        ussd_char_of_septet "$(( val & 0x7F ))"
    done
}

# ── USSD facility message (TS 24.090): [DCS][7-bit text] ────────────────
ussd_dcs_name() {
    case "$1" in
        0x0F) echo "GSM 7-bit default alphabet" ;;
        0x00) echo "GSM 7-bit default alphabet (packed)" ;;
        0x44) echo "8-bit data" ;;
        0x48) echo "UCS2 (16-bit)" ;;
        *) echo "unknown — never classified as a safe default" ;;
    esac
}
ussd_build() {
    local dcs text="${2:-}"
    dcs=$(printf '%s' "${1:-0F}" | tr 'A-F' 'a-f')
    local packed; packed=$(ussd_pack "$text") || return 2
    printf 'dcs\t%s\ntext7bit\t%s\nmessage\t%s%s\n' "$dcs" "$packed" "$dcs" "$packed"
}

# ── MMI / supplementary-service parsing (TS 22.030) ─────────────────────
ussd_ss_name() {
    case "$1" in
        21) echo "Call Forwarding Unconditional" ;;
        61) echo "Call Forwarding on No Reply" ;;
        62) echo "Call Forwarding on Not Reachable" ;;
        67) echo "Call Forwarding on Busy" ;;
        002) echo "All forwarding services" ;;
        33) echo "Barring of All Outgoing Calls" ;;
        35) echo "Barring of All Incoming Calls" ;;
        43) echo "Call Waiting" ;;
        30) echo "Caller ID Presentation" ;;
        31) echo "Caller ID Restriction" ;;
        03) echo "Change barring password" ;;
        06) echo "IMEI request (*#06#)" ;;
        *) echo "unknown supplementary-service code" ;;
    esac
}
ussd_mmi_parse() {
    local s="${1:-}"
    [[ -n "$s" ]] || { printf 'ERROR\tempty MMI string\n' >&2; return 2; }
    local action="" code="" param=""
    if [[ "$s" =~ ^\*#([0-9]+)\*([0-9*#]+)#$ ]]; then action=interrogate; code="${BASH_REMATCH[1]}"; param="${BASH_REMATCH[2]}"
    elif [[ "$s" =~ ^\*#([0-9]+)#$ ]];            then action=interrogate; code="${BASH_REMATCH[1]}"
    elif [[ "$s" =~ ^\*\*([0-9]+)\*([^#]*)#$ ]];  then action=register;    code="${BASH_REMATCH[1]}"; param="${BASH_REMATCH[2]}"
    elif [[ "$s" =~ ^\*([0-9]+)\*([^#]*)#$ ]];    then action=activate;    code="${BASH_REMATCH[1]}"; param="${BASH_REMATCH[2]}"
    elif [[ "$s" =~ ^##([0-9]+)#$ ]];             then action=erase;       code="${BASH_REMATCH[1]}"
    elif [[ "$s" =~ ^#([0-9]+)#$ ]];              then action=deactivate;  code="${BASH_REMATCH[1]}"
    else
        printf 'ERROR\tnot a well-formed MMI/SS string: %s\n' "$s" >&2; return 1
    fi
    printf 'action\t%s\ncode\t%s\nservice\t%s\nparameter\t%s\n' \
        "$action" "$code" "$(ussd_ss_name "$code")" "$param"
}

# ── injection detection (the defensive half) ────────────────────────────
# A string delivered by an SMS/USSD/STK push that embeds a fresh MMI trigger
# can launch a supplementary-service transaction with no subscriber intent.
ussd_inject_detect() {
    local s="${1:-}"
    printf 'finding\tseverity\tdetail\n'
    local n=0
    if [[ "$s" =~ [*#]{1,2}[0-9]{2,}[*#] ]]; then
        printf 'embedded_mmi_trigger\tHIGH\tthe string contains a USSD/MMI trigger sequence; a parser that re-dispatches it starts a new SS transaction\n'; n=$((n+1))
    fi
    if [[ "$s" =~ https?:// ]]; then
        printf 'embedded_url\tMEDIUM\tthe string carries a URL; a STK/S@T browser command can be steered to it\n'; n=$((n+1))
    fi
    if [[ "$s" =~ (090|091|092|093|0900)[0-9]{3,} ]]; then
        printf 'premium_rate_number\tHIGH\ta premium-rate range number appears in the payload\n'; n=$((n+1))
    fi
    if [[ "${s,,}" =~ (install|tar|bip|s@t|sat[ /-]?browser) ]]; then
        printf 'stk_command_keyword\tMEDIUM\tthe payload names a toolkit action; treat as a proactive-command candidate\n'; n=$((n+1))
    fi
    (( n == 0 )) && printf 'none\tINFO\tno embedded trigger, URL or premium-rate pattern\n'
    printf 'findings\t%d\n' "$n"
    return 0
}

ussd_plan() {
    cat <<'EOF'
status	handoff
what	sending a USSD/SS transaction or an OTA push to a handset
hardware	a USIM you control plus a programmable SIM (sysmoISIM-SJA2) or an Osmocom testbed with a USSD gateway
software	osmo-msc, osmo-hlr, a USSD centre, or a rooted handset test bench
flow	1. build the facility message here with --build  2. originate it through the owned gateway  3. observe with the injection detector
note	originating against a live HLR needs that subscriber's authorisation; nothing is transmitted by this module
EOF
}

ussd_selftest() {
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
    export USSD_DIR="$d/loot/ussd"
    mkdir -p "$USSD_DIR"

    # 1. The published 7-bit packing example: 'h'(0x68) and 'i'(0x69) pack to
    #    E8 34. This is the worked example in every GSM 03.38 explanation.
    chk pack-hi   "$(ussd_pack hi)"        "e834"
    chk unpack-hi "$(ussd_unpack e834)"    "hi"
    chk septet-h  "$(ussd_septet_of_char h)" "104"
    chk septet-i  "$(ussd_septet_of_char i)" "105"
    chk char-104  "$(ussd_char_of_septet 104)" "h"
    # round-trip a string that mixes letters, digits and the MMI characters.
    local s1="*#21#"
    chk roundtrip-mmi "$(ussd_unpack "$(ussd_pack "$s1")")" "$s1"
    local s2="+15551234"
    chk roundtrip-plus "$(ussd_unpack "$(ussd_pack "$s2")")" "$s2"
    chk pack-empty "$(ussd_pack '' >/dev/null 2>&1; echo $?)" "2"
    chk pack-badchar "$(ussd_pack 'tab	' >/dev/null 2>&1; echo $?)" "2"
    chk unpack-badhex "$(ussd_unpack zz >/dev/null 2>&1; echo $?)" "2"

    # 2. DCS default (TS 23.038): 0x0F for USSD.
    chk dcs-0f "$(ussd_dcs_name 0x0F)" "GSM 7-bit default alphabet"
    chk dcs-unknown "$(ussd_dcs_name 0xEE)" "unknown — never classified as a safe default"

    # 3. Facility message build: DCS then packed text.
    local out; out=$(ussd_build 0F hi)
    chk build-msg   "$(fld "$out" message)" "0fe834"
    chk build-7bit  "$(fld "$out" text7bit)" "e834"

    # 4. MMI parsing with the TS 22.030 service codes.
    out=$(ussd_mmi_parse '*#21#')
    chk mmi-interrogate "$(fld "$out" action)" "interrogate"
    chk mmi-code        "$(fld "$out" code)" "21"
    chk mmi-name        "$(fld "$out" service)" "Call Forwarding Unconditional"
    out=$(ussd_mmi_parse '*67*+15551234#')
    chk mmi-activate "$(fld "$out" action)" "activate"
    chk mmi-param    "$(fld "$out" parameter)" "+15551234"
    chk mmi-busy     "$(fld "$out" service)" "Call Forwarding on Busy"
    out=$(ussd_mmi_parse '**61*+15551234#')
    chk mmi-register "$(fld "$out" action)" "register"
    chk mmi-noreply  "$(fld "$out" service)" "Call Forwarding on No Reply"
    out=$(ussd_mmi_parse '##21#')
    chk mmi-erase "$(fld "$out" action)" "erase"
    out=$(ussd_mmi_parse '#21#')
    chk mmi-deactivate "$(fld "$out" action)" "deactivate"
    out=$(ussd_mmi_parse '*#06#')
    chk mmi-imei "$(fld "$out" service)" "IMEI request (*#06#)"
    chk mmi-malformed "$(ussd_mmi_parse 'hello' >/dev/null 2>&1; echo $?)" "1"
    chk mmi-empty "$(ussd_mmi_parse '' >/dev/null 2>&1; echo $?)" "2"
    chk mmi-unknown-code "$(ussd_ss_name 99)" "unknown supplementary-service code"

    # 5. Injection detection: fires on the pattern, abstains on plain text.
    out=$(ussd_inject_detect 'hi *#002# please')
    chk inj-trigger "$(fld "$out" embedded_mmi_trigger)" "HIGH"
    chk inj-count   "$(fld "$out" findings)" "1"
    out=$(ussd_inject_detect 'call me on +15551234')
    chk inj-clean "$(fld "$out" none)" "INFO"
    chk inj-clean-count "$(fld "$out" findings)" "0"
    out=$(ussd_inject_detect 'tap http://evil.example/install to continue')
    chk inj-url "$(fld "$out" embedded_url)" "MEDIUM"
    chk inj-stk "$(fld "$out" stk_command_keyword)" "MEDIUM"

    printf 'ASSERTIONS\t%d\n' "$nchk"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

ussd_menu() {
    while true; do
        banner
        echo "  === USSD ==="
        echo
        cat <<'M'
  [1]  Pack a string to 7-bit
  [2]  Unpack 7-bit to a string
  [3]  Build a USSD facility message
  [4]  Parse an MMI / SS string
  [5]  Service-code reference
  [6]  Detect USSD/STK injection
  [7]  Plan (handoff)
  [0]  back
M
        read -rp "  choice> " c || return 0
        case "$c" in
            1) read -rp "  text> " t; ussd_pack "$t"; echo; read -rp "  enter " _ ;;
            2) read -rp "  hex> " h; ussd_unpack "$h"; echo; read -rp "  enter " _ ;;
            3) read -rp "  dcs (hex)> " x; read -rp "  text> " t; ussd_build "$x" "$t"; read -rp "  enter " _ ;;
            4) read -rp "  mmi string> " m; ussd_mmi_parse "$m"; read -rp "  enter " _ ;;
            5) for c in 21 61 62 67 002 33 35 43 30 31 06; do printf '  %s\t%s\n' "$c" "$(ussd_ss_name "$c")"; done; read -rp "  enter " _ ;;
            6) read -rp "  payload> " p; ussd_inject_detect "$p"; read -rp "  enter " _ ;;
            7) ussd_plan; read -rp "  enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

ussd_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)  ussd_status_tsv ;;
        --pack)        ussd_pack "${1:-}" ;;
        --unpack)      ussd_unpack "${1:-}" ;;
        --build)       ussd_build "${1:-0F}" "${2:-}" ;;
        --mmi)         ussd_mmi_parse "${1:-}" ;;
        --ss-codes)    for c in 21 61 62 67 002 33 35 43 30 31 06; do printf '%s\t%s\n' "$c" "$(ussd_ss_name "$c")"; done ;;
        --detect)      ussd_inject_detect "${1:-}" ;;
        --plan)        ussd_plan ;;
        --selftest)    ussd_selftest ;;
        --menu)        ussd_menu ;;
        *)
            cat >&2 <<EOF
USSD Forge — MMI/SS parsing, 7-bit packing and injection detection

Usage: $0 COMMAND
  --status-tsv      module state as TSV
  --pack <text>     GSM 7-bit default-alphabet packing
  --unpack <hex>    decode 7-bit packed text
  --build <dcs> <text>   USSD facility message (DCS + packed text)
  --mmi <string>    parse *#...# / **...# MMI strings (TS 22.030)
  --ss-codes        supplementary-service code reference
  --detect <payload>   USSD/STK injection findings
  --plan            lab USSD handoff plan
  --selftest        verify packing and parsers, no radio needed
  --menu            interactive menu
EOF
            return 2 ;;
    esac
}

# status lives here so the dispatch reads top-down.
ussd_status_tsv() {
    printf 'MODULE\tussd\n'
    printf 'TARGET\tUSSD/MMI messages, supplementary-service codes, STK injection\n'
    printf 'TRANSMIT\tnone — codec and detection only\n'
    printf 'SELFTEST\tyes\n'
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
    ussd_cli_main "$@"
fi
