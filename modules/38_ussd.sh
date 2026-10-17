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
# The whole table, both ways. Every one of the 128 septets decodes to the
# character the clause assigns it -- there are no unassigned positions -- and
# every character the table names packs back to its septet. The extension
# table (§6.2.1.1) rides behind ESC (27): those characters emit "E <code>" on
# encode and take two septets, which is why the packer works on septets rather
# than on characters.
#
# The previous table was a hand-picked subset ("only what a USSD string
# carries"): 'è', '¥', '_', '€' and every bracketed character were refused on
# encode, and the decoder answered '?' for 26 positions -- a silent
# substitution in a function whose own comment promised a hard error. A USSD
# message can carry any of these; a decoder that invents a '?' turns a card's
# answer into a different string.
ussd_septet_of_char() {
    local ch="${1:-}"
    [[ -n "$ch" ]] || { printf 'ERROR\tempty character\n' >&2; return 2; }
    case "$ch" in
        '@') printf '0';   return 0 ;;
        '£') printf '1';   return 0 ;;
        '$') printf '2';   return 0 ;;
        '¥') printf '3';   return 0 ;;
        'è') printf '4';   return 0 ;;
        'é') printf '5';   return 0 ;;
        'ù') printf '6';   return 0 ;;
        'ì') printf '7';   return 0 ;;
        'ò') printf '8';   return 0 ;;
        'Ç') printf '9';   return 0 ;;
        'Ø') printf '11';  return 0 ;;
        'ø') printf '12';  return 0 ;;
        'Å') printf '14';  return 0 ;;
        'å') printf '15';  return 0 ;;
        'Δ') printf '16';  return 0 ;;
        '_') printf '17';  return 0 ;;
        'Φ') printf '18';  return 0 ;;
        'Γ') printf '19';  return 0 ;;
        'Λ') printf '20';  return 0 ;;
        'Ω') printf '21';  return 0 ;;
        'Π') printf '22';  return 0 ;;
        'Ψ') printf '23';  return 0 ;;
        'Σ') printf '24';  return 0 ;;
        'Θ') printf '25';  return 0 ;;
        'Ξ') printf '26';  return 0 ;;
        'Æ') printf '28';  return 0 ;;
        'æ') printf '29';  return 0 ;;
        'ß') printf '30';  return 0 ;;
        'É') printf '31';  return 0 ;;
        '¤') printf '36';  return 0 ;;
        '¡') printf '64';  return 0 ;;
        'Ä') printf '91';  return 0 ;;
        'Ö') printf '92';  return 0 ;;
        'Ñ') printf '93';  return 0 ;;
        'Ü') printf '94';  return 0 ;;
        '§') printf '95';  return 0 ;;
        '¿') printf '96';  return 0 ;;
        'ä') printf '123'; return 0 ;;
        'ö') printf '124'; return 0 ;;
        'ñ') printf '125'; return 0 ;;
        'ü') printf '126'; return 0 ;;
        'à') printf '127'; return 0 ;;
        $'\n') printf '10'; return 0 ;;
        $'\r') printf '13'; return 0 ;;
        # §6.2.1.1 extension table: ESC (27) then the extension code.
        '[')  printf 'E 60';  return 0 ;;
        '\') printf 'E 47';  return 0 ;;
        ']')  printf 'E 62';  return 0 ;;
        '^')  printf 'E 20';  return 0 ;;
        '{')  printf 'E 40';  return 0 ;;
        '|')  printf 'E 64';  return 0 ;;
        '}')  printf 'E 41';  return 0 ;;
        '~')  printf 'E 61';  return 0 ;;
        '€')  printf 'E 101'; return 0 ;;
        $'\f') printf 'E 10'; return 0 ;;
    esac
    # Between the named characters the table is the identity on printable
    # ASCII. Position 0x24 is '¤' and 0x40 '¡', both already taken above.
    local o
    o=$(printf '%d' "'$ch" 2>/dev/null) || o=""
    if [[ "$o" =~ ^[0-9]+$ ]] && (( o >= 32 && o <= 126 )) && [[ "$ch" != '¤' && "$ch" != '¡' ]]; then
        printf '%d' "$o"; return 0
    fi
    printf 'ERROR\tcharacter not in the 7-bit default alphabet: %s\n' "$ch" >&2
    return 2
}
ussd_char_of_septet() {
    local s="${1:-0}"
    case "$s" in
        0)   printf '@' ;;
        1)   printf '£' ;;
        2)   printf '$' ;;
        3)   printf '¥' ;;
        4)   printf 'è' ;;
        5)   printf 'é' ;;
        6)   printf 'ù' ;;
        7)   printf 'ì' ;;
        8)   printf 'ò' ;;
        9)   printf 'Ç' ;;
        10)  printf '\n' ;;
        11)  printf 'Ø' ;;
        12)  printf 'ø' ;;
        13)  printf '\r' ;;
        14)  printf 'Å' ;;
        15)  printf 'å' ;;
        16)  printf 'Δ' ;;
        17)  printf '_' ;;
        18)  printf 'Φ' ;;
        19)  printf 'Γ' ;;
        20)  printf 'Λ' ;;
        21)  printf 'Ω' ;;
        22)  printf 'Π' ;;
        23)  printf 'Ψ' ;;
        24)  printf 'Σ' ;;
        25)  printf 'Θ' ;;
        26)  printf 'Ξ' ;;
        27)  printf '\033' ;;
        28)  printf 'Æ' ;;
        29)  printf 'æ' ;;
        30)  printf 'ß' ;;
        31)  printf 'É' ;;
        36)  printf '¤' ;;
        64)  printf '¡' ;;
        91)  printf 'Ä' ;;
        92)  printf 'Ö' ;;
        93)  printf 'Ñ' ;;
        94)  printf 'Ü' ;;
        95)  printf '§' ;;
        96)  printf '¿' ;;
        123) printf 'ä' ;;
        124) printf 'ö' ;;
        125) printf 'ñ' ;;
        126) printf 'ü' ;;
        127) printf 'à' ;;
        *)   printf "\\$(printf '%03o' "$s")" ;;
    esac
}
ussd_ext_char() {
    case "${1:-}" in
        10)  printf '\f' ;;
        20)  printf '^' ;;
        40)  printf '{' ;;
        41)  printf '}' ;;
        47)  printf '\\' ;;
        60)  printf '[' ;;
        61)  printf '~' ;;
        62)  printf ']' ;;
        64)  printf '|' ;;
        101) printf '€' ;;
        *)   printf 'ERROR\tno GSM 7-bit extension character for code %s\n' "${1:-}" >&2; return 2 ;;
    esac
}
# Text -> space-separated septet codes; an extension character emits "27 <code>".
ussd_septets_of_text() {
    local text="${1:-}" out=() i ch enc
    [[ -n "$text" ]] || { printf 'ERROR\tempty string\n' >&2; return 2; }
    for (( i = 0; i < ${#text}; i++ )); do
        ch="${text:i:1}"
        enc=$(ussd_septet_of_char "$ch") || return 2
        if [[ "$enc" == E\ * ]]; then out+=( 27 "${enc#E }"); else out+=( "$enc" ); fi
    done
    printf '%s' "${out[*]}"
}

# ── 7-bit packing (TS 23.038 §6.1.2.1) ──────────────────────────────────
# "The bit number zero is always transmitted first": septet i starts at bit
# 7*i of the octet string, low bit first.
ussd_pack_septets() {
    local codes="${1:-}" s
    local out=() i=0 byte shift
    set -- $codes
    (( $# > 0 )) || { printf 'ERROR\tno septets to pack\n' >&2; return 2; }
    local nbytes=$(( ($# * 7 + 7) / 8 ))
    for (( byte = 0; byte < nbytes; byte++ )); do out[byte]=0; done
    for s in "$@"; do
        (( s >= 0 && s <= 127 )) || { printf 'ERROR\tseptet out of range: %s\n' "$s" >&2; return 2; }
        local bp=$(( i * 7 )) b=$(( i * 7 / 8 )) sh=$(( i * 7 % 8 ))
        out[b]=$(( out[b] | ((s << sh) & 0xFF) ))
        if (( sh > 1 )); then
            out[b+1]=$(( out[b+1] | (s >> (8 - sh)) ))
        fi
        i=$(( i + 1 ))
    done
    printf '%02x' "${out[@]}"
}
ussd_pack() {
    local codes; codes=$(ussd_septets_of_text "${1:-}") || return 2
    ussd_pack_septets "$codes"
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
    local esc=0 val
    for (( i = 0; i < nseptets; i++ )); do
        local bitpos=$(( i * 7 )) byte=$(( i * 7 / 8 )) shift=$(( i * 7 % 8 ))
        val=$(( b[byte] >> shift ))
        if (( shift > 1 )); then
            val=$(( val | (b[byte+1] << (8 - shift)) ))
        fi
        val=$(( val & 0x7F ))
        if (( esc == 1 )); then
            ussd_ext_char "$val" || return 2
            esc=0
        elif (( val == 27 )); then
            esc=1
        else
            ussd_char_of_septet "$val"
        fi
    done
    (( esc == 0 )) || { printf 'ERROR\tdangling ESC (27) at the end of the septets\n' >&2; return 2; }
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
# TS 22.030 §5.3 / §5.4 start-string grammar:
#   *SC#        activate            (#SC#        deactivate)
#   *SC*SI#     activate with SI    (#SC*SI#     deactivate with SI)
#   **SC*SI#    register            (##SC#       erase)
#   *#SC#       interrogate         (*#SC*SI#    interrogate with SI)
# and each form may carry one more "*SIA" (the "service information" that
# selects e.g. a forwarding timer) after the SI:
#   **SC*SI*SIA#   *SC*SI*SIA#   *#SC*SI*SIA#
# The activate form without an SI -- *43#, the way call waiting is turned on --
# used to be rejected as malformed because the pattern demanded "*" after the
# code, while the deactivate and erase forms already accepted their SI-less
# shape.
ussd_mmi_parse() {
    local s="${1:-}"
    [[ -n "$s" ]] || { printf 'ERROR\tempty MMI string\n' >&2; return 2; }
    local action="" body="" code="" param="" sia="" note=""
    case "$s" in
        '**'*) action=register;    body="${s:2}" ;;
        '##'*) action=erase;       body="${s:2}" ;;
        '*#'*) action=interrogate; body="${s:2}" ;;
        '*'*)  action=activate;    body="${s:1}" ;;
        '#'*)  action=deactivate;  body="${s:1}" ;;
        *)     printf 'ERROR\tnot a well-formed MMI/SS string: %s\n' "$s" >&2; return 1 ;;
    esac
    if [[ "$body" != *# || "${body%#}" == *'#'* ]]; then
        printf 'ERROR\tnot a well-formed MMI/SS string: %s\n' "$s" >&2; return 1
    fi
    body="${body%#}"
    if [[ -z "$body" ]]; then
        printf 'ERROR\tnot a well-formed MMI/SS string: %s (no service code)\n' "$s" >&2; return 1
    fi
    local -a f=()
    local IFS='*'
    read -r -a f <<< "$body"
    unset IFS
    code="${f[0]}"
    param="${f[1]:-}"
    sia="${f[2]:-}"
    if ! [[ "$code" =~ ^[0-9]{1,4}$ ]]; then
        printf 'ERROR\tnot a well-formed MMI/SS string: %s (service code "%s" is not 1-4 digits)\n' "$s" "$code" >&2
        return 1
    fi
    if (( ${#f[@]} > 3 )); then
        printf 'ERROR\tnot a well-formed MMI/SS string: %s (at most SC, SI and SIA are expected)\n' "$s" >&2
        return 1
    fi
    if [[ "$action" == activate && -z "$param" ]]; then
        note="no SI: a bare *SC# is equally a plain MMI/USSD string, so the network decides whether it is an SS activation"
    fi
    printf 'action\t%s\ncode\t%s\nservice\t%s\nparameter\t%s\n' \
        "$action" "$code" "$(ussd_ss_name "$code")" "$param"
    [[ -n "$sia" ]]   && printf 'sia\t%s\n' "$sia"
    [[ -n "$note" ]]  && printf 'note\t%s\n' "$note"
    return 0
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
    # The whole table, both ways. The default alphabet assigns all 128 septets,
    # so a decode never has to invent a character; the extension table rides
    # behind ESC (27) and takes two septets.
    chk pack-accent   "$(ussd_pack 'è')" "04"
    chk char-04       "$(ussd_char_of_septet 4)" "è"
    chk char-24       "$(ussd_char_of_septet 36)" "¤"
    chk char-40       "$(ussd_char_of_septet 64)" "¡"
    chk char-7f       "$(ussd_char_of_septet 127)" "à"
    chk pack-euro     "$(ussd_pack '€')" "9b32"
    chk unpack-euro   "$(ussd_unpack 9b32)" "€"
    chk pack-backslash "$(ussd_pack '\')" "9b17"
    chk unpack-backslash "$(ussd_unpack 9b17)" '\'
    chk unpack-caret  "$(ussd_unpack 1b0a)" "^"
    chk unpack-dangling "$(ussd_unpack 1b >/dev/null 2>&1; echo $?)" "2"
    chk pack-ext-mixed "$(ussd_pack 'a[b')" "e10d4f0c"
    chk roundtrip-ext "$(ussd_unpack "$(ussd_pack 'a[b')")" "a[b"

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
    # *43# -- the way call waiting is switched on -- has no SI, and TS 22.030
    # §5.3 admits the SI-less activate form just as it admits #SC# and ##SC#.
    out=$(ussd_mmi_parse '*43#')
    chk mmi-activate-noparam "$(fld "$out" action)" "activate"
    chk mmi-noparam-empty    "$(fld "$out" parameter)" ""
    chk mmi-noparam-note     "$([[ -n "$(fld "$out" note)" ]] && echo yes)" "yes"
    out=$(ussd_mmi_parse '**21*+4917112345678*20#')
    chk mmi-sia      "$(fld "$out" sia)" "20"
    chk mmi-sia-param "$(fld "$out" parameter)" "+4917112345678"
    out=$(ussd_mmi_parse '*#21*1#')
    chk mmi-interrogate-si "$(fld "$out" parameter)" "1"
    chk mmi-code-not-numeric "$(ussd_mmi_parse '*#abc#' >/dev/null 2>&1; echo $?)" "1"
    chk mmi-no-service-code "$(ussd_mmi_parse '*##' >/dev/null 2>&1; echo $?)" "1"
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
  --pack <text>     GSM 7-bit default-alphabet packing, extension chars too
  --unpack <hex> [<septets>]   decode 7-bit packed text (ESC handled)
  --build <dcs> <text>   USSD facility message (DCS + packed text)
  --mmi <string>    parse *#...# / **...# MMI strings (TS 22.030): SC, SI, SIA
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
