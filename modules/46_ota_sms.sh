#!/usr/bin/env bash
# ota_sms — TS 23.048 OTA command-packet construction and key/counter audit.
#
# An OTA (Over-The-Air) binary SMS is how a carrier updates a SIM: a TS 23.048
# command packet carrying SPI, TAR, counter and a KIc/KID-selected key set. The
# protocol is published; the S@T and WIB application classes are documented.
# What is *not* free is the target: affecting a SIM you do not hold needs that
# SIM's OTA keys, so this module is built for own-SIM and lab construction plus
# the audit that finds a weak SPI, a replayed counter or an un-keyed payload.
# 20_sim keeps the reader/defensive side; this module builds and audits.
#
# Attack owned: O5 adjacency (SIM/eSIM OTA) — construction plus vulnerability
# detection, per docs/MODULE_ROSTER.md. Own-SIM and lab only.
#
# The second half is the TS 23.040 SMS TP layer (Phase 2 of
# docs/OFFENSIVE-GAP-ANALYSIS.md): TP-MTI/TP-PID/TP-DCS/TP-SCTS/address/TP-UDL
# encode and parse, plus the Type 0 "silent SMS" audit. A Type 0 message is
# acknowledged by the ME and then discarded without indication or storage
# (TS 23.040 §9.2.3.9), so it is the one message whose success is invisible —
# which is exactly why the parser must classify it rather than treat it as an
# ordinary message with an empty body. Nothing here transmits: delivery is a
# handoff to a loopback SMSC you run (--plan-tp).
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

MOD_TMP="$TMP_DIR/ota_sms"
OTASM_DIR="$LOOT_DIR/ota_sms"
mkdir -p "$MOD_TMP" "$OTASM_DIR" 2>/dev/null

declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
declare -F warn >/dev/null 2>&1 || warn() { printf '[warn] %s\n' "$*" >&2; }
declare -F err  >/dev/null 2>&1 || err()  { printf '[err]  %s\n' "$*" >&2; }
declare -F ok   >/dev/null 2>&1 || ok()   { printf '[ok]   %s\n' "$*" >&2; }
declare -F banner >/dev/null 2>&1 || banner() { :; }

otasm_sanitize() { printf '%s' "${1:-}" | tr '\t\r\n' '   '; }
OTASM_F=()
otasm_split() {
    OTASM_F=()
    local i n
    n=$(printf '%s' "$1" | awk -F'\t' '{print NF}')
    for (( i = 1; i <= n; i++ )); do
        OTASM_F+=("$(printf '%s' "$1" | cut -f"$i")")
    done
}
otasm_norm_hex() { printf '%s' "${1:-}" | tr -d ' \t\r\n:.-' | sed 's/^0x//I' | tr 'A-F' 'a-f'; }
otasm_is_hex() {
    local h; h=$(otasm_norm_hex "${1:-}")
    [[ -n "$h" && "$h" =~ ^[0-9a-f]+$ && $(( ${#h} % 2 )) -eq 0 ]]
}
otasm_byte() { printf '%02X' "$(( ${1:-0} & 0xFF ))"; }

otasm_status_tsv() {
    printf 'MODULE\tota_sms\n'
    printf 'TARGET\tTS 23.048 OTA command packet, SPI, TAR, counter, key audit\n'
    printf 'TARGET2\tTS 23.040 SMS TP layer + TS 23.038 alphabet/DCS; Type 0 silent SMS\n'
    printf 'SCOPE\town-SIM and lab; a live subscriber needs their OTA keys\n'
    printf 'TRANSMIT\tnone — construction and audit; delivery is a handoff\n'
    printf 'TP_LAYER\tMTI/PID/DCS/SCTS/address/UDL encode and parse; Type 0 audit\n'
    printf 'KAT\tTS 23.038 §6.1.2.1.1 packing vectors (hi=e834, hello=e8329bfd06)\n'
    printf 'SELFTEST\tyes\n'
}

# ── BER length (X.690 §8.1.3) for the CPL field ─────────────────────────
otasm_berlen() {
    local n="${1:-}"
    [[ "$n" =~ ^[0-9]+$ ]] || { printf 'ERROR\tlength must be numeric\n' >&2; return 2; }
    (( n <= 127 )) && { printf '%02X' "$(( n & 0xFF ))"; return 0; }
    if (( n <= 0xFF )); then printf '81%02X' "$(( n & 0xFF ))"
    elif (( n <= 0xFFFF )); then printf '82%02X%02X' "$(( (n>>8)&0xFF ))" "$(( n&0xFF ))"
    else printf 'ERROR\tlength too large\n' >&2; return 2; fi
}
# read a BER length at octet offset $1; prints "value<TAB>octets"
otasm_berlen_read() {
    local h="$1" off="${2:-0}"
    local b0=$(( 16#${h:$((off*2)):2} ))
    if (( (b0 & 0x80) == 0 )); then printf '%d\t1' "$b0"; return 0; fi
    local n=$(( b0 & 0x7F ))
    (( n >= 1 && n <= 3 )) || { printf 'ERROR\tlength-of-length %d unsupported\n' "$n" >&2; return 1; }
    local v=$(( 16#${h:$(( (off+1)*2 )):$((n*2))} ))
    printf '%d\t%d' "$v" "$(( n + 1 ))"
}

# ── SPI (TS 23.048 §8.1) ────────────────────────────────────────────────
# Octet 1: b8-b7 RC/CC/DS, b6 ciphering, b5-b4 counter, b3-b1 reserved.
# Octet 2: b8-b7 PoR, b6-b5 PoR RC/CC/DS, b4 PoR ciphering, b3 PoR transport,
#          b2-b1 reserved. (Same bit layout as 20_sim's sim_spi_decode.)
otasm_spi_build() {
    local rccds="${1:-0}" cipher="${2:-0}" counter="${3:-0}"
    local por="${4:-0}" por_rccds="${5:-0}" por_cipher="${6:-0}" por_transport="${7:-0}"
    local i
    for i in "$rccds" "$cipher" "$counter" "$por" "$por_rccds" "$por_cipher" "$por_transport"; do
        [[ "$i" =~ ^[0-9]+$ ]] || { printf 'ERROR\tSPI fields must be numeric\n' >&2; return 2; }
    done
    (( rccds <= 3 && cipher <= 1 && counter <= 3 && por <= 3 && por_rccds <= 3 && por_cipher <= 1 && por_transport <= 1 )) || {
        printf 'ERROR\tSPI sub-field out of range\n' >&2; return 2; }
    local o1=$(( (rccds<<6) | (cipher<<5) | (counter<<3) ))
    local o2=$(( (por<<6) | (por_rccds<<4) | (por_cipher<<3) | (por_transport<<2) ))
    printf '%02X%02X\n' "$o1" "$o2"
}
otasm_spi_parse() {
    local in="${1:-}" h
    if [[ "$in" =~ ^[0-9A-Fa-f]{4}$ ]]; then
        h=$(printf '%s' "$in" | tr 'A-F' 'a-f')
    elif [[ "$in" =~ ^[0-9]+$ ]]; then
        printf -v h '%04X' "$(( in & 0xFFFF ))"
    else
        printf 'ERROR\tSPI must be 2 octets of hex or a 16-bit decimal\n' >&2; return 2
    fi
    [[ "$h" =~ ^[0-9a-f]{4}$ ]] || { printf 'ERROR\tSPI must be 2 octets of hex or a 16-bit decimal\n' >&2; return 2; }
    local o1=$(( 16#${h:0:2} )) o2=$(( 16#${h:2:2} ))
    local rccds=$(( (o1>>6)&3 )) cipher=$(( (o1>>5)&1 )) counter=$(( (o1>>3)&3 ))
    local por=$(( (o2>>6)&3 )) por_rccds=$(( (o2>>4)&3 )) por_cipher=$(( (o2>>3)&1 )) por_transport=$(( (o2>>2)&1 ))
    local rccds_t counter_t
    case "$rccds" in 0) rccds_t="no RC, CC or DS";; 1) rccds_t="RC";; 2) rccds_t="CC";; 3) rccds_t="DS";; esac
    case "$counter" in
        0) counter_t="no counter (replay indiscriminate)";;
        1) counter_t="informational only (replay possible)";;
        2) counter_t="process iff counter > RE";;
        3) counter_t="process iff counter == RE+1 (strict)";; esac
    printf 'spi\t%s\nrccds\t%s\nrccds_meaning\t%s\nciphering\t%s\n' "$h" "$rccds" "$rccds_t" "$cipher"
    printf 'ciphering_meaning\t%s\ncounter_mode\t%s\ncounter_meaning\t%s\n' \
        "$([[ $cipher -eq 1 ]] && echo "applied" || echo "NOT applied (payload in the clear)")" "$counter" "$counter_t"
    printf 'por\t%s\npor_transport\t%s\n' "$por" "$([[ $por_transport -eq 1 ]] && echo "SMS-SUBMIT" || echo "SMS-DELIVER-REPORT")"
    local n=0
    (( cipher == 0 )) && { printf 'finding\tHIGH\tSPI b6=0 — the command payload is sent in the clear\n'; n=$((n+1)); }
    (( rccds == 0 )) && { printf 'finding\tHIGH\tSPI b8b7=00 — no RC/CC/DS; the packet has no integrity protection\n'; n=$((n+1)); }
    (( counter == 0 || counter == 1 )) && { printf 'finding\tMEDIUM\tSPI b5b4=%d — the counter does not stop a replay\n' "$counter"; n=$((n+1)); }
    (( n == 0 )) && printf 'note\tINFO\tciphering on, integrity present, counter enforced\n'
    printf 'findings\t%d\n' "$n"
    return 0
}

# ── command packet build / parse (TS 23.048 §5.1.1) ─────────────────────
#   CPI(1) CPL(BER) CHI(1) CHL(1) CMD(CHL) SPI(2) KIc(1) KID(1) TAR(3)
#   CNTR(5) PCNTR(1) DATA(rest)
otasm_packet_build() {
    local cpi="${1:-01}" tar="${2:-000000}" counter="${3:-0}" spi="${4:-B800}"
    local kic="${5:-01}" kid="${6:-01}" data; data=$(otasm_norm_hex "${7:-}")
    local chi="${8:-01}" cmd; cmd=$(otasm_norm_hex "${9:-01}")
    [[ "$counter" =~ ^[0-9]+$ ]] || { printf 'ERROR\tcounter must be numeric\n' >&2; return 2; }
    otasm_is_hex "$tar" && (( ${#tar} == 6 )) || { printf 'ERROR\tTAR must be 3 octets of hex\n' >&2; return 2; }
    otasm_is_hex "$spi" && (( ${#spi} == 4 )) || { printf 'ERROR\tSPI must be 2 octets of hex\n' >&2; return 2; }
    local cntr; printf -v cntr '%010X' "$(( counter & 0xFFFFFFFFFF ))"
    local chl=$(( ${#cmd} / 2 ))
    local rest; rest="${chi}$(otasm_byte "$chl")${cmd}${spi}${kic}${kid}${tar}${cntr}00${data}"
    local base=$(( 1 + ${#rest}/2 ))
    local cpl
    if (( base + 1 <= 127 )); then cpl=$(printf '%02X' "$(( base + 1 ))")
    elif (( base + 2 <= 255 )); then cpl=$(printf '81%02X' "$(( base + 2 ))")
    else cpl=$(printf '82%04X' "$(( base + 3 ))"); fi
    printf '%s%s%s\n' "$cpi" "$cpl" "$rest"
}
otasm_packet_parse() {
    local h; h=$(otasm_norm_hex "${1:-}")
    otasm_is_hex "$h" || { printf 'ERROR\tnot valid hex\n' >&2; return 2; }
    (( ${#h} >= 2 + 2 + 2 + 2 + 2 + 4 + 2 + 2 + 6 + 10 + 2 )) || {
        printf 'ERROR\tpacket shorter than the minimum command packet\n' >&2; return 1; }
    local cpi="${h:0:2}"
    local cpl_read; cpl_read=$(otasm_berlen_read "$h" 1) || return 1
    local cpl; cpl=$(printf '%s' "$cpl_read" | cut -f1)
    local cpl_oct=$(printf '%s' "$cpl_read" | cut -f2)
    local off=$(( 1 + cpl_oct ))
    local chi="${h:$((off*2)):2}"; off=$(( off + 1 ))
    local chl=$(( 16#${h:$((off*2)):2} )); off=$(( off + 1 ))
    local cmd="${h:$((off*2)):$((chl*2))}"; off=$(( off + chl ))
    local spi="${h:$((off*2)):4}"; off=$(( off + 2 ))
    local kic="${h:$((off*2)):2}"; off=$(( off + 1 ))
    local kid="${h:$((off*2)):2}"; off=$(( off + 1 ))
    local tar="${h:$((off*2)):6}"; off=$(( off + 3 ))
    local cntr="${h:$((off*2)):10}"; off=$(( off + 5 ))
    local pcntr="${h:$((off*2)):2}"; off=$(( off + 1 ))
    local data="${h:$((off*2))}"
    local cn=$(( 16#${cntr} ))
    printf 'cpi\t%s\ncpl\t%d\ncpl_octets\t%d\nchi\t%s\nchl\t%d\ncmd\t%s\nspi\t%s\n' \
        "$cpi" "$cpl" "$cpl_oct" "$chi" "$chl" "$cmd" "$spi"
    printf 'kic\t%s\nkid\t%s\ntar\t%s\ncounter\t%s\ncounter_dec\t%d\npcntr\t%s\ndata\t%s\n' \
        "$kic" "$kid" "$tar" "$cntr" "$cn" "$pcntr" "$data"
    printf 'packet_bytes\t%d\n' "$(( ${#h}/2 ))"
}

# ── counter / replay decision (TS 23.048 §8.2) ──────────────────────────
otasm_counter_check() {
    local counter="${1:-}" re="${2:-}" mode="${3:-0}"
    [[ "$counter" =~ ^[0-9]+$ && "$re" =~ ^[0-9]+$ && "$mode" =~ ^[0-9]+$ ]] || {
        printf 'ERROR\tcounter, RE and mode must be numeric\n' >&2; return 2; }
    local verdict
    case "$mode" in
        0) verdict="process (counter absent — no replay protection)" ;;
        1) verdict="process (counter informational only)" ;;
        2) (( counter > re )) && verdict="process (counter above the received value)" || verdict="REPLAY (counter not above RE)" ;;
        3) (( counter == re + 1 )) && verdict="process (counter is exactly RE+1)" || verdict="REPLAY (counter is not RE+1)" ;;
        *) printf 'ERROR\tcounter mode must be 0..3\n' >&2; return 2 ;;
    esac
    printf 'mode\t%d\ncounter\t%d\nre\t%d\nverdict\t%s\n' "$mode" "$counter" "$re" "$verdict"
}

# ════════════════════════════════════════════════════════════════════════
# TS 23.040 TP layer (SM-TL) — the short message an OTA packet rides in.
#
# The half above builds the TS 23.048 command packet *inside* a SM; this half
# is the SM itself: TP-MTI / TP-PID / TP-DCS / TP-UD, and the report types.
# It is here because TS 23.040 §9.2.3.9 defines "Short Message Type 0"
# (TP-PID = 0x40): the ME must acknowledge it, must not indicate it to the
# user and must not store it, whatever the memory state. That is the presence
# trigger every rogue-BTS module needs, so it is built and audited here.
#
# Building a TPDU is not transmitting one. Nothing below opens a socket,
# a serial port or a modem, and --send / --deliver stay rejected.
# ════════════════════════════════════════════════════════════════════════

# ── TS 23.038 §6.2.1 GSM 7-bit default alphabet ─────────────────────────
# Prints the septet code, or "E <code>" for a character reachable only
# through the §6.2.1.1 extension table (ESC 27 then the extension code).
# A character outside the alphabet is a hard error, never a silent
# substitution — the same rule 43_ussd applies.
otasm_tp_g7_code() {
    local ch="${1:-}"
    [[ -n "$ch" ]] || { printf 'ERROR\tempty character\n' >&2; return 2; }
    case "$ch" in
        '@') printf '0';   return 0 ;;
        '$') printf '2';   return 0 ;;
        '_') printf '17';  return 0 ;;
        '£') printf '1';   return 0 ;;
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
        # §6.2.1.1 extension table — ESC (27) then the extension code.
        '[')  printf 'E 60';  return 0 ;;
        '\\') printf 'E 47';  return 0 ;;
        ']')  printf 'E 62';  return 0 ;;
        '^')  printf 'E 20';  return 0 ;;
        '{')  printf 'E 40';  return 0 ;;
        '|')  printf 'E 64';  return 0 ;;
        '}')  printf 'E 41';  return 0 ;;
        '~')  printf 'E 61';  return 0 ;;
        '€')  printf 'E 101'; return 0 ;;
        $'\n') printf '10'; return 0 ;;
        $'\r') printf '13'; return 0 ;;
    esac
    # The main table is the identity for printable ASCII apart from the three
    # exceptions above. Everything else — including '`' and the non-Latin-1
    # characters the table leaves out — is an error.
    local c
    c=$(printf '%d' "'$ch" 2>/dev/null) || c=0
    if (( c >= 32 && c <= 126 )); then printf '%d' "$c"; return 0; fi
    printf 'ERROR\tcharacter not in the GSM 7-bit default alphabet: %s\n' "$ch" >&2
    return 2
}
# Main table only (septet -> character); 27 is the ESC, handled by the caller.
otasm_tp_g7_char() {
    local s="${1:-0}"
    [[ "$s" =~ ^[0-9]+$ ]] || { printf 'ERROR\tseptet must be numeric\n' >&2; return 2; }
    (( s >= 0 && s <= 127 )) || { printf 'ERROR\tseptet out of range: %s\n' "$s" >&2; return 2; }
    case "$s" in
        0) printf '@' ;; 1) printf '£' ;; 2) printf '$' ;; 3) printf '¥' ;;
        4) printf 'è' ;; 5) printf 'é' ;; 6) printf 'ù' ;; 7) printf 'ì' ;;
        8) printf 'ò' ;; 9) printf 'Ç' ;; 10) printf '\n' ;; 11) printf 'Ø' ;;
        12) printf 'ø' ;; 13) printf '\r' ;; 14) printf 'Å' ;; 15) printf 'å' ;;
        16) printf 'Δ' ;; 17) printf '_' ;; 18) printf 'Φ' ;; 19) printf 'Γ' ;;
        20) printf 'Λ' ;; 21) printf 'Ω' ;; 22) printf 'Π' ;; 23) printf 'Ψ' ;;
        24) printf 'Σ' ;; 25) printf 'Θ' ;; 26) printf 'Ξ' ;; 27) printf '\033' ;;
        28) printf 'Æ' ;; 29) printf 'æ' ;; 30) printf 'ß' ;; 31) printf 'É' ;;
        36) printf '¤' ;; 64) printf '¡' ;;
        91) printf 'Ä' ;; 92) printf 'Ö' ;; 93) printf 'Ñ' ;; 94) printf 'Ü' ;; 95) printf '§' ;;
        96) printf '¿' ;;
        123) printf 'ä' ;; 124) printf 'ö' ;; 125) printf 'ñ' ;; 126) printf 'ü' ;;
        127) printf 'à' ;;
        *) printf "\\$(printf '%03o' "$s")" ;;
    esac
}
# Extension table only (extension code -> character), TS 23.038 §6.2.1.1.
otasm_tp_g7_ext_char() {
    case "${1:-}" in
        10) printf '\f' ;;
        20) printf '^' ;;
        40) printf '{' ;;
        41) printf '}' ;;
        47) printf '\\' ;;
        60) printf '[' ;;
        61) printf '~' ;;
        62) printf ']' ;;
        64) printf '|' ;;
        101) printf '€' ;;
        *) printf 'ERROR\tno GSM 7-bit extension character for code %s\n' "${1:-}" >&2; return 2 ;;
    esac
}
# Text -> space-separated septet codes (an extension character emits "27 <code>").
otasm_tp_septets() {
    local text="${1:-}" out=() i ch enc
    [[ -n "$text" ]] || { printf 'ERROR\tempty text\n' >&2; return 2; }
    for (( i = 0; i < ${#text}; i++ )); do
        ch="${text:i:1}"
        enc=$(otasm_tp_g7_code "$ch") || return 2
        if [[ "$enc" == E\ * ]]; then out+=( 27 "${enc#E }"); else out+=( "$enc" ); fi
    done
    printf '%s' "${out[*]}"
}
# Space-separated septet codes -> text.
otasm_tp_text() {
    local codes="${1:-}" s out="" esc=0
    set -- $codes
    (( $# > 0 )) || { printf 'ERROR\tno septets\n' >&2; return 2; }
    for s in "$@"; do
        if (( esc == 1 )); then
            out+=$(otasm_tp_g7_ext_char "$s") || return 2
            esc=0
        elif (( s == 27 )); then
            esc=1
        else
            out+=$(otasm_tp_g7_char "$s") || return 2
        fi
    done
    (( esc == 0 )) || { printf 'ERROR\tdangling ESC (27) at the end of the septets\n' >&2; return 2; }
    printf '%s' "$out"
}

# ── TS 23.038 §6.1.2.1.1 seven-bit packing ──────────────────────────────
# "The bit number zero is always transmitted first."  Codes are packed
# low-bit-first, so septet i starts at bit 7*i of the octet string.
otasm_tp_pack() {
    local codes="${1:-}" s i=0 byte shift
    local out=()
    set -- $codes
    (( $# > 0 )) || { printf 'ERROR\tno septets to pack\n' >&2; return 2; }
    local nbytes=$(( ($# * 7 + 7) / 8 ))
    for (( byte = 0; byte < nbytes; byte++ )); do out[byte]=0; done
    for s in "$@"; do
        [[ "$s" =~ ^[0-9]+$ ]] && (( s >= 0 && s <= 127 )) || {
            printf 'ERROR\tseptet out of range: %s\n' "$s" >&2; return 2; }
        byte=$(( i * 7 / 8 )); shift=$(( i * 7 % 8 ))
        out[byte]=$(( out[byte] | ((s << shift) & 0xFF) ))
        (( shift > 1 )) && out[byte+1]=$(( out[byte+1] | (s >> (8 - shift)) ))
        i=$(( i + 1 ))
    done
    printf '%02x' "${out[@]}"
}
# hex + septet count -> space-separated codes.  The count is the TP-UDL: taking
# it explicitly is what stops a padded payload decoding trailing fill bits as
# '@' characters (the bug recorded in docs/FEATURE-GAPS.md for 43_ussd).
otasm_tp_unpack() {
    local h; h=$(otasm_norm_hex "${1:-}")
    local count="${2:-0}"
    otasm_is_hex "$h" || { printf 'ERROR\tnot even-length hex\n' >&2; return 2; }
    [[ "$count" =~ ^[0-9]+$ ]] || { printf 'ERROR\tseptet count must be numeric\n' >&2; return 2; }
    local nbytes=$(( ${#h} / 2 ))
    local b=() i byte shift val
    for (( i = 0; i < nbytes; i++ )); do b[i]=$(( 16#${h:$((i*2)):2} )); done
    local nseptets=$(( nbytes * 8 / 7 ))
    (( count > 0 && count < nseptets )) && nseptets=$count
    local out=()
    for (( i = 0; i < nseptets; i++ )); do
        byte=$(( i * 7 / 8 )); shift=$(( i * 7 % 8 ))
        val=$(( b[byte] >> shift ))
        (( shift > 1 )) && val=$(( val | (b[byte+1] << (8 - shift)) ))
        out+=( "$(( val & 0x7F ))" )
    done
    printf '%s' "${out[*]}"
}
# Text -> packed hex, and packed hex + septet count -> text.
otasm_tp_pack_text() {
    local codes; codes=$(otasm_tp_septets "${1:-}") || return 2
    otasm_tp_pack "$codes"
}
otasm_tp_unpack_text() {
    local codes; codes=$(otasm_tp_unpack "${1:-}" "${2:-0}") || return 2
    otasm_tp_text "$codes"
}

# ── TS 23.040 §9.2.3.11 TP-SCTS ─────────────────────────────────────────
# Seven semi-octet-swapped octets: YY MM DD hh mm ss TZ.  Within an octet the
# low half-octet holds the most significant digit (§9.1.2.3).  The time zone
# is a signed number of quarter hours; its sign is bit 3 of the seventh octet
# and the tens digit is therefore limited to 0..7 (§9.2.3.11).
otasm_tp_scts_build() {
    local d="${1:-}" tz="${2:-0}" out="" i
    [[ "$d" =~ ^[0-9]{12}$ ]] || {
        printf 'ERROR\tSCTS must be 12 decimal digits (YYMMDDhhmmss)\n' >&2; return 2; }
    [[ "$tz" =~ ^-?[0-9]{1,2}$ ]] || {
        printf 'ERROR\ttime zone must be signed quarter hours (-79..79)\n' >&2; return 2; }
    for (( i = 0; i < 12; i += 2 )); do out+="${d:$((i+1)):1}${d:$i:1}"; done
    local a=${tz#-} sign=0
    (( tz < 0 )) && sign=1
    local tzd b
    printf -v tzd '%02d' "$a"
    b=$(( (16#${tzd:1:1} << 4) | 16#${tzd:0:1} ))
    (( sign == 1 )) && b=$(( b | 0x08 ))
    printf '%s%02x\n' "$out" "$b"
}
otasm_tp_scts_parse() {
    local h; h=$(otasm_norm_hex "${1:-}")
    otasm_is_hex "$h" && (( ${#h} == 14 )) || {
        printf 'ERROR\tTP-SCTS must be 7 octets\n' >&2; return 2; }
    local sw="" i
    for (( i = 0; i < 12; i += 2 )); do sw+="${h:$((i+1)):1}${h:$i:1}"; done
    local tzb=$(( 16#${h:12:2} ))
    local neg=$(( (tzb >> 3) & 1 ))
    local units=$(( (tzb >> 4) & 0x0F )) tens=$(( tzb & 0x07 ))
    local q=$(( tens * 10 + units ))
    local signed=$q; (( neg == 1 )) && signed=$(( -q ))
    printf 'scts\t%s\n' "$h"
    printf 'scts_year\t20%s\nscts_month\t%s\nscts_day\t%s\n' "${sw:0:2}" "${sw:2:2}" "${sw:4:2}"
    printf 'scts_hour\t%s\nscts_minute\t%s\nscts_second\t%s\n' "${sw:6:2}" "${sw:8:2}" "${sw:10:2}"
    printf 'scts_tz_quarters\t%d\n' "$signed"
    printf 'scts_tz\tUTC%+d:%02d\n' "$(( signed / 4 ))" "$(( (signed % 4) * 15 ))"
    printf 'scts_local\t20%s-%s-%sT%s:%s:%s\n' \
        "${sw:0:2}" "${sw:2:2}" "${sw:4:2}" "${sw:6:2}" "${sw:8:2}" "${sw:10:2}"
    return 0
}

# ── TS 23.040 §9.1.2.5 address field ────────────────────────────────────
# [Address-Length][Type-of-Address][Address-Value].  The length counts useful
# semi-octets only, so an odd digit count carries an 'F' fill semi-octet.
otasm_tp_addr_build() {
    local ton="${1:-0}" npi="${2:-0}" digits="${3:-}"
    [[ "$ton" =~ ^[0-7]$ ]] || { printf 'ERROR\ttype-of-number must be 0..7\n' >&2; return 2; }
    [[ "$npi" =~ ^[0-9]$ ]] || { printf 'ERROR\tnumbering plan must be 0..9\n' >&2; return 2; }
    (( ton != 5 )) || {
        printf 'ERROR\talphanumeric (type-of-number 5) originators are readable but not built here\n' >&2; return 2; }
    digits=$(printf '%s' "$digits" | tr -d ' ()-')
    [[ "$digits" =~ ^[0-9]*$ ]] || { printf 'ERROR\taddress digits must be decimal\n' >&2; return 2; }
    local n=${#digits}
    (( n >= 1 && n <= 20 )) || { printf 'ERROR\taddress must be 1..20 digits\n' >&2; return 2; }
    local val="" i a b
    for (( i = 0; i < n; i += 2 )); do
        a="${digits:i:1}"; b="${digits:$((i+1)):1}"
        [[ -n "$b" ]] || b=f
        val+="${b}${a}"
    done
    printf '%02x%02x%s\n' "$n" "$(( 0x80 | (ton << 4) | npi ))" "$val"
}
otasm_tp_addr_parse() {
    local h; h=$(otasm_norm_hex "${1:-}")
    otasm_is_hex "$h" && (( ${#h} >= 2 )) || { printf 'ERROR\taddress field must be hex\n' >&2; return 2; }
    local alen=$(( 16#${h:0:2} ))
    local voctets=$(( (alen + 1) / 2 ))
    (( ${#h} >= (1 + 1 + voctets) * 2 )) || {
        printf 'ERROR\taddress field shorter than its Address-Length (%d semi-octets)\n' "$alen" >&2; return 1; }
    local toa=$(( 16#${h:2:2} ))
    local val="${h:4:$((voctets*2))}"
    local ton=$(( (toa >> 4) & 0x07 )) npi=$(( toa & 0x0F ))
    local ton_t
    case "$ton" in
        0) ton_t="unknown" ;; 1) ton_t="international" ;; 2) ton_t="national" ;;
        3) ton_t="network specific" ;; 4) ton_t="subscriber" ;;
        5) ton_t="alphanumeric" ;; 6) ton_t="abbreviated" ;; 7) ton_t="reserved (interpret as unknown)" ;;
    esac
    local npi_t
    case "$npi" in
        0) npi_t="unknown" ;; 1) npi_t="ISDN/E.164" ;; 3) npi_t="data/X.121" ;; 4) npi_t="telex" ;;
        5|6) npi_t="service-centre specific" ;; 8) npi_t="national" ;; 9) npi_t="private" ;;
        10) npi_t="ERMES" ;; 15) npi_t="reserved for extension" ;; *) npi_t="reserved (interpret as unknown)" ;;
    esac
    printf 'addr\t%s\naddr_octets\t%d\naddr_length\t%d\ntoa\t%02x\ntoa_ton\t%d\ntoa_ton_meaning\t%s\ntoa_npi\t%d\ntoa_npi_meaning\t%s\n' \
        "$h" $(( 2 + voctets )) "$alen" "$toa" "$ton" "$ton_t" "$npi" "$npi_t"
    local digits="" i
    for (( i = 0; i < voctets; i++ )); do
        local lo="${val:$((i*2+1)):1}" hi="${val:$((i*2)):1}"
        if (( alen % 2 == 1 )) && (( i == voctets - 1 )); then
            digits+="$lo"
        else
            digits+="$lo$hi"
        fi
    done
    # A received address may carry non-integer semi-octets (§9.1.2.3).
    local shown; shown=$(printf '%s' "$digits" | sed -e 's/^A/*/; s/^B/#/; s/^C/a/; s/^D/b/; s/^E/c/')
    if (( ton == 5 )); then
        local ns=$(( alen * 4 / 7 ))
        printf 'addr_value\t%s\naddr_alpha_septets\t%d\naddr_alpha\t%s\n' \
            "$digits" "$ns" "$(otasm_tp_unpack_text "$val" "$ns" 2>/dev/null)"
    else
        printf 'addr_value\t%s\naddr_digits\t%s\n' "$digits" "$shown"
    fi
    return 0
}

# ── TS 23.040 §9.2.3.9 TP-PID ───────────────────────────────────────────
# bits 7..6 select the block; 00/01 with bit 5 = 0 is an SM-AL protocol id,
# with bit 5 = 1 a telematic device type.  The 01 block carries the silent
# Short Message Type 0 (0x40) and the Replace / Device-Triggering ids.
otasm_tp_pid_parse() {
    local h; h=$(otasm_norm_hex "${1:-}")
    otasm_is_hex "$h" && (( ${#h} == 2 )) || { printf 'ERROR\tTP-PID must be one octet\n' >&2; return 2; }
    local pid=$(( 16#$h ))
    local hi=$(( (pid >> 6) & 3 )) lo=$(( pid & 0x3F ))
    local grp meaning="" silent="no" finding_n=0
    case "$hi" in
        0|1)
            if (( (pid & 0x20) == 0 )); then
                grp="SME-to-SME / SM-AL protocol"
                meaning=$(printf 'SM-AL protocol id 0x%02X (no telematic interworking)' "$lo")
            else
                grp="telematic interworking"
                local dev=$(( pid & 0x1F ))
                case "$dev" in
                    0) meaning="implicit — device type is specific to this SC" ;;
                    1) meaning="telex (or teletex reduced to telex format)" ;;
                    2) meaning="group 3 telefax" ;;
                    3) meaning="group 4 telefax" ;;
                    4) meaning="voice telephone (conversion to speech)" ;;
                    5) meaning="ERMES" ;;
                    6) meaning="National Paging system" ;;
                    7) meaning="Videotex" ;;
                    8) meaning="teletex, carrier unspecified" ;;
                    9) meaning="teletex, in PSPDN" ;;
                    10) meaning="teletex, in CSPDN" ;;
                    11) meaning="teletex, in analog PSTN" ;;
                    12) meaning="teletex, in digital ISDN" ;;
                    13) meaning="UCI" ;;
                    16) meaning="message handling facility" ;;
                    17) meaning="public X.400-based message handling system" ;;
                    18) meaning="Internet Electronic Mail" ;;
                    31) meaning="GSM/UMTS mobile station" ;;
                    14|15|19|20|21|22|23) meaning="reserved telematic device type" ;;
                    *) meaning="value specific to the SC" ;;
                esac
            fi
            ;;
        2) grp="reserved"; meaning="reserved — an MS interprets this as 0x00 but stores it as received" ;;
        3) grp="SC specific"; meaning="for SC specific use" ;;
    esac
    if (( hi == 1 )); then
        case "$lo" in
            0) meaning="Short Message Type 0 — the ME acknowledges, discards, does not indicate and does not store it"
               silent="yes" ;;
            1|2|3|4|5|6|7) meaning=$(printf 'Replace Short Message Type %d' "$lo") ;;
            8) meaning="Device Triggering Short Message" ;;
            30) meaning="Enhanced Message Service (obsolete)" ;;
            31) meaning="Return Call Message" ;;
            60) meaning="ANSI-136 R-DATA" ;;
            61) meaning="ME Data download" ;;
            62) meaning="ME De-personalization Short Message" ;;
            63) meaning="(U)SIM Data download" ;;
        esac
    fi
    printf 'pid\t%s\npid_bits76\t%d\npid_group\t%s\npid_meaning\t%s\npid_silent\t%s\n' \
        "$h" "$hi" "$grp" "$meaning" "$silent"
    if (( pid == 0x40 )); then
        printf 'finding\tHIGH\tTP-PID 0x40 Short Message Type 0 — silent: acknowledged, not indicated, not stored (TS 23.040 §9.2.3.9)\n'
        finding_n=$(( finding_n + 1 ))
    elif (( pid == 0x48 )); then
        printf 'finding\tMEDIUM\tTP-PID 0x48 Device Triggering — consumed by the device/application, not necessarily shown to the user\n'
        finding_n=$(( finding_n + 1 ))
    elif (( hi == 2 )); then
        printf 'finding\tLOW\tTP-PID 0x%02X is reserved; a parser that treats it as a safe default would be wrong\n' "$pid"
        finding_n=$(( finding_n + 1 ))
    fi
    printf 'findings\t%d\n' "$finding_n"
    return 0
}

# ── TS 23.038 §4 TP-DCS ─────────────────────────────────────────────────
otasm_tp_dcs_parse() {
    local h; h=$(otasm_norm_hex "${1:-}")
    otasm_is_hex "$h" && (( ${#h} == 2 )) || { printf 'ERROR\tTP-DCS must be one octet\n' >&2; return 2; }
    local dcs=$(( 16#$h ))
    local grp=$(( (dcs >> 4) & 0x0F ))
    local group alpha class="none" compressed="no" meaning="" forced="no" n=0
    case "$grp" in
        0|1|2|3)
            group="general data coding (00xx)"
            (( (dcs >> 5) & 1 )) && compressed="yes"
            local cs=$(( (dcs >> 2) & 3 ))
            case "$cs" in
                0) alpha="GSM 7-bit default alphabet" ;;
                1) alpha="8-bit data" ;;
                2) alpha="UCS2 (16-bit)" ;;
                3) alpha="reserved character set" ;;
            esac
            if (( (dcs >> 4) & 1 )); then
                case $(( dcs & 3 )) in
                    0) class="0"; forced="yes" ;;
                    1) class="1" ;; 2) class="2" ;; 3) class="3" ;;
                esac
            fi
            meaning="$alpha"
            [[ "$compressed" == yes ]] && meaning+=", compressed (TS 23.042)"
            [[ "$class" != none ]] && meaning+=", message class $class"
            [[ "$class" == none ]] && meaning+=", no message class"
            ;;
        4|5|6|7)
            group="automatic deletion (01xx)"
            (( (dcs >> 5) & 1 )) && compressed="yes"
            local cs2=$(( (dcs >> 2) & 3 ))
            case "$cs2" in
                0) alpha="GSM 7-bit default alphabet" ;; 1) alpha="8-bit data" ;;
                2) alpha="UCS2 (16-bit)" ;; 3) alpha="reserved character set" ;;
            esac
            meaning="marked for automatic deletion after reading; $alpha"
            ;;
        8|9|10|11)
            group="reserved coding group"
            alpha="unknown"
            meaning=$(printf 'reserved coding group %d — never classified as a safe default (TS 23.038 §4)' "$grp")
            ;;
        12)
            group="MWI: discard message (1100)"
            alpha="GSM 7-bit default alphabet"
            meaning="message waiting indication, discard after presenting"
            ;;
        13|14)
            group="MWI: store message ($([[ $grp == 13 ]] && echo 1101 || echo 1110))"
            alpha=$([[ $grp == 14 ]] && echo "UCS2 (16-bit)" || echo "GSM 7-bit default alphabet")
            local sense=$(( (dcs >> 3) & 1 ))
            local itype=$(( dcs & 3 ))
            local it_t
            case "$itype" in 0) it_t="voicemail" ;; 1) it_t="fax" ;; 2) it_t="electronic mail" ;; 3) it_t="other" ;; esac
            meaning="message waiting $it_t $( ((sense==1)) && echo active || echo inactive )"
            ;;
        15)
            group="data coding / message class (1111)"
            if (( (dcs >> 2) & 1 )); then alpha="8-bit data"; else alpha="GSM 7-bit default alphabet"; fi
            case $(( dcs & 3 )) in
                0) class="0"; forced="yes" ;; 1) class="1" ;; 2) class="2" ;; 3) class="3" ;;
            esac
            meaning="$alpha, message class $class"
            ;;
    esac
    printf 'dcs\t%s\ndcs_group_bits\t%d\ndcs_group\t%s\ndcs_alphabet\t%s\ndcs_class\t%s\ndcs_compressed\t%s\ndcs_meaning\t%s\n' \
        "$h" "$grp" "$group" "$alpha" "$class" "$compressed" "$meaning"
    printf 'dcs_class0_immediate_display\t%s\n' "$forced"
    if (( grp >= 8 && grp <= 11 )); then
        printf 'finding\tMEDIUM\tTP-DCS 0x%s is in a reserved coding group; an unknown DCS must not be treated as the 7-bit default\n' "$h"
        n=$(( n + 1 ))
    fi
    (( n == 0 )) && printf 'note\tINFO\tDCS 0x%s decoded to a defined TS 23.038 §4 group\n' "$h"
    printf 'findings\t%d\n' "$n"
    return 0
}
# alphabet: 7bit | 8bit | ucs2 ; class: none | 0..3 ; [compressed] [autodelete]
otasm_tp_dcs_build() {
    local alphabet="${1:-7bit}" class="${2:-none}" compressed="${3:-0}" del="${4:-0}" cs
    case "$alphabet" in
        7bit) cs=0 ;; 8bit) cs=1 ;; ucs2) cs=2 ;;
        *) printf 'ERROR\talphabet must be 7bit, 8bit or ucs2\n' >&2; return 2 ;;
    esac
    [[ "$compressed" =~ ^[01]$ && "$del" =~ ^[01]$ ]] || {
        printf 'ERROR\tcompressed and autodelete flags must be 0 or 1\n' >&2; return 2; }
    local cl=0 present=0
    case "$class" in
        none) present=0 ;;
        0) cl=0; present=1 ;; 1) cl=1; present=1 ;; 2) cl=2; present=1 ;; 3) cl=3; present=1 ;;
        *) printf 'ERROR\tclass must be none, 0, 1, 2 or 3\n' >&2; return 2 ;;
    esac
    local b=$(( (compressed << 5) | (present << 4) | (cs << 2) | cl ))
    (( del == 1 )) && b=$(( b | 0x40 ))
    printf '%02x\n' "$b"
}

# ── TS 23.040 §9.2.3.22 TP-FCS and §9.2.3.15 TP-ST ─────────────────────
otasm_tp_fcs_parse() {
    local h; h=$(otasm_norm_hex "${1:-}")
    otasm_is_hex "$h" && (( ${#h} == 2 )) || { printf 'ERROR\tTP-FCS must be one octet\n' >&2; return 2; }
    local v=$(( 16#$h )) t
    # NOTE: `case` patterns are globs, so these MUST be decimal — `0x80` would
    # never match the decimal expansion of $v.  This bit an earlier revision.
    case "$v" in
        128) t="Telematic interworking not supported" ;;
        129) t="Short message Type 0 not supported" ;;
        130) t="Cannot replace short message" ;;
        143) t="Unspecified TP-PID error" ;;
        144) t="Data coding scheme (alphabet) not supported" ;;
        145) t="Message class not supported" ;;
        159) t="Unspecified TP-DCS error" ;;
        160) t="Command cannot be actioned" ;;
        161) t="Command unsupported" ;;
        175) t="Unspecified TP-Command error" ;;
        176) t="TPDU not supported" ;;
        192) t="SC busy" ;;
        193) t="No SC subscription" ;;
        194) t="SC system failure" ;;
        195) t="Invalid SME address" ;;
        196) t="Destination SME barred" ;;
        197) t="SM Rejected-Duplicate SM" ;;
        198) t="TP-VPF not supported" ;;
        199) t="TP-VP not supported" ;;
        208) t="(U)SIM SMS storage full" ;;
        209) t="No SMS storage capability in (U)SIM" ;;
        210) t="Error in MS" ;;
        211) t="Memory Capacity Exceeded" ;;
        212) t="(U)SIM Application Toolkit Busy" ;;
        213) t="(U)SIM data download error" ;;
        255) t="Unspecified error cause" ;;
        *)
            if (( (v >= 0x80 && v <= 0x8E) || (v >= 0x92 && v <= 0x9E) || (v >= 0xA2 && v <= 0xAE) || (v >= 0xB1 && v <= 0xBF) || (v >= 0xC8 && v <= 0xCF) || (v >= 0xD6 && v <= 0xDF) )); then
                t="reserved — treat as an unspecified error cause"
            elif (( v <= 0x7F )); then
                t="reserved"
            else
                t="value specific to an application"
            fi ;;
    esac
    printf 'fcs\t%s\nfcs_meaning\t%s\n' "$h" "$t"
    (( v == 0x81 )) && printf 'note\tINFO\tTP-FCS 0x81 — the SC/ME rejected the message because Type 0 is not supported\n'
    return 0
}
otasm_tp_st_parse() {
    local h; h=$(otasm_norm_hex "${1:-}")
    otasm_is_hex "$h" && (( ${#h} == 2 )) || { printf 'ERROR\tTP-ST must be one octet\n' >&2; return 2; }
    local v=$(( 16#$h )) t
    if (( (v & 0x80) == 0x80 )); then
        printf 'st\t%s\nst_bits7\t1\nst_meaning\t%s\n' "$h" "bits 0..6 reserved for a value with bit 7 set"
        return 0
    fi
    # Decimal patterns again — see the note in otasm_tp_fcs_parse.
    case "$v" in
        0) t="Short message received by the SME (transaction completed)" ;;
        1) t="Short message forwarded by the SC to the SME but the SC is unable to confirm delivery" ;;
        2) t="Short message replaced by the SC" ;;
        32) t="Congestion (temporary error, SC still trying)" ;;
        33) t="SME busy (temporary error, SC still trying)" ;;
        34) t="No response from SME (temporary error, SC still trying)" ;;
        35) t="Service rejected (temporary error, SC still trying)" ;;
        36) t="Quality of service not available (temporary error, SC still trying)" ;;
        37) t="Error in SME (temporary error, SC still trying)" ;;
        64) t="Remote procedure error (permanent error)" ;;
        65) t="Incompatible destination (permanent error)" ;;
        66) t="Connection rejected by SME (permanent error)" ;;
        67) t="Not obtainable (permanent error)" ;;
        68) t="Quality of service not available (permanent error)" ;;
        69) t="No interworking available (permanent error)" ;;
        70) t="SM Validity Period Expired (permanent error)" ;;
        71) t="SM Deleted by originating SME (permanent error)" ;;
        72) t="SM Deleted by SC Administration (permanent error)" ;;
        73) t="SM does not exist (permanent error)" ;;
        96) t="Congestion (temporary error, SC not making any more attempts)" ;;
        97) t="SME busy (temporary error, SC not making any more attempts)" ;;
        98) t="No response from SME (temporary error, SC not making any more attempts)" ;;
        99) t="Service rejected (temporary error, SC not making any more attempts)" ;;
        100) t="Quality of service not available (temporary error, SC not making any more attempts)" ;;
        101) t="Error in SME (temporary error, SC not making any more attempts)" ;;
        *)
            if (( (v >= 0x03 && v <= 0x0F) || (v >= 0x26 && v <= 0x2F) || (v >= 0x4A && v <= 0x4F) || (v >= 0x66 && v <= 0x6F) )); then
                t="reserved — interpret as Service Rejected (0x23)"
            elif (( (v >= 0x10 && v <= 0x1F) || (v >= 0x30 && v <= 0x3F) || (v >= 0x50 && v <= 0x5F) || (v >= 0x70 && v <= 0x7F) )); then
                t="value specific to this SC"
            else
                t="unrecognised — interpret as Service Rejected (0x23)"
            fi ;;
    esac
    printf 'st\t%s\nst_bits7\t0\nst_meaning\t%s\n' "$h" "$t"
    return 0
}

# ── TS 23.040 §9.2.2 TPDU assembly ──────────────────────────────────────
# First octets (§9.2.3.1-.7, .17, .23, .25, .28):
#   SMS-DELIVER        bit0-1 MTI=00  bit2 TP-MMS  bit3 TP-LP  bit4 reserved
#                      bit5 TP-SRI  bit6 TP-UDHI  bit7 TP-RP
#   SMS-SUBMIT         bit0-1 MTI=01  bit2 TP-RD   bit3-4 TP-VPF
#                      bit5 TP-SRR  bit6 TP-UDHI  bit7 TP-RP
#   SMS-STATUS-REPORT  bit0-1 MTI=10  bit2 TP-MMS  bit3 TP-LP  bit4 reserved
#                      bit5 TP-SRQ  bit6 TP-UDHI  bit7 reserved
#   SMS-COMMAND        bit0-1 MTI=10  bit5 TP-SRR  bit6 TP-UDHI
# A reserved MTI is processed as SMS-DELIVER but stored exactly as received
# (§9.2.3.1), which is why the parser never silently coerces it.

# <oa_addr_hex> <pid> <dcs> <scts_hex> <ud_hex> <udl> [flags_octet_extra]
otasm_tpdu_build_deliver() {
    local oa="${1:-}" pid="${2:-00}" dcs="${3:-00}" scts="${4:-}" ud="${5:-}" udl="${6:-0}" extra="${7:-0}"
    local oh; oh=$(otasm_norm_hex "$oa")
    otasm_is_hex "$oh" && (( ${#oh} >= 4 )) || {
        printf 'ERROR\tTP-OA must be an address field (Length,Type-of-Address,value)\n' >&2; return 2; }
    local ph; ph=$(otasm_norm_hex "$pid"); otasm_is_hex "$ph" && (( ${#ph} == 2 )) || {
        printf 'ERROR\tTP-PID must be one octet\n' >&2; return 2; }
    local dh; dh=$(otasm_norm_hex "$dcs"); otasm_is_hex "$dh" && (( ${#dh} == 2 )) || {
        printf 'ERROR\tTP-DCS must be one octet\n' >&2; return 2; }
    local sh; sh=$(otasm_norm_hex "$scts"); otasm_is_hex "$sh" && (( ${#sh} == 14 )) || {
        printf 'ERROR\tTP-SCTS must be 7 octets\n' >&2; return 2; }
    local uh; uh=$(otasm_norm_hex "$ud")
    # An empty TP-UD is legitimate — and is exactly what a Type 0 silent
    # message carries — so it must pass here while malformed hex must not.
    [[ -z "$uh" ]] || otasm_is_hex "$uh" || { printf 'ERROR\tTP-UD must be hex\n' >&2; return 2; }
    [[ "$udl" =~ ^[0-9]+$ ]] || { printf 'ERROR\tTP-UDL must be a decimal octet\n' >&2; return 2; }
    (( udl >= 0 && udl <= 255 )) || { printf 'ERROR\tTP-UDL must fit one octet\n' >&2; return 2; }
    [[ "$extra" =~ ^(0[xX][0-9a-fA-F]+|[0-9]+)$ ]] || { printf 'ERROR\tflag bits must be a number\n' >&2; return 2; }
    # `extra` is the raw flags octet with the TP-MTI bits ignored, so callers
    # pass the real bit value (0x40 = TP-UDHI, 0x20 = TP-SRI/TP-SRR, ...).
    local b0=$(( extra & 0xFC ))
    printf '%02x%s%s%s%s%02x%s\n' "$b0" "$oh" "$ph" "$dh" "$sh" "$udl" "$uh"
}

# <da_addr_hex> <pid> <dcs> <ud_hex> <udl> [mr] [vpf] [vp_hex] [extra]
otasm_tpdu_build_submit() {
    local da="${1:-}" pid="${2:-00}" dcs="${3:-00}" ud="${4:-}" udl="${5:-0}" mr="${6:-0}" vpf="${7:-0}" vp="${8:-}" extra="${9:-0}"
    local ah; ah=$(otasm_norm_hex "$da")
    otasm_is_hex "$ah" && (( ${#ah} >= 4 )) || {
        printf 'ERROR\tTP-DA must be an address field\n' >&2; return 2; }
    [[ "$mr" =~ ^[0-9]+$ ]] && (( mr <= 255 )) || { printf 'ERROR\tTP-MR must be 0..255\n' >&2; return 2; }
    [[ "$vpf" =~ ^[0-3]$ ]] || { printf 'ERROR\tTP-VPF must be 0..3\n' >&2; return 2; }
    local vh; vh=$(otasm_norm_hex "$vp")
    local vpf_octets
    case "$vpf" in
        0) vpf_octets=0 ;;
        1) vpf_octets=1 ;;
        2) vpf_octets=7 ;;
        3) vpf_octets=7 ;;
    esac
    (( ${#vh} == vpf_octets * 2 )) || {
        printf 'ERROR\tTP-VPF %d needs %d octet(s) of TP-VP, got %d hex digits\n' \
            "$vpf" "$vpf_octets" "${#vh}" >&2; return 2; }
    # TP-VPF comes from its own argument because it also fixes the TP-VP
    # length; `extra` supplies the remaining flag bits raw (0x04 TP-RD,
    # 0x20 TP-SRR, 0x40 TP-UDHI, 0x80 TP-RP).
    local b0=$(( 0x01 | (extra & 0xE4) | ((vpf & 3) << 3) ))
    printf '%02x%02x%s%02x%02x%s%02x%s\n' \
        "$b0" "$mr" "$ah" "$(( 16#$(otasm_norm_hex "$pid") ))" "$(( 16#$(otasm_norm_hex "$dcs") ))" \
        "$vh" "$udl" "$(otasm_norm_hex "$ud")"
}

# Wrap a TPDU with an SMSC address field for the full "SCA ‖ TPDU" form that a
# modem expects.  An absent SMSC is encoded as the single octet 00.
otasm_smsc_wrap() {
    local sca="${1:-}" tpdu="${2:-}"
    local sh; sh=$(otasm_norm_hex "$sca"); local th; th=$(otasm_norm_hex "$tpdu")
    otasm_is_hex "$th" || { printf 'ERROR\tTPDU must be hex\n' >&2; return 2; }
    if [[ -z "$sh" ]]; then
        printf '00%s\n' "$th"
    else
        otasm_is_hex "$sh" || { printf 'ERROR\tSMSC address must be hex\n' >&2; return 2; }
        printf '%s%s\n' "$sh" "$th"
    fi
}

# ── TS 23.040 TPDU parsing ──────────────────────────────────────────────
_otasm_oct() { printf '%s' "${1:$(( $2 * 2 )):2}"; }

otasm_tpdu_parse() {
    local h; h=$(otasm_norm_hex "${1:-}")
    otasm_is_hex "$h" && (( ${#h} >= 2 )) || { printf 'ERROR\tTPDU must be hex\n' >&2; return 2; }
    (( ${#h} % 2 == 0 )) || { printf 'ERROR\tTPDU has an odd number of hex digits\n' >&2; return 2; }
    local n=$(( ${#h} / 2 ))
    local b0=$(( 16#$( _otasm_oct "$h" 0 ) ))
    local mti=$(( b0 & 3 ))
    local pos=1 nf=0
    printf 'tpdu\t%s\ntpdu_octets\t%d\nmti\t%d\n' "$h" "$n" "$mti"
    case "$mti" in
        0) printf 'mti_meaning\tSMS-DELIVER (or SMS-DELIVER-REPORT in the SC-to-MS direction)\n'
           printf 'mt_mms\t%d\nmt_lp\t%d\nmt_sri\t%d\nmt_udhi\t%d\nmt_rp\t%d\nmt_reserved_bit4\t%d\n' \
               "$(( (b0 >> 2) & 1 ))" "$(( (b0 >> 3) & 1 ))" "$(( (b0 >> 5) & 1 ))" \
               "$(( (b0 >> 6) & 1 ))" "$(( (b0 >> 7) & 1 ))" "$(( (b0 >> 4) & 1 ))" ;;
        1) printf 'mti_meaning\tSMS-SUBMIT (MS-to-SC) or SMS-SUBMIT-REPORT (SC-to-MS)\n'
           printf 'mt_rd\t%d\nmt_vpf\t%d\nmt_srr\t%d\nmt_udhi\t%d\nmt_rp\t%d\n' \
               "$(( (b0 >> 2) & 1 ))" "$(( (b0 >> 3) & 3 ))" "$(( (b0 >> 5) & 1 ))" \
               "$(( (b0 >> 6) & 1 ))" "$(( (b0 >> 7) & 1 ))" ;;
        2) printf 'mti_meaning\tSMS-STATUS-REPORT (SC-to-MS) or SMS-COMMAND (MS-to-SC)\n'
           printf 'mt_mms\t%d\nmt_lp\t%d\nmt_srq_ct\t%d\nmt_udhi\t%d\n' \
               "$(( (b0 >> 2) & 1 ))" "$(( (b0 >> 3) & 1 ))" "$(( (b0 >> 5) & 1 ))" "$(( (b0 >> 6) & 1 ))" ;;
        3) printf 'mti_meaning\treserved MTI — an MS must process this as SMS-DELIVER but store it exactly as received (§9.2.3.1)\n'
           printf 'finding\tMEDIUM\treserved TP-MTI 3; the TPDU below is decoded as SMS-DELIVER for display only\n'
           nf=$(( nf + 1 )) ;;
    esac

    # TP-OA / TP-DA / TP-RA all share the address field format.
    _otasm_read_addr() {
        local start=$1
        (( start < n )) || { printf 'ERROR\tTPDU truncated before an address field\n' >&2; return 2; }
        local alen=$(( 16#$( _otasm_oct "$h" "$start" ) ))
        local voctets=$(( (alen + 1) / 2 ))
        local total=$(( 1 + 1 + voctets ))
        (( start + total <= n )) || { printf 'ERROR\tTPDU truncated inside an address field\n' >&2; return 2; }
        printf '%s' "${h:$((start*2)):$((total*2))}"
        return 0
    }

    if (( mti == 0 || mti == 1 )); then
        local mr=""
        if (( mti == 1 )); then
            (( pos < n )) || { printf 'ERROR\tTPDU truncated before TP-MR\n' >&2; return 2; }
            mr=$( _otasm_oct "$h" "$pos" ); pos=$(( pos + 1 ))
            printf 'mr\t%s\n' "$mr"
        fi
        local afield; afield=$( _otasm_read_addr "$pos" ) || { printf 'ERROR\tTPDU truncated inside an address field\n' >&2; return 1; }
        if (( mti == 0 )); then
            echo "--- TP-OA"
            otasm_tp_addr_parse "$afield" | sed 's/^addr/oa/; s/^toa/oa_toa/'
        else
            echo "--- TP-DA"
            otasm_tp_addr_parse "$afield" | sed 's/^addr/da/; s/^toa/da_toa/'
        fi
        # `afield` already contains the Address-Length octet, so it advances
        # the cursor by its own length — adding 1 again shifts every later
        # field by an octet (this did exactly that in an earlier revision).
        local af_octets=$(( ${#afield} / 2 ))
        pos=$(( pos + af_octets ))
        (( pos + 2 <= n )) || { printf 'ERROR\tTPDU truncated before TP-PID/TP-DCS\n' >&2; return 1; }
        echo "--- TP-PID"
        otasm_tp_pid_parse "$( _otasm_oct "$h" "$pos" )"; pos=$(( pos + 1 ))
        echo "--- TP-DCS"
        local dcs_oct dcs_out dcs_alpha
        dcs_oct=$( _otasm_oct "$h" "$pos" )
        dcs_out=$( otasm_tp_dcs_parse "$dcs_oct" )
        printf '%s\n' "$dcs_out"
        dcs_alpha=$( printf '%s\n' "$dcs_out" | sed -n 's/^dcs_alphabet\t//p' )
        pos=$(( pos + 1 ))
        if (( mti == 0 )); then
            (( pos + 7 <= n )) || { printf 'ERROR\tTPDU truncated before TP-SCTS\n' >&2; return 1; }
            echo "--- TP-SCTS"
            otasm_tp_scts_parse "${h:$((pos*2)):14}"; pos=$(( pos + 7 ))
        else
            local vpf=$(( (b0 >> 3) & 3 )) vo
            case "$vpf" in 0) vo=0 ;; 1) vo=1 ;; *) vo=7 ;; esac
            if (( vo > 0 )); then
                (( pos + vo <= n )) || { printf 'ERROR\tTPDU truncated before TP-VP\n' >&2; return 1; }
                printf 'vp_octets\t%d\nvp\t%s\n' "$vo" "${h:$((pos*2)):$((vo*2))}"
                pos=$(( pos + vo ))
            fi
        fi
        (( pos < n )) || { printf 'ERROR\tTPDU truncated before TP-UDL\n' >&2; return 1; }
        local udl=$(( 16#$( _otasm_oct "$h" "$pos" ) )); pos=$(( pos + 1 ))
        printf -- '--- TP-UD\nudl\t%d\n' "$udl"
        local ud_hex="${h:$((pos*2))}"
        local ud_bytes=$(( n - pos ))
        printf 'ud_octets\t%d\nud\t%s\n' "$ud_bytes" "$ud_hex"
        # TP-UDL counts septets for the 7-bit alphabet and octets otherwise
        # (§9.2.3.16 / §9.2.4), so the two must be cross-checked, never assumed.
        if (( (b0 >> 6) & 1 )); then
            printf 'note\tINFO\tTP-UDHI is set: the first octets of TP-UD are a header, not text (TS 23.040 §9.2.3.23)\n'
            nf=$(( nf + 1 ))
        fi
        if (( ud_bytes == 0 && udl == 0 )); then
            printf 'ud_empty\tyes\n'
            printf 'finding\tHIGH\tzero-length TP-UD — the message carries no content, so nothing can be shown to the user\n'
            nf=$(( nf + 1 ))
        elif [[ "$dcs_alpha" == "GSM 7-bit default alphabet" ]]; then
            # TP-UDL counts septets only for the 7-bit alphabet (§9.2.3.16).
            local need=$(( (udl * 7 + 7) / 8 ))
            if (( ud_bytes == need )); then
                printf 'udl_units\tseptets (%d septets in %d octets)\n' "$udl" "$ud_bytes"
            else
                printf 'udl_units\tinconsistent\n'
                printf 'finding\tMEDIUM\tTP-UDL %d septets needs %d octets of TP-UD but %d are present\n' "$udl" "$need" "$ud_bytes"
                nf=$(( nf + 1 ))
            fi
        elif (( ud_bytes == udl )); then
            printf 'udl_units\toctets\n'
        else
            printf 'udl_units\tinconsistent\n'
            printf 'finding\tMEDIUM\tTP-UDL %d does not match %d octets of TP-UD under alphabet "%s"\n' "$udl" "$ud_bytes" "$dcs_alpha"
            nf=$(( nf + 1 ))
        fi
    elif (( mti == 2 )); then
        (( pos < n )) || { printf 'ERROR\tTPDU truncated before TP-MR\n' >&2; return 1; }
        printf 'mr\t%s\n' "$( _otasm_oct "$h" "$pos" )"; pos=$(( pos + 1 ))
        local rafield; rafield=$( _otasm_read_addr "$pos" ) || { printf 'ERROR\tTPDU truncated inside TP-RA\n' >&2; return 1; }
        echo "--- TP-RA"
        otasm_tp_addr_parse "$rafield" | sed 's/^addr/ra/; s/^toa/ra_toa/'
        pos=$(( pos + ${#rafield} / 2 ))
        if (( pos + 1 + 7 + 7 + 1 <= n )); then
            echo "--- TP-SCTS"
            otasm_tp_scts_parse "${h:$((pos*2)):14}"; pos=$(( pos + 7 ))
            printf 'dt\t%s\n' "${h:$((pos*2)):14}"; pos=$(( pos + 7 ))
            echo "--- TP-ST"
            local st; st=$( _otasm_oct "$h" "$pos" ); pos=$(( pos + 1 ))
            otasm_tp_st_parse "$st"
            local stv=$(( 16#$st ))
            if (( (stv & 0x80) == 0 )) && (( (stv >= 32 && stv <= 37) || (stv >= 96 && stv <= 101) )); then
                printf 'st_retryable\tyes\n'
            elif (( (stv & 0x80) == 0 )); then
                printf 'st_retryable\tno\n'
            fi
            local pi; pi=$( _otasm_oct "$h" "$pos" ); pos=$(( pos + 1 ))
            printf 'pi\t%s\n' "$pi"
            printf 'pi_pid_present\t%d\npi_dcs_present\t%d\npi_udl_present\t%d\n' \
                "$(( 16#$pi & 1 ))" "$(( (16#$pi >> 1) & 1 ))" "$(( (16#$pi >> 2) & 1 ))"
        else
            echo "--- SMS-STATUS-REPORT too short for TP-SCTS/TP-DT/TP-ST; treating as SMS-COMMAND"
            (( pos + 1 <= n )) || { printf 'finding\tMEDIUM\tTPDU ends after the address; no TP-ST present\n'; nf=$(( nf + 1 )); }
        fi
    fi
    printf 'findings\t%d\n' "$nf"
    return 0
}

# ── Type 0 silent SMS (TS 23.040 §9.2.3.9 + §9.2.3.1 note) ──────────────
# A Type 0 message is the smallest thing a network can deliver to a handset:
# TP-PID 0x40 with an empty TP-UD.  The ME acknowledges it and then discards
# it without indicating or storing it, so it is invisible to the user and does
# not consume SMS storage.  This builds one for an owned handset or the
# loopback SMSC the module's own plan describes.
otasm_type0_build() {
    local oa="${1:-}" scts="${2:-}" dcs="${3:-00}"
    if [[ -z "$oa" ]]; then
        # Default originator: international 0000 (a network-internal address
        # that no handset can reply to).
        oa=$(otasm_tp_addr_build 1 1 0000) || return 2
    fi
    if [[ -z "$scts" ]]; then
        scts=$(otasm_tp_scts_build "$(date -u +%y%m%d%H%M%S)" 0) || return 2
    fi
    otasm_tpdu_build_deliver "$oa" 40 "$dcs" "$scts" "" 0 0
}

# Audit a hex TPDU for the Type 0 / silent-message properties.
otasm_type0_audit() {
    local h; h=$(otasm_norm_hex "${1:-}")
    otasm_is_hex "$h" && (( ${#h} >= 2 )) || { printf 'ERROR\tTPDU must be hex\n' >&2; return 2; }
    local b0=$(( 16#$( _otasm_oct "$h" 0 ) ))
    local mti=$(( b0 & 3 ))
    # Walk to TP-PID: skip the first octet, optional TP-MR, then TP-OA/TP-DA.
    local pos=1
    (( mti == 1 )) && pos=$(( pos + 1 ))
    local n=$(( ${#h} / 2 ))
    (( pos < n )) || { printf 'ERROR\tTPDU too short to contain an address\n' >&2; return 2; }
    local alen=$(( 16#$( _otasm_oct "$h" "$pos" ) ))
    pos=$(( pos + 2 + (alen + 1) / 2 ))
    (( pos < n )) || { printf 'ERROR\tTPDU too short to contain TP-PID\n' >&2; return 2; }
    local pid=$(( 16#$( _otasm_oct "$h" "$pos" ) )); pos=$(( pos + 1 ))
    (( pos < n )) || { printf 'ERROR\tTPDU too short to contain TP-DCS\n' >&2; return 2; }
    local dcs=$(( 16#$( _otasm_oct "$h" "$pos" ) )); pos=$(( pos + 1 ))
    printf 'type0_mti\t%d\ntype0_pid\t%02x\ntype0_dcs\t%02x\ntype0_is_type0\t%s\n' \
        "$mti" "$pid" "$dcs" "$( ((pid == 0x40)) && echo yes || echo no )"
    (( pid == 0x40 )) || {
        printf 'note\tINFO\tTP-PID 0x%02X is not Short Message Type 0 (0x40); no silence property to report\n' "$pid"
        printf 'findings\t0\n'; return 0; }
    local found=0
    if (( mti == 0 )); then
        found=$(( found + 1 ))
        printf 'finding\tHIGH\tTP-PID 0x40 Short Message Type 0: the ME discards this without indicating or storing it (TS 23.040 §9.2.3.9)\n'
    else
        printf 'note\tINFO\tTP-PID 0x40 in a non-DELIVER TPDU (MTI %d); Type 0 is an MS-terminated property\n' "$mti"
    fi
    found=$(( found + 1 ))
    printf 'finding\tMEDIUM\tTP-DCS 0x%02X decides whether a payload would be rendered at all; with an empty TP-UD there is nothing to render\n' "$dcs"
    printf 'note\tINFO\tTP-FCS 0x81 is the failure cause an SC returns when it does not support Type 0 (TS 23.040 §9.2.3.22)\n'
    printf 'findings\t%d\n' "$found"
    return 0
}

# ── GSM 7-bit packing KAT ───────────────────────────────────────────────
# TS 23.038 §6.1.2.1.1's own worked example, so the packer is anchored to the
# published result rather than to a round-trip that would pass either way.
otasm_tp_packing_kat() {
    local n=0 got
    # Anchored on TS 23.038 §6.1.2.1.1's normative bit-layout tables, and on
    # the same `hi` vector 43_ussd already asserts, so a regression in either
    # packer is caught by the other module.
    _otasm_kat_case() {
        local text="$1" want="$2" label
        got=$(otasm_tp_pack_text "$text")
        label="kat_$(printf '%s' "$text" | tr -c 'A-Za-z0-9' _)"
        printf '%s\t%s\n' "$label" "$got"
        if [[ "$got" == "$want" ]]; then
            printf '%s_ok\tPASS\n' "$label"
        else
            printf '%s_ok\tFAIL want=%s got=%s\n' "$label" "$want" "$got"
            n=$(( n + 1 ))
        fi
        local back
        back=$(otasm_tp_unpack_text "$got" "${#text}")
        if [[ "$back" == "$text" ]]; then
            printf '%s_roundtrip\tPASS\n' "$label"
        else
            printf '%s_roundtrip\tFAIL want=%s got=%s\n' "$label" "$text" "$back"
            n=$(( n + 1 ))
        fi
    }
    _otasm_kat_case hi e834
    _otasm_kat_case Hi c834
    _otasm_kat_case hello e8329bfd06
    _otasm_kat_case Hello c8329bfd06
    printf 'failures\t%d\n' "$n"
    return $(( n > 0 ))
}

otasm_plan() {
    cat <<'EOF'
status	handoff
what	delivering an OTA command packet to a SIM
hardware	a programmable USIM you own (sysmoISIM-SJA2) plus an ISIM/OTA test bench, or a rooted modem you hold
software	pySim, osmo-sim-auth, or a SIMtrace2/pcsc reader with the SIM's OTA key set
flow	1. build a packet here with --packet  2. run --spi and --counter-check on it  3. deliver it to your own SIM
note	a live subscriber's SIM needs that subscriber's KIc/KID; this module never holds or derives another party's keys
EOF
}

# The TS 23.040 half needs a terminating SMSC rather than a SIM. A loopback
# SMSC is the honest way to exercise the TP layer end to end without a carrier.
otasm_plan_tp() {
    cat <<'EOF'
status	handoff
what	exercising the TS 23.040 TP layer against a terminating SMSC you run
hardware	none for the encoder/decoder; an SMS-capable modem you own for the loopback leg
software	an SMSC that accepts a raw TPDU on its own interface (e.g. smscsim / a
	scripted SMPP ESME that writes the TPDU to a pcap or a modem's AT+CMGS path)
flow	1. build the TPDU here (--tpdu-deliver / --type0-build)
	2. wrap it with --smsc-wrap and hand it to your own SMSC's injection point
	3. capture what the handset receives and re-run --tpdu-parse on the raw bytes
	4. --type0 confirms the Type 0 properties the handset is obliged to honour
scope	a Type 0 message is acknowledged and discarded without indication or
	storage (TS 23.040 §9.2.3.9). Its only effect on a handset you own is the
	absence of one. Point this at your own test handset, never a third party's.
EOF
}

otasm_selftest() {
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
    export OTASM_DIR="$d/loot/ota_sms"
    mkdir -p "$OTASM_DIR"

    # 1. SPI bit layout (TS 23.048 §8.1). RC/CC/DS=2, cipher=1, counter=3 ->
    #    octet1 = 10 1 11 000 = 0xB8; octet2 all zero.
    chk spi-build "$(otasm_spi_build 2 1 3 0 0 0 0)" "B800"
    chk spi-build2 "$(otasm_spi_build 1 0 0 0 0 0 0)" "4000"
    local out; out=$(otasm_spi_parse B800)
    chk spi-rccds   "$(fld "$out" rccds)" "2"
    chk spi-cipher  "$(fld "$out" ciphering)" "1"
    chk spi-counter "$(fld "$out" counter_mode)" "3"
    chk spi-clean   "$(fld "$out" findings)" "0"
    chk spi-dec     "$(fld "$(otasm_spi_parse 16384)" rccds)" "1"
    chk spi-bad     "$(otasm_spi_build 9 0 0 0 0 0 0 >/dev/null 2>&1; echo $?)" "2"

    # 2. Weak SPI is flagged, and unknown/insecure is never reported safe.
    out=$(otasm_spi_parse 0000)
    chk spi-weak-cipher  "$(fld "$out" ciphering_meaning)" "NOT applied (payload in the clear)"
    chk spi-weak-integr  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="finding" && $2=="HIGH"' | wc -l | tr -d ' ')" "2"
    chk spi-weak-findings "$(fld "$out" findings)" "3"
    out=$(otasm_spi_parse 2000)   # cipher on, no integrity, counter 0
    chk spi-partial "$(fld "$out" findings)" "2"

    # 3. Command packet build/parse round-trip.
    local pkt; pkt=$(otasm_packet_build 01 010203 5 B800 01 02 aabbcc 01 01)
    out=$(otasm_packet_parse "$pkt")
    chk pkt-cpi   "$(fld "$out" cpi)" "01"
    chk pkt-spi   "$(fld "$out" spi)" "b800"
    chk pkt-kic   "$(fld "$out" kic)" "01"
    chk pkt-kid   "$(fld "$out" kid)" "02"
    chk pkt-tar   "$(fld "$out" tar)" "010203"
    chk pkt-counter "$(fld "$out" counter_dec)" "5"
    chk pkt-data  "$(fld "$out" data)" "aabbcc"
    chk pkt-cpl-matches "$(fld "$out" cpl)" "$(fld "$out" packet_bytes)"
    chk pkt-badhex "$(otasm_packet_parse zz >/dev/null 2>&1; echo $?)" "2"
    chk pkt-short  "$(otasm_packet_parse 01 >/dev/null 2>&1; echo $?)" "1"
    # a large payload forces the two-octet CPL form and still round-trips.
    local big; big=$(printf 'aa%.0s' {1..200})
    pkt=$(otasm_packet_build 01 010203 9 B800 01 02 "$big" 01 01)
    chk pkt-big-cpl-oct "$(fld "$(otasm_packet_parse "$pkt")" cpl_octets)" "2"
    chk pkt-big-data-len "$(( ${#big} / 2 ))" "200"

    # 4. Counter / replay decisions per the SPI mode.
    chk cnt-none    "$(fld "$(otasm_counter_check 100 100 0)" verdict)" "process (counter absent — no replay protection)"
    chk cnt-info    "$(fld "$(otasm_counter_check 100 100 1)" verdict)" "process (counter informational only)"
    chk cnt-gt-ok   "$(fld "$(otasm_counter_check 101 100 2)" verdict)" "process (counter above the received value)"
    chk cnt-gt-rep  "$(fld "$(otasm_counter_check 100 100 2)" verdict)" "REPLAY (counter not above RE)"
    chk cnt-seq-ok  "$(fld "$(otasm_counter_check 101 100 3)" verdict)" "process (counter is exactly RE+1)"
    chk cnt-seq-rep "$(fld "$(otasm_counter_check 103 100 3)" verdict)" "REPLAY (counter is not RE+1)"
    chk cnt-badmode "$(otasm_counter_check 1 1 9 >/dev/null 2>&1; echo $?)" "2"

    # 5. TS 23.040 TP layer: packing, field codecs, TPDU round-trip, Type 0.
    #    The packing vector is TS 23.038 §6.1.2.1.1's own, shared with 43_ussd.
    chk tp-pack-hi    "$(otasm_tp_pack_text hi)" "e834"
    chk tp-pack-Hi    "$(otasm_tp_pack_text Hi)" "c834"
    chk tp-pack-hello "$(otasm_tp_pack_text hello)" "e8329bfd06"
    chk tp-pack-Hello "$(otasm_tp_pack_text Hello)" "c8329bfd06"
    chk tp-pack-rt    "$(otasm_tp_unpack_text "$(otasm_tp_pack_text Hello)" 5)" "Hello"
    chk tp-kat        "$(fld "$(otasm_tp_packing_kat)" failures)" "0"

    # Semi-octet swap plus the signed quarter-hour time zone (§9.2.3.11).
    local scts; scts=$(otasm_tp_scts_build 240517143000 8)
    chk tp-scts-build "$scts" "42507141030080"
    chk tp-scts-year  "$(fld "$(otasm_tp_scts_parse "$scts")" scts_year)" "2024"
    chk tp-scts-day   "$(fld "$(otasm_tp_scts_parse "$scts")" scts_day)" "17"
    chk tp-scts-tz    "$(fld "$(otasm_tp_scts_parse "$scts")" scts_tz_quarters)" "8"
    chk tp-scts-neg   "$(fld "$(otasm_tp_scts_parse "$(otasm_tp_scts_build 240101000000 -20)")" scts_tz_quarters)" "-20"
    chk tp-scts-bad   "$(otasm_tp_scts_build 2405 0 >/dev/null 2>&1; echo $?)" "2"

    # Address field: odd digit counts carry an 'F' fill semi-octet (§9.1.2.5).
    local af; af=$(otasm_tp_addr_build 1 1 15551234567)
    chk tp-addr-build "$af" "0b915155214365f7"
    chk tp-addr-value "$(fld "$(otasm_tp_addr_parse "$af")" addr_value)" "15551234567"
    chk tp-addr-ton   "$(fld "$(otasm_tp_addr_parse "$af")" toa_ton_meaning)" "international"
    chk tp-addr-odd   "$(otasm_tp_addr_build 2 0 5551234)" "07a0551532f4"
    chk tp-addr-odd-v "$(fld "$(otasm_tp_addr_parse "$(otasm_tp_addr_build 2 0 5551234)")" addr_value)" "5551234"
    chk tp-addr-alpha "$(otasm_tp_addr_build 5 0 1234 >/dev/null 2>&1; echo $?)" "2"
    chk tp-addr-short "$(otasm_tp_addr_parse 0b91 >/dev/null 2>&1; echo $?)" "1"

    # TP-PID: Type 0 is the silent one (§9.2.3.9), and it must be reported.
    chk tp-pid-40-silent "$(fld "$(otasm_tp_pid_parse 40)" pid_silent)" "yes"
    chk tp-pid-40-find   "$(fld "$(otasm_tp_pid_parse 40)" findings)" "1"
    chk tp-pid-00-quiet  "$(fld "$(otasm_tp_pid_parse 00)" pid_silent)" "no"
    chk tp-pid-48        "$(fld "$(otasm_tp_pid_parse 48)" pid_meaning)" "Device Triggering Short Message"
    chk tp-pid-7f        "$(fld "$(otasm_tp_pid_parse 7f)" pid_meaning)" "(U)SIM Data download"
    chk tp-pid-c0        "$(fld "$(otasm_tp_pid_parse c0)" pid_group)" "SC specific"

    # TP-DCS: alphabet, class, and the reserved groups that must not be
    # silently read as the 7-bit default (TS 23.038 §4).
    chk tp-dcs-00   "$(fld "$(otasm_tp_dcs_parse 00)" dcs_meaning)" "GSM 7-bit default alphabet, no message class"
    chk tp-dcs-08   "$(fld "$(otasm_tp_dcs_parse 08)" dcs_alphabet)" "UCS2 (16-bit)"
    chk tp-dcs-f0-c "$(fld "$(otasm_tp_dcs_parse f0)" dcs_class)" "0"
    chk tp-dcs-f0-d "$(fld "$(otasm_tp_dcs_parse f0)" dcs_class0_immediate_display)" "yes"
    chk tp-dcs-80   "$(fld "$(otasm_tp_dcs_parse 80)" findings)" "1"
    chk tp-dcs-d0   "$(fld "$(otasm_tp_dcs_parse d0)" dcs_group)" "MWI: store message (1101)"
    chk tp-dcs-build "$(otasm_tp_dcs_build ucs2 none 0 0)" "08"
    chk tp-dcs-bld-c "$(otasm_tp_dcs_build 8bit 2 0 1)" "56"
    chk tp-dcs-bad   "$(otasm_tp_dcs_build klingon none 0 0 >/dev/null 2>&1; echo $?)" "2"

    # TP-FCS / TP-ST: an SC rejecting Type 0 answers with 0x81 (§9.2.3.22).
    chk tp-fcs-81 "$(fld "$(otasm_tp_fcs_parse 81)" fcs_meaning)" "Short message Type 0 not supported"
    chk tp-fcs-90 "$(fld "$(otasm_tp_fcs_parse 90)" fcs_meaning)" "Data coding scheme (alphabet) not supported"
    chk tp-fcs-res "$(fld "$(otasm_tp_fcs_parse 83)" fcs_meaning)" "reserved — treat as an unspecified error cause"
    chk tp-st-00  "$(fld "$(otasm_tp_st_parse 00)" st_meaning)" "Short message received by the SME (transaction completed)"
    chk tp-st-23  "$(fld "$(otasm_tp_st_parse 23)" st_meaning)" "Service rejected (temporary error, SC still trying)"
    chk tp-st-res "$(fld "$(otasm_tp_st_parse 03)" st_meaning)" "reserved — interpret as Service Rejected (0x23)"

    # Full TPDU: build a Type 0 silent SMS-DELIVER and read it back.
    local t0; t0=$(otasm_type0_build "" "$scts")
    chk tp-type0-len  "$(fld "$(otasm_tpdu_parse "$t0")" tpdu_octets)" "15"
    chk tp-type0-mti  "$(fld "$(otasm_tpdu_parse "$t0")" mti)" "0"
    chk tp-type0-pid  "$(fld "$(otasm_tpdu_parse "$t0")" pid)" "40"
    chk tp-type0-udl  "$(fld "$(otasm_tpdu_parse "$t0")" udl)" "0"
    chk tp-type0-empty "$(fld "$(otasm_tpdu_parse "$t0")" ud_empty)" "yes"
    chk tp-type0-scts "$(fld "$(otasm_tpdu_parse "$t0")" scts_local)" "2024-05-17T14:30:00"
    chk tp-type0-audit "$(fld "$(otasm_type0_audit "$t0")" type0_is_type0)" "yes"
    chk tp-type0-find  "$(( $(fld "$(otasm_type0_audit "$t0")" findings) >= 1 ? 1 : 0 ))" "1"

    # The severity channel is reserved for counted findings: every line emitted
    # as "finding" must be reflected in the findings total, and an informational
    # line must arrive as "note". This invariant caught a MEDIUM that was printed
    # but never counted, so it is asserted rather than assumed.
    local t0o; t0o=$(otasm_type0_audit "$t0")
    chk tp-type0-count "$(fld "$t0o" findings)" "2"
    chk tp-type0-tally "$(printf '%s\n' "$t0o" | awk -F'\t' '$1=="finding"' | wc -l | tr -d ' ')" "$(fld "$t0o" findings)"
    chk tp-no-info-finding "$(printf '%s\n' "$t0o" "$(otasm_spi_parse B800)" "$(otasm_tp_fcs_parse 81)" "$(otasm_spi_parse 0000)" | awk -F'\t' '$1=="finding" && $2=="INFO"' | wc -l | tr -d ' ')" "0"
    chk tp-spi-tally "$(printf '%s\n' "$(otasm_spi_parse 0000)" | awk -F'\t' '$1=="finding"' | wc -l | tr -d ' ')" "$(fld "$(otasm_spi_parse 0000)" findings)"

    # SMS-SUBMIT round-trip through the address field and the packer.
    local sub; sub=$(otasm_tpdu_build_submit "$af" 00 00 "$(otasm_tp_pack_text hello)" 5 7 0 "" 0)
    out=$(otasm_tpdu_parse "$sub")
    chk tp-sub-mti   "$(fld "$out" mti)" "1"
    chk tp-sub-mr    "$(fld "$out" mr)" "07"
    chk tp-sub-da    "$(fld "$out" da_value)" "15551234567"
    chk tp-sub-ud    "$(fld "$out" ud)" "e8329bfd06"
    chk tp-sub-units "$(fld "$out" udl_units)" "septets (5 septets in 5 octets)"

    # A UDL that disagrees with the TP-UD length must be flagged, never applied.
    chk tp-udl-mismatch "$(fld "$(otasm_tpdu_parse "$(otasm_tpdu_build_deliver "$af" 00 00 "$scts" deadbeef 200 0)")" udl_units)" "inconsistent"
    # A reserved TP-MTI is decoded but reported, never silently coerced.
    chk tp-mti-reserved "$(printf '%s\n' "$(otasm_tpdu_parse "03${t0:2}")" | awk -F'\t' '$1=="finding" && $2=="MEDIUM"' | wc -l | tr -d ' ')" "1"
    chk tp-udhi "$(fld "$(otasm_tpdu_parse "$(otasm_tpdu_build_deliver "$af" 00 00 "$scts" deadbeef 4 64)")" mt_udhi)" "1"

    # 6. Scope: no send/deliver verb is dispatchable.
    chk scope-no-send    "$(otasm_cli_main --send >/dev/null 2>&1; echo $?)" "2"
    chk scope-no-deliver "$(otasm_cli_main --deliver >/dev/null 2>&1; echo $?)" "2"

    printf 'ASSERTIONS\t%d\n' "$nchk"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

otasm_menu() {
    while true; do
        banner
        echo "  === OTA Binary SMS ==="
        echo
        cat <<'M'
  [1]  Build an SPI
  [2]  Parse / audit an SPI
  [3]  Build a command packet
  [4]  Parse a command packet
  [5]  Counter / replay check
  [6]  Plan (handoff)
  --- TS 23.040 TP layer ---
  [7]  Decode a TP-PID (incl. Type 0)
  [8]  Decode / build a TP-DCS
  [9]  Build / decode a TP-SCTS
  [10] Build / decode an address field
  [11] GSM 7-bit packing KAT, pack and unpack text
  [12] Build an SMS-DELIVER / SMS-SUBMIT TPDU
  [13] Parse a TPDU
  [14] Build / audit a Type 0 silent SMS
  [15] Decode TP-FCS / TP-ST
  [0]  back
M
        read -rp "  choice> " c || return 0
        case "$c" in
            1) read -rp "  rccds(0-3)> " a; read -rp "  cipher(0-1)> " b; read -rp "  counter(0-3)> " d
               otasm_spi_build "$a" "$b" "$d"; echo; read -rp "  enter " _ ;;
            2) read -rp "  spi (hex or decimal)> " s; otasm_spi_parse "$s"; read -rp "  enter " _ ;;
            3) read -rp "  TAR(6hex)> " t; read -rp "  counter> " n; read -rp "  SPI(4hex)> " s
               read -rp "  KIc(2hex)> " k1; read -rp "  KID(2hex)> " k2; read -rp "  data hex> " dd
               otasm_packet_build 01 "$t" "$n" "$s" "$k1" "$k2" "$dd"; echo; read -rp "  enter " _ ;;
            4) read -rp "  packet hex> " p; otasm_packet_parse "$p"; read -rp "  enter " _ ;;
            5) read -rp "  counter> " n; read -rp "  RE> " r; read -rp "  mode 0-3> " m
               otasm_counter_check "$n" "$r" "${m:-0}"; read -rp "  enter " _ ;;
            6) otasm_plan; read -rp "  enter " _ ;;
            7) read -rp "  TP-PID hex> " p; otasm_tp_pid_parse "$p"; read -rp "  enter " _ ;;
            8) read -rp "  [p]arse or [b]uild> " m
               if [[ "$m" == b ]]; then
                   read -rp "  alphabet 7bit|8bit|ucs2> " al; read -rp "  class none|0|1|2|3> " cl
                   read -rp "  compressed 0|1> " cp; read -rp "  autodelete 0|1> " ad
                   otasm_tp_dcs_build "$al" "$cl" "${cp:-0}" "${ad:-0}"
               else
                   read -rp "  TP-DCS hex> " dd; otasm_tp_dcs_parse "$dd"
               fi; read -rp "  enter " _ ;;
            9) read -rp "  [p]arse hex7 or [b]uild YYMMDDhhmmss> " m
               if [[ "$m" == b ]]; then
                   read -rp "  YYMMDDhhmmss> " ts; read -rp "  tz quarter hours> " tz
                   otasm_tp_scts_build "$ts" "${tz:-0}"
               else
                   otasm_tp_scts_parse "$m"
               fi; read -rp "  enter " _ ;;
           10) read -rp "  [p]arse hex or [b]uild ton/npi/digits> " m
               if [[ "$m" == b ]]; then
                   read -rp "  ton 0-7> " tn; read -rp "  npi 0-9> " np; read -rp "  digits> " dg
                   otasm_tp_addr_build "${tn:-0}" "${np:-0}" "$dg"
               else
                   otasm_tp_addr_parse "$m"
               fi; read -rp "  enter " _ ;;
           11) otasm_tp_packing_kat
               read -rp "  pack text (blank to skip)> " tx
               if [[ -n "$tx" ]]; then
                   local packed; packed=$(otasm_tp_pack_text "$tx")
                   printf 'packed\t%s\n' "$packed"
                   printf 'back\t%s\n' "$(otasm_tp_unpack_text "$packed" "${#tx}")"
               fi
               read -rp "  TP-UD octets to read back (blank to skip)> " uh
               if [[ -n "$uh" ]]; then read -rp "  septet count> " sn; otasm_tp_unpack_text "$uh" "$sn"; fi
               read -rp "  enter " _ ;;
           12) read -rp "  [d]eliver or [s]ubmit> " m
               if [[ "$m" == s ]]; then
                   read -rp "  TP-DA address hex> " ad; read -rp "  TP-PID hex> " pp; read -rp "  TP-DCS hex> " dc
                   read -rp "  TP-UD hex> " uu; read -rp "  TP-UDL> " ul; read -rp "  TP-MR> " mr
                   otasm_tpdu_build_submit "$ad" "$pp" "$dc" "$uu" "$ul" "${mr:-0}" 0 "" 0
               else
                   read -rp "  TP-OA address hex> " ad; read -rp "  TP-PID hex> " pp; read -rp "  TP-DCS hex> " dc
                   read -rp "  TP-SCTS hex14> " st; read -rp "  TP-UD hex> " uu; read -rp "  TP-UDL> " ul
                   otasm_tpdu_build_deliver "$ad" "$pp" "$dc" "$st" "$uu" "$ul" 0
               fi; read -rp "  enter " _ ;;
           13) read -rp "  TPDU hex> " tp; otasm_tpdu_parse "$tp"; read -rp "  enter " _ ;;
           14) read -rp "  [b]uild or [a]udit hex> " m
               if [[ "$m" == b ]]; then
                   read -rp "  originator address hex (blank = intl 0000)> " oa
                   read -rp "  TP-SCTS hex14 (blank = now)> " st
                   otasm_type0_build "$oa" "$st"
               else
                   otasm_type0_audit "$m"
               fi; read -rp "  enter " _ ;;
           15) read -rp "  f<hex> for TP-FCS, s<hex> for TP-ST> " m
               if [[ "${m:0:1}" == f ]]; then otasm_tp_fcs_parse "${m:1}"; else otasm_tp_st_parse "${m:1}"; fi
               read -rp "  enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

otasm_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)     otasm_status_tsv ;;
        --spi-build)      otasm_spi_build "${1:-0}" "${2:-0}" "${3:-0}" "${4:-0}" "${5:-0}" "${6:-0}" "${7:-0}" ;;
        --spi)            otasm_spi_parse "${1:-}" ;;
        --packet)         otasm_packet_build "${1:-01}" "${2:-000000}" "${3:-0}" "${4:-B800}" "${5:-01}" "${6:-01}" "${7:-}" "${8:-01}" "${9:-01}" ;;
        --parse-packet)   otasm_packet_parse "${1:-}" ;;
        --counter-check)  otasm_counter_check "${1:-}" "${2:-}" "${3:-0}" ;;
        --tp-pid)         otasm_tp_pid_parse "${1:-}" ;;
        --tp-dcs)         otasm_tp_dcs_parse "${1:-}" ;;
        --tp-dcs-build)   otasm_tp_dcs_build "${1:-7bit}" "${2:-none}" "${3:-0}" "${4:-0}" ;;
        --tp-fcs)         otasm_tp_fcs_parse "${1:-}" ;;
        --tp-st)          otasm_tp_st_parse "${1:-}" ;;
        --tp-scts-build)  otasm_tp_scts_build "${1:-}" "${2:-0}" ;;
        --tp-scts)        otasm_tp_scts_parse "${1:-}" ;;
        --tp-addr-build)  otasm_tp_addr_build "${1:-0}" "${2:-0}" "${3:-}" ;;
        --tp-addr)        otasm_tp_addr_parse "${1:-}" ;;
        --tp-ud-build)    otasm_tp_pack_text "${1:-}" ;;
        --tp-ud-read)     otasm_tp_unpack_text "${1:-}" "${2:-0}" ;;
        --tp-kat)         otasm_tp_packing_kat ;;
        --tpdu-parse)     otasm_tpdu_parse "${1:-}" ;;
        --tpdu-deliver)   otasm_tpdu_build_deliver "${1:-}" "${2:-00}" "${3:-00}" "${4:-}" "${5:-}" "${6:-0}" "${7:-0}" ;;
        --tpdu-submit)    otasm_tpdu_build_submit "${1:-}" "${2:-00}" "${3:-00}" "${4:-}" "${5:-0}" "${6:-0}" "${7:-0}" "${8:-}" "${9:-0}" ;;
        --smsc-wrap)      otasm_smsc_wrap "${1:-}" "${2:-}" ;;
        --type0-build)    otasm_type0_build "${1:-}" "${2:-}" "${3:-00}" ;;
        --type0)          otasm_type0_audit "${1:-}" ;;
        --plan)           otasm_plan ;;
        --plan-tp)        otasm_plan_tp ;;
        --selftest)       otasm_selftest ;;
        --menu)           otasm_menu ;;
        *)
            cat >&2 <<EOF
OTA Binary SMS — TS 23.048 command packet construction and key/counter audit

Usage: $0 COMMAND
  --status-tsv                       module state as TSV
  --spi-build <rccds> <cipher> <counter> [por...]
  --spi <hex|dec>                    parse and audit an SPI
  --packet <cpi> <tar> <counter> <spi> <kic> <kid> <data> [chi] [cmd]
  --parse-packet <hex>               decode a command packet
  --counter-check <counter> <RE> [mode]   replay decision per SPI mode
  --tp-kat                           GSM 7-bit packing KAT (TS 23.038 §6.1.2.1.1)
  --tp-pid <hex>                     decode TP-PID, including Type 0 / triggering
  --tp-dcs <hex>                     decode TP-DCS per TS 23.038 §4
  --tp-dcs-build <alpha> <class> [compressed] [autodelete]
  --tp-fcs <hex>                     decode a TP-Failure-Cause
  --tp-st <hex>                      decode a TP-Status
  --tp-scts-build <YYMMDDhhmmss> [tz-quarters]
  --tp-scts <hex7>                   decode TP-SCTS
  --tp-addr-build <ton> <npi> <digits>
  --tp-addr <hex>                    decode an address field
  --tp-ud-build <text>               pack text into TP-UD octets
  --tp-ud-read <hex> <septets>       unpack TP-UD back to text
  --tpdu-parse <hex>                 decode a complete TPDU
  --tpdu-deliver <oa> <pid> <dcs> <scts> <ud> <udl> [flagbits]
  --tpdu-submit <da> <pid> <dcs> <ud> <udl> [mr] [vpf] [vp] [flagbits]
  --smsc-wrap <sca-hex> <tpdu-hex>   prepend an SMSC address field
  --type0-build [oa] [scts] [dcs]    build a Type 0 silent SMS-DELIVER
  --type0 <hex>                      audit a TPDU for the Type 0 properties
  --plan                             own-SIM delivery handoff plan
  --plan-tp                          loopback-SMSC handoff plan for the TP layer
  --selftest                         verify SPI, packet and replay logic
  --menu                             interactive menu

Scope: own-SIM and lab construction plus vulnerability detection. Affecting a
SIM you do not hold requires that SIM's OTA keys, which this module never holds.
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
    otasm_cli_main "$@"
fi
