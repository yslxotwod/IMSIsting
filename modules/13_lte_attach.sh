#!/usr/bin/env bash
# LTE Attach / NAS — EPS Mobility Management (EMM) encode/decode
#
# The NAS layer is pure protocol: everything here is computed from 3GPP
# TS 24.301, so it is performed for real with no radio, no root and no
# network. Nothing in this module is a plan — see 15_lte_core.sh for the
# vectors that genuinely need a lab EPC.
#
# Reference clause map (TS 24.301):
#   9.9.2.0   EPS mobility management messages (Table 9.9.2.1.1)
#   9.9.3.1   Attach request
#   9.9.3.2   Attach accept
#   9.9.3.3   Attach reject
#   9.9.3.4   Detach request / 9.9.3.7 Detach accept
#   9.9.3.12  Tracking area update request
#   9.9.3.17  Identity request / 9.9.3.18 Identity response
#   9.9.3.19  Authentication request / 9.9.3.20 Authentication response
#   9.9.3.21  Authentication failure / 9.9.3.22 Authentication reject
#   9.9.3.23  Security mode command / 9.9.3.24 Security mode complete
#   9.9.3.25  Security mode reject
#   9.9.3.26  EMM status / 9.9.3.27 EMM information
#   9.9.4.x   Information elements
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

MOD_TMP="$TMP_DIR/lte_attach"
LATT_DIR="$LOOT_DIR/lte_attach"
LATT_IDENT="$LATT_DIR/identities.tsv"
mkdir -p "$MOD_TMP" "$LATT_DIR" 2>/dev/null

# ── sanitisation ────────────────────────────────────────────────────────
# Any string that reaches a TSV row is untrusted: an operator name or a
# decode annotation sourced from a capture can carry a tab and forge an
# entire row in a consumer that splits on tab. Tabs, CR and LF become
# spaces at the point of output.
latt_sanitize() {
    printf '%s' "${1:-}" | tr '\t\r\n' '   '
}

# ── NFC / hex helpers ───────────────────────────────────────────────────
latt_nfc() {
    local s="${1:-}"
    s="${s^^}"
    s="${s//[[:space:]]/}"
    s="${s//:/}"
    s="${s//-/}"
    printf '%s' "$s"
}

latt_is_hex() {
    [[ "${1:-}" =~ ^[0-9A-Fa-f]+$ ]] && (( ${#1} % 2 == 0 ))
}

# ── BCD codec — TS 24.301 §9.9.2.3 / TS 23.003 §2.2 ─────────────────────
#
# A "BCD number" (IMSI, IMEI, MSISDN, ME identity) is carried as:
#
#   octet 1 : digit 2 (high nibble) | digit 1 (low nibble)
#   octet 2 : digit 4 | digit 3
#   ...
#   last octet : filler (high nibble) | digit N (low nibble)
#
# Digits are stored in *reverse nibble order*: the low nibble of an octet
# holds the earlier digit. When the digit count is odd the final digit sits
# alone in the low nibble of a whole extra octet whose high nibble is the
# filler, canonically 0xF.
#
#   IMSI "310150123456789" (15 digits, odd)
#     -> 13 10 51 10 32 54 76 F8   (8 bytes)
#        ^^ = 1,3  ^^ = 0,1  ^^ = 5,1 ...
#
#   IMSI "31015012345678" (14 digits, even)
#     -> 13 10 51 10 32 54 76 8    (7 bytes)
latt_bcd_encode_num() {
    local digits="${1:-}"
    [[ -n "$digits" ]] || return 1
    [[ "$digits" =~ ^[0-9]+$ ]] || return 1
    local n=${#digits}
    local out="" i d1 d2
    for (( i = 0; i < n; i += 2 )); do
        d1="${digits:$i:1}"
        if (( i + 1 < n )); then d2="${digits:$((i+1)):1}"; else d2="F"; fi
        out+="${d2}${d1}"
    done
    printf '%s' "$out"
}

# Decode BCD nibbles back to a digit string.
#
# Two callers, two situations:
#
#  * `latt_bcd_decode_num <hex>` — no length information, so we infer it.
#    An even digit count produces an exact whole number of BCD octets
#    (no filler); an odd count produces a final octet whose high nibble
#    is the filler 0xF. We therefore only drop the trailing nibble when
#    the encoding is odd-length *or* the last high nibble is the 0xF
#    filler. Dropping it unconditionally, which is the obvious-looking
#    implementation, silently truncates every 14-digit IMSI.
#  * `latt_bcd_decode_num <hex> <digits>` — the caller knows the exact
#    digit count (the EPS mobile identity length field gives it), so we
#    take exactly that many digits and ignore any filler.
latt_bcd_decode_num() {
    local hex; hex=$(latt_nfc "${1:-}")
    local want="${2:-}"
    latt_is_hex "$hex" || return 1
    [[ -n "$hex" ]] || return 1
    local out="" i
    for (( i = 0; i < ${#hex}; i += 2 )); do
        out+="${hex:$((i+1)):1}${hex:$i:1}"
    done
    if [[ -n "$want" ]]; then
        # Authoritative digit count supplied by the caller.
        [[ "$want" =~ ^[0-9]+$ ]] || return 1
        (( want <= ${#out} )) || return 1
        out="${out:0:$want}"
    else
        # Infer: strip the final nibble only when it is a filler.
        local last_hi="${hex:$(( ${#hex} - 2 )):1}"
        if (( ${#hex} % 2 == 0 )) && [[ "$last_hi" == "F" || "$last_hi" == "f" ]]; then
            out="${out:0:${#out}-1}"
        elif (( ${#hex} % 2 != 0 )); then
            out="${out:0:${#out}-1}"
        fi
    fi
    [[ "$out" =~ ^[0-9]+$ ]] || return 1
    printf '%s' "$out"
}

# ── EPS mobile identity — TS 24.301 §9.9.3.12 ───────────────────────────
# Octet 1 is the IEI (0x08 for IMSI/IMEI/IMEISV, 0x01 for GUTI); octet 2
# is length, then the *value part* which begins with one type octet:
#
#   type = 0b001 (1)  IMSI       value = 3..8 BCD octets (see above)
#   type = 0b010 (2)  IMEI       as IMSI, 15 digits
#   type = 0b011 (3)  IMEISV     as IMSI
#   type = 0b110 (6)  GUTI       value = PLMN(3) | M-TMSI(4) | MMEI(3 )
#
# So an IMSI identity IE is always type_octet + value = 1 + 8 = 9 octets
# for a 15-digit IMSI, i.e. length field 9.
latt_imsi_to_eps_mobile_id() {
    local imsi="${1:-}"
    [[ "$imsi" =~ ^[0-9]{14,15}$ ]] || return 1
    local bcd; bcd=$(latt_bcd_encode_num "$imsi") || return 1
    # Value part = 1 type octet + ceil(digits/2) BCD octets.
    # 15 digits -> 1 + 8 = 9 ; 14 digits -> 1 + 7 = 8.
    local vlen=$(( (${#imsi} + 1) / 2 + 1 ))
    printf '08%02X01%s' "$vlen" "$bcd"
}

latt_imei_to_eps_mobile_id() {
    local imei="${1:-}"
    [[ "$imei" =~ ^[0-9]{15}$ ]] || return 1
    local bcd; bcd=$(latt_bcd_encode_num "$imei") || return 1
    local vlen=$(( (${#imei} + 1) / 2 + 1 ))
    printf '08%02X02%s' "$vlen" "$bcd"
}

# Decode an EPS mobile identity value-part (the bytes *after* IEI and
# length) into "type<TAB>digits". Accepts either the value part alone or
# the full `08 09 01 ...` encoding.
#
# When the length octet is present it is authoritative: the value part is
# `len` octets, of which the first is the type octet, so the BCD payload
# is `len - 1` octets and therefore carries 2*(len-1) digits plus one more
# if the final octet's high nibble is a filler. That resolves the even/odd
# ambiguity that the bare nibble string cannot.
latt_eps_mobile_id_decode() {
    local hex; hex=$(latt_nfc "${1:-}")
    latt_is_hex "$hex" || return 1
    [[ -n "$hex" ]] || return 1
    local bcd_octets="" declared_len=""
    case "${hex:0:2}" in
        08)
            # Full IEI + length + value form.
            local len="${hex:2:2}"
            [[ "$len" =~ ^[0-9A-Fa-f]{2}$ ]] || return 1
            declared_len=$(( 16#$len ))
            hex="${hex:4}"
            ;;
    esac
    [[ ${#hex} -ge 2 ]] || return 1
    local typ="${hex:0:2}"
    local body="${hex:2}"
    local digits=""
    if [[ -n "$declared_len" ]]; then
        # Trim the body to exactly the declared value-part size.
        (( declared_len >= 1 )) || return 1
        local want_hex=$(( (declared_len - 1) * 2 ))
        (( want_hex <= ${#body} )) || return 1
        body="${body:0:$want_hex}"
        bcd_octets=$(( declared_len - 1 ))
    else
        bcd_octets=$(( ${#body} / 2 ))
    fi
    # Digit count: 2 per BCD octet, less one when the last octet's high
    # nibble is the 0xF filler (odd digit count).
    local last_hi=""
    (( bcd_octets > 0 )) && last_hi="${body:$(( (bcd_octets - 1) * 2 )):1}"
    if [[ "$last_hi" == "F" || "$last_hi" == "f" ]]; then
        digits=$(latt_bcd_decode_num "$body" $(( bcd_octets * 2 - 1 ))) || return 1
    else
        digits=$(latt_bcd_decode_num "$body" $(( bcd_octets * 2 ))) || return 1
    fi
    case "$typ" in
        01) printf 'IMSI\t%s'   "$digits" ;;
        02) printf 'IMEI\t%s'   "$digits" ;;
        03) printf 'IMEISV\t%s' "$digits" ;;
        06) printf 'GUTI\t%s'   "$body" ;;
        *)  return 1 ;;
    esac
}

# ── assigned-number tables ──────────────────────────────────────────────
#
# EPS attach type — TS 24.301 §9.9.3.11 (Table 9.9.3.11.1: value 1..4 are
# the only assigned ones; 0 and 5..7 are spare).
latt_attach_type_name() {
    case "${1:-}" in
        1) echo "EPS attach" ;;
        2) echo "combined EPS/IMSI attach" ;;
        3) echo "EPS emergency attach" ;;
        4) echo "reserved (EPS attach for emergency services)" ;;
        0|5|6|7) echo "spare" ;;
        *) echo "invalid" ;;
    esac
}

# EMM cause — TS 24.301 §9.9.3.9 (Table 9.9.3.9.1). Complete assigned set.
latt_emm_cause_name() {
    case "${1:-}" in
        2)   echo "IMSI unknown in HSS" ;;
        3)   echo "Illegal UE" ;;
        5)   echo "IMEI not accepted" ;;
        6)   echo "Illegal ME" ;;
        7)   echo "EPS services not allowed" ;;
        8)   echo "EPS services and non-EPS services not allowed" ;;
        9)   echo "UE identity cannot be derived by the network" ;;
        10)  echo "Implicitly detached" ;;
        11)  echo "PLMN not allowed" ;;
        12)  echo "Tracking area not allowed" ;;
        13)  echo "Roaming not allowed in this tracking area" ;;
        14)  echo "EPS services not allowed in this PLMN" ;;
        15)  echo "No suitable cells in tracking area" ;;
        16)  echo "MSC temporarily not reachable" ;;
        17)  echo "Network failure" ;;
        18)  echo "CS domain not available" ;;
        19)  echo "ESM failure" ;;
        20)  echo "MAC failure" ;;
        21)  echo "Synch failure" ;;
        22)  echo "Congestion" ;;
        23)  echo "UE security capabilities mismatch" ;;
        24)  echo "Security mode rejected, unspecified" ;;
        25)  echo "Not authorized for this CSG" ;;
        26)  echo "Non-EPS authentication unacceptable" ;;
        27)  echo "Requested service option not authorized in this PLMN" ;;
        28)  echo "CS fallback call not available (no EPS bearer context activated)" ;;
        31)  echo "Redirection to 5GCN required" ;;
        35)  echo "Requested service option not authorized" ;;
        39)  echo "CS service temporarily not available" ;;
        40)  echo "No EPS bearer context activated" ;;
        42)  echo "Severe network failure" ;;
        43)  echo "Temporarily not authorized for this CSG" ;;
        65)  echo "Maximum number of EPS bearers reached" ;;
        66)  echo "Requested APN not supported in current RAT and PLMN combination" ;;
        81)  echo "Invalid PTI value" ;;
        95)  echo "Semantically incorrect message" ;;
        96)  echo "Invalid mandatory information" ;;
        97)  echo "Message type non-existent or not implemented" ;;
        98)  echo "Message type not compatible with protocol state" ;;
        99)  echo "Information element non-existent or not implemented" ;;
        100) echo "Conditional IE error" ;;
        101) echo "Message not compatible with protocol state" ;;
        111) echo "Protocol error, unspecified" ;;
        *)   echo "unassigned" ;;
    esac
}

# NAS message type — TS 24.301 §9.8 (Table 9.8.1). EMM half only; the ESM
# half is noted where a NAS message-type byte may legally carry it.
latt_msg_type_name() {
    case "${1:-}" in
        0x41) echo "ATTACH REQUEST" ;;
        0x42) echo "ATTACH ACCEPT" ;;
        0x43) echo "ATTACH COMPLETE" ;;
        0x44) echo "ATTACH REJECT" ;;
        0x45) echo "DETACH REQUEST" ;;
        0x46) echo "DETACH ACCEPT" ;;
        0x47) echo "TRACKING AREA UPDATE REQUEST" ;;
        0x48) echo "TRACKING AREA UPDATE ACCEPT" ;;
        0x49) echo "TRACKING AREA UPDATE COMPLETE" ;;
        0x4A) echo "TRACKING AREA UPDATE REJECT" ;;
        0x4B) echo "EXTENDED SERVICE REQUEST" ;;
        0x4C) echo "SERVICE REJECT" ;;
        0x4D) echo "GUTI REALLOCATION COMMAND" ;;
        0x4E) echo "GUTI REALLOCATION COMPLETE" ;;
        0x4F) echo "AUTHENTICATION REQUEST" ;;
        0x50) echo "AUTHENTICATION RESPONSE" ;;
        0x51) echo "AUTHENTICATION REJECT" ;;
        0x52) echo "AUTHENTICATION FAILURE" ;;
        0x53) echo "IDENTITY REQUEST" ;;
        0x54) echo "IDENTITY RESPONSE" ;;
        0x55) echo "SECURITY MODE COMMAND" ;;
        0x56) echo "SECURITY MODE COMPLETE" ;;
        0x57) echo "SECURITY MODE REJECT" ;;
        0x58) echo "EMM STATUS" ;;
        0x59) echo "EMM INFORMATION" ;;
        0x5A) echo "DOWNLINK NAS TRANSPORT" ;;
        0x5B) echo "UPLINK NAS TRANSPORT" ;;
        0x5C) echo "CS SERVICE NOTIFICATION" ;;
        0x5D) echo "DOWNLINK GENERIC NAS TRANSPORT" ;;
        0x5E) echo "UPLINK GENERIC NAS TRANSPORT" ;;
        0x01|0x02|0x03|0x04|0x05|0x06|0x07|0x08|0x09) echo "ESM message (PDN connectivity/bearer)" ;;
        *)    echo "unknown" ;;
    esac
}

# Security header type — TS 24.301 §9.3.1 (Table 9.3.1.1). This is the low
# nibble of octet 1 of every plain NAS message.
latt_security_header_name() {
    case "${1:-}" in
        0) echo "PLAIN NAS" ;;
        1) echo "INTEGRITY PROTECTED" ;;
        2) echo "INTEGRITY PROTECTED AND NEW EPS SECURITY CONTEXT" ;;
        3) echo "INTEGRITY PROTECTED WITH NEW EPS SECURITY CONTEXT" ;;
        4) echo "INTEGRITY PROTECTED AND PARTIALLY CIPHERED NEW EPS SECURITY CONTEXT" ;;
        5) echo "INTEGRITY PROTECTED AND CIPHERED NEW EPS SECURITY CONTEXT" ;;
        *) echo "reserved" ;;
    esac
}

# Protocol discriminator — TS 24.007 §11.2.3.1 (Table 11.2.3.1.1).
# A plain `[[ ]] && echo || echo` chain cannot express three cases: bash
# short-circuits on the first successful echo and the later branches never
# run, which is why this is a case statement and not an inline test.
latt_pd_name() {
    case "${1:-}" in
        01) echo "EPS session management" ;;
        02) echo "call control" ;;
        03) echo "supplementary services" ;;
        05) echo "mobility management (2G/3G)" ;;
        06) echo "radio resources management" ;;
        07) echo "EPS mobility management" ;;
        08) echo "GPRS mobility management" ;;
        09) echo "SMS" ;;
        0A) echo "session management (2G/3G)" ;;
        0F) echo "test procedure" ;;
        *)  echo "reserved/unknown" ;;
    esac
}

latt_security_is_plain() { [[ "${1:-}" == "0" ]]; }

# Identity type — TS 24.301 §9.9.3.16 (Table 9.9.3.16.1). NOTE: this table
# is NOT the EPS mobile identity table; value 1 here means IMSI, which is
# the whole point of the identity-exposure check below.
latt_identity_type_name() {
    case "${1:-}" in
        1) echo "IMSI" ;;
        2) echo "IMEI" ;;
        3) echo "IMEISV" ;;
        4) echo "TMSI" ;;
        5) echo "GUTI" ;;
        *) echo "reserved" ;;
    esac
}

# EMM cause carried in an Attach Reject that steers a UE to another RAT.
latt_is_downgrade_cause() {
    case "${1:-}" in
        14|15|12|13|11) return 0 ;;   # PLMN/TA not allowed -> reselect
        *) return 1 ;;
    esac
}

# ── message parsing ─────────────────────────────────────────────────────
#
# Common EMM header, octets 1..3 (TS 24.301 §9.1):
#   octet 1 : EPS bearer identity (high nibble) | security header type (low)
#             For plain EMM messages the high nibble is 0.
#   octet 2 : EPS mobility management protocol discriminator = 0x07 (TS 24.007 §11.2.3.1.4)
#   octet 3 : procedure transaction identity (for ESM) OR message type.
#             Plain EMM signalling carries the message type directly.
latt_parse_nas_header() {
    local hex; hex=$(latt_nfc "${1:-}")
    latt_is_hex "$hex" || { printf 'ERROR\tnot valid hex: %s\n' "$(latt_sanitize "${1:-}")" >&2; return 1; }
    (( ${#hex} >= 6 )) || { printf 'ERROR\tNAS message shorter than the 3-octet header\n' >&2; return 1; }

    local oct1 dec sh
    oct1="${hex:0:2}"; dec=$((16#${oct1}))
    sh=$(( dec & 0x0F ))
    local ebi; ebi=$(printf '%d' $(( dec >> 4 )))
    local pd="${hex:2:2}"
    local mt="${hex:4:2}"

    printf 'octet1\t%s\n'  "$oct1"
    printf 'security_header\t%s\n' "$sh"
    printf 'security_header_name\t%s\n' "$(latt_security_header_name "$sh")"
    printf 'plain\t%s\n' "$([[ "$sh" == "0" ]] && echo yes || echo no)"
    printf 'eps_bearer_identity\t%s\n' "$ebi"
    printf 'protocol_discriminator\t%s\n' "$pd"
    printf 'protocol_discriminator_name\t%s\n' "$(latt_pd_name "$pd")"
    printf 'message_type\t%s\n' "$mt"
    printf 'message_name\t%s\n' "$(latt_msg_type_name "0x$mt")"
    printf 'body\t%s\n' "${hex:6}"
}

# ── Attach Request builder — TS 24.301 §9.9.3.1 ─────────────────────────
#
# Mandatory portion (octets 4..10 for an IMSI-attach):
#   octet 4 : EPS attach type (1) | NAS key set identifier (0b111 if none)
#   octet 5 : EPS mobile identity (IMSI) first octet of the IE
#   octet 6 : length of EPS mobile identity value part = 9
#   octet 7 : type of identity = 1 (IMSI)
#   octets 8..15 : 8 BCD octets of the 15-digit IMSI
#   octet 16: UE network capability IEI = 0x33, then 2-byte length + value
#   ...     : ESM message container IEI = 0x2D (replaces ESM info transfer)
latt_build_attach_request() {
    local imsi="${1:-}" ue_caps="${2:-}" esm="${3:-}" attach_type="${4:-1}"
    local ksi="${5:-7}"

    [[ "$imsi" =~ ^[0-9]{14,15}$ ]] || {
        printf 'ERROR\tIMSI must be 14 or 15 digits: %s\n' "$(latt_sanitize "${imsi:-<none>}")" >&2
        return 1
    }
    [[ "$attach_type" =~ ^[0-9]+$ ]] && (( attach_type >= 0 && attach_type <= 7 )) || {
        printf 'ERROR\tEPS attach type out of range 0..7: %s\n' "$(latt_sanitize "${attach_type}")" >&2
        return 1
    }
    [[ "$ksi" =~ ^[0-9]+$ ]] && (( ksi >= 0 && ksi <= 7 )) || {
        printf 'ERROR\tNAS key set identifier out of range 0..7: %s\n' "$(latt_sanitize "${ksi}")" >&2
        return 1
    }

    # Octet 4: attach type in bits 3-1, KSI in bits 7-5, spare in bits 4/0.
    local oct4; oct4=$(printf '%02X' $(( (ksi << 5) | (attach_type << 1) )))
    # Octet 1: EBI 0 | security header 0. Octet 2: PD 0x07. Octet 3: 0x41.
    local hdr="000741"

    local mob; mob=$(latt_imsi_to_eps_mobile_id "$imsi") || {
        printf 'ERROR\tcould not BCD-encode IMSI\n' >&2; return 1
    }

    local out="${hdr}${oct4}${mob}"

    if [[ -n "$ue_caps" ]]; then
        local c; c=$(latt_nfc "$ue_caps")
        latt_is_hex "$c" || { printf 'ERROR\tUE network capability must be hex\n' >&2; return 1; }
        # 10#  forces decimal: a bare $(( 010 / 2 )) is octal in bash and
        # silently yields 4 instead of 5.
        local clen=$(( 10#${#c} / 2 ))
        out+="33$(printf '%02X' "$clen")${c}"
    fi
    if [[ -n "$esm" ]]; then
        local e; e=$(latt_nfc "$esm")
        latt_is_hex "$e" || { printf 'ERROR\tESM message container must be hex\n' >&2; return 1; }
        # ESM message container is a 2-octet-length TLV (TS 24.301 §9.9.4.16).
        local elen=$(( 10#${#e} / 2 ))
        (( elen <= 65535 )) || { printf 'ERROR\tESM message container too long\n' >&2; return 1; }
        out+="2D$(printf '%04X' "$elen")${e}"
    fi
    printf '%s' "$out"
}

# ── identity-exposure detection ─────────────────────────────────────────
#
# The classic LTE identity exposure: the network sends IDENTITY REQUEST
# asking for the IMSI while the NAS security context is still *null*, i.e.
# the message carries security header type 0 (plain NAS). A UE answers in
# the clear and the IMSI is readable by anyone holding the air interface.
#
# A passive IMSI catcher and a hostile eNB both use this. It is also the
# first message a real MME sends on a fresh attach, which is why the check
# distinguishes "exposed" (plain + IMSI request) from "protected" (the same
# request under an established security context).
latt_identity_exposure() {
    local hex="${1:-}"
    local hdr; hdr=$(latt_parse_nas_header "$hex") || return 1
    local mt sh it
    mt=$(printf '%s\n' "$hdr" | awk -F'\t' '$1=="message_type"{print $2}')
    sh=$(printf '%s\n' "$hdr" | awk -F'\t' '$1=="security_header"{print $2}')
    [[ "$mt" == "53" ]] || {
        printf 'ERROR\tnot an IDENTITY REQUEST (message type 0x%s, %s)\n' \
            "$mt" "$(latt_msg_type_name "0x$mt")" >&2
        return 1
    }
    # Octet 4 of an Identity Request is the identity type IE (octet 5 if a
    # spare half-octet is inserted, which TS 24.301 does not do here).
    local body; body=$(printf '%s\n' "$hdr" | awk -F'\t' '$1=="body"{print $2}')
    it="${body:0:2}"
    local itn; itn=$(latt_identity_type_name "$((16#${it:-0}))")

    printf 'message_type\t%s\n' "$mt"
    printf 'security_header\t%s\n' "$sh"
    printf 'security_context\t%s\n' "$(latt_security_header_name "$sh")"
    printf 'identity_type\t%s\n' "$it"
    printf 'identity_type_name\t%s\n' "$itn"

    if latt_security_is_plain "$sh"; then
        if [[ "$it" == "01" ]]; then
            printf 'exposure\tyes\n'
            printf 'finding\tIMSI requested in a PLAIN (unprotected) NAS message — IMSI transmitted in the clear\n'
            printf 'severity\thigh\n'
            printf 'mitre\tT1589.001 / GSMA FS.11 IMSI catching\n'
            return 0
        fi
        printf 'exposure\tyes\n'
        printf 'finding\t%s requested in a PLAIN NAS message — identity sent in the clear\n' "$itn"
        printf 'severity\tmedium\n'
        return 0
    fi
    printf 'exposure\tno\n'
    printf 'finding\tidentity requested under an established security context (%s) — not exposed\n' \
        "$(latt_security_header_name "$sh")"
    printf 'severity\tnone\n'
    return 0
}

# ── full decode ─────────────────────────────────────────────────────────
latt_decode_nas() {
    local hex="${1:-}"
    local hdr; hdr=$(latt_parse_nas_header "$hex") || return 1
    printf '%s\n' "$hdr"
    local mt body
    mt=$(printf '%s\n' "$hdr" | awk -F'\t' '$1=="message_type"{print $2}')
    body=$(printf '%s\n' "$hdr" | awk -F'\t' '$1=="body"{print $2}')

    case "$mt" in
        41|47)  # ATTACH REQUEST / TAU REQUEST
            local o4 at ksi
            o4="${body:0:2}"
            at=$(( (16#${o4:-0} >> 1) & 0x07 ))
            ksi=$(( (16#${o4:-0} >> 5) & 0x07 ))
            printf 'eps_attach_type\t%s\n' "$at"
            printf 'eps_attach_type_name\t%s\n' "$(latt_attach_type_name "$at")"
            printf 'nas_key_set_identifier\t%s\n' "$ksi"
            printf 'nas_key_set_identifier_name\t%s\n' \
                "$([[ "$ksi" == "7" ]] && echo 'no key available' || echo "KSI $ksi")"
            latt_decode_ies "${body:2}" ;;
        42)  # ATTACH ACCEPT
            local o4
            o4="${body:0:2}"
            printf 'eps_attach_type\t%s\n' "$(( (16#${o4:-0} >> 1) & 0x07 ))"
            printf 'eps_attach_type_name\t%s\n' "$(latt_attach_type_name "$(( (16#${o4:-0} >> 1) & 0x07 ))")"
            printf 'guti\t%s\n' "${body:2:10}"
            latt_decode_ies "${body:12}" ;;
        44|4A) # ATTACH REJECT / TAU REJECT
            local c="${body:0:2}"
            printf 'emm_cause\t%s\n' "$((16#${c:-0}))"
            printf 'emm_cause_name\t%s\n' "$(latt_emm_cause_name "$((16#${c:-0}))")"
            latt_decode_ies "${body:2}" ;;
        45)  # DETACH REQUEST
            local o4 dt
            o4="${body:0:2}"; dt=$(( (16#${o4:-0} >> 1) & 0x07 ))
            printf 'detach_type\t%s\n' "$dt"
            case "$dt" in
                1) printf 'detach_type_name\t%s\n' "EPS detach" ;;
                2) printf 'detach_type_name\t%s\n' "IMSI detach" ;;
                3) printf 'detach_type_name\t%s\n' "combined EPS/IMSI detach" ;;
                4) printf 'detach_type_name\t%s\n' "reserved" ;;
                *) printf 'detach_type_name\t%s\n' "reserved" ;;
            esac
            printf 'ksi\t%s\n' "$(( (16#${o4:-0} >> 5) & 0x07 ))"
            latt_decode_ies "${body:2}" ;;
        4F)  # AUTHENTICATION REQUEST — RAND + AUTN, 16 octets each
            printf 'rand\t%s\n' "${body:0:32}"
            printf 'autn\t%s\n' "${body:32:32}"
            printf 'rand_len\t%s\n' "$(( ${#body} >= 32 ? 16 : ${#body} / 2 ))" ;;
        50)  # AUTHENTICATION RESPONSE — RES
            printf 'res\t%s\n' "${body}"
            printf 'res_len\t%s\n' "$(( ${#body} / 2 ))" ;;
        52)  # AUTHENTICATION FAILURE — cause + optional AUTS
            local c="${body:0:2}"
            printf 'emm_cause\t%s\n' "$((16#${c:-0}))"
            printf 'emm_cause_name\t%s\n' "$(latt_emm_cause_name "$((16#${c:-0}))")"
            [[ -n "${body:2}" ]] && printf 'auts\t%s\n' "${body:2}" ;;
        53)  # IDENTITY REQUEST
            local it="${body:0:2}"
            printf 'identity_type\t%s\n' "$it"
            printf 'identity_type_name\t%s\n' "$(latt_identity_type_name "$((16#${it:-0}))")" ;;
        54)  # IDENTITY RESPONSE
            local mid; mid=$(latt_eps_mobile_id_decode "$body" 2>/dev/null)
            if [[ -n "$mid" ]]; then
                printf 'mobile_identity_type\t%s\n' "$(printf '%s' "$mid" | cut -f1)"
                printf 'mobile_identity\t%s\n'      "$(printf '%s' "$mid" | cut -f2)"
            else
                printf 'mobile_identity_raw\t%s\n' "$body"
            fi ;;
        55)  # SECURITY MODE COMMAND
            local c="${body:0:2}"
            printf 'selected_nas_cipher\t%s\n' "$(( 16#${c:-0} & 0x0F ))"
            printf 'selected_nas_integrity\t%s\n' "$(( (16#${c:-0} >> 4) & 0x0F ))"
            printf 'nas_mac\t%s\n' "${body:2:8}"
            latt_decode_ies "${body:10}" ;;
        56)  # SECURITY MODE COMPLETE
            printf 'nas_mac\t%s\n' "${body:0:8}"
            latt_decode_ies "${body:8}" ;;
        57)  # SECURITY MODE REJECT
            local c="${body:0:2}"
            printf 'emm_cause\t%s\n' "$((16#${c:-0}))"
            printf 'emm_cause_name\t%s\n' "$(latt_emm_cause_name "$((16#${c:-0}))")" ;;
        58)  # EMM STATUS
            local c="${body:0:2}"
            printf 'emm_cause\t%s\n' "$((16#${c:-0}))"
            printf 'emm_cause_name\t%s\n' "$(latt_emm_cause_name "$((16#${c:-0}))")" ;;
        *)   # Unknown/unsupported: report the body honestly rather than guess.
            printf 'body_raw\t%s\n' "$body"
            printf 'decode_note\tno IE walker for message type 0x%s\n' "$mt" ;;
    esac
    return 0
}

# ── IE walker — TS 24.301 §9.9.4 ────────────────────────────────────────
#
# Optional IEs are Type-Value (TV, 1-octet type) or Type-Length-Value
# (TLV, 1-octet type + 1-octet length + value). The first nibble of the
# type distinguishes them in TS 24.007 §11.2.4: format is the *high* half
# of the type octet, and for the EMM messages here the type octet is a
# full octet whose high nibble selects the format.
#
#   0x2D ESM message container          TLV  (TS 24.301 §9.9.4.16)
#   0x33 UE network capability          TLV  (§9.9.4.30)
#   0x53 EPS bearer context status      TLV  (§9.9.4.20)
#   0x52 MS network capability          TLV
#   0x5C TMSI status                    TV   (§9.9.4.28, value 0 or 1 octet)
#   0x0B EPS attach result              TV
#   0x08 EPS mobile identity            TLV
#   0x50 ESM message container (UL)     TLV
#   0x57 EMM cause ... etc.
#
# We walk conservatively: a known TLV consumes type+length+value, a known
# TV consumes type+fixed value, anything else is reported as opaque and
# the walk stops rather than desynchronising.
latt_ie_lengths_tlv() {
    case "${1:-}" in
        0x08|0x2D|0x33|0x50|0x52|0x53|0x17|0x19|0x1A|0x1C|0x2B|0x31|0x34|0x35|0x3A|0x5D) echo "TLV" ;;
        0x0B|0x0C|0x0D|0x0E|0x0F|0x1B|0x1D|0x22|0x23|0x25|0x26|0x27|0x28|0x29|0x2A|0x2C|0x30|0x32|0x36|0x37|0x38|0x39|0x3B|0x3C|0x3D|0x3E|0x3F|0x5C) echo "TV" ;;
        *) echo "?" ;;
    esac
}

latt_ie_name() {
    case "${1:-}" in
        0x08) echo "EPS mobile identity" ;;
        0x0B) echo "EPS attach result" ;;
        0x17) echo "EMM cause" ;;
        0x19) echo "ESM message container (old)" ;;
        0x1A) echo "EPS network feature support" ;;
        0x2D) echo "ESM message container" ;;
        0x33) echo "UE network capability" ;;
        0x52) echo "MS network capability" ;;
        0x53) echo "EPS bearer context status" ;;
        0x50) echo "ESM message container (UL)" ;;
        0x5C) echo "TMSI status" ;;
        0x57) echo "EMM cause (alt)" ;;
        *)    echo "unknown IE" ;;
    esac
}

latt_decode_ies() {
    local body; body=$(latt_nfc "${1:-}")
    (( ${#body} >= 2 )) || return 0
    local off=0 total=$(( ${#body} / 2 ))
    while (( off < total )); do
        local t="${body:$((off*2)):2}"
        local fmt; fmt=$(latt_ie_lengths_tlv "0x$t")
        local tname; tname=$(latt_ie_name "0x$t")
        if [[ "$fmt" == "TLV" ]]; then
            # ESM message container (0x2D, 0x50) is the one EMM IE in this
            # set whose length field is TWO octets — TS 24.301 §9.9.4.16
            # and §9.9.4.17. Reading it as one octet desynchronises the
            # whole walk, so the distinction is load-bearing.
            local lb=1
            case "$t" in 2D|50) lb=2 ;; esac
            (( off + 1 + lb <= total )) || {
                printf 'ie.%d\ttype=0x%s TLV truncated at length field\n' "$off" "$t"; break; }
            local l vlen
            if (( lb == 2 )); then
                l="${body:$(((off+1)*2)):4}"
                vlen=$(( 16#${l:0:2} * 256 + 16#${l:2:2} ))
            else
                l="${body:$(((off+1)*2)):2}"
                vlen=$(( 16#${l:-0} ))
            fi
            local val="${body:$(((off+1+lb)*2)):$((vlen*2))}"
            printf 'ie.%d\ttype=0x%s len=%d %s value=%s\n' "$off" "$t" "$vlen" "$tname" "$val"
            # Some IEs deserve real interpretation rather than a hex dump.
            case "$t" in
                08) local mid; mid=$(latt_eps_mobile_id_decode "$val" 2>/dev/null)
                    [[ -n "$mid" ]] && printf 'ie.%d.decoded\t%s=%s\n' "$off" \
                        "$(printf '%s' "$mid" | cut -f1)" "$(printf '%s' "$mid" | cut -f2)" ;;
                33) printf 'ie.%d.decoded\tue_network_capability=%s\n' "$off" "$val" ;;
                2D|50)
                    # The container holds a whole ESM message with its own
                    # 3-octet header (TS 24.301 §9.2):
                    #   octet 1: EPS bearer identity (high) | PTI (low)
                    #   octet 2: ESM protocol discriminator = 0x02 for a
                    #            plain ESM message (0x01 does not appear here;
                    #            the container's own PD is implied)
                    #   octet 3: ESM message type
                    if (( ${#val} >= 6 )); then
                        local esm_o1="${val:0:2}"
                        printf 'ie.%d.decoded\tesm_ebi=%d esm_pti=%d esm_msg_type=0x%s\n' \
                            "$off" \
                            "$(( 16#$esm_o1 >> 4 ))" \
                            "$(( 16#$esm_o1 & 0x0F ))" \
                            "${val:4:2}"
                    fi ;;
            esac
            off=$(( off + 1 + lb + vlen ))
        elif [[ "$fmt" == "TV" ]]; then
            printf 'ie.%d\ttype=0x%s TV %s value=%s\n' "$off" "$t" "$tname" "${body:$(((off+1)*2)):2}"
            off=$(( off + 2 ))
        else
            printf 'ie.%d\ttype=0x%s opaque (not a known EMM IE) remaining=%s\n' \
                "$off" "$t" "${body:$((off*2))}"
            break
        fi
    done
    return 0
}

# ── identity store ──────────────────────────────────────────────────────
# One row per identity recovered from a decode. Untrusted digits are
# sanitised before they land in the row, same as everything else.
latt_store_identity() {
    local kind="$1" value="$2" src="$3"
    mkdir -p "$LATT_DIR"
    [[ -f "$LATT_IDENT" ]] || printf 'ts\tkind\tvalue\tsource\n' > "$LATT_IDENT"
    printf '%s\t%s\t%s\t%s\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        "$(latt_sanitize "$kind")" "$(latt_sanitize "$value")" "$(latt_sanitize "$src")" \
        >> "$LATT_IDENT"
}

latt_identity_count() {
    [[ -f "$LATT_IDENT" ]] || { echo 0; return; }
    local n; n=$(tail -n +2 "$LATT_IDENT" 2>/dev/null | grep -c . || true)
    echo "${n:-0}"
}

# ── CLI verbs ───────────────────────────────────────────────────────────
latt_cli_status_tsv() {
    local idc; idc=$(latt_identity_count)
    printf 'module\tlte_attach\n'
    printf 'tag\tlatt\n'
    printf 'dir\t%s\n'        "$LATT_DIR"
    printf 'store\t%s\n'      "$LATT_IDENT"
    printf 'identities\t%s\n' "$idc"
    printf 'refs\t%s\n'       "3GPP TS 24.301, TS 23.003"
    printf 'radio_required\tno\n'
}

latt_cmd_imsi_encode() {
    local imsi="${1:-}"
    [[ "$imsi" =~ ^[0-9]{14,15}$ ]] || {
        printf 'ERROR\tIMSI must be 14 or 15 digits: %s\n' "$(latt_sanitize "${imsi:-<none>}")" >&2
        return 2
    }
    local id; id=$(latt_imsi_to_eps_mobile_id "$imsi") || {
        printf 'ERROR\tIMSI encode failed\n' >&2; return 1
    }
    printf 'imsi\t%s\n' "$imsi"
    printf 'digits\t%s\n' "${#imsi}"
    printf 'bcd\t%s\n' "$(latt_bcd_encode_num "$imsi")"
    printf 'eps_mobile_identity\t%s\n' "$id"
    printf 'type_of_identity\t1 (IMSI)\n'
    printf 'length_octet\t%s\n' "$(printf '%d' $((16#${id:2:2})))"
}

latt_cmd_imsi_decode() {
    local val="${1:-}"
    [[ -n "$val" ]] || { printf 'ERROR\tusage: --imsi-decode <hex>\n' >&2; return 2; }
    local out; out=$(latt_eps_mobile_id_decode "$val") || {
        printf 'ERROR\tnot a decodable EPS mobile identity: %s\n' "$(latt_sanitize "$val")" >&2
        return 1
    }
    local kind digits
    kind=$(printf '%s' "$out" | cut -f1)
    digits=$(printf '%s' "$out" | cut -f2)
    printf 'kind\t%s\n' "$kind"
    printf 'digits\t%s\n' "$digits"
    printf 'length\t%s\n' "${#digits}"
    case "$kind" in
        IMSI)
            printf 'mcc\t%s\n' "${digits:0:3}"
            printf 'mnc\t%s\n' "${digits:3:2}"
            printf 'msin\t%s\n' "${digits:5}" ;;
        IMEI)
            printf 'tac\t%s\n' "${digits:0:8}"
            printf 'serial\t%s\n' "${digits:8:6}"
            printf 'check_digit\t%s\n' "${digits:14:1}" ;;
    esac
}

latt_cmd_encode_attach() {
    local imsi="${1:-}" caps="${2:-}" esm="${3:-}"
    [[ -n "$imsi" ]] || {
        printf 'ERROR\tusage: --encode-attach <IMSI> [ue_caps_hex] [esm_hex]\n' >&2
        return 2
    }
    local hex; hex=$(latt_build_attach_request "$imsi" "$caps" "$esm") || return 1
    printf 'imsi\t%s\n' "$imsi"
    printf 'msg_type\t0x41\n'
    printf 'msg_name\t%s\n' "$(latt_msg_type_name 0x41)"
    printf 'nas_hex\t%s\n' "$hex"
    printf 'octets\t%s\n' "$(( ${#hex} / 2 ))"
}

latt_cmd_decode_nas() {
    local hex="${1:-}"
    [[ -n "$hex" ]] || { printf 'ERROR\tusage: --decode-nas <hex>\n' >&2; return 2; }
    latt_decode_nas "$hex" || return 1
}

latt_cmd_identity_exposure() {
    local hex="${1:-}"
    [[ -n "$hex" ]] || { printf 'ERROR\tusage: --identity-exposure <hex>\n' >&2; return 2; }
    local out rc
    out=$(latt_identity_exposure "$hex"); rc=$?
    [[ "$rc" -ne 0 ]] && return "$rc"
    printf '%s\n' "$out"
    # Record the finding so a later report can cite it.
    local exp; exp=$(printf '%s\n' "$out" | awk -F'\t' '$1=="exposure"{print $2}')
    if [[ "$exp" == "yes" ]]; then
        latt_store_identity "identity-request" "plain-nas" "latt:--identity-exposure"
    fi
    return 0
}

# ── hardware guard ──────────────────────────────────────────────────────
# Nothing in this module needs a radio, but a caller may want to know what
# would be required to put these frames on the air. Name the missing tool.
latt_find_lte_ue_stack() {
    local t
    for t in srsue srsran nr-uesoftmodem; do
        command -v "$t" >/dev/null 2>&1 && { echo "$t"; return 0; }
    done
    return 1
}

latt_require_ue_stack() {
    local s; s=$(latt_find_lte_ue_stack) || {
        printf 'ERROR\tno LTE UE stack — install srsRAN (srsue) to transmit NAS frames\n' >&2
        return 1
    }
    printf 'OK\t%s\n' "$s"
}

# ── selftest — no radio, no root, no network ────────────────────────────
latt_selftest() {
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
    export CAPTURES_DIR="$d/captures"
    export STATE_DIR="$d/state"
    export LATT_DIR="$d/loot/lte_attach"
    export LATT_IDENT="$LATT_DIR/identities.tsv"

    # ── 1. BCD primitives, byte-exact ───────────────────────────────────
    # 15-digit IMSI: 8 BCD octets, last high nibble is the 0xF filler.
    chk bcd-enc-15  "$(latt_bcd_encode_num 310150123456789)" "13100521436587F9"
    chk bcd-enc-15-len "$(( $(printf '%s' "$(latt_bcd_encode_num 310150123456789)" | wc -c) / 2 ))" "8"
    # 14-digit (even): 7 BCD octets, no filler.
    chk bcd-enc-14  "$(latt_bcd_encode_num 31015012345678)"  "13100521436587"
    # Leading-zero MNC: 208-01 -> 20801. The zero lands in an odd position
    # and must end up as the lone low nibble of a filler octet (F0 last).
    chk bcd-enc-lead0 "$(latt_bcd_encode_num 208011234567890)" "02081132547698F0"
    chk bcd-dec-15  "$(latt_bcd_decode_num 13100521436587F9)" "310150123456789"
    chk bcd-dec-14  "$(latt_bcd_decode_num 13100521436587)"  "31015012345678"
    # A bare even-length BCD string has no filler nibble to strip. One
    # octet 0x12 = digit1 2 (low nibble), digit2 1 (high) -> "21".
    chk bcd-dec-even-nostrip "$(latt_bcd_decode_num 12)" "21"
    chk bcd-dec-two-octet   "$(latt_bcd_decode_num 1234)" "2143"
    chk bcd-dec-lead0 "$(latt_bcd_decode_num 02081132547698F0)" "208011234567890"
    chk bcd-dec-nonhex "$(latt_bcd_decode_num ZZ >/dev/null 2>&1; echo $?)" "1"

    # ── 2. IMSI/IMEI round-trips over a spread of real-shaped identities ─
    # Covers: odd digit count, even digit count, leading-zero MNC,
    # MCC 310 (US), 208 (FR), 234 (UK), 262 (DE), 460 (CN).
    local imsi
    for imsi in 310150123456789 31015012345678 208011234567890 234150123456789 262011234567890 460001234567890 001010000000001; do
        local enc dec
        enc=$(latt_imsi_to_eps_mobile_id "$imsi")
        dec=$(latt_eps_mobile_id_decode "$enc" | cut -f2)
        chk "imsi-roundtrip-$imsi" "$dec" "$imsi"
    done
    # The encoded IE for a 15-digit IMSI is fixed at 22 hex chars:
    # 08 | 09 | 01 | 8 BCD octets. A 14-digit IMSI drops to 20 chars.
    chk imsi-ie-length "$(printf '%s' "$(latt_imsi_to_eps_mobile_id 310150123456789)" | wc -c)" "22"
    chk imsi-ie-prefix "$(latt_imsi_to_eps_mobile_id 310150123456789)" "08090113100521436587F9"
    chk imei-ie-prefix "$(latt_imei_to_eps_mobile_id 356938035643809)" "08090253968330653408F9"
    # 14 digits -> value part is 1 type octet + 7 BCD octets = length 8.
    chk imsi-ie-14len  "$(printf '%s' "$(latt_imsi_to_eps_mobile_id 31015012345678)" | wc -c)" "20"
    chk imsi-ie-14lenoct "$(latt_imsi_to_eps_mobile_id 31015012345678 | cut -c3-4)" "08"
    chk imsi-ie-15lenoct "$(latt_imsi_to_eps_mobile_id 310150123456789 | cut -c3-4)" "09"
    chk imsi-ie-bad     "$(latt_imsi_to_eps_mobile_id 12345 >/dev/null 2>&1; echo $?)" "1"
    chk imsi-ie-nonnumeric "$(latt_imsi_to_eps_mobile_id 31015012345678A >/dev/null 2>&1; echo $?)" "1"

    # ── 3. Hand-built Attach Request, byte-exact ────────────────────────
    # 00 07 41        header (EBI 0 | plain, PD 0x07 EMM, MT 0x41)
    # E2              octet 4: attach type 1 (EPS attach) << 1 | KSI 7 << 5
    #                 0b1110_0010 = 0xE2
    # 08 09 01 <8>    EPS mobile identity, IMSI, length 9, type 1
    local ar
    ar=$(latt_build_attach_request 310150123456789)
    chk attach-octets   "$(( ${#ar} / 2 ))" "15"
    chk attach-hex      "$ar" "000741E208090113100521436587F9"
    chk attach-mt       "${ar:4:2}" "41"
    chk attach-pd       "${ar:2:2}" "07"
    chk attach-sh       "${ar:0:2}" "00"
    chk attach-oct4     "${ar:6:2}" "E2"

    # With UE network capability (IEI 0x33) and an ESM container (IEI 0x2D).
    # 0xE0 0xE0 is a commonly seen 2-octet UE network capability
    # (EEA0/EEA1/EIA0/EIA2 style bitmask); the ESM container carries a
    # PDN CONNECTIVITY REQUEST (PD 0x02, PTI 0x01, MT 0xD0, ...).
    # The ESM message container length is TWO octets (0x0005), not one.
    ar=$(latt_build_attach_request 310150123456789 E0E0 0201D00128)
    chk attach-caps-hex "$ar" "000741E208090113100521436587F93302E0E02D00050201D00128"
    chk attach-caps-iei "$(printf '%s' "$ar" | grep -o '3302E0E0' | head -1)" "3302E0E0"
    chk attach-esm-iei  "$(printf '%s' "$ar" | grep -o '2D00050201D00128' | head -1)" "2D00050201D00128"
    # Regression guard for the octal-length bug: bash parses $((010/2)) as
    # octal, so a 5-octet payload used to encode as 0x0004 not 0x0005.
    chk attach-esm-len5   "$(latt_build_attach_request 310150123456789 '' 0201D00128 | grep -o '2D[0-9A-F]\{4\}' | head -1)" "2D0005"
    chk attach-esm-len6   "$(latt_build_attach_request 310150123456789 '' 0201D0012800 | grep -o '2D[0-9A-F]\{4\}' | head -1)" "2D0006"
    chk attach-esm-len300 "$(latt_build_attach_request 310150123456789 '' "$(printf 'AB%.0s' $(seq 1 300))" | grep -o '2D[0-9A-F]\{4\}' | head -1)" "2D012C"
    chk attach-bad-imsi "$(latt_build_attach_request abc >/dev/null 2>&1; echo $?)" "1"
    chk attach-bad-type "$(latt_build_attach_request 310150123456789 '' '' 9 >/dev/null 2>&1; echo $?)" "1"
    chk attach-bad-ksi  "$(latt_build_attach_request 310150123456789 '' '' 1 9 >/dev/null 2>&1; echo $?)" "1"

    # ── 4. Header parsing: message type and security header ─────────────
    out=$(latt_parse_nas_header "000741E208090113100521436587F9")
    chk hdr-mt       "$(fld "$out" message_type)" "41"
    chk hdr-mt-name  "$(fld "$out" message_name)" "ATTACH REQUEST"
    chk hdr-sh       "$(fld "$out" security_header)" "0"
    chk hdr-sh-name  "$(fld "$out" security_header_name)" "PLAIN NAS"
    chk hdr-plain    "$(fld "$out" plain)" "yes"
    chk hdr-pd       "$(fld "$out" protocol_discriminator)" "07"
    chk hdr-ebi      "$(fld "$out" eps_bearer_identity)" "0"

    # A protected message: octet 1 = 0x27 -> EBI 2, security header 7?
    # No: security header type occupies the low nibble, and 0x01 is
    # INTEGRITY PROTECTED. Use EBI 0, SH 1 -> octet 1 = 0x01.
    out=$(latt_parse_nas_header "0107530001")
    chk hdr2-sh      "$(fld "$out" security_header)" "1"
    chk hdr2-sh-name "$(fld "$out" security_header_name)" "INTEGRITY PROTECTED"
    chk hdr2-plain   "$(fld "$out" plain)" "no"
    chk hdr2-mt      "$(fld "$out" message_type)" "53"
    # EBI is the high nibble: 0x21 -> EBI 2, SH 1.
    out=$(latt_parse_nas_header "2107530001")
    chk hdr3-ebi     "$(fld "$out" eps_bearer_identity)" "2"
    chk hdr3-sh      "$(fld "$out" security_header)" "1"

    chk hdr-short    "$(latt_parse_nas_header 0007 >/dev/null 2>&1; echo $?)" "1"
    chk hdr-nonhex   "$(latt_parse_nas_header ZZYY >/dev/null 2>&1; echo $?)" "1"
    chk hdr-oddlen   "$(latt_parse_nas_header 00074 >/dev/null 2>&1; echo $?)" "1"

    # ── 5. Identity exposure: the classic finding ───────────────────────
    # 00 07 53 01 = plain NAS (SH 0) IDENTITY REQUEST asking for IMSI.
    out=$(latt_identity_exposure "00075301"); rc=$?
    chk exposure-rc         "$rc" "0"
    chk exposure-flag       "$(fld "$out" exposure)" "yes"
    chk exposure-type       "$(fld "$out" identity_type_name)" "IMSI"
    chk exposure-severity   "$(fld "$out" severity)" "high"
    chk exposure-sh         "$(fld "$out" security_header)" "0"

    # Same request, but under an established security context
    # (SH 1 = integrity protected) MUST NOT be flagged.
    out=$(latt_identity_exposure "01075301"); rc=$?
    chk protected-rc        "$rc" "0"
    chk protected-flag      "$(fld "$out" exposure)" "no"
    chk protected-severity  "$(fld "$out" severity)" "none"
    chk protected-sh        "$(fld "$out" security_header)" "1"

    # SH 2 (integrity protected + new EPS security context) likewise.
    out=$(latt_identity_exposure "02075301")
    chk protected2-flag     "$(fld "$out" exposure)" "no"

    # A plain IMEI request is still an exposure, but medium severity.
    out=$(latt_identity_exposure "00075302")
    chk exposure-imei-flag  "$(fld "$out" exposure)" "yes"
    chk exposure-imei-name  "$(fld "$out" identity_type_name)" "IMEI"
    chk exposure-imei-sev   "$(fld "$out" severity)" "medium"

    # A non-Identity-Request message is a hard error, not a silent "no".
    chk exposure-wrong-mt   "$(latt_identity_exposure "00074101" >/dev/null 2>&1; echo $?)" "1"
    chk exposure-bad-hex    "$(latt_identity_exposure "nothex" >/dev/null 2>&1; echo $?)" "1"

    # ── 6. Full decode of several message types ─────────────────────────
    out=$(latt_decode_nas "000741E208090113100521436587F9")
    chk dec-attach-mt    "$(fld "$out" message_name)" "ATTACH REQUEST"
    chk dec-attach-type  "$(fld "$out" eps_attach_type_name)" "EPS attach"
    chk dec-attach-ksi   "$(fld "$out" nas_key_set_identifier)" "7"

    # Attach reject, cause 15 = "No suitable cells in tracking area".
    out=$(latt_decode_nas "0007440F")
    chk dec-reject-name  "$(fld "$out" message_name)" "ATTACH REJECT"
    chk dec-reject-cause "$(fld "$out" emm_cause)" "15"
    chk dec-reject-cname "$(fld "$out" emm_cause_name)" "No suitable cells in tracking area"

    # Attach reject, cause 2 = "IMSI unknown in HSS".
    out=$(latt_decode_nas "00074402")
    chk dec-reject2 "$(fld "$out" emm_cause_name)" "IMSI unknown in HSS"

    # Authentication request: RAND(16) || AUTN(16), fixed by TS 33.401.
    local rand="000102030405060708090A0B0C0D0E0F"
    local autn="101112131415161718191A1B1C1D1E1F"
    out=$(latt_decode_nas "00074F${rand}${autn}")
    chk dec-auth-mt   "$(fld "$out" message_name)" "AUTHENTICATION REQUEST"
    chk dec-auth-rand "$(fld "$out" rand)" "$rand"
    chk dec-auth-autn "$(fld "$out" autn)" "$autn"
    chk dec-auth-rlen "$(fld "$out" rand_len)" "16"

    # Authentication response carrying an 8-octet RES.
    out=$(latt_decode_nas "000750A1A2A3A4A5A6A7A8")
    chk dec-res     "$(fld "$out" res)" "A1A2A3A4A5A6A7A8"
    chk dec-res-len "$(fld "$out" res_len)" "8"

    # Security mode command: cipher 2 (128-EEA2), integrity 2 (128-EIA2),
    # i.e. octet 4 = 0x22.
    out=$(latt_decode_nas "00075522000000000000")
    chk dec-smc-cipher "$(fld "$out" selected_nas_cipher)" "2"
    chk dec-smc-integ  "$(fld "$out" selected_nas_integrity)" "2"
    chk dec-smc-mac    "$(fld "$out" nas_mac)" "00000000"

    # Security mode complete under integrity protection (SH 1).
    out=$(latt_decode_nas "0107561122334455")
    chk dec-smc-done-mt  "$(fld "$out" message_name)" "SECURITY MODE COMPLETE"
    chk dec-smc-done-mac "$(fld "$out" nas_mac)" "11223344"

    # Detach request, type 1 = EPS detach.
    out=$(latt_decode_nas "00074502")
    chk dec-detach-mt   "$(fld "$out" message_name)" "DETACH REQUEST"
    chk dec-detach-type "$(fld "$out" detach_type_name)" "EPS detach"

    # Identity response carrying an IMSI as EPS mobile identity.
    out=$(latt_decode_nas "00075408090113100521436587F9")
    chk dec-idresp-mt   "$(fld "$out" message_name)" "IDENTITY RESPONSE"
    chk dec-idresp-type "$(fld "$out" mobile_identity_type)" "IMSI"
    chk dec-idresp-imsi "$(fld "$out" mobile_identity)" "310150123456789"

    # TAU request (0x47) uses the same leading octet layout as attach.
    out=$(latt_decode_nas "000747E208090113100521436587F9")
    chk dec-tau-mt   "$(fld "$out" message_name)" "TRACKING AREA UPDATE REQUEST"
    chk dec-tau-type "$(fld "$out" eps_attach_type_name)" "EPS attach"

    chk dec-bad-hex   "$(latt_decode_nas zz >/dev/null 2>&1; echo $?)" "1"
    chk dec-empty     "$(latt_cmd_decode_nas '' >/dev/null 2>&1; echo $?)" "2"

    # ── 7. IE walker over a TLV and a grouped body ──────────────────────
    # Body: 08 09 01 <8 BCD> | 33 02 E0E0 | 2D 05 0201D00128
    out=$(latt_decode_ies "08090113100521436587F93302E0E02D00050201D00128")
    chk iewalk-count   "$(printf '%s\n' "$out" | awk -F'\t' '$1 ~ /^ie\.[0-9]+$/' | grep -c .)" "3"
    chk iewalk-decoded "$(printf '%s\n' "$out" | awk -F'\t' '$1 ~ /\.decoded$/' | grep -c .)" "3"
    # The ESM container is a 2-octet-length TLV: reading it as 1 octet
    # desynchronises the walk, so assert the decoded ESM header too.
    chk iewalk-esm "$(printf '%s\n' "$out" | awk -F'\t' '$1=="ie.15.decoded"{print $2}')" \
        "esm_ebi=0 esm_pti=2 esm_msg_type=0xD0"
    chk iewalk-esm-len "$(printf '%s\n' "$out" | awk -F'\t' '$1=="ie.15"{print $2}' | grep -o 'len=[0-9]*')" "len=5"
    # A 300-octet ESM container must still walk in one step.
    chk iewalk-big-esm "$(latt_decode_ies "2D012C$(printf 'AB%.0s' $(seq 1 300))" | awk -F'\t' '$1 ~ /^ie\.[0-9]+$/' | grep -c .)" "1"
    chk iewalk-id      "$(printf '%s\n' "$out" | grep '^ie\.0.decoded' | cut -f2)" "IMSI=310150123456789"
    chk iewalk-tlv2    "$(printf '%s\n' "$out" | grep -c 'type=0x33')" "1"
    chk iewalk-tlv3    "$(printf '%s\n' "$out" | grep -c 'type=0x2D')" "1"
    # An unknown octet must stop the walk rather than desynchronise.
    out=$(latt_decode_ies "FFFF")
    chk iewalk-opaque  "$(printf '%s\n' "$out" | grep -c 'opaque')" "1"
    # Empty body is not an error.
    chk iewalk-empty   "$(latt_decode_ies '' >/dev/null 2>&1; echo $?)" "0"

    # ── 8. Assigned-number classification ───────────────────────────────
    chk cause-2   "$(latt_emm_cause_name 2)"   "IMSI unknown in HSS"
    chk cause-15  "$(latt_emm_cause_name 15)"  "No suitable cells in tracking area"
    chk cause-22  "$(latt_emm_cause_name 22)"  "Congestion"
    chk cause-unk "$(latt_emm_cause_name 200)" "unassigned"
    chk mt-41     "$(latt_msg_type_name 0x41)" "ATTACH REQUEST"
    chk mt-53     "$(latt_msg_type_name 0x53)" "IDENTITY REQUEST"
    chk mt-55     "$(latt_msg_type_name 0x55)" "SECURITY MODE COMMAND"
    chk mt-unk    "$(latt_msg_type_name 0xFE)" "unknown"
    chk idt-1     "$(latt_identity_type_name 1)" "IMSI"
    chk idt-5     "$(latt_identity_type_name 5)" "GUTI"
    chk sh-0      "$(latt_security_header_name 0)" "PLAIN NAS"
    # The PD name must be a single line: an inline &&/|| chain here used to
    # emit two rows and corrupt the TSV.
    chk pd-07     "$(latt_pd_name 07)" "EPS mobility management"
    chk pd-02     "$(latt_pd_name 02)" "call control"
    chk pd-01     "$(latt_pd_name 01)" "EPS session management"
    chk pd-unk    "$(latt_pd_name FF)" "reserved/unknown"
    chk pd-lines  "$(latt_parse_nas_header 000741E2 | grep -c '^protocol_discriminator_name')" "1"
    chk sh-1      "$(latt_security_header_name 1)" "INTEGRITY PROTECTED"
    chk att-1     "$(latt_attach_type_name 1)" "EPS attach"
    chk att-2     "$(latt_attach_type_name 2)" "combined EPS/IMSI attach"
    chk att-3     "$(latt_attach_type_name 3)" "EPS emergency attach"

    # ── 9. Verb validation returns non-zero ─────────────────────────────
    chk v-imsi-enc-missing "$(latt_cmd_imsi_encode >/dev/null 2>&1; echo $?)" "2"
    chk v-imsi-enc-bad     "$(latt_cmd_imsi_encode 1234 >/dev/null 2>&1; echo $?)" "2"
    chk v-imsi-dec-missing "$(latt_cmd_imsi_decode >/dev/null 2>&1; echo $?)" "2"
    chk v-imsi-dec-bad     "$(latt_cmd_imsi_decode 0809FF >/dev/null 2>&1; echo $?)" "1"
    chk v-enc-missing      "$(latt_cmd_encode_attach >/dev/null 2>&1; echo $?)" "2"
    chk v-enc-bad-imsi     "$(latt_cmd_encode_attach 42 >/dev/null 2>&1; echo $?)" "1"
    chk v-dec-missing      "$(latt_cmd_decode_nas >/dev/null 2>&1; echo $?)" "2"
    chk v-dec-bad          "$(latt_cmd_decode_nas 0007 >/dev/null 2>&1; echo $?)" "1"
    chk v-exp-missing      "$(latt_cmd_identity_exposure >/dev/null 2>&1; echo $?)" "2"
    chk v-exp-wrong-mt     "$(latt_cmd_identity_exposure 00074101 >/dev/null 2>&1; echo $?)" "1"
    chk v-cli-unknown      "$(latt_cli_main --nope >/dev/null 2>&1; echo $?)" "2"
    chk v-ue-stack-absent  "$(latt_require_ue_stack >/dev/null 2>&1; echo $?)" "$([[ -n "$(latt_find_lte_ue_stack || true)" ]] && echo 0 || echo 1)"

    # ── 10. Verb output shape ───────────────────────────────────────────
    out=$(latt_cmd_imsi_encode 310150123456789); rc=$?
    chk v-enc-rc   "$rc" "0"
    chk v-enc-hex  "$(fld "$out" eps_mobile_identity)" "08090113100521436587F9"
    chk v-enc-bcd  "$(fld "$out" bcd)" "13100521436587F9"
    out=$(latt_cmd_imsi_decode 08090113100521436587F9)
    chk v-dec-mcc  "$(fld "$out" mcc)" "310"
    chk v-dec-mnc  "$(fld "$out" mnc)" "15"
    chk v-dec-msin "$(fld "$out" msin)" "0123456789"
    out=$(latt_cmd_imsi_decode 08090102081132547698F0)
    chk v-dec2-mnc "$(fld "$out" mnc)" "01"
    out=$(latt_cmd_encode_attach 310150123456789)
    chk v-att-rc   "$rc" "0"
    chk v-att-hex  "$(fld "$out" nas_hex)" "000741E208090113100521436587F9"
    out=$(latt_cmd_decode_nas 00075301)
    chk v-dec-nas-mt "$(fld "$out" message_name)" "IDENTITY REQUEST"

    # ── 11. Identity store round-trip ───────────────────────────────────
    latt_store_identity IMSI 310150123456789 selftest
    latt_store_identity IMEI 356938035643809 selftest
    chk store-count   "$(latt_identity_count)" "2"
    chk store-header  "$(grep -c '^ts' "$LATT_IDENT")" "1"

    # ── 12. Status TSV contract ─────────────────────────────────────────
    out=$(latt_cli_status_tsv)
    chk status-tag   "$(fld "$out" tag)" "latt"
    chk status-dir   "$(fld "$out" dir)" "$LATT_DIR"
    chk status-ident "$(fld "$out" identities)" "2"
    chk status-radio "$(fld "$out" radio_required)" "no"

    # ── 13. TSV sanitisation: a tab in an untrusted field cannot forge a row
    chk san-tab "$(latt_sanitize $'a\tb')" "a b"
    chk san-nl  "$(latt_sanitize $'a\nb')" "a b"
    chk san-cr  "$(latt_sanitize $'a\rb')" "a b"

    rm -rf "$d"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ── menu ────────────────────────────────────────────────────────────────
latt_menu() {
    while true; do
        banner
        echo -e "  ${C_MAG}=== LTE Attach / NAS ===${C_RESET}"
        echo -e "  ue stack: ${C_GRN}$(latt_find_lte_ue_stack || echo none)${C_RESET}"
        echo -e "  ids:      ${C_GRN}$(latt_identity_count)${C_RESET}"
        echo -e "  store:    ${C_DIM}$LATT_IDENT${C_RESET}\n"
        cat << 'M'
  [1]  encode an Attach Request from an IMSI
  [2]  decode a NAS message (hex)
  [3]  IMSI -> EPS mobile identity (BCD)
  [4]  EPS mobile identity -> IMSI
  [5]  check a NAS message for identity exposure
  [6]  list recovered identities
  [7]  status
  [0]  back

M
        read -rp "  choice> " c || return 0  # EOF: leave the menu cleanly
        case "$c" in
            1)
                if [[ -n "${IMSISTING_CLI:-}" ]]; then
                    echo "[-] need an IMSI; cannot prompt in CLI mode" >&2
                else
                    read -rp "  IMSI (14-15 digits)> " i
                    latt_cmd_encode_attach "$i" | column -t -s$'\t' 2>/dev/null || latt_cmd_encode_attach "$i"
                    read -rp "  press enter " _
                fi ;;
            2)
                if [[ -n "${IMSISTING_CLI:-}" ]]; then
                    echo "[-] need hex; cannot prompt in CLI mode" >&2
                else
                    read -rp "  NAS hex> " h
                    latt_cmd_decode_nas "$h" | column -t -s$'\t' 2>/dev/null || latt_cmd_decode_nas "$h"
                    read -rp "  press enter " _
                fi ;;
            3)
                if [[ -n "${IMSISTING_CLI:-}" ]]; then
                    echo "[-] need an IMSI; cannot prompt in CLI mode" >&2
                else
                    read -rp "  IMSI> " i
                    latt_cmd_imsi_encode "$i" | column -t -s$'\t' 2>/dev/null || latt_cmd_imsi_encode "$i"
                    read -rp "  press enter " _
                fi ;;
            4)
                if [[ -n "${IMSISTING_CLI:-}" ]]; then
                    echo "[-] need hex; cannot prompt in CLI mode" >&2
                else
                    read -rp "  EPS mobile identity hex> " h
                    latt_cmd_imsi_decode "$h" | column -t -s$'\t' 2>/dev/null || latt_cmd_imsi_decode "$h"
                    read -rp "  press enter " _
                fi ;;
            5)
                if [[ -n "${IMSISTING_CLI:-}" ]]; then
                    echo "[-] need hex; cannot prompt in CLI mode" >&2
                else
                    read -rp "  NAS hex> " h
                    latt_cmd_identity_exposure "$h" | column -t -s$'\t' 2>/dev/null || true
                    read -rp "  press enter " _
                fi ;;
            6)
                if [[ "$(latt_identity_count)" -eq 0 ]]; then
                    warn "no identities recovered yet"
                else
                    column -t -s$'\t' < "$LATT_IDENT" 2>/dev/null || cat "$LATT_IDENT"
                fi
                read -rp "  press enter " _ ;;
            7) latt_cli_status_tsv | column -t -s$'\t' 2>/dev/null || latt_cli_status_tsv
               read -rp "  press enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ── CLI dispatch ────────────────────────────────────────────────────────
latt_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)       latt_cli_status_tsv ;;
        --decode-nas)       latt_cmd_decode_nas "${1:-}" ;;
        --encode-attach)    latt_cmd_encode_attach "${1:-}" "${2:-}" "${3:-}" ;;
        --imsi-encode)      latt_cmd_imsi_encode "${1:-}" ;;
        --imsi-decode)      latt_cmd_imsi_decode "${1:-}" ;;
        --identity-exposure) latt_cmd_identity_exposure "${1:-}" ;;
        --ue-stack)         latt_require_ue_stack ;;
        --selftest)         latt_selftest ;;
        --menu)             latt_menu ;;
        *)
            cat >&2 <<EOF
LTE Attach / NAS — EPS Mobility Management encode and decode (TS 24.301)

Usage: $0 COMMAND
  --status-tsv                 module state as TSV
  --decode-nas <hex>           parse an EMM message header and its IEs
  --encode-attach <IMSI> [CAPS_HEX] [ESM_HEX]
                               build a byte-exact Attach Request
  --imsi-encode <IMSI>         IMSI -> EPS mobile identity (BCD, TS 23.003)
  --imsi-decode <hex>          EPS mobile identity -> IMSI / IMEI / GUTI
  --identity-exposure <hex>    flag a plain-NAS IDENTITY REQUEST for IMSI
  --ue-stack                   report the LTE UE stack, by name if absent
  --selftest                   verify the codecs without a radio
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
    latt_cli_main "$@"
fi
