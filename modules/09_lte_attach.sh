#!/usr/bin/env bash
# LTE Attach Forge — EPS Mobility Management (EMM) encode/decode
#
# The NAS layer is pure protocol: everything here is computed from 3GPP
# TS 24.301, so it is performed for real with no radio, no root and no
# network. Nothing in this module is a plan — see 11_lte_core.sh for the
# vectors that genuinely need a lab EPC.
#
# The middle of an attach is built here too (R4): --setup-complete wraps a NAS
# PDU in the RRCConnectionSetupComplete a handset sends on UL-DCCH, and
# --nas-responder holds the attach state across the UE's own messages, reading
# the identity the subscriber states and answering with the network's next
# message wherever this tree can encode one honestly. The RRC encoding lives in
# tools/lte_rrc.py and the downlink NAS bytes come from 32_nas_signaling, so
# neither layer is implemented twice.
#
# The message-type table is TS 24.301 §9.9.2.0 as tshark names it. It was
# shifted by one from 0x4B upward before R4, which read a tracking-area update
# request as a tracking-area update accept; --selftest now pins the values.
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
#   type = 0b110 (6)  GUTI       value = PLMN(3) | MME group id(2) |
#                                MME code(1) | M-TMSI(4)   -- the order
#                                tshark reads: 00 F1 10 12 34 56 DE AD BE EF
#                                is 001/01, group 4660, code 86, M-TMSI
#                                0xDEADBEEF. The type octet is 0xF6: bits 3-1
#                                hold 110 and bit 4 is the odd/even indicator.
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
    local code="${1:-}"
    code="${code#0x}"; code="${code#0X}"
    code="0x${code^^}"
    # TS 24.301 §9.8.1, as tshark 4.2.2 names the same values in its nas-eps
    # table (tools/nas-oracle/check_nas_built.py pins the builder against it).
    # The gaps are real: 0x47 and 0x57..0x5B are not assigned, and this table
    # says "unassigned" rather than inventing a name for them.
    case "$code" in
        0x41) echo "ATTACH REQUEST" ;;
        0x42) echo "ATTACH ACCEPT" ;;
        0x43) echo "ATTACH COMPLETE" ;;
        0x44) echo "ATTACH REJECT" ;;
        0x45) echo "DETACH REQUEST" ;;
        0x46) echo "DETACH ACCEPT" ;;
        0x48) echo "TRACKING AREA UPDATE REQUEST" ;;
        0x49) echo "TRACKING AREA UPDATE ACCEPT" ;;
        0x4A) echo "TRACKING AREA UPDATE COMPLETE" ;;
        0x4B) echo "TRACKING AREA UPDATE REJECT" ;;
        0x4C) echo "EXTENDED SERVICE REQUEST" ;;
        0x4D) echo "CONTROL PLANE SERVICE REQUEST" ;;
        0x4E) echo "SERVICE REJECT" ;;
        0x4F) echo "SERVICE ACCEPT" ;;
        0x50) echo "GUTI REALLOCATION COMMAND" ;;
        0x51) echo "GUTI REALLOCATION COMPLETE" ;;
        0x52) echo "AUTHENTICATION REQUEST" ;;
        0x53) echo "AUTHENTICATION RESPONSE" ;;
        0x54) echo "AUTHENTICATION REJECT" ;;
        0x55) echo "IDENTITY REQUEST" ;;
        0x56) echo "IDENTITY RESPONSE" ;;
        0x5C) echo "AUTHENTICATION FAILURE" ;;
        0x5D) echo "SECURITY MODE COMMAND" ;;
        0x5E) echo "SECURITY MODE COMPLETE" ;;
        0x5F) echo "SECURITY MODE REJECT" ;;
        0x60) echo "EMM STATUS" ;;
        0x61) echo "EMM INFORMATION" ;;
        0x62) echo "DOWNLINK NAS TRANSPORT" ;;
        0x63) echo "UPLINK NAS TRANSPORT" ;;
        0x64) echo "CS SERVICE NOTIFICATION" ;;
        0x68) echo "DOWNLINK GENERIC NAS TRANSPORT" ;;
        0x69) echo "UPLINK GENERIC NAS TRANSPORT" ;;
        0x47|0x57|0x58|0x59|0x5A|0x5B) echo "unassigned" ;;
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
# The NAS header is TWO octets for mobility management and three for session
# management, and this module had it as three for both until a referee said
# otherwise (TS 24.301 §9.3.1, checked against tshark's NAS-EPS dissector):
#
#   EMM (PD 0x07): octet 1 = security header type (bits 8-5) | protocol
#                  discriminator (bits 4-1); octet 2 = message type.
#   ESM (PD 0x02): octet 1 = EPS bearer identity (bits 8-5) | protocol
#                  discriminator (bits 4-1); octet 2 = procedure transaction
#                  identity; octet 3 = message type.
#
# So an Attach Request opens `07 41` -- not `00 07 41`. The extra leading
# octet this module used to write put the discriminator where a dissector
# expects the security header, and put the message type one octet late; the
# only thing that agreed with it was this module's own decoder, which is what
# a shared mistake looks like.
latt_parse_nas_header() {
    local hex; hex=$(latt_nfc "${1:-}")
    latt_is_hex "$hex" || { printf 'ERROR\tnot valid hex: %s\n' "$(latt_sanitize "${1:-}")" >&2; return 1; }
    (( ${#hex} >= 4 )) || { printf 'ERROR\tNAS message shorter than a two-octet header\n' >&2; return 1; }

    local oct1 pd high mt body pti=""
    oct1=$(( 16#${hex:0:2} ))
    pd=$(( oct1 & 0x0F ))          # protocol discriminator: the LOW nibble
    high=$(( (oct1 >> 4) & 0x0F )) # security header type (EMM) or bearer id (ESM)

    if (( pd == 2 )); then
        # EPS session management: bearer identity, PTI, then the message type.
        (( ${#hex} >= 6 )) || { printf 'ERROR\tESM message shorter than a three-octet header\n' >&2; return 1; }
        pti=$(printf '%02X' $(( 16#${hex:2:2} )))
        mt=${hex:4:2}
        body=${hex:6}
    else
        mt=${hex:2:2}
        body=${hex:4}
    fi

    printf 'octet1\t%02X\n' "$oct1"
    if (( pd == 2 )); then
        printf 'eps_bearer_identity\t%s\n' "$high"
        printf 'procedure_transaction_identity\t%s\n' "$pti"
    else
        printf 'security_header\t%s\n' "$high"
        printf 'security_header_name\t%s\n' "$(latt_security_header_name "$high")"
        printf 'plain\t%s\n' "$([[ "$high" == "0" ]] && echo yes || echo no)"
    fi
    printf 'protocol_discriminator\t%02X\n' "$pd"
    printf 'protocol_discriminator_name\t%s\n' "$(latt_pd_name "$(printf '%02X' "$pd")")"
    printf 'message_type\t%s\n' "$mt"
    printf 'message_name\t%s\n' "$(latt_msg_type_name "0x$mt")"
    printf 'body\t%s\n' "$body"
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
    # Octet 1: security header 0 | PD 0x07.  Octet 2: message type 0x41.
    # Two octets, not three -- see the header note above.
    local hdr="0741"

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
    [[ "$mt" == "55" ]] || {
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
        41|48)  # ATTACH REQUEST / TAU REQUEST
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
        42|49)  # ATTACH ACCEPT / TAU ACCEPT
            local o4
            o4="${body:0:2}"
            printf 'eps_attach_type\t%s\n' "$(( (16#${o4:-0} >> 1) & 0x07 ))"
            printf 'eps_attach_type_name\t%s\n' "$(latt_attach_type_name "$(( (16#${o4:-0} >> 1) & 0x07 ))")"
            printf 'guti\t%s\n' "${body:2:10}"
            latt_decode_ies "${body:12}" ;;
        44|4B) # ATTACH REJECT / TAU REJECT
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
        52)  # AUTHENTICATION REQUEST — RAND + AUTN, 16 octets each
            printf 'rand\t%s\n' "${body:0:32}"
            printf 'autn\t%s\n' "${body:32:32}"
            printf 'rand_len\t%s\n' "$(( ${#body} >= 32 ? 16 : ${#body} / 2 ))" ;;
        53)  # AUTHENTICATION RESPONSE — RES
            printf 'res\t%s\n' "${body}"
            printf 'res_len\t%s\n' "$(( ${#body} / 2 ))" ;;
        5C)  # AUTHENTICATION FAILURE — cause + optional AUTS
            local c="${body:0:2}"
            printf 'emm_cause\t%s\n' "$((16#${c:-0}))"
            printf 'emm_cause_name\t%s\n' "$(latt_emm_cause_name "$((16#${c:-0}))")"
            [[ -n "${body:2}" ]] && printf 'auts\t%s\n' "${body:2}" ;;
        55)  # IDENTITY REQUEST
            local it="${body:0:2}"
            printf 'identity_type\t%s\n' "$it"
            printf 'identity_type_name\t%s\n' "$(latt_identity_type_name "$((16#${it:-0}))")" ;;
        56)  # IDENTITY RESPONSE
            local mid; mid=$(latt_eps_mobile_id_decode "$body" 2>/dev/null)
            if [[ -n "$mid" ]]; then
                printf 'mobile_identity_type\t%s\n' "$(printf '%s' "$mid" | cut -f1)"
                printf 'mobile_identity\t%s\n'      "$(printf '%s' "$mid" | cut -f2)"
            else
                printf 'mobile_identity_raw\t%s\n' "$body"
            fi ;;
        5D)  # SECURITY MODE COMMAND
            local c="${body:0:2}"
            printf 'selected_nas_cipher\t%s\n' "$(( 16#${c:-0} & 0x0F ))"
            printf 'selected_nas_integrity\t%s\n' "$(( (16#${c:-0} >> 4) & 0x0F ))"
            printf 'nas_mac\t%s\n' "${body:2:8}"
            latt_decode_ies "${body:10}" ;;
        5E)  # SECURITY MODE COMPLETE
            printf 'nas_mac\t%s\n' "${body:0:8}"
            latt_decode_ies "${body:8}" ;;
        5F)  # SECURITY MODE REJECT
            local c="${body:0:2}"
            printf 'emm_cause\t%s\n' "$((16#${c:-0}))"
            printf 'emm_cause_name\t%s\n' "$(latt_emm_cause_name "$((16#${c:-0}))")" ;;
        60)  # EMM STATUS
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

# ── RRCConnectionSetupComplete: the door the attach walks through ───────
#
# A UE answers RRCConnectionSetup with an RRCConnectionSetupComplete whose
# dedicatedInfoNAS carries its FIRST NAS PDU -- in practice the attach request
# or the identity it was asked for.  Building and reading that container is the
# missing middle between "a cell exists" and "a subscriber answered": everything
# 16_sim, 14_suci and 18_imsi_exposure want arrives inside it.
#
# The RRC half is not encoded here.  tools/lte_rrc.py owns the TS 36.331
# unaligned-PER layout, including the UL-DCCH envelope, and this module only
# names the fields; a second encoder is how the two would drift apart.
LATT_RRC_TOOL="$IMSISTING_ROOT/tools/lte_rrc.py"

latt_rrc_tool() {
    [[ -f "$LATT_RRC_TOOL" ]] || {
        printf 'ERROR\ttools/lte_rrc.py is missing, so no RRC message can be built\n' >&2
        return 1; }
    command -v python3 >/dev/null 2>&1 || {
        printf 'ERROR\tpython3 is missing, so tools/lte_rrc.py cannot run\n' >&2
        return 1; }
}

latt_cmd_setup_complete() {
    local nas="" plmn="1" tx="0"
    while (( $# > 0 )); do
        case "${1:-}" in
            --plmn) plmn="${2:-1}"; shift 2 ;;
            --tx)   tx="${2:-0}";   shift 2 ;;
            --*)    printf 'ERROR\t--setup-complete does not take %s\n' "$(latt_sanitize "$1")" >&2; return 2 ;;
            *)
                [[ -z "$nas" ]] || { printf 'ERROR\t--setup-complete takes one NAS PDU\n' >&2; return 2; }
                nas="$1"; shift ;;
        esac
    done
    [[ -n "$nas" ]] || {
        printf 'ERROR\tusage: --setup-complete <nas_hex> [--plmn n] [--tx n]\n' >&2; return 2; }
    local n; n=$(latt_nfc "$nas")
    latt_is_hex "$n" || { printf 'ERROR\tdedicatedInfoNAS must be hex\n' >&2; return 2; }
    [[ "$plmn" =~ ^[1-6]$ ]] || { printf 'ERROR\t--plmn is selectedPLMN-Identity, 1..6\n' >&2; return 2; }
    [[ "$tx" =~ ^[0-3]$ ]] || { printf 'ERROR\t--tx is rrc-TransactionIdentifier, 0..3\n' >&2; return 2; }
    latt_rrc_tool || return 1

    local out rc
    out=$(python3 "$LATT_RRC_TOOL" setup-complete --nas "$n" --plmn "$plmn" --tx "$tx" 2>&1); rc=$?
    if (( rc != 0 )); then
        printf 'ERROR\ttools/lte_rrc.py refused: %s\n' "$(latt_sanitize "$(printf '%s' "$out" | head -1)")" >&2
        return 1
    fi
    local hex; hex=$(printf '%s\n' "$out" | awk -F'  +' '$1=="hex"{print $2}')
    local bits; bits=$(printf '%s\n' "$out" | awk -F'  +' '$1=="bitlen"{print $2; exit}')
    printf 'rrc_message\tRRCConnectionSetupComplete\n'
    printf 'envelope\tUL-DCCH-Message/c1/rrcConnectionSetupComplete-r8\n'
    printf 'selected_plmn_identity\t%s\n' "$plmn"
    printf 'rrc_transaction_identifier\t%s\n' "$tx"
    printf 'dedicated_info_nas\t%s\n' "${n^^}"
    printf 'nas_octets\t%d\n' "$(( ${#n} / 2 ))"
    printf 'rrc_bitlen\t%s\n' "${bits%% *}"
    printf 'rrc_hex\t%s\n' "${hex^^}"
    printf 'octets\t%d\n' "$(( ${#hex} / 2 ))"
    printf 'ref\t3GPP TS 36.331 6.2.2 (RRCConnectionSetupComplete), 6.3.6 (UL-DCCH-Message)\n'
    printf 'limit\tnothing below RRC is built: no RLC/MAC/PHY framing, so this is a message body, not a transmission\n'
}

# Read the container back.  A UE's Setup Complete is the first place a
# network learns which subscriber is talking, so the NAS it carries is
# decoded here and the identity it states is recorded in the module's store.
latt_cmd_parse_setup_complete() {
    local hex; hex=$(latt_nfc "${1:-}")
    [[ -n "$hex" ]] || {
        printf 'ERROR\tusage: --parse-setup-complete <rrc_hex>\n' >&2; return 2; }
    latt_is_hex "$hex" || { printf 'ERROR\tnot valid hex\n' >&2; return 2; }
    latt_rrc_tool || return 1

    local out rc
    out=$(python3 "$LATT_RRC_TOOL" decode --type setup-complete --hex "$hex" 2>&1); rc=$?
    if (( rc != 0 )); then
        printf 'ERROR\ttools/lte_rrc.py refused: %s\n' \
            "$(latt_sanitize "$(printf '%s' "$out" | head -1)")" >&2
        return 1
    fi
    local plmn nas
    plmn=$(printf '%s\n' "$out" | awk -F'  +' '$1=="plmn"{print $2}')
    nas=$(printf '%s\n' "$out" | awk -F'  +' '$1=="nas_hex"{print $2}')
    printf 'rrc_message\tRRCConnectionSetupComplete\n'
    printf 'selected_plmn_identity\t%s\n' "$plmn"
    printf 'dedicated_info_nas\t%s\n' "${nas^^}"
    printf 'nas_octets\t%d\n' "$(( ${#nas} / 2 ))"
    [[ -n "$nas" ]] || {
        printf 'note\tthe container carries no NAS PDU\n'
        return 0; }

    local hdr; hdr=$(latt_parse_nas_header "$nas") || return 1
    printf '%s\n' "$hdr" | awk -F'\t' '$1=="security_header_name" || $1=="plain" || \
        $1=="message_type" || $1=="message_name"' || true

    # The identity the UE stated, if it stated one.  In an attach or TAU
    # request the EPS mobile identity is the first IE after the mandatory
    # attach-type octet, so its TLV starts at octet 4 of the message; an
    # identity response carries nothing else, so its IE starts at octet 3.
    local mid=""
    case "$nas" in
        0741*|0748*)  # attach request / TAU request: EPS mobile identity TLV
            mid=$(latt_eps_mobile_id_decode "${nas:6}" 2>/dev/null || true) ;;
        0756*)        # identity response: the mobile identity is the whole body
            mid=$(latt_eps_mobile_id_decode "${nas:4}" 2>/dev/null || true) ;;
    esac
    if [[ -n "$mid" ]]; then
        local kind digits
        kind=$(printf '%s' "$mid" | cut -f1)
        digits=$(printf '%s' "$mid" | cut -f2)
        printf 'identity_kind\t%s\n' "$kind"
        printf 'identity\t%s\n' "$digits"
        latt_store_identity "setup-complete-$kind" "$digits" "latt:--parse-setup-complete"
        printf 'identity_stored\tyes\n'
    else
        printf 'identity_stored\tno\n'
        printf 'identity_note\tthe NAS PDU states no IMSI: a GUTI attach only names the subscriber once the network asks\n'
    fi
}

# ── the NAS responder: the middle of an attach ─────────────────────────
#
# An eNB that only builds RRC messages cannot get a subscriber to say anything,
# and a NAS decoder that only reads captures cannot answer.  This holds the
# state between them: it takes the uplink NAS PDUs a UE actually sends, keeps
# the attach state, and answers with the network's next message wherever this
# tree can encode one honestly.
#
# What it does NOT do is pretend.  The downlink messages that need material
# this tree cannot build -- an AUTN at a confirmed offset (32_nas_signaling
# refuses it), a NAS-MAC over a key this tree does not hold -- are named in a
# `next` row with the reason, so the operator sees exactly where a real eNB
# would continue and this one stops.
#
# State is one 0600 TSV under STATE_DIR so a session survives a restart, which
# is the difference between a responder and a demo.
NASF_MODULE="$IMSISTING_ROOT/modules/32_nas_signaling.sh"

# Resolved per call, not at load: --selftest points STATE_DIR at a temporary
# tree after this file has been sourced, and a path frozen at load time would
# keep writing into the operator's real state directory.
latt_state_dir() { printf '%s/lte_attach' "$STATE_DIR"; }
latt_ue_state()  { printf '%s/ue.tsv' "$(latt_state_dir)"; }

latt_state_get() {  # <key> -> value, empty when the key is absent
    [[ -f "$(latt_ue_state)" ]] || return 0
    awk -F'\t' -v k="$1" '$1==k{print $2; exit}' "$(latt_ue_state)" 2>/dev/null || true
}

latt_state_set() {  # <key> <value> [<key> <value> ...] -> rewrite the store
    mkdir -p "$(latt_state_dir)" 2>/dev/null
    local tmp; tmp=$(mktemp "$(latt_state_dir)/state.XXXXXX") || return 1
    local -a args=("$@") newkeys=() i
    for (( i = 0; i + 1 < ${#args[@]}; i += 2 )); do newkeys+=("${args[i]}"); done
    if [[ -f "$(latt_ue_state)" ]]; then
        local k v keep
        while IFS=$'\t' read -r k v; do
            [[ -z "$k" ]] && continue
            keep=1
            for (( i = 0; i < ${#newkeys[@]}; i++ )); do
                [[ "${newkeys[i]}" == "$k" ]] && keep=0
            done
            (( keep )) && printf '%s\t%s\n' "$k" "$v" >> "$tmp"
        done < "$(latt_ue_state)"
    fi
    while (( $# >= 2 )); do
        printf '%s\t%s\n' "$1" "$2" >> "$tmp"
        shift 2
    done
    chmod 0600 "$tmp" 2>/dev/null
    mv "$tmp" "$(latt_ue_state)" 2>/dev/null || { rm -f "$tmp"; return 1; }
}


# Ask 32_nas_signaling for the network-side message.  One implementation of
# the NAS encodings, not two: this module owns the state machine, that one owns
# the bytes.
latt_answer_build() {  # <message> [extra args...] -> hex on stdout
    [[ -f "$NASF_MODULE" ]] || return 1
    local msg="$1"; shift
    local out
    out=$(bash "$NASF_MODULE" --build-nas eps "$msg" "$@" 2>/dev/null) || return 1
    printf '%s\n' "$out" | awk -F'\t' '$1=="hex"{print $2; exit}'
}

# ── DoLTEst-style negative corpus (K6) ──────────────────────────────────
# Cases a device must reject or ignore, per TS 24.301, handed to the responder
# so its answer is a normative one rather than a guess. A "check" feeds the
# case through the same responder path an operator would use and compares the
# reaction with the expectation. Tier 4 to send (needs a radio); the corpus and
# the expectations are Tier 0 and live here.
latt_doltest_cases() {
    printf 'id\tspec\tdirection\tmessage\thex\texpect\tnote\n'
    printf 'd1\t24.301 8.2.4\tul\tAttach request truncated after the attach type\t074103\treject-96\tmissing the mandatory EPS mobile identity\n'
    printf 'd2\t24.301 7.3\tul\tUnknown EMM message type\t0774\tignore\tan unknown message type is ignored, not answered\n'
    printf 'd3\t24.301 8.2.25\tul\tIdentity response with an unacceptable identity type\t0756F4\treject-96\ttype octet is not IMSI/IMEI/IMEISV\n'
    printf 'd4\t24.301 8.2.4\tul\tAttach request naming a GUTI\t07410306F600F110270F3737359255\taccept\ta GUTI attach is legal; with no binding the responder asks for the IMSI behind it\n'
}

latt_doltest_check() {   # <case-id>
    local id="${1:-}" spec dir expect note hex n=0
    [[ -n "$id" ]] || {
        printf 'ERROR\tusage: --doltest-check <case-id>\n' >&2; return 2; }
    local case_spec case_hex case_expect case_note
    case "$id" in
        d1) spec="24.301 8.2.4";  hex=074103;            expect=reject-96 ;;
        d2) spec="24.301 7.3";    hex=0774;              expect=ignore ;;
        d3) spec="24.301 8.2.25"; hex=0756F4;            expect=reject-96 ;;
        d4) spec="24.301 8.2.4";  hex=07410306F600F110270F3737359255; expect=accept ;;
        *) printf 'ERROR\tno such case: %s (d1..d4)\n' "$(latt_sanitize "$id")" >&2; return 2 ;;
    esac
    local out; out=$(printf 'reset\nul %s\n' "$hex" | latt_cmd_nas_responder -)
    local rej none
    rej=$(printf '%s\n' "$out" | awk -F'\t' '$1=="reject_cause"{print $2; exit}')
    none=$(printf '%s\n' "$out" | awk -F'\t' '$1=="downlink" && $2=="none"{print 1; exit}')
    local actual verdict
    if [[ -n "$rej" ]]; then
        actual="reject-$rej"
    elif [[ -n "$none" ]]; then
        actual="ignore"
    else
        actual="answered"
    fi
    case "$expect" in
        ignore)   [[ "$actual" == ignore ]] && verdict=pass || verdict=fail ;;
        reject-*) [[ "$actual" == "$expect" ]] && verdict=pass || verdict=fail ;;
        accept)   [[ "$actual" == "answered" ]] && verdict=pass || verdict=fail ;;
    esac
    printf 'case\t%s\n' "$id"
    printf 'spec\t%s\n' "$spec"
    printf 'hex\t%s\n' "$hex"
    printf 'expect\t%s\n' "$expect"
    printf 'actual\t%s\n' "$actual"
    printf 'verdict\t%s\n' "$verdict"
    [[ "$verdict" == pass ]]
}

# The identity a UE states, in either place it can state one: the EPS mobile
# The identity a UE states, in either place it can state one: the EPS mobile
# identity IE of an attach/TAU request (first IE after octet 4), or the whole
# body of an identity response.
latt_identity_from_nas() {  # <nas_hex> -> KIND<TAB><digits>
    local nas="$1" mid=""
    case "$nas" in
        0741*|0748*) mid=$(latt_eps_mobile_id_decode "${nas:6}" 2>/dev/null || true) ;;
        0756*)
            # A standard identity response carries the EPS mobile identity as
            # an IE: IEI 08 then a length octet, then the value. Older vectors
            # in this tree put the type octet straight after the message type,
            # so both shapes are read.
            # The decoder takes the IEI and the length octet when they are
            # there, and the length is what settles 15 digits from 16, so the
            # whole tail is handed over rather than a value part guessed at.
            mid=$(latt_eps_mobile_id_decode "${nas:4}" 2>/dev/null || true) ;;
    esac
    [[ -n "$mid" ]] && printf '%s' "$mid"
    return 0
}

latt_cmd_nas_responder() {
    local source="${1:--}"
    # The FlashCatch model needs the responder to answer an identity
    # response with a challenge instead of an accept, so the mode is a
    # property of the run rather than of the file.
    local fc=0
    [[ "${2:-}" == "--flashcatch" ]] && fc=1
    local state imsi step=0 line kind pdu mt
    state=$(latt_state_get state); state="${state:-idle}"
    imsi=$(latt_state_get imsi)
    mkdir -p "$(latt_state_dir)" 2>/dev/null
    chmod 0700 "$(latt_state_dir)" 2>/dev/null

    if [[ "$source" != "-" && ! -r "$source" ]]; then
        printf 'ERROR\tno readable input at %s\n' "$(latt_sanitize "$source")" >&2
        return 2
    fi

    printf 'responder\tready\n'
    printf 'state\t%s\n' "$state"
    [[ -n "$imsi" ]] && printf 'imsi\t%s\n' "$imsi"
    printf 'state_file\t%s\n' "$(latt_ue_state)"
    printf 'input\t%s\n' "$([[ "$source" == "-" ]] && echo 'stdin' || latt_sanitize "$source")"
    (( fc )) && printf 'mode\tflashcatch (identity first, no reject, barring by failed authentication)\n'

    while IFS= read -r line; do
        line="${line%$'\r'}"
        [[ -z "${line// /}" ]] && continue
        [[ "$line" == \#* ]] && continue
        kind="ul"; pdu="$line"
        case "$line" in
            ul\ *|UL\ *) kind="ul"; pdu="${line#* }" ;;
            dl\ *|DL\ *) kind="dl"; pdu="${line#* }" ;;
            note\ *) printf 'note\t%s\n' "$(latt_sanitize "${line#note }")"; continue ;;
            reset)
                state="idle"; imsi=""
                latt_state_set state idle imsi "" fc_fails 0
                printf 'reset\tstate=idle\n'
                continue ;;
        esac
        pdu=$(latt_nfc "$pdu")
        if ! latt_is_hex "$pdu" || (( ${#pdu} < 4 )); then
            printf 'ERROR\tnot a NAS PDU: %s\n' "$(latt_sanitize "$pdu")" >&2
            continue
        fi
        step=$(( step + 1 ))
        mt="${pdu:2:2}"
        local mname; mname=$(latt_msg_type_name "0x$mt")

        case "$kind:$mt" in
            ul:41|ul:48)
                # A truncated attach request (missing the EPS mobile identity,
                # which is mandatory per TS 24.301 8.2.4) is rejected rather
                # than guessed at: 96 = invalid mandatory information.
                if (( ${#pdu} < 14 )); then
                    local rej; rej=$(latt_answer_build attach-reject --cause 96)
                    printf 'step\t%s\n' "$step"
                    printf 'uplink\t%s\n' "$mname"
                    printf 'reject\ttruncated attach request (missing mandatory IEs)\n'
                    printf 'reject_cause\t%s\n' "96"
                    printf 'downlink\tAttach reject\n'
                    printf 'downlink_hex\t%s\n' "$rej"
                    printf 'next\tinvalid mandatory information, TS 24.301 8.2.4\n'
                    latt_state_set exchanges "$(($(latt_state_get exchanges || echo 0) + 1))"
                    continue
                fi
                local id; id=$(latt_identity_from_nas "$pdu")
                if [[ -n "$id" ]]; then
                    imsi=$(printf '%s' "$id" | cut -f2)
                    latt_store_identity "$(printf '%s' "$id" | cut -f1)" "$imsi" \
                        "latt:--nas-responder"
                    state="attach-requested"
                    local acc; acc=$(latt_answer_build attach-accept)
                    printf 'step\t%s\n' "$step"
                    printf 'uplink\t%s\n' "$mname"
                    printf 'identity\t%s\n' "$imsi"
                    printf 'state\t%s\n' "$state"
                    printf 'downlink\tAttach accept\n'
                    printf 'downlink_hex\t%s\n' "$acc"
                    [[ -n "$acc" ]] && printf 'downlink_octets\t%d\n' "$(( ${#acc} / 2 ))"
                    printf 'next\tAttach complete from the UE\n'
                    printf 'limit\tthe accept carries no ESM message container, so no default bearer exists yet\n'
                    latt_state_set state "$state" imsi "$imsi" \
                        exchanges "$(($(latt_state_get exchanges || echo 0) + 1))"
                else
                    # A GUTI attach names no subscriber on its own. If the
                    # binding is already known the attach resolves without
                    # asking again -- that is what having harvested the parse
                    # half buys. If it is not, remember which GUTI was
                    # presented and ask for the IMSI behind it.
                    local ghex gdec gstr bound_imsi
                    ghex="${pdu:6}"; gdec=$(latt_guti_decode "$ghex" 2>/dev/null || true)
                    gstr=$(printf '%s\n' "$gdec" | awk -F'\t' '$1=="guti"{print $2; exit}')
                    bound_imsi=""
                    if [[ -n "$gstr" ]]; then
                        bound_imsi=$(awk -F'\t' -v g="$gstr" '$1==g{print $7; exit}' \
                            "$LATT_GUTI_MAP" 2>/dev/null)
                    fi
                    if [[ -n "$bound_imsi" ]]; then
                        imsi="$bound_imsi"
                        state="attach-requested"
                        local acc2; acc2=$(latt_answer_build attach-accept)
                        printf 'step\t%s\n' "$step"
                        printf 'uplink\t%s\n' "$mname"
                        printf 'guti\t%s\n' "$gstr"
                        printf 'identity\t%s\n' "$imsi"
                        printf 'resolved_by\tguti binding\n'
                        printf 'state\t%s\n' "$state"
                        printf 'downlink\tAttach accept\n'
                        printf 'downlink_hex\t%s\n' "$acc2"
                        [[ -n "$acc2" ]] && printf 'downlink_octets\t%d\n' "$(( ${#acc2} / 2 ))"
                        printf 'next\tAttach complete from the UE\n'
                        latt_state_set state "$state" imsi "$imsi" pending_guti "$gstr" \
                            exchanges "$(($(latt_state_get exchanges || echo 0) + 1))"
                        continue
                    fi
                    # Ask for the IMSI, and keep the GUTI so the answer can be
                    # bound to it.
                    state="identity-requested"
                    local req; req=$(latt_answer_build identity-request --identity imsi)
                    printf 'step\t%s\n' "$step"
                    printf 'uplink\t%s\n' "$mname"
                    printf 'guti\t%s\n' "$gstr"
                    printf 'identity\tnone -- the UE gave a temporary identity\n'
                    printf 'resolved_by\tnone: no binding for this GUTI yet\n'
                    printf 'state\t%s\n' "$state"
                    printf 'downlink\tIdentity request\n'
                    printf 'downlink_hex\t%s\n' "$req"
                    printf 'next\tIdentity response carrying the IMSI, in the clear\n'
                    printf 'limit\tthis is the exposure: the IMSI is asked for before any security context exists\n'
                    latt_state_set state "$state" pending_guti "$gstr" \
                        pending_guti_hex "$ghex" \
                        exchanges "$(($(latt_state_get exchanges || echo 0) + 1))"
                fi ;;
            ul:56)
                # Types 1 (IMSI), 2 (IMEI), 3 (IMEISV) have a place here;
                # anything else, including a type octet left over from the
                # requested identity, is refused with invalid mandatory
                # information (TS 24.301 8.2.25).
                local vidx=2
                [[ "${pdu:4:2}" == "08" ]] && vidx=4
                local it; it=$(( 16#${pdu:$(( vidx * 2 )):2} & 7 ))
                case "$it" in
                    1|2|3) ;;
                    *)
                        printf 'step\t%s\n' "$step"
                        printf 'uplink\t%s\n' "$mname"
                        printf 'reject\tidentity type %s is not acceptable here\n' "$it"
                        printf 'reject_cause\t%s\n' "96"
                        local rej; rej=$(latt_answer_build attach-reject --cause 96)
                        printf 'downlink_hex\t%s\n' "$rej"
                        printf 'next\tinvalid mandatory information, TS 24.301 8.2.25\n'
                        latt_state_set exchanges "$(($(latt_state_get exchanges || echo 0) + 1))"
                        continue ;;
                esac
                local id; id=$(latt_identity_from_nas "$pdu")
                if [[ -n "$id" ]]; then
                    imsi=$(printf '%s' "$id" | cut -f2)
                    latt_store_identity "$(printf '%s' "$id" | cut -f1)" "$imsi" \
                        "latt:--nas-responder"
                    if (( fc )); then
                        # Phase 1 is over: the IMSI arrived without a reject
                        # ever being sent, so nothing in this exchange tells
                        # the UE to delete its security context.
                        local r1 areq
                        r1=$(printf '%032X' $(( 0xA0FC0000 + step * 16#100 )))
                        areq=$(latt_answer_build auth-request --rand "$r1")
                        printf 'phase\t1 capture\n'
                        printf 'capture_messages\t%s\n' "$step"
                        printf 'identity_asked_before_security\tyes\n'
                        printf 'reject_sent\tno\n'
                        printf 'security_context_rule\tnot deleted: TS 24.301 5.5.3.3.5 and 5.6.1.5 delete it on a TAU or service reject, and no reject was sent\n'
                        printf 'guti_retained\tyes\n'
                        printf 'phase\t2 detach\n'
                        printf 'auth_request\t1\n'
                        printf 'rand\t%s\n' "$r1"
                        printf 'downlink\tAuthentication request\n'
                        printf 'downlink_hex\t%s\n' "$areq"
                        printf 'mac\tnot encoded here: --auth-request in 32_nas_signaling refuses to place AUTN after RAND, so these octets carry RAND only; the wrong MAC is the point of the step and is stated rather than built\n'
                        printf 'next\tAuthentication failure from the UE, twice more\n'
                        latt_state_set state auth-sent imsi "$imsi" fc_fails 0 \
                            exchanges "$(($(latt_state_get exchanges || echo 0) + 1))"
                        continue
                    fi
                    # The GUTI the UE presented a moment ago now has a name:
                    # this is the harvest's parse half, done without a radio.
                    local pending_hex pending_name prow
                    pending_hex=$(latt_state_get pending_guti_hex)
                    pending_name=$(latt_state_get pending_guti)
                    if [[ -n "$pending_hex" ]] && prow=$(latt_guti_decode "$pending_hex" 2>/dev/null); then
                        latt_guti_store_put "$prow" "$imsi" "latt:--nas-responder" >/dev/null 2>&1 || true
                        printf 'guti_bound\t%s\n' "$pending_name"
                        printf 'guti_bound_imsi\t%s\n' "$imsi"
                    fi
                    latt_state_set pending_guti "" pending_guti_hex ""
                    state="attach-requested"
                    local acc; acc=$(latt_answer_build attach-accept)
                    printf 'step\t%s\n' "$step"
                    printf 'uplink\t%s\n' "$mname"
                    printf 'identity\t%s\n' "$imsi"
                    printf 'state\t%s\n' "$state"
                    printf 'downlink\tAttach accept\n'
                    printf 'downlink_hex\t%s\n' "$acc"
                    [[ -n "$acc" ]] && printf 'downlink_octets\t%d\n' "$(( ${#acc} / 2 ))"
                    printf 'next\tAuthentication request (needs an AUTN at a confirmed offset)\n'
                    printf 'limit\t32_nas_signaling refuses AUTN because its position after RAND could not be confirmed, so this tree cannot continue the authentication exchange\n'
                    latt_state_set state "$state" imsi "$imsi" \
                        exchanges "$(($(latt_state_get exchanges || echo 0) + 1))"
                else
                    printf 'step\t%s\n' "$step"
                    printf 'uplink\t%s\n' "$mname"
                    printf 'state\t%s\n' "$state"
                    printf 'note\tthe identity response carried no decodable IMSI\n'
                fi ;;
            ul:5C|ul:5c)
                # A failed authentication is the detach mechanism here, not an
                # accident: three of them in a row are what makes the UE mark
                # the cell barred (TS 24.301 5.4.2.7 and TS 36.304 5.3.1).
                local fails; fails=$(latt_state_get fc_fails); fails="${fails:-0}"
                fails=$(( fails + 1 ))
                printf 'step\t%s\n' "$step"
                printf 'uplink\t%s\n' "$mname"
                printf 'auth_failure\t%s\n' "$fails"
                if (( fails < 3 )); then
                    local rn areqn
                    rn=$(printf '%032X' $(( 0xA0FC0000 + step * 16#100 )))
                    areqn=$(latt_answer_build auth-request --rand "$rn")
                    printf 'rand\t%s\n' "$rn"
                    printf 'downlink\tAuthentication request\n'
                    printf 'downlink_hex\t%s\n' "$areqn"
                    printf 'next\tAuthentication failure %d of 3\n' "$(( fails + 1 ))"
                    latt_state_set fc_fails "$fails" state auth-sent \
                        exchanges "$(($(latt_state_get exchanges || echo 0) + 1))"
                else
                    printf 'downlink\tnone\n'
                    printf 'cell_barred\tyes\n'
                    printf 'bar_duration_s\t300\n'
                    printf 'bar_rule\tTS 36.304 5.3.1: a UE that marks a cell barred does not select it for 300 s\n'
                    printf 'finding\tflashcatch_barring HIGH\n'
                    printf 'security_context_retained\tyes\n'
                    printf 'tmsi_retained\tyes\n'
                    printf 'linkability\tthe IMSI captured in phase 1 is now mapped to the TMSI the UE kept\n'
                    printf 'next\tthe UE reselects the previous legitimate cell and reuses its security context\n'
                    latt_state_set fc_fails "$fails" state barred
                fi ;;
            ul:43)
                state="registered"
                printf 'step\t%s\n' "$step"
                printf 'uplink\t%s\n' "$mname"
                printf 'state\t%s\n' "$state"
                printf 'next\tPDN connectivity request, then the ESM bearer handshake\n'
                latt_state_set state "$state" ;;
            dl:*)
                printf 'step\t%s\n' "$step"
                printf 'downlink\t%s\n' "$mname"
                printf 'state\t%s\n' "$state"
                printf 'note\tno answer: this side is the network\n' ;;
            *)
                printf 'step\t%s\n' "$step"
                printf 'uplink\t%s\n' "$mname"
                printf 'state\t%s\n' "$state"
                printf 'downlink\tnone\n'
                printf 'ignored\tunknown EMM message type 0x%s (TS 24.301 7.3)\n' "$mt"
                printf 'limit\tthe responder answers the attach handshake only; every other procedure is decoded and left to the operator\n' ;;
        esac
    done < <([[ "$source" == "-" ]] && cat || cat -- "$source")

    printf 'exchanges\t%s\n' "$step"
    printf 'final_state\t%s\n' "$(latt_state_get state)"
    [[ -n "$(latt_state_get imsi)" ]] && printf 'final_imsi\t%s\n' "$(latt_state_get imsi)"
    return 0
}

# ── GUTI: the identity a network issues, and what it maps back to ───────
#
# A GUTI is the network's own temporary name for a subscriber: PLMN, MME group,
# MME code, M-TMSI (TS 24.301 §9.9.3.12). It names nobody on its own, which is
# exactly why it is useful: a subscriber who re-attaches with it is asking the
# network to recognise the context behind it. Harvesting the parse half means
# reading the GUTI out of an attach request and holding the binding the moment
# an identity response supplies the IMSI behind it.
LATT_GUTI_MAP="$LATT_DIR/guti_map.tsv"
# The header is written with %b so the tabs are real tabs: a header carrying
# literal backslash-t is invisible to every reader that splits on tab.
latt_guti_header() { printf 'guti\tmcc\tmnc\tmme_group\tmme_code\tm_tmsi\timsi\tsource\tfirst_seen\tlast_seen\tattaches'; }

latt_guti_store_init() {
    mkdir -p "$LATT_DIR" 2>/dev/null
    [[ -f "$LATT_GUTI_MAP" ]] || { latt_guti_header; printf '\n'; } > "$LATT_GUTI_MAP"
}

# The value part of an EPS mobile identity carrying a GUTI, from any of the
# shapes it arrives in: bare value (type first), length + value, or an IE with
# the 0x08 identifier in front.
latt_guti_value() {  # <hex> -> the 11-octet value part, or empty
    local h; h=$(latt_nfc "${1:-}")
    latt_is_hex "$h" || return 1
    local first=$(( 16#${h:0:2} ))
    # 08 <len> <type> ...   (IEI + length form)
    if (( first == 8 )) && (( ${#h} >= 8 )); then
        h="${h:4}"
    fi
    # <len> <type> ...  (length-first form; only when the next octet is a type)
    if (( ${#h} >= 6 )); then
        local second=$(( 16#${h:2:2} ))
        if (( first >= 0x0A && first <= 0x0C )) && (( (second & 0x07) == 6 )); then
            h="${h:2}"
        fi
    fi
    [[ ${#h} -ge 22 ]] || return 1
    printf '%s' "${h:0:22}"
}

latt_guti_decode() {  # <hex> -> rows
    local v; v=$(latt_guti_value "${1:-}") || {
        printf 'ERROR\tnot an EPS mobile identity carrying a GUTI: %s\n' "$(latt_sanitize "${1:-<none>}")" >&2
        return 1; }
    local type=$(( 16#${v:0:2} ))
    (( (type & 0x07) == 6 )) || {
        printf 'ERROR\tthe identity type is %d, not 6 (GUTI)\n' "$(( type & 0x07 ))" >&2; return 1; }
    local plmn="${v:2:6}" grp="${v:8:4}" code="${v:12:2}" tmsi="${v:14:8}"
    local mcc mnc
    mcc=$(latt_plmn_decode "$plmn") || return 1
    mnc=$(printf '%s' "$mcc" | cut -f2); mcc=$(printf '%s' "$mcc" | cut -f1)
    printf 'identity_type\tGUTI\n'
    printf 'plmn\t%s-%s\n' "$mcc" "$mnc"
    printf 'mcc\t%s\n' "$mcc"
    printf 'mnc\t%s\n' "$mnc"
    printf 'mme_group\t%s\n' "$(( 16#$grp ))"
    printf 'mme_code\t%s\n' "$(( 16#$code ))"
    printf 'm_tmsi\t%s\n' "$(( 16#$tmsi ))"
    printf 'm_tmsi_hex\t%s\n' "${tmsi^^}"
    printf 'guti\t%s-%s-%s-%s-%s\n' "$mcc" "$mnc" "$(( 16#$grp ))" "$(( 16#$code ))" "$(( 16#$tmsi ))"
    printf 'value_hex\t%s\n' "${v^^}"
    printf 'ref\t3GPP TS 24.301 9.9.3.12 (EPS mobile identity, GUTI)\n'
}

# PLMN from three BCD octets, the layout 43_ran_share owns: MCC in octet 1 and
# the low nibble of octet 2, MNC split across octets 2 and 3, a two-digit MNC
# marked by an F filler.
latt_plmn_decode() {  # <6 hex> -> "mcc<TAB>mnc"
    local h; h=$(latt_nfc "${1:-}")
    [[ "$h" =~ ^[0-9A-Fa-f]{6}$ ]] || return 1
    local o1=$(( 16#${h:0:2} )) o2=$(( 16#${h:2:2} )) o3=$(( 16#${h:4:2} ))
    local d1=$(( o1 & 0xF )) d2=$(( (o1 >> 4) & 0xF )) d3=$(( o2 & 0xF ))
    local d4=$(( o3 & 0xF )) d5=$(( (o3 >> 4) & 0xF )) d6=$(( (o2 >> 4) & 0xF ))
    local mcc="${d1}${d2}${d3}" mnc
    if (( d6 == 0xF )); then mnc="${d4}${d5}"; else mnc="${d4}${d5}${d6}"; fi
    printf '%s\t%s' "$mcc" "$mnc"
}

latt_guti_encode() {  # <plmn> <mme_group> <mme_code> <m_tmsi> -> hex
    local plmn="${1:-}" grp="${2:-}" code="${3:-}" tmsi="${4:-}"
    [[ "$grp" =~ ^[0-9]+$ ]] && (( grp >= 0 && grp <= 65535 )) || {
        printf 'ERROR\tMME group id is 0..65535\n' >&2; return 2; }
    [[ "$code" =~ ^[0-9]+$ ]] && (( code >= 0 && code <= 255 )) || {
        printf 'ERROR\tMME code is 0..255\n' >&2; return 2; }
    [[ "$tmsi" =~ ^[0-9]+$ ]] && (( tmsi >= 0 && tmsi <= 4294967295 )) || {
        printf 'ERROR\tM-TMSI is 0..4294967295\n' >&2; return 2; }
    local bcd; bcd=$(latt_plmn_encode "$plmn") || return 2
    printf 'F6%s%04X%02X%08X' "$bcd" "$grp" "$code" "$tmsi"
}

latt_plmn_encode() {  # <mcc> [mnc] or "00101" -> 3 BCD octets
    local plmn="${1:-}" mcc mnc
    if [[ "$plmn" =~ ^[0-9]{5,6}$ ]]; then
        mcc="${plmn:0:3}"; mnc="${plmn:3}"
    elif [[ "$plmn" == *-* ]]; then
        mcc="${plmn%%-*}"; mnc="${plmn#*-}"
    else
        printf 'ERROR\ta PLMN is MCC and MNC: 00101, 001-01 or 310260\n' >&2; return 1
    fi
    [[ "$mcc" =~ ^[0-9]{3}$ && "$mnc" =~ ^[0-9]{2,3}$ ]] || {
        printf 'ERROR\tMCC is 3 digits and MNC 2 or 3: %s\n' "$(latt_sanitize "$plmn")" >&2; return 1; }
    local o1 o2 o3
    o1=$(( (10#${mcc:1:1} << 4) | 10#${mcc:0:1} ))
    if (( ${#mnc} == 3 )); then
        o2=$(( (10#${mnc:2:1} << 4) | 10#${mcc:2:1} ))
    else
        o2=$(( (0xF << 4) | 10#${mcc:2:1} ))
    fi
    o3=$(( (10#${mnc:1:1} << 4) | 10#${mnc:0:1} ))
    printf '%02X%02X%02X' "$o1" "$o2" "$o3"
}

# The binding store: one row per GUTI, rewritten in place. A GUTI is reused
# across attaches, so an append would grow a second row per attach and the
# lookup would have to guess which one is current; upserting keeps one truth
# per name and counts the attaches on it.
latt_guti_store_put() {  # <decode rows> <imsi> <source>
    local rows="$1" imsi="$2" src="$3"
    local guti mcc mnc grp code tmsi
    guti=$(printf '%s\n' "$rows" | awk -F'\t' '$1=="guti"{print $2; exit}')
    mcc=$(printf '%s\n' "$rows" | awk -F'\t' '$1=="mcc"{print $2; exit}')
    mnc=$(printf '%s\n' "$rows" | awk -F'\t' '$1=="mnc"{print $2; exit}')
    grp=$(printf '%s\n' "$rows" | awk -F'\t' '$1=="mme_group"{print $2; exit}')
    code=$(printf '%s\n' "$rows" | awk -F'\t' '$1=="mme_code"{print $2; exit}')
    tmsi=$(printf '%s\n' "$rows" | awk -F'\t' '$1=="m_tmsi"{print $2; exit}')
    [[ -n "$guti" ]] || { printf 'ERROR\tno GUTI to store\n' >&2; return 1; }
    [[ "$imsi" =~ ^[0-9]{14,15}$ ]] || {
        printf 'ERROR\tan IMSI is 14 or 15 digits: %s\n' "$(latt_sanitize "${imsi:-<none>}")" >&2; return 2; }
    latt_guti_store_init
    local now prev_first attaches
    now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    prev_first=$(awk -F'\t' -v g="$guti" '$1==g{print $9; exit}' "$LATT_GUTI_MAP" 2>/dev/null)
    attaches=$(awk -F'\t' -v g="$guti" '$1==g{print $11; exit}' "$LATT_GUTI_MAP" 2>/dev/null)
    [[ -n "$prev_first" ]] || prev_first="$now"
    attaches=$(( ${attaches:-0} + 1 ))
    local tmp; tmp=$(mktemp "$LATT_DIR/guti.XXXXXX") || return 1
    { latt_guti_header; printf '\n'; } > "$tmp"
    awk -F'\t' -v OFS='\t' -v g="$guti" '$1!=g && NR>1{print}' "$LATT_GUTI_MAP" >> "$tmp" 2>/dev/null
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$guti" "$mcc" "$mnc" "$grp" "$code" "$tmsi" "$imsi" \
        "$(latt_sanitize "$src")" "$prev_first" "$now" "$attaches" >> "$tmp"
    mv "$tmp" "$LATT_GUTI_MAP" || { rm -f "$tmp"; return 1; }
    printf 'stored\t%s\n' "$guti"
    printf 'imsi\t%s\n' "$imsi"
    printf 'attaches\t%s\n' "$attaches"
}

latt_guti_lookup() {  # <guti | guti_hex> -> rows
    local guti="${1:-}" decoded
    if [[ "$guti" =~ ^[0-9A-Fa-f]{8,}$ ]]; then
        decoded=$(latt_guti_decode "$guti" 2>/dev/null | awk -F'\t' '$1=="guti"{print $2; exit}')
        [[ -n "$decoded" ]] && guti="$decoded"
    fi
    latt_guti_store_init
    local row; row=$(awk -F'\t' -v g="$guti" '$1==g{print; exit}' "$LATT_GUTI_MAP" 2>/dev/null)
    if [[ -z "$row" ]]; then
        printf 'guti\t%s\n' "$guti"
        printf 'bound\tno\n'
        printf 'note\tno IMSI has been bound to this GUTI yet: it names no subscriber until an identity response supplies one\n'
        return 1
    fi
    printf 'guti\t%s\n'          "$(printf '%s' "$row" | cut -f1)"
    printf 'bound\tyes\n'
    printf 'imsi\t%s\n'           "$(printf '%s' "$row" | cut -f7)"
    printf 'plmn\t%s-%s\n'        "$(printf '%s' "$row" | cut -f2)" "$(printf '%s' "$row" | cut -f3)"
    printf 'mme_group\t%s\n'      "$(printf '%s' "$row" | cut -f4)"
    printf 'mme_code\t%s\n'       "$(printf '%s' "$row" | cut -f5)"
    printf 'm_tmsi\t%s\n'         "$(printf '%s' "$row" | cut -f6)"
    printf 'source\t%s\n'         "$(printf '%s' "$row" | cut -f8)"
    printf 'first_seen\t%s\n'     "$(printf '%s' "$row" | cut -f9)"
    printf 'last_seen\t%s\n'      "$(printf '%s' "$row" | cut -f10)"
    printf 'attaches\t%s\n'       "$(printf '%s' "$row" | cut -f11)"
}

latt_cmd_guti_decode() {
    local hex="${1:-}"
    [[ -n "$hex" ]] || { printf 'ERROR\tusage: --guti-decode <hex>\n' >&2; return 2; }
    latt_guti_decode "$hex"
}

latt_cmd_guti_map() {
    local hex="${1:-}" imsi="${2:-}" rows
    [[ -n "$hex" && -n "$imsi" ]] || {
        printf 'ERROR\tusage: --guti-map <guti_hex> <imsi>\n' >&2; return 2; }
    rows=$(latt_guti_decode "$hex") || return 1
    latt_guti_store_put "$rows" "$imsi" "latt:--guti-map"
}

latt_cmd_guti_tsv() {
    local which="${1:-}"
    if [[ -n "$which" ]]; then latt_guti_lookup "$which"; return $?; fi
    latt_guti_store_init
    cat "$LATT_GUTI_MAP"
    local n; n=$(($(grep -c . "$LATT_GUTI_MAP" 2>/dev/null || echo 1) - 1))
    printf 'BOUND_GUTI_COUNT\t%s\n' "$n"
    [[ "$n" -gt 0 ]]
}
# ── GUTI reallocation observation ─────────────────────────────────────
# A GUTI reallocation is a temporary identity replaced by another, and the
# only place the replacement is visible without forcing it is the exchange
# itself: the network sends GUTI REALLOCATION COMMAND (NAS type 0x50) with
# the new identity, the UE answers COMPLETE (0x51). This half records the
# replacement in the order it was seen and can walk the chain old -> new ->
# newer. Forcing one (a Tier-4 transmit) is not done here.
LATT_REALLOC="$LATT_DIR/realloc.tsv"
latt_realloc_header() { printf 'observed_at\told_guti\tnew_guti\timsi\tcause\tsource'; }

latt_realloc_init() {
    mkdir -p "$LATT_DIR" 2>/dev/null
    [[ -f "$LATT_REALLOC" ]] || { latt_realloc_header; printf '\n'; } > "$LATT_REALLOC"
}

# GUTI REALLOCATION COMMAND body (TS 24.301 8.2.18): EPS mobile identity
# carrying the new GUTI, then an optional TAI (5 octets: PLMN + TAC) when the
# spare bit says one follows, then an optional reallocation cause.
latt_realloc_command() {   # <hex>
    local h; h=$(latt_nfc "${1:-}")
    latt_is_hex "$h" || { printf 'ERROR\treallocation command must be hex\n' >&2; return 2; }
    local v; v=$(latt_guti_value "$h")
    if [[ -z "$v" ]]; then
        local t=$(( 16#${h:0:2} ))
        if (( (t & 7) == 1 )); then
            printf 'reallocated_identity\tIMSI\n'
            printf 'note\tthis reallocation carries an IMSI, not a GUTI (type 1)\n'
            return 1
        fi
        printf 'ERROR\tthe command does not carry an EPS mobile identity\n' >&2; return 2
    fi
    local type=$(( 16#${v:0:2} ))
    if (( (type & 0x07) == 6 )); then
        printf 'reallocated_identity\tGUTI\n'
        printf '%s\n' "$(latt_guti_decode "$v")"
    else
        printf 'reallocated_identity\tIMSI\n'
        printf 'note\tthis reallocation carries an IMSI, not a GUTI (type %d)\n' "$(( type & 0x07 ))"
        return 1
    fi
    local rest="${h:${#v}}"
    if (( ${#rest} >= 10 )); then
        printf 'tai\t%s\n' "$(latt_nfc "${rest:0:10}")"
        rest="${rest:10}"
    fi
    if (( ${#rest} >= 2 )); then
        printf 'cause\t%s\n' "${rest:0:2}"
    fi
    printf 'ref\t3GPP TS 24.301 8.2.18 (GUTI reallocation command)\n'
}

latt_realloc_record() {   # <old-guti-hex> <new-guti-hex> [--imsi IMSI] [--cause HEX]
    local old new imsi="" cause="-" h
    old=$(latt_guti_value "${1:-}" 2>/dev/null); new=$(latt_guti_value "${2:-}" 2>/dev/null)
    [[ -n "$old" && -n "$new" ]] || {
        printf 'ERROR\tusage: --realloc-record <old-guti-hex> <new-guti-hex> [--imsi IMSI] [--cause HEX]\n' >&2
        return 2; }
    shift 2 || true
    while (( $# )); do
        case "$1" in
            --imsi)  imsi="${2:-}"; shift 2 ;;
            --cause) cause=$(latt_nfc "${2:-}"); shift 2 ;;
            *) printf 'ERROR\tunknown option %s\n' "$(latt_sanitize "$1")" >&2; return 2 ;;
        esac
    done
    if [[ -n "$imsi" ]]; then
        [[ "$imsi" =~ ^[0-9]{14,15}$ ]] || { printf 'ERROR\tIMSI is 14 or 15 digits\n' >&2; return 2; }
    fi
    [[ "$cause" == "-" || "$cause" =~ ^[0-9A-Fa-f]{2}$ ]] || {
        printf 'ERROR\t--cause must be 2 hex digits\n' >&2; return 2; }
    local old_name new_name
    old_name=$(latt_guti_decode "$old" 2>/dev/null | awk -F'\t' '$1=="guti"{print $2; exit}')
    new_name=$(latt_guti_decode "$new" 2>/dev/null | awk -F'\t' '$1=="guti"{print $2; exit}')
    [[ -n "$old_name" && -n "$new_name" ]] || { printf 'ERROR\tboth ends must decode as GUTIs\n' >&2; return 2; }
    latt_realloc_init
    local now; now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$now" "$old_name" "$new_name" \
        "$(latt_sanitize "${imsi:-}")" "$(printf '%s' "${cause^^}")" "latt:--realloc-record" >> "$LATT_REALLOC"
    printf 'recorded\tyes\n'
    printf 'old_guti\t%s\n' "$old_name"
    printf 'new_guti\t%s\n' "$new_name"
    [[ -n "$imsi" ]] && printf 'imsi\t%s\n' "$imsi"
    printf 'observed_at\t%s\n' "$now"
}

latt_cmd_realloc_list() {
    latt_realloc_init
    cat "$LATT_REALLOC"
    local n; n=$(($(grep -c . "$LATT_REALLOC" 2>/dev/null || echo 1) - 1))
    printf 'REALLOC_COUNT\t%s\n' "$n"
    [[ "$n" -gt 0 ]]
}

latt_cmd_realloc_chain() {   # <guti | guti-hex>
    local name="${1:-}" raw
    raw=$(latt_guti_value "$name" 2>/dev/null) || {
        printf 'ERROR\tnot a GUTI: %s\n' "$(latt_sanitize "${name:-<none>}")" >&2; return 2; }
    name=$(latt_guti_decode "$raw" | awk -F'\t' '$1=="guti"{print $2; exit}')
    latt_realloc_init
    local cur="$name" hops=0
    printf 'start\t%s\n' "$cur"
    while (( hops < 16 )); do
        local next
        next=$(awk -F'\t' -v g="$cur" '$2==g{print $3; exit}' "$LATT_REALLOC" 2>/dev/null)
        [[ -n "$next" ]] || break
        printf 'next\t%s\n' "$next"
        cur="$next"; hops=$(( hops + 1 ))
    done
    printf 'current\t%s\n' "$cur"
    printf 'hops\t%d\n' "$hops"
    if (( hops == 0 )); then
        printf 'note\tno recorded reallocation starts at this GUTI\n'
        return 1
    fi
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
# ── TS 24.008 GPRS mobility and session management ──────────────────────
# The LTE side of this module speaks TS 24.301 only. A 3G or 2G handset is
# not that protocol: it attaches with GMM, opens its data bearer with SM, and
# carries its identity in the same four-octet header the MM layer has used
# since GSM. The octets below are composed from the caller's own IE list and
# read back by position, because the field layouts of the individual IEs are
# message-specific and this module will not guess one: what it does verify is
# the layer-3 header (protocol discriminator, transaction identifier or skip
# indicator, message type) and the three IE formats 24.008 actually defines.
#
#   type 1 (TV, half octet): IEI in the high nibble, value in the low nibble
#   type 2 (TV):             IEI, then one octet of value
#   type 3 (TLV):            IEI, one length octet, value
#   type 4 (TLV-E):          IEI, two length octets, value
#
# (TS 24.008 clause 10.5, "coding of information elements".)

latt_24008_gmm_name() {
    case "${1^^}" in
        41) echo "ATTACH REQUEST" ;;
        42) echo "ATTACH ACCEPT" ;;
        43) echo "ATTACH COMPLETE" ;;
        44) echo "ATTACH REJECT" ;;
        45) echo "DETACH REQUEST" ;;
        46) echo "DETACH ACCEPT" ;;
        48) echo "ROUTING AREA UPDATE REQUEST" ;;
        49) echo "ROUTING AREA UPDATE ACCEPT" ;;
        4A) echo "ROUTING AREA UPDATE COMPLETE" ;;
        4B) echo "ROUTING AREA UPDATE REJECT" ;;
        4C) echo "SERVICE REQUEST" ;;
        4D) echo "SERVICE ACCEPT" ;;
        4E) echo "SERVICE REJECT" ;;
        4F) echo "AUTHENTICATION AND CIPHERING REQUEST" ;;
        50) echo "AUTHENTICATION AND CIPHERING RESPONSE" ;;
        51) echo "AUTHENTICATION AND CIPHERING FAILURE" ;;
        52) echo "IDENTITY REQUEST" ;;
        53) echo "IDENTITY RESPONSE" ;;
        55) echo "GMM STATUS" ;;
        56) echo "GMM INFORMATION" ;;
        *)  return 1 ;;
    esac
}

latt_24008_sm_name() {
    case "${1^^}" in
        41) echo "ACTIVATE PDP CONTEXT REQUEST" ;;
        42) echo "ACTIVATE PDP CONTEXT ACCEPT" ;;
        43) echo "ACTIVATE PDP CONTEXT REJECT" ;;
        46) echo "DEACTIVATE PDP CONTEXT REQUEST" ;;
        47) echo "DEACTIVATE PDP CONTEXT ACCEPT" ;;
        48) echo "MODIFY PDP CONTEXT REQUEST" ;;
        49) echo "MODIFY PDP CONTEXT ACCEPT" ;;
        *)  return 1 ;;
    esac
}

latt_24008_pd_name() {
    case "${1^^}" in
        02) echo "session management (SM)" ;;
        03) echo "call control (CC)" ;;
        05) echo "mobility management (MM)" ;;
        06) echo "radio resources management (RR)" ;;
        08) echo "GPRS mobility management (GMM)" ;;
        0A) echo "GPRS session management (SM)" ;;
        *)  return 1 ;;
    esac
}

# One information element, in the format the caller names. The formats are the
# part of 24.008 this module places on its own; the IEI and value are the
# caller's, because an IEI is only meaningful inside one message.
# Which message-type table applies, from the protocol discriminator. 0x41 is
# ATTACH REQUEST in GMM and ACTIVATE PDP CONTEXT REQUEST in SM, so the table
# cannot be chosen from the message type alone.
latt_24008_domain() {
    case "${1^^}" in
        08|0a) echo "GMM" ;;
        02)    echo "SM" ;;
        *)     echo "none" ;;
    esac
}

latt_24008_ie() {  # fmt iei value-hex
    local fmt="${1:-}" iei="${2:-}" val="${3:-}" n
    iei="${iei#0x}"; iei="${iei#0X}"
    [[ "$iei" =~ ^[0-9A-Fa-f]{1,2}$ ]] || {
        printf 'ERROR\tIEI "%s" is not one or two hex digits\n' "$(latt_sanitize "$iei")" >&2; return 2; }
    val="${val//[[:space:]]/}"
    [[ -z "$val" || "$val" =~ ^[0-9A-Fa-f]+$ ]] || {
        printf 'ERROR\tvalue "%s" is not hex\n' "$(latt_sanitize "$val")" >&2; return 2; }
    (( ${#val} % 2 == 0 )) || {
        printf 'ERROR\tvalue "%s" is a whole number of octets\n' "$(latt_sanitize "$val")" >&2; return 2; }
    n=$(( ${#val} / 2 ))
    case "$fmt" in
        t1) (( n == 0 )) || {
                printf 'ERROR\ta type 1 IE carries no length: the value is the low nibble of the IEI octet\n' >&2
                return 2; }
            printf '%X' "$(( (16#$iei << 4) & 0xF0 ))" ;;
        t2) printf '%s%s' "$iei" "$val" ;;
        t3) (( n <= 255 )) || { printf 'ERROR\ta type 3 IE cannot be longer than 255 octets\n' >&2; return 2; }
            printf '%s%02X%s' "$iei" "$n" "$val" ;;
        t4) printf '%s%04X%s' "$iei" "$n" "$val" ;;
        v)  printf '%s' "$val" ;;
        *)  printf 'ERROR\tIE format "%s" is not t1, t2, t3, t4 or v\n' "$(latt_sanitize "$fmt")" >&2
            printf 'WHY\tTS 24.008 clause 10.5 defines exactly those four TV/TLV layouts\n' >&2
            return 2 ;;
    esac
}

# Layer-3 message: protocol discriminator, transaction identifier / skip
# indicator, message type, then whatever the caller listed.
latt_24008_build() {  # pd-hex type-hex ti|skip [fmt:iei:value ...]
    local pd="${1:-}" mt="${2:-}" ti="${3:-}" out rest
    [[ "$pd" =~ ^[0-9A-Fa-f]{2}$ ]] || {
        printf 'ERROR\tprotocol discriminator must be one octet of hex\n' >&2; return 2; }
    [[ "$mt" =~ ^[0-9A-Fa-f]{2}$ ]] || {
        printf 'ERROR\tmessage type must be one octet of hex\n' >&2; return 2; }
    latt_24008_pd_name "$pd" >/dev/null 2>&1 || {
        printf 'ERROR\t0x%s is not a protocol discriminator TS 24.008 defines\n' "$pd" >&2; return 2; }
    out="${pd}${ti}${mt}"
    shift 3 || true
    for rest in "$@"; do
        # One assignment per statement: in this bash a multi-assignment local
        # that reads the previous name yields an empty value.
        local fmt mid iei val
        fmt="${rest%%:*}"
        mid="${rest#*:}"
        iei="${mid%%:*}"
        val="${mid#*:}"
        out+=$(latt_24008_ie "$fmt" "$iei" "$val") || return 2
    done
    printf '%s' "$out"
}

latt_24008_ti() {  # value 0..7 -> transaction identifier octet
    local v="${1:-0}"
    [[ "$v" =~ ^[0-7]$ ]] || {
        printf 'ERROR\ttransaction identifier must be 0..7\n' >&2; return 2; }
    printf '%02X' "$(( (v << 4) | 0x0 ))"
}

latt_cmd_24008_build() {
    local pd="${1:-}" mt="${2:-}" ti="${3:-}"
    [[ -n "$mt" ]] || {
        printf 'ERROR\tusage: --24008-build <pd-hex> <type-hex> <ti|skip> [fmt:iei:value ...]\n' >&2
        printf 'WHY\tTS 24.008 section 9.4 and 9.5 define the message identities; the IEs are the caller'"'"'s because an IEI is only meaningful inside one message\n' >&2
        return 2; }
    local out; out=$(latt_24008_build "$pd" "$mt" "$ti" "${@:4}") || return 2
    printf 'protocol_discriminator\t%s\n' "$pd"
    printf 'pd_name\t%s\n' "$(latt_24008_pd_name "$pd" 2>/dev/null || echo unknown)"
    printf 'message_type\t%s\n' "$mt"
    local dom
    dom=$(latt_24008_domain "$pd")
    if [[ "$dom" == "SM" ]] && latt_24008_sm_name "$mt" >/dev/null 2>&1; then
        printf 'message_name\t%s\n' "$(latt_24008_sm_name "$mt")"
        printf 'message_domain\tSM\n'
    elif [[ "$dom" == "GMM" ]] && latt_24008_gmm_name "$mt" >/dev/null 2>&1; then
        printf 'message_name\t%s\n' "$(latt_24008_gmm_name "$mt")"
        printf 'message_domain\tGMM\n'
    else
        printf 'message_name\tunknown\n'
        printf 'message_domain\tnone\n'
    fi
    printf 'ies\t%s\n' "$(( $# - 3 ))"
    printf 'hex\t%s\n' "$out"
    printf 'octets\t%s\n' "$(( ${#out} / 2 ))"
    printf 'ref\tTS 24.008 clause 9.4 (GMM), 9.5 (SM), 10.5 (coding of information elements)\n'
    printf 'limit\tthe layer-3 header and the IE formats are placed here; whether a given IEI belongs in a given message is not checked, because that table is per message and this module does not carry it\n'
}

# Reading a 24.008 PDU back. The header is unambiguous; the IE list is walked
# only with a format map the caller supplies, because the same IEI number is a
# different IE in a different message and the octets do not say which format
# they are.
latt_24008_parse() {  # hex [fmt:iei ...]
    local hex="${1:-}" fmtmap="${2:-}" pd ti mt out name domain
    hex="${hex//[[:space:]]/}"; hex="${hex//0x/}"; hex="${hex,,}"
    [[ "$hex" =~ ^[0-9a-f]+$ ]] || { printf 'ERROR\tPDU must be hex\n' >&2; return 1; }
    (( ${#hex} % 2 == 0 )) || { printf 'ERROR\tPDU must be whole octets\n' >&2; return 1; }
    (( ${#hex} >= 6 )) || {
        printf 'ERROR\tPDU is shorter than the one-octet header plus message type\n' >&2; return 1; }
    pd="${hex:0:2}"; ti="${hex:2:2}"; mt="${hex:4:2}"
    printf 'protocol_discriminator\t%s\n' "$pd"
    printf 'pd_name\t%s\n' "$(latt_24008_pd_name "$pd" 2>/dev/null || echo unknown)"
    printf 'header_octet\t%s\n' "$ti"
    if [[ "$pd" == "08" || "$pd" == "0a" ]]; then
        printf 'skip_indicator\t%s\n' "$ti"
        printf 'ti_or_skip\tskip_indicator\n'
    else
        printf 'transaction_id\t%s\n' "$(( 16#$ti >> 4 ))"
        printf 'ti_flag\t%s\n' "$(( 16#$ti & 0x08 ? 1 : 0 ))"
        printf 'ti_or_skip\ttransaction_identifier\n'
    fi
    printf 'message_type\t%s\n' "$mt"
    local pdom
    pdom=$(latt_24008_domain "$pd")
    if [[ "$pdom" == "SM" ]] && name=$(latt_24008_sm_name "$mt" 2>/dev/null); then domain=SM
    elif [[ "$pdom" == "GMM" ]] && name=$(latt_24008_gmm_name "$mt" 2>/dev/null); then domain=GMM
    else name=unknown; domain=none; fi
    printf 'message_name\t%s\n' "$name"
    printf 'message_domain\t%s\n' "$domain"
    local rest="${hex:6}" n=$(( (${#hex} - 6) / 2 ))
    printf 'body_octets\t%s\n' "$n"
    if [[ -z "$fmtmap" ]]; then
        if (( n > 0 )); then
            printf 'note\tthe body is not walked: an IEI number means a different IE, and a different format, in every message, so the caller supplies the map\n'
            printf 'body_hex\t%s\n' "$rest"
        fi
        return 0
    fi
    # walk with a caller-supplied map of iei:format
    local i=0 pos=0 byte iei fmt len val
    while (( pos < ${#rest} )); do
        byte="${rest:pos:2}"
        iei="${byte^^}"
        fmt=""
        local spec
        for spec in $fmtmap; do
            local want got
            want="${spec%%:*}"
            got="${spec#*:}"
            want="${want#0x}"; want="${want#0X}"
            want=$(printf '%02X' "$(( 16#$want ))") || continue
            if [[ "$want" == "$iei" ]]; then fmt="$got"; fi
        done
        # A type 1 IEI lives in the high nibble of its own octet, so a map
        # entry such as "1:t1" has to be matched against the nibble.
        if [[ -z "$fmt" ]]; then
            local hi
            hi=$(printf '%02X' "$(( (16#$byte >> 4) & 0x0F ))")
            for spec in $fmtmap; do
                local want got
                want="${spec%%:*}"
                got="${spec#*:}"
                want="${want#0x}"; want="${want#0X}"
                want=$(printf '%02X' "$(( 16#$want ))") || continue
                if [[ "$want" == "$hi" && "$got" == "t1" ]]; then fmt="t1"; fi
            done
        fi
        if [[ -z "$fmt" ]]; then
            printf 'ie\t%s\t%s\tunmapped\t%s\t\n' "$i" "$pos" "$byte"
            printf 'note\tIEI 0x%s is not in the map the caller supplied, so its length is unknown and the walk stops here\n' "$byte"
            return 0
        fi
        case "$fmt" in
            t1) printf 'ie\t%s\t%s\t%s\t%s\t%s\n' "$i" "$pos" "type1" "$iei" "$(( 16#$byte & 0x0F ))"
                pos=$(( pos + 2 )) ;;
            t2) val="${rest:pos+2:2}"
                printf 'ie\t%s\t%s\t%s\t%s\t%s\n' "$i" "$pos" "type2" "$iei" "$val"
                pos=$(( pos + 4 )) ;;
            t3) len=$(( 16#${rest:pos+2:2} ))
                val="${rest:pos+4:len*2}"
                (( ${#val} == len * 2 )) || {
                    printf 'ERROR\tIE 0x%s declares %d octets but the PDU ends first\n' "$iei" "$len" >&2; return 1; }
                printf 'ie\t%s\t%s\t%s\t%s\t%s\n' "$i" "$pos" "type3" "$iei" "$val"
                pos=$(( pos + 4 + len * 2 )) ;;
            t4) len=$(( 16#${rest:pos+2:4} ))
                val="${rest:pos+6:len*2}"
                (( ${#val} == len * 2 )) || {
                    printf 'ERROR\tIE 0x%s declares %d octets but the PDU ends first\n' "$iei" "$len" >&2; return 1; }
                printf 'ie\t%s\t%s\t%s\t%s\t%s\n' "$i" "$pos" "type4" "$iei" "$val"
                pos=$(( pos + 6 + len * 2 )) ;;
        esac
        i=$(( i + 1 ))
    done
    printf 'ies\t%s\n' "$i"
    return 0
}

latt_cmd_24008_parse() {
    local hex="${1:-}"
    [[ -n "$hex" ]] || { printf 'ERROR\tusage: --24008-parse <hex> [iei:fmt ...]\n' >&2; return 2; }
    latt_24008_parse "$hex" "${2:-}"
}

# ── FlashCatch: the catcher that is not noticed (K11) ──────────────────
# Paci, Bologna, Palamà and Bianchi, "FlashCatch: Minimizing Disruption in
# IMSI Catcher Operations", WiSec 2025, doi 10.1145/3734477.3734705.
#
# The published sequence is two moves inside EMM common procedures:
#   1. answer a TAU or Service Request with an Identity Request instead of a
#      reject, which is what TS 24.301 4.4.4.2 allows before security exists,
#      so the IMSI arrives in two messages and no reject is ever sent;
#   2. fail authentication three times in a row afterwards, so the UE marks
#      the cell barred (TS 36.304 5.3.1 holds it for 300 s), returns to its
#      previous cell, and keeps the security context and the TMSI -- because
#      no reject was sent, nothing told it to delete them.
# The model runs the real responder, so the rows below are what this tree
# answers rather than a second description of it.
latt_flashcatch_run() {  # [imsi]
    local imsi="${1:-001010000000001}"
    [[ "$imsi" =~ ^[0-9]{14,15}$ ]] || {
        printf 'ERROR\tnot an IMSI: %s\n' "$(latt_sanitize "$imsi")" >&2; return 2; }

    local tail_id; tail_id=$(latt_imsi_to_eps_mobile_id "$imsi") || {
        printf 'ERROR\tcould not encode the IMSI as an EPS mobile identity\n' >&2; return 1; }
    # A GUTI the FBS has no binding for: that is what makes it ask.
    local tau="07410306F600F110270F3737359255"
    local ir="0756${tail_id}"

    printf 'model\tflashcatch\n'
    printf 'imsi\t%s\n' "$imsi"
    printf 'transcript\tattach or TAU request naming a GUTI -> identity request -> identity response -> three failed authentications\n'

    local i out
    out=$(printf 'reset\nul %s\nul %s\nul 075C14\nul 075C14\nul 075C14\n' "$tau" "$ir" \
        | latt_cmd_nas_responder - --flashcatch 2>&1)
    while IFS= read -r i; do
        case "$i" in
            step$'\t'*|rand$'\t'*|downlink_hex$'\t'*|state$'\t'*) continue ;;
        esac
        printf '%s\n' "$i"
    done <<< "$out"

    local fails banned
    fails=$(printf '%s\n' "$out" | awk -F'\t' '$1=="auth_failure"{n=$2} END{print n+0}')
    banned=$(printf '%s\n' "$out" | awk -F'\t' '$1=="cell_barred"{print $2; exit}')

    printf 'auth_failures\t%s\n' "$fails"
    printf 'capture_messages\t2\n'
    printf 'capture_auth_failures\t%s\n' "$fails"
    printf 'cell_barred\t%s\n' "${banned:-no}"
    printf 'bar_duration_s\t300\n'
    printf 'security_context\tretained\n'
    printf 'tmsi\tretained, so the IMSI is now mapped to a temporary identity\n'
    printf 'naive_path\tTAU or service reject with cause 10, which makes the UE delete the context and reselect for up to 25 s\n'
    printf 'naive_disruption_s\t25\n'
    printf 'flashcatch_disruption_ms\t50\n'
    printf 'disruption_reduction\t500\n'
    printf 'paper_claim\tat least 50x less noticeable disruption and over 200x faster capture (WiSec 2025)\n'
    printf 'what_is_gone\tservice disruption, the indicator a user or a monitor was expected to notice\n'
    printf 'what_remains\tidentity asked for before any security context exists\n'
    printf 'what_remains\tthree consecutive authentication failures with no security mode command between them\n'
    printf 'what_remains\ta cell the UE never returns to for 300 s\n'
    printf 'what_remains\tthe same TMSI before and after, which is the linkability the paper describes\n'
    printf 'detection_shift\tfrom service-level impairment to protocol content: who asked for the IMSI and when\n'
    printf 'ref\tTS 24.301 4.4.4.2 (messages accepted without integrity protection), 5.4.2.7 (repeated authentication failures)\n'
    printf 'ref\tTS 36.304 5.3.1 (a barred cell is not selected for 300 s)\n'
    printf 'ref\tPaci, Bologna, Palamà, Bianchi, WiSec 2025, doi 10.1145/3734477.3734705\n'
    printf 'limit\tthe barring timer and the reselection time are the handset behaviour the paper measured, not something this tree can observe; no radio is involved\n'
    printf 'verdict\tflashcatch_sequence_modelled\n'
}

latt_flashcatch_detect() {  # <tsv: t_s direction nas_hex>
    local file="${1:-}"
    if [[ -z "$file" ]]; then
        printf 'ERROR\tusage: --flashcatch-detect <tsv with t_s, direction, nas_hex>\n' >&2; return 2
    fi
    [[ -r "$file" ]] || { printf 'ERROR\tno readable log at %s\n' "$(latt_sanitize "$file")" >&2; return 1; }

    local rows ir attach fails
    rows=$(awk -F'\t' 'NF>=3 && $1 !~ /^#/ && $3 ~ /^[0-9A-Fa-f]+$/ {n++} END{print n+0}' "$file")
    ir=$(awk -F'\t' 'NF>=3 && $1 !~ /^#/ && tolower($2) ~ /^d/ && toupper(substr($3,3,2))=="55" {n++} END{print n+0}' "$file")
    attach=$(awk -F'\t' 'NF>=3 && $1 !~ /^#/ && tolower($2) ~ /^u/ {t=toupper(substr($3,3,2)); if (t=="41"||t=="48"||t=="4C") n++} END{print n+0}' "$file")
    fails=$(awk -F'\t' 'NF>=3 && $1 !~ /^#/ && tolower($2) ~ /^u/ && toupper(substr($3,3,2))=="5C" {n++} END{print n+0}' "$file")

    printf 'log\t%s\n' "$(latt_sanitize "$file")"
    printf 'rows\t%s\n' "$rows"
    printf 'identity_requests\t%s\n' "$ir"
    printf 'establishment_requests\t%s\n' "$attach"
    printf 'authentication_failures\t%s\n' "$fails"

    local shaped=0
    if (( ir > 0 && attach == 0 )); then
        printf 'finding\tidentity_request_before_establishment HIGH\n'
        printf 'why_1\tthe network asked for an IMSI before the UE told it who it is; TS 24.301 4.4.4.2 is why the UE answers anyway\n'
        shaped=1
    fi
    if (( fails >= 3 )); then
        printf 'finding\tthree_consecutive_auth_failures HIGH\n'
        printf 'why_2\tthree failures with no security mode command is the barring move, not a subscriber with a bad card\n'
        shaped=1
    fi
    if (( shaped )); then
        printf 'verdict\tflashcatch_shaped\n'
    else
        printf 'finding\tno_flashcatch_shape INFO\n'
        printf 'verdict\tno_flashcatch_shape_in_this_log\n'
    fi
    printf 'ref\tWiSec 2025 doi 10.1145/3734477.3734705; TS 24.301 4.4.4.2, 5.4.2.7; TS 36.304 5.3.1\n'
    printf 'limit\tthis reads directions and message types only: it cannot tell a catcher from an operator that asked for an IMSI because it genuinely lost the GUTI\n'
    return 0
}

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
    # 07              octet 1: security header 0 (plain, high nibble) | PD 0x07
    # 41              octet 2: message type 0x41 (ATTACH REQUEST)
    # E2              octet 3: attach type 1 (EPS attach) << 1 | KSI 7 << 5
    #                 0b1110_0010 = 0xE2
    # 08 09 01 <8>    EPS mobile identity, IMSI, length 9, type 1
    local ar
    ar=$(latt_build_attach_request 310150123456789)
    chk attach-octets   "$(( ${#ar} / 2 ))" "14"
    chk attach-hex      "$ar" "0741E208090113100521436587F9"
    chk attach-mt       "${ar:2:2}" "41"
    chk attach-pd       "$(( 16#${ar:0:2} & 0x0F ))" "7"
    chk attach-sh       "$(( 16#${ar:0:2} >> 4 ))" "0"
    chk attach-oct3     "${ar:4:2}" "E2"
    # The three-octet header this module used to write: tshark reads `00 07`
    # as PD 0 (reserved) and finds no message type at all.
    chk attach-no-leading-zero "$(printf '%s' "$ar" | cut -c1-2)" "07"

    # With UE network capability (IEI 0x33) and an ESM container (IEI 0x2D).
    # 0xE0 0xE0 is a commonly seen 2-octet UE network capability
    # (EEA0/EEA1/EIA0/EIA2 style bitmask); the ESM container carries a
    # PDN CONNECTIVITY REQUEST (PD 0x02, PTI 0x01, MT 0xD0, ...).
    # The ESM message container length is TWO octets (0x0005), not one.
    ar=$(latt_build_attach_request 310150123456789 E0E0 0201D00128)
    chk attach-caps-hex "$ar" "0741E208090113100521436587F93302E0E02D00050201D00128"
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
    # EMM is TWO octets: security header type (high nibble) | PD (low), then
    # the message type.  0x07 = plain NAS + EPS mobility management.
    out=$(latt_parse_nas_header "0741E208090113100521436587F9")
    chk hdr-mt       "$(fld "$out" message_type)" "41"
    chk hdr-mt-name  "$(fld "$out" message_name)" "ATTACH REQUEST"
    chk hdr-sh       "$(fld "$out" security_header)" "0"
    chk hdr-sh-name  "$(fld "$out" security_header_name)" "PLAIN NAS"
    chk hdr-plain    "$(fld "$out" plain)" "yes"
    chk hdr-pd       "$(fld "$out" protocol_discriminator)" "07"
    chk hdr-pd-name  "$(fld "$out" protocol_discriminator_name)" "EPS mobility management"
    chk hdr-body     "$(fld "$out" body)" "E208090113100521436587F9"

    # The same octets under an established context: security header 1 moves
    # into the HIGH nibble of octet 1, so the byte is 0x17 and the message
    # type stays at octet 2.
    out=$(latt_parse_nas_header "17550001")
    chk hdr2-sh      "$(fld "$out" security_header)" "1"
    chk hdr2-sh-name "$(fld "$out" security_header_name)" "INTEGRITY PROTECTED"
    chk hdr2-plain   "$(fld "$out" plain)" "no"
    chk hdr2-mt      "$(fld "$out" message_type)" "55"
    out=$(latt_parse_nas_header "27550001")
    chk hdr3-sh      "$(fld "$out" security_header)" "2"
    chk hdr3-sh-name "$(fld "$out" security_header_name)" "INTEGRITY PROTECTED AND NEW EPS SECURITY CONTEXT"

    # ESM is THREE octets: EPS bearer identity (high nibble) | PD 0x02, then
    # the procedure transaction identity, then the message type.
    out=$(latt_parse_nas_header "22012900")
    chk hdr-esm-ebi  "$(fld "$out" eps_bearer_identity)" "2"
    chk hdr-esm-pti  "$(fld "$out" procedure_transaction_identity)" "01"
    chk hdr-esm-pd   "$(fld "$out" protocol_discriminator)" "02"
    chk hdr-esm-mt   "$(fld "$out" message_type)" "29"
    chk hdr-esm-body "$(fld "$out" body)" "00"

    chk hdr-short    "$(latt_parse_nas_header 07 >/dev/null 2>&1; echo $?)" "1"
    chk hdr-esm-short "$(latt_parse_nas_header 2201 >/dev/null 2>&1; echo $?)" "1"
    chk hdr-nonhex   "$(latt_parse_nas_header ZZYY >/dev/null 2>&1; echo $?)" "1"
    chk hdr-oddlen   "$(latt_parse_nas_header 00074 >/dev/null 2>&1; echo $?)" "1"

    # ── 5. Identity exposure: the classic finding ───────────────────────
    # 07 55 01 = plain NAS (SH 0) IDENTITY REQUEST asking for IMSI.
    out=$(latt_identity_exposure "075501"); rc=$?
    chk exposure-rc         "$rc" "0"
    chk exposure-flag       "$(fld "$out" exposure)" "yes"
    chk exposure-type       "$(fld "$out" identity_type_name)" "IMSI"
    chk exposure-severity   "$(fld "$out" severity)" "high"
    chk exposure-sh         "$(fld "$out" security_header)" "0"

    # Same request, but under an established security context
    # (SH 1 = integrity protected) MUST NOT be flagged.
    out=$(latt_identity_exposure "175501"); rc=$?
    chk protected-rc        "$rc" "0"
    chk protected-flag      "$(fld "$out" exposure)" "no"
    chk protected-severity  "$(fld "$out" severity)" "none"
    chk protected-sh        "$(fld "$out" security_header)" "1"

    # SH 2 (integrity protected + new EPS security context) likewise.
    out=$(latt_identity_exposure "275501")
    chk protected2-flag     "$(fld "$out" exposure)" "no"

    # A plain IMEI request is still an exposure, but medium severity.
    out=$(latt_identity_exposure "075502")
    chk exposure-imei-flag  "$(fld "$out" exposure)" "yes"
    chk exposure-imei-name  "$(fld "$out" identity_type_name)" "IMEI"
    chk exposure-imei-sev   "$(fld "$out" severity)" "medium"

    # A non-Identity-Request message is a hard error, not a silent "no".
    chk exposure-wrong-mt   "$(latt_identity_exposure "074101" >/dev/null 2>&1; echo $?)" "1"
    chk exposure-bad-hex    "$(latt_identity_exposure "nothex" >/dev/null 2>&1; echo $?)" "1"

    # ── 6. Full decode of several message types ─────────────────────────
    out=$(latt_decode_nas "0741E208090113100521436587F9")
    chk dec-attach-mt    "$(fld "$out" message_name)" "ATTACH REQUEST"
    chk dec-attach-type  "$(fld "$out" eps_attach_type_name)" "EPS attach"
    chk dec-attach-ksi   "$(fld "$out" nas_key_set_identifier)" "7"

    # Attach reject, cause 15 = "No suitable cells in tracking area".
    out=$(latt_decode_nas "07440F")
    chk dec-reject-name  "$(fld "$out" message_name)" "ATTACH REJECT"
    chk dec-reject-cause "$(fld "$out" emm_cause)" "15"
    chk dec-reject-cname "$(fld "$out" emm_cause_name)" "No suitable cells in tracking area"

    # Attach reject, cause 2 = "IMSI unknown in HSS".
    out=$(latt_decode_nas "074402")
    chk dec-reject2 "$(fld "$out" emm_cause_name)" "IMSI unknown in HSS"

    # Authentication request: RAND(16) || AUTN(16), fixed by TS 33.401.
    local rand="000102030405060708090A0B0C0D0E0F"
    local autn="101112131415161718191A1B1C1D1E1F"
    out=$(latt_decode_nas "0752${rand}${autn}")
    chk dec-auth-mt   "$(fld "$out" message_name)" "AUTHENTICATION REQUEST"
    chk dec-auth-rand "$(fld "$out" rand)" "$rand"
    chk dec-auth-autn "$(fld "$out" autn)" "$autn"
    chk dec-auth-rlen "$(fld "$out" rand_len)" "16"

    # Authentication response carrying an 8-octet RES.
    out=$(latt_decode_nas "0753A1A2A3A4A5A6A7A8")
    chk dec-res     "$(fld "$out" res)" "A1A2A3A4A5A6A7A8"
    chk dec-res-len "$(fld "$out" res_len)" "8"

    # Security mode command: cipher 2 (128-EEA2), integrity 2 (128-EIA2),
    # i.e. octet 4 = 0x22.
    out=$(latt_decode_nas "075D22000000000000")
    chk dec-smc-cipher "$(fld "$out" selected_nas_cipher)" "2"
    chk dec-smc-integ  "$(fld "$out" selected_nas_integrity)" "2"
    chk dec-smc-mac    "$(fld "$out" nas_mac)" "00000000"

    # Security mode complete under integrity protection (SH 1).
    out=$(latt_decode_nas "175E1122334455")
    chk dec-smc-done-mt  "$(fld "$out" message_name)" "SECURITY MODE COMPLETE"
    chk dec-smc-done-mac "$(fld "$out" nas_mac)" "11223344"

    # Detach request, type 1 = EPS detach.
    out=$(latt_decode_nas "074502")
    chk dec-detach-mt   "$(fld "$out" message_name)" "DETACH REQUEST"
    chk dec-detach-type "$(fld "$out" detach_type_name)" "EPS detach"

    # Identity response carrying an IMSI as EPS mobile identity.
    out=$(latt_decode_nas "075608090113100521436587F9")
    chk dec-idresp-mt   "$(fld "$out" message_name)" "IDENTITY RESPONSE"
    chk dec-idresp-type "$(fld "$out" mobile_identity_type)" "IMSI"
    chk dec-idresp-imsi "$(fld "$out" mobile_identity)" "310150123456789"

    # TAU request (0x47) uses the same leading octet layout as attach.
    out=$(latt_decode_nas "0748E208090113100521436587F9")
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
    chk mt-55     "$(latt_msg_type_name 0x55)" "IDENTITY REQUEST"
    chk mt-5d     "$(latt_msg_type_name 0x5d)" "SECURITY MODE COMMAND"
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
    chk pd-lines  "$(latt_parse_nas_header 0741E2 | grep -c '^protocol_discriminator_name')" "1"
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
    chk v-dec-bad          "$(latt_cmd_decode_nas 07 >/dev/null 2>&1; echo $?)" "1"
    chk v-exp-missing      "$(latt_cmd_identity_exposure >/dev/null 2>&1; echo $?)" "2"
    chk v-exp-wrong-mt     "$(latt_cmd_identity_exposure 074101 >/dev/null 2>&1; echo $?)" "1"
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
    chk v-att-hex  "$(fld "$out" nas_hex)" "0741E208090113100521436587F9"
    out=$(latt_cmd_decode_nas 075501)
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
    # ── the middle of an attach (R4) ───────────────────────────────────
    # The message-type table is tshark's own ordering (TS 24.301 §9.8.1), and
    # it used to be shifted by one from 0x4B upward: a TAU request read as a
    # TAU accept and an identity response read as a security mode complete.
    chk mt-0x41   "$(latt_msg_type_name 0x41)" "ATTACH REQUEST"
    chk mt-0x48   "$(latt_msg_type_name 0x48)" "TRACKING AREA UPDATE REQUEST"
    chk mt-0x4b   "$(latt_msg_type_name 0x4b)" "TRACKING AREA UPDATE REJECT"
    chk mt-0x4f   "$(latt_msg_type_name 0x4f)" "SERVICE ACCEPT"
    chk mt-0x55   "$(latt_msg_type_name 0x55)" "IDENTITY REQUEST"
    chk mt-0x56   "$(latt_msg_type_name 0x56)" "IDENTITY RESPONSE"
    chk mt-0x5d   "$(latt_msg_type_name 0x5d)" "SECURITY MODE COMMAND"
    chk mt-0x5e   "$(latt_msg_type_name 0x5e)" "SECURITY MODE COMPLETE"
    chk mt-0x47-unassigned "$(latt_msg_type_name 0x47)" "unassigned"

    # The RRC container: build it, read it back, and check that the identity a
    # UE states inside it comes out again.
    local nas="0741E208090113100521436587F9"
    local rrc rrc_rc
    rrc=$(latt_cmd_setup_complete "$nas" 2>&1); rrc_rc=$?
    chk rrc-build-rc "$rrc_rc" "0"
    chk rrc-message "$(fld "$rrc" rrc_message)" "RRCConnectionSetupComplete"
    chk rrc-plmn "$(fld "$rrc" selected_plmn_identity)" "1"
    chk rrc-nas "$(fld "$rrc" dedicated_info_nas)" "$nas"
    chk rrc-nas-octets "$(fld "$rrc" nas_octets)" "14"
    local rrc_hex; rrc_hex=$(fld "$rrc" rrc_hex)
    chk rrc-hex-envelope "$(printf '%s' "$rrc_hex" | cut -c1-2)" "20"
    chk rrc-hex-octets "$(( ${#rrc_hex} / 2 ))" "$(fld "$rrc" octets)"

    local back; back=$(latt_cmd_parse_setup_complete "$rrc_hex" 2>&1)
    chk rrc-back-nas "$(fld "$back" dedicated_info_nas)" "$nas"
    chk rrc-back-name "$(fld "$back" message_name)" "ATTACH REQUEST"
    chk rrc-back-identity "$(fld "$back" identity)" "310150123456789"
    chk rrc-back-stored "$(fld "$back" identity_stored)" "yes"
    chk rrc-back-kind "$(fld "$back" identity_kind)" "IMSI"
    chk rrc-refused-empty "$(latt_cmd_setup_complete "" >/dev/null 2>&1; echo $?)" "2"
    chk rrc-refused-plmn "$(latt_cmd_setup_complete "$nas" --plmn 9 >/dev/null 2>&1; echo $?)" "2"
    chk rrc-refused-hex "$(latt_cmd_setup_complete 741E2 >/dev/null 2>&1; echo $?)" "2"

    # The responder holds the attach and answers with the network's next
    # message; the IMSI it read is the handover R1/R2/R3 want.
    local session; session=$(printf 'reset\nul 0741E208090113100521436587F9\nul 0743\n' | \
        latt_cmd_nas_responder - 2>&1)
    chk resp-ready "$(fld "$session" responder)" "ready"
    chk resp-state "$(fld "$session" final_state)" "registered"
    chk resp-imsi "$(fld "$session" final_imsi)" "310150123456789"
    chk resp-exchanges "$(fld "$session" exchanges)" "2"
    chk resp-accept "$(printf '%s\n' "$session" | awk -F'\t' '$1=="downlink_hex"{print $2; exit}')" \
        "0742011E5407000100F1100001"
    chk resp-accept-named "$(printf '%s\n' "$session" | awk -F'\t' '$1=="downlink"{print $2; exit}')" \
        "Attach accept"
    # The identity is already in the module's store, whatever the state said.
    chk resp-identity-stored "$(grep -q "nas-responder" "$LATT_IDENT" && echo yes || echo no)" "yes"

    # A GUTI attach names no subscriber: the responder asks, and the limit it
    # states is the one that matters -- the IMSI is requested in the clear.
    local guti_session; guti_session=$(printf 'reset\nul 0741E2080906000102E0A1B2C3D4\n' | \
        latt_cmd_nas_responder - 2>&1)
    chk resp-guti-asks "$(printf '%s\n' "$guti_session" | awk -F'\t' '$1=="downlink"{print $2; exit}')" \
        "Identity request"
    chk resp-guti-state "$(fld "$guti_session" final_state)" "identity-requested"
    chk resp-guti-noimsi "$(fld "$guti_session" final_imsi)" ""

    # ── GUTI: the identity a network issued (R5, parse half) ───────────
    # The octet order is the one tshark reads: PLMN(3) | MME group(2) |
    # MME code(1) | M-TMSI(4). 00 F1 10 12 34 56 DE AD BE EF is therefore
    # 001/01, group 4660, code 86, M-TMSI 0xDEADBEEF -- the same numbers
    # tshark printed for that frame, pinned here so the layout cannot drift.
    export LATT_GUTI_MAP="$d/loot/lte_attach/guti_map.tsv"
    local gut; gut=$(latt_guti_encode 00101 4660 86 3735928559)
    chk guti-encode "$gut" "F600F110123456DEADBEEF"
    local gdec; gdec=$(latt_guti_decode "$gut")
    chk guti-mcc   "$(fld "$gdec" mcc)" "001"
    chk guti-mnc   "$(fld "$gdec" mnc)" "01"
    chk guti-group "$(fld "$gdec" mme_group)" "4660"
    chk guti-code  "$(fld "$gdec" mme_code)" "86"
    chk guti-tmsi  "$(fld "$gdec" m_tmsi)" "3735928559"
    chk guti-name  "$(fld "$gdec" guti)" "001-01-4660-86-3735928559"
    # The same identity arrives in three shapes: bare value, LV and an IE.
    chk guti-decode-ie "$(latt_guti_decode 080BF600F110123456DEADBEEF | awk -F'\t' '$1=="m_tmsi"{print $2; exit}')" "3735928559"
    chk guti-decode-lv "$(latt_guti_decode 0BF600F110123456DEADBEEF | awk -F'\t' '$1=="m_tmsi"{print $2; exit}')" "3735928559"
    chk guti-bad-type "$(latt_guti_decode 080B0100F110123456DEADBEEF >/dev/null 2>&1; echo $?)" "1"
    chk guti-bad-hex  "$(latt_guti_decode ZZ >/dev/null 2>&1; echo $?)" "1"
    # A three-digit MNC round-trips too.
    local gut3; gut3=$(latt_guti_encode 310260 1 2 3)
    chk guti-encode-3mnc "$(latt_guti_decode "$gut3" | awk -F'\t' '$1=="plmn"{print $2; exit}')" "310-260"

    # The binding store: one row per GUTI, attaches counted, upsert not append.
    local out1; out1=$(latt_cmd_guti_map "$gut" 001010000000001)
    chk guti-map-stored "$(fld "$out1" stored)" "001-01-4660-86-3735928559"
    chk guti-map-attaches "$(fld "$out1" attaches)" "1"
    out1=$(latt_cmd_guti_map "$gut" 001010000000001)
    chk guti-map-attaches2 "$(fld "$out1" attaches)" "2"
    chk guti-map-rows "$(( $(grep -c . "$LATT_GUTI_MAP") - 1 ))" "1"
    chk guti-lookup-bound "$(latt_cmd_guti_tsv "$gut" | awk -F'\t' '$1=="imsi"{print $2; exit}')" "001010000000001"
    chk guti-lookup-rc "$(latt_cmd_guti_tsv "$gut" >/dev/null 2>&1; echo $?)" "0"
    chk guti-lookup-miss "$(latt_cmd_guti_tsv F600F110999999DEADBEEF | awk -F'\t' '$1=="bound"{print $2; exit}')" "no"
    chk guti-lookup-miss-rc "$(latt_cmd_guti_tsv F600F110999999DEADBEEF >/dev/null 2>&1; echo $?)" "1"

    # The responder: a GUTI attach asks for the IMSI, the identity response
    # binds the GUTI, and the same GUTI then resolves without asking.
    # A GUTI distinct from the one bound above, so the responder has to ask.
    local guti_hex="080BF600F110270F3737359255"
    local session2; session2=$(printf 'reset\nul 0741E2%s\nul 075608090100010100000000F1\n' \
        "$guti_hex" | latt_cmd_nas_responder - 2>&1)
    chk guti-resp-asks "$(printf '%s\n' "$session2" | awk -F'\t' '$1=="downlink"{print $2; exit}')" \
        "Identity request"
    chk guti-resp-binds "$(printf '%s\n' "$session2" | awk -F'\t' '$1=="guti_bound"{print $2; exit}')" \
        "001-01-9999-55-926257749"
    chk guti-resp-bound-imsi "$(printf '%s\n' "$session2" | awk -F'\t' '$1=="guti_bound_imsi"{print $2; exit}')" \
        "001010000000001"
    local session3; session3=$(printf 'reset\nul 0741E2%s\n' "$guti_hex" | \
        latt_cmd_nas_responder - 2>&1)
    chk guti-resp-resolves "$(printf '%s\n' "$session3" | awk -F'\t' '$1=="resolved_by"{print $2; exit}')" \
        "guti binding"
    chk guti-resp-accept "$(printf '%s\n' "$session3" | awk -F'\t' '$1=="downlink"{print $2; exit}')" \
        "Attach accept"

    # ── GUTI reallocation observation ─────────────────────────────────
    # One old GUTI and one new one, both valid to latt_guti_value: type 6
    # (GUTI) then PLMN/MME group/MME code/M-TMSI.
    local rg1="06f4701000010102030405" rg2="06f4701000020202030406"
    local rec; rec=$(latt_realloc_record "$rg1" "$rg2" --imsi 204080000000001 2>&1)
    chk realloc-recorded   "$(printf '%s\n' "$rec" | awk -F'\t' '$1=="recorded"{print $2; exit}')" "yes"
    chk realloc-old-guti   "$(printf '%s\n' "$rec" | awk -F'\t' '$1=="old_guti"{print $2; exit}')" "4150-017-1-1-33752069"
    chk realloc-new-guti   "$(printf '%s\n' "$rec" | awk -F'\t' '$1=="new_guti"{print $2; exit}')" "4150-017-2-2-33752070"
    local rts; rts=$(printf '%s\n' "$rec" | awk -F'\t' '$1=="observed_at"{print $2; exit}')
    [[ "$rts" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || {
        bad=$((bad+1)); printf 'realloc-stamped\tFAIL format=%s\n' "$rts"; }
    local chain; chain=$(latt_cmd_realloc_chain "$rg1" 2>&1)
    chk realloc-chain-next "$(printf '%s\n' "$chain" | awk -F'\t' '$1=="next"{print $2; exit}')" "4150-017-2-2-33752070"
    chk realloc-chain-hops "$(printf '%s\n' "$chain" | awk -F'\t' '$1=="hops"{print $2; exit}')" "1"
    local list; list=$(latt_cmd_realloc_list 2>&1)
    chk realloc-list-n     "$(printf '%s\n' "$list" | awk -F'\t' '$1=="REALLOC_COUNT"{print $2; exit}')" "1"
    # a command that does not carry an identity refuses
    local badcmd; badcmd=$(latt_realloc_command "00" 2>&1); local badcmd_rc=$?
    chk realloc-cmd-refuses-rc "$badcmd_rc" "2"
    chk realloc-cmd-refuses    "$(printf '%s\n' "$badcmd" | awk -F'\t' '$1=="ERROR"{print $2; exit}')" \
        "the command does not carry an EPS mobile identity"
    # a reallocation that carries an IMSI instead of a GUTI says so and returns 1
    local imsicmd; imsicmd=$(latt_realloc_command "010f10f4700000000001" 2>&1); local imsicmd_rc=$?
    chk realloc-cmd-imsi-rc    "$imsicmd_rc" "1"
    chk realloc-cmd-imsi-note  "$(printf '%s\n' "$imsicmd" | awk -F'\t' '$1=="reallocated_identity"{print $2; exit}')" "IMSI"
    rm -f "$LATT_REALLOC"

    # ── TS 24.008 GMM/SM: header, IE formats, and the read-back ────────
    local m41; m41=$(latt_cmd_24008_build 08 41 00 't1:1:' 't3:19:4121' 2>&1)
    chk m24008-pd      "$(printf '%s\n' "$m41" | awk -F'\t' '$1=="pd_name"{print $2; exit}')" \
        "GPRS mobility management (GMM)"
    chk m24008-type    "$(printf '%s\n' "$m41" | awk -F'\t' '$1=="message_type"{print $2; exit}')" "41"
    chk m24008-name    "$(printf '%s\n' "$m41" | awk -F'\t' '$1=="message_name"{print $2; exit}')" "ATTACH REQUEST"
    chk m24008-domain  "$(printf '%s\n' "$m41" | awk -F'\t' '$1=="message_domain"{print $2; exit}')" "GMM"
    chk m24008-ies     "$(printf '%s\n' "$m41" | awk -F'\t' '$1=="ies"{print $2; exit}')" "2"
    chk m24008-hex     "$(printf '%s\n' "$m41" | awk -F'\t' '$1=="hex"{print $2; exit}')" "0800411019024121"
    chk m24008-octets  "$(printf '%s\n' "$m41" | awk -F'\t' '$1=="octets"{print $2; exit}')" "8"
    # formats: t1 is a nibble, t2 one octet, t3 one length octet, t4 two
    chk m24008-t1      "$(latt_24008_ie t1 1 '' 2>&1)" "10"
    chk m24008-t2      "$(latt_24008_ie t2 17 05 2>&1)" "1705"
    chk m24008-t3      "$(latt_24008_ie t3 28 0102 2>&1)" "28020102"
    chk m24008-t4      "$(latt_24008_ie t4 33 0102 2>&1)" "3300020102"
    chk m24008-v       "$(latt_24008_ie v 00 dead 2>&1)" "dead"
    chk m24008-badfmt  "$(latt_24008_ie t9 1 00 >/dev/null 2>&1; echo $?)" "2"
    chk m24008-t1-len  "$(latt_24008_ie t1 1 00 >/dev/null 2>&1; echo $?)" "2"
    chk m24008-t3-long "$(latt_24008_ie t3 1 "$(printf '00%.0s' {1..256})" >/dev/null 2>&1; echo $?)" "2"
    chk m24008-ti      "$(latt_24008_ti 5 2>&1)" "50"
    chk m24008-ti-bad  "$(latt_24008_ti 9 >/dev/null 2>&1; echo $?)" "2"
    chk m24008-nopd    "$(latt_cmd_24008_build 09 41 00 >/dev/null 2>&1; echo $?)" "2"
    chk m24008-noargs  "$(latt_cmd_24008_build >/dev/null 2>&1; echo $?)" "2"
    # the SM family and the transaction identifier header
    local m41s; m41s=$(latt_cmd_24008_build 02 41 "$(latt_24008_ti 3)" 't3:28:6d6e633030312e6d63633030312e67707273' 2>&1)
    chk m24008-sm-name   "$(printf '%s\n' "$m41s" | awk -F'\t' '$1=="message_name"{print $2; exit}')" "ACTIVATE PDP CONTEXT REQUEST"
    chk m24008-sm-domain "$(printf '%s\n' "$m41s" | awk -F'\t' '$1=="message_domain"{print $2; exit}')" "SM"
    chk m24008-sm-ti     "$(latt_24008_parse "$(printf '%s\n' "$m41s" | awk -F'\t' '$1=="hex"{print $2; exit}')" 2>&1 | awk -F'\t' '$1=="transaction_id"{print $2; exit}')" "3"
    # read back the GMM message: the walk needs the caller's format map
    local p41; p41=$(latt_24008_parse 0800411019024121 '1:t1 19:t3' 2>&1)
    chk m24008-parse-skip  "$(printf '%s\n' "$p41" | awk -F'\t' '$1=="ti_or_skip"{print $2; exit}')" "skip_indicator"
    chk m24008-parse-ies   "$(printf '%s\n' "$p41" | awk -F'\t' '$1=="ies"{print $2; exit}')" "2"
    chk m24008-parse-f1    "$(printf '%s\n' "$p41" | awk -F'\t' '$1=="ie" && $2==0{print $4; exit}')" "type1"
    chk m24008-parse-v1    "$(printf '%s\n' "$p41" | awk -F'\t' '$1=="ie" && $2==0{print $6; exit}')" "0"
    chk m24008-parse-f2    "$(printf '%s\n' "$p41" | awk -F'\t' '$1=="ie" && $2==1{print $4; exit}')" "type3"
    chk m24008-parse-v2    "$(printf '%s\n' "$p41" | awk -F'\t' '$1=="ie" && $2==1{print $6; exit}')" "4121"
    chk m24008-parse-nomap "$(latt_24008_parse 0800411019024121 2>&1 | grep -c 'an IEI number means a different IE')" "1"
    chk m24008-parse-unmapped "$(latt_24008_parse 0800411019024121 '19:t3' 2>&1 | awk -F'\t' '$1=="ie"{print $4; exit}')" "unmapped"
    chk m24008-parse-short "$(latt_24008_parse 0800 >/dev/null 2>&1; echo $?)" "1"
    chk m24008-parse-noarg "$(latt_cmd_24008_parse >/dev/null 2>&1; echo $?)" "2"
    # the message tables name the families the row asked about
    chk m24008-gmm-rau  "$(latt_24008_gmm_name 48 2>&1)" "ROUTING AREA UPDATE REQUEST"
    chk m24008-gmm-detach "$(latt_24008_gmm_name 46 2>&1)" "DETACH ACCEPT"
    chk m24008-sm-deact "$(latt_24008_sm_name 46 2>&1)" "DEACTIVATE PDP CONTEXT REQUEST"
    chk m24008-unknown  "$(latt_24008_gmm_name 7f >/dev/null 2>&1; echo $?)" "1"


    # FlashCatch (K11) — the sequence, and the detector that reads it back.
    local fcout fcbad fcg o1 o2
    fcout=$(latt_flashcatch_run 001010000000001 2>&1)
    chk fc-capture   "$(fld "$fcout" capture_messages)" "2"
    chk fc-fails     "$(fld "$fcout" capture_auth_failures)" "3"
    chk fc-barred    "$(fld "$fcout" cell_barred)" "yes"
    chk fc-bar-s     "$(fld "$fcout" bar_duration_s)" "300"
    chk fc-context   "$(fld "$fcout" security_context)" "retained"
    chk fc-verdict   "$(fld "$fcout" verdict)" "flashcatch_sequence_modelled"
    chk fc-paper     "$(printf '%s\n' "$fcout" | grep -c '3734477.3734705')" "1"
    chk fc-rot       "$(latt_flashcatch_run 12345 >/dev/null 2>&1; echo $?)" "2"

    fcbad=$(mktemp); fcg=$(mktemp)
    printf 't_s\tdirection\tnas_hex\n' > "$fcbad"
    printf '0.000\tdl\t075501\n0.030\tul\t07560809010001010000000000F1\n' >> "$fcbad"
    printf '0.140\tul\t075C14\n0.220\tul\t075C14\n0.300\tul\t075C14\n' >> "$fcbad"
    printf 't_s\tdirection\tnas_hex\n' > "$fcg"
    printf '0.000\tul\t07410306F600F110270F3737359255\n0.040\tdl\t075501\n' >> "$fcg"
    o1=$(latt_flashcatch_detect "$fcbad" 2>&1)
    o2=$(latt_flashcatch_detect "$fcg" 2>&1)
    chk fc-detect-ir    "$(fld "$o1" identity_requests)" "1"
    chk fc-detect-fails "$(fld "$o1" authentication_failures)" "3"
    chk fc-detect-shape "$(fld "$o1" verdict)" "flashcatch_shaped"
    chk fc-detect-find  "$(printf '%s\n' "$o1" | grep -c '^finding')" "2"
    chk fc-detect-clean "$(fld "$o2" verdict)" "no_flashcatch_shape_in_this_log"
    chk fc-detect-noarg "$(latt_flashcatch_detect >/dev/null 2>&1; echo $?)" "2"
    chk fc-detect-nofile "$(latt_flashcatch_detect /nonexistent 2>/dev/null; echo $?)" "1"
    rm -f "$fcbad" "$fcg"

    rm -f "$LATT_REALLOC"

    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ── menu ────────────────────────────────────────────────────────────────
latt_menu() {
    while true; do
        banner
        echo -e "  ${C_MAG}=== LTE Attach Forge ===${C_RESET}"
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
        --setup-complete)   latt_cmd_setup_complete "$@" ;;
        --parse-setup-complete) latt_cmd_parse_setup_complete "${1:-}" ;;
        --nas-responder)    latt_cmd_nas_responder "${1:--}" "${2:-}" ;;
        --guti-decode)      latt_cmd_guti_decode "${1:-}" ;;
        --guti-map)         latt_cmd_guti_map "${1:-}" "${2:-}" ;;
        --guti-tsv)         latt_cmd_guti_tsv "${1:-}" ;;
        --realloc-command)  latt_realloc_command "${1:-}" ;;
        --realloc-record)   latt_realloc_record "${1:-}" "${2:-}" "${@:3}" ;;
        --realloc-list)     latt_cmd_realloc_list ;;
        --realloc-chain)    latt_cmd_realloc_chain "${1:-}" ;;
        --flashcatch)       latt_flashcatch_run "${1:-}" ;;
        --flashcatch-detect) latt_flashcatch_detect "${1:-}" ;;
        --24008-build)      latt_cmd_24008_build "$@" ;;
        --24008-parse)      latt_cmd_24008_parse "${1:-}" "${2:-}" ;;
        --doltest)          latt_doltest_cases ;;
        --doltest-check)    latt_doltest_check "${1:-}" ;;
        --ue-stack)         latt_require_ue_stack ;;
        --selftest)         latt_selftest ;;
        --menu)             latt_menu ;;
        *)
            cat >&2 <<EOF
LTE Attach Forge — EPS Mobility Management encode and decode (TS 24.301)

Usage: $0 COMMAND
  --status-tsv                 module state as TSV
  --decode-nas <hex>           parse an EMM message header and its IEs
  --setup-complete <nas_hex> [--plmn n] [--tx n]
                             the UE's RRCConnectionSetupComplete on UL-DCCH,
                             carrying the first NAS PDU (TS 36.331 6.2.2)
  --parse-setup-complete <rrc_hex>
                             read that container back: the selected PLMN, the
                             NAS PDU, and the identity the UE stated
  --nas-responder [<file>]   hold the attach state: each "ul <hex>" line is a
                             UE NAS PDU, and the answering lines carry the
                             network's next message. State persists in
                             $STATE_DIR/lte_attach/ue.tsv
  --guti-decode <hex>        read a GUTI: PLMN, MME group, MME code, M-TMSI
  --guti-map <hex> <imsi>    bind a GUTI to the IMSI behind it
  --guti-tsv [<hex>]         the bindings, or one looked up by GUTI
  --realloc-command <hex>    decode a GUTI REALLOCATION COMMAND (new GUTI, TAI, cause)
  --realloc-record <old> <new> [--imsi IMSI] [--cause HEX]
                             record one old->new replacement
  --realloc-list             every recorded replacement
  --realloc-chain <guti>     walk old -> new -> current
  --doltest                  the negative-test corpus (id, clause, expectation)
  --doltest-check <id>       drive one case through the responder and compare
  --flashcatch [IMSI]        model the low-disruption catcher: identity first, no reject,
                               then three failed authentications that bar the cell
  --flashcatch-detect <tsv>  read a NAS log for that shape (identity before establishment,
                             three failures, no security mode command)
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
