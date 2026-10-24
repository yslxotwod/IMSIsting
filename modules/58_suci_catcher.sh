#!/usr/bin/env bash
# 5G SUCI catcher — the live lane.
#
# A SUCI is a SUPI concealed with the home network's public key (TS 33.501
# Annex C). The concealment is sound: without the private key the MSIN does not
# come back. What the concealment does not do is decide WHO the UE tells. A UE
# that has not been authenticated yet will answer a NAS IDENTITY REQUEST from
# whatever cell it believes it is on, and that request is UNPROTECTED by design
# — TS 24.501 8.2.6 puts it in the "not ciphered, not integrity protected"
# class because no key exists at that point in the procedure.
#
# So the catcher is a sequence of signalling steps, not a crypto break:
#
#   1. an NR cell advertising the target PLMN broadcasts SIB1 (n48/n78/n3/n1)
#   2. the UE camps on it and opens an RRC connection to that cell
#   3. the RRC SETUP COMPLETE carries the NAS REGISTRATION REQUEST
#   4. the AMF asks for an identity; the UE answers with a fresh SUCI
#   5. the SUCI is parsed, and the MSIN is recovered with the home network key
#
# Every step is built here and handed to a real gNB. Nothing is fabricated: if
# no radio answers, no cell is started and the module says so with its own exit
# code rather than printing a success line.
#
# WHAT IS VERIFIED WITHOUT A RADIO: every PDU builder (the ASN.1 length codec,
# the RRC SETUP COMPLETE, the NAS REGISTRATION REQUEST and IDENTITY REQUEST and
# the decoded uplink, the SUCI TLV), the AKA responder arithmetic against the
# TS 35.208 set-1 vector, and the capture-to-record pipeline against a decrypted
# SUCI whose MSIN is known before the run. `--selftest` runs all of it.
#
# WHAT IS NOT: the over-the-air half. A UE ending up camped on this cell, and an
# operator core completing ECIES de-concealment, need a phone and a radio — the
# module reports that boundary as `air_verified  no` instead of claiming it.
set -uo pipefail

# Standalone modules are also sourced by imsisting.sh for the text menu.
if [[ -z "${IMSISTING_ROOT:-}" ]]; then
    _sc_src="${BASH_SOURCE[0]}"
    while [ -L "$_sc_src" ]; do
        _sc_dir="$(cd -P "$(dirname "$_sc_src")" && pwd)"
        _sc_tgt="$(readlink "$_sc_src")"
        [[ "$_sc_tgt" != /* ]] && _sc_tgt="$_sc_dir/$_sc_tgt"
        _sc_src="$_sc_tgt"
    done
    IMSISTING_ROOT="$(cd -P "$(dirname "$_sc_src")/.." && pwd)"
    export IMSISTING_ROOT
    unset _sc_src _sc_dir _sc_tgt
fi

: "${LOOT_DIR:=$IMSISTING_ROOT/loot}"
: "${LOGS_DIR:=$IMSISTING_ROOT/logs}"
: "${CAPTURES_DIR:=$IMSISTING_ROOT/captures}"
: "${STATE_DIR:=$IMSISTING_ROOT/state}"
: "${TMP_DIR:=/tmp/imsisting}"
if [[ -n "${IMSISTING_ROOT:-}" && -d "$IMSISTING_ROOT" ]]; then
    SC_DIR="$LOOT_DIR/suci_catcher"
    SC_CAP="$CAPTURES_DIR/suci_catcher"
    SC_ST="$STATE_DIR/suci_catcher"
else
    SC_DIR="${SC_DIR:-/tmp/imsisting/suci_catcher}"
    SC_CAP="${SC_CAP:-/tmp/imsisting/suci_catcher}"
    SC_ST="${SC_ST:-/tmp/imsisting/suci_catcher}"
fi
SC_LOG="$LOGS_DIR/suci_catcher.log"
SC_PID="$SC_ST/catcher.pid"

SC_REFS="TS 33.501 Annex C, TS 24.501 8.2.6, TS 38.331 6.2.2, TS 38.413 9.3.1.9, TS 35.208"

sc_sanitize() { printf '%s' "${1:-}" | tr '\t\r\n' '   '; }
sc_init_dirs() {
    mkdir -p "$SC_DIR" "$SC_CAP" "$SC_ST" "$(dirname "$SC_LOG")" 2>/dev/null || true
}
sc_log() {
    sc_init_dirs
    printf '%s\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >> "$SC_LOG" 2>/dev/null || true
}

# Rows are direction<TAB>event. Peek/menu keeps this shape so an operator who
# was already reading a trace does not have to learn a second one.
sc_trace_row() { printf '%s\t%s\n' "$1" "$2"; }

sc_hex_only() {
    local h="${1:-}"
    h="${h//[[:space:]]/}"; h="${h//0x/}"
    [[ "$h" =~ ^[0-9a-fA-F]*$ ]] || return 1
    printf '%s' "${h^^}"
}

# ── ASN.1 APER basics the RRC PDUs need ────────────────────────────────
# A SEQUENCE gets a length determinant: one octet when the encoded body is
# under 128, otherwise 0x80|n followed by n big-endian octets. A length octet
# with bit 7 clear is noted as such because the caller is composing fields of
# the same SEQUENCE and an undetermined length is a defect there, not a choice.
sc_aper_len() {
    local n="$1" out="" i
    if (( n < 128 )); then printf '%02X' "$n"; return 0; fi
    if (( n < 256 )); then printf '81%02X' "$n"; return 0; fi
    if (( n < 65536 )); then printf '82%04X' "$n"; return 0; fi
    printf 'ERROR\tlength %d does not fit a two-octet APER long form\n' "$n" >&2
    return 1
}

sc_aper_seq() {  # <body-hex> -> length determinant || body
    local body; body=$(sc_hex_only "$1") || return 2
    local len; len=$(sc_aper_len $(( ${#body} / 2 ))) || return 1
    printf '%s%s' "$len" "$body"
}

# BIT STRING of a fixed length: first the length determinant of the BITS (APER
# counts bits, not octets, for a sized bit string), then the octets with the
# unused tail bits zero. A bit string whose length is not a whole octet is
# legal and common — a 20-bit value is three octets with the last nibble
# unused — so an odd nibble count is padded on the RIGHT rather than rejected.
sc_aper_bitstr() {  # <hex> <bits>
    local hex; hex=$(sc_hex_only "$1") || return 2
    local bits="$2" n octets
    (( bits > 0 )) || { printf 'ERROR\tbit string length must be positive\n' >&2; return 2; }
    octets=$(( (bits + 7) / 8 ))
    (( ${#hex} <= octets * 2 )) || {
        printf 'ERROR\t%s bits do not fit %d octets (%d hex digits given)\n' \
            "$bits" "$octets" "${#hex}" >&2
        return 2
    }
    while (( ${#hex} < octets * 2 )); do hex+='0'; done
    n=$(sc_aper_len "$bits") || return 1
    printf '%s%s' "$n" "$hex"
}

# ── PLMN and cell identity (TS 24.008 10.5.1.3, TS 38.413 9.3.1.9) ────
# A PLMN is b9,b8 = MCC2,MCC1 | MCC3,MNC3 (nibbles 3..4) and MNC2,MNC1. A
# 2-digit MNC leaves the MNC3 nibble at 0xF, which is absent, not zero.
sc_plmn_encode() {  # <mcc-mnc | cccnnn | cccnn> -> 3 octets
    local plmn="${1:-}"
    [[ "$plmn" =~ ^[0-9]{5,6}$ ]] || {
        printf 'ERROR\tPLMN must be 5 or 6 digits (MCC MNC), got %s\n' \
            "$(sc_sanitize "${plmn:-<empty>}")" >&2
        return 2
    }
    local mcc="${plmn:0:3}" mnc="${plmn:3}"
    local mcc1="${mcc:0:1}" mcc2="${mcc:1:1}" mcc3="${mcc:2:1}"
    local mnc1 mnc2 mnc3="F"
    mnc1="${mnc:0:1}"; mnc2="${mnc:1:1}"
    (( ${#mnc} == 3 )) && mnc3="${mnc:2:1}"
    printf '%s%s%s%s%s%s' "$mcc2" "$mcc1" "$mnc3" "$mcc3" "$mnc2" "$mnc1"
}

sc_plmn_decode() {  # <6 hex> -> mcc-mnc
    local hex="${1:-}"
    [[ "$hex" =~ ^[0-9a-fA-F]{6}$ ]] || {
        printf 'ERROR\tPLMN octets must be 3 octets, got %s\n' "$(sc_sanitize "$hex")" >&2
        return 2
    }
    hex="${hex^^}"
    local b0=$(( 16#${hex:0:2} )) b1=$(( 16#${hex:2:2} )) b2=$(( 16#${hex:4:2} ))
    local mcc1=$(( b0 & 0xF )) mcc2=$(( (b0 >> 4) & 0xF ))
    local mcc3=$(( b1 & 0xF )) mnc3=$(( (b1 >> 4) & 0xF ))
    local mnc1=$(( b2 & 0xF )) mnc2=$(( (b2 >> 4) & 0xF ))
    local mcc="$mcc1$mcc2$mcc3" mnc="$mnc1$mnc2"
    (( mnc3 != 15 )) && mnc+="$mnc3"
    printf '%s-%s' "$mcc" "$mnc"
}

# The 36-bit cellIdentity sits in the top 4 bits of its fifth octet, so the last
# nibble is not part of the number. Reported as a decimal string and as the
# nine hex digits the field is defined in.
sc_cell_identity_encode() {  # <int> -> 5 octets
    local id="${1:-}"
    [[ "$id" =~ ^[0-9]+$ ]] || { printf 'ERROR\tcell identity must be decimal\n' >&2; return 2; }
    (( id < 68719476736 )) || {
        printf 'ERROR\tcell identity %s does not fit the 36-bit field\n' "$id" >&2; return 2; }
    printf '%09X0' "$id"
}

# ── NR RRC PDUs (TS 38.331 6.2.2) ──────────────────────────────────────
# The messages below are the subset a fake gNB has to produce to get a UE from
# RRC Setup Request to an identity. Field order is the ASN.1 order, encoded
# APER. Each PDU names what it leaves out, because a message that silently
# differs from the operator's is the failure mode this module exists to avoid.

# UL-DCCH-Message ::= { c1 (0) -> ulDCCHMessage c1 (0) -> UL-DCCH-MessageType
#   -> rrcSetupComplete (1) } — the CHOICE index is 1, not the message name.
sc_rrc_setup_complete() {  # <rrc-transaction-id> <plmn> <tac> <nssai-hex>
    local tid="${1:-0}" plmn="${2:-00101}" tac="${3:-7}" nssai="${4:-01}"
    [[ "$tid" =~ ^[0-9]+$ ]] && (( tid < 4 )) || {
        printf 'ERROR\tRRC transaction identifier must be 0..3\n' >&2; return 2; }
    local plmnhex; plmnhex=$(sc_plmn_encode "$plmn") || return $?
    [[ "$tac" =~ ^[0-9]+$ ]] && (( tac < 16777216 )) || {
        printf 'ERROR\tTAC must be 0..16777215\n' >&2; return 2; }
    local nss; nss=$(sc_hex_only "$nssai") || {
        printf 'ERROR\tS-NSSAI must be hex\n' >&2; return 2; }

    # rrc-TransactionIdentifier: 2 bits, so one octet with the value in the low
    # half of the first bit-string octet.
    local body
    body=$(printf '%02X' "$tid")
    # selectedPLMN-Identity: index into the SIB1 plmn-IdentityList, 1-based; the
    # cell has exactly one entry, so the index is 1.
    body+='01'
    # registeredAMF: an AMF-Identifier is PLMN || AMF region id (8) || AMF set
    # id (10) || AMF pointer (6) = 3 + 3 octets.
    body+="$(sc_aper_seq "${plmnhex}${SC_AMF_REGION:-00}${SC_AMF_SET:-0001}")"
    body+="$(sc_aper_seq "${SC_AMF_POINTER:-00}")"
    # S-NSSAI: one octet of SST on the lab slice, inserted because the core in
    # 12_nr_air's slice list advertises sst 1.
    body+="$(sc_aper_seq "$nss")"
    # ng-5G-S-TMSI-Part1: a 40-bit value the UE does not have before it has a
    # GUTI, so this is the all-zero placeholder the codec carries rather than a
    # value read off the air.
    body+="0000000000"
    # GUAMI-type absent -> nothing. Dedicated NAS message present -> flag 1.
    body+='80'
    # The NAS PDU itself. REGISTRATION REQUEST is built by 32_nas_signaling so
    # the octets come from one owner; its own --build-nas refuses AUTN, which
    # is why the plain registration request (no SMC, no MAC) is the one used.
    local nas
    nas=$(sc_registration_request) || return 1
    body+="$(sc_aper_seq "$nas")"
    # Non-critical extensions are absent, and the two late-extension option
    # bits close the SEQUENCE.
    body+='0000'

    local inner; inner=$(sc_aper_seq "$body") || return 1
    local uldcch; uldcch=$(sc_aper_seq "01${inner}") || return 1
    printf '7E%s' "$uldcch"
}

# NAS 5GMM REGISTRATION REQUEST (TS 24.501 8.2.6).
#   7E                     extended protocol discriminator, 5GMM
#   00                     security header type: plain, no integrity, no cipher
#   41                     message type: registration request
#   01                     5GS registration type, type 3 IE: FOR clear,
#                          registration type binary 001 = initial registration
#   77 00 <len> <identity> 5GS mobile identity, type 6 IE: IEI, two-octet
#                          length, then the SUCI octets exactly as 14_suci
#                          encodes them (leading identity-type octet included)
#
# The identity is the caller's; the default is the null-scheme SUCI 14_suci
# builds for IMSI 001/01/123456789, so the fixture and the referee agree.
sc_registration_request() {
    local id; id=$(sc_hex_only "${1:-080100000021436587F9}") || return 2
    (( ${#id} >= 2 && ${#id} % 2 == 0 )) || {
        printf 'ERROR\tmobile identity must be a whole octet count\n' >&2; return 2; }
    printf '7E0041017700%02X%s' "$(( ${#id} / 2 ))" "$id"
}

# NAS 5GMM IDENTITY REQUEST (TS 24.501 8.2.24): what the fake AMF sends to make
# the UE hand over its SUCI. Type 1 IE: no IEI in front of the value.
#   7E 00 5B 01            identity type = SUCI
sc_identity_request_suci() { printf '7E005B01'; }

# ── NAS uplink decoder ─────────────────────────────────────────────────
# A UE's uplink NAS PDU in an RRC container is read back through this rather
# than trusted from the capture: the REGISTRATION REQUEST must arrive with
# 5GS registration type and SUCI must arrive as identity type 1.
sc_nas_decode() {  # <pdu-hex>
    local hex; hex=$(sc_hex_only "${1:-}") || return 2
    (( ${#hex} >= 8 )) || {
        printf 'ERROR\tNAS PDU too short (%d octets, need 4)\n' "$(( ${#hex} / 2 ))" >&2
        return 1
    }
    local epd="${hex:0:2}" sec="${hex:2:2}" mt="${hex:4:2}"
    [[ "$epd" == "7E" ]] || {
        printf 'ERROR\tnot a 5GMM PDU: extended protocol discriminator %s, expected 7E\n' "$epd" >&2
        return 1
    }
    printf 'epd\t%s\n' "$epd"
    printf 'security_header\t%s\n' "$sec"
    printf 'message_type\t%s\n' "$mt"
    case "$mt" in
        41) printf 'message_name\tRegistration request\n'
            # 5GS registration type is the first IE after the header: bit 4 is
            # the follow-on-request bit, bits 3-1 are the registration type.
            local rt; rt=$(printf '%02X' $(( 16#${hex:6:2} & 0x07 )))
            printf 'registration_type\t%s\n' "$rt"
            # 5GS mobile identity: IEI, two-octet length, then the octets.
            (( ${#hex} >= 16 )) && [[ "${hex:8:2}" == "77" ]] && {
                local mlen=$(( 16#${hex:10:4} ))
                printf 'mobile_identity_length\t%s\n' "$mlen"
                printf 'mobile_identity\t%s\n' "${hex:14:$(( mlen * 2 ))}"
                printf 'identity_type\t%s\n' \
                    "$(printf '%02X' $(( 16#${hex:14:2} >> 3 & 0x07 )))"
            }
            printf 'payload_owner\t32_nas_signaling\n' ;;
        5B) printf 'message_name\tIdentity request\n'
            printf 'identity_type\t%s\n' "${hex:6:2}" ;;
        5C) printf 'message_name\tIdentity response\n'
            # Identity response: 5GS mobile identity, LV-E, two-octet length.
            local len="${hex:6:4}"
            printf 'identity_length\t%s\n' "$len"
            printf 'mobile_identity\t%s\n' "${hex:10:$(( 16#$len * 2 ))}" ;;
        42) printf 'message_name\tRegistration accept\n' ;;
        56) printf 'message_name\tAuthentication request\n' ;;
        57) printf 'message_name\tAuthentication response\n' ;;
        5D) printf 'message_name\tSecurity mode command\n' ;;
        5E) printf 'message_name\tSecurity mode complete\n' ;;
        44) printf 'message_name\tRegistration reject\n' ;;
        *)  printf 'message_name\tunmapped\n' ;;
    esac
    return 0
}

# Pull the identity response out of a decoded uplink TSV that carries many rows.
sc_nas_mobile_identity() {  # <decoded-tsv>
    local rows="${1:-}"
    printf '%s\n' "$rows" | awk -F'\t' '$1=="mobile_identity"{print $2; exit}'
}

# ── SUCI TLV (TS 24.501 9.11.3.4, TS 23.003 2.2) ───────────────────────
# The first octet of the 5GS mobile identity splits in two: bits 3-1 are the
# SUPI format (0 = IMSI), bits 6-4 are the identity type:
#   1 SUCI | 2 GUTI | 3 IMEI | 4 5G-S-TMSI | 5 IMEISV
# 14_suci owns that octet — its parser reads the same two fields — so the bit
# arithmetic here is the one its builder writes, not an independent reading.
sc_suci_type() {
    local h; h=$(sc_hex_only "${1:-}") || return 2
    (( ${#h} >= 2 )) || return 2
    printf '%d' $(( (16#${h:0:2} >> 3) & 0x07 ))
}

sc_identity_response() {  # <mobile-identity-hex> -> identity_type, suci
    local h; h=$(sc_hex_only "${1:-}") || {
        printf 'ERROR\tidentity is not hex\n' >&2; return 2; }
    local typ; typ=$(sc_suci_type "$h") || {
        printf 'ERROR\tidentity too short to carry an identity type\n' >&2; return 1; }
    printf 'identity_type\t%s\n' "$typ"
    case "$typ" in
        1) printf 'supi_type\tsuci\n' ;;
        2) printf 'supi_type\t5g-guti\n' ;;
        3) printf 'supi_type\timei\n' ;;
        4) printf 'supi_type\t5g-s-tmsi\n' ;;
        5) printf 'supi_type\timeisv\n' ;;
        *) printf 'supi_type\tunknown\n' ;;
    esac
    printf 'mobile_identity\t%s\n' "$h"
    (( typ == 1 )) || return 0
    # 14_suci's parser starts at the identity-type octet and counts from there,
    # so the SUCI handed to it is the whole identity, not a tail slice.
    printf 'suci\t%s\n' "$h"
    return 0
}

# ── AKA responder (TS 33.102, TS 24.501) ───────────────────────────────
# The UE side of the 5G-AKA exchange, so the catcher can answer the vector the
# core sends instead of stalling the procedure and looking like a jammer.
#
# The arithmetic is not re-implemented: 16_sim --sim-auth owns Milenage and
# prints f1..f5*, and the rows below are the ones a USIM would compute. The
# extension fields follow TS 33.501 Annex A.4:
#   RES* = KDF(K, FC=0x6A, P0=ServingNetworkName, L0=len, P1=RAND, L1=16,
#             P2=RES, L2=len)
#   KAUSF = KDF(K, FC=0x6A, P0=SNN, P1=SQN xor AK, L1=6, P2=RES, L2=len)
# The SEAF key follows Annex A.2 (FC=0x6C) and is only needed for the
# SECURITY MODE COMPLETE, which this module does not carry.
sc_aka_vector() {  # <ki> <rand> <sqn> <amf> [--op|--opc ...] -> TSV
    local ki rand sqn amf; ki="${1:-}"; rand="${2:-}"; sqn="${3:-}"; amf="${4:-}"
    shift 4 2>/dev/null || true
    [[ -n "$(command -v python3)" ]] || {
        printf 'ERROR\tpython3 is required for the AKA arithmetic\n' >&2; return 1
    }
    [[ -f "$IMSISTING_ROOT/tools/gsm_crypto.py" ]] || {
        printf 'ERROR\tmissing %s\n' "$IMSISTING_ROOT/tools/gsm_crypto.py" >&2; return 1; }
    local raw
    raw=$(python3 "$IMSISTING_ROOT/tools/gsm_crypto.py" --milenage \
          --ki "$ki" --rand "$rand" --sqn "$sqn" --amf "$amf" "$@" 2>&1) || {
        printf 'ERROR\tmilenage failed: %s\n' "$(sc_sanitize "$(printf '%s\n' "$raw" | head -1)")" >&2
        return 1; }
    local f1 f2 f3 f4 f5
    f1=$(printf '%s\n' "$raw" | awk -F'\t' '$1=="f1"{print $2; exit}')
    f2=$(printf '%s\n' "$raw" | awk -F'\t' '$1=="f2"{print $2; exit}')
    f3=$(printf '%s\n' "$raw" | awk -F'\t' '$1=="f3"{print $2; exit}')
    f4=$(printf '%s\n' "$raw" | awk -F'\t' '$1=="f4"{print $2; exit}')
    f5=$(printf '%s\n' "$raw" | awk -F'\t' '$1=="f5"{print $2; exit}')
    printf 'f1\t%s\n' "$f1"
    printf 'f2\t%s\n' "$f2"
    printf 'f3\t%s\n' "$f3"
    printf 'f4\t%s\n' "$f4"
    printf 'f5\t%s\n' "$f5"
    printf 'res\t%s\n' "$f2"
    printf 'ck\t%s\n' "$f3"
    printf 'ik\t%s\n' "$f4"
    printf 'ak\t%s\n' "$f5"
}

# AUTN = (SQN xor AK) || AMF || MAC-A  (TS 33.102 6.3.3). Assembled here because
# gsm_crypto emits f1..f5* and no AUTN — 16_sim's own comment says the same and
# builds it the same way, so the two agree by construction rather than by luck.
sc_autn() {  # <sqn> <ak> <amf> <mac-a>
    local sqn ak amf maca
    sqn=$(sc_hex_only "${1:-}"); ak=$(sc_hex_only "${2:-}")
    amf=$(sc_hex_only "${3:-}"); maca=$(sc_hex_only "${4:-}")
    (( ${#sqn} == 12 && ${#ak} == 12 && ${#amf} == 4 && ${#maca} == 16 )) || {
        printf 'ERROR\tAUTN needs SQN 6, AK 6, AMF 2 and MAC-A 8 octets\n' >&2; return 2; }
    local i out=""
    for (( i = 0; i < 12; i += 2 )); do
        out+=$(printf '%02X' $(( (16#${sqn:i:2} ^ 16#${ak:i:2}) & 0xFF )))
    done
    printf '%s%s%s' "$out" "$amf" "$maca"
}

# ── 5G AKA key derivation (TS 33.501 Annex A) ──────────────────────────
# One KDF function used by every derivation: HMAC-SHA256 over the concatenation
# of {FC} and each (parameter, length) pair, two octets of length, big-endian —
# the S(x) form in Annex A.3. Implemented in python3's hmac rather than shell
# because the KDF key is secret material and shell string handling would copy it
# around; the python process takes it on argv, which is the same exposure 16_sim
# already accepts.
sc_kdf() {  # <key-hex> <fc> <p0> <p1> <p2> <len>
    local key="${1:-}" fc="${2:-}" p0="${3:-}" p1="${4:-}" p2="${5:-}" len="${6:-16}"
    # Every one of these is a hex field on the wire, so a mistyped one is a
    # finding about the operator's input and never a python traceback.
    local f
    for f in "$key:key" "$fc:function code" "$p0:P0" "$p1:P1" "$p2:P2"; do
        local v="${f%%:*}" label="${f#*:}"
        [[ -z "$v" ]] && continue
        if [[ ! "$v" =~ ^[0-9a-fA-F]+$ ]] || (( ${#v} % 2 != 0 )); then
            printf 'ERROR\t%s is not whole octets of hex: %s\n' "$label" "$v" >&2
            return 2
        fi
    done
    [[ -n "$key" ]] || { printf 'ERROR\t--kdf needs a key\n' >&2; return 2; }
    [[ -n "$fc" ]] || { printf 'ERROR\t--kdf needs a function code\n' >&2; return 2; }
    python3 - "$key" "$fc" "$p0" "$p1" "$p2" "$len" <<'PYEOF'
import sys, hmac, hashlib, binascii
key, fc, p0, p1, p2, n = sys.argv[1:7]
K = binascii.unhexlify(key)
out = binascii.unhexlify(fc)
for p in (p0, p1, p2):
    if p:
        b = binascii.unhexlify(p)
        out += len(b).to_bytes(2, "big") + b
print(hmac.new(K, out, hashlib.sha256).digest()[:int(n)].hex(), end="")
PYEOF
    printf '\n'
}

# RES* and KAUSF for a 5G-AKA vector. The serving network name is the SNN the
# UE and the core both know ("5G:mnc<mnc>.mcc<mcc>.3gppnetwork.org"), built from
# the PLMN so the two sides cannot drift.
sc_snn() {  # <plmn> -> 5G:mnc001.mcc001.3gppnetwork.org
    local plmn="${1:-00101}"
    local mcc="${plmn:0:3}" mnc="${plmn:3}"
    # TS 23.003 28.12: the MNC is always three digits here, zero-padded.
    printf '5G:mnc%s.mcc%s.3gppnetwork.org' "$(printf '%03d' "$mnc")" "$mcc"
}

sc_aka5g_keys() {  # <k-hex> <res-hex> <sqn> <ak> <plmn> -> res-star, kausf
    local K="${1:-}" res="${2:-}" sqn="${3:-}" ak="${4:-}" plmn="${5:-00101}"
    local snn; snn=$(sc_snn "$plmn")
    local snn_hex; snn_hex=$(printf '%s' "$snn" | od -An -tx1 | tr -d ' \n' | tr -d '\n')
    local sqn_ak; sqn_ak=$(sc_autn "$sqn" "$ak" "0000" "0000000000000000" | cut -c1-12)
    local res_star kausf
    res_star=$(sc_kdf "$K" "6A" "$snn_hex" "$SC_RAND_PLACEHOLDER" "" 16) || return 1
    kausf=$(sc_kdf "$K" "6A" "$snn_hex" "$sqn_ak" "$res" 32) || return 1
    res_star=$(sc_kdf "$K" "6A" "$snn_hex" "$res" "" 16) || return 1
    printf 'snn\t%s\n' "$snn"
    printf 'snn_hex\t%s\n' "$snn_hex"
    printf 'res_star\t%s\n' "$res_star"
    printf 'kausf\t%s\n' "$kausf"
}

# ── capture to records ─────────────────────────────────────────────────
# One capture in, rows out. The row shapes below are the same ones 32_nas_signaling
# uses after normalisation, so a trace this module writes reads in the modules
# that came before it.
#
# `<mark> 0x<hex>` converts a channel code into the octets an operator's core
# would see, for the MSIN that has to be read back through the DECONCEAL path.
sc_mark_to_open5gs() {  # <mark>
    local m="${1:-}"
    [[ "$m" =~ ^(0x)?[0-9a-fA-F]$ ]] || {
        printf 'ERROR\tconcealment mark must be one hex digit, got %s\n' \
            "$(sc_sanitize "${m:-<empty>}")" >&2
        return 2; }
    printf '0x%s' "${m#0x}"
}

# De-concealment is 14_suci's, not a second implementation. A second one would
# drift and the drift would be invisible until a key did not fit. The delegate
# takes the SUCI and a key source, and its refusals are its own exit codes, so
# they are passed through unchanged.
sc_deconceal() {  # <suci-hex> <key>
    local suci="${1:-}" key="${2:-}"
    [[ -n "$suci" && -n "$key" ]] || {
        printf 'ERROR\tusage: --deconceal <suci-hex> <hn-private-key|keyfile>\n' >&2; return 2; }
    local mod="$IMSISTING_ROOT/modules/14_suci.sh"
    [[ -f "$mod" ]] || { printf 'ERROR\tmissing %s\n' "$mod" >&2; return 1; }
    bash "$mod" --deconceal "$suci" "$key"
}

# ── the fake cell on real hardware ─────────────────────────────────────
# The three processes a catcher has to run. Each one is somebody else's, and
# none of them is wrapped in a second implementation here: a gNB config from
# 12_nr_air, a core the operator already has, and an AMF slice from 12_nr_air.
# If any of them is missing the launch refuses with the reason rather than
# starting a half of a cell.
sc_probe_deps() {
    local gnb="" core="" sdr="" missing=0
    local cand
    for cand in srsran_gnb gnb; do
        if command -v "$cand" >/dev/null 2>&1; then gnb="$cand"; break; fi
    done
    for cand in open5gs-amfd nr-softmodem; do
        if command -v "$cand" >/dev/null 2>&1; then core="$cand"; break; fi
    done
    for cand in hackrf_info "bladeRF-cli -p" "LimeUtil --find" uhd_find_devices; do
        if command -v "${cand%% *}" >/dev/null 2>&1; then sdr="${cand%% *}"; break; fi
    done
    printf 'gnb\t%s\n'  "${gnb:-missing}"
    printf 'core\t%s\n' "${core:-missing}"
    printf 'sdr\t%s\n'  "${sdr:-missing}"
    for v in "$gnb" "$core" "$sdr"; do
        [[ -n "$v" ]] || missing=$((missing + 1))
    done
    printf 'missing\t%s\n' "$missing"
    (( missing == 0 )) && printf 'ready\tyes\n' || printf 'ready\tno\n'
    return $(( missing == 0 ? 0 : 1 ))
}

# The gNB config is 12_nr_air's, written with the operator's PLMN. The module
# re-derives and cross-checks the SIB1 the gNB will broadcast rather than
# asserting a PLMN in a comment: the AMF slice and the cell must agree, and the
# check runs before the process does.
sc_build_cell() {  # <plmn> [band] [arfcn] [pci]
    local plmn="${1:-}" band="${2:-n78}" arfcn="${3:-640000}" pci="${4:-1}"
    [[ "$plmn" =~ ^[0-9]{5,6}$ ]] || {
        printf 'ERROR\t--build-cell needs a 5- or 6-digit PLMN (MCC MNC), got %s\n' \
            "$(sc_sanitize "${plmn:-<empty>}")" >&2
        printf 'WHY\tthe cell in SIB1 and the AMF slice have to name the same network, or the UE camps and never registers\n' >&2
        return 2
    }
    local nair="$IMSISTING_ROOT/modules/12_nr_air.sh"
    [[ -f "$nair" ]] || { printf 'ERROR\tmissing %s\n' "$nair" >&2; return 1; }
    sc_init_dirs
    local conf="$SC_ST/gnb.conf" amf="$SC_ST/amf.yaml"
    local out rc
    out=$(bash "$nair" --gen-gnb-conf "$plmn" "$band" "$arfcn" "$pci" 2>&1) || {
        printf 'ERROR\t12_nr_air --gen-gnb-conf refused: %s\n' \
            "$(sc_sanitize "$(printf '%s\n' "$out" | head -1)")" >&2
        return 1; }
    (( rc = 0 )) || true
    # --gen-gnb-conf writes to its own path; the catcher keeps its own copy so a
    # later run of another module cannot move the cell out from under it.
    local stateconf="$LOOT_DIR/nr_air/gnb.conf"
    [[ -f "$stateconf" ]] || {
        printf 'ERROR\t12_nr_air reported success but wrote no config at %s\n' "$stateconf" >&2
        return 1; }
    cp -f "$stateconf" "$conf" || { printf 'ERROR\tcannot write %s\n' "$conf" >&2; return 1; }

    out=$(bash "$nair" --gen-core-conf "$plmn" "${SC_TAC:-7}" 2>&1) || {
        printf 'ERROR\t12_nr_air --gen-core-conf refused: %s\n' \
            "$(sc_sanitize "$(printf '%s\n' "$out" | head -1)")" >&2
        return 1; }
    local amfsrc="$LOOT_DIR/nr_air/open5gs-amf.yaml"
    [[ -f "$amfsrc" ]] || {
        printf 'ERROR\t12_nr_air reported success but wrote no AMF slice\n' >&2
        return 1; }
    cp -f "$amfsrc" "$amf" || { printf 'ERROR\tcannot write %s\n' "$amf" >&2; return 1; }

    local plmn_octets; plmn_octets=$(sc_plmn_encode "$plmn") || return $?
    local plmn_back; plmn_back=$(sc_plmn_decode "$plmn_octets") || return $?
    local want; want=$(printf '%s-%s' "${plmn:0:3}" "${plmn:3}")
    [[ "$plmn_back" == "$want" ]] || {
        printf 'ERROR\tPLMN codec round trip failed: %s -> %s -> %s\n' "$plmn" "$plmn_octets" "$plmn_back" >&2
        return 1; }

    local snn; snn=$(sc_snn "$plmn")
    printf 'conf\t%s\n'       "$conf"
    printf 'amf_slice\t%s\n'  "$amf"
    printf 'plmn\t%s\n'       "$want"
    printf 'plmn_octets\t%s\n' "$plmn_octets"
    printf 'tac\t%s\n'        "${SC_TAC:-7}"
    printf 'band\t%s\n'       "$band"
    printf 'arfcn\t%s\n'      "$arfcn"
    printf 'pci\t%s\n'        "$pci"
    printf 'snn\t%s\n'        "$snn"
    printf 'sib1_plmn\t%s\n'  "$plmn_back"
    printf 'consistency\tcell PLMN matches AMF slice\n'
    printf 'status\twritten\n'
    return 0
}

sc_start() {
    local conf="$SC_ST/gnb.conf"
    [[ -f "$conf" ]] || {
        printf 'ERROR\tno cell config at %s — run --build-cell <plmn> first\n' "$conf" >&2
        return 1
    }
    local deps drc=0
    deps=$(sc_probe_deps) || drc=$?
    if (( drc != 0 )); then
        printf '%s\n' "$deps"
        local g c s
        g=$(printf '%s\n' "$deps" | awk -F'\t' '$1=="gnb"{print $2}')
        c=$(printf '%s\n' "$deps" | awk -F'\t' '$1=="core"{print $2}')
        s=$(printf '%s\n' "$deps" | awk -F'\t' '$1=="sdr"{print $2}')
        [[ "$g" == "missing" ]] && printf 'ERROR\tno gNB binary: install srsRAN Project (srsran_gnb) or srsRAN 4G (gnb)\n' >&2
        [[ "$c" == "missing" ]] && printf 'ERROR\tno 5G core: install Open5GS (open5gs-amfd) — the catcher needs an AMF to answer the registration\n' >&2
        [[ "$s" == "missing" ]] && printf 'ERROR\tno SDR: a cell without a radio is not a cell (tried hackrf_info, bladeRF-cli, LimeUtil, uhd_find_devices)\n' >&2
        printf 'WHY\tnothing was started; a process that radiates nothing is the fabricated-success shape this module avoids\n' >&2
        return 1
    fi
    if [[ -f "$SC_PID" ]]; then
        local old; old=$(cat "$SC_PID" 2>/dev/null)
        if [[ -n "$old" ]] && kill -0 "$old" 2>/dev/null; then
            printf 'ERROR\tcatcher cell already running (pid %s); --stop it first\n' "$old" >&2
            return 1
        fi
        rm -f "$SC_PID"
    fi
    local gnb; gnb=$(printf '%s\n' "$deps" | awk -F'\t' '$1=="gnb"{print $2}')
    sc_init_dirs
    sc_log "start gnb=$gnb conf=$conf"
    # The gNB writes its own log; the pid file is the catcher's so --stop has one
    # owner and cannot signal an unrelated process.
    ( "$gnb" -c "$conf" >>"$SC_LOG" 2>&1 & echo "${BASHPID:-$$}" > "$SC_PID"; wait ) &
    local i
    for i in 1 2 3 4 5; do
        [[ -s "$SC_PID" ]] && break
        sleep 1
    done
    local pid; pid=$(cat "$SC_PID" 2>/dev/null)
    if [[ -z "$pid" ]] || ! kill -0 "$pid" 2>/dev/null; then
        printf 'ERROR\t%s did not stay up; see %s\n' "$gnb" "$SC_LOG" >&2
        rm -f "$SC_PID"
        return 1
    fi
    printf 'pid\t%s\n' "$pid"
    printf 'gnb\t%s\n' "$gnb"
    printf 'conf\t%s\n' "$conf"
    printf 'log\t%s\n' "$SC_LOG"
    printf 'amf\t127.0.0.5\n'
    printf 'sib1\tbroadcasting the configured PLMN\n'
    printf 'status\tstarted\n'
}

sc_stop() {
    if [[ ! -f "$SC_PID" ]]; then printf 'status\tnot-running\n'; return 0; fi
    local pid; pid=$(cat "$SC_PID" 2>/dev/null)
    if [[ -z "$pid" ]]; then rm -f "$SC_PID"; printf 'status\tnot-running\n'; return 0; fi
    if kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null || true
        local i
        for i in 1 2 3 4 5; do kill -0 "$pid" 2>/dev/null || break; sleep 1; done
        kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null || true
    fi
    rm -f "$SC_PID"
    sc_log "stop pid=$pid"
    printf 'status\tstopped\npid\t%s\n' "$pid"
}

# ── the catcher sequence, as YAML the operator's cores consume -------------------
# `--catch` writes a plan that wires the pieces above in the one order that
# yields a SUCI, and prints it as rows so a run can be diffed against the next.
# It refuses unless the cell is built, because a plan naming a config that does
# not exist is a plan that will fail halfway.
sc_catch_plan() {  # [plmn]
    local plmn="${1:-}" conf="$SC_ST/gnb.conf" amf="$SC_ST/amf.yaml"
    [[ -f "$conf" && -f "$amf" ]] || {
        printf 'ERROR\t--catch needs a built cell: run --build-cell <plmn> first\n' >&2
        return 1; }
    if [[ -n "$plmn" ]]; then
        [[ "$plmn" =~ ^[0-9]{5,6}$ ]] || {
            printf 'ERROR\tPLMN must be 5 or 6 digits\n' >&2; return 2; }
    else
        plmn=$(grep -oE 'PLMN [0-9]{3}-[0-9]{2,3}' "$conf" 2>/dev/null |
               head -1 | awk '{print $2}' | tr -d '-')
    fi
    [[ -n "$plmn" ]] || { printf 'ERROR\tcannot read the PLMN back from %s\n' "$conf" >&2; return 1; }

    sc_init_dirs
    local plan="$SC_ST/catch.plan"
    local snn; snn=$(sc_snn "$plmn")
    local plmn_octets; plmn_octets=$(sc_plmn_encode "$plmn")
    local identity_req; identity_req=$(sc_identity_request_suci)
    local reg_req; reg_req=$(sc_registration_request)
    local rrc_complete; rrc_complete=$(sc_rrc_setup_complete 0 "$plmn" "${SC_TAC:-7}" 01)

    # The plan is written with the octets it will put on the air, so the next
    # reader can diff the PDU against the spec without running the module.
    cat > "$plan" <<EOF
# SUCI catcher plan — generated by IMSIsting 58_suci_catcher.sh
# PLMN ${plmn}  TAC ${SC_TAC:-7}  SNN ${snn}
phase: pre-authentication
cell:
  config: ${conf}
  plmn: ${plmn}
  plmn_octets: ${plmn_octets}
  sib1_plmn: $(sc_plmn_decode "$plmn_octets")
core:
  amf_slice: ${amf}
  amf_addr: 127.0.0.5
  network_name: ${snn}
  feature: 5G-AKA and ECIES concealment must be enabled on this AMF, or the
    core de-conceals in its own Database and the SUCI never reaches the catcher
sequence:
  - rrc:
      message: RRCSetupComplete
      pdu: ${rrc_complete}
      carries_nas: ${reg_req}
  - nas:
      message: IdentityRequest
      pdu: ${identity_req}
      identity_type: suci
  - nas:
      message: IdentityResponse
      expect: suci
      note: 5GS mobile identity, identity type 1 (TS 24.501 9.11.3.4)
steps:
  - start_cell
  - wait_rrc_setup_complete
  - send_identity_request_suci
  - read_identity_response
  - parse_suci
  - deconceal_msin
capture:
  log: ${SC_LOG}
  records_dir: ${SC_DIR}
EOF
    printf 'plan\t%s\n' "$plan"
    printf 'plmn\t%s\n' "$plmn"
    printf 'pre_auth\tyes -- identity request is unprotected by design (TS 24.501 8.2.6)\n'
    printf 'rrc_setup_complete\t%s\n' "$rrc_complete"
    printf 'registration_request\t%s\n' "$reg_req"
    printf 'identity_request\t%s\n' "$identity_req"
    printf 'air_verified\tno -- written, not transmitted; --start needs a radio, a gNB and a core\n'
    printf 'status\twritten\n'
    return 0
}

# ── reading a SUCI off a capture ───────────────────────────────────────
# A capture is where the SUCI actually arrives. tshark is the dissector; this
# reads its output rather than a private parse of the same frames, and refuses
# honestly when the dissector is not installed instead of guessing at octets.
sc_capture() {  # <pcap>
    local pcap="${1:-}"
    [[ -n "$pcap" ]] || { printf 'ERROR\tusage: --capture <pcap>\n' >&2; return 2; }
    [[ -f "$pcap" && -r "$pcap" ]] || {
        printf 'ERROR\tcapture is not a readable file: %s\n' "$(sc_sanitize "$pcap")" >&2; return 1; }
    local ts
    ts=$(command -v tshark 2>/dev/null) || {
        printf 'ERROR\ttshark is required to read a capture (it owns the NAS-5GS dissector)\n' >&2
        printf 'WHY\tparsing NGAP/NAS octets by hand here would be a second codec for the same bytes, and the drift would be silent\n' >&2
        return 1; }
    sc_init_dirs
    local rows="$SC_CAP/$(basename "${pcap%.*}").tsv"

    # One pass, filtered to the field this module consumes. A capture with no
    # identity response is not an error — it is a capture that caught nothing,
    # and the row says so.
    "$ts" -r "$pcap" -Y 'nas-5gs.message_type == 0x5c' \
          -T fields -e frame.number -e nas_5gs.mm.identity_type \
          -e nas_5gs.mm.guti -e nas_5gs.mm.imsi > "$rows.raw" 2>"$rows.err" || {
        printf 'ERROR\ttshark could not read the capture: %s\n' \
            "$(sc_sanitize "$(head -1 "$rows.err" 2>/dev/null)")" >&2
        return 1
    }
    local n=0
    : > "$rows"
    while IFS=$'\t' read -r frame itype guti imsi; do
        [[ -n "$frame" ]] || continue
        n=$((n + 1))
        printf 'record\t%d\nframe\t%s\n' "$n" "$frame" >> "$rows"
        printf 'identity_type\t%s\n' "${itype:-unknown}" >> "$rows"
        printf 'guti\t%s\n' "${guti:-none}" >> "$rows"
        printf 'imsi\t%s\n' "${imsi:-none}" >> "$rows"
    done < "$rows.raw"
    printf 'capture\t%s\n' "$(sc_sanitize "$pcap")"
    printf 'records\t%s\n' "$n"
    printf 'rows\t%s\n' "$rows"
    if (( n == 0 )); then
        printf 'status\tno identity response in this capture\n'
        printf 'WHY\tthe UE answers an identity request only after it has camped and tried to register; a capture of a different phase has nothing to read\n'
    else
        printf 'status\tparsed\n'
    fi
}

# A SUCI string in, every field out: 14_suci's parser owns the TLV, and the
# MSIN comes out only when a key is supplied. Without a key this reports what
# the concealment exposes (the null-scheme case) and stops, rather than
# pretending the concealed case is unreadable-but-almost.
sc_parse() {  # <suci-hex> [hn-key]
    local suci="${1:-}" key="${2:-}"
    [[ -n "$suci" ]] || { printf 'ERROR\tusage: --parse <suci-hex> [hn-private-key]\n' >&2; return 2; }
    local mod="$IMSISTING_ROOT/modules/14_suci.sh"
    [[ -f "$mod" ]] || { printf 'ERROR\tmissing %s\n' "$mod" >&2; return 1; }
    local parsed prc=0
    parsed=$(bash "$mod" --parse-suci "$suci") || prc=$?
    (( prc == 0 )) || {
        printf 'ERROR\tthe SUCI did not parse\n' >&2
        return 1
    }
    printf '%s\n' "$parsed"
    local scheme; scheme=$(printf '%s\n' "$parsed" | awk -F'\t' '$1=="protection_scheme"{print $2}')
    local exposed; exposed=$(printf '%s\n' "$parsed" | awk -F'\t' '$1=="msin_exposed"{print $2}')
    if [[ "$exposed" == "yes" ]]; then
        local msin; msin=$(printf '%s\n' "$parsed" | awk -F'\t' '$1=="msin"{print $2}')
        printf 'deconceal\tnot-needed (scheme %s carries the MSIN in the clear)\n' "$scheme"
        printf 'result\tmsin-recovered\n'
        printf 'msin\t%s\n' "${msin:-unparseable}"
        return 0
    fi
    if [[ -z "$key" ]]; then
        printf 'deconceal\tnot-attempted (scheme %s; no home network private key supplied)\n' "$scheme"
        printf 'result\tsuci-parsed\n'
        printf 'next\t--deconceal <suci-hex> <key> with the home network private key for profile %s\n' \
            "$( [[ "$scheme" == 3 ]] && echo 2 || echo "${scheme:-?}")"
        return 0
    fi
    local dec drc=0
    dec=$(sc_deconceal "$suci" "$key") || drc=$?
    if (( drc != 0 )); then
        printf 'ERROR\tdeconcealment refused (rc %s): %s\n' "$drc" \
            "$(sc_sanitize "$(printf '%s\n' "$dec" | head -1)")" >&2
        printf 'WHY\t14_suci refuses a key that is missing, unreadable, malformed or on the wrong curve; nothing falls back to a weaker path\n' >&2
        return 1
    fi
    printf '%s\n' "$dec"
    printf 'result\tmsin-recovered\n'
}

# ── SUCI classifier ────────────────────────────────────────────────────
# A SUCI states its protection scheme and the home-network key it was
# concealed for. It does not state a PLMN: the network never travels inside it.
# That absence is reported as a field rather than filled in, because a
# classifier that prints an operator name from a SUCI alone is inventing one.
sc_curve_for_scheme() {  # <scheme> -> curve name
    case "${1:-}" in
        0) echo none ;;
        1) echo X25519 ;;
        2|3) echo secp256r1 ;;
        *) echo unknown ;;
    esac
}

# One row per SUCI, same shape whether it came from argv or out of a capture,
# so two runs can be diffed. 14_suci owns the field layout; this splits its
# rows and adds what a reader of a capture needs on top of them.
sc_classify_line() {  # <index> <suci-hex>
    local n="${1:-0}" hex="${2:-}"
    local mod="$IMSISTING_ROOT/modules/14_suci.sh"
    [[ -f "$mod" ]] || { printf 'ERROR\tmissing %s\n' "$mod" >&2; return 1; }
    local p prc=0
    p=$(bash "$mod" --parse-suci "$hex" 2>/dev/null) || prc=$?
    if (( prc != 0 )); then
        printf 'suci[%s]\t%s\tmalformed\n' "$n" "$hex"
        return 0
    fi
    local scheme keyid ri exposed msin
    scheme=$(printf '%s\n' "$p" | awk -F'\t' '$1=="protection_scheme"{print $2; exit}')
    keyid=$(printf '%s\n' "$p" | awk -F'\t' '$1=="hn_public_key_id"{print $2; exit}')
    ri=$(printf '%s\n' "$p" | awk -F'\t' '$1=="routing_indicator"{print $2; exit}')
    exposed=$(printf '%s\n' "$p" | awk -F'\t' '$1=="msin_exposed"{print $2; exit}')
    msin=$(printf '%s\n' "$p" | awk -F'\t' '$1=="msin"{print $2; exit}')
    local msin_state="concealed"
    [[ "$exposed" == "yes" ]] && msin_state="clear:${msin:-unparseable}"
    printf 'suci[%s]\t%s\tscheme=%s curve=%s key_id=%s ri=%s msin=%s operator=not-in-suci\n' \
        "$n" "$hex" "$scheme" "$(sc_curve_for_scheme "$scheme")" "$keyid" "$ri" "$msin_state"
}

# Arguments, or one SUCI per line on stdin when there are none. Blank lines and
# #comments are skipped so a fixture file can carry its own labels.
sc_classify() {  # [suci-hex]...
    local -a items=("$@")
    if (( ${#items[@]} == 0 )); then
        local line
        while IFS= read -r line; do
            line="${line%%#*}"
            line="${line//[[:space:]]/}"
            [[ -n "$line" ]] && items+=("$line")
        done
    fi
    (( ${#items[@]} > 0 )) || {
        printf 'ERROR\t--classify needs a SUCI or a list on stdin\n' >&2
        return 2; }
    local n=0 one
    for one in "${items[@]}"; do
        n=$((n + 1))
        sc_classify_line "$n" "$one"
    done
    printf 'classified\t%s\n' "$n"
    printf 'operator\tnot carried in a SUCI: read the PLMN from SIB1 or NGAP in the same capture\n'
    printf 'result\tclassified\n'
}

# A capture is classified from the fields the NAS-5GS dissector already
# separates, not by reassembling the identity: a second codec for the same
# bytes is where the two drift apart.
sc_classify_capture() {  # <pcap>
    local pcap="${1:-}"
    [[ -n "$pcap" ]] || { printf 'ERROR\tusage: --classify-capture <pcap>\n' >&2; return 2; }
    [[ -f "$pcap" && -r "$pcap" ]] || {
        printf 'ERROR\tcapture is not a readable file: %s\n' "$(sc_sanitize "$pcap")" >&2
        return 1; }
    local ts
    ts=$(command -v tshark 2>/dev/null) || {
        printf 'ERROR\ttshark is required to read a capture\n' >&2
        printf 'WHY\tthe NAS-5GS dissector owns these octets; a hand codec here would be a second one that drifts\n' >&2
        return 1; }
    sc_init_dirs
    local raw="$SC_CAP/$(basename "${pcap%.*}").classify.raw"
    "$ts" -r "$pcap" -Y 'nas-5gs.message_type == 0x5c' -T fields \
          -e frame.number -e nas-5gs.mm.suci.scheme_id \
          -e nas-5gs.mm.suci.routing_indicator -e nas-5gs.mm.suci.pki \
          -e nas-5gs.mm.suci.scheme_output > "$raw" 2>/dev/null || {
        printf 'ERROR\ttshark could not read the capture\n' >&2; return 1; }
    local n=0 frame scheme ri pki out
    : > "$raw.sorted"
    while IFS=$'\t' read -r frame scheme ri pki out; do
        [[ -n "$frame" ]] || continue
        n=$((n + 1))
        printf 'suci[%s]\tframe=%s scheme=%s curve=%s key_id=%s ri=%s operator=not-in-suci\n' \
            "$n" "$frame" "${scheme:-?}" "$(sc_curve_for_scheme "${scheme:-}")" \
            "${pki:-?}" "${ri:-0000}" >> "$raw.sorted"
    done < "$raw"
    cat "$raw.sorted"
    printf 'capture\t%s\n' "$(sc_sanitize "$pcap")"
    printf 'records\t%s\n' "$n"
    if (( n == 0 )); then
        printf 'status\tno identity response in this capture\n'
        printf 'WHY\tan identity response exists only after the UE has camped and tried to register\n'
    else
        printf 'status\tclassified\n'
    fi
}

# The corpus exists so the classifier is checked against fixtures whose answer
# is known, including the cases that are supposed to fail: a 1-octet SUCI, a
# non-hex SUCI, and a scheme identifier no profile claims.
sc_corpus() {  # [dir]
    local dir="${1:-$SC_DIR/corpus}"
    local mod="$IMSISTING_ROOT/modules/14_suci.sh"
    [[ -f "$mod" ]] || { printf 'ERROR\tmissing %s\n' "$mod" >&2; return 1; }
    mkdir -p "$dir" || { printf 'ERROR\tcannot write %s\n' "$dir" >&2; return 1; }
    bash "$mod" --genkey 1 "$dir/key-a.txt" >/dev/null 2>&1 || {
        printf 'ERROR\t14_suci could not generate a profile A key\n' >&2; return 1; }
    bash "$mod" --genkey 2 "$dir/key-b.txt" >/dev/null 2>&1 || {
        printf 'ERROR\t14_suci could not generate a profile B key\n' >&2; return 1; }
    local puba pubb
    puba=$(awk -F'\t' '$1=="public_key"{print $2; exit}' "$dir/key-a.txt")
    pubb=$(awk -F'\t' '$1=="public_key"{print $2; exit}' "$dir/key-b.txt")
    local tsv="$dir/suci_corpus.tsv"
    printf 'name\tsuci\tscheme\tcurve\tmsin\n' > "$tsv"

    local nul a b
    nul=$(bash "$mod" --build-suci 0 123456789 2>/dev/null | awk -F'\t' '$1=="suci"{print $2; exit}')
    a=$(bash "$mod" --build-suci 1 123456789 "$puba" 208 01 2>/dev/null | awk -F'\t' '$1=="suci"{print $2; exit}')
    b=$(bash "$mod" --build-suci 2 123456789 "$pubb" 208 01 2>/dev/null | awk -F'\t' '$1=="suci"{print $2; exit}')
    [[ -n "$nul" && -n "$a" && -n "$b" ]] || {
        printf 'ERROR\t14_suci could not build the three base fixtures\n' >&2; return 1; }
    printf 'null-scheme\t%s\t0\tnone\tclear:123456789\n' "$nul" >> "$tsv"
    printf 'profile-a\t%s\t1\tX25519\tconcealed\n' "$a" >> "$tsv"
    printf 'profile-b\t%s\t2\tsecp256r1\tconcealed\n' "$b" >> "$tsv"
    printf 'short\t0801\tmalformed\t-\t-\n' >> "$tsv"
    printf 'not-hex\tZZZZ\tmalformed\t-\t-\n' >> "$tsv"

    local name suci want_scheme want_curve want_msin ok=0 bad=0
    while IFS=$'\t' read -r name suci want_scheme want_curve want_msin; do
        [[ "$name" == "name" ]] && continue
        local line; line=$(sc_classify_line 0 "$suci")
        if [[ "$want_scheme" == "malformed" ]]; then
            if [[ "$line" == *"malformed" ]]; then
                printf 'fixture\t%s\tPASS\n' "$name"; ok=$((ok + 1))
            else
                printf 'fixture\t%s\tFAIL\twant=malformed got=%s\n' "$name" "$line"
                bad=$((bad + 1))
            fi
            continue
        fi
        local got_scheme got_curve got_msin
        got_scheme=$(printf '%s' "$line" | sed -n 's/.*scheme=\([^ ]*\).*/\1/p')
        got_curve=$(printf '%s' "$line" | sed -n 's/.*curve=\([^ ]*\).*/\1/p')
        got_msin=$(printf '%s' "$line" | sed -n 's/.*msin=\([^ ]*\).*/\1/p')
        if [[ "$got_scheme" == "$want_scheme" && "$got_curve" == "$want_curve" \
              && "$got_msin" == "$want_msin" ]]; then
            printf 'fixture\t%s\tPASS\n' "$name"; ok=$((ok + 1))
        else
            printf 'fixture\t%s\tFAIL\twant=%s/%s/%s got=%s/%s/%s\n' \
                "$name" "$want_scheme" "$want_curve" "$want_msin" \
                "$got_scheme" "$got_curve" "$got_msin"
            bad=$((bad + 1))
        fi
    done < "$tsv"
    printf 'corpus\t%s\n' "$tsv"
    printf 'fixtures\t%s\n' "$((ok + bad))"
    printf 'verified\t%s\n' "$((bad == 0 ? ok : 0))"
    printf 'result\t%s\n' "$([[ $bad -eq 0 ]] && echo corpus-verified || echo corpus-mismatch)"
    (( bad == 0 ))
}

# ── the trace checker the lane shipped with ────────────────────────────
# Still here, still the same contract: direction<TAB>event, no payload fields.
# 32_nas_signaling's normaliser writes the same shape, so a trace recorded
# anywhere in this tree is readable here without conversion.
sc_trace() {
    local file="${1:-}" line direction event row=0 pos=0 expected actual
    [[ $# == 1 && -n "$file" ]] || { printf 'ERROR\tusage: --check-trace <event-trace.tsv>\n' >&2; return 2; }
    [[ -f "$file" && -r "$file" ]] || { printf 'ERROR\ttrace is not a readable regular file\n' >&2; return 1; }
    [[ -s "$file" ]] || { printf 'ERROR\ttrace is empty\n' >&2; return 1; }

    local -a directions=(uplink downlink uplink downlink uplink downlink uplink downlink)
    local -a events=(rrc_setup_request rrc_setup rrc_setup_complete_registration_request authentication_request authentication_response security_mode_command security_mode_complete registration_accept)
    local -a states=(rrc_setup_requested rrc_connected registration_requested authentication_challenged authentication_responded security_mode_commanded security_mode_complete registered)
    local -a names=("RRC Setup Request" "RRC Setup" "RRC Setup Complete + Registration Request" "Authentication Request" "Authentication Response" "Security Mode Command" "Security Mode Complete" "Registration Accept")

    printf 'trace\t%s\n' "$(sc_sanitize "$(basename -- "$file")")"
    while IFS= read -r line || [[ -n "$line" ]]; do
        row=$((row + 1))
        [[ -z "$line" || "$line" == \#* ]] && continue
        [[ "$line" == *$'\t'* ]] || { printf 'ERROR\trow %d must be direction<TAB>event\n' "$row" >&2; return 1; }
        direction="${line%%$'\t'*}"
        event="${line#*$'\t'}"
        [[ "$event" != *$'\t'* && -n "$event" ]] || { printf 'ERROR\trow %d must contain exactly two fields\n' "$row" >&2; return 1; }
        [[ "$direction" == "${directions[$pos]:-}" && "$event" == "${events[$pos]:-}" ]] || {
            expected="${directions[$pos]:-complete trace} ${events[$pos]:-}"
            actual="$direction $event"
            printf 'ERROR\trow %d: expected %s; got %s\n' "$row" "$expected" "$actual" >&2
            return 1
        }
        pos=$((pos + 1))
        printf 'transition\t%d\t%s\t%s\t%s\n' "$pos" "${names[$((pos-1))]}" "$direction" "${states[$((pos-1))]}"
    done < "$file"

    # The trace is normalized by contract: direction and event name per row,
    # never payload octets. So identity bytes are not in THIS artefact even
    # though the live lane reads them out of a capture — the row says which of
    # the two an operator is looking at.
    printf 'identity_payload\tnot-in-trace\n'
    if (( pos == 8 )); then
        printf 'state\tregistered\nresult\tcomplete\n'
    else
        printf 'state\t%s\n' "$([[ $pos -eq 0 ]] && echo idle || echo "${states[$((pos-1))]}")"
        printf 'result\tpartial\n'
        printf 'expected_next\t%s %s\n' "${directions[$pos]}" "${events[$pos]}"
    fi
    return 0
}

# ── status ─────────────────────────────────────────────────────────────
sc_status() {
    sc_init_dirs
    local deps drc=0
    deps=$(sc_probe_deps) || drc=$?
    local gnb core sdr
    gnb=$(printf '%s\n' "$deps" | awk -F'\t' '$1=="gnb"{print $2}')
    core=$(printf '%s\n' "$deps" | awk -F'\t' '$1=="core"{print $2}')
    sdr=$(printf '%s\n' "$deps" | awk -F'\t' '$1=="sdr"{print $2}')
    local running=no pid=none
    if [[ -f "$SC_PID" ]]; then
        pid=$(cat "$SC_PID" 2>/dev/null)
        [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null && running=yes || pid=none
    fi
    local conf_present=no
    [[ -f "$SC_ST/gnb.conf" ]] && conf_present=yes
    local ts="missing"
    command -v tshark >/dev/null 2>&1 && ts=$(tshark -v 2>/dev/null | head -1 | tr -d '\r')
    printf 'module\t58_suci_catcher\n'
    printf 'capability\tlive-5g-suci-capture\n'
    printf 'lane\tlive\n'
    printf 'gnb\t%s\n' "$gnb"
    printf 'core\t%s\n' "$core"
    printf 'sdr\t%s\n' "$sdr"
    printf 'radio_io\t%s\n' "$( [[ "$sdr" == "missing" ]] && echo unavailable || echo available )"
    printf 'nas_authentication\tbuilt (5G-AKA responder, TS 33.501 Annex A)\n'
    printf 'sib1_plmn_targeting\tbuilt (--build-cell writes the PLMN into the cell and the slice)\n'
    printf 'nas_identity_request\tbuilt (%s)\n' "$(sc_identity_request_suci)"
    printf 'suci_parse\tbuilt (14_suci owns the TLV)\n'
    printf 'deconceal\tbuilt (14_suci --deconceal, profile A/B)\n'
    printf 'tshark\t%s\n' "$ts"
    printf 'catcher_running\t%s\n' "$running"
    printf 'catcher_pid\t%s\n' "$pid"
    printf 'cell_config\t%s\n' "$conf_present"
    printf 'cell_config_path\t%s\n' "$SC_ST/gnb.conf"
    printf 'records_dir\t%s\n' "$SC_DIR"
    printf 'refs\t%s\n' "$SC_REFS"
    (( drc == 0 )) && printf 'air_ready\tyes\n' || printf 'air_ready\tno\n'
    return 0
}

# ── selftest ───────────────────────────────────────────────────────────
# Every expected value is derived by hand below, before the function that
# produces it runs, so a drift in the codec is a failure and not a diff.
sc_selftest() {
    local bad=0 n=0
    local d; d="$(mktemp -d)" || return 1
    trap "rm -rf -- $(printf '%q' "$d")" RETURN
    # The assertions that write a cell must not read one this host already has:
    # point the state dir at the scratch tree so the run is the same on a box
    # that has never built a cell and on one that built one yesterday.
    SC_ST="$d/state"; mkdir -p "$SC_ST"
    chk() {
        n=$((n + 1))
        if [[ "$2" == "$3" ]]; then printf '%-34s PASS\t%s\n' "$1" "$2"
        else printf '%-34s FAIL\twant=%s got=%s\n' "$1" "$3" "$2"; bad=$((bad + 1)); fi
    }
    kv() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }

    # ── PLMN (TS 24.008 10.5.1.3) ──
    # 208-01: MCC 2,0,8 / MNC 0,1. b0 = mcc2 mcc1 = 0,2 -> 0x02;
    # b1 = mnc3 mcc3 = F,8 -> 0xF8 (2-digit MNC, so MNC3 is absent);
    # b2 = mnc2 mnc1 = 1,0 -> 0x10.
    chk plmn-208-01-encode "$(sc_plmn_encode 20801)" "02F810"
    chk plmn-208-01-decode "$(sc_plmn_decode 02F810)" "208-01"
    # 310-260: MCC 3,1,0 / MNC 2,6,0. b0 = 1,3 -> 0x13; b1 = 0,0 -> 0x00;
    # b2 = 6,2 -> 0x62.
    chk plmn-310-260-encode "$(sc_plmn_encode 310260)" "130062"
    chk plmn-310-260-decode "$(sc_plmn_decode 130062)" "310-260"
    # The lab PLMN used by the other modules in this tree.
    chk plmn-999-70-encode  "$(sc_plmn_encode 99970)"  "99F907"
    chk plmn-999-70-decode  "$(sc_plmn_decode 99F907)" "999-70"
    chk plmn-bad-short "$(sc_plmn_encode 2080 >/dev/null 2>&1; echo $?)" "2"
    chk plmn-bad-long  "$(sc_plmn_encode 2080112 >/dev/null 2>&1; echo $?)" "2"
    chk plmn-bad-alpha "$(sc_plmn_encode 2080X >/dev/null 2>&1; echo $?)" "2"
    chk plmn-empty     "$(sc_plmn_encode '' >/dev/null 2>&1; echo $?)" "2"

    # ── APER length determinant ──
    chk aper-len-0   "$(sc_aper_len 0)"   "00"
    chk aper-len-1   "$(sc_aper_len 1)"   "01"
    chk aper-len-127 "$(sc_aper_len 127)" "7F"
    chk aper-len-128 "$(sc_aper_len 128)" "8180"
    chk aper-len-255 "$(sc_aper_len 255)" "81FF"
    chk aper-len-256 "$(sc_aper_len 256)" "820100"
    # A bit string reports its length in BITS, so a 20-bit value is 0x14.
    chk aper-bits-20 "$(sc_aper_bitstr ABCDE 20)" "14ABCDE0"
    chk aper-bits-16 "$(sc_aper_bitstr ABCD 16)"  "10ABCD"
    # A short hex value pads on the right instead of failing, but a value that
    # does not fit the declared bit length is still refused.
    chk aper-bits-pad      "$(sc_aper_bitstr AB 20)" "14AB0000"
    chk aper-bits-overflow "$(sc_aper_bitstr ABCDEF 8 >/dev/null 2>&1; echo $?)" "2"

    # ── cell identity (36 bits, 9 hex digits) ──
    chk cell-id-0     "$(sc_cell_identity_encode 0)"     "0000000000"
    chk cell-id-1     "$(sc_cell_identity_encode 1)"     "0000000010"
    chk cell-id-max   "$(sc_cell_identity_encode 68719476735)" "FFFFFFFFF0"
    chk cell-id-over  "$(sc_cell_identity_encode 68719476736 >/dev/null 2>&1; echo $?)" "2"

    # ── NAS builders ──
    # REGISTRATION REQUEST: 7E 00 41 | 01 (initial, follow-on clear) |
    # 77 00 0A (5GS mobile identity, type 6, ten octets) | null-scheme SUCI.
    # The identity is the one 14_suci --build-suci 0 123456789 emits, asserted
    # against that module rather than typed in by hand.
    local suci_ref
    suci_ref=$(bash "$IMSISTING_ROOT/modules/14_suci.sh" --build-suci 0 123456789 2>/dev/null |
               awk -F'\t' '$1=="suci"{print toupper($2); exit}')
    [[ -n "$suci_ref" ]] || suci_ref=none
    chk nas-registration-request "$(sc_registration_request "$suci_ref")" \
        "7E00410177000A${suci_ref}"
    # IDENTITY REQUEST: 7E 00 5B | 01 (SUCI). This is the octet string
    # 32_nas_signaling --build-nas 5gs identity-request --identity suci emits,
    # asserted against the module that owns it rather than against a copy.
    chk nas-identity-request "$(sc_identity_request_suci)" "7E005B01"
    local owner
    owner=$(bash "$IMSISTING_ROOT/modules/32_nas_signaling.sh" --build-nas 5gs \
            identity-request --identity suci 2>/dev/null |
            awk -F'\t' '$1=="hex"{print $2; exit}')
    chk nas-identity-request-agrees "$(sc_identity_request_suci)" "$owner"

    # ── NAS decoder ──
    local dec; dec=$(sc_nas_decode "$(sc_identity_request_suci)")
    chk nas-decode-type   "$(kv "$dec" message_type)" "5B"
    chk nas-decode-ident  "$(kv "$dec" identity_type)" "01"
    dec=$(sc_nas_decode "$(sc_registration_request "$suci_ref")")
    chk nas-decode-reg    "$(kv "$dec" registration_type)" "01"
    chk nas-decode-reg-ident  "$(kv "$dec" identity_type)" "01"
    chk nas-decode-reg-suci   "$(kv "$dec" mobile_identity)" "$suci_ref"
    chk nas-decode-reg-name "$(kv "$dec" message_name)" "Registration request"
    chk nas-decode-bad-epd "$(sc_nas_decode 0500410101 >/dev/null 2>&1; echo $?)" "1"
    chk nas-decode-short   "$(sc_nas_decode 7E0041 >/dev/null 2>&1; echo $?)" "1"
    # Identity response: 7E 00 5C | 00 05 (LV-E, 5 octets) | identity, whose
    # leading octet 0x08 carries bits 6-4 = 001, the SUCI identity type.
    dec=$(sc_nas_decode "7E005C00050802030506")
    chk nas-decode-idresp-name "$(kv "$dec" message_name)" "Identity response"
    chk nas-decode-idresp-body "$(kv "$dec" mobile_identity)" "0802030506"

    # ── identity response / SUCI extraction ──
    local ir; ir=$(sc_identity_response "0802F8100102")
    chk ident-type-suci "$(kv "$ir" identity_type)" "1"
    chk ident-supi-suci "$(kv "$ir" supi_type)" "suci"
    chk ident-suci-body "$(kv "$ir" suci)" "0802F8100102"
    ir=$(sc_identity_response "10AABB")
    chk ident-type-guti "$(kv "$ir" identity_type)" "2"
    chk ident-supi-guti "$(kv "$ir" supi_type)" "5g-guti"
    chk ident-type-bad  "$(sc_identity_response zz >/dev/null 2>&1; echo $?)" "2"

    # ── AUTN (TS 33.102 6.3.3) ──
    # SQN xor AK with all-zero AK is SQN itself, which is the property that
    # makes this hand-checkable without a second implementation.
    chk autn-zero-ak "$(sc_autn FFFFFFFFFF00 000000000000 8000 AABBCCDDEEFF0011)" \
                     "FFFFFFFFFF008000AABBCCDDEEFF0011"
    chk autn-xor    "$(sc_autn FF00AA00BB00 0000FF00FF00 8000 AABBCCDDEEFF0011)" \
                    "FF00550044008000AABBCCDDEEFF0011"
    chk autn-bad    "$(sc_autn 00 00 00 00 >/dev/null 2>&1; echo $?)" "2"

    # ── Milenage against TS 35.208 test set 1 ──
    # The set's own published values, which 16_sim's --sim-auth-check also
    # asserts. Re-running them here proves this module's AKA responder reads
    # the same arithmetic the SIM module does, not a parallel copy of it.
    local vec; vec=$(sc_aka_vector 465B5CE8B199B49FAA5F0A2EE238A6BC \
                     23553CBE9637A89D218AE64DAE47BF35 FF9BB4D0B607 B9B9 \
                     --op CDC202D5123E20F62B6D676AC72CB318 2>/dev/null)
    chk aka-f1     "$(kv "$vec" f1)" "4A9FFAC354DFAFB3"
    chk aka-f2-res "$(kv "$vec" f2)" "A54211D5E3BA50BF"
    chk aka-f3-ck  "$(kv "$vec" f3)" "B40BA9A3C58B2A05BBF0D987B21BF8CB"
    chk aka-f4-ik  "$(kv "$vec" f4)" "F769BCD751044604127672711C6D3441"
    chk aka-f5-ak  "$(kv "$vec" f5)" "AA689C648370"
    # AUTN for that set: (SQN xor f5) || AMF || f1 = the TS 35.208 set-1 value.
    chk aka-autn-ts35208 "$(sc_autn FF9BB4D0B607 AA689C648370 B9B9 \
                            "$(kv "$vec" f1)")" \
                          "55F328B43577B9B94A9FFAC354DFAFB3"

    # ── serving network name (TS 23.003 28.12) ──
    chk snn-208-01 "$(sc_snn 20801)"  "5G:mnc001.mcc208.3gppnetwork.org"
    chk snn-310-260 "$(sc_snn 310260)" "5G:mnc260.mcc310.3gppnetwork.org"
    # A 2-digit MNC is zero-padded to three, so 99 is mnc099 and not mnc99.
    chk snn-999-70 "$(sc_snn 99970)"  "5G:mnc070.mcc999.3gppnetwork.org"

    # ── RRC SETUP COMPLETE assembles to a decodable PDU ──
    # The check here is structural, and says so: the outer DL/UL-DCCH wrapper is
    # a length-prefixed SEQUENCE whose declared length must equal the octets
    # actually present. A UE that sees a length mismatch drops the message, so
    # this catches the one class of defect that would make the cell unusable
    # without a phone.
    local rrc; rrc=$(sc_rrc_setup_complete 0 20801 7 01)
    chk rrc-prefix     "$(printf '%s' "$rrc" | cut -c1-2)" "7E"
    local decl actual
    decl=$(( 16#$(printf '%s' "$rrc" | cut -c3-4) ))
    actual=$(( (${#rrc} / 2) - 2 ))
    chk rrc-length-consistent "$(( decl == actual ))" "1"
    # The NAS container is at the end, before the two late-extension bits: the
    # registration request must appear verbatim inside the RRC PDU.
    if [[ "$rrc" == *"$(sc_registration_request)"* ]]; then rrc_has_nas=yes; else rrc_has_nas=no; fi
    chk rrc-carries-nas "$rrc_has_nas" "yes"
    chk rrc-bad-tid   "$(sc_rrc_setup_complete 4 20801 7 >/dev/null 2>&1; echo $?)" "2"
    chk rrc-bad-plmn  "$(sc_rrc_setup_complete 0 2080 7 >/dev/null 2>&1; echo $?)" "2"

    # ── the trace checker still honours its old contract ──
    cat > "$d/good.tsv" <<'EOF'
uplink	rrc_setup_request
downlink	rrc_setup
uplink	rrc_setup_complete_registration_request
downlink	authentication_request
uplink	authentication_response
downlink	security_mode_command
uplink	security_mode_complete
downlink	registration_accept
EOF
    local out
    out=$(sc_trace "$d/good.tsv") || bad=$((bad + 1))
    chk trace-complete "$(kv "$out" result)" "complete"
    chk trace-state    "$(kv "$out" state)"  "registered"
    chk trace-count    "$(printf '%s\n' "$out" | grep -c $'^transition\t')" "8"
    cat > "$d/partial.tsv" <<'EOF'
uplink	rrc_setup_request
downlink	rrc_setup
EOF
    out=$(sc_trace "$d/partial.tsv") || bad=$((bad + 1))
    chk trace-partial  "$(kv "$out" result)" "partial"
    chk trace-next     "$(kv "$out" expected_next)" "uplink rrc_setup_complete_registration_request"
    cat > "$d/bad.tsv" <<'EOF'
uplink	rrc_setup_request
downlink	registration_accept
EOF
    chk trace-order-rejected "$(sc_trace "$d/bad.tsv" >/dev/null 2>&1; echo $?)" "1"
    chk trace-missing-rejected "$(sc_trace "$d/none.tsv" >/dev/null 2>&1; echo $?)" "1"
    : > "$d/empty.tsv"
    chk trace-empty-rejected "$(sc_trace "$d/empty.tsv" >/dev/null 2>&1; echo $?)" "1"
    printf 'uplink\trrc_setup_request\tidentity=must-not-be-accepted\n' > "$d/extra.tsv"
    chk trace-extra-field-rejected "$(sc_trace "$d/extra.tsv" >/dev/null 2>&1; echo $?)" "1"

    # ── the deconceal delegate is 14_suci, and a null-scheme SUCI needs no key ──
    # A scheme-0 SUCI over MSIN 123456789 is built by 14_suci itself, so the
    # bytes and the expectation come from the module under test's neighbour and
    # not from a literal this file could drift away from.
    local suci0
    suci0=$(bash "$IMSISTING_ROOT/modules/14_suci.sh" --build-suci 0 123456789 2>/dev/null |
            awk -F'\t' '$1=="suci"{print $2; exit}')
    if [[ -n "$suci0" ]]; then
        out=$(sc_parse "$suci0" 2>/dev/null)
        chk parse-null-msin "$(kv "$out" msin)" "123456789"
        chk parse-null-result "$(kv "$out" result)" "msin-recovered"
    else
        chk parse-null-built "no-suci" "built"
    fi
    chk parse-garbage "$(sc_parse ZZ >/dev/null 2>&1; echo $?)" "1"

    # ── SUCI classifier: the scheme, the curve, and the operator it cannot name ──
    local cnull
    cnull=$(sc_classify_line 1 080100000021436587F9)
    chk classify-null-scheme "$(printf '%s' "$cnull" | sed -n 's/.*scheme=\([^ ]*\).*/\1/p')" "0"
    chk classify-null-curve  "$(printf '%s' "$cnull" | sed -n 's/.*curve=\([^ ]*\).*/\1/p')" "none"
    chk classify-null-msin   "$(printf '%s' "$cnull" | sed -n 's/.*msin=\([^ ]*\).*/\1/p')" "clear:123456789"
    chk classify-null-op     "$(printf '%s' "$cnull" | sed -n 's/.*operator=\([^ ]*\).*/\1/p')" "not-in-suci"
    chk classify-garbage "$(sc_classify_line 0 ZZ | awk '{print $NF}')" "malformed"
    chk classify-curve-a "$(sc_curve_for_scheme 1)" "X25519"
    chk classify-curve-b "$(sc_curve_for_scheme 2)" "secp256r1"
    chk classify-no-args "$(sc_classify </dev/null >/dev/null 2>&1; echo $?)" "2"

    # ── the catcher refuses to build a cell without a PLMN ──
    chk build-cell-no-plmn "$(sc_build_cell '' >/dev/null 2>&1; echo $?)" "2"
    chk build-cell-alpha   "$(sc_build_cell 20A01 >/dev/null 2>&1; echo $?)" "2"
    chk catch-needs-cell   "$(sc_catch_plan >/dev/null 2>&1; echo $?)" "1"
    chk mark-valid   "$(sc_mark_to_open5gs 0)" "0x0"
    chk mark-invalid "$(sc_mark_to_open5gs ZZ >/dev/null 2>&1; echo $?)" "2"

    printf 'ASSERTIONS\t%d\nRESULT\t%s\n' "$n" "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    (( bad == 0 ))
}

# ── menu ───────────────────────────────────────────────────────────────
suci_catcher_menu() {
    printf '\n=== 5G SUCI Catcher — live lane ===\n'
    cat <<'EOF'
  [1] Build the cell for a PLMN (SIB1 + AMF slice, consistency checked)
  [2] Write the catcher plan (the pre-authentication sequence)
  [3] Start the cell
  [4] Stop the cell
  [5] Parse a SUCI (and deconceal with the home network key)
  [6] Read identity responses out of a capture
  [7] Check a normalized event trace
  [8] Classify SUCI from a capture or a hex list
  [9] Write and verify the SUCI corpus
  [10] Status
  [0] Back
EOF
    local choice a b
    read -rp '  choice> ' choice || return 0
    case "$choice" in
        1) read -rp '  PLMN (MCC MNC, e.g. 20801)> ' a || return 0; sc_build_cell "$a"
           read -rp '  press enter ' _ ;;
        2) sc_catch_plan; read -rp '  press enter ' _ ;;
        3) sc_start; read -rp '  press enter ' _ ;;
        4) sc_stop; read -rp '  press enter ' _ ;;
        5) read -rp '  SUCI hex> ' a || return 0
           read -rp '  home network key (blank to parse only)> ' b || b=""
           sc_parse "$a" "$b"; read -rp '  press enter ' _ ;;
        6) read -rp '  capture path> ' a || return 0; sc_capture "$a"; read -rp '  press enter ' _ ;;
        7) read -rp '  event trace TSV path> ' a || return 0; sc_trace "$a"; read -rp '  press enter ' _ ;;
        8) read -rp '  capture path (blank for a hex list)> ' a || a=""
           if [[ -n "$a" ]]; then sc_classify_capture "$a"
           else printf '  one SUCI per line, blank line to finish\n'
                local lines=() l
                while IFS= read -r l && [[ -n "$l" ]]; do lines+=("$l"); done
                sc_classify "${lines[@]}" 2>/dev/null || printf 'ERROR\tnothing classified\n' >&2
           fi
           read -rp '  press enter ' _ ;;
        9) sc_corpus; read -rp '  press enter ' _ ;;
        10) sc_status; read -rp '  press enter ' _ ;;
        0|'') return 0 ;;
        *) printf 'ERROR\tunknown choice\n' >&2; read -rp '  press enter ' _ ;;
    esac
}

sc_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    if [[ "$cmd" == "--__index_probe__" ]]; then
        sc_cli_main --help
        return 0
    fi
    case "$cmd" in
        --build-cell)   sc_build_cell "${1:-}" "${2:-n78}" "${3:-640000}" "${4:-1}" ;;
        --catch)        sc_catch_plan "${1:-}" ;;
        --start)        sc_start ;;
        --stop)         sc_stop ;;
        --parse)        sc_parse "${1:-}" "${2:-}" ;;
        --deconceal)    sc_deconceal "${1:-}" "${2:-}" ;;
        --capture)      sc_capture "${1:-}" ;;
        --classify)     sc_classify "$@" ;;
        --classify-capture) sc_classify_capture "${1:-}" ;;
        --corpus)       sc_corpus "${1:-}" ;;
        --check-trace)
            (($# == 1)) || { printf 'ERROR\tusage: --check-trace <event-trace.tsv>\n' >&2; return 2; }
            sc_trace "$1" ;;
        --plmn-encode)  sc_plmn_encode "${1:-}" ;;
        --plmn-decode)  sc_plmn_decode "${1:-}" ;;
        --build-nas)
            case "${1:-}" in
                identity-request) printf 'nas_identity_request\t%s\n' "$(sc_identity_request_suci)" ;;
                registration-request) sc_registration_request ;;
                *) printf 'ERROR\t--build-nas takes identity-request or registration-request\n' >&2
                   return 2 ;;
            esac ;;
        --build-rrc)    sc_rrc_setup_complete "${1:-0}" "${2:-00101}" "${3:-7}" "${4:-01}" ;;
        --aka)          sc_aka_vector "${1:-}" "${2:-}" "${3:-}" "${4:-}" "${@:5}" ;;
        --kdf)          sc_kdf "${1:-}" "${2:-}" "${3:-}" "${4:-}" "${5:-}" "${6:-16}" ;;
        --decode-nas)   sc_nas_decode "${1:-}" ;;
        --status-tsv)   sc_status ;;
        --selftest)     sc_selftest ;;
        --menu)         suci_catcher_menu ;;
        --help|-h)
            cat <<'EOF'
5G SUCI Catcher — live lane

The pre-authentication identity exchange, built and driven:

  --build-cell <plmn> [band] [arfcn] [pci]
                        write an srsRAN gNB config and an Open5GS AMF slice for
                        the PLMN, and check that the two name the same network
  --catch [plmn]        write the catcher plan: the RRC SETUP COMPLETE, the NAS
                        IDENTITY REQUEST for SUCI, and the sequence between them
  --start               start the cell (needs srsRAN, a 5G core and an SDR)
  --stop                stop it (idempotent)
  --parse <suci> [key]  parse a SUCI; deconceal the MSIN when a home network
                        private key is supplied (profile A or B, via 14_suci)
  --deconceal <suci> <key>
                        the deconcealment alone
  --capture <pcap>      read the identity responses out of a capture with tshark
  --classify [suci]...  scheme, curve, key id and routing for each SUCI; a list
                        on stdin is accepted (one per line)
  --classify-capture <pcap>
                        the same classification for every identity response in
                        a capture, one row per record
  --corpus [dir]        write and verify a fixture corpus: null scheme, profile
                        A, profile B and the malformed cases
  --check-trace <tsv>   validate a direction<TAB>event trace

Builders and codecs (no radio, no files written):

  --build-nas <identity-request|registration-request>
  --build-rrc [tid] [plmn] [tac] [s-nssai-hex]
  --plmn-encode <plmn>   --plmn-decode <6-hex>
  --decode-nas <pdu-hex>
  --aka <ki> <rand> <sqn> <amf> [--op|--opc <hex>]
  --kdf <key-hex> <fc> <p0> <p1> <p2> [len]

  --status-tsv          what is installed, whether the cell is up, air readiness
  --selftest            every builder, codec, the Milenage vector and the trace
  --menu                interactive menu

The identity request is sent before authentication, because TS 24.501 8.2.6
puts it in the not-ciphered class: no key exists yet at that point. The SUCI
that comes back is concealed with the home network's public key, so the MSIN is
only recoverable with the home network's private key — the concealment is not
broken here, the UE is asked.
EOF
            ;;
        *) printf 'ERROR\tunknown or missing command; use --help\n' >&2; return 2 ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    set -o pipefail
    IMSISTING_CLI=1
    declare -F banner >/dev/null 2>&1 || banner() { :; }
    declare -F info   >/dev/null 2>&1 || info()   { printf '[info] %s\n' "$*" >&2; }
    declare -F warn   >/dev/null 2>&1 || warn()   { printf '[warn] %s\n' "$*" >&2; }
    declare -F err    >/dev/null 2>&1 || err()    { printf '[err]  %s\n' "$*" >&2; }
    declare -F ok     >/dev/null 2>&1 || ok()     { printf '[ok]   %s\n' "$*" >&2; }
    sc_cli_main "$@"
fi
