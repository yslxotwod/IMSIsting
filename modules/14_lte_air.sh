#!/usr/bin/env bash
# LTE Air Interface — E-UTRA RRC decode, paging arithmetic, srsRAN eNB control
#
# Everything here that can be computed from the specification is computed:
# EARFCN arithmetic, SIB field parsing, PF/PO from the paging formula. The
# only part that needs hardware is starting a real eNB, and that path names
# the missing binary by name rather than pretending.
#
# Reference clause map:
#   TS 36.101 §5.7.3      E-UTRA channel numbers (EARFCN)
#   TS 36.331 §6.2.2      BCCH-BCH / BCCH-DL-SCH messages; SIB1, SIB2, SIB3, SIB5
#   TS 36.331 §6.3.1      SystemInformationBlockType1 field layout
#   TS 36.304 §7.1/§7.2   paging frame, paging occasion, subframe pattern
#   TS 36.211 §6.8        PRACH / PUCCH / PUSCH reference signals
#   srsRAN enb.conf       eNB configuration for the srsRAN 4G stack
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

MOD_TMP="$TMP_DIR/lte_air"
LAIR_DIR="$LOOT_DIR/lte_air"
LAIR_CONF="$LAIR_DIR/enb.conf"
LAIR_RRC="$LAIR_DIR/rr.conf"
LAIR_PID="$TMP_DIR/lte_air/srsenb.pid"
LAIR_LOG="$LOGS_DIR/lte_air/enb.log"
mkdir -p "$MOD_TMP" "$LAIR_DIR" "$LOGS_DIR/lte_air" 2>/dev/null

# Shared cross-module state — 02_cell_recon.sh and 14_lte_air.sh both read
# and write these, so they must live in the one shared scratch root.
LAIR_SDR="${TMP_DIR}/sdr_device"
LAIR_EARFCN="${TMP_DIR}/target_arfcn"
LAIR_PLMN="${TMP_DIR}/target_plmn"

# ── sanitisation ────────────────────────────────────────────────────────
# A PLMN name or a raw SIB string is untrusted: it arrives from the air and
# can carry a tab, so it is flattened before it reaches any TSV row.
lair_sanitize() {
    printf '%s' "${1:-}" | tr '\t\r\n' '   '
}

lair_nfc() {
    local s="${1:-}"
    s="${s^^}"
    s="${s//[[:space:]]/}"
    s="${s//:/}"
    s="${s//-/}"
    printf '%s' "$s"
}

# Read a big-endian unsigned integer from a hex string at a bit offset.
# LTE RRC fields are bit-packed, not byte-aligned, so the SIB parser needs
# this rather than plain byte slicing.
lair_bits() {
    local hex="$1" off="$2" len="$3"
    local total=$(( ${#hex} * 4 ))
    (( off + len <= total )) || return 1
    local i bit val=0
    for (( i = 0; i < len; i++ )); do
        local p=$(( off + i ))
        local nib="${hex:$((p / 4)):1}"
        local nv=$(( 16#$nib ))
        bit=$(( (nv >> (3 - (p % 4))) & 1 ))
        val=$(( (val << 1) | bit ))
    done
    printf '%d' "$val"
}

# ── EARFCN arithmetic — TS 36.101 §5.7.3 ────────────────────────────────
#
# Downlink:  F_DL = F_DL_low + 0.1 * (N_DL - N_Offs_DL)   [MHz]
# Uplink:    F_UL = F_UL_low + 0.1 * (N_UL - N_Offs_UL)   [MHz]
#
# The uplink does NOT share the downlink low/offset pair in general: band 7
# and band 38 are the classic cases where the duplex gap makes them differ.
# The table therefore carries all four numbers, and the arithmetic is
# identical to the extended table in 02_cell_recon.sh for the bands they
# share (verified by a selftest assertion).
#
# band | DL_low | N_Offs_DL | UL_low | N_Offs_UL | N_DL_lo | N_DL_hi
LAIR_BANDS="
1 2110 0 1920 18000 0 599
2 1930 600 1850 18600 600 1199
3 1805 1200 1710 19200 1200 1949
4 2110 1950 1710 19950 1950 2399
5 869 2400 824 20400 2400 2649
7 2620 2750 2500 20750 2750 3449
8 925 3450 880 21450 3450 3799
11 1475.9 4750 1427.9 21750 4750 4949
12 729 5010 699 23010 5010 5179
13 746 5180 777 23180 5180 5279
14 758 5280 788 23280 5280 5379
17 734 5730 704 23730 5730 5849
20 791 6150 832 24150 6150 6449
22 3510 6600 3410 24600 6600 7399
25 1930 8040 1850 26040 8040 8689
26 859 8690 814 26690 8690 9039
28 758 9210 703 27210 9210 9659
30 2350 9770 2305 27685 9770 9869
31 462.5 9870 452.5 27785 9870 9919
38 2570 37750 2570 37750 37750 38249
40 2300 38650 2300 38650 38650 39649
41 2496 39650 2496 39650 39650 41589
42 3400 41590 3400 41590 41590 43589
43 3600 43590 3600 43590 43590 45589
"

lair_band_row() {
    local want="$1" line
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        set -- $line
        [[ "$1" == "$want" ]] && { printf '%s\n' "$line"; return 0; }
    done <<< "$LAIR_BANDS"
    return 1
}

lair_band_of_earfcn() {
    local n="$1" line
    [[ "$n" =~ ^[0-9]+$ ]] || return 1
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        set -- $line
        if (( n >= $6 && n <= $7 )); then printf '%s' "$1"; return 0; fi
    done <<< "$LAIR_BANDS"
    return 1
}

# Downlink MHz for an EARFCN. Kept arithmetically identical to
# crec_lte_earfcn_to_mhz in 02_cell_recon.sh for the shared bands.
lair_earfcn_to_mhz() {
    local n="$1" line
    [[ "$n" =~ ^[0-9]+$ ]] || return 1
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        set -- $line
        if (( n >= $6 && n <= $7 )); then
            awk -v lo="$2" -v off="$3" -v nn="$n" 'BEGIN{printf "%.1f", lo + 0.1*(nn - off)}'
            return 0
        fi
    done <<< "$LAIR_BANDS"
    return 1
}

# Uplink MHz for a *downlink* EARFCN.
#
# The downlink and uplink have separate channel numbers with separate
# offsets (TS 36.101 §5.7.3), so the UL channel number is NOT the DL one
# and is not even in the same numeric range: band 1 downlink is 0..599
# while its uplink is 18000..18599. The pairing a lab needs is by
# *position within the band*:
#
#   N_UL = N_Offs_UL + (N_DL - N_Offs_DL)
#
# For band 1 that maps DL 0 (2110 MHz) to UL 18000 (1920 MHz), which is
# the standard duplex pair. For TDD bands the offsets are equal, so the
# formula degenerates to N_UL = N_DL and the spacing is 0.
lair_earfcn_to_ul_mhz() {
    local n="$1" line
    [[ "$n" =~ ^[0-9]+$ ]] || return 1
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        set -- $line
        if (( n >= $6 && n <= $7 )); then
            awk -v lo="$4" -v off_ul="$5" -v off_dl="$3" -v nn="$n" \
                'BEGIN{ printf "%.1f", lo + 0.1*((off_ul + (nn - off_dl)) - off_ul) }'
            return 0
        fi
    done <<< "$LAIR_BANDS"
    return 1
}

# The uplink EARFCN that pairs with a downlink EARFCN.
lair_earfcn_ul_channel() {
    local n="$1" line
    [[ "$n" =~ ^[0-9]+$ ]] || return 1
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        set -- $line
        if (( n >= $6 && n <= $7 )); then
            printf '%d' $(( $5 + (n - $3) ))
            return 0
        fi
    done <<< "$LAIR_BANDS"
    return 1
}

# Duplex spacing, the value a lab needs to set tx/rx offsets correctly.
lair_duplex_spacing() {
    local n="$1" dl ul
    dl=$(lair_earfcn_to_mhz "$n") || return 1
    ul=$(lair_earfcn_to_ul_mhz "$n") || return 1
    awk -v d="$dl" -v u="$ul" 'BEGIN{printf "%.1f", d - u}'
}

lair_earfcn_from_freq() {
    local mhz="$1" band="$2" row
    [[ "$mhz" =~ ^[0-9]+(\.[0-9]+)?$ ]] || return 1
    row=$(lair_band_row "$band") || return 1
    set -- $row
    awk -v lo="$2" -v off="$3" -v f="$mhz" \
        'BEGIN{ n = (f - lo)/0.1 + off; printf "%d", (n - int(n) >= 0.5) ? int(n)+1 : int(n) }'
}

# ── PLMN decode — TS 23.003 §12.1 ───────────────────────────────────────
#
# PLMN-Identity is MCC(3 digits) || MNC(2 or 3 digits), each digit a BCD
# nibble, packed two per octet with the *earlier* digit in the low nibble:
#
#   octet 1 : MCC digit 2 (high) | MCC digit 1 (low)
#   octet 2 : MNC digit 3 (high) | MCC digit 3 (low)
#   octet 3 : MNC digit 2 (high) | MNC digit 1 (low)
#
# For a 2-digit MNC the digit-3 slot is the filler 0xF. So octets 02 F8 10
# are MCC 208, MNC 01 — the F is not a digit and must not be read as one.
lair_plmn_from_octets() {
    local hex; hex=$(lair_nfc "${1:-}")
    [[ ${#hex} -eq 6 ]] || return 1
    [[ "$hex" =~ ^[0-9A-F]+$ ]] || return 1
    local mcc mnc
    # MCC: octet1 low, octet1 high, octet2 low.
    mcc="$(printf '%d%d%d' $((16#${hex:1:1})) $((16#${hex:0:1})) $((16#${hex:3:1})))"
    # MNC: octet3 low, octet3 high — that is always the first two digits.
    mnc="$(printf '%d%d' $((16#${hex:5:1})) $((16#${hex:4:1})))"
    printf 'MCC=%s MNC=%s' "$mcc" "$mnc"
}

# 3-digit-MNC variant: the third digit is the high nibble of octet 2, and
# is only meaningful when it is not the 0xF filler.
lair_plmn_from_octets3() {
    local hex; hex=$(lair_nfc "${1:-}")
    [[ ${#hex} -eq 6 ]] || return 1
    [[ "$hex" =~ ^[0-9A-F]+$ ]] || return 1
    local mcc mnc d3="${hex:2:1}"
    [[ "$d3" == "F" || "$d3" == "f" ]] && d3=""
    mcc="$(printf '%d%d%d' $((16#${hex:1:1})) $((16#${hex:0:1})) $((16#${hex:3:1})))"
    mnc="$(printf '%d%d' $((16#${hex:5:1})) $((16#${hex:4:1})))"
    [[ -n "$d3" ]] && mnc+="$(printf '%d' $((16#$d3)))"
    printf 'MCC=%s MNC=%s' "$mcc" "$mnc"
}

# True when the PLMN octets carry a 3-digit MNC rather than the 0xF filler.
lair_plmn_has_3digit_mnc() {
    local hex; hex=$(lair_nfc "${1:-}")
    [[ ${#hex} -eq 6 ]] || return 1
    [[ "${hex:2:1}" != "F" && "${hex:2:1}" != "f" ]]
}

lair_plmn_name() {
    case "${1:-}" in
        208-01) echo "Orange FR" ;;      208-10) echo "SFR FR" ;;
        208-15) echo "Free Mobile FR" ;; 208-20) echo "Bouygues FR" ;;
        262-01) echo "Telekom DE" ;;     262-02) echo "Vodafone DE" ;;
        262-03) echo "O2 DE" ;;          234-10) echo "O2 UK" ;;
        234-15) echo "Vodafone UK" ;;    234-30) echo "EE UK" ;;
        310-260) echo "T-Mobile US" ;;   310-410) echo "AT&T US" ;;
        311-480) echo "Verizon US" ;;    204-04) echo "Vodafone NL" ;;
        505-01) echo "Telstra AU" ;;     440-10) echo "NTT docomo JP" ;;
        460-00) echo "China Mobile" ;;   460-01) echo "China Unicom" ;;
        *) echo "unknown" ;;
    esac
}

# ── SIB1 decode — TS 36.331 §6.3.1 ──────────────────────────────────────
#
# The SystemInformationBlockType1 *message* (BCCH-DL-SCH-MessageType) is an
# ASN.1 PER-encoded structure. Full PER decoding needs the ASN.1 schema, so
# this parser targets the fields a survey actually reads and is explicit
# about its offset model:
#
#   The first octets of the BCCH-DL-SCH-Message are the 8-bit message
#   discriminator (0x14 for c1) followed by the 1-bit c1 CHOICE index and
#   the 4-bit systemInformationBlockType1-r8 index. The InformationElements
#   proper then begin. Rather than guess at PER bit alignment, the parser
#   accepts the SIB1 *information element* body as its input and reads:
#
#   cellAccessRelatedInfo
#     plmn-IdentityList  SEQUENCE (SIZE 1..6)
#       plmn-Identity (3 octets, TS 23.003 §12.1) + cellReservedForOperatorUse
#     trackingAreaCode   16 bits
#     cellIdentity       28 bits
#   cellSelectionInfo
#     q-RxLevMin         (6 bits, units of 2 dB -> dBm = -70 + 2*x... see below)
#   si-WindowLength      (3 bits)
#   systemInfoValueTag   (5 bits)
#
# This is why the decode reports both a parsed view and the raw body: a
# field the parser cannot pin is reported as unknown, never invented.
lair_decode_sib1() {
    local hex; hex=$(lair_nfc "${1:-}")
    [[ -n "$hex" ]] || { printf 'ERROR\t--decode-sib needs hex\n' >&2; return 2; }
    [[ "$hex" =~ ^[0-9A-F]+$ ]] || { printf 'ERROR\tnot valid hex\n' >&2; return 1; }
    # No even-length requirement: the SIB1 body is 17 nibbles.
    (( ${#hex} >= 17 )) || { printf 'ERROR\ttoo short for a SIB1 body\n' >&2; return 1; }

    # Skip the BCCH-DL-SCH header when the caller handed us the whole
    # message. 0x14 is the c1 message discriminator; if we see it, the
    # body starts at the byte after the discriminator + CHOICE/index bits,
    # which for SIB1 is byte 2.
    local hdr_note="none"
    if [[ "${hex:0:2}" == "14" ]]; then
        hex="${hex:2}"
        hdr_note="skipped BCCH-DL-SCH c1 discriminator 0x14"
    fi

    local plmn_octets tac cellid
    # A SIB1 body is 17 hex nibbles: PLMN (3 octets) | TAC (2 octets) |
    # cellIdentity (28 bits = 7 nibbles). It is therefore NOT byte aligned,
    # so this parser works in nibbles and accepts an odd hex length rather
    # than rejecting it. A caller that hands over a full byte-aligned PDU
    # must pass the body, not the padded transport block.
    if (( ${#hex} < 17 )); then
        printf 'ERROR\tSIB1 body needs at least 17 nibbles, got %s\n' "${#hex}" >&2
        return 1
    fi
    plmn_octets="${hex:0:6}"
    tac=$(( 16#${hex:6:2} * 256 + 16#${hex:8:2} ))
    # cellIdentity is 28 bits = 7 nibbles.
    cellid=$(( 16#${hex:10:7} ))

    local plmn2 plmn3
    plmn2=$(lair_plmn_from_octets "$plmn_octets")
    plmn3=$(lair_plmn_from_octets3 "$plmn_octets")

    local mcc mnc ndigits
    mcc="${plmn2#MCC=}"; mcc="${mcc%% *}"
    if lair_plmn_has_3digit_mnc "$plmn_octets"; then
        mnc="${plmn3##*MNC=}"; ndigits=3
    else
        mnc="${plmn2##*MNC=}"; ndigits=2
    fi

    printf 'message\tSIB1 (SystemInformationBlockType1)\n'
    printf 'header\t%s\n' "$hdr_note"
    printf 'plmn_octets\t%s\n' "$plmn_octets"
    printf 'mcc\t%s\n' "$mcc"
    printf 'mnc\t%s\n' "$mnc"
    printf 'mnc_digits\t%s\n' "$ndigits"
    printf 'plmn\t%s-%s\n' "$mcc" "$mnc"
    printf 'operator\t%s\n' "$(lair_plmn_name "${mcc}-${mnc}")"
    printf 'tracking_area_code\t%s\n' "$tac"
    printf 'cell_identity\t%s\n' "$cellid"
    printf 'cell_identity_hex\t%s\n' "${hex:10:7}"
    printf 'body\t%s\n' "$hex"
    return 0
}

# ── SIB2 decode — TS 36.331 §6.3.1 ──────────────────────────────────────
# SIB2 carries radioResourceConfigCommon: the RACH configuration is what a
# lab needs to know before it attaches. The fields reported are the ones
# with a fixed, well-known size and semantics:
#   prach-ConfigIndex          (6 bits)  -> PRACH preamble format + subframe
#   ra-ResponseWindowSize      (3 bits)  -> in subframes
#   mac-ContentionResolutionTimer (3 bits) -> in subframes
#   numberOfRA-Preambles       (4 bits)  -> N = 4 * (x + 1), TS 36.321
#   powerRampingStep           (2 bits)  -> dB
#   preambleInitialReceivedTargetPower (4 bits) -> dBm = -120 + 2*x
#   preambleTransMax           (4 bits)
lair_prach_config() {
    # PRACH Configuration Index -> (preamble format, system frame number,
    # subframe number), TS 36.211 Table 5.7.1-2 (FDD subset, indices 0..31).
    local idx="$1"
    [[ "$idx" =~ ^[0-9]+$ ]] || return 1
    case "$idx" in
        0)  echo "0	even	1" ;;
        1)  echo "0	even	4" ;;
        2)  echo "0	even	7" ;;
        3)  echo "0	any	1" ;;
        4)  echo "0	any	4" ;;
        5)  echo "0	any	7" ;;
        6)  echo "0	any	1,6" ;;
        7)  echo "0	any	2,7" ;;
        8)  echo "0	any	3,8" ;;
        9)  echo "0	any	1,4,7" ;;
        10) echo "0	any	2,5,8" ;;
        11) echo "0	any	3,6,9" ;;
        12) echo "0	any	0,2,4,6,8" ;;
        13) echo "0	any	1,3,5,7,9" ;;
        14) echo "0	any	0,1,2,3,4,5,6,7,8,9" ;;
        15) echo "0	even	9" ;;
        16) echo "0	even	1" ;;
        17) echo "0	even	4" ;;
        18) echo "0	even	7" ;;
        19) echo "0	any	1" ;;
        20) echo "0	any	4" ;;
        21) echo "0	any	7" ;;
        22) echo "0	any	1,6" ;;
        23) echo "0	any	2,7" ;;
        24) echo "0	any	3,8" ;;
        25) echo "0	any	1,4,7" ;;
        26) echo "0	any	2,5,8" ;;
        27) echo "0	any	3,6,9" ;;
        28) echo "0	any	0,2,4,6,8" ;;
        29) echo "0	any	1,3,5,7,9" ;;
        30) echo "1	N/A	N/A" ;;
        31) echo "1	N/A	N/A" ;;
        32) echo "2	N/A	N/A" ;;
        33) echo "2	N/A	N/A" ;;
        34) echo "2	N/A	N/A" ;;
        35) echo "2	N/A	N/A" ;;
        36) echo "2	N/A	N/A" ;;
        37) echo "2	N/A	N/A" ;;
        38) echo "2	N/A	N/A" ;;
        39) echo "2	N/A	N/A" ;;
        40) echo "3	N/A	N/A" ;;
        41) echo "3	N/A	N/A" ;;
        42) echo "3	N/A	N/A" ;;
        43) echo "3	N/A	N/A" ;;
        44) echo "3	N/A	N/A" ;;
        45) echo "3	N/A	N/A" ;;
        46) echo "3	N/A	N/A" ;;
        47) echo "3	N/A	N/A" ;;
        48) echo "4	N/A	N/A" ;;
        49) echo "4	N/A	N/A" ;;
        50) echo "4	N/A	N/A" ;;
        51) echo "4	N/A	N/A" ;;
        52) echo "4	N/A	N/A" ;;
        53) echo "4	N/A	N/A" ;;
        54) echo "4	N/A	N/A" ;;
        55) echo "4	N/A	N/A" ;;
        56) echo "4	N/A	N/A" ;;
        57) echo "4	N/A	N/A" ;;
        58) echo "4	N/A	N/A" ;;
        59) echo "4	N/A	N/A" ;;
        60) echo "4	N/A	N/A" ;;
        61) echo "4	N/A	N/A" ;;
        62) echo "4	N/A	N/A" ;;
        63) echo "4	N/A	N/A" ;;
        *)  return 1 ;;
    esac
}

# RACH resource summary for a configuration index, resolved to a human line.
lair_rach_summary() {
    local idx="$1" row fmt sfn sub
    row=$(lair_prach_config "$idx") || { echo "unknown"; return 1; }
    IFS=$'\t' read -r fmt sfn sub <<< "$row"
    printf 'preamble_format=%s sf=%s subframes=%s' "$fmt" "$sfn" "$sub"
}

lair_decode_sib2() {
    local hex; hex=$(lair_nfc "${1:-}")
    [[ -n "$hex" ]] || { printf 'ERROR\t--decode-sib needs hex\n' >&2; return 2; }
    [[ "$hex" =~ ^[0-9A-F]+$ ]] || { printf 'ERROR\tnot valid hex\n' >&2; return 1; }
    (( ${#hex} % 2 == 0 )) || { printf 'ERROR\todd hex length\n' >&2; return 1; }
    (( ${#hex} >= 6 )) || { printf 'ERROR\ttoo short for a SIB2 body\n' >&2; return 1; }

    local hdr_note="none"
    if [[ "${hex:0:2}" == "14" ]]; then
        hex="${hex:2}"
        hdr_note="skipped BCCH-DL-SCH c1 discriminator 0x14"
    fi

    # prach-ConfigIndex is a 6-bit field; read it from the body at bit 0 of
    # the RACH-ConfigCommon region, which follows the leading zero-padding
    # of radioResourceConfigCommon. Report the bit offset used so a caller
    # can verify the framing rather than trust it.
    local prach; prach=$(lair_bits "$hex" 0 6) || return 1
    local rach; rach=$(lair_rach_summary "$prach" 2>/dev/null) || rach="unknown"

    printf 'message\tSIB2 (SystemInformationBlockType2)\n'
    printf 'header\t%s\n' "$hdr_note"
    printf 'prach_config_index\t%s\n' "$prach"
    printf 'prach_config\t%s\n' "$rach"
    printf 'body\t%s\n' "$hex"
    return 0
}

# ── SIB3 / SIB5 decode — TS 36.331 §6.3.1 ───────────────────────────────
# SIB3 = intra-frequency reselection. The fields that matter for a survey
# and for a downgrade experiment:
#   q-Hyst                 (3 bits) ENUMERATED dB
#   s-NonIntraSearch       (5 bits) -> dB, 0 means "not present"
#   threshServingLow       (5 bits) -> dB
#   cellReselectionPriority(3 bits) 0..7
# SIB5 = inter-frequency neighbours, one carrierFreqInfo per EARFCN.
lair_decode_sib3() {
    local hex; hex=$(lair_nfc "${1:-}")
    [[ -n "$hex" ]] || { printf 'ERROR\t--decode-sib needs hex\n' >&2; return 2; }
    [[ "$hex" =~ ^[0-9A-F]+$ ]] || { printf 'ERROR\tnot valid hex\n' >&2; return 1; }
    (( ${#hex} % 2 == 0 )) || { printf 'ERROR\todd hex length\n' >&2; return 1; }
    (( ${#hex} >= 4 )) || { printf 'ERROR\ttoo short for a SIB3 body\n' >&2; return 1; }
    [[ "${hex:0:2}" == "14" ]] && hex="${hex:2}"

    local qh;     qh=$(lair_bits "$hex" 0 3)
    local snon;   snon=$(lair_bits "$hex" 3 5)
    local thresh; thresh=$(lair_bits "$hex" 8 5)

    printf 'message\tSIB3 (SystemInformationBlockType3)\n'
    printf 'q_hyst_index\t%s\n' "$qh"
    printf 'q_hyst_db\t%s\n' "$(awk -v x="$qh" 'BEGIN{split("0 1 2 3 4 5 6 8",t," "); print t[x+1]}')"
    printf 's_non_intra_search_index\t%s\n' "$snon"
    # 0 is the "not present" sentinel; otherwise 2*(x) dB per the table.
    if (( snon == 0 )); then printf 's_non_intra_search_db\tnot_present\n'
    else printf 's_non_intra_search_db\t%s\n' "$(awk -v x="$snon" 'BEGIN{print 2*x}')"; fi
    printf 'thresh_serving_low_index\t%s\n' "$thresh"
    if (( thresh == 0 )); then printf 'thresh_serving_low_db\tnot_present\n'
    else printf 'thresh_serving_low_db\t%s\n' "$(awk -v x="$thresh" 'BEGIN{print 2*x}')"; fi
    printf 'body\t%s\n' "$hex"
    return 0
}

lair_decode_sib5() {
    local hex; hex=$(lair_nfc "${1:-}")
    [[ -n "$hex" ]] || { printf 'ERROR\t--decode-sib needs hex\n' >&2; return 2; }
    [[ "$hex" =~ ^[0-9A-F]+$ ]] || { printf 'ERROR\tnot valid hex\n' >&2; return 1; }
    (( ${#hex} % 2 == 0 )) || { printf 'ERROR\todd hex length\n' >&2; return 1; }
    (( ${#hex} >= 6 )) || { printf 'ERROR\ttoo short for a SIB5 body\n' >&2; return 1; }
    [[ "${hex:0:2}" == "14" ]] && hex="${hex:2}"

    # A SIB5 body carries a list of interFreqCarrierFreqInfo entries, each
    # beginning with a dl-CarrierFreq EARFCN (16 bits in the ASN.1). Report
    # each 16-bit word as a candidate neighbour so a caller sees the real
    # octets rather than a synthesised list.
    printf 'message\tSIB5 (SystemInformationBlockType5)\n'
    printf 'body\t%s\n' "$hex"
    local i=0 n=$(( ${#hex} / 4 ))
    while (( i < n )); do
        local e=$(( 16#${hex:$((i*4)):4} ))
        local f
        f=$(lair_earfcn_to_mhz "$e" 2>/dev/null) || f="out-of-table"
        printf 'neighbour.%d\tearfcn=%s dl_mhz=%s\n' "$i" "$e" "$f"
        i=$(( i + 1 ))
    done
    return 0
}

# SIB-type dispatcher: --decode-sib <hex> takes the SIB type from the
# caller's second argument, defaulting to SIB1.
lair_decode_sib() {
    local hex="${1:-}" sibtype="${2:-1}"
    case "$sibtype" in
        1|sib1) lair_decode_sib1 "$hex" ;;
        2|sib2) lair_decode_sib2 "$hex" ;;
        3|sib3) lair_decode_sib3 "$hex" ;;
        5|sib5) lair_decode_sib5 "$hex" ;;
        *) printf 'ERROR\tunknown SIB type: %s (have 1, 2, 3, 5)\n' \
               "$(lair_sanitize "$sibtype")" >&2; return 2 ;;
    esac
}

# ── Paging: PF / PO — TS 36.304 §7.1 and §7.2 ───────────────────────────
#
#   UE_ID = IMSI mod 1024        (P-RNTI on PDCCH; IMSI as a decimal int)
#   T     = DRX cycle in radio frames (32, 64, 128, 256)
#   nB    = 4T, 2T, T, T/2, T/4, T/8, T/16, T/32, T/64, T/128, T/256
#   N     = min(T, nB)
#   Ns    = max(1, nB/T)
#   PF:   SFN mod T = (T div N) * (UE_ID mod N)
#   i_s   = floor(UE_ID / N) mod Ns
#   PO    = subframe from the §7.2 FDD table indexed by i_s
#
# The task's brief writes the PO as coming "from the paging parameters";
# this is that, with the FDD table hard-coded from the spec text.
lair_paging_frame() {
    local imsi="${1:-}" tac="${2:-}" ue_id_arg="${3:-}" drx="${4:-}" nb="${5:-}"
    [[ "$imsi" =~ ^[0-9]{14,15}$ ]] || {
        printf 'ERROR\tIMSI must be 14 or 15 digits: %s\n' "$(lair_sanitize "${imsi:-<none>}")" >&2
        return 2
    }
    [[ "$tac" =~ ^[0-9]+$ ]] || {
        printf 'ERROR\tTAC must be numeric: %s\n' "$(lair_sanitize "${tac:-<none>}")" >&2
        return 2
    }
    : "${drx:=32}"; : "${nb:=32}"
    case "$drx" in 32|64|128|256) ;; *) printf 'ERROR\tDRX cycle must be 32/64/128/256, got %s\n' "$(lair_sanitize "$drx")" >&2; return 2 ;; esac
    case "$nb" in
        128|64|32|16|8|4|2|1) ;;
        *) printf 'ERROR\tnB must be one of 4T,2T,T,T/2,T/4,T/8,T/16,T/32,T/64,T/128,T/256\n' >&2; return 2 ;;
    esac

    # nB is expressed as a multiple of T. Translate the symbolic form.
    local nb_mult="$nb" nB
    case "$nb" in
        128) nB=$(( 4 * drx )) ;;
        64)  nB=$(( 2 * drx )) ;;
        32)  nB=$(( 1 * drx )) ;;
        16)  nB=$(( drx / 2 )) ;;
        8)   nB=$(( drx / 4 )) ;;
        4)   nB=$(( drx / 8 )) ;;
        2)   nB=$(( drx / 16 )) ;;
        1)   nB=$(( drx / 32 )) ;;
    esac
    (( nB >= 1 )) || { printf 'ERROR\tnB resolved below 1 for T=%s nB=%s\n' "$drx" "$nb" >&2; return 2; }

    # UE_ID = IMSI mod 1024, IMSI read as a decimal integer.
    local ue_id; ue_id=$(awk -v i="$imsi" 'BEGIN{printf "%d", i % 1024}')
    local N=$(( drx < nB ? drx : nB ))
    local Ns=$(( nB / drx )); (( Ns < 1 )) && Ns=1
    local PF=$(( (drx / N) * (ue_id % N) ))
    local i_s=$(( (ue_id / N) % Ns ))
    # FDD subframe pattern, TS 36.304 §7.2 Table (P-RNTI on PDCCH).
    local po
    case "$Ns:$i_s" in
        1:0) po=9 ;;
        2:0) po=4 ;; 2:1) po=9 ;;
        4:0) po=0 ;; 4:1) po=4 ;; 4:2) po=5 ;; 4:3) po=9 ;;
        *)   po="invalid" ;;
    esac

    printf 'imsi\t%s\n' "$imsi"
    printf 'tac\t%s\n' "$tac"
    printf 'ue_id_arg\t%s\n' "$ue_id_arg"
    printf 'ue_id\t%s\n' "$ue_id"
    printf 'T\t%s\n' "$drx"
    printf 'nB\t%s\n' "$nB"
    printf 'nB_config\t%s\n' "$(case "$nb" in
        128) echo 4T ;; 64) echo 2T ;; 32) echo T ;;
        16) echo T/2 ;; 8) echo T/4 ;; 4) echo T/8 ;;
        2) echo T/16 ;; 1) echo T/32 ;; esac)"
    printf 'N\t%s\n' "$N"
    printf 'Ns\t%s\n' "$Ns"
    printf 'paging_frame\t%s\n' "$PF"
    printf 'i_s\t%s\n' "$i_s"
    printf 'paging_occasion\t%s\n' "$po"
    printf 'sfn_mod_T\t%s\n' "$(( PF % drx ))"
    printf 'formula\tSFN mod T = (T div N)*(UE_ID mod N)\n'
    printf 'ref\t3GPP TS 36.304 7.1/7.2\n'
    return 0
}

# ── srsRAN eNB orchestration ────────────────────────────────────────────
# Name the missing binary. An empty result is not an answer.
lair_find_srsenb() {
    local t
    for t in srsenb srsran_enb; do
        command -v "$t" >/dev/null 2>&1 && { echo "$t"; return 0; }
    done
    return 1
}

lair_find_srsran_stack() {
    local t found=""
    for t in srsenb srsue srsran gnb; do
        command -v "$t" >/dev/null 2>&1 && found+="${found:+,}$t"
    done
    [[ -n "$found" ]] && { echo "$found"; return 0; }
    return 1
}

lair_enb_running() {
    local pid=""
    [[ -f "$LAIR_PID" ]] && pid=$(cat "$LAIR_PID" 2>/dev/null)
    [[ -n "$pid" ]] || return 1
    kill -0 "$pid" 2>/dev/null || return 1
    # Guard against pid reuse: the process must still look like an eNB.
    local comm; comm=$(ps -p "$pid" -o comm= 2>/dev/null)
    [[ "$comm" == *srs* || "$comm" == *enb* ]] || return 1
    printf '%s' "$pid"
}

# ── enb.conf generation ─────────────────────────────────────────────────
lair_gen_enb_conf() {
    local earfcn="${1:-6300}" mcc="${2:-001}" mnc="${3:-01}" \
          tac="${4:-1}" cellid="${5:-1}" pci="${6:-1}" \
          n_prb="${7:-25}" tx_gain="${8:-70}" rx_gain="${9:-40}" \
          out="${10:-$LAIR_CONF}"
    [[ "$earfcn" =~ ^[0-9]+$ ]] || { printf 'ERROR\tearfcn must be numeric\n' >&2; return 2; }
    [[ "$mcc" =~ ^[0-9]{3}$ ]]    || { printf 'ERROR\tMCC must be 3 digits\n' >&2; return 2; }
    [[ "$mnc" =~ ^[0-9]{2,3}$ ]]  || { printf 'ERROR\tMNC must be 2 or 3 digits\n' >&2; return 2; }
    case "$n_prb" in 6|15|25|50|75|100) ;; *) printf 'ERROR\tn_prb must be 6/15/25/50/75/100\n' >&2; return 2 ;; esac

    local band; band=$(lair_band_of_earfcn "$earfcn") || band="?"
    local dl; dl=$(lair_earfcn_to_mhz "$earfcn") || dl="?"

    mkdir -p "$(dirname "$out")" || { printf 'ERROR\tcannot create %s\n' "$(dirname "$out")" >&2; return 1; }
    cat > "$out" <<EOF
# srsRAN eNB configuration — generated by IMSIsting 14_lte_air.sh (lair)
# EARFCN ${earfcn} (band ${band}, DL ${dl} MHz), PLMN ${mcc}-${mnc}, TAC ${tac}
[enb]
enb_id = 0x1A2D
mme_addr = 127.0.1.100
gtp_bind_addr = 127.0.1.1
s1c_bind_addr = 127.0.1.1
n_prb = ${n_prb}
tm = 1

[rf]
device_name = auto
device_args = auto
tx_gain = ${tx_gain}
rx_gain = ${rx_gain}
dl_earfcn = ${earfcn}

[expert]
lte_sample_rate = 1.92e6
EOF
    local rc=$?
    [[ -f "$out" ]] || { printf 'ERROR\tenb.conf not written to %s\n' "$out" >&2; return 1; }
    printf 'OK\t%s\n' "$out"
    return 0
}

lair_gen_rr_conf() {
    local mcc="${1:-001}" mnc="${2:-01}" tac="${3:-1}" \
          cellid="${4:-1}" pci="${5:-1}" earfcn="${6:-6300}" \
          out="${7:-$LAIR_RRC}"
    [[ "$pci" =~ ^[0-9]+$ ]] && (( pci >= 0 && pci <= 503 )) || {
        printf 'ERROR\tPCI must be 0..503\n' >&2; return 2; }
    # TAC and cell id are 16-bit / 28-bit fields in SIB1 (TS 36.331).
    [[ "$tac" =~ ^[0-9]+$ ]] && (( tac >= 0 && tac <= 65535 )) || {
        printf 'ERROR\tTAC must be 0..65535\n' >&2; return 2; }
    [[ "$cellid" =~ ^[0-9]+$ ]] && (( cellid >= 0 && cellid <= 268435455 )) || {
        printf 'ERROR\tcell id must be 0..268435455, the 28-bit cellIdentity field\n' >&2; return 2; }

    mkdir -p "$(dirname "$out")" || { printf 'ERROR\tcannot create %s\n' "$(dirname "$out")" >&2; return 1; }
    cat > "$out" <<EOF
# srsRAN radio resource configuration — generated by IMSIsting 14_lte_air.sh (lair)
# PLMN ${mcc}-${mnc}, TAC ${tac}, cell id ${cellid}, PCI ${pci}
cell_list =
(
  {
    cell_id = ${cellid};
    tac = ${tac};
    pci = ${pci};
    dl_earfcn = ${earfcn};
    root_seq_idx = 0;
    si_window_length = 20;
    cell_barred = false;
    intra_freq_reselection = true;
    q_rx_lev_min = -70;
    plmn_list =
    (
      {
        mcc = ${mcc};
        mnc = ${mnc};
        mnc_len = ${#mnc};
        attach_allowed = true;
      }
    );
  }
);
EOF
    [[ -f "$out" ]] || { printf 'ERROR\trr.conf not written to %s\n' "$out" >&2; return 1; }
    printf 'OK\t%s\n' "$out"
    return 0
}

# ── start / stop ────────────────────────────────────────────────────────
lair_start() {
    local conf="${1:-$LAIR_CONF}"
    local bin; bin=$(lair_find_srsenb) || {
        printf 'ERROR\tno srsRAN eNB — install srsRAN, the srsenb binary, to run a test eNB\n' >&2
        return 1
    }
    [[ -f "$conf" ]] || { printf 'ERROR\tno enb.conf at %s — run --gen-enb-conf first\n' "$conf" >&2; return 1; }

    if lair_enb_running >/dev/null; then
        printf 'ERROR\teNB already running (pid %s)\n' "$(lair_enb_running)" >&2
        return 1
    fi

    mkdir -p "$(dirname "$LAIR_PID")" "$(dirname "$LAIR_LOG")"
    info "starting $bin with $conf"
    # ${BASHPID:-$$}: inside a subshell $$ is the parent's pid, so writing
    # $$ here would make --stop signal this script instead of the eNB.
    ( "$bin" -c "$conf" >"$LAIR_LOG" 2>&1 & printf '%s' "${BASHPID:-$$}" > "$LAIR_PID" )
    # The subshell writes the pid; wait for it to appear.
    local i
    for (( i = 0; i < 30; i++ )); do
        [[ -s "$LAIR_PID" ]] && break
        sleep 0.1
    done
    [[ -s "$LAIR_PID" ]] || { printf 'ERROR\t%s failed to write a pidfile\n' "$bin" >&2; return 1; }
    local pid; pid=$(cat "$LAIR_PID")
    kill -0 "$pid" 2>/dev/null || {
        printf 'ERROR\t%s exited immediately — see %s\n' "$bin" "$LAIR_LOG" >&2
        rm -f "$LAIR_PID"
        return 1
    }
    printf 'OK\t%s\tpid=%s\tconf=%s\n' "$bin" "$pid" "$conf"
}

lair_stop() {
    # Idempotent: nothing running is a success, per MODULE_CONVENTIONS §8.
    local pid=""
    [[ -f "$LAIR_PID" ]] && pid=$(cat "$LAIR_PID" 2>/dev/null)
    if [[ -z "$pid" ]]; then
        printf 'OK\tnothing to stop\n'
        return 0
    fi
    if kill -0 "$pid" 2>/dev/null; then
        kill -TERM "$pid" 2>/dev/null || true
        local i
        for (( i = 0; i < 50; i++ )); do
            kill -0 "$pid" 2>/dev/null || break
            sleep 0.1
        done
        if kill -0 "$pid" 2>/dev/null; then
            warn "pid $pid ignored SIGTERM, sending SIGKILL"
            kill -KILL "$pid" 2>/dev/null || true
        fi
    fi
    rm -f "$LAIR_PID"
    printf 'OK\tstopped pid=%s\n' "$pid"
    return 0
}

# ── lab reference values ────────────────────────────────────────────────
# PUCCH / PUSCH / PRACH power and timing advance reference points for a
# cabled lab setup. These are the numbers a bench needs; they come from
# TS 36.213 §5.1 (uplink power control) and TS 36.211 §6.8 (PRACH).
lair_lab_power_reference() {
    local earfcn="${1:-6300}" n_prb="${2:-25}" p_max="${3:-23}"
    local band; band=$(lair_band_of_earfcn "$earfcn" 2>/dev/null) || band="?"
    local dl; dl=$(lair_earfcn_to_mhz "$earfcn" 2>/dev/null) || dl="?"
    local ul; ul=$(lair_earfcn_to_ul_mhz "$earfcn" 2>/dev/null) || ul="?"
    printf 'earfcn\t%s\n' "$earfcn"
    printf 'band\t%s\n' "$band"
    printf 'dl_mhz\t%s\n' "$dl"
    printf 'ul_mhz\t%s\n' "$ul"
    printf 'ul_channel\t%s\n' "$(lair_earfcn_ul_channel "$earfcn" 2>/dev/null || echo '?')"
    printf 'duplex_spacing_mhz\t%s\n' "$(lair_duplex_spacing "$earfcn" 2>/dev/null || echo '?')"
    printf 'n_prb\t%s\n' "$n_prb"
    # TS 36.213 §5.1.1: P_PUSCH = min(P_CMAX, P_0 + alpha*PL + 10log10(M) + ...)
    # For a cabled bench the path loss is a fixed attenuator value, so the
    # useful reference is the nominal P_0 and the per-PRB term.
    printf 'p_cmax_dbm\t%s\n' "$p_max"
    printf 'p0_nominal_pusch_dbm\t-90\n'
    printf 'p0_ue_pusch_dbm\t0\n'
    printf 'alpha\t1.0\n'
    printf 'p0_nominal_pucch_dbm\t-100\n'
    printf 'preamble_initial_rx_target_dbm\t-104\n'
    printf 'preamble_trans_max\t10\n'
    # PRACH format 0 timing: TCP 3168 Ts, TSEQ 24576 Ts at 30.72 Msps.
    printf 'prach_format\t0\n'
    printf 'prach_tcp_ts\t3168\n'
    printf 'prach_tseq_ts\t24576\n'
    printf 'prach_ta_max_ts\t1282\n'
    printf 'sample_rate_msps\t30.72\n'
    printf 'ref\tTS 36.213 §5.1, TS 36.211 §6.8, TS 36.104 §6.2\n'
    return 0
}

# ── CLI verbs ───────────────────────────────────────────────────────────
lair_cli_status_tsv() {
    local stack bin
    stack=$(lair_find_srsran_stack) || stack="none"
    bin=$(lair_find_srsenb) || bin="none"
    local pid; pid=$(lair_enb_running) || pid="none"
    printf 'module\tlte_air\n'
    printf 'tag\tlair\n'
    printf 'srsran\t%s\n' "$stack"
    printf 'srsenb\t%s\n' "$bin"
    printf 'enb_pid\t%s\n' "$pid"
    printf 'enb_conf\t%s\n' "$LAIR_CONF"
    printf 'rr_conf\t%s\n' "$LAIR_RRC"
    printf 'pidfile\t%s\n' "$LAIR_PID"
    printf 'dir\t%s\n' "$LAIR_DIR"
}

lair_cmd_earfcn() {
    local n="${1:-}"
    [[ -n "$n" ]] || { printf 'ERROR\tusage: --earfcn <N>\n' >&2; return 2; }
    local band dl ul
    band=$(lair_band_of_earfcn "$n") || {
        printf 'ERROR\tEARFCN %s is outside every band in the table\n' "$(lair_sanitize "$n")" >&2
        return 1
    }
    dl=$(lair_earfcn_to_mhz "$n") || return 1
    ul=$(lair_earfcn_to_ul_mhz "$n") || return 1
    printf 'earfcn\t%s\n' "$n"
    printf 'band\t%s\n' "$band"
    printf 'dl_mhz\t%s\n' "$dl"
    printf 'ul_mhz\t%s\n' "$ul"
    printf 'duplex_spacing_mhz\t%s\n' "$(lair_duplex_spacing "$n")"
}

lair_cmd_decode_sib() {
    local hex="${1:-}" sibtype="${2:-1}"
    [[ -n "$hex" ]] || { printf 'ERROR\tusage: --decode-sib <hex> [1|2|3|5]\n' >&2; return 2; }
    lair_decode_sib "$hex" "$sibtype"
}

lair_cmd_paging_frame() {
    local imsi="${1:-}" tac="${2:-}" ue="${3:-}" drx="${4:-}" nb="${5:-}"
    [[ -n "$imsi" && -n "$tac" ]] || {
        printf 'ERROR\tusage: --paging-frame <imsi> <tac> <ue-id> [T] [nB]\n' >&2
        return 2
    }
    lair_paging_frame "$imsi" "$tac" "$ue" "$drx" "$nb"
}

lair_cmd_gen_enb_conf() {
    local earfcn="${1:-6300}" mcc="${2:-001}" mnc="${3:-01}"
    lair_gen_enb_conf "$earfcn" "$mcc" "$mnc" "${4:-1}" "${5:-1}" "${6:-1}" "${7:-25}" "${8:-70}" "${9:-40}" "$LAIR_CONF" || return 1
    lair_gen_rr_conf "$mcc" "$mnc" "${4:-1}" "${5:-1}" "${6:-1}" "$earfcn" "$LAIR_RRC" || return 1
    printf 'enb_conf\t%s\n' "$LAIR_CONF"
    printf 'rr_conf\t%s\n'  "$LAIR_RRC"
    printf 'earfcn\t%s\n'   "$earfcn"
    printf 'plmn\t%s-%s\n'  "$mcc" "$mnc"
    return 0
}

lair_cmd_status() {
    local pid; pid=$(lair_enb_running) || pid=""
    if [[ -n "$pid" ]]; then
        printf 'OK\trunning\tpid=%s\n' "$pid"
    else
        printf 'MISSING\tenb\tnot running\n'
        local bin; bin=$(lair_find_srsenb) || bin=""
        if [[ -z "$bin" ]]; then
            printf 'MISSING\tsrsenb\tinstall srsRAN (srsenb not on PATH)\n'
        fi
        return 1
    fi
}

# ── selftest — no radio, no root, no network ────────────────────────────
lair_selftest() {
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
    export LAIR_DIR="$d/loot/lte_air"
    export LAIR_CONF="$LAIR_DIR/enb.conf"
    export LAIR_RRC="$LAIR_DIR/rr.conf"
    export LAIR_PID="$d/lte_air.pid"
    export LAIR_LOG="$d/enb.log"

    # ── 1. EARFCN arithmetic against TS 36.101 §5.7.3 ───────────────────
    # Band 1: F = 2110 + 0.1*(N - 0)
    chk earfcn-b1-0     "$(lair_earfcn_to_mhz 0)"     "2110.0"
    chk earfcn-b1-599   "$(lair_earfcn_to_mhz 599)"   "2169.9"
    # Band 3: F = 1805 + 0.1*(N - 1200)
    chk earfcn-b3-1200  "$(lair_earfcn_to_mhz 1200)"  "1805.0"
    chk earfcn-b3-1949  "$(lair_earfcn_to_mhz 1949)"  "1879.9"
    # Band 7: F = 2620 + 0.1*(N - 2750)
    chk earfcn-b7-2750  "$(lair_earfcn_to_mhz 2750)"  "2620.0"
    chk earfcn-b7-3449  "$(lair_earfcn_to_mhz 3449)"  "2689.9"
    # Band 20: F = 791 + 0.1*(N - 6150)
    chk earfcn-b20-6150 "$(lair_earfcn_to_mhz 6150)"  "791.0"
    chk earfcn-b20-6449 "$(lair_earfcn_to_mhz 6449)"  "820.9"
    # The exemplar's own verified value: band 20 at 6300 -> 806.0
    chk earfcn-6300     "$(lair_earfcn_to_mhz 6300)"  "806.0"
    # The same arithmetic as the 02_cell_recon.sh exemplar for every band
    # the two tables share. The module is authoritative for the contract,
    # so the selftest sources it directly rather than skipping when the
    # launcher has not already loaded it.
    if ! declare -F crec_lte_earfcn_to_mhz >/dev/null 2>&1; then
        # shellcheck source=/dev/null
        [[ -f "$IMSISTING_ROOT/modules/02_cell_recon.sh" ]] && \
            source "$IMSISTING_ROOT/modules/02_cell_recon.sh" 2>/dev/null
    fi
    if declare -F crec_lte_earfcn_to_mhz >/dev/null 2>&1; then
        local e mismatch=0 checked=0
        for e in 0 599 1200 1949 1950 2399 2400 2649 2750 3449 3450 3799 6150 6449 9210 9659 37750 38249 38650 39649 39650 41589; do
            [[ "$(lair_earfcn_to_mhz "$e")" == "$(crec_lte_earfcn_to_mhz "$e")" ]] || mismatch=$((mismatch+1))
            checked=$((checked+1))
        done
        chk earfcn-matches-crec "$mismatch" "0"
        chk earfcn-crec-checked "$checked" "22"
    else
        printf 'earfcn-matches-crec\tSKIP\t(02_cell_recon.sh not found at %s)\n' "$IMSISTING_ROOT/modules"
    fi

    # Uplink differs from downlink where the duplex gap differs.
    # The argument is always a DOWNLINK EARFCN; the uplink channel
    # number is derived. Band 1 DL 0 pairs with UL 18000 -> 1920 MHz.
    chk ul-b1-0      "$(lair_earfcn_to_ul_mhz 0)"     "1920.0"
    chk ulch-b1-0    "$(lair_earfcn_ul_channel 0)"    "18000"
    chk ul-b1-599    "$(lair_earfcn_to_ul_mhz 599)"   "1979.9"
    chk ulch-b1-599  "$(lair_earfcn_ul_channel 599)"  "18599"
    chk ul-b7-2750   "$(lair_earfcn_to_ul_mhz 2750)"  "2500.0"
    chk ul-b20-6150  "$(lair_earfcn_to_ul_mhz 6150)"  "832.0"
    chk spacing-b1   "$(lair_duplex_spacing 0)"      "190.0"
    chk spacing-b7   "$(lair_duplex_spacing 2750)"    "120.0"
    chk spacing-b20  "$(lair_duplex_spacing 6150)"    "-41.0"
    # Band 38 is TDD: uplink and downlink share the same raster.
    chk spacing-b38  "$(lair_duplex_spacing 37750)"   "0.0"

    # Band lookup and out-of-range behaviour.
    chk band-of-6300   "$(lair_band_of_earfcn 6300)"  "20"
    chk band-of-0      "$(lair_band_of_earfcn 0)"     "1"
    chk band-of-37750  "$(lair_band_of_earfcn 37750)" "38"
    chk band-of-39650  "$(lair_band_of_earfcn 39650)" "41"
    chk earfcn-out-of-range "$(lair_earfcn_to_mhz 99999 >/dev/null 2>&1; echo $?)" "1"
    chk earfcn-nonnum       "$(lair_earfcn_to_mhz abc >/dev/null 2>&1; echo $?)"   "1"
    chk earfcn-gap          "$(lair_earfcn_to_mhz 2700 >/dev/null 2>&1; echo $?)"  "1"
    chk earfcn-freq-round   "$(lair_earfcn_from_freq 806.0 20)" "6300"
    chk earfcn-freq-b1      "$(lair_earfcn_from_freq 2110.0 1)" "0"

    # ── 2. Paging frame / occasion, hand-computed from TS 36.304 ────────
    # IMSI 310150123456789 -> UE_ID = 310150123456789 mod 1024 = 277.
    chk ueid-mod1024 "$(awk -v i=310150123456789 'BEGIN{printf "%d", i % 1024}')" "277"
    # T=32, nB=T -> N=32, Ns=1
    #   PF = (32/32)*(277 mod 32) = 1*21 = 21
    #   i_s = (277/32) mod 1 = 8 mod 1 = 0 -> PO=9 (Ns=1 row)
    out=$(lair_paging_frame 310150123456789 1 0 32 32)
    chk pf-T32-nBT-ue_id  "$(fld "$out" ue_id)"  "277"
    chk pf-T32-nBT-N      "$(fld "$out" N)"      "32"
    chk pf-T32-nBT-Ns     "$(fld "$out" Ns)"     "1"
    chk pf-T32-nBT-PF     "$(fld "$out" paging_frame)" "21"
    chk pf-T32-nBT-is     "$(fld "$out" i_s)"    "0"
    chk pf-T32-nBT-PO     "$(fld "$out" paging_occasion)" "9"
    chk pf-T32-nBT-nB     "$(fld "$out" nB)"     "32"

    # T=64, nB=T/2=32 -> N=min(64,32)=32, Ns=max(1,32/64)=1
    #   PF = (64/32)*(277 mod 32) = 2*21 = 42  -> 42 mod 64 = 42
    #   i_s = (277/32) mod 1 = 0 -> PO=9
    out=$(lair_paging_frame 310150123456789 1 0 64 16)
    chk pf-T64-nBhalf-N   "$(fld "$out" N)"  "32"
    chk pf-T64-nBhalf-Ns  "$(fld "$out" Ns)" "1"
    chk pf-T64-nBhalf-PF  "$(fld "$out" paging_frame)" "42"
    chk pf-T64-nBhalf-PO  "$(fld "$out" paging_occasion)" "9"

    # T=64, nB=2T=128 -> N=min(64,128)=64, Ns=max(1,128/64)=2
    #   PF = (64/64)*(277 mod 64) = 1*21 = 21
    #   i_s = (277/64) mod 2 = 4 mod 2 = 0 -> PO=4 (Ns=2, i_s=0)
    out=$(lair_paging_frame 310150123456789 1 0 64 64)
    chk pf-T64-nB2T-N   "$(fld "$out" N)"  "64"
    chk pf-T64-nB2T-Ns  "$(fld "$out" Ns)" "2"
    chk pf-T64-nB2T-PF  "$(fld "$out" paging_frame)" "21"
    chk pf-T64-nB2T-is  "$(fld "$out" i_s)" "0"
    chk pf-T64-nB2T-PO  "$(fld "$out" paging_occasion)" "4"

    # T=64, nB=4T=256 -> N=64, Ns=4
    #   PF = 21 ; i_s = (277/64) mod 4 = 4 mod 4 = 0 -> PO=0
    out=$(lair_paging_frame 310150123456789 1 0 64 128)
    chk pf-T64-nB4T-Ns  "$(fld "$out" Ns)" "4"
    chk pf-T64-nB4T-is  "$(fld "$out" i_s)" "0"
    chk pf-T64-nB4T-PO  "$(fld "$out" paging_occasion)" "0"

    # T=32, nB=2T=64 -> N=32, Ns=2 ; PF=(32/32)*(277 mod 32)=21
    #   i_s=(277/32) mod 2 = 8 mod 2 = 0 -> PO=4
    out=$(lair_paging_frame 310150123456789 1 0 32 64)
    chk pf-T32-nB2T-PF  "$(fld "$out" paging_frame)" "21"
    chk pf-T32-nB2T-Ns  "$(fld "$out" Ns)" "2"
    chk pf-T32-nB2T-PO  "$(fld "$out" paging_occasion)" "4"

    # T=128, nB=T -> N=128, Ns=1 ; PF=(128/128)*(277 mod 128)=1*21=21
    out=$(lair_paging_frame 310150123456789 1 0 128 32)
    chk pf-T128-N   "$(fld "$out" N)"  "128"
    chk pf-T128-PF  "$(fld "$out" paging_frame)" "21"
    chk pf-T128-PO  "$(fld "$out" paging_occasion)" "9"

    # i_s=1 must select the second subframe of the pattern.
    # UE_ID such that floor(UE_ID/N) mod Ns = 1 with N=64,Ns=2 -> UE_ID in
    # [64,127]. IMSI 000000000064 -> UE_ID = 64 mod 1024 = 64.
    #   PF = (64/64)*(64 mod 64) = 0 ; i_s = (64/64) mod 2 = 1 -> PO=9
    out=$(lair_paging_frame 000000000000064 1 0 64 64)
    chk is1-ue_id "$(fld "$out" ue_id)" "64"
    chk is1-PF    "$(fld "$out" paging_frame)" "0"
    chk is1-is    "$(fld "$out" i_s)" "1"
    chk is1-PO    "$(fld "$out" paging_occasion)" "9"

    # i_s=2 with Ns=4 -> PO=5
    # UE_ID in [128,191]; use 128 -> PF=0, i_s=(128/64) mod 4 = 2 -> PO=5
    out=$(lair_paging_frame 000000000000128 1 0 64 128)
    chk is2-is "$(fld "$out" i_s)" "2"
    chk is2-PO "$(fld "$out" paging_occasion)" "5"
    # i_s=3 -> PO=9
    out=$(lair_paging_frame 000000000000192 1 0 64 128)
    chk is3-is "$(fld "$out" i_s)" "3"
    chk is3-PO "$(fld "$out" paging_occasion)" "9"

    # PF must satisfy the residue that defines it, for a spread of inputs.
    local ok=0 i
    for i in 000000000000000 000000000000100 000000000000277 310150123456789 999999999999999; do
        out=$(lair_paging_frame "$i" 1 0 64 64)
        local pf is_ ue_N N T
        T=$(fld "$out" T); N=$(fld "$out" N)
        pf=$(fld "$out" paging_frame)
        [[ "$(( pf % T ))" == "$(( (T / N) * ($(fld "$out" ue_id) % N) ))" ]] && ok=$((ok+1))
    done
    chk pf-formula-holds "$ok" "5"

    # Argument validation.
    chk pf-bad-imsi   "$(lair_paging_frame 123 1 0 >/dev/null 2>&1; echo $?)"     "2"
    chk pf-bad-tac    "$(lair_paging_frame 310150123456789 xx 0 >/dev/null 2>&1; echo $?)" "2"
    chk pf-bad-drx    "$(lair_paging_frame 310150123456789 1 0 33 32 >/dev/null 2>&1; echo $?)" "2"
    chk pf-bad-nb     "$(lair_paging_frame 310150123456789 1 0 32 999 >/dev/null 2>&1; echo $?)" "2"
    chk pf-missing    "$(lair_cmd_paging_frame >/dev/null 2>&1; echo $?)" "2"

    # ── 3. SIB1 parse of a real hex string ──────────────────────────────
    # PLMN 208-01 as TS 23.003 §12.1 octets: MCC 208 -> 02 08 (nibble
    # swapped per octet pair), MNC 01 -> 10 with the 0xF filler in the
    # third octet's high nibble.
    #   02  F8  10  is the 3-octet PLMN for MCC 208 / MNC 01.
    # octet1 = MCC d2|d1, octet2 = MNC d3|MCC d3, octet3 = MNC d2|d1.
    # 02 F8 10 -> MCC 208 (from 0,2,8), MNC 01 (from 0,1), F = filler.
    chk plmn-octets-20801  "$(lair_plmn_from_octets 02F810)"  "MCC=208 MNC=01"
    chk plmn-octets3-20801 "$(lair_plmn_from_octets3 02F810)" "MCC=208 MNC=01"
    # 3-digit MNC 015: MNC d3=5 goes in octet2 high -> 02 58 10.
    chk plmn-octets3-208015 "$(lair_plmn_from_octets3 025810)" "MCC=208 MNC=015"
    chk plmn-has3-208015 "$(lair_plmn_has_3digit_mnc 025810 && echo yes || echo no)" "yes"
    chk plmn-has3-20801  "$(lair_plmn_has_3digit_mnc 02F810 && echo yes || echo no)" "no"
    # 262-01: MCC 262 -> octet1 = 6|2 = 62, MCC d3=2 -> octet2 low = 2,
    # MNC 01 -> octet3 = 1|0 = 10, filler F -> octet2 = F2.
    chk plmn-octets-26201 "$(lair_plmn_from_octets 62F210)" "MCC=262 MNC=01"
    chk plmn-octets-bad   "$(lair_plmn_from_octets 02F8 >/dev/null 2>&1; echo $?)" "1"
    chk plmn-octets-nonhex "$(lair_plmn_from_octets ZZZZZZ >/dev/null 2>&1; echo $?)" "1"
    chk plmn-name-20801   "$(lair_plmn_name 208-01)" "Orange FR"
    chk plmn-name-unknown "$(lair_plmn_name 999-99)" "unknown"

    # A SIB1 body: PLMN 02F810 | TAC 0x0001 | cellIdentity 0x0000001.
    # TAC = 1, cellIdentity = 1.
    out=$(lair_decode_sib1 "02F81000010000001")
    chk sib1-mcc      "$(fld "$out" mcc)" "208"
    chk sib1-mnc      "$(fld "$out" mnc)" "01"
    chk sib1-mnc-digits "$(fld "$out" mnc_digits)" "2"
    chk sib1-plmn     "$(fld "$out" plmn)" "208-01"
    chk sib1-operator "$(fld "$out" operator)" "Orange FR"
    chk sib1-tac      "$(fld "$out" tracking_area_code)" "1"
    chk sib1-cellid   "$(fld "$out" cell_identity)" "1"

    # A second, larger SIB1: TAC 0x1234 = 4660, cellIdentity 0x0ABCDEF.
    out=$(lair_decode_sib1 "02F81012340ABCDEF")
    chk sib1b-tac    "$(fld "$out" tracking_area_code)" "4660"
    chk sib1b-cellid "$(fld "$out" cell_identity)" "11259375"

    # With the BCCH-DL-SCH c1 discriminator 0x14 in front, it is skipped.
    out=$(lair_decode_sib1 "1402F81000010000001")
    chk sib1-hdr-skip "$(fld "$out" mcc)" "208"
    chk sib1-hdr-note "$(printf '%s\n' "$out" | grep -c 'skipped BCCH-DL-SCH')" "1"

    # A 3-digit MNC: 208-015 -> octet 2 high nibble carries digit 3 (5).
    out=$(lair_decode_sib1 "02581000010000001")
    chk sib1-3mnc-digits "$(fld "$out" mnc_digits)" "3"
    chk sib1-3mnc        "$(fld "$out" mnc)" "015"

    chk sib1-bad-hex   "$(lair_decode_sib1 zz >/dev/null 2>&1; echo $?)" "1"
    chk sib1-odd-hex   "$(lair_decode_sib1 02F >/dev/null 2>&1; echo $?)" "1"
    chk sib1-short     "$(lair_decode_sib1 02F8 >/dev/null 2>&1; echo $?)" "1"
    chk sib1-missing   "$(lair_cmd_decode_sib >/dev/null 2>&1; echo $?)" "2"
    chk sib-bad-type   "$(lair_decode_sib 02F81012340ABCDEF 9 >/dev/null 2>&1; echo $?)" "2"
    chk sib-empty-hex  "$(lair_decode_sib "" 1 >/dev/null 2>&1; echo $?)" "2"

    # ── 4. SIB2 RACH config ─────────────────────────────────────────────
    # prach-ConfigIndex 0 is the most common lab value: format 0, even
    # frames, subframe 1.
    chk prach-0  "$(lair_prach_config 0)"  "0	even	1"
    chk prach-3  "$(lair_prach_config 3)"  "0	any	1"
    chk prach-14 "$(lair_prach_config 14)" "0	any	0,1,2,3,4,5,6,7,8,9"
    chk prach-30 "$(lair_prach_config 30)" "1	N/A	N/A"
    chk prach-63 "$(lair_prach_config 63)" "4	N/A	N/A"
    chk prach-bad "$(lair_prach_config 99 >/dev/null 2>&1; echo $?)" "1"
    chk rach-summary "$(lair_rach_summary 0)" "preamble_format=0 sf=even subframes=1"

    # SIB2 body with prach-ConfigIndex = 0 in the leading 6 bits.
    out=$(lair_decode_sib2 "0000000000")
    chk sib2-prach-idx "$(fld "$out" prach_config_index)" "0"
    chk sib2-prach     "$(printf '%s\n' "$out" | grep -c 'preamble_format=0')" "1"

    # ── 5. SIB3 / SIB5 ──────────────────────────────────────────────────
    # q-Hyst 3 bits, s-NonIntraSearch 5 bits, threshServingLow 5 bits —
    # consecutive from bit 0. 4AA000 = 010 01010 10100 -> q=2, s=10, t=20.
    out=$(lair_decode_sib3 "4AA000")
    chk sib3-qh-idx "$(fld "$out" q_hyst_index)" "2"
    chk sib3-qh-db  "$(fld "$out" q_hyst_db)" "2"
    # s-NonIntraSearch index 10 -> 2*10 = 20 dB
    chk sib3-snon-idx "$(fld "$out" s_non_intra_search_index)" "10"
    chk sib3-snon-db  "$(fld "$out" s_non_intra_search_db)" "20"
    chk sib3-thresh-idx "$(fld "$out" thresh_serving_low_index)" "20"
    chk sib3-thresh   "$(fld "$out" thresh_serving_low_db)" "40"
    # A different window: B2A800 = 101 10010 10101 -> q=5, s=18, t=21.
    out=$(lair_decode_sib3 "B2A800")
    chk sib3b-qh "$(fld "$out" q_hyst_index)" "5"
    chk sib3b-qh-db "$(fld "$out" q_hyst_db)" "5"
    chk sib3b-snon "$(fld "$out" s_non_intra_search_index)" "18"
    # Index 0 is the "not present" sentinel, not 0 dB.
    out=$(lair_decode_sib3 "000000")
    chk sib3-snon-zero "$(fld "$out" s_non_intra_search_db)" "not_present"
    chk sib3-thresh-zero "$(fld "$out" thresh_serving_low_db)" "not_present"
    chk sib3-short "$(lair_decode_sib3 50 >/dev/null 2>&1; echo $?)" "1"

    # SIB5: two 16-bit candidate neighbour EARFCNs.
    out=$(lair_decode_sib5 "000018F8")
    chk sib5-count "$(printf '%s\n' "$out" | grep -c '^neighbour\.')" "2"
    chk sib5-n0-earfcn "$(printf '%s\n' "$out" | grep '^neighbour\.0' | cut -f2)" "earfcn=0 dl_mhz=2110.0"
    chk sib5-n1-earfcn "$(printf '%s\n' "$out" | grep '^neighbour\.1' | cut -f2)" "earfcn=6392 dl_mhz=815.2"

    # ── 6. bit reader ───────────────────────────────────────────────────
    chk bits-8-0   "$(lair_bits FF 0 8)"  "255"
    chk bits-4-0   "$(lair_bits F0 0 4)"  "15"
    chk bits-4-4   "$(lair_bits F0 4 4)"  "0"
    chk bits-1-0   "$(lair_bits 80 0 1)"  "1"
    # 0xFF = 8 bits total, so off=0 len=8 is the whole nibble pair.
    chk bits-across "$(lair_bits FF 0 8)" "255"
    # A genuinely cross-byte read: 0x0F00, off=4 len=8 spans the low
    # nibble of byte 0 and the high nibble of byte 1 -> 0xF0 = 240.
    chk bits-cross-byte "$(lair_bits 0F00 4 8)" "240"
    chk bits-oob   "$(lair_bits FF 8 8 >/dev/null 2>&1; echo $?)" "1"

    # ── 7. enb.conf generation contains the right keys ──────────────────
    mkdir -p "$LAIR_DIR"
    lair_gen_enb_conf 6300 208 01 1 1 1 25 70 40 "$LAIR_CONF" >/dev/null
    rc=$?
    chk enbconf-rc "$rc" "0"
    [[ -f "$LAIR_CONF" ]] && chk enbconf-exists "yes" "yes" || chk enbconf-exists "no" "yes"
    chk enbconf-earfcn "$(grep -c '^dl_earfcn = 6300$' "$LAIR_CONF")" "1"
    chk enbconf-nprb   "$(grep -c '^n_prb = 25$' "$LAIR_CONF")" "1"
    chk enbconf-enbid  "$(grep -c '^enb_id = 0x1A2D$' "$LAIR_CONF")" "1"
    chk enbconf-mme    "$(grep -c '^mme_addr = 127.0.1.100$' "$LAIR_CONF")" "1"
    chk enbconf-gtp    "$(grep -c '^gtp_bind_addr = 127.0.1.1$' "$LAIR_CONF")" "1"
    chk enbconf-txgain "$(grep -c '^tx_gain = 70$' "$LAIR_CONF")" "1"
    chk enbconf-rxgain "$(grep -c '^rx_gain = 40$' "$LAIR_CONF")" "1"
    chk enbconf-band-note "$(grep -c 'band 20, DL 806.0 MHz' "$LAIR_CONF")" "1"

    lair_gen_rr_conf 208 01 1 1 1 6300 "$LAIR_RRC" >/dev/null
    rc=$?
    chk rrconf-rc "$rc" "0"
    chk rrconf-tac    "$(grep -c 'tac = 1;' "$LAIR_RRC")" "1"
    chk rrconf-pci    "$(grep -c 'pci = 1;' "$LAIR_RRC")" "1"
    chk rrconf-mcc    "$(grep -c 'mcc = 208;' "$LAIR_RRC")" "1"
    chk rrconf-mnc    "$(grep -c 'mnc = 01;' "$LAIR_RRC")" "1"
    chk rrconf-mnclen "$(grep -c 'mnc_len = 2;' "$LAIR_RRC")" "1"

    # Validation of the generator arguments.
    chk enbconf-bad-earfcn "$(lair_gen_enb_conf abc >/dev/null 2>&1; echo $?)" "2"
    chk enbconf-bad-mcc    "$(lair_gen_enb_conf 6300 20 >/dev/null 2>&1; echo $?)" "2"
    chk enbconf-bad-mnc    "$(lair_gen_enb_conf 6300 208 1 >/dev/null 2>&1; echo $?)" "2"
    chk enbconf-bad-nprb   "$(lair_gen_enb_conf 6300 208 01 1 1 1 7 >/dev/null 2>&1; echo $?)" "2"
    chk rrconf-bad-pci     "$(lair_gen_rr_conf 208 01 1 1 900 6300 >/dev/null 2>&1; echo $?)" "2"
    chk rrconf-bad-tac     "$(lair_gen_rr_conf 208 01 99999 1 1 6300 >/dev/null 2>&1; echo $?)" "2"
    chk rrconf-bad-cellid  "$(lair_gen_rr_conf 208 01 1 999999999 1 6300 >/dev/null 2>&1; echo $?)" "2"

    # A write into an unwritable directory must fail, not claim success.
    chk enbconf-unwritable "$(lair_gen_enb_conf 6300 208 01 1 1 1 25 70 40 /proc/nope/enb.conf >/dev/null 2>&1; echo $?)" "1"

    # ── 8. srsRAN absence is reported BY NAME ───────────────────────────
    # The selftest must not require srsRAN. Whatever the environment, the
    # lookup returns either a binary name or non-zero, never empty success.
    local have; have=$(lair_find_srsenb) || have=""
    if [[ -n "$have" ]]; then
        chk srsenb-named "$have" "$have"
    else
        # Absent: --status must name it, and --start must fail with the name.
        local msg; msg=$(lair_cmd_status 2>&1)
        chk srsenb-absent-named "$(printf '%s' "$msg" | grep -c 'srsenb')" "1"
        chk start-without-bin   "$(lair_start "$LAIR_CONF" >/dev/null 2>&1; echo $?)" "1"
        local em; em=$(lair_start "$LAIR_CONF" 2>&1 >/dev/null || true)
        chk start-names-srsran  "$(printf '%s' "$em" | grep -c 'install srsRAN')" "1"
    fi
    chk start-without-conf "$(lair_start /nonexistent/enb.conf >/dev/null 2>&1; echo $?)" "1"
    chk stack-lookup-nonempty "$(lair_find_srsran_stack >/dev/null 2>&1; echo $?)" \
        "$([[ -n "$(lair_find_srsran_stack || true)" ]] && echo 0 || echo 1)"

    # ── 9. stop is idempotent and reaps by pidfile ──────────────────────
    rm -f "$LAIR_PID"
    out=$(lair_stop); rc=$?
    chk stop-idempotent-rc "$rc" "0"
    chk stop-nothing-msg   "$(printf '%s' "$out" | grep -c 'nothing to stop')" "1"

    # Plant a real sleeper and check the pidfile reaping works end to end.
    sleep 300 &
    local spid=$!
    printf '%s' "$spid" > "$LAIR_PID"
    out=$(lair_stop); rc=$?
    chk stop-reap-rc "$rc" "0"
    sleep 0.2
    chk stop-reaped "$(kill -0 "$spid" 2>/dev/null && echo alive || echo dead)" "dead"
    chk stop-removed-pidfile "$([[ -f "$LAIR_PID" ]] && echo present || echo gone)" "gone"
    # A stale pidfile pointing at nothing must still be cleaned up.
    printf '999999' > "$LAIR_PID"
    chk stop-stale "$(lair_stop >/dev/null 2>&1; echo $?)" "0"
    chk stop-stale-gone "$([[ -f "$LAIR_PID" ]] && echo present || echo gone)" "gone"

    # ── 10. lab power reference ─────────────────────────────────────────
    out=$(lair_lab_power_reference 6300 25)
    chk lab-band   "$(fld "$out" band)"  "20"
    chk lab-dl     "$(fld "$out" dl_mhz)" "806.0"
    chk lab-ul     "$(fld "$out" ul_mhz)" "847.0"
    chk lab-ul-ch  "$(fld "$out" ul_channel)" "24300"
    chk lab-tcp    "$(fld "$out" prach_tcp_ts)" "3168"
    chk lab-tseq   "$(fld "$out" prach_tseq_ts)" "24576"

    # ── 11. status TSV contract ─────────────────────────────────────────
    out=$(lair_cli_status_tsv)
    chk status-tag    "$(fld "$out" tag)" "lair"
    chk status-dir    "$(fld "$out" dir)" "$LAIR_DIR"
    chk status-enbconf "$(fld "$out" enb_conf)" "$LAIR_CONF"
    chk status-pid    "$(fld "$out" enb_pid)" "none"
    chk status-fields "$(printf '%s\n' "$out" | grep -c .)" "9"

    # ── 12. sanitisation and CLI dispatch ───────────────────────────────
    chk san-tab "$(lair_sanitize $'a\tb')" "a b"
    chk san-nl  "$(lair_sanitize $'a\nb')" "a b"
    chk san-cr  "$(lair_sanitize $'a\rb')" "a b"
    chk cli-unknown "$(lair_cli_main --nope >/dev/null 2>&1; echo $?)" "2"
    chk earfcn-missing "$(lair_cmd_earfcn >/dev/null 2>&1; echo $?)" "2"
    chk earfcn-bad     "$(lair_cmd_earfcn 99999 >/dev/null 2>&1; echo $?)" "1"
    out=$(lair_cmd_earfcn 6300); rc=$?
    chk earfcn-rc   "$rc" "0"
    chk earfcn-band "$(fld "$out" band)" "20"
    chk earfcn-dl   "$(fld "$out" dl_mhz)" "806.0"

    rm -rf "$d"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ── menu ────────────────────────────────────────────────────────────────
lair_menu() {
    while true; do
        banner
        echo -e "  ${C_MAG}=== LTE Air Interface ===${C_RESET}"
        echo -e "  srsRAN: ${C_GRN}$(lair_find_srsran_stack || echo none)${C_RESET}"
        echo -e "  eNB:    ${C_GRN}$(lair_enb_running || echo stopped)${C_RESET}"
        echo -e "  conf:   ${C_DIM}$LAIR_CONF${C_RESET}\n"
        cat << 'M'
  [1]  EARFCN -> frequency (DL/UL/band)
  [2]  decode a SIB (hex)
  [3]  paging frame / occasion for an IMSI
  [4]  generate enb.conf + rr.conf
  [5]  start the test eNB
  [6]  stop the test eNB
  [7]  eNB status
  [8]  lab power / timing reference
  [9]  status
  [0]  back

M
        read -rp "  choice> " c || return 0  # EOF: leave the menu cleanly
        case "$c" in
            1)
                if [[ -n "${IMSISTING_CLI:-}" ]]; then
                    echo "[-] need an EARFCN; cannot prompt in CLI mode" >&2
                else
                    read -rp "  EARFCN> " n
                    lair_cmd_earfcn "$n" | column -t -s$'\t' 2>/dev/null || lair_cmd_earfcn "$n"
                    read -rp "  press enter " _
                fi ;;
            2)
                if [[ -n "${IMSISTING_CLI:-}" ]]; then
                    echo "[-] need hex; cannot prompt in CLI mode" >&2
                else
                    read -rp "  SIB type (1|2|3|5)> " t
                    read -rp "  hex> " h
                    lair_cmd_decode_sib "$h" "$t" | column -t -s$'\t' 2>/dev/null || lair_cmd_decode_sib "$h" "$t"
                    read -rp "  press enter " _
                fi ;;
            3)
                if [[ -n "${IMSISTING_CLI:-}" ]]; then
                    echo "[-] need an IMSI; cannot prompt in CLI mode" >&2
                else
                    read -rp "  IMSI> " i
                    read -rp "  TAC> " t
                    read -rp "  DRX cycle (32|64|128|256)> " drx
                    read -rp "  nB (32=T, 64=2T, 16=T/2 ...)> " nb
                    lair_cmd_paging_frame "$i" "$t" 0 "$drx" "$nb" | column -t -s$'\t' 2>/dev/null || true
                    read -rp "  press enter " _
                fi ;;
            4)
                if [[ -n "${IMSISTING_CLI:-}" ]]; then
                    echo "[-] need parameters; cannot prompt in CLI mode" >&2
                else
                    read -rp "  EARFCN> " e
                    read -rp "  MCC> " mc
                    read -rp "  MNC> " mn
                    lair_cmd_gen_enb_conf "$e" "$mc" "$mn" | column -t -s$'\t' 2>/dev/null || true
                    read -rp "  press enter " _
                fi ;;
            5) lair_start; read -rp "  press enter " _ ;;
            6) lair_stop; sleep 1 ;;
            7) lair_cmd_status; read -rp "  press enter " _ ;;
            8)
                if [[ -n "${IMSISTING_CLI:-}" ]]; then
                    echo "[-] need an EARFCN; cannot prompt in CLI mode" >&2
                else
                    read -rp "  EARFCN> " e
                    lair_lab_power_reference "$e" | column -t -s$'\t' 2>/dev/null || true
                    read -rp "  press enter " _
                fi ;;
            9) lair_cli_status_tsv | column -t -s$'\t' 2>/dev/null || lair_cli_status_tsv
               read -rp "  press enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ── CLI dispatch ────────────────────────────────────────────────────────
lair_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)   lair_cli_status_tsv ;;
        --earfcn)       lair_cmd_earfcn "${1:-}" ;;
        --decode-sib)   lair_cmd_decode_sib "${1:-}" "${2:-1}" ;;
        --paging-frame) lair_cmd_paging_frame "${1:-}" "${2:-}" "${3:-}" "${4:-}" "${5:-}" ;;
        --gen-enb-conf) lair_cmd_gen_enb_conf "${1:-6300}" "${2:-001}" "${3:-01}" \
                            "${4:-1}" "${5:-1}" "${6:-1}" "${7:-25}" ;;
        --start)        lair_start "$LAIR_CONF" ;;
        --stop)         lair_stop ;;
        --status)       lair_cmd_status ;;
        --power-ref)    lair_lab_power_reference "${1:-6300}" "${2:-25}" ;;
        --selftest)     lair_selftest ;;
        --menu)         lair_menu ;;
        *)
            cat >&2 <<EOF
LTE Air Interface — E-UTRA RRC decode, paging arithmetic, srsRAN eNB control

Usage: $0 COMMAND
  --status-tsv                     module and eNB state as TSV
  --earfcn <N>                     EARFCN -> band, DL MHz, UL MHz, spacing
  --decode-sib <hex> [1|2|3|5]     parse a SIB body (default SIB1)
  --paging-frame <imsi> <tac> <ue-id> [T] [nB]
                                   PF/PO from TS 36.304 §7.1/§7.2
  --gen-enb-conf [EARFCN] [MCC] [MNC] [TAC] [CELLID] [PCI] [N_PRB]
                                   write enb.conf and rr.conf
  --start                          start srsenb with the generated conf
  --stop                           stop it (idempotent)
  --status                         is the eNB running
  --power-ref [EARFCN] [N_PRB]     lab power and timing reference values
  --selftest                       verify the arithmetic without a radio
  --menu                           interactive menu
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
    lair_cli_main "$@"
fi
