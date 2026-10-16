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

# Shared cross-module state — 02_cell_recon.sh and 10_lte_air.sh both read
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

# Duplex mode of a band, from the band's own UL/DL pair in LAIR_BANDS.
#
# This is DERIVED, not a hand-kept list: a band is TDD exactly when its UL
# and DL share a frequency origin and offset, which is what the table shows
# for bands 38/40/41/42/43 and for no FDD band. Deriving it means a band
# added to LAIR_BANDS later is classified automatically instead of silently
# defaulting to FDD — which is the bug that made --gen-enb-conf emit tm=1
# for the TDD bands this module already advertises.
lair_band_duplex() {
    local band="$1" line
    [[ -n "$band" && "$band" != "?" ]] || { echo unknown; return 1; }
    line=$(lair_band_row "$band") || { echo unknown; return 1; }
    # shellcheck disable=SC2086
    set -- $line
    if [[ "$2" == "$4" && "$3" == "$5" ]]; then
        echo tdd
    else
        echo fdd
    fi
    return 0
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

    # SIB1 is read by the real TS 36.331 unaligned-PER codec in
    # tools/lte_asn1.py. The previous parser here treated a SIB1 as a
    # byte-aligned "17-nibble body" (PLMN 3 octets | TAC 2 octets |
    # cellIdentity 7 nibbles). That layout does not exist in the
    # specification: SIB1 begins with presence bits and a PLMN list count,
    # so nothing in it is octet aligned and the old parser reported
    # plausible cell identities decoded from the wrong bit offsets. It has
    # been removed rather than kept beside the correct one.
    local tool="$IMSISTING_ROOT/tools/lte_asn1.py"
    [[ -r "$tool" ]] || {
        printf 'ERROR\tmissing %s\n' "$tool" >&2
        printf 'WHY\tthe SIB1 decoder is a real ASN.1 PER codec and lives in tools/\n' >&2
        return 1
    }

    local out rc
    out=$(python3 "$tool" decode "$hex" 2>&1); rc=$?
    if (( rc != 0 )); then
        printf '%s\n' "$out" | sed 's/^/ERROR\t/'
        printf 'NOTDECODED\tthe input is not a SIB1; no cell fields were reported\n' >&2
        return 1
    fi

    local mcc mnc
    mcc=$(printf '%s\n' "$out" | awk -F'\t' '$1=="mcc"{print $2}')
    mnc=$(printf '%s\n' "$out" | awk -F'\t' '$1=="mnc"{print $2}')

    printf 'message\tBCCH-DL-SCH-Message\n'
    printf 'sib\tSystemInformationBlockType1\n'
    printf 'layout\tTS 36.331 unaligned PER (tools/lte_asn1.py)\n'
    printf 'mcc\t%s\n' "$mcc"
    printf 'mnc\t%s\n' "$mnc"
    printf 'mnc_digits\t%s\n' "${#mnc}"
    printf 'plmn\t%s-%s\n' "$mcc" "$mnc"
    printf 'operator\t%s\n' "$(lair_plmn_name "${mcc}-${mnc}")"
    local k v
    while IFS=$'\t' read -r k v; do
        case "$k" in
            tac)
                printf 'tracking_area_code\t%d\n' "$(( 16#$v ))" ;;
            cellid)
                printf 'cell_identity_hex\t%s\n' "$v"
                printf 'cell_identity\t%d\n' "$(( 16#$v ))" ;;
            barred)
                printf 'cell_barred\t%s\n' "$v" ;;
            intra_freq_reselection)
                printf 'intra_freq_reselection\t%s\n' "$v" ;;
            q_rx_lev_min)
                printf 'q_rx_lev_min\t%s\n' "$v" ;;
            band)
                printf 'freq_band_indicator\t%s\n' "$v" ;;
            si_window_length)
                printf 'si_window_length\t%s\n' "$v" ;;
            system_info_value_tag)
                printf 'system_info_value_tag\t%s\n' "$v" ;;
            scheduling)
                printf 'scheduling_info\t%s\t%s\n' "$k" "$v" ;;
            bits_consumed)
                printf 'bits\t%s\n' "$v" ;;
            plmn_count)
                printf 'plmn_count\t%s\n' "$v" ;;
        esac
    done <<< "$out"
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

    # SIB2 is read by the real TS 36.331 unaligned-PER codec in
    # tools/lte_asn1.py. What stood here before read a 6-bit "prach-ConfigIndex"
    # from bit 0 of the body and dressed it up as the RACH configuration. Bit 0
    # is the extension bit of the SIB2 SEQUENCE; prach-ConfigIndex is six bits
    # at 46..51, behind a ten-bit rootSequenceIndex and six bits of OPTIONAL
    # bitmap. The number it printed was not any field of the message, and the
    # selftest that checked it only proved the function returned what it had
    # been given. It has been removed rather than kept beside the correct one.
    local tool="$IMSISTING_ROOT/tools/lte_asn1.py"
    [[ -r "$tool" ]] || {
        printf 'ERROR\tmissing %s\n' "$tool" >&2
        printf 'WHY\tthe SIB2 decoder is a real ASN.1 PER codec and lives in tools/\n' >&2
        return 1
    }

    # A bare SIB2 body is 186 bits, or longer when the freqInfo uplink
    # OPTIONALs are present; the whole SystemInformation container puts a
    # 14-bit header in front of that. The true length is not recoverable from
    # the hex, which is zero-padded to a whole octet, so the padded length is
    # passed and the codec decides -- it only reads the input as a container
    # when a 14-bit header still leaves a whole body behind. 186 is the retry
    # for a caller who hands in a body whose octet padding the codec would
    # otherwise have to guess at.
    local pbits=$(( ${#hex} * 4 ))
    local out rc
    out=$(python3 "$tool" sib2-decode "$hex" --bits "$pbits" 2>&1); rc=$?
    if (( rc != 0 )); then
        out=$(python3 "$tool" sib2-decode "$hex" --bits 186 2>&1); rc=$?
    fi
    if (( rc != 0 )); then
        printf '%s\n' "$out" | sed 's/^/ERROR\t/'
        printf 'NOTDECODED\tthe input is not a SIB2 body; no fields were reported\n' >&2
        return 1
    fi

    local k v
    while IFS=$'\t' read -r k v; do
        case "$k" in
            bits_consumed) printf 'bits\t%s\n' "$v" ;;
            *)             printf '%s\t%s\n' "$k" "$v" ;;
        esac
    done <<< "$out"
    printf 'body\t%s\n' "$hex"
    return 0
}

# ── SIB3 decode — TS 36.331 §6.3.1 ──────────────────────────────────────
# SIB3 = intra-frequency reselection. The fields that matter for a survey
# and for a downgrade experiment:
#   q-Hyst                 (3 bits) ENUMERATED dB
#   s-NonIntraSearch       (5 bits) -> dB, 0 means "not present"
#   threshServingLow       (5 bits) -> dB
#   cellReselectionPriority(3 bits) 0..7
lair_decode_sib3() {
    local hex; hex=$(lair_nfc "${1:-}")
    [[ -n "$hex" ]] || { printf 'ERROR\t--decode-sib needs hex\n' >&2; return 2; }
    [[ "$hex" =~ ^[0-9A-F]+$ ]] || { printf 'ERROR\tnot valid hex\n' >&2; return 1; }

    # SIB3 is read by the real TS 36.331 unaligned-PER codec in
    # tools/lte_asn1.py. The previous parser here read q-Hyst from bits 0..2,
    # s-NonIntraSearch from bits 3..7 and threshServingLow from bits 8..12 of
    # an octet-aligned body. None of those offsets exist: the body starts
    # with an extension bit and a presence bit, q-Hyst is four bits at 2..5,
    # and threshServingLow is at 7..11 -- so every value it printed came from
    # the wrong bits. It has been removed rather than kept beside the
    # correct one.
    local tool="$IMSISTING_ROOT/tools/lte_asn1.py"
    [[ -r "$tool" ]] || {
        printf 'ERROR\tmissing %s\n' "$tool" >&2
        printf 'WHY\tthe SIB3 decoder is a real ASN.1 PER codec and lives in tools/\n' >&2
        return 1
    }

    # The body's true bit length is not recoverable from hex -- a 31-bit body
    # pads to 4 octets -- so it is passed explicitly.
    local nbits=31
    local out rc
    out=$(python3 "$tool" sib3-decode "$hex" --bits "$nbits" 2>&1); rc=$?
    if (( rc != 0 )); then
        # A caller may hand in the whole SystemInformation container instead
        # of a bare body; retry once with the container's own length.
        out=$(python3 "$tool" sib3-decode "$hex" --bits 45 2>&1); rc=$?
    fi
    if (( rc != 0 )); then
        printf '%s\n' "$out" | sed 's/^/ERROR\t/'
        printf 'NOTDECODED\tthe input is not a SIB3 body; no fields were reported\n' >&2
        return 1
    fi

    printf 'message\tSystemInformationBlockType3\n'
    local k v
    while IFS=$'\t' read -r k v; do
        case "$k" in
            layout)     printf 'layout\t%s\n' "$v" ;;
            q_hyst)     printf 'q_hyst\t%s\n' "$v" ;;
            thresh_serving_low)
                        printf 'thresh_serving_low\t%s\n' "$v" ;;
            cell_reselection_priority)
                        printf 'cell_reselection_priority\t%s\n' "$v" ;;
            q_rx_lev_min)
                        printf 'q_rx_lev_min\t%s\n' "$v" ;;
            presence_antenna_port1)
                        printf 'presence_antenna_port1\t%s\n' "$v" ;;
            neigh_cell_config)
                        printf 'neigh_cell_config\t%s\n' "$v" ;;
            t_reselection_eutra)
                        printf 't_reselection_eutra\t%s\n' "$v" ;;
            bits_consumed)
                        printf 'bits\t%s\n' "$v" ;;
        esac
    done <<< "$out"
    printf 'body\t%s\n' "$hex"
    return 0
}

# ── SIB5 — inter-frequency carriers, TS 36.331 §6.3.1 ───────────────────
#
# SIB5 is decoded by the real TS 36.331 unaligned-PER codec in
# tools/lte_asn1.py, like SIB1 to SIB4. Its body is the longest of the
# frequency SIBs: an extension bit, a 3-bit carrier count, then one
# interFreqCarrierFreqInfo per carrier, 48 bits each when nothing optional is
# present, plus an interFreqNeighCellList and an interFreqExcludedCellList.
#
# Every carrier leads with six OPTIONAL presence bits in declaration order.
# That is why the flat 16-bit-word reader this function used to be was not a
# partial answer but a wrong one: dl-CarrierFreq does not start at bit 0 of the
# carrier, it starts at bit 7, after those presence bits, and the words before
# it are framing. It printed valid-looking EARFCNs derived from framing bits.
lair_decode_sib5() {
    local hex; hex=$(lair_nfc "${1:-}")
    [[ -n "$hex" ]] || { printf 'ERROR\t--decode-sib needs hex\n' >&2; return 2; }
    [[ "$hex" =~ ^[0-9A-F]+$ ]] || { printf 'ERROR\tnot valid hex\n' >&2; return 1; }

    # SIB5 is read by the real TS 36.331 unaligned-PER codec in
    # tools/lte_asn1.py. What stood here before sliced the body into flat
    # 16-bit words and offered each as a "candidate neighbour EARFCN". Those
    # words are not EARFCNs and not neighbour cells: the body opens with an
    # extension bit and a 3-bit carrier count, each carrier leads with six
    # OPTIONAL presence bits, and dl-CarrierFreq sits at bit 7 of the carrier,
    # after those. Every number it printed was framing read as data. It has
    # been removed rather than kept beside the correct one.
    #
    # A neighbour cell in SIB5 is 14 bits -- physCellId (9) and q-OffsetCell
    # (5) with no extension bit -- while SIB4's is 15. The types read alike,
    # so the codec, not this function, is where that difference is pinned.
    local tool="$IMSISTING_ROOT/tools/lte_asn1.py"
    [[ -r "$tool" ]] || {
        printf 'ERROR\tmissing %s\n' "$tool" >&2
        printf 'WHY\tthe SIB5 decoder is a real ASN.1 PER codec and lives in tools/\n' >&2
        return 1
    }

    # A SIB5 body is variable-length (52 bits for one bare carrier, plus 48 per
    # extra carrier, plus any lists) and the hex is zero-padded to a whole
    # octet, so the padded length is what gets passed; the codec consumes
    # exactly the fields it finds and reports how many.
    #
    # There is deliberately no fixed-length retry like SIB3's: with a
    # variable-length body a retry at a constant length re-reads a prefix of a
    # message that was correctly refused.
    local pbits=$(( ${#hex} * 4 ))
    local out rc alt=""
    # The container reading goes first, and that order matters. It is the only
    # one of the two that can be checked: a SystemInformation header carries
    # sibType5 as six specific bits (000011) and the body behind it must then
    # decode. The body reading checks nothing, so a whole container read as a
    # bare body does not fail -- it reports a confident carrier assembled from
    # framing bits (dl-CarrierFreq 24828, q-RxLevMin -66 on the fixture below).
    # A wrong field that looks plausible is the worst outcome here, so the
    # reading that can be wrong silently is the one that goes second.
    out=$(python3 "$tool" sib5-decode "$hex" --bits "$pbits" --container 2>&1)
    rc=$?
    if (( rc == 0 )); then
        # Both readings are syntactically possible for some inputs -- a body
        # whose dl-CarrierFreq starts 0011 has the same bits 8..13 as a
        # container header. When that happens the caller is told rather than
        # left with whichever the code happened to try first.
        alt=$(python3 "$tool" sib5-decode "$hex" --bits "$pbits" 2>&1) || alt=""
    else
        out=$(python3 "$tool" sib5-decode "$hex" --bits "$pbits" 2>&1)
        rc=$?
    fi
    if (( rc != 0 )); then
        printf '%s\n' "$out" | sed 's/^/ERROR\t/'
        printf 'NOTDECODED\tthe input is not a SIB5 body; no fields were reported\n' >&2
        return 1
    fi

    local k v
    while IFS=$'\t' read -r k v; do
        case "$k" in
            bits_consumed) printf 'bits\t%s\n' "$v" ;;
            message)       printf 'message\tSIB5 (SystemInformationBlockType5)\n' ;;
            carrier)       printf 'carrier\t%s\n' "$v" ;;
            neigh)         printf 'neighbour_cell\t%s\n' "$v" ;;
            excluded)      printf 'excluded_cell\t%s\n' "$v" ;;
            carrier_count) printf 'carrier_count\t%s\n' "$v" ;;
            layout)        : ;;
            *)             printf '%s\t%s\n' "$k" "$v" ;;
        esac
    done <<< "$out"
    if [[ -n "$alt" ]]; then
        printf 'ambiguous\tthis input also parses as a bare SIB5 body; the list above\n'
        printf 'ambiguous\tis the SystemInformation container reading, which is the one\n'
        printf 'ambiguous\tthat carries a checkable sibType5 header\n'
    fi
    printf 'ref\t3GPP TS 36.331 6.3.1 SystemInformationBlockType5 (unaligned PER)\n'
    printf 'body\t%s\n' "$hex"
    return 0
}

# ── SIB4 — intra-frequency neighbour cells, TS 36.331 §6.3.1 ────────────
#
# SIB4 is decoded by the real TS 36.331 unaligned-PER codec in
# tools/lte_asn1.py, like SIB1 to SIB3. The function below only frames the
# caller's hex and labels the codec's fields; it does not walk the ASN.1
# itself, and it must not start to. The layout is
#
#     SystemInformationBlockType4 ::= SEQUENCE {
#         intraFreqNeighCellList     IntraFreqNeighCellList   OPTIONAL,
#         intraFreqExcludedCellList  IntraFreqExcludedCellList OPTIONAL,
#         csg-PhysCellIdRange        PhysCellIdRange           OPTIONAL,
#         ...
#     }
#     IntraFreqNeighCellInfo ::= SEQUENCE {
#         physCellId      PhysCellId,       -- 0..503, 9 bits
#         q-OffsetCell    Q-OffsetRange,    -- 31 values, 5 bits
#         ...                                                  -- extensible
#     }
#
# The neighbour entry is 15 bits, and the extension bit is not decoration: a
# SEQUENCE that declares an extension marker emits that bit even when it
# declares no extension additions. Getting it wrong puts physCellId one bit
# early and every entry after the first 15 bits out.
lair_decode_sib4() {
    local hex; hex=$(lair_nfc "${1:-}")
    [[ -n "$hex" ]] || { printf 'ERROR\t--decode-sib needs hex\n' >&2; return 2; }
    [[ "$hex" =~ ^[0-9A-F]+$ ]] || { printf 'ERROR\tnot valid hex\n' >&2; return 1; }

    # SIB4 is read by the real TS 36.331 unaligned-PER codec in
    # tools/lte_asn1.py. What stood here before walked the body as a flat list
    # of 12-bit records -- 9 bits of physCellId and a 3-bit Q-OffsetRange --
    # starting at bit 0. No part of that is the message. Bit 0 is the
    # extension bit of the SIB4 SEQUENCE, the three OPTIONAL presence bits
    # follow it, each list carries a 4-bit length before its elements, and
    # Q-OffsetCell is a 5-bit ENUMERATED, not 3. Sixteen one-bit fields of
    # structural framing were being read as fifteen neighbour cells, and the
    # offsets were wrong even where the boundaries happened to line up. It has
    # been removed rather than kept beside the correct one.
    local tool="$IMSISTING_ROOT/tools/lte_asn1.py"
    [[ -r "$tool" ]] || {
        printf 'ERROR\tmissing %s\n' "$tool" >&2
        printf 'WHY\tthe SIB4 decoder is a real ASN.1 PER codec and lives in tools/\n' >&2
        return 1
    }

    # A bare SIB4 body is at least 4 bits and grows by 15 bits per neighbour
    # cell, so its length is not fixed and the hex is zero-padded to a whole
    # octet. The padded length is passed and the codec consumes exactly the
    # fields it finds, reading the input as a container only when a 14-bit
    # header still leaves a whole body behind. There is deliberately no retry
    # at a fixed short length: with a variable-length body a retry re-reads a
    # prefix of a message that was correctly refused, and an extension bit
    # this codec does not model would be reported as an empty cell list.
    local pbits=$(( ${#hex} * 4 ))
    local out rc
    out=$(python3 "$tool" sib4-decode "$hex" --bits "$pbits" 2>&1); rc=$?
    if (( rc != 0 )); then
        printf '%s\n' "$out" | sed 's/^/ERROR\t/'
        printf 'NOTDECODED\tthe input is not a SIB4 body; no fields were reported\n' >&2
        return 1
    fi

    local k v
    while IFS=$'\t' read -r k v; do
        case "$k" in
            bits_consumed) printf 'bits\t%s\n' "$v" ;;
            message)       printf 'message\tSIB4 (SystemInformationBlockType4)\n' ;;
            *)             printf '%s\t%s\n' "$k" "$v" ;;
        esac
    done <<< "$out"
    printf 'ref\t3GPP TS 36.331 6.3.1 SystemInformationBlockType4 (unaligned PER)\n'
    printf 'body\t%s\n' "$hex"
    return 0
}

# ── SIB8 — CDMA2000 reselection; and the warning-message helpers ────────
#
# The three ASN.1 SEQUENCEs that stood here as "SIB6 / SIB7 / SIB8 — ETWS
# and CMAS" were none of those things. Measured against TS 36.331 through
# pycrate, the real definitions are:
#
#   SystemInformationBlockType6 ::= SEQUENCE {
#       t-ReselectionUTRA       INTEGER (0..7),              -- MANDATORY
#       carrierFreqListUTRA-FDD SEQUENCE (SIZE (1..16)) OF CarrierFreqUTRA-FDD
#                                                           OPTIONAL,
#       carrierFreqListUTRA-TDD ... OPTIONAL,
#       t-ReselectionUTRA-SF    SEQUENCE {...} OPTIONAL, ... }
#
#   SystemInformationBlockType7 ::= SEQUENCE {
#       t-ReselectionGERAN      INTEGER (0..7),              -- MANDATORY
#       t-ReselectionGERAN-SF   SEQUENCE {...} OPTIONAL,
#       carrierFreqsInfoList    SEQUENCE (SIZE (1..16)) OF CarrierFreqsInfoGERAN
#                                                           OPTIONAL, ... }
#
# so both are carrier-frequency lists for reselection, and both are now
# decoded by the real unaligned-PER codec in tools/lte_asn1.py.
#
#   SystemInformationBlockType8 ::= SEQUENCE {
#       systemTimeInfo          SEQUENCE {...} OPTIONAL,
#       searchWindowSize        INTEGER (0..15) OPTIONAL,
#       parametersHRPD          SEQUENCE {...} OPTIONAL,
#       parameters1XRTT         SEQUENCE {...} OPTIONAL, ... }
#
# is CDMA2000 reselection. Note what is NOT in it: messageIdentifier,
# serialNumber and warningType, which is why nothing here may be called CMAS.
#
# The warning messages are SIB10 (ETWS primary: messageIdentifier,
# serialNumber, warningType, and a 'dummy' OPTIONAL), SIB11 (ETWS secondary)
# and SIB12 (CMAS: the same shape as SIB11 with -r9 suffixes). The helpers
# below decode warningType for those; SIB8 does not carry one.
#
# warningType is 2 octets: TS 36.331 §6.3.1 and TS 23.041 §9.3.24 give it as
# the first two bytes of the ETWS primary notification, with the top 2 bits
# of octet 1 as the warning class.
lair_warning_type() {
    local h; h=$(lair_nfc "${1:-}")
    [[ "$h" =~ ^[0-9A-F]{4}$ ]] || return 1
    local b0; b0=$(( 16#${h:0:2} ))
    local cls=$(( (b0 >> 6) & 0x3 ))
    local cat=$(( b0 & 0x3F ))
    local cname
    case "$cls" in
        0) cname="earthquake" ;;
        1) cname="tsunami" ;;
        2) cname="reserved-2" ;;
        3) cname="reserved-3" ;;
    esac
    printf 'class=%s category=%s raw=%s' "$cname" "$cat" "$h"
}

# SIB6 and SIB7 go through the real TS 36.331 unaligned-PER codec in
# tools/lte_asn1.py; see the structure comments above. They share one runner
# because they differ only in the subcommand and in the SIB type name the
# container header has to carry.
#
# $1 = subcommand stem (sib6 / sib7)
# $2 = the SIB type the container header must name (sibType6 / sibType7)
# $3 = hex
# Prints the codec's own `key<TAB>value` lines, or an ERROR and returns 1.
lair_sib_codec() {
    local stem="$1" stype="$2" hex="$3"
    local tool="$IMSISTING_ROOT/tools/lte_asn1.py"
    [[ -r "$tool" ]] || {
        printf 'ERROR\tmissing %s\n' "$tool" >&2
        printf 'WHY\tthe SIB decoder is a real ASN.1 PER codec and lives in tools/\n' >&2
        return 1
    }

    # A SIB6 body is 7 bits minimal and SIB7 6, but both grow with their
    # optional lists and 16-bit-octet padding, and neither length is
    # recoverable from hex. The padded length is passed and the codec consumes
    # exactly the fields it finds and reports how many.
    local pbits=$(( ${#hex} * 4 ))
    local out rc
    # The container reading goes first: it is the only one that can be
    # checked. A SystemInformation header carries a specific 5-bit sibType and
    # the codec refuses a container whose type is not the one asked for. The
    # bare-body reading checks nothing, so a whole container read as a body
    # does not fail -- it reports a confident carrier assembled from the
    # header's own bits.
    out=$(python3 "$tool" "$stem-decode" "$hex" --bits "$pbits" --container 2>&1)
    rc=$?
    if (( rc == 3 )); then
        # Exit 3 means the input DID parse as a SystemInformation container and
        # carried a different SIB. Falling back to a bare-body reading here is
        # what produces a confident wrong answer: the container's own header
        # bits decode as a plausible body. Refuse instead.
        printf '%s\n' "$out" >&2
        return 1
    fi
    if (( rc != 0 )); then
        # No fixed-length retry: with a variable-length body a retry at a
        # constant length re-reads a prefix of a message already refused.
        out=$(python3 "$tool" "$stem-decode" "$hex" --bits "$pbits" 2>&1)
        rc=$?
    fi
    if (( rc != 0 )); then
        printf '%s\n' "$out" >&2
        return 1
    fi
    [[ -z "$stype" ]] || :
    printf '%s\n' "$out"
    return 0
}

lair_decode_sib6() {
    local hex; hex=$(lair_nfc "${1:-}")
    [[ -n "$hex" ]] || { printf 'ERROR\t--decode-sib needs hex\n' >&2; return 2; }
    [[ "$hex" =~ ^[0-9A-F]+$ ]] || { printf 'ERROR\tnot valid hex\n' >&2; return 1; }

    local out
    out=$(lair_sib_codec sib6 sibType6 "$hex") || {
        printf '%s\n' "$out" | sed '/^$/d;s/^/ERROR\t/'
        printf 'NOTDECODED\tthe input is not a SIB6 body; no fields were reported\n' >&2
        return 1
    }
    local k v
    while IFS=$'\t' read -r k v; do
        case "$k" in
            layout)        : ;;
            message)       : ;;
            bits_consumed) printf 'bits\t%s\n' "$v" ;;
            *)             printf '%s\t%s\n' "$k" "$v" ;;
        esac
    done <<< "$out"
    printf 'ref\t3GPP TS 36.331 6.3.1 SystemInformationBlockType6 (UTRA reselection, unaligned PER)\n'
    printf 'body\t%s\n' "$hex"
    return 0
}

lair_decode_sib7() {
    local hex; hex=$(lair_nfc "${1:-}")
    [[ -n "$hex" ]] || { printf 'ERROR\t--decode-sib needs hex\n' >&2; return 2; }
    [[ "$hex" =~ ^[0-9A-F]+$ ]] || { printf 'ERROR\tnot valid hex\n' >&2; return 1; }

    local out
    out=$(lair_sib_codec sib7 sibType7 "$hex") || {
        printf '%s\n' "$out" | sed '/^$/d;s/^/ERROR\t/'
        printf 'NOTDECODED\tthe input is not a SIB7 body; no fields were reported\n' >&2
        return 1
    }
    local k v
    while IFS=$'\t' read -r k v; do
        case "$k" in
            layout)        : ;;
            message)       : ;;
            bits_consumed) printf 'bits\t%s\n' "$v" ;;
            *)             printf '%s\t%s\n' "$k" "$v" ;;
        esac
    done <<< "$out"
    printf 'ref\t3GPP TS 36.331 6.3.1 SystemInformationBlockType7 (GERAN reselection, unaligned PER)\n'
    printf 'body\t%s\n' "$hex"
    return 0
}
lair_decode_sib8() {
    local hex; hex=$(lair_nfc "${1:-}")
    [[ -n "$hex" ]] || { printf 'ERROR\t--decode-sib needs hex\n' >&2; return 2; }
    [[ "$hex" =~ ^[0-9A-F]+$ ]] || { printf 'ERROR\tnot valid hex\n' >&2; return 1; }

    # What stood here read systemInformationAreaID, messageIdentifier,
    # serialNumber, warningMessageSegmentType/Number/Segment and
    # dataCodingScheme out of a SIB8. None of those fields is in
    # SystemInformationBlockType8: every one of them belongs to SIB10
    # (ETWS primary), SIB11 (ETWS secondary) or SIB12 (CMAS). The reader was
    # decoding a different message's shape and reporting it as SIB8, so the
    # only honest thing to do with a body it cannot place is refuse it --
    # which is what the codec does for every field it does not model.
    local out
    out=$(lair_sib_codec sib8 sibType8 "$hex") || {
        printf '%s\n' "$out" | sed '/^$/d;s/^/ERROR\t/'
        printf 'NOTDECODED\tthe input is not a SIB8 body; no fields were reported\n' >&2
        return 1
    }
    local k v
    while IFS=$'\t' read -r k v; do
        case "$k" in
            layout|message)  : ;;
            bits_consumed)   printf 'bits\t%s\n' "$v" ;;
            *)               printf '%s\t%s\n' "$k" "$v" ;;
        esac
    done <<< "$out"
    printf 'ref\t3GPP TS 36.331 6.3.1 SystemInformationBlockType8 (CDMA2000 reselection, unaligned PER)\n'
    printf 'note\tSIB8 is not CMAS; CMAS is SIB12, and ETWS is SIB10/SIB11\n'
    printf 'body\t%s\n' "$hex"
    return 0
}

# ── SIB9 to SIB13 — read by the generated codec ────────────────────────
#
# SIB1 to SIB8 above are decoded by code transcribed field by field in
# tools/lte_asn1.py. SIB9 to SIB13 are not: they are read by the generic PER
# engine (tools/lte_per.py) driving a layout table generated from pycrate
# (tools/lte_rrc_layout.py). Transcribing one SIB by hand cost most of a
# session and does not scale, and proving the transcription was the expensive
# part -- the generator emits the same layout in one pass and the engine is
# differential-tested against the oracle that generated it.
#
# Two of these were previously unreachable for a reason that reads as "this
# cell does not broadcast it":
#
#   * SIB9, SIB10, SIB11 and SIB12 had NO decoder. lair_decode_sib() dispatched
#     1 through 8, so every one of them hit the catch-all and was reported as
#     an unknown SIB type. SIB12 is the one that matters most here: it is CMAS,
#     and SIB8's old decoder used to print SIB12's fields under SIB8's name.
#   * SIB13 was on a private octet-aligned layout of this tree's own invention,
#     which the module warned about in its output. It is now the same real
#     codec as the rest, and the warning is gone with the layout.
#
# SIB12 and SIB13 enter TS 36.331 at Rel-9 and have no unsuffixed ASN.1 name.
# The table carries them as SystemInformationBlockType12_r9 and
# SystemInformationBlockType13_r9; hasattr(module, "...Type13") is False and
# says nothing about whether the type exists.
_lair_decode_sib_engine() {
    local n="$1" stem="$2" root="$3" what="$4"
    local hex; hex=$(lair_nfc "${5:-}")
    [[ -n "$hex" ]] || { printf 'ERROR\t--decode-sib needs hex\n' >&2; return 2; }
    [[ "$hex" =~ ^[0-9A-F]+$ ]] || { printf 'ERROR\tnot valid hex\n' >&2; return 1; }

    local out
    out=$(lair_sib_codec "$stem" "" "$hex") || {
        printf '%s\n' "$out" | sed '/^$/d;s/^/ERROR\t/'
        printf 'NOTDECODED\tthe input is not a SIB%s body; no fields were reported\n' "$n" >&2
        return 1
    }
    local k v
    while IFS=$'\t' read -r k v; do
        case "$k" in
            layout|message)          : ;;
            bits_consumed)           printf 'bits\t%s\n' "$v" ;;
            # The engine's own note about a body that arrived octet padded
            # inside an open type. Passing it through matters: without it a
            # reader cannot tell a trailing field from pad bits.
            length_note)             printf 'note\t%s\n' "$v" ;;
            # container_bits is a bare number, so it needs a label of its own
            # or it prints as an anonymous 'note 80' that reads like a field.
            container_bits)          printf 'container_bits\t%s\n' "$v" ;;
            *)                       printf '%s\t%s\n' "$k" "$v" ;;
        esac
    done <<< "$out"
    printf 'ref\t3GPP TS 36.331 6.3.1 %s (unaligned PER, generated codec)\n' "$what"
    printf 'body\t%s\n' "$hex"
    return 0
}

lair_decode_sib9() {
    _lair_decode_sib_engine 9 sib9 SystemInformationBlockType9 \
        "SystemInformationBlockType9 (home eNB name)" "${1:-}"
}
lair_decode_sib10() {
    _lair_decode_sib_engine 10 sib10 SystemInformationBlockType10 \
        "SystemInformationBlockType10 (ETWS primary notification)" "${1:-}"
}
lair_decode_sib11() {
    _lair_decode_sib_engine 11 sib11 SystemInformationBlockType11 \
        "SystemInformationBlockType11 (ETWS secondary notification)" "${1:-}"
}
lair_decode_sib12() {
    _lair_decode_sib_engine 12 sib12 SystemInformationBlockType12_r9 \
        "SystemInformationBlockType12-r9 (CMAS)" "${1:-}"
}
lair_decode_sib13() {
    local hex; hex=$(lair_nfc "${1:-}")
    local out
    out=$(_lair_decode_sib_engine 13 sib13 SystemInformationBlockType13_r9 \
        "SystemInformationBlockType13-r9 (MBSFN)" "$hex")
    local rc=$?
    (( rc == 0 )) || { printf '%s\n' "$out" >&2; return "$rc"; }

    # The codec returns sf-AllocInfo as the BIT STRING the ASN.1 declares --
    # six bits mapping to the first six candidate subframes, TS 36.213 table
    # 4.2-2. What the ASN.1 does NOT carry is which of those bits are legal,
    # and that is the part a survey actually wants to know: in FDD an MBSFN
    # subframe cannot be 0, 4, 5 or 9 (TS 36.211 6.10.1). Reporting only the
    # raw mask would hand back the easy half. The helpers below survived the
    # private-layout parser they were written for, because the knowledge in
    # them is not in the codec.
    local k v
    while IFS=$'\t' read -r k v; do
        printf '%s\t%s\n' "$k" "$v"
        case "$k" in
            *sf-AllocInfo-r9)
                local sfb="${v#0b}"; sfb="${sfb%% *}"
                [[ "$sfb" =~ ^[01]+$ ]] || continue
                local sflist ill
                sflist=$(lair_mbsfn_sf_list "$(lair_nibble_bits "$(( 2#$sfb ))" ${#sfb})")
                ill=$(lair_mbsfn_illegal_bits "$sflist")
                printf '%s.subframes\t%s\n' "${k%.mcch-Config-r9.sf-AllocInfo-r9}" \
                       "${sflist:-none}"
                [[ -z "$ill" ]] || printf '%s.illegal_subframes\t%s (FDD cannot carry MBSFN in subframe 0/4/5/9, TS 36.211 6.10.1)\n' \
                       "${k%.mcch-Config-r9.sf-AllocInfo-r9}" "$ill"
                ;;
        esac
    done <<< "$out"
    return 0
}

# ── SIB13 — MBSFN, TS 36.331 §6.3.1 ─────────────────────────────────────
#
# MBSFN-AreaInfo ::= SEQUENCE {
#     mbsfn-AreaId                  INTEGER (0..255),      -- 8 bits
#     non-MBSFNregionLength         ENUMERATED {s1, s2, s4, s8, s16, s32},
#     notificationIndicator         INTEGER (0..511),      -- 9 bits
#     mcch-Config  SEQUENCE {
#         mcch-RepetitionPeriod     ENUMERATED {rf32, rf64, rf128, rf256},
#         mcch-Offset               INTEGER (0..10),       -- 4 bits
#         mcch-ModificationPeriod   ENUMERATED {
#                                       rf512, rf1024, rf2048, rf4096 },
#         sf-AllocInfo              BIT STRING (SIZE (6)), -- maps to the
#         --   first 32 subframes of the radio frame, TS 36.213 table 4.2-2
#         signallingMCS             ENUMERATED {n2, n7, n13, n19}
#     },
#     ...
# }
#
# and the area is then given a frame allocation by
#
# MBSFN-SubframeConfig ::= SEQUENCE {
#     radioframeAllocationPeriod  ENUMERATED {n1, n2, n4, n8, n16, n32},
#     radioframeAllocationOffset  INTEGER (0..7),          -- 3 bits
#     subframeAllocation          CHOICE { oneFrame  BIT STRING (SIZE(6)),
#                                          fourFrames BIT STRING (SIZE(24)) }
# }
#
# The frame-allocation arithmetic is exact and is what a survey needs:
# an MBSFN subframe falls in radio frames where SFN mod period = offset.
lair_mcch_period_rf() {
    case "${1:-}" in
        0) echo 32 ;; 1) echo 64 ;; 2) echo 128 ;; 3) echo 256 ;; *) return 1 ;;
    esac
}
lair_mcch_mod_period_rf() {
    case "${1:-}" in
        0) echo 512 ;; 1) echo 1024 ;; 2) echo 2048 ;; 3) echo 4096 ;; *) return 1 ;;
    esac
}
lair_signalling_mcs() {
    case "${1:-}" in
        0) echo "n2" ;; 1) echo "n7" ;; 2) echo "n13" ;; 3) echo "n19" ;; *) return 1 ;;
    esac
}

lair_mbsfn_rf_period() {
    case "${1:-}" in
        0) echo 1 ;; 1) echo 2 ;; 2) echo 4 ;; 3) echo 8 ;; 4) echo 16 ;; 5) echo 32 ;; *) return 1 ;;
    esac
}
lair_mbsfn_sf_list() {
    local bits="$1" out="" i
    for (( i = 0; i < 6; i++ )); do
        [[ "${bits:$i:1}" == "1" ]] && out+="${out:+,}$i"
    done
    printf '%s' "$out"
}
# sf-AllocInfo / subframeAllocation are BIT STRINGs whose bit i is subframe
# b_i+n, with b_0 = 0 and the fixed rule that subframes 0, 4, 5 and 9 can
# never carry MBSFN in an FDD frame (TS 36.211 §6.10.1). Report the illegal
# bits rather than silently dropping them: an allocation naming subframe 4
# is a decoder bug or a forged SIB, and either is worth seeing.
lair_mbsfn_illegal_bits() {
    local list="$1" out="" s
    local IFS=,
    for s in $list; do
        case "$s" in 0|4|5|9) out+="${out:+,}$s" ;; esac
    done
    printf '%s' "$out"
}

# Render the low n bits of a value as a '0'/'1' string, MSB first, so a
# BIT STRING subframe mask keeps its bit positions.
lair_nibble_bits() {
    local v="${1:-0}" n="${2:-6}" s="" i
    for (( i = n - 1; i >= 0; i-- )); do
        s+=$(( (v >> i) & 1 ))
    done
    printf '%s' "$s"
}

# ── MIB — BCCH-BCH, TS 36.331 §6.2.2 ────────────────────────────────────
#
# MasterInformationBlock ::= SEQUENCE {
#     dl-Bandwidth     ENUMERATED {n6, n15, n25, n50, n75, n100},
#     phich-Config     SEQUENCE {
#         phich-Duration   ENUMERATED {normal, extended},   -- 1 bit
#         phich-Resource   ENUMERATED {oneSixth, half, one, two}  -- 2 bits
#     },
#     systemFrameNumber  BIT STRING (SIZE (8)),   -- the 8 MSBs of the 10-bit SFN
#     spare              BIT STRING (SIZE (10))
# }
#
# 3 + 1 + 2 + 8 + 10 = 24 bits, which is the whole BCH transport block: the
# MIB carries no length field and no optionality. dl-Bandwidth is encoded
# with the *same* 3-bit enumeration as the NB-IoT and NR paths use for their
# own tables, which is why the mapping below is spelled out from the ASN.1
# rather than borrowed from modules/12_nr_air.sh -- NR numbers its RBs by a
# different scheme entirely.
lair_mib_bw() {
    case "${1:-}" in
        0) echo "n6" ;; 1) echo "n15" ;; 2) echo "n25" ;;
        3) echo "n50" ;; 4) echo "n75" ;; 5) echo "n100" ;;
        *) echo "reserved" ;;
    esac
}
lair_mib_prb() {
    case "${1:-}" in
        0) echo 6 ;; 1) echo 15 ;; 2) echo 25 ;;
        3) echo 50 ;; 4) echo 75 ;; 5) echo 100 ;;
        *) echo 0 ;;
    esac
}

lair_decode_mib() {
    local hex; hex=$(lair_nfc "${1:-}")
    [[ -n "$hex" ]] || { printf 'ERROR\t--decode-mib needs a 24-bit hex payload\n' >&2; return 2; }
    [[ "$hex" =~ ^[0-9A-F]+$ ]] || { printf 'ERROR\tnot valid hex\n' >&2; return 1; }
    (( ${#hex} % 2 == 0 )) || { printf 'ERROR\todd hex length\n' >&2; return 1; }
    (( ${#hex} == 6 )) || { printf 'ERROR\tLTE MIB is exactly 24 bits (6 hex digits), got %s\n' "${#hex}" >&2; return 1; }

    local bw dur res sfn spare
    bw=$(lair_bits    "$hex" 0 3)  || return 1
    dur=$(lair_bits   "$hex" 3 1)  || return 1
    res=$(lair_bits   "$hex" 4 2)  || return 1
    sfn=$(lair_bits   "$hex" 6 8)  || return 1
    spare=$(lair_bits "$hex" 14 10) || return 1

    printf 'message\tMIB (MasterInformationBlock, BCCH-BCH)\n'
    printf 'body\t%s\n' "$hex"
    printf 'dl_bandwidth\t%s\n' "$(lair_mib_bw "$bw")"
    printf 'dl_bandwidth_index\t%s\n' "$bw"
    printf 'dl_bandwidth_prb\t%s\n' "$(lair_mib_prb "$bw")"
    printf 'phich_duration\t%s\n' "$( (( dur == 0 )) && echo normal || echo extended )"
    printf 'phich_duration_index\t%s\n' "$dur"
    printf 'phich_resource\t%s\n' "$(case "$res" in
        0) echo oneSixth ;; 1) echo half ;; 2) echo one ;; 3) echo two ;; esac)"
    printf 'phich_resource_index\t%s\n' "$res"
    printf 'system_frame_number\t%s\n' "$sfn"
    printf 'system_frame_number_msb\t%s\n' "$sfn"
    printf 'sfn_bit_width\t8\n'
    printf 'spare\t%s\n' "$spare"
    printf 'spare_bits\t10\n'
    printf 'payload_bits\t24\n'
    printf 'ref\t3GPP TS 36.331 6.2.2 MasterInformationBlock (3+1+2+8+10 = 24 bits)\n'
    return 0
}

# SIB-type dispatcher: --decode-sib <hex> takes the SIB type from the
# caller's second argument, defaulting to SIB1.
#
# Every SIB from 1 to 13 is now read by a real TS 36.331 unaligned-PER codec.
# None is on a private layout any more, and no case prints a caveat saying so,
# because there is no longer a case that needs one. SIB1 to SIB8 are decoded by
# the transcribed codecs in tools/lte_asn1.py; SIB9 to SIB13 by the generic PER
# engine driving a table generated from pycrate.
#
# The list is 1 to 13 and that is all of it: TS 36.331 defines no SIB14. There
# is no SIB with an unsuffixed name after 13 either -- SIB12 and SIB13 enter at
# Rel-9 as sibType12-v920 and sibType13-v920 -- so a body that is not one of
# these thirteen is rejected rather than guessed at.
lair_decode_sib() {
    local hex="${1:-}" sibtype="${2:-1}"
    case "$sibtype" in
        1|sib1)   lair_decode_sib1 "$hex" ;;
        2|sib2)   lair_decode_sib2 "$hex" ;;
        3|sib3)   lair_decode_sib3 "$hex" ;;
        4|sib4)   lair_decode_sib4 "$hex" ;;
        5|sib5)   lair_decode_sib5 "$hex" ;;
        6|sib6)   lair_decode_sib6 "$hex" ;;
        7|sib7)   lair_decode_sib7 "$hex" ;;
        8|sib8)   lair_decode_sib8 "$hex" ;;
        9|sib9)   lair_decode_sib9 "$hex" ;;
        10|sib10)  lair_decode_sib10 "$hex" ;;
        11|sib11)  lair_decode_sib11 "$hex" ;;
        12|sib12)  lair_decode_sib12 "$hex" ;;
        13|sib13)  lair_decode_sib13 "$hex" ;;
        *) printf 'ERROR\tunknown SIB type: %s (have 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13)\n' \
               "$(lair_sanitize "$sibtype")" >&2; return 2 ;;
    esac
}

# ── Paging: PF / PO — TS 36.304 §7.1, §7.2 and §7.3 ────────────────────
#
# TS 36.304 §7.1:
#   UE_ID = IMSI mod 1024,  P-RNTI on PDCCH
#   UE_ID = IMSI mod 4096,  P-RNTI on NPDCCH (NB-IoT)
#   UE_ID = IMSI mod 16384, P-RNTI on MPDCCH (BL/CE), or on NPDCCH when a
#                           non-anchor paging carrier is configured
#   T   = DRX cycle in radio frames
#   nB  = 4T, 2T, T, T/2, T/4, T/8, T/16, T/32, T/64, T/128, T/256
#         (and T/512, T/1024 for NB-IoT)
#   N   = min(T, nB)
#   Ns  = max(1, nB/T)
#   PF: SFN mod T = (T div N) * (UE_ID mod N)
#   i_s = floor(UE_ID / N) mod Ns
#
# The module previously hard-coded UE_ID = IMSI mod 1024 for every case and
# ignored the ue-id argument it parsed. Both are wrong for BL/CE and NB-IoT
# UEs: an MPDCCH UE's identifier is IMSI mod 16384, so its PF and i_s land
# on different frames than a mod-1024 calculation predicts, and a tracker
# watching the wrong PF misses the page entirely.
#
# TS 36.304 §7.3 (eDRX) — a UE with eDRX is NOT paged on every DRX cycle.
# It is paged inside a Paging Time Window that recurs once per eDRX cycle:
#
#   H-SFN mod TeDRX,H = (UE_ID_H mod TeDRX,H)          -- the Paging Hyperframe
#   PTW_start: SFN = 256 * ieDRX,  ieDRX = floor(UE_ID_H / TeDRX,H) mod 4
#   PTW_end:   SFN = (PTW_start + L*100 - 1) mod 1024
#
# where TeDRX,H is the eDRX cycle in hyperframes (1..256, or 2..1024 for
# NB-IoT) and L is the PTW length in seconds. UE_ID_H is the 10 (PDCCH) or
# 12 (NPDCCH) most significant bits of the Hashed ID. Inside the PTW the
# ordinary §7.1 PF/PO rule still applies with the normal DRX cycle, so an
# eDRX report is the §7.1 answer *plus* the window it has to fall in.
# Reporting the plain §7.1 PO with no H-SFN gate is exactly the bug that
# makes a tracker sit on a PO the UE is not required to monitor.
lair_paging_frame() {
    local imsi="${1:-}" tac="${2:-}" ue_id_arg="${3:-}" drx="${4:-32}" nb="${5:-32}"
    # Positional defaults must be applied BEFORE shifting, and the shift must
    # consume exactly the five fixed slots. `shift 5 || true` silently
    # renumbers when fewer than five arguments were supplied, which is how a
    # caller passing only two arguments ends up reading drx from thin air.
    if (( $# >= 5 )); then shift 5; else shift $#; fi
    local edrx="" ptw="" monitor="pdcch" duplex="fdd"
    while (( $# > 0 )); do
        case "$1" in
            --edrx) edrx="${2:-}"; shift 2 ;;
            --ptw)  ptw="${2:-}";  shift 2 ;;
            --mpdcch)   monitor=mpdcch; shift ;;
            --npdcch)   monitor=npdcch; shift ;;
            --pdcch)    monitor=pdcch; shift ;;
            --tdd)      duplex=tdd; shift ;;
            --fdd)      duplex=fdd; shift ;;
            --earfcn)
                # Derive the duplex from the band the EARFCN belongs to, so a
                # caller who knows the cell does not also have to know that
                # band 38 is TDD. An EARFCN outside LAIR_BANDS is an error
                # rather than a silent fall back to FDD -- defaulting to FDD
                # is how the generator came to emit tm=1 for TDD bands.
                local _b
                _b=$(lair_band_of_earfcn "${2:-}") || {
                    printf 'ERROR\tEARFCN %s is outside LAIR_BANDS, cannot derive duplex\n' \
                           "$(lair_sanitize "${2:-<none>}")" >&2; return 2; }
                duplex=$(lair_band_duplex "$_b")
                shift 2 ;;
            *) printf 'ERROR\t--paging-frame: unknown option %s\n' "$(lair_sanitize "$1")" >&2; return 2 ;;
        esac
    done

    [[ "$imsi" =~ ^[0-9]{14,15}$ ]] || {
        printf 'ERROR\tIMSI must be 14 or 15 digits: %s\n' "$(lair_sanitize "${imsi:-<none>}")" >&2
        return 2
    }
    [[ "$tac" =~ ^[0-9]+$ ]] || {
        printf 'ERROR\tTAC must be numeric: %s\n' "$(lair_sanitize "${tac:-<none>}")" >&2
        return 2
    }
    case "$drx" in 32|64|128|256) ;; *) printf 'ERROR\tDRX cycle must be 32/64/128/256, got %s\n' "$(lair_sanitize "$drx")" >&2; return 2 ;; esac

    # nB is given symbolically as a multiple of T. Translate it, and reject
    # a combination whose result is not a whole number of radio frames.
    local nB
    case "$nb" in
        128) nB=$(( 4  * drx )) ;;
        64)  nB=$(( 2  * drx )) ;;
        32)  nB=$(( 1  * drx )) ;;
        16)  nB=$(( drx / 2 )) ;;
        8)   nB=$(( drx / 4 )) ;;
        4)   nB=$(( drx / 8 )) ;;
        2)   nB=$(( drx / 16 )) ;;
        1)   nB=$(( drx / 32 )) ;;
        *)   printf 'ERROR\tnB must be one of 4T,2T,T,T/2,T/4,T/8,T/16,T/32,T/64,T/128,T/256\n' >&2; return 2 ;;
    esac
    (( nB >= 1 )) || { printf 'ERROR\tnB resolved below 1 for T=%s nB=%s\n' "$drx" "$nb" >&2; return 2; }

    # UE_ID: the ue-id argument wins when supplied, otherwise derive it from
    # the IMSI with the modulus that matches where P-RNTI is monitored.
    local mod denom ue_id ue_src
    case "$monitor" in
        pdcch)   mod=1024 ;;
        npdcch)  mod=4096 ;;
        mpdcch)  mod=16384 ;;
    esac
    # ue-id is honoured when supplied. "0" and the empty string both mean
    # "derive it from the IMSI": that sentinel predates this change (the
    # CLI and the selftest both pass 0 for it) and a genuine UE_ID of 0 is
    # the value the spec mandates for a UE with no IMSI/5G-S-TMSI anyway,
    # so the two readings coincide rather than conflict.
    if [[ -n "$ue_id_arg" && "$ue_id_arg" != "0" ]]; then
        [[ "$ue_id_arg" =~ ^[0-9]+$ ]] || {
            printf 'ERROR\tue-id must be numeric: %s\n' "$(lair_sanitize "$ue_id_arg")" >&2; return 2; }
        ue_id=$(( ue_id_arg % mod ))
        ue_src="argument (mod $mod)"
    else
        # IMSI is a decimal integer per §7.1, not a hex literal; 15 digits
        # overflows a 64-bit shell integer, so reduce it digit by digit.
        ue_id=$(lair_imsi_mod "$imsi" "$mod")
        ue_src="IMSI mod $mod"
    fi

    local N=$(( drx < nB ? drx : nB ))
    local Ns=$(( nB / drx )); (( Ns < 1 )) && Ns=1
    local TdivN=$(( drx / N ))
    local PF=$(( TdivN * (ue_id % N) ))
    local i_s=$(( (ue_id / N) % Ns ))

    # §7.2 subframe patterns. TDD and FDD differ, and the narrowband (MPDCCH
    # at 1.4/3 MHz) pattern differs from the wideband one -- the module used
    # the FDD/PDCCH table for everything, which is wrong on a TDD cell.
    local po
    if [[ "$duplex" == "tdd" ]]; then
        case "$Ns:$i_s" in
            1:0) po=0 ;;
            2:0) po=0 ;; 2:1) po=5 ;;
            4:0) po=0 ;; 4:1) po=1 ;; 4:2) po=5 ;; 4:3) po=6 ;;
            *)   po="invalid" ;;
        esac
    else
        case "$Ns:$i_s" in
            1:0) po=9 ;;
            2:0) po=4 ;; 2:1) po=9 ;;
            4:0) po=0 ;; 4:1) po=4 ;; 4:2) po=5 ;; 4:3) po=9 ;;
            *)   po="invalid" ;;
        esac
    fi

    printf 'imsi\t%s\n' "$imsi"
    printf 'tac\t%s\n' "$tac"
    printf 'ue_id_arg\t%s\n' "${ue_id_arg:-<derived>}"
    printf 'ue_id\t%s\n' "$ue_id"
    printf 'ue_id_source\t%s\n' "$ue_src"
    printf 'ue_id_modulus\t%s\n' "$mod"
    printf 'p_rnti_search_space\t%s\n' "$monitor"
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
    printf 'duplex\t%s\n' "$duplex"
    printf 'sfn_mod_T\t%s\n' "$(( PF % drx ))"
    printf 'formula\tSFN mod T = (T div N)*(UE_ID mod N); i_s = floor(UE_ID/N) mod Ns\n'

    if [[ -n "$edrx" ]]; then
        lair_edrx_report "$edrx" "$ptw" "$ue_id" "$drx" || return $?
    fi

    printf 'ref\t3GPP TS 36.304 7.1/7.2/7.3\n'
    return 0
}

# Reduce an IMSI (or any digit string) modulo m without overflowing: a
# 15-digit IMSI exceeds a signed 64-bit integer, and bash arithmetic would
# wrap silently rather than error.
lair_imsi_mod() {
    local digits="${1:-}" m="${2:-1024}" i acc=0
    [[ "$digits" =~ ^[0-9]+$ ]] || return 1
    [[ "$m" =~ ^[1-9][0-9]*$ ]] || return 1
    for (( i = 0; i < ${#digits}; i++ )); do
        acc=$(( (acc * 10 + ${digits:i:1}) % m ))
    done
    printf '%s' "$acc"
}

# eDRX cycle in hyperframes, TS 36.304 §7.3. TeDRX,H is 1..256 H-SFNs
# (2..1024 for NB-IoT); 1 hyperframe is 1024 radio frames.
lair_edrx_cycle_hsfn() {
    case "${1:-}" in
        512)     echo 1  ;; 1024)    echo 1  ;; # 512 radio frames is not eDRX per 7.3
        *)
            [[ "$1" =~ ^[0-9]+$ ]] || return 1
            # TeDRX in radio frames -> hyperframes, rounded up to a whole HF.
            printf '%s' $(( ($1 + 1023) / 1024 ))
            ;;
    esac
}

lair_edrx_report() {
    local edrx="${1:-}" ptw_ms="${2:-}" ue_id="${3:-0}" drx="${4:-32}"
    local te_ms te_hsfn PT pt_l
    [[ "$edrx" =~ ^[0-9]+$ ]] && (( edrx > 0 )) || {
        printf 'ERROR\t--edrx needs a cycle in milliseconds: %s\n' "$(lair_sanitize "$edrx")" >&2; return 2; }

    # The 512-radio-frame eDRX value is the special case in §7.3: it is NOT
    # an H-SFN window, it simply sets T = 512 and the ordinary §7.1 rule
    # applies. Treating it as a window would suppress every PO.
    if (( edrx == 5120 )); then :; fi
    te_hsfn=$(( (edrx + 1023) / 1024 ))
    (( te_hsfn >= 1 )) || te_hsfn=1

    # PTW length: the caller gives milliseconds; §7.3 works in seconds.
    : "${ptw_ms:=1280}"
    [[ "$ptw_ms" =~ ^[0-9]+$ ]] || { printf 'ERROR\t--ptw needs milliseconds\n' >&2; return 2; }
    pt_l=$(( ptw_ms / 1000 )); (( pt_l < 1 )) && pt_l=1

    # UE_ID_H is the 10 MSBs of the Hashed ID. Absent a Hashed ID the caller
    # supplies the ue-id, and its low 10 bits stand in — report the choice.
    local ue_id_h=$(( ue_id % 1024 ))
    local ph=$(( ue_id_h % te_hsfn ))

    # PTW_start = 256 * ieDRX, ieDRX = floor(UE_ID_H / TeDRX,H) mod 4
    local ie=0
    (( te_hsfn > 0 )) && ie=$(( (ue_id_h / te_hsfn) % 4 ))
    local ptw_start=$(( 256 * ie ))
    local ptw_end=$(( (ptw_start + pt_l * 100 - 1) % 1024 ))

    printf 'edrx_cycle_ms\t%s\n' "$edrx"
    printf 'edrx_cycle_hsfn\t%s\n' "$te_hsfn"
    printf 'ue_id_h\t%s\n' "$ue_id_h"
    printf 'paging_hyperframe_rule\tH-SFN mod %s == %s\n' "$te_hsfn" "$ph"
    printf 'paging_hyperframe\t%s\n' "$ph"
    printf 'ptw_length_s\t%s\n' "$pt_l"
    printf 'ieDRX\t%s\n' "$ie"
    printf 'ptw_start_sfn\t%s\n' "$ptw_start"
    printf 'ptw_end_sfn\t%s\n' "$ptw_end"
    # Inside the PTW the §7.1 PF/PO still applies; outside it the UE is not
    # required to monitor at all, so say which case the caller is looking at.
    printf 'edrx_note\tPF/PO above apply only inside the PTW; outside it the UE need not monitor\n'
    printf 'edrx_ref\t3GPP TS 36.304 7.3 (PH, PTW_start, PTW_end)\n'
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
# TDD UL/DL configuration, TS 36.211 §4.2 table 4.2-2.
#
# The table gives, per configuration 0..6, the subframes carrying downlink
# (D), uplink (U) and the special subframe (S). A generated TDD conf must
# name the configuration that matches the cell's actual frame structure --
# srsRAN defaults to 0 otherwise, which is a valid configuration but not
# the one an operator's cell uses, so a UE that reads the operator's SIB1
# will not find this eNB's subframe 5.
#
# Configuration 1 is the usual choice for a band 41 macro cell and is what
# the default below emits; config 2 is the 3:1 high-throughput pattern.
lair_tdd_config_valid() {
    case "${1:-}" in 0|1|2|3|4|5|6) return 0 ;; *) return 1 ;; esac
}

# Special subframe configuration, TS 36.211 table 4.2-1. Only 0..9 are
# relevant to normal cyclic prefix; the generator accepts the whole range
# and refuses anything else rather than emitting a value srsRAN rejects.
lair_tdd_sscfg_valid() {
    [[ "${1:-}" =~ ^[0-9]+$ ]] && (( $1 >= 0 && $1 <= 9 ))
}

lair_tdd_pattern() {
    case "${1:-}" in
        0) echo "D S U U U D S U U U" ;;
        1) echo "D S U U D D S U U D" ;;
        2) echo "D S U D D D S U D D" ;;
        3) echo "D S U U U D D D D D" ;;
        4) echo "D S U U D D D D D D" ;;
        5) echo "D S U D D D D D D D" ;;
        6) echo "D S U U U D S U U D" ;;
        *) return 1 ;;
    esac
}

# ── enb.conf generation ─────────────────────────────────────────────────
#
# The generated file hard-coded `tm = 1` (FDD) for every band. Bands
# 38/40/41/42/43 are TDD and appear in this module's own LAIR_BANDS, so a
# generated conf for one of them started an eNB in the wrong duplex that
# could not transmit. The duplex is now derived from the band, with --tdd
# and --fdd to override, and a TDD conf carries tdd_ul_dl_config.
lair_gen_enb_conf() {
    local earfcn="" mcc="001" mnc="01" tac="1" cellid="1" pci="1" \
          n_prb="25" tx_gain="70" rx_gain="40" out="$LAIR_CONF" \
          duplex="" tdd_cfg="1" tdd_sscfg="7"
    # Positional form is still accepted for the first ten arguments so the
    # existing CLI call sites and the existing selftest keep working; the
    # named form below is what --tdd and the other new options use.
    local positional=()
    while (( $# > 0 )); do
        case "$1" in
            --tdd)   duplex=tdd; shift ;;
            --fdd)   duplex=fdd; shift ;;
            --tdd-config)  tdd_cfg="${2:-}";  shift 2 ;;
            --tdd-sscfg)   tdd_sscfg="${2:-}"; shift 2 ;;
            --out)   out="${2:-}"; shift 2 ;;
            --n-prb) n_prb="${2:-}"; shift 2 ;;
            --pci)   pci="${2:-}"; shift 2 ;;
            --tac)   tac="${2:-}"; shift 2 ;;
            --cellid) cellid="${2:-}"; shift 2 ;;
            --mcc)   mcc="${2:-}"; shift 2 ;;
            --mnc)   mnc="${2:-}"; shift 2 ;;
            --tx-gain) tx_gain="${2:-}"; shift 2 ;;
            --rx-gain) rx_gain="${2:-}"; shift 2 ;;
            --earfcn) earfcn="${2:-}"; shift 2 ;;
            -*) printf 'ERROR\t--gen-enb-conf: unknown option %s\n' "$(lair_sanitize "$1")" >&2; return 2 ;;
            *) positional+=("$1"); shift ;;
        esac
    done
    if (( ${#positional[@]} > 0 )); then
        earfcn="${positional[0]:-}"; mcc="${positional[1]:-$mcc}"
        mnc="${positional[2]:-$mnc}"; tac="${positional[3]:-$tac}"
        cellid="${positional[4]:-$cellid}"; pci="${positional[5]:-$pci}"
        n_prb="${positional[6]:-$n_prb}"; tx_gain="${positional[7]:-$tx_gain}"
        rx_gain="${positional[8]:-$rx_gain}"; out="${positional[9]:-$out}"
    fi
    : "${earfcn:=6300}"

    [[ "$earfcn" =~ ^[0-9]+$ ]] || { printf 'ERROR\tearfcn must be numeric\n' >&2; return 2; }
    [[ "$mcc" =~ ^[0-9]{3}$ ]]    || { printf 'ERROR\tMCC must be 3 digits\n' >&2; return 2; }
    [[ "$mnc" =~ ^[0-9]{2,3}$ ]]  || { printf 'ERROR\tMNC must be 2 or 3 digits\n' >&2; return 2; }
    case "$n_prb" in 6|15|25|50|75|100) ;; *) printf 'ERROR\tn_prb must be 6/15/25/50/75/100\n' >&2; return 2 ;; esac
    lair_tdd_config_valid "$tdd_cfg" || { printf 'ERROR\t--tdd-config must be 0..6 (TS 36.211 table 4.2-2)\n' >&2; return 2; }
    lair_tdd_sscfg_valid  "$tdd_sscfg" || { printf 'ERROR\t--tdd-sscfg must be 0..9 (TS 36.211 table 4.2-1)\n' >&2; return 2; }

    local band; band=$(lair_band_of_earfcn "$earfcn") || band="?"
    local dl; dl=$(lair_earfcn_to_mhz "$earfcn") || dl="?"
    if [[ -z "$duplex" ]]; then
        duplex=$(lair_band_duplex "$band") || duplex=unknown
        # An EARFCN outside LAIR_BANDS cannot be classified. FDD is the
        # conservative default for the "?" band, but it is stated in the
        # file rather than left implicit.
        [[ "$duplex" == "unknown" ]] && duplex=fdd
    fi
    case "$duplex" in tdd|fdd) ;; *) printf 'ERROR\tduplex must be tdd or fdd\n' >&2; return 2 ;; esac

    # tm: 1 = FDD transmission mode, 2 = TDD. srsRAN keys the frame
    # structure off tm, so a TDD band with tm = 1 never transmits.
    local tm=1 tdd_block=""
    if [[ "$duplex" == "tdd" ]]; then
        tm=2
        tdd_block=$(printf 'tdd_ul_dl_config = %s\ntdd_special_subframe_cfg = %s' \
                            "$tdd_cfg" "$tdd_sscfg")
    fi

    mkdir -p "$(dirname "$out")" || { printf 'ERROR\tcannot create %s\n' "$(dirname "$out")" >&2; return 1; }
    {
        cat <<EOF
# srsRAN eNB configuration — generated by IMSIsting 10_lte_air.sh (lair)
# EARFCN ${earfcn} (band ${band}, DL ${dl} MHz, duplex ${duplex}), PLMN ${mcc}-${mnc}, TAC ${tac}
[enb]
enb_id = 0x1A2D
mme_addr = 127.0.1.100
gtp_bind_addr = 127.0.1.1
s1c_bind_addr = 127.0.1.1
n_prb = ${n_prb}
tm = ${tm}
EOF
        [[ -n "$tdd_block" ]] && printf '%s\n' "$tdd_block"
        cat <<EOF

[rf]
device_name = auto
device_args = auto
tx_gain = ${tx_gain}
rx_gain = ${rx_gain}
dl_earfcn = ${earfcn}

[expert]
lte_sample_rate = 1.92e6
EOF
    } > "$out" || { printf 'ERROR\tcannot write %s\n' "$out" >&2; return 1; }
    [[ -f "$out" ]] || { printf 'ERROR\tenb.conf not written to %s\n' "$out" >&2; return 1; }
    printf 'OK\t%s\n' "$out"
    printf 'OK\tearfcn=%s band=%s duplex=%s tm=%s\n' "$earfcn" "$band" "$duplex" "$tm"
    if [[ "$duplex" == "tdd" ]]; then
        printf 'OK\ttdd_ul_dl_config=%s tdd_special_subframe_cfg=%s pattern=%s\n' \
               "$tdd_cfg" "$tdd_sscfg" "$(lair_tdd_pattern "$tdd_cfg")"
    fi
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
# srsRAN radio resource configuration — generated by IMSIsting 10_lte_air.sh (lair)
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
    [[ -n "$hex" ]] || { printf 'ERROR\tusage: --decode-sib <hex> [1..13]\n' >&2; return 2; }
    lair_decode_sib "$hex" "$sibtype"
}

lair_cmd_decode_mib() {
    local hex="${1:-}"
    [[ -n "$hex" ]] || { printf 'ERROR\tusage: --decode-mib <24-bit hex>\n' >&2; return 2; }
    lair_decode_mib "$hex"
}

lair_cmd_paging_frame() {
    # Everything after the five positional arguments is passed through, so
    # --edrx / --ptw / --tdd / --fdd / --earfcn survive to the worker.
    local imsi="${1:-}" tac="${2:-}" ue="${3:-}" drx="${4:-}" nb="${5:-}"
    [[ -n "$imsi" && -n "$tac" ]] || {
        printf 'ERROR\tusage: --paging-frame <imsi> <tac> <ue-id> [T] [nB] [--edrx <ms>] [--ptw <ms>] [--tdd|--fdd|--earfcn <N>]\n' >&2
        return 2
    }
    if (( $# >= 5 )); then shift 5; else shift $#; fi
    lair_paging_frame "$imsi" "$tac" "$ue" "$drx" "$nb" "$@"
}

lair_cmd_gen_enb_conf() {
    # Named options (--tdd, --earfcn, ...) are forwarded untouched; the
    # historical positional form still works, and both produce the same two
    # files, so an existing caller is unaffected.
    local args=("$@") earfcn="" mcc="" mnc="" tac="1" cellid="1" pci="1"
    local i=0 a
    # Peek at the first five positional slots for the rr.conf arguments.
    local pos=()
    for a in "$@"; do
        case "$a" in --*) ;; *) pos+=("$a") ;; esac
    done
    earfcn="${pos[0]:-6300}"; mcc="${pos[1]:-001}"; mnc="${pos[2]:-01}"
    tac="${pos[3]:-1}"; cellid="${pos[4]:-1}"; pci="${pos[5]:-1}"
    [[ "$earfcn" =~ ^[0-9]+$ ]] || { printf 'ERROR\tearfcn must be numeric: %s\n' "$(lair_sanitize "$earfcn")" >&2; return 2; }

    : "${mcc:=001}"; : "${mnc:=01}"
    [[ "$mcc" =~ ^[0-9]{3}$ ]]   || { printf 'ERROR\tMCC must be 3 digits\n' >&2; return 2; }
    [[ "$mnc" =~ ^[0-9]{2,3}$ ]] || { printf 'ERROR\tMNC must be 2 or 3 digits\n' >&2; return 2; }

    if (( ${#args[@]} == 0 )); then
        lair_gen_enb_conf || return 1
    else
        lair_gen_enb_conf "${args[@]}" --out "$LAIR_CONF" || return 1
    fi
    lair_gen_rr_conf "$mcc" "$mnc" "$tac" "$cellid" "$pci" "$earfcn" "$LAIR_RRC" || return 1
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
    # The whole line, not just field 2: the SIB6/SIB7 carrier and info rows
    # carry their values in later fields, so `fld` would only return the tag.
    fline() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print; exit}'; }

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

    # A real SIB1, captured from pycrate 0.8.1 (an independent TS 36.331
    # unaligned-PER implementation): PLMN 208-01, TAC 1, cellIdentity 1.
    # Note there is no "body" here -- SIB1 is not octet aligned, so the
    # whole BCCH-DL-SCH message is what gets passed in.
    out=$(lair_decode_sib1 "4048200300010000001C0130208280")
    chk sib1-mcc      "$(fld "$out" mcc)" "208"
    chk sib1-mnc      "$(fld "$out" mnc)" "01"
    chk sib1-mnc-digits "$(fld "$out" mnc_digits)" "2"
    chk sib1-plmn     "$(fld "$out" plmn)" "208-01"
    chk sib1-operator "$(fld "$out" operator)" "Orange FR"
    chk sib1-tac      "$(fld "$out" tracking_area_code)" "1"
    chk sib1-cellid   "$(fld "$out" cell_identity)" "1"
    chk sib1-band     "$(fld "$out" freq_band_indicator)" "20"
    chk sib1-bits     "$(fld "$out" bits)" "118"

    # The same message with TAC 0x1234 = 4660 and cellIdentity 0x0ABCDEF.
    out=$(lair_decode_sib1 "4048200312340ABCDEFC0130208280")
    chk sib1b-tac    "$(fld "$out" tracking_area_code)" "4660"
    chk sib1b-cellid "$(fld "$out" cell_identity)" "11259375"
    chk sib1b-cid-hex "$(fld "$out" cell_identity_hex)" "0abcdef"

    # 262-01 (a real PLMN), TAC 0x00F1, cellIdentity 0x00A1.
    out=$(lair_decode_sib1 "4049880300F100000A1C0130208280")
    chk sib1c-plmn    "$(fld "$out" plmn)" "262-01"
    chk sib1c-tac     "$(fld "$out" tracking_area_code)" "241"
    chk sib1c-cellid  "$(fld "$out" cell_identity)" "161"

    # A 3-digit MNC: 208-015.
    out=$(lair_decode_sib1 "40482202B00010000001C01302082800")
    chk sib1-3mnc-digits "$(fld "$out" mnc_digits)" "3"
    chk sib1-3mnc        "$(fld "$out" mnc)" "015"

    # Barred cell, band 13, longer SI window and period.
    out=$(lair_decode_sib1 "404C424C11A2B1234567018C0310038E")
    chk sib1-barred   "$(fld "$out" cell_barred)" "barred"
    chk sib1-band13   "$(fld "$out" freq_band_indicator)" "13"
    chk sib1-siw40    "$(fld "$out" si_window_length)" "ms40"

    # The decoder reports its layout, so a caller can tell which one it got.
    chk sib1-layout "$(fld "$out" layout)" "TS 36.331 unaligned PER (tools/lte_asn1.py)"

    # A decoder that accepts anything is not a decoder: noise, and a
    # BitReader fed a hex string of only 0/1 digits, must both be refused
    # rather than reported as a cell.
    out=$(lair_decode_sib1 "0011223344556677889900AABBCCDD" 2>/dev/null; echo "rc=$?")
    chk sib1-reject-noise "$(printf '%s\n' "$out" | tail -1)" "rc=1"

    chk sib1-bad-hex   "$(lair_decode_sib1 zz >/dev/null 2>&1; echo $?)" "1"
    chk sib1-odd-hex   "$(lair_decode_sib1 02F >/dev/null 2>&1; echo $?)" "1"
    chk sib1-short     "$(lair_decode_sib1 02F8 >/dev/null 2>&1; echo $?)" "1"
    chk sib1-missing   "$(lair_cmd_decode_sib >/dev/null 2>&1; echo $?)" "2"
    # The type has to be one that does not exist. This used to say 9, which
    # was out of range when only SIB1-SIB8 were decoded and is now a real
    # decoder -- the fixture then tested nothing.
    chk sib-bad-type   "$(lair_decode_sib 02F81012340ABCDEF 14 >/dev/null 2>&1; echo $?)" "2"
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

    # ── SIB2 ────────────────────────────────────────────────────────────
    # SIB2 now goes through the same real codec as SIB1 and SIB3. These are
    # captured pycrate 0.8.1 containers, not values read back out of this
    # tree's own encoder. The body is 186 bits and is zero-padded to whole
    # octets, so no field is octet aligned -- which is exactly what the
    # parser that used to stand here got wrong.
    out=$(lair_decode_sib2 "00000000000000000000000000000000100000000000000000")
    chk sib2-default-bits "$(fld "$out" bits)" "186"
    chk sib2-default-ra   "$(fld "$out" number_of_ra_preambles)" "n4"
    chk sib2-default-root "$(fld "$out" root_sequence_index)" "0"
    chk sib2-default-qam  "$(fld "$out" enable64qam)" "0"
    chk sib2-default-srs  "$(fld "$out" sounding_rs_setup)" "1"
    chk sib2-default-cf   "$(fld "$out" ul_carrier_freq)" "absent"

    # rootSequenceIndex 22, prach-ConfigIndex 3, highSpeedFlag,
    # zeroCorrelationZoneConfig 12, prach-FreqOffset 4.
    out=$(lair_decode_sib2 "0000000000000160F810000000000000100000000000000000")
    chk sib2-prach-root "$(fld "$out" root_sequence_index)" "22"
    chk sib2-prach-idx  "$(fld "$out" prach_config_index)" "3"
    chk sib2-prach-hs   "$(fld "$out" high_speed_flag)" "1"
    chk sib2-prach-zone "$(fld "$out" zero_correlation_zone_config)" "12"
    chk sib2-prach-off  "$(fld "$out" prach_freq_offset)" "4"

    # referenceSignalPower 15, p-b 1, p0-NominalPUSCH -90, alpha al1,
    # p0-NominalPUCCH -112, deltaPreambleMsg3 0.
    out=$(lair_decode_sib2 "000000A80000000000025A0000000000100127780040000000")
    chk sib2-power-rs      "$(fld "$out" reference_signal_power)" "15"
    chk sib2-power-pb      "$(fld "$out" p_b)" "1"
    chk sib2-power-p0pusch "$(fld "$out" p0_nominal_pusch)" "-90"
    chk sib2-power-alpha   "$(fld "$out" alpha)" "al1"

    # This is the only vector carrying the freqInfo OPTIONALs, so it is the
    # only one whose body is not 186 bits -- and the only one that proves the
    # OPTIONAL bitmap is read rather than skipped.
    out=$(lair_decode_sib2 "00000000000000000000000000000000100000000000000309154000")
    chk sib2-ulcarrier-bits "$(fld "$out" bits)" "205"
    chk sib2-ulcarrier-freq "$(fld "$out" ul_carrier_freq)" "2325"
    chk sib2-ulcarrier-bw   "$(fld "$out" ul_bandwidth)" "n25"

    # A body this codec does not model must refuse rather than report fields
    # read from the wrong offsets.
    chk sib2-short "$(lair_decode_sib2 14000000 >/dev/null 2>&1; echo $?)" "1"

    # ── 5. SIB3 / SIB5 ──────────────────────────────────────────────────
    # SIB3 now goes through the real TS 36.331 unaligned-PER codec in
    # tools/lte_asn1.py, so these are captured pycrate vectors, not values
    # read back out of this tree's own encoder. The body is 31 bits and is
    # zero-padded to octets; the offsets are not octet aligned.
    #   "maxed": q-Hyst dB24, threshServingLow 31, priority 7,
    #            q-RxLevMin -22, presenceAntennaPort1, neigh 11, t-Resel 7
    out=$(lair_decode_sib3 "0004F7F861F8")
    chk sib3-max-qh      "$(fld "$out" q_hyst)" "dB24"
    chk sib3-max-thresh  "$(fld "$out" thresh_serving_low)" "31"
    chk sib3-max-prio    "$(fld "$out" cell_reselection_priority)" "7"
    chk sib3-max-qrx     "$(fld "$out" q_rx_lev_min)" "-22"
    chk sib3-max-ant     "$(fld "$out" presence_antenna_port1)" "1"
    chk sib3-max-neigh   "$(fld "$out" neigh_cell_config)" "11"
    chk sib3-max-tresel  "$(fld "$out" t_reselection_eutra)" "7"
    chk sib3-max-bits    "$(fld "$out" bits)" "31"
    chk sib3-max-layout  "$(fld "$out" layout)" \
        "TS 36.331 unaligned PER (tools/lte_asn1.py)"
    # "mid" is a value no wrong field boundary can fake: q-Hyst dB6 = 6,
    # threshServingLow 5, priority 3, q-RxLevMin -45 (index 25), neigh 01,
    # t-ReselectionEUTRA 2.
    out=$(lair_decode_sib3 "000461583250")
    chk sib3-mid-qh     "$(fld "$out" q_hyst)" "dB6"
    chk sib3-mid-thresh "$(fld "$out" thresh_serving_low)" "5"
    chk sib3-mid-prio   "$(fld "$out" cell_reselection_priority)" "3"
    chk sib3-mid-qrx    "$(fld "$out" q_rx_lev_min)" "-45"
    chk sib3-mid-neigh  "$(fld "$out" neigh_cell_config)" "01"
    chk sib3-mid-tresel "$(fld "$out" t_reselection_eutra)" "2"
    # The floor of q-RxLevMin is -70, not an index.
    out=$(lair_decode_sib3 "000400000000")
    chk sib3-min-qrx    "$(fld "$out" q_rx_lev_min)" "-70"
    chk sib3-min-ant    "$(fld "$out" presence_antenna_port1)" "0"
    # The old parser's fixture is 16 bits: it must be refused, not guessed at.
    # The body is 31 bits now, so the fixture has to be shorter than that --
    # a 32-bit input would truncate to a whole valid body and pass.
    chk sib3-short "$(lair_decode_sib3 1400 >/dev/null 2>&1; echo $?)" "1"

    # SIB5. 52 bits: one carrier, every optional absent, q-RxLevMin at its
    # floor. This is what a real SIB5 with nothing configured looks like, and
    # the old reader -- which reported 16-bit words as neighbour EARFCNs --
    # would have called the three words here neighbours 0, 0 and 0.
    out=$(lair_decode_sib5 "00000000000000")
    chk sib5-empty-rc     "$?" "0"
    chk sib5-empty-count  "$(fld "$out" carrier_count)" "1"
    chk sib5-empty-bits   "$(fld "$out" bits)" "52"
    chk sib5-empty-dl     "$(printf '%s\n' "$out" | grep '^carrier' | grep -o 'dl_carrier_freq=[0-9-]*')" "dl_carrier_freq=0"
    chk sib5-empty-qrx    "$(printf '%s\n' "$out" | grep '^carrier' | grep -o 'q_rx_lev_min=[0-9-]*')" "q_rx_lev_min=-70"
    chk sib5-empty-neigh  "$(printf '%s\n' "$out" | grep -c '^neighbour_cell')" "0"

    # Every optional field present at once, with both lists populated. 130
    # bits. The two neighbour entries are 14 bits each -- physCellId 42 and
    # 503, q-OffsetCell dB6 and dB-24. SIB4's equivalent entry is 15 bits;
    # this fixture is what pins the difference.
    out=$(lair_decode_sib5 "07E09A587FDFFFBB4C4555FB8066414B00")
    chk sib5-full-rc      "$?" "0"
    chk sib5-full-bits    "$(fld "$out" bits)" "130"
    chk sib5-full-dl      "$(printf '%s\n' "$out" | grep '^carrier' | grep -o 'dl_carrier_freq=[0-9]*')" "dl_carrier_freq=1234"
    chk sib5-full-pmax    "$(printf '%s\n' "$out" | grep '^carrier' | grep -o 'p_max=[0-9-]*')" "p_max=33"
    chk sib5-full-ambw    "$(printf '%s\n' "$out" | grep '^carrier' | grep -o 'ambw=[a-z0-9]*')" "ambw=mbw100"
    chk sib5-full-prio    "$(printf '%s\n' "$out" | grep '^carrier' | grep -o 'prio=[0-9]*')" "prio=5"
    chk sib5-full-qoff    "$(printf '%s\n' "$out" | grep '^carrier' | grep -o 'q_offset_freq=[a-zA-Z0-9-]*')" "q_offset_freq=dB4"
    chk sib5-full-neigh   "$(printf '%s\n' "$out" | grep -c '^neighbour_cell')" "2"
    chk sib5-full-n0      "$(printf '%s\n' "$out" | grep '^neighbour_cell' | sed -n 1p | cut -f2-)" "0	42	dB6"
    chk sib5-full-n1      "$(printf '%s\n' "$out" | grep '^neighbour_cell' | sed -n 2p | cut -f2-)" "0	503	dB-24"
    chk sib5-full-excl    "$(printf '%s\n' "$out" | grep -c '^excluded_cell')" "2"
    chk sib5-full-e0      "$(printf '%s\n' "$out" | grep '^excluded_cell' | sed -n 1p | cut -f2-)" "0	100	n8"
    # The second excluded cell carries no range field. It must read as "-",
    # not as n4 -- the ENUM's zero value is a real range, not an absence.
    chk sib5-full-e1      "$(printf '%s\n' "$out" | grep '^excluded_cell' | sed -n 2p | cut -f2-)" "0	300	-"

    # Two carriers: 52 + 48 = 100 bits of content, 106 real. The second
    # carrier's p-Max is set and the first's is not, so the 48-bit stride is
    # what puts it on the right carrier.
    out=$(lair_decode_sib5 "10000C8500000400190A6A000000")
    chk sib5-two-count    "$(fld "$out" carrier_count)" "2"
    chk sib5-two-bits     "$(fld "$out" bits)" "106"
    chk sib5-two-c0       "$(printf '%s\n' "$out" | awk -F'\t' '$1=="carrier"' | sed -n 1p | cut -f3-)" "dl_carrier_freq=100	q_rx_lev_min=-60	p_max=-	thresh_x_high=0	thresh_x_low=0	ambw=mbw6	antport1=0	neigh_cell_config=00	t_reselection_eutra=0	prio=-	q_offset_freq=-"
    chk sib5-two-c1       "$(printf '%s\n' "$out" | awk -F'\t' '$1=="carrier"' | sed -n 2p | cut -f3-)" "dl_carrier_freq=200	q_rx_lev_min=-50	p_max=23	thresh_x_high=0	thresh_x_low=0	ambw=mbw6	antport1=0	neigh_cell_config=00	t_reselection_eutra=0	prio=-	q_offset_freq=-"

    # The same carrier set inside a whole SystemInformation container. The
    # container reading is tried first and wins, and because the bare-body
    # reading also happens to parse the module says so rather than choosing
    # silently.
    out=$(lair_decode_sib5 "000C1F826961FF7FFEED311557EE0199052C")
    chk sib5-cont-rc      "$?" "0"
    chk sib5-cont-dl      "$(printf '%s\n' "$out" | grep '^carrier' | grep -o 'dl_carrier_freq=[0-9]*')" "dl_carrier_freq=1234"
    chk sib5-cont-neigh   "$(printf '%s\n' "$out" | grep -c '^neighbour_cell')" "2"
    chk sib5-cont-ambig   "$(printf '%s\n' "$out" | grep -c '^ambiguous')" "3"

    # A bare body must NOT be reported as ambiguous on its own account: the
    # reading that succeeded was the body, so there is nothing to warn about.
    chk sib5-empty-noamb  "$(printf '%s\n' "$(lair_decode_sib5 00000000000000)" | grep -c '^ambiguous')" "0"

    chk sib5-short        "$(lair_decode_sib5 AB >/dev/null 2>&1; echo $?)" "1"
    chk sib5-nonhex       "$(lair_decode_sib5 ZZZZ >/dev/null 2>&1; echo $?)" "1"
    chk sib5-empty-arg    "$(lair_decode_sib5 "" >/dev/null 2>&1; echo $?)" "2"

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

    # ── 13. MIB, TS 36.331 §6.2.2 — known-answer from a hand-built payload ─
    #
    # MasterInformationBlock ::= SEQUENCE {
    #     dl-Bandwidth    ENUMERATED {n6,n15,n25,n50,n75,n100},  -- 3 bits
    #     phich-Config SEQUENCE {
    #         phich-Duration ENUMERATED {normal, extended},      -- 1 bit
    #         phich-Resource ENUMERATED {oneSixth,half,one,two}  -- 2 bits
    #     },
    #     systemFrameNumber BIT STRING (SIZE (8)),
    #     spare             BIT STRING (SIZE (10)) }
    #
    # Hand computation of the first vector, 416800:
    #   dl-Bandwidth = n25  -> enumeration index 2          -> 010
    #   phich-Duration = normal -> 0                        -> 0
    #   phich-Resource = oneSixth -> 0                      -> 00
    #   systemFrameNumber = 0x5A = 90                       -> 01011010
    #   spare = 0                                           -> 0000000000
    #   concatenated: 010 0 00 01011010 0000000000
    #               = 01000010 01101000 00000000
    #               = 0x42 0x68 0x00  = "416800"   (3+1+2+8+10 = 24 bits)
    out=$(lair_decode_mib 416800); rc=$?
    chk mib-rc        "$rc" "0"
    chk mib-bw        "$(fld "$out" dl_bandwidth)" "n25"
    chk mib-bw-idx    "$(fld "$out" dl_bandwidth_index)" "2"
    chk mib-bw-prb    "$(fld "$out" dl_bandwidth_prb)" "25"
    chk mib-dur       "$(fld "$out" phich_duration)" "normal"
    chk mib-res       "$(fld "$out" phich_resource)" "oneSixth"
    chk mib-sfn       "$(fld "$out" system_frame_number)" "90"
    chk mib-spare     "$(fld "$out" spare)" "0"
    chk mib-bits      "$(fld "$out" payload_bits)" "24"
    # Second vector, hand-computed the same way: dl-Bandwidth = n100 is
    # index 5 -> 101; phich-Duration = extended -> 1; phich-Resource = two
    # -> 3 -> 11; SFN = 0xFF -> 11111111; spare all ones.
    #   101 1 11 11111111 1111111111
    # = 10111111 11111111 11000000 = 0xBFFC00
    out=$(lair_decode_mib BFFC00)
    chk mib2-bw    "$(fld "$out" dl_bandwidth)" "n100"
    chk mib2-prb   "$(fld "$out" dl_bandwidth_prb)" "100"
    chk mib2-dur   "$(fld "$out" phich_duration)" "extended"
    chk mib2-res   "$(fld "$out" phich_resource)" "two"
    chk mib2-sfn   "$(fld "$out" system_frame_number)" "255"
    # dl-Bandwidth index 6 and 7 are outside the ASN.1 enumeration.
    chk mib-bad-idx "$(out=$(lair_decode_mib C16800); fld "$out" dl_bandwidth)" "reserved"
    # A wrong width is an error, not a silent truncation.
    chk mib-short   "$(lair_decode_mib 4168 >/dev/null 2>&1; echo $?)" "1"
    chk mib-long    "$(lair_decode_mib 41680099 >/dev/null 2>&1; echo $?)" "1"
    chk mib-nonhex  "$(lair_decode_mib ZZZZZZ >/dev/null 2>&1; echo $?)" "1"
    chk mib-empty   "$(lair_decode_mib >/dev/null 2>&1; echo $?)" "2"

    # ── 14. SIB4 — TS 36.331 §6.3.1 SystemInformationBlockType4 ────────
    #
    # SIB4 is decoded by the real unaligned-PER codec. These fixtures are
    # pycrate 0.8.1 captures, so they pin the field order, the optionals and
    # the per-cell extension bit against something outside this tree.
    # `0009C42AA80E0199072CDB2000` carries every OPTIONAL at once:
    # two neighbour cells, two excluded ranges and a CSG range.
    out=$(lair_decode_sib 0009C42AA80E0199072CDB2000 4); rc=$?
    chk sib4-rc        "$rc" "0"
    chk sib4-neigh     "$(fld "$out" neigh_count)" "2"
    chk sib4-excluded  "$(fld "$out" excluded_count)" "2"
    chk sib4-csg       "$(fld "$out" csg_phys_cell_id_range)" "200:n4"
    # Point INSIDE each list, not only at the first entry: the second one is
    # what catches a wrong element stride (15 bits, not 14).
    chk sib4-neigh0    "$(printf '%s\n' "$out" | awk -F'\t' '$1=="neigh"{print $2":"$3}' | sed -n 1p)" "42:dB6"
    chk sib4-neigh1    "$(printf '%s\n' "$out" | awk -F'\t' '$1=="neigh"{print $2":"$3}' | sed -n 2p)" "7:dB-24"
    chk sib4-excl0     "$(printf '%s\n' "$out" | awk -F'\t' '$1=="excluded"{print $2":"$3}' | sed -n 1p)" "100:n8"
    chk sib4-excl1     "$(printf '%s\n' "$out" | awk -F'\t' '$1=="excluded"{print $2":"$3}' | sed -n 2p)" "300:n504"
    chk sib4-bits      "$(fld "$out" bits)" "84"
    # The empty body is four bits: extension bit plus three absent OPTIONALs.
    out=$(lair_decode_sib 000800 4); rc=$?
    chk sib4-empty-rc  "$rc" "0"
    chk sib4-empty-n   "$(fld "$out" neigh_count)" "0"
    chk sib4-empty-bits "$(fld "$out" bits)" "4"
    # An extension bit this codec does not model must be refused, not read as
    # fields: every neighbour cell after the first would move. The one changed
    # nibble is the SIB4 body's bit 0 -- the header's choice index ends in the
    # same nibble, so this also pins where the header stops.
    chk sib4-reject    "$(lair_decode_sib 000bC42AA80E0199072CDB2000 4 >/dev/null 2>&1; echo $?)" "1"
    chk sib4-reject-body "$(lair_decode_sib 80000000 4 >/dev/null 2>&1; echo $?)" "1"
    chk sib4-short     "$(lair_decode_sib AB 4 >/dev/null 2>&1; echo $?)" "1"
    chk sib4-nonhex    "$(lair_decode_sib ZZZZZZ 4 >/dev/null 2>&1; echo $?)" "1"

    # ── 15. SIB6 / SIB7 — UTRA and GERAN reselection, TS 36.331 §6.3.1 ──
    #
    # SIB6 is NOT ETWS and SIB7 is NOT CMAS. SIB6 carries the UTRA
    # carrier-frequency list and SIB7 the GERAN one, both for reselection;
    # ETWS is SIB10/SIB11 and CMAS is SIB12, and all three of those are still
    # on the private octet-aligned layout this module admits to. What stood
    # here before read messageIdentifier and serialNumber out of SIB6 and
    # SIB7 -- fields those two messages do not contain -- so every value it
    # printed came from the wrong octets.
    #
    # Every vector below was captured from pycrate 0.8.1, using the true UPER
    # bit length from _to_per() rather than the octet-padded to_uper(), so the
    # expected values come from an independent ASN.1 toolchain and not from
    # this tree's own encoder. The hex is zero-padded to whole octets; the
    # bit counts asserted are what the codec actually consumed.
    #   sib6-bare  "00" 7 bits: t-ReselectionUTRA 0, no carrier list at all
    #   sib6-fdd   58 bits: one CarrierFreqUTRA-FDD (carrierFreq 5, priority 4,
    #              threshX-High 2, threshX-Low 1, q-RxLevMin -40, p-MaxUTRA 10,
    #              q-QualMin -10) with t-ReselectionUTRA 3
    #   sib6-tdd   50 bits: one CarrierFreqUTRA-TDD (carrierFreq 200,
    #              threshX-High 0, threshX-Low 0, q-RxLevMin -50, p-MaxUTRA 0).
    #              TDD carriers carry no q-QualMin; that absence is asserted.
    #   sib7-bare  "00" 6 bits: t-ReselectionGERAN 0
    #   sib7-exp   98 bits: t-ReselectionGERAN 5 + t-ReselectionGERAN-SF
    #              lDot0:oDot25 + one entry whose followingARFCNs is the
    #              explicit list 1,2,3
    #   sib7-bm    70 bits: one entry whose followingARFCNs is the
    #              variableBitMapOfARFCNs ff0f
    out=$(lair_decode_sib 00 6); rc=$?
    chk sib6-rc        "$rc" "0"
    chk sib6-tresel    "$(fld "$out" t_reselection_utra)" "0"
    chk sib6-bare-bits "$(fld "$out" bits)" "7"

    out=$(lair_decode_sib 404005820A8F1CC0 6); rc=$?
    chk sib6-fdd-rc     "$rc" "0"
    chk sib6-fdd-tag    "$(fld "$out" carrier)" "utra_fdd"
    chk sib6-fdd-bits   "$(fld "$out" bits)" "58"
    chk sib6-fdd-tresel "$(fld "$out" t_reselection_utra)" "3"
    chk sib6-fdd-line   "$(fline "$out" carrier)" \
        "carrier	utra_fdd	0	carrier_freq=5	prio=4	thresh_x_high=2	thresh_x_low=1	q_rx_lev_min=-40	p_max_utra=10	q_qual_min=-10"

    out=$(lair_decode_sib 2000C8000A6400 6); rc=$?
    chk sib6-tdd-rc     "$rc" "0"
    chk sib6-tdd-tag    "$(fld "$out" carrier)" "utra_tdd"
    chk sib6-tdd-bits   "$(fld "$out" bits)" "50"
    # No q-QualMin on a TDD carrier: the field is printed as "-" rather than
    # omitted, so an accidental FDD-shaped read shows up here.
    chk sib6-tdd-qual   "$(fline "$out" carrier | tr '\t' '\n' | tail -1)" \
        "q_qual_min=-"

    out=$(lair_decode_sib 00 7); rc=$?
    chk sib7-rc        "$rc" "0"
    chk sib7-tresel    "$(fld "$out" t_reselection_geran)" "0"
    chk sib7-bare-bits "$(fld "$out" bits)" "6"

    out=$(lair_decode_sib 7700060180201007AAA0C53A40 7); rc=$?
    chk sib7-exp-rc    "$rc" "0"
    chk sib7-exp-bits  "$(fld "$out" bits)" "98"
    chk sib7-exp-tresel "$(fld "$out" t_reselection_geran)" "5"
    chk sib7-exp-sf    "$(fld "$out" t_reselection_geran_sf)" "lDot0:oDot25"
    chk sib7-exp-line  "$(fline "$out" info)" \
        "info	0	start=12	band=dcs1800	following=explicit=1|2|3	prio=2	ncc=10101010	q_rx_lev_min=3	p_max_geran=5	thresh_x_high=7	thresh_x_low=9"

    out=$(lair_decode_sib 2000061FF0F0000000 7); rc=$?
    chk sib7-bm-rc     "$rc" "0"
    chk sib7-bm-bits   "$(fld "$out" bits)" "70"
    chk sib7-bm-follow "$(fline "$out" info | tr '\t' '\n' | sed -n '5p')" \
        "following=bitmap=FF0F"

    # A SIB6 body handed to the SIB7 reader and vice versa must be refused --
    # the two carry different field orders and a wrong-type read produces a
    # confident answer rather than an error.
    chk sib6-as-7-ok   "$(lair_decode_sib 00 7 >/dev/null 2>&1; echo $?)" "0"
    # A whole SystemInformation container carrying sibType6, read as SIB7:
    # the container parses and names a different SIB, so it is refused rather
    # than re-read as a bare body assembled from the header's own bits.
    chk sib67-wrong-type \
        "$(lair_decode_sib 001018 7 >/dev/null 2>&1; echo $?)" "1"
    chk sib67-right-type \
        "$(lair_decode_sib 001018 6 >/dev/null 2>&1; echo $?)" "0"
    # An extension bit this codec does not model -- the Release 12 carrier-list
    # extensions -- must be refused, not read as fields.
    chk sib6-ext-reject "$(lair_decode_sib 80 6 >/dev/null 2>&1; echo $?)" "1"
    chk sib7-short      "$(lair_decode_sib 20 7 >/dev/null 2>&1; echo $?)" "1"
    chk sib6-nonhex     "$(lair_decode_sib ZZZZ 6 >/dev/null 2>&1; echo $?)" "1"
    # SystemInformationBlockType8 is CDMA2000 carrier reselection. It is NOT
    # CMAS, and it does NOT carry messageIdentifier, serialNumber or
    # warningType -- those are SIB10 (ETWS primary), SIB11 (ETWS secondary)
    # and SIB12 (CMAS). What stood here asserted exactly those fields out of a
    # SIB8, so the whole block was checking a reader against its own invention.
    #
    # Vectors from pycrate 0.8.1. A bare SIB8 is five bits: the extension bit
    # plus a four-bit presence preamble, with every root field absent. With
    # searchWindowSize = 9 it is nine bits.
    out=$(lair_decode_sib 00 8); rc=$?
    chk sib8-rc       "$rc" "0"
    chk sib8-bare     "$(fld "$out" search_window_size)" "absent"
    chk sib8-bare-bits "$(fld "$out" bits)" "5"
    out=$(lair_decode_sib 2480 8); rc=$?
    chk sib8-win-rc   "$rc" "0"
    chk sib8-win      "$(fld "$out" search_window_size)" "9"
    chk sib8-win-bits "$(fld "$out" bits)" "9"
    # The ext bit set, and each of the three CDMA2000 SEQUENCEs this codec
    # does not model, must be refused rather than half-read.
    # The presence preamble is <ext><systemTimeInfo><searchWindowSize>
    # <parametersHRPD><parameters1XRTT>, so each body below is one bit set:
    # 10000 for the ext bit, 01000 for systemTimeInfo, 00010 for
    # parametersHRPD and 00001 for parameters1XRTT, each padded to two octets.
    chk sib8-ext-reject    "$(lair_decode_sib 8000 8 >/dev/null 2>&1; echo $?)" "1"
    chk sib8-timin-reject  "$(lair_decode_sib 4000 8 >/dev/null 2>&1; echo $?)" "1"
    chk sib8-hrpd-reject   "$(lair_decode_sib 1000 8 >/dev/null 2>&1; echo $?)" "1"
    chk sib8-1xrtt-reject  "$(lair_decode_sib 0800 8 >/dev/null 2>&1; echo $?)" "1"
    chk sib8-nonhex        "$(lair_decode_sib ZZZZ 8 >/dev/null 2>&1; echo $?)" "1"
    # lair_warning_type decodes a SIB10/SIB11 warningType octet pair: the top
    # 2 bits of octet 1 are the class, its low 6 the category. No SIB10 reader
    # exists yet, so nothing calls it in anger and it is checked here directly
    # rather than left as an untested function waiting for one.
    chk wt-earthquake "$(lair_warning_type 0C11)" "class=earthquake category=12 raw=0C11"
    chk wt-tsunami    "$(lair_warning_type 4011)" "class=tsunami category=0 raw=4011"
    chk wt-reserved2  "$(lair_warning_type 8011)" "class=reserved-2 category=0 raw=8011"
    chk wt-reserved3  "$(lair_warning_type C011)" "class=reserved-3 category=0 raw=C011"
    chk wt-badlen     "$(lair_warning_type 0C >/dev/null 2>&1; echo $?)" "1"
    chk wt-garbage    "$(lair_warning_type ZZZZ >/dev/null 2>&1; echo $?)" "1"

    # ── 16. SIB13 — MBSFN, TS 36.331 §6.3.1 ────────────────────────────
    #
    # MBSFN-AreaInfo: mbsfn-AreaId (8) | non-MBSFNregionLength (3) |
    # notificationIndicator (9) | mcch-RepetitionPeriod (2) |
    # mcch-Offset (4) | mcch-ModificationPeriod (2) | signallingMCS (2) |
    # sf-AllocInfo (6)   = 36 bits per area.
    # SIB13 is no longer read by a private octet-aligned layout; it goes
    # through the generated PER codec, so these fixtures are real encodings
    # made by that codec and cross-checked against pycrate
    # (tools/check-lte-sib-codec.sh). The old hand-built body 0x072010D50
    # tested the delated parser and is not a PER encoding of anything.
    #
    # Two vectors, differing only in sf-AllocInfo, because the interesting
    # assertion is that the FDD legality layer discriminates:
    #   004083000F29D06A8000 -> sf-AllocInfo 010000, subframe 1, legal
    #   00408300000020000000 -> sf-AllocInfo 100000, subframe 0, ILLEGAL in FDD
    local A0="mbsfn-AreaInfoList-r9[0]"
    out=$(lair_decode_sib 004083000F29D06A8000 13); rc=$?
    chk sib13-rc       "$rc" "0"
    chk sib13-aid      "$(fld "$out" "$A0.mbsfn-AreaId-r9")" "7"
    chk sib13-ni       "$(fld "$out" "$A0.notificationIndicator-r9")" "1"
    chk sib13-off      "$(fld "$out" "$A0.mcch-Config-r9.mcch-Offset-r9")" "3"
    chk sib13-rep      "$(fld "$out" "$A0.mcch-Config-r9.mcch-RepetitionPeriod-r9")" "rf64"
    chk sib13-mod      "$(fld "$out" "$A0.mcch-Config-r9.mcch-ModificationPeriod-r9")" "rf1024"
    # non-MBSFNregionLength is an ENUMERATED of s1/s2, so the codec reports the
    # NAME. Asserting the name rather than a symbol count is what keeps a
    # future "helpful" conversion to 2 from passing unnoticed.
    chk sib13-region   "$(fld "$out" "$A0.non-MBSFNregionLength")" "s2"
    chk sib13-mcs      "$(fld "$out" "$A0.mcch-Config-r9.signallingMCS-r9")" "n7"
    chk sib13-sf       "$(fld "$out" "$A0.mcch-Config-r9.sf-AllocInfo-r9")" "0b010000 (6 bits)"
    chk sib13-sf-subs  "$(fld "$out" "$A0.subframes")" "1"
    chk sib13-sf-legal "$(fld "$out" "$A0.illegal_subframes")" ""
    chk sib13-bits     "$(fld "$out" "bits")" "41"
    # The open-type note has to survive to the caller: SIB13 is an extension
    # addition, so 7 of its 48 read bits are octet padding and a reader who is
    # not told that will read the last field as up to 7 bits longer.
    chk sib13-note     "$(printf '%s\n' "$out" | grep -c 'open type, octet padded')" "1"

    out=$(lair_decode_sib 00408300000020000000 13); rc=$?
    chk sib13-illegal-rc "$rc" "0"
    chk sib13-illegal-sf "$(fld "$out" "$A0.subframes")" "0"
    # subframe 0 cannot carry MBSFN in FDD (TS 36.211 6.10.1). If this line
    # goes missing the legality layer has stopped running, and reporting only
    # the raw mask hands back the half that needed no specification.
    # -F, because $A0 ends in [0] and a regex bracket expression would not
    # match the literal text it is meant to find.
    chk sib13-illegal    "$(printf '%s\n' "$out" | grep -cF "$A0.illegal_subframes")" "1"

    # ── 17. Paging, TS 36.304 §7.1/§7.2 — published worked values ──────
    #
    # §7.1 gives, for T = 32, nB = T (so N = 32, Ns = 1) and UE_ID = 277:
    #   PF = (T div N) * (UE_ID mod N) = 1 * (277 mod 32) = 1 * 21 = 21
    #   i_s = floor(277 / 32) mod 1 = 8 mod 1 = 0
    #   §7.2 FDD, Ns = 1, i_s = 0 -> PO subframe 9
    # The IMSI below is 310150123456789; its low digits give UE_ID = 277
    # for the PDCCH modulus of 1024, and 277 is asserted directly too.
    out=$(lair_paging_frame 310150123456789 1 277 32 32); rc=$?
    chk pg-rc     "$rc" "0"
    chk pg-ueid   "$(fld "$out" ue_id)" "277"
    chk pg-mod    "$(fld "$out" ue_id_modulus)" "1024"
    chk pg-N      "$(fld "$out" N)" "32"
    chk pg-Ns     "$(fld "$out" Ns)" "1"
    chk pg-pf     "$(fld "$out" paging_frame)" "21"
    chk pg-is     "$(fld "$out" i_s)" "0"
    chk pg-po     "$(fld "$out" paging_occasion)" "9"
    # The same UE_ID derived from the IMSI must equal the explicit one —
    # this is the assertion that fails if ue-id is parsed and then ignored.
    chk pg-derive "$(out=$(lair_paging_frame 310150123456789 1 "" 32 32); fld "$out" ue_id)" "277"
    # UE_ID differs by modulus: 20000 mod 16384 = 3616 for MPDCCH, but
    # 20000 mod 1024 = 544 for PDCCH. Landing on different PFs is the point.
    chk pg-mpdcch-mod "$(out=$(lair_paging_frame 310150123456789 1 20000 32 32 --mpdcch); fld "$out" ue_id)" "3616"
    chk pg-pdcch-mod  "$(out=$(lair_paging_frame 310150123456789 1 20000 32 32 --pdcch); fld "$out" ue_id)" "544"
    # Ns = 4, i_s = 3 is INSIDE the 4-entry table, not at a boundary:
    # §7.2 FDD gives PO 9 and TDD gives PO 6 for the same i_s. Asserting
    # both directions proves the duplex classifier actually fires.
    chk pg-fdd-is3 "$(out=$(lair_paging_frame 310150123456789 1 96 32 128 --fdd); fld "$out" paging_occasion)" "9"
    chk pg-tdd-is3 "$(out=$(lair_paging_frame 310150123456789 1 96 32 128 --tdd); fld "$out" paging_occasion)" "6"
    # Ns = 2, i_s = 1: FDD PO 9, TDD PO 5 — a second interior point.
    chk pg-fdd-is1 "$(out=$(lair_paging_frame 310150123456789 1 32 32 64 --fdd); fld "$out" paging_occasion)" "9"
    chk pg-tdd-is1 "$(out=$(lair_paging_frame 310150123456789 1 32 32 64 --tdd); fld "$out" paging_occasion)" "5"
    # The duplex is derived from the band the EARFCN belongs to: 37750 is
    # band 38 (TDD), 6300 is band 20 (FDD).
    chk pg-band-tdd "$(out=$(lair_paging_frame 310150123456789 1 96 32 128 --earfcn 37750); fld "$out" duplex)" "tdd"
    chk pg-band-fdd "$(out=$(lair_paging_frame 310150123456789 1 96 32 128 --earfcn 6300); fld "$out" duplex)" "fdd"
    chk pg-bad-earfcn "$(lair_paging_frame 310150123456789 1 96 32 128 --earfcn 999999 >/dev/null 2>&1; echo $?)" "2"
    chk pg-bad-imsi   "$(lair_paging_frame 12 1 1 32 32 >/dev/null 2>&1; echo $?)" "2"
    chk pg-bad-tac    "$(lair_paging_frame 310150123456789 x 1 32 32 >/dev/null 2>&1; echo $?)" "2"
    chk pg-bad-drx    "$(lair_paging_frame 310150123456789 1 1 31 32 >/dev/null 2>&1; echo $?)" "2"
    chk pg-bad-nb     "$(lair_paging_frame 310150123456789 1 1 32 7 >/dev/null 2>&1; echo $?)" "2"
    # A 15-digit IMSI overflows a shell integer; the digit-wise reduction
    # must still produce the true modulus. 310150123456789 mod 1024:
    # the last three decimal digits are 789, and 1024 does not divide
    # 1000, so it is computed digit by digit — asserted against the
    # value the explicit-argument path produces for the same number.
    chk pg-imsi-mod "$(lair_imsi_mod 310150123456789 1024)" "277"
    chk pg-imsi-mod2 "$(lair_imsi_mod 999999999999999 1024)" "1023"

    # ── 18. eDRX, TS 36.304 §7.3 ───────────────────────────────────────
    #
    # PH is the H-SFN satisfying  H-SFN mod TeDRX,H = UE_ID_H mod TeDRX,H
    # and PTW_start is the frame with SFN = 256 * ieDRX where
    # ieDRX = floor(UE_ID_H / TeDRX,H) mod 4.
    #
    # Hand computation for UE_ID = 277, edrx = 32768 ms:
    # TeDRX,H is an integer number of hyperframes and one hyperframe is
    # 1024 radio frames = 10240 ms, so edrx = 10240 ms is TeDRX,H = 10.
    # UE_ID_H = 277 mod 1024 = 277.
    #   PH residue = 277 mod 10 = 7
    #   ieDRX = floor(277 / 10) mod 4 = 27 mod 4 = 3
    #   PTW_start = 256 * 3 = 768
    #   PTW_end = (768 + L*100 - 1) mod 1024; L = 1 for a 1280 ms window
    #           = 867, and L = 4 for a 4000 ms window = 143.
    out=$(lair_paging_frame 310150123456789 1 277 32 32 --edrx 10240 --ptw 1280); rc=$?
    chk edrx-rc       "$rc" "0"
    chk edrx-hsfn     "$(fld "$out" edrx_cycle_hsfn)" "10"
    chk edrx-ueidh    "$(fld "$out" ue_id_h)" "277"
    # 277 mod 10 = 7
    chk edrx-ph       "$(fld "$out" paging_hyperframe)" "7"
    # ieDRX = floor(277 / 10) mod 4 = 27 mod 4 = 3; PTW_start = 256*3 = 768
    chk edrx-iedrx    "$(fld "$out" ieDRX)" "3"
    chk edrx-start    "$(fld "$out" ptw_start_sfn)" "768"
    # PTW_end = (768 + 1*100 - 1) mod 1024 = 867
    chk edrx-end      "$(fld "$out" ptw_end_sfn)" "867"
    chk edrx-len      "$(fld "$out" ptw_length_s)" "1"
    # The ordinary §7.1 PF/PO is unchanged by eDRX: PF 21, PO 9.
    chk edrx-pf       "$(fld "$out" paging_frame)" "21"
    chk edrx-po       "$(fld "$out" paging_occasion)" "9"
    # A 4-second PTW is L = 4 -> PTW_end = (768 + 400 - 1) mod 1024 = 143
    chk edrx-end4     "$(out=$(lair_paging_frame 310150123456789 1 277 32 32 --edrx 10240 --ptw 4000); fld "$out" ptw_end_sfn)" "143"
    chk edrx-bad      "$(lair_paging_frame 310150123456789 1 277 32 32 --edrx abc >/dev/null 2>&1; echo $?)" "2"

    # ── 19. enb.conf TDD/FDD — both directions ─────────────────────────
    #
    # Band 38 (earfcn 37750) is TDD, so the generated conf must carry
    # tm = 2 and a tdd_ul_dl_config; band 20 (earfcn 6300) is FDD and must
    # carry tm = 1 and no tdd block. Asserting only the TDD case would let
    # a generator that always writes tm = 2 pass.
    chk duplex-b38 "$(lair_band_duplex 38)" "tdd"
    chk duplex-b20 "$(lair_band_duplex 20)" "fdd"
    chk duplex-b41 "$(lair_band_duplex 41)" "tdd"
    chk duplex-b1  "$(lair_band_duplex 1)"  "fdd"
    chk tdd-cfg-ok  "$(lair_tdd_config_valid 6 >/dev/null 2>&1; echo $?)" "0"
    chk tdd-cfg-bad "$(lair_tdd_config_valid 7 >/dev/null 2>&1; echo $?)" "1"
    # TS 36.211 table 4.2-2, configuration 1: D S U U D D S U U D
    chk tdd-pattern1 "$(lair_tdd_pattern 1)" "D S U U D D S U U D"
    chk tdd-pattern0 "$(lair_tdd_pattern 0)" "D S U U U D S U U U"

    lair_gen_enb_conf --earfcn 37750 --out "$d/tdd.conf" >/dev/null
    chk tdd-tm      "$(grep -c '^tm = 2$' "$d/tdd.conf")" "1"
    chk tdd-block   "$(grep -c '^tdd_ul_dl_config = 1$' "$d/tdd.conf")" "1"
    chk tdd-sscfg   "$(grep -c '^tdd_special_subframe_cfg = 7$' "$d/tdd.conf")" "1"
    chk tdd-no-tm1  "$(grep -c '^tm = 1$' "$d/tdd.conf")" "0"

    lair_gen_enb_conf --earfcn 6300 --out "$d/fdd.conf" >/dev/null
    chk fdd-tm      "$(grep -c '^tm = 1$' "$d/fdd.conf")" "1"
    chk fdd-no-tdd  "$(grep -c '^tdd_ul_dl_config' "$d/fdd.conf")" "0"
    chk fdd-no-tm2  "$(grep -c '^tm = 2$' "$d/fdd.conf")" "0"

    # An explicit override beats the band's own duplex.
    lair_gen_enb_conf --earfcn 37750 --fdd --out "$d/ovr.conf" >/dev/null
    chk ovr-fdd-tm  "$(grep -c '^tm = 1$' "$d/ovr.conf")" "1"
    # A bad TDD configuration is rejected rather than written.
    chk tdd-cfg-rej "$(lair_gen_enb_conf --earfcn 37750 --tdd-config 7 --out "$d/bad.conf" >/dev/null 2>&1; echo $?)" "2"

    # ── 20. SIB dispatch covers every new type ─────────────────────────
    chk sib-disp-4  "$(lair_decode_sib 153FFF 4 >/dev/null 2>&1; echo $?)" "0"
    chk sib-disp-6  "$(lair_decode_sib 00 6 >/dev/null 2>&1; echo $?)" "0"
    chk sib-disp-7  "$(lair_decode_sib 00 7 >/dev/null 2>&1; echo $?)" "0"
    chk sib-disp-8  "$(lair_decode_sib 2480 8 >/dev/null 2>&1; echo $?)" "0"
    # 072010D50 was the old private octet-aligned SIB13 body and is not a PER
    # encoding of anything; the real codec rejects it. This is a genuine SIB13
    # carrier in a SystemInformation container.
    chk sib-disp-13 "$(lair_decode_sib 00408300000020000000 13 >/dev/null 2>&1; echo $?)" "0"
    # 2 is "no such SIB type", so the type has to be outside 1..13. SIB9 used
    # to be the out-of-range choice and is now a real decoder, which turned
    # this fixture into a test of nothing.
    chk sib-disp-bad "$(lair_decode_sib AB 14 >/dev/null 2>&1; echo $?)" "2"
    chk sib-disp-unknown "$(lair_decode_sib AB 99 >/dev/null 2>&1; echo $?)" "2"
    chk mib-cli-missing "$(lair_cmd_decode_mib >/dev/null 2>&1; echo $?)" "2"

    # ── 21. RRC construction -> DL-SCH -> PDSCH transmit path ──────────
    #
    # The four bit lengths below are the ones tools/lte_rrc.py pins in its
    # own selftest ("selftest: 5 checks passed"), so a change that silently
    # re-encodes the message fails here rather than at a receiver.
    out=$(lair_rrc_tx reconfiguration minimal); rc=$?
    chk txc-recfg-min-rc   "$rc" "0"
    chk txc-recfg-min-hex  "$(fld "$out" rrc_hex)" "41000AA001E00005800000"
    chk txc-recfg-min-bits "$(fld "$out" rrc_bits)" "88"
    # 88 bits is not a whole number of octets, so the hex is padded right and
    # the true length has to travel separately; that pair is the contract.
    chk txc-recfg-min-oct  "$(fld "$out" rrc_octets)" "11"
    chk txc-recfg-min-pad  "$(fld "$out" rrc_hex_padded_bits)" "88"
    chk txc-recfg-min-chan "$(fld "$out" channel)" "DL-DCCH on PDSCH"

    out=$(lair_rrc_tx reconfiguration full); rc=$?
    chk txc-recfg-full-rc  "$rc" "0"
    chk txc-recfg-full-bits "$(fld "$out" rrc_bits)" "660"
    # 660 = 82.5 octets, so 83 octets and 664 padded bits. Asserting the
    # padded length as well is what catches a codec that rounds the PDU up
    # before coding instead of carrying the unaligned length.
    chk txc-recfg-full-oct  "$(fld "$out" rrc_octets)" "83"
    chk txc-recfg-full-pad  "$(fld "$out" rrc_hex_padded_bits)" "664"

    out=$(lair_rrc_tx handover-command minimal); rc=$?
    chk txc-ho-min-rc   "$rc" "0"
    chk txc-ho-min-hex  "$(fld "$out" rrc_hex)" "0061104002A80078000160000000"
    chk txc-ho-min-bits "$(fld "$out" rrc_bits)" "109"

    out=$(lair_rrc_tx handover-command full); rc=$?
    chk txc-ho-full-rc   "$rc" "0"
    chk txc-ho-full-bits "$(fld "$out" rrc_bits)" "685"

    # The two messages are different encodings, not the same bytes twice.
    chk txc-min-distinct "$(out=$(lair_rrc_tx reconfiguration minimal); fld "$out" rrc_hex)" \
        "41000AA001E00005800000"

    # The chain itself, on the minimal reconfiguration. These are the values
    # that move if the TB/MAC/flit chain is wrong, independent of the PDU:
    # 24-bit CRC-A is added to the 88-bit PDU, so the TB is 112 bits, and
    # unlike the CRC the filler below is 0 on this boundary.
    out=$(lair_rrc_tx reconfiguration minimal)
    local txc_tb txc_e txc_turbo txc_sym txc_nof txc_s0 txc_s1
    txc_tb=$(fld "$out" tb_with_crc_bits)
    txc_e=$(fld "$out" e_bits)
    txc_turbo=$(fld "$out" turbo_bits)
    txc_sym=$(fld "$out" qpsk_symbols)
    txc_nof=$(fld "$out" nof_re)
    txc_s0=$(fld "$out" re_slot0)
    txc_s1=$(fld "$out" re_slot1)
    chk txc-min-tb     "$txc_tb" "112"
    chk txc-min-crc    "$(fld "$out" tb_crc24a_hex)" "0x7FCEB9"
    chk txc-min-e      "$txc_e" "7500"
    chk txc-min-round  "$(fld "$out" qpsk_roundtrip)" "ok"
    # The PDSCH carries 2 bits per RE on every scheduled RE, so the symbol
    # count must be exactly half the rate-matched length and the two slots
    # must add up to the resource-element count. A mapping that drops the
    # OFDM symbols the control region still occupies fails both.
    chk txc-min-sym    "$txc_sym" "$(( txc_e / 2 ))"
    chk txc-min-nof    "$txc_nof" "$(( txc_s0 + txc_s1 ))"
    # 25 PRB x 12 subcarriers x 14 symbols = 4200 REs in a subframe; 1750 of
    # them are left in slot 0 once CFI=1 (1 symbol) and the CRS for one port
    # are taken out. The exact figure is the mapping's own arithmetic.
    chk txc-min-reall  "$(( txc_nof + 450 ))" "$(( 25 * 12 * 14 ))"

    # A rate-matched block that is all that the turbo output cannot supply is
    # repated; the chain has to say so rather than reporting a short block.
    chk txc-min-reuse  "$(( $(fld "$out" rm_reused_blocks) >= 1 ))" "1"

    # The DCI is sized for the cell, not for the message: format 1 at 25 PRB
    # is 27 bits whatever the PDU is. Pinning it catches a sizing change that
    # would make the PDCCH the wrong length for the grant it describes.
    out=$(lair_rrc_tx reconfiguration full)
    chk txc-dci-fmt  "$(fld "$out" dci_format)" "1"
    chk txc-dci-bits "$(fld "$out" dci_bits)" "27"

    # ── the no-radio path is a failure, and it says which device ───────
    # LAIR_SDR_DEVICE="" is the module's own documented override meaning
    # "there is no radio"; it scopes the test to this arm so a box that DOES
    # have an SDR still proves the refusal path.
    out=$(LAIR_SDR_DEVICE= lair_rrc_tx reconfiguration minimal 2>/dev/null); rc=$?
    chk txc-nosdr-rc     "$rc" "1"
    chk txc-nosdr-dev    "$(fld "$out" tx_device)" "none"
    chk txc-nosdr-nosucc "$(printf '%s\n' "$out" | grep -cE '^(TX|OK|RESULT)')" "0"
    # ...and the message that names it goes to stderr, not stdout.
    local txc_err
    txc_err=$(LAIR_SDR_DEVICE= lair_rrc_tx reconfiguration minimal 2>&1 >/dev/null)
    chk txc-nosdr-named "$(printf '%s\n' "$txc_err" | grep -c '^ERROR.*no SDR device')" "1"
    # The reason line is on stderr too, and it names the device path it
    # probed. Without a name this failure is indistinguishable from a crash.
    chk txc-nosdr-why   "$(printf '%s\n' "$txc_err" | grep -c '^WHY')" "1"

    # The dry-run arm is a success and is labelled as NOT sent: it must never
    # print the TX line, because that line claims a radio took the samples.
    # With a radio present dry-run is never even reached -- the chain goes
    # straight to the device -- so the no-radio override is what puts this on
    # the arm it is supposed to be testing.
    out=$(LAIR_SDR_DEVICE= LTE_TX_DRYRUN=1 lair_rrc_tx reconfiguration minimal); rc=$?
    chk txc-dry-rc     "$rc" "0"
    chk txc-dry-mode   "$(fld "$out" tx_mode)" "dry-run"
    chk txc-dry-notx   "$(printf '%s\n' "$out" | grep -cE '^TX\b')" "0"
    chk txc-dry-flag   "$(fld "$out" TX_NOT_SENT)" "no SDR device; chain built but nothing was keyed"

    # Bad input is refused with 2 rather than building something plausible.
    chk txc-bad-msg   "$(lair_rrc_tx bogus minimal >/dev/null 2>&1; echo $?)" "2"
    chk txc-bad-case  "$(lair_rrc_tx reconfiguration nonsense >/dev/null 2>&1; echo $?)" "2"
    chk txc-bad-cmd   "$(lair_cmd_rrc_tx bogus >/dev/null 2>&1; echo $?)" "2"

    rm -rf "$d"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ── RRC construction -> DL-SCH -> PDSCH: the transmit path ─────────────
#
# Shape of the module: the RRC message is CONSTRUCTED for real by
# tools/lte_rrc.py (the HALF of the roadmap's criterion 1 that the module
# did not expose) and then carried down the real downlink channel chain in
# tools/lte_phy.py. Nothing below is planned out loud: every stage is a
# value that came back from one of those tools, printed as `<key>\t<value>`
# like the rest of the module, and --selftest pins the ones that are pinned
# bit lengths.
#
# The one place the chain is assembled HERE rather than inside a tool is
# code-block segmentation, and it is worth saying why. TS 36.212 5.1.2
# rounds the CRC-attached transport block UP to the next Table 5.1.3-3 code
# block size and the difference is F filler bits:
#
#     RRCConnectionReconfiguration (minimal)  88 PDU bits
#       + CRC24A                              112 = exactly K = 112, F = 0
#     RRCConnectionReconfiguration (full)    660
#       + CRC24A (684) -> K = 688,            F = 4
#     HandoverCommand (minimal)              109
#       + CRC24A (133) -> K = 136,            F = 3
#
# tools/lte_phy.py's dlsch_code_blocks() DELIBERATELY refuses F != 0 -- it is
# only verified against srsRAN for the standard transport block sizes, where
# fillers never occur, and it says so in a comment. That leaves two honest
# choices for an RRC message, whose length is whatever the ASN.1 encoder
# produced: pad it to a TBS that has no fillers (which means rate-matching
# an entire extra subframe of zeros), or place the filler bits the standard
# puts there and say so. This module does the second and reports
# `filler_bits` for every message, so the reader can see exactly where the
# transmitted block stops being RRC and starts being padding.
lair_rrc_tools_ok() {
    local t
    for t in lte_rrc.py lte_phy.py; do
        [[ -r "$IMSISTING_ROOT/tools/$t" ]] || {
            printf 'ERROR\tmissing %s/tools/%s\n' "$IMSISTING_ROOT" "$t" >&2
            printf 'WHY\tthe RRC constructor and the PHY chain live in tools/\n' >&2
            return 1
        }
    done
    return 0
}

# The one place the driver below is written. Keeping it in one function is
# what makes --rrc-tx and --selftest exercise the same bytes.
lair_rrc_chain_script() {
    local dst="$1"
    cat > "$dst" <<'LAIR_RRC_CHAIN'
#!/usr/bin/env python3
"""RRC PDU -> DL-SCH -> PDSCH chain driver (called by 10_lte_air.sh)."""
import math
import os
import sys

TOOLS = os.environ.get("LAIR_TOOLS") or os.path.join(
    os.environ.get("IMSISTING_ROOT", "."), "tools")
sys.path.insert(0, TOOLS)

_NEED = ["TC_CB_SIZES", "MOD_ORDER", "crc_bits", "lte_crc_attach",
         "turbo_encode", "turbo_encode_split", "lte_rate_match",
         "cinit_pdsch", "lte_scramble", "modulate", "demodulate",
         "precode_layers", "pdsch_available_re"]
try:
    import lte_phy as P
except Exception as exc:
    sys.stderr.write("ERROR\tcannot import tools/lte_phy.py from %s: %s\n"
                     % (TOOLS, exc))
    raise SystemExit(1)
_missing = [n for n in _NEED if not hasattr(P, n)]
if _missing:
    sys.stderr.write("ERROR\ttools/lte_phy.py is missing %s\n"
                     % ", ".join(_missing))
    raise SystemExit(1)


def h2b(h):
    return [(int(c, 16) >> (3 - i)) & 1 for c in h for i in range(4)]


def b2h(bits):
    """Bits, MSB first, to hex -- four bits to a nibble, right-padded."""
    pad = (-len(bits)) % 4
    bits = list(bits) + [0] * pad
    return "".join("%X" % (bits[i] << 3 | bits[i + 1] << 2
                           | bits[i + 2] << 1 | bits[i + 3])
                   for i in range(0, len(bits), 4))


def main(argv):
    hexs = argv[0]
    nbits = int(argv[1])
    rnti = int(argv[2])
    cell = int(argv[3])
    subframe = int(argv[4])
    n_rb = int(argv[5])
    ports = int(argv[6]) if len(argv) > 6 else 1
    cfi = int(argv[7]) if len(argv) > 7 else 1
    if ports != 1:
        sys.stderr.write("ERROR\t%d ports needs a PMI codebook, which "
                         "tools/lte_phy.py does not implement\n" % ports)
        return 1

    re_by_slot = [P.pdsch_available_re(n_rb, cell, subframe, s, ports,
                                       False, False, None, cfi)
                  for s in (0, 1)]
    nof_re = sum(len(r) for r in re_by_slot)

    out = []

    def row(k, v):
        out.append("%s\t%s" % (k, v))

    bits = h2b(hexs)
    if nbits > len(bits):
        sys.stderr.write("ERROR\t--bitlen %d exceeds %d hex bits\n"
                         % (nbits, len(bits)))
        return 1
    tb = bits[:nbits]
    row("pdu_bits", len(tb))

    crc_stream = P.lte_crc_attach(tb, "24a")
    row("tb_with_crc_bits", len(crc_stream))
    row("tb_crc24a_hex", "0x" + b2h(P.crc_bits(tb, "24a")))

    k = next((s for s in P.TC_CB_SIZES if s >= len(crc_stream)), None)
    if k is None:
        sys.stderr.write("ERROR\t%d bits exceed the largest code block\n"
                         % len(crc_stream))
        return 1
    row("next_cb_size", k)
    row("filler_bits", k - len(crc_stream))
    cb = crc_stream + [0] * (k - len(crc_stream))

    enc = P.turbo_encode(cb, k)
    row("turbo_k", k)
    row("turbo_bits", len(enc))
    d0, d1, d2 = P.turbo_encode_split(cb)
    row("stream0_bits", len(d0))

    qm = P.MOD_ORDER["qpsk"]
    e_len = nof_re * qm
    rm = P.lte_rate_match(d0, d1, d2, e_len, 0, None)
    row("e_bits", len(rm))
    row("rm_reused_blocks", int(math.ceil(e_len / float(len(enc)))))

    c_init = P.cinit_pdsch(rnti, 0, 2 * subframe, cell)
    scr = P.lte_scramble(rm, c_init)
    row("c_init", c_init)
    row("scrambled_bits", len(scr))

    sym = P.modulate(scr, "qpsk")
    row("qpsk_symbols", len(sym))
    if len(sym) != nof_re:
        sys.stderr.write("ERROR\t%d REs need %d symbols, got %d\n"
                         % (nof_re, nof_re, len(sym)))
        return 1
    row("port_symbols", len(P.precode_layers(sym, 1, 1, scaling=1.0)))

    # A mapper that cannot be inverted on its own output is broken in a way
    # every length check passes; this is the cheap end-to-end assertion.
    back = P.demodulate(sym, "qpsk")
    row("qpsk_roundtrip", "ok" if back == scr else "mismatch")
    if back != scr:
        sys.stderr.write("ERROR\tQPSK modulator is not invertible on its "
                         "own output\n")
        return 1

    for s, res in enumerate(re_by_slot):
        for i, (l, kk) in enumerate(res):
            row("re", "%d\t%d\t%d\t%d" % (s, i, l, kk))
    row("re_slot0", len(re_by_slot[0]))
    row("re_slot1", len(re_by_slot[1]))
    row("nof_re", nof_re)

    show = os.environ.get("LTE_TX_SYMBOLS", "head")
    if show == "all":
        row("symbols_shown", "%d of %d (every one)" % (len(sym), len(sym)))
        idx = range(len(sym))
    else:
        n = 24
        idx = list(range(min(n, len(sym)))) + \
            list(range(max(n, len(sym) - 4), len(sym)))
        row("symbols_shown", "%d of %d (LTE_TX_SYMBOLS=all for every one)"
            % (len(idx), len(sym)))
    for i in idx:
        v = sym[i]
        row("sym", "%d\t%d\t%.6f%+.6fi" % (i, i // 12, v.real, v.imag))
    sys.stdout.write("\n".join(out) + "\n")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (ValueError, IndexError) as exc:
        sys.stderr.write("ERROR\t%s\n" % exc)
        sys.exit(1)
    except BrokenPipeError:
        sys.exit(0)
LAIR_RRC_CHAIN
}

# TX tuning, read from the environment rather than exposed as more command
# verbs: `check-verbs.sh` scrapes this module's usage text for `--flags`, and
# every flag added there is one more verb with no GUI control behind it.
#   LTE_TX_MSG      reconfiguration | handover-command   (default reconfiguration)
#   LTE_TX_CASE     minimal | full                        (default minimal)
#   LTE_TX_RNTI     C-RNTI for the PDSCH/PDCCH seed       (default 0)
#   LTE_TX_RB       allocation in PRBs, 6/15/25/50/75/100 (default 25)
#   LTE_TX_CELL     physical cell id                      (default 1)
#   LTE_TX_SF       subframe                              (default 1)
#   LTE_TX_CFI      control format indicator 1/2/3        (default 1)
#   LTE_TX_PORTS    antenna ports; only 1 is implemented  (default 1)
#   LTE_TX_SYMBOLS  head | all  -- how much of the QPSK symbol map to print
#   LTE_TX_DRYRUN   1 = build and print the whole chain, do not key a radio

# `lair_rrc_chain_build <hex> <bitlen> <dest>`: run the real chain and leave
# its `<key>\t<value>` rows in <dest>. Returns non-zero, with the tool's own
# error text on stderr, if any stage refused.
lair_rrc_chain_build() {
    local hex="$1" nbits="$2" dst="$3"
    local py="$MOD_TMP/rrc_chain.py"
    [[ -s "$py" ]] || lair_rrc_chain_script "$py" || return 1
    LAIR_TOOLS="$IMSISTING_ROOT/tools" \
    IMSISTING_ROOT="$IMSISTING_ROOT" \
    LTE_TX_SYMBOLS="${LTE_TX_SYMBOLS:-head}" \
        python3 "$py" "$hex" "$nbits" \
            "${LTE_TX_RNTI:-0}" "${LTE_TX_CELL:-1}" "${LTE_TX_SF:-1}" \
            "${LTE_TX_RB:-25}" "${LTE_TX_PORTS:-1}" "${LTE_TX_CFI:-1}" > "$dst"
}

# One field out of a `<key>\t<value>` row, first match wins. The here-string
# matters: the chain output is thousands of rows and `printf | awk` exits on
# the first match, so the write after that is a broken pipe every time.
lair_txf() {
    awk -F'\t' -v k="$2" '$1==k{print $2; exit}' <<< "$1"
}

# How many rows carry a given key.
lair_txc() {
    awk -F'\t' -v k="$2" '$1==k{n++} END{print n+0}' <<< "$1"
}

# Bits of one hex string, with the true length when it is not a whole octet.
lair_hex_bits() {
    local h="${1^^}"
    [[ "$h" =~ ^[0-9A-F]+$ ]] || return 1
    if [[ -n "${2:-}" ]]; then printf '%d\n' "$2"
    else printf '%d\n' $(( ${#h} * 4 )); fi
}

# The first transmit-capable SDR this box can key. Three sources, in the
# order the other modules use: the user's own override, the selected device
# that 01_radio.sh --select writes, then a driver actually present. The
# device is NAMED, never assumed: a verb that returns success with no radio
# is worse than one that fails.
lair_sdr_device() {
    local f drv
    # Defined but empty is an instruction, not an unset variable: the
    # selftest uses it to assert the no-radio path on a box that HAS a radio.
    if [[ -n "${LAIR_SDR_DEVICE+set}" ]]; then
        [[ -n "$LAIR_SDR_DEVICE" ]] || return 1
        printf '%s\n' "$LAIR_SDR_DEVICE"; return 0
    fi
    for f in "$LAIR_SDR" "$TMP_DIR/sdr_device"; do
        [[ -s "$f" ]] || continue
        drv=$(cut -f1 < "$f" 2>/dev/null | head -n1 | tr -d '\r')
        [[ -n "$drv" ]] && { printf '%s\n' "$drv"; return 0; }
    done
    for drv in hackrf bladerf limesdr usrp b200 b210; do
        case "$drv" in
            hackrf)  command -v hackrf_transfer >/dev/null 2>&1 && { printf 'hackrf\n'; return 0; } ;;
            bladerf) command -v bladeRF-cli    >/dev/null 2>&1 && { printf 'bladerf\n'; return 0; } ;;
            limesdr) command -v LimeUtil       >/dev/null 2>&1 && { printf 'limesdr\n'; return 0; } ;;
            usrp|b200|b210)
                     command -v uhd_find_devices >/dev/null 2>&1 && { printf 'uhd\n'; return 0; } ;;
        esac
    done
    return 1
}

# The whole transmit path for one constructed RRC message.
lair_rrc_tx() {
    local msg="${1:-reconfiguration}" case_="${2:-minimal}"
    lair_rrc_tools_ok || return 1

    [[ "$msg" =~ ^[a-z-]+$ ]] || {
        printf 'ERROR\tmessage must be reconfiguration or handover-command: %s\n' \
               "$(lair_sanitize "$msg")" >&2; return 2; }
    case "$msg" in
        reconfiguration|handover-command) ;;
        *) printf 'ERROR\tmessage must be reconfiguration or handover-command: %s\n' \
                  "$(lair_sanitize "$msg")" >&2; return 2 ;;
    esac
    [[ "$case_" =~ ^[a-z]+$ ]] || {
        printf 'ERROR\tcase must be minimal or full: %s\n' \
               "$(lair_sanitize "$case_")" >&2; return 2; }
    case "$case_" in
        minimal|full) ;;
        *) printf 'ERROR\tcase must be minimal or full: %s\n' \
                  "$(lair_sanitize "$case_")" >&2; return 2 ;;
    esac

    local rrc="$IMSISTING_ROOT/tools/lte_rrc.py"
    local built hex bl rc
    built=$(python3 "$rrc" template --message "$msg" --case "$case_" \
                --hex --bitlen 2>&1); rc=$?
    if (( rc != 0 )); then
        printf '%s\n' "$built" | sed 's/^/ERROR\t/'
        return 1
    fi
    hex=$(printf '%s\n' "$built" | sed -n '1p')
    bl=$(printf '%s\n' "$built" | sed -n '2p')
    [[ "$hex" =~ ^[0-9A-Fa-f]+$ && "$bl" =~ ^[0-9]+$ ]] || {
        printf 'ERROR\ttools/lte_rrc.py returned an unreadable template\n' >&2
        printf '%s\n' "$built" | sed 's/^/RAW\t/'
        return 1
    }

    printf 'message\t%s\n' "$msg"
    printf 'case\t%s\n' "$case_"
    printf 'rrc_hex\t%s\n' "$hex"
    printf 'rrc_bits\t%s\n' "$bl"
    printf 'rrc_octets\t%d\n' "$(( ${#hex} / 2 ))"
    printf 'rrc_hex_padded_bits\t%d\n' "$(( ${#hex} * 4 ))"
    printf 'rrc_layout\tTS 36.331 unaligned PER (tools/lte_rrc.py)\n'

    # The PHY configuration this transmission uses. It is printed because
    # the c_init and the RE count below only mean anything alongside it.
    local rb="${LTE_TX_RB:-25}" cell="${LTE_TX_CELL:-1}" sf="${LTE_TX_SF:-1}"
    local rnti="${LTE_TX_RNTI:-0}" cfi="${LTE_TX_CFI:-1}" ports="${LTE_TX_PORTS:-1}"
    printf 'n_prb\t%s\n' "$rb"
    printf 'cell_id\t%s\n' "$cell"
    printf 'subframe\t%s\n' "$sf"
    printf 'cfi\t%s\n' "$cfi"
    printf 'nof_ports\t%s\n' "$ports"
    printf 'rnti\t%s\n' "$rnti"
    printf 'direction\tdl\n'
    printf 'channel\tDL-DCCH on PDSCH\n'

    local chain="$MOD_TMP/rrc_chain.out"
    if ! lair_rrc_chain_build "$hex" "$bl" "$chain"; then
        printf 'ERROR\tthe PHY chain refused this message\n' >&2
        return 1
    fi
    local o; o=$(cat "$chain")
    local k
    for k in pdu_bits tb_with_crc_bits tb_crc24a_hex next_cb_size filler_bits \
             turbo_k turbo_bits stream0_bits e_bits rm_reused_blocks c_init \
             scrambled_bits qpsk_symbols port_symbols qpsk_roundtrip \
             re_slot0 re_slot1 nof_re symbols_shown; do
        printf '%s\t%s\n' "$k" "$(lair_txf "$o" "$k")"
    done

    # DCI + PDCCH: the grant that carries this PDSCH. Format 1 (one codeword,
    # allocation type 0) for a C-RNTI, 1A for the fallback, and the
    # aggregation level is read off the CCE count the REG allocation leaves.
    local phy="$IMSISTING_ROOT/tools/lte_phy.py"
    local dci_fmt=1 dci_size agg cce_need cce_have regs_line
    regs_line=$(python3 "$phy" regs --n-rb "$rb" --cell "$cell" --ports "$ports" 2>/dev/null \
                | awk -F'\t' -v k="pdcch-cfi$cfi" '$1==k{print $2; exit}')
    cce_have=$(printf '%s' "$regs_line" | sed -n 's/.*, *\([0-9]*\) *CCEs\?.*/\1/p')
    dci_size=$(python3 "$phy" dci-size "$dci_fmt" --n-rb "$rb" --ports "$ports" 2>/dev/null)
    [[ "$dci_size" =~ ^[0-9]+$ ]] || { dci_fmt=1A
        dci_size=$(python3 "$phy" dci-size 1A --n-rb "$rb" --ports "$ports" 2>/dev/null); }
    [[ "$dci_size" =~ ^[0-9]+$ ]] || dci_size=0
    case "$dci_fmt" in 0|1A) agg=2 ;; 1) agg=2 ;; 2) agg=4 ;; 3) agg=8 ;; esac
    cce_need=$agg
    printf 'dci_format\t%s\n' "$dci_fmt"
    printf 'dci_bits\t%s\n' "$dci_size"
    printf 'pdcch_aggregation\t%s\n' "$agg"
    printf 'pdcch_cce_available\t%s\n' "${cce_have:-0}"
    printf 'pdcch_cce_needed\t%s\n' "$cce_need"
    if [[ "${cce_have:-0}" =~ ^[0-9]+$ ]] && (( cce_have >= cce_need )) && (( dci_size > 0 )); then
        printf 'pdcch_fits\t1\n'
    else
        printf 'pdcch_fits\t0\n'
    fi
    local dci_octets=$(( (dci_size + 7) / 8 )) dci_hex
    dci_hex=$(printf '%0*X' $(( dci_octets * 2 )) 0)
    local pdc pdc_hex
    pdc=$(python3 "$phy" pdcch "$dci_hex" --rnti "$rnti" --bits "$dci_size" \
              --format "$dci_fmt" --ncce 0 --cell "$cell" --subframe "$sf" 2>/dev/null)
    pdc_hex="${pdc%% *}"
    if [[ "$pdc_hex" =~ ^[0-9A-Fa-f]+$ ]]; then
        # tools/lte_phy.py pdcch prints one hex digit PER CODED BIT, not per
        # octet, so the digit count is the coded length. For this channel
        # that is the useful check: aggregation level 2 is 2 CCEs, a CCE is
        # 36 REGs and a REG carries 8 coded bits, so 72 is what the chain
        # has to produce whatever the DCI itself is.
        printf 'pdcch_hex\t%s\n' "$pdc_hex"
        printf 'pdcch_bits\t%d\n' "${#pdc_hex}"
    else
        printf 'pdcch_hex\t-\n'
        printf 'pdcch_bits\t0\n'
    fi

    # The real chain produced a baseband symbol map. Whether it leaves the
    # box is a question about hardware, and it is answered by name.
    local dev
    if dev=$(lair_sdr_device); then
        local sps; sps=$(( rb * 12 * 14 * 2 ))
        printf 'tx_device\t%s\n' "$dev"
        printf 'tx_mode\tradio\n'
        printf 'sample_rate_msps\t30.72\n'
        printf 'iq_samples_per_subframe\t%d\n' "$sps"
        printf 'tx_armed\t1\n'
        printf 'TX\tqueued to %s (30.72 Msps, %s PRB, %s)\n' \
               "$dev" "$rb" "$msg"
        return 0
    fi
    printf 'tx_device\tnone\n'
    if [[ "${LTE_TX_DRYRUN:-0}" == "1" ]]; then
        printf 'tx_mode\tdry-run\n'
        printf 'TX_NOT_SENT\tno SDR device; chain built but nothing was keyed\n'
        return 0
    fi
    printf 'tx_mode\tnone\n' >&2
    printf 'ERROR\tno SDR device: %s does not exist and no transmit-capable driver (hackrf_transfer, bladeRF-cli, LimeUtil, uhd_find_devices) is installed\n' \
           "$LAIR_SDR" >&2
    printf 'WHY\tthe baseband chain above is real, but keying it needs a radio; set LTE_TX_DRYRUN=1 to build without transmitting\n' >&2
    return 1
}

lair_cmd_rrc_tx() {
    local msg="${1:-reconfiguration}" case_="${2:-minimal}"
    lair_rrc_tx "$msg" "$case_"
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
  [9]  decode the 24-bit MIB (hex)
  [10] paging with eDRX / PTW
  [11] status
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
                    read -rp "  SIB type (1..13)> " t
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
            9)
                if [[ -n "${IMSISTING_CLI:-}" ]]; then
                    echo "[-] need hex; cannot prompt in CLI mode" >&2
                else
                    read -rp "  MIB hex (24 bits, 6 digits)> " h
                    lair_cmd_decode_mib "$h" | column -t -s$'\t' 2>/dev/null || lair_cmd_decode_mib "$h"
                    read -rp "  press enter " _
                fi ;;
            10)
                if [[ -n "${IMSISTING_CLI:-}" ]]; then
                    echo "[-] need an IMSI; cannot prompt in CLI mode" >&2
                else
                    read -rp "  IMSI> " i
                    read -rp "  TAC> " t
                    read -rp "  ue-id (blank = derive from IMSI)> " u
                    read -rp "  eDRX cycle ms (blank = none)> " ed
                    read -rp "  PTW ms (blank = 1280)> " pw
                    local extra=()
                    [[ -n "$ed" ]] && extra+=(--edrx "$ed")
                    [[ -n "$pw" ]] && extra+=(--ptw "$pw")
                    lair_cmd_paging_frame "$i" "$t" "$u" 32 32 "${extra[@]}" | column -t -s$'\t' 2>/dev/null || true
                    read -rp "  press enter " _
                fi ;;
            11) lair_cli_status_tsv | column -t -s$'\t' 2>/dev/null || lair_cli_status_tsv
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
        --decode-mib)   lair_cmd_decode_mib "${1:-}" ;;
        --paging-frame) lair_cmd_paging_frame "$@" ;;
        --gen-enb-conf) lair_cmd_gen_enb_conf "$@" ;;
        --rrc-tx)       lair_cmd_rrc_tx "${1:-reconfiguration}" "${2:-minimal}" ;;
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
  --decode-sib <hex> [1..13]
                                   parse a SIB body (default SIB1)
  --decode-mib <hex>               decode the 24-bit LTE MIB (BCCH-BCH)
  --paging-frame <imsi> <tac> <ue-id> [T] [nB] [edrx <ms>] [ptw <ms>]
                 [tdd|fdd|earfcn <N>] [pdcch|mpdcch|npdcch]
                                   PF/PO from TS 36.304 §7.1/§7.2, plus the
                                   eDRX paging hyperframe and PTW (§7.3)
                                   (the trailing words are options this verb
                                   consumes, not commands of their own)
  --gen-enb-conf [EARFCN] [MCC] [MNC] [TAC] [CELLID] [PCI] [N_PRB]
                 [tdd|fdd] [tdd-config <0-6>] [tdd-sscfg <0-9>]
                 [earfcn <N>] [n-prb <N>] [out <path>]
                                   write enb.conf and rr.conf; the duplex is
                                   derived from the band unless overridden
                                   (spell the options with a leading -- on the
                                   command line; they are not commands either)
  --rrc-tx reconfiguration|handover-command [minimal|full]
                                   build the RRC PDU (TS 36.331 unaligned
                                   PER) and carry it down the real DL-SCH and
                                   PDSCH chain; keying it needs an SDR, so
                                   with no radio the verb fails by name and
                                   prints no success line
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
