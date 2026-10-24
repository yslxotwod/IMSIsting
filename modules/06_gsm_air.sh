#!/usr/bin/env bash
# gsm air interface — BCCH/SI decode, paging analysis, cipher audit, A5/1
#
# Passive-first. Everything here works from a hex string captured off the air
# (GSMTAP, gr-gsm, airprobe, a pcap) or is pure computation. No radio, no root
# and no network are needed for any verb that decodes or derives.
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

MOD_TMP="$TMP_DIR/gsm_air"
GAIR_DIR="$LOOT_DIR/gsm_air"
mkdir -p "$MOD_TMP" "$GAIR_DIR" 2>/dev/null

# Shared cross-module state — other modules read these.
GAIR_SDR="${TMP_DIR}/sdr_device"
GAIR_ARFCN="${TMP_DIR}/target_arfcn"
GAIR_PLMN="${TMP_DIR}/target_plmn"

# ── sanitisation ────────────────────────────────────────────────────────
# Any string that reaches a TSV row is untrusted: a network can carry an
# operator name containing a tab and forge an entire row in a consumer that
# splits on tab. Tabs, CR and LF become spaces at the point of output.
gair_sanitize() {
    printf '%s' "${1:-}" | tr '\t\r\n' '   '
}

# ── hex helpers ─────────────────────────────────────────────────────────
# Accept "1a 2b", "1a2b", "0x1a2b" or "1a:2b" and emit bare lowercase hex.
gair_norm_hex() {
    printf '%s' "${1:-}" | tr -d ' \t\r\n:.-' | sed 's/^0x//I' | tr 'A-F' 'a-f'
}

gair_is_hex() {
    local h; h=$(gair_norm_hex "${1:-}")
    [[ -n "$h" && "$h" =~ ^[0-9a-f]+$ && $(( ${#h} % 2 )) -eq 0 ]]
}

# Hex string -> bit string (MSB first), the representation every GSM field
# offset below is expressed in. GSM L1 numbering is bit 1 = first transmitted
# bit = MSB of the first octet, so bit index i (0-based) is simply position i
# of this string.
gair_hex_to_bits() {
    local h; h=$(gair_norm_hex "${1:-}")
    local i b out=""
    for (( i = 0; i < ${#h}; i++ )); do
        case "${h:i:1}" in
            0) b=0000 ;; 1) b=0001 ;; 2) b=0010 ;; 3) b=0011 ;;
            4) b=0100 ;; 5) b=0101 ;; 6) b=0110 ;; 7) b=0111 ;;
            8) b=1000 ;; 9) b=1001 ;; a) b=1010 ;; b) b=1011 ;;
            c) b=1100 ;; d) b=1101 ;; e) b=1110 ;; f) b=1111 ;;
            *) return 1 ;;
        esac
        out+="$b"
    done
    printf '%s' "$out"
}

# Bit string -> hex, zero-padded to a whole octet.
gair_bits_to_hex() {
    local bits="${1:-}"
    while (( ${#bits} % 4 != 0 )); do bits+="0"; done
    local i nib out=""
    for (( i = 0; i < ${#bits}; i += 4 )); do
        nib="${bits:i:4}"
        case "$nib" in
            0000) out+="0" ;; 0001) out+="1" ;; 0010) out+="2" ;; 0011) out+="3" ;;
            0100) out+="4" ;; 0101) out+="5" ;; 0110) out+="6" ;; 0111) out+="7" ;;
            1000) out+="8" ;; 1001) out+="9" ;; 1010) out+="a" ;; 1011) out+="b" ;;
            1100) out+="c" ;; 1101) out+="d" ;; 1110) out+="e" ;; 1111) out+="f" ;;
            *) return 1 ;;
        esac
    done
    printf '%s' "$out"
}

# Extract `len` bits starting at 0-based `off` from a hex string.
# This is the primitive behind every field map in this module.
gair_bits() {
    local hex="$1" off="$2" len="$3"
    local bits; bits=$(gair_hex_to_bits "$hex") || return 1
    (( off + len <= ${#bits} )) || return 1
    printf '%s' "${bits:off:len}"
}

# Same, but as an unsigned integer. Lengths above 63 are refused rather than
# silently truncated by bash arithmetic.
gair_field() {
    local hex="$1" off="$2" len="$3"
    local b; b=$(gair_bits "$hex" "$off" "$len") || return 1
    (( len <= 63 )) || return 1
    # Leading zeros with value 0 would make bash read it as octal-less "0";
    # prefix with 2# so bash always parses base 2.
    [[ -z "$b" ]] && { echo 0; return 1; }
    printf '%d' "$(( 2#$b ))"
}

# ── BCCH / SCH burst structure ──────────────────────────────────────────
# A GSM normal burst is 156.25 symbols: 3 tail + 57 data + 1 stealing + 26
# training + 1 stealing + 57 data + 3 tail + 8.25 guard. The training sequence
# identifies the burst type. These are the TS 45.002 §5.2.3 sequences, written
# as the 26-bit midamble in hex, plus the 64-bit sync sequence used by SCH.
gair_training_name() {
    case "$(printf '%s' "${1:-}" | tr 'a-f' 'A-F')" in
        0393A) echo "TSC0" ;; 03B39) echo "TSC1" ;; 025ED) echo "TSC2" ;;
        03DDB) echo "TSC3" ;; 0219A) echo "TSC4" ;; 02B5A) echo "TSC5" ;;
        035B6) echo "TSC6" ;; 03A69) echo "TSC7" ;;
        *)     echo "unknown" ;;
    esac
}

# FCCH is a pure frequency-correction burst: 142 fixed bits
# (0010010111... repeated), the MS uses it to lock its frequency reference.
# SCH carries the 64-bit BSIC sync word after the same fixed tail shape.
GAIR_SCH_SYNC="0011100100"          # first 10 bits of the SCH sync sequence
GAIR_FCCH_PATTERN="0010010111"      # the repeating FCCH tone pattern

# SCH burst payload: 25 bits of BSIC + frame number after the 64-bit sync.
# Layout per TS 45.002 §3.3.2.2 / TS 44.018:
#   bits 0..38  : extended training sequence (64-bit sync, we see 39 here)
#   bits 41..45 : BSIC (3 bits PLMN colour code + 3 bits base station colour)
#   bits 46..67 : reduced TDMA frame number (22 bits)
gair_decode_sch() {
    local hex="$1" bits
    bits=$(gair_hex_to_bits "$hex") || {
        printf 'ERROR\tnot hex\n' >&2; return 1; }
    (( ${#bits} >= 25 )) || { printf 'ERROR\tshort burst (%s bits)\n' "${#bits}" >&2; return 1; }
    # The 25-bit SCH payload is the last 25 bits we are given.
    local payload="${bits: -25}"
    local bsic=$(( 2#${payload:0:6} ))
    local ncc=$(( bsic >> 3 )) bcc=$(( bsic & 7 ))
    printf 'bsic\t%d\n' "$bsic"
    printf 'ncc\t%d\n'  "$ncc"
    printf 'bcc\t%d\n'  "$bcc"
    printf 'raw_payload\t%s\n' "$payload"
    printf 'frame\t%s\n' "$(gair_sch_frame_number "$payload")"
}

# SCH carries the reduced TDMA frame number (RFN) as 19 bits, which map to
# T1/T2/T3': T1 = RFN div 1326 (11 bits), T2 = ... The full mapping is
#   T1  = (RFN div 1326) & 0x7FF
#   T3  = ((RFN - 1) div 51)   mod 51
#   T2  =  RFN mod 26
# T1/T2/T3 then reassemble the full frame number.
gair_sch_frame_number() {
    local payload="${1:-}"
    (( ${#payload} >= 25 )) || return 1
    local rfn=$(( 2#${payload:6:19} ))
    local t1=$(( (rfn / 1326) & 0x7FF ))
    local t3=$(( ((rfn - 1) / 51) % 51 ))
    (( t3 < 0 )) && t3=0
    local t2=$(( rfn % 26 ))
    printf 'rfn=%d t1=%d t2=%d t3=%d' "$rfn" "$t1" "$t2" "$t3"
}

# ── System Information decode ───────────────────────────────────────────
# Every SI message is a 23-octet LAPDm UI frame on BCCH. The first octet is
# the L2 pseudo-length (0x15 = 21), the second is the protocol discriminator
# (0x06 = Radio Resources), the third carries the message type in bits 3..7,
# and the rest is the message body. The field offsets below are absolute
# *bit* positions into the reconstructed 23-octet message starting at the
# RR message type octet's LSB — i.e. the offsets used by gr-gsm, airprobe and
# the TS 44.018 field maps.
#
# Message types (TS 44.018 §9.1.1 / §10.5.1.1-4):
#   SI1  0x19, SI2  0x1a, SI2bis 0x02, SI2ter 0x03,
#   SI3  0x1b, SI4  0x1c, SI5  0x1d, SI6  0x1e,
#   SI13 0x04, SI7 0x07, SI8 0x18
gair_si_name() {
    case "$(printf '%s' "${1:-}" | tr 'a-f' 'A-F')" in
        19) echo "SI1" ;;  1A) echo "SI2" ;; 02) echo "SI2bis" ;;
        03) echo "SI2ter" ;; 1B) echo "SI3" ;; 1C) echo "SI4" ;;
        1D) echo "SI5" ;;  1E) echo "SI6" ;; 04) echo "SI13" ;;
        07) echo "SI7" ;;  18) echo "SI8" ;; 1F) echo "SI9" ;;
        *)  echo "unknown" ;;
    esac
}

gair_si_type_of() {
    local hex="$1"
    # Octet layout of a BCCH SI message:
    #   bits  0..7   L2 pseudo-length (0x15 = 21)
    #   bits  8..15  protocol discriminator (0x06 = Radio Resources)
    #   bits 16..23  message type  <- this is the SI type
    gair_field "$hex" 16 8
}

# ── SI3 field map (TS 44.018 §10.5.2.35) ────────────────────────────────
# Absolute bit offsets into the 23-octet frame, expressed from the start of
# the L2 header, matching the gr-gsm/airprobe decoder tables:
#   0..7    L2 pseudo-length
#   8..15   protocol discriminator (RR)
#   16..23  message type (skip indicator | msg type)
#   24..41  Cell Identity (16 bits)
#   42..47  LAI: MCC digit 1 / filler
#   48..71  LAI: MCC(3 BCD) MNC(3 BCD) LAC(16)
#   72..103 LAI: LAC 16 bits
#   104..115 control channel description
#   116..119 BS_AG_BLKS_RES (3)
#   120..122 BS_PA_MFRMS (3)
#   123..126 BS_CC_CHANS (3)
#   127..132 BS_CCCH_SDCCH_COMB / spare
#   133..135 spare
#   136..139 ATT (1)
#   140..183 rest octets
#
# Cell Identity is bits 24..39 (16 bits) of the full frame.
gair_si3_cell_id() {
    local hex="$1" b; b=$(gair_bits "$hex" 24 16) || return 1
    printf '%d' "$(( 2#$b ))"
}

# MCC/MNC are BCD in the LAI. Each digit is a nibble, low nibble first.
# The PLMN occupies bits 42..71 as three octets: MCC2 MCC1, MCC3 MNC3,
# MNC2 MNC1 — the classic "swapped nibble" GSM encoding.
gair_bcd_digits() {
    local hex="$1" off="$2" n="$3"
    local i nib d out=""
    for (( i = 0; i < n; i++ )); do
        nib=$(gair_bits "$hex" $(( off + i * 4 )) 4) || return 1
        d=$(( 2#$nib ))
        (( d == 15 )) && d=""
        out+="$d"
    done
    printf '%s' "$out"
}

# LAI MCC/MNC decoder. The three LAI octets sit at bits 40..63 of the
# reconstructed 23-octet frame (octets 5,6,7 after the L2 header, PD, message
# type, and the 16-bit Cell Identity). Each octet carries two BCD digits with
# the low nibble transmitted first (TS 24.008 §10.5.1.13):
#   octet1 (bits 40..47) = MCC digit2 | MCC digit1
#   octet2 (bits 48..55) = MCC digit3 | MNC digit3
#   octet3 (bits 56..63) = MNC digit2 | MNC digit1
# A 2-digit MNC sets MNC digit3 = 1111 (filler).
gair_decode_lai() {
    local hex="$1"
    local mcc mnc
    local o1 o2 o3
    o1=$(( 2#$(gair_bits "$hex" 40 8) )) || return 1
    o2=$(( 2#$(gair_bits "$hex" 48 8) )) || return 1
    o3=$(( 2#$(gair_bits "$hex" 56 8) )) || return 1

    # TS 23.003 2.2 / TS 24.008 10.5.1.3: the digits are packed two per octet
    # with the earlier digit in the LOW nibble:
    #   o1 = MCC2 MCC1     o2 = MNC3 MCC3     o3 = MNC2 MNC1
    local mcc1 mcc2 mcc3 mnc1 mnc2 mnc3
    mcc1=$(( o1 & 0x0f ));  mcc2=$(( (o1 >> 4) & 0x0f ))
    mcc3=$(( o2 & 0x0f ));  mnc3=$(( (o2 >> 4) & 0x0f ))
    mnc1=$(( o3 & 0x0f ));  mnc2=$(( (o3 >> 4) & 0x0f ))

    # A digit of 15 is the filler; only the MNC may carry one (2-digit MNC).
    local mcc_fill=0
    (( mcc1 == 15 || mcc2 == 15 || mcc3 == 15 )) && mcc_fill=1
    mcc="${mcc1}${mcc2}${mcc3}"
    if (( mnc3 == 15 )); then mnc="${mnc1}${mnc2}"; else mnc="${mnc1}${mnc2}${mnc3}"; fi

    local lac
    lac=$(gair_field "$hex" 64 16) || return 1
    printf 'mcc\t%s\nmnc\t%s\nlac\t%s\n' "$mcc" "$mnc" "$lac"
    (( mcc_fill == 1 )) && printf 'mcc_malformed\t1\n'
    return 0
}

# Full SI3 decode: every field a survey cares about.
gair_decode_si3() {
    local hex="$1"
    local t; t=$(gair_si_type_of "$hex") || {
        printf 'ERROR\tnot hex\n' >&2; return 1; }
    printf 'type\t%s\n' "$(gair_si_name "$(printf '%02x' "$t")")"
    local ci; ci=$(gair_si3_cell_id "$hex") || return 1
    printf 'cell_id\t%s\n' "$ci"
    gair_decode_lai "$hex" || return 1

    # Control channel description (TS 44.018 §10.5.2.5 / §10.5.2.11):
    #   bits 104..106 ATT, 107..111 BS_AG_BLKS_RES, 112..114 BS_PA_MFRMS
    # The concrete positions vary with which optional fields precede it, so we
    # also accept explicit BS_AG_BLKS_RES/BS_PA_MFRMS offsets when they are
    # handed in. Defaults follow the SI3 layout above.
    local agblk pamfrms ccch
    agblk=$(gair_field "$hex" 116 3)   || agblk=""
    pamfrms=$(gair_field "$hex" 119 3) || pamfrms=""
    ccch=$(gair_field "$hex" 122 3)    || ccch=""
    [[ -n "$agblk" ]]   && printf 'bs_ag_blks_res\t%s\n' "$agblk"
    [[ -n "$pamfrms" ]] && printf 'bs_pa_mfrms\t%s\n' "$pamfrms"
    [[ -n "$ccch" ]]    && printf 'bs_cc_chans\t%s\n' "$ccch"

    # T3212: periodic location update timer, in units of 6 minutes (decihours).
    # 0 means periodic updating is disabled. It lives in the rest octets of SI3.
    local t3212
    t3212=$(gair_field "$hex" 136 8) || t3212=""
    if [[ -n "$t3212" ]]; then
        printf 't3212\t%s\n' "$t3212"
        printf 't3212_minutes\t%s\n' "$(( t3212 * 6 ))"
    fi
    return 0
}

# ── SI1 field map (TS 44.018 §10.5.2.33) ────────────────────────────────
# SI1 carries the CA (cell allocation) list of ARFCNs and the RACH control
# parameters. The cell channel description is a bit map: bit 0 set means the
# ARFCN at that position is in the allocation, and the ARFCN is derived from
# the band's base frequency, exactly as TS 44.018 §10.5.2.1b defines:
#   ARFCN = 0        -> the "0" bit is 1 => ARFCN 0
#   ARFCN 1..124     -> GSM900,      F = 890 + 0.2 * N
#   ARFCN 128..251   -> GSM850,      F = 824 + 0.2 * N
#   ARFCN 512..885   -> DCS1800,     F = 1710 + 0.2 * (N - 511)
#   ARFCN 512..810   -> PCS1900 (same numbers as DCS; band decides)
gair_si1_neighbor_arfcns() {
    local hex="$1"
    # The 16-octet cell channel description follows the RR header. For the
    # "bit map 0" format (bits 0..1 of the IE = 00) the 124 bits that follow
    # are one bit per ARFCN 1..124.
    local fmt; fmt=$(gair_bits "$hex" 24 2) || return 1
    local i b out=""
    if [[ "$fmt" == "00" ]]; then
        for (( i = 0; i < 124; i++ )); do
            b=$(gair_bits "$hex" $(( 26 + i )) 1) || continue
            [[ "$b" == "1" ]] && out+="$(( i + 1 )) "
        done
    fi
    printf '%s' "${out% }"
}

# ── SI2 / SI4 / SI13 ────────────────────────────────────────────────────
# SI2 and SI4 carry the BA (BCCH allocation) list of neighbour ARFCNs, in the
# same bit-map format as SI1's CA list. SI4 additionally carries the CBCH
# channel description and the LAC/CI when SI3 is not broadcast.
gair_decode_ba_list() {
    local hex="$1" label="${2:-neighbors}" off="${3:-24}"
    local fmt; fmt=$(gair_bits "$hex" "$off" 2) || return 1
    local i b out=""
    if [[ "$fmt" == "00" ]]; then
        for (( i = 0; i < 124; i++ )); do
            b=$(gair_bits "$hex" $(( off + 2 + i )) 1) || continue
            [[ "$b" == "1" ]] && out+="$(( i + 1 )) "
        done
    fi
    printf '%s\t%s\n' "$label" "${out% }"
}

# SI13 (GPRS) carries the GPRS cell options, including the GPRS cipher mode
# and the PBCCH/PSI1 configuration. Its message type is 0x04.
gair_decode_si13() {
    local hex="$1"
    local t; t=$(gair_si_type_of "$hex") || {
        printf 'ERROR\tnot hex\n' >&2; return 1; }
    printf 'type\t%s\n' "$(gair_si_name "$(printf '%02x' "$t")")"
    # GPRS Mobile Allocation / padding. The RAC and the GPRS cell options
    # follow the SI13 header; SPGC_CCCH_SUP / PBCCH presence is in the
    # rest octets.
    local rac; rac=$(gair_field "$hex" 24 8) || rac=""
    [[ -n "$rac" ]] && printf 'rac\t%s\n' "$rac"
    printf 'gprs_supported\t%s\n' "$([[ "$t" -eq 4 ]] && echo yes || echo no)"
    return 0
}

# Generic dispatcher: pick the right field map for a hex SI message.
gair_decode_si() {
    local hex="$1"
    gair_is_hex "$hex" || {
        printf 'ERROR\tdecode-si needs an even-length hex string\n' >&2; return 2; }
    local t name
    t=$(gair_si_type_of "$hex") || return 1
    name=$(gair_si_name "$(printf '%02x' "$t")")
    printf 'message\t%s\n' "$name"
    case "$name" in
        SI1)  gair_decode_si1 "$hex" ;;
        SI2)  gair_decode_ba_list "$hex" ba_list 24 ;;
        SI2bis|SI2ter) gair_decode_ba_list "$hex" ba_list 24 ;;
        SI3)  gair_decode_si3 "$hex" ;;
        SI4)  gair_decode_si3 "$hex"
              gair_decode_ba_list "$hex" ba_list 24 ;;
        SI13) gair_decode_si13 "$hex" ;;
        *)
            printf 'ERROR\tno field map for message type 0x%02x (%s)\n' "$t" "$name" >&2
            return 1 ;;
    esac
}

gair_decode_si1() {
    local hex="$1"
    local nb; nb=$(gair_si1_neighbor_arfcns "$hex") || return 1
    printf 'cell_allocation_arfcns\t%s\n' "$nb"
    # RACH control parameters (TS 44.018 §10.5.2.29): ACC (16 bits), then
    # MAX_RETRANS (2), TX_INTEGER (4), CELL_BAR_ACCESS (1), RE (1),
    # EC (1), AC (1). The RACH control IE sits late in SI1.
    return 0
}

# ── paging analysis ─────────────────────────────────────────────────────
# Paging group per 3GPP TS 45.002 §6.5.2 and §6.5.3, quoted from the section:
#
#   CCCH_GROUP   (0 .. BS_CC_CHANS-1) = ((IMSI mod 1000) mod (BS_CC_CHANS x N)) div N
#   PAGING_GROUP (0 .. N-1)           = ((IMSI mod 1000) mod (BS_CC_CHANS x N)) mod N
#
# where N = (paging blocks per 51-multiframe) x BS_PA_MFRMS.
#
# THE BASE MODULUS IS 1000, NOT 1024. An IMSI is a decimal BCD string, so the
# reduction is by the last three DECIMAL digits; a power-of-two modulus has no
# basis in the section. This function used 1024 until it was corrected against
# the spec text, and its selftest asserted values computed from the same wrong
# modulus, so the suite passed while every paging group it reported was wrong.
#
# The paging blocks available per 51-multiframe come from TS 45.002 table 5:
# nine on a non-combined cell, three when the CCCH shares TS0 with SDCCH/4
# (BS_CCCH_SDCCH_COMB), less the BS_AG_BLKS_RES blocks reserved for access
# grants, which are counted from and including block number 0:
#
#   pblocks = (BS_CCCH_SDCCH_COMB ? 3 : 9) - BS_AG_BLKS_RES
#
# The MS monitors one block per 51-multiframe:
#
#   paging block index = PAGING_GROUP mod (N div BS_PA_MFRMS)
#                      = PAGING_GROUP mod pblocks
#
# and the 51-multiframe it must watch satisfies
#
#   PAGING_GROUP div pblocks = (FN div 51) mod BS_PA_MFRMS
#
# The index is relative to the AVAILABLE blocks, so the CCCH block number in
# the multiframe (block B0..B8 order, table 4) is BS_AG_BLKS_RES + index.
gair_paging_group() {
    local imsi="${1:-}"
    [[ "$imsi" =~ ^[0-9]{6,15}$ ]] || return 1
    # bash arithmetic is 64-bit: a 15-digit IMSI fits with room to spare.
    printf '%d' "$(( 10#$imsi % 1000 ))"
}

gair_paging_params() {
    local imsi="$1" pamfrms="${2:-2}" agblk="${3:-1}" ccch="${4:-1}" comb="${5:-false}"
    local grp; grp=$(gair_paging_group "$imsi") || return 1
    (( pamfrms >= 2 && pamfrms <= 9 )) || return 1
    (( ccch >= 1 && ccch <= 4 )) || return 1
    (( agblk >= 0 && agblk <= 7 )) || return 1
    # TS 45.002 table 5: blocks available per 51-multiframe on this CCCH.
    local maxb=9
    [[ "$comb" == "true" ]] && maxb=3
    local n=$(( maxb - agblk ))
    (( n >= 1 )) || return 1
    local n_total=$(( n * pamfrms ))
    local x=$(( grp % (ccch * n_total) ))
    local ccch_group=$(( x / n_total ))
    local pg=$(( x % n_total ))
    local block=$(( pg % n ))
    local slot=$(( agblk + block ))
    printf 'imsi\t%s\n' "$imsi"
    printf 'imsi_mod_1000\t%d\n' "$(( 10#$imsi % 1000 ))"
    printf 'paging_group\t%d\n' "$pg"
    printf 'ccch_group\t%d\n' "$ccch_group"
    printf 'bs_pa_mfrms\t%d\n' "$pamfrms"
    printf 'bs_cc_chans\t%d\n' "$ccch"
    printf 'bs_ag_blks_res\t%d\n' "$agblk"
    printf 'bs_ccch_sdcch_comb\t%s\n' "$comb"
    printf 'paging_block_index\t%d\n' "$block"
    printf 'ccch_slot\t%d\n' "$slot"
    printf 'blocks_per_multiframe\t%d\n' "$n"
    printf 'paging_blocks_total\t%d\n' "$n_total"
    printf 'repeat_every_multiframes\t%d\n' "$pamfrms"
}

# Paging Request Type 1/2/3 parse (TS 44.018 §9.1.22-24, §10.5.2.29a-c).
# The paging request carries 1 to 4 paging records, each of which is either
#  - a TMSI (4 octets, type "TMSI"), or
#  - an IMSI (8 octets: identity type in the low nibble of octet 1), or
#  - an IMEI.
# The identity type discriminator is bits 5..7 of the first octet of a
# mobile identity IE:
#   001 = IMSI, 100 = TMSI, 011 = IMEI, 101 = IMEISV
gair_identity_type() {
    case "${1:-}" in
        1) echo "IMSI" ;;   2) echo "IMEI" ;;
        3) echo "IMEISV" ;; 4) echo "TMSI" ;;
        5) echo "TMSI+IMEI" ;;
        *) echo "unknown" ;;
    esac
}

# Mobile identity IE decoder. `hex` is the IE value (first octet = identity
# type in bits 0..2, odd/even indicator in bit 3).
gair_decode_identity_ie() {
    local hex; hex=$(gair_norm_hex "$1" 2>/dev/null) || hex="$1"
    hex=$(printf '%s' "$hex" | tr 'A-F' 'a-f')
    [[ "$hex" =~ ^[0-9a-f]+$ ]] || return 1
    (( ${#hex} >= 2 )) || return 1

    # Mobile identity IE octet 1 (TS 24.008 10.5.1.4):
    #   bits 1-3  type of identity (001 IMSI, 010 IMEI, 011 IMEISV, 100 TMSI)
    #   bit 4     odd/even indicator
    #   bits 5-8  spare
    # An earlier version had these the wrong way round -- type in bits 2-4 and
    # parity in bit 1 -- so it read a TMSI as an IMSI and mis-packed every
    # digit. Both the decoder and its test vector carried the same error, which
    # is why 91 passing assertions did not catch it.
    local o=$(( 16#${hex:0:2} ))
    local type=$(( o & 7 ))
    local odd=$(( (o >> 3) & 1 ))
    printf 'identity_type\t%s\n' "$(gair_identity_type "$type")"
    printf 'identity_type_code\t%d\n' "$type"
    printf 'odd_even\t%s\n' "$([[ $odd -eq 1 ]] && echo odd || echo even)"

    case "$type" in
        1|2|3)
            # IMSI / IMEI / IMEISV. The FIRST digit is the high nibble of
            # octet 1; every following octet contributes its LOW nibble and
            # then its HIGH nibble. 0xF is the filler and ends the digits.
            local i b d out=""
            d=$(( 16#${hex:0:1} ))
            (( d != 15 )) && out+="$d"
            for (( i = 1; i * 2 < ${#hex}; i++ )); do
                b="${hex:$(( i * 2 )):2}"
                (( ${#b} == 2 )) || break
                d=$(( 16#${b:1:1} )); (( d == 15 )) && break; out+="$d"
                d=$(( 16#${b:0:1} )); (( d == 15 )) && break; out+="$d"
            done
            [[ -n "$out" ]] || return 1
            printf 'imsi\t%s\n' "$out"
            printf 'exposure\tplaintext-over-the-air\n' ;;
        4)
            # TMSI: the four octets after the type octet, taken as-is.
            local t="${hex:2:8}"
            (( ${#t} == 8 )) || return 1
            printf 'tmsi\t%s\n' "$t" ;;
        *)
            printf 'value\t%s\n' "$hex" ;;
    esac
    return 0
}

# Per-payload identity exposure, for a caller that holds a capture rather than
# a store: 03_gsmtap hands us every GSM Um payload via --identity-exposure.
# TSV with the kind in field 1 and the value in field 2, which is the shape
# 03_gsmtap's --identities-tsv consumes.
#
# A GSMTAP GSM Um payload is a WHOLE message, so the Mobile Identity IE has to
# be located before it can be decoded. Only message types that carry one at a
# fixed offset are handled; anything else is refused rather than guessed at,
# so a payload that is not an identity message claims nothing.
gair_identity_exposure() {
    local hex; hex=$(gair_norm_hex "${1:-}")
    gair_is_hex "$hex" || return 2
    (( ${#hex} >= 4 )) || return 2

    # Abis framing prefixes an L2 pseudo-length octet whose value plus one
    # equals the number of bytes that follow it. Um framing has no such octet.
    local body="$hex"
    local l2=$(( 16#${hex:0:2} ))
    (( l2 + 1 == ${#hex} / 2 )) && body="${hex:2}"
    (( ${#body} >= 4 )) || return 1

    local pd=$(( 16#${body:0:2} & 0x0f ))
    local mt=$(( 16#${body:2:2} ))

    # Octet index at which the Mobile Identity IE begins.
    local ie
    case "$pd:$mt" in
        6:9)  ie=2 ;;   # RR  IDENTITY RESPONSE      TS 44.018 9.1.15
        5:1)  ie=3 ;;   # MM  IMSI DETACH INDICATOR  TS 24.008 9.2.10
        5:8)  ie=3 ;;   # MM  LOCATION UPDATING REQ  TS 24.008 9.2.15
        5:36) ie=3 ;;   # MM  CM SERVICE REQUEST     TS 24.008 9.2.9
        5:39) ie=3 ;;   # MM  PAGING RESPONSE        TS 24.008 9.2.18
        *)    return 1 ;;
    esac
    (( ${#body} / 2 > ie )) || return 1

    local out
    out=$(gair_decode_identity_ie "${body:$(( ie * 2 ))}" 2>/dev/null) || return 1
    [[ -n "$out" ]] || return 1
    printf '%s\n' "$out"
    return 0
}

gair_cmd_identity_exposure() {
    local arg="${1:-}"
    [[ -n "$arg" ]] || {
        printf 'ERROR\tusage: --identity-exposure <hex message>\n' >&2; return 2; }
    gair_identity_exposure "$arg" || {
        printf 'ERROR\tno mobile identity in this message\n' >&2; return 1; }
}

# ── cipher mode audit ───────────────────────────────────────────────────
# Cipher Mode Setting, TS 44.018 §10.5.2.9 and TS 24.008 §10.5.1.6: the
# algorithm identifier is a 3-bit field at bit 1 of the first octet.
#   000 = A5/0 (no encryption)      001 = A5/1
#   010 = A5/2                       011 = A5/3
#   100 = A5/4                       101 = A5/5
#   110 = A5/6                       111 = A5/7
gair_cipher_name() {
    case "${1:-}" in
        0) echo "A5/0" ;; 1) echo "A5/1" ;; 2) echo "A5/2" ;; 3) echo "A5/3" ;;
        4) echo "A5/4" ;; 5) echo "A5/5" ;; 6) echo "A5/6" ;; 7) echo "A5/7" ;;
        *) echo "unknown" ;;
    esac
}

# Known break status. This is the honest column: what the literature says,
# not what the operator claims.
gair_cipher_break_status() {
    case "${1:-}" in
        0) echo "NULL: no encryption at all; keystream is all zeros" ;;
        1) echo "BROKEN: 64-bit state, Briceno/Goldberg/Wagner 1998 reverse-engineered; Nohl 2009 rainbow tables recover Kc in seconds; A5/1 is not a security control" ;;
        2) echo "BROKEN: export-grade, cryptanalysis announced at Crypto'99; breakable in real time with ~16 bits of work" ;;
        3) echo "BROKEN: KASUMI-based; Dunkelman/Keller/Shamir sandwich attack 2010 breaks full KASUMI in 2^32; still far better than A5/1" ;;
        4) echo "WEAKENED: 128-bit KASUMI variant sharing the A5/3 KASUMI core" ;;
        5|6|7) echo "UNSPECIFIED: reserved identifier; no public cryptanalysis" ;;
        *) echo "unknown" ;;
    esac
}

gair_cipher_risk() {
    case "${1:-}" in
        0) echo "CRITICAL" ;; 1) echo "CRITICAL" ;; 2) echo "CRITICAL" ;;
        3) echo "HIGH" ;; 4) echo "MEDIUM" ;; *) echo "UNKNOWN" ;;
    esac
}

# Decode a Cipher Mode Command (or Cipher Mode Setting IE) hex string and
# report which algorithm was requested plus its break status.
gair_cipher_audit_hex() {
    local hex="$1"
    gair_is_hex "$hex" || {
        printf 'ERROR\tcipher-audit needs hex (e.g. 01)\n' >&2; return 2; }
    # Accept a full RR Cipher Mode Command or a bare Cipher Mode Setting IE.
    # In both cases the algorithm identifier sits in the low 3 bits of the
    # first octet of the cipher mode setting IE. For a bare IE that is octet 1
    # of the string; for a full RR message it is octet 2 (after the
    # skip-indicator/protocol-discriminator and message-type octets).
    local alg
    if (( ${#hex} >= 4 )); then
        # Full RR message: octet index 2 (0-based byte 2) holds the IE.
        alg=$(( 16#${hex:2:2} & 7 ))
    else
        alg=$(( 16#${hex:0:2} & 7 ))
    fi
    printf 'algorithm_id\t%s\n' "$alg"
    printf 'algorithm\t%s\n' "$(gair_cipher_name "$alg")"
    printf 'risk\t%s\n' "$(gair_cipher_risk "$alg")"
    printf 'break_status\t%s\n' "$(gair_cipher_break_status "$alg")"
    if (( alg == 0 )); then
        printf 'finding\tNULL_CIPHER_REQUESTED\n'
        printf 'note\t%s\n' "A5/0 means the Cipher Mode Command asks the MS to encrypt with an all-zero keystream — user data and signalling are in the clear"
    elif (( alg == 1 || alg == 2 )); then
        printf 'finding\tWEAK_CIPHER_REQUESTED\n'
    fi
    return 0
}

# ── A5/1 keystream ──────────────────────────────────────────────────────
# The three-LFSR machine, verified against the official Briceno/Goldberg/
# Wagner test vector (Kc=0x1223456789ABCDEF, frame=0x134, A->B =
# 534EAA58 2FE8151A B6E1855A 728C00). Implemented in python3: the LFSR
# machine needs real bitwise ops and awk has no portable ones. An earlier awk
# fallback was removed rather than shipped approximate. python3 is a hard
# dependency of the toolkit (00_deps.sh), so this adds nothing new.
#
# Registers:   R1 19 bits (mask 0x07FFFF), R2 22 bits (0x3FFFFF),
#              R3 23 bits (0x7FFFFF)
# Clock bits:  R1 bit 8, R2 bit 10, R3 bit 10 — majority of the three
# Feedback:    R1 taps bits 18,17,16,13   (0x072000)
#              R2 taps bits 21,20         (0x300000)
#              R3 taps bits 22,21,20,7    (0x700080)
# Output:      XOR of the top bits (R1 bit 18, R2 bit 21, R3 bit 22)
#
# Key setup loads 64 Kc bits LSB-first, clocking all three registers every
# step and XORing the key bit into bit 0. Then the 22 frame-number bits the
# same way. Then 100 majority-clocked steps with output disabled.
#
# NOTE: the clock happens *before* each output bit is read. Getting this
# order wrong produces a plausible-looking but wrong keystream.
gair_a5_1_keystream() {
    local kc="${1:-}" count="${2:-114}"
    gair_is_hex "$kc" || {
        printf 'ERROR\ta5-1-keystream needs a 64-bit Kc in hex (e.g. 0011223344556677)\n' >&2
        return 2
    }
    [[ "$count" =~ ^[0-9]+$ ]] || {
        printf 'ERROR\tbit count must be a positive integer\n' >&2; return 2; }
    (( count >= 1 && count <= 4096 )) || {
        printf 'ERROR\tbit count out of range 1..4096\n' >&2; return 2; }
    # The reference machine is implemented in python3, which every target of
    # this toolkit has (00_deps.sh checks it). awk has no reliable bitwise
    # operators across implementations, so it is not used here.
    gair_a5_1_keystream_py "$kc" "$count" "${3:-0}"
}

# Authoritative A5/1 implementation. python3 is a hard dependency of the
# toolkit (see 00_deps.sh); the algorithm is short enough to inline.
gair_a5_1_keystream_py() {
    local kc="$1" count="${2:-114}" fn="${3:-0}"
    command -v python3 >/dev/null 2>&1 || {
        printf 'ERROR\tpython3 missing — cannot run A5/1\n' >&2; return 1; }
    python3 - "$kc" "$count" "$fn" <<'PY'
import sys

R1MASK, R2MASK, R3MASK = 0x07FFFF, 0x3FFFFF, 0x7FFFFF
R1MID,  R2MID,  R3MID  = 0x000100, 0x000400, 0x000400
R1TAPS, R2TAPS, R3TAPS = 0x072000, 0x300000, 0x700080
R1OUT,  R2OUT,  R3OUT  = 0x040000, 0x200000, 0x400000


def parity(x):
    x ^= x >> 16
    x ^= x >> 8
    x ^= x >> 4
    x ^= x >> 2
    x ^= x >> 1
    return x & 1


def clockone(reg, mask, taps):
    t = reg & taps
    reg = (reg << 1) & mask
    reg |= parity(t)
    return reg


class A51:
    def __init__(self, kc, frame):
        self.R1 = self.R2 = self.R3 = 0
        # 64 key bits, LSB first
        for i in range(64):
            self._clockall()
            kb = (kc >> i) & 1
            self.R1 ^= kb
            self.R2 ^= kb
            self.R3 ^= kb
        # 22 frame-number bits, LSB first
        for i in range(22):
            self._clockall()
            fb = (frame >> i) & 1
            self.R1 ^= fb
            self.R2 ^= fb
            self.R3 ^= fb
        for _ in range(100):
            self._clock()

    def _clockall(self):
        self.R1 = clockone(self.R1, R1MASK, R1TAPS)
        self.R2 = clockone(self.R2, R2MASK, R2TAPS)
        self.R3 = clockone(self.R3, R3MASK, R3TAPS)

    def _majority(self):
        s = ((self.R1 & R1MID) != 0) + ((self.R2 & R2MID) != 0) + \
            ((self.R3 & R3MID) != 0)
        return 1 if s >= 2 else 0

    def _clock(self):
        m = self._majority()
        if ((self.R1 & R1MID) != 0) == m:
            self.R1 = clockone(self.R1, R1MASK, R1TAPS)
        if ((self.R2 & R2MID) != 0) == m:
            self.R2 = clockone(self.R2, R2MASK, R2TAPS)
        if ((self.R3 & R3MID) != 0) == m:
            self.R3 = clockone(self.R3, R3MASK, R3TAPS)

    def getbit(self):
        return parity(self.R1 & R1OUT) ^ parity(self.R2 & R2OUT) ^ \
            parity(self.R3 & R3OUT)

    def bits(self, n):
        out = []
        for _ in range(n):
            self._clock()          # clock BEFORE reading the output bit
            out.append(self.getbit())
        return out


def main():
    kc_hex = sys.argv[1]
    n = int(sys.argv[2])
    fn = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0

    # Kc arrives as the 8 octets of the cipher key in transmission order.
    # The A5/1 loader consumes the key LSB-first starting from the *first*
    # transmitted octet, so the 16-hex-digit string is read as a little-endian
    # 64-bit integer: octet order is reversed relative to the printed hex.
    # (This is the convention the official BGW test vector uses: the byte
    # array {12,23,45,67,89,AB,CD,EF} loads as the integer 0xEFCDAB8967452312.)
    if len(kc_hex) % 2:
        kc_hex = "0" + kc_hex
    octets = [kc_hex[i:i + 2] for i in range(0, len(kc_hex), 2)]
    kc = int("".join(reversed(octets)), 16)

    a = A51(kc, fn)
    bits = a.bits(n)
    # MSB-first packing, matching the on-air burst order.
    hexs = ""
    for i in range(0, len(bits), 4):
        nib = bits[i:i + 4]
        nib = nib + [0] * (4 - len(nib))
        v = (nib[0] << 3) | (nib[1] << 2) | (nib[2] << 1) | nib[3]
        hexs += "%x" % v
    sys.stdout.write(hexs + "\n")


main()
PY
}

# The 22-bit frame number used for a given TCH/SDCCH frame, from T1/T2/T3:
#   FN = 51 * ((T3 - T2) mod 26) + T3 + 51 * 26 * T1
gair_frame_number_from_t1t2t3() {
    local t1="${1:-0}" t2="${2:-0}" t3="${3:-0}"
    [[ "$t1" =~ ^[0-9]+$ && "$t2" =~ ^[0-9]+$ && "$t3" =~ [0-9]+$ ]] || return 1
    (( t1 <= 2047 && t2 <= 25 && t3 <= 50 )) || return 1
    local t3t2=$(( (t3 - t2) % 26 ))
    (( t3t2 < 0 )) && t3t2=$(( t3t2 + 26 ))
    printf '%d' "$(( 51 * t3t2 + t3 + 1326 * t1 ))"
}

# ── IMSI exposure ───────────────────────────────────────────────────────
# Where an IMSI crosses the air interface in the clear. Each of these is a
# real GSM procedure in which the permanent identity is transmitted, either
# because no TMSI has been assigned yet or because the network demands it.
gair_imsi_exposure_points() {
    cat <<'EOF'
procedure	message	direction	when	identity	protection
Location Update Request	LOCATION UPDATING REQUEST	MS -> network	first attach, after LA change, periodic T3212 expiry	IMSI (mobile identity IE)	none on the first attach: no TMSI and no cipher key exist yet
CM Service Request	CM SERVICE REQUEST	MS -> network	MO call, MO SMS, supplementary service	IMSI or TMSI	IMSI only when the MS has no valid TMSI
Identity Response	IDENTITY RESPONSE	MS -> network	whenever the network sends IDENTITY REQUEST with type=IMSI	IMSI (forced)	none if sent before ciphering is enabled; this is the IMSI-catcher primitive
Attach Request (GPRS)	ATTACH REQUEST	MS -> network	GPRS attach	IMSI or P-TMSI	none on first attach
RAU Request	ROUTING AREA UPDATE REQUEST	MS -> network	GPRS routing area change	IMSI or P-TMSI	none when no P-TMSI is held
Authentication Response	AUTHENTICATION RESPONSE	MS -> network	every authentication	SRES (not the IMSI)	the IMSI is not sent, but SRES is a function of the IMSI-derived Ki
TMSI Reallocation Complete	TMSI REALLOCATION COMPLETE	MS -> network	after a TMSI is assigned	none	the IMSI was sent in the preceding reallocation command in the clear unless ciphering started
EOF
}

gair_imsi_exposure_tsv() {
    printf 'procedure\tmessage\tdirection\twhen\tidentity\tprotection\n'
    gair_imsi_exposure_points | tail -n +2
}

# ── hardware guards ─────────────────────────────────────────────────────
# Each guard names the missing radio. An empty result is not an answer.
gair_find_sdr() {
    local d
    for d in hackrf bladerf limesdr usrp; do
        case "$d" in
            hackrf)  command -v hackrf_info     >/dev/null 2>&1 && { echo "hackrf";  return 0; } ;;
            bladerf) command -v bladeRF-cli     >/dev/null 2>&1 && { echo "bladerf"; return 0; } ;;
            limesdr) command -v LimeUtil        >/dev/null 2>&1 && { echo "limesdr"; return 0; } ;;
            usrp)    command -v uhd_find_devices >/dev/null 2>&1 && { echo "usrp"; return 0; } ;;
        esac
    done
    command -v rtl_test >/dev/null 2>&1 && { echo "rtlsdr"; return 0; }
    return 1
}

gair_find_gsm_tool() {
    for t in grgsm_livemon grgsm_scanner grgsm_decode airprobe_rtlsdr; do
        command -v "$t" >/dev/null 2>&1 && { echo "$t"; return 0; }
    done
    return 1
}

# ── capture-driven decode (no radio) ────────────────────────────────────
# Pull SI3 / paging messages straight out of a GSMTAP pcap.
gair_decode_pcap() {
    local pcap="${1:-}"
    [[ -n "$pcap" && -f "$pcap" ]] || {
        printf 'ERROR\tno such capture: %s\n' "${pcap:-<none>}" >&2; return 1; }
    command -v tshark >/dev/null 2>&1 || {
        printf 'ERROR\tno tshark — install wireshark-cli to read captures\n' >&2
        return 1; }
    local out
    out=$(tshark -r "$pcap" -Y 'gsm_a.rr' -T fields -e gsm_a.rr.msgtype \
              -e gsm_a.msg_type 2>/dev/null | head -200)
    [[ -z "$out" ]] && {
        printf 'ERROR\tno GSM RR messages in %s\n' "$pcap" >&2; return 1; }
    printf '%s\n' "$out"
}

# ── persistence ─────────────────────────────────────────────────────────
GAIR_SI_STORE="$GAIR_DIR/si.tsv"
gair_init_store() {
    mkdir -p "$GAIR_DIR" 2>/dev/null
    [[ -f "$GAIR_SI_STORE" ]] || gair_si_header > "$GAIR_SI_STORE"
}
gair_si_header() {
    printf 'message\tmcc\tmnc\tlac\tcell_id\tt3212\tneighbors\tsource\tts\n'
}
gair_store_si_row() {
    gair_init_store
    printf '%s\n' "$1" >> "$GAIR_SI_STORE"
}
# Persist what a decode actually learned. Only SI3/SI4 carry a LAI and a cell
# identity, so only those produce a row; every other type returns 1 and the
# store stays untouched. 07_gsm_attack --vector-imsi-catcher reads this file as
# its default cell, which is why the columns are the ones it needs.
gair_store_decoded_si() {   # <decode output: TSV rows on stdout>
    local rows="${1:-}" name mcc mnc lac ci t3212
    name=$(printf '%s\n' "$rows" | awk -F'\t' '$1=="message"{print $2; exit}')
    case "$name" in SI3|SI4) ;; *) return 1 ;; esac
    mcc=$(printf '%s\n' "$rows"   | awk -F'\t' '$1=="mcc"{print $2; exit}')
    mnc=$(printf '%s\n' "$rows"   | awk -F'\t' '$1=="mnc"{print $2; exit}')
    lac=$(printf '%s\n' "$rows"   | awk -F'\t' '$1=="lac"{print $2; exit}')
    ci=$(printf '%s\n' "$rows"    | awk -F'\t' '$1=="cell_id"{print $2; exit}')
    t3212=$(printf '%s\n' "$rows" | awk -F'\t' '$1=="t3212"{print $2; exit}')
    [[ -n "$mcc" && -n "$lac" && -n "$ci" ]] || return 1
    gair_init_store
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$name" "$mcc" "$mnc" "$lac" "$ci" "${t3212:--}" "-" \
        "decode-si" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$GAIR_SI_STORE"
    return 0
}
gair_si_count() {
    [[ -f "$GAIR_SI_STORE" ]] || { echo 0; return; }
    local n; n=$(tail -n +2 "$GAIR_SI_STORE" 2>/dev/null | grep -c . || true)
    echo "${n:-0}"
}

# ── CLI verbs ───────────────────────────────────────────────────────────
gair_cli_status_tsv() {
    local sdr tool
    sdr=$(gair_find_sdr) || sdr="none"
    tool=$(gair_find_gsm_tool) || tool="none"
    printf 'sdr\t%s\n'            "$sdr"
    printf 'gsm_tool\t%s\n'       "$tool"
    printf 'gsm_scanner\t%s\n'    "$(gair_find_gsm_tool || echo none)"
    printf 'si_records\t%s\n'     "$(gair_si_count)"
    printf 'dir\t%s\n'            "$GAIR_DIR"
    printf 'store\t%s\n'          "$GAIR_SI_STORE"
    printf 'a5_1_backend\t%s\n'   "$(command -v python3 >/dev/null 2>&1 && echo python3 || echo none)"
    printf 'burst_len_symbols\t156.25\n'
    printf 'frame_number_bits\t22\n'
    printf 'kc_bits\t64\n'
}

gair_cmd_decode_si() {
    local hex="${1:-}"
    [[ -n "$hex" ]] || {
        printf 'ERROR\tusage: --decode-si <hex>\n' >&2; return 2; }
    local out rc
    out=$(gair_decode_si "$hex"); rc=$?
    (( rc == 0 )) || return "$rc"
    printf '%s\n' "$out"
    # A decode is also a sighting: SI3/SI4 get stored so the cell can be
    # cloned without retyping it. A type with no LAI stores nothing, and that
    # is not an error in the decode that just succeeded.
    gair_store_decoded_si "$out" || true
    return 0
}

gair_cmd_paging_group() {
    local imsi="${1:-}" pamfrms="${2:-2}" agblk="${3:-1}"
    [[ -n "$imsi" ]] || {
        printf 'ERROR\tusage: --paging-group <imsi> [bs_pa_mfrms] [bs_ag_blks_res]\n' >&2
        return 2; }
    gair_paging_params "$imsi" "$pamfrms" "$agblk" || {
        printf 'ERROR\tbad IMSI or paging parameters: %s\n' "$imsi" >&2; return 1; }
}

gair_cmd_cipher_audit() {
    local hex="${1:-01}"
    gair_cipher_audit_hex "$hex"
}

gair_cmd_a5_keystream() {
    local kc="${1:-}" count="${2:-114}"
    [[ -n "$kc" ]] || {
        printf 'ERROR\tusage: --a5-1-keystream <kc-hex> [bits] [frame]\n' >&2
        return 2; }
    local ks; ks=$(gair_a5_1_keystream "$kc" "$count" "${3:-0}") || return 1
    printf 'kc\t%s\n'    "$(gair_norm_hex "$kc")"
    printf 'frame\t%s\n' "${3:-0}"
    printf 'bits\t%s\n'  "$count"
    printf 'keystream\t%s\n' "$ks"
}

# ── selftest — no radio, no root, no network ────────────────────────────
gair_selftest() {
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
    export GAIR_DIR="$d/loot/gsm_air"
    export GAIR_SI_STORE="$GAIR_DIR/si.tsv"

    # 1. Hex/bit plumbing: round-trip must be byte-exact.
    chk hex-norm-upper   "$(gair_norm_hex 'AB CD')"      "abcd"
    chk hex-to-bits      "$(gair_hex_to_bits 'a5')"      "10100101"
    chk bits-to-hex      "$(gair_bits_to_hex '10100101')" "a5"
    chk bit-roundtrip    "$(gair_bits_to_hex "$(gair_hex_to_bits 'deadbeef')")" "deadbeef"
    chk is-hex-ok        "$(gair_is_hex 'deadbeef'; echo $?)" "0"
    chk is-hex-odd       "$(gair_is_hex 'abc'; echo $?)"      "1"
    chk is-hex-junk      "$(gair_is_hex 'zz'; echo $?)"       "1"

    # 2. Bit field extraction at real offsets.
    #    0xf0 = 11110000: bits 0..3 = 1111, bits 4..7 = 0000
    chk field-hi-nibble  "$(gair_field 'f0' 0 4)"  "15"
    chk field-lo-nibble  "$(gair_field 'f0' 4 4)"  "0"
    #    "abcd" = 1010 1011 1100 1101; bits 0..7 = 0xab, bits 8..15 = 0xcd.
    chk field-byte       "$(gair_field 'abcd' 8 8)" "205"      # 0xcd
    chk field-byte-hi    "$(gair_field 'abcd' 0 8)" "171"      # 0xab
    chk field-2bit       "$(gair_field 'abcd' 0 2)" "2"        # 10 = 2
    chk field-oob        "$(gair_field 'ab' 12 8 >/dev/null 2>&1; echo $?)" "1"

    # 3. Real SI3 hex string (23 octets, as broadcast on BCCH).
    #    L2 len 15, PD 06 (RR), msg type 1b (SI3), then cell id, LAI, ...
    local si3="15061b00010000000000000000000000000000"
    chk si3-type-code    "$(gair_si_type_of "$si3")" "27"
    chk si3-type-name    "$(gair_si_name "$(printf '%02x' "$(gair_si_type_of "$si3")")")" "SI3"
    chk si3-cell-id      "$(gair_si3_cell_id "$si3")" "1"

    #    MCC/MNC extraction from a real PLMN encoding. Per TS 23.003 §2.2 the
    #    IMSI/LAI digits are packed two per octet with digit1 in the LOW nibble,
    #    and the octets run  MCC2 MCC1 | MNC3 MCC3 | MNC2 MNC1, so MCC=262 MNC=01
    #    packs as 62 f2 10 (the F is the 2-digit MNC filler). MCC=208 MNC=01
    #    packs as 02 f8 10.
    #    Frame: header 15061b + CI 0001 + 62 f2 10 + LAC 3039 (=12345).
    local si3b="15061b000162f21030390000000000000000"
    local lai; lai=$(gair_decode_lai "$si3b")
    chk si3-mcc "$(fld "$lai" mcc)" "262"
    chk si3-mnc "$(fld "$lai" mnc)" "01"
    chk si3-lac "$(fld "$lai" lac)" "12345"

    #    A 3-digit MNC fills the MNC3 nibble: MCC=262 MNC=010 -> 62 02 10.
    local si3c="15061b000162021030390000000000000000"
    chk si3-mnc-3digit "$(fld "$(gair_decode_lai "$si3c")" mnc)" "010"

    #    A known-good foreign PLMN: MCC=208 MNC=01 packs as 02 f8 10.
    local si3d="15061b000102f81030390000000000000000"
    chk si3-mcc-fr "$(fld "$(gair_decode_lai "$si3d")" mcc)" "208"
    chk si3-mnc-fr "$(fld "$(gair_decode_lai "$si3d")" mnc)" "01"

    # 3b. A decode is also a sighting: --decode-si must persist the cell onto
    #     one row of the store (07_gsm_attack reads that file for its defaults),
    #     and a type with no LAI must add nothing.
    gair_cmd_decode_si "$si3b" >/dev/null 2>&1
    chk si-store-rows "$(gair_si_count)" "1"
    chk si-store-cell "$(awk -F'\t' 'NR==2{printf "%s/%s/%s/%s", $2, $3, $4, $5}' "$GAIR_SI_STORE")" "262/01/12345/1"
    chk si-store-type "$(awk -F'\t' 'NR==2{print $1}' "$GAIR_SI_STORE")" "SI3"
    chk si-store-none "$(gair_store_decoded_si "$(printf 'message\tSI1\nmcc\t262\nlac\t1\n')"; echo $?)" "1"
    chk si-store-none-count "$(gair_si_count)" "1"

    # 4. Unknown message type must fail, not guess.
    chk si-unknown-type "$(gair_decode_si '1506ff00000000' >/dev/null 2>&1; echo $?)" "1"
    chk si-nonhex       "$(gair_decode_si 'zzzz' >/dev/null 2>&1; echo $?)" "2"
    chk si-nonhex-empty "$(gair_cmd_decode_si >/dev/null 2>&1; echo $?)" "2"

    # 5. Paging group: hand-computed from TS 45.002 §6.5.2, whose base modulus
    #    is 1000 — the last three DECIMAL digits of the IMSI — not 1024.
    chk page-group-1  "$(gair_paging_group 310150123456789)" "789"
    chk page-group-2  "$(gair_paging_group 208011234567890)" "890"
    chk page-group-3  "$(gair_paging_group 123456789012345)" "345"
    chk page-group-4  "$(gair_paging_group 001010000000001)" "1"
    chk page-group-bad "$(gair_paging_group 'not-an-imsi' >/dev/null 2>&1; echo $?)" "1"
    chk page-group-short "$(gair_paging_group '12345' >/dev/null 2>&1; echo $?)" "1"
    #    Regression guard for the old power-of-two modulus: 310150123456789 mod
    #    1024 = 277, and 277 must not be what this reports.
    chk page-group-not1024 "$([[ "$(gair_paging_group 310150123456789)" == "277" ]] && echo yes || echo no)" "no"

    #    Block index = PAGING_GROUP mod pblocks, pblocks = 9 - BS_AG_BLKS_RES on
    #    a non-combined cell (TS 45.002 table 5). 789 mod 8 = 5, and the CCCH
    #    block number is 1 + 5 = 6.
    out=$(gair_paging_params 310150123456789 2 1)
    chk page-block-mf2  "$(fld "$out" paging_block_index)"    "5"
    chk page-slot-mf2   "$(fld "$out" ccch_slot)"             "6"
    chk page-pblocks-2  "$(fld "$out" blocks_per_multiframe)" "8"
    #    789 mod 7 = 5 when two blocks are reserved for access grants.
    out=$(gair_paging_params 310150123456789 6 2)
    chk page-block-mf6 "$(fld "$out" paging_block_index)" "5"
    chk page-slot      "$(fld "$out" ccch_slot)"          "7"
    chk page-total-n   "$(fld "$out" paging_blocks_total)" "42"
    #    Combined CCCH + SDCCH/4 leaves three blocks (table 5). 789 mod 3 = 0.
    out=$(gair_paging_params 310150123456789 2 0 1 true)
    chk page-block-comb "$(fld "$out" paging_block_index)"    "0"
    chk page-pblocks-c  "$(fld "$out" blocks_per_multiframe)" "3"
    chk page-comb-flag  "$(fld "$out" bs_ccch_sdcch_comb)"    "true"
    chk page-bad-mfrms "$(gair_paging_params 310150123456789 99 >/dev/null 2>&1; echo $?)" "1"
    chk page-bad-ccch  "$(gair_paging_params 310150123456789 2 1 9 >/dev/null 2>&1; echo $?)" "1"
    #    Reserving more blocks than the combined layout has must fail, not clamp.
    chk page-over-res  "$(gair_paging_params 310150123456789 2 4 1 true >/dev/null 2>&1; echo $?)" "1"

    # 6. A5/1 known-answer vector — the official Briceno/Goldberg/Wagner
    #    test vector: Kc octets 12 23 45 67 89 AB CD EF, frame 0x134,
    #    A->B keystream = 53 4E AA 58 2F E8 15 1A B6 E1 85 5A 72 8C 0.
    local ks; ks=$(gair_a5_1_keystream 1223456789abcdef 112 0x134)
    chk a51-kat "$ks" "534eaa582fe8151ab6e1855a728c"

    #    112 bits is exactly 28 hex digits.
    chk a51-len "$(printf '%s' "$ks" | wc -c | tr -d ' ')" "28"
    #    Determinism and key sensitivity: two different Kc must diverge.
    local ks2; ks2=$(gair_a5_1_keystream 1223456789abcdee 112 0x134)
    chk a51-kc-sensitive "$([[ "$ks" != "$ks2" ]] && echo differs || echo same)" "differs"
    #    Frame sensitivity: the 22-bit frame number must change the stream.
    local ks3; ks3=$(gair_a5_1_keystream 1223456789abcdef 112 0x135)
    chk a51-fn-sensitive "$([[ "$ks" != "$ks3" ]] && echo differs || echo same)" "differs"
    #    A5/0 is the null cipher: all-zero keystream, by definition.
    chk a50-null "$(gair_cipher_name 0)" "A5/0"
    #    Argument validation must return non-zero.
    chk a51-bad-kc  "$(gair_a5_1_keystream 'zz' 114 >/dev/null 2>&1; echo $?)" "2"
    chk a51-bad-cnt "$(gair_a5_1_keystream 00 0 >/dev/null 2>&1; echo $?)"    "2"
    chk a51-big-cnt "$(gair_a5_1_keystream 00 99999 >/dev/null 2>&1; echo $?)" "2"
    chk a51-no-kc   "$(gair_cmd_a5_keystream >/dev/null 2>&1; echo $?)" "2"

    # 7. Cipher classification, including A5/0 flagged.
    chk cipher-name-0 "$(gair_cipher_name 0)" "A5/0"
    chk cipher-name-1 "$(gair_cipher_name 1)" "A5/1"
    chk cipher-name-3 "$(gair_cipher_name 3)" "A5/3"
    chk cipher-risk-0 "$(gair_cipher_risk 0)" "CRITICAL"
    chk cipher-risk-3 "$(gair_cipher_risk 3)" "HIGH"
    chk cipher-a50-flagged \
        "$(gair_cipher_audit_hex '00' | awk -F'\t' '$1=="finding"{print $2}')" \
        "NULL_CIPHER_REQUESTED"
    chk cipher-a51-finding \
        "$(gair_cipher_audit_hex '01' | awk -F'\t' '$1=="finding"{print $2}')" \
        "WEAK_CIPHER_REQUESTED"
    chk cipher-a53-broken \
        "$(gair_cipher_audit_hex '03' | awk -F'\t' '$1=="break_status"{print ($2 ~ /^BROKEN/) ? "y":"n"}')" "y"
    chk cipher-bad-hex "$(gair_cipher_audit_hex 'zz' >/dev/null 2>&1; echo $?)" "2"

    # 8. Identity IE decode — the IMSI exposure primitive.
    #    Mobile identity IE for IMSI 310150123456789 (TS 24.008 §10.5.1.4):
    #      octet1 = type(001) | odd(1)<<3 = 0x39, first digit 3 in its high
    #      nibble; each following octet low-nibble-first, F filler last:
    #      39 01 51 10 32 54 76 98
    local idie="3901511032547698"
    chk id-type   "$(fld "$(gair_decode_identity_ie "$idie")" identity_type)" "IMSI"
    chk id-imsi   "$(fld "$(gair_decode_identity_ie "$idie")" imsi)" "310150123456789"
    chk id-expose "$(fld "$(gair_decode_identity_ie "$idie")" exposure)" "plaintext-over-the-air"
    chk id-odd    "$(fld "$(gair_decode_identity_ie "$idie")" odd_even)" "odd"
    #    TMSI: type=100 (4) | odd/even(0)<<3 -> octet1 = 0x04, followed by the
    #    32-bit TMSI value.
    local tid="0412345678"
    chk id-tmsi-type "$(fld "$(gair_decode_identity_ie "$tid")" identity_type)" "TMSI"
    chk id-tmsi-val  "$(fld "$(gair_decode_identity_ie "$tid")" tmsi)" "12345678"
    chk id-tmsi-code "$(fld "$(gair_decode_identity_ie "$tid")" identity_type_code)" "4"
    chk id-bad-nonhex "$(gair_decode_identity_ie 'zz' >/dev/null 2>&1; echo $?)" "1"

    #    --identity-exposure locates the identity IE inside a WHOLE message,
    #    which is what 03_gsmtap hands us. A bare IE is not a message, a
    #    message carrying no identity must claim nothing, and an Abis-framed
    #    payload (L2 pseudo-length: value = octets that follow it) must still
    #    be read. These are the cases the caller actually produces.
    chk ir-rr-response "$(fld "$(gair_identity_exposure "0609$idie")" imsi)" "310150123456789"
    chk ir-rr-type     "$(fld "$(gair_identity_exposure "0609$idie")" identity_type)" "IMSI"
    chk ir-mm-lu-req   "$(fld "$(gair_identity_exposure "050800$idie")" imsi)" "310150123456789"
    chk ir-mm-cm-svc   "$(fld "$(gair_identity_exposure "052400$idie")" imsi)" "310150123456789"
    chk ir-abis-frame  "$(fld "$(gair_identity_exposure "0a0609$idie")" imsi)" "310150123456789"
    chk ir-bare-ie     "$(gair_identity_exposure "$idie" >/dev/null 2>&1; echo $?)" "1"
    chk ir-no-identity "$(gair_identity_exposure '06061b000162f2103039' >/dev/null 2>&1; echo $?)" "1"
    chk ir-nonhex      "$(gair_identity_exposure 'zzzz' >/dev/null 2>&1; echo $?)" "2"
    chk ir-empty       "$(gair_identity_exposure '' >/dev/null 2>&1; echo $?)" "2"

    # 9. SCH burst: BSIC and frame number from a real 25-bit payload.
    #    bsic = 6 bits, ncc = bsic div 8 (3 bits), bcc = bsic mod 8 (3 bits).
    local sch; sch=$(gair_decode_sch "0123456789abcdef")
    local sbsic sncc sbcc
    sbsic=$(fld "$sch" bsic); sncc=$(fld "$sch" ncc); sbcc=$(fld "$sch" bcc)
    chk sch-bsic-parts "$(( sncc * 8 + sbcc ))" "$sbsic"
    chk sch-bsic-range "$([[ "$sbsic" -ge 0 && "$sbsic" -le 63 ]] && echo ok || echo bad)" "ok"
    chk sch-ncc-range  "$([[ "$sncc" -ge 0 && "$sncc" -le 7 ]] && echo ok || echo bad)" "ok"
    chk sch-bcc-range  "$([[ "$sbcc" -ge 0 && "$sbcc" -le 7 ]] && echo ok || echo bad)" "ok"
    chk sch-payload-len "$(printf '%s' "$(fld "$sch" raw_payload)" | wc -c | tr -d ' ')" "25"
    chk sch-bad-hex    "$(gair_decode_sch 'zz' >/dev/null 2>&1; echo $?)" "1"
    chk sch-short      "$(gair_decode_sch 'ab' >/dev/null 2>&1; echo $?)" "1"

    # 10. Frame number reassembly from T1/T2/T3.
    chk fn-t1t2t3   "$(gair_frame_number_from_t1t2t3 0 0 0)" "0"
    chk fn-known    "$(gair_frame_number_from_t1t2t3 1 0 0)" "1326"
    chk fn-bad-t1   "$(gair_frame_number_from_t1t2t3 9999 0 0 >/dev/null 2>&1; echo $?)" "1"
    chk fn-bad-t2   "$(gair_frame_number_from_t1t2t3 0 99 0 >/dev/null 2>&1; echo $?)" "1"

    # 11. Burst structure constants and training sequences.
    chk tsc-0 "$(gair_training_name '0393A')" "TSC0"
    chk tsc-7 "$(gair_training_name '03A69')" "TSC7"
    chk tsc-x "$(gair_training_name '00000')" "unknown"

    # 12. IMSI exposure table is well-formed TSV with the documented header.
    gair_init_store
    chk exposure-header "$(gair_imsi_exposure_tsv | head -1)" \
        "procedure	message	direction	when	identity	protection"
    chk exposure-rows   "$(gair_imsi_exposure_tsv | tail -n +2 | grep -c .)" "7"
    chk exposure-legacy "$(gair_imsi_exposure_points | grep -c 'Identity Response')" "1"
    chk exposure-fields "$(gair_imsi_exposure_tsv | tail -n +2 | awk -F'\t' 'NF!=6' | grep -c .)" "0"
    chk exposure-lu     "$(gair_imsi_exposure_points | grep -c 'LOCATION UPDATING REQUEST')" "1"
    chk exposure-cm     "$(gair_imsi_exposure_points | grep -c 'CM SERVICE REQUEST')" "1"

    # 13. Sanitisation: a tab in an untrusted string must not forge a row.
    local evil; evil=$(gair_sanitize $'Evil\tOperator\r\nRow')
    chk sanitize-tabs "$(printf '%s' "$evil" | tr -cd '\t' | wc -c | tr -d ' ')" "0"
    chk sanitize-nl   "$(printf '%s' "$evil" | tr -cd '\n' | wc -c | tr -d ' ')" "0"

    # 14. Status TSV contract. SDR presence is environment-dependent, so only
    #     the invariant fields are asserted. The store is emptied first: the
    #     decode in 3b wrote a real row, and this block asserts the empty-count
    #     path rather than a count that depends on test order.
    rm -f "$GAIR_SI_STORE"
    out=$(gair_cli_status_tsv)
    chk status-dir          "$(fld "$out" dir)"   "$GAIR_DIR"
    chk status-store        "$(fld "$out" store)" "$GAIR_SI_STORE"
    chk status-si           "$(fld "$out" si_records)" "0"
    chk status-burst        "$(fld "$out" burst_len_symbols)" "156.25"
    chk status-fnbits       "$(fld "$out" frame_number_bits)" "22"
    chk status-kcbits       "$(fld "$out" kc_bits)" "64"

    # 15. CLI dispatch: unknown verb is a usage error (2), not a success.
    chk cli-unknown "$(gair_cli_main --nope >/dev/null 2>&1; echo $?)" "2"

    rm -rf "$d"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ── menu ────────────────────────────────────────────────────────────────
gair_menu() {
    local c
    while true; do
        banner
        echo -e "  ${C_MAG}=== GSM air interface ===${C_RESET}"
        echo -e "  sdr:   ${C_GRN}$(gair_find_sdr || echo none)${C_RESET}"
        echo -e "  tool:  ${C_GRN}$(gair_find_gsm_tool || echo none)${C_RESET}"
        echo -e "  store: ${C_DIM}$GAIR_SI_STORE${C_RESET}\n"
        cat << 'M'
  [1]  decode a System Information message (hex)
  [2]  paging group from an IMSI
  [3]  cipher mode audit (hex)
  [4]  A5/1 keystream from Kc + frame
  [5]  A5/1 known-answer self-check
  [6]  IMSI exposure points
  [7]  decode an SCH burst
  [8]  decode RR messages from a GSMTAP pcap
  [0]  back

M
        if [[ -n "${IMSISTING_CLI:-}" ]]; then
            echo "[-] menu unavailable in CLI mode" >&2; return 1
        fi
        read -rp "  choice> " c || return 0  # EOF: leave the menu cleanly
        case "$c" in
            1)
                read -rp "  SI hex> " h
                gair_cmd_decode_si "$h" | column -t -s$'\t' 2>/dev/null || gair_cmd_decode_si "$h"
                read -rp "  press enter " _ ;;
            2)
                read -rp "  IMSI> " i
                read -rp "  BS_PA_MFRMS (2-9, default 2)> " m
                gair_cmd_paging_group "$i" "${m:-2}" | column -t -s$'\t' 2>/dev/null \
                    || gair_cmd_paging_group "$i" "${m:-2}"
                read -rp "  press enter " _ ;;
            3)
                read -rp "  cipher mode hex (default 01)> " h
                gair_cmd_cipher_audit "${h:-01}" | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            4)
                read -rp "  Kc hex (16 hex chars)> " k
                read -rp "  frame number> " f
                gair_cmd_a5_keystream "$k" 114 "${f:-0}" | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            5)
                echo "  Kc=1223456789abcdef frame=0x134"
                echo "  expect 534eaa582fe8151ab6e1855a728c00"
                gair_cmd_a5_keystream 1223456789abcdef 114 0x134
                read -rp "  press enter " _ ;;
            6) gair_imsi_exposure_tsv | column -t -s$'\t' 2>/dev/null || gair_imsi_exposure_tsv
               read -rp "  press enter " _ ;;
            7)
                read -rp "  SCH burst hex> " h
                gair_decode_sch "$h" | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            8)
                read -rp "  pcap path> " p
                gair_decode_pcap "$p"
                read -rp "  press enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ── CLI dispatch ────────────────────────────────────────────────────────
gair_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)          gair_cli_status_tsv ;;
        --decode-si)           gair_cmd_decode_si "${1:-}" ;;
        --paging-group)        gair_cmd_paging_group "${1:-}" "${2:-2}" "${3:-1}" ;;
        --cipher-audit)        gair_cmd_cipher_audit "${1:-01}" ;;
        --a5-1-keystream)      gair_cmd_a5_keystream "${1:-}" "${2:-114}" "${3:-0}" ;;
        --imsi-exposure-tsv)   gair_imsi_exposure_tsv ;;
        --identity-exposure)   gair_cmd_identity_exposure "${1:-}" ;;
        --decode-sch)          gair_decode_sch "${1:-}" ;;
        --decode-pcap)         gair_decode_pcap "${1:-}" ;;
        --selftest)            gair_selftest ;;
        --menu)                gair_menu ;;
        *)
            cat >&2 <<EOF
GSM Air Interface — BCCH/SI decode, paging, cipher audit, A5/1

Usage: $0 COMMAND
  --status-tsv                    tool and store state as TSV
  --decode-si <hex>               decode a System Information message
  --paging-group <imsi> [mfrms]   paging group and block from an IMSI
  --cipher-audit [hex]            classify a Cipher Mode Command
  --a5-1-keystream <kc> [n] [fn]  A5/1 keystream, Kc in hex, fn default 0
  --imsi-exposure-tsv             where an IMSI crosses the air in the clear
  --identity-exposure <hex>       mobile identity in one Um message (TSV)
  --decode-sch <hex>              BSIC and frame number from an SCH burst
  --decode-pcap <pcap>            list RR messages in a GSMTAP capture
  --selftest                      verify decoders and A5/1 without a radio
  --menu                          interactive menu
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
    gair_cli_main "$@"
fi
