#!/usr/bin/env bash
# umts air interface — UARFCN, SIB decode, RRC integrity, AKA relay analysis
#
# Everything that decodes or derives here is pure computation: no radio, no
# root, no network. The UARFCN arithmetic, the SIB field maps, the UIA1/UIA2
# MAC-I input assembly and the AKA flow are all real; the only handoff is
# actually transmitting or intercepting a NodeB, which names its hardware.
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

MOD_TMP="$TMP_DIR/umts_air"
UAIR_DIR="$LOOT_DIR/umts_air"
mkdir -p "$MOD_TMP" "$UAIR_DIR" 2>/dev/null

# Shared cross-module state — other modules read these.
UAIR_SDR="${TMP_DIR}/sdr_device"
UAIR_UARFCN="${TMP_DIR}/target_uarfcn"
UAIR_PLMN="${TMP_DIR}/target_plmn"

# ── sanitisation ────────────────────────────────────────────────────────
uair_sanitize() {
    printf '%s' "${1:-}" | tr '\t\r\n' '   '
}

# ── hex helpers (shared contract with the other air-interface modules) ──
uair_norm_hex() {
    printf '%s' "${1:-}" | tr -d ' \t\r\n:.-' | sed 's/^0x//I' | tr 'A-F' 'a-f'
}
uair_is_hex() {
    local h; h=$(uair_norm_hex "${1:-}")
    [[ -n "$h" && "$h" =~ ^[0-9a-f]+$ && $(( ${#h} % 2 )) -eq 0 ]]
}
uair_hex_to_bits() {
    local h; h=$(uair_norm_hex "${1:-}")
    local i out=""
    for (( i = 0; i < ${#h}; i++ )); do
        case "${h:i:1}" in
            0) out+=0000 ;; 1) out+=0001 ;; 2) out+=0010 ;; 3) out+=0011 ;;
            4) out+=0100 ;; 5) out+=0101 ;; 6) out+=0110 ;; 7) out+=0111 ;;
            8) out+=1000 ;; 9) out+=1001 ;; a) out+=1010 ;; b) out+=1011 ;;
            c) out+=1100 ;; d) out+=1101 ;; e) out+=1110 ;; f) out+=1111 ;;
            *) return 1 ;;
        esac
    done
    printf '%s' "$out"
}
uair_bits() {
    local hex="$1" off="$2" len="$3"
    local bits; bits=$(uair_hex_to_bits "$hex") || return 1
    (( off + len <= ${#bits} )) || return 1
    printf '%s' "${bits:off:len}"
}
# Bit string -> hex, zero-padded to a whole octet. Needed to build test blobs
# and to render a field that does not start on a nibble boundary.
uair_bits_to_hex() {
    local bits="${1:-}"
    # Pad to a whole octet: a SIB blob is transmitted as bytes, so a bit
    # string that ends mid-octet must be zero-filled to the octet boundary.
    while (( ${#bits} % 8 != 0 )); do bits+="0"; done
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
# Decimal -> fixed-width binary string, zero-padded. Used to build test
# blobs and to place a field at a known bit offset. Avoids depending on bc.
uair_bin() {
    local v="${1:-0}" width="${2:-8}"
    [[ "$v" =~ ^[0-9]+$ && "$width" =~ ^[1-9][0-9]*$ ]] || return 1
    local out=""
    local i
    for (( i = width - 1; i >= 0; i-- )); do
        out+=$(( (v >> i) & 1 ))
    done
    printf '%s' "$out"
}

uair_field() {
    local hex="$1" off="$2" len="$3"
    local b; b=$(uair_bits "$hex" "$off" "$len") || return 1
    (( len <= 63 )) || return 1
    [[ -z "$b" ]] && { echo 0; return 1; }
    printf '%d' "$(( 2#$b ))"
}

# ── UARFCN arithmetic ───────────────────────────────────────────────────
# TS 25.101 section 5.4. The carrier frequency is designated by the UTRA
# Absolute Radio Frequency Channel Number. The channel raster is 200 kHz for
# every UMTS band, so a UARFCN counts 200 kHz steps:
#
#     F(MHz) = 0.2 * N        equivalently     N = 5 * F
#
# The same relation written as N = 5 * (F - F_offset) is the per-band form,
# where F_offset shifts the origin so the counting starts at the band edge;
# with F_offset = 0 it reduces to F = N/5 = 0.2*N. Verified against the band
# edges: band I carriers span 10562..10838 -> 2112.4..2167.6 MHz, sitting
# inside the 2110..2170 MHz band as expected (the outer 2.4 MHz is the band
# edge, not a carrier centre).
#
# The 5 MHz raster reading of the same numbers is the "N in 5 MHz units"
# form: F = 5 * N' would hold only if N' counted 1 MHz steps. Both forms are
# implemented below and are labelled so a reader cannot confuse them.
UAIR_RASTER_KHZ=200

uair_uarfcn_to_mhz() {
    local n="${1:-}"
    [[ "$n" =~ ^[0-9]+$ ]] || {
        printf 'ERROR\tUARFCN must be a non-negative integer\n' >&2; return 2; }
    (( n >= 0 && n <= 16383 )) || {
        printf 'ERROR\tUARFCN %s out of range 0..16383\n' "$n" >&2; return 2; }
    # 200 kHz per step -> divide by 5 for MHz.
    awk -v n="$n" 'BEGIN{printf "%.1f", n / 5.0}'
}

# The 5 MHz-raster form: for a raster measured in whole MHz this is F = 5 * N.
# Kept explicit because the two readings differ by a factor of 25.
uair_uarfcn_to_mhz_5mhz_raster() {
    local n="${1:-}"
    [[ "$n" =~ ^[0-9]+$ ]] || {
        printf 'ERROR\tUARFCN must be a non-negative integer\n' >&2; return 2; }
    awk -v n="$n" 'BEGIN{printf "%.1f", 5.0 * n}'
}

uair_mhz_to_uarfcn() {
    local f="${1:-}"
    [[ "$f" =~ ^[0-9]+(\.[0-9]+)?$ ]] || {
        printf 'ERROR\tfrequency must be a non-negative number in MHz\n' >&2; return 2; }
    awk -v f="$f" 'BEGIN{
        n = f * 5.0
        r = int(n + 0.5)
        # Report the rounding error so a non-raster frequency is visible.
        printf "uarfcn\t%d\nexact\t%.4f\nrounding_error_khz\t%.1f\n", r, n, (n - r) * 200.0
    }'
}

# Per-band validity, TS 25.101 table 5.4 (the bands a survey actually meets).
# N ranges are the carrier-centre range: F_offset is the band edge and the
# outermost carrier sits 2.4 MHz inside it.
uair_band_of_uarfcn() {
    local n="${1:-}"
    [[ "$n" =~ ^[0-9]+$ ]] || return 1
    awk -v n="$n" 'BEGIN{
        # band -> name, N_dl_lo, N_dl_hi
        split("1 2100 10562 10838|2 1900 9662 9938|3 1800 1162 1513|" \
              "4 1700 1537 1738|5 850 4357 4458|6 850 4387 4413|" \
              "7 2600 2237 2563|8 900 2937 3088",
              bands, "|")
        for (i = 1; i <= length(bands); i++) {
            split(bands[i], b, " ")
            if (n >= b[3] && n <= b[4]) { printf "%s\t%s\n", b[1], b[2]; exit }
        }
        exit 1
    }'
}

uair_cmd_uarfcn() {
    local n="${1:-}"
    [[ -n "$n" ]] || {
        printf 'ERROR\tusage: --uarfcn <N>\n' >&2; return 2; }
    local f; f=$(uair_uarfcn_to_mhz "$n") || return $?
    printf 'uarfcn\t%s\n' "$n"
    printf 'raster_khz\t%s\n' "$UAIR_RASTER_KHZ"
    printf 'freq_mhz\t%s\n' "$f"
    local band; band=$(uair_band_of_uarfcn "$n") || band=""
    if [[ -n "$band" ]]; then
        printf 'band\t%s\n' "$(printf '%s' "$band" | cut -f1)"
        printf 'band_name_mhz\t%s\n' "$(printf '%s' "$band" | cut -f2)"
    else
        printf 'band\tunknown\n'
    fi
    return 0
}

# ── SIB decode ──────────────────────────────────────────────────────────
# UMTS System Information Blocks are carried in RRC SYSTEM INFORMATION
# messages on BCCH (BCH transport). Each SIB has a fixed field layout; the
# ones below are the ones a survey reads.
#
# SIB3 (TS 25.331 section 10.2.2.8.4): cell identity and cell selection.
#   The cell identity is a 28-bit value. In the ASN.1 it is
#   CellIdentity ::= BIT STRING (SIZE (28)).
# SIB5 (section 10.2.2.8.6): configuration of the common physical channels of
#   the cells to be considered for cell re-selection (the neighbour list).
# SIB6 (section 10.2.2.8.7): same for the cells in FDD mode on another
#   frequency, plus the UTRA carrier info.
# SIB7 (section 10.2.2.8.8): the uplink interference level and the dynamic
#   persistence level, refreshed on a timer.
# SIB11 (section 10.2.2.8.12): measurement control information for the
#   cells in the neighbour list, with per-cell measurement quantities.
# SIB12 (section 10.2.2.8.13): measurement control in connected mode.
#
# These SIBs are ASN.1 PER encoded, not fixed-offset bit fields, so a
# decode without the ASN.1 schema cannot honestly claim every field. What
# this module does decode for real is the SIB type tag and the fields whose
# position in the PER encoding is fixed by the schema's leading CHOICE.
uair_sib_name() {
    case "${1:-}" in
        1) echo "SIB1" ;;   2) echo "SIB2" ;;   3) echo "SIB3" ;;
        4) echo "SIB4" ;;   5) echo "SIB5" ;;   6) echo "SIB6" ;;
        7) echo "SIB7" ;;   8) echo "SIB8" ;;   9) echo "SIB9" ;;
        10) echo "SIB10" ;; 11) echo "SIB11" ;; 12) echo "SIB12" ;;
        13) echo "SIB13" ;; 14) echo "SIB14" ;; 15) echo "SIB15" ;;
        16) echo "SIB16" ;; 17) echo "SIB17" ;; 18) echo "SIB18" ;;
        *) echo "unknown" ;;
    esac
}

# What each SIB carries — the field map a reader needs before trusting a
# decoder. Emitted as TSV so it can be piped.
uair_sib_fields() {
    cat <<'EOF'
sib	carries	key_fields
SIB1	Core network and UE timers	cn_CommonInfo, T3212 (periodic location update timer), DRX cycle length coefficient
SIB2	URA identity	URA identity (UTRAN Registration Area) for URA_PCH state
SIB3	Cell identity and cell selection	CellIdentity (28 bits), CellIdentity is the CI; cell selection and re-selection quality measure, q-Hyst, Treselection
SIB4	Cell selection in connected mode	CellIdentity, same selection parameters for connected mode
SIB5	Common physical channels of intra-frequency neighbours	neighbour cell list: downlink scrambling codes, primary CPICH TX power, cell identity per neighbour
SIB6	Common physical channels of inter-frequency neighbours	UTRA carrier info (UARFCN), downlink scrambling code per neighbour, cell identity
SIB7	Uplink interference and persistence	UL interference level (dynamic, -110..-70 dBm), dynamic persistence level (expires, hence periodic refresh)
SIB8	Cell selection/reselection in FDD	CPICH Ec/No and RSCP measurement quantities, thresholds
SIB11	Measurement control in idle mode	measurement identity, measurement objects (intra/inter/RAT), reporting criteria, per-cell measurement quantities
SIB12	Measurement control in connected mode	same as SIB11 for CELL_DCH/CELL_FACH, plus the cell identity of the serving cell
SIB13	ANSF (application specific)	not security relevant
SIB18	PLMN identities of neighbours	PLMN identity per neighbour cell, for manual PLMN selection
EOF
}

uair_sib_fields_tsv() {
    printf 'sib\tcarries\tkey_fields\n'
    uair_sib_fields | tail -n +2
}

# Extract the SIB type tag. In an RRC SYSTEM INFORMATION message the SIBs are
# a SEQUENCE of SIB CHOICE values; the tag is the low 5 bits of the first
# octet after the message header. We report the tag and the raw payload, and
# decline to invent ASN.1 fields we cannot derive without the schema.
uair_decode_sib() {
    local hex="$1"
    uair_is_hex "$hex" || {
        printf 'ERROR\tdecode-sib needs an even-length hex string\n' >&2; return 2; }
    local bits; bits=$(uair_hex_to_bits "$hex") || return 1
    # A usable SIB blob is at least 2 octets: tag plus content.
    (( ${#bits} >= 16 )) || {
        printf 'ERROR\tshort SIB blob (%s bits), need at least 16\n' "${#bits}" >&2
        return 1; }
    printf 'raw\t%s\n' "$hex"
    printf 'octets\t%s\n' "$(( ${#bits} / 8 ))"
    local tag; tag=$(( 2#${bits:0:5} ))
    printf 'sib_tag\t%s\n' "$tag"
    printf 'sib\t%s\n' "$(uair_sib_name "$tag")"
    # SIB3 and SIB4 lead with the CellIdentity in the PER encoding once the
    # tag and the optional PLMN block are skipped; the 28-bit field is
    # reported at the schema-documented position within the content.
    if (( tag == 3 || tag == 4 )); then
        if (( ${#bits} >= 33 )); then
            local ci; ci=$(( 2#${bits:5:28} ))
            printf 'cell_identity\t%s\n' "$ci"
            printf 'cell_identity_bits\t28\n'
        fi
    fi
    # SIB7 carries the uplink interference level as a 6-bit field in the
    # value range -110..-70 dBm in 1 dB steps (TS 25.331 10.3.5.5).
    if (( tag == 7 )); then
        if (( ${#bits} >= 11 )); then
            local ue; ue=$(( 2#${bits:5:6} ))
            printf 'ul_interference_raw\t%s\n' "$ue"
            printf 'ul_interference_dbm\t%s\n' "$(( ue - 110 ))"
        fi
    fi
    local known
    known=$(uair_sib_fields | awk -F'\t' -v s="$(uair_sib_name "$tag")" '$1==s{print $2}')
    if [[ -n "$known" ]]; then
        printf 'carries\t%s\n' "$(uair_sanitize "$known")"
    else
        printf 'warning\tunknown SIB tag; content not interpreted\n'
    fi
    return 0
}

# ── UARFCN carrier list for SIB6 (real arithmetic) ──────────────────────
uair_sib6_carriers() {
    local first="${1:-}" count="${2:-}"
    [[ "$first" =~ ^[0-9]+$ && "$count" =~ ^[0-9]+$ ]] || {
        printf 'ERROR\tusage: --sib6-carriers <first-uarfcn> <count>\n' >&2; return 2; }
    (( count >= 1 && count <= 64 )) || {
        printf 'ERROR\tcount out of range 1..64\n' >&2; return 2; }
    local i n f
    printf 'index\tuarfcn\tfreq_mhz\n'
    for (( i = 0; i < count; i++ )); do
        n=$(( first + i * 25 ))      # adjacent 5 MHz carriers are 25 UARFCN apart
        f=$(uair_uarfcn_to_mhz "$n") || continue
        printf '%d\t%d\t%s\n' "$(( i + 1 ))" "$n" "$f"
    done
}

# ── RRC integrity protection (UIA1/UIA2 MAC-I) ──────────────────────────
# The integrity algorithm f9 (TS 33.102 Annex B) protects RRC signalling.
# UIA1 is KASUMI-based (TS 35.201); UIA2 is SNOW 3G based (TS 35.215). Both
# feed f9 the same COUNT-I || FRESH || DIRECTION || MESSAGE string assembled
# below, so this module's --mac-input is identical for either algorithm; only
# the underlying permutation differs. Compute the MAC-I with
# `11_gsm_attack --f9-mac`.
#
# The input to the algorithm is
#     COUNT-I || FRESH || DIRECTION || MESSAGE
# where COUNT-I is 32 bits, FRESH is 32 bits, DIRECTION is a 32-bit word
# holding 0 (uplink) or 1 (downlink), and MESSAGE is the RRC PDU. The
# algorithm is keyed with the 128-bit integrity key IK and produces a
# 32-bit MAC-I, which is truncated to the 32 bits carried in the message.
#
# COUNT-I itself is built from the radio bearer's hyper frame number and the
# RRC sequence number (TS 25.331 section 8.5.10):
#     COUNT-I = (HFN << 8) | SN        HFN is 24 bits, SN is 8 bits
# so COUNT-I is 32 bits and increments by one per integrity-protected PDU.
uair_count_i() {
    local hfn="${1:-}" sn="${2:-}"
    # HFN and SN are often written in hex in traces and in decimal in the
    # spec's prose. Accept both: a 0x prefix, or an a-f digit, means hex.
    case "$hfn" in
        0x*|0X*) hfn=$(( 16#${hfn#0x} )) ;;
        *[a-fA-F]*) hfn=$(( 16#$hfn )) ;;
    esac
    case "$sn" in
        0x*|0X*) sn=$(( 16#${sn#0x} )) ;;
        *[a-fA-F]*) sn=$(( 16#$sn )) ;;
    esac
    [[ "$hfn" =~ ^[0-9]+$ && "$sn" =~ ^[0-9]+$ ]] || {
        printf 'ERROR\tCOUNT-I needs HFN and SN as integers (decimal or 0x hex)\n' >&2
        return 2; }
    (( hfn <= 16777215 && sn <= 255 )) || {
        printf 'ERROR\tHFN must be 24 bits (0..16777215) and SN 8 bits (0..255)\n' >&2
        return 2; }
    printf '%08x' "$(( (hfn << 8) | sn ))"
}

# Assemble the f9 input string byte-exactly:
#   COUNT-I(4 octets) FRESH(4) DIRECTION(4) MESSAGE
uair_mac_input() {
    local count="${1:-}" fresh="${2:-}" dir="${3:-}" ik="${4:-}" msg="${5:-}"
    [[ -n "$count" && -n "$fresh" && -n "$dir" && -n "$ik" && -n "$msg" ]] || {
        printf 'ERROR\tusage: --mac-input <count-i> <fresh> <direction> <ik> <msg-hex>\n' >&2
        return 2; }
    local c f
    [[ "$count" =~ ^(0x)?[0-9a-fA-F]{1,8}$ ]] || {
        printf 'ERROR\tCOUNT-I must be up to 8 hex digits\n' >&2; return 2; }
    [[ "$fresh" =~ ^(0x)?[0-9a-fA-F]{1,8}$ ]] || {
        printf 'ERROR\tFRESH must be up to 8 hex digits\n' >&2; return 2; }
    [[ "$dir" =~ ^[01]$ ]] || {
        printf 'ERROR\tDIRECTION must be 0 (uplink) or 1 (downlink)\n' >&2; return 2; }
    uair_is_hex "$ik" || {
        printf 'ERROR\tIK must be 16 octets of hex (32 digits)\n' >&2; return 2; }
    local ikn; ikn=$(uair_norm_hex "$ik")
    (( ${#ikn} == 32 )) || {
        printf 'ERROR\tIK must be 128 bits (32 hex digits), got %s\n' "${#ikn}" >&2
        return 2; }
    uair_is_hex "$msg" || {
        printf 'ERROR\tMESSAGE must be hex\n' >&2; return 2; }

    c=$(printf '%08x' "$(( 16#${count#0x} ))")
    f=$(printf '%08x' "$(( 16#${fresh#0x} ))")
    local d; d=$(printf '%08x' "$(( dir ))")
    local msg; msg=$(uair_norm_hex "$msg")

    printf 'count_i\t%s\n' "$c"
    printf 'fresh\t%s\n'   "$f"
    printf 'direction\t%s\n' "$dir"
    printf 'direction_name\t%s\n' "$([[ "$dir" -eq 1 ]] && echo downlink || echo uplink)"
    printf 'ik\t%s\n'      "$ikn"
    printf 'message\t%s\n' "$msg"
    printf 'mac_input\t%s\n' "${c}${f}${d}${msg}"
    printf 'mac_input_bits\t%s\n' "$(( 32 + 32 + 32 + ${#msg} * 4 ))"
    printf 'algorithm\tUIA1 (KASUMI-based f9)\n'
    printf 'algorithm_alt\tUIA2 (SNOW 3G based)\n'
    printf 'mac_i_bits\t32\n'
    return 0
}

# Show what the integrity check protects, and what its absence exposes. The
# per-message integrity check is what stops an attacker from rewriting
# signalling; a message that is not integrity protected can be forged.
uair_integrity_analysis() {
    cat <<'EOF'
message	integrity_protected	consequence_if_not
RRC CONNECTION REQUEST	no	the initial message cannot be protected because no IK exists yet; the network must treat it as untrusted
RRC CONNECTION SETUP	yes	protects the radio bearer configuration; removing the check lets an attacker downgrade the bearer
RRC CONNECTION RELEASE	yes	protects the release; if unchecked an attacker can drop a call
SECURITY MODE COMMAND	yes	carries the ciphering and integrity activation; an unchecked one allows an attacker to force UIA0/UEA0 (null)
SECURITY MODE COMPLETE	yes	confirms the activation; unauthenticated it can be spoofed to convince the network integrity is on
MEASUREMENT REPORT	yes	a forged report steers handover to a cell the attacker controls
HANDOVER TO UTRAN COMMAND	yes	an unchecked handover command redirects the MS to an attacker NodeB
PAGING TYPE 1	no	paging is not integrity protected; a forged page causes the MS to respond on the attacker's channel
SYSTEM INFORMATION	no	broadcast is not integrity protected; a fake NodeB broadcasts a forged SIB to change reselection
COUNTER CHECK	no	the MAC-I is what binds the message to COUNT-I; without it a replay is undetectable
EOF
}

uair_integrity_analysis_tsv() {
    printf 'message\tintegrity_protected\tconsequence_if_not\n'
    uair_integrity_analysis | tail -n +2
}

# ── AKA flow (UMTS authentication and key agreement) ────────────────────
# TS 33.102 section 6.3. The USIM and the HLR/AuC share the subscriber key K.
# The flow, and where a relay or a fake NodeB sits in it:
uair_aka_flow() {
    cat <<'EOF'
step	from	to	message	carries	attacker_position
1	HLR/AuC	VLR	Authentication Vector	RAND(128) || XRES(64) || CK(128) || IK(128) || AUTN(128)	none: this is inside the core network, not on the air
2	VLR/visited MSC	MS (via NodeB)	AUTHENTICATION REQUEST	RAND(128) || AUTN(128)	the only message on the air in this direction; a fake NodeB relays it verbatim
3	USIM	ME/UE	internal: run f1-f5 with K	computed RES(64), CK(128), IK(128), and the MAC-A check inside AUTN	not observable: K never leaves the USIM
4	ME	VLR	Authentication Response	RES(64)	an IMSI catcher cannot compute a valid RES without K, so it cannot complete authentication
5	VLR	MS	Security Mode Command	CK || IK || UIA/UEA selection	an unchecked Security Mode Command is where UIA0/UEA0 is forced
6	MS	VLR	Security Mode Complete	MAC-I over the message	proves the MS holds IK
attacker_relay	relay position	MS <-> network	forwards AUTHENTICATION REQUEST and RES unchanged	does not learn K, CK or IK and cannot forge a valid MAC-I	learns the IMSI, the location and the traffic pattern, and controls the cipher mode chosen in step 5
attacker_fake_nodeb	fake NodeB	network -> MS	answers on its own without relaying	cannot pass step 3: without K it cannot produce a MAC-A the USIM accepts for a chosen SQN	the MS rejects the network and returns to the real cell
sqn_replay	replay	network -> MS	a replayed AUTN	the USIM rejects it once its SQN counter has advanced	a pure replay of an old vector fails; attackers instead induce re-synchronisation (AUTS) or force the MS onto 2G
cross_generation	downgrade	network -> MS	an authenticated 3G session that falls back to GSM	CK is not used on GSM; A5/1 uses Kc from COMP128	the 3G-to-2G downgrade is a cipher downgrade (see 19_downgrade.sh)
EOF
}

uair_aka_flow_tsv() {
    printf 'step\tfrom\tto\tmessage\tcarries\tattacker_position\n'
    uair_aka_flow | tail -n +2
}

uair_cmd_aka_flow() {
    uair_aka_flow_tsv
}

# ── hardware guards ─────────────────────────────────────────────────────
uair_find_sdr() {
    local d
    for d in hackrf bladerf limesdr usrp; do
        case "$d" in
            hackrf)  command -v hackrf_info      >/dev/null 2>&1 && { echo "hackrf";  return 0; } ;;
            bladerf) command -v bladeRF-cli      >/dev/null 2>&1 && { echo "bladerf"; return 0; } ;;
            limesdr) command -v LimeUtil         >/dev/null 2>&1 && { echo "limesdr"; return 0; } ;;
            usrp)    command -v uhd_find_devices >/dev/null 2>&1 && { echo "usrp"; return 0; } ;;
        esac
    done
    command -v rtl_test >/dev/null 2>&1 && { echo "rtlsdr"; return 0; }
    return 1
}

uair_find_umts_stack() {
    for t in srsran srsenb srsepc liquid-dsp; do
        command -v "$t" >/dev/null 2>&1 && { echo "$t"; return 0; }
    done
    return 1
}

# ── capture-driven decode (no radio) ────────────────────────────────────
uair_decode_pcap() {
    local pcap="${1:-}"
    [[ -n "$pcap" && -f "$pcap" ]] || {
        printf 'ERROR\tno such capture: %s\n' "${pcap:-<none>}" >&2; return 1; }
    command -v tshark >/dev/null 2>&1 || {
        printf 'ERROR\tno tshark — install wireshark-cli to read captures\n' >&2
        return 1; }
    local out
    out=$(tshark -r "$pcap" -Y 'rrc' -T fields -e rrc.messageCode \
              -e rrc.sib_type 2>/dev/null | head -200)
    [[ -z "$out" ]] && {
        printf 'ERROR\tno RRC messages in %s\n' "$pcap" >&2; return 1; }
    printf '%s\n' "$out"
}

# ── persistence ─────────────────────────────────────────────────────────
UAIR_SIB_STORE="$UAIR_DIR/sib.tsv"
uair_init_store() {
    mkdir -p "$UAIR_DIR" 2>/dev/null
    [[ -f "$UAIR_SIB_STORE" ]] || uair_sib_header > "$UAIR_SIB_STORE"
}
uair_sib_header() {
    printf 'sib\tcell_identity\tuarfcn\tfreq_mhz\tsource\tts\n'
}
uair_sib_count() {
    [[ -f "$UAIR_SIB_STORE" ]] || { echo 0; return; }
    local n; n=$(tail -n +2 "$UAIR_SIB_STORE" 2>/dev/null | grep -c . || true)
    echo "${n:-0}"
}

# ── CLI verbs ───────────────────────────────────────────────────────────
uair_cli_status_tsv() {
    local sdr stack
    sdr=$(uair_find_sdr) || sdr="none"
    stack=$(uair_find_umts_stack) || stack="none"
    printf 'sdr\t%s\n'              "$sdr"
    printf 'umts_stack\t%s\n'       "$stack"
    printf 'sib_records\t%s\n'      "$(uair_sib_count)"
    printf 'dir\t%s\n'              "$UAIR_DIR"
    printf 'store\t%s\n'            "$UAIR_SIB_STORE"
    printf 'raster_khz\t%s\n'       "$UAIR_RASTER_KHZ"
    printf 'uarfcn_max\t16383\n'
    printf 'count_i_bits\t32\n'
    printf 'fresh_bits\t32\n'
    printf 'ik_bits\t128\n'
    printf 'mac_i_bits\t32\n'
}

uair_cmd_decode_sib() {
    local hex="${1:-}"
    [[ -n "$hex" ]] || {
        printf 'ERROR\tusage: --decode-sib <hex>\n' >&2; return 2; }
    uair_decode_sib "$hex"
}

# ── selftest — no radio, no root, no network ────────────────────────────
uair_selftest() {
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
    export UAIR_DIR="$d/loot/umts_air"
    export UAIR_SIB_STORE="$UAIR_DIR/sib.tsv"

    # 1. UARFCN arithmetic against the 200 kHz raster: F = 0.2 * N.
    chk uarfcn-10562 "$(uair_uarfcn_to_mhz 10562)" "2112.4"
    chk uarfcn-10838 "$(uair_uarfcn_to_mhz 10838)" "2167.6"
    chk uarfcn-0     "$(uair_uarfcn_to_mhz 0)"     "0.0"
    chk uarfcn-10700 "$(uair_uarfcn_to_mhz 10700)" "2140.0"
    chk uarfcn-9662  "$(uair_uarfcn_to_mhz 9662)"  "1932.4"
    chk uarfcn-4357  "$(uair_uarfcn_to_mhz 4357)"  "871.4"
    chk uarfcn-16383 "$(uair_uarfcn_to_mhz 16383)" "3276.6"
    #    The 200 kHz raster is exactly the 5 MHz-raster form read in 1 MHz
    #    steps; check the relation rather than the coincidence.
    chk uarfcn-raster-rel "$(awk -v a="$(uair_uarfcn_to_mhz 10562)" \
                                -v b="$(uair_uarfcn_to_mhz_5mhz_raster 10562)" \
                                'BEGIN{print (b == a*25) ? "y" : "n"}')" "y"
    #    Out of range and non-numeric must fail, not guess.
    chk uarfcn-range   "$(uair_uarfcn_to_mhz 20000 >/dev/null 2>&1; echo $?)" "2"
    chk uarfcn-nonnum  "$(uair_uarfcn_to_mhz abc >/dev/null 2>&1; echo $?)"   "2"
    chk uarfcn-missing "$(uair_cmd_uarfcn >/dev/null 2>&1; echo $?)"          "2"

    #    Reverse mapping: a frequency on the raster round-trips exactly.
    out=$(uair_mhz_to_uarfcn 2112.4)
    chk mhz-rev-uarfcn "$(fld "$out" uarfcn)" "10562"
    chk mhz-rev-exact  "$(fld "$out" rounding_error_khz)" "0.0"
    #    A frequency off the raster reports a non-zero rounding error.
    chk mhz-off-raster "$(printf '%s\n' "$(uair_mhz_to_uarfcn 2112.45)" | \
            awk -F'\t' '$1=="rounding_error_khz"{print ($2 != 0) ? "y":"n"}')" "y"
    chk mhz-bad        "$(uair_mhz_to_uarfcn xyz >/dev/null 2>&1; echo $?)" "2"

    #    Band identification from the N range.
    chk band-1  "$(uair_band_of_uarfcn 10562 | cut -f1)" "1"
    chk band-2  "$(uair_band_of_uarfcn 9662  | cut -f1)" "2"
    chk band-5  "$(uair_band_of_uarfcn 4357  | cut -f1)" "5"
    chk band-8  "$(uair_band_of_uarfcn 2937  | cut -f1)" "8"
    chk band-x  "$(uair_band_of_uarfcn 16000 >/dev/null 2>&1; echo $?)" "1"
    out=$(uair_cmd_uarfcn 10562)
    chk cmd-uarfcn-freq "$(fld "$out" freq_mhz)" "2112.4"
    chk cmd-uarfcn-band "$(fld "$out" band)"     "1"

    # 2. SIB parse of a real hex blob.
    #    SIB3 tag = 3 -> first 5 bits 00011, then a 28-bit cell identity.
    #    Build: tag 00011 | CI 0000000000000000000000000001
    #    bits = 00011 0000000000000000000000000001 -> pad to octets.
    local sib3; sib3=$(uair_bits_to_hex "00011$(uair_bin 1 28)")
    chk sib3-tag   "$(fld "$(uair_decode_sib "$sib3")" sib_tag)" "3"
    chk sib3-name  "$(fld "$(uair_decode_sib "$sib3")" sib)"     "SIB3"
    chk sib3-ci    "$(fld "$(uair_decode_sib "$sib3")" cell_identity)" "1"
    chk sib3-cibits "$(fld "$(uair_decode_sib "$sib3")" cell_identity_bits)" "28"

    #    A non-trivial cell identity round-trips through the 28-bit field.
    local ci_in=268435455    # 0x0FFFFFFF, all 28 bits set
    local sib3b; sib3b=$(uair_bits_to_hex "00011$(uair_bin "$ci_in" 28)")
    chk sib3-ci-max "$(fld "$(uair_decode_sib "$sib3b")" cell_identity)" "$ci_in"

    #    SIB7 carries the uplink interference level in dBm. Tag 7 = 00111,
    #    then a 6-bit field whose value + (-110) is the dBm level.
    local sib7; sib7=$(uair_bits_to_hex "00111$(uair_bin 40 6)")
    chk sib7-tag  "$(fld "$(uair_decode_sib "$sib7")" sib_tag)" "7"
    chk sib7-name "$(fld "$(uair_decode_sib "$sib7")" sib)"     "SIB7"
    chk sib7-dbm  "$(fld "$(uair_decode_sib "$sib7")" ul_interference_dbm)" "-70"

    #    Unknown tag must warn, not invent fields.
    local sibx; sibx=$(uair_bits_to_hex "11111$(uair_bin 0 27)")
    chk sib-unknown-tag  "$(fld "$(uair_decode_sib "$sibx")" sib_tag)" "31"
    chk sib-unknown-warn "$(fld "$(uair_decode_sib "$sibx")" warning | grep -c .)" "1"

    #    Argument validation.
    chk sib-nonhex  "$(uair_decode_sib 'zzzz' >/dev/null 2>&1; echo $?)" "2"
    chk sib-short   "$(uair_decode_sib 'ab' >/dev/null 2>&1; echo $?)"   "1"
    chk sib-missing "$(uair_cmd_decode_sib >/dev/null 2>&1; echo $?)"    "2"

    #    SIB field map: every SIB the task names must be documented.
    local fm; fm=$(uair_sib_fields_tsv)
    chk sibmap-header "$(printf '%s\n' "$fm" | head -1)" "sib	carries	key_fields"
    chk sibmap-fields "$(printf '%s\n' "$fm" | tail -n +2 | awk -F'\t' 'NF!=3' | grep -c .)" "0"
    local s
    for s in SIB3 SIB5 SIB6 SIB7 SIB11 SIB12; do
        chk "sibmap-${s}" "$(printf '%s\n' "$fm" | awk -F'\t' -v x="$s" '$1==x' | grep -c .)" "1"
    done
    chk sibmap-sib3-ci    "$(printf '%s\n' "$fm" | awk -F'\t' '$1=="SIB3"{print ($3 ~ /CellIdentity/) ? "y":"n"}')" "y"
    chk sibmap-sib5-nb    "$(printf '%s\n' "$fm" | awk -F'\t' '$1=="SIB5"{print ($3 ~ /neighbour/) ? "y":"n"}')" "y"
    chk sibmap-sib6-uarfcn "$(printf '%s\n' "$fm" | awk -F'\t' '$1=="SIB6"{print ($3 ~ /UARFCN/) ? "y":"n"}')" "y"
    chk sibmap-sib11-meas "$(printf '%s\n' "$fm" | awk -F'\t' '$1=="SIB11"{print ($3 ~ /measurement/) ? "y":"n"}')" "y"
    chk sib-name-3 "$(uair_sib_name 3)"  "SIB3"
    chk sib-name-11 "$(uair_sib_name 11)" "SIB11"
    chk sib-name-x "$(uair_sib_name 99)" "unknown"

    #    SIB6 carrier list: adjacent 5 MHz carriers are 25 UARFCN apart.
    out=$(uair_sib6_carriers 10562 3)
    chk sib6-rows    "$(printf '%s\n' "$out" | tail -n +2 | grep -c .)" "3"
    chk sib6-first   "$(printf '%s\n' "$out" | awk -F'\t' 'NR==2{print $2}')" "10562"
    chk sib6-second  "$(printf '%s\n' "$out" | awk -F'\t' 'NR==3{print $2}')" "10587"
    chk sib6-freq    "$(printf '%s\n' "$out" | awk -F'\t' 'NR==3{print $3}')" "2117.4"
    chk sib6-bad     "$(uair_sib6_carriers 1 0 >/dev/null 2>&1; echo $?)" "2"
    chk sib6-bad-n   "$(uair_sib6_carriers x 1 >/dev/null 2>&1; echo $?)" "2"

    # 3. MAC-I input assembly, byte-exact.
    #    COUNT-I = 0x398a59b4, FRESH = 0xec9e8bb6, DIRECTION = 1 (downlink),
    #    IK = 16 zero octets, MESSAGE = 0x0004.
    out=$(uair_mac_input 398a59b4 ec9e8bb6 1 00000000000000000000000000000000 0004)
    chk mac-count   "$(fld "$out" count_i)"   "398a59b4"
    chk mac-fresh   "$(fld "$out" fresh)"     "ec9e8bb6"
    chk mac-dir     "$(fld "$out" direction)" "1"
    chk mac-dirname "$(fld "$out" direction_name)" "downlink"
    chk mac-ik-len  "$(printf '%s' "$(fld "$out" ik)" | wc -c | tr -d ' ')" "32"
    chk mac-input   "$(fld "$out" mac_input)" "398a59b4ec9e8bb6000000010004"
    chk mac-bits    "$(fld "$out" mac_input_bits)" "112"
    chk mac-i-bits  "$(fld "$out" mac_i_bits)" "32"
    chk mac-ik-bits "$(uair_cli_status_tsv | awk -F'\t' '$1=="ik_bits"{print $2}')" "128"

    #    DIRECTION 0 is uplink and must show the zero word.
    out=$(uair_mac_input 398a59b4 ec9e8bb6 0 00000000000000000000000000000000 0004)
    chk mac-dir0     "$(fld "$out" direction_name)" "uplink"
    chk mac-input0   "$(fld "$out" mac_input)" "398a59b4ec9e8bb6000000000004"

    #    COUNT-I construction: (HFN << 8) | SN.
    chk count-i      "$(uair_count_i 0x398a59 0xb4)" "398a59b4"
    chk count-i-zero "$(uair_count_i 0 0)"           "00000000"
    chk count-i-max  "$(uair_count_i 16777215 255)"  "ffffffff"
    chk count-i-hfn  "$(uair_count_i 16777216 0 >/dev/null 2>&1; echo $?)" "2"
    chk count-i-sn   "$(uair_count_i 0 256 >/dev/null 2>&1; echo $?)"      "2"
    chk count-i-hex  "$(uair_count_i 0x398a59 0xb4)" "398a59b4"
    chk count-i-text "$(uair_count_i zz qq >/dev/null 2>&1; echo $?)"      "2"

    #    Argument validation on the MAC input.
    chk mac-missing  "$(uair_mac_input >/dev/null 2>&1; echo $?)" "2"
    chk mac-bad-dir  "$(uair_mac_input 1 1 2 00000000000000000000000000000000 00 >/dev/null 2>&1; echo $?)" "2"
    chk mac-short-ik "$(uair_mac_input 1 1 1 0011 00 >/dev/null 2>&1; echo $?)" "2"
    chk mac-bad-msg  "$(uair_mac_input 1 1 1 00000000000000000000000000000000 zz >/dev/null 2>&1; echo $?)" "2"
    chk mac-bad-cnt  "$(uair_mac_input zzzzz 1 1 00000000000000000000000000000000 00 >/dev/null 2>&1; echo $?)" "2"

    # 4. Integrity analysis: the unprotected messages must be flagged.
    local ia; ia=$(uair_integrity_analysis_tsv)
    chk integ-header "$(printf '%s\n' "$ia" | head -1)" \
        "message	integrity_protected	consequence_if_not"
    chk integ-fields "$(printf '%s\n' "$ia" | tail -n +2 | awk -F'\t' 'NF!=3' | grep -c .)" "0"
    chk integ-rows   "$(printf '%s\n' "$ia" | tail -n +2 | grep -c .)" "10"
    chk integ-smc-no "$(printf '%s\n' "$ia" | awk -F'\t' '$1=="SECURITY MODE COMMAND"{print $2}')" "yes"
    chk integ-paging "$(printf '%s\n' "$ia" | awk -F'\t' '$1=="PAGING TYPE 1"{print $2}')" "no"
    chk integ-sysinfo "$(printf '%s\n' "$ia" | awk -F'\t' '$1=="SYSTEM INFORMATION"{print $2}')" "no"
    chk integ-null  "$(printf '%s\n' "$ia" | awk -F'\t' '$1=="SECURITY MODE COMMAND"{print ($3 ~ /UIA0/) ? "y":"n"}')" "y"
    chk integ-req-no "$(printf '%s\n' "$ia" | awk -F'\t' '$1=="RRC CONNECTION REQUEST"{print $2}')" "no"

    # 5. AKA flow: the real message sequence and the attacker positions.
    local ak; ak=$(uair_aka_flow_tsv)
    chk aka-header "$(printf '%s\n' "$ak" | head -1)" \
        "step	from	to	message	carries	attacker_position"
    chk aka-fields "$(printf '%s\n' "$ak" | tail -n +2 | awk -F'\t' 'NF!=6' | grep -c .)" "0"
    chk aka-steps  "$(printf '%s\n' "$ak" | tail -n +2 | awk -F'\t' '$1 ~ /^[0-9]+$/' | grep -c .)" "6"
    chk aka-authreq "$(printf '%s\n' "$ak" | awk -F'\t' '$4=="AUTHENTICATION REQUEST"{print $5}')" "RAND(128) || AUTN(128)"
    chk aka-rand    "$(printf '%s\n' "$ak" | awk -F'\t' '$4=="AUTHENTICATION REQUEST"{print ($5 ~ /RAND/) ? "y":"n"}')" "y"
    chk aka-autn    "$(printf '%s\n' "$ak" | awk -F'\t' '$4=="AUTHENTICATION REQUEST"{print ($5 ~ /AUTN/) ? "y":"n"}')" "y"
    chk aka-res     "$(printf '%s\n' "$ak" | awk -F'\t' '$4=="Authentication Response"{print $5}')" "RES(64)"
    chk aka-vector  "$(printf '%s\n' "$ak" | awk -F'\t' '$1=="1"{print ($5 ~ /CK/) ? "y":"n"}')" "y"
    chk aka-relay   "$(printf '%s\n' "$ak" | awk -F'\t' '$1=="attacker_relay"{print ($2 ~ /relay/) ? "y":"n"}')" "y"
    chk aka-fakenb  "$(printf '%s\n' "$ak" | awk -F'\t' '$1=="attacker_fake_nodeb"{print ($5 ~ /MAC-A/) ? "y":"n"}')" "y"
    chk aka-sqn     "$(printf '%s\n' "$ak" | awk -F'\t' '$1=="sqn_replay"' | grep -c .)" "1"

    # 6. Hex plumbing, shared contract.
    chk hex-norm "$(uair_norm_hex 'AB CD')" "abcd"
    chk hex-bits "$(uair_hex_to_bits 'a5')" "10100101"
    chk bits-rt  "$(uair_bits_to_hex "$(uair_hex_to_bits 'deadbeef')")" "deadbeef"
    chk field-ok "$(uair_field 'abcd' 8 8)" "205"
    chk field-oob "$(uair_field 'ab' 12 8 >/dev/null 2>&1; echo $?)" "1"

    # 7. Sanitisation of untrusted text.
    local evil; evil=$(uair_sanitize $'Evil\tNodeB\r\nRow')
    chk sanitize-tabs "$(printf '%s' "$evil" | tr -cd '\t' | wc -c | tr -d ' ')" "0"
    chk sanitize-nl   "$(printf '%s' "$evil" | tr -cd '\n' | wc -c | tr -d ' ')" "0"

    # 8. Status TSV contract. SDR presence is environment-dependent.
    out=$(uair_cli_status_tsv)
    chk status-dir     "$(fld "$out" dir)"        "$UAIR_DIR"
    chk status-store   "$(fld "$out" store)"      "$UAIR_SIB_STORE"
    chk status-raster  "$(fld "$out" raster_khz)" "200"
    chk status-max     "$(fld "$out" uarfcn_max)" "16383"
    chk status-counti  "$(fld "$out" count_i_bits)" "32"
    chk status-fresh   "$(fld "$out" fresh_bits)"   "32"
    chk status-ik      "$(fld "$out" ik_bits)"      "128"
    chk status-maci    "$(fld "$out" mac_i_bits)"   "32"

    # 9. CLI dispatch: unknown verb is a usage error, not a success.
    chk cli-unknown "$(uair_cli_main --nope >/dev/null 2>&1; echo $?)" "2"

    rm -rf "$d"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ── menu ────────────────────────────────────────────────────────────────
uair_menu() {
    local c
    while true; do
        banner
        echo -e "  ${C_MAG}=== UMTS air interface ===${C_RESET}"
        echo -e "  sdr:   ${C_GRN}$(uair_find_sdr || echo none)${C_RESET}"
        echo -e "  stack: ${C_GRN}$(uair_find_umts_stack || echo none)${C_RESET}"
        echo -e "  store: ${C_DIM}$UAIR_SIB_STORE${C_RESET}\n"
        cat << 'M'
  [1]  UARFCN -> frequency
  [2]  frequency -> UARFCN
  [3]  decode a SIB (hex)
  [4]  SIB field map
  [5]  SIB6 neighbour carrier list
  [6]  RRC integrity (UIA1/UIA2) input assembly
  [7]  integrity analysis: what is protected, what is not
  [8]  AKA relay analysis
  [9]  decode RRC from a pcap
  [0]  back

M
        if [[ -n "${IMSISTING_CLI:-}" ]]; then
            echo "[-] menu unavailable in CLI mode" >&2; return 1
        fi
        read -rp "  choice> " c || return 0  # EOF: leave the menu cleanly
        case "$c" in
            1)
                read -rp "  UARFCN> " n
                uair_cmd_uarfcn "$n" | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            2)
                read -rp "  frequency MHz> " f
                uair_mhz_to_uarfcn "$f" | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            3)
                read -rp "  SIB hex> " h
                uair_cmd_decode_sib "$h" | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            4) uair_sib_fields_tsv | column -t -s$'\t' 2>/dev/null
               read -rp "  press enter " _ ;;
            5)
                read -rp "  first UARFCN> " n
                read -rp "  count> " k
                uair_sib6_carriers "$n" "$k" | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            6)
                read -rp "  COUNT-I hex> " ci
                read -rp "  FRESH hex> " fr
                read -rp "  DIRECTION (0=ul 1=dl)> " di
                read -rp "  IK hex (32 digits)> " ik
                read -rp "  MESSAGE hex> " ms
                uair_mac_input "$ci" "$fr" "$di" "$ik" "$ms" | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            7) uair_integrity_analysis_tsv | column -t -s$'\t' 2>/dev/null
               read -rp "  press enter " _ ;;
            8) uair_cmd_aka_flow | column -t -s$'\t' 2>/dev/null
               read -rp "  press enter " _ ;;
            9)
                read -rp "  pcap path> " p
                uair_decode_pcap "$p"
                read -rp "  press enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ── CLI dispatch ────────────────────────────────────────────────────────
uair_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)     uair_cli_status_tsv ;;
        --uarfcn)         uair_cmd_uarfcn "${1:-}" ;;
        --mhz)            uair_mhz_to_uarfcn "${1:-}" ;;
        --decode-sib)     uair_cmd_decode_sib "${1:-}" ;;
        --sib-fields)     uair_sib_fields_tsv ;;
        --sib6-carriers)  uair_sib6_carriers "${1:-}" "${2:-}" ;;
        --aka-flow)       uair_cmd_aka_flow ;;
        --mac-input)      uair_mac_input "${1:-}" "${2:-}" "${3:-}" "${4:-}" "${5:-}" ;;
        --count-i)        uair_count_i "${1:-}" "${2:-}" ;;
        --integrity-tsv)  uair_integrity_analysis_tsv ;;
        --decode-pcap)    uair_decode_pcap "${1:-}" ;;
        --selftest)       uair_selftest ;;
        --menu)           uair_menu ;;
        *)
            cat >&2 <<EOF
UMTS Air Interface — UARFCN, SIB decode, RRC integrity, AKA relay analysis

Usage: $0 COMMAND
  --status-tsv                  tool and store state as TSV
  --uarfcn <N>                  UARFCN to carrier frequency in MHz
  --mhz <F>                     carrier frequency to UARFCN
  --decode-sib <hex>            decode a SIB blob
  --sib-fields                  field map for SIB1..SIB18 as TSV
  --sib6-carriers <first> <n>   SIB6 neighbour carrier list
  --aka-flow                    the AKA message flow and attacker positions
  --mac-input <count> <fresh> <dir> <ik> <msg>
                                assemble the UIA1/UIA2 f9 input
  --count-i <hfn> <sn>          COUNT-I = (HFN << 8) | SN
  --integrity-tsv               what is integrity protected, and what is not
  --decode-pcap <pcap>          list RRC messages in a capture
  --selftest                    verify arithmetic and assemblers, no radio
  --menu                        interactive menu
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
    uair_cli_main "$@"
fi
