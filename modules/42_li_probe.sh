#!/usr/bin/env bash
# li_probe — 3GPP lawful interception: the interfaces, the interception-posture
# signals a capture can show, and an encoder for the X1/HI1 provisioning and
# activation records and the X3/HI3 interception-product envelope.
#
# SCOPE, stated first. This module cannot intercept anything and no verb here
# pretends to. Two halves:
#
#   * Detection (--interfaces, --iface, --architecture, --score, --report,
#     --plan) reads what you give it and sends nothing.
#   * Encoding (--provision-target, --activate, --intercept) builds real bytes
#     for the protocol artefacts of a lawful-intercept system: exact field
#     layout, orderings and encodings. The provisioning and activation records
#     are the TS 33.108 Annex M HI1 operation (ThreeGPP-HI1NotificationOperations)
#     in BER, encoded by tools/li_hi1.py and compared octet for octet against
#     pycrate by tools/check-li-ber.sh. The X3/HI3 interception product is this
#     module's own length-prefixed TLV envelope (magic LIPR) and says so: TS
#     33.108's HI3 record is not transcribed in this tree, and calling a
#     self-defined envelope a TS 33.108 PDU is the fabrication this tree keeps
#     paying for. No encoder verb opens a socket, sends anything or asks for a
#     flag; each one prints its artefact, carries a note saying what it never
#     contacts, and exits 3 with a handoff: an interception is performed by an
#     operator on the operator's own network, under statutory authority, and
#     delivering an artefact is that operator's action, not this module's.
#
# Attack owned: O12/O13 adjacency (tracking via the core) — detection half; the
# X1/X3 protocol artefacts are the encoder half.
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

MOD_TMP="$TMP_DIR/li_probe"
LIPR_DIR="$LOOT_DIR/li_probe"
mkdir -p "$MOD_TMP" "$LIPR_DIR" 2>/dev/null

declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
declare -F warn >/dev/null 2>&1 || warn() { printf '[warn] %s\n' "$*" >&2; }
declare -F err  >/dev/null 2>&1 || err()  { printf '[err]  %s\n' "$*" >&2; }
declare -F ok   >/dev/null 2>&1 || ok()   { printf '[ok]   %s\n' "$*" >&2; }
declare -F banner >/dev/null 2>&1 || banner() { :; }

lipr_sanitize() { printf '%s' "${1:-}" | tr '\t\r\n' '   '; }

# Errors go to stderr, one record per line, and the function returns non-zero.
# Two shapes, because two different things went wrong: lipr_fail is "the machine
# could not do it" (rc 1), lipr_refuse is "this module will not do it" (rc 2)
# and always states why.
lipr_fail() {
    printf 'ERROR\t%s\n' "$1" >&2
    return 1
}
lipr_refuse() {
    printf 'ERROR\t%s\n' "$1" >&2
    printf 'WHY\t%s\n' "${2:-refused}" >&2
    return 2
}

# ── byte arithmetic (§15: mask at the point of emission) ────────────────
# printf '%02X' does not truncate: a value above 255 emits three digits. Every
# octet this module emits goes through these three functions, so the mask is
# applied exactly once, where the octet is produced.
lipr_byte()  { printf '%02X' "$(( ${1:-0} & 0xFF ))"; }
lipr_u16be() { printf '%04X' "$(( ${1:-0} & 0xFFFF ))"; }
lipr_u32be() { printf '%08X' "$(( ${1:-0} & 0xFFFFFFFF ))"; }

# Text field -> the octets of its bytes. od is coreutils and is the only
# external the encoder needs; a missing od is an ERROR, not empty output.
lipr_require_od() {
    command -v od >/dev/null 2>&1 && return 0
    lipr_fail "od (coreutils) is not on PATH; the text-field encoder needs it for byte-exact octets"
    return 1
}
lipr_hexify() {
    printf '%s' "${1:-}" | od -An -v -tx1 | tr -d ' \n' | tr 'a-f' 'A-F'
}

# Semi-octet BCD: two digits per octet, low-order nibble first, an odd digit
# count padded with 0xF. This is the packing 3GPP signalling uses for telephone
# numbers and for the IMSI's digits; the definition is restated here so the
# encoding is not a black box. The caller validates that $1 is all digits.
#   310150123456789 -> 13 10 05 21 43 65 87 F9   (15 digits, odd, padded F)
#   1234            -> 21 43
lipr_bcd() {
    local d="${1:-}" i n out=""
    n=${#d}
    (( n > 0 )) || return 1
    for (( i = 0; i < n; i += 2 )); do
        local lo="${d:i:1}" hi="F"
        (( i + 1 < n )) && hi="${d:i+1:1}"
        out+="${hi}${lo}"
    done
    printf '%s' "${out^^}"
}

# Hex -> raw bytes on disk. Pure bash printf %b, so no xxd/vim dependency.
lipr_write_bytes() {
    local path="${1:-}" hex="${2:-}" esc="" i
    [[ -n "$path" ]] || { lipr_fail "empty --out path"; return 1; }
    [[ "$hex" =~ ^([0-9A-Fa-f]{2})+$ ]] || { lipr_fail "refusing to write a non-hex artefact"; return 1; }
    for (( i = 0; i < ${#hex}; i += 2 )); do
        esc+="\\x${hex:i:2}"
    done
    mkdir -p "$(dirname "$path")" 2>/dev/null
    printf '%b' "$esc" > "$path" || { lipr_fail "could not write $path"; return 1; }
    [[ -s "$path" ]] || { lipr_fail "$path is empty after the write"; return 1; }
    return 0
}

# The reader for the envelope this module writes. It decodes hand-computed
# literals, which is what makes the selftest a known-answer test rather than a
# round trip: the parser never sees what the encoder produced.
lipr_parse() {
    local h="${1:-}" n=0 off=0 tag len len_hex vhex
    [[ -n "$h" ]] || { lipr_fail "no hex to parse"; return 1; }
    [[ "$h" =~ ^[0-9A-Fa-f]+$ ]] || { lipr_fail "not hex: $(lipr_sanitize "$h")"; return 1; }
    h="${h^^}"
    n=${#h}
    (( n % 2 == 0 )) || { lipr_fail "odd hex digit count: $n"; return 1; }
    (( n >= 12 )) || { lipr_fail "shorter than the 6-octet header: $(( n / 2 )) octets"; return 1; }
    [[ "${h:0:8}" == "4C495052" ]] || { lipr_fail "magic is ${h:0:8}, not 4C495052"; return 1; }
    printf 'hdr\tmagic\tLIPR\n'
    printf 'hdr\tversion\t0x%s\n' "${h:8:2}"
    printf 'hdr\ttype\t0x%s\n' "${h:10:2}"
    off=6
    while (( off * 2 < n )); do
        (( (off + 3) * 2 <= n )) || { lipr_fail "truncated TLV header at octet $off"; return 1; }
        tag="${h:off*2:2}"
        len_hex="${h:off*2+2:4}"
        [[ "$len_hex" =~ ^[0-9A-Fa-f]{4}$ ]] || { lipr_fail "TLV 0x$tag has a non-hex length field"; return 1; }
        len=$(( 16#$len_hex ))
        (( (off + 3 + len) * 2 <= n )) || {
            lipr_fail "TLV 0x$tag claims $len value octets but only $(( n / 2 - off - 3 )) remain"
            return 1; }
        vhex="${h:(off+3)*2:len*2}"
        printf 'tlv\t0x%s\t%d\t%s\n' "$tag" "$len" "$vhex"
        off=$(( off + 3 + len ))
    done
    (( off * 2 == n )) || { lipr_fail "trailing octets after the last TLV"; return 1; }
    return 0
}

lipr_status_tsv() {
    printf 'MODULE\tli_probe\n'
    printf 'TARGET\t3GPP lawful-interception interfaces, interception-posture signals, and a protocol-artefact encoder\n'
    printf 'SCOPE\tdetection verbs read what they are given; the X1/HI1 provisioning and activation records and the X3/HI3 interception-product envelope are encoded byte-exact, and nothing is sent or intercepted\n'
    printf 'DETECTION_VERBS\t--interfaces --iface --architecture --score --report --plan\n'
    printf 'ENCODE_VERBS\t--provision-target --activate --intercept\n'
    printf 'ENCODE_GATE\tnone -- the encoder verbs run without a flag\n'
    printf 'DELIVERS\tnothing; every encoder exits 3 with a handoff after printing the artefact\n'
    printf 'PDU\tthe provisioning and activation records are 3GPP TS 33.108 Annex M HI1 (ThreeGPP-HI1NotificationOperations) BER PDUs, encoded by tools/li_hi1.py and compared against pycrate by tools/check-li-ber.sh\n'
    printf 'LIMIT\twhat remains unmodelled: the X3/HI3 interception product is this module own length-prefixed TLV (magic LIPR), not a TS 33.108 PDU, because HI3 is not transcribed here; the HI1 Notification has no target-identity field, so TARGET, SERVICES and the DF2/DF3 destinations are printed as not encoded instead of being folded into a field they do not belong to; domainID, the national parameters, broadcastStatus, deliveryInformation, interceptionType and Network-Element-Identifier iP-Address are refused by tools/li_hi1.py when asked for\n'
    printf 'HANDOFF\trc 3 after the artefact is printed: delivery needs an ADMF/DF2/DF3 on the operator own network, which this module never contacts\n'
    printf 'SELFTEST\tyes\n'
}

# ── LI interfaces (TS 33.107 / TS 33.108; 5G in TS 33.128) ──────────────
lipr_interfaces() {
    cat <<'EOF'
interface	handover	name	endpoints
X1	HI1	administration	ADMF -> DF2/DF3 (provisioning, target activation/deactivation)
X2	HI2	IRI	DF2 -> LEMF (intercept-related information: signalling events, not content)
X3	HI3	CC	DF3 -> LEMF (content of communication)
EOF
}
lipr_name_of() {
    case "$1" in
        X1|HI1) echo "administration (ADMF to DF2/DF3)" ;;
        X2|HI2) echo "IRI (DF2 to LEMF, signalling events)" ;;
        X3|HI3) echo "CC (DF3 to LEMF, content)" ;;
        *) echo "unknown interface — never classified as a handover interface" ;;
    esac
}
lipr_architecture() {
    cat <<'EOF'
node	role
ADMF	Administration Function — provisions intercepts; the only node that may activate a target
POI	Point of Interception — inside the network element (MME/AMF/UPF/HLR), not on the wire
DF2	Delivery Function 2 — mediates IRI (X2) toward the LEMF
DF3	Delivery Function 3 — mediates CC (X3) toward the LEMF
LEMF	Law Enforcement Monitoring Facility — the collection endpoint
EOF
}

# ── interception-posture scoring ────────────────────────────────────────
# A capture cannot prove an intercept is active; it can only show signalling
# that a lawful intercept or an IMSI catcher tends to produce. These are the
# signals, weighted, per TS 33.107 §6 and IMSI-catcher behaviour. Input TSV:
#   ts<TAB>imsi<TAB>event<TAB>cell<TAB>silent
# event in {identity_request, auth_request, location_update, silent_sms, detach}.
lipr_score() {
    local file="${1:-}"
    [[ -f "$file" ]] || { printf 'ERROR\tno such signalling file: %s\n' "$file" >&2; return 1; }
    awk -F'\t' '
        NR==1 && $1 ~ /^ts/ { next }
        NF>=3 {
            imsi=$2; ev=$3; cell=$4
            cnt[imsi SUBSEP ev]++
            if (cell != "" && !(imsi SUBSEP "c" SUBSEP cell in seen)) { seen[imsi SUBSEP "c" SUBSEP cell]=1; nc[imsi]++ }
            if (imsi != "" && !(imsi in any)) any[imsi]=1
        }
        END {
            printf "finding\tseverity\timsi\tdetail\n"
            total=0
            for (imsi in any) {
                ir=cnt[imsi SUBSEP "identity_request"]+0
                ar=cnt[imsi SUBSEP "auth_request"]+0
                lu=cnt[imsi SUBSEP "location_update"]+0
                sm=cnt[imsi SUBSEP "silent_sms"]+0
                cells=nc[imsi]+0
                sc=0
                if (ir>=3) { printf "forced_identity_burst\tHIGH\t%s\t%d identity requests for one subscriber; repeated forced-identity is an LI/IMSI-catcher signature\n", imsi, ir; sc+=3 }
                if (sm>=1) { printf "silent_sms\tHIGH\t%s\t%d silent/undelivered SMS; used to verify a target is on the network\n", imsi, sm; sc+=2 }
                if (ar>=5) { printf "auth_storm\tMEDIUM\t%s\t%d authentication requests; a re-authentication burst\n", imsi, ar; sc+=1 }
                if (lu>=5) { printf "location_update_burst\tMEDIUM\t%s\t%d location updates\n", imsi, lu; sc+=1 }
                if (cells>=5) { printf "wide_cell_spread\tMEDIUM\t%s\tsubscriber seen across %d cells\n", imsi, cells; sc+=1 }
                total+=sc
                if (sc>=3) risk[imsi]="high"; else if (sc>=1) risk[imsi]="medium"; else risk[imsi]="low"
            }
            printf "summary\tscore\t%d\n", total
            band="low"; for (i in risk) { if (risk[i]=="high") band="high"; else if (risk[i]=="medium" && band!="high") band="medium" }
            printf "summary\trisk\t%s\n", band
        }' "$file"
}

lipr_report() {
    cat <<'EOF'
section	content
provenance	which capture, which interface point, timestamps in UTC, clock source
signals	the per-subscriber findings from --score, with the raw event counts
limits	the air interface does not carry an LI flag; these are heuristics, not proof
escalation	a carrier's own mediation/ADMF logs and the DF2 IRI feed are the admissible record
regulator	notify the national regulator with the measurement log; keep the capture chain of custody
EOF
}

lipr_plan() {
    cat <<'EOF'
status	handoff
what	confirming an intercept from the network side rather than inferring it
hardware	a lab core (Open5GS/Osmocom) with its ADMF/DF mediation, or an operator's lawful-authorisation audit
software	the mediation function's own logs, the X1 provisioning record, and the operator's LI-management audit trail
encoder	--provision-target and --activate build the TS 33.108 HI1 operation as BER bytes; they hand it off and never deliver it
flow	1. collect signalling into the TSV this module scores  2. --score for the posture  3. --report for the handling
note	only the operator (or its national authority) can confirm an active intercept; this module encodes the artefacts and contacts nothing
EOF
}

# ════════════════════════════════════════════════════════════════════════
# ── the encoder half ────────────────────────────────────────────────────
#
# This section is a protocol encoder, not an interceptor. Three things sit
# between the operator and an artefact, and they are separate on purpose,
# because the failure this tree keeps paying for is a module that skips one and
# prints a success line anyway:
#
#   1. the bytes. Two protocols, named apart because they are not the same
#      thing:
#
#        X1/HI1 provisioning and activation are 3GPP TS 33.108 Annex M HI1
#        (ThreeGPP-HI1NotificationOperations), BER per X.690. They are built by
#        tools/li_hi1.py — a standard-library encoder, so the module carries no
#        third-party dependency — and tools/check-li-ber.sh checks that encoder
#        against pycrate, which compiles tools/asn/ts33108-hi1.asn and encodes
#        the same values. A hand-written encoder that only agrees with itself
#        would be worth nothing.
#
#        X3/HI3 interception products are this module's own length-prefixed TLV
#        envelope (magic LIPR). TS 33.108's HI3 record is not transcribed in
#        this tree, and the failure it has paid for three times is a fabricated
#        ASN.1 type with invented fields. A labelled self-defined envelope is
#        honest; an invented HI3 PDU is not.
#
# Nothing here opens a socket, and no verb can claim an artefact was sent,
# activated or intercepted. --intercept takes its payload as an argument
# precisely because this module captures nothing.

LIPR_ENVELOPE_MAGIC=4C495052      # "LIPR", this module's own magic
LIPR_ENVELOPE_VERSION=1

# The note every encoder verb carries. It is a TSV row rather than a stderr
# block: a verb that refuses nothing has no reason to shout, and a reader who
# parses the output still learns what the artefact is for and what it is not.
#
#   3GPP TS 33.107/33.108 define the X1/HI1, X2/HI2 and X3/HI3 interfaces. This
#   module encodes artefacts and delivers none of them.
LIPR_NOTE='lawful interception is operated by a network under statutory authority; these verbs encode artefacts and contact no ADMF, DF2, DF3 or LEMF'

# ── the HI1 encoder (TS 33.108 Annex M, BER) ────────────────────────────
# tools/li_hi1.py is the encoder: Python's standard library only, no pycrate at
# runtime, checked against pycrate by tools/check-li-ber.sh. This module owns the
# conf, the validation and the reporting; the bytes come from the one encoder so
# there is a single place to be right or wrong.
LIPR_HI1_TOOL="$IMSISTING_ROOT/tools/li_hi1.py"

# Its refusal (exit 3) becomes this module's refusal (exit 2) with the same
# words: "the standard cannot carry that value" and "this module will not write
# it" are the same answer to the operator.
lipr_hi1_call() {   # prints the encoder's TSV; rc 0 on success
    local out="" rc=0 e w
    [[ -f "$LIPR_HI1_TOOL" ]] || {
        lipr_fail "tools/li_hi1.py is missing; it is the HI1 encoder this module ships"
        return 1; }
    command -v python3 >/dev/null 2>&1 || {
        lipr_fail "python3 is not on PATH; tools/li_hi1.py is the HI1 encoder"
        return 1; }
    out=$(python3 "$LIPR_HI1_TOOL" --encode "$@" 2>"$MOD_TMP/li_hi1.err") || rc=$?
    if (( rc != 0 )); then
        e=$(awk -F'\t' '$1=="ERROR"{print $2; exit}' "$MOD_TMP/li_hi1.err" 2>/dev/null)
        w=$(awk -F'\t' '$1=="WHY"{print $2; exit}' "$MOD_TMP/li_hi1.err" 2>/dev/null)
        if (( rc == 3 )); then
            lipr_refuse "${e:-tools/li_hi1.py refused the value}" \
                "${w:-the HI1 operation cannot carry that value}"
            return 2
        fi
        lipr_fail "${e:-tools/li_hi1.py exited $rc}"
        return 1
    fi
    [[ -n "$out" ]] || { lipr_fail "tools/li_hi1.py printed no PDU"; return 1; }
    printf '%s\n' "$out"
}

# This module's TARGET_TYPE table is its own; TS 33.108's TargetType names only
# some of the forms, so the ones with no code are reported rather than guessed at.
lipr_target_type_code() {   # $1 module type, $2 target -> a TargetType name or ""
    case "${1:-}" in
        imsi)   printf 'imsi' ;;
        msisdn) printf 'msisdn' ;;
        uri)
            case "${2:-}" in
                sip:*) printf 'sip-uri' ;;
                tel:*) printf 'tel-uri' ;;
                *)     printf '' ;;
            esac ;;
        *) printf '' ;;
    esac
}

# A row for what the PDU does not carry. It is printed rather than omitted: a
# reader who supplied a field has to be told the artefact does not contain it.
lipr_not_encoded() {   # $1 field, $2 the module's value, $3 why it is not in the PDU
    printf 'not_encoded\t%s\t%s\t%s\n' "$1" "$(lipr_sanitize "${2:-}")" "$3"
}

# Print one HI1 artefact: this module's rows, then the encoder's field table.
# LIPR_ART_HEX is set from the encoder so --out writes the PDU and nothing else.
lipr_emit_hi1() {   # $1 label, $2 interface, $3 the encoder's TSV
    local label="$1" iface="$2" tsout="$3"
    LIPR_ART_HEX=$(printf '%s\n' "$tsout" | awk -F'\t' '$1=="pdu_hex"{print $2; exit}')
    printf 'artefact\t%s\n' "$label"
    printf 'interface\t%s\n' "$iface"
    printf 'standard\t%s\n' "$(printf '%s\n' "$tsout" | awk -F'\t' '$1=="standard"{print $2; exit}')"
    printf 'encoding\t%s\n' "$(printf '%s\n' "$tsout" | awk -F'\t' '$1=="encoding"{print $2; exit}')"
    printf 'operation\t%s\n' "$(printf '%s\n' "$tsout" | awk -F'\t' '$1=="operation"{print $2; exit}')"
    printf 'artefact_bytes\t%s\n' "$(printf '%s\n' "$tsout" | awk -F'\t' '$1=="pdu_bytes"{print $2; exit}')"
    printf 'artefact_hex\t%s\n' "$LIPR_ART_HEX"
    printf '%s\n' "$tsout" | awk -F'\t' '$1=="tlv"'
    printf 'field_count\t%s\n' "$(printf '%s\n' "$tsout" | awk -F'\t' '$1=="tlv"{c++} END{print c+0}')"
}

# The conf keys that name HI1's Network-Identifier, which is optional: the
# operator's identifier (1..5 ASCII) and the network element (form:value).
LIPR_C_OPERATOR="" LIPR_C_NE=""

# Build the HI1 operation for a loaded conf and print the encoder's TSV.
# $1 = liActivated|liDeactivated, $2 = label, $3 = interface, $4 = the extra
# note row for the operation? No: the caller emits its own rows around this.
lipr_hi1_build() {   # $1 operation; sets LIPR_HI1_TSV
    local op="$1" tcode now
    now=$(lipr_now) || return $?
    tcode=$(lipr_target_type_code "$LIPR_C_TYPE" "$LIPR_C_TARGET")
    local -a hargs=( --operation "$op" --liid "$LIPR_C_WARRANT" --epoch "$now" )
    [[ -n "$tcode" ]] && hargs+=( --target-type "$tcode" )
    [[ -n "$LIPR_C_OPERATOR" ]] && hargs+=( --operator-id "$LIPR_C_OPERATOR" )
    [[ -n "$LIPR_C_NE" ]] && hargs+=( --ne-id "$LIPR_C_NE" )
    LIPR_HI1_TSV=$(lipr_hi1_call "${hargs[@]}") || return $?
    LIPR_HI1_TCODE="$tcode"
    return 0
}

# The rows for the conf fields that the HI1 Notification has no field for. The
# standard's Notification carries the LIID, a time and the network identifier;
# it does not carry the subscriber identity (the LIID is the correlation key),
# the IRI/CC service pair, or a delivery destination with a port.
lipr_hi1_not_encoded() {   # $1 = mode (provision|activate)
    lipr_not_encoded target_identity "$LIPR_C_TARGET" \
        "TS 33.108's HI1 Notification has no target-identity field: the LIID above is the identifier the lawful authorisation names, and the ADMF maps it to this subscriber. The octets of the identity are printed here because they were given, not because they are in the PDU."
    if [[ -n "$LIPR_HI1_TCODE" ]]; then
        printf 'target_type\t%s\n' "$(lipr_sanitize "$LIPR_C_TYPE")"
    else
        lipr_not_encoded target_type "$LIPR_C_TYPE" \
            "TS 33.108's TargetType ENUMERATED names mSISDN, iMSI, iMEI, e164-Format, nAI, sip-URI, tel-URI, iMPU and iMPI; this identity form has no enumerator, so target-Information is left out rather than carrying a wrong code"
    fi
    if [[ -n "$LIPR_C_SERVICES" ]]; then
        lipr_not_encoded services "$LIPR_C_SERVICES" \
            "HI1 has no field that enables IRI and CC; InterceptionType's voice/data wording is a different question, and writing it here would claim a voice/data split the conf never stated"
    fi
    if [[ -n "$LIPR_C_DF2" ]]; then
        lipr_not_encoded df2_destination "$LIPR_C_DF2" \
            "HI1's DeliveryInformation carries an IPAddress, which has no port and no host name; a host:port delivery destination would lose the port, so it stays in the conf and this row says so"
    fi
    if [[ -n "$LIPR_C_DF3" ]]; then
        lipr_not_encoded df3_destination "$LIPR_C_DF3" \
            "as for DF2_DEST: the destination the conf names is not the address HI1 would carry, and it is not silently truncated to one"
    fi
}

# ── the envelope builder ────────────────────────────────────────────────
# Layout: magic(4) version(1) artefact_type(1) then repeated
#         tag(1) length(2, big-endian) value(length)
# Every field row records the value's offset, its length and its octets, so a
# reader can find the field in the hex without trusting this module's word.
LIPR_ART_HEX=""
LIPR_ART_OFF=0
LIPR_FIELD_ROWS=()

lipr_art_reset() {
    LIPR_ART_HEX=""
    LIPR_ART_OFF=0
    LIPR_FIELD_ROWS=()
}
lipr_art_start() {   # $1 = artefact type octet
    LIPR_ART_HEX="${LIPR_ENVELOPE_MAGIC}$(lipr_byte "$LIPR_ENVELOPE_VERSION")$(lipr_byte "${1:-0}")"
    LIPR_ART_OFF=6
}
lipr_tlv() {         # tag name display_value encoding value_hex
    local tag="${1:-0}" name="${2:-}" value="${3:-}" enc="${4:-}" vhex="${5:-}"
    local vlen=$(( ${#vhex} / 2 )) off="$LIPR_ART_OFF"
    LIPR_ART_HEX+="$(lipr_byte "$tag")$(lipr_u16be "$vlen")${vhex}"
    LIPR_FIELD_ROWS+=("$(printf 'field\t%s\t%s\t%d\t%s\t%d\t%s' \
        "$name" "$(lipr_sanitize "$value")" "$vlen" "$enc" "$off" "$vhex")")
    LIPR_ART_OFF=$(( off + 3 + vlen ))
}
lipr_emit_common() {  # label type_octet interface ordering
    local label="$1" tcode="$2" iface="$3" ordering="$4"
    printf 'artefact\t%s\n' "$label"
    printf 'interface\t%s\n' "$iface"
    printf 'artefact_type\t0x%s\n' "$(lipr_byte "$tcode")"
    printf 'envelope\t%s\n' 'self-defined: magic 4C495052 ("LIPR") + version 0x01 + artefact type + repeated tag(1) length(2, big-endian) value(N)'
    printf 'standard\t%s\n' 'TS 33.108 names the X1/HI1, X2/HI2 and X3/HI3 interfaces; its HI1 module is encoded by tools/li_hi1.py, and its HI3 record is NOT transcribed in this tree, so this artefact is a self-defined envelope and not a TS 33.108 PDU'
    printf 'ordering\t%s\n' "$ordering"
    printf 'artefact_bytes\t%d\n' "$(( ${#LIPR_ART_HEX} / 2 ))"
    printf 'artefact_hex\t%s\n' "$LIPR_ART_HEX"
    if (( ${#LIPR_FIELD_ROWS[@]} > 0 )); then
        printf '%s\n' "${LIPR_FIELD_ROWS[@]}"
    fi
    printf 'field_count\t%d\n' "${#LIPR_FIELD_ROWS[@]}"
}
lipr_emit_out() {     # $1 = --out path or empty
    local out="${1:-}"
    [[ -n "$out" ]] || return 0
    lipr_write_bytes "$out" "$LIPR_ART_HEX" || return 1
    printf 'out_file\t%s\n' "$(lipr_sanitize "$out")"
    printf 'out_bytes\t%d\n' "$(( ${#LIPR_ART_HEX} / 2 ))"
    return 0
}
lipr_emit_handoff() {  # $1 = exact handoff text
    printf 'status\thandoff\n'
    printf 'sent\t0\n'
    printf 'handoff\t%s\n' "$1"
}

# ── conf: a small KEY=VALUE file, validated rather than trusted ─────────
# An unknown key is refused, not ignored: a mistyped key silently dropped
# produces a request that does not say what its author thinks it says.
LIPR_C_TYPE="" LIPR_C_TARGET="" LIPR_C_WARRANT="" LIPR_C_SERVICES=""
LIPR_C_DF2="" LIPR_C_DF3=""
LIPR_ID_CODE="" LIPR_ID_HEX="" LIPR_ID_ENC="" LIPR_ID_TEXT=""
LIPR_SERVICES_MASK="" LIPR_SERVICES_TEXT=""
LIPR_CONF_IGNORED=""

lipr_trim() {
    local s="${1:-}"
    s="${s#"${s%%[![:space:]]*}"}"
    s="${s%"${s##*[![:space:]]}"}"
    printf '%s' "$s"
}

# Identity types and codes are this module's own table (printed in every
# artefact), not an ASN.1 ENUMERATED read out of the standard.
#   imsi -> 1, msisdn -> 2, supi -> 3, uri -> 4, email -> 5
# IMSI and MSISDN are carried as semi-octet BCD, the others as text octets.
lipr_identity_encode() {
    local t="${1:-}" v="${2:-}"
    case "$t" in
        imsi)
            [[ "$v" =~ ^[0-9]{6,15}$ ]] || {
                lipr_refuse "TARGET '$v' is not an IMSI" \
                    "an IMSI is at most 15 digits and at least 6 (a 3-digit MCC, a 2- or 3-digit MNC and at least one MSIN digit); anything else is a different identity form -- say TARGET_TYPE=supi or uri instead of guessing"
                return 2; }
            LIPR_ID_CODE=1
            LIPR_ID_HEX=$(lipr_bcd "$v") || return 1
            LIPR_ID_ENC="bcd semi-octet (2 digits/octet, low nibble first, odd count padded 0xF)"
            LIPR_ID_TEXT="$v"
            ;;
        msisdn)
            [[ "$v" =~ ^[0-9]{1,15}$ ]] || {
                lipr_refuse "TARGET '$v' is not an MSISDN" \
                    "an E.164 number is at most 15 digits; the country code is part of the digits, do not add a + or separators"
                return 2; }
            LIPR_ID_CODE=2
            LIPR_ID_HEX=$(lipr_bcd "$v") || return 1
            LIPR_ID_ENC="bcd semi-octet (2 digits/octet, low nibble first, odd count padded 0xF)"
            LIPR_ID_TEXT="$v"
            ;;
        supi)
            [[ "$v" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$ ]] || {
                lipr_refuse "TARGET '$v' is not a usable SUPI text" \
                    "a 5G SUPI is carried here as its text form (for example imsi-<digits>); this encoder will not validate the 5G identity grammar itself, so it accepts 1..64 ASCII characters and refuses anything else rather than encoding a different identity"
                return 2; }
            LIPR_ID_CODE=3
            LIPR_ID_HEX=$(lipr_hexify "$v") || return 1
            LIPR_ID_ENC="utf-8 octets of the text form"
            LIPR_ID_TEXT="$v"
            ;;
        uri)
            [[ "$v" =~ ^[A-Za-z][A-Za-z0-9+.-]*://[^[:space:]]+$ ]] || {
                lipr_refuse "TARGET '$v' is not a URI" \
                    "a URI target needs a scheme and no whitespace (for example sip:user@example.invalid); a bare address is TARGET_TYPE=email or supi, and an IMSI is TARGET_TYPE=imsi"
                return 2; }
            LIPR_ID_CODE=4
            LIPR_ID_HEX=$(lipr_hexify "$v") || return 1
            LIPR_ID_ENC="utf-8 octets of the URI"
            LIPR_ID_TEXT="$v"
            ;;
        email)
            [[ "$v" =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]] || {
                lipr_refuse "TARGET '$v' is not an email address" \
                    "an email target needs one local part, one @ and a dotted domain, with no whitespace"
                return 2; }
            LIPR_ID_CODE=5
            LIPR_ID_HEX=$(lipr_hexify "$v") || return 1
            LIPR_ID_ENC="utf-8 octets of the address"
            LIPR_ID_TEXT="$v"
            ;;
        *)
            lipr_refuse "TARGET_TYPE '$t' is not one this encoder carries" \
                "the forms are imsi, msisdn, supi, uri and email; there is no silent default, because an identity encoded under the wrong type is a request for the wrong target"
            return 2 ;;
    esac
    return 0
}

# SERVICES -> a one-octet bitmask. 0x01 IRI toward DF2 (X2/HI2), 0x02 CC toward
# DF3 (X3/HI3). Order and repetition in the conf do not matter; an unknown
# service is refused, because a bit this module invents means nothing to the
# receiving DF.
lipr_services_mask() {   # prints the decimal mask; rc 2 on refusal
    local text="${1:-}" svc rest mask=0
    [[ -n "$text" ]] || {
        lipr_refuse "SERVICES is empty" "a provisioning request that asks for no service requests nothing; use SERVICES=iri, SERVICES=cc or SERVICES=iri,cc"
        return 2; }
    [[ "$text" =~ ^[a-z]+(,[a-z]+)*$ ]] || {
        lipr_refuse "SERVICES '$text' is not a comma-separated list of service names" "the list is iri and/or cc, with no spaces: iri,cc"
        return 2; }
    rest="$text"
    while [[ -n "$rest" ]]; do
        if [[ "$rest" == *,* ]]; then svc="${rest%%,*}"; rest="${rest#*,}"; else svc="$rest"; rest=""; fi
        case "$svc" in
            iri) mask=$(( mask | 1 )) ;;
            cc)  mask=$(( mask | 2 )) ;;
            *) lipr_refuse "unknown service '$svc' in SERVICES" "the services are iri (X2/HI2 intercept-related information, delivered by DF2) and cc (X3/HI3 content of communication, delivered by DF3); this module has no code for anything else"
               return 2 ;;
        esac
    done
    LIPR_SERVICES_TEXT="$text"
    LIPR_SERVICES_MASK="$mask"
    printf '%s' "$mask"
}

# host:port, where host is a name, an IPv4 literal, or a bracketed IPv6
# literal, and the port is 1..65535.
lipr_validate_dest() {
    local what="$1" v="$2" host="${2%:*}" port="${2##*:}"
    [[ -n "$v" ]] || { lipr_refuse "$what is empty" "a delivery destination is host:port"; return 2; }
    [[ "$v" == *:* ]] || { lipr_refuse "$what '$v' has no port" "a delivery destination is host:port, for example 10.0.0.2:9002"; return 2; }
    [[ -n "$host" ]] || { lipr_refuse "$what '$v' has an empty host" "a delivery destination is host:port"; return 2; }
    [[ "$port" =~ ^[0-9]{1,5}$ ]] || { lipr_refuse "$what '$v' has a non-numeric port" "the port is the digits after the last colon, 1..65535"; return 2; }
    (( 10#$port >= 1 && 10#$port <= 65535 )) || {
        lipr_refuse "$what '$v' has port $port outside 1..65535" "a delivery function listens on a real TCP port; 0 and above 65535 are not ports"
        return 2; }
    if [[ "$host" =~ ^\[[0-9A-Fa-f:]+\]$ ]]; then
        return 0
    fi
    [[ "$host" =~ ^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$ ]] || {
        lipr_refuse "$what host '$host' is not a name or an address" "the host is a DNS name, an IPv4 literal, or a bracketed IPv6 literal; a scheme, a path or a trailing dot is not"
        return 2; }
    return 0
}

# $1 path, $2 mode (provision|activate). Populates the LIPR_* fields or refuses
# with rc 2. Nothing is encoded here.
lipr_conf_load() {
    local path="${1:-}" mode="${2:-provision}" line key val lineno=0
    LIPR_C_TYPE="" LIPR_C_TARGET="" LIPR_C_WARRANT="" LIPR_C_SERVICES=""
    LIPR_C_DF2="" LIPR_C_DF3="" LIPR_C_OPERATOR="" LIPR_C_NE=""
    LIPR_CONF_IGNORED=""
    LIPR_ID_CODE="" LIPR_ID_HEX="" LIPR_ID_ENC="" LIPR_ID_TEXT=""
    LIPR_SERVICES_MASK="" LIPR_SERVICES_TEXT=""
    [[ -n "$path" ]] || { lipr_refuse "no conf file given" "the interface is --provision-target <conf> or --activate <conf>; the conf is a small KEY=VALUE file"; return 2; }
    [[ -e "$path" ]] || { lipr_fail "no such conf file: $path"; return 1; }
    [[ -f "$path" ]] || { lipr_fail "not a regular file: $path"; return 1; }
    [[ -r "$path" ]] || { lipr_fail "conf file is not readable: $path"; return 1; }
    while IFS= read -r line || [[ -n "$line" ]]; do
        lineno=$(( lineno + 1 ))
        line="${line%$'\r'}"
        [[ "$line" =~ ^[[:space:]]*$ ]] && continue
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ "$line" == *=* ]] || {
            lipr_refuse "conf line $lineno has no KEY=VALUE: $(lipr_sanitize "$line")" "every non-comment line is one KEY=VALUE pair; a line this module cannot read is a line it will not guess at"
            return 2; }
        key=$(lipr_trim "${line%%=*}")
        val=$(lipr_trim "${line#*=}")
        case "$key" in
            TARGET_TYPE) LIPR_C_TYPE="$val" ;;
            TARGET)      LIPR_C_TARGET="$val" ;;
            WARRANT)     LIPR_C_WARRANT="$val" ;;
            SERVICES)    LIPR_C_SERVICES="$val" ;;
            DF2_DEST)    LIPR_C_DF2="$val" ;;
            DF3_DEST)    LIPR_C_DF3="$val" ;;
            OPERATOR_ID) LIPR_C_OPERATOR="$val" ;;
            NETWORK_ELEMENT) LIPR_C_NE="$val" ;;
            *) lipr_refuse "unknown conf key '$key' at line $lineno" "the keys are TARGET_TYPE, TARGET, WARRANT, SERVICES, DF2_DEST, DF3_DEST and optionally OPERATOR_ID and NETWORK_ELEMENT (form:value, e164|x25|ip|dns); a mistyped key that is silently ignored encodes a request that does not say what its author thought it said"
               return 2 ;;
        esac
    done < "$path"

    [[ -n "$LIPR_C_TYPE" ]] || { lipr_refuse "conf has no TARGET_TYPE" "TARGET_TYPE names the identity form: imsi, msisdn, supi, uri or email"; return 2; }
    [[ -n "$LIPR_C_TARGET" ]] || { lipr_refuse "conf has no TARGET" "TARGET is the identity the warrant names; there is nothing to provision without it"; return 2; }
    [[ -n "$LIPR_C_WARRANT" ]] || { lipr_refuse "conf has no WARRANT" "WARRANT is the authorisation reference the record is tied to; an intercept record with no authorisation reference is the thing this module exists to stop"; return 2; }
    [[ "$LIPR_C_WARRANT" =~ ^[^[:cntrl:]]{1,64}$ ]] || { lipr_refuse "WARRANT is not 1..64 printable characters" "the reference is a short printable string; control characters cannot be carried in a text field and are refused rather than stripped"; return 2; }

    lipr_identity_encode "$LIPR_C_TYPE" "$LIPR_C_TARGET" || return 2
    lipr_services_mask "$LIPR_C_SERVICES" >/dev/null || return 2

    if [[ "$mode" == "provision" ]]; then
        if (( LIPR_SERVICES_MASK & 1 )) && [[ -z "$LIPR_C_DF2" ]]; then
            lipr_refuse "SERVICES includes iri but DF2_DEST is missing" "an IRI request has to say where DF2 delivers it; without a destination the request is undeliverable"
            return 2
        fi
        if (( LIPR_SERVICES_MASK & 2 )) && [[ -z "$LIPR_C_DF3" ]]; then
            lipr_refuse "SERVICES includes cc but DF3_DEST is missing" "a content-of-communication request has to say where DF3 delivers it; without a destination the request is undeliverable"
            return 2
        fi
        if [[ -n "$LIPR_C_DF2" ]] && (( ! (LIPR_SERVICES_MASK & 1) )); then
            lipr_refuse "DF2_DEST is set but SERVICES does not include iri" "a destination for a service that was not requested is a contradiction; drop the key or add iri to SERVICES"
            return 2
        fi
        if [[ -n "$LIPR_C_DF3" ]] && (( ! (LIPR_SERVICES_MASK & 2) )); then
            lipr_refuse "DF3_DEST is set but SERVICES does not include cc" "a destination for a service that was not requested is a contradiction; drop the key or add cc to SERVICES"
            return 2
        fi
        [[ -n "$LIPR_C_DF2" ]] && { lipr_validate_dest DF2_DEST "$LIPR_C_DF2" || return 2; }
        [[ -n "$LIPR_C_DF3" ]] && { lipr_validate_dest DF3_DEST "$LIPR_C_DF3" || return 2; }
    else
        # An activation record is about a target already provisioned: the
        # delivery destinations belong to the provisioning record, so they are
        # reported as carried nowhere rather than dropped in silence.
        if [[ -n "$LIPR_C_DF2" || -n "$LIPR_C_DF3" ]]; then
            LIPR_CONF_IGNORED="DF2_DEST and DF3_DEST are provisioning destinations; the activation record does not carry them"
        fi
    fi
    return 0
}

# Whole seconds since the epoch for the activation and capture timestamps.
# LIPR_NOW makes a harness run reproducible; without it the clock is read once.
lipr_now() {
    local n="${LIPR_NOW:-}"
    if [[ -z "$n" ]]; then
        n=$(date -u +%s 2>/dev/null) || { lipr_fail "cannot read the clock for the timestamp"; return 1; }
    fi
    [[ "$n" =~ ^[0-9]{1,10}$ ]] || { lipr_refuse "LIPR_NOW '$n' is not whole seconds since the epoch" "the timestamp is an unsigned 32-bit second count; set LIPR_NOW to a number in 0..4294967295"; return 2; }
    (( 10#$n <= 4294967295 )) || { lipr_refuse "LIPR_NOW '$n' does not fit an unsigned 32-bit second count" "0..4294967295"; return 2; }
    printf '%s' "$(( 10#$n ))"
}

lipr_seq() {
    local n="${LIPR_SEQ:-0}"
    [[ "$n" =~ ^[0-9]{1,10}$ ]] || { lipr_refuse "LIPR_SEQ '$n' is not a sequence number" "the sequence is an unsigned 32-bit integer; 0 is the first octet string of a session"; return 2; }
    (( 10#$n <= 4294967295 )) || { lipr_refuse "LIPR_SEQ '$n' does not fit an unsigned 32-bit integer" "0..4294967295"; return 2; }
    printf '%s' "$(( 10#$n ))"
}

# ── --provision-target ──────────────────────────────────────────────────
# The provisioning request as a real PDU: the TS 33.108 Annex M HI1 operation
# (liActivated), BER-encoded by tools/li_hi1.py. TS 33.108 defines no separate
# provisioning operation and no ASN.1 for the ADMF-to-DF leg, so the request is
# the standard's own activation notification, and the conf fields the operation
# has no room for are printed as not encoded. It contacts nothing.
lipr_cmd_provision() {
    local conf="" out=""
    while (( $# )); do
        case "$1" in
            --out) out="${2:-}"; shift 2 ;;
            --*)
                lipr_refuse "--provision-target does not take $1" "the interface is --provision-target <conf> [--out <path>]"
                return 2 ;;
            *)
                if [[ -z "$conf" ]]; then conf="$1"; shift
                else lipr_refuse "two conf paths given: $conf and $1" "one invocation provisions one target"; return 2; fi ;;
        esac
    done
    lipr_require_od || return 1
    lipr_conf_load "$conf" provision || return $?
    lipr_hi1_build liActivated || return $?

    lipr_art_reset
    lipr_emit_hi1 "provisioning_request" \
        "X1/HI1 administration (ADMF -> DF2/DF3), carried as the TS 33.108 Hi1 operation" \
        "$LIPR_HI1_TSV"
    printf 'note\t%s\n' "$LIPR_NOTE"
    lipr_hi1_not_encoded provision
    lipr_emit_out "$out" || return 1
    lipr_emit_handoff "an ADMF on X1/HI1 that accepts this activation notification and drives DF2 (IRI, X2/HI2) and DF3 (CC, X3/HI3); this module encodes the PDU, opens no socket and sends nothing, so delivery is the operator's action on the operator's own core"
    return 3
}

# ── --activate ──────────────────────────────────────────────────────────
# The activation record for an already-provisioned target: the TS 33.108 Annex M
# HI1 operation, BER-encoded by tools/li_hi1.py. --action activate is
# liActivated, --action withdraw is liDeactivated -- two alternatives of the
# standard's CHOICE, not one record shape with a home-made action octet.
lipr_cmd_activate() {
    local conf="" out="" action="activate" acode=""
    while (( $# )); do
        case "$1" in
            --action) action="${2:-}"; shift 2 ;;
            --out)    out="${2:-}"; shift 2 ;;
            --*)
                lipr_refuse "--activate does not take $1" "the interface is --activate <conf> [--action activate|withdraw] [--out <path>]"
                return 2 ;;
            *)
                if [[ -z "$conf" ]]; then conf="$1"; shift
                else lipr_refuse "two conf paths given: $conf and $1" "one invocation activates or withdraws one target"; return 2; fi ;;
        esac
    done
    case "$action" in
        activate) acode=1 ;;
        withdraw) acode=2 ;;
        *) lipr_refuse "action '$action' is not activate or withdraw" "the activation record carries one action code; this module's table is 0x01 activate and 0x02 withdraw"
           return 2 ;;
    esac
    lipr_require_od || return 1
    lipr_conf_load "$conf" activate || return $?
    local hi1op
    case "$acode" in
        1) hi1op=liActivated ;;
        2) hi1op=liDeactivated ;;
    esac
    lipr_hi1_build "$hi1op" || return $?

    lipr_art_reset
    lipr_emit_hi1 "activation_record" \
        "X1/HI1 administration (ADMF -> DF2/DF3), carried as the TS 33.108 Hi1 operation" \
        "$LIPR_HI1_TSV"
    printf 'action\t%s\n' "$action"
    printf 'note\t%s\n' "$LIPR_NOTE"
    if [[ -n "$LIPR_CONF_IGNORED" ]]; then
        printf 'note\t%s\n' "$LIPR_CONF_IGNORED"
    fi
    lipr_emit_out "$out" || return 1
    lipr_emit_handoff "the ADMF on X1/HI1 that owns this target's existing intercept: an activation or withdrawal record that reaches it starts or ends a real collection, so this module encodes the record, opens no socket, and hands delivery to the operator"
    return 3
}

# ── --intercept ─────────────────────────────────────────────────────────
# The X3/HI3 interception-product envelope around a payload the operator
# supplies. It captures nothing: the payload is an argument, and the output
# says so.
lipr_cmd_intercept() {
    local payload="" case_id="" out="" now seq
    while (( $# )); do
        case "$1" in
            --case) case_id="${2:-}"; shift 2 ;;
            --out)  out="${2:-}"; shift 2 ;;
            --*)
                lipr_refuse "--intercept does not take $1" "the interface is --intercept <hex> [--case <id>] [--out <path>]; LIPR_NOW and LIPR_SEQ set the timestamp and sequence for a reproducible run"
                return 2 ;;
            *)
                if [[ -z "$payload" ]]; then payload="$1"; shift
                else lipr_refuse "two payloads given: $payload and $1" "one envelope carries one payload"; return 2; fi ;;
        esac
    done
    lipr_require_od || return 1

    [[ -n "$payload" ]] || {
        lipr_refuse "no payload given" "the envelope carries content the operator supplied; this module captures nothing, so an empty payload would be an envelope around nothing -- the provisioning and activation verbs are the signalling records"
        return 2; }
    [[ "$payload" =~ ^([0-9A-Fa-f]{2})+$ ]] || {
        lipr_refuse "payload is not an even-length hex octet string: $(lipr_sanitize "$payload")" "the payload is raw octets in hex, two digits per octet; an odd digit count or a non-hex character is refused rather than padded or truncated"
        return 2; }
    payload="${payload^^}"

    if [[ -n "$case_id" ]]; then
        [[ "$case_id" =~ ^[A-Za-z0-9._:-]{1,64}$ ]] || {
            lipr_refuse "case id '$case_id' is not a usable correlation identifier" "the correlation identifier ties the product to one intercept; it is 1..64 characters from A-Z a-z 0-9 . _ : - and nothing else"
            return 2; }
    else
        case_id="unassigned"
    fi
    now=$(lipr_now) || return $?
    seq=$(lipr_seq) || return $?

    lipr_art_reset
    lipr_art_start 3
    lipr_tlv 9 correlation_id "$case_id" \
        "utf-8 octets of the correlation identifier; 'unassigned' when no --case was given" \
        "$(lipr_hexify "$case_id")"
    lipr_tlv 10 capture_time "$now" \
        "u32 big-endian, seconds since the Unix epoch, UTC" "$(lipr_u32be "$now")"
    lipr_tlv 11 sequence_number "$seq" \
        "u32 big-endian, the product's position in the session" "$(lipr_u32be "$seq")"
    lipr_tlv 12 payload "$payload" \
        "the operator's octets, encoded in place and unchanged" "$payload"

    lipr_emit_common "interception_product" 3 "X3/HI3 content of communication (DF3 -> LEMF)" \
        "correlation_id, capture_time, sequence_number, payload (this module's order)"
    printf 'note\t%s\n' "$LIPR_NOTE"
    printf 'payload_source\targument (this module captured nothing)\n'
    printf 'captured\t0\n'
    printf 'intercepted\t0\n'
    if [[ "$case_id" == "unassigned" ]]; then
        printf 'note\tno --case was given; the correlation identifier is the literal string unassigned, which a DF3 has to replace before this envelope can be tied to an intercept\n'
    fi
    lipr_emit_out "$out" || return 1
    lipr_emit_handoff "a DF3 on X3/HI3 that carries this product towards an LEMF; the payload here is the octet string the operator supplied, not a capture, so this module encodes the envelope, opens no socket, and hands delivery to the operator"
    return 3
}

# ── scope check ─────────────────────────────────────────────────────────
# The seam this guards: the encoder verbs produce an artefact and deliver
# nothing, and the detection verbs stay ungated because they read what they are
# handed. A gate on a reader is theatre; a delivery claim on a writer is a lie.
lipr_scope_check() {
    local self="${BASH_SOURCE[0]}" hits=0 v body
    [[ -f "$self" ]] || { lipr_fail "cannot read module source"; return 1; }
    for v in lipr_cmd_provision lipr_cmd_activate lipr_cmd_intercept; do
        body=$(awk -v fn="$v() {" 'index($0, fn) == 1 { f = 1 } f { print } f && /^}/ { exit }' "$self")
        if [[ -z "$body" ]]; then
            printf 'scope_violation\t%s is missing\n' "$v"; hits=$(( hits + 1 )); continue
        fi
        # It must exit 3 with a handoff rather than return 0 as if it delivered.
        grep -q 'return 3' <<< "$body" || {
            printf 'scope_violation\t%s does not end in a handoff (return 3)\n' "$v"; hits=$(( hits + 1 )); }
        # And it must say what it did not do.
        grep -q "LIPR_NOTE" <<< "$body" || {
            printf 'scope_violation\t%s does not carry the note about what it never contacts\n' "$v"; hits=$(( hits + 1 )); }
        if grep -qE 'curl|wget|nc -|socket\(|urllib' <<< "$body"; then
            printf 'scope_violation\t%s opens a transport; this module delivers nothing\n' "$v"; hits=$(( hits + 1 )); fi
    done
    printf 'scope\t%s\n' "$([[ $hits -eq 0 ]] && echo encodes-and-hands-off || echo VIOLATION)"
    printf 'scope_checked\t3 encoder verbs x (handoff + note + no transport)\n'
    (( hits == 0 )) || return 1
    return 0
}

lipr_selftest() {
    local bad=0 nchk=0
    chk() {
        nchk=$(( nchk + 1 ))
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$(( bad + 1 )); fi
    }
    fld() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }
    has() { printf '%s\n' "$1" | grep -qi -- "$2" && echo yes || echo no; }
    tlvfield() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1=="field" && $2==k {print $7; exit}'; }
    # The HI1 encoder prints tlv <path> <tag> <len> <offset> <hex>; the path is
    # what a reader looks up, so the helper keys on it.
    h1field() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1=="tlv" && $2==k {print $6; exit}'; }

    local d
    d=$(mktemp -d "$MOD_TMP/selftest.XXXXXX") || {
        printf 'ERROR\tmktemp failed under %s\n' "$MOD_TMP" >&2; return 1; }
    trap 'rm -rf "$d"' EXIT
    export LOOT_DIR="$d/loot" CAPTURES_DIR="$d/captures" STATE_DIR="$d/state"
    export LIPR_DIR="$d/loot/li_probe"
    mkdir -p "$LIPR_DIR"

    # 1. Interface naming (TS 33.108): X1=HI1=admin, X2=HI2=IRI, X3=HI3=CC.
    chk if-x1 "$(lipr_name_of X1)" "administration (ADMF to DF2/DF3)"
    chk if-x2 "$(lipr_name_of X2)" "IRI (DF2 to LEMF, signalling events)"
    chk if-x3 "$(lipr_name_of X3)" "CC (DF3 to LEMF, content)"
    chk if-hi2 "$(lipr_name_of HI2)" "IRI (DF2 to LEMF, signalling events)"
    chk if-unknown "$(lipr_name_of X9)" "unknown interface — never classified as a handover interface"
    chk if-table-x2 "$(lipr_interfaces | awk -F'\t' '$1=="X2"{print $3}')" "IRI"

    # 2. A quiet subscriber scores low; a surveilled-looking one scores high.
    printf 'ts\timsi\tevent\tcell\tsilent\n' > "$d/quiet.tsv"
    printf '2026-01-01T00:00:00Z\t310150000000001\tlocation_update\tcellA\t\n' >> "$d/quiet.tsv"
    printf '2026-01-01T00:01:00Z\t310150000000001\tauth_request\tcellA\t\n' >> "$d/quiet.tsv"
    local out; out=$(lipr_score "$d/quiet.tsv")
    chk quiet-score "$(printf '%s\n' "$out" | awk -F'\t' '$1=="summary" && $2=="score"{print $3}')" "0"
    chk quiet-risk  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="summary" && $2=="risk"{print $3}')" "low"

    { printf 'ts\timsi\tevent\tcell\tsilent\n'
      for i in 1 2 3 4; do printf '2026-01-01T00:0%d:00Z\t310150000000002\tidentity_request\tcellA\t\n' "$i"; done
      printf '2026-01-01T00:05:00Z\t310150000000002\tsilent_sms\tcellA\tyes\n'
      for c in A B C D E F; do printf '2026-01-01T00:1%d:00Z\t310150000000002\tlocation_update\tcell%s\t\n' "$(( $(printf '%d' "'$c") - 65 ))" "$c"; done
    } > "$d/noisy.tsv"
    out=$(lipr_score "$d/noisy.tsv")
    chk noisy-forced "$(printf '%s\n' "$out" | awk -F'\t' '$1=="forced_identity_burst"{print $2}')" "HIGH"
    chk noisy-silent "$(printf '%s\n' "$out" | awk -F'\t' '$1=="silent_sms"{print $2}')" "HIGH"
    chk noisy-spread "$(printf '%s\n' "$out" | awk -F'\t' '$1=="wide_cell_spread"{print $2}')" "MEDIUM"
    chk noisy-risk   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="summary" && $2=="risk"{print $3}')" "high"
    chk noisy-score-pos "$(printf '%s\n' "$out" | awk -F'\t' '$1=="summary" && $2=="score"{print ($3>0)?"yes":"no"}')" "yes"
    chk score-missing "$(lipr_score "$d/none.tsv" >/dev/null 2>&1; echo $?)" "1"

    # 3. Report and plan are present and name the admissible record.
    chk report-escalation "$(lipr_report | awk -F'\t' '$1=="escalation"{print ($2 ~ /ADMF/)?"yes":"no"}')" "yes"
    chk plan-status "$(fld "$(lipr_plan)" status)" "handoff"

    # 4. Known-answer vectors for the two encodings the envelope rests on.
    #    BCD is hand-computed from its definition: two digits per octet,
    #    low-order nibble first, odd count padded 0xF.
    #      310150123456789 -> 13 10 05 21 43 65 87 F9
    #      15551234567     -> 51 55 21 43 65 F7
    #      1234            -> 21 43
    chk bcd-imsi15 "$(lipr_bcd 310150123456789)" "13100521436587F9"
    chk bcd-msisdn11 "$(lipr_bcd 15551234567)" "5155214365F7"
    chk bcd-even "$(lipr_bcd 1234)" "2143"
    chk imsi-refused "$(lipr_identity_encode imsi 31015A >/dev/null 2>&1; echo $?)" "2"
    chk imsi-too-long "$(lipr_identity_encode imsi 3101501234567890 >/dev/null 2>&1; echo $?)" "2"
    #    A URI is carried as the octets of its text: hand-computed ASCII.
    chk identity-uri-code "$(lipr_identity_encode uri 'https://a.b/c' >/dev/null 2>&1; printf '%s' "$LIPR_ID_CODE")" "4"
    chk identity-uri-hex  "$(lipr_identity_encode uri 'https://a.b/c' >/dev/null 2>&1; printf '%s' "$LIPR_ID_HEX")" "68747470733A2F2F612E622F63"
    chk identity-bad-type "$(lipr_identity_encode tmsi 12345 >/dev/null 2>&1; echo $?)" "2"
    #    SERVICES: one octet, bit 0 IRI, bit 1 CC. Order and repetition are the
    #    conf author's business; an unknown service is refused.
    chk services-iri "$(lipr_services_mask iri)" "1"
    chk services-cc "$(lipr_services_mask cc)" "2"
    chk services-both "$(lipr_services_mask iri,cc)" "3"
    chk services-order "$(lipr_services_mask cc,iri)" "3"
    chk services-dupe "$(lipr_services_mask iri,iri)" "1"
    chk services-unknown "$(lipr_services_mask gprs >/dev/null 2>&1; echo $?)" "2"
    chk services-empty "$(lipr_services_mask '' >/dev/null 2>&1; echo $?)" "2"

    # 5. No gate: every encoder verb runs with no flag and hands off, rc 3.
    #    prints ERROR and WHY on stderr, leaves stdout empty and writes
    #    nothing -- including when an --out path was supplied.
    local conf="$d/prov.conf"
    cat > "$conf" <<'CONF'
TARGET_TYPE=imsi
TARGET=310150123456789
WARRANT=LIID-0001
SERVICES=iri,cc
DF2_DEST=10.0.0.2:9002
DF3_DEST=10.0.0.2:9003
CONF
    local dout derr rc
    # The encoder runs with no flag and no environment variable: there is no
    # gate. What it still must not do is deliver, and that is what the handoff
    # and the empty stderr below are checking.
    dout=$(lipr_cli_main --provision-target "$conf" 2>/dev/null); rc=$?
    chk ungated-provision-rc "$rc" "3"
    chk ungated-provision-stdout "$(printf '%s\n' "$dout" | grep -c '^artefact	provisioning_request')" "1"
    derr=$(lipr_cli_main --provision-target "$conf" 2>&1 >/dev/null)
    chk ungated-stderr-empty "$(printf '%s\n' "$derr" | grep -c .)" "0"
    chk ungated-status-handoff "$(printf '%s\n' "$dout" | awk -F'\t' '$1=="status"{print $2}')" "handoff"
    chk ungated-sent-zero "$(printf '%s\n' "$dout" | awk -F'\t' '$1=="sent"{print $2}')" "0"
    chk ungated-note "$(printf '%s\n' "$dout" | grep -c '^note')" "1"
    chk ungated-activate "$(lipr_cli_main --activate "$conf" >/dev/null 2>&1; echo $?)" "3"
    chk ungated-intercept "$(lipr_cli_main --intercept 0A1B2C >/dev/null 2>&1; echo $?)" "3"

    # 6. The provisioning request is the real thing: the TS 33.108 Annex M HI1
    #    operation liActivated, BER per X.690, octet for octet the PDU pycrate
    #    produces for the same value (tools/check-li-ber.sh is the comparison).
    #    The literal is read off that referee, not off this module's encoder:
    #      A1 21                      Notification, context tag [1], 33 octets
    #        81 09 4C4949442D30303031   lawfulInterceptionIdentifier "LIID-0001"
    #        A3 0F                      timeStamp [3], explicit because it is a CHOICE
    #          81 0D 3236303...5A       utcTime "260101000000Z"
    #        A6 03                      target-Information [6]
    #          83 01 01                 targetType iMSI(1)
    #    = 2 + 11 + 17 + 5 = 35 octets.
    local PHI1="A12181094C4949442D30303031A30F810D3236303130313030303030305AA603830101"
    out=$(LIPR_NOW=1767225600 lipr_cli_main --provision-target "$conf" 2>/dev/null); rc=$?
    chk provision-rc "$rc" "3"
    chk provision-hex "$(fld "$out" artefact_hex)" "$PHI1"
    chk provision-bytes "$(fld "$out" artefact_bytes)" "35"
    chk provision-operation "$(fld "$out" operation)" "liActivated"
    chk provision-names-standard "$(has "$(fld "$out" standard)" 'TS 33.108')" "yes"
    chk provision-names-hi1 "$(has "$(fld "$out" standard)" 'ThreeGPP-HI1NotificationOperations')" "yes"
    chk provision-ber "$(has "$(fld "$out" encoding)" 'ber')" "yes"
    chk provision-liid "$(h1field "$out" liActivated.lawfulInterceptionIdentifier)" "4C4949442D30303031"
    chk provision-utc "$(h1field "$out" liActivated.timeStamp.utcTime)" "3236303130313030303030305A"
    chk provision-target-type "$(h1field "$out" liActivated.target-Information.targetType)" "01"
    chk provision-fields "$(printf '%s\n' "$out" | grep -c '^tlv')" "6"
    chk provision-field-count "$(fld "$out" field_count)" "6"
    chk provision-status "$(fld "$out" status)" "handoff"
    chk provision-sent "$(fld "$out" sent)" "0"
    #    The old lie is gone from the output, not just from the header comment.
    chk provision-not-self-defined "$(printf '%s\n' "$out" | grep -ci 'self-defined')" "0"
    chk provision-no-limits-row "$(printf '%s\n' "$out" | grep -c '^ENVELOPE')" "0"
    #    A conf field the operation has no room for is printed as not encoded,
    #    once per field, with the reason -- never folded into a field it is not.
    chk provision-not-encoded-count "$(printf '%s\n' "$out" | grep -c '^not_encoded')" "4"
    chk provision-not-encoded-names "$(printf '%s\n' "$out" | awk -F'\t' '$1=="not_encoded"{printf "%s%s", sep, $2; sep=" "}')" "target_identity services df2_destination df3_destination"
    chk provision-target-reported "$(printf '%s\n' "$out" | grep -c '310150123456789')" "1"

    #    The retired gate flag is gone, and passing it is a usage error rather
    #    than a silent no-op: an operator who still has it in a script must find
    #    out.
    chk retired-gate-flag "$(lipr_cli_main --i-have-a-lab-and-authorisation --provision-target "$conf" >/dev/null 2>&1; echo $?)" "2"

    #    The bytes on disk are the PDU in the hex, not a second rendering.
    out=$(LIPR_NOW=1767225600 lipr_cli_main --provision-target "$conf" --out "$d/prov.bin" 2>/dev/null)
    chk out-file-path "$(fld "$out" out_file)" "$d/prov.bin"
    chk out-file-bytes "$(stat -c %s "$d/prov.bin" 2>/dev/null)" "35"
    chk out-file-hex "$(od -An -v -tx1 "$d/prov.bin" | tr -d ' \n' | tr 'a-f' 'A-F')" "$PHI1"

    # 7. The LIPR reader, on a hand-written literal -- never on the encoder's
    #    output. The literal is the X3/HI3 product envelope, the one artefact
    #    that is still this module's own framing:
    #      4C495052 01 03            magic "LIPR", version 1, type 3 (product)
    #      09 0009 434153452D30303031  "CASE-0001" as ASCII
    #      0A 0004 6955B900          capture time (1767225600, big-endian)
    #      0B 0004 00000007          sequence 7
    #      0C 0003 0A1B2C            the payload, encoded in place
    #    = 6 + 12 + 7 + 7 + 6 = 38 octets.
    local IH="4C4950520103"
    IH+="090009434153452D30303031"
    IH+="0A00046955B900"
    IH+="0B000400000007"
    IH+="0C00030A1B2C"
    local parsed
    parsed=$(lipr_parse "$IH"); rc=$?
    chk parse-rc "$rc" "0"
    chk parse-type "$(printf '%s\n' "$parsed" | awk -F'\t' '$1=="hdr" && $2=="type"{print $3}')" "0x03"
    chk parse-version "$(printf '%s\n' "$parsed" | awk -F'\t' '$1=="hdr" && $2=="version"{print $3}')" "0x01"
    chk parse-tlvs "$(printf '%s\n' "$parsed" | grep -c '^tlv')" "4"
    chk parse-order "$(printf '%s\n' "$parsed" | awk -F'\t' '$1=="tlv"{printf "%s%s", sep, $2; sep=" "}')" "0x09 0x0A 0x0B 0x0C"
    chk parse-correlation "$(printf '%s\n' "$parsed" | awk -F'\t' '$1=="tlv" && $2=="0x09"{print $4}')" "434153452D30303031"
    chk parse-payload "$(printf '%s\n' "$parsed" | awk -F'\t' '$1=="tlv" && $2=="0x0C"{print $4}')" "0A1B2C"
    chk parse-truncated "$(lipr_parse "${IH%????}" >/dev/null 2>&1; echo $?)" "1"
    chk parse-bad-magic "$(lipr_parse "00000000${IH:8}" >/dev/null 2>&1; echo $?)" "1"
    chk parse-nonhex "$(lipr_parse "ZZ" >/dev/null 2>&1; echo $?)" "1"

    # 8. Withdrawal is liDeactivated and activation is liActivated: two
    #    alternatives of the standard's CHOICE, so the difference is the context
    #    tag 0xA2 against 0xA1 and nothing else. Both literals are the referee's.
    local WHI1="A22181094C4949442D30303031A30F810D3236303130313030303030305AA603830101"
    out=$(LIPR_NOW=1767225600 lipr_cli_main --activate "$conf" --action withdraw 2>/dev/null); rc=$?
    chk activate-rc "$rc" "3"
    chk activate-hex "$(fld "$out" artefact_hex)" "$WHI1"
    chk activate-bytes "$(fld "$out" artefact_bytes)" "35"
    chk activate-operation "$(fld "$out" operation)" "liDeactivated"
    chk activate-action-row "$(fld "$out" action)" "withdraw"
    chk activate-record-name "$(fld "$out" artefact)" "activation_record"
    chk activate-liid "$(h1field "$out" liDeactivated.lawfulInterceptionIdentifier)" "4C4949442D30303031"
    chk activate-default-hex "$(LIPR_NOW=1767225600 lipr_cli_main --activate "$conf" 2>/dev/null | awk -F'\t' '$1=="artefact_hex"{print $2}')" "$PHI1"
    chk activate-default-op "$(LIPR_NOW=1767225600 lipr_cli_main --activate "$conf" 2>/dev/null | awk -F'\t' '$1=="operation"{print $2}')" "liActivated"
    chk activate-has-note "$(printf '%s\n' "$out" | grep -c "^note")" "2"
    chk activate-bad-action "$(lipr_cli_main --activate "$conf" --action freeze >/dev/null 2>&1; echo $?)" "2"

    # 9. The interception-product envelope, the artefact that is still this
    #    module's own framing because TS 33.108's HI3 record is not transcribed
    #    in this tree. Its own standard row says so; that is the honest half of
    #    what used to be one blanket lie.
    out=$(LIPR_NOW=1767225600 LIPR_SEQ=7 lipr_cli_main --intercept 0A1B2C --case CASE-0001 2>/dev/null); rc=$?
    chk intercept-rc "$rc" "3"
    chk intercept-hex "$(fld "$out" artefact_hex)" "$IH"
    chk intercept-bytes "$(fld "$out" artefact_bytes)" "38"
    chk intercept-owns-framing "$(has "$(fld "$out" standard)" 'not a TS 33.108 PDU')" "yes"
    chk intercept-payload "$(tlvfield "$out" payload)" "0A1B2C"
    chk intercept-payload-in-place "$(printf '%s' "$(fld "$out" artefact_hex)" | grep -c '0C00030A1B2C')" "1"
    chk intercept-correlation "$(tlvfield "$out" correlation_id)" "434153452D30303031"
    chk intercept-time "$(tlvfield "$out" capture_time)" "6955B900"
    chk intercept-seq "$(tlvfield "$out" sequence_number)" "00000007"
    chk intercept-captured "$(fld "$out" captured)" "0"
    chk intercept-parses "$(lipr_parse "$IH" | grep -c '^tlv')" "4"
    chk intercept-default-case "$(LIPR_NOW=0 lipr_cli_main --intercept FF 2>/dev/null | awk -F'\t' '$1=="field" && $2=="correlation_id"{print $3}')" "unassigned"
    chk intercept-empty "$(lipr_cli_main --intercept '' >/dev/null 2>&1; echo $?)" "2"
    chk intercept-odd "$(lipr_cli_main --intercept 0A1B2 >/dev/null 2>&1; echo $?)" "2"
    chk intercept-nonhex "$(lipr_cli_main --intercept 0A1BZZ >/dev/null 2>&1; echo $?)" "2"
    chk intercept-bad-case "$(lipr_cli_main --intercept 0A --case 'bad id' >/dev/null 2>&1; echo $?)" "2"

    # 10. The conf is validated, not trusted: an unknown key, a missing
    #     destination and a contradictory one are refused rather than encoded.
    printf 'TARGET_TYPE=imsi\nTARGET=310150123456789\nWARRANT=W\nSERVICES=iri,cc\nTICKET=1\nDF2_DEST=a:1\nDF3_DEST=b:2\n' > "$d/unknown.conf"
    chk conf-unknown-key "$(lipr_cli_main --provision-target "$d/unknown.conf" >/dev/null 2>&1; echo $?)" "2"
    printf 'TARGET_TYPE=imsi\nTARGET=310150123456789\nWARRANT=W\nSERVICES=iri,cc\nDF2_DEST=a:1\n' > "$d/nodf3.conf"
    chk conf-missing-df3 "$(lipr_cli_main --provision-target "$d/nodf3.conf" >/dev/null 2>&1; echo $?)" "2"
    printf 'TARGET_TYPE=imsi\nTARGET=310150123456789\nWARRANT=W\nSERVICES=iri\nDF2_DEST=a:1\nDF3_DEST=b:2\n' > "$d/contra.conf"
    chk conf-contradictory-dest "$(lipr_cli_main --provision-target "$d/contra.conf" >/dev/null 2>&1; echo $?)" "2"
    printf 'TARGET_TYPE=imsi\nTARGET=310150123456789\nWARRANT=W\nSERVICES=iri\nDF2_DEST=a:70000\n' > "$d/badport.conf"
    chk conf-bad-port "$(lipr_cli_main --provision-target "$d/badport.conf" >/dev/null 2>&1; echo $?)" "2"
    printf 'TARGET_TYPE=imsi\nTARGET=310150123456789\nSERVICES=iri\nDF2_DEST=a:1\n' > "$d/nowarrant.conf"
    chk conf-no-warrant "$(lipr_cli_main --provision-target "$d/nowarrant.conf" >/dev/null 2>&1; echo $?)" "2"
    chk conf-missing-file "$(lipr_cli_main --provision-target "$d/nope.conf" >/dev/null 2>&1; echo $?)" "1"
    #     A warrant reference longer than HI1's SIZE (1..25) is the standard's
    #     refusal, not this module's convenience: the LIID is an OCTET STRING
    #     with a fixed size range, and truncating it would name another target.
    printf 'TARGET_TYPE=imsi\nTARGET=310150123456789\nWARRANT=ABCDEFGHIJKLMNOPQRSTUVWXYZ\nSERVICES=iri\nDF2_DEST=a:1\n' > "$d/liid26.conf"
    chk conf-liid-too-long "$(lipr_cli_main --provision-target "$d/liid26.conf" >/dev/null 2>&1; echo $?)" "2"
    chk conf-liid-names-size "$(lipr_cli_main --provision-target "$d/liid26.conf" 2>&1 >/dev/null | grep -c 'SIZE')" "1"

    # 11. There is no gate and therefore no stderr block. What the module still
    #     owes a reader is the standing note, in the output, saying what these
    #     verbs do not do: encode artefacts, contact nothing.
    dout=$(lipr_cli_main --provision-target "$conf" 2>/dev/null)
    derr=$(lipr_cli_main --provision-target "$conf" 2>&1 >/dev/null)
    chk stderr-empty "$(printf '%s\n' "$derr" | grep -c .)" "0"
    chk note-on-stdout "$(printf '%s\n' "$dout" | grep -c '^note	lawful interception is operated')" "1"
    chk note-names-admf "$(printf '%s\n' "$dout" | grep -c 'contact no ADMF, DF2, DF3 or LEMF')" "1"
    chk stdout-has-no-warning "$(printf '%s\n' "$dout" | grep -c '^WARNING')" "0"
    chk stdout-tabular "$(printf '%s\n' "$dout" | awk -F'\t' 'NF==6 && $1=="tlv"{c++} END{print c+0}')" "6"

    # 12. Scope: the seam between the ungated detection verbs and the gated
    #     encoder verbs, and the verbs are dispatchable.
    out=$(lipr_scope_check); rc=$?
    chk scope-rc "$rc" "0"
    chk scope-value "$(fld "$out" scope)" "encodes-and-hands-off"
    chk scope-violations "$(printf '%s\n' "$out" | grep -c '^scope_violation')" "0"
    chk scope-verbs-dispatch "$(printf '%s\n' "$out" | awk -F'\t' '$1=="scope_checked"{print ($2 ~ /3 encoder verbs/)?"yes":"no"}')" "yes"

    # 13. --status-tsv stops implying detection-only, and says there is no gate.
    out=$(LIPR_GATE_ARMED=0 IMSI_LAB_AUTHORISED=0 lipr_status_tsv)
    chk status-module "$(fld "$out" MODULE)" "li_probe"
    chk status-no-gate "$(printf '%s\n' "$out" | awk -F'\t' '$1=="ENCODE_GATE"{print ($2 ~ /^none/)?"none":"other"}')" "none"
    chk status-delivers-nothing "$(printf '%s\n' "$out" | awk -F'\t' '$1=="DELIVERS"{print ($2 ~ /nothing/)?"no":"yes"}')" "no"
    chk status-encode-verbs "$(fld "$out" ENCODE_VERBS)" "--provision-target --activate --intercept"
    chk status-no-detection-only "$(printf '%s\n' "$out" | grep -ci 'detection-only')" "0"
    chk status-scope-no-gate "$(printf '%s\n' "$out" | awk -F'\t' '$1=="SCOPE"{print ($2 ~ /gate/)?"yes":"no"}')" "no"
    chk status-pdu "$(has "$(fld "$out" PDU)" 'TS 33.108')" "yes"
    chk status-pdu-names-hi1 "$(has "$(fld "$out" PDU)" 'ThreeGPP-HI1NotificationOperations')" "yes"
    chk status-no-envelope-row "$(printf '%s\n' "$out" | grep -c '^ENVELOPE')" "0"
    chk status-limit-names-product "$(has "$(fld "$out" LIMIT)" 'X3/HI3')" "yes"
    chk status-limit-names-target "$(has "$(fld "$out" LIMIT)" 'target-identity')" "yes"

    printf 'ASSERTIONS\t%d\n' "$nchk"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

lipr_menu() {
    while true; do
        banner
        echo "  === LI Interception ==="
        echo
        cat <<'M'
  [1]  LI interface reference
  [2]  LI architecture reference
  [3]  Score interception-posture signals
  [4]  Reporting guidance
  [5]  Plan (handoff)
  [6]  Provisioning request bytes
  [7]  Activation or withdrawal record
  [8]  Interception-product envelope
  [0]  back

  6-7 encode a real TS 33.108 HI1 PDU; 8 encodes this module's own product
  envelope. None of them sends anything, and each carries a note saying so.
M
        read -rp "  choice> " c || return 0
        case "$c" in
            1) lipr_interfaces; read -rp "  enter " _ ;;
            2) lipr_architecture; read -rp "  enter " _ ;;
            3) read -rp "  signalling tsv> " p; lipr_score "$p"; read -rp "  enter " _ ;;
            4) lipr_report; read -rp "  enter " _ ;;
            5) lipr_plan; read -rp "  enter " _ ;;
            6) read -rp "  conf> " p; lipr_cmd_provision "$p"; read -rp "  enter " _ ;;
            7) read -rp "  conf> " p; read -rp "  action (activate/withdraw)> " ac
               case "$ac" in
                   withdraw) lipr_cmd_activate "$p" --action withdraw ;;
                   *)        lipr_cmd_activate "$p" ;;
               esac; read -rp "  enter " _ ;;
            8) read -rp "  payload hex> " ph; read -rp "  case id (blank = unassigned)> " cid
               if [[ -n "$cid" ]]; then lipr_cmd_intercept "$ph" --case "$cid"
               else lipr_cmd_intercept "$ph"; fi; read -rp "  enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

lipr_cli_main() {
    # Scan for the authorisation flag anywhere in the argument list so it can
    # precede or follow the verb, then remove it before dispatch. The env
    # variable is the alternative for a driver with no flag to pass.
    # No flag is stripped any more. --i-have-a-lab-and-authorisation was the old
    # gate; if a script still passes it, the verb must reject it rather than
    # accept it and do nothing, so it reaches the dispatcher untouched.
    local -a args=( "$@" ) rest=()
    local cmd="${args[0]:-}"
    (( ${#args[@]} > 1 )) && rest=( "${args[@]:1}" )
    case "$cmd" in
        --status-tsv)  lipr_status_tsv ;;
        --interfaces)  lipr_interfaces ;;
        --iface)       lipr_name_of "${rest[0]:-}" ;;
        --architecture) lipr_architecture ;;
        --score|--detect) lipr_score "${rest[0]:-}" ;;
        --report)      lipr_report ;;
        --plan)        lipr_plan ;;
        --provision-target) lipr_cmd_provision "${rest[@]}" ;;
        --activate)    lipr_cmd_activate "${rest[@]}" ;;
        --intercept)   lipr_cmd_intercept "${rest[@]}" ;;
        --selftest)    lipr_selftest ;;
        --menu)        lipr_menu ;;
        *)
            cat >&2 <<EOF
LI Interception — 3GPP lawful-interception interfaces, posture signals, and an
encoder for the TS 33.108 HI1 operation (X1/HI1) and this module's own X3/HI3
product envelope

Usage: $0 COMMAND
  --status-tsv         module state as TSV, including what the PDU does not model
  --interfaces         X1/HI1, X2/HI2, X3/HI3 reference (TS 33.108)
  --iface <X1|X2|X3>   name one interface
  --architecture       ADMF/POI/DF2/DF3/LEMF roles
  --score <tsv>        interception-posture score over signalling events
  --report             what to record and where to escalate
  --plan               network-side confirmation handoff
  --provision-target <conf> [--out <path>]
                       encode the provisioning request as a TS 33.108 HI1
                       operation (liActivated) in BER
  --activate <conf> [--action activate|withdraw] [--out <path>]
                       encode the activation record: liActivated, or
                       liDeactivated with --action withdraw
  --intercept <hex> [--case <id>] [--out <path>]
                       encode an X3/HI3 interception-product envelope (this
                       module's own LIPR framing) around a payload YOU supply;
                       it captures nothing
  --selftest           verify the model, the scorer and the encodings
  --menu               interactive menu

The encoder verbs take a small KEY=VALUE conf (TARGET_TYPE, TARGET, WARRANT,
SERVICES, DF2_DEST, DF3_DEST, and optionally OPERATOR_ID and NETWORK_ELEMENT in
form:value with form e164, x25, ip or dns) or a payload in hex. LIPR_NOW and
LIPR_SEQ pin the timestamp and sequence so a harness run is reproducible. Exit
codes: 0 done, 1 an I/O or clock failure, 2 refused or bad input, 3 the
artefact is built and printed and delivery is a handoff.

--provision-target and --activate print a real PDU of 3GPP TS 33.108 Annex M:
the HI1 operation ThreeGPP-HI1NotificationOperations, BER-encoded per X.690 by
tools/li_hi1.py, with the tagged field table printed beside the hex. That
encoder has no third-party dependency, and tools/check-li-ber.sh compares it
octet for octet against pycrate's ASN.1 compiler when the oracle venv is
present. The conf fields the operation has no room for -- the subscriber
identity, the IRI/CC pair, a delivery host:port -- are printed as not_encoded
with the reason, never folded into a field they are not.

--intercept is the exception and says so in its own output: TS 33.108's HI3
record is not transcribed in this tree, so the product envelope is this
module's own length-prefixed TLV (magic LIPR) and is not a TS 33.108 PDU.

Scope: the detection verbs read what you give them and send nothing. The three
encoder verbs build real bytes -- field layout, length prefixes, orderings,
encodings -- open no socket, and exit 3 with a handoff; none of them asks for a
flag. Lawful
interception is performed by a network operator on its own network under
statutory authority; a provisioning request that reaches a live ADMF interferes
with real intercepts and real criminal investigations, and a lab core is not a
substitute for that authority if the traffic is real.
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
    lipr_cli_main "$@"
fi
