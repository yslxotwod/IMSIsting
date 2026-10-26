#!/usr/bin/env bash
# gtpu — the GTP-U user plane between the core and the RAN.
#
# GTP-C is signalling: a message you build and send on a control association,
# which is what 11_lte_core owns. GTP-U is not that. It is an encapsulation
# with its own header, its own failure modes and its own send path, and putting
# it inside a control-plane module would put a payload carrier inside a
# signalling page. Nothing else in this tree owns the user plane between the
# core and the RAN, so it gets its own module.
#
# The header (TS 29.281 §5.1):
#   octet 1     version (1), PT (1 for GTP), E/S/PN flags, spare
#   octet 2     message type
#   octets 3-4  length: octets after the 8-octet mandatory header
#   octets 5-8  TEID
#   conditional: sequence number (E), N-PDU number (S), next extension header
# An extension header follows while its length octet is non-zero: length (1,
# in 4-octet units after this octet), content, next extension type.
#
# TS 38.415 puts the PDU Session Container in that chain: it carries the QoS
# Flow Identifier and, in the DL, the Reflective QoS Indicator and the Paging
# Policy Indicator. That is the whole reason a forged user-plane packet is more
# than a tunnel through a TEID — the container decides which QoS flow the
# packet is charged to and which RAN behaviour it triggers.
#
# Attack owned: user-plane injection and tunnel abuse across the S1-U/N3
# reference point — TEID space collision, echo storms, and an inner packet
# addressed anywhere the tunnel is allowed to reach.
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

MOD_TMP="$TMP_DIR/gtpu"
GTPU_DIR="$LOOT_DIR/gtpu"
mkdir -p "$MOD_TMP" "$GTPU_DIR" 2>/dev/null

declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
declare -F warn >/dev/null 2>&1 || warn() { printf '[warn] %s\n' "$*" >&2; }
declare -F err  >/dev/null 2>&1 || err()  { printf '[err]  %s\n' "$*" >&2; }
declare -F ok   >/dev/null 2>&1 || ok()   { printf '[ok]   %s\n' "$*" >&2; }
declare -F banner >/dev/null 2>&1 || banner() { :; }

gtpu_sanitize() { printf '%s' "${1:-}" | tr '\t\r\n' '   '; }

# ── primitives ──────────────────────────────────────────────────────────
gtpu_is_hex() { [[ "${1:-}" =~ ^[0-9A-Fa-f]+$ ]] && (( ${#1} % 2 == 0 )); }

gtpu_hex2dec() { printf '%d' "$(( 16#${1:-0} ))"; }

gtpu_dec2hex() {  # <value> <octets>
    local v="${1:-0}" n="${2:-1}" out=''
    local i
    for (( i = n - 1; i >= 0; i-- )); do
        out+=$(printf '%02X' "$(( (v >> (i * 8)) & 0xFF ))")
    done
    printf '%s' "$out"
}

# The GTP-U message types this module builds or names. 255 is the echo
# request and 254 the echo response (TS 29.281 §7.1); everything else in the
# list is a G-PDU carrying a payload (255 is the only control-shaped one here,
# which is why an echo storm is the cheapest thing to do with a user plane).
gtpu_msg_name() {
    case "${1:-}" in
        01) printf 'echo-request' ;;
        02) printf 'echo-response' ;;
        03) printf 'error-indication' ;;
        10) printf 'supported-extension-headers-notification' ;;
        20) printf 'end-marker' ;;
        FF) printf 'G-PDU' ;;
        *)  printf 'unknown' ;;
    esac
}

gtpu_usage() {
    cat >&2 <<'EOF'
GTP-U — the user plane between the core and the RAN (TS 29.281)

Usage: gtpu COMMAND
  --status-tsv                   module state as TSV
  --parse <hex>                  decode a GTP-U packet: flags, TEID, length,
                                 sequence, extension chain, inner IP hint
  --build <teid-hex> [opts]      a G-PDU with an optional PDU Session
                                 Container (TS 38.415) inside it
      --qfi <0-63>               QoS Flow Identifier
      --rqi <0|1>                Reflective QoS Indicator (DL only)
      --ppi <0|1>                Paging Policy Indicator
      --inner <hex>              the encapsulated payload
      --seq <n>                  sequence number, sets E
      --ext <type>:<hex>         an opaque extension header, repeatable
  --pdu-session <hex>            decode just a PDU Session Container
  --echo <count> [--teid <hex>]  an echo-request burst, printed as packets
  --teid-scan <hex>              what a TEID value is and what it collides with
  --inner-route <hex>            decode the inner IPv4 header and report where
                                 the tunnel is actually allowed to deliver
  --detect <pcap|hex>            find GTP-U anomalies in traffic or a capture
  --paths                        the reference points and what each allows
  --plan <name>                  write a handoff plan for the parts that need
                                 a live peer (echo-storm|teid-collision|inject)
  --selftest                     verify every encoder and decoder headlessly
  --menu                         interactive menu

A TEID is only meaningful inside a tunnel the peer already created. Nothing in
this module discovers one: 11_lte_core owns the control plane that would.
EOF
}

# ── --parse ─────────────────────────────────────────────────────────────
# Decoding has to survive what a real capture contains: an S flag with no
# sequence, a PN flag with no next-extension octet, an extension chain that
# loops. Every one of those is reported, never guessed past.
gtpu_cmd_parse() {
    local hex="${1:-}"
    hex="${hex// /}"; hex="${hex//:/}"; hex="${hex//$'\n'/}"; hex="${hex^^}"
    [[ -n "$hex" ]] || { printf 'ERROR\tno packet given\n' >&2; return 2; }
    gtpu_is_hex "$hex" || { printf 'ERROR\tpacket is not hex\n' >&2; return 2; }
    (( ${#hex} >= 16 )) || {
        printf 'ERROR\t%d octets: a GTP-U base header is 8\n' "$(( ${#hex} / 2 ))" >&2; return 2; }

    # TS 29.281 5.1: octet 1 flags, octet 2 message type, octets 3-4 length,
    # octets 5-8 TEID. Version is 1 for GTPv1-U, NOT 3.
    local o1="${hex:0:2}"
    local mtype="${hex:2:2}"
    local length=$(( 16#${hex:4:4} ))
    local teid="${hex:8:8}"
    local v=$(( ( 16#$o1 >> 5 ) & 0x7 ))
    local pt=$(( ( 16#$o1 >> 4 ) & 0x1 ))
    local s=$(( ( 16#$o1 >> 1 ) & 0x1 ))
    local pn=$(( ( 16#$o1 >> 0 ) & 0x1 ))
    local e=$(( ( 16#$o1 >> 2 ) & 0x1 ))
    local total=$(( ${#hex} / 2 ))

    printf 'version\t%d\n' "$v"
    printf 'protocol_type\t%d\n' "$pt"
    printf 'flags\tE=%d S=%d PN=%d\n' "$e" "$s" "$pn"
    printf 'message_type\t%s\n' "$mtype"
    printf 'message_name\t%s\n' "$(gtpu_msg_name "$mtype")"
    printf 'length_field\t%d\n' "$length"
    printf 'teid\t%s\n' "$teid"
    printf 'teid_dec\t%d\n' "$(( 16#$teid ))"
    printf 'octets_total\t%d\n' "$total"

    # The length field covers everything after the 8-octet base header. A
    # packet that does not match it is truncated or padded, and both are worth
    # saying out loud rather than silently parsing the longer of the two.
    local expect=$(( 8 + length ))
    printf 'octets_expected\t%d\n' "$expect"
    if (( total < expect )); then
        printf 'length_check\tshort: %d octets present, length field says %d\n' "$total" "$expect"
    elif (( total > expect )); then
        printf 'length_check\tlong: %d octets present, %d trailing (Ethernet padding or a second packet)\n' \
            "$(( total - expect ))" "$(( total - expect ))"
    else
        printf 'length_check\tconsistent\n'
    fi

    local off=8 extra=0
    if (( e || s || pn )); then
        extra=4
        local seq
        seq="${hex:$(( off * 2 )):4}"
        printf 'sequence\t%s\t%d\n' "$seq" "$(( 16#$seq ))"
        printf 'npdu\t%s\n' "${hex:$(( off * 2 + 4 )):2}"
        printf 'next_ext_type\t%s\n' "${hex:$(( off * 2 + 6 )):2}"
        off=$(( off + 4 ))
    fi

    # Extension chain: each header is length(1) | content | next type(1), where
    # length counts 4-octet units AFTER the length octet. A zero length or a
    # zero next-type ends the chain; a repeat of a type already seen is a loop.
    local depth=0 seen=' ' ext_type
    if (( extra )); then
        ext_type="${hex:$(( off * 2 - 2 )):2}"
    else
        printf 'extension_headers\tnone\n'
        ext_type='00'
    fi
    while [[ "$ext_type" != "00" && -n "$ext_type" ]] && (( depth < 8 )); do
        if [[ "$seen" == *" $ext_type "* ]]; then
            printf 'extension_%d_loop\textension type %s already appeared; refusing to walk further\n' \
                "$depth" "$ext_type"
            break
        fi
        seen+="$ext_type "
        (( off + 1 <= total )) || { printf 'extension_%d\ttruncated\n' "$depth"; break; }
        local elen_hex="${hex:$(( off * 2 )):2}"
        local elen=$(( 16#$elen_hex ))
        # TS 29.281 5.2.1: the header is (length + 1) 4-octet units in total,
        # counting the length octet and the trailing next-type octet.
        local ext_total=$(( ( elen + 1 ) * 4 ))
        printf 'extension_%d_type\t%s\n' "$depth" "$ext_type"
        printf 'extension_%d_length_octet\t%d\n' "$depth" "$elen"
        printf 'extension_%d_octets\t%d\n' "$depth" "$ext_total"
        if (( off + ext_total > total )); then
            printf 'extension_%d\ttruncated: claims %d octets, %d remain\n' \
                "$depth" "$ext_total" "$(( total - off ))"
            break
        fi
        local content_len=$(( ext_total - 2 ))
        local content="${hex:$(( (off + 1) * 2 )):$(( content_len * 2 ))}"
        printf 'extension_%d_content\t%s\n' "$depth" "$content"
        if [[ "$ext_type" == "85" ]]; then
            # TS 38.415: extension type 0x85 is the PDU Session Container.
            gtpu_decode_psc "$content" | sed "s/^/extension_${depth}_psc_/"
        fi
        local next="${hex:$(( (off + ext_total - 1) * 2 )):2}"
        printf 'extension_%d_next\t%s\n' "$depth" "$next"
        ext_type="$next"
        off=$(( off + ext_total ))
        depth=$(( depth + 1 ))
    done
    (( depth == 0 )) && (( extra )) && printf 'extension_headers\tnone in chain\n'

    local inner="${hex:$(( off * 2 ))}"
    printf 'inner_octets\t%d\n' "$(( ${#inner} / 2 ))"
    if (( ${#inner} >= 40 )); then
        local iv=$(( ( 16#${inner:0:2} >> 4 ) & 0xF ))
        if (( iv == 4 )); then
            printf 'inner\tshape=IPv4 %s\n' "$(gtpu_ipv4_summary "$inner")"
        elif (( iv == 6 )); then
            printf 'inner\tshape=IPv6 (TS 29.281 allows both; this decoder names only v4)\n'
        elif (( iv == 0 )); then
            printf 'inner\tshape=not decodable here (payload starts with a zero nibble)\n'
        else
            printf 'inner\tshape=not IPv4/IPv6 (version nibble %d)\n' "$iv"
        fi
    elif (( ${#inner} > 0 )); then
        printf 'inner\tshape=payload too short for an IP header (%d octets)\n' "$(( ${#inner} / 2 ))"
    else
        printf 'inner\tshape=empty (a bare GTP-U header, e.g. an end marker)\n'
    fi
    return 0
}

# gtpu_ipv4_summary <hex> — src, dst, protocol and the first octets of L4.
gtpu_ipv4_summary() {
    local hex="${1:-}"
    (( ${#hex} >= 40 )) || { printf 'truncated'; return 1; }
    local ihl=$(( ( 16#${hex:0:2} & 0xF ) * 4 ))
    local proto="${hex:18:2}"
    local src="${hex:24:8}" dst="${hex:32:8}"
    local sip dip
    sip="$(( 16#${src:0:2} )).$(( 16#${src:2:2} )).$(( 16#${src:4:2} )).$(( 16#${src:6:2} ))"
    dip="$(( 16#${dst:0:2} )).$(( 16#${dst:2:2} )).$(( 16#${dst:4:2} )).$(( 16#${dst:6:2} ))"
    local pname
    case "$proto" in
        01) pname=ICMP ;; 06) pname=TCP ;; 11) pname=UDP ;;
        2F) pname=GRE ;; 32) pname=ESP ;; 84) pname=SCTP ;;
        *)  pname="IP-proto-$(( 16#$proto ))" ;;
    esac
    printf 'src=%s dst=%s proto=%s ihl=%d' "$sip" "$dip" "$pname" "$ihl"
}

# ── PDU Session Container (TS 38.415) ───────────────────────────────────
# Extension header 0x85. The first octet is the PDU type:
#   0  DL PDU SESSION INFORMATION (PDU Type 0)
#   1  UL PDU SESSION INFORMATION (PDU Type 1)
# and after it, octet 2, the QoS Flow Identifier is the low 6 bits.
# The DL form additionally carries the Reflective QoS Indicator and the Paging
# Policy Indicator; the UL form carries neither.
gtpu_decode_psc() {
    local hex="${1:-}"
    hex="${hex// /}"; hex="${hex^^}"
    if (( ${#hex} < 4 )); then
        printf 'pdu_type\tempty\n'
        return 0
    fi
    # TS 38.415 5.5.2.1 figure: octet 1 is PDU Type in bits 7-4 and the
    # QMP/SNP/MSNP/Spare flags in bits 3-0. Octet 2 is the QFI, all 8 bits.
    # Octet 3 (optional) is PPP(7) RQI(6) PPI(5-3) Spare(2-0).
    local o1=$(( 16#${hex:0:2} ))
    local pdu_type=$(( (o1 >> 4) & 0xF ))
    printf 'pdu_type\t%d\n' "$pdu_type"
    case "$pdu_type" in
        0) printf 'direction\tDL (DL PDU SESSION INFORMATION)\n' ;;
        1) printf 'direction\tUL (UL PDU SESSION INFORMATION)\n' ;;
        *) printf 'direction\treserved PDU type %d (2-15 reserved for extension)\n' "$pdu_type" ;;
    esac
    printf 'qmp\t%d\n'  "$(( (o1 >> 3) & 1 ))"
    printf 'snp\t%d\n'  "$(( (o1 >> 2) & 1 ))"
    printf 'msnp\t%d\n' "$(( (o1 >> 1) & 1 ))"
    printf 'octet1\t%s\n' "${hex:0:2}"
    local qfi=$(( 16#${hex:2:2} ))
    printf 'qfi\t%d\n' "$qfi"
    if (( pdu_type == 0 && ${#hex} >= 6 )); then
        local o3=$(( 16#${hex:4:2} ))
        printf 'ppp\t%d\n' "$(( (o3 >> 7) & 1 ))"
        printf 'rqi\t%d\n' "$(( (o3 >> 6) & 1 ))"
        printf 'ppi\t%d\n' "$(( (o3 >> 3) & 0x7 ))"
        printf 'rqi_note\trqi=1 makes the RAN mirror this flow\x27s QoS treatment on the UE\x27s own uplink\n'
    elif (( pdu_type == 1 )); then
        local o3=$(( 16#${hex:4:2} ))
        printf 'dl_delay_ind\t%d\n' "$(( (o3 >> 3) & 1 ))"
        printf 'ul_delay_ind\t%d\n' "$(( (o3 >> 2) & 1 ))"
        printf 'rqi\tnot present (UL form)\n'
        printf 'ppi\tnot present (UL form)\n'
    fi
    printf 'spec\tTS 38.415 5.5.2.1 (DL) / 5.5.2.2 (UL)\n'
    return 0
}

gtpu_cmd_pdu_session() {
    gtpu_decode_psc "${1:-}"
}

# ── --build ─────────────────────────────────────────────────────────────
gtpu_cmd_build() {
    local teid="${1:-}"; shift 2>/dev/null || true
    local qfi='' rqi='' ppi='' inner='' seq='' mtype='FF'
    local -a exts=()
    while (( $# )); do
        case "$1" in
            --qfi)   qfi="${2:-}";   shift 2 2>/dev/null || shift ;;
            --rqi)   rqi="${2:-}";   shift 2 2>/dev/null || shift ;;
            --ppi)   ppi="${2:-}";   shift 2 2>/dev/null || shift ;;
            --inner) inner="${2:-}"; shift 2 2>/dev/null || shift ;;
            --seq)   seq="${2:-}";   shift 2 2>/dev/null || shift ;;
            --type)  mtype="${2:-}"; shift 2 2>/dev/null || shift ;;
            --ext)   exts+=("${2:-}"); shift 2 2>/dev/null || shift ;;
            -h|--help) gtpu_usage; return 0 ;;
            *) printf 'ERROR\tunknown option %s\n' "$(gtpu_sanitize "$1")" >&2; return 2 ;;
        esac
    done
    teid="${teid%0x}"; teid="${teid^^}"
    [[ "$teid" =~ ^[0-9A-F]{1,8}$ ]] || {
        printf 'ERROR\tTEID must be 1-8 hex digits\n' >&2; return 2; }
    teid=$(gtpu_dec2hex "$(( 16#$teid ))" 4)
    mtype="${mtype^^}"; [[ "$mtype" =~ ^[0-9A-F]{2}$ ]] || {
        printf 'ERROR\tmessage type must be one octet\n' >&2; return 2; }
    inner="${inner// /}"; inner="${inner^^}"
    [[ -z "$inner" ]] || gtpu_is_hex "$inner" || {
        printf 'ERROR\t--inner must be even-length hex\n' >&2; return 2; }

    # Build each extension into a list first so the trailing next-type octets
    # can be linked correctly. A chain is a linked list: each header's last
    # octet names the type of the header that follows, zero ends it.
    local -a ext_blocks=()
    local -a ext_types=()
    local spec etype econtent
    for spec in "${exts[@]}"; do
        [[ "$spec" == *:* ]] || {
            printf 'ERROR\t--ext wants <type>:<hex>, got %s\n' "$(gtpu_sanitize "$spec")" >&2; return 2; }
        etype="${spec%%:*}"; etype="${etype^^}"
        econtent="${spec#*:}"; econtent="${econtent// /}"; econtent="${econtent^^}"
        [[ "$etype" =~ ^[0-9A-F]{2}$ ]] || {
            printf 'ERROR\textension type %s is not one octet\n' "$(gtpu_sanitize "$etype")" >&2; return 2; }
        gtpu_is_hex "$econtent" || { printf 'ERROR\textension content is not hex\n' >&2; return 2; }
        local blk
        blk=$(gtpu_ext_block "$econtent") || return 2
        ext_blocks+=("$blk")
        ext_types+=("$etype")
    done

    # A PDU Session Container is just another extension, built here when the
    # QoS fields are asked for and no explicit --ext covered it.
    if [[ -n "$qfi" || -n "$rqi" || -n "$ppi" ]]; then
        local psc blk
        psc=$(gtpu_build_psc "$qfi" "$rqi" "$ppi") || return 2
        blk=$(gtpu_ext_block "$psc") || return 2
        ext_blocks+=("$blk")
        ext_types+=("85")
    fi

    # Link: block i's last octet (the next-type slot) points at type i+1.
    local ext_hex='' ext_type0='00'
    local i
    for (( i = 0; i < ${#ext_blocks[@]}; i++ )); do
        local blk="${ext_blocks[i]}"
        local nxt='00'
        (( i + 1 < ${#ext_blocks[@]} )) && nxt="${ext_types[i+1]}"
        ext_hex+="${blk%??}${nxt}"
        (( i == 0 )) && ext_type0="${ext_types[0]}"
    done

    # Link the chain: each header's trailing next-type points at the one after.
    local payload_len=$(( ${#inner} / 2 ))
    local seq_hex=''
    local flags=$(( 0x30 ))   # version 1 (0x20) | PT 1 (0x10)
    if [[ -n "$seq" ]]; then
        flags=$(( flags | 0x04 ))   # E
        seq_hex=$(gtpu_dec2hex "$(( 16#$seq ))" 2)
    elif [[ -n "$ext_hex" ]]; then
        # An extension chain needs the optional 4-octet field to exist, so the
        # E bit has to be set even without a caller-supplied sequence.
        flags=$(( flags | 0x04 ))
        seq_hex='0000'
    fi
    local extra_hex=''
    if [[ -n "$seq_hex" || -n "$ext_hex" ]]; then
        extra_hex="${seq_hex:-0000}00${ext_type0}"
    fi

    local body_len=$(( ${#extra_hex} / 2 + ${#ext_hex} / 2 + payload_len ))
    local hex
    # octet 1 flags | octet 2 message type | octets 3-4 length | 5-8 TEID
    hex=$(printf '%02X' "$flags")
    hex+="$mtype"
    hex+=$(gtpu_dec2hex "$body_len" 2)
    hex+="$teid"
    hex+="$extra_hex"
    hex+="$ext_hex"
    hex+="$inner"

    printf 'field\tvalue\n'
    printf 'version\t1\n'
    printf 'message_type\t%s\n' "$mtype"
    printf 'message_name\t%s\n' "$(gtpu_msg_name "$mtype")"
    printf 'teid\t%s\n' "$teid"
    printf 'teid_dec\t%d\n' "$(( 16#$teid ))"
    printf 'flags\tE=%d S=%d PN=%d\n' \
        "$(( (flags >> 2) & 1 ))" "$(( (flags >> 1) & 1 ))" "$(( flags & 1 ))"
    printf 'length_field\t%d\n' "$body_len"
    printf 'inner_octets\t%d\n' "$payload_len"
    printf 'extension_octets\t%d\n' "$(( ${#ext_hex} / 2 ))"
    printf 'hex\t%s\n' "$hex"
    printf 'octets\t%d\n' "$(( ${#hex} / 2 ))"
    printf 'limit\ta TEID is only meaningful inside a tunnel the peer created; this builds the packet, not the tunnel\n'
    printf 'cross_ref\t11_lte_core owns the GTP-C that creates the tunnel\n'
    return 0
}

# gtpu_build_psc <qfi> <rqi> <ppi> -> the PDU Session Container content hex
gtpu_build_psc() {
    local qfi="${1:-}" rqi="${2:-0}" ppi="${3:-0}" ppp="${4:-0}"
    [[ "$qfi" =~ ^[0-9]+$ ]] || { printf 'ERROR\t--qfi must be 0-63\n' >&2; return 2; }
    (( qfi <= 63 )) || { printf 'ERROR\t--qfi is 6 bits by OAM range, got %d\n' "$qfi" >&2; return 2; }
    [[ "$rqi" =~ ^[01]$ ]] || { printf 'ERROR\t--rqi is 0 or 1\n' >&2; return 2; }
    [[ "$ppi" =~ ^[0-7]$ ]] || { printf 'ERROR\t--ppi is 0-7 (3 bits)\n' >&2; return 2; }
    [[ "$ppp" =~ ^[01]$ ]] || { printf 'ERROR\t--ppp is 0 or 1\n' >&2; return 2; }
    # PDU Type 0 in bits 7-4 (0x00), flags clear in bits 3-0;
    # QFI in octet 2; PPP(7) RQI(6) PPI(5-3) in octet 3.
    local o1; o1=$(printf '%02X' "$(( 0 << 4 ))")
    local o2; o2=$(printf '%02X' "$qfi")
    local o3; o3=$(printf '%02X' "$(( (ppp << 7) | (rqi << 6) | (ppi << 3) ))")
    printf '%s%s%s' "$o1" "$o2" "$o3"
}

# gtpu_ext_block <content hex> -> length octet + padded content + a next-type
# slot currently holding 00. TS 29.281 5.2.1: length octet (1) + content +
# next-type (1) = n*4, and the length field carries n-1.
gtpu_ext_block() {
    local content="${1:-}"
    local clen=$(( ${#content} / 2 ))
    local pad=$(( (4 - ( (clen + 2) % 4 )) % 4 ))
    local padded="$content"
    local _p _pt
    for (( _p = 0; _p < pad; _p++ )); do padded+='00'; done
    local n=$(( (clen + pad + 2) / 4 ))
    (( n - 1 <= 255 )) || { printf 'ERROR\textension too long\n' >&2; return 2; }
    printf '%02X%s00' "$(( n - 1 ))" "$padded"
}

# ── --echo ──────────────────────────────────────────────────────────────
gtpu_cmd_echo() {
    local count="${1:-1}" teid_hex='00000000'
    shift 2>/dev/null || true
    while (( $# )); do
        case "$1" in
            --teid) teid_hex="${2:-00000000}"; shift 2 2>/dev/null || shift ;;
            *) printf 'ERROR\tunknown option %s\n' "$(gtpu_sanitize "$1")" >&2; return 2 ;;
        esac
    done
    [[ "$count" =~ ^[0-9]+$ ]] || { printf 'ERROR\t--echo wants a count\n' >&2; return 2; }
    (( count >= 1 && count <= 10000 )) || {
        printf 'ERROR\tcount must be 1-10000; a user plane does not need more\n' >&2; return 2; }
    teid_hex="${teid_hex^^}"
    [[ "$teid_hex" =~ ^[0-9A-F]{8}$ ]] || {
        printf 'ERROR\tTEID must be 8 hex digits\n' >&2; return 2; }

    printf 'seq\tteid\thex\tuse\n'
    local i seq_hex h
    for (( i = 1; i <= count; i++ )); do
        seq_hex=$(gtpu_dec2hex "$(( i & 0xFFFF ))" 2)
        # echo-request = 0x01, E set, length 0, no payload.
        # flags 34 (v1/PT1/E) | type 01 | length 0004 (seq+npdu+next-ext) |
        # TEID | sequence | N-PDU | next-extension-type
        h=$(printf '3401%s%s%s%s' "0004" "$teid_hex" "$seq_hex" "0000")
        printf '%d\t%s\t%s\t%s\n' "$i" "$teid_hex" "$h" \
            "$(gtpu_echo_use "$i" "$count")"
    done
    printf 'note\techo is the only GTP-U message a tunnel-less peer must answer (TS 29.281 7.1); a flood of it costs the peer a reply per packet\n'
    printf 'limit\tno rate limit is described in the specification: the guard is the peer\x27s own storm control, if it has one\n'
    return 0
}

gtpu_echo_use() {
    local i="$1" n="$2"
    if (( n == 1 )); then
        printf 'reachability probe: does a peer answer on this TEID at all'
    elif (( i % 100 == 0 )); then
        printf 'chapter marker %d/%d' "$i" "$n"
    else
        printf 'storm: reply cost per packet, no state to clean up on the sender'
    fi
}

# ── --teid-scan ─────────────────────────────────────────────────────────
# A TEID is a 32-bit value the receiver chose. It carries no structure the
# sender can rely on, which is exactly why "what collides with this" is a
# question about the receiver, not the number.
gtpu_cmd_teid_scan() {
    local hex="${1:-}"
    hex="${hex%0x}"; hex="${hex^^}"
    [[ "$hex" =~ ^[0-9A-F]{1,8}$ ]] || {
        printf 'ERROR\tTEID must be 1-8 hex digits\n' >&2; return 2; }
    local v=$(( 16#$hex ))
    printf 'field\tvalue\n'
    printf 'teid\t%s\n' "$(gtpu_dec2hex "$v" 4)"
    printf 'teid_dec\t%d\n' "$v"
    printf 'assignable\t%s\n' "$([ "$v" -ne 0 ] && echo yes || echo 'no: 0 is reserved for a tunnel-less message')"
    printf 'reserved_bits\tnone — all 32 bits are the receiver\x27s own choice\n'
    case "$v" in
        0) printf 'collision_risk\tzero is the sentinel: any peer that reads a TEID of 0 as "no tunnel" will reject this\n' ;;
        FFFFFFFF) printf 'collision_risk\ta maximal value; some stacks allocate downward from the top and will collide early\n' ;;
        *) if (( v < 256 )); then
               printf 'collision_risk\tlow values are what a sequential allocator hands out first, so this is the most likely to already exist\n'
           elif (( v > 0xFFFF0000 )); then
               printf 'collision_risk\thigh values are common in hash-based allocators; a collision here needs the peer\x27s full table\n'
           else
               printf 'collision_risk\tno structure to exploit: a collision is a property of the receiver\x27s allocator, not of this number\n'
           fi ;;
    esac
    printf 'attack_shape\ttwo tunnels that share a TEID in one receiver make one peer deliver the other\x27s traffic; that needs control of the allocation, which is 11_lte_core\x27s territory\n'
    printf 'limit\tthis cannot test a peer. It describes the value; a real collision test needs the receiver\x27s allocation sequence\n'
    return 0
}

# ── --inner-route ───────────────────────────────────────────────────────
# The question a user-plane attacker actually has: once a packet is inside a
# tunnel, where may it come out? The answer is not in the GTP-U header at all.
gtpu_cmd_inner_route() {
    local hex="${1:-}"
    hex="${hex// /}"; hex="${hex//:/}"; hex="${hex^^}"
    gtpu_is_hex "$hex" || { printf 'ERROR\tinner packet as hex\n' >&2; return 2; }
    (( ${#hex} >= 40 )) || { printf 'ERROR\tan IPv4 header is at least 20 octets\n' >&2; return 2; }
    local ver=$(( ( 16#${hex:0:2} >> 4 ) & 0xF ))
    (( ver == 4 )) || { printf 'ERROR\tversion nibble %d: not IPv4\n' "$ver" >&2; return 2; }
    local sum; sum=$(gtpu_ipv4_summary "$hex")
    printf 'field\tvalue\n'
    printf 'inner_ip\t%s\n' "$sum"
    local dst="${hex:32:8}"
    local d1=$(( 16#${dst:0:2} )) d2=$(( 16#${dst:2:2} ))
    printf 'dst_scope\t%s\n' "$(gtpu_addr_scope "$d1" "$d2")"
    printf 'delivery_rule\tthe tunnel does not route: the receiving node decapsulates and then routes the inner packet\n'
    case "$(gtpu_addr_scope "$d1" "$d2")" in
        "private (RFC 1918)")
            printf 'reach_verdict\tthe inner address is private, so it lands in the peer\x27s own network — wherever that peers\x27 management plane lives\n' ;;
        "loopback")
            printf 'reach_verdict\tloopback is the peer itself, never a subscriber\n' ;;
        "link-local"|"broadcast"|"multicast")
            printf 'reach_verdict\tspecial-purpose; a receiver that decapsulates without filtering delivers to its own link\n' ;;
        *)
            printf 'reach_verdict\troutable destination: depends entirely on whether the peer filters the inner packet\n' ;;
    esac
    printf 'spec\tTS 29.281 (GTP-U header), TS 23.501 (the tunnel carries user packets and the node routes them)\n'
    return 0
}

gtpu_addr_scope() {
    local a="${1:-0}" b="${2:-0}"
    if (( a == 10 )); then echo "private (RFC 1918)"
    elif (( a == 172 && b >= 16 && b <= 31 )); then echo "private (RFC 1918)"
    elif (( a == 192 && b == 168 )); then echo "private (RFC 1918)"
    elif (( a == 127 )); then echo "loopback"
    elif (( a == 169 && b == 254 )); then echo "link-local"
    elif (( a == 0 || a >= 224 )); then echo "broadcast"
    elif (( a >= 224 && a <= 239 )); then echo "multicast"
    else echo "routable"
    fi
}

# ── --detect ────────────────────────────────────────────────────────────
# The anomalies worth naming are the ones that do not need a capture parser:
# a length field that disagrees with the packet, a TEID of zero on a G-PDU, an
# extension chain that loops, and an echo burst with no replies.
gtpu_cmd_detect() {
    local src="${1:-}"
    [[ -n "$src" ]] || { printf 'ERROR\tgive a capture or a hex packet\n' >&2; return 2; }
    printf 'finding\tclass\tspecific\tdetail\n'
    if [[ -f "$src" ]]; then
        printf 'capture\tinput\tfile\t%s\n' "$(gtpu_sanitize "$src")"
        if command -v tshark >/dev/null 2>&1; then
            local n
            n=$(tshark -r "$src" -Y 'gtp || gtpv2' -T fields -e frame.number 2>/dev/null | grep -c . || true)
            printf 'gtp_packets\tcount\ttshark\t%s\n' "${n:-0}"
            # A G-PDU with TEID 0 is a tunnel-less payload, which no real
            # receiver expects; an echo with a TEID is the mirror image.
            local zero teid_echo
            zero=$(tshark -r "$src" -Y 'gtp.message_type == 255 && gtp.teid == 0' \
                -T fields -e frame.number 2>/dev/null | grep -c . || true)
            printf 'g_pdu_teid_zero\tanomaly\t%s\t%s\n' "${zero:-0}" \
                "$([ "${zero:-0}" -gt 0 ] && echo 'a G-PDU with no tunnel address: forged, or a broken stack' || echo none)"
            teid_echo=$(tshark -r "$src" -Y 'gtp.message_type == 1 && gtp.teid != 0' \
                -T fields -e frame.number 2>/dev/null | grep -c . || true)
            printf 'echo_with_teid\tanomaly\t%s\t%s\n' "${teid_echo:-0}" \
                "$([ "${teid_echo:-0}" -gt 0 ] && echo 'echo-request normally carries TEID 0; a TEID here is worth reading' || echo none)"
        else
            printf 'note\tno tshark: capture scanning needs it\n'
        fi
    else
        local hex="${src// /}"; hex="${hex//:/}"; hex="${hex^^}"
        if gtpu_is_hex "$hex" && (( ${#hex} >= 16 )); then
            local mtype="${hex:2:2}"
            local teid="${hex:8:8}"
            local len=$(( 16#${hex:4:4} ))
            local total=$(( ${#hex} / 2 ))
            if [[ "$mtype" == "FF" && "$teid" == "00000000" ]]; then
                printf 'g_pdu_teid_zero\tHIGH\ttunnel address\t%s\n' \
                    'a G-PDU with no TEID: it cannot be delivered by any receiver, so it is forged or misbuilt'
            fi
            if (( total != 8 + len )); then
                printf 'length_mismatch\tMEDIUM\theader length\t%s\n' \
                    "$(printf 'field says %d octets, packet has %d' "$(( 8 + len ))" "$total")"
            fi
            (( (16#${hex:0:2} >> 2) & 1 )) && printf 'e_flag\tINFO\tsequence\t%s\n' \
                'E set: the sequence number is present and peers may use it for ordering'
            printf 'verdict\t%s\n' "$( [ -n "$hex" ] && echo decoded || echo unparseable )"
        else
            printf 'ERROR\tnot a capture and not a GTP-U packet\n' >&2; return 2
        fi
    fi
    return 0
}

# ── --paths ─────────────────────────────────────────────────────────────
gtpu_cmd_paths() {
    printf 'reference_point\tspec\tcarries\twhat_a_peer_sees\n'
    printf 'S1-U\tTS 23.401\tGTP-U between S-GW and eNB\tTEID per EPS bearer, one TEID each way\n'
    printf 'S5/S8-U\tTS 23.401\tGTP-U between S-GW and P-GW\tthe inner Gi packet, routed after decapsulation\n'
    printf 'N3\tTS 23.501\tGTP-U between UPF and gNB\tTS 38.415 PDU Session Container: QFI, RQI, PPI\n'
    printf 'N9\tTS 23.501\tGTP-U between UPFs\tthe same container, but the peer is another UPF\n'
    printf 'N6\tTS 23.501\tplain IP to the data network\tno GTP at all: this is where the packet becomes user traffic\n'
    printf 'note\tevery point above trusts the TEID. None authenticates it; the security is the tunnel\x27s existence, not the packet\n'
    printf 'note\tN3 is the one that carries the PDU Session Container, so it is the one where QoS forgery lands (--build --qfi)\n'
    printf 'cross_ref\t11_lte_core builds the GTP-C that creates every tunnel named here\n'
    return 0
}

# ── --plan ──────────────────────────────────────────────────────────────
gtpu_cmd_plan() {
    local name="${1:-}"
    local dir="$GTPU_DIR/plans"
    mkdir -p "$dir" 2>/dev/null
    case "$name" in
        echo-storm)
            cat <<'EOF'
GTP-U echo storm — handoff plan

What this does: every echo-request the peer receives obliges a reply, and no
state is created on the sender. The cost is asymmetric by construction, which
is the whole point of choosing this instead of a data flood.

Before the peer:  11_lte_core --status-tsv to confirm the N3/S1-U address and
                  that the peer answers a single echo at all.
Send:             62_gtpu.sh --echo 1000 --teid 00000000, replayed at the
                  rate the peer can absorb without dropping the association.
Observe:          the peer's reply latency and its storm control, if any.
Stop condition:   the association drops or the peer stops replying — both mean
                  the flood already bit, so stop rather than escalate.

What this cannot do: nothing here creates a tunnel. If the peer does not
already hold an association, an echo is just an ICMP-shaped packet.
EOF
            ;;
        teid-collision)
            cat <<'EOF'
GTP-U TEID collision — handoff plan

The value is not the attack. The allocator is.

1. 11_lte_core --list-tsv for the existing tunnels and their TEIDs.
2. Identify how the peer allocates: a sequential allocator hands out low
   values, a hash allocator spreads them. 62_gtpu.sh --teid-scan <value>
   names what the candidates look like, not whether they exist.
3. Create an association whose TEID lands on one already in use in the same
   receiver. One peer then decapsulates the other's traffic.

Precondition: control of association creation. Without it this plan has no
first step, and 11_lte_core is where that control lives.
EOF
            ;;
        inject)
            cat <<'EOF'
GTP-U injection — handoff plan

1. 11_lte_core: create or identify the tunnel (TEID + peer address).
2. 62_gtpu.sh --build <teid> --inner <ipv4 packet hex> --qfi <n>
   The PDU Session Container decides the QoS flow; --rqi 1 makes the RAN
   mirror that flow's treatment on the UE's own uplink.
3. 62_gtpu.sh --inner-route <inner hex> — read where the packet will land
   before sending it. A private inner address reaches the peer's own network.
4. Send over the N3/S1-U socket owned by the tunnel.

What the peer must do for this to work: decapsulate without filtering the
inner packet. That is the default on most user planes, and it is the finding
worth reporting as much as the injection itself.
EOF
            ;;
        *)
            printf 'ERROR\tplan is echo-storm, teid-collision or inject\n' >&2; return 2 ;;
    esac
    printf 'plan_written\t%s\n' "$(gtpu_sanitize "$dir/$name.plan")" >&2
    printf '%s\n' "$dir/$name.plan"
    return 0
}

# ── --status-tsv ────────────────────────────────────────────────────────
gtpu_cmd_status() {
    printf 'module\tgtpu\n'
    printf 'spec_gtpu\tTS 29.281\n'
    printf 'spec_psc\tTS 38.415 5.5.2\n'
    printf 'control_plane\t11_lte_core\n'
    printf 'user_plane\tself\n'
    local p
    for p in S1-U S5/S8-U N3 N9 N6; do
        printf 'path\t%s\n' "$p"
    done
    return 0
}

# ── selftest ────────────────────────────────────────────────────────────
gtpu_selftest() {
    local bad=0 nchk=0
    chk() {
        nchk=$(( nchk + 1 ))
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$(( bad + 1 )); fi
    }
    fld() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }

    # ── header decode ───────────────────────────────────────────────────
    # TS 29.281 5.1: octet 1 flags (v1, PT=1 -> 0x30), octet 2 message type,
    # octets 3-4 length, octets 5-8 TEID.
    local out
    out=$(gtpu_cmd_parse "30FF000000000001" 2>&1)
    chk parse-version      "$(fld "$out" version)" "1"
    chk parse-pt           "$(fld "$out" protocol_type)" "1"
    chk parse-type         "$(fld "$out" message_type)" "FF"
    chk parse-name         "$(fld "$out" message_name)" "G-PDU"
    chk parse-teid         "$(fld "$out" teid)" "00000001"
    chk parse-teid-dec     "$(fld "$out" teid_dec)" "1"
    chk parse-length-ok    "$(fld "$out" length_check)" "consistent"
    # Version is 1, not 3 — a 0x60 flags octet is GTPv2 and must not read as ours.
    # A v2 flags octet (0x60) must report version 3, never 1.
    out=$(gtpu_cmd_parse "60FF000000000001" 2>&1)
    chk parse-version-not-1 "$(fld "$out" version)" "3"

    # A length field that disagrees with the packet is reported, never trusted.
    out=$(gtpu_cmd_parse "30FF000000000001DEADBEEF0000" 2>&1)
    chk parse-len-long     "$(fld "$out" length_check | cut -c1-4)" "long"
    out=$(gtpu_cmd_parse "30FF001000000001DEAD" 2>&1)
    chk parse-len-short    "$(fld "$out" length_check | cut -c1-5)" "short"

    # Echo-request with E set: 0x34, type 01, length 4 (seq+npdu+ne).
    out=$(gtpu_cmd_parse "340100040000000000010000" 2>&1)
    chk parse-echo-name    "$(fld "$out" message_name)" "echo-request"
    chk parse-echo-flag    "$(fld "$out" flags)" "E=1 S=0 PN=0"
    chk parse-echo-seq     "$(fld "$out" sequence)" "0001"

    # ── PDU Session Container (TS 38.415) ───────────────────────────────
    # DL, QFI 9, RQI 1, PPI 2 -> 00 09 49
    out=$(gtpu_build_psc 9 1 2 2>/dev/null)
    chk psc-build          "$out" "000950"
    local dec
    dec=$(gtpu_decode_psc "000950" 2>/dev/null)
    chk psc-pdu-type       "$(fld "$dec" pdu_type)" "0"
    chk psc-qfi            "$(fld "$dec" qfi)" "9"
    chk psc-rqi            "$(fld "$dec" rqi)" "1"
    chk psc-ppi            "$(fld "$dec" ppi)" "2"
    chk psc-direction      "$(fld "$dec" direction | cut -c1-2)" "DL"
    # UL form has no RQI or PPI, and saying it does would be a lie.
    dec=$(gtpu_decode_psc "100905" 2>/dev/null)
    chk psc-ul-direction   "$(fld "$dec" direction | cut -c1-2)" "UL"
    chk psc-ul-no-rqi      "$(fld "$dec" rqi | cut -c1-3)" "not"

    # ── build + round-trip through parse ────────────────────────────────
    out=$(gtpu_cmd_build 00000001 --qfi 9 --rqi 1 --ppi 2 --inner 45000014000000004011aaaa0a0000010a000002 2>/dev/null)
    local built; built=$(fld "$out" hex)
    chk build-octets       "$(fld "$out" octets)" "$(( ${#built} / 2 ))"
    chk build-teid         "$(fld "$out" teid)" "00000001"
    chk build-has-ext      "$( [ "$(fld "$out" extension_octets)" -gt 0 ] && echo yes)" "yes"
    # The whole point: what goes out must decode back to what went in.
    local back
    back=$(gtpu_cmd_parse "$built" 2>&1)
    chk roundtrip-teid     "$(fld "$back" teid)" "00000001"
    chk roundtrip-type     "$(fld "$back" message_name)" "G-PDU"
    chk roundtrip-qfi      "$(fld "$back" extension_0_psc_qfi)" "9"
    chk roundtrip-rqi      "$(fld "$back" extension_0_psc_rqi)" "1"
    chk roundtrip-ext-type "$(fld "$back" extension_0_type)" "85"
    chk roundtrip-length   "$(fld "$back" length_check)" "consistent"
    chk roundtrip-inner    "$(fld "$back" inner | grep -c '^shape=IPv4')" "1"

    # ── extension chain loop refusal ────────────────────────────────────
    # An extension whose next-type points back at itself is a loop; walking it
    # must stop and say so rather than spin or truncate silently.
    # An extension whose next-type points back at itself is a loop. Walking it
    # must stop and say so rather than spin or silently truncate.
    out=$(gtpu_cmd_parse "34FF001400000001000000AA01DEADBEEF0000AA01DEADBEEF0000" 2>&1)
    chk parse-ext-loop "$(printf '%s' "$out" | grep -c 'already appeared')" "1"

    # ── TEID scan ───────────────────────────────────────────────────────
    out=$(gtpu_cmd_teid_scan 00000000 2>/dev/null)
    chk teid-zero-not-assignable "$(fld "$out" assignable | cut -c1-2)" "no"
    chk teid-zero-sentinel      "$(fld "$out" collision_risk | grep -c 'sentinel')" "1"
    out=$(gtpu_cmd_teid_scan 00000010 2>/dev/null)
    chk teid-low-sequential     "$(fld "$out" collision_risk | grep -c 'sequential')" "1"

    # ── inner routing ───────────────────────────────────────────────────
    out=$(gtpu_cmd_inner_route 4500001400000000401100000a000001c0a80101 2>/dev/null)
    chk inner-private     "$(fld "$out" dst_scope | cut -c1-7)" "private"
    chk inner-routes      "$(fld "$out" delivery_rule | grep -c 'does not route')" "1"

    # ── echo ────────────────────────────────────────────────────────────
    out=$(gtpu_cmd_echo 3 2>/dev/null)
    chk echo-count        "$(printf '%s\n' "$out" | awk -F'\t' '$1 ~ /^[0-9]+$/ {c++} END{print c+0}')" "3"
    chk echo-type         "$(printf '%s\n' "$out" | awk -F'\t' 'NR==2{print substr($3,3,2)}')" "01"
    chk echo-teid-zero    "$(printf '%s\n' "$out" | awk -F'\t' 'NR==2{print $2}')" "00000000"

    # ── detect ──────────────────────────────────────────────────────────
    out=$(gtpu_cmd_detect "30FF000000000000" 2>/dev/null)
    chk detect-gpdu-teid-zero "$(printf '%s' "$out" | grep -c 'g_pdu_teid_zero')" "1"
    out=$(gtpu_cmd_detect "30000001000000010000000000000000" 2>/dev/null)
    chk detect-len-mismatch "$(printf '%s' "$out" | grep -c 'length_mismatch')" "1"

    printf 'RESULT\t%s\n' "$([ "$bad" -eq 0 ] && echo PASS || echo "FAIL bad=$bad")"
    (( bad == 0 ))
}

# ── menu ────────────────────────────────────────────────────────────────
gtpu_menu() {
    local c
    while true; do
        printf '\n  GTP-U user plane (TS 29.281 / TS 38.415)\n'
        printf '  1) decode a packet          5) echo burst\n'
        printf '  2) build a G-PDU            6) TEID scan\n'
        printf '  3) PDU Session Container    7) inner route\n'
        printf '  4) detect                   8) reference points\n'
        printf '  0) back\n'
        read -rp '  choice: ' c
        case "$c" in
            1) read -rp '  hex: ' h; gtpu_cmd_parse "$h" ;;
            2) read -rp '  teid: ' h; gtpu_cmd_build "$h" ;;
            3) read -rp '  psc hex: ' h; gtpu_cmd_pdu_session "$h" ;;
            4) read -rp '  capture or hex: ' h; gtpu_cmd_detect "$h" ;;
            5) read -rp '  count: ' h; gtpu_cmd_echo "$h" ;;
            6) read -rp '  teid: ' h; gtpu_cmd_teid_scan "$h" ;;
            7) read -rp '  inner ipv4 hex: ' h; gtpu_cmd_inner_route "$h" ;;
            8) gtpu_cmd_paths ;;
            0) return ;;
            *) printf '  invalid\n' ;;
        esac
    done
}

# ── CLI dispatch ────────────────────────────────────────────────────────
gtpu_cli_main() {
    local cmd="${1:-}"
    (( $# > 0 )) && shift
    case "$cmd" in
        --status-tsv)  gtpu_cmd_status ;;
        --parse)       gtpu_cmd_parse "${1:-}" ;;
        --build)       gtpu_cmd_build "${1:-}" "${@:2}" ;;
        --pdu-session) gtpu_cmd_pdu_session "${1:-}" ;;
        --echo)        gtpu_cmd_echo "${1:-1}" "${@:2}" ;;
        --teid-scan)   gtpu_cmd_teid_scan "${1:-}" ;;
        --inner-route) gtpu_cmd_inner_route "${1:-}" ;;
        --detect)      gtpu_cmd_detect "${1:-}" ;;
        --paths)       gtpu_cmd_paths ;;
        --plan)        gtpu_cmd_plan "${1:-}" ;;
        --selftest)    gtpu_selftest ;;
        --menu)        gtpu_menu ;;
        -h|--help|"")  gtpu_usage; [[ -n "$cmd" ]] && return 0 || return 2 ;;
        *)             gtpu_usage; return 2 ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    set -o pipefail
    IMSISTING_CLI=1
    : "${TMP_DIR:=/tmp/imsisting}"
    declare -F banner >/dev/null 2>&1 || banner() { :; }
    declare -F info   >/dev/null 2>&1 || info()   { printf '[info] %s\n' "$*" >&2; }
    declare -F warn   >/dev/null 2>&1 || warn()   { printf '[warn] %s\n' "$*" >&2; }
    declare -F err    >/dev/null 2>&1 || err()    { printf '[err]  %s\n' "$*" >&2; }
    declare -F ok     >/dev/null 2>&1 || ok()     { printf '[ok]   %s\n' "$*" >&2; }
    gtpu_cli_main "$@"
fi
