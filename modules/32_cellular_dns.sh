#!/usr/bin/env bash
# Cellular DNS — RFC 1035 codec, resolver discovery, and the aLTEr attack
#                                                                   (tag: cdns)
#
# Capability split, per MODULE_CONVENTIONS.md §9:
#
#   * Everything encodable is encoded for real. The DNS message codec (header
#     bit fields, question, answer/authority/additional records, name
#     compression pointers, and the record types that matter on a cellular
#     bearer) is implemented here from the octets, both directions, and the
#     pcap reader is a real Ethernet/IPv4/IPv6/UDP/GTP-U walk that runs with
#     python3's standard library only.
#   * The aLTEr *attack* needs a layer-2 position on the LTE user plane — a
#     rogue eNB or a compromised backhaul link. That is not achievable from a
#     passive capture, so the vector is a `status: handoff` plan naming the
#     testbed. The detection half runs for real on any capture.
#
# Reference clause map (values asserted in --selftest are marked):
#   RFC 1035 §4.1.1   DNS header fields (ID, QR, Opcode, AA, TC, RD, RA, RCODE)
#   RFC 1035 §4.1.3   question section (QNAME, QTYPE, QCLASS)
#   RFC 1035 §4.1.4   resource-record format (TYPE, CLASS, TTL, RDLENGTH, RDATA)
#   RFC 1035 §4.1.4   message compression (0b11 pointer, 14-bit offset)
#   RFC 3596 §2.1     AAAA (type 28)
#   RFC 2782          SRV (type 33)
#   RFC 3225 §3       the DO bit in the OPT pseudo-RR TTL field
#   RFC 4035 §3.2.3   AD and CD header bits (DNSSEC)
#   TS 23.401 §5.3.2  the PCO in the Attach/PDN connectivity accept carries the
#                     operator's DNS and P-CSCF addresses
#   TS 24.008 §10.5.6.3 / Table 10.5.154   protocol configuration options
#   TS 33.401         LTE user-plane (PDCP) confidentiality without integrity
#   Rupprecht, Kohls, Holz, Popper, "Breaking LTE on Layer Two",
#                     IEEE Symposium on Security and Privacy 2019, §IV —
#                     the aLTEr attack. (The brief for this module cited
#                     "NDSS 2019"; the paper appeared at IEEE S&P 2019,
#                     doi 10.1109/SP.2019.00040. Cited here as it was
#                     published.)
#
# Known-answer authorities used by --selftest:
#   * RFC 1035 §4.1.1 / §4.1.4: the canonical query encoding for
#     www.example.com (labels 3www7example3com0) is asserted byte-exact, and
#     the compressed response built from it is asserted byte-exact with the
#     0xC00C pointer.
#   * Wireshark 4.2.2 `tshark` (`dns.qry.type`, `dns.flags.opcode`,
#     `dns.flags.rcode`) for the type/opcode/rcode tables.
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

MOD_TMP="$TMP_DIR/cellular_dns"
CDNS_DIR="$LOOT_DIR/cellular_dns"
CDNS_PLANS="$CDNS_DIR/plans"
mkdir -p "$MOD_TMP" "$CDNS_DIR" "$CDNS_PLANS" 2>/dev/null

# ── sanitisation and TSV splitting ──────────────────────────────────────
cdns_sanitize() { printf '%s' "${1:-}" | tr '\t\r\n' '   '; }

# Split a TSV line into CDNS_F with `cut -f`, preserving empty fields. A
# `while read` with IFS=$'\t' collapses tab runs and shifts every column after
# an empty one (MODULE_CONVENTIONS §12).
CDNS_F=()
cdns_split() {
    CDNS_F=()
    local i n
    n=$(printf '%s' "$1" | awk -F'\t' '{print NF}')
    for (( i = 1; i <= n; i++ )); do
        CDNS_F+=("$(printf '%s' "$1" | cut -f"$i")")
    done
}

cdns_byte() { printf '%02X' "$(( ${1:-0} & 0xFF ))"; }
cdns_word() { printf '%04X' "$(( ${1:-0} & 0xFFFF ))"; }
cdns_dword() { printf '%08X' "$(( ${1:-0} & 0xFFFFFFFF ))"; }

# Print the value of a TSV key from a captured parse result.
cdns_fld() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }

cdns_nfc() {
    local s="${1:-}"
    s="${s^^}"; s="${s//[[:space:]]/}"; s="${s//:/}"; s="${s//-/}"
    printf '%s' "$s"
}
cdns_is_hex() { [[ "${1:-}" =~ ^[0-9A-Fa-f]+$ ]] && (( ${#1} % 2 == 0 )); }

# ── RFC 1035 registries ─────────────────────────────────────────────────
# Type values from RFC 1035 §3.2.2/§3.2.3, RFC 3596 §2.1, RFC 2782, and the
# DNSSEC set; the names were cross-checked against Wireshark 4.2.2
# dns.qry.type.
cdns_type_name() {
    case "${1:-}" in
        1)   echo "A" ;;
        2)   echo "NS" ;;
        5)   echo "CNAME" ;;
        6)   echo "SOA" ;;
        12)  echo "PTR" ;;
        15)  echo "MX" ;;
        16)  echo "TXT" ;;
        28)  echo "AAAA" ;;
        33)  echo "SRV" ;;
        41)  echo "OPT" ;;
        43)  echo "DS" ;;
        46)  echo "RRSIG" ;;
        47)  echo "NSEC" ;;
        48)  echo "DNSKEY" ;;
        255) echo "ANY" ;;
        *)   echo "TYPE${1:-0}" ;;
    esac
}

cdns_type_code() {
    case "${1^^}" in
        A) echo 1 ;; NS) echo 2 ;; CNAME) echo 5 ;; SOA) echo 6 ;;
        PTR) echo 12 ;; MX) echo 15 ;; TXT) echo 16 ;; AAAA) echo 28 ;;
        SRV) echo 33 ;; OPT) echo 41 ;; DS) echo 43 ;; RRSIG) echo 46 ;;
        NSEC) echo 47 ;; DNSKEY) echo 48 ;; ANY) echo 255 ;;
        *) return 1 ;;
    esac
}

cdns_class_name() {
    case "${1:-}" in
        1) echo "IN" ;; 3) echo "CH" ;; 4) echo "HS" ;; 255) echo "ANY" ;;
        *) echo "CLASS${1:-0}" ;;
    esac
}

cdns_opcode_name() {
    case "${1:-}" in
        0) echo "QUERY" ;; 1) echo "IQUERY" ;; 2) echo "STATUS" ;;
        4) echo "NOTIFY" ;; 5) echo "UPDATE" ;; *) echo "OPCODE${1:-0}" ;;
    esac
}

cdns_rcode_name() {
    case "${1:-}" in
        0) echo "NOERROR" ;; 1) echo "FORMERR" ;; 2) echo "SERVFAIL" ;;
        3) echo "NXDOMAIN" ;; 4) echo "NOTIMP" ;; 5) echo "REFUSED" ;;
        6) echo "YXDOMAIN" ;; 7) echo "YXRRSET" ;; 8) echo "NXRRSET" ;;
        9) echo "NOTAUTH" ;; 10) echo "NOTZONE" ;;
        *) echo "RCODE${1:-0}" ;;
    esac
}

# ── names ───────────────────────────────────────────────────────────────
# Encode a presentation-format name into length-prefixed labels (RFC 1035
# §4.1.1). No compression is emitted: a query never needs it and a
# compression pointer in a query would break the answer's 0xC00C pointer.
cdns_name_encode() {
    local name="${1:-}" out="" lab i ch
    [[ -n "$name" ]] || return 1
    (( ${#name} <= 253 )) || { printf 'ERROR\tname longer than 253 octets\n' >&2; return 1; }
    name="${name%.}"
    local IFS='.'
    for lab in $name; do
        ((${#lab} >= 1 && ${#lab} <= 63)) || { printf 'ERROR\tlabel length out of range: %s\n' "$(cdns_sanitize "$lab")" >&2; return 1; }
        out+="$(cdns_byte "${#lab}")"
        for (( i = 0; i < ${#lab}; i++ )); do
            ch=$(printf '%d' "'${lab:$i:1}")
            (( ch >= 1 && ch <= 127 )) || { printf 'ERROR\tnon-ASCII label octet in %s\n' "$(cdns_sanitize "$name")" >&2; return 1; }
            out+=$(cdns_byte "$ch")
        done
    done
    out+="00"
    printf '%s' "$out"
}

# Decode a name at byte offset $2 of hex $1, following compression pointers
# (RFC 1035 §4.1.4). Sets CDNS_NAME (presentation form, no trailing dot) and
# CDNS_NEXT (offset just past the name in the original stream, i.e. past the
# first pointer when one was followed).
cdns_name_decode() {
    local hex="${1^^}" off="${2:-0}"
    CDNS_NAME=""; CDNS_NEXT=0
    local jumped=0 guard=0 pos="$off" l ptr i ch
    while (( guard < 128 )); do
        guard=$(( guard + 1 ))
        (( ${#hex} >= (pos + 1) * 2 )) || return 1
        l=$(( 16#${hex:$((pos * 2)):2} ))
        if (( (l & 0xC0) == 0xC0 )); then
            (( ${#hex} >= (pos + 2) * 2 )) || return 1
            ptr=$(( ((l & 0x3F) << 8) | 16#${hex:$(((pos + 1) * 2)):2} ))
            (( jumped == 0 )) && CDNS_NEXT=$(( pos + 2 ))
            jumped=1
            (( ptr < ${#hex} / 2 )) || return 1
            pos=$ptr
            continue
        elif (( (l & 0xC0) == 0 )); then
            if (( l == 0 )); then
                (( jumped == 0 )) && CDNS_NEXT=$(( pos + 1 ))
                break
            fi
            (( ${#hex} >= (pos + 1 + l) * 2 )) || return 1
            for (( i = 0; i < l; i++ )); do
                ch=$(( 16#${hex:$(((pos + 1 + i) * 2)):2} ))
                CDNS_NAME+="$(printf "\\$(printf '%03o' "$ch")")"
            done
            CDNS_NAME+="."
            pos=$(( pos + 1 + l ))
        else
            return 1
        fi
    done
    CDNS_NAME="${CDNS_NAME%.}"
    return 0
}

# ── addresses ───────────────────────────────────────────────────────────
cdns_ipv4_hex() {
    local ip="${1:-}" a b c d o
    # Do not reuse an octet variable as the validation loop variable: the loop
    # overwrites it and the address comes out rotated.
    IFS=. read -r a b c d <<<"$ip"
    for o in "$a" "$b" "$c" "$d"; do
        [[ "$o" =~ ^[0-9]+$ ]] && (( o <= 255 )) || { printf 'ERROR\tnot an IPv4 address: %s\n' "$(cdns_sanitize "$ip")" >&2; return 1; }
    done
    printf '%s%s%s%s' "$(cdns_byte "$a")" "$(cdns_byte "$b")" "$(cdns_byte "$c")" "$(cdns_byte "$d")"
}

cdns_hex_ipv4() {
    local h="${1:-}"
    [[ "$h" =~ ^[0-9A-Fa-f]{8}$ ]] || return 1
    printf '%d.%d.%d.%d' $(( 16#${h:0:2} )) $(( 16#${h:2:2} )) $(( 16#${h:4:2} )) $(( 16#${h:6:2} ))
}

# ── message builder ─────────────────────────────────────────────────────
# cdns_build_query <name> [type] [id] [rd]
cdns_build_query() {
    local name="${1:-}" type="${2:-A}" id="${3:-1234}" rd="${4:-1}"
    local qh; qh=$(cdns_name_encode "$name") || return 1
    local tcode; tcode=$(cdns_type_code "$type") || {
        printf 'ERROR\tunknown query type: %s\n' "$(cdns_sanitize "$type")" >&2; return 1; }
    [[ "$id" =~ ^(0x)?[0-9A-Fa-f]{1,4}$ ]] || { printf 'ERROR\tbad transaction id\n' >&2; return 1; }
    local idv; idv=$(( id ))
    local flags=0
    (( rd )) && flags=$(( flags | 0x0100 ))
    # header, then QNAME QTYPE QCLASS in that order (RFC 1035 §4.1.3).
    printf '%s%s0001000000000000%s%s0001' \
        "$(cdns_word "$idv")" "$(cdns_word "$flags")" "$qh" "$(cdns_word "$tcode")"
}

# cdns_build_response <query-hex> <answer-ip> [ttl] [rcode]
# Echoes the query's ID and question, sets QR|RA and (when the query asked for
# recursion) RD, and appends one A or AAAA answer whose owner name is a
# 0xC00C pointer to the question name at offset 12 — the compression form
# RFC 1035 §4.1.4 defines and every resolver emits.
cdns_build_response() {
    local qhex; qhex=$(cdns_nfc "${1:-}")
    local ip="${2:-}" ttl="${3:-300}" rcode="${4:-0}"
    cdns_is_hex "$qhex" && (( ${#qhex} >= 24 )) || { printf 'ERROR\t--build-response needs a full query in hex\n' >&2; return 1; }
    [[ "$ttl" =~ ^[0-9]+$ ]] && (( ttl <= 4294967295 )) || { printf 'ERROR\tbad TTL\n' >&2; return 1; }
    local qid=$(( 16#${qhex:0:4} ))
    local qflags=$(( 16#${qhex:4:4} ))
    local qrd=$(( (qflags >> 8) & 1 ))
    local qd=$(( 16#${qhex:8:4} ))
    (( qd == 1 )) || { printf 'ERROR\tonly a single-question query can be answered\n' >&2; return 1; }
    cdns_name_decode "$qhex" 12 || { printf 'ERROR\tcannot decode the question name\n' >&2; return 1; }
    local qname="$CDNS_NAME"
    local qoff=$CDNS_NEXT
    local qtype=$(( 16#${qhex:$((qoff * 2)):4} ))
    local qclass=$(( 16#${qhex:$((qoff * 2 + 4)):4} ))
    local ans_type="$qtype" rdata=""
    case "$qtype" in
        1)   rdata=$(cdns_ipv4_hex "$ip") || return 1 ;;
        28)  rdata=$(cdns_ipv6_hex "$ip") || return 1 ;;
        *)   # Answer A for a non-address query type: only used for spoof
             # construction, and reported as an A answer.
             ans_type=1; rdata=$(cdns_ipv4_hex "$ip") || return 1 ;;
    esac
    local flags=$(( 0x8000 | (qrd << 8) | 0x0080 | (rcode & 0x0F) ))
    local rh; rh=$(cdns_name_encode "$qname") || return 1
    local rr
    rr="C00C$(cdns_word "$ans_type")$(cdns_word "$qclass")$(cdns_dword "$ttl")$(cdns_word $(( ${#rdata} / 2 )))$rdata"
    printf '%s%s0001000100000000%s%s%s' \
        "$(cdns_word "$qid")" "$(cdns_word "$flags")" "$rh" \
        "$(cdns_word "$qtype")$(cdns_word "$qclass")" "$rr"
}

cdns_ipv6_hex() {
    local ip="${1:-}"
    command -v python3 >/dev/null 2>&1 || { printf 'ERROR\tpython3 is required to encode an IPv6 answer\n' >&2; return 1; }
    python3 - "$ip" <<'PY'
import ipaddress, sys
try:
    a = ipaddress.IPv6Address(sys.argv[1])
except Exception:
    sys.exit(1)
print(a.packed.hex().upper())
PY
}

# ── parser ──────────────────────────────────────────────────────────────
# Emit one TSV row per field. A response that does not parse is an error, not
# an empty success.
cdns_parse() {
    local hex; hex=$(cdns_nfc "${1:-}")
    cdns_is_hex "$hex" || { printf 'ERROR\tnot valid hex\n' >&2; return 1; }
    (( ${#hex} >= 24 )) || { printf 'ERROR\tDNS message shorter than the 12-octet header\n' >&2; return 1; }
    local id=$(( 16#${hex:0:4} ))
    local flags=$(( 16#${hex:4:4} ))
    local qd=$(( 16#${hex:8:4} )) an=$(( 16#${hex:12:4} ))
    local ns=$(( 16#${hex:16:4} )) ar=$(( 16#${hex:20:4} ))
    printf 'id\t%s\n'    "$id"
    printf 'flags\t%s\n' "$(cdns_word "$flags")"
    printf 'qr\t%s\n'    "$(( (flags >> 15) & 1 ))"
    printf 'opcode\t%s\n' "$(( (flags >> 11) & 0x0F ))"
    printf 'opcode_name\t%s\n' "$(cdns_opcode_name $(( (flags >> 11) & 0x0F )))"
    printf 'aa\t%s\n' "$(( (flags >> 10) & 1 ))"
    printf 'tc\t%s\n' "$(( (flags >> 9) & 1 ))"
    printf 'rd\t%s\n' "$(( (flags >> 8) & 1 ))"
    printf 'ra\t%s\n' "$(( (flags >> 7) & 1 ))"
    printf 'z\t%s\n'  "$(( (flags >> 6) & 1 ))"
    printf 'ad\t%s\n' "$(( (flags >> 5) & 1 ))"
    printf 'cd\t%s\n' "$(( (flags >> 4) & 1 ))"
    printf 'rcode\t%s\n' "$(( flags & 0x0F ))"
    printf 'rcode_name\t%s\n' "$(cdns_rcode_name $(( flags & 0x0F )))"
    printf 'qdcount\t%s\n' "$qd"
    printf 'ancount\t%s\n' "$an"
    printf 'nscount\t%s\n' "$ns"
    printf 'arcount\t%s\n' "$ar"

    local off=12 i ttl rdlen sec idx rtype rclass rdata
    for (( i = 0; i < qd; i++ )); do
        cdns_name_decode "$hex" "$off" || { printf 'ERROR\tquestion %s name is malformed\n' "$i" >&2; return 1; }
        printf 'question.%s.name\t%s\n' "$i" "$(cdns_sanitize "$CDNS_NAME")"
        off=$CDNS_NEXT
        (( ${#hex} >= (off + 4) * 2 )) || { printf 'ERROR\tquestion %s is truncated\n' "$i" >&2; return 1; }
        rtype=$(( 16#${hex:$((off * 2)):4} ))
        rclass=$(( 16#${hex:$((off * 2 + 4)):4} ))
        printf 'question.%s.type\t%s\n' "$i" "$rtype"
        printf 'question.%s.type_name\t%s\n' "$i" "$(cdns_type_name "$rtype")"
        printf 'question.%s.class\t%s\n' "$i" "$(cdns_class_name "$rclass")"
        off=$(( off + 4 ))
    done

    local -a counts=( "$an" "$ns" "$ar" )
    local -a names=( "answer" "authority" "additional" )
    local s
    for s in 0 1 2; do
        sec="${names[$s]}"
        for (( idx = 0; idx < ${counts[$s]}; idx++ )); do
            cdns_name_decode "$hex" "$off" || { printf 'ERROR\t%s record %s name is malformed\n' "$sec" "$idx" >&2; return 1; }
            printf '%s.%s.name\t%s\n' "$sec" "$idx" "$(cdns_sanitize "$CDNS_NAME")"
            off=$CDNS_NEXT
            (( ${#hex} >= (off + 10) * 2 )) || { printf 'ERROR\t%s record %s header is truncated\n' "$sec" "$idx" >&2; return 1; }
            rtype=$(( 16#${hex:$((off * 2)):4} ))
            rclass=$(( 16#${hex:$((off * 2 + 4)):4} ))
            # RR header: TYPE(2) CLASS(2) TTL(4) RDLENGTH(2), then RDATA.
            ttl=$(( 16#${hex:$((off * 2 + 8)):4} * 65536 + 16#${hex:$((off * 2 + 12)):4} ))
            rdlen=$(( 16#${hex:$((off * 2 + 16)):4} ))
            (( ${#hex} >= (off + 10 + rdlen) * 2 )) || { printf 'ERROR\t%s record %s rdata is truncated\n' "$sec" "$idx" >&2; return 1; }
            rdata="${hex:$(((off + 10) * 2)):$((rdlen * 2))}"
            printf '%s.%s.type\t%s\n' "$sec" "$idx" "$rtype"
            printf '%s.%s.type_name\t%s\n' "$sec" "$idx" "$(cdns_type_name "$rtype")"
            printf '%s.%s.class\t%s\n' "$sec" "$idx" "$(cdns_class_name "$rclass")"
            printf '%s.%s.ttl\t%s\n' "$sec" "$idx" "$ttl"
            printf '%s.%s.rdlength\t%s\n' "$sec" "$idx" "$rdlen"
            printf '%s.%s.rdata\t%s\n' "$sec" "$idx" "$rdata"
            case "$rtype" in
                1)  [[ $rdlen -eq 4 ]] && printf '%s.%s.value\t%s\n' "$sec" "$idx" "$(cdns_hex_ipv4 "$rdata")" ;;
                28) printf '%s.%s.value\t%s\n' "$sec" "$idx" "$rdata" ;;
                5|2|12)
                    if cdns_name_decode "$hex" $(( off + 10 )); then
                        printf '%s.%s.value\t%s\n' "$sec" "$idx" "$(cdns_sanitize "$CDNS_NAME")"
                    fi ;;
                41)
                    # RFC 3225: the DO bit is bit 15 of the OPT TTL field.
                    printf 'do\t%s\n' "$(( (ttl >> 15) & 1 ))"
                    printf '%s.%s.opt_udp_size\t%s\n' "$sec" "$idx" "$rclass"
                    ;;
                15) # MX: preference + exchange name
                    if (( rdlen > 2 )) && cdns_name_decode "$hex" $(( off + 12 )); then
                        printf '%s.%s.value\t%s %s\n' "$sec" "$idx" "$(( 16#${rdata:0:4} ))" "$(cdns_sanitize "$CDNS_NAME")"
                    fi ;;
            esac
            off=$(( off + 10 + rdlen ))
        done
    done
    return 0
}

# ── pcap extraction ─────────────────────────────────────────────────────
# A real reader: classic pcap and pcapng, Ethernet / Linux SLL / raw IP, IPv4
# and IPv6, UDP, and GTP-U decapsulation so DNS carried inside the cellular
# user plane is found as well as DNS on a plain bearer. python3 stdlib only.
cdns_pcap_py() {
    cat <<'PYEOF'
import sys, struct

def _u16(b, o, e):
    return struct.unpack_from(e + 'H', b, o)[0]
def _u32(b, o, e):
    return struct.unpack_from(e + 'I', b, o)[0]

def blocks_pcap(data):
    magic = data[:4]
    if magic in (b'\xa1\xb2\xc3\xd4', b'\xa1\xb2\x3c\x4d'):
        e = '>'
    elif magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1'):
        e = '<'
    else:
        return None, None
    if len(data) < 24:
        return None, None
    linktype = _u32(data, 20, e)
    off = 24
    out = []
    while off + 16 <= len(data):
        ts, tus, incl, orig = struct.unpack_from(e + 'IIII', data, off)
        off += 16
        if incl > len(data) - off:
            break
        out.append((ts + tus / 1000000.0, data[off:off + incl]))
        off += incl
    return linktype, out

def blocks_pcapng(data):
    off = 0
    e = '<'
    seen_shb = False
    linktypes = []
    out = []
    while off + 12 <= len(data):
        # The block type is read little-endian only to spot the Section Header
        # Block; once the byte-order magic is known every length is re-read in
        # the file's own byte order.
        btype_probe = struct.unpack_from('<I', data, off)[0]
        if btype_probe == 0x0A0D0D0A or (not seen_shb and data[off:off + 4] == b'\x0a\x0d\x0d\x0a'):
            bom = struct.unpack_from('<I', data, off + 8)[0]
            e = '<' if bom == 0x1A2B3C4D else '>'
            seen_shb = True
        btype = _u32(data, off, e)
        blen = _u32(data, off + 4, e)
        if blen < 12 or off + blen > len(data):
            break
        body = data[off + 8:off + blen - 4]
        if btype == 0x0A0D0D0A:
            pass
        elif btype == 1:  # IDB
            linktypes.append(_u16(body, 0, e))
        elif btype == 6:  # EPB
            iface = _u32(body, 0, e)
            tsh = _u32(body, 4, e)
            tsl = _u32(body, 8, e)
            cap = _u32(body, 12, e)
            ts = ((tsh << 32) | tsl) / 1000000.0
            pkt = body[20:20 + cap]
            lt = linktypes[iface] if iface < len(linktypes) else 1
            out.append((lt, ts, pkt))
        elif btype == 3:  # SPB
            orig = _u32(body, 0, e)
            lt = linktypes[0] if linktypes else 1
            out.append((lt, 0.0, body[4:4 + orig]))
        off += blen
    return out

def ipv4(tvb):
    if len(tvb) < 20:
        return None
    ihl = (tvb[0] & 0x0F) * 4
    if ihl < 20 or len(tvb) < ihl:
        return None
    proto = tvb[9]
    frag = struct.unpack_from('>H', tvb, 6)[0]
    if frag & 0x1FFF:
        return None
    src = '.'.join(str(x) for x in tvb[12:16])
    dst = '.'.join(str(x) for x in tvb[16:20])
    return proto, src, dst, tvb[ihl:]

def ipv6(tvb):
    if len(tvb) < 40:
        return None
    nh = tvb[6]
    src = ':'.join('%02x%02x' % (tvb[8 + i * 2], tvb[9 + i * 2]) for i in range(8))
    dst = ':'.join('%02x%02x' % (tvb[24 + i * 2], tvb[25 + i * 2]) for i in range(8))
    return nh, src, dst, tvb[40:]

def udp(tvb):
    if len(tvb) < 8:
        return None
    sp, dp, ln = struct.unpack_from('>HHH', tvb, 0)
    return sp, dp, tvb[8:]

def gtp_u(tvb):
    if len(tvb) < 8:
        return None
    flags = tvb[0]
    if (flags >> 5) & 0x07 != 1:
        return None
    hlen = 8
    if flags & 0x07:
        hlen += 4
    if len(tvb) < hlen:
        return None
    return tvb[hlen:]

def l3(tvb, linktype):
    if linktype == 1:  # Ethernet
        if len(tvb) < 14:
            return None
        et = struct.unpack_from('>H', tvb, 12)[0]
        off = 14
        while et in (0x8100, 0x88A8) and len(tvb) >= off + 4:
            et = struct.unpack_from('>H', tvb, off + 2)[0]
            off += 4
        if et == 0x0800:
            return ipv4(tvb[off:])
        if et == 0x86DD:
            return ipv6(tvb[off:])
        return None
    if linktype in (101, 12, 14, 228):
        if not tvb:
            return None
        v = tvb[0] >> 4
        return ipv4(tvb) if v == 4 else (ipv6(tvb) if v == 6 else None)
    if linktype == 113:  # Linux SLL
        if len(tvb) < 16:
            return None
        et = struct.unpack_from('>H', tvb, 14)[0]
        if et == 0x0800:
            return ipv4(tvb[16:])
        if et == 0x86DD:
            return ipv6(tvb[16:])
        return None
    if linktype == 276:  # Linux SLL2
        if len(tvb) < 20:
            return None
        et = struct.unpack_from('>H', tvb, 0)[0]
        if et == 0x0800:
            return ipv4(tvb[20:])
        if et == 0x86DD:
            return ipv6(tvb[20:])
        return None
    return None

def main():
    path = sys.argv[1]
    with open(path, 'rb') as f:
        data = f.read()
    frames = []
    lt, pkts = blocks_pcap(data)
    if lt is not None:
        for i, (ts, pkt) in enumerate(pkts, 1):
            frames.append((i, ts, lt, pkt))
    else:
        for i, (lt2, ts, pkt) in enumerate(blocks_pcapng(data), 1):
            frames.append((i, ts, lt2, pkt))
    for idx, ts, linktype, pkt in frames:
        encap = 'eth'
        parsed = l3(pkt, linktype)
        if not parsed:
            continue
        proto, src, dst, payload = parsed
        if proto != 17:
            continue
        u = udp(payload)
        if not u:
            continue
        sp, dp, up = u
        if 2152 in (sp, dp):
            inner = gtp_u(up)
            if inner:
                p2 = ipv4(inner)
                if p2 and p2[0] == 17:
                    u2 = udp(p2[3])
                    if u2:
                        sp2, dp2, up2 = u2
                        if 53 in (sp2, dp2) and len(up2) >= 12:
                            print('pkt\t%d\t%.6f\t%s\t%d\t%s\t%d\tgtpu\t%s' %
                                  (idx, ts, p2[1], sp2, p2[2], dp2, up2.hex().upper()))
                            continue
        if 53 in (sp, dp) and len(up) >= 12:
            print('pkt\t%d\t%.6f\t%s\t%d\t%s\t%d\t%s\t%s' %
                  (idx, ts, src, sp, dst, dp, encap, up.hex().upper()))
        elif dp in (853, 5353) or sp in (853, 5353):
            print('altport\t%d\t%.6f\t%s\t%d\t%s\t%d\t%s' % (idx, ts, src, sp, dst, dp, encap))
    return 0

sys.exit(main())
PYEOF
}

# Extract DNS packets from a capture as "pkt" rows. Requires python3.
cdns_extract_pcap() {
    local pcap="${1:-}"
    [[ -n "$pcap" ]] || { printf 'ERROR\tusage: cdns_extract_pcap <pcap>\n' >&2; return 2; }
    [[ -r "$pcap" ]] || { printf 'ERROR\tcannot read capture: %s\n' "$(cdns_sanitize "$pcap")" >&2; return 1; }
    command -v python3 >/dev/null 2>&1 || { printf 'MISSING\tpython3 is required to read a capture\n' >&2; return 1; }
    python3 <(cdns_pcap_py) "$pcap"
}

# ── detection ───────────────────────────────────────────────────────────
# Pure function over the TSV rows cdns_detect_rows produces, so the rules can
# be unit-tested without a capture.
#
# Rules, and why each is a real signal:
#   response-without-query    a response whose (ID, question) matches no query
#   id-mismatch               a response answering a name that was queried with
#                             a different transaction ID
#   question-mismatch         the response's question section is not the one
#                             that was asked
#   answer-question-contradiction
#                             the answer owner name is not the question name
#                             (the aLTEr rewrite, expressed on the wire)
#   resolver-address-mismatch a response from an address the client never sent
#                             a query to
#   ttl-anomaly               an answer TTL far from every other TTL seen for
#                             that name in the capture
#   dnssec-bogus-ad           AD=1 with no RRSIG present (RFC 4035 §3.2.3)
#   dnssec-stripped           the query set DO but no RRSIG came back for a
#                             name that is signed elsewhere in the capture
#   dnssec-not-validated      informational: RRSIG present, chain validation
#                             is NOT performed here (no trust anchor, no
#                             crypto in the toolchain) — reported so a caller
#                             never reads a silent pass as a validated answer
cdns_detect_stream() {
    local line
    local -A qkey qname_by qname_asked resolvers resolvers_by_client
    local -A seen_rrsig ttl_samples ttl_count a_names
    local -a resp_rows=()
    # `local` inside the read loop would wreck field splitting; declare the
    # per-row variables up front (MODULE_CONVENTIONS §15).
    local kind frame ts src sport dst dport id rcode aa ra ad cd qname qtype
    local answers rrsig doflag ttls
    local key altkey ckey
    local -a atoks
    local n=0

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        cdns_split "$line"
        kind="${CDNS_F[0]:-}"
        case "$kind" in
            query)
                frame="${CDNS_F[1]:-}"; ts="${CDNS_F[2]:-}"; src="${CDNS_F[3]:-}"
                sport="${CDNS_F[4]:-}"; dst="${CDNS_F[5]:-}"; dport="${CDNS_F[6]:-}"
                id="${CDNS_F[7]:-}"; qname="${CDNS_F[8]:-}"; qtype="${CDNS_F[9]:-}"; doflag="${CDNS_F[10]:-}"
                key="$id|$src|$dst"
                qkey["$key"]="$qname|$qtype|$doflag"
                qname_by["$id|$src"]="$qname"
                qname_asked["$qname"]=1
                resolvers["$dst"]=1
                resolvers_by_client["$src|$dst"]=1
                ;;
            response)
                resp_rows+=( "$line" )
                ;;
        esac
    done

    local r
    for r in "${resp_rows[@]}"; do
        cdns_split "$r"
        frame="${CDNS_F[1]:-}"; ts="${CDNS_F[2]:-}"; src="${CDNS_F[3]:-}"
        sport="${CDNS_F[4]:-}"; dst="${CDNS_F[5]:-}"; dport="${CDNS_F[6]:-}"
        id="${CDNS_F[7]:-}"; rcode="${CDNS_F[8]:-}"; aa="${CDNS_F[9]:-}"
        ra="${CDNS_F[10]:-}"; ad="${CDNS_F[11]:-}"; cd="${CDNS_F[12]:-}"
        qname="${CDNS_F[13]:-}"; qtype="${CDNS_F[14]:-}"
        answers="${CDNS_F[15]:-}"; rrsig="${CDNS_F[16]:-}"; doflag="${CDNS_F[17]:-}"
        ttls="${CDNS_F[18]:-}"

        key="$id|$dst|$src"
        if [[ -z "${qkey[$key]:-}" ]]; then
            # Try to find a query for the same question from the same client
            # with a different ID: that is an ID mismatch, not a stray answer.
            altkey=""
            local qk
            for qk in "${!qkey[@]}"; do
                local qk_id="${qk%%|*}"
                local rest="${qk#*|}"
                local qk_src="${rest%%|*}"
                local qk_dst="${rest#*|}"
                if [[ "$qk_src" == "$dst" && "$qk_dst" != "$src" ]]; then :; fi
                if [[ "$qk_src" == "$dst" ]]; then
                    local qv="${qkey[$qk]}"
                    if [[ "${qv%%|*}" == "$qname" && "$qk_id" != "$id" ]]; then
                        altkey="$qk_id"; break
                    fi
                fi
            done
            if [[ -n "$altkey" ]]; then
                printf 'FINDING\tHIGH\tid-mismatch\t%s\tquery id %s answered with id %s for %s\n' \
                    "$(cdns_sanitize "$frame")" "$(cdns_sanitize "$altkey")" "$(cdns_sanitize "$id")" "$(cdns_sanitize "$qname")"
            else
                printf 'FINDING\tHIGH\tresponse-without-query\t%s\tid %s %s from %s\n' \
                    "$(cdns_sanitize "$frame")" "$(cdns_sanitize "$id")" "$(cdns_sanitize "$qname")" "$(cdns_sanitize "$src")"
            fi
        else
            local want="${qkey[$key]}"
            local want_name="${want%%|*}"
            if [[ "$want_name" != "$qname" ]]; then
                printf 'FINDING\tHIGH\tquestion-mismatch\t%s\tasked %s, answer carries question %s\n' \
                    "$(cdns_sanitize "$frame")" "$(cdns_sanitize "$want_name")" "$(cdns_sanitize "$qname")"
            fi
        fi
        if [[ -z "${resolvers_by_client[$dst|$src]:-}" ]]; then
            printf 'FINDING\tHIGH\tresolver-address-mismatch\t%s\tresponse for %s from %s, but no query was sent to %s\n' \
                "$(cdns_sanitize "$frame")" "$(cdns_sanitize "$qname")" "$(cdns_sanitize "$src")" "$(cdns_sanitize "$src")"
        fi
        # Answer owner name vs the question name.
        if [[ -n "$answers" ]]; then
            local first="${answers%%;*}"
            local aname="${first%%:*}"
            if [[ -n "$aname" && "$aname" != "$qname" ]]; then
                printf 'FINDING\tHIGH\tanswer-question-contradiction\t%s\nthe response asks about %s but the first answer is owned by %s\n' \
                    "$(cdns_sanitize "$frame")" "$(cdns_sanitize "$qname")" "$(cdns_sanitize "$aname")"
            fi
        fi
        if [[ "$rcode" == "3" && -n "$answers" ]]; then
            printf 'FINDING\tMEDIUM\tnxdomain-with-answer\t%s\tNXDOMAIN for %s carries %s answers\n' \
                "$(cdns_sanitize "$frame")" "$(cdns_sanitize "$qname")" "$(printf '%s' "$answers" | tr ';' '\n' | grep -c .)"
        fi
        # TTL anomaly: compare against every other TTL seen for the same name.
        local t
        for t in ${ttls//,/ }; do
            [[ "$t" =~ ^[0-9]+$ ]] || continue
            local prev="${ttl_samples[$qname]:-}"
            if [[ -n "$prev" ]]; then
                local lo=999999999 hi=0 p
                for p in ${prev//,/ }; do
                    (( p < lo )) && lo=$p
                    (( p > hi )) && hi=$p
                done
                if (( hi > 0 && t > hi * 10 )) || (( t > 604800 )); then
                    printf 'FINDING\tMEDIUM\tttl-anomaly\t%s\t%s TTL %s vs %s seen elsewhere\n' \
                        "$(cdns_sanitize "$frame")" "$(cdns_sanitize "$qname")" "$(cdns_sanitize "$t")" "$(cdns_sanitize "$hi")"
                fi
            fi
            ttl_samples["$qname"]="${prev:+$prev,}$t"
            ttl_count["$qname"]=$(( ${ttl_count[$qname]:-0} + 1 ))
        done
        [[ "$rrsig" == "1" ]] && seen_rrsig["$qname"]=1
        if [[ "$ad" == "1" && "$rrsig" != "1" ]]; then
            printf 'FINDING\tHIGH\tdnssec-bogus-ad\t%s\tAD set for %s but no RRSIG in the response\n' \
                "$(cdns_sanitize "$frame")" "$(cdns_sanitize "$qname")"
        fi
        if [[ "$doflag" == "1" && "$rrsig" != "1" && -n "${seen_rrsig[$qname]:-}" ]]; then
            printf 'FINDING\tMEDIUM\tdnssec-stripped\t%s\tDO set and %s is signed elsewhere in this capture, but no RRSIG here\n' \
                "$(cdns_sanitize "$frame")" "$(cdns_sanitize "$qname")"
        fi
        if [[ "$rrsig" == "1" ]]; then
            printf 'FINDING\tINFO\tdnssec-not-validated\t%s\tRRSIG present for %s; cryptographic chain validation is NOT performed (no trust anchor in the toolchain)\n' \
                "$(cdns_sanitize "$frame")" "$(cdns_sanitize "$qname")"
        fi
    done
    return 0
}

# Turn DNS payload hex + endpoints into detection rows.
cdns_row_from_hex() {
    local dnshex="${1:-}" src="${2:-}" sport="${3:-}" dst="${4:-}" dport="${5:-}" frame="${6:-}" ts="${7:-}"
    local p; p=$(cdns_parse "$dnshex") || return 1
    local qr; qr=$(cdns_fld "$p" qr)
    local id; id=$(cdns_fld "$p" id)
    local qname; qname=$(cdns_fld "$p" question.0.name)
    local qtype; qtype=$(cdns_fld "$p" question.0.type)
    local doflag; doflag=$(cdns_fld "$p" do)
    if [[ "$qr" == "0" ]]; then
        printf 'query\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$frame" "$ts" "$src" "$sport" "$dst" "$dport" "$id" \
            "$(cdns_sanitize "$qname")" "$(cdns_sanitize "$qtype")" "${doflag:-0}"
        return 0
    fi
    # Response: gather the answer section, the RRSIG presence and the TTL set.
    local answers="" rrsig=0 ttls="" i n ttl aname atype aval
    n=$(printf '%s\n' "$p" | awk -F'\t' '$1=="ancount"{print $2; exit}')
    for (( i = 0; i < ${n:-0}; i++ )); do
        aname=$(printf '%s\n' "$p" | awk -F'\t' -v k="answer.$i.name" '$1==k{print $2; exit}')
        atype=$(printf '%s\n' "$p" | awk -F'\t' -v k="answer.$i.type" '$1==k{print $2; exit}')
        aval=$(printf '%s\n' "$p" | awk -F'\t' -v k="answer.$i.value" '$1==k{print $2; exit}')
        ttl=$(printf '%s\n' "$p" | awk -F'\t' -v k="answer.$i.ttl" '$1==k{print $2; exit}')
        [[ "$atype" == "46" ]] && rrsig=1
        [[ -n "$ttl" ]] && ttls+="${ttls:+,}$ttl"
        answers+="${answers:+;}${aname}:${atype}:${aval:-}:${ttl:-0}"
    done
    printf 'response\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$frame" "$ts" "$src" "$sport" "$dst" "$dport" "$id" \
        "$(cdns_fld "$p" rcode)" "$(cdns_fld "$p" aa)" "$(cdns_fld "$p" ra)" "$(cdns_fld "$p" ad)" "$(cdns_fld "$p" cd)" \
        "$(cdns_sanitize "$qname")" "$(cdns_sanitize "$qtype")" \
        "$(cdns_sanitize "$answers")" "$rrsig" "${doflag:-0}" "$(cdns_sanitize "$ttls")"
    return 0
}

cdns_detect_rows() {
    local pcap="${1:-}"
    [[ -n "$pcap" ]] || { printf 'ERROR\tusage: --detect <pcap>\n' >&2; return 2; }
    local rows; rows=$(cdns_extract_pcap "$pcap") || return 1
    # Declare every per-row variable before the read loop: `local` inside a
    # `while read` body is the field-splitting trap in MODULE_CONVENTIONS §15.
    local line kind rest f ts s sp d dp enc dh
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        kind=$(printf '%s' "$line" | cut -f1)
        case "$kind" in
            altport)
                rest=$(printf '%s' "$line" | cut -f2-)
                printf 'altport\t%s\n' "$rest"
                ;;
            pkt)
                # pkt frame ts src sport dst dport encap dnshex
                f=$(printf '%s' "$line" | cut -f2)
                ts=$(printf '%s' "$line" | cut -f3)
                s=$(printf '%s' "$line" | cut -f4)
                sp=$(printf '%s' "$line" | cut -f5)
                d=$(printf '%s' "$line" | cut -f6)
                dp=$(printf '%s' "$line" | cut -f7)
                enc=$(printf '%s' "$line" | cut -f8)
                dh=$(printf '%s' "$line" | cut -f9)
                cdns_row_from_hex "$dh" "$s" "$sp" "$d" "$dp" "$f" "$ts" || {
                    printf 'ERROR\tframe %s carries an unparseable DNS message\n' "$(cdns_sanitize "$f")" >&2
                    return 1
                }
                ;;
        esac
    done <<<"$rows"
    return 0
}

cdns_cmd_detect() {
    local pcap="${1:-}"
    [[ -n "$pcap" ]] || { printf 'ERROR\tusage: --detect <pcap>\n' >&2; return 2; }
    local rows; rows=$(cdns_detect_rows "$pcap") || return 1
    local counts; counts=$(printf '%s\n' "$rows" | awk -F'\t' '{c[$1]++} END{for (k in c) print k"\t"c[k]}')
    printf 'capture\t%s\n' "$(cdns_sanitize "$pcap")"
    printf 'queries\t%s\n' "$(printf '%s\n' "$counts" | awk -F'\t' '$1=="query"{print $2}')"
    printf 'responses\t%s\n' "$(printf '%s\n' "$counts" | awk -F'\t' '$1=="response"{print $2}')"
    printf 'header\tseverity\trule\tframe\tdetail\n'
    printf '%s\n' "$rows" | cdns_detect_stream
    return 0
}

# ── resolver discovery ──────────────────────────────────────────────────
# Where the UE's resolver comes from on a cellular bearer:
#   * the operator resolver handed out in the PCO of the Attach Accept /
#     PDN connectivity accept (TS 23.401 §5.3.2, TS 24.008 §10.5.6.3),
#   * the P-CSCF, which the UE uses for IMS and which is also PCO-supplied,
#   * a public resolver hardcoded by the OS or an app,
#   * a DHCP-provided resolver on some bearers.
# Which of these is in play is visible in the capture: the destination
# addresses of the DNS queries are the resolver, and the profile of those
# addresses says which kind it is.
cdns_resolver_class() {
    local ip="${1:-}"
    case "$ip" in
        8.8.8.8|8.8.4.4|1.1.1.1|1.0.0.1|9.9.9.9|149.112.112.112|208.67.222.222|208.67.220.220|64.6.64.6|64.6.65.6)
            echo "public-resolver" ;;
        10.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|192.168.*|100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*)
            echo "operator-internal" ;;
        *) echo "other" ;;
    esac
}

# PCO protocol identifiers. TS 24.008 §10.5.6.3 Table 10.5.154 lists the
# container IDs; only 0001H is named here because it is the one that could be
# corroborated locally (TS 34.229-1 names container 0001H as the P-CSCF
# address request). Everything else is reported numerically rather than
# guessed at.
cdns_pco_container_name() {
    case "${1^^}" in
        0001) echo "P-CSCF address" ;;
        *)    echo "container-${1^^}" ;;
    esac
}

# Structural walk of a PCO value: a leading octet (extension bit + the
# configuration protocol), then a sequence of (ID, length, value) containers.
cdns_pco_parse() {
    local hex; hex=$(cdns_nfc "${1:-}")
    cdns_is_hex "$hex" && (( ${#hex} >= 2 )) || { printf 'ERROR\tPCO needs hex\n' >&2; return 1; }
    local first=$(( 16#${hex:0:2} ))
    printf 'config_protocol\t%s\n' "$(( first & 0x07 ))"
    printf 'extension_bit\t%s\n' "$(( (first >> 7) & 1 ))"
    local off=1 id len val
    while (( (off + 3) * 2 <= ${#hex} )); do
        id="${hex:$((off * 2)):4}"
        len=$(( 16#${hex:$((off * 2 + 4)):2} ))
        (( ${#hex} >= (off + 3 + len) * 2 )) || {
            printf 'ERROR\tPCO container %s is truncated\n' "$id" >&2; return 1; }
        val="${hex:$(((off + 3) * 2)):$((len * 2))}"
        printf 'container\t%s\t%s\t%s\t%s\n' "$id" "$len" "$val" "$(cdns_pco_container_name "$id")"
        off=$(( off + 3 + len ))
    done
    return 0
}

cdns_resolver_discovery() {
    local pcap="${1:-}"
    [[ -n "$pcap" ]] || { printf 'ERROR\tusage: --resolver-discovery <pcap>\n' >&2; return 2; }
    local rows; rows=$(cdns_detect_rows "$pcap") || return 1
    printf 'capture\t%s\n' "$(cdns_sanitize "$pcap")"
    printf 'header\tresolver_ip\tport\tqueries\tclass\tlearned_from\n'
    local line
    # Queries only: the destination of a query is the resolver in use.
    local -A cnt port
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        [[ "$(printf '%s' "$line" | cut -f1)" == "query" ]] || continue
        local d dp
        d=$(printf '%s' "$line" | cut -f6)
        dp=$(printf '%s' "$line" | cut -f7)
        cnt["$d"]=$(( ${cnt[$d]:-0} + 1 ))
        port["$d"]="$dp"
    done <<<"$rows"
    local ip
    for ip in "${!cnt[@]}"; do
        printf 'resolver\t%s\t%s\t%s\t%s\t%s\n' \
            "$(cdns_sanitize "$ip")" "$(cdns_sanitize "${port[$ip]:-53}")" "${cnt[$ip]}" \
            "$(cdns_resolver_class "$ip")" \
            "$(case "$(cdns_resolver_class "$ip")" in
                   public-resolver) echo "OS/app default, not PCO-supplied" ;;
                   operator-internal) echo "PCO in Attach/PDN accept, or DHCP on the bearer" ;;
                   *) echo "unknown provenance" ;;
               esac)"
    done
    # Encrypted transports on the same bearer, which hide the resolver name.
    printf '%s\n' "$rows" | awk -F'\t' '$1=="altport"{printf "alt_transport\t%s\t%s\t%s\t%s\n",$4,$5,$6,$7}'
    printf 'note\t%s\n' "the P-CSCF and the operator DNS are carried in the PCO of the Attach Accept / PDN connectivity accept (TS 24.008 10.5.6.3); use --pco <hex> to decode one"
    return 0
}

# ── the aLTEr attack, described as it is performed ──────────────────────
cdns_alter_notes() {
    cat <<'EOF'
step	actor	action	precondition	why_it_works
1	attacker	hold a layer-2 position on the LTE user-plane path between the UE and the S-GW: a rogue eNB the UE reselects to, or a compromised/misconfigured backhaul link	the UE attaches or hands over to the attacker-controlled eNB, or the attacker sits on the S1-U path	the user plane is the only part of the radio path the attacker needs to touch
2	attacker	observe the GTP-U G-PDU carrying the UE's DNS query: outer IP/UDP 2152, GTP-U header, inner IP/UDP/53, DNS question	the query is in flight and the attacker sees the G-PDU	the TEID and the inner packet are not integrity protected
3	attacker	record the DNS transaction ID and the question section, then let the query reach the real resolver (or answer it directly)	the attacker can forward the G-PDU	the answer has to match the ID and question or the UE discards it
4	attacker	rewrite the inner IP packet's DNS response in place: same ID, same question, replaced answer RR, recomputed IP and UDP checksums and lengths	a response is in flight and the attacker can rewrite before the S-GW forwards it	LTE user-plane PDCP provides confidentiality but NOT integrity (TS 33.401); the UE's PDCP accepts a modified packet
5	attacker	re-encapsulate into GTP-U and forward to the eNB, which re-encrypts and delivers to the UE	the attacker is still on the path	the UE sees a valid DNS answer for a name it asked about
6	attacker	the UE connects to the substituted address	the answer was an A/AAAA the attacker chose	no layer-2 integrity means no way for the UE to detect the rewrite
precondition	the attack requires a layer-2 position on the user plane, which a passive capture cannot reach; it is not a remote attack and it does not work against a network that enforces user-plane integrity (5G does, via the Integrity Protection of User Plane DRBs, TS 33.501)
detection	the rewrite is visible on the wire as an answer whose owner name is not the question name, an ID that does not match the query, a response from an address no query went to, or a DNSSEC validation failure — all of which --detect reports
detection	DNSSEC is the only end-to-end defence: the rewrite breaks RRSIG validation at a validating resolver, which is why the detection half of this module separates a DNSSEC failure from a plain mismatch
EOF
}

# ── plans — status: handoff ─────────────────────────────────────────────
cdns_plan_write() {
    local name="$1" title="$2" needs="$3" body="$4"
    mkdir -p "$CDNS_PLANS" || { printf 'ERROR\tcannot create %s\n' "$CDNS_PLANS" >&2; return 1; }
    local out="$CDNS_PLANS/${name}.plan"
    {
        printf 'status: handoff\n'
        printf 'plan: %s\n' "$title"
        printf 'module: 32_cellular_dns.sh (cdns)\n'
        printf 'requires: %s\n' "$needs"
        printf 'generated: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf '\n'
        printf '%s\n' "$body"
    } > "$out" || { printf 'ERROR\tcould not write %s\n' "$out" >&2; return 1; }
    [[ -s "$out" ]] || { printf 'ERROR\t%s is empty\n' "$out" >&2; return 1; }
    printf '%s' "$out"
}

cdns_plan_alter_lab() {
    local body
    body=$(cat <<'EOF'
# aLTEr lab — LTE layer-2 DNS rewrite (handoff)

## What this is
Rupprecht, Kohls, Holz and Popper, "Breaking LTE on Layer Two", IEEE S&P 2019
(doi 10.1109/SP.2019.00040): LTE user-plane PDCP is encrypted but not
integrity-protected, so an attacker with a layer-2 position rewrites the inner
IP packet of a GTP-U G-PDU in flight. Applied to DNS it redirects any name the
UE resolves. This plan names the hardware, because the vector cannot run from
a capture: it needs a layer-2 position.

## What is already implemented in software
- RFC 1035 encode/decode, including compression pointers, asserted byte-exact
  against the RFC's own www.example.com encoding.
- `--build-query` and `--build-response` produce the exact frames the rewrite
  needs (the response matches the query's ID and question and uses the 0xC00C
  answer-name pointer).
- `--detect` reports the rewrite from a capture: answer/question contradiction,
  ID mismatch, response without a query, resolver address mismatch, TTL
  anomaly, and the DNSSEC signals.
- `--resolver-discovery` reports which resolver the bearer actually used.

## What the handoff needs
1. A test LTE network you own: srsRAN (srsenb + srsue) or OpenAirInterface, with
   a USRP B210 / N210 or a LimeSDR, PLUS a second SDR for the rogue eNB, or an
   S1-U path you can bridge through a Linux host.
2. A rogue eNB build (srsRAN with a modified S1-U path, or the aLTEr authors'
   own setup) able to forward GTP-U while rewriting the inner packet.
3. The UE camped on the rogue eNB with a test SIM, resolving a name you
   control, and a resolver on the test network.
4. A validating resolver with a trust anchor to demonstrate the DNSSEC
   defence, and one without, to demonstrate the plain rewrite.

## Steps
1. Stand up the test EPC and the rogue eNB; camp the test UE on it.
2. Capture on S1-U and confirm a plain DNS exchange with `--detect`.
3. Enable the in-path rewrite: for a response to `probe.test`, replace the
   answer with the attacker address while preserving the ID and question.
   `--build-response <query-hex> <attacker-ip>` gives the exact bytes.
4. Confirm the UE connects to the substituted address.
5. Re-run with a validating resolver and show the rewrite fails DNSSEC
   validation, and that `--detect` reports `dnssec-stripped` or
   `dnssec-bogus-ad` rather than a plain mismatch.

## Safety
A rogue eNB is a transmitter and will attract real UEs if it is on the air.
It must be in a Faraday cage or on a licensed test band with the transmitter
power set so it cannot be reached from outside the lab. Never on a live PLMN.
EOF
)
    cdns_plan_write "alter-lab" "aLTEr LTE layer-2 DNS rewrite on a lab eNB" \
        "a test LTE network (srsRAN or OpenAirInterface) with a USRP B210/N210 or LimeSDR, a second SDR or an S1-U bridge host for the rogue eNB, a test SIM, and a resolver you control (plus one validating resolver for the DNSSEC case)" \
        "$body"
}

cdns_cmd_plan() {
    local which="${1:-}" pf rc
    case "$which" in
        alter-lab) pf=$(cdns_plan_alter_lab); rc=$? ;;
        *)
            printf 'ERROR\tunknown plan: %s (want alter-lab)\n' "$(cdns_sanitize "${which:-<none>}")" >&2
            return 2 ;;
    esac
    [[ "$rc" -eq 0 && -n "$pf" ]] || return "${rc:-1}"
    printf 'plan_file\t%s\n' "$pf"
    printf 'status\thandoff\n'
    printf 'note\t%s\n' "the rewrite needs a layer-2 position; no traffic was sent"
    return 0
}

# ── CLI verbs ───────────────────────────────────────────────────────────
cdns_cli_status_tsv() {
    local plans=0
    [[ -d "$CDNS_PLANS" ]] && plans=$(find "$CDNS_PLANS" -name '*.plan' -type f 2>/dev/null | wc -l)
    printf 'module\tcellular_dns\n'
    printf 'tag\tcdns\n'
    printf 'dir\t%s\n' "$CDNS_DIR"
    printf 'plans_dir\t%s\n' "$CDNS_PLANS"
    printf 'plans\t%s\n' "$plans"
    printf 'python3\t%s\n' "$(command -v python3 >/dev/null 2>&1 && echo yes || echo no)"
    printf 'tshark\t%s\n' "$(command -v tshark >/dev/null 2>&1 && echo yes || echo no)"
    printf 'encap\tEthernet,Linux-SLL,raw-IP,IPv4,IPv6,UDP,GTP-U\n'
    printf 'refs\tRFC 1035, RFC 3596, RFC 2782, RFC 3225, RFC 4035, TS 23.401, TS 24.008, TS 33.401\n'
    printf 'attack_status\thandoff\n'
}

cdns_cmd_decode_dns() {
    local hex="${1:-}"
    [[ -n "$hex" ]] || { printf 'ERROR\tusage: --decode-dns <hex>\n' >&2; return 2; }
    cdns_parse "$hex"
}

cdns_cmd_build_query() {
    local name="${1:-}" type="${2:-A}"
    [[ -n "$name" ]] || { printf 'ERROR\tusage: --build-query <name> [type]\n' >&2; return 2; }
    local hex; hex=$(cdns_build_query "$name" "$type") || return 1
    printf 'message\tDNS query\n'
    printf 'name\t%s\n' "$(cdns_sanitize "$name")"
    printf 'qtype\t%s\n' "$(cdns_sanitize "$type")"
    printf 'octets\t%s\n' "$(( ${#hex} / 2 ))"
    printf 'hex\t%s\n' "$hex"
    printf 'roundtrip_name\t%s\n' "$(cdns_parse "$hex" | awk -F'\t' '$1=="question.0.name"{print $2}')"
}

cdns_cmd_build_response() {
    local qhex="${1:-}" ip="${2:-}"
    [[ -n "$qhex" && -n "$ip" ]] || { printf 'ERROR\tusage: --build-response <query-hex> <answer-ip>\n' >&2; return 2; }
    local hex; hex=$(cdns_build_response "$qhex" "$ip") || return 1
    local p; p=$(cdns_parse "$hex") || { printf 'ERROR\tbuilt response does not parse\n' >&2; return 1; }
    printf 'message\tDNS response (rewritten answer)\n'
    printf 'answer_ip\t%s\n' "$(cdns_sanitize "$ip")"
    printf 'octets\t%s\n' "$(( ${#hex} / 2 ))"
    printf 'hex\t%s\n' "$hex"
    printf 'roundtrip_id\t%s\n' "$(printf '%s\n' "$p" | awk -F'\t' '$1=="id"{print $2}')"
    printf 'roundtrip_qname\t%s\n' "$(printf '%s\n' "$p" | awk -F'\t' '$1=="question.0.name"{print $2}')"
    printf 'roundtrip_qr\t%s\n' "$(printf '%s\n' "$p" | awk -F'\t' '$1=="qr"{print $2}')"
    printf 'roundtrip_answer\t%s\n' "$(printf '%s\n' "$p" | awk -F'\t' '$1=="answer.0.value"{print $2}')"
}

cdns_cmd_resolver_discovery() { cdns_resolver_discovery "${1:-}"; }

# ── selftest — no radio, no root, no network ────────────────────────────
cdns_selftest() {
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
    export CDNS_DIR="$d/loot/cellular_dns"
    export CDNS_PLANS="$CDNS_DIR/plans"
    mkdir -p "$CDNS_PLANS"

    # ── 1. The RFC 1035 encoding vector, byte-exact ─────────────────────
    # RFC 1035 §4.1.1 / §4.1.4 gives the labels for www.example.com as
    # 3www 7example 3com 0 and an A/IN question; the query below is that
    # encoding with ID 0x1234 and RD set.
    local q
    q=$(cdns_build_query www.example.com A 0x1234)
    chk build-query-rfc "$q" "12340100000100000000000003777777076578616D706C6503636F6D0000010001"
    out=$(cdns_parse "$q"); rc=$?
    chk parse-query-rc   "$rc" "0"
    chk parse-query-id   "$(fld "$out" id)" "4660"
    chk parse-query-qr   "$(fld "$out" qr)" "0"
    chk parse-query-op   "$(fld "$out" opcode)" "0"
    chk parse-query-opn  "$(fld "$out" opcode_name)" "QUERY"
    chk parse-query-rd   "$(fld "$out" rd)" "1"
    chk parse-query-ra   "$(fld "$out" ra)" "0"
    chk parse-query-aa   "$(fld "$out" aa)" "0"
    chk parse-query-tc   "$(fld "$out" tc)" "0"
    chk parse-query-rcode "$(fld "$out" rcode)" "0"
    chk parse-query-qd   "$(fld "$out" qdcount)" "1"
    chk parse-query-an   "$(fld "$out" ancount)" "0"
    chk parse-query-name "$(fld "$out" question.0.name)" "www.example.com"
    chk parse-query-type "$(fld "$out" question.0.type)" "1"
    chk parse-query-typn "$(fld "$out" question.0.type_name)" "A"
    chk parse-query-class "$(fld "$out" question.0.class)" "IN"

    # ── 2. Header bit fields, positional not "any bit set" ──────────────
    out=$(cdns_parse "12348180000100010000000003777777076578616D706C6503636F6D0000010001C00C000100010000012C00045DB8D822")
    chk hdr-qr  "$(fld "$out" qr)" "1"
    chk hdr-aa  "$(fld "$out" aa)" "0"
    chk hdr-rd  "$(fld "$out" rd)" "1"
    chk hdr-ra  "$(fld "$out" ra)" "1"
    chk hdr-rc  "$(fld "$out" rcode_name)" "NOERROR"
    # A different flag word must move the bits independently.
    out=$(cdns_parse "12348500000100010000000003777777076578616D706C6503636F6D0000010001C00C000100010000012C00045DB8D822")
    chk hdr-aa2 "$(fld "$out" aa)" "1"
    chk hdr-ra2 "$(fld "$out" ra)" "0"
    out=$(cdns_parse "12348183000100000000000003777777076578616D706C6503636F6D0000010001")
    chk hdr-rcode-nx "$(fld "$out" rcode)" "3"
    chk hdr-rcode-nxn "$(fld "$out" rcode_name)" "NXDOMAIN"

    # ── 3. Compression pointer, byte-exact ──────────────────────────────
    local resp
    resp=$(cdns_build_response "$q" 93.184.216.34 300)
    chk build-resp-hex "$resp" "12348180000100010000000003777777076578616D706C6503636F6D0000010001C00C000100010000012C00045DB8D822"
    out=$(cdns_parse "$resp"); rc=$?
    chk resp-rc        "$rc" "0"
    chk resp-id        "$(fld "$out" id)" "4660"
    chk resp-qr        "$(fld "$out" qr)" "1"
    chk resp-answer-name "$(fld "$out" answer.0.name)" "www.example.com"
    chk resp-answer-type "$(fld "$out" answer.0.type_name)" "A"
    chk resp-answer-ttl  "$(fld "$out" answer.0.ttl)" "300"
    chk resp-answer-value "$(fld "$out" answer.0.value)" "93.184.216.34"
    chk resp-question  "$(fld "$out" question.0.name)" "www.example.com"
    # The ID and question of a built response must be the query's, exactly.
    chk resp-id-matches-query "$(fld "$out" id)" "$(fld "$(cdns_parse "$q")" id)"
    chk resp-q-matches-query  "$(fld "$out" question.0.name)" "$(fld "$(cdns_parse "$q")" question.0.name)"

    # ── 4. AAAA and name round-trips ────────────────────────────────────
    q=$(cdns_build_query example.com AAAA 0xABCD)
    out=$(cdns_parse "$q")
    chk aaaa-type "$(fld "$out" question.0.type)" "28"
    chk aaaa-name "$(fld "$out" question.0.type_name)" "AAAA"
    chk aaaa-id   "$(fld "$out" id)" "43981"
    resp=$(cdns_build_response "$q" 2606:2800:220:1:248:1893:25c8:1946 60)
    out=$(cdns_parse "$resp")
    chk aaaa-answer-type "$(fld "$out" answer.0.type)" "28"
    chk aaaa-answer-len  "$(fld "$out" answer.0.rdlength)" "16"
    chk aaaa-answer-value "$(fld "$out" answer.0.value)" "26062800022000010248189325C81946"
    # A name with a trailing dot is the same name.
    chk trailing-dot "$(cdns_name_encode www.example.com.)" "$(cdns_name_encode www.example.com)"
    # An over-long label must fail, not truncate.
    chk label-oob "$(cdns_name_encode "$(printf 'a%.0s' {1..64}).com" >/dev/null 2>&1; echo $?)" "1"
    chk name-empty "$(cdns_name_encode '' >/dev/null 2>&1; echo $?)" "1"

    # ── 5. Registries, known answers from the RFCs and tshark ───────────
    chk type-1    "$(cdns_type_name 1)" "A"
    chk type-2    "$(cdns_type_name 2)" "NS"
    chk type-5    "$(cdns_type_name 5)" "CNAME"
    chk type-6    "$(cdns_type_name 6)" "SOA"
    chk type-12   "$(cdns_type_name 12)" "PTR"
    chk type-15   "$(cdns_type_name 15)" "MX"
    chk type-16   "$(cdns_type_name 16)" "TXT"
    chk type-28   "$(cdns_type_name 28)" "AAAA"
    chk type-33   "$(cdns_type_name 33)" "SRV"
    chk type-unknown "$(cdns_type_name 999)" "TYPE999"
    chk code-AAAA "$(cdns_type_code AAAA)" "28"
    chk code-srv  "$(cdns_type_code SRV)" "33"
    chk code-bad  "$(cdns_type_code NOPE >/dev/null 2>&1; echo $?)" "1"
    chk rcode-3   "$(cdns_rcode_name 3)" "NXDOMAIN"
    chk rcode-5   "$(cdns_rcode_name 5)" "REFUSED"
    chk opcode-0  "$(cdns_opcode_name 0)" "QUERY"
    chk opcode-5  "$(cdns_opcode_name 5)" "UPDATE"
    chk class-in  "$(cdns_class_name 1)" "IN"
    chk ipv4-rt   "$(cdns_hex_ipv4 "$(cdns_ipv4_hex 10.20.30.40)")" "10.20.30.40"
    chk ipv4-bad  "$(cdns_ipv4_hex 10.20.30.999 >/dev/null 2>&1; echo $?)" "1"

    # ── 6. Detection fires and abstains, both directions ────────────────
    # A clean exchange: query then matching response.
    out=$(printf 'query\t1\t0.1\t10.0.0.2\t40000\t10.99.0.1\t53\t4660\twww.example.com\t1\t0\nresponse\t2\t0.2\t10.99.0.1\t53\t10.0.0.2\t40000\t4660\t0\t0\t1\t0\t0\twww.example.com\t1\twww.example.com:1:93.184.216.34:300\t0\t0\t300\n' | cdns_detect_stream)
    chk detect-clean-total  "$(printf '%s' "$out" | grep -c '^FINDING')" "0"
    chk detect-clean-nocontra "$(printf '%s' "$out" | grep -c 'answer-question-contradiction')" "0"
    # The rewrite: same ID and question, answer owned by another name.
    out=$(printf 'query\t1\t0.1\t10.0.0.2\t40000\t10.99.0.1\t53\t4660\twww.example.com\t1\t0\nresponse\t2\t0.2\t10.99.0.1\t53\t10.0.0.2\t40000\t4660\t0\t0\t1\t0\t0\twww.example.com\t1\tevil.example.net:1:203.0.113.9:300\t0\t0\t300\n' | cdns_detect_stream)
    chk detect-contradiction "$(printf '%s' "$out" | grep -c 'answer-question-contradiction')" "1"
    # ID mismatch: answer for a name that was asked with a different ID.
    out=$(printf 'query\t1\t0.1\t10.0.0.2\t40000\t10.99.0.1\t53\t4660\twww.example.com\t1\t0\nresponse\t2\t0.2\t10.99.0.1\t53\t10.0.0.2\t40000\t9999\t0\t0\t1\t0\t0\twww.example.com\t1\twww.example.com:1:203.0.113.9:300\t0\t0\t300\n' | cdns_detect_stream)
    chk detect-id-mismatch "$(printf '%s' "$out" | grep -c 'id-mismatch')" "1"
    # A response with no query at all.
    out=$(printf 'response\t2\t0.2\t10.99.0.1\t53\t10.0.0.2\t40000\t1\t0\t0\t1\t0\t0\twww.example.com\t1\twww.example.com:1:1.2.3.4:300\t0\t0\t300\n' | cdns_detect_stream)
    chk detect-no-query "$(printf '%s' "$out" | grep -c 'response-without-query')" "1"
    # Question mismatch: the response carries a different question.
    out=$(printf 'query\t1\t0.1\t10.0.0.2\t40000\t10.99.0.1\t53\t4660\twww.example.com\t1\t0\nresponse\t2\t0.2\t10.99.0.1\t53\t10.0.0.2\t40000\t4660\t0\t0\t1\t0\t0\tother.example.com\t1\tother.example.com:1:1.2.3.4:300\t0\t0\t300\n' | cdns_detect_stream)
    chk detect-question-mismatch "$(printf '%s' "$out" | grep -c 'question-mismatch')" "1"
    # TTL anomaly: 300 seen before, then 999999.
    out=$(printf 'query\t1\t0.1\t10.0.0.2\t40000\t10.99.0.1\t53\t4660\twww.example.com\t1\t0\nresponse\t2\t0.2\t10.99.0.1\t53\t10.0.0.2\t40000\t4660\t0\t0\t1\t0\t0\twww.example.com\t1\twww.example.com:1:1.2.3.4:300\t0\t0\t300\nresponse\t3\t0.3\t10.99.0.1\t53\t10.0.0.2\t40000\t4660\t0\t0\t1\t0\t0\twww.example.com\t1\twww.example.com:1:1.2.3.5:999999\t0\t0\t999999\n' | cdns_detect_stream)
    chk detect-ttl "$(printf '%s' "$out" | grep -c 'ttl-anomaly')" "1"
    # DNSSEC: AD with no RRSIG is bogus-ad, NOT a plain mismatch.
    out=$(printf 'query\t1\t0.1\t10.0.0.2\t40000\t10.99.0.1\t53\t4660\tsigned.example.com\t1\t1\nresponse\t2\t0.2\t10.99.0.1\t53\t10.0.0.2\t40000\t4660\t0\t0\t1\t1\t0\tsigned.example.com\t1\tsigned.example.com:1:1.2.3.4:300\t0\t1\t300\n' | cdns_detect_stream)
    chk dnssec-bogus-ad "$(printf '%s' "$out" | grep -c 'dnssec-bogus-ad')" "1"
    chk dnssec-not-contradiction "$(printf '%s' "$out" | grep -c 'answer-question-contradiction')" "0"
    chk dnssec-not-mismatch "$(printf '%s' "$out" | grep -c 'question-mismatch')" "0"
    # DNSSEC stripped: DO set, the name is signed elsewhere, no RRSIG here.
    out=$(printf 'query\t1\t0.1\t10.0.0.2\t40000\t10.99.0.1\t53\t1\tsigned.example.com\t1\t1\nresponse\t2\t0.2\t10.99.0.1\t53\t10.0.0.2\t40000\t1\t0\t0\t1\t0\t0\tsigned.example.com\t1\tsigned.example.com:46:x:300;signed.example.com:1:1.2.3.4:300\t1\t1\t300\nquery\t3\t0.3\t10.0.0.2\t40000\t10.99.0.1\t53\t2\tsigned.example.com\t1\t1\nresponse\t4\t0.4\t10.99.0.1\t53\t10.0.0.2\t40000\t2\t0\t0\t1\t0\t0\tsigned.example.com\t1\tsigned.example.com:1:1.2.3.5:300\t0\t1\t300\n' | cdns_detect_stream)
    chk dnssec-stripped "$(printf '%s' "$out" | grep -c 'dnssec-stripped')" "1"
    chk dnssec-notvalidated "$(printf '%s' "$out" | grep -c 'dnssec-not-validated')" "1"
    # The DNSSEC rules are named distinctly from a plain mismatch.
    chk dnssec-distinct-names "$( [[ 'dnssec-bogus-ad' != 'answer-question-contradiction' && 'dnssec-stripped' != 'question-mismatch' ]] && echo yes || echo no)" "yes"

    # ── 7. PCO walk ─────────────────────────────────────────────────────
    # One container: ID 0001, length 4, value C0A80101.
    out=$(cdns_pco_parse "80000104C0A80101")
    chk pco-proto  "$(fld "$out" config_protocol)" "0"
    chk pco-ext    "$(fld "$out" extension_bit)" "1"
    chk pco-cid    "$(printf '%s\n' "$out" | awk -F'\t' '$1=="container"{print $2}')" "0001"
    chk pco-clen   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="container"{print $3}')" "4"
    chk pco-cval   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="container"{print $4}')" "C0A80101"
    chk pco-cname  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="container"{print $5}')" "P-CSCF address"
    chk pco-trunc  "$(cdns_pco_parse "80000108C0A8" >/dev/null 2>&1; echo $?)" "1"
    chk resolver-class-public "$(cdns_resolver_class 8.8.8.8)" "public-resolver"
    chk resolver-class-op     "$(cdns_resolver_class 10.99.0.1)" "operator-internal"

    # ── 8. pcap path end to end, built here with python3 stdlib ─────────
    local pcap="$d/dns.pcap" pq
    pq=$(cdns_build_query www.example.com A 0x1234)
    if command -v python3 >/dev/null 2>&1; then
        python3 - "$pcap" "$pq" <<'PY'
import struct, sys
path, qhex = sys.argv[1], sys.argv[2]
q = bytes.fromhex(qhex)
# a matching response built by hand: ID 0x1234, QR|RD|RA, 1 question, 1 answer
name = bytes.fromhex('03777777076578616D706C6503636F6D00')
ans = bytes.fromhex('C00C') + struct.pack('>HHIH', 1, 1, 300, 4) + bytes([93,184,216,34])
good = struct.pack('>HHHHHH', 0x1234, 0x8180, 1, 1, 0, 0) + name + struct.pack('>HH', 1, 1) + ans
# a rewritten response: same ID and question, answer owned by evil.example.net
evilname = bytes.fromhex('046576696C076578616D706C65036E657400')
evilans = evilname + struct.pack('>HHIH', 1, 1, 300, 4) + bytes([203,0,113,9])
bad = struct.pack('>HHHHHH', 0x1234, 0x8180, 1, 1, 0, 0) + name + struct.pack('>HH', 1, 1) + evilans

def eth(payload):
    return bytes.fromhex('001122334455') + bytes.fromhex('66778899AABB') + struct.pack('>H', 0x0800) + payload
def ipv4(src, dst, payload):
    total = 20 + len(payload)
    hdr = struct.pack('>BBHHHBBH', 0x45, 0, total, 1, 0, 64, 17, 0) + bytes(src) + bytes(dst)
    return hdr + payload
def udp(sp, dp, payload):
    return struct.pack('>HHHH', sp, dp, 8 + len(payload), 0) + payload
def frame(src, dst, sp, dp, dns):
    return eth(ipv4(src, dst, udp(sp, dp, dns)))
C = [10,0,0,2]; R = [10,99,0,1]
frames = [
    frame(C, R, 40000, 53, q),
    frame(R, C, 53, 40000, good),
    frame(C, R, 40001, 53, q),
    frame(R, C, 53, 40001, bad),
]
with open(path, 'wb') as f:
    f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for i, fr in enumerate(frames):
        f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
        f.write(fr)
PY
        out=$(cdns_cmd_detect "$pcap"); rc=$?
        chk detect-pcap-rc      "$rc" "0"
        chk detect-pcap-queries "$(fld "$out" queries)" "2"
        chk detect-pcap-resps   "$(fld "$out" responses)" "2"
        chk detect-pcap-contra  "$(printf '%s\n' "$out" | grep -c 'answer-question-contradiction')" "1"
        chk detect-pcap-clean   "$(printf '%s\n' "$out" | grep -c '^FINDING')" "1"
        # Resolver discovery must name the resolver the queries went to.
        out=$(cdns_cmd_resolver_discovery "$pcap"); rc=$?
        chk resolver-rc   "$rc" "0"
        chk resolver-ip   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="resolver"{print $2}')" "10.99.0.1"
        chk resolver-cnt  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="resolver"{print $4}')" "2"
        chk resolver-kind "$(printf '%s\n' "$out" | awk -F'\t' '$1=="resolver"{print $5}')" "operator-internal"
        chk extract-pcap-rows "$(cdns_extract_pcap "$pcap" | grep -c '^pkt')" "4"
    else
        printf 'pcap-suite\tSKIP python3 not present\n'
    fi

    # ── 9. Argument validation returns non-zero ─────────────────────────
    chk val-decode-none   "$(cdns_cmd_decode_dns >/dev/null 2>&1; echo $?)" "2"
    chk val-decode-bad    "$(cdns_cmd_decode_dns zzzz >/dev/null 2>&1; echo $?)" "1"
    chk val-decode-short  "$(cdns_cmd_decode_dns 1234 >/dev/null 2>&1; echo $?)" "1"
    chk val-query-none    "$(cdns_cmd_build_query >/dev/null 2>&1; echo $?)" "2"
    chk val-query-badtype "$(cdns_cmd_build_query example.com NOPE >/dev/null 2>&1; echo $?)" "1"
    chk val-resp-none     "$(cdns_cmd_build_response >/dev/null 2>&1; echo $?)" "2"
    chk val-resp-badip    "$(cdns_cmd_build_response "$q" 999.1.1.1 >/dev/null 2>&1; echo $?)" "1"
    chk val-resp-badq     "$(cdns_cmd_build_response zzzz 1.2.3.4 >/dev/null 2>&1; echo $?)" "1"
    chk val-detect-none   "$(cdns_cmd_detect >/dev/null 2>&1; echo $?)" "2"
    chk val-detect-nofile "$(cdns_cmd_detect /nonexistent.pcap >/dev/null 2>&1; echo $?)" "1"
    chk val-resolver-none "$(cdns_cmd_resolver_discovery >/dev/null 2>&1; echo $?)" "2"

    # ── 10. Plan carries status: handoff ────────────────────────────────
    local pf file
    pf=$(cdns_cmd_plan alter-lab); rc=$?
    chk plan-rc     "$rc" "0"
    chk plan-status "$(printf '%s\n' "$pf" | awk -F'\t' '$1=="status"{print $2}')" "handoff"
    file=$(printf '%s\n' "$pf" | awk -F'\t' '$1=="plan_file"{print $2}')
    chk plan-file-status "$(grep -c '^status: handoff' "$file")" "1"
    chk plan-file-layer2 "$(grep -q 'layer-2 position' "$file" && echo yes || echo no)" "yes"
    chk plan-file-hw     "$(grep -q 'USRP' "$file" && echo yes || echo no)" "yes"
    chk plan-unknown     "$(cdns_cmd_plan nope >/dev/null 2>&1; echo $?)" "2"

    # ── 11. Status TSV and sanitisation ─────────────────────────────────
    out=$(cdns_cli_status_tsv)
    chk status-module "$(fld "$out" module)" "cellular_dns"
    chk status-tag    "$(fld "$out" tag)"    "cdns"
    chk status-dir    "$(fld "$out" dir)"    "$CDNS_DIR"
    local evil
    evil=$(cdns_sanitize $'a\tb\nc')
    chk sanitize-tabs "$(printf '%s' "$evil" | tr -cd '\t' | wc -c)" "0"
    chk sanitize-nl   "$(printf '%s' "$evil" | wc -l)" "0"
    CDNS_F=()
    cdns_split $'x\t\ty\tz'
    chk split-len    "${#CDNS_F[@]}" "4"
    chk split-empty  "${CDNS_F[1]}" ""
    chk split-third  "${CDNS_F[2]}" "y"

    rm -rf "$d"
    trap - EXIT
    [[ -n "$_prev_trap" ]] && eval "$_prev_trap"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ── menu ────────────────────────────────────────────────────────────────
cdns_menu() {
    local c h p
    while true; do
        banner
        echo -e "  ${C_MAG}=== Cellular DNS / aLTEr ===${C_RESET}"
        echo -e "  plans: ${C_GRN}$(find "$CDNS_PLANS" -name '*.plan' -type f 2>/dev/null | wc -l)${C_RESET}"
        echo -e "  dir:   ${C_DIM}$CDNS_PLANS${C_RESET}\n"
        cat << 'M'
  [1]  decode a DNS message (hex)
  [2]  build a DNS query
  [3]  build a rewritten DNS response for a query
  [4]  resolver discovery from a pcap
  [5]  detect DNS rewrite / spoofing in a pcap
  [6]  decode a PCO (protocol configuration options)
  [7]  the aLTEr sequence, step by step
  [8]  plan: aLTEr lab
  [9]  status
  [0]  back

M
        read -rp "  choice> " c
        case "$c" in
            1) if [[ -n "${IMSISTING_CLI:-}" ]]; then echo "[-] need hex; cannot prompt in CLI mode" >&2
               else read -rp "  DNS hex> " h; cdns_cmd_decode_dns "$h" | column -t -s$'\t' 2>/dev/null || cdns_cmd_decode_dns "$h"
                    read -rp "  press enter " _; fi ;;
            2) if [[ -n "${IMSISTING_CLI:-}" ]]; then echo "[-] need a name; cannot prompt in CLI mode" >&2
               else read -rp "  name> " p; read -rp "  type [A]> " t
                    cdns_cmd_build_query "$p" "${t:-A}"; read -rp "  press enter " _; fi ;;
            3) if [[ -n "${IMSISTING_CLI:-}" ]]; then echo "[-] need a query; cannot prompt in CLI mode" >&2
               else read -rp "  query hex> " h; read -rp "  answer ip> " p
                    cdns_cmd_build_response "$h" "$p"; read -rp "  press enter " _; fi ;;
            4) if [[ -n "${IMSISTING_CLI:-}" ]]; then echo "[-] need a pcap; cannot prompt in CLI mode" >&2
               else read -rp "  pcap> " p; cdns_cmd_resolver_discovery "$p" | column -t -s$'\t' 2>/dev/null || cdns_cmd_resolver_discovery "$p"
                    read -rp "  press enter " _; fi ;;
            5) if [[ -n "${IMSISTING_CLI:-}" ]]; then echo "[-] need a pcap; cannot prompt in CLI mode" >&2
               else read -rp "  pcap> " p; cdns_cmd_detect "$p" | column -t -s$'\t' 2>/dev/null || cdns_cmd_detect "$p"
                    read -rp "  press enter " _; fi ;;
            6) if [[ -n "${IMSISTING_CLI:-}" ]]; then echo "[-] need hex; cannot prompt in CLI mode" >&2
               else read -rp "  PCO hex> " h; cdns_pco_parse "$h" | column -t -s$'\t' 2>/dev/null; read -rp "  press enter " _; fi ;;
            7) cdns_alter_notes | column -t -s$'\t' 2>/dev/null || cdns_alter_notes
               read -rp "  press enter " _ ;;
            8) cdns_cmd_plan alter-lab; read -rp "  press enter " _ ;;
            9) cdns_cli_status_tsv | column -t -s$'\t' 2>/dev/null || cdns_cli_status_tsv
               read -rp "  press enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ── CLI dispatch ────────────────────────────────────────────────────────
cdns_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)          cdns_cli_status_tsv ;;
        --decode-dns)          cdns_cmd_decode_dns "${1:-}" ;;
        --build-query)         cdns_cmd_build_query "${1:-}" "${2:-A}" ;;
        --build-response)      cdns_cmd_build_response "${1:-}" "${2:-}" ;;
        --resolver-discovery)  cdns_cmd_resolver_discovery "${1:-}" ;;
        --detect)              cdns_cmd_detect "${1:-}" ;;
        --pco)                 cdns_pco_parse "${1:-}" ;;
        --alter)               cdns_alter_notes ;;
        --plan)                cdns_cmd_plan "${1:-}" ;;
        --selftest)            cdns_selftest ;;
        --menu)                cdns_menu ;;
        *)
            cat >&2 <<EOF
Cellular DNS — RFC 1035 codec, resolver discovery, aLTEr detection

Usage: $0 COMMAND
  --status-tsv                    module state as TSV
  --decode-dns <hex>              parse a DNS message, decompressing names
  --build-query <name> [type]     build a DNS query (default type A)
  --build-response <query> <ip>   build a response rewritten for <ip>
  --resolver-discovery <pcap>     which resolver the bearer used, and how
  --detect <pcap>                 report DNS rewrite and spoofing signals
  --pco <hex>                     walk protocol configuration options
  --alter                         the aLTEr sequence, step by step
  --plan alter-lab                write the handed-off lab plan
  --selftest                      verify the codec against RFC 1035 vectors
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
    cdns_cli_main "$@"
fi
