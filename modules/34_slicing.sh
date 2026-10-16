#!/usr/bin/env bash
# Slicing Escape — S-NSSAI codec, slice selection, isolation testing
#                                                                   (tag: slic)
#
# Capability split, per MODULE_CONVENTIONS.md §9:
#
#   * Everything encodable is encoded for real. The S-NSSAI (SST/SD), the NSSAI
#     container, the registration-time selection outcome, and the isolation
#     evaluation over observed N3 transport endpoints are all computed here.
#   * The isolation evaluation is deliberately conservative: an isolation
#     conclusion is only reached when the capture (or an explicit mapping)
#     actually binds slices to transport endpoints. When a needed field is
#     absent the module says "not determinable from this capture" and names
#     the missing field. A false "isolated" is the one answer that must never
#     be produced.
#   * A slice-escape run needs a 5G SA testbed with two slices and a
#     subscription that is authorised for only one of them. That is a
#     `status: handoff` plan naming the testbed.
#
# Reference clause map (values asserted in --selftest are marked):
#   TS 23.003 §28.4.2      S-NSSAI: SST (1 octet) + SD (3 octets); SD
#                          0xFFFFFF means "no SD"
#   TS 23.501 §5.15.2.2    network slicing; Table 5.15.2.2-1 SST values
#   TS 23.501 §5.15.5.2.1  NSSF role in slice selection
#   TS 23.501 §5.15.5.3    S-NSSAI mapping between the HPLMN and the VPLMN
#   TS 24.501 §9.11.3.37   NSSAI / S-NSSAI information elements
#   TS 24.501 §9.11.3.46   rejected NSSAI and its cause values
#   TS 24.501 §8.2.6       Registration procedure (requested -> allowed NSSAI)
#   TS 23.502 §4.2.3       slice-specific authorisation and the NSSF
#   TS 29.244              PFCP: F-TEID, Node ID (for the isolation evidence)
#   TS 38.413              NGAP: PDU Session Resource Setup carries the S-NSSAI
#   GSMA IR.88 / 5G SA     visited-network slice mapping enforcement
#
# Known-answer authorities used by --selftest:
#   * TS 23.003 §28.4.2 for the byte layout, and TS 23.501 Table 5.15.2.2-1
#     for the SST assignments (1 eMBB, 2 URLLC, 3 MIoT, 4 V2X, 5 HMTC).
#   * Wireshark 4.2.2 `tshark`: the 5GS NAS framing used by --selection
#     ([extended protocol discriminator 0x7E][spare half octet | security
#     header type][message type][IEs]) was confirmed by exporting a PDU to the
#     `nas-5gs` dissector (`text2pcap -l 252 -P nas-5gs`); 7E 00 44 16 decodes
#     as Registration reject with 5GMM cause "Congestion (22)" and 7E 00 44 3E
#     as cause "No network slices available (62)", which --selftest asserts.
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

MOD_TMP="$TMP_DIR/slicing"
SLIC_DIR="$LOOT_DIR/slicing"
SLIC_PLANS="$SLIC_DIR/plans"
mkdir -p "$MOD_TMP" "$SLIC_DIR" "$SLIC_PLANS" 2>/dev/null

# ── sanitisation and TSV splitting ──────────────────────────────────────
slic_sanitize() { printf '%s' "${1:-}" | tr '\t\r\n' '   '; }

# Split a TSV line into SLIC_F, preserving empty fields. Parameter expansion,
# never `IFS=$'\t' read` (MODULE_CONVENTIONS §12): a tab is whitespace to
# `read`, so a run of tabs collapses and every later field shifts.
SLIC_F=()
slic_split() {
    SLIC_F=()
    local line="${1:-}"
    while :; do
        if [[ "$line" == *$'\t'* ]]; then
            SLIC_F+=( "${line%%$'\t'*}" )
            line="${line#*$'\t'}"
        else
            SLIC_F+=( "$line" )
            break
        fi
    done
}

slic_byte() { printf '%02X' "$(( ${1:-0} & 0xFF ))"; }
slic_nfc() {
    local s="${1:-}"; s="${s^^}"; s="${s//[[:space:]]/}"; s="${s//:/}"; s="${s//-/}"
    printf '%s' "$s"
}
slic_is_hex() { [[ "${1:-}" =~ ^[0-9A-Fa-f]+$ ]] && (( ${#1} % 2 == 0 )); }

# ── SST table — TS 23.501 Table 5.15.2.2-1 ──────────────────────────────
# SST 0 is not assigned in the table; 1..5 are the standardised service types.
# An unknown SST is reported as unknown and is NEVER folded onto eMBB: a
# report that silently maps an unassigned value to eMBB would hide exactly the
# case an operator-specific slice is being used without authorisation.
slic_sst_name() {
    case "${1:-}" in
        1) echo "eMBB (enhanced Mobile Broadband)" ;;
        2) echo "URLLC (ultra-Reliable Low-Latency Communications)" ;;
        3) echo "MIoT (massive IoT / mMTC)" ;;
        4) echo "V2X (Vehicle-to-Everything)" ;;
        5) echo "HMTC (High-Performance Machine-Type Communications)" ;;
        *) echo "unknown" ;;
    esac
}

slic_sst_known() { [[ "$(slic_sst_name "${1:-}")" != "unknown" ]]; }

slic_sst_table() {
    cat <<'EOF'
sst	name	standard	source
1	eMBB (enhanced Mobile Broadband)	3GPP	TS 23.501 Table 5.15.2.2-1
2	URLLC (ultra-Reliable Low-Latency Communications)	3GPP	TS 23.501 Table 5.15.2.2-1
3	MIoT (massive IoT / mMTC)	3GPP	TS 23.501 Table 5.15.2.2-1
4	V2X (Vehicle-to-Everything)	3GPP	TS 23.501 Table 5.15.2.2-1
5	HMTC (High-Performance Machine-Type Communications)	3GPP	TS 23.501 Table 5.15.2.2-1
128-255	operator-specific	operator	TS 23.501 5.15.2.2: SST values 128-255 are operator-specific
note	0 is not assigned by the table; an unassigned value is reported as unknown and never mapped to eMBB		
EOF
}

# ── S-NSSAI codec — TS 23.003 §28.4.2 ───────────────────────────────────
# S-NSSAI = SST (1 octet) + SD (3 octets). The SD is 0xFFFFFF when the slice
# has no differentiator, and the "no SD" form is transmitted as SST only.
slic_encode_s_nssai() {
    local sst="${1:-}" sd="${2:-}"
    [[ "$sst" =~ ^[0-9]+$ ]] && (( sst <= 255 )) || {
        printf 'ERROR\tSST must be 1-3 decimal digits (0-255)\n' >&2; return 1; }
    case "${sd,,}" in
        ""|none|ffffff|no-sd|nosd) sd="FFFFFF" ;;
        *) sd=$(slic_nfc "$sd")
           [[ "$sd" =~ ^[0-9A-Fa-f]{6}$ ]] || {
               printf 'ERROR\tSD must be 3 octets of hex (e.g. 000001) or "none"\n' >&2; return 1; } ;;
    esac
    printf '%s%s' "$(slic_byte "$sst")" "${sd^^}"
}

slic_decode_s_nssai() {
    local hex; hex=$(slic_nfc "${1:-}")
    slic_is_hex "$hex" || { printf 'ERROR\tS-NSSAI needs hex\n' >&2; return 1; }
    local n=$(( ${#hex} / 2 ))
    case "$n" in
        1)  printf 's_nssai\t%s\n' "$hex"
            printf 'length\t1\n'
            printf 'sst\t%s\n' "$(( 16#$hex ))"
            printf 'sst_name\t%s\n' "$(slic_sst_name $(( 16#$hex )))"
            printf 'sd\tffffff\n'
            printf 'sd_present\t0\n'
            printf 'note\t%s\n' "SST only: the slice has no slice differentiator on the wire (TS 24.501 9.11.3.37)"
            return 0 ;;
        4)  local sst=$(( 16#${hex:0:2} )) sd="${hex:2:6}"
            printf 's_nssai\t%s\n' "$hex"
            printf 'length\t4\n'
            printf 'sst\t%s\n' "$sst"
            printf 'sst_name\t%s\n' "$(slic_sst_name "$sst")"
            printf 'sst_known\t%s\n' "$(slic_sst_known "$sst" && echo yes || echo no)"
            printf 'sd\t%s\n' "${sd,,}"
            printf 'sd_present\t%s\n' "$([[ "${sd^^}" == "FFFFFF" ]] && echo 0 || echo 1)"
            printf 'sd_decimal\t%s\n' "$(( 16#$sd ))"
            return 0 ;;
        *)  printf 'ERROR\tS-NSSAI is 1 octet (SST) or 4 octets (SST+SD); got %s octets\n' "$n" >&2
            return 1 ;;
    esac
}

# ── NSSAI container — TS 24.501 §9.11.3.37 ──────────────────────────────
# An NSSAI is a sequence of S-NSSAIs, each itself length-prefixed:
#   [len=1][SST] | [len=4][SST][SD][SD][SD] ...
# A full NSSAI IE prepends an IEI octet and a length octet. slic_nssai_parse
# accepts either the container value or the full IE (it detects the leading
# IEI by checking whether the first octet matches the remaining length).
slic_nssai_parse() {
    local hex; hex=$(slic_nfc "${1:-}")
    [[ -n "$hex" ]] || { printf 'ERROR\tusage: --nssai-parse <hex>\n' >&2; return 2; }
    slic_is_hex "$hex" && (( ${#hex} >= 4 )) || { printf 'ERROR\tNSSAI needs hex (a container value or a full IE)\n' >&2; return 1; }
    local off=0 iei=""
    # Full-IE form: [IEI][len][content...]. If the length fits the remainder
    # exactly and the first octet is not itself a plausible S-NSSAI length
    # header that consumes the whole thing, treat it as an IE.
    local first=$(( 16#${hex:0:2} ))
    local len2=$(( 16#${hex:2:2} ))
    if (( (off + 2 + len2) * 2 == ${#hex} )) && (( first != 1 && first != 4 )); then
        iei=$(slic_byte "$first")
        off=2
        printf 'iei\t%s\n' "$iei"
    fi
    printf 'container\t%s\n' "${hex:$((off*2))}"
    printf 'header\ts_nssai\tsst\tsst_name\tsd\tsd_present\n'
    local idx=0
    while (( off * 2 < ${#hex} )); do
        (( ${#hex} >= (off + 1) * 2 )) || { printf 'ERROR\tNSSAI is truncated at S-NSSAI %s\n' "$idx" >&2; return 1; }
        local l=$(( 16#${hex:$((off*2)):2} ))
        (( l == 1 || l == 4 )) || {
            printf 'ERROR\tS-NSSAI %s declares length %s; TS 24.501 allows 1 or 4\n' "$idx" "$l" >&2; return 1; }
        (( ${#hex} >= (off + 1 + l) * 2 )) || {
            printf 'ERROR\tS-NSSAI %s is truncated\n' "$idx" >&2; return 1; }
        local v="${hex:$(((off+1)*2)):$((l*2))}"
        local sst=$(( 16#${v:0:2} ))
        local sd="ffffff" present=0
        if (( l == 4 )); then sd="${v:2:6}"; [[ "${sd^^}" == "FFFFFF" ]] || present=1; fi
        printf 'entry\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$idx" "$v" "$sst" "$(slic_sanitize "$(slic_sst_name "$sst")")" "${sd,,}" "$present"
        idx=$(( idx + 1 ))
        off=$(( off + 1 + l ))
    done
    printf 'count\t%s\n' "$idx"
    return 0
}

# ── slice selection ─────────────────────────────────────────────────────
# slic_selection <requested-nssai> [allowed-nssai] [rejected-nssai]
#
# The outcome classes are the ones that matter for security:
#   allowed            requested and in the allowed NSSAI
#   rejected           requested and in the rejected NSSAI (with its cause)
#   dropped            requested, neither allowed nor rejected — silently
#                      discarded, which is the case an operator cannot see
#   unrequested-allowed  in the allowed NSSAI but never requested: the network
#                      granted a slice the UE did not ask for, which is the
#                      "honoured without authorisation" class
# With only the requested NSSAI the outcome is not determinable; the function
# says so rather than assuming.
slic_selection() {
    local req="${1:-}" allow="${2:-}" rej="${3:-}"
    [[ -n "$req" ]] || { printf 'ERROR\tusage: --selection <requested-nssai-hex> [allowed-hex] [rejected-hex]\n' >&2; return 2; }
    local rp; rp=$(slic_nssai_parse "$req") || return 1
    local -a req_list=()
    local line
    while IFS= read -r line; do
        slic_split "$line"
        [[ "${SLIC_F[0]:-}" == "entry" ]] && req_list+=( "${SLIC_F[2]}" )
    done <<<"$rp"
    printf 'requested_count\t%s\n' "${#req_list[@]}"
    printf 'header\tclass\ts_nssai\tsst\tsst_name\tsd\tsd_present\tdetail\n'
    if [[ -z "$allow" && -z "$rej" ]]; then
        local v idx=0
        for v in "${req_list[@]}"; do
            local sst=$(( 16#${v:0:2} ))
            local sd="ffffff" present=0
            (( ${#v} == 8 )) && { sd="${v:2:6}"; [[ "${sd^^}" == "FFFFFF" ]] || present=1; }
            printf 'selection\trequested\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                "$v" "$sst" "$(slic_sanitize "$(slic_sst_name "$sst")")" "${sd,,}" "$present" \
                "outcome not determinable from this input: no allowed or rejected NSSAI supplied"
            idx=$(( idx + 1 ))
        done
        printf 'outcome\tnot-determinable\n'
        printf 'missing\t%s\n' "the allowed NSSAI (and the rejected NSSAI with its cause) from the Registration Accept"
        return 0
    fi
    local -A allow_set rej_set rej_cause
    local ap rjp
    if [[ -n "$allow" ]]; then
        ap=$(slic_nssai_parse "$allow") || return 1
        while IFS= read -r line; do
            slic_split "$line"
            [[ "${SLIC_F[0]:-}" == "entry" ]] && allow_set["${SLIC_F[2]}"]=1
        done <<<"$ap"
    fi
    if [[ -n "$rej" ]]; then
        rjp=$(slic_nssai_parse "$rej") || return 1
        while IFS= read -r line; do
            slic_split "$line"
            [[ "${SLIC_F[0]:-}" == "entry" ]] && rej_set["${SLIC_F[2]}"]=1
        done <<<"$rjp"
    fi
    local v sst sd present nallow=0 nrej=0 ndrop=0 nbad=0
    for v in "${req_list[@]}"; do
        sst=$(( 16#${v:0:2} )); sd="ffffff"; present=0
        (( ${#v} == 8 )) && { sd="${v:2:6}"; [[ "${sd^^}" == "FFFFFF" ]] || present=1; }
        if [[ -n "${allow_set[$v]:-}" ]]; then
            nallow=$(( nallow + 1 ))
            printf 'selection\tallowed\t%s\t%s\t%s\t%s\t%s\t%s\n' "$v" "$sst" \
                "$(slic_sanitize "$(slic_sst_name "$sst")")" "${sd,,}" "$present" "granted"
        elif [[ -n "${rej_set[$v]:-}" ]]; then
            nrej=$(( nrej + 1 ))
            printf 'selection\trejected\t%s\t%s\t%s\t%s\t%s\t%s\n' "$v" "$sst" \
                "$(slic_sanitize "$(slic_sst_name "$sst")")" "${sd,,}" "$present" "rejected NSSAI"
        else
            ndrop=$(( ndrop + 1 ))
            printf 'selection\tdropped\t%s\t%s\t%s\t%s\t%s\t%s\n' "$v" "$sst" \
                "$(slic_sanitize "$(slic_sst_name "$sst")")" "${sd,,}" "$present" \
                "neither allowed nor rejected: the UE has no signal about why"
        fi
    done
    # Allowed but never requested: the grant the UE did not ask for.
    local k
    for k in "${!allow_set[@]}"; do
        local found=0 r
        for r in "${req_list[@]}"; do [[ "$r" == "$k" ]] && found=1; done
        (( found )) && continue
        nbad=$(( nbad + 1 ))
        sst=$(( 16#${k:0:2} )); sd="ffffff"; present=0
        (( ${#k} == 8 )) && { sd="${k:2:6}"; [[ "${sd^^}" == "FFFFFF" ]] || present=1; }
        printf 'selection\tunrequested-allowed\t%s\t%s\t%s\t%s\t%s\t%s\n' "$k" "$sst" \
            "$(slic_sanitize "$(slic_sst_name "$sst")")" "${sd,,}" "$present" \
            "the allowed NSSAI grants a slice the UE never requested"
    done
    printf 'outcome\t%s\n' "$([[ $nbad -gt 0 || $ndrop -gt 0 ]] && echo anomalous || echo consistent)"
    printf 'allowed\t%s\n' "$nallow"
    printf 'rejected\t%s\n' "$nrej"
    printf 'dropped\t%s\n' "$ndrop"
    printf 'unrequested_allowed\t%s\n' "$nbad"
    if (( nbad > 0 )); then
        printf 'finding\tHIGH\tunrequested-allowed-slice\tthe network granted a slice outside the requested set\n'
    fi
    if (( ndrop > 0 )); then
        printf 'finding\tMEDIUM\tsilently-dropped-request\ta requested slice was neither allowed nor rejected\n'
    fi
    return 0
}

# ── 5GS NAS slice extraction (for --selection on a captured PDU) ────────
# 5GS plain NAS framing (verified with Wireshark 4.2.2 via
# `text2pcap -l 252 -P nas-5gs`): octet 1 extended protocol discriminator
# (0x7E for 5GMM), octet 2 spare half octet | security header type, octet 3
# message type, then the information elements.
slic_nas_5gs_type() {
    local hex; hex=$(slic_nfc "${1:-}")
    slic_is_hex "$hex" && (( ${#hex} >= 6 )) || return 1
    [[ "${hex:0:2}" == "7E" ]] || return 1
    printf '%d' "$(( 16#${hex:4:2} ))"
}

slic_nas_5gs_message_name() {
    case "${1:-}" in
        65) echo "Registration request" ;;
        66) echo "Registration accept" ;;
        67) echo "Registration complete" ;;
        68) echo "Registration reject" ;;
        76) echo "Service request" ;;
        77) echo "Service reject" ;;
        78) echo "Service accept" ;;
        193) echo "PDU session establishment request" ;;
        194) echo "PDU session establishment accept" ;;
        195) echo "PDU session establishment reject" ;;
        *) echo "unknown" ;;
    esac
}

# The 5GMM cause of a Registration reject / Service reject, which is the octet
# immediately after the 3-octet 5GS plain-NAS header. Verified: 7E 00 44 16 is
# "Congestion (22)" and 7E 00 44 3E is "No network slices available (62)".
slic_nas_5gs_cause() {
    local hex; hex=$(slic_nfc "${1:-}")
    local t; t=$(slic_nas_5gs_type "$hex") || return 1
    case "$t" in
        68|77) (( ${#hex} >= 8 )) && printf '%d' "$(( 16#${hex:6:2} ))" ;;
        *) printf '' ;;
    esac
}

slic_5gmm_cause_name() {
    case "${1:-}" in
        22)  echo "Congestion" ;;
        62)  echo "No network slices available" ;;
        65)  echo "Maximum number of PDU sessions reached" ;;
        67)  echo "Insufficient resources for specific slice and DNN" ;;
        69)  echo "Insufficient resources for specific slice" ;;
        73)  echo "Serving network not authorized" ;;
        91)  echo "DNN not supported or not subscribed in the slice" ;;
        92)  echo "Insufficient user-plane resources for the PDU session" ;;
        *)   echo "unknown" ;;
    esac
}

# ── isolation evidence ──────────────────────────────────────────────────
# A pcap alone can show the N3 transport (GTP-U endpoints and TEIDs) but not
# which slice a TEID belongs to: the S-NSSAI lives in the NAS/NGAP signalling.
# The module therefore accepts an explicit slice->TEID mapping and compares:
#   * dedicated UPF      distinct N3 endpoints per slice
#   * shared-transport   different S-NSSAIs on the same N3 endpoint
#   * shared-upf-shared-teid-space  same endpoint AND overlapping TEIDs
# Anything it cannot establish is reported as not-determinable.
slic_pcap_py() {
    cat <<'PYEOF'
import sys, struct

def _u16(b, o, e): return struct.unpack_from(e + 'H', b, o)[0]
def _u32(b, o, e): return struct.unpack_from(e + 'I', b, o)[0]

def classic(data):
    magic = data[:4]
    if magic in (b'\xa1\xb2\xc3\xd4', b'\xa1\xb2\x3c\x4d'): e = '>'
    elif magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1'): e = '<'
    else: return None, None
    if len(data) < 24: return None, None
    lt = _u32(data, 20, e); off, out = 24, []
    while off + 16 <= len(data):
        ts, tus, incl, orig = struct.unpack_from(e + 'IIII', data, off)
        off += 16
        if incl > len(data) - off: break
        out.append((data[off:off + incl],))
        off += incl
    return lt, out

def pcapng(data):
    off, e, seen, lts, out = 0, '<', False, [], []
    while off + 12 <= len(data):
        probe = struct.unpack_from('<I', data, off)[0]
        if probe == 0x0A0D0D0A or (not seen and data[off:off + 4] == b'\x0a\x0d\x0d\x0a'):
            bom = struct.unpack_from('<I', data, off + 8)[0]
            e = '<' if bom == 0x1A2B3C4D else '>'; seen = True
        btype = _u32(data, off, e); blen = _u32(data, off + 4, e)
        if blen < 12 or off + blen > len(data): break
        body = data[off + 8:off + blen - 4]
        if btype == 1: lts.append(_u16(body, 0, e))
        elif btype == 6:
            iface = _u32(body, 0, e); cap = _u32(body, 12, e)
            out.append(((lts[iface] if iface < len(lts) else 1), body[20:20 + cap]))
        elif btype == 3:
            orig = _u32(body, 0, e); out.append(((lts[0] if lts else 1), body[4:4 + orig]))
        off += blen
    return out

def ipv4(t):
    if len(t) < 20: return None
    ihl = (t[0] & 0x0F) * 4
    if ihl < 20 or len(t) < ihl: return None
    if struct.unpack_from('>H', t, 6)[0] & 0x1FFF: return None
    return t[9], '.'.join(str(x) for x in t[12:16]), '.'.join(str(x) for x in t[16:20]), t[ihl:]

def l3(t, lt):
    if lt == 1:
        if len(t) < 14: return None
        et = struct.unpack_from('>H', t, 12)[0]; off = 14
        while et in (0x8100, 0x88A8) and len(t) >= off + 4:
            et = struct.unpack_from('>H', t, off + 2)[0]; off += 4
        return ipv4(t[off:]) if et == 0x0800 else None
    if lt in (101, 12, 14, 228): return ipv4(t)
    if lt == 113: return ipv4(t[16:]) if len(t) >= 16 and _u16(t, 14, '>') == 0x0800 else None
    if lt == 276: return ipv4(t[20:]) if len(t) >= 20 and _u16(t, 0, '>') == 0x0800 else None
    return None

def pfcp_ies(hexs):
    # TS 29.244: IE = type (2) + length (2) + value, 4-octet aligned.
    out, b, off = [], bytes.fromhex(hexs), 0
    while off + 4 <= len(b):
        t = struct.unpack_from('>H', b, off)[0]
        ln = struct.unpack_from('>H', b, off + 2)[0]
        if off + 4 + ln > len(b): break
        out.append((t, b[off + 4:off + 4 + ln]))
        off += 4 + ln + ((4 - ln % 4) % 4)
    return out

def main():
    path = sys.argv[1]
    with open(path, 'rb') as f: data = f.read()
    lt, pkts = classic(data)
    if lt is not None:
        frames = [(1, p[0]) for p in pkts]
    else:
        frames = [(lt2, p) for lt2, p in pcapng(data)]
    for linktype, pkt in frames:
        parsed = l3(pkt, linktype)
        if not parsed: continue
        proto, src, dst, payload = parsed
        if proto != 17 or len(payload) < 8: continue
        sp, dp = struct.unpack_from('>HH', payload, 0)
        up = payload[8:]
        if 2152 in (sp, dp) and len(up) >= 8:
            flags = up[0]
            if (flags >> 5) & 0x07 == 1:
                teid = struct.unpack_from('>I', up, 4)[0]
                print('gtpu\t%s\t%s\t%d' % (src, dst, teid))
        elif 8805 in (sp, dp) and len(up) >= 8:
            mtype = up[1]
            body = up[4:]
            nodeid = ''
            fteid = ''
            for t, v in pfcp_ies(body.hex()):
                if t == 60 and len(v) >= 5:   # Node ID (IPv4)
                    nodeid = '.'.join(str(x) for x in v[1:5])
                elif t == 21 and len(v) >= 9: # F-TEID
                    fteid = str(struct.unpack_from('>I', v, 1)[0])
            if nodeid or fteid:
                print('pfcp\t%s\t%s\t%d\t%s\t%s' % (src, dst, mtype, nodeid or '-', fteid or '-'))
    return 0

sys.exit(main())
PYEOF
}

slic_gtpu_flows() {
    local pcap="${1:-}"
    [[ -r "$pcap" ]] || { printf 'ERROR\tcannot read capture: %s\n' "$(slic_sanitize "$pcap")" >&2; return 1; }
    command -v python3 >/dev/null 2>&1 || { printf 'MISSING\tpython3 is required to read a capture\n' >&2; return 1; }
    python3 <(slic_pcap_py) "$pcap"
}

# slic_isolation_check <pcap> [slice=teid[,teid];slice=teid...]
#
# Without a slice->TEID mapping the capture cannot bind a slice to transport,
# and the answer is "not-determinable" naming the missing binding. With a
# mapping, the transport endpoints per slice are compared.
slic_isolation_check() {
    local pcap="${1:-}" map="${2:-}"
    [[ -n "$pcap" ]] || { printf 'ERROR\tusage: --isolation-check <pcap> [slice=teid[,teid];...]\n' >&2; return 2; }
    local obs; obs=$(slic_gtpu_flows "$pcap") || return 1
    local gtpu_lines pfcp_lines
    gtpu_lines=$(printf '%s\n' "$obs" | awk -F'\t' '$1=="gtpu"')
    pfcp_lines=$(printf '%s\n' "$obs" | awk -F'\t' '$1=="pfcp"')
    printf 'capture\t%s\n' "$(slic_sanitize "$pcap")"
    printf 'gtpu_flows\t%s\n' "$(printf '%s\n' "$gtpu_lines" | grep -c .)"
    printf 'pfcp_messages\t%s\n' "$(printf '%s\n' "$pfcp_lines" | grep -c .)"
    printf 'header\tobservation\tsrc\tdst\tdetail\n'
    local line
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        slic_split "$line"
        [[ "${SLIC_F[0]:-}" == "gtpu" ]] && printf 'gtpu\tflow\t%s\t%s\tteid=%s\n' \
            "$(slic_sanitize "${SLIC_F[1]}")" "$(slic_sanitize "${SLIC_F[2]}")" "$(slic_sanitize "${SLIC_F[3]}")"
    done <<<"$gtpu_lines"
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        slic_split "$line"
        [[ "${SLIC_F[0]:-}" == "pfcp" ]] && printf 'pfcp\tmessage\t%s\t%s\ttype=%s node=%s f-teid=%s\n' \
            "$(slic_sanitize "${SLIC_F[1]}")" "$(slic_sanitize "${SLIC_F[2]}")" \
            "$(slic_sanitize "${SLIC_F[3]}")" "$(slic_sanitize "${SLIC_F[4]}")" "$(slic_sanitize "${SLIC_F[5]}")"
    done <<<"$pfcp_lines"

    if [[ -z "$map" ]]; then
        printf 'isolation\tnot-determinable\n'
        printf 'missing\t%s\n' "the S-NSSAI to TEID/N3 binding, which lives in the NAS/NGAP signalling, and a cross-slice reachability observation (a pcap cannot show whether slice A's user plane can reach slice B's service)"
        printf 'finding\tINFO\tnot-determinable-from-capture\tthe capture shows the transport but not which slice owns it; supply slice=teid[,...];... to evaluate\n'
        return 0
    fi

    # Parse the mapping: "slice=teid[,teid];slice=teid"
    local -A slice_teids slice_endpoints
    local part
    local IFS=';'
    for part in $map; do
        local name="${part%%=*}" teids="${part#*=}"
        [[ "$name" != "$part" && -n "$teids" ]] || {
            printf 'ERROR\tslice map entries must be slice=teid[,teid]; got "%s"\n' "$(slic_sanitize "$part")" >&2
            unset IFS; return 2; }
        local t
        local IFS=','
        for t in $teids; do
            [[ "$t" =~ ^[0-9]+$ ]] || { printf 'ERROR\tTEID must be decimal: "%s"\n' "$(slic_sanitize "$t")" >&2; unset IFS; return 2; }
            slice_teids["$name"]+="${slice_teids[$name]:+,}${t}"
            local ep
            ep=$(printf '%s\n' "$gtpu_lines" | awk -F'\t' -v t="$t" '$3==t || $4==t {print $2"->"$3; exit}')
            [[ -n "$ep" ]] && slice_endpoints["$name"]+="${slice_endpoints[$name]:+,}${ep}"
        done
        unset IFS
    done
    unset IFS

    local -a names=()
    local k
    for k in "${!slice_teids[@]}"; do names+=( "$k" ); done
    if (( ${#names[@]} < 2 )); then
        printf 'isolation\tnot-determinable\n'
        printf 'missing\t%s\n' "fewer than two slices were mapped; cross-slice isolation needs at least two"
        return 0
    fi
    printf 'header2\tslice\tslice\tevaluated\tshared_endpoints\n'
    local i j a b ea eb shared
    for (( i = 0; i < ${#names[@]}; i++ )); do
        for (( j = i + 1; j < ${#names[@]}; j++ )); do
            a="${names[$i]}"; b="${names[$j]}"
            ea="${slice_endpoints[$a]:-}"; eb="${slice_endpoints[$b]:-}"
            if [[ -z "$ea" || -z "$eb" ]]; then
                printf 'pair\t%s\t%s\tnot-determinable\tno observed GTP-U flow for the mapped TEID(s)\n' \
                    "$(slic_sanitize "$a")" "$(slic_sanitize "$b")"
                continue
            fi
            shared=""
            local e
            local IFS=','
            for e in $ea; do
                local f
                for f in $eb; do [[ "$e" == "$f" ]] && shared="$e"; done
            done
            unset IFS
            if [[ -n "$shared" ]]; then
                printf 'pair\t%s\t%s\tshared-transport\t%s\n' \
                    "$(slic_sanitize "$a")" "$(slic_sanitize "$b")" "$(slic_sanitize "$shared")"
                printf 'finding\tHIGH\tslice-isolation-failure\tslices %s and %s share the N3 endpoint %s, so any transport-level enforcement of the slice boundary is absent\n' \
                    "$(slic_sanitize "$a")" "$(slic_sanitize "$b")" "$(slic_sanitize "$shared")"
            else
                printf 'pair\t%s\t%s\tdistinct-transport\t%s vs %s\n' \
                    "$(slic_sanitize "$a")" "$(slic_sanitize "$b")" "$(slic_sanitize "$ea")" "$(slic_sanitize "$eb")"
            fi
        done
    done
    printf 'isolation\t%s\n' "distinct-transport-is-not-isolation: different N3 endpoints are necessary but not sufficient; a user-plane reachability test between the slices is still required"
    return 0
}

# ── detection rules for slice events ────────────────────────────────────
# Row: event frame ts ue slice kind cause
#   kind = register | session-establish | session-modify | reject
slic_detect_stream() {
    local line
    local -A seen_slice_by_ue last_slice_by_ue
    local n=0
    local frame ts ue slice kind cause
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        slic_split "$line"
        [[ "${SLIC_F[0]:-}" == "event" ]] || continue
        n=$(( n + 1 ))
        frame="${SLIC_F[1]:-}"; ts="${SLIC_F[2]:-}"; ue="${SLIC_F[3]:-}"
        slice="${SLIC_F[4]:-}"; kind="${SLIC_F[5]:-}"; cause="${SLIC_F[6]:-}"
        # 1. an unexpected S-NSSAI in a session establishment: a slice this UE
        #    has never registered on.
        if [[ "$kind" == "session-establish" ]]; then
            if [[ -n "${last_slice_by_ue[$ue]:-}" && "${last_slice_by_ue[$ue]}" != "$slice" ]]; then
                printf 'FINDING\tHIGH\tslice-change-mid-session\t%s\tue %s established a session on %s while its registration slice was %s\n' \
                    "$(slic_sanitize "$frame")" "$(slic_sanitize "$ue")" "$(slic_sanitize "$slice")" "$(slic_sanitize "${last_slice_by_ue[$ue]}")"
            fi
            if [[ -z "${seen_slice_by_ue[$ue|$slice]:-}" ]]; then
                printf 'FINDING\tMEDIUM\tunexpected-s-nssai-in-session\t%s\tue %s requested a session on %s with no prior registration on it\n' \
                    "$(slic_sanitize "$frame")" "$(slic_sanitize "$ue")" "$(slic_sanitize "$slice")"
            fi
        fi
        if [[ "$kind" == "register" ]]; then
            seen_slice_by_ue["$ue|$slice"]=1
            last_slice_by_ue["$ue"]="$slice"
        fi
        if [[ "$kind" == "reject" && -n "$cause" ]]; then
            # A rejection cause tells an observer which slices the
            # subscription has and which the network will not serve.
            case "$cause" in
                62|69|91|67)
                    printf 'FINDING\tMEDIUM\trejection-cause-reveals-slice-config\t%s\tue %s got cause %s (%s), which names the slice configuration\n' \
                        "$(slic_sanitize "$frame")" "$(slic_sanitize "$ue")" "$(slic_sanitize "$cause")" \
                        "$(slic_sanitize "$(slic_5gmm_cause_name "$cause")")" ;;
            esac
        fi
    done
    (( n > 0 )) || { printf 'ERROR\tno slice events to inspect\n' >&2; return 1; }
    return 0
}

slic_cmd_detect() {
    local file="${1:-}"
    [[ -n "$file" ]] || { printf 'ERROR\tusage: --detect <slice-events.tsv>\n' >&2; return 2; }
    [[ -r "$file" ]] || { printf 'ERROR\tcannot read %s\n' "$(slic_sanitize "$file")" >&2; return 1; }
    printf 'input\t%s\n' "$(slic_sanitize "$file")"
    printf 'header\tseverity\trule\tframe\tdetail\n'
    slic_detect_stream < "$file"
}

# ── attack surface and vulnerability classes ────────────────────────────
slic_surface_notes() {
    cat <<'EOF'
class	mechanism	precondition	impact	note
slice-honoured-without-authorisation	a requested S-NSSAI that the subscription does not include is granted anyway	the NSSF/AMF does not check the requested S-NSSAI against the UE's subscribed S-NSSAIs	the UE reaches a slice it is not entitled to	the requested NSSAI is UE-controlled; the allowed NSSAI must be derived from the subscription, not echoed back
no-subscription-slice	a slice the subscriber has no subscription for, reached via a PDU session with that S-NSSAI	no per-slice authorisation at session establishment	unauthorised service access	TS 23.501 5.15.5.2.1 places the check at the AMF/NSSF; a PDU session that reaches a slice the UE is not subscribed to means the check is absent
shared-upf-no-vrf	isolation is signalled (distinct S-NSSAI) but the UPF is shared without a VRF or a network-instance separation	one UPF instance serving several slices	cross-slice reachability and traffic mixing	the slice boundary is then a label, not a boundary: the S-NSSAI exists in the signalling and nowhere in the forwarding path
roaming-mapping-not-enforced	the visited network maps the UE's S-NSSAI to a VPLMN value and the mapping is not enforced	roaming with a slice that the VPLMN maps	the UE reaches a VPLMN slice it should not, or the wrong slice	isolation must hold for the mapped S-NSSAI, not just the HPLMN one (TS 23.501 5.15.5.3)
slice-id-enumeration	distinct rejection causes reveal which slices exist and which are refused	rejections carry specific causes to an unauthorised UE	slice inventory from outside	cause 62 (no network slices available), 69 (insufficient resources for specific slice), 91 (DNN not supported in the slice) discriminate the configuration
nssf-bypass	signalling a requested NSSAI after registration, or a modified requested NSSAI in a new registration, hoping the NSSF is only consulted once	the AMF does not re-run slice selection	slice change without re-authorisation	the requested NSSAI is an input to selection, never a grant; a slice change must go back through the NSSF
n2-n3-signalled-not-enforced	the S-NSSAI appears in NGAP and NAS but not in the N3 encapsulation	no per-slice network instance at the N3 boundary	a misconfigured UPF routes across slices	check whether the N3 endpoint is per-slice or shared; the S-NSSAI has no place in the GTP-U header, so enforcement must be at the UPF network instance
EOF
}

# ── plans — status: handoff ─────────────────────────────────────────────
slic_plan_write() {
    local name="$1" title="$2" needs="$3" body="$4"
    mkdir -p "$SLIC_PLANS" || { printf 'ERROR\tcannot create %s\n' "$SLIC_PLANS" >&2; return 1; }
    local out="$SLIC_PLANS/${name}.plan"
    {
        printf 'status: handoff\n'
        printf 'plan: %s\n' "$title"
        printf 'module: 34_slicing.sh (slic)\n'
        printf 'requires: %s\n' "$needs"
        printf 'generated: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf '\n'
        printf '%s\n' "$body"
    } > "$out" || { printf 'ERROR\tcould not write %s\n' "$out" >&2; return 1; }
    [[ -s "$out" ]] || { printf 'ERROR\t%s is empty\n' "$out" >&2; return 1; }
    printf '%s' "$out"
}

slic_plan_escape_lab() {
    local body
    body=$(cat <<'EOF'
# Slice escape lab — 5G SA with two slices (handoff)

## What the handoff needs
1. A 5G SA testbed with at least two slices: Open5GS or free5GC with a gNB
   (srsRAN or OpenAirInterface) and two S-NSSAIs configured, e.g.
   1/000001 (eMBB) and 2/000002 (URLLC), each with its own SMF/UPF or one UPF
   with two network instances.
2. A subscriber whose subscription includes only ONE of the two slices, so the
   other slice is the unauthorised one.
3. A second UPF configuration with a SHARED UPF and no per-slice network
   instance/VRF, to reproduce the shared-UPF isolation failure.
4. A UE with a programmable test SIM and a way to set the requested NSSAI.
5. An N3 capture point (GTP-U) and an N2 capture point (NGAP), plus a
   reachability target inside each slice (a service address) to test whether
   slice A's user plane can reach slice B's service.

## What is already implemented in software
- S-NSSAI SST/SD encode and decode, the NSSAI container parse, and the
  selection outcome (`--selection`) including the "granted but never
  requested" and "silently dropped" classes.
- The isolation evaluation (`--isolation-check`) over observed GTP-U endpoints
  with an explicit slice->TEID map, which reports shared-transport and
  refuses to claim isolation from a capture alone.
- The detection rules for an unexpected S-NSSAI, a mid-session slice change
  and a rejection cause that names the slice configuration.

## Steps
1. Bring the testbed up; register the UE and capture the requested and allowed
   NSSAI. Run `--selection <requested> <allowed> <rejected>` and confirm the
   outcome matches the subscription.
2. Set the requested NSSAI to the slice the subscriber is NOT subscribed to
   and re-register. If the allowed NSSAI contains it, that is the
   honoured-without-authorisation class.
3. Establish a PDU session on the unauthorised slice and confirm user-plane
   reachability.
4. Capture N3 and run `--isolation-check <pcap> <sliceA=teid,...;sliceB=teid,...>`
   to show whether the two slices share an N3 endpoint.
5. From a host in slice A, attempt to reach the service address in slice B.
   Record the result — this is the observation the capture cannot make.
6. Repeat with the shared-UPF configuration and with the visited-network
   mapping in a roaming setup.

## Safety
A 5G SA testbed with two network instances is core-network equipment; this is
a lab topology on spectrum you are licensed for. Nothing here transmits.
EOF
)
    slic_plan_write "slice-escape-lab" "5G SA two-slice escape and isolation lab" \
        "a 5G SA testbed (Open5GS or free5GC + srsRAN/OAI gNB) with two S-NSSAIs on either separate or shared UPFs, a test SIM subscribed to only one slice, a UE that can set the requested NSSAI, and N2/N3 capture plus an in-slice reachability target" \
        "$body"
}

slic_cmd_plan() {
    local which="${1:-}" pf rc
    case "$which" in
        slice-escape-lab) pf=$(slic_plan_escape_lab); rc=$? ;;
        *)
            printf 'ERROR\tunknown plan: %s (want slice-escape-lab)\n' "$(slic_sanitize "${which:-<none>}")" >&2
            return 2 ;;
    esac
    [[ "$rc" -eq 0 && -n "$pf" ]] || return "${rc:-1}"
    printf 'plan_file\t%s\n' "$pf"
    printf 'status\thandoff\n'
    printf 'note\t%s\n' "this vector needs the testbed named in the plan; no traffic was sent"
    return 0
}

# ── CLI verbs ───────────────────────────────────────────────────────────
slic_cli_status_tsv() {
    local plans=0
    [[ -d "$SLIC_PLANS" ]] && plans=$(find "$SLIC_PLANS" -name '*.plan' -type f 2>/dev/null | wc -l)
    printf 'module\tslicing\n'
    printf 'tag\tslic\n'
    printf 'dir\t%s\n' "$SLIC_DIR"
    printf 'plans_dir\t%s\n' "$SLIC_PLANS"
    printf 'plans\t%s\n' "$plans"
    printf 'sst_assigned\t1,2,3,4,5\n'
    printf 'python3\t%s\n' "$(command -v python3 >/dev/null 2>&1 && echo yes || echo no)"
    printf 'isolation_verdict\t%s\n' "not-determinable without a slice-to-TEID binding"
    printf 'refs\tTS 23.003, TS 23.501, TS 23.502, TS 24.501, TS 29.244, TS 38.413\n'
}

slic_cmd_encode() {
    local sst="${1:-}" sd="${2:-}"
    [[ -n "$sst" ]] || { printf 'ERROR\tusage: --encode-s-nssai <sst> [sd]\n' >&2; return 2; }
    local hex; hex=$(slic_encode_s_nssai "$sst" "$sd") || return 1
    printf 'sst\t%s\n' "$(slic_sanitize "$sst")"
    printf 'sst_name\t%s\n' "$(slic_sst_name "$sst")"
    printf 'sd\t%s\n' "$(slic_sanitize "${sd:-none}")"
    printf 'octets\t%s\n' "$(( ${#hex} / 2 ))"
    printf 'hex\t%s\n' "$hex"
    printf 'roundtrip_sst\t%s\n' "$(slic_decode_s_nssai "$hex" | awk -F'\t' '$1=="sst"{print $2}')"
    printf 'roundtrip_sd\t%s\n' "$(slic_decode_s_nssai "$hex" | awk -F'\t' '$1=="sd"{print $2}')"
}

slic_cmd_decode() {
    local hex="${1:-}"
    [[ -n "$hex" ]] || { printf 'ERROR\tusage: --decode-s-nssai <hex>\n' >&2; return 2; }
    slic_decode_s_nssai "$hex"
}

slic_cmd_nssai() {
    local hex="${1:-}"
    [[ -n "$hex" ]] || { printf 'ERROR\tusage: --nssai-parse <hex>\n' >&2; return 2; }
    slic_nssai_parse "$hex"
}

slic_cmd_selection() {
    local req="${1:-}" allow="${2:-}" rej="${3:-}"
    [[ -n "$req" ]] || { printf 'ERROR\tusage: --selection <requested-hex> [allowed-hex] [rejected-hex]\n' >&2; return 2; }
    slic_selection "$req" "$allow" "$rej"
}

slic_cmd_isolation() {
    local pcap="${1:-}" map="${2:-}"
    [[ -n "$pcap" ]] || { printf 'ERROR\tusage: --isolation-check <pcap> [slice=teid,...;...]\n' >&2; return 2; }
    slic_isolation_check "$pcap" "$map"
}

# ── selftest — no radio, no root, no network ────────────────────────────
slic_selftest() {
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
    export SLIC_DIR="$d/loot/slicing"
    export SLIC_PLANS="$SLIC_DIR/plans"
    mkdir -p "$SLIC_PLANS"

    # ── 1. SST table, known answers from TS 23.501 Table 5.15.2.2-1 ─────
    chk sst-1 "$(slic_sst_name 1)" "eMBB (enhanced Mobile Broadband)"
    chk sst-2 "$(slic_sst_name 2)" "URLLC (ultra-Reliable Low-Latency Communications)"
    chk sst-3 "$(slic_sst_name 3)" "MIoT (massive IoT / mMTC)"
    chk sst-4 "$(slic_sst_name 4)" "V2X (Vehicle-to-Everything)"
    chk sst-5 "$(slic_sst_name 5)" "HMTC (High-Performance Machine-Type Communications)"
    # An unassigned SST must be reported as unknown, never folded onto eMBB.
    chk sst-0-unknown  "$(slic_sst_name 0)" "unknown"
    chk sst-6-unknown  "$(slic_sst_name 6)" "unknown"
    chk sst-200-unknown "$(slic_sst_name 200)" "unknown"
    chk sst-unknown-not-embb "$(slic_sst_name 99 | grep -c 'eMBB')" "0"
    chk sst-known-1  "$(slic_sst_known 1 && echo yes || echo no)" "yes"
    chk sst-known-99 "$(slic_sst_known 99 && echo yes || echo no)" "no"
    chk sst-table-rows "$(slic_sst_table | grep -c '^[0-9]')" "6"
    chk sst-table-source "$(slic_sst_table | grep -c 'TS 23.501 Table 5.15.2.2-1')" "5"

    # ── 2. S-NSSAI encode/decode, byte-exact ────────────────────────────
    chk enc-embb      "$(slic_encode_s_nssai 1 000001)" "01000001"
    chk enc-urllc     "$(slic_encode_s_nssai 2 000002)" "02000002"
    chk enc-miot      "$(slic_encode_s_nssai 3 000003)" "03000003"
    chk enc-v2x       "$(slic_encode_s_nssai 4 000004)" "04000004"
    chk enc-hmtc      "$(slic_encode_s_nssai 5 000005)" "05000005"
    chk enc-no-sd     "$(slic_encode_s_nssai 1)" "01FFFFFF"
    chk enc-sd-none   "$(slic_encode_s_nssai 1 none)" "01FFFFFF"
    chk enc-sd-case   "$(slic_encode_s_nssai 1 abcdef)" "01ABCDEF"
    chk enc-oob       "$(slic_encode_s_nssai 256 000001 >/dev/null 2>&1; echo $?)" "1"
    chk enc-bad-sd    "$(slic_encode_s_nssai 1 zzz >/dev/null 2>&1; echo $?)" "1"
    chk enc-empty     "$(slic_encode_s_nssai '' >/dev/null 2>&1; echo $?)" "1"
    out=$(slic_decode_s_nssai 01000001); rc=$?
    chk dec-rc        "$rc" "0"
    chk dec-len       "$(fld "$out" length)" "4"
    chk dec-sst       "$(fld "$out" sst)" "1"
    chk dec-sst-name  "$(fld "$out" sst_name)" "eMBB (enhanced Mobile Broadband)"
    chk dec-sst-known "$(fld "$out" sst_known)" "yes"
    chk dec-sd        "$(fld "$out" sd)" "000001"
    chk dec-sd-present "$(fld "$out" sd_present)" "1"
    # SST-only form.
    out=$(slic_decode_s_nssai 02)
    chk dec1-len    "$(fld "$out" length)" "1"
    chk dec1-sst    "$(fld "$out" sst)" "2"
    chk dec1-sst-name "$(fld "$out" sst_name)" "URLLC (ultra-Reliable Low-Latency Communications)"
    chk dec1-sd     "$(fld "$out" sd)" "ffffff"
    chk dec1-nopresent "$(fld "$out" sd_present)" "0"
    # The 0xFFFFFF differentiator means "no SD" even in the 4-octet form.
    out=$(slic_decode_s_nssai 01FFFFFF)
    chk dec-nosd-present "$(fld "$out" sd_present)" "0"
    # Unknown SST is reported as unknown through the decoder too.
    out=$(slic_decode_s_nssai 63000001)
    chk dec-unknown-sst "$(fld "$out" sst_name)" "unknown"
    chk dec-unknown-known "$(fld "$out" sst_known)" "no"
    chk dec-bad-len   "$(slic_decode_s_nssai 0102 >/dev/null 2>&1; echo $?)" "1"
    chk dec-nonhex    "$(slic_decode_s_nssai zz >/dev/null 2>&1; echo $?)" "1"
    # Round-trip every assigned SST.
    local s
    for s in 1 2 3 4 5; do
        chk "roundtrip-$s" "$(slic_decode_s_nssai "$(slic_encode_s_nssai "$s" 123456)" | awk -F'\t' '$1=="sst"{print $2}')" "$s"
    done

    # ── 3. NSSAI container parse, including a multi-slice hex ───────────
    # eMBB(1/000001) + URLLC(2/000002): each S-NSSAI is length-prefixed.
    out=$(slic_nssai_parse "0401000001"; echo) 2>/dev/null
    # full container: [4][01 00 00 01] is a single 4-octet S-NSSAI
    out=$(slic_nssai_parse "0401000001"); rc=$?
    chk nssai-rc     "$rc" "0"
    chk nssai-count  "$(fld "$out" count)" "1"
    chk nssai-e0     "$(printf '%s\n' "$out" | awk -F'\t' '$1=="entry"{print $3}')" "01000001"
    chk nssai-sst    "$(printf '%s\n' "$out" | awk -F'\t' '$1=="entry"{print $4}')" "1"
    # Multi-slice: [4]01000001 [1]02  -> two entries, 5 octets
    out=$(slic_nssai_parse "04010000010102"); rc=$?
    chk nssai2-rc    "$rc" "0"
    chk nssai2-count "$(fld "$out" count)" "2"
    chk nssai2-e0sst "$(printf '%s\n' "$out" | awk -F'\t' '$1=="entry" && $2==0{print $4}')" "1"
    chk nssai2-e1sst "$(printf '%s\n' "$out" | awk -F'\t' '$1=="entry" && $2==1{print $4}')" "2"
    chk nssai2-e1sd  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="entry" && $2==1{print $6}')" "ffffff"
    # Three slices, mixed 1-octet and 4-octet forms.
    out=$(slic_nssai_parse "040100000101020404000004")
    chk nssai3-count "$(fld "$out" count)" "3"
    chk nssai3-e2sst "$(printf '%s\n' "$out" | awk -F'\t' '$1=="entry" && $2==2{print $4}')" "4"
    # A full NSSAI IE (IEI + length + container) is accepted and the IEI reported.
    out=$(slic_nssai_parse "2a050401000001")
    chk nssai-iei    "$(fld "$out" iei)" "2A"
    chk nssai-iei-cnt "$(fld "$out" count)" "1"
    # Malformed containers fail rather than silently truncating.
    chk nssai-bad-len  "$(slic_nssai_parse "0301000001" >/dev/null 2>&1; echo $?)" "1"
    chk nssai-trunc    "$(slic_nssai_parse "04010000" >/dev/null 2>&1; echo $?)" "1"
    chk nssai-none     "$(slic_nssai_parse >/dev/null 2>&1; echo $?)" "2"

    # ── 4. Selection outcomes ───────────────────────────────────────────
    # requested eMBB+URLLC, allowed eMBB only, rejected URLLC with a cause:
    # the dropped/unrequested classes must not appear.
    out=$(slic_selection "04010000010402000002" "0401000001" "0402000002"); rc=$?
    chk sel-rc        "$rc" "0"
    chk sel-outcome   "$(fld "$out" outcome)" "consistent"
    chk sel-allowed   "$(fld "$out" allowed)" "1"
    chk sel-rejected  "$(fld "$out" rejected)" "1"
    chk sel-dropped   "$(fld "$out" dropped)" "0"
    chk sel-unreq     "$(fld "$out" unrequested_allowed)" "0"
    chk sel-no-finding "$(printf '%s\n' "$out" | grep -c '^finding')" "0"
    # The network grants a slice that was never requested.
    out=$(slic_selection "0401000001" "04010000010402000002" "")
    chk sel-unreq-bad "$(fld "$out" unrequested_allowed)" "1"
    chk sel-unreq-outcome "$(fld "$out" outcome)" "anomalous"
    chk sel-unreq-finding "$(printf '%s\n' "$out" | grep -c 'unrequested-allowed-slice')" "1"
    # A requested slice the network neither allows nor rejects.
    out=$(slic_selection "04010000010402000002" "0401000001" "")
    chk sel-drop-count "$(fld "$out" dropped)" "1"
    chk sel-drop-finding "$(printf '%s\n' "$out" | grep -c 'silently-dropped-request')" "1"
    # With only the requested NSSAI the outcome is explicitly not determinable.
    out=$(slic_selection "0401000001")
    chk sel-1arg-outcome "$(fld "$out" outcome)" "not-determinable"
    chk sel-1arg-missing "$(fld "$out" missing)" "the allowed NSSAI (and the rejected NSSAI with its cause) from the Registration Accept"
    chk sel-1arg-none    "$(printf '%s\n' "$out" | grep -c '^selection	allowed')" "0"
    chk sel-none         "$(slic_selection >/dev/null 2>&1; echo $?)" "2"
    chk sel-bad-req      "$(slic_selection zz >/dev/null 2>&1; echo $?)" "1"

    # ── 5. 5GS NAS framing, known answers from tshark ───────────────────
    # 7E 00 44 16 is Registration reject with 5GMM cause 22; tshark 4.2.2
    # decodes it as "Congestion (22)" via the nas-5gs dissector.
    chk nas-type     "$(slic_nas_5gs_type "7E004416")" "68"
    chk nas-name     "$(slic_nas_5gs_message_name 68)" "Registration reject"
    chk nas-cause    "$(slic_nas_5gs_cause "7E004416")" "22"
    chk nas-cause-nm "$(slic_5gmm_cause_name 22)" "Congestion"
    chk nas-cause62  "$(slic_nas_5gs_cause "7E00443E")" "62"
    chk nas-cause62n "$(slic_5gmm_cause_name 62)" "No network slices available"
    chk nas-causename62 "$(slic_5gmm_cause_name 62)" "No network slices available"
    chk nas-not5gs   "$(slic_nas_5gs_type "07440F" >/dev/null 2>&1; echo $?)" "1"
    chk nas-short    "$(slic_nas_5gs_type "7E00" >/dev/null 2>&1; echo $?)" "1"
    chk nas-msg-names "$(slic_nas_5gs_message_name 65)" "Registration request"
    chk nas-session  "$(slic_nas_5gs_message_name 193)" "PDU session establishment request"

    # ── 6. Detection rules ──────────────────────────────────────────────
    # A clean sequence: register on slice A, then a session on slice A.
    out=$(printf 'event\t1\t1\tue1\t01000001\tregister\t\nevent\t2\t2\tue1\t01000001\tsession-establish\t\n' | slic_detect_stream)
    chk detect-clean "$(printf '%s' "$out" | grep -c '^FINDING')" "0"
    # A session on a slice the UE never registered on.
    out=$(printf 'event\t3\t3\tue1\t01000001\tregister\t\nevent\t4\t4\tue1\t02000002\tsession-establish\t\n' | slic_detect_stream)
    chk detect-unexpected "$(printf '%s' "$out" | grep -c 'unexpected-s-nssai-in-session')" "1"
    chk detect-change     "$(printf '%s' "$out" | grep -c 'slice-change-mid-session')" "1"
    # A rejection cause that names the slice configuration.
    out=$(printf 'event\t5\t5\tue1\t01000001\treject\t62\n' | slic_detect_stream)
    chk detect-cause "$(printf '%s' "$out" | grep -c 'rejection-cause-reveals-slice-config')" "1"
    # A benign cause must not fire that rule.
    out=$(printf 'event\t6\t6\tue1\t01000001\treject\t22\n' | slic_detect_stream)
    chk detect-cause-quiet "$(printf '%s' "$out" | grep -c 'rejection-cause-reveals-slice-config')" "0"
    chk detect-empty "$(printf '' | slic_detect_stream >/dev/null 2>&1; echo $?)" "1"

    # ── 7. Isolation: never claim isolation it cannot establish ─────────
    local pcap="$d/n3.pcap"
    if command -v python3 >/dev/null 2>&1; then
        python3 - "$pcap" <<'PY'
import struct, sys
path = sys.argv[1]
def eth(p): return bytes.fromhex('00112233445566778899aabb') + struct.pack('>H', 0x0800) + p
def ip(s, d, p):
    return struct.pack('>BBHHHBBH', 0x45, 0, 20 + len(p), 1, 0, 64, 17, 0) + s + d + p
def udp(sp, dp, p): return struct.pack('>HHHH', sp, dp, 8 + len(p), 0) + p
def gtpu(teid):
    # GTPv1-U G-PDU: flags 0x30 (version 1, PT=1), type 0xFF, length, TEID
    return struct.pack('>BBHI', 0x30, 0xFF, 4, teid) + b'\x45\x00\x00\x14' + b'\x00' * 16
UPF1 = bytes([10, 20, 0, 1]); UPF2 = bytes([10, 20, 0, 2]); GNB = bytes([10, 10, 0, 1])
frames = []
for teid in (1001, 1002):          # both slices on the same UPF endpoint
    frames.append(eth(ip(UPF1, GNB, udp(2152, 2152, gtpu(teid)))))
frames.append(eth(ip(UPF2, GNB, udp(2152, 2152, gtpu(2001)))))
with open(path, 'wb') as f:
    f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for i, fr in enumerate(frames):
        f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
        f.write(fr)
PY
        # No slice mapping: the answer must be "not determinable", and it must
        # NOT claim isolation.
        out=$(slic_cmd_isolation "$pcap"); rc=$?
        chk iso-rc        "$rc" "0"
        chk iso-verdict   "$(fld "$out" isolation)" "not-determinable"
        chk iso-missing   "$(printf '%s\n' "$out" | grep -c 'S-NSSAI to TEID')" "1"
        chk iso-no-claim  "$(printf '%s\n' "$out" | grep -ci 'isolated')" "0"
        chk iso-flows     "$(fld "$out" gtpu_flows)" "3"
        # With a mapping: slices A(1001) and B(1002) both land on 10.20.0.1,
        # so the transport is shared.
        out=$(slic_cmd_isolation "$pcap" "A=1001;B=1002")
        chk iso-shared    "$(printf '%s\n' "$out" | grep -c 'shared-transport')" "1"
        chk iso-finding   "$(printf '%s\n' "$out" | grep -c 'slice-isolation-failure')" "1"
        # A(1001) on UPF1 and C(2001) on UPF2: distinct endpoints, which is
        # necessary but explicitly not sufficient.
        out=$(slic_cmd_isolation "$pcap" "A=1001;C=2001")
        chk iso-distinct  "$(printf '%s\n' "$out" | grep -c '^pair.*distinct-transport')" "1"
        chk iso-notclaim  "$(fld "$out" isolation | grep -c 'not-isolation')" "1"
        # A mapping whose TEIDs never appear is not determinable either.
        out=$(slic_cmd_isolation "$pcap" "A=9999;B=8888")
        chk iso-nomatch   "$(printf '%s\n' "$out" | grep -c 'not-determinable')" "1"
        chk iso-bad-map   "$(slic_cmd_isolation "$pcap" "A" >/dev/null 2>&1; echo $?)" "2"
        chk iso-bad-teid  "$(slic_cmd_isolation "$pcap" "A=abc;B=1" >/dev/null 2>&1; echo $?)" "2"
    else
        printf 'isolation-suite\tSKIP python3 not present\n'
    fi

    # ── 8. Plans carry status: handoff ──────────────────────────────────
    local pf file
    pf=$(slic_cmd_plan slice-escape-lab); rc=$?
    chk plan-rc     "$rc" "0"
    chk plan-status "$(printf '%s\n' "$pf" | awk -F'\t' '$1=="status"{print $2}')" "handoff"
    file=$(printf '%s\n' "$pf" | awk -F'\t' '$1=="plan_file"{print $2}')
    chk plan-file-status "$(grep -c '^status: handoff' "$file")" "1"
    chk plan-file-slices "$(grep -q 'two S-NSSAIs' "$file" && echo yes || echo no)" "yes"
    chk plan-file-upf    "$(grep -q 'SHARED UPF' "$file" && echo yes || echo no)" "yes"
    chk plan-unknown     "$(slic_cmd_plan nope >/dev/null 2>&1; echo $?)" "2"

    # ── 9. Status TSV, surface notes, sanitisation ──────────────────────
    out=$(slic_cli_status_tsv)
    chk status-module "$(fld "$out" module)" "slicing"
    chk status-tag    "$(fld "$out" tag)" "slic"
    chk status-dir    "$(fld "$out" dir)" "$SLIC_DIR"
    chk status-sst    "$(fld "$out" sst_assigned)" "1,2,3,4,5"
    out=$(slic_surface_notes)
    chk surface-auth   "$(printf '%s\n' "$out" | grep -c 'slice-honoured-without-authorisation')" "1"
    chk surface-vrf    "$(printf '%s\n' "$out" | grep -c 'shared-upf-no-vrf')" "1"
    chk surface-roam   "$(printf '%s\n' "$out" | grep -c 'roaming-mapping-not-enforced')" "1"
    chk surface-enum   "$(printf '%s\n' "$out" | grep -c 'slice-id-enumeration')" "1"
    local evil
    evil=$(slic_sanitize $'a\tb\nc')
    chk sanitize-tabs "$(printf '%s' "$evil" | tr -cd '\t' | wc -c)" "0"
    chk sanitize-nl   "$(printf '%s' "$evil" | wc -l)" "0"
    SLIC_F=()
    slic_split $'x\t\ty\tz'
    chk split-len   "${#SLIC_F[@]}" "4"
    chk split-empty "${SLIC_F[1]}" ""
    chk split-third "${SLIC_F[2]}" "y"

    # ── 10. Argument validation returns non-zero ────────────────────────
    chk val-encode-none  "$(slic_cmd_encode >/dev/null 2>&1; echo $?)" "2"
    chk val-decode-none  "$(slic_cmd_decode >/dev/null 2>&1; echo $?)" "2"
    chk val-decode-bad   "$(slic_cmd_decode 0102 >/dev/null 2>&1; echo $?)" "1"
    chk val-nssai-none   "$(slic_cmd_nssai >/dev/null 2>&1; echo $?)" "2"
    chk val-sel-none     "$(slic_cmd_selection >/dev/null 2>&1; echo $?)" "2"
    chk val-iso-none     "$(slic_cmd_isolation >/dev/null 2>&1; echo $?)" "2"
    chk val-iso-nofile   "$(slic_cmd_isolation /nonexistent.pcap >/dev/null 2>&1; echo $?)" "1"
    chk val-detect-none  "$(slic_cmd_detect >/dev/null 2>&1; echo $?)" "2"
    chk val-detect-nofile "$(slic_cmd_detect /nonexistent.tsv >/dev/null 2>&1; echo $?)" "1"

    rm -rf "$d"
    trap - EXIT
    [[ -n "$_prev_trap" ]] && eval "$_prev_trap"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ── menu ────────────────────────────────────────────────────────────────
slic_menu() {
    local c p h
    while true; do
        banner
        echo -e "  ${C_MAG}=== Slicing Escape ===${C_RESET}"
        echo -e "  SST:  ${C_GRN}1 eMBB  2 URLLC  3 MIoT  4 V2X  5 HMTC${C_RESET}"
        echo -e "  dir:  ${C_DIM}$SLIC_PLANS${C_RESET}\n"
        cat << 'M'
  [1]  SST table
  [2]  encode an S-NSSAI
  [3]  decode an S-NSSAI
  [4]  parse an NSSAI container
  [5]  slice selection (requested / allowed / rejected)
  [6]  isolation check from a capture
  [7]  decode a 5GS NAS slice message
  [8]  vulnerability classes
  [9]  plan: slice escape lab
  [10] status
  [0]  back

M
        read -rp "  choice> " c
        case "$c" in
            1) slic_sst_table | column -t -s$'\t' 2>/dev/null || slic_sst_table
               read -rp "  press enter " _ ;;
            2) if [[ -n "${IMSISTING_CLI:-}" ]]; then echo "[-] need an SST; cannot prompt in CLI mode" >&2
               else read -rp "  SST (1-255)> " p; read -rp "  SD (6 hex or none)> " s
                    slic_cmd_encode "$p" "${s:-none}"; read -rp "  press enter " _; fi ;;
            3) if [[ -n "${IMSISTING_CLI:-}" ]]; then echo "[-] need hex; cannot prompt in CLI mode" >&2
               else read -rp "  S-NSSAI hex> " h; slic_cmd_decode "$h" | column -t -s$'\t' 2>/dev/null; read -rp "  press enter " _; fi ;;
            4) if [[ -n "${IMSISTING_CLI:-}" ]]; then echo "[-] need hex; cannot prompt in CLI mode" >&2
               else read -rp "  NSSAI hex> " h; slic_cmd_nssai "$h" | column -t -s$'\t' 2>/dev/null; read -rp "  press enter " _; fi ;;
            5) if [[ -n "${IMSISTING_CLI:-}" ]]; then echo "[-] need hex; cannot prompt in CLI mode" >&2
               else read -rp "  requested NSSAI hex> " r; read -rp "  allowed NSSAI hex (blank)> " a; read -rp "  rejected NSSAI hex (blank)> " j
                    slic_cmd_selection "$r" "$a" "$j" | column -t -s$'\t' 2>/dev/null; read -rp "  press enter " _; fi ;;
            6) if [[ -n "${IMSISTING_CLI:-}" ]]; then echo "[-] need a pcap; cannot prompt in CLI mode" >&2
               else read -rp "  pcap> " p; read -rp "  slice map (blank, e.g. A=1001;B=1002)> " m
                    slic_cmd_isolation "$p" "$m" | column -t -s$'\t' 2>/dev/null; read -rp "  press enter " _; fi ;;
            7) if [[ -n "${IMSISTING_CLI:-}" ]]; then echo "[-] need hex; cannot prompt in CLI mode" >&2
               else read -rp "  5GS NAS hex> " h
                    printf 'message_type\t%s\nmessage_name\t%s\ncause\t%s\ncause_name\t%s\n' \
                        "$(slic_nas_5gs_type "$h")" "$(slic_nas_5gs_message_name "$(slic_nas_5gs_type "$h")")" \
                        "$(slic_nas_5gs_cause "$h")" "$(slic_5gmm_cause_name "$(slic_nas_5gs_cause "$h")")"
                    read -rp "  press enter " _; fi ;;
            8) slic_surface_notes | column -t -s$'\t' 2>/dev/null || slic_surface_notes
               read -rp "  press enter " _ ;;
            9) slic_cmd_plan slice-escape-lab; read -rp "  press enter " _ ;;
            10) slic_cli_status_tsv | column -t -s$'\t' 2>/dev/null || slic_cli_status_tsv
                read -rp "  press enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ── CLI dispatch ────────────────────────────────────────────────────────
slic_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)        slic_cli_status_tsv ;;
        --sst-table)         slic_sst_table ;;
        --encode-s-nssai)    slic_cmd_encode "${1:-}" "${2:-}" ;;
        --decode-s-nssai)    slic_cmd_decode "${1:-}" ;;
        --nssai-parse)       slic_cmd_nssai "${1:-}" ;;
        --selection)         slic_cmd_selection "${1:-}" "${2:-}" "${3:-}" ;;
        --isolation-check)   slic_cmd_isolation "${1:-}" "${2:-}" ;;
        --detect)            slic_cmd_detect "${1:-}" ;;
        --nas5gs)            {
                                 local h="${1:-}"
                                 [[ -n "$h" ]] || { printf 'ERROR\tusage: --nas5gs <hex>\n' >&2; return 2; }
                                 local t; t=$(slic_nas_5gs_type "$h") || { printf 'ERROR\tnot a 5GS plain NAS message (no 0x7E extended protocol discriminator)\n' >&2; return 1; }
                                 local cz; cz=$(slic_nas_5gs_cause "$h")
                                 printf 'message_type\t%s\n' "$t"
                                 printf 'message_name\t%s\n' "$(slic_nas_5gs_message_name "$t")"
                                 printf 'cause\t%s\n' "$cz"
                                 printf 'cause_name\t%s\n' "$([[ -n "$cz" ]] && slic_5gmm_cause_name "$cz" || printf '')"
                             } ;;
        --surface)           slic_surface_notes ;;
        --plan)              slic_cmd_plan "${1:-}" ;;
        --selftest)          slic_selftest ;;
        --menu)              slic_menu ;;
        *)
            cat >&2 <<EOF
Slicing Escape — S-NSSAI codec, slice selection, isolation testing

Usage: $0 COMMAND
  --status-tsv                        module state as TSV
  --sst-table                         the standardised SST values with sources
  --encode-s-nssai <sst> [sd]         S-NSSAI hex (SST + 3-octet SD)
  --decode-s-nssai <hex>              S-NSSAI hex -> SST/SD and the SST name
  --nssai-parse <hex>                 NSSAI container (or full IE) -> slices
  --selection <req> [allow] [reject]  the selection outcome, including
                                      granted-but-unrequested and dropped
  --isolation-check <pcap> [map]      isolation evidence; never claims
                                      isolation it cannot establish
  --detect <slice-events.tsv>         session-level slice anomaly rules
  --nas5gs <hex>                      decode a 5GS plain NAS slice message
  --surface                           the vulnerability classes
  --plan slice-escape-lab             write the handed-off lab plan
  --selftest                          verify the codec and rules
  --menu                              interactive menu
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
    slic_cli_main "$@"
fi
