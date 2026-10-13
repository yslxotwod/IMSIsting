#!/usr/bin/env bash
# paging track — paging-occasion arithmetic, paging-record parse, ToRPEDO
# ("Torpedo") and paging-based IMSI recovery ("Piercer"), and paging-anomaly
# detection.
#
# Everything that derives a paging occasion is pure arithmetic and runs with no
# radio, no root and no network. The capture-driven verbs read a GSMTAP pcap
# with a native python pcab reader (python3 is a hard dependency, 00_deps.sh),
# because the Wireshark build on a target may not hand a GSMTAP PCH payload to
# its GSM RR dissector.
#
# Attacks owned: P8 (paging channel monitoring), O13 (ToRPEDO), O14 (paging-
# based IMSI recovery).
#
# Paper note, stated because the build brief and the literature differ: the
# paging-collision attack known as "Torpedo"/ToRPEDO and the paging-based IMSI
# recovery ("IMSI-Cracking") are published in
#   S. R. Hussain, M. Echeverria, O. Chowdhury, N. Li, E. Bertino,
#   "Privacy Attacks to the 4G and 5G Cellular Paging Protocols Using Side
#   Channel Information", NDSS 2019.
# The brief attributes ToRPEDO to USENIX Security 2019 and names the IMSI
# recovery "Piercer (2021)". The mechanism implemented here is the published
# NDSS 2019 one; the venue is cited as verified rather than as briefed.
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

MOD_TMP="$TMP_DIR/paging_track"
PGT_DIR="$LOOT_DIR/paging_track"
PGT_PLAN_DIR="$PGT_DIR/plans"
mkdir -p "$MOD_TMP" "$PGT_DIR" "$PGT_PLAN_DIR" 2>/dev/null

declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
declare -F warn >/dev/null 2>&1 || warn() { printf '[warn] %s\n' "$*" >&2; }
declare -F err  >/dev/null 2>&1 || err()  { printf '[err]  %s\n' "$*" >&2; }
declare -F ok   >/dev/null 2>&1 || ok()   { printf '[ok]   %s\n' "$*" >&2; }
declare -F banner >/dev/null 2>&1 || banner() { :; }

# ── sanitisation and TSV splitting ──────────────────────────────────────
pgt_sanitize() { printf '%s' "${1:-}" | tr '\t\r\n' '   '; }

# Split a TSV line preserving empty fields. `IFS=$'\t' read` collapses runs of
# tabs; cut -f does not (MODULE_CONVENTIONS.md §12).
PGT_F=()
pgt_split() {
    PGT_F=()
    local i n
    n=$(printf '%s' "$1" | awk -F'\t' '{print NF}')
    for (( i = 1; i <= n; i++ )); do
        PGT_F+=("$(printf '%s' "$1" | cut -f"$i")")
    done
}

pgt_norm_hex() { printf '%s' "${1:-}" | tr -d ' \t\r\n:.-' | sed 's/^0x//I' | tr 'A-F' 'a-f'; }

pgt_is_hex() {
    local h; h=$(pgt_norm_hex "${1:-}")
    [[ -n "$h" && "$h" =~ ^[0-9a-f]+$ && $(( ${#h} % 2 )) -eq 0 ]]
}

# Mask at the point of emission: printf %02X does not truncate (conventions §15).
pgt_byte() { printf '%02X' "$(( ${1:-0} & 0xFF ))"; }
pgt_word() { printf '%04X' "$(( ${1:-0} & 0xFFFF ))"; }

# ── GSM paging arithmetic ───────────────────────────────────────────────
# 3GPP TS 45.002 §6.5.2 (and TS 44.018 §10.5.2.29a-c for the paging request):
#
#   paging_group = IMSI mod 1024
#   block        = paging_group mod (BS_PA_MFRMS div 2)
#
# BS_PA_MFRMS is the number of 51-frame multiframes between paging blocks for
# the subscriber (2..9). With BS_CC_CHANS=1 the subscriber returns to that
# block every BS_PA_MFRMS multiframes. BS_AG_BLKS_RES reserves the leading
# blocks of each multiframe for the AGCH.
pgt_paging_group() {
    local imsi="${1:-}"
    [[ "$imsi" =~ ^[0-9]{6,15}$ ]] || return 1
    printf '%d' "$(( 10#$imsi % 1024 ))"
}

pgt_paging_block() {
    local imsi="$1" pamfrms="${2:-2}"
    local grp; grp=$(pgt_paging_group "$imsi") || return 1
    [[ "$pamfrms" =~ ^[0-9]+$ ]] || return 1
    (( pamfrms >= 2 && pamfrms <= 9 )) || return 1
    local n=$(( pamfrms / 2 )); (( n >= 1 )) || n=1
    printf '%d' "$(( grp % n ))"
}

pgt_gsm_params() {
    local imsi="$1" pamfrms="${2:-2}" agblk="${3:-1}"
    local grp; grp=$(pgt_paging_group "$imsi") || return 1
    [[ "$pamfrms" =~ ^[0-9]+$ ]] || return 1
    (( pamfrms >= 2 && pamfrms <= 9 )) || return 1
    [[ "$agblk" =~ ^[0-9]+$ ]] || return 1
    (( agblk >= 0 )) || return 1
    local n=$(( pamfrms / 2 )); (( n >= 1 )) || n=1
    local block=$(( grp % n ))
    printf 'generation\tgsm\nimsi\t%s\npaging_group\t%d\nbs_pa_mfrms\t%d\nblocks_per_multiframe\t%d\npaging_block_index\t%d\nbs_ag_blks_res\t%d\nccch_block_index\t%d\nrepeat_every_multiframes\t%d\n' \
        "$imsi" "$grp" "$pamfrms" "$n" "$block" "$agblk" "$(( agblk + block ))" "$pamfrms"
}

# ── LTE paging frame and occasion ───────────────────────────────────────
# 3GPP TS 36.304 §7.2:
#   T            DRX cycle in radio frames, T in {32,64,128,256}
#   nB           4T,2T,T,T/2,T/4,T/8,T/16,T/32 (from SIB2 pagingConfig)
#   N  = min(T, nB)
#   Ns = max(1, nB/T)
#   UE_ID        IMSI mod 1024 (TS 36.304 §7.2), so callers pass IMSI mod 1024
#   PF: SFN mod T = (T div N) * (UE_ID mod N)
#   i_s = floor(UE_ID / N) mod Ns
#   subframe from TS 36.304 Table 7.2-1 (FDD and TDD patterns differ)
pgt_lte_params() {
    local ue="${1:-}" t="${2:-64}" nb="${3:-}" duplex="${4:-fdd}"
    [[ "$ue" =~ ^[0-9]+$ ]] || return 1
    (( ue >= 0 && ue <= 1023 )) || return 1
    [[ "$t" =~ ^[0-9]+$ ]] || return 1
    case "$t" in 32|64|128|256) ;; *) return 1 ;; esac
    [[ -z "$nb" ]] && nb="$t"
    [[ "$nb" =~ ^[0-9]+$ ]] || return 1
    case "$nb" in
        $(( 4*t ))|$(( 2*t ))|$(( t ))|$(( t/2 ))|$(( t/4 ))|$(( t/8 ))|$(( t/16 ))|$(( t/32 ))) ;;
        *) return 1 ;;
    esac
    case "$duplex" in fdd|tdd) ;; *) return 1 ;; esac
    local N=$(( nb < t ? nb : t ))
    local Ns=$(( nb / t )); (( Ns >= 1 )) || Ns=1
    local TdivN=$(( t / N ))
    local pf=$(( TdivN * (ue % N) ))
    local is=$(( (ue / N) % Ns ))
    local sub
    if [[ "$duplex" == "tdd" ]]; then
        case "$Ns:$is" in
            1:0) sub=0 ;; 2:0) sub=0 ;; 2:1) sub=5 ;;
            4:0) sub=0 ;; 4:1) sub=1 ;; 4:2) sub=5 ;; 4:3) sub=6 ;;
            *) return 1 ;;
        esac
    else
        case "$Ns:$is" in
            1:0) sub=9 ;; 2:0) sub=4 ;; 2:1) sub=9 ;;
            4:0) sub=0 ;; 4:1) sub=4 ;; 4:2) sub=5 ;; 4:3) sub=9 ;;
            *) return 1 ;;
        esac
    fi
    printf 'generation\tlte\nue_id\t%d\nt\t%d\nnb\t%d\nn\t%d\nns\t%d\nt_div_n\t%d\npf_sfn\t%d\ni_s\t%d\npo_subframe\t%d\nduplex\t%s\n' \
        "$ue" "$t" "$nb" "$N" "$Ns" "$TdivN" "$pf" "$is" "$sub" "$duplex"
}

# ── NR paging frame and occasion ────────────────────────────────────────
# 3GPP TS 38.304 §7.1:
#   UE_ID = 5G-S-TMSI mod 1024
#   T, nB, N = min(T,nB), Ns = max(1,nB/T) as for LTE
#   PF: (SFN + PF_offset) mod T = (T div N) * (UE_ID mod N)
#   i_s = floor(UE_ID / N) mod Ns
# The PO is the (i_s + 1)-th PDCCH monitoring occasion for paging inside the
# PF (TS 38.304 §7.1); this module reports the PO index, not a monitoring
# occasion that depends on the search space, which SIB1 would have to supply.
pgt_nr_params() {
    local ue="${1:-}" t="${2:-32}" nb="${3:-}" off="${4:-0}"
    [[ "$ue" =~ ^[0-9]+$ ]] || return 1
    (( ue >= 0 && ue <= 1023 )) || return 1
    [[ "$t" =~ ^[0-9]+$ ]] || return 1
    case "$t" in 32|64|128|256) ;; *) return 1 ;; esac
    [[ -z "$nb" ]] && nb="$t"
    [[ "$nb" =~ ^[0-9]+$ ]] || return 1
    case "$nb" in
        $(( 4*t ))|$(( 2*t ))|$(( t ))|$(( t/2 ))|$(( t/4 ))|$(( t/8 ))|$(( t/16 ))|$(( t/32 ))) ;;
        *) return 1 ;;
    esac
    [[ "$off" =~ ^[0-9]+$ ]] || return 1
    (( off >= 0 && off <= 3 )) || return 1
    local N=$(( nb < t ? nb : t ))
    local Ns=$(( nb / t )); (( Ns >= 1 )) || Ns=1
    local TdivN=$(( t / N ))
    local rhs=$(( TdivN * (ue % N) ))
    local sfn
    for (( sfn = 0; sfn < t; sfn++ )); do
        (( (sfn + off) % t == rhs )) && break
    done
    (( sfn < t )) || return 1
    local is=$(( (ue / N) % Ns ))
    printf 'generation\tnr\nue_id\t%d\nt\t%d\nnb\t%d\npf_offset\t%d\nn\t%d\nns\t%d\nt_div_n\t%d\npf_rhs\t%d\npf_sfn\t%d\ni_s\t%d\npo_index\t%d\n' \
        "$ue" "$t" "$nb" "$off" "$N" "$Ns" "$TdivN" "$rhs" "$sfn" "$is" "$(( is + 1 ))"
}

# ── mobile identity parse ───────────────────────────────────────────────
# TS 24.008 §10.5.1.4 (GSM), TS 24.301 §9.9.3.4 (EPS), TS 24.501 §9.11.3.4
# (5GS). The identity content octet is coded:
#   bits 3..1  type of identity: 001 IMSI, 010 IMEI, 011 IMEISV, 100 TMSI
#   bit  4     odd/even indicator
#   bits 8..5  spare, except for IMSI/IMEI/IMEISV where they carry the FIRST
#              digit of the identity (high nibble of the content octet)
# Remaining digits are packed two per octet, LOW nibble first, with an F filler
# in the high nibble of the last octet when the digit count is odd.
#
# Known-answer vectors below are taken verbatim from the libosmocore test suite
# tests/gsm0408/gsm0408_test.c (an independent, widely deployed implementation)
# and agree with the spec text:
#   IMSI "123456789012345" -> content 19 32 54 76 98 10 32 54
#   IMSI "12345678901234"  -> content 11 32 54 76 98 10 32 f4
#   IMSI "423423"          -> content 41 32 24 f3
#   IMSI "4234235"         -> content 49 32 24 53
#   IMEI "123456789012345" -> content 1a 32 54 76 98 10 32 54
#   IMEISV "9876543210987654" -> content 93 78 56 34 12 90 78 56 f4
#   TMSI 0xAABBCCDD        -> content f4 aa bb cc dd
pgt_parse_mi() {
    local h; h=$(pgt_norm_hex "${1:-}")
    [[ "$h" =~ ^[0-9a-f]{4,}$ ]] || return 1
    (( ${#h} % 2 == 0 )) || return 1
    local b0=$(( 16#${h:0:2} ))
    local type=$(( b0 & 0x07 ))
    local odd=$(( (b0 & 0x08) >> 3 ))
    local first=$(( (b0 >> 4) & 0x0F ))
    local itype
    case "$type" in
        1) itype="IMSI" ;; 2) itype="IMEI" ;; 3) itype="IMEISV" ;; 4) itype="TMSI" ;;
        *) return 1 ;;
    esac
    if (( type == 4 )); then
        local v="${h:2}"
        (( ${#v} == 8 )) || return 1
        printf 'identity_type\tTMSI\ntmsi\t0x%s\nraw\t%s\n' "$v" "$h"
        return 0
    fi
    local digits="$first" rest="${h:2}" i lo hi
    for (( i = 0; i < ${#rest}; i += 2 )); do
        hi=$(( 16#${rest:i:1} ))        # high nibble of the octet
        lo=$(( 16#${rest:i+1:1} ))      # low nibble
        digits+="$lo"
        (( hi == 15 )) && continue       # F filler
        digits+="$hi"
    done
    local oe="even"; (( odd )) && oe="odd"
    printf 'identity_type\t%s\nodd_even\t%s\nidentity\t%s\ndigits\t%d\nraw\t%s\n' \
        "$itype" "$oe" "$digits" "${#digits}" "$h"
}

# pgt_parse_paging <generation> <hex>
#   gsm : an RR Paging Request Type 1/2/3 (06 21/22/23) or Paging Response
#         (06 27) message, or a bare mobile-identity content octet string.
#         Paging records are LV: one length octet then that many content octets.
#   lte : UE identity content. IMSI -> 24.301 BCD; S-TMSI -> f4 || MMEC || M-TMSI.
#   nr  : UE identity content. IMSI -> 24.501 BCD; 5G-S-TMSI -> f4 || 6 octets
#         of AMF Set ID (10 bits) || AMF Pointer (6 bits) || 5G-TMSI (32 bits),
#         per TS 23.501 §2.10.2.
pgt_parse_paging() {
    local gen="${1:-gsm}" h
    h=$(pgt_norm_hex "${2:-}")
    [[ -n "$h" && "$h" =~ ^[0-9a-f]+$ ]] || return 2
    (( ${#h} % 2 == 0 )) || return 2
    (( ${#h} >= 2 )) || return 2
    case "$gen" in
      gsm)
        local body="$h" mode="bare"
        case "${body:0:4}" in
            0621|0622|0623)
                # Paging Request Type 1/2/3: LV mobile-identity records.
                body="${body:4}"; mode="lv" ;;
            0627)
                # Paging Response: 0627 || CKSN(1) || classmark LV || identity LV
                body="${body:4}"; mode="lv"
                (( ${#body} >= 2 )) || return 1
                body="${body:2}"
                (( ${#body} >= 2 )) || return 1
                local cl=$(( 16#${body:0:2} ))
                body="${body:2}"
                body="${body:$(( cl * 2 ))}"
                ;;
        esac
        (( ${#body} >= 2 )) || return 1
        if [[ "$mode" == "bare" ]]; then
            local out; out=$(pgt_parse_mi "$body") || return 1
            printf '%s\ngeneration\tgsm\n' "$out"
            return 0
        fi
        # LV records: one length octet then that many content octets each.
        local n=0
        while (( ${#body} >= 2 )); do
            local clen=$(( 16#${body:0:2} ))
            (( clen >= 1 )) || return 1
            local rec="${body:2:$(( clen * 2 ))}"
            (( ${#rec} == clen * 2 )) || return 1
            local o; o=$(pgt_parse_mi "$rec") || return 1
            printf 'record\t%d\n%s\n' "$n" "$o"
            body="${body:$(( (1 + clen) * 2 ))}"
            n=$(( n + 1 ))
        done
        (( n > 0 )) || return 1
        printf 'generation\tgsm\nrecords\t%d\n' "$n"
        return 0 ;;
      lte|nr)
        local b0=$(( 16#${h:0:2} ))
        local type=$(( b0 & 0x07 ))
        local v="${h:2}"
        if (( type == 1 )); then
            local o; o=$(pgt_parse_mi "$h") || return 1
            printf '%s\ngeneration\t%s\nmapped_identity\timsi\n' "$o" "$gen"
            return 0
        fi
        if (( type == 4 )); then
            if [[ "$gen" == "lte" ]] && (( ${#v} == 8 )); then
                printf 'identity_type\tTMSI\ntmsi\t0x%s\nraw\t%s\ngeneration\tlte\nmapped_identity\ttmsi\n' "$v" "$h"
                return 0
            fi
            if [[ "$gen" == "lte" ]] && (( ${#v} == 10 )); then
                printf 'identity_type\tS-TMSI\nmmec\t0x%s\nm_tmsi\t0x%s\ns_tmsi\t%s\nraw\t%s\ngeneration\tlte\nmapped_identity\ts-tmsi\n' \
                    "${v:0:2}" "${v:2:8}" "$v" "$h"
                return 0
            fi
            if [[ "$gen" == "nr" ]] && (( ${#v} == 12 )); then
                local val=$(( 16#$v ))
                local amfset=$(( (val >> 38) & 0x3FF ))
                local amfptr=$(( (val >> 32) & 0x3F ))
                local t5=$(( val & 0xFFFFFFFF ))
                printf 'identity_type\t5G-S-TMSI\namf_set_id\t%d\namf_pointer\t%d\n5g_tmsi\t0x%s\n5g_s_tmsi\t%s\nraw\t%s\ngeneration\tnr\nmapped_identity\t5g-s-tmsi\n' \
                    "$amfset" "$amfptr" "$(printf '%08x' "$t5")" "$v" "$h"
                return 0
            fi
            return 1
        fi
        return 1 ;;
      *) return 2 ;;
    esac
}

# ── capture reader ──────────────────────────────────────────────────────
# Native pcap reader + GSMTAP extractor. Emits one row per GSM Um frame:
#   ts <TAB> frame_number <TAB> l3_message_hex
pgt_py() {
    command -v python3 >/dev/null 2>&1 || {
        printf 'ERROR\tpython3 missing — cannot read captures\n' >&2; return 1; }
    python3 - "$@" <<'PY'
import sys, struct

def w_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for ts, pkt in frames:
            s = int(ts); us = int(round((ts - s) * 1000000))
            f.write(struct.pack('<IIII', s, us, len(pkt), len(pkt)))
            f.write(pkt)

def eth_gsmtap(payload, subtype, fn, ts):
    gs = struct.pack('!BBBBHbbI', 2, 4, 1, 0, 0, 0, 0, fn) + bytes([subtype, 0, 0, 0]) + payload
    udp = struct.pack('!HHHH', 4729, 4729, 8 + len(gs), 0) + gs
    iph = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                      b'\x0a\x00\x00\x01', b'\x0a\x00\x00\x02')
    eth = b'\xff' * 6 + b'\x02\x02\x02\x02\x02\x02' + struct.pack('!H', 0x0800) + iph + udp
    return (ts, eth)

def read_pcap(path):
    d = open(path, 'rb').read()
    if len(d) < 24:
        raise ValueError('file shorter than a pcap global header')
    magic = d[:4]
    if magic == b'\xd4\xc3\xb2\xa1':
        endian = '<'
    elif magic == b'\xa1\xb2\xc3\xd4':
        endian = '>'
    else:
        raise ValueError('not a classic pcap (pcapng is not supported; use editcap -F pcap)')
    link = struct.unpack(endian + 'IHHiIII', d[:24])[6]
    off = 24; out = []
    while off + 16 <= len(d):
        s, us, incl, orig = struct.unpack(endian + 'IIII', d[off:off + 16]); off += 16
        if off + incl > len(d):
            break
        out.append((s + us / 1000000.0, d[off:off + incl], link))
        off += incl
    return out

def l3_of(pkt, link):
    if link != 1:
        return None
    if len(pkt) < 14:
        return None
    et = struct.unpack('!H', pkt[12:14])[0]
    if et != 0x0800:
        return None
    ip = pkt[14:]
    if len(ip) < 20 or (ip[0] >> 4) != 4:
        return None
    ihl = (ip[0] & 0x0f) * 4
    if ip[9] != 17 or len(ip) < ihl + 8:
        return None
    udp = ip[ihl:]
    sport, dport = struct.unpack('!HH', udp[:4])
    if 4729 not in (sport, dport):
        return None
    gs = udp[8:]
    if len(gs) < 16:
        return None
    gtype = gs[2]
    fn = struct.unpack('!I', gs[8:12])[0]
    subtype = gs[12]
    return (gtype, subtype, fn, gs[16:])

def cmd_events(path):
    for ts, pkt, link in read_pcap(path):
        r = l3_of(pkt, link)
        if not r:
            continue
        gtype, subtype, fn, l3 = r
        if gtype != 1:
            continue
        print('%f\t%d\t%d\t%s' % (ts, fn, subtype, l3.hex()))

def tmsi_req(tmsi, fn):
    # RR Paging Request Type 1 (06 21) + LV mobile identity (f4 || TMSI)
    return bytes.fromhex('062105f4' + tmsi)

def tmsi_resp(tmsi, fn):
    # RR Paging Response (06 27) + CKSN(00) + classmark LV(03 505886) + LV identity
    return bytes.fromhex('0627000350588605f4' + tmsi)

def imsi_req(imsi_hex):
    return bytes.fromhex('0621' + '08' + imsi_hex)

def cmd_mkfixture(out, kind):
    frames = []
    if kind == 'normal':
        # four subscribers, each paged once and answered 5 ms later, spread
        # over four seconds. Frame numbers step so that each paging block is
        # visited; the target 0x11223344 is paged at a frame with fn mod 3 == 1.
        subs = ['11223344', '55667788', '99aabbcc', 'ddeeff00']
        fr = [4, 10, 16, 22]
        for i, t in enumerate(subs):
            fn = fr[i] if i == 0 else (fr[i] // 3) * 3
            frames.append(eth_gsmtap(tmsi_req(t, fn), 0x05, fn, i * 1.0))
            frames.append(eth_gsmtap(tmsi_resp(t, fn), 0x05, fn, i * 1.0 + 0.005))
    elif kind == 'burst':
        # 60 distinct TMSIs paged inside 1.5 s, none answered (ToRPEDO storm)
        for i in range(60):
            t = '%08x' % (0x0A000000 + i)
            fn = i % 51
            frames.append(eth_gsmtap(tmsi_req(t, fn), 0x05, fn, i * 0.025))
    elif kind == 'collision':
        for i in range(6):
            t = '%08x' % (0x0B000000 + i)
            frames.append(eth_gsmtap(tmsi_req(t, 1), 0x05, 1, 0.05 * i))
        for i in range(6):
            t = '%08x' % (0x0B000000 + i)
            frames.append(eth_gsmtap(tmsi_resp(t, 1), 0x05, 1, 1.0 + 0.05 * i))
    else:
        raise SystemExit('unknown fixture kind')

    # sort by time
    frames.sort(key=lambda x: x[0])
    w_pcap(out, frames)

def main():
    argv = sys.argv[1:]
    if not argv:
        raise SystemExit('usage: pgt_py <events|mkfixture> ...')
    mode = argv[0]
    if mode == 'events':
        cmd_events(argv[1])
    elif mode == 'mkfixture':
        cmd_mkfixture(argv[1], argv[2])
    else:
        raise SystemExit('unknown mode ' + mode)

main()
PY
}

# Emit TSV paging events from a pcap:
#   kind <TAB> ts <TAB> frame <TAB> identity_type <TAB> identity
# kind is "request" or "response".
pgt_events() {
    local pcap="${1:-}"
    [[ -f "$pcap" ]] || { printf 'ERROR\tno such capture: %s\n' "${pcap:-<none>}" >&2; return 1; }
    local raw; raw=$(pgt_py events "$pcap") || return 1
    local line ts fn ch msg mt
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        pgt_split "$line"
        ts="${PGT_F[0]:-}"; fn="${PGT_F[1]:-}"; ch="${PGT_F[2]:-}"; msg="${PGT_F[3]:-}"
        [[ -n "$msg" ]] || continue
        mt="${msg:2:2}"
        case "$mt" in
            21|22|23) : ;;
            27) : ;;
            *) continue ;;
        esac
        local kind="request"
        [[ "$mt" == "27" ]] && kind="response"
        local rec
        rec=$(pgt_parse_paging gsm "$msg") || continue
        local itype="" ident=""
        while IFS= read -r l; do
            [[ -z "$l" ]] && continue
            case "$l" in
                identity_type$'\t'*) itype="${l#*$'\t'}" ;;
                identity$'\t'*)      ident="${l#*$'\t'}" ;;
                tmsi$'\t'*)          ident="${l#*$'\t'}" ;;
            esac
        done <<<"$rec"
        [[ -n "$itype" && -n "$ident" ]] || continue
        printf '%s\t%s\t%s\t%s\t%s\n' "$kind" "$ts" "$fn" "$itype" "$ident"
    done <<<"$raw"
}

pgt_event_count() {
    local pcap="$1"; [[ -f "$pcap" ]] || { echo 0; return; }
    pgt_events "$pcap" 2>/dev/null | grep -c . || true
}

# ── ToRPEDO (paging-collision) model ────────────────────────────────────
# The published attack (Hussain et al., NDSS 2019) works because the paging
# occasion is a function of IMSI mod 1024, so a page aimed at one identity
# wakes every identity that shares the occasion. Two consequences are modelled
# here:
#   * collision   — how many distinct identities a single paging occasion wakes
#   * presence    — whether the target answers the page, and when
# The timing of the paging response, not just its presence, is what leaks the
# target's rough distance: the response is separated from the page by the radio
# round trip plus core/processing delay. The model refuses to name a distance
# when the capture carries no response timing.
pgt_torpedo_model() {
    local pcap="${1:-}"
    local ev; ev=$(pgt_events "$pcap") || return 1
    [[ -n "$ev" ]] || { printf 'ERROR\tno paging messages in %s\n' "${pcap:-<none>}" >&2; return 1; }
    local nreq nresp
    nreq=$(printf '%s\n' "$ev"  | awk -F'\t' '$1=="request"{n++} END{print n+0}')
    nresp=$(printf '%s\n' "$ev" | awk -F'\t' '$1=="response"{n++} END{print n+0}')
    (( nreq > 0 )) || { printf 'ERROR\tno paging requests in %s\n' "$pcap" >&2; return 1; }

    printf 'model\tToRPEDO paging-occasion collision (Hussain et al., NDSS 2019)\n'
    printf 'capture\t%s\n' "$(pgt_sanitize "$pcap")"
    printf 'paging_requests\t%d\npaging_responses\t%d\n' "$nreq" "$nresp"

    # Collision: distinct identities sharing one paging occasion (frame).
    local maxcoll
    maxcoll=$(printf '%s\n' "$ev" | awk -F'\t' '$1=="request"{print $3"\t"$5}' \
              | sort -u | awk -F'\t' '{c[$1]++} END{m=0; for(k in c) if(c[k]>m) m=c[k]; print m+0}')
    printf 'max_identities_per_paging_occasion\t%s\n' "${maxcoll:-0}"
    printf 'collision_detected\t%s\n' "$([[ "${maxcoll:-0}" -gt 4 ]] && echo yes || echo no)"

    if (( nresp == 0 )); then
        printf 'status\tnot_determinable\n'
        printf 'reason\t%s\n' "capture carries paging requests but no paging responses: presence and timing are not determinable from this capture"
        return 1
    fi

    # Presence and response timing per identity.
    local ident
    while IFS= read -r ident; do
        [[ -z "$ident" ]] && continue
        local rt
        rt=$(printf '%s\n' "$ev" | awk -F'\t' -v id="$ident" '
            $1=="request"  && $5==id { if (!(id in seen)) { first[id]=$2; seen[id]=1 } }
            $1=="response" && $5==id { print $2 - first[id] }
        ' | head -n1)
        if [[ -z "$rt" ]]; then
            printf 'target\t%s\tpresent\t%s\tresponse_delay_ms\t%s\n' \
                "$(pgt_sanitize "$ident")" "no" "-"
        else
            local ms; ms=$(awk -v d="$rt" 'BEGIN{printf "%.3f", d*1000}')
            printf 'target\t%s\tpresent\tyes\tresponse_delay_ms\t%s\n' \
                "$(pgt_sanitize "$ident")" "$ms"
        fi
    done < <(printf '%s\n' "$ev" | awk -F'\t' '$1=="request"{print $5}' | sort -u)

    # Rough distance from the smallest observed response delay. Below 10 ms the
    # radio round trip can dominate; above it the estimate is processing-bound
    # and is reported as not determinable rather than as a location.
    local mind
    mind=$(printf '%s\n' "$ev" | awk -F'\t' '
        $1=="request"{f[$5]=$2; seen[$5]=1}
        $1=="response" && ($5 in seen){d=$2-f[$5]; if(m==""||d<m) m=d}
        END{if(m=="") print ""; else printf "%.6f", m}')
    if [[ -n "$mind" ]]; then
        local ms; ms=$(awk -v d="$mind" 'BEGIN{printf "%.3f", d*1000}')
        printf 'min_response_delay_ms\t%s\n' "$ms"
        if awk -v d="$mind" 'BEGIN{exit !(d < 0.010)}'; then
            local km; km=$(awk -v d="$mind" 'BEGIN{printf "%.3f", 299792.458*d/2}')
            printf 'location_estimate\tcoarse\ndistance_km_max\t%s\n' "$km"
        else
            printf 'location_estimate\tnot_determinable\n'
            printf 'location_reason\t%s\n' "response delay is processing/core dominated (>10 ms), so it is not a radio-distance measurement"
        fi
    fi

    printf 'sequence\t%s\n' "1. observe the target's paging occasion (IMSI mod 1024 -> block)"
    printf 'sequence\t%s\n' "2. cause the network to page the target (an incoming call, an SMS, a service request)"
    printf 'sequence\t%s\n' "3. co-locate the page with records for other identities sharing the occasion (collision)"
    printf 'sequence\t%s\n' "4. watch for the paging response on the shared occasion: a response proves presence"
    printf 'sequence\t%s\n' "5. compare response timing across pages to bracket the target's distance"
    printf 'status\tdeterminable\n'
    printf 'note\t%s\n' "steps 1-5 are passive observation; injecting paging records to force a collision needs a base station you are authorised to run, which this module does not build"
    return 0
}

# ── paging-based IMSI recovery ("Piercer"/IMSI-Cracking) ────────────────
# Model: the paging occasion is a function of the identity (GSM: IMSI mod 1024
# -> block; LTE: IMSI mod 1024 -> PF/PO). An attacker who triggers a page and
# observes WHICH occasion carries it learns the target's group, and matches it
# against a candidate set. The observed block in a capture is taken as
#   observed_block = frame_number mod blocks_per_multiframe
# with blocks_per_multiframe = BS_PA_MFRMS/2, which is the identity's paging
# block by TS 45.002 §6.5.2 when the capture's frame numbering is that of the
# paging channel.
#
# Timing budget: one observation per triggered page, and one page per paging
# occasion. An occasion recurs every BS_PA_MFRMS multiframes (GSM) or T radio
# frames (LTE). The information per observation is log2(blocks) bits (GSM) or
# log2(T) bits (LTE), so a candidate set of N identities needs
# ceil(log2(N)/log2(blocks)) GSM observations.
pgt_piercer_correlate() {
    local cands="${1:-}" pcap="${2:-}"
    [[ -f "$cands" ]] || { printf 'ERROR\tno such candidate file: %s\n' "${cands:-<none>}" >&2; return 2; }
    [[ -f "$pcap"  ]] || { printf 'ERROR\tno such capture: %s\n' "${pcap:-<none>}" >&2; return 2; }
    local mfrms="${3:-6}"
    [[ "$mfrms" =~ ^[0-9]+$ ]] || return 2
    (( mfrms >= 2 && mfrms <= 9 )) || return 2
    local blocks=$(( mfrms / 2 )); (( blocks >= 1 )) || blocks=1

    local ev; ev=$(pgt_events "$pcap") || return 1
    local req; req=$(printf '%s\n' "$ev" | awk -F'\t' '$1=="request"{print $3"\t"$5}')
    [[ -n "$req" ]] || {
        printf 'status\tnot_determinable\n'
        printf 'reason\t%s\n' "capture carries no paging-request timing, so no occasion can be attributed to a candidate"
        return 1
    }
    local observed
    observed=$(printf '%s\n' "$req" | awk -F'\t' -v b="$blocks" '{print $1 % b}' | sort -u | tr '\n' ' ')
    printf 'model\tpaging-occasion correlation (Hussain et al., NDSS 2019)\n'
    printf 'capture\t%s\ncandidates_file\t%s\nbs_pa_mfrms\t%s\nblocks_per_multiframe\t%s\nobserved_blocks\t%s\n' \
        "$(pgt_sanitize "$pcap")" "$(pgt_sanitize "$cands")" "$mfrms" "$blocks" "$(pgt_sanitize "${observed% }")"

    local total=0 line imsi grp blk score
    local -a rows
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        # Accept a bare IMSI or a TSV first column.
        imsi=$(printf '%s' "$line" | cut -f1)
        [[ "$imsi" =~ ^[0-9]{6,15}$ ]] || continue
        total=$(( total + 1 ))
        grp=$(pgt_paging_group "$imsi") || continue
        blk=$(( grp % blocks ))
        score=0
        for ob in $observed; do
            [[ "$ob" == "$blk" ]] && score=$(( score + 1 ))
        done
        rows+=("$(printf '%d\t%s\t%s\t%s' "$score" "$imsi" "$grp" "$blk")")
    done < "$cands"
    (( total > 0 )) || { printf 'ERROR\tno IMSIs in %s\n' "$cands" >&2; return 1; }

    printf 'candidates\t%d\n' "$total"
    local ranked
    ranked=$(printf '%s\n' "${rows[@]}" | sort -t$'\t' -k1,1nr -k2,2)
    printf 'rank\tscore\timsi\tpaging_group\tblock\n'
    local r=1
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        pgt_split "$line"
        printf '%d\t%s\t%s\t%s\t%s\n' "$r" "${PGT_F[0]}" "$(pgt_sanitize "${PGT_F[1]}")" "${PGT_F[2]}" "${PGT_F[3]}"
        r=$(( r + 1 ))
    done <<<"$ranked"

    local top; top=$(printf '%s\n' "$ranked" | head -n1 | cut -f2)
    local obs_n obs_bits cycles
    obs_n=$(printf '%s\n' "$req" | wc -l | tr -d ' ')
    obs_bits=$(awk -v b="$blocks" 'BEGIN{printf "%.2f", (b>1)?(log(b)/log(2)):0}')
    if (( blocks > 1 )); then
        cycles=$(awk -v n="$total" -v b="$blocks" 'BEGIN{printf "%d", (log(n)/log(2))/(log(b)/log(2)) + 0.999}')
    else
        cycles=0
    fi
    printf 'top_candidate\t%s\n' "$top"
    printf 'observations\t%s\nbits_per_observation\t%s\n' "$obs_n" "$obs_bits"
    if (( blocks > 1 )); then
        printf 'timing_budget_cycles\t%d\n' "$cycles"
        printf 'timing_budget_note\t%s\n' "each cycle is BS_PA_MFRMS multiframes (GSM, 51 frames each, 4.615 ms per frame); ${cycles} triggered pages are needed to separate ${total} candidates"
        printf 'status\trecovered\n'
    else
        printf 'status\tnot_determinable\n'
        printf 'reason\t%s\n' "BS_PA_MFRMS=${mfrms} gives one paging block per multiframe: the occasion carries no information about IMSI mod 1024, so candidates cannot be separated by timing alone"
        return 1
    fi
    return 0
}

# ── paging-anomaly detection ────────────────────────────────────────────
# Signals, all computed from the capture (the honest half of the attack):
#   S1 paging rate per subscriber above the observation window norm
#   S2 paging from an identity that never answers (unexpected TMSI)
#   S3 paging-record density on one occasion above the 1..4 a paging request
#      normally carries (a storm / collision)
#   S4 repeated paging with no paging response following
pgt_detect() {
    local pcap="${1:-}"
    local ev; ev=$(pgt_events "$pcap") || return 1
    [[ -n "$ev" ]] || { printf 'ERROR\tno paging messages in %s\n' "${pcap:-<none>}" >&2; return 1; }
    local nreq nresp
    nreq=$(printf '%s\n' "$ev"  | awk -F'\t' '$1=="request"{n++} END{print n+0}')
    nresp=$(printf '%s\n' "$ev" | awk -F'\t' '$1=="response"{n++} END{print n+0}')
    (( nreq > 0 )) || { printf 'ERROR\tno paging requests in %s\n' "$pcap" >&2; return 1; }

    local span
    span=$(printf '%s\n' "$ev" | awk -F'\t' 'NR==1{lo=$2;hi=$2} {if($2<lo)lo=$2; if($2>hi)hi=$2} END{printf "%.6f", hi-lo}')
    local maxsub maxcoll unanswered repeated
    maxsub=$(printf '%s\n' "$ev" | awk -F'\t' '$1=="request"{c[$5]++} END{m=0; for(k in c) if(c[k]>m)m=c[k]; print m+0}')
    maxcoll=$(printf '%s\n' "$ev" | awk -F'\t' '$1=="request"{print $3"\t"$5}' | sort -u \
              | awk -F'\t' '{c[$1]++} END{m=0; for(k in c) if(c[k]>m)m=c[k]; print m+0}')
    unanswered=$(printf '%s\n' "$ev" | awk -F'\t' '
        $1=="request"{r[$5]=1} $1=="response"{a[$5]=1}
        END{n=0; for(k in r) if(!(k in a)) n++; print n+0}')
    repeated=$(printf '%s\n' "$ev" | awk -F'\t' '
        $1=="request"{r[$5]++} $1=="response"{a[$5]=1}
        END{n=0; for(k in r) if(r[k]>=3 && !(k in a)) n++; print n+0}')

    printf 'capture\t%s\n' "$(pgt_sanitize "$pcap")"
    printf 'window_seconds\t%s\npaging_requests\t%d\npaging_responses\t%d\n' "$span" "$nreq" "$nresp"
    printf 'max_pages_per_subscriber\t%s\n' "$maxsub"
    printf 'max_records_per_occasion\t%s\n' "$maxcoll"
    printf 'identities_never_answering\t%s\n' "$unanswered"
    printf 'identities_paged_3plus_without_answer\t%s\n' "$repeated"

    local hits=0 findings=""
    if (( maxsub > 10 )); then
        hits=$(( hits + 1 )); findings+="S1 paging_rate_per_subscriber=$maxsub;"
    fi
    if (( unanswered > 50 )); then
        hits=$(( hits + 1 )); findings+="S2 unexpected_tmsi_unanswered=$unanswered;"
    fi
    if (( maxcoll > 4 )); then
        hits=$(( hits + 1 )); findings+="S3 paging_record_density=$maxcoll;"
    fi
    if (( repeated > 0 )); then
        hits=$(( hits + 1 )); findings+="S4 repeated_paging_no_answer=$repeated;"
    fi
    printf 'findings\t%s\n' "$(pgt_sanitize "${findings:-none}")"
    printf 'signal_hits\t%d\n' "$hits"
    if (( hits > 0 )); then
        printf 'verdict\tpaging_anomaly\n'
        printf 'note\t%s\n' "a paging storm is indistinguishable from an aggressive but legitimate paging load without the reference norm for the cell; the operator's own counters are the record that settles it"
        return 0
    fi
    printf 'verdict\tnormal\n'
    return 0
}

# ── plan files (handoff) ────────────────────────────────────────────────
pgt_plan() {
    local kind="${1:-}"
    case "$kind" in
        torpedo|piercer) ;;
        *) printf 'ERROR\tunknown plan: %s (want torpedo|piercer)\n' "${kind:-<none>}" >&2; return 2 ;;
    esac
    local hw ts f
    hw="a base-station testbed you are authorised to run (Osmocom osmo-bts + osmo-bsc, or srsRAN with a USRP B210 / LimeSDR), a programmable SIM, and a faraday-isolated or licensed test cell"
    ts=$(date +%Y%m%d_%H%M%S)
    mkdir -p "$PGT_PLAN_DIR"
    f="$PGT_PLAN_DIR/plan_${kind}_${ts}.txt"
    {
        echo "plan: $kind"
        echo "status: handoff"
        echo "hardware: $hw"
        echo "ts: $(date -Is)"
        echo
        if [[ "$kind" == "torpedo" ]]; then
            cat <<'EOF'
objective
  Reproduce ToRPEDO (Hussain et al., NDSS 2019): show that a paging occasion
  is a function of IMSI mod 1024, so that a small number of paging records
  wakes many identities, and that the paging response reveals presence.

why this needs hardware
  The passive half is in this module: --detect reads a capture, --po computes
  the occasion. The active half needs a base station that can send PAGING
  REQUEST messages on a chosen paging occasion. That is a transmit path with
  an operator licence, not a software step.

prerequisites
  * an authorised base-station testbed (osmo-bts + osmo-bsc, or srsRAN + USRP)
  * a test cell whose PLMN you are permitted to transmit
  * at least two programmable SIMs whose IMSIs share a paging occlusion
    (IMSI mod 1024 equal for the same BS_PA_MFRMS), or LTE UEs with equal
    IMSI mod 1024
  * a passive receiver for the response timing (the same SDR, receive-only)

procedure
  1. Compute the occasion:  modules/33_paging_track.sh --po <imsi> <mfrms> gsm
  2. Page identity A on its occasion and record the response delay.
  3. Page identity B on the same occasion. Both wake. Record both responses.
  4. Vary the page time and compare the response delay distribution.
EOF
        else
            cat <<'EOF'
objective
  Reproduce paging-based IMSI recovery (IMSI-Cracking, Hussain et al., NDSS
  2019): trigger a page to the target, observe which paging occasion carries
  it, and match the occasion against a candidate IMSI set.

why this needs hardware
  The attacker must cause the network to page the target (an incoming call or
  SMS is enough) and must then observe the paging occasion. Observation is
  passive and legal where the spectrum is licensed to the observer; causing a
  page against a third party is not something this module does.

prerequisites
  * a passive receiver on the paging channel with frame-number accuracy
  * a way to trigger a page to the target that you are authorised to use
    (a call or SMS to the target's own number, with the target's consent)
  * a candidate IMSI set (the correlation input)

procedure
  1. Trigger one page and capture the paging occasion:
       modules/33_paging_track.sh --detect capture.pcap
  2. Correlate against the candidate set:
       modules/33_paging_track.sh --piercer-correlate candidates.txt capture.pcap 6
  3. Repeat until the top candidate is stable; the timing budget printed by
     the verb states how many triggered pages are needed.
EOF
        fi
    } | tee "$f"
    printf 'plan_file\t%s\nstatus\thandoff\n' "$f"
    return 0
}

# ── CLI verbs ───────────────────────────────────────────────────────────
pgt_cli_status_tsv() {
    local py="none" radio="none"
    command -v python3 >/dev/null 2>&1 && py="python3"
    command -v hackrf_info >/dev/null 2>&1 && radio="hackrf"
    [[ "$radio" == "none" ]] && command -v uhd_find_devices >/dev/null 2>&1 && radio="usrp"
    [[ "$radio" == "none" ]] && command -v rtl_test >/dev/null 2>&1 && radio="rtlsdr"
    printf 'module\tpaging_track\n'
    printf 'tag\tpgt\n'
    printf 'pcap_reader\t%s\n' "$py"
    printf 'radio\t%s\n' "$radio"
    printf 'dir\t%s\n' "$PGT_DIR"
    printf 'plan_dir\t%s\n' "$PGT_PLAN_DIR"
    printf 'gsm_paging_group\t%s\n' "IMSI mod 1024 (TS 45.002 6.5.2)"
    printf 'gsm_paging_block\t%s\n' "group mod (BS_PA_MFRMS div 2)"
    printf 'lte_pf\t%s\n' "SFN mod T = (T div N)*(UE_ID mod N) (TS 36.304 7.2)"
    printf 'nr_pf\t%s\n' "(SFN + PF_offset) mod T = (T div N)*(UE_ID mod N) (TS 38.304 7.1)"
}

pgt_cmd_po() {
    local imsi="${1:-}" arg="${2:-}" gen="${3:-gsm}" extra="${4:-}" extra2="${5:-}"
    [[ -n "$imsi" && -n "$arg" ]] || {
        printf 'ERROR\tusage: --po <imsi> <mfrms|T> <gsm|lte|nr> [nB] [pf_offset|fdd|tdd]\n' >&2
        return 2
    }
    case "$gen" in
        gsm) pgt_gsm_params "$imsi" "$arg" "${extra:-1}" ;;
        lte) pgt_lte_params "$imsi" "$arg" "$extra" "${extra2:-fdd}" ;;
        nr)  pgt_nr_params  "$imsi" "$arg" "$extra" "${extra2:-0}" ;;
        *)   printf 'ERROR\tunknown generation: %s (want gsm|lte|nr)\n' "$gen" >&2; return 2 ;;
    esac
}

pgt_cmd_paging_parse() {
    local h="${1:-}" gen="${2:-gsm}"
    [[ -n "$h" ]] || { printf 'ERROR\tusage: --paging-parse <hex> [gsm|lte|nr]\n' >&2; return 2; }
    pgt_parse_paging "$gen" "$h"
}

pgt_cmd_torpedo() {
    local p="${1:-}"
    [[ -n "$p" ]] || { printf 'ERROR\tusage: --torpedo-model <pcap>\n' >&2; return 2; }
    pgt_torpedo_model "$p"
}

pgt_cmd_piercer() {
    local c="${1:-}" p="${2:-}" m="${3:-6}"
    [[ -n "$c" && -n "$p" ]] || {
        printf 'ERROR\tusage: --piercer-correlate <candidates-file> <pcap> [mfrms]\n' >&2; return 2; }
    pgt_piercer_correlate "$c" "$p" "$m"
}

pgt_cmd_detect() {
    local p="${1:-}"
    [[ -n "$p" ]] || { printf 'ERROR\tusage: --detect <pcap>\n' >&2; return 2; }
    pgt_detect "$p"
}

# ── selftest — no radio, no root, no network ────────────────────────────
pgt_selftest() {
    local bad=0 nchk=0
    chk() {
        nchk=$(( nchk + 1 ))
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$(( bad + 1 )); fi
    }
    fld() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }

    local d out rc
    d=$(mktemp -d "$MOD_TMP/selftest.XXXXXX") || {
        printf 'ERROR\tmktemp failed under %s\n' "$MOD_TMP" >&2; return 1; }
    trap 'rm -rf "$d"' EXIT
    export LOOT_DIR="$d/loot" CAPTURES_DIR="$d/captures" STATE_DIR="$d/state"
    export PGT_DIR="$d/loot/paging_track"
    export PGT_PLAN_DIR="$PGT_DIR/plans"
    mkdir -p "$PGT_DIR" "$PGT_PLAN_DIR"

    # 1. GSM paging group = IMSI mod 1024 (TS 45.002 6.5.2).
    chk gsm-group-310150123456789 "$(pgt_paging_group 310150123456789)" "277"
    chk gsm-group-208011234567890 "$(pgt_paging_group 208011234567890)" "722"
    chk gsm-group-123456789012345 "$(pgt_paging_group 123456789012345)" "889"
    chk gsm-group-001010000000001 "$(pgt_paging_group 001010000000001)" "1"
    chk gsm-group-bad "$(pgt_paging_group not-an-imsi >/dev/null 2>&1; echo $?)" "1"
    chk gsm-group-short "$(pgt_paging_group 12345 >/dev/null 2>&1; echo $?)" "1"

    # 2. Block index = group mod (BS_PA_MFRMS div 2).
    chk gsm-block-277-mfrms6 "$(pgt_paging_block 310150123456789 6)" "1"
    chk gsm-block-722-mfrms6 "$(pgt_paging_block 208011234567890 6)" "2"
    chk gsm-block-889-mfrms8 "$(pgt_paging_block 123456789012345 8)" "1"
    chk gsm-block-277-mfrms2 "$(pgt_paging_block 310150123456789 2)" "0"
    out=$(pgt_gsm_params 310150123456789 6 1)
    chk gsm-params-block "$(fld "$out" paging_block_index)" "1"
    chk gsm-params-ccch  "$(fld "$out" ccch_block_index)"  "2"
    chk gsm-params-bad-mfrms "$(pgt_gsm_params 310150123456789 99 >/dev/null 2>&1; echo $?)" "1"

    # 3. LTE PF/PO (TS 36.304 7.2, Table 7.2-1).
    out=$(pgt_lte_params 277 64 64)
    chk lte-277-64-64-n  "$(fld "$out" n)"  "64"
    chk lte-277-64-64-ns "$(fld "$out" ns)" "1"
    chk lte-277-64-64-sfn "$(fld "$out" pf_sfn)" "21"
    chk lte-277-64-64-sub "$(fld "$out" po_subframe)" "9"
    # T div N != 1: nB = T/4 = 16 -> N=16, T div N = 4, PF = 4*(277 mod 16) = 20
    out=$(pgt_lte_params 277 64 16)
    chk lte-tdivn "$(fld "$out" t_div_n)" "4"
    chk lte-tdivn-n "$(fld "$out" n)" "16"
    chk lte-tdivn-sfn "$(fld "$out" pf_sfn)" "20"
    chk lte-tdivn-sub "$(fld "$out" po_subframe)" "9"
    # Ns=2: nB = 2T -> i_s = floor(722/64) mod 2 = 1 -> subframe 9
    out=$(pgt_lte_params 722 64 128)
    chk lte-ns2 "$(fld "$out" ns)" "2"
    chk lte-ns2-is "$(fld "$out" i_s)" "1"
    chk lte-ns2-sfn "$(fld "$out" pf_sfn)" "18"
    chk lte-ns2-sub "$(fld "$out" po_subframe)" "9"
    # Ns=4: i_s = 11 mod 4 = 3 -> subframe 9 (FDD) / 6 (TDD)
    out=$(pgt_lte_params 722 64 256)
    chk lte-ns4-is "$(fld "$out" i_s)" "3"
    chk lte-ns4-tdd "$(fld "$(pgt_lte_params 722 64 256 tdd)" po_subframe)" "6"
    out=$(pgt_lte_params 889 128 128)
    chk lte-889-128-sfn "$(fld "$out" pf_sfn)" "121"
    chk lte-bad-t   "$(pgt_lte_params 277 100 100 >/dev/null 2>&1; echo $?)" "1"
    chk lte-bad-nb  "$(pgt_lte_params 277 64 7 >/dev/null 2>&1; echo $?)" "1"
    chk lte-bad-ue  "$(pgt_lte_params 5000 64 64 >/dev/null 2>&1; echo $?)" "1"

    # 4. NR PF/PO (TS 38.304 7.1).
    out=$(pgt_nr_params 277 32 32 0)
    chk nr-277-32-sfn "$(fld "$out" pf_sfn)" "21"
    chk nr-277-32-po  "$(fld "$out" po_index)" "1"
    out=$(pgt_nr_params 722 64 64 1)
    chk nr-offset-sfn "$(fld "$out" pf_sfn)" "17"
    chk nr-offset-rhs "$(fld "$out" pf_rhs)" "18"
    out=$(pgt_nr_params 277 128 32 0)
    chk nr-tdivn "$(fld "$out" t_div_n)" "4"
    chk nr-tdivn-sfn "$(fld "$out" pf_sfn)" "84"
    out=$(pgt_nr_params 722 64 128 0)
    chk nr-ns2-is "$(fld "$out" i_s)" "1"
    chk nr-ns2-po "$(fld "$out" po_index)" "2"
    chk nr-bad-off "$(pgt_nr_params 277 32 32 9 >/dev/null 2>&1; echo $?)" "1"
    chk nr-bad-t   "$(pgt_nr_params 277 50 50 >/dev/null 2>&1; echo $?)" "1"

    # 5. Mobile identity parse — libosmocore known-answer vectors.
    out=$(pgt_parse_mi 1932547698103254)
    chk mi-imsi-15-type  "$(fld "$out" identity_type)" "IMSI"
    chk mi-imsi-15-value "$(fld "$out" identity)" "123456789012345"
    out=$(pgt_parse_mi 11325476981032f4)
    chk mi-imsi-14-odd  "$(fld "$out" odd_even)" "even"
    chk mi-imsi-14-value "$(fld "$out" identity)" "12345678901234"
    out=$(pgt_parse_mi 413224f3)
    chk mi-imsi-423423 "$(fld "$out" identity)" "423423"
    out=$(pgt_parse_mi 49322453)
    chk mi-imsi-4234235 "$(fld "$out" identity)" "4234235"
    out=$(pgt_parse_mi 1a32547698103254)
    chk mi-imei-type "$(fld "$out" identity_type)" "IMEI"
    chk mi-imei-value "$(fld "$out" identity)" "123456789012345"
    out=$(pgt_parse_mi 9378563412907856f4)
    chk mi-imeisv-type "$(fld "$out" identity_type)" "IMEISV"
    chk mi-imeisv-value "$(fld "$out" identity)" "9876543210987654"
    out=$(pgt_parse_mi f4aabbccdd)
    chk mi-tmsi-type  "$(fld "$out" identity_type)" "TMSI"
    chk mi-tmsi-value "$(fld "$out" tmsi)" "0xaabbccdd"
    chk mi-bad-type "$(pgt_parse_mi 0032547698103254 >/dev/null 2>&1; echo $?)" "1"
    chk mi-bad-tmsi-len "$(pgt_parse_mi f4aabbcc >/dev/null 2>&1; echo $?)" "1"

    # 6. Paging message parse per generation.
    out=$(pgt_parse_paging gsm "0621081932547698103254")
    chk gsm-page-req-records "$(fld "$out" records)" "1"
    chk gsm-page-req-type "$(fld "$out" identity_type)" "IMSI"
    chk gsm-page-req-value "$(fld "$out" identity)" "123456789012345"
    out=$(pgt_parse_paging gsm "062105f4aabbccdd")
    chk gsm-page-tmsi-type "$(fld "$out" identity_type)" "TMSI"
    chk gsm-page-tmsi-value "$(fld "$out" tmsi)" "0xaabbccdd"
    # two records in one request: TMSI then IMSI
    out=$(pgt_parse_paging gsm "062105f4aabbccdd081932547698103254")
    chk gsm-page-two-records "$(fld "$out" records)" "2"
    # Paging Response (libosmocore): 0627 00 03 505886 04 19325476 -> IMSI 1234567
    out=$(pgt_parse_paging gsm "062700035058860419325476")
    chk gsm-page-resp-type "$(fld "$out" identity_type)" "IMSI"
    chk gsm-page-resp-value "$(fld "$out" identity)" "1234567"
    out=$(pgt_parse_paging lte "1932547698103254")
    chk lte-page-imsi "$(fld "$out" identity)" "123456789012345"
    out=$(pgt_parse_paging lte "f45a42e40412")
    chk lte-page-stmsi-type "$(fld "$out" identity_type)" "S-TMSI"
    chk lte-page-stmsi-mmec "$(fld "$out" mmec)" "0x5a"
    chk lte-page-stmsi-mtmsi "$(fld "$out" m_tmsi)" "0x42e40412"
    out=$(pgt_parse_paging nr "f4000000000001")
    chk nr-page-stmsi-type "$(fld "$out" identity_type)" "5G-S-TMSI"
    chk nr-page-stmsi-tmsi "$(fld "$out" 5g_tmsi)" "0x00000001"
    chk page-bad-gen "$(pgt_parse_paging wimax aabb >/dev/null 2>&1; echo $?)" "2"
    chk page-bad-hex "$(pgt_parse_paging gsm zz >/dev/null 2>&1; echo $?)" "2"

    # 7. Capture fixtures: the Torpedo model must say "not determinable" when
    #    the capture has no paging-response timing.
    pgt_py mkfixture "$d/normal.pcap" normal
    pgt_py mkfixture "$d/burst.pcap"  burst
    pgt_py mkfixture "$d/coll.pcap"   collision
    chk fixture-normal-events "$(pgt_event_count "$d/normal.pcap")" "8"
    chk fixture-burst-events  "$(pgt_event_count "$d/burst.pcap")"  "60"
    out=$(pgt_torpedo_model "$d/normal.pcap"); rc=$?
    chk torpedo-normal-rc     "$rc" "0"
    chk torpedo-normal-status "$(fld "$out" status)" "determinable"
    chk torpedo-normal-present "$(printf '%s\n' "$out" | awk -F'\t' '$1=="target" && $4=="yes"{n++} END{print n+0}')" "4"
    out=$(pgt_torpedo_model "$d/burst.pcap"); rc=$?
    chk torpedo-burst-rc     "$rc" "1"
    chk torpedo-burst-status "$(fld "$out" status)" "not_determinable"
    chk torpedo-burst-no-guess "$(printf '%s\n' "$out" | grep -c '^location_estimate')" "0"
    out=$(pgt_torpedo_model "$d/coll.pcap")
    chk torpedo-collision "$(fld "$out" collision_detected)" "yes"
    chk torpedo-bad-pcap "$(pgt_torpedo_model /nonexistent.pcap >/dev/null 2>&1; echo $?)" "1"

    # 8. IMSI recovery by occasion correlation. One observation cannot split
    #    candidates that share a paging block: the true IMSI must score at the
    #    top, and a candidate in a different block must score zero.
    printf '310150123456789\n208011234567890\n123456789012345\n001010000000001\n' > "$d/cands.txt"
    out=$(pgt_piercer_correlate "$d/cands.txt" "$d/normal.pcap" 6); rc=$?
    chk piercer-rc "$rc" "0"
    chk piercer-top "$(fld "$out" top_candidate | awk '{print ($1=="310150123456789"||$1=="123456789012345"||$1=="001010000000001")?"in-block":"wrong"}')" "in-block"
    chk piercer-true-score  "$(printf '%s\n' "$out" | awk -F'\t' '$3=="310150123456789"{print $2}')" "1"
    chk piercer-other-score "$(printf '%s\n' "$out" | awk -F'\t' '$3=="208011234567890"{print $2}')" "0"
    # mfrms=2 -> one block -> no information -> not determinable, non-zero.
    out=$(pgt_piercer_correlate "$d/cands.txt" "$d/normal.pcap" 2); rc=$?
    chk piercer-mfrms2-rc "$rc" "1"
    chk piercer-mfrms2-status "$(fld "$out" status)" "not_determinable"
    chk piercer-no-cands "$(pgt_piercer_correlate /nonexistent "$d/normal.pcap" >/dev/null 2>&1; echo $?)" "2"

    # 9. Paging-anomaly detector, both directions.
    out=$(pgt_detect "$d/burst.pcap")
    chk detect-burst "$(fld "$out" verdict)" "paging_anomaly"
    out=$(pgt_detect "$d/normal.pcap")
    chk detect-normal "$(fld "$out" verdict)" "normal"
    chk detect-bad "$(pgt_detect /nonexistent.pcap >/dev/null 2>&1; echo $?)" "1"

    # 10. Plans are handoff, name the radio and the layer-2 position.
    out=$(pgt_plan torpedo)
    chk plan-torpedo-status "$(printf '%s\n' "$out" | grep -c '^status: handoff')" "1"
    chk plan-torpedo-plan   "$(printf '%s\n' "$out" | grep -c '^plan_file')" "1"
    out=$(pgt_plan piercer)
    chk plan-piercer-status "$(printf '%s\n' "$out" | grep -c '^status: handoff')" "1"
    pf=$(find "$PGT_PLAN_DIR" -name 'plan_torpedo_*.txt' | head -n1)
    chk plan-file-radio "$([[ "$(grep -ci 'USRP\|LimeSDR\|base-station' "$pf")" -ge 1 ]] && echo yes || echo no)" "yes"
    chk plan-file-handoff "$(grep -c '^status: handoff' "$pf")" "1"
    chk plan-unknown "$(pgt_plan nope >/dev/null 2>&1; echo $?)" "2"

    # 11. Verb validation.
    chk v-po-missing "$(pgt_cmd_po >/dev/null 2>&1; echo $?)" "2"
    chk v-po-bad-gen "$(pgt_cmd_po 310150123456789 6 watts >/dev/null 2>&1; echo $?)" "2"
    chk v-parse-missing "$(pgt_cmd_paging_parse >/dev/null 2>&1; echo $?)" "2"
    chk v-torpedo-missing "$(pgt_cmd_torpedo >/dev/null 2>&1; echo $?)" "2"
    chk v-piercer-missing "$(pgt_cmd_piercer >/dev/null 2>&1; echo $?)" "2"
    chk v-detect-missing "$(pgt_cmd_detect >/dev/null 2>&1; echo $?)" "2"

    # 12. Status TSV invariants.
    out=$(pgt_cli_status_tsv)
    chk status-dir "$(fld "$out" dir)" "$PGT_DIR"
    chk status-tag "$(fld "$out" tag)" "pgt"

    printf 'ASSERTIONS\t%d\n' "$nchk"
    rm -rf "$d"
    trap - EXIT
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ── menu ────────────────────────────────────────────────────────────────
pgt_menu() {
    while true; do
        banner
        echo -e "  ${C_MAG}=== paging track ===${C_RESET}"
        echo -e "  loot: ${C_DIM}$PGT_DIR${C_RESET}\n"
        cat <<'M'
  [1]  GSM paging occasion  (IMSI mod 1024)
  [2]  LTE paging frame/occasion  (TS 36.304)
  [3]  NR paging frame/occasion   (TS 38.304)
  [4]  parse a paging record (hex)
  [5]  ToRPEDO model from a capture
  [6]  IMSI recovery: correlate candidates against a capture
  [7]  detect a paging anomaly in a capture
  [8]  write a handoff plan (torpedo / piercer)
  [0]  back

M
        read -rp "  choice> " c || return 0  # EOF: leave the menu cleanly
        case "$c" in
            1) read -rp "  IMSI> " i; read -rp "  BS_PA_MFRMS (2-9)> " m
               pgt_cmd_po "$i" "$m" gsm | column -t -s$'\t' 2>/dev/null || true
               read -rp "  press enter " _ ;;
            2) read -rp "  IMSI (UE_ID = IMSI mod 1024)> " i
               read -rp "  T (32|64|128|256)> " t
               read -rp "  nB (blank = T)> " nb
               pgt_cmd_po "$i" "$t" lte "$nb" | column -t -s$'\t' 2>/dev/null || true
               read -rp "  press enter " _ ;;
            3) read -rp "  UE_ID (5G-S-TMSI mod 1024)> " i
               read -rp "  T (32|64|128|256)> " t
               read -rp "  nB (blank = T)> " nb
               read -rp "  PF_offset (0-3)> " off
               pgt_cmd_po "$i" "$t" nr "$nb" "$off" | column -t -s$'\t' 2>/dev/null || true
               read -rp "  press enter " _ ;;
            4) read -rp "  hex> " x; read -rp "  gen (gsm|lte|nr)> " g
               pgt_cmd_paging_parse "$x" "$g" | column -t -s$'\t' 2>/dev/null || true
               read -rp "  press enter " _ ;;
            5) read -rp "  pcap> " p; pgt_cmd_torpedo "$p" | column -t -s$'\t' 2>/dev/null || true
               read -rp "  press enter " _ ;;
            6) read -rp "  candidates file> " cf; read -rp "  pcap> " p
               pgt_cmd_piercer "$cf" "$p" | column -t -s$'\t' 2>/dev/null || true
               read -rp "  press enter " _ ;;
            7) read -rp "  pcap> " p; pgt_cmd_detect "$p" | column -t -s$'\t' 2>/dev/null || true
               read -rp "  press enter " _ ;;
            8) read -rp "  plan (torpedo|piercer)> " k; pgt_plan "$k"; read -rp "  press enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ── CLI dispatch ────────────────────────────────────────────────────────
pgt_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)       pgt_cli_status_tsv ;;
        --po)               pgt_cmd_po "${1:-}" "${2:-}" "${3:-gsm}" "${4:-}" "${5:-}" ;;
        --paging-parse)     pgt_cmd_paging_parse "${1:-}" "${2:-gsm}" ;;
        --torpedo-model)    pgt_cmd_torpedo "${1:-}" ;;
        --piercer-correlate) pgt_cmd_piercer "${1:-}" "${2:-}" "${3:-6}" ;;
        --detect)           pgt_cmd_detect "${1:-}" ;;
        --plan)             pgt_plan "${1:-}" ;;
        --selftest)         pgt_selftest ;;
        --menu)             pgt_menu ;;
        *)
            cat >&2 <<EOF
Paging Track — paging occasions, ToRPEDO, paging-based IMSI recovery

Usage: $0 COMMAND
  --status-tsv                          module state as TSV
  --po <imsi> <mfrms|T> <gsm|lte|nr> [nB] [pf_offset|fdd|tdd]
                                        paging group/block or PF/PO
  --paging-parse <hex> [gsm|lte|nr]     paging record identity and value
  --torpedo-model <pcap>                collision and response-timing model
  --piercer-correlate <cands> <pcap> [mfrms]
                                        rank candidate IMSIs by occasion
  --detect <pcap>                       paging-anomaly signals and verdict
  --plan <torpedo|piercer>              write a handoff plan
  --selftest                            verify arithmetic and parsers, no radio
  --menu                                interactive menu

Formulas (cited): TS 45.002 6.5.2 (GSM), TS 36.304 7.2 (LTE),
TS 38.304 7.1 (NR). ToRPEDO and paging-based IMSI recovery: Hussain,
Echeverria, Chowdhury, Li, Bertino, NDSS 2019.
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
    pgt_cli_main "$@"
fi
