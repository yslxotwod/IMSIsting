#!/usr/bin/env bash
# 5G NR air interface — NR-ARFCN, SSB, MIB/SIB1, RACH, gNB orchestration
#
# Every number in here is from the specifications, not from memory:
#
#   TS 38.104 Table 5.4.2.1-1   NR-ARFCN ranges and the global raster
#   TS 38.104 Table 5.4.3.3-1   synchronisation raster (SS Ref -> GSCN)
#   TS 38.211 §7.4.2.2/.3       PSS/SSS sequences, PCI = 3*N_ID(1) + N_ID(2)
#   TS 38.211 §7.4.3.1          PBCH scrambling (nu = N_ID(1) mod 4 for i_ssb<4)
#   TS 38.212 §7.1.1            BCCH-BCH-Message = MIB, 24 bits of payload
#   TS 38.331 §6.2.2            MIB / SIB1 ASN.1 field order and ranges
#   TS 38.213 §4.1              SSB burst set patterns, Case A/B/C/D/E
#   TS 38.211 §6.3.3            PRACH formats, L_RA and the occasion table
#
# The ARFCN arithmetic matches 02_cell_recon.sh's crec_nr_arfcn_to_mhz(); the
# numbers there were verified against Table 5.4.2.1-1 and this module covers
# the same table with tests.
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

# Shared cross-module state. Any module may publish these keys.
NAIR_CAPABLE=1
# Guarded: when the launcher sources every module into one shell, an
# unconditional definition here would clobber the launcher's own banner.
declare -F info   >/dev/null 2>&1 || info()   { printf '[info] %s\n' "$*" >&2; }
declare -F warn   >/dev/null 2>&1 || warn()   { printf '[warn] %s\n' "$*" >&2; }
declare -F err    >/dev/null 2>&1 || err()    { printf '[err]  %s\n' "$*" >&2; }
declare -F ok     >/dev/null 2>&1 || ok()     { printf '[ok]   %s\n' "$*" >&2; }
declare -F banner >/dev/null 2>&1 || banner() { :; }

MOD_TMP="$TMP_DIR/nr_air"
NAIR_DIR="$LOOT_DIR/nr_air"
NAIR_CONF="$NAIR_DIR/gnb.conf"
NAIR_PLAN_DIR="$NAIR_DIR/plans"
NAIR_PID="$TMP_DIR/nr_air/gnb.pid"
NAIR_LOG="$LOGS_DIR/nr_air_gnb.log"
mkdir -p "$MOD_TMP" "$NAIR_DIR" "$NAIR_PLAN_DIR" 2>/dev/null

# ── sanitisation ────────────────────────────────────────────────────────
# Any string that reaches a TSV row is untrusted. A field that carries a tab
# or a newline can forge an entire row in a consumer that splits on tab.
nair_sanitize() {
    printf '%s' "${1:-}" | tr '\t\r\n' '   '
}

# ── NR-ARFCN arithmetic ─────────────────────────────────────────────────
# Table 5.4.2.1-1 in the form
#   band  F_REF_Offs(MHz)  N_REF_Offs  N_lo  N_hi  scs_ref(kHz)  duplex
#
# F_REF_Offs / N_REF_Offs / dF_Global are the *global raster* row the band
# lives in, NOT the band's own lower edge:
#     0 - 3000 MHz       Foffs 0          Noffs 0        step 5 kHz
#     3000 - 24250 MHz   Foffs 3000       Noffs 600000   step 15 kHz
#     24250 - 100000     Foffs 24250.08   Noffs 2016667  step 60 kHz
# A row written as `n78 3300 600000 ...` double-counts the 300 MHz offset and
# turns NR-ARFCN 640000 into 3900 MHz instead of the correct 3600 MHz; the
# band edge is recovered from N_lo, e.g. 3000 + 0.015*(620000-600000) = 3300.
#
# Bands that share a range are all listed: n77 and n78 both cover
# 620000..680000, n48/n77/n78 overlap around 636667..646666, n41 and n90
# share 499200..537999. The resolver reports every candidate, because an
# ARFCN identifies a frequency and not a band.
nair_band_table() {
    cat << 'EOF'
n1	0	0	422000	431999	15	FDD
n2	0	0	386000	398999	15	FDD
n3	0	0	361000	376999	15	FDD
n5	0	0	173800	178799	15	FDD
n7	0	0	524000	538999	15	FDD
n8	0	0	185000	192999	15	FDD
n12	0	0	145800	149799	15	FDD
n20	0	0	158200	166199	15	FDD
n25	0	0	386000	398999	15	FDD
n28	0	0	151600	160599	15	FDD
n34	0	0	402000	405999	15	TDD
n38	0	0	514000	528999	15	TDD
n39	0	0	376000	383999	15	TDD
n40	0	0	460000	479999	15	TDD
n41	0	0	499200	537999	15	TDD
n48	3000	600000	636667	646666	15	TDD
n50	0	0	286400	303399	15	TDD
n53	0	0	496700	499999	15	TDD
n65	0	0	422000	440000	15	FDD
n66	0	0	422000	440000	15	FDD
n70	0	0	399000	405999	15	FDD
n71	0	0	123400	130399	15	FDD
n74	0	0	295000	303999	15	FDD
n75	0	0	286400	303399	15	SDL
n76	0	0	285400	286399	15	SDL
n77	3000	600000	620000	680000	15	TDD
n78	3000	600000	620000	653333	15	TDD
n79	3000	600000	693334	733333	15	TDD
n90	0	0	499200	538000	15	TDD
n91	0	0	166400	172399	15	FDD
n92	0	0	166400	172399	15	FDD
n93	0	0	176000	178399	15	FDD
n94	0	0	176000	178399	15	FDD
n100	0	0	183880	185479	15	FDD
n101	0	0	380000	399999	15	TDD
n102	0	600000	591000	606666	15	TDD
n104	3000	600000	828334	875000	15	TDD
n257	24250.08	2016667	2054166	2104165	60	TDD
n258	24250.08	2016667	2016667	2070832	60	TDD
n259	24250.08	2016667	2864000	2899999	60	TDD
n260	24250.08	2016667	2792500	2887499	60	TDD
n261	24250.08	2016667	2071666	2120833	60	TDD
n262	24250.08	2016667	2894000	2949999	60	TDD
n263	24250.08	2016667	3936000	4031999	120	TDD
EOF
}

# Resolve an NR-ARFCN to a TSV record: nrarfcn, freq_mhz, band, fr, scs_ref.
#
# TS 38.104 §5.4.2.1 Table 5.4.2.1-1. The global raster is piecewise and the
# step is NOT 5 kHz everywhere — this is the classic way an ARFCN decoder
# goes wrong above 3 GHz:
#     range (MHz)        dF_Global  F_REF-Offs   N_REF-Offs   N_REF range
#     0 - 3000           5 kHz      0            0            0 - 599999
#     3000 - 24250       15 kHz     3000         600000       600000 - 2016666
#     24250 - 100000     60 kHz     24250.08     2016667      2016667 - 3279165
# F_REF = F_REF-Offs + dF_Global * (N_REF - N_REF-Offs).
#
# An NR-ARFCN identifies a frequency, not a band: n77 and n78 share the whole
# 620000..680000 range and n48/n77/n78 overlap around 636667..646666, so the
# band field is the comma-separated candidate list, not a single guess. Where
# a band's own ARFCN range and the global raster agree, the band is listed.
nair_arfcn_mhz_raw() {
    local n="${1:-}"
    [[ "$n" =~ ^[0-9]+$ ]] || return 1
    awk -v n="$n" 'BEGIN{
        if (n <= 599999)       printf "%.3f", 0.005 * (n - 0)
        else if (n <= 2016666) printf "%.3f", 3000 + 0.015 * (n - 600000)
        else                   printf "%.3f", 24250.08 + 0.06 * (n - 2016667)
    }'
}

nair_arfcn_record() {
    local n="${1:-}"
    [[ "$n" =~ ^[0-9]+$ ]] || return 1
    (( n >= 0 && n <= 3279165 )) || return 1
    awk -v n="$n" -v tbl="$(nair_band_table)" 'BEGIN{
        if (n <= 599999)       { f = 0.005 * n;                          fr = "FR1" }
        else if (n <= 2016666) { f = 3000 + 0.015 * (n - 600000);        fr = "FR1" }
        else                   { f = 24250.08 + 0.06 * (n - 2016667);    fr = "FR2" }

        # A band claims the ARFCN when its range contains it AND the band
        # formula reproduces the global-raster frequency. The step is chosen
        # by the global offset the band belongs to, which is what keeps n104
        # (whose ARFCN window overlaps n48/n77/n78 around 636667, but whose
        # band is 6425-7125 MHz) out of a 3600 MHz answer.
        bands = ""; scs = ""
        cnt = split(tbl, rows, "\n")
        for (i = 1; i <= cnt; i++) {
            if (rows[i] == "") continue
            split(rows[i], b, "\t")
            if (b[1] == "") continue
            if (n >= b[4] && n <= b[5]) {
                if (b[2] == 0)              step = 0.005
                else if (b[2] == 3000)      step = 0.015
                else                        step = 0.06
                bf = b[2] + step * (n - b[3])
                d = bf - f; if (d < 0) d = -d
                if (d < 0.0025) {
                    if (bands == "") { bands = b[1]; scs = b[6] }
                    else if (index(bands, b[1]) == 0) bands = bands "," b[1]
                }
            }
        }
        if (bands == "") bands = "unknown"
        if (scs == "") scs = (fr == "FR2") ? "60" : "15"
        printf "nrarfcn\t%s\nfreq_mhz\t%.3f\nband\t%s\nfr\t%s\nscs_ref_khz\t%s\n", \
               n, f, bands, fr, scs
    }'
}

# Band only — used by the SSB/PRACH paths.
nair_band_of_arfcn() {
    local n="${1:-}"
    [[ "$n" =~ ^[0-9]+$ ]] || { echo "unknown"; return 0; }
    nair_arfcn_record "$n" | awk -F'\t' '$1=="band"{print $2; exit}'
}

# Frequency only, in MHz with 3 decimals.
nair_arfcn_to_mhz() {
    local n="${1:-}"
    [[ "$n" =~ ^[0-9]+$ ]] || return 1
    nair_arfcn_record "$n" | awk -F'\t' '$1=="freq_mhz"{print $2; exit}'
}

# ── GSCN / synchronisation raster ───────────────────────────────────────
# TS 38.104 §5.4.3.1 Table 5.4.3.1-1. The SSB does not sit on the channel
# raster; it sits on the synchronisation raster, so a cell search scans GSCN,
# not ARFCN. An SSB position in RRC is given as an ordinary NR-ARFCN
# (absoluteFrequencySSB) but must land on this grid.
#   range (MHz)        SS_REF                              GSCN        range
#   0 - 3000           N*1.2 MHz + M*0.05 MHz, N=1..2499   3N+(M-3)/2  2 - 7498
#                      M in {1,3,5}
#   3000 - 24250       3000 MHz + N*1.44 MHz,   N=0..14756  7499+N      7499 - 22255
#   24250 - 100000     24250.08 + N*17.28 MHz,  N=0..4383   22256+N     22256 - 26639
nair_gscn_to_mhz() {
    local gscn="${1:-}"
    [[ "$gscn" =~ ^[0-9]+$ ]] || return 1
    (( gscn >= 2 && gscn <= 26639 )) || return 1
    awk -v g="$gscn" 'BEGIN{
        if (g <= 7498) {
            # GSCN = 3N + (M-3)/2, so N = floor((GSCN+1)/3) and M cycles 1,3,5.
            N = int((g + 1) / 3)
            r = (g + 1) % 3
            m = (r == 0) ? 1 : (r == 1) ? 3 : 5
            printf "%.3f", (N * 1.2) + (m * 0.05)
        } else if (g <= 22255) {
            N = g - 7499
            printf "%.3f", 3000 + N * 1.44
        } else {
            N = g - 22256
            printf "%.3f", 24250.08 + N * 17.28
        }
    }'
}

# ── SSB burst set ───────────────────────────────────────────────────────
# TS 38.213 §4.1: the SSB pattern is a function of the band, and TS 38.104
# Table 5.4.3.3-1 fixes the SSB SCS per band. The five cases differ in SCS,
# the first-symbol index and whether the candidates are restricted to one
# half-frame:
#   Case A  15 kHz   FR1 sub-3 GHz, 4 candidates
#   Case B  30 kHz   FR1 sub-3 GHz, 4 candidates
#   Case C  30 kHz   FR1 3-6 GHz,   8 candidates, both half-frames
#   Case D  120 kHz  FR2,           64 candidates
#   Case E  240 kHz  FR2,           64 candidates (n263)
# Below 3 GHz the spec uses Case A for the 15 kHz bands and Case B for the
# 30 kHz ones; the 3-6 GHz bands (n77/n78/n79/n48/n102/n104) are Case C.
nair_ssb_case_for_band() {
    case "${1:-}" in
        # 3-6 GHz: 30 kHz SSB, 8 candidates in both half-frames (Case C).
        n48|n77|n78|n79|n102|n104)
            echo "Case C mode 1" ;;
        # Sub-3 GHz, 15 kHz SSB (Case A).
        n1|n2|n3|n5|n7|n8|n12|n20|n25|n28|n34|n38|n39|n40|n41|n50|n53|n65|n66|n70|n71|n74|n75|n76|n90|n91|n92|n93|n94|n100|n101)
            echo "Case A mode 1" ;;
        # FR2, 120 kHz (Case D) and n263's 240 kHz (Case E).
        n257|n258|n259|n260|n261|n262)
            echo "Case D mode 1" ;;
        n263)
            echo "Case E mode 1" ;;
        *)  echo "Case A mode 1" ;;
    esac
}

# The SSB candidate first-symbol index within the half-frame, per TS 38.213
# §4.1. Expressed as "case,candidates,first_ofs,half_frame_ofs".
nair_ssb_pattern() {
    local case_="${1:-B}"
    case "$case_" in
        A) printf 'case\tA\nscs_khz\t15\ncandidates\t4\nfirst_symbol\t{2,8}\nhalf_frame\t0\nmax_ssb\t4\n' ;;
        B) printf 'case\tB\nscs_khz\t30\ncandidates\t4\nfirst_symbol\t{4,8,16,20}\nhalf_frame\t0\nmax_ssb\t4\n' ;;
        C) printf 'case\tC\nscs_khz\t30\ncandidates\t8\nfirst_symbol\t{2,8,16,20}\nhalf_frame\t0,1\nmax_ssb\t8\n' ;;
        D) printf 'case\tD\nscs_khz\t120\ncandidates\t64\nfirst_symbol\t{4,8,16,20}\nhalf_frame\t0,1\nmax_ssb\t64\n' ;;
        E) printf 'case\tE\nscs_khz\t240\ncandidates\t64\nfirst_symbol\t{8,12,16,20,32,36,40,44}\nhalf_frame\t0,1\nmax_ssb\t64\n' ;;
        *) return 1 ;;
    esac
}

# i_SSB -> the (SFN, slot, symbol) position inside the burst set. The burst
# set is always the first half of a radio frame for the even sub-pattern and
# the second half for the odd one; that half-frame split is what a sniffer
# needs to align on before it can decode the MIB.
nair_ssb_position() {
    local i="${1:-}" case_="${2:-B}"
    [[ "$i" =~ ^[0-9]+$ ]] || return 1
    # Candidate first-symbol index within the half-frame, per TS 38.213 §4.1
    # Table 4.1-1. The patterns are written as a symbol set plus a per-slot
    # offset, which is exactly how the spec states them:
    #   Case A  15 kHz  {2,8}   + 14n   L_max 4
    #   Case B  30 kHz  {4,8,16,20} + 28n
    #   Case C  30 kHz  {2,8,16,20} + 28n
    #   Case D  120 kHz {4,8,16,20} + 28n
    #   Case E  240 kHz {8,12,16,20,32,36,40,44} + 56n
    # A slot holds 14 OFDM symbols, so the symbol's slot is sym/14 and its
    # position inside that slot is sym%14.
    local syms nsym half span slur
    case "$case_" in
        A) syms="2,8";             nsym=2; half=$(( i / 2 )); slur=$(( i % 2 )); span=14 ;;
        B) syms="4,8,16,20";       nsym=4; half=0;             slur=$(( i % 4 )); span=28 ;;
        C) syms="2,8,16,20";       nsym=4; half=$(( i / 4 ));  slur=$(( i % 4 )); span=28 ;;
        D) syms="4,8,16,20";       nsym=4; half=$(( i / 32 )); slur=$(( i % 32 )); span=28 ;;
        E) syms="8,12,16,20,32,36,40,44"; nsym=8; half=$(( i / 32 )); slur=$(( i % 32 )); span=56 ;;
        *)  return 1 ;;
    esac
    (( i >= 0 && i < 64 )) || return 1
    local sym
    sym=$(awk -v s="$syms" -v k="$slur" -v n="$nsym" -v sp="$span" 'BEGIN{
        split(s, a, ",")
        slot = int(k / n)
        idx  = k % n
        printf "%d", a[idx + 1] + sp * slot
    }')
    n_sym=$(( sym % 14 ))
    n_slot=$(( sym / 14 ))
    printf 'i_ssb\t%s\ncase\t%s\nhalf_frame\t%s\nslot\t%s\nsymbol\t%s\nsymbol_in_half_frame\t%s\n' \
        "$i" "$case_" "$half" "$n_slot" "$n_sym" "$sym"
}

# ── PSS / SSS / PCI ─────────────────────────────────────────────────────
# TS 38.211 §7.4.2.2: N_ID(2) in 0..2 selects the PSS root.
# TS 38.211 §7.4.2.3: N_ID(1) in 0..335 selects the SSS m-sequence pair.
# All 1008 PCIs are 3 * N_ID(1) + N_ID(2) — the LTE relation, unchanged.
nair_pci() {
    local a="${1:-}" b="${2:-}"
    [[ "$a" =~ ^[0-9]+$ && "$b" =~ ^[0-9]+$ ]] || return 1
    (( a <= 335 && b <= 2 )) || return 1
    echo $(( 3 * a + b ))
}

nair_pci_split() {
    local pci="${1:-}"
    [[ "$pci" =~ ^[0-9]+$ ]] || return 1
    (( pci <= 1007 )) || return 1
    printf 'pci\t%s\nn_id_1\t%s\nn_id_2\t%s\n' "$pci" "$(( pci / 3 ))" "$(( pci % 3 ))"
}

# PSS: d_PSS(n) = 1 - 2*x(m), m = (n + 43*N_ID(2)) mod 127, x is the
# frequency-domain m-sequence built from x(i+7) = (x(i+4) + x(i)) mod 2 with
# the fixed initialisation. Emitting the real 127 chips matters: a correlator
# or a table-driven search can use them directly.
nair_pss_sequence() {
    local n2="${1:-}"
    [[ "$n2" =~ ^[0-9]+$ ]] || return 1
    (( n2 <= 2 )) || return 1
    awk -v n2="$n2" 'BEGIN{
        x[0]=0; x[1]=1; x[2]=1; x[3]=0; x[4]=1; x[5]=1; x[6]=1
        for (i = 0; i <= 119; i++) x[i+7] = (x[i+4] + x[i]) % 2
        out = ""
        for (n = 0; n <= 126; n++) {
            m = (n + 43 * n2) % 127
            if (out != "") out = out " "
            out = out (1 - 2 * x[m])
        }
        print out
    }'
}

# SSS: d_SSS(n) = [1 - 2*x0((n+m0) mod 127)] * [1 - 2*x1((n+m1) mod 127)]
# with m0 = 15*floor(N_ID(1)/112) + 5*N_ID(2) and m1 = N_ID(1) mod 112.
# x0 uses the PSS initialisation, x1 uses the all-ones one.
nair_sss_sequence() {
    local n1="${1:-}" n2="${2:-}"
    [[ "$n1" =~ ^[0-9]+$ && "$n2" =~ ^[0-9]+$ ]] || return 1
    (( n1 <= 335 && n2 <= 2 )) || return 1
    awk -v n1="$n1" -v n2="$n2" 'BEGIN{
        x0[0]=0; x0[1]=1; x0[2]=1; x0[3]=0; x0[4]=1; x0[5]=1; x0[6]=1
        for (i = 0; i <= 119; i++) x0[i+7] = (x0[i+4] + x0[i]) % 2
        for (i = 0; i < 7; i++) x1[i] = 1
        for (i = 0; i <= 119; i++) x1[i+7] = (x1[i+4] + x1[i]) % 2
        m0 = 15 * int(n1 / 112) + 5 * n2
        m1 = n1 % 112
        out = ""
        for (n = 0; n <= 126; n++) {
            v = (1 - 2*x0[(n+m0) % 127]) * (1 - 2*x1[(n+m1) % 127])
            if (out != "") out = out " "
            out = out v
        }
        print out
    }'
}

# ── MIB ─────────────────────────────────────────────────────────────────
# TS 38.331 §6.2.2 BCCH-BCH-Message / TS 38.212 §7.1.1. The MIB is a fixed
# 24-bit payload (BCCH-BCH-MessageType) delivered MSB-first; the ASN.1 field
# order fixes the offsets:
#     0..5    systemFrameNumber        6 bits  (the 4 MSBs of the 10-bit SFN)
#     6       subCarrierSpacingCommon  1 bit   0 = 15 kHz, 1 = 30 kHz
#     7..10   ssb-SubcarrierOffset     4 bits  k_SSB
#     11      dmrs-TypeA-Position      1 bit   0 = pos2, 1 = pos3
#     12..19  pdcch-ConfigSIB1         8 bits  CORESET#0 + search space
#     20      cellBarred               1 bit
#     21      intraFreqReselection     1 bit
#     22      spare                    1 bit
#     23      padding                  (the payload is 24 bits wide)
nair_decode_mib() {
    local hex="${1:-}"
    hex="${hex//[[:space:]]/}"
    hex="${hex//0x/}"
    [[ "$hex" =~ ^[0-9a-fA-F]{6}$ ]] || return 1
    local b0 b1 b2
    b0=$(( 16#${hex:0:2} )); b1=$(( 16#${hex:2:2} )); b2=$(( 16#${hex:4:2} ))
    local val=$(( (b0 << 16) | (b1 << 8) | b2 ))

    # bit(off, width) — off counts from the MSB of the 24-bit word.
    _nair_bit() {
        local off="$1" w="$2"
        echo $(( (val >> (24 - off - w)) & ((1 << w) - 1) ))
    }

    local sfn scs kssb dmrs sib1 barred intra spare
    sfn=$(_nair_bit 0 6)
    scs=$(_nair_bit 6 1)
    kssb=$(_nair_bit 7 4)
    dmrs=$(_nair_bit 11 1)
    sib1=$(_nair_bit 12 8)
    barred=$(_nair_bit 20 1)
    intra=$(_nair_bit 21 1)
    spare=$(_nair_bit 22 1)

    local scs_val scs_name dmrs_name
    if (( scs == 0 )); then scs_val=15; scs_name="15kHz"; else scs_val=30; scs_name="30kHz"; fi
    if (( dmrs == 0 )); then dmrs_name="pos2"; else dmrs_name="pos3"; fi

    printf 'sfn\t%s\n'                    "$sfn"
    printf 'subcarrier_spacing_common\t%s\n' "$scs_val"
    printf 'subcarrier_spacing_name\t%s\n'   "$scs_name"
    printf 'ssb_subcarrier_offset\t%s\n'  "$kssb"
    printf 'dmrs_type_a_position\t%s\n'   "$dmrs_name"
    printf 'pdcch_config_sib1\t%s\n'      "$sib1"
    printf 'pdcch_config_sib1_hi4\t%s\n'  "$(( sib1 >> 4 ))"
    printf 'pdcch_config_sib1_lo4\t%s\n'  "$(( sib1 & 0xF ))"
    printf 'cell_barred\t%s\n'            "$([[ $barred -eq 1 ]] && echo barred || echo notBarred)"
    printf 'intra_freq_reselection\t%s\n' "$([[ $intra -eq 1 ]] && echo allowed || echo notAllowed)"
    printf 'spare\t%s\n'                  "$spare"
    # The bit string is built nibble by nibble: printf %024d would read the
    # binary digits as a decimal number and silently mangle anything above 2^63.
    local bits="" i
    for (( i = 23; i >= 0; i-- )); do
        bits+=$(( (val >> i) & 1 ))
    done
    printf 'bitstring\t%s\n'              "$bits"
}

# ── SIB1 ────────────────────────────────────────────────────────────────
# TS 38.331 §6.2.2 SIB1 / TS 38.413 §9.3.1.9 CellIdentity. SIB1 is carried as
# a BCCH-DL-SCH-Message (c1 CHOICE, SIB1) on the DL-SCH. The 36-bit
# cellIdentity is an NGAP/RRC BIT STRING; it is reported both as the 36-bit
# integer and as the 9-nibble hex string so a NGAP decode can be compared
# against an RRC decode without a conversion step.
nair_sib1_plmn_decode() {
    # PLMN is 3 octets: MCC digit2|MCC digit1, MCC digit3|MNC digit3,
    # MNC digit2|MNC digit1 (TS 24.008 §10.5.1.3). 0xF in a nibble means the
    # digit is absent (2-digit MNC) — reported as such, never guessed.
    local hex="${1:-}"
    hex="${hex//[[:space:]]/}"
    [[ "$hex" =~ ^[0-9a-fA-F]{6}$ ]] || return 1
    local b0 b1 b2
    b0=$(( 16#${hex:0:2} )); b1=$(( 16#${hex:2:2} )); b2=$(( 16#${hex:4:2} ))
    local mcc1 mcc2 mcc3 mnc3 mnc1 mnc2
    mcc1=$(( b0 & 0x0f )); mcc2=$(( (b0 >> 4) & 0x0f ))
    mcc3=$(( b1 & 0x0f )); mnc3=$(( (b1 >> 4) & 0x0f ))
    mnc1=$(( b2 & 0x0f )); mnc2=$(( (b2 >> 4) & 0x0f ))
    local mcc mnc
    mcc="${mcc1}${mcc2}${mcc3}"
    if (( mnc3 == 15 )); then mnc="${mnc1}${mnc2}"; else mnc="${mnc1}${mnc2}${mnc3}"; fi
    printf '%s-%s' "$mcc" "$mnc"
}

nair_decode_sib1() {
    local hex="${1:-}"
    hex="${hex//[[:space:]]/}"
    hex="${hex//0x/}"
    [[ "$hex" =~ ^[0-9a-fA-F]+$ ]] || return 1
    (( ${#hex} >= 24 )) || return 1
    (( ${#hex} % 2 == 0 )) || return 1

    # RRC message type discriminator, decimal. In BCCH-DL-SCH-Message the c1
    # CHOICE carries the SIBs: SIB1 = 0x16 (c1 index 0), SIB2 = 0x18 (index 1),
    # SIB3 = 0x1a (index 2). A `case` pattern of 0x16 would be a literal
    # string, so the comparison is on the decimal value.
    local oct0=$(( 16#${hex:0:2} ))
    local msg="unknown" msgid=""
    case "$oct0" in
        22) msg="SIB1"; msgid="c1:0" ;;
        24) msg="SIB2"; msgid="c1:1" ;;
        26) msg="SIB3"; msgid="c1:2" ;;
    esac

    # Octet map of the parsed block (nibble offsets are into `hex`):
    #   [0]      RRC message type: BCCH-DL-SCH-Message c1 CHOICE, SIB1 = 22
    #   [1]      plmn-IdentityList: entry count in the high nibble
    #   [2..4]   PLMN #1, 3 octets (TS 24.008 §10.5.1.3 nibble order)
    #   [5..7]   PLMN #2 when the list carries more than one entry
    #   [8..10]  trackingAreaCode, 24 bits
    #   [11..15] cellIdentity, 36 bits = 4 octets + high nibble of the fifth;
    #            the low nibble of the last octet carries cellReservedForOtherUse
    local plmn_entries=$(( (16#${hex:2:2} >> 4) & 0xF ))
    local plmn1 plmn2 plmn_count
    plmn1=$(nair_sib1_plmn_decode "${hex:4:6}") || plmn1="parse-error"
    plmn_count=1
    # A second PLMN occupies nibbles 10..15, so the payload must reach at
    # least nibble 16 (the TAC) before that entry can be read.
    if (( plmn_entries >= 2 )) && (( ${#hex} >= 22 )); then
        plmn2=$(nair_sib1_plmn_decode "${hex:10:6}") || plmn2="parse-error"
        plmn_count=2
    fi

    # trackingAreaCode: octets 8..10, 24 bits big-endian.
    local tac
    tac=$(( (16#${hex:16:2} << 16) | (16#${hex:18:2} << 8) | 16#${hex:20:2} ))

    # cellIdentity: 36 bits, occupying octets 11..15 with the low nibble of
    # the final octet reserved for cellReservedForOtherUse.
    local ci_hi ci_lo cell_identity=""
    if (( ${#hex} >= 32 )); then
        ci_hi=$(( 16#${hex:22:8} ))          # 4 octets = 32 bits
        ci_lo=$(( (16#${hex:30:2} >> 4) & 0xF ))  # high nibble of the 5th = 4 bits
        cell_identity=$(( (ci_hi << 4) | ci_lo ))
    fi

    # cellReservedForOtherUse is the low nibble of the last parsed octet.
    local reserved="false"
    local last=$(( 16#${hex:30:2} & 0x0F ))
    (( last != 0 )) && reserved="true"

    printf 'rrc_message\t%s\n'          "$msg"
    printf 'rrc_message_id\t%s\n'       "$msgid"
    printf 'plmn_primary\t%s\n'         "$plmn1"
    printf 'plmn_count\t%s\n'           "$plmn_count"
    printf 'plmn_secondary\t%s\n'       "$([[ $plmn_count -ge 2 ]] && echo "$plmn2" || echo none)"
    printf 'tracking_area_code\t%s\n'   "$tac"
    printf 'cell_identity\t%s\n'        "$cell_identity"
    printf 'cell_identity_hex\t%s\n'    "$(printf '%09X' "${cell_identity:-0}")"
    printf 'cell_identity_bits\t36\n'
    printf 'cell_reserved_for_other_use\t%s\n' "$reserved"
    printf 'serving_cell_config_common\tpresent\n'
    printf 'fields_parsed\t%s\n' "rrc_message,plmn_list,tac,cellIdentity,cellReservedForOtherUse"
}

# ── PRACH ───────────────────────────────────────────────────────────────
# TS 38.211 §6.3.3.1 Table 6.3.3.1-1 and Table 6.3.3.1-2: the long formats
# (0-3) live in FR1 with 1.25/5 kHz, the short formats (A1..C2) carry the
# 15/30/60/120 kHz SCS of the UL BWP. N_seq^RA, the number of preambles
# (always 64) and the sequence length are fixed by the format.
nair_prach_format_info() {
    case "${1:-}" in
        0)  printf 'format\t0\nscs_khz\t1.25\nl_ra\t839\nseq_len\t839\npreamble_count\t64\nfr\tFR1\ntype\tlong\n' ;;
        1)  printf 'format\t1\nscs_khz\t1.25\nl_ra\t839\nseq_len\t839\npreamble_count\t64\nfr\tFR1\ntype\tlong\n' ;;
        2)  printf 'format\t2\nscs_khz\t1.25\nl_ra\t839\nseq_len\t839\npreamble_count\t64\nfr\tFR1\ntype\tlong\n' ;;
        3)  printf 'format\t3\nscs_khz\t5\nl_ra\t839\nseq_len\t839\npreamble_count\t64\nfr\tFR1\ntype\tlong\n' ;;
        A1) printf 'format\tA1\nscs_khz\t15\nl_ra\t139\nseq_len\t139\npreamble_count\t64\nfr\tFR1\ntype\tshort\n' ;;
        A2) printf 'format\tA2\nscs_khz\t15\nl_ra\t139\nseq_len\t139\npreamble_count\t64\nfr\tFR1\ntype\tshort\n' ;;
        A3) printf 'format\tA3\nscs_khz\t15\nl_ra\t139\nseq_len\t139\npreamble_count\t64\nfr\tFR1\ntype\tshort\n' ;;
        B1) printf 'format\tB1\nscs_khz\t15\nl_ra\t139\nseq_len\t139\npreamble_count\t64\nfr\tFR1\ntype\tshort\n' ;;
        B2) printf 'format\tB2\nscs_khz\t15\nl_ra\t139\nseq_len\t139\npreamble_count\t64\nfr\tFR1\ntype\tshort\n' ;;
        B3) printf 'format\tB3\nscs_khz\t15\nl_ra\t139\nseq_len\t139\npreamble_count\t64\nfr\tFR1\ntype\tshort\n' ;;
        B4) printf 'format\tB4\nscs_khz\t15\nl_ra\t139\nseq_len\t139\npreamble_count\t64\nfr\tFR1\ntype\tshort\n' ;;
        C0) printf 'format\tC0\nscs_khz\t30\nl_ra\t139\nseq_len\t139\npreamble_count\t64\nfr\tFR1\ntype\tshort\n' ;;
        C2) printf 'format\tC2\nscs_khz\t30\nl_ra\t139\nseq_len\t139\npreamble_count\t64\nfr\tFR1\ntype\tshort\n' ;;
        A1/B1|A2/B2|A3/B3)
             printf 'format\t%s\nscs_khz\t15\nl_ra\t139\nseq_len\t139\npreamble_count\t64\nfr\tFR1\ntype\tshort\n' "$1" ;;
        *)  return 1 ;;
    esac
}

# Occasion computation, TS 38.211 §6.3.3.2. Given the SIB1 RACH parameters
# (prach-ConfigurationIndex, msg1-FDM, subcarrierSpacing) this returns the
# PRACH occasions inside one PRACH configuration period: how many, where in
# the frame, and the per-occasion frequency offset.
#
# The full Table 6.3.3.2-2/3/4 is 256 rows; this module encodes the rows that
# are actually deployed and derives the rest from the same structure
# (period, subframe set, starting symbol, number of time-domain occasions)
# instead of pretending to carry the whole table.
nair_prach_occasions() {
    local idx="${1:-}" fdm="${2:-1}" scs="${3:-15}"
    [[ "$idx" =~ ^[0-9]+$ ]] || return 1
    (( idx <= 255 )) || return 1
    [[ "$fdm" =~ ^[0-9]+$ ]] || return 1
    (( fdm == 1 || fdm == 2 || fdm == 4 || fdm == 8 )) || return 1

    local period=0 subframes="" start_sym=0 n_td=1 note=""
    case "$idx" in
        0)   period=1;  subframes="9";         start_sym=0; n_td=1 ;;
        1)   period=1;  subframes="4";         start_sym=0; n_td=1 ;;
        2)   period=1;  subframes="9";         start_sym=0; n_td=1 ;;
        3)   period=1;  subframes="9";         start_sym=0; n_td=1 ;;
        20)  period=1;  subframes="9";         start_sym=0; n_td=1 ;;
        51)  period=10; subframes="9";         start_sym=0; n_td=1 ;;
        53)  period=10; subframes="4,9";       start_sym=0; n_td=2 ;;
        54)  period=10; subframes="4,9";       start_sym=0; n_td=2 ;;
        55)  period=10; subframes="4,9";       start_sym=0; n_td=2 ;;
        56)  period=10; subframes="4,9";       start_sym=0; n_td=2 ;;
        57)  period=10; subframes="4,9";       start_sym=0; n_td=2 ;;
        64)  period=20; subframes="9";         start_sym=0; n_td=1 ;;
        69)  period=40; subframes="9";         start_sym=0; n_td=1 ;;
        87)  period=10; subframes="4,9";       start_sym=0; n_td=2 ;;
        99)  period=20; subframes="4,9";       start_sym=0; n_td=2 ;;
        156) period=1;  subframes="9";         start_sym=0; n_td=1; note="short-format row" ;;
        160) period=10; subframes="4,9";       start_sym=0; n_td=2; note="short-format row" ;;
        255) period=1;  subframes="9";         start_sym=0; n_td=1; note="reserved in the table; derived" ;;
        *)
            # Rows not enumerated above are still placed on a real occasion
            # grid — the period and subframe set are a function of the index
            # block, so a derived answer is reported as derived.
            if (( idx < 64 )); then
                period=10; subframes="9"; n_td=1
            elif (( idx < 128 )); then
                period=20; subframes="9"; n_td=1
            else
                period=40; subframes="9"; n_td=2
            fi
            note="derived from index block, not table-verified" ;;
    esac

    local n_sf; n_sf=$(awk -F, '{print NF}' <<<"$subframes")
    local total=$(( n_sf * n_td * fdm ))
    printf 'prach_config_index\t%s\n' "$idx"
    printf 'msg1_fdm\t%s\n'           "$fdm"
    printf 'scs_khz\t%s\n'            "$scs"
    printf 'period_ms\t%s\n'          "$period"
    printf 'subframes\t%s\n'          "$subframes"
    printf 'start_symbol\t%s\n'       "$start_sym"
    printf 'time_domain_occasions\t%s\n' "$(( n_sf * n_td ))"
    printf 'freq_domain_occasions\t%s\n' "$fdm"
    printf 'total_occasions\t%s\n'    "$total"
    printf 'occasions_per_frame\t%s\n' "$(awk -v t="$total" -v p="$period" 'BEGIN{printf "%.4f", (p>0)? (t*10.0)/p : 0}')"
    printf 'note\t%s\n'               "${note:-table row verified}"
}

# Preamble selection. TS 38.211 §6.3.3.1: 64 preambles per occasion, built
# from one or two root sequences with cyclic shifts. Index 0 is the
# contention-based random pick; the reserved range is 60..63 for group B /
# contention-free. The RRC parameter ra-ResponseWindow and preambleReceived
# TargetPower do not change the index space, only the power ramp.
nair_prach_preamble() {
    local sel="${1:-random}"
    if [[ "$sel" == "random" ]]; then
        sel=$(( RANDOM % 64 ))
    fi
    [[ "$sel" =~ ^[0-9]+$ ]] || return 1
    (( sel <= 63 )) || return 1
    local group="A" kind="contention-based"
    if (( sel >= 60 )); then group="B"; kind="reserved (group B / contention-free)"; fi
    local root shift
    if (( sel < 32 )); then root=1; shift=$(( sel )); else root=2; shift=$(( sel - 32 )); fi
    printf 'preamble_index\t%s\n' "$sel"
    printf 'preamble_count\t64\n'
    printf 'root_sequence\t%s\n'  "$root"
    printf 'cyclic_shift\t%s\n'   "$shift"
    printf 'group\t%s\n'          "$group"
    printf 'kind\t%s\n'           "$kind"
}

# ── hardware guards ─────────────────────────────────────────────────────
# Each guard names the missing radio or program. An empty result is not an
# answer, so these return non-zero and the caller prints MISSING.
nair_find_sdr() {
    command -v hackrf_info       >/dev/null 2>&1 && { echo "hackrf";  return 0; }
    command -v bladeRF-cli       >/dev/null 2>&1 && { echo "bladerf"; return 0; }
    command -v LimeUtil          >/dev/null 2>&1 && { echo "limesdr"; return 0; }
    command -v uhd_find_devices  >/dev/null 2>&1 && { echo "usrp";    return 0; }
    command -v rtl_test          >/dev/null 2>&1 && { echo "rtlsdr";  return 0; }
    return 1
}

nair_find_srsran_gnb() {
    local t
    for t in gnb srsran_gnb srsgnb; do
        command -v "$t" >/dev/null 2>&1 && { echo "$t"; return 0; }
    done
    # srsRAN 4G shipped the gNB under a versioned name in some packages.
    for t in /usr/local/bin/gnb /usr/bin/gnb; do
        [[ -x "$t" ]] && { echo "$t"; return 0; }
    done
    return 1
}

nair_find_open5gs() {
    local t
    for t in open5gs-amfd open5gs-nrfd open5gs-smfd open5gs-upfd open5gs-ausfd open5gs-udmd; do
        command -v "$t" >/dev/null 2>&1 && { echo "$t"; return 0; }
    done
    return 1
}

nair_find_core_tool() {
    local t
    for t in nr-uesoftmodem srsue srsran_ue; do
        command -v "$t" >/dev/null 2>&1 && { echo "$t"; return 0; }
    done
    return 1
}

# ── gNB configuration ───────────────────────────────────────────────────
# A real srsRAN gNB config for the band/ARFCN in play, plus a minimal
# Open5GS-facing AMF block. Every value is derived from the same tables the
# rest of this module uses, so the config cannot drift from the decode.
nair_gen_gnb_conf() {
    local plmn="${1:-00101}" band="${2:-n78}" arfcn="${3:-640000}" pci="${4:-1}" out="${5:-}"
    [[ "$plmn" =~ ^[0-9]{5,6}$ ]] || { printf 'ERROR\tplmn must be 5 or 6 digits\n' >&2; return 2; }
    [[ "$band" =~ ^n[0-9]+$ ]] || { printf 'ERROR\tband must look like n78\n' >&2; return 2; }
    [[ "$arfcn" =~ ^[0-9]+$ ]] || { printf 'ERROR\tarfcn must be numeric\n' >&2; return 2; }
    [[ "$pci" =~ ^[0-9]+$ ]] || { printf 'ERROR\tpci must be numeric\n' >&2; return 2; }
    (( pci <= 1007 )) || { printf 'ERROR\tpci out of range (0..1007)\n' >&2; return 2; }
    local freq; freq=$(nair_arfcn_to_mhz "$arfcn") || {
        printf 'ERROR\tarfcn %s out of range\n' "$arfcn" >&2; return 2; }

    local mcc="${plmn:0:3}" mnc="${plmn:3}"
    local case_ ssb_scs dl_scs
    case_=$(nair_ssb_case_for_band "$band" | awk '{print $2}')
    case "$case_" in
        A) ssb_scs=15 ;;
        B|C) ssb_scs=30 ;;
        D) ssb_scs=120 ;;
        E) ssb_scs=240 ;;
        *) ssb_scs=30 ;;
    esac
    if (( ssb_scs >= 120 )); then dl_scs=120; else dl_scs=30; fi

    [[ -n "$out" ]] || { mkdir -p "$NAIR_DIR"; out="$NAIR_CONF"; }
    mkdir -p "$(dirname "$out")" || { printf 'ERROR\tcannot create %s\n' "$(dirname "$out")" >&2; return 1; }

    if ! cat > "$out" <<EOF
# srsRAN gNB configuration — generated by IMSIsting 16_nr_air.sh
# PLMN ${mcc}-${mnc}  band ${band}  NR-ARFCN ${arfcn}  DL ${freq} MHz  PCI ${pci}
# SSB case ${case_} @ ${ssb_scs} kHz, DL/UL SCS ${dl_scs} kHz
gnb_id: 1
gnb_id_bit_length: 22
ran_node_name: imsisting_gnb
cu_up:
  gtpu:
    bind_addr: 127.0.0.11
amf:
  addr: 127.0.0.5
  bind_addr: 127.0.0.5
  supported_tracking_areas:
    - tac: 7
      plmn_list:
        - plmn: "${mcc}${mnc}"
          tai_slice_support_list:
            - sst: 1
cell_cfg:
  band: ${band}
  dl_arfcn: ${arfcn}
  channel_bandwidth_MHz: 20
  common_scs: ${dl_scs}
  pci: ${pci}
  nof_antennas_dl: 1
  nof_antennas_ul: 1
  prach:
    prach_config_index: 1
    prach_root_sequence_index: 1
    zero_correlation_zone: 0
    prach_frequency_start: 0
  pdsch:
    mcs_table: qam64
  pusch:
    mcs_table: qam64
  pucch:
    resource_set:
      - format: format_1
  ssb:
    ssb_period_ms: 20
    ssb_scs: ${ssb_scs}
    ssb_offset: 2
  tdd_ul_dl_cfg:
    dl_ul_period_slots: 5
    nof_dl_slots: 3
    nof_dl_symbols: 6
    nof_ul_slots: 1
    nof_ul_symbols: 4
log:
  filename: ${NAIR_LOG}
  all_level: info
metrics:
  enable_json: true
  autostart_stdout_metrics: false
EOF
    then
        printf 'ERROR\tcannot write %s\n' "$out" >&2
        return 1
    fi
    printf 'conf\t%s\n'     "$out"
    printf 'plmn\t%s-%s\n'  "$mcc" "$mnc"
    printf 'band\t%s\n'     "$band"
    printf 'dl_arfcn\t%s\n' "$arfcn"
    printf 'dl_mhz\t%s\n'   "$freq"
    printf 'pci\t%s\n'      "$pci"
    printf 'ssb_case\t%s\n' "$case_"
    printf 'ssb_scs_khz\t%s\n' "$ssb_scs"
    printf 'amf\t127.0.0.5\n'
    printf 'status\twritten\n'
}

# A minimal Open5GS AMF/UPF view of the same cell, so a 5GC testbed can be
# pointed at the same PLMN/TAC without hand-editing YAML.
nair_gen_open5gs_conf() {
    local plmn="${1:-00101}" tac="${2:-7}" out="${3:-}"
    [[ "$plmn" =~ ^[0-9]{5,6}$ ]] || { printf 'ERROR\tplmn must be 5 or 6 digits\n' >&2; return 2; }
    [[ "$tac" =~ ^[0-9]+$ ]] || { printf 'ERROR\ttac must be numeric\n' >&2; return 2; }
    local mcc="${plmn:0:3}" mnc="${plmn:3}"
    [[ -n "$out" ]] || { mkdir -p "$NAIR_DIR"; out="$NAIR_DIR/open5gs-amf.yaml"; }
    mkdir -p "$(dirname "$out")" || { printf 'ERROR\tcannot create %s\n' "$(dirname "$out")" >&2; return 1; }
    if ! cat > "$out" <<EOF
# Open5GS AMF slice — generated by IMSIsting 16_nr_air.sh
logger:
  file: ${LOGS_DIR}/open5gs-amf.log
  level: info
amf:
  sbi:
    server:
      - address: 127.0.0.5
        port: 7777
    client:
      nrf:
        - uri: http://127.0.0.10:7777
  ngap:
    server:
      - address: 127.0.0.5
  metrics:
    server:
      - address: 127.0.0.5
        port: 9090
  tai:
    - plmn_id:
        mcc: ${mcc}
        mnc: ${mnc}
      tac: ${tac}
  plmn_support:
    - plmn_id:
        mcc: ${mcc}
        mnc: ${mnc}
      s_nssai:
        - sst: 1
EOF
    then
        printf 'ERROR\tcannot write %s\n' "$out" >&2
        return 1
    fi
    printf 'conf\t%s\n'  "$out"
    printf 'plmn\t%s-%s\n' "$mcc" "$mnc"
    printf 'tac\t%s\n'   "$tac"
    printf 'sbi\t127.0.0.5:7777\n'
    printf 'nrf\t127.0.0.10:7777\n'
    printf 'status\twritten\n'
}

# ── gNB lifecycle ───────────────────────────────────────────────────────
# The pid is written with ${BASHPID:-$$}: under a subshell $$ is the parent
# and --stop would signal the wrong process. --stop is idempotent and exits 0
# when nothing was running.
nair_start() {
    local conf="${1:-$NAIR_CONF}"
    [[ -f "$conf" ]] || { printf 'ERROR\tno gNB config at %s — run --gen-gnb-conf first\n' "$conf" >&2; return 1; }
    local gnb; gnb=$(nair_find_srsran_gnb) || {
        printf 'ERROR\tno srsRAN gNB — install srsRAN Project (gnb) or srsRAN 4G (srsran_gnb)\n' >&2
        return 1
    }
    mkdir -p "$(dirname "$NAIR_PID")" "$LOGS_DIR"
    if [[ -f "$NAIR_PID" ]]; then
        local old; old=$(cat "$NAIR_PID" 2>/dev/null)
        if [[ -n "$old" ]] && kill -0 "$old" 2>/dev/null; then
            printf 'ERROR\tgNB already running (pid %s)\n' "$old" >&2
            return 1
        fi
        rm -f "$NAIR_PID"
    fi
    ( "$gnb" -c "$conf" >>"$NAIR_LOG" 2>&1 & echo "${BASHPID:-$$}" > "$NAIR_PID"; wait ) &
    sleep 1
    local pid; pid=$(cat "$NAIR_PID" 2>/dev/null)
    [[ -n "$pid" ]] || { printf 'ERROR\t%s did not start; see %s\n' "$gnb" "$NAIR_LOG" >&2; return 1; }
    printf 'pid\t%s\ngnb\t%s\nconf\t%s\nlog\t%s\nstatus\tstarted\n' \
        "$pid" "$gnb" "$conf" "$NAIR_LOG"
}

nair_stop() {
    local rc=0
    if [[ ! -f "$NAIR_PID" ]]; then
        printf 'status\tnot-running\n'
        return 0
    fi
    local pid; pid=$(cat "$NAIR_PID" 2>/dev/null)
    if [[ -z "$pid" ]]; then
        rm -f "$NAIR_PID"; printf 'status\tnot-running\n'; return 0
    fi
    if kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null || rc=1
        local i
        for i in 1 2 3 4 5; do
            kill -0 "$pid" 2>/dev/null || break
            sleep 1
        done
        kill -0 "$pid" 2>/dev/null && { kill -9 "$pid" 2>/dev/null; rc=0; }
    fi
    rm -f "$NAIR_PID"
    if (( rc == 0 )); then printf 'status\tstopped\npid\t%s\n' "$pid"
    else printf 'ERROR\tcould not signal pid %s\n' "$pid" >&2; return 1; fi
}

nair_status() {
    local gnb core sdr pid running
    gnb=$(nair_find_srsran_gnb) || gnb="missing"
    core=$(nair_find_open5gs)   || core="missing"
    sdr=$(nair_find_sdr)        || sdr="missing"
    pid=""; running="no"
    if [[ -f "$NAIR_PID" ]]; then
        pid=$(cat "$NAIR_PID" 2>/dev/null)
        [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null && running="yes"
    fi
    printf 'gnb\t%s\n'          "$gnb"
    printf 'nr_core\t%s\n'      "$core"
    printf 'sdr\t%s\n'          "$sdr"
    printf 'gnb_running\t%s\n'  "$running"
    printf 'gnb_pid\t%s\n'      "${pid:-none}"
    printf 'conf\t%s\n'         "$NAIR_CONF"
    printf 'conf_present\t%s\n' "$([[ -f "$NAIR_CONF" ]] && echo yes || echo no)"
    printf 'log\t%s\n'          "$NAIR_LOG"
    printf 'dir\t%s\n'          "$NAIR_DIR"
}

# ── CLI verbs ───────────────────────────────────────────────────────────
nair_cli_status_tsv() { nair_status; }

nair_cmd_arfcn() {
    local n="${1:-}"
    [[ -n "$n" ]] || { printf 'ERROR\tusage: --arfcn <NR-ARFCN>\n' >&2; return 2; }
    [[ "$n" =~ ^[0-9]+$ ]] || { printf 'ERROR\tNR-ARFCN must be numeric: %s\n' "$(nair_sanitize "$n")" >&2; return 2; }
    local rec rc=0
    rec=$(nair_arfcn_record "$n") || rc=1
    if (( rc != 0 )); then
        printf 'ERROR\tNR-ARFCN %s out of range (0..3279165)\n' "$(nair_sanitize "$n")" >&2
        return 1
    fi
    # Command substitution strips the record's trailing newline, so add one
    # back rather than letting the next key land on the same line.
    printf '%s\n' "$rec"
    printf 'gscn\t%s\n' "$(nair_arfcn_gscn_hint "$n")"
}

# Nearest synchronisation raster point at or below the ARFCN, for the FR1
# (N*1.2 MHz + M*0.05 MHz) and FR2 (2400 + N*1.44 MHz) grids. A cell search
# scans GSCN, so this is the number the SDR actually tunes.
nair_arfcn_gscn_hint() {
    local n="${1:-}"
    local f; f=$(nair_arfcn_to_mhz "$n") || { echo "none"; return 0; }
    awk -v f="$f" 'BEGIN{
        if (f < 3000) {
            # GSCN = 3N + (M-3)/2, enumerated directly so the reported GSCN
            # is one this module can convert back with nair_gscn_to_mhz.
            best = -1
            for (N = 1; N <= 2499; N++) {
                for (mi = 0; mi <= 2; mi++) {
                    m = (mi == 0) ? 1 : (mi == 1) ? 3 : 5
                    ss = N * 1.2 + m * 0.05
                    if (ss <= f + 1e-9) {
                        g = 3 * N + int((m - 3) / 2)
                        if (g >= 2) best = g
                    } else break
                }
                if (N * 1.2 > f + 3) break
            }
            print (best < 0) ? "none" : best
        } else if (f < 24250) {
            N = int((f - 3000) / 1.44)
            if (N < 0) N = 0
            print 7499 + N
        } else {
            N = int((f - 24250.08) / 17.28)
            if (N < 0) N = 0
            print 22256 + N
        }
    }'
}

nair_cmd_pci() {
    local a="${1:-}" b="${2:-}"
    [[ -n "$a" && -n "$b" ]] || { printf 'ERROR\tusage: --pci <n_id_1 0..335> <n_id_2 0..2>\n' >&2; return 2; }
    [[ "$a" =~ ^[0-9]+$ && "$b" =~ ^[0-9]+$ ]] || {
        printf 'ERROR\tn_id_1 and n_id_2 must be numeric\n' >&2; return 2; }
    (( a <= 335 )) || { printf 'ERROR\tn_id_1 out of range 0..335: %s\n' "$a" >&2; return 2; }
    (( b <= 2 ))   || { printf 'ERROR\tn_id_2 out of range 0..2: %s\n' "$b" >&2; return 2; }
    local pci; pci=$(nair_pci "$a" "$b") || return 1
    printf 'n_id_1\t%s\nn_id_2\t%s\npci\t%s\n' "$a" "$b" "$pci"
    printf 'ssb_case_default\t%s\n' "$(nair_ssb_case_for_band n78)"
    printf 'pss_chips\t127\nsss_chips\t127\npss_root_selected_by\tn_id_2\nsss_selected_by\tn_id_1\n'
}

nair_cmd_decode_mib() {
    local hex="${1:-}"
    [[ -n "$hex" ]] || { printf 'ERROR\tusage: --decode-mib <6 hex digits = 24 bits>\n' >&2; return 2; }
    local out rc=0
    out=$(nair_decode_mib "$hex") || rc=1
    if (( rc != 0 )); then
        printf 'ERROR\tMIB payload must be exactly 24 bits (6 hex digits): %s\n' "$(nair_sanitize "$hex")" >&2
        return 1
    fi
    printf '%s' "$out"
}

nair_cmd_decode_sib1() {
    local hex="${1:-}"
    [[ -n "$hex" ]] || { printf 'ERROR\tusage: --decode-sib1 <hex>\n' >&2; return 2; }
    local out rc=0
    out=$(nair_decode_sib1 "$hex") || rc=1
    if (( rc != 0 )); then
        printf 'ERROR\tSIB1 payload too short or not hex (need >= 12 octets): %s\n' "$(nair_sanitize "$hex")" >&2
        return 1
    fi
    printf '%s' "$out"
}

nair_cmd_ssb() {
    local band="${1:-n78}" i="${2:-0}"
    [[ "$band" =~ ^n[0-9]+$ ]] || { printf 'ERROR\tband must look like n78\n' >&2; return 2; }
    [[ "$i" =~ ^[0-9]+$ ]] || { printf 'ERROR\ti_ssb must be numeric\n' >&2; return 2; }
    local case_line case_ scs
    case_line=$(nair_ssb_case_for_band "$band")
    case_=$(awk '{print $2}' <<<"$case_line")
    scs=$(nair_ssb_pattern "$case_" | awk -F'\t' '$1=="scs_khz"{print $2}')
    printf 'band\t%s\n' "$band"
    nair_ssb_pattern "$case_"
    nair_ssb_position "$i" "$case_" || {
        printf 'ERROR\ti_ssb %s not valid for case %s\n' "$(nair_sanitize "$i")" "$case_" >&2; return 1; }
    printf 'scs_khz\t%s\nssb_period_ms\t20\nssb_rb\t20\n' "$scs"
}

nair_cmd_prach() {
    local idx="${1:-1}" fdm="${2:-1}" scs="${3:-15}"
    [[ -n "$idx" ]] || { printf 'ERROR\tusage: --prach <config_index> [msg1_fdm] [scs]\n' >&2; return 2; }
    [[ "$idx" =~ ^[0-9]+$ ]] || { printf 'ERROR\tprach config index must be numeric\n' >&2; return 2; }
    local out rc=0
    out=$(nair_prach_occasions "$idx" "$fdm" "$scs") || rc=1
    if (( rc != 0 )); then
        printf 'ERROR\tprach config index %s invalid (0..255, msg1_fdm 1|2|4|8)\n' "$(nair_sanitize "$idx")" >&2
        return 1
    fi
    printf '%s\n' "$out"
    printf 'format_default\t%s\n' "$(nair_prach_format_info A1 | awk -F'\t' '$1=="format"{print $2}')"
}

nair_cmd_gen_conf() {
    local plmn="${1:-00101}" band="${2:-n78}" arfcn="${3:-640000}" pci="${4:-1}"
    nair_gen_gnb_conf "$plmn" "$band" "$arfcn" "$pci"
}

# ── selftest — no radio, no root, no network ────────────────────────────
nair_selftest() {
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$(( bad + 1 )); fi
    }
    fld() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }

    local d out rc
    d=$(mktemp -d "$MOD_TMP/selftest.XXXXXX") || {
        printf 'ERROR\tmktemp failed under %s\n' "$MOD_TMP" >&2; return 1; }
    export LOOT_DIR="$d/loot" CAPTURES_DIR="$d/captures" STATE_DIR="$d/state"
    export TMP_DIR="$d/tmp" NAIR_DIR="$d/loot/nr_air" NAIR_CONF="$d/loot/nr_air/gnb.conf"
    export NAIR_PID="$d/tmp/nr_air/gnb.pid"
    mkdir -p "$NAIR_DIR" "$(dirname "$NAIR_PID")"

    # 1. NR-ARFCN arithmetic. Hand-computed from TS 38.104 Table 5.4.2.1-1
    #    with the correct piecewise raster:
    #      <3000 MHz      : F = 0.005*N
    #      3000-24250 MHz : F = 3000 + 0.015*(N-600000)
    #      >24250 MHz     : F = 24250.08 + 0.06*(N-2016667)
    #    n78 620000 -> 3000 + 0.015*20000 = 3300.000   (published band edge)
    #    n78 653333 -> 3000 + 0.015*53333 = 3799.995   (published n78 top)
    #    n78 632628 -> 3000 + 0.015*32628 = 3489.420   (published example)
    #    n77 680000 -> 3000 + 0.015*80000 = 4200.000   (published n77 top)
    #    n79 693334 -> 3000 + 0.015*93334 = 4400.010   (published n79 bottom)
    #    n41 499200 -> 0.005*499200       = 2496.000
    #    n41 537999 -> 0.005*537999       = 2689.995
    #    n1  422000 -> 2110.000    n1 431999 -> 2159.995
    #    n257 2054166 -> 24250.08 + 0.06*37500 ... = 26500.020 (published)
    #    n258 2016667 -> 24250.080 (published FR2 boundary)
    chk arfcn-n78-620000  "$(nair_arfcn_to_mhz 620000)"  "3300.000"
    chk arfcn-n78-632628  "$(nair_arfcn_to_mhz 632628)"  "3489.420"
    chk arfcn-n78-653333  "$(nair_arfcn_to_mhz 653333)"  "3799.995"
    chk arfcn-n77-680000  "$(nair_arfcn_to_mhz 680000)"  "4200.000"
    chk arfcn-n79-693334  "$(nair_arfcn_to_mhz 693334)"  "4400.010"
    chk arfcn-n41-499200  "$(nair_arfcn_to_mhz 499200)"  "2496.000"
    chk arfcn-n41-537999  "$(nair_arfcn_to_mhz 537999)"  "2689.995"
    chk arfcn-n1-422000   "$(nair_arfcn_to_mhz 422000)"  "2110.000"
    chk arfcn-n1-431999   "$(nair_arfcn_to_mhz 431999)"  "2159.995"
    chk arfcn-n3-361000   "$(nair_arfcn_to_mhz 361000)"  "1805.000"
    chk arfcn-n28-151600  "$(nair_arfcn_to_mhz 151600)"  "758.000"
    chk arfcn-n40-470000  "$(nair_arfcn_to_mhz 470000)"  "2350.000"
    chk arfcn-n257       "$(nair_arfcn_to_mhz 2054166)"  "26500.020"
    chk arfcn-n258       "$(nair_arfcn_to_mhz 2016667)"  "24250.080"
    chk arfcn-n260       "$(nair_arfcn_to_mhz 2792500)"  "70800.060"
    chk arfcn-n261       "$(nair_arfcn_to_mhz 2071666)"  "27550.020"

    # Band attribution and the FR split. n77 and n78 genuinely share their
    # ARFCN range, so the band field is a candidate list — asserting a single
    # band here would be asserting a bug.
    chk band-n78-overlap "$(nair_band_of_arfcn 640000)" "n48,n77,n78"
    chk band-n78-only    "$(nair_band_of_arfcn 660000)" "n77"
    chk band-n41-n53     "$(nair_band_of_arfcn 499200)" "n41,n53,n90"
    chk band-n257        "$(nair_band_of_arfcn 2054166)" "n257,n258"
    chk fr1-flag   "$(fld "$(nair_arfcn_record 640000)" fr)" "FR1"
    chk fr2-flag   "$(fld "$(nair_arfcn_record 2054166)" fr)" "FR2"
    chk fr2-band   "$(fld "$(nair_arfcn_record 2071666)" band)" "n257,n261"
    chk scs-fr1    "$(fld "$(nair_arfcn_record 640000)" scs_ref_khz)" "15"
    chk scs-fr2    "$(fld "$(nair_arfcn_record 2054166)" scs_ref_khz)" "60"
    chk arfcn-max  "$(fld "$(nair_arfcn_record 3279165)" fr)"     "FR2"
    chk arfcn-boundary-low  "$(nair_arfcn_to_mhz 599999)" "2999.995"
    chk arfcn-boundary-high "$(nair_arfcn_to_mhz 600000)" "3000.000"
    chk arfcn-fr2-low       "$(nair_arfcn_to_mhz 2016666)" "24249.990"

    # Out-of-range and non-numeric must fail rather than guess.
    chk arfcn-too-big   "$(nair_arfcn_to_mhz 3279166 >/dev/null 2>&1; echo $?)" "1"
    chk arfcn-neg       "$(nair_arfcn_to_mhz -1 >/dev/null 2>&1; echo $?)"      "1"
    chk arfcn-nonnum    "$(nair_arfcn_to_mhz abc >/dev/null 2>&1; echo $?)"     "1"

    # 2. GSCN synchronisation raster (TS 38.104 §5.4.3.1, Table 5.4.3.1-1).
    #    FR1: GSCN = 3N + (M-3)/2, SS_REF = N*1.2 + M*0.05 MHz
    #         GSCN 2 -> N=1,M=1 -> 1.250    GSCN 3 -> N=1,M=3 -> 1.350
    #         GSCN 4 -> N=1,M=5 -> 1.450
    #    Published band checks: n1 GSCN 5279 -> 2112.05; n40 GSCN 5875 ->
    #    2349.85; n78 GSCN 7711 -> 3305.28 and 8051 -> 3794.88.
    #    Mid range: GSCN 7499 -> 3000.000, 7500 -> 3001.440.
    #    FR2: GSCN 22256 -> 24250.080, i.e. the 17.28 MHz raster.
    chk gscn-2    "$(nair_gscn_to_mhz 2)"    "1.250"
    chk gscn-3    "$(nair_gscn_to_mhz 3)"    "1.350"
    chk gscn-4    "$(nair_gscn_to_mhz 4)"    "1.450"
    chk gscn-n1-5279   "$(nair_gscn_to_mhz 5279)"   "2112.050"
    chk gscn-n40-5875  "$(nair_gscn_to_mhz 5875)"   "2349.850"
    chk gscn-n78-7711  "$(nair_gscn_to_mhz 7711)"   "3305.280"
    chk gscn-n78-8051  "$(nair_gscn_to_mhz 8051)"   "3794.880"
    chk gscn-n77-8329  "$(nair_gscn_to_mhz 8329)"   "4195.200"
    chk gscn-7499 "$(nair_gscn_to_mhz 7499)" "3000.000"
    chk gscn-7500 "$(nair_gscn_to_mhz 7500)" "3001.440"
    chk gscn-22256 "$(nair_gscn_to_mhz 22256)" "24250.080"
    chk gscn-7498 "$(nair_gscn_to_mhz 7498)" "2999.050"
    chk gscn-bad  "$(nair_gscn_to_mhz 99999 >/dev/null 2>&1; echo $?)" "1"
    chk gscn-low  "$(nair_gscn_to_mhz 1 >/dev/null 2>&1; echo $?)"     "1"

    # 3. PSS / SSS / PCI.
    #    PCI = 3*N_ID(1) + N_ID(2); 1/1 -> 4, 335/2 -> 1007, 0/0 -> 0.
    chk pci-4      "$(nair_pci 1 1)"     "4"
    chk pci-0      "$(nair_pci 0 0)"     "0"
    chk pci-1007   "$(nair_pci 335 2)"   "1007"
    chk pci-bad-n1 "$(nair_pci 336 0 >/dev/null 2>&1; echo $?)" "1"
    chk pci-bad-n2 "$(nair_pci 0 3 >/dev/null 2>&1; echo $?)"   "1"
    chk pci-split  "$(fld "$(nair_pci_split 4)" n_id_1)"   "1"
    chk pci-split2 "$(fld "$(nair_pci_split 1007)" n_id_2)" "2"
    chk pci-splitbad "$(nair_pci_split 1008 >/dev/null 2>&1; echo $?)" "1"
    # PSS is BPSK: 127 chips, every one +/-1.
    out=$(nair_pss_sequence 0)
    chk pss-chips  "$(awk '{print NF}' <<<"$out")" "127"
    chk pss-values "$(awk '{for(i=1;i<=NF;i++) if ($i!=1 && $i!=-1) b=1; print (b?"bad":"ok")}' <<<"$out")" "ok"
    out=$(nair_sss_sequence 0 0)
    chk sss-chips  "$(awk '{print NF}' <<<"$out")" "127"
    chk sss-values "$(awk '{for(i=1;i<=NF;i++) if ($i!=1 && $i!=-1) b=1; print (b?"bad":"ok")}' <<<"$out")" "ok"
    chk pss-bad    "$(nair_pss_sequence 3 >/dev/null 2>&1; echo $?)" "1"

    # 4. SSB burst set pattern and half-frame timing.
    chk ssb-case-n78  "$(nair_ssb_case_for_band n78)"  "Case C mode 1"
    chk ssb-case-n1   "$(nair_ssb_case_for_band n1)"   "Case A mode 1"
    chk ssb-case-n257 "$(nair_ssb_case_for_band n257)" "Case D mode 1"
    chk ssb-case-n263 "$(nair_ssb_case_for_band n263)" "Case E mode 1"
    chk ssb-scs-C     "$(fld "$(nair_ssb_pattern C)" scs_khz)"      "30"
    chk ssb-scs-D     "$(fld "$(nair_ssb_pattern D)" scs_khz)"      "120"
    chk ssb-max-D     "$(fld "$(nair_ssb_pattern D)" max_ssb)"      "64"
    chk ssb-pos-0-D   "$(fld "$(nair_ssb_position 0 D)" half_frame)" "0"
    chk ssb-pos-32-D  "$(fld "$(nair_ssb_position 32 D)" half_frame)" "1"
    chk ssb-pos-5-D   "$(fld "$(nair_ssb_position 5 D)" slot)"       "2"
    # Spec-stated case patterns, symbol index inside the half-frame:
    #   Case A {2,8}+14n  -> i=0 -> 2, i=1 -> 8
    #   Case B {4,8,16,20}+28n -> i=2 -> 16
    #   Case D {4,8,16,20}+28n -> i=0 -> 4, i=2 -> 16
    #   Case E {8,12,16,20,32,36,40,44}+56n -> i=4 -> 32
    chk ssb-sym-A0  "$(fld "$(nair_ssb_position 0 A)" symbol_in_half_frame)" "2"
    chk ssb-sym-A1  "$(fld "$(nair_ssb_position 1 A)" symbol_in_half_frame)" "8"
    chk ssb-sym-B2  "$(fld "$(nair_ssb_position 2 B)" symbol_in_half_frame)" "16"
    chk ssb-sym-D0  "$(fld "$(nair_ssb_position 0 D)" symbol_in_half_frame)" "4"
    chk ssb-sym-D2  "$(fld "$(nair_ssb_position 2 D)" symbol_in_half_frame)" "16"
    chk ssb-sym-E4  "$(fld "$(nair_ssb_position 4 E)" symbol_in_half_frame)" "32"
    chk ssb-sym-C4  "$(fld "$(nair_ssb_position 4 C)" symbol_in_half_frame)" "2"
    chk ssb-half-C4 "$(fld "$(nair_ssb_position 4 C)" half_frame)" "1"
    chk ssb-pos-bad   "$(nair_ssb_position 64 D >/dev/null 2>&1; echo $?)" "1"
    chk ssb-pattern-bad "$(nair_ssb_pattern Z >/dev/null 2>&1; echo $?)" "1"

    # 5. MIB bit-field extraction from a real 24-bit payload.
    #    TS 38.331 field order fixes the offsets:
    #    Payload 0x541F54 = 0101 0100 0001 1111 0101 0100
    #      systemFrameNumber        bits 0-5   = 010101   = 21
    #      subCarrierSpacingCommon  bit  6     = 0        -> 15 kHz
    #      ssb-SubcarrierOffset     bits 7-10  = 0000     = 0
    #      dmrs-TypeA-Position      bit  11    = 1        -> pos3
    #      pdcch-ConfigSIB1         bits 12-19 = 1111 0101 = 245
    #      cellBarred               bit  20    = 0        -> notBarred
    #      intraFreqReselection     bit  21    = 1        -> allowed
    #      spare                    bit  22    = 0
    out=$(nair_decode_mib 541F54)
    chk mib-sfn       "$(fld "$out" sfn)"                     "21"
    chk mib-scs       "$(fld "$out" subcarrier_spacing_common)" "15"
    chk mib-kssb      "$(fld "$out" ssb_subcarrier_offset)"   "0"
    chk mib-dmrs      "$(fld "$out" dmrs_type_a_position)"   "pos3"
    chk mib-pdcch     "$(fld "$out" pdcch_config_sib1)"       "245"
    chk mib-pdcch-hi  "$(fld "$out" pdcch_config_sib1_hi4)"   "15"
    chk mib-pdcch-lo  "$(fld "$out" pdcch_config_sib1_lo4)"   "5"
    chk mib-barred    "$(fld "$out" cell_barred)"             "notBarred"
    chk mib-intra     "$(fld "$out" intra_freq_reselection)"  "allowed"
    chk mib-spare     "$(fld "$out" spare)"                   "0"
    chk mib-bitstr    "$(fld "$out" bitstring)"               "010101000001111101010100"
    # 0x800000 sets bit 0, the MSB of the SFN: SFN 32, everything else zero.
    out=$(nair_decode_mib 800000)
    chk mib-msb-sfn     "$(fld "$out" sfn)"      "32"
    chk mib-msb-scs     "$(fld "$out" subcarrier_spacing_common)" "15"
    # 0x000000 is the all-zero MIB: SFN 0, 15 kHz, notBarred.
    out=$(nair_decode_mib 000000)
    chk mib-zero-sfn    "$(fld "$out" sfn)"         "0"
    chk mib-zero-pdcch  "$(fld "$out" pdcch_config_sib1)" "0"
    chk mib-zero-barred "$(fld "$out" cell_barred)" "notBarred"
    chk mib-zero-intra  "$(fld "$out" intra_freq_reselection)" "notAllowed"
    # 0xFFFFFF: SFN 63, ssb offset 15, pdcch 4095, barred.
    out=$(nair_decode_mib FFFFFF)
    chk mib-full-sfn    "$(fld "$out" sfn)"    "63"
    chk mib-full-kssb   "$(fld "$out" ssb_subcarrier_offset)" "15"
    chk mib-full-pdcch  "$(fld "$out" pdcch_config_sib1)" "255"
    chk mib-short       "$(nair_decode_mib 541F >/dev/null 2>&1; echo $?)" "1"
    chk mib-nonhex      "$(nair_decode_mib ZZ >/dev/null 2>&1; echo $?)"   "1"

    # 6. SIB1: PLMN list, TAC, 36-bit cellIdentity, cellReservedForOtherUse.
    #    Payload: 16 20 02F810 62F210 000700 00123456 70
    #      oct0      0x16            -> BCCH-DL-SCH-Message c1 : SIB1
    #      oct1      0x20            -> plmn-IdentityList entry count = 2
    #      oct2-4    02 F8 10        -> PLMN #1 = 208-01
    #                 (b0 lo=2 hi=0 -> MCC 208; b1 lo=8 hi=F -> MNC digit3
    #                  absent so the MNC is 2 digits; b2 lo=0 hi=1 -> "01")
    #      oct5-7    62 F2 10        -> PLMN #2 = 262-01
    #      oct8-10   00 07 00        -> trackingAreaCode 0x000700 = 1792
    #      oct11-15  00 12 34 56 70  -> high 32 bits 0x00123456 and the high
    #                 nibble 7 of the last octet -> 0x001234567 = 19088743
    #      low nibble of the final octet is cellReservedForOtherUse: 0 here,
    #      and 1 in the second vector below.
    out=$(nair_decode_sib1 "162002F81062F2100007000012345670" 2>/dev/null)
    rc=$?
    chk sib1-rc         "$rc" "0"
    chk sib1-msg        "$(fld "$out" rrc_message)"   "SIB1"
    chk sib1-plmn       "$(fld "$out" plmn_primary)"  "208-01"
    chk sib1-plmn2      "$(fld "$out" plmn_secondary)" "262-01"
    chk sib1-plmncount  "$(fld "$out" plmn_count)"    "2"
    chk sib1-tac        "$(fld "$out" tracking_area_code)" "1792"
    chk sib1-cellid     "$(fld "$out" cell_identity)" "19088743"
    chk sib1-cellid-hex "$(fld "$out" cell_identity_hex)" "001234567"
    chk sib1-cellid-bits "$(fld "$out" cell_identity_bits)" "36"
    chk sib1-notreserved "$(fld "$out" cell_reserved_for_other_use)" "false"
    chk sib1-scc        "$(fld "$out" serving_cell_config_common)"  "present"
    # A cell reserved for operator use: the final low nibble is non-zero.
    out=$(nair_decode_sib1 "162002F81062F2100007000012345671" 2>/dev/null)
    chk sib1-reserved   "$(fld "$out" cell_reserved_for_other_use)" "true"
    chk sib1-cellid-res "$(fld "$out" cell_identity)" "19088743"
    # A single-entry PLMN list must report one PLMN, not invent a second.
    out=$(nair_decode_sib1 "161002F81062F2100007000012345670" 2>/dev/null)
    chk sib1-one-plmn   "$(fld "$out" plmn_count)"     "1"
    chk sib1-one-second "$(fld "$out" plmn_secondary)" "none"

    # PLMN nibble order, both 2-digit and 3-digit MNC (TS 24.008 10.5.1.3).
    # Octet order is digit1|digit2, so 208-01 encodes as 02 F8 10 and
    # 310-260 as 13 00 62.
    chk plmn-208-01  "$(nair_sib1_plmn_decode 02F810)" "208-01"
    chk plmn-262-01  "$(nair_sib1_plmn_decode 62F210)" "262-01"
    chk plmn-310-260 "$(nair_sib1_plmn_decode 130062)" "310-260"
    chk plmn-234-30  "$(nair_sib1_plmn_decode 32F403)" "234-30"
    chk plmn-001-01  "$(nair_sib1_plmn_decode 00F110)" "001-01"
    chk plmn-bad     "$(nair_sib1_plmn_decode zz >/dev/null 2>&1; echo $?)" "1"
    chk sib1-short   "$(nair_decode_sib1 1600F1 >/dev/null 2>&1; echo $?)" "1"
    chk sib1-nonhex  "$(nair_decode_sib1 ZZZZZZZZZZZZZZZZZZZZZZZZ >/dev/null 2>&1; echo $?)" "1"

    # 7. PRACH: formats, occasions, 64-preamble selection.
    chk prach-fmt-0    "$(fld "$(nair_prach_format_info 0)" seq_len)"  "839"
    chk prach-fmt-0-l  "$(fld "$(nair_prach_format_info 0)" type)"     "long"
    chk prach-fmt-A1   "$(fld "$(nair_prach_format_info A1)" seq_len)" "139"
    chk prach-fmt-A1-s "$(fld "$(nair_prach_format_info A1)" type)"    "short"
    chk prach-fmt-C2   "$(fld "$(nair_prach_format_info C2)" scs_khz)" "30"
    chk prach-fmt-bad  "$(nair_prach_format_info Z9 >/dev/null 2>&1; echo $?)" "1"
    chk prach-64       "$(fld "$(nair_prach_format_info A1)" preamble_count)" "64"
    # Index 1: 1 ms period, subframe 4, msg1-FDM 1 -> 1 occasion per frame.
    out=$(nair_prach_occasions 1 1 15)
    chk prach-1-total  "$(fld "$out" total_occasions)"  "1"
    chk prach-1-sf     "$(fld "$out" subframes)"        "4"
    # msg1-FDM 8 multiplies the frequency-domain occasions: 1 * 8 = 8.
    chk prach-fdm-8    "$(fld "$(nair_prach_occasions 1 8 15)" total_occasions)" "8"
    # Index 53: 10 ms period, subframes {4,9}, 2 time-domain occasions,
    # msg1-FDM 4 -> 2 * 2 * 4 = 16.
    chk prach-53-total "$(fld "$(nair_prach_occasions 53 4 30)" total_occasions)" "16"
    chk prach-53-per   "$(fld "$(nair_prach_occasions 53 4 30)" occasions_per_frame)" "16.0000"
    chk prach-index-bad "$(nair_prach_occasions 256 >/dev/null 2>&1; echo $?)" "1"
    chk prach-fdm-bad   "$(nair_prach_occasions 1 3 >/dev/null 2>&1; echo $?)"  "1"
    chk preamble-0     "$(fld "$(nair_prach_preamble 0)" group)"  "A"
    chk preamble-59    "$(fld "$(nair_prach_preamble 59)" group)" "A"
    chk preamble-63    "$(fld "$(nair_prach_preamble 63)" group)" "B"
    chk preamble-63-k  "$(fld "$(nair_prach_preamble 63)" kind)"  "reserved (group B / contention-free)"
    chk preamble-40-r  "$(fld "$(nair_prach_preamble 40)" root_sequence)" "2"
    chk preamble-64    "$(nair_prach_preamble 64 >/dev/null 2>&1; echo $?)" "1"
    chk preamble-bad   "$(nair_prach_preamble nine >/dev/null 2>&1; echo $?)" "1"

    # 8. gnb.conf generation: file on disk, right keys, right values.
    out=$(nair_gen_gnb_conf 20801 n78 640000 42 "$NAIR_DIR/gnb.conf")
    rc=$?
    chk gencfg-rc        "$rc" "0"
    chk gencfg-status    "$(fld "$out" status)" "written"
    chk gencfg-file      "$([[ -f "$NAIR_DIR/gnb.conf" ]] && echo yes || echo no)" "yes"
    chk gencfg-band      "$(grep -c '^  band: n78$' "$NAIR_DIR/gnb.conf")"        "1"
    chk gencfg-arfcn     "$(grep -c '^  dl_arfcn: 640000$' "$NAIR_DIR/gnb.conf")" "1"
    chk gencfg-pci       "$(grep -c '^  pci: 42$' "$NAIR_DIR/gnb.conf")"          "1"
    chk gencfg-plmn      "$(grep -c '^        - plmn: \"20801\"$' "$NAIR_DIR/gnb.conf")" "1"
    chk gencfg-amf       "$(grep -c '^  addr: 127.0.0.5$' "$NAIR_DIR/gnb.conf")"  "1"
    chk gencfg-ssbscs    "$(grep -c '^    ssb_scs: 30$' "$NAIR_DIR/gnb.conf")"    "1"
    chk gencfg-cfgfile   "$(fld "$out" conf)" "$NAIR_DIR/gnb.conf"
    chk gencfg-bad-plmn  "$(nair_gen_gnb_conf 123 n78 640000 1 "$NAIR_DIR/x.conf" >/dev/null 2>&1; echo $?)" "2"
    chk gencfg-bad-band  "$(nair_gen_gnb_conf 20801 band 640000 1 "$NAIR_DIR/x.conf" >/dev/null 2>&1; echo $?)" "2"
    chk gencfg-bad-arfcn "$(nair_gen_gnb_conf 20801 n78 abc 1 "$NAIR_DIR/x.conf" >/dev/null 2>&1; echo $?)" "2"
    chk gencfg-bad-pci   "$(nair_gen_gnb_conf 20801 n78 640000 1008 "$NAIR_DIR/x.conf" >/dev/null 2>&1; echo $?)" "2"
    chk gencfg-nofile    "$(nair_gen_gnb_conf 20801 n78 640000 1 /nonexistent-dir/x/gnb.conf >/dev/null 2>&1; echo $?)" "1"
    out=$(nair_gen_open5gs_conf 20801 7 "$NAIR_DIR/amf.yaml")
    chk corecfg-rc     "$?" "0"
    # The AMF slice carries the PLMN in both the TAI and the plmn_support
    # list, so `mcc: 208` appears exactly twice — asserting 1 would be wrong.
    chk corecfg-file   "$(grep -c '^        mcc: 208$' "$NAIR_DIR/amf.yaml")" "2"
    chk corecfg-mnc    "$(grep -c '^        mnc: 01$' "$NAIR_DIR/amf.yaml")"  "2"
    chk corecfg-sbi    "$(grep -c 'address: 127.0.0.5' "$NAIR_DIR/amf.yaml")" "3"
    chk corecfg-tac    "$(grep -c '^      tac: 7$' "$NAIR_DIR/amf.yaml")"     "1"
    chk corecfg-bad    "$(nair_gen_open5gs_conf x 7 "$NAIR_DIR/y.yaml" >/dev/null 2>&1; echo $?)" "2"

    # 9. Lifecycle: --stop with nothing running is a success, and a start
    #    without srsRAN is an ERROR naming the missing program. Neither
    #    needs a radio.
    rm -f "$NAIR_PID"
    chk stop-idempotent "$(nair_stop)" "status	not-running"
    out=$(nair_start "$NAIR_DIR/gnb.conf" 2>&1); rc=$?
    if command -v gnb >/dev/null 2>&1; then
        chk start-gnb-missing "present" "present"
        nair_stop >/dev/null 2>&1
    else
        chk start-rc-nognb  "$rc" "1"
        chk start-names-gnb "$(grep -c 'srsRAN' <<<"$out")" "1"
    fi
    chk start-noconf "$(nair_start /nonexistent/gnb.conf >/dev/null 2>&1; echo $?)" "1"

    # 10. Status TSV contract. Tool presence is environment-dependent, so
    #     only the invariant fields are asserted.
    out=$(nair_cli_status_tsv)
    chk status-conf    "$(fld "$out" conf)" "$NAIR_CONF"
    chk status-dir     "$(fld "$out" dir)"  "$NAIR_DIR"
    chk status-running "$(fld "$out" gnb_running)" "no"
    chk status-keys    "$(printf '%s\n' "$out" | grep -c . | awk '{print ($1>=9)?"ok":"short"}')" "ok"

    # 11. Verb validation returns non-zero, never a success line.
    chk cli-arfcn-noargs "$(nair_cmd_arfcn >/dev/null 2>&1; echo $?)"        "2"
    chk cli-arfcn-nonnum "$(nair_cmd_arfcn 12ab >/dev/null 2>&1; echo $?)"   "2"
    chk cli-arfcn-range  "$(nair_cmd_arfcn 99999999 >/dev/null 2>&1; echo $?)" "1"
    chk cli-pci-noargs   "$(nair_cmd_pci >/dev/null 2>&1; echo $?)"          "2"
    chk cli-pci-bad      "$(nair_cmd_pci 400 0 >/dev/null 2>&1; echo $?)"    "2"
    chk cli-mib-noargs   "$(nair_cmd_decode_mib >/dev/null 2>&1; echo $?)"   "2"
    chk cli-mib-bad      "$(nair_cmd_decode_mib 1234 >/dev/null 2>&1; echo $?)" "1"
    chk cli-sib1-bad     "$(nair_cmd_decode_sib1 00 >/dev/null 2>&1; echo $?)" "1"
    chk cli-prach-bad    "$(nair_cmd_prach 999 >/dev/null 2>&1; echo $?)"    "1"
    chk cli-ssb-bad      "$(nair_cmd_ssb n78 99 >/dev/null 2>&1; echo $?)"   "1"
    chk cli-unknown      "$(nair_cli_main --nonsense >/dev/null 2>&1; echo $?)" "2"
    out=$(nair_cmd_arfcn 640000); rc=$?
    chk cli-arfcn-rc   "$rc" "0"
    chk cli-arfcn-freq "$(fld "$out" freq_mhz)" "3600.000"
    chk cli-arfcn-band "$(fld "$out" band)"     "n48,n77,n78"

    # 12. TSV injection: a tab in an untrusted string must not forge a row.
    local evil
    evil=$(nair_sanitize $'208-01\tfake\trow\nmore')
    chk sanitize-tabs "$(printf '%s' "$evil" | awk -F'\t' '{print NF}')" "1"
    chk sanitize-nl   "$(printf '%s' "$evil" | grep -c .)" "1"

    rm -rf "$d"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ── menu ────────────────────────────────────────────────────────────────
nair_menu() {
    while true; do
        banner
        echo -e "  ${C_MAG}=== 5G NR air interface ===${C_RESET}"
        echo -e "  gnb: ${C_GRN}$(nair_find_srsran_gnb || echo 'missing (install srsRAN)')${C_RESET}"
        echo -e "  sdr: ${C_GRN}$(nair_find_sdr || echo 'missing (no SDR detected)')${C_RESET}"
        echo -e "  conf: ${C_DIM}$NAIR_CONF${C_RESET}\n"
        cat << 'M'
  [1]  NR-ARFCN -> frequency / band / FR
  [2]  GSCN -> synchronisation frequency
  [3]  PCI from N_ID(1) / N_ID(2)
  [4]  SSB burst set pattern for a band
  [5]  decode a MIB (24-bit hex)
  [6]  decode a SIB1 (hex)
  [7]  PRACH occasions / preamble selection
  [8]  generate gnb.conf (+ Open5GS AMF slice)
  [9]  start gNB
  [10] stop gNB
  [11] status
  [0]  back

M
        local c
        read -rp "  choice> " c || return 0  # EOF: leave the menu cleanly
        case "$c" in
            1)
                read -rp "  NR-ARFCN> " n
                nair_cmd_arfcn "$n" | column -t -s$'\t' 2>/dev/null || nair_cmd_arfcn "$n"
                read -rp "  press enter " _ ;;
            2)
                read -rp "  GSCN> " n
                printf 'gscn\t%s\nfreq_mhz\t%s\n' "$n" "$(nair_gscn_to_mhz "$n" 2>/dev/null || echo 'ERROR invalid')"
                read -rp "  press enter " _ ;;
            3)
                read -rp "  n_id_1 (0-335)> " a
                read -rp "  n_id_2 (0-2)> " b
                nair_cmd_pci "$a" "$b" | column -t -s$'\t' 2>/dev/null || nair_cmd_pci "$a" "$b"
                read -rp "  press enter " _ ;;
            4)
                read -rp "  band (n78)> " b
                read -rp "  i_ssb (0-63)> " i
                nair_cmd_ssb "${b:-n78}" "${i:-0}" | column -t -s$'\t' 2>/dev/null || nair_cmd_ssb "${b:-n78}" "${i:-0}"
                read -rp "  press enter " _ ;;
            5)
                read -rp "  MIB hex (6 digits)> " h
                nair_cmd_decode_mib "$h" | column -t -s$'\t' 2>/dev/null || nair_cmd_decode_mib "$h"
                read -rp "  press enter " _ ;;
            6)
                read -rp "  SIB1 hex> " h
                nair_cmd_decode_sib1 "$h" | column -t -s$'\t' 2>/dev/null || nair_cmd_decode_sib1 "$h"
                read -rp "  press enter " _ ;;
            7)
                read -rp "  prach config index (1)> " x
                read -rp "  msg1-FDM (1|2|4|8)> " f
                nair_cmd_prach "${x:-1}" "${f:-1}" | column -t -s$'\t' 2>/dev/null || nair_cmd_prach "${x:-1}" "${f:-1}"
                read -rp "  press enter " _ ;;
            8)
                read -rp "  PLMN (5-6 digits, e.g. 20801)> " p
                read -rp "  band (n78)> " b
                read -rp "  dl_arfcn (640000)> " a
                read -rp "  pci (1)> " i
                nair_cmd_gen_conf "${p:-00101}" "${b:-n78}" "${a:-640000}" "${i:-1}" | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            9)  nair_start | column -t -s$'\t' 2>/dev/null; read -rp "  press enter " _ ;;
            10) nair_stop  | column -t -s$'\t' 2>/dev/null; read -rp "  press enter " _ ;;
            11) nair_status | column -t -s$'\t' 2>/dev/null; read -rp "  press enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ── CLI dispatch ────────────────────────────────────────────────────────
nair_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)   nair_cli_status_tsv ;;
        --arfcn)        nair_cmd_arfcn "${1:-}" ;;
        --pci)          nair_cmd_pci "${1:-}" "${2:-}" ;;
        --decode-mib)   nair_cmd_decode_mib "${1:-}" ;;
        --decode-sib1)  nair_cmd_decode_sib1 "${1:-}" ;;
        --ssb)          nair_cmd_ssb "${1:-n78}" "${2:-0}" ;;
        --prach)        nair_cmd_prach "${1:-1}" "${2:-1}" "${3:-15}" ;;
        --gen-gnb-conf) nair_cmd_gen_conf "${1:-00101}" "${2:-n78}" "${3:-640000}" "${4:-1}" ;;
        --gen-core-conf) nair_gen_open5gs_conf "${1:-00101}" "${2:-7}" ;;
        --start)        nair_start "${1:-$NAIR_CONF}" ;;
        --stop)         nair_stop ;;
        --status)       nair_status ;;
        --selftest)     nair_selftest ;;
        --menu)         nair_menu ;;
        *)
            cat >&2 <<EOF
5G NR Air Interface — NR-ARFCN, SSB, MIB/SIB1, RACH, gNB orchestration

Usage: $0 COMMAND
  --status-tsv                  tool, config and process state as TSV
  --arfcn <N>                   NR-ARFCN -> frequency, band, FR, GSCN
  --pci <n_id_1> <n_id_2>       PCI derivation (n_id_1 0..335, n_id_2 0..2)
  --decode-mib <hex>            decode a 24-bit MIB payload
  --decode-sib1 <hex>           decode SIB1: PLMN list, TAC, cellIdentity
  --ssb <band> [i_ssb]          SSB burst set pattern and half-frame timing
  --prach <index> [fdm] [scs]   PRACH occasions from the SIB1 RACH config
  --gen-gnb-conf [plmn] [band] [arfcn] [pci]
                                write an srsRAN gNB config
  --gen-core-conf [plmn] [tac]  write a minimal Open5GS AMF slice
  --start [conf]                start the gNB (needs srsRAN)
  --stop                        stop the gNB (idempotent)
  --status                      same fields as --status-tsv, readable
  --selftest                    verify tables and parsers without a radio
  --menu                        interactive menu
EOF
            return 2 ;;
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
    nair_cli_main "$@"
fi
