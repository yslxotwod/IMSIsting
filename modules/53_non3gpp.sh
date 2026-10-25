#!/usr/bin/env bash
# non3gpp — non-3GPP land mobile radio: TETRA, DMR and GSM-R.
#
# Not every radio is 3GPP. TETRA (public safety), DMR (commercial) and GSM-R
# (rail) each have their own air interface and ciphering, and each shows up in
# a spectrum survey next to cellular. This module is a reference for their frame
# structure, cipher families and bands, a band classifier so a survey can tell
# them apart, and a detection note for their weaknesses. It receives only.
#
# Attack owned: adjacent-radio reconnaissance (extends 02/28) — detection half.
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

MOD_TMP="$TMP_DIR/non3gpp"
N3G_DIR="$LOOT_DIR/non3gpp"
mkdir -p "$MOD_TMP" "$N3G_DIR" 2>/dev/null

declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
declare -F warn >/dev/null 2>&1 || warn() { printf '[warn] %s\n' "$*" >&2; }
declare -F err  >/dev/null 2>&1 || err()  { printf '[err]  %s\n' "$*" >&2; }
declare -F ok   >/dev/null 2>&1 || ok()   { printf '[ok]   %s\n' "$*" >&2; }
declare -F banner >/dev/null 2>&1 || banner() { :; }

n3g_sanitize() { printf '%s' "${1:-}" | tr '\t\r\n' '   '; }
N3G_F=()
n3g_split() {
    N3G_F=()
    local i n
    n=$(printf '%s' "$1" | awk -F'\t' '{print NF}')
    for (( i = 1; i <= n; i++ )); do
        N3G_F+=("$(printf '%s' "$1" | cut -f"$i")")
    done
}

n3g_status_tsv() {
    printf 'MODULE\tnon3gpp\n'
    printf 'TARGET\tTETRA, DMR and GSM-R frame structure, ciphering and bands\n'
    printf 'TRANSMIT\tnone — receive and reference only\n'
    printf 'SELFTEST\tyes\n'
}

# ── TETRA (ETSI EN 300 392) ─────────────────────────────────────────────
n3g_tetra_table() {
    cat <<'EOF'
property	value	spec
carrier_spacing	25 kHz	EN 300 392-2
tdma_slots	4	EN 300 392-2
frame_ms	56.67	EN 300 392-2
modulation	pi/4-DQPSK	EN 300 392-2
gross_bitrate	36 kbit/s	EN 300 392-2
duplex_split_400	10 MHz (380-390 UL / 390-400 DL)	EN 300 392-2
guard_ms	0	EN 300 392-2 (no guard interval; 2040 bits at 36 kbit/s)
cipher	TEA1-TEA4	EN 300 392-7
EOF
}
n3g_tetra_tea() {
    case "$1" in
        TEA1) echo "TEA1 — the original cipher, weakened by design; the published cryptanalysis breaks it, so its traffic is not confidential" ;;
        TEA2) echo "TEA2 — 80-bit key, restricted distribution for public safety" ;;
        TEA3) echo "TEA3 — 80-bit key, export variant" ;;
        TEA4) echo "TEA4 — the open, weaker variant" ;;
        *) echo "unknown TEA — never classified as strong" ;;
    esac
}

# ── DMR (ETSI TS 102 361) ───────────────────────────────────────────────
n3g_dmr_table() {
    cat <<'EOF'
property	value	spec
carrier_spacing	12.5 kHz	TS 102 361-1
tdma_slots	2	TS 102 361-1
frame_ms	60	TS 102 361-1
modulation	4FSK	TS 102 361-1
bitrate	9.6 kbit/s	TS 102 361-1
guard_ms	2.5	TS 102 361-1 (2.5 ms guard per 30 ms burst; 264 payload bits at 9.6 kbit/s)
cipher	DMRA privacy / enhanced encryption	TS 102 361-4
EOF
}

# ── GSM-R (ETSI EN 301 515) ─────────────────────────────────────────────
n3g_gsmr_table() {
    cat <<'EOF'
property	value	spec
band	876-880 MHz UL / 921-925 MHz DL	EN 301 515
raster	200 kHz	3GPP/ETSI
features	ASCI (VGCS/VBS), eMLPP preemption, functional addressing	EN 301 515
EOF
}

# ── frame arithmetic ────────────────────────────────────────────────────
n3g_tdma_slot() {
    local frame="${1:-}" slots="${2:-}"
    [[ "$frame" =~ ^[0-9]+([.][0-9]+)?$ && "$slots" =~ ^[1-9][0-9]*$ ]] || {
        printf 'ERROR\tframe length must be numeric and slots a positive integer\n' >&2; return 2; }
    awk -v f="$frame" -v s="$slots" 'BEGIN{ printf "frame_ms\t%s\nslots\t%d\nslot_ms\t%.4f\n", f, s, f/s }'
}

# ── derived frame arithmetic ────────────────────────────────────────────
# The tables above carry frame durations as typed constants. A typed constant
# is only worth what its source is worth, so the same durations are derived
# here from the air interface itself: a slot holds symbols, each symbol carries
# bits, and the gross bit rate fixes how long those bits take. The published
# durations then become known-answer checks on the derivation rather than
# inputs to it.
#
# TETRA: 255 symbols per slot, pi/4-DQPSK (2 bits/symbol), 4 slots, 36 kbit/s
#        -> 2040 bits/frame, 56.6667 ms/frame, 14.1667 ms/slot
# DMR:   132 symbols per burst at 4FSK (2 bits/symbol), 2 slots, 30 ms burst
#        -> 264 bits per burst, 60 ms per frame
n3g_frame_math() {
    local syms="${1:-}" bps="${2:-}" slots="${3:-}" rate="${4:-}" guard="${5:-0}"
    [[ "$syms" =~ ^[1-9][0-9]*$ && "$slots" =~ ^[1-9][0-9]*$ ]] || {
        printf 'ERROR\tsymbols per slot and slot count must be positive integers\n' >&2; return 2; }
    [[ "$bps" =~ ^[0-9]+([.][0-9]+)?$ ]] || {
        printf 'ERROR\tbits per symbol must be numeric\n' >&2; return 2; }
    [[ "$rate" =~ ^[1-9][0-9]*$ ]] || {
        printf 'ERROR\tgross bit rate must be a positive integer (bit/s)\n' >&2; return 2; }
    [[ "$guard" =~ ^[0-9]+([.][0-9]+)?$ ]] || {
        printf 'ERROR\tguard time must be numeric milliseconds per slot\n' >&2; return 2; }
    awk -v s="$syms" -v b="$bps" -v n="$slots" -v r="$rate" -v g="$guard" 'BEGIN{
        bits_slot = s * b
        bits_frame = bits_slot * n
        payload_ms = bits_frame / r * 1000.0
        frame_ms = payload_ms + n * g
        printf "symbols_per_slot\t%d\nbits_per_symbol\t%s\nbits_per_slot\t%.0f\nslots\t%d\nbits_per_frame\t%.0f\npayload_ms\t%.4f\nguard_ms_per_slot\t%s\nframe_ms\t%.4f\nslot_ms\t%.4f\n",
               s, b, bits_slot, n, bits_frame, payload_ms, g, frame_ms, frame_ms / n
    }'
}

# ── band classifier ─────────────────────────────────────────────────────
# A survey sees a channel bandwidth and, sometimes, a modulation. Narrowband
# LMR splits cleanly by spacing.
n3g_classify() {
    local bw="${1:-}" mod="${2:-unknown}"
    [[ "$bw" =~ ^[0-9]+([.][0-9]+)?$ ]] || { printf 'ERROR\tbandwidth (kHz) must be numeric\n' >&2; return 2; }
    local tech
    awk -v b="$bw" 'BEGIN{
        if (b >= 24 && b <= 26)      print "TETRA (4-slot TDMA, 25 kHz)"
        else if (b >= 12 && b <= 13) print "DMR/dPMR (2-slot TDMA, 12.5 kHz)"
        else if (b >= 6 && b < 9)    print "dPMR/NXDN (6.25 kHz narrowband)"
        else if (b >= 190 && b <= 210) print "GSM-R / GSM (200 kHz raster)"
        else                         print "unknown LMR spacing — never classified"
    }' | { read -r t; printf 'bandwidth_khz\t%s\nmodulation\t%s\ntechnology\t%s\n' "$bw" "$mod" "$t"; }
}

# ── codecs: the part that turns bits back into a voice ──────────────────
# A demodulator produces bits. Turning those bits into speech is the vocoder,
# and every system below uses one whose text is not in this tree and, for DMR,
# whose implementation is licensed silicon. The bit budget is what a decoder
# would have to consume, so the missing half is a number rather than an
# omission: ACELP is 137 bits per 30 ms frame, AMBE+2 is 67 per 27.5 ms.
# Nothing here decodes audio, and the last column says so on every row.
n3g_codec_table() {
    cat <<'EOF'
system	codec	bit_rate_bps	frame_ms	speech_standard	licence	implemented_here
TETRA	ACELP	4567	30	EN 300 395-2	public text	no
DMR	AMBE+2	2450	27.5	TS 102 361-2	DVSI licensed	no
DMR	AMBE+2 half rate	1225	27.5	TS 102 361-2	DVSI licensed	no
GSM-R	EFR	12200	20	TS 46.060	public text	no
GSM-R	AMR 4.75	4750	20	TS 26.090	public text	no
GSM-R	AMR 12.2	12200	20	TS 26.090	public text	no
EOF
}

n3g_codec_budget() {
    printf 'system\tcodec\tbit_rate_bps\tframe_ms\tbits_per_frame\tspeech_standard\tlicence\timplemented_here\n'
    n3g_codec_table | tail -n +2 | awk -F'\t' '{
        printf "%s\t%s\t%s\t%s\t%.0f\t%s\t%s\t%s\n", $1, $2, $3, $4, $3 * $4 / 1000, $5, $6, $7
    }'
}

# ── bands: what may be transmitted, and at what power ───────────────────
# The receive half of this module needs no permission. The transmit half does.
# The licensed bands are here for contrast, and to say plainly that 876-880 MHz
# is never something a tool arranges. The interesting rows are the exempt ones:
# 500 mW on PMR446 or 2 W on FRS is the cheapest legal transmitter anyone can
# own, which makes those bands the honest place to learn a transmit path.
n3g_band_table() {
    cat <<'EOF'
region	band	low_mhz	high_mhz	max_power	licence	note
EU	pmr446	446.0	446.2	500 mW EIRP	exempt	ERC/REC 70-03 Annex 1; analogue and digital share the band
UK	pmr446	446.0	446.2	500 mW EIRP	exempt	the same band at the same power, under Ofcom
US	FRS	462.5625	462.7125	2 W ERP	exempt	channels 1-7; 467.5625-467.7125 are channels 8-14
US	MURS	151.82	154.6	2 W ERP	exempt	five VHF channels, business use
RAIL	GSM-R	876.0	880.0	network-licensed	licensed	the railway mobile network; never exempt anywhere
PS	TETRA	380.0	400.0	network-licensed	licensed	public safety; a network licence, not a purchase
EOF
}

n3g_bands() {
    local region="${1:-all}"
    [[ "$region" =~ ^[A-Za-z-]+$ ]] || {
        printf 'ERROR\tregion must be a name like EU, UK, US, RAIL or PS\n' >&2; return 2; }
    printf 'region\tband\tlow_mhz\thigh_mhz\twidth_khz\tmax_power\tlicence\tnote\n'
    n3g_band_table | tail -n +2 | awk -F'\t' -v want="$region" '
        BEGIN { upper = toupper(want); found = 0 }
        upper == "ALL" || toupper($1) == upper {
            found = 1
            printf "%s\t%s\t%s\t%s\t%.1f\t%s\t%s\t%s\n", $1, $2, $3, $4, ($4 - $3) * 1000, $5, $6, $7
        }
        END {
            if (!found) { printf "ERROR\tno band in region %s\n", want > "/dev/stderr"; exit 2 }
        }'
}

n3g_detect_note() {
    cat <<'EOF'
system	weakness	detection note
TETRA TEA1	a deliberately weakened cipher	look for TEA1-ciphered traffic on a public-safety carrier; treat as cleartext for confidentiality purposes
TETRA TEA4	open, weak variant	the open variant is used for interoperability; same caution
DMR privacy	commercial privacy is a scrambler, not a confidentiality mechanism	privacy keys are often default or shared; treat it as obfuscation, never as protection
GSM-R	shares the GSM stack and its older ciphers	rail signalling availability is safety-critical; observe, do not interfere
EOF
}

n3g_plan() {
    cat <<'EOF'
status	handoff
what	receiving TETRA/DMR/GSM-R
hardware	an SDR covering the band: TETRA 380-400 MHz, DMR 400-470 MHz, GSM-R 876-925 MHz
software	telive or a TETRA demodulator for TETRA, dmrdecode/DSD for DMR, gr-gsm for GSM-R
flow	1. --classify the observed channel spacing  2. --tdma for the frame maths  3. --detect-note for the cipher posture
transmit	the exempt rows of --bands are the only place a transmit path makes sense without a licence, and --codecs is what a receive chain still lacks to produce audio
note	receiving public-safety traffic may be restricted where you are; decrypting it requires keys you are not entitled to
EOF
}

n3g_selftest() {
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
    export N3G_DIR="$d/loot/non3gpp"
    mkdir -p "$N3G_DIR"

    # 1. TETRA frame structure (EN 300 392-2): 4 slots in 56.67 ms.
    chk tetra-slots "$(n3g_tetra_table | awk -F'\t' '$1=="tdma_slots"{print $2}')" "4"
    chk tetra-slot "$(fld "$(n3g_tdma_slot 56.67 4)" slot_ms)" "14.1675"
    chk tetra-bw "$(n3g_tetra_table | awk -F'\t' '$1=="carrier_spacing"{print $2}')" "25 kHz"
    # The claim is the mechanism, not a key-bit figure copied from a paper:
    # naming a number this tree cannot cite would be the same fault as a
    # fabricated decoder, one decimal place quieter.
    chk tetra-tea1 "$(n3g_tetra_tea TEA1)" "TEA1 — the original cipher, weakened by design; the published cryptanalysis breaks it, so its traffic is not confidential"
    chk tetra-tea1-no-figure "$(n3g_tetra_tea TEA1 | grep -c '40-bit')" "0"
    chk tetra-tea2 "$(n3g_tetra_tea TEA2)" "TEA2 — 80-bit key, restricted distribution for public safety"
    chk tetra-tea-unknown "$(n3g_tetra_tea TEA9)" "unknown TEA — never classified as strong"

    # 2. DMR frame structure (TS 102 361-1): 2 slots in 60 ms.
    chk dmr-slots "$(n3g_dmr_table | awk -F'\t' '$1=="tdma_slots"{print $2}')" "2"
    chk dmr-slot "$(fld "$(n3g_tdma_slot 60 2)" slot_ms)" "30.0000"
    chk dmr-mod "$(n3g_dmr_table | awk -F'\t' '$1=="modulation"{print $2}')" "4FSK"

    # 2b. The published frame durations are DERIVED from the air interface here
    # and then checked against the standard's own numbers: 56.67 ms for TETRA
    # (2040 bits at 36 kbit/s) and 60 ms for DMR (528 bits at 9.6 kbit/s plus
    # two 2.5 ms guards). A typed constant would only prove the constant.
    chk frame-tetra "$(fld "$(n3g_frame_math 255 2 4 36000)" frame_ms)" "56.6667"
    chk frame-tetra-slot "$(fld "$(n3g_frame_math 255 2 4 36000)" slot_ms)" "14.1667"
    chk frame-tetra-vs-table "$(n3g_tetra_table | awk -F'\t' '$1=="frame_ms"{printf"%.2f",$2}')" "56.67"
    chk frame-dmr "$(fld "$(n3g_frame_math 132 2 2 9600 2.5)" frame_ms)" "60.0000"
    chk frame-dmr-payload "$(fld "$(n3g_frame_math 132 2 2 9600 2.5)" payload_ms)" "55.0000"
    chk frame-dmr-vs-table "$(n3g_dmr_table | awk -F'\t' '$1=="frame_ms"{printf"%.0f",$2}')" "60"
    chk frame-guard-agrees "$(n3g_dmr_table | awk -F'\t' '$1=="guard_ms"{print $2}')" "2.5"
    chk frame-bad-rate "$(n3g_frame_math 255 2 4 0 >/dev/null 2>&1; echo $?)" "2"
    chk frame-bad-guard "$(n3g_frame_math 132 2 2 9600 x >/dev/null 2>&1; echo $?)" "2"

    # 3. GSM-R band (EN 301 515).
    chk gsmr-ul "$(n3g_gsmr_table | awk -F'\t' '$1=="band"{print $2}' | cut -d' ' -f1)" "876-880"
    chk gsmr-feat "$(n3g_gsmr_table | awk -F'\t' '$1=="features"{print ($2 ~ /eMLPP/)?"yes":"no"}')" "yes"

    # 4. Band classifier: each spacing maps, unknown never guesses.
    chk cls-tetra "$(fld "$(n3g_classify 25)" technology)" "TETRA (4-slot TDMA, 25 kHz)"
    chk cls-dmr   "$(fld "$(n3g_classify 12.5)" technology)" "DMR/dPMR (2-slot TDMA, 12.5 kHz)"
    chk cls-dpmr  "$(fld "$(n3g_classify 6.25)" technology)" "dPMR/NXDN (6.25 kHz narrowband)"
    chk cls-gsmr  "$(fld "$(n3g_classify 200)" technology)" "GSM-R / GSM (200 kHz raster)"
    chk cls-unknown "$(fld "$(n3g_classify 33)" technology)" "unknown LMR spacing — never classified"
    chk cls-bad "$(n3g_classify x >/dev/null 2>&1; echo $?)" "2"
    chk slot-bad "$(n3g_tdma_slot 60 0 >/dev/null 2>&1; echo $?)" "2"

    # 5. Detection note names the TEA1 weakness and the GSM-R caution.
    chk detect-tea1 "$(n3g_detect_note | awk -F'\t' '$1=="TETRA TEA1"{print ($2 ~ /weakened/)?"yes":"no"}')" "yes"
    chk detect-gsmr "$(n3g_detect_note | awk -F'\t' '$1=="GSM-R"{print ($3 ~ /observe, do not interfere/)?"yes":"no"}')" "yes"

    # 6. Codecs: the bit budget of the half this tree does not decode. The
    # numbers are rate x frame, so they are arithmetic rather than a quoted
    # constant, and the last column admits the absence on every row.
    chk codec-acelp "$(n3g_codec_budget | awk -F'\t' '$1=="TETRA" && $2=="ACELP"{print $5}')" "137"
    chk codec-ambe "$(n3g_codec_budget | awk -F'\t' '$1=="DMR" && $2=="AMBE+2"{print $5}')" "67"
    chk codec-ambe-half "$(n3g_codec_budget | awk -F'\t' '$2=="AMBE+2 half rate"{print $5}')" "34"
    chk codec-efr "$(n3g_codec_budget | awk -F'\t' '$1=="GSM-R" && $2=="EFR"{print $5}')" "244"
    chk codec-amr "$(n3g_codec_budget | awk -F'\t' '$1=="GSM-R" && $2=="AMR 4.75"{print $5}')" "95"
    chk codec-none-implemented "$(n3g_codec_budget | awk -F'\t' 'NR>1 && $8!="no"' | wc -l)" "0"
    chk codec-licensed "$(n3g_codec_budget | awk -F'\t' '$2=="AMBE+2"{print ($7 ~ /licensed/)?"yes":"no"}')" "yes"

    # 7. Bands: the exempt rows are the only legal transmitter anyone owns,
    # and the licensed rows must never read as purchasable.
    chk bands-pmr-width "$(n3g_bands EU | awk -F'\t' '$2=="pmr446"{print $5}')" "200.0"
    chk bands-pmr-power "$(n3g_bands EU | awk -F'\t' '$2=="pmr446"{print $6}')" "500 mW EIRP"
    chk bands-exempt "$(n3g_bands all | awk -F'\t' '$7=="exempt"' | wc -l)" "4"
    chk bands-licensed "$(n3g_bands all | awk -F'\t' '$7=="licensed"' | wc -l)" "2"
    chk bands-eu-rows "$(n3g_bands EU | wc -l)" "2"
    chk bands-bad-region "$(n3g_bands 9 >/dev/null 2>&1; echo $?)" "2"
    chk bands-no-such-region "$(n3g_bands ZZ >/dev/null 2>&1; echo $?)" "2"

    printf 'ASSERTIONS\t%d\n' "$nchk"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

n3g_menu() {
    while true; do
        banner
        echo "  === TETRA / DMR / GSM-R ==="
        echo
        cat <<'M'
  [1]  TETRA reference
  [2]  TEA cipher reference
  [3]  DMR reference
  [4]  GSM-R reference
  [5]  TDMA slot maths
  [6]  Classify a channel spacing
  [7]  Codec bit budgets
  [8]  Bands and licence class
  [9]  Detection notes
  [10] Plan (handoff)
  [0]  back
M
        read -rp "  choice> " c || return 0
        case "$c" in
            1) n3g_tetra_table; read -rp "  enter " _ ;;
            2) for t in TEA1 TEA2 TEA3 TEA4; do printf '%s\t%s\n' "$t" "$(n3g_tetra_tea "$t")"; done; read -rp "  enter " _ ;;
            3) n3g_dmr_table; read -rp "  enter " _ ;;
            4) n3g_gsmr_table; read -rp "  enter " _ ;;
            5) read -rp "  frame ms> " f; read -rp "  slots> " s; n3g_tdma_slot "$f" "$s"; read -rp "  enter " _ ;;
            6) read -rp "  bandwidth kHz> " b; read -rp "  modulation> " m; n3g_classify "$b" "${m:-unknown}"; read -rp "  enter " _ ;;
            7) n3g_codec_budget; read -rp "  enter " _ ;;
            8) n3g_bands "all"; read -rp "  enter " _ ;;
            9) n3g_detect_note; read -rp "  enter " _ ;;
            10) n3g_plan; read -rp "  enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

n3g_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)   n3g_status_tsv ;;
        --tetra)        n3g_tetra_table ;;
        --tea)          n3g_tetra_tea "${1:-}" ;;
        --dmr)          n3g_dmr_table ;;
        --gsmr)         n3g_gsmr_table ;;
        --tdma)         n3g_tdma_slot "${1:-}" "${2:-}" ;;
        --frame-math)   n3g_frame_math "${1:-}" "${2:-}" "${3:-}" "${4:-}" "${5:-0}" ;;
        --classify)     n3g_classify "${1:-}" "${2:-unknown}" ;;
        --codecs)       n3g_codec_budget ;;
        --bands)        n3g_bands "${1:-all}" ;;
        --detect-note)  n3g_detect_note ;;
        --plan)         n3g_plan ;;
        --selftest)     n3g_selftest ;;
        --menu)         n3g_menu ;;
        *)
            cat >&2 <<EOF
Non-3GPP Land Mobile Radio — TETRA, DMR and GSM-R

Usage: $0 COMMAND
  --status-tsv              module state as TSV
  --tetra                   TETRA frame/band reference (EN 300 392)
  --tea <TEA1..TEA4>        TETRA cipher description
  --dmr                     DMR reference (TS 102 361)
  --gsmr                    GSM-R band/feature reference (EN 301 515)
  --tdma <frame_ms> <slots> TDMA slot arithmetic (from a stated frame length)
  --frame-math <syms> <bits/sym> <slots> <bit/s>  derive the frame length from the air interface
  --classify <khz> [mod]    identify the technology from channel spacing
  --codecs                  the vocoders and the bit budget a decoder must consume
  --bands [REGION]          band edges, power and licence class; PMR446/FRS are the exempt ones
  --detect-note             cipher-weakness and detection notes
  --plan                    receive-only handoff plan
  --selftest                verify the references and the classifier
  --menu                    interactive menu
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
    n3g_cli_main "$@"
fi
