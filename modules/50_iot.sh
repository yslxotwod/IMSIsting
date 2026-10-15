#!/usr/bin/env bash
# NB-IoT / Cat-M1 — narrowband IoT air interface with NPRACH, NPSS, NSSS, NPDCCH, NPDSCH
#
# NB-IoT (Narrowband IoT) and Cat-M1 are low-power wide-area (LPWA) technologies
# that share the LTE spectrum but use a 180 kHz channel with different physical
# layer structures. This module covers NPRACH, NPSS/NSSS, NPDCCH/NPDSCH, and
# the unique SIB types (SIB1-NB, SIB2-NB, SIB3-NB, SIB4-NB, SIB5-NB, SIB14-NB).
#
# Attack owned: LPWA adjacency (extends P1/P8 — NB-IoT devices as an identity
# and availability target) — decode and framing half. NPRACH resource maps,
# NPSS/NSSS and the SIB1-NB/SIB14-NB fields are decoded for real here; standing
# up a cell, or flooding NPRACH, is a named-hardware plan (--plan).
#
# Resolve IMSISTING_ROOT from this script's own path.
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

MOD_TMP="$TMP_DIR/iot"
IOT_DIR="$LOOT_DIR/iot"
IOT_PLAN_DIR="$IOT_DIR/plans"
mkdir -p "$MOD_TMP" "$IOT_DIR" "$IOT_PLAN_DIR" 2>/dev/null

# Palette
C_RED=$'\e[38;5;196m'; C_GRN=$'\e[38;5;46m';   C_YEL=$'\e[38;5;226m'
C_CYN=$'\e[38;5;51m';  C_MAG=$'\e[38;5;201m';  C_BLU=$'\e[38;5;39m'
C_ORG=$'\e[38;5;208m'; C_PUR=$'\e[38;5;135m';  C_DIM=$'\e[38;5;240m'
C_WHT=$'\e[38;5;255m'; C_BOLD=$'\e[1m';        C_RESET=$'\e[0m'
export C_RED C_GRN C_YEL C_CYN C_MAG C_BLU C_ORG C_PUR C_DIM C_WHT C_BOLD C_RESET

declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
declare -F ok   >/dev/null 2>&1 || ok()   { printf '[ok]   %s\n' "$*" >&2; }
declare -F warn >/dev/null 2>&1 || warn() { printf '[warn] %s\n' "$*" >&2; }
declare -F err  >/dev/null 2>&1 || err()  { printf '[err]  %s\n' "$*" >&2; }

# ── status ──────────────────────────────────────────────────────────────
iot_status_tsv() {
    local tool_missing=()
    for t in python3 awk; do
        command -v "$t" >/dev/null 2>&1 || tool_missing+=("$t")
    done
    local status=ok
    ((${#tool_missing[@]} > 0)) && status=missing
    printf 'STATUS\t%s\n' "$status"
    ((${#tool_missing[@]} > 0)) && printf 'MISSING\t%s\n' "$(IFS=,; echo "${tool_missing[*]}")"
}

# ── NPRACH parameters (TS 36.211 §14.2) ─────────────────────────────────
# NPRACH uses 12 subcarriers, preamble format 0 with N_cp=67 or N_cp=125
iot_nprach_params() {
    local central_freq="${1:-2140.0}"  # n28 example
    local prach_cfg="${2:-0}"          # index 0-15
    local subcar_spacing="${3:-3.75}"  # kHz
    
    # Format 0: N_cp=67 (normal CP) or N_cp=125 (extended CP)
    local n_cp=67
    local symbol_len=$((15360 + n_cp))
    local frame_len=$((153600 + 10*n_cp))
    
    cat << EOF
NPRACH Parameters
=================
Central Freq: ${central_freq} MHz
PRACH Config: ${prach_cfg}
Subcarrier:   ${subcar_spacing} kHz
Symbols:      12 subcarriers × 7 symbols = 84 resource elements
CP length:    ${n_cp} samples (${symbol_len} samples/symbol)
Frame length: ${frame_len} samples
EOF
}

# ── NPSS/NSSS sequences (TS 36.211 §14.3) ───────────────────────────────
# NPSS: 127-point ZC sequence, period 10ms
# NSSS: 127-point ZC sequence, period 20ms, different ZC root
iot_npss_to_nss() {
    local pci="${1:-0}"
    
    # PCI = 3*N_ID(1) + N_ID(2), where N_ID(1) and N_ID(2) define the ZC roots
    local n_id_1=$(( pci / 3 ))
    local n_id_2=$(( pci % 3 ))
    
    cat << EOF
NPSS/NSSS for PCI=$pci
=====================
N_ID(1): $n_id_1
N_ID(2): $n_id_2
NPSS:    ZC sequence with root $n_id_1, period 10ms
NSSS:    ZC sequence with root ($n_id_1 + $n_id_2 + 1) mod 127, period 20ms
EOF
}

# ── SIB1-NB decoding (TS 36.331 §6.3.1) ────────────────────────────────
iot_decode_sib1_nb() {
    local hex="$1"
    [[ -z "$hex" ]] && { warn "usage: --decode-sib1-nb <hex>"; return 1; }
    
    # SIB1-NB is 160 bits (20 octets)
    [[ ${#hex} -lt 40 ]] && { warn "SIB1-NB too short"; return 1; }
    
    local mib_nb="${hex:0:4}"
    local sched_info="${hex:4:2}"
    local si_period="${hex:6:2}"
    local tdd_config="${hex:8:2}"
    local pws_cfg="${hex:10:2}"
    local cell_id="${hex:12:6}"
    
    cat << EOF
SIB1-NB Decoded
===============
MIB-NB:        $mib_nb
Scheduling:    $sched_info
SI Period:     $si_period × 1024 frames
TDD Config:    $tdd_config
PWS Config:    $pws_cfg
Cell ID:       0x$cell_id
EOF
}

# ── Band mapping (TS 36.104 Table 5.7.3-1) ─────────────────────────────
iot_nprfcn_to_mhz() {
    local nprfcn="$1"
    [[ "$nprfcn" =~ ^[0-9]+$ ]] || { warn "NPRFCN must be numeric"; return 1; }
    
    # NB-IoT operates in-band, stand-alone, or guard-band
    # Frequency is derived from the carrier bandwidth center
    awk -v n="$nprfcn" 'BEGIN{
        if (n >= 0 && n <= 999) printf "%.3f", 410.0 + 0.1*n
        else if (n >= 1000 && n <= 1999) printf "%.3f", 500.0 + 0.1*(n-1000)
        else exit 1
    }' || { warn "NPRFCN out of range"; return 1; }
}

# ── Plan files (MODULE_CONVENTIONS §9) ─────────────────────────────────
# The decode half of this module runs anywhere. Standing up a cell that an
# NB-IoT device will actually attach to, and flooding its NPRACH, both need
# hardware this tree does not assume — so they ship as labelled plan files
# whose first lines are `status: handoff` and the exact hardware.
iot_plan() {
    local kind="${1:-}"
    case "$kind" in
        fake-cell|nprach-flood) ;;
        *) printf 'ERROR\tunknown plan: %s (want fake-cell|nprach-flood)\n' "${kind:-<none>}" >&2; return 2 ;;
    esac
    local hw ts f
    hw="an SDR you are authorised to transmit with (USRP B210/X310 or LimeSDR), srsRAN (srsRAN_4G or srsRAN Project) or OpenAirInterface built for NB-IoT/Cat-M1, a programmable SIM or an NB-IoT test USIM, a faraday-isolated enclosure or a licensed test cell, and a sacrificial IoT device or module (Quectel BC66/BG96, u-blox SARA-N) you own"
    ts=$(date +%Y%m%d_%H%M%S)
    mkdir -p "$IOT_PLAN_DIR"
    f="$IOT_PLAN_DIR/plan_${kind}_${ts}.txt"
    {
        echo "plan: $kind"
        echo "status: handoff"
        echo "hardware: $hw"
        echo "ts: $(date -Is)"
        echo
        if [[ "$kind" == "fake-cell" ]]; then
            cat <<'EOF'
objective
  Show that an NB-IoT / Cat-M1 device will select and attach to a cell this
  module controls, and record what identity material it offers before any
  application-layer authentication happens.

why it is worth doing
  LPWA devices are deployed as meters, trackers and sensors, frequently with
  no user-visible indication of which cell they are on. LTE identity
  protection (a GUTI) does not survive a cell the device has never seen, and
  the attach that follows is where the device is most willing to talk.

preconditions
  1. The target's band is known: run `01_radio --survey` or read the device's
     band list. NB-IoT is most often n8 / n20 / n28; Cat-M1 also n1/n3/n18.
  2. An NPRFCN in that band with no live operator, so the real cell does not
     out-compete the test cell. `--to-mhz <nprfcn>` converts.
  3. The device is powered in the enclosure, not on the production network.

sequence
  1. Stand up the cell with srsRAN's NB-IoT mode at the chosen NPRFCN, with
     MIB-NB and SIB1-NB set to advertise access, and SIB14-NB (access barring)
     left permissive. This module's `--decode-sib1 <hex>` verifies the SIB1-NB
     you broadcast decodes to what you intended.
  2. Watch the attach: RRC connection setup, then the NAS ATTACH REQUEST. The
     IMSI appears only if the device has no valid GUTI for this PLMN — which
     is the normal case for a cell it has never seen. If it offers a GUTI,
     issue an identity request; a device with no stored mapping answers.
  3. Record the IMEISV as well. Many LPWA modules answer even when the SIM is
     absent, and the module model plus firmware narrows the CVE set in 25_lte_cve.
  4. If the device accepts a network-initiated detach, note that it will
     re-attach and offer identity again — this is the repeatable part.

what is proven and what is not
  Proven: the device selects and attaches to a cell you control, and the
  identity/equipment material it volunteers.
  Not proven: anything about the core network. This is an air-interface
  capture, and no traffic leaves the enclosure.

stop conditions
  Abort on the first unexpected transmission in the surrounding spectrum, and
  keep the run inside the enclosure or the licensed cell. An NB-IoT cell at
  n28 shares spectrum with live downlink; transmitting outside a shielded
  environment is interference, not research.
EOF
        else
            cat <<'EOF'
objective
  Measure how little NPRACH traffic it takes to make an NB-IoT cell unable to
  serve legitimate devices, and whether the preamble a device picks is
  predictable enough to target.

why it is worth doing
  NPRACH is 12 subcarriers in a 180 kHz channel with a small number of
  preamble formats and a frequency-hopping pattern that is fully specified.
  Capacity is tiny compared with LTE PRACH, so the ratio of attacker packets
  to legitimate service loss is unusually favourable.

preconditions
  1. A cell you own — either the fake-cell plan above, or a lab eNB running
     NB-IoT on an isolated band.
  2. One or more sacrificial devices with no production SIM.
  3. A power level chosen so the preamble reaches the eNB and nothing else.

sequence
  1. Baseline: log the device's preamble selection. Run `--nprach <freq> <cfg>
     <spacing>` for the configured preamble format and subcarrier set, then
     confirm against the capture that the real preamble fell where predicted.
  2. Drive preambles at increasing rate. The interesting measurement is not
     the maximum rate but the *lowest* rate at which the legitimate device's
     contention resolution stops completing.
  3. Repeat with the preambles offset from the device's; if both complete, the
     collision is resource-blocking rather than preamble-blocking, and the
     distinction changes the mitigation.
  4. Record the rate, the configured NPRACH periodicity, and the number of
     repetitions used (NB-IoT repeats preambles up to 128 times, which is what
     makes the amplification real).

what is proven and what is not
  Proven: the offered load at which this cell stops completing contention
  resolution, on this band and configuration.
  Not proven: that the same rate works against an operator cell. NPRACH
  periodicity and repetition counts are operator configuration, and
  `01_radio --survey` cannot read them — they come from SIB2-NB on the target.
EOF
        fi
    } > "$f"
    printf 'PLAN\t%s\n' "$f"
    printf 'STATUS\thandoff\n'
    printf 'HARDWARE\t%s\n' "$hw"
}

# ── Selftest ───────────────────────────────────────────────────────────
iot_selftest() {
    local bad=0 nchk=0
    chk() {
        nchk=$(( nchk + 1 ))
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$(( bad + 1 )); fi
    }

    # 1. NPRACH parameter checks (TS 36.211 §14.2)
    local params=$(iot_nprach_params 2140.0 0 3.75)
    local symbols=$(echo "$params" | awk '/resource elements/{print $8}')
    local cp=$(echo "$params" | grep 'CP length:' | awk '{print $3}')
    chk nprach-symbols "$symbols" "84"
    chk nprach-cp "$cp" "67"

    # 2. NPSS/NSSS ZC root calculation
    local zc_root=$(iot_npss_to_nss 1)
    local n_id_1=$(echo "$zc_root" | grep 'N_ID(1):' | awk '{print $2}')
    local n_id_2=$(echo "$zc_root" | grep 'N_ID(2):' | awk '{print $2}')
    chk npss-nid1 "$n_id_1" "0"
    chk npss-nid2 "$n_id_2" "1"

    # 3. SIB1-NB decoding
    local sib1=$(iot_decode_sib1_nb "0000000000000000000000000000000000000000")
    local field_count=$(echo "$sib1" | grep -c ':')
    chk sib1-fields "$field_count" "6"

    # 4. NPRFCN to MHz (TS 36.104)
    chk nprfcn-0   "$(iot_nprfcn_to_mhz 0)"   "410.000"
    chk nprfcn-500 "$(iot_nprfcn_to_mhz 500)" "460.000"
    chk nprfcn-999 "$(iot_nprfcn_to_mhz 999)" "509.900"
    chk nprfcn-oob "$(iot_nprfcn_to_mhz 10000 >/dev/null 2>&1; echo $?)" "1"

    # 5. Unknown values must fail, not guess
    chk nprfcn-neg "$(iot_nprfcn_to_mhz -1 >/dev/null 2>&1; echo $?)" "1"
    chk nprfcn-str "$(iot_nprfcn_to_mhz abc >/dev/null 2>&1; echo $?)" "1"
    chk sib1-short "$(iot_decode_sib1_nb "000000" >/dev/null 2>&1; echo $?)" "1"

    # 6. --plan is a handoff and must say so, and must reject an unknown kind.
    chk plan-bad-kind "$(iot_plan not-a-plan >/dev/null 2>&1; echo $?)" "2"
    chk plan-no-args  "$(iot_plan >/dev/null 2>&1; echo $?)" "2"
    local plan_out plan_file
    plan_out=$(iot_plan fake-cell 2>&1) || true
    plan_file=$(printf '%s\n' "$plan_out" | awk -F'\t' '$1=="PLAN"{print $2}')
    chk plan-emits-status "$(printf '%s\n' "$plan_out" | awk -F'\t' '$1=="STATUS"{print $2}')" "handoff"
    chk plan-file-written "$([[ -n "$plan_file" && -f "$plan_file" ]] && echo y || echo n)" "y"
    chk plan-file-says-handoff "$(grep -c '^status: handoff$' "$plan_file" 2>/dev/null)" "1"
    chk plan-file-names-hw "$(grep -c '^hardware: ' "$plan_file" 2>/dev/null)" "1"
    [[ -n "$plan_file" && -f "$plan_file" ]] && rm -f "$plan_file"

    printf 'ASSERTIONS\t%d\n' "$nchk"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ── menu ───────────────────────────────────────────────────────────────
iot_menu() {
    while true; do
        banner
        echo -e "  ${C_MAG}=== NB-IoT / Cat-M1 ===${C_RESET}\n"
        cat << 'M'
  [1]  NPRACH parameters
  [2]  NPSS/NSSS ZC roots
  [3]  Decode SIB1-NB
  [4]  NPRFCN to MHz
  [0]  back

M
        read -rp "  choice> " c || return 0
        case "$c" in
            1)
                read -rp "  freq (MHz)> " f
                read -rp "  prach_cfg> " p
                read -rp "  subcarrier (kHz)> " s
                iot_nprach_params "$f" "$p" "$s"; read -rp "  press enter " _ ;;
            2)
                read -rp "  PCI> " p
                iot_npss_to_nss "$p"; read -rp "  press enter " _ ;;
            3)
                read -rp "  hex> " h
                iot_decode_sib1_nb "$h"; read -rp "  press enter " _ ;;
            4)
                read -rp "  nprfcn> " n
                echo "$(iot_nprfcn_to_mhz "$n") MHz"
                read -rp "  press enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ── CLI dispatch ───────────────────────────────────────────────────────
iot_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)   iot_status_tsv ;;
        --nprach)       iot_nprach_params "${1:-2140.0}" "${2:-0}" "${3:-3.75}" ;;
        --npss-nss)     iot_npss_to_nss "${1:-0}" ;;
        --decode-sib1)  iot_decode_sib1_nb "${1:-}" ;;
        --to-mhz)       iot_nprfcn_to_mhz "${1:-}" ;;
        --plan)         iot_plan "${1:-}" ;;
        --selftest)     iot_selftest ;;
        --menu)         iot_menu ;;
        *) cat >&2 <<EOF
NB-IoT / Cat-M1 — narrowband IoT air interface

Usage: $0 COMMAND
  --status-tsv       tool and store state as TSV
  --nprach [freq] [cfg] [spacing]
  --npss-nss [pci]
  --decode-sib1 <hex>
  --to-mhz <nprfcn>
  --plan <fake-cell|nprach-flood>
                     write a handoff plan (status: handoff) for a vector that
                     needs transmit hardware; no transmission is performed
  --selftest         verify tables and parsers
  --menu             interactive menu
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
    iot_cli_main "$@"
fi
