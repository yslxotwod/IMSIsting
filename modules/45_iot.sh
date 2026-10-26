#!/usr/bin/env bash
# NB-IoT / Cat-M1 — narrowband IoT air interface with NPRACH, NPSS, NSSS, NPDCCH, NPDSCH
#
# NB-IoT (Narrowband IoT) and Cat-M1 are low-power wide-area (LPWA) technologies
# that share the LTE spectrum but use a 180 kHz channel with different physical
# layer structures. This module decodes the unique SIB types (MIB-NB,
# SIB1-NB and, through the same codec, SIB2/3/4/5/14-NB) and does the PCI
# decomposition a receiver needs before it correlates NPSS/NSSS.
#
# Attack owned: LPWA adjacency (extends P1/P8 — NB-IoT devices as an identity
# and availability target) — decode and framing half. MIB-NB and SIB1-NB are
# decoded here, by the
# generated PER codec rather than by slicing hex, so every field printed came
# out of the message. The whole NB broadcast set is reachable through that
# codec; the two verbs expose the two messages a capture usually has.
#
# NPRACH is computed, not tabulated. --nprach traces the symbol-group hopping
# of TS 36.211 10.1.6.1 (one subcarrier per group, the first four groups
# deterministic, the rest from the clause 7.2 sequence seeded with the cell id)
# through tools/nbiot_nprach.py, and --nprach-decode lifts nprach-ConfigSIB-NB
# out of a real SIB2-NB. What this module used to print instead was an
# 84-resource-element grid that is not NPRACH at all, and it ignored its
# arguments, so no input changed the answer.
#
# NPRFCN->MHz is still REFUSED. This module used to answer a single 410 MHz
# intercept plus a 500 MHz branch above 1000, neither of which is a band rule;
# and the column that would settle it is not where the old WHY claimed -- TS
# 36.104 V16.6.0 Table 5.7.3-1 carries only the E-UTRA channel numbers, and
# NPRFCN appears in none of 36.104, 36.101 or 36.211.
# Standing up a cell, or flooding NPRACH, is a named-hardware plan (--plan).
#
# The decode half needs no radio and no schema package: tools/lte_per.py is
# standard library only and tools/lte_rrc_nb_layout.py is generated data.
# Regenerate it (needs pycrate, i.e. the oracle venv) with:
#   /home/ysl/.lte-oracles/venv/bin/python tools/asn1gen.py --family nbiot
# and re-certify it with:
#   /home/ysl/.lte-oracles/venv/bin/python tools/lte-per-oracle/verify_per.py \
#       --table tools/lte_rrc_nb_layout.py
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
IOT_TOOL_NPRACH="$IMSISTING_ROOT/tools/nbiot_nprach.py"
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

# ── NPRACH parameters: refused, see the WHY below ────────────────────────
# NPRACH uses 12 subcarriers, preamble format 0 with N_cp=67 or N_cp=125
iot_nprach_params() {
    # An NPRACH preamble is a sequence of symbol groups, each ONE subcarrier
    # wide, whose subcarrier is chosen by the hopping rule of TS 36.211
    # 10.1.6.1. This verb used to print a CP of 67 samples, 15360-sample
    # symbols and "12 subcarriers x 7 symbols = 84 resource elements", none of
    # which are NPRACH numbers, and it ignored its arguments.
    local cell="${1:-0}" init="${2:-0}" offset="${3:-0}" sub="${4:-12}"
    local fmt="${5:-0}" groups="${6:-0}"
    if [[ ! -f "$IOT_TOOL_NPRACH" ]]; then
        printf 'ERROR\ttools/nbiot_nprach.py is missing\n' >&2
        printf 'WHY\tNPRACH hopping is a per-symbol-group rule; without the tool this verb can only guess\n' >&2
        return 1
    fi
    local out rc
    out=$(python3 "$IOT_TOOL_NPRACH" pattern --cell "$cell" --init "$init" \
            --offset "$offset" --num-subcarriers "$sub" --format "$fmt" \
            --groups "$groups" 2>&1)
    rc=$?
    printf '%s\n' "$out"
    return $rc
}

# ── NPRACH configuration out of a real SIB2-NB ──────────────────────────
# The seven fields TS 36.211 10.1.6.1 names are all in nprach-ConfigSIB-NB of
# SystemInformationBlockType2-NB, which the NB layout table carries. This verb
# decodes the message and then lifts those fields out by name, so the answer is
# the configuration a cell actually broadcast rather than a constant.
iot_decode_sib2_nb() {
    local hex="${1:-}"
    [[ -n "$hex" ]] || { warn "usage: --nprach-decode <sib2-nb hex>"; return 2; }
    local out
    out=$(iot_nb_codec SystemInformationBlockType2_NB_r13 "$hex") || return 1
    local consumed
    consumed=$(printf '%s\n' "$out" | awk -F'\t' '$1=="bits_consumed"{print $2}')
    if [[ -n "$consumed" ]] && (( consumed < 40 )); then
        printf '%s\n' "$out" | sed '/^$/d;s/^/ERROR\t/'
        printf 'NOTDECODED\tonly %s bits were a SIB2-NB; this is not one\n' "$consumed" >&2
        return 1
    fi
    printf '%s\n' "$out"
    # Lift the NPRACH configuration out by name. A field the message does not
    # carry is named as absent rather than printed as zero.
    local key val found=0
    local -a wanted=(
        "nprach-Periodicity-r13"
        "nprach-SubcarrierOffset-r13"
        "nprach-NumSubcarriers-r13"
        "nprach-NumCBRA-StartSubcarriers-r13"
        "nprach-SubcarrierMSG3-RangeStart-r13"
        "numRepetitionsPerPreambleAttempt-r13"
        "nprach-StartTime-r13"
    )
    local w
    for w in "${wanted[@]}"; do
        val=$(printf '%s\n' "$out" | awk -F'\t' -v k="$w" 'index($1, k) > 0 { print $2; exit }')
        if [[ -n "$val" ]]; then
            printf 'nprach_config\t%s\t%s\n' "$w" "$val"
            found=$((found + 1))
        else
            printf 'nprach_config\t%s\tabsent\n' "$w"
        fi
    done
    printf 'nprach_config_fields\t%d\n' "$found"
    printf 'ref\t3GPP TS 36.331 6.3.1 SystemInformationBlockType2-NB nprach-ConfigSIB-NB; the field names and their meaning are 3GPP TS 36.211 10.1.6.1 (N_period, N_sc^offset, N_sc^NPRACH, N_sc_cont, N_MSG3, N_rep, N_start)\n'
    printf 'limit\tthis reports the configuration the message carries; it does not decide whether the cell is valid, which needs N_sc^offset + N_sc^NPRACH <= N_sc^UL from the uplink bandwidth\n'
    return 0
}

# ── NPSS/NSSS sequences (TS 36.211 §10.2.7) ─────────────────────────────
# NPSS is a FIXED length-11 ZC sequence with root 5, and does not depend on the
# cell at all; a receiver uses it to find a carrier, not to identify one. NSSS
# is the PCI-bearing sequence: its root comes from N_ID(1), and its cyclic
# shift from N_ID(2), with PCI = 3*N_ID(1) + N_ID(2).
#
# What that means for this verb: the PCI split below is correct FOR NSSS, and
# the earlier text attributed it to NPSS as well, which was wrong in the one
# way that matters -- an operator hunting cells by NPSS root would have been
# searching for something that does not vary. Neither sequence is synthesised
# here, because generating 128 OFDM samples needs a modulator this module does
# not have.
iot_npss_to_nss() {
    local pci="${1:-0}"
    [[ "$pci" =~ ^[0-9]+$ ]] && (( pci >= 0 && pci <= 503 )) || {
        printf 'ERROR\tPCI must be an integer in 0..503\n' >&2; return 2; }

    local n_id_1=$(( pci / 3 ))
    local n_id_2=$(( pci % 3 ))
    local theta=$(( (n_id_1 * n_id_2) % 128 ))
    cat << EOF
pci	$pci
n_id_1	$n_id_1
n_id_2	$n_id_2
npss	root 5, length 11, fixed -- independent of PCI
nsss_root	$n_id_1
nsss_shift	$n_id_2
nsss_theta	$theta
note	sequences are not synthesised here; this is the PCI decomposition a receiver needs before correlating
EOF
}

# ── NB-IoT RRC decoding (TS 36.331 §6.3, unaligned PER) ────────────────
#
# These read real NB-IoT messages with the generated PER codec: the standard
# library engine in tools/lte_per.py driving tools/lte_rrc_nb_layout.py, a
# table generated from the same schema pycrate is built from and differential
# tested against it (214 types, 2848 cases, 0 disagreements).
#
# What stood here before was not a decoder. It sliced the hex at fixed
# character offsets -- hex[0:4] called "MIB-NB", hex[6:2] called "SI Period"
# and multiplied by 1024, hex[12:6] called "Cell ID" -- and printed the six
# slices with exit 0. A SIB1-NB does not begin with a MIB-NB (that is a
# different message on a different channel), has no "TDD Config" field at all
# in the -NB variant, and its cell identity is 28 bits inside
# cellAccessRelatedInfo, not the twelfth hex digit. The output was stable,
# plausible, and invented; a reader had no way to tell from the text.
#
# The NB message set is why this needed its own layout table rather than a new
# branch in the LTE one: no LTE root reaches SIB1-NB, so the generated LTE
# table carried no NB type at all and there was nothing for a decoder to call.
#
# A length is not recoverable from hex, so the caller's buffer is handed over
# whole and the engine reports bits_consumed. --exact is available for the case
# where the caller knows the true length, and refuses rather than accepting a
# trailing field as pad.
iot_nb_codec() {
    local type_name="$1" hex="${2:-}" bits="${3:-}"
    local tool="$IMSISTING_ROOT/tools/lte_asn1.py"
    [[ -r "$tool" ]] || {
        printf 'ERROR\tmissing %s\n' "$tool" >&2
        printf 'WHY\tthe NB-IoT decoder is a real ASN.1 PER codec and lives in tools/\n' >&2
        return 1
    }
    hex="${hex//[[:space:]]/}"
    hex="${hex#0x}"; hex="${hex#0X}"
    hex="${hex^^}"
    [[ -n "$hex" ]] || { printf 'ERROR\tno hex given\n' >&2; return 2; }
    [[ "$hex" =~ ^[0-9A-F]+$ ]] || {
        printf 'ERROR\tnot valid hex: %s\n' "$(printf '%s' "$hex" | cut -c1-32)" >&2
        return 1
    }

    local args=(type-decode "$type_name" "$hex" --family nbiot)
    [[ -n "$bits" ]] && args+=(--bits "$bits" --exact)

    local out rc
    out=$(python3 "$tool" "${args[@]}" 2>&1)
    rc=$?
    if (( rc != 0 )); then
        # The engine's own message is the diagnosis, so it is passed through
        # rather than replaced with a summary: "the bits ran out" and "this is
        # not that type" lead to different next steps.
        printf '%s\n' "$out" | sed '/^$/d;s/^/ERROR\t/'
        printf 'NOTDECODED\t%s was not decoded from these bits; no fields were reported\n' "$type_name" >&2
        return 1
    fi
    printf '%s\n' "$out"
    return 0
}

iot_decode_sib1_nb() {
    local hex="${1:-}"
    [[ -n "$hex" ]] || { warn "usage: --decode-sib1 <hex>"; return 2; }
    local out
    out=$(iot_nb_codec SystemInformationBlockType1_NB "$hex") || return 1
    # A SIB1-NB carries the cell's identity and barring state, so a decode that
    # consumed implausibly few bits has read something else. 40 bits is the
    # floor of a legal message: the mandatory fields alone exceed it.
    local consumed
    consumed=$(printf '%s\n' "$out" | awk -F'\t' '$1=="bits_consumed"{print $2}')
    if [[ -n "$consumed" ]] && (( consumed < 40 )); then
        printf '%s\n' "$out" | sed '/^$/d;s/^/ERROR\t/'
        printf 'NOTDECODED\tonly %s bits were a SIB1-NB; this is not one\n' "$consumed" >&2
        return 1
    fi
    printf '%s\n' "$out"
    printf 'ref\t3GPP TS 36.331 6.3.1 SystemInformationBlockType1-NB (unaligned PER, generated codec)\n'
    return 0
}

iot_decode_mib_nb() {
    local hex="${1:-}"
    [[ -n "$hex" ]] || { warn "usage: --decode-mib <hex>"; return 2; }
    # MIB-NB is exactly 34 bits (TS 36.331 6.2.1) and arrives padded to ten
    # nibbles, so five octets of hex is the only spelling that carries it. A
    # longer buffer is refused rather than truncated: --bits would happily cut
    # it to 34 and consume every bit, which reads as a pass on input that was
    # never a MIB-NB. A shorter one has no room for the message.
    local h="${hex//[[:space:]]/}"; h="${h#0x}"; h="${h#0X}"
    if [[ ${#h} -ne 10 ]]; then
        printf 'ERROR\tMIB-NB is 34 bits, carried in 5 octets of hex (10 digits); got %d digits\n' "${#h}" >&2
        printf 'WHY\tthe message does not fill the buffer, so the buffer length is the only thing that tells a 34-bit MIB-NB from a longer message read short\n' >&2
        return 1
    fi
    local out
    out=$(iot_nb_codec MasterInformationBlock_NB "$hex" 34) || return 1
    printf '%s\n' "$out"
    printf 'ref\t3GPP TS 36.331 6.2.1 MasterInformationBlock-NB, 34 bits (unaligned PER, generated codec)\n'
    return 0
}


# ── Band mapping (TS 36.104 Table 5.7.3-1) ─────────────────────────────
# This used to answer 410.0 + 0.1*n for NPRFCN 0..999 and 500.0 + 0.1*(n-1000)
# for 1000..1999. Neither formula is in Table 5.7.3-1: NPRFCN is defined per
# operating band as F = F_low + 0.1*(NPRFCN - N_Offs-NB), so one global
# intercept cannot be right for more than one band, and the second branch has
# no counterpart in the table at all. A wrong frequency is the worst kind of
# wrong here, because it aims a receiver (or a transmitter behind a gate) at a
# band where nothing is being sent.
#
# Refusing is the honest answer until the per-band N_Offs-NB column is in the
# tree. `33_jamming_detect --earfcn` already carries the LTE EARFCN raster from
# the same clause, and that raster is what an NB-IoT carrier is placed on when
# it is deployed in-band.
iot_nprfcn_to_mhz() {
    local nprfcn="${1:-}"
    [[ "$nprfcn" =~ ^[0-9]+$ ]] || {
        printf 'ERROR\tNPRFCN must be a non-negative integer\n' >&2; return 2; }
    printf 'ERROR\tNPRFCN to MHz is not mapped here\n' >&2
    printf 'WHY\tthis module used to answer 410.0 + 0.1*n for 0..999 and 500.0 + 0.1*(n-1000) above that, neither of which is a band rule; aiming a receiver at the wrong band is silent failure. And the column that would settle it is not where this module claimed: TS 36.104 V16.6.0 Table 5.7.3-1 is E-UTRA channel numbers (F_DL_low, N_Offs-DL, F_UL_low, N_Offs-UL per band) with no NPRFCN column, and NPRFCN does not appear anywhere in TS 36.104 V16.6.0, TS 36.101 V16.6.0 or TS 36.211 V16.2.0.\n' >&2
    printf 'WHAT IS REAL\t33_jamming_detect --earfcn <n> carries the LTE EARFCN raster from the same clause, which is the carrier an in-band NB-IoT cell sits on.\n' >&2
    printf 'NEXT\tfind the clause that actually numbers the NB-IoT carrier (the 100 kHz raster is separate from the E-UTRA 100 kHz ARFCN step) and transcribe its per-band offsets, checking against a published deployment before this verb answers\n' >&2
    return 2
}

# ── Plan files (MODULE_CONVENTIONS §9) ─────────────────────────────────
# The decode half of this module runs anywhere. Standing up a cell that an
# NB-IoT device will actually attach to, and flooding its NPRACH, both need
# hardware this tree does not assume — so they ship as labelled plan files
# whose first lines are `status: handoff` and the exact hardware.
# ── I4: the narrowband attach, end to end ───────────────────────────────
# NB-IoT is not a different NAS. The attach that a UE performs on a
# narrowband carrier is the same Attach Request, the same identity response and
# the same security mode command as on LTE; what changes is the transport, the
# number of repetitions each message is given, and the fact that a device may
# be reachable only inside a paging window that lasts seconds. This verb lists
# the sequence so the difference is visible where it actually is, and states
# the one thing the sequence does not change: an identity request on NB-IoT is
# as loud as an identity request anywhere else.
iot_nb_attach() {
    local ce="${1:-0}"
    [[ "$ce" =~ ^[0-2]$ ]] || { printf 'ERROR\tcoverage enhancement level is 0, 1 or 2\n' >&2; return 2; }
    local mode="${2:-in-band}"
    case "$mode" in in-band|guard-band|standalone) ;; *)
        printf 'ERROR\tmode is in-band, guard-band or standalone\n' >&2; return 2 ;; esac

    printf 'step\tprocedure\tmessage\tdirection\tfields\tref\n'
    cat <<'EOF'
1	rrc	RRCConnectionRequest-NB	ul	establishmentCause, ue-Identity (S-TMSI or a random value)	TS 36.331 5.3.3.3
2	rrc	RRCConnectionSetup-NB	dl	radioResourceConfigDedicated-NB: SRB1, and SRB1bis when CP CIoT	TS 36.331 6.2.2
3	rrc	RRCConnectionSetupComplete-NB	ul	selectedPLMN-Identity, dedicatedInfoNAS carrying the Attach Request	TS 36.331 5.3.3
4	nas	Attach Request	ul	EPS attach type, EPS mobile identity, UE network capability (the CIoT bits live here), ESM container	TS 24.301 8.2.4
5	nas	Identity Request / Response	dl then ul	IMSI, asked exactly when there is no usable GUTI: the same NAS message as on any other RAT	TS 24.301 8.2.25
6	nas	Authentication Request, Security Mode Command	dl then ul	the vectors and KASME that the core derives; nothing narrowband-specific	TS 24.301 5.4.2
7	rrc	RRCConnectionReconfiguration-NB	dl	SRB1bis, and a user plane only when UP CIoT was granted	TS 36.331 5.3.5
8	nas	Attach Accept	dl	EPS bearer, APN, CIoT EPS optimisation IE (CP or UP), DRX and eDRX parameters	TS 24.301 8.2.1
9	rrc	RRCConnectionRelease	dl	releaseCause, extendedWaitTime (a cell can hold a device off with it), resumeIdentity when the context is kept	TS 36.331 6.2.2
10	rrc	RRCConnectionSuspend-NB	dl	suspendConfig, resumeIdentity: the radio goes away and the context stays in the core	TS 36.331 5.3.13
11	rrc	Early Data Transmission	ul	CP-EDT puts the Attach Request inside msg3; UP-EDT sends data on the resume	TS 36.300 22.4, TS 36.331 5.3.3.1a
12	ce	Coverage enhancement	both	the level multiplies repetitions of NPUSCH and NPDCCH by a count the cell configures, not by a constant	TS 36.321 5.1, TS 36.211 10.1.6
EOF
    printf 'ce_level\t%s\n' "$ce"
    printf 'mode\t%s\n' "$mode"
    case "$ce" in
        0) printf 'ce_meaning\tno repetition budget beyond the cell baseline; the level a device uses when the measured RSRP is good\n' ;;
        1) printf 'ce_meaning\tone step of repetition;\nthe count itself comes from nprach-ConfigSIB-NB and the pdsch/pusch config, so it is a cell decision\n' ;;
        2) printf 'ce_meaning\tthe deepest budget the cell offers; every message is repeated and the paging window is long enough to be measured in seconds\n' ;;
    esac
    printf 'ce_repetitions_source\tthe broadcast configuration of the cell, read with --nprach-decode; the standard fixes the mechanism and leaves the count to the operator\n'
    printf 'nas_unchanged\tyes: the narrowband flow is the same EMM attach on a different transport, so identity exposure is not reduced and not increased\n'
    printf 'reachability\ta device on this level may listen only inside its paging window, which is why a page can take seconds to land\n'
    printf 'ref\tTS 36.331 5.3.3, TS 24.301 8.2.4, TS 36.300 22.4, TS 36.304 7.1\n'
    printf 'limit\tthis is the message sequence, not the bytes: the NB-IoT RRC codec here decodes SIB1-NB, SIB2-NB and MIB-NB, and the RRCConnection* messages are read as ASN.1 names only when a capture supplies them\n'
    return 0
}

# ── I4: where coverage enhancement can be turned against the cell ───────
# The coverage enhancement level is the one number in this flow that a device
# reports and the cell obeys. Nothing in the air interface proves the report,
# so the abuse surface is arithmetic rather than cryptanalysis: one level of
# inflation multiplies the repetitions the cell schedules for that device, and
# the repetition count is what the sector spends.
iot_ce_abuse() {
    local ce=2 ues=1000 rep=128
    while (($#)); do
        case "$1" in
            --ce)  ce="${2:-}";  shift 2 ;;
            --ues) ues="${2:-}"; shift 2 ;;
            --rep) rep="${2:-}"; shift 2 ;;
            *) printf 'ERROR\tunknown option %s\n' "$1" >&2; return 2 ;;
        esac
    done
    [[ "$ce" =~ ^[0-2]$ ]] || { printf 'ERROR\t--ce is 0, 1 or 2\n' >&2; return 2; }
    [[ "$ues" =~ ^[0-9]+$ ]] && (( ues > 0 )) || { printf 'ERROR\t--ues must be a positive count\n' >&2; return 2; }
    [[ "$rep" =~ ^[0-9]+$ ]] && (( rep > 0 )) || { printf 'ERROR\t--rep must be a positive repetition count\n' >&2; return 2; }

    local occ=$(( ues * rep ))
    printf 'ce_level\t%s\n' "$ce"
    printf 'ues\t%s\n' "$ues"
    printf 'repetitions\t%s\n' "$rep"
    printf 'npdcch_subframes\t%s\n' "$occ"
    printf 'occupancy_s\t%s\n' "$(awk -v o="$occ" 'BEGIN{printf "%.3f", o/1000}')"
    printf 'attack\tneeds\teffect\tdetection\tref\n'
    cat <<'EOF'
E1 ce_level_inflation	only the report: the level a device asks for is not proved by anything on the air	a device that reports the deepest level while its measured RSRP is good makes the cell spend the deep-level repetition budget on it	per-device CE level compared against the RSRP in the same measurement report	TS 36.321 5.1, TS 36.331 nprach-ConfigSIB-NB
E2 nprach_congestion	many devices at one level	NPRACH preambles collide, every collision retries with power ramping, and the retries are the load	PRACH/NPRACH collision and retry counters	TS 36.321 5.1.1
E3 repetition_amplifier	the broadcast repetition count, which is a cell setting	the count is obeyed by every device in the sector, so one setting scales the whole cell's NPDCCH and NPUSCH occupancy	scheduled repetitions against the RSRP distribution of the served devices	TS 36.211 10.1.6, TS 36.300 22.4
E4 paging_cost	devices inside a long paging window	each page holds NPDCCH for the repetition budget, so a paging test costs repetitions per device rather than one subframe	P-RNTI scheduling and paging load counters	TS 36.304 7.1
E5 suspend_state	a suspended context in the core	the resume identity is what a device presents later, from wherever it is, and the context was created before it moved	resume failures, TAU after resume, resume identity reuse	TS 24.301 5.3.2A, TS 36.331 5.3.13
EOF
    printf 'finding\tce_inflation_is_unproved\tMEDIUM\tthe reported level is what the cell schedules against and nothing on the air proves it\n'
    printf 'finding\tbroadcast_amplifier\tMEDIUM\tthe repetition count is one cell setting that scales every served device\n'
    printf 'checkable\tyes: collision, retry and scheduling counters. The abuse is visible in load, not in a message\n'
    printf 'ref\tTS 36.321 5.1, TS 36.304 7.1, TS 36.211 10.1.6\n'
    printf 'verdict\tabuse_surface_listed\n'
    return 0
}


# ── R64: the two numbers this tree can and cannot settle ────────────────
# The NPRACH rule is a computation that can be checked against the clause, and
# tools/nbiot_nprach.py does check it: the Gold generator is imported from
# tools/lte_phy.py rather than rewritten, the format table is TS 36.211
# Table 10.1.6.1-1, and the tool carries its own selfcheck. This verb makes the
# checking visible instead of assumed, and it holds every group to the bounds
# the clause sets: one subcarrier per group, inside [n_sc_offset,
# n_sc_offset + n_sc_nprach), with the CP and sequence lengths the format says.
iot_nprach_verify() {
    local cell="${1:-0}" init="${2:-0}" groups="${3:-12}"
    [[ "$cell" =~ ^[0-9]+$ ]]   || { printf 'ERROR\tcell id is a non-negative integer\n' >&2; return 2; }
    [[ "$init" =~ ^[0-9]+$ ]]   || { printf 'ERROR\tn_init is a non-negative integer\n' >&2; return 2; }
    [[ "$groups" =~ ^[0-9]+$ ]] && (( groups > 0 )) || { printf 'ERROR\tgroup count must be positive\n' >&2; return 2; }
    [[ -f "$IOT_TOOL_NPRACH" ]] || {
        printf 'ERROR\ttools/nbiot_nprach.py is missing\n' >&2; return 1; }

    local out
    out=$(python3 "$IOT_TOOL_NPRACH" pattern --cell "$cell" --init "$init" --groups "$groups" 2>&1) || {
        printf '%s\n' "$out"; return 1; }
    local lo hi nsc
    lo=$(printf '%s\n' "$out"  | awk -F'\t' '$1=="n_sc_offset"{print $2; exit}')
    nsc=$(printf '%s\n' "$out" | awk -F'\t' '$1=="n_sc_nprach"{print $2; exit}')
    lo="${lo:-0}"; nsc="${nsc:-12}"
    hi=$(( lo + nsc - 1 ))

    local gs bad=0 total=0
    gs=$(printf '%s\n' "$out" | awk -F'\t' '$1=="groups"{print $2; exit}')
    printf 'cell\t%s\n' "$cell"
    printf 'n_init\t%s\n' "$init"
    printf 'n_sc_offset\t%s\n' "$lo"
    printf 'n_sc_nprach\t%s\n' "$nsc"
    printf 'groups\t%s\n' "${gs:-0}"
    printf 'group\tsubcarrier\tcp_samples\tseq_samples\tinside_window\n'
    printf '%s\n' "$out" | awk -F'\t' -v lo="$lo" -v hi="$hi" '
        $1=="group" {
            inside = ($4 >= lo && $4 <= hi) ? "yes" : "NO"
            printf "g%s\t%s\t%s\t%s\t%s\n", $2, $4, $7, $9, inside
        }' | while IFS=$'\t' read -r g sc cp sq ins; do
            printf '%s\t%s\t%s\t%s\t%s\n' "$g" "$sc" "$cp" "$sq" "$ins"
        done
    bad=$(printf '%s\n' "$out" | awk -F'\t' -v lo="$lo" -v hi="$hi" \
        '$1=="group" && ($4 < lo || $4 > hi)' | wc -l)
    total=$(( ${gs:-0} ))
    printf 'outside_window\t%s\n' "$bad"
    local chkout chkpass chkfail
    chkout=$(python3 "$IOT_TOOL_NPRACH" selfcheck 2>&1) || true
    chkpass=$(printf '%s\n' "$chkout" | awk -F'\t' '$1=="CHECKS"{print $2; exit}')
    chkfail=$(printf '%s\n' "$chkout" | awk -F'\t' '$1=="FAILED"{print $2; exit}')
    printf 'tool_selfcheck\t%s\n' "$(printf '%s\n' "$chkout" | awk -F'\t' '$1=="RESULT"{print $2; exit}')"
    printf 'tool_checks_passed\t%s\n' "${chkpass:-0}"
    printf 'tool_checks_failed\t%s\n' "${chkfail:-0}"
    printf 'ref\tTS 36.211 10.1.6.1 (one subcarrier per symbol group, N_sc^NPRACH window) and Table 10.1.6.1-1 (formats)\n'
    if (( bad > 0 )) || [[ "${chkfail:-0}" != "0" ]]; then
        printf 'verdict\tnprach_disagrees_with_the_clause\n'
        return 1
    fi
    printf 'verdict\tnprach_verified\n'
    return 0
}

# The other number cannot be settled here. NPRFcn to hertz is a per-band table
# (TS 36.104 5.7.3-1) that this tree does not carry, and guessing a band edge
# would produce a number that looks like an answer. What CAN be done without
# that table is the raster arithmetic itself: the NB-IoT carrier raster is
# 100 kHz, so given an anchor frequency that the operator supplies from their
# own plan, the n-th raster position is the anchor plus n steps of 100 kHz.
# The verb refuses until the anchor is given, and says whose number it is.
iot_freq_plan() {
    local nprfcn="${1:-}" flow="${2:-}"
    [[ -n "$nprfcn" ]] || { printf 'ERROR\tusage: --freq-plan <nprfcn> [anchor-mhz]\n' >&2; return 2; }
    [[ "$nprfcn" =~ ^[0-9]+$ ]] || {
        printf 'ERROR\tNPRFcn is a non-negative integer\n' >&2; return 2; }
    printf 'nprfcn\t%s\n' "$nprfcn"
    printf 'raster_khz\t100\n'
    if [[ -z "$flow" ]]; then
        printf 'needs\tTS 36.104 Table 5.7.3-1, the per-band NB-IoT carrier offset table, which this tree does not carry\n'
        printf 'would_be\tf = anchor + nprfcn * 0.1 MHz, where anchor is the band entry point from that table\n'
        printf 'why_refused\ta guessed band edge is a number that looks like an answer; supplying the anchor makes the arithmetic exact and the provenance explicit\n'
        printf 'workaround\tgive the anchor as the second argument, or use --to-mhz for the same refusal in one row\n'
        printf 'ref\tTS 36.104 5.7.3\n'
        printf 'verdict\tanchor_not_in_this_tree\n'
        return 1
    fi
    [[ "$flow" =~ ^[0-9]+(\.[0-9]+)?$ ]] || {
        printf 'ERROR\tthe anchor is a frequency in MHz\n' >&2; return 2; }
    local step freq
    step=$(awk -v n="$nprfcn" 'BEGIN{printf "%.4f", n/10}')
    freq=$(awk -v a="$flow" -v s="$step" 'BEGIN{printf "%.4f", a + s}')
    printf 'anchor_mhz\t%s\n' "$flow"
    printf 'step_mhz\t%s\n' "$step"
    printf 'freq_mhz\t%s\n' "$freq"
    printf 'provenance\tanchor supplied by the caller; the 100 kHz step and the direction are the raster definition, the band edge is not invented here\n'
    printf 'limit\tthis is arithmetic on the anchor, not a substitute for the per-band table: it cannot tell whether the result is inside the band\n'
    printf 'ref\tTS 36.104 5.7.3 (100 kHz NB-IoT carrier raster)\n'
    printf 'verdict\traster_position_computed\n'
    return 0
}


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
     absent, and the module model plus firmware narrows the CVE set in 21_lte_cve.
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
# ── NIDD — the configuration where the payload is not IP ───────────────
# NB-IoT and Cat-M1 exist to carry a few hundred octets from a meter. When the
# payload is non-IP, there is no IP header anywhere on the path, so the
# operator's IP-layer tools have nothing to look at and the data is delivered
# to an application server through an API instead of a bearer. That API is
# where the payload becomes visible, and it is where the access control lives.

iot_nidd_plane() {
    cat <<'PLANE'
leg	1	ue	mme	NAS ESM	the payload inside NAS, with PDN type non-IP	the ue and the mme: leg 1 is the only leg the air interface protects
leg	2	mme	scef	T6a, Diameter (TS 29.336)	the payload in a Diameter AVP	the core: in the clear between the two nodes unless the operator runs IPsec
leg	3	scef	scs	as	T8, HTTP (TS 29.122)	the payload as an API body	TLS is a deployment choice here, not a requirement of the reference point
leg	4	scs	as	application	whatever the application does with it	outside any 3GPP scope
PLANE
}

iot_cmd_nidd_plane() {
    printf 'spec\tTS 23.682 4.4.6\tNIDD: non-IP data delivered through the SCEF\n'
    printf 'spec\tTS 29.122\tT8, the API between the SCEF and the SCS/AS\n'
    printf 'spec\tTS 29.336\tS6t and T6a, the Diameter legs the MME and SCEF speak\n'
    printf 'spec\tTS 24.301\tPDN type non-IP, which is what makes the bearer carry no IP\n'
    printf 'spec\tTS 23.003\tthe external identifier, local-part and domain-part, which is how the API names a device\n'
    iot_nidd_plane
    printf 'legs\t4\n'
    printf 'protected_by_the_air_interface\t1\n'
    printf 'finding\tpayload_leaves_the_nas_encryption\tHIGH\tthe air-interface cipher covers leg 1 and stops at the MME; from the SCEF onward the payload is an API body\n'
    printf 'finding\tt8_credentials_are_the_access_control\tHIGH\tevery device in a subscription group is reachable by whoever holds the SCS/AS credentials, and nothing ties a call to the application that made it\n'
    printf 'finding\texternal_identifier_is_the_join\tHIGH\tthe API names devices by external identifier and the SCEF holds the mapping to the IMSI, so the identifier is the join between the application world and the subscriber\n'
    printf 'finding\tnon_ip_data_is_invisible_to_ip_tools\tMEDIUM\tthere is no IP header on any leg, so an IP-layer monitor beside the core sees nothing and an API log is the only record\n'
    printf 'where_a_payload_can_be_read\tT6a in the core, T8 at the SCEF, and the SCS itself\n'
    printf 'ref\tTS 23.682 4.4.6 and 5.13, TS 29.122, TS 29.336, TS 24.301 6.5\n'
    printf 'limit\tThis states the path the payload takes. Whether any leg is protected beyond what the reference point requires is an operator decision this module cannot observe.\n'
    printf 'verdict\tnidd_plane_described\n'
}

iot_hex_to_base64() {
    local hex="$1"
    if command -v xxd >/dev/null 2>&1; then
        printf '%s' "$hex" | xxd -r -p | base64 -w0
    elif command -v base64 >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
        python3 -c 'import sys,binascii,base64;sys.stdout.write(base64.b64encode(binascii.unhexlify(sys.argv[1])).decode())' "$hex"
    else
        return 1
    fi
}

iot_cmd_nidd_build() {
    local payload="" direction="mt" scs="scs-1" sub="sub-0001" ext="meter-0001@example.com"
    while (($# > 0)); do
        case "$1" in
            --direction)     direction="${2:-}"; shift 2 ;;
            --scs-as-id)     scs="${2:-}"; shift 2 ;;
            --subscription)  sub="${2:-}"; shift 2 ;;
            --external-id)   ext="${2:-}"; shift 2 ;;
            --)              shift; payload="${1:-}"; shift ;;
            *)               payload="$1"; shift ;;
        esac
    done
    [[ -z "$payload" ]] && { printf 'ERROR\tno payload: give the octets as hex\n' >&2; printf 'WHY\tthe T8 body carries the payload, so there is nothing to send without one\n' >&2; return 2; }
    [[ "$payload" =~ ^[0-9A-Fa-f]+$ ]] || { printf 'ERROR\tpayload is not hex\n' >&2; return 2; }
    (( ${#payload} % 2 == 0 )) || { printf 'ERROR\tpayload has an odd number of nibbles\n' >&2; return 2; }
    case "$direction" in
        mt|mo) ;;
        *) printf 'ERROR\t--direction is mt or mo\n' >&2; return 2 ;;
    esac
    local b64 octets path method
    b64="$(iot_hex_to_base64 "$payload")" || { printf 'ERROR\tno way to encode base64 (xxd or python3)\n' >&2; return 1; }
    octets=$(( ${#payload} / 2 ))
    if [[ "$direction" == "mt" ]]; then
        method="POST"
        path="/nidd/v1/${scs}/subscriptions/${sub}/transactions"
        method_note="the SCS asks the SCEF to deliver this payload to one device"
    else
        method="POST"
        path="/nidd/v1/${scs}/subscriptions/${sub}/notification"
        method_note="the SCEF pushes an uplink payload to the SCS; the roles are reversed and the resource is a notification"
    fi
    local body
    body="$(printf '{"mtcProviderId":"%s","externalId":"%s","niddDownlinkData":"%s"}' "$scs" "$ext" "$b64")"
    if [[ "$direction" == "mo" ]]; then
        body="$(printf '{"mtcProviderId":"%s","externalId":"%s","niddUplinkData":"%s"}' "$scs" "$ext" "$b64")"
    fi
    printf 'api\tTS 29.122\tNIDD\n'
    printf 'direction\t%s\n' "$direction"
    printf 'method\t%s\n' "$method"
    printf 'path\t%s\n' "$path"
    printf 'content_type\tapplication/json\n'
    printf 'body\t%s\n' "$body"
    printf 'body_octets\t%s\n' "$(printf '%s' "$body" | wc -c | tr -d ' ')"
    printf 'payload_octets\t%s\n' "$octets"
    printf 'payload_hex\t%s\n' "$(printf '%s' "$payload" | tr 'a-f' 'A-F')"
    printf 'payload_base64\t%s\n' "$b64"
    printf 'external_id\t%s\n' "$ext"
    printf 'subscription\t%s\n' "$sub"
    printf 'scs_as_id\t%s\n' "$scs"
    printf 'what_the_call_says\t%s\n' "$method_note"
    printf 'what_the_receiver_must_decide\tthe external identifier resolves to an IMSI at the SCEF, so the SCEF is the only node that can say which subscriber this payload reached\n'
    printf 'access_control\tthe credentials provisioned for this SCS/AS; the body carries no second factor\n'
    printf 'ref\tTS 29.122 (NIDD API), TS 23.682 4.4.6\n'
    printf 'limit\tThe resource names follow the NIDD API model; a deployment is authoritative through its own OpenAPI document, and the field set there is the one a real SCEF accepts.\n'
    printf 'verdict\tnidd_transaction_built\n'
}

iot_cmd_nidd_audit() {
    local file="$1"
    [[ -z "$file" ]] && { printf 'ERROR\tusage: --nidd-audit <calls.tsv>\n' >&2; return 2; }
    [[ -f "$file" ]] || { printf 'ERROR\tno such file: %s\n' "$file" >&2; return 1; }
    awk -F'\t' '
        NR == 1 { next }
        NF < 4 { next }
        {
            app = $1; sbn = $2; ext = $3; dir = $4; bytes = $5 + 0
            calls++
            seen_app[app] = 1
            seen_sub[sbn] = 1
            seen_dev[ext] = 1
            if (dir == "mo") { up += bytes; upc++ }
            else if (dir == "mt") { down += bytes; downc++ }
            perapp[app]++
            appunits[app SUBSEP ext] = 1
            if (dir == "mo") saw_mo[ext] = 1
            if (dir == "mt") saw_mt[ext] = 1
        }
        END {
            na = 0; for (a in seen_app) na++
            ns = 0; for (s in seen_sub) ns++
            nd = 0; for (d in seen_dev) nd++
            for (k in appunits) { split(k, p, SUBSEP); appdev[p[1]]++ }
            maxapp = ""; maxn = 0
            for (a in appdev) if (appdev[a] > maxn) { maxn = appdev[a]; maxapp = a }
            both = 0
            for (d in seen_dev) if (saw_mo[d] && saw_mt[d]) both++
            downonly = 0; downonlydev = ""
            for (d in seen_dev) if (saw_mt[d] && !saw_mo[d]) { downonly++; if (downonlydev == "") downonlydev = d }
            printf "calls\t%d\n", calls
            printf "applications\t%d\n", na
            printf "subscriptions\t%d\n", ns
            printf "devices\t%d\n", nd
            printf "uplink_calls\t%d\n", upc
            printf "downlink_calls\t%d\n", downc
            printf "uplink_octets\t%d\n", up
            printf "downlink_octets\t%d\n", down
            printf "devices_with_both_directions\t%d\n", both
            printf "devices_with_downlink_only\t%d\n", downonly
            printf "devices_per_application_max\t%d\n", maxn
            if (maxn > 0) printf "busiest_application\t%s\n", maxapp
            for (a in perapp) printf "application\t%s\t%d\n", a, perapp[a]
            if (maxn >= 3) printf "finding\tone_application_reads_many_devices\tHIGH\t%s addressed %d devices through one credential set, so one leaked credential is that many meters\n", maxapp, maxn
            if (downonly > 0) printf "finding\tdownlink_only_device\tMEDIUM\t%s never sent uplink data, so every call about it was somebody pushing to it\n", downonlydev
            if (both > 0) printf "note\tbidirectional_devices\t%d devices saw traffic in both directions, which is what a working application looks like\n", both
            printf "ref\tTS 29.122 (NIDD API), TS 23.682 4.4.6, TS 23.003 (external identifier)\n"
            printf "limit\tThe log is what the SCEF API recorded. A payload read at T6a inside the core leaves no row here at all.\n"
            printf "verdict\t%s\n", (calls > 0 ? "nidd_log_accounted" : "no_calls_in_this_file")
        }' "$file"
}

iot_selftest() {
    local bad=0 nchk=0
    chk() {
        nchk=$(( nchk + 1 ))
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$(( bad + 1 )); fi
    }

    # 1. NPRACH refuses rather than printing constants no message produced.
    # The hopping rule is deterministic for the first four symbol groups, so
    # these are hand-computed from TS 36.211 10.1.6.1 rather than read back
    # from this module: n_init = 5 is n-tilde(0) = 5, 5 is odd so group 1 is
    # 4, 4 < 6 so group 2 is 10, 10 is even so group 3 is 11.
    chk nprach-prefix "$(iot_nprach_params 0 5 0 12 0 4 2>/dev/null | awk -F'\t' '$1=="group"{printf "%s,", $4}')" "5,4,10,11,"
    chk nprach-cp "$(iot_nprach_params 0 5 0 12 0 4 2>/dev/null | awk -F'\t' '$1=="cp_samples"{print $2}')" "2048"
    chk nprach-seq "$(iot_nprach_params 0 5 0 12 0 4 2>/dev/null | awk -F'\t' '$1=="seq_samples"{print $2}')" "40960"
    chk nprach-group-us "$(iot_nprach_params 0 5 0 12 0 4 2>/dev/null | awk -F'\t' '$1=="group_us"{print $2}')" "1400.00"
    chk nprach-fmt2-cp "$(iot_nprach_params 0 5 0 36 2 6 2>/dev/null | awk -F'\t' '$1=="cp_samples"{print $2}')" "24576"
    chk nprach-no-84 "$(iot_nprach_params 0 5 0 12 0 4 2>/dev/null | grep -c '84 resource')" "0"
    chk nprach-bad-format "$(iot_nprach_params 0 5 0 12 7 0 >/dev/null 2>&1; echo $?)" "2"
    chk nprach-bad-init "$(iot_nprach_params 0 99 >/dev/null 2>&1; echo $?)" "2"
    chk nprach-decode-no-args "$(iot_decode_sib2_nb >/dev/null 2>&1; echo $?)" "2"

    # 2. NPSS/NSSS: the PCI decomposition is real, and NPSS is stated as the
    #    fixed sequence it is. Known answers: PCI 1 -> (0,1); PCI 503 ->
    #    (167,2); PCI 0 -> (0,0).
    local zc_root; zc_root=$(iot_npss_to_nss 1)
    chk npss-nid1 "$(printf '%s\n' "$zc_root" | awk -F'\t' '$1=="n_id_1"{print $2}')" "0"
    chk npss-nid2 "$(printf '%s\n' "$zc_root" | awk -F'\t' '$1=="n_id_2"{print $2}')" "1"
    chk npss-pci503-1 "$(printf '%s\n' "$(iot_npss_to_nss 503)" | awk -F'\t' '$1=="n_id_1"{print $2}')" "167"
    chk npss-pci503-2 "$(printf '%s\n' "$(iot_npss_to_nss 503)" | awk -F'\t' '$1=="n_id_2"{print $2}')" "2"
    chk npss-pci-max "$(iot_npss_to_nss 504 >/dev/null 2>&1; echo $?)" "2"
    chk npss-fixed-root "$(printf '%s\n' "$zc_root" | grep -c 'root 5, length 11, fixed')" "1"
    chk npss-no-cell-dep "$(printf '%s\n' "$zc_root" | grep '^npss' | grep -c 'independent of PCI')" "1"

    # 3. NB-IoT RRC decoding — the generated PER codec on fixed bit strings.
    #
    # These are known-answer assertions, not smoke tests: the all-zero SIB1-NB
    # below is 160 bits and the codec says 117 of them are a message, with
    # specific values in specific fields. Pinning those values is what makes
    # this a test of the decoder rather than of the decoder's exit code. The
    # codec's agreement with pycrate is established separately, by
    # tools/lte-per-oracle/verify_per.py over every type in the table.
    local mib
    mib=$(iot_decode_mib_nb "0000000000" 2>/dev/null)
    chk mib-bits   "$(printf '%s\n' "$mib" | awk -F'\t' '$1=="bits_consumed"{print $2}')" "34"
    chk mib-sfn    "$(printf '%s\n' "$mib" | awk -F'\t' '$1=="systemFrameNumber-MSB-r13"{print $2}')" "0b0000 (4 bits)"
    chk mib-mode   "$(printf '%s\n' "$mib" | awk -F'\t' '$1=="operationModeInfo-r13"{print $2}')" \
                   "inband-SamePCI-r13({'eutra-CRS-SequenceInfo-r13': 0})"
    chk mib-ref    "$(printf '%s\n' "$mib" | awk -F'\t' '$1=="ref"' | wc -l)" "1"

    local sib1
    sib1=$(iot_decode_sib1_nb "0000000000000000000000000000000000000000" 2>/dev/null)
    chk sib1-bits   "$(printf '%s\n' "$sib1" | awk -F'\t' '$1=="bits_consumed"{print $2}')" "117"
    chk sib1-barred "$(printf '%s\n' "$sib1" | awk -F'\t' '$1=="cellAccessRelatedInfo-r13.cellBarred-r13"{print $2}')" "barred"
    chk sib1-tac    "$(printf '%s\n' "$sib1" | awk -F'\t' '$1=="cellAccessRelatedInfo-r13.trackingAreaCode-r13"{print $2}')" "0x0000 (16 bits)"
    chk sib1-band   "$(printf '%s\n' "$sib1" | awk -F'\t' '$1=="freqBandIndicator-r13"{print $2}')" "1"
    # pad_bits is the codec saying how much of the buffer was not message. It
    # is printed rather than silently dropped, because a caller comparing two
    # decodes needs to know the two inputs were the same length.
    chk sib1-pad    "$(printf '%s\n' "$sib1" | awk -F'\t' '$1=="pad_bits"{print $2}')" "43"
    # The fields the old slice-and-label decoder invented. cellIdentity is 28
    # bits inside cellAccessRelatedInfo; a decoder that reports it as six hex
    # digits at a fixed offset is not reading the message.
    chk sib1-cellid "$(printf '%s\n' "$sib1" | awk -F'\t' '$1=="cellAccessRelatedInfo-r13.cellIdentity-r13"{print $2}')" \
                    "0b0000000000000000000000000000 (28 bits)"
    chk sib1-no-tdd "$(printf '%s\n' "$sib1" | grep -c 'TDD Config')" "0"

    # 4. NPRFCN to MHz refuses (TS 36.104 Table 5.7.3-1 is per-band)
    # NPRFCN refuses: Table 5.7.3-1 is per-band and this tree carries no
    # N_Offs-NB column, so any single intercept would be right for one band.
    chk nprfcn-refuses "$(iot_nprfcn_to_mhz 0 >/dev/null 2>&1; echo $?)" "2"
    chk nprfcn-no-410 "$(iot_nprfcn_to_mhz 0 2>/dev/null | grep -c '410')" "0"

    # 5. Unknown values must fail, not guess
    chk nprfcn-neg "$(iot_nprfcn_to_mhz -1 >/dev/null 2>&1; echo $?)" "2"
    chk nprfcn-str "$(iot_nprfcn_to_mhz abc >/dev/null 2>&1; echo $?)" "2"
    chk sib1-short "$(iot_decode_sib1_nb "000000" >/dev/null 2>&1; echo $?)" "1"
    # The refusal cases are the point of this section. A decoder that answers
    # anyway on input it cannot read is the fault this build removed.
    chk sib1-nothex     "$(iot_decode_sib1_nb "zzzzzzzz" >/dev/null 2>&1; echo $?)" "1"
    chk sib1-no-args    "$(iot_decode_sib1_nb >/dev/null 2>&1; echo $?)" "2"
    chk mib-wrong-len   "$(iot_decode_mib_nb "000000000000" >/dev/null 2>&1; echo $?)" "1"
    chk mib-nothex      "$(iot_decode_mib_nb "zzzzzzzzzz" >/dev/null 2>&1; echo $?)" "1"
    chk mib-no-args     "$(iot_decode_mib_nb >/dev/null 2>&1; echo $?)" "2"

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

    # I4: the narrowband attach is twelve steps and the same NAS; the abuse
    # surface is arithmetic on the repetition budget.
    local naout
    naout=$(iot_nb_attach 2)
    chk nb-attach-steps "$(printf '%s\n' "$naout" | awk -F'\t' '$1 ~ /^[0-9]+$/' | wc -l)" "12"
    chk nb-attach-ce "$(printf '%s\n' "$naout" | awk -F'\t' '$1=="ce_level"{print $2}')" "2"
    chk nb-attach-nas "$(printf '%s\n' "$naout" | awk -F'\t' '$1=="nas_unchanged" && $2 ~ /^yes/{print "same"}')" "same"
    chk nb-attach-identity "$(printf '%s\n' "$naout" | awk -F'\t' '$3 ~ /Identity Request/{print "asked"}')" "asked"
    chk nb-attach-edt "$(printf '%s\n' "$naout" | awk -F'\t' '$3 ~ /Early Data Transmission/{print "present"}')" "present"
    chk nb-attach-bad-ce "$(iot_nb_attach 3 >/dev/null 2>&1; echo $?)" "2"
    chk nb-attach-bad-mode "$(iot_nb_attach 0 underwater >/dev/null 2>&1; echo $?)" "2"
    local ceout
    ceout=$(iot_ce_abuse --ues 1000 --rep 128)
    chk ce-subframes "$(printf '%s\n' "$ceout" | awk -F'\t' '$1=="npdcch_subframes"{print $2}')" "128000"
    chk ce-occupancy "$(printf '%s\n' "$ceout" | awk -F'\t' '$1=="occupancy_s"{print $2}')" "128.000"
    chk ce-rows "$(printf '%s\n' "$ceout" | awk -F'\t' '$1 ~ /^E[0-9]/' | wc -l)" "5"
    chk ce-inflation-row "$(printf '%s\n' "$ceout" | awk -F'\t' '$1=="finding" && $2=="ce_inflation_is_unproved"{print $3}')" "MEDIUM"
    chk ce-verdict "$(printf '%s\n' "$ceout" | awk -F'\t' '$1=="verdict"{print $2}')" "abuse_surface_listed"
    chk ce-bad-ues "$(iot_ce_abuse --ues 0 >/dev/null 2>&1; echo $?)" "2"
    chk ce-bad-rep "$(iot_ce_abuse --rep x >/dev/null 2>&1; echo $?)" "2"
    # R64: the NPRACH rule is checkable, the NPRFcn anchor is not in the tree.
    local nvout
    nvout=$(iot_nprach_verify 0 0 6)
    chk npr-verdict "$(printf '%s\n' "$nvout" | awk -F'\t' '$1=="verdict"{print $2}')" "nprach_verified"
    chk npr-outside "$(printf '%s\n' "$nvout" | awk -F'\t' '$1=="outside_window"{print $2}')" "0"
    chk npr-selfcheck "$(printf '%s\n' "$nvout" | awk -F'\t' '$1=="tool_selfcheck"{print $2}')" "PASS"
    chk npr-checks "$(printf '%s\n' "$nvout" | awk -F'\t' '$1=="tool_checks_failed"{print $2}')" "0"
    chk npr-group-rows "$(printf '%s\n' "$nvout" | awk -F'\t' '$1 ~ /^g[0-9]/' | wc -l)" "6"
    chk npr-all-inside "$(printf '%s\n' "$nvout" | awk -F'\t' '$1 ~ /^g[0-9]/ && $5=="yes"' | wc -l)" "6"
    chk npr-bad-groups "$(iot_nprach_verify 0 0 0 >/dev/null 2>&1; echo $?)" "2"
    chk fp-refused "$(iot_freq_plan 42 >/dev/null 2>&1; echo $?)" "1"
    chk fp-needs "$(iot_freq_plan 42 | awk -F'\t' '$1=="needs" && $2 ~ /5.7.3-1/{print "named"}')" "named"
    chk fp-computed "$(iot_freq_plan 42 1805.0 | awk -F'\t' '$1=="freq_mhz"{print $2}')" "1809.2000"
    chk fp-step "$(iot_freq_plan 42 1805.0 | awk -F'\t' '$1=="step_mhz"{print $2}')" "4.2000"
    chk fp-bad-anchor "$(iot_freq_plan 42 abc >/dev/null 2>&1; echo $?)" "2"
    chk fp-no-arg "$(iot_freq_plan >/dev/null 2>&1; echo $?)" "2"

    # NIDD: the non-IP path, the API call that carries the octets, and a log of
    # API calls accounted for. The base64 is checked against a hand value
    # because that is the one encoding in the path a reader can verify alone.
    local pla plm plo plf
    pla=$(iot_cmd_nidd_plane 2>/dev/null)
    chk nidd-legs "$(printf '%s\n' "$pla" | awk -F'\t' '$1=="legs"{print $2}')" 4
    chk nidd-protected "$(printf '%s\n' "$pla" | awk -F'\t' '$1=="protected_by_the_air_interface"{print $2}')" 1
    chk nidd-leg3 "$(printf '%s\n' "$pla" | awk -F'\t' '$1=="leg" && $2=="3"{print $6}' | grep -c 'T8')" 1
    chk nidd-encryption "$(printf '%s\n' "$pla" | awk -F'\t' '$1=="finding" && $2=="payload_leaves_the_nas_encryption"{print $3}')" HIGH
    chk nidd-join "$(printf '%s\n' "$pla" | awk -F'\t' '$1=="finding" && $2=="external_identifier_is_the_join"{print $3}')" HIGH
    chk nidd-verdict "$(printf '%s\n' "$pla" | awk -F'\t' '$1=="verdict"{print $2}')" nidd_plane_described
    plm=$(iot_cmd_nidd_build 0102030405 2>/dev/null)
    chk nidd-build-b64 "$(printf '%s\n' "$plm" | awk -F'\t' '$1=="payload_base64"{print $2}')" AQIDBAU=
    chk nidd-build-octets "$(printf '%s\n' "$plm" | awk -F'\t' '$1=="payload_octets"{print $2}')" 5
    chk nidd-build-mt-path "$(printf '%s\n' "$plm" | awk -F'\t' '$1=="path"{print $2}')" /nidd/v1/scs-1/subscriptions/sub-0001/transactions
    chk nidd-build-mt-field "$(printf '%s\n' "$plm" | awk -F'\t' '$1=="body" && $2 ~ /niddDownlinkData/{print "downlink"}')" downlink
    chk nidd-build-verdict "$(printf '%s\n' "$plm" | awk -F'\t' '$1=="verdict"{print $2}')" nidd_transaction_built
    plo=$(iot_cmd_nidd_build 0a0b --direction mo 2>/dev/null)
    chk nidd-build-mo-path "$(printf '%s\n' "$plo" | awk -F'\t' '$1=="path"{print $2}')" /nidd/v1/scs-1/subscriptions/sub-0001/notification
    chk nidd-build-mo-field "$(printf '%s\n' "$plo" | awk -F'\t' '$1=="body" && $2 ~ /niddUplinkData/{print "uplink"}')" uplink
    chk nidd-build-noarg "$(iot_cmd_nidd_build >/dev/null 2>&1; echo $?)" 2
    chk nidd-build-badhex "$(iot_cmd_nidd_build zz >/dev/null 2>&1; echo $?)" 2
    chk nidd-build-odd "$(iot_cmd_nidd_build abc >/dev/null 2>&1; echo $?)" 2
    chk nidd-build-baddir "$(iot_cmd_nidd_build 0102 --direction sideways >/dev/null 2>&1; echo $?)" 2
    local nf
    nf="$(mktemp)"
    printf 'scs_as_id\tsubscription\texternal_id\tdirection\tbytes\tt\n' > "$nf"
    printf 'app-power\tsub-1\tmeter-1@example.com\tmo\t42\t2026-02-01T10:00:00Z\n' >> "$nf"
    printf 'app-power\tsub-1\tmeter-2@example.com\tmo\t40\t2026-02-01T10:01:00Z\n' >> "$nf"
    printf 'app-power\tsub-1\tmeter-3@example.com\tmt\t12\t2026-02-01T10:02:00Z\n' >> "$nf"
    printf 'app-power\tsub-1\tmeter-3@example.com\tmo\t41\t2026-02-01T10:03:00Z\n' >> "$nf"
    printf 'app-water\tsub-2\tvalve-9@example.com\tmt\t8\t2026-02-01T10:04:00Z\n' >> "$nf"
    plf=$(iot_cmd_nidd_audit "$nf" 2>/dev/null)
    chk nidd-audit-calls "$(printf '%s\n' "$plf" | awk -F'\t' '$1=="calls"{print $2}')" 5
    chk nidd-audit-apps "$(printf '%s\n' "$plf" | awk -F'\t' '$1=="applications"{print $2}')" 2
    chk nidd-audit-devices "$(printf '%s\n' "$plf" | awk -F'\t' '$1=="devices"{print $2}')" 4
    chk nidd-audit-up "$(printf '%s\n' "$plf" | awk -F'\t' '$1=="uplink_octets"{print $2}')" 123
    chk nidd-audit-down "$(printf '%s\n' "$plf" | awk -F'\t' '$1=="downlink_octets"{print $2}')" 20
    chk nidd-audit-both "$(printf '%s\n' "$plf" | awk -F'\t' '$1=="devices_with_both_directions"{print $2}')" 1
    chk nidd-audit-max "$(printf '%s\n' "$plf" | awk -F'\t' '$1=="devices_per_application_max"{print $2}')" 3
    chk nidd-audit-harvest "$(printf '%s\n' "$plf" | awk -F'\t' '$1=="finding" && $2=="one_application_reads_many_devices"{print $3}')" HIGH
    chk nidd-audit-downonly "$(printf '%s\n' "$plf" | awk -F'\t' '$1=="finding" && $2=="downlink_only_device"{print $3}')" MEDIUM
    chk nidd-audit-verdict "$(printf '%s\n' "$plf" | awk -F'\t' '$1=="verdict"{print $2}')" nidd_log_accounted
    chk nidd-audit-noarg "$(iot_cmd_nidd_audit >/dev/null 2>&1; echo $?)" 2
    chk nidd-audit-nofile "$(iot_cmd_nidd_audit /tmp/definitely-not-here-nidd.tsv >/dev/null 2>&1; echo $?)" 1
    rm -f "$nf"

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
  [1]  NPRACH parameters (refused)
  [2]  NPSS/NSSS PCI decomposition
  [3]  Decode SIB1-NB
  [4]  Decode MIB-NB
  [5]  NPRFCN to MHz (refused)
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
                read -rp "  hex (5 octets)> " h
                iot_decode_mib_nb "$h"; read -rp "  press enter " _ ;;
            5)
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
        --nprach)       iot_nprach_params "${1:-0}" "${2:-0}" "${3:-0}" "${4:-12}" "${5:-0}" "${6:-0}" ;;
        --nprach-decode) iot_decode_sib2_nb "${1:-}" ;;
        --npss-nss)     iot_npss_to_nss "${1:-0}" ;;
        --decode-sib1)  iot_decode_sib1_nb "${1:-}" ;;
        --decode-mib)   iot_decode_mib_nb "${1:-}" ;;
        --to-mhz)       iot_nprfcn_to_mhz "${1:-}" ;;
        --nprach-verify) iot_nprach_verify "${1:-0}" "${2:-0}" "${3:-12}" ;;
        --freq-plan)    iot_freq_plan "${1:-}" "${2:-}" ;;
        --nb-attach)    iot_nb_attach "${1:-0}" "${2:-in-band}" ;;
        --ce-abuse)     iot_ce_abuse "$@" ;;
        --plan)         iot_plan "${1:-}" ;;
        --nidd)         iot_cmd_nidd_plane ;;
        --nidd-build)   iot_cmd_nidd_build "$@" ;;
        --nidd-audit)   iot_cmd_nidd_audit "${1:-}" ;;
        --selftest)     iot_selftest ;;
        --menu)         iot_menu ;;
        *) cat >&2 <<EOF
NB-IoT / Cat-M1 — narrowband IoT air interface

Usage: $0 COMMAND
  --status-tsv       tool and store state as TSV
  --nprach [<cell>] [<n_init>] [<offset>] [<subcarriers>] [<format>] [<groups>]
                     NPRACH symbol-group hopping (3GPP TS 36.211 10.1.6.1)
  --nprach-decode <hex>   read nprach-ConfigSIB-NB out of a SIB2-NB
  --npss-nss <pci>   PCI -> N_ID(1)/N_ID(2); NPSS is fixed, NSSS is the PCI-bearing one
  --decode-sib1 <hex>  decode a SystemInformationBlockType1-NB
  --decode-mib <hex>   decode a MasterInformationBlock-NB (5 octets, 34 bits)
  --to-mhz <nprfcn>  refuses: TS 36.104 Table 5.7.3-1 is per-band and absent here
  --nprach-verify [cell] [n_init] [groups]
                     hold the NPRACH hopping to the clause bounds, with the tool selfcheck
  --freq-plan <nprfcn> [anchor-mhz]
                     the 100 kHz raster arithmetic, refused until an anchor is supplied
  --nb-attach [ce 0|1|2] [in-band|guard-band|standalone]
                     the narrowband attach message by message
  --ce-abuse [--ce N] [--ues N] [--rep N]
                     where coverage enhancement can be turned against a cell
  --nidd             the non-IP data path: UE to MME, MME to SCEF over T6a,
                     SCEF to application over the T8 API, and which leg the
                     air interface actually protects
  --nidd-build <hex> [--direction mt|mo] [--scs-as-id ID] [--subscription ID]
                     [--external-id id]
                     build the T8 API call that carries these octets, since a
                     non-IP payload leaves the core as an HTTP body
  --nidd-audit <tsv> account for a log of SCEF or NEF API calls: which
                     application read which devices, in which direction
  --plan <fake-cell|nprach-flood>
                     write a handoff plan (status: handoff) for a vector that
                     needs transmit hardware; no transmission is performed
  --selftest         verify the codec known answers and the refusals
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
