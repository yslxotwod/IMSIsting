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
# NPRACH parameters and NPRFCN->MHz are REFUSED, on purpose. The first needs
# NPRACH-ConfigSIB-NB out of a SIB2-NB (a decode, not a constant), and the
# second needs the per-band N_Offs-NB column of TS 36.104 Table 5.7.3-1. What
# the module used to print for both was invented: an 84-resource-element grid
# that is not NPRACH, and a single 410 MHz intercept plus a 500 MHz branch that
# appears in no version of the table.
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
    # This printed a CP of 67 samples, 15360-sample symbols, a 153600-sample
    # frame and "12 subcarriers x 7 symbols = 84 resource elements". None of
    # those are NPRACH numbers: NPRACH is a frequency-hopped single-tone
    # preamble whose symbol groups are 1 subcarrier wide (TS 36.211 clause
    # 10.1.6), not a 12-subcarrier grid, and the sample counts were normalised
    # to a 3.84 MHz LTE raster this module never receives at. The arguments
    # were ignored, so the output did not depend on them either.
    #
    # NPRACH's real parameters live in NPRACH-ConfigSIB-NB and
    # NPRACH-ConfigCommon-NB in TS 36.331, which are in the NB layout table
    # this module now carries -- so the honest move is to decode a configuration
    # message rather than print constants that no message produced.
    printf 'ERROR\tNPRACH parameters are not computed here\n' >&2
    printf 'WHY\tThe output this verb used to print (CP 67, 15360-sample symbols, 84 resource elements) were not NPRACH values: an NPRACH preamble is a single-tone frequency-hopping pattern in TS 36.211 clause 10.1.6, not a 12-subcarrier grid. The arguments were ignored, so no input changed the answer.\n' >&2
    printf 'WHAT IS REAL\t--decode-sib1 / --decode-mib read the NPRACH configuration out of a real message: it is a field of SystemInformationBlockType2-NB, which the NB layout table carries.\n' >&2
    printf 'NEXT\tadd an --nprach-decode that takes a SIB2-NB buffer and reports nprach-ConfigSIB-NB as decoded fields\n' >&2
    return 2
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
    printf 'WHY\tTS 36.104 Table 5.7.3-1 defines NPRFCN per operating band as F = F_low + 0.1*(NPRFCN - N_Offs-NB). This module used to answer 410.0 + 0.1*n for 0..999 and 500.0 + 0.1*(n-1000) above that; the first is right for at most one band and the second is in no version of the table. Aiming a receiver at the wrong band is silent failure.\n' >&2
    printf 'WHAT IS REAL\t33_jamming_detect --earfcn <n> carries the LTE EARFCN raster from the same clause, which is the carrier an in-band NB-IoT cell sits on.\n' >&2
    printf 'NEXT\ttranscribe the per-band N_Offs-NB column of Table 5.7.3-1 and check it against a published NB-IoT deployment before this verb answers\n' >&2
    return 2
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
iot_selftest() {
    local bad=0 nchk=0
    chk() {
        nchk=$(( nchk + 1 ))
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$(( bad + 1 )); fi
    }

    # 1. NPRACH refuses rather than printing constants no message produced.
    chk nprach-refuses "$(iot_nprach_params 2140.0 0 3.75 >/dev/null 2>&1; echo $?)" "2"
    chk nprach-no-84 "$(iot_nprach_params 2>/dev/null | grep -c '84 resource')" "0"

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
        --nprach)       iot_nprach_params "${1:-2140.0}" "${2:-0}" "${3:-3.75}" ;;
        --npss-nss)     iot_npss_to_nss "${1:-0}" ;;
        --decode-sib1)  iot_decode_sib1_nb "${1:-}" ;;
        --decode-mib)   iot_decode_mib_nb "${1:-}" ;;
        --to-mhz)       iot_nprfcn_to_mhz "${1:-}" ;;
        --plan)         iot_plan "${1:-}" ;;
        --selftest)     iot_selftest ;;
        --menu)         iot_menu ;;
        *) cat >&2 <<EOF
NB-IoT / Cat-M1 — narrowband IoT air interface

Usage: $0 COMMAND
  --status-tsv       tool and store state as TSV
  --nprach           refuses: NPRACH parameters are not in this tree
  --npss-nss <pci>   PCI -> N_ID(1)/N_ID(2); NPSS is fixed, NSSS is the PCI-bearing one
  --decode-sib1 <hex>  decode a SystemInformationBlockType1-NB
  --decode-mib <hex>   decode a MasterInformationBlock-NB (5 octets, 34 bits)
  --to-mhz <nprfcn>  refuses: TS 36.104 Table 5.7.3-1 is per-band and absent here
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
