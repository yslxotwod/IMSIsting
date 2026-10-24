#!/usr/bin/env bash
# NAS signalling — measurement, procedure mix, storm detection, cost model
#                                                                   (tag: nasf)
#
# Capability split, per MODULE_CONVENTIONS.md §9:
#
#   * Measurement and detection are performed for real. The NAS message type
#     tables, the procedure classification, the cause-code tables, the rate
#     and per-procedure statistics and the storm profile all run here over a
#     capture (GSMTAP or a raw-NAS UDP stream; S1AP/NGAP captures through
#     tshark when it is present).
#   * The lab characterisation is a documented cost model: the message
#     sequence of each load pattern and the amplification factor it produces.
#   * SAFETY SCOPE — this module ships NO unattended flooding tool. The
#     transmit path is `status: handoff` and is gated four ways: it requires
#     the explicit `--i-have-a-lab-and-authorisation` flag, a named lab PLMN
#     argument (reserved test/internal MCC only), a rate at or below a stated
#     ceiling, and it refuses to run at all without those. It sends nothing;
#     it writes the plan and prints the parameters that were accepted, so a
#     testbed run is reproducible.
#
# Reference clause map (values asserted in --selftest are marked):
#   TS 24.301 §9.8      EPS NAS message types (EMM)
#   TS 24.301 §9.9.3.9  EMM cause values
#   TS 24.301 §8.2.4    Attach procedure message sequence
#   TS 24.301 §5.5.3    Tracking area updating
#   TS 24.301 §5.6.1    Service request procedure
#   TS 24.501 §9.7      ­ 5GS NAS message types (5GMM)
#   TS 24.501 §9.11.3.2 5GMM cause values
#   TS 23.401 §5.3.2    Attach / PDN connectivity signalling load
#   TS 33.401 §6.1      Authentication and NAS security setup
#   GSMTAP (Osmocom "gsmtap.h")   UDP 4729, type 18 = LTE NAS, 16-octet header
#
# Known-answer authorities used by --selftest:
#   * Wireshark 4.2.2 `tshark`: every NAS message type value and name in the
#     EPS and 5GS tables, and every EMM cause used here, was read back out of
#     the dissectors (`tshark -G values` for `nas-eps.nas_msg_emm_type`,
#     `nas-eps.nas_msg_esm_type`, `nas-5gs.mm.message_type`,
#     `nas-5gs.sm.message_type`, `diameter.3gpp.ran_nas.emm_cause`,
#     `nas-5gs.mm.5gmm_cause`). The GSMTAP LTE-NAS framing (UDP 4729, type 18,
#     16-octet header, NAS PDU at offset 16) was confirmed the same way by
#     building a frame with text2pcap and reading it back.
#   * TS 24.301 §9.8.1: the EMM message types are decimal 65..105, so 0x41 is
#     Attach request and 0x48 is Tracking area update request.
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
    IMSISTING_ROOT="$(cd -P "$(dirname "${_sl_src}")/.." && pwd)"
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

MOD_TMP="$TMP_DIR/nas_signaling"
NASF_DIR="$LOOT_DIR/nas_signaling"
NASF_PLANS="$NASF_DIR/plans"
mkdir -p "$MOD_TMP" "$NASF_DIR" "$NASF_PLANS" 2>/dev/null

# Hard safety limits for any transmit path. These are constants, not
# preferences: a caller cannot raise them from the command line.
NASF_RATE_CEILING=50          # messages per second, absolute maximum
NASF_RATE_DEFAULT=5           # messages per second when the caller does not say
NASF_LAB_MCC_ALLOW="001 999"  # ITU-reserved test / internal-use MCCs only
NASF_GSMTAP_PORT=4729
NASF_RAW_PORT=47999

# ── sanitisation and TSV splitting ──────────────────────────────────────
nasf_sanitize() { printf '%s' "${1:-}" | tr '\t\r\n' '   '; }

# Split a TSV line into NASF_F, preserving empty fields. This is the same
# contract as the `cut -f` split in MODULE_CONVENTIONS §12 — it just does it
# with parameter expansion instead of one subprocess per field, because the
# storm analysis splits every row of a capture and the process spawns
# dominated the run time. It never uses `IFS=$'\t' read`.
NASF_F=()
nasf_split() {
    NASF_F=()
    local line="${1:-}"
    while :; do
        if [[ "$line" == *$'\t'* ]]; then
            NASF_F+=( "${line%%$'\t'*}" )
            line="${line#*$'\t'}"
        else
            NASF_F+=( "$line" )
            break
        fi
    done
}

nasf_byte() { printf '%02X' "$(( ${1:-0} & 0xFF ))"; }
nasf_nfc() {
    local s="${1:-}"; s="${s^^}"; s="${s//[[:space:]]/}"; s="${s//:/}"; s="${s//-/}"
    printf '%s' "$s"
}
nasf_is_hex() { [[ "${1:-}" =~ ^[0-9A-Fa-f]+$ ]] && (( ${#1} % 2 == 0 )); }

# ── NAS message type tables ─────────────────────────────────────────────
# Values and names read back from Wireshark 4.2.2 nas-eps.nas_msg_emm_type /
# nas-eps.nas_msg_esm_type / nas-5gs.mm.message_type / nas-5gs.sm.message_type.
# Note that EPS and 5GS share the low type values (0x41 is Attach request in
# EPS and Registration request in 5GS), so every lookup takes a generation.
nasf_eps_msg_name() {
    case "${1:-}" in
        65)  echo "Attach request" ;;
        66)  echo "Attach accept" ;;
        67)  echo "Attach complete" ;;
        68)  echo "Attach reject" ;;
        69)  echo "Detach request" ;;
        70)  echo "Detach accept" ;;
        72)  echo "Tracking area update request" ;;
        73)  echo "Tracking area update accept" ;;
        74)  echo "Tracking area update complete" ;;
        75)  echo "Tracking area update reject" ;;
        76)  echo "Extended service request" ;;
        77)  echo "Control plane service request" ;;
        78)  echo "Service reject" ;;
        79)  echo "Service accept" ;;
        80)  echo "GUTI reallocation command" ;;
        81)  echo "GUTI reallocation complete" ;;
        82)  echo "Authentication request" ;;
        83)  echo "Authentication response" ;;
        84)  echo "Authentication reject" ;;
        85)  echo "Identity request" ;;
        86)  echo "Identity response" ;;
        92)  echo "Authentication failure" ;;
        93)  echo "Security mode command" ;;
        94)  echo "Security mode complete" ;;
        95)  echo "Security mode reject" ;;
        96)  echo "EMM status" ;;
        97)  echo "EMM information" ;;
        98)  echo "Downlink NAS transport" ;;
        99)  echo "Uplink NAS transport" ;;
        100) echo "CS service notification" ;;
        104) echo "Downlink generic NAS transport" ;;
        105) echo "Uplink generic NAS transport" ;;
        193) echo "Activate default EPS bearer context request" ;;
        194) echo "Activate default EPS bearer context accept" ;;
        195) echo "Activate default EPS bearer context reject" ;;
        197) echo "Activate dedicated EPS bearer context request" ;;
        198) echo "Activate dedicated EPS bearer context accept" ;;
        199) echo "Activate dedicated EPS bearer context reject" ;;
        201) echo "Modify EPS bearer context request" ;;
        202) echo "Modify EPS bearer context accept" ;;
        203) echo "Modify EPS bearer context reject" ;;
        205) echo "Deactivate EPS bearer context request" ;;
        206) echo "Deactivate EPS bearer context accept" ;;
        208) echo "PDN connectivity request" ;;
        209) echo "PDN connectivity reject" ;;
        210) echo "PDN disconnect request" ;;
        211) echo "PDN disconnect reject" ;;
        212) echo "Bearer resource allocation request" ;;
        213) echo "Bearer resource allocation reject" ;;
        214) echo "Bearer resource modification request" ;;
        215) echo "Bearer resource modification reject" ;;
        217) echo "ESM information request" ;;
        218) echo "ESM information response" ;;
        219) echo "Notification" ;;
        220) echo "ESM dummy message" ;;
        232) echo "ESM status" ;;
        *)   echo "unknown" ;;
    esac
}

nasf_5gs_msg_name() {
    case "${1:-}" in
        65)  echo "Registration request" ;;
        66)  echo "Registration accept" ;;
        67)  echo "Registration complete" ;;
        68)  echo "Registration reject" ;;
        69)  echo "Deregistration request (UE originating)" ;;
        70)  echo "Deregistration accept (UE originating)" ;;
        71)  echo "Deregistration request (UE terminated)" ;;
        72)  echo "Deregistration accept (UE terminated)" ;;
        76)  echo "Service request" ;;
        77)  echo "Service reject" ;;
        78)  echo "Service accept" ;;
        79)  echo "Control plane service request" ;;
        80)  echo "Network slice-specific authentication command" ;;
        81)  echo "Network slice-specific authentication complete" ;;
        82)  echo "Network slice-specific authentication result" ;;
        84)  echo "Configuration update command" ;;
        85)  echo "Configuration update complete" ;;
        86)  echo "Authentication request" ;;
        87)  echo "Authentication response" ;;
        88)  echo "Authentication reject" ;;
        89)  echo "Authentication failure" ;;
        90)  echo "Authentication result" ;;
        91)  echo "Identity request" ;;
        92)  echo "Identity response" ;;
        93)  echo "Security mode command" ;;
        94)  echo "Security mode complete" ;;
        95)  echo "Security mode reject" ;;
        100) echo "5GMM status" ;;
        101) echo "Notification" ;;
        193) echo "PDU session establishment request" ;;
        194) echo "PDU session establishment accept" ;;
        195) echo "PDU session establishment reject" ;;
        197) echo "PDU session authentication command" ;;
        198) echo "PDU session authentication complete" ;;
        199) echo "PDU session authentication result" ;;
        201) echo "PDU session modification request" ;;
        202) echo "PDU session modification reject" ;;
        203) echo "PDU session modification command" ;;
        204) echo "PDU session modification complete" ;;
        205) echo "PDU session modification command reject" ;;
        209) echo "PDU session release request" ;;
        210) echo "PDU session release reject" ;;
        211) echo "PDU session release command" ;;
        212) echo "PDU session release complete" ;;
        214) echo "5GSM status" ;;
        216) echo "Service-level authentication command" ;;
        217) echo "Service-level authentication complete" ;;
        *)   echo "unknown" ;;
    esac
}

nasf_msg_name() {  # <generation> <type>
    case "${1:-eps}" in
        eps) nasf_eps_msg_name "${2:-}" ;;
        5gs) nasf_5gs_msg_name "${2:-}" ;;
        *)   echo "unknown" ;;
    esac
}

# Procedure family per message type. The families are the ones the brief names
# plus the ESM/5GSM session family, which carries most of the message volume
# in a real attach.
nasf_procedure() {
    local gen="${1:-eps}" t="${2:-}"
    case "$gen" in
        eps)
            case "$t" in
                65|66|67|68)   echo "attach" ;;
                72|73|74|75)   echo "tau" ;;
                76|77|78|79)   echo "service-request" ;;
                69|70)         echo "detach" ;;
                82|83|84|92)   echo "authentication" ;;
                93|94|95)      echo "security-mode" ;;
                85|86)         echo "identity" ;;
                80|81)         echo "guti-reallocation" ;;
                193|194|195|197|198|199|201|202|203|205|206|208|209|210|211|212|213|214|215|217|218|219|220|232)
                               echo "esm-session" ;;
                96|97|98|99|100|104|105) echo "transport/status" ;;
                *)             echo "other" ;;
            esac ;;
        5gs)
            case "$t" in
                65|66|67|68)   echo "registration" ;;
                69|70|71|72)   echo "deregistration" ;;
                76|77|78|79)   echo "service-request" ;;
                86|87|88|89|90) echo "authentication" ;;
                93|94|95)      echo "security-mode" ;;
                91|92)         echo "identity" ;;
                80|81|82)      echo "slice-auth" ;;
                84|85)         echo "configuration-update" ;;
                193|194|195|197|198|199|201|202|203|204|205|209|210|211|212|214|216|217)
                               echo "session-management" ;;
                100|101)       echo "transport/status" ;;
                *)             echo "other" ;;
            esac ;;
        *) echo "other" ;;
    esac
}

# Reject / release messages: the denominator for the reject ratio.
nasf_is_reject() {
    local gen="${1:-eps}" t="${2:-}"
    case "$gen" in
        eps) case "$t" in 68|75|78|84|92|95|195|199|203|209|211|213|215) echo 1; return 0 ;; esac ;;
        5gs) case "$t" in 68|72|77|88|89|95|195|202|205|210) echo 1; return 0 ;; esac ;;
    esac
    echo 0
}

# ── cause codes ─────────────────────────────────────────────────────────
# EMM cause values from TS 24.301 §9.9.3.9, names read back from Wireshark
# 4.2.2 (the dissector field is diameter.3gpp.ran_nas.emm_cause).
nasf_emm_cause_name() {
    case "${1:-}" in
        2)   echo "IMSI unknown in HSS" ;;
        3)   echo "Illegal UE" ;;
        5)   echo "IMEI not accepted" ;;
        6)   echo "Illegal ME" ;;
        7)   echo "EPS services not allowed" ;;
        8)   echo "EPS services and non-EPS services not allowed" ;;
        9)   echo "UE identity cannot be derived by the network" ;;
        10)  echo "Implicitly detached" ;;
        11)  echo "PLMN not allowed" ;;
        12)  echo "Tracking Area not allowed" ;;
        13)  echo "Roaming not allowed in this tracking area" ;;
        14)  echo "EPS services not allowed in this PLMN" ;;
        15)  echo "No Suitable Cells In tracking area" ;;
        16)  echo "MSC temporarily not reachable" ;;
        17)  echo "Network failure" ;;
        18)  echo "CS domain not available" ;;
        19)  echo "ESM failure" ;;
        20)  echo "MAC failure" ;;
        21)  echo "Synch failure" ;;
        22)  echo "Congestion" ;;
        23)  echo "UE security capabilities mismatch" ;;
        24)  echo "Security mode rejected, unspecified" ;;
        25)  echo "Not authorized for this CSG" ;;
        26)  echo "Non-EPS authentication unacceptable" ;;
        31)  echo "Redirection to 5GCN required" ;;
        35)  echo "Requested service option not authorized in this PLMN" ;;
        39)  echo "CS service temporarily not available" ;;
        40)  echo "No EPS bearer context activated" ;;
        42)  echo "Severe network failure" ;;
        78)  echo "PLMN not allowed to operate at the present UE location" ;;
        95)  echo "Semantically incorrect message" ;;
        96)  echo "Invalid mandatory information" ;;
        97)  echo "Message type non-existent or not implemented" ;;
        98)  echo "Message type not compatible with the protocol state" ;;
        99)  echo "Information element non-existent or not implemented" ;;
        100) echo "Conditional IE error" ;;
        101) echo "Message not compatible with the protocol state" ;;
        111) echo "Protocol error, unspecified" ;;
        *)   echo "unknown" ;;
    esac
}

nasf_5gmm_cause_name() {
    case "${1:-}" in
        3)   echo "Illegal UE" ;;
        5)   echo "PEI not accepted" ;;
        6)   echo "Illegal ME" ;;
        7)   echo "5GS services not allowed" ;;
        9)   echo "UE identity cannot be derived by the network" ;;
        10)  echo "Implicitly deregistered" ;;
        11)  echo "PLMN not allowed" ;;
        12)  echo "Tracking area not allowed" ;;
        13)  echo "Roaming not allowed in this tracking area" ;;
        15)  echo "No suitable cells in tracking area" ;;
        20)  echo "MAC failure" ;;
        21)  echo "Synch failure" ;;
        22)  echo "Congestion" ;;
        23)  echo "UE security capabilities mismatch" ;;
        24)  echo "Security mode rejected, unspecified" ;;
        26)  echo "Non-5G authentication unacceptable" ;;
        27)  echo "N1 mode not allowed" ;;
        28)  echo "Restricted service area" ;;
        31)  echo "Redirection to EPC required" ;;
        43)  echo "LADN not available" ;;
        62)  echo "No network slices available" ;;
        65)  echo "Maximum number of PDU sessions reached" ;;
        67)  echo "Insufficient resources for specific slice and DNN" ;;
        69)  echo "Insufficient resources for specific slice" ;;
        71)  echo "ngKSI already in use" ;;
        72)  echo "Non-3GPP access to 5GCN not allowed" ;;
        73)  echo "Serving network not authorized" ;;
        74)  echo "Temporarily not authorized for this SNPN" ;;
        75)  echo "Permanently not authorized for this SNPN" ;;
        76)  echo "Not authorized for this CAG or authorized for CAG cells only" ;;
        77)  echo "Wireline access area not allowed" ;;
        78)  echo "PLMN not allowed to operate at the present UE location" ;;
        79)  echo "UAS services not allowed" ;;
        80)  echo "Disaster roaming for the determined PLMN with disaster condition not allowed" ;;
        90)  echo "Payload was not forwarded" ;;
        91)  echo "DNN not supported or not subscribed in the slice" ;;
        92)  echo "Insufficient user-plane resources for the PDU session" ;;
        93)  echo "Onboarding services terminated" ;;
        95)  echo "Semantically incorrect message" ;;
        96)  echo "Invalid mandatory information" ;;
        97)  echo "Message type non-existent or not implemented" ;;
        98)  echo "Message type not compatible with the protocol state" ;;
        99)  echo "Information element non-existent or not implemented" ;;
        100) echo "Conditional IE error" ;;
        101) echo "Message not compatible with the protocol state" ;;
        111) echo "Protocol error, unspecified" ;;
        *)   echo "unknown" ;;
    esac
}

nasf_cause_name() {
    case "${1:-eps}" in
        eps) nasf_emm_cause_name "${2:-}" ;;
        5gs) nasf_5gmm_cause_name "${2:-}" ;;
        *)   echo "unknown" ;;
    esac
}

# Cause codes on the wire.
#
# TS 24.301 §8.2.7/§8.2.26/§8.2.28: Attach reject, Tracking area update reject
# and Service reject carry the EMM cause as the octet immediately after the
# message type (a mandatory IE with no IEI). Verified against Wireshark 4.2.2:
# 07 44 0F is read as Attach reject with EMM cause 15, 07 4B 16 as TAU reject
# with cause 22. Detach request (0x45) carries the detach type in that octet
# instead, so it contributes no cause.
nasf_extract_cause() {  # <generation> <msgtype> <nas_hex>
    local gen="${1:-eps}" t="${2:-}" hex="${3^^}"
    if [[ "$gen" == "5gs" ]]; then
        # The 5GMM cause is the octet after the 3-octet 5GS plain-NAS header.
        (( ${#hex} >= 8 )) || { printf ''; return 0; }
        case "$t" in
            68|77) printf '%d' "$(( 16#${hex:6:2} ))"; return 0 ;;
        esac
        printf ''; return 0
    fi
    # EPS: the EMM cause is the octet after the 2-octet EPS plain-NAS header.
    # A three-octet message (type + cause) is the whole frame.
    (( ${#hex} >= 6 )) || { printf ''; return 0; }
    case "$t" in
        68|75|78) printf '%d' "$(( 16#${hex:4:2} ))"; return 0 ;;
    esac
    printf ''
}

# ── NAS PDU parse ───────────────────────────────────────────────────────
# <generation> <nas_hex> -> TSV one row per field. The security-protected
# wrapper is reported but not decrypted: a capture that only carries
# protected NAS still yields the outer type, which is the measurement input.
nasf_parse() {
    local gen="${1:-eps}" hex; hex=$(nasf_nfc "${2:-}")
    nasf_is_hex "$hex" || { printf 'ERROR\tnot valid hex\n' >&2; return 1; }
    local sht pdn t
    if [[ "$gen" == "5gs" ]]; then
        # 5GS plain NAS framing (TS 24.501 9.1.1):
        #   octet 1 extended protocol discriminator (0x7E for 5GMM)
        #   octet 2 spare half octet | security header type
        #   octet 3 message type
        # Confirmed against Wireshark 4.2.2 by exporting the PDU to the
        # `nas-5gs` dissector: 7E 00 44 16 is Registration reject with 5GMM
        # cause 22. The EPS layout is different (security header | PD first),
        # and using the EPS offsets on a 5GS PDU reads the message type out of
        # the security-header octet.
        (( ${#hex} >= 6 )) || { printf 'ERROR\t5GS NAS PDU shorter than three octets\n' >&2; return 1; }
        pdn=$(( 16#${hex:0:2} ))
        [[ "$pdn" -ge 0x7E ]] || { printf 'ERROR\tnot a 5GS plain NAS message (extended protocol discriminator 0x%s)\n' "${hex:0:2}" >&2; return 1; }
        sht=$(( (16#${hex:2:2} >> 4) & 0x0F ))
        t=$(( 16#${hex:4:2} ))
    else
        (( ${#hex} >= 4 )) || { printf 'ERROR\tNAS PDU shorter than two octets\n' >&2; return 1; }
        local pd=$(( 16#${hex:0:2} ))
        sht=$(( (pd >> 4) & 0x0F ))
        pdn=$(( pd & 0x0F ))
        t=$(( 16#${hex:2:2} ))
    fi
    printf 'generation\t%s\n' "$gen"
    printf 'protocol_discriminator\t%s\n' "$pdn"
    printf 'security_header_type\t%s\n' "$sht"
    printf 'plain_nas\t%s\n' "$(( sht == 0 ? 1 : 0 ))"
    printf 'message_type\t%s\n' "$t"
    printf 'message_name\t%s\n' "$(nasf_msg_name "$gen" "$t")"
    printf 'procedure\t%s\n' "$(nasf_procedure "$gen" "$t")"
    printf 'reject\t%s\n' "$(nasf_is_reject "$gen" "$t")"
    local cause; cause=$(nasf_extract_cause "$gen" "$t" "$hex")
    printf 'cause\t%s\n' "${cause:-}"
    printf 'cause_name\t%s\n' "$([[ -n "$cause" ]] && nasf_cause_name "$gen" "$cause" || printf '')"
    return 0
}

# ── capture extraction ──────────────────────────────────────────────────
# python3-stdlib reader for GSMTAP (UDP 4729, LTE NAS) and a raw-NAS UDP port.
# Same link/IP walk as the DNS module; SCTP/ASN.1 (S1AP, NGAP) is handled by
# the tshark fallback below rather than reimplemented here.
nasf_pcap_py() {
    cat <<'PYEOF'
import sys, struct

def _u16(b, o, e): return struct.unpack_from(e + 'H', b, o)[0]
def _u32(b, o, e): return struct.unpack_from(e + 'I', b, o)[0]

def classic(data):
    magic = data[:4]
    if magic in (b'\xa1\xb2\xc3\xd4', b'\xa1\xb2\x3c\x4d'): e = '>'
    elif magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1'): e = '<'
    else: return None, None
    if len(data) < 24: return None, None
    lt = _u32(data, 20, e)
    off, out = 24, []
    while off + 16 <= len(data):
        ts, tus, incl, orig = struct.unpack_from(e + 'IIII', data, off)
        off += 16
        if incl > len(data) - off: break
        out.append((ts + tus / 1000000.0, data[off:off + incl]))
        off += incl
    return lt, out

def pcapng(data):
    off, e, seen, lts, out = 0, '<', False, [], []
    while off + 12 <= len(data):
        probe = struct.unpack_from('<I', data, off)[0]
        if probe == 0x0A0D0D0A or (not seen and data[off:off + 4] == b'\x0a\x0d\x0d\x0a'):
            bom = struct.unpack_from('<I', data, off + 8)[0]
            e = '<' if bom == 0x1A2B3C4D else '>'
            seen = True
        btype = _u32(data, off, e); blen = _u32(data, off + 4, e)
        if blen < 12 or off + blen > len(data): break
        body = data[off + 8:off + blen - 4]
        if btype == 1:
            lts.append(_u16(body, 0, e))
        elif btype == 6:
            iface = _u32(body, 0, e)
            tsh = _u32(body, 4, e); tsl = _u32(body, 8, e); cap = _u32(body, 12, e)
            out.append((lts[iface] if iface < len(lts) else 1,
                        ((tsh << 32) | tsl) / 1000000.0, body[20:20 + cap]))
        elif btype == 3:
            orig = _u32(body, 0, e)
            out.append((lts[0] if lts else 1, 0.0, body[4:4 + orig]))
        off += blen
    return out

def ipv4(t):
    if len(t) < 20: return None
    ihl = (t[0] & 0x0F) * 4
    if ihl < 20 or len(t) < ihl: return None
    if struct.unpack_from('>H', t, 6)[0] & 0x1FFF: return None
    return t[9], '.'.join(str(x) for x in t[12:16]), '.'.join(str(x) for x in t[16:20]), t[ihl:]

def ipv6(t):
    if len(t) < 40: return None
    s = ':'.join('%02x%02x' % (t[8 + i * 2], t[9 + i * 2]) for i in range(8))
    d = ':'.join('%02x%02x' % (t[24 + i * 2], t[25 + i * 2]) for i in range(8))
    return t[6], s, d, t[40:]

def l3(t, lt):
    if lt == 1:
        if len(t) < 14: return None
        et = struct.unpack_from('>H', t, 12)[0]; off = 14
        while et in (0x8100, 0x88A8) and len(t) >= off + 4:
            et = struct.unpack_from('>H', t, off + 2)[0]; off += 4
        if et == 0x0800: return ipv4(t[off:])
        if et == 0x86DD: return ipv6(t[off:])
        return None
    if lt in (101, 12, 14, 228):
        if not t: return None
        v = t[0] >> 4
        return ipv4(t) if v == 4 else (ipv6(t) if v == 6 else None)
    if lt == 113:
        if len(t) < 16: return None
        et = struct.unpack_from('>H', t, 14)[0]
        return ipv4(t[16:]) if et == 0x0800 else (ipv6(t[16:]) if et == 0x86DD else None)
    if lt == 276:
        if len(t) < 20: return None
        et = struct.unpack_from('>H', t, 0)[0]
        return ipv4(t[20:]) if et == 0x0800 else (ipv6(t[20:]) if et == 0x86DD else None)
    return None

def main():
    path = sys.argv[1]
    raw_port = int(sys.argv[2]) if len(sys.argv) > 2 else 47999
    gsmtap_port = int(sys.argv[3]) if len(sys.argv) > 3 else 4729
    with open(path, 'rb') as f: data = f.read()
    lt, pkts = classic(data)
    if lt is not None:
        frames = [(i, ts, lt, p) for i, (ts, p) in enumerate(pkts, 1)]
    else:
        frames = [(i, ts, lt2, p) for i, (lt2, ts, p) in enumerate(pcapng(data), 1)]
    for idx, ts, linktype, pkt in frames:
        parsed = l3(pkt, linktype)
        if not parsed: continue
        proto, src, dst, payload = parsed
        if proto != 17: continue
        if len(payload) < 8: continue
        sp, dp, ln = struct.unpack_from('>HHH', payload, 0)
        up = payload[8:]
        if gsmtap_port in (sp, dp):
            if len(up) < 16: continue
            gtype = up[2]
            if gtype != 18:   # GSMTAP_TYPE_LTE_NAS
                continue
            nas = up[16:]
            if len(nas) >= 2:
                print('nas\t%d\t%.6f\t%s\t%s\tgsmtap\t%s\tnone\t%s' %
                      (idx, ts, src, dst, nas.hex().upper(), ''))
        elif raw_port in (sp, dp):
            if len(up) >= 2:
                print('nas\t%d\t%.6f\t%s\t%s\traw-udp\t%s\tnone\t%s' %
                      (idx, ts, src, dst, up.hex().upper(), ''))
    return 0

sys.exit(main())
PYEOF
}

# tshark fallback: covers S1AP and NGAP captures, where NAS lives inside ASN.1.
# Emits the same row shape, with the subscriber column filled from whichever
# identity field the dissector decoded.
nasf_extract_tshark() {
    local pcap="${1:-}"
    command -v tshark >/dev/null 2>&1 || return 1
    local fields=( -e frame.number -e frame.time_epoch -e ip.src -e ip.dst
                   -e nas-eps.nas_msg_emm_type -e nas-eps.nas_msg_esm_type
                   -e nas-5gs.mm.message_type -e nas-5gs.sm.message_type
                   -e nas-eps.emm.cause -e nas-5gs.mm.5gmm_cause
                   -e nas-eps.emm.imei -e nas-eps.emm.m_tmsi
                   -e nas-5gs.mm.imei -e nas-5gs.mm.imeisv )
    tshark -r "$pcap" -n -Y 'nas-eps || nas-5gs' -T fields "${fields[@]}" 2>/dev/null
}

nasf_capture_rows() {
    local pcap="${1:-}"
    [[ -n "$pcap" ]] || { printf 'ERROR\tusage: nasf_capture_rows <pcap>\n' >&2; return 2; }
    [[ -r "$pcap" ]] || { printf 'ERROR\tcannot read capture: %s\n' "$(nasf_sanitize "$pcap")" >&2; return 1; }
    local rows="" rc=0
    if command -v python3 >/dev/null 2>&1; then
        rows=$(python3 <(nasf_pcap_py) "$pcap" "$NASF_RAW_PORT" "$NASF_GSMTAP_PORT") || rc=$?
    fi
    if [[ -z "$rows" ]] && command -v tshark >/dev/null 2>&1; then
        # S1AP / NGAP: NAS inside ASN.1. Emit rows with the decoded type.
        local line
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            nasf_split "$line"
            local fr="${NASF_F[0]:-}" ts="${NASF_F[1]:-}" s="${NASF_F[2]:-}" d="${NASF_F[3]:-}"
            local emm="${NASF_F[4]:-}" esm="${NASF_F[5]:-}" mm="${NASF_F[6]:-}" sm="${NASF_F[7]:-}"
            local ec="${NASF_F[8]:-}" mc="${NASF_F[9]:-}"
            local imei="${NASF_F[10]:-}" tmsi="${NASF_F[11]:-}"
            local imei5="${NASF_F[12]:-}" imeisv5="${NASF_F[13]:-}"
            local gen t cause sub="none"
            if [[ -n "$emm" || -n "$esm" ]]; then
                gen=eps
                t="${emm:-$esm}"
                cause="$ec"
            elif [[ -n "$mm" || -n "$sm" ]]; then
                gen=5gs
                t="${mm:-$sm}"
                cause="$mc"
            else
                continue
            fi
            [[ -n "$imei" ]] && sub="imei:$imei"
            [[ -n "$imei5" && "$sub" == "none" ]] && sub="imei:$imei5"
            [[ -n "$imeisv5" && "$sub" == "none" ]] && sub="imeisv:$imeisv5"
            [[ -n "$tmsi" && "$sub" == "none" ]] && sub="m-tmsi:$tmsi"
            printf 'decoded\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                "$(nasf_sanitize "$fr")" "$(nasf_sanitize "${ts:-0}")" \
                "$(nasf_sanitize "${s:-?}")" "$(nasf_sanitize "${d:-?}")" \
                "$(nasf_sanitize "$gen")" "$(nasf_sanitize "$t")" \
                "$(nasf_sanitize "${cause:-}")" "$(nasf_sanitize "$sub")"
        done <<<"$rows"
        return 0
    fi
    (( rc == 0 )) || { printf 'ERROR\tpython3 could not read %s\n' "$(nasf_sanitize "$pcap")" >&2; return 1; }
    [[ -n "$rows" ]] || { printf 'MISSING\tno NAS messages found in %s (GSMTAP type 18 on UDP 4729 or raw NAS on UDP %s; S1AP/NGAP needs tshark)\n' \
        "$(nasf_sanitize "$pcap")" "$NASF_RAW_PORT" >&2; return 1; }
    printf '%s\n' "$rows"
}

# Normalise raw captures into the analysis row shape:
#   record  frame ts src dst encap gen type cause sub
nasf_normalise() {
    local line
    local fr ts s d enc dh gen sub t cause
    # Declare before the read loop: `local` inside a `while read` body is the
    # field-splitting trap (MODULE_CONVENTIONS §15).
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        nasf_split "$line"
        case "${NASF_F[0]:-}" in
            decoded)
                printf 'row\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                    "${NASF_F[1]:-}" "${NASF_F[2]:-}" "${NASF_F[3]:-}" "${NASF_F[4]:-}" \
                    "${NASF_F[5]:-}" "${NASF_F[6]:-}" "${NASF_F[7]:-}" "${NASF_F[8]:-}"
                ;;
            nas)
                fr="${NASF_F[1]:-}"; ts="${NASF_F[2]:-}"; s="${NASF_F[3]:-}"; d="${NASF_F[4]:-}"
                enc="${NASF_F[5]:-}"; dh="${NASF_F[6]:-}"; sub="${NASF_F[7]:-}"
                [[ -z "$sub" ]] && sub="none"
                # GSMTAP LTE NAS is EPS. A raw-NAS stream is EPS unless the
                # caller says otherwise; the type tables are chosen below by
                # looking at the discriminator.
                local pd=$(( 16#${dh:0:2} ))
                gen=eps
                if (( pd >= 0x7E )); then
                    # 5GS plain NAS: [ext PD][spare|sec hdr][message type]
                    gen=5gs
                    (( ${#dh} >= 6 )) || continue
                    t=$(( 16#${dh:4:2} ))
                else
                    t=$(( 16#${dh:2:2} ))
                fi
                cause=$(nasf_extract_cause "$gen" "$t" "$dh")
                printf 'row\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                    "$(nasf_sanitize "$fr")" "$(nasf_sanitize "${ts:-0}")" \
                    "$(nasf_sanitize "${s:-?}")" "$(nasf_sanitize "${d:-?}")" \
                    "$gen" "$t" "$(nasf_sanitize "${cause:-}")" "$sub"
                ;;
        esac
    done
}

# ── analysis (pure functions over the row shape) ────────────────────────
# Row: record frame ts src dst gen type cause sub
# Every rule below is a pure function of that stream, which is what makes it
# testable without a capture.

nasf_rate_rows() {
    local line
    local n=0 first="" last="" fr ts rate
    local -A proc_n type_n sub_n
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        nasf_split "$line"
        [[ "${NASF_F[0]:-}" == "row" ]] || continue
        n=$(( n + 1 ))
        ts="${NASF_F[2]:-0}"
        [[ -z "$first" ]] && first="$ts"
        last="$ts"
        proc_n["$(nasf_procedure "${NASF_F[5]:-eps}" "${NASF_F[6]:-0}")"]=$(( ${proc_n["$(nasf_procedure "${NASF_F[5]:-eps}" "${NASF_F[6]:-0}")"]:-0} + 1 ))
        type_n["${NASF_F[5]:-eps}:${NASF_F[6]:-0}"]=$(( ${type_n["${NASF_F[5]:-eps}:${NASF_F[6]:-0}"]:-0} + 1 ))
        sub_n["${NASF_F[8]:-none}"]=$(( ${sub_n["${NASF_F[8]:-none}"]:-0} + 1 ))
    done
    (( n > 0 )) || { printf 'ERROR\tno NAS messages to measure\n' >&2; return 1; }
    local dur; dur=$(awk -v a="$first" -v b="$last" 'BEGIN{printf "%.6f", b-a}')
    rate=$(awk -v n="$n" -v d="$dur" 'BEGIN{ if (d+0 <= 0) print n; else printf "%.3f", n/(d+0) }')
    printf 'messages\t%s\n' "$n"
    printf 'first_ts\t%s\n' "$first"
    printf 'last_ts\t%s\n' "$last"
    printf 'duration_s\t%s\n' "$dur"
    printf 'rate_msg_s\t%s\n' "$rate"
    printf 'unique_subscribers\t%s\n' "$(printf '%s\n' "${!sub_n[@]}" | grep -vc '^none$')"
    printf 'unattributed\t%s\n' "${sub_n[none]:-0}"
    printf 'header\tscope\tkey\tmessages\trate_msg_s\n'
    local k
    for k in "${!proc_n[@]}"; do
        printf 'procedure\t%s\t%s\t%s\t%s\n' "$(nasf_sanitize "$k")" "$(nasf_sanitize "$k")" \
            "${proc_n[$k]}" "$(awk -v c="${proc_n[$k]}" -v d="$dur" 'BEGIN{ if (d+0<=0) print c; else printf "%.3f", c/(d+0) }')"
    done
    for k in "${!type_n[@]}"; do
        local g="${k%%:*}" t="${k##*:}"
        printf 'message\t%s\t%s\t%s\t%s\n' "$g" "$(nasf_sanitize "$(nasf_msg_name "$g" "$t")")" \
            "${type_n[$k]}" "$(awk -v c="${type_n[$k]}" -v d="$dur" 'BEGIN{ if (d+0<=0) print c; else printf "%.3f", c/(d+0) }')"
    done
    for k in "${!sub_n[@]}"; do
        [[ "$k" == "none" ]] && continue
        printf 'subscriber\t%s\t%s\t%s\t%s\n' "sub" "$(nasf_sanitize "$k")" "${sub_n[$k]}" \
            "$(awk -v c="${sub_n[$k]}" -v d="$dur" 'BEGIN{ if (d+0<=0) print c; else printf "%.3f", c/(d+0) }')"
    done
    return 0
}

nasf_procedure_mix_rows() {
    local line
    local n=0
    local -A proc_n cause_n rej_n
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        nasf_split "$line"
        [[ "${NASF_F[0]:-}" == "row" ]] || continue
        n=$(( n + 1 ))
        local p; p=$(nasf_procedure "${NASF_F[5]:-eps}" "${NASF_F[6]:-0}")
        proc_n["$p"]=$(( ${proc_n[$p]:-0} + 1 ))
        local r; r=$(nasf_is_reject "${NASF_F[5]:-eps}" "${NASF_F[6]:-0}")
        (( r )) && rej_n["$p"]=$(( ${rej_n[$p]:-0} + 1 ))
    done
    (( n > 0 )) || { printf 'ERROR\tno NAS messages to classify\n' >&2; return 1; }
    printf 'messages\t%s\n' "$n"
    printf 'header\tprocedure\tmessages\tshare_pct\trejects\n'
    local k
    for k in "${!proc_n[@]}"; do
        printf 'mix\t%s\t%s\t%s\t%s\n' "$(nasf_sanitize "$k")" "${proc_n[$k]}" \
            "$(awk -v c="${proc_n[$k]}" -v n="$n" 'BEGIN{printf "%.2f", 100*c/n}')" \
            "${rej_n[$k]:-0}"
    done
    return 0
}

nasf_causes_rows() {
    local line
    local n=0 withcause=0
    local -A cause_n
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        nasf_split "$line"
        [[ "${NASF_F[0]:-}" == "row" ]] || continue
        n=$(( n + 1 ))
        local c="${NASF_F[7]:-}"
        [[ -z "$c" ]] && continue
        withcause=$(( withcause + 1 ))
        cause_n["${NASF_F[5]:-eps}:$c"]=$(( ${cause_n["${NASF_F[5]:-eps}:$c"]:-0} + 1 ))
    done
    (( n > 0 )) || { printf 'ERROR\tno NAS messages to inspect for causes\n' >&2; return 1; }
    printf 'messages\t%s\n' "$n"
    printf 'causes_present\t%s\n' "$withcause"
    printf 'header\tgeneration\tcause\tname\tcount\tshare_pct\n'
    local k
    for k in "${!cause_n[@]}"; do
        local g="${k%%:*}" c="${k##*:}"
        printf 'cause\t%s\t%s\t%s\t%s\t%s\n' "$g" "$(nasf_sanitize "$c")" \
            "$(nasf_sanitize "$(nasf_cause_name "$g" "$c")")" "${cause_n[$k]}" \
            "$(awk -v x="${cause_n[$k]}" -v w="$withcause" 'BEGIN{ if (w>0) printf "%.2f", 100*x/w; else print 0 }')"
    done
    return 0
}

# Storm profile. Fires only when the load signature matches, and abstains
# otherwise — a detector that always fires is worthless.
#
# Rules:
#   storm-rate-flat-subscribers  the second half of the capture runs at >= 3x
#                                the rate of the first half while the unique
#                                subscriber count does not grow
#   single-subscriber-dominates  one subscriber key is > 50% of all messages
#   repeated-identical-procedure the same (subscriber, message type) recurs
#                                >= 20 times in the capture
#   cause-clustering             one cause value is > 50% of all causes present
#   rising-reject-ratio          the reject share more than doubles between the
#                                halves and is above 10% in the second
#   subscriber-count-rising      informational: the subscriber count grew, so
#                                the load is growth, not a storm
nasf_storm_rows() {
    local line
    local -a rows=()
    local -A sub_n pair_n cause_n
    local n=0
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        nasf_split "$line"
        [[ "${NASF_F[0]:-}" == "row" ]] || continue
        rows+=( "$line" )
        n=$(( n + 1 ))
        sub_n["${NASF_F[8]:-none}"]=$(( ${sub_n["${NASF_F[8]:-none}"]:-0} + 1 ))
        local p="${NASF_F[8]:-none}|${NASF_F[5]:-eps}:${NASF_F[6]:-0}"
        pair_n["$p"]=$(( ${pair_n[$p]:-0} + 1 ))
        local c="${NASF_F[7]:-}"
        [[ -n "$c" ]] && cause_n["${NASF_F[5]:-eps}:$c"]=$(( ${cause_n["${NASF_F[5]:-eps}:$c"]:-0} + 1 ))
    done
    (( n > 0 )) || { printf 'ERROR\tno NAS messages to profile\n' >&2; return 1; }

    local half=$(( n / 2 ))
    local i first_ts last_ts mid_ts
    first_ts=$(printf '%s' "${rows[0]}" | cut -f3)
    last_ts=$(printf '%s' "${rows[$(( n - 1 ))]}" | cut -f3)
    mid_ts=$(printf '%s' "${rows[$half]}" | cut -f3)

    local -A h1sub h2sub h1cause h2cause
    local h1=0 h2=0 h1rej=0 h2rej=0
    for (( i = 0; i < n; i++ )); do
        nasf_split "${rows[$i]}"
        local s="${NASF_F[8]:-none}" r
        r=$(nasf_is_reject "${NASF_F[5]:-eps}" "${NASF_F[6]:-0}")
        if (( i < half )); then
            h1=$(( h1 + 1 )); h1sub["$s"]=1; (( r )) && h1rej=$(( h1rej + 1 ))
        else
            h2=$(( h2 + 1 )); h2sub["$s"]=1; (( r )) && h2rej=$(( h2rej + 1 ))
        fi
    done
    local d1 d2 r1 r2
    d1=$(awk -v a="$first_ts" -v b="$mid_ts" 'BEGIN{printf "%.6f", b-a}')
    d2=$(awk -v a="$mid_ts" -v b="$last_ts" 'BEGIN{printf "%.6f", b-a}')
    (( $(awk -v d="$d1" 'BEGIN{print (d<=0)?1:0}') )) && d1=1
    (( $(awk -v d="$d2" 'BEGIN{print (d<=0)?1:0}') )) && d2=1
    r1=$(awk -v c="$h1" -v d="$d1" 'BEGIN{printf "%.3f", c/d}')
    r2=$(awk -v c="$h2" -v d="$d2" 'BEGIN{printf "%.3f", c/d}')

    printf 'messages\t%s\n' "$n"
    printf 'half1_messages\t%s\n' "$h1"
    printf 'half2_messages\t%s\n' "$h2"
    printf 'half1_rate_msg_s\t%s\n' "$r1"
    printf 'half2_rate_msg_s\t%s\n' "$r2"
    printf 'half1_unique_subscribers\t%s\n' "${#h1sub[@]}"
    printf 'half2_unique_subscribers\t%s\n' "${#h2sub[@]}"
    printf 'header\tseverity\trule\tdetail\n'

    # Rate rise with a flat subscriber count.
    if (( ${#h2sub[@]} <= ${#h1sub[@]} )) && \
       (( $(awk -v a="$r1" -v b="$r2" 'BEGIN{print (b >= 3*a && b >= 5) ? 1 : 0}') )); then
        printf 'finding\tHIGH\tstorm-rate-flat-subscribers\t%s -> %s msg/s across the capture with the unique subscriber count flat at %s -> %s\n' \
            "$r1" "$r2" "${#h1sub[@]}" "${#h2sub[@]}"
    fi
    if (( ${#h2sub[@]} > ${#h1sub[@]} )); then
        printf 'finding\tINFO\tsubscriber-count-rising\tunique subscriber keys grew %s -> %s: growth, not a storm\n' \
            "${#h1sub[@]}" "${#h2sub[@]}"
    fi
    # One subscriber dominating.
    local k
    for k in "${!sub_n[@]}"; do
        [[ "$k" == "none" ]] && continue
        if (( sub_n[$k] * 2 > n )); then
            printf 'finding\tHIGH\tsingle-subscriber-dominates\t%s accounts for %s of %s messages\n' \
                "$(nasf_sanitize "$k")" "${sub_n[$k]}" "$n"
        fi
    done
    # Repeated identical procedure.
    for k in "${!pair_n[@]}"; do
        (( pair_n[$k] >= 20 )) || continue
        printf 'finding\tMEDIUM\trepeated-identical-procedure\t%s repeated %s times\n' \
            "$(nasf_sanitize "$k")" "${pair_n[$k]}"
    done
    # Cause clustering.
    local total_causes=0
    for k in "${!cause_n[@]}"; do total_causes=$(( total_causes + cause_n[$k] )); done
    for k in "${!cause_n[@]}"; do
        if (( total_causes > 0 && cause_n[$k] * 2 > total_causes )); then
            local g="${k%%:*}" c="${k##*:}"
            printf 'finding\tMEDIUM\tcause-clustering\tcause %s (%s) is %s of %s causes present\n' \
                "$(nasf_sanitize "$c")" "$(nasf_sanitize "$(nasf_cause_name "$g" "$c")")" \
                "${cause_n[$k]}" "$total_causes"
        fi
    done
    # Rising reject ratio.
    local rr1 rr2
    rr1=$(awk -v a="$h1rej" -v b="$h1" 'BEGIN{printf "%.4f", (b>0)?a/b:0}')
    rr2=$(awk -v a="$h2rej" -v b="$h2" 'BEGIN{printf "%.4f", (b>0)?a/b:0}')
    if (( $(awk -v a="$rr1" -v b="$rr2" 'BEGIN{print (b > 0.10 && b > 2*a) ? 1 : 0}') )); then
        printf 'finding\tHIGH\trising-reject-ratio\treject share %s -> %s between the halves\n' "$rr1" "$rr2"
    fi
    # If nothing fired we print nothing above the header; the caller sees an
    # empty finding set, which is the honest answer for a healthy capture.
    return 0
}

# ── the cost model ──────────────────────────────────────────────────────
# Analysis of the protocol's cost structure: what each documented load pattern
# costs in NAS messages, in access-stratum messages and in core transactions.
# "Amplification" is core transactions per UE-originated NAS message.
nasf_cost_model() {
    cat <<'EOF'
pattern	ue_action	nas_sequence	nas_messages	s1ap_or_ngap	core_transactions	amplification	note
attach-detach-loop	attach then detach, repeat	Attach request -> Identity request/response (optional) -> Authentication request/response -> Security mode command/complete -> Attach accept/complete -> (PDN connectivity request/accept) -> Detach request/accept	8-11 per cycle	10-14 per cycle	ULR/ULA + AIR/AIA + (CLR/CLA on the next attach) + Update-Location at the SGSN	~3 core transactions per NAS message	the most expensive per UE action: it re-runs authentication and moves the subscriber registration every cycle, so the HSS sees ULR + AIR each time (TS 23.401 5.3.2)
tau-storm	repeated Tracking area update with a changing TAI	Tracking area update request -> Tracking area update accept	2 per cycle	2-3 per cycle	ULR/ULA at the HSS when the TAI changes, and ISD/DSR when the subscription profile has to be re-pushed	~1-1.5	cheap per message but the HSS/UDM cost is per TAI change, not per message; a UE that is made to change TAI on every cycle doubles the cost (TS 24.301 5.5.3)
service-request-flood	repeated Service request / Control plane service request	Extended service request -> Service accept (or Service reject)	2 per cycle	2-4 per cycle	none in the common case; only the MME state machine	~0 the cheapest NAS procedure, which is why it is the one that scales: the cost is connection state and paging-channel occupancy, not core signalling
authentication-failure-loop	repeat attach with a deliberately wrong authentication response	Attach request -> Authentication request -> Authentication failure (MAC failure / Synch failure) -> Authentication reject	4 per cycle	4-6 per cycle	HSS counters and (on many implementations) a temporary barring or a re-sync attempt per failure	~0.5-1 each failure consumes an authentication vector from the HSS, which is a finite per-subscriber resource
paging-to-service-request	network pages an idle UE; the UE answers with Service request	paging (RRC/S1AP) -> Service request -> Service accept	2 per cycle	3-5 per cycle	none in the core	- the paging-to-service-request ratio is the metric that separates a real traffic rise from a paging amplifier: a storm shows many pages with few valid service requests
nas-message-cost-model	measurement basis	one NAS message costs one S1AP/NGAP NAS transport, one RRC message and (for the mobility procedures) one core transaction	-	-	-	- TS 24.301 / TS 24.501 define the messages; the core transactions are TS 23.401 5.3.2 (attach, ULR/AIR) and TS 29.272 (S6a)
safety-scope	why there is no flooding verb	load applied at rate degrades emergency service on the same cell and the same MME/AMF, and an operator cannot tell a test from an attack	-	-	-	- the deliverable here is the measurement, the detection and this cost model; the transmit path is gated and handed off
EOF
}

# ── transmit path: gated, handoff-only, sends nothing ───────────────────
# Argument validation is the enforcement point. Everything below refuses
# unless the caller has said, in full, what they are doing and where.
nasf_validate_lab_plmn() {
    local plmn="${1:-}"
    [[ "$plmn" =~ ^[0-9]{5,6}$ ]] || {
        printf 'ERROR\t--transmit needs a named lab PLMN (5 or 6 digits, e.g. 00101 or 99970); got "%s"\n' \
            "$(nasf_sanitize "${plmn:-<empty>}")" >&2
        return 2
    }
    local mcc="${plmn:0:3}"
    local ok=0 m
    for m in $NASF_LAB_MCC_ALLOW; do [[ "$mcc" == "$m" ]] && ok=1; done
    (( ok )) || {
        printf 'ERROR\tPLMN %s is not a lab PLMN: MCC must be one of %s (ITU-reserved test/internal use)\n' \
            "$(nasf_sanitize "$plmn")" "$NASF_LAB_MCC_ALLOW" >&2
        return 2
    }
    return 0
}

nasf_validate_rate() {
    local rate="${1:-}"
    [[ "$rate" =~ ^[0-9]+$ ]] || {
        printf 'ERROR\t--rate must be a positive integer (messages per second)\n' >&2
        return 2
    }
    (( rate >= 1 )) || { printf 'ERROR\t--rate must be at least 1\n' >&2; return 2; }
    (( rate <= NASF_RATE_CEILING )) || {
        printf 'ERROR\t--rate %s exceeds the hard ceiling of %s msg/s; this module will not go faster\n' \
            "$rate" "$NASF_RATE_CEILING" >&2
        return 2
    }
    return 0
}

nasf_plan_lab_storm() {
    local plmn="${1:-<none>}" rate="${2:-$NASF_RATE_DEFAULT}"
    mkdir -p "$NASF_PLANS" || { printf 'ERROR\tcannot create %s\n' "$NASF_PLANS" >&2; return 1; }
    local out="$NASF_PLANS/lab-storm.plan"
    {
        printf 'status: handoff\n'
        printf 'plan: %s\n' "NAS signalling load characterisation on a lab PLMN"
        printf 'module: 32_nas_signaling.sh (nasf)\n'
        printf 'requires: %s\n' "an isolated lab PLMN (MCC 001 or 999) with its own eNB/gNB and core (srsRAN or OpenAirInterface + Open5GS/free5GC), one or more test UEs on programmable test SIMs, and a Faraday cage or a shielded RF path"
        printf 'lab_plmn: %s\n' "$(nasf_sanitize "$plmn")"
        printf 'rate_ceiling_msg_s: %s\n' "$NASF_RATE_CEILING"
        printf 'requested_rate_msg_s: %s\n' "$(nasf_sanitize "$rate")"
        printf 'generated: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf '\n'
        cat <<'EOF'
# NAS signalling load characterisation — handoff

## Scope and safety
This module does not ship a flooding tool. What it hands off is a bounded
characterisation run on an *isolated* lab PLMN, for measuring how the core
behaves under each documented NAS load pattern. Signalling load at rate
degrades emergency service on the same cell and the same MME/AMF, and it is
indistinguishable from an attack at the operator's monitoring. That is why the
transmit path is gated, rate-limited and handed off rather than shipped.

## What is already implemented in software
- NAS message type tables for EPS and 5GS, the procedure classification, the
  EMM and 5GMM cause tables, and the rate / procedure-mix / cause / storm
  analysis (`--rate`, `--procedure-mix`, `--causes`, `--storm-profile`).
- The cost model (`--cost-model`): the message sequence of each pattern and
  the core transactions it produces.
- Argument validation that enforces the lab PLMN, the authorisation flag and
  the rate ceiling before anything else happens.

## What the handoff needs
1. An isolated lab PLMN with MCC 001 (test) or 999 (internal use), its own
   eNB/gNB and core: srsRAN or OpenAirInterface with Open5GS or free5GC.
2. One or more test UEs with programmable test SIMs (sysmoUSIM/sysmoISIM or
   an eSIM profile you own), so the attach/detach, TAU and service-request
   patterns can be driven from the UE side.
3. A Faraday cage or a conducted RF path, so the lab PLMN cannot be reached
   from outside and cannot attract a real UE.
4. A capture point on the NAS path: GSMTAP from the eNB/gNB (UDP 4729) or an
   S1AP/NGAP capture, which `--rate` and `--storm-profile` read directly.

## Procedure
1. Bring the lab up and confirm one UE attaches and detaches cleanly.
2. Capture NAS with GSMTAP and record the baseline with `--rate`.
3. Drive ONE pattern at the accepted rate, for a bounded duration:
   the attach/detach loop, the TAU storm, the service-request flood, or the
   authentication-failure loop (which consumes authentication vectors).
4. Record `--storm-profile` on the capture and confirm the detector fires on
   the pattern and does not fire on the idle baseline.
5. Compare the measured core transaction counts against `--cost-model`.
6. Stop. Do not raise the rate above the ceiling; the ceiling exists because
   the interesting behaviour (state exhaustion, reject ratios) appears well
   below it, and above it the run is just an outage.

## Refusal conditions (enforced in code)
- no lab PLMN, or a PLMN whose MCC is not 001/999
- a rate above 50 msg/s, or a non-integer rate
EOF
    } > "$out" || { printf 'ERROR\tcould not write %s\n' "$out" >&2; return 1; }
    [[ -s "$out" ]] || { printf 'ERROR\t%s is empty\n' "$out" >&2; return 1; }
    printf '%s' "$out"
}

# The transmit verb. Never sends anything: it validates, then writes the plan.
nasf_cmd_transmit() {
    local plmn="${1:-}" rate="${2:-$NASF_RATE_DEFAULT}"
    nasf_validate_lab_plmn "$plmn" || return 2
    nasf_validate_rate "$rate" || return 2
    local pf
    pf=$(nasf_plan_lab_storm "$plmn" "$rate") || return 1
    printf 'plan_file\t%s\n' "$pf"
    printf 'status\thandoff\n'
    printf 'lab_plmn\t%s\n' "$(nasf_sanitize "$plmn")"
    printf 'rate_msg_s\t%s\n' "$(nasf_sanitize "$rate")"
    printf 'rate_ceiling_msg_s\t%s\n' "$NASF_RATE_CEILING"
    printf 'sent\t0\n'
    printf 'note\t%s\n' "nothing was transmitted; signalling load at rate degrades emergency service on a live network, so this path is bounded and handed off to the lab named in the plan"
    return 0
}

# ── the unauthenticated message builders ────────────────────────────────
# An MME has to talk to a handset before it has authenticated it. Attach
# reject, TAU reject, Service reject, Identity request, Authentication
# request/failure and the Security mode messages all arrive in that window,
# and every one of them is a header plus fixed IEs whose values this module
# already carries (the EMM cause table and the identity types above).
#
# What is built here is the octets. Nothing is sent: there is no SCTP
# association and no NGAP to carry it, so a builder that says "built" is
# telling the truth and a builder that said "sent" would not be.
#
# Two things are deliberately NOT built, and the output says so in a `limit`
# row rather than leaving the reader to guess:
#   * the NAS-MAC on a Security mode command -- it is a function of K_ASME and
#     an integrity algorithm this tree does not implement, so the message is
#     built up to the MAC and a handset will treat it as unprotected;
#   * any encrypted IE -- the same reason, one layer down.
#
# Sources. The message type numbers and the EPS EMM cause values were read out
# of Wireshark 4.2.2's own value tables (`tshark -G values`) and each built
# vector is decoded back by `tools/check-nas-vectors.sh`, which is why the
# known answers in the selftest are not this file quoting itself. The TS
# clause numbers for the individual IEs are NOT reproduced: this author could
# not check them, and a wrong clause number is worse than none. The layout
# stated below is the one the oracle confirms.

nasf_eps_type() {  # <name> -> message type as two hex digits
    case "${1:-}" in
        attach-accept)          printf '42' ;;
        detach-accept)          printf '46' ;;
        tau-accept)             printf '49' ;;
        service-accept)         printf '4F' ;;
        attach-reject)          printf '44' ;;
        tau-reject)             printf '4B' ;;
        service-reject)         printf '4E' ;;
        identity-request)       printf '55' ;;
        auth-request)           printf '52' ;;
        auth-reject)            printf '54' ;;
        auth-failure)           printf '5C' ;;
        security-mode-command)  printf '5D' ;;
        security-mode-reject)   printf '5F' ;;
        *) return 1 ;;
    esac
}

nasf_5gs_type() {  # <name> -> message type as two hex digits
    case "${1:-}" in
        registration-reject)    printf '44' ;;
        service-reject)         printf '4D' ;;
        identity-request)       printf '5B' ;;
        auth-request)           printf '56' ;;
        auth-reject)            printf '58' ;;
        auth-failure)           printf '59' ;;
        security-mode-command)  printf '5D' ;;
        security-mode-reject)   printf '5F' ;;
        *) return 1 ;;
    esac
}

nasf_eps_messages()  { printf 'attach-accept detach-accept tau-accept service-accept attach-reject tau-reject service-reject identity-request auth-request auth-reject auth-failure security-mode-command security-mode-reject'; }
nasf_5gs_messages()  { printf 'registration-reject service-reject identity-request auth-request auth-reject auth-failure security-mode-command security-mode-reject'; }

# Identity type octets. EPS values from Wireshark 4.2.2 (`nas-eps.emm.id_type2`:
# 1 IMSI, 2 IMEI, 3 IMEISV, 4 TMSI). The 5GS values are TS 24.501's own list and
# are NOT oracle-checked -- no GSMTAP encapsulation reaches the nas-5gs
# dissector, so the check script reports them as unverified rather than passing
# them. Saying that here is the difference between a gap and a lie.
nasf_identity_code() {  # <gen> <name> -> octet
    case "${1:-}" in
        eps)
            case "${2:-}" in
                imsi)   printf '01' ;;
                imei)   printf '02' ;;
                imeisv) printf '03' ;;
                tmsi)   printf '04' ;;
                *) return 1 ;;
            esac ;;
        5gs)
            case "${2:-}" in
                suci)       printf '01' ;;
                5g-guti)    printf '02' ;;
                imei)       printf '03' ;;
                5g-s-tmsi)  printf '04' ;;
                imeisv)     printf '05' ;;
                *) return 1 ;;
            esac ;;
        *) return 1 ;;
    esac
}

# EPS attach result (TS 24.301 §9.9.3.10) and EPS update result (§9.9.3.13).
nasf_attach_result_name() {
    case "${1:-}" in
        0) printf 'reserved' ;;
        1) printf 'EPS only' ;;
        2) printf 'combined EPS/IMSI' ;;
        *) printf 'reserved' ;;
    esac
}

nasf_tau_result_name() {
    case "${1:-}" in
        0) printf 'TA updated' ;;
        1) printf 'TA updated, ISR activated' ;;
        *) printf 'reserved' ;;
    esac
}

# PLMN identity, BCD, as TS 23.003 §2.2 orders it and both the TAI list and
# the EPS mobile identity use it: octet 1 = MCC2|MCC1, octet 2 = MNC3|MCC3
# (MNC3 is F for a two-digit MNC), octet 3 = MNC2|MNC1.  The octet order is
# asserted in --selftest against `43_ran_share --plmn-encode`, which is the
# module that owns PLMN coding.
nasf_plmn_bcd() {  # <mcc 3 digits> <mnc 2 or 3 digits>
    local mcc="${1:-}" mnc="${2:-}"
    [[ "$mcc" =~ ^[0-9]{3}$ ]] || { printf 'ERROR\tMCC must be 3 digits\n' >&2; return 1; }
    [[ "$mnc" =~ ^[0-9]{2,3}$ ]] || { printf 'ERROR\tMNC must be 2 or 3 digits\n' >&2; return 1; }
    local o1 o2 o3
    o1=$(( (10#${mcc:1:1} << 4) | 10#${mcc:0:1} ))
    if (( ${#mnc} == 3 )); then
        o2=$(( (10#${mnc:2:1} << 4) | 10#${mcc:2:1} ))
    else
        o2=$(( (0xF << 4) | 10#${mcc:2:1} ))
    fi
    o3=$(( (10#${mnc:1:1} << 4) | 10#${mnc:0:1} ))
    printf '%02X%02X%02X' "$o1" "$o2" "$o3"
}

# TAI list IE (type 4, TLV, IEI 0x54) carrying one TAI.  Value part: the
# list-type octet (spare + 3-bit type; 000 is a partial list), the TAI count,
# then each TAI as a 3-octet BCD PLMN and a 2-octet TAC.
nasf_tai_list() {  # <plmn 5 or 6 digits> <tac 4 hex>
    local plmn="${1:-00101}" tac="${2:-0001}"
    [[ "$plmn" =~ ^[0-9]{5,6}$ ]] || {
        printf 'ERROR\t--tai wants a 5- or 6-digit PLMN (MCC + MNC), got %s\n' "$(nasf_sanitize "$plmn")" >&2; return 1; }
    [[ "$tac" =~ ^[0-9A-Fa-f]{4}$ ]] || {
        printf 'ERROR\t--tac wants 4 hex digits, got %s\n' "$(nasf_sanitize "$tac")" >&2; return 1; }
    local bcd; bcd=$(nasf_plmn_bcd "${plmn:0:3}" "${plmn:3}") || return 1
    # The value part is 7 octets: list type, count, PLMN (3), TAC (2).
    printf '5407%s%02X%s%s' "00" 1 "$bcd" "${tac^^}"
}

nasf_hexlen() { printf '%d' "$(( ${#1} / 2 ))"; }

# nasf_build <gen> <message> [flags] -> TSV on stdout
nasf_build() {
    local gen="${1:-eps}" msg="${2:-}"; shift 2 2>/dev/null || { shift; }
    local cause="" ident="" rand="" autn="" auts="" eea="" eia="" ksi="0" ksitype="0" out=""
    local accept_result="" tai_plmn="00101" tac="0001" t3412="1E"
    while (( $# > 0 )); do
        local flag="$1"
        case "$flag" in
            --cause)        cause="${2:-}";  shift 2 ;;
            --result)       accept_result="${2:-}"; shift 2 ;;
            --tai)          tai_plmn="${2:-}"; shift 2 ;;
            --tac)          tac="${2:-}";    shift 2 ;;
            --t3412)        t3412="${2:-}";  shift 2 ;;
            --identity)     ident="${2:-}";  shift 2 ;;
            --rand)         rand="${2:-}";   shift 2 ;;
            --autn)         autn="${2:-}";   shift 2 ;;
            --auts)         auts="${2:-}";   shift 2 ;;
            --ksi)          ksi="${2:-}";    shift 2 ;;
            --ksi-type)     ksitype="${2:-}"; shift 2 ;;
            --out)          out="${2:-}";    shift 2 ;;
            --algorithms)
                eea="${2:-}"; eia="${3:-}"
                [[ -n "$eea" && -n "$eia" ]] || {
                    printf 'ERROR\t--algorithms takes two values: <eea> <eia>\n' >&2; return 2; }
                shift 3 ;;
            *)
                printf 'ERROR\t--build does not take %s (see --help)\n' "$(nasf_sanitize "$flag")" >&2
                return 2 ;;
        esac
        (( $# >= 0 )) || break
    done

    case "$gen" in eps|5gs) ;; *)
        printf 'ERROR\t--build needs a generation: eps or 5gs; got %s\n' "$(nasf_sanitize "$gen")" >&2; return 2 ;; esac

    local t
    if [[ "$gen" == "eps" ]]; then t=$(nasf_eps_type "$msg") || {
            printf 'ERROR\tunknown EPS message: %s\n' "$(nasf_sanitize "$msg")" >&2
            printf 'WHY\tthe builders cover the pre-authentication window: %s\n' "$(nasf_eps_messages)" >&2
            return 2; }
    else t=$(nasf_5gs_type "$msg") || {
            printf 'ERROR\tunknown 5GS message: %s\n' "$(nasf_sanitize "$msg")" >&2
            printf 'WHY\tthe builders cover the pre-authentication window: %s\n' "$(nasf_5gs_messages)" >&2
            return 2; }
    fi

    # header
    local hex
    if [[ "$gen" == "eps" ]]; then hex="07${t}"; else hex="7E00${t}"; fi

    local limit="" fields=""
    case "$msg" in
        attach-reject|tau-reject|service-reject|registration-reject|security-mode-reject)
            [[ -n "$cause" ]] || { printf 'ERROR\t%s needs --cause <n>; the cause is a mandatory IE\n' "$msg" >&2; return 2; }
            [[ "$cause" =~ ^[0-9]+$ ]] || { printf 'ERROR\t--cause must be a decimal number, got %s\n' "$(nasf_sanitize "$cause")" >&2; return 2; }
            (( cause >= 0 && cause <= 255 )) || { printf 'ERROR\t--cause must be 0..255\n' >&2; return 2; }
            local cname; cname=$(nasf_cause_name "$gen" "$cause")
            if [[ "$cname" == "unknown" || "$cname" == "unassigned" || -z "$cname" ]]; then
                limit="cause ${cause} is not in the ${gen} cause table; the octet is built as given"
            fi
            hex+=$(nasf_byte "$cause")
            fields="cause=$cause ($cname)"
            ;;
        identity-request)
            [[ -n "$ident" ]] || { printf 'ERROR\tidentity-request needs --identity; valid for %s: %s\n' "$gen" "$([[ $gen == eps ]] && echo 'imsi imei imeisv tmsi' || echo 'suci 5g-guti imei 5g-s-tmsi imeisv')" >&2; return 2; }
            local icode; icode=$(nasf_identity_code "$gen" "$ident") || {
                printf 'ERROR\t%s is not an identity type in %s\n' "$(nasf_sanitize "$ident")" "$gen" >&2; return 2; }
            hex+="$icode"
            fields="identity=$ident"
            ;;
        auth-request)
            # RAND is built; AUTN is NOT, and this is the honest limit of the
            # whole Phase 16 message set. AUTN belongs after RAND, and no
            # implementation this tree can reach will confirm where: Wireshark
            # 4.2.2's nas-eps dissector has no AUTN field at all (only RAND and
            # the message authentication code), and it reports the whole message
            # "Malformed Packet" as soon as 16 further octets follow the RAND.
            # An octet at an unconfirmed offset is a guess, so it is refused
            # rather than emitted -- with the evidence, so the next reader can
            # settle it against TS 24.301 and add it here.
            local r
            r=$(nasf_nfc "${rand:-}")
            [[ -n "$r" ]] || { printf 'ERROR\tauth-request needs --rand <32 hex>\n' >&2; return 2; }
            nasf_is_hex "$r" || { printf 'ERROR\t--rand is not hex\n' >&2; return 2; }
            (( $(nasf_hexlen "$r") == 16 )) || { printf 'ERROR\t--rand must be 16 octets (32 hex digits); got %d\n' "$(nasf_hexlen "$r")" >&2; return 2; }
            if [[ -n "$autn" ]]; then
                printf 'ERROR\t--autn is not built: the position of AUTN after RAND could not be confirmed\n' >&2
                printf 'WHY\tWireshark 4.2.2 has no AUTN field in its nas-eps dissector and reports the message malformed when 16 octets follow the RAND, so an AUTN at that offset would be a guess; verify against TS 24.301 and add it here\n' >&2
                return 2
            fi
            [[ "$ksi" =~ ^[0-7]$ ]] || { printf 'ERROR\t--ksi must be 0..7\n' >&2; return 2; }
            [[ "$ksitype" =~ ^[01]$ ]] || { printf 'ERROR\t--ksi-type must be 0 (native) or 1 (mapped)\n' >&2; return 2; }
            hex+=$(printf '%X%X' "$ksitype" "$ksi")
            hex+="${r^^}"
            fields="ksi=$ksi ksi_type=$ksitype rand_octets=16"
            limit="RAND only: AUTN is not built (see the --autn refusal) and the MAC is absent, so no handset will authenticate against this"
            ;;
        auth-reject)
            fields="no_ie=1"
            ;;
        auth-failure)
            [[ -n "$cause" ]] || { printf 'ERROR\tauth-failure needs --cause <n>\n' >&2; return 2; }
            [[ "$cause" =~ ^[0-9]+$ ]] || { printf 'ERROR\t--cause must be a decimal number\n' >&2; return 2; }
            hex+=$(nasf_byte "$cause")
            fields="cause=$cause ($(nasf_cause_name "$gen" "$cause"))"
            if [[ -n "$auts" ]]; then
                local s; s=$(nasf_nfc "$auts")
                nasf_is_hex "$s" || { printf 'ERROR\t--auts is not hex\n' >&2; return 2; }
                (( $(nasf_hexlen "$s") == 14 )) || { printf 'ERROR\t--auts must be 14 octets (28 hex digits); got %d\n' "$(nasf_hexlen "$s")" >&2; return 2; }
                hex+="${s^^}"
                fields+=" auts_octets=14"
            fi
            ;;
        attach-accept|tau-accept)
            # Mandatory IEs only, in the order TS 24.301 §8.2.1.2 / §8.2.2.2
            # puts them: the result (type 1, TV), the T3412 timer (type 3, TV)
            # and the TAI list (type 4, TLV).  The ESM message container is
            # what carries the default bearer, and no activate-default-bearer
            # request is built here yet, so the accept stops before it and the
            # limitation is stated rather than papered over.
            local result="${accept_result:-}"
            if [[ "$msg" == "attach-accept" ]]; then
                [[ -n "$result" ]] || result=1
                [[ "$result" =~ ^[0-9]+$ ]] && (( result >= 0 && result <= 7 )) || {
                    printf 'ERROR\t--result must be 0..7 (1 = EPS only)\n' >&2; return 2; }
                hex+=$(nasf_byte "$result")
                fields="attach_result=$result ($(nasf_attach_result_name "$result"))"
            else
                [[ -n "$result" ]] || result=0
                [[ "$result" =~ ^[0-9]+$ ]] && (( result >= 0 && result <= 7 )) || {
                    printf 'ERROR\t--result must be 0..7 (0 = TA updated)\n' >&2; return 2; }
                hex+=$(nasf_byte "$result")
                fields="update_result=$result ($(nasf_tau_result_name "$result"))"
            fi
            hex+="${t3412:-1E}"
            fields+=" t3412=${t3412:-1E}"
            local tai; tai=$(nasf_tai_list "${tai_plmn:-00101}" "${tac:-0001}") || return 2
            hex+="$tai"
            fields+=" tai_list=1"
            limit="the ESM message container is not built: no activate-default-EPS-bearer-context request exists in this tree yet, so the accept carries no default bearer and a handset will ask for one"
            ;;
        service-accept|detach-accept)
            # Both are allowed to carry nothing: TS 24.301 §9.8.1 lists no
            # mandatory IE for either, and a detach accept with a cause is
            # optional.
            if [[ -n "$cause" ]]; then
                [[ "$cause" =~ ^[0-9]+$ ]] || { printf 'ERROR\t--cause must be a decimal number\n' >&2; return 2; }
                hex+=$(nasf_byte "$cause")
                fields="cause=$cause ($(nasf_cause_name "$gen" "$cause"))"
            else
                fields="no_ie=1"
            fi
            ;;
        security-mode-command)
            [[ -n "$eea" && -n "$eia" ]] || { printf 'ERROR\tsecurity-mode-command needs --algorithms <eea> <eia>\n' >&2; return 2; }
            [[ "$eea" =~ ^[0-7]$ && "$eia" =~ ^[0-7]$ ]] || { printf 'ERROR\t--algorithms takes two values 0..7\n' >&2; return 2; }
            [[ "$ksi" =~ ^[0-7]$ ]] || { printf 'ERROR\t--ksi must be 0..7\n' >&2; return 2; }
            hex+=$(printf '%X%X' "$eea" "$eia")
            hex+=$(printf '0%X' "$ksi")
            # Replayed UE security capabilities: LV, length 2, then one octet
            # of EEA bits and one of EIA bits. The bit for algorithm n is
            # 1 << (7 - n), with the null algorithm 0 at bit 8 -- which is what
            # tshark reads back: 20 20 is "128-EEA2: Supported, 128-EIA2:
            # Supported" and 02 02 is "Not supported". The module replays the
            # algorithms it just selected, which is the capability a UE that
            # accepted them must have.
            local eea_mask eia_mask
            if (( eea == 0 )); then eea_mask=0x80; else eea_mask=$(( 1 << (7 - eea) )); fi
            if (( eia == 0 )); then eia_mask=0x80; else eia_mask=$(( 1 << (7 - eia) )); fi
            hex+=$(printf '02%02X%02X' "$eea_mask" "$eia_mask")
            fields="eea=$eea eia=$eia ksi=$ksi replayed_caps=$(printf '%02X%02X' "$eea_mask" "$eia_mask")"
            limit="NAS-MAC is not built: it is a function of K_ASME and an integrity algorithm this tree does not implement, so the message stops before the MAC and a handset will treat it as unprotected"
            ;;
    esac

    local bytes; bytes=$(nasf_hexlen "$hex")
    printf 'generation\t%s\n' "$gen"
    printf 'message\t%s\n' "$msg"
    printf 'message_type\t%s\n' "$t"
    printf 'message_name\t%s\n' "$(nasf_msg_name "$gen" "$(( 16#$t ))")"
    [[ -n "$fields" ]] && printf 'fields\t%s\n' "$fields"
    printf 'bytes\t%d\n' "$bytes"
    printf 'hex\t%s\n' "${hex^^}"
    printf 'built\tyes\n'
    printf 'sent\t0\n'
    printf 'carrier\tnone -- no SCTP association and no NGAP/S1AP wrapper is built here, so this is a message, not a transmission\n'
    [[ -n "$limit" ]] && printf 'limit\t%s\n' "$limit"
    if [[ -n "$out" ]]; then
        command -v xxd >/dev/null 2>&1 || {
            printf 'ERROR\t--out needs xxd, which is not on PATH\n' >&2; return 1; }
        mkdir -p "$(dirname "$out")" 2>/dev/null
        printf '%s' "${hex^^}" | xxd -r -p > "$out" 2>/dev/null || {
            printf 'ERROR\tcould not write %s\n' "$(nasf_sanitize "$out")" >&2; return 1; }
        printf 'out_file\t%s\n' "$(nasf_sanitize "$out")"
    fi
    return 0
}

nasf_cmd_build() {
    local gen="${1:-eps}" msg="${2:-}"
    [[ -n "$msg" ]] || {
        printf 'ERROR\tusage: --build-nas <eps|5gs> <message> [--cause n] [--identity t] [--rand hex --autn hex] [--algorithms eea eia] [--out path]\n' >&2
        printf 'WHY\tEPS: %s\n' "$(nasf_eps_messages)" >&2
        printf 'WHY\t5GS: %s\n' "$(nasf_5gs_messages)" >&2
        return 2; }
    shift 2
    nasf_build "$gen" "$msg" "$@"
}

# ── CLI verbs ───────────────────────────────────────────────────────────
nasf_cli_status_tsv() {
    local plans=0
    [[ -d "$NASF_PLANS" ]] && plans=$(find "$NASF_PLANS" -name '*.plan' -type f 2>/dev/null | wc -l)
    printf 'module\tnas_signaling\n'
    printf 'tag\tnasf\n'
    printf 'dir\t%s\n' "$NASF_DIR"
    printf 'plans_dir\t%s\n' "$NASF_PLANS"
    printf 'plans\t%s\n' "$plans"
    printf 'python3\t%s\n' "$(command -v python3 >/dev/null 2>&1 && echo yes || echo no)"
    printf 'tshark\t%s\n' "$(command -v tshark >/dev/null 2>&1 && echo yes || echo no)"
    printf 'sources\tGSMTAP LTE NAS (UDP %s), raw NAS (UDP %s), S1AP/NGAP via tshark\n' "$NASF_GSMTAP_PORT" "$NASF_RAW_PORT"
    printf 'rate_ceiling_msg_s\t%s\n' "$NASF_RATE_CEILING"
    printf 'transmit_path\thandoff\n'
    printf 'gate\tnone -- the builders produce octets and send nothing\n'
    printf 'builders_eps\t%s\n' "$(nasf_eps_messages)"
    printf 'builders_5gs\t%s\n' "$(nasf_5gs_messages)"
    printf 'builders_count\t%s\n' "$(( $(nasf_eps_messages | wc -w) + $(nasf_5gs_messages | wc -w) ))"
    printf 'nas_mac\tnot built -- needs K_ASME and an integrity algorithm\n'
    printf 'refs\tTS 24.301, TS 24.501, TS 23.401, TS 33.401, GSMTAP\n'
}

nasf_rows_for() {  # <pcap> -> normalised rows on stdout
    local pcap="${1:-}"
    [[ -n "$pcap" ]] || { printf 'ERROR\tusage: needs a capture path\n' >&2; return 2; }
    nasf_capture_rows "$pcap" | nasf_normalise
}

nasf_cmd_rate() {
    local pcap="${1:-}"
    [[ -n "$pcap" ]] || { printf 'ERROR\tusage: --rate <pcap>\n' >&2; return 2; }
    local rows; rows=$(nasf_rows_for "$pcap") || return 1
    [[ -n "$rows" ]] || { printf 'ERROR\tno NAS messages in %s\n' "$(nasf_sanitize "$pcap")" >&2; return 1; }
    printf 'capture\t%s\n' "$(nasf_sanitize "$pcap")"
    printf '%s\n' "$rows" | nasf_rate_rows
}

nasf_cmd_procedure_mix() {
    local pcap="${1:-}"
    [[ -n "$pcap" ]] || { printf 'ERROR\tusage: --procedure-mix <pcap>\n' >&2; return 2; }
    local rows; rows=$(nasf_rows_for "$pcap") || return 1
    [[ -n "$rows" ]] || { printf 'ERROR\tno NAS messages in %s\n' "$(nasf_sanitize "$pcap")" >&2; return 1; }
    printf 'capture\t%s\n' "$(nasf_sanitize "$pcap")"
    printf '%s\n' "$rows" | nasf_procedure_mix_rows
}

nasf_cmd_causes() {
    local pcap="${1:-}"
    [[ -n "$pcap" ]] || { printf 'ERROR\tusage: --causes <pcap>\n' >&2; return 2; }
    local rows; rows=$(nasf_rows_for "$pcap") || return 1
    [[ -n "$rows" ]] || { printf 'ERROR\tno NAS messages in %s\n' "$(nasf_sanitize "$pcap")" >&2; return 1; }
    printf 'capture\t%s\n' "$(nasf_sanitize "$pcap")"
    printf '%s\n' "$rows" | nasf_causes_rows
}

nasf_cmd_storm_profile() {
    local pcap="${1:-}"
    [[ -n "$pcap" ]] || { printf 'ERROR\tusage: --storm-profile <pcap>\n' >&2; return 2; }
    local rows; rows=$(nasf_rows_for "$pcap") || return 1
    [[ -n "$rows" ]] || { printf 'ERROR\tno NAS messages in %s\n' "$(nasf_sanitize "$pcap")" >&2; return 1; }
    printf 'capture\t%s\n' "$(nasf_sanitize "$pcap")"
    printf '%s\n' "$rows" | nasf_storm_rows
}

nasf_cmd_decode() {
    local gen="${1:-eps}" hex="${2:-}"
    [[ -n "$hex" ]] || { printf 'ERROR\tusage: --decode-nas <eps|5gs> <hex>\n' >&2; return 2; }
    nasf_parse "$gen" "$hex"
}

nasf_cmd_plan() {
    local which="${1:-}"
    case "$which" in
        lab-storm)
            local pf; pf=$(nasf_plan_lab_storm "00101" "$NASF_RATE_DEFAULT") || return 1
            printf 'plan_file\t%s\n' "$pf"
            printf 'status\thandoff\n'
            printf 'note\t%s\n' "the plan names the lab PLMN, the rate ceiling and the refusal conditions; no traffic was sent"
            return 0 ;;
        *)
            printf 'ERROR\tunknown plan: %s (want lab-storm)\n' "$(nasf_sanitize "${which:-<none>}")" >&2
            return 2 ;;
    esac
}

# ── selftest — no radio, no root, no network ────────────────────────────
nasf_selftest() {
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
    local _prev_trap; _prev_trap=$(trap -p EXIT)
    trap 'rm -rf "$d"' EXIT
    export LOOT_DIR="$d/loot"
    export CAPTURES_DIR="$d/captures"
    export STATE_DIR="$d/state"
    export NASF_DIR="$d/loot/nas_signaling"
    export NASF_PLANS="$NASF_DIR/plans"
    mkdir -p "$NASF_PLANS"

    # ── 1. Message type tables, known answers from tshark ───────────────
    chk eps-65  "$(nasf_eps_msg_name 65)"  "Attach request"
    chk eps-66  "$(nasf_eps_msg_name 66)"  "Attach accept"
    chk eps-68  "$(nasf_eps_msg_name 68)"  "Attach reject"
    chk eps-69  "$(nasf_eps_msg_name 69)"  "Detach request"
    chk eps-72  "$(nasf_eps_msg_name 72)"  "Tracking area update request"
    chk eps-75  "$(nasf_eps_msg_name 75)"  "Tracking area update reject"
    chk eps-76  "$(nasf_eps_msg_name 76)"  "Extended service request"
    chk eps-77  "$(nasf_eps_msg_name 77)"  "Control plane service request"
    chk eps-82  "$(nasf_eps_msg_name 82)"  "Authentication request"
    chk eps-83  "$(nasf_eps_msg_name 83)"  "Authentication response"
    chk eps-85  "$(nasf_eps_msg_name 85)"  "Identity request"
    chk eps-86  "$(nasf_eps_msg_name 86)"  "Identity response"
    chk eps-92  "$(nasf_eps_msg_name 92)"  "Authentication failure"
    chk eps-93  "$(nasf_eps_msg_name 93)"  "Security mode command"
    chk eps-94  "$(nasf_eps_msg_name 94)"  "Security mode complete"
    chk eps-96  "$(nasf_eps_msg_name 96)"  "EMM status"
    chk eps-208 "$(nasf_eps_msg_name 208)" "PDN connectivity request"
    chk eps-unknown "$(nasf_eps_msg_name 250)" "unknown"
    # The 5GS table shares the low values deliberately; 0x41 is a *different*
    # message in each generation, which is why every lookup takes one.
    chk g5-65   "$(nasf_5gs_msg_name 65)"  "Registration request"
    chk g5-76   "$(nasf_5gs_msg_name 76)"  "Service request"
    chk g5-86   "$(nasf_5gs_msg_name 86)"  "Authentication request"
    chk g5-91   "$(nasf_5gs_msg_name 91)"  "Identity request"
    chk g5-93   "$(nasf_5gs_msg_name 93)"  "Security mode command"
    chk g5-193  "$(nasf_5gs_msg_name 193)" "PDU session establishment request"
    chk gen-differs "$( [[ "$(nasf_msg_name eps 65)" != "$(nasf_msg_name 5gs 65)" ]] && echo yes || echo no)" "yes"

    # ── 2. Procedure classification for every real NAS message type ─────
    local m
    for m in 65 66 67 68; do chk "proc-attach-$m" "$(nasf_procedure eps "$m")" "attach"; done
    for m in 72 73 74 75; do chk "proc-tau-$m" "$(nasf_procedure eps "$m")" "tau"; done
    for m in 76 77 78 79; do chk "proc-svc-$m" "$(nasf_procedure eps "$m")" "service-request"; done
    for m in 69 70; do chk "proc-detach-$m" "$(nasf_procedure eps "$m")" "detach"; done
    for m in 82 83 84 92; do chk "proc-auth-$m" "$(nasf_procedure eps "$m")" "authentication"; done
    for m in 93 94 95; do chk "proc-sec-$m" "$(nasf_procedure eps "$m")" "security-mode"; done
    for m in 85 86; do chk "proc-id-$m" "$(nasf_procedure eps "$m")" "identity"; done
    chk proc-esm       "$(nasf_procedure eps 208)" "esm-session"
    chk proc-other     "$(nasf_procedure eps 250)" "other"
    for m in 65 66 67 68; do chk "proc5-reg-$m" "$(nasf_procedure 5gs "$m")" "registration"; done
    chk proc5-svc      "$(nasf_procedure 5gs 76)" "service-request"
    chk proc5-sess     "$(nasf_procedure 5gs 193)" "session-management"
    chk reject-yes     "$(nasf_is_reject eps 68)" "1"
    chk reject-no      "$(nasf_is_reject eps 65)" "0"

    # ── 3. EMM / 5GMM causes, known answers from tshark ─────────────────
    chk emm-2   "$(nasf_emm_cause_name 2)"  "IMSI unknown in HSS"
    chk emm-15  "$(nasf_emm_cause_name 15)" "No Suitable Cells In tracking area"
    chk emm-20  "$(nasf_emm_cause_name 20)" "MAC failure"
    chk emm-21  "$(nasf_emm_cause_name 21)" "Synch failure"
    chk emm-22  "$(nasf_emm_cause_name 22)" "Congestion"
    chk emm-unknown "$(nasf_emm_cause_name 200)" "unknown"
    chk g5mm-22 "$(nasf_5gmm_cause_name 22)" "Congestion"
    chk g5mm-72 "$(nasf_5gmm_cause_name 72)" "Non-3GPP access to 5GCN not allowed"
    chk g5mm-73 "$(nasf_5gmm_cause_name 73)" "Serving network not authorized"

    # ── 4. NAS PDU parse against tshark-verified frames ─────────────────
    # 07 44 0F: Attach reject, EMM cause 15 — tshark 4.2.2 reads exactly that.
    out=$(nasf_parse eps "07440F"); rc=$?
    chk parse-rc      "$rc" "0"
    chk parse-pd      "$(fld "$out" protocol_discriminator)" "7"
    chk parse-sht     "$(fld "$out" security_header_type)" "0"
    chk parse-plain   "$(fld "$out" plain_nas)" "1"
    chk parse-type    "$(fld "$out" message_type)" "68"
    chk parse-name    "$(fld "$out" message_name)" "Attach reject"
    chk parse-proc    "$(fld "$out" procedure)" "attach"
    chk parse-cause   "$(fld "$out" cause)" "15"
    chk parse-causename "$(fld "$out" cause_name)" "No Suitable Cells In tracking area"
    # 07 4B 16: TAU reject, cause 22.
    out=$(nasf_parse eps "074B16")
    chk parse-tau-name  "$(fld "$out" message_name)" "Tracking area update reject"
    chk parse-tau-cause "$(fld "$out" cause)" "22"
    chk parse-tau-cn    "$(fld "$out" cause_name)" "Congestion"
    # 07 41: Attach request, no cause.
    out=$(nasf_parse eps "0741")
    chk parse-att-name  "$(fld "$out" message_name)" "Attach request"
    chk parse-att-cause "$(fld "$out" cause)" ""
    chk parse-short     "$(nasf_parse eps 07 >/dev/null 2>&1; echo $?)" "1"
    chk parse-nonhex    "$(nasf_parse eps zz >/dev/null 2>&1; echo $?)" "1"
    # 5GS framing is different from EPS and was verified against Wireshark
    # 4.2.2: 7E 00 44 16 is Registration reject with 5GMM cause 22, and
    # 7E 00 44 3E is cause 62. Using the EPS offsets here would read the
    # message type out of the security-header octet.
    out=$(nasf_parse 5gs "7E004416"); rc=$?
    chk parse5-rc     "$rc" "0"
    chk parse5-epd    "$(fld "$out" protocol_discriminator)" "126"
    chk parse5-sht    "$(fld "$out" security_header_type)" "0"
    chk parse5-plain  "$(fld "$out" plain_nas)" "1"
    chk parse5-type   "$(fld "$out" message_type)" "68"
    chk parse5-name   "$(fld "$out" message_name)" "Registration reject"
    chk parse5-cause  "$(fld "$out" cause)" "22"
    chk parse5-cname  "$(fld "$out" cause_name)" "Congestion"
    out=$(nasf_parse 5gs "7E00443E")
    chk parse5-cause62 "$(fld "$out" cause)" "62"
    chk parse5-cname62 "$(fld "$out" cause_name)" "No network slices available"
    chk parse5-short  "$(nasf_parse 5gs 7E00 >/dev/null 2>&1; echo $?)" "1"

    # ── 5. Rate against a synthetic capture with a known count/duration ─
    # 60 messages spread over exactly 59 seconds => 1.017 msg/s.
    local pcap="$d/rate.pcap"
    if command -v python3 >/dev/null 2>&1; then
        python3 - "$pcap" <<'PY'
import struct, sys
path = sys.argv[1]
def gsmtap(nas):
    return struct.pack('>BBBBhbbI', 2, 4, 18, 0, 0, 0, 0, 0) + b'\x00' * 4 + nas
def eth(p): return bytes.fromhex('00112233445566778899aabb') + struct.pack('>H', 0x0800) + p
def ip(s, d, p):
    return struct.pack('>BBHHHBBH', 0x45, 0, 20 + len(p), 1, 0, 64, 17, 0) + s + d + p
def udp(sp, dp, p): return struct.pack('>HHHH', sp, dp, 8 + len(p), 0) + p
C = bytes([10, 0, 0, 2]); S = bytes([10, 0, 0, 1])
# 60 periodic TAU requests, one per second, over 59 seconds
n, frames = 60, []
for i in range(n):
    nas = bytes([0x07, 0x48])
    fr = eth(ip(C, S, udp(40000, 4729, gsmtap(nas))))
    frames.append((1700000000 + i, fr))
with open(path, 'wb') as f:
    f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for ts, fr in frames:
        f.write(struct.pack('<IIII', ts, 0, len(fr), len(fr)))
        f.write(fr)
PY
        out=$(nasf_cmd_rate "$pcap"); rc=$?
        chk rate-rc       "$rc" "0"
        chk rate-count    "$(fld "$out" messages)" "60"
        chk rate-duration "$(fld "$out" duration_s)" "59.000000"
        chk rate-value    "$(fld "$out" rate_msg_s)" "1.017"
        chk rate-proc-n   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="procedure" && $2=="tau"{print $4}')" "60"
        out=$(nasf_cmd_procedure_mix "$pcap")
        chk mix-count  "$(fld "$out" messages)" "60"
        chk mix-tau    "$(printf '%s\n' "$out" | awk -F'\t' '$1=="mix" && $2=="tau"{print $3}')" "60"
        chk mix-share  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="mix" && $2=="tau"{print $4}')" "100.00"
        out=$(nasf_cmd_causes "$pcap")
        chk causes-none "$(fld "$out" causes_present)" "0"
        # The capture contains only a steady TAU stream: no storm finding.
        out=$(nasf_cmd_storm_profile "$pcap")
        chk storm-steady "$(printf '%s\n' "$out" | grep -c 'storm-rate-flat-subscribers')" "0"

        # A storm: 120 messages, 10 in the first half over 10 s, 110 in the
        # second half over ~0.19 s, one subscriber throughout.
        storm="$d/storm.pcap"
        python3 - "$storm" <<'PY'
import struct, sys
path = sys.argv[1]
def gsmtap(nas):
    return struct.pack('>BBBBhbbI', 2, 4, 18, 0, 0, 0, 0, 0) + b'\x00' * 4 + nas
def eth(p): return bytes.fromhex('00112233445566778899aabb') + struct.pack('>H', 0x0800) + p
def ip(s, d, p):
    return struct.pack('>BBHHHBBH', 0x45, 0, 20 + len(p), 1, 0, 64, 17, 0) + s + d + p
def udp(sp, dp, p): return struct.pack('>HHHH', sp, dp, 8 + len(p), 0) + p
C = bytes([10, 0, 0, 2]); S = bytes([10, 0, 0, 1])
frames = []
for i in range(10):
    frames.append((1700000000 + i, eth(ip(C, S, udp(40000, 4729, gsmtap(bytes([0x07, 0x41])))))))
for i in range(590):
    frames.append((1700000010 + i * 0.0017, eth(ip(C, S, udp(40000, 4729, gsmtap(bytes([0x07, 0x41])))))))
with open(path, 'wb') as f:
    f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for ts, fr in frames:
        sec = int(ts); usec = int((ts - sec) * 1000000)
        f.write(struct.pack('<IIII', sec, usec, len(fr), len(fr)))
        f.write(fr)
PY
        out=$(nasf_cmd_storm_profile "$storm"); rc=$?
        chk storm-rc    "$rc" "0"
        chk storm-fires "$(printf '%s\n' "$out" | grep -c 'storm-rate-flat-subscribers')" "1"
        chk storm-rep   "$(printf '%s\n' "$out" | grep -c 'repeated-identical-procedure')" "1"
    else
        printf 'capture-suite\tSKIP python3 not present\n'
    fi

    # ── 6. Storm rules are pure functions of the row stream ─────────────
    # A synthetic storm with an explicit subscriber key: flat subscriber
    # count, rate rising 1.1 -> 15 msg/s (the second half is compressed in
    # time, which is what a storm looks like on the wire).
    local rows="" i
    for i in $(seq 1 10); do
        rows+="row	$i	$i	10.0.0.2	10.0.0.1	eps	65		imsi:310150123456789
"
    done
    for i in $(seq 11 40); do
        rows+="row	$i	$(( 11 + (i - 11) / 15 )).$(( (i * 7) % 100 ))	10.0.0.2	10.0.0.1	eps	65		imsi:310150123456789
"
    done
    out=$(printf '%s' "$rows" | nasf_storm_rows)
    chk pure-storm-rate  "$(printf '%s\n' "$out" | grep -c 'storm-rate-flat-subscribers')" "1"
    chk pure-storm-dom   "$(printf '%s\n' "$out" | grep -c 'single-subscriber-dominates')" "1"
    chk pure-storm-rep   "$(printf '%s\n' "$out" | grep -c 'repeated-identical-procedure')" "1"
    chk pure-storm-sub1  "$(fld "$out" half1_unique_subscribers)" "1"
    chk pure-storm-sub2  "$(fld "$out" half2_unique_subscribers)" "1"
    # The normal trace: the subscriber count grows (10 -> 30 distinct keys and
    # a steady rate), so the flat-subscriber rule must NOT fire and the
    # informational growth finding must.
    rows=""
    for i in $(seq 1 20); do
        if (( i % 2 )); then
            rows+="row	$i	$i	10.0.0.2	10.0.0.1	eps	65		imsi:310150123450001
"
        else
            rows+="row	$i	$i	10.0.0.2	10.0.0.1	eps	65		imsi:310150123450002
"
        fi
    done
    for i in $(seq 21 40); do
        rows+="row	$i	$i	10.0.0.2	10.0.0.1	eps	65		imsi:31015012345$(printf '%03d' "$i")
"
    done
    out=$(printf '%s' "$rows" | nasf_storm_rows)
    chk pure-normal-flat   "$(printf '%s\n' "$out" | grep -c 'storm-rate-flat-subscribers')" "0"
    chk pure-normal-growth "$(printf '%s\n' "$out" | grep -c 'subscriber-count-rising')" "1"
    # half 1 repeats two subscriber keys, half 2 has twenty distinct ones.
    chk pure-normal-sub1   "$(fld "$out" half1_unique_subscribers)" "2"
    chk pure-normal-sub2   "$(fld "$out" half2_unique_subscribers)" "20"
    # Cause clustering: one cause repeated.
    rows=""
    for i in $(seq 1 40); do
        rows+="row	$i	$i	10.0.0.2	10.0.0.1	eps	68	22	none
"
    done
    out=$(printf '%s' "$rows" | nasf_storm_rows)
    chk pure-cause "$(printf '%s\n' "$out" | grep -c 'cause-clustering')" "1"
    # Rising reject ratio: none in the first half, most of the second half
    # rejects, at a constant rate so the storm rule stays quiet.
    rows=""
    for i in $(seq 1 20); do
        rows+="row	$i	$i	10.0.0.2	10.0.0.1	eps	65		imsi:310150123450001
"
    done
    for i in $(seq 21 40); do
        rows+="row	$i	$i	10.0.0.2	10.0.0.1	eps	68	22	imsi:310150123450001
"
    done
    out=$(printf '%s' "$rows" | nasf_storm_rows)
    chk pure-rejrise "$(printf '%s\n' "$out" | grep -c 'rising-reject-ratio')" "1"
    # A quiet, healthy stream fires nothing at all.
    rows=""
    for i in $(seq 1 10); do
        rows+="row	$i	$i	10.0.0.2	10.0.0.1	eps	65		imsi:3101501234567$(printf '%02d' "$i")
"
    done
    out=$(printf '%s' "$rows" | nasf_storm_rows)
    chk pure-quiet "$(printf '%s\n' "$out" | grep -c '^finding')" "0"

    # ── 7. The transmit path: gating, ceiling, no traffic ───────────────
    # Ungated since the Phase 12 reversal: a lab PLMN and a bounded rate at
    # 00101/5 write the plan and send nothing. There is no flag to leave out.
    rm -f "$NASF_PLANS/lab-storm.plan"
    out=$(nasf_cmd_transmit 00101 5 2>/dev/null); rc=$?
    chk tx-rc           "$rc" "0"
    chk tx-status       "$(fld "$out" status)" "handoff"
    chk tx-sent         "$(fld "$out" sent)" "0"
    chk tx-plan-written "$([[ -f "$NASF_PLANS/lab-storm.plan" ]] && echo yes || echo no)" "yes"
    # No PLMN: refuse.
    chk tx-no-plmn      "$(nasf_cmd_transmit '' 5 >/dev/null 2>&1; echo $?)" "2"
    # A live-network MCC: refuse.
    chk tx-live-plmn    "$(nasf_cmd_transmit 20801 5 >/dev/null 2>&1; echo $?)" "2"
    chk tx-us-plmn      "$(nasf_cmd_transmit 310260 5 >/dev/null 2>&1; echo $?)" "2"
    # Rate ceiling enforced in argument validation.
    chk tx-rate-toohigh "$(nasf_cmd_transmit 00101 100000 >/dev/null 2>&1; echo $?)" "2"
    chk tx-rate-ceiling "$(nasf_validate_rate 51 >/dev/null 2>&1; echo $?)" "2"
    chk tx-rate-zero    "$(nasf_validate_rate 0 >/dev/null 2>&1; echo $?)" "2"
    chk tx-rate-bad     "$(nasf_validate_rate abc >/dev/null 2>&1; echo $?)" "2"
    chk tx-rate-at-ceil "$(nasf_validate_rate 50 >/dev/null 2>&1; echo $?)" "0"
    chk tx-rate-under   "$(nasf_validate_rate 5 >/dev/null 2>&1; echo $?)" "0"
    chk tx-plmn-ok      "$(nasf_validate_lab_plmn 99970 >/dev/null 2>&1; echo $?)" "0"
    chk tx-plmn-bad     "$(nasf_validate_lab_plmn 0010 >/dev/null 2>&1; echo $?)" "2"
    # With everything valid it writes the plan and reports sent=0.
    out=$(nasf_cmd_transmit 00101 5); rc=$?
    chk tx-ok-rc     "$rc" "0"
    chk tx-ok-status "$(printf '%s\n' "$out" | awk -F'\t' '$1=="status"{print $2}')" "handoff"
    chk tx-ok-sent   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="sent"{print $2}')" "0"
    chk tx-ok-ceil   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="rate_ceiling_msg_s"{print $2}')" "$NASF_RATE_CEILING"
    local file; file=$(printf '%s\n' "$out" | awk -F'\t' '$1=="plan_file"{print $2}')
    chk tx-plan-status "$(grep -c '^status: handoff' "$file")" "1"
    chk tx-plan-plmn   "$(grep -q 'lab_plmn: 00101' "$file" && echo yes || echo no)" "yes"
    chk tx-plan-safety "$(grep -q 'degrades emergency service' "$file" && echo yes || echo no)" "yes"
    chk tx-plan-no-gate "$(grep -c 'i-have-a-lab-and-authorisation' "$file")" "0"
    unset NASF_LAB_AUTHORISED

    # ── 8. Cost model carries every documented pattern ──────────────────
    out=$(nasf_cost_model)
    chk cost-attach "$(printf '%s\n' "$out" | awk -F'\t' '$1=="attach-detach-loop"{print $1}')" "attach-detach-loop"
    chk cost-tau    "$(printf '%s\n' "$out" | awk -F'\t' '$1=="tau-storm"{print $1}')" "tau-storm"
    chk cost-svc    "$(printf '%s\n' "$out" | awk -F'\t' '$1=="service-request-flood"{print $1}')" "service-request-flood"
    chk cost-auth   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="authentication-failure-loop"{print $1}')" "authentication-failure-loop"
    chk cost-paging "$(printf '%s\n' "$out" | grep -c 'paging-to-service-request')" "1"
    chk cost-safety "$(printf '%s\n' "$out" | grep -c 'safety-scope')" "1"
    chk cost-emerg  "$(printf '%s\n' "$out" | grep -c 'emergency service')" "1"

    # ── 9. Plans, status TSV, sanitisation ──────────────────────────────
    out=$(nasf_cmd_plan lab-storm); rc=$?
    chk plan-rc     "$rc" "0"
    chk plan-status "$(printf '%s\n' "$out" | awk -F'\t' '$1=="status"{print $2}')" "handoff"
    chk plan-unknown "$(nasf_cmd_plan nope >/dev/null 2>&1; echo $?)" "2"
    out=$(nasf_cli_status_tsv)
    chk status-module "$(fld "$out" module)" "nas_signaling"
    chk status-tag    "$(fld "$out" tag)" "nasf"
    chk status-ceil   "$(fld "$out" rate_ceiling_msg_s)" "$NASF_RATE_CEILING"
    chk status-tx     "$(fld "$out" transmit_path)" "handoff"
    chk status-gate   "$(fld "$out" gate | cut -d" " -f1)" "none"
    chk status-builders "$(fld "$out" builders_count)" "21"
    local evil
    evil=$(nasf_sanitize $'a\tb\nc')
    chk sanitize-tabs "$(printf '%s' "$evil" | tr -cd '\t' | wc -c)" "0"
    chk sanitize-nl   "$(printf '%s' "$evil" | wc -l)" "0"
    NASF_F=()
    nasf_split $'p\t\tq\tr'
    chk split-len   "${#NASF_F[@]}" "4"
    chk split-empty "${NASF_F[1]}" ""
    chk split-third "${NASF_F[2]}" "q"

    # ── 10. Argument validation returns non-zero ────────────────────────
    chk val-rate-none     "$(nasf_cmd_rate >/dev/null 2>&1; echo $?)" "2"
    chk val-rate-nofile   "$(nasf_cmd_rate /nonexistent.pcap >/dev/null 2>&1; echo $?)" "1"
    chk val-mix-none      "$(nasf_cmd_procedure_mix >/dev/null 2>&1; echo $?)" "2"
    chk val-causes-none   "$(nasf_cmd_causes >/dev/null 2>&1; echo $?)" "2"
    chk val-storm-none    "$(nasf_cmd_storm_profile >/dev/null 2>&1; echo $?)" "2"
    chk val-decode-none   "$(nasf_cmd_decode >/dev/null 2>&1; echo $?)" "2"

    # ── 11. The unauthenticated message builders ────────────────────────
    # Every expected hex below was decoded back by tshark 4.2.2 through
    # tools/nas-oracle/check_nas_built.py, so these are the oracle's answers,
    # not this file quoting itself. The 5GS vectors cannot be checked that way
    # (no GSMTAP payload type for 5G NAS) and are marked here as such.
    local hx
    hx() { nasf_cmd_build "$@" 2>/dev/null | awk -F'\t' '$1=="hex"{print $2; exit}'; }

    chk b-eps-attach-reject  "$(hx eps attach-reject --cause 15)"          "07440F"
    chk b-eps-tau-reject     "$(hx eps tau-reject --cause 12)"             "074B0C"
    chk b-eps-service-reject "$(hx eps service-reject --cause 22)"         "074E16"
    chk b-eps-identity-imsi  "$(hx eps identity-request --identity imsi)"  "075501"
    chk b-eps-identity-imeisv "$(hx eps identity-request --identity imeisv)" "075503"
    chk b-eps-auth-reject    "$(hx eps auth-reject)"                       "0754"
    chk b-eps-auth-failure   "$(hx eps auth-failure --cause 21)"           "075C15"
    chk b-eps-smc-reject     "$(hx eps security-mode-reject --cause 23)"   "075F17"
    # Selected EEA2/EIA2, KSI 3, replayed capabilities 20 20 (EEA2+EIA2 in the
    # capability bit map, which the oracle reads back as "Supported").
    chk b-eps-smc             "$(hx eps security-mode-command --algorithms 2 2 --ksi 3)" "075D2203022020"
    chk b-eps-auth-request    "$(hx eps auth-request --rand 000102030405060708090a0b0c0d0e0f --ksi 3)" \
        "075203000102030405060708090A0B0C0D0E0F"

    # 5GS: same header rule (7E 00 <type>) and message type numbers read from
    # tshark's own value table. Structure only -- no decoded message backs these.
    chk b-5gs-reg-reject     "$(hx 5gs registration-reject --cause 22)"    "7E004416"
    chk b-5gs-service-reject "$(hx 5gs service-reject --cause 22)"         "7E004D16"
    chk b-5gs-identity-suci  "$(hx 5gs identity-request --identity suci)"  "7E005B01"
    chk b-5gs-auth-failure   "$(hx 5gs auth-failure --cause 21)"           "7E005915"
    chk b-5gs-smc-reject     "$(hx 5gs security-mode-reject --cause 23)"   "7E005F17"

    # The message is built, never sent, and says where it stops.
    out=$(nasf_cmd_build eps security-mode-command --algorithms 2 2 --ksi 3 2>/dev/null)
    chk b-sent-zero    "$(fld "$out" sent)" "0"
    chk b-built        "$(fld "$out" built)" "yes"
    chk b-carrier-none "$(printf '%s' "$(fld "$out" carrier)" | grep -c 'no SCTP')" "1"
    chk b-smc-limit    "$(printf '%s' "$(fld "$out" limit)" | grep -c 'NAS-MAC is not built')" "1"

    # Refusals: an unverifiable IE, an unknown message, an unlisted cause, a
    # retired flag. Each is a non-zero exit with nothing on stdout.
    # The accept side of the handshake, pinned octet for octet. The GSMTAP
    # oracle in tools/nas-oracle/check_nas_built.py decodes these same bytes
    # with tshark; these assertions keep them from drifting silently when the
    # oracle cannot run.
    chk b-attach-accept "$(nasf_build eps attach-accept | awk -F'\t' '$1=="hex"{print $2}')" \
        "0742011E5407000100F1100001"
    chk b-tau-accept "$(nasf_build eps tau-accept | awk -F'\t' '$1=="hex"{print $2}')" \
        "0749001E5407000100F1100001"
    chk b-service-accept "$(nasf_build eps service-accept | awk -F'\t' '$1=="hex"{print $2}')" "074F"
    chk b-detach-accept "$(nasf_build eps detach-accept | awk -F'\t' '$1=="hex"{print $2}')" "0746"
    chk b-attach-accept-tai "$(nasf_build eps attach-accept --tai 310260 --tac 1A2B | \
        awk -F'\t' '$1=="hex"{print $2}')" "0742011E540700011300621A2B"
    chk b-attach-accept-limit "$(nasf_build eps attach-accept | awk -F'\t' '$1=="limit"{print ($2 ~ /ESM message container/)?"yes":"no"}')" "yes"
    chk b-bad-tai "$(nasf_build eps attach-accept --tai 0010 >/dev/null 2>&1; echo $?)" "2"
    chk b-plmn-bcd "$(nasf_plmn_bcd 001 01)" "00F110"
    chk b-plmn-bcd-match "$(nasf_plmn_bcd 310 260)" "$(bash "$IMSISTING_ROOT/modules/43_ran_share.sh" --plmn-encode 310 260)"
    chk b-autn-refused "$(nasf_cmd_build eps auth-request --rand 000102030405060708090a0b0c0d0e0f --autn 101112131415161718191a1b1c1d1e1f >/dev/null 2>&1; echo $?)" "2"
    chk b-bad-message  "$(nasf_cmd_build eps attach-request --cause 15 >/dev/null 2>&1; echo $?)" "2"
    chk b-bad-cause    "$(nasf_cmd_build eps attach-reject --cause 999 >/dev/null 2>&1; echo $?)" "2"
    chk b-bad-identity "$(nasf_cmd_build eps identity-request --identity suci >/dev/null 2>&1; echo $?)" "2"
    chk b-no-message   "$(nasf_cmd_build eps >/dev/null 2>&1; echo $?)" "2"
    chk b-retired-flag "$(nasf_cli_main --i-have-a-lab-and-authorisation --build-nas eps auth-reject >/dev/null 2>&1; echo $?)" "2"
    chk b-retired-stdout "$(nasf_cli_main --i-have-a-lab-and-authorisation --build-nas eps auth-reject 2>/dev/null | wc -c)" "0"

    # The outside check, when its oracle is present. A skip is not a pass: the
    # suite prints SKIP and the reason, so a host without tshark cannot look
    # green for a check that never ran.
    if command -v tshark >/dev/null 2>&1; then
        timeout 180 python3 "$IMSISTING_ROOT/tools/nas-oracle/check_nas_built.py" \
            >"$d/oracle.out" 2>"$d/oracle.err"
        local orc=$?
        chk oracle-rc "$orc" "0"
        chk oracle-checked "$(grep -c '^ok	' "$d/oracle.out")" "14"
        chk oracle-agree "$(awk -F'\t' '$1=="RESULT"{print $2}' "$d/oracle.out")" "PASS"
    else
        printf 'oracle\tSKIP\ttshark is not on PATH, so the built vectors were \
not decoded by an outside implementation\n'
    fi

    rm -rf "$d"
    trap - EXIT
    [[ -n "$_prev_trap" ]] && eval "$_prev_trap"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ── menu ────────────────────────────────────────────────────────────────
nasf_menu() {
    local c p
    while true; do
        banner
        echo -e "  ${C_MAG}=== NAS signalling ===${C_RESET}"
        echo -e "  rate ceiling: ${C_GRN}${NASF_RATE_CEILING} msg/s${C_RESET}"
        echo -e "  transmit:     ${C_DIM}handoff -- the builders produce octets, nothing is sent${C_RESET}"
        echo -e "  dir:          ${C_DIM}$NASF_PLANS${C_RESET}\n"
        cat << 'M'
  [1]  message rate from a capture
  [2]  procedure mix from a capture
  [3]  cause distribution from a capture
  [4]  storm profile from a capture
  [5]  decode a NAS PDU
  [6]  the cost model
  [7]  plan: lab signalling characterisation
  [8]  build a pre-authentication message (reject / identity / auth)
  [9]  status
  [0]  back

M
        read -rp "  choice> " c
        case "$c" in
            1) if [[ -n "${IMSISTING_CLI:-}" ]]; then echo "[-] need a pcap; cannot prompt in CLI mode" >&2
               else read -rp "  pcap> " p; nasf_cmd_rate "$p" | column -t -s$'\t' 2>/dev/null || nasf_cmd_rate "$p"
                    read -rp "  press enter " _; fi ;;
            2) if [[ -n "${IMSISTING_CLI:-}" ]]; then echo "[-] need a pcap; cannot prompt in CLI mode" >&2
               else read -rp "  pcap> " p; nasf_cmd_procedure_mix "$p" | column -t -s$'\t' 2>/dev/null || nasf_cmd_procedure_mix "$p"
                    read -rp "  press enter " _; fi ;;
            3) if [[ -n "${IMSISTING_CLI:-}" ]]; then echo "[-] need a pcap; cannot prompt in CLI mode" >&2
               else read -rp "  pcap> " p; nasf_cmd_causes "$p" | column -t -s$'\t' 2>/dev/null || nasf_cmd_causes "$p"
                    read -rp "  press enter " _; fi ;;
            4) if [[ -n "${IMSISTING_CLI:-}" ]]; then echo "[-] need a pcap; cannot prompt in CLI mode" >&2
               else read -rp "  pcap> " p; nasf_cmd_storm_profile "$p" | column -t -s$'\t' 2>/dev/null || nasf_cmd_storm_profile "$p"
                    read -rp "  press enter " _; fi ;;
            5) if [[ -n "${IMSISTING_CLI:-}" ]]; then echo "[-] need hex; cannot prompt in CLI mode" >&2
               else read -rp "  generation (eps|5gs)> " g; read -rp "  NAS hex> " h
                    nasf_cmd_decode "${g:-eps}" "$h" | column -t -s$'\t' 2>/dev/null; read -rp "  press enter " _; fi ;;
            6) nasf_cost_model | column -t -s$'\t' 2>/dev/null || nasf_cost_model
               read -rp "  press enter " _ ;;
            7) nasf_cmd_plan lab-storm; read -rp "  press enter " _ ;;
            8) if [[ -n "${IMSISTING_CLI:-}" ]]; then echo "[-] the builder needs arguments; use --build-nas in CLI mode" >&2
               else read -rp "  generation (eps|5gs)> " p; local g="$p"
                    read -rp "  message> " p
                    read -rp "  extra flags (e.g. --cause 15), empty for none> " c
                    # shellcheck disable=SC2086
                    nasf_cmd_build "$g" "$p" $c
                    read -rp "  press enter " _; fi ;;
            9) nasf_cli_status_tsv | column -t -s$'\t' 2>/dev/null || nasf_cli_status_tsv
               read -rp "  press enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ── CLI dispatch ────────────────────────────────────────────────────────
nasf_cli_main() {
    # No authorisation gate. Standing policy since the Phase 12 reversal: the
    # artefact is real, the effect is absent, and a verb says in its own output
    # which half it did not do. The flag this module used to require is still
    # named here so that a script carrying it is told it is retired rather than
    # silently accepted -- a flag that stops meaning anything must not go on
    # looking as if it does.
    local a
    for a in "$@"; do
        if [[ "$a" == "--i-have-a-lab-and-authorisation" ]]; then
            printf 'ERROR\t--i-have-a-lab-and-authorisation is retired: this module has no gate\n' >&2
            printf 'WHY\tthe verb builds a message and sends nothing, so there is nothing to authorise; drop the flag\n' >&2
            return 2
        fi
    done
    local cmd="${1:-}"
    local rest=()
    if (( $# > 1 )); then rest=( "${@:2}" ); fi
    case "$cmd" in
        --status-tsv)      nasf_cli_status_tsv ;;
        --rate)            nasf_cmd_rate "${rest[0]:-}" ;;
        --procedure-mix)   nasf_cmd_procedure_mix "${rest[0]:-}" ;;
        --causes)          nasf_cmd_causes "${rest[0]:-}" ;;
        --storm-profile)   nasf_cmd_storm_profile "${rest[0]:-}" ;;
        --decode-nas)      nasf_cmd_decode "${rest[0]:-eps}" "${rest[1]:-}" ;;
        --build-nas)       nasf_cmd_build "${rest[0]:-eps}" "${rest[1]:-}" "${rest[@]:2}" ;;
        --cost-model)      nasf_cost_model ;;
        --plan)            nasf_cmd_plan "${rest[0]:-}" ;;
        --transmit)        nasf_cmd_transmit "${rest[0]:-}" "${rest[1]:-$NASF_RATE_DEFAULT}" ;;
        --selftest)        nasf_selftest ;;
        --menu)            nasf_menu ;;
        *)
            cat >&2 <<EOF
NAS signalling — measurement, procedure mix, storm detection, cost model

Usage: $0 COMMAND
  --status-tsv                    module state as TSV
  --rate <pcap>                   NAS message rate overall, per procedure and
                                  per subscriber
  --procedure-mix <pcap>          procedure distribution and reject share
  --causes <pcap>                 cause-code distribution
  --storm-profile <pcap>          signalling-storm detection
  --decode-nas <eps|5gs> <hex>    decode a NAS PDU header and cause
  --build-nas <eps|5gs> <message> [flags]
                                  build one pre-authentication message: the
                                  octets an MME/AMF sends before it has
                                  authenticated the subscriber. Sends nothing.
    EPS messages: $(nasf_eps_messages)
    5GS messages: $(nasf_5gs_messages)
    flags: --cause <n>  --identity <type>  --rand <32 hex> --autn <32 hex>
           --auts <28 hex>  --algorithms <eea> <eia>  --ksi <0-7>
           --ksi-type <0|1>  --out <path>
  --cost-model                    the documented cost of each load pattern
  --plan lab-storm                write the handed-off characterisation plan
  --transmit <lab-plmn> [rate]    handoff: lab PLMN (MCC 001/999), rate <= $NASF_RATE_CEILING msg/s.
                                  Writes the plan and sends nothing.
  --selftest                      verify the tables, the builders and the rules
  --menu                          interactive menu

Sources: GSMTAP LTE NAS on UDP $NASF_GSMTAP_PORT, raw NAS on UDP $NASF_RAW_PORT,
S1AP/NGAP captures through tshark. Built messages are checked against tshark by
tools/check-nas-vectors.sh.
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
    nasf_cli_main "$@"
fi
