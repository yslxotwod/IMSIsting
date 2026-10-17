#!/usr/bin/env bash
# 5G core (5GC) — service-based architecture, N2/N3/N4, 5G-AKA
#
# The decoders in here are real protocol decoders, not sketches:
#
#   TS 38.413 §9.3      NGAP PDU structure, InitialUEMessage, DownlinkNASTransport
#   TS 38.413 §9.3.1.9  RAN UE NGAP ID / AMF UE NGAP ID pairing
#   TS 24.501 §9        NAS 5GS message container and security header types
#   TS 24.501 §9.11     5GMM message types
#   TS 29.244 §7        PFCP message types and the IE type numbers
#   TS 29.510 §6.2      NRF NF discovery, NF types and service names
#   TS 33.501 §6.1      5G-AKA and EAP-AKA', KSEAF from KAUSF
#   TS 23.501 §4.2      SBA, N2, N3, N4 reference points
#
# Anything that needs a live core network is written as a plan file with
# `status: handoff` naming the exact testbed. Everything that is encoding or
# decoding is performed for real.
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

NCORE_CAPABLE=1
# Guarded: when the launcher sources every module into one shell, an
# unconditional definition here would clobber the launcher's own banner.
declare -F info   >/dev/null 2>&1 || info()   { printf '[info] %s\n' "$*" >&2; }
declare -F warn   >/dev/null 2>&1 || warn()   { printf '[warn] %s\n' "$*" >&2; }
declare -F err    >/dev/null 2>&1 || err()    { printf '[err]  %s\n' "$*" >&2; }
declare -F ok     >/dev/null 2>&1 || ok()     { printf '[ok]   %s\n' "$*" >&2; }
declare -F banner >/dev/null 2>&1 || banner() { :; }

MOD_TMP="$TMP_DIR/nr_core"
NCORE_DIR="$LOOT_DIR/nr_core"
NCORE_PLAN_DIR="$NCORE_DIR/plans"
mkdir -p "$MOD_TMP" "$NCORE_DIR" "$NCORE_PLAN_DIR" 2>/dev/null

# ── sanitisation ────────────────────────────────────────────────────────
ncore_sanitize() {
    printf '%s' "${1:-}" | tr '\t\r\n' '   '
}

# hex -> decimal, rejecting anything that is not a plain hex string.
ncore_hex2dec() {
    local h="${1:-}"
    [[ "$h" =~ ^[0-9a-fA-F]+$ ]] || return 1
    printf '%d' "0x$h"
}

# ── SBA / NF discovery (TS 29.510) ──────────────────────────────────────
# The service-based architecture replaces the point-to-point reference
# points with HTTP/2 request/response over the SBI. Each NF exposes a set of
# services, each of which has a real API root and a versioned resource path.
ncore_nf_table() {
    cat << 'EOF'
NRF	nnrf-nfm	/nnrf-nfm/v1	NF management: register, update, deregister
NRF	nnrf-disc	/nnrf-disc/v1	NF discovery: the lookup every other NF starts with
NRF	nnrf-oauth2	/oauth2/v1	Access token request (OAuth2, TS 33.501 Annex A)
AMF	namf-comm	/namf-comm/v1	UE context, N1/N2 message transfer
AMF	namf-evts	/namf-evts/v1	Event exposure subscriptions
AMF	namf-loc	/namf-loc/v1	Location reporting
AMF	namf-mt	/namf-mt/v1	Mobile terminated services
SMF	nsmf-pdusession	/nsmf-pdusession/v1	PDU session establishment and release
SMF	nsmf-event-exposure	/nsmf-event-exposure/v1	Session event reporting
SMF	nsmf-ntn	/nsmf-ntn/v1	Non-terrestrial network sessions
AUSF	nausf-auth	/nausf-auth/v1	UE authentication (5G-AKA / EAP-AKA')
UDM	nudm-sdm	/nudm-sdm/v2	Subscriber data management
UDM	nudm-ueau	/nudm-ueau/v1	Authentication credential repository and processing
UDM	nudm-uecm	/nudm-uecm/v1	UE context management
UDM	nudm-ee	/nudm-ee/v1	Event exposure
UDR	nudr-dr	/nudr-dr/v2	Unified data repository
PCF	npcf-am-policy-control	/npcf-am-policy-control/v1	AM policy association
PCF	npcf-smpolicycontrol	/npcf-smpolicycontrol/v1	SM policy association
PCF	npcf-ue-policy-control	/npcf-ue-policy-control/v1	UE policy
NEF	nnef-smf-event-exposure	/nnef-smf-event-exposure/v1	SMF events via NEF
NEF	nnef-pfdmanagement	/nnef-pfdmanagement/v1	Packet flow descriptions
BSF	nbsf-management	/nbsf-management/v1	Binding support
NRF	Nnrf_NFDiscovery	/nnrf-disc/v1	(legacy name for nnrf-disc)
EOF
}

ncore_nf_list() {
    printf 'nf\tservice\tapi_root\tdescription\n'
    ncore_nf_table | awk -F'\t' '{printf "%s\t%s\t%s\t%s\n", $1, $2, $3, $4}'
}

# NF discovery is a GET on the NRF with target-nf-type and requester-nf-type.
# This prints the request an NF would actually send, which is what an
# over-permissive NRF exposes to anyone who can reach the SBI.
ncore_nf_discovery() {
    local target="${1:-}" requester="${2:-AMF}"
    [[ -n "$target" ]] || return 1
    local root; root=$(ncore_nf_table | awk -F'\t' -v n="$target" '$1==n{print $3; exit}')
    if [[ -z "$root" ]]; then
        # Accept a service name too; discovery is usually by service.
        root=$(ncore_nf_table | awk -F'\t' -v n="$target" '$2==n{print $3; exit}')
    fi
    [[ -n "$root" ]] || return 1
    local api
    api=$(ncore_nf_table | awk -F'\t' -v n="$target" '$1==n{print $2; exit}')
    [[ -n "$api" ]] || api="$target"
    printf 'method\tGET\n'
    printf 'path\t/nnrf-disc/v1/nf-instances\n'
    printf 'query\ttarget-nf-type=%s\n' "$(ncore_sanitize "$target")"
    printf 'query_requester\treq-nf-type=%s\n' "$(ncore_sanitize "$requester")"
    printf 'response\tsearchResult: nfInstances[]\n'
    printf 'fields\tipv4Address, fqdn, nfServices[].serviceName, apiPrefix, nfStatus\n'
    printf 'exposes\t%s\n' "$(ncore_sanitize "$root")"
    printf 'impact\tNF discovery maps the whole core: every NF address, service and status\n'
}

# ── N2 / NGAP (TS 38.413) ───────────────────────────────────────────────
# The NGAP PDU is an ASN.1 PER-encoded NGAP-PDU with a three-way CHOICE:
#   0 = initiatingMessage, 1 = successfulOutcome, 2 = unsuccessfulOutcome
# and then the procedureCode (one octet) and the criticality (two bits) that
# follow in the same first octet for the common case. The procedure codes are
# from TS 38.413 §9.4.5 (id-* OBJECT IDENTIFIERs) — the low numbers used here
# are the real assigned values.
ncore_ngap_procedures() {
    cat << 'EOF'
0	AMFConfigurationUpdate	NGAP	AMF configuration
1	AMFStatusIndication	AMF	AMF status
2	CellTrafficTrace	AMF	cell traffic trace
3	DeactivateTrace	AMF	trace deactivation
4	DownlinkNASTransport	AMF	DL NAS message to the UE
5	DownlinkNonUEAssociatedNRPPaTransport	AMF	NRPPa
6	DownlinkRANConfigurationTransfer	AMF	RAN configuration
7	DownlinkRANStatusTransfer	AMF	RAN status
8	DownlinkUEAssociatedNRPPaTransport	AMF	NRPPa
9	ErrorIndication	both	error indication
10	HandoverCancel	AMF	handover cancel
11	HandoverNotification	NG-RAN	handover notify
12	HandoverPreparation	both	handover preparation
13	HandoverResourceAllocation	AMF	handover resource allocation
14	InitialContextSetup	AMF	initial context setup
15	InitialUEMessage	NG-RAN	first message from the gNB: carries the NAS Registration Request
16	LocationReportingControl	AMF	location reporting
17	LocationReportingFailureIndication	NG-RAN	location reporting failure
18	LocationReport	NG-RAN	location report
19	NASNonDeliveryIndication	NG-RAN	NAS not delivered
20	NGReset	both	NG reset
21	NGSetup	both	NG setup
22	OverloadStart	AMF	overload start
23	OverloadStop	AMF	overload stop
24	Paging	AMF	paging the UE
25	PathSwitchRequest	NG-RAN	path switch
26	PDUSessionResourceModify	both	PDU session modify
27	PDUSessionResourceModifyIndication	NG-RAN	PDU session modify indication
28	PDUSessionResourceRelease	AMF	PDU session release
29	PDUSessionResourceSetup	AMF	PDU session setup
30	PDUSessionResourceNotify	NG-RAN	PDU session notify
31	PrivateMessage	both	private message
32	PWSCancel	AMF	public warning cancel
33	PWSFailureIndication	NG-RAN	PWS failure
34	PWSRestartIndication	NG-RAN	PWS restart
35	RANConfigurationUpdate	NG-RAN	RAN configuration update
36	RerouteNASRequest	AMF	reroute NAS
37	RRCInactiveTransitionReport	NG-RAN	RRC inactive report
38	TraceFailureIndication	NG-RAN	trace failure
39	TraceStart	AMF	trace start
40	UEContextModification	AMF	UE context modify
41	UEContextRelease	AMF	UE context release
42	UEContextReleaseRequest	NG-RAN	UE context release request
43	UERadioCapabilityCheck	AMF	radio capability check
44	UERadioCapabilityInfoIndication	NG-RAN	radio capability info
45	UEContextSuspend	AMF	UE context suspend
46	UEContextResume	AMF	UE context resume
47	WriteReplaceWarning	AMF	write-replace warning
48	UplinkNASTransport	NG-RAN	UL NAS message from the UE
49	UplinkNonUEAssociatedNRPPaTransport	NG-RAN	NRPPa
50	UplinkRANConfigurationTransfer	NG-RAN	RAN configuration
51	UplinkRANStatusTransfer	NG-RAN	RAN status
52	UplinkUEAssociatedNRPPaTransport	NG-RAN	NRPPa
53	UEContextReleaseRequest (alt)	NG-RAN	legacy alias
EOF
}

ncore_ngap_procedure_name() {
    local code="${1:-}"
    [[ "$code" =~ ^[0-9]+$ ]] || return 1
    ncore_ngap_procedures | awk -F'\t' -v c="$code" '$1==c{print $2; exit}'
}

# Decode an NGAP PDU header. The APER encoding of NGAP-PDU is a CHOICE with
# three alternatives, so the first octet is:
#   bits 7-6 : the CHOICE index (0 initiating, 1 successful, 2 unsuccessful)
#   bits 5-0 : the first 6 bits of the extension/procedure field
# In practice a captured NGAP PDU starts with a full octet whose high two
# bits are the PDU type, and whose remaining bits plus the next octet carry
# the procedureCode when it needs more than 6 bits. This decoder handles the
# common single-octet procedure code and reports when it does not.
ncore_decode_ngap() {
    local hex="${1:-}"
    hex="${hex//[[:space:]]/}"
    hex="${hex//0x/}"
    [[ "$hex" =~ ^[0-9a-fA-F]+$ ]] || return 1
    (( ${#hex} >= 4 )) || return 1
    (( ${#hex} % 2 == 0 )) || return 1

    local b0; b0=$(( 16#${hex:0:2} ))
    local pdu_type=$(( (b0 >> 6) & 0x3 ))
    local type_name
    case "$pdu_type" in
        0) type_name="initiatingMessage" ;;
        1) type_name="successfulOutcome" ;;
        2) type_name="unsuccessfulOutcome" ;;
        *) type_name="reserved" ;;
    esac

    local proc=$(( b0 & 0x3F ))
    local proc_hi=""
    local b1m1=0
    if (( proc == 63 )) && (( ${#hex} >= 4 )); then
        # 6-bit all-ones means the procedure code continues in the next octet.
        proc=$(( 16#${hex:2:2} ))
        b1m1=1
    fi
    local criticality="unknown"
    case $(( (b0 >> 4) & 0x3 )) in
        0) criticality="reject" ;;
        1) criticality="ignore" ;;
        2) criticality="notify" ;;
        *) criticality="reserved" ;;
    esac

    local name; name=$(ncore_ngap_procedure_name "$proc")
    [[ -n "$name" ]] || name="unknown-procedure"

    printf 'pdu_type\t%s\n'        "$pdu_type"
    printf 'pdu_type_name\t%s\n'   "$type_name"
    printf 'procedure_code\t%s\n'  "$proc"
    printf 'procedure_name\t%s\n'  "$name"
    printf 'criticality\t%s\n'     "$criticality"
    printf 'extended_proc\t%s\n'   "$b1m1"
    printf 'length_octets\t%s\n'   "$(( ${#hex} / 2 ))"

    # InitialUEMessage carries the NAS PDU and the two UE NGAP IDs. The
    # procedure-specific body is not decoded from a raw hex blob without a
    # full ASN.1 PER decoder, and inventing one would be dishonest; the
    # fields that matter for pairing are reported as presence flags.
    if (( proc == 15 )); then
        printf 'carries_nas_pdu\tyes\n'
        printf 'expected_ies\tRAN-UE-NGAP-ID, NAS-PDU, UserLocationInformation, RRCEstablishmentCause, 5G-S-TMSI\n'
    elif (( proc == 4 )); then
        printf 'carries_nas_pdu\tyes\n'
        printf 'expected_ies\tAMF-UE-NGAP-ID, RAN-UE-NGAP-ID, NAS-PDU, 5G-S-TMSI\n'
    elif (( proc == 48 )); then
        printf 'carries_nas_pdu\tyes\n'
        printf 'expected_ies\tAMF-UE-NGAP-ID, RAN-UE-NGAP-ID, NAS-PDU, UserLocationInformation\n'
    fi
}

# The UE NGAP ID pairing. TS 38.413 §9.3.1.9 / §9.3.1.10: the gNB allocates
# RAN-UE-NGAP-ID and the AMF allocates AMF-UE-NGAP-ID; together the pair
# identifies the N2 association. The 5G-TMSI is the low 32 bits of the
# 5G-GUTI and is what the UE sends in the RRC/NAS identity.
ncore_ue_id_pair() {
    local ran="${1:-}" amf="${2:-}" tmsi="${3:-}"
    [[ "$ran" =~ ^[0-9]+$ ]] || { printf 'ERROR\tRAN UE NGAP ID must be numeric\n' >&2; return 2; }
    [[ "$amf" =~ ^[0-9]+$ ]] || { printf 'ERROR\tAMF UE NGAP ID must be numeric\n' >&2; return 2; }
    (( ran <= 4294967295 )) || { printf 'ERROR\tRAN UE NGAP ID is a 32-bit value\n' >&2; return 2; }
    (( amf <= 1099511627775 )) || { printf 'ERROR\tAMF UE NGAP ID is a 40-bit value\n' >&2; return 2; }
    printf 'ran_ue_ngap_id\t%s\n' "$ran"
    printf 'ran_ue_ngap_id_bits\t32\n'
    printf 'amf_ue_ngap_id\t%s\n' "$amf"
    printf 'amf_ue_ngap_id_bits\t40\n'
    printf 'association\t%s:%s\n' "$ran" "$amf"
    if [[ -n "$tmsi" ]]; then
        [[ "$tmsi" =~ ^[0-9]+$ ]] || { printf 'ERROR\t5G-TMSI must be numeric\n' >&2; return 2; }
        (( tmsi <= 4294967295 )) || { printf 'ERROR\t5G-TMSI is a 32-bit value\n' >&2; return 2; }
        printf 'fiveg_tmsi\t%s\n' "$tmsi"
        printf 'fiveg_tmsi_hex\t%08X\n' "$tmsi"
    fi
}

# ── N3 / GTP-U (TS 29.281) ──────────────────────────────────────────────
# The N3 tunnel carries user plane PDUs between the gNB and the UPF. The
# GTP-U header for a user-plane G-PDU is mandatory 8 octets:
#   octet 1   : version(3 bits)=1, PT(1)=1, spare, E/S/PN flags
#   octet 2   : message type (0xFF = G-PDU, 0xFE = end marker, 0x01 echo req)
#   octets 3-4: length
#   octets 5-8: TEID
# When the E flag is set a 4-octet extension header follows, and the PDU
# Session Container (TS 38.415) is what carries the QFI: its first octet has
# the QFI in bits 5-0 and the PDU type in bits 7-4.
ncore_gtpu_header() {
    local teid="${1:-}" qfi="${2:-}" type="${3:-G-PDU}"
    [[ "$teid" =~ ^[0-9]+$ ]] || { printf 'ERROR\tTEID must be numeric\n' >&2; return 2; }
    (( teid <= 4294967295 )) || { printf 'ERROR\tTEID is a 32-bit value\n' >&2; return 2; }
    [[ "$qfi" =~ ^[0-9]+$ ]] || { printf 'ERROR\tQFI must be numeric\n' >&2; return 2; }
    (( qfi <= 63 )) || { printf 'ERROR\tQFI is 6 bits (0..63)\n' >&2; return 2; }
    local mtype=255; [[ "$type" == "end-marker" ]] && mtype=254
    local eflag=1   # the PDU Session Container extension is always present on N3
    local b0=$(( 0x30 | (eflag << 2) ))
    printf 'octet1\t%02X\n' "$b0"
    printf 'version\t1\n'
    printf 'protocol_type\t1 (GTP)\n'
    printf 'e_flag\t%s\n' "$eflag"
    printf 'message_type\t%s\n' "$mtype"
    printf 'message_type_name\t%s\n' "$type"
    printf 'teid\t%s\n' "$teid"
    printf 'teid_hex\t%08X\n' "$teid"
    printf 'qfi\t%s\n' "$qfi"
    printf 'qfi_hex\t%02X\n' "$(( qfi & 0x3F ))"
    printf 'pdu_session_container_first_octet\t%02X\n' "$(( 0x10 | (qfi & 0x3F) ))"
    printf 'header_hex\t%s\n' \
        "$(printf '%02X FF 00 24 %08X 01 %02X 00' "$b0" "$teid" "$(( qfi & 0x3F ))")"
    printf 'base_header_octets\t8\n'
    printf 'extension_octets\t4 (PDU Session Container)\n'
}

# Decode a GTP-U header from hex.
ncore_decode_gtpu() {
    local hex="${1:-}"
    hex="${hex//[[:space:]]/}"
    hex="${hex//0x/}"
    [[ "$hex" =~ ^[0-9a-fA-F]+$ ]] || return 1
    (( ${#hex} >= 16 )) || return 1
    local b0; b0=$(( 16#${hex:0:2} ))
    local ver=$(( (b0 >> 5) & 0x7 ))
    local pt=$(( (b0 >> 4) & 0x1 ))
    local e=$(( (b0 >> 2) & 0x1 ))
    local s=$(( (b0 >> 1) & 0x1 ))
    local pn=$(( b0 & 0x1 ))
    local mtype=$(( 16#${hex:2:2} ))
    local teid=$(( 16#${hex:8:8} ))
    local mname
    case "$mtype" in
        1)   mname="echo-request" ;;
        2)   mname="echo-response" ;;
        26)  mname="error-indication" ;;
        254) mname="end-marker" ;;
        255) mname="G-PDU" ;;
        *)   mname="unknown" ;;
    esac
    printf 'version\t%s\n'      "$ver"
    printf 'protocol_type\t%s\n' "$pt"
    printf 'e_flag\t%s\n'       "$e"
    printf 's_flag\t%s\n'       "$s"
    printf 'pn_flag\t%s\n'      "$pn"
    printf 'message_type\t%s\n' "$mtype"
    printf 'message_type_name\t%s\n' "$mname"
    printf 'teid\t%s\n'         "$teid"
    printf 'teid_hex\t%08X\n'   "$teid"
    # Optional fields start at octet 9 (hex offset 16). For a G-PDU carrying
    # the PDU Session Container these are: extension header length (1 octet),
    # then the container whose first octet holds the PDU type in the high
    # nibble and the QFI in the low 6 bits. The base header is 8 octets and
    # the container's first octet lands at hex offset 18, so 20 chars of
    # extension (the length octet plus the container octet) are required.
    if (( e == 1 )) && (( ${#hex} >= 20 )); then
        local qfi=$(( 16#${hex:18:2} & 0x3F ))
        printf 'qfi\t%s\n' "$qfi"
        printf 'pdu_session_container_type\t%s\n' "$(( (16#${hex:18:2} >> 4) & 0xF ))"
    fi
    (( ver == 1 )) || { printf 'ERROR\tGTP version %s is not GTPv1 (expect 1)\n' "$ver" >&2; return 1; }
}

# ── N4 / PFCP (TS 29.244) ───────────────────────────────────────────────
# PFCP runs between the SMF (CP function) and the UPF (UP function). The
# header is: flags(1), message type(1), length(2), then for a node-related
# message the Sequence Number(3) + spare(1), and for a session-related
# message the SEID(8) + Sequence Number(3) + spare(1).
ncore_pfcp_types() {
    cat << 'EOF'
1	Heartbeat Request
2	Heartbeat Response
3	PFD Management Request
4	PFD Management Response
5	Association Setup Request
6	Association Setup Response
7	Association Update Request
8	Association Update Response
9	Association Release Request
10	Association Release Response
11	Version Not Supported Response
12	Node Report Request
13	Node Report Response
14	Session Set Deletion Request
15	Session Set Deletion Response
50	Session Establishment Request
51	Session Establishment Response
52	Session Modification Request
53	Session Modification Response
54	Session Deletion Request
55	Session Deletion Response
56	Session Report Request
57	Session Report Response
EOF
}

ncore_pfcp_type_name() {
    local t="${1:-}"
    [[ "$t" =~ ^[0-9]+$ ]] || return 1
    ncore_pfcp_types | awk -F'\t' -v x="$t" '$1==x{print $2; exit}'
}

# The real IE type numbers from TS 29.244 Table 8.1.2-1 (v15.2.0), read
# directly from the specification text rather than recalled. F-TEID is 21,
# Apply Action is 44, UE IP Address is 93, UR-SEQN is 104 and PDR ID is 56.
# An earlier draft of this table had 23/54/50/30 for those, all of them wrong.
ncore_pfcp_ies() {
    # TS 29.244 Table 8.1.2-1 (v15.8.0), every row of the IE type registry.
    cat << 'IEEOF'
1	Create PDR
2	PDI
3	Create FAR
4	Forwarding Parameters
5	Duplicating Parameters
6	Create URR
7	Create QER
8	Created PDR
9	Update PDR
10	Update FAR
11	Update Forwarding Parameters
12	Update BAR (PFCP Session Report Response)
13	Update URR
14	Update QER
15	Remove PDR
16	Remove FAR
17	Remove URR
18	Remove QER
19	Cause
20	Source Interface
21	F-TEID
22	Network Instance
23	SDF Filter
24	Application ID
25	Gate Status
26	MBR
27	GBR
28	QER Correlation ID
29	Precedence
30	Transport Level Marking
31	Volume Threshold
32	Time Threshold
33	Monitoring Time
34	Subsequent Volume Threshold
35	Subsequent Time Threshold
36	Inactivity Detection Time
37	Reporting Triggers
38	Redirect Information
39	Report Type
40	Offending IE
41	Forwarding Policy
42	Destination Interface
43	UP Function Features
44	Apply Action
45	Downlink Data Service Information
46	Downlink Data Notification Delay
47	DL Buffering Duration
48	DL Buffering Suggested Packet Count
49	PFCPSMReq-Flags
50	PFCPSRRsp-Flags
51	Load Control Information
52	Sequence Number
53	Metric
54	Overload Control Information
55	Timer
56	PDR ID
57	F-SEID
58	Application ID's PFDs
59	PFD context
60	Node ID
61	PFD contents
62	Measurement Method
63	Usage Report Trigger
64	Measurement Period
65	FQ-CSID
66	Volume Measurement
67	Duration Measurement
68	Application Detection Information
69	Time of First Packet
70	Time of Last Packet
71	Quota Holding Time
72	Dropped DL Traffic Threshold
73	Volume Quota
74	Time Quota
75	Start Time
76	End Time
77	Query URR
78	Usage Report (Session Modification Response)
79	Usage Report (Session Deletion Response)
80	Usage Report (Session Report Request)
81	URR ID
82	Linked URR ID
83	Downlink Data Report
84	Outer Header Creation
85	Create BAR
86	Update BAR (Session Modification Request)
87	Remove BAR
88	BAR ID
89	CP Function Features
90	Usage Information
91	Application Instance ID
92	Flow Information
93	UE IP Address
94	Packet Rate
95	Outer Header Removal
96	Recovery Time Stamp
97	DL Flow Level Marking
98	Header Enrichment
99	Error Indication Report
100	Measurement Information
101	Node Report Type
102	User Plane Path Failure Report
103	Remote GTP-U Peer
104	UR-SEQN
105	Update Duplicating Parameters
106	Activate Predefined Rules
107	Deactivate Predefined Rules
108	FAR ID
109	QER ID
110	OCI Flags
111	PFCP Association Release Request
112	Graceful Release Period
113	PDN Type
114	Failed Rule ID
115	Time Quota Mechanism
116	User Plane IP Resource Information
117	User Plane Inactivity Timer
118	Aggregated URRs
119	Multiplier
120	Aggregated URR ID
121	Subsequent Volume Quota
122	Subsequent Time Quota
123	RQI
124	QFI
125	Query URR Reference
126	Additional Usage Reports Information
127	Create Traffic Endpoint
128	Created Traffic Endpoint
129	Update Traffic Endpoint
130	Remove Traffic Endpoint
131	Traffic Endpoint ID
132	Ethernet Packet Filter
133	MAC address
134	C-TAG
135	S-TAG
136	Ethertype
137	Proxying
138	Ethernet Filter ID
139	Ethernet Filter Properties
140	Suggested Buffering Packets Count
141	User ID
142	Ethernet PDU Session Information
143	Ethernet Traffic Information
144	MAC Addresses Detected
145	MAC Addresses Removed
146	Ethernet Inactivity Timer
147	Additional Monitoring Time
148	Event Quota
149	Event Threshold
150	Subsequent Event Quota
151	Subsequent Event Threshold
152	Trace Information
153	Framed-Route
154	Framed-Routing
155	Framed-IPv6-Route
156	Event Time Stamp
157	Averaging Window
158	Paging Policy Indicator
159	APN/DNN
160	3GPP Interface Type
IEEOF
}


ncore_pfcp_ie_name() {
    local t="${1:-}"
    [[ "$t" =~ ^[0-9]+$ ]] || return 1
    ncore_pfcp_ies | awk -F'\t' -v x="$t" '$1==x{print $2; exit}'
}

# TS 29.244 §7.2.2.4.1: apart from the node related messages the S flag shall
# be 1, and MP is only meaningful on a session related message (§7.2.2.3).
ncore_pfcp_session_type() {
    case "${1:-}" in 50|51|52|53|54|55|56|57) return 0 ;; esac
    return 1
}

# TS 29.244 §8.1.2: an IE is a Type (2 octets), a Length (2 octets) and the
# Value. Bit 8 of the first type octet is the V flag; the remaining 15 bits
# are the IE type, and a vendor specific IE carries the 2-octet Enterprise ID
# as the first two octets of its value.
# The grouped IEs are the ones whose value is itself a sequence of IEs: the
# groups defined in §7.5 (Create/Update/Remove PDR, FAR, QER, URR and the
# traffic endpoint groups) plus Application ID's PFDs (Table 7.4.3.1-2).
ncore_pfcp_ie_grouped() {
    case "${1:-}" in
        1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18|58|84|85|86|87|128|129|130)
            return 0 ;;
    esac
    return 1
}

ncore_pfcp_ie_walk() {
    local hex="${1:-}" depth="${2:-0}" label="${3:-ie}" total
    total=$(( ${#hex} / 2 ))
    [[ "$hex" =~ ^[0-9a-fA-F]*$ ]] || return 1
    local off=0 n=0
    while (( off + 4 <= total )); do
        local base=$(( off * 2 ))
        local t=$(( (16#${hex:$base:2} << 8) | 16#${hex:$((base+2)):2} ))
        local len=$(( (16#${hex:$((base+4)):2} << 8) | 16#${hex:$((base+6)):2} ))
        local vflag=0
        if (( t & 0x8000 )); then vflag=1; t=$(( t & 0x7FFF )); fi
        (( off + 4 + len <= total )) || {
            printf 'ERROR\t%s.%d type %s claims %s value octets but only %s remain\n' \
                "$label" "$n" "$t" "$len" "$(( total - off - 4 ))" >&2
            return 1
        }
        local val="${hex:$(((off + 4) * 2)):$((len * 2))}"
        printf '%s.%d.type\t%s\n'   "$label" "$n" "$t"
        local iname; iname=$(ncore_pfcp_ie_name "$t")
        [[ -n "$iname" ]] || iname="unknown ($t)"
        printf '%s.%d.name\t%s\n'   "$label" "$n" "$iname"
        printf '%s.%d.length\t%s\n' "$label" "$n" "$len"
        printf '%s.%d.vendor\t%s\n'   "$label" "$n" "$vflag"
        if (( vflag == 1 )); then
            (( len >= 2 )) || { printf 'ERROR\t%s.%d is vendor specific but shorter than its Enterprise ID\n' "$label" "$n" >&2; return 1; }
            printf '%s.%d.enterprise_id\t%s\n' "$label" "$n" "$(( 16#${val:0:4} ))"
            printf '%s.%d.value\t%s\n' "$label" "$n" "${val:4}"
        else
            printf '%s.%d.value\t%s\n' "$label" "$n" "$val"
        fi
        if (( vflag == 0 )) && ncore_pfcp_ie_grouped "$t"; then
            ncore_pfcp_ie_walk "$val" "$(( depth + 1 ))" "${label}.${n}" || return 1
        fi
        off=$(( off + 4 + len ))
        n=$(( n + 1 ))
    done
    if (( off < total )); then
        printf 'ERROR\t%s octet(s) left over after the last IE, too few for a header\n' \
            "$(( total - off ))" >&2
        return 1
    fi
    printf '%s_count\t%s\n' "$label" "$n"
    return 0
}

ncore_decode_pfcp() {
    local hex="${1:-}"
    hex="${hex//[[:space:]]/}"
    hex="${hex//0x/}"
    [[ "$hex" =~ ^[0-9a-fA-F]+$ ]] || return 1
    (( ${#hex} >= 8 )) || return 1
    (( ${#hex} % 2 == 0 )) || return 1
    local total=$(( ${#hex} / 2 ))
    local b0; b0=$(( 16#${hex:0:2} ))
    # TS 29.244 §7.2.2.1: bits 6..8 version, bit 2 MP, bit 1 S, bits 3..5 spare.
    local ver=$(( (b0 >> 5) & 0x7 ))
    local s=$(( b0 & 0x1 ))
    local mp=$(( (b0 >> 1) & 0x1 ))
    local spare=$(( (b0 >> 2) & 0x7 ))
    local mtype=$(( 16#${hex:2:2} ))
    local mlen=$(( (16#${hex:4:2} << 8) | 16#${hex:6:2} ))
    local mname; mname=$(ncore_pfcp_type_name "$mtype")
    [[ -n "$mname" ]] || mname="unknown ($mtype)"
    local hdr=8
    (( s == 1 )) && hdr=16

    printf 'version\t%s\n'          "$ver"
    printf 'message_type\t%s\n'     "$mtype"
    printf 'message_type_name\t%s\n' "$mname"
    printf 'length\t%s\n'           "$mlen"
    printf 'header_octets\t%s\n'    "$hdr"
    printf 'actual_octets\t%s\n'    "$total"
    if (( mlen != total - 4 )); then
        printf 'length_agrees\tno (declared %s, the frame carries %s after the first four)\n' \
            "$mlen" "$(( total - 4 ))"
    else
        printf 'length_agrees\tyes\n'
    fi
    printf 'seid_present\t%s\n'     "$([[ $s -eq 1 ]] && echo yes || echo no)"
    printf 'priority_present\t%s\n' "$([[ $mp -eq 1 ]] && echo yes || echo no)"
    printf 'session_related\t%s\n'  "$(ncore_pfcp_session_type "$mtype" && echo yes || echo no)"
    printf 'spare_bits\t%s\n'       "$spare"
    if (( total < hdr )); then
        printf 'ERROR\tPFCP header needs %s octets, the frame carries %s\n' "$hdr" "$total" >&2
        return 1
    fi
    if (( s == 1 )); then
        local seid=$(( 16#${hex:8:16} ))
        printf 'seid\t%s\n'     "$seid"
        printf 'seid_hex\t%016X\n' "$seid"
        printf 'sequence\t%s\n' "$(( (16#${hex:24:2} << 16) | (16#${hex:26:2} << 8) | 16#${hex:28:2} ))"
    else
        printf 'sequence\t%s\n' "$(( (16#${hex:8:2} << 16) | (16#${hex:10:2} << 8) | 16#${hex:12:2} ))"
    fi
    # Octet n+3: the high nibble is Message Priority when MP=1 (§7.2.2.3),
    # the low nibble is spare and shall be zero.
    local tail=$(( (hdr - 1) * 2 ))
    local tailv=$(( 16#${hex:$tail:2} ))
    if (( mp == 1 )); then
        printf 'message_priority\t%s\n' "$(( (tailv >> 4) & 0xF ))"
    else
        printf 'message_priority\tnone (MP=0)\n'
    fi
    (( (tailv & 0x0F) == 0 )) || printf 'note\tthe trailing spare nibble is %s, the clause sets it to zero\n' "$(( tailv & 0xF ))"
    if (( ver != 1 )); then
        printf 'ERROR\tPFCP version %s is not 1 (TS 29.244 §7.2.2.1)\n' "$ver" >&2
        return 1
    fi
    (( spare == 0 )) || { printf 'ERROR\tspare bits of octet 1 are %s, the clause sets them to zero\n' "$spare" >&2; return 1; }
    if ncore_pfcp_session_type "$mtype" && (( s == 0 )); then
        printf 'ERROR\t%s is session related, so the S flag shall be 1 (§7.2.2.4.1)\n' "$mname" >&2
        return 1
    fi
    if ! ncore_pfcp_session_type "$mtype" && (( mp == 1 )); then
        printf 'note\tMP is set on a node related message; §7.2.2.2 shows it as MP=0\n'
    fi
    ncore_pfcp_ie_walk "${hex:$((hdr * 2))}" 0 ie
}


# The rule structure a Session Establishment Request builds:
#   PDR  (Packet Detection Rule)  matches traffic  -> PDI, precedence, FAR ID, QER ID, URR ID
#   FAR  (Forwarding Action Rule) applies action   -> Apply Action, Forwarding Parameters
#   QER  (QoS Enforcement Rule)   shapes traffic    -> Gate Status, MBR, GBR, QFI
#   URR  (Usage Reporting Rule)   measures usage    -> Measurement Method, Reporting Triggers
ncore_pfcp_rules() {
    local teid="${1:-1}" qfi="${2:-1}" ue_ip="${3:-10.45.0.2}"
    [[ "$teid" =~ ^[0-9]+$ ]] || { printf 'ERROR\tTEID must be numeric\n' >&2; return 2; }
    [[ "$qfi" =~ ^[0-9]+$ ]] || { printf 'ERROR\tQFI must be numeric\n' >&2; return 2; }
    (( qfi <= 63 )) || { printf 'ERROR\tQFI is 6 bits\n' >&2; return 2; }
    printf 'rule\tPDR\n'
    printf 'pdr_id\t1 (IE 56 Packet Detection Rule ID)\n'
    printf 'precedence\t100 (IE 29)\n'
    printf 'pdi\tsource-interface=access(0) (IE 20), f-teid=%s (IE 21), ue-ip=%s (IE 93)\n' "$teid" "$(ncore_sanitize "$ue_ip")"
    printf 'pdr_far_id\t1 (IE 108)\n'
    printf 'pdr_qer_id\t1 (IE 109)\n'
    printf 'rule\tFAR\n'
    printf 'far_id\t1 (IE 108)\n'
    printf 'apply_action\tFORW (IE 44, bit 2)\n'
    printf 'destination_interface\tcore (1) (IE 42)\n'
    printf 'outer_header_creation\tGTP-U/UDP/IPv4, teid=%s (IE 21 F-TEID / IE 4 Forwarding Parameters)\n' "$teid"
    printf 'rule\tQER\n'
    printf 'qer_id\t1 (IE 109)\n'
    printf 'qfi\t%s (the QFI is carried in the PDI / QER, per TS 29.244 7.5.2)\n' "$qfi"
    printf 'gate_status\topen (IE 25)\n'
    printf 'mbr\tIE 26\n'
    printf 'gbr\tIE 27\n'
    printf 'rule\tURR\n'
    printf 'urr_id\t1\n'
    printf 'measurement_method\tvolumetime (IE 62)\n'
    printf 'reporting_triggers\tPERIO (IE 37)\n'
    printf 'volume_threshold\tIE 31\n'
}

# ── 5G-AKA / EAP-AKA' (TS 33.501 §6.1) ──────────────────────────────────
# The 5G authentication flow:
#   1. UE -> SEAF(AMF): Registration Request carrying the SUCI
#   2. SEAF -> AUSF:    Nausf_UEAuthentication_Authenticate with the SUCI and
#                       the serving network name
#   3. AUSF -> UDM:     Nudm_UEAuthentication_Get; UDM deconceals the SUCI,
#                       derives the 5G HE AV (RAND, AUTN, XRES*)
#   4. AUSF -> SEAF:    the 5G SE AV, including HXRES* and KSEAF
#   5. SEAF -> UE:      Authentication Request (RAND, AUTN), NAS in clear
#   6. UE -> SEAF:      Authentication Response (RES*)
#   7. SEAF compares RES* with HXRES*; AUSF compares RES* with XRES*
#   8. SEAF -> UE:      Security Mode Command; UE replies Security Mode Complete
#
# The key hierarchy is bound to the serving network name, which is what stops
# a rogue SN from replaying an authentication from another network:
#   KSEAF = HMAC-SHA-256(K_AUSF, 0x6C || SN name)
#   KAUSF = the AN key derivation output of the 5G AKA
ncore_aka_flow() {
    printf 'step\t1\nactor\tUE -> SEAF (AMF)\nmessage\tRegistration Request\ncarries\tSUCI (or 5G-GUTI on re-registration)\nprotection\tplain NAS\n'
    printf 'step\t2\nactor\tSEAF -> AUSF\nmessage\tNausf_UEAuthentication_Authenticate Request\ncarries\tSUCI, serving network name\napi\tnausf-auth /nausf-auth/v1/ue-authentications\n'
    printf 'step\t3\nactor\tAUSF -> UDM/ARPF\nmessage\tNudm_UEAuthentication_Get Request\ncarries\tSUCI, serving network name\napi\tnudm-ueau /nudm-ueau/v1/{supiOrSuci}/security-information/generate-auth-data\n'
    printf 'step\t4\nactor\tUDM/ARPF\naction\tdeconceal SUCI to SUPI, run 5G-AKA, derive KAUSF and the 5G HE AV\n'
    printf 'step\t5\nactor\tAUSF -> SEAF\nmessage\t5G SE AV\ncarries\tRAND, AUTN, HXRES*, KSEAF\n'
    printf 'step\t6\nactor\tSEAF -> UE\nmessage\tAuthentication Request\ncarries\tRAND, AUTN\nprotection\tplain NAS\n'
    printf 'step\t7\nactor\tUE\naction\tverify AUTN (MAC, SQN, AMF separation bit), compute RES*\n'
    printf 'step\t8\nactor\tUE -> SEAF\nmessage\tAuthentication Response\ncarries\tRES*\nprotection\tplain NAS\n'
    printf 'step\t9\nactor\tSEAF\naction\tcompare RES* with HXRES*\n'
    printf 'step\t10\nactor\tAUSF\naction\tcompare RES* with XRES*\n'
    printf 'step\t11\nactor\tSEAF -> UE\nmessage\tSecurity Mode Command\ncarries\tselected NEA/NIA, UE security capability\n'
    printf 'step\t12\nactor\tUE -> SEAF\nmessage\tSecurity Mode Complete\nprotection\tintegrity protected\n'
}

# KSEAF = HMAC-SHA-256(KAUSF, 0x6C || serving network name), TS 33.501 §A.2.
# The 0x6C octet is the P0 constant for the SEAF key.
ncore_kseaf() {
    local kausf_hex="${1:-}" sn="${2:-}"
    kausf_hex="${kausf_hex//[[:space:]]/}"
    kausf_hex="${kausf_hex//0x/}"
    [[ "$kausf_hex" =~ ^[0-9a-fA-F]{64}$ ]] || {
        printf 'ERROR\tKAUSF must be 32 bytes (64 hex digits)\n' >&2; return 2; }
    [[ -n "$sn" ]] || { printf 'ERROR\tserving network name required (5G:mnc<MNC>.mcc<MCC>.3gppnetwork.org)\n' >&2; return 2; }
    command -v openssl >/dev/null 2>&1 || {
        printf 'ERROR\topenssl is required for the HMAC-SHA-256 key derivation\n' >&2; return 1; }
    # P0 = 0x6C, then the ASCII serving network name.
    local sn_hex; sn_hex=$(printf '%s' "$sn" | xxd -p | tr -d '\n')
    local msg="6c${sn_hex}"
    local kseaf
    kseaf=$(printf '%s' "$msg" | xxd -r -p | openssl dgst -sha256 -mac HMAC \
              -macopt "hexkey:${kausf_hex,,}" -binary 2>/dev/null | xxd -p | tr -d '\n')
    if [[ -z "$kseaf" || ${#kseaf} -ne 64 ]]; then
        printf 'ERROR\tHMAC-SHA-256 derivation failed\n' >&2; return 1
    fi
    printf 'kausf\t%s\n'      "${kausf_hex,,}"
    printf 'serving_network\t%s\n' "$(ncore_sanitize "$sn")"
    printf 'p0\t6C\n'
    printf 'mac_input_hex\t%s\n' "$msg"
    printf 'kseaf\t%s\n'      "$kseaf"
    printf 'kseaf_bits\t256\n'
}

# ── NAS 5GS (TS 24.501) ─────────────────────────────────────────────────
# The NAS 5GS message container: the first octet is the Extended Protocol
# Discriminator (0x7E for 5GMM), the second is the Security Header Type in
# its low nibble and the Extended Protocol Discriminator in the high nibble
# for plain NAS, or the security header type for protected NAS.
ncore_nas_security_types() {
    cat << 'EOF'
0	Plain NAS message, not security protected	plain	no	no
1	Integrity protected	integrity	protected	no
2	Integrity protected and ciphered	integrity+cipher	protected	yes
3	Integrity protected with new 5G NAS security context	integrity	new-context	no
4	Integrity protected and ciphered with new 5G NAS security context	integrity+cipher	new-context	yes
EOF
}

ncore_nas_security_name() {
    local t="${1:-}"
    [[ "$t" =~ ^[0-9]+$ ]] || return 1
    ncore_nas_security_types | awk -F'\t' -v x="$t" '$1==x{print $2; exit}'
}

# 5GMM message types, TS 24.501 Table 9.11.1-1. For an unprotected message the
# type is octet 2 itself, so the assigned values run 0x41..0x67 for 5GMM (and
# 0xC1..0xD6 for 5GSM). These are the real assignments.
ncore_nas_5gmm_types() {
    cat << 'EOF'
0x41	Registration Request	UE to network
0x42	Registration Accept	network to UE
0x43	Registration Complete	UE to network
0x44	Registration Reject	network to UE
0x45	Deregistration Request (UE originating)	UE to network
0x46	Deregistration Accept (UE originating)	network to UE
0x47	Deregistration Request (UE terminated)	network to UE
0x48	Deregistration Accept (UE terminated)	UE to network
0x4C	Service Request	UE to network
0x4D	Service Reject	network to UE
0x4E	Service Accept	network to UE
0x4F	Control Plane Service Request	UE to network
0x50	Network Slice-Specific Authentication and Authorization Command	network to UE
0x51	Network Slice-Specific Authentication and Authorization Complete	UE to network
0x52	Network Slice-Specific Authentication and Authorization Result	network to UE
0x54	Configuration Update Command	network to UE
0x55	Configuration Update Complete	UE to network
0x56	Authentication Request	network to UE
0x57	Authentication Response	UE to network
0x58	Authentication Reject	network to UE
0x59	Authentication Failure	UE to network
0x5A	Authentication Result	network to UE
0x5B	Identity Request	network to UE
0x5C	Identity Response	UE to network
0x5D	Security Mode Command	network to UE
0x5E	Security Mode Complete	UE to network
0x5F	Security Mode Reject	UE to network
0x60	5GMM Status	both
0x64	Notification	network to UE
0x65	Notification Response	UE to network
0x66	UL NAS Transport	UE to network
0x67	DL NAS Transport	network to UE
EOF
}

ncore_nas_5gmm_name() {
    local t="${1:-}"
    t="${t//0x/}"
    [[ "$t" =~ ^[0-9a-fA-F]{1,2}$ ]] || return 1
    local d=$(( 16#$t ))
    ncore_nas_5gmm_types | awk -F'\t' -v x="$d" '{v=strtonum($1); if (v==x) {print $2; exit}}'
}

# Mobile identity types: TS 24.501 Table 9.11.3.4.1. The 5GS mobile identity
# IE type is 0x77 in the IE type table; its first content octet's low 3 bits
# select the identity.
ncore_mobile_identity_types() {
    cat << 'EOF'
1	SUCI	SUCI	concealed SUPI, sent when the UE has no 5G-GUTI
2	5G-GUTI	5G-GUTI	temporary identity, the normal case
3	IMEI	IMEI	equipment identity
4	5G-S-TMSI	5G-S-TMSI	short form of the 5G-GUTI
5	IMEISV	IMEISV	equipment identity and software version
6	MAC address	MAC	used by some non-3GPP access
0	No identity	none	no identity available
EOF
}

# Decode the NAS 5GS header and, when it is a plain 5GMM message, the type.
ncore_decode_nas_5gs() {
    local hex="${1:-}"
    hex="${hex//[[:space:]]/}"
    hex="${hex//0x/}"
    [[ "$hex" =~ ^[0-9a-fA-F]+$ ]] || return 1
    (( ${#hex} >= 4 )) || return 1
    (( ${#hex} % 2 == 0 )) || return 1

    # TS 24.501 §9.3: octet 1 is the Extended Protocol Discriminator. Octet 2
    # depends on whether the message is security protected:
    #   plain:     octet 2 IS the 5GMM/5GSM message type
    #   protected: octet 2 is Security header type (high nibble) | EPD (low
    #              nibble), and the payload follows as a plain NAS message
    # The SHT therefore cannot be read before knowing that the message is
    # protected, which is why the plain case is detected from octet 2 itself.
    local epd=$(( 16#${hex:0:2} ))
    local b1=$(( 16#${hex:2:2} ))
    local epd_name
    case "$epd" in
        126) epd_name="5GMM (mobility management)" ;;
        127) epd_name="5GSM (session management)" ;;
        46)  epd_name="5GSM (session management, legacy 0x2E)" ;;
        47)  epd_name="5GMM (mobility management, legacy 0x2F)" ;;
        *)   epd_name="unknown" ;;
    esac
    printf 'extended_protocol_discriminator\t0x%02X\n' "$epd"
    printf 'epd_name\t%s\n' "$epd_name"

    # The 5GMM message types occupy 0x41..0x67 and the 5GSM types 0xC1..0xD6,
    # so the low nibble of the SHT (1..4) is unambiguous against them.
    local low=$(( b1 & 0x0F ))
    local sht=-1
    if (( low >= 1 && low <= 4 )) && (( (b1 >> 4) == 0x2 )); then
        sht=$low
    fi
    # The protected layout puts a fixed 0x2 in the high nibble of octet 2
    # (EPD 2 = "5GS mobility management" in the short form), which is what a
    # protected NAS message always shows.
    if (( sht >= 0 )); then
        local sn; sn=$(ncore_nas_security_name "$sht")
        [[ -n "$sn" ]] || sn="unknown"
        local protected="no" ciphered="no"
        case "$sht" in
            1|3) protected="yes" ;;
            2|4) protected="yes"; ciphered="yes" ;;
        esac
        printf 'security_header_type\t%s\n' "$sht"
        printf 'security_header_name\t%s\n' "$sn"
        printf 'security_protected\t%s\n' "$protected"
        printf 'ciphered\t%s\n' "$ciphered"
        # The MAC and sequence number follow; the inner NAS message sits after
        # them and cannot be read without the 5G NAS keys.
        printf 'mac_octets\t4\n'
        printf 'sequence_number_octets\t1\n'
        printf 'message_type\tencrypted\n'
        printf 'message_type_name\tunreadable-without-5g-nas-keys\n'
        printf 'note\tinner NAS type is only readable after de-protection\n'
    else
        printf 'security_header_type\t0\n'
        printf 'security_header_name\tPlain NAS message, not security protected\n'
        printf 'security_protected\tno\n'
        printf 'ciphered\tno\n'
        local mname; mname=$(ncore_nas_5gmm_name "$(printf '%02X' "$b1")")
        [[ -n "$mname" ]] || mname="unknown"
        printf 'message_type\t0x%02X\n' "$b1"
        printf 'message_type_name\t%s\n' "$mname"
        printf 'plaintext\t%s\n' "$hex"
    fi
}

# 5G-GUTI: TS 24.501 §9.11.3.4. The 5G-GUTI is
#   <PLMN (3 octets)> <AMF Region ID (1)> <AMF Set ID (10 bits)>
#   <AMF Pointer (6 bits)> <5G-TMSI (4 octets)>
# so it is 3 + 1 + 2 + 4 = 10 octets and the 5G-TMSI is the last 4.
ncore_decode_5g_guti() {
    local hex="${1:-}"
    hex="${hex//[[:space:]]/}"
    hex="${hex//0x/}"
    [[ "$hex" =~ ^[0-9a-fA-F]+$ ]] || return 1
    (( ${#hex} == 20 || ${#hex} == 22 )) || return 1
    # Accept an optional leading identity-type octet (0x7x) and length.
    local body="$hex"
    if (( ${#hex} == 22 )); then body="${hex:2}"; fi
    local plmn
    plmn=$(ncore_sanitize "$(printf '%02X%02X%02X' "$(( 16#${body:0:2} ))" "$(( 16#${body:2:2} ))" "$(( 16#${body:4:2} ))")")
    local amf_region=$(( 16#${body:6:2} ))
    local setid_po=$(( (16#${body:8:2} << 8) | 16#${body:10:2} ))
    local amf_setid=$(( (setid_po >> 6) & 0x3FF ))
    local amf_pointer=$(( setid_po & 0x3F ))
    local tmsi=$(( 16#${body:12:8} ))
    printf 'plmn_bytes\t%s\n' "$plmn"
    printf 'amf_region_id\t%s\n' "$amf_region"
    printf 'amf_set_id\t%s\n' "$amf_setid"
    printf 'amf_pointer\t%s\n' "$amf_pointer"
    printf 'fiveg_tmsi\t%s\n' "$tmsi"
    printf 'fiveg_tmsi_hex\t%08X\n' "$tmsi"
    printf 'fiveg_guti_octets\t10\n'
}

# ── plan files — hardware the vector needs ──────────────────────────────
# A plan is not an attack. It names the testbed, the steps and the expected
# observable, and it carries `status: handoff` so nothing downstream mistakes
# it for a completed action.
ncore_plan() {
    local name="${1:-}"
    local f="$NCORE_PLAN_DIR/${name}.plan"
    mkdir -p "$NCORE_PLAN_DIR" || { printf 'ERROR\tcannot create %s\n' "$NCORE_PLAN_DIR" >&2; return 1; }
    local need="" steps="" why=""
    case "$name" in
        n2-expose)
            why="N2 is NGAP over SCTP and, in a real deployment, sits in the RAN transport network. Where it is not IPsec-protected (TS 33.501 §9 requires NDS/IP or IPsec on N2) an attacker with transport access can read and inject NGAP."
            need="Open5GS amfd with an NGAP listener reachable over SCTP (default 127.0.0.5:38412), plus a gNB or an SCTP client that can speak NGAP. tshark with the ngap dissector for capture."
            steps="1. Confirm reachability: sctp_test / ss -S on udp? no: ss --sctp -lnp for the AMF port.\n2. Capture with: tshark -i <if> -f 'sctp port 38412' -w n2.pcap\n3. Decode a captured PDU with: $0 --decode-ngap <hex>\n4. Map the RAN/AMF UE NGAP ID pairing with the ue-id-pair verb.\n5. Look for InitialUEMessage carrying a clear-text NAS Registration Request (SUCI exposure)."
            ;;
        nrf-discovery)
            why="NRF discovery is unauthenticated unless the operator enables OAuth2 (TS 33.501 Annex A). An over-permissive NRF answers any GET with the full NF inventory: addresses, services and status."
            need="Open5GS nrfd reachable on the SBI (default 127.0.0.10:7777) and curl. Optional: a valid access token if OAuth2 is enforced."
            steps="1. Query: curl -s 'http://<nrf>:7777/nnrf-disc/v1/nf-instances?target-nf-type=AMF'\n2. Enumerate: target-nf-type in {AMF,SMF,UPF,AUSF,UDM,PCF,NEF,BSF,NRF}.\n3. Record each nfInstances[].ipv4Address and nfServices[].apiPrefix.\n4. Repeat the same query per service to see which API roots are exposed.\n5. Compare against the api_root column of --nf-list."
            ;;
        sepp-bypass)
            why="SEPP exists to protect inter-PLMN signalling (TS 33.501 §12, PRINS). A SEPP that is absent, misconfigured or that trusts an IPX peer without consent lets a roaming partner's NFs talk directly to the home network's SBI."
            need="Two core networks (e.g. two Open5GS instances) with an N32 interface or an IPX simulator in between, and DNS control for the .3gppnetwork.org names."
            steps="1. Establish whether N32 is present at all: trace between the two SEPPs.\n2. Request an NF discovery across the boundary and see whether the SEPP filters target-nf-type.\n3. Test the PRINS consent model: does a discovery for a subscriber of a third PLMN get answered?\n4. Check whether the SEPP validates the serving network name in the authentication exchange.\n5. Record which services cross the boundary unfiltered."
            ;;
        ipx-attack)
            why="The IPX is a shared transport between carriers. A compromised or hostile IPX can read and modify SS7/Diameter/HTTP2 signalling, including the SUCI and the authentication vectors."
            need="A lab IPX path (two cores and an intermediary), or a roaming simulator, plus capture points on both sides."
            steps="1. Position a capture on the IPX-facing interface (this is the hardest part and needs cooperation).\n2. Baseline the normal signalling, then compare the SUCI/SUPI fields across a roam.\n3. Test whether an NRF discovery for a home subscriber is answered from the visited network.\n4. Check SEPP filtering of the nausf-auth and nudm-ueau services specifically.\n5. Report any service reachable from the visited side that should not be."
            ;;
        *) printf 'ERROR\tunknown plan: %s\n' "$(ncore_sanitize "$name")" >&2; return 2 ;;
    esac
    if ! cat > "$f" <<EOF
plan: ${name}
status: handoff
module: 13_nr_core.sh
generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)

what_this_is:
  A plan, not an executed attack. It names the testbed required and the
  steps to run. Steps that are pure encoding/decoding are performed for
  real by this module and are not listed here.

why:
  ${why}

testbed_required:
  ${need}

steps:
$(printf '%b' "  ${steps}" | sed 's/^/  /')

decoders_available_offline:
  $0 --decode-ngap <hex>
  $0 --decode-nas-5gs <hex>
  $0 --decode-pfcp <hex>

references:
  TS 23.501 4.2   reference points and SBA
  TS 33.501 6.1   5G-AKA and EAP-AKA'
  TS 33.501 9     NDS/IP and N2 security
  TS 33.501 12    inter-PLMN and SEPP
  TS 38.413 9     NGAP
  TS 29.244 7     PFCP
  TS 29.510 6.2   NRF NF discovery
EOF
    then
        printf 'ERROR\tcannot write plan %s\n' "$f" >&2
        return 1
    fi
    printf 'plan\t%s\n'   "$f"
    printf 'name\t%s\n'   "$name"
    printf 'status\thandoff\n'
    printf 'testbed\t%s\n' "$(ncore_sanitize "$need")"
}

# ── hardware / software guards ──────────────────────────────────────────
ncore_find_open5gs() {
    local t
    for t in open5gs-amfd open5gs-nrfd open5gs-smfd open5gs-upfd open5gs-ausfd open5gs-udmd open5gs-pcrfd; do
        command -v "$t" >/dev/null 2>&1 && { echo "$t"; return 0; }
    done
    return 1
}

ncore_find_free5gc() {
    command -v free5gc   >/dev/null 2>&1 && { echo "free5gc";   return 0; }
    command -v nrf       >/dev/null 2>&1 && { echo "free5gc-nrf"; return 0; }
    return 1
}

ncore_find_pfcp_tool() {
    local t
    for t in upfgtp smf gtpu; do
        command -v "$t" >/dev/null 2>&1 && { echo "$t"; return 0; }
    done
    return 1
}

ncore_find_capture_tool() {
    command -v tshark >/dev/null 2>&1 && { echo "tshark"; return 0; }
    command -v tcpdump >/dev/null 2>&1 && { echo "tcpdump"; return 0; }
    return 1
}

ncore_status() {
    local core5g core4g cap
    core5g=$(ncore_find_open5gs) || core5g="missing"
    core4g=$(ncore_find_free5gc) || core4g="missing"
    cap=$(ncore_find_capture_tool) || cap="missing"
    printf 'open5gs\t%s\n'      "$core5g"
    printf 'free5gc\t%s\n'      "$core4g"
    printf 'capture\t%s\n'      "$cap"
    printf 'pfcp_tool\t%s\n'    "$(ncore_find_pfcp_tool || echo missing)"
    printf 'plans\t%s\n'        "$(ls -1 "$NCORE_PLAN_DIR"/*.plan 2>/dev/null | wc -l)"
    printf 'dir\t%s\n'          "$NCORE_DIR"
    printf 'plan_dir\t%s\n'     "$NCORE_PLAN_DIR"
}

# ── CLI verbs ───────────────────────────────────────────────────────────
ncore_cli_status_tsv() { ncore_status; }

ncore_cmd_nf_list() {
    ncore_nf_list
}

ncore_cmd_decode_ngap() {
    local hex="${1:-}"
    [[ -n "$hex" ]] || { printf 'ERROR\tusage: --decode-ngap <hex>\n' >&2; return 2; }
    # The shape of the argument is checked here, so that a decoder that
    # refuses a WELL FORMED NGAP PDU is not reported as a malformed hex string:
    # its own error says what is wrong, and the fields it did read are still
    # printed.
    local clean="${hex//[[:space:]]/}"
    clean="${clean//0x/}"
    if ! [[ "$clean" =~ ^[0-9a-fA-F]+$ ]] || (( ${#clean} % 2 != 0 )) || (( ${#clean} < 4 )); then
        printf 'ERROR\t--decode-ngap takes an even number of hex digits (at least 2 octets): %s\n' \
            "$(ncore_sanitize "$hex")" >&2
        return 1
    fi
    local out rc=0
    out=$(ncore_decode_ngap "$hex") || rc=1
    printf '%s\n' "$out"
    if (( rc != 0 )); then
        printf 'ERROR\t%s is not a well formed NGAP PDU; the fields above are what could be read\n' \
            "$(ncore_sanitize "$clean")" >&2
        return 1
    fi
    return 0
}

ncore_cmd_decode_nas() {
    local hex="${1:-}"
    [[ -n "$hex" ]] || { printf 'ERROR\tusage: --decode-nas-5gs <hex>\n' >&2; return 2; }
    # The shape of the argument is checked here, so that a decoder that
    # refuses a WELL FORMED NAS 5GS message is not reported as a malformed hex string:
    # its own error says what is wrong, and the fields it did read are still
    # printed.
    local clean="${hex//[[:space:]]/}"
    clean="${clean//0x/}"
    if ! [[ "$clean" =~ ^[0-9a-fA-F]+$ ]] || (( ${#clean} % 2 != 0 )) || (( ${#clean} < 4 )); then
        printf 'ERROR\t--decode-nas-5gs takes an even number of hex digits (at least 2 octets): %s\n' \
            "$(ncore_sanitize "$hex")" >&2
        return 1
    fi
    local out rc=0
    out=$(ncore_decode_nas_5gs "$hex") || rc=1
    printf '%s\n' "$out"
    if (( rc != 0 )); then
        printf 'ERROR\t%s is not a well formed NAS 5GS message; the fields above are what could be read\n' \
            "$(ncore_sanitize "$clean")" >&2
        return 1
    fi
    return 0
}

ncore_cmd_decode_pfcp() {
    local hex="${1:-}"
    [[ -n "$hex" ]] || { printf 'ERROR\tusage: --decode-pfcp <hex>\n' >&2; return 2; }
    # The shape of the argument is checked here, so that a decoder that
    # refuses a WELL FORMED PFCP message is not reported as a malformed hex string:
    # its own error says what is wrong, and the fields it did read are still
    # printed.
    local clean="${hex//[[:space:]]/}"
    clean="${clean//0x/}"
    if ! [[ "$clean" =~ ^[0-9a-fA-F]+$ ]] || (( ${#clean} % 2 != 0 )) || (( ${#clean} < 8 )); then
        printf 'ERROR\t--decode-pfcp takes an even number of hex digits (at least 4 octets): %s\n' \
            "$(ncore_sanitize "$hex")" >&2
        return 1
    fi
    local out rc=0
    out=$(ncore_decode_pfcp "$hex") || rc=1
    printf '%s\n' "$out"
    if (( rc != 0 )); then
        printf 'ERROR\t%s is not a well formed PFCP message; the fields above are what could be read\n' \
            "$(ncore_sanitize "$clean")" >&2
        return 1
    fi
    return 0
}

ncore_cmd_decode_gtpu() {
    local hex="${1:-}"
    [[ -n "$hex" ]] || { printf 'ERROR\tusage: --decode-gtpu <hex>\n' >&2; return 2; }
    local out rc=0
    out=$(ncore_decode_gtpu "$hex") || rc=1
    if (( rc != 0 )); then
        printf 'ERROR\tGTP-U header invalid (need >= 8 octets, version 1): %s\n' \
            "$(ncore_sanitize "$hex")" >&2
        return 1
    fi
    printf '%s\n' "$out"
}

ncore_cmd_decode_guti() {
    local hex="${1:-}"
    [[ -n "$hex" ]] || { printf 'ERROR\tusage: --decode-5g-guti <20 or 22 hex digits>\n' >&2; return 2; }
    local out rc=0
    out=$(ncore_decode_5g_guti "$hex") || rc=1
    if (( rc != 0 )); then
        printf 'ERROR\t5G-GUTI must be 10 octets (20 hex digits), optionally prefixed by the identity octet: %s\n' \
            "$(ncore_sanitize "$hex")" >&2
        return 1
    fi
    printf '%s\n' "$out"
}

ncore_cmd_kseaf() {
    local k="${1:-}" sn="${2:-}"
    [[ -n "$k" && -n "$sn" ]] || {
        printf 'ERROR\tusage: --kseaf <kausf-hex-32-bytes> <serving-network-name>\n' >&2; return 2; }
    ncore_kseaf "$k" "$sn"
}

ncore_cmd_nf_discovery() {
    local target="${1:-}" requester="${2:-AMF}"
    [[ -n "$target" ]] || { printf 'ERROR\tusage: --nf-discovery <NF|service> [requester-NF]\n' >&2; return 2; }
    local out rc=0
    out=$(ncore_nf_discovery "$target" "$requester") || rc=1
    if (( rc != 0 )); then
        printf 'ERROR\tunknown NF or service: %s\n' "$(ncore_sanitize "$target")" >&2
        return 1
    fi
    printf '%s\n' "$out"
}

ncore_cmd_plan() {
    local name="${1:-}"
    [[ -n "$name" ]] || {
        printf 'ERROR\tusage: --plan <n2-expose|nrf-discovery|sepp-bypass|ipx-attack>\n' >&2; return 2; }
    ncore_plan "$name"
}

ncore_cmd_ue_id_pair() {
    local ran="${1:-}" amf="${2:-}" tmsi="${3:-}"
    [[ -n "$ran" && -n "$amf" ]] || {
        printf 'ERROR\tusage: --ue-id-pair <ran-ue-ngap-id> <amf-ue-ngap-id> [5g-tmsi]\n' >&2; return 2; }
    ncore_ue_id_pair "$ran" "$amf" "$tmsi"
}

# ── selftest — no radio, no root, no network ────────────────────────────
ncore_selftest() {
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
    export TMP_DIR="$d/tmp" NCORE_DIR="$d/loot/nr_core" NCORE_PLAN_DIR="$d/loot/nr_core/plans"
    mkdir -p "$NCORE_DIR" "$NCORE_PLAN_DIR"

    # 1. NGAP PDU type and procedure code.
    #    InitialUEMessage is procedureCode 15, an initiatingMessage, so the
    #    first octet is 0b00_001111 = 0x0F.
    out=$(ncore_decode_ngap "0F002000")
    chk ngap-pdu-type   "$(fld "$out" pdu_type)"        "0"
    chk ngap-type-name  "$(fld "$out" pdu_type_name)"   "initiatingMessage"
    chk ngap-proc       "$(fld "$out" procedure_code)"  "15"
    chk ngap-proc-name  "$(fld "$out" procedure_name)"  "InitialUEMessage"
    chk ngap-carries    "$(fld "$out" carries_nas_pdu)" "yes"
    # DownlinkNASTransport is procedureCode 4 -> 0x04.
    out=$(ncore_decode_ngap "0400")
    chk ngap-dl-proc    "$(fld "$out" procedure_code)" "4"
    chk ngap-dl-name    "$(fld "$out" procedure_name)" "DownlinkNASTransport"
    # UplinkNASTransport is procedureCode 48 -> 0x30.
    out=$(ncore_decode_ngap "3000")
    chk ngap-ul-name    "$(fld "$out" procedure_name)" "UplinkNASTransport"
    # successfulOutcome is PDU type 1: 0b01_000000 = 0x40 for code 0.
    out=$(ncore_decode_ngap "4000")
    chk ngap-success    "$(fld "$out" pdu_type_name)"  "successfulOutcome"
    chk ngap-success-p  "$(fld "$out" procedure_code)" "0"
    # unsuccessfulOutcome is PDU type 2: 0b10_000000 = 0x80.
    out=$(ncore_decode_ngap "8000")
    chk ngap-unsucc     "$(fld "$out" pdu_type_name)"  "unsuccessfulOutcome"
    chk ngap-bad-odd    "$(ncore_decode_ngap ABC >/dev/null 2>&1; echo $?)"  "1"
    chk ngap-bad-nonhex "$(ncore_decode_ngap ZZ >/dev/null 2>&1; echo $?)"   "1"
    chk ngap-bad-short  "$(ncore_decode_ngap 0F >/dev/null 2>&1; echo $?)"   "1"

    # 2. NGAP procedure table: real assigned codes.
    chk ngap-tbl-15  "$(ncore_ngap_procedure_name 15)" "InitialUEMessage"
    chk ngap-tbl-4   "$(ncore_ngap_procedure_name 4)"  "DownlinkNASTransport"
    chk ngap-tbl-48  "$(ncore_ngap_procedure_name 48)" "UplinkNASTransport"
    chk ngap-tbl-24  "$(ncore_ngap_procedure_name 24)" "Paging"
    chk ngap-tbl-29  "$(ncore_ngap_procedure_name 29)" "PDUSessionResourceSetup"
    chk ngap-tbl-21  "$(ncore_ngap_procedure_name 21)" "NGSetup"
    chk ngap-tbl-bad "$(ncore_ngap_procedure_name 9999)" ""

    # 3. UE NGAP ID pairing and the 5G-TMSI.
    out=$(ncore_ue_id_pair 1 42 305419896)
    chk ueids-ran     "$(fld "$out" ran_ue_ngap_id)"  "1"
    chk ueids-ran-b   "$(fld "$out" ran_ue_ngap_id_bits)" "32"
    chk ueids-amf     "$(fld "$out" amf_ue_ngap_id)"  "42"
    chk ueids-amf-b   "$(fld "$out" amf_ue_ngap_id_bits)" "40"
    chk ueids-assoc   "$(fld "$out" association)"     "1:42"
    chk ueids-tmsi    "$(fld "$out" fiveg_tmsi_hex)"  "12345678"
    chk ueids-bad-ran "$(ncore_ue_id_pair abc 1 >/dev/null 2>&1; echo $?)" "2"
    chk ueids-bad-amf "$(ncore_ue_id_pair 1 xyz >/dev/null 2>&1; echo $?)" "2"
    chk ueids-ran-32  "$(ncore_ue_id_pair 4294967296 1 >/dev/null 2>&1; echo $?)" "2"

    # 4. NAS 5GS security header type classification.
    #    Registration Request: EPD 0x7E, security header 0 -> 7E 41.
    out=$(ncore_decode_nas_5gs "7E4100")
    chk nas-epd        "$(fld "$out" extended_protocol_discriminator)" "0x7E"
    chk nas-epd-name   "$(fld "$out" epd_name)"  "5GMM (mobility management)"
    chk nas-sht        "$(fld "$out" security_header_type)" "0"
    chk nas-plain      "$(fld "$out" security_header_name)" "Plain NAS message, not security protected"
    chk nas-protected  "$(fld "$out" security_protected)"    "no"
    chk nas-msgtype    "$(fld "$out" message_type_name)"     "Registration Request"
    chk nas-msgbyte    "$(fld "$out" message_type)"          "0x41"
    #    Security Mode Command: 7E 5D with plain header.
    chk nas-smc        "$(fld "$(ncore_decode_nas_5gs 7E5D00)" message_type_name)" "Security Mode Command"
    chk nas-smcomplete "$(fld "$(ncore_decode_nas_5gs 7E5E00)" message_type_name)" "Security Mode Complete"
    chk nas-authreq    "$(fld "$(ncore_decode_nas_5gs 7E5600)" message_type_name)" "Authentication Request"
    chk nas-authrsp    "$(fld "$(ncore_decode_nas_5gs 7E5700)" message_type_name)" "Authentication Response"
    chk nas-regaccept  "$(fld "$(ncore_decode_nas_5gs 7E4200)" message_type_name)" "Registration Accept"
    chk nas-regreject  "$(fld "$(ncore_decode_nas_5gs 7E4400)" message_type_name)" "Registration Reject"
    chk nas-ulnas      "$(fld "$(ncore_decode_nas_5gs 7E6600)" message_type_name)" "UL NAS Transport"
    chk nas-dlnas      "$(fld "$(ncore_decode_nas_5gs 7E6700)" message_type_name)" "DL NAS Transport"
    #    Integrity protected: 7E 21 (SHT 1 in the low nibble, EPD 2 high).
    out=$(ncore_decode_nas_5gs "7E21AABBCCDD00")
    chk nas-sht1       "$(fld "$out" security_header_type)" "1"
    chk nas-sht1-name  "$(fld "$out" security_header_name)" "Integrity protected"
    chk nas-sht1-prot  "$(fld "$out" security_protected)"   "yes"
    chk nas-sht1-ciph  "$(fld "$out" ciphered)"             "no"
    #    Integrity protected and ciphered: 7E 22.
    out=$(ncore_decode_nas_5gs "7E22AABBCCDD00")
    chk nas-sht2-name  "$(fld "$out" security_header_name)" "Integrity protected and ciphered"
    chk nas-sht2-ciph  "$(fld "$out" ciphered)"             "yes"
    #    New 5G NAS security context variants 3 and 4.
    chk nas-sht3       "$(fld "$(ncore_decode_nas_5gs 7E23AABBCCDD00)" security_header_name)" "Integrity protected with new 5G NAS security context"
    chk nas-sht4-ciph  "$(fld "$(ncore_decode_nas_5gs 7E24AABBCCDD00)" ciphered)" "yes"
    chk nas-bad-nonhex "$(ncore_decode_nas_5gs ZZ >/dev/null 2>&1; echo $?)" "1"
    chk nas-bad-short  "$(ncore_decode_nas_5gs 7E >/dev/null 2>&1; echo $?)" "1"

    # 5. 5GMM message type table completeness at the assigned values.
    chk 5gmm-41  "$(ncore_nas_5gmm_name 41)" "Registration Request"
    chk 5gmm-44  "$(ncore_nas_5gmm_name 44)" "Registration Reject"
    chk 5gmm-56  "$(ncore_nas_5gmm_name 56)" "Authentication Request"
    chk 5gmm-5d  "$(ncore_nas_5gmm_name 5D)" "Security Mode Command"
    chk 5gmm-66  "$(ncore_nas_5gmm_name 66)" "UL NAS Transport"
    chk 5gmm-bad "$(ncore_nas_5gmm_name 99)" ""

    # 6. 5G-GUTI decode: PLMN, AMF region/set/pointer and the 5G-TMSI.
    #    Bytes: 02 F8 10 (208-01) 01 (region) 00 2A (set 0, pointer 42)
    #           12 34 56 78 (5G-TMSI 0x12345678)
    out=$(ncore_decode_5g_guti "02F81001 002A 12345678")
    chk guti-plmn     "$(fld "$out" plmn_bytes)"      "02F810"
    chk guti-region   "$(fld "$out" amf_region_id)"   "1"
    chk guti-setid    "$(fld "$out" amf_set_id)"      "0"
    chk guti-pointer  "$(fld "$out" amf_pointer)"     "42"
    chk guti-tmsi     "$(fld "$out" fiveg_tmsi)"      "305419896"
    chk guti-tmsi-hex "$(fld "$out" fiveg_tmsi_hex)"  "12345678"
    chk guti-octets   "$(fld "$out" fiveg_guti_octets)" "10"
    # A set ID of 0x3FF and pointer 0x3F exercise the 10/6 bit split.
    out=$(ncore_decode_5g_guti "02F81001 FFFF 00000001")
    chk guti-max-set     "$(fld "$out" amf_set_id)"  "1023"
    chk guti-max-pointer "$(fld "$out" amf_pointer)" "63"
    chk guti-max-tmsi    "$(fld "$out" fiveg_tmsi)"  "1"
    chk guti-bad-len  "$(ncore_decode_5g_guti 02F8 >/dev/null 2>&1; echo $?)" "1"
    chk guti-bad-hex  "$(ncore_decode_5g_guti ZZZZZZZZZZZZZZZZZZZZ >/dev/null 2>&1; echo $?)" "1"

    # 7. PFCP message type classification and the session header.
    #    Session Establishment Request = 50, with a SEID present:
    #    flags 0x21 (version 1, S=1 ... MP=0 -> SEID present), type 0x32 (50),
    #    length 0x0004, SEID 8 octets, seq 3 octets, spare.
    out=$(ncore_decode_pfcp "21 32 0004 0000000000000001 000001 00")
    chk pfcp-ver      "$(fld "$out" version)"            "1"
    chk pfcp-type     "$(fld "$out" message_type)"       "50"
    chk pfcp-name     "$(fld "$out" message_type_name)"  "Session Establishment Request"
    chk pfcp-seid-y   "$(fld "$out" seid_present)"       "yes"
    chk pfcp-session  "$(fld "$out" session_related)"    "yes"
    chk pfcp-seq      "$(fld "$out" sequence)"           "1"
    # Heartbeat Request = 1, a node-related message with no SEID.
    out=$(ncore_decode_pfcp "20 01 0004 000001 00")
    chk pfcp-hb-name  "$(fld "$out" message_type_name)"  "Heartbeat Request"
    chk pfcp-hb-seid  "$(fld "$out" seid_present)"       "no"
    chk pfcp-hb-sess  "$(fld "$out" session_related)"    "no"
    # Association Setup Request = 5.
    chk pfcp-assoc    "$(fld "$(ncore_decode_pfcp '20 05 0004 000001 00')" message_type_name)" "Association Setup Request"
    # Session Deletion Request = 54.
    chk pfcp-del      "$(fld "$(ncore_decode_pfcp '21 36 0004 0000000000000001 000001 00')" message_type_name)" "Session Deletion Request"
    chk pfcp-unknown  "$(fld "$(ncore_decode_pfcp '20 63 0004 000001 00')" message_type_name)" "unknown (99)"
    chk pfcp-bad-ver  "$(ncore_decode_pfcp '40 01 0004 000001 00' >/dev/null 2>&1; echo $?)" "1"
    chk pfcp-bad-short "$(ncore_decode_pfcp '20 01' >/dev/null 2>&1; echo $?)" "1"

    # The IE walk (§8.1.2): type, name, length, value; a vendor specific IE
    # keeps its Enterprise ID out of the value and a grouped IE is entered.
    out=$(ncore_decode_pfcp '21 32 000A 0000000000000001 000001 00 0013 0001 01')
    chk pfcp-ie-len   "$(fld "$out" ie.0.length)"   "1"
    chk pfcp-ie-name  "$(fld "$out" ie.0.name)"     "Cause"
    chk pfcp-ie-value "$(fld "$out" ie.0.value)"    "01"
    chk pfcp-ie-count "$(fld "$out" ie_count)"      "1"
    out=$(ncore_decode_pfcp '21 32 000E 0000000000000001 000001 00 8064 0004 28AF A1B2')
    chk pfcp-ie-vendor    "$(fld "$out" ie.0.vendor)"        "1"
    chk pfcp-ie-enterprise "$(fld "$out" ie.0.enterprise_id)" "10415"
    chk pfcp-ie-vvalue    "$(fld "$out" ie.0.value)"         "A1B2"
    # Create PDR (1) holding PDR ID (56) and PDI (2) holding Source Interface
    # (20), three levels deep.
    out=$(ncore_decode_pfcp '21 32 001F 0000000000000001 000001 00 0001 000F 0038 0002 0007 0002 0005 0014 0001 00')
    chk pfcp-group-name  "$(fld "$out" 'ie.0.name')"          "Create PDR"
    chk pfcp-group-child "$(fld "$out" 'ie.0.0.name')"        "PDR ID"
    chk pfcp-group-nest  "$(fld "$out" 'ie.0.1.name')"        "PDI"
    chk pfcp-group-leaf  "$(fld "$out" 'ie.0.1.0.name')"      "Source Interface"
    # A Length that runs past the frame and a trailing fragment are refused.
    chk pfcp-ie-truncated "$(ncore_decode_pfcp '21 32 000E 0000000000000001 000001 00 0013 0002 01' >/dev/null 2>&1; echo $?)" "1"
    chk pfcp-ie-leftover  "$(ncore_decode_pfcp '21 32 000F 0000000000000001 000001 00 0013 0001 01 0013' >/dev/null 2>&1; echo $?)" "1"
    chk pfcp-len-mismatch "$(fld "$(ncore_decode_pfcp '21 32 000B 0000000000000001 000001 00 0013 0001 01')" length_agrees)" "no (declared 11, the frame carries 17 after the first four)"

    # 8. PFCP IE table: the real IE type numbers.
    chk ie-1   "$(ncore_pfcp_ie_name 1)"   "Create PDR"
    chk ie-2   "$(ncore_pfcp_ie_name 2)"   "PDI"
    chk ie-3   "$(ncore_pfcp_ie_name 3)"   "Create FAR"
    chk ie-6   "$(ncore_pfcp_ie_name 6)"   "Create URR"
    chk ie-7   "$(ncore_pfcp_ie_name 7)"   "Create QER"
    chk ie-19  "$(ncore_pfcp_ie_name 19)"  "Cause"
    chk ie-21  "$(ncore_pfcp_ie_name 21)"  "F-TEID"
    chk ie-42  "$(ncore_pfcp_ie_name 42)"  "Destination Interface"
    chk ie-56  "$(ncore_pfcp_ie_name 56)"  "PDR ID"
    # The rows above 40 were shifted: 41 is Forwarding Policy, 49 is
    # PFCPSMReq-Flags, 58 Application ID's PFDs, 59 PFD context, 81 URR ID.
    chk ie-41  "$(ncore_pfcp_ie_name 41)"  "Forwarding Policy"
    chk ie-49  "$(ncore_pfcp_ie_name 49)"  "PFCPSMReq-Flags"
    chk ie-58  "$(ncore_pfcp_ie_name 58)"  "Application ID's PFDs"
    chk ie-59  "$(ncore_pfcp_ie_name 59)"  "PFD context"
    chk ie-81  "$(ncore_pfcp_ie_name 81)"  "URR ID"
    chk ie-160 "$(ncore_pfcp_ie_name 160)" "3GPP Interface Type"
    chk ie-108 "$(ncore_pfcp_ie_name 108)" "FAR ID"
    chk ie-109 "$(ncore_pfcp_ie_name 109)" "QER ID"
    chk ie-93  "$(ncore_pfcp_ie_name 93)"  "UE IP Address"
    chk ie-44  "$(ncore_pfcp_ie_name 44)"  "Apply Action"
    chk ie-104 "$(ncore_pfcp_ie_name 104)" "UR-SEQN"
    chk ie-bad "$(ncore_pfcp_ie_name 9999)" ""

    # 9. The PDR/FAR/QER/URR rule walk.
    out=$(ncore_pfcp_rules 1 9)
    chk rules-pdr    "$(printf '%s\n' "$out" | grep -c '^rule	PDR')"  "1"
    chk rules-far    "$(printf '%s\n' "$out" | grep -c '^rule	FAR')"  "1"
    chk rules-qer    "$(printf '%s\n' "$out" | grep -c '^rule	QER')"  "1"
    chk rules-urr    "$(printf '%s\n' "$out" | grep -c '^rule	URR')"  "1"
    chk rules-qfi    "$(printf '%s\n' "$out" | grep -c '^qfi	9 ')" "1"
    chk rules-teid   "$(printf '%s\n' "$out" | grep -c 'f-teid=1 (IE 21)')" "1"
    chk rules-bad-qfi "$(ncore_pfcp_rules 1 64 >/dev/null 2>&1; echo $?)" "2"
    chk rules-bad-teid "$(ncore_pfcp_rules abc 1 >/dev/null 2>&1; echo $?)" "2"

    # 10. GTP-U: the N3 tunnel header and the QFI extension.
    out=$(ncore_gtpu_header 305419896 9)
    chk gtpu-teid     "$(fld "$out" teid)"      "305419896"
    chk gtpu-teid-hex "$(fld "$out" teid_hex)"  "12345678"
    chk gtpu-qfi      "$(fld "$out" qfi)"       "9"
    chk gtpu-ver      "$(fld "$out" version)"   "1"
    chk gtpu-pt       "$(fld "$out" protocol_type)" "1 (GTP)"
    chk gtpu-eflag    "$(fld "$out" e_flag)"    "1"
    chk gtpu-oa       "$(fld "$out" message_type_name)" "G-PDU"
    chk gtpu-bytes    "$(fld "$out" base_header_octets)" "8"
    chk gtpu-bad-teid "$(ncore_gtpu_header abc 1 >/dev/null 2>&1; echo $?)" "2"
    chk gtpu-bad-qfi  "$(ncore_gtpu_header 1 64 >/dev/null 2>&1; echo $?)"  "2"
    # Round-trip: the emitted header hex must decode back to the same values.
    local hdr; hdr=$(fld "$out" header_hex)
    hdr="${hdr// /}"
    out=$(ncore_decode_gtpu "$hdr")
    chk gtpu-rt-teid  "$(fld "$out" teid)"     "305419896"
    chk gtpu-rt-qfi   "$(fld "$out" qfi)"      "9"
    chk gtpu-rt-name  "$(fld "$out" message_type_name)" "G-PDU"
    chk gtpu-rt-ver   "$(fld "$out" version)"  "1"
    chk gtpu-bad-gtp  "$(ncore_decode_gtpu '0000000000000000' >/dev/null 2>&1; echo $?)" "1"

    # 11. NF API roots: the real service names.
    chk nf-nrf-disc "$(ncore_nf_table | awk -F'\t' '$2=="nnrf-disc"{print $3; exit}')" "/nnrf-disc/v1"
    chk nf-ausf     "$(ncore_nf_table | awk -F'\t' '$2=="nausf-auth"{print $3; exit}')" "/nausf-auth/v1"
    chk nf-udm-sdm  "$(ncore_nf_table | awk -F'\t' '$2=="nudm-sdm"{print $3; exit}')"  "/nudm-sdm/v2"
    chk nf-udm-ueau "$(ncore_nf_table | awk -F'\t' '$2=="nudm-ueau"{print $3; exit}')" "/nudm-ueau/v1"
    chk nf-smf      "$(ncore_nf_table | awk -F'\t' '$2=="nsmf-pdusession"{print $3; exit}')" "/nsmf-pdusession/v1"
    chk nf-amf      "$(ncore_nf_table | awk -F'\t' '$2=="namf-comm"{print $3; exit}')" "/namf-comm/v1"
    chk nf-nef      "$(ncore_nf_table | awk -F'\t' '$2=="nnef-smf-event-exposure"{print $3; exit}')" "/nnef-smf-event-exposure/v1"
    chk nf-pcf      "$(ncore_nf_table | awk -F'\t' '$2=="npcf-am-policy-control"{print $3; exit}')" "/npcf-am-policy-control/v1"
    chk nf-list-hdr "$(ncore_nf_list | head -1)" "nf	service	api_root	description"
    chk nf-list-rows "$(ncore_nf_list | tail -n +2 | grep -c . | awk '{print ($1>=20)?"ok":"short"}')" "ok"

    # 12. NF discovery request shape.
    out=$(ncore_nf_discovery AMF)
    chk disc-method "$(fld "$out" method)" "GET"
    chk disc-path   "$(fld "$out" path)"   "/nnrf-disc/v1/nf-instances"
    chk disc-target "$(fld "$out" query)"  "target-nf-type=AMF"
    chk disc-req    "$(fld "$out" query_requester)" "req-nf-type=AMF"
    chk disc-api    "$(fld "$out" exposes)" "/namf-comm/v1"
    chk disc-bad    "$(ncore_nf_discovery NOPE >/dev/null 2>&1; echo $?)" "1"
    chk disc-none   "$(ncore_nf_discovery '' >/dev/null 2>&1; echo $?)"   "1"

    # 13. 5G-AKA flow shape: every real step present.
    out=$(ncore_aka_flow)
    chk aka-steps     "$(printf '%s\n' "$out" | grep -c '^step	')" "12"
    chk aka-suci      "$(printf '%s\n' "$out" | grep -c 'SUCI')"    "4"
    chk aka-kseaf     "$(printf '%s\n' "$out" | grep -c 'KSEAF')"   "1"
    chk aka-ausf      "$(printf '%s\n' "$out" | grep -c 'nausf-auth')" "1"
    chk aka-udm       "$(printf '%s\n' "$out" | grep -c 'nudm-ueau')"  "1"
    chk aka-serving   "$(printf '%s\n' "$out" | grep -c 'serving network name')" "2"

    # 14. KSEAF derivation. TS 33.501 §A.2 defines
    #     KSEAF = HMAC-SHA-256(KAUSF, 0x6C || serving network name).
    #     Verified against an independent openssl computation below.
    if command -v openssl >/dev/null 2>&1; then
        local kausf sn_name want got
        kausf=$(printf 'a%.0s' $(seq 1 64))
        sn_name="5G:mnc001.mcc208.3gppnetwork.org"
        got=$(ncore_kseaf "$kausf" "$sn_name")
        want=$(printf '6c%s' "$(printf '%s' "$sn_name" | xxd -p | tr -d '\n')" \
               | xxd -r -p | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$kausf" -binary \
               | xxd -p | tr -d '\n')
        chk kseaf-value   "$(fld "$got" kseaf)" "$want"
        chk kseaf-p0      "$(fld "$got" p0)"    "6C"
        chk kseaf-bits    "$(fld "$got" kseaf_bits)" "256"
        chk kseaf-len     "$(printf '%s' "$(fld "$got" kseaf)" | wc -c)" "64"
        chk kseaf-mac-in  "$(fld "$got" mac_input_hex)" "6c35473a6d6e633030312e6d63633230382e336770706e6574776f726b2e6f7267"
        # The serving network name is a security input: a different SN must
        # produce a different KSEAF, which is the anti-replay binding.
        got=$(ncore_kseaf "$kausf" "5G:mnc002.mcc208.3gppnetwork.org")
        chk kseaf-binding "$([[ "$(fld "$got" kseaf)" != "$want" ]] && echo differs || echo same)" "differs"
        chk kseaf-bad-key "$(ncore_kseaf 1234 sn >/dev/null 2>&1; echo $?)" "2"
        chk kseaf-no-sn   "$(ncore_kseaf "$kausf" '' >/dev/null 2>&1; echo $?)" "2"
    else
        printf 'kseaf-derivation\tSKIP openssl not installed\n'
    fi

    # 15. Plan files carry status: handoff and name the testbed.
    local p
    for p in n2-expose nrf-discovery sepp-bypass ipx-attack; do
        out=$(ncore_plan "$p")
        chk "plan-$p-status" "$(fld "$out" status)" "handoff"
        chk "plan-$p-file"   "$([[ -f "$NCORE_PLAN_DIR/${p}.plan" ]] && echo yes || echo no)" "yes"
        chk "plan-$p-field"  "$(grep -c '^status: handoff$' "$NCORE_PLAN_DIR/${p}.plan")" "1"
        chk "plan-$p-testbed" "$(grep -c '^testbed_required:' "$NCORE_PLAN_DIR/${p}.plan")" "1"
        chk "plan-$p-steps"   "$(grep -c '^steps:' "$NCORE_PLAN_DIR/${p}.plan")" "1"
        chk "plan-$p-nonempty" "$(awk '/^testbed_required:/{getline; if (length($0)>10) print "yes"; exit}' \
                                  "$NCORE_PLAN_DIR/${p}.plan")" "yes"
    done
    chk plan-bad "$(ncore_plan nonsense >/dev/null 2>&1; echo $?)" "2"
    chk plan-none "$(ncore_plan '' >/dev/null 2>&1; echo $?)"      "2"

    # 16. Verb validation returns non-zero and never prints success.
    chk cli-ngap-noargs   "$(ncore_cmd_decode_ngap >/dev/null 2>&1; echo $?)"   "2"
    chk cli-ngap-badlen   "$(ncore_cmd_decode_ngap ABC >/dev/null 2>&1; echo $?)" "1"
    chk cli-nas-noargs    "$(ncore_cmd_decode_nas >/dev/null 2>&1; echo $?)"    "2"
    chk cli-nas-badhex    "$(ncore_cmd_decode_nas QQ >/dev/null 2>&1; echo $?)" "1"
    chk cli-pfcp-noargs   "$(ncore_cmd_decode_pfcp >/dev/null 2>&1; echo $?)"   "2"
    chk cli-pfcp-short    "$(ncore_cmd_decode_pfcp 20 >/dev/null 2>&1; echo $?)" "1"
    chk cli-gtpu-noargs   "$(ncore_cmd_decode_gtpu >/dev/null 2>&1; echo $?)"   "2"
    chk cli-guti-noargs   "$(ncore_cmd_decode_guti >/dev/null 2>&1; echo $?)"   "2"
    chk cli-discovery-bad "$(ncore_cmd_nf_discovery ZZZ >/dev/null 2>&1; echo $?)" "1"
    chk cli-plan-bad      "$(ncore_cmd_plan badname >/dev/null 2>&1; echo $?)"  "2"
    chk cli-ueids-noargs  "$(ncore_cmd_ue_id_pair >/dev/null 2>&1; echo $?)"    "2"
    chk cli-kseaf-noargs  "$(ncore_cmd_kseaf >/dev/null 2>&1; echo $?)"         "2"
    chk cli-unknown       "$(ncore_cli_main --wat >/dev/null 2>&1; echo $?)"    "2"

    # 17. Status TSV contract.
    out=$(ncore_cli_status_tsv)
    chk status-dir    "$(fld "$out" dir)"      "$NCORE_DIR"
    chk status-plandir "$(fld "$out" plan_dir)" "$NCORE_PLAN_DIR"
    chk status-keys   "$(printf '%s\n' "$out" | grep -c . | awk '{print ($1>=6)?"ok":"short"}')" "ok"

    # 18. TSV injection: a tab in an untrusted string must not forge a row.
    local evil
    evil=$(ncore_sanitize $'AMF\tfake\trow\nmore')
    chk sanitize-tabs "$(printf '%s' "$evil" | awk -F'\t' '{print NF}')" "1"
    chk sanitize-nl   "$(printf '%s' "$evil" | grep -c .)" "1"

    rm -rf "$d"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ── menu ────────────────────────────────────────────────────────────────
ncore_menu() {
    while true; do
        banner
        echo -e "  ${C_MAG}=== 5G core (SBA) ===${C_RESET}"
        echo -e "  core: ${C_GRN}$(ncore_find_open5gs || echo 'missing (install Open5GS)')${C_RESET}"
        echo -e "  cap:  ${C_GRN}$(ncore_find_capture_tool || echo 'missing (install tshark)')${C_RESET}"
        echo -e "  plans:${C_DIM}$NCORE_PLAN_DIR${C_RESET}\n"
        cat << 'M'
  [1]  NF list and API roots
  [2]  NF discovery request (NRF)
  [3]  decode NGAP (N2)
  [4]  decode NAS 5GS
  [5]  decode PFCP (N4)
  [6]  decode GTP-U (N3)
  [7]  decode 5G-GUTI
  [8]  UE NGAP ID pairing
  [9]  5G-AKA / EAP-AKA' flow
  [10] KSEAF derivation from KAUSF
  [11] plan: N2 exposure
  [12] plan: NRF discovery
  [13] plan: SEPP bypass
  [14] plan: IPX attack
  [15] status
  [0]  back

M
        local c
        read -rp "  choice> " c || return 0  # EOF: leave the menu cleanly
        case "$c" in
            1) ncore_cmd_nf_list | column -t -s$'\t' 2>/dev/null; read -rp "  press enter " _ ;;
            2)
                read -rp "  target NF/service (AMF)> " t
                ncore_cmd_nf_discovery "${t:-AMF}" | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            3)
                read -rp "  NGAP hex> " h
                ncore_cmd_decode_ngap "$h" | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            4)
                read -rp "  NAS hex (e.g. 7E4100)> " h
                ncore_cmd_decode_nas "$h" | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            5)
                read -rp "  PFCP hex> " h
                ncore_cmd_decode_pfcp "$h" | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            6)
                read -rp "  GTP-U hex> " h
                ncore_cmd_decode_gtpu "$h" | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            7)
                read -rp "  5G-GUTI hex (20 digits)> " h
                ncore_cmd_decode_guti "$h" | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            8)
                read -rp "  RAN UE NGAP ID> " r
                read -rp "  AMF UE NGAP ID> " a
                read -rp "  5G-TMSI (optional)> " t
                ncore_cmd_ue_id_pair "$r" "$a" "$t" | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            9) ncore_aka_flow | column -t -s$'\t' 2>/dev/null; read -rp "  press enter " _ ;;
            10)
                read -rp "  KAUSF hex (64 digits)> " k
                read -rp "  serving network name> " s
                ncore_cmd_kseaf "$k" "$s" | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            11) ncore_cmd_plan n2-expose    | column -t -s$'\t' 2>/dev/null; read -rp "  press enter " _ ;;
            12) ncore_cmd_plan nrf-discovery | column -t -s$'\t' 2>/dev/null; read -rp "  press enter " _ ;;
            13) ncore_cmd_plan sepp-bypass  | column -t -s$'\t' 2>/dev/null; read -rp "  press enter " _ ;;
            14) ncore_cmd_plan ipx-attack   | column -t -s$'\t' 2>/dev/null; read -rp "  press enter " _ ;;
            15) ncore_status | column -t -s$'\t' 2>/dev/null; read -rp "  press enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ── CLI dispatch ────────────────────────────────────────────────────────
ncore_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)      ncore_cli_status_tsv ;;
        --nf-list)         ncore_cmd_nf_list ;;
        --nf-discovery)    ncore_cmd_nf_discovery "${1:-}" "${2:-AMF}" ;;
        --decode-ngap)     ncore_cmd_decode_ngap "${1:-}" ;;
        --decode-nas-5gs)  ncore_cmd_decode_nas "${1:-}" ;;
        --decode-pfcp)     ncore_cmd_decode_pfcp "${1:-}" ;;
        --decode-gtpu)     ncore_cmd_decode_gtpu "${1:-}" ;;
        --decode-5g-guti)  ncore_cmd_decode_guti "${1:-}" ;;
        --ue-id-pair)      ncore_cmd_ue_id_pair "${1:-}" "${2:-}" "${3:-}" ;;
        --aka-flow)        ncore_aka_flow ;;
        --kseaf)           ncore_cmd_kseaf "${1:-}" "${2:-}" ;;
        --pfcp-rules)      ncore_pfcp_rules "${1:-1}" "${2:-1}" ;;
        --gtpu-header)     ncore_gtpu_header "${1:-1}" "${2:-1}" ;;
        --plan)            ncore_cmd_plan "${1:-}" ;;
        --selftest)        ncore_selftest ;;
        --menu)            ncore_menu ;;
        *)
            cat >&2 <<EOF
5G Core (SBA) — SBA, N2/N3/N4, 5G-AKA, roaming attack surface

Usage: $0 COMMAND
  --status-tsv                  installed cores, capture tools and plan state
  --nf-list                     NF service table with the real API roots
  --nf-discovery <NF|service> [requester]
                                the NRF discovery request an NF sends
  --decode-ngap <hex>           NGAP PDU type, procedure code and name
  --decode-nas-5gs <hex>        NAS security header type and 5GMM message type
  --decode-pfcp <hex>           PFCP message type, SEID and sequence
  --decode-gtpu <hex>           GTP-U header, TEID and QFI extension
  --decode-5g-guti <hex>        PLMN, AMF region/set/pointer, 5G-TMSI
  --ue-id-pair <ran> <amf> [tmsi]
                                the RAN/AMF UE NGAP ID pairing
  --aka-flow                    5G-AKA / EAP-AKA' message flow
  --kseaf <kausf-hex> <sn-name> KSEAF = HMAC-SHA-256(KAUSF, 0x6C || SN name)
  --pfcp-rules [teid] [qfi]     the PDR/FAR/QER/URR rule structure
  --gtpu-header [teid] [qfi]    build an N3 GTP-U header with the QFI
  --plan <name>                 write a handoff plan
                                (n2-expose|nrf-discovery|sepp-bypass|ipx-attack)
  --selftest                    verify the decoders without a core network
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
    ncore_cli_main "$@"
fi
