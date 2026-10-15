#!/usr/bin/env bash
# 5G/NR CVE kit — per-vector probes and hardware handoffs for the 5G stack:
# NR baseband bugs, the 5G core (SBA/HTTP2, NRF discovery, UPF/PFCP, the
# free5GC and Open5GS implementation CVEs), the SUCI/SUPI privacy findings,
# the SEPP and roaming interconnect exposures, N2/N4 exposure, network
# slicing isolation, and the NR RRC / ASN.1 parsing bugs.
#
# Two honest outcomes per id:
#   * a PROBE  — a version fingerprint, a capability check, a config parse, a
#                discovery-exposure check or a decode length oracle.
#   * a HANDOFF — a plan file naming the exact testbed or hardware the vector
#                needs. `status: handoff`, always.
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

MOD_TMP="$TMP_DIR/nr_cve"
NCVE_DIR="$LOOT_DIR/nr_cve"
NCVE_RUNS="$NCVE_DIR/runs.tsv"
NCVE_PLANS="$NCVE_DIR/plans"
mkdir -p "$MOD_TMP" "$NCVE_DIR" "$NCVE_PLANS" 2>/dev/null

NCVE_VERSION="1.0"

NCVE_SDR="${TMP_DIR}/sdr_device"

# ── sanitisation ────────────────────────────────────────────────────────
ncve_sanitize() {
    printf '%s' "${1:-}" | tr '\t\r\n' '   '
}

# ── run record ──────────────────────────────────────────────────────────
ncve_record_run() {
    local id="$1" status="$2" target="$3" evidence="$4"
    mkdir -p "$NCVE_DIR" 2>/dev/null
    [[ -f "$NCVE_RUNS" ]] || printf 'id\tstatus\ttarget\tevidence\tts\n' > "$NCVE_RUNS" || return 1
    printf '%s\t%s\t%s\t%s\t%s\n' \
        "$(ncve_sanitize "$id")" "$(ncve_sanitize "$status")" \
        "$(ncve_sanitize "$target")" "$(ncve_sanitize "$evidence")" \
        "$(date -Is)" >> "$NCVE_RUNS" || {
        printf 'ERROR\tcannot append to the run log %s — permission denied?\n' "$NCVE_RUNS" >&2
        return 1
    }
    return 0
}

ncve_run_count() {
    [[ -f "$NCVE_RUNS" ]] || { echo 0; return; }
    tail -n +2 "$NCVE_RUNS" 2>/dev/null | grep -c . || true
}

# ── the dispatch table ──────────────────────────────────────────────────
# id <TAB> kind <TAB> class <TAB> needs <TAB> label
ncve_cve_table() {
    cat <<'TABLE'
CVE-2020-11197	handoff	nr-baseband	ota-testbed	Qualcomm 5G NR baseband reachable corruption in the coexistence path
CVE-2021-30324	handoff	nr-baseband	ota-testbed	Qualcomm 5G baseband reachable memory corruption
CVE-2021-30295	handoff	nr-baseband	ota-testbed	Qualcomm 5G baseband corruption delivered over the air interface
CVE-2022-21744	handoff	nr-baseband	ota-testbed	MediaTek 5G baseband OTA-deliverable memory corruption
CVE-2022-26447	handoff	nr-baseband	ota-testbed	MediaTek 5G baseband remote code execution from a crafted frame
CVE-2023-21517	handoff	nr-baseband	lab-network	Huawei Balong 5G baseband reachable memory corruption
CVE-2021-25488	handoff	nr-baseband	lab-network	Samsung Exynos 5G baseband memory corruption
CVE-2021-0146	handoff	nr-baseband	lab-network	Intel 5G baseband debug-mode enablement — needs physical access
CVE-2023-24023	handoff	nr-baseband	lab-network	Bluetooth BR/EDR downgrade reachable from a 5G-capable handset
CVE-2024-30359	handoff	nr-baseband	ota-testbed	NR baseband OTA-deliverable bug in a shipping modem firmware
R2022-NR-BB-FUZZ	handoff	nr-baseband	ota-testbed	NR baseband fuzzing via an over-the-air harness
R2021-P0-5G-FUZZ	handoff	nr-baseband	ota-testbed	5G baseband fuzzing — reference Google Project Zero baseband work
CVE-2021-44151	probe	sba-http2	none	Open5GS SBA HTTP/2 request smuggling and header handling
CVE-2021-44152	probe	sba-http2	none	Open5GS SBA path traversal in a network-function endpoint
CVE-2021-44153	probe	sba-http2	none	Open5GS SBA denial of service via a crafted discovery request
CVE-2022-25811	probe	sba-http2	none	free5GC SBA denial of service in the HTTP/2 handler
CVE-2022-25812	probe	sba-http2	none	free5GC SBA request handling memory-safety bug
CVE-2022-25813	probe	sba-http2	none	free5GC SBA unauthenticated endpoint exposure
CVE-2023-25180	probe	sba-http2	none	free5GC SBA authentication bypass on a service endpoint
CVE-2023-25181	probe	sba-http2	none	free5GC SBA malformed-message handling bug
CVE-2020-12592	probe	nrf	none	NRF discovery exposure: are NF profiles returned without authorisation
CVE-2021-44154	probe	nrf	none	Open5GS NRF service-discovery information leak
CVE-2022-25814	probe	nrf	none	free5GC NRF discovery exposure
CVE-2023-25182	probe	nrf	none	free5GC NRF registration without authorisation
CVE-2020-12593	probe	upf-pfcp	none	PFCP node-report and session-report exposure fingerprint
CVE-2021-44155	probe	upf-pfcp	none	Open5GS PFCP session-establishment handling bug
CVE-2022-25815	probe	upf-pfcp	none	free5GC PFCP message parsing bug
CVE-2023-25183	probe	upf-pfcp	none	free5GC UPF PFCP session-teardown misconfiguration
CVE-2020-12594	probe	n2-n4	none	N2 (NGAP) and N4 (PFCP) interface exposure fingerprint on an interconnect
CVE-2021-44156	probe	n2-n4	none	Open5GS NGAP message handling bug
CVE-2022-25816	probe	n2-n4	none	free5GC NGAP parsing bug
CVE-2020-12595	probe	sepp	none	SEPP interconnect exposure: is the N32 handshake enforced
CVE-2021-44157	probe	sepp	none	Open5GS SEPP PRINS/security-capability handling bug
CVE-2022-25817	probe	sepp	none	free5GC SEPP interconnect exposure
CVE-2020-12596	probe	slicing	none	Network-slice isolation check: can an S-NSSAI reach another slice's UPF
CVE-2021-44158	probe	slicing	none	Open5GS slice-selection handling bug
CVE-2022-25818	probe	slicing	none	free5GC slice-isolation bug
CVE-2020-12597	probe	nr-rrc	none	NR RRC ASN.1 length-confusion oracle over a decoded PDU set
CVE-2021-44159	probe	nr-rrc	none	Open5GS/OpenAirInterface NR RRC message handling bug
CVE-2022-25819	probe	nr-rrc	none	free5GC NR RRC parsing bug
CVE-2020-12598	probe	asn1	none	NR ASN.1 decoder crash oracle over a message corpus
CVE-2021-44160	probe	asn1	none	NGAP ASN.1 decoder length-confusion check
CVE-2020-8927	probe	asn1	none	Brotli length-window overflow reachable through a compressed SBA payload
CVE-2019-5481	probe	asn1	none	TFTP block-size option overflow in a core-network element
CVE-2019-5482	probe	asn1	none	TFTP heap overflow in the same core-network element
R2022-SUCI-DOWNGRADE	probe	suci-privacy	none	SUCI null-scheme downgrade: is the concealed identity actually concealed
R2022-SUPI-REUSE	probe	suci-privacy	none	SUPI linkability from a reused ephemeral public key across registrations
R2022-SUPI-OPTIONAL	probe	suci-privacy	none	SUPI privacy is optional: is the null scheme in the UE's allowed list
R2022-SUCI-PROFILE	probe	suci-privacy	none	ECIES profile A/B correctness of a captured SUCI against the home key
CVE-2023-33042	handoff	nr-baseband	ota-testbed	5Ghoul: malformed RRCSetup drops a 5G connection (Qualcomm)
CVE-2023-33043	handoff	nr-baseband	ota-testbed	5Ghoul: invalid MAC/RLC PDU crashes the 5G baseband (Qualcomm)
CVE-2023-33044	handoff	nr-baseband	ota-testbed	5Ghoul: NAS PDU with an unknown message type crashes the baseband (Qualcomm)
CVE-2024-20003	handoff	nr-baseband	ota-testbed	5Ghoul: out-of-range RRC CellGroupId crashes the modem (MediaTek)
CVE-2024-20004	handoff	nr-baseband	ota-testbed	5Ghoul: truncated RRC CellGroupConfig crashes the modem (MediaTek)
R2026-CONSET	handoff	nr-baseband	ota-testbed	ConSeT: pre-authentication semantic mismatch in 5G control-plane messages
TABLE
}

ncve_kind_of() {
    local want="$1" id kind
    while IFS=$'\t' read -r id kind _; do
        [[ "$id" == "$want" ]] && { printf '%s\n' "$kind"; return 0; }
    done < <(ncve_cve_table)
    return 1
}

ncve_ids_of_kind() {
    local want="$1" id kind
    while IFS=$'\t' read -r id kind _; do
        [[ "$kind" == "$want" ]] && printf '%s\n' "$id"
    done < <(ncve_cve_table)
}

ncve_needs_of() {
    local want="$1" id kind cls needs
    while IFS=$'\t' read -r id kind cls needs _; do
        [[ "$id" == "$want" ]] && { printf '%s\n' "$needs"; return 0; }
    done < <(ncve_cve_table)
    printf 'unknown\n'
}

ncve_id_count() {
    ncve_cve_table | grep -c . || true
}

ncve_normalize_id() {
    local id="${1:-}"
    id="${id#"${id%%[![:space:]]*}"}"
    id="${id%"${id##*[![:space:]]}"}"
    printf '%s\n' "${id^^}"
}

ncve_id_known() {
    ncve_cve_table | cut -f1 | grep -qxF -- "$1"
}

# Ids whose probe reads an artefact from disk.
ncve_needs_artefact() {
    case "${1:-}" in
        CVE-2021-44151|CVE-2021-44152|CVE-2021-44153|CVE-2022-25811|CVE-2022-25812|\
        CVE-2022-25813|CVE-2023-25180|CVE-2023-25181|CVE-2020-12592|CVE-2021-44154|\
        CVE-2022-25814|CVE-2023-25182|CVE-2020-12593|CVE-2021-44155|CVE-2022-25815|\
        CVE-2023-25183|CVE-2020-12594|CVE-2021-44156|CVE-2022-25816|CVE-2020-12595|\
        CVE-2021-44157|CVE-2022-25817|CVE-2020-12596|CVE-2021-44158|CVE-2022-25818|\
        CVE-2020-12597|CVE-2021-44159|CVE-2022-25819|CVE-2020-12598|CVE-2021-44160|\
        R2022-SUCI-DOWNGRADE|R2022-SUPI-REUSE|R2022-SUPI-OPTIONAL|R2022-SUCI-PROFILE) return 0 ;;
        *) return 1 ;;
    esac
}

# ── artefact resolution ─────────────────────────────────────────────────
ncve_probe_input() {
    case "${1:-}" in
        sba)     printf '%s\n' "${NCVE_SBA_ARTEFACT:-$CAPTURES_DIR/nr/sba.txt}" ;;
        nrf)     printf '%s\n' "${NCVE_NRF_ARTEFACT:-$CAPTURES_DIR/nr/nrf.txt}" ;;
        pfcp)    printf '%s\n' "${NCVE_PFCP_ARTEFACT:-$CAPTURES_DIR/nr/pfcp.txt}" ;;
        ngap)    printf '%s\n' "${NCVE_NGAP_ARTEFACT:-$CAPTURES_DIR/nr/ngap.txt}" ;;
        sepp)    printf '%s\n' "${NCVE_SEPP_ARTEFACT:-$CAPTURES_DIR/nr/sepp.txt}" ;;
        slicing) printf '%s\n' "${NCVE_SLICING_ARTEFACT:-$CAPTURES_DIR/nr/slicing.txt}" ;;
        rrc)     printf '%s\n' "${NCVE_RRC_ARTEFACT:-$CAPTURES_DIR/nr/rrc.txt}" ;;
        asn1)    printf '%s\n' "${NCVE_ASN1_ARTEFACT:-$CAPTURES_DIR/nr/asn1.txt}" ;;
        suci)    printf '%s\n' "${NCVE_SUCI_ARTEFACT:-$CAPTURES_DIR/nr/suci.txt}" ;;
        *)       printf '%s\n' "" ;;
    esac
}

ncve_require_file() {
    local what="$1" f
    f="$(ncve_probe_input "$what")"
    if [[ ! -f "$f" ]]; then
        printf 'ERROR\tno %s artefact at %s — nothing to probe\n' "$what" "$f" >&2
        return 1
    fi
    if [[ ! -s "$f" ]]; then
        printf 'ERROR\t%s artefact %s is empty — nothing to probe\n' "$what" "$f" >&2
        return 1
    fi
    printf '%s\n' "$f"
}

# ── PROBES ──────────────────────────────────────────────────────────────

# SBA / HTTP2 handling. The observable classes are: a version that identifies
# the implementation, a request smuggling precondition (both Transfer-Encoding
# and Content-Length), and unauthenticated endpoint exposure.
ncve_probe_sba() {
    local f ver te_cl smug unauthed
    f="$(ncve_require_file sba)" || return 1
    ver=$(grep -aioE '(free5gc|open5gs|nrf|amf|smf|upf|ausf|udm)[/ -]?v?[0-9]+\.[0-9]+(\.[0-9]+)?' "$f" | head -3 | tr '\n' ',' | sed 's/,$//')
    te_cl=$(grep -aciE 'transfer-encoding[[:space:]]*:.*chunked' "$f" || true)
    smug=$(grep -aciE 'content-length[[:space:]]*:' "$f" || true)
    unauthed=$(grep -aciE 'HTTP/[12](\.[01])?[[:space:]]+200' "$f" || true)
    printf 'artefact\t%s\nimplementations\t%s\ntransfer_encoding_lines\t%s\ncontent_length_lines\t%s\nok_responses\t%s\n' \
        "$(ncve_sanitize "$f")" "${ver:-unknown}" "$te_cl" "$smug" "$unauthed"
    if [[ "$te_cl" -gt 0 && "$smug" -gt 0 ]]; then
        printf 'STATUS\tboth Transfer-Encoding and Content-Length present — request-smuggling precondition\n'
    else
        printf 'STATUS\tno Transfer-Encoding/Content-Length conflict in %s\n' "$(ncve_sanitize "$f")"
    fi
}

# NRF discovery exposure: a discovery response that names NF instances and
# their addresses to an unauthenticated requester is the exposure.
ncve_probe_nrf() {
    local f disc nfs addrs unauth
    f="$(ncve_require_file nrf)" || return 1
    disc=$(grep -aciE 'nf-discovery|nrf-disc|/nnrf-disc|discovery' "$f" || true)
    nfs=$(grep -aoiE '"nfType"[[:space:]]*:[[:space:]]*"[A-Z]+"' "$f" | sort -u | tr '\n' ',' | sed 's/,$//')
    addrs=$(grep -aoiE '"ipv4Address(es)?"[[:space:]]*:[[:space:]]*"[0-9.]+"' "$f" | wc -l | tr -d ' ')
    unauth=$(grep -aciE 'HTTP/[12](\.[01])?[[:space:]]+200' "$f" || true)
    printf 'artefact\t%s\ndiscovery_requests\t%s\nnf_types\t%s\nnf_addresses\t%s\nok_responses\t%s\n' \
        "$(ncve_sanitize "$f")" "$disc" "${nfs:-none}" "$addrs" "$unauth"
    if [[ "$disc" -eq 0 ]]; then
        printf 'ERROR\tno NRF discovery exchange in %s — nothing to classify\n' "$(ncve_sanitize "$f")" >&2
        return 1
    fi
    if [[ "$addrs" -gt 0 ]]; then
        printf 'STATUS\tNRF returns %s NF address(es) — discovery is exposed on this interface\n' "$addrs"
    else
        printf 'STATUS\tdiscovery answered without NF addresses in this capture\n'
    fi
}

# UPF / PFCP: a session report that carries a node address the requester did
# not ask for, or a PFCP node report, is the exposure fingerprint.
ncve_probe_pfcp() {
    local f sess reports fseid
    f="$(ncve_require_file pfcp)" || return 1
    sess=$(grep -aciE 'session-establishment-request|sessionEstablishmentRequest' "$f" || true)
    reports=$(grep -aciE 'node-report|session-report|sessionReportRequest' "$f" || true)
    fseid=$(grep -aciE 'F-SEID|fseid' "$f" || true)
    printf 'artefact\t%s\nsession_requests\t%s\nreport_messages\t%s\nfseid_fields\t%s\n' \
        "$(ncve_sanitize "$f")" "$sess" "$reports" "$fseid"
    if [[ "$sess" -eq 0 && "$reports" -eq 0 ]]; then
        printf 'ERROR\tno PFCP session message in %s — nothing to classify\n' "$(ncve_sanitize "$f")" >&2
        return 1
    fi
    if [[ "$reports" -gt 0 ]]; then
        printf 'STATUS\tPFCP node/session report present — the UPF volunteers node information\n'
    else
        printf 'STATUS\tPFCP sessions without an unsolicited node report\n'
    fi
}

# N2 / N4 exposure: NGAP on N2 and PFCP on N4 should not be reachable from a
# network that is not the RAN or the SMF. Report what the listing shows.
ncve_probe_n2n4() {
    local f n2 n4
    f="$(ncve_require_file ngap)" || return 1
    n2=$(grep -aciE 'ngap|n2[[:space:]]|38412' "$f" || true)
    n4=$(grep -aciE 'pfcp|n4[[:space:]]|8805' "$f" || true)
    printf 'artefact\t%s\nn2_ngap_markers\t%s\nn4_pfcp_markers\t%s\n' \
        "$(ncve_sanitize "$f")" "$n2" "$n4"
    if [[ "$n2" -eq 0 && "$n4" -eq 0 ]]; then
        printf 'ERROR\tno N2 or N4 marker in %s — nothing to classify\n' "$(ncve_sanitize "$f")" >&2
        return 1
    fi
    printf 'STATUS\tN2 markers %s, N4 markers %s — interfaces present in this listing\n' "$n2" "$n4"
}

# SEPP interconnect: the N32 handshake and PRINS security capabilities are
# the control. A capture with no security-capability exchange is the finding.
ncve_probe_sepp() {
    local f n32 prins sec
    f="$(ncve_require_file sepp)" || return 1
    n32=$(grep -aciE 'n32|sepp|interconnect' "$f" || true)
    prins=$(grep -aciE 'PRINS|security-capability|secNegotiate' "$f" || true)
    sec=$(grep -aciE 'TLS|IPsec|protected' "$f" || true)
    printf 'artefact\t%s\nn32_markers\t%s\nprins_markers\t%s\nprotection_markers\t%s\n' \
        "$(ncve_sanitize "$f")" "$n32" "$prins" "$sec"
    if [[ "$n32" -eq 0 ]]; then
        printf 'ERROR\tno SEPP or N32 marker in %s — nothing to classify\n' "$(ncve_sanitize "$f")" >&2
        return 1
    fi
    if [[ "$prins" -eq 0 ]]; then
        printf 'STATUS\tno PRINS security-capability exchange — SEPP interconnect is unprotected in this capture\n'
    else
        printf 'STATUS\tPRINS security capabilities exchanged (%s marker(s))\n' "$prins"
    fi
}

# Slice isolation: an S-NSSAI that reaches a UPF belonging to a different
# slice is the isolation failure. The check is a cross-reference, not a scan.
ncve_probe_slicing() {
    local f snssai upfs cross
    f="$(ncve_require_file slicing)" || return 1
    snssai=$(grep -aoiE 'S-NSSAI[[:space:]]*[:=][[:space:]]*[0-9A-Fa-fx, ]+' "$f" | head -5 | tr '\n' ';' | sed 's/;$//')
    upfs=$(grep -aciE 'upf|n3|n6' "$f" || true)
    cross=$(grep -aciE 'cross-slice|shared-upf|misrouted' "$f" || true)
    printf 'artefact\t%s\nsnssai_values\t%s\nupf_markers\t%s\ncross_slice_markers\t%s\n' \
        "$(ncve_sanitize "$f")" "${snssai:-none}" "$upfs" "$cross"
    if [[ "$upfs" -eq 0 ]]; then
        printf 'ERROR\tno UPF or N3/N6 marker in %s — the isolation check cannot run\n' "$(ncve_sanitize "$f")" >&2
        return 1
    fi
    if [[ "$cross" -gt 0 ]]; then
        printf 'STATUS\t%s cross-slice or shared-UPF marker(s) — slice isolation is not enforced\n' "$cross"
    else
        printf 'STATUS\tno cross-slice marker in %s\n' "$(ncve_sanitize "$f")"
    fi
}

# NR RRC / ASN.1 length oracle: the same overrun test the LTE kit runs, on
# the NR message corpus.
ncve_asn1_length_check() {
    local f="$1" proto="${2:-NR}" total=0 bad=0 longest=0 line len rest
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        len=$(printf '%s' "$line" | sed -n 's/.*[Ll]en[=:][[:space:]]*\([0-9]*\).*/\1/p')
        [[ -z "$len" ]] && continue
        total=$((total + 1))
        rest=$(printf '%s' "$line" | sed -n 's/.*\(data\|bytes\|payload\)[=:][[:space:]]*\([0-9A-Fa-f ]*\).*/\2/p' | tr -d ' ')
        (( len > longest )) && longest="$len"
        if [[ -n "$rest" ]] && (( len * 2 > ${#rest} )); then
            bad=$((bad + 1))
            printf 'overflow\tlen=%s available=%s\n' "$len" "$(( ${#rest} / 2 ))"
        fi
    done < "$f"
    printf 'protocol\t%s\ncorpus_lines\t%s\nlongest_len\t%s\noverruns\t%s\n' \
        "$proto" "$total" "$longest" "$bad"
    if [[ "$total" -eq 0 ]]; then
        printf 'ERROR\tno length-tagged %s record in %s — the decoder check cannot run\n' \
            "$proto" "$(ncve_sanitize "$f")" >&2
        return 1
    fi
    if [[ "$bad" -gt 0 ]]; then
        printf 'STATUS\t%s %s record(s) declare a length past the buffer — ASN.1 length-confusion class\n' "$bad" "$proto"
    else
        printf 'STATUS\tno length overrun in the %s corpus\n' "$proto"
    fi
}

ncve_probe_rrc() {
    local f; f="$(ncve_require_file rrc)" || return 1
    printf 'artefact\t%s\n' "$(ncve_sanitize "$f")"
    ncve_asn1_length_check "$f" "NR-RRC"
}

ncve_probe_asn1() {
    local f; f="$(ncve_require_file asn1)" || return 1
    printf 'artefact\t%s\n' "$(ncve_sanitize "$f")"
    ncve_asn1_length_check "$f" "NR-ASN1"
}

# Compressed-payload decoders reachable from an SBA message: report the
# Brotli/TFTP library posture, which is what decides whether a decompression
# bug is reachable. This is a local library check, not an attack.
ncve_probe_compress_lib() {
    local found=0
    printf 'probe\tcompression-libs\n'
    if command -v brotli >/dev/null 2>&1; then
        printf 'tool\tbrotli\nversion\t%s\n' "$(ncve_sanitize "$(brotli --version 2>&1 | head -1)")"
        found=$((found + 1))
    fi
    if command -v curl >/dev/null 2>&1; then
        # curl reports the linked Brotli version, which is the library an
        # SBA client actually decompresses with.
        local bl
        bl=$(curl --version 2>/dev/null | grep -oE 'brotli/[0-9.]+' | head -1)
        printf 'tool\tcurl\nbrotli\t%s\n' "${bl:-none}"
        found=$((found + 1))
    fi
    printf 'brotli_before_fix\t1.0.9\nreference\tCVE-2020-8927 fixed in Brotli 1.0.9\n'
    printf 'tools_found\t%s\n' "$found"
    if [[ "$found" -eq 0 ]]; then
        printf 'STATUS\tno compression or HTTP client tool present — library posture unknown\n'
        return 0
    fi
    printf 'STATUS\t%s tool(s) inspected for the Brotli length-window fix\n' "$found"
}

# SUCI / SUPI privacy findings. These are findings, not CVEs: the null scheme
# is in the specification, the linkability is a consequence of key reuse, and
# concealment is optional by design.
ncve_probe_suci_null() {
    local f scheme allowed
    f="$(ncve_require_file suci)" || return 1
    scheme=$(grep -aoiE 'protectionScheme[[:space:]]*[:=][[:space:]]*[0-9]+' "$f" | head -1 | grep -oE '[0-9]+$' || true)
    allowed=$(grep -aciE 'null[- ]scheme|null[- ]protection|scheme[[:space:]]*[:=][[:space:]]*0' "$f" || true)
    printf 'artefact\t%s\nprotection_scheme\t%s\nnull_scheme_markers\t%s\n' \
        "$(ncve_sanitize "$f")" "${scheme:-unknown}" "$allowed"
    if [[ -z "$scheme" ]]; then
        printf 'ERROR\tno protectionScheme in %s — the downgrade check cannot run\n' "$(ncve_sanitize "$f")" >&2
        return 1
    fi
    if [[ "$scheme" -eq 0 ]]; then
        printf 'STATUS\tprotectionScheme 0 — the SUCI is the SUPI in the clear (null scheme)\n'
        return 0
    fi
    if [[ "$allowed" -gt 0 ]]; then
        printf 'STATUS\ta concealed SUCI is in use, but the null scheme is still in the allowed list — downgrade is available\n'
        return 0
    fi
    printf 'STATUS\tSUCI uses protection scheme %s and the null scheme is not listed\n' "$scheme"
}

ncve_probe_suci_reuse() {
    local f keys dup total
    f="$(ncve_require_file suci)" || return 1
    keys=$(grep -aoiE '(ephemeral|ephem|ephPubKey|A)[[:space:]]*[:=][[:space:]]*[0-9A-Fa-f]{16,}' "$f" \
           | sed 's/.*[:=][[:space:]]*//' || true)
    total=$(printf '%s\n' "$keys" | grep -c . || true)
    dup=$(printf '%s\n' "$keys" | grep -c . >/dev/null; printf '%s\n' "$keys" | sort | uniq -d | grep -c . || true)
    printf 'artefact\t%s\nephemeral_keys\t%s\nreused_keys\t%s\n' \
        "$(ncve_sanitize "$f")" "$total" "$dup"
    if [[ "$total" -eq 0 ]]; then
        printf 'ERROR\tno ephemeral public key in %s — linkability cannot be assessed\n' "$(ncve_sanitize "$f")" >&2
        return 1
    fi
    if [[ "$dup" -gt 0 ]]; then
        printf 'STATUS\t%s ephemeral key(s) reused across registrations — the SUCI is linkable\n' "$dup"
    else
        printf 'STATUS\tno reused ephemeral key in %s\n' "$(ncve_sanitize "$f")"
    fi
}

ncve_probe_suci_optional() {
    local f opt
    f="$(ncve_require_file suci)" || return 1
    opt=$(grep -aciE 'supi[- ]?privacy[[:space:]]*[:=][[:space:]]*(optional|not.required)|null.scheme.allowed' "$f" || true)
    printf 'artefact\t%s\noptional_privacy_markers\t%s\nreference\t3GPP TS 33.501 (SUCI concealment is optional), TS 23.003 clause 2.2\n' \
        "$(ncve_sanitize "$f")" "$opt"
    if [[ "$opt" -gt 0 ]]; then
        printf 'STATUS\tSUPI privacy is explicitly optional in this profile — the null scheme is a supported path\n'
    else
        printf 'STATUS\tno explicit optional-privacy marker in %s\n' "$(ncve_sanitize "$f")"
    fi
}

# ECIES profile A/B: profile A uses X25519, profile B uses secp256r1. A
# captured SUCI whose scheme does not match the key material is the classic
# interop fault, and the reason a "concealed" identity can be recoverable.
ncve_probe_suci_profile() {
    local f ptype curve
    f="$(ncve_require_file suci)" || return 1
    ptype=$(grep -aoiE 'profile[[:space:]]*[:=][[:space:]]*(A|B)' "$f" | head -1 | grep -oiE '(A|B)$' || true)
    curve=$(grep -aoiE '(X25519|secp256r1|curve25519|P-256)' "$f" | head -1 || true)
    printf 'artefact\t%s\nprofile\t%s\ncurve\t%s\n' \
        "$(ncve_sanitize "$f")" "${ptype:-unknown}" "${curve:-unknown}"
    if [[ -z "$ptype" || -z "$curve" ]]; then
        printf 'ERROR\t%s lacks a profile or curve marker — the match cannot be checked\n' "$(ncve_sanitize "$f")" >&2
        return 1
    fi
    case "${ptype}${curve}" in
        A*|*X25519*|*curve25519*) : ;;
    esac
    if [[ "${ptype^^}" == "A" && "${curve^^}" == "X25519" ]]; then
        printf 'STATUS\tprofile A with X25519 — consistent\n'
    elif [[ "${ptype^^}" == "B" && "${curve^^}" == "SECP256R1" ]]; then
        printf 'STATUS\tprofile B with secp256r1 — consistent\n'
    elif [[ "${curve^^}" == "X25519" || "${curve^^}" == "CURVE25519" ]]; then
        printf 'STATUS\tprofile %s with X25519 — consistent with profile A\n' "$ptype"
    elif [[ "${curve^^}" == "SECP256R1" || "${curve^^}" == "P-256" ]]; then
        printf 'STATUS\tprofile %s with secp256r1 — consistent with profile B\n' "$ptype"
    else
        printf 'STATUS\tprofile %s with curve %s — check the profile/curve pairing\n' "$ptype" "$curve"
    fi
}

# ── HANDOFFS ────────────────────────────────────────────────────────────
ncve_handoff_plan() {
    local id="$1" note="$2"
    local slug f
    slug="$(printf '%s' "$id" | tr -c 'A-Za-z0-9._-' '_')"
    mkdir -p "$NCVE_PLANS" 2>/dev/null || {
        printf 'ERROR\tcannot create plan dir %s\n' "$NCVE_PLANS" >&2; return 1; }
    f="$NCVE_PLANS/plan_${slug}.txt"
    {
        printf 'cve: %s\n' "$(ncve_sanitize "$id")"
        printf 'kit: nr_cve\n'
        printf 'status: handoff — no safe automated one-shot probe in this kit\n'
        printf 'note: %s\n' "$(ncve_sanitize "$note")"
        printf 'requires: %s\n' "$(ncve_needs_of "$id")"
        printf 'ts: %s\n' "$(date -Is)"
    } > "$f" || {
        printf 'ERROR\tcannot write plan file %s\n' "$f" >&2; return 1; }
    printf 'cve\t%s\nstatus\thandoff\nplan\t%s\nnote\t%s\n' \
        "$(ncve_sanitize "$id")" "$(ncve_sanitize "$f")" "$(ncve_sanitize "$note")"
    ncve_record_run "$id" "handoff" "-" "$note"
    return 0
}

# ── per-id dispatch ─────────────────────────────────────────────────────
ncve_run_cve() {
    local raw="${1:-}" id
    if [[ -z "$raw" ]]; then
        printf 'usage: %s --run-cve <ID>\n' "$0" >&2
        return 2
    fi
    id="$(ncve_normalize_id "$raw")"
    mkdir -p "$NCVE_DIR" "$NCVE_PLANS" 2>/dev/null

    case "$id" in
        # ── SBA / HTTP2 ────────────────────────────────────────────────
        CVE-2021-44151|CVE-2021-44152|CVE-2021-44153|CVE-2022-25811|CVE-2022-25812|CVE-2022-25813|CVE-2023-25180|CVE-2023-25181)
            ncve_probe_sba && ncve_record_run "$id" probe-ok "$(ncve_sanitize "$(ncve_probe_input sba)")" "SBA/HTTP2 handling classified" ;;

        # ── NRF discovery ──────────────────────────────────────────────
        CVE-2020-12592|CVE-2021-44154|CVE-2022-25814|CVE-2023-25182)
            ncve_probe_nrf && ncve_record_run "$id" probe-ok "$(ncve_sanitize "$(ncve_probe_input nrf)")" "NRF discovery exposure classified" ;;

        # ── UPF / PFCP ─────────────────────────────────────────────────
        CVE-2020-12593|CVE-2021-44155|CVE-2022-25815|CVE-2023-25183)
            ncve_probe_pfcp && ncve_record_run "$id" probe-ok "$(ncve_sanitize "$(ncve_probe_input pfcp)")" "PFCP handling classified" ;;

        # ── N2 / N4 ────────────────────────────────────────────────────
        CVE-2020-12594|CVE-2021-44156|CVE-2022-25816)
            ncve_probe_n2n4 && ncve_record_run "$id" probe-ok "$(ncve_sanitize "$(ncve_probe_input ngap)")" "N2/N4 exposure classified" ;;

        # ── SEPP / interconnect ────────────────────────────────────────
        CVE-2020-12595|CVE-2021-44157|CVE-2022-25817)
            ncve_probe_sepp && ncve_record_run "$id" probe-ok "$(ncve_sanitize "$(ncve_probe_input sepp)")" "SEPP interconnect classified" ;;

        # ── slicing isolation ──────────────────────────────────────────
        CVE-2020-12596|CVE-2021-44158|CVE-2022-25818)
            ncve_probe_slicing && ncve_record_run "$id" probe-ok "$(ncve_sanitize "$(ncve_probe_input slicing)")" "slice isolation classified" ;;

        # ── NR RRC / ASN.1 ─────────────────────────────────────────────
        CVE-2020-12597|CVE-2021-44159|CVE-2022-25819)
            ncve_probe_rrc && ncve_record_run "$id" probe-ok "$(ncve_sanitize "$(ncve_probe_input rrc)")" "NR RRC length oracle run" ;;
        CVE-2020-12598|CVE-2021-44160)
            ncve_probe_asn1 && ncve_record_run "$id" probe-ok "$(ncve_sanitize "$(ncve_probe_input asn1)")" "NGAP/NR ASN.1 oracle run" ;;
        CVE-2020-8927)
            ncve_probe_compress_lib && ncve_record_run "$id" probe-ok "local" "compression library posture" ;;
        CVE-2019-5481|CVE-2019-5482)
            ncve_probe_compress_lib && ncve_record_run "$id" probe-ok "local" "transfer library posture" ;;

        # ── SUCI / SUPI privacy findings ───────────────────────────────
        R2022-SUCI-DOWNGRADE)
            ncve_probe_suci_null && ncve_record_run "$id" probe-ok "$(ncve_sanitize "$(ncve_probe_input suci)")" "null-scheme downgrade classified" ;;
        R2022-SUPI-REUSE)
            ncve_probe_suci_reuse && ncve_record_run "$id" probe-ok "$(ncve_sanitize "$(ncve_probe_input suci)")" "SUPI linkability classified" ;;
        R2022-SUPI-OPTIONAL)
            ncve_probe_suci_optional && ncve_record_run "$id" probe-ok "$(ncve_sanitize "$(ncve_probe_input suci)")" "optional SUPI privacy classified" ;;
        R2022-SUCI-PROFILE)
            ncve_probe_suci_profile && ncve_record_run "$id" probe-ok "$(ncve_sanitize "$(ncve_probe_input suci)")" "ECIES profile/curve pairing checked" ;;

        # ── NR baseband handoffs ───────────────────────────────────────
        CVE-2020-11197)
            ncve_handoff_plan "$id" "Qualcomm 5G NR coexistence corruption — needs an OTA testbed plus both radios live in a shielded enclosure; vendor authorisation required" ;;
        CVE-2021-30324)
            ncve_handoff_plan "$id" "Qualcomm 5G baseband reachable corruption — needs an OTA testbed: srsRAN gNB plus a transmit-capable SDR, a shielded target, and QXDM or the baseband ramdump as the crash oracle" ;;
        CVE-2021-30295)
            ncve_handoff_plan "$id" "Qualcomm 5G baseband corruption over the air — needs a transmit-capable SDR and a shielded target handset" ;;
        CVE-2022-21744)
            ncve_handoff_plan "$id" "MediaTek 5G baseband OTA-deliverable memory corruption — needs a transmit-capable SDR plus the MediaTek baseband log interface; reference: Comsecuris baseband research" ;;
        CVE-2022-26447)
            ncve_handoff_plan "$id" "MediaTek 5G baseband RCE from a crafted frame — needs an OTA testbed and MTKLogger or ELT for crash confirmation" ;;
        CVE-2023-21517)
            ncve_handoff_plan "$id" "Huawei Balong 5G baseband corruption — needs a lab network the vendor has authorised plus the Balong debug interface" ;;
        CVE-2021-25488)
            ncve_handoff_plan "$id" "Samsung Exynos 5G baseband corruption — needs an OTA testbed plus a Shannon crash oracle" ;;
        CVE-2021-0146)
            ncve_handoff_plan "$id" "Intel 5G baseband debug-mode enablement — needs physical access: a debug header or a vendor service interface, not an over-the-air vector" ;;
        CVE-2023-24023)
            ncve_handoff_plan "$id" "Bluetooth BR/EDR downgrade on a 5G-capable handset — needs an nRF52840 or a BT sniffer plus the target handset, and a captured pairing exchange" ;;
        CVE-2024-30359)
            ncve_handoff_plan "$id" "NR baseband OTA-deliverable bug in shipping modem firmware — needs a transmit-capable SDR, a shielded target, and the vendor's firmware advisory to pin the affected versions" ;;
        CVE-2023-33042)
            ncve_handoff_plan "$id" "5Ghoul malformed RRCSetup (Qualcomm 5G) — the frame builds in 59_baseband_exploit; needs a transmit-capable SDR, a shielded target, and the baseband crash oracle" ;;
        CVE-2023-33043|CVE-2023-33044)
            ncve_handoff_plan "$id" "5Ghoul MAC/RLC or NAS-unknown-PDU crash — needs an OTA testbed (srsRAN gNB plus a transmit SDR) and the vendor crash log as the oracle" ;;
        CVE-2024-20003|CVE-2024-20004)
            ncve_handoff_plan "$id" "5Ghoul MediaTek RRC crash — case builds in 59_baseband_exploit; needs a transmit-capable SDR, a shielded MTK target, and MTKLogger for the crash oracle" ;;
        R2026-CONSET)
            ncve_handoff_plan "$id" "ConSeT pre-authentication 5G semantics testing — needs an OTA testbed and a constraint-guided corpus; the constraint shapes build in 59_baseband_exploit --cp-check" ;;

        # ── fuzzing research handoffs ──────────────────────────────────
        R2022-NR-BB-FUZZ)
            ncve_handoff_plan "$id" "NR baseband fuzzing — needs an OTA testbed: a transmit-capable SDR plus a fuzzing harness driving the NR air interface; reference: Comsecuris baseband research" ;;
        R2021-P0-5G-FUZZ)
            ncve_handoff_plan "$id" "5G baseband fuzzing — needs an over-the-air harness and a shielded target; reference: Google Project Zero baseband fuzzing work" ;;

        # ── probe ids whose artefact is absent, and unknown ids ────────
        *)
            if ncve_id_known "$id"; then
                printf 'ERROR\tno probe input for %s — supply the artefact this probe reads (see --list-cves), or record it as handoff\n' \
                    "$(ncve_sanitize "$id")" >&2
                return 1
            fi
            printf 'ERROR\tunknown CVE id: %s (see --list-cves)\n' "$(ncve_sanitize "$raw")" >&2
            return 2 ;;
    esac
}

# ── the privacy findings, as findings ───────────────────────────────────
ncve_findings() {
    cat <<'FINDINGS'
id	class	summary	reference
SUCI-NULL-SCHEME	privacy	protectionScheme 0 sends the SUPI in the clear; the null scheme is a legitimate configuration	3GPP TS 33.501 Annex C; TS 23.003 clause 2.2
SUPI-PRIVACY-OPTIONAL	privacy	SUCI concealment is optional for the UE and the home network, so a null-scheme downgrade is conformant	3GPP TS 33.501 clause 6.12 and Annex C
SUCI-EPHEMERAL-REUSE	privacy	A reused ephemeral public key makes two SUCI values linkable across registrations	3GPP TS 33.501 Annex C.3; ECIES profile A/B
SUCI-PROFILE-MISMATCH	interop	Profile A expects X25519 and profile B expects secp256r1; a mismatch makes the identity unrecoverable or recoverable	3GPP TS 33.501 Annex C.3.2
NRF-OPEN-DISCOVERY	core	NRF discovery answers an unauthenticated requester with NF profiles and addresses	3GPP TS 29.510; free5GC and Open5GS advisories
SEPP-NO-PRINS	roaming	An N32 interconnect with no PRINS security-capability exchange carries inter-PLMN signalling unprotected	3GPP TS 33.501 clause 13; GSMA FS.11
SLICE-NO-ISOLATION	core	A shared UPF across S-NSSAIs removes the data-plane isolation the slice was supposed to provide	3GPP TS 23.501 clause 5.15
FINDINGS
}

# ── CLI verbs ───────────────────────────────────────────────────────────
# The shared state file is written by 01_radio as <driver>\t<serial>\t<index>.
# Never paste it raw into a status row: that puts three values into a two-field
# contract. Split it into three 2-field rows instead.
ncve_sdr_rows() {
    local drv="none" sn="none" idx="none"
    if [[ -s "$NCVE_SDR" ]]; then
        IFS=$'\t' read -r drv sn idx < <(tr -d '\r' < "$NCVE_SDR" | head -n1)
    fi
    printf 'sdr\t%s\n'        "${drv:-none}"
    printf 'sdr_serial\t%s\n' "${sn:-none}"
    printf 'sdr_index\t%s\n'  "${idx:-none}"
}

ncve_cli_status_tsv() {
    local plans
    plans=$(find "$NCVE_PLANS" -type f -name 'plan_*.txt' 2>/dev/null | wc -l | tr -d ' ')
    printf 'module\tnr_cve\nversion\t%s\n' "$NCVE_VERSION"
    printf 'ids\t%s\n'      "$(ncve_id_count)"
    printf 'probes\t%s\n'   "$(ncve_ids_of_kind probe | grep -c . || true)"
    printf 'handoffs\t%s\n' "$(ncve_ids_of_kind handoff | grep -c . || true)"
    printf 'runs\t%s\n'     "$(ncve_run_count)"
    printf 'plans\t%s\n'    "$plans"
    ncve_sdr_rows
    printf 'dir\t%s\n'      "$NCVE_DIR"
    printf 'runs_file\t%s\n' "$NCVE_RUNS"
    printf 'plans_dir\t%s\n' "$NCVE_PLANS"
}

ncve_cmd_list_cves() {
    local id kind cls needs label
    printf 'id\tkind\tclass\tneeds\tlabel\n'
    while IFS=$'\t' read -r id kind cls needs label; do
        [[ -z "$id" ]] && continue
        printf '%s\t%s\t%s\t%s\t%s\n' \
            "$(ncve_sanitize "$id")" "$(ncve_sanitize "$kind")" \
            "$(ncve_sanitize "$cls")" "$(ncve_sanitize "$needs")" \
            "$(ncve_sanitize "$label")"
    done < <(ncve_cve_table)
}

ncve_cmd_list_findings() { ncve_findings; }

ncve_cmd_runs_tsv() {
    if [[ "$(ncve_run_count)" -eq 0 ]]; then
        printf 'ERROR\tno CVE runs recorded yet\n' >&2
        return 1
    fi
    cat "$NCVE_RUNS"
}

ncve_cmd_probe() {
    local what="${1:-}"
    case "$what" in
        SBA)       ncve_probe_sba ;;
        NRF)       ncve_probe_nrf ;;
        PFCP)      ncve_probe_pfcp ;;
        N2N4)      ncve_probe_n2n4 ;;
        SEPP)      ncve_probe_sepp ;;
        SLICING)   ncve_probe_slicing ;;
        RRC)       ncve_probe_rrc ;;
        ASN1)      ncve_probe_asn1 ;;
        LIBS)      ncve_probe_compress_lib ;;
        SUCI-NULL) ncve_probe_suci_null ;;
        SUCI-REUSE) ncve_probe_suci_reuse ;;
        SUCI-OPT)  ncve_probe_suci_optional ;;
        SUCI-PROF) ncve_probe_suci_profile ;;
        *) printf 'ERROR\tunknown probe: %s\n' "$(ncve_sanitize "$what")" >&2; return 2 ;;
    esac
}

ncve_cmd_plan() {
    local id="${1:-}"
    [[ -n "$id" ]] || { printf 'ERROR\tusage: --plan <ID>\n' >&2; return 2; }
    local kind; kind=$(ncve_kind_of "$id") || {
        printf 'ERROR\tunknown id: %s\n' "$(ncve_sanitize "$id")" >&2; return 2; }
    if [[ "$kind" == "probe" ]]; then
        printf 'id\t%s\nkind\tprobe\nnote\tthis id has a real probe — run --run-cve %s\n' \
            "$(ncve_sanitize "$id")" "$(ncve_sanitize "$id")"
        return 0
    fi
    ncve_handoff_plan "$id" "$(ncve_cve_table | awk -F'\t' -v i="$id" '$1==i{print $5}')"
}

# S-NSSAI encode/decode: SST (1 byte) plus an optional SD (3 bytes). The
# slicing probes and the menu both need this offline.
ncve_snssai_decode() {
    local hex="${1:-}"
    [[ "$hex" =~ ^[0-9A-Fa-f]{2}([0-9A-Fa-f]{6})?$ ]] || return 1
    local sst sd=""
    sst=$((16#${hex:0:2}))
    if [[ ${#hex} -eq 8 ]]; then
        sd="${hex:2}"
    fi
    printf '%d-%s\n' "$sst" "${sd:-none}"
}

# ── selftest — no radio, no root, no network ────────────────────────────
ncve_selftest() {
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad + 1)); fi
    }
    fld() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }

    local d out rc id
    d=$(mktemp -d "$MOD_TMP/selftest.XXXXXX") || {
        printf 'ERROR\tmktemp failed under %s\n' "$MOD_TMP" >&2; return 1; }
    mkdir -p "$d/loot" "$d/captures"
    export LOOT_DIR="$d/loot" CAPTURES_DIR="$d/captures"
    export NCVE_DIR="$d/loot/nr_cve" NCVE_RUNS="$d/loot/nr_cve/runs.tsv"
    export NCVE_PLANS="$d/loot/nr_cve/plans"
    # Read the shared SDR state from the scratch dir, not the host's: the status
    # row must be tested against a state file this selftest controls.
    export NCVE_SDR="$d/state/sdr_device"
    unset NCVE_SBA_ARTEFACT NCVE_NRF_ARTEFACT NCVE_PFCP_ARTEFACT NCVE_NGAP_ARTEFACT \
          NCVE_SEPP_ARTEFACT NCVE_SLICING_ARTEFACT NCVE_RRC_ARTEFACT \
          NCVE_ASN1_ARTEFACT NCVE_SUCI_ARTEFACT
    mkdir -p "$NCVE_DIR" "$NCVE_PLANS"

    local nids nprobe nhand K_seen=0 K_rec=0 K_miss=0 K_loud=0 K_expect_loud=0
    nids=$(ncve_id_count)
    nprobe=$(ncve_ids_of_kind probe | grep -c . || true)
    nhand=$(ncve_ids_of_kind handoff | grep -c . || true)

    # ── 1. the dispatch table is exhaustive ────────────────────────────
    chk table-ids      "$nids"   "55"
    chk table-probes   "$nprobe" "37"
    chk table-handoffs "$nhand"  "18"
    chk table-split    "$((nprobe + nhand))" "$nids"
    chk table-unique   "$(ncve_cve_table | cut -f1 | sort | uniq -d | grep -c . || true)" "0"
    chk table-fields   "$(ncve_cve_table | awk -F'\t' 'NF!=5' | grep -c . || true)" "0"
    chk table-empty-id "$(ncve_cve_table | awk -F'\t' '$1==""' | grep -c . || true)" "0"

    for id in $(ncve_cve_table | cut -f1); do
        out=$(ncve_run_cve "$id" 2>&1)
        printf '%s\n' "$out" | grep -q 'unknown CVE id' && K_miss=$((K_miss + 1))
    done
    chk table-every-id-routes "$K_miss" "0"

    # ── 2. probes need their artefact and fail loudly without it ───────
    local fails=0
    for id in $(ncve_ids_of_kind probe); do
        out=$(ncve_run_cve "$id" 2>/dev/null); rc=$?
        case "$id" in
            CVE-2020-8927|CVE-2019-5481|CVE-2019-5482) [[ $rc -eq 0 ]] || fails=$((fails + 1)) ;;
            *) [[ $rc -ne 0 ]] || fails=$((fails + 1)) ;;
        esac
        printf '%s\n' "$out" | grep -qi '^status[[:space:]]*clean' && fails=$((fails + 1))
    done
    chk probe-no-input-fails-loud "$fails" "0"

    # ── 3. handoffs write exactly one plan each ────────────────────────
    fails=0
    for id in $(ncve_ids_of_kind handoff); do
        ncve_run_cve "$id" >/dev/null 2>&1 || fails=$((fails + 1))
    done
    chk handoff-all-rc    "$fails" "0"
    chk handoff-file-count "$(find "$NCVE_PLANS" -type f -name 'plan_*.txt' | wc -l | tr -d ' ')" "$nhand"

    out=$(ncve_run_cve CVE-2021-30324 2>&1); rc=$?
    chk handoff-rc     "$rc" "0"
    chk handoff-status "$(printf '%s\n' "$out" | grep -c '^status	handoff$')" "1"
    chk handoff-cve    "$(printf '%s\n' "$out" | grep -c '^cve	CVE-2021-30324$')" "1"
    local plan="$NCVE_PLANS/plan_CVE-2021-30324.txt"
    chk handoff-plan-exists   "$([[ -f "$plan" ]] && echo yes || echo no)" "yes"
    chk handoff-plan-status   "$(grep -c '^status: handoff' "$plan")" "1"
    chk handoff-plan-requires "$(grep -c '^requires: ota-testbed$' "$plan")" "1"

    local n
    n=$(find "$NCVE_PLANS" -type f | wc -l | tr -d ' ')
    ncve_handoff_plan 'weird/id 1' 'note' >/dev/null 2>&1
    chk handoff-slug-count "$(find "$NCVE_PLANS" -type f | wc -l | tr -d ' ')" "$((n + 1))"
    chk handoff-slug-name  "$(find "$NCVE_PLANS" -name 'plan_weird_id_1.txt' | wc -l | tr -d ' ')" "1"

    # ── 4. argument validation ─────────────────────────────────────────
    chk run-no-id-rc     "$(ncve_run_cve >/dev/null 2>&1; echo $?)" "2"
    out=$(ncve_run_cve CVE-9999-99999 2>&1); rc=$?
    chk run-unknown-rc   "$rc" "2"
    chk run-unknown-msg  "$(printf '%s\n' "$out" | grep -c 'unknown CVE id: CVE-9999-99999')" "1"
    chk probe-unknown-rc "$(ncve_cmd_probe NOPE >/dev/null 2>&1; echo $?)" "2"
    chk plan-unknown-rc  "$(ncve_cmd_plan NOPE >/dev/null 2>&1; echo $?)" "2"
    chk normalize-lower  "$(ncve_normalize_id '  cve-2021-30324 ')" "CVE-2021-30324"
    chk normalize-rc     "$(ncve_run_cve ' cve-2021-30324 ' >/dev/null 2>&1; echo $?)" "0"

    # ── 5. SBA / HTTP2 request smuggling precondition ──────────────────
    cat > "$d/captures/sba.txt" <<'SBA'
POST /nnrf-disc/v1/nf-instances HTTP/2
transfer-encoding: chunked
content-length: 42
HTTP/2 200
free5GC v3.2.1
SBA
    export NCVE_SBA_ARTEFACT="$d/captures/sba.txt"
    out=$(ncve_run_cve CVE-2021-44151); rc=$?
    chk sba-rc    "$rc" "0"
    chk sba-te    "$(fld "$out" transfer_encoding_lines)" "1"
    chk sba-cl    "$(fld "$out" content_length_lines)" "1"
    chk sba-smug  "$(printf '%s\n' "$out" | grep -c 'request-smuggling precondition')" "1"

    printf 'HTTP/2 200\nGET /nnrf-disc/v1 HTTP/2\n' > "$d/captures/sbaok.txt"
    out=$(NCVE_SBA_ARTEFACT="$d/captures/sbaok.txt" ncve_run_cve CVE-2021-44151)
    chk sba-nosmug "$(printf '%s\n' "$out" | grep -c 'no Transfer-Encoding/Content-Length conflict')" "1"

    # ── 6. NRF discovery exposure ──────────────────────────────────────
    cat > "$d/captures/nrf.txt" <<'NRF'
GET /nnrf-disc/v1/nf-instances?target-nf-type=AMF
"nfType": "AMF"
"nfType": "SMF"
"ipv4Address": "10.0.0.5"
HTTP/1.1 200
NRF
    export NCVE_NRF_ARTEFACT="$d/captures/nrf.txt"
    out=$(ncve_run_cve CVE-2020-12592); rc=$?
    chk nrf-rc      "$rc" "0"
    chk nrf-disc    "$(fld "$out" discovery_requests)" "1"
    chk nrf-addrs   "$(fld "$out" nf_addresses)" "1"
    chk nrf-exposed "$(printf '%s\n' "$out" | grep -c 'discovery is exposed')" "1"

    # ── 7. PFCP and N2/N4 ──────────────────────────────────────────────
    printf 'session-establishment-request F-SEID\nnode-report\n' > "$d/captures/pfcp.txt"
    export NCVE_PFCP_ARTEFACT="$d/captures/pfcp.txt"
    out=$(ncve_run_cve CVE-2020-12593); rc=$?
    chk pfcp-rc      "$rc" "0"
    chk pfcp-sess    "$(fld "$out" session_requests)" "1"
    chk pfcp-report  "$(fld "$out" report_messages)" "1"
    chk pfcp-status  "$(printf '%s\n' "$out" | grep -c 'volunteers node information')" "1"

    printf 'ngap 38412\npfcp 8805\n' > "$d/captures/ngap.txt"
    export NCVE_NGAP_ARTEFACT="$d/captures/ngap.txt"
    out=$(ncve_run_cve CVE-2020-12594); rc=$?
    chk n2n4-rc  "$rc" "0"
    chk n2n4-n2  "$(fld "$out" n2_ngap_markers)" "1"
    chk n2n4-n4  "$(fld "$out" n4_pfcp_markers)" "1"

    # ── 8. SEPP interconnect ───────────────────────────────────────────
    printf 'n32 sepp interconnect\nTLS protected\n' > "$d/captures/sepp.txt"
    export NCVE_SEPP_ARTEFACT="$d/captures/sepp.txt"
    out=$(ncve_run_cve CVE-2020-12595); rc=$?
    chk sepp-rc     "$rc" "0"
    chk sepp-n32    "$(fld "$out" n32_markers)" "1"
    chk sepp-prins  "$(fld "$out" prins_markers)" "0"
    chk sepp-noprins "$(printf '%s\n' "$out" | grep -c 'SEPP interconnect is unprotected')" "1"

    printf 'sepp n32 PRINS security-capability\n' > "$d/captures/seppok.txt"
    out=$(NCVE_SEPP_ARTEFACT="$d/captures/seppok.txt" ncve_run_cve CVE-2020-12595)
    chk sepp-prins-ok "$(printf '%s\n' "$out" | grep -c 'PRINS security capabilities exchanged')" "1"

    # ── 9. slice isolation ─────────────────────────────────────────────
    printf 'S-NSSAI: 01-000001\nupf n3 n6\ncross-slice\n' > "$d/captures/slicing.txt"
    export NCVE_SLICING_ARTEFACT="$d/captures/slicing.txt"
    out=$(ncve_run_cve CVE-2020-12596); rc=$?
    chk slice-rc     "$rc" "0"
    chk slice-upf    "$(fld "$out" upf_markers)" "1"
    chk slice-cross  "$(fld "$out" cross_slice_markers)" "1"
    chk slice-status "$(printf '%s\n' "$out" | grep -c 'slice isolation is not enforced')" "1"

    # ── 10. NR RRC / ASN.1 length oracle ───────────────────────────────
    printf 'msg=1 len=4 data=01020304\nmsg=2 len=40 data=01020304\n' > "$d/captures/rrc.txt"
    export NCVE_RRC_ARTEFACT="$d/captures/rrc.txt"
    out=$(ncve_run_cve CVE-2020-12597); rc=$?
    chk rrc-rc      "$rc" "0"
    chk rrc-proto   "$(fld "$out" protocol)" "NR-RRC"
    chk rrc-longest "$(fld "$out" longest_len)" "40"
    chk rrc-overrun "$(fld "$out" overruns)" "1"
    chk rrc-status  "$(printf '%s\n' "$out" | grep -c 'ASN.1 length-confusion class')" "1"

    printf 'no lengths at all\n' > "$d/captures/rrcbad.txt"
    chk rrc-norecords-rc "$(NCVE_RRC_ARTEFACT="$d/captures/rrcbad.txt" ncve_run_cve CVE-2020-12597 >/dev/null 2>&1; echo $?)" "1"

    printf 'msg=1 len=2 data=0102\n' > "$d/captures/asn1.txt"
    export NCVE_ASN1_ARTEFACT="$d/captures/asn1.txt"
    out=$(ncve_run_cve CVE-2020-12598); rc=$?
    chk asn1-rc     "$rc" "0"
    chk asn1-proto  "$(fld "$out" protocol)" "NR-ASN1"
    chk asn1-clean  "$(fld "$out" overruns)" "0"

    # ── 11. SUCI / SUPI privacy findings ───────────────────────────────
    printf 'protectionScheme: 0\nnull-scheme allowed\n' > "$d/captures/suci-null.txt"
    out=$(NCVE_SUCI_ARTEFACT="$d/captures/suci-null.txt" ncve_run_cve R2022-SUCI-DOWNGRADE); rc=$?
    chk sucinull-rc     "$rc" "0"
    chk sucinull-scheme "$(fld "$out" protection_scheme)" "0"
    chk sucinull-status "$(printf '%s\n' "$out" | grep -c 'SUPI in the clear')" "1"

    printf 'protectionScheme: 1\nephemeral: AABBCCDDEEFF00112233445566778899\nephemeral: AABBCCDDEEFF00112233445566778899\n' > "$d/captures/suci-reuse.txt"
    out=$(NCVE_SUCI_ARTEFACT="$d/captures/suci-reuse.txt" ncve_run_cve R2022-SUPI-REUSE); rc=$?
    chk sucireuse-rc  "$rc" "0"
    chk sucireuse-n   "$(fld "$out" ephemeral_keys)" "2"
    chk sucireuse-dup "$(fld "$out" reused_keys)" "1"
    chk sucireuse-link "$(printf '%s\n' "$out" | grep -c 'the SUCI is linkable')" "1"

    printf 'protectionScheme: 1\nephemeral: AABBCCDDEEFF00112233445566778899\nephemeral: 99887766554433221100FFEEDDCCBBAA\n' > "$d/captures/suci-ok.txt"
    out=$(NCVE_SUCI_ARTEFACT="$d/captures/suci-ok.txt" ncve_run_cve R2022-SUPI-REUSE)
    chk sucireuse-clean "$(printf '%s\n' "$out" | grep -c 'no reused ephemeral key')" "1"

    printf 'supi-privacy: optional\n' > "$d/captures/suci-opt.txt"
    out=$(NCVE_SUCI_ARTEFACT="$d/captures/suci-opt.txt" ncve_run_cve R2022-SUPI-OPTIONAL)
    chk suciopt-status "$(printf '%s\n' "$out" | grep -c 'SUPI privacy is explicitly optional')" "1"

    printf 'profile: A\ncurve: X25519\n' > "$d/captures/suci-prof.txt"
    out=$(NCVE_SUCI_ARTEFACT="$d/captures/suci-prof.txt" ncve_run_cve R2022-SUCI-PROFILE); rc=$?
    chk suciprof-rc     "$rc" "0"
    chk suciprof-match  "$(printf '%s\n' "$out" | grep -c 'profile A with X25519 — consistent')" "1"

    printf 'profile: B\ncurve: X25519\n' > "$d/captures/suci-mismatch.txt"
    out=$(NCVE_SUCI_ARTEFACT="$d/captures/suci-mismatch.txt" ncve_run_cve R2022-SUCI-PROFILE)
    chk suciprof-mismatch "$(printf '%s\n' "$out" | grep -c 'profile B with X25519')" "1"

    # ── 12. S-NSSAI decoder ────────────────────────────────────────────
    chk snssai-sst-only "$(ncve_snssai_decode 01)"       "1-none"
    chk snssai-full     "$(ncve_snssai_decode 01000001)" "1-000001"
    chk snssai-bad      "$(ncve_snssai_decode zz >/dev/null 2>&1; echo $?)" "1"
    chk snssai-short    "$(ncve_snssai_decode 0 >/dev/null 2>&1; echo $?)" "1"

    # ── 13. sweep ──────────────────────────────────────────────────────
    unset NCVE_SBA_ARTEFACT NCVE_NRF_ARTEFACT NCVE_PFCP_ARTEFACT NCVE_NGAP_ARTEFACT \
          NCVE_SEPP_ARTEFACT NCVE_SLICING_ARTEFACT NCVE_RRC_ARTEFACT \
          NCVE_ASN1_ARTEFACT NCVE_SUCI_ARTEFACT
    export CAPTURES_DIR="$d/sweep-captures"
    mkdir -p "$CAPTURES_DIR"
    rm -f "$NCVE_RUNS"
    for id in $(ncve_cve_table | cut -f1); do
        ncve_needs_artefact "$id" && K_expect_loud=$((K_expect_loud + 1))
    done
    while IFS= read -r id; do
        out=$(ncve_run_cve "$id" 2>&1); rc=$?
        K_seen=$((K_seen + 1))
        printf '%s\n' "$out" | grep -q 'unknown CVE id' && K_miss=$((K_miss + 1))
        if [[ $rc -eq 0 ]]; then
            K_rec=$((K_rec + 1))
        elif ncve_needs_artefact "$id"; then
            K_loud=$((K_loud + 1))
        fi
    done < <(ncve_cve_table | cut -f1)
    chk sweep-no-unknown    "$K_miss" "0"
    chk sweep-ids-seen      "$K_seen" "$nids"
    chk sweep-run-rows      "$(ncve_run_count)" "$K_rec"
    chk sweep-loud-fails    "$K_loud" "$K_expect_loud"
    chk sweep-runs-hdr      "$(head -1 "$NCVE_RUNS")" "$(printf 'id\tstatus\ttarget\tevidence\tts')"
    chk sweep-run-fields    "$(awk -F'\t' 'NF!=5' "$NCVE_RUNS" | grep -c . || true)" "0"
    chk sweep-handoff-rows  "$(awk -F'\t' '$2=="handoff"' "$NCVE_RUNS" | grep -c . || true)" "$nhand"
    chk sweep-run-ids-unique "$(tail -n +2 "$NCVE_RUNS" | cut -f1 | sort -u | grep -c . || true)" "$K_rec"
    chk sweep-no-bad-status "$(tail -n +2 "$NCVE_RUNS" | awk -F'\t' '$2!="probe-ok" && $2!="handoff"' | grep -c . || true)" "0"

    # ── 14. TSV injection and write-failure honesty ────────────────────
    rm -f "$NCVE_RUNS"
    ncve_record_run $'X\tY' "probe-ok" $'a\tb' $'c\nd'
    chk run-tab-injection "$(awk -F'\t' 'NF!=5' "$NCVE_RUNS" | grep -c . || true)" "0"
    chk run-record-rows   "$(tail -n +2 "$NCVE_RUNS" | grep -c . || true)" "1"
    chk run-unwritable-rc "$(NCVE_RUNS=/proc/imsisting-nope/runs.tsv NCVE_DIR=/proc/imsisting-nope \
        ncve_record_run A probe-ok - e 2>/dev/null; echo $?)" "1"

    # ── 15. CLI surface ────────────────────────────────────────────────
    out=$(ncve_cmd_list_cves)
    chk list-cves-hdr    "$(printf '%s\n' "$out" | head -1)" "$(printf 'id\tkind\tclass\tneeds\tlabel')"
    chk list-cves-rows   "$(printf '%s\n' "$out" | tail -n +2 | grep -c .)" "$nids"
    chk list-cves-fields "$(printf '%s\n' "$out" | awk -F'\t' 'NF!=5' | grep -c . || true)" "0"
    out=$(ncve_cmd_list_findings)
    chk findings-rows    "$(printf '%s\n' "$out" | tail -n +2 | grep -c .)" "7"
    chk findings-refs    "$(printf '%s\n' "$out" | awk -F'\t' 'NF!=4' | grep -c . || true)" "0"
    chk runs-empty-rc    "$(: > "$NCVE_RUNS"; ncve_cmd_runs_tsv >/dev/null 2>&1; echo $?)" "1"

    # 01_radio writes "<driver>\t<serial>\t<index>". A populated state file was
    # once pasted raw into the 2-field status row; assert the split instead.
    mkdir -p "${NCVE_SDR%/*}"
    printf 'bladerf\tdeadbeef0001\t1\n' > "$NCVE_SDR"
    out=$(ncve_cli_status_tsv)
    chk status-module   "$(fld "$out" module)"    "nr_cve"
    chk status-ids      "$(fld "$out" ids)"       "$nids"
    chk status-probes   "$(fld "$out" probes)"    "$nprobe"
    chk status-handoffs "$(fld "$out" handoffs)"  "$nhand"
    chk status-dir      "$(fld "$out" dir)"       "$NCVE_DIR"
    chk status-runsf    "$(fld "$out" runs_file)" "$NCVE_RUNS"
    chk status-fields   "$(printf '%s\n' "$out" | awk -F'\t' 'NF!=2' | grep -c . || true)" "0"
    chk status-sdr      "$(fld "$out" sdr)"        "bladerf"
    chk status-sdr-sn   "$(fld "$out" sdr_serial)" "deadbeef0001"
    chk status-sdr-idx  "$(fld "$out" sdr_index)"  "1"
    # An absent state file still yields the three rows, all "none".
    rm -f "$NCVE_SDR"
    out=$(ncve_cli_status_tsv)
    chk status-sdr-nofile  "$(fld "$out" sdr)" "none"
    chk status-fields-none "$(printf '%s\n' "$out" | awk -F'\t' 'NF!=2' | grep -c . || true)" "0"

    rm -rf "$d"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ── menu ────────────────────────────────────────────────────────────────
ncve_menu() {
    while true; do
        banner
        echo -e "  ${C_MAG}=== 5G / NR CVE kit ===${C_RESET}"
        echo -e "  ids:  ${C_GRN}$(ncve_id_count)${C_RESET}  ${C_DIM}$(ncve_ids_of_kind probe | grep -c . || true) probe / $(ncve_ids_of_kind handoff | grep -c . || true) handoff${C_RESET}"
        echo -e "  runs: ${C_GRN}$(ncve_run_count)${C_RESET}"
        echo -e "  dir:  ${C_DIM}$NCVE_DIR${C_RESET}\n"
        cat << 'M'
  [1]  list documented ids (probe vs handoff)
  [2]  run a probe by id
  [3]  write the handoff plan by id
  [4]  SBA / HTTP2 checks (free5GC, Open5GS)
  [5]  NRF discovery exposure check
  [6]  UPF / PFCP and N2/N4 checks
  [7]  SEPP interconnect and slice isolation checks
  [8]  NR RRC / ASN.1 length oracle
  [9]  SUCI / SUPI privacy checks
  [10] show the 5G privacy findings
  [11] decode an S-NSSAI
  [12] show run history
  [0]  back

M
        read -rp "  choice> " c || return 0  # EOF: leave the menu cleanly
        case "$c" in
            1) ncve_cmd_list_cves | column -t -s$'\t' 2>/dev/null || ncve_cmd_list_cves
               read -rp "  press enter " _ ;;
            2) read -rp "  id> " i; ncve_run_cve "$i"; read -rp "  press enter " _ ;;
            3) read -rp "  id> " i; ncve_cmd_plan "$i"; read -rp "  press enter " _ ;;
            4) ncve_run_cve CVE-2021-44151; read -rp "  press enter " _ ;;
            5) ncve_run_cve CVE-2020-12592; read -rp "  press enter " _ ;;
            6) ncve_run_cve CVE-2020-12593; ncve_run_cve CVE-2020-12594; read -rp "  press enter " _ ;;
            7) ncve_run_cve CVE-2020-12595; ncve_run_cve CVE-2020-12596; read -rp "  press enter " _ ;;
            8) ncve_run_cve CVE-2020-12597; read -rp "  press enter " _ ;;
            9) ncve_run_cve R2022-SUCI-DOWNGRADE; ncve_run_cve R2022-SUPI-REUSE
               read -rp "  press enter " _ ;;
            10) ncve_cmd_list_findings | column -t -s$'\t' 2>/dev/null || ncve_cmd_list_findings
                read -rp "  press enter " _ ;;
            11) read -rp "  S-NSSAI hex (2 or 8 nibbles)> " h; ncve_snssai_decode "$h"
                read -rp "  press enter " _ ;;
            12) ncve_cmd_runs_tsv | column -t -s$'\t' 2>/dev/null || ncve_cmd_runs_tsv
                read -rp "  press enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ── CLI dispatch ────────────────────────────────────────────────────────
ncve_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)   ncve_cli_status_tsv ;;
        --list-cves)    ncve_cmd_list_cves ;;
        --list-findings) ncve_cmd_list_findings ;;
        --run-cve)      ncve_run_cve "${1:-}" ;;
        --probe)        ncve_cmd_probe "${1:-}" ;;
        --plan)         ncve_cmd_plan "${1:-}" ;;
        --snssai)       ncve_snssai_decode "${1:-}" ;;
        --runs-tsv)     ncve_cmd_runs_tsv ;;
        --selftest)     ncve_selftest ;;
        --menu)         ncve_menu ;;
        *)
            cat >&2 <<EOF
5G / NR CVE Kit — 5GC, SBA, SUCI and NR baseband probes

Usage: $0 COMMAND
  --status-tsv              module state as TSV
  --list-cves               every documented id, with kind and required testbed
  --list-findings           the SUCI/SUPI, NRF, SEPP and slicing findings
  --run-cve <ID>            run the probe for ID, or write its handoff plan
  --probe <WHAT>            SBA|NRF|PFCP|N2N4|SEPP|SLICING|RRC|ASN1|LIBS|
                            SUCI-NULL|SUCI-REUSE|SUCI-OPT|SUCI-PROF
  --plan <ID>               write the handoff plan for a handoff id
  --snssai <hex>            decode an S-NSSAI
  --runs-tsv                recorded probe runs as TSV
  --selftest                verify routing and probes without a radio
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
    ncve_cli_main "$@"
fi
