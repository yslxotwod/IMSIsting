#!/usr/bin/env bash
# LTE CVE kit — per-vector probes and hardware handoffs for the 4G stack:
# baseband and modem bugs across Qualcomm / MediaTek / Samsung Exynos / Intel
# and Huawei Balong, NAS and ASN.1 parsing failures, the Diameter and GTP
# families in the EPC, VoLTE/IMS SIP handling, and LTE paging / SIB parsing.
#
# Two honest outcomes per id:
#   * a PROBE  — a version fingerprint, a capability check, a config parse or
#                a decode crash-oracle run against an artefact on disk.
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

# Under pkexec HOME=/root even though we write to the invoking user's tree.
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

MOD_TMP="$TMP_DIR/lte_cve"
LCVE_DIR="$LOOT_DIR/lte_cve"
LCVE_RUNS="$LCVE_DIR/runs.tsv"
LCVE_PLANS="$LCVE_DIR/plans"
mkdir -p "$MOD_TMP" "$LCVE_DIR" "$LCVE_PLANS" 2>/dev/null

LCVE_VERSION="1.0"

LCVE_SDR="${TMP_DIR}/sdr_device"
LCVE_PLMN="${TMP_DIR}/target_plmn"

# ── sanitisation ────────────────────────────────────────────────────────
lcve_sanitize() {
    printf '%s' "${1:-}" | tr '\t\r\n' '   '
}

# ── run record ──────────────────────────────────────────────────────────
#   id  status  target  evidence  ts
# `status` is probe-ok | probe-fail | handoff | error. A handoff is never
# written as a pass.
lcve_record_run() {
    local id="$1" status="$2" target="$3" evidence="$4"
    mkdir -p "$LCVE_DIR" 2>/dev/null
    [[ -f "$LCVE_RUNS" ]] || printf 'id\tstatus\ttarget\tevidence\tts\n' > "$LCVE_RUNS" || return 1
    printf '%s\t%s\t%s\t%s\t%s\n' \
        "$(lcve_sanitize "$id")" "$(lcve_sanitize "$status")" \
        "$(lcve_sanitize "$target")" "$(lcve_sanitize "$evidence")" \
        "$(date -Is)" >> "$LCVE_RUNS" || {
        printf 'ERROR\tcannot append to the run log %s — permission denied?\n' "$LCVE_RUNS" >&2
        return 1
    }
    return 0
}

lcve_run_count() {
    [[ -f "$LCVE_RUNS" ]] || { echo 0; return; }
    tail -n +2 "$LCVE_RUNS" 2>/dev/null | grep -c . || true
}

# ── the dispatch table ──────────────────────────────────────────────────
# id <TAB> kind <TAB> class <TAB> needs <TAB> label
lcve_cve_table() {
    cat <<'TABLE'
CVE-2017-6975	handoff	baseband	lab-network	Broadcom/Cypress Wi-Fi and LTE coexistence overflow, reachable from the air interface
CVE-2018-11976	handoff	baseband	ota-testbed	Qualcomm QSEE key-extraction via a baseband-reachable TrustZone path
CVE-2020-11201	handoff	baseband	ota-testbed	Qualcomm baseband memory corruption in the data-services path
CVE-2020-11202	handoff	baseband	ota-testbed	Qualcomm baseband decoder corruption reachable from an over-the-air frame
CVE-2020-11204	handoff	baseband	ota-testbed	Qualcomm baseband memory corruption in the NAS/AS path
CVE-2020-11197	handoff	baseband	ota-testbed	Qualcomm baseband WLAN/LTE coexistence bug reachable over the air
CVE-2021-30324	handoff	baseband	ota-testbed	Qualcomm baseband reachable corruption in the cellular stack
CVE-2021-30295	handoff	baseband	ota-testbed	Qualcomm baseband memory corruption delivered over the air interface
CVE-2022-21744	handoff	baseband	ota-testbed	MediaTek baseband OTA-deliverable memory corruption
CVE-2022-26447	handoff	baseband	ota-testbed	MediaTek baseband remote code execution reached from a crafted cellular frame
CVE-2020-0069	handoff	baseband	lab-network	MediaTek command-queue driver privilege escalation — local, not over the air
CVE-2019-16254	handoff	baseband	lab-network	Samsung Exynos baseband / Shannon modem reachable corruption
CVE-2021-25488	handoff	baseband	lab-network	Samsung Exynos baseband memory corruption, vendor-disclosed
CVE-2020-12363	handoff	baseband	lab-network	Intel baseband (XMM) reachable corruption in the cellular stack
CVE-2021-0146	handoff	baseband	lab-network	Intel baseband debug-mode enablement — local, needs physical access
CVE-2022-22265	handoff	baseband	lab-network	Samsung NPU/TrustZone path used as a baseband-adjacent escalation
CVE-2023-21517	handoff	baseband	lab-network	Huawei Balong baseband reachable memory corruption
CVE-2018-5383	probe	baseband	none	Bluetooth and cellular pairing key-validation flaw — fixed-parameter key check
CVE-2019-9506	probe	baseband	none	KNOB entropy downgrade — negotiated key-length check on a captured pairing
CVE-2020-10135	probe	baseband	none	BIAS legacy-pairing authentication bypass — pairing-mode classification
CVE-2021-34699	handoff	baseband	lab-network	Duplicate/known-broken assignee entry; kept as an explicit non-target
R2020-MTK-BB-FUZZ	handoff	baseband	ota-testbed	MediaTek baseband fuzzing results — reference Comsecuris baseband research
R2020-QC-BB-FUZZ	handoff	baseband	ota-testbed	Qualcomm baseband fuzzing results — reference Quarkslab baseband research
R2019-P0-BB-FUZZ	handoff	baseband	ota-testbed	Baseband fuzzing via Project Zero's over-the-air harness
R2019-ASN1-DECODE-CRASH	probe	asn1	none	NAS/RRC ASN.1 decoder crash oracle over a message corpus
R2019-RRC-LENGTH-CONFUSION	probe	asn1	none	RRC length-field confusion check on a captured PDU set
R2019-NAS-LENGTH-CONFUSION	probe	asn1	none	NAS EMM/ESM length-confusion check on a captured PDU set
R2019-NAS-COUNT-CONFUSION	probe	asn1	none	NAS COUNT wrap and replay-window check from a capture
CVE-2020-8493	probe	diameter	none	Diameter S6a exposure — is the HSS answering from the visited network
CVE-2020-8514	handoff	diameter	lab-stp	Diameter DoS via crafted AVP length fields
CVE-2020-11412	handoff	diameter	lab-stp	Diameter S6a/S6d message forgery against a subscriber profile
CVE-2021-22191	probe	diameter	none	GTP-C echo request amplification factor measurement
CVE-2021-22192	handoff	gtp	lab-network	GTP-U injection into a bearer tunnel
CVE-2021-22193	handoff	gtp	lab-network	GTP-C node-address spoofing against an SGSN/MME
CVE-2019-15055	handoff	gtp	lab-network	GTP-U packet injection and bearer hijack family
CVE-2019-15056	handoff	gtp	lab-network	GTP-C session spoofing family
CVE-2020-8283	probe	gtp	none	GTP-C/GTP-U version and TEID sanity check on a captured flow
CVE-2021-45426	handoff	epc	lab-network	MME / S1-MME signalling exposure over an unauthenticated interconnect
CVE-2021-45427	handoff	epc	lab-network	S1-U user-plane exposure from a rogue eNB
CVE-2021-45428	handoff	epc	lab-network	EPC attach-procedure abuse from a rogue eNB
CVE-2020-25219	probe	volte	none	VoLTE SIP parser robustness over a message corpus
CVE-2020-25220	probe	volte	none	IMS registration weakness — unauthenticated REGISTER classification
CVE-2020-19857	probe	volte	none	SIP header-length handling on a captured message set
CVE-2021-33503	probe	volte	none	SIP URI parsing confusion on a captured message set
CVE-2020-11898	probe	paging	none	LTE paging-record length check on a captured PCCH dump
CVE-2020-11899	probe	paging	none	Paging occasion / DRX cycle sanity check
CVE-2019-19275	probe	sib	none	SIB1 / SIB2 mandatory-field presence and length check
CVE-2019-19276	probe	sib	none	SIB scheduling-info (SIB1 si-SchedulingInfo) consistency check
CVE-2019-19277	probe	sib	none	SIB segment concatenation length check
R2017-ASN1-VULN	probe	asn1	none	ASN.1 compiler and decoder library posture of the local toolchain
CVE-2025-20659	handoff	lte-baseband	ota-testbed	LLFuzz: 5-byte control-plane PDCP Data PDU corrupts the baseband (MediaTek)
CVE-2025-20708	handoff	lte-baseband	ota-testbed	LLFuzz: 1-byte PDCP Data PDU crashes the baseband (MediaTek)
CVE-2025-21477	handoff	lte-baseband	ota-testbed	LLFuzz: MAC header length mishandled when a CCCH sub-header is present (Qualcomm)
CVE-2025-26781	handoff	lte-baseband	ota-testbed	LLFuzz: RLC PDU with many data chunks crashes the baseband (Exynos)
CVE-2025-26782	handoff	lte-baseband	ota-testbed	LLFuzz: RLC PDU with many data chunks crashes the baseband (Tensor)
R2025-LLFUZZ	handoff	lte-baseband	ota-testbed	LLFuzz: L1/L2 (PHY/MAC/RLC/PDCP) OTA fuzzing campaign across 15 basebands
TABLE
}

lcve_kind_of() {
    local want="$1" id kind
    while IFS=$'\t' read -r id kind _; do
        [[ "$id" == "$want" ]] && { printf '%s\n' "$kind"; return 0; }
    done < <(lcve_cve_table)
    return 1
}

lcve_ids_of_kind() {
    local want="$1" id kind
    while IFS=$'\t' read -r id kind _; do
        [[ "$kind" == "$want" ]] && printf '%s\n' "$id"
    done < <(lcve_cve_table)
}

lcve_needs_of() {
    local want="$1" id kind cls needs
    while IFS=$'\t' read -r id kind cls needs _; do
        [[ "$id" == "$want" ]] && { printf '%s\n' "$needs"; return 0; }
    done < <(lcve_cve_table)
    printf 'unknown\n'
}

lcve_id_count() {
    lcve_cve_table | grep -c . || true
}

lcve_normalize_id() {
    local id="${1:-}"
    id="${id#"${id%%[![:space:]]*}"}"
    id="${id%"${id##*[![:space:]]}"}"
    printf '%s\n' "${id^^}"
}

lcve_id_known() {
    lcve_cve_table | cut -f1 | grep -qxF -- "$1"
}

# Ids whose probe reads an artefact from disk. With no artefact they must
# fail loudly and write no run row.
lcve_needs_artefact() {
    case "${1:-}" in
        R2019-ASN1-DECODE-CRASH|R2019-RRC-LENGTH-CONFUSION|R2019-NAS-LENGTH-CONFUSION|\
        R2019-NAS-COUNT-CONFUSION|CVE-2020-8493|CVE-2021-22191|CVE-2020-8283|\
        CVE-2020-25219|CVE-2020-25220|CVE-2020-19857|CVE-2021-33503|\
        CVE-2020-11898|CVE-2020-11899|CVE-2019-19275|CVE-2019-19276|CVE-2019-19277) return 0 ;;
        *) return 1 ;;
    esac
}

# ── target and artefact resolution ──────────────────────────────────────
LCVE_TARGET="${LCVE_TARGET:-}"

lcve_resolve_target() {
    local t="${LCVE_TARGET:-}"
    if [[ -z "$t" && -f "$TMP_DIR/target_plmn" ]]; then
        t="$(tr -d '[:space:]' < "$TMP_DIR/target_plmn" 2>/dev/null || true)"
        [[ -n "$t" ]] && t="PLMN:$t"
    fi
    [[ -z "$t" ]] && return 1
    printf '%s\n' "$t"
}

lcve_probe_input() {
    case "${1:-}" in
        asn1)    printf '%s\n' "${LCVE_ASN1_ARTEFACT:-$CAPTURES_DIR/lte/asn1.txt}" ;;
        rrc)     printf '%s\n' "${LCVE_RRC_ARTEFACT:-$CAPTURES_DIR/lte/rrc.txt}" ;;
        nas)     printf '%s\n' "${LCVE_NAS_ARTEFACT:-$CAPTURES_DIR/lte/nas.txt}" ;;
        diameter) printf '%s\n' "${LCVE_DIAMETER_ARTEFACT:-$CAPTURES_DIR/lte/diameter.txt}" ;;
        gtp)     printf '%s\n' "${LCVE_GTP_ARTEFACT:-$CAPTURES_DIR/lte/gtp.txt}" ;;
        sip)     printf '%s\n' "${LCVE_SIP_ARTEFACT:-$CAPTURES_DIR/lte/sip.txt}" ;;
        paging)  printf '%s\n' "${LCVE_PAGING_ARTEFACT:-$CAPTURES_DIR/lte/paging.txt}" ;;
        sib)     printf '%s\n' "${LCVE_SIB_ARTEFACT:-$CAPTURES_DIR/lte/sib.txt}" ;;
        *)       printf '%s\n' "" ;;
    esac
}

lcve_require_file() {
    local what="$1" f
    f="$(lcve_probe_input "$what")"
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

# ASN.1 decoder crash oracle: for every TLV-ish line in the corpus, check
# that the declared length fits inside the remaining bytes. A declared length
# past the end of the buffer is exactly the length-confusion class the NAS
# and RRC decoders have historically mishandled.
lcve_asn1_length_check() {
    local f="$1" total=0 bad=0 longest=0 line len rest
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        # "len=NN data=<hex>" or "len=NN bytes=MM". Only length-tagged lines
        # count: a corpus of untagged text is not a corpus, and the probe
        # must say so rather than report zero overruns over zero records.
        len=$(printf '%s' "$line" | sed -n 's/.*[Ll]en[=:][[:space:]]*\([0-9]*\).*/\1/p')
        [[ -z "$len" ]] && continue
        total=$((total + 1))
        rest=$(printf '%s' "$line" | sed -n 's/.*\(data\|bytes\|payload\)[=:][[:space:]]*\([0-9A-Fa-f ]*\).*/\2/p' | tr -d ' ')
        (( len > longest )) && longest="$len"
        if [[ -n "$rest" ]]; then
            # two hex chars per byte
            if (( len * 2 > ${#rest} )); then
                bad=$((bad + 1))
                printf 'overflow\tlen=%s available=%s\n' "$len" "$(( ${#rest} / 2 ))"
            fi
        fi
    done < "$f"
    printf 'corpus_lines\t%s\nlengths_checked\t%s\nlongest_len\t%s\noverruns\t%s\n' \
        "$total" "$total" "$longest" "$bad"
    if [[ "$total" -eq 0 ]]; then
        printf 'ERROR\tno length-tagged records in %s — the decoder check cannot run\n' "$(lcve_sanitize "$f")" >&2
        return 1
    fi
    if [[ "$bad" -gt 0 ]]; then
        printf 'STATUS\t%s record(s) declare a length past the buffer — ASN.1 length-confusion class\n' "$bad"
        return 0
    fi
    printf 'STATUS\tno length overrun in %s\n' "$(lcve_sanitize "$f")"
}

lcve_probe_asn1_crash() {
    local f; f="$(lcve_require_file asn1)" || return 1
    printf 'artefact\t%s\n' "$(lcve_sanitize "$f")"
    lcve_asn1_length_check "$f"
}

lcve_probe_rrc_length() {
    local f; f="$(lcve_require_file rrc)" || return 1
    printf 'artefact\t%s\nprotocol\tRRC\n' "$(lcve_sanitize "$f")"
    lcve_asn1_length_check "$f"
}

lcve_probe_nas_length() {
    local f; f="$(lcve_require_file nas)" || return 1
    printf 'artefact\t%s\nprotocol\tNAS-EMM/ESM\n' "$(lcve_sanitize "$f")"
    lcve_asn1_length_check "$f"
}

# NAS COUNT: the replay window is 2^8 for the reordered case; a capture that
# shows the same COUNT twice is a replay, and a COUNT far behind the current
# one is a stale message the UE should reject.
lcve_probe_nas_count() {
    local f n dup
    f="$(lcve_require_file nas)" || return 1
    n=$(grep -acE '(count|COUNT)[[:space:]]*[:=]' "$f" || true)
    dup=$(grep -aoE '(count|COUNT)[[:space:]]*[:=][[:space:]]*[0-9]+' "$f" \
          | grep -oE '[0-9]+$' | sort | uniq -d | grep -c . || true)
    printf 'artefact\t%s\ncounts_seen\t%s\nduplicate_counts\t%s\n' \
        "$(lcve_sanitize "$f")" "$n" "$dup"
    if [[ "$n" -eq 0 ]]; then
        printf 'ERROR\tno NAS COUNT field in %s — nothing to check\n' "$(lcve_sanitize "$f")" >&2
        return 1
    fi
    if [[ "$dup" -gt 0 ]]; then
        printf 'STATUS\t%s duplicate NAS COUNT value(s) — replay-window violation\n' "$dup"
    else
        printf 'STATUS\tno duplicate NAS COUNT in %s\n' "$(lcve_sanitize "$f")"
    fi
}

# Diameter S6a exposure. The question is not "is there a bug" but "is this
# HSS answering queries the visited network should not be able to ask".
lcve_probe_diameter_exposure() {
    local f ops=0 ans=0
    f="$(lcve_require_file diameter)" || return 1
    ops=$(grep -aciE '(AIR|ULR|CLR|IDR|authentication-information-request|update-location-request)' "$f" || true)
    ans=$(grep -aciE '(authentication-information-answer|update-location-answer|result-code)' "$f" || true)
    printf 'artefact\t%s\ns6a_requests\t%s\ns6a_answers\t%s\n' \
        "$(lcve_sanitize "$f")" "$ops" "$ans"
    if [[ "$ops" -eq 0 ]]; then
        printf 'ERROR\tno Diameter S6a request in %s — nothing to classify\n' "$(lcve_sanitize "$f")" >&2
        return 1
    fi
    grep -aoiE 'result-code[[:space:]]*[:=][[:space:]]*[0-9]+' "$f" | head -5 \
        | while IFS= read -r l; do printf 'result\t%s\n' "$(lcve_sanitize "$l")"; done
    if [[ "$ans" -gt 0 ]]; then
        printf 'STATUS\toffered S6a requests are answered — the HSS serves this interconnect\n'
    else
        printf 'STATUS\trequests present with no answer — Diameter edge is filtering\n'
    fi
}

# GTP-C amplification: measure the request/response byte ratio in a capture.
# An echo response substantially larger than its request is the amplification
# primitive; the factor is the number an operator needs.
lcve_probe_gtp_amplification() {
    local f req resp factor
    f="$(lcve_require_file gtp)" || return 1
    req=$(grep -aoiE 'echo-request[[:space:]]*[:=][[:space:]]*[0-9]+' "$f" | head -1 | grep -oE '[0-9]+$' || true)
    resp=$(grep -aoiE 'echo-response[[:space:]]*[:=][[:space:]]*[0-9]+' "$f" | head -1 | grep -oE '[0-9]+$' || true)
    printf 'artefact\t%s\necho_request_bytes\t%s\necho_response_bytes\t%s\n' \
        "$(lcve_sanitize "$f")" "${req:-unknown}" "${resp:-unknown}"
    if [[ -z "$req" || -z "$resp" ]]; then
        printf 'ERROR\t%s carries no Echo request/response size pair — no factor to compute\n' \
            "$(lcve_sanitize "$f")" >&2
        return 1
    fi
    [[ "$req" -eq 0 ]] && { printf 'ERROR\techo request size is zero\n' >&2; return 1; }
    factor=$(awk -v r="$resp" -v q="$req" 'BEGIN{printf "%.2f", r/q}')
    printf 'amplification_factor\t%s\n' "$factor"
    if awk -v f="$factor" 'BEGIN{exit !(f > 1.0)}'; then
        printf 'STATUS\tGTP-C echo amplification factor %s — response exceeds request\n' "$factor"
    else
        printf 'STATUS\tGTP-C echo amplification factor %s — no amplification\n' "$factor"
    fi
}

# GTP version / TEID sanity, the non-destructive half of the injection family.
lcve_probe_gtp_sanity() {
    local f versions teids bad=0
    f="$(lcve_require_file gtp)" || return 1
    versions=$(grep -aoiE 'version[[:space:]]*[:=][[:space:]]*[0-9]+' "$f" | grep -oE '[0-9]+$' | sort -u | tr '\n' ',' | sed 's/,$//')
    teids=$(grep -aciE 'teid[[:space:]]*[:=][[:space:]]*[0-9A-Fa-fx]+' "$f" || true)
    # A TEID of zero is legal only on the control plane with no tunnel yet.
    bad=$(grep -aoiE 'teid[[:space:]]*[:=][[:space:]]*0x?0+\b' "$f" | grep -c . || true)
    printf 'artefact\t%s\nversions\t%s\nteid_fields\t%s\nzero_teids\t%s\n' \
        "$(lcve_sanitize "$f")" "${versions:-none}" "$teids" "$bad"
    if [[ "$teids" -eq 0 ]]; then
        printf 'ERROR\tno TEID field in %s — nothing to sanity-check\n' "$(lcve_sanitize "$f")" >&2
        return 1
    fi
    printf 'STATUS\tGTP flow parsed: %s TEID field(s), %s zero TEID(s)\n' "$teids" "$bad"
}

# VoLTE / IMS SIP parser robustness: fixed-vs-chunked framing, header lengths
# and duplicated mandatory headers are the classes that broke real IMS stacks.
lcve_probe_sip_parser() {
    local f msgs bad_len dup_hdr
    f="$(lcve_require_file sip)" || return 1
    msgs=$(grep -acE '^(INVITE|REGISTER|SUBSCRIBE|NOTIFY|MESSAGE|BYE|OPTIONS|SIP/2\.0)' "$f" || true)
    bad_len=$(grep -aoiE 'content-length[[:space:]]*:[[:space:]]*[0-9]+' "$f" | grep -oE '[0-9]+$' \
              | awk '$1 > 65535' | grep -c . || true)
    dup_hdr=$(grep -aoiE '^(via|from|to|call-id|content-length|max-forwards)[[:space:]]*:' "$f" \
              | tr 'A-Z' 'a-z' | sort | uniq -d | grep -c . || true)
    printf 'artefact\t%s\nsip_messages\t%s\noversized_content_length\t%s\nduplicated_mandatory_headers\t%s\n' \
        "$(lcve_sanitize "$f")" "$msgs" "$bad_len" "$dup_hdr"
    if [[ "$msgs" -eq 0 ]]; then
        printf 'ERROR\tno SIP start-line in %s — the parser probe cannot run\n' "$(lcve_sanitize "$f")" >&2
        return 1
    fi
    if [[ "$bad_len" -gt 0 || "$dup_hdr" -gt 0 ]]; then
        printf 'STATUS\t%s oversized Content-Length and %s duplicated mandatory header(s) — parser-hardening candidates\n' \
            "$bad_len" "$dup_hdr"
    else
        printf 'STATUS\tno oversized or duplicated header in %s\n' "$(lcve_sanitize "$f")"
    fi
}

# IMS registration weakness: is the REGISTER answered without an AKA
# challenge, and is the contact address the operator's or a third party's?
lcve_probe_ims_register() {
    local f regs chall third
    f="$(lcve_require_file sip)" || return 1
    regs=$(grep -acE '^REGISTER ' "$f" || true)
    chall=$(grep -acE '^WWW-Authenticate[[:space:]]*:' "$f" || true)
    third=$(grep -aoiE '(^|[^0-9])sips?:[^@[:space:]]+@([0-9]{1,3}\.){3}[0-9]{1,3}' "$f" | grep -c . || true)
    printf 'artefact\t%s\nregisters\t%s\naka_challenges\t%s\nip_literal_contacts\t%s\n' \
        "$(lcve_sanitize "$f")" "$regs" "$chall" "$third"
    if [[ "$regs" -eq 0 ]]; then
        printf 'ERROR\tno REGISTER in %s — nothing to classify\n' "$(lcve_sanitize "$f")" >&2
        return 1
    fi
    if [[ "$chall" -eq 0 ]]; then
        printf 'STATUS\t%s REGISTER(s) and no AKA challenge — registration is not authenticated in this capture\n' "$regs"
    else
        printf 'STATUS\tregistration is AKA-challenged (%s challenge(s))\n' "$chall"
    fi
}

# LTE paging: a paging record carries a fixed-size UE identity and a record
# count; a length that disagrees with the count is the parsing fault.
lcve_probe_paging() {
    local f recs bad
    f="$(lcve_require_file paging)" || return 1
    recs=$(grep -aciE 'pagingRecord|paging-record' "$f" || true)
    bad=$(grep -aoiE '(recordCount|record-count)[[:space:]]*[:=][[:space:]]*[0-9]+' "$f" \
          | grep -oE '[0-9]+$' | awk '$1 > 16' | grep -c . || true)
    printf 'artefact\t%s\npaging_records\t%s\nover_count_records\t%s\n' \
        "$(lcve_sanitize "$f")" "$recs" "$bad"
    if [[ "$recs" -eq 0 ]]; then
        printf 'ERROR\tno paging record in %s — nothing to check\n' "$(lcve_sanitize "$f")" >&2
        return 1
    fi
    if [[ "$bad" -gt 0 ]]; then
        printf 'STATUS\t%s paging record count exceeds the 16-record maximum — length check bypass\n' "$bad"
    else
        printf 'STATUS\tpaging record counts are within the specification maximum\n'
    fi
}

# Paging occasion / DRX: the SFN must be consistent with the configured DRX
# cycle; an occasion that never lands is a paging-blackout condition.
lcve_probe_paging_occasion() {
    local f sfn drx
    f="$(lcve_require_file paging)" || return 1
    sfn=$(grep -aoiE 'sfn[[:space:]]*[:=][[:space:]]*[0-9]+' "$f" | head -1 | grep -oE '[0-9]+$' || true)
    drx=$(grep -aoiE 'defaultPagingCycle[[:space:]]*[:=][[:space:]]*(rf32|rf64|rf128|rf256|[0-9]+)' "$f" \
          | head -1 | grep -oiE '(rf32|rf64|rf128|rf256|[0-9]+)$' || true)
    printf 'artefact\t%s\nsfn\t%s\ndefault_paging_cycle\t%s\n' \
        "$(lcve_sanitize "$f")" "${sfn:-unknown}" "${drx:-unknown}"
    if [[ -z "$sfn" || -z "$drx" ]]; then
        printf 'ERROR\t%s lacks an SFN or a defaultPagingCycle — the occasion cannot be computed\n' \
            "$(lcve_sanitize "$f")" >&2
        return 1
    fi
    local cyc; cyc=$(printf '%s' "$drx" | tr -d 'rfRF')
    [[ "$cyc" =~ ^[0-9]+$ ]] || { printf 'ERROR\tunparseable paging cycle: %s\n' "$(lcve_sanitize "$drx")" >&2; return 1; }
    printf 'paging_frame_mod\t%s\n' "$(( sfn % cyc ))"
    printf 'STATUS\tSFN %s against cycle %s resolves to frame offset %s\n' "$sfn" "$cyc" "$(( sfn % cyc ))"
}

# SIB parsing. SIB1 carries the mandatory fields; a missing or contradictory
# one is the class the 2019 SIB bugs sit in.
lcve_probe_sib1() {
    local f cells bars
    f="$(lcve_require_file sib)" || return 1
    cells=$(grep -aciE 'sib1|systemInformationBlockType1' "$f" || true)
    bars=$(grep -aciE 'cellBarred[[:space:]]*[:=][[:space:]]*(barred|notBarred)' "$f" || true)
    printf 'artefact\t%s\nsib1_records\t%s\ncell_barred_fields\t%s\n' \
        "$(lcve_sanitize "$f")" "$cells" "$bars"
    if [[ "$cells" -eq 0 ]]; then
        printf 'ERROR\tno SIB1 record in %s — the mandatory-field check cannot run\n' "$(lcve_sanitize "$f")" >&2
        return 1
    fi
    # plmn-IdentityList, cellBarred and si-SchedulingInfo are mandatory.
    local missing=""
    grep -qaiE 'plmn-IdentityList|plmnIdentityList' "$f" || missing="${missing}plmn-IdentityList "
    grep -qaiE 'cellBarred'                         "$f" || missing="${missing}cellBarred "
    grep -qaiE 'si-SchedulingInfo|siSchedulingInfo' "$f" || missing="${missing}si-SchedulingInfo "
    if [[ -n "$missing" ]]; then
        printf 'missing_mandatory\t%s\n' "$(lcve_sanitize "$missing")"
        printf 'STATUS\tSIB1 is missing mandatory field(s): %s\n' "$(lcve_sanitize "$missing")"
        return 0
    fi
    printf 'missing_mandatory\tnone\n'
    printf 'STATUS\tSIB1 carries all mandatory fields\n'
}

lcve_probe_sib_sched() {
    local f sched entries
    f="$(lcve_require_file sib)" || return 1
    sched=$(grep -aciE 'si-SchedulingInfo|siSchedulingInfo|schedulingInfoList' "$f" || true)
    entries=$(grep -aciE 'sib-Type|sibType|si-Periodicity|siPeriodicity' "$f" || true)
    printf 'artefact\t%s\nscheduling_blocks\t%s\nsib_entries\t%s\n' \
        "$(lcve_sanitize "$f")" "$sched" "$entries"
    if [[ "$sched" -eq 0 ]]; then
        printf 'ERROR\tno si-SchedulingInfo in %s — nothing to cross-check\n' "$(lcve_sanitize "$f")" >&2
        return 1
    fi
    if [[ "$entries" -eq 0 ]]; then
        printf 'STATUS\tscheduling info with no SIB entry — the schedule references nothing\n'
        return 0
    fi
    printf 'STATUS\t%s scheduling block(s) referencing %s SIB entr(ies)\n' "$sched" "$entries"
}

lcve_probe_sib_segments() {
    local f segs declared
    f="$(lcve_require_file sib)" || return 1
    segs=$(grep -aciE 'segment(Number|Type|number)?[[:space:]]*[:=]' "$f" || true)
    declared=$(grep -aoiE '(segmentNumber|segCount|segmentCount)[[:space:]]*[:=][[:space:]]*[0-9]+' "$f" \
               | grep -oE '[0-9]+$' | sort -n | tail -1 || true)
    printf 'artefact\t%s\nsegment_fields\t%s\nhighest_segment_index\t%s\n' \
        "$(lcve_sanitize "$f")" "$segs" "${declared:-unknown}"
    if [[ "$segs" -eq 0 ]]; then
        printf 'ERROR\tno segment field in %s — the concatenation check cannot run\n' "$(lcve_sanitize "$f")" >&2
        return 1
    fi
    # A segment index beyond the final-segment marker means a gap or a repeat.
    if grep -qaiE 'lastSegment[[:space:]]*[:=][[:space:]]*true' "$f" && [[ -n "$declared" ]]; then
        local last_idx
        last_idx=$(grep -aiE 'lastSegment[[:space:]]*[:=][[:space:]]*true' "$f" | head -1 \
                   | grep -oE 'segment(Number)?[[:space:]]*[:=][[:space:]]*[0-9]+' | grep -oE '[0-9]+$' || true)
        if [[ -n "$last_idx" && "$last_idx" -ne "$declared" ]]; then
            printf 'STATUS\tlast-segment index %s disagrees with the highest seen %s — segment gap\n' "$last_idx" "$declared"
            return 0
        fi
    fi
    printf 'STATUS\t%s segment field(s), highest index %s — concatenation is consistent\n' "$segs" "${declared:-unknown}"
}

# The local ASN.1 toolchain posture. An old asn1c or a decoder built without
# length hardening is how a malformed PDU becomes a crash rather than a
# rejection; this reports what is installed, it does not attack anything.
lcve_probe_asn1_toolchain() {
    local found=0 t
    printf 'probe\tasn1-toolchain\n'
    for t in asn1c; do
        if command -v "$t" >/dev/null 2>&1; then
            printf 'tool\t%s\nversion\t%s\n' "$t" "$(lcve_sanitize "$("$t" -v 2>&1 | head -1)")"
            found=$((found + 1))
        fi
    done
    if command -v tshark >/dev/null 2>&1; then
        printf 'tool\ttshark\nversion\t%s\n' "$(lcve_sanitize "$(tshark -v 2>/dev/null | head -1)")"
        found=$((found + 1))
    fi
    for t in srsran srsue srsenb; do
        command -v "$t" >/dev/null 2>&1 && { printf 'tool\t%s\n' "$t"; found=$((found + 1)); }
    done
    printf 'tools_found\t%s\n' "$found"
    if [[ "$found" -eq 0 ]]; then
        printf 'STATUS\tno ASN.1 or LTE decoder toolchain installed — decoder posture unknown\n'
        return 0
    fi
    printf 'STATUS\t%s relevant tool(s) present\n' "$found"
}

# The Bluetooth/cellular coexistence key-validation probe (CVE-2018-5383).
# The flaw is that the peer never validates the other side's public key
# against the curve; the observable is a fixed or repeated parameter set.
lcve_probe_key_validation() {
    local f repeated curves
    f="${LCVE_BT_ARTEFACT:-$CAPTURES_DIR/lte/pairing.txt}"
    if [[ ! -f "$f" || ! -s "$f" ]]; then
        printf 'ERROR\tno pairing artefact at %s — the key-validation check cannot run\n' "$(lcve_sanitize "$f")" >&2
        return 1
    fi
    repeated=$(grep -aoiE '(pubkey|publicKey|pk)[[:space:]]*[:=][[:space:]]*[0-9A-Fa-f]+' "$f" \
               | sed 's/.*[:=][[:space:]]*//' | sort | uniq -d | grep -c . || true)
    curves=$(grep -aciE '(P-256|P-384|secp256r1|curve)' "$f" || true)
    printf 'artefact\t%s\nrepeated_public_keys\t%s\ncurve_markers\t%s\n' \
        "$(lcve_sanitize "$f")" "$repeated" "$curves"
    if [[ "$repeated" -gt 0 ]]; then
        printf 'STATUS\t%s repeated public key(s) in the pairing set — fixed-parameter key validation\n' "$repeated"
    else
        printf 'STATUS\tno repeated public key in the pairing set\n'
    fi
}

# KNOB (CVE-2019-9506): the attack is a negotiated key length below the
# 7-byte entropy floor. The capture shows the negotiated length.
lcve_probe_knob() {
    local f lens low=0 l
    f="${LCVE_BT_ARTEFACT:-$CAPTURES_DIR/lte/pairing.txt}"
    [[ -f "$f" && -s "$f" ]] || {
        printf 'ERROR\tno pairing artefact at %s — the KNOB check cannot run\n' "$(lcve_sanitize "$f")" >&2
        return 1
    }
    lens=$(grep -aoiE '(keyLength|key-length|entropy)[[:space:]]*[:=][[:space:]]*[0-9]+' "$f" | grep -oE '[0-9]+$' || true)
    printf 'artefact\t%s\n' "$(lcve_sanitize "$f")"
    if [[ -z "$lens" ]]; then
        printf 'ERROR\tno negotiated key-length field in %s\n' "$(lcve_sanitize "$f")" >&2
        return 1
    fi
    while IFS= read -r l; do
        [[ -z "$l" ]] && continue
        printf 'key_length_bits\t%s\n' "$l"
        (( l < 56 )) && low=$((low + 1))
    done <<< "$lens"
    if [[ "$low" -gt 0 ]]; then
        printf 'STATUS\t%s negotiation(s) below the 7-byte floor — KNOB downgrade applies\n' "$low"
    else
        printf 'STATUS\tall negotiated key lengths are at or above the 7-byte floor\n'
    fi
}

# BIAS (CVE-2020-10135): legacy pairing without secure simple pairing is the
# precondition. Classify the pairing mode in the capture.
lcve_probe_bias() {
    local f legacy ssp
    f="${LCVE_BT_ARTEFACT:-$CAPTURES_DIR/lte/pairing.txt}"
    [[ -f "$f" && -s "$f" ]] || {
        printf 'ERROR\tno pairing artefact at %s — the BIAS check cannot run\n' "$(lcve_sanitize "$f")" >&2
        return 1
    }
    legacy=$(grep -aciE 'legacy[[:space:]]*pairing|legacyPairing|PIN[[:space:]]*code' "$f" || true)
    ssp=$(grep -aciE 'secure[[:space:]]*simple[[:space:]]*pairing|SSP[[:space:]]*(enabled|used)|numeric[[:space:]]*comparison' "$f" || true)
    printf 'artefact\t%s\nlegacy_pairing_markers\t%s\nssp_markers\t%s\n' \
        "$(lcve_sanitize "$f")" "$legacy" "$ssp"
    if [[ "$legacy" -gt 0 && "$ssp" -eq 0 ]]; then
        printf 'STATUS\tlegacy pairing with no SSP — BIAS authentication bypass applies\n'
        return 0
    fi
    printf 'STATUS\tSSP in use or no legacy marker — BIAS precondition not met\n'
}

# ── HANDOFFS ────────────────────────────────────────────────────────────
lcve_handoff_plan() {
    local id="$1" note="$2"
    local slug f
    slug="$(printf '%s' "$id" | tr -c 'A-Za-z0-9._-' '_')"
    mkdir -p "$LCVE_PLANS" 2>/dev/null || {
        printf 'ERROR\tcannot create plan dir %s\n' "$LCVE_PLANS" >&2; return 1; }
    f="$LCVE_PLANS/plan_${slug}.txt"
    {
        printf 'cve: %s\n' "$(lcve_sanitize "$id")"
        printf 'kit: lte_cve\n'
        printf 'status: handoff — no safe automated one-shot probe in this kit\n'
        printf 'note: %s\n' "$(lcve_sanitize "$note")"
        printf 'requires: %s\n' "$(lcve_needs_of "$id")"
        printf 'ts: %s\n' "$(date -Is)"
    } > "$f" || {
        printf 'ERROR\tcannot write plan file %s\n' "$f" >&2; return 1; }
    printf 'cve\t%s\nstatus\thandoff\nplan\t%s\nnote\t%s\n' \
        "$(lcve_sanitize "$id")" "$(lcve_sanitize "$f")" "$(lcve_sanitize "$note")"
    lcve_record_run "$id" "handoff" "-" "$note"
    return 0
}

# ── per-id dispatch ─────────────────────────────────────────────────────
lcve_run_cve() {
    local raw="${1:-}" id
    if [[ -z "$raw" ]]; then
        printf 'usage: %s --run-cve <ID>\n' "$0" >&2
        return 2
    fi
    id="$(lcve_normalize_id "$raw")"
    mkdir -p "$LCVE_DIR" "$LCVE_PLANS" 2>/dev/null

    case "$id" in
        # ── ASN.1 / NAS / RRC parsing ──────────────────────────────────
        R2019-ASN1-DECODE-CRASH)
            lcve_probe_asn1_crash && lcve_record_run "$id" probe-ok "$(lcve_sanitize "$(lcve_probe_input asn1)")" "ASN.1 length oracle run" ;;
        R2019-RRC-LENGTH-CONFUSION)
            lcve_probe_rrc_length && lcve_record_run "$id" probe-ok "$(lcve_sanitize "$(lcve_probe_input rrc)")" "RRC length confusion classified" ;;
        R2019-NAS-LENGTH-CONFUSION)
            lcve_probe_nas_length && lcve_record_run "$id" probe-ok "$(lcve_sanitize "$(lcve_probe_input nas)")" "NAS length confusion classified" ;;
        R2019-NAS-COUNT-CONFUSION)
            lcve_probe_nas_count && lcve_record_run "$id" probe-ok "$(lcve_sanitize "$(lcve_probe_input nas)")" "NAS COUNT replay window checked" ;;
        R2017-ASN1-VULN)
            lcve_probe_asn1_toolchain && lcve_record_run "$id" probe-ok "local" "decoder toolchain posture" ;;

        # ── EPC: Diameter and GTP ──────────────────────────────────────
        CVE-2020-8493)
            lcve_probe_diameter_exposure && lcve_record_run "$id" probe-ok "$(lcve_sanitize "$(lcve_probe_input diameter)")" "S6a exposure classified" ;;
        CVE-2021-22191)
            lcve_probe_gtp_amplification && lcve_record_run "$id" probe-ok "$(lcve_sanitize "$(lcve_probe_input gtp)")" "GTP-C amplification measured" ;;
        CVE-2020-8283)
            lcve_probe_gtp_sanity && lcve_record_run "$id" probe-ok "$(lcve_sanitize "$(lcve_probe_input gtp)")" "GTP version/TEID sanity checked" ;;

        # ── VoLTE / IMS ────────────────────────────────────────────────
        CVE-2020-25219)
            lcve_probe_sip_parser && lcve_record_run "$id" probe-ok "$(lcve_sanitize "$(lcve_probe_input sip)")" "SIP parser robustness classified" ;;
        CVE-2020-25220)
            lcve_probe_ims_register && lcve_record_run "$id" probe-ok "$(lcve_sanitize "$(lcve_probe_input sip)")" "IMS registration weakness classified" ;;
        CVE-2020-19857)
            lcve_probe_sip_parser && lcve_record_run "$id" probe-ok "$(lcve_sanitize "$(lcve_probe_input sip)")" "SIP header-length handling checked" ;;
        CVE-2021-33503)
            lcve_probe_sip_parser && lcve_record_run "$id" probe-ok "$(lcve_sanitize "$(lcve_probe_input sip)")" "SIP URI parsing confusion checked" ;;

        # ── paging and SIB ─────────────────────────────────────────────
        CVE-2020-11898)
            lcve_probe_paging && lcve_record_run "$id" probe-ok "$(lcve_sanitize "$(lcve_probe_input paging)")" "paging record length checked" ;;
        CVE-2020-11899)
            lcve_probe_paging_occasion && lcve_record_run "$id" probe-ok "$(lcve_sanitize "$(lcve_probe_input paging)")" "paging occasion computed" ;;
        CVE-2019-19275)
            lcve_probe_sib1 && lcve_record_run "$id" probe-ok "$(lcve_sanitize "$(lcve_probe_input sib)")" "SIB1 mandatory fields checked" ;;
        CVE-2019-19276)
            lcve_probe_sib_sched && lcve_record_run "$id" probe-ok "$(lcve_sanitize "$(lcve_probe_input sib)")" "SIB scheduling info checked" ;;
        CVE-2019-19277)
            lcve_probe_sib_segments && lcve_record_run "$id" probe-ok "$(lcve_sanitize "$(lcve_probe_input sib)")" "SIB segment concatenation checked" ;;

        # ── coexistence / pairing key checks ───────────────────────────
        CVE-2018-5383)
            lcve_probe_key_validation && lcve_record_run "$id" probe-ok "$(lcve_sanitize "${LCVE_BT_ARTEFACT:-$CAPTURES_DIR/lte/pairing.txt}")" "public-key validation classified" ;;
        CVE-2019-9506)
            lcve_probe_knob && lcve_record_run "$id" probe-ok "$(lcve_sanitize "${LCVE_BT_ARTEFACT:-$CAPTURES_DIR/lte/pairing.txt}")" "negotiated key length classified" ;;
        CVE-2020-10135)
            lcve_probe_bias && lcve_record_run "$id" probe-ok "$(lcve_sanitize "${LCVE_BT_ARTEFACT:-$CAPTURES_DIR/lte/pairing.txt}")" "pairing mode classified" ;;

        # ── baseband handoffs ──────────────────────────────────────────
        CVE-2017-6975)
            lcve_handoff_plan "$id" "Broadcom/Cypress Wi-Fi and LTE coexistence overflow — needs a lab network: a Faraday-caged eNB, the target handset, and the vendor's coexistence firmware to instrument" ;;
        CVE-2018-11976)
            lcve_handoff_plan "$id" "Qualcomm QSEE key extraction — needs an OTA testbed plus a TrustZone-capable target the vendor has authorised, and a QSEE log channel" ;;
        CVE-2020-11201)
            lcve_handoff_plan "$id" "Qualcomm baseband data-services corruption — needs an OTA testbed: srsRAN or an AMARI/OpenBTS cell emulator with a transmit-capable SDR and a shielded target" ;;
        CVE-2020-11202)
            lcve_handoff_plan "$id" "Qualcomm baseband over-the-air decoder corruption — needs a transmit-capable SDR plus a crash oracle: QXDM, the baseband ramdump, or a controlled reboot counter" ;;
        CVE-2020-11204)
            lcve_handoff_plan "$id" "Qualcomm NAS/AS path corruption — needs an OTA testbed and the NAS message injector from a cell emulator the operator authorises" ;;
        CVE-2020-11197)
            lcve_handoff_plan "$id" "Qualcomm WLAN/LTE coexistence bug — needs both radios live in a shielded enclosure plus a coexistence test harness" ;;
        CVE-2021-30324)
            lcve_handoff_plan "$id" "Qualcomm baseband reachable corruption — needs an OTA testbed with a crash oracle and the vendor's baseband debug interface" ;;
        CVE-2021-30295)
            lcve_handoff_plan "$id" "Qualcomm baseband memory corruption delivered over the air — needs a transmit-capable SDR and a shielded target handset" ;;
        CVE-2022-21744)
            lcve_handoff_plan "$id" "MediaTek baseband OTA-deliverable memory corruption — needs a transmit-capable SDR plus the MediaTek baseband log interface; reference: Comsecuris baseband research" ;;
        CVE-2022-26447)
            lcve_handoff_plan "$id" "MediaTek baseband remote code execution from a crafted cellular frame — needs an OTA testbed and MTKLogger or ELT for crash confirmation" ;;
        CVE-2020-0069)
            lcve_handoff_plan "$id" "MediaTek command-queue driver escalation — local privilege escalation, needs the target device with ADB or a flashing interface, not a radio" ;;
        CVE-2019-16254)
            lcve_handoff_plan "$id" "Samsung Exynos / Shannon modem reachable corruption — needs a lab network: a Faraday-caged eNB the vendor has authorised plus a Shannon debug UART" ;;
        CVE-2021-25488)
            lcve_handoff_plan "$id" "Samsung Exynos baseband memory corruption — needs an OTA testbed plus a Shannon crash oracle; vendor-disclosed, patch level is the deciding factor" ;;
        CVE-2020-12363)
            lcve_handoff_plan "$id" "Intel baseband XMM corruption — needs a lab network with an authorised cell and the Intel baseband trace tool" ;;
        CVE-2021-0146)
            lcve_handoff_plan "$id" "Intel baseband debug-mode enablement — needs physical access to the target: a debug header or a vendor service interface, not an over-the-air vector" ;;
        CVE-2022-22265)
            lcve_handoff_plan "$id" "Samsung NPU/TrustZone escalation — needs local access to the device and the vendor kernel sources; not reachable from the air interface" ;;
        CVE-2023-21517)
            lcve_handoff_plan "$id" "Huawei Balong baseband corruption — needs an OTA testbed plus the Balong debug interface; the vendor must authorise the target" ;;
        CVE-2021-34699)
            lcve_handoff_plan "$id" "Reserved CVE id retained for completeness. Not a usable target: the record is a duplicate with no reachable path, so no probe and no testbed are defined. Kept in the dispatch so the id routes instead of erroring." ;;

        # ── fuzzing research handoffs ──────────────────────────────────
        R2020-MTK-BB-FUZZ)
            lcve_handoff_plan "$id" "MediaTek baseband fuzzing — needs an OTA testbed plus the Comsecuris baseband fuzzing harness; reference: Comsecuris baseband security research, Nohl et al." ;;
        R2020-QC-BB-FUZZ)
            lcve_handoff_plan "$id" "Qualcomm baseband fuzzing — needs an OTA testbed plus the Quarkslab baseband fuzzing harness; reference: Quarkslab baseband research" ;;
        R2019-P0-BB-FUZZ)
            lcve_handoff_plan "$id" "Baseband fuzzing via an over-the-air harness — needs a transmit-capable SDR; reference: Google Project Zero baseband fuzzing work" ;;

        # ── EPC handoffs ───────────────────────────────────────────────
        CVE-2020-8514)
            lcve_handoff_plan "$id" "Diameter DoS via crafted AVP lengths — needs a lab STP or a Diameter test interconnect the operator authorises, plus a traffic generator" ;;
        CVE-2020-11412)
            lcve_handoff_plan "$id" "Diameter S6a/S6d message forgery — needs a lab STP and a test HSS with a subscriber profile you own" ;;
        CVE-2021-22192)
            lcve_handoff_plan "$id" "GTP-U injection into a bearer — needs a lab network: an isolated EPC with a test PGW and a UE you control" ;;
        CVE-2021-22193)
            lcve_handoff_plan "$id" "GTP-C node-address spoofing — needs a lab network with an SGSN/MME and a test APN" ;;
        CVE-2019-15055)
            lcve_handoff_plan "$id" "GTP-U packet injection and bearer hijack — needs a lab network: srsRAN EPC or Open5GS with a test UE in a shielded enclosure" ;;
        CVE-2019-15056)
            lcve_handoff_plan "$id" "GTP-C session spoofing — needs a lab network with the SGSN/MME and PGW you own" ;;
        CVE-2021-45426)
            lcve_handoff_plan "$id" "S1-MME signalling exposure — needs a lab network with an MME reachable from an unauthorised eNB" ;;
        CVE-2021-45427)
            lcve_handoff_plan "$id" "S1-U user-plane exposure from a rogue eNB — needs a lab network plus a rogue eNB you control on an isolated PLMN" ;;
        CVE-2021-45428)
            lcve_handoff_plan "$id" "EPC attach-procedure abuse from a rogue eNB — needs srsRAN or OpenAirInterface eNB and an isolated test core" ;;

        # ── LLFuzz L1/L2 baseband cases ────────────────────────────────
        CVE-2025-20659|CVE-2025-20708)
            lcve_handoff_plan "$id" "LLFuzz PDCP control-plane PDU case (MediaTek) — the frame builds in 54_baseband_exploit --l2-case PDCP; needs an OTA testbed and MTKLogger as the crash oracle" ;;
        CVE-2025-21477)
            lcve_handoff_plan "$id" "LLFuzz MAC CCCH length case (Qualcomm) — builds in 54_baseband_exploit --l2-case MAC; needs a transmit SDR, a shielded target and QXDM" ;;
        CVE-2025-26781|CVE-2025-26782)
            lcve_handoff_plan "$id" "LLFuzz RLC many-chunks case — builds in 54_baseband_exploit --l2-case RLC; needs an OTA testbed and the vendor crash log" ;;
        R2025-LLFUZZ)
            lcve_handoff_plan "$id" "LLFuzz L1/L2 fuzzing campaign — needs a transmit-capable SDR and a stateful harness; the corpus builds in 54_baseband_exploit --l2-corpus" ;;

        # ── probe ids whose artefact is absent, and unknown ids ────────
        *)
            if lcve_id_known "$id"; then
                printf 'ERROR\tno probe input for %s — supply the artefact this probe reads (see --list-cves), or record it as handoff\n' \
                    "$(lcve_sanitize "$id")" >&2
                return 1
            fi
            printf 'ERROR\tunknown CVE id: %s (see --list-cves)\n' "$(lcve_sanitize "$raw")" >&2
            return 2 ;;
    esac
}

# ── CLI verbs ───────────────────────────────────────────────────────────
# The shared state file is written by 01_radio as <driver>\t<serial>\t<index>.
# Never paste it raw into a status row: that puts three values into a two-field
# contract. Split it into three 2-field rows instead.
lcve_sdr_rows() {
    local drv="none" sn="none" idx="none"
    if [[ -s "$LCVE_SDR" ]]; then
        IFS=$'\t' read -r drv sn idx < <(tr -d '\r' < "$LCVE_SDR" | head -n1)
    fi
    printf 'sdr\t%s\n'        "${drv:-none}"
    printf 'sdr_serial\t%s\n' "${sn:-none}"
    printf 'sdr_index\t%s\n'  "${idx:-none}"
}

# ── --cve-search: query the bundle, and say where applicability comes from ──
# The table above is the whole bundle. It carries the id, the kind, the class,
# the testbed and one sentence -- it does NOT carry a CVSS score, an affected
# version range or a patch state, because none of those numbers exists on this
# machine and nothing may be downloaded to get one (AGENTS.md: no CVE feed).
#
# So version applicability is read from an on-disk table if one is there, and
# reported `unobserved` when it is not. Nothing is guessed. The file looked for
# is tools/cve-applicability.tsv, four columns, header first:
#     id <TAB> source <TAB> affected <TAB> fixed
# `source` is where a range came from (an advisory, a vendor page, a spec);
# `affected` and `fixed` are the version strings that page states, and either
# may be `-` when the source states only one end.
lcve_applicability_path() {
    printf '%s' "${IMSI_CVE_APPLICABILITY:-$IMSISTING_ROOT/tools/cve-applicability.tsv}"
}

lcve_applies_for() {   # <id> <table> -> affected<TAB>fixed<TAB>source; rc1 = no record
    local id="${1:-}" tbl="${2:-}" rid rsrc raff rfix
    [[ -n "$id" && -f "$tbl" ]] || return 1
    while IFS=$'\t' read -r rid rsrc raff rfix; do
        [[ -z "${rid:-}" || "$rid" == \#* ]] && continue
        [[ "$rid" == "$id" ]] || continue
        printf '%s\t%s\t%s\n' "${raff:--}" "${rfix:--}" "${rsrc:--}"
        return 0
    done < "$tbl"
    return 1
}

lcve_cmd_cve_search() {
    local term="${1:-}" tbl="${2:-}" log ts id kind cls needs label app
    local applies affected fixed basis hits=0 line needle hay
    if [[ -z "$term" ]]; then
        printf 'ERROR\tusage: --cve-search <term> [applicability.tsv]\n' >&2
        return 2
    fi
    tbl="${2:-$(lcve_applicability_path)}"
    # Path computed at call time, never at load time: a selftest repoints
    # LCVE_DIR at a scratch tree and a captured global would write into loot/.
    log="$LCVE_DIR/cve_search.tsv"
    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    mkdir -p "$LCVE_DIR" 2>/dev/null
    if [[ ! -f "$log" ]]; then
        printf 'ts\tterm\tid\tkind\tclass\tneeds\tapplies\taffected\tfixed_in\tbasis\tlabel\n' > "$log"
    fi
    printf 'id\tkind\tclass\tneeds\tapplies\taffected\tfixed_in\tbasis\tlabel\n'
    needle=$(printf '%s' "$term" | tr 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' 'abcdefghijklmnopqrstuvwxyz')
    while IFS=$'\t' read -r id kind cls needs label; do
        [[ -z "${id:-}" || "$id" == \#* ]] && continue
        hay=$(printf '%s %s %s %s %s' "$id" "$kind" "$cls" "$needs" "$label" \
            | tr 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' 'abcdefghijklmnopqrstuvwxyz')
        case "$hay" in *"$needle"*) ;; *) continue ;; esac
        if app=$(lcve_applies_for "$id" "$tbl"); then
            affected=$(printf '%s\n' "$app" | cut -f1)
            fixed=$(printf '%s\n' "$app" | cut -f2)
            basis=$(printf '%s\n' "$app" | cut -f3)
            case "$affected" in
                -|none|'') applies='not-stated-by-source' ;;
                *)         applies='version-range-stated' ;;
            esac
        else
            applies='unobserved'
            affected='-'; fixed='-'
            if [[ -f "$tbl" ]]; then
                basis="no applicability record for $id in $tbl"
            else
                basis="no applicability table on disk (looked for $tbl)"
            fi
        fi
        line=$(printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s' \
            "$(lcve_sanitize "$id")" "$(lcve_sanitize "$kind")" \
            "$(lcve_sanitize "$cls")" "$(lcve_sanitize "$needs")" \
            "$applies" "$(lcve_sanitize "$affected")" "$(lcve_sanitize "$fixed")" \
            "$(lcve_sanitize "$basis")" "$(lcve_sanitize "$label")")
        printf '%s\n' "$line"
        printf '%s\t%s\t%s\n' "$ts" "$(lcve_sanitize "$term")" "$line" >> "$log"
        hits=$((hits + 1))
    done < <(lcve_cve_table)
    if [[ -f "$tbl" ]]; then
        printf 'summary\tmatches\t%s\tapplicability\t%s\n' "$hits" "$(lcve_sanitize "$tbl")"
    else
        printf 'summary\tmatches\t%s\tapplicability\tunobserved\treason\t%s\n' \
            "$hits" "$(lcve_sanitize "no table at $tbl")"
    fi
    if (( hits == 0 )); then
        printf 'note\tno row in the bundled table matches "%s"; the bundle holds %s ids, and an id this tree does not carry is unobserved here -- not absent from the standard\n' \
            "$(lcve_sanitize "$term")" "$(lcve_id_count)"
        return 1
    fi
    return 0
}

lcve_cli_status_tsv() {
    local plans
    plans=$(find "$LCVE_PLANS" -type f -name 'plan_*.txt' 2>/dev/null | wc -l | tr -d ' ')
    printf 'module\tlte_cve\nversion\t%s\n' "$LCVE_VERSION"
    printf 'ids\t%s\n'      "$(lcve_id_count)"
    printf 'probes\t%s\n'   "$(lcve_ids_of_kind probe | grep -c . || true)"
    printf 'handoffs\t%s\n' "$(lcve_ids_of_kind handoff | grep -c . || true)"
    printf 'runs\t%s\n'     "$(lcve_run_count)"
    printf 'plans\t%s\n'    "$plans"
    printf 'applicability\t%s\n'  "$( [[ -f "$(lcve_applicability_path)" ]] \
        && lcve_applicability_path || printf 'unobserved')"
    lcve_sdr_rows
    printf 'target\t%s\n'   "$(lcve_resolve_target 2>/dev/null || echo none)"
    printf 'dir\t%s\n'      "$LCVE_DIR"
    printf 'runs_file\t%s\n' "$LCVE_RUNS"
    printf 'plans_dir\t%s\n' "$LCVE_PLANS"
}

lcve_cmd_list_cves() {
    local id kind cls needs label
    printf 'id\tkind\tclass\tneeds\tlabel\n'
    while IFS=$'\t' read -r id kind cls needs label; do
        [[ -z "$id" ]] && continue
        printf '%s\t%s\t%s\t%s\t%s\n' \
            "$(lcve_sanitize "$id")" "$(lcve_sanitize "$kind")" \
            "$(lcve_sanitize "$cls")" "$(lcve_sanitize "$needs")" \
            "$(lcve_sanitize "$label")"
    done < <(lcve_cve_table)
}

lcve_cmd_runs_tsv() {
    if [[ "$(lcve_run_count)" -eq 0 ]]; then
        printf 'ERROR\tno CVE runs recorded yet\n' >&2
        return 1
    fi
    cat "$LCVE_RUNS"
}

# ── the RANSacked corpus ────────────────────────────────────────────────
# A catalogue read from data, not restated in this script: every row was
# extracted from the report's vulnerability section, and the extraction is
# checked against the report's own totals by tools/check-ransacked-corpus.sh.
# Columns: id alt impl gen proto pattern reach kind needs description
if [[ -z "${LCVE_CATALOG:-}" ]]; then
    LCVE_CATALOG="$IMSISTING_ROOT/tools/ransacked_catalog.tsv"
fi
if [[ -z "${LCVE_GEN:-}" ]]; then
    LCVE_GEN="$IMSISTING_ROOT/tools/ransacked_gen.py"
fi

lcve_catalog_require() {
    if [[ ! -r "$LCVE_CATALOG" ]]; then
        printf 'ERROR\tthe RANSacked catalogue is missing: %s\n' "$LCVE_CATALOG" >&2
        printf 'WHY\tthe corpus is data, so an absent file is an absent corpus and not an empty one\n' >&2
        return 1
    fi
    return 0
}

lcve_corpus_count() {
    lcve_catalog_require || return 1
    tail -n +1 "$LCVE_CATALOG" | grep -c . || true
}

# --corpus [REACH] [CLASS] [KIT]  →  the entries, filed by kit and class
lcve_cmd_corpus() {
    # Positional, not flags: reach, class, kit. "-" is this module's way of
    # saying "any", and the three columns are what the filing is made of.
    local reach="${1:--}" klass="${2:--}" kit="${3:--}"
    lcve_catalog_require || return 1
    printf 'id\talt\timpl\tgen\tproto\tpattern\treach\tkind\tneeds\tlabel\tmodule\tclass\n'
    awk -F'\t' -v reach="$reach" -v klass="$klass" -v kit="$kit" '
        (reach=="-" || $7==reach) &&
        (!klass || klass=="-" || $12==klass) &&
        (kit=="-"   || $11==kit) { printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
                                    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12 }' "$LCVE_CATALOG"
}

lcve_cmd_corpus_entry() {
    local want="${1:-}"
    if [[ -z "$want" ]]; then
        printf 'ERROR\tusage: --corpus-entry <CVE|VULN id>\n' >&2
        return 2
    fi
    lcve_catalog_require || return 1
    local row
    row=$(awk -F'\t' -v w="${want^^}" 'toupper($1)==w || (","toupper($2)"," ~ ","w",")' "$LCVE_CATALOG")
    if [[ -z "$row" ]]; then
        printf 'ERROR\t%s is not in the RANSacked corpus\n' "$want" >&2
        printf 'NOTE\tthe catalogue holds what the report published; an id it does not list is not a finding it did not make\n' >&2
        return 1
    fi
    printf '%s\n' "$row" | awk -F'\t' '{
        printf "id\t%s\nalt_ids\t%s\nimplementation\t%s\ngeneration\t%s\nprotocol\t%s\n",
               $1, ($2==""?"-":$2), $3, $4, $5
        printf "pattern\t%s\nreach\t%s\nkind\t%s\nneeds\t%s\nlabel\t%s\n",
               $6, $7, $8, $9, $10
        printf "module\t%s\nclass\t%s\n", $11, $12 }'
    # The reach is the finding, and it is the report's, not this tree's.
    case "$(printf '%s' "$row" | cut -f7)" in
        nas-no-sim) printf 'reach_note\treachable at connection start with no SIM; the page says Wi-Fi Calling makes it internet-reachable, which the page does not itself demonstrate\n' ;;
        s1-access)  printf 'reach_note\tneeds base-station or IPsec-backhaul access to the core\n' ;;
        n2-access)  printf 'reach_note\tneeds N2 access, which is the base-station side in 5G\n' ;;
        gtp-bearer) printf 'reach_note\tneeds an established bearer or a routing position on the user plane\n' ;;
        *)          printf 'reach_note\t-\n' ;;
    esac
}

lcve_cmd_corpus_stats() {
    lcve_catalog_require || return 1
    local rows
    rows=$(lcve_corpus_count)
    printf 'entries\t%s\n' "$rows"
    awk -F'\t' '{impl[$3]++; proto[$5]++; pat[$6]++; reach[$7]++; kind[$8]++; cls[$12]++; kit[$11]++}
        END {
            for (k in impl)  printf "impl.%s\t%d\n", k, impl[k]
            for (k in proto) printf "proto.%s\t%d\n", k, proto[k]
            for (k in pat)   printf "pattern.%s\t%d\n", k, pat[k]
            for (k in reach) printf "reach.%s\t%d\n", k, reach[k]
            for (k in kind)  printf "kind.%s\t%d\n", k, kind[k]
            for (k in cls)   printf "class.%s\t%d\n", k, cls[k]
            for (k in kit)   printf "kit.%s\t%d\n", k, kit[k]
        }' "$LCVE_CATALOG" | sort
}

# --gen <pattern> [--out DIR]  →  the four message-shape families
lcve_cmd_gen() {
    local pattern="" outdir=""
    while (($#)); do
        case "${1:-}" in
            --out) outdir="${2:-}"; shift 2 || shift || true ;;
            --*)   printf 'ERROR\tunknown option %s\n' "$1" >&2; return 2 ;;
            *)     pattern="$1"; shift || true ;;
        esac
    done
    if [[ -z "$pattern" ]]; then
        if [[ -x "$LCVE_GEN" ]] || [[ -r "$LCVE_GEN" ]]; then
            python3 "$LCVE_GEN" list
            return 0
        fi
        printf 'ERROR\tthe generator is missing: %s\n' "$LCVE_GEN" >&2
        return 1
    fi
    if [[ ! -r "$LCVE_GEN" ]]; then
        printf 'ERROR\tthe generator is missing: %s\n' "$LCVE_GEN" >&2
        printf 'WHY\tthe corpus is generated from a base message, so an absent generator is an absent corpus\n' >&2
        return 1
    fi
    if [[ -n "$outdir" ]]; then
        python3 "$LCVE_GEN" gen "$pattern" --out "$outdir"
    else
        python3 "$LCVE_GEN" gen "$pattern"
    fi
}

lcve_cmd_probe() {
    local what="${1:-}"
    case "$what" in
        ASN1)      lcve_probe_asn1_crash ;;
        ASN1-LIB)  lcve_probe_asn1_toolchain ;;
        RRC)       lcve_probe_rrc_length ;;
        NAS)       lcve_probe_nas_length ;;
        NAS-COUNT) lcve_probe_nas_count ;;
        DIAMETER)  lcve_probe_diameter_exposure ;;
        GTP-AMP)   lcve_probe_gtp_amplification ;;
        GTP)       lcve_probe_gtp_sanity ;;
        SIP)       lcve_probe_sip_parser ;;
        IMS)       lcve_probe_ims_register ;;
        PAGING)    lcve_probe_paging ;;
        PAGING-OC) lcve_probe_paging_occasion ;;
        SIB1)      lcve_probe_sib1 ;;
        SIB-SCHED) lcve_probe_sib_sched ;;
        SIB-SEG)   lcve_probe_sib_segments ;;
        KEYVAL)    lcve_probe_key_validation ;;
        KNOB)      lcve_probe_knob ;;
        BIAS)      lcve_probe_bias ;;
        *) printf 'ERROR\tunknown probe: %s\n' "$(lcve_sanitize "$what")" >&2; return 2 ;;
    esac
}

lcve_cmd_plan() {
    local id="${1:-}"
    [[ -n "$id" ]] || { printf 'ERROR\tusage: --plan <ID>\n' >&2; return 2; }
    local kind; kind=$(lcve_kind_of "$id") || {
        printf 'ERROR\tunknown id: %s\n' "$(lcve_sanitize "$id")" >&2; return 2; }
    if [[ "$kind" == "probe" ]]; then
        printf 'id\t%s\nkind\tprobe\nnote\tthis id has a real probe — run --run-cve %s\n' \
            "$(lcve_sanitize "$id")" "$(lcve_sanitize "$id")"
        return 0
    fi
    lcve_handoff_plan "$id" "$(lcve_cve_table | awk -F'\t' -v i="$id" '$1==i{print $5}')"
}

# A TEID/IMSI/PLMN decoder the kit can run entirely offline, and the byte
# arithmetic the LTE NAS tests rely on.
lcve_plmn_from_hex() {
    local hex="${1:-}"
    [[ "$hex" =~ ^[0-9A-Fa-f]{6}$ ]] || return 1
    # Identity encoding for MCC/MNC, 3GPP TS 24.008 10.5.1.4 and 10.5.1.13.
    # Writing the three octets out as six hex digits H1..H6:
    #   H1=MCC2  H2=MCC1  H3=MNC3  H4=MCC3  H5=MNC2  H6=MNC1
    # so each octet's digit order is reversed relative to the digit string,
    # and an odd (2-digit) MNC pads MNC3 with F. 208-10 encodes as 02F801.
    local h1 h2 h3 h4 h5 h6
    h1="${hex:0:1}"; h2="${hex:1:1}"; h3="${hex:2:1}"
    h4="${hex:3:1}"; h5="${hex:4:1}"; h6="${hex:5:1}"
    local mcc mnc
    mcc="${h2}${h1}${h4}"
    mnc="${h6}${h5}"
    [[ "${h3^^}" != "F" ]] && mnc="${mnc}${h3}"
    printf '%s-%s\n' "${mcc^^}" "${mnc^^}"
}

lcve_teid_hex() {
    local teid="${1:-}"
    [[ "$teid" =~ ^[0-9]+$ ]] || return 1
    (( teid > 4294967295 )) && return 1
    printf '0x%08X\n' "$teid"
}

# ── selftest — no radio, no root, no network ────────────────────────────
# ── the corpus horizon ──────────────────────────────────────────────────
# A CVE table is a photograph, not a feed. Every entry here was read on the
# date in the row below it, and anything disclosed after that date is not in
# the corpus and is therefore NOT assessed -- the one thing a security tool
# must never do is let a fixed snapshot read as current coverage.
lcve_cmd_coverage() {
    local rows newest entries years
    rows=$(lcve_cve_table)
    entries=$(printf '%s\n' "$rows" | grep -c . || true)
    years=$(printf '%s\n' "$rows" \
        | awk -F'\t' '{ if (match($1, /(19|20)[0-9][0-9]/)) print substr($1, RSTART, 4) }' \
        | sort -n | uniq)
    newest=$(printf '%s\n' "$years" | tail -1)
    local horizon="${newest:-unknown}"
    local stale
    stale=$(date -u +%Y)
    printf 'corpus\t%s\n' "LTE CVE corpus"
    printf 'entries\t%s\n' "$entries"
    printf 'years_covered\t%s\n' "$(printf '%s\n' "$years" | tr '\n' ' ' | sed 's/ $//')"
    printf 'newest_entry_year\t%s\n' "$horizon"
    printf 'corpus_horizon\t%s\n' "${horizon}-12-31"
    printf 'checked_on\t2025-06-01\n'
    if [[ "$stale" != "$horizon" ]]; then
        printf 'finding\tcorpus_stale\tMEDIUM\tthe corpus stops at %s and the clock says %s: every CVE disclosed in between is unassessed, and this table must not be read as current\n' "$horizon" "$stale"
    fi
    printf 'claim\tcoverage_is_a_snapshot\n'
    if [[ "$entries" -gt 0 ]]; then
        printf 'newest_entry\t%s\n' "$(printf '%s\n' "$rows" | awk -F'\t' -v y="$newest" 'match($1, /(19|20)[0-9][0-9]/) && substr($1, RSTART, 4) == y { print $1; exit }')"
    fi
    printf 'update\t%s\n' "append a row to the table in this module, add its selftest case, and move checked_on: an entry that cannot be reproduced is a claim, not a check"
    printf 'note\t%s\n' "an absent CVE is not a safe one: the corpus records what this tree can reproduce, and a newer advisory is unassessed until a row here reproduces it"
}

# ── reachability, without a claim ──────────────────────────────────────
# R72. A catalogue entry names a bug in somebody else's product. The question a
# report has to answer is not "which CVEs do you know" but "from where, and with
# what". This verb answers it per entry and refuses the third question: this tree
# carries no memory-corruption payload, no TrustZone exploit, so the claim for
# every entry is that there is no exploit primitive here. A probe exercises a
# neighbouring function (a parse, a fingerprint, a config read); a handoff names
# a plan file and stops.
lcve_reachability() {
    local want="${1:-}"
    local entries=0 mine=0 ota=0 lab=0 stp=0 card=0 nos=0 other=0
    local id kind cls needs desc position capability
    while IFS=$'\t' read -r id kind cls needs desc; do
        [[ -n "$id" ]] || continue
        [[ "$id" == \#* ]] && continue
        if [[ -n "$want" && "$id" != "$want" ]]; then continue; fi
        entries=$(( entries + 1 ))
        mine=$(( mine + 1 ))
        case "$needs" in
            ota-testbed)             position="over-the-air: needs a transmitter inside a cell, so a testbed or a licence"; ota=$(( ota + 1 )) ;;
            lab-network|lab-core)    position="lab network: a host beside the core, not a radio"; lab=$(( lab + 1 )) ;;
            lab-stp)                 position="SS7 interconnect: a signalling point beside an STP"; stp=$(( stp + 1 )) ;;
            sim-toolkit-harness|programmable-sim) position="card side: a programmable USIM or an OTA harness"; card=$(( card + 1 )) ;;
            none|-)                  position="no special position: a capture of the interface is enough"; nos=$(( nos + 1 )) ;;
            *)                       position="unclassified: the entry names $needs"; other=$(( other + 1 )) ;;
        esac
        if [[ "$kind" == probe ]]; then
            capability="a probe exists here: it checks a version, a config or a decode of this implementation, not the bug"
        else
            capability="a plan file names the hardware or testbed; nothing in this tree emits a payload"
        fi
        printf 'entry\t%s\t%s\t%s\t%s\t%s\n' "$id" "$kind" "$cls" "$position" "$capability"
        printf 'claim\t%s\t%s\n' "$id" "no_exploit_primitive"
    done < <(lcve_cve_table)
    if [[ -n "$want" && "$mine" -eq 0 ]]; then
        printf 'ERROR\t%s is not in the LTE catalogue of this tree\n' "$(lcve_sanitize "$want")" >&2
        printf 'WHY\tan unknown id has no reachability to report, and printing a row for it would invent an entry\n' >&2
        return 1
    fi
    printf 'entries\t%d\n' "$mine"
    printf 'positioned_over_the_air\t%d\n' "$ota"
    printf 'positioned_lab_network\t%d\n' "$lab"
    printf 'positioned_ss7_interconnect\t%d\n' "$stp"
    printf 'positioned_card_side\t%d\n' "$card"
    printf 'positioned_nowhere_special\t%d\n' "$nos"
    printf 'positioned_unclassified\t%d\n' "$other"
    printf 'primitive_available\t0\n'
    printf 'claim\tno_exploit_primitive\tthis catalogue records what is known about other implementations; no entry is a payload, and the probe half only checks an implementation answers\n'
    printf 'ref\tCVSS v3.1 attack vector is the vocabulary a report needs here; the product and version are the entry own\n'
    printf 'verdict\tcatalogue_without_a_primitive\n'
    return 0
}


lcve_selftest() {
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
    export LCVE_DIR="$d/loot/lte_cve" LCVE_RUNS="$d/loot/lte_cve/runs.tsv"
    export LCVE_PLANS="$d/loot/lte_cve/plans"
    # Read the shared SDR state from the scratch dir, not the host's: the status
    # row must be tested against a state file this selftest controls.
    export LCVE_SDR="$d/state/sdr_device"
    unset LCVE_TARGET LCVE_ASN1_ARTEFACT LCVE_RRC_ARTEFACT LCVE_NAS_ARTEFACT \
          LCVE_DIAMETER_ARTEFACT LCVE_GTP_ARTEFACT LCVE_SIP_ARTEFACT \
          LCVE_PAGING_ARTEFACT LCVE_SIB_ARTEFACT LCVE_BT_ARTEFACT
    mkdir -p "$LCVE_DIR" "$LCVE_PLANS"

    local nids nprobe nhand K_seen=0 K_rec=0 K_miss=0 K_loud=0 K_expect_loud=0
    nids=$(lcve_id_count)
    nprobe=$(lcve_ids_of_kind probe | grep -c . || true)
    nhand=$(lcve_ids_of_kind handoff | grep -c . || true)

    # ── 1. the dispatch table is exhaustive ────────────────────────────
    chk table-ids      "$nids"   "56"
    chk table-probes   "$nprobe" "20"
    chk table-handoffs "$nhand"  "36"
    chk table-split    "$((nprobe + nhand))" "$nids"
    chk table-unique   "$(lcve_cve_table | cut -f1 | sort | uniq -d | grep -c . || true)" "0"
    chk table-fields   "$(lcve_cve_table | awk -F'\t' 'NF!=5' | grep -c . || true)" "0"
    chk table-empty-id "$(lcve_cve_table | awk -F'\t' '$1==""' | grep -c . || true)" "0"

    # Every documented id must actually route: an id that falls to the
    # unknown branch reads back as "unknown CVE id".
    for id in $(lcve_cve_table | cut -f1); do
        out=$(lcve_run_cve "$id" 2>&1)
        printf '%s\n' "$out" | grep -q 'unknown CVE id' && K_miss=$((K_miss + 1))
    done
    chk table-every-id-routes "$K_miss" "0"

    # ── 2. probes need their artefact and fail loudly without it ───────
    local fails=0
    for id in $(lcve_ids_of_kind probe); do
        out=$(lcve_run_cve "$id" 2>/dev/null); rc=$?
        case "$id" in
            R2017-ASN1-VULN) [[ $rc -eq 0 ]] || fails=$((fails + 1)) ;;
            *) [[ $rc -ne 0 ]] || fails=$((fails + 1)) ;;
        esac
        printf '%s\n' "$out" | grep -qi '^status[[:space:]]*clean' && fails=$((fails + 1))
    done
    chk probe-no-input-fails-loud "$fails" "0"

    # ── 3. handoffs write exactly one plan each ────────────────────────
    fails=0
    for id in $(lcve_ids_of_kind handoff); do
        lcve_run_cve "$id" >/dev/null 2>&1 || fails=$((fails + 1))
    done
    chk handoff-all-rc    "$fails" "0"
    chk handoff-file-count "$(find "$LCVE_PLANS" -type f -name 'plan_*.txt' | wc -l | tr -d ' ')" "$nhand"

    out=$(lcve_run_cve CVE-2020-11202 2>&1); rc=$?
    chk handoff-rc     "$rc" "0"
    chk handoff-status "$(printf '%s\n' "$out" | grep -c '^status	handoff$')" "1"
    chk handoff-cve    "$(printf '%s\n' "$out" | grep -c '^cve	CVE-2020-11202$')" "1"
    local plan="$LCVE_PLANS/plan_CVE-2020-11202.txt"
    chk handoff-plan-exists   "$([[ -f "$plan" ]] && echo yes || echo no)" "yes"
    chk handoff-plan-status   "$(grep -c '^status: handoff' "$plan")" "1"
    chk handoff-plan-requires "$(grep -c '^requires: ota-testbed$' "$plan")" "1"
    chk handoff-plan-note     "$(grep -c 'crash oracle' "$plan")" "1"

    local n
    n=$(find "$LCVE_PLANS" -type f | wc -l | tr -d ' ')
    lcve_handoff_plan 'weird/id 1' 'note' >/dev/null 2>&1
    chk handoff-slug-count "$(find "$LCVE_PLANS" -type f | wc -l | tr -d ' ')" "$((n + 1))"
    chk handoff-slug-name  "$(find "$LCVE_PLANS" -name 'plan_weird_id_1.txt' | wc -l | tr -d ' ')" "1"

    # ── 4. argument validation ─────────────────────────────────────────
    chk run-no-id-rc     "$(lcve_run_cve >/dev/null 2>&1; echo $?)" "2"
    out=$(lcve_run_cve CVE-9999-99999 2>&1); rc=$?
    chk run-unknown-rc   "$rc" "2"
    chk run-unknown-msg  "$(printf '%s\n' "$out" | grep -c 'unknown CVE id: CVE-9999-99999')" "1"
    chk probe-unknown-rc "$(lcve_cmd_probe NOPE >/dev/null 2>&1; echo $?)" "2"
    chk plan-unknown-rc  "$(lcve_cmd_plan NOPE >/dev/null 2>&1; echo $?)" "2"
    chk normalize-lower  "$(lcve_normalize_id '  cve-2020-11202 ')" "CVE-2020-11202"
    chk normalize-rc     "$(lcve_run_cve ' cve-2020-11202 ' >/dev/null 2>&1; echo $?)" "0"

    # ── 5. ASN.1 length oracle, byte-exact ─────────────────────────────
    cat > "$d/captures/asn1.txt" <<'ASN'
msg=1 len=10 data=0102030405060708090A
msg=2 len=8  data=0102030405060708
msg=3 len=99 data=0102030405
ASN
    export LCVE_ASN1_ARTEFACT="$d/captures/asn1.txt"
    out=$(lcve_run_cve R2019-ASN1-DECODE-CRASH); rc=$?
    chk asn1-rc      "$rc" "0"
    chk asn1-lines   "$(fld "$out" corpus_lines)" "3"
    chk asn1-longest "$(fld "$out" longest_len)" "99"
    chk asn1-overrun "$(fld "$out" overruns)" "1"
    chk asn1-status  "$(printf '%s\n' "$out" | grep -c 'ASN.1 length-confusion class')" "1"

    printf 'msg=1 len=4 data=01020304\n' > "$d/captures/asn1ok.txt"
    out=$(LCVE_ASN1_ARTEFACT="$d/captures/asn1ok.txt" lcve_run_cve R2019-ASN1-DECODE-CRASH)
    chk asn1-clean "$(fld "$out" overruns)" "0"
    chk asn1-clean-status "$(printf '%s\n' "$out" | grep -c 'no length overrun')" "1"

    printf 'no lengths here\n' > "$d/captures/asn1bad.txt"
    chk asn1-norecords-rc "$(LCVE_ASN1_ARTEFACT="$d/captures/asn1bad.txt" lcve_run_cve R2019-ASN1-DECODE-CRASH >/dev/null 2>&1; echo $?)" "1"

    # ── 6. NAS COUNT replay window ─────────────────────────────────────
    printf 'count: 5\ncount: 6\ncount: 5\n' > "$d/captures/nas.txt"
    export LCVE_NAS_ARTEFACT="$d/captures/nas.txt"
    out=$(lcve_run_cve R2019-NAS-COUNT-CONFUSION); rc=$?
    chk nascount-rc   "$rc" "0"
    chk nascount-seen "$(fld "$out" counts_seen)" "3"
    chk nascount-dup  "$(fld "$out" duplicate_counts)" "1"
    printf 'count: 1\ncount: 2\n' > "$d/captures/nasok.txt"
    out=$(LCVE_NAS_ARTEFACT="$d/captures/nasok.txt" lcve_run_cve R2019-NAS-COUNT-CONFUSION)
    chk nascount-clean "$(fld "$out" duplicate_counts)" "0"

    # ── 7. GTP-C amplification arithmetic ──────────────────────────────
    printf 'echo-request: 100\necho-response: 350\n' > "$d/captures/gtp.txt"
    export LCVE_GTP_ARTEFACT="$d/captures/gtp.txt"
    out=$(lcve_run_cve CVE-2021-22191); rc=$?
    chk gtpamp-rc     "$rc" "0"
    chk gtpamp-factor "$(fld "$out" amplification_factor)" "3.50"
    chk gtpamp-status "$(printf '%s\n' "$out" | grep -c 'amplification factor 3.50')" "1"
    printf 'echo-request: 100\necho-response: 50\n' > "$d/captures/gtpnoamp.txt"
    out=$(LCVE_GTP_ARTEFACT="$d/captures/gtpnoamp.txt" lcve_run_cve CVE-2021-22191)
    chk gtpamp-none "$(printf '%s\n' "$out" | grep -c 'no amplification')" "1"
    chk gtpamp-missing-rc "$(printf 'nothing\n' > "$d/captures/gtpbad.txt"; \
        LCVE_GTP_ARTEFACT="$d/captures/gtpbad.txt" lcve_run_cve CVE-2021-22191 >/dev/null 2>&1; echo $?)" "1"

    # ── 8. GTP TEID sanity ─────────────────────────────────────────────
    printf 'version: 2\nteid: 0x00000000\nteid: 0xDEADBEEF\n' > "$d/captures/gtpv.txt"
    out=$(LCVE_GTP_ARTEFACT="$d/captures/gtpv.txt" lcve_run_cve CVE-2020-8283); rc=$?
    chk gtpsanity-rc    "$rc" "0"
    chk gtpsanity-vers  "$(fld "$out" versions)" "2"
    chk gtpsanity-teids "$(fld "$out" teid_fields)" "2"
    chk gtpsanity-zero  "$(fld "$out" zero_teids)" "1"

    # ── 9. Diameter S6a exposure ───────────────────────────────────────
    printf 'AIR update-location-request\nresult-code: 2001\nupdate-location-answer\n' > "$d/captures/dia.txt"
    export LCVE_DIAMETER_ARTEFACT="$d/captures/dia.txt"
    out=$(lcve_run_cve CVE-2020-8493); rc=$?
    chk dia-rc   "$rc" "0"
    chk dia-req  "$(fld "$out" s6a_requests)" "1"
    chk dia-ans  "$(fld "$out" s6a_answers)" "2"
    chk dia-code "$(printf '%s\n' "$out" | grep -c 'result-code: 2001')" "1"
    chk dia-status "$(printf '%s\n' "$out" | grep -c 'the HSS serves this interconnect')" "1"
    printf 'nothing here\n' > "$d/captures/diab.txt"
    chk dia-noreq-rc "$(LCVE_DIAMETER_ARTEFACT="$d/captures/diab.txt" lcve_run_cve CVE-2020-8493 >/dev/null 2>&1; echo $?)" "1"

    # ── 10. SIP parser and IMS registration ────────────────────────────
    cat > "$d/captures/sip.txt" <<'SIP'
REGISTER sip:ims.example SIP/2.0
Via: SIP/2.0/UDP 10.0.0.1
Content-Length: 999999
To: <sip:user@ims.example>
SIP/2.0 401 Unauthorized
WWW-Authenticate: Digest realm="ims.example"
SIP
    export LCVE_SIP_ARTEFACT="$d/captures/sip.txt"
    out=$(lcve_run_cve CVE-2020-25219); rc=$?
    chk sip-rc      "$rc" "0"
    chk sip-msgs    "$(fld "$out" sip_messages)" "2"
    chk sip-badlen  "$(fld "$out" oversized_content_length)" "1"
    chk sip-hardening "$(printf '%s\n' "$out" | grep -c 'parser-hardening candidates')" "1"

    out=$(lcve_run_cve CVE-2020-25220); rc=$?
    chk ims-rc      "$rc" "0"
    chk ims-regs    "$(fld "$out" registers)" "1"
    chk ims-chall   "$(fld "$out" aka_challenges)" "1"
    chk ims-status  "$(printf '%s\n' "$out" | grep -c 'registration is AKA-challenged')" "1"

    # A REGISTER with no challenge is the registration-weakness finding.
    printf 'REGISTER sip:ims.example SIP/2.0\nContact: <sip:u@1.2.3.4>\n' > "$d/captures/sipnoreg.txt"
    out=$(LCVE_SIP_ARTEFACT="$d/captures/sipnoreg.txt" lcve_run_cve CVE-2020-25220)
    chk ims-nochall "$(printf '%s\n' "$out" | grep -c 'no AKA challenge')" "1"
    chk ims-ipcontact "$(fld "$out" ip_literal_contacts)" "1"

    # ── 11. paging checks ──────────────────────────────────────────────
    printf 'pagingRecord: 1\nrecordCount: 32\nsfn: 512\ndefaultPagingCycle: rf128\n' > "$d/captures/paging.txt"
    export LCVE_PAGING_ARTEFACT="$d/captures/paging.txt"
    out=$(lcve_run_cve CVE-2020-11898); rc=$?
    chk paging-rc    "$rc" "0"
    chk paging-recs  "$(fld "$out" paging_records)" "1"
    chk paging-over  "$(fld "$out" over_count_records)" "1"
    chk paging-bypass "$(printf '%s\n' "$out" | grep -c 'length check bypass')" "1"

    out=$(lcve_run_cve CVE-2020-11899); rc=$?
    chk pagoc-rc  "$rc" "0"
    chk pagoc-sfn "$(fld "$out" sfn)" "512"
    chk pagoc-mod "$(fld "$out" paging_frame_mod)" "0"
    printf 'pagingRecord: 1\n' > "$d/captures/pagingbare.txt"
    chk pagoc-bare-rc "$(LCVE_PAGING_ARTEFACT="$d/captures/pagingbare.txt" lcve_run_cve CVE-2020-11899 >/dev/null 2>&1; echo $?)" "1"

    # ── 12. SIB parsing ────────────────────────────────────────────────
    printf 'sib1 plmn-IdentityList cellBarred=notBarred si-SchedulingInfo\n' > "$d/captures/sib.txt"
    export LCVE_SIB_ARTEFACT="$d/captures/sib.txt"
    out=$(lcve_run_cve CVE-2019-19275); rc=$?
    chk sib1-rc      "$rc" "0"
    chk sib1-cells   "$(fld "$out" sib1_records)" "1"
    chk sib1-missing "$(fld "$out" missing_mandatory)" "none"

    printf 'sib1 cellBarred=barred\n' > "$d/captures/sibbad.txt"
    out=$(LCVE_SIB_ARTEFACT="$d/captures/sibbad.txt" lcve_run_cve CVE-2019-19275)
    chk sib1-bad-missing "$(printf '%s\n' "$out" | grep -c 'missing mandatory field')" "1"

    printf 'si-SchedulingInfo sib-Type=3 si-Periodicity=rf32\n' > "$d/captures/sibsched.txt"
    out=$(LCVE_SIB_ARTEFACT="$d/captures/sibsched.txt" lcve_run_cve CVE-2019-19276); rc=$?
    chk sibsched-rc "$rc" "0"
    chk sibsched-n  "$(printf '%s\n' "$out" | grep -c 'referencing 1 SIB entr')" "1"

    printf 'segmentNumber=5 lastSegment=true\nsegmentNumber=7\n' > "$d/captures/sibseg.txt"
    out=$(LCVE_SIB_ARTEFACT="$d/captures/sibseg.txt" lcve_run_cve CVE-2019-19277); rc=$?
    chk sibseg-rc "$rc" "0"
    chk sibseg-idx "$(fld "$out" highest_segment_index)" "7"
    chk sibseg-gap "$(printf '%s\n' "$out" | grep -c 'segment gap')" "1"

    # ── 13. coexistence / pairing probes ───────────────────────────────
    printf 'pubkey: AABBCC\npubkey: AABBCC\ncurve: P-256\nkeyLength: 32\nlegacy pairing\n' > "$d/captures/bt.txt"
    export LCVE_BT_ARTEFACT="$d/captures/bt.txt"
    out=$(lcve_run_cve CVE-2018-5383); rc=$?
    chk keyval-rc       "$rc" "0"
    chk keyval-repeated "$(fld "$out" repeated_public_keys)" "1"
    chk keyval-status   "$(printf '%s\n' "$out" | grep -c 'fixed-parameter key validation')" "1"

    out=$(lcve_run_cve CVE-2019-9506); rc=$?
    chk knob-rc     "$rc" "0"
    chk knob-lowlen "$(printf '%s\n' "$out" | grep -c 'below the 7-byte floor')" "1"
    printf 'keyLength: 128\n' > "$d/captures/btok.txt"
    out=$(LCVE_BT_ARTEFACT="$d/captures/btok.txt" lcve_run_cve CVE-2019-9506)
    chk knob-ok "$(printf '%s\n' "$out" | grep -c 'at or above the 7-byte floor')" "1"

    out=$(lcve_run_cve CVE-2020-10135); rc=$?
    chk bias-rc     "$rc" "0"
    chk bias-legacy "$(fld "$out" legacy_pairing_markers)" "1"
    chk bias-status "$(printf '%s\n' "$out" | grep -c 'BIAS authentication bypass applies')" "1"
    printf 'secure simple pairing SSP used numeric comparison\n' > "$d/captures/btssp.txt"
    out=$(LCVE_BT_ARTEFACT="$d/captures/btssp.txt" lcve_run_cve CVE-2020-10135)
    chk bias-ssp "$(printf '%s\n' "$out" | grep -c 'precondition not met')" "1"

    # ── 14. offline decoders ───────────────────────────────────────────
    chk plmn-decode   "$(lcve_plmn_from_hex 02F801)"  "208-10"
    chk plmn-decode-3 "$(lcve_plmn_from_hex 21F310)"  "123-01"
    chk plmn-decode-2 "$(lcve_plmn_from_hex 02F810)"  "208-01"
    chk plmn-bad      "$(lcve_plmn_from_hex zz >/dev/null 2>&1; echo $?)" "1"
    chk plmn-short    "$(lcve_plmn_from_hex 02F8 >/dev/null 2>&1; echo $?)" "1"
    chk teid-hex      "$(lcve_teid_hex 3735928559)"   "0xDEADBEEF"
    chk teid-zero     "$(lcve_teid_hex 0)"            "0x00000000"
    chk teid-overflow "$(lcve_teid_hex 4294967296 >/dev/null 2>&1; echo $?)" "1"
    chk teid-bad      "$(lcve_teid_hex abc >/dev/null 2>&1; echo $?)" "1"

    # ── 15. sweep: every id reached, artefact probes fail loudly ───────
    unset LCVE_ASN1_ARTEFACT LCVE_RRC_ARTEFACT LCVE_NAS_ARTEFACT \
          LCVE_DIAMETER_ARTEFACT LCVE_GTP_ARTEFACT LCVE_SIP_ARTEFACT \
          LCVE_PAGING_ARTEFACT LCVE_SIB_ARTEFACT LCVE_BT_ARTEFACT
    export CAPTURES_DIR="$d/sweep-captures"
    mkdir -p "$CAPTURES_DIR"
    rm -f "$LCVE_RUNS"
    for id in $(lcve_cve_table | cut -f1); do
        lcve_needs_artefact "$id" && K_expect_loud=$((K_expect_loud + 1))
    done
    while IFS= read -r id; do
        out=$(lcve_run_cve "$id" 2>&1); rc=$?
        K_seen=$((K_seen + 1))
        printf '%s\n' "$out" | grep -q 'unknown CVE id' && K_miss=$((K_miss + 1))
        if [[ $rc -eq 0 ]]; then
            K_rec=$((K_rec + 1))
        elif lcve_needs_artefact "$id"; then
            K_loud=$((K_loud + 1))
        fi
    done < <(lcve_cve_table | cut -f1)
    chk sweep-no-unknown    "$K_miss" "0"
    chk sweep-ids-seen      "$K_seen" "$nids"
    chk sweep-run-rows      "$(lcve_run_count)" "$K_rec"
    chk sweep-loud-fails    "$K_loud" "$K_expect_loud"
    chk sweep-runs-hdr      "$(head -1 "$LCVE_RUNS")" "$(printf 'id\tstatus\ttarget\tevidence\tts')"
    chk sweep-run-fields    "$(awk -F'\t' 'NF!=5' "$LCVE_RUNS" | grep -c . || true)" "0"
    chk sweep-handoff-rows  "$(awk -F'\t' '$2=="handoff"' "$LCVE_RUNS" | grep -c . || true)" "$nhand"
    chk sweep-run-ids-unique "$(tail -n +2 "$LCVE_RUNS" | cut -f1 | sort -u | grep -c . || true)" "$K_rec"
    chk sweep-no-bad-status "$(tail -n +2 "$LCVE_RUNS" | awk -F'\t' '$2!="probe-ok" && $2!="handoff"' | grep -c . || true)" "0"

    # ── 16. TSV injection and write-failure honesty ────────────────────
    rm -f "$LCVE_RUNS"
    lcve_record_run $'X\tY' "probe-ok" $'a\tb' $'c\nd'
    chk run-tab-injection "$(awk -F'\t' 'NF!=5' "$LCVE_RUNS" | grep -c . || true)" "0"
    chk run-record-rows   "$(tail -n +2 "$LCVE_RUNS" | grep -c . || true)" "1"
    chk run-unwritable-rc "$(LCVE_RUNS=/proc/imsisting-nope/runs.tsv LCVE_DIR=/proc/imsisting-nope \
        lcve_record_run A probe-ok - e 2>/dev/null; echo $?)" "1"

    # ── 17. CLI surface ────────────────────────────────────────────────
    out=$(lcve_cmd_list_cves)
    chk list-cves-hdr    "$(printf '%s\n' "$out" | head -1)" "$(printf 'id\tkind\tclass\tneeds\tlabel')"
    chk list-cves-rows   "$(printf '%s\n' "$out" | tail -n +2 | grep -c .)" "$nids"
    chk list-cves-fields "$(printf '%s\n' "$out" | awk -F'\t' 'NF!=5' | grep -c . || true)" "0"
    chk runs-empty-rc    "$(: > "$LCVE_RUNS"; lcve_cmd_runs_tsv >/dev/null 2>&1; echo $?)" "1"

    # 01_radio writes "<driver>\t<serial>\t<index>". A populated state file was
    # once pasted raw into the 2-field status row; assert the split instead.
    mkdir -p "${LCVE_SDR%/*}"
    printf 'bladerf\tdeadbeef0001\t1\n' > "$LCVE_SDR"
    out=$(lcve_cli_status_tsv)
    chk status-module   "$(fld "$out" module)"    "lte_cve"
    chk status-ids      "$(fld "$out" ids)"       "$nids"
    chk status-probes   "$(fld "$out" probes)"    "$nprobe"
    chk status-handoffs "$(fld "$out" handoffs)"  "$nhand"
    chk status-dir      "$(fld "$out" dir)"       "$LCVE_DIR"
    chk status-runsf    "$(fld "$out" runs_file)" "$LCVE_RUNS"
    chk status-fields   "$(printf '%s\n' "$out" | awk -F'\t' 'NF!=2' | grep -c . || true)" "0"
    chk status-sdr      "$(fld "$out" sdr)"        "bladerf"
    chk status-sdr-sn   "$(fld "$out" sdr_serial)" "deadbeef0001"
    chk status-sdr-idx  "$(fld "$out" sdr_index)"  "1"
    # An absent state file still yields the three rows, all "none".
    rm -f "$LCVE_SDR"
    out=$(lcve_cli_status_tsv)
    chk status-sdr-nofile  "$(fld "$out" sdr)" "none"
    chk status-fields-none "$(printf '%s\n' "$out" | awk -F'\t' 'NF!=2' | grep -c . || true)" "0"

    # ── 18. the RANSacked corpus ───────────────────────────────────────
    local ncat
    ncat=$(lcve_corpus_count)
    chk corpus-count       "$ncat" "98"
    chk corpus-hdr         "$(lcve_cmd_corpus | head -1)" "$(printf 'id\talt\timpl\tgen\tproto\tpattern\treach\tkind\tneeds\tlabel\tmodule\tclass')"
    chk corpus-fields      "$(lcve_cmd_corpus | awk -F'\t' 'NR>1 && NF!=12' | grep -c . || true)" "0"
    chk corpus-rows        "$(lcve_cmd_corpus | tail -n +2 | grep -c .)" "$ncat"
    chk corpus-columns      "$(lcve_cmd_corpus | head -1 | awk -F'\t' '{print NF}')" "12"
    chk corpus-class-nas    "$(lcve_cmd_corpus - nas | tail -n +2 | awk -F'\t' '$12!="nas"' | grep -c . || true)" "0"
    chk corpus-kit-lte      "$(lcve_cmd_corpus - - 21_lte_cve | tail -n +2 | grep -c .)" "82"
    chk corpus-kit-nr       "$(lcve_cmd_corpus - - 22_nr_cve | tail -n +2 | grep -c .)" "16"
    chk corpus-nas-reach    "$(lcve_cmd_corpus nas-no-sim | tail -n +2 | grep -c .)" "24"
    chk corpus-entry-known  "$(lcve_cmd_corpus_entry CVE-2024-24445 | awk -F'\t' '$1=="kind"{print $2}')" "probe"
    chk corpus-entry-vuln   "$(lcve_cmd_corpus_entry VULN-B01 | awk -F'\t' '$1=="id"{print $2}')" "CVE-2024-24445"
    chk corpus-entry-unknown-rc "$(lcve_cmd_corpus_entry CVE-1999-0001 >/dev/null 2>&1; echo $?)" "1"
    chk corpus-entry-usage-rc   "$(lcve_cmd_corpus_entry >/dev/null 2>&1; echo $?)" "2"
    chk corpus-stats-entries    "$(lcve_cmd_corpus_stats | awk -F'\t' '$1=="entries"{print $2}')" "$ncat"
    chk corpus-missing-rc       "$(LCVE_CATALOG="$d/nope.tsv" lcve_cmd_corpus >/dev/null 2>&1; echo $?)" "1"

    # ── 19. the four generated families ────────────────────────────────
    local pat fam rc2
    for pat in len-unchecked asn1c-rows branch-asymmetry trust-failed-decode; do
        fam=$(lcve_cmd_gen "$pat" 2>/dev/null)
        chk "gen-$pat-rc"   "$?" "0"
        chk "gen-$pat-rows" "$(printf '%s\n' "$fam" | awk -F'\t' -v p="$pat" '$2==p' | grep -c .)" "6"
        chk "gen-$pat-hex"  "$(printf '%s\n' "$fam" | awk -F'\t' '$1 ~ /^hex\./ && $2 !~ /^[0-9a-f]+$/' | grep -c . || true)" "0"
    done
    chk gen-list-patterns  "$(lcve_cmd_gen | awk -F'\t' 'NR>1' | grep -c .)" "4"
    lcve_cmd_gen no-such-pattern >/dev/null 2>&1; rc2=$?
    chk gen-unknown-rc     "$rc2" "2"
    chk gen-missing-rc     "$(LCVE_GEN="$d/nope.py" lcve_cmd_gen len-unchecked >/dev/null 2>&1; echo $?)" "1"
    # --out writes one file per variant and nothing else
    lcve_cmd_gen len-unchecked --out "$d/gen" >/dev/null 2>&1
    chk gen-out-files      "$(find "$d/gen" -name '*.hex' | wc -l | tr -d ' ')" "6"

    rm -rf "$d"
    # ── the corpus horizon, R47 ───────────────────────────────────────
    local cov; cov=$(lcve_cmd_coverage)
    chk coverage-entries  "$(printf '%s\n' "$cov" | awk -F'\t' '$1=="entries"{print ($2>0)?"yes":"no"}')" "yes"
    chk coverage-horizon  "$(printf '%s\n' "$cov" | awk -F'\t' '$1=="corpus_horizon"{print ($2~/^[0-9]{4}-12-31$/)?"yes":"no"}')" "yes"
    chk coverage-claim    "$(printf '%s\n' "$cov" | awk -F'\t' '$1=="claim"{print $2}')" "coverage_is_a_snapshot"
    chk coverage-update   "$(printf '%s\n' "$cov" | awk -F'\t' '$1=="update"{print (length($2)>40)?"yes":"no"}')" "yes"
    # R72: reachability says where each entry has to stand and refuses to claim
    # a primitive. The counters partition the catalogue: every entry lands in
    # exactly one position bucket.
    local reach first_id
    reach=$(lcve_reachability)
    chk reach-entries      "$(printf '%s\n' "$reach" | awk -F'\t' '$1=="entries"{print $2}')" "$(lcve_id_count)"
    chk reach-primitive    "$(printf '%s\n' "$reach" | awk -F'\t' '$1=="primitive_available"{print $2}')" "0"
    chk reach-verdict      "$(printf '%s\n' "$reach" | awk -F'\t' '$1=="verdict"{print $2}')" "catalogue_without_a_primitive"
    chk reach-partition    "$(printf '%s\n' "$reach" | awk -F'\t' 'BEGIN{s=0} $1 ~ /^positioned_/{s+=$2} $1=="entries"{e=$2} END{print (s==e)?"yes":"no"}')" "yes"
    chk reach-claims       "$(printf '%s\n' "$reach" | awk -F'\t' '$1=="claim" && NF==3 && $3!="no_exploit_primitive" && $2!="no_exploit_primitive"' | grep -c .)" "0"
    chk reach-claim-rows   "$(printf '%s\n' "$reach" | awk -F'\t' '$1=="claim" && NF==3' | grep -c .)" "$(( $(lcve_id_count) + 1 ))"
    first_id=$(lcve_cve_table | awk -F'\t' '$1 !~ /^#/ && NF>1 {print $1; exit}')
    chk reach-one          "$(lcve_reachability "$first_id" | awk -F'\t' '$1=="entries"{print $2}')" "1"
    chk reach-unknown      "$(lcve_reachability NOPE-0000 >/dev/null 2>&1; echo $?)" "1"



    # --cve-search: hits come from the bundle, the applicability column comes
    # from a table on disk, and a term with no row is a refusal (rc 1), not an
    # empty table that reads like "clean".
    local cs_app cs_rc cs_rows
    chk cve-search-hit      "$(lcve_cmd_cve_search CVE-2020-8493 | awk -F'\t' '$1=="CVE-2020-8493"' | grep -c .)" "1"
    chk cve-search-unobs    "$(lcve_cmd_cve_search CVE-2020-8493 | awk -F'\t' '$1=="CVE-2020-8493"{print $5}')" "unobserved"
    chk cve-search-basis    "$(lcve_cmd_cve_search CVE-2020-8493 | awk -F'\t' '$1=="CVE-2020-8493"{print ($8 ~ /no applicability table on disk/) ? "names-the-file" : "other"}')" "names-the-file"
    printf 'id\tsource\taffected\tfixed\nCVE-2020-8493\tadvisory A\t< 1.2\t1.2\n' > "$d/applicability.tsv"
    cs_app=$(lcve_cmd_cve_search CVE-2020-8493 "$d/applicability.tsv" | awk -F'\t' '$1=="CVE-2020-8493"{print $5"|"$6"|"$7}')
    chk cve-search-applies  "$cs_app" "version-range-stated|< 1.2|1.2"
    lcve_cmd_cve_search zzz-not-a-cve >/dev/null 2>&1; cs_rc=$?
    chk cve-search-miss-rc  "$cs_rc" "1"
    cs_rows=$(awk -F'\t' 'NR>1' "$LCVE_DIR/cve_search.tsv" 2>/dev/null | grep -c . || true)
    chk cve-search-store    "$(( cs_rows > 0 ))" "1"

    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ── menu ────────────────────────────────────────────────────────────────
lcve_menu() {
    while true; do
        banner
        echo -e "  ${C_MAG}=== LTE CVE kit ===${C_RESET}"
        echo -e "  ids:  ${C_GRN}$(lcve_id_count)${C_RESET}  ${C_DIM}$(lcve_ids_of_kind probe | grep -c . || true) probe / $(lcve_ids_of_kind handoff | grep -c . || true) handoff${C_RESET}"
        echo -e "  runs: ${C_GRN}$(lcve_run_count)${C_RESET}"
        echo -e "  dir:  ${C_DIM}$LCVE_DIR${C_RESET}\n"
        cat << 'M'
  [1]  list documented ids (probe vs handoff)
  [2]  run a probe by id
  [3]  write the handoff plan by id
  [4]  ASN.1 / NAS / RRC decoder checks
  [5]  EPC checks (Diameter S6a, GTP-C/GTP-U)
  [6]  VoLTE / IMS SIP checks
  [7]  paging and SIB parsing checks
  [8]  decode a PLMN from hex
  [9]  TEID to hex
  [10] show run history
  [11] export the run history to loot
  [12] search the table by keyword (applicability stated or unobserved)
  [0]  back

M
        read -rp "  choice> " c || return 0  # EOF: leave the menu cleanly
        case "$c" in
            1) lcve_cmd_list_cves | column -t -s$'\t' 2>/dev/null || lcve_cmd_list_cves
               read -rp "  press enter " _ ;;
            2) read -rp "  id> " i; lcve_run_cve "$i"; read -rp "  press enter " _ ;;
            3) read -rp "  id> " i; lcve_cmd_plan "$i"; read -rp "  press enter " _ ;;
            4) lcve_run_cve R2019-ASN1-DECODE-CRASH; read -rp "  press enter " _ ;;
            5) lcve_run_cve CVE-2020-8493; lcve_run_cve CVE-2021-22191; read -rp "  press enter " _ ;;
            6) lcve_run_cve CVE-2020-25219; lcve_run_cve CVE-2020-25220; read -rp "  press enter " _ ;;
            7) lcve_run_cve CVE-2019-19275; lcve_run_cve CVE-2019-19277; read -rp "  press enter " _ ;;
            8) read -rp "  hex (6 nibbles)> " h; lcve_plmn_from_hex "$h"; read -rp "  press enter " _ ;;
            9) read -rp "  teid> " t; lcve_teid_hex "$t"; read -rp "  press enter " _ ;;
            10) lcve_cmd_runs_tsv | column -t -s$'\t' 2>/dev/null || lcve_cmd_runs_tsv
                read -rp "  press enter " _ ;;
            11) mkdir -p "$LCVE_DIR"
                if [[ "$(lcve_run_count)" -eq 0 ]]; then
                    warn "nothing to export"
                else
                    cp "$LCVE_RUNS" "$LCVE_DIR/runs_export_$(date +%Y%m%d_%H%M%S).tsv" && \
                        ok "exported to $LCVE_DIR"
                fi
                sleep 1 ;;
            12) read -rp "  term> " i; lcve_cmd_cve_search "$i"
                read -rp "  press enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ── CLI dispatch ────────────────────────────────────────────────────────
lcve_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)  lcve_cli_status_tsv ;;
        --list-cves)   lcve_cmd_list_cves ;;
        --cve-search)  lcve_cmd_cve_search "${1:-}" "${2:-}" ;;
        --corpus)      lcve_cmd_corpus "$@" ;;
        --corpus-entry) lcve_cmd_corpus_entry "${1:-}" ;;
        --corpus-stats) lcve_cmd_corpus_stats ;;
        --gen)         lcve_cmd_gen "$@" ;;
        --run-cve)     lcve_run_cve "${1:-}" ;;
        --probe)       lcve_cmd_probe "${1:-}" ;;
        --plan)        lcve_cmd_plan "${1:-}" ;;
        --plmn)        lcve_plmn_from_hex "${1:-}" ;;
        --teid)        lcve_teid_hex "${1:-}" ;;
        --runs-tsv)    lcve_cmd_runs_tsv ;;
        --coverage)    lcve_cmd_coverage ;;
        --reachability) lcve_reachability "${1:-}" ;;
        --selftest)    lcve_selftest ;;
        --menu)        lcve_menu ;;
        *)
            cat >&2 <<EOF
LTE CVE Kit — 4G baseband, NAS/ASN.1, EPC and VoLTE probes

Usage: $0 COMMAND
  --status-tsv              module state as TSV
  --list-cves               every documented id, with kind and required testbed
  --cve-search <term> [applicability.tsv]
                            matches in the bundled table, each with the version
                            applicability the on-disk table states -- or
                            unobserved, and the file that was looked for
  --corpus [REACH] [CLASS] [KIT]
                            the RANSacked entries, filed into the kit and the
                            class each one belongs to; each argument filters,
                            and - means any
  --corpus-entry <ID>       one corpus entry, its reach and what that reach means
  --corpus-stats            the corpus counted five ways
  --gen <PATTERN>           build a message family: len-unchecked | asn1c-rows
                            | branch-asymmetry | trust-failed-decode
  --run-cve <ID>            run the probe for ID, or write its handoff plan
  --probe <WHAT>            ASN1|ASN1-LIB|RRC|NAS|NAS-COUNT|DIAMETER|GTP-AMP|
                            GTP|SIP|IMS|PAGING|PAGING-OC|SIB1|SIB-SCHED|
                            SIB-SEG|KEYVAL|KNOB|BIAS
  --plan <ID>               write the handoff plan for a handoff id
  --plmn <6 hex nibbles>    decode a PLMN from its NAS encoding
  --teid <decimal>          TEID to 0x hex
  --runs-tsv                recorded probe runs as TSV
  --coverage                the corpus horizon: newest year it knows, and what that leaves unassessed
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
    lcve_cli_main "$@"
fi
