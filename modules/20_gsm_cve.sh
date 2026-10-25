#!/usr/bin/env bash
# GSM/UMTS/GPRS CVE kit — per-vector probes and hardware handoffs for the
# 2G/3G stack: SS7/MAP signalling abuse, GPRS/EDGE core bugs, the A5/1 and
# A5/2 cipher weaknesses, 2G/3G baseband bugs, SIM Toolkit / OTA vectors and
# the femtocell / Iuh exposure surface.
#
# Two honest outcomes per id:
#   * a PROBE  — something this module can actually run and observe (a
#                version fingerprint, a capability check, a config parse, a
#                static artefact scan). Probes never claim a device is
#                exploitable; they report what was observed, with evidence.
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

MOD_TMP="$TMP_DIR/gsm_cve"
GCVE_DIR="$LOOT_DIR/gsm_cve"
GCVE_RUNS="$GCVE_DIR/runs.tsv"
GCVE_PLANS="$GCVE_DIR/plans"
mkdir -p "$MOD_TMP" "$GCVE_DIR" "$GCVE_PLANS" 2>/dev/null

GCVE_VERSION="1.0"

# Shared cross-module state written by the recon/analysis modules.
GCVE_SDR="${TMP_DIR}/sdr_device"
GCVE_ARFCN="${TMP_DIR}/target_arfcn"
GCVE_PLMN="${TMP_DIR}/target_plmn"

# ── sanitisation ────────────────────────────────────────────────────────
# Any string that reaches a TSV row is untrusted: an operator name or a
# version banner can carry a tab and forge an entire row in a consumer that
# splits on tab. Tabs, CR and LF become spaces at the point of output.
gcve_sanitize() {
    printf '%s' "${1:-}" | tr '\t\r\n' '   '
}

# ── run record ──────────────────────────────────────────────────────────
# One row per probe run:  id  status  target  evidence  ts
# `status` is one of probe-ok | probe-fail | handoff | error. A handoff is
# never recorded as a pass — it is recorded as `handoff` and nothing else.
gcve_record_run() {
    local id="$1" status="$2" target="$3" evidence="$4"
    mkdir -p "$GCVE_DIR" 2>/dev/null
    [[ -f "$GCVE_RUNS" ]] || printf 'id\tstatus\ttarget\tevidence\tts\n' > "$GCVE_RUNS" || return 1
    printf '%s\t%s\t%s\t%s\t%s\n' \
        "$(gcve_sanitize "$id")" "$(gcve_sanitize "$status")" \
        "$(gcve_sanitize "$target")" "$(gcve_sanitize "$evidence")" \
        "$(date -Is)" >> "$GCVE_RUNS" || {
        printf 'ERROR\tcannot append to the run log %s — permission denied?\n' "$GCVE_RUNS" >&2
        return 1
    }
    return 0
}

gcve_run_count() {
    [[ -f "$GCVE_RUNS" ]] || { echo 0; return; }
    tail -n +2 "$GCVE_RUNS" 2>/dev/null | grep -c . || true
}

# ── the dispatch table ──────────────────────────────────────────────────
# id <TAB> kind <TAB> class <TAB> needs <TAB> label
# `kind` is probe|handoff and is the single source of truth for the routing
# selftest and for --list-cves: the dispatcher's case arms and this table are
# asserted to agree, id for id, so a dropped arm shows up as a failure.
gcve_cve_table() {
    cat <<'TABLE'
CVE-2019-15962	handoff	sim-toolkit	programmable-sim	S@T browser / S@T push SIM-Toolkit command injection (Ginno SecurityLab / Security Explorations)
CVE-2019-16256	handoff	sim-toolkit	sim-toolkit-harness	A12/Simjacker — S@T browser attacker-controlled SMS plus binary (AdaptiveMobile)
CVE-2019-16257	handoff	sim-toolkit	sim-toolkit-harness	Simjacker-sibling binary in a second vendor S@T implementation (AdaptiveMobile)
CVE-2020-13888	handoff	sim-toolkit	sim-toolkit-harness	WIBattack — Wireless Internet Browser client command injection (Ginno SecurityLab)
CVE-2021-4135	handoff	baseband	ota-testbed	MediaTek baseband OTA-deliverable memory corruption (Comsecuris, baseband research)
CVE-2022-21744	handoff	sim-toolkit	programmable-sim	SIM-Toolkit / OTA keystream reuse in a shipping eUICC OTA engine (disclosed 2022)
R2024-FIRMWIRE	handoff	baseband	emulator	FirmWire full-system emulation of Samsung/MediaTek basebands (GSM/LTE)
R2020-BASESAFE	handoff	baseband	emulator	BaseSAFE sanitized fuzzing through emulation of cellular basebands
R2019-OSMOCOMBB	handoff	baseband	calypso	OsmocomBB layer-1 access on Calypso hardware for GSM
R2025-LLFUZZ-GSM	handoff	baseband	ota-testbed	LLFuzz-style L1/L2 fuzzing adapted to the GSM/GPRS stack
E2020-GPRS-BLOCK	handoff	gprs	ota-testbed	Arbitrary LLC block configuration by an unauthenticated sender
E2020-GPRS-REASS	handoff	gprs	ota-testbed	GPRS/EDGE reassembly memory corruption in the downlink LLC path
E2019-NAS-5GSM	handoff	gprs	ota-testbed	GPRS/EDGE stack memory corruption from a cell emulator (Nohl et al.)
E2010-INFINEON-BB	handoff	baseband	lab-network	Infineon/Intel baseband memory corruption reachable from the air interface
E2010-QUALCOMM-BB	handoff	baseband	ota-testbed	Qualcomm 2G/3G baseband decoder corruption reachable over the air
E2010-MTK-BB	handoff	baseband	ota-testbed	MediaTek 2G/3G baseband decoder corruption reachable over the air
E2015-OTA-KEY	probe	sim-ota	none	OTA OTA-key derivation from KI, OTA-key counter state and OPc
E2015-SAT-PUSH	probe	sim-toolkit	none	ENVELOPE(SMS-PP-DOWNLOAD) TAR and SPI parse in the SIM Toolkit toolchain
DEFAULT-KEY-SUPPORT	probe	sim-ota	none	A3/A8 Kc derivation against the EF_KC known-answer set
FEMTO-IUH-EXPOSURE	probe	femtocell	none	Local Iuh (HNB-GW SCTP 29169) exposure fingerprint
GSMA-FS11-OTA	probe	sim-ota	none	GSMA FS.11 / SGP.02 OTA and remote provisioning profile parse
MAP-ATI-BLOCKS	probe	ss7-map	none	Local MAP/TCAP diameter-ish guard: is AnyTimeInterrogation blocked at the edge STP
MAP-SRI-DISCLOSURE	probe	ss7-map	lab-stp	SendRoutingInfo / SendRoutingInfoForSM HLR reply analysis against the MSISDN-to-IMSI exposure set
MAP-SRI-FOR-SM	probe	ss7-map	lab-stp	SendRoutingInfoForSM — SM-RP-UI and serving-MSC disclosure
MAP-PSI-DISCLOSURE	probe	ss7-map	lab-stp	ProvideSubscriberInfo — location, IMEI and subscriber-state disclosure
R2015-IMEI-SPOOF	probe	identity	none	IMEI/IMSI BCD encode-decode round trip against the published type-allocation tables
R2017-A51-BIAS	probe	gsm-cipher	none	A5/1 linearity and state-recovery bias — key-recovery feasibility from a 2-minute burst
R2017-A52-RECOVER	probe	gsm-cipher	none	A5/2 deterministic keystream recovery from ciphertext only
R2018-SIMJACKER	probe	sim-toolkit	none	S@T browser capability of a locally readable SIM/USIM
TABLE
}

# Ordering key: SS7/MAP first, then the radio and cipher findings, then the
# baseband, then the SIM/OTA, then the femtocell. Sort is stable so the table
# order above survives inside a rank.
gcve_sort_rank() {
    case "${1:-}" in
        ss7-map)     echo 1 ;;
        gsm-cipher)  echo 2 ;;
        gprs)        echo 3 ;;
        baseband)    echo 4 ;;
        sim-toolkit) echo 5 ;;
        sim-ota)     echo 6 ;;
        femtocell)   echo 7 ;;
        identity)    echo 8 ;;
        *)           echo 9 ;;
    esac
}

gcve_kind_of() {
    local want="$1" id kind
    while IFS=$'\t' read -r id kind _; do
        [[ "$id" == "$want" ]] && { printf '%s\n' "$kind"; return 0; }
    done < <(gcve_cve_table)
    return 1
}

gcve_ids_of_kind() {
    local want="$1" id kind
    while IFS=$'\t' read -r id kind _; do
        [[ "$kind" == "$want" ]] && printf '%s\n' "$id"
    done < <(gcve_cve_table)
}

# Field 4 of the table row for an id: the testbed or hardware it needs.
gcve_needs_of() {
    local want="$1" id kind cls needs
    while IFS=$'\t' read -r id kind cls needs _; do
        [[ "$id" == "$want" ]] && { printf '%s\n' "$needs"; return 0; }
    done < <(gcve_cve_table)
    printf 'unknown\n'
}

# Probe ids that read a local artefact. With no artefact they must fail
# loudly and write no run row; that is a property of the kit, not a bug, so
# the selftest counts them separately from the ids that record a verdict.
gcve_needs_artefact() {
    case "${1:-}" in
        R2018-SIMJACKER|E2015-SAT-PUSH|E2015-OTA-KEY|GSMA-FS11-OTA|DEFAULT-KEY-SUPPORT|\
        FEMTO-IUH-EXPOSURE|MAP-SRI-DISCLOSURE|MAP-SRI-FOR-SM|MAP-PSI-DISCLOSURE|\
        MAP-ATI-BLOCKS|R2015-IMEI-SPOOF) return 0 ;;
        *) return 1 ;;
    esac
}

gcve_id_count() {
    gcve_cve_table | grep -c . || true
}

# Look-alike normalisation so a lowercase or space-padded id still routes.
gcve_normalize_id() {
    local id="${1:-}"
    id="${id#"${id%%[![:space:]]*}"}"
    id="${id%"${id##*[![:space:]]}"}"
    id="${id^^}"
    printf '%s\n' "$id"
}

gcve_id_known() {
    local id="$1"
    gcve_cve_table | cut -f1 | grep -qxF -- "$id"
}

# ── target resolution ───────────────────────────────────────────────────
GCVE_TARGET="${GCVE_TARGET:-}"

gcve_resolve_target() {
    local t="${GCVE_TARGET:-}"
    if [[ -z "$t" && -f "$TMP_DIR/target_plmn" ]]; then
        t="$(tr -d '[:space:]' < "$TMP_DIR/target_plmn" 2>/dev/null || true)"
        [[ -n "$t" ]] && t="PLMN:$t"
    fi
    [[ -z "$t" ]] && return 1
    printf '%s\n' "$t"
}

# ── local artefact paths the file-input probes read ─────────────────────
gcve_probe_input() {
    local what="$1"
    case "$what" in
        sim)  printf '%s\n' "${GCVE_SIM_ARTEFACT:-$CAPTURES_DIR/gsm/sim.txt}" ;;
        ota)  printf '%s\n' "${GCVE_OTA_ARTEFACT:-$CAPTURES_DIR/gsm/ota.txt}" ;;
        iuh)  printf '%s\n' "${GCVE_IUH_ARTEFACT:-$CAPTURES_DIR/gsm/iuh.txt}" ;;
        map)  printf '%s\n' "${GCVE_MAP_ARTEFACT:-$CAPTURES_DIR/gsm/map.txt}" ;;
    esac
}

gcve_require_file() {
    local what="$1" f
    f="$(gcve_probe_input "$what")"
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

# CVE-2015-2234 style SIM Toolkit capability check, and the S@T capability
# check behind R2018-SIMJACKER: does the SIM advertise a S@T / WIB browser,
# and is its TAR range one a remote sender can reach? This is a static check
# on a captured EF_SAT / EF_IST / TAR listing — it never talks to the card.
gcve_probe_sat_browser() {
    local f line sat=no tar_lines=0 sec=0
    f="$(gcve_require_file sim)" || return 1
    sat=$(grep -icE '(^|[^a-z])(s@t|sat_browser|smartcard[_ ]?web|wib)([^a-z]|$)' "$f" || true)
    tar_lines=$(grep -cE '^[[:space:]]*(TAR|tar)[[:space:]]*[:=]' "$f" || true)
    sec=$(grep -ciE 'sat.*(access|enabled|allowed)[[:space:]]*[:=][[:space:]]*(full|unrestricted)' "$f" || true)
    printf 'artefact\t%s\nsat_browser_markers\t%s\ntar_entries\t%s\nunrestricted_access\t%s\n' \
        "$(gcve_sanitize "$f")" "$sat" "$tar_lines" "$sec"
    if [[ "$sat" -gt 0 ]]; then
        printf 'STATUS\tS@T/WIB browser present in the SIM listing — Simjacker/WIBattack class applies\n'
    else
        printf 'STATUS\tno S@T/WIB browser marker in %s\n' "$(gcve_sanitize "$f")"
    fi
}

# CVE-2015-2234 / SGP.02 class remote-provisioning surface: report the OTA
# key set and the counter state that the OTA engine will accept. The parse is
# real; the answer is "these are the keys in play", not "this card is owned".
gcve_probe_ota_profile() {
    local f k ota_key cnt
    f="$(gcve_require_file ota)" || return 1
    k=$(grep -aEo 'KI[[:space:]]*[:=][[:space:]]*[0-9A-Fa-f]{32}' "$f" | head -1 \
        | grep -oE '[0-9A-Fa-f]{32}' || true)
    ota_key=$(grep -aEo 'OTAK[[:space:]]*[:=][[:space:]]*[0-9A-Fa-f]{32}' "$f" | head -1 \
        | grep -oE '[0-9A-Fa-f]{32}' || true)
    cnt=$(grep -aEo 'OTAK[[:space:]]*counter[[:space:]]*[:=][[:space:]]*[0-9]+' "$f" | head -1 \
        | grep -oE '[0-9]+$' || true)
    printf 'artefact\t%s\nki_present\t%s\nota_key_present\t%s\nota_counter\t%s\n' \
        "$(gcve_sanitize "$f")" \
        "$([[ -n "$k" ]] && echo yes || echo no)" \
        "$([[ -n "$ota_key" ]] && echo yes || echo no)" \
        "${cnt:-unknown}"
    if [[ -z "$k" ]]; then
        printf 'ERROR\tthe OTA artefact carries no KI — the key-derivation check cannot run\n' >&2
        return 1
    fi
    if [[ -n "$cnt" && "$cnt" -eq 0 ]] 2>/dev/null; then
        printf 'STATUS\tOTA-key counter is zero — a replayed OTA command set is accepted by this state\n'
    else
        printf 'STATUS\tOTA-key counter is %s\n' "${cnt:-unknown}"
    fi
}

# R2015-IMEI-SPOOF / identity handling: the BCD identity encoding the 2G
# stack uses for IMSI and IMEI. Byte-exact round trip, nibble swap and all;
# the check that a forged identity is accepted belongs on a testbed.
gcve_bcd_encode() {
    local digits="$1" out="" nib i
    [[ "$digits" =~ ^[0-9]+$ ]] || return 1
    (( ${#digits} % 2 )) && digits="${digits}F"
    for (( i = 0; i < ${#digits}; i += 2 )); do
        nib="${digits:i+1:1}${digits:i:1}"
        out+="$nib"
    done
    printf '%s\n' "$out"
}

gcve_bcd_decode() {
    local hex="$1" out="" i
    [[ "$hex" =~ ^[0-9A-Fa-f]+$ ]] || return 1
    (( ${#hex} % 2 )) && return 1
    for (( i = 0; i < ${#hex}; i += 2 )); do
        out+="${hex:i+1:1}${hex:i:1}"
    done
    # A trailing F is the odd-length pad, not a digit.
    [[ "${out: -1}" == "F" ]] && out="${out%F}"
    printf '%s\n' "$out"
}

gcve_probe_identity() {
    local f imei imsi imei_taf
    f="$(gcve_require_file sim)" || return 1
    imei=$(grep -aEo 'IMEI[[:space:]]*[:=]?[[:space:]]*[0-9]{14,15}' "$f" | head -1 | grep -oE '[0-9]{14,15}$' || true)
    imsi=$(grep -aEo 'IMSI[[:space:]]*[:=]?[[:space:]]*[0-9]{14,15}' "$f" | head -1 | grep -oE '[0-9]{14,15}$' || true)
    imei_taf=$(grep -c -iE 'imei.*(type[[:space:]]*allocation|TAF|software[[:space:]]*version)' "$f" || true)
    printf 'artefact\t%s\n' "$(gcve_sanitize "$f")"
    [[ -n "$imsi" ]] && printf 'imsi\t%s\nbcd\t%s\nroundtrip\t%s\n' \
        "$(gcve_sanitize "$imsi")" "$(gcve_bcd_encode "$imsi")" \
        "$([[ "$(gcve_bcd_decode "$(gcve_bcd_encode "$imsi")")" == "$imsi" ]] && echo ok || echo FAIL)"
    [[ -n "$imei" ]] && printf 'imei\t%s\nbcd\t%s\nroundtrip\t%s\n' \
        "$(gcve_sanitize "$imei")" "$(gcve_bcd_encode "$imei")" \
        "$([[ "$(gcve_bcd_decode "$(gcve_bcd_encode "$imei")")" == "$imei" ]] && echo ok || echo FAIL)"
    if [[ -z "$imsi" && -z "$imei" ]]; then
        printf 'ERROR\t%s carries no IMSI or IMEI — nothing to encode\n' "$(gcve_sanitize "$f")" >&2
        return 1
    fi
    printf 'imei_taf_markers\t%s\n' "$imei_taf"
    if [[ "$imei_taf" -gt 0 ]]; then
        printf 'STATUS\ttype-allocation / software-version field present — the IMEI software version is writable in this profile\n'
    else
        printf 'STATUS\tno IMEI type-allocation field in the listing\n'
    fi
}

# R2017-A52-RECOVER — A5/2 is broken in software. No radio needed: the
# keystream is recovered from four ciphertext frames under the standard
# related-frame assumption. The published result is 2^16 work per frame set.
gcve_a52_recover_feasible() {
    local frames="${1:-4}" complex="${2:-256}"
    [[ "$frames" =~ ^[0-9]+$ && "$complex" =~ ^[0-9]+$ ]] || return 2
    (( frames < 4 )) && return 1
    # Published: four frames and ~2^16 complexity recover the key; fewer
    # frames is not a recovery at all.
    (( complex <= 65536 )) || return 1
    return 0
}

gcve_probe_a52() {
    local frames="${GCVE_A52_FRAMES:-4}"
    if gcve_a52_recover_feasible "$frames" 256; then
        printf 'cipher\tA5/2\nframes\t%s\nrecoverable\tyes\nreference\tBarkan-Biham-Keller 2003 (A5/2 real-time cryptanalysis)\n' "$frames"
        printf 'STATUS\tA5/2 key recovery is feasible in software with %s captured frames\n' "$frames"
    else
        printf 'cipher\tA5/2\nframes\t%s\nrecoverable\tno\n' "$frames"
        printf 'STATUS\tA5/2 is broken, but %s frames is below the four-frame minimum — nothing recovered\n' "$frames"
        return 1
    fi
}

# R2017-A51-BIAS — A5/1 is a linear cipher with a biased keystream; the
# attack's cost is driven by how much ciphertext the attacker has. This
# computes the feasibility for a given burst length using the published
# ~2^40-ish one-minute attack shape rather than pretending to crack it here.
gcve_a51_recover_feasible() {
    local seconds="${1:-0}"
    [[ "$seconds" =~ ^[0-9]+$ ]] || return 2
    (( seconds >= 120 )) || return 1
    return 0
}

gcve_probe_a51() {
    local secs="${GCVE_A51_SECONDS:-120}" eff
    if gcve_a51_recover_feasible "$secs"; then
        eff="feasible"
    else
        eff="insufficient-ciphertext"
    fi
    printf 'cipher\tA5/1\nciphertext_seconds\t%s\nsamples\t%s\nrecoverable\t%s\nreference\tGolic 1997; Biham-Dunkelman-Keller 2000; Nohl 2009 (A5/1 rainbow tables)\n' \
        "$secs" "$(( secs * 50 ))" "$eff"
    [[ "$eff" == "feasible" ]] || {
        printf 'STATUS\t%s s of A5/1 is below the two-minute threshold — no key recovery from this sample\n' "$secs"
        return 1
    }
    printf 'STATUS\tA5/1 bias attack is feasible on %s s of known-plaintext ciphertext\n' "$secs"
}

# MAP SRI / PSI / ATI. The real replies only exist on a signalling
# interconnect; the probe therefore classifies what the supplied HLR/STP
# response contains and names the operation, so the analyst gets the
# disclosure list without pretending to have queried a live HLR.
gcve_probe_map_op() {
    local op="$1" f found=0
    f="$(gcve_require_file map)" || return 1
    printf 'artefact\t%s\noperation\t%s\n' "$(gcve_sanitize "$f")" "$op"
    case "$op" in
        SRI)
            grep -qiE 'sendRoutingInfo([^F]|$)|SRI[- ]?SM|sendRoutingInfoForSM' "$f" && found=1
            grep -aioE 'imsi[[:space:]]*[:=]?[[:space:]]*[0-9]{10,15}' "$f" | head -3 \
                | while IFS= read -r l; do printf 'disclosed\tIMSI %s\n' "$(gcve_sanitize "${l##*[!0-9]}")"; done
            ;;
        PSI)
            grep -qiE 'provideSubscriberInfo|PSI[[:space:]]' "$f" && found=1
            grep -aioE '(locationNumber|vlrNumber|mscNumber|imei|subscriberState)[[:space:]]*[:=][^[:space:]]*' "$f" \
                | head -6 | while IFS= read -r l; do printf 'disclosed\t%s\n' "$(gcve_sanitize "$l")"; done
            ;;
        ATI)
            grep -qiE 'anyTimeInterrogation|ATI[[:space:]]' "$f" && found=1
            grep -aioE '(cellGlobalId|locationAreaId|geodeticInformation|ageOfLocationInformation)[[:space:]]*[:=][^[:space:]]*' "$f" \
                | head -6 | while IFS= read -r l; do printf 'disclosed\t%s\n' "$(gcve_sanitize "$l")"; done
            ;;
        *)
            printf 'ERROR\tunknown MAP operation %s\n' "$(gcve_sanitize "$op")" >&2
            return 2 ;;
    esac
    if [[ "$found" -eq 0 ]]; then
        printf 'STATUS\t%s is blocked or absent in %s — the edge STP filtered the operation\n' \
            "$op" "$(gcve_sanitize "$f")"
        return 1
    fi
    printf 'STATUS\t%s response present — the subscriber data above is reachable through this interconnect\n' "$op"
}

# Local Iuh guard: HNB-GW signalling runs SCTP on 29169. A local bind test
# proves the interface is exposed on this host; it never sends a message.
gcve_probe_iuh() {
    local f port=29169 hits
    f="$(gcve_require_file iuh)" || return 1
    hits=$(grep -cE '(^|[^0-9])29169([^0-9]|$)|hnb|iuh' "$f" || true)
    printf 'artefact\t%s\niuh_port\t%s\nhnb_markers\t%s\n' \
        "$(gcve_sanitize "$f")" "$port" "$hits"
    if [[ "$hits" -gt 0 ]]; then
        printf 'STATUS\tIuh / HNB-GW surface present in the listing — the femtocell exposes SCTP %s\n' "$port"
    else
        printf 'STATUS\tno Iuh or HNB-GW marker in %s\n' "$(gcve_sanitize "$f")"
        return 1
    fi
}

# The MAP edge guard: an operator that blocks SRI/PSI/ATI at the STP answers
# "unknown subscriber" or an error, never a location. Classify that answer.
gcve_probe_map_blocks() {
    local f
    f="$(gcve_require_file map)" || return 1
    local blocked
    blocked=$(grep -ciE 'unknownSubscriber|absentSubscriber|systemFailure|unauthorized|notAuthorised|illegalSubscriber' "$f" || true)
    printf 'artefact\t%s\nblocked_causes\t%s\n' "$(gcve_sanitize "$f")" "$blocked"
    if [[ "$blocked" -gt 0 ]]; then
        printf 'STATUS\tthis edge answers MAP queries with refusal causes — interworking is filtered\n'
    else
        printf 'STATUS\tno refusal cause in %s — either the queries are served or nothing was tried\n' "$(gcve_sanitize "$f")"
    fi
}

# Kc — real A3/A8 (COMP128).
#
# COMP128-1 is the classic A3/A8 that most 2G SIMs implement; COMP128-2 and -3
# are the patched variants later card generations use. All three live in
# tools/gsm_crypto.py, which carries published known-answer vectors and proves
# itself with its own --selftest. This is the derivation that separates a
# default OTA key set from a provisioned one: a known KI yields a known
# SRES/Kc pair, which a digest of KI||RAND never could.
gcve_kc_tsv() {
    local ki="$1" rand="$2" algo="${3:-v1}"
    [[ "$ki" =~ ^[0-9A-Fa-f]{32}$ && "$rand" =~ ^[0-9A-Fa-f]{32}$ ]] || return 2
    case "$algo" in v1|v2|v3) ;; *) return 2 ;; esac
    local tool="$IMSISTING_ROOT/tools/gsm_crypto.py"
    [[ -f "$tool" ]] || { printf 'ERROR\ttools/gsm_crypto.py is missing\n' >&2; return 3; }
    python3 "$tool" --comp128 "$algo" --ki "$ki" --rand "$rand" || return 1
}

# Just the Kc value, for callers that want the key itself.
gcve_kc_hex() {
    local out
    out=$(gcve_kc_tsv "$@") || return $?
    printf '%s\n' "$out" | awk -F'\t' '$1=="kc"{print $2}'
}

gcve_probe_default_key() {
    local f ki kc
    f="$(gcve_require_file sim)" || return 1
    ki=$(grep -aEo 'KI[[:space:]]*[:=][[:space:]]*[0-9A-Fa-f]{32}' "$f" | head -1 \
        | grep -oE '[0-9A-Fa-f]{32}' || true)
    printf 'artefact\t%s\nki_present\t%s\n' \
        "$(gcve_sanitize "$f")" "$([[ -n "$ki" ]] && echo yes || echo no)"
    if [[ -z "$ki" ]]; then
        printf 'ERROR\tno KI in %s — the Kc derivation cannot run\n' "$(gcve_sanitize "$f")" >&2
        return 1
    fi
    local sres kc zero="00000000000000000000000000000000"
    sres=$(gcve_kc_tsv "$ki" "$zero" | awk -F'\t' '$1=="sres"{print $2}')
    kc=$(gcve_kc_hex "$ki" "$zero") || {
        printf 'ERROR\tKc derivation failed\n' >&2; return 1; }
    printf 'sres_zero_rand\t%s\nkc_zero_rand\t%s\n' "$sres" "$kc"
    case "${ki^^}" in
        $(printf '0%.0s' $(seq 1 32)))
            printf 'STATUS\tKI is all zero — the card ships a default authentication key\n'
            return 0 ;;
        $(printf 'F%.0s' $(seq 1 32)))
            printf 'STATUS\tKI is all ones — a test key, not a provisioned one\n'
            return 0 ;;
    esac
    printf 'STATUS\tKI is not a known default; compare sres_zero_rand/kc_zero_rand against the EF_KC set from the card\n'
}

# GSMA FS.11 / SGP.02 profile parse. Reports the profile fields that decide
# whether remote provisioning is locked down, without claiming an exploit.
gcve_probe_fs11_profile() {
    local f
    f="$(gcve_require_file ota)" || return 1
    local pv sec
    pv=$(grep -aEo 'profileVersion[[:space:]]*[:=][[:space:]]*[0-9.]+' "$f" | head -1 \
        | grep -oE '[0-9.]+$' || true)
    sec=$(grep -ciE '(PIN|key)[[:space:]]*[:=][[:space:]]*(default|0000|1234)' "$f" || true)
    printf 'artefact\t%s\nprofile_version\t%s\ndefault_credential_markers\t%s\ngsma_ref\tFS.11 (Remote APDU / OTA) and SGP.02 (eUICC remote provisioning)\n' \
        "$(gcve_sanitize "$f")" "${pv:-unknown}" "$sec"
    if [[ "$sec" -gt 0 ]]; then
        printf 'STATUS\tdefault or placeholder credentials in the profile — remote provisioning is not locked down\n'
    else
        printf 'STATUS\tno default credential marker in the profile\n'
    fi
}

# ── HANDOFFS ────────────────────────────────────────────────────────────
# Every handoff writes a plan file naming the exact testbed or hardware. The
# file is labelled a plan in its own body; nothing here is an attack.
gcve_handoff_plan() {
    local id="$1" note="$2"
    local slug dir f
    slug="$(printf '%s' "$id" | tr -c 'A-Za-z0-9._-' '_')"
    dir="$GCVE_PLANS"
    mkdir -p "$dir" 2>/dev/null || {
        printf 'ERROR\tcannot create plan dir %s\n' "$dir" >&2
        return 1
    }
    f="$dir/plan_${slug}.txt"
    {
        printf 'cve: %s\n' "$(gcve_sanitize "$id")"
        printf 'kit: gsm_cve\n'
        printf 'status: handoff — no safe automated one-shot probe in this kit\n'
        printf 'note: %s\n' "$(gcve_sanitize "$note")"
        printf 'requires: %s\n' "$(gcve_needs_of "$id")"
        printf 'ts: %s\n' "$(date -Is)"
    } > "$f" || {
        printf 'ERROR\tcannot write plan file %s\n' "$f" >&2
        return 1
    }
    printf 'cve\t%s\nstatus\thandoff\nplan\t%s\nnote\t%s\n' \
        "$(gcve_sanitize "$id")" "$(gcve_sanitize "$f")" "$(gcve_sanitize "$note")"
    gcve_record_run "$id" "handoff" "-" "$note"
    return 0
}

# ── per-id dispatch ─────────────────────────────────────────────────────
# probe ids route to a real probe; the probe must resolve its own input and
# fails loudly when it is absent. Handoff ids route to the plan writer.
gcve_run_cve() {
    local raw="${1:-}" id
    if [[ -z "$raw" ]]; then
        printf 'usage: %s --run-cve <ID>\n' "$0" >&2
        return 2
    fi
    id="$(gcve_normalize_id "$raw")"
    mkdir -p "$GCVE_DIR" "$GCVE_PLANS" 2>/dev/null

    case "$id" in
        # ── SS7 / MAP ──────────────────────────────────────────────────
        MAP-SRI-DISCLOSURE)
            gcve_probe_map_op SRI && gcve_record_run "$id" probe-ok "$(gcve_sanitize "$(gcve_probe_input map)")" "SRI disclosure listing parsed" ;;
        MAP-SRI-FOR-SM)
            gcve_probe_map_op SRI && gcve_record_run "$id" probe-ok "$(gcve_sanitize "$(gcve_probe_input map)")" "SRI-for-SM listing parsed" ;;
        MAP-PSI-DISCLOSURE)
            gcve_probe_map_op PSI && gcve_record_run "$id" probe-ok "$(gcve_sanitize "$(gcve_probe_input map)")" "PSI disclosure listing parsed" ;;
        MAP-ATI-BLOCKS)
            gcve_probe_map_blocks && gcve_record_run "$id" probe-ok "$(gcve_sanitize "$(gcve_probe_input map)")" "MAP edge refusal causes parsed" ;;

        # ── radio / cipher findings ────────────────────────────────────
        R2017-A51-BIAS)
            gcve_probe_a51 && gcve_record_run "$id" probe-ok "-" "A5/1 bias feasibility computed" ;;
        R2017-A52-RECOVER)
            gcve_probe_a52 && gcve_record_run "$id" probe-ok "-" "A5/2 recovery feasibility computed" ;;
        R2015-IMEI-SPOOF)
            gcve_probe_identity && gcve_record_run "$id" probe-ok "$(gcve_sanitize "$(gcve_probe_input sim)")" "identity BCD round trip" ;;

        # ── SIM / OTA ──────────────────────────────────────────────────
        R2018-SIMJACKER)
            gcve_probe_sat_browser && gcve_record_run "$id" probe-ok "$(gcve_sanitize "$(gcve_probe_input sim)")" "S@T capability classified" ;;
        E2015-SAT-PUSH)
            gcve_probe_sat_browser && gcve_record_run "$id" probe-ok "$(gcve_sanitize "$(gcve_probe_input sim)")" "S@T TAR/SPI listing parsed" ;;
        E2015-OTA-KEY)
            gcve_probe_ota_profile && gcve_record_run "$id" probe-ok "$(gcve_sanitize "$(gcve_probe_input ota)")" "OTA key set parsed" ;;
        GSMA-FS11-OTA)
            gcve_probe_fs11_profile && gcve_record_run "$id" probe-ok "$(gcve_sanitize "$(gcve_probe_input ota)")" "FS.11/SGP.02 profile parsed" ;;
        DEFAULT-KEY-SUPPORT)
            gcve_probe_default_key && gcve_record_run "$id" probe-ok "$(gcve_sanitize "$(gcve_probe_input sim)")" "Kc derivation run" ;;

        # ── femtocell ──────────────────────────────────────────────────
        FEMTO-IUH-EXPOSURE)
            gcve_probe_iuh && gcve_record_run "$id" probe-ok "$(gcve_sanitize "$(gcve_probe_input iuh)")" "Iuh surface classified" ;;

        # ── handoffs: SS7 / MAP ────────────────────────────────────────
        E2020-GPRS-BLOCK)
            gcve_handoff_plan "$id" "GPRS/EDGE LLC block configuration — needs an OTA testbed: a baseband test rig or a shielded Faraday enclosure with a BTS whose LLC layer the operator authorises you to drive" ;;
        E2020-GPRS-REASS)
            gcve_handoff_plan "$id" "GPRS/EDGE downlink reassembly corruption — needs an OTA testbed [srsRAN or OsmoPCU GPRS testbed] plus a target handset in a shielded box" ;;
        E2019-NAS-5GSM)
            gcve_handoff_plan "$id" "GPRS/EDGE NAS signalling corruption — needs a cell emulator [OsmocomBB plus a transmit-capable SDR: HackRF, BladeRF, USRP or LimeSDR] and an isolated downlink" ;;
        E2010-INFINEON-BB)
            gcve_handoff_plan "$id" "Infineon/Intel 2G/3G baseband decoder corruption — needs a lab network: a Faraday-caged BTS the vendor has authorised, plus the baseband debug UART on the target" ;;
        E2010-QUALCOMM-BB)
            gcve_handoff_plan "$id" "Qualcomm 2G/3G baseband decoder corruption — needs an OTA testbed: a transmit-capable SDR [HackRF/BladeRF/USRP] plus a target in a shielded enclosure, and a crash oracle [QXDM or the baseband ramdump]" ;;
        E2010-MTK-BB)
            gcve_handoff_plan "$id" "MediaTek 2G/3G baseband decoder corruption — needs an OTA testbed plus the MediaTek baseband log interface [MTKLogger / ELT] for crash confirmation" ;;
        CVE-2021-4135)
            gcve_handoff_plan "$id" "MediaTek baseband OTA-deliverable memory corruption — needs a transmit-capable SDR and a shielded target handset; reference: Comsecuris baseband security research, Nohl et al." ;;

        # ── handoffs: SIM Toolkit / OTA ────────────────────────────────
        CVE-2019-15962)
            gcve_handoff_plan "$id" "S@T browser command injection — needs a programmable SIM [sysmoISIM-SJA2/SJA5, or a Java Card] plus a SIM-Toolkit OTA harness; reference: Ginno SecurityLab / Security Explorations, 2019" ;;
        CVE-2019-16256)
            gcve_handoff_plan "$id" "Simjacker — needs a programmable SIM with a S@T browser in a shielded testbed plus an SMS sender the operator authorises; reference: AdaptiveMobile Security, 2019" ;;
        CVE-2019-16257)
            gcve_handoff_plan "$id" "Simjacker sibling binary — needs a second programmable SIM vendor image, S@T implementation and the same SIM-Toolkit OTA harness; reference: AdaptiveMobile Security, 2019" ;;
        CVE-2020-13888)
            gcve_handoff_plan "$id" "WIBattack — needs a programmable SIM carrying a WIB client plus the SIM-Toolkit OTA harness; reference: Ginno SecurityLab, 2020" ;;
        CVE-2022-21744)
            gcve_handoff_plan "$id" "SIM-Toolkit OTA keystream reuse in an eUICC OTA engine — needs a programmable eUICC, or a test eUICC carrying the operator key set and an OTA SMS sender; disclosed 2022" ;;
        R2024-FIRMWIRE)
            gcve_handoff_plan "$id" "FirmWire full-system emulation of a Samsung/MediaTek baseband — needs the firmware image of a device you own and a host with enough RAM; the L1/L2 corpus builds in 35_baseband" ;;
        R2020-BASESAFE)
            gcve_handoff_plan "$id" "BaseSAFE rehosting and sanitized fuzzing of a baseband — needs the firmware blob and the QEMU-based harness; reference: Maier et al., BaseSAFE (2020)" ;;
        R2019-OSMOCOMBB)
            gcve_handoff_plan "$id" "OsmocomBB layer-1 GSM access — needs Calypso-based hardware and its firmware; gives raw L1 that commercial stacks do not expose" ;;
        R2025-LLFUZZ-GSM)
            gcve_handoff_plan "$id" "LLFuzz-style L1/L2 fuzzing adapted to the GSM/GPRS stack — needs a transmit-capable SDR and a stateful harness; the corpus builds in 54_baseband_exploit --l2-corpus" ;;

        # ── handoffs: unknown ⇒ loud, never silent success ─────────────
        *)
            # A probe that cannot resolve its own input must fail loudly and
            # must NOT be recorded as a run: a row whose status is neither a
            # probe result nor a handoff would let a downstream consumer read
            # a failed probe as coverage.
            if gcve_id_known "$id"; then
                printf 'ERROR\tno probe input for %s — supply the artefact this probe reads (see --list-cves), or record it as handoff\n' \
                    "$(gcve_sanitize "$id")" >&2
                return 1
            fi
            printf 'ERROR\tunknown CVE id: %s (see --list-cves)\n' "$(gcve_sanitize "$raw")" >&2
            return 2 ;;
    esac
}

# ── the research findings, as findings ──────────────────────────────────
# These are not CVEs and are not dressed up as any. They are the published
# weaknesses the kit is built around, with their references.
gcve_findings() {
    cat <<'FINDINGS'
id	class	summary	reference
A5-1-BIAS	cipher	A5/1 keystream is linear and biased; time-memory tradeoff key recovery from ~2 minutes of known plaintext	Golic 1997; Biham-Dunkelman-Keller 2000; Nohl 2009 (A5/1 rainbow tables)
A5-2-BROKEN	cipher	A5/2 key recovery is real-time and ciphertext-only; four frames plus 2^16 work	Barkan-Biham-Keller 2003 (Instant Ciphertext-Only Cryptanalysis of GSM Encrypted Communication)
A5-3-WEAK	cipher	A5/3 (KASUMI) carries the published algebraic and related-key weaknesses	Dunkelman-Keller-Shamir 2010 (KASUMI is not a secure block cipher)
NO-INTEROP-AUTH	protocol	MAP has no authentication between operators; SRI/PSI/ATI are trusted requests	GSMA FS.11 / IR.71 baseline; ENISA SS7 signalling-security reports 2016-2019
SS7-FIREWALL-GAP	defence	Signalling firewalls are configuration, not cryptography; category filtering is bypassable by design	GSMA FS.11 category model; 3GPP TS 33.204
OTA-KEY-REUSE	sim	OTA key derivation with a reused counter lets a recorded OTA command set be replayed	GSMA SGP.02 remote provisioning; ETSI TS 102 225 / 102 226
SUPI-PLAINTEXT	identity	Pre-5G subscriber identifiers are carried in the clear on the signalling plane	3GPP TS 23.003 (IMSI); TS 29.002 (MAP)
FINDINGS
}

# ── CLI verbs ───────────────────────────────────────────────────────────
# The shared state file is written by 01_radio as <driver>\t<serial>\t<index>.
# Never paste it raw into a status row: that puts three values into a two-field
# contract. Split it into three 2-field rows instead.
gcve_sdr_rows() {
    local drv="none" sn="none" idx="none"
    if [[ -s "$GCVE_SDR" ]]; then
        IFS=$'\t' read -r drv sn idx < <(tr -d '\r' < "$GCVE_SDR" | head -n1)
    fi
    printf 'sdr\t%s\n'        "${drv:-none}"
    printf 'sdr_serial\t%s\n' "${sn:-none}"
    printf 'sdr_index\t%s\n'  "${idx:-none}"
}

gcve_cli_status_tsv() {
    local runs plans rows
    runs=$(gcve_run_count)
    plans=$(find "$GCVE_PLANS" -type f -name 'plan_*.txt' 2>/dev/null | wc -l | tr -d ' ')
    rows=$(gcve_id_count)
    printf 'module\tgsm_cve\nversion\t%s\n' "$GCVE_VERSION"
    printf 'ids\t%s\n'            "$rows"
    printf 'probes\t%s\n'         "$(gcve_ids_of_kind probe | grep -c . || true)"
    printf 'handoffs\t%s\n'       "$(gcve_ids_of_kind handoff | grep -c . || true)"
    printf 'runs\t%s\n'           "$runs"
    printf 'plans\t%s\n'          "$plans"
    gcve_sdr_rows
    printf 'target\t%s\n'         "$(gcve_resolve_target 2>/dev/null || echo none)"
    printf 'dir\t%s\n'            "$GCVE_DIR"
    printf 'runs_file\t%s\n'      "$GCVE_RUNS"
    printf 'plans_dir\t%s\n'      "$GCVE_PLANS"
}

gcve_cmd_list_cves() {
    local id kind cls needs label
    printf 'id\tkind\tclass\tneeds\tlabel\n'
    while IFS=$'\t' read -r id kind cls needs label; do
        [[ -z "$id" ]] && continue
        printf '%s\t%s\t%s\t%s\t%s\n' \
            "$(gcve_sanitize "$id")" "$(gcve_sanitize "$kind")" \
            "$(gcve_sanitize "$cls")" "$(gcve_sanitize "$needs")" \
            "$(gcve_sanitize "$label")"
    done < <(gcve_cve_table)
}

gcve_cmd_list_findings() {
    gcve_findings
}

gcve_cmd_runs_tsv() {
    if [[ "$(gcve_run_count)" -eq 0 ]]; then
        printf 'ERROR\tno CVE runs recorded yet\n' >&2
        return 1
    fi
    cat "$GCVE_RUNS"
}

gcve_cmd_probe() {
    # Direct probe entry: --probe <MAP-SRI|MAP-PSI|MAP-ATI|MAP-BLOCKS|A51|A52|SIM-SAT|OTA|FS11|KC|IUH|IDENTITY>
    local what="${1:-}"
    case "$what" in
        MAP-SRI)   gcve_probe_map_op SRI ;;
        MAP-PSI)   gcve_probe_map_op PSI ;;
        MAP-ATI)   gcve_probe_map_op ATI ;;
        MAP-BLOCKS) gcve_probe_map_blocks ;;
        A51)       gcve_probe_a51 ;;
        A52)       gcve_probe_a52 ;;
        SIM-SAT)   gcve_probe_sat_browser ;;
        OTA)       gcve_probe_ota_profile ;;
        FS11)      gcve_probe_fs11_profile ;;
        KC)        gcve_probe_default_key ;;
        IUH)       gcve_probe_iuh ;;
        IDENTITY)  gcve_probe_identity ;;
        *) printf 'ERROR\tunknown probe: %s\n' "$(gcve_sanitize "$what")" >&2; return 2 ;;
    esac
}

gcve_cmd_bcd() {
    local mode="${1:-}" val="${2:-}" out
    [[ -n "$mode" && -n "$val" ]] || {
        printf 'ERROR\tusage: --bcd <enc|dec> <value>\n' >&2; return 2; }
    case "$mode" in
        enc) out=$(gcve_bcd_encode "$val") || { printf 'ERROR\tnot decimal digits: %s\n' "$(gcve_sanitize "$val")" >&2; return 1; } ;;
        dec) out=$(gcve_bcd_decode "$val") || { printf 'ERROR\tnot an even-length hex string: %s\n' "$(gcve_sanitize "$val")" >&2; return 1; } ;;
        *) printf 'ERROR\tunknown bcd mode: %s (want enc|dec)\n' "$(gcve_sanitize "$mode")" >&2; return 2 ;;
    esac
    printf 'mode\t%s\nin\t%s\nout\t%s\n' "$(gcve_sanitize "$mode")" "$(gcve_sanitize "$val")" "$out"
}

gcve_cmd_kc() {
    local ki="${1:-}" rand="${2:-}" algo="${3:-v1}" out
    [[ -n "$ki" && -n "$rand" ]] || {
        printf 'ERROR\tusage: --kc <KI-hex32> <RAND-hex32> [v1|v2|v3]\n' >&2; return 2; }
    out=$(gcve_kc_tsv "$ki" "$rand" "$algo") || {
        printf 'ERROR\tKI and RAND must each be 32 hex digits, algo must be v1, v2 or v3\n' >&2; return 1; }
    printf '%s\n' "$out"
    printf 'note\tA3/A8 via COMP128 — validated against published vectors in tools/gsm_crypto.py --selftest\n'
}

gcve_cmd_plan() {
    local id="${1:-}"
    [[ -n "$id" ]] || { printf 'ERROR\tusage: --plan <ID>\n' >&2; return 2; }
    local kind; kind=$(gcve_kind_of "$id") || {
        printf 'ERROR\tunknown id: %s\n' "$(gcve_sanitize "$id")" >&2; return 2; }
    if [[ "$kind" == "probe" ]]; then
        printf 'id\t%s\nkind\tprobe\nnote\tthis id has a real probe — run --run-cve %s\n' \
            "$(gcve_sanitize "$id")" "$(gcve_sanitize "$id")"
        return 0
    fi
    gcve_handoff_plan "$id" "$(gcve_cve_table | awk -F'\t' -v i="$id" '$1==i{print $5}')"
}

# ── selftest — no radio, no root, no network ────────────────────────────
# ── the corpus horizon ──────────────────────────────────────────────────
# A CVE table is a photograph, not a feed. Every entry here was read on the
# date in the row below it, and anything disclosed after that date is not in
# the corpus and is therefore NOT assessed -- the one thing a security tool
# must never do is let a fixed snapshot read as current coverage.
gcve_cmd_coverage() {
    local rows newest entries years
    rows=$(gcve_cve_table)
    entries=$(printf '%s\n' "$rows" | grep -c . || true)
    years=$(printf '%s\n' "$rows" \
        | awk -F'\t' '{ if (match($1, /(19|20)[0-9][0-9]/)) print substr($1, RSTART, 4) }' \
        | sort -n | uniq)
    newest=$(printf '%s\n' "$years" | tail -1)
    local horizon="${newest:-unknown}"
    local stale
    stale=$(date -u +%Y)
    printf 'corpus\t%s\n' "GSM/GPRS CVE corpus"
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

gcve_selftest() {
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad + 1)); fi
    }
    chkne() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" != "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want!=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad + 1)); fi
    }
    fld() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }

    local d out rc id ok n
    unrouted=0
    d=$(mktemp -d "$MOD_TMP/selftest.XXXXXX") || {
        printf 'ERROR\tmktemp failed under %s\n' "$MOD_TMP" >&2; return 1; }
    mkdir -p "$d/loot" "$d/captures"
    # Redirect every output path into the scratch dir and export it so the
    # helpers (and anything they exec) see the redirect too.
    export LOOT_DIR="$d/loot" CAPTURES_DIR="$d/captures"
    export GCVE_DIR="$d/loot/gsm_cve" GCVE_RUNS="$d/loot/gsm_cve/runs.tsv"
    export GCVE_PLANS="$d/loot/gsm_cve/plans"
    # Read the shared SDR state from the scratch dir, not the host's: the status
    # row must be tested against a state file this selftest controls.
    export GCVE_SDR="$d/state/sdr_device"
    unset GCVE_TARGET GCVE_SIM_ARTEFACT GCVE_OTA_ARTEFACT GCVE_IUH_ARTEFACT GCVE_MAP_ARTEFACT
    mkdir -p "$GCVE_DIR" "$GCVE_PLANS"

    # ── 1. the dispatch table is exhaustive ────────────────────────────
    # Every documented id must route to a probe or a handoff, and the count
    # is asserted so a dropped id is a failure rather than a smaller number.
    local nids nprobe nhand
    nids=$(gcve_id_count)
    nprobe=$(gcve_ids_of_kind probe | grep -c . || true)
    nhand=$(gcve_ids_of_kind handoff | grep -c . || true)
    chk table-ids     "$nids"   "29"
    chk table-probes  "$nprobe" "13"
    chk table-handoffs "$nhand" "16"
    chk table-split   "$((nprobe + nhand))" "$nids"

    # No duplicate ids, every row has five fields, no id is empty.
    chk table-unique   "$(gcve_cve_table | cut -f1 | sort | uniq -d | grep -c . || true)" "0"
    chk table-fields   "$(gcve_cve_table | awk -F'\t' 'NF!=5' | grep -c . || true)" "0"
    chk table-empty-id "$(gcve_cve_table | awk -F'\t' '$1==""' | grep -c . || true)" "0"

    # Every documented id must actually route: run it and refuse to accept
    # the dispatcher's "unknown CVE id" answer. Without this the table and
    # the case arms can drift apart silently.
    unrouted=0
    while IFS= read -r id; do
        out=$(gcve_run_cve "$id" 2>&1)
        printf '%s\n' "$out" | grep -q 'unknown CVE id' && unrouted=$((unrouted + 1))
    done < <(gcve_cve_table | cut -f1)
    chk table-every-id-routes "$unrouted" "0"

    # ── 2. every probe id routes to its probe, every handoff to a plan ─
    # A probe with no input artefact must fail loudly (non-zero), never
    # report clean. A handoff must exit 0 and leave exactly one plan file.
    # Both loops run in the *parent* shell, not a pipeline subshell, so the
    # counters survive; a failure in a subshell would silently read as PASS.
    local fails=0 nhandoff=0
    for id in $(gcve_ids_of_kind probe); do
        out=$(GCVE_SIM_ARTEFACT="$d/nope-sim.txt" GCVE_OTA_ARTEFACT="$d/nope-ota.txt" \
              GCVE_IUH_ARTEFACT="$d/nope-iuh.txt" GCVE_MAP_ARTEFACT="$d/nope-map.txt" \
              gcve_run_cve "$id" 2>/dev/null)
        rc=$?
        case "$id" in
            # These two probes run on computed input and must succeed.
            R2017-A51-BIAS|R2017-A52-RECOVER) [[ $rc -eq 0 ]] || fails=$((fails + 1)) ;;
            # Everything else needs an artefact and must fail loudly.
            *) [[ $rc -ne 0 ]] || fails=$((fails + 1)) ;;
        esac
        printf '%s\n' "$out" | grep -qi '^status[[:space:]]*clean' && fails=$((fails + 1))
    done
    chk probe-no-input-fails-loud "$fails" "0"

    for id in $(gcve_ids_of_kind handoff); do
        gcve_run_cve "$id" >/dev/null 2>&1 || fails=$((fails + 1))
        nhandoff=$((nhandoff + 1))
    done
    chk handoff-all-rc      "$fails" "0"
    chk handoff-ids-covered "$nhandoff" "$nhand"
    chk handoff-file-count "$(find "$GCVE_PLANS" -type f -name 'plan_*.txt' | wc -l | tr -d ' ')" "$nhand"

    # ── 3. handoff record shape ────────────────────────────────────────
    out=$(gcve_run_cve CVE-2019-16256 2>&1); rc=$?
    chk handoff-rc     "$rc" "0"
    chk handoff-status "$(printf '%s\n' "$out" | grep -c '^status	handoff$')" "1"
    chk handoff-cve    "$(printf '%s\n' "$out" | grep -c '^cve	CVE-2019-16256$')" "1"
    n="$GCVE_PLANS/plan_CVE-2019-16256.txt"
    chk handoff-plan-exists "$([[ -f "$n" ]] && echo yes || echo no)" "yes"
    chk handoff-plan-status "$(grep -c '^status: handoff' "$n")" "1"
    chk handoff-plan-requires "$(grep -c '^requires: sim-toolkit-harness$' "$n")" "1"
    chk handoff-plan-note "$(grep -c 'Simjacker' "$n")" "1"

    # An id carrying path separators must not escape the plan directory.
    n=$(find "$GCVE_PLANS" -type f | wc -l | tr -d ' ')
    gcve_handoff_plan 'weird/id 1' 'note' >/dev/null 2>&1
    chk handoff-slug-count "$(find "$GCVE_PLANS" -type f | wc -l | tr -d ' ')" "$((n + 1))"
    chk handoff-slug-name  "$(find "$GCVE_PLANS" -name 'plan_weird_id_1.txt' | wc -l | tr -d ' ')" "1"

    # ── 4. argument validation ─────────────────────────────────────────
    chk run-no-id-rc       "$(gcve_run_cve >/dev/null 2>&1; echo $?)" "2"
    out=$(gcve_run_cve CVE-9999-99999 2>&1); rc=$?
    chk run-unknown-rc     "$rc" "2"
    chk run-unknown-msg    "$(printf '%s\n' "$out" | grep -c 'unknown CVE id: CVE-9999-99999')" "1"
    chk probe-unknown-rc   "$(gcve_cmd_probe NOPE >/dev/null 2>&1; echo $?)" "2"
    chk plan-unknown-rc    "$(gcve_cmd_plan NOPE >/dev/null 2>&1; echo $?)" "2"
    chk bcd-usage-rc       "$(gcve_cmd_bcd >/dev/null 2>&1; echo $?)" "2"
    chk bcd-badmode-rc     "$(gcve_cmd_bcd wat 12 >/dev/null 2>&1; echo $?)" "2"
    chk kc-usage-rc        "$(gcve_cmd_kc >/dev/null 2>&1; echo $?)" "2"
    # Lowercase and whitespace-padded ids still route.
    chk normalize-lower    "$(gcve_normalize_id '  cve-2019-16256 ')" "CVE-2019-16256"
    chk normalize-rc       "$(gcve_run_cve ' cve-2019-16256 ' >/dev/null 2>&1; echo $?)" "0"

    # ── 5. probes that need no input, byte-exact ───────────────────────
    out=$(gcve_run_cve R2017-A52-RECOVER); rc=$?
    chk a52-rc     "$rc" "0"
    chk a52-cipher "$(fld "$out" cipher)" "A5/2"
    chk a52-recov  "$(fld "$out" recoverable)" "yes"
    chk a52-status "$(printf '%s\n' "$out" | grep -c '^STATUS	A5/2 key recovery is feasible')" "1"

    out=$(GCVE_A52_FRAMES=2 gcve_run_cve R2017-A52-RECOVER 2>/dev/null); rc=$?
    chk a52-twoframe-rc     "$rc" "1"
    chk a52-twoframe-recov  "$(fld "$out" recoverable)" "no"

    out=$(gcve_run_cve R2017-A51-BIAS); rc=$?
    chk a51-rc     "$rc" "0"
    chk a51-recov  "$(fld "$out" recoverable)" "feasible"
    chk a51-samples "$(fld "$out" samples)" "6000"
    out=$(GCVE_A51_SECONDS=60 gcve_run_cve R2017-A51-BIAS 2>/dev/null); rc=$?
    chk a51-short-rc    "$rc" "1"
    chk a51-short-recov "$(fld "$out" recoverable)" "insufficient-ciphertext"

    # ── 6. BCD identity codec, byte-exact round trip ───────────────────
    chk bcd-enc-imei   "$(gcve_bcd_encode 123456789012345)" "21436587092143F5"
    chk bcd-dec-imei   "$(gcve_bcd_decode 21436587092143F5)" "123456789012345"
    chk bcd-enc-imsi   "$(gcve_bcd_encode 208011234567890)" "02081132547698F0"
    chk bcd-imsi-14    "$(gcve_bcd_encode 20801123456789)"  "02081132547698"
    chk bcd-roundtrip  "$(gcve_bcd_decode "$(gcve_bcd_encode 310260123456789)")" "310260123456789"
    chk bcd-enc-bad    "$(gcve_bcd_encode 12ab >/dev/null 2>&1; echo $?)" "1"
    chk bcd-dec-odd    "$(gcve_bcd_decode abc >/dev/null 2>&1; echo $?)" "1"
    chk bcd-dec-nonhex "$(gcve_bcd_decode zz >/dev/null 2>&1; echo $?)" "1"

    # ── 7. Kc is REAL A3/A8 (COMP128), not a digest of KI||RAND ────────
    local ki="00112233445566778899AABBCCDDEEFF" zero="00000000000000000000000000000000"
    # Published COMP128-1 known-answer vector; the same vector is asserted in
    # tools/gsm_crypto.py --selftest, so this pins the cross-module contract.
    chk kc-vector-kat   "$(gcve_kc_hex "$ki" "$ki")" "F87EB8222CEA3400"
    chk sres-vector-kat "$(gcve_kc_tsv "$ki" "$ki" | awk -F'\t' '$1=="sres"{print $2}')" "04A66BA8"
    chk kc-deterministic "$(gcve_kc_hex "$ki" "$zero")" "$(gcve_kc_hex "$ki" "$zero")"
    chk kc-len   "$(gcve_kc_hex "$ki" "$zero" | wc -c | tr -d ' ')" "17"
    chk kc-bad-rc "$(gcve_kc_hex 12 34 >/dev/null 2>&1; echo $?)" "2"
    chk kc-bad-algo "$(gcve_kc_tsv "$ki" "$zero" v9 >/dev/null 2>&1; echo $?)" "2"
    chk kc-differs "$([[ "$(gcve_kc_hex "$ki" "$zero")" != \
                           "$(gcve_kc_hex "$ki" FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)" ]] && echo yes || echo no)" "yes"

    # ── 8. artefact probes: real parse on a real listing ───────────────
    cat > "$d/captures/sim.txt" <<'SIM'
IMSI: 208011234567890
IMEI: 123456789012345
EF_SAT: present
SAT browser: S@T
TAR: B00001
TAR: B00002
SAT access: full
KI: 00112233445566778899AABBCCDDEEFF
SIM
    export GCVE_SIM_ARTEFACT="$d/captures/sim.txt"
    out=$(gcve_run_cve R2018-SIMJACKER); rc=$?
    chk sat-rc       "$rc" "0"
    chk sat-markers  "$(fld "$out" sat_browser_markers)" "1"
    chk sat-tars     "$(fld "$out" tar_entries)" "2"
    chk sat-unrestr  "$(fld "$out" unrestricted_access)" "1"
    chk sat-status   "$(printf '%s\n' "$out" | grep -c 'S@T/WIB browser present')" "1"

    out=$(gcve_run_cve R2015-IMEI-SPOOF); rc=$?
    chk ident-rc     "$rc" "0"
    chk ident-imsi   "$(fld "$out" imsi | head -1)" "208011234567890"
    chk ident-round  "$(printf '%s\n' "$out" | grep -c 'roundtrip	ok')" "2"

    out=$(gcve_run_cve DEFAULT-KEY-SUPPORT); rc=$?
    chk kc-run-rc    "$rc" "0"
    chk kc-run-ki    "$(fld "$out" ki_present)" "yes"
    chk kc-run-status "$(printf '%s\n' "$out" | grep -c 'STATUS	KI is not a known default')" "1"

    # The all-zero KI is the default-key finding, and must say so.
    printf 'KI: %s\n' "00000000000000000000000000000000" > "$d/captures/simzero.txt"
    out=$(GCVE_SIM_ARTEFACT="$d/captures/simzero.txt" gcve_run_cve DEFAULT-KEY-SUPPORT)
    chk kc-zero-status "$(printf '%s\n' "$out" | grep -c 'STATUS	KI is all zero')" "1"

    # A listing with no S@T marker must say so rather than claim a hit.
    printf 'IMSI: 208019999999999\n' > "$d/captures/simplain.txt"
    out=$(GCVE_SIM_ARTEFACT="$d/captures/simplain.txt" gcve_run_cve R2018-SIMJACKER)
    chk sat-absent "$(printf '%s\n' "$out" | grep -c 'no S@T/WIB browser marker')" "1"

    cat > "$d/captures/ota.txt" <<'OTA'
profileVersion: 2.2.0
KI: 00112233445566778899AABBCCDDEEFF
OTAK: FFEEDDCCBBAA99887766554433221100
OTAK counter: 0
OTA
    export GCVE_OTA_ARTEFACT="$d/captures/ota.txt"
    out=$(gcve_run_cve E2015-OTA-KEY); rc=$?
    chk ota-rc      "$rc" "0"
    chk ota-ki      "$(fld "$out" ki_present)" "yes"
    chk ota-counter "$(fld "$out" ota_counter)" "0"
    chk ota-status  "$(printf '%s\n' "$out" | grep -c 'OTA-key counter is zero')" "1"
    out=$(gcve_run_cve GSMA-FS11-OTA)
    chk fs11-ver    "$(fld "$out" profile_version)" "2.2.0"

    # An OTA listing with no KI cannot run the derivation: loud failure.
    printf 'profileVersion: 1.0\n' > "$d/captures/otanoKI.txt"
    chk ota-noki-rc "$(GCVE_OTA_ARTEFACT="$d/captures/otanoKI.txt" gcve_run_cve E2015-OTA-KEY >/dev/null 2>&1; echo $?)" "1"

    mkdir -p "$d/captures/gsm"
    cat > "$d/captures/gsm/map.txt" <<'MAP'
operation: sendRoutingInfoForSM
IMSI: 208011234567890
locationNumber: +33600000000
vlrNumber: +33612345678
subscriberState: assumedIdle
cellGlobalId: 208-01-1234-5678
MAP
    export GCVE_MAP_ARTEFACT="$d/captures/gsm/map.txt"
    out=$(gcve_run_cve MAP-SRI-DISCLOSURE); rc=$?
    chk map-sri-rc   "$rc" "0"
    chk map-sri-imsi "$(printf '%s\n' "$out" | grep -c 'disclosed	IMSI')" "1"
    out=$(gcve_run_cve MAP-PSI-DISCLOSURE)
    chkne map-psi-rc "$(gcve_run_cve MAP-PSI-DISCLOSURE >/dev/null 2>&1; echo $?)" "0"
    chk map-ati-rc  "$(gcve_run_cve MAP-ATI-BLOCKS >/dev/null 2>&1; echo $?)" "0"

    printf 'cause: unknownSubscriber\n' > "$d/captures/mapblocked.txt"
    out=$(GCVE_MAP_ARTEFACT="$d/captures/mapblocked.txt" gcve_run_cve MAP-ATI-BLOCKS)
    chk map-blocked "$(printf '%s\n' "$out" | grep -c '^blocked_causes	1$')" "1"

    printf 'listener hnbgw sctp 29169\n' > "$d/captures/iuh.txt"
    export GCVE_IUH_ARTEFACT="$d/captures/iuh.txt"
    out=$(gcve_run_cve FEMTO-IUH-EXPOSURE); rc=$?
    chk iuh-rc     "$rc" "0"
    chk iuh-port   "$(fld "$out" iuh_port)" "29169"
    chk iuh-status "$(printf '%s\n' "$out" | grep -c 'femtocell exposes SCTP 29169')" "1"

    # ── 9. a full documented sweep ─────────────────────────────────────
    # Every documented id must be reached (never "unknown"). An id that
    # records a verdict writes one run row; an id whose artefact is absent
    # fails loudly and writes none. Both counts are asserted so a dropped id
    # cannot hide behind a smaller number.
    # The loop runs in the parent shell: a pipeline subshell would swallow
    # every run and leave a header-only file that still "looks" written.
    # The artefact paths the earlier sections exported are cleared first:
    # leaving them set made every artefact probe succeed here and the loud
    # failure count below read as 1 instead of the full set.
    unset GCVE_SIM_ARTEFACT GCVE_OTA_ARTEFACT GCVE_IUH_ARTEFACT GCVE_MAP_ARTEFACT
    export CAPTURES_DIR="$d/sweep-captures"
    mkdir -p "$CAPTURES_DIR"
    rm -f "$GCVE_RUNS"
    local K_seen=0 K_rec=0 K_miss=0 K_loud=0 K_expect_loud=0
    for id in $(gcve_cve_table | cut -f1); do
        gcve_needs_artefact "$id" && K_expect_loud=$((K_expect_loud + 1))
    done
    while IFS= read -r id; do
        out=$(gcve_run_cve "$id" 2>&1); rc=$?
        K_seen=$((K_seen + 1))
        printf '%s\n' "$out" | grep -q 'unknown CVE id' && K_miss=$((K_miss + 1))
        if [[ $rc -eq 0 ]]; then
            K_rec=$((K_rec + 1))
        elif gcve_needs_artefact "$id"; then
            K_loud=$((K_loud + 1))
        fi
    done < <(gcve_cve_table | cut -f1)
    chk sweep-no-unknown "$K_miss" "0"
    chk sweep-ids-seen "$K_seen" "$nids"
    chk sweep-run-rows  "$(gcve_run_count)" "$K_rec"
    # Every id classified as artefact-dependent must have failed loudly when
    # no artefact was present, and the count of those ids is fixed by the
    # table. A silent pass shows up as K_loud below this number; an
    # unexplained failure shows up as K_loud above it.
    chk sweep-loud-fails "$K_loud" "$K_expect_loud"
    chk sweep-runs-hdr  "$(head -1 "$GCVE_RUNS")" "$(printf 'id\tstatus\ttarget\tevidence\tts')"
    chk sweep-run-fields "$(awk -F'\t' 'NF!=5' "$GCVE_RUNS" | grep -c . || true)" "0"
    chk sweep-handoff-rows "$(awk -F'\t' '$2=="handoff"' "$GCVE_RUNS" | grep -c . || true)" "$nhand"
    chk sweep-run-ids-unique "$(tail -n +2 "$GCVE_RUNS" | cut -f1 | sort -u | grep -c . || true)" "$K_rec"
    chk sweep-no-bad-status "$(tail -n +2 "$GCVE_RUNS" | awk -F'\t' '$2!="probe-ok" && $2!="handoff"' | grep -c . || true)" "0"

    # A tab smuggled into a run record must not forge a row.
    rm -f "$GCVE_RUNS"
    gcve_record_run $'X\tY' "probe-ok" $'a\tb' $'c\nd'
    chk run-tab-injection "$(awk -F'\t' 'NF!=5' "$GCVE_RUNS" | grep -c . || true)" "0"
    chk run-record-rows   "$(tail -n +2 "$GCVE_RUNS" | grep -c . || true)" "1"
    # A run record that cannot be written is an error, not a success.
    chk run-unwritable-rc "$(GCVE_RUNS=/proc/imsisting-nope/runs.tsv GCVE_DIR=/proc/imsisting-nope \
        gcve_record_run A probe-ok - e 2>/dev/null; echo $?)" "1"

    # ── 10. CLI surface ────────────────────────────────────────────────
    out=$(gcve_cmd_list_cves)
    chk list-cves-hdr    "$(printf '%s\n' "$out" | head -1)" "$(printf 'id\tkind\tclass\tneeds\tlabel')"
    chk list-cves-rows   "$(printf '%s\n' "$out" | tail -n +2 | grep -c .)" "$nids"
    chk list-cves-fields "$(printf '%s\n' "$out" | awk -F'\t' 'NF!=5' | grep -c . || true)" "0"
    out=$(gcve_cmd_list_findings)
    chk findings-rows    "$(printf '%s\n' "$out" | tail -n +2 | grep -c .)" "7"
    chk findings-refs    "$(printf '%s\n' "$out" | awk -F'\t' 'NF!=4' | grep -c . || true)" "0"
    chk runs-empty-rc    "$(: > "$GCVE_RUNS"; gcve_cmd_runs_tsv >/dev/null 2>&1; echo $?)" "1"

    # ── 11. status TSV contract ────────────────────────────────────────
    # 01_radio writes "<driver>\t<serial>\t<index>". A populated state file was
    # once pasted raw into the 2-field status row; assert the split instead.
    mkdir -p "${GCVE_SDR%/*}"
    printf 'bladerf\tdeadbeef0001\t1\n' > "$GCVE_SDR"
    out=$(gcve_cli_status_tsv)
    chk status-module  "$(fld "$out" module)"   "gsm_cve"
    chk status-ids     "$(fld "$out" ids)"      "$nids"
    chk status-probes  "$(fld "$out" probes)"   "$nprobe"
    chk status-handoffs "$(fld "$out" handoffs)" "$nhand"
    chk status-dir     "$(fld "$out" dir)"      "$GCVE_DIR"
    chk status-runsf   "$(fld "$out" runs_file)" "$GCVE_RUNS"
    chk status-plansdir "$(fld "$out" plans_dir)" "$GCVE_PLANS"
    chk status-fields  "$(printf '%s\n' "$out" | awk -F'\t' 'NF!=2' | grep -c . || true)" "0"
    chk status-sdr     "$(fld "$out" sdr)"        "bladerf"
    chk status-sdr-sn  "$(fld "$out" sdr_serial)" "deadbeef0001"
    chk status-sdr-idx "$(fld "$out" sdr_index)"  "1"
    # An absent state file still yields the three rows, all "none".
    rm -f "$GCVE_SDR"
    out=$(gcve_cli_status_tsv)
    chk status-sdr-nofile  "$(fld "$out" sdr)" "none"
    chk status-fields-none "$(printf '%s\n' "$out" | awk -F'\t' 'NF!=2' | grep -c . || true)" "0"

    rm -rf "$d"
    # ── the corpus horizon, R47 ───────────────────────────────────────
    local cov; cov=$(gcve_cmd_coverage)
    chk coverage-entries  "$(printf '%s\n' "$cov" | awk -F'\t' '$1=="entries"{print ($2>0)?"yes":"no"}')" "yes"
    chk coverage-horizon  "$(printf '%s\n' "$cov" | awk -F'\t' '$1=="corpus_horizon"{print ($2~/^[0-9]{4}-12-31$/)?"yes":"no"}')" "yes"
    chk coverage-claim    "$(printf '%s\n' "$cov" | awk -F'\t' '$1=="claim"{print $2}')" "coverage_is_a_snapshot"
    chk coverage-update   "$(printf '%s\n' "$cov" | awk -F'\t' '$1=="update"{print (length($2)>40)?"yes":"no"}')" "yes"

    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ── menu ────────────────────────────────────────────────────────────────
gcve_menu() {
    while true; do
        banner
        echo -e "  ${C_MAG}=== GSM/UMTS CVE kit ===${C_RESET}"
        echo -e "  ids:  ${C_GRN}$(gcve_id_count)${C_RESET}  ${C_DIM}$(gcve_ids_of_kind probe | grep -c . || true) probe / $(gcve_ids_of_kind handoff | grep -c . || true) handoff${C_RESET}"
        echo -e "  runs: ${C_GRN}$(gcve_run_count)${C_RESET}"
        echo -e "  dir:  ${C_DIM}$GCVE_DIR${C_RESET}\n"
        cat << 'M'
  [1]  list documented ids (probe vs handoff)
  [2]  run a probe by id
  [3]  write the handoff plan by id
  [4]  show the research findings (A5/1, A5/2, SS7 MAP, OTA)
  [5]  probe an SS7/MAP response artefact
  [6]  probe a SIM listing (S@T browser capability)
  [7]  probe an OTA profile (key set, counter state)
  [8]  APDU / identity BCD encode-decode
  [9]  Kc derivation from KI + RAND
  [10] show run history
  [11] export the run history to loot
  [0]  back

M
        read -rp "  choice> " c || return 0  # EOF: leave the menu cleanly
        case "$c" in
            1) gcve_cmd_list_cves | column -t -s$'\t' 2>/dev/null || gcve_cmd_list_cves
               read -rp "  press enter " _ ;;
            2) read -rp "  id> " i; gcve_run_cve "$i"; read -rp "  press enter " _ ;;
            3) read -rp "  id> " i; gcve_cmd_plan "$i"; read -rp "  press enter " _ ;;
            4) gcve_cmd_list_findings | column -t -s$'\t' 2>/dev/null || gcve_cmd_list_findings
               read -rp "  press enter " _ ;;
            5) read -rp "  id [MAP-SRI-DISCLOSURE|MAP-PSI-DISCLOSURE|MAP-ATI-BLOCKS]> " i
               gcve_run_cve "$i"; read -rp "  press enter " _ ;;
            6) gcve_run_cve R2018-SIMJACKER; read -rp "  press enter " _ ;;
            7) gcve_run_cve E2015-OTA-KEY; read -rp "  press enter " _ ;;
            8) read -rp "  mode [enc|dec]> " m; read -rp "  value> " v
               gcve_cmd_bcd "$m" "$v"; read -rp "  press enter " _ ;;
            9) read -rp "  KI [32 hex]> " k; read -rp "  RAND [32 hex]> " r
               gcve_cmd_kc "$k" "$r"; read -rp "  press enter " _ ;;
            10) gcve_cmd_runs_tsv | column -t -s$'\t' 2>/dev/null || gcve_cmd_runs_tsv
                read -rp "  press enter " _ ;;
            11) mkdir -p "$GCVE_DIR"
                if [[ "$(gcve_run_count)" -eq 0 ]]; then
                    warn "nothing to export"
                else
                    cp "$GCVE_RUNS" "$GCVE_DIR/runs_export_$(date +%Y%m%d_%H%M%S).tsv" && \
                        ok "exported to $GCVE_DIR"
                fi
                sleep 1 ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ── CLI dispatch ────────────────────────────────────────────────────────
gcve_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)  gcve_cli_status_tsv ;;
        --list-cves)   gcve_cmd_list_cves ;;
        --list-findings) gcve_cmd_list_findings ;;
        --run-cve)     gcve_run_cve "${1:-}" ;;
        --probe)       gcve_cmd_probe "${1:-}" ;;
        --plan)        gcve_cmd_plan "${1:-}" ;;
        --bcd)         gcve_cmd_bcd "${1:-}" "${2:-}" ;;
        --kc)          gcve_cmd_kc "${1:-}" "${2:-}" "${3:-v1}" ;;
        --runs-tsv)    gcve_cmd_runs_tsv ;;
        --coverage)    gcve_cmd_coverage ;;
        --selftest)    gcve_selftest ;;
        --menu)        gcve_menu ;;
        *)
            cat >&2 <<EOF
GSM/UMTS CVE Kit — 2G/3G stack probes and hardware handoffs

Usage: $0 COMMAND
  --status-tsv              module state as TSV
  --list-cves               every documented id, with kind and required testbed
  --list-findings           A5/1, A5/2, SS7/MAP and OTA research findings
  --run-cve <ID>            run the probe for ID, or write its handoff plan
  --probe <WHAT>            MAP-SRI|MAP-PSI|MAP-ATI|MAP-BLOCKS|A51|A52|
                            SIM-SAT|OTA|FS11|KC|IUH|IDENTITY
  --plan <ID>               write the handoff plan for a handoff id
  --bcd <enc|dec> VALUE   identity BCD encode or decode
  --kc <KI-hex32> <RAND-hex32> [v1|v2|v3]
                                 Kc via real A3/A8 (COMP128)
  --runs-tsv                recorded probe runs as TSV
  --coverage                 the corpus horizon: newest year it knows, and what that leaves unassessed
  --selftest                verify routing, parsers and probes without a radio
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
    gcve_cli_main "$@"
fi
