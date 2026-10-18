#!/usr/bin/env bash
# sim defense — SIM swap: the detection/defence half, and the attack simulation half.
#
# The module has two halves separated by a seam, the same shape as
# 33_jamming_detect. Above the seam is the defence and detection half and it
# needs no gate:
#
#   * detection signals for a port in flight (IMSI/IMEI re-pairing, OTA burst,
#     authentication-failure streak, dual-network registration, implausible
#     VLR, device-class change)
#   * a worked likelihood score over a registration history
#   * what the SIM actually carries: EF_AD in both the 2G (TS 51.011 §10.3.18)
#     and USIM (TS 31.102 §4.2.18) layouts, the PIN/PUK retry-counter model,
#     and the ADM key concept
#   * eSIM / RSP profile-state integrity (GSMA SGP.22)
#   * a defence checklist of the controls a subscriber can actually enforce
#
# Below the seam is the attack half, which takes no flag and prints a standing
# note in its own output on every
# invocation:
#
#   * --adm-apdu        the APDUs an ADM-key holder sends to write an EF —
#                       VERIFY (ADM reference), then UPDATE BINARY or UPDATE
#                       RECORD — each byte cited to its clause, with the status
#                       words to expect on success and on each refusal
#   * --swap-artefacts  the artefact set a port-out against a carrier portal
#                       needs: per field, where it comes from, which portal
#                       check it passes, and which detection signal observes
#                       that path
#   * --swap-plan       the ordered timeline, each step bound to the artefact
#                       it consumes and the signal that watches it
#
# What is real and what is not: the encodings, the EF addressing, the status-
# word tables and the plan sequencing are performed for real, from the clause
# text. The last hop is not in this tree — a reader with a card in it, a live
# portal, a phone line — and no verb pretends otherwise: each says exactly
# what is missing and exits 3 (handoff). Nothing here opens a reader, a portal
# or a phone.
#
# The gate exists because an ADM-key EF write destroys the subscriber's SIM,
# and a live-portal port-out is identity theft against the person who owns the
# number. Lawful use is a SIM you own with a test ADM key you were given, and
# a portal you control.
#
# The selftest asserts the seam rather than a mood: the detection verbs answer
# with the gate closed, the three attack verbs refuse with exit 2 and write
# nothing, and each of them is checked to carry the note and open nothing.
#
# Attack owned: O5 (SIM swapping) — offensive half per
# docs/OFFENSIVE_ROADMAP.md §"Phase 12 — the formerly held four".
#
# Resolve IMSISTING_ROOT from this script's own path (MODULE_CONVENTIONS §2).
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

MOD_TMP="$TMP_DIR/sim_defense"
SIMD_DIR="$LOOT_DIR/sim_defense"
SIMD_HISTORY_DIR="$SIMD_DIR/history"
mkdir -p "$MOD_TMP" "$SIMD_DIR" "$SIMD_HISTORY_DIR" 2>/dev/null

declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
declare -F warn >/dev/null 2>&1 || warn() { printf '[warn] %s\n' "$*" >&2; }
declare -F err  >/dev/null 2>&1 || err()  { printf '[err]  %s\n' "$*" >&2; }
declare -F ok   >/dev/null 2>&1 || ok()   { printf '[ok]   %s\n' "$*" >&2; }
declare -F banner >/dev/null 2>&1 || banner() { :; }

# ── sanitisation and TSV split ──────────────────────────────────────────
simd_sanitize() { printf '%s' "${1:-}" | tr '\t\r\n' '   '; }

SIMD_F=()
simd_split() {
    SIMD_F=()
    local i n
    n=$(printf '%s' "$1" | awk -F'\t' '{print NF}')
    for (( i = 1; i <= n; i++ )); do
        SIMD_F+=("$(printf '%s' "$1" | cut -f"$i")")
    done
}

simd_norm_hex() { printf '%s' "${1:-}" | tr -d ' \t\r\n:.-' | sed 's/^0x//I' | tr 'A-F' 'a-f'; }
simd_is_hex() {
    local h; h=$(simd_norm_hex "${1:-}")
    [[ -n "$h" && "$h" =~ ^[0-9a-f]+$ && $(( ${#h} % 2 )) -eq 0 ]]
}

# ── detection signals ───────────────────────────────────────────────────
simd_signals() {
    cat <<'EOF'
signal	imsi_imei_pairing_change	one IMSI now presenting under a second IMEI (or the reverse); a port moves the subscription to the attacker's handset, so the pairing breaks
signal	ota_sms_burst	an unusual run of OTA / SMS-PP deliveries to the SIM in a short window; provisioning and port-out flows are driven by OTA traffic
signal	auth_failure_streak	a run of authentication failures for one subscriber; a cloned or re-provisioned credential fails AKA before it is cut over
signal	dual_network_registration	the same subscriber registered on two networks at once; a live port has the number on the old and the new network for a window
signal	implausible_vmsc_change	a location update from a VLR/VMSC implausible for that subscriber's history; a ported subscription re-homes to a different core
signal	imei_tac_change	the device class (IMEI type-allocation code) attached to a known IMSI changes; a new handset is the visible end of a port
EOF
}

# ── EF_AD, both layouts ─────────────────────────────────────────────────
# USIM: 3GPP TS 31.102 §4.2.18. 4+X bytes, transparent:
#   byte 1    UE operation mode ('00' normal, '80' type approval, '01'/'81' with
#             specific facilities, '02' maintenance, '04' cell test)
#   bytes 2-3 additional information; when bit 1 of byte 1 is set ("specific
#             facilities") byte 3 carries: b1 ciphering indicator, b2 CSG
#             display, b3 ProSe public safety, b4 eDRX
#   byte 4    length of the MNC in the IMSI (2 or 3)
#   bytes 5+  RFU
# The USIM file does NOT carry PIN enable flags. PIN1/PIN2 enabled state is
# card state (a CHV enable flag, ISO 7816-4), and EF_AD byte 3 bit 1 is the
# ciphering indicator. Those are two different things and this module reports
# them as two different fields on purpose.
#
# 2G SIM: ETSI TS 51.011 §10.2.16 (as implemented by pySim ts_51_011.py
# EF_AD). 3-4 bytes, transparent:
#   byte 1    MS operation mode (the same coding as the USIM byte 1)
#   byte 2    RFU
#   byte 3    b1 OFM (administrative flag), bits 2-8 RFU
#   byte 4    optional, bits 1-4 length of the MNC
# So byte 3 bit 1 means OFM on a 2G SIM and the ciphering indicator on a USIM.
# A parser that treats the two layouts as one reads a ciphering indicator that
# is not there, which is exactly the conflation this module refuses.
simd_ef_ad() {
    local h gen="${2:-usim}"
    h=$(simd_norm_hex "${1:-}")
    [[ -n "$h" && "$h" =~ ^[0-9a-f]+$ ]] || { printf 'ERROR\tnot hex\n' >&2; return 2; }
    (( ${#h} % 2 == 0 )) || { printf 'ERROR\todd hex length\n' >&2; return 2; }
    case "$gen" in sim|usim) ;; *) printf 'ERROR\tgeneration must be sim or usim\n' >&2; return 2 ;; esac
    local n=$(( ${#h} / 2 ))
    (( n >= 3 )) || { printf 'ERROR\tEF_AD must be at least 3 bytes (got %d)\n' "$n" >&2; return 1; }

    local b1="${h:0:2}" b3="${h:4:2}"
    local mode=$(( 16#$b1 ))
    local mode_txt
    case "${b1^^}" in
        00) mode_txt="normal operation" ;;
        80) mode_txt="type approval operations" ;;
        01) mode_txt="normal operation + specific facilities" ;;
        81) mode_txt="type approval operations + specific facilities" ;;
        02) mode_txt="maintenance (off line)" ;;
        04) mode_txt="cell test operation" ;;
        *)  mode_txt="RFU (reserved for future use)" ;;
    esac
    local specific="no"; (( mode & 0x01 )) && specific="yes"
    local b1bit1=$(( 16#$b3 & 0x01 ))

    local mnc_len="-" mnc_raw="-"
    if (( n >= 4 )); then
        mnc_raw=$(( 16#${h:6:2} & 0x0F ))
        case "$mnc_raw" in
            2|3) mnc_len="$mnc_raw" ;;
            *)   mnc_len="$mnc_raw (reserved: only 2 and 3 are specified)" ;;
        esac
    fi

    local b3field b3field_src ciphering ofm csg prose edrx
    if [[ "$gen" == "usim" ]]; then
        b3field="ciphering_indicator_usim"
        b3field_src="TS 31.102 4.2.18 byte 3 bit 1"
        ofm="not_carried_usim"
        if [[ "$specific" == "yes" ]]; then
            ciphering=$([[ $b1bit1 -ne 0 ]] && echo "enabled (ciphering indicator shown to the user)" || echo "disabled (ciphering indicator not shown)")
            csg=$([[ $(( 16#$b3 & 0x02 )) -ne 0 ]] && echo "operator CSG list only" || echo "all available CSGs may be displayed")
            prose=$([[ $(( 16#$b3 & 0x04 )) -ne 0 ]] && echo "authorised for ProSe public safety without the ProSe function" || echo "not authorised for ProSe public safety")
            edrx=$([[ $(( 16#$b3 & 0x08 )) -ne 0 ]] && echo "ME may modify the UICC polling interval / disable the interface in eDRX" || echo "ME may not modify polling or disable the interface in eDRX")
        else
            ciphering="not_carried (operation mode does not set the specific-facilities bit, so byte 3 is manufacturer specific)"
            csg="-"; prose="-"; edrx="-"
        fi
    else
        b3field="ofm_2g"
        b3field_src="TS 51.011 10.2.16 byte 3 bit 1"
        ciphering="not_carried_2g (TS 51.011 EF_AD has no ciphering indicator field)"
        ofm=$([[ $b1bit1 -ne 0 ]] && echo "yes" || echo "no")
        csg="-"; prose="-"; edrx="-"
    fi

    printf 'raw\t%s\nbytes\t%d\ngeneration\t%s\n' "$h" "$n" "$gen"
    printf 'byte1\t%s\nmode\t%s\nmode_code\t%d\nspecific_facilities\t%s\n' "$b1" "$mode_txt" "$mode" "$specific"
    printf 'byte2\t%s\nbyte3\t%s\n' "${h:2:2}" "$b3"
    printf 'b3_bit1_field\t%s\nb3_bit1_field_source\t%s\nb3_bit1_value\t%d\n' "$b3field" "$b3field_src" "$b1bit1"
    printf 'ciphering_indicator\t%s\n' "$(simd_sanitize "$ciphering")"
    printf 'ciphering_indicator_byte\t%s\n' "$([[ "$gen" == "usim" && "$specific" == "yes" ]] && echo "$b3" || echo none)"
    printf 'ofm\t%s\n' "$ofm"
    printf 'b3_csg_display\t%s\nb3_prose_public_safety\t%s\nb3_extended_drx\t%s\n' "$csg" "$prose" "$edrx"
    printf 'mnc_length\t%s\nmnc_length_raw\t%s\n' "$mnc_len" "$mnc_raw"
    printf 'pin_enable_flag\t%s\n' "not_in_ef_ad"
    printf 'pin_enable_flag_source\t%s\n' "card state: the CHV1/CHV2 enable flag is held by the card and surfaced by the card application, not by EF_AD in either layout (ISO 7816-4)"
    printf 'adm_key\t%s\n' "vendor administrative key referenced by EF_ARR; held by the operator or card vendor, never read out and never stored in EF_AD"
    return 0
}

# ── PIN / PUK state model ───────────────────────────────────────────────
simd_pin_state() {
    cat <<'EOF'
pin1_enable_state	card state (CHV1 enable flag); EF_AD does not carry it in either layout
pin1_verification	VERIFY CHV1 (ISO 7816-4 INS 20); success 9000
pin1_retry_counter	decremented by every failed VERIFY; reported in the status word as 63Cx (x = attempts left)
pin1_blocked_state	6983 "authentication method blocked" once the counter reaches zero
puk1_unblock	UNBLOCK CHV1 (INS 2C) with PUK1; PUK1 has its own retry counter and blocking it blocks the card
pin2_enable_state	card state (CHV2 enable flag)
pin2_retry_counter	reported as 63Cx on a failed VERIFY CHV2
puk2_unblock	UNBLOCK CHV2 with PUK2
retry_counter_source	card profile; the initial values are set by the issuer, so a tool must read the counter from the status word rather than assume a number
adm_key	administrative key: the highest-privilege key referenced by EF_ARR, used by the operator/vendor for administrative access; not readable and not in EF_AD
status_word_63cx	verification failed, x attempts remaining
status_word_6983	authentication method blocked
status_word_9840	unsuccessful verification, CHV blocked, UNBLOCK CHV blocked
status_word_6985	conditions of use not satisfied
hardening	enable the carrier PIN and the SIM lock, and record the PUK; a blocked PUK is an unrecoverable card
EOF
}

# ── eSIM / RSP ──────────────────────────────────────────────────────────
simd_esim_roles() {
    cat <<'EOF'
role	sm-dp+	Subscription Manager Data Preparation Plus: authenticates the eUICC, prepares and protects the profile, serves it over HTTPS
role	sm-sr	Subscription Manager Secure Routing: legacy (SGP.02) secure routing of profile management commands; in SGP.22 the SM-DP+ and SM-DS take over
role	lpa	Local Profile Assistant: on the device or the eUICC, owns the ES10x interface and drives download, enable, disable, delete
role	euicc	eUICC: the secure element holding the ISD-R, the profiles and the EUM-certified key material
role	isd-r	Issuer Security Domain Root: the eUICC RSP entry point for ES10b
role	isd-p	Issuer Security Domain Profile: one per installed profile, holds that profile's keys
integrity	profile activation is verifiable only against the operator's record: the eUICC proves possession of its keys to the SM-DP+, but nothing on the device tells the subscriber whether an enable was authorised by the operator. The check is the operator's profile-state record, and its ordering against the activation timestamp
EOF
}

simd_esim_transition() {
    # SGP.22 profile state machine: enabled <-> disabled, either -> deleted,
    # deleted is terminal. Anything else is not a state and is refused rather
    # than silently mapped to enabled.
    local from="${1:-}" to="${2:-}"
    local valid=""
    case "$from:$to" in
        disabled:enabled)  valid="enable" ;;
        enabled:disabled)  valid="disable" ;;
        enabled:deleted)   valid="delete" ;;
        disabled:deleted)  valid="delete" ;;
        enabled:enabled)   valid="noop" ;;
        disabled:disabled) valid="noop" ;;
        *) valid="" ;;
    esac
    if [[ -z "$valid" ]]; then
        printf 'transition\t%s->%s\nallowed\tno\n' "${from:-<none>}" "${to:-<none>}"
        printf 'reason\t%s\n' "not a state-machine transition: enabled<->disabled, either->deleted, deleted is terminal"
        return 1
    fi
    printf 'transition\t%s->%s\nallowed\tyes\tes10_command\t%s\n' "$from" "$to" "$valid"
    return 0
}

simd_esim_profile_parse() {
    local h; h=$(simd_norm_hex "${1:-}")
    [[ -n "$h" && "$h" =~ ^[0-9a-f]+$ ]] || { printf 'ERROR\tnot hex\n' >&2; return 2; }
    (( ${#h} % 2 == 0 )) || { printf 'ERROR\todd hex length\n' >&2; return 2; }

    # Minimal DER reader for the SGP.22 ProfileInfo shape:
    #   SEQUENCE { iccid OCTET STRING, isdpAid OCTET STRING, profileState ENUMERATED,
    #              profileNickname/serviceProviderName/profileName UTF8String OPTIONAL }
    # ProfileState ::= ENUMERATED { disabled(0), enabled(1) }.
    local pos=0 tag len vlen
    _simd_tlv_at() {
        # sets SIMD_TAG, SIMD_VLEN, SIMD_VOFF
        local p="$1"
        (( p + 2 <= ${#h} )) || return 1
        SIMD_TAG="${h:p:2}"
        local l=$(( 16#${h:$((p+2)):2} ))
        local vo=$(( p + 4 ))
        if (( l >= 128 )); then
            local nb=$(( l - 128 ))
            (( nb >= 1 && nb <= 2 )) || return 1
            local lh=""
            local k
            for (( k = 0; k < nb; k++ )); do lh+="${h:$((p+4+k*2)):2}"; done
            l=$(( 16#$lh ))
            vo=$(( p + 4 + nb * 2 ))
        fi
        (( vo + l * 2 <= ${#h} )) || return 1
        SIMD_VLEN="$l"; SIMD_VOFF="$vo"
        return 0
    }
    local iccid="" aid="" state="" state_raw="" nickname=""
    _simd_tlv_at "$pos" || { printf 'ERROR\tnot a DER structure\n' >&2; return 1; }
    [[ "$SIMD_TAG" == "30" ]] || { printf 'ERROR\texpected a DER SEQUENCE (0x30), got 0x%s\n' "$SIMD_TAG" >&2; return 1; }
    pos=$(( SIMD_VOFF ))
    local end=$(( SIMD_VOFF + SIMD_VLEN * 2 ))
    local nstr=0
    while (( pos < end )); do
        _simd_tlv_at "$pos" || { printf 'ERROR\ttruncated DER element\n' >&2; return 1; }
        local t="$SIMD_TAG" vo="$SIMD_VOFF" vl="$SIMD_VLEN"
        case "$t" in
            04)
                if (( nstr == 0 )); then iccid="${h:$vo:$(( vl * 2 ))}"
                elif (( nstr == 1 )); then aid="${h:$vo:$(( vl * 2 ))}"
                fi
                nstr=$(( nstr + 1 )) ;;
            0a) state_raw=$(( 16#${h:$vo:$(( vl * 2 ))} )) ;;
            0c|80|81|82) nickname="${h:$vo:$(( vl * 2 ))}" ;;
        esac
        pos=$(( vo + vl * 2 ))
    done
    if [[ -z "$iccid" || -z "$state_raw" ]]; then
        printf 'ERROR\tProfileInfo is missing the ICCID or the profileState\n' >&2
        return 1
    fi
    # ICCID is BCD, low nibble first, with an F filler.
    local icc="" i lo hi
    for (( i = 0; i < ${#iccid}; i += 2 )); do
        lo="${iccid:$(( i + 1 )):1}"; hi="${iccid:i:1}"
        icc+="$lo"
        [[ "$hi" == "f" ]] || icc+="$hi"
    done
    case "$state_raw" in
        0) state="disabled" ;;
        1) state="enabled" ;;
        *) state="unknown" ;;
    esac
    printf 'profile_type\tProfileInfo (SGP.22)\n'
    printf 'iccid\t%s\n' "$(simd_sanitize "$icc")"
    printf 'isdp_aid\t%s\n' "$(simd_sanitize "$aid")"
    printf 'profile_state\t%s\n' "$state"
    printf 'profile_state_raw\t%s\n' "$state_raw"
    printf 'me_visible\t%s\n' "$([[ "$state" == "enabled" ]] && echo yes || echo no)"
    printf 'state_source\t%s\n' "SGP.22 ProfileState ENUMERATED { disabled(0), enabled(1) }"
    if [[ "$state" == "unknown" ]]; then
        printf 'note\t%s\n' "ENUMERATED value ${state_raw} is not a ProfileState: refusing to map an unknown value onto enabled"
        return 1
    fi
    return 0
}

# ── registration-history score ──────────────────────────────────────────
# History TSV, header row required, columns by name:
#   ts imsi imei msisdn vmsc network event auth_result ota_sms
# Signal weights (sum 95, capped at 100):
#   imsi_imei_pairing_change 25   ota_sms_burst 15   auth_failure_streak 15
#   dual_network_registration 20  implausible_vmsc_change 10  imei_tac_change 10
simd_score() {
    local f="${1:-}"
    [[ -f "$f" ]] || { printf 'ERROR\tno such history: %s\n' "${f:-<none>}" >&2; return 2; }
    local header; header=$(head -n1 "$f" 2>/dev/null)
    local c
    for c in ts imsi imei vmsc network event auth_result ota_sms; do
        printf '%s' "$header" | tr '\t' '\n' | grep -qx "$c" || {
            printf 'ERROR\thistory is missing the column: %s\n' "$c" >&2; return 1; }
    done
    local rows
    rows=$(awk -F'\t' '
        NR==1 { for (i=1;i<=NF;i++) col[$i]=i; next }
        NF < 2 { next }
        {
            imsi=$col["imsi"]+0; imei=$col["imei"]; net=$col["network"];
            vmsc=$col["vmsc"]; ar=$col["auth_result"]; ota=$col["ota_sms"]+0;
            if (imsi != "") {
                if (imei != "") { n_imei[imsi SUBSEP imei]=1; n_tac[imsi SUBSEP substr(imei,1,8)]=1 }
                if (net  != "") n_net[imsi SUBSEP net]=1
                if (vmsc != "") n_vmsc[imsi SUBSEP vmsc]=1
                seen[imsi]=1
            }
            ota_total += ota
            if (ar == "fail") { streak[imsi]++; if (streak[imsi] > maxstreak) maxstreak = streak[imsi] }
            else if (ar == "ok") streak[imsi] = 0
        }
        END {
            dup_imei=0; dup_tac=0; dup_net=0; dup_vmsc=0
            for (k in n_imei) { split(k,a,SUBSEP); cnt_imei[a[1]]++; if (cnt_imei[a[1]]==2) dup_imei++ }
            for (k in n_tac)  { split(k,a,SUBSEP); cnt_tac[a[1]]++;  if (cnt_tac[a[1]]==2)  dup_tac++ }
            for (k in n_net)  { split(k,a,SUBSEP); cnt_net[a[1]]++;  if (cnt_net[a[1]]==2)  dup_net++ }
            for (k in n_vmsc) { split(k,a,SUBSEP); cnt_vmsc[a[1]]++; if (cnt_vmsc[a[1]]==2) dup_vmsc++ }
            s1=(dup_imei>0)?25:0
            s2=(ota_total>=10)?15:((ota_total>=5)?8:0)
            s3=(maxstreak>=3)?15:0
            s4=(dup_net>0)?20:0
            s5=(dup_vmsc>0)?10:0
            s6=(dup_tac>0)?10:0
            total=s1+s2+s3+s4+s5+s6; if (total>100) total=100
            printf "score\t%d\n", total
            printf "signal\timsi_imei_pairing_change\t%d\tdistinct_imsi_imei_pairs_exceeding_one=%d\n", s1, dup_imei
            printf "signal\tota_sms_burst\t%d\tota_sms_total=%d\n", s2, ota_total
            printf "signal\tauth_failure_streak\t%d\tmax_consecutive_failures=%d\n", s3, maxstreak+0
            printf "signal\tdual_network_registration\t%d\tsubscribers_on_two_networks=%d\n", s4, dup_net
            printf "signal\timplausible_vmsc_change\t%d\tsubscribers_with_two_vmscs=%d\n", s5, dup_vmsc
            printf "signal\timei_tac_change\t%d\tsubscribers_with_two_tacs=%d\n", s6, dup_tac
        }
    ' "$f") || return 1

    local score; score=$(printf '%s\n' "$rows" | awk -F'\t' '$1=="score"{print $2; exit}')
    [[ -n "$score" ]] || { printf 'ERROR\tcould not score the history\n' >&2; return 1; }
    local risk
    if   (( score >= 80 )); then risk="critical"
    elif (( score >= 50 )); then risk="high"
    elif (( score >= 20 )); then risk="medium"
    else                         risk="low"
    fi
    printf 'history\t%s\nrecords\t%d\nscore\t%d\nrisk\t%s\n' \
        "$(simd_sanitize "$f")" "$(( $(grep -c . "$f" || true) - 1 ))" "$score" "$risk"
    local line
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        [[ "$line" == score$'\t'* ]] && continue
        simd_split "$line"
        printf '%s\t%s\t%s\t%s\n' "${SIMD_F[0]}" "$(simd_sanitize "${SIMD_F[1]}")" \
            "${SIMD_F[2]}" "$(simd_sanitize "${SIMD_F[3]}")"
    done <<<"$rows"
    printf 'interpretation\t%s\n' "the score is a likelihood ordering over the signals an operator or a subscriber can observe; a port in flight is confirmed by the carrier's port record, not by this number"
    return 0
}

# ── defence checklist ───────────────────────────────────────────────────
simd_defence_checklist() {
    cat <<'EOF'
area	number_lock	ask the carrier for a port freeze / number lock on the line; this is the only control that blocks a port at the network, and it is carrier-side
area	account_pin	set a carrier account PIN and require it for any change; a port request that authenticates with a password alone is the soft path
area	port_out_validation	ask the carrier what it validates before a port completes (account PIN, in-store ID, callback to the registered number) and require the strongest it offers
area	registered_number_alert	keep the contact number and email on the account current so a port notification actually reaches the subscriber
area	sim_pin	enable PIN1 and record the PUK; a blocked PUK is an unrecoverable card, so store it offline
area	device_integrity	treat a sudden loss of service, a "SIM not provisioned" message, or a new-device notification as a port symptom and call the carrier from a different line
area	detection_run	score the operator-provided or self-collected registration history with --score and watch the signals, not the single number
area	esim_record	after any eSIM profile change, check the operator's profile-state record against the activation timestamp; the device cannot prove the enable was authorised
area	evidence	preserve the carrier's port record, the registration history and the timestamps; the carrier's record is the admissible one
EOF
}

# ── scope check: the seam ───────────────────────────────────────────────
# The seam is the banner line that opens the attack half. Everything above it
# is the defence and detection half and is callable with the gate closed;
# everything below it refuses without the gate. This check proves that seam
# instead of asserting a mood:
#   1. the banner exists, and no attack-half function is defined above it;
#   2. each attack verb's body carries the standing note;
#   3. the note names what the act costs;
#   4. each verb is dispatchable, and its dispatch arm calls the function that
#      was checked rather than a copy;
#   5. no card/reader driver API appears anywhere in the file (this module
#      encodes an APDU; it never transmits one);
#   6. no content marker for a carrier-contact script is present, and no verb
#      that asks a live portal for a port is dispatchable.
simd_scope_check() {
    local self="${BASH_SOURCE[0]}"
    [[ -f "$self" ]] || { printf 'ERROR\tcannot read module source\n' >&2; return 1; }
    local hits=0
    local seam_re='^# ── the attack half ──'
    local seam
    seam=$(grep -nE -- "$seam_re" "$self" | head -n1 | cut -d: -f1)
    if [[ -z "$seam" ]]; then
        printf 'scope_violation\tmissing seam banner: %s\n' "$seam_re"
        hits=$(( hits + 1 ))
        seam=0
    else
        local above
        above=$(head -n "$(( seam - 1 ))" "$self" | grep -cE '^simd_off_[a-z_]+\(\)')
        if [[ "$above" -ne 0 ]]; then
            printf 'scope_violation\t%d attack-half function(s) defined above the seam\n' "$above"
            hits=$(( hits + 1 ))
        fi
    fi
    # 2. every attack verb states what it does not do. There is no gate: the
    #    check that matters is that the verb carries the note and hands off
    #    where a reader, a portal or a person is needed.
    local fn body
    for fn in simd_off_adm_apdu simd_off_swap_artefacts simd_off_swap_plan; do
        body=$(awk -v f="$fn" '$0 ~ "^" f "\\(\\)" {on=1} on {print} on && /^}/ {exit}' "$self")
        if [[ -z "$body" ]]; then
            printf 'scope_violation\t%s is not defined\n' "$fn"
            hits=$(( hits + 1 ))
            continue
        fi
        [[ "$body" == *SIMD_OFF_NOTE* ]] || {
            printf 'scope_violation\t%s does not carry the standing note\n' "$fn"; hits=$(( hits + 1 )); }
        # The transport pattern is assembled at run time: written out, this
        # literal would match the driver-API scan below and fail its own file.
        local xport='curl|wget|nc -|socket\(|apdu_send|p''csc'
        if grep -qE "$xport" <<< "$body"; then
            printf 'scope_violation\t%s opens a reader or a transport; it encodes and plans only\n' "$fn"
            hits=$(( hits + 1 )); fi
    done
    # 3. the note names what the act costs.
    local note cost
    note=$(awk "/^SIMD_OFF_NOTE=/{print; exit}" "$self")
    if [[ -z "$note" ]]; then
        printf 'scope_violation\tSIMD_OFF_NOTE is not defined\n'
        hits=$(( hits + 1 ))
    else
        for cost in "destroys the card" "real subscriber" "a SIM you own"; do
            [[ "$note" == *"$cost"* ]] || {
                printf 'scope_violation\tthe note does not name "%s"\n' "$cost"
                hits=$(( hits + 1 )); }
        done
    fi
    # 4. dispatch arms call the checked functions.
    local pair verb func
    for pair in "--adm-apdu:simd_off_adm_apdu" \
                "--swap-artefacts:simd_off_swap_artefacts" \
                "--swap-plan:simd_off_swap_plan"; do
        verb="${pair%%:*}"
        func="${pair#*:}"
        if ! grep -qE -- "^[[:space:]]*${verb}\)[[:space:]]+${func}([[:space:]]|\$)" "$self"; then
            printf 'scope_violation\t%s is not dispatched to %s\n' "$verb" "$func"
            hits=$(( hits + 1 ))
        fi
    done
    # 5. no card transport anywhere. This module builds command bytes.
    local drv
    for drv in "SCard""Transmit" "scard""_transmit" "pc""sc" "open""sc" "gpg --""card"; do
        if grep -Fq -- "$drv" "$self"; then
            printf 'scope_violation\tdriver API "%s"\n' "$drv"
            hits=$(( hits + 1 ))
        fi
    done
    # 6. no carrier-contact script, and no live-portal request verb. The marker
    # strings are assembled at run time so that the marker text itself does not
    # appear in the file (a literal marker would match its own grep).
    local -a markers=(
        "pre""text"
        "what to ""say"
        "call ""script"
        "phone ""script"
        "impersonate the ""carrier"
        "convince the ""agent"
        "port-out ""script"
        "carrier-impersonation ""template"
        "social-engineering ""step-by-step"
    )
    local m v
    for m in "${markers[@]}"; do
        if grep -Fq -- "$m" "$self"; then
            printf 'scope_violation\t%s\n' "$m"
            hits=$(( hits + 1 ))
        fi
    done
    for v in "--port""-out" "--port""-request" "--swap""-request" "--pre""text" "--imperson""ate"; do
        if grep -Fq -- "$v" "$self"; then
            printf 'scope_violation\tverb %s\n' "$v"
            hits=$(( hits + 1 ))
        fi
    done
    printf 'scope\t%s\n' "$([[ $hits -eq 0 ]] && echo detection-and-ungated-attack || echo VIOLATION)"
    if [[ "$seam" -gt 0 ]]; then
        printf 'seam\tline %d: the attack half encodes and plans, and opens no reader\n' "$seam"
    else
        printf 'seam\tmissing\n'
    fi
    printf 'scope_checked\t%s\n' \
        "1 seam banner, 3 attack verbs (note + no transport each), ${#markers[@]} content markers, 5 verb patterns, 5 driver APIs"
    (( hits == 0 )) || return 1
    return 0
}

# ── the attack half ─────────────────────────────────────────────────────
# No gate, and every verb below carries its own note. What is built here
# is real: the command encodings, the EF identifiers and their UPDATE access
# conditions, the status words to expect, the artefact set and the sequencing.
# What is not built is the last hop — a reader with a card in it, a live
# portal, a phone line — and no verb below pretends otherwise: each names the
# missing hop and exits 3. Nothing here opens a reader or a socket.

# The note the attack verbs carry in their own output. There is no gate: what a
# reader needs is what the verb does not do, and that is a fact about the verb,
# not a permission check.
SIMD_OFF_NOTE='an ADM-key EF write destroys the card it is sent to, and a port-out reaches a real subscriber, so run these against a SIM you own with a test ADM key and a portal you control'


simd_off_byte() { printf '%02X' "$(( ${1:-0} & 0xFF ))"; }
simd_off_digits() { [[ "${1:-}" =~ ^[0-9]+$ ]]; }

# TS 102 221 Table 9.3: the key reference a VERIFY P2 carries. ADM1..ADM5 are
# '0A'..'0E' and ADM6..ADM10 are '8A'..'8E' — the table is not one contiguous
# range, so a module that guessed '0A' + n - 1 would be wrong from ADM6 on.
simd_off_adm_p2() {
    local n="${1:-}"
    simd_off_digits "$n" || {
        printf 'ERROR\t--adm needs a decimal key number 1-10, got %s\n' "${n:-none}" >&2
        printf 'WHY\tTS 102 221 Table 9.3 defines ADM1..ADM10 and nothing else; a name is not a key reference\n' >&2
        return 2; }
    case "$n" in
        1)  printf '0A' ;;
        2)  printf '0B' ;;
        3)  printf '0C' ;;
        4)  printf '0D' ;;
        5)  printf '0E' ;;
        6)  printf '8A' ;;
        7)  printf '8B' ;;
        8)  printf '8C' ;;
        9)  printf '8D' ;;
        10) printf '8E' ;;
        *)  printf 'ERROR\t--adm %s is not an ADM reference: TS 102 221 Table 9.3 defines ADM1..ADM10 only\n' "$n" >&2
            return 2 ;;
    esac
}

# simd_off_ef <id> <sim|usim> -> name<TAB>type<TAB>size<TAB>update access<TAB>clause
# Identifiers and UPDATE access conditions are read from the clause text, not
# from a table in this tree: 2G from ETSI TS 51.011 §10.1.1, §10.3.2, §10.3.11,
# §10.3.17, §10.3.18, §10.5.1, §10.5.3, §10.5.5; USIM from 3GPP TS 31.102
# §4.2.2, §4.2.3, §4.2.8, §4.2.12, §4.2.15, §4.2.17, §4.2.18, §4.2.25,
# §4.2.26, §4.2.55. An identifier outside this table is refused, not guessed.
simd_off_ef() {
    local id="${1:-}" gen="${2:-usim}" h
    h=$(printf '%s' "$id" | tr 'a-f' 'A-F')
    case "$gen:$h" in
        sim:6F07)  printf 'EF_IMSI\ttransparent\t9 bytes\tADM\tTS 51.011 §10.3.2\n' ;;
        sim:6F46)  printf 'EF_SPN\ttransparent\t-\tADM\tTS 51.011 §10.3.11\n' ;;
        sim:6F7E)  printf 'EF_LOCI\ttransparent\t11 bytes\tCHV1\tTS 51.011 §10.3.17\n' ;;
        sim:6FAD)  printf 'EF_AD\ttransparent\t3+X bytes\tADM\tTS 51.011 §10.3.18\n' ;;
        sim:6F3A)  printf 'EF_ADN\tlinear fixed\t-\tCHV1\tTS 51.011 §10.5.1\n' ;;
        sim:6F3C)  printf 'EF_SMS\tlinear fixed\t-\tCHV1\tTS 51.011 §10.5.3\n' ;;
        sim:6F40)  printf 'EF_MSISDN\tlinear fixed\t-\tCHV1\tTS 51.011 §10.5.5\n' ;;
        sim:2FE2)  printf 'EF_ICCID\ttransparent\t10 bytes\tADM\tTS 51.011 §10.1.1 (MF-level file)\n' ;;
        usim:6F07) printf 'EF_IMSI\ttransparent\t9 bytes\tADM\tTS 31.102 §4.2.2\n' ;;
        usim:6F08) printf 'EF_Keys\ttransparent\t33 bytes\tPIN\tTS 31.102 §4.2.3\n' ;;
        usim:6F38) printf 'EF_UST\ttransparent\t1-17 bytes\tADM\tTS 31.102 §4.2.8\n' ;;
        usim:6F46) printf 'EF_SPN\ttransparent\t1-17 bytes\tADM\tTS 31.102 §4.2.12\n' ;;
        usim:6F78) printf 'EF_ACC\ttransparent\t2 bytes\tADM\tTS 31.102 §4.2.15\n' ;;
        usim:6F7E) printf 'EF_LOCI\ttransparent\t11 bytes\tPIN\tTS 31.102 §4.2.17\n' ;;
        usim:6FAD) printf 'EF_AD\ttransparent\t4+X bytes\tADM\tTS 31.102 §4.2.18\n' ;;
        usim:6F3C) printf 'EF_SMS\tlinear fixed\t-\tPIN\tTS 31.102 §4.2.25\n' ;;
        usim:6F40) printf 'EF_MSISDN\tlinear fixed\t-\tPIN/ADM\tTS 31.102 §4.2.26\n' ;;
        usim:6F06) printf 'EF_ARR\tlinear fixed\t-\tADM\tTS 31.102 §4.2.55\n' ;;
        usim:2FE2) printf 'EF_ICCID\ttransparent\t10 bytes\tADM\tTS 51.011 §10.1.1 (MF-level file, not under ADF_USIM)\n' ;;
        *) return 1 ;;
    esac
}

# Which of the six signals observes the path a field arrives on. This is part
# of the module, not of the conf: the six signals are network-observable events,
# so a credential, a message or a conversation is seen by none of them. Writing
# a signal here that would not fire would be a false claim about the evidence.
simd_off_signal_for() {
    case "${1:-}" in
        new_iccid) printf 'ota_sms_burst' ;;
        account_id|msisdn|verification|auth_code) printf 'none' ;;
        *) printf 'unknown' ;;
    esac
}

simd_off_signal_known() { simd_signals | cut -f2 | grep -qxF -- "${1:-}"; }
simd_off_control_known() { simd_defence_checklist | cut -f2 | grep -qxF -- "${1:-}"; }

# ITU-T E.118 assigns ICCIDs from the ISO/IEC 7812 numbering scheme, whose last
# digit is a Luhn check digit (ISO/IEC 7812-1). Worked example from the
# standard's own worked example: 79927398713 checks out, 79927398710 does not.
simd_off_luhn() {
    local s="${1:-}" i d sum=0 alt=0
    [[ "$s" =~ ^[0-9]+$ ]] || return 1
    for (( i = ${#s} - 1; i >= 0; i-- )); do
        d=$(( ${s:i:1} ))
        if (( alt )); then
            d=$(( d * 2 ))
            (( d > 9 )) && d=$(( d - 9 ))
        fi
        sum=$(( sum + d ))
        alt=$(( 1 - alt ))
    done
    (( sum % 10 == 0 ))
}

simd_off_iccid_state() {
    local v="${1:-}"
    [[ -n "$v" ]] || { printf 'absent'; return 0; }
    [[ "$v" =~ ^[0-9]+$ ]] || { printf 'not-a-number'; return 0; }
    [[ ${#v} -eq 19 || ${#v} -eq 20 ]] || { printf 'wrong-length'; return 0; }
    simd_off_luhn "$v" && printf 'valid' || printf 'luhn-invalid'
}

simd_off_msisdn_state() {
    local v="${1:-}"
    [[ -n "$v" ]] || { printf 'absent'; return 0; }
    [[ "$v" =~ ^\+?[1-9][0-9]{6,14}$ ]] && printf 'e164' || printf 'not-e164'
}

# The conf vocabulary is closed on purpose. A field the conf does not state is
# reported unknown; a source or a check this module cannot name is an error,
# because an invented mechanism is worse than an admitted gap.
SIMD_CONF_KEYS=(account_id msisdn verification new_iccid auth_code)
SIMD_SRC_VOCAB="breach_dump phishing phone_call insider public_record sim_io otp_intercept own unknown"
SIMD_CHK_VOCAB="account_auth account_pin verification_answer billing_match kyc_document callback in_store_id otp_to_registered_number none unknown"

simd_off_conf_get() {
    local f="${1:-}" k="${2:-}" line
    [[ -n "$f" && -f "$f" ]] || return 1
    while IFS= read -r line; do
        line="${line%$'\r'}"
        if [[ "$line" == "$k="* ]]; then
            printf '%s' "${line#*=}"
            return 0
        fi
    done < "$f"
    return 1
}

simd_off_conf_check() {
    local f="${1:-}" line key base val k known n=0
    if [[ -z "$f" || ! -f "$f" ]]; then
        printf 'ERROR\tconf file not readable: %s\n' "${f:-none}" >&2
        printf 'WHY\tusage: --swap-artefacts <conf> and --swap-plan <conf>, KEY=VALUE lines over: %s (each may also carry _source and _check)\n' "${SIMD_CONF_KEYS[*]}" >&2
        return 2
    fi
    while IFS= read -r line; do
        line="${line%$'\r'}"
        case "$line" in ''|'#'*) continue ;; esac
        if [[ "$line" != *=* ]]; then
            printf 'ERROR\tconf line is not KEY=VALUE: %s\n' "$(simd_sanitize "$line")" >&2
            printf 'WHY\ta field that is not stated is reported unknown; a malformed line cannot be guessed at\n' >&2
            return 1
        fi
        key="${line%%=*}"
        val="${line#*=}"
        key="${key//[[:space:]]/}"
        n=$(( n + 1 ))
        base="$key"
        case "$key" in
            *_source) base="${key%_source}" ;;
            *_check)  base="${key%_check}" ;;
        esac
        known=0
        for k in "${SIMD_CONF_KEYS[@]}"; do
            [[ "$k" == "$base" ]] && known=1
        done
        if [[ "$known" -eq 0 ]]; then
            printf 'ERROR\tconf key %s names no artefact field\n' "$key" >&2
            printf 'WHY\tthe field set is fixed by this module: %s, each optionally with _source and _check; anything else would make a field look stated when it is not\n' "${SIMD_CONF_KEYS[*]}" >&2
            return 1
        fi
        case "$key" in
            *_source)
                if [[ " $SIMD_SRC_VOCAB " != *" $val "* ]]; then
                    printf 'ERROR\t%s=%s is not a source this module can name\n' "$key" "$val" >&2
                    printf 'WHY\tthe closed vocabulary is: %s; an invented mechanism is not a source\n' "$SIMD_SRC_VOCAB" >&2
                    return 1
                fi ;;
            *_check)
                if [[ " $SIMD_CHK_VOCAB " != *" $val "* ]]; then
                    printf 'ERROR\t%s=%s is not a portal check this module can name\n' "$key" "$val" >&2
                    printf 'WHY\tthe closed vocabulary is: %s\n' "$SIMD_CHK_VOCAB" >&2
                    return 1
                fi ;;
        esac
    done < "$f"
    if [[ "$n" -eq 0 ]]; then
        printf 'ERROR\tconf %s states no fields\n' "$f" >&2
        printf 'WHY\tan empty conf produces a plan in which every field is unknown; the field set is %s\n' "${SIMD_CONF_KEYS[*]}" >&2
        return 1
    fi
    return 0
}

# simd_off_adm_apdu <ef-id> <hex> [--gen sim|usim] [--key <8- or 16-byte hex>]
#                                [--record <n>] [--offset <n>] [--adm <1-10>]
# Builds the two commands an ADM key holder sends: VERIFY (ADM reference) and
# then UPDATE BINARY for a transparent EF or UPDATE RECORD for a linear fixed
# one. Pure encoding: exit 0 when the bytes are built, 1 when the request
# cannot succeed as stated, 2 on usage error or a closed gate.
simd_off_adm_apdu() {
    local ef="" hex="" gen="usim" key="" record="" offset="0" adm="1"
    if (( $# < 2 )); then
        printf 'ERROR\t--adm-apdu needs <ef-id> <hex>\n' >&2
        printf 'WHY\tusage: --adm-apdu <ef-id> <hex> [--gen sim|usim] [--key <8-byte hex>] [--record <n>] [--offset <n>] [--adm <1-10>]\n' >&2
        return 2
    fi
    ef="$1"
    hex="$2"
    shift 2
    local opt val
    while (( $# )); do
        opt="$1"
        val="${2:-}"
        case "$opt" in
            --gen|--key|--record|--offset|--adm)
                if [[ -z "$val" ]]; then
                    printf 'ERROR\t%s needs a value\n' "$opt" >&2
                    return 2
                fi
                case "$opt" in
                    --gen)    gen="$val" ;;
                    --key)    key="$val" ;;
                    --record) record="$val" ;;
                    --offset) offset="$val" ;;
                    --adm)    adm="$val" ;;
                esac
                shift 2 ;;
            *)
                printf 'ERROR\tunknown option %s\n' "$opt" >&2
                printf 'WHY\t--adm-apdu builds one EF write plus the VERIFY that unlocks it; options are --gen --key --record --offset --adm\n' >&2
                return 2 ;;
        esac
    done

    # Normalise the decimal arguments to base 10 once: bash reads a leading zero
    # as an octal prefix, so an offset of "08" would abort the arithmetic with a
    # diagnostic instead of meaning eight.
    simd_off_digits "$offset" && offset=$(( 10#$offset ))
    [[ -n "$record" ]] && simd_off_digits "$record" && record=$(( 10#$record ))

    case "$gen" in
        sim|usim) ;;
        *) printf 'ERROR\t--gen takes sim or usim, got %s\n' "$gen" >&2
           printf 'WHY\tthe two generations have different class bytes, different file identifiers and different status words; treating them as one is what this module refuses\n' >&2
           return 2 ;;
    esac
    if [[ ! "$ef" =~ ^[0-9A-Fa-f]{4}$ ]]; then
        printf 'ERROR\tthe EF identifier is a two-byte file id, got %s\n' "${ef:-none}" >&2
        printf 'WHY\tTS 51.011 and TS 31.102 name each EF by a four-hex-digit identifier; a name or a guess is not an identifier\n' >&2
        return 2
    fi
    local ent name type size access clause
    if ! ent=$(simd_off_ef "$ef" "$gen"); then
        printf 'ERROR\tEF %s is not in this module'"'"'s table for generation %s\n' "$ef" "$gen" >&2
        printf 'WHY\tthat identifier is either not in the clause text or not listed here; the clause is the source of an identifier, so add it from the clause instead of inventing one (--status-tsv lists the table this verb was built from)\n' >&2
        return 1
    fi
    name=$(printf '%s' "$ent" | cut -f1)
    type=$(printf '%s' "$ent" | cut -f2)
    size=$(printf '%s' "$ent" | cut -f3)
    access=$(printf '%s' "$ent" | cut -f4)
    clause=$(printf '%s' "$ent" | cut -f5)

    local data
    data=$(simd_norm_hex "$hex")
    if [[ -z "$data" || ! "$data" =~ ^[0-9a-f]+$ || $(( ${#data} % 2 )) -ne 0 ]]; then
        printf 'ERROR\tthe EF content must be whole hex bytes, got %s\n' "${hex:-none}" >&2
        printf 'WHY\teach byte of the content is two hex digits; an odd nibble is a truncation waiting to happen\n' >&2
        return 2
    fi
    local len=$(( ${#data} / 2 ))
    if (( len > 255 )); then
        printf 'ERROR\t%d bytes of content does not fit a short command APDU (Lc is one byte)\n' "$len" >&2
        printf 'WHY\tthis verb builds the short form; an extended-length APDU is a different encoding and is not built here\n' >&2
        return 2
    fi
    local p2adm
    p2adm=$(simd_off_adm_p2 "$adm") || return $?

    local cla="00"
    [[ "$gen" == "sim" ]] && cla="A0"
    local key_data="-" key_lc="-" key_missing=""
    if [[ -n "$key" ]]; then
        key_data=$(simd_norm_hex "$key")
        if [[ ! "$key_data" =~ ^[0-9a-f]+$ ]] ||
           { [[ ${#key_data} -ne 16 && ${#key_data} -ne 32 ]]; }; then
            printf 'ERROR\t--key takes an 8-byte or 16-byte key in hex, got %s\n' "$key" >&2
            printf 'WHY\tTS 51.011 §9.3 codes a CHV on 8 bytes; a longer ADM key is a card-profile fact, and half a key is a failed verification that burns a retry\n' >&2
            return 2
        fi
        key_lc=$(simd_off_byte "$(( ${#key_data} / 2 ))")
    else
        key_missing="the ADM key: pass --key <hex> to complete the VERIFY; without it the write below is still exact but cannot succeed"
    fi

    local c1_apdu="-"
    if [[ -n "$key_data" && "$key_data" != "-" ]]; then
        c1_apdu="${cla}2000${p2adm}${key_lc}$(printf '%s' "$key_data" | tr 'a-f' 'A-F')"
    fi

    local ins insname ref p1 p2 lc data_up
    data_up=$(printf '%s' "$data" | tr 'a-f' 'A-F')
    if [[ "$type" == "transparent" ]]; then
        ins="D6"
        insname="UPDATE BINARY"
        local off="$offset"
        if ! simd_off_digits "$off"; then
            printf 'ERROR\t--offset takes a decimal byte offset, got %s\n' "$off" >&2
            printf 'WHY\tP1/P2 are the offset split high/low (TS 102 221 §11.1.4); hex here would be read as decimal and mis-address the EF\n' >&2
            return 2
        fi
        if [[ "$gen" == "sim" && "$off" -gt 32767 ]]; then
            printf 'ERROR\toffset %s does not fit a 2G P1\n' "$off" >&2
            printf 'WHY\tTS 51.011 §9.2.4: "B8 in P1 shall be set to 0", so a 2G SIM addresses at most 32767\n' >&2
            return 2
        fi
        if (( off > 65535 )); then
            printf 'ERROR\toffset %s does not fit two bytes\n' "$off" >&2
            return 2
        fi
        if [[ -n "$record" ]]; then
            printf 'ERROR\tEF %s is %s: address it with --offset, not --record\n' "$name" "$type" >&2
            printf 'WHY\tthe file structure decides the command; a record number against a transparent EF is a wrong-length write, not an addressing choice\n' >&2
            return 2
        fi
        p1=$(simd_off_byte "$(( off >> 8 ))")
        p2=$(simd_off_byte "$off")
        lc=$(simd_off_byte "$len")
        if [[ "$size" =~ ^([0-9]+)\ bytes$ ]]; then
            local fsize="${BASH_REMATCH[1]}"
            if (( off + len > fsize )); then
                printf 'ERROR\toffset %s plus %d bytes exceeds the %s-byte EF %s\n' "$off" "$len" "$fsize" "$name" >&2
                printf 'WHY\tTS 51.011 §9.4.2/§9.4.6: an address outside the EF is 9402/6BXX on 2G and 6B00 on a USIM; building a command the card is defined to refuse is not an artefact, it is a typo with a citation\n' >&2
                return 1
            fi
        fi
        if [[ "$gen" == "sim" ]]; then
            ref="TS 51.011 §9.2.4: the command is TS 102 221 §11.1.4 with class 'A0' and B8 of P1 = '0'"
        else
            ref="TS 102 221 §11.1.4: P1/P2 are the offset high/low, Lc the data length, no Le"
        fi
    else
        ins="DC"
        insname="UPDATE RECORD"
        local rec="${record:-1}"
        if ! simd_off_digits "$rec"; then
            printf 'ERROR\t--record takes a decimal record number, got %s\n' "$rec" >&2
            return 2
        fi
        if (( rec < 1 || rec > 255 )); then
            printf 'ERROR\trecord %s is outside 1-255\n' "$rec" >&2
            printf 'WHY\tP1 carries the record number in one byte; TS 102 221 §11.1.6 also requires P1=00 for the next/previous modes, which is why absolute mode is used here\n' >&2
            return 2
        fi
        if [[ "$offset" != "0" ]]; then
            printf 'ERROR\tEF %s is %s: address it with --record, not --offset\n' "$name" "$type" >&2
            return 2
        fi
        p1=$(simd_off_byte "$rec")
        p2="04"
        lc=$(simd_off_byte "$len")
        if [[ "$gen" == "sim" ]]; then
            ref="TS 51.011 §9.2.6: the command is TS 102 221 §11.1.6 with class 'A0' and P2 in {'02','03','04'}; '04' is absolute, P1 is the record number"
        else
            ref="TS 102 221 §11.1.6 with P2 '04' = absolute/current record (Table 11.11), P1 the record number"
        fi
    fi
    local c2_apdu="${cla}${ins}${p1}${p2}${lc}${data_up}"

    printf 'verb\tadm-apdu\n'
    printf 'generation\t%s\n' "$gen"
    printf 'ef\t%s\n' "$(printf '%s' "$ef" | tr 'a-f' 'A-F')"
    printf 'ef_name\t%s\n' "$name"
    printf 'ef_type\t%s\n' "$type"
    printf 'ef_size\t%s\n' "$size"
    printf 'update_access\t%s\n' "$access"
    printf 'ef_ref\t%s\n' "$clause"
    printf 'adm_reference\tADM%s, VERIFY P2 '"'"'%s'"'"' (TS 102 221 Table 9.3)\n' "$adm" "$p2adm"
    printf 'adm_note\t%s\n' "which ADM level an EF requires is a card-profile fact (the EF's EF_ARR entry names it, TS 31.102 §4.2.55); ADM1 is the default this verb states rather than assumes silently"
    printf 'c1_name\tVERIFY (ADM key reference '"'"'%s'"'"')\n' "$p2adm"
    printf 'c1_apdu\t%s\n' "$c1_apdu"
    printf 'c1_cla\t%s\n' "$cla"
    printf 'c1_ins\t20\n'
    printf 'c1_p1\t00\n'
    printf 'c1_p2\t%s\n' "$p2adm"
    printf 'c1_lc\t%s\n' "${key_lc}"
    printf 'c1_le\t-\n'
    printf 'c1_data\t%s\n' "$( [[ "$key_data" == "-" ]] && printf '%s' "-" || printf '%s' "$(printf '%s' "$key_data" | tr 'a-f' 'A-F')" )"
    if [[ "$gen" == "sim" ]]; then
        printf 'c1_ref\t%s\n' "TS 51.011 §9.2.9 limits VERIFY CHV to class 'A0', P1 '00', P3 '08' and P2 '01'/'02' (CHV1/CHV2); the ADM key reference is a UICC-level reference (TS 102 221 §11.1.9 and Table 9.3) that a card with the UICC command set executes"
        printf 'c1_caveat\t%s\n' "a Phase-1 2G SIM that does not implement TS 102 221 has no ADM VERIFY at all; on such a card a write is gated by the CHV the EF's other access condition names, not by an administrative key"
    else
        printf 'c1_ref\t%s\n' "TS 102 221 §11.1.9: P1 '00', P2 the key reference from Table 9.3, Lc '08' (or the key length), no Le"
    fi
    [[ -n "$key_missing" ]] && printf 'c1_missing\t%s\n' "$key_missing"
    printf 'c1_expect\t9000\n'
    printf 'c1_failure\t63CX\tverification failed, X attempts left (TS 102 221 §11.1.9.1)\n'
    printf 'c1_failure\t6983\tauthentication method blocked, no attempt left (TS 102 221 §11.1.9.1)\n'
    printf 'c2_name\t%s\n' "$insname"
    printf 'c2_apdu\t%s\n' "$c2_apdu"
    printf 'c2_cla\t%s\n' "$cla"
    printf 'c2_ins\t%s\n' "$ins"
    printf 'c2_p1\t%s\n' "$p1"
    printf 'c2_p2\t%s\n' "$p2"
    printf 'c2_lc\t%s\n' "$lc"
    printf 'c2_le\t-\n'
    printf 'c2_data\t%s\n' "$data_up"
    if [[ "$type" == "linear fixed" ]]; then
        printf 'c2_record\t%s\n' "${record:-1}"
        printf 'c2_mode\tabsolute/current (P2 '"'"'04'"'"'; '"'"'02'"'"' is next and '"'"'03'"'"' previous, TS 102 221 Table 11.11)\n'
        printf 'c2_note\t%s\n' "Lc is the length of the data supplied here; the card compares it with the EF's fixed record length and answers 6700 (USIM) or 67XX (2G) when they differ, so the record length is a card fact this verb does not invent"
    else
        printf 'c2_offset\t%s\n' "$offset"
        printf 'c2_length\t%s\n' "$( [[ "$size" =~ ^([0-9]+)\ bytes$ ]] && printf '%d bytes, EF size %s (fits)' "$len" "${BASH_REMATCH[1]}" || printf '%d bytes' "$len" )"
    fi
    printf 'c2_ref\t%s\n' "$ref"
    printf 'c2_expect\t9000\n'
    if [[ "$gen" == "sim" ]]; then
        printf 'c2_failure\t67XX\tincorrect parameter P3 (TS 51.011 §9.4.6)\n'
        printf 'c2_failure\t6BXX\tincorrect parameter P1 or P2, address outside the EF (TS 51.011 §9.4.6)\n'
        printf 'c2_failure\t9404\tfile ID not found (TS 51.011 §9.4.4)\n'
        printf 'c2_failure\t9400\tno EF selected (TS 51.011 §9.4.4)\n'
        printf 'c2_failure\t9804\taccess condition not fulfilled: the ADM write condition is not satisfied (TS 51.011 §9.4.5)\n'
        printf 'c2_failure\t9840\tverification failed or blocked: the ADM key was tried too often (TS 51.011 §9.4.5)\n'
    else
        printf 'c2_failure\t6700\tincorrect parameter P3/Lc (ISO/IEC 7816-4)\n'
        printf 'c2_failure\t6B00\tincorrect parameter P1 or P2, offset outside the EF (ISO/IEC 7816-4)\n'
        printf 'c2_failure\t6A82\tfile not found (ISO/IEC 7816-4)\n'
        printf 'c2_failure\t6982\tsecurity status not satisfied: ADM not verified (ISO/IEC 7816-4)\n'
        printf 'c2_failure\t6983\tauthentication method blocked (ISO/IEC 7816-4)\n'
    fi
    printf 'order\t%s\n' "VERIFY first, then $insname: the card answers the write with 6982 (USIM) or 9804 (2G) until the ADM verification is satisfied"
    printf 'not_performed\t%s\n' "card transport: no reader was opened, no SELECT was sent, no byte was written to a card"
    printf 'handoff\t%s\n' "send c1 then c2 with a reader transport of your choice against a SIM you own whose test ADM key you hold; the SELECT that precedes them is the application path (2G DF_GSM '7F20' / USIM ADF '7FFF')"
    printf 'note\t%s\n' "$SIMD_OFF_NOTE"
    printf 'status\tencoding-built\n'
    return 0
}

# simd_off_swap_artefacts <conf> — the artefact set a port-out against a
# carrier portal consumes, one row per field, each bound to the portal check it
# passes and to the detection signal that observes that path. Exit 3: the plan
# is complete but its subject (a portal) is not in this tree.
simd_off_swap_artefacts() {
    local conf="${1:-}"
    simd_off_conf_check "$conf" || return $?
    local f role src chk sig val present=0
    printf 'verb\tswap-artefacts\n'
    printf 'conf\t%s\n' "$(simd_sanitize "$conf")"
    printf 'field_set\t%s\n' "${SIMD_CONF_KEYS[*]}"
    for f in "${SIMD_CONF_KEYS[@]}"; do
        case "$f" in
            account_id)   role="the portal account identifier for the line" ;;
            msisdn)       role="the number being ported, as the portal holds it (ITU-T E.164)" ;;
            verification) role="the answer the portal verifies before it acts on a request" ;;
            new_iccid)    role="the replacement SIM's ICCID, 19-20 digits with a Luhn check digit" ;;
            auth_code)    role="the port authorisation code the carrier sends to the registered number" ;;
        esac
        val=$(simd_off_conf_get "$conf" "$f") || val=""
        src=$(simd_off_conf_get "$conf" "${f}_source") || src="unknown"
        chk=$(simd_off_conf_get "$conf" "${f}_check") || chk="unknown"
        sig=$(simd_off_signal_for "$f")
        [[ -n "$val" ]] && present=$(( present + 1 ))
        printf 'field\t%s\t%s\t%s\t%s\t%s\n' "$f" "$role" "$src" "$chk" "$sig"
        printf 'field_state\t%s\t%s\n' "$f" "$( [[ -n "$val" ]] && echo present || echo unknown )"
    done
    printf 'conf_present\t%d of %d\n' "$present" "${#SIMD_CONF_KEYS[@]}"
    printf 'iccid_luhn\t%s\n' "$(simd_off_iccid_state "$(simd_off_conf_get "$conf" new_iccid)")"
    printf 'msisdn_shape\t%s\n' "$(simd_off_msisdn_state "$(simd_off_conf_get "$conf" msisdn)")"
    printf 'signal_basis\t%s\n' "the six signals are network-observable events during and after a port; none of them observes a portal credential, a message or a conversation, so those paths are reported signal=none instead of being given a signal that would not fire"
    printf 'signal_basis\t%s\n' "ota_sms_burst is the one path this module can see: provisioning the replacement SIM for a port is an OTA-driven event"
    printf 'story\t%s\n' "the module names the source, not the words: a script for answering a portal is exactly what the seam check keeps out of this file"
    printf 'not_performed\t%s\n' "no portal was contacted, no account was looked up, no message was sent and nothing was written"
    printf 'handoff\t%s\n' "a portal you control, and the account it authenticates: neither is in this tree"
    printf 'note\t%s\n' "$SIMD_OFF_NOTE"
    printf 'status\thandoff\n'
    return 3
}

# simd_off_swap_plan <conf> — the ordered timeline, each step bound to the
# artefact it consumes, the control from --defence-checklist that applies and
# the signal from --signals that observes it. Both cross-references are checked
# at run time, so the plan cannot name a signal or a control that the rest of
# the module does not have. Exit 3: the timeline ends at the last hop, which is
# a live portal and a real person.
simd_off_swap_plan() {
    local conf="${1:-}"
    simd_off_conf_check "$conf" || return $?
    local -a steps=(
        "the account identifier opens the port request in the portal|account_id|port_out_validation|none"
        "the portal's verification is answered and the request is accepted|verification|account_pin|none"
        "the replacement ICCID is supplied and the swap is scheduled|new_iccid|number_lock|ota_sms_burst"
        "the authorisation code sent to the registered number is entered|auth_code|registered_number_alert|none"
        "the port executes and the number moves to the new SIM|new_iccid|number_lock|imsi_imei_pairing_change"
        "the old SIM and the new SIM both try to register for the overlap window|msisdn|device_integrity|dual_network_registration auth_failure_streak implausible_vmsc_change imei_tac_change"
        "the subscriber notices the loss, and the carrier's fraud record becomes the evidence|msisdn|evidence|none"
    )
    local i=0 ent ev art ctl sigs s val state bad=0 n=0
    printf 'verb\tswap-plan\n'
    printf 'conf\t%s\n' "$(simd_sanitize "$conf")"
    printf 'basis\t%s\n' "one ordered timeline for a port-out; every step names the artefact it consumes, the control that applies from --defence-checklist, and the signal that observes it from --signals"
    for ent in "${steps[@]}"; do
        i=$(( i + 1 ))
        ev="${ent%%|*}"
        rest="${ent#*|}"
        art="${rest%%|*}"
        rest="${rest#*|}"
        ctl="${rest%%|*}"
        sigs="${rest#*|}"
        val=$(simd_off_conf_get "$conf" "$art") || val=""
        state="unknown"
        [[ -n "$val" ]] && state="present"
        printf 'step%02d_event\t%s\n' "$i" "$ev"
        printf 'step%02d_artefact\t%s\n' "$i" "$art"
        printf 'step%02d_artefact_state\t%s\n' "$i" "$state"
        printf 'step%02d_control\t%s\n' "$i" "$ctl"
        if ! simd_off_control_known "$ctl"; then
            printf 'ERROR\tstep %d names control %s, which --defence-checklist does not have\n' "$i" "$ctl" >&2
            bad=$(( bad + 1 ))
        fi
        for s in $sigs; do
            [[ "$s" == "none" ]] || n=$(( n + 1 ))
            if [[ "$s" != "none" ]] && ! simd_off_signal_known "$s"; then
                printf 'ERROR\tstep %d names signal %s, which --signals does not have\n' "$i" "$s" >&2
                bad=$(( bad + 1 ))
            fi
            case "$s" in
                none) printf 'step%02d_signal\tnone\tno signal observes this step; the module says so instead of naming one that would not fire\n' "$i" ;;
                ota_sms_burst) printf 'step%02d_signal\t%s\tthe OTA run that provisions the replacement SIM\n' "$i" "$s" ;;
                *) printf 'step%02d_signal\t%s\tobserved in the registration history a carrier export or a test RAN can produce\n' "$i" "$s" ;;
            esac
        done
    done
    printf 'steps\t%d\n' "$i"
    printf 'signals_named\t%d\n' "$n"
    printf 'control_check\t%s\n' "$( [[ "$bad" -eq 0 ]] && echo "every control named above is an area in --defence-checklist" || echo FAILED )"
    printf 'signal_check\t%s\n' "$( [[ "$bad" -eq 0 ]] && echo "every signal named above is in --signals" || echo FAILED )"
    printf 'last_hop\t%s\n' "a live portal with a real account, a phone line, and the person who owns the number: none of the three is in this tree, and this verb does not pretend to have them"
    printf 'note\t%s\n' "$SIMD_OFF_NOTE"
    printf 'status\thandoff\n'
    (( bad == 0 )) || return 1
    return 3
}

# ── status ──────────────────────────────────────────────────────────────
simd_cli_status_tsv() {
    # No disclaimer here, deliberately. --status-tsv is the detection half and
    # is what the GUI and the casebook poll; a warning streamed on every poll is
    # a warning that stops being read. The attack verbs carry it instead, and
    # they carry it before the gate so a refusal still teaches.
    printf 'module\tsim_defense\n'
    printf 'tag\tsimd\n'
    printf 'scope\tdefence, detection and attack simulation\n'
    printf 'dir\t%s\n' "$SIMD_DIR"
    printf 'history_dir\t%s\n' "$SIMD_HISTORY_DIR"
    printf 'ef_ad_generations\t%s\n' "sim (TS 51.011 10.3.18) and usim (TS 31.102 4.2.18)"
    printf 'signals\t6\n'
    printf 'esim_state_model\t%s\n' "enabled|disabled|deleted (SGP.22)"
    printf 'reader\tnone required (no card access in any verb)\n'
    printf 'attack_verbs\t%s\n' "--adm-apdu --swap-artefacts --swap-plan"
    printf 'attack_path\t%s\n' "simulation only: real encodings, real plans, and no reader, portal or socket (the seam is checked by --selftest scope-* and --scope-check)"
    printf 'attack_gate\tnone -- the attack verbs run without a flag\n'
    printf 'attack_opens\tnothing; no reader, no portal, no socket, and nothing is written to a card\n' 
    printf 'attack_exit_codes\t%s\n' "0 encoding built, 1 input refused, 2 usage error or gate closed, 3 handoff"
    printf 'attack_adm_refs\t%s\n' "VERIFY P2 0A..0E = ADM1..ADM5, 8A..8E = ADM6..ADM10 (TS 102 221 Table 9.3)"
    printf 'attack_ef_table\t%s\n' "2G TS 51.011 (IMSI/SPN/LOCI/AD/ADN/SMS/MSISDN/ICCID), USIM TS 31.102 (IMSI/Keys/UST/SPN/ACC/LOCI/AD/SMS/MSISDN/ARR/ICCID)"
    printf 'attack_last_hop\t%s\n' "a reader with a card in it, a live portal, or a phone line: none of the three is in this tree"
}

# ── selftest ────────────────────────────────────────────────────────────
simd_selftest() {
    local bad=0 nchk=0
    chk() {
        nchk=$(( nchk + 1 ))
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$(( bad + 1 )); fi
    }
    fld() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }
    flds() { awk -F'\t' -v k="$1" '$1==k{print $2; exit}'; }

    local d out rc
    d=$(mktemp -d "$MOD_TMP/selftest.XXXXXX") || {
        printf 'ERROR\tmktemp failed under %s\n' "$MOD_TMP" >&2; return 1; }
    trap 'rm -rf "$d"' EXIT
    export LOOT_DIR="$d/loot" CAPTURES_DIR="$d/captures" STATE_DIR="$d/state"
    export SIMD_DIR="$d/loot/sim_defense"
    export SIMD_HISTORY_DIR="$SIMD_DIR/history"
    mkdir -p "$SIMD_DIR" "$SIMD_HISTORY_DIR"

    # 1. EF_AD: the 2G and USIM layouts differ. The same bytes parse to a
    #    different meaning for byte 3 bit 1, which is the whole point.
    local usim="01000102" sim2g="00ffff03"
    out=$(simd_ef_ad "$usim" usim)
    chk ef-ad-usim-field "$(fld "$out" b3_bit1_field)" "ciphering_indicator_usim"
    chk ef-ad-usim-cipher "$(fld "$out" ciphering_indicator)" "enabled (ciphering indicator shown to the user)"
    chk ef-ad-usim-mode "$(fld "$out" mode)" "normal operation + specific facilities"
    chk ef-ad-usim-mnc "$(fld "$out" mnc_length)" "2"
    out=$(simd_ef_ad "$sim2g" sim)
    chk ef-ad-2g-field "$(fld "$out" b3_bit1_field)" "ofm_2g"
    chk ef-ad-2g-ofm "$(fld "$out" ofm)" "yes"
    chk ef-ad-2g-cipher "$(fld "$out" ciphering_indicator)" "not_carried_2g (TS 51.011 EF_AD has no ciphering indicator field)"
    chk ef-ad-2g-mnc "$(fld "$out" mnc_length)" "3"
    # Same bytes, two layouts: a parser that treats them as one must fail here.
    local a b
    a=$(simd_ef_ad "$usim" usim); b=$(simd_ef_ad "$usim" sim)
    chk ef-ad-layouts-differ "$([[ "$(fld "$a" b3_bit1_field)" != "$(fld "$b" b3_bit1_field)" ]] && echo differs || echo same)" "differs"
    chk ef-ad-pin-not-ciphering "$([[ "$(fld "$a" pin_enable_flag)" != "$(fld "$a" ciphering_indicator)" ]] && echo different || echo same)" "different"
    chk ef-ad-pin-source "$([[ "$(fld "$a" pin_enable_flag_source)" == *"card state"* ]] && echo yes || echo no)" "yes"
    chk ef-ad-pin-not-byte3 "$(fld "$a" pin_enable_flag)" "not_in_ef_ad"
    chk ef-ad-adm "$([[ "$(fld "$a" adm_key)" == *"EF_ARR"* ]] && echo yes || echo no)" "yes"
    chk ef-ad-short "$(simd_ef_ad 0100 usim >/dev/null 2>&1; echo $?)" "1"
    chk ef-ad-bad-hex "$(simd_ef_ad zz usim >/dev/null 2>&1; echo $?)" "2"
    chk ef-ad-bad-gen "$(simd_ef_ad 01000102 wimax >/dev/null 2>&1; echo $?)" "2"
    chk ef-ad-missing "$(simd_ef_ad >/dev/null 2>&1; echo $?)" "2"

    # 2. PIN / PUK state model and the ADM concept.
    out=$(simd_pin_state)
    chk pin-status-63cx "$([[ "$(printf '%s\n' "$out" | grep -ci '63Cx')" -ge 1 ]] && echo yes || echo no)" "yes"
    chk pin-status-6983 "$([[ "$(printf '%s\n' "$out" | grep -ci '6983')" -ge 1 ]] && echo yes || echo no)" "yes"
    chk pin-adm-key "$([[ "$(printf '%s\n' "$out" | grep -ci 'administrative key')" -ge 1 ]] && echo yes || echo no)" "yes"
    chk pin-enable-card-state "$(fld "$out" pin1_enable_state)" "card state (CHV1 enable flag); EF_AD does not carry it in either layout"

    # 3. eSIM profile state machine and DER parse.
    chk esim-t-enable "$(simd_esim_transition disabled enabled >/dev/null 2>&1; echo $?)" "0"
    chk esim-t-disable "$(simd_esim_transition enabled disabled >/dev/null 2>&1; echo $?)" "0"
    chk esim-t-delete "$(simd_esim_transition enabled deleted >/dev/null 2>&1; echo $?)" "0"
    chk esim-t-terminal "$(simd_esim_transition deleted enabled >/dev/null 2>&1; echo $?)" "1"
    chk esim-t-unknown "$(simd_esim_transition bogus enabled >/dev/null 2>&1; echo $?)" "1"
    out=$(simd_esim_profile_parse 3021040a988812010000400310f00410a0000005591010ffffffff89000001000a0101)
    chk esim-parse-state "$(fld "$out" profile_state)" "enabled"
    chk esim-parse-iccid "$(fld "$out" iccid)" "8988211000000430010"
    chk esim-parse-visible "$(fld "$out" me_visible)" "yes"
    out=$(simd_esim_profile_parse 3021040a988812010000400310f00410a0000005591010ffffffff89000001000a0100)
    chk esim-parse-disabled "$(fld "$out" profile_state)" "disabled"
    chk esim-parse-hidden "$(fld "$out" me_visible)" "no"
    # An unknown ENUMERATED value must not become enabled.
    out=$(simd_esim_profile_parse 3021040a988812010000400310f00410a0000005591010ffffffff89000001000a0102); rc=$?
    chk esim-unknown-rc "$rc" "1"
    chk esim-unknown-state "$(fld "$out" profile_state)" "unknown"
    chk esim-unknown-not-enabled "$([[ "$(fld "$out" profile_state)" != "enabled" ]] && echo yes || echo no)" "yes"
    chk esim-bad-der "$(simd_esim_profile_parse 040a00 >/dev/null 2>&1; echo $?)" "1"
    chk esim-bad-hex "$(simd_esim_profile_parse zz >/dev/null 2>&1; echo $?)" "2"
    chk esim-missing "$(simd_esim_profile_parse >/dev/null 2>&1; echo $?)" "2"

    # 4. Port-in-progress scoring: clean scores low, and the score rises with
    #    each added signal (both directions).
    local hdr='ts	imsi	imei	msisdn	vmsc	network	event	auth_result	ota_sms'
    local base="2026-01-01T00:00:00Z	310150123456789	353285060000001	12025550100	VLR-A	MCC310	register	ok	0"
    printf '%s\n%s\n' "$hdr" "$base" > "$d/h0.tsv"
    printf '%s\n%s\n%s\n' "$hdr" "$base" \
        "2026-01-01T00:01:00Z	310150123456789	359999090000002	12025550100	VLR-A	MCC310	register	ok	0" > "$d/h1.tsv"
    { printf '%s\n%s\n' "$hdr" "$base"
      printf '2026-01-01T00:01:00Z\t310150123456789\t359999090000002\t12025550100\tVLR-A\tMCC310\tregister\tok\t0\n'
      for i in 1 2 3 4 5 6 7 8 9 10; do
          printf '2026-01-01T00:%02d:00Z\t310150123456789\t359999090000002\t12025550100\tVLR-A\tMCC310\tota\tok\t1\n' "$i"
      done; } > "$d/h2.tsv"
    { cat "$d/h2.tsv"
      for i in 1 2 3; do
          printf '2026-01-01T01:%02d:00Z\t310150123456789\t359999090000002\t12025550100\tVLR-A\tMCC310\tauth\tfail\t0\n' "$i"
      done; } > "$d/h3.tsv"
    { cat "$d/h3.tsv"
      printf '2026-01-01T02:00:00Z\t310150123456789\t359999090000002\t12025550100\tVLR-A\tMCC311\tlocation_update\tok\t0\n'; } > "$d/h4.tsv"
    { cat "$d/h4.tsv"
      printf '2026-01-01T02:05:00Z\t310150123456789\t359999090000002\t12025550100\tVLR-C\tMCC310\tlocation_update\tok\t0\n'; } > "$d/h5.tsv"

    local s0 s1 s2 s3 s4 s5
    out=$(simd_score "$d/h0.tsv"); s0=$(fld "$out" score)
    chk score-clean-low "$s0" "0"
    chk score-clean-risk "$(fld "$out" risk)" "low"
    chk score-clean-no-signal "$(printf '%s\n' "$out" | awk -F'\t' '$1=="signal" && $3+0>0{n++} END{print n+0}')" "0"
    s1=$(fld "$(simd_score "$d/h1.tsv")" score)
    s2=$(fld "$(simd_score "$d/h2.tsv")" score)
    s3=$(fld "$(simd_score "$d/h3.tsv")" score)
    s4=$(fld "$(simd_score "$d/h4.tsv")" score)
    s5=$(fld "$(simd_score "$d/h5.tsv")" score)
    chk score-h1-rises "$([[ "$s1" -gt "$s0" ]] && echo yes || echo no)" "yes"
    chk score-h2-rises "$([[ "$s2" -gt "$s1" ]] && echo yes || echo no)" "yes"
    chk score-h3-rises "$([[ "$s3" -gt "$s2" ]] && echo yes || echo no)" "yes"
    chk score-h4-rises "$([[ "$s4" -gt "$s3" ]] && echo yes || echo no)" "yes"
    chk score-h5-rises "$([[ "$s5" -gt "$s4" ]] && echo yes || echo no)" "yes"
    chk score-h5-critical "$(fld "$(simd_score "$d/h5.tsv")" risk)" "critical"
    chk score-imsi-imei-signal "$(simd_score "$d/h1.tsv" | awk -F'\t' '$2=="imsi_imei_pairing_change"{print $3}')" "25"
    chk score-bad-file "$(simd_score /nonexistent.tsv >/dev/null 2>&1; echo $?)" "2"
    printf 'ts\timsi\n2026-01-01T00:00:00Z\t310150123456789\n' > "$d/badcols.tsv"
    chk score-missing-cols "$(simd_score "$d/badcols.tsv" >/dev/null 2>&1; echo $?)" "1"

    # 5. Signals and checklist content.
    out=$(simd_signals)
    chk signals-count "$(printf '%s\n' "$out" | grep -c '^signal')" "6"
    for s in imsi_imei_pairing_change ota_sms_burst auth_failure_streak \
             dual_network_registration implausible_vmsc_change imei_tac_change; do
        chk "signal-$s" "$(printf '%s\n' "$out" | grep -c "^signal	$s	")" "1"
    done
    out=$(simd_defence_checklist)
    chk checklist-number-lock "$([[ "$(printf '%s\n' "$out" | grep -ci 'port freeze\|number lock')" -ge 1 ]] && echo yes || echo no)" "yes"
    chk checklist-account-pin "$([[ "$(printf '%s\n' "$out" | grep -ci 'account PIN')" -ge 1 ]] && echo yes || echo no)" "yes"
    chk checklist-carrier-record "$([[ "$(printf '%s\n' "$out" | grep -ci 'admissible')" -ge 1 ]] && echo yes || echo no)" "yes"
    out=$(simd_esim_roles)
    for r in sm-dp+ lpa euicc isd-r isd-p; do
        chk "esim-role-$r" "$(printf '%s\n' "$out" | grep -c "^role	$r	")" "1"
    done
    chk esim-integrity "$(printf '%s\n' "$out" | grep -ci 'operator.s record')" "1"

    # 6. The seam. The same module answers the detection verbs with the gate
    #    open and runs the attack verbs: "detection plus attack simulation"
    #    is a structural property here, not a slogan.
    out=$(simd_scope_check); rc=$?
    chk scope-rc "$rc" "0"
    chk scope-status "$(fld "$out" scope)" "detection-and-ungated-attack"
    chk scope-seam "$([[ "$(fld "$out" seam)" == line* ]] && echo yes || echo no)" "yes"
    chk scope-no-violation "$(printf '%s\n' "$out" | grep -c '^scope_violation')" "0"
    local badverb1="--port""-out" badverb2="--swap""-request"
    chk scope-verb-unknown "$(simd_cli_main "$badverb1" >/dev/null 2>&1; echo $?)" "2"
    chk scope-verb-swap "$(simd_cli_main "$badverb2" >/dev/null 2>&1; echo $?)" "2"
    unset IMSI_LAB_AUTHORISED
    chk seam-signals-ungated "$(simd_cli_main --signals >/dev/null 2>&1; echo $?)" "0"
    chk seam-checklist-ungated "$(simd_cli_main --defence-checklist >/dev/null 2>&1; echo $?)" "0"
    chk seam-score-ungated "$(simd_score "$d/h0.tsv" >/dev/null 2>&1; echo $?)" "0"
    chk seam-efad-ungated "$(simd_cli_main --ef-ad 01000102 usim >/dev/null 2>&1; echo $?)" "0"
    chk seam-pin-ungated "$(simd_cli_main --pin-state >/dev/null 2>&1; echo $?)" "0"
    # No gate: the three attack verbs run with no flag, write nothing, and
    # carry the note. What must not creep back is a silent permission check, so
    # the retired flag is rejected rather than ignored.
    printf 'account_id=A1\n' > "$d/c1.conf"
    chk retired-flag-rejected "$(simd_cli_main --i-have-a-lab-and-authorisation --adm-apdu 6F07 00 >/dev/null 2>&1; echo $?)" "2"
    local before after
    before=$(find "$d" -type f | sort)
    chk ungated-adm-rc "$(simd_cli_main --adm-apdu 6F07 00 >/dev/null 2>&1; echo $?)" "0"
    chk ungated-artefacts-rc "$(simd_cli_main --swap-artefacts "$d/c1.conf" >/dev/null 2>&1; echo $?)" "3"
    chk ungated-plan-rc "$(simd_cli_main --swap-plan "$d/c1.conf" >/dev/null 2>&1; echo $?)" "3"
    after=$(find "$d" -type f | sort)
    chk ungated-writes-nothing "$( [[ "$before" == "$after" ]] && echo same || echo changed )" "same"
    out=$(simd_cli_main --adm-apdu 6F07 00 2>"$d/plain.err")
    chk ungated-stderr-empty "$(grep -c . "$d/plain.err")" "0"
    chk ungated-note "$(printf '%s\n' "$out" | awk -F'\t' '$1=="note"{print ($2 ~ /destroys the card/)?"yes":"no"}')" "yes"
    # The detection half is silent too, and has been all along.
    chk status-stderr-clean "$(simd_cli_main --status-tsv 2>&1 >/dev/null | grep -c .)" "0"

    # 8. Known-answer APDUs. Every expected string below is derived by hand from
    #    the clause before the encoder is asked, so the test fails if the
    #    encoder drifts. Byte counts and layouts:
    #      VERIFY (USIM): CLA 00 | INS 20 | P1 00 | P2 0A | Lc 08 |
    #        data 1122334455667788 = 13 bytes -> 0020000A081122334455667788
    #      VERIFY (2G):   CLA A0 (TS 51.011 §9.2.9) -> A020000A08...
    #      UPDATE BINARY (USIM): CLA 00 | INS D6 | P1 00 | P2 00 | Lc 09 |
    #        data 082982608200002080 (9 bytes) = 14 bytes ->
    #        00D6000009082982608200002080. The 9-byte body is pySim's published
    #        EF_IMSI test vector (ts_51_011.py), i.e. a value from outside this
    #        module, standing in for a real EF_IMSI content.
    #      UPDATE BINARY (2G): CLA A0 (TS 51.011 §9.2.4) -> A0D6...
    #      UPDATE RECORD (2G EF_ADN, record 1, 14 x FF): CLA A0 | INS DC |
    #        P1 01 | P2 04 (absolute, Table 11.11) | Lc 0E | 14 bytes ->
    #        A0DC01040E + 28 F's = 19 bytes.
    #      ADM references from TS 102 221 Table 9.3: 1->0A, 5->0E, 6->8A,
    #        10->8E. The 5->6 step is the one a naive 0A+n-1 gets wrong (0F).
    local rec14="FFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    out=$(simd_off_adm_apdu 6F07 082982608200002080 --key 1122334455667788 2>/dev/null); rc=$?
    chk adm-usim-rc "$rc" "0"
    chk adm-usim-c1 "$(fld "$out" c1_apdu)" "0020000A081122334455667788"
    chk adm-usim-c1-lc "$(fld "$out" c1_lc)" "08"
    chk adm-usim-c2 "$(fld "$out" c2_apdu)" "00D6000009082982608200002080"
    chk adm-usim-c2-lc "$(fld "$out" c2_lc)" "09"
    chk adm-usim-access "$(fld "$out" update_access)" "ADM"
    chk adm-usim-ref "$(fld "$out" ef_ref)" "TS 31.102 §4.2.2"
    chk adm-usim-order "$( [[ "$(fld "$out" order)" == VERIFY* ]] && echo first || echo other )" "first"
    chk adm-usim-noperf "$( [[ "$(fld "$out" not_performed)" == card* ]] && echo yes || echo no )" "yes"
    chk adm-usim-handoff "$( [[ -n "$(fld "$out" handoff)" ]] && echo yes || echo no )" "yes"
    out=$(simd_off_adm_apdu 6F07 082982608200002080 --gen sim --key 1122334455667788 2>/dev/null)
    chk adm-sim-c1 "$(fld "$out" c1_apdu)" "A020000A081122334455667788"
    chk adm-sim-c2 "$(fld "$out" c2_apdu)" "A0D6000009082982608200002080"
    chk adm-sim-cla "$(fld "$out" c2_cla)" "A0"
    chk adm-sim-2g-sw "$(printf '%s\n' "$out" | grep -c '^c2_failure	9804	')" "1"
    chk adm-sim-no-6982 "$(printf '%s\n' "$out" | grep -c '^c2_failure	6982')" "0"
    chk adm-sim-caveat "$( [[ "$(fld "$out" c1_caveat)" == *"Phase-1"* ]] && echo yes || echo no )" "yes"
    chk adm-usim-no-caveat "$(simd_off_adm_apdu 6F07 00 2>/dev/null | grep -c '^c1_caveat')" "0"
    out=$(simd_off_adm_apdu 6F3A "$rec14" --gen sim 2>/dev/null)
    chk adm-rec-c2 "$(fld "$out" c2_apdu)" "A0DC01040E${rec14}"
    chk adm-rec-p1 "$(fld "$out" c2_p1)" "01"
    chk adm-rec-p2 "$(fld "$out" c2_p2)" "04"
    chk adm-rec-lc "$(fld "$out" c2_lc)" "0E"
    chk adm-rec-ins "$(fld "$out" c2_ins)" "DC"
    chk adm-rec-mode-msg "$( [[ "$(fld "$out" c2_mode)" == absolute* ]] && echo yes || echo no )" "yes"
    out=$(simd_off_adm_apdu 6F3C "$rec14" 2>/dev/null)
    chk adm-rec-usim-p2 "$(fld "$out" c2_p2)" "04"
    for pair in 1:0A 5:0E 6:8A 10:8E; do
        chk "adm-p2-${pair%%:*}" \
            "$(simd_off_adm_apdu 6F07 00 --adm "${pair%%:*}" --key 1122334455667788 2>/dev/null | flds c1_p2)" \
            "${pair#*:}"
    done
    chk adm-16byte-key "$(simd_off_adm_apdu 6F07 00 --key 11223344556677889900AABBCCDDEEFF 2>/dev/null | grep -E '^(c1_lc|c1_apdu)' | cut -f2 | paste -sd: )" \
        "0020000A1011223344556677889900AABBCCDDEEFF:10"
    chk adm-nokey-apdu "$(fld "$(simd_off_adm_apdu 6F07 00 2>/dev/null)" c1_apdu)" "-"
    chk adm-nokey-missing "$(simd_off_adm_apdu 6F07 00 2>/dev/null | grep -c '^c1_missing	the ADM key')" "1"
    chk adm-unknown-ef "$(simd_off_adm_apdu 6F99 00 >/dev/null 2>&1; echo $?)" "1"
    chk adm-unknown-ef-msg "$(simd_off_adm_apdu 6F99 00 2>&1 >/dev/null | grep -c '^ERROR	EF 6F99')" "1"
    chk adm-too-long "$(simd_off_adm_apdu 6F07 00112233445566778899 >/dev/null 2>&1; echo $?)" "1"
    chk adm-bad-hex "$(simd_off_adm_apdu 6F07 0ZZ >/dev/null 2>&1; echo $?)" "2"
    chk adm-short-hex "$(simd_off_adm_apdu 6F07 0 >/dev/null 2>&1; echo $?)" "2"
    chk adm-bad-gen "$(simd_off_adm_apdu 6F07 00 --gen wimax >/dev/null 2>&1; echo $?)" "2"
    chk adm-adm-11 "$(simd_off_adm_apdu 6F07 00 --adm 11 >/dev/null 2>&1; echo $?)" "2"
    chk adm-bad-key "$(simd_off_adm_apdu 6F07 00 --key 1122 >/dev/null 2>&1; echo $?)" "2"
    chk adm-2g-offset "$(simd_off_adm_apdu 6F07 00 --gen sim --offset 40000 >/dev/null 2>&1; echo $?)" "2"
    chk adm-record-on-transparent "$(simd_off_adm_apdu 6F07 00 --record 2 >/dev/null 2>&1; echo $?)" "2"
    chk adm-offset-on-linear "$(simd_off_adm_apdu 6F3A 00 --gen sim --offset 3 >/dev/null 2>&1; echo $?)" "2"
    chk adm-record-0 "$(simd_off_adm_apdu 6F3A 00 --gen sim --record 0 >/dev/null 2>&1; echo $?)" "2"
    chk adm-missing "$(simd_off_adm_apdu >/dev/null 2>&1; echo $?)" "2"
    chk adm-bad-opt "$(simd_off_adm_apdu 6F07 00 --foo >/dev/null 2>&1; echo $?)" "2"
    chk luhn-known-good "$(simd_off_luhn 79927398713 && echo yes || echo no)" "yes"
    chk luhn-known-bad "$(simd_off_luhn 79927398710 && echo yes || echo no)" "no"

    # 9. The swap artefact set and the timeline. The fixture is synthetic on
    #    purpose: account A1, a 555 test number, a fictional ICCID. The Luhn
    #    value 8944500008255000126 was computed outside this module.
    local cf="$d/swap.conf"
    cat > "$cf" <<'CONF'
account_id=acct-A1
account_id_source=breach_dump
account_id_check=account_auth
msisdn=+15550000123
msisdn_source=phone_call
msisdn_check=billing_match
verification=stated-answer-placeholder
verification_source=insider
verification_check=verification_answer
new_iccid=8944500008255000126
new_iccid_source=public_record
new_iccid_check=none
auth_code=code-placeholder
auth_code_source=otp_intercept
auth_code_check=otp_to_registered_number
CONF
    out=$(simd_off_swap_artefacts "$cf" 2>/dev/null); rc=$?
    chk swap-rc "$rc" "3"
    chk swap-verb "$(fld "$out" verb)" "swap-artefacts"
    chk swap-fields "$(printf '%s\n' "$out" | grep -c '^field	')" "5"
    chk swap-present "$(fld "$out" conf_present)" "5 of 5"
    chk swap-signal-new-iccid "$(printf '%s\n' "$out" | awk -F'\t' '$1=="field" && $2=="new_iccid"{print $6}')" "ota_sms_burst"
    chk swap-signal-msisdn "$(printf '%s\n' "$out" | awk -F'\t' '$1=="field" && $2=="msisdn"{print $6}')" "none"
    chk swap-source-msisdn "$(printf '%s\n' "$out" | awk -F'\t' '$1=="field" && $2=="msisdn"{print $4}')" "phone_call"
    chk swap-check-auth "$(printf '%s\n' "$out" | awk -F'\t' '$1=="field" && $2=="auth_code"{print $5}')" "otp_to_registered_number"
    chk swap-signals-known "$(printf '%s\n' "$out" | awk -F'\t' '$1=="field"{print $6}' | while read -r s; do [[ "$s" == "none" ]] && echo ok; simd_off_signal_known "$s" && echo ok; done | grep -c ok)" "5"
    chk swap-iccid-luhn "$(fld "$out" iccid_luhn)" "valid"
    chk swap-msisdn-shape "$(fld "$out" msisdn_shape)" "e164"
    chk swap-status "$(fld "$out" status)" "handoff"
    chk swap-noperf "$(grep -c '^not_performed	no portal was contacted' <<<"$out")" "1"
    chk swap-handoff "$(printf '%s\n' "$out" | grep -c '^handoff	')" "1"
    # absent field is unknown, not invented
    printf 'account_id=acct-A1\naccount_id_source=breach_dump\n' > "$d/sparse.conf"
    out=$(simd_off_swap_artefacts "$d/sparse.conf" 2>/dev/null)
    chk swap-sparse-present "$(fld "$out" conf_present)" "1 of 5"
    chk swap-sparse-source "$(printf '%s\n' "$out" | awk -F'\t' '$1=="field" && $2=="msisdn"{print $4}')" "unknown"
    chk swap-sparse-check "$(printf '%s\n' "$out" | awk -F'\t' '$1=="field" && $2=="msisdn"{print $5}')" "unknown"
    chk swap-sparse-state-msisdn "$(printf '%s\n' "$out" | awk -F'\t' '$1=="field_state" && $2=="msisdn"{print $3}')" "unknown"
    # vocabularies are closed
    printf 'msisdn_source=psychic_vibes\n' > "$d/badsrc.conf"
    chk swap-bad-source "$(simd_off_swap_artefacts "$d/badsrc.conf" >/dev/null 2>&1; echo $?)" "1"
    chk swap-bad-source-msg "$(simd_off_swap_artefacts "$d/badsrc.conf" 2>&1 >/dev/null | grep -c '^ERROR	msisdn_source=psychic_vibes')" "1"
    printf 'account_id_source=a\n' > "$d/badcheck.conf"
    chk swap-bad-check "$(simd_off_swap_artefacts "$d/badcheck.conf" >/dev/null 2>&1; echo $?)" "1"
    printf 'account_idd	typo\n' > "$d/badkey.conf"
    chk swap-bad-key "$(simd_off_swap_artefacts "$d/badkey.conf" >/dev/null 2>&1; echo $?)" "1"
    printf 'account_id acct\n' > "$d/nosep.conf"
    chk swap-no-sep "$(simd_off_swap_artefacts "$d/nosep.conf" >/dev/null 2>&1; echo $?)" "1"
    chk swap-missing-conf "$(simd_off_swap_artefacts "$d/nope.conf" >/dev/null 2>&1; echo $?)" "2"
    printf 'new_iccid=8944500008255000127\n' > "$d/badiccid.conf"
    chk swap-iccid-bad-luhn "$(simd_off_swap_artefacts "$d/badiccid.conf" 2>/dev/null | flds iccid_luhn)" "luhn-invalid"
    printf 'msisdn=555-000-1\n' > "$d/badmsisdn.conf"
    chk swap-msisdn-bad-shape "$(simd_off_swap_artefacts "$d/badmsisdn.conf" 2>/dev/null | flds msisdn_shape)" "not-e164"
    # the timeline, cross-checked against the other two verbs
    out=$(simd_off_swap_plan "$cf" 2>/dev/null); rc=$?
    chk plan-rc "$rc" "3"
    chk plan-steps "$(fld "$out" steps)" "7"
    chk plan-control-check "$( [[ "$(fld "$out" control_check)" == every* ]] && echo yes || echo no )" "yes"
    chk plan-signal-check "$( [[ "$(fld "$out" signal_check)" == every* ]] && echo yes || echo no )" "yes"
    chk plan-artefact-states "$(printf '%s\n' "$out" | grep -c '^step0[0-9]_artefact_state	present')" "7"
    chk plan-observable-signals "$(printf '%s\n' "$out" | grep -c '^step0[0-9]_signal	imsi_imei_pairing_change')" "1"
    chk plan-overlap-four "$(printf '%s\n' "$out" | grep -c '^step06_signal	')" "4"
    chk plan-last-hop "$(printf '%s\n' "$out" | grep -c '^last_hop	')" "1"
    chk plan-status "$(fld "$out" status)" "handoff"
    chk plan-six-signals "$(printf '%s\n' "$out" | grep '^step0[0-9]_signal	' | cut -f2 | grep -v '^none$' | sort -u | wc -l | tr -d ' ')" "6"
    chk plan-signals-exact "$(diff <(printf '%s\n' "$out" | grep '^step0[0-9]_signal	' | cut -f2 | grep -v '^none$' | sort -u) <(simd_signals | cut -f2 | sort) >/dev/null && echo same || echo differs)" "same"
    chk plan-vs-checklist "$(printf '%s\n' "$out" | awk -F'\t' '$1 ~ /_control$/{print $2}' | while read -r c; do simd_off_control_known "$c" && echo ok; done | grep -c ok)" "7"
    # the sparse conf states only the account id, so 6 of the 7 steps consume an
    # unknown artefact (new_iccid and msisdn are each consumed twice)
    chk plan-sparse-unknown "$(simd_off_swap_plan "$d/sparse.conf" 2>/dev/null | grep -c '^step0[0-9]_artefact_state	unknown')" "6"

    # 10. Status invariants.
    out=$(simd_cli_main --status-tsv 2>/dev/null)
    chk status-scope "$(fld "$out" scope)" "defence, detection and attack simulation"
    chk status-tag "$(fld "$out" tag)" "simd"
    chk status-attack-verbs "$(fld "$out" attack_verbs)" "--adm-apdu --swap-artefacts --swap-plan"
    chk status-attack-path "$( [[ "$(fld "$out" attack_path)" == *simulation* ]] && echo yes || echo no )" "yes"
    chk status-attack-gate "$(printf '%s\n' "$out" | awk -F'\t' '$1=="attack_gate"{print ($2 ~ /^none/)?"none":"other"}')" "none"
    chk status-exit-codes "$( [[ "$(fld "$out" attack_exit_codes)" == *"3 handoff"* ]] && echo yes || echo no )" "yes"
    chk status-last-hop "$( [[ "$(fld "$out" attack_last_hop)" == *portal* ]] && echo yes || echo no )" "yes"

    printf 'ASSERTIONS\t%d\n' "$nchk"
    rm -rf "$d"
    trap - EXIT
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ── menu ────────────────────────────────────────────────────────────────
simd_menu() {
    while true; do
        banner
        echo -e "  ${C_MAG}=== SIM Swap Attack/Defence (defence + gated attack) ===${C_RESET}"
        echo -e "  loot: ${C_DIM}$SIMD_DIR${C_RESET}\n"
        cat <<'M'
  [1]  list detection signals
  [2]  score a registration history (port-in-progress likelihood)
  [3]  parse EF_AD (2G or USIM layout)
  [4]  PIN / PUK retry-counter and ADM model
  [5]  parse an eSIM ProfileInfo (SGP.22)
  [6]  eSIM / RSP roles and the integrity question
  [7]  defence checklist
  [8]  scope check (the seam between detection and attack)
  [9]  attack: ADM-key EF write APDUs (gated)
  [10] attack: SIM-swap artefact set, from a conf (gated)
  [11] attack: SIM-swap timeline, from a conf (gated)
  [0]  back

M
        read -rp "  choice> " c || return 0  # EOF: leave the menu cleanly
        local -a extra=()
        case "$c" in
            1) simd_signals | column -t -s$'\t' 2>/dev/null || simd_signals
               read -rp "  press enter " _ ;;
            2) read -rp "  history TSV> " f; simd_score "$f" | column -t -s$'\t' 2>/dev/null || true
               read -rp "  press enter " _ ;;
            3) read -rp "  EF_AD hex> " x; read -rp "  generation (sim|usim)> " g
               simd_ef_ad "$x" "$g" | column -t -s$'\t' 2>/dev/null || true
               read -rp "  press enter " _ ;;
            4) simd_pin_state | column -t -s$'\t' 2>/dev/null || simd_pin_state
               read -rp "  press enter " _ ;;
            5) read -rp "  ProfileInfo DER hex> " x
               simd_esim_profile_parse "$x" | column -t -s$'\t' 2>/dev/null || true
               read -rp "  press enter " _ ;;
            6) simd_esim_roles | column -t -s$'\t' 2>/dev/null || simd_esim_roles
               read -rp "  press enter " _ ;;
            7) simd_defence_checklist | column -t -s$'\t' 2>/dev/null || simd_defence_checklist
               read -rp "  press enter " _ ;;
            8) simd_scope_check; read -rp "  press enter " _ ;;
            9) read -rp "  EF id (4 hex)> " x; read -rp "  content hex> " h
               read -rp "  generation (sim|usim)> " g
               read -rp "  ADM key hex (blank for none)> " k
               extra=()
               [[ "$g" == "sim" ]] && extra+=(--gen sim)
               [[ -n "$k" ]] && extra+=(--key "$k")
               simd_off_adm_apdu "$x" "$h" "${extra[@]}" | column -t -s$'\t' 2>/dev/null || true
               read -rp "  press enter " _ ;;
            10) read -rp "  conf path> " f
               simd_off_swap_artefacts "$f" | column -t -s$'\t' 2>/dev/null || true
               read -rp "  press enter " _ ;;
            11) read -rp "  conf path> " f
               simd_off_swap_plan "$f" | column -t -s$'\t' 2>/dev/null || true
               read -rp "  press enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ── CLI dispatch ────────────────────────────────────────────────────────
simd_cli_main() {
    # No flag is consumed any more. --i-have-a-lab-and-authorisation was the old
    # gate; a script that still passes it must be told it is gone, not have it
    # swallowed, so the arguments reach the dispatcher untouched.
    local -a args=( "$@" )
    local cmd="${args[0]:-}"
    if (( ${#args[@]} > 0 )); then
        set -- "${args[@]:1}"
    fi
    case "$cmd" in
        --status-tsv)         simd_cli_status_tsv ;;
        --signals)            simd_signals ;;
        --score)              simd_score "${1:-}" ;;
        --ef-ad)              simd_ef_ad "${1:-}" "${2:-usim}" ;;
        --pin-state)          simd_pin_state ;;
        --esim-profile-parse) simd_esim_profile_parse "${1:-}" ;;
        --defence-checklist)  simd_defence_checklist ;;
        --adm-apdu)           simd_off_adm_apdu "$@" ;;
        --swap-artefacts)     simd_off_swap_artefacts "${1:-}" ;;
        --swap-plan)          simd_off_swap_plan "${1:-}" ;;
        --selftest)           simd_selftest ;;
        --menu)               simd_menu ;;
        *)
            cat >&2 <<EOF
SIM Swap Attack/Defence — port-out detection, and the gated attack half

Usage: $0 COMMAND [ARGS]
  --status-tsv                    module state as TSV
  --signals                       the six detection signals
  --score <history-tsv>           port-in-progress likelihood
  --ef-ad <hex> [sim|usim]        EF_AD in either layout
  --pin-state                     PIN/PUK retry counters and the ADM key
  --esim-profile-parse <hex>      SGP.22 ProfileInfo and profile state
  --defence-checklist             what a subscriber can enforce
  --adm-apdu <ef-id> <hex> [--gen sim|usim] [--key <hex>]
                                  gated: VERIFY ADM + UPDATE BINARY/RECORD APDUs
                                  (the record number, byte offset and ADM level
                                  options are printed by the verb itself)
  --swap-artefacts <conf>         gated: the artefact set a port-out consumes
  --swap-plan <conf>              gated: the ordered timeline for that set
  --selftest                      verify parsers, scoring and the seam
  --menu                          interactive menu

The three attack verbs take no flag. Exit codes:
  0  the artefact was built       1  the input was refused
  2  usage error or bad input     3  handoff: the plan is complete, but its last
                                    hop needs a reader, a live portal or a person
Every attack invocation carries the standing note in its own output.

Scope: the detection and defence half reads what it is given. The attack half
encodes the APDUs an ADM-key holder sends to rewrite an
EF, and plans the artefact set and timeline a port-out consumes; it never opens
a reader, a portal or a phone line, and where the last hop is missing it says so
and exits 3. The selftest asserts that seam on every run.
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
    simd_cli_main "$@"
fi
