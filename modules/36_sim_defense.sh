#!/usr/bin/env bash
# sim defense — detection and defence for a SIM port already in flight.
#
# SCOPE, stated first because it is the point of the module: SIM swapping is
# not a technical attack. It is a carrier-representative social-engineering
# action against a real person's phone number, and a toolkit that shipped a
# template for it would be shipping an identity-theft guide aimed at a real
# person. This module therefore builds only the defensive half:
#
#   * detection signals for a port in flight (IMSI/IMEI re-pairing, OTA burst,
#     authentication-failure streak, dual-network registration, implausible
#     VLR, device-class change)
#   * a worked likelihood score over a registration history
#   * what the SIM actually carries: EF_AD in both the 2G (TS 51.011) and USIM
#     (TS 31.102 §4.2.18) layouts, the PIN/PUK retry-counter model, and the ADM
#     key concept
#   * eSIM / RSP profile-state integrity (GSMA SGP.22)
#   * a defence checklist of the controls a subscriber can actually enforce
#
# The selftest asserts that this file contains no template for contacting a
# carrier as somebody else, and that no verb resembling a port request is
# dispatchable.
#
# Attack owned: O5 (SIM swapping) — detection and defence only, per
# docs/ATTACK_COVERAGE.md.
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

# ── scope check ─────────────────────────────────────────────────────────
# Asserts this file contains no template for contacting a carrier as somebody
# else. The markers are
# assembled at run time so that the marker text itself does not appear in the
# file (a literal marker would match its own grep).
simd_scope_check() {
    local self="${BASH_SOURCE[0]}"
    [[ -f "$self" ]] || { printf 'ERROR\tcannot read module source\n' >&2; return 1; }
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
    local m hits=0
    for m in "${markers[@]}"; do
        if grep -Fq -- "$m" "$self"; then
            printf 'scope_violation\t%s\n' "$m"
            hits=$(( hits + 1 ))
        fi
    done
    # No verb that resembles a port request may be dispatchable.
    local v
    for v in "--port""-out" "--port""-request" "--swap""-request" "--pre""text" "--imperson""ate"; do
        if grep -Fq -- "$v" "$self"; then
            printf 'scope_violation\tverb %s\n' "$v"
            hits=$(( hits + 1 ))
        fi
    done
    printf 'scope\t%s\n' "$([[ $hits -eq 0 ]] && echo defence-only || echo VIOLATION)"
    printf 'scope_checked\t%d markers + 5 verb patterns\n' "${#markers[@]}"
    (( hits == 0 )) || return 1
    return 0
}

# ── status ──────────────────────────────────────────────────────────────
simd_cli_status_tsv() {
    printf 'module\tsim_defense\n'
    printf 'tag\tsimd\n'
    printf 'scope\tdefence and detection only\n'
    printf 'dir\t%s\n' "$SIMD_DIR"
    printf 'history_dir\t%s\n' "$SIMD_HISTORY_DIR"
    printf 'ef_ad_generations\t%s\n' "sim (TS 51.011 10.2.16) and usim (TS 31.102 4.2.18)"
    printf 'signals\t6\n'
    printf 'esim_state_model\t%s\n' "enabled|disabled|deleted (SGP.22)"
    printf 'reader\tnone required (no card access in any verb)\n'
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

    # 6. Scope: defence only, no template for contacting a carrier as somebody
    #    else, and no port-request verb.
    out=$(simd_scope_check); rc=$?
    chk scope-rc "$rc" "0"
    chk scope-status "$(fld "$out" scope)" "defence-only"
    chk scope-no-violation "$(printf '%s\n' "$out" | grep -c '^scope_violation')" "0"
    # and no port-request verb is dispatchable
    local badverb1="--port""-out" badverb2="--swap""-request"
    chk scope-verb-unknown "$(simd_cli_main "$badverb1" >/dev/null 2>&1; echo $?)" "2"
    chk scope-verb-swap "$(simd_cli_main "$badverb2" >/dev/null 2>&1; echo $?)" "2"

    # 7. Status invariants.
    out=$(simd_cli_status_tsv)
    chk status-scope "$(fld "$out" scope)" "defence and detection only"
    chk status-tag "$(fld "$out" tag)" "simd"

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
        echo -e "  ${C_MAG}=== SIM defence (detection / defence only) ===${C_RESET}"
        echo -e "  loot: ${C_DIM}$SIMD_DIR${C_RESET}\n"
        cat <<'M'
  [1]  list detection signals
  [2]  score a registration history (port-in-progress likelihood)
  [3]  parse EF_AD (2G or USIM layout)
  [4]  PIN / PUK retry-counter and ADM model
  [5]  parse an eSIM ProfileInfo (SGP.22)
  [6]  eSIM / RSP roles and the integrity question
  [7]  defence checklist
  [8]  scope check (defence only)
  [0]  back

M
        read -rp "  choice> " c || return 0  # EOF: leave the menu cleanly
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
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ── CLI dispatch ────────────────────────────────────────────────────────
simd_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)         simd_cli_status_tsv ;;
        --signals)            simd_signals ;;
        --score)              simd_score "${1:-}" ;;
        --ef-ad)              simd_ef_ad "${1:-}" "${2:-usim}" ;;
        --pin-state)          simd_pin_state ;;
        --esim-profile-parse) simd_esim_profile_parse "${1:-}" ;;
        --defence-checklist)  simd_defence_checklist ;;
        --selftest)           simd_selftest ;;
        --menu)               simd_menu ;;
        *)
            cat >&2 <<EOF
SIM Defence — detection and defence for a SIM port in flight (defence only)

Usage: $0 COMMAND
  --status-tsv                    module state as TSV
  --signals                       the six detection signals
  --score <history-tsv>           port-in-progress likelihood
  --ef-ad <hex> [sim|usim]        EF_AD in either layout
  --pin-state                     PIN/PUK retry counters and the ADM key
  --esim-profile-parse <hex>      SGP.22 ProfileInfo and profile state
  --defence-checklist             what a subscriber can enforce
  --selftest                      verify parsers and scoring, no card needed
  --menu                          interactive menu

Scope: this module detects and defends. It does not document how to port a
number, and the selftest asserts that no such content is present.
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
