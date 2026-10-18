#!/usr/bin/env bash
# Wi-Fi Offload / LWA — ePDG trust model, WFA certificates, LWA traffic steering
#
# Wi-Fi offload (IEEE 802.11) and LTE-WLAN Aggregation (LWA) extend cellular
# coverage using unlicensed spectrum. This module tests ePDG authentication,
# WFA certificate validation, and LWA traffic steering.
#
# Resolve IMSISTING_ROOT from this script's own path.
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

MOD_TMP="$TMP_DIR/wifioff"
WIFOFF_DIR="$LOOT_DIR/wifioff"
mkdir -p "$MOD_TMP" "$WIFOFF_DIR" 2>/dev/null

# Palette
C_RED=$'\e[38;5;196m'; C_GRN=$'\e[38;5;46m';   C_YEL=$'\e[38;5;226m'
C_CYN=$'\e[38;5;51m';  C_MAG=$'\e[38;5;201m';  C_BLU=$'\e[38;5;39m'
C_ORG=$'\e[38;5;208m'; C_PUR=$'\e[38;5;135m';  C_DIM=$'\e[38;5;240m'
C_WHT=$'\e[38;5;255m'; C_BOLD=$'\e[1m';        C_RESET=$'\e[0m'
export C_RED C_GRN C_YEL C_CYN C_MAG C_BLU C_ORG C_PUR C_DIM C_WHT C_BOLD C_RESET

declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
declare -F ok   >/dev/null 2>&1 || ok()   { printf '[ok]   %s\n' "$*" >&2; }
declare -F warn >/dev/null 2>&1 || warn() { printf '[warn] %s\n' "$*" >&2; }
declare -F err  >/dev/null 2>&1 || err()  { printf '[err]  %s\n' "$*" >&2; }

# ── hex + EAP framing ──────────────────────────────────────────────────
# ASCII -> uppercase hex, no separators.  od is POSIX, and reading the bytes
# back with `printf '%b'` is the only decoder used here.
wifioff_hex_of_string() {
    printf '%s' "$1" | od -An -v -tx1 | tr -d ' \n' | tr 'a-f' 'A-F'
}

# One EAP message (RFC 3748 §4): Code(1) Identifier(1) Length(2, big-endian)
# [Type(1)] [Data].  Length counts the whole message, so a Request/Response is
# 5 + len(Data) and a Success/Failure is 4 with neither Type nor Data.  Every
# field is range-checked before it is printed: `printf '%02X'` on a
# leading-zero string is an octal printf argument (MODULE_CONVENTIONS §15).
wifioff_eap_frame() {
    local code="$1" id="$2" type="${3:-}" data="${4:-}"
    local dlen=0 len hex

    [[ "$code" =~ ^(0|[1-9][0-9]{0,2})$ && "$id" =~ ^(0|[1-9][0-9]{0,2})$ ]] || {
        printf 'ERROR\tEAP Code and Identifier are decimal 0-255; got code="%s" id="%s"\n' "$code" "$id" >&2
        return 2
    }
    code=$(( 10#$code )); id=$(( 10#$id ))
    if (( code < 1 || code > 4 )); then
        printf 'ERROR\tEAP Code is 1 Request, 2 Response, 3 Success or 4 Failure; got %d\n' "$code" >&2
        return 2
    fi
    if (( id > 255 )); then
        printf 'ERROR\tEAP Identifier is one octet; got %d\n' "$id" >&2
        return 2
    fi

    if [[ -n "$data" ]]; then
        [[ "$data" =~ ^([0-9A-Fa-f]{2})+$ ]] || {
            printf 'ERROR\tEAP Data must be whole hex octets; got "%s"\n' "$data" >&2
            return 2
        }
        data=$(printf '%s' "$data" | tr 'a-f' 'A-F')
        dlen=$(( ${#data} / 2 ))
    fi

    if (( code <= 2 )); then
        [[ "$type" =~ ^(0|[1-9][0-9]{0,2})$ ]] && (( 10#$type >= 1 && 10#$type <= 255 )) || {
            printf 'ERROR\tan EAP Request/Response needs a Type octet 1-255; got "%s"\n' "$type" >&2
            return 2
        }
        type=$(( 10#$type ))
        len=$(( 5 + dlen ))
        if (( len > 65535 )); then
            printf 'ERROR\tEAP Length is two octets; %d octets do not fit\n' "$len" >&2
            return 2
        fi
        printf -v hex '%02X%02X%02X%02X%02X%s' "$code" "$id" \
            "$(( (len >> 8) & 0xFF ))" "$(( len & 0xFF ))" "$type" "$data"
    else
        if (( dlen != 0 )) || [[ -n "$type" ]]; then
            printf 'ERROR\tEAP Success/Failure carry no Type and no Data (RFC 3748); got type="%s" data="%s"\n' "$type" "$data" >&2
            return 2
        fi
        printf -v hex '%02X%02X%02X%02X' "$code" "$id" 0 4
    fi
    printf '%s\n' "$hex"
}

# ── status ──────────────────────────────────────────────────────────────
wifioff_status_tsv() {
    local tool_missing=()
    for t in python3 openssl; do
        command -v "$t" >/dev/null 2>&1 || tool_missing+=("$t")
    done
    local status=ok
    ((${#tool_missing[@]} > 0)) && status=missing
    printf 'STATUS\t%s\n' "$status"
    ((${#tool_missing[@]} > 0)) && printf 'MISSING\t%s\n' "$(IFS=,; echo "${tool_missing[*]}")"
}

# ── ePDG FQDN (3GPP TS 23.003, EPC node FQDN form) ─────────────────────
# epdg.epc.mnc<MNC>.mcc<MCC>.pub.3gppnetwork.org — the MNC field of this FQDN
# is three digits, so a 2-digit MNC is zero-padded, and the "pub" label is the
# operator-identifier form a UE actually resolves.
# MCC and MNC cannot be told apart in a bare digit string unless MCC's fixed
# 3-digit width is assumed, so only 5- and 6-digit PLMNs are decidable. Any
# other width is refused instead of sliced: the old code ran ${plmn:0:3} /
# ${plmn:3:3} on whatever it was handed and always produced a plausible name.
wifioff_epdg_fqdn() {
    local plmn="${1:-}" mcc mnc
    if [[ ! "$plmn" =~ ^[0-9]{5,6}$ ]]; then
        printf 'ERROR\t--epdg-fqdn needs the PLMN as 5 or 6 digits (MCC 3 + MNC 2 or 3); got "%s"\n' "$plmn" >&2
        return 2
    fi
    mcc="${plmn:0:3}"
    mnc="${plmn:3}"
    if (( ${#mnc} == 2 )); then mnc="0${mnc}"; fi
    printf 'epdg.epc.mnc%s.mcc%s.pub.3gppnetwork.org\n' "$mnc" "$mcc"
}

# ── certificate assertions ─────────────────────────────────────────────
# One CHECK row per assertion, each with the rule it is testing.  Nothing here
# is inferred from the certificate about itself, and no row is a bare verdict:
# what is not evaluated is printed as SKIP, never as PASS.
#   parse                      the file is a certificate openssl can read
#   not-expired                now < notAfter              (RFC 5280 §4.1.2.5)
#   not-yet-valid              now >= notBefore            (RFC 5280 §4.1.2.5)
#   san-present                subjectAltName is present, because the identity
#                              comes from subjectAltName and not from the CN,
#                              which RFC 6125 §6.4.4 deprecates for clients
#   san-matches-fqdn           exact case-insensitive DNS SAN match
#                              (RFC 6125 §6.4.1); no wildcard accepted, an
#                              ePDG name is a fixed name
#   keyUsage-digitalSignature  if keyUsage is present it allows
#                              digitalSignature (RFC 5280 §4.2.1.3, needed by
#                              a TLS 1.3 CertificateVerify, RFC 8446 §4.4.2.2)
#   eku-serverAuth             if extendedKeyUsage is present it contains
#                              serverAuth (RFC 5280 §4.2.1.12)
#   chain                      openssl verify against a CA bundle the caller
#                              supplies; SKIP, not PASS, when none is given
#   revocation                 always SKIP: no CRL or OCSP fetch happens here
#   profile-wfa-33.310         always SKIP: the Wi-Fi Alliance / 3GPP device
#                              certificate profile (policy OIDs, device
#                              identity) is not described in this file
wifioff_validate_cert() {
    local cert="${1:-}" ca="${2:-}" want="${3:-}"
    local npass=0 nfail=0 nskip=0 skipped=""
    local subj iss nb na serial san san_lines ku eku want_l info ext

    _wchk() {  # id, status, detail
        printf 'CHECK\t%s\t%s\t%s\n' "$1" "$2" "$3"
        case "$2" in
            PASS) npass=$(( npass + 1 )) ;;
            FAIL) nfail=$(( nfail + 1 )) ;;
            SKIP) nskip=$(( nskip + 1 )); skipped="${skipped:+$skipped,}$1" ;;
        esac
    }

    if [[ -z "$cert" ]]; then
        printf 'ERROR\t--validate-cert needs a certificate file: --validate-cert <cert.pem> [ca.pem] [expect-fqdn]\n' >&2
        return 2
    fi
    if [[ ! -f "$cert" || ! -r "$cert" ]]; then
        printf 'ERROR\tcannot read certificate file "%s"\n' "$cert" >&2
        return 2
    fi

    # One call for every identity/date field, and one for every extension the
    # assertions read, rather than six separate openssl startups.
    info=$(openssl x509 -in "$cert" -noout -subject -issuer -startdate -enddate -serial 2>/dev/null)
    subj=$(printf '%s\n' "$info" | sed -n 's/^subject=//p')
    if [[ -z "$subj" ]]; then
        printf 'ERROR\t"%s" is not a certificate openssl x509 can parse (PEM or DER expected)\n' "$cert" >&2
        return 2
    fi
    iss=$(printf '%s\n' "$info" | sed -n 's/^issuer=//p')
    nb=$(printf '%s\n' "$info" | sed -n 's/^notBefore=//p')
    na=$(printf '%s\n' "$info" | sed -n 's/^notAfter=//p')
    serial=$(printf '%s\n' "$info" | sed -n 's/^serial=//p')

    # openssl prints nothing for an absent extension (rc 0, "No extensions in
    # certificate" on stderr), so an empty block below means "absent", which
    # each check reports as SKIP or FAIL -- never as a pass.
    ext=$(openssl x509 -in "$cert" -noout -ext keyUsage,extendedKeyUsage,subjectAltName 2>/dev/null)
    _wext() {  # anchored header regex -> the indented values that belong to it
        printf '%s\n' "$ext" | awk -v re="$1" '
            /^X509v3 / { blk = ($0 ~ re); next }
            blk        { sub(/^[[:space:]]+/, ""); sub(/[[:space:]]+$/, ""); if (length) print }
        '
    }

    _wchk parse PASS "openssl x509 read it"
    printf 'INFO\tsubject\t%s\n' "$subj"
    printf 'INFO\tissuer\t%s\n' "$iss"
    printf 'INFO\tserial\t%s\n' "$serial"
    printf 'INFO\tnotBefore\t%s\n' "$nb"
    printf 'INFO\tnotAfter\t%s\n' "$na"

    # now < notAfter.  openssl is the oracle for "has expired".
    if openssl x509 -in "$cert" -noout -checkend 0 >/dev/null 2>&1; then
        _wchk not-expired PASS "now < notAfter ($na)"
    else
        _wchk not-expired FAIL "notAfter ($na) is in the past; the certificate is expired"
    fi

    # now >= notBefore.  Needs the date parsed; if date(1) cannot, say SKIP.
    local now nb_epoch
    now=$(date -u +%s)
    nb_epoch=$(date -u -d "$nb" +%s 2>/dev/null)
    if [[ -z "$nb_epoch" ]]; then
        _wchk not-yet-valid SKIP "date(1) cannot parse notBefore \"$nb\""
    elif (( now < nb_epoch )); then
        _wchk not-yet-valid FAIL "notBefore ($nb) is in the future; the certificate cannot be used yet"
    else
        _wchk not-yet-valid PASS "now >= notBefore ($nb)"
    fi

    san_lines=$(_wext '^X509v3 Subject Alternative Name:')
    san=$(printf '%s' "$san_lines" | tr '\n' ';' | sed 's/;$//')
    if [[ -n "$san" ]]; then
        _wchk san-present PASS "$san"
    else
        _wchk san-present FAIL "no subjectAltName extension: the identity could only come from the subject CN"
    fi

    if [[ -n "$want" ]]; then
        want_l="${want,,}"
        local hit="" seen="" line="" dns_list
        dns_list=$(printf '%s\n' "$san_lines" | tr ',' '\n' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | sed -n 's/^DNS://p')
        while IFS= read -r line; do
            [[ -n "$line" ]] || continue
            seen="${seen:+$seen,}$line"
            [[ "${line,,}" == "$want_l" ]] && hit="$line"
        done <<< "$dns_list"
        if [[ -n "$hit" ]]; then
            _wchk san-matches-fqdn PASS "DNS:$hit"
        else
            _wchk san-matches-fqdn FAIL "no DNS SAN equals \"$want\" (case-insensitive, exact; wildcards are not accepted); SANs present: ${seen:-none}"
        fi
    fi

    ku=$(_wext '^X509v3 Key Usage:' | tr '\n' ' ' | sed 's/ *$//')
    if [[ -z "$ku" ]]; then
        _wchk keyUsage-digitalSignature SKIP "no keyUsage extension: absent means unrestricted (RFC 5280 §4.2.1.3)"
    elif [[ "$ku" == *"Digital Signature"* ]]; then
        _wchk keyUsage-digitalSignature PASS "$ku"
    else
        _wchk keyUsage-digitalSignature FAIL "keyUsage present without digitalSignature, which a TLS 1.3 CertificateVerify needs: $ku"
    fi

    eku=$(_wext '^X509v3 Extended Key Usage:' | tr '\n' ' ' | sed 's/ *$//')
    if [[ -z "$eku" ]]; then
        _wchk eku-serverAuth SKIP "no extendedKeyUsage extension: absent means any purpose (RFC 5280 §4.2.1.12)"
    elif [[ "$eku" == *"TLS Web Server Authentication"* ]]; then
        _wchk eku-serverAuth PASS "$eku"
    else
        _wchk eku-serverAuth FAIL "extendedKeyUsage present without serverAuth: $eku"
    fi

    if [[ -n "$ca" ]]; then
        if [[ ! -f "$ca" || ! -r "$ca" ]]; then
            printf 'ERROR\tCA bundle "%s" is not readable\n' "$ca" >&2
            return 2
        fi
        local vout="" vrc=0
        vout=$(openssl verify -CAfile "$ca" "$cert" 2>&1)
        vrc=$?
        vout=$(printf '%s' "$vout" | tr '\n' ' ' | sed 's/ *$//')
        if (( vrc == 0 )); then
            _wchk chain PASS "$vout"
        else
            _wchk chain FAIL "$vout"
        fi
    else
        _wchk chain SKIP "no CA bundle given: nothing was verified about the issuer or the signature"
    fi

    _wchk revocation SKIP "not checked: needs a CRL, an OCSP responder or network access"
    _wchk profile-wfa-33.310 SKIP "the Wi-Fi Alliance / 3GPP TS 33.310 device-certificate profile (policy OIDs, device identity) is not described in this file"

    printf 'SUMMARY\t%d\t%d\t%d\n' "$npass" "$nfail" "$nskip"
    if (( nfail > 0 )); then
        printf 'RESULT\tFAIL(%d)\n' "$nfail"
        return 1
    fi
    printf 'RESULT\tPASS\n'
    if (( nskip > 0 )); then
        printf 'NOTCHECKED\t%s\n' "$skipped"
    fi
    return 0
}

# ── LWA: refuses, because this file has no LWA encoder ──────────────────
# Everything the old version printed here was either echoed back or a literal.
wifioff_lwa_config() {
    printf 'ERROR\t--lwa-config builds and parses no LWA frame, so it prints no configuration\n' >&2
    printf 'WHY\tLWA user plane (TS 36.360 / TS 36.361) rides in LWIP: the WLAN MAC address and the DRB-to-WLAN mapping travel inside the LTE RRC WLAN-Container (WLAN-Config-r12 / WLAN-Container-r12, TS 36.331), and the Xw-U tunnel carries LWIP PDUs whose encapsulation is a defined bit layout. XwAP (TS 36.463) is the control plane beside it. This file contains no encoder or decoder for either container, so any "configuration" it printed could only be input echoed back dressed up as a frame.\n' >&2
    printf 'WHY\tThe old output was not even a computation over its arguments: the frequencies were the literals "5.180 GHz" and "5.200 GHz" whichever channels were passed (channel 44 is 5220 MHz, not 5180), and "Aggregation: Enabled (LWA)" plus "Security: AES-GCM" were constants taken from no argument at all.\n' >&2
    printf 'NEXT\tto work on real LWA, feed an actual RRC WLAN-Container or an XwAP PDU from a capture to a dissector that implements TS 36.331 / TS 36.463, and read the container there\n' >&2
    return 3
}

# ── SWu EAP authentication flow (EAP-AKA, RFC 4187) ────────────────────
# What is modelled: an EPC ePDG reached over SWu, which is what a 15-digit
# LTE-shaped IMSI and this module's own PLMN handling describe.  EAP-AKA'
# (type 50, RFC 5448 / TS 33.501) is a different procedure and is named as
# such rather than relabelled.  The identity exchange is encoded for real;
# the AKA challenge needs K from the USIM or the AuC and is a handoff.
wifioff_auth_flow() {
    local imsi="${1:-001010000000000}" identity="${2:-}" method="${3:-aka}"
    local chal_type label spec req resp succ hx

    case "$method" in
        aka)       chal_type=23; label="EAP-AKA";  spec="RFC 4187" ;;
        aka-prime) chal_type=50; label="EAP-AKA prime"; spec="RFC 5448" ;;
        *) printf 'ERROR\t--auth-flow method is "aka" or "aka-prime"; got "%s"\n' "$method" >&2
           return 2 ;;
    esac
    if [[ ! "$imsi" =~ ^[0-9]{5,15}$ ]]; then
        printf 'ERROR\tIMSI is 5-15 decimal digits; got "%s"\n' "$imsi" >&2
        return 2
    fi
    [[ -n "$identity" ]] || identity="$imsi"
    # Printable ASCII, no spaces, checked byte-wise under LC_ALL=C: a regex
    # bracket range such as [!-~] is a *collating* range in a UTF-8 locale and
    # matches nothing there ([[ "abc" =~ ^[!-~]+$ ]] is false under
    # en_US.UTF-8), which would refuse every valid identity.
    if [[ -z "$identity" ]] || [[ -n "$(printf '%s' "$identity" | LC_ALL=C tr -d '[:graph:]')" ]]; then
        printf 'ERROR\tan EAP identity is printable ASCII with no spaces (an NAI, RFC 4282); got "%s"\n' "$identity" >&2
        return 2
    fi

    hx=$(wifioff_hex_of_string "$identity")
    req=$(wifioff_eap_frame 1 0 1 "")      || return 2
    resp=$(wifioff_eap_frame 2 0 1 "$hx")  || return 2
    succ=$(wifioff_eap_frame 3 0 "" "")    || return 2

    printf 'FLOW\t%s over SWu to an EPC ePDG\n' "$label"
    printf 'SPEC\t%s; EAP itself is RFC 3748\n' "$spec"
    printf 'WHY\t1\tthe ePDG is the EAP authenticator: the UE is the IKEv2 initiator and in EAP-over-IKEv2 the initiator is always the EAP peer (RFC 7296), so the ePDG answers as responder and relays to the 3GPP AAA server over SWm\n'
    printf 'WHY\t2\tthe authenticator sends the Requests and the peer sends the Responses (RFC 3748); Wireshark names Code 1 "Request" and Code 2 "Response" (field eap.code, tshark -G values)\n'
    printf 'IMSI\t%s\n' "$imsi"
    printf 'IDENTITY\t%s\n' "$identity"
    printf 'STEP\t1\tepdg->ue\tEAP-Request/Identity\t%s\n' "$req"
    printf 'STEP\t2\tue->epdg\tEAP-Response/Identity\t%s\n' "$resp"
    printf 'STEP\t3\tepdg->ue\tEAP-Request/AKA-Challenge (type %d, subtype 1)\tNOT-BUILT\n' "$chal_type"
    printf 'STEP\t4\tue->epdg\tEAP-Response/AKA-Challenge (type %d)\tNOT-BUILT\n' "$chal_type"
    printf 'STEP\t5\tepdg->ue\tEAP-Success\t%s\n' "$succ"
    printf 'NOTE\t2\tthe identity octets are the string given on the command line, verbatim; the NAI decoration ("<imsi>@nai.epc...") depends on PLMN selection and is not synthesised here\n'
    printf 'NOTE\t3\tnot built: the challenge body is AT_RAND (16 octets) + AT_AUTN (16) + AT_MAC (5 + 16), and AT_MAC is HMAC-SHA1-128 keyed with K (RFC 4187 §10.15); K lives in the USIM or the AuC\n'
    printf 'NOTE\t5\tEAP-Success is four octets with no Type and no Data (RFC 3748); it is shown because its header is fully determined, not as a claim that authentication succeeded\n'
    if [[ "$method" == aka-prime ]]; then
        printf 'SCOPE\tEAP-AKA prime challenge not built: RFC 5448 changes the key derivation and needs the same K as EAP-AKA, so only the identity step above is modelled for it\n'
    else
        printf 'SCOPE\tEAP-AKA prime (type 50, RFC 5448 / TS 33.501) is a different procedure and is NOT modelled here: --auth-flow ... aka-prime prints its type number and the identity step, nothing more\n'
    fi
    printf 'status\thandoff\n'
    printf 'HARDWARE\tan ePDG (IKEv2 responder) plus either a USIM holding K/SEQ or an HSS/AuC holding the subscriber key; neither is present in this environment\n'
    printf 'PLAN\tcomplete steps 3-4 with the real credentials, or dissect a capture instead -- Wireshark decodes the EAP-AKA attributes (field eap.aka.*)\n'
}

# ── Cert thumbprint extraction (for debugging) ─────────────────────────
wifioff_cert_thumbprint() {
    local cert_path="${1:-}" fp
    if [[ -z "$cert_path" ]]; then
        printf 'ERROR\tusage: --cert-thumb <cert.pem>\n' >&2
        return 2
    fi
    if [[ ! -f "$cert_path" || ! -r "$cert_path" ]]; then
        printf 'ERROR\tcannot read certificate file "%s"\n' "$cert_path" >&2
        return 2
    fi
    fp=$(openssl x509 -in "$cert_path" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)
    if [[ -z "$fp" ]]; then
        printf 'ERROR\t"%s" is not a certificate openssl x509 can parse\n' "$cert_path" >&2
        return 2
    fi
    printf 'SHA256\t%s\n' "$fp"
    printf 'SUBJECT\t%s\n' "$(openssl x509 -in "$cert_path" -noout -subject 2>/dev/null | sed 's/^subject=//')"
}

# ── Selftest ───────────────────────────────────────────────────────────
wifioff_selftest() {
    local bad=0 nchk=0
    chk() {
        nchk=$(( nchk + 1 ))
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$(( bad + 1 )); fi
    }

    # Scratch state, redirected away from the real stores (MODULE_CONVENTIONS §7)
    local old_trap td
    old_trap=$(trap -p EXIT)
    td=$(mktemp -d "${TMP_DIR:-/tmp}/wifioff-st.XXXXXX") || { printf 'RESULT\tFAIL(mktemp)\n'; return 1; }
    WIFIOFF_ST_TMP="$td"
    trap 'rm -rf -- "${WIFIOFF_ST_TMP:-}"' EXIT
    local LOOT_DIR="$td/loot" CAPTURES_DIR="$td/captures" STATE_DIR="$td/state"
    mkdir -p "$LOOT_DIR" "$CAPTURES_DIR" "$STATE_DIR" 2>/dev/null
    export LOOT_DIR CAPTURES_DIR STATE_DIR

    # ── ePDG FQDN ───────────────────────────────────────────────────────
    # Expected values from 3GPP TS 23.003's EPC node-FQDN form, the same
    # vectors 36_vowifi.sh carries: mnc260.mcc310, and a 2-digit MNC padded
    # to mnc015.
    chk epdg-fqdn-mcc310-mnc260 "$(wifioff_epdg_fqdn 310260)" "epdg.epc.mnc260.mcc310.pub.3gppnetwork.org"
    chk epdg-fqdn-mnc-padded    "$(wifioff_epdg_fqdn 23415)"  "epdg.epc.mnc015.mcc234.pub.3gppnetwork.org"
    chk epdg-fqdn-pub-label     "$(wifioff_epdg_fqdn 20801 | cut -d. -f5)" "pub"
    chk epdg-fqdn-short-rc      "$(wifioff_epdg_fqdn 2080 >/dev/null 2>&1; printf '%s' "$?")" 2
    chk epdg-fqdn-long-rc       "$(wifioff_epdg_fqdn 2080111 >/dev/null 2>&1; printf '%s' "$?")" 2
    chk epdg-fqdn-alpha-rc      "$(wifioff_epdg_fqdn 20A01 >/dev/null 2>&1; printf '%s' "$?")" 2
    chk epdg-fqdn-refusal-quiet "$(wifioff_epdg_fqdn 2080 2>/dev/null | wc -c | tr -d ' ')" 0

    # ── EAP framing, expected values dissected by Wireshark 4.2.2 ───────
    # Each hex string below was fed to tshark as an EAPOL/EAP frame and read
    # back with -T fields -e eap.code -e eap.id -e eap.len -e eap.type, so
    # the Code/Identifier/Length/Type interpretation is Wireshark's, not this
    # file's.  0101000501 -> code 1, id 1, len 5, type 1 (Request/Identity);
    # 03010004 -> code 3, len 4, no type (Success); 04010004 -> Failure;
    # the 54-octet NAI below -> code 2, id 1, len 59, type 1, identity.full
    # equals the NAI; a 300-octet identity -> len 305 (0x0131).
    chk eap-req-identity-hex  "$(wifioff_eap_frame 1 1 1 "")" "0101000501"
    chk eap-success-hex       "$(wifioff_eap_frame 3 1 "" "")" "03010004"
    chk eap-failure-hex       "$(wifioff_eap_frame 4 1 "" "")" "04010004"
    local nai="0001010000000000@nai.epc.mnc001.mcc208.3gppnetwork.org"
    local rh; rh=$(wifioff_eap_frame 2 1 1 "$(wifioff_hex_of_string "$nai")")
    chk eap-resp-identity-header  "${rh:0:10}" "0201003B01"
    chk eap-resp-identity-length  "$(( ${#rh} / 2 ))" 59
    chk eap-resp-identity-payload "$(printf '%b' "$(printf '%s' "${rh:10}" | sed 's/\(..\)/\\x\1/g')")" "$nai"
    local long_id; long_id=$(wifioff_hex_of_string "$(printf 'A%.0s' $(seq 1 300))")
    chk eap-length-16bit "$(wifioff_eap_frame 2 7 1 "$long_id" | cut -c1-10)" "0207013101"
    chk eap-bad-code-rc        "$(wifioff_eap_frame 5 0 1 "" >/dev/null 2>&1; printf '%s' "$?")" 2
    chk eap-success-with-type  "$(wifioff_eap_frame 3 0 1 "" >/dev/null 2>&1; printf '%s' "$?")" 2
    chk eap-odd-hex-rc         "$(wifioff_eap_frame 2 0 1 "ABC" >/dev/null 2>&1; printf '%s' "$?")" 2

    # ── auth flow shape and direction ───────────────────────────────────
    local flow; flow=$(wifioff_auth_flow "001010000000000" "" aka)
    chk flow-step1-direction "$(awk -F'\t' '$1=="STEP" && $2==1 {print $3}' <<<"$flow")" "epdg->ue"
    chk flow-step2-direction "$(awk -F'\t' '$1=="STEP" && $2==2 {print $3}' <<<"$flow")" "ue->epdg"
    chk flow-step1-hex       "$(awk -F'\t' '$1=="STEP" && $2==1 {print $5}' <<<"$flow")" "0100000501"
    chk flow-step2-hex       "$(awk -F'\t' '$1=="STEP" && $2==2 {print substr($5,1,8)}' <<<"$flow")" "02000014"
    chk flow-no-ue-request   "$(awk -F'\t' '$1=="STEP" && $3=="ue->epdg" && $4 ~ /Request/ {n++} END{print n+0}' <<<"$flow")" 0
    chk flow-no-epdg-response "$(awk -F'\t' '$1=="STEP" && $3=="epdg->ue" && $4 ~ /Response/ {n++} END{print n+0}' <<<"$flow")" 0
    chk flow-aka-type23      "$(awk -F'\t' '$1=="STEP" && $2==3 {print $4}' <<<"$flow" | grep -c 'type 23')" 1
    chk flow-challenge-unbuilt "$(awk -F'\t' '$1=="STEP" && ($2==3 || $2==4) {print $5}' <<<"$flow" | grep -c 'NOT-BUILT')" 2
    chk flow-status-handoff  "$(awk -F'\t' '$1=="status" {print $2}' <<<"$flow")" "handoff"
    chk flow-hardware-named  "$(awk -F'\t' '$1=="HARDWARE"' <<<"$flow" | grep -c 'USIM')" 1
    local flowp; flowp=$(wifioff_auth_flow "001010000000000" "" aka-prime)
    chk flow-prime-type50    "$(awk -F'\t' '$1=="STEP" && $2==3 {print $4}' <<<"$flowp" | grep -c 'type 50')" 1
    chk flow-prime-labelled  "$(awk -F'\t' '$1=="FLOW" {print $2}' <<<"$flowp")" "EAP-AKA prime over SWu to an EPC ePDG"
    chk flow-bad-method-rc   "$(wifioff_auth_flow 001010000000000 "" eap-tls >/dev/null 2>&1; printf '%s' "$?")" 2
    chk flow-bad-identity-rc "$(wifioff_auth_flow 001010000000000 "0010@ex ample" >/dev/null 2>&1; printf '%s' "$?")" 2
    chk flow-bad-imsi-rc     "$(wifioff_auth_flow 00101000000000X >/dev/null 2>&1; printf '%s' "$?")" 2

    # ── LWA refusal ─────────────────────────────────────────────────────
    local lout lrc
    lout=$(wifioff_lwa_config "aa:bb:cc:dd:ee:ff" 44 48 2>&1); lrc=$?
    chk lwa-refuse-rc      "$lrc" 3
    chk lwa-refuse-error   "$(printf '%s\n' "$lout" | grep -c '^ERROR')" 1
    chk lwa-refuse-why     "$(printf '%s\n' "$lout" | grep -c '^WHY')" 2
    chk lwa-no-echoed-mac  "$(printf '%s\n' "$lout" | grep -c 'aa:bb')" 0
    chk lwa-no-config-body "$(printf '%s\n' "$lout" | grep -c 'Primary Channel')" 0

    # ── certificates: fixtures built here, so nothing about the host is
    #    assumed (MODULE_CONVENTIONS §13) ────────────────────────────────
    if command -v openssl >/dev/null 2>&1; then
        local ca="$td/ca" san="epdg.epc.mnc001.mcc208.pub.3gppnetwork.org"
        mkdir -p "$ca/newcerts" 2>/dev/null
        : > "$ca/index.txt"; printf '1000\n' > "$ca/serial"
        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -keyout "$ca/ca.key" -out "$ca/ca.pem" -days 3650 -nodes \
            -subj "/CN=wifioff selftest CA" -addext "basicConstraints=critical,CA:TRUE" \
            -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1
        cat > "$ca/ca.cnf" <<CNF
[ca]
default_ca = CA_default
[CA_default]
dir = $ca
database = \$dir/index.txt
serial = \$dir/serial
new_certs_dir = \$dir/newcerts
certificate = \$dir/ca.pem
private_key = \$dir/ca.key
default_md = sha256
default_days = 365
policy = policy_any
copy_extensions = copy
[policy_any]
commonName = supplied
CNF
        openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -keyout "$ca/k.key" -out "$ca/good.csr" -nodes \
            -subj "/CN=$san" -addext "subjectAltName=DNS:$san" \
            -addext "keyUsage=critical,digitalSignature" \
            -addext "extendedKeyUsage=serverAuth" >/dev/null 2>&1
        openssl ca -batch -config "$ca/ca.cnf" -in "$ca/good.csr" -out "$ca/good.pem" -notext >/dev/null 2>&1
        openssl req -new -key "$ca/k.key" -out "$ca/exp.csr" -subj "/CN=expired.$san" \
            -addext "subjectAltName=DNS:$san" >/dev/null 2>&1
        openssl ca -batch -config "$ca/ca.cnf" -in "$ca/exp.csr" -out "$ca/expired.pem" \
            -startdate 200101000000Z -enddate 200201000000Z -notext >/dev/null 2>&1
        openssl req -new -key "$ca/k.key" -out "$ca/fut.csr" -subj "/CN=future.$san" \
            -addext "subjectAltName=DNS:$san" >/dev/null 2>&1
        openssl ca -batch -config "$ca/ca.cnf" -in "$ca/fut.csr" -out "$ca/future.pem" \
            -startdate 300101000000Z -enddate 310101000000Z -notext >/dev/null 2>&1
        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -keyout "$ca/o.key" -out "$ca/other.pem" -days 365 -nodes \
            -subj "/CN=$san" -addext "subjectAltName=DNS:$san" >/dev/null 2>&1
        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -keyout "$ca/n.key" -out "$ca/nosan.pem" -days 365 -nodes \
            -subj "/CN=$san" >/dev/null 2>&1

        cstat() { awk -F'\t' -v id="$1" '$1=="CHECK" && $2==id {print $3}' <<<"$2"; }

        local out rc
        out=$(wifioff_validate_cert "$ca/good.pem" "$ca/ca.pem" "$san" 2>&1); rc=$?
        chk cert-good-rc          "$rc" 0
        chk cert-good-parse       "$(cstat parse "$out")" PASS
        chk cert-good-dates       "$(cstat not-expired "$out")/$(cstat not-yet-valid "$out")" "PASS/PASS"
        chk cert-good-san         "$(cstat san-present "$out")" PASS
        chk cert-good-san-match   "$(cstat san-matches-fqdn "$out")" PASS
        chk cert-good-ku          "$(cstat keyUsage-digitalSignature "$out")" PASS
        chk cert-good-eku         "$(cstat eku-serverAuth "$out")" PASS
        chk cert-good-chain       "$(cstat chain "$out")" PASS
        chk cert-revocation-skip  "$(cstat revocation "$out")" SKIP
        chk cert-profile-skip     "$(cstat profile-wfa-33.310 "$out")" SKIP
        chk cert-notchecked-listed "$(printf '%s\n' "$out" | grep -c '^NOTCHECKED.*revocation')" 1
        chk cert-no-bare-valid    "$(printf '%s\n' "$out" | grep -ci 'status:[[:space:]]*valid')" 0

        out=$(wifioff_validate_cert "$ca/good.pem" 2>&1); rc=$?
        chk cert-no-ca-rc         "$rc" 0
        chk cert-no-ca-chain-skip "$(cstat chain "$out")" SKIP

        out=$(wifioff_validate_cert "$ca/expired.pem" "$ca/ca.pem" 2>&1); rc=$?
        chk cert-expired-rc     "$rc" 1
        chk cert-expired-status "$(cstat not-expired "$out")" FAIL

        out=$(wifioff_validate_cert "$ca/future.pem" "$ca/ca.pem" 2>&1); rc=$?
        chk cert-future-rc     "$rc" 1
        chk cert-future-status "$(cstat not-yet-valid "$out")" FAIL

        out=$(wifioff_validate_cert "$ca/other.pem" "$ca/ca.pem" 2>&1); rc=$?
        chk cert-wrong-issuer-rc    "$rc" 1
        chk cert-wrong-issuer-chain "$(cstat chain "$out")" FAIL

        out=$(wifioff_validate_cert "$ca/good.pem" "" "epdg.epc.mnc260.mcc310.pub.3gppnetwork.org" 2>&1); rc=$?
        chk cert-fqdn-mismatch-rc "$rc" 1
        chk cert-fqdn-mismatch    "$(cstat san-matches-fqdn "$out")" FAIL

        out=$(wifioff_validate_cert "$ca/nosan.pem" 2>&1)
        chk cert-nosan-present "$(cstat san-present "$out")" FAIL
        chk cert-nosan-ku-skip "$(cstat keyUsage-digitalSignature "$out")" SKIP
        chk cert-nosan-eku-skip "$(cstat eku-serverAuth "$out")" SKIP

        chk cert-noarg-rc   "$(wifioff_validate_cert >/dev/null 2>&1; printf '%s' "$?")" 2
        chk cert-missing-rc "$(wifioff_validate_cert "$td/nope.pem" >/dev/null 2>&1; printf '%s' "$?")" 2
        printf 'not a certificate\n' > "$td/garbage.pem"
        chk cert-garbage-rc "$(wifioff_validate_cert "$td/garbage.pem" >/dev/null 2>&1; printf '%s' "$?")" 2

        # thumbprint: the column-free sha256 of the DER encoding is an
        # independent second reader of the same octets
        local fp der
        fp=$(wifioff_cert_thumbprint "$ca/good.pem" 2>/dev/null | awk -F'\t' '$1=="SHA256" {print $2}')
        der=$(openssl x509 -in "$ca/good.pem" -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1 \
            | tr 'a-f' 'A-F' | sed 's/../&:/g; s/:$//')
        chk thumb-matches-der "$fp" "$der"
        chk thumb-hex-len     "$(printf '%s' "$fp" | tr -d ':' | wc -c | tr -d ' ')" 64
        chk thumb-missing-rc  "$(wifioff_cert_thumbprint "$td/nope.pem" >/dev/null 2>&1; printf '%s' "$?")" 2
    else
        printf 'SKIP\tcert-assertions (openssl not on PATH)\n'
    fi

    # The epoch for 2020-01-01T00:00:00Z is 1577836800 by definition of Unix
    # time; this pins the date(1) parse the not-yet-valid check relies on.
    if [[ "$(date -u -d '1970-01-01T00:00:00Z' +%s 2>/dev/null)" == 0 ]]; then
        chk date-parse-of-openssl-form "$(date -u -d 'Jan  1 00:00:00 2020 GMT' +%s 2>/dev/null)" 1577836800
    else
        printf 'SKIP\tdate-parse-of-openssl-form (date -d unavailable)\n'
    fi

    rm -rf -- "$td" 2>/dev/null
    WIFIOFF_ST_TMP=""
    trap - EXIT
    [[ -n "$old_trap" ]] && eval "$old_trap"

    printf 'ASSERTIONS\t%d\n' "$nchk"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ── menu ───────────────────────────────────────────────────────────────
wifioff_menu() {
    while true; do
        banner
        echo -e "  ${C_MAG}=== Wi-Fi Offload / LWA ===${C_RESET}\n"
        cat << 'M'
  [1]  ePDG FQDN for PLMN
  [2]  Validate certificate (stated assertions, with a CA bundle and a name)
  [3]  LWA configuration — refuses, no LWA codec in this file
  [4]  Show EAP-AKA auth flow (what is encoded, what is handoff)
  [5]  Certificate thumbprint
  [0]  back

M
        read -rp "  choice> " c || return 0
        case "$c" in
            1)
                read -rp "  PLMN (MCC+MNC, 5 or 6 digits)> " p
                wifioff_epdg_fqdn "$p"
                read -rp "  press enter " _ ;;
            2)
                read -rp "  cert path> " f
                read -rp "  CA bundle (blank for none)> " b
                read -rp "  name to match (blank for none)> " n
                wifioff_validate_cert "$f" "$b" "$n"; read -rp "  press enter " _ ;;
            3)
                wifioff_lwa_config; read -rp "  press enter " _ ;;
            4)
                read -rp "  IMSI> " i
                read -rp "  identity/NAI (blank = the IMSI)> " n
                read -rp "  method [aka|aka-prime]> " m
                wifioff_auth_flow "$i" "$n" "${m:-aka}"; read -rp "  press enter " _ ;;
            5)
                read -rp "  cert path> " f
                wifioff_cert_thumbprint "$f"; read -rp "  press enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ── CLI dispatch ───────────────────────────────────────────────────────
wifioff_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)    wifioff_status_tsv ;;
        --epdg-fqdn)     wifioff_epdg_fqdn "${1:-20801}" ;;
        --validate-cert) wifioff_validate_cert "${1:-}" "${2:-}" "${3:-}" ;;
        --lwa-config)    wifioff_lwa_config ;;
        --auth-flow)     wifioff_auth_flow "${1:-001010000000000}" "${2:-}" "${3:-}" ;;
        --cert-thumb)    wifioff_cert_thumbprint "${1:-}" ;;
        --selftest)      wifioff_selftest ;;
        --menu)          wifioff_menu ;;
        *) cat >&2 <<EOF
Wi-Fi Offload / LWA — ePDG trust model, certificate assertions, LWA refusal

Usage: $0 COMMAND
  --status-tsv                     tool state as TSV
  --epdg-fqdn [plmn]               ePDG FQDN from MCC+MNC (5 or 6 digits)
  --validate-cert <cert> [ca] [name]
                                   stated assertions; then a CA bundle and a
                                   name to match, each optional
  --lwa-config                     refuses: no LWA/LWIP codec in this module
  --auth-flow [imsi] [identity] [aka|aka-prime]
                                   EAP identity exchange, byte for byte
  --cert-thumb <cert.pem>          SHA-256 of the certificate
  --selftest                       known-answer and refusal tests
  --menu                           interactive menu
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
    wifioff_cli_main "$@"
fi
