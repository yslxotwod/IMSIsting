#!/usr/bin/env bash
# vowifi — VoWiFi / ePDG: IKEv2 over SWu, EAP-AKA, and the tunnel to the EPC.
#
# Voice over Wi-Fi reaches the EPC through an ePDG, over the SWu reference
# point: IKEv2 (RFC 7296) carrying EAP-AKA (RFC 4187) to authenticate the USIM,
# then an IPsec child SA for the user plane. This module builds and decodes
# those messages, derives the identifiers the UE presents, and detects a
# downgraded or null-ciphered tunnel. It performs no over-the-air step.
#
# Attack owned: O12 adjacency (IMP4GT identity mapping) and the VoWiFi half of
# the IMS surface; the keystream half lives in 30_volte_ims per ATTACK_COVERAGE.
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

MOD_TMP="$TMP_DIR/vowifi"
VOWI_DIR="$LOOT_DIR/vowifi"
mkdir -p "$MOD_TMP" "$VOWI_DIR" 2>/dev/null

declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
declare -F warn >/dev/null 2>&1 || warn() { printf '[warn] %s\n' "$*" >&2; }
declare -F err  >/dev/null 2>&1 || err()  { printf '[err]  %s\n' "$*" >&2; }
declare -F ok   >/dev/null 2>&1 || ok()   { printf '[ok]   %s\n' "$*" >&2; }
declare -F banner >/dev/null 2>&1 || banner() { :; }

vowi_sanitize() { printf '%s' "${1:-}" | tr '\t\r\n' '   '; }
VOWI_F=()
vowi_split() {
    VOWI_F=()
    local i n
    n=$(printf '%s' "$1" | awk -F'\t' '{print NF}')
    for (( i = 1; i <= n; i++ )); do
        VOWI_F+=("$(printf '%s' "$1" | cut -f"$i")")
    done
}
vowi_norm_hex() { printf '%s' "${1:-}" | tr -d ' \t\r\n:.-' | sed 's/^0x//I' | tr 'A-F' 'a-f'; }
vowi_is_hex() {
    local h; h=$(vowi_norm_hex "${1:-}")
    [[ -n "$h" && "$h" =~ ^[0-9a-f]+$ && $(( ${#h} % 2 )) -eq 0 ]]
}
vowi_byte() { printf '%02X' "$(( ${1:-0} & 0xFF ))"; }

vowi_status_tsv() {
    printf 'MODULE\tvowifi\n'
    printf 'TARGET\tIKEv2/SWu to the ePDG, EAP-AKA, IPsec child SA\n'
    printf 'PORTS\tUDP/500, UDP/4500 (NAT-T)\n'
    printf 'TRANSMIT\tnone — encode/decode and detection only\n'
    printf 'SELFTEST\tyes\n'
}

# ── IKEv2 header (RFC 7296 §3.1) ────────────────────────────────────────
#   initiator SPI 8 | responder SPI 8 | next payload 1 | version 1 (0x20)
#   exchange type 1 | flags 1 | message id 4 | length 4   => 28 octets
vowi_ike_types() {
    cat <<'EOF'
kind	value	name
exchange	34	IKE_SA_INIT
exchange	35	IKE_AUTH
exchange	36	CREATE_CHILD_SA
exchange	37	INFORMATIONAL
payload	33	SA
payload	34	KE
payload	35	IDi
payload	36	IDr
payload	39	AUTH
payload	40	Ni
payload	41	Nr
payload	42	N
payload	43	D
payload	44	V
payload	45	TSi
payload	46	TSr
payload	47	SK
payload	48	CP
payload	49	EAP
EOF
}

vowi_ike_name() {
    case "$1" in
        34) echo "IKE_SA_INIT" ;; 35) echo "IKE_AUTH" ;;
        36) echo "CREATE_CHILD_SA" ;; 37) echo "INFORMATIONAL" ;;
        *) echo "unknown-or-payload-type" ;;
    esac
}

vowi_ike_build() {
    local ispi; ispi=$(vowi_norm_hex "${1:-1122334455667788}")
    local rspi; rspi=$(vowi_norm_hex "${2:-0000000000000000}")
    local next="${3:-33}" exch="${4:-34}" flags="${5:-8}" mid; mid=$(vowi_norm_hex "${6:-00000000}")
    [[ ${#ispi} -eq 16 && ${#rspi} -eq 16 && ${#mid} -eq 8 ]] || {
        printf 'ERROR\tSPIs must be 8 octets and message id 4 octets of hex\n' >&2; return 2; }
    printf '%s%s%s20%s%s%s%08X' "$ispi" "$rspi" "$(vowi_byte "$next")" \
        "$(vowi_byte "$exch")" "$(vowi_byte "$flags")" "$mid" 28
}

vowi_ike_parse() {
    local h; h=$(vowi_norm_hex "${1:-}")
    vowi_is_hex "$h" || { printf 'ERROR\tnot valid hex\n' >&2; return 2; }
    (( ${#h} >= 56 )) || { printf 'ERROR\tIKEv2 header is 28 octets\n' >&2; return 1; }
    local ispi="${h:0:16}" rspi="${h:16:16}"
    local next=$(( 16#${h:32:2} )) ver=$(( 16#${h:34:2} ))
    local exch=$(( 16#${h:36:2} )) flags=$(( 16#${h:38:2} ))
    local mid=$(( 16#${h:40:8} )) len=$(( 16#${h:48:8} ))
    printf 'initiator_spi\t%s\nresponder_spi\t%s\nnext_payload\t%d\nversion\t0x%02X\n' \
        "$ispi" "$rspi" "$next" "$ver"
    printf 'exchange_type\t%d\nexchange_name\t%s\nflags\t0x%02X\n' \
        "$exch" "$(vowi_ike_name "$exch")" "$flags"
    printf 'initiator\t%s\nmessage_id\t%d\nlength_field\t%d\n' \
        "$([[ $(( flags & 0x08 )) -ne 0 ]] && echo yes || echo no)" "$mid" "$len"
    (( ver == 0x20 )) || printf 'version_alert\tnot IKEv2 (version octet 0x%02X)\n' "$ver"
}

# Walk a payload chain: each generic payload header is next(1) flags(1) len(2).
vowi_payload_walk() {
    local h; h=$(vowi_norm_hex "${1:-}")
    local start="${2:-33}"
    vowi_is_hex "$h" || { printf 'ERROR\tnot valid hex\n' >&2; return 2; }
    local off=0 nt="$start"
    printf 'order\tpayload_type\tname\n'
    local guard=0
    while (( nt != 0 )); do
        (( guard++ > 64 )) && { printf 'ERROR\tpayload chain did not terminate\n' >&2; return 1; }
        (( off * 2 + 4 <= ${#h} )) || { printf 'ERROR\ttruncated payload at octet %d\n' "$off" >&2; return 1; }
        local nxt=$(( 16#${h:$(( off*2 )):2} ))
        local plen=$(( 16#${h:$(( off*2 + 4 )):4} ))
        printf '%d\t%d\t%s\n' "$off" "$nt" "$(vowi_payload_name "$nt")"
        (( plen <= 0 )) && { printf 'ERROR\tzero-length payload — would loop\n' >&2; return 1; }
        off=$(( off + plen )); nt=$nxt
    done
}
vowi_payload_name() {
    case "$1" in
        33) echo SA ;; 34) echo KE ;; 35) echo IDi ;; 36) echo IDr ;;
        39) echo AUTH ;; 40) echo Ni ;; 41) echo Nr ;; 42) echo N ;; 43) echo D ;;
        44) echo V ;; 45) echo TSi ;; 46) echo TSr ;; 47) echo SK ;; 48) echo CP ;; 49) echo EAP ;;
        *) echo unknown ;;
    esac
}

# ── EAP-AKA (RFC 4187 §10) ──────────────────────────────────────────────
vowi_eap_aka() {
    local code="${1:-1}" id="${2:-1}" subtype="${3:-1}"
    local eap_type=23
    printf '%02X%02X%04X%02X%02X' "$(vowi_byte "$code")" "$(vowi_byte "$id")" "8" "$eap_type" "$(vowi_byte "$subtype")"
}
vowi_eap_name() {
    case "$1" in 1) echo "Request" ;; 2) echo "Response" ;; 3) echo "Success" ;; 4) echo "Failure" ;; *) echo unknown ;; esac
}
vowi_aka_subtype_name() {
    case "$1" in
        1) echo "Challenge" ;; 2) echo "Authentication-Response" ;; 3) echo "Synchronization-Failure" ;;
        4) echo "Identity" ;; 5) echo "Notification" ;; 6) echo "Re-authentication" ;; 12) echo "Client-Error" ;;
        *) echo unknown ;;
    esac
}
vowi_eap_parse() {
    local h; h=$(vowi_norm_hex "${1:-}")
    vowi_is_hex "$h" || { printf 'ERROR\tnot valid hex\n' >&2; return 2; }
    (( ${#h} >= 10 )) || { printf 'ERROR\tEAP-AKA packet too short\n' >&2; return 1; }
    local code=$(( 16#${h:0:2} )) id=$(( 16#${h:2:2} ))
    local len=$(( 16#${h:4:4} )) typ=$(( 16#${h:8:2} ))
    (( typ == 23 )) || { printf 'ERROR\tnot EAP-AKA (type %d, expected 23)\n' "$typ" >&2; return 1; }
    local sub=$(( 16#${h:10:2} ))
    printf 'code\t%d\ncode_name\t%s\nid\t%d\nlength\t%d\ntype\t%d\nsubtype\t%d\nsubtype_name\t%s\n' \
        "$code" "$(vowi_eap_name "$code")" "$id" "$len" "$typ" "$sub" "$(vowi_aka_subtype_name "$sub")"
}

# ── identifiers (TS 23.003) ─────────────────────────────────────────────
vowi_nai() {
    local imsi="${1:-}" mcc="${2:-}" mnc="${3:-}"
    [[ "$imsi" =~ ^[0-9]{6,15}$ ]] || { printf 'ERROR\tIMSI must be 6..15 digits\n' >&2; return 2; }
    [[ "$mcc" =~ ^[0-9]{3}$ ]] || { printf 'ERROR\tMCC is 3 digits\n' >&2; return 2; }
    [[ "$mnc" =~ ^[0-9]{2,3}$ ]] || { printf 'ERROR\tMNC is 2 or 3 digits\n' >&2; return 2; }
    local mnc3; mnc3=$(printf '%03d' "$mnc")
    printf '0%s@nai.epc.mnc%s.mcc%s.3gppnetwork.org\n' "$imsi" "$mnc3" "$mcc"
}
vowi_epdg_fqdn() {
    local mcc="${1:-}" mnc="${2:-}"
    [[ "$mcc" =~ ^[0-9]{3}$ && "$mnc" =~ ^[0-9]{2,3}$ ]] || {
        printf 'ERROR\tneed a 3-digit MCC and a 2/3-digit MNC\n' >&2; return 2; }
    printf 'epdg.epc.mnc%03d.mcc%s.pub.3gppnetwork.org\n' "$mnc" "$mcc"
}

# ── transform safety (RFC 7296 §3.3.2, IANA IKEv2 transforms) ──────────
vowi_encr_classify() {
    local id="${1:-}"
    [[ "$id" =~ ^[0-9]+$ ]] || { printf 'ERROR\ttransform id must be numeric\n' >&2; return 2; }
    local name verdict
    case "$id" in
        11) name="ENCR_NULL"; verdict="weak — no confidentiality" ;;
        21) name="ENCR_NULL_AUTH_AES_GMAC"; verdict="weak — null encryption, integrity only" ;;
        3)  name="ENCR_3DES"; verdict="legacy — 64-bit block, deprecated" ;;
        12) name="ENCR_AES_CBC"; verdict="ok" ;;
        13) name="ENCR_AES_CTR"; verdict="ok" ;;
        20) name="ENCR_AES_GCM_16"; verdict="ok" ;;
        28) name="ENCR_CHACHA20_POLY1305"; verdict="ok" ;;
        2)  name="ENCR_DES"; verdict="weak — DES" ;;
        5)  name="ENCR_IDEA"; verdict="weak — IDEA" ;;
        *)  name="unknown"; verdict="unknown — never scored as ok" ;;
    esac
    printf 'transform_id\t%d\nname\t%s\nverdict\t%s\n' "$id" "$name" "$verdict"
}
vowi_integrity_classify() {
    local id="${1:-}"
    [[ "$id" =~ ^[0-9]+$ ]] || { printf 'ERROR\ttransform id must be numeric\n' >&2; return 2; }
    local name verdict
    case "$id" in
        0)  name="NONE"; verdict="weak — no integrity" ;;
        1)  name="HMAC_MD5_96"; verdict="weak — MD5" ;;
        2)  name="HMAC_SHA1_96"; verdict="legacy" ;;
        12) name="HMAC_SHA2_256_128"; verdict="ok" ;;
        14) name="HMAC_SHA2_512_256"; verdict="ok" ;;
        *)  name="unknown"; verdict="unknown — never scored as ok" ;;
    esac
    printf 'transform_id\t%d\nname\t%s\nverdict\t%s\n' "$id" "$name" "$verdict"
}

vowi_plan() {
    cat <<'EOF'
status	handoff
what	standing up an ePDG and a UE that speaks SWu/IKEv2
hardware	a UE with VoWiFi enabled and a carrier ePDG, or a lab ePDG (strongSwan with the 3GPP SWu plugins)
software	strongSwan, srsRAN (optional), a USIM or soft-USIM with the subscriber's Ki/OPc
flow	1. decode a captured IKE_SA_INIT/IKE_AUTH here  2. run the transform classifiers on the proposals  3. run --null-check on the negotiated child SA
note	authenticating to a live ePDG needs a real subscription; nothing is transmitted by this module
EOF
}

vowi_selftest() {
    local bad=0 nchk=0
    chk() {
        nchk=$(( nchk + 1 ))
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$(( bad + 1 )); fi
    }
    fld() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }

    local d
    d=$(mktemp -d "$MOD_TMP/selftest.XXXXXX") || {
        printf 'ERROR\tmktemp failed under %s\n' "$MOD_TMP" >&2; return 1; }
    trap 'rm -rf "$d"' EXIT
    export LOOT_DIR="$d/loot" CAPTURES_DIR="$d/captures" STATE_DIR="$d/state"
    export VOWI_DIR="$d/loot/vowifi"
    mkdir -p "$VOWI_DIR"

    # 1. IKEv2 exchange types are the RFC 7296 §3.1 / IANA numbers.
    chk exh-34 "$(vowi_ike_name 34)" "IKE_SA_INIT"
    chk exh-35 "$(vowi_ike_name 35)" "IKE_AUTH"
    chk exh-36 "$(vowi_ike_name 36)" "CREATE_CHILD_SA"
    chk exh-37 "$(vowi_ike_name 37)" "INFORMATIONAL"

    # 2. Header build is exactly 28 octets and round-trips through the parser.
    local hdr; hdr=$(vowi_ike_build 1122334455667788 0000000000000000 33 34 8 00000000)
    chk hdr-len "$(( ${#hdr} / 2 ))" "28"
    local out; out=$(vowi_ike_parse "$hdr")
    chk hdr-parsi "$(fld "$out" initiator_spi)" "1122334455667788"
    chk hdr-next  "$(fld "$out" next_payload)" "33"
    chk hdr-exch  "$(fld "$out" exchange_type)" "34"
    chk hdr-ver   "$(fld "$out" version)" "0x20"
    chk hdr-init  "$(fld "$out" initiator)" "yes"
    chk hdr-lenfield "$(fld "$out" length_field)" "28"
    # a non-v2 version octet must raise the alert, not be called IKEv2.
    local h10; h10=$(vowi_norm_hex "${hdr:0:34}10${hdr:36}")
    chk hdr-ver-alert "$(printf '%s\n' "$(vowi_ike_parse "$h10")" | grep -c version_alert)" "1"
    chk hdr-short "$(vowi_ike_parse 0011 >/dev/null 2>&1; echo $?)" "1"
    chk hdr-badhex "$(vowi_ike_parse zz >/dev/null 2>&1; echo $?)" "2"

    # 3. EAP-AKA (RFC 4187): type 23, subtype names.
    chk eap-type "$(printf '%s' "$(vowi_eap_aka 1 1 1)" | cut -c9-10)" "17"
    chk eap-sub-challenge "$(vowi_aka_subtype_name 1)" "Challenge"
    chk eap-sub-authresp  "$(vowi_aka_subtype_name 2)" "Authentication-Response"
    chk eap-sub-identity  "$(vowi_aka_subtype_name 4)" "Identity"
    local eap; eap=$(vowi_eap_aka 1 7 1)
    out=$(vowi_eap_parse "$eap")
    chk eap-parse-code "$(fld "$out" code_name)" "Request"
    chk eap-parse-id   "$(fld "$out" id)" "7"
    chk eap-parse-sub  "$(fld "$out" subtype_name)" "Challenge"
    # a wrong EAP type must be rejected, not decoded as AKA.
    chk eap-wrong "$(vowi_eap_parse 0101000501 >/dev/null 2>&1; echo $?)" "1"
    chk eap-short "$(vowi_eap_parse 0101 >/dev/null 2>&1; echo $?)" "1"

    # 4. Identifiers (TS 23.003).
    chk nai "$(vowi_nai 310150123456789 310 260)" \
        "0310150123456789@nai.epc.mnc260.mcc310.3gppnetwork.org"
    chk nai-mnc2 "$(vowi_nai 234150123456789 234 15)" \
        "0234150123456789@nai.epc.mnc015.mcc234.3gppnetwork.org"
    chk epdg "$(vowi_epdg_fqdn 310 260)" \
        "epdg.epc.mnc260.mcc310.pub.3gppnetwork.org"
    chk epdg-mnc2 "$(vowi_epdg_fqdn 234 15)" \
        "epdg.epc.mnc015.mcc234.pub.3gppnetwork.org"
    chk nai-badimsi "$(vowi_nai 12 310 260 >/dev/null 2>&1; echo $?)" "2"
    chk epdg-badmcc "$(vowi_epdg_fqdn 31 260 >/dev/null 2>&1; echo $?)" "2"

    # 5. Transform classifiers. Unknown is never 'ok' (MODULE_CONVENTIONS §16).
    chk encr-null "$(fld "$(vowi_encr_classify 11)" verdict)" "weak — no confidentiality"
    chk encr-null-gmac "$(fld "$(vowi_encr_classify 21)" name)" "ENCR_NULL_AUTH_AES_GMAC"
    chk encr-aesgcm "$(fld "$(vowi_encr_classify 20)" verdict)" "ok"
    chk encr-3des "$(fld "$(vowi_encr_classify 3)" verdict)" "legacy — 64-bit block, deprecated"
    chk encr-unknown "$(fld "$(vowi_encr_classify 999)" verdict)" "unknown — never scored as ok"
    chk int-none "$(fld "$(vowi_integrity_classify 0)" verdict)" "weak — no integrity"
    chk int-sha256 "$(fld "$(vowi_integrity_classify 12)" verdict)" "ok"
    chk int-unknown "$(fld "$(vowi_integrity_classify 77)" verdict)" "unknown — never scored as ok"

    # 6. Payload chain walk: two payloads then terminator.
    #    payload @0: next=40(Ni) len=4 ; payload @4: next=0 len=4.
    local chain="28"  # next payload 40, flags 00, len 0004
    chain="28000004"; chain+="00000004"; chain+="aabbccdd"
    out=$(vowi_payload_walk "$chain" 33)
    chk walk-first "$(printf '%s\n' "$out" | sed -n '2p' | cut -f3)" "SA"
    chk walk-second "$(printf '%s\n' "$out" | sed -n '3p' | cut -f3)" "Ni"
    chk walk-rows "$(printf '%s\n' "$out" | tail -n +2 | wc -l | tr -d ' ')" "2"

    printf 'ASSERTIONS\t%d\n' "$nchk"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

vowi_menu() {
    while true; do
        banner
        echo "  === VoWiFi / ePDG Attacks ==="
        echo
        cat <<'M'
  [1]  IKEv2 type reference
  [2]  Build an IKEv2 header
  [3]  Parse an IKEv2 header
  [4]  Build an EAP-AKA packet
  [5]  Parse an EAP-AKA packet
  [6]  Derive the SWu NAI
  [7]  Derive the ePDG FQDN
  [8]  Classify an encryption transform
  [9]  Classify an integrity transform
  [10] Walk a payload chain
  [11] Plan (handoff)
  [0]  back
M
        read -rp "  choice> " c || return 0
        case "$c" in
            1)  vowi_ike_types; read -rp "  enter " _ ;;
            2)  read -rp "  iSPI(hex16)> " a; read -rp "  rSPI(hex16)> " b
                read -rp "  next payload> " n; read -rp "  exchange> " e
                vowi_ike_build "$a" "$b" "$n" "$e" 8 00000000; echo; read -rp "  enter " _ ;;
            3)  read -rp "  hex> " h; vowi_ike_parse "$h"; read -rp "  enter " _ ;;
            4)  read -rp "  code> " cd; read -rp "  id> " id; read -rp "  subtype> " st
                vowi_eap_aka "$cd" "$id" "$st"; echo; read -rp "  enter " _ ;;
            5)  read -rp "  hex> " h; vowi_eap_parse "$h"; read -rp "  enter " _ ;;
            6)  read -rp "  imsi> " i; read -rp "  mcc> " m; read -rp "  mnc> " n
                vowi_nai "$i" "$m" "$n"; read -rp "  enter " _ ;;
            7)  read -rp "  mcc> " m; read -rp "  mnc> " n; vowi_epdg_fqdn "$m" "$n"; read -rp "  enter " _ ;;
            8)  read -rp "  transform id> " t; vowi_encr_classify "$t"; read -rp "  enter " _ ;;
            9)  read -rp "  transform id> " t; vowi_integrity_classify "$t"; read -rp "  enter " _ ;;
            10) read -rp "  chain hex> " h; read -rp "  first payload type> " f
                vowi_payload_walk "$h" "$f"; read -rp "  enter " _ ;;
            11) vowi_plan; read -rp "  enter " _ ;;
            0)  return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

vowi_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)   vowi_status_tsv ;;
        --types)        vowi_ike_types ;;
        --ike-build)    vowi_ike_build "${1:-1122334455667788}" "${2:-0000000000000000}" "${3:-33}" "${4:-34}" "${5:-8}" "${6:-00000000}" ;;
        --ike-parse)    vowi_ike_parse "${1:-}" ;;
        --eap-build)    vowi_eap_aka "${1:-1}" "${2:-1}" "${3:-1}" ;;
        --eap-parse)    vowi_eap_parse "${1:-}" ;;
        --nai)          vowi_nai "${1:-}" "${2:-}" "${3:-}" ;;
        --epdg)         vowi_epdg_fqdn "${1:-}" "${2:-}" ;;
        --encr)         vowi_encr_classify "${1:-}" ;;
        --integrity)    vowi_integrity_classify "${1:-}" ;;
        --walk)         vowi_payload_walk "${1:-}" "${2:-33}" ;;
        --plan)         vowi_plan ;;
        --selftest)     vowi_selftest ;;
        --menu)         vowi_menu ;;
        *)
            cat >&2 <<EOF
VoWiFi / ePDG Attacks — IKEv2/SWu, EAP-AKA and the tunnel to the EPC

Usage: $0 COMMAND
  --status-tsv         module state as TSV
  --types              IKEv2 exchange and payload type reference
  --ike-build <iSPI> <rSPI> <next> <exch> [flags] [msgid]
  --ike-parse <hex>    decode a 28-octet IKEv2 header
  --eap-build <code> <id> <subtype>
  --eap-parse <hex>    decode an EAP-AKA packet
  --nai <imsi> <mcc> <mnc>   SWu NAI (TS 23.003)
  --epdg <mcc> <mnc>         ePDG discovery FQDN
  --encr <id>          encryption transform verdict
  --integrity <id>     integrity transform verdict
  --walk <hex> [type]  walk an IKEv2 payload chain
  --plan               lab ePDG handoff plan
  --selftest           verify codecs and tables, no radio needed
  --menu               interactive menu
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
    vowi_cli_main "$@"
fi
