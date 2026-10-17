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

# ── IKEv2 and EAP-AKA registries ────────────────────────────────────────
# Every row here is the registry's, not a guess. Sources, in the order the
# kinds appear: IANA "IKEv2 Parameters" (exchange types, payload types,
# transform types, identification types, notify error and status types,
# transform IDs 1-5 = ENCR, PRF, INTEG, KE, SN), whose numbers are RFC 7296
# §3.1-§3.10 carried forward; RFC 4187 §11 for the EAP-AKA subtypes and
# attributes (the registry is shared with EAP-SIM); RFC 9048 §8.2 for
# AT_KDF_INPUT 23, AT_KDF 24 and AT_BIDDING 136.
#
# What this table replaced, because it is the reason the file changed: the
# payload numbering was shifted by one from 42 onward -- 41 is Notify and
# 42 Delete (Ni and Nr are the same type, 40), so the old table called a
# Delete payload "N", an encrypted SK payload "TSr" and a Configuration
# payload "SK", which is every IKE_AUTH message read wrong. It had no CERT
# or CERTREQ, and an invented 41 "Nr". The EAP-AKA subtypes were numbered
# from an old draft: 2 is AKA-Authentication-Reject, not a response, and
# Notification is 12, Re-authentication 13, Client-Error 14.
vowi_registry() {
    cat <<'REGTBL'
kind	value	name
exchange	34	IKE_SA_INIT
exchange	35	IKE_AUTH
exchange	36	CREATE_CHILD_SA
exchange	37	INFORMATIONAL
exchange	38	IKE_SESSION_RESUME
exchange	39	GSA_AUTH
exchange	40	GSA_REGISTRATION
exchange	41	GSA_REKEY
exchange	42	GSA_INBAND_REKEY
exchange	43	IKE_INTERMEDIATE
exchange	44	IKE_FOLLOWUP_KE
payload	0	none
payload	33	SA
payload	34	KE
payload	35	IDi
payload	36	IDr
payload	37	CERT
payload	38	CERTREQ
payload	39	AUTH
payload	40	Ni
payload	41	N
payload	42	D
payload	43	V
payload	44	TSi
payload	45	TSr
payload	46	SK
payload	47	CP
payload	48	EAP
payload	49	GSPM
payload	50	IDg
payload	51	GSA
payload	52	KD
payload	53	SKF
payload	54	PS
transform	1	Encryption Algorithm (ENCR)
transform	2	Pseudo-random Function (PRF)
transform	3	Integrity Algorithm (INTEG)
transform	4	Key Exchange Method (KE)
transform	5	Sequence Numbers (SN)
transform	6	Additional Key Exchange 1 (ADDKE1)
transform	7	Additional Key Exchange 2 (ADDKE2)
transform	8	Additional Key Exchange 3 (ADDKE3)
transform	9	Additional Key Exchange 4 (ADDKE4)
transform	10	Additional Key Exchange 5 (ADDKE5)
transform	11	Additional Key Exchange 6 (ADDKE6)
transform	12	Additional Key Exchange 7 (ADDKE7)
transform	13	Key Wrap Algorithm (KWA)
transform	14	Group Controller Authentication Method (GCAUTH)
idtype	1	ID_IPV4_ADDR
idtype	2	ID_FQDN
idtype	3	ID_RFC822_ADDR
idtype	5	ID_IPV6_ADDR
idtype	9	ID_DER_ASN1_DN
idtype	10	ID_DER_ASN1_GN
idtype	11	ID_KEY_ID
idtype	12	ID_FC_NAME
idtype	13	ID_NULL
encr	1	ENCR_DES_IV64
encr	2	ENCR_DES
encr	3	ENCR_3DES
encr	4	ENCR_RC5
encr	5	ENCR_IDEA
encr	6	ENCR_CAST
encr	7	ENCR_BLOWFISH
encr	8	ENCR_3IDEA
encr	9	ENCR_DES_IV32
encr	11	ENCR_NULL
encr	12	ENCR_AES_CBC
encr	13	ENCR_AES_CTR
encr	14	ENCR_AES_CCM_8
encr	15	ENCR_AES_CCM_12
encr	16	ENCR_AES_CCM_16
encr	18	ENCR_AES_GCM_8
encr	19	ENCR_AES_GCM_12
encr	20	ENCR_AES_GCM_16
encr	21	ENCR_NULL_AUTH_AES_GMAC
encr	22	Reserved for IEEE P1619 XTS-AES
encr	23	ENCR_CAMELLIA_CBC
encr	24	ENCR_CAMELLIA_CTR
encr	25	ENCR_CAMELLIA_CCM_8
encr	26	ENCR_CAMELLIA_CCM_12
encr	27	ENCR_CAMELLIA_CCM_16
encr	28	ENCR_CHACHA20_POLY1305
encr	29	ENCR_AES_CCM_8_IIV
encr	30	ENCR_AES_GCM_16_IIV
encr	31	ENCR_CHACHA20_POLY1305_IIV
encr	32	ENCR_KUZNYECHIK_MGM_KTREE
encr	33	ENCR_MAGMA_MGM_KTREE
encr	34	ENCR_KUZNYECHIK_MGM_MAC_KTREE
encr	35	ENCR_MAGMA_MGM_MAC_KTREE
prf	1	PRF_HMAC_MD5
prf	2	PRF_HMAC_SHA1
prf	3	PRF_HMAC_TIGER
prf	4	PRF_AES128_XCBC
prf	5	PRF_HMAC_SHA2_256
prf	6	PRF_HMAC_SHA2_384
prf	7	PRF_HMAC_SHA2_512
prf	8	PRF_AES128_CMAC
prf	9	PRF_HMAC_STREEBOG_512
integ	0	NONE
integ	1	AUTH_HMAC_MD5_96
integ	2	AUTH_HMAC_SHA1_96
integ	3	AUTH_DES_MAC
integ	4	AUTH_KPDK_MD5
integ	5	AUTH_AES_XCBC_96
integ	6	AUTH_HMAC_MD5_128
integ	7	AUTH_HMAC_SHA1_160
integ	8	AUTH_AES_CMAC_96
integ	9	AUTH_AES_128_GMAC
integ	10	AUTH_AES_192_GMAC
integ	11	AUTH_AES_256_GMAC
integ	12	AUTH_HMAC_SHA2_256_128
integ	13	AUTH_HMAC_SHA2_384_192
integ	14	AUTH_HMAC_SHA2_512_256
ke	0	NONE
ke	1	768-bit MODP Group
ke	2	1024-bit MODP Group
ke	5	1536-bit MODP Group
ke	14	2048-bit MODP Group
ke	15	3072-bit MODP Group
ke	16	4096-bit MODP Group
ke	17	6144-bit MODP Group
ke	18	8192-bit MODP Group
ke	19	256-bit random ECP group
ke	20	384-bit random ECP group
ke	21	521-bit random ECP group
ke	22	1024-bit MODP Group with 160-bit Prime Order Subgroup
ke	23	2048-bit MODP Group with 224-bit Prime Order Subgroup
ke	24	2048-bit MODP Group with 256-bit Prime Order Subgroup
ke	25	192-bit Random ECP Group
ke	26	224-bit Random ECP Group
ke	27	brainpoolP224r1
ke	28	brainpoolP256r1
ke	29	brainpoolP384r1
ke	30	brainpoolP512r1
ke	31	Curve25519
ke	32	Curve448
ke	33	GOST3410_2012_256
ke	34	GOST3410_2012_512
ke	35	ml-kem-512
ke	36	ml-kem-768
ke	37	ml-kem-1024
esn	0	32-bit Sequential Numbers
esn	1	Partially Transmitted 64-bit Sequential Numbers
esn	2	32-bit Unspecified Numbers
notify-error	1	UNSUPPORTED_CRITICAL_PAYLOAD
notify-error	4	INVALID_IKE_SPI
notify-error	5	INVALID_MAJOR_VERSION
notify-error	7	INVALID_SYNTAX
notify-error	9	INVALID_MESSAGE_ID
notify-error	11	INVALID_SPI
notify-error	14	NO_PROPOSAL_CHOSEN
notify-error	17	INVALID_KE_PAYLOAD
notify-error	24	AUTHENTICATION_FAILED
notify-error	34	SINGLE_PAIR_REQUIRED
notify-error	35	NO_ADDITIONAL_SAS
notify-error	36	INTERNAL_ADDRESS_FAILURE
notify-error	37	FAILED_CP_REQUIRED
notify-error	38	TS_UNACCEPTABLE
notify-error	39	INVALID_SELECTORS
notify-error	40	UNACCEPTABLE_ADDRESSES
notify-error	41	UNEXPECTED_NAT_DETECTED
notify-error	42	USE_ASSIGNED_HoA
notify-error	43	TEMPORARY_FAILURE
notify-error	44	CHILD_SA_NOT_FOUND
notify-error	45	INVALID_GROUP_ID
notify-error	46	AUTHORIZATION_FAILED
notify-error	47	STATE_NOT_FOUND
notify-error	48	TS_MAX_QUEUE
notify-error	49	REGISTRATION_FAILED
notify-status	16384	INITIAL_CONTACT
notify-status	16385	SET_WINDOW_SIZE
notify-status	16386	ADDITIONAL_TS_POSSIBLE
notify-status	16387	IPCOMP_SUPPORTED
notify-status	16388	NAT_DETECTION_SOURCE_IP
notify-status	16389	NAT_DETECTION_DESTINATION_IP
notify-status	16390	COOKIE
notify-status	16391	USE_TRANSPORT_MODE
notify-status	16392	HTTP_CERT_LOOKUP_SUPPORTED
notify-status	16393	REKEY_SA
notify-status	16394	ESP_TFC_PADDING_NOT_SUPPORTED
notify-status	16395	NON_FIRST_FRAGMENTS_ALSO
notify-status	16396	MOBIKE_SUPPORTED
notify-status	16397	ADDITIONAL_IP4_ADDRESS
notify-status	16398	ADDITIONAL_IP6_ADDRESS
notify-status	16399	NO_ADDITIONAL_ADDRESSES
notify-status	16400	UPDATE_SA_ADDRESSES
notify-status	16401	COOKIE2
notify-status	16402	NO_NATS_ALLOWED
notify-status	16403	AUTH_LIFETIME
notify-status	16404	MULTIPLE_AUTH_SUPPORTED
notify-status	16405	ANOTHER_AUTH_FOLLOWS
notify-status	16406	REDIRECT_SUPPORTED
notify-status	16407	REDIRECT
notify-status	16408	REDIRECTED_FROM
notify-status	16409	TICKET_LT_OPAQUE
notify-status	16410	TICKET_REQUEST
notify-status	16411	TICKET_ACK
notify-status	16412	TICKET_NACK
notify-status	16413	TICKET_OPAQUE
notify-status	16414	LINK_ID
notify-status	16415	USE_WESP_MODE
notify-status	16416	ROHC_SUPPORTED
notify-status	16417	EAP_ONLY_AUTHENTICATION
notify-status	16418	CHILDLESS_IKEV2_SUPPORTED
notify-status	16419	QUICK_CRASH_DETECTION
notify-status	16420	IKEV2_MESSAGE_ID_SYNC_SUPPORTED
notify-status	16421	IPSEC_REPLAY_COUNTER_SYNC_SUPPORTED
notify-status	16422	IKEV2_MESSAGE_ID_SYNC
notify-status	16423	IPSEC_REPLAY_COUNTER_SYNC
notify-status	16424	SECURE_PASSWORD_METHODS
notify-status	16425	PSK_PERSIST
notify-status	16426	PSK_CONFIRM
notify-status	16427	ERX_SUPPORTED
notify-status	16428	IFOM_CAPABILITY
notify-status	16429	GROUP_SENDER
notify-status	16430	IKEV2_FRAGMENTATION_SUPPORTED
notify-status	16431	SIGNATURE_HASH_ALGORITHMS
notify-status	16432	CLONE_IKE_SA_SUPPORTED
notify-status	16433	CLONE_IKE_SA
notify-status	16434	PUZZLE
notify-status	16435	USE_PPK
notify-status	16436	PPK_IDENTITY
notify-status	16437	NO_PPK_AUTH
notify-status	16438	INTERMEDIATE_EXCHANGE_SUPPORTED
notify-status	16439	IP4_ALLOWED
notify-status	16440	IP6_ALLOWED
notify-status	16441	ADDITIONAL_KEY_EXCHANGE
notify-status	16442	USE_AGGFRAG
notify-status	16443	SUPPORTED_AUTH_METHODS
notify-status	16444	SA_RESOURCE_INFO
notify-status	16445	USE_PPK_INT
notify-status	16446	PPK_IDENTITY_KEY
notify-status	16447	IKE_SA_INIT_FULL_TRANSCRIPT_AUTH
eap-subtype	1	AKA-Challenge
eap-subtype	2	AKA-Authentication-Reject
eap-subtype	4	AKA-Synchronization-Failure
eap-subtype	5	AKA-Identity
eap-subtype	10	SIM-Start
eap-subtype	11	SIM-Challenge
eap-subtype	12	AKA-Notification
eap-subtype	13	AKA-Reauthentication
eap-subtype	14	AKA-Client-Error
eap-att	1	AT_RAND
eap-att	2	AT_AUTN
eap-att	3	AT_RES
eap-att	4	AT_AUTS
eap-att	6	AT_PADDING
eap-att	7	AT_NONCE_MT
eap-att	10	AT_PERMANENT_ID_REQ
eap-att	11	AT_MAC
eap-att	12	AT_NOTIFICATION
eap-att	13	AT_ANY_ID_REQ
eap-att	14	AT_IDENTITY
eap-att	15	AT_VERSION_LIST
eap-att	16	AT_SELECTED_VERSION
eap-att	17	AT_FULLAUTH_ID_REQ
eap-att	19	AT_COUNTER
eap-att	20	AT_COUNTER_TOO_SMALL
eap-att	21	AT_NONCE_S
eap-att	22	AT_CLIENT_ERROR_CODE
eap-att	23	AT_KDF_INPUT
eap-att	24	AT_KDF
eap-att	129	AT_IV
eap-att	130	AT_ENCR_DATA
eap-att	132	AT_NEXT_PSEUDONYM
eap-att	133	AT_NEXT_REAUTH_ID
eap-att	134	AT_CHECKCODE
eap-att	135	AT_RESULT_IND
eap-att	136	AT_BIDDING
REGTBL
}

# The registry lookup: empty when the value is not assigned.
vowi_reg_name() {
    vowi_registry | awk -F'\t' -v k="${1:-}" -v v="${2:-}" '$1==k && $2==v {print $3; exit}'
}

vowi_ike_name()            { local n; n=$(vowi_reg_name exchange "${1:-}"); printf '%s\n' "${n:-unassigned}"; }
vowi_payload_name()        { local n; n=$(vowi_reg_name payload "${1:-}");  printf '%s\n' "${n:-unassigned}"; }
vowi_transform_type_name() { local n; n=$(vowi_reg_name transform "${1:-}"); printf '%s\n' "${n:-unassigned}"; }
vowi_id_type_name()        { local n; n=$(vowi_reg_name idtype "${1:-}");   printf '%s\n' "${n:-unassigned}"; }
vowi_eap_attr_name()       { local n; n=$(vowi_reg_name eap-att "${1:-}");  printf '%s\n' "${n:-unknown}"; }
vowi_aka_subtype_name()    { local n; n=$(vowi_reg_name eap-subtype "${1:-}"); printf '%s\n' "${n:-unknown}"; }
vowi_notify_name() {
    local n
    n=$(vowi_reg_name notify-error "${1:-}"); [[ -n "$n" ]] || n=$(vowi_reg_name notify-status "${1:-}")
    printf '%s\n' "${n:-unassigned}"
}

# ── IKEv2 header (RFC 7296 §3.1) ────────────────────────────────────────
#   initiator SPI 8 | responder SPI 8 | next payload 1 | version 1 (0x20)
#   exchange type 1 | flags 1 (I 0x08, V 0x10, R 0x20; the rest reserved)
#   message id 4 | length 4   => 28 octets
vowi_ike_build() {
    local ispi; ispi=$(vowi_norm_hex "${1:-1122334455667788}")
    local rspi; rspi=$(vowi_norm_hex "${2:-0000000000000000}")
    local next="${3:-33}" exch="${4:-34}" flags="${5:-8}" mid; mid=$(vowi_norm_hex "${6:-00000000}")
    [[ ${#ispi} -eq 16 && ${#rspi} -eq 16 && ${#mid} -eq 8 ]] || {
        printf 'ERROR\tSPIs must be 8 octets and message id 4 octets of hex\n' >&2; return 2; }
    printf '%s%s%s20%s%s%s%08X' "$ispi" "$rspi" "$(vowi_byte "$next")" \
        "$(vowi_byte "$exch")" "$(vowi_byte "$flags")" "$mid" 28
}

# The clause's own consistency rules, each reported and each a non-zero exit:
# the major version is 2 (§3.1), the length field counts the whole message, and
# only the I, V and R flag bits are defined -- a set reserved bit is a message
# from something that does not implement this RFC.
vowi_ike_parse() {
    local h; h=$(vowi_norm_hex "${1:-}")
    vowi_is_hex "$h" || { printf 'ERROR\tnot valid hex\n' >&2; return 2; }
    (( ${#h} >= 56 )) || { printf 'ERROR\tIKEv2 header is 28 octets\n' >&2; return 1; }
    local ispi="${h:0:16}" rspi="${h:16:16}"
    local next=$(( 16#${h:32:2} )) ver=$(( 16#${h:34:2} ))
    local exch=$(( 16#${h:36:2} )) flags=$(( 16#${h:38:2} ))
    local mid=$(( 16#${h:40:8} )) len=$(( 16#${h:48:8} ))
    local frame=$(( ${#h} / 2 )) rc=0
    printf 'initiator_spi\t%s\nresponder_spi\t%s\nnext_payload\t%s\nnext_payload_name\t%s\n' \
        "$ispi" "$rspi" "$next" "$(vowi_payload_name "$next")"
    printf 'version\t0x%02X\nversion_major\t%d\nversion_minor\t%d\n' \
        "$ver" "$(( ver >> 4 ))" "$(( ver & 0x0F ))"
    printf 'exchange_type\t%d\nexchange_name\t%s\nflags\t0x%02X\n' \
        "$exch" "$(vowi_ike_name "$exch")" "$flags"
    printf 'initiator\t%s\nversion_flag\t%s\nresponse\t%s\n' \
        "$([[ $(( flags & 0x08 )) -ne 0 ]] && echo yes || echo no)" \
        "$([[ $(( flags & 0x10 )) -ne 0 ]] && echo yes || echo no)" \
        "$([[ $(( flags & 0x20 )) -ne 0 ]] && echo yes || echo no)"
    printf 'message_id\t%d\nlength_field\t%d\nframe_octets\t%d\n' "$mid" "$len" "$frame"
    (( (ver >> 4) == 2 )) || { printf 'version_alert\tmajor version %d; IKEv2 is major 2\n' "$(( ver >> 4 ))"; rc=1; }
    (( len == frame )) || { printf 'length_alert\tlength field %d but %d octets arrived\n' "$len" "$frame"; rc=1; }
    (( (flags & 0xC7) == 0 )) || { printf 'flags_alert\treserved flag bits 0x%02X set; only I(0x08), V(0x10) and R(0x20) are defined\n' "$(( flags & 0xC7 ))"; rc=1; }
    return $rc
}

# The payload chain (§3.2): each payload starts with next(1), flags(1) whose
# high bit is the critical bit, and its own length(2) counted from that header.
# The message length bounds the chain, and an SK payload ends the visible part:
# what follows it is encrypted (§3.14), so walking further would be reading
# ciphertext as headers.
vowi_payload_walk() {
    local h; h=$(vowi_norm_hex "${1:-}")
    vowi_is_hex "$h" || { printf 'ERROR\tnot valid hex\n' >&2; return 2; }
    (( ${#h} >= 56 )) || { printf 'ERROR\tan IKEv2 message starts with the 28-octet header\n' >&2; return 1; }
    local total=$(( ${#h} / 2 ))
    local len=$(( 16#${h:48:8} ))
    (( len >= 28 && len <= total )) || {
        printf 'ERROR\tlength field %d does not fit the %d-octet frame\n' "$len" "$total" >&2; return 1; }
    local nt=$(( 16#${h:32:2} )) off=28 n=0
    printf 'order\toffset\ttype\tname\tcritical\tlength\n'
    while (( nt != 0 )); do
        (( n++ > 64 )) && { printf 'ERROR\tpayload chain did not terminate\n' >&2; return 1; }
        (( off + 4 <= len )) || {
            printf 'ERROR\tpayload %s declared at octet %d but the message ends at %d\n' "$nt" "$off" "$len" >&2; return 1; }
        local nxt=$(( 16#${h:$((off*2)):2} ))
        local pflags=$(( 16#${h:$((off*2+2)):2} ))
        local plen=$(( 16#${h:$((off*2+4)):4} ))
        local crit=no; (( pflags & 0x80 )) && crit=yes
        printf '%d\t%d\t%s\t%s\t%s\t%d\n' "$n" "$off" "$nt" "$(vowi_payload_name "$nt")" "$crit" "$plen"
        (( plen >= 4 )) || {
            printf 'ERROR\tpayload %s at octet %d has length %d; its own header is 4 octets\n' "$nt" "$off" "$plen" >&2; return 1; }
        (( off + plen <= len )) || {
            printf 'ERROR\tpayload %s at octet %d runs past the message (%d octets into a %d-octet message)\n' \
                "$nt" "$off" "$plen" "$len" >&2; return 1; }
        (( pflags & 0x7F )) && printf 'note\tpayload %s has reserved flag bits 0x%02X set\n' "$nt" "$(( pflags & 0x7F ))"
        (( nt == 46 )) && { printf 'note\tSK payload: the chain continues encrypted\n'; return 0; }
        off=$(( off + plen )); nt=$nxt
    done
    (( off < len )) && printf 'note\t%d octet(s) after the last payload\n' "$(( len - off ))"
    return 0
}

# ── EAP-AKA and EAP-AKA' (RFC 4187 §8.1, §11; RFC 9048 §8.2) ────────────
# Packet: Code(1) Identifier(1) Length(2) Type(1)=23 Subtype(1) Reserved(2),
# then attributes: Type(1) Length(1, counted in 4-octet units) Value padded
# to a 4-octet boundary. The old builder emitted six octets while declaring
# eight -- the two reserved octets were never written -- and the parser read
# the header and stopped, so AT_MAC, the one attribute that says whether the
# message was authenticated, was invisible in every capture.
vowi_eap_aka() {
    local code="${1:-1}" id="${2:-1}" sub="${3:-1}" attrs
    attrs=$(vowi_norm_hex "${4:-}")
    [[ -z "$attrs" ]] || vowi_is_hex "$attrs" || {
        printf 'ERROR\tattributes must be an even number of hex digits\n' >&2; return 2; }
    (( ${#attrs} % 8 == 0 )) || {
        printf 'ERROR\tattributes are 4-octet aligned (%d octets given)\n' "$(( ${#attrs} / 2 ))" >&2; return 2; }
    local hdr
    hdr=$(printf '%s%04X%s%s0000' "$(vowi_byte "$id")" \
              "$(( 8 + ${#attrs} / 2 ))" "$(vowi_byte 23)" "$(vowi_byte "$sub")")
    printf '%s%s%s' "$(vowi_byte "$code")" "$hdr" "$attrs"
}

# One attribute, padded to its length in 4-octet units (§8.1).
vowi_eap_attr() {
    local t="${1:-}" v; v=$(vowi_norm_hex "${2:-}")
    vowi_is_hex "$v" || { printf 'ERROR\tattribute value must be hex\n' >&2; return 2; }
    local n=$(( 2 + ${#v} / 2 ))
    local units=$(( (n + 3) / 4 ))
    local pad=$(( units * 4 - n )) padhex=""
    (( pad > 0 )) && padhex=$(printf '00%.0s' $(seq 1 "$pad"))
    printf '%s%s%s%s' "$(vowi_byte "$t")" "$(printf '%02X' "$units")" "$v" "$padhex"
}

vowi_eap_name() {
    case "$1" in 1) echo "Request" ;; 2) echo "Response" ;; 3) echo "Success" ;; 4) echo "Failure" ;; *) echo unknown ;; esac
}

vowi_eap_parse() {
    local h; h=$(vowi_norm_hex "${1:-}")
    vowi_is_hex "$h" || { printf 'ERROR\tnot valid hex\n' >&2; return 2; }
    local total=$(( ${#h} / 2 ))
    (( total >= 8 )) || {
        printf 'ERROR\tEAP-AKA is a 4-octet EAP header plus a 4-octet AKA header\n' >&2; return 1; }
    local code=$(( 16#${h:0:2} )) id=$(( 16#${h:2:2} ))
    local len=$(( 16#${h:4:4} )) typ=$(( 16#${h:8:2} ))
    (( typ == 23 )) || { printf 'ERROR\tnot EAP-AKA (type %d, RFC 4187 assigns 23)\n' "$typ" >&2; return 1; }
    local sub=$(( 16#${h:10:2} )) res=$(( 16#${h:12:4} ))
    local rc=0
    printf 'code\t%d\ncode_name\t%s\nid\t%d\nlength\t%d\ntype\t%d\nsubtype\t%d\nsubtype_name\t%s\nreserved\t0x%04X\n' \
        "$code" "$(vowi_eap_name "$code")" "$id" "$len" "$typ" "$sub" "$(vowi_aka_subtype_name "$sub")" "$res"
    (( len == total )) || { printf 'length_alert\tlength field %d but %d octets arrived\n' "$len" "$total"; rc=1; }
    (( res == 0 )) || { printf 'reserved_alert\treserved octets 0x%04X; §8.1 says zero\n' "$res"; rc=1; }
    local off=8 n=0
    while (( off < total )); do
        (( off + 2 <= total )) || { printf 'ERROR\tattribute header at octet %d is truncated\n' "$off" >&2; return 1; }
        local at=$(( 16#${h:$((off*2)):2} ))
        local au=$(( 16#${h:$((off*2+2)):2} ))
        local abytes=$(( au * 4 ))
        (( au >= 1 )) || { printf 'ERROR\tattribute %d at octet %d has length 0, which §8.1 forbids\n' "$at" "$off" >&2; return 1; }
        (( off + abytes <= total )) || {
            printf 'ERROR\tattribute %s at octet %d claims %d octets, %d remain\n' \
                "$at" "$off" "$abytes" "$(( total - off ))" >&2; return 1; }
        # AT_RAND, AT_AUTN and AT_MAC carry a 16-octet value padded to 20, and
        # AT_KDF a 2-octet value padded to 4 (RFC 4187 10.6, 10.15; RFC 9048
        # 3.2), so the alignment zeros are not part of the value they name.
        local vlen=$(( abytes * 2 - 4 ))
        case "$at" in
            1|2|11) vlen=32 ;;
            24)     vlen=4 ;;
        esac
        printf 'att.%d.type\t%d\natt.%d.name\t%s\natt.%d.length\t%d\natt.%d.value\t%s\n' \
            "$n" "$at" "$n" "$(vowi_eap_attr_name "$at")" "$n" "$abytes" "$n" \
            "${h:$((off*2+4)):$vlen}"
        # The clause fixes these lengths, so a wrong one is a refusal, not a note.
        case "$at" in
            1|2|11) (( abytes == 20 )) || {
                printf 'ERROR\t%s is 20 octets (5 units), %d given\n' "$(vowi_eap_attr_name "$at")" "$abytes" >&2; rc=1; } ;;
            24) (( abytes == 4 )) || {
                printf 'ERROR\tAT_KDF is 4 octets (1 unit), %d given\n' "$abytes" >&2; rc=1; } ;;
            3) (( abytes >= 4 )) || {
                printf 'ERROR\tAT_RES carries a 2-octet RES length and RES, so at least 4 octets\n' >&2; rc=1; } ;;
        esac
        n=$(( n + 1 )); off=$(( off + abytes ))
    done
    (( n == 0 )) && printf 'note\tno attributes: a request without AT_MAC cannot be authenticated\n'
    return $rc
}

# ── SA payload: proposals and transforms (RFC 7296 §3.3.1, §3.3.2) ──────
# Proposal: last(1) reserved(1) length(2) proposal#(1) protocol(1) spi_size(1)
#           transforms(1) spi... then the transforms.
# Transform: last(1) reserved(1) length(2) type(1) reserved(1) id(2) attrs.
# The module's job here is the downgrade question: a proposal that offers
# ENCR_NULL (§3.3.2 value 11, or 21 null-with-GMAC) or INTEG NONE (0) is the
# negotiation an attacker wants and the one a capture should never show.
vowi_sa_parse() {
    local h; h=$(vowi_norm_hex "${1:-}")
    vowi_is_hex "$h" || { printf 'ERROR\tthe SA payload body must be hex\n' >&2; return 2; }
    local total=$(( ${#h} / 2 ))
    local off=0 pn=0 found=0 rc=0
    while (( off < total )); do
        (( off + 8 <= total )) || { printf 'ERROR\tproposal at octet %d is shorter than its 8-octet header\n' "$off" >&2; return 1; }
        local last=$(( 16#${h:$((off*2)):2} ))
        local plen=$(( 16#${h:$((off*2+4)):4} ))
        local pid=$(( 16#${h:$((off*2+8)):2} ))
        local proto=$(( 16#${h:$((off*2+10)):2} ))
        local spisz=$(( 16#${h:$((off*2+12)):2} ))
        local ntr=$(( 16#${h:$((off*2+14)):2} ))
        (( plen >= 8 && off + plen <= total )) || {
            printf 'ERROR\tproposal %d at octet %d claims %d octets, %d remain\n' "$pid" "$off" "$plen" "$(( total - off ))" >&2; return 1; }
        printf 'proposal.%d.number\t%d\nproposal.%d.protocol\t%d\nproposal.%d.transforms\t%d\nproposal.%d.spi\t%s\n' \
            "$pn" "$pid" "$pn" "$proto" "$pn" "$ntr" "$pn" \
            "${h:$((off*2+16)):$((spisz*2))}"
        (( (last == 0 || last == 2) )) || printf 'note\tproposal %d has last-proposal octet %d; §3.3.1 defines 0 and 2\n' "$pid" "$last"
        local toff=$(( off + 8 + spisz )) tn=0
        while (( tn < ntr )); do
            (( toff + 8 <= off + plen )) || {
                printf 'ERROR\tproposal %d announces %d transform(s) but ends after %d\n' "$pid" "$ntr" "$tn" >&2; return 1; }
            local tlast=$(( 16#${h:$((toff*2)):2} ))
            local tlen=$(( 16#${h:$((toff*2+4)):4} ))
            local ttype=$(( 16#${h:$((toff*2+8)):2} ))
            local tid=$(( 16#${h:$((toff*2+12)):4} ))
            (( tlen >= 8 && toff + tlen <= off + plen )) || {
                printf 'ERROR\ttransform at octet %d claims %d octets, past the proposal\n' "$toff" "$tlen" >&2; return 1; }
            (( (tlast == 0 || tlast == 3) )) || printf 'note\ttransform at octet %d has last-transform octet %d; §3.3.2 defines 0 and 3\n' "$toff" "$tlast"
            local tname
            case "$ttype" in
                1) tname=$(vowi_encr_name "$tid") ;;
                2) tname=$(vowi_prf_name "$tid") ;;
                3) tname=$(vowi_integ_name "$tid") ;;
                4) tname=$(vowi_dh_name "$tid") ;;
                5) tname=$(vowi_esn_name "$tid") ;;
                *) tname="unknown" ;;
            esac
            printf 'proposal.%d.transform.%d.type\t%d\nproposal.%d.transform.%d.name\t%s\nproposal.%d.transform.%d.id\t%d\n' \
                "$pn" "$tn" "$ttype" "$pn" "$tn" "$tname" "$pn" "$tn" "$tid"
            # the downgrade test
            case "$ttype:$tid" in
                1:11|1:21) printf 'null_transform\tproposal %d offers %s\n' "$pid" "$tname"; found=$(( found + 1 )) ;;
                3:0)       printf 'null_transform\tproposal %d offers INTEG NONE\n' "$pid"; found=$(( found + 1 )) ;;
            esac
            tn=$(( tn + 1 )); toff=$(( toff + tlen ))
        done
        (( last == 2 )) && break
        off=$(( off + plen ))
        (( last == 0 && off >= total )) && break
    done
    if (( found > 0 )); then
        printf 'tunnel_verdict\tweak — %d null transform(s) offered (RFC 8247 §4.2.2)\n' "$found"
    else
        printf 'tunnel_verdict\tno NULL encryption or INTEG NONE offered\n'
    fi
    return $rc
}

# ── transform safety ────────────────────────────────────────────────────
# RFC 7296 §3.3.2 numbers the proposals, and the IANA transform registries say
# what each number is; RFC 8247 is the guidance on which of them are still
# acceptable. A NULL cipher or a NULL integrity algorithm is a negotiated
# downgrade, not a preference: the module scores it weak and refuses to call an
# unknown id ok.
vowi_encr_name()  { local n; n=$(vowi_reg_name encr "${1:-}");  printf '%s\n' "${n:-unknown}"; }
vowi_integ_name() { local n; n=$(vowi_reg_name integ "${1:-}"); printf '%s\n' "${n:-unknown}"; }
vowi_prf_name()   { local n; n=$(vowi_reg_name prf "${1:-}");   printf '%s\n' "${n:-unknown}"; }
vowi_dh_name()    { local n; n=$(vowi_reg_name ke "${1:-}");    printf '%s\n' "${n:-unknown}"; }
vowi_esn_name()   { local n; n=$(vowi_reg_name esn "${1:-}");   printf '%s\n' "${n:-unknown}"; }

vowi_encr_verdict() {
    case "${1:-}" in
        21)                              echo "weak — null encryption, GMAC only" ;;
        11|29|30|31)                     echo "weak — no confidentiality" ;;
        1|2|4|5|6|7|8|9|22|34|35)        echo "weak — broken, reserved or deprecrated" ;;
        3)                               echo "legacy — 64-bit block, deprecated" ;;
        12|13|14|15|16|18|19|20|23|24|25|26|27|28|32|33) echo "ok" ;;
        *)                               echo "unknown — never scored as ok" ;;
    esac
}
vowi_integrity_verdict() {
    case "${1:-}" in
        0)                  echo "weak — no integrity" ;;
        1|3|4|6|7)          echo "weak — broken or deprecated MAC" ;;
        2)                  echo "legacy" ;;
        5|8|9|10|11|12|13|14) echo "ok" ;;
        *)                  echo "unknown — never scored as ok" ;;
    esac
}
vowi_encr_classify() {
    local id="${1:-}"
    [[ "$id" =~ ^[0-9]+$ ]] || { printf 'ERROR\ttransform id must be numeric\n' >&2; return 2; }
    printf 'transform_id\t%d\nname\t%s\nverdict\t%s\n' "$id" "$(vowi_encr_name "$id")" "$(vowi_encr_verdict "$id")"
}
vowi_integrity_classify() {
    local id="${1:-}"
    [[ "$id" =~ ^[0-9]+$ ]] || { printf 'ERROR\ttransform id must be numeric\n' >&2; return 2; }
    printf 'transform_id\t%d\nname\t%s\nverdict\t%s\n' "$id" "$(vowi_integ_name "$id")" "$(vowi_integrity_verdict "$id")"
}
vowi_dh_classify() {
    local id="${1:-}"
    [[ "$id" =~ ^[0-9]+$ ]] || { printf 'ERROR\ttransform id must be numeric\n' >&2; return 2; }
    local verdict
    case "$id" in
        1|2)   verdict="weak — 768/1024-bit MODP, pre-logjam" ;;
        3|4)   verdict="weak — reserved group" ;;
        5)     verdict="legacy — 1536-bit MODP" ;;
        14|15|16|17|18|19|20|21) verdict="ok" ;;
        22|23|24) verdict="legacy — MODP with a small prime-order subgroup" ;;
        25|26|27|28|29|30) verdict="ok" ;;
        31|32) verdict="ok — Curve25519/Curve448" ;;
        33|34) verdict="ok — GOST 2012" ;;
        35|36|37) verdict="ok — ML-KEM" ;;
        *)     verdict="unknown — never scored as ok" ;;
    esac
    printf 'transform_id\t%d\nname\t%s\nverdict\t%s\n' "$id" "$(vowi_dh_name "$id")" "$verdict"
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

    # 1. The registries are the IANA ones. The payload numbering is the one a
    #    capture needs: 37/38 CERT/CERTREQ, 40 Ni, 41 N, 42 D, 46 SK, 47 CP,
    #    48 EAP. The old table was shifted by one from 42 onward and had no
    #    CERT at all, so an IKE_AUTH's encrypted payload read as TSr.
    chk reg-exh-34 "$(vowi_ike_name 34)" "IKE_SA_INIT"
    chk reg-exh-35 "$(vowi_ike_name 35)" "IKE_AUTH"
    chk reg-exh-36 "$(vowi_ike_name 36)" "CREATE_CHILD_SA"
    chk reg-exh-37 "$(vowi_ike_name 37)" "INFORMATIONAL"
    chk reg-exh-38 "$(vowi_ike_name 38)" "IKE_SESSION_RESUME"
    chk reg-exh-43 "$(vowi_ike_name 43)" "IKE_INTERMEDIATE"
    chk reg-exh-44 "$(vowi_ike_name 44)" "IKE_FOLLOWUP_KE"
    chk reg-pay-33 "$(vowi_payload_name 33)" "SA"
    chk reg-pay-37 "$(vowi_payload_name 37)" "CERT"
    chk reg-pay-38 "$(vowi_payload_name 38)" "CERTREQ"
    chk reg-pay-40 "$(vowi_payload_name 40)" "Ni"
    chk reg-pay-41 "$(vowi_payload_name 41)" "N"
    chk reg-pay-42 "$(vowi_payload_name 42)" "D"
    chk reg-pay-43 "$(vowi_payload_name 43)" "V"
    chk reg-pay-44 "$(vowi_payload_name 44)" "TSi"
    chk reg-pay-46 "$(vowi_payload_name 46)" "SK"
    chk reg-pay-47 "$(vowi_payload_name 47)" "CP"
    chk reg-pay-48 "$(vowi_payload_name 48)" "EAP"
    chk reg-pay-54 "$(vowi_payload_name 54)" "PS"
    chk reg-pay-unassigned "$(vowi_payload_name 55)" "unassigned"
    chk reg-xform-1 "$(vowi_transform_type_name 1)" "Encryption Algorithm (ENCR)"
    chk reg-xform-5 "$(vowi_transform_type_name 5)" "Sequence Numbers (SN)"
    chk reg-id-2 "$(vowi_id_type_name 2)" "ID_FQDN"
    chk reg-id-11 "$(vowi_id_type_name 11)" "ID_KEY_ID"
    chk reg-notify-status "$(vowi_notify_name 16384)" "INITIAL_CONTACT"
    chk reg-notify-error  "$(vowi_notify_name 7)" "INVALID_SYNTAX"
    chk reg-notify-unassigned "$(vowi_notify_name 16000)" "unassigned"
    chk reg-esn-1 "$(vowi_esn_name 1)" "Partially Transmitted 64-bit Sequential Numbers"
    chk reg-eapatt-1 "$(vowi_eap_attr_name 1)" "AT_RAND"
    chk reg-eapatt-24 "$(vowi_eap_attr_name 24)" "AT_KDF"
    chk reg-eapatt-136 "$(vowi_eap_attr_name 136)" "AT_BIDDING"

    # 2. Header build is exactly 28 octets and round-trips through the parser.
    local hdr; hdr=$(vowi_ike_build 1122334455667788 0000000000000000 33 34 8 00000000)
    chk hdr-len "$(( ${#hdr} / 2 ))" "28"
    local out; out=$(vowi_ike_parse "$hdr")
    chk hdr-parsi "$(fld "$out" initiator_spi)" "1122334455667788"
    chk hdr-next  "$(fld "$out" next_payload)" "33"
    chk hdr-next-name "$(fld "$out" next_payload_name)" "SA"
    chk hdr-exch  "$(fld "$out" exchange_type)" "34"
    chk hdr-ver   "$(fld "$out" version)" "0x20"
    chk hdr-major "$(fld "$out" version_major)" "2"
    chk hdr-init  "$(fld "$out" initiator)" "yes"
    chk hdr-resp  "$(fld "$out" response)" "no"
    chk hdr-lenfield "$(fld "$out" length_field)" "28"
    # a non-v2 major version must raise the alert, not be called IKEv2.
    local h10; h10=$(vowi_norm_hex "${hdr:0:34}10${hdr:36}")
    chk hdr-ver-alert "$(printf '%s\n' "$(vowi_ike_parse "$h10" 2>/dev/null)" | grep -c version_alert)" "1"
    # the length field counts the whole message (#3.1)
    local hlen; hlen="${hdr:0:48}0000001E"
    chk hdr-len-alert "$(printf '%s\n' "$(vowi_ike_parse "$hlen" 2>/dev/null)" | grep -c length_alert)" "1"
    # only I (0x08), V (0x10) and R (0x20) are defined flag bits
    local hflag; hflag=$(vowi_ike_build 1122334455667788 0000000000000000 33 34 9 00000000)
    chk hdr-flag-alert "$(printf '%s\n' "$(vowi_ike_parse "$hflag" 2>/dev/null)" | grep -c flags_alert)" "1"
    chk hdr-short "$(vowi_ike_parse 0011 >/dev/null 2>&1; echo $?)" "1"
    chk hdr-badhex "$(vowi_ike_parse zz >/dev/null 2>&1; echo $?)" "2"

    # 3. EAP-AKA (RFC 4187 8.1, 11): the 8-octet header, the registry subtypes,
    #    and the attribute walk that makes AT_MAC visible.
    local eap; eap=$(vowi_eap_aka 1 7 1)
    chk eap-header-len "$(( ${#eap} / 2 ))" "8"
    chk eap-declared "$(( 16#${eap:4:4} ))" "8"
    chk eap-reserved "${eap:12:4}" "0000"
    chk eap-type "$(( 16#${eap:8:2} ))" "23"
    chk eap-sub-challenge "$(vowi_aka_subtype_name 1)" "AKA-Challenge"
    chk eap-sub-reject  "$(vowi_aka_subtype_name 2)" "AKA-Authentication-Reject"
    chk eap-sub-sync    "$(vowi_aka_subtype_name 4)" "AKA-Synchronization-Failure"
    chk eap-sub-id      "$(vowi_aka_subtype_name 5)" "AKA-Identity"
    chk eap-sub-notif   "$(vowi_aka_subtype_name 12)" "AKA-Notification"
    chk eap-sub-reauth  "$(vowi_aka_subtype_name 13)" "AKA-Reauthentication"
    chk eap-sub-err     "$(vowi_aka_subtype_name 14)" "AKA-Client-Error"
    local rand; rand=$(vowi_eap_attr 1 000102030405060708090a0b0c0d0e0f)
    chk eap-attr-rand-len "$(( ${#rand} / 2 ))" "20"
    local mac; mac=$(vowi_eap_attr 11 000102030405060708090a0b0c0d0e0f)
    local pkt; pkt=$(vowi_eap_aka 1 7 1 "$rand$mac")
    out=$(vowi_eap_parse "$pkt")
    chk eap-att-0-name "$(fld "$out" att.0.name)" "AT_RAND"
    chk eap-att-1-name "$(fld "$out" att.1.name)" "AT_MAC"
    chk eap-att-1-len  "$(fld "$out" att.1.length)" "20"
    chk eap-att-1-valu "$(fld "$out" att.1.value)" "000102030405060708090a0b0c0d0e0f"
    chk eap-att-count   "$(printf '%s\n' "$out" | grep -c '^att\.[0-9]*\.name')" "2"
    chk eap-att-pad     "$(vowi_eap_attr 3 0102)" "03010102"
    # the clause fixes some lengths: AT_KDF is one unit, AT_MAC five
    local badkdf; badkdf=$(vowi_eap_aka 1 7 1 "$(vowi_eap_attr 24 0000000000000000000000000000)")
    chk eap-kdf-len "$(vowi_eap_parse "$badkdf" >/dev/null 2>&1; echo $?)" "1"
    local badmac; badmac=$(vowi_eap_aka 1 7 1 "$(vowi_eap_attr 11 00010203)")
    chk eap-mac-len "$(vowi_eap_parse "$badmac" >/dev/null 2>&1; echo $?)" "1"
    chk eap-wrong "$(vowi_eap_parse 0101000501 >/dev/null 2>&1; echo $?)" "1"
    chk eap-short "$(vowi_eap_parse 0101 >/dev/null 2>&1; echo $?)" "1"
    # a length field that disagrees with the octets arrived is refused
    local badlen2; badlen2="${eap:0:4}0010${eap:8}"
    chk eap-len-alert "$(printf '%s\n' "$(vowi_eap_parse "$badlen2" 2>/dev/null)" | grep -c length_alert)" "1"

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

    # 5. Transform classifiers. Unknown is never 'ok' (MODULE_CONVENTIONS 16).
    chk encr-null "$(fld "$(vowi_encr_classify 11)" verdict)" "weak — no confidentiality"
    chk encr-null-gmac "$(fld "$(vowi_encr_classify 21)" name)" "ENCR_NULL_AUTH_AES_GMAC"
    chk encr-aesgcm "$(fld "$(vowi_encr_classify 20)" verdict)" "ok"
    chk encr-aesctr "$(fld "$(vowi_encr_classify 13)" name)" "ENCR_AES_CTR"
    chk encr-3des "$(fld "$(vowi_encr_classify 3)" verdict)" "legacy — 64-bit block, deprecated"
    chk encr-unknown "$(fld "$(vowi_encr_classify 999)" verdict)" "unknown — never scored as ok"
    chk int-none "$(fld "$(vowi_integrity_classify 0)" verdict)" "weak — no integrity"
    chk int-sha256 "$(fld "$(vowi_integrity_classify 12)" name)" "AUTH_HMAC_SHA2_256_128"
    chk int-sha1 "$(fld "$(vowi_integrity_classify 2)" verdict)" "legacy"
    chk int-unknown "$(fld "$(vowi_integrity_classify 77)" verdict)" "unknown — never scored as ok"
    chk dh-1024 "$(fld "$(vowi_dh_classify 2)" verdict)" "weak — 768/1024-bit MODP, pre-logjam"
    chk dh-2048 "$(fld "$(vowi_dh_classify 14)" name)" "2048-bit MODP Group"
    chk dh-ecp256 "$(fld "$(vowi_dh_classify 19)" verdict)" "ok"
    chk dh-x25519 "$(fld "$(vowi_dh_classify 31)" name)" "Curve25519"
    chk dh-unknown "$(fld "$(vowi_dh_classify 999)" verdict)" "unknown — never scored as ok"

    # 6. Payload chain walk: a full message, the SK stop, and a refusal when a
    #    payload claims more octets than the message carries.
    local base; base=$(vowi_ike_build 1122334455667788 0000000000000000 33 35 8 00000000)
    local msg; msg="${base:0:48}00000024"     # 36 octets: 28 header + 2 payloads
    msg+="28000004"                            # SA: next 40 (Ni), len 4
    msg+="00000004"                            # Ni: next 0, len 4
    out=$(vowi_payload_walk "$msg")
    chk walk-first  "$(printf '%s\n' "$out" | sed -n '2p' | cut -f4)" "SA"
    chk walk-second "$(printf '%s\n' "$out" | sed -n '3p' | cut -f4)" "Ni"
    chk walk-rows   "$(printf '%s\n' "$out" | tail -n +2 | wc -l | tr -d ' ')" "2"
    local skbase; skbase=$(vowi_ike_build 1122334455667788 0000000000000000 46 35 8 00000000)
    local skmsg; skmsg="${skbase:0:48}00000020"; skmsg+="00000004"   # one SK, 32 octets
    out=$(vowi_payload_walk "$skmsg")
    chk walk-sk-name "$(printf '%s\n' "$out" | sed -n '2p' | cut -f4)" "SK"
    chk walk-sk-stop "$(printf '%s\n' "$out" | grep -c 'SK payload')" "1"
    local over; over="${skbase:0:48}00000020"; over+="00000040"     # claims 64 in 32
    chk walk-over "$(vowi_payload_walk "$over" >/dev/null 2>&1; echo $?)" "1"
    local short4; short4="${skbase:0:48}00000020"; short4+="00000002" # len below a header
    chk walk-short "$(vowi_payload_walk "$short4" >/dev/null 2>&1; echo $?)" "1"

    # 7. SA proposals (§3.3.1) and the downgrade they can offer (§3.3.2).
    out=$(vowi_sa_parse 0000001801010002000000080100000C030000080300000C)
    chk sa-transforms "$(fld "$out" proposal.0.transforms)" "2"
    chk sa-encr-name  "$(fld "$out" proposal.0.transform.0.name)" "ENCR_AES_CBC"
    chk sa-integ-name "$(fld "$out" proposal.0.transform.1.name)" "AUTH_HMAC_SHA2_256_128"
    chk sa-clean      "$(fld "$out" tunnel_verdict)" "no NULL encryption or INTEG NONE offered"
    out=$(vowi_sa_parse 0000001001010001030000080100000B)
    chk sa-null-encr  "$(printf '%s\n' "$out" | grep -c '^null_transform')" "1"
    chk sa-null-name  "$(fld "$out" proposal.0.transform.0.name)" "ENCR_NULL"
    out=$(vowi_sa_parse 00000018010100020000000803000000030000080000000C)
    chk sa-null-integ "$(printf '%s\n' "$out" | grep -c '^null_transform')" "1"
    # a proposal whose length runs past the payload is refused, not partially read
    chk sa-over "$(vowi_sa_parse 000000FF01010001030000080100000B >/dev/null 2>&1; echo $?)" "1"

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
            1)  vowi_registry | head -40; read -rp "  enter " _ ;;
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
        --types)        local kind="${1:-}"; vowi_registry | { [[ -n "$kind" ]] && awk -F'\t' -v k="$kind" 'NR==1 || $1==k' || cat; } ;;
        --payload)      vowi_payload_name "${1:-}" ;;
        --transform)    vowi_transform_type_name "${1:-}" ;;
        --id-type)      vowi_id_type_name "${1:-}" ;;
        --notify)       vowi_notify_name "${1:-}" ;;
        --eap-attr)     vowi_eap_attr_name "${1:-}" ;;
        --dh)           vowi_dh_classify "${1:-}" ;;
        --esn)          vowi_esn_name "${1:-}" ;;
        --ike-build)    vowi_ike_build "${1:-1122334455667788}" "${2:-0000000000000000}" "${3:-33}" "${4:-34}" "${5:-8}" "${6:-00000000}" ;;
        --ike-parse)    vowi_ike_parse "${1:-}" ;;
        --eap-build)    vowi_eap_aka "${1:-1}" "${2:-1}" "${3:-1}" "${4:-}" ;;
        --eap-parse)    vowi_eap_parse "${1:-}" ;;
        --nai)          vowi_nai "${1:-}" "${2:-}" "${3:-}" ;;
        --epdg)         vowi_epdg_fqdn "${1:-}" "${2:-}" ;;
        --encr)         vowi_encr_classify "${1:-}" ;;
        --integrity)    vowi_integrity_classify "${1:-}" ;;
        --walk)         vowi_payload_walk "${1:-}" "${2:-33}" ;;
        --null-check)   vowi_sa_parse "${1:-}" ;;
        --plan)         vowi_plan ;;
        --selftest)     vowi_selftest ;;
        --menu)         vowi_menu ;;
        *)
            cat >&2 <<EOF
VoWiFi / ePDG Attacks — IKEv2/SWu, EAP-AKA and the tunnel to the EPC

Usage: $0 COMMAND
  --status-tsv         module state as TSV
  --types [kind]       IKEv2 / EAP-AKA registries (exchange, payload,
                       transform, idtype, notify-error, notify-status,
                       eap-subtype, eap-att, encr, prf, integ, ke, esn)
  --payload <n>        payload type name (RFC 7296 3.2)
  --transform <n>      transform type name (RFC 7296 3.3.2)
  --id-type <n>        identification payload type (RFC 7296 3.5)
  --notify <n>         notify message name (RFC 7296 3.10)
  --eap-attr <n>       EAP-AKA attribute name (RFC 4187 11)
  --dh <n>             key exchange method verdict (RFC 8247)
  --esn <n>            sequence number transform (RFC 7296 3.3.2)
  --ike-build <iSPI> <rSPI> <next> <exch> [flags] [msgid]
  --ike-parse <hex>    decode a 28-octet IKEv2 header
  --eap-build <code> <id> <subtype> [attrs hex]
                       build an EAP-AKA packet (attributes 4-octet aligned)
  --eap-parse <hex>    decode an EAP-AKA packet
  --nai <imsi> <mcc> <mnc>   SWu NAI (TS 23.003)
  --epdg <mcc> <mnc>         ePDG discovery FQDN
  --encr <id>          encryption transform verdict
  --integrity <id>     integrity transform verdict
  --walk <hex> [type]  walk an IKEv2 payload chain
  --null-check <hex>   read an SA payload and report NULL encryption or
                       INTEG NONE in the proposals (RFC 7296 3.3.1/3.3.2)
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
